# Contract: architecture

## 1. Intent & Invariants

- What: two orthogonal trait layers let vpnctl grow protocols and node daemons
  independently. Adding one side must never touch the other.
- Invariants:
  - Adding a kernel or protocol must NOT require changes in `core`, `ssh`,
    `crypto`, `inventory`, or `daemon` — one new module + one registration line.
  - Protocols never own mutable inventory state; secrets arrive per-render.
  - Every inventory mutation is auditable. Audit payloads record UUID/device-ID
    presence with `*_set` booleans, never the credential values. User targets
    and server IDs retain attribution. Admin HTML and CSV also redact UUID and
    device-ID fields in legacy payloads recursively, retaining at most an
    eight-character prefix (short values are fully redacted).
  - The workspace bans `unsafe`, `unwrap`/`expect`/`panic` outside tests, and
    `openssl-sys` / `native-tls`.

## 2. Interface / Data Contract

```rust
// crates/core
trait Kernel {
    fn id(&self) -> KernelId;
    fn supported_protocols(&self) -> &[ProtocolId];
    fn validate_server_support(&self, server: &Server) -> Result<()>;
    fn service_units(&self) -> &'static [&'static str];
    async fn ensure_installed(&self, ssh: &dyn SshTransport) -> Result<()>;
    async fn apply_config(&self, ssh: &dyn SshTransport, cfg: &str) -> Result<()>;
    // server_secret_specs: a secret-bearing protocol DECLARES its own
    // server-side secrets (Protocol::server_secret_specs); the daemon minter
    // iterates enabled protocols via the registry. NEVER hard-code a central
    // per-protocol secret list in the daemon.
}

trait Protocol {
    fn id(&self) -> ProtocolId;
    fn server_secret_specs(&self) -> Vec<ServerSecretSpec> { vec![] }
    fn server_secret_specs_for(&self, secrets: &HashMap<String, String>)
        -> Result<Vec<ServerSecretSpec>> { Ok(self.server_secret_specs()) }
    fn validate_server(&self, ctx: &RenderCtx) -> Result<()>;
    fn server_inbound(&self, ctx: &RenderCtx) -> Result<String>;
    fn client_config(&self, ctx: &RenderCtx) -> Result<String>;
    fn share_link(&self, ctx: &RenderCtx) -> Result<String>;
}

// Registration: crates/kernels/src/registry.rs — one `register_kernel` / `register_protocol`
// line per implementation. `Registry::validate_server` rejects incompatible
// kernel × protocol combos BEFORE any SSH session opens.
```

`vpnctl_kernels::build_registry() -> vpnctl_core::Result<Registry>` is the
single builder used by CLI and daemon. Its location in
`crates/kernels/src/registry.rs` reuses a crate both consumers already depend on;
`vpnctl-kernels` depends on `vpnctl-protocols` for composition, while protocols
depend only on core, so no dependency cycle or extra crate is needed. Kernel
implementations still use protocol traits rather than concrete protocol types.
Registration order is preserved because registry iteration feeds client output.

Kernel implementations declare every managed systemd unit, including auxiliary
services, through `service_units`. Before installing/applying enabled kernels,
every deploy entry point stops and disables the installed services of kernels
that the operator disabled on that server (a `server.kernel.disable` audit row)
and that are not enabled again. Units of kernels vpnctl never managed on the
server are left alone; missing units are a no-op; shutdown errors fail the
deploy. This shared lifecycle hook keeps unit names inside the kernel module
when new kernels are registered.

Kernel dependency checks and protocol setting checks are dispatched by the
registry to their owning implementations. Context-aware secret declarations
keep method-dependent key sizes in the protocol; inventory only mints declared
missing secrets and preserves existing values.

Managed sing-box and Xray user traffic must not reach loopback, private,
link-local, unspecified or other service ranges, or the server's inventory IP.
The rule applies to TCP and UDP, including domain destinations such as
`localhost` and domains resolving to a denied IP. The server-IP rule needs a
literal inventory address: a hostname server keeps the range isolation without
it, while AWG endpoints still require a literal IP. Client configuration and
share-link bytes do not change.

Sing-box resolves proxy destinations before applying `ip_is_private`, the
explicit `USER_TRAFFIC_DENIED_CIDRS` list (`ip_is_private` misses CGNAT
`100.64.0.0/10`, which Tailscale uses) and the server `/32` or `/128` rejection to every user inbound and AWG endpoint. Direct
egress uses those resolved addresses; the existing AWG-only rules are unchanged.
This uses the documented [resolve action](https://sing-box.sagernet.org/configuration/route/rule_action/#resolve),
supported by the managed `1.14.2-vpnctl.2` release. Xray `26.3.27` uses a default
[loopback outbound](https://xtls.github.io/en/config/outbounds/loopback.html)
with `targetStrategy: ForceIPv4v6` (IPv4 first, for nodes without IPv6 egress) to resolve once and re-enter routing with the
actual destination IP. Explicit IPv4/IPv6 CIDRs and the server IP route to a
blackhole before the resolved inbound may use direct egress. This avoids both
external GeoIP files and a second DNS lookup after the security decision.
The Clash and Stats listeners remain on loopback, reachable by the daemon's
existing SSH pollers.

## 3. Verification Checklist

- [ ] Adding kernel `X` touches only `crates/kernels/src/x.rs` + one line in
      `crates/kernels/src/registry.rs` (review-agent checks for cross-crate edits).
- [ ] `build_registry_matches_canonical_set` pins shared membership and order;
      CLI and daemon both re-export this builder without local registrations.
- [ ] `cargo deny check` passes (no openssl-sys / native-tls).
- [ ] clippy `-D warnings` passes (no unwrap/expect/panic in non-test code).
- [ ] Every new inventory write path emits an `audit_log` row; no-op writes
      emit none.
- [ ] A new secret-bearing protocol renders without `MissingSecret` after
      `bootstrap_server_secrets` (regression guard: all-protocols server).
- [ ] Rendering tests cover every sing-box user inbound, unchanged AWG-only
      guards, IPv4/IPv6 server isolation and Xray's resolve/block/direct order.
      Native kernel checks must reject literal and domain-resolved local targets
      over TCP/UDP while allowing public egress; client output stays unchanged.
