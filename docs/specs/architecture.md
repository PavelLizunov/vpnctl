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
missing secrets and preserves existing values. See
[node kernel installation and rendering validation](node-kernel-rendering-validation.md).

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
