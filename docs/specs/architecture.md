# Contract: architecture

## 1. Intent & Invariants

- What: two orthogonal trait layers let vpnctl grow protocols and node daemons
  independently. Adding one side must never touch the other.
- Invariants:
  - Adding a kernel or protocol must NOT require changes in `core`, `ssh`,
    `crypto`, `inventory`, or `daemon` — one new module + one registration line.
  - Protocols never own mutable inventory state; secrets arrive per-render.
  - Every inventory mutation is auditable.
  - The workspace bans `unsafe`, `unwrap`/`expect`/`panic` outside tests, and
    `openssl-sys` / `native-tls`.

## 2. Interface / Data Contract

```rust
// crates/core
trait Kernel {
    fn id(&self) -> KernelId;
    fn supported_protocols(&self) -> &[ProtocolId];
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
    fn server_inbound(&self, ctx: &RenderCtx) -> Result<String>;
    fn client_config(&self, ctx: &RenderCtx) -> Result<String>;
    fn share_link(&self, ctx: &RenderCtx) -> Result<String>;
}

// Registration: cli/src/registry.rs — one `register_kernel` / `register_protocol`
// line per implementation. `Registry::validate_server` rejects incompatible
// kernel × protocol combos BEFORE any SSH session opens.
```

## 3. Verification Checklist

- [ ] Adding kernel `X` touches only `crates/kernels/src/x.rs` + one line in
      `cli/src/registry.rs` (review-agent checks for cross-crate edits).
- [ ] `cargo deny check` passes (no openssl-sys / native-tls).
- [ ] clippy `-D warnings` passes (no unwrap/expect/panic in non-test code).
- [ ] Every new inventory write path emits an `audit_log` row; no-op writes
      emit none.
- [ ] A new secret-bearing protocol renders without `MissingSecret` after
      `bootstrap_server_secrets` (regression guard: all-protocols server).
