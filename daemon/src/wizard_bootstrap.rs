//! Phase E sub-iter 4b — add-server wizard's SSE bootstrap engine.
//!
//! # What this does (operator's view)
//!
//! Operator pasted an IP + root password into step 1. This module
//! turns that into a fully-deployed VPN server, streaming progress
//! line-by-line over Server-Sent Events:
//!
//! 1. **probe** — `ssh root@<addr>` with the supplied password, run
//!    `true` to confirm credentials work.
//! 2. **fingerprint** — `ssh-keyscan` the host's ed25519/rsa key and
//!    pin it as `trusted_host_fingerprint` (SHA256 form). TOFU — if
//!    we ever see a different fingerprint later, the daemon will
//!    refuse to connect until the operator approves the change.
//! 3. **push-key** — append the daemon's deploy pubkey to the
//!    server's `~/.ssh/authorized_keys` (idempotent — won't double-
//!    add if the operator re-runs the wizard for the same host).
//! 4. **verify-key** — `ssh -i <deploy-key>` (NO password) and run
//!    `true`. Proves pubkey auth works before we commit to inventory.
//! 5. **register** — `inv.add_server()` with default kernel
//!    `sing-box` + every protocol sing-box supports. Pavel's UX brief:
//!    "сразу все" — operator can disable on the detail page after.
//! 6. **secrets** — mint VLESS-REALITY keypair, WireGuard server
//!    keypair, Hysteria2 obfs password. Same logic as
//!    `server_deploy` handler.
//! 7. **install-\<kernel\>** — for each declared kernel:
//!    `kernel.ensure_installed(&ssh)` (apt-get install sing-box etc).
//! 8. **apply-\<kernel\>** — render the config + push via
//!    `kernel.apply_config(&ssh, &config)` (systemctl restart).
//! 9. **done** — final event carrying the new server's URL so the
//!    browser can redirect.
//!
//! Steps 1-2-3 use **password auth** via `sshpass -e ssh`; steps 4
//! onward use **key auth** via `SubprocessSshTransport`. The split
//! exists because we can't use key auth until step 3 finishes
//! pushing the key.
//!
//! # Why a separate module (not inline in the handler)
//!
//! The handler's job is request/response routing — wrapping a stream
//! into an `axum::response::sse::Sse` value. The bootstrap LOGIC
//! (sequencing, retries, error mapping) lives here so it can be unit-
//! tested without spinning up an axum router.
//!
//! # Error model
//!
//! Each phase either yields a `Step` (advisory progress text) or an
//! `Error` (terminal — pipeline returns early, no more events). After
//! `Ok` or `Error`, the spawned task ends and the mpsc Sender drops,
//! closing the ReceiverStream so the browser sees a clean EOF.
//!
//! # Cancellation semantics (deliberate — do not "fix")
//!
//! The bootstrap task is **detached** — it runs to completion even
//! if the SSE client disconnects mid-flight. Rationale: the operator
//! clicked "create server" with the expectation that the server
//! WILL exist when they next look. Aborting on tab-close would leave
//! a half-bootstrapped node (key pushed, server registered, sing-box
//! not installed yet) and require a second deploy click. Worse, the
//! operator might assume their click had no effect and not come back.
//!
//! The cost is small: a stranded subprocess running sshpass/ssh-keyscan
//! against a real node finishes in <60 s and the spawned task is
//! capped by the kernel install timeout. If the operator wants to
//! ABORT (rare), the recovery path is "go to /admin/servers, find
//! the half-baked entry, delete it" — one explicit operator action,
//! which matches the one-action ceiling.
//!
//! Review-agent 2026-05-17 (critical-2) flagged the lack of
//! cancellation; the decision to keep "run-to-completion" is
//! documented here so the next review pass doesn't re-raise it.
//!
//! # Why mpsc + ReceiverStream (not `async_stream::stream!`)
//!
//! Tried `stream!` first — it lets you write straight-line async
//! code with `yield X;` to emit events. But `stream!` is a syntactic
//! macro: it walks the body looking for `yield` tokens BEFORE other
//! macros expand, so `macro_rules! step { … yield X; … }` invocations
//! at the call site never get scanned and the resulting code doesn't
//! compile. We have ~30 yield points and don't want to expand them
//! all by hand, so we switched to a separate `bootstrap_pipeline()`
//! function that calls `tx.send(...).await` (which behaves like a
//! normal expression and can be macro-wrapped) and spawn it on a
//! tokio task feeding a bounded mpsc channel. The `ReceiverStream`
//! adapter turns the channel into a `Stream` for axum's `Sse::new`.

mod audit;
mod bootstrap;
mod guard;
mod kernel_update;
mod redeploy;
mod types;
mod util;

#[cfg(test)]
mod tests;

pub use vpnctl_inventory::bootstrap_server_secrets;

pub(crate) use self::audit::*;
pub use self::bootstrap::*;
pub use self::guard::*;
pub use self::kernel_update::*;
pub use self::redeploy::*;
pub use self::types::*;
pub use self::util::*;
