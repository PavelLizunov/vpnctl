//! Phase 3c — Settings GeoIP «update now» SSE backend.
//!
//! Companion to the monthly `vpnctl-geoip-update.timer` (Phase 3b).
//! Lets the operator click a button in /admin/settings to fire the
//! same `vpnctl geoip-update` CLI between scheduled runs, streaming
//! the command's stdout + stderr line-by-line via Server-Sent Events.
//!
//! ## Event shape
//!
//! Mirrors the wizard-bootstrap SSE shape (Step / Ok / Error tagged
//! enum) so the front-end JS pattern is identical:
//! `addEventListener('step', …)` / `'ok'` / `'error'`.
//!
//! ## Subprocess strategy
//!
//! `/usr/local/bin/vpnctl geoip-update` via [`std::process::Command`]
//! — NOT [`tokio::process::Command`]. Tokio's process module switched
//! to `pidfd_spawnp` in glibc 2.39 for child management; prod runs
//! glibc 2.36 → daemon crash-loops with `GLIBC_2.39 not found`.
//! Caught by Pavel 2026-05-16 when Track-3 (clash-poller) shipped
//! `tokio::process` and the daemon imploded on the homelab host.
//! The accepted workaround pattern is in
//! [`crate::ssh_subprocess::SubprocessSshTransport`]:
//! `std::process::Command` + [`tokio::task::spawn_blocking`].
//!
//! ## Orchestration
//!
//! One `spawn_blocking` task owns the [`std::process::Child`] and
//! two std reader threads (one stdout, one stderr). The readers
//! can't be `tokio::io::BufReader::lines()` because the underlying
//! pipes are blocking std I/O — we'd block the runtime. Each reader
//! pumps each line into a `tokio::sync::mpsc::Sender<UpdateEvent>`
//! via `blocking_send`. The orchestrator awaits `child.wait()`,
//! joins both readers, then sends the terminal `Ok` / `Error`.
//!
//! ## Backpressure + disconnect
//!
//! Channel capacity is 64 events. If the SSE client disconnects
//! (operator closed the browser tab), `blocking_send` returns Err,
//! the readers exit, but the child PROCESS keeps running to
//! completion — `vpnctl geoip-update` is idempotent + safe to
//! orphan; killing it mid-download leaves a `.partial.gz` artefact
//! that the next run cleans up. The trade is "small disk litter on
//! disconnect" vs "wasted bytes already downloaded on disconnect" —
//! we prefer to let it finish.
//!
//! ## Concurrent fires
//!
//! No daemon-side lock: two simultaneous "update now" clicks spawn
//! two subprocesses. `vpnctl geoip-update` writes to a single
//! `.partial.gz` filename, so the later writer overwrites the
//! earlier one. atomic-rename happens on success. Worst case: both
//! finish, one's atomic-rename wins, the other's silently
//! overwritten. Acceptable for a button the operator clicks at most
//! once between monthly ticks.

use std::process::{Command, Stdio};
use std::sync::OnceLock;

use serde::Serialize;
use tokio::sync::{Semaphore, mpsc};
use tokio_stream::wrappers::ReceiverStream;

/// Process-wide semaphore capping concurrent `vpnctl geoip-update`
/// runs to 1. Two simultaneous «update now» clicks (operator
/// double-clicking, or two browser tabs) used to spawn two
/// subprocesses racing on the `.partial.gz` filename + holding two
/// blocking-pool threads for the duration. The semaphore is acquired
/// at the very start of [`try_run_update`]; failure to acquire
/// returns an Already-running stream that emits one Error event +
/// closes immediately.
fn concurrent_fire_gate() -> &'static Semaphore {
    static GATE: OnceLock<Semaphore> = OnceLock::new();
    GATE.get_or_init(|| Semaphore::new(1))
}

/// Default path to the vpnctl CLI on the daemon host. Matches the
/// `ExecStart=` in `scripts/vpnctl-geoip-update.service`. Overridable
/// per-process via `VPNCTLD_VPNCTL_BIN` so tests + alternate install
/// prefixes don't need code edits.
pub const DEFAULT_VPNCTL_BIN: &str = "/usr/local/bin/vpnctl";

/// Resolve the `vpnctl` binary path the runner should exec. Env var
/// override > compile-time default.
pub fn resolve_vpnctl_bin() -> String {
    std::env::var("VPNCTLD_VPNCTL_BIN").unwrap_or_else(|_| DEFAULT_VPNCTL_BIN.to_string())
}

/// SSE-shaped event. Tagged enum on `kind` so the front-end can
/// route by `event:` name + JSON-parse the data payload.
#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum UpdateEvent {
    /// A line of subprocess output. `stream` is `"stdout"` or
    /// `"stderr"` so the UI can colour stderr differently.
    Step {
        stream: &'static str,
        message: String,
    },
    /// Subprocess exited 0. Terminal event — stream completes.
    Ok { message: String },
    /// Subprocess failed to spawn, exited non-zero, or wait failed.
    /// Terminal event — stream completes.
    Error { message: String },
}

impl UpdateEvent {
    /// SSE `event:` name. Mirrors the wizard-bootstrap convention.
    pub fn event_name(&self) -> &'static str {
        match self {
            UpdateEvent::Step { .. } => "step",
            UpdateEvent::Ok { .. } => "ok",
            UpdateEvent::Error { .. } => "error",
        }
    }
}

/// Start `<vpnctl_bin> geoip-update` as a subprocess and return a
/// Stream of [`UpdateEvent`]s. The stream completes after the
/// terminal Ok/Error event.
///
/// Gated by [`concurrent_fire_gate`] — only ONE update runs at a
/// time, daemon-wide. Concurrent attempts get a single Error event
/// and a closed stream so the UI surfaces «already running» without
/// spawning a redundant subprocess.
///
/// The function returns immediately (the subprocess spawn happens
/// on a background blocking task) — useful so the SSE handler can
/// attach the stream to a response without waiting.
pub fn run_update(vpnctl_bin: String) -> ReceiverStream<UpdateEvent> {
    let (tx, rx) = mpsc::channel(64);
    // try_acquire is non-blocking — the SemaphorePermit lives for
    // the duration of the spawn_blocking task (released on drop).
    // The 'static lifetime on the semaphore lets the permit be
    // moved into the task closure. If we can't get a permit, emit
    // ONE Error event + close the channel.
    match concurrent_fire_gate().try_acquire() {
        Ok(permit) => {
            tokio::task::spawn_blocking(move || {
                run_blocking(vpnctl_bin, tx);
                drop(permit);
            });
        }
        Err(_) => {
            let _ = tx.try_send(UpdateEvent::Error {
                message: "vpnctl admin: another geoip-update is already running on this daemon; \
                          wait for it to finish, then retry"
                    .into(),
            });
            // tx drops → rx returns None → stream completes.
        }
    }
    ReceiverStream::new(rx)
}

/// Synchronous body of [`run_update`]. Extracted for clarity — runs
/// inside `spawn_blocking`, never on the async runtime.
///
/// `tx` is taken by value (not `&`) because the two reader threads
/// below MOVE clones of it into `std::thread::spawn` closures — the
/// `'static` lifetime that thread::spawn requires precludes borrowing.
#[allow(clippy::needless_pass_by_value)]
fn run_blocking(vpnctl_bin: String, tx: mpsc::Sender<UpdateEvent>) {
    let mut child = match Command::new(&vpnctl_bin)
        .arg("geoip-update")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            let _ = tx.blocking_send(UpdateEvent::Error {
                message: format!("vpnctl admin: failed to spawn {vpnctl_bin}: {e}"),
            });
            return;
        }
    };

    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let tx_out = tx.clone();
    let h_out = std::thread::spawn(move || pump_lines(stdout, "stdout", tx_out));
    let tx_err = tx.clone();
    let h_err = std::thread::spawn(move || pump_lines(stderr, "stderr", tx_err));

    let status = child.wait();
    // Join the readers AFTER wait so we drain whatever they buffered
    // before the child closed its pipes. Either reader panicking
    // (extremely unlikely — just BufRead + send) leaves the join
    // returning Err; we ignore + still emit a terminal event.
    let _ = h_out.join();
    let _ = h_err.join();

    let terminal = match status {
        Ok(s) if s.success() => UpdateEvent::Ok {
            // Descriptive, NOT imperative — per the post-2026-05-18
            // operator-action policy («don't ask the operator to
            // run shell commands»). The daemon doesn't auto-restart
            // because that would interrupt the ongoing SSE response
            // + every other request in flight. Operator restarts
            // on their own schedule (a future Settings button is
            // welcome — Phase 3d).
            message: "geoip-update completed; new DBs will load on next vpnctld restart".into(),
        },
        Ok(s) => UpdateEvent::Error {
            message: format!("vpnctl admin: geoip-update exited with {s}"),
        },
        Err(e) => UpdateEvent::Error {
            message: format!("vpnctl admin: wait failed: {e}"),
        },
    };
    let _ = tx.blocking_send(terminal);
}

/// Read `pipe` line-by-line and push each as a Step event tagged
/// with `stream_name`. Returns when EOF is reached, the receiver is
/// dropped (SSE client disconnect), or the pipe was `None`.
///
/// `tx` is owned (not `&`) because this function runs inside a
/// `std::thread::spawn` closure that captures it by move.
#[allow(clippy::needless_pass_by_value)]
fn pump_lines<R: std::io::Read>(
    pipe: Option<R>,
    stream_name: &'static str,
    tx: mpsc::Sender<UpdateEvent>,
) {
    use std::io::{BufRead, BufReader};
    let Some(pipe) = pipe else {
        return;
    };
    for line in BufReader::new(pipe).lines().map_while(Result::ok) {
        if tx
            .blocking_send(UpdateEvent::Step {
                stream: stream_name,
                message: line,
            })
            .is_err()
        {
            // Receiver dropped — SSE client disconnected. Stop
            // pumping; the orchestrator will still wait for the
            // child to finish on its own.
            break;
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use tokio_stream::StreamExt;

    /// Test-only serializer for the runner tests that touch the
    /// process-global `concurrent_fire_gate()` semaphore. Without
    /// it, `cargo test` runs tests in parallel and tests 2-5 race
    /// on whether they get the permit — some flaky-fail with an
    /// "already running" Error event when they expected happy path.
    /// Tokio Mutex (not std) so the lock spans `.await` points.
    fn test_gate_serializer() -> &'static tokio::sync::Mutex<()> {
        static M: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
        M.get_or_init(|| tokio::sync::Mutex::new(()))
    }

    #[test]
    fn event_name_matches_serde_tag() {
        // Pinning the SSE event name → JSON tag mapping. The UI's
        // EventSource.addEventListener('step'|'ok'|'error', …) must
        // see the SAME names that serde emits in the data payload.
        assert_eq!(
            UpdateEvent::Step {
                stream: "stdout",
                message: "x".into(),
            }
            .event_name(),
            "step"
        );
        assert_eq!(
            UpdateEvent::Ok {
                message: "x".into(),
            }
            .event_name(),
            "ok"
        );
        assert_eq!(
            UpdateEvent::Error {
                message: "x".into(),
            }
            .event_name(),
            "error"
        );
    }

    #[tokio::test]
    async fn run_update_streams_subprocess_stdout_then_ok_on_success() {
        let _serial = test_gate_serializer().lock().await;
        // Use `/bin/sh -c 'echo hi'` as a stand-in for `vpnctl
        // geoip-update` — we want to prove the wiring (stdout →
        // Step → Ok), not the geoip download itself.
        //
        // Direct binary swap: `resolve_vpnctl_bin` returns whatever
        // we pass to `run_update`, so just hand it `/bin/sh`. The
        // `geoip-update` arg becomes the script — which means we
        // can't easily test a bare /bin/sh invocation. Instead use
        // /bin/echo: vpnctl_bin="/bin/echo", arg="geoip-update" →
        // echoes the literal string "geoip-update" and exits 0.
        let mut stream = run_update("/bin/echo".to_string());
        let mut steps = Vec::new();
        let mut terminal = None;
        while let Some(ev) = stream.next().await {
            match &ev {
                UpdateEvent::Step { message, .. } => steps.push(message.clone()),
                UpdateEvent::Ok { .. } | UpdateEvent::Error { .. } => {
                    terminal = Some(ev);
                    break;
                }
            }
        }
        assert!(
            steps.iter().any(|m| m == "geoip-update"),
            "expected stdout step with echoed arg, got: {steps:?}"
        );
        assert!(
            matches!(terminal, Some(UpdateEvent::Ok { .. })),
            "expected terminal Ok, got: {terminal:?}"
        );
    }

    #[tokio::test]
    async fn run_update_emits_error_when_binary_missing() {
        let _serial = test_gate_serializer().lock().await;
        // Spawn a path that definitely doesn't exist → spawn fails
        // → terminal Error event, no Step events. Use a tempdir
        // so the test is portable across Linux distros (don't
        // assume `/var/empty/` exists).
        let dir = tempfile::TempDir::new().expect("tempdir");
        let bin = dir.path().join("definitely-not-a-real-binary-xyz123");
        let mut stream = run_update(bin.to_string_lossy().into_owned());
        let ev = stream.next().await.expect("expected at least one event");
        match &ev {
            UpdateEvent::Error { message } => {
                assert!(
                    message.starts_with("vpnctl admin: "),
                    "every /admin/* error message carries the unified prefix, got: {message}"
                );
            }
            other => panic!("expected terminal Error on spawn failure, got: {other:?}"),
        }
        // Stream must be exhausted after the terminal event.
        assert!(stream.next().await.is_none(), "stream must end after Error");
    }

    #[tokio::test]
    async fn run_update_emits_error_when_subprocess_exits_nonzero() {
        let _serial = test_gate_serializer().lock().await;
        // /bin/false exits 1 without output. Should yield zero
        // Steps + a terminal Error mentioning the exit status.
        let mut stream = run_update("/bin/false".to_string());
        let mut steps = 0;
        let mut terminal = None;
        while let Some(ev) = stream.next().await {
            match &ev {
                UpdateEvent::Step { .. } => steps += 1,
                _ => {
                    terminal = Some(ev);
                    break;
                }
            }
        }
        assert_eq!(steps, 0, "/bin/false has no output");
        match terminal {
            Some(UpdateEvent::Error { message }) => {
                assert!(
                    message.contains("exited with"),
                    "error message must mention exit status, got: {message}"
                );
                assert!(
                    message.starts_with("vpnctl admin: "),
                    "every /admin/* error message carries the unified prefix, got: {message}"
                );
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn run_update_second_concurrent_fire_returns_already_running_error() {
        let _serial = test_gate_serializer().lock().await;
        // Pavel UX: a button the operator can double-click. The
        // second click must NOT spawn a second subprocess (would
        // race on the .partial.gz filename + hold a second blocking
        // thread for the full download duration). Instead it gets
        // a single Error event explaining the situation.
        //
        // We acquire a permit manually so the gate is "busy" without
        // having to spawn a real long-running subprocess that would
        // make the test slow + flaky.
        let _hold = concurrent_fire_gate()
            .try_acquire()
            .expect("first acquire must succeed (serializer ensures no other test holds it)");
        let mut stream = run_update("/bin/echo".to_string());
        let ev = stream.next().await.expect("expected one Error event");
        match &ev {
            UpdateEvent::Error { message } => {
                assert!(
                    message.contains("already running"),
                    "expected already-running diagnostic, got: {message}"
                );
                assert!(
                    message.starts_with("vpnctl admin: "),
                    "unified prefix required, got: {message}"
                );
            }
            other => panic!("expected Error event, got: {other:?}"),
        }
        assert!(
            stream.next().await.is_none(),
            "stream must end after the already-running Error"
        );
        // Permit drops here, releasing the gate for other tests.
        drop(_hold);
    }
}
