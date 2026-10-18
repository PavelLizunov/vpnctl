use std::process::{Command, Stdio};
use std::sync::OnceLock;

use serde::Serialize;
use tokio::sync::{Semaphore, mpsc};
use tokio_stream::wrappers::ReceiverStream;

fn concurrent_fire_gate() -> &'static Semaphore {
    static GATE: OnceLock<Semaphore> = OnceLock::new();
    GATE.get_or_init(|| Semaphore::new(1))
}

pub const DEFAULT_VPNCTL_BIN: &str = "/usr/local/bin/vpnctl";

pub fn resolve_vpnctl_bin() -> String {
    std::env::var("VPNCTLD_VPNCTL_BIN").unwrap_or_else(|_| DEFAULT_VPNCTL_BIN.to_string())
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum UpdateEvent {
    Step {
        stream: &'static str,
        message: String,
    },
    Ok {
        message: String,
    },
    Error {
        message: String,
    },
}

impl UpdateEvent {
    pub fn event_name(&self) -> &'static str {
        match self {
            UpdateEvent::Step { .. } => "step",
            UpdateEvent::Ok { .. } => "ok",
            UpdateEvent::Error { .. } => "error",
        }
    }
}

pub fn run_update(vpnctl_bin: String) -> ReceiverStream<UpdateEvent> {
    let (tx, rx) = mpsc::channel(64);
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
        }
    }
    ReceiverStream::new(rx)
}

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
    let _ = h_out.join();
    let _ = h_err.join();

    let terminal = match status {
        Ok(s) if s.success() => UpdateEvent::Ok {
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
            break;
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use tokio_stream::StreamExt;

    fn test_gate_serializer() -> &'static tokio::sync::Mutex<()> {
        static M: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
        M.get_or_init(|| tokio::sync::Mutex::new(()))
    }

    async fn await_gate_free() {
        for _ in 0..200 {
            if concurrent_fire_gate().available_permits() > 0 {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        panic!("gate must become free within 1s (no real subprocess holds it this long)");
    }

    #[test]
    fn event_name_matches_serde_tag() {
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

    #[cfg(unix)]
    #[tokio::test]
    async fn run_update_streams_subprocess_stdout_then_ok_on_success() {
        let _serial = test_gate_serializer().lock().await;
        await_gate_free().await;
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
        await_gate_free().await;
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
        assert!(stream.next().await.is_none(), "stream must end after Error");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn run_update_emits_error_when_subprocess_exits_nonzero() {
        let _serial = test_gate_serializer().lock().await;
        await_gate_free().await;
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
        await_gate_free().await;
        let _hold = concurrent_fire_gate()
            .try_acquire()
            .expect("first acquire must succeed (gate confirmed free above)");
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
        drop(_hold);
    }
}
