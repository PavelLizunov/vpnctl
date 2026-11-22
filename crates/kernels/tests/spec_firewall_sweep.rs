//! Spec tests for the periodic managed-firewall sweep.
//!
//! `sweep_firewall` observes a node through one privileged UFW invocation and
//! turns its confirmation lines into typed per-family idle and removal results. These tests
//! pin the command contract, the protected port inventory, and output parsing
//! without touching a real SSH server.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::{BTreeSet, HashMap};
use std::sync::Mutex;

use async_trait::async_trait;
use vpnctl_core::{
    CoreError, KernelId, ProtocolId, RenderCtx, Result, Server, ServerId, SshTransport,
};
use vpnctl_kernels::{FirewallSweep, build_registry, sweep_firewall};

#[derive(Debug, Default)]
struct RecordingTransport {
    execs: Mutex<Vec<String>>,
    unprivileged: Mutex<Vec<String>>,
    uploads: Mutex<Vec<String>>,
    reads: Mutex<Vec<String>>,
    fail_exec: bool,
    stdout: String,
}

#[async_trait]
impl SshTransport for RecordingTransport {
    async fn exec(&self, cmd: &str) -> Result<String> {
        self.execs.lock().unwrap().push(cmd.to_string());
        if self.fail_exec {
            return Err(CoreError::Transport(
                "fixture firewall sweep transport failure".into(),
            ));
        }
        Ok(self.stdout.clone())
    }

    async fn exec_unprivileged(&self, cmd: &str) -> Result<String> {
        self.unprivileged.lock().unwrap().push(cmd.to_string());
        Ok(String::new())
    }

    async fn upload(&self, path: &str, _content: &[u8]) -> Result<()> {
        self.uploads.lock().unwrap().push(path.to_string());
        Ok(())
    }

    async fn read_file(&self, path: &str) -> Result<Vec<u8>> {
        self.reads.lock().unwrap().push(path.to_string());
        Ok(Vec::new())
    }
}

fn server(enabled: &[&str], kernels: &[&str], ssh_port: u16) -> Server {
    Server {
        id: ServerId("firewall-sweep-spec".into()),
        address: "198.51.100.7".into(),
        ssh_port,
        ssh_user: "root".into(),
        kernels: kernels.iter().map(|id| KernelId((*id).into())).collect(),
        enabled_protocols: enabled.iter().map(|id| ProtocolId((*id).into())).collect(),
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    }
}

fn secrets(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
        .collect()
}

/// A sweep argument token, with an address family suffix for confirmed rules.
fn port_token(token: &str) -> Option<(&str, u16)> {
    let (transport, port) = token.split_once(':')?;
    if !matches!(transport, "tcp" | "udp" | "tcp4" | "tcp6" | "udp4" | "udp6") {
        return None;
    }
    if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let port = port.parse::<u16>().ok()?;
    (port != 0).then_some((transport, port))
}

/// The command's input contract: it ends with `vpnctl_ufw sweep` followed by
/// protected tokens, `--`, and the previous idle tokens.
fn sweep_arguments(command: &str) -> (Vec<String>, Vec<String>) {
    let trimmed = command.trim_end();
    let marker = "vpnctl_ufw sweep";
    let start = trimmed
        .rfind(marker)
        .unwrap_or_else(|| panic!("command has no `{marker}` invocation: {command:?}"));
    let suffix = &trimmed[start + marker.len()..];
    assert!(
        suffix.starts_with(' '),
        "`{marker}` must be followed by the sweep arguments: {command:?}"
    );

    let tokens: Vec<&str> = suffix.split_whitespace().collect();
    let separators: Vec<usize> = tokens
        .iter()
        .enumerate()
        .filter_map(|(index, token)| (*token == "--").then_some(index))
        .collect();
    assert_eq!(
        separators.len(),
        1,
        "the sweep invocation must contain exactly one `--`: {command:?}"
    );

    let split = separators[0];
    let protected = &tokens[..split];
    let previous = &tokens[split + 1..];
    for token in protected.iter().chain(previous) {
        assert!(
            port_token(token).is_some(),
            "unexpected non-port token {token:?} in {command:?}"
        );
    }

    (
        protected.iter().map(|token| (*token).to_string()).collect(),
        previous.iter().map(|token| (*token).to_string()).collect(),
    )
}

fn assert_single_sweep(
    transport: &RecordingTransport,
    expected_protected: &[&str],
    expected_previous: &[&str],
) {
    assert!(
        transport.unprivileged.lock().unwrap().is_empty(),
        "the firewall sweep must not use the unprivileged exec path"
    );
    assert!(
        transport.uploads.lock().unwrap().is_empty(),
        "the firewall sweep must not upload files"
    );
    assert!(
        transport.reads.lock().unwrap().is_empty(),
        "the firewall sweep must not read remote files"
    );

    let execs = transport.execs.lock().unwrap();
    assert_eq!(
        execs.len(),
        1,
        "expected exactly one privileged sweep exec, got {execs:#?}"
    );

    let (protected, previous) = sweep_arguments(&execs[0]);

    let actual: BTreeSet<&str> = protected.iter().map(String::as_str).collect();
    let expected: BTreeSet<&str> = expected_protected.iter().copied().collect();
    assert_eq!(
        actual, expected,
        "unexpected protected sweep ports in {:?}",
        execs[0]
    );
    assert_eq!(
        protected.len(),
        actual.len(),
        "protected sweep tokens must be deduplicated: {protected:?}"
    );

    let actual: BTreeSet<&str> = previous.iter().map(String::as_str).collect();
    let expected: BTreeSet<&str> = expected_previous.iter().copied().collect();
    assert_eq!(
        actual, expected,
        "unexpected previous-idle sweep ports in {:?}",
        execs[0]
    );
    assert_eq!(
        previous.len(),
        actual.len(),
        "previous-idle sweep tokens must be deduplicated: {previous:?}"
    );
}

#[tokio::test]
async fn nominal_sweep_protects_ssh_reserved_protocol_and_caddy_ports() {
    let registry = build_registry().unwrap();
    let server = server(
        &["vless+reality", "wireguard", "naive"],
        &["caddy", "sing-box"],
        2222,
    );
    let secrets = secrets(&[
        ("vless.listen_port", "8443"),
        ("wireguard.listen_port", "52820"),
    ]);
    let ctx = RenderCtx::new(&server, &secrets);
    let previous_idle = BTreeSet::from([("tcp4", 9000), ("udp6", 9001)]);
    let ssh = RecordingTransport {
        stdout: "idle tcp4:9000\nidle udp6:9001\nremoved tcp6:8443\nremoved udp4:5353\nfailed tcp4:9999\n".into(),
        ..RecordingTransport::default()
    };

    let sweep: FirewallSweep = sweep_firewall(&ssh, &registry, &ctx, &[2052, 2053], &previous_idle)
        .await
        .unwrap();

    assert_single_sweep(
        &ssh,
        &[
            "tcp:2222",
            "tcp:8443",
            "udp:52820",
            "tcp:443",
            "tcp:80",
            "tcp:2052",
            "udp:2052",
            "tcp:2053",
            "udp:2053",
        ],
        &["tcp4:9000", "udp6:9001"],
    );
    assert_eq!(
        sweep.idle_unmarked,
        BTreeSet::from([("tcp4", 9000), ("udp6", 9001)])
    );
    assert_eq!(
        sweep.removed,
        BTreeSet::from([("tcp6", 8443), ("udp4", 5353)])
    );
    assert_eq!(sweep.failed, Some(("tcp4", 9999)));
}

#[tokio::test]
async fn empty_protocol_set_still_sweeps_once_with_reserved_ports_and_empty_confirmation() {
    let registry = build_registry().unwrap();
    let server = server(&[], &["caddy", "sing-box"], 22);
    let secrets = secrets(&[]);
    let ctx = RenderCtx::new(&server, &secrets);
    let previous_idle = BTreeSet::new();
    let ssh = RecordingTransport::default();

    let sweep: FirewallSweep = sweep_firewall(&ssh, &registry, &ctx, &[22, 51820], &previous_idle)
        .await
        .unwrap();

    assert_single_sweep(&ssh, &["tcp:22", "udp:22", "tcp:51820", "udp:51820"], &[]);
    assert!(
        sweep.idle_unmarked.is_empty(),
        "an empty confirmation reports no idle ports"
    );
    assert!(
        sweep.removed.is_empty(),
        "an empty confirmation reports no removed ports"
    );
}

#[tokio::test]
async fn caddy_acme_port_is_protected_for_vless_ws_front_ports() {
    let registry = build_registry().unwrap();
    let server = server(&["vless-ws"], &["caddy", "sing-box"], 2200);
    let secrets = secrets(&[("vlessws.listen_port", "2087")]);
    let ctx = RenderCtx::new(&server, &secrets);
    let ssh = RecordingTransport::default();

    let sweep: FirewallSweep = sweep_firewall(&ssh, &registry, &ctx, &[], &BTreeSet::new())
        .await
        .unwrap();

    assert_single_sweep(&ssh, &["tcp:2200", "tcp:2087", "tcp:80"], &[]);
    assert!(sweep.idle_unmarked.is_empty());
    assert!(sweep.removed.is_empty());
}

#[tokio::test]
async fn caddy_acme_port_is_absent_when_no_enabled_protocol_is_served_by_caddy() {
    let registry = build_registry().unwrap();
    let server = server(&["vless+reality"], &["caddy", "sing-box"], 2222);
    let secrets = secrets(&[]);
    let ctx = RenderCtx::new(&server, &secrets);
    let ssh = RecordingTransport::default();

    let sweep: FirewallSweep = sweep_firewall(&ssh, &registry, &ctx, &[], &BTreeSet::new())
        .await
        .unwrap();

    assert_single_sweep(&ssh, &["tcp:2222", "tcp:443"], &[]);
    assert!(sweep.idle_unmarked.is_empty());
    assert!(sweep.removed.is_empty());
}

#[tokio::test]
async fn invalid_and_unrelated_output_is_ignored() {
    let registry = build_registry().unwrap();
    let server = server(&[], &["sing-box"], 2222);
    let secrets = secrets(&[]);
    let ctx = RenderCtx::new(&server, &secrets);
    let ssh = RecordingTransport {
        stdout: concat!(
            "idle tcp4:443\n",
            "idle udp6:443\n",
            "idle tcp4:443\n",
            "idle tcp4:1\n",
            "removed udp4:53\n",
            "removed tcp6:53\n",
            "removed udp4:65535\n",
            "idle tcp4:0\n",
            "removed udp4:65536\n",
            "idle tcp4:not-a-port\n",
            "removed udp4:\n",
            "idle sctp:8443\n",
            "idle tcp:9443\n",
            "removed tcp6:-1\n",
            "banana tcp:1234\n",
            "tcp:1234\n",
            "idle\n",
            "removed\n",
            "UFW default input policy is deny\n",
        )
        .into(),
        ..RecordingTransport::default()
    };

    let sweep: FirewallSweep = sweep_firewall(&ssh, &registry, &ctx, &[], &BTreeSet::new())
        .await
        .unwrap();

    assert_single_sweep(&ssh, &["tcp:2222"], &[]);
    assert_eq!(
        sweep.idle_unmarked,
        BTreeSet::from([("tcp4", 443), ("udp6", 443), ("tcp4", 1)])
    );
    assert_eq!(
        sweep.removed,
        BTreeSet::from([("udp4", 53), ("tcp6", 53), ("udp4", 65535)])
    );
}

#[tokio::test]
async fn unregistered_enabled_protocol_fails_before_any_remote_call() {
    let registry = build_registry().unwrap();
    let server = server(&["not-registered"], &["sing-box"], 22);
    let secrets = secrets(&[]);
    let ctx = RenderCtx::new(&server, &secrets);
    let ssh = RecordingTransport::default();

    assert!(
        sweep_firewall(&ssh, &registry, &ctx, &[], &BTreeSet::new())
            .await
            .is_err(),
        "an unknown enabled protocol must fail the sweep"
    );
    assert!(
        ssh.execs.lock().unwrap().is_empty(),
        "an unknown enabled protocol must not mutate the firewall"
    );
    assert!(ssh.unprivileged.lock().unwrap().is_empty());
    assert!(ssh.uploads.lock().unwrap().is_empty());
    assert!(ssh.reads.lock().unwrap().is_empty());
}

#[tokio::test]
async fn transport_failure_propagates() {
    let registry = build_registry().unwrap();
    let server = server(&[], &["sing-box"], 22);
    let secrets = secrets(&[]);
    let ctx = RenderCtx::new(&server, &secrets);
    let ssh = RecordingTransport {
        fail_exec: true,
        ..RecordingTransport::default()
    };

    match sweep_firewall(&ssh, &registry, &ctx, &[], &BTreeSet::new()).await {
        Ok(_) => panic!("expected the transport failure to propagate"),
        Err(CoreError::Transport(message)) => assert!(
            message.contains("fixture firewall sweep transport failure"),
            "unexpected transport message: {message}"
        ),
        Err(other) => panic!("expected transport error, got {other:?}"),
    }

    assert_eq!(ssh.execs.lock().unwrap().len(), 1);
    assert!(ssh.unprivileged.lock().unwrap().is_empty());
    assert!(ssh.uploads.lock().unwrap().is_empty());
    assert!(ssh.reads.lock().unwrap().is_empty());
}
