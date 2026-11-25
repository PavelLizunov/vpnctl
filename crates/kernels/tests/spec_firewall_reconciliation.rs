#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::{BTreeSet, HashMap};
use std::sync::Mutex;

use async_trait::async_trait;
use vpnctl_core::{
    CoreError, KernelId, ProtocolId, RenderCtx, Result, Server, ServerId, SshTransport,
};
use vpnctl_kernels::{build_registry, reconcile_firewall};

#[derive(Debug, Default)]
struct RecordingTransport {
    execs: Mutex<Vec<String>>,
    unprivileged: Mutex<Vec<String>>,
    uploads: Mutex<Vec<String>>,
    fail_exec: bool,
    stdout: String,
}

#[async_trait]
impl SshTransport for RecordingTransport {
    async fn exec(&self, cmd: &str) -> Result<String> {
        self.execs.lock().unwrap().push(cmd.to_string());
        if self.fail_exec {
            return Err(CoreError::Transport(
                "fixture firewall transport failure".into(),
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
        panic!("firewall reconciliation must not read files, attempted {path}");
    }
}

fn server(enabled: &[&str], kernels: &[&str], ssh_port: u16) -> Server {
    Server {
        id: ServerId("firewall-spec".into()),
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

fn is_port_token(token: &str) -> bool {
    let Some((transport, port)) = token.split_once(':') else {
        return false;
    };
    matches!(transport, "tcp" | "udp")
        && !port.is_empty()
        && port.bytes().all(|byte| byte.is_ascii_digit())
        && port.parse::<u16>().is_ok()
}

/// The command's input contract: the `cleanup` action followed by
/// space-separated `tcp:PORT` / `udp:PORT` argument tokens.
fn cleanup_arguments(command: &str) -> Vec<String> {
    let tokens: Vec<&str> = command.split_whitespace().collect();
    for (index, token) in tokens.iter().enumerate() {
        if *token != "cleanup" {
            continue;
        }
        let arguments = &tokens[index + 1..];
        if !arguments.is_empty() && arguments.iter().all(|token| is_port_token(token)) {
            return arguments.iter().map(|token| (*token).to_string()).collect();
        }
    }
    panic!("command has no `cleanup` action followed by port tokens: {command}");
}

fn assert_single_privileged_cleanup(transport: &RecordingTransport, expected: &[&str]) {
    assert!(
        transport.unprivileged.lock().unwrap().is_empty(),
        "firewall reconciliation must use the privileged exec path only"
    );
    assert!(
        transport.uploads.lock().unwrap().is_empty(),
        "firewall reconciliation must not upload files"
    );

    let execs = transport.execs.lock().unwrap();
    assert_eq!(
        execs.len(),
        1,
        "expected exactly one privileged exec, got {execs:#?}"
    );
    let arguments = cleanup_arguments(&execs[0]);
    let actual: BTreeSet<&str> = arguments.iter().map(String::as_str).collect();
    let expected: BTreeSet<&str> = expected.iter().copied().collect();
    assert_eq!(
        actual, expected,
        "unexpected cleanup arguments in {:?}",
        execs[0]
    );
    assert_eq!(
        arguments.len(),
        actual.len(),
        "cleanup argument tokens must be deduplicated: {arguments:?}"
    );
}

#[tokio::test]
async fn cleanup_protects_dynamic_ports_and_caddy_acme_port() {
    let registry = build_registry().unwrap();

    let naive_server = server(&["naive", "wireguard"], &["caddy", "sing-box"], 2222);
    let naive_secrets = secrets(&[("wireguard.listen_port", "52820")]);
    let naive_ctx = RenderCtx::new(&naive_server, &naive_secrets);
    let naive_ssh = RecordingTransport::default();
    assert!(
        reconcile_firewall(&naive_ssh, &registry, &naive_ctx, &[])
            .await
            .unwrap()
            .is_none()
    );
    assert_single_privileged_cleanup(&naive_ssh, &["tcp:2222", "tcp:443", "udp:52820", "tcp:80"]);

    let vless_ws_server = server(&["vless-ws"], &["caddy", "sing-box"], 2200);
    let vless_ws_secrets = secrets(&[("vlessws.listen_port", "2087")]);
    let vless_ws_ctx = RenderCtx::new(&vless_ws_server, &vless_ws_secrets);
    let vless_ws_ssh = RecordingTransport::default();
    assert!(
        reconcile_firewall(&vless_ws_ssh, &registry, &vless_ws_ctx, &[])
            .await
            .unwrap()
            .is_none()
    );
    assert_single_privileged_cleanup(&vless_ws_ssh, &["tcp:2200", "tcp:2087", "tcp:80"]);
}

#[tokio::test]
async fn cleanup_deduplicates_ports_shared_by_protocols() {
    let registry = build_registry().unwrap();
    let server = server(&["naive", "vmess"], &["caddy", "xray"], 2222);
    let secrets = secrets(&[("vmess.listen_port", "443")]);
    let ctx = RenderCtx::new(&server, &secrets);
    let ssh = RecordingTransport::default();

    assert!(
        reconcile_firewall(&ssh, &registry, &ctx, &[])
            .await
            .unwrap()
            .is_none()
    );

    assert_single_privileged_cleanup(&ssh, &["tcp:2222", "tcp:443", "tcp:80"]);
}

#[tokio::test]
async fn transport_failure_is_returned_to_the_caller() {
    let registry = build_registry().unwrap();
    let server = server(&["naive"], &["caddy"], 22);
    let secrets = secrets(&[]);
    let ctx = RenderCtx::new(&server, &secrets);
    let ssh = RecordingTransport {
        fail_exec: true,
        ..RecordingTransport::default()
    };

    let error = reconcile_firewall(&ssh, &registry, &ctx, &[])
        .await
        .unwrap_err();
    match error {
        CoreError::Transport(message) => assert!(
            message.contains("fixture firewall transport failure"),
            "unexpected transport message: {message}"
        ),
        other => panic!("expected transport error, got {other:?}"),
    }
    assert_eq!(ssh.execs.lock().unwrap().len(), 1);
    assert!(ssh.unprivileged.lock().unwrap().is_empty());
    assert!(ssh.uploads.lock().unwrap().is_empty());
}

#[tokio::test]
async fn empty_protocol_set_still_cleans_stale_rules_and_protects_ssh() {
    let registry = build_registry().unwrap();
    let server = server(&[], &["caddy", "sing-box"], 2222);
    let secrets = secrets(&[]);
    let ctx = RenderCtx::new(&server, &secrets);
    let ssh = RecordingTransport::default();

    assert!(
        reconcile_firewall(&ssh, &registry, &ctx, &[])
            .await
            .unwrap()
            .is_none()
    );

    assert_single_privileged_cleanup(&ssh, &["tcp:2222"]);
}

#[tokio::test]
async fn unknown_enabled_protocol_fails_without_touching_the_firewall() {
    let registry = build_registry().unwrap();
    let server = server(&["naive", "not-registered"], &["caddy"], 22);
    let secrets = secrets(&[]);
    let ctx = RenderCtx::new(&server, &secrets);
    let ssh = RecordingTransport::default();

    assert!(
        reconcile_firewall(&ssh, &registry, &ctx, &[])
            .await
            .is_err(),
        "an unknown enabled protocol must fail the reconciliation"
    );
    assert!(
        ssh.execs.lock().unwrap().is_empty(),
        "an unknown enabled protocol must not mutate the firewall"
    );
    assert!(ssh.unprivileged.lock().unwrap().is_empty());
    assert!(ssh.uploads.lock().unwrap().is_empty());
}

#[tokio::test]
async fn cleanup_reports_unmarked_ports_without_echoing_unexpected_output() {
    let registry = build_registry().unwrap();
    let server = server(&[], &["sing-box"], 22);
    let secrets = secrets(&[]);
    let ctx = RenderCtx::new(&server, &secrets);
    let ssh = RecordingTransport {
        stdout: "tcp:8443 udp:53 bad:44 malformed tcp:100000".into(),
        ..RecordingTransport::default()
    };

    let warning = reconcile_firewall(&ssh, &registry, &ctx, &[])
        .await
        .unwrap();

    assert_eq!(
        warning.as_deref(),
        Some("UFW retained unmarked allowances with no public listener: 8443/tcp, 53/udp"),
    );
}

#[tokio::test]
async fn cleanup_reports_nftables_drop_policy_blocked_ports_without_echoing_garbage() {
    let registry = build_registry().unwrap();
    let server = server(&[], &["sing-box"], 22);
    let secrets = secrets(&[]);
    let ctx = RenderCtx::new(&server, &secrets);
    let ssh = RecordingTransport {
        stdout: "nft-blocked:tcp:8443 nft-blocked:udp:53 nft-blocked:bad:44 garbage".into(),
        ..RecordingTransport::default()
    };

    let warning = reconcile_firewall(&ssh, &registry, &ctx, &[])
        .await
        .unwrap();

    assert_eq!(
        warning.as_deref(),
        Some(
            "nftables input chain has policy drop without an explicit accept rule for: 8443/tcp, 53/udp (UFW is inactive or not installed)"
        ),
    );
}

#[test]
fn embedded_nftables_drop_policy_checker_detects_missing_and_allowed_ports() {
    let script = include_str!("../src/firewall/ufw.py");
    let driver = r#"
import importlib.util, json, sys
namespace = {}
exec(sys.stdin.read(), namespace)
find_blocked = namespace["find_nft_blocked_ports"]

blocked_ruleset = {
    "nftables": [
        {"table": {"family": "inet", "name": "hostfw"}},
        {"chain": {"family": "inet", "table": "hostfw", "name": "input", "type": "filter", "hook": "input", "prio": 0, "policy": "drop"}},
        {"rule": {"family": "inet", "table": "hostfw", "chain": "input", "expr": [
            {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "lo"}},
            {"accept": None},
        ]}},
        {"rule": {"family": "inet", "table": "hostfw", "chain": "input", "expr": [
            {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": {"set": [22, 443]}}},
            {"accept": None},
        ]}},
    ]
}
ports = {("tcp", 22), ("tcp", 8443), ("udp", 53)}
assert find_blocked(blocked_ruleset, ports) == [("tcp", 8443), ("udp", 53)], find_blocked(blocked_ruleset, ports)

fixed_ruleset = {
    "nftables": blocked_ruleset["nftables"] + [
        {"rule": {"family": "inet", "table": "hostfw", "chain": "input", "expr": [
            {"match": {"op": "==", "left": {"ct": {"key": "state"}}, "right": "new"}},
            {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 8443}},
            {"accept": None},
        ]}},
        {"rule": {"family": "inet", "table": "hostfw", "chain": "input", "expr": [
            {"match": {"op": "==", "left": {"payload": {"protocol": "udp", "field": "dport"}}, "right": {"set": [{"range": [50, 60]}]}}},
            {"accept": None},
        ]}},
    ]
}
assert find_blocked(fixed_ruleset, ports) == [], find_blocked(fixed_ruleset, ports)

# Negated / inequality rules must not falsely mark excluded ports as allowed.
negated_ruleset = {
    "nftables": [
        {"table": {"family": "inet", "name": "hostfw"}},
        {"chain": {"family": "inet", "table": "hostfw", "name": "input", "hook": "input", "policy": "drop"}},
        {"rule": {"family": "inet", "table": "hostfw", "chain": "input", "expr": [
            {"match": {"op": "==", "left": {"meta": {"key": "l4proto"}}, "right": "tcp"}},
            {"match": {"op": "!=", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 443}},
            {"accept": None},
        ]}},
    ]
}
assert find_blocked(negated_ruleset, [("tcp", 443)]) == [("tcp", 443)], find_blocked(negated_ruleset, [("tcp", 443)])
print("NFT_CHECK_OK")
"#;
    let mut child = std::process::Command::new("python3")
        .args(["-c", driver])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    {
        use std::io::Write;
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(script.as_bytes())
            .unwrap();
    }
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "python check failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "NFT_CHECK_OK"
    );
}
