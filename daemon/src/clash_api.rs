//! Track-3 chunk 1 — clash-api client.
//!
//! sing-box exposes a Clash-compatible JSON API on `127.0.0.1:9090`
//! (loopback only — see `kernels::sing_box::render_config`'s
//! `experimental.clash_api.external_controller` block, landed in
//! commit 537342c). This module talks to that API to pull live
//! per-connection traffic counters.
//!
//! # Why over SSH
//!
//! The clash-api binds to loopback to avoid exposing yet another port
//! on the public VPN node. The daemon (running on the homelab on
//! `192.168.0.236`) reaches it by SSH-ing into the VPN node and
//! running `curl` from there:
//!
//! ```text
//! vpnctld ── ssh ──▶ vpn-node ── curl 127.0.0.1:9090 ──▶ sing-box
//! ```
//!
//! Pros vs alternatives:
//! - **No new HTTP-client dep.** We already have a hardened SSH
//!   transport (`vpnctl-ssh::RusshTransport`) with host-key pinning
//!   and proxy-jump support. Adding `reqwest` would pull tls
//!   transitive deps that `cargo-deny` would have to allowlist
//!   (CLAUDE.md "no openssl-sys / native-tls").
//! - **No port forwarding.** SSH `-L` tunnels need lifecycle
//!   management; one-shot `curl` over `exec` is stateless.
//! - **No exposing 9090 externally.** Loopback stays loopback.
//!
//! # What we poll
//!
//! sing-box's `/connections` endpoint returns a snapshot in a single
//! GET — `{download_total, upload_total, connections: [...]}`. The
//! traffic-rate stream (`/traffic`) is SSE which would hang `curl`
//! without `--max-time`; we don't need rate-per-second yet, only
//! deltas between polls.
//!
//! # Per-user attribution
//!
//! Each `Connection.metadata.user` carries the inbound user name as
//! configured in sing-box. For our `vless+reality` inbounds the user
//! name is the operator-typed `User.id` (NOT the UUID — that's a
//! protocol-level detail). The poller (chunk 2) joins on
//! `metadata.user == User.id` to attribute traffic per user.
//!
//! Connections without a `user` field (rare — outbound system
//! traffic) are kept in the snapshot but excluded from per-user
//! attribution.
//!
//! # Schema notes
//!
//! Field names below match sing-box's actual JSON output. The
//! Clash project upstream uses camelCase (`downloadTotal`,
//! `uploadTotal`), and sing-box preserves those. Our `serde`
//! derives use `#[serde(rename_all = "camelCase")]` to bridge
//! between Rust snake_case and the wire format.

use async_trait::async_trait;
use serde::Deserialize;
use vpnctl_core::SshTransport;

/// One active connection as reported by sing-box.
///
/// `upload` / `download` are byte counts since this connection
/// opened — NOT a rate. The poller diff's two snapshots to compute
/// per-interval traffic.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Connection {
    /// Connection id assigned by sing-box. Stable for the lifetime
    /// of the connection.
    pub id: String,
    /// Bytes uploaded by the client over this connection so far.
    pub upload: u64,
    /// Bytes downloaded to the client over this connection so far.
    pub download: u64,
    /// ISO-8601 wall-clock connection start. Useful for ageing out
    /// connections in the UI.
    pub start: String,
    pub metadata: ConnectionMeta,
}

/// Metadata sing-box attaches to each connection. Most fields are
/// informational; `user` is the per-inbound user name we attribute
/// traffic against.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionMeta {
    /// `tcp` or `udp`.
    pub network: String,
    /// Destination IP as a string (sing-box renders both v4 and v6).
    /// Empty for connections sing-box hasn't resolved yet — we treat
    /// that as `""` rather than rejecting the row.
    ///
    /// Field name is `destinationIP` (uppercase IP) on the wire, which
    /// is NOT what `rename_all = "camelCase"` produces (it would expect
    /// `destinationIp`). Clash spec uses uppercase initialisms — we
    /// override per-field. Same story for `sourceIP` below.
    #[serde(default, rename = "destinationIP")]
    pub destination_ip: String,
    /// Destination port as a STRING — Clash wire format quirk.
    #[serde(default)]
    pub destination_port: String,
    /// Phase 4c — source IP of the client behind the VLESS / TUIC
    /// auth. This is the **real public IP** of the user's device
    /// as seen by sing-box AFTER the inbound auth, NOT a NAT'd
    /// internal address. Preserved by sing-box despite NM-11
    /// (which only drops `user`), so it gives us a per-device
    /// attribution proxy: same source IP across multiple
    /// connections = (usually) same device. Joining against
    /// `sub_access_log.ip` lets us map source IP → user_id when
    /// the same client recently fetched their subscription URL.
    #[serde(default, rename = "sourceIP")]
    pub source_ip: String,
    /// Source port (Clash wire-format quirk: also a STRING).
    /// Per-connection, changes every dial.
    #[serde(default)]
    pub source_port: String,
    /// DNS name the client asked for, when sing-box resolved one
    /// (typically present for HTTPS SNI / HTTP Host). Empty when
    /// sing-box only got the raw IP. Far more useful than
    /// `destination_ip` for the operator («youtube.com» vs
    /// «172.217.16.142»).
    #[serde(default)]
    pub host: String,
    /// Inbound user name as configured in sing-box. Maps to our
    /// `User.id` (operator-typed, e.g. "alice"), NOT to the protocol
    /// UUID. **Currently always None on production** because of
    /// NM-11 (sing-box upstream's TrackerMetadata.MarshalJSON
    /// drops this field). See NM-11 in CLAUDE.md for the upstream
    /// fix path.
    #[serde(default)]
    pub user: Option<String>,
}

/// Snapshot of `/connections` — totals plus the per-connection
/// detail. The totals are server-wide lifetime byte counts; the
/// per-connection numbers are per-connection lifetime.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    /// Bytes downloaded across all connections since sing-box start.
    /// Resets when the daemon is restarted on the node.
    #[serde(default)]
    pub download_total: u64,
    #[serde(default)]
    pub upload_total: u64,
    /// Currently-active connections.
    #[serde(default)]
    pub connections: Vec<Connection>,
}

/// Polling errors. Three categories matter for the eventual UI:
/// transport (server unreachable / SSH down), parse (clash-api
/// returned junk — likely sing-box version drift), and the
/// `command exit != 0` case (curl failed because the endpoint isn't
/// listening, e.g. an old node deployed before commit 537342c that
/// has no clash-api block). The latter shows up as an
/// `Ssh("exit code 7")` from the SSH transport and gets surfaced
/// under `Transport` — chunk 2 will inspect the exit code more
/// carefully and add an `Unsupported` variant if needed.
#[derive(Debug, thiserror::Error)]
pub enum ClashApiError {
    /// SSH layer failed: connection error, key mismatch, command
    /// non-zero exit (curl can't reach 127.0.0.1:9090).
    #[error("ssh transport: {0}")]
    Transport(String),
    /// Got a response, but it didn't parse as the expected JSON
    /// schema. Surfaces sing-box version drift or a clash-api
    /// build that returns a different shape.
    #[error("parse: {0}")]
    Parse(String),
}

/// One-shot curl command sent to the node. Pinned to localhost so a
/// compromised DNS on the node can't redirect us anywhere; pinned
/// `--max-time 5` so a hung clash-api doesn't wedge the poller.
///
/// Public so chunk 2 can audit-log it verbatim.
pub const POLL_CONNECTIONS_CMD: &str = concat!(
    "curl -fsS --max-time 5 ",
    "http://127.0.0.1:9090/connections",
);

/// Trait the poller calls. Defined as a trait so chunk 2 can wrap
/// it with a retry layer / metrics layer without re-implementing
/// the parser.
#[async_trait]
pub trait ClashClient: Send + Sync {
    async fn snapshot(&self) -> Result<Snapshot, ClashApiError>;
}

/// Default implementation: SSH-curl to one VPN node.
#[derive(Debug)]
pub struct SshClashClient<'a> {
    ssh: &'a dyn SshTransport,
}

impl<'a> SshClashClient<'a> {
    pub fn new(ssh: &'a dyn SshTransport) -> Self {
        Self { ssh }
    }
}

#[async_trait]
impl ClashClient for SshClashClient<'_> {
    async fn snapshot(&self) -> Result<Snapshot, ClashApiError> {
        let raw = self
            .ssh
            .exec(POLL_CONNECTIONS_CMD)
            .await
            .map_err(|e| ClashApiError::Transport(e.to_string()))?;
        // Empty body = curl succeeded but the endpoint returned 200
        // with no content — defensive cast to "no connections".
        // Anything non-empty must parse as the schema or it's a
        // version drift we want to surface.
        if raw.trim().is_empty() {
            return Ok(Snapshot::default());
        }
        serde_json::from_str(&raw).map_err(|e| ClashApiError::Parse(e.to_string()))
    }
}

impl Snapshot {
    /// Sum of per-user bytes (upload + download) across this
    /// snapshot. Useful for chunk 3's "live throughput per user"
    /// rendering. Connections without a `user` are excluded.
    pub fn bytes_per_user(&self) -> std::collections::HashMap<String, (u64, u64)> {
        let mut out: std::collections::HashMap<String, (u64, u64)> =
            std::collections::HashMap::new();
        for c in &self.connections {
            if let Some(u) = c.metadata.user.as_deref() {
                let entry = out.entry(u.to_string()).or_default();
                entry.0 = entry.0.saturating_add(c.upload);
                entry.1 = entry.1.saturating_add(c.download);
            }
        }
        out
    }

    /// Number of connections attributable to a given user. O(n)
    /// because n is bounded by `connections.len()` (typically <100
    /// per VPN node) — a HashMap pre-pass would be premature.
    pub fn connection_count_for_user(&self, user: &str) -> usize {
        self.connections
            .iter()
            .filter(|c| c.metadata.user.as_deref() == Some(user))
            .count()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use vpnctl_ssh::MockTransport;

    /// Minimal valid `/connections` response with one TCP connection
    /// attributed to user "alice". This is the schema we expect from
    /// sing-box ≥ 1.10's clash-api implementation.
    const SAMPLE_RESPONSE: &str = r#"{
        "downloadTotal": 8192,
        "uploadTotal": 1024,
        "connections": [
            {
                "id": "conn-abc-123",
                "upload": 256,
                "download": 4096,
                "start": "2026-05-15T20:30:00Z",
                "metadata": {
                    "network": "tcp",
                    "destinationIP": "1.2.3.4",
                    "destinationPort": "443",
                    "user": "alice"
                }
            },
            {
                "id": "conn-def-456",
                "upload": 100,
                "download": 200,
                "start": "2026-05-15T20:31:00Z",
                "metadata": {
                    "network": "udp",
                    "destinationIP": "8.8.8.8",
                    "destinationPort": "53",
                    "user": "bob"
                }
            }
        ]
    }"#;

    #[test]
    fn parse_real_clash_response_extracts_totals_and_per_connection_data() {
        let snap: Snapshot = serde_json::from_str(SAMPLE_RESPONSE).unwrap();
        assert_eq!(snap.download_total, 8192);
        assert_eq!(snap.upload_total, 1024);
        assert_eq!(snap.connections.len(), 2);
        assert_eq!(snap.connections[0].id, "conn-abc-123");
        assert_eq!(snap.connections[0].metadata.network, "tcp");
        assert_eq!(snap.connections[0].metadata.destination_ip, "1.2.3.4");
        assert_eq!(snap.connections[0].metadata.user.as_deref(), Some("alice"));
    }

    #[test]
    fn parse_empty_connections_array_is_valid_quiet_node() {
        let snap: Snapshot =
            serde_json::from_str(r#"{"downloadTotal": 0, "uploadTotal": 0, "connections": []}"#)
                .unwrap();
        assert!(snap.connections.is_empty());
        assert_eq!(snap.download_total, 0);
    }

    #[test]
    fn parse_connection_without_user_field_keeps_row_with_user_none() {
        // Outbound system traffic (e.g. sing-box's own DNS lookups)
        // arrives without a `user` — we keep the connection in the
        // snapshot so the totals stay correct, but bytes_per_user
        // skips it.
        let snap: Snapshot = serde_json::from_str(
            r#"{"downloadTotal":0,"uploadTotal":0,"connections":[{
                "id":"sys-1","upload":10,"download":20,
                "start":"2026-05-15T20:30:00Z",
                "metadata":{"network":"udp","destinationIP":"1.1.1.1","destinationPort":"53"}
            }]}"#,
        )
        .unwrap();
        assert_eq!(snap.connections.len(), 1);
        assert!(snap.connections[0].metadata.user.is_none());
        assert!(
            snap.bytes_per_user().is_empty(),
            "user-less connections must not appear in per-user attribution"
        );
    }

    #[test]
    fn bytes_per_user_aggregates_across_connections() {
        // Two TCP connections from alice + one UDP from bob — sum
        // upload/download per user.
        let snap: Snapshot = serde_json::from_str(
            r#"{"downloadTotal":0,"uploadTotal":0,"connections":[
                {"id":"a1","upload":100,"download":200,"start":"x","metadata":{"network":"tcp","destinationIP":"","destinationPort":"","user":"alice"}},
                {"id":"a2","upload":50,"download":75,"start":"x","metadata":{"network":"tcp","destinationIP":"","destinationPort":"","user":"alice"}},
                {"id":"b1","upload":10,"download":20,"start":"x","metadata":{"network":"udp","destinationIP":"","destinationPort":"","user":"bob"}}
            ]}"#,
        )
        .unwrap();
        let per_user = snap.bytes_per_user();
        assert_eq!(per_user.get("alice"), Some(&(150, 275)));
        assert_eq!(per_user.get("bob"), Some(&(10, 20)));
    }

    #[test]
    fn connection_count_for_user_counts_only_matching_rows() {
        let snap: Snapshot = serde_json::from_str(SAMPLE_RESPONSE).unwrap();
        assert_eq!(snap.connection_count_for_user("alice"), 1);
        assert_eq!(snap.connection_count_for_user("bob"), 1);
        assert_eq!(snap.connection_count_for_user("eve"), 0);
    }

    #[tokio::test]
    async fn snapshot_via_mock_ssh_returns_parsed_data() {
        let ssh = MockTransport::new();
        ssh.expect(POLL_CONNECTIONS_CMD, SAMPLE_RESPONSE);
        let client = SshClashClient::new(&ssh);
        let snap = client.snapshot().await.unwrap();
        assert_eq!(snap.connections.len(), 2);
        assert_eq!(snap.connections[1].metadata.user.as_deref(), Some("bob"));
    }

    #[tokio::test]
    async fn snapshot_with_empty_response_is_default_quiet_node() {
        // Mock returns "" by default for unregistered commands. The
        // contract is that an empty body is treated as "no
        // connections" rather than a parse error — handles the case
        // where sing-box just started up and hasn't seen a client
        // yet.
        let ssh = MockTransport::new();
        ssh.expect(POLL_CONNECTIONS_CMD, "");
        let client = SshClashClient::new(&ssh);
        let snap = client.snapshot().await.unwrap();
        assert_eq!(snap.connections.len(), 0);
        assert_eq!(snap.upload_total, 0);
    }

    #[tokio::test]
    async fn snapshot_with_garbage_response_returns_parse_error() {
        let ssh = MockTransport::new();
        ssh.expect(POLL_CONNECTIONS_CMD, "{this is not valid json");
        let client = SshClashClient::new(&ssh);
        let err = client.snapshot().await.unwrap_err();
        assert!(
            matches!(err, ClashApiError::Parse(_)),
            "expected ClashApiError::Parse, got {err:?}"
        );
    }

    #[test]
    fn poll_command_pins_loopback_and_timeout() {
        // Two security-critical invariants pinned in code so a future
        // edit to POLL_CONNECTIONS_CMD that drops either lands in
        // review with a failing test:
        //   1. URL is `http://127.0.0.1:9090` — DNS-free, can't be
        //      redirected by a compromised resolver on the node.
        //   2. `--max-time 5` is set — a hung sing-box doesn't wedge
        //      the poller indefinitely.
        assert!(
            POLL_CONNECTIONS_CMD.contains("http://127.0.0.1:9090"),
            "poll command must hit literal loopback (no DNS)"
        );
        assert!(
            POLL_CONNECTIONS_CMD.contains("--max-time"),
            "poll command must cap curl runtime"
        );
        assert!(
            POLL_CONNECTIONS_CMD.contains("-fsS"),
            "poll command must use -f (fail on HTTP error) -s -S"
        );
    }
}
