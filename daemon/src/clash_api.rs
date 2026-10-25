use async_trait::async_trait;
use serde::Deserialize;
use vpnctl_core::SshTransport;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Connection {
    pub id: String,
    pub upload: u64,
    pub download: u64,
    pub start: String,
    pub metadata: ConnectionMeta,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionMeta {
    pub network: String,
    #[serde(default, rename = "destinationIP")]
    pub destination_ip: String,
    #[serde(default)]
    pub destination_port: String,
    #[serde(default, rename = "sourceIP")]
    pub source_ip: String,
    #[serde(default)]
    pub source_port: String,
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub user: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    #[serde(default)]
    pub download_total: u64,
    #[serde(default)]
    pub upload_total: u64,
    #[serde(default)]
    pub connections: Vec<Connection>,
}

#[derive(Debug, thiserror::Error)]
pub enum ClashApiError {
    #[error("ssh transport: {0}")]
    Transport(String),
    #[error("parse: {0}")]
    Parse(String),
}

pub const POLL_CONNECTIONS_CMD: &str = concat!(
    "curl -fsS --max-time 5 ",
    "http://127.0.0.1:9090/connections",
);

#[allow(clippy::double_must_use)]
#[async_trait]
pub trait ClashClient: Send + Sync {
    async fn snapshot(&self) -> Result<Snapshot, ClashApiError>;
}

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
        if raw.trim().is_empty() {
            return Ok(Snapshot::default());
        }
        serde_json::from_str(&raw).map_err(|e| ClashApiError::Parse(e.to_string()))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use vpnctl_ssh::MockTransport;

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
        assert_eq!(snap.connections[0].upload, 256);
        assert_eq!(snap.connections[0].download, 4096);
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
