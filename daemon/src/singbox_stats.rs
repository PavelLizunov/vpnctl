//! Node-side cumulative sing-box V2Ray Stats helper client.
//!
//! The gRPC listener and helper stay on the managed VPN node. vpnctld reaches
//! them through the existing pinned SSH transport and receives one bounded JSON
//! document; upstream counters are never reset by the read.

use std::collections::BTreeMap;

use async_trait::async_trait;
use serde::Deserialize;
use vpnctl_core::{SshTransport, UserId};
use vpnctl_inventory::VpnCumulativeCounter;

const QUERY_STATS_CMD: &str =
    "/usr/local/libexec/vpnctl/singbox-stats-helper --address 127.0.0.1:10085 --timeout 5s";

#[derive(Debug, thiserror::Error)]
pub(crate) enum StatsError {
    #[error("stats helper transport failed: {0}")]
    Transport(String),
    #[error("stats helper returned invalid JSON")]
    InvalidJson,
    #[error("stats helper returned an empty user id")]
    EmptyUser,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct UserTotals {
    upload_total: u64,
    download_total: u64,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct HelperOutput {
    server_upload_total: u64,
    server_download_total: u64,
    uptime_seconds: u64,
    users: BTreeMap<String, UserTotals>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CumulativeSnapshot {
    pub server_upload_total: u64,
    pub server_download_total: u64,
    pub uptime_seconds: u64,
    pub users: Vec<VpnCumulativeCounter>,
}

fn parse_output(raw: &str) -> Result<CumulativeSnapshot, StatsError> {
    let output: HelperOutput = serde_json::from_str(raw).map_err(|_| StatsError::InvalidJson)?;
    let users = output
        .users
        .into_iter()
        .map(|(user_id, totals)| {
            if user_id.is_empty() {
                return Err(StatsError::EmptyUser);
            }
            Ok(VpnCumulativeCounter {
                user_id: UserId(user_id),
                upload_total: totals.upload_total,
                download_total: totals.download_total,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(CumulativeSnapshot {
        server_upload_total: output.server_upload_total,
        server_download_total: output.server_download_total,
        uptime_seconds: output.uptime_seconds,
        users,
    })
}

#[async_trait]
pub(crate) trait StatsClient: Send + Sync {
    async fn cumulative_snapshot(&self) -> Result<CumulativeSnapshot, StatsError>;
}

pub(crate) struct SshStatsClient<'a> {
    ssh: &'a dyn SshTransport,
}

impl<'a> SshStatsClient<'a> {
    pub(crate) fn new(ssh: &'a dyn SshTransport) -> Self {
        Self { ssh }
    }
}

#[async_trait]
impl StatsClient for SshStatsClient<'_> {
    async fn cumulative_snapshot(&self) -> Result<CumulativeSnapshot, StatsError> {
        let raw = self
            .ssh
            .exec(QUERY_STATS_CMD)
            .await
            .map_err(|error| StatsError::Transport(error.to_string()))?;
        parse_output(&raw)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn parse_output_is_sorted_and_exact() {
        let snapshot = parse_output(
            r#"{"server_upload_total":10,"server_download_total":20,"uptime_seconds":30,"users":{"bob":{"upload_total":3,"download_total":4},"alice":{"upload_total":1,"download_total":2}}}"#,
        )
        .unwrap();
        assert_eq!(snapshot.server_upload_total, 10);
        assert_eq!(snapshot.server_download_total, 20);
        assert_eq!(snapshot.uptime_seconds, 30);
        assert_eq!(snapshot.users[0].user_id.0, "alice");
        assert_eq!(snapshot.users[0].upload_total, 1);
        assert_eq!(snapshot.users[1].user_id.0, "bob");
    }

    #[test]
    fn parse_output_rejects_unknown_fields() {
        let error =
            parse_output(r#"{"users":{"alice":{"upload_total":1,"download_total":2,"extra":3}}}"#)
                .unwrap_err();
        assert!(matches!(error, StatsError::InvalidJson));
    }

    #[test]
    fn command_is_loopback_bounded_and_does_not_reset() {
        assert!(QUERY_STATS_CMD.contains("127.0.0.1:10085"));
        assert!(QUERY_STATS_CMD.contains("--timeout 5s"));
        assert!(!QUERY_STATS_CMD.contains("reset"));
    }
}
