use std::collections::BTreeMap;

use async_trait::async_trait;
use serde::Deserialize;
use vpnctl_core::{SshTransport, UserId};
use vpnctl_inventory::VpnCumulativeCounter;

const QUERY_STATS_CMD: &str = r#"
generation() {
    boot=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null) &&
    start=$(systemctl show -p ExecMainStartTimestampMonotonic --value sing-box 2>/dev/null) &&
    [ -n "$boot" ] && [ -n "$start" ] &&
    [ "$start" != 0 ] && printf '%s:%s' "$boot" "$start"
}
before=$(generation) || before=
stats=$(/usr/local/libexec/vpnctl/singbox-stats-helper --address 127.0.0.1:10085 --timeout 5s) || exit $?
after=$(generation) || after=
[ "$before" = "$after" ] || exit 1
printf 'vpnctl-generation:%s\n%s\n' "$before" "$stats"
"#;

#[derive(Debug, thiserror::Error)]
pub(crate) enum StatsError {
    #[error("stats helper transport failed: {0}")]
    Transport(String),
    #[error("stats helper returned invalid JSON")]
    InvalidJson,
    #[error("stats helper returned an empty user id")]
    EmptyUser,
    #[error("stats collection returned an invalid process generation")]
    InvalidGeneration,
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
    pub generation: Option<String>,
    pub users: Vec<VpnCumulativeCounter>,
}

fn parse_output(raw: &str) -> Result<CumulativeSnapshot, StatsError> {
    let (generation, raw) = if let Some(framed) = raw.strip_prefix("vpnctl-generation:") {
        let (token, json) = framed
            .split_once('\n')
            .ok_or(StatsError::InvalidGeneration)?;
        let generation = if token.is_empty() {
            None
        } else {
            if !valid_generation(token) {
                return Err(StatsError::InvalidGeneration);
            }
            Some(token.to_owned())
        };
        (generation, json)
    } else {
        (None, raw)
    };
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
        generation,
        users,
    })
}

fn valid_generation(token: &str) -> bool {
    if !(38..=57).contains(&token.len()) {
        return false;
    }
    let Some((boot, start)) = token.split_once(':') else {
        return false;
    };
    boot.len() == 36
        && boot.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
        && !start.is_empty()
        && start.bytes().all(|byte| byte.is_ascii_digit())
        && start.parse::<u64>().is_ok_and(|value| value > 0)
}

#[allow(clippy::double_must_use)]
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
        assert_eq!(snapshot.generation, None);
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
    fn parse_output_accepts_generation_and_legacy_fallback() {
        let json = r#"{"server_upload_total":10,"server_download_total":20,"uptime_seconds":30,"users":{}}"#;
        let legacy = parse_output(json).unwrap();
        let empty = parse_output(&format!("vpnctl-generation:\n{json}")).unwrap();
        assert_eq!(empty, legacy);
        let token = "00000000-0000-0000-0000-000000000001:123456";
        let mut expected = legacy;
        expected.generation = Some(token.into());
        assert_eq!(
            parse_output(&format!("vpnctl-generation:{token}\n{json}")).unwrap(),
            expected
        );
    }

    #[test]
    fn parse_output_rejects_malformed_or_unbounded_generation() {
        let json = r#"{"server_upload_total":10,"server_download_total":20,"uptime_seconds":30,"users":{}}"#;
        for token in [
            "00000000-0000-0000-0000-000000000001:0",
            "00000000-0000-0000-0000-000000000001:-1",
            "00000000-0000-0000-0000-000000000001:18446744073709551616",
            "00000000-0000-0000-0000-000000000001:123456789012345678901",
            "000000000000-0000-0000-000000000001:100",
            "g0000000-0000-0000-0000-000000000001:100",
            "00000000-0000-0000-0000-000000000001:100:200",
            "00000000-0000-0000-0000-000000000001: 100",
        ] {
            assert!(matches!(
                parse_output(&format!("vpnctl-generation:{token}\n{json}")),
                Err(StatsError::InvalidGeneration)
            ));
        }
        assert!(matches!(
            parse_output("vpnctl-generation:missing-newline"),
            Err(StatsError::InvalidGeneration)
        ));
    }

    #[test]
    fn collection_command_frames_generation_and_rejects_mid_query_restarts() {
        let dir = tempfile::TempDir::new().unwrap();
        let start = dir.path().join("start");
        let prelude = r#"
cat() {
    [ "$*" = /proc/sys/kernel/random/boot_id ] || return 1
    printf '00000000-0000-0000-0000-000000000001\n'
}
systemctl() {
    [ "$*" = 'show -p ExecMainStartTimestampMonotonic --value sing-box' ] || return 1
    [ "$SCENARIO" != unavailable ] || return 1
    if [ "$SCENARIO" = empty ]; then return 0; fi
    if [ "$SCENARIO" = stopped ]; then printf '0\n'; return 0; fi
    command cat "$GEN_TEST_START"
}
stats_helper() {
    [ "$SCENARIO" != failed ] || return 42
    if [ "$SCENARIO" = restarted ]; then printf 200 > "$GEN_TEST_START"; fi
    printf '%s\n' '{"server_upload_total":10,"server_download_total":20,"uptime_seconds":30,"users":{}}'
}
"#;
        let command = QUERY_STATS_CMD.replace(
            "/usr/local/libexec/vpnctl/singbox-stats-helper",
            "stats_helper",
        );
        for scenario in [
            "stable",
            "unavailable",
            "empty",
            "stopped",
            "restarted",
            "failed",
        ] {
            std::fs::write(&start, "100\n").unwrap();
            let output = std::process::Command::new("bash")
                .arg("-c")
                .arg(format!("{prelude}\n{command}"))
                .env("GEN_TEST_START", &start)
                .env("SCENARIO", scenario)
                .output()
                .unwrap();
            assert_eq!(
                output.status.success(),
                matches!(scenario, "stable" | "unavailable" | "empty" | "stopped"),
                "{scenario}"
            );
            if output.status.success() {
                let snapshot = parse_output(std::str::from_utf8(&output.stdout).unwrap()).unwrap();
                assert_eq!(snapshot.server_upload_total, 10);
                assert_eq!(
                    snapshot.generation.as_deref(),
                    (scenario == "stable").then_some("00000000-0000-0000-0000-000000000001:100")
                );
            } else {
                assert!(output.stdout.is_empty());
            }
        }
    }

    #[test]
    fn command_is_loopback_bounded_and_does_not_reset() {
        assert!(QUERY_STATS_CMD.contains("127.0.0.1:10085"));
        assert!(QUERY_STATS_CMD.contains("--timeout 5s"));
        assert!(!QUERY_STATS_CMD.contains("reset"));
    }
}
