use std::time::Duration;

use vpnctl_core::SshTransport;
use vpnctl_inventory::SqliteInventory;

use super::diff::{DISK_PRESSURE_RECOVER_PCT, SINGBOX_LOG_TRIGGER_BYTES};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Remediation {
    RestartSingbox,
    StartFail2ban,
    CleanDisk,
    RotateSingboxLog,
}

impl Remediation {
    pub(crate) fn for_kind(kind: &str) -> Option<Self> {
        match kind {
            "server.singbox.down" => Some(Self::RestartSingbox),
            "server.fail2ban.down" => Some(Self::StartFail2ban),
            "server.disk.pressure" => Some(Self::CleanDisk),
            "server.singbox.log.too_big" => Some(Self::RotateSingboxLog),
            _ => None,
        }
    }

    pub(crate) fn recovery_kind(self) -> &'static str {
        match self {
            Self::RestartSingbox => "server.singbox.up",
            Self::StartFail2ban => "server.fail2ban.up",
            Self::CleanDisk => "server.disk.recovered",
            Self::RotateSingboxLog => "server.singbox.log.recovered",
        }
    }

    pub(crate) fn action(self) -> &'static str {
        match self {
            Self::RestartSingbox => "restart sing-box",
            Self::StartFail2ban => "start fail2ban",
            Self::CleanDisk => "rotate sing-box log + vacuum journal 14d + clean package cache",
            Self::RotateSingboxLog => "rotate sing-box log",
        }
    }

    pub(crate) fn command(self) -> &'static str {
        match self {
            Self::RestartSingbox => concat!(
                r#"set -eu; "#,
                r#"if [ "$(id -u)" -eq 0 ]; then SUDO=""; else SUDO="sudo -n"; fi; "#,
                r#"$SUDO systemctl restart sing-box; $SUDO systemctl is-active --quiet sing-box"#
            ),
            Self::StartFail2ban => concat!(
                r#"set -eu; "#,
                r#"if [ "$(id -u)" -eq 0 ]; then SUDO=""; else SUDO="sudo -n"; fi; "#,
                r#"$SUDO systemctl start fail2ban; $SUDO systemctl is-active --quiet fail2ban"#
            ),
            Self::CleanDisk => concat!(
                r#"set +e; "#,
                r#"if [ "$(id -u)" -eq 0 ]; then SUDO=""; else SUDO="sudo -n"; fi; rc=0; "#,
                r#"$SUDO logrotate -f /etc/logrotate.d/sing-box || rc=1; "#,
                r#"$SUDO journalctl --vacuum-time=14d || rc=1; "#,
                r#"$SUDO apt-get clean || rc=1; "#,
                r#"pct=$(df -P / | awk 'NR==2 {gsub(/%/,"",$5); print $5}'); "#,
                r#"[ -n "$pct" ] && [ "$pct" -lt 85 ] || rc=1; exit "$rc""#
            ),
            Self::RotateSingboxLog => concat!(
                r#"set -eu; "#,
                r#"if [ "$(id -u)" -eq 0 ]; then SUDO=""; else SUDO="sudo -n"; fi; "#,
                r#"$SUDO logrotate -f /etc/logrotate.d/sing-box; "#,
                r#"bytes=$($SUDO stat -c %s /var/log/sing-box.log); "#,
                r#"[ "$bytes" -lt 524288000 ]"#
            ),
        }
    }

    pub(crate) fn verified_by(self, probe: &crate::node_probe::Probe) -> bool {
        match self {
            Self::RestartSingbox => probe.sing_box_active == Some(true),
            Self::StartFail2ban => probe.fail2ban_active == Some(true),
            Self::CleanDisk => probe
                .disk_pct()
                .is_some_and(|pct| pct < DISK_PRESSURE_RECOVER_PCT),
            Self::RotateSingboxLog => probe
                .sing_box_log_bytes
                .is_some_and(|bytes| bytes < SINGBOX_LOG_TRIGGER_BYTES),
        }
    }

    pub(crate) fn recovery_payload(self, probe: &crate::node_probe::Probe) -> serde_json::Value {
        match self {
            Self::RestartSingbox | Self::StartFail2ban => serde_json::json!({
                "auto_remediated": true,
                "action": self.action(),
            }),
            Self::CleanDisk => serde_json::json!({
                "auto_remediated": true,
                "action": self.action(),
                "current_pct": probe.disk_pct(),
            }),
            Self::RotateSingboxLog => serde_json::json!({
                "auto_remediated": true,
                "action": self.action(),
                "current_bytes": probe.sing_box_log_bytes,
            }),
        }
    }
}

pub(crate) async fn auto_remediate_alert(
    inv: &SqliteInventory,
    server: &vpnctl_core::Server,
    alert_id: i64,
    condition_kind: &str,
    plan: Remediation,
    subject: &str,
) -> bool {
    let jump = match inv.resolve_jump_host(server).await {
        Ok(j) => j,
        Err(e) => {
            tracing::warn!(
                target = "vpnctld::health_remediation",
                server = %server.id.0,
                "jump host resolution failed: {e}"
            );
            return false;
        }
    };
    let key_path = crate::app::deploy_key_path();
    let ssh = crate::ssh_subprocess::SubprocessSshTransport::new(
        server.address.clone(),
        server.ssh_user.clone(),
        key_path,
    )
    .port(server.ssh_port)
    .trusted_fingerprint(server.trusted_host_fingerprint.clone())
    .with_jump(jump)
    .timeout(Duration::from_secs(120));

    let command_result = ssh.exec(plan.command()).await;
    let probe = if command_result.is_ok() {
        match crate::node_probe_poller::probe_one_server(inv, server).await {
            crate::node_probe_poller::ProbeOutcome::Ok(probe) => Some(probe),
            _ => None,
        }
    } else {
        None
    };
    let verified = probe.as_ref().is_some_and(|p| plan.verified_by(p));
    let error = command_result
        .as_ref()
        .err()
        .map(ToString::to_string)
        .or_else(|| (!verified).then(|| "post-action health probe did not verify recovery".into()));

    if let Err(e) = inv
        .audit(
            "vpnctld",
            "server.auto_remediate",
            Some(&server.id.0),
            Some(&serde_json::json!({
                "alert_id": alert_id,
                "kind": condition_kind,
                "action": plan.action(),
                "verified": verified,
                "error": error.as_deref(),
            })),
        )
        .await
    {
        tracing::warn!(
            target = "vpnctld::health_monitor",
            server = %server.id.0,
            error = %e,
            "server.auto_remediate audit write failed"
        );
    }
    if !verified {
        tracing::warn!(
            target = "vpnctld::health_monitor",
            server = %server.id.0,
            kind = condition_kind,
            action = plan.action(),
            error = ?error,
            "automatic remediation did not verify; alert remains open"
        );
        return false;
    }

    let acked = match inv.ack_open_alerts(condition_kind, Some(&server.id)).await {
        Ok(n) if n > 0 => n,
        Ok(_) => return false,
        Err(e) => {
            tracing::warn!(
                target = "vpnctld::health_monitor",
                server = %server.id.0,
                error = %e,
                "automatic remediation verified but alert auto-ack failed"
            );
            return false;
        }
    };
    let Some(probe) = probe else {
        return false;
    };
    let payload = plan.recovery_payload(&probe);
    let summary = format!("fixed automatically: {}", plan.action());
    let recovery_id = match inv
        .insert_alert_acked(
            plan.recovery_kind(),
            Some(&server.id),
            "info",
            &summary,
            Some(&payload.to_string()),
        )
        .await
    {
        Ok(id) => id,
        Err(e) => {
            tracing::warn!(
                target = "vpnctld::health_monitor",
                server = %server.id.0,
                error = %e,
                "automatic remediation recovery row failed"
            );
            crate::node_probe_poller::recover_alert(
                inv,
                plan.recovery_kind(),
                condition_kind,
                subject,
                &payload,
                Some(&server.id),
                None,
            )
            .await;
            return true;
        }
    };
    tracing::info!(
        target = "vpnctld::health_monitor",
        server = %server.id.0,
        kind = condition_kind,
        action = plan.action(),
        acked,
        "fixed automatically"
    );
    crate::node_probe_poller::recover_alert(
        inv,
        plan.recovery_kind(),
        condition_kind,
        subject,
        &payload,
        Some(&server.id),
        Some(recovery_id),
    )
    .await;
    true
}
