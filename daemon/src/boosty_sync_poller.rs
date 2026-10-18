use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use vpnctl_boosty_bridge::{ApplyMode, sync_from_inventory};
use vpnctl_core::{Registry, Server, UserId};
use vpnctl_inventory::SqliteInventory;

const DEFAULT_INTERVAL_SECS: u64 = 3600;

pub(crate) const SYNC_FAILED_ALERT_KIND: &str = "boosty.sync.failed";

pub fn spawn_boosty_sync_poller(
    inv: SqliteInventory,
    registry: Arc<Registry>,
    deploy_key_path: PathBuf,
) -> tokio::task::JoinHandle<()> {
    use tokio::time::{MissedTickBehavior, interval};

    tokio::spawn(async move {
        let interval_secs = match inv.get_boosty_settings().await {
            Ok(s) if s.poll_interval_secs > 0 => s.poll_interval_secs,
            _ => DEFAULT_INTERVAL_SECS,
        };

        let mut tick = interval(Duration::from_secs(interval_secs));
        tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        tick.tick().await;

        loop {
            tick.tick().await;
            run_tick(&inv, &registry, &deploy_key_path).await;
        }
    })
}

pub async fn run_tick(inv: &SqliteInventory, registry: &Arc<Registry>, deploy_key_path: &Path) {
    let settings = match inv.get_boosty_settings().await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(
                target = "vpnctld::boosty",
                error = %e,
                "read boosty_settings failed; skipping tick"
            );
            return;
        }
    };

    if !settings.enabled {
        return;
    }

    let mode = if settings.auto_disable_lapsed {
        ApplyMode::Full
    } else {
        ApplyMode::EnableOnly
    };

    match sync_from_inventory(inv, mode).await {
        Ok(report) => {
            note_sync_recovery(inv).await;
            tracing::info!(
                target = "vpnctld::boosty",
                enabled = report.enabled.len(),
                disabled = report.disabled.len(),
                lapsed_pending = report.lapsed_pending.len(),
                grace_pending = report.grace_pending.len(),
                provisioned = report.provisioned.len(),
                new_subscribers = report.new_subscribers.len(),
                suppressed_disables = report.suppressed_disables.len(),
                errors = report.errors.len(),
                "boosty sync tick"
            );
            for e in &report.errors {
                tracing::warn!(target = "vpnctld::boosty", error = %e, "sync action failed");
            }

            let flipped: Vec<String> = report
                .enabled
                .iter()
                .chain(report.disabled.iter())
                .chain(report.provisioned.iter())
                .cloned()
                .collect();
            if !flipped.is_empty() {
                deploy_flipped_users(inv, registry, deploy_key_path, &flipped, "boosty.sync").await;
            }
        }
        Err(e) => {
            tracing::warn!(
                target = "vpnctld::boosty",
                error = %e,
                "boosty sync failed"
            );
            note_sync_failure(inv, &e).await;
        }
    }
}

async fn note_sync_failure(inv: &SqliteInventory, err: &vpnctl_boosty_bridge::BridgeError) {
    let summary = vpnctl_boosty_bridge::sync_failure_summary(err);
    let payload = serde_json::json!({
        "auth": err.is_auth_failure(),
    });
    match inv
        .insert_alert_if_no_unacked(
            SYNC_FAILED_ALERT_KIND,
            None,
            "warning",
            &summary,
            Some(&payload.to_string()),
        )
        .await
    {
        Ok(Some(alert_id)) => {
            crate::node_probe_poller::push_alert(
                inv,
                SYNC_FAILED_ALERT_KIND,
                "warning",
                "boosty",
                &payload,
                Some(alert_id),
            )
            .await;
        }
        Ok(None) => {}
        Err(e) => tracing::warn!(
            target = "vpnctld::boosty",
            error = %e,
            "insert boosty.sync.failed alert failed"
        ),
    }
}

async fn note_sync_recovery(inv: &SqliteInventory) {
    if let Err(e) = inv.ack_open_alerts(SYNC_FAILED_ALERT_KIND, None).await {
        tracing::warn!(
            target = "vpnctld::boosty",
            error = %e,
            "auto-ack boosty.sync.failed failed"
        );
    }
}

pub(crate) async fn deploy_flipped_users(
    inv: &SqliteInventory,
    registry: &Arc<Registry>,
    deploy_key_path: &Path,
    user_ids: &[String],
    trigger: &'static str,
) {
    let mut by_id: BTreeMap<String, Server> = BTreeMap::new();
    for uid in user_ids {
        match inv.servers_for_user(&UserId(uid.clone())).await {
            Ok(servers) => {
                for s in servers {
                    by_id.insert(s.id.0.clone(), s);
                }
            }
            Err(e) => tracing::warn!(
                target = "vpnctld::boosty",
                user = %uid,
                error = %e,
                "servers_for_user failed; node deploy for this user skipped"
            ),
        }
    }
    if by_id.is_empty() {
        return;
    }
    let servers: Vec<Server> = by_id.into_values().collect();
    let server_ids: Vec<String> = servers.iter().map(|s| s.id.0.clone()).collect();

    let failed = crate::wizard_bootstrap::redeploy_servers_collect_errors(
        servers,
        inv.clone(),
        Arc::clone(registry),
        deploy_key_path.to_path_buf(),
    )
    .await;

    if failed.is_empty() {
        tracing::info!(
            target = "vpnctld::boosty",
            users = ?user_ids,
            servers = ?server_ids,
            trigger,
            "boosty autodeploy applied (configs re-rendered + reloaded)"
        );
    } else {
        tracing::warn!(
            target = "vpnctld::boosty",
            users = ?user_ids,
            failed = ?failed,
            trigger,
            "boosty autodeploy: some servers failed — retry via Deploy all"
        );
    }
    if let Err(e) = inv
        .audit(
            "boosty-bridge",
            "boosty.autodeploy",
            None,
            Some(&serde_json::json!({
                "trigger": trigger,
                "users": user_ids,
                "servers": server_ids,
                "ok": failed.is_empty(),
                "failed": failed,
            })),
        )
        .await
    {
        tracing::warn!(target = "vpnctld::boosty", error = %e, "audit boosty.autodeploy failed");
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn run_tick_is_noop_when_disabled() {
        let tmp = tempfile::tempdir().unwrap();
        let inv = SqliteInventory::open(&tmp.path().join("inv.db"))
            .await
            .unwrap();
        let registry = Arc::new(crate::app::build_registry().unwrap());
        run_tick(&inv, &registry, Path::new("/nonexistent-key")).await;
    }

    #[tokio::test]
    async fn sync_failure_alert_dedups_and_recovers() {
        let tmp = tempfile::tempdir().unwrap();
        let inv = SqliteInventory::open(&tmp.path().join("inv.db"))
            .await
            .unwrap();
        let err = vpnctl_boosty_bridge::BridgeError::Config("x".into());

        note_sync_failure(&inv, &err).await;
        note_sync_failure(&inv, &err).await;
        assert_eq!(
            inv.unacked_alert_count().await.unwrap(),
            1,
            "dedup while open"
        );

        note_sync_recovery(&inv).await;
        assert_eq!(
            inv.unacked_alert_count().await.unwrap(),
            0,
            "recovery auto-acks"
        );

        note_sync_failure(&inv, &err).await;
        assert_eq!(
            inv.unacked_alert_count().await.unwrap(),
            1,
            "re-fires after recovery"
        );
    }

    #[tokio::test]
    async fn deploy_flipped_users_without_grants_is_noop() {
        let tmp = tempfile::tempdir().unwrap();
        let inv = SqliteInventory::open(&tmp.path().join("inv.db"))
            .await
            .unwrap();
        let registry = Arc::new(crate::app::build_registry().unwrap());
        deploy_flipped_users(
            &inv,
            &registry,
            Path::new("/nonexistent-key"),
            &["ghost".to_string()],
            "test",
        )
        .await;
        let audits = inv.recent_audit(10).await.unwrap();
        assert!(
            audits.iter().all(|a| a.action != "boosty.autodeploy"),
            "no servers -> no autodeploy audit row"
        );
    }

    #[tokio::test]
    async fn deploy_flipped_users_audits_redeploy_failure() {
        use vpnctl_core::{KernelId, ProtocolId, ServerId, User};

        let tmp = tempfile::tempdir().unwrap();
        let inv = SqliteInventory::open(&tmp.path().join("inv.db"))
            .await
            .unwrap();
        let registry = Arc::new(crate::app::build_registry().unwrap());
        let uid = UserId("alice".into());
        let sid = ServerId("de".into());
        inv.add_user(&User {
            id: uid.clone(),
            uuid: "00000000-0000-0000-0000-000000000001".into(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: false,
        })
        .await
        .unwrap();
        inv.add_server(&Server {
            id: sid.clone(),
            address: "192.0.2.1".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![ProtocolId("vless+reality".into())],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
        inv.grant(&uid, &sid).await.unwrap();

        deploy_flipped_users(
            &inv,
            &registry,
            &tmp.path().join("missing-deploy-key"),
            &[uid.0],
            "test",
        )
        .await;

        let row = inv
            .recent_audit(10)
            .await
            .unwrap()
            .into_iter()
            .find(|a| a.action == "boosty.autodeploy")
            .expect("failed redeploy must be audited");
        let payload = row.payload.expect("autodeploy audit payload");
        assert_eq!(payload["ok"], false);
        assert_eq!(payload["servers"], serde_json::json!(["de"]));
        assert!(
            payload["failed"][0]
                .as_str()
                .is_some_and(|s| s.contains("deploy key")),
            "failure must explain the missing deploy key: {payload}"
        );
    }
}
