use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use boosty_api::api_client::ApiClient;
use vpnctl_core::{User, UserId};
use vpnctl_inventory::{BoostySettings, SqliteInventory, SqliteInventoryError};

use crate::client::{BOOSTY_BASE_URL, build_client};
use crate::reconcile::{Action, LinkedUser, SubscriberState, reconcile};
use crate::roster::{is_vpn_eligible, subscriber_events};
use crate::types::{ApplyMode, BridgeError, NewSubscriberInfo, SubscriberSnapshot, SyncReport};

const MAX_AUTO_PROVISION_PER_TICK: usize = 5;
const SYNC_LEASE_SECS: i64 = 600;

fn sync_gate() -> &'static tokio::sync::Mutex<()> {
    static GATE: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    GATE.get_or_init(|| tokio::sync::Mutex::new(()))
}

pub async fn sync_from_settings(
    inv: &SqliteInventory,
    settings: &BoostySettings,
    mode: ApplyMode,
) -> Result<SyncReport, BridgeError> {
    sync_from_settings_at(inv, settings, mode, BOOSTY_BASE_URL).await
}

pub async fn sync_from_inventory(
    inv: &SqliteInventory,
    mode: ApplyMode,
) -> Result<SyncReport, BridgeError> {
    let _guard = sync_gate().lock().await;
    let owner = format!(
        "{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );
    if !inv
        .acquire_boosty_sync_lease(&owner, SYNC_LEASE_SECS)
        .await?
    {
        return Err(BridgeError::Config(
            "another Boosty sync is already in progress".into(),
        ));
    }

    let result = match inv.get_boosty_settings().await {
        Ok(settings) => sync_from_settings(inv, &settings, mode).await,
        Err(error) => Err(error.into()),
    };
    if let Err(error) = inv.release_boosty_sync_lease(&owner).await {
        tracing::warn!(target = "boosty_bridge", %error, "releasing Boosty sync lease failed");
    }
    result
}

pub async fn sync_from_settings_at(
    inv: &SqliteInventory,
    settings: &BoostySettings,
    mode: ApplyMode,
    base_url: &str,
) -> Result<SyncReport, BridgeError> {
    let blog = settings
        .blog_url
        .as_deref()
        .filter(|b| !b.is_empty())
        .ok_or_else(|| BridgeError::Config("blog_url not set".into()))?;

    let client = build_client(settings, base_url).await?;
    let mut active_client = client;
    let mut result = sync_once_with_policy(
        &active_client,
        inv,
        blog,
        mode,
        settings.grace_days,
        settings.auto_create_users,
    )
    .await;

    if let Err(ref err) = result
        && err.is_auth_failure()
        && settings.access_token.is_some()
        && let (Some(refresh), Some(device)) = (
            settings.refresh_token.as_deref(),
            settings.device_id.as_deref(),
        )
        && !refresh.is_empty()
        && !device.is_empty()
    {
        tracing::info!(
            target = "boosty_bridge",
            "bearer token returned auth failure; attempting refresh recovery flow"
        );
        if let Ok(refresh_client) =
            crate::client::build_refresh_client(refresh, device, base_url).await
        {
            active_client = refresh_client;
            result = sync_once_with_policy(
                &active_client,
                inv,
                blog,
                mode,
                settings.grace_days,
                settings.auto_create_users,
            )
            .await;
            if result.is_ok() {
                if let Some(stale_token) = settings.access_token.as_deref() {
                    if let Err(e) = inv.clear_boosty_access_token(stale_token).await {
                        tracing::warn!(
                            target = "boosty_bridge",
                            error = %e,
                            "clearing stale access token after refresh recovery failed"
                        );
                    }
                }
            }
        }
    }

    if let Some(expected) = settings.refresh_token.as_deref()
        && let Some(rotated) = active_client.refresh_token().await
        && expected != rotated
    {
        match inv.rotate_boosty_refresh_token(expected, &rotated).await {
            Ok(true) => {}
            Ok(false) => tracing::info!(
                target = "boosty_bridge",
                "kept the Boosty refresh credential changed during this sync"
            ),
            Err(e) => {
                if result.is_ok() {
                    return Err(e.into());
                }
                tracing::warn!(
                    target = "boosty_bridge",
                    error = %e,
                    "persisting rotated refresh token failed after a failed sync"
                );
            }
        }
    }

    if mode != ApplyMode::DryRun
        && let Ok(report) = &mut result
    {
        let previous = inv
            .boosty_last_report()
            .await
            .ok()
            .flatten()
            .and_then(|(json, _)| serde_json::from_str::<SyncReport>(&json).ok());
        let events = subscriber_events(previous.as_ref(), report);
        match serde_json::to_string(report) {
            Ok(json) => {
                if let Err(e) = inv.set_boosty_report_and_events(&json, &events).await {
                    tracing::warn!(
                        target = "boosty_bridge",
                        error = %e,
                        "persisting sync report + subscriber events failed"
                    );
                }
            }
            Err(e) => tracing::warn!(
                target = "boosty_bridge",
                error = %e,
                "serializing sync report failed"
            ),
        }
    }

    result
}

pub async fn sync_once(
    client: &ApiClient,
    inv: &SqliteInventory,
    blog: &str,
    mode: ApplyMode,
) -> Result<SyncReport, BridgeError> {
    sync_once_with_policy(client, inv, blog, mode, 0, false).await
}

pub async fn sync_once_with_policy(
    client: &ApiClient,
    inv: &SqliteInventory,
    blog: &str,
    mode: ApplyMode,
    grace_days: u16,
    auto_create_users: bool,
) -> Result<SyncReport, BridgeError> {
    let subscribers = client
        .get_all_subscribers(blog, Some("on_time"), Some("gt"))
        .await?;
    let now = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    )
    .unwrap_or(i64::MAX);
    let subscriber_ids: Vec<i64> = subscribers
        .iter()
        .map(|s| {
            i64::try_from(s.id).map_err(|_| {
                BridgeError::Config(format!("Boosty subscriber id {} exceeds SQLite i64", s.id))
            })
        })
        .collect::<Result<_, _>>()?;
    let subscriber_snapshots: Vec<SubscriberSnapshot> = subscribers
        .iter()
        .zip(&subscriber_ids)
        .map(|(s, &subscriber_id)| {
            Ok(SubscriberSnapshot {
                subscriber_id,
                name: s.name.clone(),
                present: true,
                missing_since: None,
                status: s.status.clone(),
                subscribed: s.subscribed,
                on_time: s.on_time,
                off_time: s.off_time,
                next_pay_time: s.next_pay_time,
                price: s.price.to_string(),
                payments: s.payments.to_string(),
                is_fee_paid: s.is_fee_paid,
                can_write: s.can_write,
                is_black_listed: s.is_black_listed,
                level_id: i64::try_from(s.level.id).map_err(|_| {
                    BridgeError::Config(format!(
                        "Boosty level id {} exceeds SQLite i64",
                        s.level.id
                    ))
                })?,
                level_name: s.level.name.clone(),
                level_price: s.level.price.to_string(),
            })
        })
        .collect::<Result<_, BridgeError>>()?;

    let name_by_id: HashMap<i64, String> = subscribers
        .iter()
        .zip(&subscriber_ids)
        .map(|(s, &id)| (id, s.name.clone()))
        .collect();
    let subscriber_by_id: HashMap<i64, &boosty_api::model::Subscriber> =
        subscriber_ids.iter().copied().zip(&subscribers).collect();

    let states: Vec<SubscriberState> = subscribers
        .iter()
        .zip(&subscriber_ids)
        .map(|(s, &id)| SubscriberState {
            subscriber_id: id,
            active: is_vpn_eligible(s),
        })
        .collect();
    let active_count = states.iter().filter(|s| s.active).count();
    let excluded_unpaid = subscribers
        .iter()
        .filter(|s| s.is_active() && !is_vpn_eligible(s))
        .count();

    let link_pairs = inv.list_boosty_links_with_lapse().await?;
    let users = inv.list_users().await?;
    let disabled_by_user: HashMap<&str, bool> = users
        .iter()
        .map(|u| (u.id.0.as_str(), u.disabled))
        .collect();

    let mut lapsed_by_user = HashMap::new();
    let mut links = Vec::with_capacity(link_pairs.len());
    for (uid, sid, stored_lapse) in &link_pairs {
        if let Some(&disabled) = disabled_by_user.get(uid.0.as_str()) {
            let subscriber = subscriber_by_id.get(sid).copied();
            let lapse = if subscriber.is_some_and(is_vpn_eligible) {
                None
            } else {
                let api_off_time = subscriber
                    .and_then(|s| s.off_time)
                    .filter(|ts| *ts > 0 && *ts <= now);
                Some(
                    stored_lapse
                        .map(|stored| stored.min(api_off_time.unwrap_or(now)))
                        .unwrap_or_else(|| api_off_time.unwrap_or(now)),
                )
            };
            let observed = if mode == ApplyMode::DryRun {
                lapse
            } else {
                inv.observe_boosty_lapse(uid, lapse).await?
            };
            if let Some(since) = observed {
                lapsed_by_user.insert(uid.0.clone(), since);
            }
            links.push(LinkedUser {
                user_id: uid.0.clone(),
                subscriber_id: *sid,
                disabled,
            });
        }
    }

    let mut report = SyncReport {
        observed_at: now,
        total_subscribers: subscribers.len(),
        active_subscribers: active_count,
        excluded_unpaid,
        linked: links.len(),
        subscribers: subscriber_snapshots,
        ..Default::default()
    };

    let suppress_disables =
        !links.is_empty() && (subscribers.is_empty() || (active_count == 0 && excluded_unpaid > 0));

    for action in reconcile(&states, &links) {
        match action {
            Action::Enable { user_id } => {
                apply_disabled(inv, &mut report, &user_id, false, mode).await;
            }
            Action::Disable { user_id } if suppress_disables => {
                report.suppressed_disables.push(user_id);
            }
            Action::Disable { user_id } => match mode {
                ApplyMode::DryRun => report.disabled.push(user_id),
                ApplyMode::EnableOnly => report.lapsed_pending.push(user_id),
                ApplyMode::Full => {
                    let grace_secs = i64::from(grace_days) * 86_400;
                    let since = lapsed_by_user.get(&user_id).copied().unwrap_or(now);
                    if now.saturating_sub(since) < grace_secs {
                        report.grace_pending.push(user_id);
                    } else {
                        apply_disabled(inv, &mut report, &user_id, true, mode).await;
                    }
                }
            },
            Action::NewSubscriber { subscriber_id } => {
                let info = NewSubscriberInfo {
                    subscriber_id,
                    name: name_by_id.get(&subscriber_id).cloned().unwrap_or_default(),
                };
                if mode == ApplyMode::DryRun
                    || !auto_create_users
                    || report.provisioned.len() >= MAX_AUTO_PROVISION_PER_TICK
                {
                    report.new_subscribers.push(info);
                    continue;
                }
                match provision_boosty_user(inv, subscriber_id).await {
                    Ok(user_id) => {
                        report.linked += 1;
                        report.provisioned.push(user_id);
                    }
                    Err(e) => {
                        report.errors.push(format!(
                            "provision Boosty subscriber {subscriber_id} failed: {e}"
                        ));
                        report.new_subscribers.push(info);
                    }
                }
            }
        }
    }
    if !report.suppressed_disables.is_empty() {
        tracing::warn!(
            target = "boosty_bridge",
            users = ?report.suppressed_disables,
            total_subscribers = subscribers.len(),
            "roster yielded ZERO vpn-eligible subscribers — suppressed all disables (blog_url typo, expired token, or Boosty price serialization quirk?)"
        );
    }

    Ok(report)
}

async fn provision_boosty_user(
    inv: &SqliteInventory,
    subscriber_id: i64,
) -> Result<String, BridgeError> {
    let id = format!("boosty-{subscriber_id}");
    let (wireguard_private, wireguard_pubkey) = vpnctl_crypto::gen_wireguard_keypair();
    let user = User {
        id: UserId(id.clone()),
        uuid: vpnctl_crypto::gen_uuid(),
        tuic_password: Some(vpnctl_crypto::gen_password(24)?),
        wireguard_pubkey: Some(wireguard_pubkey),
        wireguard_private: Some(wireguard_private),
        sub_token: None,
        vpn_router_device_id: Some(vpnctl_crypto::gen_vpn_router_device_id()?),
        disabled: false,
    };
    match inv.add_boosty_user(&user, subscriber_id).await {
        Ok(grants) => {
            if let Err(e) = inv
                .audit(
                    "boosty-bridge",
                    "boosty.provision",
                    Some(&id),
                    Some(&serde_json::json!({
                        "subscriber_id": subscriber_id,
                        "servers_granted": grants,
                    })),
                )
                .await
            {
                tracing::warn!(
                    target = "boosty_bridge",
                    user = %id,
                    error = %e,
                    "audit boosty.provision failed"
                );
            }
            Ok(id)
        }
        Err(SqliteInventoryError::AlreadyExists(_)) => inv
            .list_boosty_links()
            .await?
            .into_iter()
            .find_map(|(uid, sid)| (sid == subscriber_id).then_some(uid.0))
            .ok_or_else(|| {
                BridgeError::Config(format!(
                    "vpnctl user `{id}` already exists and is not linked to subscriber {subscriber_id}"
                ))
            }),
        Err(e) => Err(e.into()),
    }
}

async fn apply_disabled(
    inv: &SqliteInventory,
    report: &mut SyncReport,
    user_id: &str,
    disabled: bool,
    mode: ApplyMode,
) {
    if mode == ApplyMode::DryRun {
        report.record(disabled, user_id);
        return;
    }

    let uid = UserId(user_id.to_string());
    match inv.set_user_disabled(&uid, disabled).await {
        Ok(changed) => {
            report.record(disabled, user_id);
            if changed {
                let action = if disabled {
                    "boosty.disable"
                } else {
                    "boosty.enable"
                };
                if let Err(e) = inv
                    .audit(
                        "boosty-bridge",
                        action,
                        Some(user_id),
                        Some(&serde_json::json!({ "reason": "subscription reconcile" })),
                    )
                    .await
                {
                    report
                        .errors
                        .push(format!("audit {action} for {user_id} failed: {e}"));
                }
            }
        }
        Err(e) => report
            .errors
            .push(format!("set disabled={disabled} for {user_id} failed: {e}")),
    }
}
