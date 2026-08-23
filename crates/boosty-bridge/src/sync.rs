//! Sync orchestration, reconciliation execution, auto-provisioning, and inventory application.

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
// ponytail: 10 minutes exceeds today's bounded roster pass; renew the lease
// only if a future account grows enough for a measured sync to approach it.
const SYNC_LEASE_SECS: i64 = 600;

fn sync_gate() -> &'static tokio::sync::Mutex<()> {
    // ponytail: the schema has one Boosty account, so one local gate is enough;
    // the DB lease in sync_from_inventory covers other processes.
    static GATE: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    GATE.get_or_init(|| tokio::sync::Mutex::new(()))
}

/// Full sync from stored settings: build the client, reconcile against the
/// blog roster, apply per `mode`, and persist any rotated refresh token.
pub async fn sync_from_settings(
    inv: &SqliteInventory,
    settings: &BoostySettings,
    mode: ApplyMode,
) -> Result<SyncReport, BridgeError> {
    sync_from_settings_at(inv, settings, mode, BOOSTY_BASE_URL).await
}

/// Production entry point. Serializing refreshes prevents the manual Web
/// button and background poller from consuming the same rotating token.
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

/// [`sync_from_settings`] against an explicit API base URL (tests point
/// this at a mock server; production uses [`BOOSTY_BASE_URL`]).
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
    let mut result = sync_once_with_policy(
        &client,
        inv,
        blog,
        mode,
        settings.grace_days,
        settings.auto_create_users,
    )
    .await;

    // Boosty rotates the refresh token on every refresh and invalidates the
    // old one, and every pass starts with a refresh (fresh client). Persist
    // the rotated value BEFORE propagating a sync error: a pass that
    // authenticated but failed mid-fetch has already consumed the stored
    // token — losing the rotated one would brick auth on the next pass.
    if let Some(expected) = settings.refresh_token.as_deref()
        && let Some(rotated) = client.refresh_token().await
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
                    // Sync worked; the failed persist is now the real error —
                    // the next pass would refresh with a consumed token.
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

    // Persist the applied report so /admin/boosty can render its actionable
    // sections without a live (state-mutating) sync on GET. Dry-run passes
    // are pure previews and deliberately leave the stored report untouched.
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

/// Run one reconciliation pass against the live Boosty roster.
///
/// Fetches every subscriber of `blog`, joins them with the linked vpnctl
/// users, computes the [`reconcile`] plan, and applies it according to
/// `mode`. A single failed enable/disable write is logged into
/// [`SyncReport::errors`] and does not abort the pass.
pub async fn sync_once(
    client: &ApiClient,
    inv: &SqliteInventory,
    blog: &str,
    mode: ApplyMode,
) -> Result<SyncReport, BridgeError> {
    sync_once_with_policy(client, inv, blog, mode, 0, false).await
}

/// Reconcile with the operator's grace-period and provisioning policy.
pub async fn sync_once_with_policy(
    client: &ApiClient,
    inv: &SqliteInventory,
    blog: &str,
    mode: ApplyMode,
    grace_days: u16,
    auto_create_users: bool,
) -> Result<SyncReport, BridgeError> {
    // 1. Fetch the live roster (active + inactive).
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

    // VPN-eligibility = actively subscribed to a PAID level. Boosty's free
    // "Follower" pseudo-level has `level.price == 0`; those follows report
    // status "active" but must NOT get VPN (operator policy 2026-07-10:
    // paid tiers only). So the reconciler's `active` flag means "paid-\
    // active", not merely "active": a free follower is never enabled, never
    // surfaced to link, and a linked user who DOWNGRADES to free gets
    // disabled — exactly like a lapse.
    // ponytail: gate is `level.price > 0`; if a blog ever needs per-level
    // rules (e.g. only tiers ≥ N₽), add a level allow-list to
    // boosty_settings then — not needed for a single paid/free split.
    let states: Vec<SubscriberState> = subscribers
        .iter()
        .zip(&subscriber_ids)
        .map(|(s, &id)| SubscriberState {
            subscriber_id: id,
            active: is_vpn_eligible(s),
        })
        .collect();
    let active_count = states.iter().filter(|s| s.active).count();
    // Active-but-not-eligible subscribers, excluded from VPN by the paid-only
    // gate (surfaced for operator transparency, not an error). Exact
    // complement of `is_vpn_eligible` among active subscribers, so NaN /
    // negative prices land HERE rather than vanishing from both totals.
    let excluded_unpaid = subscribers
        .iter()
        .filter(|s| s.is_active() && !is_vpn_eligible(s))
        .count();

    // 2. Join links with each linked user's current disabled state.
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

    // Fail-safe: suppress ALL disables (Full mode) when the roster looks
    // fleet-cuttingly wrong while payers are linked. Two signatures:
    //   * an EMPTY roster (wrong blog_url / API error), and
    //   * subscribers are present and ACTIVE, yet NONE are paid-eligible
    //     (`active_count == 0 && excluded_unpaid > 0`) — the signature of a
    //     Boosty `level.price` serialization quirk returning 0 for paid
    //     tiers, far likelier than every payer downgrading to free at once.
    // Crucially this does NOT fire on a genuine all-*inactive* roster
    // (everyone lapsed): those are real lapses and flow through to
    // lapse/disable. A single downgrade among payers also flows through
    // (others keep active_count > 0). Only the anomaly is held for the
    // operator to confirm — matching the codebase's safe-default posture.
    // (API *errors* abort before this point; this guards the successful-
    // but-wrong response.)
    let suppress_disables =
        !links.is_empty() && (subscribers.is_empty() || (active_count == 0 && excluded_unpaid > 0));

    // 3. Reconcile + apply.
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
        // A poller tick and a manual sync may race. The fixed username makes
        // one INSERT win; the loser accepts only the link created for this
        // exact subscriber, never an unrelated username collision.
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

/// Apply one `disabled` flip (or record it, in dry-run), auditing on
/// actual state change and collecting any error into the report.
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
