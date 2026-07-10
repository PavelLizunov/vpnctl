//! Boosty → vpnctl provisioning bridge.
//!
//! Reconciles VPN access with Boosty subscription state: an active
//! subscriber's linked user is enabled, a lapsed subscriber's linked user
//! is disabled (soft-mute — secrets/uuid/device_id/grants preserved, so
//! re-subscribing restores access byte-for-byte). Only users LINKED to a
//! Boosty subscriber are ever touched (see [`reconcile`]).
//!
//! The pure decision logic lives in [`reconcile`]; [`sync_once`] is the
//! I/O orchestration (fetch subscribers → reconcile → apply).

mod reconcile;

pub use reconcile::{Action, LinkedUser, SubscriberState, reconcile};

use std::collections::HashMap;

use boosty_api::api_client::ApiClient;
use vpnctl_core::UserId;
use vpnctl_inventory::{BoostySettings, SqliteInventory};

/// Boosty API base URL.
const BOOSTY_BASE_URL: &str = "https://api.boosty.to";

/// How aggressively [`sync_once`] applies the reconciliation plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyMode {
    /// Change nothing; the report describes what WOULD happen.
    DryRun,
    /// Apply re-enables automatically; surface lapses as `lapsed_pending`
    /// for the operator to confirm (the "auto-provision, disable on a
    /// button" policy). This is the safe default for the poller.
    EnableOnly,
    /// Apply both re-enables and disables automatically.
    Full,
}

/// An active subscriber with no linked vpnctl user, surfaced for the
/// operator to link or provision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewSubscriberInfo {
    /// Boosty numeric subscriber id.
    pub subscriber_id: i64,
    /// Display name (for the admin UI / CLI output).
    pub name: String,
}

/// Outcome of one [`sync_once`] pass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncReport {
    /// Total subscribers fetched from Boosty.
    pub total_subscribers: usize,
    /// How many of those are currently active.
    pub active_subscribers: usize,
    /// How many vpnctl users are linked to a Boosty subscriber.
    pub linked: usize,
    /// User ids re-enabled (or, in dry-run, that would be).
    pub enabled: Vec<String>,
    /// User ids disabled (only in `Full`, or would-be in dry-run).
    pub disabled: Vec<String>,
    /// Linked users whose subscription lapsed but were left enabled
    /// (mode `EnableOnly`) — the operator disables these via a button.
    pub lapsed_pending: Vec<String>,
    /// Active subscribers with no linked user.
    pub new_subscribers: Vec<NewSubscriberInfo>,
    /// Non-fatal per-action errors (one failed write doesn't abort the run).
    pub errors: Vec<String>,
}

/// Errors that abort a whole sync pass (as opposed to a single-action
/// error, which is collected into [`SyncReport::errors`]).
#[derive(Debug, thiserror::Error)]
pub enum BridgeError {
    #[error("Boosty API error: {0}")]
    Api(#[from] boosty_api::error::ApiError),
    #[error("Boosty auth error: {0}")]
    Auth(#[from] boosty_api::error::AuthError),
    #[error("inventory error: {0}")]
    Inventory(#[from] vpnctl_inventory::SqliteInventoryError),
    #[error("bridge misconfigured: {0}")]
    Config(String),
}

/// Build an authenticated Boosty [`ApiClient`] from bridge settings.
///
/// Prefers the static bearer token; falls back to the refresh flow
/// (refresh token + device id). Errors if neither is configured.
pub async fn build_client(settings: &BoostySettings) -> Result<ApiClient, BridgeError> {
    let client = ApiClient::new(reqwest::Client::new(), BOOSTY_BASE_URL);

    if let Some(token) = settings.access_token.as_deref()
        && !token.is_empty()
    {
        client.set_bearer_token(token).await?;
        return Ok(client);
    }

    if let (Some(refresh), Some(device)) = (
        settings.refresh_token.as_deref(),
        settings.device_id.as_deref(),
    ) && !refresh.is_empty()
        && !device.is_empty()
    {
        client
            .set_refresh_token_and_device_id(refresh, device)
            .await?;
        return Ok(client);
    }

    Err(BridgeError::Config(
        "no Boosty credentials set (need an access token, or a refresh token + device id)".into(),
    ))
}

/// Full sync from stored settings: build the client, reconcile against the
/// blog roster, apply per `mode`, and persist any rotated refresh token.
pub async fn sync_from_settings(
    inv: &SqliteInventory,
    settings: &BoostySettings,
    mode: ApplyMode,
) -> Result<SyncReport, BridgeError> {
    let blog = settings
        .blog_url
        .as_deref()
        .filter(|b| !b.is_empty())
        .ok_or_else(|| BridgeError::Config("blog_url not set".into()))?;

    let client = build_client(settings).await?;
    let report = sync_once(&client, inv, blog, mode).await?;

    // Boosty rotates the refresh token on every refresh; persist the new
    // value so the next daemon start / sync still authenticates.
    if settings.refresh_token.is_some()
        && let Some(rotated) = client.refresh_token().await
        && settings.refresh_token.as_deref() != Some(rotated.as_str())
    {
        inv.set_boosty_refresh_token(&rotated).await?;
    }

    Ok(report)
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
    // 1. Fetch the live roster (active + inactive).
    let subscribers = client
        .get_all_subscribers(blog, Some("on_time"), Some("gt"))
        .await?;

    let name_by_id: HashMap<i64, String> = subscribers
        .iter()
        .map(|s| (s.id as i64, s.name.clone()))
        .collect();

    let states: Vec<SubscriberState> = subscribers
        .iter()
        .map(|s| SubscriberState {
            subscriber_id: s.id as i64,
            active: s.is_active(),
        })
        .collect();
    let active_count = states.iter().filter(|s| s.active).count();

    // 2. Join links with each linked user's current disabled state.
    let link_pairs = inv.list_boosty_links().await?;
    let users = inv.list_users().await?;
    let disabled_by_user: HashMap<&str, bool> = users
        .iter()
        .map(|u| (u.id.0.as_str(), u.disabled))
        .collect();

    let links: Vec<LinkedUser> = link_pairs
        .iter()
        .filter_map(|(uid, sid)| {
            disabled_by_user
                .get(uid.0.as_str())
                .map(|&disabled| LinkedUser {
                    user_id: uid.0.clone(),
                    subscriber_id: *sid,
                    disabled,
                })
        })
        .collect();

    let mut report = SyncReport {
        total_subscribers: subscribers.len(),
        active_subscribers: active_count,
        linked: links.len(),
        ..Default::default()
    };

    // 3. Reconcile + apply.
    for action in reconcile(&states, &links) {
        match action {
            Action::Enable { user_id } => {
                apply_disabled(inv, &mut report, &user_id, false, mode).await;
            }
            Action::Disable { user_id } => match mode {
                ApplyMode::DryRun => report.disabled.push(user_id),
                ApplyMode::EnableOnly => report.lapsed_pending.push(user_id),
                ApplyMode::Full => {
                    apply_disabled(inv, &mut report, &user_id, true, mode).await;
                }
            },
            Action::NewSubscriber { subscriber_id } => {
                report.new_subscribers.push(NewSubscriberInfo {
                    subscriber_id,
                    name: name_by_id.get(&subscriber_id).cloned().unwrap_or_default(),
                });
            }
        }
    }

    Ok(report)
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

impl SyncReport {
    /// Record an applied (or dry-run) flip into the right bucket.
    fn record(&mut self, disabled: bool, user_id: &str) {
        if disabled {
            self.disabled.push(user_id.to_string());
        } else {
            self.enabled.push(user_id.to_string());
        }
    }
}
