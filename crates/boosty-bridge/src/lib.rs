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
use std::time::Duration;

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
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NewSubscriberInfo {
    /// Boosty numeric subscriber id.
    pub subscriber_id: i64,
    /// Display name (for the admin UI / CLI output).
    pub name: String,
}

/// Outcome of one [`sync_once`] pass.
///
/// Serializable: the daemon persists the last APPLIED report so the admin
/// page can render it without a live (state-mutating) sync on GET.
/// `#[serde(default)]` keeps old stored rows readable when fields grow.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct SyncReport {
    /// Total subscribers fetched from Boosty.
    pub total_subscribers: usize,
    /// How many of those are VPN-eligible (active AND on a paid level).
    pub active_subscribers: usize,
    /// Active subscribers on the free "Follower" level, excluded from VPN
    /// by the paid-only gate (transparency, not an error).
    pub excluded_unpaid: usize,
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
    /// Disables suppressed by the zero-eligible fail-safe: the roster was
    /// EMPTY, or non-empty with active subscribers but NONE paid-eligible
    /// (a wrong `blog_url` / expired token / Boosty price-serialization
    /// quirk) — far more likely than every payer lapsing at once, so
    /// nothing was touched. A genuine single lapse/downgrade still flows
    /// through to disable.
    pub suppressed_disables: Vec<String>,
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

/// Connection / total-request timeouts for the HTTP client. Token refresh
/// holds the client's internal auth mutex across the network call (see
/// boosty_api docs), so a client WITHOUT timeouts turns one hung connection
/// into a permanently stuck poller and a hanging /admin/boosty page.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Build an authenticated Boosty [`ApiClient`] from bridge settings.
///
/// Prefers the refresh flow (refresh token + device id): access tokens
/// expire within ~an hour, so with both credentials configured a static
/// token would kill the bridge on its first expiry. Falls back to the
/// static bearer token; errors if neither is configured.
///
/// `base_url` is the API root (production callers pass [`BOOSTY_BASE_URL`]
/// via [`sync_from_settings`]; tests point it at a mock server).
pub async fn build_client(
    settings: &BoostySettings,
    base_url: &str,
) -> Result<ApiClient, BridgeError> {
    let http = reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .build()
        .map_err(|e| BridgeError::Config(format!("building HTTP client failed: {e}")))?;
    let client = ApiClient::new(http, base_url);

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

    if let Some(token) = settings.access_token.as_deref()
        && !token.is_empty()
    {
        client.set_bearer_token(token).await?;
        return Ok(client);
    }

    Err(BridgeError::Config(
        "no Boosty credentials set (need a refresh token + device id, or an access token)".into(),
    ))
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
    let result = sync_once(&client, inv, blog, mode).await;

    // Boosty rotates the refresh token on every refresh and invalidates the
    // old one, and every pass starts with a refresh (fresh client). Persist
    // the rotated value BEFORE propagating a sync error: a pass that
    // authenticated but failed mid-fetch has already consumed the stored
    // token — losing the rotated one would brick auth on the next pass.
    if settings.refresh_token.is_some()
        && let Some(rotated) = client.refresh_token().await
        && settings.refresh_token.as_deref() != Some(rotated.as_str())
    {
        if let Err(e) = inv.set_boosty_refresh_token(&rotated).await {
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

    // Persist the applied report so /admin/boosty can render its actionable
    // sections without a live (state-mutating) sync on GET. Dry-run passes
    // are pure previews and deliberately leave the stored report untouched.
    if mode != ApplyMode::DryRun
        && let Ok(report) = &result
    {
        match serde_json::to_string(report) {
            Ok(json) => {
                if let Err(e) = inv.set_boosty_last_report(&json).await {
                    tracing::warn!(
                        target = "boosty_bridge",
                        error = %e,
                        "persisting last sync report failed"
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

/// Whether a Boosty subscriber should have VPN access: actively subscribed
/// to a PAID level. The free "Follower" pseudo-level reports `price == 0`
/// and is excluded (operator policy 2026-07-10). `NaN` price → excluded
/// (`NaN > 0.0` is false), the safe default.
fn is_vpn_eligible(s: &boosty_api::model::Subscriber) -> bool {
    s.is_active() && s.level.price > 0.0
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

    // VPN-eligibility = actively subscribed to a PAID level. Boosty's free
    // "Follower" pseudo-level has `level.price == 0`; those follows report
    // status "active" but must NOT get VPN (operator policy 2026-07-10:
    // paid tiers only). So the reconciler's `active` flag means "paid-
    // active", not merely "active": a free follower is never enabled, never
    // surfaced to link, and a linked user who DOWNGRADES to free gets
    // disabled — exactly like a lapse.
    // ponytail: gate is `level.price > 0`; if a blog ever needs per-level
    // rules (e.g. only tiers ≥ N₽), add a level allow-list to
    // boosty_settings then — not needed for a single paid/free split.
    let states: Vec<SubscriberState> = subscribers
        .iter()
        .map(|s| SubscriberState {
            subscriber_id: s.id as i64,
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
        excluded_unpaid,
        linked: links.len(),
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

/// Operator-facing one-liner for a failed sync pass (alert summaries).
///
/// An auth failure means the stored credentials are DEAD — Boosty rotates
/// the refresh token one-shot, so the bridge cannot self-heal and the fix
/// is to paste fresh credentials on /admin/boosty (never an SSH
/// instruction — operator-action policy). Everything else (network, 5xx,
/// model drift) is flagged transient.
pub fn sync_failure_summary(err: &BridgeError) -> String {
    match err {
        BridgeError::Auth(_) => format!(
            "Boosty auth failed — stored credentials are dead (the bridge cannot self-heal): \
             paste a fresh refresh token + device id on /admin/boosty. ({err})"
        ),
        _ => format!("Boosty sync failed (network/API; usually transient): {err}"),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn auth_failure_summary_names_the_web_fix_surface_not_ssh() {
        let err = BridgeError::Auth(boosty_api::error::AuthError::EmptyRefreshToken);
        let s = sync_failure_summary(&err);
        assert!(s.contains("/admin/boosty"), "{s}");
        assert!(s.contains("cannot self-heal"), "{s}");
        assert!(
            !s.to_lowercase().contains("ssh"),
            "operator-action policy: {s}"
        );
    }

    #[test]
    fn transient_failure_summary_is_marked_transient() {
        let err = BridgeError::Config("blog_url not set".into());
        let s = sync_failure_summary(&err);
        assert!(s.contains("transient"), "{s}");
        assert!(s.contains("blog_url not set"), "{s}");
    }
}
