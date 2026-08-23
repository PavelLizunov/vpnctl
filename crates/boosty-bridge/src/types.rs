//! Bridge types, error definitions, and report structures.

/// How aggressively [`sync_once`](crate::sync_once) applies the reconciliation plan.
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

/// Privacy-bounded snapshot of the Boosty roster. It deliberately excludes
/// email, avatar URLs and unstructured level data; the operator gets the
/// subscription/payment facts needed for support without retaining extra PII.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct SubscriberSnapshot {
    pub subscriber_id: i64,
    pub name: String,
    pub present: bool,
    pub missing_since: Option<i64>,
    pub status: String,
    pub subscribed: bool,
    pub on_time: i64,
    pub off_time: Option<i64>,
    pub next_pay_time: Option<i64>,
    /// Boosty exposes floating-point totals without a transaction currency;
    /// strings preserve the observed value without inventing accounting math.
    pub price: String,
    pub payments: String,
    pub is_fee_paid: bool,
    pub can_write: bool,
    pub is_black_listed: bool,
    pub level_id: i64,
    pub level_name: String,
    pub level_price: String,
}

impl Default for SubscriberSnapshot {
    fn default() -> Self {
        Self {
            subscriber_id: 0,
            name: String::new(),
            present: true,
            missing_since: None,
            status: String::new(),
            subscribed: false,
            on_time: 0,
            off_time: None,
            next_pay_time: None,
            price: String::new(),
            payments: String::new(),
            is_fee_paid: false,
            can_write: false,
            is_black_listed: false,
            level_id: 0,
            level_name: String::new(),
            level_price: String::new(),
        }
    }
}

/// Outcome of one [`sync_once`](crate::sync_once) pass.
///
/// Serializable: the daemon persists the last APPLIED report so the admin
/// page can render it without a live (state-mutating) sync on GET.
/// `#[serde(default)]` keeps old stored rows readable when fields grow.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct SyncReport {
    /// Unix timestamp at which Boosty returned this roster.
    pub observed_at: i64,
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
    /// Linked users still inside the configured auto-disable grace period.
    pub grace_pending: Vec<String>,
    /// Active subscribers with no linked user.
    pub new_subscribers: Vec<NewSubscriberInfo>,
    /// Complete vpnctl users automatically created during this pass.
    pub provisioned: Vec<String>,
    /// Non-fatal per-action errors (one failed write doesn't abort the run).
    pub errors: Vec<String>,
    /// Disables suppressed by the zero-eligible fail-safe: the roster was
    /// EMPTY, or non-empty with active subscribers but NONE paid-eligible
    /// (a wrong `blog_url` / expired token / Boosty price-serialization
    /// quirk) — far more likely than every payer lapsing at once, so
    /// nothing was touched. A genuine single lapse/downgrade still flows
    /// through to disable.
    pub suppressed_disables: Vec<String>,
    /// Current roster plus retained missing tombstones, used to derive the
    /// append-only event timeline on the next applied pass.
    pub subscribers: Vec<SubscriberSnapshot>,
}

impl SyncReport {
    /// Record an applied (or dry-run) flip into the right bucket.
    pub(crate) fn record(&mut self, disabled: bool, user_id: &str) {
        if disabled {
            self.disabled.push(user_id.to_string());
        } else {
            self.enabled.push(user_id.to_string());
        }
    }
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
    #[error("credential generation failed: {0}")]
    Crypto(#[from] std::io::Error),
    #[error("bridge misconfigured: {0}")]
    Config(String),
}

impl BridgeError {
    /// Token refresh failures arrive either directly or wrapped by an
    /// API call. Credential/client errors need operator action; network,
    /// parse, rate-limit and server errors can recover on a later tick.
    pub fn is_auth_failure(&self) -> bool {
        use boosty_api::error::{ApiError, AuthError};
        use reqwest::StatusCode;

        let terminal_auth = |err: &AuthError| match err {
            AuthError::HttpRequest(_) | AuthError::ParseError(_) => false,
            AuthError::HttpStatus { status, .. } => {
                status.is_client_error()
                    && !matches!(
                        *status,
                        StatusCode::REQUEST_TIMEOUT | StatusCode::TOO_MANY_REQUESTS
                    )
            }
            _ => true,
        };

        match self {
            Self::Auth(err) | Self::Api(ApiError::Auth(err)) => terminal_auth(err),
            Self::Api(ApiError::Unauthorized) => true,
            Self::Api(ApiError::HttpStatus { status, .. }) => {
                matches!(*status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN)
            }
            _ => false,
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
    if err.is_auth_failure() {
        format!(
            "Boosty auth failed — stored credentials are dead (the bridge cannot self-heal): \
             paste a fresh refresh token + device id on /admin/boosty. ({err})"
        )
    } else {
        format!("Boosty sync failed (network/API; usually transient): {err}")
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
    fn api_wrapped_refresh_failure_is_still_auth_failure() {
        let err = BridgeError::Api(boosty_api::error::ApiError::Auth(
            boosty_api::error::AuthError::HttpStatus {
                status: reqwest::StatusCode::BAD_REQUEST,
                body: r#"{"error":"invalid_grant"}"#.into(),
            },
        ));
        let s = sync_failure_summary(&err);
        assert!(err.is_auth_failure());
        assert!(s.contains("credentials are dead"), "{s}");
        assert!(!s.contains("usually transient"), "{s}");
    }

    #[test]
    fn transient_failure_summary_is_marked_transient() {
        let err = BridgeError::Config("blog_url not set".into());
        let s = sync_failure_summary(&err);
        assert!(s.contains("transient"), "{s}");
        assert!(s.contains("blog_url not set"), "{s}");
    }
}
