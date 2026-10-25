#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyMode {
    DryRun,
    EnableOnly,
    Full,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NewSubscriberInfo {
    pub subscriber_id: i64,
    pub name: String,
}

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

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct SyncReport {
    pub observed_at: i64,
    pub total_subscribers: usize,
    pub active_subscribers: usize,
    pub excluded_unpaid: usize,
    pub linked: usize,
    pub enabled: Vec<String>,
    pub disabled: Vec<String>,
    pub lapsed_pending: Vec<String>,
    pub grace_pending: Vec<String>,
    pub new_subscribers: Vec<NewSubscriberInfo>,
    pub provisioned: Vec<String>,
    pub errors: Vec<String>,
    pub suppressed_disables: Vec<String>,
    pub subscribers: Vec<SubscriberSnapshot>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct BoostyIncomeSummary {
    pub active_payers: usize,
    pub mrr_rub_cents: i64,
    pub total_revenue_rub_cents: i64,
}

impl SyncReport {
    pub(crate) fn record(&mut self, disabled: bool, user_id: &str) {
        if disabled {
            self.disabled.push(user_id.to_string());
        } else {
            self.enabled.push(user_id.to_string());
        }
    }

    pub fn income_summary(&self) -> BoostyIncomeSummary {
        let mut active_payers = 0usize;
        let mut mrr_rub_cents: i64 = 0;
        let mut total_revenue_rub_cents: i64 = 0;

        for sub in &self.subscribers {
            if let Ok(payments_f) = sub.payments.trim().parse::<f64>()
                && payments_f > 0.0
                && payments_f.is_finite()
            {
                let kopecks = (payments_f * 100.0).round() as i64;
                total_revenue_rub_cents = total_revenue_rub_cents.saturating_add(kopecks);
            }

            if sub.present
                && sub.status.eq_ignore_ascii_case("active")
                && let Ok(price_f) = sub.price.trim().parse::<f64>()
                && price_f > 0.0
                && price_f.is_finite()
            {
                let kopecks = (price_f * 100.0).round() as i64;
                mrr_rub_cents = mrr_rub_cents.saturating_add(kopecks);
                active_payers += 1;
            }
        }

        BoostyIncomeSummary {
            active_payers,
            mrr_rub_cents,
            total_revenue_rub_cents,
        }
    }
}

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

    #[test]
    fn income_summary_computes_mrr_and_total_revenue() {
        let report = SyncReport {
            subscribers: vec![
                SubscriberSnapshot {
                    subscriber_id: 1,
                    status: "active".into(),
                    present: true,
                    price: "300".into(),
                    payments: "900".into(),
                    ..Default::default()
                },
                SubscriberSnapshot {
                    subscriber_id: 2,
                    status: "ACTIVE".into(),
                    present: true,
                    price: "150.50".into(),
                    payments: "451.50".into(),
                    ..Default::default()
                },
                SubscriberSnapshot {
                    subscriber_id: 3,
                    status: "active".into(),
                    present: true,
                    price: "0".into(),
                    payments: "0".into(),
                    ..Default::default()
                },
                SubscriberSnapshot {
                    subscriber_id: 4,
                    status: "inactive".into(),
                    present: true,
                    price: "500".into(),
                    payments: "1500".into(),
                    ..Default::default()
                },
                SubscriberSnapshot {
                    subscriber_id: 5,
                    status: "active".into(),
                    present: false,
                    price: "200".into(),
                    payments: "600".into(),
                    ..Default::default()
                },
                SubscriberSnapshot {
                    subscriber_id: 6,
                    status: "active".into(),
                    present: true,
                    price: "not-a-number".into(),
                    payments: "invalid".into(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };

        let summary = report.income_summary();
        assert_eq!(summary.active_payers, 2);
        assert_eq!(summary.mrr_rub_cents, 45_050);
        assert_eq!(summary.total_revenue_rub_cents, 345_150);
    }
}
