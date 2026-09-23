use axum::extract::{Path, State};
use axum::response::{IntoResponse, Redirect, Response};
use vpnctl_core::ServerId;
use vpnctl_inventory::{BillingCycle, ServerBillingInput};

use super::super::helpers::{bad_request, internal_error, not_found};
use crate::AppState;
use crate::http_util::form_field;

/// `POST /admin/servers/{id}/billing` — save/update rental billing info for a server.
pub(crate) async fn server_set_billing(
    Path(server_id): Path<String>,
    State(state): State<AppState>,
    body: String,
) -> Response {
    let sid = ServerId(server_id.clone());

    match state.inv.get_server(&sid).await {
        Ok(Some(_)) => {}
        Ok(None) => return not_found(&format!("no such server '{server_id}'")),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    }

    let Some(due_date) = form_field(&body, "due_date") else {
        return bad_request("vpnctl admin: due_date is required");
    };
    if vpnctl_inventory::validate_due_date(&due_date).is_err() {
        return bad_request("vpnctl admin: due_date must be in YYYY-MM-DD format");
    }

    let cycle_str = form_field(&body, "billing_cycle").unwrap_or_else(|| "monthly".into());
    let Ok(cycle) = cycle_str.parse::<BillingCycle>() else {
        return bad_request("vpnctl admin: invalid billing_cycle");
    };

    let amount_str = form_field(&body, "amount").unwrap_or_default();
    let amount_cents = match parse_amount_to_cents(&amount_str) {
        Ok(c) => c,
        Err(e) => return bad_request(&format!("vpnctl admin: invalid amount: {e}")),
    };

    let currency = form_field(&body, "currency")
        .unwrap_or_else(|| "EUR".into())
        .trim()
        .to_uppercase();
    if currency.is_empty() || currency.len() > 8 {
        return bad_request("vpnctl admin: currency must be 1-8 characters");
    }

    let auto_renew = matches!(
        form_field(&body, "auto_renew").as_deref(),
        Some("1") | Some("true") | Some("on")
    );

    let billing_url = form_field(&body, "billing_url")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    if let Some(ref u) = billing_url {
        if !u.starts_with("http://") && !u.starts_with("https://") {
            return bad_request("vpnctl admin: billing_url must start with http:// or https://");
        }
    }

    let notes = form_field(&body, "notes")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let initial_payments_count = form_field(&body, "initial_payments_count")
        .and_then(|s| s.trim().parse::<i64>().ok())
        .filter(|&n| n > 0);

    let input = ServerBillingInput {
        due_date,
        billing_cycle: cycle,
        amount_cents,
        currency,
        auto_renew,
        billing_url,
        notes,
        initial_payments_count,
    };

    if let Err(e) = state.inv.set_server_billing(&sid, &input).await {
        return internal_error(anyhow::Error::new(e));
    }

    let return_to = safe_return_to(form_field(&body, "return_to"));
    Redirect::to(&return_to).into_response()
}

/// `POST /admin/servers/{id}/billing/advance` — one-click mark paid / advance by 1 cycle.
pub(crate) async fn server_advance_billing(
    Path(server_id): Path<String>,
    State(state): State<AppState>,
    body: String,
) -> Response {
    let sid = ServerId(server_id.clone());

    match state.inv.get_server(&sid).await {
        Ok(Some(_)) => {}
        Ok(None) => return not_found(&format!("no such server '{server_id}'")),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    }

    if let Err(e) = state.inv.advance_server_billing_cycle(&sid).await {
        return internal_error(anyhow::Error::new(e));
    }

    let return_to = safe_return_to(form_field(&body, "return_to"));
    Redirect::to(&return_to).into_response()
}

/// `POST /admin/servers/billing/settings` — update display currency, markup coefficient, or auto-refresh.
pub(crate) async fn billing_update_settings(
    State(state): State<AppState>,
    body: String,
) -> Response {
    let display_currency = form_field(&body, "display_currency")
        .map(|s| s.trim().to_uppercase())
        .filter(|s| !s.is_empty() && s.len() <= 8);

    let default_markup_bps = form_field(&body, "markup_coeff").and_then(|s| {
        let clean = s.trim().replace(',', ".");
        clean
            .parse::<f64>()
            .ok()
            .map(|f| (f * 10_000.0).round() as i64)
    });

    let auto_refresh =
        form_field(&body, "auto_refresh").map(|v| matches!(v.as_str(), "1" | "true" | "on"));

    let input = vpnctl_inventory::CurrencySettingsInput {
        display_currency,
        default_markup_bps,
        markup_overrides: None,
        rate_overrides: None,
        auto_refresh,
    };

    if let Err(e) = state.inv.set_currency_settings(&input).await {
        return internal_error(anyhow::Error::new(e));
    }

    let return_to = safe_return_to(form_field(&body, "return_to"));
    Redirect::to(&return_to).into_response()
}

/// `POST /admin/servers/billing/refresh-rates` — manual on-demand trigger to fetch exchange rates.
pub(crate) async fn billing_refresh_rates(State(state): State<AppState>, body: String) -> Response {
    if let Err(e) = crate::exchange_rate_poller::refresh_exchange_rates(&state.inv).await {
        tracing::warn!(target = "vpnctld::currency", error = %e, "manual refresh_exchange_rates failed");
    }

    let return_to = safe_return_to(form_field(&body, "return_to"));
    Redirect::to(&return_to).into_response()
}

fn safe_return_to(raw: Option<String>) -> String {
    match raw {
        Some(r) if !r.contains("//") && !r.contains("..") && !r.contains(['\r', '\n', '\\']) => {
            if let Some(rest) = r.strip_prefix("/admin/servers") {
                if rest.is_empty()
                    || rest.starts_with('/')
                    || rest.starts_with('?')
                    || rest.starts_with('#')
                {
                    return r;
                }
            }
            "/admin/servers/billing".to_string()
        }
        _ => "/admin/servers/billing".to_string(),
    }
}

fn parse_amount_to_cents(s: &str) -> std::result::Result<i64, String> {
    let s = s.trim().replace(',', ".");
    if s.is_empty() {
        return Ok(0);
    }
    if s.starts_with('-') {
        return Err("amount cannot be negative".into());
    }
    let parts: Vec<&str> = s.split('.').collect();
    match parts.len() {
        1 => {
            if !parts[0].chars().all(|c| c.is_ascii_digit()) {
                return Err("invalid amount number".into());
            }
            let units: i64 = parts[0].parse().map_err(|_| "invalid number".to_string())?;
            Ok(units.saturating_mul(100))
        }
        2 => {
            let units: i64 = if parts[0].is_empty() {
                0
            } else {
                if !parts[0].chars().all(|c| c.is_ascii_digit()) {
                    return Err("invalid amount number".into());
                }
                parts[0].parse().map_err(|_| "invalid number".to_string())?
            };
            let dec = parts[1];
            if !dec.chars().all(|c| c.is_ascii_digit()) {
                return Err("invalid decimal digits".into());
            }
            let digits: String = dec.chars().take(2).collect();
            let cents: i64 = match digits.len() {
                1 => {
                    digits
                        .parse::<i64>()
                        .map_err(|_| "invalid decimal".to_string())?
                        * 10
                }
                2 => digits
                    .parse::<i64>()
                    .map_err(|_| "invalid decimal".to_string())?,
                _ => 0,
            };
            Ok(units.saturating_mul(100).saturating_add(cents))
        }
        _ => Err("invalid decimal format".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_return_to_validates_admin_servers_paths() {
        // Valid paths matching /admin/servers
        assert_eq!(safe_return_to(Some("/admin/servers".into())), "/admin/servers");
        assert_eq!(safe_return_to(Some("/admin/servers/".into())), "/admin/servers/");
        assert_eq!(
            safe_return_to(Some("/admin/servers/billing".into())),
            "/admin/servers/billing"
        );
        assert_eq!(
            safe_return_to(Some("/admin/servers?tab=1".into())),
            "/admin/servers?tab=1"
        );
        assert_eq!(
            safe_return_to(Some("/admin/servers#anchor".into())),
            "/admin/servers#anchor"
        );

        // Invalid path prefix confusion attempts
        assert_eq!(
            safe_return_to(Some("/admin/servers_evil".into())),
            "/admin/servers/billing"
        );
        assert_eq!(
            safe_return_to(Some("/admin/servers.evil.com".into())),
            "/admin/servers/billing"
        );
        assert_eq!(
            safe_return_to(Some("/admin/serversfoo".into())),
            "/admin/servers/billing"
        );

        // Rejections for path traversal / control characters
        assert_eq!(
            safe_return_to(Some("/admin/servers/../evil".into())),
            "/admin/servers/billing"
        );
        assert_eq!(
            safe_return_to(Some("/admin/servers//evil".into())),
            "/admin/servers/billing"
        );
        assert_eq!(
            safe_return_to(Some("/admin/servers\\evil".into())),
            "/admin/servers/billing"
        );
        assert_eq!(
            safe_return_to(Some("/admin/servers\revil".into())),
            "/admin/servers/billing"
        );
        assert_eq!(
            safe_return_to(Some("/admin/servers\nevil".into())),
            "/admin/servers/billing"
        );
        assert_eq!(safe_return_to(None), "/admin/servers/billing");
    }
}
