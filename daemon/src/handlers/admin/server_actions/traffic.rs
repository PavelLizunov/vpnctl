use axum::extract::{Path, State};
use axum::response::{IntoResponse, Redirect, Response};
use vpnctl_core::ServerId;
use vpnctl_inventory::ServerTrafficLimit;

use super::super::helpers::{bad_request, internal_error, not_found};
use crate::{
    AppState,
    http_util::{form_field, path_segment_encode},
};

// Decimal arithmetic keeps large TB settings exact and rejects exponents/NaN.
fn parse_limit(text: &str, unit: &str) -> Option<u64> {
    let multiplier: u128 = match unit {
        "GB" => 1_000_000_000,
        "TB" => 1_000_000_000_000,
        "GiB" => 1 << 30,
        "TiB" => 1 << 40,
        _ => return None,
    };
    let (whole, fraction) = text.split_once('.').unwrap_or((text, ""));
    if whole.is_empty()
        || !whole.bytes().all(|b| b.is_ascii_digit())
        || fraction.len() > 9
        || !fraction.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let scale = 10u128.checked_pow(fraction.len().try_into().ok()?)?;
    let numerator = whole
        .parse::<u128>()
        .ok()?
        .checked_mul(scale)?
        .checked_add(if fraction.is_empty() {
            0
        } else {
            fraction.parse().ok()?
        })?;
    let scaled = numerator.checked_mul(multiplier)?;
    if scaled % scale != 0 {
        return None;
    }
    let bytes = scaled / scale;
    (bytes > 0 && bytes <= i64::MAX as u128).then_some(bytes as u64)
}

pub(crate) async fn server_set_traffic_limit(
    Path(server_id): Path<String>,
    State(state): State<AppState>,
    body: String,
) -> Response {
    let sid = ServerId(server_id);
    match state.inv.get_server(&sid).await {
        Ok(Some(_)) => {}
        Ok(None) => return not_found("no such server"),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    }
    let Some(amount) = form_field(&body, "limit") else {
        return bad_request("limit is required (leave empty to clear)");
    };
    let limit = if amount.trim().is_empty() {
        None
    } else {
        let unit = form_field(&body, "unit").unwrap_or_default();
        let Some(limit_bytes) = parse_limit(amount.trim(), &unit) else {
            return bad_request(
                "limit must be positive decimal bytes in GB, TB, GiB or TiB (up to 9 decimals, whole bytes, maximum i64::MAX bytes)",
            );
        };
        let direction = form_field(&body, "direction").unwrap_or_default();
        let reset_day = form_field(&body, "reset_day").and_then(|s| s.parse::<u8>().ok());
        let warning_pct = form_field(&body, "warning_pct").and_then(|s| s.parse::<u8>().ok());
        let (Some(reset_day), Some(warning_pct)) = (reset_day, warning_pct) else {
            return bad_request("reset_day must be 1..31 and warning_pct 1..100");
        };
        if !matches!(direction.as_str(), "rx" | "tx" | "both")
            || !(1..=31).contains(&reset_day)
            || !(1..=100).contains(&warning_pct)
        {
            return bad_request(
                "direction must be rx, tx or both; reset_day 1..31; warning_pct 1..100",
            );
        }
        Some(ServerTrafficLimit {
            limit_bytes,
            direction,
            reset_day,
            warning_pct,
        })
    };
    if let Err(e) = state
        .inv
        .set_server_traffic_limit(&sid, limit.as_ref(), "admin")
        .await
    {
        return internal_error(anyhow::Error::new(e));
    }
    Redirect::to(&format!(
        "/admin/servers/{}/activity#traffic-limit",
        path_segment_encode(&sid.0)
    ))
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::parse_limit;
    #[test]
    fn quota_units_round_trip_exact_bytes_and_reject_fractional_bytes_and_overflow() {
        for (value, unit, expected) in [
            ("4", "TB", 4_000_000_000_000),
            ("4", "TiB", 4 << 40),
            ("0.000000001", "GB", 1),
            ("1.5", "GiB", 3 << 29),
            ("9223372036.854775807", "GB", i64::MAX as u64),
        ] {
            assert_eq!(parse_limit(value, unit), Some(expected));
        }
        for (value, unit) in [
            ("0.000000001", "GiB"),
            ("9223372036.854775808", "GB"),
            ("1e3", "TB"),
            ("NaN", "TB"),
            ("1", "tb"),
            ("9999999999999999999999999999999999999999999999", "TB"),
        ] {
            assert_eq!(parse_limit(value, unit), None);
        }
    }
}
