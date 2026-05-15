//! Phase F monitoring stats endpoints. Server-side aggregation of
//! `sub_access_log` into time buckets that the `/admin/monitoring`
//! HTML page renders as inline-SVG sparklines.
//!
//! The `/api/v1/stats/*` URLs are intentionally separate from the
//! admin tree:
//!   * They sit under `/api/v1/*` so they're predictably curl-able
//!     for any future external tool (e.g. Grafana scraping).
//!   * They are NOT behind the admin basic-auth or CSRF middleware
//!     — they expose only aggregate counts (no IPs, no tokens), so
//!     the data is much less sensitive than the user-detail page
//!     that already shows the same numbers.

use axum::Json;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};

use crate::app::AppState;

/// Query string for the sub-access stats endpoint. All optional with
/// sensible defaults — `?bucket=hour&since=24` is the implied call.
#[derive(Debug, Deserialize)]
pub(crate) struct SubAccessQuery {
    /// `"hour"` or `"day"`. Defaults to `"hour"` when omitted.
    #[serde(default = "default_bucket")]
    pub bucket: String,
    /// Look-back window in HOURS (not the original spec's "24h"
    /// string — keeping it numeric avoids a humanize parser).
    /// Defaults to 24.
    #[serde(default = "default_since_hours")]
    pub since_hours: u32,
}

fn default_bucket() -> String {
    "hour".to_string()
}
fn default_since_hours() -> u32 {
    24
}

/// JSON response shape. One element per bucket the inventory returned;
/// gaps (zero-hit buckets) are NOT filled here — the SSR page does
/// gap-filling so the JSON stays compact for external consumers.
#[derive(Debug, Serialize)]
pub(crate) struct SubAccessStats {
    pub bucket: String,
    pub since_hours: u32,
    pub buckets: Vec<BucketJson>,
}

#[derive(Debug, Serialize)]
pub(crate) struct BucketJson {
    /// ISO-8601 UTC bucket start.
    pub ts: String,
    pub hits: u64,
    pub distinct_ips: u64,
}

/// `GET /api/v1/stats/sub-access?bucket=hour&since_hours=24`
pub(crate) async fn sub_access(
    State(state): State<AppState>,
    Query(q): Query<SubAccessQuery>,
) -> Response {
    // Bound `since_hours` so an operator running `?since_hours=99999`
    // doesn't ask SQLite to scan a multi-year window.
    const MAX_SINCE_HOURS: u32 = 24 * 30; // 30 days, matches retention
    let since = q.since_hours.clamp(1, MAX_SINCE_HOURS);

    match state.inv.sub_access_buckets(&q.bucket, since).await {
        Ok(buckets) => {
            let body = SubAccessStats {
                bucket: q.bucket.clone(),
                since_hours: since,
                buckets: buckets
                    .into_iter()
                    .map(|b| BucketJson {
                        ts: b.bucket_start.to_rfc3339(),
                        hits: b.hits,
                        distinct_ips: b.distinct_ips,
                    })
                    .collect(),
            };
            (StatusCode::OK, Json(body)).into_response()
        }
        Err(vpnctl_inventory::SqliteInventoryError::Invalid(msg)) => (
            StatusCode::BAD_REQUEST,
            format!("invalid bucket arg: {msg}\n"),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(target = "vpnctld::stats", error = %e, "sub_access_buckets failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal error\n").into_response()
        }
    }
}
