use axum::Json;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};

use crate::app::AppState;

#[derive(Debug, Deserialize)]
pub(crate) struct SubAccessQuery {
    #[serde(default = "default_bucket")]
    pub bucket: String,
    #[serde(default = "default_since_hours")]
    pub since_hours: u32,
}

fn default_bucket() -> String {
    "hour".to_string()
}
fn default_since_hours() -> u32 {
    24
}

#[derive(Debug, Serialize)]
pub(crate) struct SubAccessStats {
    pub bucket: String,
    pub since_hours: u32,
    pub buckets: Vec<BucketJson>,
}

#[derive(Debug, Serialize)]
pub(crate) struct BucketJson {
    pub ts: String,
    pub hits: u64,
    pub distinct_ips: u64,
}

pub(crate) async fn sub_access(
    State(state): State<AppState>,
    Query(q): Query<SubAccessQuery>,
) -> Response {
    const MAX_SINCE_HOURS: u32 = 24 * 30;
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
