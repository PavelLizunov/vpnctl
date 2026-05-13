use axum::Json;
use serde::Serialize;

#[derive(Serialize)]
pub(crate) struct Health {
    status: &'static str,
    version: &'static str,
}

pub(crate) async fn get() -> Json<Health> {
    Json(Health {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
    })
}
