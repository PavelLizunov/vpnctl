use axum::Json;
use serde::Serialize;

#[derive(Serialize)]
pub(crate) struct Health {
    status: &'static str,
    /// Stable SemVer contract — machine-readable, safe to grep/parse.
    version: &'static str,
    /// Build provenance `<semver>+<short-git-sha>` (or `+unknown`), so the
    /// deployed commit is identifiable without breaking scripts that parse
    /// `version`. Same stamp as the admin footer and `vpnctl --version`.
    build: &'static str,
}

pub(crate) async fn get() -> Json<Health> {
    Json(Health {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
        build: vpnctl_core::build_version(),
    })
}
