//! Types and query parameters for user-detail admin handlers.

/// Phase 4a — query parameters for the user-detail page.
/// (`?show_egress` left with the legacy Subscription-access table it
/// toggled, R2 2026-07-10 — the v2 geo-log always shows egress rows
/// inline with their ⚠ marker instead of hiding them.)
#[derive(Debug, Default, serde::Deserialize)]
pub(crate) struct UserDetailQuery {
    /// 2026-05-23 — VPN-traffic sparkline window. One of «24h»,
    /// «7d», «30d», «all». Defaults to 24h. Backed by
    /// `pick_vpn_sparkline_window`.
    #[serde(default)]
    pub(crate) vpn_window: Option<String>,
    /// v2 4c — Activity sub-access log page (0-based). 25 rows/page.
    #[serde(default)]
    pub(crate) log_page: Option<i64>,
}

impl UserDetailQuery {
    /// Clamped 0-based log page.
    pub(crate) fn log_page(&self) -> i64 {
        self.log_page.unwrap_or(0).clamp(0, 10_000)
    }
}

/// user_detail's in-page tabs (ui-audit §3-§4). Same recipe as
/// `ServerTab`: real sub-routes (`/admin/users/{id}/{slug}`), plain
/// `<a href>` links, each tab renders only its own sections. `Overview`
/// is the default (bare `/admin/users/{id}`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum UserTab {
    Overview,
    Delivery,
    Access,
    Activity,
    Traffic,
}

impl UserTab {
    pub(crate) fn slug(self) -> &'static str {
        match self {
            UserTab::Overview => "overview",
            UserTab::Delivery => "delivery",
            UserTab::Access => "access",
            UserTab::Activity => "activity",
            UserTab::Traffic => "traffic",
        }
    }
}
