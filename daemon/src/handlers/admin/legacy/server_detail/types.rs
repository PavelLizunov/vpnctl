use maud::{Markup, html};

/// Query string for the server-detail page (PR-Server).
///
/// * `drift=live` — opt-in flag that arms the highest-risk card
///   (server#1 drift-detail): a best-effort live SSH read of the
///   node's `/etc/sing-box/config.json` to diff the on-node UUIDs
///   against inventory. GATED so the DEFAULT page load stays fast —
///   no SSH happens unless the operator clicks «check live drift».
/// * `vpn_window` — shared window slug (`24h|7d|30d|all`) consumed by
///   the per-server traffic sparkline's `window_picker_section`, same
///   shape as the dashboard + user-detail pages.
#[derive(serde::Deserialize, Default)]
pub(crate) struct ServerDetailQuery {
    #[serde(default)]
    pub(crate) drift: Option<String>,
    #[serde(default)]
    pub(crate) vpn_window: Option<String>,
    /// v2 3d — grants-tab sort: `id` (default) · `presence` · `traffic`.
    #[serde(default)]
    pub(crate) grant_sort: Option<String>,
}

impl ServerDetailQuery {
    /// True only for the explicit `?drift=live` opt-in. Any other
    /// value (absent, `?drift=`, `?drift=foo`) keeps the live SSH
    /// read disarmed — the default fast path.
    pub(crate) fn drift_live(&self) -> bool {
        matches!(self.drift.as_deref(), Some("live"))
    }
}

/// server_detail's in-page tabs (ui-audit §3-§4). Each is a real
/// sub-route (`/admin/servers/{id}/{slug}`) so navigation is plain
/// `<a href>` — zero JS, back-button-correct, deep-linkable — and each
/// tab renders only its own sections. `Status` is the default (bare
/// `/admin/servers/{id}`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ServerTab {
    Status,
    Activity,
    Protocols,
    Grants,
    Setup,
}

impl ServerTab {
    pub(crate) fn slug(self) -> &'static str {
        match self {
            ServerTab::Status => "status",
            ServerTab::Activity => "activity",
            ServerTab::Protocols => "protocols",
            ServerTab::Grants => "grants",
            ServerTab::Setup => "setup",
        }
    }
}

/// The `.ed-tabs` bar — dead CSS since Phase A (admin.css:608), worn
/// here for the first time. `base` must already be path-segment-encoded;
/// `active` is the current tab's slug (its link gets `.ed-tab--on`).
/// `cursor`/`text-decoration` are set inline because the dead CSS was
/// authored for JS toggles (cursor:default, no link reset).
pub(crate) fn detail_tabs(base: &str, active: &str, tabs: &[(&str, &str)]) -> Markup {
    html! {
        div.ed-tabs {
            @for (slug, label) in tabs {
                a class=(if *slug == active { "ed-tab ed-tab--on" } else { "ed-tab" })
                  href=(format!("{base}/{slug}"))
                  style="cursor: pointer; text-decoration: none;" {
                    (label)
                }
            }
        }
    }
}
