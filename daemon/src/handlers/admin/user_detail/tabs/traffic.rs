use maud::{Markup, html};

use crate::AppState;
use crate::handlers::admin::legacy::{live_vpn_stats_section, user_top_destinations_section};
use crate::handlers::admin::user_detail::types::UserDetailQuery;
use crate::i18n::Locale;

pub(crate) async fn render_traffic_tab(
    state: &AppState,
    uid: &vpnctl_core::UserId,
    query: &UserDetailQuery,
    lang: Locale,
) -> Markup {
    html! {
        // R2 2026-07-10: the fixed-24h «Traffic by server» table
        // that used to open this tab duplicated the window-driven
        // per-server table inside Live-VPN-stats below (same
        // numbers at the default 24h window). The live table
        // gained its «total» column; one table remains.

        // ── Live VPN stats (Track-3 chunk 3) + user#6 trend ──────
        // The window picker (24h/7d/30d/all) is now folded INTO this
        // section — it re-fetches the picked window's rows once and
        // drives both the compact `sparkline_svg` trend and the full
        // chart, so the previous page-level picker is gone (it would
        // have rendered a second, duplicate picker).
        (live_vpn_stats_section(state, uid, query.vpn_window.as_deref(), lang).await)
        (user_top_destinations_section(state, uid, lang).await)
    }
}
