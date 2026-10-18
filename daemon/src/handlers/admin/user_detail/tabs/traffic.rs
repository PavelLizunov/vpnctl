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

        (live_vpn_stats_section(state, uid, query.vpn_window.as_deref(), lang).await)
        (user_top_destinations_section(state, uid, lang).await)
    }
}
