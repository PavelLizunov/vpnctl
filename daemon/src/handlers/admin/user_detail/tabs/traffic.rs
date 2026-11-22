use maud::{Markup, html};

use crate::AppState;
use crate::handlers::admin::legacy::{
    live_vpn_stats_section, user_top_destinations_section, user_traffic_limit_section,
};
use crate::handlers::admin::user_detail::types::UserDetailQuery;
use crate::i18n::Locale;

pub(crate) async fn render_traffic_tab(
    state: &AppState,
    uid: &vpnctl_core::UserId,
    query: &UserDetailQuery,
    lang: Locale,
) -> Markup {
    let filters = (
        query.vpn_window.as_deref().unwrap_or("24h"),
        query.vpn_server.as_deref(),
    );
    html! {
        (user_traffic_limit_section(state, uid, lang, Some(filters)).await)
        (live_vpn_stats_section(
            state,
            uid,
            query.vpn_window.as_deref(),
            query.vpn_server.as_deref(),
            lang,
        ).await)
        details.ed-traffic-disclosure {
            summary { (crate::i18n::tr(lang, "Destinations · all nodes, last 7 days", "Назначения · все узлы за 7 дней")) }
            (user_top_destinations_section(state, uid, lang).await)
        }
    }
}
