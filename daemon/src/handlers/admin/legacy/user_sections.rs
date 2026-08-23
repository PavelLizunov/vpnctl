//! Admin UI legacy handlers — user sections facade over thematic submodules.

mod origins;
mod sessions;
mod share_links;
mod tasks;
mod traffic;

pub(crate) use self::origins::{
    ua_clusters_section, user_is_likely_shared, user_online_badge, user_source_ips_section,
    user_subscription_origins_section,
};
pub(crate) use self::sessions::{user_sessions_section, user_top_destinations_section};
pub(crate) use self::share_links::{
    collect_amnezia_links, collect_awg_links, collect_share_links, ninitux_url, qr_svg,
    share_link_card, sub_url,
};
pub(crate) use self::tasks::spawn_user_servers_redeploy;
pub(crate) use self::traffic::{
    DEFAULT_TRAFFIC_THRESHOLD_PCT, live_vpn_stats_section, user_traffic_limit_section,
};

#[cfg(test)]
pub(super) use self::origins::classify_reserved_ip;
pub(super) use self::traffic::{
    VpnSparklineWindow, pick_vpn_sparkline_window, vpn_traffic_chart, window_picker_section,
};
