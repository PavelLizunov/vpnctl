//! User detail integration smoke tests: overview, routes, subscription, share links, WireGuard, traffic, activity, access, origins, presence.

#[path = "user_detail/access_origins_presence.rs"]
mod access_origins_presence;
#[path = "user_detail/chain_subscription.rs"]
mod chain_subscription;
#[path = "user_detail/overview_routes.rs"]
mod overview_routes;
#[path = "user_detail/subscription_share_links.rs"]
mod subscription_share_links;
#[path = "user_detail/traffic_activity.rs"]
mod traffic_activity;
#[path = "user_detail/wireguard.rs"]
mod wireguard;
