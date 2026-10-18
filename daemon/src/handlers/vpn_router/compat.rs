const VPN_CLIENT_KEYWORDS: &[&str] = &[
    "streisand",
    "v2rayn",
    "v2rayng",
    "v2raytun",
    "shadowrocket",
    "quantumult",
    "surge",
    "clash",
    "sing-box",
    "hiddify",
    "nekoray",
    "nekobox",
    "v2box",
    "foxray",
    "matsuri",
    "sagernet",
    "karing",
    "happ",
];

pub(crate) fn is_vpn_client_ua(ua: &str) -> bool {
    is_vpn_client_ua_v2ray_family(ua)
}

pub(crate) fn is_vpn_client_ua_v2ray_family(ua: &str) -> bool {
    let lower = ua.to_ascii_lowercase();
    VPN_CLIENT_KEYWORDS.iter().any(|kw| lower.contains(kw))
}

const VPNROUTER_CLIENT_UAS: &[&str] = &["vpnrouter"];

pub(crate) fn is_vpnrouter_client_ua(ua: &str) -> bool {
    let lower = ua.to_ascii_lowercase();
    VPNROUTER_CLIENT_UAS.iter().any(|kw| lower.contains(kw))
}

const V2RAY_CORE_NO_SINGBOX_TRANSPORTS: &[&str] = &["v2raytun", "v2rayn"];

pub(crate) fn client_supports_singbox_transports(ua: &str) -> bool {
    let lower = ua.to_ascii_lowercase();
    !V2RAY_CORE_NO_SINGBOX_TRANSPORTS
        .iter()
        .any(|kw| lower.contains(kw))
}

pub(crate) fn country_display_name(server_id: &str) -> String {
    match server_id.to_ascii_lowercase().as_str() {
        "de" => "Germany".into(),
        "is" => "Iceland".into(),
        "fi" => "Finland".into(),
        "se" => "Sweden".into(),
        "nl" => "Netherlands".into(),
        "us" => "United States".into(),
        "gb" => "United Kingdom".into(),
        "fr" => "France".into(),
        _ => server_id.to_ascii_uppercase(),
    }
}

pub(crate) fn server_display_label(server_id: &str, custom: Option<&str>) -> String {
    match custom.map(str::trim).filter(|s| !s.is_empty()) {
        Some(c) => c.to_string(),
        None => country_display_name(server_id),
    }
}
