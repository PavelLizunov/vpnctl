//! Compatibility filters, UA matching and server label helpers for
//! the ninitux subscription compatibility endpoint.

/// Lowercase substrings that identify a standard VPN client UA — when
/// any of these appear in the header, the response switches to raw
/// base64 instead of the JSON wrapper. Verbatim from
/// `_VPN_CLIENT_KEYWORDS` in
/// `subscription-server/app/routers/subscription.py`.
const VPN_CLIENT_KEYWORDS: &[&str] = &[
    "streisand",
    "v2rayn",
    "v2rayng",
    // 2026-05-23 quickfix (Pavel: «через V2raytun наш QR не
    // работает»). V2rayTun is the iOS V2Ray successor; its UA
    // («V2rayTun/2.x CFNetwork/x Darwin/x») lowercases to
    // `v2raytun` — NOT a substring of `v2rayn` (which lacks the
    // `tu`), so we need an explicit entry.
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
    // 2026-06-16 (Pavel: «Happ пишет json-error»). Happ (happ.su) is a
    // sing-box-based iOS/Android/desktop client whose UA lowercases to
    // contain `happ` (e.g. «Happ/1.6.0 (iPhone; iOS 18.0)»). Without an
    // entry it fell through to the `render_singbox` JSON branch and Happ —
    // which imports a subscription URL as the universal base64 share-link
    // list, NOT a raw sing-box config — choked with a JSON parse error.
    // Routing it to the base64 path fixes import. Happ runs sing-box core,
    // so it is intentionally NOT in `V2RAY_CORE_NO_SINGBOX_TRANSPORTS` —
    // it still receives the hysteria2/tuic/anytls entries (e.g. Latvia HY2).
    "happ",
];

pub(crate) fn is_vpn_client_ua(ua: &str) -> bool {
    is_vpn_client_ua_v2ray_family(ua)
}

/// Re-export of [`is_vpn_client_ua`] for cross-module use (sub.rs
/// quickfix 2026-05-23 — V2Ray-family UA dispatch on the legacy
/// `/sub/<token>` endpoint). Keeping a single keyword list +
/// classifier so the two endpoints can't drift on which UAs
/// trigger the raw base64 path.
pub(crate) fn is_vpn_client_ua_v2ray_family(ua: &str) -> bool {
    let lower = ua.to_ascii_lowercase();
    VPN_CLIENT_KEYWORDS.iter().any(|kw| lower.contains(kw))
}

/// UAs of the operator's custom VPNRouter client — the only one that speaks
/// the custom subscription schemes (`awg://` AmneziaWG + `vless://…type=xhttp`).
/// A generic v2ray/clash/sing-box client on this endpoint would at best ignore
/// such a line and at worst (strict parser) drop the whole config, so those
/// schemes are UA-gated to VPNRouter only — a generic client never sees them,
/// eliminating the forward-compat risk of advertising a custom transport
/// fleet-wide. Extend the list if a second custom-scheme-aware client appears.
const VPNROUTER_CLIENT_UAS: &[&str] = &["vpnrouter"];

pub(crate) fn is_vpnrouter_client_ua(ua: &str) -> bool {
    let lower = ua.to_ascii_lowercase();
    VPNROUTER_CLIENT_UAS.iter().any(|kw| lower.contains(kw))
}

/// V2Ray/Xray-core clients in the v2ray family that do NOT speak the
/// sing-box-only transports (Hysteria2 / TUIC / AnyTLS). Emitting a
/// `hysteria2://` / `tuic://` / `anytls://` share-link to one of these
/// breaks its whole subscription import — the user sees the supported
/// (VLESS) configs vanish too. 2026-06-16 (Pavel): V2rayTun stopped
/// importing VLESS once a `hysteria2://` entry led the list, while the
/// cdn Hysteria2 + the de/is/nl VLESS were all server-healthy. Sing-box-
/// core clients (Streisand, NekoBox, Shadowrocket, Hiddify, …) parse
/// these fine and keep the full set. `v2rayn` is a substring of
/// `v2rayng`, so the two share one entry; `v2raytun` is NOT (`tu` breaks
/// the match), hence its own.
const V2RAY_CORE_NO_SINGBOX_TRANSPORTS: &[&str] = &["v2raytun", "v2rayn"];

/// True when the client's UA can parse the sing-box-only transports
/// (Hysteria2 / TUIC / AnyTLS) in a base64 share-link subscription.
/// Permissive by default (an unknown / sing-box-core UA → true); returns
/// false only for the known V2Ray/Xray-core denylist above.
pub(crate) fn client_supports_singbox_transports(ua: &str) -> bool {
    let lower = ua.to_ascii_lowercase();
    !V2RAY_CORE_NO_SINGBOX_TRANSPORTS
        .iter()
        .any(|kw| lower.contains(kw))
}

/// Map an ISO-3166-1 alpha-2 server id to a user-facing country name.
///
/// Server IDs in vpnctld inventory follow the convention (post-2026-05-20
/// rename): two-letter lowercase ISO codes for production country nodes
/// (`de`, `is`, `fi`, `nl`, `us`, …). The label rendered into the
/// subscription URI fragment (`#Germany VLESS`) is what end-users see
/// in their mobile app's outbound list — Pavel's UX requirement: «по
/// названию легко понять для чего конфиг и что за сервер».
///
/// Unknown IDs (legacy multi-segment slugs, test servers, ad-hoc
/// names) fall back to uppercased ID — operator-debugging-friendly,
/// still distinct from production country names. When adding a new
/// production country, extend the match arm here AND rename the
/// inventory row (`UPDATE servers SET id='nl' WHERE id='vps-nl-01'`).
///
/// Hard-coded mapping (not a `servers.display_name` column) because:
///   1. ISO country codes are an external standard, not operator data
///   2. Adding a column + UI form for editing is scope creep — the
///      country mapping is stable (Germany was Germany 50 years ago)
///   3. Compiled mapping means typos surface at build time
pub(crate) fn country_display_name(server_id: &str) -> String {
    // Case-insensitive lookup (2026-06-04): quick-add now accepts
    // mixed-case server ids, and `De`/`DE` should still map to
    // Germany rather than fall through to the uppercased-id branch.
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

/// Resolve the user-facing server label for the subscription URI
/// fragment / outbound tag. Precedence: operator-set `display_name`
/// (from `servers.display_name`, passed in as `custom`) → the hard-coded
/// ISO-code→country map → uppercased id. This is the single source of
/// truth shared by both the `/sub` and `/api/v1/app/config` render paths
/// so a server is labelled identically in every client.
pub(crate) fn server_display_label(server_id: &str, custom: Option<&str>) -> String {
    match custom.map(str::trim).filter(|s| !s.is_empty()) {
        Some(c) => c.to_string(),
        None => country_display_name(server_id),
    }
}
