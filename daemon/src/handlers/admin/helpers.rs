//! Common utility functions and formatting helpers for admin UI handlers.

//! Common utility functions and formatting helpers for admin UI handlers.

use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use maud::{DOCTYPE, Markup, html};

use crate::AppState;
use super::ui::{foot, root_class, topbar};

const COOKIE_THEME: &str = "vpnctl_theme";
const COOKIE_ACCENT: &str = "vpnctl_accent";

pub(crate) async fn topbar_alert_count(state: &AppState) -> u64 {
    state.inv.unacked_alert_count().await.unwrap_or(0)
}

#[allow(clippy::needless_pass_by_value)]
pub(crate) async fn render_page(
    state: &AppState,
    active_nav: &str,
    theme: &str,
    accent: &str,
    lang: crate::i18n::Locale,
    body: Markup,
) -> Markup {
    let alerts = topbar_alert_count(state).await;
    shell(active_nav, theme, accent, lang, alerts, body)
}

#[allow(clippy::needless_pass_by_value)]
pub(crate) fn shell(
    active_nav: &str,
    theme: &str,
    accent: &str,
    lang: crate::i18n::Locale,
    alerts_unacked: u64,
    body: Markup,
) -> Markup {
    let cls = root_class(theme, accent);
    html! {
        (DOCTYPE)
        html lang=(lang.html_lang()) {
            head {
                meta charset="utf-8" {}
                meta name="viewport" content="width=device-width, initial-scale=1" {}
                title { "vpnctl admin" }
                link rel="icon" type="image/svg+xml" href="/admin/assets/favicon.svg" {}
                link rel="stylesheet" href="/admin/assets/admin.css" {}
                script src="/admin/assets/admin.js" defer {}
            }
            body {
                div class=(cls) {
                    (topbar(active_nav, lang, alerts_unacked))
                    main.ed-main {
                        (body)
                    }
                    (foot(lang))
                }
            }
        }
    }
}

pub(crate) fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in raw.split(';') {
        let part = part.trim();
        if let Some((k, v)) = part.split_once('=') {
            if k == name {
                return Some(v);
            }
        }
    }
    None
}

pub(crate) fn theme_accent(headers: &HeaderMap) -> (String, String) {
    let theme = cookie(headers, COOKIE_THEME)
        .unwrap_or("default")
        .to_string();
    let accent = cookie(headers, COOKIE_ACCENT)
        .unwrap_or("default")
        .to_string();
    (theme, accent)
}

pub(crate) fn theme_accent_lang(headers: &HeaderMap) -> (String, String, crate::i18n::Locale) {
    let (theme, accent) = theme_accent(headers);
    let lang = crate::i18n::Locale::from_request(headers);
    (theme, accent, lang)
}

#[allow(clippy::needless_pass_by_value)]
pub(crate) fn internal_error(err: anyhow::Error) -> Response {
    tracing::error!(
        target = "vpnctld::admin",
        error = format!("{err:#}"),
        "handler failed; returning opaque 500 to client"
    );
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        error_text("internal error — please retry the action"),
    )
        .into_response()
}

pub(crate) fn error_text(detail: &str) -> String {
    let sanitised = detail.replace(['\n', '\r'], " ");
    format!("vpnctl admin: {sanitised}\n")
}

pub(crate) fn error_resp(status: StatusCode, detail: &str) -> Response {
    (status, error_text(detail)).into_response()
}

pub(crate) fn bad_request(detail: &str) -> Response {
    error_resp(StatusCode::BAD_REQUEST, detail)
}

pub(crate) fn not_found(detail: &str) -> Response {
    error_resp(StatusCode::NOT_FOUND, detail)
}

pub(crate) fn user_not_found(id: &str) -> Response {
    not_found(&format!("no such user '{id}'"))
}

pub(crate) fn unauthorized(detail: &str) -> Response {
    error_resp(StatusCode::UNAUTHORIZED, detail)
}

static DISPLAY_TZ: std::sync::OnceLock<std::sync::RwLock<chrono_tz::Tz>> =
    std::sync::OnceLock::new();

pub(crate) fn init_display_tz(tz: chrono_tz::Tz) {
    let _ = DISPLAY_TZ.set(std::sync::RwLock::new(tz));
}

pub(crate) fn set_display_tz_cache(tz: chrono_tz::Tz) {
    if let Some(lock) = DISPLAY_TZ.get() {
        if let Ok(mut guard) = lock.write() {
            *guard = tz;
        }
    } else {
        let _ = DISPLAY_TZ.set(std::sync::RwLock::new(tz));
    }
}

pub(crate) fn display_tz() -> chrono_tz::Tz {
    DISPLAY_TZ
        .get()
        .and_then(|lock| lock.read().ok().map(|g| *g))
        .unwrap_or(chrono_tz::Europe::Moscow)
}

pub(crate) fn humanize_bytes(n: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    if n < 1024 {
        return format!("{n} B");
    }
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

pub(crate) fn humanize_age(d: chrono::Duration, lang: crate::i18n::Locale) -> String {
    use crate::i18n::tr;
    let secs = d.num_seconds();
    if secs < 60 {
        return tr(lang, "just now", "только что").to_string();
    }
    let mins = secs / 60;
    if mins < 60 {
        return format!("{}{}", mins, tr(lang, "m ago", "м назад"));
    }
    let hours = mins / 60;
    if hours < 24 {
        return format!("{}{}", hours, tr(lang, "h ago", "ч назад"));
    }
    let days = hours / 24;
    format!("{}{}", days, tr(lang, "d ago", "д назад"))
}

pub(crate) fn humanize_since(
    ts: chrono::DateTime<chrono::Utc>,
    lang: crate::i18n::Locale,
) -> String {
    use crate::i18n::tr;
    let secs = (chrono::Utc::now() - ts).num_seconds().max(0);
    if secs < 60 {
        tr(lang, "just now", "только что").to_string()
    } else if secs < 3600 {
        format!("{}{}", secs / 60, tr(lang, "m ago", "м назад"))
    } else if secs < 86_400 {
        format!("{}{}", secs / 3600, tr(lang, "h ago", "ч назад"))
    } else {
        format!("{}{}", secs / 86_400, tr(lang, "d ago", "д назад"))
    }
}

pub(crate) fn format_msk(dt: chrono::DateTime<chrono::Utc>) -> String {
    format_local_with_pattern(dt, "%m-%d %H:%M")
}

pub(crate) fn format_msk_iso(dt: chrono::DateTime<chrono::Utc>) -> String {
    format_local_with_pattern(dt, "%Y-%m-%d %H:%M")
}

pub(crate) fn format_local_with_pattern(
    dt: chrono::DateTime<chrono::Utc>,
    pattern: &str,
) -> String {
    let tz = display_tz();
    let local = dt.with_timezone(&tz);
    local.format(&format!("{pattern} %Z")).to_string()
}

pub(crate) fn pct_color(pct: Option<u8>) -> &'static str {
    match pct {
        Some(p) if p >= 99 => "#2e7d32", // green
        Some(p) if p >= 95 => "#e6a23c", // amber
        Some(_) => "#c62828",            // red (incl. Some(0))
        None => "var(--mute)",           // grey
    }
}

pub(crate) fn pct_label(pct: Option<u8>, lang: crate::i18n::Locale) -> String {
    match pct {
        Some(p) => format!("{p}%"),
        None => crate::i18n::tr(lang, "— no data", "— нет данных").to_string(),
    }
}

pub(crate) fn pct_disk(h: &vpnctl_inventory::NodeHealthRow) -> Option<u8> {
    let (used, total) = (h.disk_used_mib?, h.disk_total_mib?);
    if total == 0 {
        return None;
    }
    Some(((used.saturating_mul(100)) / total).min(100) as u8)
}

pub(crate) fn pct_mem(h: &vpnctl_inventory::NodeHealthRow) -> Option<u8> {
    let (avail, total) = (h.mem_available_mib?, h.mem_total_mib?);
    if total == 0 {
        return None;
    }
    let free_pct = ((avail.saturating_mul(100)) / total).min(100) as u8;
    Some(100u8.saturating_sub(free_pct))
}

pub(crate) fn quality_score_color(score: Option<u8>) -> &'static str {
    match score {
        Some(80..=100) => "#2e7d32",
        Some(60..=79) => "#e6a23c",
        Some(_) => "#c62828",
        None => "var(--mute)",
    }
}

pub(crate) fn extract_ip_from_label(label: &str) -> Option<&str> {
    if !label.is_empty()
        && !label.contains(':')
        && label.chars().all(|c| c.is_ascii_digit() || c == '.')
    {
        return Some(label);
    }
    let (left, right) = label.rsplit_once(':')?;
    if left.is_empty() || right.is_empty() {
        return None;
    }
    if !right.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    if !left.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return None;
    }
    Some(left)
}

pub(crate) fn enrich_destination_label(
    label: &str,
    dns_map: &std::collections::HashMap<String, Option<String>>,
) -> String {
    let Some(ip) = extract_ip_from_label(label) else {
        return label.to_string();
    };
    let Some(Some(host)) = dns_map.get(ip) else {
        return label.to_string();
    };
    let port_suffix = label.strip_prefix(ip).unwrap_or("");
    format!("{host}{port_suffix} ({ip})")
}

pub(crate) fn classify_reserved_ip(ip: &str) -> Option<&'static str> {
    use std::net::IpAddr;
    match ip.parse::<IpAddr>().ok()? {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            if v4.is_loopback() {
                Some("loopback")
            } else if v4.is_private() {
                Some("private/LAN")
            } else if o[0] == 100 && (o[1] & 0xc0) == 0x40 {
                Some("CGNAT")
            } else if v4.is_link_local() {
                Some("link-local")
            } else if v4.is_unspecified() {
                Some("unspecified")
            } else {
                None
            }
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() {
                Some("loopback")
            } else if v6.is_unspecified() {
                Some("unspecified")
            } else {
                let seg = v6.segments();
                if (seg[0] & 0xfe00) == 0xfc00 {
                    Some("private/ULA")
                } else if (seg[0] & 0xffc0) == 0xfe80 {
                    Some("link-local")
                } else {
                    None
                }
            }
        }
    }
}

pub(crate) fn ip_geo_fallback(ip: &str, unknown: &str) -> Markup {
    match classify_reserved_ip(ip) {
        Some(cls) => html! { em style="color: var(--mute);" { (cls) } },
        None => html! { em style="color: var(--mute);" { (unknown) } },
    }
}

pub(crate) fn sanitize_referer(referer: Option<&str>) -> String {
    let raw = match referer {
        Some(r) => r,
        None => return "/admin/".to_string(),
    };
    if raw.contains('\n') || raw.contains('\r') {
        return "/admin/".to_string();
    }
    let path = if let Some(stripped) = raw
        .strip_prefix("http://")
        .or_else(|| raw.strip_prefix("https://"))
    {
        match stripped.find('/') {
            Some(i) => &stripped[i..],
            None => return "/admin/".to_string(),
        }
    } else if raw.starts_with('/') {
        raw
    } else {
        return "/admin/".to_string();
    };
    let path_only = path.split(['?', '#']).next().unwrap_or(path);
    if path_only == "/admin" || path_only.starts_with("/admin/") {
        path.to_string()
    } else {
        "/admin/".to_string()
    }
}

pub(crate) fn read_cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let cookie_header = headers.get(header::COOKIE)?.to_str().ok()?;
    for pair in cookie_header.split(';') {
        let mut parts = pair.trim().splitn(2, '=');
        if let (Some(k), Some(v)) = (parts.next(), parts.next()) {
            if k == name {
                return Some(v);
            }
        }
    }
    None
}

pub(crate) fn valid_user_id(id: &str) -> bool {
    let len = id.len();
    if !(2..=32).contains(&len) {
        return false;
    }
    id.bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-'))
}

pub(crate) fn valid_server_id(id: &str) -> bool {
    let len = id.len();
    if !(1..=64).contains(&len) {
        return false;
    }
    id.bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

pub(crate) fn parse_version_tuple(raw: &str) -> Option<(u64, u64, u64)> {
    let trimmed = raw.trim().trim_start_matches('v');
    if trimmed.is_empty() {
        return None;
    }
    let mut parts = trimmed.split('.');
    let numeric_prefix = |s: &str| -> Option<u64> {
        let n: String = s.chars().take_while(char::is_ascii_digit).collect();
        (!n.is_empty()).then_some(n)?.parse().ok()
    };
    let major = numeric_prefix(parts.next()?)?;
    let minor = parts.next().and_then(numeric_prefix).unwrap_or(0);
    let patch = parts.next().and_then(numeric_prefix).unwrap_or(0);
    Some((major, minor, patch))
}

#[derive(Debug, Clone, Default)]
pub(crate) struct KernelObservation {
    pub(crate) version: Option<String>,
    pub(crate) active: Option<bool>,
}

pub(crate) fn kernel_observations_of(
    kernel_versions_json: Option<&str>,
) -> std::collections::BTreeMap<String, KernelObservation> {
    let Some(raw) = kernel_versions_json else {
        return std::collections::BTreeMap::new();
    };
    let Ok(serde_json::Value::Object(values)) = serde_json::from_str(raw) else {
        return std::collections::BTreeMap::new();
    };
    values
        .into_iter()
        .filter_map(|(kernel, value)| match value {
            serde_json::Value::String(version) => Some((
                kernel,
                KernelObservation {
                    version: Some(version),
                    active: None,
                },
            )),
            serde_json::Value::Object(fields) => Some((
                kernel,
                KernelObservation {
                    version: fields
                        .get("version")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_string),
                    active: fields.get("active").and_then(serde_json::Value::as_bool),
                },
            )),
            _ => None,
        })
        .collect()
}

pub(crate) fn compact_kernel_version(kernel: &str, version: &str) -> String {
    let len = version.chars().count();
    match kernel {
        "wgturn" if len > 10 && version.chars().all(|c| c.is_ascii_hexdigit()) => {
            version.chars().take(10).collect()
        }
        "amneziawg" if len > 13 => format!(
            "{}…{}",
            version.chars().take(8).collect::<String>(),
            version.chars().skip(len - 4).collect::<String>()
        ),
        _ => version.to_string(),
    }
}

pub(crate) fn kernel_priority(kernel: &str) -> u8 {
    match kernel {
        "sing-box" => 0,
        "xray" => 1,
        "amneziawg" => 2,
        _ => 3,
    }
}

pub(crate) fn ordered_kernel_ids(server: &vpnctl_core::Server) -> Vec<&vpnctl_core::KernelId> {
    let mut kernels = server.kernels.iter().collect::<Vec<_>>();
    kernels.sort_by_key(|kernel| (kernel_priority(&kernel.0), kernel.0.as_str()));
    kernels
}

pub(crate) fn kernel_versions_inline(
    server: &vpnctl_core::Server,
    kernel_versions_json: Option<&str>,
    fleet_majority_version: Option<&str>,
) -> Markup {
    let observations = kernel_observations_of(kernel_versions_json);
    let kernels = ordered_kernel_ids(server);
    let full_versions = kernels
        .iter()
        .map(|kid| {
            let version = observations
                .get(&kid.0)
                .and_then(|o| o.version.as_deref())
                .unwrap_or("—");
            format!("{} {version}", kid.0)
        })
        .collect::<Vec<_>>()
        .join(" · ");
    html! {
        div.ed-kvers title=(full_versions) {
            @for kid in kernels {
                span.ed-kvers__item {
                    span.ed-grid__mut { (kid.0) " " }
                    @if let Some(version) = observations.get(&kid.0).and_then(|o| o.version.as_deref()) {
                        span.ed-kvers__value title=(version) {
                            (compact_kernel_version(&kid.0, version))
                            @if kid.0 == "sing-box" && fleet_majority_version.is_some_and(|majority| majority != version) {
                                " ≠"
                            }
                        }
                    } @else {
                        span.ed-grid__mut { "—" }
                    }
                }
            }
        }
    }
}
