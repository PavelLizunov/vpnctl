//! Common utility functions and formatting helpers for admin UI handlers.

use axum::extract::Path;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use maud::{DOCTYPE, Markup, html};

use super::ui::{foot, root_class, topbar};
use crate::AppState;

pub(crate) const COOKIE_THEME: &str = "vpnctl_theme";
pub(crate) const COOKIE_ACCENT: &str = "vpnctl_accent";
const VALID_THEMES: &[&str] = &["default", "newsprint", "foxed", "ink"];
const VALID_ACCENTS: &[&str] = &["default", "rust", "forest", "plum"];
const VALID_LANGS: &[&str] = &["en", "ru"];

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
    for hdr in headers.get_all(header::COOKIE) {
        let Ok(raw) = hdr.to_str() else { continue };
        for part in raw.split(';') {
            let part = part.trim();
            if let Some((k, v)) = part.split_once('=') {
                if k == name {
                    return Some(v);
                }
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

pub(crate) const COOKIE_LANG: &str = "vpnctl_lang";

pub(crate) fn set_tweak_cookie(
    headers: &HeaderMap,
    cookie_name: &str,
    valid: &[&str],
    body: &str,
) -> Response {
    let value = body
        .split('&')
        .find_map(|kv| kv.strip_prefix("value="))
        .unwrap_or("");
    if !valid.contains(&value) {
        return bad_request(&format!(
            "invalid value '{value}' for tweak '{cookie_name}' (allowed: {})",
            valid.join(", ")
        ));
    }
    let cookie_val =
        format!("{cookie_name}={value}; Path=/admin; Max-Age=31536000; HttpOnly; SameSite=Lax");
    let referer = headers.get(header::REFERER).and_then(|v| v.to_str().ok());
    let target = sanitize_referer(referer);
    let mut resp = Redirect::to(&target).into_response();
    if let Ok(hv) = HeaderValue::from_str(&cookie_val) {
        resp.headers_mut().append(header::SET_COOKIE, hv);
    }
    resp
}

pub(crate) async fn set_tweak(
    headers: HeaderMap,
    Path(kind): Path<String>,
    body: String,
) -> Response {
    match kind.as_str() {
        "theme" => set_tweak_cookie(&headers, COOKIE_THEME, VALID_THEMES, &body),
        "accent" => set_tweak_cookie(&headers, COOKIE_ACCENT, VALID_ACCENTS, &body),
        "lang" => set_tweak_cookie(&headers, COOKIE_LANG, VALID_LANGS, &body),
        unknown => not_found(&format!(
            "unknown tweak kind '{unknown}' (known: theme, accent, lang)"
        )),
    }
}

pub(crate) async fn logout() -> Response {
    let mut resp = Redirect::to("/admin/").into_response();
    if let Ok(hv) = HeaderValue::from_str(&crate::handlers::auth::build_logout_cookie()) {
        resp.headers_mut().append(header::SET_COOKIE, hv);
    }
    resp
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

pub(crate) fn sparkline_svg_scaled(
    values: &[f64],
    width: u32,
    height: u32,
    y_max_override: Option<f64>,
    area_fill: bool,
) -> Markup {
    if values.is_empty() {
        return html! { svg width=(width) height=(height) viewBox=(format!("0 0 {width} {height}")) {} };
    }
    let max = y_max_override
        .unwrap_or_else(|| values.iter().copied().fold(0.0, f64::max))
        .max(1.0);
    let n = values.len();
    let dx = if n > 1 {
        width as f64 / (n - 1) as f64
    } else {
        width as f64
    };
    let points: Vec<(f64, f64)> = values
        .iter()
        .enumerate()
        .map(|(i, &v)| {
            let x = i as f64 * dx;
            let y =
                height as f64 - (v / max * (height as f64 - 2.0)).min(height as f64 - 2.0) - 1.0;
            (x, y)
        })
        .collect();

    let path_data = points
        .iter()
        .enumerate()
        .map(|(i, (x, y))| {
            if i == 0 {
                format!("M {x:.1} {y:.1}")
            } else {
                format!("L {x:.1} {y:.1}")
            }
        })
        .collect::<Vec<_>>()
        .join(" ");

    html! {
        svg width=(width) height=(height) viewBox=(format!("0 0 {width} {height}")) fill="none" style="display: block;" {
            @if area_fill && points.len() > 1 {
                @let (first_x, _) = points[0];
                @let (last_x, _) = points[points.len() - 1];
                @let area_path = format!("{path_data} L {last_x:.1} {height} L {first_x:.1} {height} Z");
                path d=(area_path) fill="var(--paper-tint)" opacity="0.5" {}
            }
            path d=(path_data) stroke="var(--ink)" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" {}
        }
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
    // Security: Reject path-traversal (`..`), protocol-relative redirects (`//`),
    // or backslashes (`\`) to prevent open redirects off-site (e.g. `/admin/../..//evil.com`).
    if (path_only == "/admin" || path_only.starts_with("/admin/"))
        && !path_only.contains("..")
        && !path_only.contains('\\')
        && !path_only.contains("//")
    {
        path.to_string()
    } else {
        "/admin/".to_string()
    }
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

pub(crate) fn sing_box_version_of(kernel_versions_json: Option<&str>) -> Option<String> {
    kernel_observations_of(kernel_versions_json)
        .remove("sing-box")
        .and_then(|o| o.version)
}

pub(crate) fn fleet_majority_version(
    kernel_versions: &[(vpnctl_core::ServerId, Option<String>)],
) -> Option<String> {
    let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for (_, j) in kernel_versions {
        if let Some(v) = sing_box_version_of(j.as_deref()) {
            *counts.entry(v).or_insert(0) += 1;
        }
    }
    counts
        .into_iter()
        .max_by(|(va, na), (vb, nb)| {
            na.cmp(nb)
                .then_with(|| parse_version_tuple(va).cmp(&parse_version_tuple(vb)))
                .then_with(|| va.cmp(vb))
        })
        .map(|(v, _)| v)
}

pub(crate) struct GeoIpDbStat {
    pub(crate) city_mtime: Option<chrono::DateTime<chrono::Utc>>,
    pub(crate) asn_mtime: Option<chrono::DateTime<chrono::Utc>>,
}

pub(crate) fn geoip_db_stat() -> GeoIpDbStat {
    let dir =
        std::env::var("VPNCTLD_GEOIP_DIR").unwrap_or_else(|_| "/var/lib/vpnctl/geoip".to_string());
    let path_city = std::path::Path::new(&dir).join("GeoLite2-City.mmdb");
    let path_asn = std::path::Path::new(&dir).join("GeoLite2-ASN.mmdb");
    let mtime = |p: &std::path::Path| {
        let meta = std::fs::metadata(p).ok()?;
        let sys_t = meta.modified().ok()?;
        Some(chrono::DateTime::<chrono::Utc>::from(sys_t))
    };
    GeoIpDbStat {
        city_mtime: mtime(&path_city),
        asn_mtime: mtime(&path_asn),
    }
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn cookie_handles_multiple_headers_and_first_match() {
        let mut headers = HeaderMap::new();
        headers.append(
            header::COOKIE,
            HeaderValue::from_static("other=123; vpnctl_theme=dark"),
        );
        headers.append(
            header::COOKIE,
            HeaderValue::from_static("vpnctl_theme=light; vpnctl_accent=blue"),
        );

        assert_eq!(cookie(&headers, "vpnctl_theme"), Some("dark"));
        assert_eq!(cookie(&headers, "vpnctl_accent"), Some("blue"));
        assert_eq!(cookie(&headers, "other"), Some("123"));
        assert_eq!(cookie(&headers, "nonexistent"), None);
    }

    #[test]
    fn sanitize_referer_accepts_valid_admin_paths() {
        assert_eq!(sanitize_referer(Some("/admin/users")), "/admin/users");
        assert_eq!(sanitize_referer(Some("/admin/")), "/admin/");
        assert_eq!(
            sanitize_referer(Some("http://192.168.0.236:18402/admin/audit")),
            "/admin/audit"
        );
        assert_eq!(
            sanitize_referer(Some("/admin/users?tab=grants")),
            "/admin/users?tab=grants"
        );
        assert_eq!(
            sanitize_referer(Some("/admin/settings#backups-section")),
            "/admin/settings#backups-section"
        );
    }

    #[test]
    fn sanitize_referer_rejects_open_redirect_and_path_traversal() {
        assert_eq!(sanitize_referer(Some("/admin/../..//evil.com")), "/admin/");
        assert_eq!(
            sanitize_referer(Some("http://192.168.0.236:18402/admin/../..//evil.com")),
            "/admin/"
        );
        assert_eq!(sanitize_referer(Some("/admin//evil.com")), "/admin/");
        assert_eq!(sanitize_referer(Some("/admin/\\evil.com")), "/admin/");
        assert_eq!(sanitize_referer(Some("//evil.com/admin/")), "/admin/");
        assert_eq!(sanitize_referer(Some("/\\evil.com/admin/")), "/admin/");
        assert_eq!(
            sanitize_referer(Some("http://evil.com/admin/../..//evil.com")),
            "/admin/"
        );
    }
}
