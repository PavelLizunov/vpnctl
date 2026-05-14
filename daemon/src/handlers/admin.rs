//! Admin UI handlers — Phase A foundation.
//!
//! Builds the editorial-style v3 shell (masthead + inline nav + main +
//! footer) using `maud` SSR. Theme and accent are page-class modifiers
//! driven by cookies (`vpnctl_theme`, `vpnctl_accent`); switching is a
//! POST to `/admin/tweak/...` which sets the cookie and redirects back.
//!
//! All admin routes live behind a basic-auth middleware (see
//! `super::auth::basic_auth_layer`).

use std::collections::HashSet;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use maud::{DOCTYPE, Markup, html};

use crate::AppState;

const COOKIE_THEME: &str = "vpnctl_theme";
const COOKIE_ACCENT: &str = "vpnctl_accent";

const VALID_THEMES: &[&str] = &["default", "newsprint", "foxed", "ink"];
const VALID_ACCENTS: &[&str] = &["default", "rust", "forest", "plum"];

/// Inline glyph — `[•]` bracket-dot, scales with `currentColor`. Matches
/// `Glyph()` from the design source.
fn glyph(size: u32) -> Markup {
    let stroke = (size as f32 / 12.0).max(1.5);
    let r = (size as f32 / 9.0).max(1.6);
    html! {
        svg width=(size) height=(size) viewBox="0 0 24 24" fill="none" aria-hidden="true" style="display:block" {
            path d="M8 4 H5 V20 H8" stroke="currentColor" stroke-width=(stroke) stroke-linecap="square" fill="none" {}
            path d="M16 4 H19 V20 H16" stroke="currentColor" stroke-width=(stroke) stroke-linecap="square" fill="none" {}
            circle cx="12" cy="12" r=(r) fill="currentColor" {}
        }
    }
}

#[derive(Clone, Copy)]
struct NavItem {
    key: &'static str,
    label: &'static str,
    count: Option<usize>,
}

const NAV: &[NavItem] = &[
    NavItem {
        key: "dashboard",
        label: "Dashboard",
        count: None,
    },
    NavItem {
        key: "monitoring",
        label: "Monitoring",
        count: None,
    },
    NavItem {
        key: "servers",
        label: "Servers",
        count: None,
    },
    NavItem {
        key: "users",
        label: "Users",
        count: None,
    },
    NavItem {
        key: "audit",
        label: "Audit",
        count: None,
    },
    NavItem {
        key: "settings",
        label: "Settings",
        count: None,
    },
];

/// URL for a nav item. Dashboard lives at `/admin/` (canonical home),
/// other sections at `/admin/<key>`. Keeps URLs predictable.
fn nav_href(key: &str) -> String {
    if key == "dashboard" {
        "/admin/".to_string()
    } else {
        format!("/admin/{key}")
    }
}

fn nav(active: &str) -> Markup {
    html! {
        nav.ed-mast__nav-inline style="padding: 12px 56px 0; border-bottom: 1px solid var(--rule);" {
            @for it in NAV {
                // Real anchor with href — without it the previous version
                // rendered styled text that didn't navigate on click.
                //
                // The active branch emits `class="on"`; the inactive one
                // emits no class attribute at all. Maud's `.on[cond]` toggle
                // would have emitted `class=""` when false (verified
                // empirically), which is wasteful and would clutter
                // selector-based assertions.
                @if it.key == active {
                    a.on href=(nav_href(it.key)) {
                        (it.label)
                        @if let Some(c) = it.count {
                            span.ct { (c) }
                        }
                    }
                } @else {
                    a href=(nav_href(it.key)) {
                        (it.label)
                        @if let Some(c) = it.count {
                            span.ct { (c) }
                        }
                    }
                }
            }
            span style="margin-left: auto; font-family: var(--mono); font-size: 11px; color: var(--dim); letter-spacing: 0; text-transform: none;" {
                "homelab · operator pavel"
            }
        }
    }
}

fn masthead(date: &str, vol: &str) -> Markup {
    html! {
        div.ed-mast {
            div.ed-mast__logo {
                (glyph(20))
                "vpnctl"
            }
            span.ed-mast__sub { "— a daily report from your homelab" }
            span.ed-mast__date {
                b { (vol) }
                " · "
                (date)
            }
        }
    }
}

fn foot() -> Markup {
    html! {
        div.ed-foot {
            div.ed-foot__l {
                span { "vpnctld " (env!("CARGO_PKG_VERSION")) }
                span { "· axum + maud + htmx" }
            }
            span { "github.com/PavelLizunov/vpnctl" }
        }
    }
}

fn tweaks_panel(theme: &str, accent: &str) -> Markup {
    html! {
        // Bottom-right floating panel — matches the design's "Tweaks"
        // affordance (theme + accent toggles) but minimal: just two
        // segmented controls. Each option is a POST that flips the
        // cookie and redirects back.
        div style="position: fixed; right: 24px; bottom: 24px; z-index: 50; background: var(--paper); border: 1px solid var(--ink); padding: 12px 14px; font-family: var(--mono); font-size: 11px; color: var(--soft); box-shadow: 0 8px 24px rgba(0,0,0,0.12);" {
            div style="margin-bottom: 8px; letter-spacing: 0.14em; text-transform: uppercase; color: var(--mute);" { "Tweaks" }
            div style="display: flex; flex-direction: column; gap: 6px;" {
                form method="post" action="/admin/tweak/theme" style="display: flex; gap: 4px; align-items: baseline;" {
                    span style="width: 50px; color: var(--mute);" { "paper" }
                    @for &name in VALID_THEMES {
                        button name="value" value=(name)
                               style=(format!(
                                   "padding: 2px 7px; border: 1px solid var(--rule-s); background: {}; color: {}; font-family: var(--mono); font-size: 11px; cursor: pointer;",
                                   if name == theme { "var(--ink)" } else { "transparent" },
                                   if name == theme { "var(--paper)" } else { "var(--ink)" },
                               )) {
                            (name)
                        }
                    }
                }
                form method="post" action="/admin/tweak/accent" style="display: flex; gap: 4px; align-items: baseline;" {
                    span style="width: 50px; color: var(--mute);" { "accent" }
                    @for &name in VALID_ACCENTS {
                        button name="value" value=(name)
                               style=(format!(
                                   "padding: 2px 7px; border: 1px solid var(--rule-s); background: {}; color: {}; font-family: var(--mono); font-size: 11px; cursor: pointer;",
                                   if name == accent { "var(--acc)" } else { "transparent" },
                                   if name == accent { "var(--paper)" } else { "var(--ink)" },
                               )) {
                            (name)
                        }
                    }
                }
            }
        }
    }
}

/// Build the page-root class string from theme/accent (matches the v3
/// stylesheet — `.ed`, `.ed.ed-newsprint`, `.ed.ed-acc-rust`, etc.).
fn root_class(theme: &str, accent: &str) -> String {
    let mut cls = String::from("ed");
    match theme {
        "newsprint" => cls.push_str(" ed-newsprint"),
        "foxed" => cls.push_str(" ed-foxed"),
        "ink" => cls.push_str(" ed-ink"),
        _ => {}
    }
    match accent {
        "rust" => cls.push_str(" ed-acc-rust"),
        "forest" => cls.push_str(" ed-acc-forest"),
        "plum" => cls.push_str(" ed-acc-plum"),
        _ => {}
    }
    cls
}

/// Wraps a screen-specific body in the chrome (masthead + nav + main + foot
/// + tweaks). `body` is the inner content of `<main class="ed-main">`.
///
/// `Markup` (a `PreEscaped<String>`) is owned and small; passing by value
/// is intentional and clippy's needless_pass_by_value is over-eager here.
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn shell(active_nav: &str, theme: &str, accent: &str, body: Markup) -> Markup {
    let cls = root_class(theme, accent);
    html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8" {}
                meta name="viewport" content="width=device-width, initial-scale=1" {}
                title { "vpnctl admin" }
                link rel="preconnect" href="https://fonts.googleapis.com" {}
                link rel="preconnect" href="https://fonts.gstatic.com" crossorigin {}
                link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Newsreader:ital,opsz,wght@0,6..72,300;0,6..72,400;0,6..72,500;0,6..72,600;1,6..72,300;1,6..72,400&family=IBM+Plex+Sans:wght@300;400;500;600&family=IBM+Plex+Mono:wght@400;500&display=swap" {}
                link rel="stylesheet" href="/admin/assets/admin.css" {}
            }
            body {
                div class=(cls) {
                    (masthead("dynamic date TBD", "vol. 0.4"))
                    (nav(active_nav))
                    main.ed-main {
                        (body)
                    }
                    (foot())
                }
                (tweaks_panel(theme, accent))
            }
        }
    }
}

/// Read a cookie value from the request headers. Cheap manual parser —
/// avoids pulling a full cookie crate for two values.
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

/// Read theme + accent cookies into owned strings (default = "default").
fn theme_accent(headers: &HeaderMap) -> (String, String) {
    let theme = cookie(headers, COOKIE_THEME)
        .unwrap_or("default")
        .to_string();
    let accent = cookie(headers, COOKIE_ACCENT)
        .unwrap_or("default")
        .to_string();
    (theme, accent)
}

/// Visible accent + theme indicator strip — every Phase A screen renders
/// it so the operator gets immediate feedback when toggling either tweak.
/// The left border + the `ed-acc` span both read from `var(--acc)`, so a
/// rust/forest/plum switch is instantly visible (without it the placeholder
/// content didn't use the variable at all).
fn tweak_indicator(theme: &str, accent: &str) -> Markup {
    html! {
        div style="display: flex; gap: 16px; align-items: baseline; padding: 10px 14px; border-left: 3px solid var(--acc); background: var(--acc-bg); margin: 18px 0; font-family: var(--mono); font-size: 12px;" {
            span style="color: var(--mute);" { "tweaks live →" }
            span { "paper " span.ed-acc { (theme) } }
            span { "accent " span.ed-acc { (accent) } }
        }
    }
}

/// Aggregated counters used in the dashboard top-row metric tiles.
struct DashboardStats {
    servers: i64,
    users: i64,
    grants: i64,
    distinct_protocols: usize,
}

/// Pull every counter the dashboard needs in one pass. All five inventory
/// queries (4 counters + recent audit) are independent so we kick them off
/// in parallel via `try_join` — the round-trips are cheap, but rendering
/// should still feel instant even after the inventory grows.
async fn collect_dashboard_data(
    state: &AppState,
) -> anyhow::Result<(DashboardStats, Vec<vpnctl_inventory::AuditEntry>)> {
    let (servers_count, users_count, grants_count, server_list, audit) = tokio::try_join!(
        state.inv.count_servers(),
        state.inv.count_users(),
        state.inv.count_grants(),
        state.inv.list_servers(),
        state.inv.recent_audit(10),
    )?;
    let distinct_protocols: HashSet<_> = server_list
        .iter()
        .flat_map(|s| s.enabled_protocols.iter().map(|p| p.0.as_str()))
        .collect();
    let stats = DashboardStats {
        servers: servers_count,
        users: users_count,
        grants: grants_count,
        distinct_protocols: distinct_protocols.len(),
    };
    Ok((stats, audit))
}

/// Render an editorial 4-cell metric row from the dashboard stats.
fn dashboard_metrics(stats: &DashboardStats) -> Markup {
    html! {
        div.ed-metrics {
            div.ed-metric {
                span.ed-metric__lbl { "Servers" }
                span.ed-metric__v { (stats.servers) }
                span.ed-metric__sub { "in inventory" }
            }
            div.ed-metric {
                span.ed-metric__lbl { "Users" }
                span.ed-metric__v { (stats.users) }
                span.ed-metric__sub {
                    "across " b { (stats.grants) }
                    @if stats.grants == 1 { " grant" } @else { " grants" }
                }
            }
            div.ed-metric {
                span.ed-metric__lbl { "Protocols" }
                span.ed-metric__v { (stats.distinct_protocols) }
                span.ed-metric__sub { "distinct, enabled" }
            }
            div.ed-metric {
                span.ed-metric__lbl { "Daemon" }
                span.ed-metric__v { em { "live" } }
                span.ed-metric__sub { "vpnctld " b { (env!("CARGO_PKG_VERSION")) } }
            }
        }
    }
}

/// Editorial timeline of the most recent audit entries. Empty inventory
/// gets a deliberate "no activity yet" stub so the section never renders
/// as a bare rule.
fn dashboard_audit(audit: &[vpnctl_inventory::AuditEntry]) -> Markup {
    html! {
        div.ed-art-eyebrow style="margin-top: 28px;" { "Recent activity" }
        @if audit.is_empty() {
            p style="font-family: var(--serif); font-style: italic; color: var(--mute); padding: 12px 0;" {
                "No actions logged yet — vpnctl bootstrap / deploy / add-user will start filling this stream."
            }
        } @else {
            div.ed-time {
                @for e in audit {
                    div.ed-time-row {
                        // 16-char ISO clip — drops fractional seconds and Z.
                        span.ed-time-row__t { (clip_ts(&e.ts.to_rfc3339())) }
                        span class=(format!("ed-time-row__a ed-time-row__a--{}", action_kind(&e.action))) {
                            (e.action)
                        }
                        span.ed-time-row__tgt {
                            @match &e.target {
                                Some(t) => (t),
                                None => "—",
                            }
                        }
                        span.ed-time-row__pl {
                            "by " (e.actor)
                        }
                    }
                }
            }
        }
    }
}

/// Map an audit action like "server.deploy" to a CSS modifier matching
/// the editorial palette (deploy/create/grant/revoke/...). Unknown
/// suffixes fall back to "other" — never to a known kind, otherwise a
/// new untyped action would silently masquerade as a deploy in the
/// timeline.
fn action_kind(action: &str) -> &'static str {
    let kind = action.split('.').next_back().unwrap_or("");
    match kind {
        "deploy" => "deploy",
        "create" => "create",
        "grant" => "grant",
        "revoke" => "revoke",
        "regenerate" => "regenerate",
        "delete" | "remove" => "delete",
        "bootstrap" => "bootstrap",
        _ => "other",
    }
}

/// Trim an RFC3339 timestamp like "2026-05-14T11:55:32.819+00:00" to
/// "2026-05-14 11:55" — the timeline column is narrow and we don't
/// want fractional seconds eating it.
fn clip_ts(ts: &str) -> String {
    // Be defensive: short strings (shouldn't happen) just round-trip.
    if ts.len() < 16 {
        return ts.to_string();
    }
    // Replace 'T' with a space and drop everything past minutes.
    let head = &ts[..16];
    head.replacen('T', " ", 1)
}

pub(crate) async fn dashboard(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<Markup, Response> {
    let (theme, accent) = theme_accent(&headers);

    let (stats, audit) = collect_dashboard_data(&state)
        .await
        .map_err(internal_error)?;

    let body = html! {
        div.ed-art-eyebrow { "Dashboard" }
        h1.ed-art-h1 { "homelab " em { "at a glance" } }
        p.ed-art-deck {
            "Counts straight from the SQLite inventory backing this daemon "
            "(" span.ed-mono { "/var/lib/vpnctl/inv.db" } "). "
            b { "Servers, users, grants and the daemon version" }
            " update on every reload."
        }
        (dashboard_metrics(&stats))
        (tweak_indicator(&theme, &accent))
        (dashboard_audit(&audit))
    };
    Ok(shell("dashboard", &theme, &accent, body))
}

/// Convert any error into a plaintext 500 response. The body is one line
/// (mirrors what the operator would see in `journalctl -u vpnctld`); a
/// shell-rendered 500 page would need to re-derive theme/accent + cookies
/// inside an error path and isn't worth the surface for an admin UI.
///
/// `anyhow::Error` is a single boxed pointer; passing by value keeps
/// call sites clean (`.map_err(internal_error)`), so silence clippy.
#[allow(clippy::needless_pass_by_value)]
fn internal_error(err: anyhow::Error) -> Response {
    tracing::error!(target = "vpnctld::admin", error = %err, "handler failed");
    (StatusCode::INTERNAL_SERVER_ERROR, format!("admin: {err}\n")).into_response()
}

/// Generic placeholder body for nav sections that don't have content yet
/// (Phase B+). Re-uses `tweak_indicator` so accent changes are visible
/// on every section, not just the dashboard.
fn section_placeholder_body(section_label: &str, theme: &str, accent: &str) -> Markup {
    html! {
        div.ed-art-eyebrow { "Phase A · placeholder" }
        h1.ed-art-h1 { (section_label) }
        p.ed-art-deck {
            "Section content lands in a later phase. The shell, nav and "
            b { "theme + accent toggles" }
            " are wired and visible above."
        }
        (tweak_indicator(theme, accent))
        div.ed-rule {}
        p style="font-family: var(--mono); font-size: 12px; color: var(--mute);" {
            "← use the nav strip above to switch sections; bottom-right Tweaks panel persists across reloads via cookie"
        }
    }
}

pub(crate) async fn monitoring(headers: HeaderMap) -> Markup {
    let (theme, accent) = theme_accent(&headers);
    let body = section_placeholder_body("Monitoring", &theme, &accent);
    shell("monitoring", &theme, &accent, body)
}

/// Editorial server card — one per row, matches `.ed-server` from the
/// design source. Renders the inventory's `Server` plus the per-server
/// user count looked up from `users_count_per_server` (defaulting to 0).
fn server_card(idx: usize, s: &vpnctl_core::Server, user_count: i64) -> Markup {
    let proto_list = if s.enabled_protocols.is_empty() {
        "—".to_string()
    } else {
        s.enabled_protocols
            .iter()
            .map(|p| p.0.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    };
    let jump = match &s.jump_via {
        Some(j) => j.0.clone(),
        None => "direct".to_string(),
    };
    let fp = s
        .trusted_host_fingerprint
        .as_deref()
        .unwrap_or("(unverified)");
    html! {
        article.ed-server {
            div.ed-server__no { (format!("№ {:02}", idx + 1)) }
            div {
                h2.ed-server__h { (s.id.0) }
                div.ed-server__addr {
                    (s.address) ":" (s.ssh_port)
                    " · " (s.ssh_user) "@"
                    " · " span.ed-mono { (s.kernel.0) }
                }
                p.ed-server__lede {
                    "Hoster " b { (s.hoster) }
                    " · " b { (user_count) } " "
                    @if user_count == 1 { "user" } @else { "users" }
                    " granted access · jump " em { (jump) }
                }
            }
            dl.ed-server__meta {
                dt { "protocols" }   dd { (proto_list) }
                dt { "fingerprint" } dd style="font-family: var(--mono); font-size: 11px;" { (fp) }
                dt { "usage ×" }     dd { (format!("{:.2}", s.usage_coefficient)) }
            }
        }
    }
}

pub(crate) async fn servers(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<Markup, Response> {
    let (theme, accent) = theme_accent(&headers);

    let (server_list, user_counts) =
        tokio::try_join!(state.inv.list_servers(), state.inv.users_count_per_server())
            .map_err(|e| internal_error(anyhow::Error::new(e)))?;

    let body = html! {
        div.ed-art-eyebrow { "Servers" }
        h1.ed-art-h1 {
            (server_list.len()) " "
            @if server_list.len() == 1 { em { "server" } } @else { em { "servers" } }
            " in inventory"
        }
        p.ed-art-deck {
            "Read straight from the SQLite inventory. Add a server with "
            span.ed-mono { "vpnctl bootstrap" } " then "
            span.ed-mono { "vpnctl deploy" }
            " — the wizard UI is on the Phase D roadmap."
        }
        (tweak_indicator(&theme, &accent))
        @if server_list.is_empty() {
            p style="font-family: var(--serif); font-style: italic; color: var(--mute); padding: 24px 0;" {
                "No servers yet. Run "
                span.ed-mono { "vpnctl bootstrap <id> <address> <ssh-user> <ssh-port>" }
                " on a fresh node and refresh."
            }
        } @else {
            div {
                @for (idx, s) in server_list.iter().enumerate() {
                    (server_card(idx, s, user_counts.get(&s.id).copied().unwrap_or(0)))
                }
            }
        }
    };
    Ok(shell("servers", &theme, &accent, body))
}

pub(crate) async fn users(headers: HeaderMap) -> Markup {
    let (theme, accent) = theme_accent(&headers);
    let body = section_placeholder_body("Users", &theme, &accent);
    shell("users", &theme, &accent, body)
}

pub(crate) async fn audit(headers: HeaderMap) -> Markup {
    let (theme, accent) = theme_accent(&headers);
    let body = section_placeholder_body("Audit", &theme, &accent);
    shell("audit", &theme, &accent, body)
}

pub(crate) async fn settings(headers: HeaderMap) -> Markup {
    let (theme, accent) = theme_accent(&headers);
    let body = section_placeholder_body("Settings", &theme, &accent);
    shell("settings", &theme, &accent, body)
}

fn set_tweak_cookie(
    headers: &HeaderMap,
    cookie_name: &str,
    valid: &[&str],
    body: &str,
) -> Response {
    // body is `value=<name>` (form-encoded). Parse minimally.
    let value = body
        .split('&')
        .find_map(|kv| kv.strip_prefix("value="))
        .unwrap_or("");
    if !valid.contains(&value) {
        return (StatusCode::BAD_REQUEST, "invalid value\n").into_response();
    }
    // 1-year, HttpOnly, SameSite=Lax — operator-only UI, no XSS surface.
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

/// Convert a Referer header into a safe redirect target. Only paths under
/// `/admin` are accepted; everything else falls back to `/admin/` so a
/// browser tricked into POSTing the tweak from `evil.example.com` doesn't
/// then get redirected to the attacker's page (open-redirect class).
///
/// Accepts:
///   - relative paths starting with `/admin` or exactly `/admin`
///   - absolute URLs whose path component starts with `/admin`
///
/// CRLF (header injection) and any other shape fall back to `/admin/`.
fn sanitize_referer(referer: Option<&str>) -> String {
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
        // Skip authority (host[:port]); take from the first '/' onward.
        // No '/' at all means the URL is just a host — no path to keep.
        match stripped.find('/') {
            Some(i) => &stripped[i..],
            None => return "/admin/".to_string(),
        }
    } else if raw.starts_with('/') {
        raw
    } else {
        // Anything else (scheme-less, javascript:, data: …) is rejected.
        return "/admin/".to_string();
    };
    // Strip query/fragment for the prefix check, then keep the original.
    let path_only = path.split(['?', '#']).next().unwrap_or(path);
    if path_only == "/admin" || path_only.starts_with("/admin/") {
        path.to_string()
    } else {
        "/admin/".to_string()
    }
}

/// Path `/admin/tweak/{kind}` dispatcher — `kind` is "theme" or "accent".
pub(crate) async fn set_tweak(
    headers: HeaderMap,
    Path(kind): Path<String>,
    body: String,
) -> Response {
    match kind.as_str() {
        "theme" => set_tweak_cookie(&headers, COOKIE_THEME, VALID_THEMES, &body),
        "accent" => set_tweak_cookie(&headers, COOKIE_ACCENT, VALID_ACCENTS, &body),
        _ => (StatusCode::NOT_FOUND, "unknown tweak\n").into_response(),
    }
}
