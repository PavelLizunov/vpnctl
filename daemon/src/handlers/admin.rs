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
const COOKIE_TWEAKS_OPEN: &str = "vpnctl_tweaks";

const VALID_THEMES: &[&str] = &["default", "newsprint", "foxed", "ink"];
const VALID_ACCENTS: &[&str] = &["default", "rust", "forest", "plum"];
/// Open / closed state of the bottom-right Tweaks panel. Default is
/// "open" — first-time visitors see the controls. After the operator
/// hits the × they get a tiny pill they can click to expand again.
const VALID_TWEAKS_OPEN: &[&str] = &["open", "closed"];

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

/// The bottom-right Tweaks panel — two collapse states, controlled by
/// the `vpnctl_tweaks` cookie:
///
/// - **`open`** (default): the full panel with theme + accent segmented
///   controls plus a `×` close button that POSTs `value=closed` to the
///   `/admin/tweak/tweaks` endpoint.
/// - **`closed`**: a tiny "↑ Tweaks" pill in the same corner. Clicking
///   it POSTs `value=open` and the panel returns. Without the pill the
///   panel would be unreachable once dismissed.
///
/// The visual rationale for collapsing: the panel was floating over the
/// page footer and (on the user-detail page) over the share-link rows
/// the operator wants to copy. Operators who are happy with their
/// theme/accent now get the chrome out of the way without sacrificing
/// discoverability.
fn tweaks_panel(theme: &str, accent: &str, open: bool) -> Markup {
    let pos_style =
        "position: fixed; right: 24px; bottom: 24px; z-index: 50; background: var(--paper);";
    if !open {
        return html! {
            // Pill form — single button POSTs `value=open`. Same /admin/tweak
            // dispatcher route, new "tweaks" kind. Without `display: inline`
            // the form would push the pill onto its own line.
            form method="post" action="/admin/tweak/tweaks" style="display: inline;" {
                button name="value" value="open"
                       title="Open theme + accent tweaks"
                       style=(format!("{pos_style} border: 1px solid var(--rule-s); padding: 6px 10px; font-family: var(--mono); font-size: 11px; color: var(--mute); cursor: pointer; box-shadow: 0 4px 12px rgba(0,0,0,0.08);")) {
                    "↑ Tweaks"
                }
            }
        };
    }
    html! {
        // Open state: full panel with × close. Header row holds the
        // label + a tight close form so the button sits inline-end.
        div style=(format!("{pos_style} border: 1px solid var(--ink); padding: 12px 14px; font-family: var(--mono); font-size: 11px; color: var(--soft); box-shadow: 0 8px 24px rgba(0,0,0,0.12);")) {
            div style="display: flex; align-items: baseline; justify-content: space-between; gap: 12px; margin-bottom: 8px;" {
                span style="letter-spacing: 0.14em; text-transform: uppercase; color: var(--mute);" { "Tweaks" }
                form method="post" action="/admin/tweak/tweaks" style="margin: 0; padding: 0;" {
                    button name="value" value="closed"
                           title="Hide tweaks panel"
                           style="background: transparent; border: 0; padding: 0 2px; font-family: var(--mono); font-size: 14px; color: var(--mute); cursor: pointer; line-height: 1;" {
                        "×"
                    }
                }
            }
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

/// Build the page-root class string from theme/accent + tweaks-panel
/// state. The `ed-tweaks-open` modifier lets the stylesheet add right-
/// padding to the footer so the panel doesn't cover the github URL when
/// open; without this hook the panel was sitting on top of the foot
/// link visibly even with the × close button.
fn root_class(theme: &str, accent: &str, tweaks_open: bool) -> String {
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
    if tweaks_open {
        cls.push_str(" ed-tweaks-open");
    }
    cls
}

/// Wraps a screen-specific body in the chrome (masthead + nav + main + foot
/// + tweaks). `body` is the inner content of `<main class="ed-main">`.
///
/// `Markup` (a `PreEscaped<String>`) is owned and small; passing by value
/// is intentional and clippy's needless_pass_by_value is over-eager here.
///
/// The shell needs to know whether the Tweaks panel is open or collapsed,
/// so callers pass the cookie-derived state via `tweaks_open`. A bool
/// parameter rather than re-reading headers here keeps `shell` pure /
/// testable (no I/O, no globals).
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn shell(
    active_nav: &str,
    theme: &str,
    accent: &str,
    tweaks_open: bool,
    body: Markup,
) -> Markup {
    let cls = root_class(theme, accent, tweaks_open);
    html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8" {}
                meta name="viewport" content="width=device-width, initial-scale=1" {}
                title { "vpnctl admin" }
                // Inline-SVG favicon — the same [•] glyph as the
                // masthead, served as a static asset. Without this the
                // browser tab shows a blank square, which is a tell-
                // tale "unfinished homepage" signal even when the rest
                // of the chrome is polished.
                link rel="icon" type="image/svg+xml" href="/admin/assets/favicon.svg" {}
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
                (tweaks_panel(theme, accent, tweaks_open))
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

/// Read theme + accent + tweaks-open cookies into owned strings + bool
/// (default = "default" / open). Single accessor so handlers don't have
/// to thread three cookie reads each.
fn theme_accent(headers: &HeaderMap) -> (String, String, bool) {
    let theme = cookie(headers, COOKIE_THEME)
        .unwrap_or("default")
        .to_string();
    let accent = cookie(headers, COOKIE_ACCENT)
        .unwrap_or("default")
        .to_string();
    // Default = open. Anything that isn't literally "closed" stays open
    // — that way a malformed cookie value can't silently hide the panel.
    let tweaks_open = cookie(headers, COOKIE_TWEAKS_OPEN) != Some("closed");
    (theme, accent, tweaks_open)
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
    let (theme, accent, tw) = theme_accent(&headers);

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
        (dashboard_audit(&audit))
    };
    Ok(shell("dashboard", &theme, &accent, tw, body))
}

/// Convert any error into a plaintext 500 response. The body is one line
/// (mirrors what the operator would see in `journalctl -u vpnctld`); a
/// shell-rendered 500 page would need to re-derive theme/accent + cookies
/// inside an error path and isn't worth the surface for an admin UI.
///
/// **Copy contract:** every backend response in the admin tree starts
/// with `vpnctl admin:` so an operator grepping `journalctl` or tailing
/// curl output has one stable prefix to filter on. See `error_text()`.
///
/// `anyhow::Error` is a single boxed pointer; passing by value keeps
/// call sites clean (`.map_err(internal_error)`), so silence clippy.
#[allow(clippy::needless_pass_by_value)]
fn internal_error(err: anyhow::Error) -> Response {
    tracing::error!(target = "vpnctld::admin", error = %err, "handler failed");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        error_text(&err.to_string()),
    )
        .into_response()
}

/// Single source of truth for the textual prefix used on every admin
/// error body. Tests pin this string so it can't drift away from the
/// `vpnctl admin: …\n` convention by accident.
pub(crate) fn error_text(detail: &str) -> String {
    format!("vpnctl admin: {detail}\n")
}

/// Generic placeholder body for nav sections that don't have content yet
/// (Phase B+). The Tweaks panel itself surfaces the active theme/accent
/// (highlighted segmented buttons), so a separate inline indicator is
/// redundant and was just adding noise above the page content.
fn section_placeholder_body(section_label: &str) -> Markup {
    html! {
        div.ed-art-eyebrow { "Phase A · placeholder" }
        h1.ed-art-h1 { (section_label) }
        p.ed-art-deck {
            "Section content lands in a later phase. The shell, nav and "
            b { "theme + accent toggles" }
            " are wired — see the bottom-right Tweaks panel."
        }
        div.ed-rule {}
        p style="font-family: var(--mono); font-size: 12px; color: var(--mute);" {
            "← use the nav strip above to switch sections; bottom-right Tweaks panel persists across reloads via cookie"
        }
    }
}

/// Phase F monitoring page. Pulls hourly + daily access buckets from
/// `sub_access_log`, gap-fills, renders two inline-SVG sparklines
/// (hits + distinct IPs) plus headline KPIs. No JS — pure SSR.
pub(crate) async fn monitoring(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<Markup, Response> {
    let (theme, accent, tw) = theme_accent(&headers);

    let hourly = state
        .inv
        .sub_access_buckets("hour", 24)
        .await
        .map_err(|e| internal_error(anyhow::Error::new(e)))?;
    let daily = state
        .inv
        .sub_access_buckets("day", 24 * 7)
        .await
        .map_err(|e| internal_error(anyhow::Error::new(e)))?;

    // Gap-fill the 24-hour window so the sparkline x-axis is even.
    let hour_filled = fill_hourly_gaps(&hourly, 24);
    let day_filled = fill_daily_gaps(&daily, 7);

    // Headline KPIs from the unfilled buckets (gap-filling adds zero
    // entries which would skew "peak" downward).
    let total_hits_24h: u64 = hourly.iter().map(|b| b.hits).sum();
    let peak_ips_hour: u64 = hourly.iter().map(|b| b.distinct_ips).max().unwrap_or(0);
    let total_hits_7d: u64 = daily.iter().map(|b| b.hits).sum();

    let body = html! {
        div.ed-art-eyebrow { "Monitoring" }
        h1.ed-art-h1 {
            (total_hits_24h) " "
            @if total_hits_24h == 1 { em { "hit" } } @else { em { "hits" } }
            " in the last 24h"
        }
        p.ed-art-deck {
            "Aggregate sub-access counters straight from "
            span.ed-mono { "sub_access_log" }
            ". Reads are server-side aggregated; no JavaScript on the "
            "page — re-render on reload."
        }

        div style="display: flex; gap: 36px; padding: 12px 0 24px; font-family: var(--serif);" {
            div {
                div style="font-size: 28px; font-weight: 400; color: var(--ink); line-height: 1;" { (total_hits_24h) }
                div style="font-family: var(--mono); font-size: 10.5px; letter-spacing: 0.14em; text-transform: uppercase; color: var(--mute); margin-top: 4px;" {
                    "hits · 24h"
                }
            }
            div {
                div style="font-size: 28px; font-weight: 400; color: var(--ink); line-height: 1;" { (peak_ips_hour) }
                div style="font-family: var(--mono); font-size: 10.5px; letter-spacing: 0.14em; text-transform: uppercase; color: var(--mute); margin-top: 4px;" {
                    "peak distinct IPs / hour"
                }
            }
            div {
                div style="font-size: 28px; font-weight: 400; color: var(--ink); line-height: 1;" { (total_hits_7d) }
                div style="font-family: var(--mono); font-size: 10.5px; letter-spacing: 0.14em; text-transform: uppercase; color: var(--mute); margin-top: 4px;" {
                    "hits · 7 days"
                }
            }
        }

        div.ed-rule {}
        div.ed-art-eyebrow style="margin-top: 18px;" { "Hourly hits · last 24h" }
        (sparkline_svg(&hour_filled.iter().map(|b| b.hits as f64).collect::<Vec<_>>(), 720, 60))
        div.ed-art-eyebrow style="margin-top: 18px;" { "Hourly distinct IPs · last 24h" }
        (sparkline_svg(&hour_filled.iter().map(|b| b.distinct_ips as f64).collect::<Vec<_>>(), 720, 60))
        div.ed-art-eyebrow style="margin-top: 18px;" { "Daily hits · last 7 days" }
        (sparkline_svg(&day_filled.iter().map(|b| b.hits as f64).collect::<Vec<_>>(), 720, 60))

        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin-top: 18px;" {
            "Same data is curl-able as JSON at "
            span.ed-mono { "/api/v1/stats/sub-access?bucket=hour&since_hours=24" }
            " (no auth — only aggregate counts, no per-IP details)."
        }
    };
    Ok(shell("monitoring", &theme, &accent, tw, body))
}

/// Fill the last `n_hours` hourly buckets with zero where the input
/// (oldest-first, with gaps) has no entry. Caller passes the result
/// from the inventory; this turns a sparse list into a dense one
/// suitable for sparkline rendering.
fn fill_hourly_gaps(
    input: &[vpnctl_inventory::AccessBucket],
    n_hours: usize,
) -> Vec<vpnctl_inventory::AccessBucket> {
    use chrono::{Duration, Timelike, Utc};
    // Build a HashMap keyed by (year-month-day-hour) for fast lookup.
    use std::collections::HashMap;
    let key = |b: &vpnctl_inventory::AccessBucket| b.bucket_start.format("%Y-%m-%dT%H").to_string();
    let by_hour: HashMap<String, &vpnctl_inventory::AccessBucket> =
        input.iter().map(|b| (key(b), b)).collect();
    let now = Utc::now()
        .with_minute(0)
        .and_then(|t| t.with_second(0))
        .and_then(|t| t.with_nanosecond(0))
        .unwrap_or_else(Utc::now);
    let mut out = Vec::with_capacity(n_hours);
    for h in (0..n_hours).rev() {
        let ts = now - Duration::hours(h as i64);
        let k = ts.format("%Y-%m-%dT%H").to_string();
        out.push(match by_hour.get(&k) {
            Some(b) => (*b).clone(),
            None => vpnctl_inventory::AccessBucket {
                bucket_start: ts,
                hits: 0,
                distinct_ips: 0,
            },
        });
    }
    out
}

/// Same as `fill_hourly_gaps` but for daily buckets over `n_days`.
fn fill_daily_gaps(
    input: &[vpnctl_inventory::AccessBucket],
    n_days: usize,
) -> Vec<vpnctl_inventory::AccessBucket> {
    use chrono::{Duration, Utc};
    use std::collections::HashMap;
    let key = |b: &vpnctl_inventory::AccessBucket| b.bucket_start.format("%Y-%m-%d").to_string();
    let by_day: HashMap<String, &vpnctl_inventory::AccessBucket> =
        input.iter().map(|b| (key(b), b)).collect();
    let today = Utc::now().date_naive();
    let mut out = Vec::with_capacity(n_days);
    for d in (0..n_days).rev() {
        let day = today - Duration::days(d as i64);
        let k = day.format("%Y-%m-%d").to_string();
        out.push(match by_day.get(&k) {
            Some(b) => (*b).clone(),
            None => vpnctl_inventory::AccessBucket {
                bucket_start: day.and_hms_opt(0, 0, 0).unwrap_or_default().and_utc(),
                hits: 0,
                distinct_ips: 0,
            },
        });
    }
    out
}

/// Inline-SVG sparkline. Pure SSR — width/height pinned, no JS,
/// stroke uses `var(--acc)` so the accent toggle in the Tweaks panel
/// recolours every chart on the page consistently.
fn sparkline_svg(values: &[f64], width: u32, height: u32) -> Markup {
    if values.is_empty() {
        return html! {
            p style="font-family: var(--serif); font-style: italic; color: var(--mute); padding: 6px 0;" {
                "(no data in window)"
            }
        };
    }
    let max = values.iter().cloned().fold(0.0_f64, f64::max).max(1.0);
    let n = values.len();
    let stride = if n > 1 {
        (width as f64 - 4.0) / (n - 1) as f64
    } else {
        0.0
    };
    let h = height as f64 - 4.0;
    let points: String = values
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let x = 2.0 + (i as f64) * stride;
            let y = 2.0 + h - (v / max) * h;
            format!("{x:.1},{y:.1}")
        })
        .collect::<Vec<_>>()
        .join(" ");
    // Filled area under the curve — same points + close-down to baseline.
    let area_points = format!(
        "2,{baseline} {points} {last_x:.1},{baseline}",
        baseline = height as f64 - 2.0,
        last_x = 2.0 + (n - 1) as f64 * stride
    );
    html! {
        svg width=(width) height=(height) viewBox=(format!("0 0 {width} {height}"))
            xmlns="http://www.w3.org/2000/svg"
            style="display: block; margin: 8px 0;" {
            polygon points=(area_points) fill="var(--acc)" opacity="0.10" {}
            polyline points=(points) fill="none" stroke="var(--acc)" stroke-width="1.5" {}
            // Right-side max-value label so operator can read the peak.
            text x=(width - 4) y="14"
                 text-anchor="end"
                 style="font-family: var(--mono); font-size: 10px; fill: var(--mute);" {
                "max " (max as u64)
            }
        }
    }
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
    let detail_href = format!("/admin/servers/{}", path_segment_encode(&s.id.0));
    html! {
        article.ed-server {
            div.ed-server__no { (format!("№ {:02}", idx + 1)) }
            div {
                // Phase H chunk 3: server id is now a link to the
                // detail page (which carries live telemetry + drift
                // info). Clickable headline matches the user-list
                // pattern from C-1.
                h2.ed-server__h {
                    a href=(detail_href) style="color: var(--ink); text-decoration: none;" {
                        (s.id.0)
                    }
                }
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
    let (theme, accent, tw) = theme_accent(&headers);

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
            "Read straight from the SQLite inventory. Add a server through the "
            a href="/admin/servers/new" style="color: var(--ink); text-decoration: underline;" {
                "wizard"
            }
            " (paste IP + root password, the daemon does the rest), or use "
            span.ed-mono { "vpnctl bootstrap" } " then " span.ed-mono { "vpnctl deploy" }
            " from the CLI."
        }

        // Phase E sub-iter 4a — wizard CTA. Sits above the list so a
        // fresh inventory finds the affordance immediately.
        div style="margin: 16px 0 24px;" {
            a href="/admin/servers/new"
              style="display: inline-block; padding: 6px 14px; border: 1px solid var(--ink); background: var(--ink); color: var(--paper); font-family: var(--mono); font-size: 11px; text-decoration: none;" {
                "add server →"
            }
        }

        @if server_list.is_empty() {
            p style="font-family: var(--serif); font-style: italic; color: var(--mute); padding: 24px 0;" {
                "No servers yet. Click "
                span.ed-mono { "add server →" }
                " above, or run "
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
    Ok(shell("servers", &theme, &accent, tw, body))
}

// ────────────────────────────────────────────────────────────────────────
//  Users — list (Phase C-1) + detail (Phase C-1) — read-only.
//  Add / regenerate / delete go in Phase C-2 once the inventory write
//  paths gain audit-logging (CLAUDE.md invariant).
// ────────────────────────────────────────────────────────────────────────

/// Mask all but the first/last 4 chars of a long opaque token. Used for
/// sub_token, tuic_password etc. — the operator should be able to spot
/// the right user by the prefix without exposing the full secret in
/// shoulder-surf range.
///
/// Counts in **chars**, not bytes. The token contract for vpnctl is
/// url-safe base64 (`sub_token`, 43 ASCII chars) or other opaque ASCII
/// secrets, so chars and bytes coincide. If a multibyte secret ever
/// shows up here the visible head/tail still come out correctly thanks
/// to `chars()`-based slicing.
fn mask_secret(s: &str) -> String {
    let n = s.chars().count();
    if n <= 8 {
        // Too short to mask meaningfully — show in full.
        return s.to_string();
    }
    let head: String = s.chars().take(4).collect();
    let tail: String = s.chars().skip(n - 4).collect();
    format!("{head}…{tail} ({n} chars)")
}

/// Percent-encode a string for use as a single URL path segment. Keeps
/// RFC 3986 unreserved chars (`A-Z`, `a-z`, `0-9`, `-`, `.`, `_`, `~`)
/// verbatim; everything else is `%XX`-escaped. Avoids pulling
/// percent-encoding as a direct dep — sub_token / user_id / server_id
/// rarely need this in practice but it costs ~10 lines to be safe
/// against operator-typed `?`, `#`, `/`, spaces.
fn path_segment_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        let unreserved = b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~');
        if unreserved {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Per-user row in the users list. Keeps the editorial cadence — one
/// `<article>` per row with id / uuid prefix / sub-token preview / grant
/// count, and a CTA arrow to the detail page.
///
/// `grants_count` is `usize` (the natural count from `Vec::len()`); maud
/// renders any `Display` integer so we don't need to pre-narrow into
/// `i64` and risk an overflow fallback that would silently mislead the
/// operator.
fn user_row(idx: usize, u: &vpnctl_core::User, grants_count: usize) -> Markup {
    let sub_token_preview = u.sub_token.as_deref().map(mask_secret);
    let uuid_preview: String = u.uuid.chars().take(8).collect();
    let detail_href = format!("/admin/users/{}", path_segment_encode(&u.id.0));
    html! {
        article.ed-server {
            div.ed-server__no { (format!("№ {:02}", idx + 1)) }
            div {
                h2.ed-server__h { (u.id.0) }
                div.ed-server__addr {
                    "uuid " span.ed-mono { (uuid_preview) "…" }
                    " · sub-token "
                    @match &sub_token_preview {
                        Some(s) => span.ed-mono { (s) },
                        None => em { "(unset — open the user to regenerate)" },
                    }
                }
                p.ed-server__lede {
                    b { (grants_count) } " "
                    @if grants_count == 1 { "server" } @else { "servers" }
                    " granted"
                    @if u.tuic_password.is_some() { " · tuic password set" }
                    @if u.wireguard_pubkey.is_some() { " · wireguard pubkey set" }
                }
            }
            dl.ed-server__meta {
                dt { "open" }
                dd {
                    a href=(detail_href)
                      class="ed-server__cta" { "detail · QR" }
                }
            }
        }
    }
}

pub(crate) async fn users(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<Markup, Response> {
    let (theme, accent, tw) = theme_accent(&headers);

    // list_users + servers_for_user-per-user would be N+1; instead use
    // the inventory's grants-count map (one query) and look up by user.
    let users_list = state
        .inv
        .list_users()
        .await
        .map_err(|e| internal_error(anyhow::Error::new(e)))?;

    // Per-user grants count: the existing aggregations only group by
    // server_id, not user_id. Since N is small (homelab) we issue one
    // small query per user — this is bounded by the operator's user
    // count and will not be a hot path.
    let mut grants_per_user: Vec<usize> = Vec::with_capacity(users_list.len());
    for u in &users_list {
        let n = state
            .inv
            .servers_for_user(&u.id)
            .await
            .map(|v| v.len())
            .map_err(|e| internal_error(anyhow::Error::new(e)))?;
        grants_per_user.push(n);
    }

    let body = html! {
        div.ed-art-eyebrow { "Users" }
        h1.ed-art-h1 {
            (users_list.len()) " "
            @if users_list.len() == 1 { em { "user" } } @else { em { "users" } }
            " on file"
        }
        p.ed-art-deck {
            "Each user has one " span.ed-mono { "/sub/<token>" } " endpoint that hands their "
            "sing-box client a fresh config covering every server they're granted on. "
            "Open a row for the QR you'll point a phone at."
        }

        // Phase C-3.2 — add-user form. UUID + tuic_password + sub_token
        // are all mint-on-server; the operator only types the human-
        // readable id. Grants come later via the user-detail page (G).
        // Phase H follow-up — optional `wireguard_pubkey` field so the
        // operator can mint a WireGuard/AmneziaWG-ready user in one
        // step. The PUBLIC key is supplied (operator generated it on
        // the device); vpnctl never sees the private one.
        div style="margin: 16px 0 28px; padding: 14px 16px; border: 1px solid var(--rule); background: var(--paper);" {
            form method="post" action="/admin/users"
                 style="display: flex; flex-direction: column; gap: 10px;" {
                div style="display: flex; gap: 10px; align-items: baseline;" {
                    label style="font-family: var(--mono); font-size: 11px; color: var(--mute); letter-spacing: 0.14em; text-transform: uppercase;" {
                        "add user"
                    }
                    input type="text" name="id" required="required"
                          placeholder="alice"
                          pattern="[A-Za-z0-9._-]+"
                          title="Letters, digits, dot, underscore, hyphen — no spaces or slashes"
                          style="flex: 1; max-width: 280px; padding: 4px 8px; border: 1px solid var(--rule-s); background: var(--paper); font-family: var(--mono); font-size: 12px; color: var(--ink);";
                    button type="submit"
                           title="Mint UUID + tuic_password + sub_token, then redirect to the user-detail page"
                           style="padding: 4px 12px; border: 1px solid var(--ink); background: var(--ink); color: var(--paper); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                        "create"
                    }
                }
                div style="display: flex; gap: 10px; align-items: baseline;" {
                    label for="wireguard_pubkey" style="font-family: var(--mono); font-size: 11px; color: var(--mute); letter-spacing: 0.14em; text-transform: uppercase;" {
                        "wg pubkey"
                    }
                    input type="text" id="wireguard_pubkey" name="wireguard_pubkey"
                          placeholder="(optional, base64 44 chars ending '=')"
                          pattern="[A-Za-z0-9+/]{43}="
                          title="WireGuard PUBLIC key — 44 base64 chars ending '='. Leave blank if user won't use WG/AmneziaWG."
                          style="flex: 1; max-width: 480px; padding: 4px 8px; border: 1px solid var(--rule-s); background: var(--paper); font-family: var(--mono); font-size: 11px; color: var(--ink);";
                    span style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute);" {
                        "private key stays on the device"
                    }
                }
            }
        }

        @if users_list.is_empty() {
            p style="font-family: var(--serif); font-style: italic; color: var(--mute); padding: 24px 0;" {
                "No users yet. Type an id above and hit "
                span.ed-mono { "create" }
                ", or use "
                span.ed-mono { "vpnctl user create <id>" }
                " from the CLI. Then grant server access via "
                span.ed-mono { "vpnctl grant <user> <server>" }
                " (web UI lands in C-3.3)."
            }
        } @else {
            div {
                @for (idx, (u, g)) in users_list.iter().zip(grants_per_user.iter()).enumerate() {
                    (user_row(idx, u, *g))
                }
            }
        }
    };
    Ok(shell("users", &theme, &accent, tw, body))
}

/// Build the canonical sub URL the QR encodes. Uses the request's `Host`
/// header so the QR is reachable from wherever the operator opened the
/// admin from (LAN IP, VPN IP, or the external one when we add reverse
/// proxy). Defaults to a sensible LAN guess if the header is missing —
/// rare in practice, but not worth crashing over.
fn sub_url(headers: &HeaderMap, sub_token: &str) -> String {
    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("127.0.0.1:18402");
    // Daemon is HTTP-only on LAN — when an operator stands up TLS in
    // front of vpnctld this becomes a config knob.
    format!("http://{host}/sub/{sub_token}")
}

/// Render an inline SVG QR for the given URL. Returns
/// `<div class="ed-qr">...<svg>...</svg>...</div>`. The SVG carries
/// no scripts, no external refs.
fn qr_svg(url: &str) -> Markup {
    use qrcode::QrCode;
    use qrcode::render::svg;

    match QrCode::new(url.as_bytes()) {
        Ok(code) => {
            let svg_str = code
                .render::<svg::Color<'_>>()
                .min_dimensions(220, 220)
                .quiet_zone(true)
                .dark_color(svg::Color("#1a1611"))
                .light_color(svg::Color("#f5efe6"))
                .build();
            html! {
                div style="display: inline-block; padding: 12px; background: var(--paper); border: 1px solid var(--rule);" {
                    (maud::PreEscaped(svg_str))
                }
            }
        }
        Err(e) => html! {
            div style="font-family: var(--mono); color: var(--red); font-size: 12px;" {
                "QR generation failed: " (e.to_string())
            }
        },
    }
}

/// Build all (server, protocol) share-links for a user — same logic as
/// the CLI's `vpnctl sub` and the daemon's `/sub/<token>` handler. Each
/// entry has the protocol id and the rendered URI; failures are logged
/// and skipped, never panic.
fn collect_share_links(
    state: &AppState,
    user: &vpnctl_core::User,
    servers: &[vpnctl_core::Server],
    secrets_per_server: &std::collections::HashMap<
        vpnctl_core::ServerId,
        std::collections::HashMap<String, String>,
    >,
) -> Vec<(vpnctl_core::ServerId, vpnctl_core::ProtocolId, String)> {
    let mut out = Vec::new();
    for server in servers {
        let Some(secrets) = secrets_per_server.get(&server.id) else {
            tracing::warn!(target = "vpnctld::admin", server = %server.id, "secrets missing for granted server");
            continue;
        };
        let ctx = vpnctl_core::RenderCtx::new(server, secrets);
        for pid in &server.enabled_protocols {
            let Some(proto) = state.registry.protocol(pid) else {
                tracing::warn!(target = "vpnctld::admin", protocol = %pid, "protocol not registered");
                continue;
            };
            match proto.share_link(&ctx, user) {
                Ok(link) => out.push((server.id.clone(), pid.clone(), link)),
                Err(e) => {
                    tracing::warn!(
                        target = "vpnctld::admin",
                        server = %server.id,
                        protocol = %pid,
                        error = %e,
                        "share_link failed, skipping"
                    );
                }
            }
        }
    }
    out
}

pub(crate) async fn user_detail(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(user_id_str): Path<String>,
) -> Result<Markup, Response> {
    let (theme, accent, tw) = theme_accent(&headers);
    let uid = vpnctl_core::UserId(user_id_str.clone());

    let user = state
        .inv
        .get_user(&uid)
        .await
        .map_err(|e| internal_error(anyhow::Error::new(e)))?;
    let Some(user) = user else {
        return Err(user_not_found(&user_id_str));
    };

    let servers = state
        .inv
        .servers_for_user(&uid)
        .await
        .map_err(|e| internal_error(anyhow::Error::new(e)))?;

    // Phase C-3.3: also need the FULL inventory of servers so the
    // detail page can show "ungranted" rows with a "grant" button.
    // The set of granted ids lets us split the full list visually.
    let all_servers = state
        .inv
        .list_servers()
        .await
        .map_err(|e| internal_error(anyhow::Error::new(e)))?;
    let granted_ids: HashSet<vpnctl_core::ServerId> =
        servers.iter().map(|s| s.id.clone()).collect();

    // Pre-fetch secrets for every granted server in parallel.
    let mut secrets_per_server = std::collections::HashMap::new();
    for s in &servers {
        let secrets = state
            .inv
            .list_server_secrets(&s.id)
            .await
            .map_err(|e| internal_error(anyhow::Error::new(e)))?;
        secrets_per_server.insert(s.id.clone(), secrets);
    }

    let share_links = collect_share_links(&state, &user, &servers, &secrets_per_server);
    let sub_token = user.sub_token.clone();
    let sub_url_str = sub_token.as_deref().map(|t| sub_url(&headers, t));

    // Phase Track-1 abuse-detection signal: how many distinct IPs hit
    // this user's /sub URL in the last 24h / 7d, plus the recent
    // access rows themselves. Failures here log a warn but DON'T block
    // the page render — the operator can still see the rest of the
    // user detail without telemetry.
    let ips_24h = state
        .inv
        .distinct_ips_for_user(&uid, 24)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(target = "vpnctld::admin", user = %uid, error = %e, "distinct_ips_for_user(24) failed");
            0
        });
    let ips_7d = state
        .inv
        .distinct_ips_for_user(&uid, 24 * 7)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(target = "vpnctld::admin", user = %uid, error = %e, "distinct_ips_for_user(168) failed");
            0
        });
    let recent_access = state
        .inv
        .recent_sub_access(&uid, 25)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(target = "vpnctld::admin", user = %uid, error = %e, "recent_sub_access failed");
            Vec::new()
        });
    // Heat threshold — first cut. 5 distinct IPs in 24h is a soft
    // signal that the URL has been shared. Configurable later via the
    // Settings section once that exists.
    const ABUSE_HEAT_THRESHOLD: u64 = 5;
    let heat_24h = ips_24h >= ABUSE_HEAT_THRESHOLD;

    let body = html! {
        div.ed-art-eyebrow {
            a href="/admin/users" style="color: var(--mute); text-decoration: none;" { "← all users" }
            "  ·  user"
        }
        h1.ed-art-h1 { (user.id.0) }
        p.ed-art-deck {
            "uuid " span.ed-mono { (user.uuid) }
        }

        // Subscription URL + QR — the headline for this page.
        div.ed-art-eyebrow style="margin-top: 28px;" { "Subscription" }
        @match (&sub_token, &sub_url_str) {
            (Some(token), Some(url)) => {
                div style="display: flex; gap: 28px; align-items: flex-start; padding: 16px 0;" {
                    (qr_svg(url))
                    div style="font-family: var(--mono); font-size: 12px; line-height: 1.7;" {
                        div { span style="color: var(--mute);" { "url   " } (url) }
                        div { span style="color: var(--mute);" { "token " } (mask_secret(token)) }
                        div style="margin-top: 12px; color: var(--soft); font-family: var(--serif); font-style: italic;" {
                            "Point a Hiddify-style client at the URL once; it will re-pull the config on its own schedule."
                        }
                        // Rotate sub-token. Idempotent-ish: clicking twice
                        // gives two new tokens, the previous URL is dead
                        // immediately. Operator's existing client must
                        // re-fetch /sub/<new-token> to keep working — so
                        // the inline copy spells out the consequence.
                        form method="post"
                             action=(format!("/admin/users/{}/sub-token/regenerate", path_segment_encode(&user.id.0)))
                             style="margin-top: 14px;" {
                            button type="submit"
                                   title="Mint a new sub_token; the previous URL stops working immediately"
                                   style="padding: 4px 10px; border: 1px solid var(--ink); background: transparent; font-family: var(--mono); font-size: 11px; color: var(--ink); cursor: pointer;" {
                                "rotate sub-token"
                            }
                        }
                    }
                }
            }
            _ => {
                p style="font-family: var(--serif); font-style: italic; color: var(--mute);" {
                    "No sub-token assigned to this user. "
                    form method="post"
                         action=(format!("/admin/users/{}/sub-token/regenerate", path_segment_encode(&user.id.0)))
                         style="display: inline; margin-left: 8px;" {
                        button type="submit"
                               style="padding: 4px 10px; border: 1px solid var(--ink); background: transparent; font-family: var(--mono); font-size: 11px; color: var(--ink); cursor: pointer;" {
                                "mint sub-token"
                            }
                    }
                }
            }
        }

        // Server access (Phase C-3.3) — full server inventory with a
        // per-row grant/revoke form. Granted rows show "✓ access ·
        // [revoke]"; ungranted rows show "[grant]". One POST per
        // click, server returns 303 to this same detail page so the
        // operator sees the post-mutation state immediately.
        div.ed-rule {}
        div.ed-art-eyebrow { "Server access" }
        @if all_servers.is_empty() {
            p style="font-family: var(--serif); font-style: italic; color: var(--mute); padding: 12px 0;" {
                "No servers in the inventory yet. Run "
                span.ed-mono { "vpnctl bootstrap <id> <ip>" }
                " to add one (web wizard lands in Phase E)."
            }
        } @else {
            ul style="list-style: none; padding: 0; font-family: var(--serif); font-size: 14px; line-height: 1.8;" {
                @for s in &all_servers {
                    li style="display: flex; align-items: baseline; gap: 12px; padding: 4px 0; border-bottom: 1px dotted var(--rule);" {
                        span style="flex: 1;" {
                            b { (s.id.0) }
                            " (" span.ed-mono { (s.address) ":" (s.ssh_port) } ", " (s.kernel.0) ")"
                        }
                        @if granted_ids.contains(&s.id) {
                            span style="font-family: var(--mono); font-size: 11px; color: var(--acc);" { "✓ access" }
                            form method="post"
                                 action=(format!("/admin/users/{}/grants/{}/revoke",
                                                 path_segment_encode(&user.id.0),
                                                 path_segment_encode(&s.id.0)))
                                 style="margin: 0;" {
                                button type="submit"
                                       title=(format!("Revoke {}'s access to {}", user.id.0, s.id.0))
                                       style="padding: 2px 8px; border: 1px solid var(--rule-s); background: transparent; font-family: var(--mono); font-size: 11px; color: var(--mute); cursor: pointer;" {
                                    "revoke"
                                }
                            }
                        } @else {
                            span style="font-family: var(--mono); font-size: 11px; color: var(--mute);" { "—" }
                            form method="post"
                                 action=(format!("/admin/users/{}/grants/{}",
                                                 path_segment_encode(&user.id.0),
                                                 path_segment_encode(&s.id.0)))
                                 style="margin: 0;" {
                                button type="submit"
                                       title=(format!("Grant {} access to {}", user.id.0, s.id.0))
                                       style="padding: 2px 8px; border: 1px solid var(--ink); background: transparent; font-family: var(--mono); font-size: 11px; color: var(--ink); cursor: pointer;" {
                                    "grant"
                                }
                            }
                        }
                    }
                }
            }
        }

        // Per-protocol share-links — only meaningful for granted servers.
        @if !servers.is_empty() {
            div.ed-art-eyebrow style="margin-top: 24px;" { "Per-protocol share links" }
            @if share_links.is_empty() {
                p style="font-family: var(--serif); font-style: italic; color: var(--mute);" {
                    "No share-links could be rendered (missing secrets or unregistered protocols). "
                    "Check " span.ed-mono { "journalctl -u vpnctld" } " for warnings."
                }
            } @else {
                ul style="list-style: none; padding: 0; font-family: var(--mono); font-size: 11.5px; line-height: 1.7; color: var(--soft);" {
                    @for (sid, pid, link) in &share_links {
                        li style="padding: 4px 0; border-bottom: 1px dotted var(--rule);" {
                            span style="color: var(--mute);" { (sid.0) " · " (pid.0) " · " }
                            (link)
                        }
                    }
                }
            }
        }

        // ── Subscription access (Phase Track-1 abuse-detection signal) ──
        div.ed-rule {}
        div.ed-art-eyebrow {
            "Subscription access"
            @if heat_24h {
                // Inline heat flag with accent colour. The eyebrow is
                // small so the operator notices it on scroll without
                // it screaming. ABUSE_HEAT_THRESHOLD documents the cut.
                span style="color: var(--acc); margin-left: 12px; letter-spacing: 0;" {
                    "· abuse signal: " (ips_24h) " distinct IPs in 24h (≥" (ABUSE_HEAT_THRESHOLD) " threshold)"
                }
            }
        }
        // Headline counters — distinct IPs in two windows. Side-by-side
        // so the operator sees both at a glance without clicking.
        div style="display: flex; gap: 36px; padding: 12px 0 18px; font-family: var(--serif);" {
            div {
                div style="font-size: 28px; font-weight: 400; color: var(--ink); line-height: 1;" { (ips_24h) }
                div style="font-family: var(--mono); font-size: 10.5px; letter-spacing: 0.14em; text-transform: uppercase; color: var(--mute); margin-top: 4px;" {
                    "distinct IPs · 24h"
                }
            }
            div {
                div style="font-size: 28px; font-weight: 400; color: var(--ink); line-height: 1;" { (ips_7d) }
                div style="font-family: var(--mono); font-size: 10.5px; letter-spacing: 0.14em; text-transform: uppercase; color: var(--mute); margin-top: 4px;" {
                    "distinct IPs · 7 days"
                }
            }
            div {
                div style="font-size: 28px; font-weight: 400; color: var(--ink); line-height: 1;" { (recent_access.len()) }
                div style="font-family: var(--mono); font-size: 10.5px; letter-spacing: 0.14em; text-transform: uppercase; color: var(--mute); margin-top: 4px;" {
                    "recent fetches"
                }
            }
        }
        // Recent rows table — last N hits, newest first. Mono-font for
        // IPs / UAs so shared-prefix cases (192.168.0.1 vs 192.168.0.2)
        // are easy to scan visually. The operator can spot patterns
        // (one IP, several UAs over time = roaming device; one UA,
        // many ASNs at once = shared URL).
        @if recent_access.is_empty() {
            p style="font-family: var(--serif); font-style: italic; color: var(--mute);" {
                "No subscription fetches recorded yet. "
                "Hits will appear here as soon as a client pulls the URL above."
            }
        } @else {
            table style="width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 11.5px;" {
                thead {
                    tr style="border-bottom: 1px solid var(--ink);" {
                        th style="text-align: left; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { "when" }
                        th style="text-align: left; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { "ip" }
                        th style="text-align: left; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { "user-agent" }
                        th style="text-align: right; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { "status" }
                        th style="text-align: right; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { "bytes" }
                    }
                }
                tbody {
                    @for row in &recent_access {
                        tr style="border-bottom: 1px dotted var(--rule);" {
                            td style="padding: 5px 8px; color: var(--soft); white-space: nowrap;" {
                                (clip_ts(&row.ts.to_rfc3339()))
                            }
                            td style="padding: 5px 8px; color: var(--ink);" { (row.ip) }
                            td style="padding: 5px 8px; color: var(--soft); overflow-wrap: anywhere; word-break: break-all;" {
                                @match &row.ua {
                                    Some(s) => (s),
                                    None => em style="color: var(--mute);" { "(none)" },
                                }
                            }
                            td style="padding: 5px 8px; text-align: right; color: var(--ink);" { (row.status) }
                            td style="padding: 5px 8px; text-align: right; color: var(--soft);" { (row.bytes) }
                        }
                    }
                }
            }
            p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin-top: 10px;" {
                "Showing the " (recent_access.len()) " most recent fetches. "
                "Rows are auto-purged after 30 days (default retention)."
            }
        }

        // ── UA fingerprint (Phase Track-4) ──────────────────────
        (ua_clusters_section(&state, &uid).await)

        // ── Live VPN stats (Track-3 chunk 3) ────────────────────
        (live_vpn_stats_section(&state, &uid).await)

        // Destructive zone (Phase C-3.4) — deliberately at the very
        // bottom so the operator scrolls past everything else first.
        // The link goes to a confirm page (GET) NOT a direct POST,
        // so a misclick doesn't immediately delete.
        div.ed-rule {}
        div.ed-art-eyebrow style="color: var(--acc); margin-top: 24px;" { "Danger zone" }
        p style="font-family: var(--serif); font-style: italic; color: var(--mute); padding: 8px 0;" {
            "Deleting drops the user, cascades to grants, and clears the FK on "
            span.ed-mono { "sub_access_log" }
            " rows (forensics survive with NULL user_id)."
        }
        a href=(format!("/admin/users/{}/delete-confirm", path_segment_encode(&user.id.0)))
          style="display: inline-block; padding: 4px 12px; border: 1px solid var(--acc); background: transparent; color: var(--acc); font-family: var(--mono); font-size: 11px; text-decoration: none;" {
            "delete user…"
        }
    };
    Ok(shell("users", &theme, &accent, tw, body))
}

/// Phase Track-4 — UA fingerprint heuristic. Renders one row per
/// distinct User-Agent that has hit this user's `/sub` URL in the
/// last 24h, with a "likely roaming" / "likely shared URL" label.
///
/// Classifier (initial cut, intentionally conservative):
///   * `distinct_slash16 >= 3` → `likely shared URL` (orange)
///   * `distinct_ips >= 3 && distinct_slash16 <= 1` → `likely roaming`
///     (one device hopping subnets within one ISP)
///   * else → unlabeled (single-IP normal client)
///
/// On inventory error returns a small "(unavailable)" nudge instead
/// of failing the whole page.
async fn ua_clusters_section(state: &AppState, uid: &vpnctl_core::UserId) -> Markup {
    let clusters = match state.inv.ua_clusters_for_user(uid, 24).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(target = "vpnctld::admin", user = %uid, error = %e, "ua_clusters_for_user failed");
            return html! {
                div.ed-rule {}
                div.ed-art-eyebrow { "UA fingerprint" }
                p style="font-family: var(--serif); font-style: italic; color: var(--mute);" {
                    "(temporarily unavailable — see journalctl)"
                }
            };
        }
    };
    if clusters.is_empty() {
        return html! {};
    }

    html! {
        div.ed-rule {}
        div.ed-art-eyebrow { "UA fingerprint · last 24h" }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
            "Heuristic. One device usually roams within one ISP /16, "
            "while a shared sub URL spreads across many ISPs. "
            "Labels: orange = likely shared, green = likely roaming."
        }
        table style="width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 11.5px;" {
            thead {
                tr style="border-bottom: 1px solid var(--ink);" {
                    th style="text-align: left; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { "user-agent" }
                    th style="text-align: right; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { "hits" }
                    th style="text-align: right; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { "ips" }
                    th style="text-align: right; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { "/16 nets" }
                    th style="text-align: left; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { "verdict" }
                }
            }
            tbody {
                @for c in &clusters {
                    @let verdict = ua_verdict(c.distinct_ips, c.distinct_slash16);
                    tr style="border-bottom: 1px dotted var(--rule);" {
                        td style="padding: 5px 8px; color: var(--soft); overflow-wrap: anywhere;" {
                            @match &c.ua {
                                Some(s) => (s),
                                None => em style="color: var(--mute);" { "(no UA)" },
                            }
                        }
                        td style="padding: 5px 8px; text-align: right; color: var(--ink);" { (c.hits) }
                        td style="padding: 5px 8px; text-align: right; color: var(--ink);" { (c.distinct_ips) }
                        td style="padding: 5px 8px; text-align: right; color: var(--ink);" { (c.distinct_slash16) }
                        td style=(verdict.style()) { (verdict.label()) }
                    }
                }
            }
        }
    }
}

/// Verdict shape — pairs the operator-visible label with its CSS
/// styling so the table cell stays consistent across rows.
enum UaVerdict {
    LikelyShared,
    LikelyRoaming,
    Unlabeled,
}

impl UaVerdict {
    fn label(&self) -> &'static str {
        match self {
            Self::LikelyShared => "likely shared URL",
            Self::LikelyRoaming => "likely roaming",
            Self::Unlabeled => "—",
        }
    }
    fn style(&self) -> &'static str {
        match self {
            Self::LikelyShared => "padding: 5px 8px; color: var(--acc); font-style: italic;",
            Self::LikelyRoaming => "padding: 5px 8px; color: var(--soft); font-style: italic;",
            Self::Unlabeled => "padding: 5px 8px; color: var(--mute);",
        }
    }
}

fn ua_verdict(distinct_ips: u64, distinct_slash16: u64) -> UaVerdict {
    if distinct_slash16 >= 3 {
        UaVerdict::LikelyShared
    } else if distinct_ips >= 3 && distinct_slash16 <= 1 {
        UaVerdict::LikelyRoaming
    } else {
        UaVerdict::Unlabeled
    }
}

/// Track-3 chunk 3 — live VPN stats section. Reads
/// `recent_vpn_stats_for_user(uid, 24h)` and renders aggregate KPIs
/// (bytes up/down, peak active connections) plus a per-server
/// breakdown.
///
/// Empty-state copy explicitly tells the operator that polling isn't
/// wired yet — chunk 4 lights up the background task. Without this
/// nudge the "no data" message would look like a bug.
async fn live_vpn_stats_section(state: &AppState, uid: &vpnctl_core::UserId) -> Markup {
    let rows = match state.inv.recent_vpn_stats_for_user(uid, 24).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(target = "vpnctld::admin", user = %uid, error = %e, "recent_vpn_stats_for_user failed");
            return html! {
                div.ed-rule {}
                div.ed-art-eyebrow { "Live VPN stats" }
                p style="font-family: var(--serif); font-style: italic; color: var(--mute);" {
                    "(temporarily unavailable — see journalctl)"
                }
            };
        }
    };
    if rows.is_empty() {
        return html! {
            div.ed-rule {}
            div.ed-art-eyebrow { "Live VPN stats · last 24h" }
            p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
                "No live stats yet. The clash-api poller is shipped (Track-3 chunks 1+2) "
                "but the daemon-side scheduler that pulls snapshots from each VPN node "
                "is queued for chunk 4 — it needs the SSH key on "
                span.ed-mono { "192.168.0.236:/var/lib/vpnctl/.ssh" }
                " plus per-node authorisation. Once wired, this section will show real "
                "per-user upload/download totals and active connection counts."
            }
        };
    }

    // Aggregate over the window: total up + down (sum of all rows
    // for this user), peak active_connections.
    let mut total_up: u64 = 0;
    let mut total_dn: u64 = 0;
    let mut peak_conns: u32 = 0;
    let mut per_server: std::collections::BTreeMap<String, (u64, u64, u32)> =
        std::collections::BTreeMap::new();
    for r in &rows {
        total_up = total_up.saturating_add(r.upload_bytes);
        total_dn = total_dn.saturating_add(r.download_bytes);
        if r.active_connections > peak_conns {
            peak_conns = r.active_connections;
        }
        let entry = per_server.entry(r.server_id.0.clone()).or_default();
        entry.0 = entry.0.saturating_add(r.upload_bytes);
        entry.1 = entry.1.saturating_add(r.download_bytes);
        if r.active_connections > entry.2 {
            entry.2 = r.active_connections;
        }
    }

    html! {
        div.ed-rule {}
        div.ed-art-eyebrow { "Live VPN stats · last 24h" }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
            "Pulled from each node's clash-api by the daemon. "
            "Numbers reflect actual VPN traffic (delta-vs-prior-snapshot per tick), "
            "not subscription-config fetches."
        }
        div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin: 12px 0 18px;" {
            (vpn_kpi_tile("uploaded", &humanize_bytes(total_up)))
            (vpn_kpi_tile("downloaded", &humanize_bytes(total_dn)))
            (vpn_kpi_tile("peak conns", &peak_conns.to_string()))
        }
        @if !per_server.is_empty() {
            table style="width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 11.5px;" {
                thead {
                    tr style="border-bottom: 1px solid var(--ink);" {
                        th style="text-align: left; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { "server" }
                        th style="text-align: right; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { "uploaded" }
                        th style="text-align: right; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { "downloaded" }
                        th style="text-align: right; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { "peak conns" }
                    }
                }
                tbody {
                    @for (server_id, (up, dn, conns)) in &per_server {
                        tr style="border-bottom: 1px dotted var(--rule);" {
                            td style="padding: 5px 8px; color: var(--ink);" { (server_id) }
                            td style="padding: 5px 8px; text-align: right; color: var(--ink);" { (humanize_bytes(*up)) }
                            td style="padding: 5px 8px; text-align: right; color: var(--ink);" { (humanize_bytes(*dn)) }
                            td style="padding: 5px 8px; text-align: right; color: var(--ink);" { (conns) }
                        }
                    }
                }
            }
        }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin-top: 10px;" {
            "Aggregated from " (rows.len())
            @if rows.len() == 1 { " snapshot" } @else { " snapshots" }
            " over the last 24 hours. Rows are auto-purged after 30 days."
        }
    }
}

/// Editorial KPI tile — small label + big-serif number. Reused
/// pattern from the dashboard / Track-1 abuse signal.
fn vpn_kpi_tile(label: &str, value: &str) -> Markup {
    html! {
        div style="border: 1px solid var(--rule); padding: 10px 12px; background: var(--paper);" {
            div style="font-family: var(--mono); font-size: 10px; color: var(--mute); letter-spacing: 0.14em; text-transform: uppercase;" { (label) }
            div style="font-family: var(--serif); font-size: 22px; color: var(--ink); margin-top: 2px;" { (value) }
        }
    }
}

/// Convert a raw byte count into a human-readable string with a
/// binary-IEC suffix. Picks the largest unit at which the number
/// is >= 1, e.g. 1024 → "1.0 KiB", 1_572_864 → "1.5 MiB".
///
/// Hand-rolled rather than pulling `byte-unit` / `humansize` —
/// this is the only place we need it and the rules are short
/// enough that an inline implementation beats a new dep.
fn humanize_bytes(n: u64) -> String {
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

/// 404 response for `/admin/users/<id>` when no such user exists. Keeps
/// the editorial chrome out (matches the bare-text 500 convention from
/// `internal_error`) so the operator sees the message in plain form.
fn user_not_found(id: &str) -> Response {
    (
        StatusCode::NOT_FOUND,
        error_text(&format!("no such user '{id}'")),
    )
        .into_response()
}

// ────────────────────────────────────────────────────────────────────────
//  Phase C-3 — write handlers (Users)
//
//  Convention shared by every write in this section:
//   1. Validate the target exists → 404 with the canonical "no such X"
//      body if not. Avoids leaking a generic 500 from the inventory's
//      "rows_affected == 0" path.
//   2. Perform the mutation.
//   3. Write the audit row (`actor="admin"`, action namespaced like the
//      CLI: `user.sub_token.regen`, target = the affected entity id).
//      An audit-write failure is LOGGED (warn) but does NOT roll the
//      mutation back: rolling back would itself need an audit row, and
//      the alternative (failed mutation, no record of the attempt) is
//      worse than (succeeded mutation, missing audit). The warn-log
//      goes to journalctl so the operator can spot the gap.
//   4. Redirect 303 back to the relevant page so the operator sees
//      the post-mutation state without a stale form re-submit risk.
// ────────────────────────────────────────────────────────────────────────

/// `POST /admin/users/{id}/sub-token/regenerate` — mint a fresh sub_token,
/// invalidate the previous one, write the audit row, redirect back to
/// the user-detail page (which will render the new token + new QR).
///
/// CSRF posture: same as the existing tweak handlers — Referer is
/// sanitised so a hostile origin can't redirect the operator off-site,
/// but the mutation itself is allowed (worst case: operator's own
/// client gets disconnected and they have to re-pull, no secret leak).
pub(crate) async fn user_regen_sub_token(
    State(state): State<AppState>,
    Path(user_id_str): Path<String>,
) -> Response {
    let uid = vpnctl_core::UserId(user_id_str.clone());

    // Step 1: existence check. The downstream regenerate_sub_token
    // would error with `Invalid("no such user: …")` but that maps to
    // a 500 via `internal_error`; an explicit 404 here matches every
    // other "unknown id" surface in the admin tree.
    match state.inv.get_user(&uid).await {
        Ok(Some(_)) => {}
        Ok(None) => return user_not_found(&user_id_str),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    }

    // Step 2: mutation. Returns the new token, but we don't expose it
    // here — the redirect target re-renders the page from the inventory,
    // which is the single source of truth.
    if let Err(e) = state.inv.regenerate_sub_token(&uid).await {
        return internal_error(anyhow::Error::new(e));
    }

    // Step 3: audit. Best-effort; see module-level convention above.
    if let Err(e) = state
        .inv
        .audit("admin", "user.sub_token.regen", Some(&user_id_str), None)
        .await
    {
        tracing::warn!(
            target = "vpnctld::admin",
            user = %user_id_str,
            error = %e,
            "audit write failed for user.sub_token.regen — mutation already committed"
        );
    }

    // Step 4: redirect. `path_segment_encode` so the redirect target
    // matches the URL the operator clicked from.
    Redirect::to(&format!(
        "/admin/users/{}",
        path_segment_encode(&user_id_str)
    ))
    .into_response()
}

/// Validate a candidate user id from the web form. The HTML5 `pattern`
/// attribute already filters most input client-side, but we re-validate
/// server-side because (a) browsers can be bypassed and (b) the CLI
/// has no client-side filter, so the rule should live in one place.
///
/// Permitted: ASCII letters, digits, `.`, `_`, `-`. Length 1..=64.
/// Rejected: spaces, slashes, `?`, `#`, percent-escapes, anything
/// non-ASCII. Same set as `path_segment_encode`'s "unreserved" with
/// the additional constraint of bounded length.
fn valid_user_id(id: &str) -> bool {
    let len = id.len();
    if !(1..=64).contains(&len) {
        return false;
    }
    id.bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// `POST /admin/users` — create a new user from the form on
/// `/admin/users`. Form body is `id=<text>` (the only field — UUID,
/// tuic_password and sub_token are all minted server-side).
///
/// Outcomes:
///   * happy path → 303 to `/admin/users/<id>` (which re-renders the
///     fresh user with QR + share-links).
///   * empty / invalid id → 400 with the canonical error body.
///   * duplicate id → 400 with "already exists".
///   * inventory error → 500 via `internal_error`.
///
/// CSRF: handled by `csrf::require_same_origin` middleware on the
/// admin router (Origin must match Host). Audit row written on
/// success only.
pub(crate) async fn user_create(State(state): State<AppState>, body: String) -> Response {
    let id_raw = body
        .split('&')
        .find_map(|kv| kv.strip_prefix("id="))
        .unwrap_or("")
        .trim();
    let id_decoded = decode_form_value(id_raw);

    if !valid_user_id(&id_decoded) {
        return (
            StatusCode::BAD_REQUEST,
            error_text(&format!(
                "invalid user id '{id_decoded}' (allowed: 1-64 chars of A-Z a-z 0-9 . _ -)"
            )),
        )
            .into_response();
    }

    // Optional `wireguard_pubkey` from the form. Empty → None.
    // Shape-check: 44 base64 chars ending '=' (same contract as
    // `vpnctl_protocols::wireguard::is_valid_wg_pubkey`). Reject
    // at write time so a typo doesn't sit in inventory until a
    // future `vpnctl deploy` tries to render WG/AmneziaWG config.
    let wg_raw = body
        .split('&')
        .find_map(|kv| kv.strip_prefix("wireguard_pubkey="))
        .unwrap_or("")
        .trim();
    let wg_decoded = decode_form_value(wg_raw);
    let wg_pubkey: Option<String> = if wg_decoded.is_empty() {
        None
    } else {
        let ok = wg_decoded.len() == 44
            && wg_decoded.ends_with('=')
            && wg_decoded
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=');
        if !ok {
            return (
                StatusCode::BAD_REQUEST,
                error_text(&format!(
                    "invalid wireguard_pubkey (must be 44 base64 chars ending '='): {wg_decoded:?}"
                )),
            )
                .into_response();
        }
        Some(wg_decoded)
    };

    // Mint the secrets. UUID is straightforward; tuic_password is 24
    // bytes of entropy, base64'd by `gen_password`. sub_token is left
    // as None — the inventory's `add_user` generates it (single source
    // of truth for sub_token entropy).
    const TUIC_PW_BYTES: usize = 24;
    let tuic_password = match vpnctl_crypto::gen_password(TUIC_PW_BYTES) {
        Ok(pw) => pw,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    let user = vpnctl_core::User {
        id: vpnctl_core::UserId(id_decoded.clone()),
        uuid: vpnctl_crypto::gen_uuid(),
        tuic_password: Some(tuic_password),
        wireguard_pubkey: wg_pubkey,
        sub_token: None,
    };

    // Mutation. `AlreadyExists` (UNIQUE violation) gets a 400 with
    // the "already exists" body — operator's typical fix is to pick a
    // different id, no need to surface a generic 500.
    if let Err(e) = state.inv.add_user(&user).await {
        return match e {
            vpnctl_inventory::SqliteInventoryError::AlreadyExists(what) => (
                StatusCode::BAD_REQUEST,
                error_text(&format!("{what} already exists — pick a different id")),
            )
                .into_response(),
            other => internal_error(anyhow::Error::new(other)),
        };
    }

    // Audit (best-effort; see module convention).
    if let Err(e) = state
        .inv
        .audit(
            "admin",
            "user.add",
            Some(&id_decoded),
            Some(&serde_json::json!({
                "uuid": user.uuid,
                "wg_pubkey_set": user.wireguard_pubkey.is_some(),
            })),
        )
        .await
    {
        tracing::warn!(
            target = "vpnctld::admin",
            user = %id_decoded,
            error = %e,
            "audit write failed for user.add — mutation already committed"
        );
    }

    Redirect::to(&format!(
        "/admin/users/{}",
        path_segment_encode(&id_decoded)
    ))
    .into_response()
}

/// `POST /admin/users/{id}/grants/{server_id}` — grant the user
/// access to the server. Idempotent: re-granting an existing pair
/// is a no-op at the SQL layer (`ON CONFLICT … DO NOTHING`), but the
/// handler still writes an audit row each time so operators can see
/// re-grant attempts in the timeline.
///
/// Both ids are validated to exist before the mutation — unknown
/// user → 404, unknown server → 404 with the same canonical body
/// shape. The `vpnctl admin: no such X` prefix is in `error_text`.
pub(crate) async fn user_grant_server(
    State(state): State<AppState>,
    Path((user_id_str, server_id_str)): Path<(String, String)>,
) -> Response {
    let uid = vpnctl_core::UserId(user_id_str.clone());
    let sid = vpnctl_core::ServerId(server_id_str.clone());

    // Both existence checks before mutation — same convention as
    // user_regen_sub_token. Prevents a generic 500 from "no such row"
    // surfaces in the inventory.
    match state.inv.get_user(&uid).await {
        Ok(Some(_)) => {}
        Ok(None) => return user_not_found(&user_id_str),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    }
    match state.inv.get_server(&sid).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                error_text(&format!("no such server '{server_id_str}'")),
            )
                .into_response();
        }
        Err(e) => return internal_error(anyhow::Error::new(e)),
    }

    if let Err(e) = state.inv.grant(&uid, &sid).await {
        return internal_error(anyhow::Error::new(e));
    }
    if let Err(e) = state
        .inv
        .audit(
            "admin",
            "grant",
            Some(&server_id_str),
            Some(&serde_json::json!({ "user": user_id_str })),
        )
        .await
    {
        tracing::warn!(
            target = "vpnctld::admin",
            user = %user_id_str,
            server = %server_id_str,
            error = %e,
            "audit write failed for grant — mutation already committed"
        );
    }
    Redirect::to(&format!(
        "/admin/users/{}",
        path_segment_encode(&user_id_str)
    ))
    .into_response()
}

/// `POST /admin/users/{id}/grants/{server_id}/revoke` — revoke the
/// grant. Idempotent like `grant`; revoking a non-existent grant is
/// a no-op at the SQL layer but still audited (the operator's
/// intent is recorded regardless of pre-state).
pub(crate) async fn user_revoke_server(
    State(state): State<AppState>,
    Path((user_id_str, server_id_str)): Path<(String, String)>,
) -> Response {
    let uid = vpnctl_core::UserId(user_id_str.clone());
    let sid = vpnctl_core::ServerId(server_id_str.clone());

    match state.inv.get_user(&uid).await {
        Ok(Some(_)) => {}
        Ok(None) => return user_not_found(&user_id_str),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    }
    match state.inv.get_server(&sid).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                error_text(&format!("no such server '{server_id_str}'")),
            )
                .into_response();
        }
        Err(e) => return internal_error(anyhow::Error::new(e)),
    }

    if let Err(e) = state.inv.revoke(&uid, &sid).await {
        return internal_error(anyhow::Error::new(e));
    }
    if let Err(e) = state
        .inv
        .audit(
            "admin",
            "revoke",
            Some(&server_id_str),
            Some(&serde_json::json!({ "user": user_id_str })),
        )
        .await
    {
        tracing::warn!(
            target = "vpnctld::admin",
            user = %user_id_str,
            server = %server_id_str,
            error = %e,
            "audit write failed for revoke — mutation already committed"
        );
    }
    Redirect::to(&format!(
        "/admin/users/{}",
        path_segment_encode(&user_id_str)
    ))
    .into_response()
}

/// Tiny URL-decoder for form values. Replaces `+` with space and
/// `%XX` with the byte. Invalid escapes pass through verbatim — the
/// validator above will reject them. Avoids pulling a percent-decode
/// dep for one form field.
fn decode_form_value(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok();
                if let Some(h) = hex {
                    if let Ok(byte) = u8::from_str_radix(h, 16) {
                        out.push(byte as char);
                        i += 3;
                        continue;
                    }
                }
                out.push('%');
                i += 1;
            }
            other => {
                out.push(other as char);
                i += 1;
            }
        }
    }
    out
}

/// `GET /admin/users/{id}/delete-confirm` — destructive-action
/// double-submit confirm page (C-3.4). Renders a form that requires
/// the operator to retype the user-id; only a matching POST to
/// `/admin/users/{id}/delete` actually deletes.
pub(crate) async fn user_delete_confirm(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(user_id_str): Path<String>,
) -> Result<Markup, Response> {
    let (theme, accent, tw) = theme_accent(&headers);
    let uid = vpnctl_core::UserId(user_id_str.clone());
    match state.inv.get_user(&uid).await {
        Ok(Some(_)) => {}
        Ok(None) => return Err(user_not_found(&user_id_str)),
        Err(e) => return Err(internal_error(anyhow::Error::new(e))),
    }
    let body = html! {
        div.ed-art-eyebrow {
            a href=(format!("/admin/users/{}", path_segment_encode(&user_id_str)))
              style="color: var(--mute); text-decoration: none;" { "← back to user" }
            "  ·  delete"
        }
        h1.ed-art-h1 {
            "delete "
            em { (user_id_str) }
            " — really?"
        }
        p.ed-art-deck {
            "This drops the user from the inventory. "
            b { "Grants" }
            " (the user × server bridge) cascade-delete via FK. "
            b { "Subscription-access log rows" }
            " for this user SURVIVE with NULL user_id (per migration 0004) "
            "so post-mortem forensics still works. "
            b { "Persistent bans" }
            " keyed by IP also survive (they're keyed by IP, not user)."
        }
        p style="font-family: var(--serif); font-style: italic; color: var(--mute); padding: 8px 0;" {
            "Type the user-id "
            span.ed-mono { (user_id_str) }
            " in the box below to confirm. The id has to match exactly — copy/paste counts."
        }
        form method="post"
             action=(format!("/admin/users/{}/delete", path_segment_encode(&user_id_str)))
             style="display: flex; gap: 10px; align-items: baseline; padding: 14px 16px; border: 1px solid var(--rule); margin: 16px 0;" {
            label style="font-family: var(--mono); font-size: 11px; color: var(--mute); letter-spacing: 0.14em; text-transform: uppercase;" {
                "confirm id"
            }
            input type="text" name="confirm" required="required"
                  autocomplete="off"
                  style="flex: 1; max-width: 280px; padding: 4px 8px; border: 1px solid var(--rule-s); background: var(--paper); font-family: var(--mono); font-size: 12px; color: var(--ink);";
            button type="submit"
                   title=(format!("Delete user {} permanently", user_id_str))
                   style="padding: 4px 12px; border: 1px solid var(--acc); background: var(--acc); color: var(--paper); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                "delete forever"
            }
            a href=(format!("/admin/users/{}", path_segment_encode(&user_id_str)))
              style="padding: 4px 10px; border: 1px solid var(--rule-s); color: var(--mute); font-family: var(--mono); font-size: 11px; text-decoration: none;" {
                "cancel"
            }
        }
    };
    Ok(shell("users", &theme, &accent, tw, body))
}

/// `POST /admin/users/{id}/delete` — actually delete. Body must be
/// `confirm=<exact-user-id>`; mismatch → 400 (the GET-form sets up
/// the correct value, so a mismatch means the operator typed
/// something different on a manual curl OR a CSRF attempt slipped
/// past the middleware — neither is a normal flow).
pub(crate) async fn user_delete(
    State(state): State<AppState>,
    Path(user_id_str): Path<String>,
    body: String,
) -> Response {
    let confirm_raw = body
        .split('&')
        .find_map(|kv| kv.strip_prefix("confirm="))
        .unwrap_or("");
    let confirm = decode_form_value(confirm_raw);
    if confirm != user_id_str {
        return (
            StatusCode::BAD_REQUEST,
            error_text(&format!(
                "delete confirm mismatch: form sent '{confirm}', URL targets '{user_id_str}' — type the user id exactly to confirm"
            )),
        )
            .into_response();
    }

    let uid = vpnctl_core::UserId(user_id_str.clone());
    match state.inv.get_user(&uid).await {
        Ok(Some(_)) => {}
        Ok(None) => return user_not_found(&user_id_str),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    }
    if let Err(e) = state.inv.remove_user(&uid).await {
        return internal_error(anyhow::Error::new(e));
    }
    if let Err(e) = state
        .inv
        .audit("admin", "user.remove", Some(&user_id_str), None)
        .await
    {
        tracing::warn!(
            target = "vpnctld::admin",
            user = %user_id_str,
            error = %e,
            "audit row for user.remove failed; mutation already committed"
        );
    }
    Redirect::to("/admin/users").into_response()
}

/// Phase D — paginated, filterable audit timeline. Replaces the
/// Phase A placeholder body. Reads `?actor=`, `?action=`, `?page=`
/// from the query string; renders a filter form, sticky-date
/// section headers (Today / Yesterday / `<YYYY-MM-DD>`), and
/// prev/next pagination links. CSV export lives at a separate
/// endpoint (`/admin/audit.csv`) keyed by the same query params.
pub(crate) async fn audit(
    headers: HeaderMap,
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<AuditQuery>,
) -> Result<Markup, Response> {
    let (theme, accent, tw) = theme_accent(&headers);

    let actor = q.actor.as_deref().filter(|s| !s.is_empty());
    let action = q.action.as_deref().filter(|s| !s.is_empty());
    /// Hard cap so `?page=99999...` can't overflow `page * PAGE_SIZE`.
    /// 1M pages × 50/page = 50M rows — way past any plausible audit
    /// history; clamping there is friendlier than panicking on overflow.
    const MAX_PAGE: i64 = 1_000_000;
    let page = q.page.unwrap_or(0).clamp(0, MAX_PAGE);

    /// Page size — small enough that even a busy operator scans
    /// each page quickly, large enough that 99% of audit history
    /// lookups don't need pagination at all.
    const PAGE_SIZE: i64 = 50;

    // Fetch one extra row to detect "is there a next page?".
    // `saturating_mul` belt-and-braces — `page` is already clamped to
    // MAX_PAGE so this can't actually saturate, but the explicit op
    // makes the overflow story visible at the call site.
    let offset = page.saturating_mul(PAGE_SIZE);
    let entries = state
        .inv
        .recent_audit_paginated(PAGE_SIZE + 1, offset, actor, action)
        .await
        .map_err(|e| internal_error(anyhow::Error::new(e)))?;

    let has_next = entries.len() as i64 > PAGE_SIZE;
    let visible: Vec<&vpnctl_inventory::AuditEntry> =
        entries.iter().take(PAGE_SIZE as usize).collect();
    let has_prev = page > 0;

    let body = html! {
        div.ed-art-eyebrow { "Audit" }
        h1.ed-art-h1 {
            "every "
            em { "mutation" }
            " on file"
        }
        p.ed-art-deck {
            "Append-only stream of every state change the daemon or CLI has made to "
            span.ed-mono { "/var/lib/vpnctl/inv.db" }
            ". Use the filters to narrow by actor or action prefix; the CSV button "
            "exports the same filtered slice."
        }

        // Filter form. GET so the URL itself encodes the filter
        // (operator can bookmark / share). All three inputs are
        // empty-tolerant — empty string = no filter on that axis.
        form method="get" action="/admin/audit"
             style="display: flex; gap: 12px; align-items: baseline; padding: 12px 14px; border: 1px solid var(--rule); margin: 16px 0 24px; font-family: var(--mono); font-size: 11px;" {
            label { "actor" }
            select name="actor"
                   style="padding: 3px 6px; border: 1px solid var(--rule-s); font-family: var(--mono); font-size: 11px;" {
                option value="" { "(any)" }
                @for opt in ["admin", "cli", "daemon"] {
                    @if Some(opt) == actor {
                        option value=(opt) selected="selected" { (opt) }
                    } @else {
                        option value=(opt) { (opt) }
                    }
                }
            }
            label { "action prefix" }
            input type="text" name="action"
                  value=(action.unwrap_or(""))
                  placeholder="user. / server. / grant"
                  style="padding: 3px 6px; max-width: 220px; border: 1px solid var(--rule-s); font-family: var(--mono); font-size: 11px;";
            button type="submit"
                   style="padding: 3px 10px; border: 1px solid var(--ink); background: var(--ink); color: var(--paper); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                "filter"
            }
            // Reset button — empty params clear all filters.
            a href="/admin/audit"
              style="padding: 3px 10px; border: 1px solid var(--rule-s); background: transparent; color: var(--mute); font-family: var(--mono); font-size: 11px; text-decoration: none;" {
                "reset"
            }
            // CSV export uses the same query string.
            a href=(audit_url("/admin/audit.csv", actor, action, None))
              style="margin-left: auto; padding: 3px 10px; border: 1px solid var(--rule-s); background: transparent; color: var(--ink); font-family: var(--mono); font-size: 11px; text-decoration: none;" {
                "export csv"
            }
        }

        // Date-grouped timeline. We walk visible rows once, emitting
        // a sticky-date header whenever the day changes from the
        // previous row. Entries are already newest-first by id.
        @if visible.is_empty() {
            p style="font-family: var(--serif); font-style: italic; color: var(--mute); padding: 24px 0;" {
                @if actor.is_some() || action.is_some() {
                    "No audit rows match the current filter."
                } @else {
                    "No audit rows yet — this stream fills as the daemon does work."
                }
            }
        } @else {
            (audit_timeline_grouped(&visible))
        }

        // Pagination links. URLs preserve the active filters.
        div style="display: flex; gap: 16px; padding: 16px 0; font-family: var(--mono); font-size: 12px;" {
            @if has_prev {
                a href=(audit_url("/admin/audit", actor, action, Some(page - 1)))
                  style="color: var(--ink); text-decoration: none;" {
                    "← prev"
                }
            } @else {
                span style="color: var(--mute);" { "← prev" }
            }
            span style="color: var(--mute);" {
                "page " (page + 1)
            }
            @if has_next {
                a href=(audit_url("/admin/audit", actor, action, Some(page + 1)))
                  style="color: var(--ink); text-decoration: none;" {
                    "next →"
                }
            } @else {
                span style="color: var(--mute);" { "next →" }
            }
        }
    };
    Ok(shell("audit", &theme, &accent, tw, body))
}

/// Query-string args for the audit timeline. All optional; empty
/// string is treated as "no filter on this axis" by the handler.
#[derive(serde::Deserialize, Debug, Default)]
pub(crate) struct AuditQuery {
    pub actor: Option<String>,
    pub action: Option<String>,
    pub page: Option<i64>,
}

/// Build a `/admin/audit*` URL preserving the current filter query.
/// Pass `Some(page)` for paginated HTML targets, `None` for the CSV
/// export endpoint (which doesn't paginate). Single helper avoids the
/// near-duplicate URL builders that the previous chunk had.
fn audit_url(base: &str, actor: Option<&str>, action: Option<&str>, page: Option<i64>) -> String {
    let mut q = String::from(base);
    let mut sep = '?';
    if let Some(a) = actor {
        q.push(sep);
        q.push_str(&format!("actor={}", path_segment_encode(a)));
        sep = '&';
    }
    if let Some(a) = action {
        q.push(sep);
        q.push_str(&format!("action={}", path_segment_encode(a)));
        sep = '&';
    }
    if let Some(p) = page {
        q.push(sep);
        q.push_str(&format!("page={p}"));
    }
    q
}

/// Render the entries grouped by date with sticky `Today / Yesterday
/// / <date>` section headers. Reuses the existing `dashboard_audit`
/// row markup so the visual style stays consistent.
fn audit_timeline_grouped(entries: &[&vpnctl_inventory::AuditEntry]) -> Markup {
    use chrono::{Duration, Utc};
    let today = Utc::now().date_naive();
    let yesterday = today - Duration::days(1);
    let mut current_label: Option<String> = None;
    html! {
        div.ed-time {
            @for e in entries {
                @let day = e.ts.date_naive();
                @let label = if day == today {
                    "Today".to_string()
                } else if day == yesterday {
                    "Yesterday".to_string()
                } else {
                    day.format("%Y-%m-%d").to_string()
                };
                @if Some(&label) != current_label.as_ref() {
                    div style="margin: 18px 0 6px; padding: 4px 0; font-family: var(--mono); font-size: 10.5px; letter-spacing: 0.14em; text-transform: uppercase; color: var(--mute); border-bottom: 1px solid var(--rule);" {
                        (label)
                    }
                }
                div.ed-time-row {
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
                @let _ = current_label.replace(label);
            }
        }
    }
}

/// `GET /admin/audit.csv?actor=...&action=...` — same filter set as
/// the HTML timeline but returns a CSV body with `Content-Disposition:
/// attachment; filename="vpnctl-audit-<YYYYMMDD>.csv"`. Limit is high
/// (10000 rows) — operator running a yearly export shouldn't have to
/// page; if they need more they bump the limit query.
pub(crate) async fn audit_csv(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<AuditQuery>,
) -> Response {
    let actor = q.actor.as_deref().filter(|s| !s.is_empty());
    let action = q.action.as_deref().filter(|s| !s.is_empty());

    /// Generous cap; the operator can re-export with ?limit= once we
    /// add that to AuditQuery in a follow-up.
    const CSV_LIMIT: i64 = 10_000;

    let entries = match state
        .inv
        .recent_audit_paginated(CSV_LIMIT, 0, actor, action)
        .await
    {
        Ok(v) => v,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };

    // Build CSV manually — adding the `csv` crate for one writer
    // would be over-engineering for 4 columns. Quote any field
    // containing `"`, `,` or newline; double-up internal quotes.
    let mut out = String::from("ts,actor,action,target,payload\n");
    for e in &entries {
        out.push_str(&csv_field(&e.ts.to_rfc3339()));
        out.push(',');
        out.push_str(&csv_field(&e.actor));
        out.push(',');
        out.push_str(&csv_field(&e.action));
        out.push(',');
        out.push_str(&csv_field(e.target.as_deref().unwrap_or("")));
        out.push(',');
        // serde_json::to_string on a Value should never fail, but if
        // it ever did the row would silently lose its payload column.
        // Log instead of swallowing so the operator notices.
        let payload_str = match &e.payload {
            None => String::new(),
            Some(v) => match serde_json::to_string(v) {
                Ok(s) => s,
                Err(err) => {
                    tracing::warn!(
                        target = "vpnctld::admin::audit_csv",
                        audit_id = e.id,
                        error = %err,
                        "audit payload failed to serialize for CSV; emitting empty cell"
                    );
                    String::new()
                }
            },
        };
        out.push_str(&csv_field(&payload_str));
        out.push('\n');
    }

    let stamp = chrono::Utc::now().format("%Y%m%d");
    let filename = format!("vpnctl-audit-{stamp}.csv");
    (
        StatusCode::OK,
        [
            ("content-type", "text/csv; charset=utf-8".to_string()),
            (
                "content-disposition",
                format!("attachment; filename=\"{filename}\""),
            ),
        ],
        out,
    )
        .into_response()
}

/// Quote a single CSV field per RFC 4180. If the field contains
/// `"`, `,`, `\n`, or `\r` we wrap it in double-quotes and double
/// any internal quotes; otherwise return the field verbatim.
fn csv_field(s: &str) -> String {
    let needs_quote = s.contains(['"', ',', '\n', '\r']);
    if !needs_quote {
        return s.to_string();
    }
    let escaped = s.replace('"', "\"\"");
    format!("\"{escaped}\"")
}

pub(crate) async fn settings(headers: HeaderMap) -> Markup {
    let (theme, accent, tw) = theme_accent(&headers);
    let body = section_placeholder_body("Settings");
    shell("settings", &theme, &accent, tw, body)
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
        // Be specific: the operator already knows it was a tweak POST
        // (they hit /admin/tweak/<kind>); the surface they need is
        // *what value* and *which kind*. Include both.
        return (
            StatusCode::BAD_REQUEST,
            error_text(&format!(
                "invalid value '{value}' for tweak '{cookie_name}' (allowed: {})",
                valid.join(", ")
            )),
        )
            .into_response();
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

/// Path `/admin/tweak/{kind}` dispatcher — `kind` is "theme", "accent",
/// or "tweaks" (the open/closed state of the panel itself).
pub(crate) async fn set_tweak(
    headers: HeaderMap,
    Path(kind): Path<String>,
    body: String,
) -> Response {
    match kind.as_str() {
        "theme" => set_tweak_cookie(&headers, COOKIE_THEME, VALID_THEMES, &body),
        "accent" => set_tweak_cookie(&headers, COOKIE_ACCENT, VALID_ACCENTS, &body),
        "tweaks" => set_tweak_cookie(&headers, COOKIE_TWEAKS_OPEN, VALID_TWEAKS_OPEN, &body),
        unknown => (
            StatusCode::NOT_FOUND,
            error_text(&format!(
                "unknown tweak kind '{unknown}' (known: theme, accent, tweaks)"
            )),
        )
            .into_response(),
    }
}

// ────────────────────────────────────────────────────────────────────────
//  Phase E — add-server wizard.
//
//  Sub-iter 4a (this commit): step-1 form + submit + step-2 stub.
//  Sub-iter 4b: SSE handler streaming `vpnctl bootstrap` + `vpnctl deploy`.
//  Sub-iter 4c: completion page + audit + return to /admin/servers.
//
//  The wizard is the operator's main reason for the admin UI to exist
//  per CLAUDE.md "Strategic context" — paste IP+root password and the
//  daemon does the rest. Sub-iter 4a establishes the session plumbing
//  so 4b can focus on the SSE plumbing without also designing input
//  validation and cookie schemes.
//
//  Security model: the session cookie is HttpOnly, SameSite=Strict,
//  Path=/admin/servers/new, and Max-Age=600s. The CSRF middleware
//  already requires a same-origin Origin header on POST; this stack
//  means a cross-origin attacker can neither read the cookie nor
//  forge a wizard step. The 32-byte random session id is opaque
//  outside the daemon process.
// ────────────────────────────────────────────────────────────────────────

/// Pull a single named cookie's value out of the `Cookie` header.
/// Returns `None` if the header is absent or the cookie name isn't
/// present. Does no URL-decoding — wizard ids are base64-url and
/// don't contain anything that would need decoding.
///
/// Hand-rolled rather than pulling `cookie` crate as a dep — the only
/// existing cookie reader in this module is in `theme_accent`, which
/// also walks the header by hand. Two readers, same pattern.
fn read_cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    for piece in raw.split(';') {
        let kv = piece.trim();
        if let Some(rest) = kv.strip_prefix(name)
            && let Some(value) = rest.strip_prefix('=')
        {
            return Some(value);
        }
    }
    None
}

/// Parse a single named field out of an `application/x-www-form-urlencoded`
/// body. Returns the URL-decoded value (`+` → space, `%XX` → byte).
/// Returns `None` if the field isn't present. Same minimal-parser
/// pattern as `user_create` — no need for a full form-decoder when the
/// wizard step has exactly two fields.
fn form_field(body: &str, name: &str) -> Option<String> {
    let prefix = format!("{name}=");
    body.split('&')
        .find_map(|kv| kv.strip_prefix(&prefix))
        .map(decode_form_value)
}

/// `GET /admin/servers/new` — render the wizard's step-1 form.
///
/// Two fields: server address (IP or hostname) and root password.
/// Submit POSTs to the same URL; success goes to `/admin/servers/new/step-2`.
/// Cancel link leads back to `/admin/servers`.
pub(crate) async fn wizard_new(headers: HeaderMap) -> Markup {
    let (theme, accent, tw) = theme_accent(&headers);
    let body = html! {
        div.ed-art-eyebrow { "Add server · step 1 of 3" }
        h1.ed-art-h1 {
            "Paste an " em { "IP" } " and the " em { "root password" }
        }
        p.ed-art-deck {
            "The daemon will SSH in as " span.ed-mono { "root" } ", push its key, "
            "create a non-root user, harden " span.ed-mono { "sshd_config" } ", "
            "install fail2ban + sing-box, render the config, and prove the service "
            "is live — all on the next screen."
        }

        form method="post" action="/admin/servers/new"
             style="margin: 24px 0; padding: 18px 20px; border: 1px solid var(--rule); background: var(--paper); display: flex; flex-direction: column; gap: 14px;" {
            div style="display: flex; flex-direction: column; gap: 4px;" {
                label for="address"
                      style="font-family: var(--mono); font-size: 11px; color: var(--mute); letter-spacing: 0.14em; text-transform: uppercase;" {
                    "address"
                }
                input id="address" name="address" type="text" required="required"
                      placeholder="198.51.100.42 or vpn-de1.example.org"
                      autocomplete="off" autocapitalize="none" spellcheck="false"
                      pattern="[A-Za-z0-9.:_-]+"
                      title="IPv4, IPv6 or hostname — no shell metacharacters"
                      style="padding: 6px 10px; border: 1px solid var(--rule-s); background: var(--paper); font-family: var(--mono); font-size: 13px; color: var(--ink);";
                p style="font-family: var(--serif); font-style: italic; font-size: 11.5px; color: var(--mute); margin: 0;" {
                    "DigitalOcean droplets must keep SSH on port 22 (Cloud Firewall blocks the rest); other hosters get the harden-to-2222 step automatically on the next screen."
                }
            }
            div style="display: flex; flex-direction: column; gap: 4px;" {
                label for="root_password"
                      style="font-family: var(--mono); font-size: 11px; color: var(--mute); letter-spacing: 0.14em; text-transform: uppercase;" {
                    "root password"
                }
                input id="root_password" name="root_password" type="password" required="required"
                      autocomplete="new-password"
                      style="padding: 6px 10px; border: 1px solid var(--rule-s); background: var(--paper); font-family: var(--mono); font-size: 13px; color: var(--ink);";
                p style="font-family: var(--serif); font-style: italic; font-size: 11.5px; color: var(--mute); margin: 0;" {
                    "Used once to push our SSH key, then password auth gets disabled. Held in daemon memory for 10 minutes; nothing is written to disk."
                }
            }
            div style="display: flex; gap: 12px; align-items: center; margin-top: 6px;" {
                button type="submit"
                       title="Validate inputs and continue to the bootstrap log"
                       style="padding: 6px 14px; border: 1px solid var(--ink); background: var(--ink); color: var(--paper); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                    "continue →"
                }
                a href="/admin/servers"
                  style="font-family: var(--mono); font-size: 11px; color: var(--mute); text-decoration: none; padding: 6px 8px;" {
                    "cancel"
                }
            }
        }
    };
    shell("servers", &theme, &accent, tw, body)
}

/// `POST /admin/servers/new` — validate the step-1 input, stash it in
/// the wizard session store, set the session cookie, redirect to
/// step 2.
///
/// On validation failure returns 400 with the canonical
/// `vpnctl admin: …` body — the operator fixes the offending field
/// without consulting source. Success redirects to step 2 (303 so a
/// browser refresh lands on step 2, not a duplicate POST).
pub(crate) async fn wizard_new_submit(State(state): State<AppState>, body: String) -> Response {
    let address_raw = form_field(&body, "address").unwrap_or_default();
    let password_raw = form_field(&body, "root_password").unwrap_or_default();

    let address = match crate::wizard::validate_address(&address_raw) {
        Ok(s) => s.to_string(),
        Err(why) => {
            return (
                StatusCode::BAD_REQUEST,
                error_text(&format!("invalid address — {why}")),
            )
                .into_response();
        }
    };
    if let Err(why) = crate::wizard::validate_password(&password_raw) {
        return (
            StatusCode::BAD_REQUEST,
            error_text(&format!("invalid root password — {why}")),
        )
            .into_response();
    }

    let session_id = state.wizard.insert(address, password_raw);

    // Cookie scope: only the wizard endpoints. Path=/admin/servers/new
    // means the browser doesn't ship the session id to /admin/users,
    // /admin/audit, etc.
    let cookie = format!(
        "{name}={id}; HttpOnly; SameSite=Strict; Path=/admin/servers/new; Max-Age=600",
        name = crate::wizard::COOKIE_NAME,
        id = session_id,
    );
    let mut resp = Redirect::to("/admin/servers/new/step-2").into_response();
    if let Ok(v) = HeaderValue::from_str(&cookie) {
        resp.headers_mut().insert(header::SET_COOKIE, v);
    }
    resp
}

/// `GET /admin/servers/new/step-2` — stub for sub-iter 4a. Reads the
/// session cookie, looks up the stashed step-1 input, and renders a
/// short page confirming the address. Sub-iter 4b replaces this with
/// the real SSE-streaming bootstrap log.
///
/// On missing/expired session redirects back to step 1 with a 303 +
/// short message — the operator's session has timed out and there's
/// nothing actionable on this screen without it.
pub(crate) async fn wizard_step2_stub(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Response {
    let (theme, accent, tw) = theme_accent(&headers);
    let session =
        read_cookie(&headers, crate::wizard::COOKIE_NAME).and_then(|id| state.wizard.get(id));

    let session = match session {
        Some(s) => s,
        None => {
            // No session = direct hit on step-2 without going through
            // step-1, OR the session expired (10-min TTL). Either way
            // the operator needs to start over.
            return (
                StatusCode::BAD_REQUEST,
                error_text(
                    "wizard session expired or missing — start over from /admin/servers/new",
                ),
            )
                .into_response();
        }
    };

    let body = html! {
        div.ed-art-eyebrow { "Add server · step 2 of 3" }
        h1.ed-art-h1 {
            "Bootstrapping " span.ed-mono { (session.address) }
        }
        p.ed-art-deck {
            "The next screen will stream " span.ed-mono { "vpnctl bootstrap" }
            " + " span.ed-mono { "vpnctl deploy" } " line-by-line over Server-Sent Events. "
            em { "Sub-iter 4b ships that part" } " — for now this is a stub that just confirms "
            "your step-1 input survived the round-trip."
        }
        div style="margin: 24px 0; padding: 14px 18px; border: 1px solid var(--rule); background: var(--paper);" {
            dl style="margin: 0; display: grid; grid-template-columns: 140px 1fr; gap: 8px 16px; font-family: var(--mono); font-size: 12px;" {
                dt style="color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { "address" }
                dd style="margin: 0; color: var(--ink);" { (session.address) }
                dt style="color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { "root password" }
                dd style="margin: 0; color: var(--mute); font-style: italic;" {
                    "(held in daemon memory — never echoed to the page)"
                }
            }
        }
        a href="/admin/servers"
          style="font-family: var(--mono); font-size: 11px; color: var(--mute); text-decoration: none;" {
            "← back to servers"
        }
    };
    shell("servers", &theme, &accent, tw, body).into_response()
}

// ────────────────────────────────────────────────────────────────────────
//  Phase H chunk 3 — server detail page with live telemetry surface.
//
//  Reads:
//    * `inv.get_server(id)` — declared state
//    * `inv.users_for_server(id)` — grants count
//    * `inv.latest_node_health(id)` — most recent probe (live)
//    * `inv.recent_node_health_for_server(id, 24)` — 24h window
//
//  Drift detection: parses the latest probe's `listening_ports_json`,
//  cross-references against `server.enabled_protocols` (mapping protocol
//  → expected ports), highlights mismatch in orange (--acc).
// ────────────────────────────────────────────────────────────────────────

/// Map a protocol id → set of (proto, port) we EXPECT it to be
/// listening on. Single source of truth for the drift check —
/// matches what each `Protocol::server_inbound` emits.
fn expected_ports_for_protocol(pid: &str) -> &'static [(&'static str, u16)] {
    match pid {
        "vless+reality" => &[("tcp", 443)],
        "tuic-v5" => &[("udp", 8443)],
        "hysteria2" => &[("udp", 8444)],
        "shadowsocks-2022" => &[("tcp", 8388), ("udp", 8388)],
        "wireguard" => &[("udp", 51820)],
        "anytls" => &[("tcp", 8843)],
        "trojan" => &[("tcp", 8643)],
        _ => &[],
    }
}

pub(crate) async fn server_detail(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(server_id_str): Path<String>,
) -> Result<Markup, Response> {
    let (theme, accent, tw) = theme_accent(&headers);
    let sid = vpnctl_core::ServerId(server_id_str.clone());

    let server = match state.inv.get_server(&sid).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return Err((
                StatusCode::NOT_FOUND,
                error_text(&format!("no such server '{server_id_str}'")),
            )
                .into_response());
        }
        Err(e) => return Err(internal_error(anyhow::Error::new(e))),
    };

    let users = state
        .inv
        .users_for_server(&sid)
        .await
        .map_err(|e| internal_error(anyhow::Error::new(e)))?;
    let user_count = users.len();

    let latest = state
        .inv
        .latest_node_health(&sid)
        .await
        .map_err(|e| internal_error(anyhow::Error::new(e)))?;

    // Compute drift: declared vs observed ports.
    let observed: std::collections::BTreeSet<(String, u16)> = latest
        .as_ref()
        .and_then(|h| h.listening_ports_json.as_deref())
        .and_then(|j| serde_json::from_str::<Vec<String>>(j).ok())
        .map(|v| {
            v.into_iter()
                .filter_map(|s| {
                    let mut p = s.splitn(2, '/');
                    let proto = p.next()?.to_string();
                    let port: u16 = p.next()?.parse().ok()?;
                    Some((proto, port))
                })
                .collect()
        })
        .unwrap_or_default();

    let expected: std::collections::BTreeSet<(String, u16)> = server
        .enabled_protocols
        .iter()
        .flat_map(|p| {
            expected_ports_for_protocol(&p.0)
                .iter()
                .map(|(pr, pt)| ((*pr).to_string(), *pt))
        })
        .collect();

    let missing: Vec<_> = expected.difference(&observed).cloned().collect();
    let extra: Vec<_> = observed
        .difference(&expected)
        .filter(|(_, port)| *port != 22) // SSH is always listening, never "extra"
        .cloned()
        .collect();

    let body = html! {
        nav style="font-family: var(--mono); font-size: 11px; color: var(--mute); margin-bottom: 12px;" {
            a href="/admin/servers" style="color: var(--mute); text-decoration: none;" {
                "← all servers"
            }
        }
        div.ed-art-eyebrow { "Server detail" }
        h1.ed-art-h1 { (server.id.0) }
        p.ed-art-deck {
            span.ed-mono { (server.address) ":" (server.ssh_port) }
            " · ssh as " span.ed-mono { (server.ssh_user) }
            " · kernel " span.ed-mono { (server.kernel.0) }
            " · hoster " b { (server.hoster) }
        }

        // Hero: current state (live or empty-state)
        (server_detail_hero(&latest, &server))

        // Declared vs observed drift
        (server_detail_drift_section(&server, &observed, &missing, &extra, latest.is_some()))

        // Grants
        div.ed-rule {}
        div.ed-art-eyebrow { "Grants" }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
            (user_count) " "
            @if user_count == 1 { "user" } @else { "users" }
            " granted access on this server."
        }
        @if users.is_empty() {
            p style="font-family: var(--serif); font-style: italic; color: var(--mute); padding: 8px 0;" {
                "No grants yet. Use "
                span.ed-mono { "vpnctl grant <user> " (server.id.0) }
                " to add."
            }
        } @else {
            ul style="list-style: none; padding: 0; font-family: var(--mono); font-size: 12px;" {
                @for u in &users {
                    li style="padding: 4px 0; border-bottom: 1px dotted var(--rule);" {
                        a href=(format!("/admin/users/{}", path_segment_encode(&u.id.0)))
                          style="color: var(--ink); text-decoration: none;" {
                            (u.id.0)
                        }
                    }
                }
            }
        }
    };
    Ok(shell("servers", &theme, &accent, tw, body))
}

/// Hero block — most-recent probe at-a-glance KPIs, OR an empty state
/// pointing at chunk 4 (the not-yet-shipped poller) so the operator
/// knows WHY the box is empty.
fn server_detail_hero(
    latest: &Option<vpnctl_inventory::NodeHealthRow>,
    server: &vpnctl_core::Server,
) -> Markup {
    let Some(h) = latest else {
        return html! {
            div.ed-rule {}
            div.ed-art-eyebrow { "Live status" }
            p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
                "No probes yet. The node-telemetry poller is scheduled for "
                em { "Phase H chunk 4" }
                " — it'll SSH " span.ed-mono { (server.address) }
                " every 5 min and persist disk/mem/load + listening-port observations. "
                "Until then this section reads as blank."
            }
        };
    };
    let sb = h
        .sing_box_active
        .map(|b| if b { "active" } else { "down" })
        .unwrap_or("?");
    let f2b = h
        .fail2ban_active
        .map(|b| if b { "active" } else { "down" })
        .unwrap_or("?");
    let disk_pct = h
        .disk_used_mib
        .zip(h.disk_total_mib)
        .filter(|(_, t)| *t > 0)
        .map(|(u, t)| format!("{}%", (u * 100 / t).min(100)))
        .unwrap_or("?".into());
    let mem_pct = h
        .mem_available_mib
        .zip(h.mem_total_mib)
        .filter(|(_, t)| *t > 0)
        .map(|(a, t)| format!("{}%", 100u64.saturating_sub(a * 100 / t)))
        .unwrap_or("?".into());
    let load = h
        .load_1min_x100
        .map(|l| format!("{:.2}", f64::from(l) / 100.0))
        .unwrap_or("?".into());
    let log_size = h
        .sing_box_log_bytes
        .map(humanize_bytes)
        .unwrap_or("?".into());

    let sb_color = match h.sing_box_active {
        Some(true) => "var(--soft)",
        Some(false) => "var(--acc)",
        None => "var(--mute)",
    };
    let f2b_color = match h.fail2ban_active {
        Some(true) => "var(--soft)",
        Some(false) => "var(--acc)",
        None => "var(--mute)",
    };
    let log_alert_color = match h.sing_box_log_bytes {
        Some(b) if b > 500 * 1024 * 1024 => "var(--acc)",
        _ => "var(--ink)",
    };

    html! {
        div.ed-rule {}
        div.ed-art-eyebrow { "Live status · last probe " span style="color: var(--mute);" {
            (h.ts.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        } }
        div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin: 12px 0 18px;" {
            (status_tile("sing-box", sb, sb_color))
            (status_tile("fail2ban", f2b, f2b_color))
            (status_tile("disk used", &disk_pct, "var(--ink)"))
            (status_tile("memory used", &mem_pct, "var(--ink)"))
            (status_tile("1-min load", &load, "var(--ink)"))
            (status_tile("sing-box log", &log_size, log_alert_color))
        }
    }
}

fn status_tile(label: &str, value: &str, value_color: &str) -> Markup {
    html! {
        div style="border: 1px solid var(--rule); padding: 10px 12px; background: var(--paper);" {
            div style="font-family: var(--mono); font-size: 10px; color: var(--mute); letter-spacing: 0.14em; text-transform: uppercase;" { (label) }
            div style=(format!("font-family: var(--serif); font-size: 22px; color: {value_color}; margin-top: 2px;")) { (value) }
        }
    }
}

/// Drift section — what does inventory THINK is listening vs what
/// IS listening. Orange highlights when sets disagree.
fn server_detail_drift_section(
    server: &vpnctl_core::Server,
    observed: &std::collections::BTreeSet<(String, u16)>,
    missing: &[(String, u16)],
    extra: &[(String, u16)],
    have_probe: bool,
) -> Markup {
    let declared: Vec<String> = server
        .enabled_protocols
        .iter()
        .map(|p| p.0.clone())
        .collect();
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow { "Declared vs observed" }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
            "Inventory says this server runs the protocols below; the latest probe sees the listening sockets on the right. Drift in orange."
        }
        div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px;" {
            div {
                div style="font-family: var(--mono); font-size: 10px; color: var(--mute); letter-spacing: 0.14em; text-transform: uppercase; margin-bottom: 4px;" {
                    "declared protocols"
                }
                @if declared.is_empty() {
                    p style="font-family: var(--serif); font-style: italic; color: var(--mute);" {
                        "(none in inventory)"
                    }
                } @else {
                    ul style="list-style: none; padding: 0; font-family: var(--mono); font-size: 12px;" {
                        @for p in &declared {
                            li style="padding: 2px 0;" { (p) }
                        }
                    }
                }
            }
            div {
                div style="font-family: var(--mono); font-size: 10px; color: var(--mute); letter-spacing: 0.14em; text-transform: uppercase; margin-bottom: 4px;" {
                    "observed listening sockets"
                }
                @if !have_probe {
                    p style="font-family: var(--serif); font-style: italic; color: var(--mute);" {
                        "(no probe — chunk 4 pending)"
                    }
                } @else if observed.is_empty() {
                    p style="font-family: var(--serif); font-style: italic; color: var(--mute);" {
                        "(probe ran but no sockets listed)"
                    }
                } @else {
                    ul style="list-style: none; padding: 0; font-family: var(--mono); font-size: 12px;" {
                        @for (proto, port) in observed {
                            li style="padding: 2px 0;" { (proto) "/" (port) }
                        }
                    }
                }
            }
        }
        @if have_probe && (!missing.is_empty() || !extra.is_empty()) {
            div style="margin-top: 14px; padding: 10px 12px; border: 1px solid var(--acc); background: var(--paper);" {
                div style="font-family: var(--mono); font-size: 10px; color: var(--acc); letter-spacing: 0.14em; text-transform: uppercase; margin-bottom: 6px;" {
                    "drift detected"
                }
                @if !missing.is_empty() {
                    p style="font-family: var(--serif); font-size: 13px; margin: 4px 0;" {
                        "Declared but " b { "NOT listening" } ": "
                        @for (i, (proto, port)) in missing.iter().enumerate() {
                            @if i > 0 { ", " }
                            span.ed-mono { (proto) "/" (port) }
                        }
                    }
                }
                @if !extra.is_empty() {
                    p style="font-family: var(--serif); font-size: 13px; margin: 4px 0;" {
                        "Listening but " b { "NOT declared" } ": "
                        @for (i, (proto, port)) in extra.iter().enumerate() {
                            @if i > 0 { ", " }
                            span.ed-mono { (proto) "/" (port) }
                        }
                    }
                }
            }
        } @else if have_probe {
            p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--soft); margin-top: 10px;" {
                "Declared and observed match. No drift."
            }
        }
    }
}
