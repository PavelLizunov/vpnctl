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

pub(crate) async fn monitoring(headers: HeaderMap) -> Markup {
    let (theme, accent, tw) = theme_accent(&headers);
    let body = section_placeholder_body("Monitoring");
    shell("monitoring", &theme, &accent, tw, body)
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
            "Read straight from the SQLite inventory. Add a server with "
            span.ed-mono { "vpnctl bootstrap" } " then "
            span.ed-mono { "vpnctl deploy" }
            " — the wizard UI is on the Phase D roadmap."
        }
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
        @if users_list.is_empty() {
            p style="font-family: var(--serif); font-style: italic; color: var(--mute); padding: 24px 0;" {
                "No users yet. Run "
                span.ed-mono { "vpnctl user create <id>" }
                " then "
                span.ed-mono { "vpnctl grant <user> <server>" }
                "."
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

        // Granted servers + per-(server, protocol) share-links.
        div.ed-rule {}
        div.ed-art-eyebrow { "Granted servers" }
        @if servers.is_empty() {
            p style="font-family: var(--serif); font-style: italic; color: var(--mute); padding: 12px 0;" {
                "No grants. Run "
                span.ed-mono { "vpnctl grant " (user.id.0) " <server-id>" }
                " from a server-detail page once those land."
            }
        } @else {
            ul style="list-style: none; padding: 0; font-family: var(--serif); font-size: 14px; line-height: 1.8;" {
                @for s in &servers {
                    li {
                        b { (s.id.0) }
                        " (" span.ed-mono { (s.address) ":" (s.ssh_port) } ", " (s.kernel.0) ")"
                    }
                }
            }
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
    };
    Ok(shell("users", &theme, &accent, tw, body))
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

pub(crate) async fn audit(headers: HeaderMap) -> Markup {
    let (theme, accent, tw) = theme_accent(&headers);
    let body = section_placeholder_body("Audit");
    shell("audit", &theme, &accent, tw, body)
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
