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
use crate::http_util::{form_field, path_segment_encode};
use vpnctl_core::humanize::format_size_bytes;

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
        key: "alerts",
        label: "Alerts",
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

/// Today's UTC date formatted for the masthead, matching the
/// editorial «— a daily report from your homelab» voice. Computed
/// per-render — caches would be more code than it's worth, and the
/// page is uncached anyway (every GET hits the admin handler).
fn masthead_date() -> String {
    chrono::Utc::now().format("%Y-%m-%d").to_string()
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
                // The volume number is always tinted with the active
                // accent. Used to be the (now-removed) floating Tweaks
                // panel that gave the accent toggle visible feedback
                // on every page; with the panel gone we need an
                // always-on accent hook in the chrome itself so
                // operators see their accent choice land.
                b style="color: var(--acc);" { (vol) }
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

/// Theme + accent picker, rendered INLINE inside the Settings page.
///
/// History: this used to be a `position: fixed` floating panel in the
/// bottom-right of every page (with open/closed cookie state). Pavel
/// 2026-05-17: «Tweaks правильнее держать в settings» — moved here.
/// Reasons it's better in Settings:
///
///   * theme/accent are one-time configuration — operator sets once
///     and forgets; chrome on every page was clutter,
///   * the floating panel overlapped share-link rows on the user-detail
///     page (Phase C-2 added a CSS hack pushing the footer right; not
///     a hack we needed long-term),
///   * Settings is where every other one-time knob lives (deploy
///     pubkey, retention TODO, etc).
///
/// The `/admin/tweak/{kind}` POST endpoints are unchanged so the
/// `sanitize_referer` redirect path still works — operator hits a
/// theme button on Settings, the POST handler reads Referer header,
/// sees `/admin/settings`, redirects back there.
fn tweaks_inline(theme: &str, accent: &str) -> Markup {
    html! {
        div style="display: flex; flex-direction: column; gap: 10px; padding: 12px 14px; border: 1px solid var(--rule); background: var(--paper); font-family: var(--mono); font-size: 11px; color: var(--soft); max-width: 480px;" {
            form method="post" action="/admin/tweak/theme" style="display: flex; gap: 6px; align-items: baseline;" {
                span style="width: 60px; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { "paper" }
                @for &name in VALID_THEMES {
                    button name="value" value=(name)
                           title=(format!("Switch paper theme to {name}"))
                           style=(format!(
                               "padding: 3px 9px; border: 1px solid var(--rule-s); background: {}; color: {}; font-family: var(--mono); font-size: 11px; cursor: pointer;",
                               if name == theme { "var(--ink)" } else { "transparent" },
                               if name == theme { "var(--paper)" } else { "var(--ink)" },
                           )) {
                        (name)
                    }
                }
            }
            form method="post" action="/admin/tweak/accent" style="display: flex; gap: 6px; align-items: baseline;" {
                span style="width: 60px; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { "accent" }
                @for &name in VALID_ACCENTS {
                    button name="value" value=(name)
                           title=(format!("Switch accent colour to {name}"))
                           style=(format!(
                               "padding: 3px 9px; border: 1px solid var(--rule-s); background: {}; color: {}; font-family: var(--mono); font-size: 11px; cursor: pointer;",
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

/// Build the page-root class string from theme + accent. Used to be
/// `(theme, accent, tweaks_open)` — the `ed-tweaks-open` modifier was
/// padding the footer right so the (then-floating) Tweaks panel
/// didn't overlap the github URL. With Tweaks moved into
/// /admin/settings the panel is gone, so the third arg disappeared
/// too. Kept the same arity expected by callers via a new param? No
/// — call sites updated to drop the arg directly.
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

/// Wraps a screen-specific body in the chrome (masthead + nav + main +
/// foot). `body` is the inner content of `<main class="ed-main">`.
///
/// `Markup` (a `PreEscaped<String>`) is owned and small; passing by value
/// is intentional and clippy's needless_pass_by_value is over-eager here.
///
/// Pre-2026-05-17 this also took a `tweaks_open: bool` for the floating
/// Tweaks panel state. Panel moved into /admin/settings; the arg is gone
/// along with the cookie + the `/admin/tweak/tweaks` route.
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
                    (masthead(&masthead_date(), &format!("vol. {}", env!("CARGO_PKG_VERSION"))))
                    (nav(active_nav))
                    main.ed-main {
                        (body)
                    }
                    (foot())
                }
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
/// Single accessor so handlers don't have to duplicate two cookie reads.
/// Pre-2026-05-17 this returned a third bool for the floating Tweaks
/// panel — gone with the panel.
fn theme_accent(headers: &HeaderMap) -> (String, String) {
    let theme = cookie(headers, COOKIE_THEME)
        .unwrap_or("default")
        .to_string();
    let accent = cookie(headers, COOKIE_ACCENT)
        .unwrap_or("default")
        .to_string();
    (theme, accent)
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
                            // Show key payload fields so the row tells
                            // the operator WHAT was enabled, granted,
                            // etc. Without this they had to crack
                            // `audit_log.payload` open by hand to
                            // disambiguate "server.protocol.enable
                            // stg" from "server.kernel.enable stg".
                            // (Caught 2026-05-16 by Pavel: «в дашборде
                            // логах не очень понятно что конкретно я
                            // включил».)
                            @if let Some(p) = &e.payload {
                                @let summary = summarize_audit_payload(p);
                                @if !summary.is_empty() {
                                    " · " span.ed-mono { (summary) }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Pull human-relevant fields out of an audit row's JSON payload
/// for the timeline display. Targets the high-frequency mutations
/// (protocol/kernel enable+disable, grant/revoke, regen, etc.) and
/// emits a compact `key=value` summary. Keys not in the explicit
/// allowlist are skipped (audit payloads sometimes include large
/// arrays we don't want to render inline). Returns empty string
/// when nothing useful surfaces — caller suppresses the separator.
///
/// **NEVER expose secrets** — the allowlist is positive (only the
/// names we explicitly want to render); raw token/password fields
/// stay invisible by default. Pinned by
/// `audit_summary_never_leaks_secret_fields`.
fn summarize_audit_payload(payload: &serde_json::Value) -> String {
    let Some(map) = payload.as_object() else {
        return String::new();
    };
    let mut parts: Vec<String> = Vec::new();
    // Whitelist of fields safe to render inline. Order = display order.
    // `protocol`, `kernel`, `user`, `from`, `wg_keypair_provenance`,
    // `new_pubkey`, `newly_added`, `was_present`, `address`,
    // `ssh_port`, `users` (count), `kernels_rendered`,
    // `config_bytes_total`, `protocols` (count).
    const SAFE_KEYS: &[&str] = &[
        "protocol",
        "kernel",
        "user",
        "from",
        "wg_keypair_provenance",
        "newly_added",
        "was_present",
        "address",
        "ssh_port",
    ];
    for k in SAFE_KEYS {
        if let Some(v) = map.get(*k) {
            // Render as plain string/number/bool — no nested objects
            // (those usually carry secrets). Lists too (could be long).
            let s = match v {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Number(n) => n.to_string(),
                serde_json::Value::Bool(b) => b.to_string(),
                _ => continue,
            };
            parts.push(format!("{k}={s}"));
        }
    }
    parts.join(" ")
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

    // Pavel iter D.6 — heavy-user heatmap. Surface the top-5
    // bandwidth-consuming users over the last 24h so the operator
    // can spot abuse-candidate accounts without drilling into each
    // user's page. Empty Vec → the section's empty-state already
    // explains why ("no live stats yet").
    let heavy_users = state
        .inv
        .top_users_by_traffic(24, 5)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(target = "vpnctld::admin", error = %e, "top_users_by_traffic failed");
            Vec::new()
        });
    // Pavel iter D.6c — limit alerts. Pre-filtered to users who
    // have crossed their configured threshold; sorted DESC by
    // percent-of-limit so the most-at-risk shows first.
    let limit_state = state
        .inv
        .users_traffic_vs_limit()
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(target = "vpnctld::admin", error = %e, "users_traffic_vs_limit failed");
            Vec::new()
        });
    let alerting: Vec<(vpnctl_core::UserId, u64, u64, u8)> = limit_state
        .into_iter()
        .filter(|(_, used, lim, threshold)| {
            *lim > 0 && ((*used as u128 * 100) / *lim as u128) >= u128::from(*threshold)
        })
        .collect();

    // Phase G — unacked infra alerts tile. Renders only when >0 so
    // the dashboard stays calm during quiet times. Counted off
    // `admin_alerts WHERE acked_at IS NULL` (single indexed SELECT).
    let unacked_alerts = state.inv.unacked_alert_count().await.unwrap_or_else(|e| {
        tracing::warn!(target = "vpnctld::admin", error = %e, "unacked_alert_count failed");
        0
    });

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
        (dashboard_alerts_tile(unacked_alerts))
        (dashboard_limit_alerts(&alerting))
        (dashboard_heavy_users(&heavy_users))
        (dashboard_audit(&audit))
    };
    Ok(shell("dashboard", &theme, &accent, body))
}

/// Phase G — single-line alerts tile under the metric row. Renders
/// only when there's at least one unacked alert; quiet dashboard stays
/// quiet. Links to `/admin/alerts` for the full feed.
fn dashboard_alerts_tile(unacked: u64) -> Markup {
    html! {
        @if unacked > 0 {
            div style="margin: 18px 0 0; padding: 14px 16px; border: 1px solid var(--rule); border-left: 3px solid var(--accent); background: var(--paper-tint);" {
                div.ed-art-eyebrow { "Homelab health" }
                p style="font-family: var(--serif); margin: 6px 0 0;" {
                    b { (unacked) }
                    @if unacked == 1 { " unacked alert" } @else { " unacked alerts" }
                    " · "
                    a href="/admin/alerts" style="color: var(--ink);" {
                        em { "see what the daemon's complaining about →" }
                    }
                }
            }
        }
    }
}

/// Render the "limit alerts" section on the dashboard. Shows only
/// users who have crossed their configured threshold (skipping the
/// section entirely when nobody is at risk — empty dashboard is
/// clean dashboard). Each row click-throughs to user-detail where
/// the operator can rotate keys / raise limit / dig in.
fn dashboard_limit_alerts(rows: &[(vpnctl_core::UserId, u64, u64, u8)]) -> Markup {
    if rows.is_empty() {
        // Clean — no one near limit, no UI clutter. Operator sees
        // this section only when something demands attention.
        return html! {};
    }
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow style="color: var(--acc);" {
            (rows.len()) " user"
            @if rows.len() != 1 { "s" }
            " near monthly limit"
        }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
            "These users have crossed their configured alert threshold "
            "(default " span.ed-mono { (DEFAULT_TRAFFIC_THRESHOLD_PCT) "%" } "). "
            "Click through to raise the cap or shape behaviour."
        }
        ul style="list-style: none; padding: 0; font-family: var(--mono); font-size: 12px; line-height: 1.8;" {
            @for (uid, used, lim, threshold) in rows {
                @let pct = ((*used as u128 * 100) / (*lim).max(1) as u128).min(999) as u32;
                @let over_limit = pct >= 100;
                li style="display: flex; align-items: baseline; gap: 12px; padding: 4px 0; border-bottom: 1px dotted var(--rule);" {
                    a href=(format!("/admin/users/{}", path_segment_encode(&uid.0)))
                      style="color: var(--ink); text-decoration: none; font-weight: 600; flex: 1;" {
                        (uid.0)
                    }
                    span style="color: var(--mute);" {
                        (fmt_traffic_progress(*used, *lim))
                    }
                    @if over_limit {
                        span style="font-family: var(--mono); font-size: 11px; color: var(--acc); font-weight: 600; margin-left: 8px;" {
                            "OVER"
                        }
                    } @else {
                        span style="font-family: var(--mono); font-size: 11px; color: var(--acc); margin-left: 8px;" {
                            "≥ " (threshold) "%"
                        }
                    }
                }
            }
        }
    }
}

/// Render the "heavy users · last 24h" section on the dashboard.
/// Sorted DESC by total bytes (upload + download). Empty list →
/// explanatory empty-state explaining the polling prerequisite.
fn dashboard_heavy_users(rows: &[(vpnctl_core::UserId, u64)]) -> Markup {
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow { "Heavy users · last 24h" }
        @if rows.is_empty() {
            p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
                "No per-user traffic recorded yet. The clash-api poller "
                "ticks every 5 minutes — once the daemon's SSH deploy key "
                "is in each node's "
                span.ed-mono { "~/.ssh/authorized_keys" }
                " (see "
                a href="/admin/settings" style="color: var(--ink);" { "Settings" }
                ") the section populates on the next tick."
            }
        } @else {
            p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
                "Top " (rows.len())
                " accounts by total (upload + download) over the last 24 hours. "
                "Click through to investigate; the user page has the full breakdown + sparkline."
            }
            ol style="list-style: decimal; padding-left: 24px; font-family: var(--mono); font-size: 12px; line-height: 1.8;" {
                @for (uid, total) in rows {
                    li style="padding: 4px 0; border-bottom: 1px dotted var(--rule);" {
                        a href=(format!("/admin/users/{}", path_segment_encode(&uid.0)))
                          style="color: var(--ink); text-decoration: none; font-weight: 600;" {
                            (uid.0)
                        }
                        span style="color: var(--mute); margin-left: 8px;" {
                            "— " (humanize_bytes(*total))
                        }
                    }
                }
            }
        }
    }
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
///
/// **Defensive normalisation:** literal `\n` and `\r` in `detail` are
/// collapsed to a single space so caller-controlled (Path<String> /
/// form-field) content can't inject an extra line into the response.
/// Every body still ends with exactly one trailing `\n` — the line
/// `vpnctl admin: <detail>\n` shape is what the layer-3 copy-contract
/// tests assert (`curl … | head -1` must capture the whole message).
/// Today every caller sanitises upstream (UserId / ServerId / form
/// validators reject `\n`), but the depth-in-defense keeps the
/// invariant local to this function.
pub(crate) fn error_text(detail: &str) -> String {
    let sanitised = detail.replace(['\n', '\r'], " ");
    format!("vpnctl admin: {sanitised}\n")
}

/// Phase F monitoring page. Pulls hourly + daily access buckets from
/// `sub_access_log`, gap-fills, renders two inline-SVG sparklines
/// (hits + distinct IPs) plus headline KPIs. No JS — pure SSR.
pub(crate) async fn monitoring(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<Markup, Response> {
    let (theme, accent) = theme_accent(&headers);

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
    Ok(shell("monitoring", &theme, &accent, body))
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
                    " · " span.ed-mono {
                        (s.kernels.iter().map(|k| k.0.clone()).collect::<Vec<_>>().join("+"))
                    }
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
            "Read straight from the SQLite inventory. Add a server through the "
            a href="/admin/servers/new" style="color: var(--ink); text-decoration: underline;" {
                "wizard"
            }
            " (paste IP + root password, the daemon does the rest), or use "
            span.ed-mono { "vpnctl bootstrap" } " then " span.ed-mono { "vpnctl deploy" }
            " from the CLI."
        }

        // Quick-add inline form — mirrors the users page one-input-
        // one-button shape. Server gets default kernel=sing-box +
        // ALL sing-box-supported protocols enabled; operator tweaks
        // on detail-page right after. The big "wizard" CTA below is
        // for the SSE-streamed bootstrap (Phase E in progress);
        // this inline path is for "I already have a deployed VPS,
        // just register it in inventory."
        div style="margin: 16px 0 16px; padding: 14px 16px; border: 1px solid var(--rule); background: var(--paper);" {
            form method="post" action="/admin/servers/quick-add"
                 style="display: flex; gap: 10px; align-items: baseline; flex-wrap: wrap;" {
                label style="font-family: var(--mono); font-size: 11px; color: var(--mute); letter-spacing: 0.14em; text-transform: uppercase;" {
                    "add server"
                }
                input type="text" name="id" required="required"
                      placeholder="e.g. fra-01"
                      pattern="[A-Za-z0-9._-]+"
                      title="Letters, digits, dot, underscore, hyphen — no spaces or slashes"
                      style="max-width: 160px; padding: 4px 8px; border: 1px solid var(--rule-s); background: var(--paper); font-family: var(--mono); font-size: 12px; color: var(--ink);";
                input type="text" name="address" required="required"
                      placeholder="ip or hostname"
                      style="max-width: 220px; padding: 4px 8px; border: 1px solid var(--rule-s); background: var(--paper); font-family: var(--mono); font-size: 12px; color: var(--ink);";
                input type="number" name="ssh_port" value="22" min="1" max="65535"
                      title="SSH port — 22 (DO) or 2222 (Cloudzy)"
                      style="max-width: 72px; padding: 4px 8px; border: 1px solid var(--rule-s); background: var(--paper); font-family: var(--mono); font-size: 12px; color: var(--ink);";
                button type="submit"
                       title="Registers the server with default kernels=sing-box + every sing-box-supported protocol enabled. Tweak everything on the detail page right after."
                       style="padding: 4px 12px; border: 1px solid var(--ink); background: var(--ink); color: var(--paper); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                    "register"
                }
                span style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); flex-basis: 100%;" {
                    "→ default kernels=sing-box, all kernel-supported protocols enabled. Tweak on the detail page."
                }
            }
        }

        // Phase E sub-iter 4a — wizard CTA. For fresh nodes that need
        // bootstrap (push our SSH key, install kernel, etc). Use the
        // quick-add above if you already have a working node.
        div style="margin: 0 0 24px;" {
            a href="/admin/servers/new"
              style="display: inline-block; padding: 6px 14px; border: 1px solid var(--ink); background: transparent; color: var(--ink); font-family: var(--mono); font-size: 11px; text-decoration: none;" {
                "wizard → bootstrap a fresh node from scratch"
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
    Ok(shell("servers", &theme, &accent, body))
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

// `path_segment_encode` moved to `crate::http_util::path_segment_encode`
// (2026-05-18, post-host-fingerprint consolidation pass) — same
// implementation was byte-identical in `daemon/src/wizard_bootstrap.rs`
// (the wizard's doc-comment explicitly admitted the duplication).
// Both surfaces now route through the shared helper.

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

/// Query params for the user list: search + sort. Both optional;
/// defaults preserve the historic alphabetic-by-id ordering.
/// Sort kinds: "id" (default), "id-desc", "servers" (most grants
/// first), "servers-desc" (least first). Search `q` is a case-
/// insensitive substring match on user.id.0 — no fancy fuzzy
/// matching, just enough to cut a 30+ user list down.
#[derive(serde::Deserialize, Default, Debug)]
pub(crate) struct UsersQuery {
    pub q: Option<String>,
    pub sort: Option<String>,
}

pub(crate) async fn users(
    headers: HeaderMap,
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<UsersQuery>,
) -> Result<Markup, Response> {
    let (theme, accent) = theme_accent(&headers);

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

    // Apply Pavel iter C2: search filter + sort. We build a sortable
    // (user, grants_count, original_index) tuple list so the row
    // numbering stays stable for the visible subset.
    let q_lower = query
        .q
        .as_deref()
        .map(|s| s.trim().to_ascii_lowercase())
        .unwrap_or_default();
    let mut pairs: Vec<(usize, &vpnctl_core::User, usize)> = users_list
        .iter()
        .zip(grants_per_user.iter().copied())
        .enumerate()
        .map(|(i, (u, g))| (i, u, g))
        .filter(|(_, u, _)| {
            q_lower.is_empty() || u.id.0.to_ascii_lowercase().contains(q_lower.as_str())
        })
        .collect();
    let sort_kind = query.sort.as_deref().unwrap_or("id");
    match sort_kind {
        "id-desc" => pairs.sort_by(|a, b| b.1.id.0.cmp(&a.1.id.0)),
        "servers" => pairs.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| a.1.id.0.cmp(&b.1.id.0))),
        "servers-desc" => pairs.sort_by(|a, b| a.2.cmp(&b.2).then_with(|| a.1.id.0.cmp(&b.1.id.0))),
        _ => pairs.sort_by(|a, b| a.1.id.0.cmp(&b.1.id.0)), // "id" default
    }
    // Helper to build a sort link that preserves the search.
    let make_sort_href = |kind: &str| -> String {
        if q_lower.is_empty() {
            format!("/admin/users?sort={kind}")
        } else {
            format!(
                "/admin/users?sort={kind}&q={}",
                path_segment_encode(&q_lower)
            )
        }
    };
    let total_users = users_list.len();
    let visible_users = pairs.len();

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
        // readable id. **All secrets — UUID, tuic_password, sub_token,
        // AND the WireGuard keypair — are generated unconditionally**
        // (per CLAUDE.md "users are assumed maximally low-tech" one-
        // action ceiling: creation = type id + Enter, no checkboxes
        // for the operator either). Per-key management (rotate WG,
        // replace with operator-provided pubkey, etc.) lives on the
        // user-detail page.
        div style="margin: 16px 0 28px; padding: 14px 16px; border: 1px solid var(--rule); background: var(--paper);" {
            form method="post" action="/admin/users"
                 style="display: flex; gap: 10px; align-items: baseline;" {
                label style="font-family: var(--mono); font-size: 11px; color: var(--mute); letter-spacing: 0.14em; text-transform: uppercase;" {
                    "add user"
                }
                input type="text" name="id" required="required"
                      placeholder="alice"
                      pattern="[A-Za-z0-9._-]+"
                      title="Letters, digits, dot, underscore, hyphen — no spaces or slashes"
                      style="flex: 1; max-width: 280px; padding: 4px 8px; border: 1px solid var(--rule-s); background: var(--paper); font-family: var(--mono); font-size: 12px; color: var(--ink);";
                button type="submit"
                       title="Mint UUID + tuic_password + sub_token + WG keypair; redirect to /admin/users/<id> where keys are visible"
                       style="padding: 4px 12px; border: 1px solid var(--ink); background: var(--ink); color: var(--paper); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                    "create"
                }
                span style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute);" {
                    "→ all keys are auto-generated and shown on the user page"
                }
            }
        }

        // Pavel iter C2: search + sort. Search is a GET form so the
        // resulting URL is shareable / bookmarkable. Sort links live
        // next to the search and pin the current direction.
        @if !users_list.is_empty() {
            div style="display: flex; gap: 16px; align-items: baseline; flex-wrap: wrap; margin: 0 0 14px;" {
                form method="get" action="/admin/users"
                     style="display: flex; gap: 6px; align-items: baseline;" {
                    label style="font-family: var(--mono); font-size: 11px; color: var(--mute); letter-spacing: 0.14em; text-transform: uppercase;" {
                        "search"
                    }
                    input type="text" name="q" value=(q_lower)
                          placeholder="user id substring"
                          style="max-width: 200px; padding: 3px 8px; border: 1px solid var(--rule-s); background: var(--paper); font-family: var(--mono); font-size: 12px; color: var(--ink);";
                    @if !sort_kind.is_empty() && sort_kind != "id" {
                        input type="hidden" name="sort" value=(sort_kind);
                    }
                    button type="submit"
                           style="padding: 3px 10px; border: 1px solid var(--ink); background: transparent; font-family: var(--mono); font-size: 11px; color: var(--ink); cursor: pointer;" {
                        "go"
                    }
                    @if !q_lower.is_empty() {
                        a href=(make_sort_href(sort_kind))
                          style="font-family: var(--mono); font-size: 11px; color: var(--mute); margin-left: 4px;" {
                            "× clear"
                        }
                    }
                }
                div style="font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                    "sort: "
                    @let sort_link = |kind: &str, label: &str| -> Markup {
                        let active = sort_kind == kind;
                        html! {
                            a href=(make_sort_href(kind))
                              style=(if active { "color: var(--ink); text-decoration: underline; margin-right: 8px;" } else { "color: var(--mute); margin-right: 8px;" }) {
                                (label)
                            }
                        }
                    };
                    (sort_link("id", "id ↑"))
                    (sort_link("id-desc", "id ↓"))
                    (sort_link("servers", "servers ↓"))
                    (sort_link("servers-desc", "servers ↑"))
                }
                @if visible_users != total_users {
                    span style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute);" {
                        "showing " (visible_users) " of " (total_users)
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
        } @else if pairs.is_empty() {
            p style="font-family: var(--serif); font-style: italic; color: var(--mute); padding: 12px 0;" {
                "No users match "
                span.ed-mono { "q=" (q_lower) }
                ". Loosen the search above or "
                a href="/admin/users" style="color: var(--ink);" { "clear it" }
                "."
            }
        } @else {
            div {
                @for (display_idx, (_orig_idx, u, g)) in pairs.iter().enumerate() {
                    (user_row(display_idx, u, *g))
                }
            }
        }
    };
    Ok(shell("users", &theme, &accent, body))
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
/// Symmetric share-link card used by both Flow A (sing-box subscription
/// URL) and Flow B (WG-native wireguard:// link) on the user-detail page.
///
/// Layout: QR on the left, masked one-liner preview + read-only textarea
/// (click → select-all, plus triple-click as a JS-free fallback) +
/// italic footnote on the right. Same DOM shape for both flows so the
/// operator never has to switch mental models between "Hiddify column"
/// and "AmneziaVPN column" — the difference is only what bytes go into
/// QR + textarea.
///
/// **Single `link` parameter** (was `(qr_url, full_link)` until
/// review-agent 2026-05-17): the QR encoding and the copy text MUST
/// be the same bytes — otherwise the recipient scans one URL and the
/// operator hand-copies another, and a low-tech recipient («ctrl+c
/// уже много», CLAUDE.md) won't notice. Collapsing to one arg makes
/// the mismatch unrepresentable at the type level.
///
/// The textarea uses `onclick="this.select()"` so a single click selects
/// the full link. Avoids the Clipboard API which requires a secure
/// context (HTTPS or localhost) — the admin UI runs over plain HTTP on
/// the homelab LAN, so navigator.clipboard would silently fail on
/// 192.168.0.236. Triple-click is the JS-free fallback every browser
/// supports; the `title` attribute spells out both interactions.
fn share_link_card(link: &str, footnote: &Markup) -> Markup {
    html! {
        div style="display: flex; gap: 14px; align-items: flex-start; margin-bottom: 14px;" {
            (qr_svg(link))
            div style="flex: 1; display: flex; flex-direction: column; gap: 6px; min-width: 0;" {
                div style="font-family: var(--mono); font-size: 11px; color: var(--soft); word-break: break-all;" {
                    (mask_secret(link))
                }
                textarea readonly="readonly" rows="3"
                         onclick="this.select()"
                         title="Click to select the full link (or triple-click if JS is disabled), then Ctrl+C / Cmd+C to copy"
                         style="width: 100%; padding: 8px 10px; font-family: var(--mono); font-size: 10.5px; line-height: 1.45; color: var(--ink); background: var(--paper); border: 1px solid var(--rule); resize: vertical; word-break: break-all; box-sizing: border-box;" {
                    (link)
                }
                div style="font-family: var(--serif); font-style: italic; color: var(--mute); font-size: 12px; line-height: 1.5;" {
                    (footnote)
                }
            }
        }
    }
}

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
/// Sibling of `collect_share_links` — one `vpn://` deep link per
/// granted server that declares the `wireguard` protocol. Used by the
/// user-detail page's Flow C card (AmneziaVPN).
///
/// Errors from `amnezia_share_link` (missing user pubkey, missing
/// server private key, malformed pubkey) are LOGGED-AND-SKIPPED — the
/// page still renders. The empty-state classifier in the Flow C card
/// distinguishes "no grants" from "no WG-capable server" from "render
/// failed" using the same `wg_capable_granted` tally as Flow B.
fn collect_amnezia_links(
    user: &vpnctl_core::User,
    servers: &[vpnctl_core::Server],
    secrets_per_server: &std::collections::HashMap<
        vpnctl_core::ServerId,
        std::collections::HashMap<String, String>,
    >,
    peers_per_server: &std::collections::HashMap<vpnctl_core::ServerId, Vec<vpnctl_core::User>>,
) -> Vec<(vpnctl_core::ServerId, String)> {
    let mut out = Vec::new();
    for server in servers {
        if !server.enabled_protocols.iter().any(|p| p.0 == "wireguard") {
            continue;
        }
        let Some(secrets) = secrets_per_server.get(&server.id) else {
            tracing::warn!(target = "vpnctld::admin", server = %server.id, "secrets missing for granted WG server (amnezia link)");
            continue;
        };
        let peers: &[vpnctl_core::User] = peers_per_server
            .get(&server.id)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let ctx = vpnctl_core::RenderCtx::with_peers(server, secrets, peers);
        match vpnctl_protocols::amnezia_share_link(&ctx, user) {
            Ok(link) => out.push((server.id.clone(), link)),
            Err(e) => {
                tracing::warn!(
                    target = "vpnctld::admin",
                    server = %server.id,
                    user = %user.id,
                    error = %e,
                    "amnezia_share_link failed, skipping Flow C entry"
                );
            }
        }
    }
    out
}

fn collect_share_links(
    state: &AppState,
    user: &vpnctl_core::User,
    servers: &[vpnctl_core::Server],
    secrets_per_server: &std::collections::HashMap<
        vpnctl_core::ServerId,
        std::collections::HashMap<String, String>,
    >,
    peers_per_server: &std::collections::HashMap<vpnctl_core::ServerId, Vec<vpnctl_core::User>>,
) -> Vec<(vpnctl_core::ServerId, vpnctl_core::ProtocolId, String)> {
    let mut out = Vec::new();
    for server in servers {
        let Some(secrets) = secrets_per_server.get(&server.id) else {
            tracing::warn!(target = "vpnctld::admin", server = %server.id, "secrets missing for granted server");
            continue;
        };
        let peers: &[vpnctl_core::User] = peers_per_server
            .get(&server.id)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let ctx = vpnctl_core::RenderCtx::with_peers(server, secrets, peers);
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
    let (theme, accent) = theme_accent(&headers);
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

    // Pre-fetch secrets + the granted-users list for every granted
    // server. The users list goes into the RenderCtx so WireGuard's
    // per-user `/32` octet matches the server's `[Peer]` block 1:1
    // (review-agent 2026-05-17 caught a hard-coded `10.66.0.2` that
    // collided across multiple WG users on the same server).
    let mut secrets_per_server = std::collections::HashMap::new();
    let mut peers_per_server = std::collections::HashMap::new();
    for s in &servers {
        let secrets = state
            .inv
            .list_server_secrets(&s.id)
            .await
            .map_err(|e| internal_error(anyhow::Error::new(e)))?;
        secrets_per_server.insert(s.id.clone(), secrets);
        let peers = state
            .inv
            .users_for_server(&s.id)
            .await
            .map_err(|e| internal_error(anyhow::Error::new(e)))?;
        peers_per_server.insert(s.id.clone(), peers);
    }

    let share_links = collect_share_links(
        &state,
        &user,
        &servers,
        &secrets_per_server,
        &peers_per_server,
    );
    // Flow C — AmneziaVPN-native deep-links (vpn://...). Built
    // separately because the format isn't `Protocol::share_link()`
    // semantics — it's an AmneziaVPN-app-specific wrapper around the
    // same WG secret material. `collect_amnezia_links` returns one
    // (server_id, vpn://...) per WG-enabled granted server.
    let amnezia_links =
        collect_amnezia_links(&user, &servers, &secrets_per_server, &peers_per_server);
    let sub_token = user.sub_token.clone();
    let sub_url_str = sub_token.as_deref().map(|t| sub_url(&headers, t));

    // WireGuard "Flow B" diagnostics — without these the empty-state
    // copy can't tell the operator WHY no WG link rendered. Three
    // distinct cases, each with a different action:
    //   * No grants at all → "grant a server with WG"
    //   * Grants exist, none declares wireguard → name them, say
    //     "enable wireguard in <server>.enabled_protocols OR grant
    //      a different server that runs WG"
    //   * Some granted server DOES declare WG but share_link failed
    //     → fall through to the existing "missing secret / unregistered
    //       protocol" guidance with a journalctl pointer.
    // Servers granted to this user whose enabled_protocols list
    // contains "wireguard". Used by the empty-state classifier.
    let wg_capable_granted: Vec<&vpnctl_core::ServerId> = servers
        .iter()
        .filter(|s| s.enabled_protocols.iter().any(|p| p.0 == "wireguard"))
        .map(|s| &s.id)
        .collect();
    // Servers in the WHOLE inventory (not just granted) that DO
    // declare wireguard — useful as a name-drop when no granted
    // server runs WG. Cheap O(servers * protocols) scan; servers
    // list is already loaded.
    let wg_capable_inventory: Vec<&vpnctl_core::ServerId> = all_servers
        .iter()
        .filter(|s| s.enabled_protocols.iter().any(|p| p.0 == "wireguard"))
        .map(|s| &s.id)
        .collect();

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

        // WireGuard / AmneziaWG key material + distribution. Always
        // shows the pubkey verbatim (it's public). Private key marker
        // only — actual value flows through `/sub/<token>` (sing-box-
        // style clients) AND as inline QR/share-links below for
        // WG-native clients (AmneziaVPN, official WireGuard app).
        // Per CLAUDE.md "users are low-tech" — the operator must see
        // every artefact needed to onboard the user in one place.
        div.ed-rule {}
        div.ed-art-eyebrow { "WireGuard keypair" }
        @match (&user.wireguard_pubkey, &user.wireguard_private) {
            (Some(pub_b64), Some(_priv_marker)) => {
                div style="padding: 12px 0;" {
                    div style="font-family: var(--mono); font-size: 12px; line-height: 1.7;" {
                        div { span style="color: var(--mute);" { "pubkey  " } (pub_b64) }
                        div {
                            span style="color: var(--mute);" { "private " }
                            span.ed-mono style="color: var(--acc);" { "✓ stored — served via /sub/<token> only" }
                        }
                    }
                    p style="font-family: var(--serif); font-style: italic; color: var(--soft); font-size: 12px; margin-top: 8px;" {
                        "Both halves were generated when the user was created. Pick the distribution flow matching the user's client app:"
                    }
                    form method="post"
                         action=(format!("/admin/users/{}/wireguard/regenerate", path_segment_encode(&user.id.0)))
                         style="margin-top: 12px;" {
                        button type="submit"
                               title="Mint a fresh Curve25519 pair. The previous keys stop working — every device using the old config must re-import."
                               style="padding: 4px 10px; border: 1px solid var(--ink); background: transparent; font-family: var(--mono); font-size: 11px; color: var(--ink); cursor: pointer;" {
                            "rotate WG keypair"
                        }
                    }

                    // Three-column distribution panel — one column per
                    // client app. Same secret material, three wire
                    // formats:
                    //   * Flow A — sing-box JSON via /sub/<token> URL
                    //   * Flow B — wireguard:// (official WG app, Hiddify)
                    //   * Flow C — vpn://    (AmneziaVPN)
                    //
                    // Plus a .conf-file download per WG-capable server
                    // as a universal fallback (drag-drop into ANY WG
                    // client incl AmneziaVPN's "File with settings"
                    // button).
                    //
                    // Pre-2026-05-17 (commit `799e28b`) Flow B claimed
                    // to cover BOTH AmneziaVPN and the WG app, but the
                    // `wireguard://?conf=` format AmneziaVPN rejects
                    // with ErrorCode 900 («нет контейнеров») — Amnezia
                    // expects its own `vpn://<base64(qCompress(json))>`
                    // deep-link. Split into B + C; honest labels.
                    div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 20px; margin-top: 24px; padding-top: 16px; border-top: 1px dotted var(--rule);" {
                        // Flow A — sing-box / Hiddify subscription URL.
                        // The QR renders the same sub_url shown in the
                        // Subscription block at the top of the page;
                        // duplicated here on purpose so the operator
                        // copies the WG-via-Hiddify link from the same
                        // distribution panel as the WG-native link.
                        div {
                            div style="font-family: var(--mono); font-size: 11px; color: var(--mute); letter-spacing: 0.14em; text-transform: uppercase; margin-bottom: 8px;" {
                                "Flow A — Hiddify / Sing-box"
                            }
                            @match (&sub_token, &sub_url_str) {
                                (Some(_), Some(url)) => {
                                    (share_link_card(url, &html! {
                                        "Sing-box / Hiddify pulls the full config (every protocol on every granted server, including WireGuard with the private key embedded) and refreshes on its own schedule. "
                                        b { "Recommended default — one URL covers everything." }
                                    }))
                                }
                                _ => {
                                    p style="font-family: var(--serif); font-style: italic; color: var(--mute); font-size: 12px; margin: 0;" {
                                        "Mint a sub-token in the "
                                        b { "Subscription" }
                                        " block above to populate this card."
                                    }
                                }
                            }
                        }
                        // Flow B — official WireGuard app + Hiddify.
                        // The `wireguard://?conf=<base64>` link works
                        // in the official WG mobile/desktop apps and
                        // in Hiddify, NOT in AmneziaVPN (separate Flow
                        // C below covers that).
                        div {
                            div style="font-family: var(--mono); font-size: 11px; color: var(--mute); letter-spacing: 0.14em; text-transform: uppercase; margin-bottom: 8px;" {
                                "Flow B — official WireGuard app / Hiddify"
                            }
                            @let wg_links: Vec<_> = share_links
                                .iter()
                                .filter(|(_, pid, _)| pid.0 == "wireguard")
                                .collect();
                            @if wg_links.is_empty() {
                                // Three-way classifier so the operator's
                                // next action is unambiguous.
                                @if servers.is_empty() {
                                    // Case A — user has zero grants.
                                    p style="font-family: var(--serif); font-style: italic; color: var(--mute); font-size: 12px; margin: 0;" {
                                        "No servers granted to this user yet. Grant a server in the "
                                        b { "Server access" }
                                        " section below — if it runs WireGuard, the QR appears here."
                                    }
                                } @else if wg_capable_granted.is_empty() {
                                    // Case B — granted servers exist but
                                    // NONE declare wireguard. Most
                                    // common case for bash-imported
                                    // users (vps-is-01 et al. run
                                    // VLESS/TUIC/Hy2, not WG).
                                    p style="font-family: var(--serif); font-size: 12px; line-height: 1.55; color: var(--ink); margin: 0 0 8px;" {
                                        b { "Keys exist, but no granted server runs WireGuard." }
                                        " The user has a WG keypair (see pubkey above), so the moment a WG-capable server is granted — or "
                                        span.ed-mono { "wireguard" }
                                        " is added to an existing server's "
                                        span.ed-mono { "enabled_protocols" }
                                        " — the QR will appear here."
                                    }
                                    p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 0 0 6px;" {
                                        "Currently granted: "
                                        @for (i, s) in servers.iter().enumerate() {
                                            @if i > 0 { ", " }
                                            span.ed-mono { (s.id.0) }
                                        }
                                        " — none have "
                                        span.ed-mono { "wireguard" }
                                        " in their protocol list."
                                    }
                                    @if !wg_capable_inventory.is_empty() {
                                        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 0;" {
                                            "WG-capable servers in the inventory you could grant: "
                                            @for (i, sid) in wg_capable_inventory.iter().enumerate() {
                                                @if i > 0 { ", " }
                                                span.ed-mono { (sid.0) }
                                            }
                                            "."
                                        }
                                    } @else {
                                        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 0;" {
                                            "No WG-capable server in the entire inventory. The "
                                            span.ed-mono { "amneziawg" }
                                            " kernel + "
                                            span.ed-mono { "wireguard" }
                                            " protocol need to be enabled on a node first (CLI: "
                                            span.ed-mono { "vpnctl server add … --protocols vless+reality,wireguard --kernel amneziawg" }
                                            ")."
                                        }
                                    }
                                } @else {
                                    // Case C — at least one granted
                                    // server DOES declare wireguard but
                                    // share_link failed (most likely:
                                    // missing wireguard.server_public_key
                                    // secret). Existing journalctl
                                    // pointer remains the right action.
                                    p style="font-family: var(--serif); font-style: italic; color: var(--mute); font-size: 12px; margin: 0;" {
                                        "Granted servers "
                                        @for (i, sid) in wg_capable_granted.iter().enumerate() {
                                            @if i > 0 { ", " }
                                            span.ed-mono { (sid.0) }
                                        }
                                        " declare wireguard but the share-link render failed. Likely missing "
                                        span.ed-mono { "wireguard.server_public_key" }
                                        " / "
                                        span.ed-mono { "wireguard.server_private_key" }
                                        " server secret — check "
                                        span.ed-mono { "journalctl -u vpnctld" }
                                        "."
                                    }
                                }
                            } @else {
                                @for (sid, _pid, link) in &wg_links {
                                    div style="margin-bottom: 18px;" {
                                        div style="font-family: var(--mono); font-size: 11px; color: var(--mute); margin-bottom: 6px;" {
                                            "server " (sid.0)
                                            " · "
                                            a href=(format!("/admin/users/{}/wireguard/conf/{}",
                                                            path_segment_encode(&user.id.0),
                                                            path_segment_encode(&sid.0)))
                                              download=(format!("{}-{}.conf", user.id.0, sid.0))
                                              style="color: var(--mute); text-decoration: underline;" {
                                                ".conf"
                                            }
                                        }
                                        (share_link_card(link, &html! {
                                            "Opens in the official WireGuard app (mobile + desktop) and Hiddify. Link is " (link.len()) " chars (the private key is base64-embedded inside). Click the box above to select-all + copy."
                                        }))
                                    }
                                }
                            }
                        }
                        // Flow C — AmneziaVPN-native deep link.
                        // Same secret material as Flow B but wrapped
                        // in AmneziaVPN's `vpn://<base64(qCompress(json))>`
                        // container format. Without this card,
                        // AmneziaVPN rejects the Flow B link with
                        // ErrorCode 900 («нет контейнеров»).
                        div {
                            div style="font-family: var(--mono); font-size: 11px; color: var(--mute); letter-spacing: 0.14em; text-transform: uppercase; margin-bottom: 8px;" {
                                "Flow C — AmneziaVPN"
                            }
                            @let amnezia_links: Vec<_> = amnezia_links
                                .iter()
                                .collect();
                            @if amnezia_links.is_empty() {
                                // Same empty-state classifier as Flow B.
                                @if servers.is_empty() {
                                    p style="font-family: var(--serif); font-style: italic; color: var(--mute); font-size: 12px; margin: 0;" {
                                        "Grant a WireGuard-capable server to populate this card."
                                    }
                                } @else if wg_capable_granted.is_empty() {
                                    p style="font-family: var(--serif); font-style: italic; color: var(--mute); font-size: 12px; margin: 0;" {
                                        "No granted server runs WireGuard yet — add "
                                        span.ed-mono { "wireguard" }
                                        " to an existing server's protocols on its detail page."
                                    }
                                } @else {
                                    p style="font-family: var(--serif); font-style: italic; color: var(--mute); font-size: 12px; margin: 0;" {
                                        "Granted WG servers "
                                        @for (i, sid) in wg_capable_granted.iter().enumerate() {
                                            @if i > 0 { ", " }
                                            span.ed-mono { (sid.0) }
                                        }
                                        " — but AmneziaVPN link rendering failed (check "
                                        span.ed-mono { "journalctl -u vpnctld" }
                                        ")."
                                    }
                                }
                            } @else {
                                @for (sid, link) in &amnezia_links {
                                    div style="margin-bottom: 18px;" {
                                        div style="font-family: var(--mono); font-size: 11px; color: var(--mute); margin-bottom: 6px;" {
                                            "server " (sid.0)
                                        }
                                        (share_link_card(link, &html! {
                                            "QR / paste opens in AmneziaVPN; the deep link is " (link.len()) " chars (zlib-compressed JSON-container inside). The same "
                                            span.ed-mono { ".conf" }
                                            " file under Flow B also imports via AmneziaVPN's "
                                            em { "File with settings" }
                                            " button as a fallback."
                                        }))
                                    }
                                }
                            }
                        }
                    }
                }
            }
            (Some(pub_b64), None) => {
                // Operator-paranoid path (CLI `--wireguard-pubkey`): only
                // pubkey present, private stays on the user device. No
                // rotate button — that'd overwrite the user's privkey
                // pairing. Operator can `vpnctl user remove` + `add`
                // to switch flows.
                div style="padding: 12px 0;" {
                    div style="font-family: var(--mono); font-size: 12px; line-height: 1.7;" {
                        div { span style="color: var(--mute);" { "pubkey  " } (pub_b64) }
                        div {
                            span style="color: var(--mute);" { "private " }
                            span.ed-mono style="color: var(--mute);" { "on user device (operator-paranoid path)" }
                        }
                    }
                }
            }
            (None, _) => {
                // Should be impossible for users created via the web
                // form (always auto-gens both). Falls through for
                // legacy users imported pre-2026-05-16 — show a
                // self-heal button.
                div style="padding: 12px 0;" {
                    p style="font-family: var(--serif); font-style: italic; color: var(--mute);" {
                        "No WireGuard keypair on this user. Imported from the legacy bash project, or created before the auto-gen default."
                    }
                    form method="post"
                         action=(format!("/admin/users/{}/wireguard/regenerate", path_segment_encode(&user.id.0)))
                         style="margin-top: 8px;" {
                        button type="submit"
                               style="padding: 4px 10px; border: 1px solid var(--ink); background: transparent; font-family: var(--mono); font-size: 11px; color: var(--ink); cursor: pointer;" {
                            "generate WG keypair"
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
                            " (" span.ed-mono { (s.address) ":" (s.ssh_port) } ", "
                            (s.kernels.iter().map(|k| k.0.clone()).collect::<Vec<_>>().join("+"))
                            ")"
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

        // ── Traffic limit + alert threshold (Pavel D.6c) ──────────
        // Show current month-to-date usage + the configured cap
        // (if any) + an inline form to change both. Re-runs the
        // usage query so the page-after-redirect immediately
        // reflects new limits.
        (user_traffic_limit_section(&state, &uid).await)

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
    Ok(shell("users", &theme, &accent, body))
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
/// Hourly upload+download sparkline over the last 24h. Renders as
/// inline SVG — paired bars (download = solid accent, upload = thin
/// ink) per hour-bucket, latest hour on the right. No JS, no
/// external refs, fits in ~140 chars of computed paint.
///
/// Empty hours (no traffic seen) render as blank cells so the
/// operator sees a true "quiet stretch" instead of a misleading
/// linear interpolation.
///
/// Returns empty Markup if the input is empty — caller already
/// has a "no live stats yet" empty-state above.
fn vpn_sparkline_24h(rows: &[vpnctl_inventory::VpnStatsRow]) -> Markup {
    use chrono::{DurationRound, TimeDelta, Utc};
    if rows.is_empty() {
        return html! {};
    }
    // Bucket by hour-of-day. Key = (day-of-month, hour) so two
    // 17:00 buckets on different days don't collapse. Anchor the
    // last bucket on the current hour so the rightmost bar is
    // "right now."
    let now = Utc::now().duration_trunc(TimeDelta::hours(1)).ok();
    let Some(now_h) = now else {
        return html! {};
    };
    // 24 cells: index 0 = 23h ago, index 23 = current hour.
    let mut up_per_hour: [u64; 24] = [0; 24];
    let mut dn_per_hour: [u64; 24] = [0; 24];
    for r in rows {
        let row_h = match r.ts.duration_trunc(TimeDelta::hours(1)) {
            Ok(t) => t,
            Err(_) => continue,
        };
        // Hours-ago, clamped to the 24-cell window.
        let diff = now_h.signed_duration_since(row_h);
        let hours_ago = diff.num_hours();
        if !(0..24).contains(&hours_ago) {
            continue;
        }
        let idx = (23 - hours_ago) as usize;
        up_per_hour[idx] = up_per_hour[idx].saturating_add(r.upload_bytes);
        dn_per_hour[idx] = dn_per_hour[idx].saturating_add(r.download_bytes);
    }
    // Max-axis = max of (up+dn) across all 24 cells; bars scale to
    // 32 px max height. Zero-max corner case: render empty cells.
    let max_total = up_per_hour
        .iter()
        .zip(dn_per_hour.iter())
        .map(|(u, d)| u.saturating_add(*d))
        .max()
        .unwrap_or(0);
    let cell_w: u32 = 14;
    let cell_gap: u32 = 2;
    let max_h: u32 = 32;
    let width = 24 * (cell_w + cell_gap);
    let height = max_h + 4;
    let bar = |idx: usize, base: u64, color: &str, y_offset: f64| -> String {
        if max_total == 0 || base == 0 {
            return String::new();
        }
        // Bar height as fraction of max, min 1px so a tiny value
        // is still visible.
        let h_px = ((base as f64 / max_total as f64) * (max_h as f64)).max(1.0);
        let x = (idx as u32) * (cell_w + cell_gap);
        let y = max_h as f64 - h_px - y_offset;
        format!(r#"<rect x="{x}" y="{y:.1}" width="{cell_w}" height="{h_px:.1}" fill="{color}"/>"#,)
    };
    let mut svg_inner = String::new();
    for i in 0..24 {
        let up = up_per_hour[i];
        let dn = dn_per_hour[i];
        // Stack download on top of upload — total bar fills the same
        // proportion either way; download usually dominates, so it's
        // the visually-driving slab.
        let up_h = if max_total == 0 {
            0.0
        } else {
            (up as f64 / max_total as f64) * (max_h as f64)
        };
        svg_inner.push_str(&bar(i, up, "var(--soft)", 0.0));
        svg_inner.push_str(&bar(i, dn, "var(--acc)", up_h));
    }
    let svg = format!(
        r#"<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" aria-label="24-hour upload+download sparkline" style="display: block;">{svg_inner}</svg>"#,
    );
    html! {
        div style="margin: 16px 0; padding: 10px 12px; background: var(--paper); border: 1px solid var(--rule);" {
            div style="font-family: var(--mono); font-size: 10px; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; margin-bottom: 6px; display: flex; justify-content: space-between; align-items: baseline;" {
                span { "24h sparkline · download " span style="display: inline-block; width: 8px; height: 8px; background: var(--acc); vertical-align: middle;" {} " · upload " span style="display: inline-block; width: 8px; height: 8px; background: var(--soft); vertical-align: middle;" {} }
                span { "max " (humanize_bytes(max_total)) " / hour" }
            }
            (maud::PreEscaped(svg))
            div style="font-family: var(--mono); font-size: 9px; color: var(--mute); display: flex; justify-content: space-between; margin-top: 4px;" {
                span { "-23h" }
                span { "now" }
            }
        }
    }
}

/// Daemon-wide default threshold when a user has none set. 80% is
/// the magic number — operators historically miss the limit when
/// alerts only fire at 100% (by then the user is already over).
/// Picked once here so changing it later is one constant edit.
pub(crate) const DEFAULT_TRAFFIC_THRESHOLD_PCT: u8 = 80;

/// Format bytes as `1.2 GiB / 5 GiB (24%)` — used in the usage
/// progress bar copy.
fn fmt_traffic_progress(used: u64, limit: u64) -> String {
    let pct = if limit == 0 {
        0
    } else {
        ((used as u128 * 100) / limit as u128).min(999) as u32
    };
    format!(
        "{used} / {limit} ({pct}%)",
        used = humanize_bytes(used),
        limit = humanize_bytes(limit),
    )
}

/// Per-user traffic-limit section on the user-detail page. Shows
/// the month-to-date total + the configured limit (if any) + an
/// inline form to change both. Operator can set a cap even when
/// no traffic has accrued yet — alerts fire only after the limit
/// is crossed.
async fn user_traffic_limit_section(state: &AppState, uid: &vpnctl_core::UserId) -> Markup {
    let used = state
        .inv
        .user_traffic_this_month(uid)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(target = "vpnctld::admin", user = %uid, error = %e, "user_traffic_this_month failed");
            0
        });
    let (limit_opt, threshold_opt) = state
        .inv
        .get_user_traffic_limit(uid)
        .await
        .unwrap_or((None, None));
    let threshold_eff = threshold_opt.unwrap_or(DEFAULT_TRAFFIC_THRESHOLD_PCT);
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow { "Traffic limit · month-to-date" }
        @match limit_opt {
            Some(lim) if lim > 0 => {
                @let pct = ((used as u128 * 100) / lim as u128).min(999) as u32;
                @let over_threshold = pct >= u32::from(threshold_eff);
                @let over_limit = pct >= 100;
                p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
                    "Total upload + download this calendar month vs. the "
                    "configured monthly cap. Alert fires at "
                    span.ed-mono { (threshold_eff) "%" } "."
                }
                div style="font-family: var(--mono); font-size: 13px; margin: 0 0 8px;" {
                    (fmt_traffic_progress(used, lim))
                    @if over_limit {
                        " · "
                        span style="color: var(--acc); font-weight: 600;" { "OVER LIMIT" }
                    } @else if over_threshold {
                        " · "
                        span style="color: var(--acc);" { "near limit" }
                    }
                }
                // Progress bar — pure CSS, no JS. Width capped at
                // 100% so a runaway user (200% of cap) still renders
                // a sane bar; the numeric copy above tells the truth.
                @let bar_pct = pct.min(100);
                // Both "over limit" and "over threshold" use accent
                // colour — the operator-facing difference is the
                // copy ("OVER LIMIT" vs "near limit"), not the bar
                // hue. Single ternary keeps clippy happy.
                @let bar_fill = if over_threshold { "var(--acc)" } else { "var(--ink)" };
                @let _ = over_limit;  // bound above; threshold check covers fill
                div style="height: 8px; background: var(--rule); margin-bottom: 16px; overflow: hidden;" {
                    div style=(format!("height: 100%; width: {bar_pct}%; background: {bar_fill};")) {}
                }
            }
            _ => {
                p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
                    "Used this month: " span.ed-mono { (humanize_bytes(used)) }
                    " — no monthly cap configured. Set one below if you want a "
                    span.ed-mono { (DEFAULT_TRAFFIC_THRESHOLD_PCT) "%-of-limit alert" }
                    " to fire on the dashboard."
                }
            }
        }

        form method="post"
             action=(format!("/admin/users/{}/traffic-limit", path_segment_encode(&uid.0)))
             style="display: flex; gap: 10px; align-items: baseline; flex-wrap: wrap; padding: 10px 12px; background: var(--paper); border: 1px solid var(--rule);" {
            label style="font-family: var(--mono); font-size: 11px; color: var(--mute); letter-spacing: 0.14em; text-transform: uppercase;" {
                "limit"
            }
            // Operator-friendly input: GiB. Backend converts to
            // bytes. 0 / empty = clear the limit.
            @let limit_gib_default = limit_opt
                .map(|b| b as f64 / 1_073_741_824.0)
                .unwrap_or(0.0);
            input type="number" name="limit_gib" step="0.1" min="0" max="100000"
                  value=(format!("{limit_gib_default:.1}"))
                  style="max-width: 80px; padding: 4px 8px; border: 1px solid var(--rule-s); background: var(--paper); font-family: var(--mono); font-size: 12px; color: var(--ink);";
            span style="font-family: var(--mono); font-size: 11px; color: var(--mute);" { "GiB / month" }
            label style="font-family: var(--mono); font-size: 11px; color: var(--mute); letter-spacing: 0.14em; text-transform: uppercase; margin-left: 8px;" {
                "alert at"
            }
            input type="number" name="threshold_pct" step="1" min="1" max="100"
                  value=(threshold_eff)
                  style="max-width: 56px; padding: 4px 8px; border: 1px solid var(--rule-s); background: var(--paper); font-family: var(--mono); font-size: 12px; color: var(--ink);";
            span style="font-family: var(--mono); font-size: 11px; color: var(--mute);" { "%" }
            button type="submit"
                   title="Set both fields. 0 GiB = clear the limit (no cap)."
                   style="padding: 4px 12px; border: 1px solid var(--ink); background: var(--ink); color: var(--paper); font-family: var(--mono); font-size: 11px; cursor: pointer; margin-left: auto;" {
                "save"
            }
        }
    }
}

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
            (status_tile("uploaded", &humanize_bytes(total_up), "var(--ink)"))
            (status_tile("downloaded", &humanize_bytes(total_dn), "var(--ink)"))
            (status_tile("peak conns", &peak_conns.to_string(), "var(--ink)"))
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
        // Hourly sparkline of upload + download (Pavel iter D.7).
        // 24-cell bar chart, height ∝ bytes/hour, sketched in inline
        // SVG so no JS, no external assets, no fonts beyond what the
        // editorial shell already loads. Bars use `var(--acc)` for
        // download (the user's "fetch volume") and a faded ink for
        // upload — both legible on every theme.
        (vpn_sparkline_24h(&rows))
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin-top: 10px;" {
            "Aggregated from " (rows.len())
            @if rows.len() == 1 { " snapshot" } @else { " snapshots" }
            " over the last 24 hours. Rows are auto-purged after 30 days."
        }
    }
}

// `vpn_kpi_tile` removed 2026-05-18 — was exactly equivalent to
// `status_tile(label, value, "var(--ink)")`. The 3 call sites at
// `live_vpn_stats_section` now invoke `status_tile` directly with
// the ink color so the editorial chrome (border + label-style + serif
// number) lives in exactly one helper.

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
    not_found(&format!("no such user '{id}'"))
}

/// Generic editorial-prefixed error response. Single point where the
/// `(status, error_text(detail)).into_response()` shape lives — every
/// status-specific helper (`bad_request`, `not_found`, `unauthorized`)
/// delegates here, and exotic codes (`CONFLICT`, `BAD_GATEWAY`,
/// `INTERNAL_SERVER_ERROR` from non-anyhow paths) call it directly
/// rather than open-coding the tuple. Keeps the prefix discipline
/// (and the newline normalisation in [`error_text`]) in lock-step
/// across every admin response.
fn error_resp(status: StatusCode, detail: &str) -> Response {
    (status, error_text(detail)).into_response()
}

/// 400 Bad Request with the editorial-prefixed body. Single source of
/// truth — was inlined as `(StatusCode::BAD_REQUEST, error_text(...))
/// .into_response()` at ~25 sites before consolidation. Delegates to
/// [`error_resp`].
fn bad_request(detail: &str) -> Response {
    error_resp(StatusCode::BAD_REQUEST, detail)
}

/// 404 Not Found with the editorial-prefixed body. Companion to
/// [`bad_request`] / [`unauthorized`] — was inlined ~14× before
/// consolidation. `user_not_found` is now a thin wrapper around this
/// helper, preserving its call-site brevity.
fn not_found(detail: &str) -> Response {
    error_resp(StatusCode::NOT_FOUND, detail)
}

/// 401 Unauthorized with the editorial-prefixed body. Used by the
/// in-handler auth gates (the basic-auth middleware emits its own
/// 401 with the literal prefix baked in — see `daemon/src/auth.rs`
/// — because it runs BEFORE this module is reachable). Was inlined
/// at ~3 sites; consolidated for parity.
#[allow(dead_code)]
fn unauthorized(detail: &str) -> Response {
    error_resp(StatusCode::UNAUTHORIZED, detail)
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

/// `POST /admin/users/{id}/wireguard/regenerate` — mint a fresh
/// Curve25519 pair, overwrite both `wireguard_pubkey` and
/// `wireguard_private` on the user row, audit, redirect to the
/// detail page (which shows the new pubkey + the "✓ stored" marker
/// for private). Every device using the OLD config stops working
/// after the next /sub/<token> re-fetch — the old pubkey is no
/// longer in the server's [Peer] list (will land on next
/// `vpnctl deploy <server>`).
///
/// Same CSRF/audit/404 posture as `user_regen_sub_token`.
pub(crate) async fn user_regen_wireguard(
    State(state): State<AppState>,
    Path(user_id_str): Path<String>,
) -> Response {
    let uid = vpnctl_core::UserId(user_id_str.clone());

    // Existence check — explicit 404 if no such user.
    match state.inv.get_user(&uid).await {
        Ok(Some(_)) => {}
        Ok(None) => return user_not_found(&user_id_str),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    }

    // Mutate.
    let (priv_b64, pub_b64) = vpnctl_crypto::gen_wireguard_keypair();
    if let Err(e) = state
        .inv
        .set_user_wireguard_keypair(&uid, &pub_b64, &priv_b64)
        .await
    {
        return internal_error(anyhow::Error::new(e));
    }

    // Audit — pin provenance + new pubkey for traceability. Private
    // value never enters the log (key VALUES never do — only
    // provenance + the pubkey, which is itself public).
    if let Err(e) = state
        .inv
        .audit(
            "admin",
            "user.wireguard.regen",
            Some(&user_id_str),
            Some(&serde_json::json!({
                "wg_keypair_provenance": "server-generated",
                "new_pubkey": pub_b64,
            })),
        )
        .await
    {
        tracing::warn!(
            target = "vpnctld::admin",
            user = %user_id_str,
            error = %e,
            "audit write failed for user.wireguard.regen — mutation already committed"
        );
    }

    Redirect::to(&format!(
        "/admin/users/{}",
        path_segment_encode(&user_id_str)
    ))
    .into_response()
}

/// `GET /admin/users/{user_id}/wireguard/conf/{server_id}` — serve a
/// drag-drop-ready `.conf` file (INI body — `[Interface]` + `[Peer]`,
/// optionally + AmneziaWG obfs lines when secrets are set) for this
/// (user, server) pair. Imports into the official WireGuard app, into
/// Hiddify, AND into AmneziaVPN's "File with settings" picker — i.e.
/// every WG client, no matter the URI scheme they prefer.
///
/// Headers:
///   * `Content-Type: text/plain; charset=utf-8` — most clients sniff
///     the body regardless, but `text/plain` is the closest match.
///   * `Content-Disposition: attachment; filename="<user>-<server>.conf"`
///     — triggers the browser's download UI instead of inline display.
///
/// Errors:
///   * 404 if the user or server doesn't exist (canonical body).
///   * 400 if the server doesn't enable the `wireguard` protocol.
///   * 500 on rendering errors (missing server pubkey etc.) — these
///     usually indicate the server hasn't been deployed.
pub(crate) async fn user_wireguard_conf_download(
    State(state): State<AppState>,
    Path((user_id_str, server_id_str)): Path<(String, String)>,
) -> Response {
    let uid = vpnctl_core::UserId(user_id_str.clone());
    let sid = vpnctl_core::ServerId(server_id_str.clone());

    let user = match state.inv.get_user(&uid).await {
        Ok(Some(u)) => u,
        Ok(None) => return user_not_found(&user_id_str),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    let server = match state.inv.get_server(&sid).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return not_found(&format!("no such server '{server_id_str}'"));
        }
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    if !server.enabled_protocols.iter().any(|p| p.0 == "wireguard") {
        return bad_request(&format!(
            "server '{server_id_str}' does not enable the 'wireguard' protocol — enable it on the server detail page before downloading a .conf"
        ));
    }
    // Grant check — refuse the download if the (user, server) pair
    // isn't granted. Without this, the URL stays "live" after a
    // revoke and a stale browser tab can still pull the .conf.
    // Doubles as the source of `ctx.peers` so the .conf address
    // matches the server's [Peer] block 1:1.
    let peers = match state.inv.users_for_server(&sid).await {
        Ok(p) => p,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    if !peers.iter().any(|p| p.id == uid) {
        return not_found(&format!(
            "user '{user_id_str}' is not granted on server '{server_id_str}'"
        ));
    }
    let secrets = match state.inv.list_server_secrets(&sid).await {
        Ok(m) => m,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    let ctx = vpnctl_core::RenderCtx::with_peers(&server, &secrets, &peers);
    let conf = match vpnctl_protocols::render_client_conf_public(&ctx, &user) {
        Ok(c) => c,
        Err(e) => return internal_error(anyhow::anyhow!(e)),
    };

    // Strip every RFC-6266 unsafe set + control bytes from the
    // filename before quoting. `valid_user_id` (POST /admin/users) IS
    // the input gate going forward, but old DB rows imported from
    // legacy bash inventory MAY contain spaces / quotes / CR / LF;
    // a CR/LF in particular would otherwise make
    // `HeaderValue::from_str` reject the header entirely and the
    // browser would default-name the file `download` (bad UX). Stripping
    // is safer than rejecting because the operator's intent (download
    // SOMETHING) is unambiguous.
    let safe = |s: &str| -> String {
        s.chars()
            .filter(|c| !matches!(c, '"' | '\\' | '\r' | '\n') && !c.is_control())
            .collect()
    };
    let filename = format!("{}-{}.conf", safe(&user.id.0), safe(&server.id.0));

    let mut resp = (StatusCode::OK, conf).into_response();
    let headers = resp.headers_mut();
    if let Ok(v) = HeaderValue::from_str("text/plain; charset=utf-8") {
        headers.insert(header::CONTENT_TYPE, v);
    }
    if let Ok(v) = HeaderValue::from_str(&format!("attachment; filename=\"{filename}\"")) {
        headers.insert(header::CONTENT_DISPOSITION, v);
    }
    resp
}

// ────────────────────────────────────────────────────────────────────────
// Phase C-4 — inventory snapshot endpoints (web-side).
//
// The scheduler in `crate::app::spawn_backup_scheduler` produces hourly
// snapshots; these two handlers give the operator the same controls
// from the Settings page WITHOUT having to wait an hour.
//
//   * `POST /admin/backup/snapshot` — trigger an immediate snapshot,
//     audit the result, redirect back to /admin/settings.
//   * `GET  /admin/backup/download/{name}` — stream a specific
//     snapshot file from DEFAULT_BACKUP_DIR with
//     `Content-Disposition: attachment` so the browser saves it
//     instead of trying to render the binary inline.
// ────────────────────────────────────────────────────────────────────────

/// `POST /admin/backup/snapshot` — manual snapshot trigger. Same
/// underlying call as the hourly scheduler; audited with
/// `trigger: "manual"` so the timeline can distinguish.
pub(crate) async fn backup_snapshot_now(State(state): State<AppState>) -> Response {
    let backup_dir = std::path::PathBuf::from(crate::app::DEFAULT_BACKUP_DIR);
    let snapshot_result = vpnctl_inventory::snapshot_now(&state.inv, &backup_dir).await;
    let snapshot_path: Option<String> = snapshot_result
        .as_ref()
        .ok()
        .map(|p| p.display().to_string());
    let snapshot_err: Option<String> = snapshot_result.as_ref().err().map(|e| e.to_string());

    if let Err(e) = state
        .inv
        .audit(
            "admin",
            "backup.snapshot",
            None,
            Some(&serde_json::json!({
                "trigger": "manual",
                "snapshot_path": snapshot_path,
                "snapshot_err": snapshot_err,
            })),
        )
        .await
    {
        tracing::warn!(
            target = "vpnctld::backup",
            error = %e,
            "audit write failed for manual backup.snapshot"
        );
    }
    if let Err(e) = snapshot_result {
        return internal_error(anyhow::Error::new(e));
    }
    // Fragment anchor → browser scrolls back to the Backups
    // section (where the operator pressed «snapshot now») instead
    // of jumping to the top of /admin/settings.
    Redirect::to("/admin/settings#backups-section").into_response()
}

/// `GET /admin/backup/download/{name}` — stream a snapshot file with
/// `Content-Disposition: attachment`. The operator-supplied `name`
/// is validated strictly (the snapshot prefix + safe-charset filename)
/// so a "../" or absolute path can never escape `DEFAULT_BACKUP_DIR`.
pub(crate) async fn backup_download(Path(name): Path<String>) -> Response {
    // Filename validation — accept ONLY files matching the snapshot
    // naming convention. Rejects `../`, absolute paths, NUL bytes,
    // anything with a slash. Belt-and-braces vs the
    // `std::path::Path::join` semantics, which would otherwise let
    // an absolute path override the parent prefix.
    if !is_safe_snapshot_name(&name) {
        return bad_request(&format!(
            "invalid snapshot name '{name}' — expected '{prefix}<timestamp>{suffix}'",
            prefix = vpnctl_inventory::backup::SNAPSHOT_FILENAME_PREFIX,
            suffix = vpnctl_inventory::backup::SNAPSHOT_FILENAME_SUFFIX,
        ));
    }
    let backup_dir = std::path::PathBuf::from(crate::app::DEFAULT_BACKUP_DIR);
    let path = backup_dir.join(&name);
    // Defence in depth: ensure the resolved path is still inside the
    // backup dir even after `join`. `canonicalize` reads through
    // symlinks — the operator could in principle create a symlink in
    // the backup dir pointing at `/etc/passwd`, but the snapshot dir
    // is daemon-owned 0700 so they'd need a root-level compromise
    // already.
    let canon_dir = match std::fs::canonicalize(&backup_dir) {
        Ok(p) => p,
        Err(e) => {
            return error_resp(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("backup dir not readable: {e}"),
            );
        }
    };
    let canon_path = match std::fs::canonicalize(&path) {
        Ok(p) => p,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return not_found(&format!("snapshot '{name}' not found"));
        }
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    if !canon_path.starts_with(&canon_dir) {
        return bad_request("snapshot path escaped backup dir — refusing");
    }
    let bytes = match std::fs::read(&canon_path) {
        Ok(b) => b,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    let mut resp = (StatusCode::OK, bytes).into_response();
    let headers = resp.headers_mut();
    if let Ok(v) = HeaderValue::from_str("application/octet-stream") {
        headers.insert(header::CONTENT_TYPE, v);
    }
    if let Ok(v) = HeaderValue::from_str(&format!("attachment; filename=\"{name}\"")) {
        headers.insert(header::CONTENT_DISPOSITION, v);
    }
    resp
}

/// Strict accept for snapshot filename — only the EXACT pattern the
/// scheduler emits passes. Delegates to
/// `vpnctl_inventory::parse_snapshot_filename` so the validator stays
/// in lock-step with the emitter (a future change to the filename
/// shape only touches the inventory crate).
fn is_safe_snapshot_name(name: &str) -> bool {
    // Length / charset gate runs BEFORE the parser so a 10MB
    // filename can't OOM the daemon and `/` / NUL / control bytes
    // never reach the filesystem layer even if the parser ever
    // accidentally accepts them.
    if name.is_empty() || name.len() > 128 {
        return false;
    }
    if name
        .chars()
        .any(|c| c.is_control() || matches!(c, '/' | '\\' | '\0' | '"' | '\'' | '`'))
    {
        return false;
    }
    // Parser is the source of truth for the precise shape
    // (`inv.db.<RFC3339-ish>.bak`).
    vpnctl_inventory::parse_snapshot_filename(name).is_some()
}

// `format_size_bytes` (storage sizes — JEDEC KB/MB/GB labels) moved
// to `vpnctl_core::humanize::format_size_bytes` (2026-05-18, post-
// host-fingerprint consolidation pass) — same fn was byte-identical
// in `cli/src/cmd/backup.rs`. **NOTE:** the sibling `humanize_bytes`
// (defined ~400 lines up, IEC KiB/MiB/GiB labels, 9 call sites for
// traffic counts) is INTENTIONALLY a different helper — see the
// crate-level rustdoc on `vpnctl_core::humanize` for the split
// rationale (storage vs traffic, JEDEC vs IEC).

/// `POST /admin/servers/{id}/protocols/{proto}/enable` — add a
/// protocol to a server's `enabled_protocols`. Idempotent at SQL.
/// Returns 404 if server doesn't exist, 400 if protocol id isn't
/// registered with the daemon (no point persisting a string that
/// nothing knows how to render). Audit row written. Always
/// redirects back to the server-detail page.
pub(crate) async fn server_enable_protocol(
    State(state): State<AppState>,
    Path((server_id_str, protocol_id_str)): Path<(String, String)>,
) -> Response {
    let sid = vpnctl_core::ServerId(server_id_str.clone());
    let pid = vpnctl_core::ProtocolId(protocol_id_str.clone());

    // Existence check (404 if no server).
    match state.inv.get_server(&sid).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return not_found(&format!("no such server '{server_id_str}'"));
        }
        Err(e) => return internal_error(anyhow::Error::new(e)),
    }
    // Reject unregistered protocol id — persisting a typo would
    // silently no-op every render+deploy from now on.
    if state.registry.protocol(&pid).is_none() {
        let known: Vec<String> = state
            .registry
            .protocol_ids()
            .into_iter()
            .map(|p| p.0)
            .collect();
        return bad_request(&format!(
            "unknown protocol '{protocol_id_str}' — registered: {}",
            known.join(", ")
        ));
    }

    let inserted = match state.inv.add_server_protocol(&sid, &pid).await {
        Ok(n) => n,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };

    if let Err(e) = state
        .inv
        .audit(
            "admin",
            "server.protocol.enable",
            Some(&server_id_str),
            Some(&serde_json::json!({
                "protocol": protocol_id_str,
                "newly_added": inserted == 1,
            })),
        )
        .await
    {
        tracing::warn!(
            target = "vpnctld::admin",
            server = %server_id_str,
            error = %e,
            "audit write failed for server.protocol.enable"
        );
    }

    Redirect::to(&format!(
        "/admin/servers/{}",
        path_segment_encode(&server_id_str)
    ))
    .into_response()
}

/// `POST /admin/servers/{id}/protocols/{proto}/disable` — remove a
/// protocol from a server's `enabled_protocols`. Idempotent. Same
/// 404/audit/redirect posture as `server_enable_protocol`.
pub(crate) async fn server_disable_protocol(
    State(state): State<AppState>,
    Path((server_id_str, protocol_id_str)): Path<(String, String)>,
) -> Response {
    let sid = vpnctl_core::ServerId(server_id_str.clone());
    let pid = vpnctl_core::ProtocolId(protocol_id_str.clone());

    match state.inv.get_server(&sid).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return not_found(&format!("no such server '{server_id_str}'"));
        }
        Err(e) => return internal_error(anyhow::Error::new(e)),
    }

    let removed = match state.inv.remove_server_protocol(&sid, &pid).await {
        Ok(n) => n,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };

    if let Err(e) = state
        .inv
        .audit(
            "admin",
            "server.protocol.disable",
            Some(&server_id_str),
            Some(&serde_json::json!({
                "protocol": protocol_id_str,
                "was_present": removed == 1,
            })),
        )
        .await
    {
        tracing::warn!(
            target = "vpnctld::admin",
            server = %server_id_str,
            error = %e,
            "audit write failed for server.protocol.disable"
        );
    }

    Redirect::to(&format!(
        "/admin/servers/{}",
        path_segment_encode(&server_id_str)
    ))
    .into_response()
}

/// `POST /admin/users/{id}/traffic-limit` — set monthly bandwidth
/// cap + alert threshold for one user. Form fields:
///   * `limit_gib` (float) — total upload+download/month in GiB.
///     `0` (or empty / negative / non-numeric) clears the cap.
///   * `threshold_pct` (int 1..=100) — alert fires at this fraction
///     of the cap. Defaults to `DEFAULT_TRAFFIC_THRESHOLD_PCT` (80)
///     when omitted.
///
/// 404 unknown user; 303 to user-detail on success. Audit row
/// records new values (NOT the user's accumulated usage — that's
/// a derived metric).
pub(crate) async fn user_set_traffic_limit(
    State(state): State<AppState>,
    Path(user_id_str): Path<String>,
    body: String,
) -> Response {
    let uid = vpnctl_core::UserId(user_id_str.clone());

    // Existence — explicit 404 (matches the rest of the admin tree).
    match state.inv.get_user(&uid).await {
        Ok(Some(_)) => {}
        Ok(None) => return user_not_found(&user_id_str),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    }

    // Parse form. Two fields, both optional in the wire format —
    // missing limit_gib = clear, missing threshold = use default.
    let limit_gib: f64 = form_field(&body, "limit_gib")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0.0);
    let threshold_pct: u8 = form_field(&body, "threshold_pct")
        .and_then(|s| s.parse().ok())
        .map(|v: u32| v.clamp(1, 100) as u8)
        .unwrap_or(DEFAULT_TRAFFIC_THRESHOLD_PCT);

    // 0 / negative / NaN = clear the limit (operator intent: "no cap").
    let limit_bytes: Option<u64> = if limit_gib > 0.0 && limit_gib.is_finite() {
        Some((limit_gib * 1_073_741_824.0) as u64)
    } else {
        None
    };

    if let Err(e) = state
        .inv
        .set_user_traffic_limit(&uid, limit_bytes, Some(threshold_pct))
        .await
    {
        return internal_error(anyhow::Error::new(e));
    }

    if let Err(e) = state
        .inv
        .audit(
            "admin",
            "user.traffic_limit.set",
            Some(&user_id_str),
            Some(&serde_json::json!({
                "limit_bytes": limit_bytes,
                "limit_gib": limit_gib,
                "threshold_pct": threshold_pct,
            })),
        )
        .await
    {
        tracing::warn!(
            target = "vpnctld::admin",
            user = %user_id_str,
            error = %e,
            "audit write failed for user.traffic_limit.set"
        );
    }

    Redirect::to(&format!(
        "/admin/users/{}",
        path_segment_encode(&user_id_str)
    ))
    .into_response()
}

/// `POST /admin/servers/{sid}/grants/{uid}` — grant the user access
/// from the SERVER side. Identical mutation to `user_grant_server`
/// (same `inv.grant` call), but the redirect target is the SERVER
/// detail page so the operator stays where they started. Mirror
/// pair: `server_revoke_user`.
pub(crate) async fn server_grant_user(
    State(state): State<AppState>,
    Path((server_id_str, user_id_str)): Path<(String, String)>,
) -> Response {
    let sid = vpnctl_core::ServerId(server_id_str.clone());
    let uid = vpnctl_core::UserId(user_id_str.clone());
    // Existence checks — explicit 404 for both, otherwise the FK
    // violation surfaces as a generic 500.
    match state.inv.get_server(&sid).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return not_found(&format!("no such server '{server_id_str}'"));
        }
        Err(e) => return internal_error(anyhow::Error::new(e)),
    }
    match state.inv.get_user(&uid).await {
        Ok(Some(_)) => {}
        Ok(None) => return user_not_found(&user_id_str),
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
            Some(&serde_json::json!({
                "user": user_id_str,
                "from": "server-detail",
            })),
        )
        .await
    {
        tracing::warn!(target = "vpnctld::admin", error = %e, "audit write failed for grant");
    }
    Redirect::to(&format!(
        "/admin/servers/{}",
        path_segment_encode(&server_id_str)
    ))
    .into_response()
}

/// `POST /admin/servers/{sid}/grants/{uid}/revoke` — revoke from the
/// SERVER side. Mirror of `server_grant_user`.
pub(crate) async fn server_revoke_user(
    State(state): State<AppState>,
    Path((server_id_str, user_id_str)): Path<(String, String)>,
) -> Response {
    let sid = vpnctl_core::ServerId(server_id_str.clone());
    let uid = vpnctl_core::UserId(user_id_str.clone());
    match state.inv.get_server(&sid).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return not_found(&format!("no such server '{server_id_str}'"));
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
            Some(&serde_json::json!({
                "user": user_id_str,
                "from": "server-detail",
            })),
        )
        .await
    {
        tracing::warn!(target = "vpnctld::admin", error = %e, "audit write failed for revoke");
    }
    Redirect::to(&format!(
        "/admin/servers/{}",
        path_segment_encode(&server_id_str)
    ))
    .into_response()
}

/// `POST /admin/servers/{id}/deploy` — the operator-facing deploy
/// button. Per CLAUDE.md "Web is the ONLY operator surface; CLI is
/// implementation detail" — Pavel must never have to open a terminal
/// to deploy a server.
///
/// **What this does TODAY (no SSH dep in production binary):**
///   * Bootstrap every missing server-secret the inventory needs to
///     render configs: REALITY keypair + short_id (for vless+reality),
///     WireGuard server keypair (for wireguard), Hysteria2 obfs
///     password (for hysteria2 + salamander). All mints happen
///     server-side via vpnctl_crypto — no SSH.
///   * Persist each new secret with audit_log row.
///   * Render kernel configs for the operator's pre-flight review
///     (writes nothing to the node — just confirms the render
///     succeeds with the now-complete secret set).
///
/// **What still needs an SSH push to the node** (post-musl-build
/// roadmap — tracked as TODO `web-deploy-apply`):
///   * `ensure_installed` (apt install sing-box / amneziawg-tools)
///   * `apply_config` (scp render output + systemctl restart)
///
/// Until the daemon ships with a working SSH path (musl static
/// binary OR glibc upgrade on the host), the install/apply steps
/// remain a one-time per-node CLI action — but the button still
/// solves the per-click pain (no operator-typed keypair generation).
///
/// Returns 303 to /admin/servers/{id} after success so the operator
/// sees the now-populated `secret_keys` block + any newly-enabled
/// share-links in the user-detail Flow B section.
pub(crate) async fn server_deploy(
    State(state): State<AppState>,
    Path(server_id_str): Path<String>,
) -> Response {
    let sid = vpnctl_core::ServerId(server_id_str.clone());

    let server = match state.inv.get_server(&sid).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return not_found(&format!("no such server '{server_id_str}'"));
        }
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };

    // Pre-flight: validate kernel/protocol compatibility via the
    // registry. If a protocol declared on this server can't be
    // rendered by any of its kernels, every bootstrap step below
    // would still succeed but the render would later fail with a
    // confusing "unsupported protocol" — surface that upfront.
    if let Err(e) = state.registry.validate_server(&server) {
        return bad_request(&format!("config invalid before deploy: {e}"));
    }

    // Bootstrap missing secrets. Shared with the Phase-E wizard
    // via `wizard_bootstrap::bootstrap_server_secrets` so any new
    // server-side secret added for a future protocol is minted
    // identically by deploy + wizard. Idempotent — re-clicking
    // deploy when everything is already minted is a safe no-op.
    let (secrets, bootstrapped) =
        match crate::wizard_bootstrap::bootstrap_server_secrets(&state.inv, &server).await {
            Ok(v) => v,
            Err(e) => return internal_error(anyhow::anyhow!(e)),
        };

    // SSH push to the node — Path C via SubprocessSshTransport.
    // For each declared kernel: ensure_installed → render config
    // (only protocols this kernel can run) → apply_config.
    //
    // Per-kernel + per-step errors are isolated to the offending
    // kernel: a failed amneziawg install does NOT prevent the
    // sing-box restart. Aggregate result is captured in the audit
    // payload (`ssh_kernels_pushed`, `ssh_errors`).
    use crate::ssh_subprocess::SubprocessSshTransport;
    let key_path = std::path::PathBuf::from(crate::app::DEFAULT_DEPLOY_KEY_PATH);
    let mut ssh_kernels_pushed: Vec<String> = Vec::new();
    let mut ssh_errors: Vec<String> = Vec::new();
    let mut total_config_bytes: usize = 0;
    let ssh_skip_reason: Option<&'static str> = if !key_path.exists() {
        Some("deploy key absent; see /admin/settings")
    } else if server.kernels.is_empty() {
        Some("server has no kernels declared")
    } else {
        None
    };
    if ssh_skip_reason.is_none() {
        let ssh =
            SubprocessSshTransport::new(server.address.clone(), server.ssh_user.clone(), key_path)
                .port(server.ssh_port);

        // Pre-load users + render context once; reused for every
        // kernel's render call.
        let users = match state.inv.users_for_server(&sid).await {
            Ok(u) => u,
            Err(e) => return internal_error(anyhow::Error::new(e)),
        };
        let ctx = vpnctl_core::RenderCtx::new(&server, &secrets);

        for kid in &server.kernels {
            let Some(kernel) = state.registry.kernel(kid) else {
                ssh_errors.push(format!("{}: kernel not registered", kid.0));
                continue;
            };
            if let Err(e) = kernel.ensure_installed(&ssh).await {
                ssh_errors.push(format!("{}: ensure_installed failed: {e}", kid.0));
                continue;
            }
            let supported = kernel.supported_protocols();
            let protocols: Vec<&dyn vpnctl_core::Protocol> = server
                .enabled_protocols
                .iter()
                .filter(|p| supported.contains(p))
                .filter_map(|p| state.registry.protocol(p))
                .collect();
            if protocols.is_empty() {
                // Kernel installed but no protocols for it — still
                // a valid step (e.g. preparing a node for future
                // protocols). Skip render+apply, report neutral.
                ssh_kernels_pushed.push(format!("{} (installed, no protocols)", kid.0));
                continue;
            }
            let config = match kernel.render_config(&ctx, &users, &protocols) {
                Ok(c) => c,
                Err(e) => {
                    ssh_errors.push(format!("{}: render failed: {e}", kid.0));
                    continue;
                }
            };
            total_config_bytes += config.len();
            if let Err(e) = kernel.apply_config(&ssh, &config).await {
                ssh_errors.push(format!("{}: apply_config failed: {e}", kid.0));
                continue;
            }
            ssh_kernels_pushed.push(kid.0.clone());
        }
    }

    // Audit — record EVERY deploy click. Captures both the
    // inventory-side bootstrap result AND the SSH-side push result
    // so the operator (and future debugging) sees the full picture.
    if let Err(e) = state
        .inv
        .audit(
            "admin",
            "server.deploy",
            Some(&server_id_str),
            Some(&serde_json::json!({
                "bootstrapped": bootstrapped,
                "kernels": server.kernels.iter().map(|k| &k.0).collect::<Vec<_>>(),
                "protocols": server.enabled_protocols.iter().map(|p| &p.0).collect::<Vec<_>>(),
                "ssh_skip_reason": ssh_skip_reason,
                "ssh_kernels_pushed": ssh_kernels_pushed,
                "ssh_errors": ssh_errors,
                "ssh_config_bytes_total": total_config_bytes,
            })),
        )
        .await
    {
        tracing::warn!(
            target = "vpnctld::admin",
            server = %server_id_str,
            error = %e,
            "audit write failed for server.deploy"
        );
    }

    Redirect::to(&format!(
        "/admin/servers/{}",
        path_segment_encode(&server_id_str)
    ))
    .into_response()
}

/// `POST /admin/servers/quick-add` — register a SERVER YOU ALREADY HAVE
/// in inventory with minimal input: id + address (+ optional ssh_port).
/// Default kernel = sing-box; default protocols = every protocol
/// sing-box supports. Operator tweaks on the detail page right after.
///
/// This is the inline path on `/admin/servers`. The fancy Phase-E
/// SSE-streamed bootstrap wizard at `/admin/servers/new` is a
/// DIFFERENT flow (it ssh-pushes our key and installs the kernel from
/// scratch — only useful for fresh nodes).
pub(crate) async fn server_quick_add(State(state): State<AppState>, body: String) -> Response {
    // Tiny form parser via the shared `form_field` helper. Note:
    // `form_field` decodes BEFORE trim (whereas the legacy inline
    // pattern trimmed BEFORE decode); strictly stricter — `%20`-
    // encoded whitespace at the edges is now normalised the same as
    // literal whitespace, so a paste like `"  vps-de1  "` and
    // `"%20vps-de1%20"` both produce `"vps-de1"`.
    let id: String = form_field(&body, "id")
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    if !valid_user_id(&id) {
        // Reuse user-id validator — same allowed alphabet (alphanumerics,
        // . _ -). Length cap 64 is reasonable for server ids too.
        return bad_request(&format!(
            "invalid server id '{id}' (allowed: 1-64 chars of A-Z a-z 0-9 . _ -)"
        ));
    }

    let address: String = form_field(&body, "address")
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    if address.is_empty() {
        return bad_request("address must not be empty (IPv4, IPv6 or hostname)");
    }
    // Shallow address shape check — full IP/hostname validation lives
    // in the bootstrap path; here we just reject obvious garbage so a
    // typo doesn't get persisted.
    if address.contains(' ') || address.len() > 253 {
        return bad_request(&format!("address looks malformed: {address:?}"));
    }

    let ssh_port: u16 = form_field(&body, "ssh_port")
        .and_then(|s| s.parse().ok())
        .unwrap_or(22);

    // Default kernel = sing-box; protocols = ALL it supports. This
    // mirrors the "users are low-tech" one-action ceiling for the
    // operator: register the server, then enable/disable on the
    // detail page (a single click each).
    use vpnctl_core::{KernelId, ProtocolId, Server, ServerId};
    let kernel_id = KernelId("sing-box".into());
    let default_protocols: Vec<ProtocolId> = state
        .registry
        .kernel(&kernel_id)
        .map(|k| k.supported_protocols())
        .unwrap_or_default();

    let server = Server {
        id: ServerId(id.clone()),
        address: address.clone(),
        ssh_port,
        ssh_user: "root".into(),
        kernels: vec![kernel_id],
        enabled_protocols: default_protocols.clone(),
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    };

    if let Err(e) = state.inv.add_server(&server).await {
        return match e {
            vpnctl_inventory::SqliteInventoryError::AlreadyExists(what) => {
                bad_request(&format!("{what} already exists — pick a different id"))
            }
            other => internal_error(anyhow::Error::new(other)),
        };
    }

    if let Err(e) = state
        .inv
        .audit(
            "admin",
            "server.quick-add",
            Some(&id),
            Some(&serde_json::json!({
                "address": address,
                "ssh_port": ssh_port,
                "kernels": ["sing-box"],
                "protocols": default_protocols.iter().map(|p| &p.0).collect::<Vec<_>>(),
            })),
        )
        .await
    {
        tracing::warn!(
            target = "vpnctld::admin",
            server = %id,
            error = %e,
            "audit write failed for server.quick-add"
        );
    }

    Redirect::to(&format!("/admin/servers/{}", path_segment_encode(&id))).into_response()
}

/// `POST /admin/servers/{id}/kernels/{kernel}/enable` — add a kernel
/// to a server's runtime set. Mirrors `server_enable_protocol`.
pub(crate) async fn server_enable_kernel(
    State(state): State<AppState>,
    Path((server_id_str, kernel_id_str)): Path<(String, String)>,
) -> Response {
    let sid = vpnctl_core::ServerId(server_id_str.clone());
    let kid = vpnctl_core::KernelId(kernel_id_str.clone());

    match state.inv.get_server(&sid).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return not_found(&format!("no such server '{server_id_str}'"));
        }
        Err(e) => return internal_error(anyhow::Error::new(e)),
    }
    // Reject unregistered kernel id — same posture as
    // server_enable_protocol: persisting a typo would silently no-op
    // every deploy.
    if state.registry.kernel(&kid).is_none() {
        let known: Vec<String> = state
            .registry
            .kernel_ids()
            .into_iter()
            .map(|k| k.0)
            .collect();
        return bad_request(&format!(
            "unknown kernel '{kernel_id_str}' — registered: {}",
            known.join(", ")
        ));
    }

    let inserted = match state.inv.add_server_kernel(&sid, &kid).await {
        Ok(n) => n,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };

    if let Err(e) = state
        .inv
        .audit(
            "admin",
            "server.kernel.enable",
            Some(&server_id_str),
            Some(&serde_json::json!({
                "kernel": kernel_id_str,
                "newly_added": inserted == 1,
            })),
        )
        .await
    {
        tracing::warn!(
            target = "vpnctld::admin",
            server = %server_id_str,
            error = %e,
            "audit write failed for server.kernel.enable"
        );
    }

    Redirect::to(&format!(
        "/admin/servers/{}",
        path_segment_encode(&server_id_str)
    ))
    .into_response()
}

/// `POST /admin/servers/{id}/kernels/{kernel}/disable` — remove a
/// kernel. Mirrors `server_disable_protocol`.
pub(crate) async fn server_disable_kernel(
    State(state): State<AppState>,
    Path((server_id_str, kernel_id_str)): Path<(String, String)>,
) -> Response {
    let sid = vpnctl_core::ServerId(server_id_str.clone());
    let kid = vpnctl_core::KernelId(kernel_id_str.clone());

    match state.inv.get_server(&sid).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return not_found(&format!("no such server '{server_id_str}'"));
        }
        Err(e) => return internal_error(anyhow::Error::new(e)),
    }

    let removed = match state.inv.remove_server_kernel(&sid, &kid).await {
        Ok(n) => n,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };

    if let Err(e) = state
        .inv
        .audit(
            "admin",
            "server.kernel.disable",
            Some(&server_id_str),
            Some(&serde_json::json!({
                "kernel": kernel_id_str,
                "was_present": removed == 1,
            })),
        )
        .await
    {
        tracing::warn!(
            target = "vpnctld::admin",
            server = %server_id_str,
            error = %e,
            "audit write failed for server.kernel.disable"
        );
    }

    Redirect::to(&format!(
        "/admin/servers/{}",
        path_segment_encode(&server_id_str)
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
    // `form_field` already routes through `decode_form_value`, so this
    // gives us the decoded value directly — no need for the prior
    // trim-then-decode dance. Trim normalises both literal and
    // `%20`-encoded leading/trailing whitespace (strictly safer than
    // the legacy pattern's trim-before-decode).
    let id_decoded: String = form_field(&body, "id")
        .map(|s| s.trim().to_string())
        .unwrap_or_default();

    if !valid_user_id(&id_decoded) {
        return bad_request(&format!(
            "invalid user id '{id_decoded}' (allowed: 1-64 chars of A-Z a-z 0-9 . _ -)"
        ));
    }

    // Mint ALL secrets unconditionally — UUID, tuic_password, WG
    // keypair, sub_token. The form has only one field (`id`) so the
    // operator does ONE action (per CLAUDE.md "users are assumed
    // maximally low-tech" one-action ceiling — applies to the
    // operator UX too, not just the end user). Per-key management
    // (rotate WG keypair, replace pubkey with operator-provided, etc.)
    // lives on the user-detail page; creation is intentionally minimal.
    const TUIC_PW_BYTES: usize = 24;
    let tuic_password = match vpnctl_crypto::gen_password(TUIC_PW_BYTES) {
        Ok(pw) => pw,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    let (wg_priv, wg_pub) = vpnctl_crypto::gen_wireguard_keypair();
    let user = vpnctl_core::User {
        id: vpnctl_core::UserId(id_decoded.clone()),
        uuid: vpnctl_crypto::gen_uuid(),
        tuic_password: Some(tuic_password),
        wireguard_pubkey: Some(wg_pub),
        wireguard_private: Some(wg_priv),
        sub_token: None,
    };

    // Mutation. `AlreadyExists` (UNIQUE violation) gets a 400 with
    // the "already exists" body — operator's typical fix is to pick a
    // different id, no need to surface a generic 500.
    if let Err(e) = state.inv.add_user(&user).await {
        return match e {
            vpnctl_inventory::SqliteInventoryError::AlreadyExists(what) => {
                bad_request(&format!("{what} already exists — pick a different id"))
            }
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
                // Web creation always server-generates the WG pair;
                // pinned so a future regression to optional flag
                // surfaces here. Key VALUES never enter audit_log.
                "wg_keypair_provenance": "server-generated",
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
            return not_found(&format!("no such server '{server_id_str}'"));
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
            return not_found(&format!("no such server '{server_id_str}'"));
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

/// `GET /admin/users/{id}/delete-confirm` — destructive-action
/// double-submit confirm page (C-3.4). Renders a form that requires
/// the operator to retype the user-id; only a matching POST to
/// `/admin/users/{id}/delete` actually deletes.
pub(crate) async fn user_delete_confirm(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(user_id_str): Path<String>,
) -> Result<Markup, Response> {
    let (theme, accent) = theme_accent(&headers);
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
    Ok(shell("users", &theme, &accent, body))
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
    let confirm = form_field(&body, "confirm").unwrap_or_default();
    if confirm != user_id_str {
        return bad_request(&format!(
            "delete confirm mismatch: form sent '{confirm}', URL targets '{user_id_str}' — type the user id exactly to confirm"
        ));
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
    let (theme, accent) = theme_accent(&headers);

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
    Ok(shell("audit", &theme, &accent, body))
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
                        @if let Some(p) = &e.payload {
                            @let summary = summarize_audit_payload(p);
                            @if !summary.is_empty() {
                                " · " span.ed-mono { (summary) }
                            }
                        }
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

// ────────────────────────────────────────────────────────────────────
//  Phase G — admin_alerts feed + ack action
// ────────────────────────────────────────────────────────────────────

/// `GET /admin/alerts?show=all` — operator-facing alerts feed. Default
/// view shows UNACKED only (the dashboard tile links here when count
/// > 0); `?show=all` includes acked rows for historical browsing.
pub(crate) async fn alerts(
    headers: HeaderMap,
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<AlertsQuery>,
) -> Result<Markup, Response> {
    let (theme, accent) = theme_accent(&headers);

    /// Generous cap — the feed wants enough history to spot patterns
    /// without paginating. Older rows are retention-pruned (acked
    /// >30d ago drops; unacked never).
    const ALERTS_LIMIT: i64 = 200;
    let include_acked = q.show.as_deref() == Some("all");
    let alerts_rows = state
        .inv
        .recent_alerts(ALERTS_LIMIT, include_acked)
        .await
        .map_err(|e| internal_error(anyhow::Error::new(e)))?;
    let unacked_total = state
        .inv
        .unacked_alert_count()
        .await
        .map_err(|e| internal_error(anyhow::Error::new(e)))?;

    let body = html! {
        div.ed-art-eyebrow { "Alerts" }
        h1.ed-art-h1 {
            "what the homelab is "
            em { "shouting" }
            " about"
        }
        p.ed-art-deck {
            "Infrastructure alerts written by the Phase G health-monitor "
            "on top of the Phase H node probe. Service flips, disk + "
            "memory pressure, runaway sing-box logs, unreachable hosts, "
            "and the «I locked myself out» class (fail2ban banned us). "
            "Ack each one when you've looked — the dashboard tile "
            em { "homelab health" } " counts unacked items."
        }
        div.ed-rule {}
        div style="display: flex; gap: 16px; align-items: baseline; margin-bottom: 14px;" {
            span.ed-mono { (unacked_total) " unacked" }
            @if include_acked {
                a href="/admin/alerts" style="color: var(--mute); text-decoration: none;" {
                    "← only unacked"
                }
            } @else {
                a href="/admin/alerts?show=all" style="color: var(--mute); text-decoration: none;" {
                    "show all (including acked) →"
                }
            }
        }
        @if alerts_rows.is_empty() {
            div.ed-empty {
                p {
                    @if include_acked {
                        "no alerts on record. Either the homelab has been "
                        em { "extraordinarily" }
                        " quiet, or vpnctld hasn't been running long enough "
                        "for the probe to fire one. Check "
                        span.ed-mono { "journalctl -u vpnctld -t vpnctld::health_monitor" }
                        " for the scan trail."
                    } @else {
                        "no unacked alerts. Everything the homelab is currently "
                        em { "complaining" }
                        " about lives here; nothing means nothing's wrong "
                        "(or every condition has been acknowledged). To "
                        "browse history: " a href="/admin/alerts?show=all" { "show all →" }
                    }
                }
            }
        } @else {
            (alerts_table(&alerts_rows))
        }
    };
    Ok(shell("alerts", &theme, &accent, body))
}

/// `POST /admin/alerts/{id}/ack` — operator dismisses one alert.
/// Idempotent: re-acking is a no-op. Always redirects back to
/// `/admin/alerts` (POST-redirect-GET so refresh-after-submit doesn't
/// re-submit). Writes an audit row with the alert id + kind so the
/// timeline shows who acknowledged what.
///
/// Path/State ordering: `Path` first, `State` after — matches the
/// convention used elsewhere in this file (`user_delete`,
/// `user_grant_server`). Caught by review-agent on the burst diff.
pub(crate) async fn alert_ack(
    axum::extract::Path(id): axum::extract::Path<i64>,
    State(state): State<AppState>,
) -> Response {
    // Reject negative / zero ids early — autoincrement starts at 1.
    // Treat as a no-op redirect rather than 400 to keep ack idempotent
    // (a stale form should not 4xx; the dashboard tile POSTs without
    // re-fetching the feed first).
    if id <= 0 {
        return Redirect::to("/admin/alerts").into_response();
    }
    let changed = match state.inv.ack_alert(id).await {
        Ok(b) => b,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    if changed {
        if let Err(e) = state
            .inv
            .audit(
                "admin",
                "alert.ack",
                Some(&id.to_string()),
                Some(&serde_json::json!({"alert_id": id})),
            )
            .await
        {
            // Audit write failed but the user-visible ack already
            // committed — surface at warn so the operator can grep
            // the journal if the audit timeline looks short.
            tracing::warn!(
                target = "vpnctld::admin::alert_ack",
                alert_id = id,
                error = %e,
                "ack succeeded but audit row failed; timeline will be missing this entry"
            );
        }
    }
    Redirect::to("/admin/alerts").into_response()
}

#[derive(serde::Deserialize, Debug, Default)]
pub(crate) struct AlertsQuery {
    /// `Some("all")` = include acked rows; default = unacked only.
    pub show: Option<String>,
}

/// Render the feed table — newest-first, severity badge, server link,
/// per-row ack button (hidden when already acked). Inline styles keep
/// this self-contained so admin.css doesn't need a Phase G section.
fn alerts_table(rows: &[vpnctl_inventory::AdminAlert]) -> Markup {
    html! {
        div.ed-time {
            @for a in rows {
                div.ed-time-row {
                    span.ed-time-row__t { (clip_ts(&a.created_at.to_rfc3339())) }
                    span class=(format!("ed-time-row__a ed-time-row__a--{}", severity_class(&a.severity))) {
                        (a.severity)
                    }
                    span.ed-time-row__tgt {
                        @match &a.server_id {
                            Some(sid) => {
                                a href=(format!("/admin/servers/{}", path_segment_encode(&sid.0)))
                                  style="color: var(--ink); text-decoration: none;" {
                                    (sid.0)
                                }
                            }
                            None => "—",
                        }
                    }
                    span.ed-time-row__pl {
                        span.ed-mono { (a.kind) }
                        " · " (a.summary)
                        @match &a.acked_at {
                            Some(when) => {
                                " · " span style="color: var(--mute);" {
                                    "acked " (clip_ts(&when.to_rfc3339()))
                                }
                            }
                            None => {
                                " · "
                                form method="post" action=(format!("/admin/alerts/{}/ack", a.id))
                                     style="display: inline;" {
                                    button type="submit"
                                           style="background: transparent; border: 1px solid var(--rule); color: var(--ink); font-family: var(--mono); font-size: 11px; padding: 2px 8px; cursor: pointer;" {
                                        "ack"
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Map alert severity string to an `ed-time-row__a--*` modifier class
/// matching what `audit_timeline_grouped` uses. Keeps colour-coding
/// consistent across the audit + alerts feeds.
fn severity_class(s: &str) -> &'static str {
    match s {
        "critical" => "fire",
        "warning" => "warn",
        "info" => "info",
        _ => "info",
    }
}

pub(crate) async fn settings(headers: HeaderMap, State(state): State<AppState>) -> Markup {
    let (theme, accent) = theme_accent(&headers);
    // Auto-generated by vpnctld on startup (see
    // `crate::app::DEFAULT_DEPLOY_KEY_PATH` + `ensure_deploy_key`).
    // Surfaces the public half so the operator can copy it into each
    // VPN node's `~/.ssh/authorized_keys`. Without this, the
    // clash-api poller + web-deploy "apply" steps can't reach the
    // node (per the operator-facing copy below).
    let deploy_key_path = std::path::Path::new(crate::app::DEFAULT_DEPLOY_KEY_PATH);
    let deploy_pubkey =
        crate::ssh_subprocess::read_public_key(deploy_key_path).map_err(|e| e.to_string());

    // Phase C-4 — inventory snapshots. Reads the canonical backup
    // dir (same path the scheduler writes to). Listing failure is
    // shown inline rather than 500-ing — the rest of Settings
    // (theme, deploy key) should still render.
    let backup_dir = std::path::PathBuf::from(crate::app::DEFAULT_BACKUP_DIR);
    let snapshots = vpnctl_inventory::list_snapshots(&backup_dir).map_err(|e| e.to_string());

    // Phase G chunk 3 — push notification transport config (Telegram
    // bot). Failure to read = render «(failed: …)» inline; don't
    // poison the rest of Settings.
    let telegram_cfg = state
        .inv
        .get_telegram_config()
        .await
        .map_err(|e| e.to_string());

    // Phase G chunk 3.5 — list inventory servers for the «proxy via»
    // dropdown. If the listing fails the dropdown shows only the
    // «direct» option (empty Vec) + the rest of Settings still renders.
    let servers_for_proxy_dropdown = state.inv.list_servers().await.unwrap_or_default();

    let body = html! {
        div.ed-art-eyebrow { "Settings" }
        h1.ed-art-h1 { "homelab " em { "controls" } }
        p.ed-art-deck {
            "Daemon-wide knobs live here. Server / user mutations live on their respective pages."
        }

        div.ed-rule {}
        div.ed-art-eyebrow { "Appearance — theme + accent" }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 12px;" {
            "Pick a paper theme (background palette) and an accent colour. Choices are stored as cookies; one-time configuration."
        }
        (tweaks_inline(&theme, &accent))

        div.ed-rule {}
        // `id` so `backup_snapshot_now`'s POST-redirect-GET can
        // anchor back to this section.
        div #backups-section.ed-art-eyebrow { "Backups — inventory snapshots" }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
            "vpnctld snapshots " span.ed-mono { (crate::app::DEFAULT_DEPLOY_KEY_PATH.replace("/.ssh/id_ed25519", "/inv.db")) }
            " hourly into "
            span.ed-mono { (crate::app::DEFAULT_BACKUP_DIR) }
            " (24 hourly + 30 daily + 12 monthly retained). "
            b { "Off-site is operator-driven" }
            " — click "
            em { "download" }
            " next to a snapshot and copy it to USB / Forgejo / cloud / wherever you trust. The daemon never pushes anywhere by itself."
        }
        div style="display: flex; gap: 12px; align-items: center; margin-bottom: 14px;" {
            form method="post" action="/admin/backup/snapshot" style="display: inline;" {
                button type="submit"
                       title="Take a snapshot now (in addition to the hourly schedule). Safe to click any time."
                       style="padding: 6px 14px; border: 1px solid var(--ink); background: var(--ink); color: var(--paper); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                    "snapshot now"
                }
            }
            span style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute);" {
                "Restore is a "
                span.ed-mono { "vpnctl restore <snapshot>" }
                " CLI command — the daemon can't replace its own open DB while it's holding it. See doc-comment in "
                span.ed-mono { "crates/inventory/src/backup.rs" }
                "."
            }
        }
        @match snapshots {
            Ok(list) if list.is_empty() => {
                p style="font-family: var(--serif); font-style: italic; color: var(--mute); font-size: 12px;" {
                    "No snapshots yet. The scheduler fires its first snapshot ~60 seconds after daemon start; click "
                    b { "snapshot now" }
                    " above to skip the wait."
                }
            }
            Ok(list) => {
                // Scrollable container so a 60-row backlog at the
                // retention policy's cap doesn't push the rest of
                // Settings (Deploy key, Telegram, etc) several
                // viewport-heights down. Sticky header keeps the
                // column labels visible while scrolling.
                div style="max-height: 360px; overflow-y: auto; border: 1px solid var(--rule);" {
                    table style="width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 11px;" {
                        thead style="position: sticky; top: 0; background: var(--paper); z-index: 1;" {
                            tr {
                                th style="text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--rule); color: var(--mute); font-weight: normal; letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { "created (UTC)" }
                                th style="text-align: right; padding: 6px 8px; border-bottom: 1px solid var(--rule); color: var(--mute); font-weight: normal; letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { "size" }
                                th style="text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--rule); color: var(--mute); font-weight: normal; letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { "action" }
                            }
                        }
                        tbody {
                            @for snap in list.iter().take(60) {
                                tr {
                                    td style="padding: 4px 8px; border-bottom: 1px dotted var(--rule);" {
                                        (snap.created.as_deref().unwrap_or("(unparseable timestamp)"))
                                    }
                                    td style="padding: 4px 8px; border-bottom: 1px dotted var(--rule); text-align: right; color: var(--soft);" {
                                        (format_size_bytes(snap.size_bytes))
                                    }
                                    td style="padding: 4px 8px; border-bottom: 1px dotted var(--rule);" {
                                        a href=(format!("/admin/backup/download/{}", path_segment_encode(&snap.file_name)))
                                          download=(&snap.file_name)
                                          title="Save this snapshot to your local disk for off-site storage"
                                          style="color: var(--ink); text-decoration: underline;" {
                                            "download"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                @if list.len() > 60 {
                    p style="font-family: var(--serif); font-style: italic; color: var(--mute); font-size: 11px; margin-top: 8px;" {
                        "(" (list.len() - 60) " older snapshot"
                        @if list.len() - 60 != 1 { "s" }
                        " hidden — the retention policy caps total count, so the table won't grow unbounded.)"
                    }
                }
            }
            Err(e) => {
                p style="font-family: var(--serif); font-style: italic; color: var(--red); font-size: 12px;" {
                    "Can't list snapshots in "
                    span.ed-mono { (crate::app::DEFAULT_BACKUP_DIR) }
                    ": " (e) ". Most likely the daemon user doesn't have access — check "
                    span.ed-mono { "ls -la /var/lib/vpnctl/" }
                    "."
                }
            }
        }

        div.ed-rule {}
        // `id` so the POST-redirect-GET after Save can use a
        // fragment anchor (`#telegram-notifications`) and the
        // browser scrolls back to this section instead of jumping
        // to the top of /admin/settings.
        div #telegram-notifications.ed-art-eyebrow { "Notifications — Telegram bot" }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
            "When an alert fires (probe-detector or service flip), vpnctld POSTs a one-line message to a Telegram chat via "
            span.ed-mono { "api.telegram.org/bot<token>/sendMessage" }
            ". One operator, one chat — paste the bot token and your numeric chat-id below. "
            "Create the bot via "
            span.ed-mono { "@BotFather" }
            " on Telegram; get your chat-id by messaging "
            span.ed-mono { "@userinfobot" }
            ". "
            b { "The token is a secret" }
            " — stored in "
            span.ed-mono { "/var/lib/vpnctl/inv.db" }
            " (daemon-owned 0640), masked in this page after save. Clear both fields and re-save to disable."
        }

        // Status line — tells the operator at a glance whether the
        // transport is wired. Three branches: config read failed,
        // both fields set ("enabled"), or partial/none ("disabled").
        @match &telegram_cfg {
            Err(e) => {
                p style="font-family: var(--serif); font-style: italic; color: var(--red); font-size: 12px;" {
                    "Can't read notification settings: " (e)
                }
            }
            Ok(None) => {
                // notification_settings singleton row missing — would
                // happen only if migration 0014 was rolled back. Loud
                // surface so the operator notices.
                p style="font-family: var(--serif); font-style: italic; color: var(--red); font-size: 12px;" {
                    "Settings row missing — migration 0014 didn't seed it. Daemon restart should re-run migrations."
                }
            }
            Ok(Some(cfg)) if cfg.is_enabled() => {
                p style="font-family: var(--mono); font-size: 12px; color: var(--ink); margin: 0 0 10px;" {
                    "Status: " b { "enabled" } " · token "
                    span style="color: var(--mute);" { "••••" (cfg.token_last4()) }
                    " · chat "
                    span style="color: var(--mute);" { (cfg.chat_id.as_deref().unwrap_or("")) }
                }
            }
            Ok(Some(cfg)) if cfg.token.is_some() || cfg.chat_id.is_some() => {
                // Partial config — one half present, the other NULL.
                // Common cause: operator pasted only one field on the
                // last save. Loud-ish surface so the stranded half is
                // visible (otherwise the «disabled» status hides the
                // fact that a token might still be sitting in inv.db).
                @let which_missing = if cfg.token.is_none() { "bot token" } else { "chat-id" };
                p style="font-family: var(--mono); font-size: 12px; color: var(--red); margin: 0 0 10px;" {
                    "Status: " b { "partial config" }
                    " — " (which_missing) " missing, transport effectively disabled. "
                    "Fill in the missing field below + save, OR clear both fields to fully reset."
                }
            }
            Ok(Some(_)) => {
                p style="font-family: var(--mono); font-size: 12px; color: var(--mute); margin: 0 0 10px;" {
                    "Status: " b style="color: var(--ink);" { "disabled" }
                    " — fill in both fields below + save."
                }
            }
        }

        form method="post" action="/admin/settings/telegram" style="margin: 0 0 14px;" {
            div style="display: grid; grid-template-columns: 140px 1fr; gap: 10px 14px; align-items: center; max-width: 720px;" {
                label for="telegram_bot_token" style="font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                    "bot token"
                }
                input type="password"
                      id="telegram_bot_token"
                      name="telegram_bot_token"
                      placeholder="leave blank to keep existing; paste new value to replace; clear BOTH fields to disable"
                      autocomplete="off"
                      style="font-family: var(--mono); font-size: 12px; padding: 5px 8px; border: 1px solid var(--rule); background: var(--paper);";
                label for="telegram_chat_id" style="font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                    "chat-id"
                }
                input type="text"
                      id="telegram_chat_id"
                      name="telegram_chat_id"
                      value=(match &telegram_cfg {
                          Ok(Some(cfg)) => cfg.chat_id.as_deref().unwrap_or(""),
                          _ => "",
                      })
                      placeholder="numeric, e.g. 123456789 (or @your_channel)"
                      style="font-family: var(--mono); font-size: 12px; padding: 5px 8px; border: 1px solid var(--rule); background: var(--paper);";

                // ─── Phase G chunk 3.5 — proxy-via-server dropdown ──
                label for="proxy_via_server_id" style="font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                    "egress"
                }
                @let current_proxy_id: &str = match &telegram_cfg {
                    Ok(Some(cfg)) => cfg.proxy_via_server_id.as_deref().unwrap_or(""),
                    _ => "",
                };
                select name="proxy_via_server_id"
                       id="proxy_via_server_id"
                       title="If the daemon host can't reach api.telegram.org directly (РФ blocks, NAT, etc), route the call through an inventory server's network instead. Uses the existing deploy SSH key — the public half must be on root@<proxy-server>:~/.ssh/authorized_keys (see «Deploy SSH key» section below to copy)."
                       style="font-family: var(--mono); font-size: 12px; padding: 5px 8px; border: 1px solid var(--rule); background: var(--paper);" {
                    option value="" selected[current_proxy_id.is_empty()] {
                        "direct (local network)"
                    }
                    @for s in &servers_for_proxy_dropdown {
                        option value=(s.id.0) selected[current_proxy_id == s.id.0] {
                            "via server: " (s.id.0) " (" (s.address) ")"
                        }
                    }
                }
            }

            @if servers_for_proxy_dropdown.is_empty() {
                p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 8px 0 0; max-width: 720px;" {
                    "No servers in inventory yet — only " b { "direct" } " egress is available. "
                    "Add a server on " span.ed-mono { "/admin/servers" }
                    " first if your daemon host can't reach " span.ed-mono { "api.telegram.org" } "."
                }
            } @else {
                p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 8px 0 0; max-width: 720px;" {
                    "Picking a " b { "via server: …" } " option requires the daemon's "
                    "deploy SSH pubkey to be on that server's "
                    span.ed-mono { "~/.ssh/authorized_keys" } ". The pubkey lives in the "
                    a href="#deploy-ssh-key" style="color: var(--ink);" {
                        b { "Deploy SSH key" }
                    }
                    " section below — copy it once, then "
                    em { "send test message" } " confirms the path works."
                }
            }

            div style="margin-top: 12px;" {
                button type="submit"
                       title="Save all three fields. Empty token = keep existing (unless chat-id is ALSO empty, then clear). Empty chat-id = clear. Egress dropdown is always overwritten with the selected value."
                       style="padding: 6px 14px; border: 1px solid var(--ink); background: var(--ink); color: var(--paper); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                    "save"
                }
            }
        }

        // Test-send button — separate form POSTing to /admin/settings/
        // telegram/test so the operator can verify their credentials
        // without waiting for an actual alert to fire. Disabled (greyed
        // out via inline disabled attr) when the transport isn't
        // currently enabled — same predicate the dispatch loop uses.
        @match &telegram_cfg {
            Ok(Some(cfg)) if cfg.is_enabled() => {
                form method="post" action="/admin/settings/telegram/test" style="margin-top: 10px;" {
                    button type="submit"
                           title="Send a test message to the configured chat. Surfaces curl / Telegram-API errors inline."
                           style="padding: 5px 12px; border: 1px solid var(--rule); background: var(--paper); color: var(--ink); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                        "send test message"
                    }
                    span style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin-left: 14px;" {
                        "Posts «🔵 vpnctld · info · test · vpnctld test message ...» to your chat."
                    }
                }
            }
            _ => {
                p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 10px 0 0;" {
                    "Test-send button appears after both fields are saved + status is "
                    b style="color: var(--ink);" { "enabled" } "."
                }
            }
        }

        div.ed-rule {}
        // `id` so the via-server SSH error message and any future
        // cross-link can anchor here. Eyebrow was previously
        // missing — fixed 2026-05-18 same commit that added the
        // anchor support.
        div #deploy-ssh-key.ed-art-eyebrow { "Deploy SSH key" }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
            "vpnctld auto-generated this Curve25519 keypair on first start. "
            "The private half stays in "
            span.ed-mono { (crate::app::DEFAULT_DEPLOY_KEY_PATH) }
            " — never shown. The public half (below) goes into each VPN node's "
            span.ed-mono { "~/.ssh/authorized_keys" }
            ". Once authorised, every "
            b { "deploy →" }
            " button click pushes configs through vpnctld → ssh subprocess → node, no operator-typed CLI needed."
        }
        @match deploy_pubkey {
            Ok(pk) => {
                pre style="font-family: var(--mono); font-size: 11px; padding: 12px 14px; background: var(--paper); border: 1px solid var(--rule); white-space: pre-wrap; word-break: break-all;" {
                    (pk)
                }
                p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 8px 0 0;" {
                    "Copy the line above. On each VPN node: "
                    span.ed-mono {
                        "echo '<paste>' >> ~/.ssh/authorized_keys && chmod 0600 ~/.ssh/authorized_keys"
                    }
                    "."
                }
            }
            Err(e) => {
                p style="font-family: var(--serif); font-style: italic; color: var(--red);" {
                    "Public key file unreadable: " (e) ". Most common cause: "
                    span.ed-mono { "/var/lib/vpnctl/.ssh" }
                    " not writable by the daemon. Check "
                    span.ed-mono { "ls -la /var/lib/vpnctl/" }
                    "; vpnctld writes there as the systemd-unit user (typically "
                    span.ed-mono { "user" } ")."
                }
            }
        }
    };
    shell("settings", &theme, &accent, body)
}

/// `POST /admin/servers/{id}/push-deploy-key` — append the daemon's
/// deploy pubkey to the server's `~/.ssh/authorized_keys` via sshpass.
/// Recovery action for servers added via quick-add / migrate-from-bash
/// (Phase E wizard does this automatically as step 3 of bootstrap).
///
/// Reuses [`crate::wizard_bootstrap::ssh_password_run`] so the remote
/// command is byte-identical to the wizard's push-key step. Idempotent
/// at the remote shell level (`grep -qxF || echo >>`), so a successful
/// click followed by an accidental second click is a no-op.
///
/// **Password handling:** the operator-typed password lives in the
/// SSHPASS env var of the sshpass child process — never in argv (so
/// `ps auxe` from non-root can't see it). After the SSH call returns,
/// the password string lives only on this handler's stack; not stored,
/// not logged, not in the audit payload.
///
/// **Audit row** written on both success + failure (operator action
/// either way). Payload: `{success: bool, error?: str}` — never the
/// password.
pub(crate) async fn server_push_deploy_key(
    Path(server_id_str): Path<String>,
    State(state): State<AppState>,
    body: String,
) -> Response {
    let sid = vpnctl_core::ServerId(server_id_str.clone());

    // Look up server. 404 if not in inventory.
    let server = match state.inv.get_server(&sid).await {
        Ok(Some(s)) => s,
        Ok(None) => return not_found(&format!("no such server '{server_id_str}'")),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };

    let password = form_field(&body, "root_password").unwrap_or_default();
    if password.is_empty() {
        return bad_request("root_password must not be empty");
    }

    // Read the daemon's deploy pubkey from disk. Same path the
    // Settings page surfaces + the wizard's BootstrapPlan uses.
    let key_path = std::path::Path::new(crate::app::DEFAULT_DEPLOY_KEY_PATH);
    let pubkey = match crate::ssh_subprocess::read_public_key(key_path) {
        Ok(p) => p,
        Err(e) => {
            return error_resp(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!(
                    "deploy pubkey unreadable at {}: {e}. \
                     Check /admin/settings (Deploy SSH key section) for the root cause.",
                    key_path.with_extension("pub").display()
                ),
            );
        }
    };

    // Idempotent remote append + chmod. Byte-identical to the
    // wizard's step 3 (push-key).
    let push_cmd = format!(
        "set -eu; \
         mkdir -p ~/.ssh && chmod 0700 ~/.ssh; \
         touch ~/.ssh/authorized_keys && chmod 0600 ~/.ssh/authorized_keys; \
         grep -qxF {pk_q} ~/.ssh/authorized_keys || echo {pk_q} >> ~/.ssh/authorized_keys; \
         echo done",
        pk_q = vpnctl_core::shell::single_quote(&pubkey),
    );

    // known_hosts path mirrors the wizard's default (and the
    // daemon's `SubprocessSshTransport` default for subsequent
    // pubkey-auth connects). Living in `/var/lib/vpnctl/.ssh/`
    // keeps it daemon-owned.
    let known_hosts = std::path::PathBuf::from("/var/lib/vpnctl/.ssh/known_hosts");

    let result = crate::wizard_bootstrap::ssh_password_run(
        &server.address,
        server.ssh_port,
        &server.ssh_user,
        &password,
        &known_hosts,
        &push_cmd,
    )
    .await;

    // Audit either way. Payload: server id, success, optional error.
    // Never the password (caller-owned secret); never the full sshpass
    // stderr (might quote the password verbatim if sshpass leaks it).
    let audit_payload = match &result {
        Ok(_) => serde_json::json!({"success": true, "server_id": &server_id_str}),
        Err(e) => serde_json::json!({
            "success": false,
            "server_id": &server_id_str,
            "error": e,
        }),
    };
    if let Err(audit_err) = state
        .inv
        .audit(
            "admin",
            "server.push_deploy_key",
            Some(&server_id_str),
            Some(&audit_payload),
        )
        .await
    {
        tracing::warn!(
            target = "vpnctld::admin::server_push_deploy_key",
            server = %server_id_str,
            error = %audit_err,
            "audit row failed; push result was {:?}",
            result.is_ok()
        );
    }

    match result {
        Ok(_) => {
            // Anchor scroll back to the section + a query flag a
            // future toast could read. For now the operator just
            // sees the page refresh; pubkey-auth verification
            // happens organically the next time the node probe
            // poller runs.
            Redirect::to(&format!(
                "/admin/servers/{}#push-deploy-key",
                path_segment_encode(&server_id_str)
            ))
            .into_response()
        }
        Err(e) => error_resp(
            StatusCode::BAD_GATEWAY,
            &format!(
                "push-deploy-key failed for {server_id_str}: {e} — \
                 common causes: wrong password, server's sshd disabled \
                 PasswordAuthentication (then you have to push the pubkey \
                 out-of-band — see /admin/settings → Deploy SSH key), \
                 server unreachable on configured port"
            ),
        ),
    }
}

/// `POST /admin/settings/telegram` — save the Telegram bot
/// transport config (Phase G chunk 3 part 1). Atomic update of both
/// fields. Either empty input → that field set to NULL in DB →
/// `is_enabled()` becomes false → transport disabled.
///
/// **Secret handling:** the token is NEVER logged or echoed back to
/// the operator after save. The audit_log payload records ONLY a
/// boolean («token set or cleared») + the chat_id; the token itself
/// stays in `notification_settings` only.
///
/// **Validation:**
///   * `token` shape: contains `:` and a non-trivial post-colon body
///     (Telegram bot tokens are `<bot_id>:<auth_hex>`); we don't pin
///     the exact length because BotFather has changed the format
///     across years.
///   * `chat_id`: either all-digits (with optional leading `-`) for
///     private chats / groups, OR `@<channel_name>` for public
///     channels.
///
/// Both checks reject obvious garbage with a 400 before the row is
/// written, so a typo doesn't silently kill alerts the operator
/// expects to receive.
pub(crate) async fn settings_telegram(State(state): State<AppState>, body: String) -> Response {
    let token_in = form_field(&body, "telegram_bot_token").unwrap_or_default();
    let chat_id_in = form_field(&body, "telegram_chat_id").unwrap_or_default();
    let token = token_in.trim();
    let chat_id = chat_id_in.trim();

    // Empty token semantics: «keep existing» NOT «clear». The «clear»
    // path requires the operator to clear BOTH fields (their browser
    // sends both inputs even when blank, so detecting clear-intent
    // means «chat_id is also empty»).
    let token_arg: Option<String> = if token.is_empty() {
        if chat_id.is_empty() {
            // Both empty → operator wants to disable. Clear both.
            None
        } else {
            // Operator changed chat_id but didn't paste a new token →
            // preserve the existing token. Fetch current.
            match state.inv.get_telegram_config().await {
                Ok(Some(cfg)) => cfg.token,
                // Singleton row missing — same condition the GET
                // handler surfaces in red on the page. Loud here too
                // so the operator doesn't silently disable the
                // transport while believing they updated chat_id.
                Ok(None) => {
                    return error_resp(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "notification_settings singleton row missing (migration 0014 not applied?) — restart vpnctld to re-run migrations, then re-save with token + chat-id both filled in",
                    );
                }
                Err(e) => return internal_error(anyhow::Error::new(e)),
            }
        }
    } else {
        // Shape gate: Telegram bot tokens always have a colon in the
        // middle. Reject obvious paste-error.
        if !token.contains(':') || token.len() < 20 {
            return bad_request(
                "bot token looks malformed (expected '<bot_id>:<auth_hex>' from @BotFather)",
            );
        }
        Some(token.to_string())
    };

    let chat_id_arg: Option<String> = if chat_id.is_empty() {
        None
    } else {
        // Shape gate: numeric (optionally leading `-`) or `@channel`.
        let looks_numeric = chat_id
            .strip_prefix('-')
            .unwrap_or(chat_id)
            .chars()
            .all(|c| c.is_ascii_digit())
            && !chat_id.is_empty()
            && chat_id != "-";
        let looks_channel = chat_id.starts_with('@')
            && chat_id.len() >= 2
            && chat_id[1..]
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_');
        if !looks_numeric && !looks_channel {
            return bad_request(
                "chat-id must be numeric (e.g. 123456789, or -100123... for supergroups) or '@channel_name'",
            );
        }
        Some(chat_id.to_string())
    };

    // ─── Phase G chunk 3.5 — proxy_via_server_id ─────────────────
    // Empty = direct (NULL in DB). Non-empty = inventory server id.
    // We DON'T validate the id against the inventory here because:
    //   (1) the dropdown can only emit existing ids OR empty;
    //   (2) if an operator hand-crafts a POST with a fake id, the
    //       build_alert_sink path will log + fall back to direct
    //       mode (loud-but-non-fatal), AND the test-send button will
    //       surface the SSH error the very next time they click it.
    let proxy_via_raw = form_field(&body, "proxy_via_server_id").unwrap_or_default();
    let proxy_arg: Option<String> = if proxy_via_raw.trim().is_empty() {
        None
    } else {
        Some(proxy_via_raw.trim().to_string())
    };

    if let Err(e) = state
        .inv
        .set_telegram_config(
            token_arg.as_deref(),
            chat_id_arg.as_deref(),
            proxy_arg.as_deref(),
        )
        .await
    {
        return internal_error(anyhow::Error::new(e));
    }

    // Audit row. Payload carries the chat_id + proxy_via_server_id
    // (both operator-visible anyway) + a boolean for «token state
    // changed». NEVER the token.
    if let Err(e) = state
        .inv
        .audit(
            "admin",
            "settings.telegram.set",
            None,
            Some(&serde_json::json!({
                "token_set": token_arg.is_some(),
                "chat_id_set": chat_id_arg.is_some(),
                "chat_id": chat_id_arg.as_deref().unwrap_or(""),
                "proxy_via_server_id": proxy_arg.as_deref().unwrap_or(""),
            })),
        )
        .await
    {
        tracing::warn!(
            target = "vpnctld::admin::settings_telegram",
            error = %e,
            "audit row for settings.telegram.set failed; config saved"
        );
    }

    // Fragment anchor → browser scrolls back to the Telegram
    // section instead of jumping to the top of /admin/settings
    // after Save / test-send.
    Redirect::to("/admin/settings#telegram-notifications").into_response()
}

/// `POST /admin/settings/telegram/test` — synchronously send a test
/// message via the currently-configured Telegram bot. Surfaces
/// success (redirect to /admin/settings) or failure (502 Bad Gateway
/// with the truncated curl-stderr line, so the operator can
/// distinguish «bot blocked», «wrong chat-id», «proxy down», «РФ
/// blocked api.telegram.org» without journalctl access).
///
/// Audit row written either way — operator action, regardless of
/// outcome. Payload includes `success: bool` + error string when
/// failed (NO token).
///
/// **NOT fire-and-forget** — unlike the probe-loop's push, this
/// handler awaits the curl call so the response carries the verdict.
/// Default timeout is 20s (curl `--max-time`), so the operator's
/// HTTP request can take that long in the worst case.
pub(crate) async fn settings_telegram_test(State(state): State<AppState>) -> Response {
    // Use the SAME sink-construction logic as the production push
    // loop (`node_probe_poller::build_alert_sink`) so the test-send
    // path doesn't drift on details like `proxy_via_server_id` —
    // operator's test verifies the exact same pipeline that real
    // alerts use.
    let sink = match crate::node_probe_poller::build_alert_sink(&state.inv).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return bad_request(
                "Telegram transport not configured — fill in both fields on /admin/settings first",
            );
        }
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };

    let send_result = sink
        .send_text(
            "test",
            "info",
            "vpnctld test message — Telegram bot is configured correctly. \
             Real alerts arrive with the same format.",
        )
        .await;

    // Audit either way.
    let audit_payload = match &send_result {
        Ok(()) => serde_json::json!({"success": true}),
        Err(e) => serde_json::json!({"success": false, "error": e.to_string()}),
    };
    if let Err(audit_err) = state
        .inv
        .audit(
            "admin",
            "settings.telegram.test_send",
            None,
            Some(&audit_payload),
        )
        .await
    {
        tracing::warn!(
            target = "vpnctld::admin::settings_telegram_test",
            error = %audit_err,
            "audit row for test_send failed; result was {:?}",
            send_result.is_ok()
        );
    }

    match send_result {
        Ok(()) => Redirect::to("/admin/settings").into_response(),
        Err(e) => error_resp(
            StatusCode::BAD_GATEWAY,
            &format!(
                "test-send failed: {e} — common causes: chat-id wrong (Telegram returns 'chat not found'), token revoked, bot never started conversation with you (open the bot in Telegram + tap Start), api.telegram.org blocked (set VPNCTLD_HTTPS_PROXY env)"
            ),
        ),
    }
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
        return bad_request(&format!(
            "invalid value '{value}' for tweak '{cookie_name}' (allowed: {})",
            valid.join(", ")
        ));
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

/// Path `/admin/tweak/{kind}` dispatcher — `kind` is "theme" or
/// "accent". Pre-2026-05-17 a third "tweaks" kind toggled the
/// floating panel; gone with the panel.
pub(crate) async fn set_tweak(
    headers: HeaderMap,
    Path(kind): Path<String>,
    body: String,
) -> Response {
    match kind.as_str() {
        "theme" => set_tweak_cookie(&headers, COOKIE_THEME, VALID_THEMES, &body),
        "accent" => set_tweak_cookie(&headers, COOKIE_ACCENT, VALID_ACCENTS, &body),
        unknown => not_found(&format!(
            "unknown tweak kind '{unknown}' (known: theme, accent)"
        )),
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

// `form_field(body, name) -> Option<String>` moved to
// `crate::http_util::form_field` (2026-05-18) — same shape, now the
// single source of truth. The wizard's local copy was identical;
// `user_create` / `server_quick_add` / `set_traffic_limit` and 7
// other handlers used a different inline pattern (`unwrap_or("")` +
// `decode_form_value`) that's now `form_field(...).unwrap_or_default()`.

/// `GET /admin/servers/new` — render the wizard's step-1 form.
///
/// Two fields: server address (IP or hostname) and root password.
/// Submit POSTs to the same URL; success goes to `/admin/servers/new/step-2`.
/// Cancel link leads back to `/admin/servers`.
pub(crate) async fn wizard_new(headers: HeaderMap) -> Markup {
    let (theme, accent) = theme_accent(&headers);
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
            div style="display: flex; flex-direction: column; gap: 4px;" {
                label for="ssh_port"
                      style="font-family: var(--mono); font-size: 11px; color: var(--mute); letter-spacing: 0.14em; text-transform: uppercase;" {
                    "ssh port (optional, default 22)"
                }
                input id="ssh_port" name="ssh_port" type="text" inputmode="numeric"
                      placeholder="22"
                      autocomplete="off" autocapitalize="none" spellcheck="false"
                      pattern="[0-9]*"
                      title="leave blank for 22; Cloudzy ships 2222"
                      style="padding: 6px 10px; border: 1px solid var(--rule-s); background: var(--paper); font-family: var(--mono); font-size: 13px; color: var(--ink); max-width: 140px;";
                p style="font-family: var(--serif); font-style: italic; font-size: 11.5px; color: var(--mute); margin: 0;" {
                    "Leave blank for 22 (the common case). Cloudzy is " span.ed-mono { "2222" } "; check the hoster's panel if SSH connect-fails on the next screen."
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
    shell("servers", &theme, &accent, body)
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
    let port_raw = form_field(&body, "ssh_port").unwrap_or_default();

    let address = match crate::wizard::validate_address(&address_raw) {
        Ok(s) => s.to_string(),
        Err(why) => {
            return bad_request(&format!("invalid address — {why}"));
        }
    };
    if let Err(why) = crate::wizard::validate_password(&password_raw) {
        return bad_request(&format!("invalid root password — {why}"));
    }
    let ssh_port = match crate::wizard::validate_ssh_port(&port_raw) {
        Ok(p) => p,
        Err(why) => {
            return bad_request(&format!("invalid ssh_port — {why}"));
        }
    };

    let session_id = state.wizard.insert(address, password_raw, ssh_port);

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

/// `GET /admin/servers/new/step-2` — render the streaming-bootstrap
/// page. Pulls the wizard session out of the cookie (same store as
/// step 1 wrote into), then renders a page whose body has:
///
///   * a header with the address being bootstrapped,
///   * a live `<pre>` log pane that an inline EventSource fills in
///     line-by-line as the bootstrap progresses,
///   * a footer that swaps to a "✓ done — go to <server>" link when
///     the bootstrap completes successfully, OR a fail summary +
///     "← start over" link on error.
///
/// The actual bootstrap work happens in `wizard_step2_sse` (the
/// EventSource source), which calls into
/// `crate::wizard_bootstrap::run_bootstrap`. Splitting the page
/// from the stream lets the operator hit refresh during a
/// bootstrap and resume watching (the bootstrap is in flight on
/// the daemon; the SSE just attaches a new viewer).
///
/// On missing/expired session: 400 + canonical error body — the
/// operator's session has timed out and there's nothing actionable
/// on this screen without it.
pub(crate) async fn wizard_step2_stub(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Response {
    let (theme, accent) = theme_accent(&headers);
    let session =
        read_cookie(&headers, crate::wizard::COOKIE_NAME).and_then(|id| state.wizard.get(id));

    let session = match session {
        Some(s) => s,
        None => {
            // No session = direct hit on step-2 without going through
            // step-1, OR the session expired (10-min TTL). Either way
            // the operator needs to start over.
            return bad_request(
                "wizard session expired or missing — start over from /admin/servers/new",
            );
        }
    };

    // The EventSource URL re-uses the same cookie — the browser
    // ships it automatically because the cookie Path is
    // `/admin/servers/new` (which covers the SSE endpoint too).
    let body = html! {
        div.ed-art-eyebrow { "Add server · step 2 of 3" }
        h1.ed-art-h1 {
            "Bootstrapping " span.ed-mono { (session.address) }
        }
        p.ed-art-deck {
            "The daemon is SSHing in as " span.ed-mono { "root" }
            " (one-time password use), pushing its deploy key, locking down "
            "the host, installing " span.ed-mono { "sing-box" }
            " and pushing the rendered config. Every step shows up below "
            "as it happens. Don't close this tab — refresh is fine, the "
            "bootstrap runs server-side and you'll re-attach."
        }
        div id="wizard-status" role="status"
            style="margin: 18px 0 6px 0; padding: 8px 14px; border: 1px solid var(--rule); background: var(--paper); font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                "connecting…"
        }
        pre id="wizard-log"
            style="margin: 0 0 18px 0; padding: 14px 18px; border: 1px solid var(--rule); background: var(--paper); font-family: var(--mono); font-size: 12px; line-height: 1.5; color: var(--ink); max-height: 480px; overflow-y: auto; white-space: pre-wrap;" {
            "▸ waiting for the daemon…\n"
        }
        div id="wizard-actions" style="display: flex; gap: 12px; align-items: center;" {
            a href="/admin/servers/new"
              style="font-family: var(--mono); font-size: 11px; color: var(--mute); text-decoration: none;" {
                "← start over"
            }
        }
        // The EventSource emits `step` / `ok` / `error` named events;
        // we attach a handler to each and append to the log. On `ok`
        // we navigate to the success URL; on `error` we leave the
        // log as-is so the operator can read what went wrong.
        //
        // No external JS dep — the whole client is ~30 lines of
        // hand-written script that any 2026-era browser supports
        // natively (EventSource is in every browser since IE was
        // alive). Inline rather than a separate asset because it's
        // tiny and the rest of the admin UI has no other JS files
        // to belong to.
        script {
            (maud::PreEscaped(r#"
(function () {
    var log = document.getElementById('wizard-log');
    var status = document.getElementById('wizard-status');
    var actions = document.getElementById('wizard-actions');
    var es = new EventSource('/admin/servers/new/step-2/sse');

    function append(line, cls) {
        var span = document.createElement('span');
        span.textContent = line + '\n';
        if (cls) { span.className = cls; }
        log.appendChild(span);
        log.scrollTop = log.scrollHeight;
    }

    es.addEventListener('step', function (ev) {
        try {
            var d = JSON.parse(ev.data);
            append('▸ [' + d.phase + '] ' + d.message);
            status.textContent = d.phase;
        } catch (e) { append('(unparsable step event: ' + ev.data + ')'); }
    });
    es.addEventListener('ok', function (ev) {
        try {
            var d = JSON.parse(ev.data);
            append('✓ done — server ' + d.server_id + ' is live.');
            status.textContent = 'done';
            status.style.color = 'var(--ink)';
            var a = document.createElement('a');
            a.href = d.redirect;
            a.textContent = '→ open ' + d.server_id;
            a.style.cssText = 'font-family: var(--mono); font-size: 12px; color: var(--ink); border: 1px solid var(--ink); padding: 6px 12px; text-decoration: none;';
            actions.prepend(a);
            // Auto-redirect after 2s so a passive operator (the most
            // common case) lands on the detail page without an extra
            // click. Operator wanting to re-read the log can hit Esc
            // or click ← start over.
            setTimeout(function () { window.location.href = d.redirect; }, 2000);
        } catch (e) { append('(unparsable ok event: ' + ev.data + ')'); }
        es.close();
    });
    es.addEventListener('error', function (ev) {
        // Browsers fire a generic 'error' event when the connection
        // closes (including after our last 'ok' or 'error' event).
        // We only treat it as a real failure if there's a payload.
        if (ev.data) {
            try {
                var d = JSON.parse(ev.data);
                append('✗ FAILED at [' + d.phase + ']: ' + d.message, 'wizard-err');
                status.textContent = 'failed at ' + d.phase;
                status.style.color = 'var(--acc)';
            } catch (e) { append('(unparsable error event: ' + ev.data + ')'); }
            es.close();
        } else if (es.readyState === EventSource.CLOSED) {
            // Connection ended without a terminal event. This means
            // the daemon dropped the connection mid-stream (rare —
            // usually the SSE handler always finishes with `ok` or
            // `error`). Show a graceful note.
            status.textContent = 'connection closed';
        }
    });
    es.addEventListener('open', function () {
        status.textContent = 'streaming…';
    });
})();
"#))
        }
    };
    shell("servers", &theme, &accent, body).into_response()
}

/// `GET /admin/servers/new/step-2/sse` — the EventSource endpoint
/// the step-2 page connects to. Reads the wizard cookie, fetches the
/// session, builds a `BootstrapPlan`, then streams events from
/// `wizard_bootstrap::run_bootstrap` as Server-Sent Events.
///
/// Events use the named-event form (`event: step\ndata: {json}\n\n`)
/// so the front-end can attach separate handlers per event type via
/// `EventSource.addEventListener('step', …)`. Saves us writing a
/// discriminator in the client JSON parser.
///
/// **Why we delete the session on first attach**: the wizard runs
/// exactly once. After the first SSE handler starts the bootstrap,
/// the session is consumed — re-opening the URL would re-run the
/// whole pipeline (including a second `inv.add_server` that fails
/// with AlreadyExists). Single-shot is the only sane semantics.
pub(crate) async fn wizard_step2_sse(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Response {
    use axum::response::sse::{Event, KeepAlive, Sse};
    use futures_core::Stream;
    use std::pin::Pin;
    use tokio_stream::StreamExt;

    let cookie = read_cookie(&headers, crate::wizard::COOKIE_NAME).map(str::to_string);
    let Some(session_id) = cookie else {
        return bad_request("wizard session missing — start over from /admin/servers/new");
    };
    let Some(session) = state.wizard.get(&session_id) else {
        return bad_request("wizard session expired — start over from /admin/servers/new");
    };
    // Single-shot semantics — after the SSE handler attaches, the
    // session is gone. Refresh on the page falls back to the
    // "session missing" branch (with a "start over" link).
    state.wizard.remove(&session_id);

    // Derive a non-colliding server id from the address. If the
    // operator wizards the same IP twice, `find_available_server_id`
    // picks `<id>-2`, `<id>-3`, … (bounded to avoid an infinite
    // loop on a corrupt inventory). Pure helper — unit-tested in
    // `wizard_bootstrap::tests`.
    let base_id = crate::wizard_bootstrap::derive_server_id(&session.address);
    if base_id.is_empty() {
        // Should be impossible — wizard validates address upfront —
        // but defensive: empty id would fail inv.add_server with a
        // useless error. Surface upfront instead.
        return bad_request(
            "address didn't produce any safe id chars — start over with a different address",
        );
    }
    let existing: std::collections::HashSet<String> = match state.inv.list_servers().await {
        Ok(list) => list.into_iter().map(|s| s.id.0).collect(),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    let server_id = match crate::wizard_bootstrap::find_available_server_id(&existing, &base_id) {
        Ok(s) => s,
        Err(e) => return error_resp(StatusCode::CONFLICT, &e),
    };

    let plan = crate::wizard_bootstrap::BootstrapPlan {
        server_id,
        address: session.address,
        ssh_port: session.ssh_port,
        root_password: session.root_password,
        deploy_key_path: std::path::PathBuf::from(crate::app::DEFAULT_DEPLOY_KEY_PATH),
        known_hosts_path: std::path::PathBuf::from("/var/lib/vpnctl/.ssh/known_hosts"),
    };

    // Map each BootstrapEvent → axum SSE Event with a named event
    // type. The infallible Result wrapper is what axum's Sse::new
    // expects (`Result<Event, Error>`) — we never produce errors
    // here because the bootstrap pipeline encodes failures as
    // `BootstrapEvent::Error` payloads, not stream-level errors.
    let inv = state.inv.clone();
    let registry = std::sync::Arc::clone(&state.registry);
    let raw = crate::wizard_bootstrap::run_bootstrap(plan, inv, registry);
    let mapped = raw.map(|ev| {
        let name = match &ev {
            crate::wizard_bootstrap::BootstrapEvent::Step { .. } => "step",
            crate::wizard_bootstrap::BootstrapEvent::Ok { .. } => "ok",
            crate::wizard_bootstrap::BootstrapEvent::Error { .. } => "error",
        };
        // The SSE Event is built from the JSON-serialised payload.
        // serde_json failure is effectively impossible on our
        // BootstrapEvent types (basic Rust strings + integers,
        // tagged enum), but if it ever happens we keep the original
        // event name and log loudly — silently swapping to a fake
        // error event would have the front-end think a `step` was a
        // terminal failure.
        let json = serde_json::to_string(&ev).unwrap_or_else(|e| {
            tracing::error!(
                target = "vpnctld::wizard",
                event_name = name,
                error = %e,
                "wizard SSE event serialisation failed — emitting placeholder"
            );
            format!("{{\"kind\":\"step\",\"phase\":\"serialise-error\",\"message\":\"daemon failed to serialise this event ({e}); see vpnctld logs\"}}")
        });
        Ok::<_, std::convert::Infallible>(Event::default().event(name).data(json))
    });

    // Box the stream so the return type fits a single Pin<Box<dyn …>>.
    // Without this, `Sse::new` would carry the unnameable `impl
    // Stream` type all the way up to the route registration.
    let stream: Pin<
        Box<dyn Stream<Item = std::result::Result<Event, std::convert::Infallible>> + Send>,
    > = Box::pin(mapped);

    // KeepAlive sends `: keep-alive\n\n` comments every 15s so
    // intermediate proxies (or a tab in the background) don't drop
    // the connection during a long apt-get install.
    Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(std::time::Duration::from_secs(15)))
        .into_response()
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
/// Look up expected `(proto, port)` tuples for a given protocol via
/// the registry. **Single source of truth** — each protocol owns its
/// own `listen_ports()` (see `vpnctl_core::Protocol`), so adding a
/// new protocol doesn't require touching this function. (Refactored
/// 2026-05-16 per review-agent finding — previous hand-maintained
/// map violated kernel/protocol orthogonality.)
fn expected_ports_for_protocol(
    registry: &vpnctl_core::Registry,
    pid: &vpnctl_core::ProtocolId,
) -> Vec<(String, u16)> {
    match registry.protocol(pid) {
        Some(p) => p
            .listen_ports()
            .iter()
            .map(|(s, n)| ((*s).to_string(), *n))
            .collect(),
        None => Vec::new(),
    }
}

pub(crate) async fn server_detail(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(server_id_str): Path<String>,
) -> Result<Markup, Response> {
    let (theme, accent) = theme_accent(&headers);
    let sid = vpnctl_core::ServerId(server_id_str.clone());

    let server = match state.inv.get_server(&sid).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return Err(not_found(&format!("no such server '{server_id_str}'")));
        }
        Err(e) => return Err(internal_error(anyhow::Error::new(e))),
    };

    let users = state
        .inv
        .users_for_server(&sid)
        .await
        .map_err(|e| internal_error(anyhow::Error::new(e)))?;
    let user_count = users.len();
    // Pavel iter B: centralised grants — also load the full user list
    // so the operator can grant access to non-granted users without
    // navigating to each user's page.
    let all_users = state
        .inv
        .list_users()
        .await
        .map_err(|e| internal_error(anyhow::Error::new(e)))?;
    let granted_user_ids: std::collections::HashSet<vpnctl_core::UserId> =
        users.iter().map(|u| u.id.clone()).collect();

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
        .flat_map(|pid| expected_ports_for_protocol(&state.registry, pid))
        .collect();

    let missing: Vec<_> = expected.difference(&observed).cloned().collect();
    // SSH is always listening — never "extra drift". Use the
    // server's CONFIGURED port (Cloudzy is on 2222, DO sticks on 22,
    // future hosters could be anything). Hardcoded 22 was caught by
    // review-agent: false-positive drift on Cloudzy nodes.
    let ssh_port = server.ssh_port;
    let extra: Vec<_> = observed
        .difference(&expected)
        .filter(|(proto, port)| !(proto == "tcp" && *port == ssh_port))
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
            " · "
            @if server.kernels.len() == 1 { "kernel " } @else { "kernels " }
            span.ed-mono {
                (server.kernels.iter().map(|k| k.0.clone()).collect::<Vec<_>>().join("+"))
            }
        }

        // Operator-facing Deploy button. Per CLAUDE.md "Web is the
        // ONLY operator surface" — Pavel must never need to open
        // a terminal. One click does the FULL deploy cycle:
        //   1. mint any missing per-protocol server secrets (REALITY
        //      keypair, WG server keypair, Hy2 obfs password) via
        //      `bootstrap_server_secrets` — idempotent,
        //   2. for each enabled kernel: SSH-push install
        //      (`ensure_installed`: apt-get + start) + render config +
        //      `apply_config` (systemctl restart),
        //   3. write an `admin / server.deploy` audit row with the
        //      bootstrapped secrets + per-kernel push result.
        //
        // Re-clicking is safe — already-minted secrets are left
        // untouched; already-installed kernels skip apt-get; config
        // render is deterministic so a redeploy with no changes is a
        // no-op systemctl restart.
        div style="margin: 12px 0 18px;" {
            form method="post"
                 action=(format!("/admin/servers/{}/deploy", path_segment_encode(&server.id.0)))
                 style="display: inline;" {
                button type="submit"
                       title="Full deploy: mint missing per-protocol server secrets, then SSH into the node and run apt-get install + render-config + systemctl restart for each enabled kernel. Re-clicking is safe — already-present secrets and kernels are skipped."
                       style="padding: 6px 14px; border: 1px solid var(--ink); background: var(--ink); color: var(--paper); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                    "deploy →"
                }
            }
            span style="margin-left: 12px; font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute);" {
                "Mints missing secrets, SSH-pushes "
                span.ed-mono { "ensure_installed" } " + " span.ed-mono { "apply_config" }
                " for every kernel, restarts the service. Subscription URLs reflect the new config immediately."
            }
            " · hoster " b { (server.hoster) }
        }

        // Hero: current state (live or empty-state)
        (server_detail_hero(&latest, &server))

        // Declared vs observed drift
        (server_detail_drift_section(&server, &observed, &missing, &extra, latest.is_some()))

        // Kernels — multi-kernel runtime selection. Mirrors the
        // Protocols section right below; same enable/disable shape.
        // Adding wireguard support to a node that today runs only
        // sing-box now means: enable amneziawg kernel here →
        // enable wireguard protocol below → `vpnctl deploy`.
        (server_detail_kernels_section(&server, &state.registry))

        // Enabled protocols — checkbox list of every registered protocol
        // with current enable state. Toggle posts back to this same
        // page (303 redirect). Changes take effect on the NEXT
        // `vpnctl deploy <server>` — inventory mutation alone doesn't
        // touch the live sing-box config (deliberate: we never push
        // without operator-initiated deploy).
        (server_detail_protocols_section(&server, &state.registry))

        // Trusted host fingerprint — TOFU pin for the daemon's SSH
        // probe + clash-api poller + deploy. The CLAUDE.md note from
        // vps-is-01 import (2026-05-16): «CLI command for this missing
        // — TODO for vpnctl: `vpnctl server set-fingerprint <id>`».
        // Web equivalent lives here so the operator never has to drop
        // to a shell + raw SQL just to pin a host key.
        (server_detail_fingerprint_section(&server))

        // Push deploy key — recovery action for servers added via
        // quick-add / migrate-from-bash where the wizard's step-3
        // pubkey push never ran. Phase G chunk 3.5 follow-up; the
        // user's «почему это не делается автоматически» surfaced
        // the gap.
        (server_detail_push_deploy_key_section(&server))

        // Grants — centralised per-server view (Pavel iter B).
        // Lists EVERY user with a per-row grant/revoke form, so the
        // operator doesn't have to bounce through each user's page
        // to manage access on a node. Same shape as the per-user
        // Server-access section, just transposed.
        div.ed-rule {}
        div.ed-art-eyebrow { "Grants" }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
            (user_count) " of " (all_users.len()) " "
            @if all_users.len() == 1 { "user" } @else { "users" }
            " have access on this server. Toggle below — POST returns 303 here."
        }
        @if all_users.is_empty() {
            p style="font-family: var(--serif); font-style: italic; color: var(--mute); padding: 8px 0;" {
                "No users in the inventory yet. Create one on "
                a href="/admin/users" style="color: var(--ink);" { "/admin/users" }
                " — then come back to grant access."
            }
        } @else {
            ul style="list-style: none; padding: 0; font-family: var(--serif); font-size: 14px; line-height: 1.8;" {
                @for u in &all_users {
                    @let sid_enc = path_segment_encode(&server.id.0);
                    @let uid_enc = path_segment_encode(&u.id.0);
                    li style="display: flex; align-items: baseline; gap: 12px; padding: 4px 0; border-bottom: 1px dotted var(--rule);" {
                        span style="flex: 1;" {
                            a href=(format!("/admin/users/{uid_enc}"))
                              style="color: var(--ink); text-decoration: none;" {
                                b { (u.id.0) }
                            }
                        }
                        @if granted_user_ids.contains(&u.id) {
                            span style="font-family: var(--mono); font-size: 11px; color: var(--acc);" { "✓ access" }
                            // Server-side route — redirect back HERE.
                            form method="post"
                                 action=(format!("/admin/servers/{sid_enc}/grants/{uid_enc}/revoke"))
                                 style="margin: 0; padding: 0;" {
                                button type="submit"
                                       title=(format!("Revoke {}'s access on {}", u.id.0, server.id.0))
                                       style="padding: 2px 8px; border: 1px solid var(--ink); background: transparent; font-family: var(--mono); font-size: 11px; color: var(--ink); cursor: pointer;" {
                                    "revoke"
                                }
                            }
                        } @else {
                            span style="font-family: var(--mono); font-size: 11px; color: var(--mute);" { "—" }
                            form method="post"
                                 action=(format!("/admin/servers/{sid_enc}/grants/{uid_enc}"))
                                 style="margin: 0; padding: 0;" {
                                button type="submit"
                                       title=(format!("Grant {} access on {}", u.id.0, server.id.0))
                                       style="padding: 2px 8px; border: 1px solid var(--ink); background: var(--ink); color: var(--paper); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                                    "grant"
                                }
                            }
                        }
                    }
                }
            }
        }
    };
    Ok(shell("servers", &theme, &accent, body))
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
/// Kernels editor — one row per kernel registered in the registry,
/// with enable/disable form. Mirrors the protocols section directly
/// below it. Per CLAUDE.md architectural principle (Kernel ×
/// Protocol orthogonality), adding a new kernel here is the first
/// step before enabling protocols that only that kernel supports
/// (e.g. amneziawg → then wireguard).
fn server_detail_kernels_section(
    server: &vpnctl_core::Server,
    registry: &vpnctl_core::Registry,
) -> Markup {
    let enabled: std::collections::HashSet<&vpnctl_core::KernelId> =
        server.kernels.iter().collect();
    let all_kernels = registry.kernel_ids();
    let sid_enc = path_segment_encode(&server.id.0);
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow { "Kernels" }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
            "Daemons running on this node. One physical VPS can host multiple "
            "(sing-box on 443/TCP + amneziawg on 51820/UDP cohabit cleanly). "
            "Each kernel installs/restarts independently; "
            span.ed-mono { "vpnctl deploy " (server.id.0) }
            " loops through every enabled kernel."
        }
        ul style="list-style: none; padding: 0; font-family: var(--mono); font-size: 12px; line-height: 1.8;" {
            @for kid in &all_kernels {
                @let is_on = enabled.contains(kid);
                @let supported = registry.kernel(kid)
                    .map(|k| k.supported_protocols()
                        .into_iter()
                        .map(|p| p.0)
                        .collect::<Vec<_>>()
                        .join(", "))
                    .unwrap_or_default();
                li style="display: flex; align-items: baseline; gap: 12px; padding: 4px 0; border-bottom: 1px dotted var(--rule);" {
                    span style="flex: 1;" {
                        (kid.0)
                        " "
                        span style="font-size: 10px; color: var(--mute); font-style: italic; font-family: var(--serif);" {
                            "(runs: " (supported) ")"
                        }
                    }
                    @if is_on {
                        span style="font-family: var(--mono); font-size: 11px; color: var(--acc); margin-right: 4px;" {
                            "✓ on"
                        }
                        form method="post"
                             action=(format!("/admin/servers/{}/kernels/{}/disable", sid_enc, path_segment_encode(&kid.0)))
                             style="margin: 0; padding: 0;" {
                            button type="submit"
                                   title=(format!("Remove {} from {}.kernels. Takes effect on next deploy.", kid.0, server.id.0))
                                   style="padding: 2px 8px; border: 1px solid var(--ink); background: transparent; font-family: var(--mono); font-size: 11px; color: var(--ink); cursor: pointer;" {
                                "disable"
                            }
                        }
                    } @else {
                        span style="font-family: var(--mono); font-size: 11px; color: var(--mute); margin-right: 4px;" {
                            "—"
                        }
                        form method="post"
                             action=(format!("/admin/servers/{}/kernels/{}/enable", sid_enc, path_segment_encode(&kid.0)))
                             style="margin: 0; padding: 0;" {
                            button type="submit"
                                   title=(format!("Add {} to {}.kernels. Takes effect on next deploy.", kid.0, server.id.0))
                                   style="padding: 2px 8px; border: 1px solid var(--ink); background: var(--ink); color: var(--paper); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                                "enable"
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Enabled-protocols editor — one row per protocol registered in the
/// registry, each with a `[on|off]` form that toggles the (server,
/// Trusted host SSH fingerprint section — shows current pinned
/// fingerprint (if any) plus a form for the operator to set / replace
/// it. Two paths:
///   * paste a `SHA256:…` literal (when the operator already has it),
///   * "Auto-detect" button → POST that runs `ssh-keyscan +
///     ssh-keygen -lf -` server-side, pins the resulting fingerprint.
///
/// Both go to the same `POST /admin/servers/{id}/set-fingerprint`
/// route; the form's hidden `mode=keyscan` differentiates.
/// Phase G chunk 3.5 follow-up — «Push deploy key» recovery action.
///
/// The Phase E wizard at `/admin/servers/new` does this automatically
/// as step 3 of bootstrap (sshpass + `mkdir -p ~/.ssh && grep -qxF ||
/// echo ... >>`). But three operator paths leave a server in
/// inventory WITHOUT the daemon's pubkey on it:
///
///   * **migrate-from-bash** — imported pre-existing servers that
///     have their own SSH key infra, daemon's key never pushed
///   * **quick-add** (`POST /admin/servers`) — minimal form, only
///     id + address + port; no password field, no push
///   * **wizard failure mid-flow** — bootstrap got past step 1-2
///     but failed before step 3 completed (rare)
///
/// All three leave Pavel with the «open a terminal + ssh root@…
/// + paste the pubkey» chore. This section makes it a single click
/// + paste-password instead.
///
/// Reuses `wizard_bootstrap::ssh_password_run` so the actual remote
/// command is byte-identical to what the wizard runs (idempotent
/// `grep -qxF || echo >>` — re-clicking after success is safe).
fn server_detail_push_deploy_key_section(server: &vpnctl_core::Server) -> Markup {
    let sid_enc = path_segment_encode(&server.id.0);
    html! {
        div.ed-rule {}
        div #push-deploy-key.ed-art-eyebrow { "Deploy SSH key — push to this server" }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px; max-width: 760px;" {
            "Daemon needs its pubkey on this server's "
            span.ed-mono { "~/.ssh/authorized_keys" }
            " before probes, deploys, or the Telegram via-server proxy can work. "
            "The Phase E wizard at "
            span.ed-mono { "/admin/servers/new" }
            " does this automatically; if the server was added via "
            span.ed-mono { "quick-add" }
            " / "
            span.ed-mono { "migrate-from-bash" }
            " (or you're not sure), push the key here. "
            "Idempotent — re-clicking after success appends nothing (uses "
            span.ed-mono { "grep -qxF || echo" }
            "). Password is used ONCE, sent via "
            span.ed-mono { "SSHPASS" }
            " env var (never in argv), then discarded."
        }
        form method="post"
             action=(format!("/admin/servers/{sid_enc}/push-deploy-key"))
             style="margin: 0 0 14px;" {
            div style="display: grid; grid-template-columns: 140px 1fr; gap: 10px 14px; align-items: center; max-width: 560px;" {
                label style="font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                    "root password"
                }
                input type="password"
                      name="root_password"
                      autocomplete="off"
                      placeholder="never stored — used once for the SSH connect, then discarded"
                      required
                      style="font-family: var(--mono); font-size: 12px; padding: 5px 8px; border: 1px solid var(--rule); background: var(--paper);";
            }
            div style="margin-top: 12px;" {
                button type="submit"
                       title="SSH to the server using sshpass + the password below, append the daemon's deploy pubkey to ~/.ssh/authorized_keys, then verify with a pubkey-auth round-trip."
                       style="padding: 6px 14px; border: 1px solid var(--ink); background: var(--ink); color: var(--paper); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                    "push deploy key"
                }
                span style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin-left: 14px;" {
                    "Connects to " span.ed-mono { (server.ssh_user) "@" (server.address) ":" (server.ssh_port) }
                }
            }
        }
    }
}

fn server_detail_fingerprint_section(server: &vpnctl_core::Server) -> Markup {
    let sid_enc = path_segment_encode(&server.id.0);
    let current = server.trusted_host_fingerprint.clone();
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow { "Trusted host fingerprint" }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
            "Pinned SHA-256 of the node's SSH ed25519 host key. vpnctld + "
            "the deploy / probe / clash-poller pipelines all refuse to "
            "talk to a host whose live key doesn't match this value — "
            "TOFU pin, set once. Update only if the node was legitimately "
            "rebuilt (and re-confirm via console)."
        }
        div style="font-family: var(--mono); font-size: 12px; padding: 8px 12px; background: var(--paper-tint); border: 1px solid var(--rule); margin-bottom: 12px;" {
            @match &current {
                Some(fp) => { "current: " (fp) }
                None => {
                    em style="color: var(--mute);" {
                        "(no fingerprint pinned — first SSH connection will TOFU-accept whatever the host presents)"
                    }
                }
            }
        }
        // Two-mode form. Auto-detect is the primary recommended path —
        // operator clicks one button + daemon does the keyscan. Manual
        // paste is the escape hatch if the operator has the fingerprint
        // from an out-of-band channel (hoster's console screenshot, etc).
        div style="display: flex; flex-direction: column; gap: 10px;" {
            form method="post"
                 action=(format!("/admin/servers/{sid_enc}/set-fingerprint"))
                 style="display: flex; gap: 8px; align-items: center;" {
                input type="hidden" name="mode" value="keyscan";
                button type="submit"
                       title="Run ssh-keyscan + ssh-keygen -lf - on the daemon host, pin the resulting fingerprint."
                       style="padding: 6px 14px; border: 1px solid var(--ink); background: var(--ink); color: var(--paper); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                    "auto-detect via ssh-keyscan →"
                }
                span style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute);" {
                    "(daemon will SSH-keyscan " span.ed-mono { (server.address) ":" (server.ssh_port) } " and pin the SHA-256)"
                }
            }
            form method="post"
                 action=(format!("/admin/servers/{sid_enc}/set-fingerprint"))
                 style="display: flex; gap: 8px; align-items: center;" {
                input type="hidden" name="mode" value="manual";
                input type="text" name="fingerprint" placeholder="SHA256:..."
                      style="flex: 1; padding: 4px 8px; font-family: var(--mono); font-size: 12px; border: 1px solid var(--rule);"
                      pattern="SHA256:[A-Za-z0-9+/=_-]{1,44}"
                      title="SHA256:<43-char-base64>";
                button type="submit"
                       style="padding: 4px 12px; border: 1px solid var(--ink); background: transparent; color: var(--ink); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                    "pin manually"
                }
            }
        }
    }
}

/// `POST /admin/servers/{id}/set-fingerprint` — operator pins the
/// trusted SHA-256. Two modes (selected by hidden form field `mode`):
///   * `keyscan` — daemon shells out to `ssh-keyscan -t ed25519 -p
///     <port> <addr> | ssh-keygen -lf -`, takes the 2nd whitespace
///     token. Convenience for the typical operator flow.
///   * `manual` — operator pasted a fingerprint string into the form.
///     Same shape validation as the CLI side.
///
/// Both audit-log `server.set_fingerprint` with the pinned value +
/// source, then redirect to `/admin/servers/{id}` so the section
/// re-renders with the new value visible.
pub(crate) async fn server_set_fingerprint(
    axum::extract::Path(server_id): axum::extract::Path<String>,
    State(state): State<AppState>,
    body: String,
) -> Response {
    let sid = vpnctl_core::ServerId(server_id.clone());
    let server = match state.inv.get_server(&sid).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return not_found(&format!("no such server '{server_id}'"));
        }
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };

    // Same `&`-split + decode_form_value pattern as user_create /
    // server_quick_add — doesn't pull a form-extractor feature.
    let mode = form_field(&body, "mode").unwrap_or_default();
    let fingerprint_in = form_field(&body, "fingerprint").unwrap_or_default();

    let (fp, source) = match mode.as_str() {
        "keyscan" => {
            // Defense-in-depth: re-validate the stored address before
            // shelling out — `validate_address` runs on every wizard
            // submit + server-quick-add, but a migrated row could
            // predate the validator. Cheap; rejects with 400 before
            // we spawn anything.
            if let Err(reason) = crate::wizard::validate_address(&server.address) {
                return bad_request(&format!(
                    "server '{server_id}' has an address that fails the validator ({reason}); \
                         fix it in the inventory before running auto-detect"
                ));
            }
            // Wrap blocking subprocess in spawn_blocking — otherwise an
            // unreachable host pins the tokio worker thread for the
            // ssh-keyscan default timeout (~5–10s), starving other
            // requests on the small homelab runtime.
            let addr = server.address.clone();
            let port = server.ssh_port;
            let scan_res = tokio::task::spawn_blocking(move || {
                vpnctl_host_fingerprint::fetch_via_keyscan(&addr, port)
            })
            .await;
            match scan_res {
                Ok(Ok(fp)) => (fp, "ssh-keyscan"),
                Ok(Err(e)) => {
                    return error_resp(
                        StatusCode::BAD_GATEWAY,
                        &format!("ssh-keyscan failed: {e}"),
                    );
                }
                Err(join_err) => {
                    return internal_error(anyhow::anyhow!(
                        "ssh-keyscan task panicked: {join_err}"
                    ));
                }
            }
        }
        "manual" => {
            if fingerprint_in.trim().is_empty() {
                return bad_request("manual mode requires a non-empty 'fingerprint' field");
            }
            (fingerprint_in.trim().to_string(), "operator-provided")
        }
        _ => {
            return bad_request("missing or invalid 'mode' (expected 'keyscan' or 'manual')");
        }
    };

    if !vpnctl_host_fingerprint::validate_shape(&fp) {
        return bad_request(&format!(
            "fingerprint '{fp}' is not in SHA256:<base64> shape"
        ));
    }

    // Capture previous fingerprint BEFORE overwriting — same forensic
    // reasoning as the CLI side. A TOFU-pin rotation has very different
    // implications depending on whether the operator rebuilt the node
    // (legit) vs someone is MITM-rotating the key (attack).
    let previous = server.trusted_host_fingerprint.clone();
    if let Err(e) = state.inv.update_trusted_fingerprint(&sid, &fp).await {
        return internal_error(anyhow::Error::new(e));
    }
    if let Err(e) = state
        .inv
        .audit(
            "admin",
            "server.set_fingerprint",
            Some(&server_id),
            Some(&serde_json::json!({
                "fingerprint": fp,
                "previous": previous,
                "source": source,
            })),
        )
        .await
    {
        tracing::warn!(
            target = "vpnctld::admin::server_set_fingerprint",
            server = %server_id,
            error = %e,
            "set_fingerprint succeeded but audit row failed; timeline will be missing this entry"
        );
    }

    Redirect::to(&format!(
        "/admin/servers/{}",
        path_segment_encode(&server_id)
    ))
    .into_response()
}

// SHA256 shape validation + ssh-keyscan/-keygen fingerprint fetching
// live in `vpnctl-host-fingerprint`. The two inline copies that used
// to sit here had drifted on the `--` flag-injection defense (the
// wizard's third copy was missing it entirely) and on the validator
// alphabet (the inventory variant rejected URL-safe base64 the surface
// validators accepted). Crate is the single source of truth; spec
// tests live with it.

fn server_detail_protocols_section(
    server: &vpnctl_core::Server,
    registry: &vpnctl_core::Registry,
) -> Markup {
    let enabled: std::collections::HashSet<&vpnctl_core::ProtocolId> =
        server.enabled_protocols.iter().collect();
    let all_protocols = registry.protocol_ids();
    // Multi-kernel: protocol is "compatible" if ANY of the server's
    // declared kernels supports it. Annotation below tells the operator
    // WHICH kernel handles it (resolves "wireguard runs on amneziawg,
    // tuic on sing-box" disambiguation that matters once a node has
    // multiple kernels).
    let kernel_supports_map: Vec<(
        vpnctl_core::KernelId,
        std::collections::HashSet<vpnctl_core::ProtocolId>,
    )> = server
        .kernels
        .iter()
        .filter_map(|kid| {
            registry
                .kernel(kid)
                .map(|k| (kid.clone(), k.supported_protocols().into_iter().collect()))
        })
        .collect();
    let kernel_supports: std::collections::HashSet<vpnctl_core::ProtocolId> = kernel_supports_map
        .iter()
        .flat_map(|(_, sup)| sup.iter().cloned())
        .collect();
    let sid_enc = path_segment_encode(&server.id.0);
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow { "Enabled protocols" }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
            "Check what runs on this node. Toggle takes effect on the next "
            span.ed-mono { "vpnctl deploy " (server.id.0) }
            " — inventory mutation doesn't push a config by itself (intentional: no surprise redeploys)."
        }
        ul style="list-style: none; padding: 0; font-family: var(--mono); font-size: 12px; line-height: 1.8;" {
            @for pid in &all_protocols {
                @let is_on = enabled.contains(pid);
                @let compatible = kernel_supports.contains(pid);
                li style="display: flex; align-items: baseline; gap: 12px; padding: 4px 0; border-bottom: 1px dotted var(--rule);" {
                    span style=(if compatible { "flex: 1; color: var(--ink);" } else { "flex: 1; color: var(--mute);" }) {
                        (pid.0)
                        @if !compatible {
                            " "
                            span style="font-size: 10px; color: var(--mute); font-style: italic; font-family: var(--serif);" {
                                "(not supported by "
                                @if server.kernels.len() == 1 { "kernel " (server.kernels[0].0) }
                                @else {
                                    "any kernel on this server: "
                                    (server.kernels.iter().map(|k| k.0.clone()).collect::<Vec<_>>().join(", "))
                                }
                                ")"
                            }
                        }
                    }
                    @if is_on {
                        span style="font-family: var(--mono); font-size: 11px; color: var(--acc); margin-right: 4px;" {
                            "✓ on"
                        }
                        form method="post"
                             action=(format!("/admin/servers/{}/protocols/{}/disable", sid_enc, path_segment_encode(&pid.0)))
                             style="margin: 0; padding: 0;" {
                            button type="submit"
                                   title=(format!("Remove {} from {}.enabled_protocols. Takes effect on next deploy.", pid.0, server.id.0))
                                   style="padding: 2px 8px; border: 1px solid var(--ink); background: transparent; font-family: var(--mono); font-size: 11px; color: var(--ink); cursor: pointer;" {
                                "disable"
                            }
                        }
                    } @else if compatible {
                        span style="font-family: var(--mono); font-size: 11px; color: var(--mute); margin-right: 4px;" {
                            "—"
                        }
                        form method="post"
                             action=(format!("/admin/servers/{}/protocols/{}/enable", sid_enc, path_segment_encode(&pid.0)))
                             style="margin: 0; padding: 0;" {
                            button type="submit"
                                   title=(format!("Add {} to {}.enabled_protocols. Takes effect on next deploy.", pid.0, server.id.0))
                                   style="padding: 2px 8px; border: 1px solid var(--ink); background: var(--ink); color: var(--paper); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                                "enable"
                            }
                        }
                    } @else {
                        // Incompatible — no button, just an explainer
                        // span so the row width is consistent.
                        span style="font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                            "incompatible"
                        }
                    }
                }
            }
        }
    }
}

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
