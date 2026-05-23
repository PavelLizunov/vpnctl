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
/// Operator's locale preference. Set by the masthead `[EN | RU]`
/// toggle (POST /admin/tweak/lang). Read in `Locale::from_request`,
/// which falls back to Accept-Language then defaults to En.
const COOKIE_LANG: &str = "vpnctl_lang";
/// Valid values for the lang cookie. Mirrors the `Locale` enum
/// variants in `crate::i18n` — adding a locale means extending this
/// list AND the enum.
const VALID_LANGS: &[&str] = &["en", "ru"];

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
    /// The URL path segment AND the `active_nav` matcher token. Stays
    /// English in both locales (URLs aren't localised).
    key: &'static str,
    /// The i18n key used to look up the localised label. nav() calls
    /// `t(lang, label_key)` to get the actual rendered text.
    label_key: crate::i18n::K,
    count: Option<usize>,
}

const NAV: &[NavItem] = &[
    NavItem {
        key: "dashboard",
        label_key: crate::i18n::K::NavDashboard,
        count: None,
    },
    NavItem {
        key: "monitoring",
        label_key: crate::i18n::K::NavMonitoring,
        count: None,
    },
    NavItem {
        key: "servers",
        label_key: crate::i18n::K::NavServers,
        count: None,
    },
    NavItem {
        key: "users",
        label_key: crate::i18n::K::NavUsers,
        count: None,
    },
    NavItem {
        key: "audit",
        label_key: crate::i18n::K::NavAudit,
        count: None,
    },
    NavItem {
        key: "alerts",
        label_key: crate::i18n::K::NavAlerts,
        count: None,
    },
    NavItem {
        key: "settings",
        label_key: crate::i18n::K::NavSettings,
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

fn nav(active: &str, lang: crate::i18n::Locale) -> Markup {
    use crate::i18n::{K, t};
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
                        (t(lang, it.label_key))
                        @if let Some(c) = it.count {
                            span.ct { (c) }
                        }
                    }
                } @else {
                    a href=(nav_href(it.key)) {
                        (t(lang, it.label_key))
                        @if let Some(c) = it.count {
                            span.ct { (c) }
                        }
                    }
                }
            }
            // A5 — inline search bar in the nav, right side.
            // GET form so the URL stays bookmarkable. Compact
            // styling that doesn't compete with nav links for
            // attention.
            form method="get" action="/admin/search"
                 style="margin-left: auto; display: flex; gap: 4px; align-items: baseline;" {
                input type="search" name="q"
                      placeholder=(match lang {
                          crate::i18n::Locale::En => "search…",
                          crate::i18n::Locale::Ru => "поиск…",
                      })
                      style="width: 140px; padding: 2px 6px; border: 1px solid var(--rule-s); background: var(--paper); font-family: var(--mono); font-size: 11px; color: var(--ink);";
                button type="submit"
                       title=(match lang {
                           crate::i18n::Locale::En => "Fleet-wide search across users / servers / alerts",
                           crate::i18n::Locale::Ru => "Поиск по флоту: пользователи / серверы / алерты",
                       })
                       style="padding: 2px 8px; border: 1px solid var(--rule-s); background: transparent; color: var(--ink); font-family: var(--mono); font-size: 10px; cursor: pointer;" {
                    "→"
                }
            }
            span style="margin-left: 16px; font-family: var(--mono); font-size: 11px; color: var(--dim); letter-spacing: 0; text-transform: none;" {
                (t(lang, K::NavOperator))
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

fn masthead(date: &str, vol: &str, lang: crate::i18n::Locale) -> Markup {
    use crate::i18n::{K, Locale, t};
    // The [EN | RU] toggle clicks POST /admin/tweak/lang/<other>;
    // the handler sets the vpnctl_lang cookie + 303-redirects back
    // via Referer. The "active" side is unlinked + bold; the
    // "other" side is a clickable form button. Two buttons (not one
    // link with `?lang=...`) so the cookie is server-set, not
    // URL-leaky.
    let other = match lang {
        Locale::En => Locale::Ru,
        Locale::Ru => Locale::En,
    };
    let toggle_form = html! {
        form method="post"
             action="/admin/tweak/lang"
             style="display: inline; margin: 0; padding: 0;" {
            input type="hidden" name="value" value=(other.cookie_value()) {}
            button type="submit"
                   title=(match other {
                       Locale::En => "Switch admin UI to English",
                       Locale::Ru => "Переключить админку на русский",
                   })
                   style="background: transparent; border: none; cursor: pointer; padding: 0 4px; font-family: var(--mono); font-size: 11px; color: var(--mute); text-decoration: underline;" {
                (other.cookie_value().to_uppercase())
            }
        }
    };
    html! {
        div.ed-mast {
            div.ed-mast__logo {
                (glyph(20))
                "vpnctl"
            }
            span.ed-mast__sub { (t(lang, K::MastSubtitle)) }
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
                " · "
                // Active locale — bold, unlinked. Then the toggle
                // button for the other locale. Visually:
                //   `vol. 0.1.0 · 2026-05-21 · EN | [RU]`
                b style="font-family: var(--mono); font-size: 11px; color: var(--ink);" {
                    (lang.cookie_value().to_uppercase())
                }
                " | "
                (toggle_form)
            }
        }
    }
}

fn foot(lang: crate::i18n::Locale) -> Markup {
    use crate::i18n::{K, t};
    html! {
        div.ed-foot {
            div.ed-foot__l {
                span { "vpnctld " (env!("CARGO_PKG_VERSION")) }
                // The admin UI is server-rendered with maud; htmx was
                // considered for the wizard but never landed (every
                // mutation today is a plain POST + 303 redirect, no
                // partial swaps). Bug-audit-agent 2026-05-21 caught
                // the footer claiming htmx — corrected.
                span { (t(lang, K::FootStack)) }
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
pub(crate) fn shell(
    active_nav: &str,
    theme: &str,
    accent: &str,
    lang: crate::i18n::Locale,
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
                    (masthead(&masthead_date(), &format!("vol. {}", env!("CARGO_PKG_VERSION")), lang))
                    (nav(active_nav, lang))
                    main.ed-main {
                        (body)
                    }
                    (foot(lang))
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

/// Same accessor pattern as `theme_accent`, but for the bilingual
/// admin shell — returns theme + accent + the operator's preferred
/// locale. Handlers call this instead of `theme_accent` so the
/// `shell()` invocation gets the locale plumbed through to
/// `masthead` + `nav` + `foot` (and onwards to any body-level
/// `t(lang, K::...)` lookups). Pavel 2026-05-21.
fn theme_accent_lang(headers: &HeaderMap) -> (String, String, crate::i18n::Locale) {
    let (theme, accent) = theme_accent(headers);
    let lang = crate::i18n::Locale::from_request(headers);
    (theme, accent, lang)
}

/// Aggregated counters used in the dashboard top-row metric tiles.
struct DashboardStats {
    servers: i64,
    users: i64,
    /// B1.user (audit 2026-05-22) — soft-suspended users. Surfaced
    /// in the Users tile sub-line so paused accounts stay visible
    /// even when the operator isn't scrolling through /admin/users.
    disabled_users: i64,
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
    let (servers_count, users_count, disabled_users_count, grants_count, server_list, audit) = tokio::try_join!(
        state.inv.count_servers(),
        state.inv.count_users(),
        state.inv.count_disabled_users(),
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
        disabled_users: disabled_users_count,
        grants: grants_count,
        distinct_protocols: distinct_protocols.len(),
    };
    Ok((stats, audit))
}

/// Render an editorial 4-cell metric row from the dashboard stats.
fn dashboard_metrics(stats: &DashboardStats, lang: crate::i18n::Locale) -> Markup {
    use crate::i18n::tr;
    html! {
        div.ed-metrics {
            div.ed-metric {
                span.ed-metric__lbl { (tr(lang, "Servers", "Серверы")) }
                span.ed-metric__v { (stats.servers) }
                span.ed-metric__sub { (tr(lang, "in inventory", "в инвентаре")) }
            }
            div.ed-metric {
                span.ed-metric__lbl { (tr(lang, "Users", "Пользователи")) }
                span.ed-metric__v { (stats.users) }
                span.ed-metric__sub {
                    (tr(lang, "across ", "всего ")) b { (stats.grants) }
                    @if stats.grants == 1 { (tr(lang, " grant", " доступ")) }
                    @else { (tr(lang, " grants", " доступов")) }
                    // B1.user surface — disabled-count appears ONLY when
                    // non-zero (quiet dashboard contract). Direct link
                    // to /admin/users so operator can drill in to
                    // re-enable / triage. Amber styling pulls the eye
                    // without screaming.
                    @if stats.disabled_users > 0 {
                        " · "
                        a href="/admin/users"
                          style="color: var(--acc); text-decoration: none;"
                          title=(tr(
                              lang,
                              "Users with disabled=true (B1.user soft-suspend). Click to drill into the user list.",
                              "Пользователи с disabled=true (B1.user мягкая пауза). Кликни, чтобы открыть список.",
                          )) {
                            b { (stats.disabled_users) }
                            // «paused» / «на паузе» are invariant
                            // across plural counts in both languages
                            // (adjective stays the same). No-op
                            // @if/@else removed per 2026-05-23 audit.
                            (tr(lang, " paused", " на паузе"))
                        }
                    }
                }
            }
            div.ed-metric {
                span.ed-metric__lbl { (tr(lang, "Protocols", "Протоколы")) }
                span.ed-metric__v { (stats.distinct_protocols) }
                span.ed-metric__sub { (tr(lang, "distinct, enabled", "уникальных, включено")) }
            }
            div.ed-metric {
                span.ed-metric__lbl { (tr(lang, "Daemon", "Демон")) }
                span.ed-metric__v { em { (tr(lang, "live", "активен")) } }
                span.ed-metric__sub { "vpnctld " b { (env!("CARGO_PKG_VERSION")) } }
            }
        }
    }
}

/// Editorial timeline of the most recent audit entries. Empty inventory
/// gets a deliberate "no activity yet" stub so the section never renders
/// as a bare rule.
fn dashboard_audit(audit: &[vpnctl_inventory::AuditEntry], lang: crate::i18n::Locale) -> Markup {
    use crate::i18n::tr;
    html! {
        div.ed-art-eyebrow style="margin-top: 28px;" {
            (tr(lang, "Recent activity", "Недавняя активность"))
        }
        @if audit.is_empty() {
            p style="font-family: var(--serif); font-style: italic; color: var(--mute); padding: 12px 0;" {
                (tr(
                    lang,
                    "No actions logged yet — vpnctl bootstrap / deploy / add-user will start filling this stream.",
                    "Действий пока не записано — vpnctl bootstrap / deploy / add-user начнут наполнять этот поток.",
                ))
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
                            (tr(lang, "by ", "автор: ")) (e.actor)
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

/// Classify an IP address from `sub_access_log.ip` into one of four
/// buckets so the admin UI can flag rows that aren't real external
/// clients. Pavel 2026-05-21: «вот такой ip это норм?» about a
/// `127.0.0.1` row — answer is «it's localhost, you (or a script
/// on the daemon host) ran a curl on the box itself». This makes
/// that visible at a glance instead of looking like a mystery
/// external client.
///
// `IpKind` + `classify_ip` moved to `crate::ip_kind` (single source
// of truth for both the admin render here AND the access-log writer
// that fires `sub_access.suspicious_local_ip` alerts). Render-side
// chip tag / tooltip / colour are admin-render-specific and stay
// here as a free-standing fn rather than methods on the shared
// enum (the enum doesn't need a `crate::i18n::Locale` dep).
use crate::ip_kind::{IpKind, classify_ip};

fn ip_kind_tag(k: IpKind, lang: crate::i18n::Locale) -> Option<&'static str> {
    match k {
        IpKind::Loopback => Some(crate::i18n::tr(lang, "localhost", "localhost")),
        IpKind::LanRfc1918 => Some(crate::i18n::tr(lang, "LAN", "LAN")),
        IpKind::LinkLocal => Some(crate::i18n::tr(lang, "link-local", "link-local")),
        IpKind::Public => None,
    }
}

fn ip_kind_tooltip(k: IpKind, lang: crate::i18n::Locale) -> &'static str {
    match k {
        IpKind::Loopback => crate::i18n::tr(
            lang,
            "Loopback (127.0.0.0/8). Hit came from a script running ON the daemon host itself (curl localhost, SSH tunnel, internal poller). Not an external client.",
            "Loopback (127.0.0.0/8). Запрос пришёл от скрипта, запущенного НА самом хосте демона (curl localhost, SSH-туннель, внутренний поллер). НЕ внешний клиент.",
        ),
        IpKind::LanRfc1918 => crate::i18n::tr(
            lang,
            "RFC 1918 private address (10/8, 172.16/12, 192.168/16). Same LAN as the daemon — likely your nginx proxy or another homelab host. Real client IP should arrive via X-Forwarded-For if the peer is in VPNCTLD_TRUSTED_PROXIES.",
            "Приватный адрес по RFC 1918 (10/8, 172.16/12, 192.168/16). Та же LAN что и демон — скорее всего твой nginx-прокси или другой homelab-хост. Реальный IP клиента должен приходить через X-Forwarded-For если пир в VPNCTLD_TRUSTED_PROXIES.",
        ),
        IpKind::LinkLocal => crate::i18n::tr(
            lang,
            "Link-local (169.254.0.0/16). DHCP-failure fallback address; should never appear in a sub-access log on a healthy network.",
            "Link-local (169.254.0.0/16). Fallback-адрес при сбое DHCP; в access-log здоровой сети появляться не должен.",
        ),
        IpKind::Public => "",
    }
}

fn ip_kind_color(k: IpKind) -> &'static str {
    match k {
        IpKind::Loopback => "var(--mute)",
        IpKind::LanRfc1918 => "var(--mute)",
        IpKind::LinkLocal => "var(--acc)",
        IpKind::Public => "var(--rule)",
    }
}

// `parse_ua_short` moved to `crate::ua` (Track-1.2 / migration 0019)
// so the access-log writer can persist its result in
// `sub_access_log.device_class` from the same source of truth. Render
// sites call `crate::ua::parse_ua_short(...)` directly. The previous
// /// doc-block lived above this comment; deleted to satisfy
// `clippy::empty-line-after-doc-comments` since there's no `fn` it
// could document anymore.

// `classify_ip` unit tests moved with the implementation to
// `crate::ip_kind::tests`. The render-side wrappers
// (`ip_kind_tag` / `_tooltip` / `_color`) are exercised end-to-end
// via the admin_smoke `track_1_2_*` tests.

pub(crate) async fn dashboard(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<Markup, Response> {
    let (theme, accent, lang) = theme_accent_lang(&headers);

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

    // Phase 4b — per-server live activity rollup for the dashboard
    // «VPN activity» tile. ONE call returns one entry per known
    // server (defaults to zeros for unpolled servers); we sum +
    // pass the per-server breakdown to the renderer.
    let live_activity = state.inv.all_servers_live_activity(24).await.unwrap_or_else(|e| {
        tracing::warn!(target = "vpnctld::admin", error = %e, "all_servers_live_activity failed");
        Vec::new()
    });

    // A2 — idle users (audit 2026-05-22): users who haven't hit
    // /sub or /api/v1/app/config in the last 30 days, plus users
    // who have NEVER appeared in the access log (created and
    // forgotten). Revoke candidates. Cap at 10 to keep the panel
    // compact — operator can drill into /admin/users for the full
    // list. Threshold of 30 days catches «forgotten phone in
    // drawer» without surfacing normal-vacation users.
    let idle_users = state.inv.idle_users(30, 10).await.unwrap_or_else(|e| {
        tracing::warn!(target = "vpnctld::admin", error = %e, "idle_users failed");
        Vec::new()
    });

    // Post-2026-05-22 — fleet-wide uptime tile. Loops `list_servers`
    // and aggregates `uptime_for_server` for 24h / 7d / 30d. Loop
    // (vs a single SUM-of-SUMs SQL helper) keeps it dead-simple +
    // reuses the already-spec-tested per-server path; for ≤100
    // servers in a homelab the N+1 query cost is negligible.
    // Per-server detail page still gives drill-in.
    let fleet_uptime = match state.inv.list_servers().await {
        Ok(servers) => {
            let mut rows: Vec<(
                vpnctl_core::ServerId,
                [Option<vpnctl_inventory::UptimeStat>; 3],
            )> = Vec::with_capacity(servers.len());
            for s in &servers {
                let u24h = state.inv.uptime_for_server(&s.id, 24).await.ok();
                let u7d = state.inv.uptime_for_server(&s.id, 24 * 7).await.ok();
                let u30d = state.inv.uptime_for_server(&s.id, 24 * 30).await.ok();
                rows.push((s.id.clone(), [u24h, u7d, u30d]));
            }
            rows
        }
        Err(e) => {
            tracing::warn!(target = "vpnctld::admin", error = %e, "list_servers (fleet uptime) failed");
            Vec::new()
        }
    };

    let body = html! {
        div.ed-art-eyebrow { (crate::i18n::t(lang, crate::i18n::K::PageDashboard)) }
        h1.ed-art-h1 {
            (crate::i18n::tr(lang, "homelab ", "homelab "))
            em { (crate::i18n::tr(lang, "at a glance", "одним взглядом")) }
        }
        p.ed-art-deck {
            (crate::i18n::tr(
                lang,
                "Counts straight from the SQLite inventory backing this daemon (",
                "Счётчики читаются напрямую из SQLite-инвентаря этого демона (",
            ))
            span.ed-mono { "/var/lib/vpnctl/inv.db" }
            (crate::i18n::tr(lang, "). ", "). "))
            b { (crate::i18n::tr(
                lang,
                "Servers, users, grants and the daemon version",
                "Серверы, пользователи, выданные доступы и версия демона",
            )) }
            (crate::i18n::tr(
                lang,
                " update on every reload.",
                " обновляются при каждой перезагрузке страницы.",
            ))
        }
        (dashboard_metrics(&stats, lang))
        (dashboard_fleet_uptime(&fleet_uptime, lang))
        (dashboard_vpn_activity(&live_activity, lang))
        (dashboard_alerts_tile(unacked_alerts, lang))
        (dashboard_idle_users(&idle_users, lang))
        (dashboard_limit_alerts(&alerting, lang))
        (dashboard_heavy_users(&heavy_users, lang))
        (dashboard_audit(&audit, lang))
    };
    Ok(shell("dashboard", &theme, &accent, lang, body))
}

/// Escape a string so it can be safely interpolated into a JS
/// single-quoted string literal embedded in an HTML `onsubmit` /
/// `onclick` attribute. Replaces backslash + single-quote in that
/// order (order matters — `\` must be escaped FIRST so we don't
/// double-escape the slash we add for `'`).
///
/// Use case: `onsubmit=(format!("return confirm('{}');", js_single_quote_escape(msg)))`
/// where `msg` may be operator-/translator-supplied copy that
/// contains apostrophes («don't», «it's», «можно ль»).
///
/// Note: HTML attribute escaping is independent and handled by maud
/// — this function only addresses the JS-string-literal layer. The
/// two are stacked: the browser HTML-decodes the attribute first
/// (turning `&apos;` into `'`), then the JS parser sees the source.
/// So we need JS-level escapes, not HTML-level.
///
/// Pinned by `js_single_quote_escape_handles_apostrophe_and_backslash`.
fn js_single_quote_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\'', "\\'")
}

/// Colour bucket for an uptime percentage. Shared by the per-server
/// `server_detail_uptime_section` chips and the dashboard-wide
/// `dashboard_fleet_uptime` chips so palette stays in one place. The
/// thresholds (≥99 green, ≥95 amber, <95 red, None grey) match Pavel's
/// confirmed SLO buckets for sing-box service uptime.
fn pct_color(pct: Option<u8>) -> &'static str {
    match pct {
        Some(p) if p >= 99 => "#2e7d32", // green
        Some(p) if p >= 95 => "#e6a23c", // amber
        Some(_) => "#c62828",            // red (incl. Some(0))
        None => "var(--mute)",           // grey
    }
}

/// Renders an uptime percent as the chip's visible text. `Some(p) →
/// "p%"` (integer; see `UptimeStat::uptime_pct` doc for why integer
/// vs decimal). `None → bilingual "— no data" / "— нет данных"` so
/// the empty branch is visually distinct from `Some(0%)` (down-the-
/// whole-window).
fn pct_label(pct: Option<u8>, lang: crate::i18n::Locale) -> String {
    match pct {
        Some(p) => format!("{p}%"),
        None => crate::i18n::tr(lang, "— no data", "— нет данных").to_string(),
    }
}

/// Fleet-wide uptime tile — dashboard companion to the per-server
/// `server_detail_uptime_section`. Three chips (24h / 7d / 30d) each
/// carrying the **fleet-weighted average** sing-box uptime%.
///
/// **Aggregation choice (probe-weighted, not server-equal-weighted):**
/// SUM(up_rows across all servers) / SUM(decidable_rows across all servers).
/// A server polled ½ as often contributes ½ as much to the average — this
/// matches the per-server semantics (each chip already counts probe rows
/// not server-days) and means a single fresh server with 1 probe doesn't
/// drown out 3 mature servers with 600 probes each. Servers with zero
/// decidable rows are silently excluded from BOTH numerator + denominator.
///
/// Renders ONLY when at least one server has at least one decidable
/// probe in some window. Otherwise the section is omitted — the operator
/// already gets «no servers polled yet» context from the absence of any
/// per-server uptime data on /admin/servers detail pages.
///
/// Chip-click navigates to /admin/servers (list) — per-server drill-in
/// lives there. Stable `data-fleet-uptime-pct` attribute for scrape
/// targets + future SLO export.
fn dashboard_fleet_uptime(
    rows: &[(
        vpnctl_core::ServerId,
        [Option<vpnctl_inventory::UptimeStat>; 3],
    )],
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;

    // Aggregate one window across all servers into (up_rows, total_decidable, n_servers).
    // `total_decidable = total_rows - unknown_rows` — we exclude
    // probes where sing_box_active is NULL (probe failed mid-flight)
    // from BOTH halves of the ratio, matching `UptimeStat::uptime_pct`'s
    // own definition. Server-count is also tallied so the chip footer
    // can read «N/M servers polled».
    let agg = |window_idx: usize| -> (u64, u64, usize) {
        let mut up: u64 = 0;
        let mut decidable: u64 = 0;
        let mut polled_servers: usize = 0;
        for (_, windows) in rows {
            if let Some(stat) = windows[window_idx].as_ref() {
                let dec = stat.total_rows.saturating_sub(stat.unknown_rows);
                if dec > 0 {
                    up = up.saturating_add(stat.up_rows);
                    decidable = decidable.saturating_add(dec);
                    polled_servers += 1;
                }
            }
        }
        (up, decidable, polled_servers)
    };

    let totals: [(u64, u64, usize); 3] = [agg(0), agg(1), agg(2)];
    let total_servers = rows.len();

    // Empty-fleet branch: NO server has decidable data in any window.
    // Render nothing — quiet dashboard for an unpolled fleet.
    if totals.iter().all(|(_, dec, _)| *dec == 0) {
        return html! {};
    }

    let pct_for = |up: u64, dec: u64| -> Option<u8> {
        if dec == 0 {
            None
        } else {
            // u128 to be safe with very large probe counts;
            // saturating cast back to u8 (% can't exceed 100).
            let p = ((u128::from(up) * 100) / u128::from(dec)) as u64;
            Some(p.min(100) as u8)
        }
    };

    let chip = |label: &str, totals: (u64, u64, usize)| -> Markup {
        let (up, dec, polled) = totals;
        let pct = pct_for(up, dec);
        let color = pct_color(pct);
        let pct_text = pct_label(pct, lang);
        // `data-fleet-uptime-pct` mirrors the per-server chip
        // attribute — same scrape contract, different prefix.
        let pct_attr = pct.map(|p| p.to_string()).unwrap_or_else(|| "none".into());
        html! {
            div data-fleet-uptime-pct=(pct_attr)
                style="display: flex; flex-direction: column; gap: 4px; padding: 12px 16px; border: 1px solid var(--rule); background: var(--paper); min-width: 120px;" {
                div style="font-family: var(--mono); font-size: 10px; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase;" {
                    (label)
                }
                div style=(format!("font-family: var(--serif); font-weight: 500; color: {color}; font-size: 22px; line-height: 1;")) {
                    (pct_text)
                }
                div style="font-family: var(--mono); font-size: 10px; color: var(--mute);" {
                    (dec) " " (tr(lang, "probes", "проб"))
                    " · " (polled) "/" (total_servers) " " (tr(lang, "polled", "опрош."))
                }
            }
        }
    };

    html! {
        section id="fleet-uptime" style="margin-top: 28px;" {
            div.ed-art-eyebrow {
                (tr(lang, "Fleet uptime · sing-box services", "Аптайм флота · сервисы sing-box"))
            }
            p style="font-family: var(--serif); font-style: italic; color: var(--mute); margin: 4px 0 12px 0;" {
                (tr(
                    lang,
                    "Probe-weighted average across all polled servers. Drill into a server detail page for per-window breakdown + last outage.",
                    "Среднее взвешенное по пробам со всех опрошенных серверов. На странице сервера — детальный разбор по окнам и время последнего инцидента.",
                ))
            }
            div style="display: flex; gap: 12px; flex-wrap: wrap;" {
                (chip(tr(lang, "last 24h", "24 часа"), totals[0]))
                (chip(tr(lang, "last 7d",  "7 дней"),  totals[1]))
                (chip(tr(lang, "last 30d", "30 дней"), totals[2]))
            }
        }
    }
}

/// Phase G — single-line alerts tile under the metric row. Renders
/// only when there's at least one unacked alert; quiet dashboard stays
/// quiet. Links to `/admin/alerts` for the full feed.
/// Phase 4b — dashboard «VPN activity» tile. Sums per-server
/// server-wide totals from `all_servers_live_activity(24)` and
/// shows: total bytes, active conns now, per-server breakdown.
/// Renders even when the poller has zero data so the operator
/// sees the structure (instead of guessing whether the section
/// would EVER appear). Empty-state copy points at the NM-11
/// upstream limit so the operator knows why per-user attribution
/// is zero today.
fn dashboard_vpn_activity(
    rows: &[(vpnctl_core::ServerId, vpnctl_inventory::ServerLiveActivity)],
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    let total_up: u64 = rows
        .iter()
        .map(|(_, a)| a.bytes_up_window)
        .fold(0u64, u64::saturating_add);
    let total_dn: u64 = rows
        .iter()
        .map(|(_, a)| a.bytes_dn_window)
        .fold(0u64, u64::saturating_add);
    let total_active: u32 = rows
        .iter()
        .map(|(_, a)| a.active_now)
        .fold(0u32, u32::saturating_add);
    let any_polled = rows.iter().any(|(_, a)| a.last_sample_ts.is_some());

    html! {
        div style="margin: 18px 0 0; padding: 14px 16px; border: 1px solid var(--rule); background: var(--paper);" {
            div.ed-art-eyebrow { (tr(lang, "VPN activity · last 24h", "VPN-активность · 24 часа")) }
            p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 12px;" {
                (tr(
                    lang,
                    "Server-wide totals from each node's clash-api (sing-box 5-minute tick). Per-user attribution is currently blocked upstream (NM-11: sing-box's clash-api wire format omits the User field); server-wide aggregates are unaffected.",
                    "Сервер-агрегатные показатели из clash-api каждой ноды (тик sing-box 5 минут). Per-user attribution заблокирован upstream (NM-11: sing-box's clash-api не передаёт поле User в wire-формате); сервер-агрегатные сводки работают.",
                ))
            }
            @if !any_polled {
                p style="font-family: var(--serif); font-style: italic; color: var(--mute); margin: 4px 0 0;" {
                    (tr(
                        lang,
                        "No clash-api samples yet — the poller hasn't reached any node. Check ",
                        "Снимков clash-api ещё нет — поллер не дошёл ни до одной ноды. Проверить ",
                    ))
                    a href="/admin/servers" style="color: var(--ink);" { (tr(lang, "Servers", "Серверы")) }
                    (tr(
                        lang,
                        " for deploy state.",
                        " на статус деплоя.",
                    ))
                }
            } @else {
                div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin: 8px 0 12px;" {
                    div title=(tr(lang, "Sum of active_connections across all servers' freshest server-wide tick.", "Сумма active_connections по всем серверам (свежий сервер-агрегатный тик).")) {
                        (status_tile(tr(lang, "active now", "активных сейчас"), &total_active.to_string(), "var(--ink)"))
                    }
                    div title=(tr(lang, "Total upload bytes (client → server) across every node over the last 24 hours.", "Total upload-байт (клиент → сервер) по всем нодам за последние 24 часа.")) {
                        (status_tile(tr(lang, "upload 24h", "upload 24ч"), &humanize_bytes(total_up), "var(--ink)"))
                    }
                    div title=(tr(lang, "Total download bytes (server → client) across every node over the last 24 hours.", "Total download-байт (сервер → клиент) по всем нодам за последние 24 часа.")) {
                        (status_tile(tr(lang, "download 24h", "download 24ч"), &humanize_bytes(total_dn), "var(--ink)"))
                    }
                }
                // Per-server breakdown — compact mono table.
                table style="width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 11.5px;" {
                    thead {
                        tr style="border-bottom: 1px solid var(--ink);" {
                            th style="text-align: left; padding: 5px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { (tr(lang, "server", "сервер")) }
                            th style="text-align: right; padding: 5px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { (tr(lang, "active", "активных")) }
                            th style="text-align: right; padding: 5px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { (tr(lang, "upload", "upload")) }
                            th style="text-align: right; padding: 5px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { (tr(lang, "download", "download")) }
                            th style="text-align: right; padding: 5px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { (tr(lang, "last poll", "последний")) }
                        }
                    }
                    tbody {
                        @for (sid, act) in rows {
                            tr style="border-bottom: 1px dotted var(--rule);" {
                                td style="padding: 4px 8px;" {
                                    a href=(format!("/admin/servers/{}", crate::http_util::path_segment_encode(&sid.0))) style="color: var(--ink); text-decoration: none;" { (sid.0) }
                                }
                                td style="padding: 4px 8px; text-align: right;" { (act.active_now) }
                                td style="padding: 4px 8px; text-align: right;" { (humanize_bytes(act.bytes_up_window)) }
                                td style="padding: 4px 8px; text-align: right;" { (humanize_bytes(act.bytes_dn_window)) }
                                td style="padding: 4px 8px; text-align: right; color: var(--mute);" {
                                    @match act.last_sample_ts {
                                        Some(ts) => (format_msk(ts)),
                                        None => (tr(lang, "—", "—")),
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

fn dashboard_alerts_tile(unacked: u64, lang: crate::i18n::Locale) -> Markup {
    use crate::i18n::tr;
    html! {
        @if unacked > 0 {
            div style="margin: 18px 0 0; padding: 14px 16px; border: 1px solid var(--rule); border-left: 3px solid var(--accent); background: var(--paper-tint);" {
                div.ed-art-eyebrow { (tr(lang, "Homelab health", "Здоровье homelab")) }
                p style="font-family: var(--serif); margin: 6px 0 0;" {
                    b { (unacked) }
                    @if unacked == 1 {
                        (tr(lang, " unacked alert", " непринятое уведомление"))
                    } @else {
                        (tr(lang, " unacked alerts", " непринятых уведомлений"))
                    }
                    " · "
                    a href="/admin/alerts" style="color: var(--ink);" {
                        em { (tr(
                            lang,
                            "see what the daemon's complaining about →",
                            "посмотреть на что жалуется демон →",
                        )) }
                    }
                }
            }
        }
    }
}

/// A2 (audit 2026-05-22) — «idle users» panel. Lists users whose
/// most recent `/sub` or `/api/v1/app/config` hit is older than 30
/// days, OR who have never appeared in `sub_access_log` at all
/// (created and forgotten). Helps the operator find revoke
/// candidates without manually grep-ing the user list.
///
/// **Rendered only when there's at least one idle user** — quiet
/// dashboard for a fleet with zero idle accounts. Each row links to
/// `/admin/users/<id>` where the operator can revoke / disable / dig
/// in. «Never seen» is displayed as «never» in italics so it visually
/// distinguishes from «seen X days ago».
fn dashboard_idle_users(
    rows: &[(vpnctl_core::UserId, Option<chrono::DateTime<chrono::Utc>>)],
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    if rows.is_empty() {
        return html! {};
    }
    let now = chrono::Utc::now();
    html! {
        section id="idle-users" style="margin-top: 28px;" {
            div.ed-art-eyebrow {
                (tr(lang, "Idle users · revoke candidates", "Простаивающие пользователи · кандидаты на отзыв"))
            }
            p style="font-family: var(--serif); font-style: italic; color: var(--mute); margin: 4px 0 12px 0;" {
                (tr(
                    lang,
                    "Users whose subscription URL hasn't been hit in 30+ days, or who have never connected. ",
                    "Пользователи, чей URL подписки не запрашивался 30+ дней, либо ни разу не подключались. ",
                ))
                em { (tr(lang, "Click to drill in", "Кликни, чтобы зайти")) }
                (tr(
                    lang,
                    " — common pattern: forgotten phone in a drawer; revoke + reclaim the sub-token slot.",
                    " — типичный паттерн: забытый телефон в ящике; отзови и освободи слот sub-токена.",
                ))
            }
            div.ed-time {
                @for (uid, last_seen) in rows {
                    div.ed-time-row {
                        // Age column on the left so the operator can
                        // scan «who's been gone longest» in one pass.
                        span.ed-time-row__t {
                            @match last_seen {
                                Some(ts) => {
                                    @let age_days = (now - *ts).num_days().max(0);
                                    (age_days) " " (tr(lang, "d ago", "д назад"))
                                }
                                None => {
                                    em style="color: var(--mute);" {
                                        (tr(lang, "never", "никогда"))
                                    }
                                }
                            }
                        }
                        span.ed-time-row__a {
                            (tr(lang, "idle", "простой"))
                        }
                        span.ed-time-row__tgt {
                            a href=(format!("/admin/users/{}", path_segment_encode(&uid.0)))
                              style="color: var(--ink); text-decoration: none;" {
                                (uid.0)
                            }
                        }
                        span.ed-time-row__pl style="color: var(--mute);" {
                            @match last_seen {
                                Some(ts) => (clip_ts(&ts.to_rfc3339())),
                                None => "—",
                            }
                        }
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
fn dashboard_limit_alerts(
    rows: &[(vpnctl_core::UserId, u64, u64, u8)],
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    if rows.is_empty() {
        // Clean — no one near limit, no UI clutter. Operator sees
        // this section only when something demands attention.
        return html! {};
    }
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow style="color: var(--acc);" {
            (rows.len())
            @if rows.len() == 1 {
                (tr(lang, " user near monthly limit", " пользователь у лимита месяца"))
            } @else {
                (tr(lang, " users near monthly limit", " пользователей у лимита месяца"))
            }
        }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
            (tr(
                lang,
                "These users have crossed their configured alert threshold (default ",
                "Эти пользователи перешли порог срабатывания уведомления (по умолчанию ",
            ))
            span.ed-mono { (DEFAULT_TRAFFIC_THRESHOLD_PCT) "%" }
            (tr(
                lang,
                "). Click through to raise the cap or shape behaviour.",
                "). Кликни чтобы поднять лимит или повлиять на поведение.",
            ))
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
                            (tr(lang, "OVER", "СВЕРХ"))
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
fn dashboard_heavy_users(rows: &[(vpnctl_core::UserId, u64)], lang: crate::i18n::Locale) -> Markup {
    use crate::i18n::{K, t, tr};
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow
            title=(tr(
                lang,
                "Top-N by sum of (upload+download bytes) across all servers, last 24 hours. Data source: clash-api 5-minute polls. wgturn / WireGuard traffic NOT included (kernel-level, no clash-api visibility); only sing-box-mediated protocols (VLESS, TUIC, Trojan, Hysteria2, AnyTLS, Shadowsocks-2022) appear here.",
                "Топ-N по сумме (upload+download байт) на всех серверах за 24 часа. Источник: 5-минутные опросы clash-api. Трафик wgturn / WireGuard НЕ учитывается (kernel-уровень, clash-api их не видит); только протоколы которые видит sing-box (VLESS, TUIC, Trojan, Hysteria2, AnyTLS, Shadowsocks-2022).",
            )) {
            (t(lang, K::EyebrowHeavyUsers))
        }
        @if rows.is_empty() {
            p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
                (tr(
                    lang,
                    "No per-user traffic recorded yet. The clash-api poller ticks every 5 minutes — once the daemon's SSH deploy key is in each node's ",
                    "Трафик по пользователям ещё не записан. Опрос clash-api идёт раз в 5 минут — как только SSH deploy-ключ демона окажется в ",
                ))
                span.ed-mono { "~/.ssh/authorized_keys" }
                (tr(lang, " (see ", " каждой ноды (см. "))
                a href="/admin/settings" style="color: var(--ink);" {
                    (t(lang, K::NavSettings))
                }
                (tr(
                    lang,
                    ") the section populates on the next tick.",
                    ") — секция наполнится на следующем тике.",
                ))
            }
        } @else {
            p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
                (tr(lang, "Top ", "Топ ")) (rows.len())
                (tr(
                    lang,
                    " accounts by total (upload + download) over the last 24 hours. Click through to investigate; the user page has the full breakdown + sparkline.",
                    " аккаунтов по суммарному (upload + download) за 24 часа. Кликни чтобы разобраться — страница пользователя содержит полную разбивку + sparkline.",
                ))
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

/// Convert any error into a plaintext 500 response.
///
/// **Body is intentionally opaque.** Prior to 2026-05-22 this function
/// inlined `err.to_string()` into the response so the operator could
/// see the failure without checking journalctl. That bled sqlx /
/// anyhow chains (schema names, file paths, occasionally row contents)
/// to anyone who could reach the admin UI. For a single-LAN operator
/// the leak was tolerable; for any external exposure (reverse proxy
/// flapping, accidental 0.0.0.0 bind, future OAuth gating) it's a
/// recon channel. Body is now a stable opaque string; the full chain
/// stays in `journalctl -u vpnctld -t vpnctld::admin` where the
/// operator can grep it.
///
/// **Copy contract:** every backend response in the admin tree starts
/// with `vpnctl admin:` so an operator grepping `journalctl` or tailing
/// curl output has one stable prefix to filter on. See `error_text()`.
///
/// `anyhow::Error` is a single boxed pointer; passing by value keeps
/// call sites clean (`.map_err(internal_error)`), so silence clippy.
#[allow(clippy::needless_pass_by_value)]
fn internal_error(err: anyhow::Error) -> Response {
    // Full chain to the log — the operator's debugging surface.
    tracing::error!(
        target = "vpnctld::admin",
        error = format!("{err:#}"),
        "handler failed; returning opaque 500 to client"
    );
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        // Opaque body — see doc-comment. Pinned by
        // `internal_error_body_does_not_leak_anyhow_chain`.
        error_text("internal error — see journalctl -u vpnctld"),
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
    let (theme, accent, lang) = theme_accent_lang(&headers);

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
        div.ed-art-eyebrow { (crate::i18n::t(lang, crate::i18n::K::PageMonitoring)) }
        h1.ed-art-h1 {
            (total_hits_24h) " "
            @if total_hits_24h == 1 { em { (crate::i18n::tr(lang, "hit", "обращение")) } }
            @else { em { (crate::i18n::tr(lang, "hits", "обращений")) } }
            (crate::i18n::tr(lang, " in the last 24h", " за последние 24 часа"))
        }
        p.ed-art-deck {
            (crate::i18n::tr(
                lang,
                "Aggregate sub-access counters straight from ",
                "Агрегированные счётчики обращений напрямую из ",
            ))
            span.ed-mono { "sub_access_log" }
            (crate::i18n::tr(
                lang,
                ". Reads are server-side aggregated; no JavaScript on the page — re-render on reload.",
                ". Все агрегации на сервере; JavaScript на странице нет — перерасчёт по перезагрузке.",
            ))
        }

        div style="display: flex; gap: 36px; padding: 12px 0 24px; font-family: var(--serif);" {
            div {
                div style="font-size: 28px; font-weight: 400; color: var(--ink); line-height: 1;" { (total_hits_24h) }
                div style="font-family: var(--mono); font-size: 10.5px; letter-spacing: 0.14em; text-transform: uppercase; color: var(--mute); margin-top: 4px;" {
                    (crate::i18n::tr(lang, "hits · 24h", "обращений · 24ч"))
                }
            }
            div {
                div style="font-size: 28px; font-weight: 400; color: var(--ink); line-height: 1;" { (peak_ips_hour) }
                div style="font-family: var(--mono); font-size: 10.5px; letter-spacing: 0.14em; text-transform: uppercase; color: var(--mute); margin-top: 4px;" {
                    (crate::i18n::tr(lang, "peak distinct IPs / hour", "пик уникальных IP / час"))
                }
            }
            div {
                div style="font-size: 28px; font-weight: 400; color: var(--ink); line-height: 1;" { (total_hits_7d) }
                div style="font-family: var(--mono); font-size: 10.5px; letter-spacing: 0.14em; text-transform: uppercase; color: var(--mute); margin-top: 4px;" {
                    (crate::i18n::tr(lang, "hits · 7 days", "обращений · 7 дней"))
                }
            }
        }

        div.ed-rule {}
        div.ed-art-eyebrow style="margin-top: 18px;" {
            (crate::i18n::tr(lang, "Hourly hits · last 24h", "Обращения по часам · за 24ч"))
        }
        (sparkline_svg(&hour_filled.iter().map(|b| b.hits as f64).collect::<Vec<_>>(), 720, 60))
        div.ed-art-eyebrow style="margin-top: 18px;" {
            (crate::i18n::tr(lang, "Hourly distinct IPs · last 24h", "Уникальные IP по часам · за 24ч"))
        }
        (sparkline_svg(&hour_filled.iter().map(|b| b.distinct_ips as f64).collect::<Vec<_>>(), 720, 60))
        div.ed-art-eyebrow style="margin-top: 18px;" {
            (crate::i18n::tr(lang, "Daily hits · last 7 days", "Обращения по дням · за 7 дней"))
        }
        (sparkline_svg(&day_filled.iter().map(|b| b.hits as f64).collect::<Vec<_>>(), 720, 60))

        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin-top: 18px;" {
            (crate::i18n::tr(
                lang,
                "Same data is curl-able as JSON at ",
                "Те же данные доступны JSON-ом через ",
            ))
            span.ed-mono { "/api/v1/stats/sub-access?bucket=hour&since_hours=24" }
            (crate::i18n::tr(
                lang,
                " (no auth — only aggregate counts, no per-IP details).",
                " (без авторизации — только агрегаты, без детализации по IP).",
            ))
        }
    };
    Ok(shell("monitoring", &theme, &accent, lang, body))
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
fn server_card(
    idx: usize,
    s: &vpnctl_core::Server,
    user_count: i64,
    hidden_matrix: &std::collections::HashMap<
        (vpnctl_core::ServerId, vpnctl_core::ProtocolId),
        bool,
    >,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    // Split `enabled_protocols` into visible + hidden by consulting
    // the `server_protocols` table (via the pre-loaded bulk matrix).
    // Defaults to `not hidden` when the matrix doesn't know about a
    // pid — same defensive fallback the server-detail page uses
    // (NM-10 review-agent note: in-memory cache vs on-disk table
    // can diverge only via raw SQL; the safe default is "show it").
    let mut visible_protos: Vec<&str> = Vec::with_capacity(s.enabled_protocols.len());
    let mut hidden_protos: Vec<&str> = Vec::new();
    for p in &s.enabled_protocols {
        let is_hidden = hidden_matrix
            .get(&(s.id.clone(), p.clone()))
            .copied()
            .unwrap_or(false);
        if is_hidden {
            hidden_protos.push(p.0.as_str());
        } else {
            visible_protos.push(p.0.as_str());
        }
    }
    let visible_str = if visible_protos.is_empty() {
        "—".to_string()
    } else {
        visible_protos.join(", ")
    };
    let jump = match &s.jump_via {
        Some(j) => j.0.clone(),
        None => tr(lang, "direct", "напрямую").to_string(),
    };
    let fp = s
        .trusted_host_fingerprint
        .as_deref()
        .unwrap_or_else(|| tr(lang, "(unverified)", "(не подтверждён)"));
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
                    (tr(lang, "Hoster ", "Хостер ")) b { (s.hoster) }
                    " · " b { (user_count) } " "
                    @if user_count == 1 { (tr(lang, "user", "пользователь")) }
                    @else { (tr(lang, "users", "пользователей")) }
                    (tr(lang, " granted access · jump ", " имеют доступ · jump через "))
                    em { (jump) }
                }
            }
            dl.ed-server__meta {
                dt { (tr(lang, "protocols", "протоколы")) }
                dd { (visible_str) }
                @if !hidden_protos.is_empty() {
                    dt style="color: var(--acc);" { (tr(lang, "hidden", "скрыты")) }
                    dd style="color: var(--acc); font-style: italic;"
                       title=(tr(
                           lang,
                           "These protocols are still enabled on the node (sing-box inbound keeps listening, cached client URIs continue to work) but the subscription render path stops emitting them. Adjust on the server detail page.",
                           "Эти протоколы по-прежнему включены на ноде (sing-box inbound продолжает слушать, кешированные клиентские URI работают), но в рендер подписок они не попадают. Управление — на странице сервера.",
                       )) {
                        (hidden_protos.join(", "))
                        " · " span.ed-mono style="font-size: 10px;" {
                            "(" (hidden_protos.len())
                            (tr(lang, " hidden, ", " скрытых, "))
                            (visible_protos.len())
                            (tr(lang, " visible)", " видимых)"))
                        }
                    }
                }
                dt { (tr(lang, "fingerprint", "отпечаток")) }
                dd style="font-family: var(--mono); font-size: 11px;" { (fp) }
                dt { (tr(lang, "usage ×", "коэф. использования")) }
                dd { (format!("{:.2}", s.usage_coefficient)) }
            }
        }
    }
}

pub(crate) async fn servers(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<Markup, Response> {
    let (theme, accent, lang) = theme_accent_lang(&headers);

    // Fan out three reads concurrently — server list, the grants
    // count per server, AND the bulk (server, protocol) → hidden
    // matrix. The hidden matrix lets `server_card` split each
    // server's `enabled_protocols` into a visible-list + a
    // hidden-list, matching the truth that the subscription render
    // sees instead of the in-memory cache. Pavel 2026-05-20 caught
    // the discrepancy after his bulk hides on fi/is — the list page
    // still showed every enabled protocol with no marker.
    let (server_list, user_counts, hidden_matrix) = tokio::try_join!(
        state.inv.list_servers(),
        state.inv.users_count_per_server(),
        state.inv.list_all_server_protocols_with_hidden(),
    )
    .map_err(|e| internal_error(anyhow::Error::new(e)))?;

    let body = html! {
        div.ed-art-eyebrow { (crate::i18n::t(lang, crate::i18n::K::PageServers)) }
        h1.ed-art-h1 {
            (server_list.len()) " "
            @if server_list.len() == 1 { em { (crate::i18n::tr(lang, "server", "сервер")) } }
            @else { em { (crate::i18n::tr(lang, "servers", "серверов")) } }
            (crate::i18n::tr(lang, " in inventory", " в инвентаре"))
        }
        p.ed-art-deck {
            (crate::i18n::tr(
                lang,
                "Read straight from the SQLite inventory. Add a server through the ",
                "Читаются напрямую из SQLite-инвентаря. Добавь сервер через ",
            ))
            a href="/admin/servers/new" style="color: var(--ink); text-decoration: underline;" {
                (crate::i18n::tr(lang, "wizard", "мастер"))
            }
            (crate::i18n::tr(
                lang,
                " (paste IP + root password, the daemon does the rest), or use ",
                " (вставь IP + root пароль, остальное сделает демон), либо через ",
            ))
            span.ed-mono { "vpnctl bootstrap" }
            (crate::i18n::tr(lang, " then ", " затем "))
            span.ed-mono { "vpnctl deploy" }
            (crate::i18n::tr(lang, " from the CLI.", " в CLI."))
        }

        div style="margin: 16px 0 16px; padding: 14px 16px; border: 1px solid var(--rule); background: var(--paper);" {
            form method="post" action="/admin/servers/quick-add"
                 style="display: flex; gap: 10px; align-items: baseline; flex-wrap: wrap;" {
                label style="font-family: var(--mono); font-size: 11px; color: var(--mute); letter-spacing: 0.14em; text-transform: uppercase;" {
                    (crate::i18n::tr(lang, "add server", "добавить сервер"))
                }
                input type="text" name="id" required="required"
                      placeholder=(crate::i18n::tr(lang, "e.g. fra-01", "напр. fra-01"))
                      pattern="[A-Za-z0-9._-]+"
                      title=(crate::i18n::tr(
                          lang,
                          "Letters, digits, dot, underscore, hyphen — no spaces or slashes",
                          "Буквы, цифры, точка, подчёркивание, дефис — без пробелов и слешей",
                      ))
                      style="max-width: 160px; padding: 4px 8px; border: 1px solid var(--rule-s); background: var(--paper); font-family: var(--mono); font-size: 12px; color: var(--ink);";
                input type="text" name="address" required="required"
                      placeholder=(crate::i18n::tr(lang, "ip or hostname", "ip или хост"))
                      title=(crate::i18n::tr(
                          lang,
                          "IPv4 / IPv6 / hostname of an already-bootstrapped node",
                          "IPv4 / IPv6 / хост уже развёрнутой ноды",
                      ))
                      style="max-width: 220px; padding: 4px 8px; border: 1px solid var(--rule-s); background: var(--paper); font-family: var(--mono); font-size: 12px; color: var(--ink);";
                input type="number" name="ssh_port" value="22" min="1" max="65535"
                      title=(crate::i18n::tr(
                          lang,
                          "SSH port — 22 (DO) or 2222 (Cloudzy)",
                          "SSH порт — 22 (DO) или 2222 (Cloudzy)",
                      ))
                      style="max-width: 72px; padding: 4px 8px; border: 1px solid var(--rule-s); background: var(--paper); font-family: var(--mono); font-size: 12px; color: var(--ink);";
                button type="submit"
                       title=(crate::i18n::tr(
                           lang,
                           "Registers the server with default kernels=sing-box + every sing-box-supported protocol enabled. Tweak everything on the detail page right after.",
                           "Регистрирует сервер с ядром sing-box и всеми поддерживаемыми им протоколами. Настройки правь на странице сервера сразу после.",
                       ))
                       style="padding: 4px 12px; border: 1px solid var(--ink); background: var(--ink); color: var(--paper); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                    (crate::i18n::tr(lang, "register", "зарегистрировать"))
                }
                span style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); flex-basis: 100%;" {
                    (crate::i18n::tr(
                        lang,
                        "→ default kernels=sing-box, all kernel-supported protocols enabled. Tweak on the detail page.",
                        "→ ядро sing-box по умолчанию, включены все поддерживаемые им протоколы. Тонкая настройка — на странице сервера.",
                    ))
                }
            }
        }

        // Phase E sub-iter 4a — wizard CTA. For fresh nodes that need
        // bootstrap (push our SSH key, install kernel, etc). Use the
        // quick-add above if you already have a working node.
        div style="margin: 0 0 24px;" {
            a href="/admin/servers/new"
              style="display: inline-block; padding: 6px 14px; border: 1px solid var(--ink); background: transparent; color: var(--ink); font-family: var(--mono); font-size: 11px; text-decoration: none;" {
                (crate::i18n::tr(
                    lang,
                    "wizard → bootstrap a fresh node from scratch",
                    "мастер → развернуть свежую ноду с нуля",
                ))
            }
        }

        @if server_list.is_empty() {
            p style="font-family: var(--serif); font-style: italic; color: var(--mute); padding: 24px 0;" {
                (crate::i18n::tr(lang, "No servers yet. Click ", "Серверов ещё нет. Кликни "))
                span.ed-mono { (crate::i18n::tr(lang, "add server →", "добавить сервер →")) }
                (crate::i18n::tr(lang, " above, or run ", " выше, или запусти "))
                span.ed-mono { "vpnctl bootstrap <id> <address> <ssh-user> <ssh-port>" }
                (crate::i18n::tr(
                    lang,
                    " on a fresh node and refresh.",
                    " на свежей ноде и обнови страницу.",
                ))
            }
        } @else {
            div {
                @for (idx, s) in server_list.iter().enumerate() {
                    (server_card(
                        idx,
                        s,
                        user_counts.get(&s.id).copied().unwrap_or(0),
                        &hidden_matrix,
                        lang,
                    ))
                }
            }
        }
    };
    Ok(shell("servers", &theme, &accent, lang, body))
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
fn user_row(
    idx: usize,
    u: &vpnctl_core::User,
    grants_count: usize,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
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
                    (tr(lang, " · sub-token ", " · sub-токен "))
                    @match &sub_token_preview {
                        Some(s) => span.ed-mono { (s) },
                        None => em { (tr(
                            lang,
                            "(unset — open the user to regenerate)",
                            "(не задан — открой пользователя чтобы сгенерировать)",
                        )) },
                    }
                }
                p.ed-server__lede {
                    b { (grants_count) } " "
                    @if grants_count == 1 { (tr(lang, "server", "сервер")) }
                    @else { (tr(lang, "servers", "серверов")) }
                    (tr(lang, " granted", " доступно"))
                    @if u.tuic_password.is_some() {
                        (tr(lang, " · tuic password set", " · tuic-пароль задан"))
                    }
                    @if u.wireguard_pubkey.is_some() {
                        (tr(lang, " · wireguard pubkey set", " · wireguard-pubkey задан"))
                    }
                }
            }
            dl.ed-server__meta {
                dt { (tr(lang, "open", "открыть")) }
                dd {
                    a href=(detail_href) class="ed-server__cta" {
                        (tr(lang, "detail · QR", "детали · QR"))
                    }
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
    let (theme, accent, lang) = theme_accent_lang(&headers);

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
        div.ed-art-eyebrow { (crate::i18n::t(lang, crate::i18n::K::PageUsers)) }
        h1.ed-art-h1 {
            (users_list.len()) " "
            @if users_list.len() == 1 { em { (crate::i18n::tr(lang, "user", "пользователь")) } }
            @else { em { (crate::i18n::tr(lang, "users", "пользователей")) } }
            (crate::i18n::tr(lang, " on file", " в базе"))
        }
        p.ed-art-deck {
            (crate::i18n::tr(
                lang,
                "Each user has a public subscription URL — ",
                "У каждого пользователя есть публичный URL подписки — ",
            ))
            span.ed-mono { "https://ninitux.com/api/v1/app/config/<device_id>" } " — "
            (crate::i18n::tr(
                lang,
                "served by vpnctld since the Phase 5 cutover (2026-05-19). The QR on every user-detail page encodes that URL; the legacy ",
                "обслуживается vpnctld с момента Phase 5 cutover (2026-05-19). QR на странице каждого пользователя кодирует этот URL; легаси ",
            ))
            span.ed-mono { "/sub/<token>" }
            (crate::i18n::tr(
                lang,
                " endpoint stays as a LAN-only fallback. Open a row for the QR you'll point a phone at.",
                " остаётся как LAN-only fallback. Открой строку — там QR, который наводишь камерой телефона.",
            ))
        }

        // Search FIRST, add-user SECOND. Pre-2026-05-19 the order
        // was reversed — Pavel hit the case where typing a query
        // into «add user» (placement default = first input on the
        // page → mouse-less keyboard flow lands there) accidentally
        // POSTed and tried to create a user. Putting search first
        // means: (a) the autofocus cursor lands on a SAFE field,
        // (b) misplaced Enter routes to a GET search not a POST
        // create, (c) the destructive «create» action gets a
        // visually distinct (dashed) container so it's harder to
        // confuse for the input box you wanted.
        //
        // Pavel iter C2: search + sort. Search is a GET form so the
        // resulting URL is shareable / bookmarkable. Sort links live
        // next to the search and pin the current direction.
        @if !users_list.is_empty() {
            div style="display: flex; gap: 16px; align-items: baseline; flex-wrap: wrap; margin: 0 0 14px;" {
                form method="get" action="/admin/users"
                     style="display: flex; gap: 6px; align-items: baseline;" {
                    label style="font-family: var(--mono); font-size: 11px; color: var(--mute); letter-spacing: 0.14em; text-transform: uppercase;" {
                        (crate::i18n::tr(lang, "search", "поиск"))
                    }
                    input type="text" name="q" value=(q_lower)
                          placeholder=(crate::i18n::tr(lang, "user id substring", "подстрока user id"))
                          autofocus
                          style="max-width: 200px; padding: 3px 8px; border: 1px solid var(--rule-s); background: var(--paper); font-family: var(--mono); font-size: 12px; color: var(--ink);";
                    @if !sort_kind.is_empty() && sort_kind != "id" {
                        input type="hidden" name="sort" value=(sort_kind);
                    }
                    button type="submit"
                           title=(crate::i18n::tr(
                               lang,
                               "Search user ids by substring (case-insensitive)",
                               "Поиск user id по подстроке (регистр игнорируется)",
                           ))
                           style="padding: 3px 10px; border: 1px solid var(--ink); background: transparent; font-family: var(--mono); font-size: 11px; color: var(--ink); cursor: pointer;" {
                        (crate::i18n::tr(lang, "go", "ок"))
                    }
                    @if !q_lower.is_empty() {
                        a href=(make_sort_href(sort_kind))
                          style="font-family: var(--mono); font-size: 11px; color: var(--mute); margin-left: 4px;" {
                            (crate::i18n::tr(lang, "× clear", "× очистить"))
                        }
                    }
                }
                div style="font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                    (crate::i18n::tr(lang, "sort: ", "сортировка: "))
                    @let sort_link = |kind: &str, label: &str| -> Markup {
                        let active = sort_kind == kind;
                        html! {
                            a href=(make_sort_href(kind))
                              style=(if active { "color: var(--ink); text-decoration: underline; margin-right: 8px;" } else { "color: var(--mute); margin-right: 8px;" }) {
                                (label)
                            }
                        }
                    };
                    (sort_link("id", crate::i18n::tr(lang, "id ↑", "id ↑")))
                    (sort_link("id-desc", crate::i18n::tr(lang, "id ↓", "id ↓")))
                    (sort_link("servers", crate::i18n::tr(lang, "servers ↓", "серверы ↓")))
                    (sort_link("servers-desc", crate::i18n::tr(lang, "servers ↑", "серверы ↑")))
                }
                @if visible_users != total_users {
                    span style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute);" {
                        (crate::i18n::tr(lang, "showing ", "показано "))
                        (visible_users)
                        (crate::i18n::tr(lang, " of ", " из "))
                        (total_users)
                    }
                }
            }
        }

        // Phase C-3.2 — add-user form, now SECOND in the page (after
        // search) per the «accidentally typed brat in add-user» bug
        // 2026-05-19. UUID + tuic_password + sub_token are all
        // mint-on-server; the operator only types the human-readable
        // id. **All secrets — UUID, tuic_password, sub_token, AND
        // the WireGuard keypair — are generated unconditionally**
        // (per CLAUDE.md "users are maximally low-tech" one-action
        // ceiling: creation = type id + Enter, no checkboxes for the
        // operator either). Per-key management (rotate WG, replace
        // with operator-provided pubkey, etc.) lives on the
        // user-detail page.
        //
        // Visual distinction (dashed border + accent eyebrow tag)
        // signals «destructive: creates a new row». The search
        // container above uses no surround at all, so they're hard
        // to confuse at a glance.
        div style="margin: 16px 0 28px; padding: 14px 16px; border: 1px dashed var(--accent); background: var(--paper);" {
            div style="font-family: var(--mono); font-size: 10px; color: var(--accent); letter-spacing: 0.14em; text-transform: uppercase; margin-bottom: 8px;" {
                (crate::i18n::tr(
                    lang,
                    "↓ create a NEW user (mints UUID + keys) ↓",
                    "↓ создать НОВОГО пользователя (сгенерирует UUID + ключи) ↓",
                ))
            }
            form method="post" action="/admin/users"
                 style="display: flex; gap: 10px; align-items: baseline; flex-wrap: wrap;" {
                label style="font-family: var(--mono); font-size: 11px; color: var(--mute); letter-spacing: 0.14em; text-transform: uppercase;" {
                    (crate::i18n::tr(lang, "new id", "новый id"))
                }
                input type="text" name="id" required="required"
                      placeholder="alice"
                      pattern="[a-z0-9._-]{2,32}"
                      maxlength="32"
                      oninput="this.value=this.value.toLowerCase().replace(/\\s+/g,'-').replace(/[^a-z0-9._-]/g,'').slice(0,32);"
                      title=(crate::i18n::tr(
                          lang,
                          "2-32 chars: a-z 0-9 . _ - only. Spaces become hyphens; uppercase becomes lowercase; other chars are stripped as you type.",
                          "2-32 символа: a-z 0-9 . _ - только. Пробелы превращаются в дефисы; верхний регистр в нижний; остальные символы отбрасываются по мере набора.",
                      ))
                      style="flex: 1; max-width: 280px; padding: 4px 8px; border: 1px solid var(--rule-s); background: var(--paper); font-family: var(--mono); font-size: 12px; color: var(--ink);";
                // D1 audit catch — pre-2026-05-22 user-create
                // produced a user with ZERO grants, then operator
                // clicked through every server to grant access
                // (3 servers × every user × manual). Default ON
                // means «one click = ready to use»; uncheck to
                // create a deliberately-ungranted user (e.g. test
                // account, future-server placeholder, paused user).
                label style="font-family: var(--mono); font-size: 11px; color: var(--ink); display: flex; align-items: center; gap: 4px;"
                      title=(crate::i18n::tr(
                          lang,
                          "Grant access to EVERY currently-registered server (default ON). Uncheck to create a user with zero grants — useful for test accounts or paused users.",
                          "Дать доступ КО ВСЕМ зарегистрированным сейчас серверам (по-умолчанию вкл). Сними галку, чтобы создать пользователя без грантов — полезно для тестового или приостановленного аккаунта.",
                      )) {
                    input type="checkbox" name="grant_all" value="1" checked="checked"
                          style="margin: 0;";
                    (crate::i18n::tr(lang, "grant all servers", "выдать все серверы"))
                }
                button type="submit"
                       title=(crate::i18n::tr(
                           lang,
                           "Mint UUID + tuic_password + sub_token + WG keypair, optionally grant all servers; redirect to /admin/users/<id> where keys are visible",
                           "Сгенерирует UUID + tuic_password + sub_token + WG-пару, по-желанию выдаст все серверы; редирект на /admin/users/<id> где ключи видны",
                       ))
                       style="padding: 4px 12px; border: 1px solid var(--accent); background: var(--accent); color: var(--paper); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                    (crate::i18n::tr(lang, "create user", "создать пользователя"))
                }
                span style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute);" {
                    (crate::i18n::tr(
                        lang,
                        "→ all keys are auto-generated and shown on the user page",
                        "→ все ключи генерируются автоматически и видны на странице пользователя",
                    ))
                }
            }
        }

        @if users_list.is_empty() {
            p style="font-family: var(--serif); font-style: italic; color: var(--mute); padding: 24px 0;" {
                (crate::i18n::tr(lang, "No users yet. Type an id above and hit ", "Пользователей пока нет. Введи id выше и нажми "))
                span.ed-mono { (crate::i18n::tr(lang, "create", "создать")) }
                (crate::i18n::tr(lang, ", or use ", ", либо запусти "))
                span.ed-mono { "vpnctl user create <id>" }
                (crate::i18n::tr(lang, " from the CLI. Then grant server access via ", " в CLI. Затем выдай доступ к серверу через "))
                span.ed-mono { "vpnctl grant <user> <server>" }
                (crate::i18n::tr(lang, " (web UI lands in C-3.3).", " (web UI приедет в C-3.3)."))
            }
        } @else if pairs.is_empty() {
            p style="font-family: var(--serif); font-style: italic; color: var(--mute); padding: 12px 0;" {
                (crate::i18n::tr(lang, "No users match ", "Под фильтр не подошёл никто: "))
                span.ed-mono { "q=" (q_lower) }
                (crate::i18n::tr(lang, ". Loosen the search above or ", ". Расслабь поиск выше или "))
                a href="/admin/users" style="color: var(--ink);" {
                    (crate::i18n::tr(lang, "clear it", "очисти его"))
                }
                "."
            }
        } @else {
            div {
                @for (display_idx, (_orig_idx, u, g)) in pairs.iter().enumerate() {
                    (user_row(display_idx, u, *g, lang))
                }
            }
        }
    };
    Ok(shell("users", &theme, &accent, lang, body))
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

/// Public production subscription URL — the one a client mobile app
/// will actually fetch from. Renders the ninitux-compat endpoint
/// served by `vpnctld` since the Phase 5 cutover (2026-05-19): nginx
/// on 192.168.0.207 reverse-proxies `https://ninitux.com/api/v1/app/config/{device_id}`
/// to `http://192.168.0.236:18402/api/v1/app/config/{device_id}`,
/// byte-equivalent for every registered user.
///
/// Returns `None` when the device_id fails the shape gate
/// (`vpnctl_crypto::is_valid_vpn_router_device_id`). Defensive —
/// `SqliteInventory::set_vpn_router_device_id` enforces the same
/// gate before writing, so a valid row should always pass; the
/// `None` branch closes the gap where a malformed device_id lands
/// in the DB via migration / external mutation / direct sqlite
/// edit. Without this check, a value like `evil?h=x.com` would
/// render as `https://ninitux.com/api/v1/app/config/evil?h=x.com`
/// and the QR a user scans would point at an attacker-controlled
/// path on a third-party host.
///
/// Hostname is hard-coded because the cutover IS the contract —
/// every client in production polls this exact URL on a fixed
/// schedule. Reading from a per-request `Host` header would
/// silently drift the displayed URL if the operator opens the admin
/// UI via IP vs hostname. (Review-agent flagged the hard-coding as
/// a config-knob debt — TODO: promote to `VPNCTLD_PUBLIC_SUBSCRIPTION_BASE_URL`
/// env var with this value as default, so staging deployments can
/// override. Defer; current deployment is a single domain.)
fn ninitux_url(device_id: &str) -> Option<String> {
    if !vpnctl_crypto::is_valid_vpn_router_device_id(device_id) {
        return None;
    }
    Some(format!("https://ninitux.com/api/v1/app/config/{device_id}"))
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
        // `min-height: 244px` matches the QR card's outer dimension
        // (220 QR + 12 padding × 2 = 244). Forces every Flow card
        // (A/B/C) to the same row height regardless of URL length,
        // so the three-column grid above is visually aligned.
        //
        // The right-side `min-width: 0` is required so the flex child
        // can shrink below its natural width — otherwise long URLs in
        // the textarea push the column wider than its grid-track.
        div style="display: flex; gap: 14px; align-items: stretch; margin-bottom: 14px; min-height: 244px;" {
            (qr_svg(link))
            div style="flex: 1; display: flex; flex-direction: column; gap: 6px; min-width: 0;" {
                // Masked-preview is single-line with ellipsis. Pre-
                // 2026-05-19 it had `word-break: break-all` which let
                // long URLs wrap onto 2-3 lines — Flow A (short sub
                // URL = 1 line) and Flow B/C (long wireguard:// /
                // vpn:// = 2-3 lines) ended up with different
                // right-side heights, breaking the column alignment
                // Pavel screenshotted.
                div style="font-family: var(--mono); font-size: 11px; color: var(--soft); white-space: nowrap; overflow: hidden; text-overflow: ellipsis;"
                     title=(mask_secret(link)) {
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

/// Fixed display side of every share-link QR, in CSS pixels. Picked
/// to fit on a phone screen at scan distance while keeping the
/// user-detail page's Flow column narrow enough that the textarea
/// doesn't wrap awkwardly.
const QR_DISPLAY_PX: u32 = 220;

/// Number of leading chars rendered inside JA3 / JA4 chips on the
/// subscription-access table. Full value is in the chip's `title=`
/// tooltip. Eight is a sweet spot — long enough that two distinct
/// fingerprints diverge in the rendered prefix (JA3 starts with the
/// numeric TLS-version-and-cipher-list, JA4 with the protocol-class
/// `t13d1516h2_…` segment), short enough to keep the chip from
/// dominating the row. Pinned by track_1_4 admin_smoke tests.
const JA_CHIP_PREFIX_CHARS: usize = 8;

fn qr_svg(url: &str) -> Markup {
    use qrcode::QrCode;
    use qrcode::render::svg;

    match QrCode::new(url.as_bytes()) {
        Ok(code) => {
            // Render at a sensible native size — the actual pixel
            // dimensions vary by URL length (denser matrix → larger
            // intrinsic SVG with `min_dimensions`). We don't care
            // because the CSS wrapper below forces the on-screen
            // size to a fixed `QR_DISPLAY_PX` regardless of the
            // intrinsic SVG dimensions.
            //
            // Pre-2026-05-19 the wrapper had NO fixed size: Flow A's
            // shortish subscription URL produced a ~220px SVG, but
            // Flow B's full wireguard:// (~600 chars base64) produced
            // a ~280-320px SVG. The three cards (A / B / C) jumped
            // 60-90px in width and the layout «прыгает» (Pavel
            // 2026-05-19).
            let svg_str = code
                .render::<svg::Color<'_>>()
                .min_dimensions(QR_DISPLAY_PX, QR_DISPLAY_PX)
                .quiet_zone(true)
                .dark_color(svg::Color("#1a1611"))
                .light_color(svg::Color("#f5efe6"))
                .build();
            // Wrapper: padded card + inner fixed-size frame. The
            // `> svg` selector with `!important` overrides the
            // hard-coded `width=` / `height=` attributes that
            // `qrcode`'s SVG builder writes — CSS scales the SVG to
            // QR_DISPLAY_PX uniformly. Matrix density still varies
            // visually (denser = finer modules) but the CARD width
            // is constant across all flows.
            //
            // Container width = QR + 2*padding (12px each side).
            let card_px = QR_DISPLAY_PX + 24;
            let inner_style = format!(
                "width: {QR_DISPLAY_PX}px; height: {QR_DISPLAY_PX}px; \
                 display: flex; align-items: stretch;"
            );
            let wrapper_style = format!(
                "display: inline-block; padding: 12px; background: var(--paper); \
                 border: 1px solid var(--rule); width: {card_px}px; height: {card_px}px; \
                 box-sizing: border-box;"
            );
            // Scoped <style> — targets the QR frame's SVG child.
            // `!important` overcomes the SVG's own intrinsic
            // width/height attrs which some browsers honour over CSS.
            //
            // The selector is `.vpnctl-qr-frame svg` (descendant, no
            // child combinator) because Maud HTML-escapes text inside
            // `style { "..." }` — a literal `>` would become `&gt;` and
            // the selector would silently match nothing. (Caught
            // 2026-05-19: previous version used `> svg` and the CSS
            // never applied → QR cards stayed at native SVG sizes →
            // visible-jump bug Pavel screenshotted.) Wrapping the CSS
            // string in `PreEscaped` would also work but the descendant
            // selector is semantically equivalent (frame has exactly
            // one SVG child) and harder to break.
            //
            // Inline style block sits inside the wrapper so it ships
            // only when a QR is rendered (no penalty to other pages).
            html! {
                div style=(wrapper_style) {
                    style {
                        ".vpnctl-qr-frame svg { \
                          width: 100% !important; \
                          height: 100% !important; \
                          display: block; \
                        }"
                    }
                    div class="vpnctl-qr-frame" style=(inner_style) {
                        (maud::PreEscaped(svg_str))
                    }
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
/// For each server in `peers`, pick `user`'s per-server uuid out of
/// the peers list (migration 0016 made `users_for_server` return User
/// rows with `uuid` already overridden by `grants.client_uuid`). The
/// returned User has its `uuid` swapped to the per-server value; all
/// other fields stay at the user's global values.
///
/// `server_id` is for diagnostics only — we log a WARN when peers is
/// non-empty AND `user.id` is missing from it, because that means
/// some caller built the peers list for the wrong server OR a grant
/// got revoked between fetch + render. Either case would silently
/// render a wrong-uuid share-link (the byte-equivalent of pre-Phase-1
/// behaviour, but masking a real bug) — surfacing it as a warn
/// matches the wg_addressing::peer_octet_in_slash24 contract.
fn user_for_server_render(
    user: &vpnctl_core::User,
    peers: &[vpnctl_core::User],
    server_id: &vpnctl_core::ServerId,
) -> vpnctl_core::User {
    let per_server_uuid = peers
        .iter()
        .find(|p| p.id == user.id)
        .map(|p| p.uuid.as_str());
    match per_server_uuid {
        Some(uuid) => user.with_per_server_uuid(uuid),
        None => {
            if !peers.is_empty() {
                tracing::warn!(
                    target = "vpnctld::admin",
                    server = %server_id,
                    user = %user.id,
                    "peer list for server does not contain target user; \
                     falling back to global user.uuid (caller bug — peers \
                     built for wrong server, or grant revoked mid-render)"
                );
            }
            user.clone()
        }
    }
}

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
        let per_server_user = user_for_server_render(user, peers, &server.id);
        match vpnctl_protocols::amnezia_share_link(&ctx, &per_server_user) {
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
        let per_server_user = user_for_server_render(user, peers, &server.id);
        for pid in &server.enabled_protocols {
            let Some(proto) = state.registry.protocol(pid) else {
                tracing::warn!(target = "vpnctld::admin", protocol = %pid, "protocol not registered");
                continue;
            };
            match proto.share_link(&ctx, &per_server_user) {
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

/// Phase 4a — query parameters for the user-detail page. Today only
/// the VPN-egress toggle; more flags can land here as they show up.
#[derive(Debug, Default, serde::Deserialize)]
pub(crate) struct UserDetailQuery {
    /// When `?show_egress=1`, the sub-access table includes rows
    /// where src IP is one of our own VPN-server addresses (the
    /// «in full-tunnel mode the user's egress is the VPN exit»
    /// case). Default = off, so the operator sees only real client
    /// IPs (the genuine abuse-signal).
    #[serde(default)]
    show_egress: Option<String>,
}

impl UserDetailQuery {
    fn show_egress(&self) -> bool {
        matches!(self.show_egress.as_deref(), Some("1") | Some("true"))
    }
}

pub(crate) async fn user_detail(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(user_id_str): Path<String>,
    axum::extract::Query(query): axum::extract::Query<UserDetailQuery>,
) -> Result<Markup, Response> {
    let (theme, accent, lang) = theme_accent_lang(&headers);
    let uid = vpnctl_core::UserId(user_id_str.clone());
    let show_egress = query.show_egress();

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
    //
    // Also pre-fetch the (server, protocol) hidden map for every
    // granted server in the same loop (migration 0018 / NM-10).
    // Used by the per-protocol delivery grid below the "Server
    // access" toggles — without it the grid would either N+1-query
    // `is_server_protocol_hidden` per cell or omit the hidden-state
    // label entirely. Loop body now issues 3 sequential queries
    // per granted server (secrets / peers / hidden); servers count
    // is bounded (≤3 in production, ≤10 in any realistic homelab),
    // so each query × server is cheap. If this ever stretches into
    // dozens of granted servers per user, fold the three reads into
    // one JOIN-based helper.
    let mut secrets_per_server = std::collections::HashMap::new();
    let mut peers_per_server = std::collections::HashMap::new();
    let mut hidden_per_server: std::collections::HashMap<
        vpnctl_core::ServerId,
        std::collections::HashMap<vpnctl_core::ProtocolId, bool>,
    > = std::collections::HashMap::new();
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
        let hidden = state
            .inv
            .list_server_protocols_with_hidden(&s.id)
            .await
            .map_err(|e| internal_error(anyhow::Error::new(e)))?;
        hidden_per_server.insert(s.id.clone(), hidden);
    }
    // Per-user override map (server_id, protocol_id) → disabled.
    // One query for the whole user; small (typically 0 entries until
    // the operator clicks "block" on a protocol). Empty map = no
    // overrides = inherit every server's visibility verbatim.
    let user_overrides = state
        .inv
        .list_protocol_overrides_for_user(&uid)
        .await
        .map_err(|e| internal_error(anyhow::Error::new(e)))?;

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
    // Phase 3+ ninitux-compat URL: the production endpoint that mobile
    // apps actually fetch. Rendered as the PRIMARY subscription URL
    // (with QR) when the user has a device_id pinned; the legacy
    // `/sub/<token>` URL is demoted to a secondary "LAN fallback"
    // block below it. When no device_id is pinned, falls back to the
    // legacy URL as the primary — kept as an escape hatch for users
    // that haven't been mapped to ninitux yet (operator can pin one
    // via the import script or the future web action).
    let ninitux_device_id = user.vpn_router_device_id.clone();
    let ninitux_url_str = ninitux_device_id.as_deref().and_then(ninitux_url);

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
    // Sibling tally for wgturn — same shape as wg_capable_granted
    // / wg_capable_inventory but for the wgturn protocol. Drives
    // Flow D's conditional rendering and its empty-state copy.
    let wgturn_capable_granted: Vec<&vpnctl_core::ServerId> = servers
        .iter()
        .filter(|s| s.enabled_protocols.iter().any(|p| p.0 == "wgturn"))
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
    // Phase 4a — default hides VPN-egress rows (where src IP =
    // one of our own VPN-server addresses, i.e. user is in
    // full-tunnel + we're seeing OUR exit IP, not theirs). The
    // `?show_egress=1` query flag flips it on for the case Pavel
    // explicitly wants to inspect the full-tunnel traffic.
    let recent_access = state
        .inv
        .recent_sub_access_filtered(&uid, 25, show_egress)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(target = "vpnctld::admin", user = %uid, error = %e, "recent_sub_access_filtered failed");
            Vec::new()
        });
    // Phase 4a — aggregates over the 30-day window for the summary
    // cards above the timeline table. Failure → zeros; cards still
    // render so the page doesn't break (operator sees the
    // diagnostic in journalctl).
    let access_aggregates = state
        .inv
        .sub_access_aggregates_for_user(&uid, 30)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(target = "vpnctld::admin", user = %uid, error = %e, "sub_access_aggregates_for_user failed");
            vpnctl_inventory::SubAccessAggregates::default()
        });
    // Heat threshold — first cut. 5 distinct IPs in 24h is a soft
    // signal that the URL has been shared. Configurable later via the
    // Settings section once that exists.
    const ABUSE_HEAT_THRESHOLD: u64 = 5;
    let heat_24h = ips_24h >= ABUSE_HEAT_THRESHOLD;

    let body = html! {
        div.ed-art-eyebrow {
            a href="/admin/users" style="color: var(--mute); text-decoration: none;" {
                (crate::i18n::tr(lang, "← all users", "← все пользователи"))
            }
            (crate::i18n::tr(lang, "  ·  user", "  ·  пользователь"))
        }
        h1.ed-art-h1 { (user.id.0) }
        p.ed-art-deck {
            "uuid " span.ed-mono { (user.uuid) }
        }

        // Subscription URL + QR — the headline for this page.
        //
        // Two URLs may exist per user post-Phase-5 (ninitux cutover,
        // 2026-05-19):
        //   * PRIMARY: the ninitux production URL
        //     `https://ninitux.com/api/v1/app/config/<device_id>` —
        //     the URL clients actually fetch. Only present when the
        //     user has a `vpn_router_device_id` pinned (33/33
        //     production users do; legacy bash-only or freshly-
        //     created users may not).
        //   * SECONDARY / LAN fallback: the legacy `/sub/<token>`
        //     URL served by vpnctld directly on port 18402. Useful
        //     for LAN debugging and as the fallback artefact for
        //     users without a device_id.
        //
        // The QR encodes the PRIMARY URL when available — that's
        // what a mobile-app user must scan. Showing the LAN URL in
        // the QR (the pre-Phase-5 behaviour) silently broke any
        // share-via-QR workflow because the client app can't reach
        // 192.168.0.236 from outside the operator's LAN. Caught by
        // visual review 2026-05-19; this block is the fix.
        div.ed-art-eyebrow style="margin-top: 28px;" {
            (crate::i18n::tr(lang, "Subscription", "Подписка"))
        }
        @match (&ninitux_device_id, &ninitux_url_str, &sub_token, &sub_url_str) {
            (Some(device_id), Some(ninitux), _, _) => {
                // Primary: ninitux production URL — QR scans this.
                div style="display: flex; gap: 28px; align-items: flex-start; padding: 16px 0;" {
                    (qr_svg(ninitux))
                    div style="font-family: var(--mono); font-size: 12px; line-height: 1.7;" {
                        div { span style="color: var(--mute);" { "url        " } (ninitux) }
                        div { span style="color: var(--mute);" { "device_id  " } (device_id) }
                        div style="margin-top: 12px; color: var(--soft); font-family: var(--serif); font-style: italic;" {
                            (crate::i18n::tr(lang, "Production URL served via nginx on ", "Production URL подаётся через nginx на "))
                            span.ed-mono { "ninitux.com" }
                            (crate::i18n::tr(lang, " → vpnctld. ", " → vpnctld. "))
                            (crate::i18n::tr(
                                lang,
                                "The user's mobile app polls this URL on a fixed schedule (3600s). ",
                                "Мобильное приложение опрашивает этот URL по таймеру (3600 сек). ",
                            ))
                            (crate::i18n::tr(
                                lang,
                                "Share the QR or the URL — both encode the same thing.",
                                "Отдай QR или URL — кодируют одно и то же.",
                            ))
                        }
                    }
                }
                // Legacy LAN fallback — collapsed below the primary,
                // muted styling, only useful for LAN debugging.
                @if let (Some(token), Some(legacy_url)) = (sub_token.as_ref(), sub_url_str.as_ref()) {
                    details style="margin-top: 8px; font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                        summary style="cursor: pointer;" { "legacy /sub/<token> fallback (LAN-only)" }
                        div style="padding: 8px 0 0 16px; line-height: 1.7;" {
                            div { span style="color: var(--mute);" { "url   " } (legacy_url) }
                            div { span style="color: var(--mute);" { "token " } (mask_secret(token)) }
                            form method="post"
                                 action=(format!("/admin/users/{}/sub-token/regenerate", path_segment_encode(&user.id.0)))
                                 style="margin-top: 10px;" {
                                button type="submit"
                                       title=(crate::i18n::tr(
                                           lang,
                                           "Mint a new sub_token. Does NOT affect the ninitux URL above — that one is keyed by device_id, which is stable.",
                                           "Сгенерировать новый sub_token. НЕ влияет на ninitux URL выше — тот ключевой по device_id, который стабилен.",
                                       ))
                                       style="padding: 4px 10px; border: 1px solid var(--rule-s); background: transparent; font-family: var(--mono); font-size: 11px; color: var(--mute); cursor: pointer;" {
                                    (crate::i18n::tr(lang, "rotate sub-token", "ротировать sub-token"))
                                }
                            }
                        }
                    }
                }
            }
            (None, _, Some(token), Some(url)) => {
                // No device_id pinned — fall back to legacy /sub/<token>
                // as the primary. Operator should pin a device_id to
                // unlock the ninitux URL (import script or future web
                // action).
                div style="display: flex; gap: 28px; align-items: flex-start; padding: 16px 0;" {
                    (qr_svg(url))
                    div style="font-family: var(--mono); font-size: 12px; line-height: 1.7;" {
                        div { span style="color: var(--mute);" { (crate::i18n::tr(lang, "url   ", "url   ")) } (url) }
                        div { span style="color: var(--mute);" { (crate::i18n::tr(lang, "token ", "token ")) } (mask_secret(token)) }
                        div style="margin-top: 12px; color: var(--soft); font-family: var(--serif); font-style: italic;" {
                            (crate::i18n::tr(lang, "Legacy ", "Легаси ")) span.ed-mono { "/sub/<token>" }
                            (crate::i18n::tr(lang, " URL — LAN-only. No ", " URL — только LAN. У этого пользователя нет "))
                            span.ed-mono { "vpn_router_device_id" }
                            (crate::i18n::tr(
                                lang,
                                " pinned for this user, so the production ",
                                ", поэтому production-URL ",
                            ))
                            span.ed-mono { "ninitux.com" }
                            (crate::i18n::tr(lang, " URL is not available yet. Pin one via ", " пока недоступен. Привяжи через "))
                            span.ed-mono { "scripts/import_from_subscription_server.py --apply" } "."
                        }
                        form method="post"
                             action=(format!("/admin/users/{}/sub-token/regenerate", path_segment_encode(&user.id.0)))
                             style="margin-top: 14px;" {
                            button type="submit"
                                   title=(crate::i18n::tr(
                                       lang,
                                       "Mint a new sub_token; the previous URL stops working immediately",
                                       "Сгенерировать новый sub_token; предыдущий URL перестанет работать немедленно",
                                   ))
                                   style="padding: 4px 10px; border: 1px solid var(--ink); background: transparent; font-family: var(--mono); font-size: 11px; color: var(--ink); cursor: pointer;" {
                                (crate::i18n::tr(lang, "rotate sub-token", "ротировать sub-token"))
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
                               title="Generate this user's FIRST sub-token + the public /sub/<token> URL. Safe — no existing config to invalidate; the user's QR + clients will start working after this."
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
        div.ed-art-eyebrow { (crate::i18n::tr(lang, "WireGuard keypair", "WireGuard-пара ключей")) }
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

                    // Distribution panel — one column per client app.
                    // Same secret material, several wire formats:
                    //   * Flow A — sing-box JSON via /sub/<token> URL
                    //   * Flow B — wireguard:// (official WG app, Hiddify)
                    //   * Flow C — vpn://    (AmneziaVPN)
                    //   * Flow D — wgturn:// (wgturn-cli, VK-TURN relay)
                    //                  — only when a granted server has
                    //                  the wgturn protocol enabled. Lives
                    //                  here so the operator hands the
                    //                  user one artefact per client app,
                    //                  same UX as A/B/C.
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
                    //
                    // Grid uses `auto-fit minmax(340px, 1fr)` so the
                    // column count adapts to viewport + Flow D's
                    // conditional presence (3 cols for non-wgturn
                    // users, 4 for wgturn users; wraps to 2x2 on
                    // narrower viewports).
                    div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(340px, 1fr)); gap: 20px; margin-top: 24px; padding-top: 16px; border-top: 1px dotted var(--rule);" {
                        // Flow A — sing-box / Hiddify subscription URL.
                        // The QR renders the same sub_url shown in the
                        // Subscription block at the top of the page;
                        // duplicated here on purpose so the operator
                        // copies the WG-via-Hiddify link from the same
                        // distribution panel as the WG-native link.
                        div {
                            div style="font-family: var(--mono); font-size: 11px; color: var(--mute); letter-spacing: 0.14em; text-transform: uppercase; margin-bottom: 8px;" {
                                (crate::i18n::tr(lang, "Flow A — Hiddify / Sing-box", "Поток A — Hiddify / Sing-box"))
                            }
                            @match (&sub_token, &sub_url_str) {
                                (Some(_), Some(url)) => {
                                    div style="font-family: var(--mono); font-size: 11px; color: var(--mute); margin-bottom: 6px;" {
                                        (crate::i18n::tr(
                                            lang,
                                            "all granted servers · refreshes on its own",
                                            "все выданные серверы · обновляется само",
                                        ))
                                    }
                                    (share_link_card(url, &html! {
                                        (crate::i18n::tr(
                                            lang,
                                            "Sing-box / Hiddify pulls the full config (every protocol on every granted server, including WireGuard with the private key embedded) and refreshes on its own schedule. ",
                                            "Sing-box / Hiddify тянет полный конфиг (все протоколы на всех выданных серверах, включая WireGuard с приватным ключом) и обновляет сам по расписанию. ",
                                        ))
                                        b { (crate::i18n::tr(
                                            lang,
                                            "Recommended default — one URL covers everything.",
                                            "Рекомендованный default — один URL покрывает всё.",
                                        )) }
                                    }))
                                }
                                _ => {
                                    p style="font-family: var(--serif); font-style: italic; color: var(--mute); font-size: 12px; margin: 0;" {
                                        (crate::i18n::tr(lang, "Mint a sub-token in the ", "Сгенерируй sub-token в блоке "))
                                        b { (crate::i18n::tr(lang, "Subscription", "Подписка")) }
                                        (crate::i18n::tr(lang, " block above to populate this card.", " выше, чтобы заполнить эту карточку.", ))
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
                                (crate::i18n::tr(lang, "Flow B — official WireGuard app / Hiddify", "Поток B — официальное WireGuard / Hiddify"))
                            }
                            @let wg_links: Vec<_> = share_links
                                .iter()
                                .filter(|(_, pid, _)| pid.0 == "wireguard")
                                .collect();
                            @if wg_links.is_empty() {
                                @if servers.is_empty() {
                                    p style="font-family: var(--serif); font-style: italic; color: var(--mute); font-size: 12px; margin: 0;" {
                                        (crate::i18n::tr(
                                            lang,
                                            "No servers granted to this user yet. Grant a server in the ",
                                            "У пользователя пока нет грантов. Выдай сервер в секции ",
                                        ))
                                        b { (crate::i18n::tr(lang, "Server access", "Доступ к серверам")) }
                                        (crate::i18n::tr(
                                            lang,
                                            " section below — if it runs WireGuard, the QR appears here.",
                                            " ниже — если сервер крутит WireGuard, QR появится здесь.",
                                        ))
                                    }
                                } @else if wg_capable_granted.is_empty() {
                                    // Case B — granted servers exist but
                                    // NONE declare wireguard. Most
                                    // common case for bash-imported
                                    // users (vps-is-01 et al. run
                                    // VLESS/TUIC/Hy2, not WG).
                                    p style="font-family: var(--serif); font-size: 12px; line-height: 1.55; color: var(--ink); margin: 0 0 8px;" {
                                        b { (crate::i18n::tr(
                                            lang,
                                            "Keys exist, but no granted server runs WireGuard.",
                                            "Ключи есть, но ни на одном выданном сервере не крутится WireGuard.",
                                        )) }
                                        (crate::i18n::tr(
                                            lang,
                                            " The user has a WG keypair (see pubkey above), so the moment a WG-capable server is granted — or ",
                                            " У пользователя есть WG-пара ключей (см. pubkey выше), так что в момент когда WG-сервер будет выдан — либо ",
                                        ))
                                        span.ed-mono { "wireguard" }
                                        (crate::i18n::tr(
                                            lang,
                                            " is added to an existing server's ",
                                            " добавится в ",
                                        ))
                                        span.ed-mono { "enabled_protocols" }
                                        (crate::i18n::tr(
                                            lang,
                                            " — the QR will appear here.",
                                            " существующего сервера — QR появится здесь.",
                                        ))
                                    }
                                    p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 0 0 6px;" {
                                        (crate::i18n::tr(lang, "Currently granted: ", "Текущие гранты: "))
                                        @for (i, s) in servers.iter().enumerate() {
                                            @if i > 0 { ", " }
                                            span.ed-mono { (s.id.0) }
                                        }
                                        (crate::i18n::tr(lang, " — none have ", " — ни у одного нет "))
                                        span.ed-mono { "wireguard" }
                                        (crate::i18n::tr(lang, " in their protocol list.", " в списке протоколов."))
                                    }
                                    @if !wg_capable_inventory.is_empty() {
                                        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 0;" {
                                            (crate::i18n::tr(
                                                lang,
                                                "WG-capable servers in the inventory you could grant: ",
                                                "WG-серверы в инвентаре, которые можно выдать: ",
                                            ))
                                            @for (i, sid) in wg_capable_inventory.iter().enumerate() {
                                                @if i > 0 { ", " }
                                                span.ed-mono { (sid.0) }
                                            }
                                            "."
                                        }
                                    } @else {
                                        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 0;" {
                                            (crate::i18n::tr(
                                                lang,
                                                "No WG-capable server in the entire inventory. The ",
                                                "В инвентаре нет ни одного WG-сервера. ",
                                            ))
                                            span.ed-mono { "amneziawg" }
                                            (crate::i18n::tr(lang, " kernel + ", " kernel + "))
                                            span.ed-mono { "wireguard" }
                                            (crate::i18n::tr(
                                                lang,
                                                " protocol need to be enabled on a node first (CLI: ",
                                                " протокол должны быть сначала включены на ноде (CLI: ",
                                            ))
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
                                        (crate::i18n::tr(lang, "Granted servers ", "Выданные серверы "))
                                        @for (i, sid) in wg_capable_granted.iter().enumerate() {
                                            @if i > 0 { ", " }
                                            span.ed-mono { (sid.0) }
                                        }
                                        (crate::i18n::tr(
                                            lang,
                                            " declare wireguard but the share-link render failed. Likely missing ",
                                            " объявляют wireguard, но рендер share-link провалился. Скорее всего нет ",
                                        ))
                                        span.ed-mono { "wireguard.server_public_key" }
                                        " / "
                                        span.ed-mono { "wireguard.server_private_key" }
                                        (crate::i18n::tr(lang, " server secret — check ", " серверного секрета — проверь "))
                                        span.ed-mono { "journalctl -u vpnctld" }
                                        "."
                                    }
                                }
                            } @else {
                                @for (sid, _pid, link) in &wg_links {
                                    div style="margin-bottom: 18px;" {
                                        div style="font-family: var(--mono); font-size: 11px; color: var(--mute); margin-bottom: 6px;" {
                                            (crate::i18n::tr(lang, "server ", "сервер ")) (sid.0)
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
                                            (crate::i18n::tr(
                                                lang,
                                                "Opens in the official WireGuard app (mobile + desktop) and Hiddify. Link is ",
                                                "Открывается в официальном WireGuard (mobile + desktop) и Hiddify. Длина ссылки ",
                                            ))
                                            (link.len())
                                            (crate::i18n::tr(
                                                lang,
                                                " chars (the private key is base64-embedded inside). Click the box above to select-all + copy.",
                                                " символов (приватный ключ закодирован base64 внутри). Кликни на блок выше, чтобы выделить и скопировать.",
                                            ))
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
                                (crate::i18n::tr(lang, "Flow C — AmneziaVPN", "Поток C — AmneziaVPN"))
                            }
                            @let amnezia_links: Vec<_> = amnezia_links
                                .iter()
                                .collect();
                            @if amnezia_links.is_empty() {
                                @if servers.is_empty() {
                                    p style="font-family: var(--serif); font-style: italic; color: var(--mute); font-size: 12px; margin: 0;" {
                                        (crate::i18n::tr(
                                            lang,
                                            "Grant a WireGuard-capable server to populate this card.",
                                            "Выдай сервер с WireGuard, чтобы заполнить эту карточку.",
                                        ))
                                    }
                                } @else if wg_capable_granted.is_empty() {
                                    p style="font-family: var(--serif); font-style: italic; color: var(--mute); font-size: 12px; margin: 0;" {
                                        (crate::i18n::tr(
                                            lang,
                                            "No granted server runs WireGuard yet — add ",
                                            "Ни на одном выданном сервере не крутится WireGuard — добавь ",
                                        ))
                                        span.ed-mono { "wireguard" }
                                        (crate::i18n::tr(
                                            lang,
                                            " to an existing server's protocols on its detail page.",
                                            " в протоколы существующего сервера на странице деталей.",
                                        ))
                                    }
                                } @else {
                                    p style="font-family: var(--serif); font-style: italic; color: var(--mute); font-size: 12px; margin: 0;" {
                                        (crate::i18n::tr(lang, "Granted WG servers ", "Выданные WG-серверы "))
                                        @for (i, sid) in wg_capable_granted.iter().enumerate() {
                                            @if i > 0 { ", " }
                                            span.ed-mono { (sid.0) }
                                        }
                                        (crate::i18n::tr(
                                            lang,
                                            " — but AmneziaVPN link rendering failed (check ",
                                            " — но рендер AmneziaVPN-ссылки провалился (проверь ",
                                        ))
                                        span.ed-mono { "journalctl -u vpnctld" }
                                        ")."
                                    }
                                }
                            } @else {
                                @for (sid, link) in &amnezia_links {
                                    div style="margin-bottom: 18px;" {
                                        div style="font-family: var(--mono); font-size: 11px; color: var(--mute); margin-bottom: 6px;" {
                                            (crate::i18n::tr(lang, "server ", "сервер ")) (sid.0)
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
                                            (crate::i18n::tr(
                                                lang,
                                                "QR / paste opens in AmneziaVPN; the deep link is ",
                                                "QR или вставка открывается в AmneziaVPN; deep-link ",
                                            ))
                                            (link.len())
                                            (crate::i18n::tr(
                                                lang,
                                                " chars (zlib-compressed JSON-container inside). The ",
                                                " символов (внутри zlib-сжатый JSON-контейнер). Ссылка ",
                                            ))
                                            span.ed-mono { ".conf" }
                                            (crate::i18n::tr(
                                                lang,
                                                " link above is a fallback for AmneziaVPN's ",
                                                " выше — резерв через ",
                                            ))
                                            em { (crate::i18n::tr(lang, "File with settings", "Файл с настройками")) }
                                            (crate::i18n::tr(lang, " import path.", " import-путь AmneziaVPN."))
                                        }))
                                    }
                                }
                            }
                        }
                        // Flow D — wgturn (VK-TURN relayed WG).
                        // Separate from Flow A/B/C because:
                        //   * sing-box CAN'T parse `type: wgturn` —
                        //     the protocol is filtered out of /sub
                        //     (`appears_in_sing_box_sub() = false`),
                        //     so Flow A doesn't deliver it.
                        //   * wgturn:// URL is consumed by the
                        //     dedicated `wgturn-cli` client, not the
                        //     official WireGuard app (Flow B) or
                        //     AmneziaVPN (Flow C).
                        // The card ONLY renders when at least one
                        // granted server has the wgturn protocol; for
                        // most users (sing-box-only) this column is
                        // omitted entirely (grid auto-fits).
                        @if !wgturn_capable_granted.is_empty() {
                            div {
                                div style="font-family: var(--mono); font-size: 11px; color: var(--mute); letter-spacing: 0.14em; text-transform: uppercase; margin-bottom: 8px;" {
                                    (crate::i18n::tr(lang, "Flow D — wgturn-cli (VK-TURN relay)", "Поток D — wgturn-cli (VK-TURN relay)"))
                                }
                                @let wgt_links: Vec<_> = share_links
                                    .iter()
                                    .filter(|(_, pid, _)| pid.0 == "wgturn")
                                    .collect();
                                @if wgt_links.is_empty() {
                                    p style="font-family: var(--serif); font-style: italic; color: var(--mute); font-size: 12px; margin: 0;" {
                                        (crate::i18n::tr(lang, "Granted wgturn servers ", "Выданные wgturn-серверы "))
                                        @for (i, sid) in wgturn_capable_granted.iter().enumerate() {
                                            @if i > 0 { ", " }
                                            span.ed-mono { (sid.0) }
                                        }
                                        (crate::i18n::tr(
                                            lang,
                                            " — but the share-link render failed. Most likely missing ",
                                            " — но рендер share-link провалился. Скорее всего нет ",
                                        ))
                                        span.ed-mono { "wgturn:server_wg_public" }
                                        (crate::i18n::tr(
                                            lang,
                                            " server secret or the user has no ",
                                            " серверного секрета или у пользователя отсутствует ",
                                        ))
                                        span.ed-mono { "wireguard_private" }
                                        (crate::i18n::tr(
                                            lang,
                                            " (create the user with ",
                                            " (создай пользователя с ",
                                        ))
                                        span.ed-mono { "--gen-wireguard" }
                                        ")."
                                    }
                                } @else {
                                    @for (sid, _pid, link) in &wgt_links {
                                        div style="margin-bottom: 18px;" {
                                            div style="font-family: var(--mono); font-size: 11px; color: var(--mute); margin-bottom: 6px;" {
                                                "server " (sid.0)
                                                " · ~200 KB/s emergency"
                                            }
                                            (share_link_card(link, &html! {
                                                "Opens in "
                                                span.ed-mono { "wgturn-cli" }
                                                " — the user pastes the link AND their own VK Calls invite at connect time: "
                                                br {}
                                                span.ed-mono style="display: inline-block; margin-top: 4px; padding: 3px 6px; background: var(--paper-tint); font-size: 10.5px;" {
                                                    "wgturn-cli connect-url '<this-link>' --vk-link '<https://vk.com/call/join/...>'"
                                                }
                                                br {}
                                                "Each VK call has a limited concurrent-stream count, so each user supplies their own. ~200 KB/s ceiling per device — position as an emergency channel beside Flow A/B/C, not a daily driver."
                                            }))
                                        }
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
                        (crate::i18n::tr(
                            lang,
                            "No WireGuard keypair on this user. Imported from the legacy bash project, or created before the auto-gen default.",
                            "У этого пользователя нет WireGuard-пары. Импортирован из старого bash-проекта или создан до того как auto-gen стал дефолтом.",
                        ))
                    }
                    form method="post"
                         action=(format!("/admin/users/{}/wireguard/regenerate", path_segment_encode(&user.id.0)))
                         style="margin-top: 8px;" {
                        button type="submit"
                               title="Mint a fresh Curve25519 keypair for this user (legacy self-heal — only shown when the user has no key on file). No existing WireGuard client config to break."
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
        // NM-12 follow-up: the per-grant disable/enable buttons in
        // the per-protocol grid below redirect with the
        // `#server-access` fragment so the operator stays anchored
        // here after a click instead of being scrolled to the top.
        div.ed-art-eyebrow id="server-access" {
            (crate::i18n::t(lang, crate::i18n::K::EyebrowServerAccess))
        }
        @if all_servers.is_empty() {
            p style="font-family: var(--serif); font-style: italic; color: var(--mute); padding: 12px 0;" {
                (crate::i18n::tr(
                    lang,
                    "No servers in the inventory yet. Run ",
                    "Серверов в инвентаре ещё нет. Запусти ",
                ))
                span.ed-mono { "vpnctl bootstrap <id> <ip>" }
                (crate::i18n::tr(lang, " to add one (web wizard lands in Phase E).", " чтобы добавить (веб-мастер придёт в Phase E)."))
            }
        } @else {
            ul style="list-style: none; padding: 0; font-family: var(--serif); font-size: 14px; line-height: 1.8;" {
                @for s in &all_servers {
                    // Outer li wraps BOTH the grant toggle row AND
                    // (for granted servers only) the per-protocol
                    // delivery grid. Single `border-bottom` keeps the
                    // visual rule between *servers*, not between the
                    // grant toggle and its own grid below.
                    li style="padding: 4px 0; border-bottom: 1px dotted var(--rule);" {
                        div style="display: flex; align-items: baseline; gap: 12px;" {
                            // Server id → link to /admin/servers/{id} in a
                            // new tab (Pavel 2026-05-19: «хочу чтоб через
                            // пользователя можно было открыть страницу
                            // сервера в отдельном окне»). `target="_blank"`
                            // + `rel="noopener"` so the new tab doesn't
                            // share window.opener with the user-detail
                            // page (security hygiene + tab-isolation).
                            span style="flex: 1;" {
                                a href=(format!("/admin/servers/{}", path_segment_encode(&s.id.0)))
                                  target="_blank"
                                  rel="noopener"
                                  title=(match lang {
                                      crate::i18n::Locale::En => format!("Open /admin/servers/{} in a new tab", s.id.0),
                                      crate::i18n::Locale::Ru => format!("Открыть /admin/servers/{} в новой вкладке", s.id.0),
                                  })
                                  style="color: var(--ink); text-decoration: none; border-bottom: 1px dotted var(--ink);" {
                                    b { (s.id.0) }
                                }
                                " (" span.ed-mono { (s.address) ":" (s.ssh_port) } ", "
                                (s.kernels.iter().map(|k| k.0.clone()).collect::<Vec<_>>().join("+"))
                                ")"
                            }
                            @if granted_ids.contains(&s.id) {
                                span style="font-family: var(--mono); font-size: 11px; color: var(--acc);" {
                                    (crate::i18n::tr(lang, "✓ access", "✓ доступ"))
                                }
                                form method="post"
                                     action=(format!("/admin/users/{}/grants/{}/revoke",
                                                     path_segment_encode(&user.id.0),
                                                     path_segment_encode(&s.id.0)))
                                     style="margin: 0;" {
                                    @let title_str = match lang {
                                        crate::i18n::Locale::En => format!("Revoke {}'s access to {}", user.id.0, s.id.0),
                                        crate::i18n::Locale::Ru => format!("Отозвать доступ {} к {}", user.id.0, s.id.0),
                                    };
                                    button type="submit"
                                           title=(title_str)
                                           style="padding: 2px 8px; border: 1px solid var(--rule-s); background: transparent; font-family: var(--mono); font-size: 11px; color: var(--mute); cursor: pointer;" {
                                        (crate::i18n::tr(lang, "revoke", "отозвать"))
                                    }
                                }
                            } @else {
                                span style="font-family: var(--mono); font-size: 11px; color: var(--mute);" { "—" }
                                form method="post"
                                     action=(format!("/admin/users/{}/grants/{}",
                                                     path_segment_encode(&user.id.0),
                                                     path_segment_encode(&s.id.0)))
                                     style="margin: 0;" {
                                    @let title_str = match lang {
                                        crate::i18n::Locale::En => format!("Grant {} access to {}", user.id.0, s.id.0),
                                        crate::i18n::Locale::Ru => format!("Выдать доступ {} к {}", user.id.0, s.id.0),
                                    };
                                    button type="submit"
                                           title=(title_str)
                                           style="padding: 2px 8px; border: 1px solid var(--ink); background: transparent; font-family: var(--mono); font-size: 11px; color: var(--ink); cursor: pointer;" {
                                        (crate::i18n::tr(lang, "grant", "выдать"))
                                    }
                                }
                            }
                        }
                        // Per-(user, server, protocol) delivery grid
                        // (migration 0018 / NM-10). Renders ONLY for
                        // GRANTED servers — ungranted ones have no
                        // (user, server) row to attach overrides to,
                        // so `set_grant_protocol_override` would
                        // refuse with Invalid. Each protocol cell
                        // shows its current delivery state +
                        // block/unblock button. Server-hidden
                        // protocols are flagged read-only (operator
                        // adjusts those on /admin/servers/{id}).
                        @if granted_ids.contains(&s.id) {
                            (user_detail_per_protocol_grid(
                                &user.id,
                                s,
                                hidden_per_server.get(&s.id),
                                &user_overrides,
                                &state.registry,
                                lang,
                            ))
                        }
                    }
                }
            }
        }

        // Per-protocol share-links — only meaningful for granted servers.
        @if !servers.is_empty() {
            div.ed-art-eyebrow style="margin-top: 24px;" {
                (crate::i18n::tr(lang, "Per-protocol share links", "Ссылки на отдельные протоколы"))
            }
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

        div.ed-rule {}
        div.ed-art-eyebrow {
            (crate::i18n::tr(lang, "Subscription access", "Обращения к подписке"))
            @if heat_24h {
                span style="color: var(--acc); margin-left: 12px; letter-spacing: 0;" {
                    (crate::i18n::tr(lang, "· abuse signal: ", "· abuse-сигнал: "))
                    (ips_24h)
                    (crate::i18n::tr(
                        lang,
                        " distinct IPs in 24h (≥",
                        " уникальных IP за 24ч (≥",
                    ))
                    (ABUSE_HEAT_THRESHOLD)
                    (crate::i18n::tr(lang, " threshold)", " порог)"))
                }
            }
        }
        // Phase 4a hero row 1 — 30-day aggregates from
        // sub_access_aggregates_for_user. Cards excluded VPN-egress
        // rows; the `last_seen` chip uses the 30d max ts.
        div style="display: flex; flex-wrap: wrap; gap: 36px; padding: 12px 0 6px; font-family: var(--serif);" {
            div title=(crate::i18n::tr(lang, "Distinct real-client IPs over the last 30 days. VPN-egress rows (where src IP = one of our VPN servers, full-tunnel mode) excluded.", "Уникальные клиентские IP за 30 дней. Строки VPN-egress (когда src IP — один из наших VPN-серверов в full-tunnel) исключены.")) {
                div style="font-size: 28px; font-weight: 400; color: var(--ink); line-height: 1;" { (access_aggregates.distinct_ips) }
                div style="font-family: var(--mono); font-size: 10.5px; letter-spacing: 0.14em; text-transform: uppercase; color: var(--mute); margin-top: 4px;" {
                    (crate::i18n::tr(lang, "distinct IPs · 30 days", "уникальных IP · 30 дней"))
                }
            }
            div title=(crate::i18n::tr(lang, "Distinct ISO country codes from GeoIP enrichment (DB-IP Lite City). Rows where GeoIP didn't resolve a country stay uncounted.", "Уникальные ISO-коды стран из GeoIP-обогащения (DB-IP Lite City). Строки где GeoIP не определил страну — не учтены.")) {
                div style="font-size: 28px; font-weight: 400; color: var(--ink); line-height: 1;" { (access_aggregates.distinct_countries) }
                div style="font-family: var(--mono); font-size: 10.5px; letter-spacing: 0.14em; text-transform: uppercase; color: var(--mute); margin-top: 4px;" {
                    (crate::i18n::tr(lang, "countries · 30 days", "стран · 30 дней"))
                }
            }
            div title=(crate::i18n::tr(lang, "Distinct ASN labels (full AS-number + operator name) from GeoIP-ASN. High distinct_ASNs with low distinct_countries = single user roaming ISPs. High both = shared subscription URL.", "Уникальные ASN (номер AS + название оператора) из GeoIP-ASN. Много ASN при малом числе стран = один юзер мигрирует между провайдерами. Много и того и другого = расшаренная подписка.")) {
                div style="font-size: 28px; font-weight: 400; color: var(--ink); line-height: 1;" { (access_aggregates.distinct_asns) }
                div style="font-family: var(--mono); font-size: 10.5px; letter-spacing: 0.14em; text-transform: uppercase; color: var(--mute); margin-top: 4px;" {
                    (crate::i18n::tr(lang, "ASNs · 30 days", "ASN · 30 дней"))
                }
            }
            div title=(crate::i18n::tr(lang, "Sum of subscription payload bytes served over the last 30 days. Subscription JSON itself, NOT actual VPN traffic.", "Сумма байт payload подписки за 30 дней. Это сам JSON-конфиг подписки, НЕ реальный VPN-трафик.")) {
                div style="font-size: 28px; font-weight: 400; color: var(--ink); line-height: 1;" { (humanize_bytes(access_aggregates.total_bytes)) }
                div style="font-family: var(--mono); font-size: 10.5px; letter-spacing: 0.14em; text-transform: uppercase; color: var(--mute); margin-top: 4px;" {
                    (crate::i18n::tr(lang, "served · 30 days", "отдано · 30 дней"))
                }
            }
            div title=(crate::i18n::tr(lang, "Most recent subscription fetch (any IP, including VPN-egress). If older than a few days, the user's client probably isn't auto-updating — they may have imported the URL once and forgotten about it.", "Последнее обращение к подписке (любой IP, включая VPN-egress). Если старше нескольких дней — клиент не auto-update'ит подписку; возможно, юзер импортировал URL один раз и забыл.")) {
                @match access_aggregates.last_seen {
                    Some(ts) => {
                        div style="font-size: 18px; font-weight: 400; color: var(--ink); line-height: 1; font-family: var(--mono);" {
                            (format_msk_iso(ts))
                        }
                    }
                    None => {
                        div style="font-size: 18px; font-weight: 400; color: var(--mute); line-height: 1; font-family: var(--serif); font-style: italic;" {
                            (crate::i18n::tr(lang, "never", "никогда"))
                        }
                    }
                }
                div style="font-family: var(--mono); font-size: 10.5px; letter-spacing: 0.14em; text-transform: uppercase; color: var(--mute); margin-top: 4px;" {
                    (crate::i18n::tr(lang, "last fetch", "последнее обращение"))
                }
            }
        }
        // Phase 4a — VPN-egress filter toggle. Default state hides
        // rows where src IP is one of our own VPN-server addresses
        // (full-tunnel egress noise). Clicking the link adds /
        // removes `?show_egress=1`. Counter shows how many rows are
        // currently hidden so the operator knows what the filter is
        // catching.
        div style="display: flex; gap: 36px; padding: 4px 0 14px; font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute);" {
            @if show_egress {
                span {
                    (crate::i18n::tr(lang, "Showing VPN-egress rows. ", "Показаны строки VPN-egress. "))
                    a href=(format!("/admin/users/{}", user.id.0))
                      style="color: var(--ink); text-decoration: underline;" {
                        (crate::i18n::tr(lang, "Hide them", "Скрыть"))
                    }
                }
            } @else {
                @if access_aggregates.egress_rows > 0 {
                    // English needs singular/plural agreement
                    // («1 row hidden» vs «12 rows hidden»); Russian
                    // sidesteps with the genitive-plural «строк» that
                    // works for 1, 2, 5, … (technically «строка» for 1
                    // is more natural but the gen-plural reads fine in
                    // context and keeps the i18n surface flat).
                    @let en_suffix = if access_aggregates.egress_rows == 1 {
                        " VPN-egress row hidden (src IP = our own VPN server, full-tunnel mode). "
                    } else {
                        " VPN-egress rows hidden (src IP = our own VPN server, full-tunnel mode). "
                    };
                    span {
                        (access_aggregates.egress_rows)
                        (crate::i18n::tr(lang, en_suffix, " строк VPN-egress скрыто (src IP — наш VPN-сервер, full-tunnel). "))
                        a href=(format!("/admin/users/{}?show_egress=1", user.id.0))
                          style="color: var(--ink); text-decoration: underline;" {
                            (crate::i18n::tr(lang, "Show them", "Показать"))
                        }
                    }
                } @else {
                    span {
                        (crate::i18n::tr(lang, "No VPN-egress rows for this user (no full-tunnel traffic observed).", "Строк VPN-egress нет (full-tunnel-трафик не наблюдался)."))
                    }
                }
            }
        }
        // Hero row 2 — the legacy 24h/7d/recent counters live here
        // because they're shorter-window vs the 30-day aggregates
        // above. Kept for continuity with the old abuse-detection
        // workflow.
        div style="display: flex; gap: 36px; padding: 4px 0 18px; font-family: var(--serif);" {
            div {
                div style="font-size: 22px; font-weight: 400; color: var(--ink); line-height: 1;" { (ips_24h) }
                div style="font-family: var(--mono); font-size: 10.5px; letter-spacing: 0.14em; text-transform: uppercase; color: var(--mute); margin-top: 4px;" {
                    (crate::i18n::tr(lang, "distinct IPs · 24h", "уникальных IP · 24ч"))
                }
            }
            div {
                div style="font-size: 22px; font-weight: 400; color: var(--ink); line-height: 1;" { (ips_7d) }
                div style="font-family: var(--mono); font-size: 10.5px; letter-spacing: 0.14em; text-transform: uppercase; color: var(--mute); margin-top: 4px;" {
                    (crate::i18n::tr(lang, "distinct IPs · 7 days", "уникальных IP · 7 дней"))
                }
            }
            div {
                div style="font-size: 22px; font-weight: 400; color: var(--ink); line-height: 1;" { (recent_access.len()) }
                div style="font-family: var(--mono); font-size: 10.5px; letter-spacing: 0.14em; text-transform: uppercase; color: var(--mute); margin-top: 4px;" {
                    (crate::i18n::tr(lang, "rows in table", "строк в таблице"))
                }
            }
        }
        @if recent_access.is_empty() {
            p style="font-family: var(--serif); font-style: italic; color: var(--mute);" {
                (crate::i18n::tr(
                    lang,
                    "No subscription fetches recorded yet. Hits will appear here as soon as a client pulls the URL above.",
                    "Обращений к подписке пока не записано. Строки появятся сразу как только клиент дёрнет URL выше.",
                ))
            }
        } @else {
            table style="width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 11.5px;" {
                thead {
                    tr style="border-bottom: 1px solid var(--ink);" {
                        th style="text-align: left; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                            (crate::i18n::tr(lang, "when", "когда"))
                        }
                        th style="text-align: left; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                            (crate::i18n::tr(lang, "ip", "ip"))
                        }
                        th style="text-align: left; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                            (crate::i18n::tr(lang, "user-agent", "user-agent"))
                        }
                        th style="text-align: right; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                            (crate::i18n::tr(lang, "status", "статус"))
                        }
                        th style="text-align: right; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                            (crate::i18n::tr(lang, "bytes", "байт"))
                        }
                    }
                }
                tbody {
                    @for row in &recent_access {
                        @let ip_kind = classify_ip(&row.ip);
                        // Prefer persisted device_class from
                        // sub_access_log (migration 0019) — that
                        // way future parser changes don't rewrite
                        // history. Fallback to live parse for
                        // pre-migration NULL rows.
                        @let ua_summary = row
                            .device_class
                            .as_deref()
                            .or_else(|| crate::ua::parse_ua_short(row.ua.as_deref()));
                        tr style="border-bottom: 1px dotted var(--rule);" {
                            td style="padding: 5px 8px; color: var(--soft); white-space: nowrap;" {
                                (clip_ts(&row.ts.to_rfc3339()))
                            }
                            td style="padding: 5px 8px; color: var(--ink);" title=(ip_kind_tooltip(ip_kind, lang)) {
                                (row.ip)
                                @if let Some(tag) = ip_kind_tag(ip_kind, lang) {
                                    " "
                                    span style=(format!("font-family: var(--mono); font-size: 9px; padding: 0 4px; border: 1px solid {color}; color: {color}; margin-left: 2px;", color = ip_kind_color(ip_kind))) {
                                        (tag)
                                    }
                                }
                                // Track-1.2 (migration 0019) — country
                                // ISO + ASN chips from GeoIP enrichment.
                                // Both columns are NULL for old rows or
                                // when VPNCTLD_GEOIP_DIR isn't set;
                                // render only what we have.
                                @if let Some(cc) = row.geo_country.as_deref() {
                                    " "
                                    span style="font-family: var(--mono); font-size: 9px; padding: 0 4px; border: 1px solid var(--acc-good, #2c5f2d); color: var(--acc-good, #2c5f2d); margin-left: 2px;"
                                         title=(crate::i18n::tr(lang, "Country (ISO 3166-1 alpha-2) from MaxMind GeoLite2 City", "Страна (ISO 3166-1 alpha-2) из MaxMind GeoLite2 City")) {
                                        (cc)
                                    }
                                }
                                @if let Some(asn) = row.geo_asn.as_deref() {
                                    " "
                                    span style="font-family: var(--mono); font-size: 9px; padding: 0 4px; color: var(--mute); margin-left: 2px;"
                                         title=(crate::i18n::tr(lang, "Autonomous System / ISP from MaxMind GeoLite2 ASN", "Автономная система / ISP из MaxMind GeoLite2 ASN")) {
                                        (asn)
                                    }
                                }
                                @if let Some(http_v) = row.http_version.as_deref() {
                                    " "
                                    span style="font-family: var(--mono); font-size: 9px; color: var(--mute); margin-left: 2px;"
                                         title=(crate::i18n::tr(lang, "HTTP version negotiated", "Согласованная версия HTTP")) {
                                        (http_v)
                                    }
                                }
                                // Track-1.4 — TLS JA3 / JA4 fingerprint chip
                                // (migration 0020). NULL until an nginx-side
                                // JA3 module forwards `X-SSL-JA3` /
                                // `X-SSL-JA4` headers. Hash itself is long;
                                // render the first JA_CHIP_PREFIX_CHARS only,
                                // full value lives in the title= tooltip.
                                @if let Some(ja3) = row.tls_ja3.as_deref() {
                                    " "
                                    span style="font-family: var(--mono); font-size: 9px; padding: 0 4px; border: 1px dotted var(--rule); color: var(--mute); margin-left: 2px;"
                                         title=(format!("{}\n{}",
                                            crate::i18n::tr(lang, "JA3 TLS ClientHello fingerprint (Salesforce). Same device through IP changes = same JA3.", "JA3 — отпечаток TLS ClientHello (Salesforce). Одно и то же устройство через смену IP = тот же JA3."),
                                            ja3)) {
                                        "JA3 " ((ja3.chars().take(JA_CHIP_PREFIX_CHARS).collect::<String>()))
                                    }
                                }
                                @if let Some(ja4) = row.tls_ja4.as_deref() {
                                    " "
                                    span style="font-family: var(--mono); font-size: 9px; padding: 0 4px; border: 1px dotted var(--rule); color: var(--mute); margin-left: 2px;"
                                         title=(format!("{}\n{}",
                                            crate::i18n::tr(lang, "JA4 TLS fingerprint (FoxIO 2023). Protocol-aware, harder to randomise than JA3.", "JA4 — отпечаток TLS (FoxIO 2023). Знает протокол, сложнее рандомизируется чем JA3."),
                                            ja4)) {
                                        "JA4 " ((ja4.chars().take(JA_CHIP_PREFIX_CHARS).collect::<String>()))
                                    }
                                }
                            }
                            td style="padding: 5px 8px; color: var(--soft); overflow-wrap: anywhere; word-break: break-all;" {
                                @match &row.ua {
                                    Some(s) => {
                                        // Parsed summary if recognised, else raw string.
                                        @if let Some(label) = ua_summary {
                                            span title=(s) style="border-bottom: 1px dotted var(--rule-s); cursor: help;" {
                                                (label)
                                            }
                                        } @else {
                                            (s)
                                        }
                                    }
                                    None => em style="color: var(--mute);" { (crate::i18n::tr(lang, "(none)", "(нет)")) },
                                }
                            }
                            td style="padding: 5px 8px; text-align: right; color: var(--ink);" { (row.status) }
                            td style="padding: 5px 8px; text-align: right; color: var(--soft);" { (row.bytes) }
                        }
                    }
                }
            }
            p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin-top: 10px;" {
                (crate::i18n::tr(lang, "Showing the ", "Показано "))
                (recent_access.len())
                (crate::i18n::tr(
                    lang,
                    " most recent fetches. Rows are auto-purged after 30 days (default retention).",
                    " последних обращений. Строки автоудаляются через 30 дней (retention по умолчанию).",
                ))
            }
        }

        // ── UA fingerprint (Phase Track-4) ──────────────────────
        (ua_clusters_section(&state, &uid, lang).await)

        // ── Live VPN stats (Track-3 chunk 3) ────────────────────
        (live_vpn_stats_section(&state, &uid, lang).await)
        (user_top_destinations_section(&state, &uid, lang).await)
        (user_sessions_section(&state, &uid, lang).await)

        // ── Traffic limit + alert threshold (Pavel D.6c) ──────────
        // Show current month-to-date usage + the configured cap
        // (if any) + an inline form to change both. Re-runs the
        // usage query so the page-after-redirect immediately
        // reflects new limits.
        (user_traffic_limit_section(&state, &uid, lang).await)

        // B1.user (audit 2026-05-22) — soft suspend. Banner +
        // toggle button. When user.disabled = true, an amber banner
        // says «this user is paused»; button reads «enable». When
        // false, just the «disable» button as part of the normal
        // user-detail card flow. No double-submit confirm because
        // the action is fully reversible (one click in either
        // direction, no secrets rotated, no grants lost).
        div.ed-rule {}
        div.ed-art-eyebrow style="margin-top: 24px;" {
            (crate::i18n::tr(lang, "Access state", "Состояние доступа"))
        }
        @if user.disabled {
            div style="border: 1px solid var(--acc); background: var(--paper); padding: 12px 14px; margin: 8px 0;" {
                div style="font-family: var(--serif); font-weight: 500; color: var(--acc); font-size: 14px;" {
                    (crate::i18n::tr(lang, "user is DISABLED", "пользователь ОТКЛЮЧЁН"))
                }
                p style="font-family: var(--serif); font-style: italic; color: var(--mute); margin: 4px 0 0;" {
                    (crate::i18n::tr(
                        lang,
                        "Subscription endpoints return an empty config. Secrets, sub-token, WG keypair and grants are unchanged — re-enable to restore access byte-for-byte.",
                        "Endpoints подписки возвращают пустой config. Секреты, sub-token, WG-пара и гранты не тронуты — включи обратно, чтобы вернуть доступ байт-в-байт.",
                    ))
                }
                form method="post"
                     action=(format!("/admin/users/{}/enable", path_segment_encode(&user.id.0)))
                     style="display: inline; margin-top: 8px;" {
                    button type="submit"
                           style="padding: 4px 12px; border: 1px solid var(--ink); background: var(--paper); color: var(--ink); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                        (crate::i18n::tr(lang, "enable user", "включить пользователя"))
                    }
                }
            }
        } @else {
            p style="font-family: var(--serif); font-style: italic; color: var(--mute); padding: 8px 0;" {
                (crate::i18n::tr(
                    lang,
                    "Pause a user's subscription without rotating secrets or revoking grants. Re-enable later restores access byte-for-byte. Useful for: forgotten phone, paused billing, temporary access freeze.",
                    "Поставь подписку на паузу без ротации секретов и без отзыва грантов. Повторное включение вернёт доступ байт-в-байт. Полезно для: забытого телефона, паузы в оплате, временной заморозки доступа.",
                ))
            }
            form method="post"
                 action=(format!("/admin/users/{}/disable", path_segment_encode(&user.id.0)))
                 style="display: inline;" {
                button type="submit"
                       title=(crate::i18n::tr(
                           lang,
                           "Soft mute: /sub/<token> and /api/v1/app/config/<device_id> return an empty config. Everything else is preserved.",
                           "Мягкое отключение: /sub/<token> и /api/v1/app/config/<device_id> возвращают пустой config. Всё остальное сохраняется.",
                       ))
                       style="padding: 4px 12px; border: 1px solid var(--mute); background: transparent; color: var(--ink); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                    (crate::i18n::tr(lang, "disable user", "отключить пользователя"))
                }
            }
        }

        div.ed-rule {}
        div.ed-art-eyebrow style="color: var(--acc); margin-top: 24px;" {
            (crate::i18n::tr(lang, "Danger zone", "Опасная зона"))
        }
        p style="font-family: var(--serif); font-style: italic; color: var(--mute); padding: 8px 0;" {
            (crate::i18n::tr(
                lang,
                "Deleting drops the user, cascades to grants, and clears the FK on ",
                "Удаление сносит пользователя, каскадно убирает grants и очищает FK в ",
            ))
            span.ed-mono { "sub_access_log" }
            (crate::i18n::tr(
                lang,
                " rows (forensics survive with NULL user_id).",
                " (forensics остаётся с NULL user_id).",
            ))
        }
        a href=(format!("/admin/users/{}/delete-confirm", path_segment_encode(&user.id.0)))
          style="display: inline-block; padding: 4px 12px; border: 1px solid var(--acc); background: transparent; color: var(--acc); font-family: var(--mono); font-size: 11px; text-decoration: none;" {
            (crate::i18n::tr(lang, "delete user…", "удалить пользователя…"))
        }
    };
    Ok(shell("users", &theme, &accent, lang, body))
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
async fn ua_clusters_section(
    state: &AppState,
    uid: &vpnctl_core::UserId,
    lang: crate::i18n::Locale,
) -> Markup {
    let clusters = match state.inv.ua_clusters_for_user(uid, 24).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(target = "vpnctld::admin", user = %uid, error = %e, "ua_clusters_for_user failed");
            return html! {
                div.ed-rule {}
                div.ed-art-eyebrow { (crate::i18n::tr(lang, "UA fingerprint", "Отпечаток User-Agent")) }
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
        div.ed-art-eyebrow {
            (crate::i18n::tr(lang, "UA fingerprint · last 24h", "Отпечаток User-Agent · за 24ч"))
        }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
            (crate::i18n::tr(
                lang,
                "Heuristic. One device usually roams within one ISP /16, while a shared sub URL spreads across many ISPs. Labels: orange = likely shared, green = likely roaming.",
                "Эвристика. Одно устройство обычно ходит в пределах одного ISP /16, а расшаренный sub URL расползается по разным ISP. Метки: оранжевый = вероятно расшарен, зелёный = вероятно роуминг.",
            ))
        }
        table style="width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 11.5px;" {
            thead {
                tr style="border-bottom: 1px solid var(--ink);" {
                    th title="Distinct User-Agent strings the subscription URL was pulled with in the last 24h. Each cluster is one row."
                       style="text-align: left; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { "user-agent" }
                    th title="Total subscription pulls from this UA (one row per /sub/<token> or /api/v1/app/config/<device> GET that produced 200)."
                       style="text-align: right; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { "hits" }
                    th title="Distinct source IPs that pulled with this UA. Normal mobile client = 1-3 IPs (home wifi + LTE + travel). Many IPs = either roaming heavily or shared URL."
                       style="text-align: right; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { "ips" }
                    th title="Distinct /16 IPv4 prefixes (≈ISP-scale buckets). One user roaming between LTE + wifi tends to stay in 1-2 /16s. >=3 /16s strongly suggests the subscription URL was shared past one human."
                       style="text-align: right; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { "/16 nets" }
                    th title="Heuristic classification from (hits, ips, /16 nets): single = one human, roaming = one human on the move, shared = the URL escaped past one human."
                       style="text-align: left; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { "verdict" }
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
async fn user_traffic_limit_section(
    state: &AppState,
    uid: &vpnctl_core::UserId,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
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
        div.ed-art-eyebrow { (tr(lang, "Traffic limit · month-to-date", "Лимит трафика · с начала месяца")) }
        @match limit_opt {
            Some(lim) if lim > 0 => {
                @let pct = ((used as u128 * 100) / lim as u128).min(999) as u32;
                @let over_threshold = pct >= u32::from(threshold_eff);
                @let over_limit = pct >= 100;
                p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
                    (tr(
                        lang,
                        "Total upload + download this calendar month vs. the configured monthly cap. Alert fires at ",
                        "Суммарно upload + download за календарный месяц vs. настроенный месячный лимит. Алерт срабатывает при ",
                    ))
                    span.ed-mono { (threshold_eff) "%" } "."
                }
                div style="font-family: var(--mono); font-size: 13px; margin: 0 0 8px;" {
                    (fmt_traffic_progress(used, lim))
                    @if over_limit {
                        " · "
                        span style="color: var(--acc); font-weight: 600;" { (tr(lang, "OVER LIMIT", "СВЕРХ ЛИМИТА")) }
                    } @else if over_threshold {
                        " · "
                        span style="color: var(--acc);" { (tr(lang, "near limit", "у лимита")) }
                    }
                }
                @let bar_pct = pct.min(100);
                @let bar_fill = if over_threshold { "var(--acc)" } else { "var(--ink)" };
                @let _ = over_limit;
                div style="height: 8px; background: var(--rule); margin-bottom: 16px; overflow: hidden;" {
                    div style=(format!("height: 100%; width: {bar_pct}%; background: {bar_fill};")) {}
                }
            }
            _ => {
                p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
                    (tr(lang, "Used this month: ", "Использовано в этом месяце: "))
                    span.ed-mono { (humanize_bytes(used)) }
                    (tr(lang, " — no monthly cap configured. Set one below if you want a ", " — месячный лимит не задан. Задай ниже если хочешь "))
                    span.ed-mono { (DEFAULT_TRAFFIC_THRESHOLD_PCT) "%-" (tr(lang, "of-limit alert", "от-лимита алерт")) }
                    (tr(lang, " to fire on the dashboard.", " на дашборде."))
                }
            }
        }

        form method="post"
             action=(format!("/admin/users/{}/traffic-limit", path_segment_encode(&uid.0)))
             style="display: flex; gap: 10px; align-items: baseline; flex-wrap: wrap; padding: 10px 12px; background: var(--paper); border: 1px solid var(--rule);" {
            label style="font-family: var(--mono); font-size: 11px; color: var(--mute); letter-spacing: 0.14em; text-transform: uppercase;" {
                (tr(lang, "limit", "лимит"))
            }
            // Operator-friendly input: GiB. Backend converts to
            // bytes. 0 / empty = clear the limit.
            @let limit_gib_default = limit_opt
                .map(|b| b as f64 / 1_073_741_824.0)
                .unwrap_or(0.0);
            input type="number" name="limit_gib" step="0.1" min="0" max="100000"
                  value=(format!("{limit_gib_default:.1}"))
                  title="Monthly cap in GiB (upload + download summed). 0 / empty = no cap. Resets on the first of each month."
                  style="max-width: 80px; padding: 4px 8px; border: 1px solid var(--rule-s); background: var(--paper); font-family: var(--mono); font-size: 12px; color: var(--ink);";
            span style="font-family: var(--mono); font-size: 11px; color: var(--mute);" { "GiB / month" }
            label style="font-family: var(--mono); font-size: 11px; color: var(--mute); letter-spacing: 0.14em; text-transform: uppercase; margin-left: 8px;" {
                "alert at"
            }
            input type="number" name="threshold_pct" step="1" min="1" max="100"
                  value=(threshold_eff)
                  title="Fire a dashboard alert (and Telegram if configured) when used / cap >= this percent. Default 80%."
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

/// Phase 5c — «Когда была активна» session timeline. Builds an
/// implicit «active from-to» window per (user, server) from the
/// 5-min clash-poll observations: consecutive ticks extend the
/// session; a gap > 15 minutes closes it. Empty until the
/// poller has run at least one tick post-Phase-5c deploy.
async fn user_sessions_section(
    state: &AppState,
    uid: &vpnctl_core::UserId,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    const LIMIT: i64 = 20;
    let rows = state
        .inv
        .recent_sessions_for_user(uid, LIMIT)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(target = "vpnctld::admin", user = %uid, error = %e, "recent_sessions_for_user failed");
            Vec::new()
        });
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow {
            (tr(lang, "Sessions · recent 20", "Сессии · последние 20"))
        }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
            (tr(
                lang,
                "Implicit «active from-to» windows per (user, server). Derived from 5-min clash-poll observations: consecutive ticks extend the session; a gap >15 minutes closes it and the next tick opens a new row. Peak conns shows the busiest snapshot during the session.",
                "Окна «активна с-по» на (юзер, сервер). Источник — 5-минутные тики clash-poll: последовательные тики расширяют сессию, пропуск >15 минут закрывает её, следующий тик открывает новую. Peak conns — самый загруженный snapshot в этой сессии.",
            ))
        }
        @if rows.is_empty() {
            p style="font-family: var(--serif); font-style: italic; color: var(--mute);" {
                (tr(
                    lang,
                    "No sessions yet. The poller writes one row per (user, server, activity window) — wait for the next clash-api scrape.",
                    "Сессий ещё нет. Поллер пишет одну запись на (юзер, сервер, окно активности) — подожди следующий скрейп clash-api.",
                ))
            }
        } @else {
            table style="width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 11.5px;" {
                thead {
                    tr style="border-bottom: 1px solid var(--ink);" {
                        th style="text-align: left; padding: 5px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                            (tr(lang, "server", "сервер"))
                        }
                        th style="text-align: left; padding: 5px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                            (tr(lang, "started", "началось"))
                        }
                        th style="text-align: left; padding: 5px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                            (tr(lang, "last seen", "последний"))
                        }
                        th style="text-align: right; padding: 5px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                            (tr(lang, "duration", "длительность"))
                        }
                        th style="text-align: right; padding: 5px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;"
                           title=(tr(lang, "Max active_connections observed across all 5-min ticks within the session.", "Max active_connections по всем 5-минутным тикам внутри сессии.")) {
                            (tr(lang, "peak conns", "макс. соед."))
                        }
                    }
                }
                tbody {
                    @for r in &rows {
                        @let dur = r.duration();
                        @let mins = dur.num_minutes().max(0);
                        @let dur_str = if mins >= 60 {
                            format!("{}h{:02}m", mins / 60, mins % 60)
                        } else {
                            format!("{mins}m")
                        };
                        tr style="border-bottom: 1px dotted var(--rule);" {
                            td style="padding: 4px 8px;" {
                                a href=(format!("/admin/servers/{}", crate::http_util::path_segment_encode(&r.server_id.0))) style="color: var(--ink); text-decoration: none;" { (r.server_id.0) }
                            }
                            td style="padding: 4px 8px;" { (format_msk(r.started_at)) }
                            td style="padding: 4px 8px;" { (format_msk(r.last_seen)) }
                            td style="padding: 4px 8px; text-align: right; font-weight: 500;" { (dur_str) }
                            td style="padding: 4px 8px; text-align: right;" { (r.conn_count_peak) }
                        }
                    }
                }
            }
        }
    }
}

/// Phase 5b — «Куда ходит этот юзер» section. Top destinations
/// over the last 7 days, ranked by hit count (number of 5-min
/// clash-poll ticks where the pair was observed). Empty until
/// the poller has run at least one tick post-Phase-5b deploy.
async fn user_top_destinations_section(
    state: &AppState,
    uid: &vpnctl_core::UserId,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    const TOP_N: u32 = 20;
    const WINDOW_DAYS: u32 = 7;
    let rows = state
        .inv
        .top_destinations_for_user(uid, WINDOW_DAYS, TOP_N)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(target = "vpnctld::admin", user = %uid, error = %e, "top_destinations_for_user failed");
            Vec::new()
        });

    // Phase 5d: enrich bare-IP labels via `dns_ptr_cache`. The
    // poller writes `IP:port` when sing-box's metadata.host was
    // empty (most TCP-to-IP traffic); the resolver background
    // job populates `dns_ptr_cache` separately. At render time we
    // bulk-lookup so each row that's still a bare IP can be shown
    // as `hostname:port (ip)` — matching the format
    // `snapshot_cache::aggregate_by_destination` uses on the
    // server-detail page (one canonical render shape for both).
    let mut ip_candidates: Vec<String> = rows
        .iter()
        .filter_map(|r| extract_ip_from_label(&r.destination_label).map(str::to_owned))
        .collect();
    ip_candidates.sort();
    ip_candidates.dedup();
    let dns_map = if ip_candidates.is_empty() {
        std::collections::HashMap::new()
    } else {
        state
            .inv
            .lookup_dns_ptr_bulk(&ip_candidates)
            .await
            .unwrap_or_else(|e| {
                tracing::warn!(target = "vpnctld::admin", user = %uid, error = %e, "lookup_dns_ptr_bulk failed");
                std::collections::HashMap::new()
            })
    };

    html! {
        div.ed-rule {}
        div.ed-art-eyebrow {
            (tr(lang, "Top destinations · last 7 days", "Топ destinations · 7 дней"))
        }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
            (tr(
                lang,
                "Which hosts this user connects to most often. Derived from clash-api snapshots (one hit per 5-minute tick where a connection to that destination was active). Reverse-DNS resolved when possible (Phase 5a-2 cache).",
                "На какие хосты юзер ходит чаще всего. Источник — snapshot'ы clash-api (один hit на 5-минутный тик, в котором соединение к этому destination было активно). Reverse-DNS подставляется когда возможно (Phase 5a-2 cache).",
            ))
        }
        @if rows.is_empty() {
            p style="font-family: var(--serif); font-style: italic; color: var(--mute);" {
                (tr(
                    lang,
                    "No destination history yet. The poller writes one hit per (destination, 5-min tick) — wait for the next clash-api scrape to fill this section.",
                    "Истории destinations ещё нет. Поллер пишет один hit на (destination, 5-минутный тик) — подожди следующий скрейп clash-api.",
                ))
            }
        } @else {
            table style="width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 11.5px;" {
                thead {
                    tr style="border-bottom: 1px solid var(--ink);" {
                        th style="text-align: left; padding: 5px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                            (tr(lang, "destination", "destination"))
                        }
                        th style="text-align: right; padding: 5px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;"
                           title=(tr(lang, "Number of 5-min ticks where a connection to this destination was alive. Not connection count — a long-lived connection contributes N hits, N = ticks-it-was-up.", "Число 5-мин тиков, в которых соединение к этому destination было активно. Не число соединений — долгое соединение даёт N hits, N = тиков-сколько-жило.")) {
                            (tr(lang, "hits · 7d", "hits · 7д"))
                        }
                        th style="text-align: right; padding: 5px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                            (tr(lang, "last seen", "последний раз"))
                        }
                    }
                }
                tbody {
                    @for r in &rows {
                        tr style="border-bottom: 1px dotted var(--rule);" {
                            td style="padding: 4px 8px; overflow-wrap: anywhere;" {
                                (enrich_destination_label(&r.destination_label, &dns_map))
                            }
                            td style="padding: 4px 8px; text-align: right; font-weight: 500;" { (r.hit_count) }
                            td style="padding: 4px 8px; text-align: right; color: var(--mute);" {
                                (format_msk(r.last_seen))
                            }
                        }
                    }
                }
            }
        }
    }
}

async fn live_vpn_stats_section(
    state: &AppState,
    uid: &vpnctl_core::UserId,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::{K, t, tr};
    let rows = match state.inv.recent_vpn_stats_for_user(uid, 24).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(target = "vpnctld::admin", user = %uid, error = %e, "recent_vpn_stats_for_user failed");
            return html! {
                div.ed-rule {}
                div.ed-art-eyebrow { (tr(lang, "Live VPN stats", "Живая статистика VPN")) }
                p style="font-family: var(--serif); font-style: italic; color: var(--mute);" {
                    (tr(lang, "(temporarily unavailable — see journalctl)", "(временно недоступно — смотри journalctl)"))
                }
            };
        }
    };
    if rows.is_empty() {
        return html! {
            div.ed-rule {}
            div.ed-art-eyebrow { (t(lang, K::EyebrowLiveStats)) }
            p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
                (tr(
                    lang,
                    "No live stats yet. The clash-api poller is shipped (Track-3 chunks 1+2) but the daemon-side scheduler that pulls snapshots from each VPN node is queued for chunk 4 — it needs the SSH key on the vpnctld host's ",
                    "Живой статистики пока нет. Поллер clash-api уже работает (Track-3 chunks 1+2), но шедулер на стороне демона, который снимает снэпшоты с каждой VPN-ноды, в очереди на chunk 4 — нужен SSH-ключ на хосте vpnctld в ",
                ))
                span.ed-mono { "/var/lib/vpnctl/.ssh" }
                (tr(
                    lang,
                    " plus per-node authorisation. Once wired, this section will show real per-user upload/download totals and active connection counts.",
                    " плюс авторизация на каждой ноде. Когда подключим — раздел покажет реальные upload/download по пользователю и активные подключения.",
                ))
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
                        th title="Sum of upload-bytes deltas from clash-api 5-min ticks over the last 24h. Counts everything sing-box saw on this user's auth — VLESS, TUIC, Trojan; wgturn / WireGuard NOT included (kernel-level, no clash-api visibility)."
                           style="text-align: right; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { "uploaded" }
                        th title="Same window + same caveats as uploaded — download direction."
                           style="text-align: right; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { "downloaded" }
                        th title="Maximum simultaneous active connections seen for this user during any 5-min poll window in the last 24h. >50 from a phone client = unusual (chat apps + browser keep ~5-15 sustained); >200 typically means torrent / web-crawler."
                           style="text-align: right; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { "peak conns" }
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
            (crate::i18n::tr(lang, "Aggregated from ", "Агрегировано из ")) (rows.len())
            @if rows.len() == 1 {
                (crate::i18n::tr(lang, " snapshot", " снэпшота"))
            } @else {
                (crate::i18n::tr(lang, " snapshots", " снэпшотов"))
            }
            (crate::i18n::tr(
                lang,
                " over the last 24 hours. Rows are auto-purged after 30 days.",
                " за последние 24 часа. Строки автоудаляются через 30 дней.",
            ))
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

/// Format a UTC timestamp in Moscow time (MSK, UTC+3, no DST since
/// 2014). Used on user-detail dense tables (Top destinations,
/// Sessions) where the operator scans for «когда последний раз ходил»
/// — UTC made the time column unreadable for the sole operator in
/// MSK. The trailing `MSK` literal makes the timezone explicit so
/// nobody mistakes the column for UTC after Phase 5d.
///
/// Fallback to `%m-%d %H:%M UTC` if `FixedOffset::east_opt` rejects
/// the offset — defensive, in practice `3 * 3600` always fits in
/// the documented `-86_399..=86_399` range.
fn format_msk(dt: chrono::DateTime<chrono::Utc>) -> String {
    match chrono::FixedOffset::east_opt(3 * 3600) {
        Some(tz) => dt.with_timezone(&tz).format("%m-%d %H:%M MSK").to_string(),
        None => dt.format("%m-%d %H:%M UTC").to_string(),
    }
}

/// Same as [`format_msk`] but emits the year too (`%Y-%m-%d %H:%M MSK`).
/// Used for «last fetch / last sample» tile timestamps where the
/// operator needs the absolute date — those values can be days/weeks
/// old, so dropping the year would be ambiguous.
fn format_msk_iso(dt: chrono::DateTime<chrono::Utc>) -> String {
    match chrono::FixedOffset::east_opt(3 * 3600) {
        Some(tz) => dt
            .with_timezone(&tz)
            .format("%Y-%m-%d %H:%M MSK")
            .to_string(),
        None => dt.format("%Y-%m-%d %H:%M UTC").to_string(),
    }
}

/// Phase 5d — pull a bare IPv4 candidate out of a `vpn_user_destinations`
/// row label so the render path can bulk-look-up reverse-DNS.
///
/// The poller (`daemon::clash_poller::poll_one_server`) writes the
/// label as one of:
///   * `host:port` — sing-box already had a DNS name (e.g. SNI), no
///     enrichment needed; we return `None` so the IP-lookup batch
///     skips this row.
///   * `IP:port` — bare IPv4 + port; return `Some(ip_slice)` so the
///     render path can probe the `dns_ptr_cache` for a hostname.
///   * `IP` — bare IPv4 alone (poller path when `destination_port` is
///     empty, see `clash_poller::poll_one_server`'s portless branch);
///     return `Some(ip_slice)` so this row gets enriched too.
///   * Anything else (hostname-form, already-enriched, IPv6 with
///     internal colons, malformed) → `None`.
///
/// Intentionally narrow: the only goal is «is this a bare IP we
/// could enrich», not «is this a valid IPv4». A malformed
/// `999.999.999.999:80` returns `Some` and the cache lookup will
/// simply miss — strictly correct because the cache key matches
/// what the writer stored.
fn extract_ip_from_label(label: &str) -> Option<&str> {
    // Portless form first: whole label is `[0-9.]+` and non-empty.
    // Has to be checked BEFORE rsplit_once(':') because that returns
    // None for the no-colon case, and we want to accept it.
    if !label.is_empty()
        && !label.contains(':')
        && label.chars().all(|c| c.is_ascii_digit() || c == '.')
    {
        return Some(label);
    }
    // With-port form: `IP:port`.
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

/// Phase 5d — assemble the visible destination label by enriching
/// bare-IP rows with their cached hostname. Single source of truth
/// for the per-row render in `user_top_destinations_section`; lives
/// here (not inline in maud) so the contract has direct unit tests.
///
/// Shape parity: the output format `hostname:port (ip)` matches
/// `snapshot_cache::aggregate_by_destination` on the server-detail
/// page — operator scanning both screens sees one canonical layout.
///
/// Passthrough rules:
///   * `label` not a bare-IP form (hostname, already-enriched, IPv6,
///     malformed) → returned unchanged.
///   * `dns_map[ip] = Some(Some(host))` → enriched as `host:port (ip)`,
///     or `host (ip)` when the original label was a portless IP.
///   * `dns_map[ip] = Some(None)` (cached negative) → returned
///     unchanged; resolver tried and got no PTR.
///   * `dns_map[ip] = None` (cache miss) → returned unchanged;
///     resolver hasn't visited this IP yet.
fn enrich_destination_label(
    label: &str,
    dns_map: &std::collections::HashMap<String, Option<String>>,
) -> String {
    let Some(ip) = extract_ip_from_label(label) else {
        return label.to_string();
    };
    let Some(Some(host)) = dns_map.get(ip) else {
        return label.to_string();
    };
    // Preserve any port suffix (`:443`, etc.) that came after the IP
    // — strip_prefix on the IP and reuse the remainder verbatim, so
    // a portless label `1.2.3.4` becomes `host (1.2.3.4)` and a
    // with-port `1.2.3.4:443` becomes `host:443 (1.2.3.4)`.
    let port_suffix = label.strip_prefix(ip).unwrap_or("");
    format!("{host}{port_suffix} ({ip})")
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

/// JSON-encode `s` for safe interpolation inside an inline `<script>`
/// block. Standard `serde_json::to_string` escapes `"`, `\` and
/// control chars — but **not `/`**. A string containing `</script>`
/// would close the script tag prematurely and yield XSS. The
/// post-process `replace("</", "<\\/")` produces a JSON-equivalent
/// string (JSON-spec allows escaped `\/`) that browsers tokenise
/// safely inside `<script>`. The escaped form is JS-identical
/// (`"<\/script>"` == `"</script>"` at runtime — only the parser
/// sees the difference).
///
/// Fallback to `""` JSON string on serialise failure (only happens
/// on non-UTF-8 input, which `&str` can't hold — defensive).
fn json_for_script(s: &str) -> String {
    serde_json::to_string(s)
        .unwrap_or_else(|_| String::from("\"\""))
        .replace("</", "<\\/")
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

/// `POST /admin/backup/self-test` — restore fire-drill.
///
/// Picks the most recent local snapshot in `DEFAULT_BACKUP_DIR`,
/// runs [`vpnctl_inventory::verify_snapshot`] on it (which copies
/// it into a per-call tmpfile + replays migrations + queries data
/// presence metrics) and renders the report inline as HTML.
///
/// This is the «is our DR insurance actually valid?» button —
/// converts the periodic-bit-rot risk from «catches it the day 236
/// burns» to «catches it the next time the operator clicks the
/// button». Future work (cron-scheduled run + Telegram alert on
/// Fail) layers on top of this same primitive.
///
/// Audit row written every invocation with the report status; one
/// place an operator (or post-mortem) can see the history.
pub(crate) async fn backup_self_test(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let backup_dir = std::path::PathBuf::from(crate::app::DEFAULT_BACKUP_DIR);
    let snapshots = match vpnctl_inventory::list_snapshots(&backup_dir) {
        Ok(list) => list,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    let Some(latest) = snapshots.into_iter().next() else {
        return error_resp(
            StatusCode::CONFLICT,
            "no snapshot to verify yet — click 'snapshot now' on /admin/settings first, \
             or wait for the hourly scheduler to fire",
        );
    };
    // Run + audit on EVERY attempt (incl. Err) so post-mortem replay
    // sees the operator's click even when verify itself broke. TOCTOU
    // friendliness: the snapshot can be pruned between `list_snapshots`
    // and `verify_snapshot` — return 409 in that narrow case rather
    // than a misleading 500.
    let verify_result = vpnctl_inventory::verify_snapshot(&latest.path).await;
    match &verify_result {
        Ok(report) => {
            if let Err(e) = state
                .inv
                .audit(
                    "admin",
                    "backup.self_test",
                    Some(&latest.file_name),
                    Some(&serde_json::json!({
                        "snapshot_path": &report.snapshot_path,
                        "snapshot_age_seconds": report.snapshot_age_seconds,
                        "overall": report.overall.label(),
                        "duration_ms": report.duration_ms,
                        "user_count": report.user_count,
                        "server_count": report.server_count,
                        "grant_count": report.grant_count,
                    })),
                )
                .await
            {
                tracing::warn!(
                    target = "vpnctld::backup",
                    error = %e,
                    "audit write failed for backup.self_test"
                );
            }
        }
        Err(err) => {
            if let Err(e) = state
                .inv
                .audit(
                    "admin",
                    "backup.self_test",
                    Some(&latest.file_name),
                    Some(&serde_json::json!({
                        "overall": "error",
                        "error": err.to_string(),
                    })),
                )
                .await
            {
                tracing::warn!(
                    target = "vpnctld::backup",
                    error = %e,
                    "audit write failed for backup.self_test (err branch)"
                );
            }
        }
    }

    let report = match verify_result {
        Ok(r) => r,
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("stat snapshot") {
                return error_resp(
                    StatusCode::CONFLICT,
                    "snapshot vanished between list and verify — click 'run restore self-test' again",
                );
            }
            return internal_error(anyhow::Error::new(e));
        }
    };

    let (theme, accent, lang) = theme_accent_lang(&headers);
    let body = render_self_test_report(&report, lang);
    shell("settings", &theme, &accent, lang, body).into_response()
}

/// Render the HTML body for the self-test result page. Pulled out
/// so a future «show last result on /admin/settings» pass can reuse
/// it without re-fetching the report.
fn render_self_test_report(
    report: &vpnctl_inventory::SelfTestReport,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    use vpnctl_inventory::CheckStatus;
    let overall_color = match report.overall {
        // Inline hex (not CSS vars): `--ok` and `--warn` aren't in
        // admin.css today and inlining keeps the self-test page's
        // colour palette self-contained. `--red` IS defined but we
        // keep the literal here for symmetry with the other two.
        CheckStatus::Ok => "#2e7d32",
        CheckStatus::Warn => "#e6a23c",
        CheckStatus::Fail => "#c62828",
    };
    let overall_label = match report.overall {
        CheckStatus::Ok => tr(lang, "PASS", "ПРОЙДЕНО"),
        CheckStatus::Warn => tr(
            lang,
            "PASS · with warnings",
            "ПРОЙДЕНО · с предупреждениями",
        ),
        CheckStatus::Fail => tr(lang, "FAIL", "ПРОВАЛ"),
    };
    let age_str = match report.snapshot_age_seconds {
        Some(s) if s < 3600 => format!("{} min", s / 60),
        Some(s) if s < 86400 => format!("{} h", s / 3600),
        Some(s) => format!("{} d", s / 86400),
        None => tr(lang, "(unknown)", "(неизвестно)").to_string(),
    };
    html! {
        h1 style="font-family: var(--serif); font-weight: 400; margin: 24px 0 4px;" {
            (tr(lang, "Restore self-test", "Самопроверка восстановления"))
        }
        p style="font-family: var(--serif); font-style: italic; color: var(--mute); margin: 0 0 18px;" {
            (tr(
                lang,
                "Did the latest snapshot actually restore into a usable database? Run on every operator click; cron-schedulable next.",
                "Восстанавливается ли последний снэпшот в рабочую БД? Запускается по клику оператора; cron-расписание — следующий шаг.",
            ))
        }
        div style=(format!(
            "display: grid; grid-template-columns: max-content 1fr; gap: 8px 16px; padding: 12px 14px; border: 2px solid {overall_color}; background: var(--paper); margin-bottom: 20px;"
        )) {
            div style="font-family: var(--mono); font-size: 11px; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase;" { (tr(lang, "overall", "итог")) }
            div style=(format!("font-family: var(--serif); font-weight: 500; color: {overall_color};")) { (overall_label) }
            div style="font-family: var(--mono); font-size: 11px; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase;" { (tr(lang, "snapshot", "снэпшот")) }
            div style="font-family: var(--mono); font-size: 12px; overflow-wrap: anywhere;" { (report.snapshot_path) }
            div style="font-family: var(--mono); font-size: 11px; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase;" { (tr(lang, "age", "возраст")) }
            div style="font-family: var(--mono); font-size: 12px;" { (age_str) }
            div style="font-family: var(--mono); font-size: 11px; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase;" { (tr(lang, "duration", "длительность")) }
            div style="font-family: var(--mono); font-size: 12px;" { (report.duration_ms) " ms" }
        }
        div.ed-rule {}
        div.ed-art-eyebrow { (tr(lang, "Per-check results", "Результаты проверок")) }
        table style="width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 12px; margin-top: 10px;" {
            thead {
                tr style="border-bottom: 1px solid var(--ink);" {
                    th style="text-align: left; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                        (tr(lang, "check", "проверка"))
                    }
                    th style="text-align: left; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                        (tr(lang, "status", "статус"))
                    }
                    th style="text-align: left; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                        (tr(lang, "detail", "детали"))
                    }
                }
            }
            tbody {
                @for c in &report.checks {
                    @let color = match c.status {
                        CheckStatus::Ok => "var(--ok, #2e7d32)",
                        CheckStatus::Warn => "var(--warn, #e6a23c)",
                        CheckStatus::Fail => "var(--red, #c62828)",
                    };
                    tr style="border-bottom: 1px dotted var(--rule);" {
                        td style="padding: 6px 8px;" { (c.name) }
                        td style=(format!("padding: 6px 8px; font-weight: 500; color: {color};")) {
                            (c.status.label().to_uppercase())
                        }
                        td style="padding: 6px 8px;" { (c.detail) }
                    }
                }
            }
        }
        div style="margin-top: 24px; display: flex; gap: 12px;" {
            form method="post" action="/admin/backup/self-test" style="display: inline;" {
                button type="submit"
                       style="padding: 6px 14px; border: 1px solid var(--ink); background: var(--ink); color: var(--paper); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                    (tr(lang, "run again", "запустить снова"))
                }
            }
            a href="/admin/settings#backups-section"
              style="padding: 6px 14px; border: 1px solid var(--rule); color: var(--ink); font-family: var(--mono); font-size: 11px; text-decoration: none;" {
                (tr(lang, "back to Settings", "назад к настройкам"))
            }
        }
    }
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
        "/admin/servers/{}#enabled-protocols",
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
        "/admin/servers/{}#enabled-protocols",
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

    let address_raw: String = form_field(&body, "address")
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    // Route through the wizard's strict validator (charset
    // `[A-Za-z0-9.:_-]`, length ≤ 255). The old quick-add gate
    // only rejected ASCII space + length > 253, letting `\n`, `\r`,
    // `\t`, and most control bytes through into `Server.address`
    // (where they could later land in log lines / audit payloads as
    // broken multi-line records). Security audit 2026-05-18 finding.
    let address = match crate::wizard::validate_address(&address_raw) {
        Ok(s) => s.to_string(),
        Err(why) => {
            return bad_request(&format!("invalid address: {why}"));
        }
    };

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
    if !(2..=32).contains(&len) {
        return false;
    }
    // Post-2026-05-20 lowercase enforcement (Pavel: «Lowercase
    // тоже скорее обезопасит»). Existing 33 production users have
    // been batch-migrated to lowercase; the validator stops new
    // mixed-case ids from re-introducing drift. Legacy `.` allowed
    // to preserve `lana.fedyanina`-style dotted names; underscore
    // for `abukarov_tk`-style. Frontend live-edit normalises input
    // as the operator types, so this 400 should only fire on the
    // direct curl path or a malicious POST.
    id.bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-'))
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
            "invalid user id '{id_decoded}' (allowed: 2-32 chars of a-z 0-9 . _ -; lowercase only)"
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
        vpn_router_device_id: None,
        // Migration 0026 default — newly-created users start enabled.
        disabled: false,
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
    // I1 unification (audit 2026-05-22): same payload shape as the
    // CLI path — `{uuid, wg_pubkey_set, wg_keypair_provenance}`.
    // Web ALWAYS server-generates the WG pair (the form has no
    // opt-out — operator preference is one-click). `wg_pubkey_set`
    // pinned at runtime against the actual mutation result rather
    // than hardcoded `true`; if a future regression makes wg_pub
    // None for any reason, the audit row will show it.
    if let Err(e) = state
        .inv
        .audit(
            "admin",
            "user.add",
            Some(&id_decoded),
            Some(&serde_json::json!({
                "uuid": user.uuid,
                "wg_pubkey_set": user.wireguard_pubkey.is_some(),
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

    // D1: grant access to every registered server, if the «grant
    // all servers» checkbox stays checked (default ON). Pre-
    // 2026-05-22 the user-create handler produced a user with ZERO
    // grants, then the operator had to drill into each server to
    // grant access. The form checkbox + this loop close the «one
    // click should produce a usable user» gap. Loop is sequential
    // (≤100 servers in homelab → ≤100ms total via the same indexed
    // grant path the per-server route uses); audit row per grant
    // matches `user_grant_server` semantics so the timeline can
    // still distinguish bulk-grant from individual grants by the
    // burst pattern.
    let grant_all = form_field(&body, "grant_all").as_deref() == Some("1");
    if grant_all {
        match state.inv.list_servers().await {
            Ok(servers) => {
                let mut granted: u32 = 0;
                for s in &servers {
                    if let Err(e) = state.inv.grant(&user.id, &s.id).await {
                        tracing::warn!(
                            target = "vpnctld::admin",
                            user = %id_decoded,
                            server = %s.id.0,
                            error = %e,
                            "grant-all: per-server grant failed; continuing"
                        );
                        continue;
                    }
                    granted += 1;
                    // Audit each grant individually so the per-
                    // server timeline filter still surfaces the
                    // event. (Filtering by `action=user.grant` will
                    // include these rows alongside hand-grants.)
                    if let Err(e) = state
                        .inv
                        .audit(
                            "admin",
                            "user.grant",
                            Some(&id_decoded),
                            Some(&serde_json::json!({
                                "server": s.id.0,
                                "source": "user.create.grant_all",
                            })),
                        )
                        .await
                    {
                        tracing::warn!(
                            target = "vpnctld::admin",
                            user = %id_decoded,
                            server = %s.id.0,
                            error = %e,
                            "audit write failed for user.grant — mutation already committed"
                        );
                    }
                }
                if granted > 0 {
                    tracing::info!(
                        target = "vpnctld::admin",
                        user = %id_decoded,
                        granted = granted,
                        total = servers.len(),
                        "user-create grant-all complete"
                    );
                }
            }
            Err(e) => {
                tracing::warn!(
                    target = "vpnctld::admin",
                    user = %id_decoded,
                    error = %e,
                    "grant-all: list_servers failed; user created without grants"
                );
            }
        }
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

/// `POST /admin/servers/{id}/grants/_grant-all` (B2, audit 2026-05-22,
/// shipped 2026-05-23) — grant access to **every existing user** on
/// this server. Common after deploying a new server: instead of
/// clicking «grant» for each user, click one button. Per-user grant
/// is idempotent at the SQL layer (`ON CONFLICT DO NOTHING`), so
/// re-running this on a fully-granted server is a no-op.
///
/// Writes ONE summary audit row (`server.grants.bulk_grant` with
/// `{granted, already_granted, failed, total_users}`) rather than
/// N individual rows — avoids audit timeline flood for the common
/// «50 users × 1 click» case. Per-user grant failures (rare —
/// inventory-layer DB error) are counted in `failed` and logged at
/// warn but DO NOT abort the batch — partial success is operator-
/// recoverable via the per-row UI.
///
/// No confirm gate (safe + reversible — operator can revoke
/// per-user OR use the bulk revoke flow).
pub(crate) async fn server_grant_all_users(
    State(state): State<AppState>,
    Path(server_id_str): Path<String>,
) -> Response {
    let sid = vpnctl_core::ServerId(server_id_str.clone());
    if let Ok(None) = state.inv.get_server(&sid).await {
        return not_found(&format!("no such server '{server_id_str}'"));
    }
    let users = match state.inv.list_users().await {
        Ok(u) => u,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    let already_granted: std::collections::HashSet<vpnctl_core::UserId> =
        match state.inv.users_for_server(&sid).await {
            Ok(v) => v.into_iter().map(|u| u.id).collect(),
            Err(e) => return internal_error(anyhow::Error::new(e)),
        };
    let mut granted: u32 = 0;
    let mut already: u32 = 0;
    let mut failed: u32 = 0;
    let mut skipped_disabled: u32 = 0;
    for u in &users {
        // Don't bulk-grant to soft-paused users (B1.user, audit
        // finding 2026-05-23). The grant would be functionally
        // harmless — disabled users' /sub renders an empty
        // config regardless — but silently un-paused-by-side-
        // effect violates the operator's «paused means out of
        // sight» mental model. Disabled users get caught here +
        // counted; operator can grant them individually after
        // enabling. Symmetric handling on revoke-all isn't
        // needed (revoking a disabled user is consistent with
        // them already being out-of-rotation).
        if u.disabled {
            skipped_disabled += 1;
            continue;
        }
        if already_granted.contains(&u.id) {
            already += 1;
            continue;
        }
        match state.inv.grant(&u.id, &sid).await {
            Ok(()) => granted += 1,
            Err(e) => {
                failed += 1;
                tracing::warn!(
                    target = "vpnctld::admin",
                    server = %server_id_str,
                    user = %u.id,
                    error = %e,
                    "bulk-grant: per-user grant failed; continuing"
                );
            }
        }
    }
    if let Err(e) = state
        .inv
        .audit(
            "admin",
            "server.grants.bulk_grant",
            Some(&server_id_str),
            Some(&serde_json::json!({
                "granted": granted,
                "already_granted": already,
                "failed": failed,
                "skipped_disabled": skipped_disabled,
                "total_users": users.len(),
            })),
        )
        .await
    {
        tracing::warn!(
            target = "vpnctld::admin",
            server = %server_id_str,
            error = %e,
            "audit write failed for server.grants.bulk_grant — mutations already committed"
        );
    }
    tracing::info!(
        target = "vpnctld::admin",
        server = %server_id_str,
        granted = granted,
        already = already,
        failed = failed,
        total = users.len(),
        "bulk-grant complete"
    );
    Redirect::to(&format!(
        "/admin/servers/{}",
        path_segment_encode(&server_id_str)
    ))
    .into_response()
}

/// `POST /admin/servers/{id}/grants/_revoke-all` (B2, audit 2026-05-22,
/// shipped 2026-05-23) — revoke access for **every currently-granted
/// user** on this server. Destructive — operator must confirm by
/// re-typing the server id in the `confirm=<id>` form field (same
/// double-submit shape as user delete in C-3.4). Mismatch → 400.
///
/// Writes ONE summary audit row (`server.grants.bulk_revoke` with
/// `{revoked, failed, total_was}`) rather than N per-user rows.
/// Per-user revoke is idempotent at the SQL layer; failures are
/// counted + logged but don't abort the batch.
pub(crate) async fn server_revoke_all_users(
    State(state): State<AppState>,
    Path(server_id_str): Path<String>,
    body: String,
) -> Response {
    let confirm = form_field(&body, "confirm").unwrap_or_default();
    if confirm != server_id_str {
        return bad_request(&format!(
            "bulk-revoke confirm mismatch: form sent '{confirm}', URL targets '{server_id_str}' — type the server id exactly to confirm"
        ));
    }
    let sid = vpnctl_core::ServerId(server_id_str.clone());
    if let Ok(None) = state.inv.get_server(&sid).await {
        return not_found(&format!("no such server '{server_id_str}'"));
    }
    let granted = match state.inv.users_for_server(&sid).await {
        Ok(v) => v,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    let total_was = granted.len();
    let mut revoked: u32 = 0;
    let mut failed: u32 = 0;
    for u in &granted {
        match state.inv.revoke(&u.id, &sid).await {
            Ok(()) => revoked += 1,
            Err(e) => {
                failed += 1;
                tracing::warn!(
                    target = "vpnctld::admin",
                    server = %server_id_str,
                    user = %u.id,
                    error = %e,
                    "bulk-revoke: per-user revoke failed; continuing"
                );
            }
        }
    }
    if let Err(e) = state
        .inv
        .audit(
            "admin",
            "server.grants.bulk_revoke",
            Some(&server_id_str),
            Some(&serde_json::json!({
                "revoked": revoked,
                "failed": failed,
                "total_was": total_was,
            })),
        )
        .await
    {
        tracing::warn!(
            target = "vpnctld::admin",
            server = %server_id_str,
            error = %e,
            "audit write failed for server.grants.bulk_revoke — mutations already committed"
        );
    }
    tracing::info!(
        target = "vpnctld::admin",
        server = %server_id_str,
        revoked = revoked,
        failed = failed,
        total_was = total_was,
        "bulk-revoke complete"
    );
    Redirect::to(&format!(
        "/admin/servers/{}",
        path_segment_encode(&server_id_str)
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
    let (theme, accent, lang) = theme_accent_lang(&headers);
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
    Ok(shell("users", &theme, &accent, lang, body))
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

/// `POST /admin/users/{id}/disable` — set the disabled flag to
/// true (B1.user, migration 0026). Idempotent: re-POSTing on an
/// already-disabled user is a no-op redirect, no audit row written.
/// Returns 303 to the user-detail page so the operator sees the
/// «disabled» banner immediately.
pub(crate) async fn user_set_disabled_true(
    State(state): State<AppState>,
    Path(user_id_str): Path<String>,
) -> Response {
    user_set_disabled_inner(state, user_id_str, true).await
}

/// `POST /admin/users/{id}/enable` — restore access by clearing the
/// disabled flag. Same idempotency + audit shape as `disable`.
pub(crate) async fn user_set_disabled_false(
    State(state): State<AppState>,
    Path(user_id_str): Path<String>,
) -> Response {
    user_set_disabled_inner(state, user_id_str, false).await
}

async fn user_set_disabled_inner(state: AppState, user_id_str: String, target: bool) -> Response {
    let uid = vpnctl_core::UserId(user_id_str.clone());
    let changed = match state.inv.set_user_disabled(&uid, target).await {
        Ok(b) => b,
        Err(vpnctl_inventory::SqliteInventoryError::Invalid(msg))
            if msg.starts_with("no such user") =>
        {
            return user_not_found(&user_id_str);
        }
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    // Audit-on-actual-mutation (NM-10 review-agent rule). No-op
    // re-POST writes nothing — timeline stays clean.
    if changed {
        let action = if target {
            "user.disable"
        } else {
            "user.enable"
        };
        if let Err(e) = state
            .inv
            .audit(
                "admin",
                action,
                Some(&user_id_str),
                Some(&serde_json::json!({
                    "disabled": target,
                })),
            )
            .await
        {
            tracing::warn!(
                target = "vpnctld::admin",
                user = %user_id_str,
                action = action,
                error = %e,
                "audit row failed for user disable/enable; mutation already committed"
            );
        }
    }
    Redirect::to(&format!(
        "/admin/users/{}",
        path_segment_encode(&user_id_str)
    ))
    .into_response()
}

/// Query string for `/admin/search` — single optional `q` field.
#[derive(serde::Deserialize, Default)]
pub(crate) struct SearchQuery {
    pub q: Option<String>,
}

/// `GET /admin/search?q=foo` (A5, audit 2026-05-22, shipped 2026-05-23)
/// — fleet-wide substring search across users / servers / alerts.
/// Click any hit to drill into the canonical detail page.
///
/// Empty `q` renders a search prompt page; non-empty `q` runs three
/// independent SQL substring scans in parallel and groups the hits
/// per type. Per-group cap = 50 rows; pathological `q="a"` won't
/// drown the page in a 10k-row table.
///
/// **Audit deliberately NOT included** — the existing /admin/audit
/// page already has a filter form on actor + action + free-text via
/// the URL, and pulling audit substring search into the universal
/// `/admin/search` would duplicate that surface AND surface large
/// payload JSON snippets the operator usually doesn't want
/// mixed with «which users match X». Link to /admin/audit from the
/// search results footer instead.
pub(crate) async fn search(
    headers: HeaderMap,
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<SearchQuery>,
) -> Result<Markup, Response> {
    let (theme, accent, lang) = theme_accent_lang(&headers);
    let query_raw = q.q.unwrap_or_default();
    let query = query_raw.trim();
    /// Per-group cap; below the existing /admin/users + /admin/servers
    /// scroll-friendliness thresholds so the results page never feels
    /// heavier than the canonical lists.
    const PER_GROUP_LIMIT: i64 = 50;

    let (users, servers, alerts) = if query.is_empty() {
        (Vec::new(), Vec::new(), Vec::new())
    } else {
        let (u, s, a) = tokio::try_join!(
            state.inv.search_users(query, PER_GROUP_LIMIT),
            state.inv.search_servers(query, PER_GROUP_LIMIT),
            state.inv.search_alerts(query, PER_GROUP_LIMIT),
        )
        .map_err(|e| internal_error(anyhow::Error::new(e)))?;
        (u, s, a)
    };

    let total_hits = users.len() + servers.len() + alerts.len();
    let body = html! {
        div.ed-art-eyebrow {
            (crate::i18n::tr(lang, "Fleet search", "Поиск по флоту"))
        }
        h1.ed-art-h1 {
            (crate::i18n::tr(lang, "find ", "найти "))
            em { (crate::i18n::tr(lang, "anything", "что угодно")) }
        }
        p.ed-art-deck {
            (crate::i18n::tr(
                lang,
                "Substring match across user ids / UUIDs / sub_tokens / device_ids, server ids / addresses, and alert kinds / summaries. Case-insensitive. Cap of 50 hits per group.",
                "Подстрочный поиск по id / UUID / sub_token / device_id пользователей, по id / адресам серверов, по kind / summary алертов. Регистронезависимо. Не больше 50 совпадений в каждой группе.",
            ))
        }
        form method="get" action="/admin/search"
             style="margin: 16px 0; display: flex; gap: 8px; align-items: baseline;" {
            input type="text" name="q"
                  value=(query)
                  autofocus="autofocus"
                  placeholder=(crate::i18n::tr(lang, "user id, ip, uuid, alert kind...", "id юзера, ip, uuid, kind алерта..."))
                  style="flex: 1; padding: 6px 10px; border: 1px solid var(--rule-s); background: var(--paper); font-family: var(--mono); font-size: 13px; color: var(--ink);";
            button type="submit"
                   style="padding: 6px 16px; border: 1px solid var(--ink); background: var(--ink); color: var(--paper); font-family: var(--mono); font-size: 12px; cursor: pointer;" {
                (crate::i18n::tr(lang, "search", "искать"))
            }
        }

        @if query.is_empty() {
            p style="font-family: var(--serif); font-style: italic; color: var(--mute); padding: 16px 0;" {
                (crate::i18n::tr(
                    lang,
                    "Type something above to begin. Hits link straight to the user / server / alert detail page.",
                    "Введи что-нибудь выше. Каждый результат — ссылка на страницу пользователя / сервера / алерта.",
                ))
            }
        } @else {
            p style="font-family: var(--mono); font-size: 11px; color: var(--mute); padding: 4px 0;" {
                (total_hits) " "
                (crate::i18n::tr(lang, "hits across ", "совпадений по "))
                (users.len()) " " (crate::i18n::tr(lang, "users · ", "юзерам · "))
                (servers.len()) " " (crate::i18n::tr(lang, "servers · ", "серверам · "))
                (alerts.len()) " " (crate::i18n::tr(lang, "alerts", "алертам"))
            }
            @if total_hits == 0 {
                p style="font-family: var(--serif); font-style: italic; color: var(--mute); padding: 16px 0;" {
                    (crate::i18n::tr(
                        lang,
                        "No matches. Audit-log searches still live on the ",
                        "Ничего не найдено. Поиск по audit-логу всё ещё на ",
                    ))
                    // Percent-encode the operator's q so a query
                    // like `foo&actor=admin` doesn't smuggle a
                    // second parameter into the fallback URL —
                    // `path_segment_encode` over-encodes (encodes
                    // `:` etc) but URLs still parse correctly.
                    a href=(format!("/admin/audit?action={}", path_segment_encode(query)))
                      style="color: var(--ink);" {
                        "/admin/audit"
                    }
                    (crate::i18n::tr(lang, " page (action filter accepts substrings).", " (фильтр action поддерживает подстроки)."))
                }
            }
            @if !users.is_empty() {
                div.ed-art-eyebrow style="margin-top: 20px;" {
                    (crate::i18n::tr(lang, "Users", "Пользователи")) " (" (users.len()) ")"
                }
                ul style="list-style: none; padding: 0; font-family: var(--serif); font-size: 13px; line-height: 1.7;" {
                    @for u in &users {
                        li style="display: flex; gap: 10px; padding: 2px 0; border-bottom: 1px dotted var(--rule);" {
                            a href=(format!("/admin/users/{}", path_segment_encode(&u.id.0)))
                              style="color: var(--ink); text-decoration: none; border-bottom: 1px dotted var(--ink);" {
                                b { (u.id.0) }
                            }
                            span style="font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                                "uuid=" (u.uuid)
                                @if u.disabled {
                                    " · "
                                    span style="color: var(--acc);" {
                                        (crate::i18n::tr(lang, "PAUSED", "ПАУЗА"))
                                    }
                                }
                            }
                        }
                    }
                }
            }
            @if !servers.is_empty() {
                div.ed-art-eyebrow style="margin-top: 20px;" {
                    (crate::i18n::tr(lang, "Servers", "Серверы")) " (" (servers.len()) ")"
                }
                ul style="list-style: none; padding: 0; font-family: var(--serif); font-size: 13px; line-height: 1.7;" {
                    @for s in &servers {
                        li style="display: flex; gap: 10px; padding: 2px 0; border-bottom: 1px dotted var(--rule);" {
                            a href=(format!("/admin/servers/{}", path_segment_encode(&s.id.0)))
                              style="color: var(--ink); text-decoration: none; border-bottom: 1px dotted var(--ink);" {
                                b { (s.id.0) }
                            }
                            span style="font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                                (s.address) ":" (s.ssh_port)
                            }
                        }
                    }
                }
            }
            @if !alerts.is_empty() {
                div.ed-art-eyebrow style="margin-top: 20px;" {
                    (crate::i18n::tr(lang, "Alerts", "Алерты")) " (" (alerts.len()) ")"
                }
                ul style="list-style: none; padding: 0; font-family: var(--serif); font-size: 13px; line-height: 1.7;" {
                    @for a in &alerts {
                        li style="display: flex; gap: 10px; padding: 2px 0; border-bottom: 1px dotted var(--rule);" {
                            // Alert detail isn't a route yet; link to
                            // /admin/alerts where the operator can ack
                            // / dig in. Show ack-state inline so the
                            // search results immediately surface
                            // open-vs-historical context.
                            a href="/admin/alerts"
                              style="color: var(--ink); text-decoration: none; border-bottom: 1px dotted var(--ink);" {
                                b { (a.kind) }
                            }
                            span style="font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                                (a.severity) " · "
                                @if a.acked_at.is_some() {
                                    span style="color: var(--mute);" {
                                        (crate::i18n::tr(lang, "acked", "принят"))
                                    }
                                } @else {
                                    span style="color: var(--acc);" {
                                        (crate::i18n::tr(lang, "OPEN", "ОТКРЫТ"))
                                    }
                                }
                                " · " (a.summary)
                            }
                        }
                    }
                }
            }
        }
    };
    Ok(shell("search", &theme, &accent, lang, body))
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
    let (theme, accent, lang) = theme_accent_lang(&headers);

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
        div.ed-art-eyebrow { (crate::i18n::t(lang, crate::i18n::K::PageAudit)) }
        h1.ed-art-h1 {
            (crate::i18n::tr(lang, "every ", "каждое "))
            em { (crate::i18n::tr(lang, "mutation", "изменение")) }
            (crate::i18n::tr(lang, " on file", " в базе"))
        }
        p.ed-art-deck {
            (crate::i18n::tr(
                lang,
                "Append-only stream of every state change the daemon or CLI has made to ",
                "Поток append-only — каждое изменение состояния которое демон или CLI сделали в ",
            ))
            span.ed-mono { "/var/lib/vpnctl/inv.db" }
            (crate::i18n::tr(
                lang,
                ". Use the filters to narrow by actor or action prefix; the CSV button exports the same filtered slice.",
                ". Используй фильтры чтобы сузить по автору / префиксу действия; кнопка CSV экспортирует ту же выборку.",
            ))
        }

        form method="get" action="/admin/audit"
             style="display: flex; gap: 12px; align-items: baseline; padding: 12px 14px; border: 1px solid var(--rule); margin: 16px 0 24px; font-family: var(--mono); font-size: 11px;" {
            label { (crate::i18n::tr(lang, "actor", "автор")) }
            select name="actor"
                   title=(crate::i18n::tr(
                       lang,
                       "admin = web UI, cli = vpnctl binary on the daemon host, daemon = scheduler / background job",
                       "admin = веб-UI, cli = бинарь vpnctl на хосте демона, daemon = шедулер / фоновая задача",
                   ))
                   style="padding: 3px 6px; border: 1px solid var(--rule-s); font-family: var(--mono); font-size: 11px;" {
                option value="" { (crate::i18n::tr(lang, "(any)", "(любой)")) }
                @for opt in ["admin", "cli", "daemon"] {
                    @if Some(opt) == actor {
                        option value=(opt) selected="selected" { (opt) }
                    } @else {
                        option value=(opt) { (opt) }
                    }
                }
            }
            label { (crate::i18n::tr(lang, "action prefix", "префикс действия")) }
            input type="text" name="action"
                  value=(action.unwrap_or(""))
                  placeholder="server.protocol. / user. / grant. / settings."
                  title=(crate::i18n::tr(
                      lang,
                      "Substring/prefix match on action column. Convention: dot-separated domain.subdomain.verb (e.g. `server.protocol.set_hidden`, `user.sub_token.regen`, `grant.protocol.set_override`). Underscores allowed INSIDE a verb.",
                      "Поиск по подстроке/префиксу в колонке action. Конвенция: точка-разделитель domain.subdomain.verb (напр. `server.protocol.set_hidden`, `user.sub_token.regen`, `grant.protocol.set_override`). Подчёркивания допустимы ВНУТРИ verb.",
                  ))
                  style="padding: 3px 6px; max-width: 320px; border: 1px solid var(--rule-s); font-family: var(--mono); font-size: 11px;";
            button type="submit"
                   title=(crate::i18n::tr(
                       lang,
                       "Apply actor + action-prefix filters. URL stores them so the page is bookmarkable.",
                       "Применить фильтры по автору + префиксу действия. URL сохраняет их — страницу можно бookmark-нуть.",
                   ))
                   style="padding: 3px 10px; border: 1px solid var(--ink); background: var(--ink); color: var(--paper); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                (crate::i18n::t(lang, crate::i18n::K::BtnFilter))
            }
            a href="/admin/audit"
              title=(crate::i18n::tr(
                  lang,
                  "Clear all filters and return to the unfiltered timeline.",
                  "Очистить все фильтры и вернуться к нефильтрованной ленте.",
              ))
              style="padding: 3px 10px; border: 1px solid var(--rule-s); background: transparent; color: var(--mute); font-family: var(--mono); font-size: 11px; text-decoration: none;" {
                (crate::i18n::t(lang, crate::i18n::K::BtnReset))
            }
            a href=(audit_url("/admin/audit.csv", actor, action, None))
              title=(crate::i18n::tr(
                  lang,
                  "Download the currently-filtered slice as CSV (up to 10000 rows). Honours both actor + action filters.",
                  "Скачать текущую выборку как CSV (до 10000 строк). Учитывает оба фильтра.",
              ))
              style="margin-left: auto; padding: 3px 10px; border: 1px solid var(--rule-s); background: transparent; color: var(--ink); font-family: var(--mono); font-size: 11px; text-decoration: none;" {
                (crate::i18n::t(lang, crate::i18n::K::BtnExportCsv))
            }
        }

        @if visible.is_empty() {
            p style="font-family: var(--serif); font-style: italic; color: var(--mute); padding: 24px 0;" {
                @if actor.is_some() || action.is_some() {
                    (crate::i18n::tr(
                        lang,
                        "No audit rows match the current filter.",
                        "Под текущий фильтр не подошла ни одна строка аудита.",
                    ))
                } @else {
                    (crate::i18n::tr(
                        lang,
                        "No audit rows yet — this stream fills as the daemon does work.",
                        "Записей аудита ещё нет — поток наполняется по мере работы демона.",
                    ))
                }
            }
        } @else {
            (audit_timeline_grouped(&visible, lang))
        }

        div style="display: flex; gap: 16px; padding: 16px 0; font-family: var(--mono); font-size: 12px;" {
            @if has_prev {
                a href=(audit_url("/admin/audit", actor, action, Some(page - 1)))
                  style="color: var(--ink); text-decoration: none;" {
                    (crate::i18n::tr(lang, "← prev", "← назад"))
                }
            } @else {
                span style="color: var(--mute);" {
                    (crate::i18n::tr(lang, "← prev", "← назад"))
                }
            }
            @let page_title = match lang {
                crate::i18n::Locale::En => format!(
                    "URL convention: ?page=N is 0-based (omitted when 0). Current URL: ?page={page}. Visible label: page {}.",
                    page + 1
                ),
                crate::i18n::Locale::Ru => format!(
                    "Конвенция URL: ?page=N считается с 0 (пропускается когда 0). Текущий URL: ?page={page}. Видимая метка: страница {}.",
                    page + 1
                ),
            };
            span style="color: var(--mute);" title=(page_title) {
                (crate::i18n::tr(lang, "page ", "стр. ")) (page + 1)
            }
            @if has_next {
                a href=(audit_url("/admin/audit", actor, action, Some(page + 1)))
                  style="color: var(--ink); text-decoration: none;" {
                    (crate::i18n::tr(lang, "next →", "вперёд →"))
                }
            } @else {
                span style="color: var(--mute);" {
                    (crate::i18n::tr(lang, "next →", "вперёд →"))
                }
            }
        }
    };
    Ok(shell("audit", &theme, &accent, lang, body))
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
fn audit_timeline_grouped(
    entries: &[&vpnctl_inventory::AuditEntry],
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    use chrono::{Duration, Utc};
    let today = Utc::now().date_naive();
    let yesterday = today - Duration::days(1);
    let mut current_label: Option<String> = None;
    html! {
        div.ed-time {
            @for e in entries {
                @let day = e.ts.date_naive();
                @let label = if day == today {
                    tr(lang, "Today", "Сегодня").to_string()
                } else if day == yesterday {
                    tr(lang, "Yesterday", "Вчера").to_string()
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
                        (tr(lang, "by ", "автор: ")) (e.actor)
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
    let (theme, accent, lang) = theme_accent_lang(&headers);

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
        div.ed-art-eyebrow { (crate::i18n::t(lang, crate::i18n::K::PageAlerts)) }
        h1.ed-art-h1 {
            (crate::i18n::tr(lang, "what the homelab is ", "на что homelab "))
            em { (crate::i18n::tr(lang, "shouting", "ругается")) }
            (crate::i18n::tr(lang, " about", ""))
        }
        p.ed-art-deck {
            (crate::i18n::tr(
                lang,
                "Infrastructure alerts written by the Phase G health-monitor on top of the Phase H node probe. Service flips, disk + memory pressure, runaway sing-box logs, unreachable hosts, and the «I locked myself out» class (fail2ban banned us). Ack each one when you've looked — the dashboard tile ",
                "Алерты инфраструктуры, которые пишет health-monitor (Phase G) поверх node probe (Phase H). Сервис упал/поднялся, давление на диск/память, разрастающиеся логи sing-box, недоступные хосты, класс «сам себя забанил» (fail2ban забанил нас). Принимай каждое (ack) когда посмотрел — тайл дашборда ",
            ))
            em { (crate::i18n::tr(lang, "homelab health", "здоровье homelab")) }
            (crate::i18n::tr(lang, " counts unacked items.", " считает непринятые."))
        }
        div.ed-rule {}
        div style="display: flex; gap: 16px; align-items: baseline; margin-bottom: 14px;" {
            span.ed-mono {
                (unacked_total) " " (crate::i18n::tr(lang, "unacked", "непринятых"))
            }
            @if include_acked {
                a href="/admin/alerts" style="color: var(--mute); text-decoration: none;" {
                    (crate::i18n::tr(lang, "← only unacked", "← только непринятые"))
                }
            } @else {
                a href="/admin/alerts?show=all" style="color: var(--mute); text-decoration: none;" {
                    (crate::i18n::tr(lang, "show all (including acked) →", "показать всё (включая принятые) →"))
                }
            }
            // Bulk-ack: only render when there's actually something
            // to ack (otherwise an «ack all (0)» button is just a
            // tiny invitation to misclick). `onsubmit` does an
            // in-browser confirm() — the action is destructive (clears
            // the whole feed), but reversible-via-history (acked rows
            // stay in /admin/alerts?show=all for 30d), so a single
            // confirm prompt is the right friction level. Pinned by
            // `alerts_page_renders_ack_all_button_when_unacked_total_nonzero`.
            @if unacked_total > 0 {
                // `onsubmit` embeds the translated string into a JS
                // single-quoted literal. Future-proof against
                // apostrophe regressions («don't», «it's») via
                // `js_single_quote_escape` — current copy is
                // apostrophe-free but the helper makes silent breakage
                // impossible. Caught by review-agent 2026-05-22:
                // unescaped interpolation silently broke confirm()
                // dialogs the first time an editor added `don't`.
                @let confirm_msg = js_single_quote_escape(crate::i18n::tr(
                    lang,
                    "Ack all unacked alerts? They will stay visible under «show all» for 30 days; nothing is deleted, just marked seen.",
                    "Принять все непринятые алерты? Они останутся видимы в «показать всё» 30 дней; ничего не удаляется, только помечается просмотренным.",
                ));
                form method="post"
                     action="/admin/alerts/ack-all"
                     style="display: inline; margin-left: auto;"
                     onsubmit=(format!("return confirm('{confirm_msg}');")) {
                    button type="submit"
                           title=(crate::i18n::tr(
                               lang,
                               "Mark every unacked alert as seen in one click. Doesn't clear or fix the underlying conditions — just clears the dashboard tile. The alert rows stay in the feed under «show all».",
                               "Отметить все непринятые алерты как просмотренные одним кликом. Не очищает и не чинит условия — лишь обнуляет тайл дашборда. Строки остаются в ленте под «показать всё».",
                           ))
                           style="background: transparent; border: 1px solid var(--rule); color: var(--accent-text, var(--ink)); font-family: var(--mono); font-size: 11px; padding: 2px 10px; cursor: pointer;" {
                        (crate::i18n::tr(lang, "ack all", "принять все"))
                        " (" (unacked_total) ")"
                    }
                }
            }
        }
        @if alerts_rows.is_empty() {
            div.ed-empty {
                p {
                    @if include_acked {
                        (crate::i18n::tr(
                            lang,
                            "no alerts on record. Either the homelab has been ",
                            "ни одного алерта в записях. Либо homelab был ",
                        ))
                        em { (crate::i18n::tr(lang, "extraordinarily", "удивительно")) }
                        (crate::i18n::tr(
                            lang,
                            " quiet, or vpnctld hasn't been running long enough for the probe to fire one. Check ",
                            " тихим, либо vpnctld запущен недостаточно долго чтобы probe что-то поймал. Проверь ",
                        ))
                        span.ed-mono { "journalctl -u vpnctld -t vpnctld::health_monitor" }
                        (crate::i18n::tr(lang, " for the scan trail.", " на предмет следов сканера."))
                    } @else {
                        (crate::i18n::tr(
                            lang,
                            "no unacked alerts. Everything the homelab is currently ",
                            "нет непринятых алертов. Всё на что сейчас homelab ",
                        ))
                        em { (crate::i18n::tr(lang, "complaining", "жалуется")) }
                        (crate::i18n::tr(
                            lang,
                            " about lives here; nothing means nothing's wrong (or every condition has been acknowledged). To browse history: ",
                            " — здесь. Пусто значит всё хорошо (либо все условия приняты). Посмотреть историю: ",
                        ))
                        a href="/admin/alerts?show=all" {
                            (crate::i18n::tr(lang, "show all →", "показать всё →"))
                        }
                    }
                }
            }
        } @else {
            (alerts_table(&alerts_rows, lang))
        }
    };
    Ok(shell("alerts", &theme, &accent, lang, body))
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

/// `POST /admin/alerts/ack-all` — operator dismisses every currently-
/// unacked alert in one go. Companion to per-row `alert_ack` for the
/// «I've triaged a backlog, clear them» workflow (fire-drill 2026-05-
/// 22: 33 `sub_access.suspicious_local_ip` alerts had accumulated
/// from legit LAN testing — clicking 33 ack buttons is a UX bug,
/// not a feature).
///
/// Idempotent — re-POSTing after everything is acked returns 0
/// rows-affected and writes NO audit row (audit-on-actual-mutation
/// convention, NM-10 review-agent rule).
///
/// Always 303s back to `/admin/alerts` so refresh-after-submit
/// can't re-submit (POST-redirect-GET).
pub(crate) async fn alert_ack_all(State(state): State<AppState>) -> Response {
    let count = match state.inv.ack_all_unacked_alerts().await {
        Ok(n) => n,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    // Audit ONLY when something actually changed. A no-op POST
    // shouldn't pollute the timeline (matches NM-10 review-agent
    // catch on `set_server_protocol_hidden` no-op-audit-spam).
    if count > 0 {
        if let Err(e) = state
            .inv
            .audit(
                "admin",
                "alerts.ack_all",
                None,
                Some(&serde_json::json!({ "count": count })),
            )
            .await
        {
            tracing::warn!(
                target = "vpnctld::admin::alert_ack_all",
                count = count,
                error = %e,
                "ack-all succeeded but audit row failed; timeline will be missing this entry"
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
fn alerts_table(rows: &[vpnctl_inventory::AdminAlert], lang: crate::i18n::Locale) -> Markup {
    use crate::i18n::{K, t, tr};
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
                                    (tr(lang, "acked ", "принято "))
                                    (clip_ts(&when.to_rfc3339()))
                                }
                            }
                            None => {
                                " · "
                                form method="post" action=(format!("/admin/alerts/{}/ack", a.id))
                                     style="display: inline;" {
                                    button type="submit"
                                           title=(tr(
                                               lang,
                                               "Mark this alert acknowledged. Doesn't clear or fix the underlying condition — just records 'I've seen it'. The alert row stays in the feed (with an acked-timestamp) until the condition resolves.",
                                               "Отметить алерт принятым. Не очищает и не чинит условие — просто фиксирует «я это видел». Строка остаётся в ленте (с меткой времени принятия) пока условие не уйдёт.",
                                           ))
                                           style="background: transparent; border: 1px solid var(--rule); color: var(--ink); font-family: var(--mono); font-size: 11px; padding: 2px 8px; cursor: pointer;" {
                                        (t(lang, K::BtnAck))
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

/// Render the «GeoIP — IP enrichment» section on Settings.
///
/// Reads `VPNCTLD_GEOIP_DIR` (defaults to `/var/lib/vpnctl/geoip`)
/// and reports per-file: present? last-modified? size?
///
/// Phase 5e — «Disaster recovery» single-glance summary in Settings.
///
/// Consolidates the operator's «what if 236 burns?» story onto one
/// screen:
///
///   1. Where the backups live (3 tiers: local hourly Rust snapshots,
///      daily encrypted bundle on 207, off-site daily bundle on
///      Iceland).
///   2. What's in each bundle (so the operator knows BEFORE the
///      disaster what they'll get back — chiefly the deploy SSH
///      key, without which a restored vpnctld is locked out of every
///      VPN node).
///   3. Last restore self-test result (from `audit_log` —
///      `backup.self_test` action) — with a "run again" button.
///   4. The restore procedure (3 steps).
///
/// All text is bilingual (EN/RU). No new persistence — the last-
/// test status is read from `audit_log` via a 50-row tail filtered
/// in the caller. If `last_self_test` is `None` the section renders
/// «not yet run» + the call-to-action.
///
/// Operator-policy compliance: this section lists shell commands
/// (`age -d`, `vpnctl restore`, `systemctl restart vpnctld`) — all
/// covered by the «daemon literally can't help» exception in
/// CLAUDE.md. The whole procedure runs on a DIFFERENT HOST than
/// 236 (because 236 is presumed dead — the entire reason this
/// section exists). At that point the daemon doesn't exist to be
/// asked to push buttons; the operator is bootstrapping a new
/// vpnctld instance from scratch. Every action that COULD be a
/// Web UI button on the running 236 (push deploy key, etc) is
/// kept in the procedure as a Web UI step on the NEW host.
fn settings_disaster_recovery_section(
    lang: crate::i18n::Locale,
    last_self_test: Option<&vpnctl_inventory::AuditEntry>,
) -> Markup {
    use crate::i18n::tr;
    // Format the last self-test: status chip + when + duration.
    // Pulled from audit_log payload, which is JSON; we don't
    // panic if the shape doesn't match — just show «(missing
    // field)» so future schema changes don't break the page.
    let last = last_self_test.map(|e| {
        let payload = e.payload.as_ref();
        let overall = payload
            .and_then(|p| p.get("overall").and_then(|v| v.as_str()))
            .unwrap_or("?")
            .to_string();
        // `Option` so a future audit-payload schema drift renders
        // «(missing)» rather than a misleading «0 ms» that would
        // look like a fast successful run in a post-mortem.
        let duration_ms: Option<i64> =
            payload.and_then(|p| p.get("duration_ms").and_then(|v| v.as_i64()));
        (e.ts, overall, duration_ms)
    });

    html! {
        div.ed-rule {}
        div #disaster-recovery.ed-art-eyebrow {
            (tr(lang, "Disaster recovery — if 192.168.0.236 burns", "Аварийное восстановление — если 192.168.0.236 сгорит"))
        }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
            (tr(
                lang,
                "What happens when the homelab host disappears and you need to bring vpnctld back from scratch — sources of truth, what's in each bundle, the self-test status, and the 3-step recovery path. Click the button below ANY time to prove the latest snapshot is restorable BEFORE you need to do it for real.",
                "Что произойдёт когда хост homelab пропадёт и нужно поднять vpnctld с нуля — источники истины, что в каждом архиве, статус self-test'а и трёхшаговый план восстановления. Нажми кнопку ниже ЛЮБОЕ время чтобы доказать что последний снэпшот восстанавливается ДО того как это станет нужно по-настоящему.",
            ))
        }

        // ── Where backups live ──────────────────────────────────────────
        div style="font-family: var(--mono); font-size: 11px; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; margin-top: 16px;" {
            (tr(lang, "Where backups live · 3 tiers", "Где живут бэкапы · 3 уровня"))
        }
        table style="width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 12px; margin-top: 8px;" {
            thead {
                tr style="border-bottom: 1px solid var(--ink);" {
                    th style="text-align: left; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                        (tr(lang, "tier", "уровень"))
                    }
                    th style="text-align: left; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                        (tr(lang, "location", "путь"))
                    }
                    th style="text-align: left; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                        (tr(lang, "encryption", "шифрование"))
                    }
                    th style="text-align: left; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                        (tr(lang, "retention", "хранение"))
                    }
                }
            }
            tbody {
                tr style="border-bottom: 1px dotted var(--rule);" {
                    td style="padding: 6px 8px;" { "1. local" }
                    td style="padding: 6px 8px;" { span.ed-mono { (crate::app::DEFAULT_BACKUP_DIR) } }
                    td style="padding: 6px 8px; color: var(--mute);" { (tr(lang, "plaintext (daemon-owned 0640)", "plaintext (демон-only 0640)")) }
                    td style="padding: 6px 8px; color: var(--mute);" { (tr(lang, "24 hourly + 30 daily + 12 monthly", "24 часовых + 30 дневных + 12 месячных")) }
                }
                tr style="border-bottom: 1px dotted var(--rule);" {
                    td style="padding: 6px 8px;" { "2. LAN archive" }
                    td style="padding: 6px 8px;" { span.ed-mono { "user@192.168.0.207:/home/user/backups/vpnctl/" } }
                    td style="padding: 6px 8px; color: var(--mute);" { (tr(lang, "age (recipient pubkey on 236)", "age (pubkey получателя на 236)")) }
                    td style="padding: 6px 8px; color: var(--mute);" { (tr(lang, "14 days · daily 03:04 UTC", "14 дней · ежедневно 03:04 UTC")) }
                }
                tr {
                    td style="padding: 6px 8px;" { "3. off-site" }
                    td style="padding: 6px 8px;" { span.ed-mono { "root@93.95.226.167:/root/vpnctl-backups/" } " (Iceland)" }
                    td style="padding: 6px 8px; color: var(--mute);" { (tr(lang, "age (same recipient)", "age (тот же получатель)")) }
                    td style="padding: 6px 8px; color: var(--mute);" { (tr(lang, "30 days · daily 03:04 UTC", "30 дней · ежедневно 03:04 UTC")) }
                }
            }
        }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 10px 0 0;" {
            (tr(
                lang,
                "The age private key (",
                "Приватный age-ключ (",
            ))
            span.ed-mono { "/home/user/vpnctl-backup-key.age" }
            (tr(
                lang,
                ") lives on 207. If 207 also burns, tiers 2+3 become unreadable — keep a copy on a USB stick / paper / password manager.",
                ") живёт на 207. Если 207 тоже сгорит, уровни 2+3 нерасшифровываются — храни копию на USB / бумаге / в password-manager.",
            ))
        }

        // ── What's bundled ──────────────────────────────────────────────
        div style="font-family: var(--mono); font-size: 11px; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; margin-top: 20px;" {
            (tr(lang, "What's in each daily bundle", "Что в ежедневном бандле"))
        }
        ul style="font-family: var(--serif); font-size: 13px; line-height: 1.6; margin: 8px 0 0 24px; padding: 0;" {
            li {
                span.ed-mono { "inv.db" }
                " — "
                (tr(lang, "the entire inventory: users, servers, grants, sub_tokens, WG keys, TUIC passwords, audit log, all sub_access_log / vpn_user_* analytics tables.", "вся inventory: users, servers, grants, sub_tokens, WG-ключи, TUIC-пароли, audit log, все аналитические таблицы sub_access_log / vpn_user_*."))
            }
            li {
                span.ed-mono { "/var/lib/vpnctl/.ssh/id_ed25519{,.pub}" }
                " — "
                b { (tr(lang, "deploy SSH key", "deploy SSH-ключ")) }
                ". " (tr(lang, "Without this a restored vpnctld can't reach ANY VPN node (CLAUDE.md «hard invariant»).", "Без него восстановленный vpnctld не достучится ни до одной VPN-ноды («жёсткий инвариант» в CLAUDE.md)."))
            }
            li {
                span.ed-mono { "/var/lib/vpnctl/.ssh/known_hosts" }
                " — "
                (tr(lang, "TOFU-pinned host keys (so post-restore SSH doesn't prompt unknown-host).", "TOFU-pinned ключи хостов (чтобы SSH после restore не спрашивал unknown-host)."))
            }
            li {
                span.ed-mono { "/etc/vpnctl/vpnctld.env" }
                " · "
                span.ed-mono { "/etc/vpnctl/backup-recipient.txt" }
                " — "
                (tr(lang, "admin password + Telegram token + which age recipient to push NEW backups to.", "admin password + Telegram-токен + кому age-encrypt'ить новые бэкапы."))
            }
            li {
                span.ed-mono { "/var/lib/vpnctl/geoip/*.mmdb" }
                " — "
                (tr(lang, "DB-IP City + ASN (130MB + 9MB). Re-fetchable via the «update now» button above, but bundling avoids the first-boot round-trip.", "DB-IP City + ASN (130MB + 9MB). Можно перекачать кнопкой «обновить сейчас» выше, но в бандле — чтобы не ждать первой загрузки."))
            }
            li {
                span.ed-mono { "/etc/systemd/system/vpnctld.{service,…}" }
                " · "
                span.ed-mono { "/etc/iptables/rules.v4" }
                " — "
                (tr(lang, "service unit + firewall rules so the restored host self-bootstraps.", "unit + iptables правила чтобы хост восстановился сам."))
            }
        }

        // ── Last self-test status ───────────────────────────────────────
        div style="font-family: var(--mono); font-size: 11px; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; margin-top: 20px;" {
            (tr(lang, "Last restore self-test", "Последний self-test восстановления"))
        }
        @match &last {
            Some((ts, overall, duration_ms)) => {
                @let color = match overall.as_str() {
                    "ok"    => "#2e7d32",
                    "warn"  => "#e6a23c",
                    "fail" | "error" => "#c62828",
                    _ => "var(--mute)",
                };
                @let label = match overall.as_str() {
                    "ok"    => tr(lang, "PASS", "ПРОЙДЕНО"),
                    "warn"  => tr(lang, "PASS · with warnings", "ПРОЙДЕНО · с предупреждениями"),
                    "fail"  => tr(lang, "FAIL", "ПРОВАЛ"),
                    "error" => tr(lang, "ERROR", "ОШИБКА"),
                    other => other,
                };
                div style="display: flex; gap: 16px; align-items: center; margin: 8px 0 14px; padding: 10px 14px; border: 1px solid var(--rule); background: var(--paper);" {
                    span style=(format!("font-family: var(--serif); font-weight: 500; color: {color}; font-size: 14px;")) { (label) }
                    span style="color: var(--mute); font-family: var(--mono); font-size: 11.5px;" {
                        (ts.format("%Y-%m-%d %H:%M UTC").to_string())
                        " · "
                        @match duration_ms {
                            Some(ms) => { (ms) " ms" }
                            None => { (tr(lang, "(duration missing)", "(длительность отсутствует)")) }
                        }
                    }
                }
            }
            None => {
                p style="font-family: var(--serif); font-style: italic; color: var(--mute); margin: 8px 0 14px; font-size: 12px;" {
                    (tr(lang, "Never run on this daemon. Click below to prove the latest snapshot restores cleanly — takes <1s, doesn't touch the live inv.db.", "Никогда не запускался на этом демоне. Кликни ниже чтобы доказать что последний снэпшот восстанавливается чисто — займёт <1с, живую inv.db не трогает."))
                }
            }
        }
        div style="display: flex; gap: 12px; margin-bottom: 18px;" {
            form method="post" action="/admin/backup/self-test" style="display: inline;" {
                button type="submit"
                       style="padding: 6px 14px; border: 1px solid var(--ink); background: var(--ink); color: var(--paper); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                    (tr(lang, "run self-test now", "запустить self-test сейчас"))
                }
            }
            a href="/admin/audit?action_prefix=backup"
              style="padding: 6px 14px; border: 1px solid var(--rule); color: var(--ink); font-family: var(--mono); font-size: 11px; text-decoration: none;" {
                (tr(lang, "self-test history", "история self-test"))
            }
        }

        // ── Restore procedure ───────────────────────────────────────────
        div style="font-family: var(--mono); font-size: 11px; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; margin-top: 16px;" {
            (tr(lang, "Restore procedure · 3 steps", "Процедура восстановления · 3 шага"))
        }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 8px;" {
            (tr(
                lang,
                "Steps 1+2 run on a NEW host (because 236 is presumed dead — there's no daemon to push buttons on). Step 3 returns to the normal Web UI on the recovered daemon.",
                "Шаги 1+2 выполняются на НОВОМ хосте (потому что 236 предположительно мёртв — некому жать кнопки в UI). Шаг 3 возвращается к обычному Web UI на восстановленном демоне.",
            ))
        }
        ol style="font-family: var(--serif); font-size: 13px; line-height: 1.6; margin: 8px 0 0 24px; padding: 0;" {
            li {
                b { (tr(lang, "On the new host: decrypt + extract", "На новом хосте: расшифруй + распакуй")) }
                " — "
                (tr(lang, "anywhere (new VPS, restored from VM snapshot, fresh laptop install). Decrypt the latest archive from tier 3 (Iceland) with ", "где угодно (новый VPS, восстановленный VM-снэпшот, свежий ноут). Расшифруй последний архив с уровня 3 (Iceland) через "))
                span.ed-mono { "age -d -i /path/to/vpnctl-backup-key.age" }
                (tr(lang, ". Extract the tar — you'll get the full ", ". Распакуй tar — получишь полный "))
                span.ed-mono { "vpnctl-snap/" }
                (tr(lang, " tree.", " дерево."))
            }
            li {
                b { (tr(lang, "On the new host: restore inv.db + start the daemon", "На новом хосте: восстанови inv.db + запусти демон")) }
                " — "
                (tr(lang, "install the new vpnctld binary (built from git, glibc-2.36-compatible), then ", "поставь свежий vpnctld binary (собранный из git, glibc-2.36-совместимый), затем "))
                span.ed-mono { "vpnctl restore /path/to/inv.db" }
                (tr(lang, ". This is the one CLI-only exception even on a HEALTHY host (daemon can't replace its own open DB); on a recovery host the daemon doesn't even exist yet. Copy env + assets + deploy key into place; ", ". Это один CLI-only шаг даже на ЗДОРОВОМ хосте (демон не может заменить свою же открытую БД); на recovery-хосте демона ещё нет. Скопируй env + assets + deploy-ключ на места; "))
                span.ed-mono { "systemctl restart vpnctld" }
                "."
            }
            li {
                b { (tr(lang, "Verify + push deploy key", "Проверь + push deploy-ключ")) }
                " — "
                (tr(lang, "click ", "кликни "))
                a href="/admin/backup/self-test" style="color: var(--ink);" { (tr(lang, "run self-test", "run self-test")) }
                (tr(lang, " on the restored daemon, then for each server in ", " на восстановленном демоне, потом для каждого сервера в "))
                a href="/admin/servers" style="color: var(--ink);" { (tr(lang, "/admin/servers", "/admin/servers")) }
                (tr(lang, " click «push deploy key» so the daemon re-authorises itself on every VPN node. ", " кликни «push deploy key» чтобы демон переавторизовался на каждой VPN-ноде. "))
                (tr(lang, "Existing client URIs continue to work byte-stable — verified by ", "Существующие client URI продолжают работать байт-стабильно — проверено через "))
                span.ed-mono { "restore_e2e" }
                (tr(lang, " test on every commit.", " тест на каждый коммит."))
            }
        }
    }
}

/// Phase 3c — the «update now» button hits
/// `/admin/settings/geoip/update-now` (SSE source). The button
/// flips into a live log pane that streams stdout/stderr from the
/// `vpnctl geoip-update` subprocess until the terminal Ok/Error
/// event closes the connection.
fn settings_geoip_section(lang: crate::i18n::Locale) -> Markup {
    use crate::i18n::tr;
    let dir = std::env::var_os("VPNCTLD_GEOIP_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("/var/lib/vpnctl/geoip"));
    let city = dir.join("GeoLite2-City.mmdb");
    let asn = dir.join("GeoLite2-ASN.mmdb");
    let describe = |p: &std::path::Path| -> Option<(u64, String)> {
        let meta = std::fs::metadata(p).ok()?;
        let size = meta.len();
        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| {
                chrono::DateTime::<chrono::Utc>::from_timestamp(d.as_secs() as i64, 0)
                    .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                    .unwrap_or_else(|| "?".to_string())
            })
            .unwrap_or_else(|| "?".to_string());
        Some((size, mtime))
    };
    let city_meta = describe(&city);
    let asn_meta = describe(&asn);
    let any_loaded = city_meta.is_some() || asn_meta.is_some();
    maud::html! {
        div.ed-art-eyebrow {
            (tr(lang, "GeoIP — IP enrichment", "GeoIP — обогащение IP-адресов"))
        }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
            (tr(
                lang,
                "When the DB-IP Lite (or MaxMind GeoLite2) MMDB files are present in this dir, every new sub_access_log row is enriched with country ISO + ASN before being persisted. Old rows + dimensions the DB doesn't recognise stay NULL — render falls back to bare IP. The DBs are queried OFFLINE — no network requests during request handling.",
                "Когда в этой папке лежат файлы DB-IP Lite (или MaxMind GeoLite2) в формате MMDB, каждая новая строка sub_access_log обогащается ISO-кодом страны + ASN перед сохранением. Старые строки и dimensions, которые DB не распознала, остаются NULL — рендер откатывается к голому IP. БД читаются ОФФЛАЙН — никаких сетевых запросов на пути запроса.",
            ))
        }
        div style="font-family: var(--mono); font-size: 12px; padding: 8px 12px; background: var(--paper-tint); border: 1px solid var(--rule); margin-bottom: 12px;" {
            div { (tr(lang, "dir   ", "папка ")) (dir.display()) }
            div {
                "City  "
                @match &city_meta {
                    Some((size, mtime)) => {
                        b style="color: var(--soft);" {
                            (tr(lang, "present", "загружен"))
                        }
                        " · " (size) " " (tr(lang, "bytes", "байт"))
                        " · " (tr(lang, "modified ", "изменён "))
                        (mtime)
                    }
                    None => {
                        em style="color: var(--mute);" {
                            (tr(lang, "(missing — run `vpnctl geoip-update`)", "(отсутствует — запусти `vpnctl geoip-update`)"))
                        }
                    }
                }
            }
            div {
                "ASN   "
                @match &asn_meta {
                    Some((size, mtime)) => {
                        b style="color: var(--soft);" {
                            (tr(lang, "present", "загружен"))
                        }
                        " · " (size) " " (tr(lang, "bytes", "байт"))
                        " · " (tr(lang, "modified ", "изменён "))
                        (mtime)
                    }
                    None => {
                        em style="color: var(--mute);" {
                            (tr(lang, "(missing — run `vpnctl geoip-update`)", "(отсутствует — запусти `vpnctl geoip-update`)"))
                        }
                    }
                }
            }
        }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
            @if any_loaded {
                (tr(
                    lang,
                    "Update once a month with ",
                    "Обновлять раз в месяц через ",
                ))
            } @else {
                (tr(
                    lang,
                    "Drop fresh MMDB files into the dir + restart the daemon, or run ",
                    "Положи свежие MMDB-файлы в папку + перезапусти демон, либо запусти ",
                ))
            }
            span.ed-mono { "vpnctl geoip-update" }
            (tr(
                lang,
                " on the daemon host. The command downloads DB-IP Lite (CC-BY 4.0, no signup) and atomic-renames the .mmdb files into this dir. Restart vpnctld for the new DB to load.",
                " на хосте демона. Команда скачивает DB-IP Lite (CC-BY 4.0, без регистрации) и атомарно подменяет .mmdb-файлы в этой папке. Перезапусти vpnctld чтобы новая БД загрузилась.",
            ))
        }
        // ── «update now» button (Phase 3c) ─────────────────────────
        // Operator clicks → button replaces itself with a live log
        // pane streaming from /admin/settings/geoip/update-now.
        // Inline vanilla JS — no framework dep. Idempotent (clicking
        // twice spawns two subprocesses; the later atomic-rename
        // wins, harmless). Subprocess is the same `vpnctl
        // geoip-update` that the monthly systemd timer fires.
        div style="margin: 14px 0;" {
            button id="geoip-update-now-btn"
                   type="button"
                   onclick="vpnctlGeoipUpdateNow()"
                   style="font-family: var(--mono); font-size: 12px; padding: 6px 14px; border: 1px solid var(--rule); background: var(--paper); color: var(--ink); cursor: pointer;"
                   title=(tr(
                       lang,
                       "Spawn the `vpnctl geoip-update` subprocess on the daemon host and stream its progress here. Same action the monthly systemd timer fires.",
                       "Запустить `vpnctl geoip-update` на хосте демона и показать прогресс здесь. То же действие, что и ежемесячный systemd timer.",
                   )) {
                (tr(lang, "update now", "обновить сейчас"))
            }
            (maud::PreEscaped(format!(r#"
<pre id="geoip-update-now-log"
     style="display:none; margin: 10px 0 0; padding: 8px 12px; background: var(--paper-tint); border: 1px solid var(--rule); font-family: var(--mono); font-size: 11px; max-height: 320px; overflow-y: auto; white-space: pre-wrap;"></pre>
<script>
function vpnctlGeoipUpdateNow() {{
  var btn = document.getElementById('geoip-update-now-btn');
  var log = document.getElementById('geoip-update-now-log');
  btn.disabled = true;
  btn.textContent = {running_label};
  log.style.display = 'block';
  log.textContent = '';
  var es = new EventSource('/admin/settings/geoip/update-now');
  function append(line, color) {{
    var span = document.createElement('span');
    if (color) {{ span.style.color = color; }}
    span.textContent = line + '\n';
    log.appendChild(span);
    log.scrollTop = log.scrollHeight;
  }}
  es.addEventListener('step', function(e) {{
    try {{
      var d = JSON.parse(e.data);
      var color = (d.stream === 'stderr') ? 'var(--acc, #c14)' : null;
      append(d.message, color);
    }} catch (err) {{ append('[parse error] ' + e.data, 'var(--acc, #c14)'); }}
  }});
  es.addEventListener('ok', function(e) {{
    try {{ var d = JSON.parse(e.data); append('✓ ' + d.message, 'var(--acc-good, #2c5f2d)'); }}
    catch (err) {{ append('✓ done', 'var(--acc-good, #2c5f2d)'); }}
    es.close();
    btn.disabled = false;
    btn.textContent = {done_label};
  }});
  es.addEventListener('error', function(e) {{
    try {{ var d = JSON.parse(e.data); append('✗ ' + d.message, 'var(--acc, #c14)'); }}
    catch (err) {{ append('✗ stream error', 'var(--acc, #c14)'); }}
    es.close();
    btn.disabled = false;
    btn.textContent = {retry_label};
  }});
  es.onerror = function() {{
    // Transport-level error (network, server crash). The named-event
    // 'error' handler above also fires on terminal errors emitted by
    // the runner — onerror catches the connection-level cases.
    es.close();
    if (!btn.disabled) {{ return; }}
    append('✗ ' + {transport_err_label}, 'var(--acc, #c14)');
    btn.disabled = false;
    btn.textContent = {retry_label};
  }};
}}
</script>"#,
                running_label = json_for_script(tr(lang, "running…", "запущено…")),
                done_label = json_for_script(tr(lang, "update now", "обновить сейчас")),
                retry_label = json_for_script(tr(lang, "retry", "повторить")),
                transport_err_label = json_for_script(tr(lang, "connection lost", "соединение потеряно")),
            )))
        }
    }
}

pub(crate) async fn settings(headers: HeaderMap, State(state): State<AppState>) -> Markup {
    let (theme, accent, lang) = theme_accent_lang(&headers);
    // Auto-generated by vpnctld on startup (see
    // `crate::app::DEFAULT_DEPLOY_KEY_PATH` + `ensure_deploy_key`).
    // Surfaces the public half for diagnostic / out-of-inventory
    // paste. In-inventory servers should use the «push deploy key»
    // button on the server-detail page — the daemon handles SSH
    // itself, no manual editing required.
    let deploy_key_path = std::path::Path::new(crate::app::DEFAULT_DEPLOY_KEY_PATH);
    let deploy_pubkey =
        crate::ssh_subprocess::read_public_key(deploy_key_path).map_err(|e| e.to_string());

    // Phase C-4 — inventory snapshots. Reads the canonical backup
    // dir (same path the scheduler writes to). Listing failure is
    // shown inline rather than 500-ing — the rest of Settings
    // (theme, deploy key) should still render.
    let backup_dir = std::path::PathBuf::from(crate::app::DEFAULT_BACKUP_DIR);
    let snapshots = vpnctl_inventory::list_snapshots(&backup_dir).map_err(|e| e.to_string());

    // Phase 5e — Disaster recovery section pulls the LATEST
    // `backup.self_test` audit row to show last drill result inline.
    // No new schema: every backup_self_test handler call writes an
    // audit row with the overall status + duration in its payload.
    // Filter in-memory (50 rows ≪ 1ms) rather than adding a
    // per-action SQL helper for one use site.
    let last_self_test = state
        .inv
        .recent_audit(50)
        .await
        .ok()
        .and_then(|rows| rows.into_iter().find(|e| e.action == "backup.self_test"));

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
        div.ed-art-eyebrow { (crate::i18n::t(lang, crate::i18n::K::PageSettings)) }
        h1.ed-art-h1 {
            (crate::i18n::tr(lang, "homelab ", "homelab "))
            em { (crate::i18n::tr(lang, "controls", "управление")) }
        }
        p.ed-art-deck {
            (crate::i18n::tr(
                lang,
                "Daemon-wide knobs live here. Server / user mutations live on their respective pages.",
                "Здесь лежат настройки уровня всего демона. Изменения серверов / пользователей — на их собственных страницах.",
            ))
        }

        div.ed-rule {}
        div.ed-art-eyebrow { (crate::i18n::tr(lang, "Appearance — theme + accent", "Внешний вид — тема + акцент")) }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 12px;" {
            (crate::i18n::tr(
                lang,
                "Pick a paper theme (background palette) and an accent colour. Choices are stored as cookies; one-time configuration.",
                "Выбери бумажную тему (фон) и акцентный цвет. Сохраняется в cookies; настраивается один раз.",
            ))
        }
        (tweaks_inline(&theme, &accent))

        div.ed-rule {}
        div #backups-section.ed-art-eyebrow {
            (crate::i18n::tr(lang, "Backups — inventory snapshots", "Бэкапы — снэпшоты инвентаря"))
        }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
            (crate::i18n::tr(lang, "vpnctld snapshots ", "vpnctld делает снэпшоты "))
            span.ed-mono { (crate::app::DEFAULT_DEPLOY_KEY_PATH.replace("/.ssh/id_ed25519", "/inv.db")) }
            (crate::i18n::tr(lang, " hourly into ", " ежечасно в "))
            span.ed-mono { (crate::app::DEFAULT_BACKUP_DIR) }
            (crate::i18n::tr(
                lang,
                " (24 hourly + 30 daily + 12 monthly retained). ",
                " (хранятся 24 часовых + 30 дневных + 12 месячных). ",
            ))
            b { (crate::i18n::tr(lang, "Off-site is operator-driven", "Off-site копии делает оператор")) }
            (crate::i18n::tr(lang, " — click ", " — кликни "))
            em { (crate::i18n::tr(lang, "download", "скачать")) }
            (crate::i18n::tr(
                lang,
                " next to a snapshot and copy it to USB / Forgejo / cloud / wherever you trust. The daemon never pushes anywhere by itself.",
                " рядом со снэпшотом и скопируй на USB / Forgejo / облако / куда доверяешь. Демон сам никуда не пушит.",
            ))
        }
        div style="display: flex; gap: 12px; align-items: center; margin-bottom: 14px; flex-wrap: wrap;" {
            form method="post" action="/admin/backup/snapshot" style="display: inline;" {
                button type="submit"
                       title=(crate::i18n::tr(
                           lang,
                           "Take a snapshot now (in addition to the hourly schedule). Safe to click any time.",
                           "Сделать снэпшот сейчас (вдобавок к часовому расписанию). Безопасно нажимать в любой момент.",
                       ))
                       style="padding: 6px 14px; border: 1px solid var(--ink); background: var(--ink); color: var(--paper); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                    (crate::i18n::tr(lang, "snapshot now", "снэпшот сейчас"))
                }
            }
            // Phase 5c — restore self-test button. Operator clicks →
            // verify_snapshot runs against the latest snapshot in a
            // tempdir → /admin/backup/self-test renders a pass/fail
            // HTML report (no SSE — completes in <1s for our DB size).
            form method="post" action="/admin/backup/self-test" style="display: inline;" {
                button type="submit"
                       title=(crate::i18n::tr(
                           lang,
                           "Run restore fire-drill against the latest snapshot — does it actually restore into a usable DB? Safe to click any time; does NOT touch live inv.db.",
                           "Запустить проверку восстановления на последнем снэпшоте — реально ли он восстанавливается в рабочую БД? Безопасно нажимать в любой момент; живую inv.db не трогает.",
                       ))
                       style="padding: 6px 14px; border: 1px solid var(--ink); background: var(--paper); color: var(--ink); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                    (crate::i18n::tr(lang, "run restore self-test", "проверить восстановление"))
                }
            }
            span style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute);" {
                (crate::i18n::tr(lang, "Restore-in-place is a ", "Восстановление поверх живой БД — это команда "))
                span.ed-mono { "vpnctl restore <snapshot>" }
                (crate::i18n::tr(
                    lang,
                    " CLI command (daemon can't replace its own open DB). The self-test above proves the snapshot WOULD restore, without touching the live DB.",
                    " в CLI (демон не может заменить свою же открытую БД). Self-test выше доказывает что снэпшот ВОССТАНОВИТСЯ, не трогая живую БД.",
                ))
            }
        }
        @match snapshots {
            Ok(list) if list.is_empty() => {
                p style="font-family: var(--serif); font-style: italic; color: var(--mute); font-size: 12px;" {
                    (crate::i18n::tr(
                        lang,
                        "No snapshots yet. The scheduler fires its first snapshot ~60 seconds after daemon start; click ",
                        "Снэпшотов пока нет. Шедулер делает первый ~60 секунд после старта демона; кликни ",
                    ))
                    b { (crate::i18n::tr(lang, "snapshot now", "снэпшот сейчас")) }
                    (crate::i18n::tr(lang, " above to skip the wait.", " выше чтобы не ждать."))
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
                                th style="text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--rule); color: var(--mute); font-weight: normal; letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                                    (crate::i18n::tr(lang, "created (UTC)", "создан (UTC)"))
                                }
                                th style="text-align: right; padding: 6px 8px; border-bottom: 1px solid var(--rule); color: var(--mute); font-weight: normal; letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                                    (crate::i18n::tr(lang, "size", "размер"))
                                }
                                th style="text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--rule); color: var(--mute); font-weight: normal; letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                                    (crate::i18n::tr(lang, "action", "действие"))
                                }
                            }
                        }
                        tbody {
                            @for snap in list.iter().take(60) {
                                tr {
                                    td style="padding: 4px 8px; border-bottom: 1px dotted var(--rule);" {
                                        (snap.created.as_deref().unwrap_or_else(|| crate::i18n::tr(lang, "(unparseable timestamp)", "(не разобран timestamp)")))
                                    }
                                    td style="padding: 4px 8px; border-bottom: 1px dotted var(--rule); text-align: right; color: var(--soft);" {
                                        (format_size_bytes(snap.size_bytes))
                                    }
                                    td style="padding: 4px 8px; border-bottom: 1px dotted var(--rule);" {
                                        a href=(format!("/admin/backup/download/{}", path_segment_encode(&snap.file_name)))
                                          download=(&snap.file_name)
                                          title=(crate::i18n::tr(
                                              lang,
                                              "Save this snapshot to your local disk for off-site storage",
                                              "Скачать этот снэпшот на локальный диск для off-site хранения",
                                          ))
                                          style="color: var(--ink); text-decoration: underline;" {
                                            (crate::i18n::tr(lang, "download", "скачать"))
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                @if list.len() > 60 {
                    p style="font-family: var(--serif); font-style: italic; color: var(--mute); font-size: 11px; margin-top: 8px;" {
                        "(" (list.len() - 60)
                        @if list.len() - 60 != 1 {
                            (crate::i18n::tr(lang, " older snapshots hidden", " более старых снэпшотов скрыто"))
                        } @else {
                            (crate::i18n::tr(lang, " older snapshot hidden", " более старый снэпшот скрыт"))
                        }
                        (crate::i18n::tr(
                            lang,
                            " — the retention policy caps total count, so the table won't grow unbounded.)",
                            " — политика хранения ограничивает количество, таблица не растёт бесконечно.)",
                        ))
                    }
                }
            }
            Err(e) => {
                p style="font-family: var(--serif); font-style: italic; color: var(--red); font-size: 12px;" {
                    (crate::i18n::tr(lang, "Can't list snapshots in ", "Не удалось перечислить снэпшоты в "))
                    span.ed-mono { (crate::app::DEFAULT_BACKUP_DIR) }
                    ": " (e)
                    (crate::i18n::tr(
                        lang,
                        ". Most likely the daemon user doesn't have access — check ",
                        ". Скорее всего у пользователя демона нет доступа — проверь ",
                    ))
                    span.ed-mono { "ls -la /var/lib/vpnctl/" }
                    "."
                }
            }
        }

        (settings_disaster_recovery_section(lang, last_self_test.as_ref()))

        div.ed-rule {}
        // `id` so the POST-redirect-GET after Save can use a
        // fragment anchor (`#telegram-notifications`) and the
        // browser scrolls back to this section instead of jumping
        // to the top of /admin/settings.
        div #telegram-notifications.ed-art-eyebrow {
            (crate::i18n::tr(
                lang,
                "Notifications — Telegram bot",
                "Уведомления — Telegram-бот",
            ))
        }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
            (crate::i18n::tr(
                lang,
                "When an alert fires (probe-detector or service flip), vpnctld POSTs a one-line message to a Telegram chat via ",
                "Когда срабатывает алерт (probe-detector или поднятие/падение сервиса), vpnctld POST-ит однострочное сообщение в Telegram-чат через ",
            ))
            span.ed-mono { "api.telegram.org/bot<token>/sendMessage" }
            (crate::i18n::tr(
                lang,
                ". One operator, one chat — paste the bot token and your numeric chat-id below. Create the bot via ",
                ". Один оператор, один чат — вставь bot-токен и свой числовой chat-id ниже. Создай бота через ",
            ))
            span.ed-mono { "@BotFather" }
            (crate::i18n::tr(lang, " on Telegram; get your chat-id by messaging ", " в Telegram; узнай свой chat-id написав "))
            span.ed-mono { "@userinfobot" }
            ". "
            b { (crate::i18n::tr(lang, "The token is a secret", "Токен — секрет")) }
            (crate::i18n::tr(lang, " — stored in ", " — хранится в "))
            span.ed-mono { "/var/lib/vpnctl/inv.db" }
            (crate::i18n::tr(
                lang,
                " (daemon-owned 0640), masked in this page after save. Clear both fields and re-save to disable.",
                " (демон-only 0640), маскируется на этой странице после сохранения. Очисти оба поля и сохрани снова чтобы отключить.",
            ))
        }

        // Status line — tells the operator at a glance whether the
        // transport is wired. Three branches: config read failed,
        // both fields set ("enabled"), or partial/none ("disabled").
        @match &telegram_cfg {
            Err(e) => {
                p style="font-family: var(--serif); font-style: italic; color: var(--red); font-size: 12px;" {
                    (crate::i18n::tr(lang, "Can't read notification settings: ", "Не удалось прочитать настройки уведомлений: ")) (e)
                }
            }
            Ok(None) => {
                p style="font-family: var(--serif); font-style: italic; color: var(--red); font-size: 12px;" {
                    (crate::i18n::tr(
                        lang,
                        "Settings row missing — migration 0014 didn't seed it. Daemon restart should re-run migrations.",
                        "Строка settings отсутствует — миграция 0014 не записала её. Перезапуск демона прогонит миграции заново.",
                    ))
                }
            }
            Ok(Some(cfg)) if cfg.is_enabled() => {
                p style="font-family: var(--mono); font-size: 12px; color: var(--ink); margin: 0 0 10px;" {
                    (crate::i18n::tr(lang, "Status: ", "Статус: ")) b { (crate::i18n::tr(lang, "enabled", "включено")) }
                    (crate::i18n::tr(lang, " · token ", " · токен "))
                    span style="color: var(--mute);" { "••••" (cfg.token_last4()) }
                    (crate::i18n::tr(lang, " · chat ", " · чат "))
                    span style="color: var(--mute);" { (cfg.chat_id.as_deref().unwrap_or("")) }
                }
            }
            Ok(Some(cfg)) if cfg.token.is_some() || cfg.chat_id.is_some() => {
                @let which_missing = if cfg.token.is_none() {
                    crate::i18n::tr(lang, "bot token", "bot-токен")
                } else {
                    crate::i18n::tr(lang, "chat-id", "chat-id")
                };
                p style="font-family: var(--mono); font-size: 12px; color: var(--red); margin: 0 0 10px;" {
                    (crate::i18n::tr(lang, "Status: ", "Статус: ")) b { (crate::i18n::tr(lang, "partial config", "конфиг неполный")) }
                    " — " (which_missing)
                    (crate::i18n::tr(
                        lang,
                        " missing, transport effectively disabled. Fill in the missing field below + save, OR clear both fields to fully reset.",
                        " отсутствует, транспорт фактически выключен. Заполни недостающее поле ниже + сохрани, ЛИБО очисти оба чтобы сбросить.",
                    ))
                }
            }
            Ok(Some(_)) => {
                p style="font-family: var(--mono); font-size: 12px; color: var(--mute); margin: 0 0 10px;" {
                    (crate::i18n::tr(lang, "Status: ", "Статус: "))
                    b style="color: var(--ink);" { (crate::i18n::tr(lang, "disabled", "выключено")) }
                    (crate::i18n::tr(lang, " — fill in both fields below + save.", " — заполни оба поля ниже + сохрани."))
                }
            }
        }

        form method="post" action="/admin/settings/telegram" style="margin: 0 0 14px;" {
            div style="display: grid; grid-template-columns: 140px 1fr; gap: 10px 14px; align-items: center; max-width: 720px;" {
                label for="telegram_bot_token" style="font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                    (crate::i18n::tr(lang, "bot token", "bot-токен"))
                }
                input type="password"
                      id="telegram_bot_token"
                      name="telegram_bot_token"
                      placeholder=(crate::i18n::tr(
                          lang,
                          "leave blank to keep existing; paste new value to replace; clear BOTH fields to disable",
                          "пусто = оставить как есть; новое значение = заменить; ОЧИСТИТЬ ОБА поля = выключить",
                      ))
                      autocomplete="off"
                      title=(crate::i18n::tr(
                          lang,
                          "Token from @BotFather, shape `123456:ABC-XYZ...`. Stored in inv.db, masked after save. Empty + empty chat-id disables the Telegram sink entirely.",
                          "Токен от @BotFather, форма `123456:ABC-XYZ...`. Хранится в inv.db, маскируется после сохранения. Пустой токен + пустой chat-id = полное отключение Telegram.",
                      ))
                      style="font-family: var(--mono); font-size: 12px; padding: 5px 8px; border: 1px solid var(--rule); background: var(--paper);";
                label for="telegram_chat_id" style="font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                    (crate::i18n::tr(lang, "chat-id", "chat-id"))
                }
                input type="text"
                      id="telegram_chat_id"
                      name="telegram_chat_id"
                      value=(match &telegram_cfg {
                          Ok(Some(cfg)) => cfg.chat_id.as_deref().unwrap_or(""),
                          _ => "",
                      })
                      placeholder=(crate::i18n::tr(
                          lang,
                          "numeric, e.g. 123456789 (or @your_channel)",
                          "число, напр. 123456789 (или @your_channel)",
                      ))
                      title=(crate::i18n::tr(
                          lang,
                          "Numeric user/group id from @userinfobot OR a public @channel handle. Test-send button below checks this end-to-end.",
                          "Числовой user/group id от @userinfobot ИЛИ публичный @channel-хэндл. Кнопка тестового сообщения ниже проверяет всю цепочку.",
                      ))
                      style="font-family: var(--mono); font-size: 12px; padding: 5px 8px; border: 1px solid var(--rule); background: var(--paper);";

                label for="proxy_via_server_id" style="font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                    (crate::i18n::tr(lang, "egress", "выход"))
                }
                @let current_proxy_id: &str = match &telegram_cfg {
                    Ok(Some(cfg)) => cfg.proxy_via_server_id.as_deref().unwrap_or(""),
                    _ => "",
                };
                select name="proxy_via_server_id"
                       id="proxy_via_server_id"
                       title=(crate::i18n::tr(
                           lang,
                           "If the daemon host can't reach api.telegram.org directly (РФ blocks, NAT, etc), route the call through an inventory server's network instead. Uses the existing deploy SSH key — the public half must be on root@<proxy-server>:~/.ssh/authorized_keys (see «Deploy SSH key» section below to copy).",
                           "Если хост демона не может достучаться до api.telegram.org напрямую (блоки РФ, NAT и т.п.), направь вызов через сеть одного из серверов инвентаря. Использует существующий deploy SSH-ключ — его публичная половина должна быть на root@<proxy-server>:~/.ssh/authorized_keys (см. секцию «Deploy SSH key» ниже).",
                       ))
                       style="font-family: var(--mono); font-size: 12px; padding: 5px 8px; border: 1px solid var(--rule); background: var(--paper);" {
                    option value="" selected[current_proxy_id.is_empty()] {
                        (crate::i18n::tr(lang, "direct (local network)", "напрямую (локальная сеть)"))
                    }
                    @for s in &servers_for_proxy_dropdown {
                        option value=(s.id.0) selected[current_proxy_id == s.id.0] {
                            (crate::i18n::tr(lang, "via server: ", "через сервер: ")) (s.id.0) " (" (s.address) ")"
                        }
                    }
                }
            }

            @if servers_for_proxy_dropdown.is_empty() {
                p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 8px 0 0; max-width: 720px;" {
                    (crate::i18n::tr(lang, "No servers in inventory yet — only ", "Серверов в инвентаре пока нет — доступен только "))
                    b { (crate::i18n::tr(lang, "direct", "напрямую")) }
                    (crate::i18n::tr(lang, " egress is available. Add a server on ", " выход. Добавь сервер на "))
                    span.ed-mono { "/admin/servers" }
                    (crate::i18n::tr(lang, " first if your daemon host can't reach ", " если хост демона не достучивается до "))
                    span.ed-mono { "api.telegram.org" } "."
                }
            } @else {
                p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 8px 0 0; max-width: 720px;" {
                    (crate::i18n::tr(lang, "Picking a ", "Выбор опции "))
                    b { (crate::i18n::tr(lang, "via server: …", "через сервер: …")) }
                    (crate::i18n::tr(
                        lang,
                        " option requires the daemon's deploy SSH pubkey to be on that server's ",
                        " требует чтобы deploy SSH публичный ключ демона был в ",
                    ))
                    span.ed-mono { "~/.ssh/authorized_keys" }
                    (crate::i18n::tr(lang, ". The pubkey lives in the ", " этого сервера. Pubkey лежит в секции "))
                    a href="#deploy-ssh-key" style="color: var(--ink);" {
                        b { (crate::i18n::tr(lang, "Deploy SSH key", "Deploy SSH-ключ")) }
                    }
                    (crate::i18n::tr(
                        lang,
                        " section below — copy it once, then ",
                        " ниже — скопируй один раз, затем ",
                    ))
                    em { (crate::i18n::tr(lang, "send test message", "отправить тестовое сообщение")) }
                    (crate::i18n::tr(lang, " confirms the path works.", " подтвердит что путь работает."))
                }
            }

            div style="margin-top: 12px;" {
                button type="submit"
                       title=(crate::i18n::tr(
                           lang,
                           "Save all three fields. Empty token = keep existing (unless chat-id is ALSO empty, then clear). Empty chat-id = clear. Egress dropdown is always overwritten with the selected value.",
                           "Сохранить все три поля. Пустой токен = оставить как есть (если chat-id ТОЖЕ пуст, тогда очистить). Пустой chat-id = очистить. Egress dropdown всегда переписывается выбранным значением.",
                       ))
                       style="padding: 6px 14px; border: 1px solid var(--ink); background: var(--ink); color: var(--paper); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                    (crate::i18n::t(lang, crate::i18n::K::BtnSave))
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
                           title=(crate::i18n::tr(
                               lang,
                               "Send a test message to the configured chat. Surfaces curl / Telegram-API errors inline.",
                               "Отправить тестовое сообщение в настроенный чат. Ошибки curl / Telegram-API показываются прямо здесь.",
                           ))
                           style="padding: 5px 12px; border: 1px solid var(--rule); background: var(--paper); color: var(--ink); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                        (crate::i18n::tr(lang, "send test message", "отправить тестовое сообщение"))
                    }
                    span style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin-left: 14px;" {
                        (crate::i18n::tr(
                            lang,
                            "Posts «🔵 vpnctld · info · test · vpnctld test message ...» to your chat.",
                            "Пошлёт «🔵 vpnctld · info · test · vpnctld test message ...» в твой чат.",
                        ))
                    }
                }
            }
            _ => {
                p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 10px 0 0;" {
                    (crate::i18n::tr(
                        lang,
                        "Test-send button appears after both fields are saved + status is ",
                        "Кнопка тестового сообщения появится после сохранения обоих полей и когда статус ",
                    ))
                    b style="color: var(--ink);" { (crate::i18n::tr(lang, "enabled", "включено")) } "."
                }
            }
        }

        div.ed-rule {}
        (settings_geoip_section(lang))

        div.ed-rule {}
        div #deploy-ssh-key.ed-art-eyebrow {
            (crate::i18n::tr(lang, "Deploy SSH key", "Deploy SSH-ключ"))
        }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
            (crate::i18n::tr(
                lang,
                "vpnctld auto-generated this Curve25519 keypair on first start. The private half stays in ",
                "vpnctld сгенерировал эту Curve25519-пару при первом старте. Приватная половина остаётся в ",
            ))
            span.ed-mono { (crate::app::DEFAULT_DEPLOY_KEY_PATH) }
            (crate::i18n::tr(
                lang,
                " — never shown. The public half (below) goes into each VPN node's ",
                " — никогда не показывается. Публичная половина (ниже) идёт в ",
            ))
            span.ed-mono { "~/.ssh/authorized_keys" }
            (crate::i18n::tr(lang, ". Once authorised, every ", " каждой VPN-ноды. Когда авторизован, каждый клик "))
            b { (crate::i18n::tr(lang, "deploy →", "деплой →")) }
            (crate::i18n::tr(
                lang,
                " button click pushes configs through vpnctld → ssh subprocess → node, no operator-typed CLI needed.",
                " пушит конфиги по пути vpnctld → ssh-подпроцесс → нода, без ручных CLI-команд оператора.",
            ))
        }
        @match deploy_pubkey {
            Ok(pk) => {
                pre style="font-family: var(--mono); font-size: 11px; padding: 12px 14px; background: var(--paper); border: 1px solid var(--rule); white-space: pre-wrap; word-break: break-all;" {
                    (pk)
                }
                p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 8px 0 0;" {
                    (crate::i18n::tr(lang, "Authorise this key on a server via the ", "Авторизуй этот ключ на сервере через "))
                    a href="/admin/servers" style="color: var(--ink);" {
                        b { "/admin/servers" }
                    }
                    (crate::i18n::tr(lang, " list → pick a server → ", " → выбрать сервер → "))
                    span.ed-mono { (crate::i18n::tr(lang, "«Deploy SSH key — push to this server»", "«Deploy SSH key — push to this server»")) }
                    (crate::i18n::tr(lang, " section → ", " секция → "))
                    span.ed-mono { (crate::i18n::tr(lang, "«push deploy key»", "«push deploy key»")) }
                    (crate::i18n::tr(
                        lang,
                        " button. The daemon handles the SSH dance for you — no manual ",
                        " кнопка. Демон делает SSH-танец сам — без ручного ",
                    ))
                    span.ed-mono { "ssh root@…" }
                    (crate::i18n::tr(lang, " or ", " или редактирования "))
                    span.ed-mono { "authorized_keys" }
                    (crate::i18n::tr(
                        lang,
                        " editing. The pubkey above is shown for diagnostic / out-of-band-paste use only (e.g. you want to authorise the key on something that ISN'T in vpnctl's inventory).",
                        " вручную. Pubkey выше показан только для диагностики / out-of-band вставки (например если ты хочешь авторизовать ключ на чём-то ВНЕ инвентаря vpnctl).",
                    ))
                }
            }
            Err(e) => {
                p style="font-family: var(--serif); font-style: italic; color: var(--red);" {
                    (crate::i18n::tr(lang, "Public key file unreadable: ", "Публичный ключ не читается: ")) (e)
                    (crate::i18n::tr(lang, ". Most common cause: ", ". Чаще всего: "))
                    span.ed-mono { "/var/lib/vpnctl/.ssh" }
                    (crate::i18n::tr(lang, " not writable by the daemon. Check ", " недоступен на запись демону. Проверь "))
                    span.ed-mono { "ls -la /var/lib/vpnctl/" }
                    (crate::i18n::tr(
                        lang,
                        "; vpnctld writes there as the systemd-unit user (typically ",
                        "; vpnctld пишет туда из-под пользователя systemd-юнита (обычно ",
                    ))
                    span.ed-mono { "user" } ")."
                }
            }
        }
    };
    shell("settings", &theme, &accent, lang, body)
}

/// `POST /admin/servers/{id}/push-deploy-key` — append the daemon's
/// deploy pubkey to the server's `~/.ssh/authorized_keys`. Recovery
/// action for servers added via quick-add / migrate-from-bash
/// (Phase E wizard does this automatically as step 3 of bootstrap).
///
/// ## Two egress paths, tried in order
///
/// 1. **Reference SSH key** (preferred) — if `VPNCTLD_REFERENCE_SSH_KEY`
///    env var points at a readable private key on the daemon host AND
///    `root_password` is left empty, the handler uses that key
///    (assumed pre-authorised on every inventory server, e.g. the
///    operator's existing `~/.ssh/id_ed25519`) for a silent push. This
///    matches Pavel's «if I added the server, the daemon should have
///    all the access» expectation: configure the env var ONCE, all
///    subsequent push-deploy-key clicks are no-input.
/// 2. **Root password via sshpass** — fallback when reference key
///    isn't set / isn't readable / didn't work. Operator-typed
///    password → SSHPASS env var of the sshpass child process →
///    never in argv (`ps auxe` from non-root can't see it). After
///    the SSH call returns, the password lives only on this handler's
///    stack; not stored, not logged, not in the audit payload.
///
/// Server-side command is byte-identical to the wizard's step 3
/// (push-key) and idempotent (`grep -qxF || echo >>`) — a successful
/// click followed by an accidental second click is a no-op.
///
/// **Audit row** written on both success + failure (operator action
/// either way). Payload: `{success: bool, method: "reference-key" | "sshpass", error?: str}`
/// — never the password.
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

    // ─── Credentials gate (BEFORE expensive pubkey read) ─────────
    // 400 ASAP if operator gave neither a password nor a usable
    // reference key on the daemon host — otherwise a missing
    // deploy-pubkey file (read step below) would surface as a
    // misleading 500 hiding the real «no creds» bug.
    let reference_key_path = std::env::var("VPNCTLD_REFERENCE_SSH_KEY").ok();
    let try_reference = password.is_empty()
        && reference_key_path
            .as_ref()
            .is_some_and(|p| !p.is_empty() && std::path::Path::new(p).exists());
    if password.is_empty() && !try_reference {
        return bad_request(
            "root_password is required (or set VPNCTLD_REFERENCE_SSH_KEY \
             on the daemon host to use a pre-authorised key instead)",
        );
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

    if let Some(ref_key) = reference_key_path.clone().filter(|_| try_reference) {
        let ssh = crate::ssh_subprocess::SubprocessSshTransport::new(
            server.address.clone(),
            server.ssh_user.clone(),
            std::path::PathBuf::from(&ref_key),
        )
        .port(server.ssh_port);
        use vpnctl_core::SshTransport;
        match ssh.exec(&push_cmd).await {
            Ok(_) => {
                if let Err(audit_err) = state
                    .inv
                    .audit(
                        "admin",
                        "server.push_deploy_key",
                        Some(&server_id_str),
                        Some(&serde_json::json!({
                            "success": true,
                            "server_id": &server_id_str,
                            "method": "reference-key",
                            "reference_key_path": &ref_key,
                        })),
                    )
                    .await
                {
                    // Bug-hunt 2026-05-18 — was `let _ =`, silently
                    // losing the operator action trail. Mirror the
                    // sshpass-path warn block.
                    tracing::warn!(
                        target = "vpnctld::admin::server_push_deploy_key",
                        server = %server_id_str,
                        error = %audit_err,
                        "audit row for server.push_deploy_key (reference-key success) failed; push succeeded"
                    );
                }
                return Redirect::to(&format!(
                    "/admin/servers/{}#push-deploy-key",
                    path_segment_encode(&server_id_str)
                ))
                .into_response();
            }
            Err(e) => {
                // Reference key didn't work (likely not authorised on
                // THIS server). If a password was ALSO provided, fall
                // through to sshpass path; otherwise surface the
                // reference-key failure with a hint.
                if password.is_empty() {
                    if let Err(audit_err) = state
                        .inv
                        .audit(
                            "admin",
                            "server.push_deploy_key",
                            Some(&server_id_str),
                            Some(&serde_json::json!({
                                "success": false,
                                "server_id": &server_id_str,
                                "method": "reference-key",
                                "error": e.to_string(),
                            })),
                        )
                        .await
                    {
                        tracing::warn!(
                            target = "vpnctld::admin::server_push_deploy_key",
                            server = %server_id_str,
                            error = %audit_err,
                            "audit row for server.push_deploy_key (reference-key failure) failed"
                        );
                    }
                    return error_resp(
                        StatusCode::BAD_GATEWAY,
                        &format!(
                            "push-deploy-key via reference key ({ref_key}) failed for \
                             {server_id_str}: {e} — the reference key isn't authorised \
                             on this server. Supply the root password below to fall back \
                             to sshpass. If password auth is also disabled, the daemon \
                             can't self-recover this server — use the hoster's console \
                             to add the pubkey shown on /admin/settings."
                        ),
                    );
                }
                // password is non-empty → continue to sshpass path.
                tracing::info!(
                    target = "vpnctld::admin::server_push_deploy_key",
                    server = %server_id_str,
                    error = %e,
                    "reference key failed; falling back to sshpass"
                );
            }
        }
    }

    // ─── Path 2: sshpass + operator-typed password ────────────────
    // (Credentials gate above already ensured password is non-empty
    // when we get here — either initial state, or fall-through from
    // reference-key failure with password supplied.)

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
        Ok(_) => serde_json::json!({
            "success": true,
            "server_id": &server_id_str,
            "method": "sshpass",
        }),
        Err(e) => serde_json::json!({
            "success": false,
            "server_id": &server_id_str,
            "method": "sshpass",
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
                 common causes: wrong password; server's sshd rejected \
                 password auth (PasswordAuthentication off — daemon can't \
                 self-recover, use the hoster's console to authorise the \
                 pubkey shown on /admin/settings); server unreachable on \
                 configured port (check /admin/servers/{server_id_str})."
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
        Ok(()) => Redirect::to("/admin/settings#telegram-notifications").into_response(),
        Err(e) => {
            let raw = e.to_string();
            // Don't double up on remediation hints: `classify_ssh_failure`
            // (in alert_sink) already produces a specific message for
            // the SSH path (Permission denied / refused / timed out /
            // host-key). Appending the generic «common causes» list on
            // top of that classified message creates redundancy that
            // dilutes the actionable bit — caught by Pavel during live
            // testing 2026-05-18. Only append the generic list when
            // the failure was NOT SSH-level (curl-direct path or
            // Telegram-API-level «ok:false»).
            let msg = if raw.contains("ssh-then-curl") {
                format!("test-send failed: {e}")
            } else {
                format!(
                    "test-send failed: {e} — common causes: \
                     chat-id wrong (Telegram returns 'chat not found'), \
                     token revoked, \
                     bot never started conversation with you \
                     (open the bot in Telegram + tap Start), \
                     api.telegram.org blocked (use the «egress» dropdown \
                     on /admin/settings to route via an inventory server, \
                     or set VPNCTLD_HTTPS_PROXY env)"
                )
            };
            error_resp(StatusCode::BAD_GATEWAY, &msg)
        }
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
        // NM-12 follow-up (Pavel 2026-05-21): bilingual admin shell.
        // Operator clicks `[EN | RU]` in the masthead → POST here
        // with `value=<en|ru>` → set the cookie + 303 redirect back
        // via Referer. Same shape as theme/accent so the
        // sanitize_referer + 1-year-cookie semantic is reused.
        "lang" => set_tweak_cookie(&headers, COOKIE_LANG, VALID_LANGS, &body),
        unknown => not_found(&format!(
            "unknown tweak kind '{unknown}' (known: theme, accent, lang)"
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
    let (theme, accent, lang) = theme_accent_lang(&headers);
    use crate::i18n::tr;
    let body = html! {
        div.ed-art-eyebrow { (tr(lang, "Add server · step 1 of 3", "Добавить сервер · шаг 1 из 3")) }
        h1.ed-art-h1 {
            (tr(lang, "Paste an ", "Вставь ")) em { "IP" }
            (tr(lang, " and the ", " и ")) em { (tr(lang, "root password", "root-пароль")) }
        }
        p.ed-art-deck {
            (tr(lang, "The daemon will SSH in as ", "Демон зайдёт по SSH как ")) span.ed-mono { "root" }
            (tr(
                lang,
                ", push its key, create a non-root user, harden ",
                ", запушит свой ключ, создаст non-root пользователя, усилит ",
            ))
            span.ed-mono { "sshd_config" }
            (tr(
                lang,
                ", install fail2ban + sing-box, render the config, and prove the service is live — all on the next screen.",
                ", установит fail2ban + sing-box, отрендерит конфиг и проверит что сервис живёт — всё это на следующем экране.",
            ))
        }

        form method="post" action="/admin/servers/new"
             style="margin: 24px 0; padding: 18px 20px; border: 1px solid var(--rule); background: var(--paper); display: flex; flex-direction: column; gap: 14px;" {
            div style="display: flex; flex-direction: column; gap: 4px;" {
                label for="address"
                      style="font-family: var(--mono); font-size: 11px; color: var(--mute); letter-spacing: 0.14em; text-transform: uppercase;" {
                    (tr(lang, "address", "адрес"))
                }
                input id="address" name="address" type="text" required="required"
                      placeholder="198.51.100.42 or vpn-de1.example.org"
                      autocomplete="off" autocapitalize="none" spellcheck="false"
                      pattern="[A-Za-z0-9.:_-]+"
                      title=(tr(
                          lang,
                          "IPv4, IPv6 or hostname — no shell metacharacters",
                          "IPv4, IPv6 или хост — без shell-метасимволов",
                      ))
                      style="padding: 6px 10px; border: 1px solid var(--rule-s); background: var(--paper); font-family: var(--mono); font-size: 13px; color: var(--ink);";
                p style="font-family: var(--serif); font-style: italic; font-size: 11.5px; color: var(--mute); margin: 0;" {
                    (tr(
                        lang,
                        "DigitalOcean droplets must keep SSH on port 22 (Cloud Firewall blocks the rest); other hosters get the harden-to-2222 step automatically on the next screen.",
                        "Дроплеты DigitalOcean должны держать SSH на 22 (Cloud Firewall блокирует остальное); другие хостеры получают шаг harden-to-2222 автоматически на следующем экране.",
                    ))
                }
            }
            div style="display: flex; flex-direction: column; gap: 4px;" {
                label for="root_password"
                      style="font-family: var(--mono); font-size: 11px; color: var(--mute); letter-spacing: 0.14em; text-transform: uppercase;" {
                    (tr(lang, "root password", "root-пароль"))
                }
                input id="root_password" name="root_password" type="password" required="required"
                      autocomplete="new-password"
                      style="padding: 6px 10px; border: 1px solid var(--rule-s); background: var(--paper); font-family: var(--mono); font-size: 13px; color: var(--ink);";
                p style="font-family: var(--serif); font-style: italic; font-size: 11.5px; color: var(--mute); margin: 0;" {
                    (tr(
                        lang,
                        "Used once to push our SSH key, then password auth gets disabled. Held in daemon memory for 10 minutes; nothing is written to disk.",
                        "Используется один раз чтобы запушить наш SSH-ключ, затем password-auth отключается. Лежит в памяти демона 10 минут; на диск ничего не пишется.",
                    ))
                }
            }
            div style="display: flex; flex-direction: column; gap: 4px;" {
                label for="ssh_port"
                      style="font-family: var(--mono); font-size: 11px; color: var(--mute); letter-spacing: 0.14em; text-transform: uppercase;" {
                    (tr(lang, "ssh port (optional, default 22)", "ssh порт (опционально, по умолч. 22)"))
                }
                input id="ssh_port" name="ssh_port" type="text" inputmode="numeric"
                      placeholder="22"
                      autocomplete="off" autocapitalize="none" spellcheck="false"
                      pattern="[0-9]*"
                      title=(tr(lang, "leave blank for 22; Cloudzy ships 2222", "оставь пусто для 22; у Cloudzy — 2222"))
                      style="padding: 6px 10px; border: 1px solid var(--rule-s); background: var(--paper); font-family: var(--mono); font-size: 13px; color: var(--ink); max-width: 140px;";
                p style="font-family: var(--serif); font-style: italic; font-size: 11.5px; color: var(--mute); margin: 0;" {
                    (tr(lang, "Leave blank for 22 (the common case). Cloudzy is ", "Оставь пусто для 22 (обычный случай). Cloudzy — это "))
                    span.ed-mono { "2222" }
                    (tr(
                        lang,
                        "; check the hoster's panel if SSH connect-fails on the next screen.",
                        "; проверь панель хостера если SSH-коннект упадёт на следующем экране.",
                    ))
                }
            }
            div style="display: flex; gap: 12px; align-items: center; margin-top: 6px;" {
                button type="submit"
                       title=(tr(
                           lang,
                           "Validate inputs and continue to the bootstrap log",
                           "Проверить ввод и продолжить к bootstrap-логу",
                       ))
                       style="padding: 6px 14px; border: 1px solid var(--ink); background: var(--ink); color: var(--paper); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                    (tr(lang, "continue →", "продолжить →"))
                }
                a href="/admin/servers"
                  style="font-family: var(--mono); font-size: 11px; color: var(--mute); text-decoration: none; padding: 6px 8px;" {
                    (tr(lang, "cancel", "отмена"))
                }
            }
        }
    };
    shell("servers", &theme, &accent, lang, body)
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
    let (theme, accent, lang) = theme_accent_lang(&headers);
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
        div.ed-art-eyebrow {
            (crate::i18n::tr(lang, "Add server · step 2 of 3", "Добавить сервер · шаг 2 из 3"))
        }
        h1.ed-art-h1 {
            (crate::i18n::tr(lang, "Bootstrapping ", "Bootstrap ")) span.ed-mono { (session.address) }
        }
        p.ed-art-deck {
            (crate::i18n::tr(
                lang,
                "The daemon is SSHing in as ",
                "Демон заходит по SSH под ",
            ))
            span.ed-mono { "root" }
            (crate::i18n::tr(
                lang,
                " (one-time password use), pushing its deploy key, locking down the host, installing ",
                " (одноразовое использование пароля), закидывает deploy-ключ, hardening хоста, ставит ",
            ))
            span.ed-mono { "sing-box" }
            (crate::i18n::tr(
                lang,
                " and pushing the rendered config. Every step shows up below as it happens. Don't close this tab — refresh is fine, the bootstrap runs server-side and you'll re-attach.",
                " и пушит готовый конфиг. Каждый шаг появится ниже по мере выполнения. Не закрывай вкладку — refresh нормально, bootstrap идёт серверно и переподключишься.",
            ))
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
    shell("servers", &theme, &accent, lang, body).into_response()
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
//  Phase 3c — Settings GeoIP «update now» SSE button.
//
//  Streams the live output of `vpnctl geoip-update` as named SSE
//  events. Auth-gated by the basic-auth middleware (same as every
//  other /admin route). One audit row per fire — provenance only,
//  no payload (the subprocess output is in journalctl).
//
//  See `crate::geoip_update_runner` for the subprocess pattern.
// ────────────────────────────────────────────────────────────────────────

/// SSE source for the Settings GeoIP «update now» button. Streams
/// `/usr/local/bin/vpnctl geoip-update` stdout/stderr line-by-line
/// to the browser. Each Step event carries a `stream:"stdout"` or
/// `"stderr"` field so the front-end can colour stderr lines for
/// the operator. Final Ok/Error event closes the stream.
///
/// CSRF defense: the endpoint is GET (EventSource only does GET),
/// state-changing (spawns a subprocess + writes an audit row).
/// We gate on `Sec-Fetch-Site` — modern browsers stamp it on every
/// fetch; an attacker's `<img src=…>` from a cross-site page would
/// set it to `cross-site` and get rejected here BEFORE the audit
/// or spawn. Absence (CLI / curl / very old browser) is allowed —
/// those aren't the realistic attack surface for a LAN-only
/// homelab admin.
pub(crate) async fn settings_geoip_update_now_sse(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Response {
    use axum::response::sse::{Event, KeepAlive, Sse};
    use futures_core::Stream;
    use std::pin::Pin;
    use tokio_stream::StreamExt;

    if let Some(sfs) = headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) {
        // "same-origin" = EventSource from /admin/settings page,
        // "none" = direct address-bar navigation. Anything else is
        // a cross-context attach — refuse without spawning or
        // logging. (Returns the unified prefix via error_resp.)
        if sfs != "same-origin" && sfs != "none" {
            return error_resp(
                StatusCode::FORBIDDEN,
                "cross-origin request rejected — open the admin UI directly",
            );
        }
    }

    // One audit row per fire — provenance only. The actual download
    // log goes to journalctl (subprocess stderr). If the audit
    // write fails the fire still proceeds (we don't want the button
    // to mysteriously do nothing because of an unrelated audit
    // problem).
    if let Err(e) = state
        .inv
        .audit("admin", "settings.geoip.update_now.fired", None, None)
        .await
    {
        tracing::warn!(
            target = "vpnctld::admin",
            error = %e,
            "audit write failed for settings.geoip.update_now.fired — subprocess will still run"
        );
    }

    let vpnctl_bin = crate::geoip_update_runner::resolve_vpnctl_bin();
    let raw = crate::geoip_update_runner::run_update(vpnctl_bin);
    let mapped = raw.map(|ev| {
        let name = ev.event_name();
        let json = serde_json::to_string(&ev).unwrap_or_else(|e| {
            tracing::error!(
                target = "vpnctld::admin",
                event_name = name,
                error = %e,
                "geoip-update SSE event serialisation failed — emitting placeholder"
            );
            format!(
                "{{\"kind\":\"step\",\"stream\":\"stderr\",\"message\":\"daemon failed to serialise this event ({e}); see vpnctld logs\"}}"
            )
        });
        Ok::<_, std::convert::Infallible>(Event::default().event(name).data(json))
    });

    let stream: Pin<
        Box<dyn Stream<Item = std::result::Result<Event, std::convert::Infallible>> + Send>,
    > = Box::pin(mapped);

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
    let (theme, accent, lang) = theme_accent_lang(&headers);
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

    // Phase H+ — rolling uptime windows for the per-server SLO chip
    // section. Three independent SQL aggregates (24h / 7d / 30d) —
    // each is one indexed scan against `(server_id, ts)`. Failure
    // → render an empty-state block, not 500: the rest of the page
    // is still valuable when uptime is the broken part. Bonus: the
    // 30d query is the only one whose denominator might be empty
    // for a new server, which `UptimeStat.uptime_pct: Option<u8>`
    // already encodes («None = no data» vs «Some(0) = was down»).
    let uptime_24h = state.inv.uptime_for_server(&sid, 24).await.ok();
    let uptime_7d = state.inv.uptime_for_server(&sid, 24 * 7).await.ok();
    let uptime_30d = state.inv.uptime_for_server(&sid, 24 * 30).await.ok();

    // A3 (audit 2026-05-22, shipped 2026-05-23) — 24h resource-trend
    // sparklines (disk %, mem-used %, sing-box log MiB). The hero
    // tile shows «right now»; the sparkline tile shows «is the
    // right-now value typical or a spike?». Helps the operator
    // distinguish a slow leak (climbing trendline) from a transient
    // burst (flat trend with one tall bar). Loaded best-effort —
    // a probe-fetch failure shouldn't break the rest of the page.
    let trend_rows = state
        .inv
        .recent_node_health_for_server(&sid, 24)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(
                target = "vpnctld::admin",
                server = %sid,
                error = %e,
                "recent_node_health_for_server (24h sparkline) failed"
            );
            Vec::new()
        });

    // Phase 4b — server-wide live activity rollup (active conns
    // now, bytes up/down over the last 24h, last poll ts). Failure
    // → zero-default; the section still renders so the operator
    // sees the diagnostic in journalctl + a clean «no data yet»
    // tile instead of a 500.
    let live_activity = state
        .inv
        .server_live_activity(&sid, 24)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(target = "vpnctld::admin", server = %sid, error = %e, "server_live_activity failed");
            vpnctl_inventory::ServerLiveActivity::default()
        });

    // Phase 4c+4d — last clash-api snapshot + log-derived
    // attribution for the «Live connections» drill-down. None
    // when the poller has never reached this server (fresh
    // daemon start / no key / etc).
    let last_server_snap = state.snapshot_cache.get(&sid);
    // Phase 5a-2 — bulk-fetch cached PTR hostnames for unique
    // destination IPs in the snapshot. Used to enrich the «top
    // destinations» table — `35.217.1.178:50005` becomes
    // `r3.googlevideo.com:50005` when cached. Misses fall back
    // to bare IP. Resolver task fills the cache asynchronously
    // every 5 minutes.
    let dns_ptr_map = if let Some(s) = last_server_snap.as_ref() {
        let mut dst_ips: std::collections::HashSet<String> = std::collections::HashSet::new();
        for c in &s.snapshot.connections {
            if c.metadata.host.is_empty() && !c.metadata.destination_ip.is_empty() {
                dst_ips.insert(c.metadata.destination_ip.clone());
            }
        }
        let ips_vec: Vec<String> = dst_ips.into_iter().collect();
        state
            .inv
            .lookup_dns_ptr_bulk(&ips_vec)
            .await
            .unwrap_or_else(|e| {
                tracing::warn!(target = "vpnctld::admin", server = %sid, error = %e, "lookup_dns_ptr_bulk failed");
                std::collections::HashMap::new()
            })
    } else {
        std::collections::HashMap::new()
    };

    // Phase 4c — sub_access correlation as the FALLBACK. We
    // extract unique sourceIPs from the snapshot, then ask
    // inventory which users have hit subscription URL from those
    // IPs in the last 7 days. Used when the Phase 4d log scrape
    // has no entry for a given (IP, port) pair (e.g. connection
    // older than the log tail window).
    let source_user_map = if let Some(s) = last_server_snap.as_ref() {
        let mut ips: std::collections::HashSet<String> = std::collections::HashSet::new();
        for c in &s.snapshot.connections {
            if !c.metadata.source_ip.is_empty() {
                ips.insert(c.metadata.source_ip.clone());
            }
        }
        let ips_vec: Vec<String> = ips.into_iter().collect();
        state
            .inv
            .users_for_source_ips(&ips_vec, 7)
            .await
            .unwrap_or_else(|e| {
                tracing::warn!(target = "vpnctld::admin", server = %sid, error = %e, "users_for_source_ips failed");
                std::collections::HashMap::new()
            })
    } else {
        std::collections::HashMap::new()
    };

    // Per-server secrets — only read here so kernel-specific sections
    // (currently wgturn's VK-link form) can display their current state.
    // Fetched even when no such kernel is enabled because the cost is
    // one indexed SELECT; conditional load would complicate the section
    // helper without measurable savings.
    let server_secrets = state
        .inv
        .list_server_secrets(&sid)
        .await
        .map_err(|e| internal_error(anyhow::Error::new(e)))?;

    // Per-(server, protocol) hidden state (migration 0018 / NM-10).
    // One bulk SELECT keyed on server_id → HashMap<ProtocolId, bool>
    // so the Enabled-protocols section can render the hide/unhide
    // chip without N+1 calls into `is_server_protocol_hidden`.
    let hidden_map = state
        .inv
        .list_server_protocols_with_hidden(&sid)
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
        div id="deploy-button" style="margin: 12px 0 18px;" {
            form method="post"
                 action=(format!("/admin/servers/{}/deploy", path_segment_encode(&server.id.0)))
                 style="display: inline;" {
                button type="submit"
                       title=(crate::i18n::tr(
                           lang,
                           "Full deploy: mint missing per-protocol server secrets, then SSH into the node and run apt-get install + render-config + systemctl restart for each enabled kernel. Re-clicking is safe — already-present secrets and kernels are skipped.",
                           "Полный деплой: дораздать недостающие per-protocol секреты, затем SSH в ноду и запустить apt-get install + render-config + systemctl restart для каждого включённого ядра. Повторный клик безопасен — уже существующие секреты и ядра пропускаются.",
                       ))
                       style="padding: 6px 14px; border: 1px solid var(--ink); background: var(--ink); color: var(--paper); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                    (crate::i18n::t(lang, crate::i18n::K::BtnDeploy))
                }
            }
            span style="margin-left: 12px; font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute);" {
                (crate::i18n::tr(lang, "Mints missing secrets, SSH-pushes ", "Создаёт недостающие секреты, SSH-пушит "))
                span.ed-mono
                    title=(crate::i18n::tr(
                        lang,
                        "ensure_installed: run the kernel's package install on the node (e.g. apt-get install sing-box). Skipped if the binary is already present at the expected version.",
                        "ensure_installed: запустить установку пакета ядра на ноде (напр. apt-get install sing-box). Пропускается если бинарь уже стоит нужной версии.",
                    )) {
                    "ensure_installed"
                }
                " + "
                span.ed-mono
                    title=(crate::i18n::tr(
                        lang,
                        "apply_config: re-render the kernel's config file (e.g. /etc/sing-box/config.json) from the current inventory state + push it to the node + systemctl restart. Brief connection drop (~1-2 sec) for live clients; they reconnect transparently.",
                        "apply_config: перерендерить конфиг ядра (напр. /etc/sing-box/config.json) из текущего инвентаря + запушить на ноду + systemctl restart. Кратковременный разрыв (~1-2 сек) для живых клиентов; переподключение прозрачное.",
                    )) {
                    "apply_config"
                }
                (crate::i18n::tr(
                    lang,
                    " for every kernel, restarts the service. Subscription URLs reflect the new config immediately.",
                    " для каждого ядра, рестартует сервис. URL подписок отражают новый конфиг сразу.",
                ))
            }
            (crate::i18n::tr(lang, " · hoster ", " · хостер ")) b { (server.hoster) }
        }

        // Hero: current state (live or empty-state)
        (server_detail_hero(&latest, &server, lang))

        // Phase H+ — rolling uptime SLO (24h / 7d / 30d) over the
        // probe data the hero showed «right-now». Renders nothing
        // when ALL three windows have no data (fresh server, no
        // probes yet — hero already covers that case with the
        // empty-state).
        (server_detail_uptime_section(
            uptime_24h.as_ref(),
            uptime_7d.as_ref(),
            uptime_30d.as_ref(),
            lang,
        ))

        // A3 — 24h resource trend sparklines (disk, mem, log size).
        (server_detail_resource_trend_section(&trend_rows, lang))

        // Phase 4b — live activity tile (server-wide totals from
        // clash-api; per-user attribution blocked by NM-11 sing-box
        // upstream, dashboard tile shows zero «attributed users»
        // intentionally to make the limit explicit).
        (server_detail_live_activity_section(&live_activity, lang))

        // Phase 4c + 4d + 5a-2 — per-connection drill-down (top
        // destinations enriched with reverse-DNS hostnames + top
        // source IPs with user correlation + TCP/UDP split).
        (server_detail_live_connections_section(last_server_snap.as_deref(), &source_user_map, &dns_ptr_map, lang))

        // Declared vs observed drift
        (server_detail_drift_section(&server, &observed, &missing, &extra, latest.is_some(), lang))

        // Kernels — multi-kernel runtime selection. Mirrors the
        // Protocols section right below; same enable/disable shape.
        // Adding wireguard support to a node that today runs only
        // sing-box now means: enable amneziawg kernel here →
        // enable wireguard protocol below → `vpnctl deploy`.
        (server_detail_kernels_section(&server, &state.registry, lang))

        // Enabled protocols — checkbox list of every registered protocol
        // with current enable state. Toggle posts back to this same
        // page (303 redirect). Changes take effect on the NEXT
        // `vpnctl deploy <server>` — inventory mutation alone doesn't
        // touch the live sing-box config (deliberate: we never push
        // without operator-initiated deploy).
        // `hidden_map` (migration 0018 / NM-10) drives the per-row
        // hide / unhide chip: hidden=1 keeps the sing-box inbound
        // running but stops emitting the protocol from `/sub/<token>`
        // and `/api/v1/app/config/<device_id>`.
        (server_detail_protocols_section(&server, &state.registry, &hidden_map, lang))

        // Trusted host fingerprint — TOFU pin for the daemon's SSH
        // probe + clash-api poller + deploy. Both the web action below
        // and the `vpnctl server set-fingerprint <id>` CLI shipped
        // 2026-05-17 (`2fda5c6`) + 2026-05-18 (`ec275c5` — extracted
        // `vpnctl-host-fingerprint` crate as single source of truth);
        // operator never needs to drop to shell + raw SQL just to pin
        // a host key. (Stale «TODO for vpnctl» note cleaned 2026-05-22.)
        (server_detail_fingerprint_section(&server, lang))

        // wgturn-specific settings — only renders when the server has
        // the wgturn kernel enabled. The VK Calls invite URL is
        // captcha-gated (can't be auto-minted server-side), so the
        // operator pastes it once here; subsequent deploys read it
        // from `server_secrets["wgturn:vk_link"]`.
        (server_detail_wgturn_section(&server, &server_secrets, lang))

        // Push deploy key — recovery action for servers added via
        // quick-add / migrate-from-bash where the wizard's step-3
        // pubkey push never ran. Phase G chunk 3.5 follow-up; the
        // user's «почему это не делается автоматически» surfaced
        // the gap.
        (server_detail_push_deploy_key_section(&server, lang))

        // Grants — centralised per-server view (Pavel iter B).
        // Lists EVERY user with a per-row grant/revoke form, so the
        // operator doesn't have to bounce through each user's page
        // to manage access on a node. Same shape as the per-user
        // Server-access section, just transposed.
        div.ed-rule {}
        div.ed-art-eyebrow { (crate::i18n::tr(lang, "Grants", "Выданные доступы")) }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
            (user_count) (crate::i18n::tr(lang, " of ", " из ")) (all_users.len()) " "
            @if all_users.len() == 1 { (crate::i18n::tr(lang, "user", "пользователь")) }
            @else { (crate::i18n::tr(lang, "users", "пользователей")) }
            (crate::i18n::tr(
                lang,
                " have access on this server. Toggle below — POST returns 303 here.",
                " имеют доступ к этому серверу. Тогли ниже — POST возвращает 303 сюда же.",
            ))
        }
        @if all_users.is_empty() {
            p style="font-family: var(--serif); font-style: italic; color: var(--mute); padding: 8px 0;" {
                (crate::i18n::tr(lang, "No users in the inventory yet. Create one on ", "В инвентаре ещё нет пользователей. Создай на "))
                a href="/admin/users" style="color: var(--ink);" { "/admin/users" }
                (crate::i18n::tr(lang, " — then come back to grant access.", " — затем вернись сюда чтобы выдать доступ."))
            }
        } @else {
            // B2 (audit 2026-05-22) — bulk grant/revoke row above
            // the per-user list. Grant-all is safe (idempotent,
            // reversible per-row); revoke-all uses a JS confirm()
            // since destructive. Rendered ONLY when at least one
            // bulk action would be meaningful: grant-all visible
            // when there's at least one un-granted user, revoke-all
            // when at least one granted.
            @let ungranted_count = all_users.iter().filter(|u| !granted_user_ids.contains(&u.id)).count();
            @let granted_count = granted_user_ids.len();
            @if ungranted_count > 0 || granted_count > 0 {
                div style="display: flex; gap: 12px; padding: 8px 0; margin-bottom: 8px; border-top: 1px solid var(--rule); border-bottom: 1px solid var(--rule);" {
                    @let sid_enc_b = path_segment_encode(&server.id.0);
                    @if ungranted_count > 0 {
                        form method="post"
                             action=(format!("/admin/servers/{sid_enc_b}/grants/_grant-all"))
                             style="margin: 0; padding: 0;" {
                            button type="submit"
                                   title=(crate::i18n::tr(
                                       lang,
                                       "Grant access to every user currently in the inventory who doesn't have it yet. Idempotent — re-running this on a fully-granted server is a no-op.",
                                       "Выдать доступ всем юзерам инвентаря, у кого его сейчас нет. Идемпотентно — повторный запуск на сервере с уже выданными грантами ничего не сломает.",
                                   ))
                                   style="padding: 4px 12px; border: 1px solid var(--ink); background: var(--ink); color: var(--paper); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                                (crate::i18n::tr(lang, "grant all ", "выдать всем "))
                                "(" (ungranted_count) ")"
                            }
                        }
                    }
                    @if granted_count > 0 {
                        // JS confirm() — destructive but reversible
                        // (operator can re-grant individually). For
                        // a fully-server-wipe flow use the danger-
                        // zone delete-server action. Hidden input
                        // confirm=<server-id> matches handler's
                        // double-submit gate; JS prompt() returns
                        // the typed value which we POST as-is.
                        @let sid_clean = server.id.0.clone();
                        @let confirm_msg = match lang {
                            crate::i18n::Locale::En => format!(
                                // Single-line — the double-escape path through
                                // `js_single_quote_escape` turns `\n` into a
                                // literal backslash-n in prompt(). Period-space
                                // reads cleanly in the prompt dialog and avoids
                                // the escape-gymnastics rabbit hole.
                                "Revoke access for all {granted_count} granted users on server '{sid_clean}'? Type the server id to confirm:"
                            ),
                            crate::i18n::Locale::Ru => format!(
                                "Отозвать доступ у всех {granted_count} юзеров с грантом на сервере '{sid_clean}'? Введи id сервера для подтверждения:"
                            ),
                        };
                        form method="post"
                             action=(format!("/admin/servers/{sid_enc_b}/grants/_revoke-all"))
                             onsubmit=(format!(
                                 "var v = prompt('{}'); if (v !== '{}') {{ alert('confirm did not match server id; nothing revoked'); return false; }} this.confirm.value = v;",
                                 js_single_quote_escape(&confirm_msg),
                                 js_single_quote_escape(&sid_clean),
                             ))
                             style="margin: 0; padding: 0;" {
                            input type="hidden" name="confirm" value="";
                            button type="submit"
                                   title=(crate::i18n::tr(
                                       lang,
                                       "Revoke access for every currently-granted user on this server. Destructive — requires confirm. Re-granting per-user remains available.",
                                       "Отозвать доступ у всех юзеров с текущим грантом на сервере. Деструктивно — нужно подтверждение. Перевыдать поштучно потом можно.",
                                   ))
                                   style="padding: 4px 12px; border: 1px solid var(--acc); background: transparent; color: var(--acc); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                                (crate::i18n::tr(lang, "revoke all ", "отозвать все "))
                                "(" (granted_count) ")…"
                            }
                        }
                    }
                }
            }
            ul style="list-style: none; padding: 0; font-family: var(--serif); font-size: 14px; line-height: 1.8;" {
                @for u in &all_users {
                    @let sid_enc = path_segment_encode(&server.id.0);
                    @let uid_enc = path_segment_encode(&u.id.0);
                    li style="display: flex; align-items: baseline; gap: 12px; padding: 4px 0; border-bottom: 1px dotted var(--rule);" {
                        span style="flex: 1;" {
                            // Pavel 2026-05-19: «и наоборот» — open the
                            // user-detail page in a new tab from
                            // the server-detail's Grants section.
                            // Mirrors the user-detail → server link
                            // for cross-navigation symmetry.
                            a href=(format!("/admin/users/{uid_enc}"))
                              target="_blank"
                              rel="noopener"
                              title=(format!("Open /admin/users/{} in a new tab", u.id.0))
                              style="color: var(--ink); text-decoration: none; border-bottom: 1px dotted var(--ink);" {
                                b { (u.id.0) }
                            }
                        }
                        @if granted_user_ids.contains(&u.id) {
                            span style="font-family: var(--mono); font-size: 11px; color: var(--acc);" {
                                (crate::i18n::tr(lang, "✓ access", "✓ доступ"))
                            }
                            form method="post"
                                 action=(format!("/admin/servers/{sid_enc}/grants/{uid_enc}/revoke"))
                                 style="margin: 0; padding: 0;" {
                                @let title_str = match lang {
                                    crate::i18n::Locale::En => format!("Revoke {}'s access on {}", u.id.0, server.id.0),
                                    crate::i18n::Locale::Ru => format!("Отозвать доступ {} на {}", u.id.0, server.id.0),
                                };
                                button type="submit"
                                       title=(title_str)
                                       style="padding: 2px 8px; border: 1px solid var(--ink); background: transparent; font-family: var(--mono); font-size: 11px; color: var(--ink); cursor: pointer;" {
                                    (crate::i18n::tr(lang, "revoke", "отозвать"))
                                }
                            }
                        } @else {
                            span style="font-family: var(--mono); font-size: 11px; color: var(--mute);" { "—" }
                            form method="post"
                                 action=(format!("/admin/servers/{sid_enc}/grants/{uid_enc}"))
                                 style="margin: 0; padding: 0;" {
                                @let title_str = match lang {
                                    crate::i18n::Locale::En => format!("Grant {} access on {}", u.id.0, server.id.0),
                                    crate::i18n::Locale::Ru => format!("Выдать {} доступ на {}", u.id.0, server.id.0),
                                };
                                button type="submit"
                                       title=(title_str)
                                       style="padding: 2px 8px; border: 1px solid var(--ink); background: var(--ink); color: var(--paper); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                                    (crate::i18n::tr(lang, "grant", "выдать"))
                                }
                            }
                        }
                    }
                }
            }
        }
    };
    Ok(shell("servers", &theme, &accent, lang, body))
}

/// Phase H+ — rolling uptime SLO section. Three chips (24h / 7d /
/// 30d) under the live-status hero. Reads `UptimeStat` values
/// fetched in the handler (uptime_for_server SQL aggregate, one
/// indexed range scan per window).
///
/// Renders NOTHING when all three windows have None — the hero
/// already shows the «no probes yet» empty state and stacking
/// another empty block would be UI noise.
///
/// Chip colour rules (per chip, independent of the others):
///   * `Some(100)`          → green «100%» — perfect, no outages
///   * `Some(>= 99)`        → green
///   * `Some(>= 95)`        → amber
///   * `Some(< 95)`         → red
///   * `Some(0)`            → red «0%» (was DOWN for the entire
///     window — distinct from None!)
///   * `None`               → grey «— no data» (no decidable rows)
///
/// Display precision is **integer %** (formatted via `{p}%` on `u8`)
/// — not one-decimal. `Option<u8>` carries enough resolution for the
/// «pick a colour bucket» purpose without false-precision in the
/// rendered chip («99%» vs «98.7%» — the latter implies precision
/// the 10-min poll cadence simply doesn't deliver).
///
/// Last-outage display: shows ISO timestamp of the most recent
/// `sing_box_active=0` row across ALL THREE windows (the widest is
/// 30d so it captures any). Renders only if found.
///
/// Last-probe staleness: if the most recent probe across all three
/// windows is older than 1200s (= 2× the DEFAULT 600s probe
/// interval), render an amber «poller may be stale» footer. The
/// threshold is hardcoded rather than reading
/// `VPNCTLD_NODE_PROBE_INTERVAL_SECS` from env — the env override
/// is daemon-startup only and the UI would have to observe its
/// own process to read it. **Caveat:** if the operator has set
/// `VPNCTLD_NODE_PROBE_INTERVAL_SECS=1800` or higher, this 1200s
/// threshold will false-positive the «stale» chip after the first
/// natural-interval tick. Acceptable today (production runs with
/// the default 600s) — file a follow-up if Pavel ever raises the
/// interval persistently.
fn server_detail_uptime_section(
    u24h: Option<&vpnctl_inventory::UptimeStat>,
    u7d: Option<&vpnctl_inventory::UptimeStat>,
    u30d: Option<&vpnctl_inventory::UptimeStat>,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;

    // Don't render the section when there's literally no data:
    //   * All three queries failed → suppress (DB error path).
    //   * All three returned `total_rows == 0` → suppress (the
    //     hero already shows «no probes yet» — stacking another
    //     empty block would be UI noise).
    //
    // Subtlety: `uptime_for_server` returns `Ok(UptimeStat { 0,
    // 0, 0, ... })` for an empty window — it does NOT return
    // `Err`. So an `is_none()` check on the Option would always
    // be false in practice (only Err → None via `.ok()`). The
    // load-bearing check is on `total_rows`.
    let any_data = u24h.is_some_and(|s| s.total_rows > 0)
        || u7d.is_some_and(|s| s.total_rows > 0)
        || u30d.is_some_and(|s| s.total_rows > 0);
    if !any_data {
        return html! {};
    }

    let chip = |label: &str, stat: Option<&vpnctl_inventory::UptimeStat>| -> Markup {
        let pct = stat.and_then(|s| s.uptime_pct);
        let color = pct_color(pct);
        let pct_text = pct_label(pct, lang);
        let row_count: u64 = stat.map(|s| s.total_rows).unwrap_or(0);
        let down_count: u64 = stat.map(|s| s.down_rows).unwrap_or(0);
        // `data-uptime-pct` is a stable scrape-target for admin_smoke
        // tests + a future operator tool that wants to extract SLOs
        // without parsing the CSS. The value is the raw u8 or the
        // literal string "none" for the no-data branch. Choosing the
        // attribute over inline-text means the test can't false-pass
        // on unrelated `100%` substrings elsewhere on the page (e.g.
        // disk-pressure tile at 100%).
        let pct_attr = pct.map(|p| p.to_string()).unwrap_or_else(|| "none".into());
        html! {
            div data-uptime-pct=(pct_attr)
                style="display: flex; flex-direction: column; gap: 4px; padding: 12px 16px; border: 1px solid var(--rule); background: var(--paper); min-width: 110px;" {
                div style="font-family: var(--mono); font-size: 10px; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase;" {
                    (label)
                }
                div style=(format!("font-family: var(--serif); font-weight: 500; color: {color}; font-size: 22px; line-height: 1;")) {
                    (pct_text)
                }
                div style="font-family: var(--mono); font-size: 10px; color: var(--mute);" {
                    (row_count) " " (tr(lang, "probes", "проб"))
                    @if down_count > 0 {
                        " · " (down_count) " " (tr(lang, "down", "падений"))
                    }
                }
            }
        }
    };

    // Pick the most recent outage across all three windows (30d is
    // widest, so if it has one, that's our answer; fall through if
    // somehow the wider window missed but a narrower didn't).
    let last_outage = u30d
        .and_then(|s| s.last_outage_at)
        .or_else(|| u7d.and_then(|s| s.last_outage_at))
        .or_else(|| u24h.and_then(|s| s.last_outage_at));

    // Most recent probe (any state). For staleness chip.
    let last_probe = u24h
        .and_then(|s| s.last_probe_at)
        .or_else(|| u7d.and_then(|s| s.last_probe_at))
        .or_else(|| u30d.and_then(|s| s.last_probe_at));

    let stale = last_probe
        .map(|ts| (chrono::Utc::now() - ts).num_seconds() > 1200)
        .unwrap_or(false);

    html! {
        div #uptime-section style="margin-top: 18px;" {
            div.ed-art-eyebrow {
                (tr(lang, "Uptime · sing-box service", "Uptime · сервис sing-box"))
            }
            p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 4px 0 12px;" {
                (tr(
                    lang,
                    "Rolling-window aggregate over `sing_box_active` from the node_probe poller (10-min default tick). \u{00ab}up\u{00bb} = systemctl reports active at probe time. Unknown probes (e.g. probe ran but sing-box wasn't installed yet) are excluded from the denominator.",
                    "Скользящие окна агрегата `sing_box_active` от node_probe-поллера (по умолчанию тик 10 минут). \u{00ab}up\u{00bb} = systemctl показал active в момент пробы. Неопределённые пробы (например проба прошла а sing-box ещё не установлен) не учитываются в знаменателе.",
                ))
            }
            div style="display: flex; gap: 12px; flex-wrap: wrap;" {
                (chip(tr(lang, "last 24h", "24 часа"), u24h))
                (chip(tr(lang, "last 7d",  "7 дней"),  u7d))
                (chip(tr(lang, "last 30d", "30 дней"), u30d))
            }
            @if last_outage.is_some() || stale {
                div style="margin-top: 12px; font-family: var(--mono); font-size: 11px; color: var(--mute); display: flex; flex-direction: column; gap: 4px;" {
                    @if let Some(ts) = last_outage {
                        @let mins = chrono::Utc::now().signed_duration_since(ts).num_minutes().max(0);
                        div {
                            (tr(lang, "Last outage observed: ", "Последнее падение: "))
                            span style="color: var(--ink);" { (ts.format("%Y-%m-%d %H:%M UTC").to_string()) }
                            " ("
                            @if mins < 60 {
                                (mins) " " (tr(lang, "min ago", "мин назад"))
                            } @else if mins < 24 * 60 {
                                (mins / 60) " " (tr(lang, "h ago", "ч назад"))
                            } @else {
                                (mins / (24 * 60)) " " (tr(lang, "d ago", "д назад"))
                            }
                            ")"
                        }
                    }
                    @if stale {
                        div style="color: #e6a23c;" {
                            (tr(
                                lang,
                                "Most recent probe is >20 min old — poller may be stalled. Check journalctl on 236.",
                                "Последняя проба старше 20 минут — поллер может быть остановлен. Проверь journalctl на 236.",
                            ))
                        }
                    }
                }
            }
        }
    }
}

/// Hero block — most-recent probe at-a-glance KPIs, OR an empty state
/// describing why the box is empty (no probe data yet — either fresh
/// server, deploy key not pushed, or poller not running).
fn server_detail_hero(
    latest: &Option<vpnctl_inventory::NodeHealthRow>,
    server: &vpnctl_core::Server,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    let Some(h) = latest else {
        return html! {
            div.ed-rule {}
            div.ed-art-eyebrow { (tr(lang, "Live status", "Живой статус")) }
            p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
                (tr(
                    lang,
                    "No probes yet. The node-telemetry poller is scheduled for ",
                    "Probe-ов пока нет. Поллер телеметрии нод запланирован в ",
                ))
                em { (tr(lang, "Phase H chunk 4", "Phase H chunk 4")) }
                (tr(lang, " — it'll SSH ", " — он будет SSH-ить ")) span.ed-mono { (server.address) }
                (tr(
                    lang,
                    " every 5 min and persist disk/mem/load + listening-port observations. Until then this section reads as blank.",
                    " каждые 5 минут и сохранять наблюдения disk/mem/load + слушающие порты. До тех пор раздел остаётся пустым.",
                ))
            }
        };
    };
    let sb = h
        .sing_box_active
        .map(|b| {
            if b {
                tr(lang, "active", "активен")
            } else {
                tr(lang, "down", "не работает")
            }
        })
        .unwrap_or("?");
    let f2b = h
        .fail2ban_active
        .map(|b| {
            if b {
                tr(lang, "active", "активен")
            } else {
                tr(lang, "down", "не работает")
            }
        })
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
        div.ed-art-eyebrow {
            (tr(lang, "Live status · last probe ", "Живой статус · последний probe "))
            span style="color: var(--mute);" {
                (h.ts.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            }
        }
        div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin: 12px 0 18px;" {
            (status_tile("sing-box", sb, sb_color))
            (status_tile("fail2ban", f2b, f2b_color))
            (status_tile(tr(lang, "disk used", "диск занят"), &disk_pct, "var(--ink)"))
            (status_tile(tr(lang, "memory used", "память занята"), &mem_pct, "var(--ink)"))
            (status_tile(tr(lang, "1-min load", "load 1мин"), &load, "var(--ink)"))
            (status_tile(tr(lang, "sing-box log", "лог sing-box"), &log_size, log_alert_color))
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

/// Phase 4b — server-wide live activity tile (active conns now +
/// 24h bytes up/down + last poll ts + attributed-users counter).
/// Companion to the per-user «Live VPN stats» section on
/// /admin/users/<id>; that one shows ONE user across all servers,
/// this one shows ALL traffic on ONE server.
///
/// NM-11 caveat surfaced in the empty-state copy: per-user
/// attribution from clash-api is blocked by a sing-box upstream
/// bug (TrackerMetadata.MarshalJSON omits the User field). Server-
/// wide totals work, per-user counts always read 0 until upstream
/// PR lands or operator adopts a forked sing-box build.
/// A3 (audit 2026-05-22) — 24h resource-trend sparklines for the
/// per-server detail page. Three small SVG charts: disk %, mem-used %,
/// sing-box log MiB. Each uses the existing reusable `sparkline_svg`
/// helper (so styling stays consistent with the dashboard + monitoring
/// page; accent-toggle in Tweaks panel recolours everything).
///
/// **Renders only when there's at least one node_health row in the
/// 24h window.** Fresh server (no probes yet) gets nothing — the hero
/// section already says «no data yet» for that case; we don't need to
/// repeat it.
///
/// Each row in `trend_rows` came from `recent_node_health_for_server`
/// which sorts DESC (newest first). For the sparkline we reverse so
/// time flows left-to-right.
fn server_detail_resource_trend_section(
    trend_rows: &[vpnctl_inventory::NodeHealthRow],
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    if trend_rows.is_empty() {
        return html! {};
    }
    // Iterate oldest→newest so the sparkline reads chronologically.
    let mut chronological: Vec<&vpnctl_inventory::NodeHealthRow> = trend_rows.iter().collect();
    chronological.reverse();

    // Disk usage % per row. Skip rows missing either side of the
    // ratio (None → no point added; sparkline tolerates a shorter
    // series gracefully).
    let disk_pct_series: Vec<f64> = chronological
        .iter()
        .filter_map(|r| {
            let used = r.disk_used_mib?;
            let total = r.disk_total_mib?;
            if total == 0 {
                return None;
            }
            Some(((used as f64) / (total as f64)) * 100.0)
        })
        .collect();

    // Memory-used % per row (probe stores AVAILABLE, hence 100 - avail/total).
    let mem_used_pct_series: Vec<f64> = chronological
        .iter()
        .filter_map(|r| {
            let avail = r.mem_available_mib?;
            let total = r.mem_total_mib?;
            if total == 0 {
                return None;
            }
            Some(100.0 - ((avail as f64) / (total as f64)) * 100.0)
        })
        .collect();

    // sing-box log size in MiB. The threshold alert
    // (server.singbox.log.too_big) fires at 500 MiB; sparkline shows
    // the climb so operator can predict «when will we hit 500».
    let log_mib_series: Vec<f64> = chronological
        .iter()
        .filter_map(|r| r.sing_box_log_bytes.map(|b| (b as f64) / (1024.0 * 1024.0)))
        .collect();

    let n_samples = chronological.len();
    html! {
        section id="resource-trend" style="margin-top: 28px;" {
            div.ed-art-eyebrow {
                (tr(lang, "Resource trend · last 24h", "Тренд ресурсов · последние 24ч"))
            }
            p style="font-family: var(--serif); font-style: italic; color: var(--mute); margin: 4px 0 12px 0;" {
                (tr(
                    lang,
                    "10-min probe snapshots over the last 24h. Sparkline reads left-to-right (oldest → newest); the «max» label on each chart is the peak in the window. Use these to tell a slow leak (climbing line) from a transient burst (flat line, one spike).",
                    "10-минутные снимки probe за последние 24 часа. Sparkline читается слева-направо (старое → новое); метка «max» в каждом графике — пик за окно. Помогает отличить медленную утечку (растущая линия) от кратковременного всплеска (плоская линия с одним пиком).",
                ))
            }
            div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 16px;" {
                div {
                    div style="font-family: var(--mono); font-size: 11px; color: var(--mute); text-transform: uppercase; letter-spacing: 0.14em;" {
                        (tr(lang, "Disk %", "Диск %"))
                    }
                    (sparkline_svg(&disk_pct_series, 280, 60))
                    div style="font-family: var(--mono); font-size: 10px; color: var(--mute);" {
                        (disk_pct_series.len()) " " (tr(lang, "samples", "точек"))
                    }
                }
                div {
                    div style="font-family: var(--mono); font-size: 11px; color: var(--mute); text-transform: uppercase; letter-spacing: 0.14em;" {
                        (tr(lang, "Mem used %", "Память исп. %"))
                    }
                    (sparkline_svg(&mem_used_pct_series, 280, 60))
                    div style="font-family: var(--mono); font-size: 10px; color: var(--mute);" {
                        (mem_used_pct_series.len()) " " (tr(lang, "samples", "точек"))
                    }
                }
                div {
                    div style="font-family: var(--mono); font-size: 11px; color: var(--mute); text-transform: uppercase; letter-spacing: 0.14em;" {
                        (tr(lang, "sing-box log MiB", "sing-box лог MiB"))
                    }
                    (sparkline_svg(&log_mib_series, 280, 60))
                    div style="font-family: var(--mono); font-size: 10px; color: var(--mute);" {
                        (log_mib_series.len()) " " (tr(lang, "samples · alert at 500 MiB", "точек · алерт на 500 MiB"))
                    }
                }
            }
            p style="font-family: var(--serif); font-style: italic; font-size: 11px; color: var(--mute); margin-top: 6px;" {
                "(" (n_samples) " " (tr(lang, "probe ticks in the window", "тиков probe в окне"))  ")"
            }
        }
    }
}

fn server_detail_live_activity_section(
    activity: &vpnctl_inventory::ServerLiveActivity,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    let last_seen_str = activity
        .last_sample_ts
        .map(|t| t.format("%Y-%m-%d %H:%M UTC").to_string())
        .unwrap_or_else(|| tr(lang, "never", "никогда").to_string());
    let total_bytes = activity
        .bytes_up_window
        .saturating_add(activity.bytes_dn_window);
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow {
            (tr(lang, "Live activity · last 24h", "Живая активность · 24 часа"))
        }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
            (tr(
                lang,
                "Server-wide totals from this node's clash-api (5-minute tick). Numbers reflect actual VPN traffic — VLESS, TUIC, Trojan auth all summed. AmneziaWG / wgturn are kernel-level and not visible to clash-api, so they're NOT counted here. ",
                "Сервер-агрегатные показатели из clash-api ноды (тик 5 минут). Числа отражают реальный VPN-трафик — VLESS, TUIC, Trojan сложены вместе. AmneziaWG / wgturn — kernel-уровень, не видны clash-api, поэтому НЕ учитываются.",
            ))
        }
        div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin: 12px 0 8px;" {
            div title=(tr(lang, "Active connections from the freshest clash-api snapshot (5-min tick). Includes all auth-bearing connections sing-box currently holds open.", "Активные соединения из самого свежего snapshot clash-api (тик 5 минут). Включает все авторизованные соединения, которые sing-box сейчас держит открытыми.")) {
                (status_tile(tr(lang, "active now", "активных сейчас"), &activity.active_now.to_string(), "var(--ink)"))
            }
            div title=(tr(lang, "Total bytes (upload + download) summed across every clash-api tick in the last 24 hours.", "Всего байт (upload + download), сумма по всем тикам clash-api за последние 24 часа.")) {
                (status_tile(tr(lang, "total 24h", "всего 24ч"), &humanize_bytes(total_bytes), "var(--ink)"))
            }
            div title=(tr(lang, "Upload bytes (client → server) over the last 24 hours.", "Upload-байт (клиент → сервер) за последние 24 часа.")) {
                (status_tile(tr(lang, "upload 24h", "upload 24ч"), &humanize_bytes(activity.bytes_up_window), "var(--ink)"))
            }
            div title=(tr(lang, "Download bytes (server → client) over the last 24 hours.", "Download-байт (сервер → клиент) за последние 24 часа.")) {
                (status_tile(tr(lang, "download 24h", "download 24ч"), &humanize_bytes(activity.bytes_dn_window), "var(--ink)"))
            }
        }
        // Last-sample line + NM-11 attribution badge — making the
        // upstream limit explicit instead of silently absent.
        p style="font-family: var(--mono); font-size: 11px; color: var(--mute); margin: 4px 0 14px;" {
            (tr(lang, "last poll: ", "последний поллинг: "))
            b style="color: var(--ink);" { (last_seen_str) }
            " · "
            (activity.distinct_users_attributed)
            (tr(lang, " users attributed (NM-11: sing-box upstream strips per-user from clash-api; server-wide totals work)", " юзеров attributed (NM-11: sing-box upstream удаляет per-user из clash-api; сервер-агрегатные totals работают)"))
        }
    }
}

/// Phase 4c — per-connection drill-down for the server-detail page.
/// Renders three views from the last clash-api snapshot:
///   1. Top destinations by bytes (host or IP:port)
///   2. Top source IPs (= per-device proxy) with user_id
///      correlation from sub_access_log
///   3. TCP / UDP / other network split
///
/// Empty-state (no snapshot yet) explains that the poller fires
/// every 5 minutes and tells the operator to come back. No
/// «restart vpnctld» / SSH instructions per operator-action policy.
fn server_detail_live_connections_section(
    server_snap: Option<&crate::snapshot_cache::ServerSnapshot>,
    source_user_map: &std::collections::HashMap<String, Vec<(vpnctl_core::UserId, u64)>>,
    dns_ptr_map: &std::collections::HashMap<String, Option<String>>,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    use crate::snapshot_cache::{aggregate_by_destination, aggregate_by_source, network_breakdown};
    const TOP_N: usize = 10;

    let Some(server_snap) = server_snap else {
        return html! {
            div.ed-rule {}
            div.ed-art-eyebrow { (tr(lang, "Live connections", "Активные соединения")) }
            p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
                (tr(
                    lang,
                    "No clash-api snapshot for this server yet. The poller fires every 5 minutes; refresh after the next tick. Empty also if the deploy key isn't authorised on this node (see Settings → Deploy SSH key).",
                    "Снимка clash-api по этому серверу ещё нет. Поллер запускается каждые 5 минут; обнови после следующего тика. Также пусто если deploy-ключ ещё не авторизован на этой ноде (см. Settings → Deploy SSH key).",
                ))
            }
        };
    };

    let snap = &server_snap.snapshot;
    let log_attribution = &server_snap.attribution;
    let nb = network_breakdown(snap);
    let top_dests = aggregate_by_destination(snap, TOP_N, dns_ptr_map);
    let top_sources = aggregate_by_source(snap, TOP_N);
    let total_conns = snap.connections.len();

    // Phase 4d — for each top-source aggregate, look up the
    // FRESHEST user_id we have for ANY (source_ip, port) pair
    // matching this IP in the log map. We don't dedupe across
    // ports: the log map can carry the same user_id under
    // different ports (one device, many connections), and we
    // want to surface that user_id. If multiple users share an
    // IP (NAT collision), pick the one with the most port
    // entries — that's the most-active device behind the NAT.
    use std::collections::HashMap as StdHashMap;
    let mut ip_to_log_user: StdHashMap<&str, StdHashMap<&str, u32>> = StdHashMap::new();
    for ((ip, _port), user) in log_attribution.iter() {
        *ip_to_log_user
            .entry(ip.as_str())
            .or_default()
            .entry(user.as_str())
            .or_insert(0) += 1;
    }
    // Resolve each IP → top user_id (highest port count).
    let log_ip_winner: StdHashMap<&str, &str> = ip_to_log_user
        .iter()
        .filter_map(|(ip, users)| {
            users
                .iter()
                .max_by_key(|(_, cnt)| **cnt)
                .map(|(user, _)| (*ip, *user))
        })
        .collect();

    html! {
        div.ed-rule {}
        div.ed-art-eyebrow {
            (tr(lang, "Live connections", "Активные соединения"))
            span style="color: var(--mute); margin-left: 12px; font-family: var(--mono); font-size: 11px; letter-spacing: 0;" {
                "· " (total_conns) " "
                (tr(lang, "connections in the last 5-min snapshot", "соединений в последнем 5-минутном снимке"))
            }
        }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
            (tr(
                lang,
                "Per-connection detail from clash-api. NM-11 (sing-box upstream) drops the `user` field on the wire, so we attribute connections to users via the source-IP ↔ subscription-fetch IP correlation (last 7 days). Best-effort — accuracy drops for NAT collisions.",
                "Деталь per-connection из clash-api. NM-11 (sing-box upstream) убирает поле `user` из wire-формата, поэтому атрибуция идёт через корреляцию source IP ↔ IP запроса подписки (последние 7 дней). Best-effort — точность падает при коллизии NAT.",
            ))
        }
        // Network breakdown row.
        div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin: 12px 0 18px;" {
            (status_tile(
                tr(lang, "tcp", "tcp"),
                &format!("{} · {}", nb.tcp_conns, humanize_bytes(nb.tcp_bytes)),
                "var(--ink)",
            ))
            (status_tile(
                tr(lang, "udp", "udp"),
                &format!("{} · {}", nb.udp_conns, humanize_bytes(nb.udp_bytes)),
                "var(--ink)",
            ))
            (status_tile(
                tr(lang, "other", "иные"),
                &format!("{} · {}", nb.other_conns, humanize_bytes(nb.other_bytes)),
                "var(--ink)",
            ))
        }

        // Top destinations table.
        h4 style="font-family: var(--mono); font-size: 10px; letter-spacing: 0.14em; text-transform: uppercase; color: var(--mute); margin: 16px 0 6px;" {
            (tr(lang, "top destinations · this snapshot", "топ destinations · этот снимок"))
        }
        @if top_dests.is_empty() {
            p style="font-family: var(--serif); font-style: italic; color: var(--mute);" {
                (tr(lang, "no active connections", "активных соединений нет"))
            }
        } @else {
            table style="width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 11.5px; margin-bottom: 18px;" {
                thead {
                    tr style="border-bottom: 1px solid var(--ink);" {
                        th style="text-align: left; padding: 5px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                            (tr(lang, "host / ip", "host / ip"))
                        }
                        th style="text-align: right; padding: 5px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                            (tr(lang, "conns", "соед."))
                        }
                        th style="text-align: right; padding: 5px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                            (tr(lang, "upload", "upload"))
                        }
                        th style="text-align: right; padding: 5px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                            (tr(lang, "download", "download"))
                        }
                        th style="text-align: right; padding: 5px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                            (tr(lang, "total", "всего"))
                        }
                    }
                }
                tbody {
                    @for d in &top_dests {
                        tr style="border-bottom: 1px dotted var(--rule);" {
                            td style="padding: 4px 8px; overflow-wrap: anywhere;" { (d.label) }
                            td style="padding: 4px 8px; text-align: right;" { (d.conns) }
                            td style="padding: 4px 8px; text-align: right;" { (humanize_bytes(d.upload)) }
                            td style="padding: 4px 8px; text-align: right;" { (humanize_bytes(d.download)) }
                            td style="padding: 4px 8px; text-align: right; font-weight: 500;" { (humanize_bytes(d.upload.saturating_add(d.download))) }
                        }
                    }
                }
            }
        }

        // Top source IPs table — with user correlation.
        h4 style="font-family: var(--mono); font-size: 10px; letter-spacing: 0.14em; text-transform: uppercase; color: var(--mute); margin: 16px 0 6px;" {
            (tr(lang, "top sources · this snapshot · likely user", "топ source IP · этот снимок · вероятный юзер"))
        }
        @if top_sources.is_empty() {
            p style="font-family: var(--serif); font-style: italic; color: var(--mute);" {
                (tr(lang, "no active source IPs", "активных source IP нет"))
            }
        } @else {
            table style="width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 11.5px;" {
                thead {
                    tr style="border-bottom: 1px solid var(--ink);" {
                        th style="text-align: left; padding: 5px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                            (tr(lang, "source ip", "source ip"))
                        }
                        th style="text-align: left; padding: 5px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;"
                           title=(tr(lang, "Most-likely user_id based on which user has hit subscription URL from this IP in the last 7 days (sub_access_log JOIN). «—» = no match.", "Наиболее вероятный user_id на основе того, какой юзер за последние 7 дней дёргал subscription URL с этого IP (JOIN на sub_access_log). «—» = совпадений нет.")) {
                            (tr(lang, "likely user", "вероятный юзер"))
                        }
                        th style="text-align: right; padding: 5px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                            (tr(lang, "conns", "соед."))
                        }
                        th style="text-align: right; padding: 5px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                            (tr(lang, "upload", "upload"))
                        }
                        th style="text-align: right; padding: 5px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                            (tr(lang, "download", "download"))
                        }
                        th style="text-align: right; padding: 5px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                            (tr(lang, "total", "всего"))
                        }
                    }
                }
                tbody {
                    @for s in &top_sources {
                        tr style="border-bottom: 1px dotted var(--rule);" {
                            td style="padding: 4px 8px;" { (s.label) }
                            td style="padding: 4px 8px;" {
                                // Phase 4d — log-derived attribution
                                // wins (exact match from sing-box
                                // accept logs). Phase 4c sub_access
                                // correlation is the fallback for
                                // connections older than the log tail.
                                @if let Some(log_user) = log_ip_winner.get(s.label.as_str()) {
                                    a href=(format!("/admin/users/{}", crate::http_util::path_segment_encode(log_user)))
                                      style="color: var(--ink); text-decoration: none; border-bottom: 1px solid var(--ink);"
                                      title=(tr(
                                          lang,
                                          "Matched from VPN server log — this user authenticated from that IP.",
                                          "Совпадение из лога VPN-сервера — этот юзер аутентифицировался с этого IP.",
                                      )) {
                                        (*log_user)
                                    }
                                    span style="color: var(--mute); margin-left: 6px; font-size: 10px;"
                                         title=(tr(lang, "Source: VPN server log. Direct, high-confidence match.", "Источник: лог VPN-сервера. Прямое сопоставление с высокой точностью.")) {
                                        (tr(lang, "log", "лог"))
                                    }
                                } @else if let Some(users) = source_user_map.get(&s.label) {
                                    @if !users.is_empty() {
                                        @let (top_uid, top_hits) = &users[0];
                                        a href=(format!("/admin/users/{}", crate::http_util::path_segment_encode(&top_uid.0)))
                                          style="color: var(--ink); text-decoration: none; border-bottom: 1px dotted var(--rule);"
                                          title=(tr(
                                              lang,
                                              "Best-guess match — this user fetched their subscription URL from this IP in the last 7 days.",
                                              "Предположительное совпадение — этот юзер запрашивал свою подписку с этого IP за последние 7 дней.",
                                          )) {
                                            (top_uid.0)
                                        }
                                        span style="color: var(--mute); margin-left: 6px; font-size: 10px;"
                                             title=(format!(
                                                "{} ({} {})",
                                                tr(lang, "Source: subscription fetches over the last 7 days. Best-guess (NAT can collide).", "Источник: запросы подписки за 7 дней. Эвристика (NAT может коллидировать)."),
                                                top_hits,
                                                tr(lang, "fetches from this IP", "запросов с этого IP"),
                                             )) {
                                            (tr(lang, "sub", "подп"))
                                        }
                                        @if users.len() > 1 {
                                            span style="color: var(--mute); margin-left: 6px;" {
                                                "+" (users.len() - 1) " "
                                                (tr(lang, "more", "ещё"))
                                            }
                                        }
                                    } @else {
                                        span style="color: var(--mute);"
                                             title=(tr(lang, "No match in VPN server log and no recent subscription fetch from this IP.", "Нет совпадения в логе VPN-сервера и нет недавних запросов подписки с этого IP.")) {
                                            "—"
                                        }
                                    }
                                } @else {
                                    span style="color: var(--mute);"
                                         title=(tr(lang, "No match in VPN server log and no recent subscription fetch from this IP.", "Нет совпадения в логе VPN-сервера и нет недавних запросов подписки с этого IP.")) {
                                        "—"
                                    }
                                }
                            }
                            td style="padding: 4px 8px; text-align: right;" { (s.conns) }
                            td style="padding: 4px 8px; text-align: right;" { (humanize_bytes(s.upload)) }
                            td style="padding: 4px 8px; text-align: right;" { (humanize_bytes(s.download)) }
                            td style="padding: 4px 8px; text-align: right; font-weight: 500;" { (humanize_bytes(s.upload.saturating_add(s.download))) }
                        }
                    }
                }
            }
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
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    let enabled: std::collections::HashSet<&vpnctl_core::KernelId> =
        server.kernels.iter().collect();
    let all_kernels = registry.kernel_ids();
    let sid_enc = path_segment_encode(&server.id.0);
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow { (tr(lang, "Kernels", "Ядра")) }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 8px;" {
            (tr(
                lang,
                "Daemons running on this node. One physical VPS can host multiple (sing-box on 443/TCP + amneziawg on 51820/UDP cohabit cleanly).",
                "Демоны, работающие на этой ноде. Один физический VPS может держать несколько (sing-box на 443/TCP + amneziawg на 51820/UDP уживаются нормально).",
            ))
        }
        div style="padding: 8px 12px; margin: 0 0 12px; background: var(--paper); border-left: 3px solid var(--accent); font-family: var(--serif); font-size: 12.5px; line-height: 1.5;" {
            b style="color: var(--accent); font-family: var(--mono); letter-spacing: 0.1em; text-transform: uppercase; font-size: 11px;" {
                (tr(
                    lang,
                    "⚠ toggle here = inventory only",
                    "⚠ тогл здесь = только инвентарь",
                ))
            }
            (tr(
                lang,
                " — the live node sees the change only after you click ",
                " — живая нода увидит изменение только после клика по ",
            ))
            a href="#deploy-button"
              style="color: var(--ink); border-bottom: 1px dotted var(--ink); text-decoration: none; font-weight: 500;" {
                span.ed-mono { (tr(lang, "deploy →", "деплой →")) }
            }
            (tr(
                lang,
                " at the top of this page. We never SSH-push a config without an explicit operator click (no surprise redeploys).",
                " вверху страницы. Мы никогда не пушим конфиг через SSH без явного клика оператора (без сюрпризов-redeploy).",
            ))
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
                            (tr(lang, "(runs: ", "(крутит: ")) (supported) ")"
                        }
                    }
                    @if is_on {
                        span style="font-family: var(--mono); font-size: 11px; color: var(--acc); margin-right: 4px;" {
                            (tr(lang, "✓ on", "✓ вкл"))
                        }
                        form method="post"
                             action=(format!("/admin/servers/{}/kernels/{}/disable", sid_enc, path_segment_encode(&kid.0)))
                             style="margin: 0; padding: 0;" {
                            @let dis_title = match lang {
                                crate::i18n::Locale::En => format!("Remove {} from {}.kernels. Takes effect on next deploy.", kid.0, server.id.0),
                                crate::i18n::Locale::Ru => format!("Убрать {} из {}.kernels. Применится при следующем деплое.", kid.0, server.id.0),
                            };
                            button type="submit"
                                   title=(dis_title)
                                   style="padding: 2px 8px; border: 1px solid var(--ink); background: transparent; font-family: var(--mono); font-size: 11px; color: var(--ink); cursor: pointer;" {
                                (crate::i18n::t(lang, crate::i18n::K::BtnDisable))
                            }
                        }
                    } @else {
                        span style="font-family: var(--mono); font-size: 11px; color: var(--mute); margin-right: 4px;" {
                            "—"
                        }
                        form method="post"
                             action=(format!("/admin/servers/{}/kernels/{}/enable", sid_enc, path_segment_encode(&kid.0)))
                             style="margin: 0; padding: 0;" {
                            @let en_title = match lang {
                                crate::i18n::Locale::En => format!("Add {} to {}.kernels. Takes effect on next deploy.", kid.0, server.id.0),
                                crate::i18n::Locale::Ru => format!("Добавить {} в {}.kernels. Применится при следующем деплое.", kid.0, server.id.0),
                            };
                            button type="submit"
                                   title=(en_title)
                                   style="padding: 2px 8px; border: 1px solid var(--ink); background: var(--ink); color: var(--paper); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                                (crate::i18n::t(lang, crate::i18n::K::BtnEnable))
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
fn server_detail_push_deploy_key_section(
    server: &vpnctl_core::Server,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    let sid_enc = path_segment_encode(&server.id.0);
    let reference_key = std::env::var("VPNCTLD_REFERENCE_SSH_KEY").ok();
    let reference_ok = reference_key
        .as_ref()
        .is_some_and(|p| std::path::Path::new(p).exists());
    html! {
        div.ed-rule {}
        div #push-deploy-key.ed-art-eyebrow {
            (tr(lang, "Deploy SSH key — push to this server", "Deploy SSH-ключ — запушить на этот сервер"))
        }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px; max-width: 760px;" {
            (tr(lang, "Daemon needs its pubkey on this server's ", "Демону нужен его pubkey в "))
            span.ed-mono { "~/.ssh/authorized_keys" }
            (tr(
                lang,
                " before probes, deploys, or the Telegram via-server proxy can work. The Phase E wizard at ",
                " этого сервера, иначе не работают probe-ы, деплои и Telegram via-server прокси. Мастер Phase E на ",
            ))
            span.ed-mono { "/admin/servers/new" }
            (tr(lang, " does this automatically. For servers added via ", " делает это автоматически. Для серверов добавленных через "))
            span.ed-mono { "quick-add" } " / " span.ed-mono { "migrate-from-bash" }
            (tr(
                lang,
                " (or when the wizard's push step failed), use this form. Idempotent — re-clicking after success is a no-op.",
                " (или если шаг push мастера упал), используй эту форму. Идемпотентно — повторный клик после успеха ничего не делает.",
            ))
        }

        @if reference_ok {
            p style="font-family: var(--mono); font-size: 11px; color: var(--ink); margin: 0 0 12px; padding: 8px 12px; background: var(--paper); border-left: 3px solid var(--acc); max-width: 760px;" {
                "✓ " b { (tr(lang, "reference SSH key configured", "reference SSH-ключ настроен")) }
                " (" span.ed-mono { (reference_key.as_deref().unwrap_or("")) } "). "
                (tr(lang, "Click ", "Клик "))
                b { (tr(lang, "push deploy key", "запушить deploy-ключ")) }
                (tr(
                    lang,
                    " with password EMPTY — daemon will use the reference key for a silent push. If that key isn't authorised on this specific server, fill in the password to fall back to sshpass.",
                    " с ПУСТЫМ паролем — демон использует reference-key для тихого push. Если этот ключ не авторизован на конкретно этом сервере — заполни пароль для fallback через sshpass.",
                ))
            }
        } @else {
            p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 0 0 12px; max-width: 760px;" {
                (tr(lang, "Tip: set ", "Подсказка: задай ")) span.ed-mono { "VPNCTLD_REFERENCE_SSH_KEY=/path/to/operator_key" }
                (tr(lang, " in the daemon's ", " в "))
                span.ed-mono { "/etc/vpnctl/vpnctld.env" }
                (tr(
                    lang,
                    " (then restart vpnctld) to skip the password input on future pushes — useful when an operator key (claude-dev, etc) is already authorised on every server.",
                    " демона (затем перезапусти vpnctld) — это позволит обходить ввод пароля на будущих push'ах, удобно когда operator-ключ (claude-dev и т.п.) уже авторизован на каждом сервере.",
                ))
            }
        }

        form method="post"
             action=(format!("/admin/servers/{sid_enc}/push-deploy-key"))
             style="margin: 0 0 14px;" {
            div style="display: grid; grid-template-columns: 140px 1fr; gap: 10px 14px; align-items: center; max-width: 560px;" {
                label style="font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                    (tr(lang, "root password", "root-пароль"))
                }
                input type="password"
                      name="root_password"
                      autocomplete="off"
                      placeholder=(if reference_ok {
                          tr(lang, "leave blank to use reference key; fill to force sshpass fallback", "пусто = reference-key; заполни = форсировать sshpass fallback")
                      } else {
                          tr(lang, "never stored — used once for the SSH connect, then discarded", "не сохраняется — используется один раз для SSH-коннекта, затем отбрасывается")
                      })
                      style="font-family: var(--mono); font-size: 12px; padding: 5px 8px; border: 1px solid var(--rule); background: var(--paper);";
            }
            div style="margin-top: 12px;" {
                button type="submit"
                       title=(crate::i18n::tr(
                           lang,
                           "Append the daemon's deploy pubkey to ~/.ssh/authorized_keys on this server. Tries reference key first (if configured) then falls back to sshpass + the password above.",
                           "Добавить deploy-pubkey демона в ~/.ssh/authorized_keys на этом сервере. Сначала пробует reference-key (если настроен), затем fallback на sshpass + пароль выше.",
                       ))
                       style="padding: 6px 14px; border: 1px solid var(--ink); background: var(--ink); color: var(--paper); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                    (crate::i18n::tr(lang, "push deploy key", "запушить deploy-ключ"))
                }
                span style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin-left: 14px;" {
                    (crate::i18n::tr(lang, "Connects to ", "Подключение к "))
                    span.ed-mono { (server.ssh_user) "@" (server.address) ":" (server.ssh_port) }
                }
            }
        }
    }
}

fn server_detail_fingerprint_section(
    server: &vpnctl_core::Server,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::{K, t, tr};
    let sid_enc = path_segment_encode(&server.id.0);
    let current = server.trusted_host_fingerprint.clone();
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow
            title=(tr(
                lang,
                "The SHA-256 of the node's SSH host public key, pinned in the inventory. Every SSH-using subsystem (deploy, probe, clash-poller) verifies the live key matches before sending any secrets — protects against MITM if someone hijacks the IP.",
                "SHA-256 публичного SSH-ключа ноды, закреплённый в инвентаре. Все подсистемы которые используют SSH (деплой, probe, clash-poller) проверяют что live-ключ совпадает прежде чем посылать секреты — защита от MITM если кто-то перехватит IP.",
            )) {
            (t(lang, K::EyebrowTrustedFingerprint))
        }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
            (tr(
                lang,
                "Pinned SHA-256 of the node's SSH ed25519 host key. vpnctld + the deploy / probe / clash-poller pipelines all refuse to talk to a host whose live key doesn't match this value — ",
                "Закреплённый SHA-256 хост-ключа ed25519 ноды. vpnctld + пайплайны деплоя / probe / clash-poller отказываются разговаривать с хостом чей live-ключ не совпадает с этим значением — ",
            ))
            span title=(tr(
                lang,
                "Trust-On-First-Use: accept whatever host key the node presents the first time, refuse changes afterwards. Standard SSH posture; same model `~/.ssh/known_hosts` uses.",
                "Trust-On-First-Use: принять любой host-ключ который нода предъявляет в первый раз, затем отказываться от смены. Стандартная SSH-модель; так же как `~/.ssh/known_hosts`.",
            )) {
                (tr(lang, "TOFU pin", "TOFU-pin"))
            }
            (tr(
                lang,
                ", set once. Update only if the node was legitimately rebuilt (and re-confirm via console).",
                ", задаётся один раз. Обновляй только если нода была легитимно пересоздана (и сверь через console).",
            ))
        }
        div style="font-family: var(--mono); font-size: 12px; padding: 8px 12px; background: var(--paper-tint); border: 1px solid var(--rule); margin-bottom: 12px;" {
            @match &current {
                Some(fp) => { (tr(lang, "current: ", "текущий: ")) (fp) }
                None => {
                    em style="color: var(--mute);" {
                        (tr(
                            lang,
                            "(no fingerprint pinned — first SSH connection will TOFU-accept whatever the host presents)",
                            "(отпечаток не закреплён — первый SSH-коннект TOFU-примет то, что хост предъявит)",
                        ))
                    }
                }
            }
        }
        div style="display: flex; flex-direction: column; gap: 10px;" {
            form method="post"
                 action=(format!("/admin/servers/{sid_enc}/set-fingerprint"))
                 style="display: flex; gap: 8px; align-items: center;" {
                input type="hidden" name="mode" value="keyscan";
                button type="submit"
                       title=(tr(
                           lang,
                           "Run ssh-keyscan + ssh-keygen -lf - on the daemon host, pin the resulting fingerprint.",
                           "Запустить ssh-keyscan + ssh-keygen -lf - на хосте демона и закрепить полученный отпечаток.",
                       ))
                       style="padding: 6px 14px; border: 1px solid var(--ink); background: var(--ink); color: var(--paper); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                    (tr(lang, "auto-detect via ssh-keyscan →", "автоопределить через ssh-keyscan →"))
                }
                span style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute);" {
                    (tr(lang, "(daemon will SSH-keyscan ", "(демон сделает ssh-keyscan "))
                    span.ed-mono { (server.address) ":" (server.ssh_port) }
                    (tr(lang, " and pin the SHA-256)", " и закрепит SHA-256)"))
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
                       title=(tr(
                           lang,
                           "Save the SHA256 fingerprint you pasted above as the trusted host key for this server (TOFU pin). Future SSH connections refuse if the node presents a different key — protects against MITM after the initial trust.",
                           "Сохранить вставленный выше SHA256-отпечаток как доверенный host-ключ для этого сервера (TOFU pin). Будущие SSH-коннекты откажутся если нода предъявит другой ключ — защита от MITM после первичного доверия.",
                       ))
                       style="padding: 4px 12px; border: 1px solid var(--ink); background: transparent; color: var(--ink); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                    (tr(lang, "pin manually", "закрепить вручную"))
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

// (`validate_wgturn_vk_link` was removed 2026-05-19 — VK link is no
// longer a per-server operator input; each END USER supplies their
// own at `wgturn-cli connect-url … --vk-link <url>` time because
// each VK call has a limited concurrent-stream count. See the
// kernel's render_config comment for the upstream
// `pkg/wgshare/doc.go` quote.)

/// Render the wgturn-specific info section on `/admin/servers/{id}`.
///
/// The section is OMITTED entirely when the server doesn't have the
/// `wgturn` kernel — keeps the page short for the common case where
/// most nodes are sing-box only. When wgturn IS in `server.kernels`,
/// the section explains the operator-facing wgturn UX:
///   * VK link is END-USER-supplied at connect time, NOT operator
///     input here (Pavel 2026-05-19 + upstream `pkg/wgshare/doc.go`).
///   * Each VK call has limited concurrent streams → per-user
///     end-user-supplied is the correct model.
///   * Operator hands the user `wgturn://…` share-link from the
///     user-detail page; user pastes their own VK link into
///     `wgturn-cli connect-url … --vk-link <url>` on their device.
fn server_detail_wgturn_section(
    server: &vpnctl_core::Server,
    _secrets: &std::collections::HashMap<String, String>,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    let has_wgturn = server.kernels.iter().any(|k| k.0 == "wgturn");
    if !has_wgturn {
        return html! {};
    }
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow { (tr(lang, "wgturn — emergency channel", "wgturn — аварийный канал")) }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
            (tr(lang, "VK-TURN-relayed WireGuard. The server-side daemon ", "WireGuard через VK-TURN relay. Серверный демон "))
            span.ed-mono { "wgturn-cli serve" }
            (tr(lang, " is configured automatically when you click ", " настраивается автоматически когда ты кликаешь "))
            span.ed-mono { (tr(lang, "deploy →", "деплой →")) }
            (tr(lang, " — no operator input is needed here.", " — ввод оператора здесь не нужен."))
        }
        div style="font-family: var(--serif); font-size: 13px; line-height: 1.6; padding: 10px 14px; background: var(--paper-tint); border-left: 3px solid var(--accent);" {
            b { (tr(lang, "VK link is supplied by the END USER, not the operator.", "VK-ссылку даёт КОНЕЧНЫЙ ПОЛЬЗОВАТЕЛЬ, не оператор.")) }
            (tr(
                lang,
                " Each VK call has limited concurrent streams, so a shared per-server link would saturate. Each user creates their own VK call invite on vk.com, then runs (or pastes the URL into their wgturn-cli)",
                " У каждого VK-звонка ограниченное число одновременных потоков, поэтому общая server-ссылка быстро бы переполнилась. Каждый пользователь сам создаёт инвайт на VK-звонок на vk.com, затем запускает (или вставляет URL в свой wgturn-cli)",
            ))
            br {}
            span.ed-mono style="display: inline-block; margin: 6px 0; padding: 4px 8px; background: var(--paper); font-size: 11px;" {
                "wgturn-cli connect-url '<wgturn://...>' --vk-link '<https://vk.com/call/join/...>'"
            }
            br {}
            (tr(lang, "The ", "Сама "))
            span.ed-mono { "wgturn://" }
            (tr(
                lang,
                " share-link itself lives on the user-detail page under «Per-protocol share links».",
                " share-ссылка лежит на странице пользователя в секции «Ссылки на отдельные протоколы».",
            ))
        }
    }
}

// (`server_set_wgturn_vk_link` POST handler removed 2026-05-19 —
// VK link is no longer a per-server admin input; see
// server_detail_wgturn_section above for the new operator copy.)

fn server_detail_protocols_section(
    server: &vpnctl_core::Server,
    registry: &vpnctl_core::Registry,
    hidden_map: &std::collections::HashMap<vpnctl_core::ProtocolId, bool>,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::{K, t, tr};
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
        // NM-12 follow-up (Pavel 2026-05-20: «каждый раз когда я
        // жму disable меня выкидывает в верх страницы»): all 4
        // visibility-toggle handlers below this row redirect to
        // `/admin/servers/{id}#enabled-protocols`. The browser
        // honours the fragment and scrolls the operator back to
        // THIS section instead of resetting to the page top.
        div.ed-art-eyebrow id="enabled-protocols" { (t(lang, K::EyebrowEnabledProtocols)) }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 8px;" {
            (tr(
                lang,
                "Check what runs on this node. Protocols are wire formats; their kernels (one or more) are picked from the section above.",
                "Что крутится на этой ноде. Протоколы — это wire-форматы; их ядра (одно или больше) выбираются выше в секции Ядра.",
            ))
        }
        // Same deploy-required notice as the Kernels section above —
        // duplicated deliberately so an operator who scrolls straight
        // to «Enabled protocols» (the more frequently-touched section)
        // doesn't miss it.
        div style="padding: 8px 12px; margin: 0 0 12px; background: var(--paper); border-left: 3px solid var(--accent); font-family: var(--serif); font-size: 12.5px; line-height: 1.5;" {
            b style="color: var(--accent); font-family: var(--mono); letter-spacing: 0.1em; text-transform: uppercase; font-size: 11px;" {
                (tr(lang, "⚠ toggle here = inventory only", "⚠ тогл здесь = только инвентарь"))
            }
            (tr(lang, " — clicking ", " — клик по "))
            span.ed-mono { (t(lang, K::BtnEnable)) }
            " / "
            span.ed-mono { (t(lang, K::BtnDisable)) }
            (tr(
                lang,
                " only writes to vpnctl's database. The actual sing-box config on the node is rewritten when you click ",
                " только пишет в БД vpnctl. Реальный конфиг sing-box на ноде переписывается когда ты кликаешь ",
            ))
            a href="#deploy-button"
              style="color: var(--ink); border-bottom: 1px dotted var(--ink); text-decoration: none; font-weight: 500;" {
                span.ed-mono { (t(lang, K::BtnDeploy)) }
            }
            (tr(
                lang,
                " at the top. So: toggle → click deploy → wait for SSE log to finish → live.",
                " вверху. То есть: тогл → клик деплой → дождаться окончания SSE-лога → live.",
            ))
        }
        ul style="list-style: none; padding: 0; font-family: var(--mono); font-size: 12px; line-height: 1.8;" {
            @for pid in &all_protocols {
                @let is_on = enabled.contains(pid);
                @let compatible = kernel_supports.contains(pid);
                // Migration 0018 / NM-10: per-(server, protocol)
                // hidden flag. Only meaningful for `is_on=true` rows
                // (hidden state on an off-protocol is silently
                // ignored by the render path). Defaults to false
                // when the bulk-loader didn't return a row for this
                // pid (e.g. add_protocol invariant on enabled but
                // schema-missing row).
                @let is_hidden = hidden_map.get(pid).copied().unwrap_or(false);
                // NM-12: DPI / active-probing resilience tier. Read
                // straight from the protocol impl in the registry —
                // none of the inventory mutations carry this; it's
                // compile-time static. Missing protocol (impossible
                // in production, registry seeds itself in main()) →
                // None → no chip rendered.
                @let risk = registry.protocol(pid).map(|p| p.dpi_risk());
                @let pid_is_weak = matches!(risk, Some(vpnctl_core::DpiRisk::Weak));
                li style="display: flex; align-items: baseline; gap: 12px; padding: 4px 0; border-bottom: 1px dotted var(--rule);" {
                    // Weak protocols get font-size 11px (vs 12px for
                    // Moderate/Strong) — Pavel 2026-05-20: «можешь
                    // даже шрифт меньше сделать у них». Visual
                    // de-emphasis without removing the row, so the
                    // operator can still see + toggle it.
                    span style=(format!(
                        "flex: 1; color: {}; font-size: {};",
                        if compatible { "var(--ink)" } else { "var(--mute)" },
                        if pid_is_weak { "11px" } else { "12px" },
                    )) {
                        (pid.0)
                        @if let Some(r) = risk {
                            " "
                            // DPI-risk chip: green/grey/red, sits
                            // alongside the protocol id so the
                            // operator's eye catches it. Colour
                            // helpers on `DpiRisk` are the single
                            // source of truth — adding a future tier
                            // (or recolouring the palette) is one
                            // edit in core/src/lib.rs. Tooltip carries
                            // the per-tier explainer string.
                            span title=(r.tooltip())
                                 style=(format!(
                                     "font-family: var(--mono); font-size: 10px; padding: 1px 6px; border: 1px solid {}; color: {}; letter-spacing: 0.04em;",
                                     r.border_css(),
                                     r.text_css(),
                                 )) {
                                (r.label())
                            }
                        }
                        @if !compatible {
                            " "
                            span style="font-size: 10px; color: var(--mute); font-style: italic; font-family: var(--serif);" {
                                (tr(lang, "(not supported by ", "(не поддерживается "))
                                @if server.kernels.len() == 1 {
                                    (tr(lang, "kernel ", "ядром ")) (server.kernels[0].0)
                                } @else {
                                    (tr(lang, "any kernel on this server: ", "ни одним ядром на этом сервере: "))
                                    (server.kernels.iter().map(|k| k.0.clone()).collect::<Vec<_>>().join(", "))
                                }
                                ")"
                            }
                        }
                    }
                    @if is_on {
                        @if is_hidden {
                            span style="font-family: var(--mono); font-size: 11px; color: var(--acc); margin-right: 4px;" {
                                (tr(lang, "✓ on · hidden", "✓ вкл · скрыт"))
                            }
                        } @else {
                            span style="font-family: var(--mono); font-size: 11px; color: var(--acc); margin-right: 4px;" {
                                (tr(lang, "✓ on", "✓ вкл"))
                            }
                        }
                        form method="post"
                             action=(format!("/admin/servers/{}/protocols/{}/disable", sid_enc, path_segment_encode(&pid.0)))
                             style="margin: 0; padding: 0;" {
                            @let dis_proto_title = match lang {
                                crate::i18n::Locale::En => format!("Remove {} from {}.enabled_protocols. Takes effect on next deploy.", pid.0, server.id.0),
                                crate::i18n::Locale::Ru => format!("Убрать {} из {}.enabled_protocols. Применится при следующем деплое.", pid.0, server.id.0),
                            };
                            button type="submit"
                                   title=(dis_proto_title)
                                   style="padding: 2px 8px; border: 1px solid var(--ink); background: transparent; font-family: var(--mono); font-size: 11px; color: var(--ink); cursor: pointer;" {
                                (t(lang, K::BtnDisable))
                            }
                        }
                        @if !compatible {
                            span style="font-family: var(--mono); font-size: 10px; color: var(--mute); font-style: italic;" {
                                (tr(lang, "(disable to clear)", "(выключи чтобы убрать)"))
                            }
                        } @else if is_hidden {
                            form method="post"
                                 action=(format!("/admin/servers/{}/protocols/{}/unhide", sid_enc, path_segment_encode(&pid.0)))
                                 style="margin: 0; padding: 0;" {
                                @let unhide_title = match lang {
                                    crate::i18n::Locale::En => format!("Resume emitting {} in this server's subscription URLs. Live sing-box inbound was never stopped; this just unmutes the render.", pid.0),
                                    crate::i18n::Locale::Ru => format!("Снова отдавать {} в URL подписок этого сервера. Живой sing-box inbound никто не останавливал; это только снимает mute с рендера.", pid.0),
                                };
                                button type="submit"
                                       title=(unhide_title)
                                       style="padding: 2px 8px; border: 1px solid var(--acc); background: var(--acc); color: var(--paper); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                                    (t(lang, K::BtnUnhide))
                                }
                            }
                        } @else {
                            form method="post"
                                 action=(format!("/admin/servers/{}/protocols/{}/hide", sid_enc, path_segment_encode(&pid.0)))
                                 style="margin: 0; padding: 0;" {
                                @let hide_title = match lang {
                                    crate::i18n::Locale::En => format!("Stop emitting {} in this server's subscription URLs WITHOUT removing the live inbound. Existing client URIs keep working until they re-pull.", pid.0),
                                    crate::i18n::Locale::Ru => format!("Перестать отдавать {} в URL подписок этого сервера БЕЗ удаления живого inbound. Закешированные клиентские URI продолжают работать до следующего pull.", pid.0),
                                };
                                button type="submit"
                                       title=(hide_title)
                                       style="padding: 2px 8px; border: 1px solid var(--rule-s); background: transparent; font-family: var(--mono); font-size: 11px; color: var(--mute); cursor: pointer;" {
                                    (t(lang, K::BtnHide))
                                }
                            }
                        }
                    } @else if compatible {
                        span style="font-family: var(--mono); font-size: 11px; color: var(--mute); margin-right: 4px;" {
                            "—"
                        }
                        form method="post"
                             action=(format!("/admin/servers/{}/protocols/{}/enable", sid_enc, path_segment_encode(&pid.0)))
                             style="margin: 0; padding: 0;" {
                            @let en_proto_title = match lang {
                                crate::i18n::Locale::En => format!("Add {} to {}.enabled_protocols. Takes effect on next deploy.", pid.0, server.id.0),
                                crate::i18n::Locale::Ru => format!("Добавить {} в {}.enabled_protocols. Применится при следующем деплое.", pid.0, server.id.0),
                            };
                            button type="submit"
                                   title=(en_proto_title)
                                   style="padding: 2px 8px; border: 1px solid var(--ink); background: var(--ink); color: var(--paper); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                                (t(lang, K::BtnEnable))
                            }
                        }
                    } @else {
                        span style="font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                            (tr(lang, "incompatible", "несовместимо"))
                        }
                    }
                }
            }
        }
    }
}

/// Per-(user, server, protocol) delivery grid — renders inside the
/// "Server access" section of /admin/users/{id}, one block per
/// granted server. Each protocol the server has enabled gets a row
/// with its current delivery state (delivered / user-blocked /
/// server-hidden) and a block/unblock button (no-op for
/// server-hidden rows — those are toggled on /admin/servers/{id}).
///
/// Migration 0018 / NM-10: the two axes are server.hidden (set on
/// server-detail) and grant_protocol_overrides.state='disabled'
/// (set here). Visibility resolution is OR-semantics — either axis
/// suppresses the protocol from this user's subscription URL.
///
/// `hidden_map = None` is treated as an empty map (server has no
/// enabled protocols at all — render an empty-state explainer).
fn user_detail_per_protocol_grid(
    uid: &vpnctl_core::UserId,
    server: &vpnctl_core::Server,
    hidden_map: Option<&std::collections::HashMap<vpnctl_core::ProtocolId, bool>>,
    user_overrides: &std::collections::HashMap<
        (vpnctl_core::ServerId, vpnctl_core::ProtocolId),
        bool,
    >,
    registry: &vpnctl_core::Registry,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    let uid_enc = path_segment_encode(&uid.0);
    let sid_enc = path_segment_encode(&server.id.0);
    // Iterate the `server_protocols` table directly (not the in-memory
    // `enabled_protocols` field) so the OR-semantics deny resolution
    // matches `visible_protocols_for_subscription` BYTE-for-BYTE.
    // Review-agent 2026-05-20: a divergence between the in-memory
    // `enabled_protocols` cache and the on-disk `server_protocols`
    // rows would silently lie about what the operator's clients see
    // on next pull. Sort alphabetically to match the canonical
    // query's `ORDER BY sp.protocol_id`.
    let mut pids: Vec<&vpnctl_core::ProtocolId> =
        hidden_map.map(|m| m.keys().collect()).unwrap_or_default();
    pids.sort_by(|a, b| a.0.cmp(&b.0));
    html! {
        div style="margin: 8px 0 4px 16px; padding: 8px 12px 6px; border-left: 2px solid var(--rule); font-family: var(--mono); font-size: 11px; line-height: 1.6;" {
            div style="color: var(--mute); letter-spacing: 0.14em; text-transform: uppercase; font-size: 10px; margin-bottom: 6px;" {
                (tr(lang, "Per-protocol delivery", "Доставка по протоколам"))
            }
            @if pids.is_empty() {
                p style="font-family: var(--serif); font-style: italic; color: var(--mute); margin: 0; font-size: 12px;" {
                    (tr(
                        lang,
                        "No protocols enabled on this server yet. Add one on the ",
                        "На этом сервере пока ничего не включено. Добавь хотя бы один через ",
                    ))
                    a href=(format!("/admin/servers/{sid_enc}"))
                      target="_blank"
                      rel="noopener"
                      style="color: var(--ink);" {
                        (tr(lang, "server detail page", "страницу сервера"))
                    }
                    (tr(lang, " — then the per-protocol toggles will appear here.", " — тогда тоглы по протоколам появятся здесь."))
                }
            } @else {
                ul style="list-style: none; padding: 0; margin: 0;" {
                    @for pid in &pids {
                        @let is_hidden = hidden_map
                            .and_then(|m| m.get(*pid).copied())
                            .unwrap_or(false);
                        @let is_user_blocked = user_overrides
                            .get(&(server.id.clone(), (*pid).clone()))
                            .copied()
                            .unwrap_or(false);
                        @let pid_enc = path_segment_encode(&pid.0);
                        // NM-12: same registry-driven risk chip the
                        // server-detail uses. Shrinks the protocol
                        // name to 10px (vs 11px row-default) when
                        // Weak — small visual sentence saying "you
                        // shouldn't be delivering this here".
                        @let risk = registry.protocol(pid).map(|p| p.dpi_risk());
                        @let pid_is_weak = matches!(risk, Some(vpnctl_core::DpiRisk::Weak));
                        li style="display: flex; align-items: baseline; gap: 10px; padding: 2px 0;" {
                            span style=(format!(
                                "flex: 1; color: var(--ink); font-size: {};",
                                if pid_is_weak { "10px" } else { "11px" },
                            )) {
                                (pid.0)
                                @if let Some(r) = risk {
                                    " "
                                    span title=(r.tooltip())
                                         style=(format!(
                                             "font-family: var(--mono); font-size: 9px; padding: 0 4px; border: 1px solid {}; color: {}; letter-spacing: 0.04em; margin-left: 2px;",
                                             r.border_css(),
                                             r.text_css(),
                                         )) {
                                        (r.label())
                                    }
                                }
                            }
                            @if is_hidden && is_user_blocked {
                                span style="color: var(--mute);" {
                                    (tr(lang, "server-hidden + user-blocked", "скрыт-на-сервере + заблокирован-у-юзера"))
                                }
                                form method="post"
                                     action=(format!("/admin/users/{uid_enc}/grants/{sid_enc}/protocols/{pid_enc}/enable"))
                                     style="margin: 0;" {
                                    button type="submit"
                                           title=(tr(
                                               lang,
                                               "Clear this user's override. Server-hidden flag remains — adjust on the server detail page.",
                                               "Очистить override этого пользователя. Флаг server-hidden останется — правится на странице сервера.",
                                           ))
                                           style="padding: 1px 6px; border: 1px solid var(--rule-s); background: transparent; color: var(--mute); font-family: var(--mono); font-size: 10px; cursor: pointer;" {
                                        (tr(lang, "unblock (user)", "разблокировать (юзер)"))
                                    }
                                }
                            } @else if is_hidden {
                                span style="color: var(--mute);" {
                                    (tr(lang, "server-hidden (read-only here)", "скрыт на сервере (здесь только чтение)"))
                                }
                            } @else if is_user_blocked {
                                span style="color: var(--acc);" {
                                    (tr(lang, "✗ user-blocked", "✗ заблокирован у юзера"))
                                }
                                form method="post"
                                     action=(format!("/admin/users/{uid_enc}/grants/{sid_enc}/protocols/{pid_enc}/enable"))
                                     style="margin: 0;" {
                                    @let unblock_title = match lang {
                                        crate::i18n::Locale::En => format!("Deliver {} to {} again on {}", pid.0, uid.0, server.id.0),
                                        crate::i18n::Locale::Ru => format!("Начать снова доставлять {} пользователю {} на {}", pid.0, uid.0, server.id.0),
                                    };
                                    button type="submit"
                                           title=(unblock_title)
                                           style="padding: 1px 6px; border: 1px solid var(--ink); background: var(--ink); color: var(--paper); font-family: var(--mono); font-size: 10px; cursor: pointer;" {
                                        (tr(lang, "unblock", "разблокировать"))
                                    }
                                }
                            } @else {
                                span style="color: var(--acc);" { (tr(lang, "✓ delivered", "✓ доставляется")) }
                                form method="post"
                                     action=(format!("/admin/users/{uid_enc}/grants/{sid_enc}/protocols/{pid_enc}/disable"))
                                     style="margin: 0;" {
                                    @let block_title = match lang {
                                        crate::i18n::Locale::En => format!("Stop delivering {} to {} on {} (per-user override; other users keep getting it)", pid.0, uid.0, server.id.0),
                                        crate::i18n::Locale::Ru => format!("Перестать доставлять {} пользователю {} на {} (per-user override; остальным продолжает идти)", pid.0, uid.0, server.id.0),
                                    };
                                    button type="submit"
                                           title=(block_title)
                                           style="padding: 1px 6px; border: 1px solid var(--rule-s); background: transparent; color: var(--mute); font-family: var(--mono); font-size: 10px; cursor: pointer;" {
                                        (tr(lang, "block", "заблокировать"))
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

fn server_detail_drift_section(
    server: &vpnctl_core::Server,
    observed: &std::collections::BTreeSet<(String, u16)>,
    missing: &[(String, u16)],
    extra: &[(String, u16)],
    have_probe: bool,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    let declared: Vec<String> = server
        .enabled_protocols
        .iter()
        .map(|p| p.0.clone())
        .collect();
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow { (tr(lang, "Declared vs observed", "Заявлено vs наблюдается")) }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
            (tr(
                lang,
                "Inventory says this server runs the protocols below; the latest probe sees the listening sockets on the right. Drift in orange.",
                "Инвентарь говорит что этот сервер крутит протоколы ниже; последний probe видит слушающие сокеты справа. Дрейф — оранжевым.",
            ))
        }
        div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px;" {
            div {
                div style="font-family: var(--mono); font-size: 10px; color: var(--mute); letter-spacing: 0.14em; text-transform: uppercase; margin-bottom: 4px;" {
                    (tr(lang, "declared protocols", "заявленные протоколы"))
                }
                @if declared.is_empty() {
                    p style="font-family: var(--serif); font-style: italic; color: var(--mute);" {
                        (tr(lang, "(none in inventory)", "(нет в инвентаре)"))
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
                    (tr(lang, "observed listening sockets", "наблюдаемые слушающие сокеты"))
                }
                @if !have_probe {
                    p style="font-family: var(--serif); font-style: italic; color: var(--mute);" {
                        (tr(lang, "(no probe — chunk 4 pending)", "(probe ещё нет — chunk 4 в очереди)"))
                    }
                } @else if observed.is_empty() {
                    p style="font-family: var(--serif); font-style: italic; color: var(--mute);" {
                        (tr(lang, "(probe ran but no sockets listed)", "(probe прошёл, но сокетов не нашлось)"))
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
                    (tr(lang, "drift detected", "обнаружен дрейф"))
                }
                @if !missing.is_empty() {
                    p style="font-family: var(--serif); font-size: 13px; margin: 4px 0;" {
                        (tr(lang, "Declared but ", "Заявлено, но "))
                        b { (tr(lang, "NOT listening", "НЕ слушает")) } ": "
                        @for (i, (proto, port)) in missing.iter().enumerate() {
                            @if i > 0 { ", " }
                            span.ed-mono { (proto) "/" (port) }
                        }
                    }
                }
                @if !extra.is_empty() {
                    p style="font-family: var(--serif); font-size: 13px; margin: 4px 0;" {
                        (tr(lang, "Listening but ", "Слушает, но "))
                        b { (tr(lang, "NOT declared", "НЕ заявлено")) } ": "
                        @for (i, (proto, port)) in extra.iter().enumerate() {
                            @if i > 0 { ", " }
                            span.ed-mono { (proto) "/" (port) }
                        }
                    }
                }
            }
        } @else if have_probe {
            p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--soft); margin-top: 10px;" {
                (tr(lang, "Declared and observed match. No drift.", "Заявленное и наблюдаемое совпадают. Дрейфа нет."))
            }
        }
    }
}

// ────────────────────────────────────────────────────────────────────────
// Migration 0018 — per-(server, protocol) hide + per-(user, server,
// protocol) deny override. Four POST handlers below mirror the
// inventory API (`set_server_protocol_hidden`, `set_grant_protocol_override`)
// 1:1. Each returns 303 to the originating page (server-detail or
// user-detail) so the operator sees post-mutation state without a
// stale form re-submit risk. Audit row is written by the inventory
// layer inside the same transaction — handler itself does NOT call
// `state.inv.audit()` (avoids double-audit).
//
// Convention: action is implied by the path suffix (`/hide` /
// `/unhide` / `/disable` / `/enable`) rather than a `value=` form
// field — keeps the markup template-side simple (one form per
// action button instead of a hidden input + JS).
// ────────────────────────────────────────────────────────────────────────

/// `POST /admin/servers/{sid}/protocols/{pid}/hide` — flip
/// `server_protocols.hidden = 1` for (sid, pid). Render path
/// (sub.rs + vpn_router.rs) immediately stops emitting this
/// protocol for any user's next subscription pull. Existing
/// cached client URIs keep working (the live sing-box inbound is
/// untouched).
pub(crate) async fn server_protocol_hide(
    State(state): State<AppState>,
    Path((server_id_str, protocol_id_str)): Path<(String, String)>,
) -> Response {
    let sid = vpnctl_core::ServerId(server_id_str.clone());
    let pid = vpnctl_core::ProtocolId(protocol_id_str.clone());
    match state.inv.set_server_protocol_hidden(&sid, &pid, true).await {
        Ok(()) => Redirect::to(&format!(
            "/admin/servers/{}#enabled-protocols",
            path_segment_encode(&server_id_str)
        ))
        .into_response(),
        Err(vpnctl_inventory::SqliteInventoryError::Invalid(msg)) => bad_request(&msg),
        Err(e) => internal_error(anyhow::Error::new(e)),
    }
}

/// `POST /admin/servers/{sid}/protocols/{pid}/unhide` — flip
/// `server_protocols.hidden = 0` for (sid, pid). Render path
/// resumes emitting this protocol on next subscription pull.
pub(crate) async fn server_protocol_unhide(
    State(state): State<AppState>,
    Path((server_id_str, protocol_id_str)): Path<(String, String)>,
) -> Response {
    let sid = vpnctl_core::ServerId(server_id_str.clone());
    let pid = vpnctl_core::ProtocolId(protocol_id_str.clone());
    match state
        .inv
        .set_server_protocol_hidden(&sid, &pid, false)
        .await
    {
        Ok(()) => Redirect::to(&format!(
            "/admin/servers/{}#enabled-protocols",
            path_segment_encode(&server_id_str)
        ))
        .into_response(),
        Err(vpnctl_inventory::SqliteInventoryError::Invalid(msg)) => bad_request(&msg),
        Err(e) => internal_error(anyhow::Error::new(e)),
    }
}

/// `POST /admin/users/{uid}/grants/{sid}/protocols/{pid}/disable` —
/// insert `grant_protocol_overrides` row with `state='disabled'`.
/// Render path skips this protocol for THIS user's subscription
/// while still emitting it for every other user.
pub(crate) async fn grant_protocol_disable(
    State(state): State<AppState>,
    Path((user_id_str, server_id_str, protocol_id_str)): Path<(String, String, String)>,
) -> Response {
    let uid = vpnctl_core::UserId(user_id_str.clone());
    let sid = vpnctl_core::ServerId(server_id_str.clone());
    let pid = vpnctl_core::ProtocolId(protocol_id_str.clone());
    match state
        .inv
        .set_grant_protocol_override(&uid, &sid, &pid, true)
        .await
    {
        Ok(()) => Redirect::to(&format!(
            "/admin/users/{}#server-access",
            path_segment_encode(&user_id_str)
        ))
        .into_response(),
        Err(vpnctl_inventory::SqliteInventoryError::Invalid(msg)) => bad_request(&msg),
        Err(e) => internal_error(anyhow::Error::new(e)),
    }
}

/// `POST /admin/users/{uid}/grants/{sid}/protocols/{pid}/enable` —
/// DELETE the per-user override row, returning the (user, server,
/// protocol) tuple to inherit-from-server-visibility.
pub(crate) async fn grant_protocol_enable(
    State(state): State<AppState>,
    Path((user_id_str, server_id_str, protocol_id_str)): Path<(String, String, String)>,
) -> Response {
    let uid = vpnctl_core::UserId(user_id_str.clone());
    let sid = vpnctl_core::ServerId(server_id_str.clone());
    let pid = vpnctl_core::ProtocolId(protocol_id_str.clone());
    match state
        .inv
        .set_grant_protocol_override(&uid, &sid, &pid, false)
        .await
    {
        Ok(()) => Redirect::to(&format!(
            "/admin/users/{}#server-access",
            path_segment_encode(&user_id_str)
        ))
        .into_response(),
        Err(vpnctl_inventory::SqliteInventoryError::Invalid(msg)) => bad_request(&msg),
        Err(e) => internal_error(anyhow::Error::new(e)),
    }
}

// ────────────────────────────────────────────────────────────────────────
//  Phase 5d unit tests — `format_msk` + `extract_ip_from_label`.
//
//  Live in the impl crate (not `tests/admin_smoke.rs`) because the
//  helpers themselves are file-private and the contracts are tiny;
//  adding axum/maud scaffolding for them would dwarf the asserts.
// ────────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod helper_tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn format_msk_shifts_utc_by_plus_three_hours_and_marks_timezone() {
        // Noon UTC = 15:00 MSK. The MSK literal is part of the
        // contract — see the user-detail Sessions table where the
        // operator needs the timezone to be unambiguous.
        let utc = chrono::Utc.with_ymd_and_hms(2026, 5, 21, 12, 0, 0).unwrap();
        assert_eq!(format_msk(utc), "05-21 15:00 MSK");
    }

    #[test]
    fn format_msk_wraps_across_midnight_when_adding_offset() {
        // 22:30 UTC on 2026-05-21 = 01:30 MSK on 2026-05-22.
        // Date column has to advance too — otherwise the late-night
        // ticks would all look like they happened "yesterday" in MSK.
        let utc = chrono::Utc
            .with_ymd_and_hms(2026, 5, 21, 22, 30, 0)
            .unwrap();
        assert_eq!(format_msk(utc), "05-22 01:30 MSK");
    }

    #[test]
    fn extract_ip_from_label_returns_ip_for_bare_ipv4_port_form() {
        assert_eq!(extract_ip_from_label("1.2.3.4:443"), Some("1.2.3.4"));
        assert_eq!(extract_ip_from_label("10.0.0.1:80"), Some("10.0.0.1"));
    }

    #[test]
    fn extract_ip_from_label_returns_none_for_hostname_form() {
        // Hostname segment contains non-digit, non-dot chars (letters,
        // hyphens) — we leave these as-is because the poller already
        // had a DNS name from sing-box metadata; enriching would just
        // duplicate the host.
        assert!(extract_ip_from_label("www.microsoft.com:443").is_none());
        assert!(extract_ip_from_label("api-v2.example.io:8443").is_none());
    }

    #[test]
    fn extract_ip_from_label_returns_none_for_already_enriched_label() {
        // `hostname:port (ip)` shape produced by Phase 5d enrichment
        // and the server-detail aggregator. The `(ip)` suffix breaks
        // the all-digits port check — the helper should refuse,
        // preventing a second enrichment round (which would render
        // garbage like `hostname:port (ip) (ip)`).
        assert!(extract_ip_from_label("example.com:443 (1.2.3.4)").is_none());
    }

    #[test]
    fn extract_ip_from_label_returns_none_for_ipv6_form() {
        // IPv6 has internal colons. The rsplit_once peels off only
        // the last `:`-segment, and the remainder contains colons
        // which fail the `digit-or-dot` check. Skipping IPv6 is
        // acceptable for Phase 5d — VPN destinations are overwhelmingly
        // v4; v6 support can be added when the cache learns it.
        assert!(extract_ip_from_label("2001:db8::1:8080").is_none());
    }

    #[test]
    fn extract_ip_from_label_returns_none_for_malformed_input() {
        assert!(extract_ip_from_label("no-colon-at-all").is_none());
        assert!(extract_ip_from_label(":443").is_none()); // empty IP
        assert!(extract_ip_from_label("1.2.3.4:").is_none()); // empty port
        assert!(extract_ip_from_label("1.2.3.4:notaport").is_none());
    }

    #[test]
    fn extract_ip_from_label_returns_ip_for_portless_bare_ipv4() {
        // The clash-poller writes the destination_label as just the IP
        // (no colon, no port) when `destination_port` is empty — see
        // `daemon::clash_poller::poll_one_server` portless branch.
        // Those rows must enrich too, otherwise the most opaque ones
        // (UDP / ICMP-style flows with no port metadata) stay as raw IPs.
        assert_eq!(extract_ip_from_label("1.2.3.4"), Some("1.2.3.4"));
        assert_eq!(extract_ip_from_label("10.0.0.1"), Some("10.0.0.1"));
    }

    #[test]
    fn format_msk_iso_emits_full_date_with_msk_marker() {
        // Used on the user-detail «last fetch» tile where the value
        // can be many days old; dropping the year would be ambiguous.
        let utc = chrono::Utc.with_ymd_and_hms(2026, 5, 21, 12, 0, 0).unwrap();
        assert_eq!(format_msk_iso(utc), "2026-05-21 15:00 MSK");
    }

    #[test]
    fn enrich_destination_label_inserts_hostname_for_cache_hit_with_port() {
        let mut cache = std::collections::HashMap::new();
        cache.insert("1.2.3.4".to_string(), Some("example.com".to_string()));
        // Shape parity with `snapshot_cache::aggregate_by_destination`:
        // `host:port (ip)`. Pins the assembly order — would catch any
        // future swap to `ip:port (host)` or dropped port suffix.
        assert_eq!(
            enrich_destination_label("1.2.3.4:443", &cache),
            "example.com:443 (1.2.3.4)"
        );
    }

    #[test]
    fn enrich_destination_label_inserts_hostname_for_cache_hit_portless() {
        let mut cache = std::collections::HashMap::new();
        cache.insert("1.2.3.4".to_string(), Some("example.com".to_string()));
        // Portless variant — when the original label had no `:port`,
        // the enriched form must not invent one.
        assert_eq!(
            enrich_destination_label("1.2.3.4", &cache),
            "example.com (1.2.3.4)"
        );
    }

    #[test]
    fn enrich_destination_label_passes_through_when_cache_misses() {
        let cache = std::collections::HashMap::new();
        // Untouched bare-IP label when the resolver hasn't visited
        // this IP yet — operator still sees the raw IP, not a panic
        // or a "(unknown)" sentinel.
        assert_eq!(
            enrich_destination_label("1.2.3.4:443", &cache),
            "1.2.3.4:443"
        );
    }

    #[test]
    fn enrich_destination_label_passes_through_for_negative_cache_entry() {
        let mut cache = std::collections::HashMap::new();
        cache.insert("1.2.3.4".to_string(), None);
        // Some(None) = resolver tried, got no PTR. The label stays
        // bare-IP rather than emitting `None:port (ip)`.
        assert_eq!(
            enrich_destination_label("1.2.3.4:443", &cache),
            "1.2.3.4:443"
        );
    }

    #[test]
    fn enrich_destination_label_passes_through_for_hostname_label() {
        let mut cache = std::collections::HashMap::new();
        // Even if a hostname accidentally exists in the cache (it
        // shouldn't — keys are IPs), the label is not bare-IP form
        // so extract_ip_from_label refuses and enrichment skips.
        cache.insert(
            "www.microsoft.com".to_string(),
            Some("ms.example".to_string()),
        );
        assert_eq!(
            enrich_destination_label("www.microsoft.com:443", &cache),
            "www.microsoft.com:443"
        );
    }
}
