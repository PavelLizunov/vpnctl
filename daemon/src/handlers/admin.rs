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
    // 2026-05-23 — render in the operator-configured display TZ
    // so «today» matches alerts / audit / chart labels.
    chrono::Utc::now()
        .with_timezone(&display_tz())
        .format("%Y-%m-%d")
        .to_string()
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
                // Logout chip. Visible exit from the persistent
                // session cookie (introduced 2026-05-26 to fix the
                // «постоянно ввожу пароль» loop). Without this, the
                // 30-day cookie has no operator-visible kill switch
                // and rotating identity requires clearing browser
                // cookies by hand.
                " · "
                form method="post"
                     action="/admin/logout"
                     style="display: inline; margin: 0; padding: 0;" {
                    button type="submit"
                           title=(match lang {
                               Locale::En => "Sign out of the admin UI on this device",
                               Locale::Ru => "Выйти из админки на этом устройстве",
                           })
                           style="background: transparent; border: none; cursor: pointer; padding: 0 4px; font-family: var(--mono); font-size: 11px; color: var(--mute); text-decoration: underline;" {
                        (match lang {
                            Locale::En => "logout",
                            Locale::Ru => "выйти",
                        })
                    }
                }
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
                // External JS (CSP `script-src 'self'` forbids inline).
                // Wires `data-sse-url` triggers (SSE-streamed re-deploy)
                // to a live log pane. `defer` so it runs after the DOM
                // parses; absent on pages without a trigger it's inert.
                script src="/admin/assets/admin.js" defer {}
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

/// Parse a dotted version string (`"1.13.12"`, leading `v` tolerated)
/// into a comparable numeric tuple. Non-numeric / missing components
/// read as 0, and we pad to three components so `"1.13"` sorts below
/// `"1.13.1"`. Used by [`kernel_floor_rollup`] to find the fleet's
/// highest sing-box version (the de-facto target) and flag any node
/// below it. Returns `None` for an unparseable string (e.g. empty)
/// so the caller can skip it rather than treat it as `0.0.0`.
fn parse_version_tuple(raw: &str) -> Option<(u64, u64, u64)> {
    let trimmed = raw.trim().trim_start_matches('v');
    if trimmed.is_empty() {
        return None;
    }
    let mut parts = trimmed.split('.');
    // The first component must exist and parse, else the string isn't
    // a version we can reason about.
    let major: u64 = parts.next()?.parse().ok()?;
    let minor: u64 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let patch: u64 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    Some((major, minor, patch))
}

/// Extract the `"sing-box"` version from a server's
/// `kernel_versions_json` blob (e.g. `{"sing-box":"1.13.12",…}`).
/// Returns `None` for `None` JSON, malformed JSON, or a missing
/// `sing-box` key. Shared by the fleet-at-a-glance version column
/// (dash#1) and the kernel-floor rollup (dash#3).
fn sing_box_version_of(kernel_versions_json: Option<&str>) -> Option<String> {
    let raw = kernel_versions_json?;
    let val: serde_json::Value = serde_json::from_str(raw).ok()?;
    val.get("sing-box")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// PR-Dash dash#3 (SHARED — PR-Server reuses this on the per-server
/// detail page) — fleet kernel-floor rollup.
///
/// Treats the **highest** sing-box version present anywhere in the
/// fleet as the de-facto target (the "floor" the operator should pull
/// everyone up to). Renders «sing-box N/M @ {floor} ✓ · K stale ⚠»
/// where N = servers already at the floor, M = servers reporting any
/// version, K = servers below it. When a fleet-wide kernel-update
/// action exists it links there — for the dashboard (static, CSP: no
/// inline JS) we link to /admin/servers where the SSE «update all
/// kernels» button lives. Renders the empty-state line when no node
/// has reported a version yet (quiet, no scary "0/0").
///
/// `kernel_versions` is `(ServerId, Option<kernel_versions_json>)` —
/// exactly the shape `kernel_versions_fleet()` (Q-4e) returns, so both
/// call sites pass it straight through.
fn kernel_floor_rollup(
    kernel_versions: &[(vpnctl_core::ServerId, Option<String>)],
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::{K, t, tr};
    // Collect (server, parsed-version) only for servers that report a
    // sing-box version we can parse.
    let mut versioned: Vec<(u64, u64, u64)> = Vec::new();
    for (_, json) in kernel_versions {
        if let Some(v) = sing_box_version_of(json.as_deref()) {
            if let Some(tuple) = parse_version_tuple(&v) {
                versioned.push(tuple);
            }
        }
    }
    let reporting = versioned.len();
    let Some(floor) = versioned.iter().copied().max() else {
        // No node reported a parseable version. Quiet empty-state.
        return html! {
            section id="kernel-rollup" style="margin-top: 28px;" {
                div.ed-art-eyebrow { (t(lang, K::EyebrowKernelRollup)) }
                p style="font-family: var(--serif); font-style: italic; color: var(--mute); margin: 6px 0 0;" {
                    (t(lang, K::KernelRollupNoData))
                }
            }
        };
    };
    let at_floor = versioned.iter().filter(|v| **v == floor).count();
    let stale = reporting.saturating_sub(at_floor);
    let floor_str = format!("{}.{}.{}", floor.0, floor.1, floor.2);
    let all_current = stale == 0;

    html! {
        section id="kernel-rollup" style="margin-top: 28px;" {
            div.ed-art-eyebrow { (t(lang, K::EyebrowKernelRollup)) }
            p style="font-family: var(--serif); font-size: 15px; margin: 8px 0 0;" {
                "sing-box "
                b { (at_floor) "/" (reporting) }
                " @ "
                span.ed-mono { (floor_str) }
                " "
                @if all_current {
                    span style="color: #2e7d32;" {
                        "✓ " (t(lang, K::KernelRollupOnTarget))
                    }
                } @else {
                    span style="color: var(--acc);" {
                        "· " (stale) " " (t(lang, K::KernelRollupStale)) " ⚠"
                    }
                }
            }
            // When something is stale, point the operator at the place
            // where the fleet-wide «update all kernels» action lives.
            // The dashboard is static (CSP: no inline JS), so we LINK to
            // /admin/servers rather than embed the SSE button here.
            @if !all_current {
                p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 0;" {
                    (tr(
                        lang,
                        "Some nodes trail the newest sing-box on the fleet. Roll the binary forward from ",
                        "Часть нод отстаёт от самой свежей sing-box во флоте. Раскатать бинарь можно из раздела ",
                    ))
                    a href="/admin/servers" style="color: var(--ink);" {
                        (tr(lang, "Servers", "Серверы"))
                    }
                    (tr(
                        lang,
                        " — the «update all kernels» action upgrades binaries without touching config.",
                        " — действие «обновить все ядра» обновляет бинарники без правки конфига.",
                    ))
                }
            }
        }
    }
}

/// PR-Dash dash#1 — fleet-at-a-glance table. One row per server:
/// sing-box up · disk% · mem% · active conns now · 24h traffic ·
/// sing-box version · last-probe age. Every input is pre-loaded by the
/// caller (the at-a-glance card adds NO new N+1 beyond the existing
/// fleet-uptime loop). Empty cells render «—».
///
/// * `latest_health` — newest `node_health` row per server (disk/mem/
///   up + probe ts), looked up in the same loop as fleet-uptime.
/// * `active_conns` — live clash-api connection count per server from
///   the in-memory snapshot cache (no DB round-trip).
/// * `traffic_24h` — server-wide upload+download bytes over the last
///   24h, weighted by `usage_coefficient`, summed from the already-
///   loaded `recent_vpn_stats_fleet` rows.
/// * `kernel_versions` — newest `kernel_versions_json` per server (the
///   sing-box version column).
#[allow(clippy::too_many_arguments)]
fn dashboard_fleet_table(
    servers: &[vpnctl_core::Server],
    latest_health: &[(
        vpnctl_core::ServerId,
        Option<vpnctl_inventory::NodeHealthRow>,
    )],
    active_conns: &[(vpnctl_core::ServerId, Option<usize>)],
    traffic_24h: &std::collections::HashMap<vpnctl_core::ServerId, u64>,
    kernel_versions: &[(vpnctl_core::ServerId, Option<String>)],
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    if servers.is_empty() {
        // No fleet yet — the dashboard metrics deck + the servers page
        // already cover the "add a server" call-to-action; staying
        // quiet here avoids a third empty table.
        return html! {};
    }
    let now = chrono::Utc::now();
    let dash = "—";
    let th = |label: &str, right: bool| -> Markup {
        let align = if right { "right" } else { "left" };
        html! {
            th style=(format!("text-align: {align}; padding: 5px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;")) {
                (label)
            }
        }
    };
    html! {
        section id="fleet-at-a-glance" style="margin-top: 28px;" {
            div.ed-art-eyebrow {
                (tr(lang, "Fleet at a glance", "Флот одним взглядом"))
            }
            p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 12px;" {
                (tr(
                    lang,
                    "One row per server — sing-box state, disk and memory pressure, live connections, traffic over the last 24h, the on-node sing-box version and how fresh the last health probe is. Open a server for the full drill-in.",
                    "Одна строка на сервер — состояние sing-box, нагрузка диска и памяти, живые подключения, трафик за 24ч, версия sing-box на ноде и свежесть последней проверки здоровья. Открой сервер для детального разбора.",
                ))
            }
            table style="width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 11.5px;" {
                thead {
                    tr style="border-bottom: 1px solid var(--ink);" {
                        (th(tr(lang, "server", "сервер"), false))
                        (th(tr(lang, "sing-box", "sing-box"), false))
                        (th(tr(lang, "disk", "диск"), true))
                        (th(tr(lang, "mem", "память"), true))
                        (th(tr(lang, "conns now", "подкл."), true))
                        (th(tr(lang, "traffic 24h", "трафик 24ч"), true))
                        (th(tr(lang, "version", "версия"), true))
                        (th(tr(lang, "last probe", "проверка"), true))
                    }
                }
                tbody {
                    @for s in servers {
                        @let health = latest_health
                            .iter()
                            .find(|(id, _)| *id == s.id)
                            .and_then(|(_, h)| h.as_ref());
                        @let conns = active_conns
                            .iter()
                            .find(|(id, _)| *id == s.id)
                            .and_then(|(_, c)| *c);
                        @let kv = kernel_versions
                            .iter()
                            .find(|(id, _)| *id == s.id)
                            .and_then(|(_, j)| sing_box_version_of(j.as_deref()));
                        @let traffic = traffic_24h.get(&s.id).copied();
                        tr style="border-bottom: 1px dotted var(--rule);" {
                            td style="padding: 4px 8px;" {
                                a href=(format!("/admin/servers/{}", path_segment_encode(&s.id.0))) style="color: var(--ink); text-decoration: none;" { (s.id.0) }
                            }
                            // sing-box up/down/unknown.
                            td style="padding: 4px 8px;" {
                                @match health.and_then(|h| h.sing_box_active) {
                                    Some(true) => span style="color: #2e7d32;" { (tr(lang, "up", "работает")) },
                                    Some(false) => span style="color: #c62828;" { (tr(lang, "down", "не работает")) },
                                    None => span style="color: var(--mute);" { (dash) },
                                }
                            }
                            // disk %.
                            td style="padding: 4px 8px; text-align: right;" {
                                @match health.and_then(pct_disk) {
                                    Some(p) => span style=(format!("color: {};", utilization_color(p))) { (p) "%" },
                                    None => span style="color: var(--mute);" { (dash) },
                                }
                            }
                            // mem %.
                            td style="padding: 4px 8px; text-align: right;" {
                                @match health.and_then(pct_mem) {
                                    Some(p) => span style=(format!("color: {};", utilization_color(p))) { (p) "%" },
                                    None => span style="color: var(--mute);" { (dash) },
                                }
                            }
                            // active conns now.
                            td style="padding: 4px 8px; text-align: right;" {
                                @match conns {
                                    Some(c) => (c),
                                    None => span style="color: var(--mute);" { (dash) },
                                }
                            }
                            // 24h traffic.
                            td style="padding: 4px 8px; text-align: right;" {
                                @match traffic {
                                    Some(b) => (humanize_bytes(b)),
                                    None => span style="color: var(--mute);" { (dash) },
                                }
                            }
                            // sing-box version.
                            td style="padding: 4px 8px; text-align: right;" {
                                @match kv {
                                    Some(v) => (v),
                                    None => span style="color: var(--mute);" { (dash) },
                                }
                            }
                            // last-probe age.
                            td style="padding: 4px 8px; text-align: right; color: var(--mute);" {
                                @match health.map(|h| h.ts) {
                                    Some(ts) => (humanize_age(now - ts, lang)),
                                    None => span style="color: var(--mute);" { (dash) },
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// disk-used percentage from a health row, `None` when the probe
/// didn't carry both numerator + denominator. Floors a `>100%` reading
/// (impossible but defensive) at 100.
fn pct_disk(h: &vpnctl_inventory::NodeHealthRow) -> Option<u8> {
    let (used, total) = (h.disk_used_mib?, h.disk_total_mib?);
    if total == 0 {
        return None;
    }
    Some(((used.saturating_mul(100)) / total).min(100) as u8)
}

/// mem-USED percentage (`100 − available/total`) from a health row.
/// `None` when the probe lacked the figures.
fn pct_mem(h: &vpnctl_inventory::NodeHealthRow) -> Option<u8> {
    let (avail, total) = (h.mem_available_mib?, h.mem_total_mib?);
    if total == 0 {
        return None;
    }
    let free_pct = ((avail.saturating_mul(100)) / total).min(100) as u8;
    Some(100u8.saturating_sub(free_pct))
}

/// Colour bucket for a *utilization* percentage (disk-used / mem-used),
/// where HIGH is bad — distinct from `pct_color`, whose thresholds are
/// tuned for uptime where HIGH is good. Green below 70% used, amber
/// 70–89%, red at 90%+. Standard ops headroom convention so the
/// at-a-glance table reads "is this node tight on resources?" correctly.
fn utilization_color(used_pct: u8) -> &'static str {
    match used_pct {
        0..=69 => "#2e7d32",  // green — comfortable headroom
        70..=89 => "#e6a23c", // amber — getting tight
        _ => "#c62828",       // red — 90%+ used
    }
}

/// Compact "how long ago" string for the last-probe column. Buckets to
/// seconds / minutes / hours / days — the operator wants "is this
/// stale?" at a glance, not millisecond precision. Negative durations
/// (clock skew between probe write + render) clamp to «just now».
fn humanize_age(d: chrono::Duration, lang: crate::i18n::Locale) -> String {
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

/// PR-Dash dash#2 — real fleet traffic totals beside the activity
/// chart. Sums upload + download bytes over the picked window
/// (weighted by `usage_coefficient`) and the prior equal-length window,
/// reporting the window total ↑↓ plus a Δ% vs the prior window. Reuses
/// the already-loaded `recent_vpn_stats_fleet` rows — the caller passes
/// rows for TWICE the window so this fn can split current vs prior
/// Rust-side without a second query.
///
/// `coeffs` maps each server to its `usage_coefficient`; unknown
/// servers default to 1.0.
fn dashboard_fleet_traffic_totals(
    rows: &[vpnctl_inventory::VpnStatsRow],
    coeffs: &std::collections::HashMap<vpnctl_core::ServerId, f64>,
    window: VpnSparklineWindow,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    use chrono::Utc;
    let window_hours = (window.cells * window.bucket_hours) as i64;
    let now = Utc::now();
    let cur_start = now - chrono::Duration::hours(window_hours);
    let prior_start = now - chrono::Duration::hours(window_hours * 2);

    // Only the server-wide rows (user_id IS NULL) carry the full
    // node traffic — per-user rows are a SUBSET of the same bytes, so
    // summing both would double-count. Match `vpn_traffic_chart`'s
    // intent: server-wide totals.
    let weight = |sid: &vpnctl_core::ServerId| -> f64 { coeffs.get(sid).copied().unwrap_or(1.0) };
    let mut cur_up = 0f64;
    let mut cur_dn = 0f64;
    let mut prior_total = 0f64;
    for r in rows {
        if r.user_id.is_some() {
            continue;
        }
        let w = weight(&r.server_id);
        let up = r.upload_bytes as f64 * w;
        let dn = r.download_bytes as f64 * w;
        if r.ts >= cur_start {
            cur_up += up;
            cur_dn += dn;
        } else if r.ts >= prior_start {
            prior_total += up + dn;
        }
    }
    let cur_total = cur_up + cur_dn;
    // Δ% vs the prior equal window. None when the prior window had no
    // traffic (division by zero / "new baseline" — can't compute a
    // meaningful percentage from zero).
    let delta_pct: Option<i64> = if prior_total > 0.0 {
        Some((((cur_total - prior_total) / prior_total) * 100.0).round() as i64)
    } else {
        None
    };
    let window_label = match lang {
        crate::i18n::Locale::En => window.label_en,
        crate::i18n::Locale::Ru => window.label_ru,
    };

    html! {
        div style="margin-top: 12px; display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px;" {
            div title=(tr(lang, "Upload bytes (client → server) summed across the fleet over the window, weighted by each server's usage coefficient.", "Upload-байты (клиент → сервер), суммированные по флоту за окно, с учётом коэффициента трафика каждого сервера.")) {
                (status_tile(&format!("↑ {} {}", tr(lang, "upload", "отправка"), window_label), &humanize_bytes(cur_up as u64), "var(--ink)"))
            }
            div title=(tr(lang, "Download bytes (server → client) summed across the fleet over the window, weighted by each server's usage coefficient.", "Download-байты (сервер → клиент), суммированные по флоту за окно, с учётом коэффициента трафика каждого сервера.")) {
                (status_tile(&format!("↓ {} {}", tr(lang, "download", "загрузка"), window_label), &humanize_bytes(cur_dn as u64), "var(--ink)"))
            }
            div title=(tr(lang, "Total traffic this window vs the previous equal-length window.", "Суммарный трафик за это окно против предыдущего окна такой же длины.")) {
                @match delta_pct {
                    Some(p) if p > 0 => (status_tile(tr(lang, "vs prior", "против пред."), &format!("+{p}%"), "#c62828")),
                    Some(p) if p < 0 => (status_tile(tr(lang, "vs prior", "против пред."), &format!("{p}%"), "#2e7d32")),
                    Some(_) => (status_tile(tr(lang, "vs prior", "против пред."), "0%", "var(--mute)")),
                    None => (status_tile(tr(lang, "vs prior", "против пред."), "—", "var(--mute)")),
                }
            }
        }
    }
}

/// PR-Dash dash#4 — open-alerts breakdown by severity + kind. Replaces
/// the count-only `dashboard_alerts_tile`: shows «critical N · warn M»
/// plus the top alert kinds. Keeps the quiet-dashboard contract —
/// renders nothing when there are zero unacked alerts. Links to
/// /admin/alerts for the full feed.
fn dashboard_alerts_breakdown(
    by_kind_sev: &[(String, String, u64)],
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    if by_kind_sev.is_empty() {
        // Quiet dashboard — no unacked alerts, no card.
        return html! {};
    }
    // Severity totals across all kinds.
    let sev_total = |sev: &str| -> u64 {
        by_kind_sev
            .iter()
            .filter(|(_, s, _)| s.eq_ignore_ascii_case(sev))
            .map(|(_, _, n)| *n)
            .fold(0u64, u64::saturating_add)
    };
    let critical = sev_total("critical");
    let warn = sev_total("warning") + sev_total("warn");
    let total: u64 = by_kind_sev
        .iter()
        .map(|(_, _, n)| *n)
        .fold(0u64, u64::saturating_add);

    // Top kinds by count — `alerts_by_kind_severity` already sorts
    // DESC by count, but a kind can span severities, so re-aggregate
    // per kind and take the top 3.
    let mut per_kind: Vec<(String, u64)> = Vec::new();
    for (kind, _, n) in by_kind_sev {
        if let Some(entry) = per_kind.iter_mut().find(|(k, _)| k == kind) {
            entry.1 = entry.1.saturating_add(*n);
        } else {
            per_kind.push((kind.clone(), *n));
        }
    }
    per_kind.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    per_kind.truncate(3);

    html! {
        div style="margin: 18px 0 0; padding: 14px 16px; border: 1px solid var(--rule); border-left: 3px solid var(--accent); background: var(--paper-tint);" {
            div.ed-art-eyebrow { (tr(lang, "Homelab health · open alerts", "Здоровье homelab · открытые алерты")) }
            p style="font-family: var(--serif); margin: 6px 0 0;" {
                @if critical > 0 {
                    span style="color: #c62828; font-weight: 600;" {
                        (tr(lang, "critical ", "критич. ")) (critical)
                    }
                    " · "
                }
                @if warn > 0 {
                    span style="color: var(--acc); font-weight: 600;" {
                        (tr(lang, "warn ", "предупр. ")) (warn)
                    }
                    " · "
                }
                // If neither critical nor warn matched (e.g. only "info"
                // severity), still surface the raw total so the operator
                // isn't left with an empty headline.
                @if critical == 0 && warn == 0 {
                    b { (total) }
                    (tr(lang, " open", " открытых"))
                    " · "
                }
                a href="/admin/alerts" style="color: var(--ink);" {
                    em { (tr(lang, "see the full feed →", "смотреть весь поток →")) }
                }
            }
            // Top kinds line.
            p style="font-family: var(--mono); font-size: 11px; color: var(--mute); margin: 8px 0 0;" {
                (tr(lang, "top: ", "топ: "))
                @for (i, (kind, n)) in per_kind.iter().enumerate() {
                    @if i > 0 { " · " }
                    (kind) " (" (n) ")"
                }
            }
        }
    }
}

/// PR-Dash dash#5 — abuse summary. Surfaces subs that look shared (one
/// Localized chip text for one sharing-risk reason (the carried value +
/// a short unit). The scorer orders reasons strongest-first, so the lead
/// chip is the smoking gun (concurrent IPs / impossible travel).
fn sharing_reason_label(
    r: crate::sharing_score::SharingReason,
    lang: crate::i18n::Locale,
) -> String {
    use crate::i18n::tr;
    use crate::sharing_score::SharingReason as R;
    match r {
        R::ConcurrentNets(n) => {
            format!("{n} {}", tr(lang, "networks at once", "сетей одновременно"))
        }
        R::DailyNets(n) => format!("{n} {}", tr(lang, "networks/day", "сетей/день")),
        R::ImpossibleTravel(h) => {
            format!(
                "{h}× {}",
                tr(lang, "impossible travel", "невозможн. перемещ.")
            )
        }
    }
}

/// PR-Dash dash#5 — account-sharing risk summary (redesigned 2026-06-17 to
/// a composite, explainable score; replaces the bare `distinct_asns >= 3`).
/// Each row shows the user, a 0-100 risk score (red=High, amber=Medium) and
/// the reasons that fired (strongest first: simultaneous IPs, impossible
/// travel, per-day IPs, client-app spread, …). Renders nothing when no user
/// reaches `FLAG_THRESHOLD` (quiet dashboard).
fn dashboard_abuse_summary(
    likely_shared: &[(vpnctl_core::UserId, crate::sharing_score::SharingScore)],
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    use crate::sharing_score::SharingLevel;
    // Defensive: skip any empty id so this render can NEVER emit a nameless
    // link to `/admin/users/`.
    let rows: Vec<&(vpnctl_core::UserId, crate::sharing_score::SharingScore)> = likely_shared
        .iter()
        .filter(|(uid, _)| !uid.0.is_empty())
        .collect();
    if rows.is_empty() {
        return html! {};
    }
    let n = rows.len();
    html! {
        div style="margin: 18px 0 0; padding: 14px 16px; border: 1px solid var(--rule); border-left: 3px solid var(--accent); background: var(--paper-tint);" {
            div.ed-art-eyebrow style="color: var(--acc);" {
                (tr(lang, "Likely-shared subscriptions", "Похоже на расшаренные подписки"))
            }
            p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 10px;" {
                b { (n) }
                @if n == 1 {
                    (tr(lang, " subscription looks shared", " подписка похожа на расшаренную"))
                } @else {
                    (tr(lang, " subscriptions look shared", " подписок похожи на расшаренные"))
                }
                (tr(
                    lang,
                    " — risk score weights SIMULTANEOUS client IPs + impossible travel far above mere network diversity (a traveller's home + mobile + work no longer trips it). Open a row to rotate the token.",
                    " — риск-скор взвешивает ОДНОВРЕМЕННЫЕ клиентские IP + невозможные перемещения намного выше простого разнообразия сетей (дом + мобильный + работа путешественника больше не срабатывают). Открой строку, чтобы сменить токен.",
                ))
            }
            ul style="list-style: none; padding: 0; font-family: var(--mono); font-size: 12px; line-height: 1.8;" {
                @for (uid, sc) in &rows {
                    li style="display: flex; align-items: baseline; gap: 10px; padding: 4px 0; border-bottom: 1px dotted var(--rule);" {
                        span style=(format!(
                            "font-weight: 700; min-width: 26px; text-align: right; color: {};",
                            if sc.level == SharingLevel::High { "#b00020" } else { "#9a6700" }
                        )) {
                            (sc.score)
                        }
                        // Link to the user's "Subscription origins" section.
                        a href=(format!("/admin/users/{}/activity#origins", path_segment_encode(&uid.0)))
                          style="color: var(--ink); text-decoration: none; font-weight: 600; flex: 1;" {
                            (uid.0)
                        }
                        span style="color: var(--mute);" {
                            @for (i, reason) in sc.reasons.iter().take(3).enumerate() {
                                @if i > 0 { " · " }
                                (sharing_reason_label(*reason, lang))
                            }
                        }
                    }
                }
            }
        }
    }
}

/// PR-Dash dash#6 — "today so far" digest. «Today: N added · M grants
/// changed · K deploys» from the audit log (Q-4g). Renders nothing
/// when every count is zero (quiet dashboard). Sits near the metrics
/// deck so it reads as a one-line "what changed today" banner.
fn dashboard_today_digest(
    digest: &vpnctl_inventory::TodayDigest,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    if digest.users_added == 0 && digest.grants_changed == 0 && digest.deploys == 0 {
        return html! {};
    }
    // Build the parts so the separators don't dangle when a count is 0.
    html! {
        div style="margin: 14px 0 0; padding: 10px 14px; border: 1px solid var(--rule); border-left: 3px solid var(--accent); background: var(--paper);" {
            p style="font-family: var(--serif); font-size: 13px; margin: 0;" {
                b { (tr(lang, "Today: ", "Сегодня: ")) }
                @if digest.users_added > 0 {
                    b { (digest.users_added) }
                    @if digest.users_added == 1 {
                        (tr(lang, " user added", " пользователь добавлен"))
                    } @else {
                        (tr(lang, " users added", " пользователей добавлено"))
                    }
                }
                @if digest.grants_changed > 0 {
                    @if digest.users_added > 0 { " · " }
                    b { (digest.grants_changed) }
                    (tr(lang, " grants changed", " доступов изменено"))
                }
                @if digest.deploys > 0 {
                    @if digest.users_added > 0 || digest.grants_changed > 0 { " · " }
                    b { (digest.deploys) }
                    @if digest.deploys == 1 {
                        (tr(lang, " deploy", " деплой"))
                    } @else {
                        (tr(lang, " deploys", " деплоев"))
                    }
                }
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
                        span.ed-time-row__t { (format_msk_iso(e.ts)) }
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

// `clip_ts` helper removed 2026-05-23 — all UI timestamp callers
// now use `format_msk_iso` to render in operator-friendly MSK
// timezone with explicit «MSK» marker. The previous helper trimmed
// an RFC3339 UTC string without any timezone conversion, which
// surfaced as UTC times in: dashboard recent activity, idle-users
// panel, /admin/audit timeline, /admin/alerts feed, user-detail
// sub-access log. CSV export (audit.csv) keeps `to_rfc3339()`
// directly — ISO format is the correct interchange for external
// tools.

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

/// Dashboard URL query — currently just the VPN traffic chart's
/// window selector (`?vpn_window=24h|7d|30d|all`). Defaults to 24h.
#[derive(serde::Deserialize, Default)]
pub(crate) struct DashboardQuery {
    pub vpn_window: Option<String>,
}

pub(crate) async fn dashboard(
    headers: HeaderMap,
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<DashboardQuery>,
) -> Result<Markup, Response> {
    let (theme, accent, lang) = theme_accent_lang(&headers);
    // 2026-05-23 — ONE window picker drives every time-series
    // tile on the dashboard: VPN activity, Heavy users, Fleet
    // traffic chart. Single source of truth in
    // VPN_SPARKLINE_WINDOWS; bookmarkable URL via
    // `?vpn_window=24h|7d|30d|all`.
    let window = pick_vpn_sparkline_window(query.vpn_window.as_deref());
    let since_hours = window.cells * window.bucket_hours;
    // PR-Dash dash#2 — pull TWICE the window so the real-traffic card
    // can compute Δ% vs the prior equal-length window Rust-side (no
    // second query). The chart below only buckets rows inside the
    // visible window — older rows fall outside its `buckets_ago` range
    // and are ignored — so the wider pull is free for the chart.
    let fleet_rows = state
        .inv
        .recent_vpn_stats_fleet(since_hours.saturating_mul(2))
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(target = "vpnctld::admin", error = %e, "recent_vpn_stats_fleet failed");
            Vec::new()
        });

    let (stats, audit) = collect_dashboard_data(&state)
        .await
        .map_err(internal_error)?;

    // Heavy users — top-5 bandwidth consumers over the selected
    // window (was hardcoded 24h pre-2026-05-23). Same data source
    // as before; tile heading + caption reflect the chosen window.
    let heavy_users = state
        .inv
        .top_users_by_traffic(since_hours, 5)
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

    // PR-Dash dash#4 replaced the count-only «unacked alerts» tile with
    // the (kind, severity) breakdown loaded below — `unacked_alert_count`
    // is no longer queried on the dashboard path.

    // Phase 4b — per-server live activity rollup for the dashboard
    // «VPN activity» tile. ONE call returns one entry per known
    // server (defaults to zeros for unpolled servers); we sum +
    // pass the per-server breakdown to the renderer.
    let live_activity = state.inv.all_servers_live_activity(since_hours).await.unwrap_or_else(|e| {
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
    // PR-Dash dash#1 — server list reused by BOTH the fleet-uptime
    // loop AND the new fleet-at-a-glance table. Loaded ONCE here so
    // the at-a-glance card adds no second N+1 beyond the existing
    // per-server uptime loop budget.
    let server_list_fleet = state.inv.list_servers().await.unwrap_or_else(|e| {
        tracing::warn!(target = "vpnctld::admin", error = %e, "list_servers (fleet) failed");
        Vec::new()
    });

    let fleet_uptime = {
        let mut rows: Vec<(
            vpnctl_core::ServerId,
            [Option<vpnctl_inventory::UptimeStat>; 3],
        )> = Vec::with_capacity(server_list_fleet.len());
        for s in &server_list_fleet {
            let u24h = state.inv.uptime_for_server(&s.id, 24).await.ok();
            let u7d = state.inv.uptime_for_server(&s.id, 24 * 7).await.ok();
            let u30d = state.inv.uptime_for_server(&s.id, 24 * 30).await.ok();
            rows.push((s.id.clone(), [u24h, u7d, u30d]));
        }
        rows
    };

    // PR-Dash — newest kernel-versions JSON per server (Q-4e). Backs
    // BOTH the fleet-at-a-glance "sing-box version" column (dash#1) AND
    // the kernel-floor rollup card (dash#3). One grouped query.
    let kernel_versions = state.inv.kernel_versions_fleet().await.unwrap_or_else(|e| {
        tracing::warn!(target = "vpnctld::admin", error = %e, "kernel_versions_fleet failed");
        Vec::new()
    });

    // PR-Dash dash#1 — latest node-health snapshot per server, for the
    // at-a-glance disk%/mem%/up/last-probe columns. Reuses the existing
    // fleet loop budget (same `server_list_fleet`, no extra list query).
    let latest_health_per_server = {
        let mut out: Vec<(
            vpnctl_core::ServerId,
            Option<vpnctl_inventory::NodeHealthRow>,
        )> = Vec::with_capacity(server_list_fleet.len());
        for s in &server_list_fleet {
            let h = state.inv.latest_node_health(&s.id).await.unwrap_or_else(|e| {
                tracing::warn!(target = "vpnctld::admin", server = %s.id, error = %e, "latest_node_health failed");
                None
            });
            out.push((s.id.clone(), h));
        }
        out
    };

    // PR-Dash dash#1 — "active conns now" per server, read from the
    // in-memory clash-api snapshot cache (no DB round-trip). `None`
    // when the poller has never reached the server.
    let active_conns_now: Vec<(vpnctl_core::ServerId, Option<usize>)> = server_list_fleet
        .iter()
        .map(|s| {
            let n = state
                .snapshot_cache
                .get(&s.id)
                .map(|snap| snap.snapshot.connections.len());
            (s.id.clone(), n)
        })
        .collect();

    // PR-Dash dash#4 — open-alerts breakdown by (kind, severity) (Q-4f).
    // Replaces the count-only tile. Keeps the quiet-dashboard contract:
    // empty Vec ⇒ the card renders nothing.
    let alerts_breakdown = state
        .inv
        .alerts_by_kind_severity()
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(target = "vpnctld::admin", error = %e, "alerts_by_kind_severity failed");
            Vec::new()
        });

    // PR-Dash dash#5 (redesigned 2026-06-17) — composite account-sharing
    // risk. Gather raw signals fleet-wide over the retention window, score
    // each (simultaneity-weighted), keep only flagged users, strongest
    // first. Empty ⇒ card hidden.
    const SHARING_WINDOW_DAYS: u32 = 30;
    const IMPOSSIBLE_TRAVEL_HOURS: f64 = 2.0;
    let mut likely_shared: Vec<(vpnctl_core::UserId, crate::sharing_score::SharingScore)> = state
        .inv
        .sharing_signals_all_users(SHARING_WINDOW_DAYS, IMPOSSIBLE_TRAVEL_HOURS)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(target = "vpnctld::admin", error = %e, "sharing_signals_all_users failed");
            Vec::new()
        })
        .into_iter()
        .map(|s| {
            let sc = crate::sharing_score::score(&s);
            (s.user_id, sc)
        })
        .filter(|(_, sc)| sc.is_flagged())
        .collect();
    likely_shared.sort_by_key(|b| std::cmp::Reverse(b.1.score));

    // PR-Dash dash#6 — "today so far" digest from the audit log (Q-4g).
    // All-zero ⇒ card hidden (quiet dashboard).
    let today_digest = state.inv.today_digest().await.unwrap_or_else(|e| {
        tracing::warn!(target = "vpnctld::admin", error = %e, "today_digest failed");
        vpnctl_inventory::TodayDigest::default()
    });

    // PR-Dash — per-server usage coefficients (for the weighted traffic
    // sums in dash#1 + dash#2). Built from the already-loaded server
    // list; no extra query.
    let coeffs: std::collections::HashMap<vpnctl_core::ServerId, f64> = server_list_fleet
        .iter()
        .map(|s| (s.id.clone(), s.usage_coefficient))
        .collect();

    // PR-Dash dash#1 — fixed 24h server-wide traffic per server (the
    // "traffic 24h" column is independent of the window picker).
    // Summed Rust-side from the already-loaded `fleet_rows` (which span
    // 2× the picked window ⊇ 24h for every window ≥ 24h; for narrower
    // pulls we just sum whatever 24h subset is present), weighted by
    // usage coefficient. Server-wide rows only (user_id IS NULL) so we
    // don't double-count the per-user subset.
    let traffic_24h: std::collections::HashMap<vpnctl_core::ServerId, u64> = {
        let cutoff = chrono::Utc::now() - chrono::Duration::hours(24);
        let mut map: std::collections::HashMap<vpnctl_core::ServerId, u64> =
            std::collections::HashMap::new();
        for r in &fleet_rows {
            if r.user_id.is_some() || r.ts < cutoff {
                continue;
            }
            let w = coeffs.get(&r.server_id).copied().unwrap_or(1.0);
            let bytes = (r.upload_bytes.saturating_add(r.download_bytes) as f64 * w) as u64;
            let entry = map.entry(r.server_id.clone()).or_insert(0);
            *entry = entry.saturating_add(bytes);
        }
        map
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
        // PR-Dash dash#6 — "today so far" digest, near the metrics deck.
        (dashboard_today_digest(&today_digest, lang))
        // PR-Dash dash#1 — fleet-at-a-glance table, after the metrics
        // deck and before the window picker.
        (dashboard_fleet_table(&server_list_fleet, &latest_health_per_server, &active_conns_now, &traffic_24h, &kernel_versions, lang))
        // 2026-05-23 — global time-window picker. ONE control
        // drives VPN activity + Heavy users + Fleet traffic chart.
        // Tabs use #timeframe anchor so click → scroll back to
        // picker (not page top). Date range follows in a separate
        // commit (Pavel «таки конкретного таймфрема, то есть
        // промежутка дать» — picker shows them via tabs first,
        // arbitrary from/to next session).
        (window_picker_section("/admin/", window.slug, lang))
        (dashboard_fleet_uptime(&fleet_uptime, lang))
        (dashboard_vpn_activity(&live_activity, window, lang))
        // Fleet-wide traffic chart. Uses the same `window` the
        // tiles above use — single picker, three tiles, one
        // mental model.
        div id="vpn-traffic" style="margin-top: 24px;" {
            div.ed-art-eyebrow {
                (crate::i18n::tr(lang, "Fleet traffic", "Трафик флота"))
                " · "
                (match lang {
                    crate::i18n::Locale::En => window.label_en,
                    crate::i18n::Locale::Ru => window.label_ru,
                })
            }
            (vpn_traffic_chart(&fleet_rows, window, lang))
            // PR-Dash dash#2 — real ↑↓ totals + Δ% beside the chart.
            (dashboard_fleet_traffic_totals(&fleet_rows, &coeffs, window, lang))
        }
        // PR-Dash dash#3 — kernel-floor rollup (shared helper).
        (kernel_floor_rollup(&kernel_versions, lang))
        // PR-Dash dash#4 — alerts breakdown (replaces the count-only
        // tile). Quiet when there are no unacked alerts.
        (dashboard_alerts_breakdown(&alerts_breakdown, lang))
        // PR-Dash dash#5 — abuse summary (likely-shared subs).
        (dashboard_abuse_summary(&likely_shared, lang))
        (dashboard_idle_users(&idle_users, lang))
        (dashboard_limit_alerts(&alerting, lang))
        (dashboard_heavy_users(&heavy_users, window, lang))
        (dashboard_audit(&audit, lang))
    };
    Ok(shell("dashboard", &theme, &accent, lang, body))
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
    window: VpnSparklineWindow,
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
    let window_label = match lang {
        crate::i18n::Locale::En => window.label_en,
        crate::i18n::Locale::Ru => window.label_ru,
    };

    html! {
        div style="margin: 18px 0 0; padding: 14px 16px; border: 1px solid var(--rule); background: var(--paper);" {
            div.ed-art-eyebrow {
                (tr(lang, "VPN activity · ", "VPN-активность · "))
                (window_label)
            }
            p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 12px;" {
                (tr(
                    lang,
                    // Refreshed (audit 2026-06-10): per-user numbers DO
                    // exist now — the sing-box access-log scraper
                    // attributes traffic per user; only the clash-api
                    // path stays blocked upstream (NM-11).
                    "Server-wide totals from each node's clash-api (sing-box 5-minute tick). Per-user numbers come from the access-log scraper on each user's page (clash-api itself omits the User field upstream — NM-11).",
                    "Сервер-агрегатные показатели из clash-api каждой ноды (тик sing-box 5 минут). Per-user цифры считает скрейпер access-логов — смотри страницу юзера (сам clash-api не передаёт поле User — NM-11).",
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
                    @let up_title = format!("{}{}", tr(lang, "Total upload bytes (client → server) across every node in window: ", "Total upload-байт (клиент → сервер) по всем нодам за окно: "), window_label);
                    @let dn_title = format!("{}{}", tr(lang, "Total download bytes (server → client) across every node in window: ", "Total download-байт (сервер → клиент) по всем нодам за окно: "), window_label);
                    @let up_label = format!("{} {}", tr(lang, "upload", "upload"), window_label);
                    @let dn_label = format!("{} {}", tr(lang, "download", "download"), window_label);
                    div title=(up_title) {
                        (status_tile(&up_label, &humanize_bytes(total_up), "var(--ink)"))
                    }
                    div title=(dn_title) {
                        (status_tile(&dn_label, &humanize_bytes(total_dn), "var(--ink)"))
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

// PR-Dash dash#4 — the count-only `dashboard_alerts_tile` was replaced
// by `dashboard_alerts_breakdown` (defined above, near the other PR-Dash
// cards), which renders the (kind, severity) breakdown from
// `alerts_by_kind_severity` instead of a bare count.

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
                    // Honest copy (audit 2026-06-10): the metric is
                    // SUBSCRIPTION pulls, not tunnel traffic — a client
                    // with a cached config can use the VPN daily and
                    // still look «idle» here. Check the user's traffic
                    // page before revoking.
                    "Users whose subscription URL hasn't been pulled in 30+ days (or never). Apps with a cached config can still be USING the VPN — check the user's traffic page before revoking. ",
                    "Пользователи, чей URL подписки не запрашивался 30+ дней (или никогда). Приложение с закэшированным конфигом может продолжать ПОЛЬЗОВАТЬСЯ VPN — проверь страницу трафика юзера перед отзывом. ",
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
                                Some(ts) => (format_msk_iso(*ts)),
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

/// Render the "heavy users · <window>" section on the dashboard.
/// Sorted DESC by total bytes (upload + download). Empty list →
/// explanatory empty-state explaining the polling prerequisite.
fn dashboard_heavy_users(
    rows: &[vpnctl_inventory::HeavyUser],
    window: VpnSparklineWindow,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::{K, t, tr};
    let window_label = match lang {
        crate::i18n::Locale::En => window.label_en,
        crate::i18n::Locale::Ru => window.label_ru,
    };
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow
            title=(tr(
                lang,
                "Top-N by sum of (upload+download bytes) across all servers in the selected window. Data source: clash-api 5-minute polls. wgturn / WireGuard traffic NOT included (kernel-level, no clash-api visibility); only sing-box-mediated protocols (VLESS, TUIC, Trojan, Hysteria2, AnyTLS, Shadowsocks-2022) appear here.",
                "Топ-N по сумме (upload+download байт) на всех серверах за выбранное окно. Источник: 5-минутные опросы clash-api. Трафик wgturn / WireGuard НЕ учитывается (kernel-уровень, clash-api их не видит); только протоколы которые видит sing-box (VLESS, TUIC, Trojan, Hysteria2, AnyTLS, Shadowsocks-2022).",
            )) {
            (tr(lang, "Heavy users · ", "Тяжёлые пользователи · "))
            (window_label)
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
                a href="/admin/settings/system#deploy-ssh-key" style="color: var(--ink);" {
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
                (tr(lang, " accounts by total (upload + download) over ", " аккаунтов по суммарному (upload + download) за "))
                (window_label)
                (tr(
                    lang,
                    ". Click through to investigate; the user page has the full breakdown + sparkline.",
                    ". Кликни чтобы разобраться — страница пользователя содержит полную разбивку + sparkline.",
                ))
            }
            table style="width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 12px;" {
                thead {
                    tr style="color: var(--mute); border-bottom: 1px solid var(--rule);" {
                        th style="text-align: left; padding: 4px 0; font-weight: 600;" {
                            (tr(lang, "User", "Пользователь"))
                        }
                        th style="text-align: right; padding: 4px 10px; font-weight: 600;" {
                            "↑ " (tr(lang, "Upload", "Отдача"))
                        }
                        th style="text-align: right; padding: 4px 10px; font-weight: 600;" {
                            "↓ " (tr(lang, "Download", "Приём"))
                        }
                        th style="text-align: right; padding: 4px 0; font-weight: 600;" {
                            "Σ " (tr(lang, "Total", "Всего"))
                        }
                    }
                }
                tbody {
                    @for hu in rows {
                        tr style="border-bottom: 1px dotted var(--rule);" {
                            td style="text-align: left; padding: 4px 0;" {
                                a href=(format!("/admin/users/{}", path_segment_encode(&hu.user_id.0)))
                                  style="color: var(--ink); text-decoration: none; font-weight: 600;" {
                                    (hu.user_id.0)
                                }
                            }
                            td style="text-align: right; padding: 4px 10px; color: var(--mute);" {
                                (humanize_bytes(hu.upload_bytes))
                            }
                            td style="text-align: right; padding: 4px 10px; color: var(--mute);" {
                                (humanize_bytes(hu.download_bytes))
                            }
                            td style="text-align: right; padding: 4px 0; font-weight: 600;" {
                                (humanize_bytes(hu.total_bytes))
                            }
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

        // Deploy-all — push EVERY server's sing-box config in one click.
        // Run this after adding a user / granting servers so the new
        // UUID lands on every node (grants alone only update inv.db; the
        // node's sing-box isn't touched until a deploy). SSE-streamed via
        // admin.js [data-sse-url]; per-server progress + a summary land in
        // the log. Best-effort — a down node is reported, rest still go.
        @if !server_list.is_empty() {
            div id="deploy-button" style="margin: 0 0 24px;" {
                button type="button"
                       data-sse-url="/admin/servers/deploy-all/sse"
                       data-busy-label=(crate::i18n::tr(lang, "deploying all… (watch the log)", "деплою все… (смотри лог)"))
                       data-retry-label=(crate::i18n::tr(lang, "retry deploy all", "повторить деплой всех"))
                       title=(crate::i18n::tr(
                           lang,
                           "Re-deploy EVERY server: pushes each node's sing-box config so newly-added users' UUIDs land on all of them. Run once after adding a user or granting servers. Best-effort — a down node is reported, the rest still deploy.",
                           "Передеплоить ВСЕ серверы: пушит конфиг sing-box на каждую ноду, чтобы UUID новых юзеров попали на все. Нажми один раз после добавления юзера или выдачи грантов. Best-effort — упавшая нода отмечается, остальные деплоятся.",
                       ))
                       style="padding: 6px 14px; border: 1px solid var(--ink); background: var(--ink); color: var(--paper); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                    (crate::i18n::tr(lang, "deploy all servers →", "развернуть все серверы →"))
                    " (" (server_list.len()) ")"
                }
                pre id="deploy-log" hidden
                    style="margin-top: 12px; padding: 10px 12px; background: var(--paper-tint); border: 1px solid var(--rule); font-family: var(--mono); font-size: 11px; line-height: 1.5; max-height: 360px; overflow-y: auto; white-space: pre-wrap;" {}
            }
            // "Update all kernels" (update-kernels PR2) — upgrade ONLY the
            // kernel binaries across the fleet (apt upgrade + service
            // restart) without re-rendering any config. SSE-streamed via
            // the same generic admin.js [data-sse-url]+[data-log] wiring;
            // its OWN log pane (`update-kernels-log`) avoids colliding with
            // `deploy-log`. Safe on inventory-drift nodes — never shrinks
            // the live user set. Best-effort — a down node is reported,
            // the rest still update.
            div id="update-kernels-button" style="margin: 0 0 24px;" {
                button type="button"
                       data-sse-url="/admin/servers/update-kernels-all/sse"
                       data-log="update-kernels-log"
                       data-busy-label=(crate::i18n::tr(lang, "updating all kernels… (watch the log)", "обновляю все ядра… (смотри лог)"))
                       data-retry-label=(crate::i18n::tr(lang, "retry update all", "повторить обновление всех"))
                       title=(crate::i18n::tr(
                           lang,
                           "Upgrade the kernel binaries on EVERY server (apt upgrade + service restart) without re-rendering any config. Run after a kernel release to roll the new binary across the fleet. The running config is left untouched, so this is safe even on a node whose inventory has drifted. Best-effort — a down node is reported, the rest still update.",
                           "Обновить бинарники ядер на ВСЕХ серверах (apt upgrade + рестарт сервиса) без перерендера конфига. Запусти после релиза ядра, чтобы раскатать новый бинарь по флоту. Рабочий конфиг не трогается, поэтому безопасно даже на ноде с дрейфом инвентаря. Best-effort — упавшая нода отмечается, остальные обновляются.",
                       ))
                       style="padding: 6px 14px; border: 1px solid var(--ink); background: transparent; color: var(--ink); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                    (crate::i18n::tr(lang, "update all kernels →", "обновить все ядра →"))
                    " (" (server_list.len()) ")"
                }
                pre id="update-kernels-log" hidden
                    style="margin-top: 12px; padding: 10px 12px; background: var(--paper-tint); border: 1px solid var(--rule); font-family: var(--mono); font-size: 11px; line-height: 1.5; max-height: 360px; overflow-y: auto; white-space: pre-wrap;" {}
            }
        }

        @if server_list.is_empty() {
            p style="font-family: var(--serif); font-style: italic; color: var(--mute); padding: 24px 0;" {
                (crate::i18n::tr(lang, "No servers yet. Click ", "Серверов ещё нет. Кликни "))
                span.ed-mono { (crate::i18n::tr(lang, "add server →", "добавить сервер →")) }
                (crate::i18n::tr(lang, " above, or run ", " выше, или запусти "))
                span.ed-mono { "vpnctl bootstrap <id> --address <addr> --root-password <pw>" }
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
/// Sort kinds: "id" (default), "id-desc", "servers" (fewest grants
/// first, ascending), "servers-desc" (most grants first, descending).
/// The bare name is ascending and `-desc` is descending, matching the
/// id / id-desc convention. Search `q` is a case-
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
        "servers" => pairs.sort_by(|a, b| a.2.cmp(&b.2).then_with(|| a.1.id.0.cmp(&b.1.id.0))),
        "servers-desc" => pairs.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| a.1.id.0.cmp(&b.1.id.0))),
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
                    (sort_link("servers", crate::i18n::tr(lang, "servers ↑", "серверы ↑")))
                    (sort_link("servers-desc", crate::i18n::tr(lang, "servers ↓", "серверы ↓")))
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

/// Sibling of [`collect_amnezia_links`] — one `awg://` link per
/// WG-enabled granted server for the user-detail Flow E card (the
/// operator's sing-box-lx-based client app). Servers without minted
/// AmneziaWG obfs (i.e. not running the `amneziawg` kernel) or a user
/// without a server-generated private key cause `awg_share_link` to
/// error; those are LOGGED-AND-SKIPPED so the page still renders and the
/// card naturally shows only AmneziaWG-capable servers.
fn collect_awg_links(
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
        // awg:// only makes sense for an AmneziaWG node (obfs minted)
        // serving the wireguard protocol. Gate on BOTH so a vanilla
        // sing-box WG server (no obfs) is skipped cleanly rather than
        // hitting awg_share_link's error path on every page render.
        let is_amnezia = server.kernels.iter().any(|k| k.0 == "amneziawg");
        let serves_wg = server.enabled_protocols.iter().any(|p| p.0 == "wireguard");
        if !is_amnezia || !serves_wg {
            continue;
        }
        let Some(secrets) = secrets_per_server.get(&server.id) else {
            continue;
        };
        let peers: &[vpnctl_core::User] = peers_per_server
            .get(&server.id)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let ctx = vpnctl_core::RenderCtx::with_peers(server, secrets, peers);
        let per_server_user = user_for_server_render(user, peers, &server.id);
        match vpnctl_protocols::awg_share_link(&ctx, &per_server_user) {
            Ok(link) => out.push((server.id.clone(), link)),
            Err(e) => {
                tracing::debug!(
                    target = "vpnctld::admin",
                    server = %server.id,
                    user = %user.id,
                    error = %e,
                    "awg_share_link skipped (no obfs / no server-gen privkey)"
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
    /// 2026-05-23 — VPN-traffic sparkline window. One of «24h»,
    /// «7d», «30d», «all». Defaults to 24h. Backed by
    /// `pick_vpn_sparkline_window`.
    #[serde(default)]
    vpn_window: Option<String>,
}

impl UserDetailQuery {
    fn show_egress(&self) -> bool {
        matches!(self.show_egress.as_deref(), Some("1") | Some("true"))
    }
}

/// user_detail's in-page tabs (ui-audit §3-§4). Same recipe as
/// `ServerTab`: real sub-routes (`/admin/users/{id}/{slug}`), plain
/// `<a href>` links, each tab renders only its own sections. `Overview`
/// is the default (bare `/admin/users/{id}`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum UserTab {
    Overview,
    Delivery,
    Access,
    Activity,
    Traffic,
}

impl UserTab {
    fn slug(self) -> &'static str {
        match self {
            UserTab::Overview => "overview",
            UserTab::Delivery => "delivery",
            UserTab::Access => "access",
            UserTab::Activity => "activity",
            UserTab::Traffic => "traffic",
        }
    }
}

// Thin axum handlers — one per tab route in app.rs. Bare
// `/admin/users/{id}` (+ trailing slash) + `/overview` both land here.
pub(crate) async fn user_detail(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(user_id_str): Path<String>,
    axum::extract::Query(query): axum::extract::Query<UserDetailQuery>,
) -> Result<Markup, Response> {
    user_detail_render(headers, state, user_id_str, query, UserTab::Overview).await
}

pub(crate) async fn user_detail_delivery(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(user_id_str): Path<String>,
    axum::extract::Query(query): axum::extract::Query<UserDetailQuery>,
) -> Result<Markup, Response> {
    user_detail_render(headers, state, user_id_str, query, UserTab::Delivery).await
}

pub(crate) async fn user_detail_access(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(user_id_str): Path<String>,
    axum::extract::Query(query): axum::extract::Query<UserDetailQuery>,
) -> Result<Markup, Response> {
    user_detail_render(headers, state, user_id_str, query, UserTab::Access).await
}

pub(crate) async fn user_detail_activity(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(user_id_str): Path<String>,
    axum::extract::Query(query): axum::extract::Query<UserDetailQuery>,
) -> Result<Markup, Response> {
    user_detail_render(headers, state, user_id_str, query, UserTab::Activity).await
}

pub(crate) async fn user_detail_traffic(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(user_id_str): Path<String>,
    axum::extract::Query(query): axum::extract::Query<UserDetailQuery>,
) -> Result<Markup, Response> {
    user_detail_render(headers, state, user_id_str, query, UserTab::Traffic).await
}

async fn user_detail_render(
    headers: HeaderMap,
    state: AppState,
    user_id_str: String,
    query: UserDetailQuery,
    tab: UserTab,
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

    // 2026-05-23 quickfix follow-up (Pavel + multiviruss incident):
    // detect servers whose running config doesn't yet include this
    // user's latest state — i.e. user was created / modified after
    // the server's most recent deploy. Surfaces as an amber banner
    // at the top of user-detail so the operator notices BEFORE the
    // user reports «connected but no traffic».
    let pending_deploy_servers: Vec<vpnctl_core::ServerId> = state
        .inv
        .servers_pending_deploy_for_user(&uid, &servers.iter().map(|s| s.id.clone()).collect::<Vec<_>>())
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(target = "vpnctld::admin", user = %uid.0, error = %e, "servers_pending_deploy_for_user failed");
            Vec::new()
        });

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
    // Flow E — awg:// links for the operator's sing-box-lx client app.
    // Only AmneziaWG-capable servers (obfs minted) yield a link.
    let awg_links = collect_awg_links(&user, &servers, &secrets_per_server, &peers_per_server);
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
    // Sibling tally for dns-tunnel — same shape / same role as
    // `wgturn_capable_granted`. dns-tunnel is ALSO a non-sing-box
    // two-process share-link (`appears_in_sing_box_sub() == false`,
    // slipstream-client + loopback VLESS), so — exactly like wgturn —
    // it never reaches the user through Flow A's /sub envelope. Drives
    // the dedicated "Flow E — dns-tunnel" delivery card + its
    // empty-state copy below the per-protocol grid.
    let dns_tunnel_capable_granted: Vec<&vpnctl_core::ServerId> = servers
        .iter()
        .filter(|s| s.enabled_protocols.iter().any(|p| p.0 == "dns-tunnel"))
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

    // PR-User user#2 — per-server traffic split over the last 24h
    // (Q-4b). One query. Failure → empty Vec, which renders the NM-11
    // empty-state explainer rather than a blank card.
    let traffic_by_server = state
        .inv
        .user_traffic_by_server(&uid, 24)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(target = "vpnctld::admin", user = %uid, error = %e, "user_traffic_by_server failed");
            Vec::new()
        });
    // PR-User user#4 — UA clusters over the last 24h, fetched here for
    // the sharing-verdict line. `ua_clusters_section` (the per-UA
    // table) keeps its own self-contained query so it stays usable for
    // any future caller; this small bounded query (one window, ≤a few
    // UA rows) is the cost of a consolidated verdict that can't drift
    // from the table's thresholds.
    let ua_clusters = state.inv.ua_clusters_for_user(&uid, 24).await.unwrap_or_else(|e| {
        tracing::warn!(target = "vpnctld::admin", user = %uid, error = %e, "ua_clusters_for_user (verdict) failed");
        Vec::new()
    });
    // abuse-origins — "Subscription origins" breakdown over the same
    // 30-day window the access cards use. Four grouped, index-backed
    // reads (country / ASN / IP / device-fingerprint), each excluding
    // VPN-egress + NULL-user rows. Failure on any one degrades only that
    // table to its empty-state (the page still renders).
    const ORIGINS_WINDOW_DAYS: u32 = 30;
    const ORIGINS_ASN_LIMIT: u32 = 10;
    const ORIGINS_IP_LIMIT: u32 = 15;
    let origins_by_country = state
        .inv
        .sub_access_by_country(&uid, ORIGINS_WINDOW_DAYS)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(target = "vpnctld::admin", user = %uid, error = %e, "sub_access_by_country failed");
            Vec::new()
        });
    let origins_by_asn = state
        .inv
        .sub_access_by_asn(&uid, ORIGINS_WINDOW_DAYS, ORIGINS_ASN_LIMIT)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(target = "vpnctld::admin", user = %uid, error = %e, "sub_access_by_asn failed");
            Vec::new()
        });
    let origins_by_ip = state
        .inv
        .sub_access_by_ip(&uid, ORIGINS_WINDOW_DAYS, ORIGINS_IP_LIMIT)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(target = "vpnctld::admin", user = %uid, error = %e, "sub_access_by_ip failed");
            Vec::new()
        });
    let origins_device_fp = state
        .inv
        .sub_access_device_fingerprint(&uid, ORIGINS_WINDOW_DAYS)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(target = "vpnctld::admin", user = %uid, error = %e, "sub_access_device_fingerprint failed");
            vpnctl_inventory::SubDeviceFp::default()
        });
    // «Source IPs» (2026-06-14) — per-(user, source_ip) activity over
    // the last 7 days from the persisted `vpn_user_source_ips` counter,
    // then a best-effort GeoIP label lookup for exactly those IPs (geo
    // is an IP attribute, so the lookup is user-independent). Both
    // degrade to an empty table on failure — the page still renders.
    const SOURCE_IPS_WINDOW_DAYS: u32 = 7;
    const SOURCE_IPS_LIMIT: u32 = 20;
    let source_ips = state
        .inv
        .top_source_ips_for_user(&uid, SOURCE_IPS_WINDOW_DAYS, SOURCE_IPS_LIMIT)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(target = "vpnctld::admin", user = %uid, error = %e, "top_source_ips_for_user failed");
            Vec::new()
        });
    let source_ip_geo = {
        let ips: Vec<String> = source_ips.iter().map(|r| r.source_ip.clone()).collect();
        state.inv.geo_labels_for_ips(&ips).await.unwrap_or_else(|e| {
            tracing::warn!(target = "vpnctld::admin", user = %uid, error = %e, "geo_labels_for_ips failed");
            std::collections::HashMap::new()
        })
    };
    // PR-User user#5 — lifecycle facts (Q-4d). created_at +
    // last_sub_fetch + age_days. On failure compose a defensible
    // fallback from the user's own created_at so the section still
    // renders (created_at is always present for an existing user).
    let lifecycle = state.inv.user_lifecycle(&uid).await.unwrap_or_else(|e| {
        tracing::warn!(target = "vpnctld::admin", user = %uid, error = %e, "user_lifecycle failed");
        vpnctl_inventory::UserLifecycle {
            created_at: chrono::Utc::now(),
            last_sub_fetch: access_aggregates.last_seen,
            age_days: 0,
        }
    });
    // PR-User user#1 — online-now presence. Walk the in-memory
    // snapshot cache across the granted servers PLUS the full
    // inventory (a connection can land on a server before the grant is
    // reflected, and the cache is cheap to read). Dedup the id set so
    // we don't double-count a server present in both lists.
    let presence_server_ids: Vec<vpnctl_core::ServerId> = {
        let mut seen: HashSet<vpnctl_core::ServerId> = HashSet::new();
        let mut out = Vec::new();
        for s in servers.iter().chain(all_servers.iter()) {
            if seen.insert(s.id.clone()) {
                out.push(s.id.clone());
            }
        }
        out
    };
    // PR-User user#1 — render the presence badge here (it does an
    // async cache + fallback-query read, which the maud `html!` block
    // below can't `.await`). Cheap: in-memory cache reads + at most one
    // bounded `users_for_source_ips` query.
    let online_badge = user_online_badge(
        &state,
        &uid,
        &presence_server_ids,
        access_aggregates.last_seen,
        lang,
    )
    .await;

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

            // PR-User user#1 — online-now presence badge, directly under
            // the user header so «is this person connected right now» is
            // the first thing the operator sees.
            (online_badge)

            // 2026-05-23 quickfix follow-up — pending-deploy banner.
            // Surfaces servers whose running config doesn't yet include
            // this user's current state. Hidden when empty (quiet
            // dashboard contract). Each server name links straight to
            // its detail page's #deploy-button anchor so one click moves
            // the operator from «I see the warning» to «I'm one click
            // from fixing it».
            //
            // Visual: amber border, prominent at the top so it's
            // noticed before the operator starts copying the QR.
            @if !pending_deploy_servers.is_empty() {
                div style="border: 1px solid var(--acc); background: var(--paper); padding: 12px 14px; margin: 12px 0 16px;" {
                    div style="font-family: var(--serif); font-weight: 500; color: var(--acc); font-size: 14px; margin-bottom: 4px;" {
                        (crate::i18n::tr(
                            lang,
                            "⚠ Config not yet deployed to:",
                            "⚠ Конфиг ещё не задеплоен на:",
                        ))
                        " "
                        @for (i, sid) in pending_deploy_servers.iter().enumerate() {
                            @if i > 0 { ", " }
                            a href=(format!("/admin/servers/{}#deploy-button", path_segment_encode(&sid.0)))
                              style="color: var(--acc); font-family: var(--mono); font-weight: 600;" {
                                (sid.0)
                            }
                        }
                    }
                    p style="font-family: var(--serif); font-style: italic; color: var(--mute); margin: 4px 0 0; font-size: 12px;" {
                        (crate::i18n::tr(
                            lang,
                            "Until you deploy each server above, the user's sing-box entry isn't on the node — REALITY handshake succeeds but VLESS auth silently drops, the client shows «connected» with no traffic. Same incident pattern as 2026-05-23 multiviruss. Or just hit the one-click button below.",
                            "Пока не задеплоишь каждый сервер выше, запись пользователя в sing-box не попадает на ноду — REALITY-рукопожатие проходит, но VLESS-auth молча отказывает, клиент показывает «подключено» без трафика. Тот же паттерн что инцидент с multiviruss 2026-05-23. Либо просто нажми кнопку ниже.",
                        ))
                    }
                    // One-click fix right here in the user view: deploy every
                    // server (pushes THIS user's UUID onto each granted node).
                    // Reuses the fleet-wide SSE deploy; `data-reload-self`
                    // reloads this user page on done so the banner re-computes
                    // and clears. A down node (fi etc.) is reported ✗ in the
                    // log; the rest still deploy.
                    div style="margin-top: 10px;" {
                        button type="button"
                               data-sse-url="/admin/servers/deploy-all/sse"
                               data-log="user-deploy-log"
                               data-reload-self="true"
                               data-busy-label=(crate::i18n::tr(lang, "deploying all… (watch the log)", "деплою все… (смотри лог)"))
                               data-retry-label=(crate::i18n::tr(lang, "retry deploy", "повторить деплой"))
                               title=(crate::i18n::tr(
                                   lang,
                                   "Deploy every server now — pushes this user's UUID onto each granted node so the config goes live. Best-effort; a down node is reported, the rest still deploy. Reloads this page when done.",
                                   "Задеплоить все серверы сейчас — пушит UUID этого юзера на каждую ноду, чтобы конфиг заработал. Best-effort; упавшая нода отмечается, остальные деплоятся. По завершении страница перезагрузится.",
                               ))
                               style="padding: 6px 14px; border: 1px solid var(--acc); background: var(--acc); color: var(--paper); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                            (crate::i18n::tr(lang, "deploy all servers now →", "развернуть все серверы сейчас →"))
                        }
                        pre id="user-deploy-log" hidden
                            style="margin-top: 10px; padding: 10px 12px; background: var(--paper-tint); border: 1px solid var(--rule); font-family: var(--mono); font-size: 11px; line-height: 1.5; max-height: 320px; overflow-y: auto; white-space: pre-wrap;" {}
                    }
                }
            }

    @let tab_base = format!("/admin/users/{}", path_segment_encode(&user.id.0));
    (detail_tabs(&tab_base, tab.slug(), &[("overview", crate::i18n::tr(lang, "Overview", "Обзор")), ("delivery", crate::i18n::tr(lang, "Delivery", "Выдача")), ("access", crate::i18n::tr(lang, "Access", "Доступ")), ("activity", crate::i18n::tr(lang, "Activity", "Активность")), ("traffic", crate::i18n::tr(lang, "Traffic", "Трафик"))]))
    @if tab == UserTab::Overview {
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

            // Extra-protocol per-user password — TUIC / naive / Hysteria2 all
            // reuse `tuic_password`. Shown ONLY when absent: a user without it
            // silently gets NO naive/HY2/TUIC links (the cdn 2026-06-07
            // incident). One-click mint turns that silent skip into a fix.
            @if user.tuic_password.is_none() {
                div.ed-rule {}
                div.ed-art-eyebrow { (crate::i18n::tr(lang, "Extra-protocol password", "Пароль доп-протоколов")) }
                div style="padding: 12px 0;" {
                    p style="font-family: var(--serif); color: var(--acc); font-size: 13px; line-height: 1.6;" {
                        (crate::i18n::tr(
                            lang,
                            "⚠ No tuic_password — TUIC, naive and Hysteria2 links can't be minted for this user, so those protocols silently won't appear in their config (VLESS is unaffected).",
                            "⚠ Нет tuic_password — ссылки TUIC, naive и Hysteria2 для этого юзера не собираются, поэтому эти протоколы молча не попадают в его конфиг (VLESS не затронут).",
                        ))
                    }
                    form method="post"
                         action=(format!("/admin/users/{}/tuic-password/mint", path_segment_encode(&user.id.0)))
                         style="margin-top: 10px;" {
                        button type="submit"
                               title=(crate::i18n::tr(
                                   lang,
                                   "Mint this user's per-user password used by TUIC / naive / Hysteria2. Safe — no existing secret to invalidate. Redeploy the user's servers afterwards so the node accepts it.",
                                   "Сгенерировать per-user пароль для TUIC / naive / Hysteria2. Безопасно — нечего инвалидировать. Затем передеплой серверы юзера, чтобы узел принял пароль.",
                               ))
                               style="padding: 4px 10px; border: 1px solid var(--ink); background: transparent; font-family: var(--mono); font-size: 11px; color: var(--ink); cursor: pointer;" {
                            (crate::i18n::tr(lang, "mint tuic password", "сгенерировать tuic-пароль"))
                        }
                    }
                    p style="font-family: var(--serif); font-style: italic; color: var(--soft); font-size: 12px; margin-top: 8px;" {
                        (crate::i18n::tr(
                            lang,
                            "After minting, redeploy the affected server(s) so the node accepts the new password.",
                            "После генерации передеплой затронутые серверы, чтобы узел принял новый пароль.",
                        ))
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
    }
    @if tab == UserTab::Delivery {
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
                            // Flow F — AmneziaWG `awg://` link for the
                            // operator's sing-box-lx-based client app. Carries
                            // the per-server obfs (s1/s2/h1-h4 minted by
                            // bootstrap) + the server-generated client key, so
                            // it's a one-tap import. Only renders when at least
                            // one granted server runs the amneziawg kernel
                            // (obfs minted ⇒ a link was produced). Letter F:
                            // A=sub, B=wireguard://, C=AmneziaVPN vpn://,
                            // D=wgturn, E=dns-tunnel — F is the next free one.
                            @if !awg_links.is_empty() {
                                div {
                                    div style="font-family: var(--mono); font-size: 11px; color: var(--mute); letter-spacing: 0.14em; text-transform: uppercase; margin-bottom: 8px;" {
                                        (crate::i18n::tr(lang, "Flow F — AmneziaWG (awg://)", "Поток F — AmneziaWG (awg://)"))
                                    }
                                    @for (sid, link) in &awg_links {
                                        div style="margin-bottom: 18px;" {
                                            div style="font-family: var(--mono); font-size: 11px; color: var(--mute); margin-bottom: 6px;" {
                                                (crate::i18n::tr(lang, "server ", "сервер ")) (sid.0)
                                            }
                                            (share_link_card(link, &html! {
                                                (crate::i18n::tr(
                                                    lang,
                                                    "Opens in the sing-box-lx-based app — per-server AmneziaWG obfuscation (s1/s2/h1-h4) baked in; one-tap, no on-device key-gen.",
                                                    "Открывается в приложении на sing-box-lx — per-server AmneziaWG-обфускация (s1/s2/h1-h4) уже внутри; один тап, без генерации ключей на устройстве.",
                                                ))
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
    }
    @if tab == UserTab::Access {
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
                    span.ed-mono { "vpnctl bootstrap <id> --address <ip> --root-password <pw>" }
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

    }
    @if tab == UserTab::Delivery {
            // Flow E — dns-tunnel (slipstream DNS-over-НСДИ last resort).
            // Mirror of Flow D (wgturn) — a SEPARATE delivery card because:
            //   * sing-box CAN'T parse `type: dns-tunnel` — the protocol is
            //     filtered out of /sub (`appears_in_sing_box_sub() = false`),
            //     so Flow A doesn't deliver it.
            //   * the `dns-tunnel://` URL is consumed by a TWO-process client
            //     bundle (slipstream-client local TCP listener + a sing-box
            //     VLESS outbound → that listener), NOT a single sing-box
            //     outbound URI — so it can't ride the JSON envelope or the
            //     V2Ray base64 sub.
            // The per-user `dns-tunnel://<…uuid=user.uuid…>` link is rendered
            // by the generic `collect_share_links` (it iterates every enabled
            // protocol and calls `share_link`, no `appears_in_sing_box_sub`
            // filter — same as the CLI `vpnctl sub` path), so it already lands
            // in the "Per-protocol share links" list below; this card lifts it
            // into its own QR + consumption instructions, exactly like wgturn.
            // The card ONLY renders when at least one granted server runs the
            // dns-tunnel protocol; sing-box-only users never see it.
            @if !dns_tunnel_capable_granted.is_empty() {
                div.ed-art-eyebrow style="margin-top: 24px;" {
                    (crate::i18n::tr(lang, "Flow E — dns-tunnel (slipstream, last resort)", "Поток E — dns-tunnel (slipstream, последний резерв)"))
                }
                @let dnst_links: Vec<_> = share_links
                    .iter()
                    .filter(|(_, pid, _)| pid.0 == "dns-tunnel")
                    .collect();
                @if dnst_links.is_empty() {
                    p style="font-family: var(--serif); font-style: italic; color: var(--mute); font-size: 12px; margin: 0;" {
                        (crate::i18n::tr(lang, "Granted dns-tunnel servers ", "Выданные dns-tunnel-серверы "))
                        @for (i, sid) in dns_tunnel_capable_granted.iter().enumerate() {
                            @if i > 0 { ", " }
                            span.ed-mono { (sid.0) }
                        }
                        (crate::i18n::tr(
                            lang,
                            " — but the share-link render failed. Most likely missing ",
                            " — но рендер share-link провалился. Скорее всего нет ",
                        ))
                        span.ed-mono { "dns-tunnel:domain" }
                        (crate::i18n::tr(lang, " or ", " или "))
                        span.ed-mono { "dns-tunnel:fingerprint" }
                        (crate::i18n::tr(
                            lang,
                            " server secret — set them via the server's secrets page.",
                            " серверного секрета — задай их на странице секретов сервера.",
                        ))
                    }
                } @else {
                    @for (sid, _pid, link) in &dnst_links {
                        div style="margin-bottom: 18px;" {
                            div style="font-family: var(--mono); font-size: 11px; color: var(--mute); margin-bottom: 6px;" {
                                "server " (sid.0)
                                (crate::i18n::tr(lang, " · break-glass when everything else is blocked", " · break-glass когда всё остальное заблокировано"))
                            }
                            (share_link_card(link, &html! {
                                (crate::i18n::tr(
                                    lang,
                                    "Two-process bundle: a local slipstream-client tunnels TCP-over-DNS to НСДИ resolvers, and a sing-box VLESS outbound points at that local listener. The link carries this user's own ",
                                    "Двухпроцессный бандл: локальный slipstream-client тоннелирует TCP-over-DNS к НСДИ-резолверам, а sing-box VLESS-outbound смотрит на этот локальный listener. В ссылке — собственный ",
                                ))
                                span.ed-mono { "uuid" }
                                (crate::i18n::tr(
                                    lang,
                                    " (the same one used for VLESS-REALITY), the tunnel domain, the multipath resolver list and the cert-pin fingerprint — nothing for the user to fill in. ",
                                    " (тот же, что и для VLESS-REALITY), домен тоннеля, multipath-список резолверов и fingerprint-пин сертификата — пользователю ничего вводить не нужно. ",
                                ))
                                b { (crate::i18n::tr(
                                    lang,
                                    "Last-resort transport — position beside Flow A/B/C/D, not as a daily driver.",
                                    "Транспорт последнего резерва — рядом с потоками A/B/C/D, не для повседневного использования.",
                                )) }
                            }))
                        }
                    }
                }
            }

            // Per-protocol share-links — only meaningful for granted servers.
            // ponytail: collapsed <details> — the Flow cards above already deliver
            // every link with a QR; this raw server×protocol dump (up to ~32 lines)
            // is the copy-all / debug view, not prime-scroll content. Content stays
            // in the DOM (just collapsed), so copy-contract + smoke tests still see it.
            @if !servers.is_empty() {
                details style="margin-top: 24px;" {
                    summary style="cursor: pointer;" {
                        span.ed-art-eyebrow {
                            (crate::i18n::tr(lang, "Per-protocol share links", "Ссылки на отдельные протоколы"))
                        }
                    }
                    @if share_links.is_empty() {
                        p style="font-family: var(--serif); font-style: italic; color: var(--mute); margin-top: 8px;" {
                            "No share-links could be rendered (missing secrets or unregistered protocols). "
                            "Check " span.ed-mono { "journalctl -u vpnctld" } " for warnings."
                        }
                    } @else {
                        ul style="list-style: none; padding: 0; margin-top: 8px; font-family: var(--mono); font-size: 11.5px; line-height: 1.7; color: var(--soft);" {
                            @for (sid, pid, link) in &share_links {
                                li style="padding: 4px 0; border-bottom: 1px dotted var(--rule);" {
                                    span style="color: var(--mute);" { (sid.0) " · " (pid.0) " · " }
                                    (link)
                                }
                            }
                        }
                    }
                }
            }

    }
    @if tab == UserTab::Activity {
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
                        a href=(format!("/admin/users/{}/activity", user.id.0))
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
                            a href=(format!("/admin/users/{}/activity?show_egress=1", user.id.0))
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
                                    (format_msk_iso(row.ts))
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
    }
    @if tab == UserTab::Overview || tab == UserTab::Activity {

            // ── PR-User user#4 — sharing-evidence verdict ────────────
            // ONE consolidated verdict line above the per-UA evidence
            // table, folding the 30-day access spread with the UA-cluster
            // /16 spread (reusing the Track-4 ua_verdict thresholds).
            (user_sharing_verdict_section(&access_aggregates, &ua_clusters, lang))

    }
    @if tab == UserTab::Activity {
            // ── abuse-origins — "Subscription origins" (#origins) ────
            // WHO is sharing: country / ISP / IP breakdown + a rough
            // device-count line. Anchored so the dashboard likely-shared
            // card links straight here. Sits below the verdict (the
            // headline) and above the per-UA table (the /16 evidence).
            (user_subscription_origins_section(
                &origins_by_country,
                &origins_by_asn,
                &origins_by_ip,
                &origins_device_fp,
                lang,
            ))

            // ── UA fingerprint (Phase Track-4) + user#7 geo footer ───
            (ua_clusters_section(&state, &uid, &access_aggregates, lang).await)

    }
    @if tab == UserTab::Traffic {
            // ── PR-User user#2 — traffic split by server (24h) ───────
            (user_detail_traffic_by_server_section(&traffic_by_server, lang))

            // ── Live VPN stats (Track-3 chunk 3) + user#6 trend ──────
            // The window picker (24h/7d/30d/all) is now folded INTO this
            // section — it re-fetches the picked window's rows once and
            // drives both the compact `sparkline_svg` trend and the full
            // chart, so the previous page-level picker is gone (it would
            // have rendered a second, duplicate picker).
            (live_vpn_stats_section(&state, &uid, query.vpn_window.as_deref(), lang).await)
            (user_top_destinations_section(&state, &uid, lang).await)

    }
    @if tab == UserTab::Activity {
            // ── Source IPs (2026-06-14) — «откуда» counterpart to the
            // «куда» destinations table: per-client-IP activity grounded
            // in real VPN connections, GeoIP-labelled + reserved-range
            // classified (the «проработай (неизвестно)» + «разбей трафик
            // по IP» deliverable). Pre-fetched above.
            (user_source_ips_section(&source_ips, &source_ip_geo, lang))

            (user_sessions_section(&state, &uid, lang).await)

    }
    @if tab == UserTab::Overview {
            // ── PR-User user#5 — lifecycle facts ─────────────────────
            (user_lifecycle_section(&lifecycle, access_aggregates.last_seen, lang))

            // ── Traffic limit + alert threshold (Pavel D.6c) ──────────
            // Show current month-to-date usage + the configured cap
            // (if any) + an inline form to change both, plus the user#3
            // month-end projection when a cap is set. Re-runs the usage
            // query so the page-after-redirect immediately reflects new
            // limits.
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
    }
        };
    Ok(shell("users", &theme, &accent, lang, body))
}

// ════════════════════════════════════════════════════════════════════
//  PR-User — informativeness cards for the user-detail page.
//
//  All seven cards reuse existing helpers (status_tile, sparkline_svg,
//  window_picker_section, humanize_bytes, fmt_traffic_progress,
//  format_msk_iso, ua_verdict) — no parallel styling. Bilingual via
//  tr() / t(). The only card that touches process state outside one
//  SQL query is user#1 (the online-now badge), and that read is
//  in-memory only — it walks the already-populated `snapshot_cache`
//  across the granted servers, never an extra DB round-trip or SSH.
// ════════════════════════════════════════════════════════════════════

/// user#1 — online-now presence badge. Walks `state.snapshot_cache`
/// across every server in `server_ids` (in production the granted set
/// joined with the full inventory; tests pass whatever they seeded),
/// counting the live clash-api connections whose `(source_ip,
/// source_port)` attribution resolves to `uid`. When the per-connection
/// attribution map misses (NM-11: the sing-box log scrape window may
/// have scrolled past a long-lived connection's accept line), we fall
/// back to `users_for_source_ips` — the same sourceIP-to-user_id join
/// the «Live connections» drill-down uses — over the unattributed
/// source IPs only, so a covered user still lights up green.
///
/// 🟢 online → "N conns on {server(s)}". Offline → "last seen {Xh
/// ago}" from `sub_access_aggregates_for_user.last_seen` (passed in as
/// `last_seen` so we don't re-query). Cheap: in-memory map reads +, at
/// most, one bounded `users_for_source_ips` query for the IPs the
/// in-memory map couldn't resolve.
async fn user_online_badge(
    state: &AppState,
    uid: &vpnctl_core::UserId,
    server_ids: &[vpnctl_core::ServerId],
    last_seen: Option<chrono::DateTime<chrono::Utc>>,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::{K, t, tr};
    // Per-server live connection count attributed to this user, plus
    // the set of (server, source_ip) pairs the in-memory attribution
    // map could NOT resolve — candidates for the sourceIP fallback.
    let mut conns_per_server: std::collections::BTreeMap<String, u32> =
        std::collections::BTreeMap::new();
    // Unresolved source IPs → the servers they appeared on (so the
    // fallback can credit the right server when a join succeeds).
    let mut unresolved: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    for sid in server_ids {
        let Some(snap) = state.snapshot_cache.get(sid) else {
            continue;
        };
        for c in &snap.snapshot.connections {
            match c.metadata.user.as_deref() {
                Some(u) if u == uid.0.as_str() => {
                    *conns_per_server.entry(sid.0.clone()).or_insert(0) += 1;
                }
                Some(_) => {
                    // Attributed to a DIFFERENT user — never this one.
                }
                None => {
                    // No user on the wire (e.g. an unpatched node) —
                    // defer to the sourceIP join below.
                    if !c.metadata.source_ip.is_empty() {
                        unresolved
                            .entry(c.metadata.source_ip.clone())
                            .or_default()
                            .push(sid.0.clone());
                    }
                }
            }
        }
    }

    // Fallback: resolve the unattributed source IPs via the same
    // sub_access_log sourceIP → user_id join the drill-down uses. One
    // bounded query over the distinct unresolved IPs (skipped entirely
    // when the in-memory map already covered everything).
    if !unresolved.is_empty() {
        let ips: Vec<String> = unresolved.keys().cloned().collect();
        match state.inv.users_for_source_ips(&ips, 7).await {
            Ok(map) => {
                for (ip, candidates) in &map {
                    // The join returns (user, hits) ordered hits-DESC;
                    // the top candidate is the most-likely owner. Credit
                    // the user only when THEY are that top candidate.
                    let owner_is_user = candidates
                        .first()
                        .map(|(u, _)| u.0.as_str() == uid.0.as_str())
                        .unwrap_or(false);
                    if owner_is_user {
                        if let Some(servers) = unresolved.get(ip) {
                            for s in servers {
                                *conns_per_server.entry(s.clone()).or_insert(0) += 1;
                            }
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!(target = "vpnctld::admin", user = %uid, error = %e, "users_for_source_ips (online badge fallback) failed");
            }
        }
    }

    let total_conns: u32 = conns_per_server.values().copied().sum();
    let online = total_conns > 0;

    html! {
        div.ed-art-eyebrow style="margin-top: 18px;" { (t(lang, K::EyebrowPresence)) }
        @if online {
            @let server_count = conns_per_server.len();
            @let server_list = conns_per_server
                .keys()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ");
            p style="font-family: var(--mono); font-size: 13px; margin: 4px 0 0; color: var(--ink);" {
                "🟢 "
                b { (tr(lang, "online", "онлайн")) }
                " · " (total_conns) " "
                @if total_conns == 1 { (tr(lang, "conn", "соединение")) }
                @else { (tr(lang, "conns", "соединений")) }
                " "
                @if server_count == 1 { (tr(lang, "on ", "на ")) }
                @else { (tr(lang, "across ", "на ")) }
                span.ed-mono { (server_list) }
            }
            p style="font-family: var(--serif); font-style: italic; font-size: 11.5px; color: var(--mute); margin: 4px 0 0;" {
                (tr(
                    lang,
                    "Live from each node's clash-api snapshot (≤5 min old), attributed by source IP — sing-box doesn't carry the username (NM-11), so a connection whose IP we've never seen on a /sub fetch stays uncounted.",
                    "Из снэпшота clash-api каждой ноды (не старше 5 мин), атрибуция по source IP — sing-box не передаёт имя юзера (NM-11), поэтому соединение с IP, который мы не видели при запросе /sub, не учитывается.",
                ))
            }
        } @else {
            p style="font-family: var(--mono); font-size: 13px; margin: 4px 0 0; color: var(--mute);" {
                (tr(lang, "offline", "офлайн"))
                " · "
                @match last_seen {
                    Some(ts) => {
                        @let ago = humanize_since(ts, lang);
                        (tr(lang, "last seen ", "последний раз ")) (ago)
                    }
                    None => (tr(lang, "never connected", "ни разу не подключался")),
                }
            }
        }
    }
}

/// Compact «X ago» for the presence badge — whole-unit granularity
/// (minutes / hours / days) is enough for «when was this user last
/// active». Clamps a future timestamp (clock skew) to «just now».
fn humanize_since(ts: chrono::DateTime<chrono::Utc>, lang: crate::i18n::Locale) -> String {
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

/// user#2 — traffic split by server. Per-server up/down over the last
/// 24h from `user_traffic_by_server(uid, 24)`. NM-11 empty-state: per-
/// connection clash attribution is NULL upstream, so this table only
/// has data once the poller's `record_vpn_stats` has written per-user
/// rows — until then we render an explainer, not a blank card.
fn user_detail_traffic_by_server_section(
    rows: &[(vpnctl_core::ServerId, u64, u64)],
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow { (tr(lang, "Traffic by server · last 24h", "Трафик по серверам · за 24ч")) }
        @if rows.is_empty() {
            p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 0;" {
                (tr(
                    lang,
                    "No per-server traffic recorded for this user in the last 24h. The split fills in once the clash-api poller has written at least one per-user tick — sing-box's clash-api carries the source IP but not the username (NM-11), so attribution lands a snapshot behind the connection. A blank table here means the user hasn't been seen connected yet, not an error.",
                    "Трафика по серверам у этого юзера за 24ч нет. Разбивка заполнится, как только поллер clash-api запишет хотя бы один per-user тик — clash-api sing-box передаёт source IP, но не имя юзера (NM-11), поэтому атрибуция отстаёт на снэпшот. Пустая таблица здесь значит, что юзера ещё не видели подключённым, а не ошибку.",
                ))
            }
        } @else {
            p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
                (tr(
                    lang,
                    "Per-server upload / download over the last 24h, weighted by each node's usage coefficient. Sums the clash-api per-tick deltas attributed to this user.",
                    "Upload / download по каждому серверу за 24ч, взвешенные коэффициентом нагрузки ноды. Сумма per-тик дельт clash-api, отнесённых к этому юзеру.",
                ))
            }
            table style="width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 11.5px;" {
                thead {
                    tr style="border-bottom: 1px solid var(--ink);" {
                        th style="text-align: left; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                            (tr(lang, "server", "сервер"))
                        }
                        th style="text-align: right; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                            (tr(lang, "uploaded", "отправлено"))
                        }
                        th style="text-align: right; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                            (tr(lang, "downloaded", "принято"))
                        }
                        th style="text-align: right; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                            (tr(lang, "total", "всего"))
                        }
                    }
                }
                tbody {
                    @for (sid, up, dn) in rows {
                        tr style="border-bottom: 1px dotted var(--rule);" {
                            td style="padding: 5px 8px; color: var(--ink);" {
                                a href=(format!("/admin/servers/{}", path_segment_encode(&sid.0))) style="color: var(--ink); text-decoration: none;" { (sid.0) }
                            }
                            td style="padding: 5px 8px; text-align: right; color: var(--ink);" { (humanize_bytes(*up)) }
                            td style="padding: 5px 8px; text-align: right; color: var(--ink);" { (humanize_bytes(*dn)) }
                            td style="padding: 5px 8px; text-align: right; color: var(--ink); font-weight: 500;" { (humanize_bytes(up.saturating_add(*dn))) }
                        }
                    }
                }
            }
        }
    }
}

/// user#4 — one consolidated sharing-evidence verdict line. Folds the
/// 30-day `sub_access_aggregates_for_user` spread (distinct IPs / ASNs
/// / countries) with the UA-cluster `/16` spread (reusing the exact
/// `ua_verdict` thresholds from card #7 / Track-4 so the two surfaces
/// can't disagree). Renders ONE sentence — "likely shared" when either
/// signal trips, "looks single-user" otherwise — above the detailed
/// per-UA table so the operator gets the headline before the evidence.
fn user_sharing_verdict_section(
    aggregates: &vpnctl_inventory::SubAccessAggregates,
    ua_clusters: &[vpnctl_inventory::UaCluster],
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    // ASN spread is the strongest single-query signal (a sub URL
    // fetched from ≥3 distinct ASNs left one human's device fleet).
    // Mirror the dashboard's likely-shared threshold.
    const SHARED_ASN_THRESHOLD: u64 = 3;
    // Reuse the Track-4 UA heuristic verbatim: any UA cluster whose
    // /16 spread trips `ua_verdict` → LikelyShared counts as evidence.
    let ua_shared = ua_clusters.iter().any(|c| {
        matches!(
            ua_verdict(c.distinct_ips, c.distinct_slash16),
            UaVerdict::LikelyShared
        )
    });
    let asn_shared = aggregates.distinct_asns >= SHARED_ASN_THRESHOLD;
    let likely_shared = ua_shared || asn_shared;

    html! {
        div.ed-rule {}
        div.ed-art-eyebrow { (tr(lang, "Sharing verdict", "Вердикт по расшариванию")) }
        @if likely_shared {
            p style="font-family: var(--mono); font-size: 13px; margin: 6px 0 0; color: var(--acc);" {
                b { (tr(lang, "Verdict: likely shared", "Вердикт: вероятно расшарен")) }
                " — "
                (aggregates.distinct_ips) (tr(lang, " IPs", " IP"))
                " / " (aggregates.distinct_asns) (tr(lang, " ASNs", " ASN"))
                " / " (aggregates.distinct_countries) (tr(lang, " countries", " стран"))
                @if ua_shared {
                    (tr(lang, " / UA spread across ISPs", " / UA-разброс по ISP"))
                }
            }
        } @else {
            p style="font-family: var(--mono); font-size: 13px; margin: 6px 0 0; color: var(--soft);" {
                (tr(lang, "Verdict: looks single-user", "Вердикт: похоже на одного юзера"))
                " — "
                (aggregates.distinct_ips) (tr(lang, " IPs", " IP"))
                " / " (aggregates.distinct_asns) (tr(lang, " ASNs", " ASN"))
                " / " (aggregates.distinct_countries) (tr(lang, " countries", " стран"))
            }
        }
        p style="font-family: var(--serif); font-style: italic; font-size: 11.5px; color: var(--mute); margin: 4px 0 0;" {
            (tr(
                lang,
                "Heuristic over the 30-day /sub access window — a subscription fetched from many ASNs / countries, or a single User-Agent spread across many ISP /16 networks, has probably escaped past one human. Not authoritative; cross-check the per-IP timeline below before acting.",
                "Эвристика по 30-дневному окну обращений к /sub — подписка, которую тянут из многих ASN / стран, или один User-Agent, расползшийся по разным ISP /16, скорее всего ушла за пределы одного человека. Не приговор; сверься с таймлайном по IP ниже прежде чем что-то делать.",
            ))
        }
    }
}

/// Shared table-header `<th>` style for the origins breakdown tables —
/// matches the per-fetch sub-access table + UA-cluster table so the
/// three "Subscription origins" tables read as one block.
const ORIGINS_TH: &str = "padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;";
/// Shared body-cell `<td>` style.
const ORIGINS_TD: &str = "padding: 5px 8px;";

/// Reformat an ISO-8601 (UTC) timestamp string from the inventory
/// origins methods (`first_seen` / `last_seen`) into the operator's MSK
/// display string via `format_msk_iso`. Returns the raw string verbatim
/// if it doesn't parse (defensive — never panics, never hides a row).
fn format_origin_ts(raw: &str) -> String {
    match chrono::DateTime::parse_from_rfc3339(raw) {
        Ok(dt) => format_msk_iso(dt.with_timezone(&chrono::Utc)),
        Err(_) => raw.to_string(),
    }
}

/// Classify a reserved / non-routable IP into a short human label so a
/// NULL GeoIP country reads as «private/LAN» or «loopback» instead of
/// the uninformative «(unknown)». For a self-hosted box, most of the
/// «(unknown)» origin rows are the homelab's OWN LAN / loopback /
/// CGNAT addresses hitting the /sub endpoint — labelling them makes
/// the operator instantly see «that's my infra, not a shared URL».
///
/// Returns `None` for an ordinary routable public IP (where
/// «(unknown)» genuinely means «GeoIP has no record») and for an
/// unparseable string. Ranges: RFC1918 private, RFC6598 CGNAT
/// (100.64/10), loopback, link-local (169.254/16, fe80::/10), ULA
/// (fc00::/7), unspecified.
fn classify_reserved_ip(ip: &str) -> Option<&'static str> {
    use std::net::IpAddr;
    match ip.parse::<IpAddr>().ok()? {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            if v4.is_loopback() {
                Some("loopback")
            } else if v4.is_private() {
                Some("private/LAN")
            } else if o[0] == 100 && (o[1] & 0xc0) == 0x40 {
                // 100.64.0.0/10 — carrier-grade NAT (RFC6598).
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
                    // fc00::/7 — unique local address (RFC4193).
                    Some("private/ULA")
                } else if (seg[0] & 0xffc0) == 0xfe80 {
                    // fe80::/10 — link-local.
                    Some("link-local")
                } else {
                    None
                }
            }
        }
    }
}

/// Fallback cell for a source IP whose GeoIP country/ASN came back
/// NULL: render the reserved-range class when the IP is non-routable,
/// else the generic `unknown` marker. Shared by the «Subscription
/// origins · By IP» table and the «Source IPs» traffic section so both
/// treat «(unknown)» identically.
fn ip_geo_fallback(ip: &str, unknown: &str) -> Markup {
    match classify_reserved_ip(ip) {
        Some(cls) => html! { em style="color: var(--mute);" { (cls) } },
        None => html! { em style="color: var(--mute);" { (unknown) } },
    }
}

/// abuse-origins — "Subscription origins" section (anchor `#origins`).
/// The actionable WHO-is-sharing view: three compact tables (by
/// country / by ISP / by IP) + a rough device-count line, all over the
/// 30-day non-egress `/sub` access window. Linked from the dashboard
/// likely-shared card. Renders an empty-state when the user has no
/// external (non-egress) fetches at all.
///
/// Pure render — every input is pre-fetched in `user_detail` (one
/// grouped query each, no N+1). Bilingual via `tr`; timestamps via
/// `format_origin_ts` → `format_msk_iso`.
fn user_subscription_origins_section(
    by_country: &[vpnctl_inventory::SubOriginCountry],
    by_asn: &[vpnctl_inventory::SubOriginAsn],
    by_ip: &[vpnctl_inventory::SubOriginIp],
    device_fp: &vpnctl_inventory::SubDeviceFp,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    let unknown = tr(lang, "(unknown)", "(неизвестно)");
    // "No external fetches" is the union signal — if there are no
    // non-egress rows, all three breakdowns are empty.
    let empty = by_country.is_empty() && by_asn.is_empty() && by_ip.is_empty();

    html! {
        div.ed-rule {}
        // The anchor lives on the eyebrow so `#origins` lands the
        // viewport at the section heading.
        div.ed-art-eyebrow id="origins" {
            (tr(lang, "Subscription origins", "Источники подписки"))
        }
        @if empty {
            p style="font-family: var(--serif); font-style: italic; color: var(--mute); padding: 8px 0;" {
                (tr(
                    lang,
                    "No external subscription fetches recorded — nothing to break down by country, ISP or IP yet.",
                    "Внешних обращений к подписке не записано — пока нечего разбивать по странам, ISP или IP.",
                ))
            }
        } @else {
            p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
                (tr(
                    lang,
                    "Where this one subscription URL was fetched from over the last 30 days — real client IPs only (VPN-egress excluded). Many countries / ISPs / IPs for a single subscription is the clearest who-is-sharing signal.",
                    "Откуда тянули этот один URL подписки за последние 30 дней — только реальные клиентские IP (VPN-egress исключён). Много стран / ISP / IP на одну подписку — самый явный сигнал, что ссылку расшарили.",
                ))
            }

            // Device-count line — a sharing signal on its own.
            // «≈N devices (M UA · K TLS-fingerprints)». N is the max of
            // the device_class / UA / JA4 distinct counts (the best
            // proxy we have), with UA + JA4 broken out so the operator
            // sees what fed the estimate.
            @let approx_devices = device_fp
                .distinct_device_classes
                .max(device_fp.distinct_uas)
                .max(device_fp.distinct_ja4);
            p style="font-family: var(--mono); font-size: 12.5px; color: var(--ink); margin: 0 0 16px;" {
                "≈ " b { (approx_devices) } " "
                (tr(lang, "devices", "устройств"))
                " "
                span style="color: var(--mute);" {
                    "(" (device_fp.distinct_uas) " " (tr(lang, "UA", "UA"))
                    " · " (device_fp.distinct_ja4) " " (tr(lang, "TLS-fingerprints", "TLS-отпечатков")) ")"
                }
            }

            // ── By country ───────────────────────────────────────────
            div.ed-art-eyebrow style="margin-top: 4px;" {
                (tr(lang, "By country", "По странам"))
            }
            table style="width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 11.5px; margin-bottom: 18px;" {
                thead {
                    tr style="border-bottom: 1px solid var(--ink);" {
                        th style=(format!("text-align: left; {ORIGINS_TH}")) { (tr(lang, "country", "страна")) }
                        th style=(format!("text-align: right; {ORIGINS_TH}")) { (tr(lang, "fetches", "обращений")) }
                        th style=(format!("text-align: right; {ORIGINS_TH}")) { (tr(lang, "distinct IPs", "уник. IP")) }
                        th style=(format!("text-align: right; {ORIGINS_TH}")) { (tr(lang, "distinct ASNs", "уник. ASN")) }
                    }
                }
                tbody {
                    @for row in by_country {
                        tr style="border-bottom: 1px dotted var(--rule);" {
                            td style=(format!("{ORIGINS_TD} color: var(--ink);")) {
                                @match row.country.as_deref() {
                                    Some(c) if !c.is_empty() => (c),
                                    _ => em style="color: var(--mute);" { (unknown) },
                                }
                            }
                            td style=(format!("{ORIGINS_TD} text-align: right; color: var(--ink);")) { (row.fetches) }
                            td style=(format!("{ORIGINS_TD} text-align: right; color: var(--soft);")) { (row.ips) }
                            td style=(format!("{ORIGINS_TD} text-align: right; color: var(--soft);")) { (row.asns) }
                        }
                    }
                }
            }

            // ── By ISP ───────────────────────────────────────────────
            div.ed-art-eyebrow {
                (tr(lang, "By ISP", "По провайдерам"))
            }
            table style="width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 11.5px; margin-bottom: 18px;" {
                thead {
                    tr style="border-bottom: 1px solid var(--ink);" {
                        th style=(format!("text-align: left; {ORIGINS_TH}")) { (tr(lang, "ASN / ISP", "ASN / ISP")) }
                        th style=(format!("text-align: left; {ORIGINS_TH}")) { (tr(lang, "country", "страна")) }
                        th style=(format!("text-align: right; {ORIGINS_TH}")) { (tr(lang, "fetches", "обращений")) }
                        th style=(format!("text-align: right; {ORIGINS_TH}")) { (tr(lang, "distinct IPs", "уник. IP")) }
                    }
                }
                tbody {
                    @for row in by_asn {
                        tr style="border-bottom: 1px dotted var(--rule);" {
                            td style=(format!("{ORIGINS_TD} color: var(--ink); overflow-wrap: anywhere;")) {
                                @match row.asn.as_deref() {
                                    Some(a) if !a.is_empty() => (a),
                                    _ => em style="color: var(--mute);" { (unknown) },
                                }
                            }
                            td style=(format!("{ORIGINS_TD} color: var(--soft);")) {
                                @match row.country.as_deref() {
                                    Some(c) if !c.is_empty() => (c),
                                    _ => em style="color: var(--mute);" { (unknown) },
                                }
                            }
                            td style=(format!("{ORIGINS_TD} text-align: right; color: var(--ink);")) { (row.fetches) }
                            td style=(format!("{ORIGINS_TD} text-align: right; color: var(--soft);")) { (row.ips) }
                        }
                    }
                }
            }

            // ── By IP ────────────────────────────────────────────────
            div.ed-art-eyebrow {
                (tr(lang, "By IP", "По IP"))
            }
            table style="width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 11.5px;" {
                thead {
                    tr style="border-bottom: 1px solid var(--ink);" {
                        th style=(format!("text-align: left; {ORIGINS_TH}")) { (tr(lang, "ip", "ip")) }
                        th style=(format!("text-align: left; {ORIGINS_TH}")) { (tr(lang, "country", "страна")) }
                        th style=(format!("text-align: left; {ORIGINS_TH}")) { (tr(lang, "ASN / ISP", "ASN / ISP")) }
                        th style=(format!("text-align: right; {ORIGINS_TH}")) { (tr(lang, "fetches", "обращений")) }
                        th style=(format!("text-align: left; {ORIGINS_TH}")) { (tr(lang, "first seen", "впервые")) }
                        th style=(format!("text-align: left; {ORIGINS_TH}")) { (tr(lang, "last seen", "последний раз")) }
                    }
                }
                tbody {
                    @for row in by_ip {
                        tr style="border-bottom: 1px dotted var(--rule);" {
                            td style=(format!("{ORIGINS_TD} color: var(--ink); overflow-wrap: anywhere;")) { (row.ip) }
                            td style=(format!("{ORIGINS_TD} color: var(--soft);")) {
                                @match row.country.as_deref() {
                                    Some(c) if !c.is_empty() => (c),
                                    _ => (ip_geo_fallback(&row.ip, unknown)),
                                }
                            }
                            td style=(format!("{ORIGINS_TD} color: var(--soft); overflow-wrap: anywhere;")) {
                                @match row.asn.as_deref() {
                                    Some(a) if !a.is_empty() => (a),
                                    _ => (ip_geo_fallback(&row.ip, unknown)),
                                }
                            }
                            td style=(format!("{ORIGINS_TD} text-align: right; color: var(--ink);")) { (row.fetches) }
                            td style=(format!("{ORIGINS_TD} color: var(--soft); white-space: nowrap;")) { (format_origin_ts(&row.first_seen)) }
                            td style=(format!("{ORIGINS_TD} color: var(--soft); white-space: nowrap;")) { (format_origin_ts(&row.last_seen)) }
                        }
                    }
                }
            }
        }
    }
}

/// «Source IPs» — the source-IP counterpart to «Top destinations».
/// Per-(user, source_ip) activity over the last 7 days from the
/// persisted `vpn_user_source_ips` hit-counter (one hit per 5-min
/// clash tick the user had a live connection from that IP), GeoIP-
/// enriched (`geo`: ip → (country, asn)) and reserved-range-classified
/// so a NULL GeoIP country reads as «private/LAN» not «(unknown)».
///
/// This is the «разбей трафик по IP внутри пользователя» view —
/// grounded in ACTUAL VPN connections, not /sub URL fetches (which
/// the «Subscription origins» tables cover). Activity-weighted (hits
/// = ticks-alive) rather than byte-weighted, by deliberate design:
/// per-IP byte deltas would need diff-engine state per (user, ip,
/// conn) tuple (see migration 0034). Many distinct PUBLIC IPs or
/// countries here is the strongest grounded sharing signal.
///
/// Pure render — `rows` and `geo` are pre-fetched in `user_detail`.
fn user_source_ips_section(
    rows: &[vpnctl_inventory::VpnUserSourceIpRow],
    geo: &std::collections::HashMap<String, (Option<String>, Option<String>)>,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    let unknown = tr(lang, "(unknown)", "(неизвестно)");
    // Distinct routable (public) IPs — the sharing-signal headline.
    // Reserved/LAN/CGNAT addresses don't count toward «sharing».
    let distinct_public = rows
        .iter()
        .filter(|r| classify_reserved_ip(&r.source_ip).is_none())
        .count();
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow { (tr(lang, "Source IPs · last 7 days", "Source IP · 7 дней")) }
        @if rows.is_empty() {
            p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 0;" {
                (tr(
                    lang,
                    "No source-IP history yet. The poller records one hit per (client IP, 5-min tick) a connection was attributed to this user — wait for the next clash-api scrape, or the user simply hasn't connected.",
                    "Истории по source IP ещё нет. Поллер пишет один hit на (клиентский IP, 5-мин тик), в котором соединение отнесено к этому юзеру — подожди следующий скрейп clash-api, либо юзер просто не подключался.",
                ))
            }
        } @else {
            p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 12px;" {
                (tr(
                    lang,
                    "Which client IPs this user actually connected FROM (real VPN connections, not /sub fetches), over the last 7 days. Activity-weighted: hits = 5-min ticks the IP was live, not bytes. Private / LAN / CGNAT addresses are labelled rather than left as «(unknown)». Many distinct public IPs or countries = the strongest grounded sharing signal.",
                    "С каких клиентских IP юзер реально подключался (реальные VPN-соединения, не обращения к /sub) за 7 дней. Взвешено активностью: hits = 5-мин тики, в которых IP был живой, не байты. Приватные / LAN / CGNAT адреса подписаны, а не оставлены как «(неизвестно)». Много разных публичных IP или стран = самый достоверный сигнал расшаривания.",
                ))
            }
            p style="font-family: var(--mono); font-size: 12.5px; color: var(--ink); margin: 0 0 14px;" {
                "≈ " b { (distinct_public) } " "
                (tr(lang, "distinct public IPs · 7d", "уник. публичных IP · 7д"))
            }
            table style="width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 11.5px;" {
                thead {
                    tr style="border-bottom: 1px solid var(--ink);" {
                        th style=(format!("text-align: left; {ORIGINS_TH}")) { (tr(lang, "source ip", "source ip")) }
                        th style=(format!("text-align: left; {ORIGINS_TH}")) { (tr(lang, "country / ISP", "страна / ISP")) }
                        th style=(format!("text-align: right; {ORIGINS_TH}"))
                           title=(tr(lang, "Number of 5-min clash ticks where this user had a live connection from this IP. Not bytes, not connection count — activity time.", "Число 5-мин тиков clash, в которых у юзера было живое соединение с этого IP. Не байты и не число соединений — время активности.")) {
                            (tr(lang, "hits · 7d", "hits · 7д"))
                        }
                        th style=(format!("text-align: left; {ORIGINS_TH}")) { (tr(lang, "last seen", "последний раз")) }
                    }
                }
                tbody {
                    @for r in rows {
                        @let (country, asn) = geo.get(&r.source_ip).cloned().unwrap_or((None, None));
                        tr style="border-bottom: 1px dotted var(--rule);" {
                            td style=(format!("{ORIGINS_TD} color: var(--ink); overflow-wrap: anywhere;")) { (r.source_ip) }
                            td style=(format!("{ORIGINS_TD} color: var(--soft); overflow-wrap: anywhere;")) {
                                @match country.as_deref() {
                                    Some(c) if !c.is_empty() => {
                                        (c)
                                        @if let Some(a) = asn.as_deref() {
                                            @if !a.is_empty() {
                                                span style="color: var(--mute);" { " · " (a) }
                                            }
                                        }
                                    }
                                    _ => (ip_geo_fallback(&r.source_ip, unknown)),
                                }
                            }
                            td style=(format!("{ORIGINS_TD} text-align: right; color: var(--ink); font-weight: 500;")) { (r.hit_count) }
                            td style=(format!("{ORIGINS_TD} color: var(--soft); white-space: nowrap;")) { (format_msk(r.last_seen)) }
                        }
                    }
                }
            }
        }
    }
}

/// user#5 — lifecycle facts: created · last seen · last fetch · age.
/// `lifecycle` is Q-4d (`user_lifecycle`), carrying created_at,
/// last_sub_fetch and age_days. `last_seen` is the most recent activity
/// of any kind, sourced from `sub_access_aggregates_for_user.last_seen`
/// (passed in to avoid a re-query). Renders timestamps via the shared
/// `format_msk_iso`.
fn user_lifecycle_section(
    lifecycle: &vpnctl_inventory::UserLifecycle,
    last_seen: Option<chrono::DateTime<chrono::Utc>>,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow { (tr(lang, "Lifecycle", "Жизненный цикл")) }
        div style="display: flex; flex-wrap: wrap; gap: 36px; padding: 10px 0 0; font-family: var(--serif);" {
            div title=(tr(lang, "When this user row was created (users.created_at).", "Когда создана запись пользователя (users.created_at).")) {
                div style="font-size: 16px; font-weight: 400; color: var(--ink); line-height: 1; font-family: var(--mono);" {
                    (format_msk_iso(lifecycle.created_at))
                }
                div style="font-family: var(--mono); font-size: 10.5px; letter-spacing: 0.14em; text-transform: uppercase; color: var(--mute); margin-top: 4px;" {
                    (tr(lang, "created", "создан"))
                }
            }
            div title=(tr(lang, "Most recent activity of any kind seen for this user (last /sub fetch or VPN tick).", "Последняя любая активность юзера (последнее обращение /sub или VPN-тик).")) {
                @match last_seen {
                    Some(ts) => {
                        div style="font-size: 16px; font-weight: 400; color: var(--ink); line-height: 1; font-family: var(--mono);" {
                            (format_msk_iso(ts))
                        }
                    }
                    None => {
                        div style="font-size: 16px; font-weight: 400; color: var(--mute); line-height: 1; font-family: var(--serif); font-style: italic;" {
                            (tr(lang, "never", "никогда"))
                        }
                    }
                }
                div style="font-family: var(--mono); font-size: 10.5px; letter-spacing: 0.14em; text-transform: uppercase; color: var(--mute); margin-top: 4px;" {
                    (tr(lang, "last seen", "последний раз"))
                }
            }
            div title=(tr(lang, "Most recent real (non-egress) /sub subscription fetch.", "Последнее реальное (не-egress) обращение к подписке /sub.")) {
                @match lifecycle.last_sub_fetch {
                    Some(ts) => {
                        div style="font-size: 16px; font-weight: 400; color: var(--ink); line-height: 1; font-family: var(--mono);" {
                            (format_msk_iso(ts))
                        }
                    }
                    None => {
                        div style="font-size: 16px; font-weight: 400; color: var(--mute); line-height: 1; font-family: var(--serif); font-style: italic;" {
                            (tr(lang, "never", "никогда"))
                        }
                    }
                }
                div style="font-family: var(--mono); font-size: 10.5px; letter-spacing: 0.14em; text-transform: uppercase; color: var(--mute); margin-top: 4px;" {
                    (tr(lang, "last fetch", "последнее обращение"))
                }
            }
            div title=(tr(lang, "Whole days since the user row was created.", "Целых дней с момента создания записи юзера.")) {
                div style="font-size: 16px; font-weight: 400; color: var(--ink); line-height: 1; font-family: var(--mono);" {
                    (lifecycle.age_days) " " (tr(lang, "days", "дн"))
                }
                div style="font-family: var(--mono); font-size: 10.5px; letter-spacing: 0.14em; text-transform: uppercase; color: var(--mute); margin-top: 4px;" {
                    (tr(lang, "age", "возраст"))
                }
            }
        }
    }
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
///
/// user#7 (PR-User) — additive geo + last-seen footer. `UaCluster`
/// carries no per-row geo (the heuristic only needs IP/16 spread), so
/// the country / ASN / last-seen columns are summarised once below the
/// table from the user's 30-day `sub_access_aggregates_for_user`
/// (passed in to avoid a re-query). The per-UA table is unchanged.
async fn ua_clusters_section(
    state: &AppState,
    uid: &vpnctl_core::UserId,
    aggregates: &vpnctl_inventory::SubAccessAggregates,
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
        // user#7 — devices/UA geo + last-seen summary. Additive footer
        // under the per-UA table: country / ASN spread + the user's most
        // recent /sub fetch, all from the 30-day aggregates (no extra
        // query). Gives the operator the «where from / how long ago»
        // context the per-UA /16 spread can't.
        div style="display: flex; flex-wrap: wrap; gap: 28px; padding: 12px 0 0; font-family: var(--serif); font-size: 12px; color: var(--mute);" {
            span title=(crate::i18n::tr(lang, "Distinct ISO country codes the subscription was fetched from over the last 30 days (GeoIP).", "Уникальных ISO-кодов стран, из которых тянули подписку за 30 дней (GeoIP).")) {
                span.ed-mono style="color: var(--ink);" { (aggregates.distinct_countries) }
                " " (crate::i18n::tr(lang, "countries · 30d", "стран · 30д"))
            }
            span title=(crate::i18n::tr(lang, "Distinct ASN / ISP labels over the last 30 days (GeoIP-ASN).", "Уникальных ASN / ISP за 30 дней (GeoIP-ASN).")) {
                span.ed-mono style="color: var(--ink);" { (aggregates.distinct_asns) }
                " " (crate::i18n::tr(lang, "ASNs · 30d", "ASN · 30д"))
            }
            span title=(crate::i18n::tr(lang, "Most recent /sub fetch (any IP).", "Последнее обращение к /sub (любой IP).")) {
                (crate::i18n::tr(lang, "last seen ", "последний раз "))
                @match aggregates.last_seen {
                    Some(ts) => span.ed-mono style="color: var(--ink);" { (format_msk_iso(ts)) },
                    None => em { (crate::i18n::tr(lang, "never", "никогда")) },
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
/// Window spec for `vpn_sparkline` — fixed grid of cells, each
/// `bucket_hours` long, ending at «now». 24h × 1h = 24 cells. 7d
/// × 24h = 7 cells. 30d × 24h = 30 cells. all-time uses a stretch
/// bucket so the operator always sees ≤30 bars even when the
/// daemon has been running for months.
#[derive(Clone, Copy, Debug)]
struct VpnSparklineWindow {
    /// Tab id used in the URL (`?window=24h`).
    slug: &'static str,
    /// Human label rendered in the tab + caption.
    label_en: &'static str,
    label_ru: &'static str,
    /// Cells in the grid.
    cells: u32,
    /// Hours covered by each cell.
    bucket_hours: u32,
    /// Optional caption-suffix override (else «per <bucket>»).
    per_bucket_en: &'static str,
    per_bucket_ru: &'static str,
}

const VPN_SPARKLINE_WINDOWS: &[VpnSparklineWindow] = &[
    VpnSparklineWindow {
        slug: "24h",
        label_en: "24h",
        label_ru: "24ч",
        cells: 24,
        bucket_hours: 1,
        per_bucket_en: "per hour",
        per_bucket_ru: "в час",
    },
    VpnSparklineWindow {
        slug: "7d",
        label_en: "7 days",
        label_ru: "7 дней",
        cells: 7,
        bucket_hours: 24,
        per_bucket_en: "per day",
        per_bucket_ru: "в сутки",
    },
    VpnSparklineWindow {
        slug: "30d",
        label_en: "30 days",
        label_ru: "30 дней",
        cells: 30,
        bucket_hours: 24,
        per_bucket_en: "per day",
        per_bucket_ru: "в сутки",
    },
    VpnSparklineWindow {
        slug: "all",
        label_en: "all",
        label_ru: "всё",
        cells: 30,
        bucket_hours: 24 * 30,
        per_bucket_en: "per month",
        per_bucket_ru: "в месяц",
    },
];

fn pick_vpn_sparkline_window(slug: Option<&str>) -> VpnSparklineWindow {
    let s = slug.unwrap_or("24h");
    VPN_SPARKLINE_WINDOWS
        .iter()
        .find(|w| w.slug == s)
        .copied()
        .unwrap_or(VPN_SPARKLINE_WINDOWS[0])
}

/// Multi-window VPN traffic sparkline (24h / 7d / 30d / all).
///
/// 2026-05-23 redesign — Pavel's feedback «график активности
/// непонятный»: the previous 24h-only chart packed 24 bars into
/// 384 px so each cell was 14 px wide, and a single hour of
/// activity surrounded by 23 empty hours looked like a noise
/// spike rather than a usable signal. Operator also wanted
/// «больше чем за 24 часа а еще и за все время». The redesign:
/// (a) supports four window slugs picked via `?window=...` query
/// param, (b) widens cells for smaller cell counts (7d → 50 px
/// bars instead of 14 px), (c) draws a 50%-of-max horizontal
/// rule so the operator can gauge «is this typical or a spike»,
/// (d) inline SVG `<title>` tooltips on each bar so hover shows
/// the absolute byte count for that bucket.
/// Round a byte count up to a «nice» tick value for Y-axis labels.
/// Powers-of-1024 family: 1, 2, 5, 10, 20, 50 × {KiB, MiB, GiB, TiB}.
/// Picks the smallest nice value ≥ `n`. Returns 1 KiB minimum so we
/// never emit a `0`-labelled axis for trace-but-nonzero traffic.
fn nice_byte_ceiling(n: u64) -> u64 {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;
    const TIB: u64 = 1024 * GIB;
    let units = [
        KIB,
        2 * KIB,
        5 * KIB,
        10 * KIB,
        20 * KIB,
        50 * KIB,
        100 * KIB,
        200 * KIB,
        500 * KIB,
        MIB,
        2 * MIB,
        5 * MIB,
        10 * MIB,
        20 * MIB,
        50 * MIB,
        100 * MIB,
        200 * MIB,
        500 * MIB,
        GIB,
        2 * GIB,
        5 * GIB,
        10 * GIB,
        20 * GIB,
        50 * GIB,
        100 * GIB,
        200 * GIB,
        500 * GIB,
        TIB,
        2 * TIB,
        5 * TIB,
        10 * TIB,
    ];
    for &u in &units {
        if u >= n.max(1) {
            return u;
        }
    }
    n
}

/// Format an X-axis tick label for the given bucket-start instant.
/// 1h buckets → `HH:MM` (e.g. «14:00»). 24h buckets → `MMM DD`
/// (e.g. «May 17»). 30d buckets → `MMM YYYY` (e.g. «May 2026»).
///
/// 2026-05-23 — converts to MSK (+03:00) before formatting. The
/// hourly bucket label especially matters: a peak at «14:00 UTC»
/// shown as «14:00» reads as 14:00 MSK, which is 11:00 UTC actually
/// — operator's intuition («it's 5pm Moscow time») gets the wrong
/// bar. Daily and monthly labels also shift, but the visual delta
/// is tiny (one day at most).
fn x_axis_tick_label(t: chrono::DateTime<chrono::Utc>, bucket_hours: u32) -> String {
    let fmt = if bucket_hours == 1 {
        "%H:%M"
    } else if bucket_hours == 24 {
        "%b %d"
    } else {
        "%b %Y"
    };
    t.with_timezone(&display_tz()).format(fmt).to_string()
}

/// user#6 — per-cell (upload + download) byte totals for the compact
/// `sparkline_svg` trend folded into `live_vpn_stats_section`. Buckets
/// `rows` into `window.cells` cells of `window.bucket_hours` each,
/// newest cell on the right — identical bucketing to `vpn_traffic_chart`
/// so the sparkline and the full chart can't disagree. Returns one f64
/// per cell (bytes); an all-zero series means «no traffic in window»
/// and the caller skips rendering the sparkline.
fn vpn_traffic_trend_series(
    rows: &[vpnctl_inventory::VpnStatsRow],
    window: VpnSparklineWindow,
) -> Vec<f64> {
    use chrono::{DurationRound, TimeDelta, Utc};
    let cells = window.cells as usize;
    let bucket_seconds = window.bucket_hours as i64 * 3600;
    let now = match Utc::now().duration_trunc(TimeDelta::seconds(bucket_seconds)) {
        Ok(t) => t,
        Err(_) => return vec![0.0; cells],
    };
    let mut per_cell: Vec<u64> = vec![0; cells];
    for r in rows {
        let row_t = match r.ts.duration_trunc(TimeDelta::seconds(bucket_seconds)) {
            Ok(t) => t,
            Err(_) => continue,
        };
        let buckets_ago = now.signed_duration_since(row_t).num_seconds() / bucket_seconds;
        if !(0..cells as i64).contains(&buckets_ago) {
            continue;
        }
        let idx = (cells as i64 - 1 - buckets_ago) as usize;
        per_cell[idx] =
            per_cell[idx].saturating_add(r.upload_bytes.saturating_add(r.download_bytes));
    }
    per_cell.into_iter().map(|v| v as f64).collect()
}

/// PowerBI / Tableau-style stacked bar chart for VPN traffic.
///
/// Replaces the previous bare-bones sparkline. The redesign is
/// 2026-05-23 follow-up to Pavel's feedback: «график без явных
/// осей x и у… посмотри как оформляют аналитические данные в
/// powerbi или в tableau». Now includes:
///
/// * **Y-axis** on the left with 5 tick labels (`0`, `25%`, `50%`,
///   `75%`, `100%` of the «nice»-rounded max) — each labeled with
///   the byte count, not a raw percentage.
/// * **Horizontal grid lines** at every Y tick, drawn in
///   `var(--rule)` so they recede visually behind the bars.
/// * **X-axis** below with date / time labels at meaningful
///   intervals (every 6h for 24h, every day for 7d, every 5 days
///   for 30d, every 6 months for «all»). Dense windows skip ticks
///   to avoid label collision.
/// * **Stacked bars** — upload at bottom, download on top, both
///   in the editorial accent palette.
/// * **Legend** (`■ download · ■ upload`) below the chart so the
///   colour mapping is unambiguous.
/// * **Per-bar tooltip** via SVG `<title>` showing bucket start +
///   absolute byte values.
/// * **Summary line** below legend: `max X per Y · total Z`.
///
/// Chart geometry: 720×240 viewBox with 56 px left padding for
/// Y labels and 32 px bottom padding for X labels. Scales
/// responsively via `style="width: 100%; max-width: 720px;
/// height: auto"`.
fn vpn_traffic_chart(
    rows: &[vpnctl_inventory::VpnStatsRow],
    window: VpnSparklineWindow,
    lang: crate::i18n::Locale,
) -> Markup {
    use chrono::{DurationRound, TimeDelta, Utc};
    let per_bucket = match lang {
        crate::i18n::Locale::En => window.per_bucket_en,
        crate::i18n::Locale::Ru => window.per_bucket_ru,
    };
    let cells = window.cells as usize;
    let bucket_seconds = window.bucket_hours as i64 * 3600;
    let now = match Utc::now().duration_trunc(TimeDelta::seconds(bucket_seconds)) {
        Ok(t) => t,
        Err(_) => return html! {},
    };
    let mut up_per_cell: Vec<u64> = vec![0; cells];
    let mut dn_per_cell: Vec<u64> = vec![0; cells];
    for r in rows {
        let row_t = match r.ts.duration_trunc(TimeDelta::seconds(bucket_seconds)) {
            Ok(t) => t,
            Err(_) => continue,
        };
        let diff = now.signed_duration_since(row_t);
        let buckets_ago = diff.num_seconds() / bucket_seconds;
        if !(0..cells as i64).contains(&buckets_ago) {
            continue;
        }
        let idx = (cells as i64 - 1 - buckets_ago) as usize;
        up_per_cell[idx] = up_per_cell[idx].saturating_add(r.upload_bytes);
        dn_per_cell[idx] = dn_per_cell[idx].saturating_add(r.download_bytes);
    }
    let raw_max = up_per_cell
        .iter()
        .zip(dn_per_cell.iter())
        .map(|(u, d)| u.saturating_add(*d))
        .max()
        .unwrap_or(0);
    let total_window: u64 = up_per_cell
        .iter()
        .zip(dn_per_cell.iter())
        .map(|(u, d)| u.saturating_add(*d))
        .sum();
    // Y-axis ceiling rounded UP to the nearest «nice» power-of-1024
    // step so the topmost label reads clean («10 GiB» instead of
    // «8.7 GiB» — operators round in their head anyway, the chart
    // should do it for them).
    let y_max = nice_byte_ceiling(raw_max);
    // Chart geometry. Coordinates are in SVG-user units; the outer
    // <svg> uses `viewBox` so the chart scales responsively to its
    // container width without distorting proportions.
    let vb_w = 720;
    let vb_h = 240;
    let pad_l = 64; // y-axis label column
    let pad_r = 16; // breathing room on right
    let pad_t = 12; // top breathing room
    let pad_b = 44; // x-axis label row + legend
    let plot_w = (vb_w - pad_l - pad_r) as f64;
    let plot_h = (vb_h - pad_t - pad_b) as f64;
    let n_ticks_y: usize = 4;
    let bar_slot = plot_w / cells as f64;
    let bar_gap = if cells > 14 { 2.0 } else { 4.0 };
    let bar_w = (bar_slot - bar_gap).max(2.0);
    let mut svg_inner = String::new();
    // Y-axis grid lines + labels at 0, 25%, 50%, 75%, 100% of y_max.
    for t in 0..=n_ticks_y {
        let frac = t as f64 / n_ticks_y as f64;
        let val = ((y_max as f64) * frac) as u64;
        let y = pad_t as f64 + plot_h - frac * plot_h;
        // Grid line spans the plot area only (not over the label
        // column) so the chart-area / label-column separation is
        // clean. Skip the topmost line if it'd touch the chart
        // border.
        svg_inner.push_str(&format!(
            r#"<line x1="{x1}" y1="{y:.1}" x2="{x2}" y2="{y:.1}" stroke="var(--rule)" stroke-width="0.5"/>"#,
            x1 = pad_l,
            x2 = vb_w - pad_r,
        ));
        // Right-aligned Y label.
        svg_inner.push_str(&format!(
            r#"<text x="{x:.1}" y="{ty:.1}" text-anchor="end" font-family="var(--mono)" font-size="10" fill="var(--mute)">{label}</text>"#,
            x = pad_l as f64 - 6.0,
            ty = y + 3.0,
            label = if val == 0 {
                "0".to_string()
            } else {
                humanize_bytes(val)
            },
        ));
    }
    // X-axis baseline (the «0» line is implicit in the lowest grid
    // row above, but draw an explicit darker line so the chart has
    // a clear floor).
    svg_inner.push_str(&format!(
        r#"<line x1="{x1}" y1="{y:.1}" x2="{x2}" y2="{y:.1}" stroke="var(--ink)" stroke-width="0.8"/>"#,
        x1 = pad_l,
        x2 = vb_w - pad_r,
        y = pad_t as f64 + plot_h,
    ));
    // Bars + per-bar tooltips. Iterate cells; for each non-zero
    // total, draw upload then download stacked.
    for i in 0..cells {
        let up = up_per_cell[i];
        let dn = dn_per_cell[i];
        let total = up.saturating_add(dn);
        let x_left = pad_l as f64 + i as f64 * bar_slot + bar_gap / 2.0;
        let bucket_start =
            now - chrono::Duration::seconds((cells as i64 - 1 - i as i64) * bucket_seconds);
        let tooltip = format!(
            "{label}\n↓ download: {dn_h}\n↑ upload: {up_h}\ntotal: {t_h}",
            label = x_axis_tick_label(bucket_start, window.bucket_hours),
            dn_h = humanize_bytes(dn),
            up_h = humanize_bytes(up),
            t_h = humanize_bytes(total),
        );
        // Empty bar still gets a hover-rect so tooltip works even
        // on quiet hours («0 download, 0 upload at 03:00»). Hover
        // rect is invisible (fill="transparent") but full plot
        // height for easy targeting.
        svg_inner.push_str(&format!(
            r#"<g><title>{tooltip}</title><rect x="{x:.1}" y="{ht_y}" width="{w:.1}" height="{ht_h:.1}" fill="transparent"/>"#,
            x = x_left,
            ht_y = pad_t,
            w = bar_w,
            ht_h = plot_h,
        ));
        if y_max > 0 && total > 0 {
            let up_h = (up as f64 / y_max as f64) * plot_h;
            let dn_h = (dn as f64 / y_max as f64) * plot_h;
            let up_y = pad_t as f64 + plot_h - up_h;
            let dn_y = up_y - dn_h;
            if up_h > 0.3 {
                svg_inner.push_str(&format!(
                    r#"<rect x="{x:.1}" y="{up_y:.1}" width="{w:.1}" height="{up_h:.1}" fill="var(--soft)"/>"#,
                    x = x_left,
                    w = bar_w,
                ));
            }
            if dn_h > 0.3 {
                svg_inner.push_str(&format!(
                    r#"<rect x="{x:.1}" y="{dn_y:.1}" width="{w:.1}" height="{dn_h:.1}" fill="var(--acc)"/>"#,
                    x = x_left,
                    w = bar_w,
                ));
            }
        }
        svg_inner.push_str("</g>");
    }
    // X-axis labels. Pick tick interval so we render ~5-8 labels
    // total — denser windows skip ticks to avoid collision.
    let tick_every = match cells {
        0..=8 => 1,
        9..=16 => 2,
        17..=32 => 5,
        _ => 6,
    };
    for i in 0..cells {
        if i % tick_every != 0 && i != cells - 1 {
            continue;
        }
        let x_center = pad_l as f64 + i as f64 * bar_slot + bar_slot / 2.0;
        let bucket_start =
            now - chrono::Duration::seconds((cells as i64 - 1 - i as i64) * bucket_seconds);
        let label = x_axis_tick_label(bucket_start, window.bucket_hours);
        svg_inner.push_str(&format!(
            r#"<text x="{x:.1}" y="{y}" text-anchor="middle" font-family="var(--mono)" font-size="10" fill="var(--mute)">{label}</text>"#,
            x = x_center,
            y = vb_h - pad_b + 18,
        ));
    }
    let svg = format!(
        r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {vb_w} {vb_h}" preserveAspectRatio="xMidYMid meet" aria-label="VPN traffic chart" style="display: block; width: 100%; max-width: 720px; height: auto;">{svg_inner}</svg>"#,
    );
    html! {
        div style="margin: 12px 0; padding: 12px 14px; background: var(--paper); border: 1px solid var(--rule);" {
            (maud::PreEscaped(svg))
            // Legend + summary line. Inline-flex so they stay on
            // one row when there's space and wrap on narrow viewports.
            div style="display: flex; flex-wrap: wrap; justify-content: space-between; align-items: baseline; gap: 12px; font-family: var(--mono); font-size: 11px; color: var(--mute); margin-top: 4px; padding: 0 4px;" {
                span {
                    span style="display: inline-block; width: 10px; height: 10px; background: var(--acc); vertical-align: middle; margin-right: 4px;" {}
                    (crate::i18n::tr(lang, "download", "загрузка"))
                    "  ·  "
                    span style="display: inline-block; width: 10px; height: 10px; background: var(--soft); vertical-align: middle; margin-right: 4px;" {}
                    (crate::i18n::tr(lang, "upload", "отправка"))
                }
                span {
                    (crate::i18n::tr(lang, "max ", "макс "))
                    b style="color: var(--ink);" { (humanize_bytes(raw_max)) }
                    " " (per_bucket) "  ·  "
                    (crate::i18n::tr(lang, "total ", "всего "))
                    b style="color: var(--ink);" { (humanize_bytes(total_window)) }
                }
            }
        }
    }
}

/// Top-of-page «time window» picker (2026-05-23 — Pavel «возможность
/// выбора как window: 24h / 7 days / 30 days / all»).
///
/// Renders ONE shared picker that drives every time-series tile on
/// the page below (VPN activity, Heavy users, Fleet traffic chart,
/// user-detail Live VPN stats, …). Sits at the top so the operator
/// picks once and scrolls down to see all tiles in sync.
///
/// Tab links use `#timeframe` anchor so a click jumps the browser
/// BACK to this picker (not the page top) after the reload —
/// preserves Pavel's «scroll-to-top is annoying» feedback.
///
/// `base_url` is the absolute path WITHOUT query string.
fn window_picker_section(base_url: &str, active_slug: &str, lang: crate::i18n::Locale) -> Markup {
    html! {
        div id="timeframe" style="margin: 20px 0 6px; padding: 10px 14px; border: 1px solid var(--rule); background: var(--paper); display: flex; flex-wrap: wrap; gap: 18px; align-items: baseline;" {
            span style="font-family: var(--mono); font-size: 11px; color: var(--mute); text-transform: uppercase; letter-spacing: 0.14em;" {
                (crate::i18n::tr(lang, "Window", "Окно"))
            }
            div style="display: flex; gap: 14px; font-family: var(--mono); font-size: 13px;" {
                @for w in VPN_SPARKLINE_WINDOWS {
                    @let label = match lang {
                        crate::i18n::Locale::En => w.label_en,
                        crate::i18n::Locale::Ru => w.label_ru,
                    };
                    @if w.slug == active_slug {
                        span style="font-weight: 600; color: var(--ink); border-bottom: 1.5px solid var(--ink); padding-bottom: 1px;" {
                            (label)
                        }
                    } @else {
                        a href=(format!("{base_url}?vpn_window={}#timeframe", w.slug))
                          style="color: var(--mute); text-decoration: none; border-bottom: 1px dotted var(--mute); padding-bottom: 1px;" {
                            (label)
                        }
                    }
                }
            }
            span style="font-family: var(--serif); font-style: italic; color: var(--mute); font-size: 11px; margin-left: auto;" {
                (crate::i18n::tr(
                    lang,
                    "→ all charts + tiles below update together (custom date range — coming next)",
                    "→ все графики и плитки ниже обновляются вместе (произвольный диапазон дат — в следующем релизе)",
                ))
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

/// user#3 — straight-line month-end traffic projection. Extrapolates
/// `used` (month-to-date bytes) to a full-month estimate assuming the
/// rest of the month matches the daily average so far:
/// `used / day_of_month × days_in_month`.
///
/// Returns `None` when `used == 0` (nothing to project — the «0»
/// projection is noise, not signal) so the caller can skip the line.
/// `day_of_month` is calendar-1-based and therefore never 0, but the
/// `.max(1)` guard makes the division provably panic-free regardless
/// of any future clock-skew bug. Saturating arithmetic throughout.
fn project_month_end(used: u64) -> Option<u64> {
    use chrono::Datelike;
    if used == 0 {
        return None;
    }
    let now = chrono::Utc::now();
    let day = u64::from(now.day()).max(1); // 1..=31, guarded
    let days_in_month = u64::from(days_in_month(now.year(), now.month()));
    // used / day × days_in_month, computed in u128 to avoid an
    // intermediate overflow on a multi-TiB month, then saturated back.
    let projected = (u128::from(used) * u128::from(days_in_month)) / u128::from(day);
    Some(projected.min(u128::from(u64::MAX)) as u64)
}

/// Calendar days in `(year, month)`. Handles leap Februaries. Returns
/// 30 for an out-of-range month (defensive — `chrono::Month` is always
/// 1..=12 in practice, but the fallback keeps the projection finite).
fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
            if leap { 29 } else { 28 }
        }
        _ => 30,
    }
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
                // user#3 — straight-line month-end projection. «If the
                // rest of the month looks like the part so far»:
                // used / day-of-month × days-in-month. Guards the
                // day-of-month == 0 impossibility (calendar days are
                // 1-based; the guard is belt-and-suspenders so a future
                // clock bug can't divide by zero). Only meaningful with
                // a cap set, so it lives in this arm.
                @if let Some(projected) = project_month_end(used) {
                    @let proj_pct = ((projected as u128 * 100) / lim as u128).min(999) as u32;
                    @let proj_over = proj_pct >= 100;
                    p style="font-family: var(--mono); font-size: 12px; margin: 0 0 14px; color: var(--mute);" {
                        (tr(lang, "projected ", "прогноз "))
                        span style=(if proj_over { "color: var(--acc); font-weight: 600;" } else { "color: var(--ink);" }) {
                            (humanize_bytes(projected))
                        }
                        (tr(lang, " by month-end (", " к концу месяца ("))
                        (proj_pct) (tr(lang, "% of cap)", "% лимита)"))
                        @if proj_over {
                            " · "
                            (tr(lang, "on track to exceed the cap", "по тренду превысит лимит"))
                        }
                    }
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
    window_slug: Option<&str>,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::{K, t, tr};
    let window = pick_vpn_sparkline_window(window_slug);
    let since_hours = window.cells * window.bucket_hours;
    let rows = match state.inv.recent_vpn_stats_for_user(uid, since_hours).await {
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
                    // Honest copy (audit 2026-06-10): the scheduler is
                    // LIVE (spawn_clash_poller, 5-min cadence) — blank
                    // here means no snapshot reached this user yet:
                    // poller can't SSH the node, sing-box clash-api off,
                    // or the user simply hasn't connected.
                    "No live stats yet. The clash-api poller runs every 5 minutes — blank means no snapshot has covered this user yet: the node may be unreachable over SSH, its sing-box may lack the clash-api block, or the user hasn't connected. The poller needs the SSH key on the vpnctld host's ",
                    "Живой статистики пока нет. Поллер clash-api снимает снэпшоты каждые 5 минут — пусто значит ни один снэпшот ещё не зацепил этого юзера: нода может быть недоступна по SSH, в её sing-box может не быть clash-api блока, либо юзер не подключался. Поллеру нужен SSH-ключ на хосте vpnctld в ",
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

    let window_label = match lang {
        crate::i18n::Locale::En => window.label_en,
        crate::i18n::Locale::Ru => window.label_ru,
    };
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow {
            (tr(lang, "Live VPN stats · ", "Живая VPN-статистика · "))
            (window_label)
        }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
            (tr(
                lang,
                "Pulled from each node's clash-api by the daemon. Numbers reflect actual VPN traffic (delta-vs-prior-snapshot per tick), not subscription-config fetches.",
                "Снимается с clash-api каждой ноды демоном. Числа — реальный VPN-трафик (дельта-к-прошлому-снэпшоту на каждом тике), не запросы конфига подписки.",
            ))
        }
        div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin: 12px 0 18px;" {
            (status_tile("uploaded", &humanize_bytes(total_up), "var(--ink)"))
            (status_tile("downloaded", &humanize_bytes(total_dn), "var(--ink)"))
            (status_tile("peak conns", &peak_conns.to_string(), "var(--ink)"))
        }
        // user#6 — 7d/30d traffic trend folded in here. A
        // `window_picker_section` scoped to THIS user's detail page lets
        // the operator widen the window (24h / 7d / 30d / all) without a
        // separate query — the section already re-fetched `rows` at the
        // picked window above, so the compact `sparkline_svg` below just
        // re-buckets those same rows into per-cell (up+down) totals. The
        // full PowerBI-style chart still renders below; this is the
        // at-a-glance shape so a 30-day trend is one click away.
        (window_picker_section(
            &format!("/admin/users/{}/traffic", path_segment_encode(&uid.0)),
            window.slug,
            lang,
        ))
        @let trend = vpn_traffic_trend_series(&rows, window);
        @if trend.iter().any(|&v| v > 0.0) {
            div style="margin: 6px 0 18px;" {
                div style="font-family: var(--mono); font-size: 10.5px; letter-spacing: 0.14em; text-transform: uppercase; color: var(--mute); margin-bottom: 2px;" {
                    (tr(lang, "traffic trend · ", "тренд трафика · ")) (window_label)
                }
                (sparkline_svg(&trend, 720, 60))
            }
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
        // 2026-05-23 — PowerBI-style chart. Window picker now
        // lives at top of page (`window_picker_section`); chart-
        // internal tabs removed so the operator has one mental
        // model «pick once, all tiles update». Anchor stays so
        // tab clicks from the top picker (or anchor links from
        // elsewhere) scroll back to the chart.
        div id="vpn-traffic" {
            (vpn_traffic_chart(&rows, window, lang))
        }
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

/// Format a UTC timestamp in the operator-configured display
/// timezone (set via /admin/settings, persisted in
/// `display_settings.timezone`, default «Europe/Moscow»). The
/// trailing UPPERCASE abbreviation (e.g. «MSK», «EST», «UTC»)
/// makes the zone explicit so nobody mistakes the column for UTC.
///
/// Renamed from `format_msk` 2026-05-23 when the timezone became
/// operator-configurable. Both this short variant (`%m-%d %H:%M
/// <ZONE>`) and the year-bearing [`format_local_iso`] read from
/// the same global TZ cache initialised at startup +
/// hot-reloaded by the Settings POST handler.
fn format_msk(dt: chrono::DateTime<chrono::Utc>) -> String {
    format_local_with_pattern(dt, "%m-%d %H:%M")
}

/// Same as [`format_msk`] but emits the year too (`%Y-%m-%d %H:%M <ZONE>`).
/// Used for «last fetch / last sample» tile timestamps where the
/// operator needs the absolute date — those values can be days/weeks
/// old, so dropping the year would be ambiguous.
fn format_msk_iso(dt: chrono::DateTime<chrono::Utc>) -> String {
    format_local_with_pattern(dt, "%Y-%m-%d %H:%M")
}

/// Inner helper: format `dt` with `pattern` followed by a space and
/// the chosen zone's abbreviation (e.g. «MSK», «UTC», «EST»). On
/// any failure to read the configured tz, fall back to UTC.
pub(crate) fn format_local_with_pattern(
    dt: chrono::DateTime<chrono::Utc>,
    pattern: &str,
) -> String {
    let tz = display_tz();
    let local = dt.with_timezone(&tz);
    // chrono-tz's `Tz::name()` gives the IANA name (`Europe/Moscow`);
    // the operator wants a short abbreviation (`MSK`). chrono's
    // `format("%Z")` resolves the abbreviation per-instant
    // (respects DST: «EST» vs «EDT» depending on date).
    local.format(&format!("{pattern} %Z")).to_string()
}

/// Process-global cache of the operator-configured display
/// timezone. Initialised on startup by `init_display_tz` (called
/// from `app::make_app_state*`); hot-reloaded by the
/// `POST /admin/settings/timezone` handler via
/// `set_display_tz_cache`.
///
/// Read on every UI timestamp render — `format_msk_iso` /
/// `format_msk` / `x_axis_tick_label` / audit day-grouping. The
/// `RwLock` is read-mostly (writes happen only when the operator
/// flips the Settings dropdown); reads are cheap and non-blocking.
static DISPLAY_TZ: std::sync::OnceLock<std::sync::RwLock<chrono_tz::Tz>> =
    std::sync::OnceLock::new();

/// Initialise the global timezone cache from the inventory's
/// `display_settings.timezone`. Called once from `make_app_state*`
/// at daemon startup. Idempotent — second call is a no-op (the
/// `OnceLock` is set once).
pub(crate) fn init_display_tz(tz: chrono_tz::Tz) {
    let _ = DISPLAY_TZ.set(std::sync::RwLock::new(tz));
}

/// Update the cached display timezone after the operator changes
/// the Settings page value. Subsequent timestamp renders see the
/// new zone immediately — no restart needed.
pub(crate) fn set_display_tz_cache(tz: chrono_tz::Tz) {
    if let Some(lock) = DISPLAY_TZ.get() {
        if let Ok(mut guard) = lock.write() {
            *guard = tz;
        }
    } else {
        // Cache not yet initialised (shouldn't happen in production
        // but defensive). Set it now.
        let _ = DISPLAY_TZ.set(std::sync::RwLock::new(tz));
    }
}

/// Read the current display timezone. Defaults to `Europe/Moscow`
/// if the cache hasn't been initialised yet (tests, early startup).
pub(crate) fn display_tz() -> chrono_tz::Tz {
    DISPLAY_TZ
        .get()
        .and_then(|lock| lock.read().ok().map(|g| *g))
        .unwrap_or(chrono_tz::Europe::Moscow)
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

// `json_for_script` removed 2026-06-10 — its only caller was the GeoIP
// «update now» inline `<script>`, which the admin CSP (`script-src
// 'self'`, no 'unsafe-inline') silently refused anyway; the button is
// now wired through admin.js's `[data-sse-url]` trigger. If inline-
// script interpolation ever returns, remember the `</` → `<\/` escape
// it carried (un-escaped `</script>` inside a JSON string = XSS).

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
        "/admin/users/{}/overview",
        path_segment_encode(&user_id_str)
    ))
    .into_response()
}

/// `POST /admin/users/{id}/tuic-password/mint` — mint a per-user
/// `tuic_password` for a user that has none. naive + Hysteria2 reuse
/// this field as their per-user secret, so a user without it silently
/// gets NO naive / Hysteria2 (or TUIC) links — exactly the `cdn`
/// 2026-06-07 incident. This is the operator's one-click fix.
/// Idempotent: a user who already has one is a no-op (we never rotate a
/// live password, which would break their links until redeploy). After
/// minting, the operator redeploys the user's servers so the node
/// accepts the new password.
pub(crate) async fn user_mint_tuic_password(
    State(state): State<AppState>,
    Path(user_id_str): Path<String>,
) -> Response {
    let uid = vpnctl_core::UserId(user_id_str.clone());
    match state.inv.get_user(&uid).await {
        Ok(Some(_)) => {}
        Ok(None) => return user_not_found(&user_id_str),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    }
    match state.inv.mint_tuic_password_if_absent(&uid).await {
        Ok(true) => {
            if let Err(e) = state
                .inv
                .audit("admin", "user.mint_tuic_password", Some(&user_id_str), None)
                .await
            {
                tracing::warn!(
                    target = "vpnctld::admin",
                    user = %user_id_str,
                    error = %e,
                    "audit write failed for user.mint_tuic_password — mutation already committed"
                );
            }
        }
        // Already had a password — idempotent no-op, no audit spam.
        Ok(false) => {}
        Err(e) => return internal_error(anyhow::Error::new(e)),
    }
    Redirect::to(&format!(
        "/admin/users/{}/overview",
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
        "/admin/users/{}/delivery",
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
    Redirect::to("/admin/settings/backups#backups-section").into_response()
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
            a href="/admin/settings/backups#backups-section"
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

    // NM-10 contract (audit 2026-06-10): a no-op re-POST (inserted == 0)
    // writes NO audit row — unconditional writes polluted the timeline
    // and the `newly_added` flag inside is honest-but-buried.
    if inserted == 1
        && let Err(e) = state
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
        "/admin/servers/{}/protocols#enabled-protocols",
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

    // NM-10 contract (audit 2026-06-10): a no-op re-POST (removed == 0)
    // writes NO audit row — unconditional writes polluted the timeline
    // and the `was_present` flag inside is honest-but-buried.
    if removed == 1
        && let Err(e) = state
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
        "/admin/servers/{}/protocols#enabled-protocols",
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
        "/admin/users/{}/overview",
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

    // Membership BEFORE the grant — the audit row is written only for
    // a NEW grant. An idempotent re-grant must NOT add a fresh
    // `user.grant` row: it would falsely re-mark the server
    // pending-deploy until a no-op redeploy (review-agent important;
    // matches the bulk path's skip-already-granted semantics).
    let was_granted = match state.inv.servers_for_user(&uid).await {
        Ok(v) => v.iter().any(|s| s.id == sid),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    if let Err(e) = state.inv.grant(&uid, &sid).await {
        return internal_error(anyhow::Error::new(e));
    }
    // Canonical grant-audit shape (2026-06-04 unification): per-user
    // `user.grant` row with target = USER id. The pending-deploy
    // detector keys on exactly this; the previous `action="grant",
    // target=<server>` row was invisible to it, so a grant made from
    // the server-detail page never raised the «config not yet
    // deployed» banner once the server had its first deploy baseline.
    if !was_granted
        && let Err(e) = state
            .inv
            .audit(
                "admin",
                "user.grant",
                Some(&user_id_str),
                Some(&serde_json::json!({
                    "server": server_id_str,
                    "source": "server-detail",
                })),
            )
            .await
    {
        tracing::warn!(target = "vpnctld::admin", error = %e, "audit write failed for user.grant");
    }
    Redirect::to(&format!(
        "/admin/servers/{}/grants",
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
    // User-existence check — the grant twin always had it; without it
    // an unknown user 200-redirected as if revoked (audit 2026-06-10).
    match state.inv.get_user(&uid).await {
        Ok(Some(_)) => {}
        Ok(None) => return user_not_found(&user_id_str),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    }
    // Membership BEFORE the revoke — the audit row is written only for
    // an ACTUAL revoke (mirror of the grant paths' 2026-06-04 shape).
    let was_granted = match state.inv.servers_for_user(&uid).await {
        Ok(v) => v.iter().any(|s| s.id == sid),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    if let Err(e) = state.inv.revoke(&uid, &sid).await {
        return internal_error(anyhow::Error::new(e));
    }
    // Canonical per-user `user.revoke` (target = USER id) — the
    // pending-deploy detector keys on per-user mutation rows; the old
    // `action="revoke", target=<server>` row was invisible to it, so a
    // revoked UUID stayed live on the node with no warning anywhere.
    if was_granted
        && let Err(e) = state
            .inv
            .audit(
                "admin",
                "user.revoke",
                Some(&user_id_str),
                Some(&serde_json::json!({
                    "server": server_id_str,
                    "source": "server-detail",
                })),
            )
            .await
    {
        tracing::warn!(target = "vpnctld::admin", error = %e, "audit write failed for user.revoke");
    }
    Redirect::to(&format!(
        "/admin/servers/{}/grants",
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

    // Concurrency gate: refuse a second node-touching deploy of THIS
    // server while one is already in flight (another tab, a curl, the
    // SSE deploy / deploy-all path). Without it two pipelines render +
    // restart the same sing-box at once. The permit is released when
    // this handler returns (RAII) — including every early-return error
    // path below.
    let _deploy_guard = match crate::wizard_bootstrap::DeployGuard::try_acquire(&server.id.0) {
        Some(g) => g,
        None => {
            return error_resp(
                StatusCode::CONFLICT,
                &format!(
                    "deploy already running for server '{}' — wait for it to finish, then retry",
                    server.id.0
                ),
            );
        }
    };

    // Bootstrap missing secrets. Shared with the Phase-E wizard
    // via `wizard_bootstrap::bootstrap_server_secrets` so any new
    // server-side secret added for a future protocol is minted
    // identically by deploy + wizard. Idempotent — re-clicking
    // deploy when everything is already minted is a safe no-op.
    let (secrets, bootstrapped) = match crate::wizard_bootstrap::bootstrap_server_secrets(
        &state.inv,
        &server,
        &state.registry,
    )
    .await
    {
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
        Some("deploy key absent; see /admin/settings/system")
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
            // Reserved-ports pre-apply guard (post-2026-05-26).
            // Refuses configs that would bind a co-tenant's port.
            if kid.0 == "sing-box" {
                match state.inv.get_reserved_ports(&server.id).await {
                    Ok(reserved) => {
                        if let Err(e) =
                            vpnctl_kernels::validate_config_excludes_ports(&config, &reserved)
                        {
                            ssh_errors
                                .push(format!("{}: reserved-ports guard refused: {e}", kid.0));
                            continue;
                        }
                    }
                    Err(e) => {
                        ssh_errors.push(format!("{}: reserved-ports lookup failed: {e}", kid.0));
                        continue;
                    }
                }
            }
            total_config_bytes += config.len();
            if let Err(e) = kernel.apply_config(&ssh, &config).await {
                ssh_errors.push(format!("{}: apply_config failed: {e}", kid.0));
                continue;
            }
            ssh_kernels_pushed.push(kid.0.clone());
            // Best-effort firewall open (Kernel::open_firewall) — a fresh
            // deploy must be reachable without a manual `ufw allow`; non-fatal
            // (the config is already applied).
            if let Err(e) = kernel.open_firewall(&ssh, &protocols).await {
                tracing::warn!(target = "vpnctld::deploy", kernel = %kid.0, error = %e, "open_firewall skipped (best-effort)");
            }
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
    if !valid_server_id(&id) {
        // Dedicated server-id validator (review 2026-06-04): the user-id
        // validator (2..=32 lowercase) used to gate this while the error
        // text promised 1-64 mixed-case — now the message matches the
        // enforced policy exactly.
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
            // dot+underscore per naming convention (was the hyphenated
            // `server.quick-add`). Convention-only: the action_kind
            // chip maps the last dot-segment and `quick_add` still
            // lands on «other» — the win is consistent `server.`-prefix
            // filtering and one fewer odd-man-out name.
            "server.quick_add",
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
            "audit write failed for server.quick_add"
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

    // NM-10 contract (audit 2026-06-10): a no-op re-POST (inserted == 0)
    // writes NO audit row — unconditional writes polluted the timeline
    // and the `newly_added` flag inside is honest-but-buried.
    if inserted == 1
        && let Err(e) = state
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
        "/admin/servers/{}/protocols",
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

    // NM-10 contract (audit 2026-06-10): a no-op re-POST (removed == 0)
    // writes NO audit row — unconditional writes polluted the timeline
    // and the `was_present` flag inside is honest-but-buried.
    if removed == 1
        && let Err(e) = state
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
        "/admin/servers/{}/protocols",
        path_segment_encode(&server_id_str)
    ))
    .into_response()
}

/// Validate a candidate USER id from the web form. The HTML5 `pattern`
/// attribute already filters most input client-side, but we re-validate
/// server-side because (a) browsers can be bypassed and (b) the CLI
/// has no client-side filter, so the rule should live in one place.
///
/// Permitted: lowercase ASCII letters, digits, `.`, `_`, `-`.
/// Length **2..=32** (the `^[a-z0-9._-]{2,32}$` convention from the
/// NM-7 username normalisation). Rejected: uppercase, spaces, slashes,
/// `?`, `#`, percent-escapes, anything non-ASCII. (Doc fixed
/// 2026-06-04 — it used to claim 1..=64 mixed-case, which the code
/// never accepted. Server ids have their own, WIDER validator:
/// [`valid_server_id`].)
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

/// Validate a candidate SERVER id (quick-add form). Deliberately WIDER
/// than [`valid_user_id`] (review 2026-06-04 — quick-add used the user
/// validator while its error text promised `1-64 chars of A-Z a-z 0-9
/// . _ -`, so e.g. a 1-char or mixed-case id was rejected with a
/// message claiming it's allowed):
///
///   * length **1..=64** — wizard-derived ids from IPv6 addresses
///     (`2001-db8--1`) and dotted IPv4s easily exceed the user cap;
///     prod also has 2-char ISO ids (`de`, `fi`).
///   * mixed case allowed — `derive_server_id` preserves the case of a
///     hostname-derived id, and the inventory has no case constraint.
///   * same charset family as `path_segment_encode`'s unreserved set,
///     so the id is always URL-safe in `/admin/servers/{id}` routes.
fn valid_server_id(id: &str) -> bool {
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
    // 2026-05-23 quickfix (Pavel: «добавил multiviruss и у него
    // только локальный конфиг»). Pre-fix, web user_create left
    // `vpn_router_device_id = NULL` and only the 33 Phase-3-imported
    // users got the production ninitux URL. Now we auto-mint a
    // 32-hex device_id on every web-create so the user-detail page
    // shows the production URL straight away — the legacy
    // `/sub/<token>` URL is demoted to «LAN fallback» as designed.
    // Mint failure (RNG) is fatal for the whole create — better to
    // refuse than to land in the «forgot the device_id again» state.
    let device_id = match vpnctl_crypto::gen_vpn_router_device_id() {
        Ok(d) => d,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    let user = vpnctl_core::User {
        id: vpnctl_core::UserId(id_decoded.clone()),
        uuid: vpnctl_crypto::gen_uuid(),
        tuic_password: Some(tuic_password),
        wireguard_pubkey: Some(wg_pub),
        wireguard_private: Some(wg_priv),
        sub_token: None,
        vpn_router_device_id: Some(device_id),
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

    // Membership BEFORE the grant — audit only a NEW grant (an
    // idempotent re-grant must not falsely re-mark the server
    // pending-deploy; see `server_grant_user`).
    let was_granted = match state.inv.servers_for_user(&uid).await {
        Ok(v) => v.iter().any(|s| s.id == sid),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    if let Err(e) = state.inv.grant(&uid, &sid).await {
        return internal_error(anyhow::Error::new(e));
    }
    // Canonical grant-audit shape (2026-06-04 unification): per-user
    // `user.grant` with target = USER id — what the pending-deploy
    // detector keys on. Previously this wrote `action="grant",
    // target=<server>`, which the detector never saw.
    if !was_granted
        && let Err(e) = state
            .inv
            .audit(
                "admin",
                "user.grant",
                Some(&user_id_str),
                Some(&serde_json::json!({
                    "server": server_id_str,
                    "source": "user-detail",
                })),
            )
            .await
    {
        tracing::warn!(
            target = "vpnctld::admin",
            user = %user_id_str,
            server = %server_id_str,
            error = %e,
            "audit write failed for user.grant — mutation already committed"
        );
    }
    Redirect::to(&format!(
        "/admin/users/{}/access",
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

    // Membership BEFORE the revoke — audit only an ACTUAL revoke
    // (mirror of the grant paths; see `server_revoke_user`).
    let was_granted = match state.inv.servers_for_user(&uid).await {
        Ok(v) => v.iter().any(|s| s.id == sid),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    if let Err(e) = state.inv.revoke(&uid, &sid).await {
        return internal_error(anyhow::Error::new(e));
    }
    // Canonical per-user `user.revoke` (target = USER id) — visible to
    // the pending-deploy detector, unlike the old server-targeted row.
    if was_granted
        && let Err(e) = state
            .inv
            .audit(
                "admin",
                "user.revoke",
                Some(&user_id_str),
                Some(&serde_json::json!({
                    "server": server_id_str,
                    "source": "user-detail",
                })),
            )
            .await
    {
        tracing::warn!(
            target = "vpnctld::admin",
            user = %user_id_str,
            server = %server_id_str,
            error = %e,
            "audit write failed for user.revoke — mutation already committed"
        );
    }
    Redirect::to(&format!(
        "/admin/users/{}/access",
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
/// Audit shape (2026-06-04 unification): ONE summary row
/// (`server.grants.bulk_grant` with `{granted, already_granted,
/// failed, total_users}`) **plus a per-user `user.grant` row
/// (target = user id) for each NEWLY-granted user**. The per-user
/// rows are what the pending-deploy detector
/// (`servers_pending_deploy_for_user`) keys on — without them a
/// bulk grant after the server's first deploy never raised the
/// «config not yet deployed» banner. Timeline flood stays bounded:
/// re-running on a fully-granted server grants 0 → writes 0
/// per-user rows (idempotent), so only the first click of the «50
/// users» case pays the N rows — and those N are exactly the N
/// real mutations. Per-user grant failures (rare — inventory-layer
/// DB error) are counted in `failed` and logged at warn but DO NOT
/// abort the batch — partial success is operator-recoverable via
/// the per-row UI.
///
/// No confirm gate (safe + reversible — operator can revoke
/// per-user OR use the bulk revoke flow).
pub(crate) async fn server_grant_all_users(
    State(state): State<AppState>,
    Path(server_id_str): Path<String>,
) -> Response {
    let sid = vpnctl_core::ServerId(server_id_str.clone());
    // 3-arm match (audit 2026-06-10): the old `if let Ok(None)` SWALLOWED
    // the DB-error arm and fell through as if the server existed.
    match state.inv.get_server(&sid).await {
        Ok(Some(_)) => {}
        Ok(None) => return not_found(&format!("no such server '{server_id_str}'")),
        Err(e) => return internal_error(anyhow::Error::new(e)),
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
            Ok(()) => {
                granted += 1;
                // Per-user `user.grant` row for each ACTUAL new grant —
                // the canonical shape the pending-deploy detector keys
                // on (see the handler doc-comment). Audit failure is
                // non-fatal: the grant is already committed.
                if let Err(e) = state
                    .inv
                    .audit(
                        "admin",
                        "user.grant",
                        Some(&u.id.0),
                        Some(&serde_json::json!({
                            "server": server_id_str,
                            "source": "server-detail.bulk",
                        })),
                    )
                    .await
                {
                    tracing::warn!(
                        target = "vpnctld::admin",
                        server = %server_id_str,
                        user = %u.id,
                        error = %e,
                        "audit write failed for user.grant (bulk) — mutation already committed"
                    );
                }
            }
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
        "/admin/servers/{}/grants",
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
    // 3-arm match (audit 2026-06-10): the old `if let Ok(None)` SWALLOWED
    // the DB-error arm and fell through as if the server existed.
    match state.inv.get_server(&sid).await {
        Ok(Some(_)) => {}
        Ok(None) => return not_found(&format!("no such server '{server_id_str}'")),
        Err(e) => return internal_error(anyhow::Error::new(e)),
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
            Ok(()) => {
                revoked += 1;
                // Per-user `user.revoke` row for each ACTUAL revoke
                // (the `granted` list is exactly the granted set, so
                // every Ok here is a real mutation). Mirrors the bulk
                // grant path; keeps the pending-deploy detector fed.
                // Audit failure non-fatal: revoke already committed.
                if let Err(e) = state
                    .inv
                    .audit(
                        "admin",
                        "user.revoke",
                        Some(&u.id.0),
                        Some(&serde_json::json!({
                            "server": server_id_str,
                            "source": "server-detail.bulk",
                        })),
                    )
                    .await
                {
                    tracing::warn!(
                        target = "vpnctld::admin",
                        server = %server_id_str,
                        user = %u.id,
                        error = %e,
                        "audit write failed for user.revoke (bulk) — mutation already committed"
                    );
                }
            }
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
        "/admin/servers/{}/grants",
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
    // Capture the user's servers BEFORE remove_user cascades the grants,
    // so the auto-deploy below can revoke their node access.
    let servers = state.inv.servers_for_user(&uid).await.unwrap_or_else(|e| {
        tracing::warn!(
            target = "vpnctld::admin",
            user = %user_id_str,
            error = %e,
            "servers_for_user failed; delete not auto-applied — use Deploy all"
        );
        Vec::new()
    });
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
    // (B) Propagate the delete to the nodes — re-render configs (now without
    // this user) + reload sing-box — so a deleted user can't keep using a
    // cached config. Backgrounded; the redirect returns now.
    spawn_user_servers_redeploy(&state, servers, user_id_str.clone(), "user.remove");
    Redirect::to("/admin/users").into_response()
}

/// `GET /admin/servers/{id}/delete-confirm` — retype-to-confirm page
/// for removing a server from the inventory (mirrors user delete). Shows
/// the cascade scope (grants / secrets / protocols) before the operator
/// commits.
pub(crate) async fn server_delete_confirm(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(server_id_str): Path<String>,
) -> Result<Markup, Response> {
    let (theme, accent, lang) = theme_accent_lang(&headers);
    let sid = vpnctl_core::ServerId(server_id_str.clone());
    let server = match state.inv.get_server(&sid).await {
        Ok(Some(s)) => s,
        Ok(None) => return Err(not_found(&format!("no such server '{server_id_str}'"))),
        Err(e) => return Err(internal_error(anyhow::Error::new(e))),
    };
    // `Option` so a DB error renders as «unknown», not a reassuring
    // fake «0 grant(s)» (audit 2026-06-10).
    let grant_count = match state.inv.users_for_server(&sid).await {
        Ok(v) => Some(v.len()),
        Err(e) => {
            tracing::warn!(
                target = "vpnctld::admin",
                server = %server_id_str,
                error = %e,
                "users_for_server failed on delete-confirm; rendering count as unknown"
            );
            None
        }
    };
    // Telegram alert relay: deleting the proxy server is allowed (the
    // FK is a deliberate non-cascade dangle, migration 0015) but every
    // subsequent alert send will fail at SSH-spawn time — warn the
    // operator BEFORE the delete, not in the logs after.
    let is_telegram_proxy = match state.inv.get_telegram_config().await {
        Ok(cfg) => cfg
            .and_then(|c| c.proxy_via_server_id)
            .is_some_and(|p| p == server_id_str),
        Err(e) => {
            // Don't silently drop the relay warning on a DB error —
            // log it; the page still renders (warning-less, like the
            // pre-fix behavior, but now visibly in the daemon log).
            tracing::warn!(
                target = "vpnctld::admin",
                server = %server_id_str,
                error = %e,
                "get_telegram_config failed on delete-confirm; relay warning suppressed"
            );
            false
        }
    };
    let back = format!("/admin/servers/{}", path_segment_encode(&server_id_str));
    let body = html! {
        div.ed-art-eyebrow {
            a href=(back) style="color: var(--mute); text-decoration: none;" { "← back to server" }
            "  ·  delete"
        }
        h1.ed-art-h1 { "delete " em { (server_id_str) } " — really?" }
        p.ed-art-deck {
            "Drops the server (" span.ed-mono { (server.address) } ") from the inventory. "
            b {
                @match grant_count {
                    Some(n) => { (n) " grant(s)" },
                    None => { "an unknown number of grants (inventory read failed — reload to retry)" },
                }
            }
            " cascade-delete — those users lose this server from their subscription on the next pull. "
            b { "Secrets" }
            " (REALITY keypair, short_id, obfs passwords) are deleted — re-adding the server later generates BRAND-NEW ones. "
            "Protocols, kernels, probe history + alerts also cascade. If another server uses this one as a ProxyJump host, that link is cleared. "
            b { "The sing-box on the node itself is NOT touched" }
            " — stop/wipe it on the host separately if the VPS lives on."
        }
        @if is_telegram_proxy {
            p style="font-family: var(--mono); font-size: 11px; color: var(--acc); border: 1px solid var(--acc); padding: 8px 12px; margin: 10px 0;" {
                b { "This server is the Telegram alert relay" }
                " (settings → notifications → proxy-via). Deleting it silently breaks every alert send until you pick another relay or clear the setting."
            }
        }
        p style="font-family: var(--serif); font-style: italic; color: var(--mute); padding: 8px 0;" {
            "Type the server-id "
            span.ed-mono { (server_id_str) }
            " in the box below to confirm. Exact match — copy/paste counts."
        }
        form method="post"
             action=(format!("/admin/servers/{}/delete", path_segment_encode(&server_id_str)))
             style="display: flex; gap: 10px; align-items: baseline; padding: 14px 16px; border: 1px solid var(--rule); margin: 16px 0;" {
            label style="font-family: var(--mono); font-size: 11px; color: var(--mute); letter-spacing: 0.14em; text-transform: uppercase;" {
                "confirm id"
            }
            input type="text" name="confirm" required="required"
                  autocomplete="off"
                  style="flex: 1; max-width: 280px; padding: 4px 8px; border: 1px solid var(--rule-s); background: var(--paper); font-family: var(--mono); font-size: 12px; color: var(--ink);";
            button type="submit"
                   title=(format!("Delete server {server_id_str} from the inventory permanently"))
                   style="padding: 4px 12px; border: 1px solid var(--acc-bad, #97233f); background: var(--acc-bad, #97233f); color: var(--paper); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                "delete forever"
            }
            a href=(back)
              style="padding: 4px 10px; border: 1px solid var(--rule-s); color: var(--mute); font-family: var(--mono); font-size: 11px; text-decoration: none;" {
                "cancel"
            }
        }
    };
    Ok(shell("servers", &theme, &accent, lang, body))
}

/// `POST /admin/servers/{id}/delete` — actually delete. Body must be
/// `confirm=<exact-server-id>`; mismatch → 400. Captures the cascade
/// scope (grant count) for the audit payload BEFORE the FK cascade wipes
/// it, then removes the server and audits `server.remove`.
pub(crate) async fn server_delete(
    State(state): State<AppState>,
    Path(server_id_str): Path<String>,
    body: String,
) -> Response {
    let confirm = form_field(&body, "confirm").unwrap_or_default();
    if confirm != server_id_str {
        return bad_request(&format!(
            "delete confirm mismatch: form sent '{confirm}', URL targets '{server_id_str}' — type the server id exactly to confirm"
        ));
    }
    let sid = vpnctl_core::ServerId(server_id_str.clone());
    let server = match state.inv.get_server(&sid).await {
        Ok(Some(s)) => s,
        Ok(None) => return not_found(&format!("no such server '{server_id_str}'")),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    // Deploy-concurrency gate (audit 2026-06-10): deleting a server
    // while its deploy pipeline is in flight let the pipeline keep
    // SSH-pushing to the node, fail FK-wise on secret upserts mid-
    // stream, and then write a server.deploy audit row for a server
    // that no longer exists. Hold the same per-server permit a deploy
    // takes; 409 if one is running. The guard drops at handler return
    // (RAII), covering every early-return below.
    let _deploy_guard = match crate::wizard_bootstrap::DeployGuard::try_acquire(&server_id_str) {
        Some(g) => g,
        None => {
            return error_resp(
                StatusCode::CONFLICT,
                &format!(
                    "deploy in flight for server '{server_id_str}' — wait for it to finish, then delete"
                ),
            );
        }
    };
    // Capture cascade scope BEFORE the delete (FK CASCADE wipes grants).
    let grants_removed = state
        .inv
        .users_for_server(&sid)
        .await
        .map(|v| v.len())
        .unwrap_or(0);
    if let Err(e) = state.inv.remove_server(&sid).await {
        return internal_error(anyhow::Error::new(e));
    }
    if let Err(e) = state
        .inv
        .audit(
            "admin",
            "server.remove",
            Some(&server_id_str),
            Some(&serde_json::json!({
                "address": server.address,
                "grants_removed": grants_removed,
            })),
        )
        .await
    {
        tracing::warn!(
            target = "vpnctld::admin",
            server = %server_id_str,
            error = %e,
            "audit row for server.remove failed; mutation already committed"
        );
    }
    Redirect::to("/admin/servers").into_response()
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

/// Background, best-effort redeploy of `servers` after a user-inventory
/// mutation (disable / enable / delete) so the change lands on the nodes
/// WITHOUT a manual «Deploy all». Mirrors that button, scoped to one
/// user's servers. `servers` must be captured by the caller at the right
/// moment — for a DELETE, BEFORE the cascade drops the grants. Empty →
/// no-op. NOTE: apply_config restarts sing-box, so other users on a node
/// see a brief blip — inherent to any config change.
fn spawn_user_servers_redeploy(
    state: &AppState,
    servers: Vec<vpnctl_core::Server>,
    user_id: String,
    trigger: &'static str,
) {
    if servers.is_empty() {
        return;
    }
    let inv = state.inv.clone();
    let registry = std::sync::Arc::clone(&state.registry);
    let key_path = std::path::PathBuf::from(crate::app::DEFAULT_DEPLOY_KEY_PATH);
    tokio::spawn(async move {
        use tokio_stream::StreamExt;
        let mut stream = Box::pin(crate::wizard_bootstrap::run_deploy_all(
            servers,
            inv.clone(),
            registry,
            key_path,
        ));
        let mut errors: Vec<String> = Vec::new();
        while let Some(ev) = stream.next().await {
            if let crate::wizard_bootstrap::BootstrapEvent::Error { phase, message } = ev {
                errors.push(format!("{phase}: {message}"));
            }
        }
        if errors.is_empty() {
            tracing::info!(
                target = "vpnctld::admin",
                user = %user_id,
                trigger,
                "auto-deploy applied to user's servers (config re-rendered + sing-box reloaded)"
            );
        } else {
            tracing::warn!(
                target = "vpnctld::admin",
                user = %user_id,
                trigger,
                errors = ?errors,
                "auto-deploy: some servers failed to apply — retry via Deploy all"
            );
        }
        let _ = inv
            .audit(
                "admin",
                "user.autodeploy",
                Some(&user_id),
                Some(&serde_json::json!({
                    "trigger": trigger,
                    "ok": errors.is_empty(),
                    "errors": errors,
                })),
            )
            .await;
    });
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

        // (B) Apply to the nodes without a manual «Deploy all»:
        // `users_for_server` now excludes disabled users, so this REVOKES
        // (disable) or RESTORES (enable) node access. Backgrounded.
        let servers = state.inv.servers_for_user(&uid).await.unwrap_or_else(|e| {
            tracing::warn!(
                target = "vpnctld::admin",
                user = %user_id_str,
                error = %e,
                "servers_for_user failed; disable/enable not auto-applied — use Deploy all"
            );
            Vec::new()
        });
        spawn_user_servers_redeploy(&state, servers, user_id_str.clone(), action);
    }
    Redirect::to(&format!(
        "/admin/users/{}/overview",
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
                    // Honest copy (2026-06-10): the action filter is
                    // PREFIX-only — the old «accepts substrings» promise
                    // made this deep link near-useless for typical
                    // search terms.
                    (crate::i18n::tr(lang, " page (action filter is prefix-match).", " (фильтр action ищет по префиксу)."))
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
                                // Masked (audit 2026-06-10): the full
                                // uuid IS the VLESS credential; the
                                // users list shows a masked preview for
                                // exactly that reason — search must not
                                // be the page that leaks it whole.
                                "uuid=" (mask_secret(&u.uuid))
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
                        @let rendered = localized_alert(a, lang);
                        li style="display: flex; gap: 10px; padding: 2px 0; border-bottom: 1px dotted var(--rule);" {
                            // Alert detail isn't a route yet; link to
                            // /admin/alerts where the operator can ack
                            // / dig in. Show ack-state inline so the
                            // search results immediately surface
                            // open-vs-historical context.
                            a href="/admin/alerts"
                              style="color: var(--ink); text-decoration: none; border-bottom: 1px dotted var(--ink);" {
                                b title=(a.kind) { (rendered.icon) " " (crate::alert_text::to_plain(&rendered.title)) }
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
                                " · " (crate::alert_text::to_plain(&rendered.body))
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
                  // Hint refreshed post-grant-rename (2026-06-10):
                  // grants now write `user.grant` / `user.revoke` /
                  // `server.grants.bulk_*` — the old bare `grant.` hint
                  // matched only the protocol-override actions.
                  placeholder="server. / user.grant / user. / settings."
                  title=(crate::i18n::tr(
                      lang,
                      "PREFIX match on the action column (not substring — `sub_token` won't match `user.sub_token.regen`; `user.` will). Convention: dot-separated domain.subdomain.verb (e.g. `server.protocol.set_hidden`, `user.grant`, `user.sub_token.regen`). Underscores allowed INSIDE a verb.",
                      "Поиск по ПРЕФИКСУ в колонке action (не подстрока — `sub_token` не найдёт `user.sub_token.regen`; `user.` найдёт). Конвенция: точка-разделитель domain.subdomain.verb (напр. `server.protocol.set_hidden`, `user.grant`, `user.sub_token.regen`). Подчёркивания допустимы ВНУТРИ verb.",
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
    // 2026-05-23 — group day-by-day in the operator-configured
    // display TZ. Otherwise an event at 23:30 UTC (= 02:30 MSK
    // next day) falls into the wrong day-header relative to the
    // ts shown beside it (which is rendered via format_msk_iso =
    // local TZ).
    let tz = display_tz();
    let today = Utc::now().with_timezone(&tz).date_naive();
    let yesterday = today - Duration::days(1);
    let mut current_label: Option<String> = None;
    html! {
        div.ed-time {
            @for e in entries {
                @let day = e.ts.with_timezone(&tz).date_naive();
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
                    span.ed-time-row__t { (format_msk_iso(e.ts)) }
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
    // Formula-injection guard (audit 2026-06-10, OWASP CSV-injection):
    // Excel/LibreOffice execute a cell starting with = + - @ as a
    // formula — an attacker-influenced field (user id, alert summary)
    // beginning with `=HYPERLINK(...)` would run on the operator's
    // machine when the export is opened. Standard mitigation: prefix a
    // single quote, which spreadsheets treat as a text marker. Server
    // ids may legitimately start with `-` — they render with a visible
    // leading `'` in a spreadsheet, an accepted cosmetic cost.
    let injectable = matches!(s.chars().next(), Some('=' | '+' | '-' | '@'));
    let s = if injectable {
        format!("'{s}")
    } else {
        s.to_string()
    };
    let needs_quote = s.contains(['"', ',', '\n', '\r']);
    if !needs_quote {
        return s;
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
                // CSP-safe confirm: the message rides in a `data-confirm`
                // attribute (maud HTML-escapes it) and admin.js attaches
                // the confirm() guard. An inline `onsubmit="…"` would be
                // blocked by `script-src 'self'` → the guard would never
                // run and ack-all would fire on a single click.
                @let confirm_msg = crate::i18n::tr(
                    lang,
                    "Ack all unacked alerts? They will stay visible under «show all» for 30 days; nothing is deleted, just marked seen.",
                    "Принять все непринятые алерты? Они останутся видимы в «показать всё» 30 дней; ничего не удаляется, только помечается просмотренным.",
                );
                form method="post"
                     action="/admin/alerts/ack-all"
                     style="display: inline; margin-left: auto;"
                     data-confirm=(confirm_msg) {
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
/// Human-readable (title, what-to-do hint) for an alert kind. The raw
/// kind stays available in the row tooltip; the title is what the
/// operator scans. Returns `None` hint for recovery/info kinds — they
/// need no action. (Alerts-cleanup 2026-06-10: Pavel's feedback —
/// «алерты сумбурные и непонятные» — raw kinds + mixed summaries gave
/// no answer to "так что мне ДЕЛАТЬ?".)
fn alert_explainer(kind: &str, lang: crate::i18n::Locale) -> (&'static str, Option<&'static str>) {
    use crate::i18n::tr;
    // Per-user suspicious kinds carry a `:<user>` suffix — match on prefix.
    if kind.starts_with("sub_access.suspicious_local_ip") {
        return (
            tr(
                lang,
                "subscription fetched from a LAN/loopback IP",
                "подписку дёрнули с LAN/loopback IP",
            ),
            Some(tr(
                lang,
                "If this is your own service host (monitoring, claude-chat, smoke checks) — add its IP to VPNCTLD_SUSPICIOUS_IP_ALLOWLIST and ack. If you don't recognise the IP/UA, the sub link may have leaked into the LAN: regenerate the user's sub_token.",
                "Если это твой служебный хост (мониторинг, claude-chat, smoke-проверки) — добавь его IP в VPNCTLD_SUSPICIOUS_IP_ALLOWLIST и прими. Если IP/UA незнакомы — sub-ссылка могла утечь в LAN: перегенерируй sub_token юзера.",
            )),
        );
    }
    match kind {
        "server.singbox.down" => (
            tr(
                lang,
                "sing-box is DOWN — VPN dead on this node",
                "sing-box УПАЛ — VPN на ноде не работает",
            ),
            Some(tr(
                lang,
                "Every user on this server is offline. Open the server page → check live status → redeploy; if SSH is dead too, use the hoster console.",
                "Все юзеры этого сервера оффлайн. Открой страницу сервера → проверь живой статус → redeploy; если SSH тоже мёртв — консоль хостера.",
            )),
        ),
        "server.singbox.up" => (
            tr(lang, "sing-box recovered", "sing-box восстановился"),
            None,
        ),
        "server.fail2ban.down" => (
            tr(
                lang,
                "fail2ban stopped — SSH brute-force shield off",
                "fail2ban остановлен — защита SSH от перебора выключена",
            ),
            Some(tr(
                lang,
                "SSH is unprotected against password guessing. Redeploy from the server page (re-installs fail2ban).",
                "SSH не защищён от перебора паролей. Передеплой со страницы сервера (переставит fail2ban).",
            )),
        ),
        "server.fail2ban.up" => (
            tr(lang, "fail2ban recovered", "fail2ban восстановился"),
            None,
        ),
        "server.disk.pressure" => (
            tr(lang, "disk almost full", "диск почти заполнен"),
            Some(tr(
                lang,
                "Above 90% — sing-box logs are the usual culprit. Server page shows the trend; a redeploy rotates the log.",
                "Выше 90% — обычно виноваты логи sing-box. Тренд на странице сервера; redeploy ротирует лог.",
            )),
        ),
        "server.disk.recovered" => (tr(lang, "disk pressure cleared", "диск разгрузился"), None),
        "server.mem.pressure" => (
            tr(lang, "memory almost exhausted", "память почти исчерпана"),
            Some(tr(
                lang,
                "Above 95% — check what's eating RAM on the node (sing-box leak? neighbour process?). OOM-kill of sing-box = outage.",
                "Выше 95% — посмотри, что ест RAM на ноде (течёт sing-box? соседний процесс?). OOM-kill sing-box = простой.",
            )),
        ),
        "server.mem.recovered" => (
            tr(lang, "memory pressure cleared", "память разгрузилась"),
            None,
        ),
        "server.singbox.log.too_big" => (
            tr(
                lang,
                "sing-box log over 500 MiB",
                "лог sing-box больше 500 MiB",
            ),
            Some(tr(
                lang,
                "Log rotation isn't keeping up. Redeploy from the server page (re-installs the logrotate fragment).",
                "Ротация логов не справляется. Передеплой со страницы сервера (переставит logrotate-фрагмент).",
            )),
        ),
        "server.unreachable" => (
            tr(lang, "node unreachable over SSH", "нода недоступна по SSH"),
            Some(tr(
                lang,
                "3+ probes failed in a row: host down, IP blocked, or sshd broken. Try the hoster console; if the node is gone for good — delete it from inventory.",
                "3+ probe подряд не прошли: хост лежит, IP заблокирован или sshd сломан. Зайди через консоль хостера; если нода умерла насовсем — удали её из инвентаря.",
            )),
        ),
        "server.fingerprint.drift" => (
            tr(
                lang,
                "SSH host key CHANGED on the node",
                "SSH host-ключ ноды ИЗМЕНИЛСЯ",
            ),
            Some(tr(
                lang,
                "Legit if you rebuilt the VPS; MITM if you didn't. Verify via the hoster console, then re-pin the fingerprint on the server page.",
                "Норма, если ты пересобирал VPS; MITM — если нет. Проверь через консоль хостера, затем перепинь отпечаток на странице сервера.",
            )),
        ),
        "server.fail2ban.banned_self" => (
            tr(
                lang,
                "fail2ban banned OUR OWN IP",
                "fail2ban забанил НАШ СОБСТВЕННЫЙ IP",
            ),
            Some(tr(
                lang,
                "The daemon can't SSH the node until unbanned. Via hoster console: fail2ban-client unban --all.",
                "Демон не попадёт на ноду по SSH, пока бан не снят. Через консоль хостера: fail2ban-client unban --all.",
            )),
        ),
        _ => (tr(lang, "", ""), None),
    }
}

/// Sort key: open-first, then critical → warning → info, then newest.
fn alert_sort_rank(a: &vpnctl_inventory::AdminAlert) -> (u8, u8, i64) {
    let open = u8::from(a.acked_at.is_some()); // open=0 first
    // Severity ranks only the OPEN section (triage order); acked rows
    // are history and stay purely chronological — an old acked
    // critical jumping above newer acked rows would misread as recent.
    let sev = if a.acked_at.is_some() {
        0
    } else {
        match a.severity.as_str() {
            "critical" => 0,
            "warning" => 1,
            _ => 2,
        }
    };
    (open, sev, -a.id)
}

fn alerts_table(rows: &[vpnctl_inventory::AdminAlert], lang: crate::i18n::Locale) -> Markup {
    use crate::i18n::tr;
    // Open-first, severity-ranked view (alerts-cleanup 2026-06-10) —
    // the raw feed was strictly chronological, so one chatty info row
    // could sit above an unacked critical.
    let mut sorted: Vec<&vpnctl_inventory::AdminAlert> = rows.iter().collect();
    sorted.sort_by_key(|a| alert_sort_rank(a));
    // The suspicious-local-ip family is the known spam cluster — when
    // 3+ are OPEN, collapse them into one <details> group (pure HTML,
    // no JS) so they stop burying the rest of the feed. Below the
    // threshold the single sorted list renders untouched (review
    // 2026-06-10: an unconditional partition floated 1-2 warning-level
    // spam rows above an open CRITICAL, contradicting the sort).
    let susp_open_count = sorted
        .iter()
        .filter(|a| a.acked_at.is_none() && a.kind.starts_with("sub_access.suspicious_local_ip"))
        .count();
    let collapse_susp = susp_open_count >= 3;
    let (susp_open, rest): (Vec<_>, Vec<_>) = if collapse_susp {
        sorted.into_iter().partition(|a| {
            a.acked_at.is_none() && a.kind.starts_with("sub_access.suspicious_local_ip")
        })
    } else {
        (Vec::new(), sorted)
    };
    let (susp_title, susp_hint) = alert_explainer("sub_access.suspicious_local_ip", lang);
    html! {
        @if collapse_susp {
            details style="border: 1px solid var(--rule); margin: 0 0 14px; padding: 8px 12px;" {
                summary style="cursor: pointer; font-family: var(--mono); font-size: 12px;" {
                    b { (susp_open.len()) " × " (susp_title) }
                    span style="color: var(--mute);" { " — " (tr(lang, "expand for per-user rows", "раскрой для строк по юзерам")) }
                }
                p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 8px 0;" {
                    (susp_hint.unwrap_or(""))
                }
                div.ed-time {
                    @for a in &susp_open { (alert_row(a, lang, false)) }
                }
            }
        }
        div.ed-time {
            @for a in &rest { (alert_row(a, lang, true)) }
        }
    }
}

/// Render an `AdminAlert` into its localized `{icon,title,body,action}`
/// for the admin UI — the SAME `alert_text::render_alert` the Telegram
/// push uses, so the dashboard + /admin/alerts speak the operator's
/// language instead of the stored English summary. Subject = the user id
/// (for `user.*:id` kinds) or the server's country label; payload comes
/// from the stored `payload_json`.
fn localized_alert(
    a: &vpnctl_inventory::AdminAlert,
    lang: crate::i18n::Locale,
) -> crate::alert_text::RenderedAlert {
    // server_id wins over a `:`-suffix: server alerts can ALSO carry a
    // suffix (e.g. `server.fingerprint.drift:de`), where the suffix is
    // the raw id — we want the country label. The suffix is only the
    // subject for user-scoped alerts (server_id is None).
    let subject = if let Some(sid) = &a.server_id {
        crate::handlers::vpn_router::server_display_label(&sid.0, None)
    } else if let Some((_, suffix)) = a.kind.split_once(':') {
        suffix.to_string()
    } else {
        String::new()
    };
    let payload: serde_json::Value = a
        .payload_json
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or(serde_json::Value::Null);
    crate::alert_text::render_alert(&a.kind, &a.severity, &subject, &payload, lang)
}

fn alert_row(
    a: &vpnctl_inventory::AdminAlert,
    lang: crate::i18n::Locale,
    with_hint: bool,
) -> Markup {
    use crate::i18n::{K, t, tr};
    let (_explainer_title, explainer_hint) = alert_explainer(&a.kind, lang);
    // Localized render (icon + title + body + action) — replaces the
    // stored English summary on the operator-facing surface.
    let rendered = localized_alert(a, lang);
    let r_title = crate::alert_text::to_plain(&rendered.title);
    let r_body = crate::alert_text::to_plain(&rendered.body);
    let r_hint: Option<String> = rendered
        .action
        .as_deref()
        .map(crate::alert_text::to_plain)
        .or_else(|| explainer_hint.map(|h| h.to_string()));
    html! {
                div.ed-time-row {
                    span.ed-time-row__t { (format_msk_iso(a.created_at)) }
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
                        // Localized icon + title first (raw kind in the
                        // tooltip) — operators scan titles, machines grep
                        // kinds. Body is the localized description, not the
                        // stored English summary.
                        b title=(a.kind) { (rendered.icon) " " (r_title) }
                        " · "
                        (r_body)
                        @match &a.acked_at {
                            Some(when) => {
                                " · " span style="color: var(--mute);" {
                                    (tr(lang, "acked ", "принято "))
                                    (format_msk_iso(*when))
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
                        // What-to-do hint — rendered only while the
                        // alert is OPEN (an acked row is history; the
                        // operator already decided). Suppressed inside
                        // the collapsed spam group, which shows the
                        // hint once at group level instead.
                        @if with_hint && a.acked_at.is_none() {
                            @if let Some(h) = &r_hint {
                                span style="display: block; font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin-top: 2px;" {
                                    "→ " (h)
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
                        (format_msk_iso(*ts))
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
            // `?action=` is the real filter param (audit 2026-06-10:
            // `action_prefix` doesn't exist in AuditQuery — the old
            // link silently showed the unfiltered timeline). Trailing
            // dot per the prefix-filter convention: matches
            // backup.snapshot + backup.self_test.
            a href="/admin/audit?action=backup."
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
                // POST form, not an anchor (audit 2026-06-10): the
                // self-test route is POST-only — a GET link 405'd.
                form method="post" action="/admin/backup/self-test"
                     style="display: inline;" {
                    button type="submit"
                           style="border: none; background: none; padding: 0; color: var(--ink); font: inherit; text-decoration: underline; cursor: pointer;" {
                        (tr(lang, "run self-test", "run self-test"))
                    }
                }
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
                // GeoIP file mtime — render in MSK to match the
                // rest of the operator-facing UI.
                chrono::DateTime::<chrono::Utc>::from_timestamp(d.as_secs() as i64, 0)
                    .map(format_msk_iso)
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
        // ── «update now» button (Phase 3c, CSP-safe since 2026-06-10) ──
        // Operator clicks → live log pane streams from
        // /admin/settings/geoip/update-now. Wired through admin.js's
        // generic `[data-sse-url]` trigger — the original inline
        // `<script>` + `onclick` were silently REFUSED by the admin CSP
        // (`script-src 'self'`, no 'unsafe-inline'), so the button did
        // nothing in a real browser (audit 2026-06-10). The geoip
        // runner's step/ok/error event shapes parse fine in the generic
        // handler (no `phase` field → message renders bare; terminal
        // `ok` has no redirect → admin.js reloads this page, which
        // also refreshes the file-status lines above). Idempotent
        // server-side: a concurrent click hits the 1-permit semaphore
        // and streams an «already running» error event.
        div style="margin: 14px 0;" {
            button id="geoip-update-now-btn"
                   type="button"
                   data-sse-url="/admin/settings/geoip/update-now"
                   data-log="geoip-update-now-log"
                   data-busy-label=(tr(lang, "running…", "запущено…"))
                   data-retry-label=(tr(lang, "retry", "повторить"))
                   style="font-family: var(--mono); font-size: 12px; padding: 6px 14px; border: 1px solid var(--rule); background: var(--paper); color: var(--ink); cursor: pointer;"
                   title=(tr(
                       lang,
                       "Spawn the `vpnctl geoip-update` subprocess on the daemon host and stream its progress here. Same action the monthly systemd timer fires.",
                       "Запустить `vpnctl geoip-update` на хосте демона и показать прогресс здесь. То же действие, что и ежемесячный systemd timer.",
                   )) {
                (tr(lang, "update now", "обновить сейчас"))
            }
            pre id="geoip-update-now-log" hidden
                style="margin: 10px 0 0; padding: 8px 12px; background: var(--paper-tint); border: 1px solid var(--rule); font-family: var(--mono); font-size: 11px; max-height: 320px; overflow-y: auto; white-space: pre-wrap;" {}
        }
    }
}

/// `POST /admin/settings/timezone` — operator picks an IANA TZ
/// name from the Settings dropdown (2026-05-23). Validates the
/// name parses as `chrono_tz::Tz`, writes to inventory + updates
/// the global cache so subsequent renders see the new zone
/// without a daemon restart.
pub(crate) async fn settings_timezone_set(State(state): State<AppState>, body: String) -> Response {
    let tz_name = form_field(&body, "tz").unwrap_or_default();
    if tz_name.is_empty() {
        return bad_request("missing `tz` field");
    }
    let tz: chrono_tz::Tz = match tz_name.parse() {
        Ok(t) => t,
        Err(_) => {
            return bad_request(&format!(
                "'{tz_name}' is not a valid IANA timezone name (e.g. 'Europe/Moscow', 'UTC', 'America/New_York')"
            ));
        }
    };
    // Persist to DB FIRST — then update cache. If the write fails
    // we want the cache to still reflect the actually-stored value.
    if let Err(e) = state.inv.set_display_timezone(&tz_name).await {
        return internal_error(anyhow::Error::new(e));
    }
    set_display_tz_cache(tz);
    // Audit row for the timeline.
    if let Err(e) = state
        .inv
        .audit(
            "admin",
            "settings.timezone.set",
            Some("display"),
            Some(&serde_json::json!({ "timezone": tz_name })),
        )
        .await
    {
        tracing::warn!(
            target = "vpnctld::admin",
            error = %e,
            "audit row for settings.timezone.set failed; mutation already committed"
        );
    }
    Redirect::to("/admin/settings/appearance#timezone-section").into_response()
}

/// settings' in-page tabs (ui-audit §5 Phase 3). Same recipe as
/// `ServerTab`/`UserTab`: real sub-routes (`/admin/settings/{slug}`),
/// plain `<a href>` links, each tab renders only its own sections.
/// `Appearance` is the default (bare `/admin/settings`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum SettingsTab {
    Appearance,
    Backups,
    Notifications,
    System,
}

impl SettingsTab {
    fn slug(self) -> &'static str {
        match self {
            SettingsTab::Appearance => "appearance",
            SettingsTab::Backups => "backups",
            SettingsTab::Notifications => "notifications",
            SettingsTab::System => "system",
        }
    }
}

// Thin axum handlers — one per tab route in app.rs. Bare
// `/admin/settings` (+ trailing slash) + `/appearance` both land here.
pub(crate) async fn settings(headers: HeaderMap, State(state): State<AppState>) -> Markup {
    settings_render(headers, state, SettingsTab::Appearance).await
}

pub(crate) async fn settings_backups(headers: HeaderMap, State(state): State<AppState>) -> Markup {
    settings_render(headers, state, SettingsTab::Backups).await
}

pub(crate) async fn settings_notifications(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Markup {
    settings_render(headers, state, SettingsTab::Notifications).await
}

pub(crate) async fn settings_system(headers: HeaderMap, State(state): State<AppState>) -> Markup {
    settings_render(headers, state, SettingsTab::System).await
}

async fn settings_render(headers: HeaderMap, state: AppState, tab: SettingsTab) -> Markup {
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
    // Filtered SQL query (audit 2026-06-10): the old in-memory scan of
    // `recent_audit(50)` went blind within ~2 days — the hourly
    // `backup.snapshot` scheduler writes 24 rows/day, evicting the
    // self-test row from the last-50 window and rendering a false
    // «Never run».
    let last_self_test = state
        .inv
        .recent_audit_paginated(1, 0, None, Some("backup.self_test"))
        .await
        .ok()
        .and_then(|rows| rows.into_iter().next());

    // 2026-05-23 — display timezone (migration 0027). Render the
    // current setting in the dropdown's selected state. Failure to
    // read = use the default; doesn't break the rest of Settings.
    let display_tz_current = state
        .inv
        .get_display_timezone()
        .await
        .unwrap_or_else(|_| "Europe/Moscow".into());

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

    (detail_tabs("/admin/settings", tab.slug(), &[("appearance", crate::i18n::tr(lang, "Appearance", "Внешний вид")), ("backups", crate::i18n::tr(lang, "Backups", "Бэкапы")), ("notifications", crate::i18n::tr(lang, "Notifications", "Уведомления")), ("system", crate::i18n::tr(lang, "System", "Система"))]))
    @if tab == SettingsTab::Appearance {
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
            div id="timezone-section" {
                div.ed-art-eyebrow {
                    (crate::i18n::tr(lang, "Display timezone", "Часовой пояс отображения"))
                }
                p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 12px;" {
                    (crate::i18n::tr(
                        lang,
                        "Every operator-visible timestamp (alerts feed, audit timeline, sub-access log, chart axis labels, …) is rendered in this timezone with its UPPERCASE abbreviation suffix (e.g. ",
                        "Каждая видимая оператору метка времени (лента alerts, audit, sub-access лог, подписи осей графиков, …) рендерится в этом часовом поясе с прописной аббревиатурой (например ",
                    ))
                    span.ed-mono { "MSK" } ", " span.ed-mono { "UTC" } ", " span.ed-mono { "EST" }
                    (crate::i18n::tr(
                        lang,
                        "). Pick an IANA timezone name; full database (incl. DST rules) is bundled.",
                        "). Выбери IANA-имя часового пояса; полная база (включая DST) встроена.",
                    ))
                }
                form method="post"
                     action="/admin/settings/timezone"
                     style="display: flex; gap: 8px; align-items: baseline;" {
                    label style="font-family: var(--mono); font-size: 11px; color: var(--mute); text-transform: uppercase; letter-spacing: 0.10em;" {
                        (crate::i18n::tr(lang, "timezone", "часовой пояс"))
                    }
                    @let common_tzs: &[&str] = &[
                        "UTC",
                        "Europe/Moscow",
                        "Europe/London",
                        "Europe/Berlin",
                        "Europe/Helsinki",
                        "Europe/Istanbul",
                        "Asia/Dubai",
                        "Asia/Tbilisi",
                        "Asia/Bangkok",
                        "Asia/Shanghai",
                        "Asia/Tokyo",
                        "America/New_York",
                        "America/Los_Angeles",
                    ];
                    select name="tz"
                           style="padding: 4px 8px; border: 1px solid var(--rule-s); background: var(--paper); font-family: var(--mono); font-size: 12px; color: var(--ink); min-width: 220px;" {
                        @for tz in common_tzs {
                            @if *tz == display_tz_current.as_str() {
                                option value=(tz) selected="selected" { (tz) }
                            } @else {
                                option value=(tz) { (tz) }
                            }
                        }
                        // If current value isn't in the common list,
                        // surface it as a selected option at the end so
                        // the operator can keep it without retyping.
                        @if !common_tzs.contains(&display_tz_current.as_str()) {
                            option value=(display_tz_current) selected="selected" {
                                (display_tz_current) " (custom)"
                            }
                        }
                    }
                    button type="submit"
                           style="padding: 4px 12px; border: 1px solid var(--accent); background: var(--accent); color: var(--paper); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                        (crate::i18n::tr(lang, "save", "сохранить"))
                    }
                    span style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute);" {
                        (crate::i18n::tr(
                            lang,
                            "→ takes effect on the next page render (no restart needed)",
                            "→ применится при следующем рендере страницы (рестарт не нужен)",
                        ))
                    }
                }
            }

    }
    @if tab == SettingsTab::Backups {
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

    }
    @if tab == SettingsTab::Notifications {
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
                                "Posts a «🟢 Telegram connected» sample in the real alert format + your chosen language.",
                                "Пошлёт пример «🟢 Telegram подключён» в реальном формате алертов и на выбранном языке.",
                            ))
                        }
                    }
                    // On-demand fleet digest (the daily scheduler sends it
                    // automatically; this is the «send it now» button).
                    form method="post" action="/admin/settings/digest-now" style="margin-top: 8px;" {
                        button type="submit"
                               title=(crate::i18n::tr(
                                   lang,
                                   "Send the fleet digest now: all-clear, or the list of open problems. Also sent daily.",
                                   "Отправить дайджест по флоту сейчас: всё спокойно или список открытых проблем. Также шлётся раз в сутки.",
                               ))
                               style="padding: 5px 12px; border: 1px solid var(--rule); background: var(--paper); color: var(--ink); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                            (crate::i18n::tr(lang, "send digest now", "отправить дайджест"))
                        }
                        span style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin-left: 14px;" {
                            (crate::i18n::tr(
                                lang,
                                "A daily summary is sent automatically; this sends one immediately.",
                                "Ежедневная сводка отправляется автоматически; эта кнопка шлёт её сразу.",
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

            // Notification language — operator-selectable locale for the
            // Telegram alert pushes. Independent of the per-browser admin-UI
            // [EN|RU] shell toggle: this one is persisted in
            // notification_settings.language + drives render_alert at push
            // time, so alerts speak the chosen language regardless of which
            // browser the operator reads /admin from.
            @let notif_lang = match &telegram_cfg {
                Ok(Some(cfg)) => crate::i18n::Locale::from_lang_code(cfg.language.as_deref()),
                _ => crate::i18n::Locale::En,
            };
            div style="margin-top: 16px;" {
                div style="font-family: var(--mono); font-size: 11px; color: var(--mute); margin-bottom: 6px;" {
                    (crate::i18n::tr(lang, "Alert language", "Язык уведомлений"))
                }
                @for (code, label, is_active) in [
                    ("ru", "Русский", notif_lang == crate::i18n::Locale::Ru),
                    ("en", "English", notif_lang == crate::i18n::Locale::En),
                ] {
                    form method="post" action="/admin/settings/notification-language"
                         style="display: inline; margin: 0 8px 0 0;" {
                        input type="hidden" name="language" value=(code);
                        button type="submit" disabled[is_active]
                               style=(if is_active {
                                   "padding: 5px 12px; border: 1px solid var(--ink); background: var(--ink); color: var(--paper); font-family: var(--mono); font-size: 11px;"
                               } else {
                                   "padding: 5px 12px; border: 1px solid var(--rule); background: var(--paper); color: var(--ink); font-family: var(--mono); font-size: 11px; cursor: pointer;"
                               }) {
                            (label)
                        }
                    }
                }
                span style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin-left: 6px;" {
                    (crate::i18n::tr(
                        lang,
                        "Telegram alerts are sent in this language.",
                        "Алерты в Telegram приходят на этом языке.",
                    ))
                }
            }

    }
    @if tab == SettingsTab::System {
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
                    "/admin/servers/{}/setup#push-deploy-key",
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
                "/admin/servers/{}/setup#push-deploy-key",
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

/// `POST /admin/settings/digest-now` — send the fleet digest to Telegram
/// on demand (the daily scheduler sends it automatically; this is the
/// «send it now» button). Audited; 303 back to /admin/settings.
pub(crate) async fn settings_digest_now(State(state): State<AppState>) -> Response {
    crate::node_probe_poller::send_digest(&state.inv).await;
    if let Err(e) = state
        .inv
        .audit("admin", "settings.digest.send", None, None)
        .await
    {
        tracing::warn!(
            target = "vpnctld::admin::settings_digest_now",
            error = %e,
            "audit row for digest-now failed; digest was sent"
        );
    }
    Redirect::to("/admin/settings/notifications#telegram-notifications").into_response()
}

/// `POST /admin/settings/notification-language` — set the operator's
/// notification language (`ru` / `en`). Persisted in
/// `notification_settings.language`; drives `alert_text::render_alert`
/// at push time so Telegram alerts (and the localized test-send) speak
/// the chosen language. Audited; 303-redirects back to /admin/settings.
pub(crate) async fn settings_notification_language(
    State(state): State<AppState>,
    body: String,
) -> Response {
    let lang_in = form_field(&body, "language").unwrap_or_default();
    let lang = lang_in.trim();
    if lang != "ru" && lang != "en" {
        return bad_request("notification language must be 'ru' or 'en'");
    }
    if let Err(e) = state.inv.set_notification_language(Some(lang)).await {
        return internal_error(anyhow::Error::new(e));
    }
    if let Err(e) = state
        .inv
        .audit(
            "admin",
            "settings.notification.language",
            None,
            Some(&serde_json::json!({ "language": lang })),
        )
        .await
    {
        tracing::warn!(
            target = "vpnctld::admin::settings_notification_language",
            error = %e,
            "audit row for notification-language change failed; setting was applied"
        );
    }
    Redirect::to("/admin/settings/notifications").into_response()
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
    Redirect::to("/admin/settings/notifications#telegram-notifications").into_response()
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

    // Render the test message in the operator's chosen language, in the
    // SAME pretty HTML format real alerts use — so the test verifies not
    // just connectivity but that the operator likes the look + locale.
    let loc = match state.inv.get_telegram_config().await {
        Ok(Some(cfg)) => crate::i18n::Locale::from_lang_code(cfg.language.as_deref()),
        _ => crate::i18n::Locale::En,
    };
    let time_local = format_local_with_pattern(chrono::Utc::now(), "%d.%m %H:%M");
    let sample = crate::alert_text::RenderedAlert {
        icon: "🟢",
        title: crate::i18n::tr(loc, "Telegram connected — vpnctl", "Telegram подключён — vpnctl")
            .to_string(),
        body: crate::i18n::tr(
            loc,
            "This is a test message. Real alerts arrive in this format: a severity icon, what happened, and what to do.",
            "Это тестовое сообщение. Реальные алерты приходят в этом формате: иконка важности, что случилось и что делать.",
        )
        .to_string(),
        action: None,
    };
    let text = crate::alert_text::to_telegram_html(&sample, loc, &time_local, false);
    let send_result = sink.send_text("test", "info", &text, true).await;

    // Audit either way.
    let audit_payload = match &send_result {
        Ok(_) => serde_json::json!({"success": true}),
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
        Ok(_) => {
            Redirect::to("/admin/settings/notifications#telegram-notifications").into_response()
        }
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

/// `POST /admin/logout` — clear the persistent session cookie and
/// redirect the operator back to `/admin/`. The follow-up request
/// will then have no cookie + no basic-auth header → middleware
/// returns 401 → browser surfaces the prompt again. Use this when
/// switching identity or after rotating the password from another
/// device. CSRF-safe because the cookie is `SameSite=Lax` and the
/// route is POST-only.
pub(crate) async fn logout() -> Response {
    let mut resp = Redirect::to("/admin/").into_response();
    if let Ok(hv) = HeaderValue::from_str(&crate::handlers::auth::build_logout_cookie()) {
        resp.headers_mut().append(header::SET_COOKIE, hv);
    }
    resp
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
        div.ed-art-eyebrow { (tr(lang, "Add server · step 1 of 2", "Добавить сервер · шаг 1 из 2")) }
        h1.ed-art-h1 {
            (tr(lang, "Paste an ", "Вставь ")) em { "IP" }
            (tr(lang, " and the ", " и ")) em { (tr(lang, "root password", "root-пароль")) }
        }
        p.ed-art-deck {
            (tr(lang, "The daemon will SSH in as ", "Демон зайдёт по SSH как ")) span.ed-mono { "root" }
            // Honest copy (review 2026-06-04): the pipeline pushes the
            // key, installs fail2ban + sing-box and applies the config —
            // it does NOT create a non-root user or harden sshd_config
            // (that's a future `harden` phase). Don't promise it.
            (tr(
                lang,
                ", push its key, install fail2ban + sing-box, render the config, and prove the service is live — all on the next screen. SSH hardening (non-root user, sshd lockdown) is not part of this wizard yet.",
                ", запушит свой ключ, установит fail2ban + sing-box, отрендерит конфиг и проверит что сервис живёт — всё это на следующем экране. SSH-hardening (non-root пользователь, lockdown sshd) пока не входит в этот мастер.",
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
                    // Honest copy (review 2026-06-04): the wizard keeps
                    // whatever SSH port you enter — there is no
                    // automatic harden-to-2222 step.
                    (tr(
                        lang,
                        "DigitalOcean droplets must keep SSH on port 22 (Cloud Firewall blocks the rest). The wizard connects on the port you enter and keeps it — no automatic port change.",
                        "Дроплеты DigitalOcean должны держать SSH на 22 (Cloud Firewall блокирует остальное). Мастер подключается на введённый порт и оставляет его — порт автоматически не меняется.",
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
                    // Honest copy (review 2026-06-04): the wizard does
                    // NOT disable password auth — every later step just
                    // uses key auth instead.
                    (tr(
                        lang,
                        "Used once to push our SSH key; every later step authenticates with the key. Held in daemon memory for 10 minutes; nothing is written to disk. Password auth stays as the host had it.",
                        "Используется один раз чтобы запушить наш SSH-ключ; дальше все шаги ходят по ключу. Лежит в памяти демона 10 минут; на диск ничего не пишется. Password-auth остаётся как был на хосте.",
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
/// `crate::wizard_bootstrap::run_bootstrap`. NOTE: the SSE session
/// is SINGLE-SHOT — the first attach consumes it, so a refresh gets
/// «session missing», NOT a re-attach (the bootstrap itself keeps
/// running server-side; result lands on the server detail page +
/// audit timeline). A job-id store with multi-viewer attach is the
/// future fix if re-attach is ever wanted.
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
            (crate::i18n::tr(lang, "Add server · step 2 of 2", "Добавить сервер · шаг 2 из 2"))
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
            // Honest copy (review 2026-06-04): no host lockdown happens
            // here (fail2ban install ≠ SSH hardening), and the SSE
            // session is SINGLE-SHOT — a refresh loses the live log
            // (the bootstrap itself keeps running server-side).
            (crate::i18n::tr(
                lang,
                " (one-time password use), pushing its deploy key, installing fail2ban + ",
                " (одноразовое использование пароля), закидывает deploy-ключ, ставит fail2ban + ",
            ))
            span.ed-mono { "sing-box" }
            (crate::i18n::tr(
                lang,
                " and pushing the rendered config. Every step shows up below as it happens. Don't close or refresh this tab — the live log attaches once; if you lose it, the bootstrap still finishes server-side and the result lands on the server's detail page + the audit timeline.",
                " и пушит готовый конфиг. Каждый шаг появится ниже по мере выполнения. Не закрывай и не обновляй вкладку — живой лог подключается один раз; если потерял его, bootstrap всё равно доработает серверно, результат будет на странице сервера и в audit-таймлайне.",
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

/// `GET /admin/servers/{id}/deploy/sse` — EventSource endpoint that
/// RE-deploys an existing server, streaming `step` / `ok` / `error`
/// events so the operator watches each phase live and sees the terminal
/// status (item-1, 2026-05-31). The heavy lifting is
/// `wizard_bootstrap::run_redeploy`, which ends in an `error` event when
/// any kernel step failed — so a crash-looping sing-box never reads as
/// success (the bug the old synchronous 303-redirect handler had).
///
/// EventSource can only issue GET, so this state-changing request can't
/// ride the POST-only Origin CSRF middleware. Guard explicitly: reject a
/// browser `Sec-Fetch-Site: cross-site` / `none` (a `<img>`/prefetch CSRF
/// attempt). Absent header = non-browser tooling (curl) which carries no
/// ambient admin cookie to forge with, so it's allowed — same posture as
/// the wizard + geoip SSE endpoints, plus basic-auth on the whole tree.
pub(crate) async fn server_deploy_sse(
    axum::extract::Path(server_id): axum::extract::Path<String>,
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Response {
    use axum::response::sse::{Event, KeepAlive, Sse};
    use futures_core::Stream;
    use std::pin::Pin;
    use tokio_stream::StreamExt;

    // Same-origin guard for the state-changing GET.
    if let Some(sfs) = headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) {
        // Unified predicate (audit 2026-06-10, same as the geoip SSE):
        // allow only "same-origin" (EventSource from an admin page) and
        // "none" (direct navigation). The old check let "same-site"
        // through while refusing "none" — opposite of the geoip guard.
        if sfs != "same-origin" && sfs != "none" {
            return error_resp(
                StatusCode::FORBIDDEN,
                "cross-origin deploy trigger refused (same-origin only)",
            );
        }
    }

    let sid = vpnctl_core::ServerId(server_id.clone());
    let server = match state.inv.get_server(&sid).await {
        Ok(Some(s)) => s,
        Ok(None) => return not_found(&format!("no such server '{server_id}'")),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };

    let key_path = std::path::PathBuf::from(crate::app::DEFAULT_DEPLOY_KEY_PATH);
    let raw = crate::wizard_bootstrap::run_redeploy(
        server,
        state.inv.clone(),
        std::sync::Arc::clone(&state.registry),
        key_path,
    );
    let mapped = raw.map(|ev| {
        let name = match &ev {
            crate::wizard_bootstrap::BootstrapEvent::Step { .. } => "step",
            crate::wizard_bootstrap::BootstrapEvent::Ok { .. } => "ok",
            crate::wizard_bootstrap::BootstrapEvent::Error { .. } => "error",
        };
        let json = serde_json::to_string(&ev).unwrap_or_else(|e| {
            tracing::error!(
                target = "vpnctld::redeploy",
                event_name = name,
                error = %e,
                "redeploy SSE event serialisation failed — emitting placeholder"
            );
            format!(
                "{{\"kind\":\"step\",\"phase\":\"serialise-error\",\"message\":\"daemon failed to serialise this event ({e}); see vpnctld logs\"}}"
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

/// `GET /admin/servers/deploy-all/sse` — EventSource that re-deploys
/// EVERY server in one streamed pass (the "Deploy all" button, 2026-06-03).
/// Run after adding a user / granting servers so the new UUID reaches all
/// nodes (a grant only updates inv.db; the node's sing-box isn't touched
/// until a deploy). Same Sec-Fetch-Site same-origin guard + basic-auth as
/// the single-server SSE deploy. Best-effort across the fleet — heavy
/// lifting in `wizard_bootstrap::run_deploy_all`.
pub(crate) async fn servers_deploy_all_sse(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Response {
    use axum::response::sse::{Event, KeepAlive, Sse};
    use futures_core::Stream;
    use std::pin::Pin;
    use tokio_stream::StreamExt;

    if let Some(sfs) = headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) {
        // Unified predicate (audit 2026-06-10, same as the geoip SSE):
        // allow only "same-origin" (EventSource from an admin page) and
        // "none" (direct navigation). The old check let "same-site"
        // through while refusing "none" — opposite of the geoip guard.
        if sfs != "same-origin" && sfs != "none" {
            return error_resp(
                StatusCode::FORBIDDEN,
                "cross-origin deploy trigger refused (same-origin only)",
            );
        }
    }

    let servers = match state.inv.list_servers().await {
        Ok(s) => s,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };

    let key_path = std::path::PathBuf::from(crate::app::DEFAULT_DEPLOY_KEY_PATH);
    let raw = crate::wizard_bootstrap::run_deploy_all(
        servers,
        state.inv.clone(),
        std::sync::Arc::clone(&state.registry),
        key_path,
    );
    let mapped = raw.map(|ev| {
        let name = match &ev {
            crate::wizard_bootstrap::BootstrapEvent::Step { .. } => "step",
            crate::wizard_bootstrap::BootstrapEvent::Ok { .. } => "ok",
            crate::wizard_bootstrap::BootstrapEvent::Error { .. } => "error",
        };
        let json = serde_json::to_string(&ev).unwrap_or_else(|e| {
            tracing::error!(
                target = "vpnctld::deploy_all",
                event_name = name,
                error = %e,
                "deploy-all SSE event serialisation failed — emitting placeholder"
            );
            format!(
                "{{\"kind\":\"step\",\"phase\":\"serialise-error\",\"message\":\"daemon failed to serialise this event ({e}); see vpnctld logs\"}}"
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

/// `GET /admin/servers/{id}/update-kernels/sse` — EventSource endpoint
/// that UPGRADES the kernel binaries on an existing server (update-kernels
/// PR2). For each declared kernel it streams `status → install → done`
/// running ONLY `ensure_installed` (apt upgrade + service restart) — it
/// never renders or applies a config, so it works on inventory-drift nodes
/// without entering the DG-1 UUID-removal guard. The heavy lifting is
/// `wizard_bootstrap::run_update_kernels`, which ends in an `error` event
/// when any kernel step failed.
///
/// EventSource can only issue GET, so this state-changing request can't
/// ride the POST-only Origin CSRF middleware. Guard explicitly: reject a
/// browser `Sec-Fetch-Site: cross-site` / non-same-origin (a `<img>`/
/// prefetch CSRF attempt). Absent header = non-browser tooling (curl)
/// which carries no ambient admin cookie to forge with, so it's allowed —
/// same posture as the deploy + geoip SSE endpoints, plus basic-auth on
/// the whole tree.
pub(crate) async fn server_update_kernels_sse(
    axum::extract::Path(server_id): axum::extract::Path<String>,
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Response {
    use axum::response::sse::{Event, KeepAlive, Sse};
    use futures_core::Stream;
    use std::pin::Pin;
    use tokio_stream::StreamExt;

    // Same-origin guard for the state-changing GET.
    if let Some(sfs) = headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) {
        if sfs != "same-origin" && sfs != "none" {
            return error_resp(
                StatusCode::FORBIDDEN,
                "cross-origin update-kernels trigger refused (same-origin only)",
            );
        }
    }

    let sid = vpnctl_core::ServerId(server_id.clone());
    let server = match state.inv.get_server(&sid).await {
        Ok(Some(s)) => s,
        Ok(None) => return not_found(&format!("no such server '{server_id}'")),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };

    let key_path = std::path::PathBuf::from(crate::app::DEFAULT_DEPLOY_KEY_PATH);
    let raw = crate::wizard_bootstrap::run_update_kernels(
        server,
        state.inv.clone(),
        std::sync::Arc::clone(&state.registry),
        key_path,
    );
    let mapped = raw.map(|ev| {
        let name = match &ev {
            crate::wizard_bootstrap::BootstrapEvent::Step { .. } => "step",
            crate::wizard_bootstrap::BootstrapEvent::Ok { .. } => "ok",
            crate::wizard_bootstrap::BootstrapEvent::Error { .. } => "error",
        };
        let json = serde_json::to_string(&ev).unwrap_or_else(|e| {
            tracing::error!(
                target = "vpnctld::update_kernels",
                event_name = name,
                error = %e,
                "update-kernels SSE event serialisation failed — emitting placeholder"
            );
            format!(
                "{{\"kind\":\"step\",\"phase\":\"serialise-error\",\"message\":\"daemon failed to serialise this event ({e}); see vpnctld logs\"}}"
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

/// `GET /admin/servers/update-kernels-all/sse` — EventSource that upgrades
/// the kernel binaries on EVERY server in one streamed pass (the "Update
/// all kernels" button). Same Sec-Fetch-Site same-origin guard + basic-
/// auth as the single-server SSE update. Best-effort across the fleet —
/// heavy lifting in `wizard_bootstrap::run_update_kernels_all`. The
/// 3-segment path avoids the `{id}` clash — same trick as
/// `deploy-all/sse`.
pub(crate) async fn servers_update_kernels_all_sse(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Response {
    use axum::response::sse::{Event, KeepAlive, Sse};
    use futures_core::Stream;
    use std::pin::Pin;
    use tokio_stream::StreamExt;

    if let Some(sfs) = headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) {
        if sfs != "same-origin" && sfs != "none" {
            return error_resp(
                StatusCode::FORBIDDEN,
                "cross-origin update-kernels trigger refused (same-origin only)",
            );
        }
    }

    let servers = match state.inv.list_servers().await {
        Ok(s) => s,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };

    let key_path = std::path::PathBuf::from(crate::app::DEFAULT_DEPLOY_KEY_PATH);
    let raw = crate::wizard_bootstrap::run_update_kernels_all(
        servers,
        state.inv.clone(),
        std::sync::Arc::clone(&state.registry),
        key_path,
    );
    let mapped = raw.map(|ev| {
        let name = match &ev {
            crate::wizard_bootstrap::BootstrapEvent::Step { .. } => "step",
            crate::wizard_bootstrap::BootstrapEvent::Ok { .. } => "ok",
            crate::wizard_bootstrap::BootstrapEvent::Error { .. } => "error",
        };
        let json = serde_json::to_string(&ev).unwrap_or_else(|e| {
            tracing::error!(
                target = "vpnctld::update_kernels",
                event_name = name,
                error = %e,
                "update-kernels-all SSE event serialisation failed — emitting placeholder"
            );
            format!(
                "{{\"kind\":\"step\",\"phase\":\"serialise-error\",\"message\":\"daemon failed to serialise this event ({e}); see vpnctld logs\"}}"
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

/// Query string for the server-detail page (PR-Server).
///
/// * `drift=live` — opt-in flag that arms the highest-risk card
///   (server#1 drift-detail): a best-effort live SSH read of the
///   node's `/etc/sing-box/config.json` to diff the on-node UUIDs
///   against inventory. GATED so the DEFAULT page load stays fast —
///   no SSH happens unless the operator clicks «check live drift».
/// * `vpn_window` — shared window slug (`24h|7d|30d|all`) consumed by
///   the per-server traffic sparkline's `window_picker_section`, same
///   shape as the dashboard + user-detail pages.
#[derive(serde::Deserialize, Default)]
pub(crate) struct ServerDetailQuery {
    #[serde(default)]
    drift: Option<String>,
    #[serde(default)]
    vpn_window: Option<String>,
}

impl ServerDetailQuery {
    /// True only for the explicit `?drift=live` opt-in. Any other
    /// value (absent, `?drift=`, `?drift=foo`) keeps the live SSH
    /// read disarmed — the default fast path.
    fn drift_live(&self) -> bool {
        matches!(self.drift.as_deref(), Some("live"))
    }
}

/// server_detail's in-page tabs (ui-audit §3-§4). Each is a real
/// sub-route (`/admin/servers/{id}/{slug}`) so navigation is plain
/// `<a href>` — zero JS, back-button-correct, deep-linkable — and each
/// tab renders only its own sections. `Status` is the default (bare
/// `/admin/servers/{id}`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ServerTab {
    Status,
    Activity,
    Protocols,
    Grants,
    Setup,
}

impl ServerTab {
    fn slug(self) -> &'static str {
        match self {
            ServerTab::Status => "status",
            ServerTab::Activity => "activity",
            ServerTab::Protocols => "protocols",
            ServerTab::Grants => "grants",
            ServerTab::Setup => "setup",
        }
    }
}

/// The `.ed-tabs` bar — dead CSS since Phase A (admin.css:608), worn
/// here for the first time. `base` must already be path-segment-encoded;
/// `active` is the current tab's slug (its link gets `.ed-tab--on`).
/// `cursor`/`text-decoration` are set inline because the dead CSS was
/// authored for JS toggles (cursor:default, no link reset).
fn detail_tabs(base: &str, active: &str, tabs: &[(&str, &str)]) -> Markup {
    html! {
        div.ed-tabs {
            @for (slug, label) in tabs {
                a class=(if *slug == active { "ed-tab ed-tab--on" } else { "ed-tab" })
                  href=(format!("{base}/{slug}"))
                  style="cursor: pointer; text-decoration: none;" {
                    (label)
                }
            }
        }
    }
}

// Thin axum handlers — one per tab route in app.rs. Bare
// `/admin/servers/{id}` (+ trailing slash) + `/status` both land here.
pub(crate) async fn server_detail(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(server_id_str): Path<String>,
    axum::extract::Query(query): axum::extract::Query<ServerDetailQuery>,
) -> Result<Markup, Response> {
    server_detail_render(headers, state, server_id_str, query, ServerTab::Status).await
}

pub(crate) async fn server_detail_activity(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(server_id_str): Path<String>,
    axum::extract::Query(query): axum::extract::Query<ServerDetailQuery>,
) -> Result<Markup, Response> {
    server_detail_render(headers, state, server_id_str, query, ServerTab::Activity).await
}

pub(crate) async fn server_detail_protocols_tab(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(server_id_str): Path<String>,
    axum::extract::Query(query): axum::extract::Query<ServerDetailQuery>,
) -> Result<Markup, Response> {
    server_detail_render(headers, state, server_id_str, query, ServerTab::Protocols).await
}

pub(crate) async fn server_detail_grants_tab(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(server_id_str): Path<String>,
    axum::extract::Query(query): axum::extract::Query<ServerDetailQuery>,
) -> Result<Markup, Response> {
    server_detail_render(headers, state, server_id_str, query, ServerTab::Grants).await
}

pub(crate) async fn server_detail_setup(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(server_id_str): Path<String>,
    axum::extract::Query(query): axum::extract::Query<ServerDetailQuery>,
) -> Result<Markup, Response> {
    server_detail_render(headers, state, server_id_str, query, ServerTab::Setup).await
}

async fn server_detail_render(
    headers: HeaderMap,
    state: AppState,
    server_id_str: String,
    query: ServerDetailQuery,
    tab: ServerTab,
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

    // Server-side pending-deploy flag (audit 2026-06-10 follow-up):
    // «grant membership changed since the last deploy». Crucially this
    // covers the REVOKE case the per-user banner can't — the revoked
    // server leaves the user's granted list, so THIS page is the only
    // surface that can warn that the node still runs the revoked UUID.
    // Best-effort: a detector error renders no banner, not a 500.
    let pending_deploy = state.inv.server_pending_deploy(&sid).await.unwrap_or(false);

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

    // Traffic accounting — NIC ground-truth (ALL protocols) vs the
    // sing-box part clash-api attributed vs the GAP between them. The
    // gap is the operator's headline: real traffic vpnctl can't yet
    // break down per-user (naive/Caddy, dns-tunnel, wgturn + overhead).
    let traffic = state
        .inv
        .server_traffic_breakdown(&sid, 24)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(target = "vpnctld::admin", server = %sid, error = %e, "server_traffic_breakdown failed");
            vpnctl_inventory::TrafficBreakdown {
                nic_total_bytes: 0,
                nic_rx_bytes: 0,
                nic_tx_bytes: 0,
                attributed_bytes: 0,
                gap_bytes: 0,
                nic_samples: 0,
                nic_iface: None,
            }
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

    // Per-server reserved-ports list (migration 0028). Empty for
    // every server in the fleet by default; this load is one
    // indexed SELECT so the section helper always has data without
    // a conditional fetch.
    let reserved_ports = state
        .inv
        .get_reserved_ports(&sid)
        .await
        .map_err(|e| internal_error(anyhow::Error::new(e)))?;

    // Operator-set subscription label (servers.display_name, migration
    // 0029). One indexed SELECT; None → the section shows the auto
    // (country-map) fallback.
    let display_name = state
        .inv
        .server_display_name(&sid)
        .await
        .map_err(|e| internal_error(anyhow::Error::new(e)))?;

    // Auto-suppress state (migration 0030): (opt-in, suppressed_at).
    let (auto_suppress_optin, suppressed_at) = state
        .inv
        .server_auto_suppress_state(&sid)
        .await
        .map_err(|e| internal_error(anyhow::Error::new(e)))?;

    // naive↔HY2 UDP-pairing opt-in (migration 0031, UX-3).
    let udp_pair_enabled = state
        .inv
        .is_server_udp_pair_enabled(&sid)
        .await
        .map_err(|e| internal_error(anyhow::Error::new(e)))?;

    // ── PR-Server informativeness cards ─────────────────────────────
    // All three SQL-backed loads are best-effort: a query error logs +
    // empty-states the relevant card rather than 500-ing the whole
    // page (the rest of the server detail stays useful). Each is one
    // indexed scan — no new N+1 (the drift-LIVE SSH read, the only
    // expensive path, is gated behind `?drift=live` below).

    // server#3 — top users by 24h traffic on THIS server (Q top-users).
    // Currently empty in prod (NM-11: clash-api drops the per-user
    // field upstream), so the section carries an explicit NM-11
    // empty-state rather than rendering a blank card.
    let top_users = state
        .inv
        .top_users_by_traffic_for_server(&sid, 24, 10)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(target = "vpnctld::admin", server = %sid, error = %e, "top_users_by_traffic_for_server failed");
            Vec::new()
        });

    // server#4 — per-server traffic sparkline. Window slug picked from
    // `?vpn_window=` (shared shape with dashboard + user-detail); rows
    // are server-wide (`recent_vpn_stats_for_server`).
    let traffic_window = pick_vpn_sparkline_window(query.vpn_window.as_deref());
    let traffic_since_hours = traffic_window.cells * traffic_window.bucket_hours;
    let traffic_rows = state
        .inv
        .recent_vpn_stats_for_server(&sid, traffic_since_hours)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(target = "vpnctld::admin", server = %sid, error = %e, "recent_vpn_stats_for_server failed");
            Vec::new()
        });

    // server#7 — server-scoped audit timeline (Q audit-for-server).
    let server_audit = state
        .inv
        .audit_for_server(&sid.0, 20)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(target = "vpnctld::admin", server = %sid, error = %e, "audit_for_server failed");
            Vec::new()
        });

    // server#2 — kernel-floor rollup scoped to THIS server. Reuses the
    // SHARED `kernel_floor_rollup` (PR-Dash) with a single-element
    // slice — `latest` already carries this node's newest
    // `kernel_versions_json` (no extra query).
    let server_kernel_versions: Vec<(vpnctl_core::ServerId, Option<String>)> = vec![(
        sid.clone(),
        latest.as_ref().and_then(|h| h.kernel_versions_json.clone()),
    )];

    // server#1 — drift-detail (live on-node UUIDs). HIGHEST RISK: the
    // ONLY card that reaches out over SSH, so it's gated behind the
    // explicit `?drift=live` opt-in. Without the flag the default page
    // load does ZERO SSH and renders a «[check live drift →]» link.
    //
    // When armed, the live read is best-effort with a hard ≤6s
    // timeout: any failure (node down, key not authorised, parse
    // error) collapses to `None` → the section renders a policy-safe
    // empty-state, NEVER a 500. The inventory UUID set comes from
    // `users` (already loaded; `.uuid` resolves COALESCE(client_uuid,
    // users.uuid)) so an orphan = a UUID the node serves that no
    // granted user accounts for.
    // Gate on the tab too, not just the query flag: the drift-detail
    // card (with its `?drift=live` arm link) only renders on the
    // protocols tab, so `/status?drift=live` (bookmark / hand-typed /
    // crawler) must NOT trigger the 6s SSH read and throw the result
    // away. review-agent Phase 1.
    let drift_live: Option<DriftLiveResult> = if tab == ServerTab::Protocols && query.drift_live() {
        Some(load_drift_live(&server, &users, &all_users).await)
    } else {
        None
    };

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
        // Pending-deploy banner — grant/revoke happened after the last
        // deploy, so the node's running config doesn't match inventory.
        // The revoke case is the dangerous one: the revoked user's UUID
        // is STILL ACCEPTED by the node until the deploy below runs.
        @if pending_deploy {
            div id="pending-deploy-banner"
                style="margin: 12px 0 0; padding: 10px 14px; border: 1px solid var(--acc); background: var(--paper-tint); font-family: var(--mono); font-size: 11px; color: var(--ink);" {
                b { (crate::i18n::tr(lang, "config not yet deployed", "конфиг ещё не задеплоен")) }
                " — "
                (crate::i18n::tr(
                    lang,
                    "grants changed since the last deploy. Until you click deploy, the node keeps running the OLD user set — a revoked user can still connect.",
                    "гранты менялись после последнего деплоя. Пока не нажат deploy, нода работает со СТАРЫМ списком юзеров — отозванный юзер всё ещё может подключиться.",
                ))
            }
        }
        div id="deploy-button" style="margin: 12px 0 18px;" {
            // JS-driven: streams per-step progress + terminal status
            // into the log pane below via SSE (admin.js wires the
            // `data-sse-url`). The terminal event is `error` when any
            // kernel step failed — so the operator sees failure, not a
            // silent "success" redirect.
            button type="button"
                   data-sse-url=(format!("/admin/servers/{}/deploy/sse", path_segment_encode(&server.id.0)))
                   data-busy-label=(crate::i18n::tr(lang, "deploying… (watch the log)", "деплою… (смотри лог)"))
                   data-retry-label=(crate::i18n::tr(lang, "retry deploy", "повторить деплой"))
                   title=(crate::i18n::tr(
                       lang,
                       "Full deploy: streamed live — mint missing per-protocol server secrets, then SSH into the node and run apt-get install + render-config + systemctl restart for each enabled kernel. Each step + the final status appears in the log below. Re-clicking is safe — already-present secrets and kernels are skipped.",
                       "Полный деплой с живым логом: дораздать недостающие per-protocol секреты, затем SSH в ноду и запустить apt-get install + render-config + systemctl restart для каждого включённого ядра. Каждый шаг + финальный статус появятся в логе ниже. Повторный клик безопасен — уже существующие секреты и ядра пропускаются.",
                   ))
                   style="padding: 6px 14px; border: 1px solid var(--ink); background: var(--ink); color: var(--paper); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                (crate::i18n::t(lang, crate::i18n::K::BtnDeploy))
            }
            // No-JS fallback: the original synchronous POST still works
            // (it just lacks the live log — the browser blocks until the
            // deploy returns, then redirects).
            noscript {
                form method="post"
                     action=(format!("/admin/servers/{}/deploy", path_segment_encode(&server.id.0)))
                     style="display: inline;" {
                    button type="submit"
                           style="padding: 6px 14px; border: 1px solid var(--ink); background: var(--ink); color: var(--paper); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                        (crate::i18n::t(lang, crate::i18n::K::BtnDeploy))
                    }
                }
            }
            // Live log pane — hidden until the operator clicks deploy.
            pre id="deploy-log" hidden
                style="margin-top: 12px; padding: 10px 12px; background: var(--paper-tint); border: 1px solid var(--rule); font-family: var(--mono); font-size: 11px; line-height: 1.5; max-height: 320px; overflow-y: auto; white-space: pre-wrap;" {}
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

        // "Update kernels" (update-kernels PR2) — upgrade ONLY the kernel
        // binaries (apt upgrade + service restart) without touching the
        // running config. Streamed via the same generic admin.js
        // [data-sse-url]+[data-log] wiring as Deploy, but its OWN log pane
        // (`update-kernels-log`) so it doesn't collide with `deploy-log`.
        // Safe on inventory-drift nodes — it never re-renders the config,
        // so it can't shrink the live user set.
        div id="update-kernels-button" style="margin: 12px 0 18px;" {
            button type="button"
                   data-sse-url=(format!("/admin/servers/{}/update-kernels/sse", path_segment_encode(&server.id.0)))
                   data-log="update-kernels-log"
                   data-busy-label=(crate::i18n::tr(lang, "updating kernels… (watch the log)", "обновляю ядра… (смотри лог)"))
                   data-retry-label=(crate::i18n::tr(lang, "retry update", "повторить обновление"))
                   title=(crate::i18n::tr(
                       lang,
                       "Upgrade the kernel binaries only: streamed live, this probes each declared kernel's version, upgrades the package (apt upgrade), restarts the service, then probes the version again — before → after lands in the log below. The running config is left untouched, so this is safe to run on a node whose inventory has drifted. Re-clicking is safe — an already-current binary is a no-op.",
                       "Обновить только бинарники ядер: с живым логом — снимает версию каждого объявленного ядра, обновляет пакет (apt upgrade), рестартует сервис и снимает версию снова — до → после появится в логе ниже. Рабочий конфиг не трогается, поэтому безопасно на ноде с дрейфом инвентаря. Повторный клик безопасен — уже актуальный бинарь = no-op.",
                   ))
                   style="padding: 6px 14px; border: 1px solid var(--ink); background: transparent; color: var(--ink); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                (crate::i18n::tr(lang, "update kernels →", "обновить ядра →"))
            }
            // Live log pane — hidden until the operator clicks update.
            pre id="update-kernels-log" hidden
                style="margin-top: 12px; padding: 10px 12px; background: var(--paper-tint); border: 1px solid var(--rule); font-family: var(--mono); font-size: 11px; line-height: 1.5; max-height: 320px; overflow-y: auto; white-space: pre-wrap;" {}
            span style="margin-left: 12px; font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute);" {
                (crate::i18n::tr(
                    lang,
                    "Upgrades the kernel binaries and restarts the service; the running config is untouched. Safe on a node whose inventory has drifted.",
                    "Обновляет бинарники ядер и рестартует сервис; рабочий конфиг не трогается. Безопасно на ноде с дрейфом инвентаря.",
                ))
            }
        }

        // Hero: current state (live or empty-state)
        (server_detail_hero(&latest, &server, lang))

        // ── in-page tabs (ui-audit §3-§4). Chrome above (nav / hero /
        // deploy / update-kernels / pending-deploy banner) shows on
        // EVERY tab so the daily deploy action never hides behind one;
        // each group below renders only on its own tab. Bare
        // /admin/servers/{id} == the `status` tab.
        @let tab_base = format!("/admin/servers/{}", path_segment_encode(&server.id.0));
        (detail_tabs(&tab_base, tab.slug(), &[
            ("status", crate::i18n::tr(lang, "Status", "Статус")),
            ("activity", crate::i18n::tr(lang, "Activity", "Активность")),
            ("protocols", crate::i18n::tr(lang, "Protocols", "Протоколы")),
            ("grants", crate::i18n::tr(lang, "Grants", "Гранты")),
            ("setup", crate::i18n::tr(lang, "Setup", "Настройка")),
        ]))

        // ── STATUS (default) — "is the node healthy, what changed".
        @if tab == ServerTab::Status {
            // Rolling uptime SLO (24h/7d/30d); nothing when no probes.
            (server_detail_uptime_section(
                uptime_24h.as_ref(),
                uptime_7d.as_ref(),
                uptime_30d.as_ref(),
                lang,
            ))
            // A3 — 24h resource trend sparklines (disk, mem, log size).
            (server_detail_resource_trend_section(&trend_rows, lang))
            // Drift SUMMARY only — the verdict + counts. The full
            // declared-vs-observed grid + observed-socket list (100+
            // rows on wgturn/xray nodes) live on the protocols tab.
            (server_detail_drift_summary(&missing, &extra, latest.is_some(), &tab_base, lang))
            // server#7 — server-scoped audit timeline (last 20).
            (server_detail_audit_section(&server_audit, lang))
        }

        // ── ACTIVITY — clash-api-snapshot-derived, read-only.
        @if tab == ServerTab::Activity {
            // Phase 4b — live activity tile (server-wide clash-api totals).
            (server_detail_live_activity_section(&live_activity, lang))
            // Traffic accounting — NIC ground-truth vs clash-attributed vs gap.
            (server_detail_gap_section(&traffic, lang))
            // Phase 4c/4d/5a-2 — per-connection drill-down (top dests +
            // reverse-DNS, source IPs with user correlation, TCP/UDP split).
            (server_detail_live_connections_section(last_server_snap.as_deref(), &source_user_map, &dns_ptr_map, lang))
            // server#4 — per-server traffic 24h/7d sparkline (?vpn_window=).
            (server_detail_traffic_section(&traffic_rows, traffic_window, &server.id, lang))
            // server#3 — top users on this server (24h); NM-11 empty-state.
            (server_detail_top_users_section(&top_users, lang))
            // server#5 — TCP/UDP split from the live clash-api snapshot.
            (server_detail_network_split_section(last_server_snap.as_deref(), lang))
        }

        // ── PROTOCOLS — "what does this node serve, on which ports".
        @if tab == ServerTab::Protocols {
            // Kernels — multi-kernel runtime selection + version-floor rollup.
            // Enable amneziawg kernel here → enable wireguard protocol
            // below → deploy. The `update kernels →` button lives in the
            // chrome above (adjacent to Deploy).
            (kernel_floor_rollup(&server_kernel_versions, lang))
            (server_detail_kernels_section(&server, &state.registry, lang))
            // Enabled protocols — enable/disable/hide (NM-10 hidden_map:
            // hidden=1 keeps the inbound running but stops emitting the
            // protocol from /sub + /api/v1/app/config). Changes take
            // effect on the NEXT deploy.
            (server_detail_protocols_section(&server, &state.registry, &hidden_map, lang))
            // Naive (Caddy) + vless-ws per-server config (domain + ACME).
            (server_detail_naive_config_section(&server, &server_secrets, lang))
            (server_detail_vlessws_config_section(&server, &server_secrets, lang))
            // naive↔HY2 UDP pairing opt-in (UX-3) — shared `pair=` so a
            // client routes UDP over the co-located HY2.
            (server_detail_udp_pair_section(&server, udp_pair_enabled, lang))
            // Reserved ports — operator port allowlist the apply-guard skips.
            (server_detail_reserved_ports_section(&server, &reserved_ports, lang))
            // wgturn VK-link — only when the wgturn kernel is enabled.
            (server_detail_wgturn_section(&server, &server_secrets, lang))
            // Declared vs observed drift — full grid incl. the observed
            // listening-socket list (port-level, probe-derived).
            (server_detail_drift_section(&server, &observed, &missing, &extra, latest.is_some(), lang))
            // Drift DETAIL — on-node orphan UUIDs; `?drift=live` arms a
            // best-effort 6s SSH read of the node's sing-box config.
            (server_detail_drift_detail_section(&server, drift_live.as_ref(), query.drift_live(), lang))
        }

        // ── GRANTS — 2nd-most-frequent action; its own uncluttered page.
        @if tab == ServerTab::Grants {
            // Centralised per-server view (Pavel iter B): every user with
            // a per-row grant/revoke form + bulk grant/revoke.
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
                        // CSP-safe typed-confirm — destructive but
                        // reversible (operator can re-grant individually).
                        // The prompt text + required match value ride in
                        // `data-confirm-prompt` / `data-confirm-match`
                        // (maud HTML-escapes both); admin.js runs the
                        // prompt(), checks the typed value, and copies it
                        // into the hidden `confirm` field the handler
                        // re-validates. An inline `onsubmit="…"` would be
                        // blocked by `script-src 'self'` → the field would
                        // stay empty and the POST would be rejected.
                        @let sid_clean = server.id.0.clone();
                        @let confirm_msg = match lang {
                            crate::i18n::Locale::En => format!(
                                "Revoke access for all {granted_count} granted users on server '{sid_clean}'? Type the server id to confirm:"
                            ),
                            crate::i18n::Locale::Ru => format!(
                                "Отозвать доступ у всех {granted_count} юзеров с грантом на сервере '{sid_clean}'? Введи id сервера для подтверждения:"
                            ),
                        };
                        form method="post"
                             action=(format!("/admin/servers/{sid_enc_b}/grants/_revoke-all"))
                             data-confirm-prompt=(confirm_msg)
                             data-confirm-match=(sid_clean)
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
        }

        // ── SETUP — the 0-2-uses/month config tail (ui-audit §4),
        // deliberately last.
        @if tab == ServerTab::Setup {
            // Trusted host fingerprint — TOFU pin for the SSH probe +
            // clash-api poller + deploy (web action + the
            // `vpnctl server set-fingerprint <id>` CLI, one source of truth).
            (server_detail_fingerprint_section(&server, lang))
            // Display name — operator subscription label (migration 0029).
            (server_detail_display_name_section(&server, display_name.as_deref(), lang))
            // Auto-suppress from subscription when unreachable (migration 0030).
            (server_detail_auto_suppress_section(&server, auto_suppress_optin, suppressed_at.as_deref(), lang))
            // Push deploy key — recovery for quick-add/migrate nodes whose
            // wizard step-3 pubkey push never ran.
            (server_detail_push_deploy_key_section(&server, lang))

            // Danger zone — remove this server from inventory entirely.
            // Retype-to-confirm page (mirrors user delete). Grants, secrets,
            // protocols, probe history + alerts cascade-delete; if another
            // server uses this as a ProxyJump host that link clears. The
            // node's own sing-box is NOT touched.
            div.ed-rule {}
            div style="margin: 18px 0 8px;" {
                a href=(format!("/admin/servers/{}/delete-confirm", path_segment_encode(&server.id.0)))
                  title=(crate::i18n::tr(
                      lang,
                      "Remove this server from the inventory (grants + secrets + protocols cascade). Opens a retype-to-confirm page.",
                      "Удалить этот сервер из инвентаря (гранты + секреты + протоколы каскадом). Откроется страница с подтверждением по перепечатке id.",
                  ))
                  style="display: inline-block; font-family: var(--mono); font-size: 11px; color: var(--acc-bad, #97233f); text-decoration: none; border: 1px solid var(--acc-bad, #97233f); padding: 5px 12px;" {
                    (crate::i18n::tr(lang, "delete this server…", "удалить этот сервер…"))
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
                            span style="color: var(--ink);" { (format_msk_iso(ts)) }
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
                // Honest copy (audit 2026-06-10): the poller is LIVE
                // (spawn_node_probe_poller, 10-min cadence) and probes
                // sing-box servers only — blank means «not probed yet»
                // or «not probeable», not «feature unshipped».
                (tr(
                    lang,
                    "No probes yet. The node-telemetry poller SSHes ",
                    "Probe-ов пока нет. Поллер телеметрии SSH-ит ",
                ))
                span.ed-mono { (server.address) }
                (tr(
                    lang,
                    " every 10 min for disk/mem/load + listening ports. Blank here means the first probe hasn't landed (fresh server / daemon restart), the node is unreachable over SSH, or this server has no sing-box kernel (only sing-box nodes are probed).",
                    " каждые 10 минут за disk/mem/load + слушающими портами. Пусто значит: первый probe ещё не прошёл (новый сервер / рестарт демона), нода недоступна по SSH, либо у сервера нет ядра sing-box (probe-ятся только sing-box ноды).",
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
                (format_msk_iso(h.ts))
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
        .map(format_msk_iso)
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

/// Traffic accounting — NIC ground-truth vs clash-attributed vs the GAP.
/// The NIC total catches ALL protocols (the operator's reconciliation
/// with the hoster's billing); the gap is the slice vpnctl can't yet
/// break down per-user (non-sing-box protocols + protocol overhead).
/// Empty-state until ≥2 NIC probe samples exist (a delta needs two).
fn server_detail_gap_section(
    t: &vpnctl_inventory::TrafficBreakdown,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    if t.nic_samples < 2 {
        return html! {
            div.ed-rule {}
            div.ed-art-eyebrow { (tr(lang, "Traffic accounting · last 24h", "Учёт трафика · 24 часа")) }
            p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
                (tr(
                    lang,
                    "No NIC ground-truth yet — the node probe captures interface byte counters every ~10 minutes; come back after a couple of probes.",
                    "Пока нет данных NIC — probe ноды снимает байт-счётчики интерфейса каждые ~10 минут; вернись через пару проверок.",
                ))
            }
        };
    }
    // Gap as a share of real traffic — how much vpnctl can't attribute.
    let gap_pct = t
        .gap_bytes
        .saturating_mul(100)
        .checked_div(t.nic_total_bytes)
        .unwrap_or(0)
        .min(100);
    // A big gap (≥50%) is a real blind spot → accent it.
    let gap_colour = if gap_pct >= 50 {
        "var(--acc)"
    } else {
        "var(--ink)"
    };
    let iface = t.nic_iface.as_deref().unwrap_or("?").to_string();
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow { (tr(lang, "Traffic accounting · last 24h", "Учёт трафика · 24 часа")) }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
            (tr(
                lang,
                "Real interface traffic (NIC ground-truth — catches ALL protocols, reconciles with the hoster) vs the sing-box part clash-api could attribute. The GAP is everything clash-api can't see: non-sing-box protocols (naive/Caddy, dns-tunnel, wgturn) plus TLS/QUIC overhead.",
                "Реальный трафик интерфейса (NIC — ловит ВСЕ протоколы, сходится с хостером) против sing-box-части, которую смог атрибутировать clash-api. ГЭП — всё, что clash-api не видит: не-sing-box протоколы (naive/Caddy, dns-tunnel, wgturn) плюс оверхед TLS/QUIC.",
            ))
        }
        div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin: 12px 0 8px;" {
            div title=(tr(lang, "Total bytes (rx+tx) on the node's default-route interface over 24h, summed from the probe's cumulative counters. This is the real traffic — every protocol, plus overhead.", "Всего байт (rx+tx) на default-route интерфейсе ноды за 24ч, сумма дельт кумулятивных счётчиков probe. Это реальный трафик — все протоколы плюс оверхед.")) {
                (status_tile(tr(lang, "NIC total", "NIC всего"), &humanize_bytes(t.nic_total_bytes), "var(--ink)"))
            }
            div title=(tr(lang, "Bytes clash-api attributed to sing-box protocols (VLESS/REALITY, TUIC, hy2, Trojan, …) over 24h — the part vpnctl can break down per-user.", "Байт, которые clash-api атрибутировал sing-box-протоколам (VLESS/REALITY, TUIC, hy2, Trojan…) за 24ч — часть, которую vpnctl раскладывает по юзерам.")) {
                (status_tile(tr(lang, "sing-box (attributed)", "sing-box (атриб.)"), &humanize_bytes(t.attributed_bytes), "var(--ink)"))
            }
            div title=(tr(lang, "NIC total minus the attributed part: non-sing-box protocols (naive/Caddy, dns-tunnel, wgturn) + protocol/OS overhead. This is what vpnctl currently can't see per-user.", "NIC всего минус атрибутированное: не-sing-box протоколы (naive/Caddy, dns-tunnel, wgturn) + оверхед протокола/ОС. Это то, что vpnctl сейчас не видит по юзерам.")) {
                (status_tile(tr(lang, "GAP (unattributed)", "ГЭП (неатриб.)"), &humanize_bytes(t.gap_bytes), gap_colour))
            }
        }
        p style="font-family: var(--mono); font-size: 11px; color: var(--mute); margin: 4px 0 14px;" {
            (tr(lang, "interface ", "интерфейс "))
            b style="color: var(--ink);" { (iface) }
            " · "
            (tr(lang, "gap ", "гэп "))
            b style=(format!("color: {gap_colour};")) { (gap_pct) "%" }
            (tr(lang, " of real traffic not attributed per-user", " реального трафика не разложено по юзерам"))
            " · rx " (humanize_bytes(t.nic_rx_bytes))
            " · tx " (humanize_bytes(t.nic_tx_bytes))
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
    let nb = network_breakdown(snap);
    let top_dests = aggregate_by_destination(snap, TOP_N, dns_ptr_map);
    let top_sources = aggregate_by_source(snap, TOP_N);
    let total_conns = snap.connections.len();

    // For each top-source aggregate, surface the user_id behind that
    // source IP, taken from the connections' `metadata.user` (emitted by
    // our patched sing-box clash-api). If several users share one IP (NAT
    // collision), pick the one with the most connections — the
    // most-active device behind the NAT.
    use std::collections::HashMap as StdHashMap;
    let mut ip_to_log_user: StdHashMap<&str, StdHashMap<&str, u32>> = StdHashMap::new();
    for c in &snap.connections {
        if let Some(user) = c.metadata.user.as_deref() {
            if !c.metadata.source_ip.is_empty() {
                *ip_to_log_user
                    .entry(c.metadata.source_ip.as_str())
                    .or_default()
                    .entry(user)
                    .or_insert(0) += 1;
            }
        }
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
                           // Honest copy (audit 2026-06-10): with the
                           // password filled the handler goes straight
                           // to sshpass — the reference key is tried
                           // ONLY when the password field is empty.
                           "Append the daemon's deploy pubkey to ~/.ssh/authorized_keys on this server. With the password filled it connects via sshpass; leave the password empty to use the configured reference key instead.",
                           "Добавить deploy-pubkey демона в ~/.ssh/authorized_keys на этом сервере. С заполненным паролем подключается через sshpass; оставь пароль пустым, чтобы использовать настроенный reference-key.",
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
            // Honest copy (audit 2026-06-10): the daemon's SSH transport
            // uses `StrictHostKeyChecking=accept-new` + its own
            // known_hosts and does NOT read this pin — daemon-side the
            // pin only feeds the fingerprint-drift WARNING alert
            // (health_monitor::check_fingerprint_drift). Hard refusal
            // happens only on the CLI deploy path (russh
            // `trusted_fingerprint`). The old copy claimed every
            // pipeline refuses on mismatch.
            (tr(
                lang,
                "Pinned SHA-256 of the node's SSH ed25519 host key. The CLI deploy refuses a host whose live key doesn't match; the daemon's pipelines (web deploy / probe / clash-poller) verify against their own known_hosts and use this pin to raise a fingerprint-drift warning alert — ",
                "Закреплённый SHA-256 хост-ключа ed25519 ноды. CLI-деплой отказывается работать с хостом, чей live-ключ не совпадает; пайплайны демона (web-деплой / probe / clash-poller) сверяются со своим known_hosts, а по этому пину поднимают warning-алерт о дрейфе отпечатка — ",
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

/// Display-name section on the server-detail page (migration 0029).
/// `current` is the operator-set `servers.display_name` (None = unset).
/// Lets the operator pin the friendly `{Country}` label end users see in
/// their client's server list — blank clears it back to the built-in
/// ISO-code→country map, then the uppercased id. Web equivalent of an
/// otherwise-unsettable field (there's no CLI for it yet).
/// Naive (Caddy + forwardproxy) per-server config. The operator sets
/// `naive.domain` + `naive.acme_email` (server_secrets) that the caddy
/// kernel renders into the Caddyfile and Caddy's built-in ACME uses to
/// mint the Let's Encrypt cert. Rendered ONLY when the `naive` protocol
/// is enabled on this server (empty markup otherwise). Carries the
/// prerequisite reminder vpnctl CANNOT satisfy for the operator: a DNS
/// A-record pointing here + open TCP 80/443.
fn server_detail_naive_config_section(
    server: &vpnctl_core::Server,
    server_secrets: &std::collections::HashMap<String, String>,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    if !server.enabled_protocols.iter().any(|p| p.0 == "naive") {
        return html! {};
    }
    let sid_enc = path_segment_encode(&server.id.0);
    let domain = server_secrets
        .get("naive.domain")
        .map(String::as_str)
        .unwrap_or("");
    let email = server_secrets
        .get("naive.acme_email")
        .map(String::as_str)
        .unwrap_or("");
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow
            title=(tr(lang,
                "Caddy + forwardproxy serves a real cover website (HTTP 200) to probes and tunnels authenticated clients. Domain + email feed Caddy's built-in ACME (Let's Encrypt).",
                "Caddy + forwardproxy отдаёт настоящий сайт-прикрытие (HTTP 200) зондам и туннелирует аутентифицированных клиентов. Домен + почта идут во встроенный ACME Caddy (Let's Encrypt).")) {
            (tr(lang, "NAIVE (CADDY) CONFIG", "КОНФИГ NAIVE (CADDY)"))
        }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 10px;" {
            (tr(lang,
                "Before deploy: point a DNS A-record at this server and open TCP 80+443 — Caddy's ACME needs both. vpnctl can't do DNS for you.",
                "До деплоя: направь DNS A-запись на этот сервер и открой TCP 80+443 — встроенному ACME Caddy нужны оба. DNS vpnctl за тебя не сделает."))
        }
        form method="post"
             action=(format!("/admin/servers/{sid_enc}/naive-config"))
             style="display: grid; grid-template-columns: 96px 1fr; gap: 6px 8px; align-items: center; max-width: 520px;" {
            label style="font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                (tr(lang, "domain", "домен"))
            }
            input type="text" name="domain" maxlength="253" required
                  value=(domain)
                  placeholder="cdn.example.com"
                  style="padding: 4px 8px; font-family: var(--mono); font-size: 12px; border: 1px solid var(--rule);";
            label style="font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                (tr(lang, "ACME email", "ACME почта"))
            }
            input type="text" name="acme_email" maxlength="254"
                  value=(email)
                  placeholder="admin@example.com"
                  style="padding: 4px 8px; font-family: var(--mono); font-size: 12px; border: 1px solid var(--rule);";
            span {}
            button type="submit"
                   title=(tr(lang, "Save naive domain + ACME email", "Сохранить домен naive + ACME почту"))
                   style="justify-self: start; padding: 4px 12px; border: 1px solid var(--ink); background: var(--ink); color: var(--paper); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                (tr(lang, "save naive config", "сохранить конфиг"))
            }
        }
    }
}

/// vless-ws (Caddy + reverse_proxy) per-server config. The operator sets
/// `vlessws.domain` + `vlessws.acme_email` + `vlessws.listen_port`
/// (server_secrets); the secret ws path (`vlessws.path`) is auto-minted at
/// deploy, so there's no field for it. Rendered ONLY when the `vless-ws`
/// protocol is enabled on this server. Carries the prerequisite reminder
/// vpnctl CANNOT satisfy: a DNS A-record pointing here + open TCP 80 (ACME)
/// and the front port.
fn server_detail_vlessws_config_section(
    server: &vpnctl_core::Server,
    server_secrets: &std::collections::HashMap<String, String>,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    if !server.enabled_protocols.iter().any(|p| p.0 == "vless-ws") {
        return html! {};
    }
    let sid_enc = path_segment_encode(&server.id.0);
    let domain = server_secrets
        .get("vlessws.domain")
        .map(String::as_str)
        .unwrap_or("");
    let email = server_secrets
        .get("vlessws.acme_email")
        .map(String::as_str)
        .unwrap_or("");
    let port = server_secrets
        .get("vlessws.listen_port")
        .map(String::as_str)
        .unwrap_or("");
    // Whether the secret ws path has been minted yet (deploy mints it).
    let path_minted = server_secrets.contains_key("vlessws.path");
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow
            title=(tr(lang,
                "Caddy terminates a real Let's-Encrypt cert on the front port, serves a decoy site at /, and reverse_proxies one secret path to a loopback sing-box VLESS+ws inbound. DIRECT (no CDN) — the RU-DPI-resistant, client-universal fallback that runs alongside REALITY on :443.",
                "Caddy терминирует настоящий сертификат Let's-Encrypt на фронт-порту, отдаёт сайт-приманку на /, и reverse_proxy одного секретного пути на loopback sing-box VLESS+ws. ПРЯМОЙ (без CDN) — устойчивый к RU-DPI, совместимый со всеми клиентами фолбэк рядом с REALITY на :443.")) {
            (tr(lang, "VLESS-WS (CADDY) CONFIG", "КОНФИГ VLESS-WS (CADDY)"))
        }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 10px;" {
            (tr(lang,
                "Before deploy: point a DNS A-record at this server and open TCP 80 (ACME) + the front port. The secret ws path is generated automatically on deploy.",
                "До деплоя: направь DNS A-запись на этот сервер и открой TCP 80 (ACME) + фронт-порт. Секретный ws-путь генерируется автоматически при деплое."))
            @if path_minted {
                (tr(lang, " The path is set.", " Путь задан."))
            } @else {
                (tr(lang, " The path is not minted yet (deploy to generate it).", " Путь ещё не сгенерирован (задеплой, чтобы создать его)."))
            }
        }
        form method="post"
             action=(format!("/admin/servers/{sid_enc}/vlessws-config"))
             style="display: grid; grid-template-columns: 96px 1fr; gap: 6px 8px; align-items: center; max-width: 520px;" {
            label style="font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                (tr(lang, "domain", "домен"))
            }
            input type="text" name="domain" maxlength="253" required
                  value=(domain)
                  placeholder="de.ninitux.top"
                  style="padding: 4px 8px; font-family: var(--mono); font-size: 12px; border: 1px solid var(--rule);";
            label style="font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                (tr(lang, "front port", "фронт-порт"))
            }
            input type="text" name="listen_port" maxlength="5" inputmode="numeric"
                  value=(port)
                  placeholder="8443"
                  title=(tr(lang, "Public TLS port Caddy serves on — NOT 443 (REALITY owns that). Blank = 8443.", "Публичный TLS-порт Caddy — НЕ 443 (его занимает REALITY). Пусто = 8443."))
                  style="padding: 4px 8px; font-family: var(--mono); font-size: 12px; border: 1px solid var(--rule);";
            label style="font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                (tr(lang, "ACME email", "ACME почта"))
            }
            input type="text" name="acme_email" maxlength="254"
                  value=(email)
                  placeholder="admin@example.com"
                  style="padding: 4px 8px; font-family: var(--mono); font-size: 12px; border: 1px solid var(--rule);";
            span {}
            button type="submit"
                   title=(tr(lang, "Save vless-ws domain + front port + ACME email", "Сохранить домен vless-ws + фронт-порт + ACME почту"))
                   style="justify-self: start; padding: 4px 12px; border: 1px solid var(--ink); background: var(--ink); color: var(--paper); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                (tr(lang, "save vless-ws config", "сохранить конфиг"))
            }
        }
    }
}

fn server_detail_display_name_section(
    server: &vpnctl_core::Server,
    current: Option<&str>,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    let sid_enc = path_segment_encode(&server.id.0);
    // What the label resolves to RIGHT NOW (custom → country-map → UPPER),
    // so the operator sees the effective value, not just the override.
    let effective = crate::handlers::vpn_router::server_display_label(&server.id.0, current);
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow
            title=(tr(
                lang,
                "Friendly name end users see in their client's server list — the '{Country}' part of the subscription label (e.g. 'Kyrgyzstan VLESS ~alice'). Blank = fall back to the built-in country map, then the uppercased server id.",
                "Понятное имя, которое пользователь видит в списке серверов клиента — часть '{Country}' в метке подписки (напр. 'Kyrgyzstan VLESS ~alice'). Пусто = фолбэк на встроенную карту стран, затем на server id в верхнем регистре.",
            )) {
            (tr(lang, "DISPLAY NAME", "ОТОБРАЖАЕМОЕ ИМЯ"))
        }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 12px;" {
            (tr(lang, "Subscription label clients see: ", "Метка в подписке, которую видят клиенты: "))
            span.ed-mono { (effective) " VLESS ~<user>" }
            @if current.is_none() {
                (tr(lang, " — auto (no custom name set)", " — авто (своё имя не задано)"))
            }
        }
        form method="post"
             action=(format!("/admin/servers/{sid_enc}/display-name"))
             style="display: flex; gap: 8px; align-items: center;" {
            input type="text" name="display_name" maxlength="64"
                  value=(current.unwrap_or(""))
                  placeholder=(tr(lang, "e.g. Kyrgyzstan  (blank = auto)", "напр. Kyrgyzstan  (пусто = авто)"))
                  style="flex: 1; padding: 4px 8px; font-family: var(--mono); font-size: 12px; border: 1px solid var(--rule);";
            button type="submit"
                   title=(tr(
                       lang,
                       "Save this server's display label. Takes effect on the next subscription pull by each client; cached URIs are unaffected.",
                       "Сохранить отображаемую метку этого сервера. Применится при следующем обновлении подписки у каждого клиента; на кэшированные URI не влияет.",
                   ))
                   style="padding: 4px 12px; border: 1px solid var(--ink); background: var(--ink); color: var(--paper); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                (tr(lang, "save name", "сохранить"))
            }
        }
    }
}

/// Auto-suppress section on the server-detail page (migration 0030).
/// Per-server opt-in to drop this server from the subscription render
/// while it's unreachable: the health monitor sets `suppressed_at` once
/// it crosses the `server.unreachable` threshold (≈30 min of failed
/// probes), and clears it on the first successful probe. Separate from
/// the manual hide (NM-10) so a suppress cycle preserves the operator's
/// per-protocol visibility. Shows the live state + a toggle.
fn server_detail_auto_suppress_section(
    server: &vpnctl_core::Server,
    opt_in: bool,
    suppressed_at: Option<&str>,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    let sid_enc = path_segment_encode(&server.id.0);
    let (btn_bg, btn_fg) = if opt_in {
        ("transparent", "var(--ink)")
    } else {
        ("var(--ink)", "var(--paper)")
    };
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow
            title=(tr(
                lang,
                "When ON, the daemon removes this server from clients' subscriptions after it fails the unreachable threshold (3 consecutive SSH probes ≈ 30 min) and restores it on the first successful probe. OFF (default) = a down server stays in the subscription and clients fall back on their own.",
                "Когда ВКЛ, демон убирает этот сервер из подписок клиентов после порога недоступности (3 неудачные SSH-пробы подряд ≈ 30 мин) и возвращает при первой успешной пробе. ВЫКЛ (по умолчанию) = упавший сервер остаётся в подписке, клиенты фолбэкаются сами.",
            )) {
            (tr(lang, "AUTO-SUPPRESS WHEN DOWN", "АВТО-СКРЫТИЕ ПРИ ПАДЕНИИ"))
        }
        @if let Some(ts) = suppressed_at {
            div style="font-family: var(--mono); font-size: 12px; padding: 8px 12px; background: var(--paper-tint); border: 1px solid var(--acc); color: var(--acc); margin: 8px 0 12px;" {
                (tr(lang, "● currently SUPPRESSED since ", "● сейчас СКРЫТ с ")) (ts)
                (tr(lang, " — hidden from subscriptions; auto-restores on recovery.", " — скрыт из подписок; вернётся автоматически при восстановлении."))
            }
        } @else {
            p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 12px;" {
                @if opt_in {
                    (tr(lang, "Armed — server is currently reachable; will auto-hide if it goes down.", "Взведено — сервер сейчас доступен; авто-скроется если упадёт."))
                } @else {
                    (tr(lang, "Off — a down server stays in the subscription (clients fall back themselves).", "Выкл — упавший сервер остаётся в подписке (клиенты фолбэкаются сами)."))
                }
            }
        }
        form method="post"
             action=(format!("/admin/servers/{sid_enc}/auto-suppress"))
             style="display: inline;" {
            input type="hidden" name="enabled" value=(if opt_in { "false" } else { "true" });
            button type="submit"
                   style=(format!("padding: 4px 12px; border: 1px solid var(--ink); background: {btn_bg}; color: {btn_fg}; font-family: var(--mono); font-size: 11px; cursor: pointer;")) {
                @if opt_in {
                    (tr(lang, "turn off auto-suppress", "выключить авто-скрытие"))
                } @else {
                    (tr(lang, "turn on auto-suppress", "включить авто-скрытие"))
                }
            }
        }
    }
}

/// naive↔HY2 UDP-pairing opt-in on the server-detail page (migration 0031,
/// UX-3). Takes effect only when this server exposes BOTH naive and
/// hysteria2 — the render then stamps both share-links with `pair=<server
/// id>`. Always rendered (discoverable); the copy explains the both-protocols
/// requirement. Single-server only by construction (the tag is the id).
fn server_detail_udp_pair_section(
    server: &vpnctl_core::Server,
    enabled: bool,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    let sid_enc = path_segment_encode(&server.id.0);
    let (btn_bg, btn_fg) = if enabled {
        ("transparent", "var(--ink)")
    } else {
        ("var(--ink)", "var(--paper)")
    };
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow
            title=(tr(
                lang,
                "When ON, this node's naive AND HY2 share-links carry a shared `pair=<server id>` tag, so a client routes UDP — which naive can't carry — over the HY2 co-located on the same node. Effective only if this server has BOTH naive and HY2 enabled. Pairing is single-server only (the tag is this server's id). OFF (default) = no pair tag.",
                "Когда ВКЛ, naive- и HY2-ссылки этого узла получают общий тег `pair=<id сервера>`, чтобы клиент гнал UDP (который naive не умеет) через HY2 на том же узле. Действует только если на сервере включены И naive, И HY2. Пара — строго в рамках одного сервера (тег = id этого сервера). ВЫКЛ (по умолчанию) = без тега pair.",
            )) {
            (tr(lang, "UDP PAIRING (NAIVE ↔ HY2)", "UDP-ПАРА (NAIVE ↔ HY2)"))
        }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 12px;" {
            @if enabled {
                (tr(lang, "On — naive & HY2 on this node share a `pair` tag (a client routes UDP over the co-located HY2). No effect unless both run here.", "Вкл — naive и HY2 этого узла имеют общий тег `pair` (клиент гонит UDP через парный HY2). Без эффекта, если оба не подняты здесь."))
            } @else {
                (tr(lang, "Off — no pairing tag. Turn on for a node that runs BOTH naive and HY2.", "Выкл — без тега pair. Включи для узла, где есть И naive, И HY2."))
            }
        }
        form method="post"
             action=(format!("/admin/servers/{sid_enc}/udp-pair"))
             style="display: inline;" {
            input type="hidden" name="enabled" value=(if enabled { "false" } else { "true" });
            button type="submit"
                   style=(format!("padding: 4px 12px; border: 1px solid var(--ink); background: {btn_bg}; color: {btn_fg}; font-family: var(--mono); font-size: 11px; cursor: pointer;")) {
                @if enabled {
                    (tr(lang, "turn off pairing", "выключить пару"))
                } @else {
                    (tr(lang, "turn on pairing", "включить пару"))
                }
            }
        }
    }
}

/// Reserved-ports section on the server-detail page (migration 0028).
/// Renders ALWAYS (even when the list is empty) so the operator has
/// a discoverable place to add port pins for a newly-detected co-
/// tenant service without having to remember the CLI invocation. The
/// list semantics are: any port here will be REFUSED by the sing-
/// box pre-apply guard, fail-closed.
fn server_detail_reserved_ports_section(
    server: &vpnctl_core::Server,
    reserved: &[u16],
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    let sid_enc = path_segment_encode(&server.id.0);
    let prefill: String = reserved
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(",");
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow
            title=(tr(
                lang,
                "Per-server allowlist of ports the daemon must NEVER bind via sing-box. Use when a co-tenant service (legacy 3x-ui Docker container, separate xray, another VPN stack) owns one of the standard ports — vpnctl deploys are refused fail-closed if any rendered inbound would collide.",
                "Список портов на этом сервере, которые демону ЗАПРЕЩЕНО занимать через sing-box. Используется когда на хосте уже крутится сторонний сервис (legacy 3x-ui Docker, отдельный xray, другой VPN-стек) на стандартном порту — vpnctl deploy отказывается, если какой-то рендеренный inbound попытается их занять, fail-closed.",
            )) {
                (tr(lang, "RESERVED PORTS", "ЗАРЕЗЕРВИРОВАННЫЕ ПОРТЫ"))
            }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
            (tr(
                lang,
                "Ports the daemon refuses to bind on this node. The sing-box pre-apply guard fails closed when any rendered inbound collides — so a co-tenant 3x-ui (or any other service vpnctl doesn't manage) can never get overwritten by a forgetful deploy.",
                "Порты, которые демон отказывается занимать на этой ноде. Пре-apply-guard sing-box падает fail-closed, если любой рендеренный inbound пересечётся — сторонний 3x-ui (или любой другой сервис, которым vpnctl не управляет) никогда не будет перезаписан забывчивым деплоем.",
            ))
        }
        div style="font-family: var(--mono); font-size: 12px; padding: 8px 12px; background: var(--paper-tint); border: 1px solid var(--rule); margin-bottom: 12px;" {
            @if reserved.is_empty() {
                em style="color: var(--mute);" {
                    (tr(
                        lang,
                        "(no ports reserved — deploys are free to use every port the renderer picks)",
                        "(ничего не зарезервировано — деплои свободно используют любые порты, которые выбирает рендерер)",
                    ))
                }
            } @else {
                (tr(lang, "current: ", "сейчас: "))
                @for (i, port) in reserved.iter().enumerate() {
                    @if i > 0 { ", " }
                    b { (port) }
                }
            }
        }
        form method="post"
             action=(format!("/admin/servers/{sid_enc}/reserved-ports"))
             style="display: flex; gap: 8px; align-items: center;" {
            input type="text" name="ports" value=(prefill)
                  placeholder="443,2053,2096"
                  style="flex: 1; padding: 4px 8px; font-family: var(--mono); font-size: 12px; border: 1px solid var(--rule);"
                  pattern="[0-9, ]*"
                  title=(tr(
                      lang,
                      "Comma-separated port numbers (1..=65535). Empty value clears the list.",
                      "Номера портов через запятую (1..=65535). Пустое поле очищает список.",
                  ));
            button type="submit"
                   title=(tr(
                       lang,
                       "Replace the reserved-ports list with the values above. Future sing-box deploys refuse to bind any port in the list.",
                       "Заменить список зарезервированных портов значениями выше. Будущие деплои sing-box откажутся занимать любой порт из списка.",
                   ))
                   style="padding: 6px 14px; border: 1px solid var(--ink); background: var(--ink); color: var(--paper); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                (tr(lang, "save", "сохранить"))
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
/// Both audit-log `server.fingerprint.set` with the pinned value +
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
    // Audit only a REAL pin change (NM-10) under the dot-convention
    // name `server.fingerprint.set` (was `server.set_fingerprint` —
    // the only server.* action with the verb glued to the domain,
    // breaking `server.fingerprint.`-prefix filtering; renamed
    // 2026-06-10, old rows keep the legacy name). A same-value re-pin
    // is a no-op — writing a row made every re-submit look like a
    // TOFU rotation in the timeline.
    if previous.as_deref() != Some(fp.as_str())
        && let Err(e) = state
            .inv
            .audit(
                "admin",
                "server.fingerprint.set",
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
        "/admin/servers/{}/setup",
        path_segment_encode(&server_id)
    ))
    .into_response()
}

/// `POST /admin/servers/{id}/naive-config` — set the naive (Caddy)
/// per-server params `naive.domain` + `naive.acme_email` (server_secrets)
/// the caddy kernel renders into the Caddyfile and Caddy's built-in ACME
/// consumes. Domain is required (the deploy render rejects an empty one).
/// Both fields are fail-closed against whitespace/brace injection — they
/// land verbatim in a Caddyfile, so the same illegal-char set the kernel
/// guards with is enforced here too, returning a clean 400 instead of a
/// node-side `caddy validate` failure. Redirects to the detail page.
pub(crate) async fn server_set_naive_config(
    axum::extract::Path(server_id): axum::extract::Path<String>,
    State(state): State<AppState>,
    body: String,
) -> Response {
    let sid = vpnctl_core::ServerId(server_id.clone());
    match state.inv.get_server(&sid).await {
        Ok(Some(_)) => {}
        Ok(None) => return not_found(&format!("no such server '{server_id}'")),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    }

    let domain_raw = form_field(&body, "domain").unwrap_or_default();
    let domain = domain_raw.trim();
    let email_raw = form_field(&body, "acme_email").unwrap_or_default();
    let email = email_raw.trim();

    // These strings land verbatim in a Caddyfile; reject anything that
    // could break out of its line/block (same guard the caddy kernel
    // applies at render). Fail with a 400 here rather than at node-side
    // `caddy validate`.
    const ILLEGAL: [char; 5] = ['\n', '\r', ' ', '{', '}'];
    if domain.is_empty() {
        return bad_request("vpnctl admin: naive domain is required");
    }
    if domain.chars().count() > 253 || domain.contains(ILLEGAL) {
        return bad_request("vpnctl admin: invalid naive domain");
    }
    if email.chars().count() > 254 || email.contains(ILLEGAL) {
        return bad_request("vpnctl admin: invalid naive ACME email");
    }

    // Two separate upserts (the generic KV setter is per-key). Not one
    // transaction, so a mid-failure could leave domain set but email
    // stale — acceptable here: single operator, the form is idempotent,
    // and re-submitting reconciles both keys.
    if let Err(e) = state
        .inv
        .set_server_secret(&sid, "naive.domain", domain)
        .await
    {
        return internal_error(anyhow::Error::new(e));
    }
    if let Err(e) = state
        .inv
        .set_server_secret(&sid, "naive.acme_email", email)
        .await
    {
        return internal_error(anyhow::Error::new(e));
    }
    // set_server_secret is the generic KV setter (no built-in audit), so
    // emit the audit row here. Best-effort: a failed audit write must not
    // 500 the operator's save (the secrets already persisted).
    let _ = state
        .inv
        .audit(
            "admin",
            "server.naive.set",
            Some(&server_id),
            Some(&serde_json::json!({
                "domain": domain,
                "acme_email_set": !email.is_empty(),
            })),
        )
        .await;

    Redirect::to(&format!(
        "/admin/servers/{}/protocols",
        path_segment_encode(&server_id)
    ))
    .into_response()
}

/// `POST /admin/servers/{id}/vlessws-config` — set the vless-ws (Caddy)
/// per-server params `vlessws.domain` + `vlessws.acme_email` +
/// `vlessws.listen_port` (server_secrets) the caddy kernel renders into the
/// vless-ws bundle + Caddy's built-in ACME consumes. The secret ws path
/// (`vlessws.path`) is NOT set here — it's auto-minted at deploy. Domain is
/// required; all three land in config/URI artefacts, so the same
/// illegal-char guard the kernel applies is enforced here, and `listen_port`
/// (when non-blank) must be a valid non-zero u16. Redirects to the detail.
pub(crate) async fn server_set_vlessws_config(
    axum::extract::Path(server_id): axum::extract::Path<String>,
    State(state): State<AppState>,
    body: String,
) -> Response {
    let sid = vpnctl_core::ServerId(server_id.clone());
    match state.inv.get_server(&sid).await {
        Ok(Some(_)) => {}
        Ok(None) => return not_found(&format!("no such server '{server_id}'")),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    }

    let domain_raw = form_field(&body, "domain").unwrap_or_default();
    let domain = domain_raw.trim();
    let email_raw = form_field(&body, "acme_email").unwrap_or_default();
    let email = email_raw.trim();
    let port_raw = form_field(&body, "listen_port").unwrap_or_default();
    let port = port_raw.trim();

    // These land verbatim in a Caddyfile / vless:// URI; reject anything
    // that could break out of its line/block (same guard the caddy kernel +
    // the vless_ws protocol apply at render). Fail 400 here rather than at
    // node-side `caddy validate`.
    const ILLEGAL: [char; 5] = ['\n', '\r', ' ', '{', '}'];
    if domain.is_empty() {
        return bad_request("vpnctl admin: vless-ws domain is required");
    }
    if domain.chars().count() > 253 || domain.contains(ILLEGAL) {
        return bad_request("vpnctl admin: invalid vless-ws domain");
    }
    if email.chars().count() > 254 || email.contains(ILLEGAL) {
        return bad_request("vpnctl admin: invalid vless-ws ACME email");
    }
    // Front port: optional (blank → kernel default 8443). When set it must
    // be a valid non-zero u16, else the kernel silently falls back and the
    // operator's typo is hidden.
    if !port.is_empty() && !matches!(port.parse::<u16>(), Ok(p) if p != 0) {
        return bad_request("vpnctl admin: invalid vless-ws front port (1..=65535)");
    }

    // Three per-key upserts (the generic KV setter is per-key). Same
    // non-transactional, idempotent-form caveat as the naive handler.
    for (key, val) in [
        ("vlessws.domain", domain),
        ("vlessws.acme_email", email),
        ("vlessws.listen_port", port),
    ] {
        if let Err(e) = state.inv.set_server_secret(&sid, key, val).await {
            return internal_error(anyhow::Error::new(e));
        }
    }
    // set_server_secret has no built-in audit, so emit the row here.
    // Best-effort: a failed audit must not 500 the save.
    let _ = state
        .inv
        .audit(
            "admin",
            "server.vlessws.set",
            Some(&server_id),
            Some(&serde_json::json!({
                "domain": domain,
                "acme_email_set": !email.is_empty(),
                "listen_port": port,
            })),
        )
        .await;

    Redirect::to(&format!(
        "/admin/servers/{}/protocols",
        path_segment_encode(&server_id)
    ))
    .into_response()
}

/// `POST /admin/servers/{id}/display-name` — set (or clear) the
/// operator-friendly subscription label (migration 0029). Form field
/// `display_name`; blank/whitespace clears the override (render falls
/// back to the ISO-code→country map, then the uppercased id). The audit
/// row (`server.display_name.set`, on actual change only) is written
/// inside the inventory transaction, so this handler doesn't double-
/// audit. Redirects to the detail page so the new label is visible.
pub(crate) async fn server_set_display_name(
    axum::extract::Path(server_id): axum::extract::Path<String>,
    State(state): State<AppState>,
    body: String,
) -> Response {
    let sid = vpnctl_core::ServerId(server_id.clone());
    // Clean 404 if the server doesn't exist (set_server_display_name
    // would reject with Invalid → 500; prefer an explicit not_found).
    match state.inv.get_server(&sid).await {
        Ok(Some(_)) => {}
        Ok(None) => return not_found(&format!("no such server '{server_id}'")),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    }

    let name = form_field(&body, "display_name").unwrap_or_default();
    // Sanity bound for a mobile client's server-list row. The inventory
    // layer trims + treats blank as a clear, so no further parsing here.
    if name.chars().count() > 64 {
        return bad_request("vpnctl admin: display name too long (max 64 characters)");
    }

    if let Err(e) = state.inv.set_server_display_name(&sid, Some(&name)).await {
        return internal_error(anyhow::Error::new(e));
    }

    Redirect::to(&format!(
        "/admin/servers/{}/setup",
        path_segment_encode(&server_id)
    ))
    .into_response()
}

/// `POST /admin/servers/{id}/auto-suppress` — toggle the per-server
/// opt-in (migration 0030) to auto-hide the server from subscriptions
/// while it's unreachable. Form field `enabled` = "true"/"false".
/// Turning it OFF also lifts any active suppression (handled in the
/// inventory layer). Audited (`server.auto_suppress.set`); redirects to
/// the detail page.
pub(crate) async fn server_set_auto_suppress(
    axum::extract::Path(server_id): axum::extract::Path<String>,
    State(state): State<AppState>,
    body: String,
) -> Response {
    let sid = vpnctl_core::ServerId(server_id.clone());
    match state.inv.get_server(&sid).await {
        Ok(Some(_)) => {}
        Ok(None) => return not_found(&format!("no such server '{server_id}'")),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    }
    let enabled = form_field(&body, "enabled").as_deref() == Some("true");
    if let Err(e) = state.inv.set_server_auto_suppress(&sid, enabled).await {
        return internal_error(anyhow::Error::new(e));
    }
    Redirect::to(&format!(
        "/admin/servers/{}/setup",
        path_segment_encode(&server_id)
    ))
    .into_response()
}

/// `POST /admin/servers/{id}/udp-pair` — toggle the per-server naive↔HY2
/// UDP-pairing opt-in (migration 0031, UX-3). Form field `enabled` =
/// "true"/"false". Audited (`server.udp_pair.set`); redirects to the detail
/// page.
pub(crate) async fn server_set_udp_pair(
    axum::extract::Path(server_id): axum::extract::Path<String>,
    State(state): State<AppState>,
    body: String,
) -> Response {
    let sid = vpnctl_core::ServerId(server_id.clone());
    match state.inv.get_server(&sid).await {
        Ok(Some(_)) => {}
        Ok(None) => return not_found(&format!("no such server '{server_id}'")),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    }
    let enabled = form_field(&body, "enabled").as_deref() == Some("true");
    if let Err(e) = state.inv.set_server_udp_pair_enabled(&sid, enabled).await {
        return internal_error(anyhow::Error::new(e));
    }
    Redirect::to(&format!(
        "/admin/servers/{}/protocols",
        path_segment_encode(&server_id)
    ))
    .into_response()
}

/// `POST /admin/servers/{id}/reserved-ports` — set the per-server
/// reserved-ports list (migration 0028). Form field `ports` is a
/// comma-separated u16 list; empty string clears. Mirrors the CLI
/// `vpnctl server set-reserved-ports` semantics one-for-one.
///
/// Per the operator-action policy in CLAUDE.md, every CLI command
/// needs a web equivalent — this handler is that equivalent for
/// the reservation contract added in commit 0028.
pub(crate) async fn server_set_reserved_ports(
    axum::extract::Path(server_id): axum::extract::Path<String>,
    State(state): State<AppState>,
    body: String,
) -> Response {
    let sid = vpnctl_core::ServerId(server_id.clone());
    // 3-arm match (audit 2026-06-10): the old `if let Ok(None)` SWALLOWED
    // the DB-error arm and fell through as if the server existed.
    match state.inv.get_server(&sid).await {
        Ok(Some(_)) => {}
        Ok(None) => return not_found(&format!("no such server '{server_id}'")),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    }

    let raw = form_field(&body, "ports").unwrap_or_default();
    let trimmed = raw.trim();
    let parsed: Vec<u16> = if trimmed.is_empty() {
        Vec::new()
    } else {
        let mut acc: Vec<u16> = Vec::new();
        for tok in trimmed.split(',') {
            let t = tok.trim();
            if t.is_empty() {
                continue;
            }
            match t.parse::<u16>() {
                Ok(0) => {
                    return bad_request("port 0 is not valid; allowed range 1..=65535");
                }
                Ok(p) => acc.push(p),
                Err(_) => {
                    return bad_request(&format!(
                        "invalid port '{t}'; expected comma-separated u16 (e.g. \
                         443,2053,2096) or empty to clear"
                    ));
                }
            }
        }
        acc.sort_unstable();
        acc.dedup();
        acc
    };

    if let Err(e) = state.inv.set_reserved_ports(&sid, &parsed).await {
        return internal_error(anyhow::Error::new(e));
    }

    Redirect::to(&format!(
        "/admin/servers/{}/protocols",
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
        // `/admin/servers/{id}/protocols#enabled-protocols`. The browser
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

// ════════════════════════════════════════════════════════════════════
//  PR-Server — informativeness cards for the server-detail page.
//
//  All seven cards reuse existing helpers (status_tile, sparkline_svg,
//  window_picker_section, humanize_bytes, summarize_audit_payload,
//  action_kind, .ed-time, kernel_floor_rollup) — no parallel styling.
//  Bilingual via tr() / t(). The only card that does I/O is server#1
//  (live SSH read, gated behind ?drift=live, best-effort, never 500).
// ════════════════════════════════════════════════════════════════════

/// One resolved orphan UUID for the server#1 drift-detail card: a
/// UUID the node serves that no granted user accounts for. `name`
/// is `Some(user_id)` when the orphan UUID DOES map to a known user
/// (e.g. a user whose grant was revoked but whose UUID still lives in
/// the node config) and `None` when it maps to nothing in inventory
/// (a likely service account / hand-added UUID).
#[derive(Debug, Clone, PartialEq, Eq)]
struct OrphanUuid {
    uuid: String,
    /// Resolved inventory user id, if the UUID matches a known user.
    name: Option<String>,
}

/// Outcome of a `?drift=live` attempt. `Ok` carries the diff; `Err`
/// carries a short, policy-safe reason string the card renders into
/// its empty-state. The reason NEVER says «ssh to the box» — it says
/// the config couldn't be read (node unreachable or deploy key).
#[derive(Debug, Clone)]
enum DriftLiveResult {
    /// Live read + parse succeeded — `orphans` are on-node UUIDs not
    /// in inventory (resolved to a user name where possible).
    Ok { orphans: Vec<OrphanUuid> },
    /// Live read failed (timeout, node down, key not authorised, parse
    /// error). The card degrades to a policy-safe empty-state.
    Unavailable,
}

/// Pure diff for server#1 — given the set of UUIDs the NODE serves and
/// the inventory `users` (whose `.uuid` already resolves
/// COALESCE(client_uuid, users.uuid)), return the orphans: UUIDs on the
/// node that are NOT in the inventory grant set. Each orphan is
/// resolved to a user id when the UUID matches a known global user
/// uuid (revoked-but-still-on-node case), else left unresolved.
///
/// Extracted as a free function so the test suite can pin the
/// orphan-detection semantics directly without standing up SSH.
fn compute_orphan_uuids(
    node_uuids: &std::collections::BTreeSet<String>,
    granted_users: &[vpnctl_core::User],
    all_users: &[vpnctl_core::User],
) -> Vec<OrphanUuid> {
    // Inventory UUID set for THIS server = the resolved uuid of every
    // granted user. A node UUID present here is accounted-for.
    let inventory_uuids: std::collections::BTreeSet<&str> =
        granted_users.iter().map(|u| u.uuid.as_str()).collect();
    // Reverse map from any KNOWN user's global uuid → user id, so an
    // orphan can still be named if it belongs to a user who simply
    // lost their grant (the dangerous revoke case the operator most
    // wants to see).
    let uuid_to_user: std::collections::HashMap<&str, &str> = all_users
        .iter()
        .map(|u| (u.uuid.as_str(), u.id.0.as_str()))
        .collect();

    node_uuids
        .iter()
        .filter(|u| !inventory_uuids.contains(u.as_str()))
        .map(|u| OrphanUuid {
            uuid: u.clone(),
            name: uuid_to_user.get(u.as_str()).map(|s| s.to_string()),
        })
        .collect()
}

/// server#1 — best-effort LIVE read of the node's sing-box config over
/// SSH, with a hard ≤6s timeout. EVERY failure mode (transport error,
/// node down, key not authorised, non-UTF-8, parse error, or the
/// outer tokio timeout) collapses to `DriftLiveResult::Unavailable` so
/// the caller can render a policy-safe empty-state — this function
/// NEVER returns an error and NEVER panics.
///
/// `granted_users` is `users_for_server(sid)` (the inventory set for
/// the diff — a node UUID present here is accounted-for). `all_users`
/// is the full inventory user list (already loaded by the handler) so
/// a revoked-but-on-node orphan can still be NAMED instead of showing
/// as «unresolved».
async fn load_drift_live(
    server: &vpnctl_core::Server,
    granted_users: &[vpnctl_core::User],
    all_users: &[vpnctl_core::User],
) -> DriftLiveResult {
    use crate::ssh_subprocess::SubprocessSshTransport;
    use vpnctl_core::SshTransport;

    let key_path = std::path::PathBuf::from(crate::app::DEFAULT_DEPLOY_KEY_PATH);
    let transport = SubprocessSshTransport::new(
        server.address.clone(),
        server.ssh_user.clone(),
        key_path,
    )
    .port(server.ssh_port)
    // Hard wall-clock cap — keep the armed path snappy even when the
    // node is black-holed (the transport already sets ConnectTimeout=10
    // + ServerAlive keepalives, but we want ≤6s end-to-end here).
    .timeout(std::time::Duration::from_secs(6));

    // Outer guard belt-and-suspenders against a wedged child the
    // transport's own timeout somehow misses — 7s leaves a 1s margin.
    let read = tokio::time::timeout(
        std::time::Duration::from_secs(7),
        transport.read_file("/etc/sing-box/config.json"),
    )
    .await;

    let bytes = match read {
        Ok(Ok(b)) => b,
        Ok(Err(e)) => {
            tracing::info!(
                target = "vpnctld::admin",
                server = %server.id,
                error = %e,
                "drift=live: live config read failed (best-effort)"
            );
            return DriftLiveResult::Unavailable;
        }
        Err(_elapsed) => {
            tracing::info!(
                target = "vpnctld::admin",
                server = %server.id,
                "drift=live: live config read timed out (best-effort)"
            );
            return DriftLiveResult::Unavailable;
        }
    };

    // Parse the on-node UUIDs (pub helper; parse failure → empty set,
    // which we treat as «no on-node users observed» rather than orphan
    // noise). The diff is against the granted set; naming uses the full
    // user list so a revoked user's lingering UUID is still labelled.
    let node_uuids = vpnctl_kernels::live_config_user_uuids(&bytes);
    let orphans = compute_orphan_uuids(&node_uuids, granted_users, all_users);
    DriftLiveResult::Ok { orphans }
}

/// server#1 — drift-detail card. Two modes:
///
/// * `armed == false` (default page load): renders a «[check live
///   drift →]» link anchored to `?drift=live`. NO SSH happened.
/// * `armed == true` (`?drift=live`): renders the orphan list from the
///   best-effort live read, or a policy-safe empty-state on any
///   failure. The empty-state copy NEVER instructs the operator to
///   «ssh to the box» — per operator-action-policy it says the config
///   couldn't be read (node unreachable or deploy key).
fn server_detail_drift_detail_section(
    server: &vpnctl_core::Server,
    drift_live: Option<&DriftLiveResult>,
    armed: bool,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::{K, t, tr};
    let sid_enc = path_segment_encode(&server.id.0);
    html! {
        section id="drift-detail" style="margin-top: 28px;" {
            div.ed-art-eyebrow { (t(lang, K::EyebrowDriftDetail)) }
            p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 12px;" {
                (tr(
                    lang,
                    "The port-level drift above compares declared protocols to listening sockets. This card goes deeper — it reads the node's live sing-box config and lists UUIDs the node still serves that no granted user accounts for (a revoked user whose UUID lingers, or a service account). It's a live SSH read, so it runs only on demand.",
                    "Дрейф по портам выше сравнивает заявленные протоколы со слушающими сокетами. Эта карточка копает глубже — читает живой конфиг sing-box на ноде и показывает UUID, которые нода всё ещё обслуживает, но за которыми не стоит ни один выданный доступ (отозванный юзер, чей UUID завис, или сервисный аккаунт). Это живое SSH-чтение, поэтому запускается только по запросу.",
                ))
            }
            @if !armed {
                // Default fast path — link to arm the live read. No SSH
                // was attempted on this render.
                p style="font-family: var(--mono); font-size: 12px; margin: 8px 0;" {
                    a href=(format!("/admin/servers/{sid_enc}/protocols?drift=live#drift-detail"))
                      style="color: var(--ink); border-bottom: 1px dotted var(--ink); text-decoration: none;" {
                        (tr(lang, "check live drift →", "проверить живой дрейф →"))
                    }
                }
                p style="font-family: var(--serif); font-style: italic; font-size: 11px; color: var(--mute); margin: 4px 0 0;" {
                    (tr(
                        lang,
                        "Skipped by default so the page loads fast — no node is contacted until you click.",
                        "По умолчанию пропускается ради быстрой загрузки — пока не нажмёшь, нода не опрашивается.",
                    ))
                }
            } @else {
                @match drift_live {
                    Some(DriftLiveResult::Ok { orphans }) if !orphans.is_empty() => {
                        div style="margin-top: 6px; padding: 10px 12px; border: 1px solid var(--acc); background: var(--paper);" {
                            div style="font-family: var(--mono); font-size: 10px; color: var(--acc); letter-spacing: 0.14em; text-transform: uppercase; margin-bottom: 6px;" {
                                (tr(lang, "orphan uuids on node", "осиротевшие uuid на ноде"))
                            }
                            ul style="list-style: none; padding: 0; font-family: var(--mono); font-size: 12px; line-height: 1.7;" {
                                @for o in orphans {
                                    li style="padding: 2px 0; border-bottom: 1px dotted var(--rule);" {
                                        span.ed-mono { (o.uuid) }
                                        " — "
                                        @match &o.name {
                                            Some(name) => {
                                                span style="color: var(--ink); font-style: italic; font-family: var(--serif);" {
                                                    (tr(lang, "maps to user ", "соответствует юзеру "))
                                                }
                                                a href=(format!("/admin/users/{}", path_segment_encode(name)))
                                                  style="color: var(--ink); border-bottom: 1px dotted var(--ink); text-decoration: none;" {
                                                    (name)
                                                }
                                            }
                                            None => {
                                                span style="color: var(--mute); font-style: italic; font-family: var(--serif);" {
                                                    (tr(lang, "(unresolved — likely service account)", "(не определён — вероятно сервисный аккаунт)"))
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            p style="font-family: var(--serif); font-style: italic; font-size: 11px; color: var(--mute); margin: 8px 0 0;" {
                                (tr(
                                    lang,
                                    "A redeploy re-renders the config from inventory and removes any UUID inventory doesn't expect.",
                                    "Redeploy перерендерит конфиг из инвентаря и уберёт любой UUID, которого инвентарь не ждёт.",
                                ))
                            }
                        }
                    }
                    Some(DriftLiveResult::Ok { .. }) => {
                        // Read succeeded, no orphans — clean state.
                        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--soft); margin-top: 6px;" {
                            (tr(
                                lang,
                                "Live config read OK — every UUID the node serves maps to a granted user. No orphans.",
                                "Живой конфиг прочитан — каждый UUID на ноде соответствует выданному доступу. Сирот нет.",
                            ))
                        }
                    }
                    _ => {
                        // Unavailable / None — policy-safe empty-state.
                        // NO «ssh to the box» instruction.
                        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin-top: 6px;" {
                            (tr(
                                lang,
                                "Couldn't read the live config (node unreachable or deploy key not authorised on it). Nothing was changed; try again after the node is back, or run a deploy which re-pushes the config anyway.",
                                "Не удалось прочитать живой конфиг (нода недоступна или deploy-ключ на ней не авторизован). Ничего не менялось; попробуй снова когда нода вернётся, либо запусти deploy — он всё равно перезальёт конфиг.",
                            ))
                        }
                    }
                }
            }
        }
    }
}

/// server#3 — top users by 24h traffic on THIS server. Reuses
/// humanize_bytes + links each user to /admin/users/{id}. Carries the
/// NM-11 empty-state (prod per-user attribution is NULL upstream —
/// clash-api drops the user field), so an empty `rows` renders an
/// explainer instead of a blank card.
fn server_detail_top_users_section(
    rows: &[(vpnctl_core::UserId, u64)],
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    html! {
        section id="top-users" style="margin-top: 28px;" {
            div.ed-art-eyebrow { (tr(lang, "Top users · last 24h", "Топ пользователей · за 24ч")) }
            @if rows.is_empty() {
                p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 0;" {
                    (tr(
                        lang,
                        "No per-user traffic attributed on this server yet. Per-user attribution is NULL upstream — clash-api drops the user field (NM-11); see the dashboard note. Server-wide totals still work in the traffic chart below.",
                        "Трафик по пользователям на этом сервере пока не атрибутирован. Атрибуция per-user пустая на уровне upstream — clash-api убирает поле user (NM-11); см. заметку на дашборде. Серверные итоги всё равно работают в графике трафика ниже.",
                    ))
                }
            } @else {
                table style="width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 11.5px; margin-top: 8px;" {
                    thead {
                        tr style="border-bottom: 1px solid var(--ink);" {
                            th style="text-align: left; padding: 5px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                                (tr(lang, "user", "пользователь"))
                            }
                            th style="text-align: right; padding: 5px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                                (tr(lang, "traffic (up+down)", "трафик (вверх+вниз)"))
                            }
                        }
                    }
                    tbody {
                        @for (uid, bytes) in rows {
                            tr style="border-bottom: 1px dotted var(--rule);" {
                                td style="padding: 5px 8px;" {
                                    a href=(format!("/admin/users/{}", path_segment_encode(&uid.0)))
                                      style="color: var(--ink); border-bottom: 1px dotted var(--ink); text-decoration: none;" {
                                        (uid.0)
                                    }
                                }
                                td style="padding: 5px 8px; text-align: right; color: var(--ink);" {
                                    (humanize_bytes(*bytes))
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// server#4 — per-server traffic sparkline (24h / 7d / 30d / all).
/// Reuses sparkline_svg + a window_picker_section scoped to
/// /admin/servers/{id}. The rows are server-wide
/// (recent_vpn_stats_for_server); we bucket them into the window's
/// cells and feed the per-cell up+down totals to the sparkline. The
/// ↑↓ summary tiles show the window totals.
fn server_detail_traffic_section(
    rows: &[vpnctl_inventory::VpnStatsRow],
    window: VpnSparklineWindow,
    server_id: &vpnctl_core::ServerId,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    // This section lives on the `activity` tab — the `?vpn_window=`
    // switcher links must keep the operator there, not bounce to status.
    let base_url = format!(
        "/admin/servers/{}/activity",
        path_segment_encode(&server_id.0)
    );
    let window_label = match lang {
        crate::i18n::Locale::En => window.label_en,
        crate::i18n::Locale::Ru => window.label_ru,
    };

    // Window totals for the ↑↓ tiles.
    let mut total_up: u64 = 0;
    let mut total_dn: u64 = 0;
    for r in rows {
        total_up = total_up.saturating_add(r.upload_bytes);
        total_dn = total_dn.saturating_add(r.download_bytes);
    }

    // Bucket into the window's cells (newest cell rightmost). Each row
    // carries a ts; index = how many bucket-widths back from now. Out-
    // of-range rows are clamped into the oldest cell.
    let now = chrono::Utc::now();
    let bucket_secs = i64::from(window.bucket_hours) * 3600;
    let cells = window.cells as usize;
    let mut series: Vec<f64> = vec![0.0; cells];
    // Guard against a degenerate window (cells == 0): `cells - 1` would
    // underflow a usize and the indexed write would panic. Every window
    // in VPN_SPARKLINE_WINDOWS has cells > 0 today, but this keeps the
    // card best-effort if that ever changes.
    if bucket_secs > 0 && cells > 0 {
        for r in rows {
            let age_secs = (now - r.ts).num_seconds().max(0);
            let back = (age_secs / bucket_secs) as usize;
            // back==0 → newest cell (last index); clamp old rows into
            // the oldest cell (index 0).
            let idx = (cells - 1).saturating_sub(back.min(cells - 1));
            let bytes = r.upload_bytes.saturating_add(r.download_bytes);
            series[idx] += bytes as f64;
        }
    }
    let has_data = series.iter().any(|v| *v > 0.0);

    html! {
        section id="server-traffic" style="margin-top: 28px;" {
            div.ed-art-eyebrow {
                (tr(lang, "Server traffic · ", "Трафик сервера · ")) (window_label)
            }
            p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 4px;" {
                (tr(
                    lang,
                    "Server-wide upload+download from clash-api 5-min ticks, bucketed across the window. Pick a window below — the sparkline + totals update together.",
                    "Серверный upload+download с 5-минутных тиков clash-api, разложенный по окну. Выбери окно ниже — спарклайн и итоги обновятся вместе.",
                ))
            }
            (window_picker_section(&base_url, window.slug, lang))
            div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px; margin: 12px 0 6px;" {
                (status_tile(tr(lang, "↑ upload", "↑ отдано"), &humanize_bytes(total_up), "var(--ink)"))
                (status_tile(tr(lang, "↓ download", "↓ принято"), &humanize_bytes(total_dn), "var(--ink)"))
            }
            @if has_data {
                (sparkline_svg(&series, 720, 90))
            } @else {
                p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 8px 0 0;" {
                    (tr(
                        lang,
                        "No traffic recorded in this window yet. The clash-api poller fills this once the node reports samples.",
                        "В этом окне трафик ещё не записан. Поллер clash-api наполнит график как только нода начнёт отдавать сэмплы.",
                    ))
                }
            }
        }
    }
}

/// server#5 — TCP/UDP split from the live clash-api snapshot. Reuses
/// status_tile + humanize_bytes + the shared `network_breakdown`. The
/// caption is explicit that clash-api carries no per-protocol tag,
/// only the network kind — this card is re-scoped from the original
/// «per-protocol» idea for exactly that reason. Cheap (no DB).
fn server_detail_network_split_section(
    server_snap: Option<&crate::snapshot_cache::ServerSnapshot>,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    use crate::snapshot_cache::network_breakdown;
    html! {
        section id="network-split" style="margin-top: 28px;" {
            div.ed-art-eyebrow { (tr(lang, "TCP / UDP split", "Разбивка TCP / UDP")) }
            p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 12px;" {
                (tr(
                    lang,
                    "From the latest clash-api snapshot. clash-api carries no per-protocol tag, only network — so this splits by transport (TCP vs UDP), not by VLESS/TUIC/etc.",
                    "Из последнего снимка clash-api. clash-api не несёт тег протокола, только network — поэтому разбивка по транспорту (TCP против UDP), а не по VLESS/TUIC/и т.п.",
                ))
            }
            @match server_snap {
                Some(snap) => {
                    @let nb = network_breakdown(&snap.snapshot);
                    div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px;" {
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
                }
                None => {
                    p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute);" {
                        (tr(
                            lang,
                            "No clash-api snapshot for this server yet. The poller fires every 5 minutes; refresh after the next tick.",
                            "Снимка clash-api по этому серверу ещё нет. Поллер запускается каждые 5 минут; обнови после следующего тика.",
                        ))
                    }
                }
            }
        }
    }
}

/// server#7 — server-scoped audit timeline (last 20). Reuses
/// `summarize_audit_payload` + `action_kind` + the `.ed-time` editorial
/// component — byte-identical row shape to the dashboard + global audit
/// timeline, just filtered to rows that reference THIS server.
fn server_detail_audit_section(
    rows: &[vpnctl_inventory::AuditEntry],
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    html! {
        section id="server-audit" style="margin-top: 28px;" {
            div.ed-art-eyebrow { (tr(lang, "Audit timeline · this server", "Лента аудита · этот сервер")) }
            @if rows.is_empty() {
                p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 0;" {
                    (tr(
                        lang,
                        "No audit rows reference this server yet — deploy / grant / revoke actions will start filling this stream.",
                        "Записей аудита по этому серверу пока нет — действия deploy / выдать / отозвать начнут наполнять эту ленту.",
                    ))
                }
            } @else {
                div.ed-time {
                    @for e in rows {
                        div.ed-time-row {
                            span.ed-time-row__t { (format_msk_iso(e.ts)) }
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
                    }
                }
            }
        }
    }
}

/// STATUS-tab drift glance (ui-audit §4): the declared-vs-observed
/// verdict + drift counts, linking to the full grid + observed-socket
/// list on the protocols tab. The list itself (100+ rows on wgturn/xray
/// nodes) stays off the status wall — that's the whole point of the tab
/// split. Counts come from the same `missing`/`extra` the full section
/// uses, so the two can never disagree.
fn server_detail_drift_summary(
    missing: &[(String, u16)],
    extra: &[(String, u16)],
    have_probe: bool,
    base: &str,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    html! {
        div.ed-rule {}
        div id="drift-summary" style="margin: 14px 0; font-family: var(--serif); font-size: 13px;" {
            @if !have_probe {
                span style="color: var(--mute); font-style: italic;" {
                    (tr(
                        lang,
                        "Drift — no probe yet (poller runs every 10 min; sing-box nodes only).",
                        "Дрейф — probe ещё нет (поллер ходит раз в 10 минут; только sing-box ноды).",
                    ))
                }
            } @else if missing.is_empty() && extra.is_empty() {
                span style="color: var(--soft);" {
                    (tr(
                        lang,
                        "✓ Declared and observed match. No drift.",
                        "✓ Заявленное и наблюдаемое совпадают. Дрейфа нет.",
                    ))
                }
            } @else {
                span style="color: var(--acc);" {
                    "⚠ " (tr(lang, "drift — ", "дрейф — "))
                    (missing.len()) " " (tr(lang, "declared-but-silent", "заявлено-но-молчит"))
                    " · "
                    (extra.len()) " " (tr(lang, "listening-but-undeclared", "слушает-но-не-заявлено"))
                }
                " "
                a href=(format!("{base}/protocols#drift-detail"))
                  style="color: var(--ink); border-bottom: 1px dotted var(--ink); text-decoration: none;" {
                    (tr(lang, "full grid on protocols tab →", "полная таблица на вкладке протоколы →"))
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
                        (tr(lang, "(no probe yet — poller runs every 10 min; sing-box nodes only)", "(probe ещё нет — поллер ходит раз в 10 минут; только sing-box ноды)"))
                    }
                } @else if observed.is_empty() {
                    p style="font-family: var(--serif); font-style: italic; color: var(--mute);" {
                        (tr(lang, "(probe ran but no sockets listed)", "(probe прошёл, но сокетов не нашлось)"))
                    }
                } @else {
                    // ponytail: 4 CSS columns — an amneziawg/wgturn/xray node
                    // opens 100+ per-peer sockets; one <li>-per-line was ~4.5k px
                    // of pure scroll. `columns: 4` (not 8 — too narrow for the
                    // ~590px grid cell, would wrap `hysteria2/8444`) cuts it ~4×.
                    ul style="list-style: none; padding: 0; margin: 0; font-family: var(--mono); font-size: 12px; columns: 4; column-gap: 16px;" {
                        @for (proto, port) in observed {
                            li style="padding: 2px 0; break-inside: avoid;" { (proto) "/" (port) }
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
            "/admin/servers/{}/protocols#enabled-protocols",
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
            "/admin/servers/{}/protocols#enabled-protocols",
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
            "/admin/users/{}/access#server-access",
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
            "/admin/users/{}/access#server-access",
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
    fn dashboard_heavy_users_renders_three_columns_upload_download_total() {
        // 2026-06-16 — the tile must show upload / download / total as
        // three separate aligned columns (was a single "— total" suffix).
        let window = VpnSparklineWindow {
            slug: "24h",
            label_en: "24h",
            label_ru: "24ч",
            cells: 24,
            bucket_hours: 1,
            per_bucket_en: "per hour",
            per_bucket_ru: "в час",
        };
        let rows = vec![vpnctl_inventory::HeavyUser {
            user_id: vpnctl_core::UserId("alice".into()),
            upload_bytes: 1_500_000_000,
            download_bytes: 3_000_000_000,
            total_bytes: 4_500_000_000,
        }];
        let html = dashboard_heavy_users(&rows, window, crate::i18n::Locale::En).into_string();
        // Three distinct column headers.
        assert!(html.contains("Upload"), "missing Upload header: {html}");
        assert!(html.contains("Download"), "missing Download header");
        assert!(html.contains("Total"), "missing Total header");
        // All three figures rendered (distinct humanized values).
        assert!(
            html.contains(&humanize_bytes(1_500_000_000)),
            "missing upload value"
        );
        assert!(
            html.contains(&humanize_bytes(3_000_000_000)),
            "missing download value"
        );
        assert!(
            html.contains(&humanize_bytes(4_500_000_000)),
            "missing total value"
        );
        // User still links through to the detail page.
        assert!(html.contains("/admin/users/alice"), "missing user link");
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
    fn classify_reserved_ip_labels_private_and_special_ranges() {
        // RFC1918 private.
        assert_eq!(classify_reserved_ip("192.168.0.207"), Some("private/LAN"));
        assert_eq!(classify_reserved_ip("10.1.2.3"), Some("private/LAN"));
        assert_eq!(classify_reserved_ip("172.16.5.5"), Some("private/LAN"));
        // Loopback.
        assert_eq!(classify_reserved_ip("127.0.0.1"), Some("loopback"));
        assert_eq!(classify_reserved_ip("::1"), Some("loopback"));
        // RFC6598 carrier-grade NAT (100.64/10) — the 100.120.2.214
        // case from the real main-brat origins table.
        assert_eq!(classify_reserved_ip("100.64.0.1"), Some("CGNAT"));
        assert_eq!(classify_reserved_ip("100.120.2.214"), Some("CGNAT"));
        assert_eq!(classify_reserved_ip("100.127.255.255"), Some("CGNAT"));
        // 100.128.x is OUTSIDE 100.64/10 → public, not CGNAT.
        assert_eq!(classify_reserved_ip("100.128.0.1"), None);
        // Link-local.
        assert_eq!(classify_reserved_ip("169.254.1.1"), Some("link-local"));
        assert_eq!(classify_reserved_ip("fe80::1"), Some("link-local"));
        // IPv6 ULA.
        assert_eq!(classify_reserved_ip("fc00::1"), Some("private/ULA"));
        assert_eq!(classify_reserved_ip("fd12:3456::1"), Some("private/ULA"));
    }

    #[test]
    fn classify_reserved_ip_returns_none_for_public_and_garbage() {
        // Ordinary routable public IPs → None (genuine "(unknown)"
        // when GeoIP has no record).
        assert_eq!(classify_reserved_ip("8.8.8.8"), None);
        assert_eq!(classify_reserved_ip("83.97.108.34"), None);
        assert_eq!(classify_reserved_ip("2606:4700:4700::1111"), None);
        // Unparseable strings must never panic — just None.
        assert_eq!(classify_reserved_ip(""), None);
        assert_eq!(classify_reserved_ip("not-an-ip"), None);
        assert_eq!(classify_reserved_ip("999.999.999.999"), None);
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

    // ── server#1 (PR-Server) drift-detail orphan diff ───────────────
    fn user(id: &str, uuid: &str) -> vpnctl_core::User {
        vpnctl_core::User {
            id: vpnctl_core::UserId(id.into()),
            uuid: uuid.into(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: false,
        }
    }

    fn uuid_set(uuids: &[&str]) -> std::collections::BTreeSet<String> {
        uuids.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn compute_orphan_uuids_flags_on_node_uuid_absent_from_inventory() {
        // Node serves alice's + a stray UUID; inventory grants only
        // alice. The stray is the orphan; alice is accounted-for.
        let alice = user("alice", "uuid-alice");
        let granted = vec![alice.clone()];
        let all = vec![alice];
        let node = uuid_set(&["uuid-alice", "uuid-stray"]);
        let orphans = compute_orphan_uuids(&node, &granted, &all);
        assert_eq!(orphans.len(), 1, "exactly one orphan expected");
        assert_eq!(orphans[0].uuid, "uuid-stray");
        assert_eq!(
            orphans[0].name, None,
            "a UUID in no known user must be unresolved"
        );
    }

    #[test]
    fn compute_orphan_uuids_names_a_revoked_user_still_on_node() {
        // bob lost his grant (not in `granted`) but is still a known
        // user AND his UUID lingers on the node → orphan, NAMED bob.
        let alice = user("alice", "uuid-alice");
        let bob = user("bob", "uuid-bob");
        let granted = vec![alice.clone()];
        let all = vec![alice, bob];
        let node = uuid_set(&["uuid-alice", "uuid-bob"]);
        let orphans = compute_orphan_uuids(&node, &granted, &all);
        assert_eq!(orphans.len(), 1);
        assert_eq!(orphans[0].uuid, "uuid-bob");
        assert_eq!(
            orphans[0].name.as_deref(),
            Some("bob"),
            "a revoked-but-known user must resolve to their id"
        );
    }

    #[test]
    fn compute_orphan_uuids_empty_when_node_matches_inventory() {
        let alice = user("alice", "uuid-alice");
        let granted = vec![alice.clone()];
        let all = vec![alice];
        let node = uuid_set(&["uuid-alice"]);
        assert!(
            compute_orphan_uuids(&node, &granted, &all).is_empty(),
            "no orphan when every on-node UUID is granted"
        );
    }

    #[test]
    fn compute_orphan_uuids_ignores_inventory_uuid_not_on_node() {
        // A granted user whose UUID is NOT on the node is NOT an orphan
        // (orphan = on-node-not-in-inventory, the one-directional diff).
        let alice = user("alice", "uuid-alice");
        let granted = vec![alice.clone()];
        let all = vec![alice];
        let node = uuid_set(&[]); // node serves nothing
        assert!(
            compute_orphan_uuids(&node, &granted, &all).is_empty(),
            "inventory-only UUIDs must never count as orphans"
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod csv_tests {
    use super::csv_field;

    /// OWASP CSV-injection pin (audit 2026-06-10): a field starting
    /// with = + - @ must be neutralised with a leading quote so
    /// Excel/LibreOffice render text instead of executing a formula.
    #[test]
    fn csv_field_neutralises_formula_prefixes() {
        assert_eq!(csv_field("=HYPERLINK(1)"), "'=HYPERLINK(1)");
        assert_eq!(csv_field("+1"), "'+1");
        assert_eq!(csv_field("-srv"), "'-srv");
        assert_eq!(csv_field("@cmd"), "'@cmd");
        // Quoting still composes with the injection guard.
        assert_eq!(csv_field("=a,b"), "\"'=a,b\"");
        // Plain fields stay untouched.
        assert_eq!(csv_field("user.grant"), "user.grant");
        assert_eq!(csv_field("a\"b"), "\"a\"\"b\"");
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod alert_explainer_policy_tests {
    use super::alert_explainer;
    use crate::i18n::Locale;

    /// Operator-action-policy (CLAUDE.md HARD rule): the explainer copy
    /// rendered into the operator's browser must NOT tell them to run
    /// `ssh` / `systemctl` / `cat` / `truncate` *on the node*. The
    /// product surface for remediation is the server page (redeploy) or
    /// the hoster console — never a shell instruction. Mirrors the
    /// contract-pin idiom of `classify_ssh_failure_recognises_permission_denied`.
    ///
    /// Every alert kind handled by `alert_explainer`, both locales.
    const ALL_KINDS: &[&str] = &[
        "sub_access.suspicious_local_ip",
        "sub_access.suspicious_local_ip:alice", // per-user suffix path
        "server.singbox.down",
        "server.singbox.up",
        "server.fail2ban.down",
        "server.fail2ban.up",
        "server.fail2ban.banned_self",
        "server.disk.pressure",
        "server.disk.recovered",
        "server.mem.pressure",
        "server.mem.recovered",
        "server.singbox.log.too_big",
        "server.unreachable",
        "server.fingerprint.drift",
    ];

    /// Substrings that signal a shell instruction the operator is told
    /// to run *themselves*. Spaced so we don't false-positive on prose
    /// (e.g. `fail2ban-client unban` via the hoster console is allowed —
    /// it's a recovery step, not a "ssh in and run this" instruction).
    const FORBIDDEN: &[&str] = &["systemctl ", "truncate ", " cat ", "ssh "];

    #[test]
    fn alert_explainer_copy_has_no_operator_shell_instructions() {
        for &kind in ALL_KINDS {
            for lang in [Locale::En, Locale::Ru] {
                let (title, hint) = alert_explainer(kind, lang);
                let blob = format!("{title}\n{}", hint.unwrap_or(""));
                for &needle in FORBIDDEN {
                    assert!(
                        !blob.contains(needle),
                        "kind={kind} lang={lang:?} leaks operator shell instruction {needle:?}: {blob}"
                    );
                }
                // Spot-pin the two rewritten kinds say the compliant thing.
                if kind == "server.fail2ban.down" {
                    assert!(
                        blob.to_lowercase().contains("redeploy")
                            || blob.to_lowercase().contains("передеплой"),
                        "fail2ban.down must point at redeploy, got: {blob}"
                    );
                }
            }
        }
    }
}
