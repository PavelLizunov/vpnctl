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

use super::helpers::*;
use super::servers::*;
use super::ui::*;
use super::users::mask_secret;
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
    /// The i18n key used to look up the localised label. topbar() calls
    /// `t(lang, label_key)` to get the actual rendered text.
    label_key: crate::i18n::K,
}

const NAV: &[NavItem] = &[
    NavItem {
        key: "dashboard",
        label_key: crate::i18n::K::NavDashboard,
    },
    NavItem {
        key: "monitoring",
        label_key: crate::i18n::K::NavMonitoring,
    },
    NavItem {
        key: "servers",
        label_key: crate::i18n::K::NavServers,
    },
    NavItem {
        key: "users",
        label_key: crate::i18n::K::NavUsers,
    },
    NavItem {
        key: "audit",
        label_key: crate::i18n::K::NavAudit,
    },
    NavItem {
        key: "alerts",
        label_key: crate::i18n::K::NavAlerts,
    },
    NavItem {
        key: "settings",
        label_key: crate::i18n::K::NavSettings,
    },
    NavItem {
        key: "boosty",
        label_key: crate::i18n::K::NavBoosty,
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

/// Design v2 topbar — one compact bar replacing the old masthead + nav.
/// `[·] vpnctl` · UPPERCASE nav with an active pill · ALERTS carries the
/// LIVE unacked count · search (`/` hotkey via admin.js) · EN|RU toggle ·
/// operator · logout. All colours from the ink token family (see
/// `.ed-tb*` in admin.css).
fn topbar(active: &str, lang: crate::i18n::Locale, alerts_unacked: u64) -> Markup {
    use crate::i18n::{K, Locale, t};
    let other = match lang {
        Locale::En => Locale::Ru,
        Locale::Ru => Locale::En,
    };
    html! {
        div.ed-tb {
            a.ed-tb__logo href="/admin/" {
                // The [·] brand mark is tinted with the operator's active
                // accent — the one always-on accent hook in the chrome now
                // that the masthead vol-number is gone.
                span style="color: var(--acc); display: flex;" { (glyph(18)) }
                "vpnctl"
            }
            nav.ed-tb__nav {
                @for it in NAV {
                    // The alerts item carries the LIVE unacked count
                    // (a warm chip); the rest have no count. The active
                    // branch emits `class="on"` (the pill), inactive
                    // emits no class attribute.
                    @let count = if it.key == "alerts" && alerts_unacked > 0 {
                        Some(alerts_unacked)
                    } else {
                        None
                    };
                    @if it.key == active {
                        a.on href=(nav_href(it.key)) {
                            (t(lang, it.label_key))
                            @if let Some(c) = count { " " span.ct { (c) } }
                        }
                    } @else {
                        a href=(nav_href(it.key)) {
                            (t(lang, it.label_key))
                            @if let Some(c) = count { " " span.ct { (c) } }
                        }
                    }
                }
            }
            span.ed-tb__r {
                form method="get" action="/admin/search" style="display: flex; margin: 0;" {
                    input.ed-tb__search type="search" name="q" id="tb-search"
                          title=(match lang {
                              Locale::En => "Fleet-wide search — press / to focus",
                              Locale::Ru => "Поиск по флоту — нажми / чтобы сфокусировать",
                          })
                          placeholder=(match lang {
                              Locale::En => "search…  /",
                              Locale::Ru => "поиск…  /",
                          });
                }
                span.ed-tb__who {
                    // Active locale bold, unlinked; the other locale is a
                    // POST toggle (server-set cookie, not URL-leaky).
                    b { (lang.cookie_value().to_uppercase()) }
                    "|"
                    form method="post" action="/admin/tweak/lang" style="display: inline; margin: 0; padding: 0;" {
                        input type="hidden" name="value" value=(other.cookie_value()) {}
                        button type="submit"
                               title=(match other {
                                   Locale::En => "Switch admin UI to English",
                                   Locale::Ru => "Переключить админку на русский",
                               }) {
                            (other.cookie_value().to_uppercase())
                        }
                    }
                    // Hidden below 1180px (see .ed-tb__host in the CSS)
                    // so the RU nav keeps to one bar row on narrow
                    // laptop windows.
                    span.ed-tb__host { " · " (t(lang, K::NavOperator)) }
                    " · "
                    form method="post" action="/admin/logout" style="display: inline; margin: 0; padding: 0;" {
                        button type="submit"
                               title=(match lang {
                                   Locale::En => "Sign out of the admin UI on this device",
                                   Locale::Ru => "Выйти из админки на этом устройстве",
                               }) {
                            (match lang { Locale::En => "logout", Locale::Ru => "выйти" })
                        }
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
                span { "vpnctld " (vpnctl_core::build_version()) }
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
fn tweaks_inline(theme: &str, accent: &str, lang: crate::i18n::Locale) -> Markup {
    use crate::i18n::tr;
    html! {
        div style="display: flex; flex-direction: column; gap: 10px; padding: 12px 14px; border: 1px solid var(--rule); background: var(--paper); font-family: var(--mono); font-size: 11px; color: var(--soft); max-width: 480px;" {
            form method="post" action="/admin/tweak/theme" style="display: flex; gap: 6px; align-items: baseline;" {
                span style="width: 60px; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { (tr(lang, "paper", "бумага")) }
                @for &name in VALID_THEMES {
                    button name="value" value=(name)
                           title=(format!("{} {name}", tr(lang, "Switch paper theme to", "Переключить тему бумаги на")))
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
                span style="width: 60px; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { (tr(lang, "accent", "акцент")) }
                @for &name in VALID_ACCENTS {
                    button name="value" value=(name)
                           title=(format!("{} {name}", tr(lang, "Switch accent colour to", "Переключить акцентный цвет на")))
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
/// Load the live unacked-alert count for the topbar chip. Best-effort:
/// a read failure renders no chip rather than 500-ing every page.
// `topbar_alert_count`, `render_page`, `shell`, `cookie`, `theme_accent`, `theme_accent_lang` moved to helpers.rs

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
async fn collect_dashboard_data(state: &AppState) -> anyhow::Result<DashboardStats> {
    let (servers_count, users_count, disabled_users_count, grants_count, server_list) = tokio::try_join!(
        state.inv.count_servers(),
        state.inv.count_users(),
        state.inv.count_disabled_users(),
        state.inv.count_grants(),
        state.inv.list_servers(),
    )?;
    let distinct_protocols: HashSet<_> = server_list
        .iter()
        .flat_map(|s| s.enabled_protocols.iter().map(|p| p.0.as_str()))
        .collect();
    Ok(DashboardStats {
        servers: servers_count,
        users: users_count,
        disabled_users: disabled_users_count,
        grants: grants_count,
        distinct_protocols: distinct_protocols.len(),
    })
}

/// Render an editorial 4-cell metric row from the dashboard stats.
fn dashboard_summary_bar(
    stats: &DashboardStats,
    conns_now: usize,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    // Densification pass (2026-07-09): the four 68px KPI cards + the
    // explanatory deck above collapse into one dense mono line. The prose
    // folds into the ⓘ hover; the counts stay. Same data, a quarter of the
    // vertical space (see design_handoff_vpnctl_densify).
    let tip = tr(
        lang,
        "Counts straight from the SQLite inventory backing this daemon (/var/lib/vpnctl/inv.db). Servers, users, grants and the daemon version update on every reload.",
        "Счётчики читаются напрямую из SQLite-инвентаря этого демона (/var/lib/vpnctl/inv.db). Серверы, пользователи, выданные доступы и версия демона обновляются при каждой перезагрузке.",
    );
    html! {
        div.ed-sumbar {
            h1.ed-sumbar__h {
                (tr(lang, "homelab ", "homelab "))
                em { (tr(lang, "at a glance", "одним взглядом")) }
            }
            span.ed-tip title=(tip) { "ⓘ" }
            span.ed-sumbar__stat {
                b { (stats.servers) } " "
                (crate::i18n::noun_for(lang, stats.servers as u64, "server", "servers", "сервер", "сервера", "серверов"))
            }
            span.ed-sumbar__stat {
                b { (stats.users) } " "
                (crate::i18n::noun_for(lang, stats.users as u64, "user", "users", "юзер", "юзера", "юзеров"))
                @if stats.disabled_users > 0 {
                    " · "
                    a.ed-sumbar__warn href="/admin/users"
                      title=(tr(
                          lang,
                          "Users with disabled=true (soft-suspended). Click to drill into the user list.",
                          "Пользователи с disabled=true (на паузе). Кликни, чтобы открыть список.",
                      )) {
                        b { (stats.disabled_users) } (tr(lang, " paused", " на паузе"))
                    }
                }
            }
            span.ed-sumbar__stat {
                b { (stats.grants) } " "
                (crate::i18n::noun_for(lang, stats.grants as u64, "grant", "grants", "доступ", "доступа", "доступов"))
            }
            span.ed-sumbar__stat {
                b { (stats.distinct_protocols) } " "
                (crate::i18n::noun_for(lang, stats.distinct_protocols as u64, "protocol", "protocols", "протокол", "протокола", "протоколов"))
            }
            span.ed-sumbar__stat { b { (conns_now) } " " (tr(lang, "conns now", "подкл. сейчас")) }
            span.ed-sumbar__live {
                span.ed-sumbar__dot {}
                "vpnctld " b { (vpnctl_core::build_version()) } " "
                em { (tr(lang, "live", "активен")) }
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
    let numeric_prefix = |s: &str| -> Option<u64> {
        let n: String = s.chars().take_while(char::is_ascii_digit).collect();
        (!n.is_empty()).then_some(n)?.parse().ok()
    };
    let major = numeric_prefix(parts.next()?)?;
    let minor = parts.next().and_then(numeric_prefix).unwrap_or(0);
    let patch = parts.next().and_then(numeric_prefix).unwrap_or(0);
    Some((major, minor, patch))
}

fn kernel_version_is_current(
    observed: &str,
    requirement: vpnctl_core::KernelVersionRequirement,
) -> bool {
    match requirement.policy {
        vpnctl_core::KernelVersionPolicy::Floor => {
            match (
                parse_version_tuple(observed),
                parse_version_tuple(requirement.value),
            ) {
                (Some(observed), Some(floor)) => observed >= floor,
                _ => false,
            }
        }
        vpnctl_core::KernelVersionPolicy::Pin => {
            observed.trim().trim_start_matches('v')
                == requirement.value.trim().trim_start_matches('v')
        }
    }
}

/// Extract the `"sing-box"` version from a server's
/// `kernel_versions_json` blob (e.g. `{"sing-box":"1.13.12",…}`).
/// Returns `None` for `None` JSON, malformed JSON, or a missing
/// `sing-box` key. Shared by the fleet-at-a-glance version column
/// (dash#1) and the kernel-floor rollup (dash#3).
fn sing_box_version_of(kernel_versions_json: Option<&str>) -> Option<String> {
    kernel_observations_of(kernel_versions_json)
        .remove("sing-box")
        .and_then(|o| o.version)
}

/// Fleet-majority sing-box version — the most frequently reported one.
/// A node on any OTHER version gets a warm «≠» drift marker. Shared by
/// the dashboard fleet table (1b) and the monitoring page (v2 3a).
fn fleet_majority_version(
    kernel_versions: &[(vpnctl_core::ServerId, Option<String>)],
) -> Option<String> {
    let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for (_, j) in kernel_versions {
        if let Some(v) = sing_box_version_of(j.as_deref()) {
            *counts.entry(v).or_insert(0) += 1;
        }
    }
    // Tie-break by the NEWER version, not HashMap iteration order — a
    // 2-vs-2 fleet mid-upgrade otherwise flips the ≠ drift marker
    // between renders. Preferring the newer side marks the not-yet-
    // upgraded nodes as drifted, which is the actionable reading.
    counts
        .into_iter()
        .max_by(|(va, na), (vb, nb)| {
            na.cmp(nb)
                .then_with(|| parse_version_tuple(va).cmp(&parse_version_tuple(vb)))
                .then_with(|| va.cmp(vb))
        })
        .map(|(v, _)| v)
}

/// GeoIP MMDB file freshness — mtimes of the city + ASN databases in
/// `VPNCTLD_GEOIP_DIR`. Shared by the Settings GeoIP section and the
/// monitoring page's «GeoIP DB» line (v2 3a).
fn server_detail_kernel_inventory_section(
    server: &vpnctl_core::Server,
    registry: &vpnctl_core::Registry,
    latest: Option<&vpnctl_inventory::NodeHealthRow>,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    let observations =
        kernel_observations_of(latest.and_then(|row| row.kernel_versions_json.as_deref()));
    let kernels = ordered_kernel_ids(server);
    let probe_age = latest.map(|row| chrono::Utc::now() - row.ts);
    let probe_stale = probe_age.is_some_and(|age| age.num_seconds() > 1200);
    html! {
        section id="kernel-version-inventory" style="margin-top: 28px;" {
            div.ed-art-eyebrow { (tr(lang, "Kernel versions", "Версии ядер")) }
            p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 12px;" {
                (tr(
                    lang,
                    "Every declared kernel, its installed build and the managed floor or pin. Probe state older than 20 minutes is marked stale.",
                    "Каждое объявленное ядро, установленная сборка и управляемый floor или pin. Проверка старше 20 минут помечается как устаревшая.",
                ))
                @if let Some(age) = probe_age {
                    " · " (tr(lang, "measured ", "измерено ")) (humanize_age(age, lang))
                }
            }
            table style="width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 11px;" {
                thead { tr style="border-bottom: 1px solid var(--ink);" {
                    th style="text-align:left;padding:5px 8px;" { (tr(lang, "declared kernel", "объявленное ядро")) }
                    th style="text-align:left;padding:5px 8px;" { (tr(lang, "installed", "установлено")) }
                    th style="text-align:left;padding:5px 8px;" { (tr(lang, "managed target", "целевая версия")) }
                    th style="text-align:left;padding:5px 8px;" { (tr(lang, "runtime", "сервис")) }
                    th style="text-align:left;padding:5px 8px;" { (tr(lang, "version state", "состояние версии")) }
                } }
                tbody {
                    @for kid in kernels {
                        @let requirement = registry.kernel(kid).and_then(|k| k.version_requirement());
                        @let observation = observations.get(&kid.0);
                        @let installed = observation.and_then(|o| o.version.as_deref());
                        @let current = installed.zip(requirement).map(|(v, r)| kernel_version_is_current(v, r));
                        tr data-kernel-version=(kid.0) style="border-bottom: 1px dotted var(--rule);" {
                            td style="padding:5px 8px;" { b { (kid.0) } }
                            td style="padding:5px 8px;" { (installed.unwrap_or("unknown")) }
                            td style="padding:5px 8px;" {
                                @if let Some(req) = requirement {
                                    (match req.policy {
                                        vpnctl_core::KernelVersionPolicy::Floor => "floor",
                                        vpnctl_core::KernelVersionPolicy::Pin => "pin",
                                    })
                                    " " (req.value)
                                } @else { "unmanaged" }
                            }
                            td style="padding:5px 8px;" {
                                @if probe_stale {
                                    span style="color:#e6a23c;" { (tr(lang, "stale", "устарело")) }
                                } @else {
                                    @match observation.and_then(|o| o.active) {
                                        Some(true) => span style="color:#2e7d32;" { (tr(lang, "active", "активно")) },
                                        Some(false) => span style="color:#c62828;" { (tr(lang, "inactive", "неактивно")) },
                                        None => span style="color:var(--mute);" { (tr(lang, "unknown", "неизвестно")) },
                                    }
                                }
                            }
                            td style="padding:5px 8px;" {
                                @if probe_stale {
                                    span style="color:#e6a23c;" { (tr(lang, "stale probe", "устаревшая проверка")) }
                                } @else {
                                    @match current {
                                        Some(true) => span style="color:#2e7d32;" { (tr(lang, "current", "актуально")) },
                                        Some(false) => span style="color:#c62828;" { (tr(lang, "stale", "устарело")) },
                                        None => span style="color:var(--mute);" { (tr(lang, "unknown", "неизвестно")) },
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

struct GeoipDbStat {
    city_mtime: Option<String>,
    asn_mtime: Option<String>,
}

fn geoip_db_stat() -> GeoipDbStat {
    let dir = std::env::var_os("VPNCTLD_GEOIP_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("/var/lib/vpnctl/geoip"));
    let mtime_of = |p: &std::path::Path| -> Option<String> {
        std::fs::metadata(p)
            .ok()?
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .and_then(|d| chrono::DateTime::<chrono::Utc>::from_timestamp(d.as_secs() as i64, 0))
            .map(format_msk_iso)
    };
    GeoipDbStat {
        city_mtime: mtime_of(&dir.join("GeoLite2-City.mmdb")),
        asn_mtime: mtime_of(&dir.join("GeoLite2-ASN.mmdb")),
    }
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
            p style="font-family: var(--serif); font-size: 14px; margin: 8px 0 0;" {
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
    // Busiest node — its conns + traffic cells render bold (mock 1b) and
    // every share bar scales against its traffic.
    let max_traffic = traffic_24h.values().copied().max().unwrap_or(0);
    // Fleet-majority sing-box version: the most frequent reported one.
    // A node on any OTHER version gets a warm «≠» drift marker.
    let majority_version = fleet_majority_version(kernel_versions);
    html! {
        section id="fleet-at-a-glance" style="margin-top: 18px;" {
            div.ed-art-eyebrow {
                (tr(lang, "Fleet", "Флот")) " "
                span.ed-tip title=(tr(
                    lang,
                    "One row per server — sing-box state, disk/memory pressure (warm cell above 70%), live connections, 24h traffic with each node's share of the busiest, the on-node sing-box version (≠ marks drift from the fleet majority) and probe freshness. Open a server for the full drill-in.",
                    "Одна строка на сервер — состояние sing-box, нагрузка диска/памяти (тёплая ячейка выше 70%), живые подключения, трафик за 24ч с долей от самой нагруженной ноды, версия sing-box на ноде (≠ помечает дрейф от большинства флота) и свежесть пробы. Открой сервер для деталей.",
                )) { "ⓘ" }
            }
            table.ed-grid style="margin-top: 8px;" {
                thead {
                    tr {
                        th { (tr(lang, "server", "сервер")) }
                        th { (tr(lang, "state", "состояние")) }
                        th.num { (tr(lang, "disk", "диск")) }
                        th.num { (tr(lang, "mem", "память")) }
                        th.num { (tr(lang, "conns", "подкл.")) }
                        th.num { (tr(lang, "traffic 24h", "трафик 24ч")) }
                        th { (tr(lang, "share of traffic", "доля трафика")) }
                        th { (tr(lang, "kernel versions", "версии ядер")) }
                        th.num { (tr(lang, "probe", "проба")) }
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
                        @let kv_json = kernel_versions
                            .iter()
                            .find(|(id, _)| *id == s.id)
                            .and_then(|(_, j)| j.as_deref());
                        @let traffic = traffic_24h.get(&s.id).copied();
                        @let busiest = max_traffic > 0 && traffic == Some(max_traffic);
                        @let disk_pct = health.and_then(pct_disk);
                        @let mem_pct = health.and_then(pct_mem);
                        tr {
                            td { a.ed-grid__id href=(format!("/admin/servers/{}", path_segment_encode(&s.id.0))) { (s.id.0) } }
                            td.ed-grid__sm {
                                @match health.and_then(|h| h.sing_box_active) {
                                    Some(true) => span.ed-stat.ed-stat--active { span.ed-stat__dot {} (tr(lang, "up", "работает")) },
                                    Some(false) => span.ed-stat.ed-stat--failed { span.ed-stat__dot {} (tr(lang, "down", "не работает")) },
                                    None => span.ed-grid__mut { (dash) },
                                }
                            }
                            td class=(if disk_pct.is_some_and(|p| p > 70) { "num warn" } else { "num" }) {
                                @match disk_pct {
                                    Some(p) => { (p) "%" @if p > 70 { " ⚠" } },
                                    None => span.ed-grid__mut { (dash) },
                                }
                            }
                            td class=(if mem_pct.is_some_and(|p| p > 70) { "num warn" } else { "num" }) {
                                @match mem_pct {
                                    Some(p) => { (p) "%" @if p > 70 { " ⚠" } },
                                    None => span.ed-grid__mut { (dash) },
                                }
                            }
                            td.num {
                                @match conns {
                                    Some(c) => @if busiest { b { (c) } } @else { (c) },
                                    None => span.ed-grid__mut { (dash) },
                                }
                            }
                            td.num {
                                @match traffic {
                                    Some(b) => @if busiest { b { (humanize_bytes(b)) } } @else { (humanize_bytes(b)) },
                                    None => span.ed-grid__mut { (dash) },
                                }
                            }
                            td {
                                @if let Some(b) = traffic {
                                    @let share = b.saturating_mul(100).checked_div(max_traffic).unwrap_or(0);
                                    div.ed-hist__bar title=(format!("{share}%")) { div style=(format!("width: {share}%;")) {} }
                                } @else {
                                    span.ed-grid__mut { (dash) }
                                }
                            }
                            td.ed-grid__sm {
                                (kernel_versions_inline(s, kv_json, majority_version.as_deref()))
                            }
                            td.num.ed-grid__mut.ed-grid__sm {
                                @match health.map(|h| h.ts) {
                                    Some(ts) => (humanize_age(now - ts, lang)),
                                    None => (dash),
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
/// chart. Uses the same aligned buckets as the chart so the bars and
/// totals cannot disagree at a day boundary.
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
    use chrono::{DurationRound, TimeDelta, Utc};
    let bucket_seconds = i64::from(window.bucket_hours) * 3600;
    let Ok(now) = Utc::now().duration_trunc(TimeDelta::seconds(bucket_seconds)) else {
        return html! {};
    };
    let cur_start =
        now - TimeDelta::seconds(i64::from(window.cells.saturating_sub(1)) * bucket_seconds);
    let prior_start = cur_start - TimeDelta::seconds(i64::from(window.cells) * bucket_seconds);

    // Sum ALL rows (per-user attributed + unattributed remainder).
    // Since the NM-11 attribution fix the server-wide row holds only
    // the unattributed remainder, so filtering to user_id IS NULL
    // undercounts by the attributed share. Match `vpn_traffic_chart`
    // which already sums every row.
    let weight = |sid: &vpnctl_core::ServerId| -> f64 { coeffs.get(sid).copied().unwrap_or(1.0) };
    let mut cur_up = 0f64;
    let mut cur_dn = 0f64;
    let mut prior_total = 0f64;
    for r in rows {
        let Ok(row_bucket) = r.ts.duration_trunc(TimeDelta::seconds(bucket_seconds)) else {
            continue;
        };
        if row_bucket > now {
            continue;
        }
        let w = weight(&r.server_id);
        let up = r.upload_bytes as f64 * w;
        let dn = r.download_bytes as f64 * w;
        if row_bucket >= cur_start {
            cur_up += up;
            cur_dn += dn;
        } else if row_bucket >= prior_start {
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

/// Dashboard 1b — health feed: the newest unacked alerts as a minimal
/// table (severity mark / kind / target / age), with the unacked total
/// in the eyebrow and a «full feed →» link to /admin/alerts. Replaces
/// the PR-Dash dash#4 (kind, severity)-counts card. Quiet-dashboard
/// contract kept — renders nothing when there are zero unacked alerts.
fn dashboard_health_feed(
    alerts: &[vpnctl_inventory::AdminAlert],
    unacked_total: u64,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    if alerts.is_empty() {
        // Quiet dashboard — no unacked alerts, no card.
        return html! {};
    }
    let now = chrono::Utc::now();
    html! {
        div {
            div.ed-art-eyebrow {
                (tr(lang, "Health feed", "Поток здоровья"))
                " · " (tr(lang, "open", "открыто")) " " (unacked_total)
            }
            table.ed-feed style="margin-top: 8px;" {
                tbody {
                    @for a in alerts {
                        // Kinds carry the subject after a colon
                        // (`user.traffic_limit:<uid>`); split so the kind
                        // column stays scannable and the subject joins
                        // the target cell.
                        @let (kind_base, kind_subject) = match a.kind.split_once(':') {
                            Some((k, s)) => (k, Some(s)),
                            None => (a.kind.as_str(), None),
                        };
                        tr {
                            td style="width: 20px;" {
                                @if a.severity.eq_ignore_ascii_case("critical") {
                                    span style="color: var(--red);" title=(a.severity) { "✖" }
                                } @else {
                                    span style="color: var(--warm);" title=(a.severity) { "⚠" }
                                }
                            }
                            td.ed-grid__mut.ed-grid__sm title=(a.summary) { (kind_base) }
                            td {
                                @match (&a.server_id, kind_subject) {
                                    (Some(sid), _) => {
                                        a href=(format!("/admin/servers/{}", path_segment_encode(&sid.0))) { (sid.0) }
                                    },
                                    (None, Some(subject)) => {
                                        // User-scoped kinds put the user id
                                        // after the colon — link it.
                                        a href=(format!("/admin/users/{}", path_segment_encode(subject))) { (subject) }
                                    },
                                    (None, None) => span.ed-grid__mut { "—" },
                                }
                            }
                            td.num.ed-grid__mut.ed-grid__sm { (humanize_age(now - a.created_at, lang)) }
                        }
                    }
                }
            }
            div style="margin-top: 6px;" {
                a href="/admin/alerts" style="font-family: var(--serif); font-style: italic; font-size: 11px; color: var(--acc); text-decoration: none;" {
                    (tr(lang, "full feed →", "весь поток →"))
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
    let network =
        |n: u64| crate::i18n::noun_for(lang, n, "network", "networks", "сеть", "сети", "сетей");
    match r {
        R::TypicalConcurrentNets(n) => {
            format!(
                "{n} {} {}",
                network(n as u64),
                tr(lang, "at once (typical)", "обычно одновременно")
            )
        }
        R::DailyNets(n) => format!("{n} {}/{}", network(n as u64), tr(lang, "day", "день")),
        R::ImpossibleTravel(h) => {
            format!(
                "{h}× {}",
                tr(lang, "impossible travel", "невозможн. перемещ.")
            )
        }
    }
}

const SHARING_WINDOW_DAYS: u32 = 30;
const IMPOSSIBLE_TRAVEL_HOURS: f64 = 2.0;

async fn load_likely_shared(
    inv: &vpnctl_inventory::SqliteInventory,
) -> Vec<(vpnctl_core::UserId, crate::sharing_score::SharingScore)> {
    let mut rows: Vec<_> = inv
        .sharing_signals_all_users(SHARING_WINDOW_DAYS, IMPOSSIBLE_TRAVEL_HOURS)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(target = "vpnctld::admin", error = %e, "sharing_signals_all_users failed");
            Vec::new()
        })
        .into_iter()
        .filter(|s| !s.user_id.0.is_empty())
        .map(|s| {
            let sc = crate::sharing_score::score(&s);
            (s.user_id, sc)
        })
        .filter(|(_, sc)| sc.is_flagged())
        .collect();
    rows.sort_by_key(|b| std::cmp::Reverse(b.1.score));
    rows
}

fn sharing_rows(
    rows: &[&(vpnctl_core::UserId, crate::sharing_score::SharingScore)],
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::sharing_score::SharingLevel;
    html! {
        @for (uid, sc) in rows {
            @let tone = if sc.level == SharingLevel::High { "var(--red)" } else { "var(--warm)" };
            tr {
                td.num style="width: 34px;" {
                    b style=(format!("color: {tone};")) { (sc.score) }
                }
                td style="width: 96px;" {
                    div.ed-scorebar {
                        div style=(format!("width: {}%; background: {tone};", sc.score)) {}
                    }
                }
                td {
                    a href=(format!("/admin/users/{}/activity#source-ips", path_segment_encode(&uid.0))) {
                        (uid.0)
                    }
                }
                td.num.ed-grid__mut {
                    @for (i, reason) in sc.reasons.iter().take(2).enumerate() {
                        @if i > 0 { " · " }
                        (sharing_reason_label(*reason, lang))
                    }
                }
            }
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
        div {
            div.ed-art-eyebrow {
                (tr(lang, "Likely-shared subscriptions", "Похоже на расшаренные подписки"))
                " · " (n) " "
                span.ed-tip title=(tr(
                    lang,
                    "Risk score weights the TYPICAL simultaneous ISP-scale network count + impossible travel far above mere network diversity. One-off peaks and adjacent mobile-carrier subnets no longer trip it. Open a row to inspect the exact VPN source IPs.",
                    "Риск-скор сильнее всего учитывает ТИПИЧНОЕ число одновременных сетей масштаба ISP и невозможные перемещения. Разовые пики и соседние подсети мобильного оператора больше не срабатывают. Открой строку, чтобы увидеть реальные source IP VPN.",
                )) { "ⓘ" }
            }
            table.ed-feed style="margin-top: 8px;" {
                tbody {
                    (sharing_rows(&rows.iter().take(6).copied().collect::<Vec<_>>(), lang))
                }
            }
            @if n > 6 {
                div style="margin-top: 8px;" {
                    a href="/admin/sharing"
                      style="font-family: var(--mono); font-size: 10px; color: var(--acc); text-decoration: none;" {
                        "+" (n - 6) " " (tr(lang, "more flagged · open full list →", "ещё под флагом · открыть весь список →"))
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
/// v2 5b — deep-copy a payload with secret-looking values replaced, so
/// the <details> expander can show the STRUCTURE without leaking what
/// the summary whitelist deliberately hides. Denylist by key substring.
pub(crate) fn redact_audit_payload(payload: &serde_json::Value) -> serde_json::Value {
    match payload {
        serde_json::Value::Object(map) => serde_json::Value::Object(
            map.iter()
                .map(|(k, v)| {
                    let kl = k.to_ascii_lowercase();
                    let secret = kl.contains("password")
                        || kl.contains("private")
                        || kl.contains("token")
                        || kl.contains("secret");
                    let nv = if secret {
                        serde_json::Value::String("<redacted>".into())
                    } else {
                        redact_audit_payload(v)
                    };
                    (k.clone(), nv)
                })
                .collect(),
        ),
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.iter().map(redact_audit_payload).collect())
        }
        other => other.clone(),
    }
}

pub(crate) fn summarize_audit_payload(payload: &serde_json::Value) -> String {
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
        // R2 2026-07-10 — alert.fire rows read as blanks without their
        // kind; bulk grant/ack rows without their count.
        "kind",
        "count",
        "server",
        "name",
        "status",
        "level",
        "payments",
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
pub(crate) fn action_kind(action: &str) -> &'static str {
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

// IP classification lives in `crate::ip_kind` (single source of
// truth for both the admin render AND the access-log writer that
// fires `sub_access.suspicious_local_ip` alerts). The render-side
// chip wrappers left with the legacy Subscription-access table
// (R2 2026-07-10); the source-IPs section labels ranges itself.

// `parse_ua_short` moved to `crate::ua` (Track-1.2 / migration 0019)
// so the access-log writer can persist its result in
// `sub_access_log.device_class` from the same source of truth. Render
// sites call `crate::ua::parse_ua_short(...)` directly. The previous
// /// doc-block lived above this comment; deleted to satisfy
// `clippy::empty-line-after-doc-comments` since there's no `fn` it
// could document anymore.

// `classify_ip` unit tests moved with the implementation to
// `crate::ip_kind::tests`. The render-side chip wrappers left with the
// legacy Subscription-access table (R2 2026-07-10); the source-IPs
// section carries its own labelling.

/// Dashboard URL query. Activity uses `vpn_window`; sharing uses the
/// three filters below. Keeping one query type lets every dashboard tab
/// flow through the same chrome and tab bar.
#[derive(serde::Deserialize, Default)]
pub(crate) struct DashboardQuery {
    pub vpn_window: Option<String>,
    pub q: Option<String>,
    pub level: Option<String>,
    pub min_score: Option<String>,
}

/// dashboard's in-page tabs (ui-audit follow-up). The at-a-glance KPI
/// metrics + today-digest + fleet table stay as CHROME (visible on every
/// tab — the landing page's whole point is the glance); the two tabs
/// split only the deeper drill-downs. `Overview` is the default (bare
/// `/admin/`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum DashboardTab {
    Overview,
    Activity,
    Sharing,
}

impl DashboardTab {
    fn slug(self) -> &'static str {
        match self {
            DashboardTab::Overview => "overview",
            DashboardTab::Activity => "activity",
            DashboardTab::Sharing => "sharing",
        }
    }
}

// Thin axum handlers — one per tab route in app.rs. Bare `/admin/`
// (+ `/admin`, `/admin/overview`) render the overview tab.
pub(crate) async fn dashboard(
    headers: HeaderMap,
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<DashboardQuery>,
) -> Result<Markup, Response> {
    dashboard_render(headers, state, query, DashboardTab::Overview).await
}

pub(crate) async fn dashboard_activity(
    headers: HeaderMap,
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<DashboardQuery>,
) -> Result<Markup, Response> {
    dashboard_render(headers, state, query, DashboardTab::Activity).await
}

pub(crate) async fn sharing(
    headers: HeaderMap,
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<DashboardQuery>,
) -> Result<Markup, Response> {
    dashboard_render(headers, state, query, DashboardTab::Sharing).await
}

fn sharing_review(
    all: &[(vpnctl_core::UserId, crate::sharing_score::SharingScore)],
    query: &DashboardQuery,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    use crate::sharing_score::SharingLevel;

    let q = query.q.as_deref().unwrap_or("").trim().to_ascii_lowercase();
    let level = match query.level.as_deref() {
        Some("high") => Some(SharingLevel::High),
        Some("medium") => Some(SharingLevel::Medium),
        _ => None,
    };
    let min_score = query
        .min_score
        .as_deref()
        .and_then(|v| v.parse::<u8>().ok())
        .map(|v| v.min(100));
    let rows: Vec<_> = all
        .iter()
        .filter(|(uid, sc)| {
            (q.is_empty() || uid.0.to_ascii_lowercase().contains(&q))
                && level.is_none_or(|wanted| sc.level == wanted)
                && min_score.is_none_or(|min| sc.score >= min)
        })
        .collect();

    let body = html! {
        div.ed-art-eyebrow {
            (tr(lang, "Sharing-risk review", "Проверка риска расшаривания"))
            " · " (rows.len()) "/" (all.len())
        }
        p.ed-deck {
            (tr(
                lang,
                "Thirty-day account-sharing signals, strongest first. The score is a heuristic, not a probability. Open a user to inspect the VPN source networks and rotate access if needed.",
                "Сигналы расшаривания за 30 дней, сначала самые сильные. Балл — эвристика, а не вероятность. Открой пользователя, чтобы проверить исходные сети VPN и при необходимости сменить доступ.",
            ))
        }
        form method="get" action="/admin/sharing" style="display: flex; flex-wrap: wrap; gap: 10px; align-items: end; margin: 16px 0;" {
            label for="sharing-q" style="display: grid; gap: 4px; font-family: var(--mono); font-size: 11px;" {
                (tr(lang, "User", "Пользователь"))
                input id="sharing-q" type="search" name="q" value=(query.q.as_deref().unwrap_or("")) placeholder="ninitux";
            }
            label for="sharing-level" style="display: grid; gap: 4px; font-family: var(--mono); font-size: 11px;" {
                (tr(lang, "Risk level", "Уровень риска"))
                select id="sharing-level" name="level" {
                    option value="" selected[level.is_none()] { (tr(lang, "any", "любой")) }
                    option value="high" selected[level == Some(SharingLevel::High)] { (tr(lang, "high", "высокий")) }
                    option value="medium" selected[level == Some(SharingLevel::Medium)] { (tr(lang, "medium", "средний")) }
                }
            }
            label for="sharing-min-score" style="display: grid; gap: 4px; font-family: var(--mono); font-size: 11px;" {
                (tr(lang, "Minimum score", "Минимальный балл"))
                input id="sharing-min-score" type="number" name="min_score" min="0" max="100"
                      value=(min_score.map(|v| v.to_string()).unwrap_or_default());
            }
            button type="submit" class="ed-abtn ed-abtn--secondary ed-abtn--sm" {
                (crate::i18n::t(lang, crate::i18n::K::BtnFilter))
            }
            a href="/admin/sharing" class="ed-abtn ed-abtn--secondary ed-abtn--sm" {
                (crate::i18n::t(lang, crate::i18n::K::BtnReset))
            }
        }
        @if rows.is_empty() {
            p.ed-empty {
                (tr(lang, "No flagged users match these filters.", "Нет отмеченных пользователей, подходящих под эти фильтры."))
            }
        } @else {
            table.ed-feed {
                tbody { (sharing_rows(&rows, lang)) }
            }
        }
    };
    body
}

async fn dashboard_render(
    headers: HeaderMap,
    state: AppState,
    query: DashboardQuery,
    tab: DashboardTab,
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
    // second query). Inventory reads the ingest-time hourly rollup,
    // not every user's raw poll row.
    let fleet_rows = state
        .inv
        .recent_vpn_stats_fleet(since_hours.saturating_mul(2), window.bucket_hours)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(target = "vpnctld::admin", error = %e, "recent_vpn_stats_fleet failed");
            Vec::new()
        });

    let stats = collect_dashboard_data(&state)
        .await
        .map_err(internal_error)?;

    // Heavy users — raw ticks for 24h, existing daily rollups for
    // longer windows. The tile heading follows the selected window.
    let heavy_users = if window.bucket_hours >= 24 {
        state
            .inv
            .top_users_by_daily_traffic(since_hours.div_ceil(24), 5)
            .await
    } else {
        state.inv.top_users_by_traffic(since_hours, 5).await
    }
    .unwrap_or_else(|e| {
        tracing::warn!(target = "vpnctld::admin", error = %e, "top users traffic query failed");
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

    let mut fleet_quality = Vec::with_capacity(server_list_fleet.len());
    for server in &server_list_fleet {
        let q24 = state
            .inv
            .service_quality_for_server(&server.id, 24, vpnctl_inventory::QUALITY_MIN_SAMPLES)
            .await
            .unwrap_or_else(|_| {
                vpnctl_inventory::score_samples(&[], 24, vpnctl_inventory::QUALITY_MIN_SAMPLES)
            });
        let q7 = state
            .inv
            .service_quality_for_server(&server.id, 24 * 7, vpnctl_inventory::QUALITY_MIN_SAMPLES)
            .await
            .unwrap_or_else(|_| {
                vpnctl_inventory::score_samples(&[], 24 * 7, vpnctl_inventory::QUALITY_MIN_SAMPLES)
            });
        fleet_quality.push((server.id.clone(), q24, q7));
    }

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
    // when the poller has never reached the server OR the last snapshot
    // went stale (polling stopped) — `get_live` gates on ~2 poll
    // intervals so a frozen snapshot can't keep reporting a live count.
    let active_conns_now: Vec<(vpnctl_core::ServerId, Option<usize>)> = server_list_fleet
        .iter()
        .map(|s| {
            let n = state
                .snapshot_cache
                .get_live(&s.id)
                .map(|snap| snap.snapshot.connections.len());
            (s.id.clone(), n)
        })
        .collect();
    let live_activity = dashboard_live_activity_from_rows(
        &server_list_fleet,
        &active_conns_now,
        &fleet_rows,
        window,
    );

    // Dashboard 1b — health feed: newest 5 unacked alerts + the unacked
    // total for the eyebrow. Quiet-dashboard contract: empty ⇒ no card.
    let recent_alerts = state.inv.recent_alerts(5, false).await.unwrap_or_else(|e| {
        tracing::warn!(target = "vpnctld::admin", error = %e, "recent_alerts failed");
        Vec::new()
    });
    let unacked_total = state.inv.unacked_alert_count().await.unwrap_or_else(|e| {
        tracing::warn!(target = "vpnctld::admin", error = %e, "unacked_alert_count failed");
        recent_alerts.len() as u64
    });

    // PR-Dash dash#5 (redesigned 2026-06-17) — composite account-sharing
    // risk. Gather raw signals fleet-wide over the retention window, score
    // each (simultaneity-weighted), keep only flagged users, strongest
    // first. Empty ⇒ card hidden.
    let likely_shared = load_likely_shared(&state.inv).await;

    // PR-Dash — per-server usage coefficients (for the weighted traffic
    // sums in dash#1 + dash#2). Built from the already-loaded server
    // list; no extra query.
    let coeffs: std::collections::HashMap<vpnctl_core::ServerId, f64> = server_list_fleet
        .iter()
        .map(|s| (s.id.clone(), s.usage_coefficient))
        .collect();

    // Fixed 24h fleet-table column is independent of the selected chart
    // bucket. Read the same compact hourly rollup as the chart.
    let traffic_24h: std::collections::HashMap<vpnctl_core::ServerId, u64> = state
        .inv
        .weighted_vpn_traffic_by_server(24)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(target = "vpnctld::admin", error = %e, "weighted_vpn_traffic_by_server failed");
            Vec::new()
        })
        .into_iter()
        .collect();

    let conns_now: usize = active_conns_now.iter().filter_map(|(_, c)| *c).sum();

    let body = html! {
        div.ed-art-eyebrow { (crate::i18n::t(lang, crate::i18n::K::PageDashboard)) }
        // Densification pass — the h1 + explanatory deck + four KPI cards
        // collapse into one dense summary bar (prose → ⓘ hover).
        (dashboard_summary_bar(&stats, conns_now, lang))
        // Dashboard 1b — dense fleet table, right under the summary bar.
        (dashboard_fleet_table(&server_list_fleet, &latest_health_per_server, &active_conns_now, &traffic_24h, &kernel_versions, lang))
        (dashboard_quality_ranking(&fleet_quality, lang))
        // ── in-page tabs (ui-audit follow-up). The KPI metrics +
        // today-digest + fleet table ABOVE are chrome (every tab — the
        // landing glance is never hidden); the three tabs below split only
        // the deeper drill-downs. Bare /admin/ == overview.
        (detail_tabs(
            "/admin",
            tab.slug(),
            &[
                ("overview", crate::i18n::tr(lang, "Overview", "Обзор")),
                ("activity", crate::i18n::tr(lang, "Activity", "Активность")),
                ("sharing", crate::i18n::tr(lang, "Sharing risk", "Риск расшаривания")),
            ],
        ))

        // ── OVERVIEW (default) — dashboard 1b two-panel row: what looks
        // shared (left) and what's unhealthy (right). Both panels keep the
        // quiet contract — an empty side simply renders nothing. Traffic-
        // limit crossings arrive as `user.traffic_limit` alerts, so they
        // surface in the health feed rather than a dedicated card.
        @if tab == DashboardTab::Overview {
            div.ed-dash-cols {
                (dashboard_abuse_summary(&likely_shared, lang))
                (dashboard_health_feed(&recent_alerts, unacked_total, lang))
            }
            // Issue 5 — the 24h / 7d / 30d / all traffic picker moved to
            // the Activity tab in the dashboard split, which hid it from
            // the Overview landing glance (Overview shows only a fixed 24h
            // fleet table). Surface a clear pointer so the existing
            // multi-window traffic history stays discoverable — a link, not
            // a duplicated chart/query.
            div style="margin-top: 14px;" {
                a href="/admin/activity#vpn-traffic"
                  style="display: inline-block; font-family: var(--mono); font-size: 12px; color: var(--mute); text-decoration: none; border: 1px solid var(--rule); border-radius: 3px; padding: 4px 10px;" {
                    (crate::i18n::tr(
                        lang,
                        "Traffic history · 1 / 7 / 30 days →",
                        "История трафика · 1 / 7 / 30 дней →",
                    ))
                }
            }
        }

        // ── ACTIVITY — the window-driven charts (traffic / uptime / usage).
        @if tab == DashboardTab::Activity {
            // Global time-window picker — ONE control drives VPN activity
            // + Fleet traffic + Heavy users, all on this tab. Base is the
            // activity tab so `?vpn_window=` reloads keep the operator here.
            (window_picker_section("/admin/activity", window.slug, lang))
            (dashboard_fleet_uptime(&fleet_uptime, lang))
            (dashboard_vpn_activity(&live_activity, window, lang))
            // Fleet-wide traffic chart (same window as the tiles above).
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
            (dashboard_heavy_users(&heavy_users, window, lang))
        }

        // ── SHARING — full fleet-wide review in the same dashboard flow.
        @if tab == DashboardTab::Sharing {
            (sharing_review(&likely_shared, &query, lang))
        }
    };
    Ok(render_page(&state, "dashboard", &theme, &accent, lang, body).await)
}

/// Colour bucket for an uptime percentage. Shared by the per-server
/// `server_detail_uptime_section` chips and the dashboard-wide
/// `dashboard_fleet_uptime` chips so palette stays in one place. The
/// thresholds (≥99 green, ≥95 amber, <95 red, None grey) match Pavel's
/// confirmed SLO buckets for sing-box service uptime.
fn quality_score_color(score: Option<u8>) -> &'static str {
    match score {
        Some(80..=100) => "#2e7d32",
        Some(60..=79) => "#e6a23c",
        Some(_) => "#c62828",
        None => "var(--mute)",
    }
}

fn dashboard_quality_ranking(
    quality: &[(
        vpnctl_core::ServerId,
        vpnctl_inventory::ServiceQualityScore,
        vpnctl_inventory::ServiceQualityScore,
    )],
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    if quality.is_empty() {
        return html! {};
    }
    let mut rows: Vec<_> = quality.iter().collect();
    rows.sort_by(|a, b| b.1.score.cmp(&a.1.score).then_with(|| a.0.0.cmp(&b.0.0)));
    html! {
        section id="fleet-quality-ranking" style="margin-top:28px;" {
            div.ed-art-eyebrow { (tr(lang, "Fleet quality ranking · service path", "Рейтинг качества флота · service path")) }
            p style="font-family:var(--serif);font-style:italic;font-size:12px;color:var(--mute);margin:6px 0 12px;" {
                (tr(
                    lang,
                    "TCP connects to every declared ingress port from vpnctld. Service quality and SSH/control availability are scored separately.",
                    "TCP-подключения ко всем объявленным ingress-портам с vpnctld. Качество сервиса и доступность SSH/control оцениваются отдельно.",
                ))
            }
            table style="width:100%;border-collapse:collapse;font-family:var(--mono);font-size:11px;" {
                thead { tr style="border-bottom:1px solid var(--ink);" {
                    th style="text-align:right;padding:5px 8px;" { "#" }
                    th style="text-align:left;padding:5px 8px;" { (tr(lang, "server", "сервер")) }
                    th style="text-align:right;padding:5px 8px;" { (tr(lang, "service 24h", "сервис 24ч")) }
                    th style="text-align:right;padding:5px 8px;" { (tr(lang, "service 7d", "сервис 7д")) }
                    th style="text-align:right;padding:5px 8px;" { (tr(lang, "availability", "доступность")) }
                    th style="text-align:right;padding:5px 8px;" { (tr(lang, "loss", "потери")) }
                    th style="text-align:right;padding:5px 8px;" { "p95" }
                    th style="text-align:right;padding:5px 8px;" { (tr(lang, "control 24h", "control 24ч")) }
                } }
                tbody {
                    @for (index, (id, q24, q7)) in rows.iter().enumerate() {
                        tr data-quality-server=(id.0) style="border-bottom:1px dotted var(--rule);" {
                            td style="text-align:right;padding:5px 8px;color:var(--mute);" { (index + 1) }
                            td style="padding:5px 8px;" { a href=(format!("/admin/servers/{}", path_segment_encode(&id.0))) style="color:var(--ink);" { (id.0) } }
                            td style=(format!("text-align:right;padding:5px 8px;color:{};", quality_score_color(q24.score))) { (q24.score.map_or_else(|| "—".into(), |v| format!("{v}/100"))) }
                            td style=(format!("text-align:right;padding:5px 8px;color:{};", quality_score_color(q7.score))) { (q7.score.map_or_else(|| "—".into(), |v| format!("{v}/100"))) }
                            td style="text-align:right;padding:5px 8px;" { (q24.availability_pct.map_or_else(|| "—".into(), |v| format!("{v:.1}%"))) }
                            td style="text-align:right;padding:5px 8px;" { (q24.packet_loss_pct.map_or_else(|| "—".into(), |v| format!("{v:.1}%"))) }
                            td style="text-align:right;padding:5px 8px;" { (q24.p95_rtt_ms.map_or_else(|| "—".into(), |v| format!("{v} ms"))) }
                            td style="text-align:right;padding:5px 8px;" { (q24.control_score.map_or_else(|| "—".into(), |v| format!("{v}/100"))) }
                        }
                    }
                }
            }
        }
    }
}

fn server_detail_quality_section(
    q24: Option<&vpnctl_inventory::ServiceQualityScore>,
    q7: Option<&vpnctl_inventory::ServiceQualityScore>,
    history: &[vpnctl_inventory::ServiceQualitySample],
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    let Some(q24) = q24 else {
        return html! {};
    };
    html! {
        section id="server-quality" style="margin-top:18px;" {
            div.ed-art-eyebrow { (tr(lang, "Quality · service path", "Качество · service path")) }
            p style="font-family:var(--serif);font-style:italic;font-size:12px;color:var(--mute);margin:4px 0 12px;" {
                (tr(lang, "Small TCP probes to real declared ingress ports from ", "Небольшие TCP-пробы реальных объявленных ingress-портов из "))
                span.ed-mono { (q24.vantage.as_deref().unwrap_or("unknown")) }
                " · " (history.len()) " " (tr(lang, "samples in 24h", "замеров за 24ч"))
            }
            div style="display:flex;gap:10px;flex-wrap:wrap;font-family:var(--mono);font-size:11px;" {
                span { "24h " b style=(format!("color:{};", quality_score_color(q24.score))) { (q24.score.map_or_else(|| "—".into(), |v| format!("{v}/100"))) } }
                span { "7d " b style=(format!("color:{};", quality_score_color(q7.and_then(|q| q.score)))) { (q7.and_then(|q| q.score).map_or_else(|| "—".into(), |v| format!("{v}/100"))) } }
                span { (tr(lang, "availability ", "доступность ")) (q24.availability_pct.map_or_else(|| "—".into(), |v| format!("{v:.1}%"))) }
                span { (tr(lang, "loss ", "потери ")) (q24.packet_loss_pct.map_or_else(|| "—".into(), |v| format!("{v:.1}%"))) }
                span { "p95 " (q24.p95_rtt_ms.map_or_else(|| "—".into(), |v| format!("{v} ms"))) }
                span { "control " (q24.control_score.map_or_else(|| "—".into(), |v| format!("{v}/100"))) }
            }
        }
    }
}

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
                    (dec) " " (crate::i18n::noun_for(lang, dec, "probe", "probes", "проба", "пробы", "проб"))
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

fn dashboard_live_activity_from_rows(
    servers: &[vpnctl_core::Server],
    active_conns: &[(vpnctl_core::ServerId, Option<usize>)],
    rows: &[vpnctl_inventory::VpnStatsRow],
    window: VpnSparklineWindow,
) -> Vec<(vpnctl_core::ServerId, vpnctl_inventory::ServerLiveActivity)> {
    use chrono::{DurationRound, TimeDelta, Utc};

    let bucket_seconds = i64::from(window.bucket_hours) * 3600;
    let now = Utc::now()
        .duration_trunc(TimeDelta::seconds(bucket_seconds))
        .ok();
    let oldest = now.map(|end| {
        end - TimeDelta::seconds(i64::from(window.cells.saturating_sub(1)) * bucket_seconds)
    });

    let mut by_server: std::collections::HashMap<
        vpnctl_core::ServerId,
        vpnctl_inventory::ServerLiveActivity,
    > = servers
        .iter()
        .map(|server| {
            (
                server.id.clone(),
                vpnctl_inventory::ServerLiveActivity::default(),
            )
        })
        .collect();

    if let (Some(oldest), Some(now)) = (oldest, now) {
        for row in rows {
            let Ok(row_bucket) = row.ts.duration_trunc(TimeDelta::seconds(bucket_seconds)) else {
                continue;
            };
            if row_bucket < oldest || row_bucket > now {
                continue;
            }
            let Some(activity) = by_server.get_mut(&row.server_id) else {
                continue;
            };
            let is_latest = activity.last_sample_ts.is_none_or(|last| row.ts > last);
            activity.bytes_up_window = activity.bytes_up_window.saturating_add(row.upload_bytes);
            activity.bytes_dn_window = activity.bytes_dn_window.saturating_add(row.download_bytes);
            if is_latest {
                activity.last_sample_ts = Some(row.ts);
                activity.active_now = row.active_connections;
            }
        }
    }

    // A fresh in-memory snapshot is more authoritative than the persisted
    // aggregate. Missing/stale cache entries fall back to the latest row.
    for (server_id, count) in active_conns {
        if let (Some(activity), Some(count)) = (by_server.get_mut(server_id), count) {
            activity.active_now = u32::try_from(*count).unwrap_or(u32::MAX);
        }
    }

    servers
        .iter()
        .map(|server| {
            (
                server.id.clone(),
                by_server.remove(&server.id).unwrap_or_default(),
            )
        })
        .collect()
}

/// Phase 4b — dashboard «VPN activity» tile. Sums the already-loaded
/// chart buckets per server and shows total bytes, active conns now,
/// and the per-server breakdown.
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
                table style="width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 11px;" {
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
// `internal_error` and `error_text` moved to helpers.rs

/// Phase F monitoring page. Pulls hourly + daily access buckets from
/// `sub_access_log`, gap-fills, renders two inline-SVG sparklines
/// (hits + distinct IPs) plus headline KPIs. No JS — pure SSR.
pub(crate) async fn monitoring(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<Markup, Response> {
    use crate::i18n::tr;
    let (theme, accent, lang) = theme_accent_lang(&headers);

    // Design v2 3a — the monitoring page IS the fleet-health surface:
    // six status tiles, per-node uptime, 24h resource trends, the
    // monitor's real thresholds, probe failures and the GeoIP DB age.
    // The former sub-access analytics moved out (the aggregate JSON
    // stays at /api/v1/stats/sub-access; heavy-users live on the
    // dashboard's Activity tab).
    let servers = state
        .inv
        .list_servers()
        .await
        .map_err(|e| internal_error(anyhow::Error::new(e)))?;

    let mut latest: Vec<(vpnctl_core::Server, Option<vpnctl_inventory::NodeHealthRow>)> =
        Vec::with_capacity(servers.len());
    let mut uptimes: Vec<[Option<vpnctl_inventory::UptimeStat>; 3]> =
        Vec::with_capacity(servers.len());
    let mut trends: Vec<Vec<vpnctl_inventory::NodeHealthRow>> = Vec::with_capacity(servers.len());
    for s in &servers {
        let h = state.inv.latest_node_health(&s.id).await.unwrap_or(None);
        let u24 = state.inv.uptime_for_server(&s.id, 24).await.ok();
        let u7 = state.inv.uptime_for_server(&s.id, 24 * 7).await.ok();
        let u30 = state.inv.uptime_for_server(&s.id, 24 * 30).await.ok();
        let t = state
            .inv
            .recent_node_health_for_server(&s.id, 24)
            .await
            .unwrap_or_default();
        latest.push((s.clone(), h));
        uptimes.push([u24, u7, u30]);
        trends.push(t);
    }
    let kernel_versions = state.inv.kernel_versions_fleet().await.unwrap_or_default();
    let alerts_by_kind = state
        .inv
        .alerts_by_kind_severity()
        .await
        .unwrap_or_default();
    let recent_all_alerts = state.inv.recent_alerts(50, true).await.unwrap_or_default();

    // ── tile aggregates ──────────────────────────────────────────────
    let probeable_total = latest.len();
    let up_count = latest
        .iter()
        .filter(|(_, h)| h.as_ref().and_then(|h| h.sing_box_active) == Some(true))
        .count();
    let open_total: u64 = alerts_by_kind.iter().map(|(_, _, n)| *n).sum();
    let open_sub_access: u64 = alerts_by_kind
        .iter()
        .filter(|(k, _, _)| k.starts_with("sub_access."))
        .map(|(_, _, n)| *n)
        .sum();
    let open_node = open_total.saturating_sub(open_sub_access);
    let worst_mem: Option<(u8, &str)> = latest
        .iter()
        .filter_map(|(s, h)| h.as_ref().and_then(pct_mem).map(|p| (p, s.id.0.as_str())))
        .max_by_key(|(p, _)| *p);
    let worst_disk: Option<(u8, &str)> = latest
        .iter()
        .filter_map(|(s, h)| h.as_ref().and_then(pct_disk).map(|p| (p, s.id.0.as_str())))
        .max_by_key(|(p, _)| *p);
    let worst_log_mib: Option<(u64, &str)> = latest
        .iter()
        .filter_map(|(s, h)| {
            h.as_ref()
                .and_then(|h| h.sing_box_log_bytes)
                .map(|b| (b / (1024 * 1024), s.id.0.as_str()))
        })
        .max_by_key(|(m, _)| *m);
    let majority_version = fleet_majority_version(&kernel_versions);
    let drifted: Vec<(&str, String)> = kernel_versions
        .iter()
        .filter_map(|(id, j)| {
            let v = sing_box_version_of(j.as_deref())?;
            if majority_version.as_ref() != Some(&v) {
                let (sid, _) = latest
                    .iter()
                    .find(|(s, _)| s.id == *id)
                    .map(|(s, h)| (s.id.0.as_str(), h))?;
                Some((sid, v))
            } else {
                None
            }
        })
        .collect();
    let probes_24h: u64 = uptimes
        .iter()
        .filter_map(|u| u[0].as_ref())
        .map(|s| s.total_rows)
        .sum();
    let last_sweep = latest
        .iter()
        .filter_map(|(_, h)| h.as_ref().map(|h| h.ts))
        .max();
    let probe_tick_min = std::env::var("VPNCTLD_NODE_PROBE_INTERVAL_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(600)
        / 60;
    let now = chrono::Utc::now();
    let has_open = |kind: &str| -> bool { alerts_by_kind.iter().any(|(k, _, _)| k == kind) };
    // Probe failures — the unreachable alerts (open OR acked) from the
    // last 7 days; recovery events show as the acked state.
    let probe_failures: Vec<&vpnctl_inventory::AdminAlert> = recent_all_alerts
        .iter()
        .filter(|a| {
            a.kind.starts_with("server.unreachable")
                && (now - a.created_at) < chrono::Duration::days(7)
        })
        .collect();
    let geoip = geoip_db_stat();

    let mem_watermark_note = format!(
        "{} · {} {}%",
        worst_mem.map(|(_, sid)| sid).unwrap_or("—"),
        tr(lang, "alert at", "алерт от"),
        crate::health_monitor::MEM_PRESSURE_TRIGGER_PCT,
    );
    let disk_watermark_note = format!(
        "{} · {} {}%",
        worst_disk.map(|(_, sid)| sid).unwrap_or("—"),
        tr(lang, "alert at", "алерт от"),
        crate::health_monitor::DISK_PRESSURE_TRIGGER_PCT,
    );

    let body = html! {
        div.ed-art-eyebrow { (crate::i18n::t(lang, crate::i18n::K::PageMonitoring)) }
        div.ed-headrow {
            h1.ed-sumbar__h { (tr(lang, "Fleet ", "Здоровье ")) em { (tr(lang, "health", "флота")) } }
            span.ed-tip title=(tr(
                lang,
                "node_probe runs on a fixed tick over SSH: service state per kernel, disk/mem/load, log sizes, listening ports. Unknown probes are excluded from uptime denominators.",
                "node_probe ходит по SSH с фиксированным тиком: состояние сервисов по каждому ядру, диск/память/load, размеры логов, слушающие порты. Неопределённые пробы не входят в знаменатель uptime.",
            )) { "ⓘ" }
            span style="font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                (probeable_total) " " (tr(lang, "nodes", "нод"))
                " · " (tr(lang, "probe tick ", "тик проб ")) (probe_tick_min) " " (tr(lang, "min", "мин"))
                @if let Some(ts) = last_sweep {
                    " · " (tr(lang, "last sweep ", "последний обход "))
                    (humanize_age(now - ts, lang))
                }
            }
            div.ed-headrow__actions {
                form method="post" action="/admin/monitoring/probe-all" {
                    button type="submit"
                           class="ed-abtn ed-abtn--secondary ed-abtn--sm"
                           title=(tr(
                               lang,
                               "Runs the full probe sweep immediately instead of waiting for the next tick. SSH into every node — takes a few seconds per node; a down node adds its connect timeout.",
                               "Запускает полный обход проб немедленно, не дожидаясь следующего тика. SSH на каждую ноду — несколько секунд на ноду; упавшая нода добавляет свой connect-timeout.",
                           )) {
                        (tr(lang, "probe all now", "опросить все сейчас"))
                    }
                }
            }
        }

        div.ed-status-strip style="margin-top: 12px;" {
            (status_tile_with_warn(
                tr(lang, "fleet", "флот"),
                &format!("{up_count} / {probeable_total} up"),
                if up_count == probeable_total { "var(--green)" } else { "var(--red)" },
                up_count != probeable_total,
            ))
            (status_tile_with_warn(
                tr(lang, "open alerts", "открытых алертов"),
                &open_total.to_string(),
                "var(--ink)",
                open_total > 0,
            ))
            (status_tile_with_warn(
                tr(lang, "mem peak", "пик памяти"),
                &worst_mem.map(|(p, _)| format!("{p}%")).unwrap_or("—".into()),
                "var(--ink)",
                worst_mem.is_some_and(|(p, _)| p > 70),
            ))
            (status_tile_with_warn(
                tr(lang, "disk peak", "пик диска"),
                &worst_disk.map(|(p, _)| format!("{p}%")).unwrap_or("—".into()),
                "var(--ink)",
                worst_disk.is_some_and(|(p, _)| p > 70),
            ))
            (status_tile_with_warn(
                tr(lang, "version drift", "дрейф версий"),
                &match drifted.len() {
                    0 => tr(lang, "in sync", "синхронно").to_string(),
                    n => format!("{n} {}", tr(lang, "node(s)", "нод")),
                },
                "var(--ink)",
                !drifted.is_empty(),
            ))
            (status_tile_with_warn(
                tr(lang, "probes 24h", "проб за 24ч"),
                &probes_24h.to_string(),
                "var(--ink)",
                false,
            ))
        }
        div style="font-family: var(--mono); font-size: 10px; color: var(--mute); margin: -12px 0 4px;" {
            (tr(lang, "open: ", "открыто: ")) (open_sub_access) " sub-access · " (open_node) " node"
            " — " (tr(lang, "mem: ", "память: ")) (mem_watermark_note)
            " — " (tr(lang, "disk: ", "диск: ")) (disk_watermark_note)
            @if let Some((sid, v)) = drifted.first() {
                " — " (tr(lang, "drift: ", "дрейф: ")) (sid) " · " (v) " ≠"
            }
        }

        section style="margin-top: 14px;" {
            div.ed-art-eyebrow {
                (tr(lang, "Uptime · sing-box service", "Uptime · сервис sing-box")) " "
                span.ed-tip title=(tr(
                    lang,
                    "Rolling-window aggregate over sing_box_active from the node_probe poller. «up» = the service reports active at probe time; unknown probes are excluded from the denominator.",
                    "Скользящие окна sing_box_active от node_probe-поллера. «up» = сервис показал active в момент пробы; неопределённые пробы не входят в знаменатель.",
                )) { "ⓘ" }
            }
            table.ed-grid style="margin-top: 8px;" {
                thead {
                    tr {
                        th { (tr(lang, "server", "сервер")) }
                        th.num { "24h" }
                        th.num { "7d" }
                        th.num { "30d" }
                        th.num { (tr(lang, "probes 30d", "проб за 30д")) }
                        th { (tr(lang, "last incident", "последний инцидент")) }
                        th {}
                    }
                }
                tbody {
                    @for (i, (s, h)) in latest.iter().enumerate() {
                        @let [u24, u7, u30] = &uptimes[i];
                        @let mem_hot = h.as_ref().and_then(pct_mem).is_some_and(|p| p > 70);
                        @let detail_href = format!("/admin/servers/{}", path_segment_encode(&s.id.0));
                        @let pct_cell = |u: &Option<vpnctl_inventory::UptimeStat>| -> Markup {
                            match u.as_ref().and_then(|u| u.uptime_pct) {
                                Some(p) => html! {
                                    span style=(format!("color: {};", pct_color(Some(p)))) { (p) "%" }
                                },
                                None => html! { span.ed-grid__mut { "—" } },
                            }
                        };
                        tr class=(if mem_hot { "on-warn" } else { "" }) {
                            td {
                                a.ed-grid__id href=(detail_href) { (s.id.0) }
                                @if mem_hot {
                                    " " span.ed-grid__flag title=(tr(lang, "Memory above the 70% heat watermark", "Память выше тепловой отметки 70%")) { "⚠" }
                                }
                            }
                            td.num { b { (pct_cell(u24)) } }
                            td.num { (pct_cell(u7)) }
                            td.num { (pct_cell(u30)) }
                            td.num.ed-grid__mut {
                                (u30.as_ref().map(|u| u.total_rows).unwrap_or(0))
                            }
                            td.ed-grid__mut.ed-grid__sm {
                                @match u30.as_ref().and_then(|u| u.last_outage_at) {
                                    Some(ts) => (format_msk_iso(ts)),
                                    None => "—",
                                }
                            }
                            td.num { a.ed-grid__open href=(detail_href) { (tr(lang, "open →", "открыть →")) } }
                        }
                    }
                }
            }
        }

        section style="margin-top: 18px;" {
            div.ed-art-eyebrow {
                (tr(lang, "Resource trend · last 24h", "Тренд ресурсов · последние 24ч")) " "
                span.ed-tip title=(tr(
                    lang,
                    "10-min probe snapshots, oldest → newest. A climbing line = slow leak; flat with one spike = transient burst. A warm max = the metric crossed its watermark inside the window.",
                    "10-минутные снимки проб, старое → новое. Растущая линия = медленная утечка; плоская с одним пиком = кратковременный всплеск. Тёплый max = метрика пересекла отметку внутри окна.",
                )) { "ⓘ" }
            }
            table.ed-grid style="margin-top: 8px;" {
                thead {
                    tr {
                        th style="width: 70px;" { (tr(lang, "server", "сервер")) }
                        th { (tr(lang, "disk %", "диск %")) }
                        th { (tr(lang, "mem %", "память %")) }
                        th { "sing-box log MiB" }
                        th.num style="width: 90px;" { (tr(lang, "1-min load", "load 1мин")) }
                    }
                }
                tbody {
                    @for (i, (s, h)) in latest.iter().enumerate() {
                        @let rows = &trends[i];
                        @let chron: Vec<&vpnctl_inventory::NodeHealthRow> = rows.iter().rev().collect();
                        @let disk_series: Vec<f64> = chron.iter().filter_map(|r| {
                            let (u, t) = (r.disk_used_mib?, r.disk_total_mib?);
                            if t == 0 { None } else { Some(u as f64 * 100.0 / t as f64) }
                        }).collect();
                        @let mem_series: Vec<f64> = chron.iter().filter_map(|r| {
                            let (a, t) = (r.mem_available_mib?, r.mem_total_mib?);
                            if t == 0 { None } else { Some(100.0 - a as f64 * 100.0 / t as f64) }
                        }).collect();
                        @let log_series: Vec<f64> = chron.iter().filter_map(|r| {
                            r.sing_box_log_bytes.map(|b| b as f64 / (1024.0 * 1024.0))
                        }).collect();
                        @let fmax = |v: &[f64]| v.iter().copied().reduce(f64::max).unwrap_or(0.0);
                        @let (dmax, mmax, lmax) = (fmax(&disk_series), fmax(&mem_series), fmax(&log_series));
                        @let load = h.as_ref().and_then(|h| h.load_1min_x100).map(|l| format!("{:.2}", l as f64 / 100.0));
                        @let cell = |series: &[f64], max: f64, warm: bool, unit: &str| -> Markup {
                            // % series get the fixed 0–100 axis; the
                            // MiB series auto-scales (shape only). The
                            // caption below is the max label, so the
                            // in-SVG one is off.
                            let y_max = if unit == "%" { Some(100.0) } else { None };
                            html! {
                                @if series.is_empty() {
                                    span.ed-grid__mut { "—" }
                                } @else {
                                    (sparkline_svg_scaled(series, 200, 30, y_max, false))
                                    div style=(if warm { "font-family: var(--mono); font-size: 10px; color: var(--warm); font-weight: 600;" } else { "font-family: var(--mono); font-size: 10px; color: var(--mute);" }) {
                                        "max " b { (format!("{max:.0}")) } (unit)
                                        @if warm { " ⚠" }
                                    }
                                }
                            }
                        };
                        tr {
                            td { a.ed-grid__id href=(format!("/admin/servers/{}", path_segment_encode(&s.id.0))) { (s.id.0) } }
                            td { (cell(&disk_series, dmax, dmax > 70.0, "%")) }
                            td { (cell(&mem_series, mmax, mmax > 70.0, "%")) }
                            td { (cell(&log_series, lmax, lmax > 500.0, " MiB")) }
                            td.num {
                                @match load {
                                    Some(l) => (l),
                                    None => span.ed-grid__mut { "—" },
                                }
                            }
                        }
                    }
                }
            }
        }

        div.ed-dash-cols {
            div {
                div.ed-art-eyebrow {
                    (tr(lang, "Alert thresholds", "Пороги алертов")) " "
                    span.ed-tip title=(tr(
                        lang,
                        "Watermarks the health monitor evaluates on every probe. Crossing one opens an alert; recovery auto-resolves it (with hysteresis on disk/mem). The 70% warm tint in tables is a visual watermark only — alerts fire at the values below.",
                        "Отметки, которые монитор здоровья проверяет на каждой пробе. Пересечение открывает алерт; восстановление закрывает его само (с гистерезисом на диске/памяти). Тёплые ячейки от 70% в таблицах — только визуальная отметка; алерты срабатывают на значениях ниже.",
                    )) { "ⓘ" }
                }
                table.ed-grid style="margin-top: 8px;" {
                    thead {
                        tr {
                            th { (tr(lang, "metric", "метрика")) }
                            th.num { (tr(lang, "warn at", "порог")) }
                            th.num { (tr(lang, "worst now", "худшее сейчас")) }
                            th { (tr(lang, "where", "где")) }
                            th { (tr(lang, "state", "состояние")) }
                        }
                    }
                    tbody {
                        @let state_cell = |open: bool| -> Markup {
                            if open {
                                html! { span style="color: var(--warm);" { "⚠ " (tr(lang, "open", "открыт")) } }
                            } else {
                                html! { span style="color: var(--green);" { "ok" } }
                            }
                        };
                        tr {
                            td { "mem_used_pct" }
                            td.num { (crate::health_monitor::MEM_PRESSURE_TRIGGER_PCT) "%" }
                            td class=(if worst_mem.is_some_and(|(p, _)| p > 70) { "num warn" } else { "num" }) {
                                (worst_mem.map(|(p, _)| format!("{p}%")).unwrap_or("—".into()))
                            }
                            td.ed-grid__mut { (worst_mem.map(|(_, s)| s).unwrap_or("—")) }
                            td { (state_cell(has_open("server.mem.pressure"))) }
                        }
                        tr {
                            td { "disk_used_pct" }
                            td.num { (crate::health_monitor::DISK_PRESSURE_TRIGGER_PCT) "%" }
                            td class=(if worst_disk.is_some_and(|(p, _)| p > 70) { "num warn" } else { "num" }) {
                                (worst_disk.map(|(p, _)| format!("{p}%")).unwrap_or("—".into()))
                            }
                            td.ed-grid__mut { (worst_disk.map(|(_, s)| s).unwrap_or("—")) }
                            td { (state_cell(has_open("server.disk.pressure"))) }
                        }
                        tr {
                            td { "singbox_log_mib" }
                            td.num { (crate::health_monitor::SINGBOX_LOG_TRIGGER_BYTES / (1024 * 1024)) }
                            td class=(if worst_log_mib.is_some_and(|(m, _)| m > 500) { "num warn" } else { "num" }) {
                                (worst_log_mib.map(|(m, _)| m.to_string()).unwrap_or("—".into()))
                            }
                            td.ed-grid__mut { (worst_log_mib.map(|(_, s)| s).unwrap_or("—")) }
                            td { (state_cell(has_open("server.singbox.log.too_big"))) }
                        }
                        tr {
                            td { "unreachable" }
                            td.num {
                                (crate::node_probe_poller::DEFAULT_UNREACHABLE_THRESHOLD)
                                (tr(lang, "× fails", "× сбоя"))
                            }
                            td.num { (probeable_total - up_count) }
                            td.ed-grid__mut { (tr(lang, "fleet", "флот")) }
                            td { (state_cell(has_open("server.unreachable"))) }
                        }
                        tr {
                            td { "version_drift" }
                            td.num { (tr(lang, "any", "любой")) }
                            td class=(if drifted.is_empty() { "num" } else { "num warn" }) { (drifted.len()) }
                            td.ed-grid__mut {
                                @match drifted.first() {
                                    Some((sid, _)) => (sid),
                                    None => "—",
                                }
                            }
                            td {
                                @if drifted.is_empty() { (state_cell(false)) }
                                @else { span style="color: var(--warm);" { "≠ " (tr(lang, "drifted", "дрейф")) } }
                            }
                        }
                    }
                }
            }
            div {
                div.ed-art-eyebrow {
                    (tr(lang, "Probe failures · 7d", "Сбои проб · 7д"))
                    " · " (probe_failures.len()) " " (tr(lang, "events", "событий"))
                }
                @if probe_failures.is_empty() {
                    p.ed-grid__mut style="font-family: var(--serif); font-style: italic; font-size: 12px;" {
                        (tr(lang, "No probe failures in the last 7 days.", "За последние 7 дней сбоев проб не было."))
                    }
                } @else {
                    table.ed-feed style="margin-top: 8px;" {
                        tbody {
                            @for a in &probe_failures {
                                tr {
                                    td.ed-grid__mut style="width: 110px;" { (a.created_at.format("%m-%d %H:%M").to_string()) }
                                    td {
                                        @match &a.server_id {
                                            Some(sid) => a href=(format!("/admin/servers/{}", path_segment_encode(&sid.0))) { (sid.0) },
                                            None => span.ed-grid__mut { "—" },
                                        }
                                    }
                                    td.ed-grid__mut.ed-grid__sm { (a.summary) }
                                    td.num {
                                        @if a.acked_at.is_some() { span style="color: var(--green);" { "✓" } }
                                        @else { span style="color: var(--warm);" { "⚠" } }
                                    }
                                }
                            }
                        }
                    }
                }
                div style="border-top: 1px solid var(--rule); margin: 14px 0 10px;" {}
                div.ed-art-eyebrow {
                    (tr(lang, "GeoIP DB", "База GeoIP")) " "
                    span.ed-tip title=(tr(
                        lang,
                        "MMDB city+ASN files enrich every new sub_access_log row offline. Refresh from Settings — new DBs load on next vpnctld restart.",
                        "MMDB-файлы city+ASN обогащают каждую новую строку sub_access_log оффлайн. Обновление — в Настройках; новые базы подхватываются при рестарте vpnctld.",
                    )) { "ⓘ" }
                }
                div style="font-family: var(--mono); font-size: 11px; color: var(--mute); margin-top: 6px;" {
                    "city db "
                    @match &geoip.city_mtime {
                        Some(m) => b { (m) },
                        None => (tr(lang, "missing", "нет")),
                    }
                    " · asn db "
                    @match &geoip.asn_mtime {
                        Some(m) => b { (m) },
                        None => (tr(lang, "missing", "нет")),
                    }
                    " · "
                    a href="/admin/settings/system#geoip" style="color: var(--acc);" {
                        (tr(lang, "update in Settings →", "обновить в Настройках →"))
                    }
                }
            }
        }
    };
    Ok(render_page(&state, "monitoring", &theme, &accent, lang, body).await)
}

/// Design v2 3a — «probe all now». Runs the SAME per-server probe the
/// poller runs on its tick, immediately, then bounces back to the
/// monitoring page (whose tables re-read the freshly written
/// node_health rows). Sequential SSH — a few seconds per node; a down
/// node adds its connect timeout. Alert state-machines stay with the
/// background monitor; this only refreshes the data.
pub(crate) async fn monitoring_probe_all(
    State(state): State<AppState>,
) -> Result<Response, Response> {
    let servers = state
        .inv
        .list_servers()
        .await
        .map_err(|e| internal_error(anyhow::Error::new(e)))?;
    let mut probed = 0u32;
    for s in &servers {
        let outcome = crate::node_probe_poller::probe_one_server(&state.inv, s).await;
        tracing::info!(
            target = "vpnctld::admin",
            server = %s.id.0,
            ?outcome,
            "manual probe sweep (monitoring page)"
        );
        probed += 1;
    }
    let _ = state
        .inv
        .audit(
            "admin",
            "monitoring.probe_all",
            None,
            Some(&serde_json::json!({ "servers": probed })),
        )
        .await;
    Ok(axum::response::Redirect::to("/admin/monitoring").into_response())
}

/// Inline-SVG sparkline. Pure SSR — width/height pinned, no JS,
/// stroke uses `var(--acc)` so the accent toggle in the Tweaks panel
/// recolours every chart on the page consistently.
/// The sparkline renderer. (The unlabelled legacy wrapper
/// `sparkline_svg` was deleted in R2 once its last caller learned to
/// pass an explicit axis + caption.)
///
/// * `y_max = Some(cap)` pins the y-axis — **percent series pass 100**
///   so a flat 28 % disk line sits at 28 % of the box height instead of
///   gluing to the top edge and reading as "maxed out" (design review
///   2026-07-10). `None` auto-scales to the window max (byte/MiB
///   series, where only the shape matters).
/// * `label_max = false` drops the in-SVG "max N" corner text for
///   callers that render their own max caption under the chart —
///   previously both rendered and disagreed by one (SVG truncated,
///   caption rounded: «max 51» inside, «max 52%» below).
fn sparkline_svg_scaled(
    values: &[f64],
    width: u32,
    height: u32,
    y_max: Option<f64>,
    label_max: bool,
) -> Markup {
    if values.is_empty() {
        return html! {
            p style="font-family: var(--serif); font-style: italic; color: var(--mute); padding: 6px 0;" {
                "(no data in window)"
            }
        };
    }
    let data_max = values.iter().cloned().fold(0.0_f64, f64::max);
    let scale = y_max.unwrap_or(data_max).max(1.0);
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
            // min(1.0) guards a >cap outlier (e.g. % rounding artifacts)
            // from drawing outside the box.
            let y = 2.0 + h - (v / scale).min(1.0) * h;
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
            @if label_max {
                // Right-side max-value label so operator can read the
                // peak. Rounded (not truncated) so it always agrees
                // with any {:.0}-formatted caption of the same series.
                text x=(width - 4) y="14"
                     text-anchor="end"
                     style="font-family: var(--mono); font-size: 10px; fill: var(--mute);" {
                    "max " (data_max.round() as u64)
                }
            }
        }
    }
}

/// Editorial server card — one per row, matches `.ed-server` from the
// `fp_short`, `server_row`, and `servers` moved to servers.rs

/// Build the canonical sub URL the QR encodes. Uses the request's `Host`
/// header so the QR is reachable from wherever the operator opened the
/// admin from (LAN IP, VPN IP, or the external one when we add reverse
/// proxy). Defaults to a sensible LAN guess if the header is missing —
/// rare in practice, but not worth crashing over.
pub(crate) fn sub_url(headers: &HeaderMap, sub_token: &str) -> String {
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
pub(crate) fn ninitux_url(device_id: &str) -> Option<String> {
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
/// The textarea carries `data-select-on-click` (admin.js delegated
/// listener) so a single click selects the full link — the old inline
/// `onclick` was refused by the CSP and silently did nothing. Avoids
/// the Clipboard API which requires a secure context (HTTPS or
/// localhost) — the admin UI runs over plain HTTP on the homelab LAN,
/// so navigator.clipboard would silently fail on 192.168.0.236.
/// Triple-click is the JS-free fallback every browser supports; the
/// `title` attribute spells out both interactions.
pub(crate) fn share_link_card(link: &str, footnote: &Markup) -> Markup {
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
                         data-select-on-click
                         title="Click to select the full link (or triple-click if JS is disabled), then Ctrl+C / Cmd+C to copy"
                         style="width: 100%; padding: 8px 10px; font-family: var(--mono); font-size: 10px; line-height: 1.45; color: var(--ink); background: var(--paper); border: 1px solid var(--rule); resize: vertical; word-break: break-all; box-sizing: border-box;" {
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

pub(crate) fn qr_svg(url: &str) -> Markup {
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

pub(crate) fn collect_amnezia_links(
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
pub(crate) fn collect_awg_links(
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

pub(crate) fn collect_share_links(
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
pub(crate) async fn user_online_badge(
    state: &AppState,
    uid: &vpnctl_core::UserId,
    server_ids: &[vpnctl_core::ServerId],
    last_seen: Option<chrono::DateTime<chrono::Utc>>,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
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
        // `get_live`: the 🟢 online badge must NOT light up from a
        // snapshot the poller stopped refreshing (~2 intervals stale).
        let Some(snap) = state.snapshot_cache.get_live(sid) else {
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
        @if online {
            @let server_count = conns_per_server.len();
            @let server_list = conns_per_server
                .keys()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ");
            span.ed-stat.ed-stat--active
                title=(tr(
                    lang,
                    "Presence — live from each node's clash-api snapshot (≤5 min old). NM-11 fallback attributes unresolved connections by source IP; unseen IPs remain uncounted.",
                    "Присутствие — live-снимок clash-api каждой ноды (не старше 5 мин). NM-11 fallback атрибутирует соединения по source IP; незнакомые IP не учитываются.",
                )) {
                span.ed-stat__dot {}
                b { (tr(lang, "online", "онлайн")) }
                " · " (total_conns) " "
                @if total_conns == 1 { (tr(lang, "conn", "соединение")) }
                @else { (tr(lang, "conns", "соединений")) }
                " "
                @if server_count == 1 { (tr(lang, "on ", "на ")) }
                @else { (tr(lang, "across ", "на ")) }
                span.ed-mono { (server_list) }
            }
        } @else {
            span.ed-stat.ed-stat--unknown
                title=(tr(lang, "Presence — no live connection in the latest clash-api snapshots.", "Присутствие — в последних снимках clash-api нет активных соединений.")) {
                span.ed-stat__dot {}
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

pub(crate) fn user_is_likely_shared(
    aggregates: &vpnctl_inventory::SubAccessAggregates,
    ua_clusters: &[vpnctl_inventory::UaCluster],
) -> bool {
    aggregates.distinct_asns >= 3
        || ua_clusters.iter().any(|c| {
            matches!(
                ua_verdict(c.distinct_ips, c.distinct_slash16),
                UaVerdict::LikelyShared
            )
        })
}

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

/// Shared th/td inline styles for the origins tables (survived the R2
/// removal of the legacy verdict section that used to sit above them).
const ORIGINS_TH: &str = "padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;";
const ORIGINS_TD: &str = "padding: 5px 8px;";

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
pub(crate) fn user_subscription_origins_section(
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
            // TT-5: the old estimate was max(device_class, UA, JA4).
            // JA4 is ALWAYS 0 (no JA4-forwarding proxy is wired), so
            // «· 0 TLS-fingerprints» was permanent dead noise that read
            // as a broken feature — dropped. UA over-counts (every app
            // version is a distinct string); device_class collapses that
            // churn (4 Streisand builds → 1) but under-counts because
            // the parser leaves the custom ninitux client NULL. So we
            // lead with device_class when we have it (labelled honestly
            // as «client families»), fall back to the raw UA count
            // otherwise, and always show the raw UA count as the upper
            // bound — never a single false-precision «≈N devices».
            @let has_families = device_fp.distinct_device_classes > 0;
            @let lead_n = if has_families { device_fp.distinct_device_classes } else { device_fp.distinct_uas };
            p style="font-family: var(--mono); font-size: 12px; color: var(--ink); margin: 0 0 16px;" {
                "≈ " b { (lead_n) } " "
                @if has_families { (tr(lang, "client families", "клиентских семейств")) }
                @else { (tr(lang, "distinct user-agents", "уникальных user-agent")) }
                " "
                span.ed-tip title=(tr(
                    lang,
                    "«Client families» collapse app-version churn — four Streisand builds count as one client. The raw user-agent count is the upper bound (each version is a distinct string). Clients the UA parser doesn't recognise (the custom ninitux app) leave device_class NULL, so families under-count. TLS fingerprints (JA4) aren't captured — no fingerprint-forwarding proxy is wired.",
                    "«Клиентские семейства» схлопывают версии приложения — четыре сборки Streisand считаются одним клиентом. Сырое число user-agent — верхняя граница (каждая версия — отдельная строка). Клиенты, которых парсер UA не узнаёт (кастомный ninitux), оставляют device_class NULL, поэтому семейства недосчитывают. TLS-отпечатки (JA4) не снимаются — прокси с их форвардингом не подключён.",
                )) { "ⓘ" }
                @if has_families {
                    " " span style="color: var(--mute);" {
                        "(" (device_fp.distinct_uas) " " (tr(lang, "distinct UA", "уник. UA")) ")"
                    }
                }
            }

            // ── By country ───────────────────────────────────────────
            div.ed-art-eyebrow style="margin-top: 4px;" {
                (tr(lang, "By country", "По странам"))
            }
            table style="width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 11px; margin-bottom: 18px;" {
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
            table style="width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 11px; margin-bottom: 18px;" {
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
            table style="width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 11px;" {
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
/// Per-(user, source_ip) activity over the last 30 days from the
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
pub(crate) fn user_source_ips_section(
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
        div.ed-art-eyebrow id="source-ips" {
            (tr(lang, "Source IPs · last 30 days", "Source IP · 30 дней"))
        }
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
                    "Which client IPs this user actually connected FROM (real VPN connections, not /sub fetches), over the last 30 days. Activity-weighted: hits = 5-min ticks the IP was live, not bytes. Private / LAN / CGNAT addresses are labelled rather than left as «(unknown)». Many distinct public IPs or countries = the strongest grounded sharing signal.",
                    "С каких клиентских IP юзер реально подключался (реальные VPN-соединения, не обращения к /sub) за 30 дней. Взвешено активностью: hits = 5-мин тики, в которых IP был живой, не байты. Приватные / LAN / CGNAT адреса подписаны, а не оставлены как «(неизвестно)». Много разных публичных IP или стран = самый достоверный сигнал расшаривания.",
                ))
            }
            p style="font-family: var(--mono); font-size: 12px; color: var(--ink); margin: 0 0 14px;" {
                "≈ " b { (distinct_public) } " "
                (tr(lang, "distinct public IPs · 30d", "уник. публичных IP · 30д"))
            }
            table style="width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 11px;" {
                thead {
                    tr style="border-bottom: 1px solid var(--ink);" {
                        th style=(format!("text-align: left; {ORIGINS_TH}")) { (tr(lang, "source ip", "source ip")) }
                        th style=(format!("text-align: left; {ORIGINS_TH}")) { (tr(lang, "country / ISP", "страна / ISP")) }
                        th style=(format!("text-align: right; {ORIGINS_TH}"))
                           title=(tr(lang, "Number of 5-min clash ticks where this user had a live connection from this IP. Not bytes, not connection count — activity time.", "Число 5-мин тиков clash, в которых у юзера было живое соединение с этого IP. Не байты и не число соединений — время активности.")) {
                            (tr(lang, "hits · 30d", "hits · 30д"))
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
pub(crate) async fn ua_clusters_section(
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
                    "(temporarily unavailable — please retry)"
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
        table style="width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 11px;" {
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
pub(crate) async fn user_traffic_limit_section(
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
                    (tr(lang, " — no monthly cap configured. Set one below to get the ", " — месячный лимит не задан. Задай ниже, чтобы получать "))
                    span.ed-mono { (DEFAULT_TRAFFIC_THRESHOLD_PCT) "%-" (tr(lang, "of-limit alert", "от-лимита алерт")) }
                    (tr(lang, " on the dashboard.", " на дашборде."))
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
            // bytes. 0 / empty = clear the limit. With no cap the
            // field renders EMPTY + a placeholder — a literal «0.0»
            // read as "limit is zero" (design review 2026-07-10).
            @let limit_gib_value = limit_opt
                .map(|b| format!("{:.1}", b as f64 / 1_073_741_824.0))
                .unwrap_or_default();
            input type="number" name="limit_gib" step="0.1" min="0" max="100000"
                  value=(limit_gib_value)
                  placeholder=(tr(lang, "no cap", "нет лимита"))
                  title=(tr(
                      lang,
                      "Monthly cap in GiB (upload + download summed). 0 / empty = no cap. Resets on the first of each month.",
                      "Месячный лимит в GiB (upload + download суммой). 0 / пусто = без лимита. Сбрасывается первого числа месяца.",
                  ))
                  style="max-width: 80px; padding: 4px 8px; border: 1px solid var(--rule-s); background: var(--paper); font-family: var(--mono); font-size: 12px; color: var(--ink);";
            span style="font-family: var(--mono); font-size: 11px; color: var(--mute);" { (tr(lang, "GiB / month", "GiB / месяц")) }
            label style="font-family: var(--mono); font-size: 11px; color: var(--mute); letter-spacing: 0.14em; text-transform: uppercase; margin-left: 8px;" {
                (tr(lang, "alert at", "алерт при"))
            }
            input type="number" name="threshold_pct" step="1" min="1" max="100"
                  value=(threshold_eff)
                  title=(tr(
                      lang,
                      "Fire a dashboard alert (and Telegram if configured) when used / cap >= this percent. Default 80%.",
                      "Поднять алерт на дашборде (и в Telegram, если настроен), когда израсходовано ≥ этого процента лимита. По умолчанию 80%.",
                  ))
                  style="max-width: 56px; padding: 4px 8px; border: 1px solid var(--rule-s); background: var(--paper); font-family: var(--mono); font-size: 12px; color: var(--ink);";
            span style="font-family: var(--mono); font-size: 11px; color: var(--mute);" { "%" }
            button type="submit"
                   title=(tr(
                       lang,
                       "Set both fields. 0 GiB = clear the limit (no cap).",
                       "Сохраняет оба поля. 0 GiB = снять лимит.",
                   ))
                   style="padding: 4px 12px; border: 1px solid var(--ink); background: var(--ink); color: var(--paper); font-family: var(--mono); font-size: 11px; cursor: pointer; margin-left: auto;" {
                (crate::i18n::t(lang, crate::i18n::K::BtnSave))
            }
        }
    }
}

/// Phase 5c — «Когда была активна» session timeline. Builds an
/// implicit «active from-to» window per (user, server) from the
/// 5-min clash-poll observations: consecutive ticks extend the
/// session; a gap > 15 minutes closes it. Empty until the
/// poller has run at least one tick post-Phase-5c deploy.
pub(crate) async fn user_sessions_section(
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
    // TT-4: a session is "live" if its last tick landed within ~one
    // poll interval (5-min poll + slack) of now.
    let now = chrono::Utc::now();
    let live_cutoff = chrono::Duration::minutes(6);
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow {
            (tr(lang, "Sessions · recent 20", "Сессии · последние 20"))
        }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
            (tr(
                lang,
                "Implicit «active from-to» windows per (user, server), newest activity first. Derived from 5-min clash-poll observations: consecutive ticks extend the session; a gap >15 minutes closes it and the next tick opens a new row. Because activity is sampled every 5 minutes, a window seen in a single tick renders «≤5m» (real duration unknown below that granularity). Peak conns shows the busiest snapshot during the session.",
                "Окна «активна с-по» на (юзер, сервер), свежая активность сверху. Источник — 5-минутные тики clash-poll: последовательные тики расширяют сессию, пропуск >15 минут закрывает её, следующий тик открывает новую. Активность сэмплится раз в 5 минут, поэтому окно, увиденное одним тиком, показывается как «≤5m» (точная длительность ниже этой гранулярности неизвестна). Peak conns — самый загруженный snapshot в этой сессии.",
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
            table style="width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 11px;" {
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
                        // TT-4: single-tick windows (started==last_seen)
                        // are «≤5m» not the misleading «0m» — the user
                        // WAS active, we just can't resolve below the
                        // 5-min poll granularity.
                        @let dur_str = if mins == 0 {
                            "≤5m".to_string()
                        } else if mins >= 60 {
                            format!("{}h{:02}m", mins / 60, mins % 60)
                        } else {
                            format!("{mins}m")
                        };
                        @let is_live = now.signed_duration_since(r.last_seen) < live_cutoff;
                        tr style=(if is_live { "border-bottom: 1px dotted var(--rule); background: color-mix(in oklab, var(--green) 7%, var(--paper));" } else { "border-bottom: 1px dotted var(--rule);" }) {
                            td style="padding: 4px 8px;" {
                                a href=(format!("/admin/servers/{}", crate::http_util::path_segment_encode(&r.server_id.0))) style="color: var(--ink); text-decoration: none;" { (r.server_id.0) }
                            }
                            td style="padding: 4px 8px;" { (format_msk(r.started_at)) }
                            td style="padding: 4px 8px;" {
                                (format_msk(r.last_seen))
                                @if is_live {
                                    " " span style="color: var(--green); font-weight: 600;" {
                                        "● " (tr(lang, "live", "активна"))
                                    }
                                }
                            }
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
pub(crate) async fn user_top_destinations_section(
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
            table style="width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 11px;" {
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

pub(crate) async fn live_vpn_stats_section(
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
                    (tr(lang, "(temporarily unavailable — please retry)", "(временно недоступно — повтори попытку)"))
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
            @let trend_max = trend.iter().copied().fold(0.0_f64, f64::max);
            div style="margin: 6px 0 18px;" {
                div style="font-family: var(--mono); font-size: 10px; letter-spacing: 0.14em; text-transform: uppercase; color: var(--mute); margin-bottom: 2px;" {
                    (tr(lang, "traffic trend · ", "тренд трафика · ")) (window_label)
                }
                // R2 2026-07-10: label_max off — the in-SVG label printed
                // RAW BYTES («max 84028835»); the humanized caption below
                // replaces it. Width matches the tables (was 720 ≈ half).
                (sparkline_svg_scaled(&trend, 1160, 60, None, false))
                div style="font-family: var(--mono); font-size: 10px; color: var(--mute);" {
                    (tr(lang, "max ", "макс ")) (humanize_bytes(trend_max as u64))
                    (tr(lang, " per bucket", " на интервал"))
                }
            }
        }
        @if !per_server.is_empty() {
            table style="width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 11px;" {
                thead {
                    tr style="border-bottom: 1px solid var(--ink);" {
                        th style="text-align: left; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { (tr(lang, "server", "сервер")) }
                        th title=(tr(
                            lang,
                            "Sum of upload-bytes deltas from clash-api 5-min ticks over the picked window, weighted by each node's usage coefficient. Counts everything sing-box saw on this user's auth — VLESS, TUIC, Trojan; wgturn / WireGuard NOT included (kernel-level, no clash-api visibility).",
                            "Сумма upload-дельт clash-api (тик 5 минут) за выбранное окно, взвешенная коэффициентом нагрузки ноды. Считает всё, что sing-box видел на auth этого юзера — VLESS, TUIC, Trojan; wgturn / WireGuard НЕ входят (kernel-уровень, clash-api их не видит).",
                        ))
                           style="text-align: right; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { (tr(lang, "uploaded", "отправлено")) }
                        th title=(tr(lang, "Same window + same caveats as uploaded — download direction.", "То же окно и те же оговорки, что и у «отправлено» — направление download."))
                           style="text-align: right; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { (tr(lang, "downloaded", "принято")) }
                        th style="text-align: right; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { (tr(lang, "total", "всего")) }
                        th title=(tr(
                            lang,
                            "Maximum simultaneous active connections seen for this user during any 5-min poll window. >50 from a phone client = unusual (chat apps + browser keep ~5-15 sustained); >200 typically means torrent / web-crawler.",
                            "Максимум одновременных соединений юзера в любом 5-минутном окне поллера. >50 с телефона — необычно (мессенджеры + браузер держат ~5-15); >200 — обычно торрент / краулер.",
                        ))
                           style="text-align: right; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { (tr(lang, "peak conns", "пик соед.")) }
                    }
                }
                tbody {
                    @for (server_id, (up, dn, conns)) in &per_server {
                        tr style="border-bottom: 1px dotted var(--rule);" {
                            td style="padding: 5px 8px; color: var(--ink);" { (server_id) }
                            td style="padding: 5px 8px; text-align: right; color: var(--ink);" { (humanize_bytes(*up)) }
                            td style="padding: 5px 8px; text-align: right; color: var(--ink);" { (humanize_bytes(*dn)) }
                            td style="padding: 5px 8px; text-align: right; color: var(--ink); font-weight: 600;" { (humanize_bytes(up.saturating_add(*dn))) }
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

// Error response helpers moved to helpers.rs

// `format_size_bytes` (storage sizes — JEDEC KB/MB/GB labels) moved
// to `vpnctl_core::humanize::format_size_bytes` (2026-05-18, post-
// host-fingerprint consolidation pass) — same fn was byte-identical
// in `cli/src/cmd/backup.rs`. **NOTE:** the sibling `humanize_bytes`
// (defined ~400 lines up, IEC KiB/MiB/GiB labels, 9 call sites for
// traffic counts) is INTENTIONALLY a different helper — see the
// crate-level rustdoc on `vpnctl_core::humanize` for the split
// rationale (storage vs traffic, JEDEC vs IEC).

/// Background, best-effort redeploy of `servers` after an inventory
/// mutation that changes node membership (grant / revoke / disable /
/// enable / delete) so the change lands on the nodes WITHOUT a manual
/// «Deploy all». Mirrors that button, scoped to the affected servers.
/// Without this, a grant only writes inv.db: the sub URI appears
/// instantly but the UUID never reaches the node's `users[]`, so the
/// REALITY handshake succeeds, VLESS-auth rejects, and the client is
/// silently forwarded to the cover dest — «connects but no internet»
/// (HANDOFF 2026-07-08 §4.1). `servers` must be captured by the caller
/// at the right moment — for a DELETE, BEFORE the cascade drops the
/// grants. Empty → no-op. `subject` labels the audit row: user id for
/// user-scoped triggers, server id for server-side bulk grant/revoke.
/// NOTE: apply_config restarts sing-box, so other users on a node see
/// a brief blip — inherent to any config change.
pub(crate) fn spawn_user_servers_redeploy(
    state: &AppState,
    servers: Vec<vpnctl_core::Server>,
    subject: String,
    trigger: &'static str,
) {
    if servers.is_empty() {
        return;
    }
    let inv = state.inv.clone();
    let registry = std::sync::Arc::clone(&state.registry);
    let key_path = std::path::PathBuf::from(crate::app::DEFAULT_DEPLOY_KEY_PATH);
    let server_ids: Vec<String> = servers.iter().map(|s| s.id.0.clone()).collect();
    // Server-side bulk triggers target a SERVER; keep them out of the
    // `user.*` audit namespace so user-timeline filters don't surface
    // server-targeted rows (review 2026-07-08).
    let action: &'static str = if trigger.starts_with("server.") {
        "server.autodeploy"
    } else {
        "user.autodeploy"
    };
    tokio::spawn(async move {
        let errors = crate::wizard_bootstrap::redeploy_servers_collect_errors(
            servers,
            inv.clone(),
            registry,
            key_path,
        )
        .await;
        if errors.is_empty() {
            tracing::info!(
                target = "vpnctld::admin",
                subject = %subject,
                trigger,
                "auto-deploy applied (config re-rendered + sing-box reloaded)"
            );
        } else {
            tracing::warn!(
                target = "vpnctld::admin",
                subject = %subject,
                trigger,
                errors = ?errors,
                "auto-deploy: some servers failed to apply — retry via Deploy all"
            );
        }
        let _ = inv
            .audit(
                "admin",
                action,
                Some(&subject),
                Some(&serde_json::json!({
                    "trigger": trigger,
                    "servers": server_ids,
                    "ok": errors.is_empty(),
                    "errors": errors,
                })),
            )
            .await;
    });
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
        div.ed-headrow {
            h1.ed-sumbar__h {
                @if query.is_empty() {
                    (crate::i18n::tr(lang, "find ", "найти "))
                    em { (crate::i18n::tr(lang, "anything", "что угодно")) }
                } @else {
                    "«" (query) "» — " (total_hits) " "
                    em { (crate::i18n::tr(lang, "matches", "совпадений")) }
                }
            }
            span.ed-tip title=(crate::i18n::tr(
                lang,
                "Substring match across user ids / UUIDs / sub_tokens / device_ids, server ids / addresses, and alert kinds / summaries. Case-insensitive. Cap of 50 hits per group.",
                "Подстрочный поиск по id / UUID / sub_token / device_id пользователей, по id / адресам серверов, по kind / summary алертов. Регистронезависимо. Не больше 50 совпадений в каждой группе.",
            )) { "ⓘ" }
            @if !query.is_empty() {
                span style="font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                    (users.len()) " " (crate::i18n::tr(lang, "users", "польз."))
                    " · " (servers.len()) " " (crate::i18n::tr(lang, "servers", "серверов"))
                    " · " (alerts.len()) " " (crate::i18n::tr(lang, "alerts", "алертов"))
                    " · "
                    a href=(format!("/admin/audit?target={}", path_segment_encode(query))) style="color: var(--acc);" {
                        (crate::i18n::tr(lang, "audit events →", "события аудита →"))
                    }
                }
            }
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
    Ok(render_page(&state, "search", &theme, &accent, lang, body).await)
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
    let target = q.target.as_deref().filter(|s| !s.is_empty());
    let exclude = q.action_exclude();
    let hiding = exclude.is_some();
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
    // `page` is already clamped to MAX_PAGE above, so `* PAGE_SIZE` can't
    // overflow i64.
    let offset = page * PAGE_SIZE;
    let entries = state
        .inv
        .recent_audit_paginated(PAGE_SIZE + 1, offset, actor, action, target, exclude)
        .await
        .map_err(|e| internal_error(anyhow::Error::new(e)))?;

    // v2 5b — «N events on file · M match» header counts.
    let (audit_total, audit_matched) = state
        .inv
        .audit_counts(actor, action, target, exclude)
        .await
        .unwrap_or((0, 0));
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

        div style="font-family: var(--mono); font-size: 11px; color: var(--mute); margin-top: 10px; display: flex; gap: 12px; align-items: baseline;" {
            span {
                (audit_total) " "
                (crate::i18n::noun_for(lang, audit_total, "event on file", "events on file", "событие в записи", "события в записи", "событий в записи"))
                @if actor.is_some() || action.is_some() || target.is_some() || hiding {
                    " · " b style="color: var(--ink);" { (audit_matched) } " "
                    (crate::i18n::tr(lang, "match the filter", "подходят под фильтр"))
                }
            }
            // Housekeeping toggle — the hourly backup.snapshot rows
            // otherwise fill the whole first page (design review
            // 2026-07-10). Preserves the other filters either way.
            @if hiding {
                a href=(audit_url("/admin/audit", actor, action, target, false, None))
                  style="color: var(--acc);"
                  title=(crate::i18n::tr(
                      lang,
                      "Snapshots are hidden. Click to show every row again.",
                      "Снапшоты скрыты. Кликни, чтобы снова показать все строки.",
                  )) {
                    (crate::i18n::tr(lang, "show snapshots →", "показать снапшоты →"))
                }
            } @else {
                a href=(audit_url("/admin/audit", actor, action, target, true, None))
                  style="color: var(--mute);"
                  title=(crate::i18n::tr(
                      lang,
                      "Hide the hourly backup.snapshot housekeeping rows so real changes surface.",
                      "Скрыть почасовые housekeeping-строки backup.snapshot, чтобы всплыли реальные изменения.",
                  )) {
                    (crate::i18n::tr(lang, "hide snapshots →", "скрыть снапшоты →"))
                }
            }
        }
        form method="get" action="/admin/audit"
             style="display: flex; gap: 12px; align-items: baseline; padding: 12px 14px; border: 1px solid var(--rule); margin: 10px 0 24px; font-family: var(--mono); font-size: 11px;" {
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
            label { (crate::i18n::tr(lang, "target contains", "цель содержит")) }
            input type="text" name="target"
                  value=(target.unwrap_or(""))
                  placeholder=(crate::i18n::tr(lang, "user or server id…", "id юзера или сервера…"))
                  title=(crate::i18n::tr(
                      lang,
                      "SUBSTRING match on the target column — `brat` matches `main-brat`.",
                      "Поиск ПОДСТРОКИ в колонке target — `brat` найдёт `main-brat`.",
                  ))
                  style="padding: 3px 6px; max-width: 180px; border: 1px solid var(--rule-s); font-family: var(--mono); font-size: 11px;";
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
            a href=(audit_url("/admin/audit.csv", actor, action, target, hiding, None))
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
                a href=(audit_url("/admin/audit", actor, action, target, hiding, Some(page - 1)))
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
                a href=(audit_url("/admin/audit", actor, action, target, hiding, Some(page + 1)))
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
    Ok(render_page(&state, "audit", &theme, &accent, lang, body).await)
}

/// Query-string args for the audit timeline. All optional; empty
/// string is treated as "no filter on this axis" by the handler.
#[derive(serde::Deserialize, Debug, Default)]
pub(crate) struct AuditQuery {
    pub actor: Option<String>,
    pub action: Option<String>,
    /// v2 5b — substring filter on the target column.
    pub target: Option<String>,
    /// Housekeeping visibility. The hourly `backup.snapshot` rows are
    /// hidden BY DEFAULT (they filled the whole first screen — R2
    /// 2026-07-10); `?hide=none` shows everything. The R1 value
    /// `?hide=snapshots` still parses as the (now default) hidden
    /// state so bookmarks keep working.
    pub hide: Option<String>,
    pub page: Option<i64>,
}

impl AuditQuery {
    /// The exact audit action excluded by the current `hide` value —
    /// single source for the handler, the CSV export and the chip URL.
    pub(crate) fn action_exclude(&self) -> Option<&'static str> {
        match self.hide.as_deref() {
            Some("none") => None,
            _ => Some("backup.snapshot"),
        }
    }
}

/// Build a `/admin/audit*` URL preserving the current filter query.
/// Pass `Some(page)` for paginated HTML targets, `None` for the CSV
/// export endpoint (which doesn't paginate). Single helper avoids the
/// near-duplicate URL builders that the previous chunk had.
fn audit_url(
    base: &str,
    actor: Option<&str>,
    action: Option<&str>,
    target: Option<&str>,
    hide_snapshots: bool,
    page: Option<i64>,
) -> String {
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
    if let Some(t) = target {
        q.push(sep);
        q.push_str(&format!("target={}", path_segment_encode(t)));
        sep = '&';
    }
    if !hide_snapshots {
        // Hidden is the default — only the SHOW-everything state needs
        // a query param.
        q.push(sep);
        q.push_str("hide=none");
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
                    div style="margin: 18px 0 6px; padding: 4px 0; font-family: var(--mono); font-size: 10px; letter-spacing: 0.14em; text-transform: uppercase; color: var(--mute); border-bottom: 1px solid var(--rule);" {
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
                            // v2 5b — full payload behind a pure-HTML
                            // <details> expander (CSP-safe, no JS).
                            " "
                            details style="display: inline-block; vertical-align: baseline;" {
                                summary style="cursor: pointer; color: var(--acc); font-family: var(--mono); font-size: 10px; list-style: none; display: inline;" { "{…}" }
                                pre style="margin: 4px 0 0; padding: 8px 10px; background: var(--paper-2); border: 1px solid var(--rule); font-family: var(--mono); font-size: 10px; white-space: pre-wrap; max-width: 680px;" {
                                    (serde_json::to_string_pretty(&redact_audit_payload(p)).unwrap_or_default())
                                }
                            }
                        }
                    }
                }
                @let _ = current_label.replace(label);
            }
        }
    }
}

/// `GET /admin/users/{id}/access.csv` — v2 4c: the full GeoIP-resolved
/// sub-access log for one user as CSV (up to 10k newest rows).
pub(crate) async fn user_access_csv(
    State(state): State<AppState>,
    Path(user_id_str): Path<String>,
) -> Response {
    let uid = vpnctl_core::UserId(user_id_str.clone());
    match state.inv.get_user(&uid).await {
        Ok(Some(_)) => {}
        Ok(None) => return user_not_found(&user_id_str),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    }
    const CSV_LIMIT: i64 = 10_000;
    let rows = match state.inv.recent_sub_access_paged(&uid, CSV_LIMIT, 0).await {
        Ok(v) => v,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    let mut out = String::from("ts,ip,country,asn,user_agent,status,is_vpn_egress\n");
    for e in &rows {
        out.push_str(&csv_field(&e.ts.to_rfc3339()));
        out.push(',');
        out.push_str(&csv_field(&e.ip));
        out.push(',');
        out.push_str(&csv_field(e.geo_country.as_deref().unwrap_or("")));
        out.push(',');
        out.push_str(&csv_field(e.geo_asn.as_deref().unwrap_or("")));
        out.push(',');
        out.push_str(&csv_field(e.ua.as_deref().unwrap_or("")));
        out.push(',');
        out.push_str(&e.status.to_string());
        out.push(',');
        out.push_str(if e.is_vpn_egress { "1" } else { "0" });
        out.push('\n');
    }
    let stamp = chrono::Utc::now().format("%Y%m%d");
    let filename = format!("vpnctl-access-{}-{stamp}.csv", user_id_str);
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
    let target = q.target.as_deref().filter(|s| !s.is_empty());
    let exclude = q.action_exclude();

    /// Generous cap; the operator can re-export with ?limit= once we
    /// add that to AuditQuery in a follow-up.
    const CSV_LIMIT: i64 = 10_000;

    let entries = match state
        .inv
        .recent_audit_paginated(CSV_LIMIT, 0, actor, action, target, exclude)
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

    // v2 5a — family split: the sub_access.* spam cluster gets its own
    // grouped table; node/fleet/user alerts the second. Counts feed the
    // header meta line.
    let (sub_rows, node_rows): (Vec<_>, Vec<_>) = alerts_rows
        .iter()
        .partition(|a| a.kind.starts_with("sub_access."));
    // The auto-resolve wording mirrors the health monitor's REAL
    // hysteresis constants (trigger 95 → recover 90 mem, 90 → 85 disk).
    let auto_resolve_note = |kind: &str| -> &'static str {
        use crate::i18n::tr;
        if kind.starts_with("server.mem.pressure") {
            tr(lang, "on drop < 90%", "при спаде < 90%")
        } else if kind.starts_with("server.disk.pressure") {
            tr(lang, "on drop < 85%", "при спаде < 85%")
        } else if kind == "server.singbox.log.too_big" {
            tr(lang, "on rotate", "после ротации")
        } else if kind.starts_with("server.unreachable") {
            tr(lang, "on next ok probe", "при следующей ok-пробе")
        } else if kind.starts_with("server.fingerprint.drift") {
            tr(lang, "on match", "при совпадении")
        } else if kind.starts_with("user.traffic_limit") {
            tr(lang, "on usage drop", "при спаде расхода")
        } else {
            tr(lang, "manual ack", "только вручную")
        }
    };
    let subject_cell = |a: &vpnctl_inventory::AdminAlert| -> Markup {
        match (&a.server_id, a.kind.split_once(':')) {
            (Some(sid), _) => html! {
                a.ed-grid__id href=(format!("/admin/servers/{}", path_segment_encode(&sid.0))) { (sid.0) }
            },
            (None, Some((_, subj))) if !subj.is_empty() => html! {
                a.ed-grid__id href=(format!("/admin/users/{}", path_segment_encode(subj))) { (subj) }
            },
            _ => html! { span.ed-grid__mut { "—" } },
        }
    };
    let ack_cell = |a: &vpnctl_inventory::AdminAlert| -> Markup {
        if a.acked_at.is_some() {
            html! { span.ed-grid__mut.ed-grid__sm { (crate::i18n::tr(lang, "acked", "принят")) } }
        } else {
            html! {
                form method="post" action=(format!("/admin/alerts/{}/ack", a.id))
                     style="margin: 0; padding: 0; display: inline;" {
                    button type="submit" class="ed-abtn ed-abtn--secondary ed-abtn--sm" { "ack" }
                }
            }
        }
    };
    let now = chrono::Utc::now();

    let body = html! {
        div.ed-art-eyebrow { (crate::i18n::t(lang, crate::i18n::K::PageAlerts)) }
        div.ed-headrow {
            h1.ed-sumbar__h {
                (unacked_total) " "
                em { (crate::i18n::noun_for(lang, unacked_total, "open alert", "open alerts", "открытый алерт", "открытых алерта", "открытых алертов")) }
            }
            span.ed-tip title=(crate::i18n::tr(
                lang,
                "Opened by the health monitor and the sub-access analyzer. Node alerts auto-resolve on recovery; sub-access alerts stay until acked. Ack is idempotent and audited; acked rows stay under «show all» for 30 days.",
                "Открываются монитором здоровья и анализатором обращений. Нодовые алерты закрываются сами при восстановлении; sub-access висят до ack. Ack идемпотентен и аудируется; принятые видны в «показать всё» 30 дней.",
            )) { "ⓘ" }
            span style="font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                (sub_rows.iter().filter(|a| a.acked_at.is_none()).count()) " sub-access · "
                (node_rows.iter().filter(|a| a.acked_at.is_none()).count()) " "
                (crate::i18n::tr(lang, "node", "нодовых"))
            }
            div.ed-headrow__actions {
                @if include_acked {
                    a href="/admin/alerts" style="font-family: var(--mono); font-size: 11px; color: var(--mute); text-decoration: none;" {
                        (crate::i18n::tr(lang, "← only unacked", "← только непринятые"))
                    }
                } @else {
                    a href="/admin/alerts?show=all" style="font-family: var(--mono); font-size: 11px; color: var(--mute); text-decoration: none;" {
                        (crate::i18n::tr(lang, "show all →", "показать всё →"))
                    }
                }
                @if unacked_total > 0 {
                    @let confirm_msg = crate::i18n::tr(
                        lang,
                        "Ack all unacked alerts? They will stay visible under «show all» for 30 days; nothing is deleted, just marked seen.",
                        "Принять все непринятые алерты? Они останутся видимы в «показать всё» 30 дней; ничего не удаляется, только помечается просмотренным.",
                    );
                    form method="post"
                         action="/admin/alerts/ack-all"
                         style="display: inline; margin: 0;"
                         data-confirm=(confirm_msg) {
                        button type="submit"
                               title=(crate::i18n::tr(
                                   lang,
                                   "Mark every unacked alert as seen in one click. Doesn't clear or fix the underlying conditions — just clears the dashboard tile.",
                                   "Отметить все непринятые как просмотренные одним кликом. Не чинит условия — лишь обнуляет тайл дашборда.",
                               ))
                               class="ed-abtn ed-abtn--secondary ed-abtn--sm" {
                            (crate::i18n::tr(lang, "ack all", "принять все"))
                            " (" (unacked_total) ")…"
                        }
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
                            " quiet, or vpnctld hasn't been running long enough for the probe to fire one.",
                            " тихим, либо vpnctld запущен недостаточно долго чтобы probe что-то поймал.",
                        ))
                    } @else {
                        (crate::i18n::tr(
                            lang,
                            "no unacked alerts. Nothing means nothing's wrong (or every condition has been acknowledged). To browse history: ",
                            "нет непринятых алертов. Пусто значит всё хорошо (либо все условия приняты). Посмотреть историю: ",
                        ))
                        a href="/admin/alerts?show=all" {
                            (crate::i18n::tr(lang, "show all →", "показать всё →"))
                        }
                    }
                }
            }
        }
        @if !sub_rows.is_empty() {
            @let sub_unacked = sub_rows.iter().filter(|a| a.acked_at.is_none()).count();
            div.ed-headrow style="margin-top: 14px;" {
                div.ed-art-eyebrow {
                    "sub_access · " (sub_rows.len()) " "
                    span.ed-tip title=(crate::i18n::tr(
                        lang,
                        "A /sub fetch arrived from a private-range source IP. Usually a client refreshing over its own tunnel; occasionally a proxy hiding the real origin. Ack after review — a repeat fetch reopens.",
                        "Обращение к /sub пришло с приватного диапазона. Обычно клиент обновлялся через собственный туннель; изредка — прокси, скрывающий источник. Ack после просмотра — повторное обращение переоткроет.",
                    )) { "ⓘ" }
                }
                @if sub_unacked > 0 {
                    // v2 5a — ack the whole family in one click.
                    form.ed-headrow__actions method="post" action="/admin/alerts/ack-family/sub_access."
                         data-confirm=(crate::i18n::tr(
                             lang,
                             "Ack every unacked sub_access alert? They stay under «show all» for 30 days.",
                             "Принять все непринятые sub_access-алерты? Останутся в «показать всё» 30 дней.",
                         )) {
                        button type="submit" class="ed-abtn ed-abtn--secondary ed-abtn--sm" {
                            (crate::i18n::tr(lang, "ack all ", "принять все ")) "(" (sub_unacked) ")"
                        }
                    }
                }
            }
            // R3 2026-07-10: the detail column used to repeat the full
            // localized sentence («User X's subscription was fetched
            // from a local/proxy IP … the logged client IP will be
            // wrong») on EVERY row — the subject already names the user
            // and the ⓘ above explains the rest, so 32 rows read as one
            // paragraph copy-pasted 32×. Now: source IP + range kind +
            // UA (the datum that actually varies row-to-row), full
            // sentence still on hover.
            table.ed-grid style="margin-top: 8px;" {
                thead {
                    tr {
                        th style="width: 26px;" {}
                        th style="width: 130px;" { (crate::i18n::tr(lang, "opened", "открыт")) }
                        th style="width: 160px;" { (crate::i18n::tr(lang, "subject", "субъект")) }
                        th style="width: 150px;" { (crate::i18n::tr(lang, "source IP", "IP источника")) }
                        th { (crate::i18n::tr(lang, "client", "клиент")) }
                        th style="width: 90px;" {}
                    }
                }
                tbody {
                    @for a in &sub_rows {
                        @let fields = sub_access_detail_fields(a);
                        tr class=(if a.acked_at.is_some() { "" } else { "on-warn" }) {
                            td { span style="color: var(--warm);" { "⚠" } }
                            td.ed-grid__mut.ed-grid__sm { (humanize_age(now - a.created_at, lang)) }
                            td { (subject_cell(a)) }
                            td.ed-grid__sm title=(a.summary) {
                                (fields.0)
                                @if let Some(kind) = fields.1 {
                                    " " span.ed-grid__mut { "[" (kind) "]" }
                                }
                            }
                            td.ed-grid__mut.ed-grid__sm { (fields.2) }
                            td.num { (ack_cell(a)) }
                        }
                    }
                }
            }
        }
        @if !node_rows.is_empty() {
            div.ed-art-eyebrow style="margin-top: 14px;" {
                (crate::i18n::tr(lang, "node · fleet · user — ", "нода · флот · юзер — ")) (node_rows.len())
            }
            table.ed-grid style="margin-top: 8px;" {
                thead {
                    tr {
                        th style="width: 26px;" {}
                        th style="width: 130px;" { (crate::i18n::tr(lang, "opened", "открыт")) }
                        th style="width: 210px;" { (crate::i18n::tr(lang, "kind", "тип")) }
                        th { (crate::i18n::tr(lang, "subject · detail", "субъект · детали")) }
                        th style="width: 130px;" { (crate::i18n::tr(lang, "auto-resolve", "автозакрытие")) }
                        th style="width: 90px;" {}
                    }
                }
                tbody {
                    @for a in &node_rows {
                        @let kind_base = a.kind.split(':').next().unwrap_or(&a.kind);
                        tr class=(if a.acked_at.is_some() { "" } else if a.severity.eq_ignore_ascii_case("critical") { "on-warn" } else { "" }) {
                            td {
                                @if a.severity.eq_ignore_ascii_case("critical") {
                                    span style="color: var(--red);" { "✖" }
                                } @else {
                                    span style="color: var(--warm);" { "⚠" }
                                }
                            }
                            td.ed-grid__mut.ed-grid__sm {
                                @if a.acked_at.is_some() { (crate::i18n::tr(lang, "resolved ", "закрыт ")) }
                                (humanize_age(now - a.created_at, lang))
                            }
                            td.ed-grid__mut.ed-grid__sm { (kind_base) }
                            @let rendered = localized_alert(a, lang);
                            td.ed-grid__sm {
                                (subject_cell(a))
                                " " span.ed-grid__mut title=(crate::alert_text::to_plain(&rendered.body)) {
                                    "· " (crate::alert_text::to_plain(&rendered.title))
                                }
                                @if let Some(act) = &rendered.action {
                                    " " span.ed-grid__mut.ed-grid__sm style="font-style: italic;" {
                                        "— " (crate::alert_text::to_plain(act))
                                    }
                                }
                            }
                            td.ed-grid__mut.ed-grid__sm { (auto_resolve_note(&a.kind)) }
                            td.num { (ack_cell(a)) }
                        }
                    }
                }
            }
        }
    };
    Ok(render_page(&state, "alerts", &theme, &accent, lang, body).await)
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

/// `POST /admin/alerts/ack-family/{prefix}` — v2 5a: ack a whole alert
/// family (all unacked kinds under `prefix`) in one click. Only two
/// safe prefixes are accepted so the route can't be abused to ack an
/// arbitrary kind by crafting a URL: `sub_access.` and `server.`.
pub(crate) async fn alert_ack_family(
    State(state): State<AppState>,
    Path(prefix): Path<String>,
) -> Response {
    let allowed = matches!(prefix.as_str(), "sub_access." | "server.");
    if !allowed {
        return bad_request("alerts: only the sub_access. and server. families can be group-acked");
    }
    let count = match state.inv.ack_unacked_by_kind_prefix(&prefix).await {
        Ok(n) => n,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    if count > 0 {
        let _ = state
            .inv
            .audit(
                "admin",
                "alerts.ack_family",
                Some(&prefix),
                Some(&serde_json::json!({ "count": count, "prefix": prefix })),
            )
            .await;
    }
    axum::response::Redirect::to("/admin/alerts").into_response()
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

/// R3 2026-07-10 — compact detail for a `sub_access.*` alert row:
/// `(ip, ip_kind, ua)` pulled from the payload. Returns the raw IP
/// string (empty → «—»), the range-kind tag (`Some("LAN")` etc.), and
/// a short client label. The full localized sentence stays on the
/// row's `title=` hover; this replaces 32× repeated boilerplate with
/// the datum that actually varies per row (the source IP).
fn sub_access_detail_fields(a: &vpnctl_inventory::AdminAlert) -> (String, Option<String>, String) {
    let payload: Option<serde_json::Value> = a
        .payload_json
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok());
    let get = |key: &str| -> Option<String> {
        payload
            .as_ref()
            .and_then(|p| p.get(key))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty())
    };
    let ip = get("ip").unwrap_or_else(|| "—".into());
    let ip_kind = get("ip_kind");
    // device_class (parsed) beats the raw UA; fall back to «—».
    let ua = get("device_class")
        .or_else(|| get("ua"))
        .unwrap_or_else(|| "—".into());
    (ip, ip_kind, ua)
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
                    span style="color: var(--mute); font-family: var(--mono); font-size: 11px;" {
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
                       class="ed-abtn ed-abtn--recovery ed-abtn--lg" {
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
    // anchor target for the monitoring page link
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
        div #geoip.ed-art-eyebrow {
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
                            (tr(lang, "(missing — use the «update now» button below)", "(отсутствует — нажми «обновить сейчас» ниже)"))
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
                            (tr(lang, "(missing — use the «update now» button below)", "(отсутствует — нажми «обновить сейчас» ниже)"))
                        }
                    }
                }
            }
        }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
            @if any_loaded {
                (tr(
                    lang,
                    "Update once a month with the ",
                    "Обновлять раз в месяц кнопкой ",
                ))
            } @else {
                (tr(
                    lang,
                    "Drop fresh MMDB files into the dir + restart the daemon, or use the ",
                    "Положи свежие MMDB-файлы в папку + перезапусти демон, либо используй ",
                ))
            }
            span.ed-mono { (tr(lang, "update now", "обновить сейчас")) }
            (tr(
                lang,
                " button below. It downloads DB-IP Lite (CC-BY 4.0, no signup) and atomic-renames the .mmdb files into this dir, then reloads the DB.",
                " ниже. Она скачивает DB-IP Lite (CC-BY 4.0, без регистрации) и атомарно подменяет .mmdb-файлы в этой папке, затем перезагружает БД.",
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
                       "Spawn the geoip-update subprocess on the daemon host and stream its progress here. Same action the monthly timer fires.",
                       "Запустить подпроцесс geoip-update на хосте демона и показать прогресс здесь. То же действие, что и ежемесячный таймер.",
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
        .recent_audit_paginated(1, 0, None, Some("backup.self_test"), None, None)
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

    // v2 6a — one-glance «is the Telegram sink live» flag for the
    // System facts table (token AND chat id both set).
    let telegram_configured = matches!(
        telegram_cfg.as_ref(),
        Ok(Some(c)) if c.token.is_some() && c.chat_id.is_some()
    );

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
            // No ed-rule here — the tab row above already draws its own
            // bottom border; stacking both produced a double line
            // (design review 2026-07-10).
            div.ed-art-eyebrow style="margin-top: 14px;" { (crate::i18n::tr(lang, "Appearance — theme + accent", "Внешний вид — тема + акцент")) }
            p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 12px;" {
                (crate::i18n::tr(
                    lang,
                    "Pick a paper theme (background palette) and an accent colour. Choices are stored as cookies; one-time configuration.",
                    "Выбери бумажную тему (фон) и акцентный цвет. Сохраняется в cookies; настраивается один раз.",
                ))
            }
            (tweaks_inline(&theme, &accent, lang))

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
            // No ed-rule — the tab row draws its own bottom border (R2).
            div #backups-section.ed-art-eyebrow style="margin-top: 14px;" {
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
                           class="ed-abtn ed-abtn--secondary ed-abtn--lg" {
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
                           class="ed-abtn ed-abtn--recovery ed-abtn--lg" {
                        (crate::i18n::tr(lang, "run restore self-test", "проверить восстановление"))
                    }
                }
                span style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute);" {
                    (crate::i18n::tr(
                        lang,
                        "Restore-in-place is a CLI command (the daemon's restore subcommand — it can't replace its own open DB). The self-test above proves the snapshot WOULD restore, without touching the live DB.",
                        "Восстановление поверх живой БД — это CLI-команда (подкоманда restore демона — он не может заменить свою же открытую БД). Self-test выше доказывает что снэпшот ВОССТАНОВИТСЯ, не трогая живую БД.",
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
                                        (crate::i18n::tr(lang, "created", "создан"))
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
                                            // R2 2026-07-10: the display timezone applies here
                                            // like everywhere else; a filename that doesn't
                                            // carry a parseable stamp shows the NAME instead of
                                            // a «(unparseable timestamp)» parser complaint.
                                            @match snap
                                                .created
                                                .as_deref()
                                                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                                            {
                                                Some(ts) => (format_msk_iso(ts.with_timezone(&chrono::Utc))),
                                                None => span.ed-grid__mut
                                                    title=(crate::i18n::tr(
                                                        lang,
                                                        "No timestamp in the filename (manual or legacy snapshot) — shown by name.",
                                                        "В имени файла нет метки времени (ручной или легаси-снэпшот) — показан по имени.",
                                                    )) {
                                                    (snap.file_name)
                                                },
                                            }
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
                            ". Most likely the daemon user doesn't have access — check the permissions on the daemon's data directory.",
                            ". Скорее всего у пользователя демона нет доступа — проверь права на каталог данных демона.",
                        ))
                    }
                }
            }

            (settings_disaster_recovery_section(lang, last_self_test.as_ref()))

    }
    @if tab == SettingsTab::Notifications {
            // No ed-rule — the tab row draws its own bottom border (R2).
            // `id` so the POST-redirect-GET after Save can use a
            // fragment anchor (`#telegram-notifications`) and the
            // browser scrolls back to this section instead of jumping
            // to the top of /admin/settings.
            div #telegram-notifications.ed-art-eyebrow style="margin-top: 14px;" {
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
                          // R2: the old placeholder was a three-clause
                          // manual that truncated at narrower widths —
                          // the full rules live in the tooltip.
                          placeholder=(crate::i18n::tr(
                              lang,
                              "blank = keep existing",
                              "пусто = оставить как есть",
                          ))
                          autocomplete="off"
                          title=(crate::i18n::tr(
                              lang,
                              "Token from @BotFather, shape `123456:ABC-XYZ...`. Stored in inv.db, masked after save. Leave blank to keep the existing token; paste a new value to replace it; clear BOTH fields and save to disable the Telegram sink entirely.",
                              "Токен от @BotFather, форма `123456:ABC-XYZ...`. Хранится в inv.db, маскируется после сохранения. Пусто = оставить текущий; новое значение = заменить; очистить ОБА поля и сохранить = полностью выключить Telegram.",
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
            div style="margin-top: 18px;" {
                div.ed-art-eyebrow style="margin-bottom: 8px;" {
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
            // v2 6a — system facts table: the daemon's moving parts and
            // their cadence, one glance. Values come from the same env
            // knobs the pollers read; alert sink state from inventory.
            @let probe_min = std::env::var("VPNCTLD_NODE_PROBE_INTERVAL_SECS").ok()
                .and_then(|v| v.parse::<u64>().ok()).unwrap_or(600) / 60;
            @let clash_min = std::env::var("VPNCTLD_POLL_INTERVAL_SECS").ok()
                .and_then(|v| v.parse::<u64>().ok()).unwrap_or(300) / 60;
            div.ed-art-eyebrow { (crate::i18n::tr(lang, "System", "Система")) }
            table.ed-feed style="margin: 8px 0 16px;" {
                tbody {
                    tr {
                        td.ed-grid__mut style="width: 160px;" { (crate::i18n::tr(lang, "probe tick", "тик проб")) }
                        td { b { (probe_min) " " (crate::i18n::tr(lang, "min", "мин")) } }
                        td.num.ed-grid__mut.ed-grid__sm { "node_probe_poller · VPNCTLD_NODE_PROBE_INTERVAL_SECS" }
                    }
                    tr {
                        td.ed-grid__mut { (crate::i18n::tr(lang, "clash poll", "опрос clash")) }
                        td { b { (clash_min) " " (crate::i18n::tr(lang, "min", "мин")) } " · " (crate::i18n::tr(lang, "per-node traffic attribution", "атрибуция трафика по нодам")) }
                        td.num.ed-grid__mut.ed-grid__sm { "clash_poller · VPNCTLD_POLL_INTERVAL_SECS" }
                    }
                    tr {
                        td.ed-grid__mut { (crate::i18n::tr(lang, "alert sink", "канал алертов")) }
                        td {
                            "telegram "
                            @if telegram_configured {
                                b style="color: var(--green);" { "on" }
                            } @else {
                                b.ed-grid__mut { "off" }
                            }
                        }
                        td.num.ed-grid__mut.ed-grid__sm {
                            a href="/admin/settings/notifications" style="color: var(--acc);" {
                                (crate::i18n::tr(lang, "configure →", "настроить →"))
                            }
                        }
                    }
                    tr {
                        td.ed-grid__mut { (crate::i18n::tr(lang, "rate limit", "rate limit")) }
                        td.ed-grid__sm { "/sub + /api/v1/app/config · " (crate::i18n::tr(lang, "per-device + non-egress per-IP buckets", "пер-девайс + пер-IP (не-egress) бакеты")) }
                        td.num.ed-grid__mut.ed-grid__sm { "rate_limit.rs" }
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
                            " button. The daemon handles the SSH dance for you — no manual SSH login or ",
                            " кнопка. Демон делает SSH-танец сам — без ручного SSH-логина или редактирования ",
                        ))
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
                        (crate::i18n::tr(
                            lang,
                            " not writable by the daemon. Check its directory permissions; vpnctld writes there as the systemd-unit user (typically ",
                            " недоступен на запись демону. Проверь права на каталог; vpnctld пишет туда из-под пользователя systemd-юнита (обычно ",
                        ))
                        span.ed-mono { "user" } ")."
                    }
                }
            }
    }
        };
    render_page(&state, "settings", &theme, &accent, lang, body).await
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
pub(crate) async fn wizard_new(headers: HeaderMap, State(state): State<AppState>) -> Markup {
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
                p style="font-family: var(--serif); font-style: italic; font-size: 11px; color: var(--mute); margin: 0;" {
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
                p style="font-family: var(--serif); font-style: italic; font-size: 11px; color: var(--mute); margin: 0;" {
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
                p style="font-family: var(--serif); font-style: italic; font-size: 11px; color: var(--mute); margin: 0;" {
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
    render_page(&state, "servers", &theme, &accent, lang, body).await
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

    // Duplicate-address guard (HANDOFF §6 #2): reject at step 1 — before
    // the operator commits to a full bootstrap — if this address already
    // belongs to a registered server. Two records for one node fight over
    // its `users[]` and the second deploy trips the DG-1 guard (the
    // `us` / `us1` incident, 2026-07-08).
    match state.inv.server_id_for_address(&address).await {
        Ok(Some(existing)) => {
            return bad_request(&format!(
                "address '{address}' is already registered to server '{existing}' — one node = one server record; edit '{existing}' instead of bootstrapping a duplicate"
            ));
        }
        Ok(None) => {}
        Err(e) => return internal_error(anyhow::Error::new(e)),
    }

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
        div.ed-headrow {
            h1.ed-sumbar__h {
                (crate::i18n::tr(lang, "Bootstrap ", "Bootstrap ")) em { (crate::i18n::tr(lang, "a fresh node", "свежую ноду")) }
            }
            span.ed-tip title=(crate::i18n::tr(
                lang,
                "SSHes in with the root password once, installs the deploy key, discards the password, installs kernels, mints secrets, deploys, probes. Don't close this tab — the live log attaches once; the bootstrap finishes server-side either way and the result lands on the server's detail page + audit timeline.",
                "Заходит по SSH с root-паролем один раз, ставит deploy-ключ, забывает пароль, ставит ядра, чеканит секреты, деплоит, пробит. Не закрывай вкладку — живой лог подключается один раз; bootstrap всё равно доработает серверно, результат будет на странице сервера и в audit-таймлайне.",
            )) { "ⓘ" }
            span style="font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                (session.address) ":" (session.ssh_port) " · root " (crate::i18n::tr(lang, "· password used once", "· пароль одноразово"))
            }
        }

        div style="display: grid; grid-template-columns: 340px minmax(0, 1fr); gap: 20px; align-items: start; margin-top: 12px;" {
            div {
                div.ed-art-eyebrow { (crate::i18n::tr(lang, "Target", "Цель")) }
                table.ed-feed style="margin: 8px 0 16px;" {
                    tbody {
                        tr { td.ed-grid__mut style="width: 90px;" { "host" } td { (session.address) ":" (session.ssh_port) } }
                        tr { td.ed-grid__mut { "ssh user" } td { "root · " span.ed-grid__mut { (crate::i18n::tr(lang, "password used once", "пароль одноразово")) } } }
                        tr { td.ed-grid__mut { "kernels" } td.ed-grid__sm { "sing-box" } }
                    }
                }
                div.ed-art-eyebrow { (crate::i18n::tr(lang, "Steps", "Шаги")) }
                // The checklist lights up as `step` events arrive
                // (admin.js maps each phase to its row). Phases are the
                // ones wizard_bootstrap actually emits.
                table.ed-feed id="wizard-steps" style="margin-top: 8px;" {
                    tbody {
                        @let step_row = |phase: &str, label: &str| -> Markup {
                            html! {
                                tr data-step-phase=(phase) {
                                    td.step-mark style="width: 20px; color: var(--mute);" { "•" }
                                    td { (label) }
                                }
                            }
                        };
                        (step_row("server", crate::i18n::tr(lang, "ssh + deploy key + harden", "ssh + deploy-ключ + харденинг")))
                        (step_row("deploy", crate::i18n::tr(lang, "install kernels + mint secrets", "установка ядер + секреты")))
                        (step_row("apply", crate::i18n::tr(lang, "apply config + start services", "применить конфиг + сервисы")))
                        (step_row("probe", crate::i18n::tr(lang, "probe ports + pin fingerprint", "проба портов + отпечаток")))
                        (step_row("done", crate::i18n::tr(lang, "complete", "готово")))
                    }
                }
                div style="margin-top: 12px;" {
                    a href="/admin/servers/new"
                      style="font-family: var(--mono); font-size: 11px; color: var(--mute); text-decoration: none;" {
                        "← " (crate::i18n::tr(lang, "start over", "начать заново"))
                    }
                }
            }
            div {
                div.ed-art-eyebrow {
                    (crate::i18n::tr(lang, "Live log", "Живой лог"))
                    " " span.ed-grid__mut style="font-family: var(--mono); font-size: 10px;" { "SSE · autoscroll" }
                }
                // CSP-safe: admin.js opens the EventSource on load
                // (data-sse-autostart) — no inline <script>.
                pre id="wizard-log"
                    data-sse-autostart="/admin/servers/new/step-2/sse"
                    data-steps-box="wizard-steps"
                    style="margin: 8px 0 0; padding: 14px 18px; border: 1px solid var(--rule); background: var(--paper-tint); font-family: var(--mono); font-size: 12px; line-height: 1.5; color: var(--ink); height: 360px; overflow-y: auto; white-space: pre-wrap;" {
                    (crate::i18n::tr(lang, "▸ connecting to the daemon…", "▸ подключение к демону…"))
                }
            }
        }
    };
    render_page(&state, "servers", &theme, &accent, lang, body)
        .await
        .into_response()
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
            format!("{{\"kind\":\"step\",\"phase\":\"serialise-error\",\"message\":\"daemon failed to serialise this event ({e}); please retry the action\"}}")
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
                "{{\"kind\":\"step\",\"phase\":\"serialise-error\",\"message\":\"daemon failed to serialise this event ({e}); please retry the action\"}}"
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
    if let Some(resp) = refuse_cross_origin_sse(&headers) {
        return resp;
    }

    let servers = match state.inv.list_servers().await {
        Ok(s) => s,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    deploy_servers_sse_response(&state, servers)
}

/// `GET /admin/users/{id}/deploy-pending/sse` — deploys ONLY the servers
/// the pending-deploy banner names for this user. Before 2026-07-10 the
/// banner button reused the fleet-wide deploy-all: one pending `us`
/// redeployed cdn/de/is/nl too — harmless (idempotent, reload-not-
/// restart) but noisy and inconsistent with the scoped banner
/// (operator report, design review R2).
pub(crate) async fn user_deploy_pending_sse(
    headers: HeaderMap,
    Path(user_id_str): Path<String>,
    State(state): State<AppState>,
) -> Response {
    if let Some(resp) = refuse_cross_origin_sse(&headers) {
        return resp;
    }
    let uid = vpnctl_core::UserId(user_id_str.clone());
    match state.inv.get_user(&uid).await {
        Ok(Some(_)) => {}
        Ok(None) => return user_not_found(&user_id_str),
        Err(e) => return internal_error(anyhow::Error::new(e)),
    }
    let granted = match state.inv.servers_for_user(&uid).await {
        Ok(v) => v,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    let granted_ids: Vec<vpnctl_core::ServerId> = granted.iter().map(|s| s.id.clone()).collect();
    let pending = match state
        .inv
        .servers_pending_deploy_for_user(&uid, &granted_ids)
        .await
    {
        Ok(v) => v,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    let servers: Vec<vpnctl_core::Server> = granted
        .into_iter()
        .filter(|s| pending.contains(&s.id))
        .collect();
    // Racing a just-finished deploy leaves nothing to do — say so
    // instead of streaming an empty run.
    if servers.is_empty() {
        use axum::response::sse::{Event, KeepAlive, Sse};
        let ev = Event::default()
            .event("ok")
            .data(r#"{"kind":"ok","message":"nothing pending — every granted server already carries this user's config"}"#);
        let stream = tokio_stream::once(Ok::<_, std::convert::Infallible>(ev));
        return Sse::new(stream)
            .keep_alive(KeepAlive::new().interval(std::time::Duration::from_secs(15)))
            .into_response();
    }
    deploy_servers_sse_response(&state, servers)
}

/// Shared Sec-Fetch-Site guard for the SSE deploy triggers. Allows
/// only "same-origin" (EventSource from an admin page) and "none"
/// (direct navigation) — unified predicate from the 2026-06-10 audit.
fn refuse_cross_origin_sse(headers: &HeaderMap) -> Option<Response> {
    if let Some(sfs) = headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) {
        if sfs != "same-origin" && sfs != "none" {
            return Some(error_resp(
                StatusCode::FORBIDDEN,
                "cross-origin deploy trigger refused (same-origin only)",
            ));
        }
    }
    None
}

/// Stream a `run_deploy_all` pass over `servers` as an SSE response —
/// the shared tail of the fleet-wide and per-user-pending deploy
/// triggers.
fn deploy_servers_sse_response(state: &AppState, servers: Vec<vpnctl_core::Server>) -> Response {
    use axum::response::sse::{Event, KeepAlive, Sse};
    use futures_core::Stream;
    use std::pin::Pin;
    use tokio_stream::StreamExt;

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
                "{{\"kind\":\"step\",\"phase\":\"serialise-error\",\"message\":\"daemon failed to serialise this event ({e}); please retry the action\"}}"
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
                "{{\"kind\":\"step\",\"phase\":\"serialise-error\",\"message\":\"daemon failed to serialise this event ({e}); please retry the action\"}}"
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
                "{{\"kind\":\"step\",\"phase\":\"serialise-error\",\"message\":\"daemon failed to serialise this event ({e}); please retry the action\"}}"
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
                "{{\"kind\":\"step\",\"stream\":\"stderr\",\"message\":\"daemon failed to serialise this event ({e}); please retry the action\"}}"
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
/// own port declaration (see `vpnctl_core::Protocol`), so adding a
/// new protocol doesn't require touching this function. (Refactored
/// 2026-05-16 per review-agent finding — previous hand-maintained
/// map violated kernel/protocol orthogonality.)
///
/// `secrets` = this server's secret map: `effective_listen_ports`
/// resolves runtime-configurable ports (vless.listen_port override),
/// so the table shows the port the node ACTUALLY binds — not the
/// compile-time default (cdn incident 2026-08-05: reality on 8443
/// rendered as «no fixed port» while 443 stayed firewalled).
fn expected_ports_for_protocol(
    registry: &vpnctl_core::Registry,
    pid: &vpnctl_core::ProtocolId,
    secrets: &std::collections::HashMap<String, String>,
) -> Vec<(String, u16)> {
    match registry.protocol(pid) {
        Some(p) => p
            .effective_listen_ports(secrets)
            .into_iter()
            .map(|(s, n)| (s.to_string(), n))
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
    /// v2 3d — grants-tab sort: `id` (default) · `presence` · `traffic`.
    #[serde(default)]
    grant_sort: Option<String>,
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
pub(crate) fn detail_tabs(base: &str, active: &str, tabs: &[(&str, &str)]) -> Markup {
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

    // Design v2 3e — is the clash-api poller currently holding a LIVE
    // snapshot for this node (checklist row «clash api reachable»).
    // `get_live`: a stale snapshot (polling stopped) must read as
    // NOT reachable, not keep a green «reachable» row from a frozen tick.
    let clash_ok = state.snapshot_cache.get_live(&sid).is_some();

    // Design v2 3d — Grants-tab-only data: grant dates (migration
    // 0039), WHICH granted users still await a deploy, per-user live
    // conns on THIS node (clash snapshot), and per-user 24h traffic.
    let (grant_dates, pending_users, grants_presence, grants_traffic) = if tab == ServerTab::Grants
    {
        let dates: std::collections::HashMap<
            vpnctl_core::UserId,
            Option<chrono::DateTime<chrono::Utc>>,
        > = state
            .inv
            .grant_dates_for_server(&sid)
            .await
            .unwrap_or_default()
            .into_iter()
            .collect();
        let pending: std::collections::HashSet<vpnctl_core::UserId> = state
            .inv
            .users_pending_deploy_for_server(&sid)
            .await
            .unwrap_or_default()
            .into_iter()
            .collect();
        let mut presence: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
        // `get_live`: per-user live conns on this node must drop out once
        // the snapshot goes stale (polling stopped).
        if let Some(snap) = state.snapshot_cache.get_live(&sid) {
            for c in &snap.snapshot.connections {
                if let Some(uid) = c.metadata.user.as_deref() {
                    *presence.entry(uid.to_string()).or_default() += 1;
                }
            }
        }
        let traffic: std::collections::HashMap<vpnctl_core::UserId, u64> = state
            .inv
            .top_users_by_traffic_for_server(&sid, 24, 1000)
            .await
            .unwrap_or_default()
            .into_iter()
            .collect();
        (dates, pending, presence, traffic)
    } else {
        Default::default()
    };

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
    let quality_24h = state
        .inv
        .service_quality_for_server(&sid, 24, vpnctl_inventory::QUALITY_MIN_SAMPLES)
        .await
        .ok();
    let quality_7d = state
        .inv
        .service_quality_for_server(&sid, 24 * 7, vpnctl_inventory::QUALITY_MIN_SAMPLES)
        .await
        .ok();
    let quality_history = state
        .inv
        .service_quality_samples_for_server(&sid, 24)
        .await
        .unwrap_or_default();

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
    // daemon start / no key / etc) OR the last snapshot went stale
    // (`get_live`: polling stopped → the live connection tables must
    // collapse to their empty state, not render a frozen tick as live).
    let last_server_snap = state.snapshot_cache.get_live(&sid);
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

    // server#4 — per-server traffic sparkline. Reuse the fleet's compact
    // hourly rollup and retain only this server.
    let traffic_window = pick_vpn_sparkline_window(query.vpn_window.as_deref());
    let traffic_since_hours = traffic_window.cells * traffic_window.bucket_hours;
    let traffic_rows = state
        .inv
        .recent_vpn_stats_fleet(traffic_since_hours, traffic_window.bucket_hours)
        .await
        .map(|rows| {
            rows.into_iter()
                .filter(|row| row.server_id == sid)
                .collect()
        })
        .unwrap_or_else(|e| {
            tracing::warn!(target = "vpnctld::admin", server = %sid, error = %e, "server traffic rollup query failed");
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
        .flat_map(|pid| expected_ports_for_protocol(&state.registry, pid, &server_secrets))
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
        nav.ed-crumb {
            a href="/admin/servers" style="color: var(--mute); text-decoration: none;" {
                "← " (crate::i18n::tr(lang, "all servers", "все серверы"))
            }
        }
        div.ed-headrow {
            h1.ed-sumbar__h { (server.id.0) }
            @if let Some(h) = latest.as_ref() {
                @if h.sing_box_active == Some(true) {
                    span.ed-stat.ed-stat--active {
                        span.ed-stat__dot {}
                        (crate::i18n::tr(lang, "up", "работает"))
                        " · " (crate::i18n::tr(lang, "probe ", "проба "))
                        (humanize_age(chrono::Utc::now() - h.ts, lang))
                    }
                } @else if h.sing_box_active == Some(false) {
                    span.ed-stat.ed-stat--failed {
                        span.ed-stat__dot {}
                        (crate::i18n::tr(lang, "down", "не работает"))
                        " · " (crate::i18n::tr(lang, "probe ", "проба "))
                        (humanize_age(chrono::Utc::now() - h.ts, lang))
                    }
                } @else {
                    span.ed-stat.ed-stat--unknown {
                        span.ed-stat__dot {}
                        (crate::i18n::tr(lang, "unknown", "неизвестно"))
                    }
                }
            }
            div.ed-headrow__actions {
                button type="button"
                       data-sse-url=(format!("/admin/servers/{}/update-kernels/sse", path_segment_encode(&server.id.0)))
                       data-log="update-kernels-log"
                       data-busy-label=(crate::i18n::tr(lang, "updating kernels… (watch the log)", "обновляю ядра… (смотри лог)"))
                       data-retry-label=(crate::i18n::tr(lang, "retry update", "повторить обновление"))
                       title=(crate::i18n::tr(
                           lang,
                           "Upgrade the kernel binaries only: streamed live, this probes each declared kernel's version, upgrades the package (apt upgrade), restarts the service, then probes the version again. The running config is left untouched, so this is safe on an inventory-drift node.",
                           "Обновить только бинарники ядер: с живым логом — снять версию каждого ядра, обновить пакет (apt upgrade), перезапустить сервис и снять версию снова. Рабочий конфиг не меняется, поэтому действие безопасно при дрейфе инвентаря.",
                       ))
                       class="ed-abtn ed-abtn--secondary ed-abtn--sm" {
                    (crate::i18n::tr(lang, "update kernels", "обновить ядра"))
                }
                button id="deploy-button" type="button"
                       data-sse-url=(format!("/admin/servers/{}/deploy/sse", path_segment_encode(&server.id.0)))
                       data-busy-label=(crate::i18n::tr(lang, "deploying… (watch the log)", "деплою… (смотри лог)"))
                       data-retry-label=(crate::i18n::tr(lang, "retry deploy", "повторить деплой"))
                       title=(crate::i18n::tr(
                           lang,
                           "Full deploy: streamed live — mint missing per-protocol secrets, SSH into the node, run ensure_installed + apply_config for every enabled kernel, and restart services. Each step and the final status appear in the log below. Re-clicking is safe.",
                           "Полный деплой с живым логом: дораздать недостающие секреты, подключиться к ноде по SSH, выполнить ensure_installed + apply_config для каждого включённого ядра и перезапустить сервисы. Каждый шаг и итог появятся в логе ниже. Повторный клик безопасен.",
                       ))
                       class="ed-abtn ed-abtn--recovery ed-abtn--sm" {
                    (crate::i18n::t(lang, crate::i18n::K::BtnDeploy))
                }
                noscript {
                    form method="post"
                         action=(format!("/admin/servers/{}/deploy", path_segment_encode(&server.id.0)))
                         style="display: inline;" {
                        button type="submit" class="ed-abtn ed-abtn--recovery ed-abtn--sm" {
                            (crate::i18n::t(lang, crate::i18n::K::BtnDeploy))
                        }
                    }
                }
            }
        }
        div.ed-detail-meta {
            (server.address) ":" (server.ssh_port)
            " · " (crate::i18n::tr(lang, "ssh as ", "ssh как ")) (server.ssh_user)
            " · "
            @if server.kernels.len() == 1 { (crate::i18n::tr(lang, "kernel ", "ядро ")) }
            @else { (crate::i18n::tr(lang, "kernels ", "ядра ")) }
            (ordered_kernel_ids(&server).iter().map(|k| k.0.clone()).collect::<Vec<_>>().join("+"))
            " · " (crate::i18n::tr(lang, "hoster ", "хостер ")) (server.hoster)
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
                style="margin: 12px 0 0; padding: 10px 14px; border: 1px solid var(--warm); border-left-width: 3px; background: var(--paper-tint); font-family: var(--mono); font-size: 11px; color: var(--ink);" {
                b style="color: var(--warm);" { "⚠ " (crate::i18n::tr(lang, "config not yet deployed", "конфиг ещё не задеплоен")) }
                " — "
                (crate::i18n::tr(
                    lang,
                    "grants changed since the last deploy. Until you click deploy, the node keeps running the OLD user set — a revoked user can still connect.",
                    "гранты менялись после последнего деплоя. Пока не нажат deploy, нода работает со СТАРЫМ списком юзеров — отозванный юзер всё ещё может подключиться.",
                ))
            }
        }
        pre id="deploy-log" hidden
            style="margin: 0 0 12px; padding: 10px 12px; background: var(--paper-tint); border: 1px solid var(--rule); font-family: var(--mono); font-size: 11px; line-height: 1.5; max-height: 320px; overflow-y: auto; white-space: pre-wrap;" {}
        pre id="update-kernels-log" hidden
            style="margin: 0 0 12px; padding: 10px 12px; background: var(--paper-tint); border: 1px solid var(--rule); font-family: var(--mono); font-size: 11px; line-height: 1.5; max-height: 320px; overflow-y: auto; white-space: pre-wrap;" {}

        // Hero: current state (live or empty-state)
        (server_detail_hero(&latest, &server, lang))

        // ── in-page tabs (ui-audit §3-§4). Chrome above (nav / hero /
        // deploy / update-kernels / pending-deploy banner) shows on
        // EVERY tab so the daily deploy action never hides behind one;
        // each group below renders only on its own tab. Bare
        // /admin/servers/{id} == the `status` tab.
        @let tab_base = format!("/admin/servers/{}", path_segment_encode(&server.id.0));
        @let protocols_tab_label = if latest.is_none() || (missing.is_empty() && extra.is_empty()) {
            crate::i18n::tr(lang, "Protocols", "Протоколы").to_string()
        } else {
            format!("{} ⚠", crate::i18n::tr(lang, "Protocols", "Протоколы"))
        };
        @let grants_tab_label = format!("{} · {}", crate::i18n::tr(lang, "Grants", "Гранты"), user_count);
        (detail_tabs(&tab_base, tab.slug(), &[
            ("status", crate::i18n::tr(lang, "Status", "Статус")),
            ("activity", crate::i18n::tr(lang, "Activity", "Активность")),
            ("protocols", protocols_tab_label.as_str()),
            ("grants", grants_tab_label.as_str()),
            ("setup", crate::i18n::tr(lang, "Setup", "Настройка")),
        ]))

        // ── STATUS (default) — "is the node healthy, what changed".
        @if tab == ServerTab::Status {
            div.ed-detail-grid {
                div {
                    // Rolling uptime SLO (24h/7d/30d) + compact drift
                    // verdict form the left scan column.
                    (server_detail_uptime_section(
                        uptime_24h.as_ref(),
                        uptime_7d.as_ref(),
                        uptime_30d.as_ref(),
                        lang,
                    ))
                    (server_detail_drift_summary(&missing, &extra, latest.is_some(), &tab_base, lang))
                }
                div {
                    // The three 24h resource sparklines own the wider
                    // right column so trend shape stays legible.
                    (server_detail_resource_trend_section(&trend_rows, lang))
                }
            }
            (server_detail_kernel_inventory_section(&server, &state.registry, latest.as_ref(), lang))
            (server_detail_quality_section(
                quality_24h.as_ref(),
                quality_7d.as_ref(),
                &quality_history,
                lang,
            ))
        }

        // ── ACTIVITY — clash-api-snapshot-derived + the audit trail
        // (design v2 3b moved events here from Status: «what happened»
        // belongs with «what's happening»).
        @if tab == ServerTab::Activity {
            // v2 3b — last-deploy summary line above the events. The
            // page-level #deploy-log pane (headrow deploy button)
            // streams live runs; this line recalls the newest archived
            // deploy from the audit trail.
            @if let Some(last_deploy) = server_audit.iter().find(|e| e.action == "server.deploy") {
                div style="font-family: var(--mono); font-size: 11px; color: var(--mute); margin: 0 0 10px;" {
                    (crate::i18n::tr(lang, "last deploy ", "последний деплой "))
                    b { (format_msk_iso(last_deploy.ts)) }
                    " · " (crate::i18n::tr(lang, "by ", "запустил ")) (last_deploy.actor)
                    " · "
                    a href="/admin/audit" style="color: var(--acc);" {
                        (crate::i18n::tr(lang, "audit with this filter →", "аудит с этим фильтром →"))
                    }
                }
            }
            // server#7 — server-scoped audit timeline (last 20),
            // moved from Status (v2 3b).
            (server_detail_audit_section(&server_audit, lang))
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
            // Declared vs observed drift FIRST (R2 2026-07-10) — the ⚠
            // on this tab's label is about drift, but the grid used to
            // sit at the very bottom below four config forms: the tab
            // opened without answering its own warning.
            (server_detail_drift_section(&server, &state.registry, &server_secrets, &observed, &missing, &extra, latest.is_some(), lang))
            (server_detail_kernels_section(&server, &state.registry, lang))
            // Enabled protocols — enable/disable/hide (NM-10 hidden_map:
            // hidden=1 keeps the inbound running but stops emitting the
            // protocol from /sub + /api/v1/app/config). Changes take
            // effect on the NEXT deploy.
            (server_detail_protocols_section(&server, &state.registry, &hidden_map, lang))
            // Naive (Caddy) + vless-ws per-server config (domain + ACME).
            (server_detail_naive_config_section(&server, &server_secrets, lang))
            (server_detail_vlessws_config_section(&server, &server_secrets, lang))
            // REALITY per-server listen port (co-tenant 443 override).
            (server_detail_reality_config_section(&server, &server_secrets, lang))
            // naive↔HY2 UDP pairing opt-in (UX-3) — shared `pair=` so a
            // client routes UDP over the co-located HY2.
            (server_detail_udp_pair_section(&server, udp_pair_enabled, lang))
            // Reserved ports — operator port allowlist the apply-guard skips.
            (server_detail_reserved_ports_section(&server, &reserved_ports, lang))
            // wgturn VK-link — only when the wgturn kernel is enabled.
            (server_detail_wgturn_section(&server, &server_secrets, lang))
            // Drift DETAIL — on-node orphan UUIDs; `?drift=live` arms a
            // best-effort 6s SSH read of the node's sing-box config.
            // Stays at the bottom: it's the on-demand deep dive, not
            // the at-a-glance verdict.
            (server_detail_drift_detail_section(&server, drift_live.as_ref(), query.drift_live(), lang))
        }

        // ── GRANTS — 2nd-most-frequent action; its own uncluttered page.
        @if tab == ServerTab::Grants {
            // Design v2 3d — dense grants table: presence, per-node 24h
            // traffic, key-state (pending deploy vs on node), grant date.
            @let deployed_count = user_count.saturating_sub(pending_users.len());
            div.ed-headrow {
                div.ed-art-eyebrow style="margin: 0;" {
                    (crate::i18n::tr(lang, "Grants", "Выданные доступы")) " "
                    span.ed-tip title=(crate::i18n::tr(
                        lang,
                        "Grant writes the pair into the inventory; keys are minted per protocol on the next deploy. «on node» means the deployed config actually contains the user — grant + forget-to-deploy is the #1 silent failure, the banner below tracks it.",
                        "Грант записывает пару в инвентарь; ключи чеканятся по протоколам на следующем деплое. «на ноде» значит, что задеплоенный конфиг реально содержит юзера — грант без деплоя это тихий сбой №1, баннер ниже его отслеживает.",
                    )) { "ⓘ" }
                }
                span style="font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                    (user_count) (crate::i18n::tr(lang, " of ", " из ")) (all_users.len())
                    " "
                    // RU forms are GENITIVE (after «из»): из 41
                    // пользователя / из 42 пользователей — not the
                    // nominative counting forms.
                    (crate::i18n::noun_for(lang, all_users.len() as u64, "user granted", "users granted", "пользователя с доступом", "пользователей с доступом", "пользователей с доступом"))
                    " · " (crate::i18n::tr(lang, "deployed config covers ", "задеплоенный конфиг покрывает "))
                    (deployed_count)
                }
            }
            @if !pending_users.is_empty() {
                div style="display: flex; align-items: center; gap: 10px; flex-wrap: wrap; border: 1px solid var(--warm); border-left-width: 3px; background: color-mix(in oklab, var(--warm) 9%, var(--paper)); padding: 9px 12px; margin: 10px 0;" {
                    span style="font-family: var(--mono); font-size: 11px; color: var(--warm);" {
                        "⚠ " b {
                            (pending_users.len())
                            (crate::i18n::tr(lang, " grant(s) not yet deployed: ", " грант(ов) ещё не задеплоено: "))
                        }
                        (pending_users.iter().map(|u| u.0.as_str()).collect::<Vec<_>>().join(", "))
                    }
                    div style="margin-left: auto;" {
                        button type="button"
                               data-sse-url=(format!("/admin/servers/{}/deploy/sse", path_segment_encode(&server.id.0)))
                               data-busy-label=(crate::i18n::tr(lang, "deploying… (watch the log)", "деплою… (смотри лог)"))
                               data-retry-label=(crate::i18n::tr(lang, "retry deploy", "повторить деплой"))
                               class="ed-abtn ed-abtn--warning ed-abtn--sm" {
                            (crate::i18n::tr(lang, "deploy now →", "задеплоить сейчас →"))
                        }
                    }
                }
            }
        @if all_users.is_empty() {
            p style="font-family: var(--serif); font-style: italic; color: var(--mute); padding: 8px 0;" {
                (crate::i18n::tr(lang, "No users in the inventory yet. Create one on ", "В инвентаре ещё нет пользователей. Создай на "))
                a href="/admin/users" style="color: var(--ink);" { "/admin/users" }
                (crate::i18n::tr(lang, " — then come back to grant access.", " — затем вернись сюда чтобы выдать доступ."))
            }
        } @else {
            @let sid_enc_b = path_segment_encode(&server.id.0);
            @let ungranted = all_users.iter().filter(|u| !granted_user_ids.contains(&u.id)).collect::<Vec<_>>();
            @let granted_count = granted_user_ids.len();
            // Grant bar (v2 3d) + the B2 bulk actions on one row.
            div.ed-inbar {
                span.ed-inbar__label { (crate::i18n::tr(lang, "grant access", "выдать доступ")) }
                form method="post" action=(format!("/admin/servers/{sid_enc_b}/grants"))
                     style="display: flex; gap: 6px; align-items: center;" {
                    input type="text" name="user_id" required="required"
                          placeholder=(crate::i18n::tr(lang, "user id…", "id пользователя…"))
                          style="width: 150px;";
                    button type="submit" class="ed-abtn ed-abtn--primary ed-abtn--sm" {
                        (crate::i18n::tr(lang, "grant", "выдать"))
                    }
                }
                span.ed-tip title=(crate::i18n::tr(
                    lang,
                    "Grant writes the pair into the inventory; keys are minted per protocol on the next deploy (auto-deploy runs after).",
                    "Грант пишет пару в инвентарь; ключи чеканятся на следующем деплое (авто-деплой запускается сам).",
                )) { "ⓘ" }
                div style="margin-left: auto; display: flex; gap: 8px;" {
                    @if !ungranted.is_empty() {
                        form method="post"
                             action=(format!("/admin/servers/{sid_enc_b}/grants/_grant-all"))
                             style="margin: 0; padding: 0;" {
                            button type="submit"
                                   title=(crate::i18n::tr(
                                       lang,
                                       "Grant access to every user currently in the inventory who doesn't have it yet. Idempotent.",
                                       "Выдать доступ всем юзерам инвентаря, у кого его сейчас нет. Идемпотентно.",
                                   ))
                                   class="ed-abtn ed-abtn--secondary ed-abtn--sm" {
                                (crate::i18n::tr(lang, "grant all ", "выдать всем "))
                                "(" (ungranted.len()) ")"
                            }
                        }
                    }
                    @if granted_count > 0 {
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
                                       "Revoke access for every currently-granted user on this server. Destructive — requires confirm.",
                                       "Отозвать доступ у всех юзеров с текущим грантом. Деструктивно — нужно подтверждение.",
                                   ))
                                   class="ed-abtn ed-abtn--danger ed-abtn--sm" {
                                (crate::i18n::tr(lang, "revoke all ", "отозвать все "))
                                "(" (granted_count) ")…"
                            }
                        }
                    }
                }
            }
            // v2 3d — sort links. `presence`/`traffic` sort desc by their
            // metric; `id` (default) is A→Z. Pending-deploy rows always
            // float to the top of any sort so the silent-failure set stays
            // visible. The link row lives just under the grant bar.
            @let grant_sort = query.grant_sort.as_deref().unwrap_or("id");
            @let sort_href = |kind: &str| -> String {
                format!("/admin/servers/{}/grants?grant_sort={kind}", path_segment_encode(&server.id.0))
            };
            div style="font-family: var(--mono); font-size: 10px; color: var(--mute); margin: 2px 0 6px;" {
                (crate::i18n::tr(lang, "sort: ", "сортировка: "))
                @for (kind, label) in [("id", "id ↑"), ("presence", crate::i18n::tr(lang, "online ↓", "онлайн ↓")), ("traffic", crate::i18n::tr(lang, "traffic ↓", "трафик ↓"))] {
                    @if grant_sort == kind {
                        span style="color: var(--ink); text-decoration: underline; margin-right: 8px;" { (label) }
                    } @else {
                        a href=(sort_href(kind)) style="color: var(--mute); margin-right: 8px;" { (label) }
                    }
                }
            }
            @let granted_rows = {
                let mut v = all_users.iter().filter(|u| granted_user_ids.contains(&u.id)).collect::<Vec<_>>();
                v.sort_by(|a, b| {
                    // Pending-deploy first in every sort (silent-failure set).
                    let pa = pending_users.contains(&a.id);
                    let pb = pending_users.contains(&b.id);
                    let ca = grants_presence.get(&a.id.0).copied().unwrap_or(0);
                    let cb = grants_presence.get(&b.id.0).copied().unwrap_or(0);
                    let ta = grants_traffic.get(&a.id).copied().unwrap_or(0);
                    let tb = grants_traffic.get(&b.id).copied().unwrap_or(0);
                    let by_metric = match grant_sort {
                        "presence" => cb.cmp(&ca).then(tb.cmp(&ta)),
                        "traffic" => tb.cmp(&ta).then(cb.cmp(&ca)),
                        _ => std::cmp::Ordering::Equal, // id → fall through to id cmp
                    };
                    pb.cmp(&pa).then(by_metric).then(a.id.0.cmp(&b.id.0))
                });
                v
            };
            table.ed-grid style="margin-top: 4px;" {
                thead {
                    tr {
                        th style="width: 34px;" { "№" }
                        th { (crate::i18n::tr(lang, "user", "пользователь")) }
                        th { (crate::i18n::tr(lang, "presence", "присутствие")) }
                        th.num { (crate::i18n::tr(lang, "traffic 24h", "трафик 24ч")) }
                        th { (crate::i18n::tr(lang, "keys on node", "ключи на ноде")) }
                        th style="width: 130px;" { (crate::i18n::tr(lang, "granted", "выдан")) }
                        th style="width: 110px;" {}
                    }
                }
                tbody {
                    @for (idx, u) in granted_rows.iter().enumerate() {
                        @let uid_enc = path_segment_encode(&u.id.0);
                        @let conns = grants_presence.get(&u.id.0).copied().unwrap_or(0);
                        @let bytes = grants_traffic.get(&u.id).copied().unwrap_or(0);
                        @let is_pending = pending_users.contains(&u.id);
                        tr class=(if is_pending { "on-warn" } else if conns > 0 { "on-green" } else { "" }) {
                            td.ed-grid__mut { (format!("{:02}", idx + 1)) }
                            td { a.ed-grid__id href=(format!("/admin/users/{uid_enc}")) { (u.id.0) } }
                            td.ed-grid__sm {
                                @if conns > 0 {
                                    span.ed-stat.ed-stat--active {
                                        span.ed-stat__dot {}
                                        (crate::i18n::tr(lang, "online", "онлайн")) " · " (conns)
                                    }
                                } @else {
                                    span.ed-grid__mut { "— " (crate::i18n::tr(lang, "offline", "офлайн")) }
                                }
                            }
                            td.num {
                                @if bytes > 0 { (humanize_bytes(bytes)) }
                                @else { span.ed-grid__mut { "—" } }
                            }
                            td.ed-grid__sm {
                                @if is_pending {
                                    span.ed-grid__flag { "⚠ " (crate::i18n::tr(lang, "pending deploy", "ждёт деплоя")) }
                                } @else {
                                    span style="color: var(--green);" { "✓ " (crate::i18n::tr(lang, "on node", "на ноде")) }
                                }
                            }
                            td.ed-grid__mut.ed-grid__sm {
                                @match grant_dates.get(&u.id).copied().flatten() {
                                    Some(ts) => (format_msk_iso(ts)),
                                    None => span title=(crate::i18n::tr(
                                        lang,
                                        "Grant predates migration 0039 (2026-07-10) — the date wasn't recorded back then.",
                                        "Грант старше миграции 0039 (2026-07-10) — дата тогда не записывалась.",
                                    )) { "—" },
                                }
                            }
                            td.num {
                                form method="post"
                                     action=(format!("/admin/servers/{sid_enc_b}/grants/{uid_enc}/revoke"))
                                     style="margin: 0; padding: 0; display: inline;" {
                                    button type="submit"
                                           title=(match lang {
                                               crate::i18n::Locale::En => format!("Revoke {}'s access on {}", u.id.0, server.id.0),
                                               crate::i18n::Locale::Ru => format!("Отозвать доступ {} на {}", u.id.0, server.id.0),
                                           })
                                           class="ed-abtn ed-abtn--warning ed-abtn--sm" {
                                        (crate::i18n::tr(lang, "revoke →", "отозвать →"))
                                    }
                                }
                            }
                        }
                    }
                }
            }
            // Not-granted footnote — each id carries its own inline
            // grant form so the operator never leaves the page.
            @if !ungranted.is_empty() {
                div style="display: flex; gap: 8px; align-items: center; flex-wrap: wrap; font-family: var(--mono); font-size: 10px; color: var(--mute); margin-top: 8px;" {
                    (crate::i18n::tr(lang, "not granted: ", "без доступа: "))
                    b style="color: var(--ink);" { (ungranted.len()) }
                    @for u in &ungranted {
                        form method="post"
                             action=(format!("/admin/servers/{sid_enc_b}/grants/{}", path_segment_encode(&u.id.0)))
                             style="margin: 0; padding: 0; display: inline;" {
                            button type="submit"
                                   title=(match lang {
                                       crate::i18n::Locale::En => format!("Grant {} access on {}", u.id.0, server.id.0),
                                       crate::i18n::Locale::Ru => format!("Выдать {} доступ на {}", u.id.0, server.id.0),
                                   })
                                   class="ed-grant-chip off" style="cursor: pointer;" {
                                (u.id.0) " — " (crate::i18n::tr(lang, "grant →", "выдать →"))
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
            // Design v2 3e — node-setup checklist, re-verified from the
            // latest probe (not just at bootstrap): a manually broken
            // node surfaces here without a redeploy. Honest subset —
            // only facts the probe/inventory actually carry today
            // (bbr/ntp/logrotate-config checks need probe extensions).
            div.ed-art-eyebrow {
                (crate::i18n::tr(lang, "Node setup · verified at last probe", "Настройка ноды · сверено последней пробой")) " "
                span.ed-tip title=(crate::i18n::tr(
                    lang,
                    "Each row is re-checked on every probe. A ⚠ here means the node drifted from its bootstrapped state.",
                    "Каждая строка перепроверяется каждой пробой. ⚠ значит, что нода уехала от состояния после bootstrap.",
                )) { "ⓘ" }
            }
            @let ok = |b: bool| -> Markup {
                if b { html! { span style="color: var(--green);" { "✓" } } }
                else { html! { span style="color: var(--warm);" { "⚠" } } }
            };
            @let kernels_reported = latest.as_ref()
                .and_then(|h| h.kernel_versions_json.as_deref())
                .and_then(|j| serde_json::from_str::<serde_json::Value>(j).ok())
                .and_then(|v| v.as_object().map(|o| {
                    let mut parts: Vec<String> = o.iter()
                        .map(|(k, ver)| format!("{k} {}", ver.as_str().unwrap_or("?")))
                        .collect();
                    parts.sort();
                    parts.join(" · ")
                }));
            table.ed-feed style="margin: 8px 0 16px;" {
                tbody {
                    tr {
                        td style="width: 20px;" { (ok(latest.is_some())) }
                        td { b { (crate::i18n::tr(lang, "deploy key installed", "деплой-ключ установлен")) } }
                        td.num.ed-grid__mut.ed-grid__sm {
                            @if latest.is_some() { (crate::i18n::tr(lang, "probe reaches the node over it", "проба ходит на ноду по нему")) }
                            @else { (crate::i18n::tr(lang, "no probe yet — key unverified", "проб ещё нет — ключ не проверен")) }
                        }
                    }
                    tr {
                        td { (ok(kernels_reported.is_some())) }
                        td { b { (crate::i18n::tr(lang, "kernels installed", "ядра установлены")) } }
                        td.num.ed-grid__mut.ed-grid__sm {
                            @match &kernels_reported {
                                Some(k) => (k),
                                None => (crate::i18n::tr(lang, "no version report yet", "версий ещё нет")),
                            }
                        }
                    }
                    tr {
                        td { (ok(latest.as_ref().and_then(|h| h.sing_box_active) == Some(true))) }
                        td { b { "sing-box " (crate::i18n::tr(lang, "service active", "сервис активен")) } }
                        td.num.ed-grid__mut.ed-grid__sm { "service active" }
                    }
                    tr {
                        td { (ok(latest.as_ref().and_then(|h| h.fail2ban_active) == Some(true))) }
                        td { b { "fail2ban " (crate::i18n::tr(lang, "active · sshd jail", "активен · sshd jail")) } }
                        td.num.ed-grid__mut.ed-grid__sm { "service active" }
                    }
                    tr {
                        td { (ok(server.trusted_host_fingerprint.is_some())) }
                        td { b { (crate::i18n::tr(lang, "host fingerprint pinned", "отпечаток хоста запинен")) } }
                        td.num.ed-grid__mut.ed-grid__sm title=(server.trusted_host_fingerprint.as_deref().unwrap_or("")) {
                            @match server.trusted_host_fingerprint.as_deref() {
                                Some(fp) => (fp_short(fp)),
                                None => (crate::i18n::tr(lang, "pin below", "запинь ниже")),
                            }
                        }
                    }
                    tr {
                        td { (ok(clash_ok)) }
                        td { b { "clash api " (crate::i18n::tr(lang, "reachable · traffic attribution", "доступен · атрибуция трафика")) } }
                        td.num.ed-grid__mut.ed-grid__sm {
                            @if clash_ok { (crate::i18n::tr(lang, "snapshot in cache", "снимок в кеше")) }
                            @else { (crate::i18n::tr(lang, "no snapshot — poller can't reach it", "нет снимка — поллер не достучался")) }
                        }
                    }
                    tr {
                        @let log_ok = latest.as_ref().and_then(|h| h.sing_box_log_bytes).is_none_or(|b| b <= 500 * 1024 * 1024);
                        td { (ok(log_ok)) }
                        td { b { "sing-box.log " (crate::i18n::tr(lang, "under the 500 MiB alert", "меньше алертных 500 MiB")) } }
                        td.num.ed-grid__mut.ed-grid__sm {
                            @match latest.as_ref().and_then(|h| h.sing_box_log_bytes) {
                                Some(b) => { (humanize_bytes(b)) @if !log_ok { " — " (crate::i18n::tr(lang, "check logrotate on the node", "проверь logrotate на ноде")) } },
                                None => "—",
                            }
                        }
                    }
                }
            }
            // v2 3e — bootstrap record from the audit trail (best
            // effort; nodes imported outside the wizard have none).
            @let bootstrap_row = server_audit.iter().find(|e| e.action.starts_with("server.bootstrap") || e.action == "bootstrap");
            div style="font-family: var(--mono); font-size: 11px; color: var(--mute); margin: 0 0 16px;" {
                (crate::i18n::tr(lang, "bootstrap record: ", "запись bootstrap: "))
                @match bootstrap_row {
                    Some(e) => { b { (format_msk_iso(e.ts)) } " · " (crate::i18n::tr(lang, "by ", "запустил ")) (e.actor) },
                    None => (crate::i18n::tr(lang, "none in the audit window (imported or pre-wizard node)", "нет в окне аудита (импорт или до-мастерная нода)")),
                }
            }

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
                  class="ed-abtn ed-abtn--danger" {
                    (crate::i18n::tr(lang, "delete this server…", "удалить этот сервер…"))
                }
            }
        }
    };
    Ok(render_page(&state, "servers", &theme, &accent, lang, body).await)
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

    let row = |label: &str, stat: Option<&vpnctl_inventory::UptimeStat>| -> Markup {
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
            tr data-uptime-pct=(pct_attr) {
                th { (label) }
                td.num style=(format!("font-family: var(--serif); font-weight: 600; color: {color};")) {
                    (pct_text)
                }
                td.num.ed-grid__mut.ed-grid__sm {
                    (row_count) " " (crate::i18n::noun_for(lang, row_count, "probe", "probes", "проба", "пробы", "проб"))
                    @if down_count > 0 { " · " (down_count) " " (tr(lang, "down", "падений")) }
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
        section #uptime-section style="margin-top: 18px;" {
            div.ed-art-eyebrow {
                (tr(lang, "Uptime · sing-box service", "Uptime · сервис sing-box"))
                " "
                span.ed-tip title=(tr(
                    lang,
                    "Rolling-window aggregate over sing_box_active from the node_probe poller (10-min default tick). Up means the service reported active at probe time; unknown probes are excluded from the denominator.",
                    "Скользящие окна sing_box_active от node_probe-поллера (тик по умолчанию 10 минут). Up означает, что сервис показал active; неопределённые пробы не входят в знаменатель.",
                )) { "ⓘ" }
            }
            table.ed-grid style="margin-top: 8px;" {
                tbody {
                    (row(tr(lang, "last 24h", "24 часа"), u24h))
                    (row(tr(lang, "last 7d",  "7 дней"),  u7d))
                    (row(tr(lang, "last 30d", "30 дней"), u30d))
                }
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
                                "Most recent probe is >20 min old — the poller may be stalled. Use the manual sweep button on this page to refresh.",
                                "Последняя проба старше 20 минут — поллер может быть остановлен. Нажми кнопку ручного сканирования на этой странице, чтобы обновить.",
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
    let disk_used_pct = h
        .disk_used_mib
        .zip(h.disk_total_mib)
        .filter(|(_, t)| *t > 0)
        .map(|(u, t)| (u * 100 / t).min(100));
    let disk_pct = disk_used_pct
        .map(|pct| format!("{pct}%"))
        .unwrap_or("?".into());
    let mem_used_pct = h
        .mem_available_mib
        .zip(h.mem_total_mib)
        .filter(|(_, t)| *t > 0)
        .map(|(a, t)| 100u64.saturating_sub(a * 100 / t));
    let mem_pct = mem_used_pct
        .map(|pct| format!("{pct}%"))
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
        div.ed-status-strip title=(format!("{} · {}", tr(lang, "last probe", "последняя проба"), format_msk_iso(h.ts))) {
            (status_tile_with_warn("sing-box", sb, sb_color, h.sing_box_active == Some(false)))
            (status_tile_with_warn("fail2ban", f2b, f2b_color, h.fail2ban_active == Some(false)))
            (status_tile_with_warn(tr(lang, "disk used", "диск занят"), &disk_pct, "var(--ink)", disk_used_pct.is_some_and(|v| v > 70)))
            (status_tile_with_warn(tr(lang, "memory used", "память занята"), &mem_pct, "var(--ink)", mem_used_pct.is_some_and(|v| v > 70)))
            (status_tile_with_warn(tr(lang, "1-min load", "load 1мин"), &load, "var(--ink)", false))
            (status_tile_with_warn(tr(lang, "sing-box log", "лог sing-box"), &log_size, log_alert_color, h.sing_box_log_bytes.is_some_and(|b| b > 500 * 1024 * 1024)))
        }
    }
}

fn status_tile(label: &str, value: &str, value_color: &str) -> Markup {
    status_tile_with_warn(label, value, value_color, false)
}

fn status_tile_with_warn(label: &str, value: &str, value_color: &str, warn: bool) -> Markup {
    html! {
        div class=(if warn { "ed-status-tile warn" } else { "ed-status-tile" }) {
            div.ed-status-tile__k { (label) }
            div.ed-status-tile__v style=(format!("color: {value_color};")) {
                (value)
                @if warn { " ⚠" }
            }
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
    let max_value = |series: &[f64]| series.iter().copied().reduce(f64::max).unwrap_or_default();
    let disk_max = max_value(&disk_pct_series);
    let mem_max = max_value(&mem_used_pct_series);
    let log_max = max_value(&log_mib_series);
    html! {
        section id="resource-trend" style="margin-top: 18px;" {
            div.ed-art-eyebrow {
                (tr(lang, "Resource trend · last 24h", "Тренд ресурсов · последние 24ч"))
                " "
                span.ed-tip title=(tr(
                    lang,
                    "10-min probe snapshots over the last 24h. Sparkline reads left-to-right (oldest → newest); the «max» label on each chart is the peak in the window. Use these to tell a slow leak (climbing line) from a transient burst (flat line, one spike).",
                    "10-минутные снимки probe за последние 24 часа. Sparkline читается слева-направо (старое → новое); метка «max» в каждом графике — пик за окно. Помогает отличить медленную утечку (растущая линия) от кратковременного всплеска (плоская линия с одним пиком).",
                )) { "ⓘ" }
            }
            div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-top: 8px;" {
                div {
                    div style="font-family: var(--mono); font-size: 11px; color: var(--mute); text-transform: uppercase; letter-spacing: 0.14em;" {
                        (tr(lang, "Disk %", "Диск %"))
                    }
                    (sparkline_svg_scaled(&disk_pct_series, 280, 60, Some(100.0), false))
                    div style="font-family: var(--mono); font-size: 10px; color: var(--mute);" {
                        (tr(lang, "max ", "макс ")) (format!("{disk_max:.0}%"))
                        " · " (disk_pct_series.len()) " " (tr(lang, "samples", "точек"))
                    }
                }
                div {
                    div style="font-family: var(--mono); font-size: 11px; color: var(--mute); text-transform: uppercase; letter-spacing: 0.14em;" {
                        (tr(lang, "Mem used %", "Память исп. %"))
                    }
                    (sparkline_svg_scaled(&mem_used_pct_series, 280, 60, Some(100.0), false))
                    div style=(if mem_max > 70.0 { "font-family: var(--mono); font-size: 10px; color: var(--warm); font-weight: 600;" } else { "font-family: var(--mono); font-size: 10px; color: var(--mute);" }) {
                        (tr(lang, "max ", "макс ")) (format!("{mem_max:.0}%"))
                        @if mem_max > 70.0 { " ⚠" }
                        " · " (mem_used_pct_series.len()) " " (tr(lang, "samples", "точек"))
                    }
                }
                div {
                    div style="font-family: var(--mono); font-size: 11px; color: var(--mute); text-transform: uppercase; letter-spacing: 0.14em;" {
                        (tr(lang, "sing-box log MiB", "sing-box лог MiB"))
                    }
                    (sparkline_svg_scaled(&log_mib_series, 280, 60, None, false))
                    div style="font-family: var(--mono); font-size: 10px; color: var(--mute);" {
                        (tr(lang, "max ", "макс ")) (format!("{log_max:.0} MiB"))
                        " · " (log_mib_series.len()) " " (tr(lang, "samples", "точек"))
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
            table style="width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 11px; margin-bottom: 18px;" {
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
            table style="width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 11px;" {
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
    let mut all_kernels = registry.kernel_ids();
    all_kernels.sort_by(|left, right| {
        kernel_priority(&left.0)
            .cmp(&kernel_priority(&right.0))
            .then_with(|| left.0.cmp(&right.0))
    });
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
        div style="padding: 8px 12px; margin: 0 0 12px; background: var(--paper); border-left: 3px solid var(--accent); font-family: var(--serif); font-size: 12px; line-height: 1.5;" {
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
                                   class="ed-abtn ed-abtn--warning ed-abtn--sm" {
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
                                   class="ed-abtn ed-abtn--sm" {
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
                // R2: short placeholder (the old sentence truncated
                // mid-word in the 400px field); full rules in `title`.
                input type="password"
                      name="root_password"
                      autocomplete="off"
                      placeholder=(if reference_ok {
                          tr(lang, "blank = reference key", "пусто = reference-key")
                      } else {
                          tr(lang, "never stored", "не сохраняется")
                      })
                      title=(if reference_ok {
                          tr(
                              lang,
                              "Leave blank to authenticate with the reference key; fill in to force the sshpass fallback. Used once for the SSH connect, then discarded — never stored, never logged.",
                              "Пусто — аутентификация reference-ключом; заполни, чтобы форсировать sshpass-fallback. Используется один раз для SSH-коннекта и отбрасывается — не хранится и не логируется.",
                          )
                      } else {
                          tr(
                              lang,
                              "Used once for the SSH connect, then discarded — never stored, never logged.",
                              "Используется один раз для SSH-коннекта и отбрасывается — не хранится и не логируется.",
                          )
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
                       class="ed-abtn ed-abtn--recovery ed-abtn--lg" {
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
                       class="ed-abtn ed-abtn--recovery ed-abtn--lg" {
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

/// VLESS+REALITY per-server listen port (`vless.listen_port`). Default 443
/// is the gold-standard cover; on a co-tenant host where something else
/// owns 443 (naive/caddy here, legacy 3x-ui elsewhere) the operator moves
/// reality to an alt port. Rendered ONLY when `vless+reality` is enabled.
/// The value is load-bearing for the firewall step, the port-conflict guard
/// and the drift table above (`effective_listen_ports`), so it gets the
/// same web surface as `vlessws.listen_port` — "web is the ONLY operator
/// surface" (PR #139 review finding 7).
fn server_detail_reality_config_section(
    server: &vpnctl_core::Server,
    server_secrets: &std::collections::HashMap<String, String>,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    if !server
        .enabled_protocols
        .iter()
        .any(|p| p.0 == "vless+reality")
    {
        return html! {};
    }
    let sid_enc = path_segment_encode(&server.id.0);
    let port = server_secrets
        .get("vless.listen_port")
        .map(String::as_str)
        .unwrap_or("");
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow
            title=(tr(lang,
                "REALITY binds this port directly. Default 443 (gold-standard HTTPS cover); set an alternate port when a co-tenant owns 443 on this host (naive/caddy, legacy 3x-ui). Saving re-validates against every other protocol's port and takes effect on deploy.",
                "REALITY слушает этот порт напрямую. По умолчанию 443 (золотой стандарт HTTPS-маскировки); задай другой порт, если 443 на этом хосте занят со-жителем (naive/caddy, легаси 3x-ui). При сохранении проверяется против портов всех остальных протоколов и вступает в силу при деплое.")) {
            (tr(lang, "VLESS+REALITY CONFIG", "КОНФИГ VLESS+REALITY"))
        }
        form method="post"
             action=(format!("/admin/servers/{sid_enc}/reality-config"))
             style="display: grid; grid-template-columns: 96px 1fr; gap: 6px 8px; align-items: center; max-width: 520px;" {
            label style="font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                (tr(lang, "listen port", "порт"))
            }
            input type="text" name="listen_port" maxlength="5" inputmode="numeric"
                  value=(port)
                  placeholder="443"
                  title=(tr(lang, "TCP port REALITY binds. Blank = 443. Must not collide with any other protocol on this node.", "TCP-порт, который слушает REALITY. Пусто = 443. Не должен совпадать с портом другого протокола на этом узле."))
                  style="padding: 4px 8px; font-family: var(--mono); font-size: 12px; border: 1px solid var(--rule);";
            span {}
            button type="submit"
                   title=(tr(lang, "Save the REALITY listen port", "Сохранить порт REALITY"))
                   style="justify-self: start; padding: 4px 12px; border: 1px solid var(--ink); background: var(--ink); color: var(--paper); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                (tr(lang, "save reality port", "сохранить порт"))
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
                "Per-server allowlist of ports the daemon must NEVER bind via sing-box. Use when a co-tenant service (legacy 3x-ui Docker container, separate xray, another VPN stack) owns one of the standard ports — deploys are refused fail-closed if any rendered inbound would collide.",
                "Список портов на этом сервере, которые демону ЗАПРЕЩЕНО занимать через sing-box. Используется когда на хосте уже крутится сторонний сервис (legacy 3x-ui Docker, отдельный xray, другой VPN-стек) на стандартном порту — деплой отказывается, если какой-то рендеренный inbound попытается их занять, fail-closed.",
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
        // Same deploy-required rule as the Kernels note above. Kept as
        // a marker for operators who scroll straight here, but R2
        // compressed it to one line — two identical banner paragraphs
        // on one screen read as a copy-paste bug.
        div style="padding: 6px 12px; margin: 0 0 12px; background: var(--paper); border-left: 3px solid var(--accent); font-family: var(--serif); font-size: 12px; line-height: 1.5;" {
            b style="color: var(--accent); font-family: var(--mono); letter-spacing: 0.1em; text-transform: uppercase; font-size: 11px;" {
                (tr(lang, "⚠ toggle here = inventory only", "⚠ тогл здесь = только инвентарь"))
            }
            (tr(lang, " — goes live on ", " — вступает в силу по "))
            a href="#deploy-button"
              style="color: var(--ink); border-bottom: 1px dotted var(--ink); text-decoration: none; font-weight: 500;" {
                span.ed-mono { (t(lang, K::BtnDeploy)) }
            }
            (tr(lang, " (details in the note under Kernels).", " (подробности — в заметке под Ядрами)."))
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
                                    (ordered_kernel_ids(server).iter().map(|k| k.0.clone()).collect::<Vec<_>>().join(", "))
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
                                   class="ed-abtn ed-abtn--warning ed-abtn--sm" {
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
                                       class="ed-abtn ed-abtn--sm" {
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
                                       class="ed-abtn ed-abtn--secondary ed-abtn--sm" {
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
                                   class="ed-abtn ed-abtn--sm" {
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
pub(crate) fn user_detail_per_protocol_grid(
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
                table style="width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 11px; margin-top: 8px;" {
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
                // R2: in-SVG label off — it printed raw bytes; the
                // humanized caption below carries the peak.
                @let series_max = series.iter().copied().fold(0.0_f64, f64::max);
                (sparkline_svg_scaled(&series, 1160, 90, None, false))
                div style="font-family: var(--mono); font-size: 10px; color: var(--mute);" {
                    (tr(lang, "max ", "макс ")) (humanize_bytes(series_max as u64))
                    (tr(lang, " per bucket", " на интервал"))
                }
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
                // `--compact` drops the target column — on a
                // server-scoped stream it repeated this server's id on
                // every row (zero information, stolen width; R2).
                div.ed-time.ed-time--compact {
                    @for e in rows {
                        div.ed-time-row {
                            span.ed-time-row__t { (format_msk_iso(e.ts)) }
                            span class=(format!("ed-time-row__a ed-time-row__a--{}", action_kind(&e.action))) {
                                (e.action)
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

#[allow(clippy::too_many_arguments)]
fn server_detail_drift_section(
    server: &vpnctl_core::Server,
    registry: &vpnctl_core::Registry,
    secrets: &std::collections::HashMap<String, String>,
    observed: &std::collections::BTreeSet<(String, u16)>,
    missing: &[(String, u16)],
    extra: &[(String, u16)],
    have_probe: bool,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    // Design v2 3c — the declared × listening drift GRID: one row per
    // declared protocol, its expected ports, and whether the latest
    // probe saw each port open. Undeclared listeners follow, grouped
    // by a small classifier instead of a 100-socket wall.
    let has_wg = server
        .enabled_protocols
        .iter()
        .any(|p| p.0.contains("wireguard") || p.0.contains("amnezia") || p.0.contains("wgturn"));
    // Group the undeclared listeners. Adopt/ignore actions are
    // deliberately absent — the inventory doesn't model per-peer
    // ports yet (NM-14); this table only keeps the wall readable.
    let mut wg_peers = 0usize;
    let mut caddy_internals: Vec<String> = Vec::new();
    let mut unclassified: Vec<String> = Vec::new();
    for (proto, port) in extra {
        if proto == "tcp" && (*port == 2019 || *port == 80) {
            caddy_internals.push(format!("{proto}/{port}"));
        } else if has_wg && proto == "udp" && *port >= 30000 {
            wg_peers += 1;
        } else {
            unclassified.push(format!("{proto}/{port}"));
        }
    }
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow {
            (tr(lang, "Declared vs observed", "Заявлено vs наблюдается")) " "
            span.ed-tip title=(tr(
                lang,
                "Declared = protocol in the inventory for this node. Listening = the latest probe found the port open (ss -tlnup). A declared-but-silent port is the dangerous drift; undeclared listeners are usually per-user wg peers.",
                "Заявлено = протокол в инвентаре этой ноды. Слушает = последняя проба нашла порт открытым (ss -tlnup). Заявлено-но-молчит — опасный дрейф; незаявленные слушатели обычно пер-пировые wg-порты.",
            )) { "ⓘ" }
        }
        @if !have_probe {
            p style="font-family: var(--serif); font-style: italic; color: var(--mute); margin-top: 8px;" {
                (tr(lang, "(no probe yet — poller runs every 10 min; sing-box nodes only)", "(probe ещё нет — поллер ходит раз в 10 минут; только sing-box ноды)"))
            }
        } @else {
            table.ed-grid style="margin-top: 8px;" {
                thead {
                    tr {
                        th { (tr(lang, "protocol", "протокол")) }
                        th { (tr(lang, "port(s)", "порт(ы)")) }
                        th { (tr(lang, "declared", "заявлен")) }
                        th { (tr(lang, "listening", "слушает")) }
                    }
                }
                tbody {
                    @for pid in &server.enabled_protocols {
                        @let ports = expected_ports_for_protocol(registry, pid, secrets);
                        @let silent = ports.iter().any(|pp| !observed.contains(pp));
                        tr class=(if silent && !ports.is_empty() { "on-warn" } else { "" }) {
                            td { b { (pid.0) } }
                            td.num.ed-grid__sm {
                                @if ports.is_empty() {
                                    span.ed-grid__mut { "—" }
                                } @else {
                                    @for (i, (proto, port)) in ports.iter().enumerate() {
                                        @if i > 0 { " · " }
                                        (port) "/" (proto)
                                    }
                                }
                            }
                            td { span style="color: var(--green);" { "✓" } }
                            td.ed-grid__sm {
                                @if ports.is_empty() {
                                    span.ed-grid__mut { (tr(lang, "n/a (no fixed port)", "н/д (нет фикс. порта)")) }
                                } @else {
                                    @for (i, pp) in ports.iter().enumerate() {
                                        @if i > 0 { " · " }
                                        @if observed.contains(pp) {
                                            span style="color: var(--green);" { "✓" }
                                        } @else {
                                            span.ed-grid__flag { "✗ " (tr(lang, "silent", "молчит")) }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            @if !missing.is_empty() {
                p style="font-family: var(--mono); font-size: 11px; color: var(--warm); margin-top: 8px;" {
                    "⚠ " (tr(lang, "declared but NOT listening: ", "заявлено, но НЕ слушает: "))
                    @for (i, (proto, port)) in missing.iter().enumerate() {
                        @if i > 0 { ", " }
                        (proto) "/" (port)
                    }
                    " — " (tr(lang, "re-deploy or check the service on the node", "передеплой или проверь сервис на ноде"))
                }
            }
            @if !extra.is_empty() {
                div.ed-art-eyebrow style="margin-top: 14px;" {
                    (tr(lang, "Listening but undeclared", "Слушает, но не заявлено"))
                    " · " (extra.len()) " "
                    span.ed-tip title=(tr(
                        lang,
                        "Per-user AmneziaWG peers each bind their own UDP port — expected, but the inventory doesn't model them yet (NM-14). This grouping keeps the wall readable; there's nothing to click.",
                        "Каждый пер-пировый порт AmneziaWG — свой UDP-сокет: ожидаемо, но инвентарь их пока не моделирует (NM-14). Группировка держит стену читабельной; кликать тут нечего.",
                    )) { "ⓘ" }
                }
                table.ed-grid style="margin-top: 8px;" {
                    thead {
                        tr {
                            th { (tr(lang, "group", "группа")) }
                            th.num { (tr(lang, "ports", "портов")) }
                            th { (tr(lang, "classification", "классификация")) }
                        }
                    }
                    tbody {
                        @if wg_peers > 0 {
                            tr {
                                td { b { (tr(lang, "wg per-user peers", "wg пер-пировые порты")) } }
                                td.num { (wg_peers) }
                                td.ed-grid__sm { span.ed-grid__flag { "⚠ " (tr(lang, "expected · unmodelled (NM-14)", "ожидаемо · не смоделировано (NM-14)")) } }
                            }
                        }
                        @if !caddy_internals.is_empty() {
                            tr {
                                td { b { "caddy internals" } }
                                td.num { (caddy_internals.len()) }
                                td.ed-grid__mut.ed-grid__sm { (caddy_internals.join(" · ")) " · " (tr(lang, "known-benign", "заведомо безобидно")) }
                            }
                        }
                        @if !unclassified.is_empty() {
                            tr {
                                td { b { (tr(lang, "unclassified", "не классифицировано")) } }
                                td.num { (unclassified.len()) }
                                td.ed-grid__sm { (unclassified.join(" · ")) }
                            }
                        }
                    }
                }
            } @else if missing.is_empty() {
                p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--soft); margin-top: 10px;" {
                    (tr(lang, "Declared and observed match. No drift.", "Заявленное и наблюдаемое совпадают. Дрейфа нет."))
                }
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
