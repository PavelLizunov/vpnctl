//! Admin UI handlers — Phase A foundation.
//!
//! Builds the editorial-style v3 shell (masthead + inline nav + main +
//! footer) using `maud` SSR. Theme and accent are page-class modifiers
//! driven by cookies (`vpnctl_theme`, `vpnctl_accent`); switching is a
//! POST to `/admin/tweak/...` which sets the cookie and redirects back.
//!
//! All admin routes live behind a basic-auth middleware (see
//! `super::auth::basic_auth_layer`).

use maud::{Markup, html};

const VALID_THEMES: &[&str] = &["default", "newsprint", "foxed", "ink"];
const VALID_ACCENTS: &[&str] = &["default", "rust", "forest", "plum"];

/// Inline glyph — `[•]` bracket-dot, scales with `currentColor`. Matches
/// `Glyph()` from the design source.
#[allow(dead_code)]
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
#[allow(dead_code)]
struct NavItem {
    /// The URL path segment AND the `active_nav` matcher token. Stays
    /// English in both locales (URLs aren't localised).
    key: &'static str,
    /// The i18n key used to look up the localised label. topbar() calls
    /// `t(lang, label_key)` to get the actual rendered text.
    label_key: crate::i18n::K,
}

#[allow(dead_code)]
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
#[allow(dead_code)]
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
#[allow(dead_code)]
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

#[allow(dead_code)]
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
pub(super) fn tweaks_inline(theme: &str, accent: &str, lang: crate::i18n::Locale) -> Markup {
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
#[allow(dead_code)]
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

// Wraps a screen-specific body in the chrome (masthead + nav + main +
// foot). The implementation moved to helpers.rs.
// `topbar_alert_count`, `render_page`, `shell`, `cookie`, `theme_accent`, `theme_accent_lang` moved to helpers.rs
