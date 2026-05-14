//! Admin UI handlers — Phase A foundation.
//!
//! Builds the editorial-style v3 shell (masthead + inline nav + main +
//! footer) using `maud` SSR. Theme and accent are page-class modifiers
//! driven by cookies (`vpnctl_theme`, `vpnctl_accent`); switching is a
//! POST to `/admin/tweak/...` which sets the cookie and redirects back.
//!
//! All admin routes live behind a basic-auth middleware (see
//! `super::auth::basic_auth_layer`).

use axum::extract::Path;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use maud::{DOCTYPE, Markup, html};

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

fn nav(active: &str) -> Markup {
    html! {
        nav.ed-mast__nav-inline style="padding: 12px 56px 0; border-bottom: 1px solid var(--rule);" {
            @for it in NAV {
                a class=(if it.key == active { "on" } else { "" }) {
                    (it.label)
                    @if let Some(c) = it.count {
                        span.ct { (c) }
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

pub(crate) async fn dashboard(headers: HeaderMap) -> Markup {
    let theme = cookie(&headers, COOKIE_THEME)
        .unwrap_or("default")
        .to_string();
    let accent = cookie(&headers, COOKIE_ACCENT)
        .unwrap_or("default")
        .to_string();

    let body = html! {
        // Phase A placeholder — masthead/nav/footer/tweaks are real;
        // dashboard content lands in Phase B.
        div.ed-art-eyebrow { "Phase A · foundation" }
        h1.ed-art-h1 { "vpnctl " em { "admin" } }
        p.ed-art-deck {
            "The shell is wired. "
            b { "Masthead, nav, footer, theme + accent toggles" }
            " all read from real state. The screens themselves "
            em { "(dashboard, servers, users, audit, monitoring, settings)" }
            " arrive in subsequent phases."
        }
        div.ed-rule {}
        div.ed-art-eyebrow { "Currently wired" }
        ul style="font-family: var(--serif); font-size: 15px; line-height: 1.8; color: var(--soft); list-style: none; padding: 0;" {
            li { "— masthead with " span.ed-mono { "[•]" } " glyph and date strip" }
            li { "— inline nav with active-page rule" }
            li { "— footer with version" }
            li { "— Tweaks panel (paper × accent), cookie-persistent" }
            li { "— basic-auth middleware on " span.ed-mono { "/admin/*" } " (env: VPNCTLD_ADMIN_USER / VPNCTLD_ADMIN_PASSWORD)" }
        }
    };
    shell("dashboard", &theme, &accent, body)
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
    let referer = headers
        .get(header::REFERER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("/admin/")
        .to_string();
    let mut resp = Redirect::to(&referer).into_response();
    if let Ok(hv) = HeaderValue::from_str(&cookie_val) {
        resp.headers_mut().append(header::SET_COOKIE, hv);
    }
    resp
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
