use maud::{Markup, html};

const VALID_THEMES: &[&str] = &["default", "newsprint", "foxed", "ink"];
const VALID_ACCENTS: &[&str] = &["default", "rust", "forest", "plum"];

#[allow(dead_code)]
fn glyph(size: u32) -> Markup {
    crate::handlers::admin::ui::glyph(size)
}

#[derive(Clone, Copy)]
#[allow(dead_code)]
struct NavItem {
    key: &'static str,
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

#[allow(dead_code)]
fn nav_href(key: &str) -> String {
    if key == "dashboard" {
        "/admin/".to_string()
    } else {
        format!("/admin/{key}")
    }
}

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
                span style="color: var(--acc); display: flex;" { (glyph(18)) }
                "vpnctl"
            }
            nav.ed-tb__nav {
                @for it in NAV {
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
                    @if let Some(name) = crate::handlers::admin::helpers::operator_name() {
                        span.ed-tb__host { " · " (t(lang, K::NavOperator)) " " (name) }
                    }
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
                span { (t(lang, K::FootStack)) }
            }
            span { "github.com/PavelLizunov/vpnctl" }
        }
    }
}

pub(super) fn tweaks_inline(theme: &str, accent: &str, lang: crate::i18n::Locale) -> Markup {
    use crate::i18n::tr;
    html! {
        div style="display: flex; flex-direction: column; gap: 10px; padding: 12px 14px; border: 1px solid var(--rule); background: var(--paper); font-family: var(--mono); font-size: 11px; color: var(--soft); max-width: 480px;" {
            form method="post" action="/admin/tweak/theme" style="display: flex; gap: 6px; align-items: baseline;" {
                span style="width: 60px; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" { (crate::handlers::admin::icons::icon("palette")) " " (tr(lang, "paper", "бумага")) }
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
