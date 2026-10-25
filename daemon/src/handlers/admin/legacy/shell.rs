use maud::{Markup, html};

const VALID_THEMES: &[&str] = &["default", "newsprint", "foxed", "ink"];
const VALID_ACCENTS: &[&str] = &["default", "rust", "forest", "plum"];

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tweaks_inline_keeps_theme_and_accent_controls_in_both_locales() {
        for lang in [crate::i18n::Locale::En, crate::i18n::Locale::Ru] {
            let markup = tweaks_inline("ink", "rust", lang).into_string();
            assert!(markup.contains("action=\"/admin/tweak/theme\""));
            assert!(markup.contains("action=\"/admin/tweak/accent\""));
            for value in [
                "default",
                "newsprint",
                "foxed",
                "ink",
                "rust",
                "forest",
                "plum",
            ] {
                assert!(markup.contains(&format!("name=\"value\" value=\"{value}\"")));
            }
        }
    }
}
