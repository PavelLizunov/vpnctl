//! Local editorial icons. Names are repository-owned Lucide symbol IDs.
use maud::{Markup, html};

/// Decorative icon; the caller keeps its visible text label.
pub(crate) fn icon(name: &str) -> Markup {
    html! {
        svg.ed-icon width="16" height="16" viewBox="0 0 24 24" fill="none"
            stroke="currentColor" stroke-width="1.8" stroke-linecap="round"
            stroke-linejoin="round" aria-hidden="true" focusable="false" {
            use href=(format!("/admin/assets/icons.svg#{name}")) {}
        }
    }
}

/// Standalone status with a localized accessible name, not color alone.
pub(crate) fn status(
    name: &str,
    lang: crate::i18n::Locale,
    en: &'static str,
    ru: &'static str,
) -> Markup {
    let label = crate::i18n::tr(lang, en, ru);
    html! { span.ed-icon-status role="img" aria-label=(label) { (icon(name)) } }
}
