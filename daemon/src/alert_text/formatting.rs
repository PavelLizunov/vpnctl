use crate::i18n::Locale;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedAlert {
    pub icon: &'static str,
    pub title: String,
    pub body: String,
    pub action: Option<String>,
}

pub fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

pub fn is_silent(severity: &str) -> bool {
    severity == "info"
}

pub fn to_plain(s: &str) -> String {
    s.replace("<code>", "")
        .replace("</code>", "")
        .replace("<b>", "")
        .replace("</b>", "")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

pub(crate) fn icon_for(kind: &str, severity: &str) -> &'static str {
    if severity == "info" || kind.ends_with(".up") || kind.ends_with(".recovered") {
        return "🟢";
    }
    match severity {
        "critical" => "🔴",
        "warning" => "🟠",
        _ => "🟡",
    }
}

pub(crate) fn pick(loc: Locale, en: String, ru: String) -> String {
    match loc {
        Locale::En => en,
        Locale::Ru => ru,
    }
}

pub(crate) fn code(s: &str) -> String {
    format!("<code>{}</code>", esc(s))
}

pub fn to_telegram_html(r: &RenderedAlert, loc: Locale, time_local: &str, repeat: bool) -> String {
    let mut m = String::with_capacity(256);
    m.push_str(r.icon);
    m.push_str(" <b>");
    m.push_str(&r.title);
    m.push_str("</b>\n\n");
    m.push_str(&r.body);
    m.push_str("\n\n🕐 ");
    m.push_str(&esc(time_local));
    if repeat {
        m.push_str(match loc {
            Locale::En => " · 🔁 repeat",
            Locale::Ru => " · 🔁 повтор",
        });
    }
    if let Some(a) = &r.action {
        m.push_str("\n⚙️ ");
        m.push_str(a);
    }
    m
}
