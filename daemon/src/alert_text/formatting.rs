//! Formatting and escaping helpers for alerts.

use crate::i18n::Locale;

/// A rendered alert split into its presentational parts. `title` already
/// includes the subject (e.g. "Нода недоступна — Нидерланды"); `body`
/// may contain `<code>…</code>` spans (HTML-escaped values).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedAlert {
    pub icon: &'static str,
    pub title: String,
    pub body: String,
    pub action: Option<String>,
}

/// HTML-escape a value going into a `parse_mode=HTML` Telegram message.
/// Telegram HTML only treats `<`, `>`, `&` as special. Applied to EVERY
/// interpolated value (subject, ip, user name) so a `<` in data can't
/// break the markup or inject a tag.
pub fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Whether the Telegram push for this severity should be SILENT
/// (`disable_notification=true`): info / recovery alerts don't buzz;
/// warning / critical do.
pub fn is_silent(severity: &str) -> bool {
    severity == "info"
}

/// Convert a rendered (Telegram-HTML) `title`/`body`/`action` string to
/// plain text for the admin UI — strips the fixed markup vocabulary
/// (`<b>`,`<code>`) then unescapes the 3 entities. Order matters: strip
/// real tags FIRST, then unescape, so a literal `<b>` in data (which the
/// render escaped to `&lt;b&gt;`) survives as text rather than being
/// stripped. maud re-escapes on render, so the result is injection-safe.
pub fn to_plain(s: &str) -> String {
    s.replace("<code>", "")
        .replace("</code>", "")
        .replace("<b>", "")
        .replace("</b>", "")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

/// Severity / kind → leading icon. Recovery (`*.up` / `*.recovered`, or
/// severity `info`) is always 🟢; otherwise by severity.
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

/// Pick the locale variant of a dynamic (interpolated) string. The
/// `i18n::tr` helper only takes `&'static str`; alert bodies interpolate
/// values, so they need this owned-String picker.
pub(crate) fn pick(loc: Locale, en: String, ru: String) -> String {
    match loc {
        Locale::En => en,
        Locale::Ru => ru,
    }
}

/// `<code>`-wrap an HTML-escaped value (for ips / ports / percentages).
pub(crate) fn code(s: &str) -> String {
    format!("<code>{}</code>", esc(s))
}

/// Lay a [`RenderedAlert`] out as a Telegram `parse_mode=HTML` message
/// body. `time_local` is the operator-TZ timestamp string; `repeat`
/// appends the «повтор» marker for a re-fired alert.
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
