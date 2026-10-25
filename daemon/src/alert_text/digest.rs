use crate::i18n::{Locale, noun_for};

use super::formatting::{esc, pick};

pub fn render_digest_html(
    loc: Locale,
    servers: usize,
    open_titles: &[String],
    time_local: &str,
) -> String {
    let mut m = String::with_capacity(256);
    let servers_noun = noun_for(
        loc,
        servers as u64,
        "server",
        "servers",
        "сервер",
        "сервера",
        "серверов",
    );
    if open_titles.is_empty() {
        m.push_str(match loc {
            Locale::En => "🟢 <b>vpnctl digest — all clear</b>",
            Locale::Ru => "🟢 <b>Дайджест vpnctl — всё спокойно</b>",
        });
        m.push_str("\n\n");
        m.push_str(&pick(
            loc,
            format!("{servers} {servers_noun} monitored · no open alerts."),
            format!("{servers} {servers_noun} под наблюдением · открытых алертов нет."),
        ));
    } else {
        let n = open_titles.len();
        let problems = noun_for(
            loc,
            n as u64,
            "open",
            "open",
            "открытая проблема",
            "открытые проблемы",
            "открытых проблем",
        );
        m.push_str(&pick(
            loc,
            format!("🔴 <b>vpnctl digest — {n} {problems}</b>"),
            format!("🔴 <b>Дайджест vpnctl — {n} {problems}</b>"),
        ));
        m.push_str("\n\n");
        for line in open_titles {
            m.push_str("• ");
            m.push_str(line);
            m.push('\n');
        }
        m.push_str(&pick(
            loc,
            format!("\n{servers} {servers_noun} monitored."),
            format!("\n{servers} {servers_noun} под наблюдением."),
        ));
    }
    m.push_str("\n\n🕐 ");
    m.push_str(&esc(time_local));
    m
}

// Split only renderer-generated HTML: tags and entities are already well formed.
pub(crate) fn render_digest_messages(
    loc: Locale,
    servers: usize,
    open_titles: &[String],
    time_local: &str,
) -> Vec<String> {
    const MAX_UNITS: usize = 4096;
    let html = render_digest_html(loc, servers, open_titles, time_local);
    let mut remaining = html.as_str();
    let mut messages = Vec::new();
    let mut message = String::new();
    let mut open_tags = Vec::new();
    let mut units = 0;
    while let Some(ch) = remaining.chars().next() {
        let end = match ch {
            '<' => remaining.find('>').map_or(ch.len_utf8(), |end| end + 1),
            '&' => remaining.find(';').map_or(ch.len_utf8(), |end| end + 1),
            _ => ch.len_utf8(),
        };
        let token = &remaining[..end];
        // UTF-16 units are a conservative bound for Telegram's character limit.
        let width = match ch {
            '<' => 0,
            '&' => 1,
            _ => ch.len_utf16(),
        };
        if units + width > MAX_UNITS {
            for tag in open_tags.iter().rev() {
                message.push_str(&format!("</{tag}>"));
            }
            messages.push(std::mem::take(&mut message));
            for tag in &open_tags {
                message.push_str(&format!("<{tag}>"));
            }
            units = 0;
        }
        message.push_str(token);
        if let Some(tag) = token.strip_prefix('<').and_then(|s| s.strip_suffix('>')) {
            if tag.starts_with('/') {
                open_tags.pop();
            } else {
                open_tags.push(tag);
            }
        }
        units += width;
        remaining = &remaining[end..];
    }
    messages.push(message);
    messages
}
