//! Fleet alert digest formatting for Telegram.

use crate::i18n::{Locale, noun_for};

use super::formatting::{esc, pick};

/// Render a fleet digest as a Telegram HTML message. `open_titles` are
/// the already-rendered, HTML-safe `{icon} {title}` lines of every open
/// alert (caller produces them via `render_alert`). Empty → an «all
/// clear» 🟢 summary; non-empty → a 🔴 list. `servers` is the fleet size
/// for the headline context.
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
            m.push_str(line); // already icon + HTML-escaped title
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
