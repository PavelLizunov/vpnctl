use serde_json::json;

use super::{is_silent, render_alert, render_digest_html, to_telegram_html};
use crate::i18n::Locale;

/// Every kind the daemon actually fires. Keep in lockstep with the
/// `kind=` literals in health_monitor.rs + node_probe_poller.rs.
const SHIPPED_KINDS: &[(&str, &str)] = &[
    ("server.singbox.down", "critical"),
    ("server.singbox.up", "info"),
    ("server.fail2ban.banned_self", "critical"),
    ("server.unreachable", "warning"),
    ("server.fail2ban.down", "warning"),
    ("server.fail2ban.up", "info"),
    ("server.disk.pressure", "warning"),
    ("server.disk.recovered", "info"),
    ("server.mem.pressure", "warning"),
    ("server.mem.recovered", "info"),
    ("server.singbox.log.too_big", "warning"),
    ("server.singbox.log.recovered", "info"),
    ("server.singbox.restarted", "warning"),
    ("server.fingerprint.drift", "warning"),
    ("server.quality.degraded", "warning"),
    ("user.traffic_limit", "warning"),
    ("server.attribution.stalled", "warning"),
    ("user.sub_no_traffic", "warning"),
    ("sub_access.suspicious_local_ip", "warning"),
    ("boosty.sync.failed", "warning"),
];

#[test]
fn every_known_kind_has_a_dedicated_arm() {
    // The fallback arm produces a title starting with "Событие"/"Alert".
    // A shipped kind must NOT hit it → its title differs.
    for (kind, sev) in SHIPPED_KINDS {
        for loc in [Locale::En, Locale::Ru] {
            let r = render_alert(kind, sev, "де", &json!({}), loc);
            assert!(
                !r.title.starts_with("Alert ") && !r.title.starts_with("Событие "),
                "kind {kind} fell through to the fallback arm ({loc:?})"
            );
            assert!(
                !r.title.is_empty() && !r.body.is_empty(),
                "empty render for {kind}"
            );
        }
    }
}

#[test]
fn both_locales_differ_for_every_kind() {
    for (kind, sev) in SHIPPED_KINDS {
        let en = render_alert(
            kind,
            sev,
            "Germany",
            &json!({"current_pct":91,"consecutive_failures":3}),
            Locale::En,
        );
        let ru = render_alert(
            kind,
            sev,
            "Германия",
            &json!({"current_pct":91,"consecutive_failures":3}),
            Locale::Ru,
        );
        assert_ne!(en.title, ru.title, "title not localized for {kind}");
        assert_ne!(en.body, ru.body, "body not localized for {kind}");
    }
}

#[test]
fn auto_remediation_recovery_says_fixed_automatically() {
    let payload = json!({
        "auto_remediated": true,
        "current_pct": 42,
        "current_bytes": 1024,
    });
    for kind in [
        "server.singbox.up",
        "server.fail2ban.up",
        "server.disk.recovered",
        "server.singbox.log.recovered",
    ] {
        let en = render_alert(kind, "info", "node", &payload, Locale::En);
        let ru = render_alert(kind, "info", "нода", &payload, Locale::Ru);
        assert!(en.title.contains("Fixed automatically"), "{kind}: {en:?}");
        assert!(
            ru.title.contains("Исправлено автоматически"),
            "{kind}: {ru:?}"
        );
    }
}

#[test]
fn unreachable_ru_is_pretty_and_actionable() {
    let r = render_alert(
        "server.unreachable",
        "warning",
        "Нидерланды",
        &json!({"consecutive_failures": 3, "ip": "194.87.222.111"}),
        Locale::Ru,
    );
    assert_eq!(r.icon, "🟠");
    assert!(r.title.contains("Нода недоступна") && r.title.contains("Нидерланды"));
    assert!(r.body.contains("194.87.222.111") && r.body.contains("3 проверок"));
    assert!(r.action.as_ref().unwrap().contains("хостер"));
    // No shell instructions in the action (operator-action policy).
    assert!(!r.action.as_ref().unwrap().to_lowercase().contains("ssh "));
}

#[test]
fn recovery_kinds_get_green_icon_and_no_action() {
    for kind in [
        "server.singbox.up",
        "server.fail2ban.up",
        "server.disk.recovered",
        "server.mem.recovered",
        "server.singbox.log.recovered",
    ] {
        let r = render_alert(kind, "info", "де", &json!({"current_pct": 40}), Locale::Ru);
        assert_eq!(r.icon, "🟢", "{kind} should be green");
        assert!(r.action.is_none(), "{kind} should have no action line");
        assert!(is_silent("info"), "recovery should be silent");
    }
}

#[test]
fn severity_icons() {
    assert_eq!(
        render_alert(
            "server.singbox.down",
            "critical",
            "x",
            &json!({}),
            Locale::En
        )
        .icon,
        "🔴"
    );
    assert_eq!(
        render_alert(
            "server.disk.pressure",
            "warning",
            "x",
            &json!({}),
            Locale::En
        )
        .icon,
        "🟠"
    );
    assert_eq!(
        render_alert(
            "server.attribution.stalled",
            "warning",
            "x",
            &json!({}),
            Locale::En
        )
        .icon,
        "🟠"
    );
}

#[test]
fn suspicious_local_ip_text_does_not_assume_proxy_misconfiguration() {
    let payload = json!({"ip": "192.168.1.23"});
    let en = render_alert(
        "sub_access.suspicious_local_ip:alice",
        "warning",
        "alice",
        &payload,
        Locale::En,
    );
    assert!(en.body.contains("local or loopback IP"), "got: {}", en.body);
    assert!(
        !en.body.contains("trusted-proxy list is empty")
            && !en.body.contains("logged client IP will be wrong"),
        "the detector does not establish either claim: {}",
        en.body
    );
    assert!(
        en.action.as_deref().is_some_and(
            |action| action.contains("Only if it should have passed through a reverse proxy")
        ),
        "proxy remediation must remain conditional: {en:?}"
    );

    let ru = render_alert(
        "sub_access.suspicious_local_ip:alice",
        "warning",
        "alice",
        &payload,
        Locale::Ru,
    );
    assert!(
        !ru.body.contains("пустом списке доверенных прокси")
            && !ru.body.contains("IP в логах будет неверным"),
        "the detector does not establish either claim: {}",
        ru.body
    );
}

#[test]
fn kind_with_user_suffix_is_stripped() {
    // `user.traffic_limit:alice` must match the base arm.
    let r = render_alert(
        "user.traffic_limit:alice",
        "warning",
        "alice",
        &json!({"used_pct": 82}),
        Locale::Ru,
    );
    assert!(
        r.title.contains("лимит"),
        "suffix kind didn't match base arm: {}",
        r.title
    );
    assert!(r.body.contains("82%"));
}

#[test]
fn html_escape_prevents_injection_in_subject() {
    // A subject carrying `<b>` must be escaped, not rendered as markup.
    let r = render_alert(
        "server.unreachable",
        "warning",
        "<b>evil</b>",
        &json!({}),
        Locale::Ru,
    );
    assert!(
        r.title.contains("&lt;b&gt;evil&lt;/b&gt;"),
        "subject not escaped: {}",
        r.title
    );
    assert!(!r.title.contains("<b>evil"));
}

#[test]
fn action_has_no_shell_instructions() {
    // operator-action policy: no `ssh root@`, `journalctl`, `systemctl`
    // in any localized action line.
    for (kind, sev) in SHIPPED_KINDS {
        for loc in [Locale::En, Locale::Ru] {
            let r = render_alert(kind, sev, "x", &json!({}), loc);
            if let Some(a) = &r.action {
                let low = a.to_lowercase();
                for bad in ["ssh root@", "journalctl", "systemctl", "ssh -i"] {
                    assert!(
                        !low.contains(bad),
                        "{kind} action leaks shell instruction {bad:?}: {a}"
                    );
                }
            }
        }
    }
}

#[test]
fn telegram_html_layout() {
    let r = render_alert(
        "server.disk.pressure",
        "warning",
        "Германия",
        &json!({"current_pct": 91}),
        Locale::Ru,
    );
    let html = to_telegram_html(&r, Locale::Ru, "26 июня, 17:40 MSK", true);
    assert!(html.starts_with("🟠 <b>Мало места на диске — Германия</b>"));
    assert!(html.contains("<code>91%</code>"));
    assert!(html.contains("🕐 26 июня, 17:40 MSK · 🔁 повтор"));
    assert!(html.contains("⚙️ "));
    // No raw `<` outside the tags we emit (sanity: balanced <b>/<code>).
    assert_eq!(html.matches("<b>").count(), 1);
    assert_eq!(html.matches("</b>").count(), 1);
}

#[test]
fn unreachable_info_severity_renders_recovery_not_down() {
    // Edit-on-recover uses severity=info on the same kind to signal
    // the 🟢 recovery variant (unreachable has no `.up` kind).
    let up = render_alert(
        "server.unreachable",
        "info",
        "Нидерланды",
        &json!({}),
        Locale::Ru,
    );
    assert_eq!(up.icon, "🟢");
    assert!(up.title.contains("снова доступна"), "got: {}", up.title);
    assert!(up.action.is_none(), "recovery has no what-to-do line");
    assert!(is_silent("info"), "recovery push is silent");
    // The warning variant is still the 🟠 down message — same kind.
    let down = render_alert(
        "server.unreachable",
        "warning",
        "Нидерланды",
        &json!({"consecutive_failures": 3}),
        Locale::Ru,
    );
    assert_eq!(down.icon, "🟠");
    assert!(down.title.contains("недоступна"), "got: {}", down.title);
    // EN side too.
    let up_en = render_alert("server.unreachable", "info", "NL", &json!({}), Locale::En);
    assert!(
        up_en.title.contains("reachable again"),
        "got: {}",
        up_en.title
    );
}

#[test]
fn user_body_keeps_inline_bold_and_escapes_subject() {
    // user.* bodies wrap the (escaped) subject in literal <b>…</b>.
    // A `<` in the user id must be escaped INSIDE the bold, and the
    // title's own <b> must stay balanced — guards against a
    // double-escape or a stray-tag regression in the user arms.
    let r = render_alert(
        "user.traffic_limit:weird",
        "warning",
        "a<b>c",
        &json!({"used_pct": 82}),
        Locale::Ru,
    );
    let html = to_telegram_html(&r, Locale::Ru, "26.06 17:40 MSK", false);
    // The dangerous `<b>` from the subject is escaped everywhere.
    assert!(html.contains("a&lt;b&gt;c"));
    assert!(!html.contains("a<b>c"));
    // Title bold + the body's inline bold around the subject → two pairs.
    assert_eq!(html.matches("<b>").count(), 2);
    assert_eq!(html.matches("</b>").count(), 2);
    assert!(html.contains("82%"));
}

#[test]
fn unknown_kind_escapes_the_raw_kind() {
    // Fallback arm must escape the kind too (parse_mode=HTML safety).
    let r = render_alert("weird.<kind>", "warning", "x", &json!({}), Locale::En);
    assert!(r.body.contains("weird.&lt;kind&gt;"));
    assert!(!r.body.contains("weird.<kind>"));
}

#[test]
fn digest_all_clear_vs_problems() {
    // All-clear: 🟢 + the fleet size, no bullet list.
    let clear = render_digest_html(Locale::Ru, 4, &[], "27.06 10:00 MSK");
    assert!(clear.starts_with("🟢 <b>Дайджест vpnctl — всё спокойно</b>"));
    assert!(clear.contains("4 сервера под наблюдением"));
    assert!(!clear.contains("• "));
    assert!(clear.contains("🕐 27.06 10:00 MSK"));
    // Problems: 🔴 + count + one bullet per title.
    let probs = render_digest_html(
        Locale::Ru,
        4,
        &[
            "🔴 <b>sing-box упал — de</b>".into(),
            "🟠 <b>Мало места на диске — fi</b>".into(),
        ],
        "27.06 10:00 MSK",
    );
    assert!(probs.contains("2 открытые проблемы"));
    assert!(probs.contains("• 🔴 <b>sing-box упал — de</b>"));
    assert_eq!(probs.matches("• ").count(), 2);
    // EN side.
    let en = render_digest_html(Locale::En, 3, &[], "27.06 10:00 MSK");
    assert!(en.contains("all clear") && en.contains("3 servers"));
}

#[test]
fn digest_ru_declines_problem_and_server_counts() {
    let title = "🟠 <b>test</b>".to_string();
    for (n, expected) in [
        (1, "1 открытая проблема"),
        (2, "2 открытые проблемы"),
        (5, "5 открытых проблем"),
        (11, "11 открытых проблем"),
        (14, "14 открытых проблем"),
        (21, "21 открытая проблема"),
    ] {
        let html = render_digest_html(Locale::Ru, 4, &vec![title.clone(); n], "now");
        assert!(html.contains(expected), "n={n}: {html}");
    }

    for (servers, expected) in [
        (1, "1 сервер под наблюдением"),
        (2, "2 сервера под наблюдением"),
        (4, "4 сервера под наблюдением"),
        (5, "5 серверов под наблюдением"),
        (11, "11 серверов под наблюдением"),
        (21, "21 сервер под наблюдением"),
    ] {
        let html = render_digest_html(Locale::Ru, servers, &[], "now");
        assert!(html.contains(expected), "servers={servers}: {html}");
    }
}

#[test]
fn quality_degraded_warning_and_recovery_render_metrics_properly() {
    let payload_warn = json!({
        "score": 45,
        "availability_pct": 85.0,
        "packet_loss_pct": 15.0,
        "p95_rtt_ms": 230,
        "jitter_ms": 12.5,
        "samples": 24,
        "vantage": "RU-MOW",
        "low_threshold": 60,
        "recover_threshold": 75,
    });

    let warn_en = render_alert(
        "server.quality.degraded",
        "warning",
        "Germany",
        &payload_warn,
        Locale::En,
    );
    assert_eq!(warn_en.icon, "🟠");
    assert!(warn_en.title.contains("Service quality degraded — Germany"));
    assert!(warn_en.body.contains("45/100"));
    assert!(warn_en.body.contains("85.0%"));
    assert!(warn_en.body.contains("15.0%"));
    assert!(warn_en.body.contains("230 ms"));
    assert!(warn_en.body.contains("RU-MOW"));
    assert!(warn_en.body.contains("60/100"));
    assert!(
        warn_en
            .action
            .as_ref()
            .unwrap()
            .contains("Check network connectivity")
    );

    let warn_ru = render_alert(
        "server.quality.degraded",
        "warning",
        "Германия",
        &payload_warn,
        Locale::Ru,
    );
    assert_eq!(warn_ru.icon, "🟠");
    assert!(
        warn_ru
            .title
            .contains("Качество связи деградировало — Германия")
    );
    assert!(warn_ru.body.contains("45/100"));
    assert!(warn_ru.body.contains("85.0%"));
    assert!(warn_ru.body.contains("15.0%"));
    assert!(warn_ru.body.contains("230 мс"));
    assert!(warn_ru.body.contains("RU-MOW"));
    assert!(warn_ru.body.contains("60/100"));
    assert!(
        warn_ru
            .action
            .as_ref()
            .unwrap()
            .contains("Проверь сетевую связность")
    );

    let payload_rec = json!({
        "score": 85,
        "availability_pct": 100.0,
        "packet_loss_pct": 0.0,
        "p95_rtt_ms": 45,
        "jitter_ms": 2.0,
        "samples": 24,
        "vantage": "RU-MOW",
        "low_threshold": 60,
        "recover_threshold": 75,
    });

    let rec_en = render_alert(
        "server.quality.degraded",
        "info",
        "Germany",
        &payload_rec,
        Locale::En,
    );
    assert_eq!(rec_en.icon, "🟢");
    assert!(rec_en.title.contains("Service quality recovered — Germany"));
    assert!(rec_en.body.contains("85/100"));
    assert!(rec_en.body.contains("0.0%"));
    assert!(rec_en.body.contains("45 ms"));
    assert!(rec_en.action.is_none());

    let rec_ru = render_alert(
        "server.quality.degraded",
        "info",
        "Германия",
        &payload_rec,
        Locale::Ru,
    );
    assert_eq!(rec_ru.icon, "🟢");
    assert!(
        rec_ru
            .title
            .contains("Качество связи восстановилось — Германия")
    );
    assert!(rec_ru.body.contains("85/100"));
    assert!(rec_ru.body.contains("0.0%"));
    assert!(rec_ru.body.contains("45 мс"));
    assert!(rec_ru.action.is_none());
}
