use crate::handlers::admin::audit::sanitize_header_filename;
use crate::handlers::admin::icons::icon;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use maud::{Markup, html};

use super::helpers::{
    bad_request, error_resp, internal_error, not_found, render_page, theme_accent_lang,
};
use crate::AppState;

pub(crate) async fn backup_snapshot_now(State(state): State<AppState>) -> Response {
    let backup_dir = vpnctl_inventory::backup_dir_from_env();
    let snapshot_result = vpnctl_inventory::snapshot_now(&state.inv, &backup_dir).await;
    let snapshot_path: Option<String> = snapshot_result
        .as_ref()
        .ok()
        .map(|p| p.display().to_string());
    let snapshot_err: Option<String> = snapshot_result.as_ref().err().map(|e| e.to_string());

    if let Err(e) = state
        .inv
        .audit(
            "admin",
            "backup.snapshot",
            None,
            Some(&serde_json::json!({
                "trigger": "manual",
                "snapshot_path": snapshot_path,
                "snapshot_err": snapshot_err,
            })),
        )
        .await
    {
        tracing::warn!(
            target = "vpnctld::backup",
            error = %e,
            "audit write failed for manual backup.snapshot"
        );
    }
    if let Err(e) = snapshot_result {
        tracing::error!(target = "vpnctld::backup", error = %e, "manual snapshot failed");
        return super::helpers::error_resp(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            &format!("snapshot into {} failed: {e}", backup_dir.display()),
        );
    }
    Redirect::to("/admin/settings/backups#backups-section").into_response()
}

pub(crate) async fn backup_download(Path(name): Path<String>) -> Response {
    if !is_safe_snapshot_name(&name) {
        return bad_request(&format!(
            "invalid snapshot name '{name}' — expected '{prefix}<timestamp>{suffix}'",
            prefix = vpnctl_inventory::backup::SNAPSHOT_FILENAME_PREFIX,
            suffix = vpnctl_inventory::backup::SNAPSHOT_FILENAME_SUFFIX,
        ));
    }
    let backup_dir = vpnctl_inventory::backup_dir_from_env();
    let path = backup_dir.join(&name);
    let canon_dir = match std::fs::canonicalize(&backup_dir) {
        Ok(p) => p,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    let canon_path = match std::fs::canonicalize(&path) {
        Ok(p) => p,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return not_found(&format!("snapshot '{name}' not found"));
        }
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    if !canon_path.starts_with(&canon_dir) {
        return bad_request("snapshot path escaped backup dir — refusing");
    }
    let bytes = match std::fs::read(&canon_path) {
        Ok(b) => b,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    let mut resp = (StatusCode::OK, bytes).into_response();
    let headers = resp.headers_mut();
    if let Ok(v) = HeaderValue::from_str("application/octet-stream") {
        headers.insert(header::CONTENT_TYPE, v);
    }
    let safe_name = sanitize_header_filename(&name);
    if let Ok(v) = HeaderValue::from_str(&format!("attachment; filename=\"{safe_name}\"")) {
        headers.insert(header::CONTENT_DISPOSITION, v);
    }
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

pub(crate) async fn backup_self_test(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let backup_dir = vpnctl_inventory::backup_dir_from_env();
    let snapshots = match vpnctl_inventory::list_snapshots(&backup_dir) {
        Ok(list) => list,
        Err(e) => return internal_error(anyhow::Error::new(e)),
    };
    let Some(latest) = snapshots.into_iter().next() else {
        return error_resp(
            StatusCode::CONFLICT,
            "no snapshot to verify yet — click 'snapshot now' on /admin/settings/backups first, \
             or wait for the hourly scheduler to fire",
        );
    };
    let verify_result = vpnctl_inventory::verify_snapshot(&latest.path).await;
    match &verify_result {
        Ok(report) => {
            if let Err(e) = state
                .inv
                .audit(
                    "admin",
                    "backup.self_test",
                    Some(&latest.file_name),
                    Some(&serde_json::json!({
                        "snapshot_path": &report.snapshot_path,
                        "snapshot_age_seconds": report.snapshot_age_seconds,
                        "overall": report.overall.label(),
                        "duration_ms": report.duration_ms,
                        "user_count": report.user_count,
                        "server_count": report.server_count,
                        "grant_count": report.grant_count,
                    })),
                )
                .await
            {
                tracing::warn!(
                    target = "vpnctld::backup",
                    error = %e,
                    "audit write failed for backup.self_test"
                );
            }
        }
        Err(err) => {
            if let Err(e) = state
                .inv
                .audit(
                    "admin",
                    "backup.self_test",
                    Some(&latest.file_name),
                    Some(&serde_json::json!({
                        "overall": "error",
                        "error": err.to_string(),
                    })),
                )
                .await
            {
                tracing::warn!(
                    target = "vpnctld::backup",
                    error = %e,
                    "audit write failed for backup.self_test (err branch)"
                );
            }
        }
    }

    let report = match verify_result {
        Ok(r) => r,
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("stat snapshot") {
                return error_resp(
                    StatusCode::CONFLICT,
                    "snapshot vanished between list and verify — click 'run restore self-test' again",
                );
            }
            return internal_error(anyhow::Error::new(e));
        }
    };

    let (theme, accent, lang) = theme_accent_lang(&headers);
    let body = render_self_test_report(&report, lang);
    render_page(&state, "settings", &theme, &accent, lang, body)
        .await
        .into_response()
}

fn render_self_test_report(
    report: &vpnctl_inventory::SelfTestReport,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    use vpnctl_inventory::CheckStatus;
    let overall_color = match report.overall {
        CheckStatus::Ok => "#2e7d32",
        CheckStatus::Warn => "#e6a23c",
        CheckStatus::Fail => "#c62828",
    };
    let overall_label = match report.overall {
        CheckStatus::Ok => tr(lang, "PASS", "ПРОЙДЕНО"),
        CheckStatus::Warn => tr(
            lang,
            "PASS · with warnings",
            "ПРОЙДЕНО · с предупреждениями",
        ),
        CheckStatus::Fail => tr(lang, "FAIL", "ПРОВАЛ"),
    };
    let age_str = match report.snapshot_age_seconds {
        Some(s) if s < 3600 => format!("{} min", s / 60),
        Some(s) if s < 86400 => format!("{} h", s / 3600),
        Some(s) => format!("{} d", s / 86400),
        None => tr(lang, "(unknown)", "(неизвестно)").to_string(),
    };
    html! {
        h1 style="font-family: var(--serif); font-weight: 400; margin: 24px 0 4px;" {
            (tr(lang, "Restore self-test", "Самопроверка восстановления"))
        }
        p style="font-family: var(--serif); font-style: italic; color: var(--mute); margin: 0 0 18px;" {
            (tr(
                lang,
                "Did the latest snapshot actually restore into a usable database? Run on every operator click; cron-schedulable next.",
                "Восстанавливается ли последний снэпшот в рабочую БД? Запускается по клику оператора; cron-расписание — следующий шаг.",
            ))
        }
        div style=(format!(
            "display: grid; grid-template-columns: max-content 1fr; gap: 8px 16px; padding: 12px 14px; border: 2px solid {overall_color}; background: var(--paper); margin-bottom: 20px;"
        )) {
            div style="font-family: var(--mono); font-size: 11px; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase;" { (tr(lang, "overall", "итог")) }
            div style=(format!("font-family: var(--serif); font-weight: 500; color: {overall_color};")) { (overall_label) }
            div style="font-family: var(--mono); font-size: 11px; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase;" { (tr(lang, "snapshot", "снэпшот")) }
            div style="font-family: var(--mono); font-size: 12px; overflow-wrap: anywhere;" { (report.snapshot_path) }
            div style="font-family: var(--mono); font-size: 11px; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase;" { (tr(lang, "age", "возраст")) }
            div style="font-family: var(--mono); font-size: 12px;" { (age_str) }
            div style="font-family: var(--mono); font-size: 11px; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase;" { (tr(lang, "duration", "длительность")) }
            div style="font-family: var(--mono); font-size: 12px;" { (report.duration_ms) " ms" }
        }
        div.ed-rule {}
        div.ed-art-eyebrow { (tr(lang, "Per-check results", "Результаты проверок")) }
        table style="width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 12px; margin-top: 10px;" {
            thead {
                tr style="border-bottom: 1px solid var(--ink);" {
                    th style="text-align: left; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                        (tr(lang, "check", "проверка"))
                    }
                    th style="text-align: left; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                        (tr(lang, "status", "статус"))
                    }
                    th style="text-align: left; padding: 6px 8px; font-weight: 500; color: var(--mute); letter-spacing: 0.10em; text-transform: uppercase; font-size: 10px;" {
                        (tr(lang, "detail", "детали"))
                    }
                }
            }
            tbody {
                @for c in &report.checks {
                    @let color = match c.status {
                        CheckStatus::Ok => "var(--green)",
                        CheckStatus::Warn => "var(--warm)",
                        CheckStatus::Fail => "var(--red, #c62828)",
                    };
                    tr style="border-bottom: 1px dotted var(--rule);" {
                        td style="padding: 6px 8px;" { (c.name) }
                        td style=(format!("padding: 6px 8px; font-weight: 500; color: {color};")) {
                            (c.status.label().to_uppercase())
                        }
                        td style="padding: 6px 8px;" { (self_test_check_detail(c, lang)) }
                    }
                }
            }
        }
        div style="margin-top: 24px; display: flex; gap: 12px;" {
            form method="post" action="/admin/backup/self-test" style="display: inline;" {
                button type="submit"
                       style="padding: 6px 14px; border: 1px solid var(--ink); background: var(--ink); color: var(--paper); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                    (icon("rotate-cw")) (tr(lang, "run again", "запустить снова"))
                }
            }
            a href="/admin/settings/backups#backups-section"
              style="padding: 6px 14px; border: 1px solid var(--rule); color: var(--ink); font-family: var(--mono); font-size: 11px; text-decoration: none;" {
                (icon("arrow-left")) (tr(lang, "back to Settings", "назад к настройкам"))
            }
        }
    }
}

fn self_test_check_detail(
    check: &vpnctl_inventory::CheckResult,
    lang: crate::i18n::Locale,
) -> String {
    use crate::i18n::tr;
    if check.status != vpnctl_inventory::CheckStatus::Warn {
        return check.detail.clone();
    }
    let detail = check.detail.as_str();
    match check.name {
        "grants_present" if detail == "0 grants" => {
            return tr(lang, "0 grants", "0 разрешений доступа").to_string();
        }
        "users_have_sub_tokens" => {
            if let Some(counts) = detail.strip_suffix(" users have sub_token") {
                return format!(
                    "{counts} {}",
                    tr(
                        lang,
                        "users have sub_token",
                        "пользователей имеют sub_token"
                    )
                );
            }
        }
        "schema_migrations_match_binary" => {
            if let Some((applied, expected)) = detail
                .strip_prefix("snapshot has ")
                .and_then(|s| s.strip_suffix(" (snapshot from older/newer vpnctld?)"))
                .and_then(|s| s.split_once(" migrations, binary expects "))
            {
                return format!(
                    "{} {applied}{} {expected} {}",
                    tr(lang, "snapshot has", "Миграций в снэпшоте:"),
                    tr(lang, " migrations, binary expects", ", программа ожидает"),
                    tr(
                        lang,
                        "(snapshot from older/newer vpnctld?)",
                        "(снэпшот от другой версии vpnctld?)",
                    ),
                );
            }
        }
        "snapshot_freshness" => {
            if let Some(seconds) = detail
                .strip_prefix("snapshot timestamp is ")
                .and_then(|s| s.strip_suffix(" seconds in the future (clock skew?)"))
            {
                return format!(
                    "{} {seconds} {}",
                    tr(lang, "snapshot timestamp is", "Время снэпшота на"),
                    tr(
                        lang,
                        "seconds in the future (clock skew?)",
                        "секунд в будущем (сбой часов?)"
                    ),
                );
            }
            if let Some(hours) = detail
                .strip_prefix("snapshot is ")
                .and_then(|s| s.strip_suffix(" hours old"))
            {
                return format!(
                    "{} {hours} {}",
                    tr(lang, "snapshot is", "Возраст снэпшота:"),
                    tr(lang, "hours old", "часов"),
                );
            }
        }
        _ => {}
    }
    check.detail.clone()
}

fn is_safe_snapshot_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 128 {
        return false;
    }
    if name
        .chars()
        .any(|c| c.is_control() || matches!(c, '/' | '\\' | '\0' | '"' | '\'' | '`'))
    {
        return false;
    }
    vpnctl_inventory::parse_snapshot_filename(name).is_some()
}

#[cfg(test)]
mod tests {
    use super::render_self_test_report;
    use crate::i18n::Locale;
    use vpnctl_inventory::{CheckResult, CheckStatus, SelfTestReport};

    #[test]
    fn self_test_report_translates_all_warning_reasons() {
        let cases = [
            ("grants_present", "0 grants", "0 разрешений доступа"),
            (
                "users_have_sub_tokens",
                "1/3 users have sub_token",
                "1/3 пользователей имеют sub_token",
            ),
            (
                "schema_migrations_match_binary",
                "snapshot has 42 migrations, binary expects 43 (snapshot from older/newer vpnctld?)",
                "Миграций в снэпшоте: 42, программа ожидает 43 (снэпшот от другой версии vpnctld?)",
            ),
            (
                "snapshot_freshness",
                "snapshot timestamp is 120 seconds in the future (clock skew?)",
                "Время снэпшота на 120 секунд в будущем (сбой часов?)",
            ),
            (
                "snapshot_freshness",
                "snapshot is 26 hours old",
                "Возраст снэпшота: 26 часов",
            ),
            ("future_check", "unknown diagnostic", "unknown diagnostic"),
        ];
        let report = SelfTestReport {
            snapshot_path: "/tmp/inv.db.bak".into(),
            snapshot_size_bytes: 4096,
            snapshot_age_seconds: Some(26 * 3600),
            schema_migrations_applied: 42,
            user_count: 3,
            server_count: 1,
            grant_count: 0,
            users_with_sub_token: 1,
            started_at: chrono::Utc::now(),
            duration_ms: 1,
            overall: CheckStatus::Warn,
            checks: cases
                .iter()
                .map(|&(name, detail, _)| CheckResult {
                    name,
                    status: CheckStatus::Warn,
                    detail: detail.into(),
                })
                .collect(),
        };
        let en = render_self_test_report(&report, Locale::En).into_string();
        let ru = render_self_test_report(&report, Locale::Ru).into_string();
        assert!(ru.contains("ПРОЙДЕНО · с предупреждениями"));
        for (name, detail, translated) in cases {
            assert!(en.contains(detail), "English reason changed for {name}");
            assert!(ru.contains(translated), "missing Russian reason for {name}");
            if detail != translated {
                assert!(!ru.contains(detail), "untranslated reason for {name}");
            }
        }
    }
}
