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
    let backup_dir = std::path::PathBuf::from(crate::app::DEFAULT_BACKUP_DIR);
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
            &format!(
                "snapshot into {} failed: {e}",
                crate::app::DEFAULT_BACKUP_DIR
            ),
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
    let backup_dir = std::path::PathBuf::from(crate::app::DEFAULT_BACKUP_DIR);
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
    let backup_dir = std::path::PathBuf::from(crate::app::DEFAULT_BACKUP_DIR);
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
                        td style="padding: 6px 8px;" { (c.detail) }
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
