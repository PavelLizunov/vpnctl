//! Backup admin handlers: immediate snapshot trigger, snapshot download,
//! and the restore self-test fire-drill.
//!
//! Extracted from `legacy.rs` as part of the admin submodules refactor.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use maud::{Markup, html};

use super::helpers::{
    bad_request, error_resp, internal_error, not_found, render_page, theme_accent_lang,
};
use crate::AppState;

// ────────────────────────────────────────────────────────────────────────
// Phase C-4 — inventory snapshot endpoints (web-side).
//
// The scheduler in `crate::app::spawn_backup_scheduler` produces hourly
// snapshots; these two handlers give the operator the same controls
// from the Settings page WITHOUT having to wait an hour.
//
//   * `POST /admin/backup/snapshot` — trigger an immediate snapshot,
//     audit the result, redirect back to /admin/settings.
//   * `GET  /admin/backup/download/{name}` — stream a specific
//     snapshot file from DEFAULT_BACKUP_DIR with
//     `Content-Disposition: attachment` so the browser saves it
//     instead of trying to render the binary inline.
// ────────────────────────────────────────────────────────────────────────

/// `POST /admin/backup/snapshot` — manual snapshot trigger. Same
/// underlying call as the hourly scheduler; audited with
/// `trigger: "manual"` so the timeline can distinguish.
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
        return internal_error(anyhow::Error::new(e));
    }
    // Fragment anchor → browser scrolls back to the Backups
    // section (where the operator pressed «snapshot now») instead
    // of jumping to the top of /admin/settings.
    Redirect::to("/admin/settings/backups#backups-section").into_response()
}

/// `GET /admin/backup/download/{name}` — stream a snapshot file with
/// `Content-Disposition: attachment`. The operator-supplied `name`
/// is validated strictly (the snapshot prefix + safe-charset filename)
/// so a "../" or absolute path can never escape `DEFAULT_BACKUP_DIR`.
pub(crate) async fn backup_download(Path(name): Path<String>) -> Response {
    // Filename validation — accept ONLY files matching the snapshot
    // naming convention. Rejects `../`, absolute paths, NUL bytes,
    // anything with a slash. Belt-and-braces vs the
    // `std::path::Path::join` semantics, which would otherwise let
    // an absolute path override the parent prefix.
    if !is_safe_snapshot_name(&name) {
        return bad_request(&format!(
            "invalid snapshot name '{name}' — expected '{prefix}<timestamp>{suffix}'",
            prefix = vpnctl_inventory::backup::SNAPSHOT_FILENAME_PREFIX,
            suffix = vpnctl_inventory::backup::SNAPSHOT_FILENAME_SUFFIX,
        ));
    }
    let backup_dir = std::path::PathBuf::from(crate::app::DEFAULT_BACKUP_DIR);
    let path = backup_dir.join(&name);
    // Defence in depth: ensure the resolved path is still inside the
    // backup dir even after `join`. `canonicalize` reads through
    // symlinks — the operator could in principle create a symlink in
    // the backup dir pointing at `/etc/passwd`, but the snapshot dir
    // is daemon-owned 0700 so they'd need a root-level compromise
    // already.
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
    let safe_name: String = name
        .chars()
        .filter(|c| !matches!(c, '"' | '\\' | '\r' | '\n') && !c.is_control())
        .collect();
    if let Ok(v) = HeaderValue::from_str(&format!("attachment; filename=\"{safe_name}\"")) {
        headers.insert(header::CONTENT_DISPOSITION, v);
    }
    resp
}

/// `POST /admin/backup/self-test` — restore fire-drill.
///
/// Picks the most recent local snapshot in `DEFAULT_BACKUP_DIR`,
/// runs [`vpnctl_inventory::verify_snapshot`] on it (which copies
/// it into a per-call tmpfile + replays migrations + queries data
/// presence metrics) and renders the report inline as HTML.
///
/// This is the «is our DR insurance actually valid?» button —
/// converts the periodic-bit-rot risk from «catches it the day 236
/// burns» to «catches it the next time the operator clicks the
/// button». Future work (cron-scheduled run + Telegram alert on
/// Fail) layers on top of this same primitive.
///
/// Audit row written every invocation with the report status; one
/// place an operator (or post-mortem) can see the history.
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
            "no snapshot to verify yet — click 'snapshot now' on /admin/settings first, \
             or wait for the hourly scheduler to fire",
        );
    };
    // Run + audit on EVERY attempt (incl. Err) so post-mortem replay
    // sees the operator's click even when verify itself broke. TOCTOU
    // friendliness: the snapshot can be pruned between `list_snapshots`
    // and `verify_snapshot` — return 409 in that narrow case rather
    // than a misleading 500.
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

/// Render the HTML body for the self-test result page. Pulled out
/// so a future «show last result on /admin/settings» pass can reuse
/// it without re-fetching the report.
fn render_self_test_report(
    report: &vpnctl_inventory::SelfTestReport,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    use vpnctl_inventory::CheckStatus;
    let overall_color = match report.overall {
        // Inline hex (not CSS vars): `--ok` and `--warn` aren't in
        // admin.css today and inlining keeps the self-test page's
        // colour palette self-contained. `--red` IS defined but we
        // keep the literal here for symmetry with the other two.
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
                        CheckStatus::Ok => "var(--ok, #2e7d32)",
                        CheckStatus::Warn => "var(--warn, #e6a23c)",
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
                    (tr(lang, "run again", "запустить снова"))
                }
            }
            a href="/admin/settings/backups#backups-section"
              style="padding: 6px 14px; border: 1px solid var(--rule); color: var(--ink); font-family: var(--mono); font-size: 11px; text-decoration: none;" {
                (tr(lang, "back to Settings", "назад к настройкам"))
            }
        }
    }
}

/// Strict accept for snapshot filename — only the EXACT pattern the
/// scheduler emits passes. Delegates to
/// `vpnctl_inventory::parse_snapshot_filename` so the validator stays
/// in lock-step with the emitter (a future change to the filename
/// shape only touches the inventory crate).
fn is_safe_snapshot_name(name: &str) -> bool {
    // Length / charset gate runs BEFORE the parser so a 10MB
    // filename can't OOM the daemon and `/` / NUL / control bytes
    // never reach the filesystem layer even if the parser ever
    // accidentally accepts them.
    if name.is_empty() || name.len() > 128 {
        return false;
    }
    if name
        .chars()
        .any(|c| c.is_control() || matches!(c, '/' | '\\' | '\0' | '"' | '\'' | '`'))
    {
        return false;
    }
    // Parser is the source of truth for the precise shape
    // (`inv.db.<RFC3339-ish>.bak`).
    vpnctl_inventory::parse_snapshot_filename(name).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_safe_snapshot_name_validates_pattern_and_rejects_injection() {
        assert!(!is_safe_snapshot_name(""));
        assert!(!is_safe_snapshot_name(
            "inv.db.2026-05-20T12:00:00Z.bak\r\nHeader: Value"
        ));
        assert!(!is_safe_snapshot_name("../inv.db.bak"));
        assert!(!is_safe_snapshot_name("inv.db.2026-05-20T12:00:00Z.bak\""));
        assert!(!is_safe_snapshot_name("inv.db.2026-05-20T12:00:00Z.bak\n"));
    }
}
