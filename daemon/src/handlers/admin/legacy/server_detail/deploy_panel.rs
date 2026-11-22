use chrono::{DateTime, Utc};
use maud::{Markup, html};
use vpnctl_core::Server;

use crate::AppState;
use crate::handlers::admin::helpers::{format_local_with_pattern, format_msk_iso, humanize_age};
use crate::handlers::admin::icons::icon;
use crate::http_util::path_segment_encode;
use crate::i18n::{Locale, tr};
use crate::wizard_bootstrap::{
    AutodeployPhase, AutodeployStatus, DeployActivity, DeployGuard, DeployOutcome, deploy_activity,
};

pub(super) struct DeployPanelFacts {
    pub(super) pending_raw: Option<bool>,
    pub(super) pending: Option<bool>,
    pub(super) operation: Option<AutodeployStatus>,
    pub(super) operation_updated_at: Option<DateTime<Utc>>,
    pub(super) activity: Option<DeployActivity>,
    pub(super) guard_active: bool,
    pub(super) last_success: Option<vpnctl_inventory::AuditEntry>,
    pub(super) last_failure: Option<vpnctl_inventory::AuditEntry>,
    pub(super) generated_at: DateTime<Utc>,
}

pub(super) async fn load(
    state: &AppState,
    server: &Server,
    pending_raw: Option<bool>,
    operation: Option<AutodeployStatus>,
    quality: Option<&vpnctl_inventory::quality::ServiceQualityMeasurement>,
) -> DeployPanelFacts {
    let pending = match (pending_raw, quality) {
        (Some(pending), Some(measurement)) => Some(pending || measurement.provisioned_at.is_none()),
        _ => None,
    };
    let guard_active = DeployGuard::is_active(&server.id.0);
    let activity = deploy_activity(&state.inv, &server.id.0);
    let operation_updated_at =
        crate::wizard_bootstrap::autodeploy_updated_at(&state.inv, &server.id.0);

    // Exact-target lookups keep a neighbouring node's audits out of this panel.
    let last_success = state
        .inv
        .latest_audit_for_target_action(&server.id.0, "server.deploy")
        .await
        .ok()
        .flatten();
    let mut last_failure = None;
    for action in [
        "server.deploy.failed",
        "server.deploy.skipped",
        "server.deploy.stale",
    ] {
        if let Ok(Some(row)) = state
            .inv
            .latest_audit_for_target_action(&server.id.0, action)
            .await
            && last_failure
                .as_ref()
                .is_none_or(|current: &vpnctl_inventory::AuditEntry| row.id > current.id)
        {
            last_failure = Some(row);
        }
    }

    DeployPanelFacts {
        pending_raw,
        pending,
        operation,
        operation_updated_at,
        activity,
        guard_active,
        last_success,
        last_failure,
        generated_at: Utc::now(),
    }
}

pub(super) struct DeployPanelView {
    pub(super) state: &'static str,
    pub(super) note: String,
    pub(super) stage_phase: Option<String>,
    pub(super) stage_message: Option<String>,
    pub(super) stage_at: Option<DateTime<Utc>>,
    pub(super) error: Option<String>,
    pub(super) can_start: bool,
    pub(super) generation: u64,
    pub(super) pending: Option<bool>,
    pub(super) pending_text: String,
    pub(super) last_success_at: Option<DateTime<Utc>>,
    pub(super) generated_at: DateTime<Utc>,
}

pub(super) fn view(facts: &DeployPanelFacts, lang: Locale) -> DeployPanelView {
    let success_row = facts.last_success.as_ref();
    let success_ts = success_row.map(|row| row.ts);
    let operation_updated_at = facts.operation_updated_at.unwrap_or(facts.generated_at);
    let current_operation = facts
        .operation
        .as_ref()
        .filter(|operation| match operation.phase {
            AutodeployPhase::Queued | AutodeployPhase::Running => true,
            AutodeployPhase::Failed => {
                success_ts.is_none_or(|success| operation_updated_at > success)
            }
        });
    let current_activity = facts
        .activity
        .as_ref()
        .filter(|activity| match activity.outcome {
            DeployOutcome::Running => {
                facts.guard_active
                    || current_operation.is_some_and(|operation| {
                        matches!(
                            operation.phase,
                            AutodeployPhase::Queued | AutodeployPhase::Running
                        )
                    })
            }
            DeployOutcome::Succeeded | DeployOutcome::Failed => success_ts.is_none_or(|success| {
                activity.finished_at.unwrap_or(activity.started_at) > success
            }),
        });
    let failure_audit = facts
        .last_failure
        .as_ref()
        .filter(|row| success_row.is_none_or(|success| row.id > success.id));

    let finished_at = current_activity.and_then(|activity| activity.finished_at);
    let current_operation = current_operation.filter(|op| {
        op.phase != AutodeployPhase::Failed
            || (!facts.guard_active
                && finished_at.is_none_or(|time| operation_updated_at >= time)
                && failure_audit.is_none_or(|audit| operation_updated_at >= audit.ts))
    });
    let current_activity = current_activity.filter(|activity| {
        activity.outcome == DeployOutcome::Running
            || (current_operation.is_none()
                && failure_audit
                    .is_none_or(|audit| activity.finished_at.is_some_and(|at| at >= audit.ts)))
    });

    let failure_tail = match facts.pending {
        Some(true) => tr(
            lang,
            "Saved changes remain pending. Retry deployment using the Deploy button.",
            "Сохранённые изменения остаются неприменёнными. Повтори через кнопку деплоя.",
        ),
        Some(false) => tr(
            lang,
            "No saved changes are pending. Retry deployment using the Deploy button.",
            "Неприменённых сохранённых изменений нет. Повтори через кнопку деплоя.",
        ),
        None => tr(
            lang,
            "Saved-change state is unknown. Retry deployment using the Deploy button.",
            "Состояние сохранённых изменений неизвестно. Повтори через кнопку деплоя.",
        ),
    };

    let (state, note) = if let Some(activity) = current_activity
        && activity.outcome == DeployOutcome::Running
    {
        (
            "running",
            tr(
                lang,
                "applying; further changes will be included in a follow-up pass",
                "применяется; новые изменения войдут в следующий проход",
            )
            .to_string(),
        )
    } else if let Some(operation) = current_operation {
        match operation.phase {
            AutodeployPhase::Queued => (
                "queued",
                tr(
                    lang,
                    "changes saved; queued for application",
                    "изменения сохранены; ожидают применения",
                )
                .to_string(),
            ),
            AutodeployPhase::Running => (
                "running",
                tr(
                    lang,
                    "applying; further changes will be included in a follow-up pass",
                    "применяется; новые изменения войдут в следующий проход",
                )
                .to_string(),
            ),
            AutodeployPhase::Failed => (
                "failed",
                format!(
                    "{} {}",
                    tr(
                        lang,
                        "automatic application failed.",
                        "автоприменение не завершено."
                    ),
                    failure_tail
                ),
            ),
        }
    } else if facts.guard_active {
        (
            "running",
            tr(
                lang,
                "another node operation is in progress; live deploy stage is not reported",
                "на сервере выполняется другая операция; живой этап деплоя не передаётся",
            )
            .to_string(),
        )
    } else if current_activity.is_some_and(|activity| activity.outcome == DeployOutcome::Failed)
        || failure_audit.is_some()
    {
        (
            "failed",
            format!(
                "{} {}",
                tr(lang, "deployment failed.", "деплой не завершён."),
                failure_tail
            ),
        )
    } else {
        match facts.pending {
            Some(true) => (
                "pending",
                tr(
                    lang,
                    "saved; awaiting application. Older config may still be active.",
                    "сохранена; ожидает применения. Прежний конфиг может быть активен.",
                )
                .to_string(),
            ),
            Some(false) => (
                "applied",
                tr(
                    lang,
                    "applied per the deployment audit — not a VPN connectivity test",
                    "применена по журналу деплоя — это не проверка VPN-подключения",
                )
                .to_string(),
            ),
            None => (
                "unknown",
                tr(
                    lang,
                    "status unknown; saved changes could not be compared with the audit",
                    "статус неизвестен; не удалось сравнить сохранённые изменения с журналом",
                )
                .to_string(),
            ),
        }
    };

    let (stage_phase, stage_message, stage_at) = if let Some(activity) = current_activity {
        (
            Some(
                activity
                    .stage_phase
                    .map(str::to_string)
                    .unwrap_or_else(|| "deploy".to_string()),
            ),
            activity
                .stage_message
                .clone()
                .or_else(|| Some(tr(lang, "starting deployment…", "запускаю деплой…").to_string())),
            activity.stage_at.or(Some(activity.started_at)),
        )
    } else if let Some(operation) = current_operation {
        let phase = match operation.phase {
            AutodeployPhase::Queued => "queue",
            AutodeployPhase::Running => "deploy",
            AutodeployPhase::Failed => "failed",
        };
        (
            Some(phase.to_string()),
            Some(operation.message.to_string()),
            Some(operation_updated_at),
        )
    } else if facts.guard_active {
        (
            Some("operation".to_string()),
            Some(
                tr(
                    lang,
                    "another node operation is in progress; live deploy stage is not reported",
                    "на сервере выполняется другая операция; живой этап деплоя не передаётся",
                )
                .to_string(),
            ),
            None,
        )
    } else if let Some(row) = failure_audit {
        (
            Some("audit".to_string()),
            Some(
                tr(
                    lang,
                    "last deploy attempt failed",
                    "последняя попытка деплоя не удалась",
                )
                .to_string(),
            ),
            Some(row.ts),
        )
    } else {
        (None, None, None)
    };

    let error = if state == "failed" {
        if let Some(operation) =
            current_operation.filter(|operation| operation.phase == AutodeployPhase::Failed)
        {
            Some(operation.message.to_string())
        } else if let Some(activity) =
            current_activity.filter(|activity| activity.outcome == DeployOutcome::Failed)
        {
            activity
                .last_error
                .clone()
                .or_else(|| activity.stage_message.clone())
        } else {
            failure_audit.and_then(|row| failure_reason(row))
        }
    } else {
        None
    };

    let pending_text = match facts.pending {
        Some(true) => tr(
            lang,
            "newer changes await application",
            "новые изменения ждут применения",
        )
        .to_string(),
        Some(false) => tr(
            lang,
            "no newer saved changes than last success",
            "нет изменений новее последнего успеха",
        )
        .to_string(),
        None => tr(
            lang,
            "unknown — audit comparison failed",
            "неизвестно — сравнение с журналом не удалось",
        )
        .to_string(),
    };

    let can_start = !facts.guard_active && !matches!(state, "running" | "queued");

    DeployPanelView {
        state,
        note,
        stage_phase,
        stage_message,
        stage_at,
        error,
        can_start,
        generation: facts
            .activity
            .as_ref()
            .map_or(0, |activity| activity.generation),
        pending: facts.pending,
        pending_text,
        last_success_at: success_ts,
        generated_at: facts.generated_at,
    }
}

pub(super) fn render(view: &DeployPanelView, server_id: &str, lang: Locale) -> Markup {
    let now = view.generated_at;
    let state_label = match view.state {
        "queued" => tr(lang, "queued", "в очереди"),
        "running" => tr(lang, "running", "выполняется"),
        "failed" => tr(lang, "failed", "ошибка"),
        "pending" => tr(lang, "pending", "ожидает"),
        "applied" => tr(lang, "applied", "применено"),
        _ => tr(lang, "unknown", "неизвестно"),
    };
    let retry_label = if view.state == "failed" {
        tr(lang, "retry deploy", "повторить деплой")
    } else {
        tr(lang, "deploy now", "деплоить сейчас")
    };
    let audit_href = format!("/admin/audit?target={}", path_segment_encode(server_id));
    html! {
        section id="deployment-status"
                class=(format!("ed-deploy ed-deploy--{}", view.state))
                data-deploy-state=(view.state)
                data-deploy-server=(server_id)
                data-deploy-generation=(view.generation)
                data-deploy-can-start=(if view.can_start { "true" } else { "false" })
                data-deploy-status-url=(format!(
                    "/admin/servers/{}?deploy_status=1",
                    path_segment_encode(server_id)
                ))
                role="status" aria-live="polite" {
            div.ed-deploy__head {
                span.ed-deploy__label {
                    (icon("rocket"))
                    " " (tr(lang, "deployment", "деплой"))
                }
                span.ed-deploy__server data-deploy-server-label {
                    (tr(lang, "server ", "сервер ")) b { (server_id) }
                }
                span.ed-deploy__badge data-deploy-badge { (state_label) }
                time.ed-deploy__since
                     datetime=(view.generated_at.to_rfc3339())
                     title=(tr(lang, "status generated at", "статус сформирован")) {
                    (format_local_with_pattern(view.generated_at, "%H:%M:%S"))
                }
            }
            div.ed-deploy__stage data-deploy-stage {
                span.ed-deploy__stage-k { (tr(lang, "stage", "этап")) }
                span.ed-deploy__stage-phase data-deploy-stage-phase {
                    (view.stage_phase.as_deref().unwrap_or("idle"))
                }
                span.ed-deploy__stage-message data-deploy-stage-message {
                    (view.stage_message.as_deref().unwrap_or_else(|| {
                        tr(lang, "no operation in progress", "операция не выполняется")
                    }))
                }
                span.ed-deploy__stage-time data-deploy-stage-time {
                    @if let Some(at) = view.stage_at {
                        " · " (humanize_age(now - at, lang))
                    }
                }
            }
            div class={"ed-deploy__facts" (if matches!(view.state, "pending" | "applied" | "unknown") { " ed-deploy__facts--compact" } else { "" })} {
                div.ed-deploy__fact
                    data-deploy-pending=(match view.pending {
                        Some(true) => "pending",
                        Some(false) => "applied",
                        None => "unknown",
                    }) {
                    span.ed-deploy__fact-k { (tr(lang, "saved", "сохранено")) }
                    span.ed-deploy__fact-v data-deploy-pending-text { (view.pending_text) }
                }
                div.ed-deploy__fact {
                    span.ed-deploy__fact-k { (tr(lang, "last success", "успех")) }
                    span.ed-deploy__fact-v {
                        @if let Some(at) = view.last_success_at {
                            time datetime=(at.to_rfc3339()) { (format_msk_iso(at)) }
                            " · " (humanize_age(now - at, lang))
                        } @else {
                            (tr(lang, "none recorded", "нет записей"))
                        }
                    }
                }
                div.ed-deploy__fact.ed-deploy__fact--error
                    data-deploy-error
                    hidden[view.error.is_none()] {
                    span.ed-deploy__fact-k { (tr(lang, "error", "ошибка")) }
                    span.ed-deploy__fact-v data-deploy-error-text {
                        (view.error.as_deref().unwrap_or(""))
                    }
                }
            }
            p.ed-deploy__note data-deploy-note { (view.note) }
            div.ed-deploy__actions {
                @if view.can_start && view.state == "failed" {
                    button type="button" class="ed-abtn ed-abtn--secondary ed-abtn--sm" data-deploy-retry {
                        (icon("rotate-cw"))
                        span { (retry_label) }
                    }
                }
                button type="button" class="ed-abtn ed-abtn--secondary ed-abtn--sm" data-deploy-refresh {
                    (icon("rotate-cw"))
                    span { (tr(lang, "check status", "проверить статус")) }
                }
                a href=(audit_href) data-deploy-audit class="ed-abtn ed-abtn--secondary ed-abtn--sm" {
                    (icon("history"))
                    span { (tr(lang, "deployment log", "журнал деплоя")) }
                }
            }
        }
    }
}

fn failure_reason(row: &vpnctl_inventory::AuditEntry) -> Option<String> {
    let payload = row.payload.as_ref()?;
    let reason = payload
        .get("error")
        .and_then(|value| value.as_str())
        .or_else(|| {
            payload
                .get("ssh_errors")
                .and_then(|value| value.as_array())
                .and_then(|errors| errors.first())
                .and_then(|value| value.as_str())
        })
        .or_else(|| {
            payload
                .get("ssh_skip_reason")
                .and_then(|value| value.as_str())
        })
        .map(str::to_string)
        .or_else(|| {
            payload
                .get("inputs_changed")
                .and_then(|value| value.as_bool())
                .and_then(|changed| {
                    changed.then(|| {
                        "inventory changed during deploy; the server remains pending".to_string()
                    })
                })
        })
        .or_else(|| {
            (row.action == "server.deploy.skipped")
                .then(|| "deploy skipped — no kernel config was applied".to_string())
        })?;
    let reason = reason.trim();
    if reason.is_empty() {
        return None;
    }
    Some(reason.chars().take(300).collect())
}
