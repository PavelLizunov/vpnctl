use crate::handlers::admin::helpers::ordered_kernel_ids;
use crate::handlers::admin::icons::icon;
use crate::http_util::path_segment_encode;
use crate::i18n::{K, Locale, t, tr};
use maud::{Markup, html};
use std::collections::{HashMap, HashSet};
use vpnctl_core::{DpiRisk, ProtocolId, Registry, Server};

pub(crate) fn server_detail_protocols_section(
    server: &Server,
    registry: &Registry,
    hidden_map: &HashMap<ProtocolId, bool>,
    lang: Locale,
) -> Markup {
    let supported: HashSet<_> = server
        .kernels
        .iter()
        .filter_map(|id| registry.kernel(id))
        .flat_map(|kernel| kernel.supported_protocols())
        .collect();
    let enabled = &server.enabled_protocols;
    let (available, incompatible): (Vec<_>, Vec<_>) = registry
        .protocol_ids()
        .into_iter()
        .filter(|pid| !enabled.contains(pid))
        .partition(|pid| supported.contains(pid));
    let kernels = ordered_kernel_ids(server)
        .iter()
        .map(|kid| kid.0.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    let server_path = format!("/admin/servers/{}", path_segment_encode(&server.id.0));
    let render_row = |pid: &ProtocolId, is_on: bool| {
        let compatible = supported.contains(pid);
        let protocol = registry.protocol(pid);
        let issued = pid.0 != "turnrelay-relay";
        let hidden = hidden_map.get(pid).copied().unwrap_or(false);
        let action = format!("{server_path}/protocols/{}", path_segment_encode(&pid.0));
        let applied_hint = tr(
            lang,
            "Applied automatically to the node.",
            "Применяется автоматически на ноде.",
        );
        html! {
            li.ed-protocol {
                div.ed-protocol__info {
                    div.ed-protocol__identity {
                        strong.ed-protocol__weak[protocol.is_some_and(|p| matches!(p.dpi_risk(), DpiRisk::Weak))] { (pid.0) }
                        @if is_on {
                            span.ed-protocol__on { (icon("check")) (tr(lang, "Enabled", "Включён")) }
                        } @else if compatible {
                            span { (tr(lang, "Disabled", "Выключен")) }
                        }
                    }
                    div.ed-protocol__meta {
                        @if is_on {
                            @if !issued {
                                span { (tr(lang, "Managed entry for TurnRelay exits", "Управляемый вход для выходов TurnRelay")) }
                            } @else if hidden {
                                span { (tr(lang, "Hidden from subscriptions", "Скрыт из подписок")) }
                            } @else if compatible {
                                span { (tr(lang, "Allowed in subscriptions", "Разрешён в подписках")) }
                            }
                            @if !compatible {
                                span { (tr(lang, "Unsupported by selected kernels", "Выбранные ядра не поддерживают протокол")) }
                            }
                        }
                        @if let Some(p) = protocol {
                            @if p.is_retired() {
                                span { (tr(lang, "(retired)", "(выведен из новых подключений)")) }
                            }
                            @let risk = p.dpi_risk();
                            span.ed-protocol__dpi title=(tr(lang, risk.tooltip(), "Устойчивость протокола к распознаванию трафика")) {
                                (tr(lang, risk.label(), match risk {
                                    DpiRisk::Strong => "Устойчивость к DPI: высокая",
                                    DpiRisk::Moderate => "Устойчивость к DPI: средняя",
                                    DpiRisk::Weak => "Устойчивость к DPI: низкая",
                                }))
                            }
                        }
                    }
                }
                div.ed-protocol__actions {
                    @if is_on && compatible && issued {
                        form method="post" action=(format!("{action}/{}", if hidden { "unhide" } else { "hide" })) {
                            button type="submit" class="ed-abtn ed-abtn--secondary ed-abtn--sm" {
                                @if hidden {
                                    (icon("eye")) (tr(lang, "Show in subscriptions", "Показать в подписках"))
                                } @else {
                                    (icon("eye-off")) (tr(lang, "Hide from subscriptions", "Скрыть из подписок"))
                                }
                            }
                        }
                    }
                    @if is_on {
                        form method="post" action=(format!("{action}/disable"))
                             data-confirm=(tr(lang, "Disable this protocol on the server for every user?", "Отключить этот протокол на сервере для всех пользователей?")) {
                            button type="submit" class="ed-abtn ed-abtn--warning ed-abtn--sm" title=(applied_hint) {
                                (icon("pause")) (t(lang, K::BtnDisable))
                            }
                        }
                    } @else if compatible {
                        form method="post" action=(format!("{action}/enable")) {
                            button type="submit" class="ed-abtn ed-abtn--sm" title=(applied_hint) {
                                (icon("power")) (t(lang, K::BtnEnable))
                            }
                        }
                    }
                }
            }
        }
    };
    html! {
        section.ed-protocols id="enabled-protocols" {
            h2 { (t(lang, K::EyebrowEnabledProtocols)) " · " (enabled.len()) }
            @if enabled.is_empty() {
                p { (tr(lang, "No protocols enabled. Choose an available protocol below.", "Все протоколы выключены. Выберите доступный протокол ниже.")) }
            } @else {
                ul { @for pid in enabled { (render_row(pid, true)) } }
            }
            details.ed-protocols__group {
                summary { (tr(lang, "Available to enable", "Можно включить")) " · " (available.len()) }
                @if available.is_empty() {
                    p { (tr(lang, "No other protocols available with these kernels.", "Для выбранных ядер нет других доступных протоколов.")) }
                } @else {
                    ul { @for pid in &available { (render_row(pid, false)) } }
                }
            }
            @if !incompatible.is_empty() {
                details.ed-protocols__group {
                    summary { (tr(lang, "Require a different kernel", "Требуют другого ядра")) " · " (incompatible.len()) }
                    p {
                        (tr(lang, "These protocols are not supported by ", "Эти протоколы не поддерживаются "))
                        @if server.kernels.len() == 1 { (tr(lang, "kernel ", "ядром ")) }
                        @else { (tr(lang, "the selected kernels: ", "выбранными ядрами: ")) }
                        (kernels) "."
                    }
                    ul { @for pid in &incompatible { (render_row(pid, false)) } }
                }
            }
            p.ed-protocols__hint {
                (tr(lang, "Changes are saved and applied automatically to the node.", "Изменения сохраняются и автоматически применяются на ноде.")) " "
                a.ed-link href=(format!("{server_path}/status#external-readiness")) {
                    (tr(lang, "View connectivity checks", "Результаты проверок подключения"))
                }
            }
        }
    }
}
