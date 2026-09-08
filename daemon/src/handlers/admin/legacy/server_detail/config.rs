use std::collections::HashSet;

use maud::{Markup, html};

use crate::handlers::admin::helpers::kernel_priority;
use crate::http_util::path_segment_encode;

/// Kernels editor — one row per kernel registered in the registry,
/// with enable/disable form. Mirrors the protocols section directly
/// below it. Per CLAUDE.md architectural principle (Kernel ×
/// Protocol orthogonality), adding a new kernel here is the first
/// step before enabling protocols that only that kernel supports
/// (e.g. amneziawg → then wireguard).
pub(super) fn server_detail_kernels_section(
    server: &vpnctl_core::Server,
    registry: &vpnctl_core::Registry,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    let enabled: HashSet<&vpnctl_core::KernelId> = server.kernels.iter().collect();
    let mut all_kernels = registry.kernel_ids();
    all_kernels.sort_by(|left, right| {
        kernel_priority(&left.0)
            .cmp(&kernel_priority(&right.0))
            .then_with(|| left.0.cmp(&right.0))
    });
    let sid_enc = path_segment_encode(&server.id.0);
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow { (tr(lang, "Kernels", "Ядра")) }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 8px;" {
            (tr(
                lang,
                "Daemons running on this node. One physical VPS can host multiple (sing-box on 443/TCP + amneziawg on 51820/UDP cohabit cleanly).",
                "Демоны, работающие на этой ноде. Один физический VPS может держать несколько (sing-box на 443/TCP + amneziawg на 51820/UDP уживаются нормально).",
            ))
        }
        div style="padding: 8px 12px; margin: 0 0 12px; background: var(--paper); border-left: 3px solid var(--accent); font-family: var(--serif); font-size: 12px; line-height: 1.5;" {
            b style="color: var(--accent); font-family: var(--mono); letter-spacing: 0.1em; text-transform: uppercase; font-size: 11px;" {
                (tr(
                    lang,
                    "⚠ toggle here = inventory only",
                    "⚠ тогл здесь = только инвентарь",
                ))
            }
            (tr(
                lang,
                " — the live node sees the change only after you click ",
                " — живая нода увидит изменение только после клика по ",
            ))
            a href="#deploy-button"
              style="color: var(--ink); border-bottom: 1px dotted var(--ink); text-decoration: none; font-weight: 500;" {
                span.ed-mono { (tr(lang, "deploy →", "деплой →")) }
            }
            (tr(
                lang,
                " at the top of this page. We never SSH-push a config without an explicit operator click (no surprise redeploys).",
                " вверху страницы. Мы никогда не пушим конфиг через SSH без явного клика оператора (без сюрпризов-redeploy).",
            ))
        }
        ul style="list-style: none; padding: 0; font-family: var(--mono); font-size: 12px; line-height: 1.8;" {
            @for kid in &all_kernels {
                @let is_on = enabled.contains(kid);
                @let supported = registry.kernel(kid)
                    .map(|k| k.supported_protocols()
                        .into_iter()
                        .map(|p| p.0)
                        .collect::<Vec<_>>()
                        .join(", "))
                    .unwrap_or_default();
                li style="display: flex; align-items: baseline; gap: 12px; padding: 4px 0; border-bottom: 1px dotted var(--rule);" {
                    span style="flex: 1;" {
                        (kid.0)
                        " "
                        span style="font-size: 10px; color: var(--mute); font-style: italic; font-family: var(--serif);" {
                            (tr(lang, "(runs: ", "(крутит: ")) (supported) ")"
                        }
                    }
                    @if is_on {
                        span style="font-family: var(--mono); font-size: 11px; color: var(--acc); margin-right: 4px;" {
                            (tr(lang, "✓ on", "✓ вкл"))
                        }
                        form method="post"
                             action=(format!("/admin/servers/{}/kernels/{}/disable", sid_enc, path_segment_encode(&kid.0)))
                             style="margin: 0; padding: 0;" {
                            @let dis_title = match lang {
                                crate::i18n::Locale::En => format!("Remove {} from {}.kernels. Takes effect on next deploy.", kid.0, server.id.0),
                                crate::i18n::Locale::Ru => format!("Убрать {} из {}.kernels. Применится при следующем деплое.", kid.0, server.id.0),
                            };
                            button type="submit"
                                   title=(dis_title)
                                   class="ed-abtn ed-abtn--warning ed-abtn--sm" {
                                (crate::i18n::t(lang, crate::i18n::K::BtnDisable))
                            }
                        }
                    } @else {
                        span style="font-family: var(--mono); font-size: 11px; color: var(--mute); margin-right: 4px;" {
                            "—"
                        }
                        form method="post"
                             action=(format!("/admin/servers/{}/kernels/{}/enable", sid_enc, path_segment_encode(&kid.0)))
                             style="margin: 0; padding: 0;" {
                            @let en_title = match lang {
                                crate::i18n::Locale::En => format!("Add {} to {}.kernels. Takes effect on next deploy.", kid.0, server.id.0),
                                crate::i18n::Locale::Ru => format!("Добавить {} в {}.kernels. Применится при следующем деплое.", kid.0, server.id.0),
                            };
                            button type="submit"
                                   title=(en_title)
                                   class="ed-abtn ed-abtn--sm" {
                                (crate::i18n::t(lang, crate::i18n::K::BtnEnable))
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Phase G chunk 3.5 follow-up — «Push deploy key» recovery action.
///
/// The Phase E wizard at `/admin/servers/new` does this automatically
/// as step 3 of bootstrap (sshpass + `mkdir -p ~/.ssh && grep -qxF ||
/// echo ... >>`). But three operator paths leave a server in
/// inventory WITHOUT the daemon's pubkey on it:
///
///   * **migrate-from-bash** — imported pre-existing servers that
///     have their own SSH key infra, daemon's key never pushed
///   * **quick-add** (`POST /admin/servers`) — minimal form, only
///     id + address + port; no password field, no push
///   * **wizard failure mid-flow** — bootstrap got past step 1-2
///     but failed before step 3 completed (rare)
///
/// All three leave Pavel with the «open a terminal + ssh root@…
/// + paste the pubkey» chore. This section makes it a single click
/// + paste-password instead.
///
/// Reuses `wizard_bootstrap::ssh_password_run` so the actual remote
/// command is byte-identical to what the wizard runs (idempotent
/// `grep -qxF || echo >>` — re-clicking after success is safe).
pub(super) fn server_detail_push_deploy_key_section(
    server: &vpnctl_core::Server,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    let sid_enc = path_segment_encode(&server.id.0);
    let reference_key = std::env::var("VPNCTLD_REFERENCE_SSH_KEY").ok();
    let reference_ok = reference_key
        .as_ref()
        .is_some_and(|p| std::path::Path::new(p).exists());
    html! {
        div.ed-rule {}
        div #push-deploy-key.ed-art-eyebrow {
            (tr(lang, "Deploy SSH key — push to this server", "Deploy SSH-ключ — запушить на этот сервер"))
        }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px; max-width: 760px;" {
            (tr(lang, "Daemon needs its pubkey on this server's ", "Демону нужен его pubkey в "))
            span.ed-mono { "~/.ssh/authorized_keys" }
            (tr(
                lang,
                " before probes, deploys, or the Telegram via-server proxy can work. The Phase E wizard at ",
                " этого сервера, иначе не работают probe-ы, деплои и Telegram via-server прокси. Мастер Phase E на ",
            ))
            span.ed-mono { "/admin/servers/new" }
            (tr(lang, " does this automatically. For servers added via ", " делает это автоматически. Для серверов добавленных через "))
            span.ed-mono { "quick-add" } " / " span.ed-mono { "migrate-from-bash" }
            (tr(
                lang,
                " (or when the wizard's push step failed), use this form. Idempotent — re-clicking after success is a no-op.",
                " (или если шаг push мастера упал), используй эту форму. Идемпотентно — повторный клик после успеха ничего не делает.",
            ))
        }

        @if reference_ok {
            p style="font-family: var(--mono); font-size: 11px; color: var(--ink); margin: 0 0 12px; padding: 8px 12px; background: var(--paper); border-left: 3px solid var(--acc); max-width: 760px;" {
                "✓ " b { (tr(lang, "reference SSH key configured", "reference SSH-ключ настроен")) }
                " (" span.ed-mono { (reference_key.as_deref().unwrap_or("")) } "). "
                (tr(lang, "Click ", "Клик "))
                b { (tr(lang, "push deploy key", "запушить deploy-ключ")) }
                (tr(
                    lang,
                    " with password EMPTY — daemon will use the reference key for a silent push. If that key isn't authorised on this specific server, fill in the password to fall back to sshpass.",
                    " с ПУСТЫМ паролем — демон использует reference-key для тихого push. Если этот ключ не авторизован на конкретно этом сервере — заполни пароль для fallback через sshpass.",
                ))
            }
        } @else {
            p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 0 0 12px; max-width: 760px;" {
                (tr(lang, "Tip: set ", "Подсказка: задай ")) span.ed-mono { "VPNCTLD_REFERENCE_SSH_KEY=/path/to/operator_key" }
                (tr(lang, " in the daemon's ", " в "))
                span.ed-mono { "/etc/vpnctl/vpnctld.env" }
                (tr(
                    lang,
                    " (then restart vpnctld) to skip the password input on future pushes — useful when an operator key (claude-dev, etc) is already authorised on every server.",
                    " демона (затем перезапусти vpnctld) — это позволит обходить ввод пароля на будущих push'ах, удобно когда operator-ключ (claude-dev и т.п.) уже авторизован на каждом сервере.",
                ))
            }
        }

        form method="post"
             action=(format!("/admin/servers/{sid_enc}/push-deploy-key"))
             style="margin: 0 0 14px;" {
            div style="display: grid; grid-template-columns: 140px 1fr; gap: 10px 14px; align-items: center; max-width: 560px;" {
                label for="setup_ssh_user" style="font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                    (tr(lang, "ssh user", "ssh пользователь"))
                }
                input id="setup_ssh_user" type="text" name="ssh_user"
                      value=(server.ssh_user)
                      autocomplete="username" autocapitalize="none" spellcheck="false"
                      pattern="[A-Za-z0-9_-]+" maxlength="32"
                      style="font-family: var(--mono); font-size: 12px; padding: 5px 8px; border: 1px solid var(--rule); background: var(--paper);";
                label style="font-family: var(--mono); font-size: 11px; color: var(--mute);" {
                    (tr(lang, "ssh password", "ssh-пароль"))
                }
                // R2: short placeholder (the old sentence truncated
                // mid-word in the 400px field); full rules in `title`.
                input type="password"
                      name="root_password"
                      autocomplete="off"
                      placeholder=(if reference_ok {
                          tr(lang, "blank = reference key", "пусто = reference-key")
                      } else {
                          tr(lang, "never stored", "не сохраняется")
                      })
                      title=(if reference_ok {
                          tr(
                              lang,
                              "Leave blank to authenticate with the reference key; fill in to force the sshpass fallback. Used once for the SSH connect, then discarded — never stored, never logged.",
                              "Пусто — аутентификация reference-ключом; заполни, чтобы форсировать sshpass-fallback. Используется один раз для SSH-коннекта и отбрасывается — не хранится и не логируется.",
                          )
                      } else {
                          tr(
                              lang,
                              "Used once for the SSH connect, then discarded — never stored, never logged.",
                              "Используется один раз для SSH-коннекта и отбрасывается — не хранится и не логируется.",
                          )
                      })
                      style="font-family: var(--mono); font-size: 12px; padding: 5px 8px; border: 1px solid var(--rule); background: var(--paper);";
            }
            div style="margin-top: 12px;" {
                button type="submit"
                       title=(crate::i18n::tr(
                           lang,
                           // Honest copy (audit 2026-06-10): with the
                           // password filled the handler goes straight
                           // to sshpass — the reference key is tried
                           // ONLY when the password field is empty.
                           "Append the daemon's deploy pubkey to ~/.ssh/authorized_keys on this server. With the password filled it connects via sshpass; leave the password empty to use the configured reference key instead.",
                           "Добавить deploy-pubkey демона в ~/.ssh/authorized_keys на этом сервере. С заполненным паролем подключается через sshpass; оставь пароль пустым, чтобы использовать настроенный reference-key.",
                       ))
                       class="ed-abtn ed-abtn--recovery ed-abtn--lg" {
                    (crate::i18n::tr(lang, "push deploy key", "запушить deploy-ключ"))
                }
                span style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin-left: 14px;" {
                    (crate::i18n::tr(lang, "Connects to ", "Подключение к "))
                    span.ed-mono { (server.ssh_user) "@" (server.address) ":" (server.ssh_port) }
                }
            }
        }
    }
}

pub(super) fn server_detail_routing_policy_section(
    server: &vpnctl_core::Server,
    role: vpnctl_inventory::ServerRole,
    candidates: &[vpnctl_core::Server],
    routing_error: Option<&str>,
    lang: crate::i18n::Locale,
) -> maud::Markup {
    let sid = crate::http_util::path_segment_encode(&server.id.0);
    maud::html! {
        section id="routing-policy" class="ed-card" style="margin: 16px 0;" {
            h3 { (crate::i18n::tr(lang, "Routing policy", "Политика маршрутизации")) }
            p class="ed-muted" {
                (crate::i18n::tr(
                    lang,
                    "Workload-only servers cannot receive user grants or enter subscriptions/fleet actions. A jump host is used only for explicit management.",
                    "Workload-only серверы не получают пользовательские grants и не входят в подписки/fleet actions. Jump host используется только для явного управления.",
                ))
            }
            @if let Some(error) = routing_error {
                div class="ed-alert ed-alert--warn" { "management route invalid: " (error) }
            }
            form method="post" action=(format!("/admin/servers/{sid}/routing-policy")) {
                label for="server-role" { "role" }
                select id="server-role" name="role" {
                    option value="vpn-exit" selected[role == vpnctl_inventory::ServerRole::VpnExit] { "vpn-exit" }
                    option value="workload-only" selected[role == vpnctl_inventory::ServerRole::WorkloadOnly] { "workload-only" }
                }
                label for="jump-via" style="margin-left: 12px;" { "jump_via" }
                select id="jump-via" name="jump_via" {
                    option value="" selected[server.jump_via.is_none()] { "direct" }
                    @for candidate in candidates {
                        @if candidate.id != server.id {
                            option value=(candidate.id.0) selected[server.jump_via.as_ref() == Some(&candidate.id)] { (candidate.id.0) }
                        }
                    }
                }
                button type="submit" class="ed-abtn ed-abtn--recovery" style="margin-left: 12px;" {
                    (crate::i18n::tr(lang, "save routing policy", "сохранить политику"))
                }
            }
        }
    }
}

/// Client entry / Входной сервер section on the server-detail page.
/// Configures `client_detour_via` for 2-hop VPN chaining.
pub(super) fn server_detail_client_detour_section(
    server: &vpnctl_core::Server,
    current_detour: Option<&vpnctl_core::ServerId>,
    candidates: &[vpnctl_core::Server],
    lang: crate::i18n::Locale,
) -> maud::Markup {
    use crate::i18n::tr;
    let sid_enc = path_segment_encode(&server.id.0);
    html! {
        section id="client-detour" class="ed-card" style="margin: 16px 0;" {
            h3 { (tr(lang, "Client entry", "Входной сервер")) }
            p class="ed-muted" {
                (tr(
                    lang,
                    "Routes client outbound traffic through an entry server before reaching this target exit (2-hop VPN chain).",
                    "Маршрутизирует клиентский трафик через входной сервер перед этим целевым выходом (2-hop VPN цепочка).",
                ))
            }
            form method="post" action=(format!("/admin/servers/{sid_enc}/client-detour")) {
                label for="client-detour-via" {
                    (tr(lang, "Client entry", "Входной сервер"))
                }
                select id="client-detour-via" name="client_detour_via" style="margin-left: 8px;" {
                    option value="" selected[current_detour.is_none()] {
                        (tr(lang, "direct (none)", "прямой (нет)"))
                    }
                    @for candidate in candidates {
                        @if candidate.id != server.id {
                            option value=(candidate.id.0) selected[current_detour == Some(&candidate.id)] {
                                (candidate.id.0)
                            }
                        }
                    }
                }
                button type="submit" class="ed-abtn ed-abtn--recovery" style="margin-left: 12px;" {
                    (tr(lang, "save client entry", "сохранить входной сервер"))
                }
            }
        }
    }
}

/// Trusted host SSH fingerprint section — shows current pinned
/// fingerprint (if any) plus a form for the operator to set / replace
/// it. Two paths:
///   * paste a `SHA256:…` literal (when the operator already has it),
///   * "Auto-detect" button → POST that runs `ssh-keyscan +
///     ssh-keygen -lf -` server-side, pins the resulting fingerprint.
///
/// Both go to the same `POST /admin/servers/{id}/set-fingerprint`
/// route; the form's hidden `mode=keyscan` differentiates.
pub(super) fn server_detail_fingerprint_section(
    server: &vpnctl_core::Server,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::{K, t, tr};
    let sid_enc = path_segment_encode(&server.id.0);
    let current = server.trusted_host_fingerprint.clone();
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow
            title=(tr(
                lang,
                "The SHA-256 of the node's SSH host public key, pinned in the inventory. Every SSH-using subsystem (deploy, probe, clash-poller) verifies the live key matches before sending any secrets — protects against MITM if someone hijacks the IP.",
                "SHA-256 публичного SSH-ключа ноды, закреплённый в инвентаре. Все подсистемы которые используют SSH (деплой, probe, clash-poller) проверяют что live-ключ совпадает прежде чем посылать секреты — защита от MITM если кто-то перехватит IP.",
            )) {
            (t(lang, K::EyebrowTrustedFingerprint))
        }
        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 14px;" {
            // Honest copy (audit 2026-06-10): the daemon's SSH transport
            // uses `StrictHostKeyChecking=accept-new` + its own
            // known_hosts and does NOT read this pin — daemon-side the
            // pin only feeds the fingerprint-drift WARNING alert
            // (health_monitor::check_fingerprint_drift). Hard refusal
            // happens only on the CLI deploy path (russh
            // `trusted_fingerprint`). The old copy claimed every
            // pipeline refuses on mismatch.
            (tr(
                lang,
                "Pinned SHA-256 of the node's SSH ed25519 host key. The CLI deploy refuses a host whose live key doesn't match; the daemon's pipelines (web deploy / probe / clash-poller) verify against their own known_hosts and use this pin to raise a fingerprint-drift warning alert — ",
                "Закреплённый SHA-256 хост-ключа ed25519 ноды. CLI-деплой отказывается работать с хостом, чей live-ключ не совпадает; пайплайны демона (web-деплой / probe / clash-poller) сверяются со своим known_hosts, а по этому пину поднимают warning-алерт о дрейфе отпечатка — ",
            ))
            span title=(tr(
                lang,
                "Trust-On-First-Use: accept whatever host key the node presents the first time, refuse changes afterwards. Standard SSH posture; same model `~/.ssh/known_hosts` uses.",
                "Trust-On-First-Use: принять любой host-ключ который нода предъявляет в первый раз, затем отказываться от смены. Стандартная SSH-модель; так же как `~/.ssh/known_hosts`.",
            )) {
                (tr(lang, "TOFU pin", "TOFU-pin"))
            }
            (tr(
                lang,
                ", set once. Update only if the node was legitimately rebuilt (and re-confirm via console).",
                ", задаётся один раз. Обновляй только если нода была легитимно пересоздана (и сверь через console).",
            ))
        }
        div style="font-family: var(--mono); font-size: 12px; padding: 8px 12px; background: var(--paper-tint); border: 1px solid var(--rule); margin-bottom: 12px;" {
            @match &current {
                Some(fp) => { (tr(lang, "current: ", "текущий: ")) (fp) }
                None => {
                    em style="color: var(--mute);" {
                        (tr(
                            lang,
                            "(no fingerprint pinned — first SSH connection will TOFU-accept whatever the host presents)",
                            "(отпечаток не закреплён — первый SSH-коннект TOFU-примет то, что хост предъявит)",
                        ))
                    }
                }
            }
        }
        div style="display: flex; flex-direction: column; gap: 10px;" {
            form method="post"
                 action=(format!("/admin/servers/{sid_enc}/set-fingerprint"))
                 style="display: flex; gap: 8px; align-items: center;" {
                input type="hidden" name="mode" value="keyscan";
                button type="submit"
                       title=(tr(
                           lang,
                           "Run ssh-keyscan + ssh-keygen -lf - on the daemon host, pin the resulting fingerprint.",
                           "Запустить ssh-keyscan + ssh-keygen -lf - на хосте демона и закрепить полученный отпечаток.",
                       ))
                       class="ed-abtn ed-abtn--recovery ed-abtn--lg" {
                    (tr(lang, "auto-detect via ssh-keyscan →", "автоопределить через ssh-keyscan →"))
                }
                span style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute);" {
                    (tr(lang, "(daemon will SSH-keyscan ", "(демон сделает ssh-keyscan "))
                    span.ed-mono { (server.address) ":" (server.ssh_port) }
                    (tr(lang, " and pin the SHA-256)", " и закрепит SHA-256)"))
                }
            }
            form method="post"
                 action=(format!("/admin/servers/{sid_enc}/set-fingerprint"))
                 style="display: flex; gap: 8px; align-items: center;" {
                input type="hidden" name="mode" value="manual";
                input type="text" name="fingerprint" placeholder="SHA256:..."
                      style="flex: 1; padding: 4px 8px; font-family: var(--mono); font-size: 12px; border: 1px solid var(--rule);"
                      pattern="SHA256:[A-Za-z0-9+/=_-]{1,44}"
                      title="SHA256:<43-char-base64>";
                button type="submit"
                       title=(tr(
                           lang,
                           "Save the SHA256 fingerprint you pasted above as the trusted host key for this server (TOFU pin). Future SSH connections refuse if the node presents a different key — protects against MITM after the initial trust.",
                           "Сохранить вставленный выше SHA256-отпечаток как доверенный host-ключ для этого сервера (TOFU pin). Будущие SSH-коннекты откажутся если нода предъявит другой ключ — защита от MITM после первичного доверия.",
                       ))
                       style="padding: 4px 12px; border: 1px solid var(--ink); background: transparent; color: var(--ink); font-family: var(--mono); font-size: 11px; cursor: pointer;" {
                    (tr(lang, "pin manually", "закрепить вручную"))
                }
            }
        }
    }
}

pub(crate) use super::config_protocols::*;

pub(crate) use super::protocol_grid::*;
pub(crate) use super::protocols_section::server_detail_protocols_section;
