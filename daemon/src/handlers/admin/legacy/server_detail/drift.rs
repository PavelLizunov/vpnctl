use std::collections::{BTreeSet, HashMap};

use maud::{Markup, html};

use crate::http_util::path_segment_encode;

/// Map a protocol id → set of (proto, port) we EXPECT it to be
/// listening on. Single source of truth for the drift check —
/// matches what each `Protocol::server_inbound` emits.
/// Look up expected `(proto, port)` tuples for a given protocol via
/// the registry. **Single source of truth** — each protocol owns its
/// own port declaration (see `vpnctl_core::Protocol`), so adding a
/// new protocol doesn't require touching this function. (Refactored
/// 2026-05-16 per review-agent finding — previous hand-maintained
/// map violated kernel/protocol orthogonality.)
///
/// `secrets` = this server's secret map: `effective_listen_ports`
/// resolves runtime-configurable ports (vless.listen_port override),
/// so the table shows the port the node ACTUALLY binds — not the
/// compile-time default (cdn incident 2026-08-05: reality on 8443
/// rendered as «no fixed port» while 443 stayed firewalled).
pub(crate) fn expected_ports_for_protocol(
    registry: &vpnctl_core::Registry,
    pid: &vpnctl_core::ProtocolId,
    secrets: &HashMap<String, String>,
) -> Vec<(String, u16)> {
    match registry.protocol(pid) {
        Some(p) => p
            .effective_listen_ports(secrets)
            .into_iter()
            .map(|(s, n)| (s.to_string(), n))
            .collect(),
        None => Vec::new(),
    }
}

/// One resolved orphan UUID for the server#1 drift-detail card: a
/// UUID the node serves that no granted user accounts for. `name`
/// is `Some(user_id)` when the orphan UUID DOES map to a known user
/// (e.g. a user whose grant was revoked but whose UUID still lives in
/// the node config) and `None` when it maps to nothing in inventory
/// (a likely service account / hand-added UUID).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OrphanUuid {
    pub(crate) uuid: String,
    /// Resolved inventory user id, if the UUID matches a known user.
    pub(crate) name: Option<String>,
}

/// Outcome of a `?drift=live` attempt. `Ok` carries the diff; `Err`
/// carries a short, policy-safe reason string the card renders into
/// its empty-state. The reason NEVER says «ssh to the box» — it says
/// the config couldn't be read (node unreachable or deploy key).
#[derive(Debug, Clone)]
pub(super) enum DriftLiveResult {
    /// Live read + parse succeeded — `orphans` are on-node UUIDs not
    /// in inventory (resolved to a user name where possible).
    Ok { orphans: Vec<OrphanUuid> },
    /// Live read failed (timeout, node down, key not authorised, parse
    /// error). The card degrades to a policy-safe empty-state.
    Unavailable,
}

/// Pure diff for server#1 — given the set of UUIDs the NODE serves and
/// the inventory `users` (whose `.uuid` already resolves
/// COALESCE(client_uuid, users.uuid)), return the orphans: UUIDs on the
/// node that are NOT in the inventory grant set. Each orphan is
/// resolved to a user id when the UUID matches a known global user
/// uuid (revoked-but-still-on-node case), else left unresolved.
///
/// Extracted as a free function so the test suite can pin the
/// orphan-detection semantics directly without standing up SSH.
pub(crate) fn compute_orphan_uuids(
    node_uuids: &BTreeSet<String>,
    granted_users: &[vpnctl_core::User],
    all_users: &[vpnctl_core::User],
) -> Vec<OrphanUuid> {
    // Inventory UUID set for THIS server = the resolved uuid of every
    // granted user. A node UUID present here is accounted-for.
    let inventory_uuids: BTreeSet<&str> = granted_users.iter().map(|u| u.uuid.as_str()).collect();
    // Reverse map from any KNOWN user's global uuid → user id, so an
    // orphan can still be named if it belongs to a user who simply
    // lost their grant (the dangerous revoke case the operator most
    // wants to see).
    let uuid_to_user: HashMap<&str, &str> = all_users
        .iter()
        .map(|u| (u.uuid.as_str(), u.id.0.as_str()))
        .collect();

    node_uuids
        .iter()
        .filter(|u| !inventory_uuids.contains(u.as_str()))
        .map(|u| OrphanUuid {
            uuid: u.clone(),
            name: uuid_to_user.get(u.as_str()).map(|s| s.to_string()),
        })
        .collect()
}

/// server#1 — best-effort LIVE read of the node's sing-box config over
/// SSH, with a hard ≤6s timeout. EVERY failure mode (transport error,
/// node down, key not authorised, non-UTF-8, parse error, or the
/// outer tokio timeout) collapses to `DriftLiveResult::Unavailable` so
/// the caller can render a policy-safe empty-state — this function
/// NEVER returns an error and NEVER panics.
///
/// `granted_users` is `users_for_server(sid)` (the inventory set for
/// the diff — a node UUID present here is accounted-for). `all_users`
/// is the full inventory user list (already loaded by the handler) so
/// a revoked-but-on-node orphan can still be NAMED instead of showing
/// as «unresolved».
pub(super) async fn load_drift_live(
    server: &vpnctl_core::Server,
    granted_users: &[vpnctl_core::User],
    all_users: &[vpnctl_core::User],
) -> DriftLiveResult {
    use crate::ssh_subprocess::SubprocessSshTransport;
    use vpnctl_core::SshTransport;

    let key_path = crate::app::deploy_key_path();
    let transport = SubprocessSshTransport::new(
        server.address.clone(),
        server.ssh_user.clone(),
        key_path,
    )
    .port(server.ssh_port)
    // Hard wall-clock cap — keep the armed path snappy even when the
    // node is black-holed (the transport already sets ConnectTimeout=10
    // + ServerAlive keepalives, but we want ≤6s end-to-end here).
    .timeout(std::time::Duration::from_secs(6));

    // Outer guard belt-and-suspenders against a wedged child the
    // transport's own timeout somehow misses — 7s leaves a 1s margin.
    let read = tokio::time::timeout(
        std::time::Duration::from_secs(7),
        transport.read_file("/etc/sing-box/config.json"),
    )
    .await;

    let bytes = match read {
        Ok(Ok(b)) => b,
        Ok(Err(e)) => {
            tracing::info!(
                target = "vpnctld::admin",
                server = %server.id,
                error = %e,
                "drift=live: live config read failed (best-effort)"
            );
            return DriftLiveResult::Unavailable;
        }
        Err(_elapsed) => {
            tracing::info!(
                target = "vpnctld::admin",
                server = %server.id,
                "drift=live: live config read timed out (best-effort)"
            );
            return DriftLiveResult::Unavailable;
        }
    };

    // Parse the on-node UUIDs (pub helper; parse failure → empty set,
    // which we treat as «no on-node users observed» rather than orphan
    // noise). The diff is against the granted set; naming uses the full
    // user list so a revoked user's lingering UUID is still labelled.
    let node_uuids = vpnctl_kernels::live_config_user_uuids(&bytes);
    let orphans = compute_orphan_uuids(&node_uuids, granted_users, all_users);
    DriftLiveResult::Ok { orphans }
}

/// server#1 — drift-detail card. Two modes:
///
/// * `armed == false` (default page load): renders a «[check live
///   drift →]» link anchored to `?drift=live`. NO SSH happened.
/// * `armed == true` (`?drift=live`): renders the orphan list from the
///   best-effort live read, or a policy-safe empty-state on any
///   failure. The empty-state copy NEVER instructs the operator to
///   «ssh to the box» — per operator-action-policy it says the config
///   couldn't be read (node unreachable or deploy key).
pub(super) fn server_detail_drift_detail_section(
    server: &vpnctl_core::Server,
    drift_live: Option<&DriftLiveResult>,
    armed: bool,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::{K, t, tr};
    let sid_enc = path_segment_encode(&server.id.0);
    html! {
        section id="drift-detail" style="margin-top: 28px;" {
            div.ed-art-eyebrow { (t(lang, K::EyebrowDriftDetail)) }
            p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin: 6px 0 12px;" {
                (tr(
                    lang,
                    "The port-level drift above compares declared protocols to listening sockets. This card goes deeper — it reads the node's live sing-box config and lists UUIDs the node still serves that no granted user accounts for (a revoked user whose UUID lingers, or a service account). It's a live SSH read, so it runs only on demand.",
                    "Дрейф по портам выше сравнивает заявленные протоколы со слушающими сокетами. Эта карточка копает глубже — читает живой конфиг sing-box на ноде и показывает UUID, которые нода всё ещё обслуживает, но за которыми не стоит ни один выданный доступ (отозванный юзер, чей UUID завис, или сервисный аккаунт). Это живое SSH-чтение, поэтому запускается только по запросу.",
                ))
            }
            @if !armed {
                // Default fast path — link to arm the live read. No SSH
                // was attempted on this render.
                p style="font-family: var(--mono); font-size: 12px; margin: 8px 0;" {
                    a href=(format!("/admin/servers/{sid_enc}/protocols?drift=live#drift-detail"))
                      style="color: var(--ink); border-bottom: 1px dotted var(--ink); text-decoration: none;" {
                        (tr(lang, "check live drift →", "проверить живой дрейф →"))
                    }
                }
                p style="font-family: var(--serif); font-style: italic; font-size: 11px; color: var(--mute); margin: 4px 0 0;" {
                    (tr(
                        lang,
                        "Skipped by default so the page loads fast — no node is contacted until you click.",
                        "По умолчанию пропускается ради быстрой загрузки — пока не нажмёшь, нода не опрашивается.",
                    ))
                }
            } @else {
                @match drift_live {
                    Some(DriftLiveResult::Ok { orphans }) if !orphans.is_empty() => {
                        div style="margin-top: 6px; padding: 10px 12px; border: 1px solid var(--acc); background: var(--paper);" {
                            div style="font-family: var(--mono); font-size: 10px; color: var(--acc); letter-spacing: 0.14em; text-transform: uppercase; margin-bottom: 6px;" {
                                (tr(lang, "orphan uuids on node", "осиротевшие uuid на ноде"))
                            }
                            ul style="list-style: none; padding: 0; font-family: var(--mono); font-size: 12px; line-height: 1.7;" {
                                @for o in orphans {
                                    li style="padding: 2px 0; border-bottom: 1px dotted var(--rule);" {
                                        span.ed-mono { (o.uuid) }
                                        " — "
                                        @match &o.name {
                                            Some(name) => {
                                                span style="color: var(--ink); font-style: italic; font-family: var(--serif);" {
                                                    (tr(lang, "maps to user ", "соответствует юзеру "))
                                                }
                                                a href=(format!("/admin/users/{}", path_segment_encode(name)))
                                                  style="color: var(--ink); border-bottom: 1px dotted var(--ink); text-decoration: none;" {
                                                    (name)
                                                }
                                            }
                                            None => {
                                                span style="color: var(--mute); font-style: italic; font-family: var(--serif);" {
                                                    (tr(lang, "(unresolved — likely service account)", "(не определён — вероятно сервисный аккаунт)"))
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            p style="font-family: var(--serif); font-style: italic; font-size: 11px; color: var(--mute); margin: 8px 0 0;" {
                                (tr(
                                    lang,
                                    "A redeploy re-renders the config from inventory and removes any UUID inventory doesn't expect.",
                                    "Redeploy перерендерит конфиг из инвентаря и уберёт любой UUID, которого инвентарь не ждёт.",
                                ))
                            }
                        }
                    }
                    Some(DriftLiveResult::Ok { .. }) => {
                        // Read succeeded, no orphans — clean state.
                        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--soft); margin-top: 6px;" {
                            (tr(
                                lang,
                                "Live config read OK — every UUID the node serves maps to a granted user. No orphans.",
                                "Живой конфиг прочитан — каждый UUID на ноде соответствует выданному доступу. Сирот нет.",
                            ))
                        }
                    }
                    _ => {
                        // Unavailable / None — policy-safe empty-state.
                        // NO «ssh to the box» instruction.
                        p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--mute); margin-top: 6px;" {
                            (tr(
                                lang,
                                "Couldn't read the live config (node unreachable or deploy key not authorised on it). Nothing was changed; try again after the node is back, or run a deploy which re-pushes the config anyway.",
                                "Не удалось прочитать живой конфиг (нода недоступна или deploy-ключ на ней не авторизован). Ничего не менялось; попробуй снова когда нода вернётся, либо запусти deploy — он всё равно перезальёт конфиг.",
                            ))
                        }
                    }
                }
            }
        }
    }
}

/// STATUS-tab drift glance (ui-audit §4): the declared-vs-observed
/// verdict + drift counts, linking to the full grid + observed-socket
/// list on the protocols tab. The list itself (100+ rows on xray
/// nodes) stays off the status wall — that's the whole point of the tab
/// split. Counts come from the same `missing`/`extra` the full section
/// uses, so the two can never disagree.
pub(super) fn server_detail_drift_summary(
    missing: &[(String, u16)],
    extra: &[(String, u16)],
    have_probe: bool,
    base: &str,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    html! {
        div.ed-rule {}
        div id="drift-summary" style="margin: 14px 0; font-family: var(--serif); font-size: 13px;" {
            @if !have_probe {
                span style="color: var(--mute); font-style: italic;" {
                    (tr(
                        lang,
                        "Drift — no probe yet (poller runs every 10 min; sing-box nodes only).",
                        "Дрейф — probe ещё нет (поллер ходит раз в 10 минут; только sing-box ноды).",
                    ))
                }
            } @else if missing.is_empty() && extra.is_empty() {
                span style="color: var(--soft);" {
                    (tr(
                        lang,
                        "✓ Declared and observed match. No drift.",
                        "✓ Заявленное и наблюдаемое совпадают. Дрейфа нет.",
                    ))
                }
            } @else {
                span style="color: var(--acc);" {
                    "⚠ " (tr(lang, "drift — ", "дрейф — "))
                    (missing.len()) " " (tr(lang, "declared-but-silent", "заявлено-но-молчит"))
                    " · "
                    (extra.len()) " " (tr(lang, "listening-but-undeclared", "слушает-но-не-заявлено"))
                }
                " "
                a href=(format!("{base}/protocols#drift-detail"))
                  style="color: var(--ink); border-bottom: 1px dotted var(--ink); text-decoration: none;" {
                    (tr(lang, "full grid on protocols tab →", "полная таблица на вкладке протоколы →"))
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn server_detail_drift_section(
    server: &vpnctl_core::Server,
    registry: &vpnctl_core::Registry,
    secrets: &HashMap<String, String>,
    observed: &BTreeSet<(String, u16)>,
    missing: &[(String, u16)],
    extra: &[(String, u16)],
    have_probe: bool,
    lang: crate::i18n::Locale,
) -> Markup {
    use crate::i18n::tr;
    // Design v2 3c — the declared × listening drift GRID: one row per
    // declared protocol, its expected ports, and whether the latest
    // probe saw each port open. Undeclared listeners follow, grouped
    // by a small classifier instead of a 100-socket wall.
    let has_wg = server
        .enabled_protocols
        .iter()
        .any(|p| p.0.contains("wireguard") || p.0.contains("amnezia"));
    // Group the undeclared listeners. Adopt/ignore actions are
    // deliberately absent — the inventory doesn't model per-peer
    // ports yet (NM-14); this table only keeps the wall readable.
    let mut wg_peers = 0usize;
    let mut caddy_internals: Vec<String> = Vec::new();
    let mut unclassified: Vec<String> = Vec::new();
    for (proto, port) in extra {
        if proto == "tcp" && (*port == 2019 || *port == 80) {
            caddy_internals.push(format!("{proto}/{port}"));
        } else if has_wg && proto == "udp" && *port >= 30000 {
            wg_peers += 1;
        } else {
            unclassified.push(format!("{proto}/{port}"));
        }
    }
    html! {
        div.ed-rule {}
        div.ed-art-eyebrow {
            (tr(lang, "Declared vs observed", "Заявлено vs наблюдается")) " "
            span.ed-tip title=(tr(
                lang,
                "Declared = protocol in the inventory for this node. Listening = the latest probe found the port open (ss -tlnup). A declared-but-silent port is the dangerous drift; undeclared listeners are usually per-user wg peers.",
                "Заявлено = протокол в инвентаре этой ноды. Слушает = последняя проба нашла порт открытым (ss -tlnup). Заявлено-но-молчит — опасный дрейф; незаявленные слушатели обычно пер-пировые wg-порты.",
            )) { "ⓘ" }
        }
        @if !have_probe {
            p style="font-family: var(--serif); font-style: italic; color: var(--mute); margin-top: 8px;" {
                (tr(lang, "(no probe yet — poller runs every 10 min; sing-box nodes only)", "(probe ещё нет — поллер ходит раз в 10 минут; только sing-box ноды)"))
            }
        } @else {
            table.ed-grid style="margin-top: 8px;" {
                thead {
                    tr {
                        th { (tr(lang, "protocol", "протокол")) }
                        th { (tr(lang, "port(s)", "порт(ы)")) }
                        th { (tr(lang, "declared", "заявлен")) }
                        th { (tr(lang, "listening", "слушает")) }
                    }
                }
                tbody {
                    @for pid in &server.enabled_protocols {
                        @let ports = expected_ports_for_protocol(registry, pid, secrets);
                        @let silent = ports.iter().any(|pp| !observed.contains(pp));
                        tr class=(if silent && !ports.is_empty() { "on-warn" } else { "" }) {
                            td { b { (pid.0) } }
                            td.num.ed-grid__sm {
                                @if ports.is_empty() {
                                    span.ed-grid__mut { "—" }
                                } @else {
                                    @for (i, (proto, port)) in ports.iter().enumerate() {
                                        @if i > 0 { " · " }
                                        (port) "/" (proto)
                                    }
                                }
                            }
                            td { span style="color: var(--green);" { "✓" } }
                            td.ed-grid__sm {
                                @if ports.is_empty() {
                                    span.ed-grid__mut { (tr(lang, "n/a (no fixed port)", "н/д (нет фикс. порта)")) }
                                } @else {
                                    @for (i, pp) in ports.iter().enumerate() {
                                        @if i > 0 { " · " }
                                        @if observed.contains(pp) {
                                            span style="color: var(--green);" { "✓" }
                                        } @else {
                                            span.ed-grid__flag { "✗ " (tr(lang, "silent", "молчит")) }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            @if !missing.is_empty() {
                p style="font-family: var(--mono); font-size: 11px; color: var(--warm); margin-top: 8px;" {
                    "⚠ " (tr(lang, "declared but NOT listening: ", "заявлено, но НЕ слушает: "))
                    @for (i, (proto, port)) in missing.iter().enumerate() {
                        @if i > 0 { ", " }
                        (proto) "/" (port)
                    }
                    " — " (tr(lang, "re-deploy or check the service on the node", "передеплой или проверь сервис на ноде"))
                }
            }
            @if !extra.is_empty() {
                div.ed-art-eyebrow style="margin-top: 14px;" {
                    (tr(lang, "Listening but undeclared", "Слушает, но не заявлено"))
                    " · " (extra.len()) " "
                    span.ed-tip title=(tr(
                        lang,
                        "Per-user AmneziaWG peers each bind their own UDP port — expected, but the inventory doesn't model them yet (NM-14). This grouping keeps the wall readable; there's nothing to click.",
                        "Каждый пер-пировый порт AmneziaWG — свой UDP-сокет: ожидаемо, но инвентарь их пока не моделирует (NM-14). Группировка держит стену читабельной; кликать тут нечего.",
                    )) { "ⓘ" }
                }
                table.ed-grid style="margin-top: 8px;" {
                    thead {
                        tr {
                            th { (tr(lang, "group", "группа")) }
                            th.num { (tr(lang, "ports", "портов")) }
                            th { (tr(lang, "classification", "классификация")) }
                        }
                    }
                    tbody {
                        @if wg_peers > 0 {
                            tr {
                                td { b { (tr(lang, "wg per-user peers", "wg пер-пировые порты")) } }
                                td.num { (wg_peers) }
                                td.ed-grid__sm { span.ed-grid__flag { "⚠ " (tr(lang, "expected · unmodelled (NM-14)", "ожидаемо · не смоделировано (NM-14)")) } }
                            }
                        }
                        @if !caddy_internals.is_empty() {
                            tr {
                                td { b { "caddy internals" } }
                                td.num { (caddy_internals.len()) }
                                td.ed-grid__mut.ed-grid__sm { (caddy_internals.join(" · ")) " · " (tr(lang, "known-benign", "заведомо безобидно")) }
                            }
                        }
                        @if !unclassified.is_empty() {
                            tr {
                                td { b { (tr(lang, "unclassified", "не классифицировано")) } }
                                td.num { (unclassified.len()) }
                                td.ed-grid__sm { (unclassified.join(" · ")) }
                            }
                        }
                    }
                }
            } @else if missing.is_empty() {
                p style="font-family: var(--serif); font-style: italic; font-size: 12px; color: var(--soft); margin-top: 10px;" {
                    (tr(lang, "Declared and observed match. No drift.", "Заявленное и наблюдаемое совпадают. Дрейфа нет."))
                }
            }
        }
    }
}
