//! Phase H chunk 4 — periodic SSH-probe scheduler.
//!
//! Sits between [`crate::node_probe::SshProbeClient`] (chunk 1, which
//! does ONE round-trip + parse) and
//! [`vpnctl_inventory::SqliteInventory::record_node_health`] (chunk 2,
//! which persists ONE row). This module is the runtime wiring: every
//! `VPNCTLD_NODE_PROBE_INTERVAL_SECS` it pulls one probe per sing-box
//! server and INSERTs the result. The `/admin/servers/{id}` page
//! (chunk 3) reads `latest_node_health` + `recent_node_health_for_server`
//! and is empty-state today; this fills it in.
//!
//! Structurally identical to [`crate::clash_poller`] — same robustness
//! contract:
//!   * **Per-server failures are isolated.** SSH unreachable, no deploy
//!     key, `ss` not installed, probe parser returns
//!     `ScriptDidNotComplete` — each one fails the ONE server's tick
//!     and continues to the next.
//!   * **Missing SSH key is a WARN, not a panic.** The empty-state on
//!     `/admin/servers/{id}` already mentions the prereq.
//!   * **No DiffEngine.** Unlike clash-api, node_health snapshots are
//!     INSERT-only (one row per tick); no in-memory state between
//!     ticks, so no `forget()` is needed and no leak guard.
//!   * **One tick per interval, sequentially per server.** Five
//!     servers × 1 s SSH each ≈ 5 s per tick. Default 5-min interval
//!     gives ~98% idle.
//!
//! ## Why a separate poller from clash_poller
//!
//! Different cadence concerns (clash is per-user traffic — useful
//! every 5 min; node_probe is service-up + disk + log size — fine at
//! 10 min if anything), different failure modes (clash is missing
//! when sing-box runs without `experimental.clash_api`; probe fails
//! when busybox lacks `ss`), different retention windows. Splitting
//! lets each evolve independently. They share the same SSH key path
//! and the same `SubprocessSshTransport` (Path C — bookworm-2.36-
//! native).
//!
//! Phase G alerts (next commit) reads `node_health` for state-change
//! detection (`sing_box_active` flipping `true → false` writes an
//! `admin_alerts` row).

use std::collections::HashMap;
use std::time::Duration;

use vpnctl_core::ServerId;
use vpnctl_inventory::SqliteInventory;

/// Centralised "does this kernel expose the probe-able surface" check.
/// Today only `sing-box` answers — AmneziaWG nodes don't run systemd
/// `sing-box`, so the probe script's `systemctl is-active sing-box`
/// would just emit `unknown` noise. Used by BOTH `node_probe_poller`
/// (writes node_health) AND `health_monitor` (reads node_health) so
/// the two surfaces never disagree on what's in scope.
///
/// **TODO(amneziawg)**: when the AmneziaWG kernel ships, either teach
/// this fn to return `true` for it AND wire a per-kernel probe variant
/// (`wg show` instead of `systemctl is-active sing-box`), OR keep the
/// sing-box-only behaviour and add a sibling `probeable_amneziawg`.
/// Today's grep target: `fn probeable`.
pub(crate) fn probeable(server: &vpnctl_core::Server) -> bool {
    server.kernels.iter().any(|k| k.0 == "sing-box")
}

/// Realistic homelab cadence for telemetry. Slower than clash-api
/// (5 min) because node probe is "is the service alive + disk OK"
/// rather than "what's happening NOW with user traffic" — 10 min
/// is fine, halves SSH overhead vs co-cadence with clash.
///
/// Override via env `VPNCTLD_NODE_PROBE_INTERVAL_SECS`. Tests use
/// short intervals to validate the loop; production sticks with
/// the default.
const DEFAULT_INTERVAL_SECS: u64 = 10 * 60;

/// Default number of consecutive SSH-probe failures before firing the
/// `server.unreachable` alert. Three ticks at the 10-min default
/// cadence ≈ 30 min ceiling on flapping noise. Override via env
/// `VPNCTLD_UNREACHABLE_THRESHOLD`.
const DEFAULT_UNREACHABLE_THRESHOLD: u32 = 3;

/// Outcome of one `probe_one_server` invocation. The poller's state
/// machine reads this to drive the `server.unreachable` consecutive-
/// failure detector (Phase G chunk 2). Probe success ⇒ `Ok(_)`; SSH-
/// or-shell-broken ⇒ `SshFailed`; probe parsed but row insert failed
/// ⇒ `RowWriteFailed` (the failure is logged but doesn't count
/// against the unreachable detector — the node IS reachable).
// `Ok(Probe)` is much larger than the error variants, but a ProbeOutcome
// is created once per probe + matched immediately (never bulk-stored), so
// boxing would add indirection for no real memory benefit.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// Probe succeeded; carries the parsed snapshot so the caller can
    /// dispatch derived alerts (e.g. `fail2ban.banned_self`).
    Ok(crate::node_probe::Probe),
    /// SSH transport / probe script failed entirely. Counts toward the
    /// `server.unreachable` consecutive-failure threshold. Carries a
    /// short human-readable reason (already redacted, safe for
    /// alert payload).
    SshFailed(String),
    /// Probe ran fine but the inventory write failed (sqlx-level
    /// error). Does NOT count toward unreachable (the node IS
    /// reachable; storage is broken, separate problem).
    RowWriteFailed,
    /// Server has no probe-able kernel (e.g. AmneziaWG-only). Skipped
    /// entirely; not a failure.
    Skipped,
    /// Deploy key not on disk. Skipped at the SSH transport boundary;
    /// not a failure.
    NoDeployKey,
}

/// Transition emitted by [`FailState::observe`] when the consecutive-
/// failure counter crosses a meaningful threshold. The caller maps
/// this into `insert_alert_if_no_unacked` / `ack_open_alerts` calls
/// against the inventory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnreachableTransition {
    /// The counter just reached the threshold for the FIRST time
    /// since the last `Recovered` (or process start). Caller fires
    /// the `server.unreachable` alert.
    BecameUnreachable {
        consecutive_failures: u32,
        threshold: u32,
    },
    /// The server is STILL failing on a later tick (counter already ≥
    /// threshold and we've already fired once). The caller RE-ATTEMPTS
    /// the idempotent `insert_alert_if_no_unacked`: a no-op while the
    /// alert is open + unacked, but if the operator ACKED it while the
    /// server is still down, the insert re-opens a fresh alert. Without
    /// this, an ack permanently silenced a still-down server until a
    /// recovery reset the in-memory `fired` flag — the kg 2026-05-31
    /// incident (acked 21:09 UTC, probes still failing 21:11/21:16, no
    /// re-fire). The DB's partial-UNIQUE-on-unacked index is what makes
    /// this safe to emit every tick (dedup while open).
    StillUnreachable {
        consecutive_failures: u32,
        threshold: u32,
    },
    /// A previously-failed server just succeeded. Caller acks any
    /// open `server.unreachable` alert for this id.
    Recovered,
    /// Counter changed but no transition worth alerting on (e.g.
    /// failure #2 of 3, or repeated success after recovery already
    /// fired).
    NoChange,
}

/// In-memory per-server consecutive-SSH-failure counter. **Not**
/// persisted across daemon restarts — restart is operator-initiated
/// and rare; the counter resetting just means a flapping server
/// needs another N ticks to re-alert. Documented in the field's
/// doc so future-Pavel doesn't try to persist it.
#[derive(Debug)]
pub struct FailState {
    /// Per-server count of consecutive failures since the last
    /// success. `0` = last outcome was Ok / Skipped / NoDeployKey.
    counters: HashMap<ServerId, u32>,
    /// Per-server flag: `true` if we've already emitted a
    /// `BecameUnreachable` for this id and haven't seen a recovery
    /// yet. Prevents re-firing every tick once the threshold is
    /// crossed.
    fired: HashMap<ServerId, bool>,
    threshold: u32,
}

impl FailState {
    /// Construct with the env-resolved threshold (defaults to 3).
    pub fn new() -> Self {
        Self::with_threshold(
            std::env::var("VPNCTLD_UNREACHABLE_THRESHOLD")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(DEFAULT_UNREACHABLE_THRESHOLD),
        )
    }

    /// Construct with an explicit threshold. Test-friendly.
    pub fn with_threshold(threshold: u32) -> Self {
        // Treat a zero threshold as 1 — a zero would mean "fire on
        // every failure" which is operator-hostile noise; clamp.
        let threshold = threshold.max(1);
        Self {
            counters: HashMap::new(),
            fired: HashMap::new(),
            threshold,
        }
    }

    /// Record one probe outcome for a server, returning the alert
    /// transition (if any). Pure state-machine; no I/O.
    pub fn observe(
        &mut self,
        server_id: &ServerId,
        outcome: &ProbeOutcome,
    ) -> UnreachableTransition {
        match outcome {
            ProbeOutcome::Ok(_) => self.recover(server_id),
            ProbeOutcome::SshFailed(_) => self.fail(server_id),
            // RowWriteFailed: the node IS reachable; don't count
            // toward unreachable. Treat as no-change (don't reset
            // the counter either — preserve in-flight detection).
            ProbeOutcome::RowWriteFailed => UnreachableTransition::NoChange,
            // Skipped / NoDeployKey: not a probe attempt; don't
            // affect counter or fired-flag.
            ProbeOutcome::Skipped | ProbeOutcome::NoDeployKey => UnreachableTransition::NoChange,
        }
    }

    fn fail(&mut self, server_id: &ServerId) -> UnreachableTransition {
        let counter = self.counters.entry(server_id.clone()).or_insert(0);
        *counter = counter.saturating_add(1);
        let reached = *counter >= self.threshold;
        let already_fired = self.fired.get(server_id).copied().unwrap_or(false);
        if reached && !already_fired {
            self.fired.insert(server_id.clone(), true);
            UnreachableTransition::BecameUnreachable {
                consecutive_failures: *counter,
                threshold: self.threshold,
            }
        } else if reached {
            // Already fired but STILL failing → re-assert so an
            // acked-but-still-down alert re-opens. The caller's insert
            // is idempotent (partial-UNIQUE on unacked), so this is a
            // no-op while the alert is open and a re-fire after an ack.
            UnreachableTransition::StillUnreachable {
                consecutive_failures: *counter,
                threshold: self.threshold,
            }
        } else {
            // Below threshold (e.g. failure #2 of 3) — not yet alertable.
            UnreachableTransition::NoChange
        }
    }

    /// Drop in-memory entries for server ids that are no longer in
    /// the current inventory snapshot. Caller passes the live set
    /// from `list_servers()`. Prevents (a) unbounded HashMap growth
    /// on server churn (b) the stale-state bug where re-adding a
    /// previously-deleted server with the same id silently inherits
    /// `fired=true` and the next N failures don't alert.
    ///
    /// Bug-hunt agent 2026-05-18 finding.
    pub fn prune(&mut self, live_ids: &std::collections::HashSet<ServerId>) {
        self.counters.retain(|k, _| live_ids.contains(k));
        self.fired.retain(|k, _| live_ids.contains(k));
    }

    fn recover(&mut self, server_id: &ServerId) -> UnreachableTransition {
        let was_failing = self.counters.get(server_id).copied().unwrap_or(0) > 0;
        let had_fired = self.fired.get(server_id).copied().unwrap_or(false);
        self.counters.insert(server_id.clone(), 0);
        self.fired.insert(server_id.clone(), false);
        // Emit `Recovered` only when there's something for the
        // caller to ack — either the alert had fired, OR the counter
        // was above zero (so a future tick MIGHT have fired). Repeat
        // successes after a stable recovery return NoChange.
        if had_fired {
            UnreachableTransition::Recovered
        } else if was_failing {
            // Counter was non-zero but threshold not crossed →
            // operator never saw an alert; nothing to ack.
            UnreachableTransition::NoChange
        } else {
            UnreachableTransition::NoChange
        }
    }
}

impl Default for FailState {
    fn default() -> Self {
        Self::new()
    }
}

/// Spawn the node-probe poller. Returns the [`tokio::task::JoinHandle`]
/// so production (which discards) and tests (which assert spawn)
/// have the same interface, matching [`crate::clash_poller::spawn_clash_poller`].
///
/// **No feature gate required** — uses
/// [`crate::ssh_subprocess::SubprocessSshTransport`] which shells out
/// to the system `/usr/bin/ssh` binary (no glibc-2.38 hazard).
pub fn spawn_node_probe_poller(inv: SqliteInventory) -> tokio::task::JoinHandle<()> {
    use tokio::time::{MissedTickBehavior, interval};

    // `> 0` guard + warn-on-bad lives in `config::parse_positive_secs`:
    // `interval(Duration::from_secs(0))` panics → poller crash-loop.
    let interval_secs = crate::config::parse_positive_secs(
        "VPNCTLD_NODE_PROBE_INTERVAL_SECS",
        DEFAULT_INTERVAL_SECS,
    );

    tokio::spawn(async move {
        let mut tick = interval(Duration::from_secs(interval_secs));
        tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        // Drop the immediate first fire — daemon startup is hot;
        // gives the operator a grace period before the first probe.
        tick.tick().await;

        let mut fail_state = FailState::new();

        loop {
            tick.tick().await;
            let servers = match inv.list_servers().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(
                        target = "vpnctld::node_probe",
                        error = %e,
                        "list_servers failed; skipping tick"
                    );
                    continue;
                }
            };
            // Prune FailState entries for ids no longer in inventory
            // BEFORE iterating. Catches the «delete + re-add same id»
            // case where stale fired=true would suppress the next
            // BecameUnreachable. Bug-hunt agent finding 2026-05-18.
            let live_ids: std::collections::HashSet<vpnctl_core::ServerId> =
                servers.iter().map(|s| s.id.clone()).collect();
            fail_state.prune(&live_ids);

            for server in &servers {
                let outcome = probe_one_server(&inv, server).await;
                dispatch_alerts(&inv, server, &outcome, &mut fail_state).await;
            }
        }
    })
}

/// Translate one [`ProbeOutcome`] into the appropriate inventory-
/// level alert writes (fire / ack). Pulled out as a free function
/// so admin_smoke can drive it with a hand-built outcome without
/// having to mock SSH + interval clock.
pub async fn dispatch_alerts(
    inv: &SqliteInventory,
    server: &vpnctl_core::Server,
    outcome: &ProbeOutcome,
    fail_state: &mut FailState,
) {
    // ─── server.unreachable (state-machine over outcomes) ─────
    match fail_state.observe(&server.id, outcome) {
        // First fire AND every subsequent still-down tick run the SAME
        // idempotent insert: while the alert is open + unacked the
        // partial-UNIQUE index makes it a no-op (Ok(None)); after the
        // operator acks a still-down server, the next tick's insert
        // re-opens it (Ok(Some) → audit + push). This is the kg
        // 2026-05-31 fix — an ack no longer permanently silences a
        // server that's still failing.
        UnreachableTransition::BecameUnreachable {
            consecutive_failures,
            threshold,
        }
        | UnreachableTransition::StillUnreachable {
            consecutive_failures,
            threshold,
        } => {
            let reason = match outcome {
                ProbeOutcome::SshFailed(msg) => msg.as_str(),
                _ => "unknown",
            };
            // Payload is operationally-relevant numbers + the redacted
            // SSH stderr. Per `insert_alert_if_no_unacked` doc: no
            // secrets.
            let payload_val = serde_json::json!({
                "consecutive_failures": consecutive_failures,
                "threshold": threshold,
                "last_ssh_error": reason,
                "ssh_user": server.ssh_user,
                "ssh_port": server.ssh_port,
                "ip": server.address,
            });
            let payload = payload_val.to_string();
            let subject = server_subject(inv, &server.id).await;
            let summary = format!(
                "{consecutive_failures} consecutive SSH probes failed — host may be down, key revoked, or sshd port changed"
            );
            match inv
                .insert_alert_if_no_unacked(
                    "server.unreachable",
                    Some(&server.id),
                    "warning",
                    &summary,
                    Some(&payload),
                )
                .await
            {
                Ok(Some(id)) => {
                    // Row freshly inserted. Honour migration 0011's
                    // contract: «audit_log row is STILL written for
                    // every alert with action='alert.fire'». Bug-
                    // hunt agent 2026-05-18 caught this — chunk 2
                    // detectors skipped it, breaking /admin/audit.
                    audit_alert_fire(inv, &server.id, id, "server.unreachable", &summary).await;
                    // Then push to the configured sink (best-effort). The
                    // row id is threaded so the message id is recorded for
                    // edit-on-recover.
                    push_alert(
                        inv,
                        "server.unreachable",
                        "warning",
                        &subject,
                        &payload_val,
                        Some(id),
                    )
                    .await;
                }
                Ok(None) => {
                    // Duplicate suppressed by the partial-UNIQUE
                    // index — same condition already raised + unacked.
                }
                Err(e) => tracing::warn!(
                    target = "vpnctld::node_probe",
                    server = %server.id.0,
                    error = %e,
                    "insert server.unreachable alert failed"
                ),
            }
            // Auto-suppress (migration 0030): if the operator opted this
            // server in, flag it suppressed so the subscription render
            // stops handing clients a dead URI. Idempotent — only the
            // first crossing actually writes + audits; later still-down
            // ticks are no-ops. Gated on the per-server opt-in (default
            // off → unchanged behaviour, server stays in the sub).
            match inv.server_auto_suppress_state(&server.id).await {
                Ok((true, _)) => {
                    if let Err(e) = inv.set_server_suppressed(&server.id, true).await {
                        tracing::warn!(
                            target = "vpnctld::node_probe",
                            server = %server.id.0,
                            error = %e,
                            "auto-suppress set failed"
                        );
                    }
                }
                Ok((false, _)) => {} // opt-in off — leave it in the sub.
                Err(e) => tracing::warn!(
                    target = "vpnctld::node_probe",
                    server = %server.id.0,
                    error = %e,
                    "auto-suppress state read failed"
                ),
            }
        }
        UnreachableTransition::Recovered => {
            // Edit-on-recover: flip the original 🔴 «недоступна» message
            // to 🟢 «снова доступна» BEFORE acking (the ack clears the
            // row but the message id is read from the most-recent
            // unreachable row regardless of ack state).
            let subject = server_subject(inv, &server.id).await;
            recover_alert(
                inv,
                "server.unreachable",
                "server.unreachable",
                &subject,
                &serde_json::json!({ "ip": server.address }),
                Some(&server.id),
                None,
            )
            .await;
            auto_ack(
                inv,
                &server.id,
                "server.unreachable",
                "probe succeeded after consecutive failures",
            )
            .await;
        }
        UnreachableTransition::NoChange => {}
    }

    // Auto-restore (migration 0030): clear suppression on ANY successful
    // probe — NOT only the `Recovered` transition. The in-memory
    // FailState resets on a daemon restart (routine — every redeploy),
    // so a server suppressed before the restart would otherwise stay
    // suppressed forever if it recovered within fewer than `threshold`
    // failed probes (recover() emits `Recovered` only when it had a
    // fired state to clear → otherwise NoChange → the clear never ran).
    // Tying the clear to the Ok OUTCOME — idempotent no-op when not
    // suppressed — makes restore restart-safe. (review-agent critical.)
    if matches!(outcome, ProbeOutcome::Ok(_)) {
        if let Err(e) = inv.set_server_suppressed(&server.id, false).await {
            tracing::warn!(
                target = "vpnctld::node_probe",
                server = %server.id.0,
                error = %e,
                "auto-restore (clear suppressed) failed"
            );
        }
    }

    // ─── server.fail2ban.banned_self (per-probe-snapshot verdict) ─
    //
    // Only inspectable when the probe succeeded AND the parser
    // produced a verdict (both SSH_CLIENT_IP and fail2ban-client
    // output were parseable). The `None` case is no-signal and
    // intentionally does NOT touch the alert state — operator-clear
    // requires explicit `Some(false)`.
    if let ProbeOutcome::Ok(probe) = outcome {
        match probe.fail2ban_self_banned {
            Some(true) => {
                let banned_list = probe.fail2ban_banned_ips.clone().unwrap_or_default();
                let our_ip = probe.probe_source_ip.clone().unwrap_or_default();
                let ban_count_other = banned_list.len().saturating_sub(1);
                // Daemon is LOCKED OUT — by definition it can't
                // self-recover (it tried to SSH and got banned).
                // The remediation must:
                //   (a) substitute the actual IP literally (the
                //       previous «<our_ip>» placeholder was a real
                //       regression — review-agent caught it),
                //   (b) live in `summary` (rendered by `alerts_table`),
                //       NOT in `payload_json` (which `/admin/alerts`
                //       never displays — only kind + summary + severity
                //       are surfaced).
                let payload_val = serde_json::json!({
                    "our_ip": our_ip,
                    "fail2ban_banned_ips": banned_list,
                    "ban_count_other": ban_count_other,
                });
                let payload = payload_val.to_string();
                let subject = server_subject(inv, &server.id).await;
                // Summary IS rendered; bake the unban command + the
                // «hoster console» hint right into it so the operator
                // sees it on /admin/alerts without drilling into the
                // (currently un-rendered) payload.
                let summary = format!(
                    "daemon's outbound IP {our_ip} is in fail2ban's banned list for sshd. \
                     Daemon can't self-recover — use the hoster's console / KVM to run \
                     `fail2ban-client set sshd unbanip {our_ip}` (the next probe \
                     auto-clears this alert)."
                );
                match inv
                    .insert_alert_if_no_unacked(
                        "server.fail2ban.banned_self",
                        Some(&server.id),
                        "critical",
                        &summary,
                        Some(&payload),
                    )
                    .await
                {
                    Ok(Some(id)) => {
                        // Honour 0011's audit_log contract — same
                        // fix as server.unreachable above.
                        audit_alert_fire(
                            inv,
                            &server.id,
                            id,
                            "server.fail2ban.banned_self",
                            &summary,
                        )
                        .await;
                        push_alert(
                            inv,
                            "server.fail2ban.banned_self",
                            "critical",
                            &subject,
                            &payload_val,
                            Some(id),
                        )
                        .await;
                    }
                    Ok(None) => {}
                    Err(e) => tracing::warn!(
                        target = "vpnctld::node_probe",
                        server = %server.id.0,
                        error = %e,
                        "insert server.fail2ban.banned_self alert failed"
                    ),
                }
            }
            Some(false) => {
                auto_ack(
                    inv,
                    &server.id,
                    "server.fail2ban.banned_self",
                    "outbound IP no longer in fail2ban-client status sshd banned list",
                )
                .await;
            }
            None => {} // no signal → no action
        }
    }
}

/// Push one freshly-inserted alert via the configured AlertSink.
/// Fire-and-forget — spawns a tokio task so the curl call (up to
/// 20s with the default timeout) doesn't block the next server's
/// probe. Reads the Telegram config from inventory each call (cheap
/// SQLite roundtrip, ~µs) so a config change via /admin/settings
/// takes effect on the very next alert without a daemon restart.
///
/// Sink-side errors are LOGGED at warn but never returned — the
/// alert is already persisted in `admin_alerts`, push is the
/// best-effort secondary delivery. If the operator wants to find
/// out why a Telegram message didn't arrive, the journal carries
/// the full curl-stderr context.
/// Write the `alert.fire` audit_log row that migration 0011's
/// schema doc-comment mandates for every newly-inserted alert.
/// Same shape as `health_monitor.rs::insert_alert`'s audit call,
/// extracted as a free fn so both `dispatch_alerts` detector
/// branches share one source of truth. Bug-hunt agent finding
/// 2026-05-18.
async fn audit_alert_fire(
    inv: &SqliteInventory,
    server_id: &ServerId,
    alert_id: i64,
    kind: &str,
    summary: &str,
) {
    if let Err(e) = inv
        .audit(
            "vpnctld",
            "alert.fire",
            Some(&server_id.0),
            Some(&serde_json::json!({
                "alert_id": alert_id,
                "kind": kind,
                "summary": summary,
            })),
        )
        .await
    {
        tracing::warn!(
            target = "vpnctld::node_probe",
            kind = kind,
            server = %server_id.0,
            error = %e,
            "audit_log row for alert.fire failed; alert row is still in admin_alerts"
        );
    }
}

/// Push one alert to the configured transport, rendered localized +
/// pretty. `subject` is the human display-name (country label for server
/// alerts, user id for user alerts); `payload` is the structured event
/// fields — the message TEXT is produced HERE in the operator's language
/// (`notification_settings.language`), so the same event speaks Russian
/// to the operator while the dashboard can render any locale.
/// `alert_id` (when known) is the `admin_alerts` row id; on a successful
/// push the transport's `message_id` is recorded against it so a later
/// recovery can EDIT this exact 🔴 message to 🟢 (see [`recover_alert`]).
pub(crate) async fn push_alert(
    inv: &SqliteInventory,
    kind: &str,
    severity: &str,
    subject: &str,
    payload: &serde_json::Value,
    alert_id: Option<i64>,
) {
    // Resolve the operator's notification language (best-effort — fall
    // back to En on any read failure rather than dropping the alert).
    let loc = match inv.get_telegram_config().await {
        Ok(Some(cfg)) => crate::i18n::Locale::from_lang_code(cfg.language.as_deref()),
        _ => crate::i18n::Locale::En,
    };
    let rendered = crate::alert_text::render_alert(kind, severity, subject, payload, loc);
    let time_local =
        crate::handlers::admin::format_local_with_pattern(chrono::Utc::now(), "%d.%m %H:%M");
    let text = crate::alert_text::to_telegram_html(&rendered, loc, &time_local, false);
    let silent = crate::alert_text::is_silent(severity);

    let sink = match build_alert_sink(inv).await {
        Ok(Some(s)) => s,
        Ok(None) => return, // transport not configured — no-op
        Err(e) => {
            tracing::warn!(
                target = "vpnctld::alert_sink",
                error = %e,
                "build_alert_sink failed; skipping push for this alert"
            );
            return;
        }
    };

    // Owned clones for the spawn — these are short strings.
    let kind = kind.to_string();
    let severity = severity.to_string();
    let inv = inv.clone();
    tokio::spawn(async move {
        // Track sink name BEFORE the move-into-await so we can log
        // it on success without resurrecting a borrow from `sink`.
        let sink_name = sink.name();
        match sink.send_text(&kind, &severity, &text, silent).await {
            Ok(message_id) => {
                tracing::info!(
                    target = "vpnctld::alert_sink",
                    kind = %kind,
                    "pushed via {}",
                    sink_name
                );
                // Record the Telegram message id against the alert row so
                // a later recovery edits THIS message instead of posting a
                // second one. Best-effort — failure just means recovery
                // falls back to a fresh 🟢 message.
                if let (Some(aid), Some(mid)) = (alert_id, message_id) {
                    if let Err(e) = inv.set_alert_telegram_message_id(aid, &mid).await {
                        tracing::warn!(
                            target = "vpnctld::alert_sink",
                            kind = %kind,
                            error = %e,
                            "failed to record telegram_message_id; edit-on-recover will fall back"
                        );
                    }
                }
            }
            Err(e) => {
                tracing::warn!(
                    target = "vpnctld::alert_sink",
                    kind = %kind,
                    error = %e,
                    "push to {} failed; alert row still in admin_alerts",
                    sink_name
                );
            }
        }
    });
}

/// Recovery push (edit-on-recover): instead of sending a SECOND message
/// when a condition clears, EDIT the original 🔴 alert message in place
/// to 🟢. Looks up the `resolves_kind`'s most-recent
/// `telegram_message_id` for `server_id`; if found, edits that message
/// with the localized recovery text; if not (transport was off when the
/// condition fired, or it predates this feature) falls back to a fresh
/// recovery message via [`push_alert`]. Recovery is always rendered as
/// the silent 🟢 info variant.
///
/// Eventual-consistency note: the condition's message id is written by a
/// spawned task inside [`push_alert`]. Recovery normally happens a probe
/// interval (≥10 min) later, so the write has long landed; a sub-second
/// flap across two back-to-back ticks could miss it and send a fresh 🟢
/// rather than editing — graceful degradation, not a bug.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn recover_alert(
    inv: &SqliteInventory,
    recovery_kind: &str,
    resolves_kind: &str,
    subject: &str,
    payload: &serde_json::Value,
    server_id: Option<&vpnctl_core::ServerId>,
    fallback_alert_id: Option<i64>,
) {
    let loc = match inv.get_telegram_config().await {
        Ok(Some(cfg)) => crate::i18n::Locale::from_lang_code(cfg.language.as_deref()),
        _ => crate::i18n::Locale::En,
    };
    let rendered = crate::alert_text::render_alert(recovery_kind, "info", subject, payload, loc);
    let time_local =
        crate::handlers::admin::format_local_with_pattern(chrono::Utc::now(), "%d.%m %H:%M");
    let text = crate::alert_text::to_telegram_html(&rendered, loc, &time_local, false);

    let message_id = match inv.latest_alert_message_id(resolves_kind, server_id).await {
        Ok(mid) => mid,
        Err(e) => {
            tracing::warn!(
                target = "vpnctld::alert_sink",
                resolves = %resolves_kind,
                error = %e,
                "latest_alert_message_id failed; sending a fresh recovery message"
            );
            None
        }
    };

    let Some(mid) = message_id else {
        // No original message to edit → fresh 🟢 (carries its own row id).
        push_alert(
            inv,
            recovery_kind,
            "info",
            subject,
            payload,
            fallback_alert_id,
        )
        .await;
        return;
    };

    let sink = match build_alert_sink(inv).await {
        Ok(Some(s)) => s,
        Ok(None) => return,
        Err(e) => {
            tracing::warn!(
                target = "vpnctld::alert_sink",
                error = %e,
                "build_alert_sink failed; skipping recovery edit"
            );
            return;
        }
    };
    let recovery_kind = recovery_kind.to_string();
    tokio::spawn(async move {
        let sink_name = sink.name();
        if let Err(e) = sink.edit_text(&mid, &text).await {
            // The original message is gone (operator deleted it, or it
            // aged past Telegram's 48h edit window). Don't lose the
            // recovery — send a fresh 🟢 instead.
            tracing::warn!(
                target = "vpnctld::alert_sink",
                kind = %recovery_kind,
                error = %e,
                "edit-on-recover via {} failed; sending a fresh recovery message",
                sink_name
            );
            let _ = sink.send_text(&recovery_kind, "info", &text, true).await;
        } else {
            tracing::info!(
                target = "vpnctld::alert_sink",
                kind = %recovery_kind,
                "edited original alert message to recovered via {}",
                sink_name
            );
        }
    });
}

/// Resolve a server's human label for an alert subject: operator's
/// custom `display_name` → country map → uppercased id. Same precedence
/// as the `/sub` + `/api/v1/app/config` render, so an alert names a node
/// exactly as the operator sees it elsewhere (e.g. `cdn` → «Latvia»).
/// Best-effort — a DB read failure degrades to the country/id resolution.
pub(crate) async fn server_subject(inv: &SqliteInventory, sid: &vpnctl_core::ServerId) -> String {
    let custom = inv.server_display_name(sid).await.ok().flatten();
    crate::handlers::vpn_router::server_display_label(&sid.0, custom.as_deref())
}

/// Build + send a fleet digest to the configured transport: «all clear»
/// 🟢 when there are no open alerts, otherwise a 🔴 list of every open
/// problem (each rendered + localized). Drives the daily scheduler + the
/// on-demand /admin/settings button. Best-effort — logs + returns on any
/// storage/transport failure. Sent silently (a routine summary).
pub(crate) async fn send_digest(inv: &SqliteInventory) {
    let loc = match inv.get_telegram_config().await {
        Ok(Some(cfg)) => crate::i18n::Locale::from_lang_code(cfg.language.as_deref()),
        _ => crate::i18n::Locale::En,
    };
    let open = inv.recent_alerts(50, false).await.unwrap_or_default();
    let servers = inv.list_servers().await.map(|s| s.len()).unwrap_or(0);
    let mut titles = Vec::with_capacity(open.len());
    for a in &open {
        // server_id wins over a `:`-suffix (server alerts can carry a
        // suffix where it's the raw id; we want the country label). The
        // suffix is the subject only for user-scoped alerts.
        let subject = if let Some(sid) = &a.server_id {
            server_subject(inv, sid).await
        } else if let Some((_, suffix)) = a.kind.split_once(':') {
            suffix.to_string()
        } else {
            String::new()
        };
        let payload: serde_json::Value = a
            .payload_json
            .as_deref()
            .and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or(serde_json::Value::Null);
        let r = crate::alert_text::render_alert(&a.kind, &a.severity, &subject, &payload, loc);
        titles.push(format!("{} {}", r.icon, r.title));
    }
    let time_local =
        crate::handlers::admin::format_local_with_pattern(chrono::Utc::now(), "%d.%m %H:%M");
    let text = crate::alert_text::render_digest_html(loc, servers, &titles, &time_local);

    let sink = match build_alert_sink(inv).await {
        Ok(Some(s)) => s,
        Ok(None) => return, // transport not configured — no-op
        Err(e) => {
            tracing::warn!(
                target = "vpnctld::alert_sink",
                error = %e,
                "build_alert_sink failed; skipping digest"
            );
            return;
        }
    };
    if let Err(e) = sink.send_text("digest", "info", &text, true).await {
        tracing::warn!(target = "vpnctld::alert_sink", error = %e, "digest push failed");
    } else {
        tracing::info!(
            target = "vpnctld::alert_sink",
            open = open.len(),
            "sent fleet digest"
        );
    }
}

/// Build the appropriate `AlertSink` from the current
/// `notification_settings` row. Returns `Ok(None)` when the
/// operator hasn't configured a transport (transport is then a
/// no-op — alert still in `admin_alerts` for the pull view). Returns
/// `Err` only on storage-layer failures the caller should log.
///
/// Pulled out as a free fn so both `push_alert` (fire-and-forget)
/// and the synchronous test-send handler share the same construction
/// logic — no risk of the two paths drifting on which server the
/// proxy uses, which proxy env var wins, etc.
pub async fn build_alert_sink(
    inv: &SqliteInventory,
) -> Result<Option<Box<dyn crate::alert_sink::AlertSink>>, vpnctl_inventory::SqliteInventoryError> {
    use crate::alert_sink::TelegramSink;

    let cfg = match inv.get_telegram_config().await? {
        Some(c) if c.is_enabled() => c,
        // Either no row OR not enabled.
        _ => return Ok(None),
    };

    // `is_enabled()` proved both halves Some, but the workspace
    // forbids `expect()` even in this provably-infallible position.
    // Defensive `match` returns Ok(None) in the impossible None arm
    // — equivalent to «transport not configured», which is the
    // operator-visible behaviour we'd want anyway.
    let (token, chat_id) = match (cfg.token, cfg.chat_id) {
        (Some(t), Some(c)) => (t, c),
        _ => return Ok(None),
    };

    // Build the base direct-mode sink first; then chain via-ssh if
    // the operator picked a proxy server.
    let mut sink = match TelegramSink::from_env(token, chat_id) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(
                target = "vpnctld::alert_sink",
                error = %e,
                "TelegramSink construction failed despite is_enabled gate; transport disabled"
            );
            return Ok(None);
        }
    };

    if let Some(server_id_str) = cfg.proxy_via_server_id.as_deref() {
        // Look up the server. Removed-from-inventory case: we log
        // + fall back to direct mode (operator-friendlier than
        // silently disabling — they'll see the «proxy server gone»
        // warning in the journal AND get the message from a working
        // direct path if their network allows; if direct ALSO fails
        // the operator gets the «port 443 timeout» curl error which
        // is the natural next step).
        let server_id = vpnctl_core::ServerId(server_id_str.to_string());
        match inv.list_servers().await {
            Ok(servers) => {
                if let Some(server) = servers.iter().find(|s| s.id == server_id) {
                    let key_path = std::env::var("VPNCTLD_DEPLOY_KEY")
                        .unwrap_or_else(|_| crate::app::DEFAULT_DEPLOY_KEY_PATH.to_string());
                    let ssh = crate::ssh_subprocess::SubprocessSshTransport::new(
                        server.address.clone(),
                        server.ssh_user.clone(),
                        std::path::PathBuf::from(&key_path),
                    )
                    .port(server.ssh_port);
                    sink = sink.with_via_ssh(ssh);
                } else {
                    // Operator explicitly chose proxy_via_server_id;
                    // silently downgrading to direct mode re-enables
                    // the network path they deliberately disabled
                    // (e.g. РФ DPI scenario where api.telegram.org
                    // is blocked from the daemon host). Per migration
                    // 0015's «losing the transport silently is worse
                    // than a loud failure» policy + bug-hunt finding
                    // 2026-05-18 — return None so push becomes a
                    // no-op AND the test-send button surfaces a
                    // clear error to the operator.
                    tracing::warn!(
                        target = "vpnctld::alert_sink",
                        server_id = %server_id_str,
                        "configured proxy_via_server_id no longer in inventory; \
                         transport DISABLED (operator must pick a different proxy \
                         server on /admin/settings or unset the field)"
                    );
                    return Ok(None);
                }
            }
            Err(e) => {
                // Storage-layer failure — propagate, don't silently
                // downgrade. Caller (test-send) will surface 500;
                // production push-loop will log+swallow as before.
                tracing::warn!(
                    target = "vpnctld::alert_sink",
                    error = %e,
                    "list_servers failed while resolving proxy_via_server_id"
                );
                return Err(e);
            }
        }
    }

    Ok(Some(Box::new(sink)))
}

/// Helper: bulk-ack any open (kind, server_id) alerts and write the
/// matching `alert.auto_ack` audit row when the ack actually moved
/// state. Centralises the «ok_with_rows → audit, ok_with_zero →
/// silent, err → warn-and-swallow» policy across every detector
/// recovery path in [`dispatch_alerts`].
///
/// Returns nothing — all errors fold into trace/warn logs because
/// the caller's tick loop must continue regardless of audit-write
/// failures (an audit failure should not block the next server's
/// probe).
async fn auto_ack(inv: &SqliteInventory, server_id: &ServerId, kind: &str, reason: &str) {
    match inv.ack_open_alerts(kind, Some(server_id)).await {
        Ok(0) => {} // no open row — nothing to log
        Ok(n) => {
            if let Err(e) = inv
                .audit(
                    "vpnctld",
                    "alert.auto_ack",
                    Some(&server_id.0),
                    Some(&serde_json::json!({
                        "kind": kind,
                        "rows_acked": n,
                        "reason": reason,
                    })),
                )
                .await
            {
                tracing::warn!(
                    target = "vpnctld::node_probe",
                    kind = kind,
                    server = %server_id.0,
                    error = %e,
                    "audit for alert.auto_ack failed"
                );
            }
        }
        Err(e) => tracing::warn!(
            target = "vpnctld::node_probe",
            kind = kind,
            server = %server_id.0,
            error = %e,
            "ack_open_alerts failed"
        ),
    }
}

/// Probe one server, insert the row, and return a [`ProbeOutcome`]
/// so the caller's `FailState` can drive the `server.unreachable`
/// detector. Pure side-effect, never panics. Every error is logged
/// at warn-or-info and folded into the outcome enum (callers don't
/// need to re-check Result variants).
async fn probe_one_server(inv: &SqliteInventory, server: &vpnctl_core::Server) -> ProbeOutcome {
    // Skip non-sing-box kernels for now via the centralised filter
    // (see `probeable` doc-comment for the AmneziaWG TODO). Once-per-
    // tick info log so the operator can grep + spot the no-op state
    // when a new kernel lands without probe support — debug is too
    // quiet (invisible by default).
    if !probeable(server) {
        tracing::info!(
            target = "vpnctld::node_probe",
            server = %server.id.0,
            kernels = ?server.kernels.iter().map(|k| k.0.as_str()).collect::<Vec<_>>(),
            "skipping probe — no probe-able kernel (today: sing-box only)"
        );
        return ProbeOutcome::Skipped;
    }

    let key_path = std::env::var("VPNCTLD_DEPLOY_KEY")
        .unwrap_or_else(|_| "/var/lib/vpnctl/.ssh/id_ed25519".to_string());
    if !std::path::Path::new(&key_path).exists() {
        // Pre-deploy: same as clash_poller, log once per tick at info
        // (operator can grep) without spamming at warn.
        tracing::info!(
            target = "vpnctld::node_probe",
            server = %server.id.0,
            key = %key_path,
            "skipping: deploy SSH key not yet on the homelab host"
        );
        return ProbeOutcome::NoDeployKey;
    }

    let ssh = crate::ssh_subprocess::SubprocessSshTransport::new(
        server.address.clone(),
        server.ssh_user.clone(),
        std::path::PathBuf::from(&key_path),
    )
    .port(server.ssh_port);

    use crate::node_probe::{ProbeClient, SshProbeClient};
    let client = SshProbeClient::new(&ssh);
    let probe = match client.snapshot().await {
        Ok(p) => p,
        Err(e) => {
            let msg = e.to_string();
            tracing::warn!(
                target = "vpnctld::node_probe",
                server = %server.id.0,
                error = %msg,
                "probe snapshot failed"
            );
            return ProbeOutcome::SshFailed(msg);
        }
    };

    // Serialise the sorted (proto, port) set as a JSON array of
    // "proto/port" strings — matches `0007_node_health.sql` schema
    // doc-comment.
    let listening_json: Option<String> = if probe.listening.is_empty() {
        None
    } else {
        let v: Vec<String> = probe
            .listening
            .iter()
            .map(|(proto, port)| format!("{proto}/{port}"))
            .collect();
        serde_json::to_string(&v).ok()
    };

    // PR-Q — serialise the on-node kernel versions as a JSON object
    // (BTreeMap → deterministic key order). NULL when empty (old node /
    // partial-probe tick) rather than `{}`.
    let kernel_versions_json: Option<String> = if probe.kernel_versions.is_empty() {
        None
    } else {
        serde_json::to_string(&probe.kernel_versions).ok()
    };

    let res = inv
        .record_node_health(
            &server.id,
            probe.sing_box_active,
            probe.fail2ban_active,
            probe.disk_used_mib,
            probe.disk_total_mib,
            probe.mem_available_mib,
            probe.mem_total_mib,
            probe.load_1min_x100,
            listening_json.as_deref(),
            probe.sing_box_log_bytes,
            kernel_versions_json.as_deref(),
            probe.nic_iface.as_deref(),
            probe.nic_rx_bytes,
            probe.nic_tx_bytes,
        )
        .await;

    match res {
        Ok(()) => {
            tracing::info!(
                target = "vpnctld::node_probe",
                server = %server.id.0,
                sing_box = ?probe.sing_box_active,
                disk_pct = ?probe.disk_pct(),
                "node_health row persisted"
            );
            ProbeOutcome::Ok(probe)
        }
        Err(e) => {
            tracing::warn!(
                target = "vpnctld::node_probe",
                server = %server.id.0,
                error = %e,
                "record_node_health failed"
            );
            ProbeOutcome::RowWriteFailed
        }
    }
}

/// Convenience: cumulative "expire" pass over `node_health` rows
/// older than `days`. Wired into the existing retention scheduler in
/// `daemon::app::spawn_retention_purger`. Pure delegate; lives here
/// rather than inline in `app.rs` so the whole node-probe surface
/// (probe + poller + purge) stays in one place.
///
/// Returns the inventory crate's own `Result` so callers don't have
/// to import `sqlx` directly (vpnctld doesn't pull sqlx as a direct
/// dep — only the inventory crate does).
pub async fn purge_old(
    inv: &SqliteInventory,
    days: u32,
) -> std::result::Result<u64, vpnctl_inventory::SqliteInventoryError> {
    inv.purge_node_health_older_than(days).await
}

// ─── Tests ──────────────────────────────────────────────────────────
//
// Unit tests here cover the helpers that don't need a tokio runtime.
// The integration with the scheduler is covered by
// `daemon/tests/admin_smoke.rs::node_probe_poller_spawns_a_runnable_task`
// (added by the same commit that wires this into `app.rs`).

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// `purge_old` is a thin pass-through; this test asserts the
    /// signature compiles and returns `Ok(0)` on a fresh tempdir
    /// inventory (no rows = nothing to drop).
    #[tokio::test]
    async fn purge_old_on_empty_inv_returns_zero() {
        let tmp = tempfile::tempdir().unwrap();
        let inv = SqliteInventory::open(&tmp.path().join("inv.db"))
            .await
            .unwrap();
        let dropped = purge_old(&inv, 30).await.unwrap();
        assert_eq!(dropped, 0);
    }

    // ─── FailState consecutive-failure detector ──────────────

    fn sid(s: &str) -> ServerId {
        ServerId(s.into())
    }

    fn ok_probe() -> ProbeOutcome {
        ProbeOutcome::Ok(crate::node_probe::Probe::default())
    }
    fn ssh_fail() -> ProbeOutcome {
        ProbeOutcome::SshFailed("boom".into())
    }

    #[test]
    fn fail_state_below_threshold_emits_no_change() {
        let mut st = FailState::with_threshold(3);
        assert_eq!(
            st.observe(&sid("a"), &ssh_fail()),
            UnreachableTransition::NoChange
        );
        assert_eq!(
            st.observe(&sid("a"), &ssh_fail()),
            UnreachableTransition::NoChange,
            "still below threshold"
        );
    }

    #[test]
    fn fail_state_at_threshold_emits_became_unreachable_once() {
        let mut st = FailState::with_threshold(3);
        st.observe(&sid("a"), &ssh_fail());
        st.observe(&sid("a"), &ssh_fail());
        let third = st.observe(&sid("a"), &ssh_fail());
        assert_eq!(
            third,
            UnreachableTransition::BecameUnreachable {
                consecutive_failures: 3,
                threshold: 3,
            }
        );
        // Fourth tick still failing — must NOT re-emit BecameUnreachable
        // (that's a one-time edge), but now emits StillUnreachable so the
        // caller re-asserts the idempotent insert — re-opening the alert
        // if the operator acked it while the server is still down.
        assert_eq!(
            st.observe(&sid("a"), &ssh_fail()),
            UnreachableTransition::StillUnreachable {
                consecutive_failures: 4,
                threshold: 3,
            },
            "already-fired + still-failing must emit StillUnreachable, not BecameUnreachable"
        );
    }

    #[test]
    fn fail_state_recovers_after_fire() {
        let mut st = FailState::with_threshold(2);
        st.observe(&sid("a"), &ssh_fail());
        st.observe(&sid("a"), &ssh_fail());
        // Now a success.
        assert_eq!(
            st.observe(&sid("a"), &ok_probe()),
            UnreachableTransition::Recovered
        );
        // Further successes are no-change.
        assert_eq!(
            st.observe(&sid("a"), &ok_probe()),
            UnreachableTransition::NoChange
        );
    }

    #[test]
    fn fail_state_subthreshold_recovery_does_not_fire_or_ack() {
        // Counter at 1 (threshold 3) → recovery → NoChange because
        // the operator never saw a fire-alert; nothing to ack.
        let mut st = FailState::with_threshold(3);
        st.observe(&sid("a"), &ssh_fail());
        assert_eq!(
            st.observe(&sid("a"), &ok_probe()),
            UnreachableTransition::NoChange
        );
    }

    #[test]
    fn fail_state_isolates_per_server() {
        let mut st = FailState::with_threshold(2);
        // Fail A twice → fire.
        st.observe(&sid("a"), &ssh_fail());
        assert_eq!(
            st.observe(&sid("a"), &ssh_fail()),
            UnreachableTransition::BecameUnreachable {
                consecutive_failures: 2,
                threshold: 2,
            }
        );
        // B is independent; one failure doesn't fire.
        assert_eq!(
            st.observe(&sid("b"), &ssh_fail()),
            UnreachableTransition::NoChange
        );
        // B success doesn't ack A's open alert.
        assert_eq!(
            st.observe(&sid("b"), &ok_probe()),
            UnreachableTransition::NoChange
        );
    }

    #[test]
    fn fail_state_skipped_and_no_key_do_not_count() {
        let mut st = FailState::with_threshold(2);
        st.observe(&sid("a"), &ssh_fail());
        // Skipped tick (e.g. kernel changed mid-poll) does NOT
        // increment the counter, but also does NOT reset it.
        assert_eq!(
            st.observe(&sid("a"), &ProbeOutcome::Skipped),
            UnreachableTransition::NoChange
        );
        assert_eq!(
            st.observe(&sid("a"), &ProbeOutcome::NoDeployKey),
            UnreachableTransition::NoChange
        );
        // The next failure crosses the threshold.
        assert_eq!(
            st.observe(&sid("a"), &ssh_fail()),
            UnreachableTransition::BecameUnreachable {
                consecutive_failures: 2,
                threshold: 2,
            }
        );
    }

    #[test]
    fn fail_state_full_fire_recover_refire_cycle() {
        // Regression for: «forgot to reset counter on recovery» and
        // «forgot to reset fired flag on recovery». Either bug leaves
        // the second fire stuck: variant b — counter stays at the
        // post-fire value, next failure jumps straight back over
        // threshold but `fired` is still true so no event; variant c
        // — counter resets but `fired` stays true, never re-fires.
        // The 1-tick assertions in fail_state_recovers_after_fire
        // don't catch either; only this full cycle does.
        let mut st = FailState::with_threshold(2);
        // Fire #1.
        st.observe(&sid("a"), &ssh_fail());
        assert!(matches!(
            st.observe(&sid("a"), &ssh_fail()),
            UnreachableTransition::BecameUnreachable { .. }
        ));
        // Recover (acks the open alert).
        assert_eq!(
            st.observe(&sid("a"), &ok_probe()),
            UnreachableTransition::Recovered
        );
        // Re-fire: two more failures must produce a SECOND
        // BecameUnreachable with counter=2 (NOT 3 or 4 — counter
        // was reset).
        st.observe(&sid("a"), &ssh_fail());
        let second = st.observe(&sid("a"), &ssh_fail());
        assert_eq!(
            second,
            UnreachableTransition::BecameUnreachable {
                consecutive_failures: 2,
                threshold: 2,
            },
            "post-recovery re-fire must emit BecameUnreachable again"
        );
    }

    #[test]
    fn fail_state_zero_threshold_clamps_to_one() {
        // Zero would mean "fire on every failure" — operator-hostile.
        let mut st = FailState::with_threshold(0);
        assert_eq!(
            st.observe(&sid("a"), &ssh_fail()),
            UnreachableTransition::BecameUnreachable {
                consecutive_failures: 1,
                threshold: 1,
            }
        );
    }

    /// Sanity: serializing the listening-ports set to JSON matches
    /// the on-disk format documented in `0007_node_health.sql`
    /// (sorted JSON array of `"proto/port"` strings).
    #[test]
    fn listening_ports_json_round_trip() {
        let mut s: BTreeSet<(String, u16)> = BTreeSet::new();
        s.insert(("tcp".into(), 443));
        s.insert(("udp".into(), 8443));
        s.insert(("tcp".into(), 22));
        let v: Vec<String> = s.iter().map(|(p, n)| format!("{p}/{n}")).collect();
        let json = serde_json::to_string(&v).unwrap();
        // BTreeSet sorts by (proto, port) lex: tcp/22 < tcp/443 < udp/8443.
        assert_eq!(json, r#"["tcp/22","tcp/443","udp/8443"]"#);
    }
}
