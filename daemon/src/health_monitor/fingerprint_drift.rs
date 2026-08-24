use vpnctl_inventory::SqliteInventory;

/// Per-tick scan for `server.fingerprint.drift`. For each server with
/// a pinned `trusted_host_fingerprint`, fetches ALL the host keys the
/// server currently serves (`fetch_all_fingerprints`) and fires a
/// `warning`-severity alert — with `{previous, observed_keys}` payload
/// + Telegram push — only when the pinned key is no longer among them.
///
/// **Membership, not single-key equality + retry (post-kg 2026-06-06).**
/// A naive «picked key == pin» compare false-fired when a single
/// `ssh-keyscan` returned only a SUBSET of the keys (a per-algorithm
/// probe dropped under packet loss) and the dropped one was the pinned
/// key type. Asking «is the pin still AMONG the served keys?» plus a
/// short retry (a real change is absent from EVERY scan; a transient
/// incomplete scan recovers within a retry) removes the false positive
/// while preserving genuine rotation / MITM detection.
///
/// **Why warning, not critical:** legitimate SSH host-key rotation
/// is a normal operator workflow (kernel upgrade, distro reinstall,
/// VPS provider migration). The drift could also be an active MITM
/// — equally bad — but the alert can't tell the difference. Operator
/// triages, ack-and-rotate via the existing /admin/servers/{id}
/// set-fingerprint form OR ignores if expected.
///
/// **Servers without a pinned fingerprint are skipped** — there's
/// nothing to compare against; first-time pin goes through the
/// wizard's TOFU path or the operator's explicit «auto via ssh-
/// keyscan» button.
///
/// **Servers behind a ProxyJump are skipped** — `ssh-keyscan` makes
/// a direct TCP connection and doesn't honour ssh_config's
/// ProxyJump rules. Pinning those servers' fingerprints today
/// happens via the operator manually proxying; the daemon's drift
/// check stays silent rather than emit false-positive «unreachable»
/// alerts for jump-only hosts. Future work: route through
/// `ssh_subprocess` with the same ProxyJump config the probe uses.
///
/// **Cadence:** runs on every `scan_once` tick (10 min default).
/// `ssh-keyscan` on 3 servers takes < 1 second total; not worth
/// a separate cron.
pub async fn check_fingerprint_drift(
    inv: &SqliteInventory,
    servers: &[vpnctl_core::Server],
) -> Result<(), vpnctl_inventory::SqliteInventoryError> {
    for server in servers {
        // Skip if no pin to compare against.
        let Some(pinned) = server.trusted_host_fingerprint.as_deref() else {
            continue;
        };
        // Skip ProxyJump targets — see doc-comment.
        if server.jump_via.is_some() {
            continue;
        }
        // Skip if address is malformed enough that ssh-keyscan
        // would obviously fail. (Defensive — keeps the log clean.)
        if server.address.is_empty() {
            continue;
        }
        // Robust drift detection (post-kg 2026-06-06): fetch ALL of
        // the server's host keys and ask «is the pinned key still
        // among them?» rather than comparing one picked key against
        // the pin. A single `ssh-keyscan` can return only a SUBSET of
        // the keys under packet loss; if the dropped one happens to be
        // the pinned key type, a naive single-key compare false-fires.
        // We retry a few times and let `decide_drift` rule: a real key
        // change is absent from EVERY scan, while a transient
        // incomplete scan recovers within a retry. Worst case for a
        // genuinely-drifted or unreachable server is ~3 keyscans + 2
        // backoff sleeps serially on this tick — fine for a handful of
        // servers; revisit (concurrency / cap) if the fleet grows.
        let kind = format!("server.fingerprint.drift:{}", server.id.0);
        const DRIFT_SCAN_ATTEMPTS: usize = 3;
        let mut attempts: Vec<Option<Vec<String>>> = Vec::with_capacity(DRIFT_SCAN_ATTEMPTS);
        for attempt in 0..DRIFT_SCAN_ATTEMPTS {
            if attempt > 0 {
                // Brief backoff between retries — a transient
                // per-algorithm probe drop clears in seconds. Off the
                // hot path: only servers whose pin didn't match the
                // first scan ever reach a second attempt.
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
            let addr = server.address.clone();
            let port = server.ssh_port;
            // ssh-keyscan is sync (shells out); spawn_blocking keeps
            // it off the tokio scheduler.
            let scanned = match tokio::task::spawn_blocking(move || {
                vpnctl_host_fingerprint::fetch_all_fingerprints(&addr, port)
            })
            .await
            {
                Ok(Ok(observed)) => Some(observed),
                Ok(Err(e)) => {
                    tracing::debug!(
                        target = "vpnctld::health_monitor",
                        server = %server.id.0,
                        error = %e,
                        "ssh-keyscan failed during fingerprint drift check; will retry"
                    );
                    None
                }
                Err(e) => {
                    tracing::warn!(
                        target = "vpnctld::health_monitor",
                        server = %server.id.0,
                        error = %e,
                        "spawn_blocking for ssh-keyscan failed"
                    );
                    None
                }
            };
            // Early exit: the pinned key is already served — no need to
            // spend the remaining attempts. Keeps the healthy-server
            // common case at one keyscan per tick, as before.
            let satisfied = scanned
                .as_ref()
                .is_some_and(|keys| pin_is_present(pinned, keys));
            attempts.push(scanned);
            if satisfied {
                break;
            }
        }
        let observed = match decide_drift(pinned, &attempts) {
            DriftDecision::Matched => {
                // Auto-recovery: the pinned key is still served. If an
                // operator accepted a new key via the web UI, or it
                // «recovered» on its own (key rotated back), close any
                // open drift alert. Silent ack (no `*.recovered` info
                // alert) — the audit_log keeps the timeline.
                match inv.ack_open_alerts(&kind, Some(&server.id)).await {
                    Ok(0) => {} // No open alert; nothing to recover.
                    Ok(n) => {
                        tracing::info!(
                            target = "vpnctld::health_monitor",
                            server = %server.id.0,
                            acked = n,
                            "auto-recovered server.fingerprint.drift — pinned key still served"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            target = "vpnctld::health_monitor",
                            server = %server.id.0,
                            error = %e,
                            "auto-recovery ack failed for server.fingerprint.drift"
                        );
                    }
                }
                continue; // No drift, no fire.
            }
            // No scan succeeded at all — can't tell drift from an
            // outage. Stay silent and try again next tick (same posture
            // as the old per-scan error `continue`).
            DriftDecision::Inconclusive => continue,
            // Pinned key absent from every successful scan → real drift.
            DriftDecision::Drift { observed } => observed,
        };
        let summary = format!(
            "host fingerprint for {} differs from pinned value — either legitimate SSH key rotation OR active MITM",
            server.id.0
        );
        let payload = serde_json::json!({
            "server_id": server.id.0,
            "previous": pinned,
            "observed_keys": observed,
            "ssh_user": server.ssh_user,
            "ssh_port": server.ssh_port,
            "ip": server.address,
        });
        let payload_str = serde_json::to_string(&payload).unwrap_or_else(|_| "{}".to_string());
        let subject = crate::node_probe_poller::server_subject(inv, &server.id).await;
        match inv
            .insert_alert_if_no_unacked(
                &kind,
                Some(&server.id),
                "warning",
                &summary,
                Some(&payload_str),
            )
            .await
        {
            Ok(Some(alert_id)) => {
                tracing::warn!(
                    target = "vpnctld::health_monitor",
                    alert_id,
                    server = %server.id.0,
                    "fired server.fingerprint.drift alert"
                );
                if let Err(e) = inv
                    .audit(
                        "vpnctld",
                        "alert.fire",
                        Some(&server.id.0),
                        Some(&serde_json::json!({
                            "alert_id": alert_id,
                            "kind": kind,
                            "severity": "warning",
                            "summary": summary,
                        })),
                    )
                    .await
                {
                    tracing::warn!(
                        target = "vpnctld::health_monitor",
                        alert_id,
                        server = %server.id.0,
                        error = %e,
                        "alert.fire audit row failed for server.fingerprint.drift"
                    );
                }
                crate::node_probe_poller::push_alert(
                    inv,
                    &kind,
                    "warning",
                    &subject,
                    &payload,
                    Some(alert_id),
                )
                .await;
            }
            Ok(None) => {
                // Already-open drift alert for this server. The
                // operator hasn't triaged yet; no point spamming
                // the same alert every 10 min.
            }
            Err(e) => {
                tracing::warn!(
                    target = "vpnctld::health_monitor",
                    server = %server.id.0,
                    error = %e,
                    "insert server.fingerprint.drift alert failed"
                );
            }
        }
    }
    Ok(())
}

/// True if the pinned fingerprint is among the set of fingerprints the
/// server currently serves. The drift check fires only when this is
/// false — i.e. the pinned key is no longer one of the host's keys.
/// Robust to a single `ssh-keyscan` returning a different key TYPE
/// than the one originally pinned (the `kg` 2026-06-06 false positive:
/// a scan that returned only the rsa key tripped a drift against the
/// ed25519 pin).
pub(crate) fn pin_is_present(pinned: &str, observed: &[String]) -> bool {
    observed.iter().any(|fp| fp.as_str() == pinned)
}

/// Outcome of evaluating one server's host-key scans against its pin.
#[derive(Debug, PartialEq)]
pub(crate) enum DriftDecision {
    /// At least one scan returned the pinned key — trust intact. The
    /// caller auto-recovers (acks) any open drift alert.
    Matched,
    /// Every successful scan agreed the pinned key is gone → genuine
    /// drift (rotation or MITM). `observed` is the union of all keys
    /// seen across the scans, for the alert payload.
    Drift { observed: Vec<String> },
    /// No scan succeeded at all — host unreachable / keyscan failed on
    /// every attempt. Can't distinguish drift from an outage, so the
    /// caller stays silent this tick.
    Inconclusive,
}

/// Decide whether a server's host key has drifted, given the results
/// of one-or-more `ssh-keyscan` attempts. Each element is `Some(keys)`
/// for a successful scan (the SHA256 fingerprints the host served) or
/// `None` for a failed attempt.
///
/// Rules:
///   * pin present in ANY successful scan         → [`DriftDecision::Matched`]
///   * pin absent from every successful scan,
///     and ≥1 scan succeeded                      → [`DriftDecision::Drift`]
///   * no scan succeeded                           → [`DriftDecision::Inconclusive`]
///
/// Pure (no I/O) so the false-positive contract — a transient scan
/// that omits the pinned key type must NOT fire once a later scan
/// returns it — is unit-testable without a live SSH daemon. `observed`
/// in the `Drift` arm is the de-duplicated union across scans (so the
/// payload reflects every key seen, not just the last partial scan).
pub(crate) fn decide_drift(pinned: &str, attempts: &[Option<Vec<String>>]) -> DriftDecision {
    let mut any_success = false;
    let mut observed: Vec<String> = Vec::new();
    for keys in attempts.iter().flatten() {
        any_success = true;
        if pin_is_present(pinned, keys) {
            return DriftDecision::Matched;
        }
        for k in keys {
            if !observed.contains(k) {
                observed.push(k.clone());
            }
        }
    }
    if any_success {
        DriftDecision::Drift { observed }
    } else {
        DriftDecision::Inconclusive
    }
}
