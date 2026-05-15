//! Bounded back-pressure for `/sub/<token>` access logging.
//!
//! Why this exists
//! ---------------
//! Phase Track-1 first wired the access log via `tokio::spawn` per
//! request — fire-and-forget, no concurrency cap. Both the retroactive
//! review-agent (review #3) and security-review (security #2)
//! independently flagged the same DoS surface: an attacker holding ONE
//! valid sub-token can hit `/sub/<token>` in a tight loop, each hit
//! spawns a background task, the SQLite pool saturates, the task
//! queue grows unbounded — eventually OOM.
//!
//! This module replaces the spawn-per-request pattern with:
//!   1. A bounded `tokio::sync::mpsc` channel sized at
//!      `ACCESS_LOG_CHANNEL_CAP` records (default 1024).
//!   2. ONE dedicated writer task that drains the channel sequentially
//!      and calls `inv.log_sub_access(...)` per record.
//!   3. The `/sub` handler does `try_send` (non-blocking) — full
//!      channel → drop the record + warn-log (back-pressure signal).
//!      The HTTP response is unaffected (still 200).
//!
//! Lifecycle
//! ---------
//! `AppState` owns the `Sender`. Cloning `AppState` (which axum does
//! per-request via `with_state`) clones the sender — channel stays
//! open as long as ANY clone of the state lives. When the runtime
//! shuts down (graceful shutdown drops the router + state), all
//! senders drop, the receiver sees `None`, the writer task drains
//! pending records and exits.
//!
//! Why a dedicated writer instead of N spawn-per-request
//! -----------------------------------------------------
//! The SQLite pool is small (8 connections); per-request spawn already
//! serialised at that bottleneck. The dedicated writer makes the
//! serialisation explicit AND bounds the in-memory queue, which is
//! what the spawn model lacked.

use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use vpnctl_core::UserId;
use vpnctl_inventory::SqliteInventory;

/// Channel capacity. 1024 records is plenty: at ~150 bytes per record
/// (UserId String + IP String + UA String + ints) the queue caps at
/// ~150 KiB. Even on a flooded daemon the writer task drains at SQLite-
/// INSERT speed (sub-millisecond on WAL), so the queue rarely fills
/// past single digits in practice. The bound exists so a pathological
/// burst can't OOM the process before the operator notices the abuse
/// signal.
pub const ACCESS_LOG_CHANNEL_CAP: usize = 1024;

/// One subscription-fetch record en route to `sub_access_log`. The
/// `/sub` handler builds this and sends it; the writer task drains
/// and persists it.
#[derive(Debug, Clone)]
pub struct AccessLogRecord {
    pub user_id: UserId,
    pub ip: String,
    pub ua: Option<String>,
    pub status: u16,
    pub bytes: u64,
}

/// Spin up the writer task. Returns the channel sender (handed to
/// `AppState` so handlers can `try_send`) plus the `JoinHandle` (so
/// `build()` can keep it alive for the process lifetime, and tests
/// can `abort()` it deterministically).
///
/// The writer loop terminates ONLY when all senders drop — that's the
/// graceful-shutdown signal. There is no explicit cancellation token
/// because the `mpsc::Receiver::recv()` returning `None` is the
/// canonical "channel closed" check; adding a token would just be a
/// second source of truth that could disagree.
pub fn spawn_writer(inv: SqliteInventory) -> (mpsc::Sender<AccessLogRecord>, JoinHandle<()>) {
    let (tx, rx) = mpsc::channel::<AccessLogRecord>(ACCESS_LOG_CHANNEL_CAP);
    let handle = tokio::spawn(run_writer(inv, rx));
    (tx, handle)
}

/// Drain the channel forever (until all senders drop). Each record is
/// persisted via `log_sub_access`; failures log a warn but never abort
/// the loop — losing one row is preferable to losing the whole
/// abuse-detection feature because of a transient SQLite hiccup.
async fn run_writer(inv: SqliteInventory, mut rx: mpsc::Receiver<AccessLogRecord>) {
    while let Some(rec) = rx.recv().await {
        if let Err(e) = inv
            .log_sub_access(
                &rec.user_id,
                &rec.ip,
                rec.ua.as_deref(),
                rec.status,
                rec.bytes,
            )
            .await
        {
            tracing::warn!(
                target = "vpnctld::access_log_writer",
                user = %rec.user_id,
                ip = %rec.ip,
                error = %e,
                "log_sub_access write failed (record dropped)"
            );
        }
    }
    tracing::info!(
        target = "vpnctld::access_log_writer",
        "channel closed, writer exiting cleanly"
    );
}

/// Helper used by the `/sub` handler: try to enqueue a record without
/// blocking. Channel-full → log a `warn` (the back-pressure signal —
/// operator should investigate why the writer is falling behind) and
/// drop the record; channel-closed → log an `error` (writer task
/// crashed, which shouldn't happen).
///
/// Returns `true` if the record was enqueued, `false` if dropped.
/// Callers don't normally check the return — the response is 200
/// either way; this is purely a logging-completeness signal.
pub fn try_enqueue(tx: &mpsc::Sender<AccessLogRecord>, rec: AccessLogRecord) -> bool {
    use tokio::sync::mpsc::error::TrySendError;
    match tx.try_send(rec) {
        Ok(()) => true,
        Err(TrySendError::Full(rec)) => {
            tracing::warn!(
                target = "vpnctld::sub",
                user = %rec.user_id,
                ip = %rec.ip,
                cap = ACCESS_LOG_CHANNEL_CAP,
                "access log channel full ({} records), dropping row (back-pressure trigger)",
                ACCESS_LOG_CHANNEL_CAP
            );
            false
        }
        Err(TrySendError::Closed(rec)) => {
            tracing::error!(
                target = "vpnctld::sub",
                user = %rec.user_id,
                ip = %rec.ip,
                "access log channel closed unexpectedly — writer task exited; row lost"
            );
            false
        }
    }
}
