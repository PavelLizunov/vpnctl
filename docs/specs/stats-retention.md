# Contract: traffic rollups and retention

## Intent and invariants

- At daemon start the retention task rolls up every UTC day still represented
  in raw VPN ticks (`catch_up_vpn_daily_rollups`), completing partial and
  missing daily rollups after multi-day downtime. The hourly purge then rolls
  up only the days it is about to delete, so it never re-aggregates the whole
  retained history under the write lock.
- Rollup and raw deletion share one `BEGIN IMMEDIATE` transaction. A failed
  rollup leaves raw history intact. Raw retention removes only complete UTC
  days before midnight of the cutoff date; it never truncates a retained day.
  Previously stored totals never shrink if legacy retention trimmed their day.
  `purge_vpn_stats_older_than(0)` therefore keeps today's ticks.
- Session retention uses `last_seen`, not `started_at`. Sessions observed within
  the poller's 15-minute continuity gap survive even a zero-day cleanup.
- Last activity survives deletion of subscription logs, active VPN ticks and
  sessions. Zero-byte, zero-connection ticks and unattributed traffic do not
  count. A persisted timestamp never moves backwards.

## Interface and data contract

- Existing method signatures remain unchanged. `u32::MAX` selects all retained
  history for `recent_vpn_stats_for_user`, `recent_vpn_stats_fleet` and
  `top_users_by_daily_traffic`; other windows retain their existing behavior.
- The user's all-history read combines raw ticks with daily totals for days
  without raw ticks on that user/server, avoiding double counting. Fleet charts
  use indefinitely retained hourly totals. The UI's `all` window expands its
  monthly buckets to include the oldest retained record.
- Migration 0062 adds global range indexes for the five cleanup predicates not
  covered by existing server/user-leading indexes: node health `ts`, quality
  samples `ts`, destination `date`, source-IP `date`, session `last_seen`.
- Migration 0063 adds `users.last_activity_at`, backfills retained activity and
  preserves exact timestamps before source-row deletion. Legacy daily-only
  activity is known to UTC-day precision and uses midnight of that day.
  Actual timestamp advances, changed rollups and nonempty VPN/session purges
  are audited; repeating a no-op does not create audit rows.
- These changes cannot recover raw history already lost before the fix.

## Verification checklist

- Multi-day downtime repairs both partial and absent daily totals before purge;
  repeated cleanup and rerolling a purged day preserve totals.
- Injected rollup failure retains raw rows and leaves audit unchanged.
- All-history user/fleet reads include old rollups; raw/daily overlap is counted
  once and bounded reads remain bounded. Charts include their oldest bucket.
- Long-running active sessions survive cleanup and keep their identity.
- Last activity survives independent source purges; quiet/fresh users stay unused,
  and older deletions neither regress timestamps nor add no-op audit rows.
- `EXPLAIN QUERY PLAN` searches retention indexes for each telemetry cleanup.
