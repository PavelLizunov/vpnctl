-- Track-3 chunk 2: persistent rolling buffer of clash-api snapshots.
--
-- One row per (snapshot, server, user) — records the DELTA in bytes
-- since the prior snapshot from that server, plus the active connection
-- count observed at snapshot time. Server-wide rows (no specific user)
-- carry user_id = NULL.
--
-- Why store deltas instead of totals: the totals reset to 0 every time
-- sing-box restarts on the node (counters live in-process). Storing
-- deltas means the read side can sum across an arbitrary time window
-- without needing to detect restart boundaries.
--
-- The poller (daemon::clash_poller, chunk 2) computes deltas in-memory
-- and only writes when the delta is non-zero — quiet nodes don't bloat
-- the table.
--
-- Retention: the existing access-log retention task (`spawn_retention_purger`
-- in `daemon::app`) will gain a parallel sweep on this table in a
-- follow-up. For now growth is bounded by N_servers × N_users × ticks/h
-- × hours_kept; at homelab scale (~5 servers, ~10 users, 60-tick/h, 30
-- days) that's ~2M rows max — comfortably indexed.

CREATE TABLE IF NOT EXISTS vpn_connection_stats (
    -- Wall-clock when the poller wrote this row. ISO-8601 with
    -- millisecond precision, same format as sub_access_log.ts so the
    -- bucketing helpers can be reused.
    ts TEXT NOT NULL,

    -- Server the snapshot was pulled from. CASCADE: dropping a server
    -- drops its history (consistent with how grants behave).
    server_id TEXT NOT NULL
        REFERENCES servers(id) ON DELETE CASCADE,

    -- Per-user attribution. NULL = server-wide totals (unattributed
    -- traffic + sum across all users). Non-NULL strings DO NOT have a
    -- FK to `users(id)` — clash-api may report a user name that no
    -- longer exists in our inventory (operator deleted the user since
    -- the last poll), and we'd rather keep the row visible in audit
    -- than CASCADE-drop it. Forensics survive renames.
    user_id TEXT,

    -- Bytes UPLOADED by clients in this interval (snapshot.upload -
    -- prior_snapshot.upload). Always >= 0 — restarts are detected by
    -- the poller and emitted as a fresh interval starting from the
    -- new total, not as a negative delta.
    upload_bytes INTEGER NOT NULL DEFAULT 0,
    download_bytes INTEGER NOT NULL DEFAULT 0,

    -- Number of active connections (matching the user, or all
    -- connections for server-wide rows). Snapshot value, NOT a delta.
    active_connections INTEGER NOT NULL DEFAULT 0
);

-- Per-user history lookup, ordered newest-first. Matches the access-log
-- index pattern.
CREATE INDEX IF NOT EXISTS idx_vcs_user_ts
    ON vpn_connection_stats(user_id, ts DESC);

-- Per-server history (dashboard server-detail will read this for
-- bandwidth sparklines).
CREATE INDEX IF NOT EXISTS idx_vcs_server_ts
    ON vpn_connection_stats(server_id, ts DESC);
