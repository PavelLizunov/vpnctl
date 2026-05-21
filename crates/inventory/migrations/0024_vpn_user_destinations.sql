-- Phase 5b — per-user × destination tracking.
--
-- Pavel: «куда ходит alice — youtube/discord/telegram?». The
-- snapshot + Phase 4d attribution already give us per-(user,
-- destination_label) data at the live-tick level; this table
-- accumulates the FACT of those visits so we can render a
-- «top destinations» list on /admin/users/<id> without scraping
-- the snapshot history (which doesn't exist — snapshots are
-- in-memory replaced every 5 min).
--
-- Granularity: per-(user_id, destination_label, date). One row
-- per day per (user, destination). hit_count is incremented at
-- every clash-poll tick where the user has at least one
-- connection to that destination; last_seen tracks the freshest
-- tick within the day.
--
-- We intentionally DO NOT track byte counts per (user, dest)
-- here — that would need diff-engine state per (user, dest,
-- conn_id) tuples to avoid double-counting across ticks, which
-- explodes complexity. Per-user byte totals live in `vpn_user_daily`
-- (which agregates from `vpn_connection_stats`); this table
-- answers «куда» not «сколько».
--
-- Destination label is the resolved form: `host:port` when
-- sing-box gave us the SNI/Host (or DNS PTR cache filled it
-- post-5a-2), or `IP:port` otherwise. Truncated to 200 chars to
-- bound row size for pathological hostnames.
--
-- Retention: 30 days rolling, swept by the existing hourly
-- retention task.

CREATE TABLE vpn_user_destinations (
    id                          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id                     TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- Resolved destination label: `host:port`, `host:port (ip)`,
    -- or `ip:port`. Truncated to 200 chars in the writer.
    destination_label           TEXT    NOT NULL,
    -- UTC date `YYYY-MM-DD` for daily slicing.
    date                        TEXT    NOT NULL,
    -- Number of clash-poll ticks during the day where this
    -- (user, destination) pair was observed. NOT a connection
    -- count — a single long-lived connection across multiple
    -- ticks contributes N hits, where N = ticks-it-was-alive.
    hit_count                   INTEGER NOT NULL DEFAULT 1,
    -- Most recent tick ts where the pair was observed.
    last_seen                   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),

    UNIQUE (user_id, destination_label, date)
);

-- Query: «top destinations for this user over the last 7 days».
-- Used by the user-detail Phase 5b section.
CREATE INDEX idx_vpn_user_destinations_user_date
    ON vpn_user_destinations (user_id, date DESC, hit_count DESC);
