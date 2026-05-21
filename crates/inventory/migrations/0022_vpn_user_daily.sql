-- Phase 5a-1 — daily per-user traffic rollups for long-term retention.
--
-- Why a separate table:
--   * `vpn_connection_stats` is rolling 30-day raw 5-min ticks
--     (Track-1.1 retention purger). For accountability ("сколько
--     трафика юзер скачал за весь май") we need to KEEP daily
--     totals past the 30-day window.
--   * 33 users × 3 servers × 365 days = ~36k rows/year. SQLite
--     trivia. Indefinite retention is the default.
--   * Pre-aggregating at the day boundary means dashboard /
--     reporting queries skip raw ticks entirely — one indexed
--     SELECT per render instead of summing thousands of ticks.
--
-- Granularity is `date` (YYYY-MM-DD) in UTC. Storing the
-- denormalised string instead of an epoch-day INT keeps queries
-- legible (`WHERE date >= '2026-05-01'`) and matches the human
-- mental model the operator uses.
--
-- Bytes columns are NOT NULL (DEFAULT 0 if a row exists at all
-- it's because there WAS some traffic). `active_connections_peak`
-- is the MAX seen across the day — useful for "did the user open
-- more conns than usual?" outlier surfacing.
--
-- Per-user accountability: `user_id` is non-NULL HERE (different
-- from `vpn_connection_stats` where it's nullable for server-wide
-- rows). Server-wide totals are recoverable by summing across
-- users for a (date, server_id) pair if needed; if we ever want
-- standalone server-wide rows in this table, add a `user_id`
-- NULL row alongside. Today we don't — the dashboard cares about
-- per-user views, server-wide live tile reads `vpn_connection_stats`.
--
-- FK ON DELETE CASCADE: dropping a user wipes their daily rows.
-- This matches the GDPR-shaped «right to be forgotten» behavior
-- the rest of inventory already has on sub_access_log.

CREATE TABLE vpn_user_daily (
    id                          INTEGER PRIMARY KEY AUTOINCREMENT,
    -- UTC date (YYYY-MM-DD). One row per (user, server, date).
    date                        TEXT    NOT NULL,
    user_id                     TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    server_id                   TEXT    NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    upload_bytes                INTEGER NOT NULL DEFAULT 0,
    download_bytes              INTEGER NOT NULL DEFAULT 0,
    -- Max active_connections observed across the day. Useful for
    -- "did this user open 200 connections at peak?" outlier
    -- detection on the user-detail page.
    active_connections_peak     INTEGER NOT NULL DEFAULT 0,
    -- Distinct source IPs that contributed to this row across the
    -- day. Roaming signal — high count = roaming device or shared
    -- subscription URL.
    distinct_source_ips         INTEGER NOT NULL DEFAULT 0,
    -- When the rollup task last touched this row. Lets us tell
    -- "this row is stale" (rollup task crashed) from "no traffic
    -- since".
    last_rolled_up_at           TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),

    -- One row per (user, server, date). UPSERT-friendly.
    UNIQUE (user_id, server_id, date)
);

-- Query: «top users by traffic for a date range» — used by the
-- dashboard heavy-users tile + per-user-detail reports. Covers
-- both 24h (one date) and 30-day (date range) windows.
CREATE INDEX idx_vpn_user_daily_date_user ON vpn_user_daily (date, user_id);

-- Query: «traffic for this user across all dates» — user-detail
-- analytics section's main read path.
CREATE INDEX idx_vpn_user_daily_user_date ON vpn_user_daily (user_id, date DESC);

-- Query: «traffic for this server across all dates» — server-
-- detail analytics + future per-server billing rollup.
CREATE INDEX idx_vpn_user_daily_server_date ON vpn_user_daily (server_id, date DESC);
