-- Phase 5c — per-user session windows (closed by inactivity gap).
--
-- A «session» here is a sliding window where the operator wants
-- to see «когда alice была online сегодня». The clash-poll cadence
-- is 5 min — if we see alice's user_id in N consecutive ticks,
-- that's one session of (N * 5) minutes. A gap of ≥ N missed
-- ticks ends the session; the next observation starts a fresh
-- session row.
--
-- Why we need this table (vs deriving from vpn_user_daily):
-- daily rollups answer «сколько за день», not «сколько отдельных
-- сессий, и какие самые длинные». Pattern «alice была активна с
-- 10:00 до 12:30, потом с 14:00 до 22:00» needs explicit
-- session rows.
--
-- Schema:
--  * (user_id, server_id) — per server because traffic patterns
--    differ per node (брат-main uses de, de other users use is).
--  * started_at + last_seen — UTC ISO-8601. Session ends when
--    a gap > SESSION_GAP_MINUTES is observed; UI computes
--    duration as `last_seen - started_at`.
--  * conn_count_peak — max active conns during the session,
--    handy for outlier detection.
--  * total_bytes — sum of upload+download credited to this user
--    on this server while the session was open. Derived from
--    vpn_user_daily per-tick deltas integrated.
--
-- Retention: 30 days rolling (sessions older are dropped by
-- the hourly retention task).
--
-- Index strategy: (user_id, started_at DESC) for the
-- user-detail timeline + (server_id, started_at DESC) for the
-- per-server view if we add one later.

CREATE TABLE vpn_user_sessions (
    id                          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id                     TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    server_id                   TEXT    NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    started_at                  TEXT    NOT NULL,
    -- Updated every tick the session continues; effectively
    -- "session end" when no more ticks come within gap budget.
    last_seen                   TEXT    NOT NULL,
    conn_count_peak             INTEGER NOT NULL DEFAULT 0,
    total_bytes                 INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX idx_vpn_user_sessions_user_started
    ON vpn_user_sessions (user_id, started_at DESC);
CREATE INDEX idx_vpn_user_sessions_server_started
    ON vpn_user_sessions (server_id, started_at DESC);
