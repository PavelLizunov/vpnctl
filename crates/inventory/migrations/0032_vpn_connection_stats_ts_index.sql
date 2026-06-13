-- Dashboard hot-path index: fleet-wide raw stats by time window.
--
-- `recent_vpn_stats_fleet` (backs the /admin dashboard's multi-window
-- traffic chart) runs
--
--     SELECT ... FROM vpn_connection_stats
--     WHERE ts > ? ORDER BY ts DESC
--
-- with NO server_id/user_id predicate — it wants EVERY server's every
-- user's row in the window. The two indexes from 0006
-- (idx_vcs_user_ts = (user_id, ts), idx_vcs_server_ts = (server_id, ts))
-- both LEAD with the subject column, so neither can satisfy a bare `ts`
-- range. EXPLAIN QUERY PLAN on prod (109k rows) showed
-- `SCAN vpn_connection_stats` + `USE TEMP B-TREE FOR ORDER BY` on every
-- dashboard load.
--
-- A standalone (ts DESC) index lets SQLite range-scan the window in
-- timestamp order, dropping both the full scan and the temp sort.
-- DESC matches the query's ORDER BY so the index is read forward.
--
-- Additive + idempotent, same style as the 0006 indexes. Pure index
-- creation — no data migration, no checksum risk for existing rows.

CREATE INDEX IF NOT EXISTS idx_vcs_ts
    ON vpn_connection_stats(ts DESC);
