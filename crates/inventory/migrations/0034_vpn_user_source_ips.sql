-- 2026-06-14 — per-user × source-IP tracking.
--
-- Pavel: «разбей трафик по ip внутри пользователя» + «проработай
-- (неизвестно)». The clash snapshot + Phase 4d attribution already
-- resolve each live connection's real client `source_ip` to a
-- user_id; this table accumulates the FACT of those connections so
-- /admin/users/<id> can show «from which client IPs did this user
-- connect» without scraping the in-memory snapshot history (which
-- doesn't exist — snapshots are replaced every 5 min).
--
-- This is the source-IP counterpart to `vpn_user_destinations`
-- (0024): same shape, same hit-per-tick semantics, same retention.
-- Distinct public IPs / countries on one user = the clearest
-- who-is-sharing signal that's grounded in ACTUAL VPN traffic
-- (the «Subscription origins» tables only see /sub URL fetches).
--
-- Granularity: per-(user_id, source_ip, date). One row per day per
-- (user, source_ip). hit_count is incremented at every clash-poll
-- tick where the user had at least one live connection from that
-- source_ip; last_seen tracks the freshest tick within the day.
--
-- We intentionally DO NOT track byte counts per (user, source_ip)
-- here — that would need diff-engine state per (user, source_ip,
-- conn_id) tuple to avoid double-counting across ticks, which
-- explodes complexity (the exact reasoning of 0024). Per-user byte
-- totals live in `vpn_user_daily`; this table answers «откуда»
-- (which client IP) and «как часто» (activity), not «сколько байт».
--
-- source_ip is the client's real public IP as sing-box reports it
-- on the inbound connection (preserved despite NM-11). Empty
-- source IPs are NEVER recorded (the writer skips them) — a row
-- here always has a concrete IP to classify / geo-locate.
--
-- Retention: 30 days rolling, swept by the existing hourly task.

CREATE TABLE vpn_user_source_ips (
    id                          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id                     TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- Client public source IP (IPv4 or IPv6 textual form). NOT NULL
    -- and never empty — the writer drops empty-source connections.
    source_ip                   TEXT    NOT NULL,
    -- UTC date `YYYY-MM-DD` for daily slicing.
    date                        TEXT    NOT NULL,
    -- Number of clash-poll ticks during the day where this
    -- (user, source_ip) pair was observed live. NOT a connection
    -- count — a single long-lived connection across multiple ticks
    -- contributes N hits, where N = ticks-it-was-alive.
    hit_count                   INTEGER NOT NULL DEFAULT 1,
    -- Most recent tick ts where the pair was observed.
    last_seen                   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),

    UNIQUE (user_id, source_ip, date)
);

-- Query: «top source IPs for this user over the last 7 days».
-- Used by the user-detail «Source IPs» section.
CREATE INDEX idx_vpn_user_source_ips_user_date
    ON vpn_user_source_ips (user_id, date DESC, hit_count DESC);
