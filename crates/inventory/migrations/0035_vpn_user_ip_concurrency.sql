-- 2026-06-17 — per-user peak CONCURRENT source-IP count.
--
-- Pavel: «продумай метод [детекта расшаривания] подробно … может мы
-- метрику упускаем». The single strongest account-sharing signal in the
-- industry (Fingerprint / Netflix household / impossible-travel) is
-- SIMULTANEITY — two different client IPs using one subscription AT THE
-- SAME MOMENT. Our existing `vpn_user_source_ips` aggregates to per-day,
-- losing the instant: a user with home + mobile on different days looks
-- the same as two people online together.
--
-- The clash-poll snapshot already carries every live connection's real
-- `source_ip` for a single point in time. `poll_one_server` dedups them
-- into a (user_id, source_ip) set per snapshot — so the number of DISTINCT
-- source IPs a user has IN ONE snapshot is, by construction, how many
-- different clients are connected to that node simultaneously. This table
-- persists the DAILY PEAK of that count per user, which feeds the
-- composite sharing-risk score. peak = 1 → one client at a time (normal);
-- peak >= 2 → at some instant the sub was used from 2+ IPs at once.
--
-- Granularity: per-(user_id, date). One row per user per UTC day; the
-- writer UPSERTs peak = MAX(existing, this_snapshot_distinct_ip_count).
-- Cross-server simultaneity is approximated by taking the MAX across every
-- server's snapshot that day (a user actively spread over two nodes at
-- once is itself a mild signal). Retention: 30 days rolling, swept by the
-- existing hourly task alongside vpn_user_source_ips.

CREATE TABLE vpn_user_ip_concurrency (
    user_id             TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- UTC calendar day, 'YYYY-MM-DD'.
    date                TEXT    NOT NULL,
    -- Max distinct source IPs seen for this user in a SINGLE clash
    -- snapshot during the day (>= 1 once any row exists).
    peak_concurrent_ips INTEGER NOT NULL,
    updated_at          TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (user_id, date)
);

-- Retention sweep filters on `date`; the PK already covers per-user reads.
CREATE INDEX idx_vpn_user_ip_concurrency_date ON vpn_user_ip_concurrency (date);
