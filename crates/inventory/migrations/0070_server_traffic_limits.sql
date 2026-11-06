-- Optional hoster quotas; do not assign an allowance to existing servers.
CREATE TABLE server_traffic_limits (
    server_id TEXT PRIMARY KEY REFERENCES servers(id) ON DELETE CASCADE,
    limit_bytes INTEGER NOT NULL CHECK(limit_bytes > 0),
    direction TEXT NOT NULL CHECK(direction IN ('rx', 'tx', 'both')),
    reset_day INTEGER NOT NULL CHECK(reset_day BETWEEN 1 AND 31),
    warning_pct INTEGER NOT NULL CHECK(warning_pct BETWEEN 1 AND 100)
);
