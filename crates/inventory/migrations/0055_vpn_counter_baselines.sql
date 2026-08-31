-- Persistent cumulative-counter baselines for crash-safe traffic deltas.
-- Inbound server totals and user totals come from one sing-box V2Ray Stats query.
CREATE TABLE vpn_server_counter_baselines (
    server_id        TEXT PRIMARY KEY REFERENCES servers(id) ON DELETE CASCADE,
    upload_total     INTEGER NOT NULL CHECK (upload_total >= 0),
    download_total   INTEGER NOT NULL CHECK (download_total >= 0),
    uptime_seconds   INTEGER NOT NULL CHECK (uptime_seconds >= 0),
    observed_at      INTEGER NOT NULL CHECK (observed_at >= 0),
    upload_ahead     INTEGER NOT NULL DEFAULT 0 CHECK (upload_ahead >= 0),
    download_ahead   INTEGER NOT NULL DEFAULT 0 CHECK (download_ahead >= 0),
    upload_pending   INTEGER NOT NULL DEFAULT 0 CHECK (upload_pending >= 0),
    download_pending INTEGER NOT NULL DEFAULT 0 CHECK (download_pending >= 0)
);

CREATE TABLE vpn_user_counter_baselines (
    server_id      TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    user_id        TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    upload_total   INTEGER NOT NULL CHECK (upload_total >= 0),
    download_total INTEGER NOT NULL CHECK (download_total >= 0),
    PRIMARY KEY (server_id, user_id)
);
