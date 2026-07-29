-- Compact fleet/server traffic source for dashboard charts.
--
-- One row per UTC hour and server. New ticks update this table in the
-- same transaction as vpn_connection_stats, so charts never need to
-- scan the rolling raw table.
CREATE TABLE vpn_server_hourly (
    hour                    TEXT NOT NULL,
    server_id               TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    upload_bytes            INTEGER NOT NULL DEFAULT 0,
    download_bytes          INTEGER NOT NULL DEFAULT 0,
    active_connections_peak INTEGER NOT NULL DEFAULT 0,
    last_sample_ts          TEXT NOT NULL,
    PRIMARY KEY (server_id, hour)
);

CREATE INDEX idx_vpn_server_hourly_hour
    ON vpn_server_hourly (hour DESC, server_id);

-- Preserve the older history already retained in vpn_user_daily.
INSERT INTO vpn_server_hourly
    (hour, server_id, upload_bytes, download_bytes,
     active_connections_peak, last_sample_ts)
SELECT
    date || 'T00:00:00.000Z',
    server_id,
    SUM(upload_bytes),
    SUM(download_bytes),
    MAX(active_connections_peak),
    date || 'T23:59:59.999Z'
FROM vpn_user_daily
GROUP BY date, server_id;

-- Raw retention has the exact recent totals, including unattributed
-- server-wide traffic. Replace the matching legacy midnight buckets.
INSERT INTO vpn_server_hourly
    (hour, server_id, upload_bytes, download_bytes,
     active_connections_peak, last_sample_ts)
SELECT
    substr(ts, 1, 13) || ':00:00.000Z',
    server_id,
    SUM(upload_bytes),
    SUM(download_bytes),
    MAX(active_connections),
    MAX(ts)
FROM vpn_connection_stats
WHERE 1
GROUP BY substr(ts, 1, 13), server_id
ON CONFLICT(server_id, hour) DO UPDATE SET
    upload_bytes            = excluded.upload_bytes,
    download_bytes          = excluded.download_bytes,
    active_connections_peak = excluded.active_connections_peak,
    last_sample_ts          = excluded.last_sample_ts;
