-- Phase H chunk 2: persistent ring of node telemetry snapshots.
--
-- One row per (snapshot, server). Polled by `daemon::node_probe`
-- via SSH every N minutes (chunk 3 wires the scheduler). Fields are
-- nullable because partial-success snapshots (one parser failed, the
-- others succeeded) are preferred over hard-failing the whole tick.
--
-- `listening_ports_json` carries the BTreeSet<(proto,port)> as a
-- sorted JSON array of strings like ["tcp/443","udp/8443"]. Storing
-- as JSON rather than a normalized child table because:
--   * Cardinality is bounded (~10 ports per snapshot, ~5 servers,
--     ~12 snapshots/hour, ~30 days retained = ~50K rows × 10 ports
--     = 500K-row child table for marginal query value).
--   * The chunk-3 UI compares observed vs declared as set-equality;
--     a single VARCHAR holds that comparison just fine.
--
-- Retention: same hourly purge cadence as `sub_access_log` /
-- `vpn_connection_stats` — `purge_node_health_older_than(days)`
-- below. Daemon scheduler wires it in chunk 3.
--
-- FK CASCADE on server_id: removing a server drops its history.
-- Consistent with vpn_connection_stats + sub_access_log on
-- server-side (the latter has SET NULL on user, never server).

CREATE TABLE IF NOT EXISTS node_health (
    -- Wall-clock at INSERT (daemon-side). ISO-8601 with millis, same
    -- format as the rest of the schema so bucket helpers can reuse.
    ts TEXT NOT NULL,

    server_id TEXT NOT NULL
        REFERENCES servers(id) ON DELETE CASCADE,

    -- Service health. NULL = parser couldn't determine (probe failed
    -- or `systemctl is-active` returned unrecognized state). 0/1 =
    -- inactive/active respectively (SQLite has no BOOLEAN, so INTEGER).
    sing_box_active INTEGER,
    fail2ban_active INTEGER,

    -- Disk usage on the root filesystem in MiB. NULL on parse failure.
    disk_used_mib INTEGER,
    disk_total_mib INTEGER,

    -- Memory in MiB. mem_available is the kernel's "really free" number
    -- (accounts for reclaimable caches), used > 80% on this metric IS
    -- pressure.
    mem_available_mib INTEGER,
    mem_total_mib INTEGER,

    -- 1-minute load average × 100 (so we store as INTEGER without
    -- losing precision). UI divides by 100 on render.
    load_1min_x100 INTEGER,

    -- Listening sockets serialized as a sorted JSON array of
    -- "proto/port" strings, e.g. ["tcp/22","tcp/443","udp/8443"].
    -- TEXT column not BLOB so SQL `LIKE` queries can grep ports
    -- without parsing JSON.
    listening_ports_json TEXT,

    -- sing-box main log file size in bytes. Threshold for the
    -- chunk-3 "log too large" alert is 500 MB; column is INTEGER so
    -- holds up to ~9 EiB without truncation.
    sing_box_log_bytes INTEGER
);

-- Newest-first per-server lookup (server-detail page reads recent N).
CREATE INDEX IF NOT EXISTS idx_node_health_server_ts
    ON node_health(server_id, ts DESC);
