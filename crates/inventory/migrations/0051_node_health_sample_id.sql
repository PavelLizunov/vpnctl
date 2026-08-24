-- Migration 0051 — Add explicit stable sample_seq and sample_id to node_health.
--
-- Replaces implicit rowid event identity with sample_seq INTEGER PRIMARY KEY AUTOINCREMENT
-- and sample_id TEXT NOT NULL UNIQUE.
--
-- Rebuilds node_health preserving all current columns, foreign keys, and indexes.
-- Legacy rows are copied ordered by ts, rowid with deterministically backfilled legacy IDs.

CREATE TABLE node_health_new (
    sample_seq INTEGER PRIMARY KEY AUTOINCREMENT,
    sample_id TEXT NOT NULL UNIQUE,
    ts TEXT NOT NULL,
    server_id TEXT NOT NULL
        REFERENCES servers(id) ON DELETE CASCADE,
    sing_box_active INTEGER,
    fail2ban_active INTEGER,
    disk_used_mib INTEGER,
    disk_total_mib INTEGER,
    mem_available_mib INTEGER,
    mem_total_mib INTEGER,
    load_1min_x100 INTEGER,
    listening_ports_json TEXT,
    sing_box_log_bytes INTEGER,
    kernel_versions_json TEXT,
    nic_iface TEXT,
    nic_rx_bytes INTEGER,
    nic_tx_bytes INTEGER,
    sing_box_nrestarts INTEGER
);

INSERT INTO node_health_new (
    sample_id,
    ts,
    server_id,
    sing_box_active,
    fail2ban_active,
    disk_used_mib,
    disk_total_mib,
    mem_available_mib,
    mem_total_mib,
    load_1min_x100,
    listening_ports_json,
    sing_box_log_bytes,
    kernel_versions_json,
    nic_iface,
    nic_rx_bytes,
    nic_tx_bytes,
    sing_box_nrestarts
)
SELECT
    'legacy-' || hex(randomblob(16)),
    ts,
    server_id,
    sing_box_active,
    fail2ban_active,
    disk_used_mib,
    disk_total_mib,
    mem_available_mib,
    mem_total_mib,
    load_1min_x100,
    listening_ports_json,
    sing_box_log_bytes,
    kernel_versions_json,
    nic_iface,
    nic_rx_bytes,
    nic_tx_bytes,
    sing_box_nrestarts
FROM node_health
ORDER BY ts ASC, rowid ASC;

DROP TABLE node_health;

ALTER TABLE node_health_new RENAME TO node_health;

CREATE INDEX IF NOT EXISTS idx_node_health_server_ts
    ON node_health(server_id, ts DESC);

CREATE UNIQUE INDEX IF NOT EXISTS idx_node_health_sample_id
    ON node_health(sample_id);
