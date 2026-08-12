-- Native service-path quality history. One row per server poll tick;
-- individual successful TCP RTTs stay in the small JSON array so 24h/7d
-- median and p95 are computed from the real observations, not averages of
-- averages. SSH-port control attempts stay separate from the service score.
-- ICMP is nullable/secondary: deployments without permission to send ICMP
-- still produce a complete TCP service-path score.
CREATE TABLE server_quality_samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    vantage TEXT NOT NULL,
    target_count INTEGER NOT NULL CHECK (target_count >= 0),
    available_targets INTEGER NOT NULL CHECK (
        available_targets >= 0 AND available_targets <= target_count
    ),
    attempts INTEGER NOT NULL CHECK (attempts >= 0),
    successes INTEGER NOT NULL CHECK (successes >= 0 AND successes <= attempts),
    tcp_rtt_ms_json TEXT NOT NULL,
    control_attempts INTEGER NOT NULL CHECK (control_attempts >= 0),
    control_successes INTEGER NOT NULL CHECK (
        control_successes >= 0 AND control_successes <= control_attempts
    ),
    control_rtt_ms_json TEXT NOT NULL,
    icmp_attempts INTEGER,
    icmp_successes INTEGER,
    icmp_rtt_ms_json TEXT
);

CREATE INDEX idx_server_quality_samples_server_ts
    ON server_quality_samples(server_id, ts DESC);
