-- Latest samples follow insertion order, independent of wall-clock adjustments.
CREATE INDEX IF NOT EXISTS idx_node_health_server_seq
    ON node_health(server_id, sample_seq DESC);
