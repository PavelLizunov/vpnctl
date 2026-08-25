CREATE TABLE protocol_assurance_samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    protocol_id TEXT NOT NULL,
    client_kind TEXT NOT NULL,
    stage TEXT NOT NULL CHECK (stage IN (
        'render', 'server_config', 'listener', 'external_path',
        'client_import', 'handshake', 'transfer'
    )),
    state TEXT NOT NULL CHECK (state IN ('verified', 'degraded', 'blocked', 'unknown')),
    latency_ms INTEGER CHECK (latency_ms IS NULL OR latency_ms >= 0),
    failure_code TEXT,
    CHECK (length(protocol_id) BETWEEN 1 AND 64),
    CHECK (length(client_kind) BETWEEN 1 AND 64),
    CHECK (failure_code IS NULL OR length(failure_code) <= 128)
);

CREATE INDEX idx_protocol_assurance_server_latest
    ON protocol_assurance_samples(server_id, protocol_id, id DESC);
CREATE INDEX idx_protocol_assurance_ts
    ON protocol_assurance_samples(ts);
