CREATE TABLE service_path_states (
    server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    target_identity TEXT NOT NULL,
    checked_at TEXT NOT NULL,
    state_json TEXT NOT NULL,
    PRIMARY KEY (server_id, target_identity)
);
CREATE TABLE service_path_incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    target_identity TEXT NOT NULL,
    incident_json TEXT NOT NULL,
    open INTEGER NOT NULL DEFAULT 1 CHECK (open IN (0, 1))
);
CREATE UNIQUE INDEX idx_service_path_open ON service_path_incidents(server_id, target_identity) WHERE open = 1;
CREATE INDEX idx_service_path_history ON service_path_incidents(server_id, id DESC);
