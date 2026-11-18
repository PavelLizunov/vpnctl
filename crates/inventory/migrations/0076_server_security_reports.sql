CREATE TABLE server_security_reports (
    server_id TEXT PRIMARY KEY NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    route_fingerprint TEXT NOT NULL,
    revision INTEGER NOT NULL,
    report_json TEXT NOT NULL
);
