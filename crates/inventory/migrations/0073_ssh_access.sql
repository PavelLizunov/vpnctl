CREATE TABLE ssh_access_checks (
    server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    route TEXT NOT NULL CHECK (route IN ('direct', 'jump')),
    route_identity TEXT NOT NULL,
    check_json TEXT NOT NULL,
    PRIMARY KEY (server_id, route)
);
