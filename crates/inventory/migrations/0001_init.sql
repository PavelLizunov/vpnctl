-- Initial schema for vpnctl SQLite inventory.
-- All timestamps stored as ISO-8601 TEXT (sqlx maps to chrono::DateTime<Utc>).
-- FK enforcement and WAL are toggled by SqliteInventory at connection time.

CREATE TABLE servers (
    id                          TEXT PRIMARY KEY,
    address                     TEXT NOT NULL,
    ssh_port                    INTEGER NOT NULL DEFAULT 22,
    ssh_user                    TEXT NOT NULL,
    kernel                      TEXT NOT NULL,                       -- KernelId (e.g. "sing-box")
    hoster                      TEXT NOT NULL,                       -- "digitalocean" / "cloudzy" / "generic"
    jump_via                    TEXT,                                -- nullable, FK to servers.id
    trusted_host_fingerprint    TEXT,                                -- "SHA256:..." or NULL until TOFU resolves
    usage_coefficient           REAL NOT NULL DEFAULT 1.0,           -- traffic accounting multiplier (Marzban-style)
    created_at                  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at                  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    FOREIGN KEY (jump_via) REFERENCES servers(id) ON DELETE SET NULL
);

-- Which protocols are enabled on which server (M:N).
CREATE TABLE server_protocols (
    server_id   TEXT NOT NULL,
    protocol_id TEXT NOT NULL,                                       -- ProtocolId (e.g. "vless+reality")
    PRIMARY KEY (server_id, protocol_id),
    FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE
);

-- Per-server key/value secrets (REALITY private/public/short_id, TLS cert paths, ...).
CREATE TABLE server_secrets (
    server_id   TEXT NOT NULL,
    key         TEXT NOT NULL,
    value       TEXT NOT NULL,
    PRIMARY KEY (server_id, key),
    FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE
);

CREATE TABLE users (
    id                  TEXT PRIMARY KEY,
    uuid                TEXT NOT NULL UNIQUE,
    tuic_password       TEXT,
    wireguard_pubkey    TEXT,
    created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- A user × server access grant.
CREATE TABLE grants (
    user_id     TEXT NOT NULL,
    server_id   TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (user_id, server_id),
    FOREIGN KEY (user_id)   REFERENCES users(id)   ON DELETE CASCADE,
    FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE
);

CREATE TABLE audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    actor       TEXT NOT NULL,                                       -- "cli" / "system" / username
    action      TEXT NOT NULL,                                       -- "server.create" / "server.deploy" / ...
    target      TEXT,                                                -- server_id / user_id / ...
    payload     TEXT                                                 -- arbitrary JSON detail
);
CREATE INDEX idx_audit_ts     ON audit_log(ts);
CREATE INDEX idx_audit_target ON audit_log(target);
