-- Fixed corporate portal state. Keep identity/history after the bound user is deleted.
CREATE TABLE corp_policy_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    user_id TEXT NOT NULL,
    policy_id TEXT NOT NULL UNIQUE,
    enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
    auth_generation INTEGER NOT NULL CHECK (auth_generation BETWEEN 1 AND 9007199254740991),
    config_version INTEGER NOT NULL CHECK (config_version BETWEEN 1 AND 9007199254740991),
    revision INTEGER NOT NULL DEFAULT 0 CHECK (revision BETWEEN 0 AND 9007199254740991),
    active_key_id TEXT NOT NULL,
    credentials_json TEXT NOT NULL
);

CREATE TABLE corp_policy_revisions (
    revision INTEGER PRIMARY KEY CHECK (revision BETWEEN 1 AND 9007199254740991),
    key_id TEXT NOT NULL,
    published_at INTEGER NOT NULL CHECK (published_at BETWEEN 1 AND 253402300799),
    payload_sha256 TEXT NOT NULL CHECK (length(payload_sha256) = 64),
    payload BLOB NOT NULL CHECK (length(payload) BETWEEN 1 AND 49152),
    envelope BLOB NOT NULL CHECK (length(envelope) BETWEEN 1 AND 65536)
);

CREATE TABLE corp_policy_egress (
    server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    ip TEXT NOT NULL,
    configuration_fingerprint TEXT NOT NULL CHECK (length(configuration_fingerprint) = 64),
    verified_at INTEGER NOT NULL CHECK (verified_at BETWEEN 1 AND 253402300799),
    PRIMARY KEY (server_id, ip)
);

CREATE TABLE corp_policy_sessions (
    token_hash TEXT PRIMARY KEY CHECK (length(token_hash) = 64),
    csrf_token TEXT NOT NULL CHECK (length(csrf_token) = 43),
    expires_at INTEGER NOT NULL CHECK (expires_at BETWEEN 1 AND 253402300799),
    auth_generation INTEGER NOT NULL CHECK (auth_generation BETWEEN 1 AND 9007199254740991)
);
CREATE INDEX idx_corp_policy_sessions_expiry ON corp_policy_sessions(expires_at);

CREATE TRIGGER corp_bound_user_deleted
AFTER DELETE ON users
WHEN EXISTS (SELECT 1 FROM corp_policy_settings WHERE user_id = OLD.id)
BEGIN
    UPDATE corp_policy_settings
    SET enabled = 0,
        auth_generation = MIN(auth_generation + 1, 9007199254740991),
        config_version = MIN(config_version + 1, 9007199254740991)
    WHERE user_id = OLD.id;
    DELETE FROM corp_policy_sessions;
    INSERT INTO audit_log (actor, action, target, payload)
    VALUES ('inventory', 'corp.binding.user_deleted', OLD.id, '{}');
END;

CREATE TRIGGER corp_bound_user_disabled
AFTER UPDATE OF disabled ON users
WHEN OLD.disabled = 0 AND NEW.disabled != 0
    AND EXISTS (SELECT 1 FROM corp_policy_settings WHERE user_id = NEW.id)
BEGIN
    UPDATE corp_policy_settings
    SET enabled = CASE
            WHEN auth_generation >= 9007199254740991 OR config_version >= 9007199254740991
            THEN 0 ELSE enabled END,
        auth_generation = MIN(auth_generation + 1, 9007199254740991),
        config_version = MIN(config_version + 1, 9007199254740991)
    WHERE user_id = NEW.id;
    DELETE FROM corp_policy_sessions;
    INSERT INTO audit_log (actor, action, target, payload)
    VALUES ('inventory', 'corp.sessions.user_disabled', NEW.id, '{}');
END;
