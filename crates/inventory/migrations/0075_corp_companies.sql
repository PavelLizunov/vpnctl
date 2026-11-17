-- Rebuild the singleton tables without changing any existing data bytes.
DROP TRIGGER corp_bound_user_deleted;
DROP TRIGGER corp_bound_user_disabled;
DROP INDEX idx_corp_policy_sessions_expiry;
ALTER TABLE corp_policy_settings RENAME TO corp_policy_settings_old;
ALTER TABLE corp_policy_revisions RENAME TO corp_policy_revisions_old;
ALTER TABLE corp_policy_egress RENAME TO corp_policy_egress_old;
ALTER TABLE corp_policy_sessions RENAME TO corp_policy_sessions_old;
ALTER TABLE corp_policy_phone_settings RENAME TO corp_policy_phone_settings_old;
ALTER TABLE corp_policy_phone_revisions RENAME TO corp_policy_phone_revisions_old;

CREATE TABLE corp_policy_settings (
    company_id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL UNIQUE,
    policy_id TEXT NOT NULL UNIQUE,
    enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
    auth_generation INTEGER NOT NULL CHECK (auth_generation BETWEEN 1 AND 9007199254740991),
    config_version INTEGER NOT NULL CHECK (config_version BETWEEN 1 AND 9007199254740991),
    revision INTEGER NOT NULL DEFAULT 0 CHECK (revision BETWEEN 0 AND 9007199254740991),
    active_key_id TEXT NOT NULL,
    credentials_json TEXT NOT NULL
);
INSERT INTO corp_policy_settings SELECT 'legacy', user_id, policy_id, enabled, auth_generation, config_version, revision, active_key_id, credentials_json FROM corp_policy_settings_old;

CREATE TABLE corp_policy_revisions (
    company_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision BETWEEN 1 AND 9007199254740991),
    key_id TEXT NOT NULL,
    published_at INTEGER NOT NULL CHECK (published_at BETWEEN 1 AND 253402300799),
    payload_sha256 TEXT NOT NULL CHECK (length(payload_sha256) = 64),
    payload BLOB NOT NULL CHECK (length(payload) BETWEEN 1 AND 49152),
    envelope BLOB NOT NULL CHECK (length(envelope) BETWEEN 1 AND 65536),
    PRIMARY KEY (company_id, revision)
);
INSERT INTO corp_policy_revisions SELECT 'legacy', revision, key_id, published_at, payload_sha256, payload, envelope FROM corp_policy_revisions_old;

CREATE TABLE corp_policy_egress (
    company_id TEXT NOT NULL,
    server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    ip TEXT NOT NULL,
    configuration_fingerprint TEXT NOT NULL CHECK (length(configuration_fingerprint) = 64),
    verified_at INTEGER NOT NULL CHECK (verified_at BETWEEN 1 AND 253402300799),
    PRIMARY KEY (company_id, server_id, ip)
);
INSERT INTO corp_policy_egress SELECT 'legacy', server_id, ip, configuration_fingerprint, verified_at FROM corp_policy_egress_old;

CREATE TABLE corp_policy_sessions (
    token_hash TEXT PRIMARY KEY CHECK (length(token_hash) = 64),
    company_id TEXT NOT NULL,
    csrf_token TEXT NOT NULL CHECK (length(csrf_token) = 43),
    expires_at INTEGER NOT NULL CHECK (expires_at BETWEEN 1 AND 253402300799),
    auth_generation INTEGER NOT NULL CHECK (auth_generation BETWEEN 1 AND 9007199254740991)
);
INSERT INTO corp_policy_sessions SELECT token_hash, 'legacy', csrf_token, expires_at, auth_generation FROM corp_policy_sessions_old;
CREATE INDEX idx_corp_policy_sessions_expiry ON corp_policy_sessions(company_id, expires_at);

CREATE TABLE corp_policy_phone_settings (
    company_id TEXT PRIMARY KEY NOT NULL,
    revision INTEGER NOT NULL DEFAULT 0 CHECK (revision BETWEEN 0 AND 9007199254740991)
);
INSERT INTO corp_policy_phone_settings SELECT 'legacy', revision FROM corp_policy_phone_settings_old;
CREATE TABLE corp_policy_phone_revisions (
    company_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision BETWEEN 1 AND 9007199254740991),
    key_id TEXT NOT NULL,
    published_at INTEGER NOT NULL CHECK (published_at BETWEEN 1 AND 253402300799),
    payload_sha256 TEXT NOT NULL CHECK (length(payload_sha256) = 64),
    payload BLOB NOT NULL CHECK (length(payload) BETWEEN 1 AND 49152),
    envelope BLOB NOT NULL CHECK (length(envelope) BETWEEN 1 AND 65536),
    PRIMARY KEY (company_id, revision)
);
INSERT INTO corp_policy_phone_revisions SELECT 'legacy', revision, key_id, published_at, payload_sha256, payload, envelope FROM corp_policy_phone_revisions_old;
DROP TABLE corp_policy_settings_old;
DROP TABLE corp_policy_revisions_old;
DROP TABLE corp_policy_egress_old;
DROP TABLE corp_policy_sessions_old;
DROP TABLE corp_policy_phone_settings_old;
DROP TABLE corp_policy_phone_revisions_old;

CREATE TRIGGER corp_bound_user_deleted AFTER DELETE ON users
WHEN EXISTS (SELECT 1 FROM corp_policy_settings WHERE user_id = OLD.id)
BEGIN
    DELETE FROM corp_policy_sessions WHERE company_id IN (SELECT company_id FROM corp_policy_settings WHERE user_id = OLD.id);
    UPDATE corp_policy_settings SET enabled = 0,
        auth_generation = MIN(auth_generation + 1, 9007199254740991),
        config_version = MIN(config_version + 1, 9007199254740991) WHERE user_id = OLD.id;
    INSERT INTO audit_log (actor, action, target, payload) VALUES ('inventory', 'corp.binding.user_deleted', OLD.id, '{}');
END;
CREATE TRIGGER corp_bound_user_disabled AFTER UPDATE OF disabled ON users
WHEN OLD.disabled = 0 AND NEW.disabled != 0 AND EXISTS (SELECT 1 FROM corp_policy_settings WHERE user_id = NEW.id)
BEGIN
    DELETE FROM corp_policy_sessions WHERE company_id IN (SELECT company_id FROM corp_policy_settings WHERE user_id = NEW.id);
    UPDATE corp_policy_settings SET enabled = CASE WHEN auth_generation >= 9007199254740991 OR config_version >= 9007199254740991 THEN 0 ELSE enabled END,
        auth_generation = MIN(auth_generation + 1, 9007199254740991),
        config_version = MIN(config_version + 1, 9007199254740991) WHERE user_id = NEW.id;
    INSERT INTO audit_log (actor, action, target, payload) VALUES ('inventory', 'corp.sessions.user_disabled', NEW.id, '{}');
END;
