-- Independent telephony publication floor; never alter the site policy journal.
CREATE TABLE corp_policy_phone_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    revision INTEGER NOT NULL DEFAULT 0 CHECK (revision BETWEEN 0 AND 9007199254740991)
);
INSERT INTO corp_policy_phone_settings (id, revision) VALUES (1, 0);
CREATE TABLE corp_policy_phone_revisions (
    revision INTEGER PRIMARY KEY CHECK (revision BETWEEN 1 AND 9007199254740991),
    key_id TEXT NOT NULL,
    published_at INTEGER NOT NULL CHECK (published_at BETWEEN 1 AND 253402300799),
    payload_sha256 TEXT NOT NULL CHECK (length(payload_sha256) = 64),
    payload BLOB NOT NULL CHECK (length(payload) BETWEEN 1 AND 49152),
    envelope BLOB NOT NULL CHECK (length(envelope) BETWEEN 1 AND 65536)
);
