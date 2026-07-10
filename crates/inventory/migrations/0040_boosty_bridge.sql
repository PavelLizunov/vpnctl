-- 0040_boosty_bridge.sql — link vpnctl users to Boosty subscribers and
-- store the bridge's own config.
--
-- ## users.boosty_subscriber_id
--
-- Optional link from a vpnctl user to a Boosty subscriber (Boosty's
-- numeric subscriber id). NULL for every operator-managed user that has
-- no Boosty origin (tester, claude-chat-proxy, hand-created accounts).
-- The reconciler (`vpnctl-boosty-bridge`) ONLY ever enables/disables
-- users whose `boosty_subscriber_id` is non-NULL — a NULL user can never
-- be touched by subscription reconciliation. Partial UNIQUE index: many
-- users may be unlinked (NULL), but no two users can point at the same
-- subscriber.
--
-- ## boosty_settings (singleton, id = 1)
--
-- Mirrors the `notification_settings` pattern (migration 0014): one
-- config row, CHECK(id = 1), seeded via INSERT OR IGNORE so UPDATE always
-- has a target.
--
-- Secret handling — `access_token` / `refresh_token` / `device_id` are
-- CREDENTIALS, same care as `notification_settings.telegram_bot_token`:
--   * stored plain (daemon-owned 0640 inv.db; already covered by backups);
--   * NEVER serialised into `audit_log.payload_json`;
--   * NEVER rendered verbatim in admin HTML (show `••••<last4>` + replace).
-- Boosty rotates the refresh token on every refresh, so the daemon writes
-- the rotated value back here (that's why it lives in a writable store,
-- not a static env var).
--
-- `auto_disable_lapsed` = 0 by default: the poller auto-ENABLES active
-- subscribers but only SURFACES lapses for the operator to confirm via a
-- button (the confirmed "auto-provision, disable on a button" policy).
-- Flip to 1 to also auto-disable lapsed subscribers.

ALTER TABLE users ADD COLUMN boosty_subscriber_id INTEGER;

CREATE UNIQUE INDEX idx_users_boosty_subscriber_id
    ON users(boosty_subscriber_id)
    WHERE boosty_subscriber_id IS NOT NULL;

CREATE TABLE boosty_settings (
    id                  INTEGER PRIMARY KEY CHECK (id = 1),
    enabled             INTEGER NOT NULL DEFAULT 0,
    blog_url            TEXT,               -- e.g. "ninitux"
    access_token        TEXT,               -- nullable secret (static token)
    refresh_token       TEXT,               -- nullable secret (rotating)
    device_id           TEXT,               -- nullable (refresh flow)
    poll_interval_secs  INTEGER NOT NULL DEFAULT 3600,
    auto_disable_lapsed INTEGER NOT NULL DEFAULT 0,
    updated_at          TEXT NOT NULL
                          DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

INSERT OR IGNORE INTO boosty_settings (id) VALUES (1);
