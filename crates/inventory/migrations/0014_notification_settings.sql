-- Phase G chunk 3 — push-notification transport config.
--
-- Single operator, single config → singleton row pattern: the table
-- has a CHECK constraint `id = 1` so only one config can ever exist.
-- The INSERT-OR-IGNORE seed at the bottom ensures the row exists
-- after migration so subsequent UPDATEs always have a target.
--
-- ## Why a dedicated table (not a kv-pairs settings table)
--
-- vpnctl doesn't have a generic `settings` table today. The only other
-- settings (theme, accent) live in cookies, not DB. A dedicated table
-- per transport (Telegram / future ntfy / future webhook) means each
-- transport adds ONE migration with its own columns + types instead
-- of stringly-typed kv pairs that fight type checking. Singleton row
-- keeps it as cheap as the kv approach.
--
-- ## Secret handling
--
-- `telegram_bot_token` is a SECRET — same care as
-- `users.wireguard_private` and `users.tuic_password`. Implications:
--   * stored plain (the inv.db file is daemon-owned 0640; the backup
--     system needs to cover it — current `inv.db.<ts>.bak` snapshots
--     already include this row);
--   * NEVER serialised into `audit_log.payload_json` (the audit
--     timeline is operator-visible; tests should pin this);
--   * NEVER rendered verbatim in admin HTML (the Settings page shows
--     `••••<last4>` + a «replace» button; the full value is only
--     shipped over HTTPS in the API call, never back to the browser).
--
-- ## Disabled state
--
-- Either column NULL ⇒ transport is disabled. Both must be set
-- atomically; the inventory API enforces this by accepting both
-- arguments together. An operator who wants to disable Telegram
-- clears both via the Settings form's empty-inputs-on-save.

CREATE TABLE notification_settings (
    id                  INTEGER PRIMARY KEY CHECK (id = 1),
    telegram_bot_token  TEXT,           -- nullable: NULL = transport disabled
    telegram_chat_id    TEXT,           -- nullable: NULL = transport disabled
    updated_at          TEXT NOT NULL
                          DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- Seed the singleton row so UPDATE always has a target. The
-- `INSERT OR IGNORE` is defensive — re-running this migration on a
-- DB that already has the row is a no-op.
INSERT OR IGNORE INTO notification_settings (id) VALUES (1);
