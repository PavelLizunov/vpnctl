-- 2026-05-23 — operator-configurable display timezone (Pavel:
-- «правильнее было чтоб часовой пояс можно было менять через
-- настройки»).
--
-- Single-row settings table (id = 1, enforced via CHECK) holding
-- per-instance UI rendering preferences. Starts with one field:
-- `timezone` — an IANA timezone name (e.g. «Europe/Moscow»,
-- «America/New_York», «UTC»). Used by `format_local_iso` to
-- convert stored UTC timestamps to operator's local time on
-- every UI surface.
--
-- Default «Europe/Moscow» preserves the behaviour shipped in
-- 14b17df (the MSK sweep) for the current single-operator
-- instance. A future second-instance operator picks their own
-- via /admin/settings.
--
-- Singleton-row pattern matches the existing notification_settings
-- table (migration 0014): one row, enforced via PRIMARY KEY + DEFAULT,
-- INSERT seed below so handlers can always SELECT-then-UPDATE without
-- a missing-row branch.

CREATE TABLE display_settings (
    id        INTEGER PRIMARY KEY CHECK (id = 1),
    timezone  TEXT    NOT NULL DEFAULT 'Europe/Moscow'
);

-- Seed the singleton row so callers can rely on SELECT returning
-- a row. Operator-mutable; future migrations adding fields use
-- `ALTER TABLE display_settings ADD COLUMN <name> <type> DEFAULT <v>`.
INSERT INTO display_settings(id) VALUES (1);
