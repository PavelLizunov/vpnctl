-- Design v2 3d — the server-detail Grants table shows WHEN each grant
-- was made. Nullable: SQLite can't ALTER-ADD a column with a
-- non-constant default, so the INSERT path stamps datetime('now')
-- explicitly and pre-existing grants render as "—".
ALTER TABLE grants ADD COLUMN granted_at TEXT;
