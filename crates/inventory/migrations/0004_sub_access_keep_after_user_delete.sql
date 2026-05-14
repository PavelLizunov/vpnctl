-- Phase Hardening (caught by retroactive review-agent + security-review
-- 2026-05-14): change `sub_access_log.user_id` foreign key from
-- `ON DELETE CASCADE` to `ON DELETE SET NULL`.
--
-- Why
-- ---
-- With CASCADE, deleting a user (Phase C-3.4 — not yet shipped, but
-- the schema bakes the behaviour in) atomically dropped every row of
-- their `sub_access_log`. That's the exact moment you might want the
-- forensic trail preserved: "this user was being abuse-pulled 50x/min
-- from an unfamiliar IP, then I deleted them — what was the IP?"
--
-- With SET NULL the row survives; only the FK link to `users` clears.
-- The existing `distinct_ips_for_user(WHERE user_id = ?1)` query
-- naturally excludes orphaned rows (they no longer match any user).
-- Operators retain the ability to scan `WHERE user_id IS NULL` to
-- inspect the abuse history of deleted users.
--
-- SQLite has no `ALTER TABLE ... DROP CONSTRAINT`, so the canonical
-- way to change a foreign key is the table-rebuild dance
-- (https://www.sqlite.org/lang_altertable.html § "Making Other Kinds
-- Of Table Schema Changes"). We:
--   1. Create a new table with the desired schema (FK SET NULL,
--      user_id nullable to permit the SET NULL outcome).
--   2. Copy every row across.
--   3. Drop the old, rename the new, recreate the indexes.
--
-- Performance: production data set today is <1k rows on the homelab.
-- Even at 100k+ rows the rebuild runs in well under a second. If we
-- ever scale past that, switch to incremental archival before
-- migrating.

CREATE TABLE sub_access_log_new (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    -- user_id is now nullable: `ON DELETE SET NULL` requires it.
    -- Existing application code must already tolerate this in queries
    -- — `WHERE user_id = ?1` excludes NULL rows naturally.
    user_id   TEXT    REFERENCES users(id) ON DELETE SET NULL,
    ip        TEXT    NOT NULL,
    ua        TEXT,
    status    INTEGER NOT NULL,
    bytes     INTEGER NOT NULL DEFAULT 0
);

INSERT INTO sub_access_log_new (id, ts, user_id, ip, ua, status, bytes)
    SELECT id, ts, user_id, ip, ua, status, bytes FROM sub_access_log;

DROP TABLE sub_access_log;
ALTER TABLE sub_access_log_new RENAME TO sub_access_log;

-- Same indexes as 0003 — drop+rename loses them along with the table.
CREATE INDEX idx_sub_access_log_user_ts ON sub_access_log (user_id, ts DESC);
CREATE INDEX idx_sub_access_log_ts ON sub_access_log (ts DESC);
