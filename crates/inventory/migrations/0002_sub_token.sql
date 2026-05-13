-- Subscription tokens for users.
--
-- Each user gets an opaque, URL-safe token. The daemon's `/sub/<token>`
-- endpoint resolves it to a user and returns their sing-box JSON config.
-- Hiddify-style clients subscribe once and re-pull on a schedule, so
-- key/secret rotation on our side becomes invisible to the end user.
--
-- The column is nullable to keep the migration cheap; backfill happens
-- in code (SqliteInventory::open ensures every existing user has a
-- non-null token after migrate).

ALTER TABLE users ADD COLUMN sub_token TEXT;

-- Unique among non-null tokens. (Partial index — empty/null tokens are
-- allowed during backfill but get filled in immediately.)
CREATE UNIQUE INDEX idx_users_sub_token ON users(sub_token)
    WHERE sub_token IS NOT NULL;
