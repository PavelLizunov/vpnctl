-- Subscription-access log — one row per `/sub/<token>` HTTP request,
-- written best-effort by the daemon AFTER the user has been resolved
-- from the token. Purpose is abuse detection (Phase Track-1):
--
--   * how many distinct IPs hit one user's subscription URL?
--   * is there a request rate that suggests a scraper?
--   * which User-Agent strings show up — fingerprinting client type
--     (Hiddify vs raw sing-box vs unknown HTTP client).
--
-- The token itself is NEVER stored here — we only keep the resolved
-- `user_id` so a row alone can't replay the request. If the user is
-- deleted (Phase C-3 chunk 4) the FK CASCADE drops their access rows.
--
-- Retention: rows are purged by `purge_sub_access_older_than(days)`
-- on a schedule defined by the daemon (default 30 days). Long-term
-- aggregates land in a separate rollup table later (Phase Track-3).

CREATE TABLE sub_access_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    -- ISO-8601 with millisecond resolution. Default uses the SQLite
    -- builtin so callers can omit it and tests can override deterministically.
    ts        TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    user_id   TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- Source IP as observed by axum's ConnectInfo. For a LAN deployment
    -- this is the real client IP. When the daemon eventually sits behind
    -- a reverse proxy we will need to honour `X-Forwarded-For` (only
    -- when the immediate peer is in a trusted-proxy allowlist).
    ip        TEXT    NOT NULL,
    -- Optional User-Agent header. Many clients (curl scripts, mis-
    -- configured ones) omit it; storing NULL beats inventing a fake.
    ua        TEXT,
    -- Final HTTP status: 200 happy path, 404 unknown-token, 500 render
    -- failure. Lets us spot probing (lots of 404s from one IP).
    status    INTEGER NOT NULL,
    -- Response body size in bytes. Useful for spotting scrapers that
    -- pull the whole config repeatedly (vs Hiddify's once-per-day
    -- refetch shape).
    bytes     INTEGER NOT NULL DEFAULT 0
);

-- Per-user lookups (the dominant query — "show this user's recent IPs").
CREATE INDEX idx_sub_access_log_user_ts ON sub_access_log (user_id, ts DESC);

-- Time-only lookups for the dashboard's global "abuse signals" tile
-- and for the retention purge.
CREATE INDEX idx_sub_access_log_ts ON sub_access_log (ts DESC);
