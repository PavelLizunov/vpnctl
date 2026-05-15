-- Phase Track-2 chunk 2 — persistent auto-bans for /sub abuse.
--
-- Background: Track-2 chunk 1 ships a token-bucket rate limiter. This
-- protects against burst, but a determined attacker who steady-states
-- right at the rate limit can keep hitting 429 forever with no
-- escalation. Chunk 2 adds the escalation: after K consecutive 429s
-- for the same key, the daemon writes a row here valid for 24h. The
-- rate limiter's `try_acquire_*` consults this table BEFORE the
-- bucket check, so a banned key gets 429 immediately without spending
-- any bucket math.
--
-- Persistence (vs the in-memory buckets / counters) means a daemon
-- restart does NOT reset bans — that's the whole point. An attacker
-- can't trigger our own restart (e.g. systemd auto-restart on crash)
-- to clear their ban.

CREATE TABLE sub_rate_bans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    -- ISO-8601 with millisecond resolution, same convention as
    -- sub_access_log.ts (see migration 0003 + the timestamp-format
    -- fix in commit fad0adf — both query-side cutoffs and write-side
    -- defaults must use the strftime form, never datetime()).
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    until_ts    TEXT    NOT NULL,
    -- 'ip' | 'token'. Indexed alongside `key` so the existence-check
    -- query (`WHERE kind = ? AND key = ? AND until_ts > now`) hits
    -- a single index entry.
    kind        TEXT    NOT NULL CHECK (kind IN ('ip', 'token')),
    -- The IP literal (v4 dotted, v6 colon-hex) OR the sub_token
    -- string. Stored verbatim — no decoding, no normalisation.
    key         TEXT    NOT NULL,
    -- Operator-readable note ("10 consecutive 429s in 60s"). Free-text;
    -- consumed by the admin UI's "Active bans" surface, not by code.
    reason      TEXT    NOT NULL DEFAULT ''
);

-- Hot lookup: is THIS (kind, key) banned right now? The until_ts
-- predicate is also covered so the index alone answers the query.
CREATE INDEX idx_sub_rate_bans_kind_key_until
    ON sub_rate_bans (kind, key, until_ts);

-- Sweep cutoff: which rows are now expired? Used by the periodic
-- cleanup task to keep the table from accumulating stale entries.
CREATE INDEX idx_sub_rate_bans_until ON sub_rate_bans (until_ts);
