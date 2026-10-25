-- Keep exact last activity when its source history is deleted. Quiet VPN ticks
-- and server-wide observations must never turn an unused account into a used one.
ALTER TABLE users ADD COLUMN last_activity_at TEXT;

CREATE TRIGGER users_last_activity_audit
AFTER UPDATE OF last_activity_at ON users
WHEN NEW.last_activity_at IS NOT OLD.last_activity_at
BEGIN
    INSERT INTO audit_log (actor, action, target)
    VALUES ('system', 'user.last_activity', NEW.id);
END;

UPDATE users SET last_activity_at = (
    SELECT MAX(ts) FROM (
        SELECT ts FROM sub_access_log WHERE user_id = users.id
        UNION ALL
        SELECT ts FROM vpn_connection_stats
        WHERE user_id = users.id
          AND (upload_bytes > 0 OR download_bytes > 0 OR active_connections > 0)
        UNION ALL
        SELECT last_seen AS ts FROM vpn_user_sessions WHERE user_id = users.id
        UNION ALL
        SELECT date || 'T00:00:00.000Z' AS ts FROM vpn_user_daily
        WHERE user_id = users.id
          AND (upload_bytes > 0 OR download_bytes > 0 OR active_connections_peak > 0)
    )
);

CREATE TRIGGER sub_access_preserve_last_activity
BEFORE DELETE ON sub_access_log
WHEN OLD.user_id IS NOT NULL
BEGIN
    UPDATE users SET last_activity_at = OLD.ts
    WHERE id = OLD.user_id
      AND (last_activity_at IS NULL OR last_activity_at < OLD.ts);
END;

CREATE TRIGGER vpn_stats_preserve_last_activity
BEFORE DELETE ON vpn_connection_stats
WHEN OLD.user_id IS NOT NULL
 AND (OLD.upload_bytes > 0 OR OLD.download_bytes > 0 OR OLD.active_connections > 0)
BEGIN
    UPDATE users SET last_activity_at = OLD.ts
    WHERE id = OLD.user_id
      AND (last_activity_at IS NULL OR last_activity_at < OLD.ts);
END;

CREATE TRIGGER vpn_sessions_preserve_last_activity
BEFORE DELETE ON vpn_user_sessions
BEGIN
    UPDATE users SET last_activity_at = OLD.last_seen
    WHERE id = OLD.user_id
      AND (last_activity_at IS NULL OR last_activity_at < OLD.last_seen);
END;
