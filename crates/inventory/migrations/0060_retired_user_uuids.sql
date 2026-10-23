-- UUIDs that once belonged to an inventory user or grant. Deploy guards treat
-- them as known, so disabling, revoking, rotating or deleting a user can drop
-- the UUID from a live node while UUIDs never seen by vpnctld stay protected.

CREATE TABLE IF NOT EXISTS retired_user_uuids (
    uuid TEXT PRIMARY KEY,
    retired_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TRIGGER IF NOT EXISTS retire_uuid_on_user_delete
BEFORE DELETE ON users
BEGIN
    INSERT OR IGNORE INTO retired_user_uuids (uuid) VALUES (old.uuid);
    INSERT OR IGNORE INTO retired_user_uuids (uuid)
        SELECT client_uuid FROM grants
         WHERE user_id = old.id AND client_uuid IS NOT NULL;
END;

CREATE TRIGGER IF NOT EXISTS retire_uuid_on_user_uuid_change
AFTER UPDATE OF uuid ON users
WHEN old.uuid IS NOT new.uuid
BEGIN
    INSERT OR IGNORE INTO retired_user_uuids (uuid) VALUES (old.uuid);
END;

CREATE TRIGGER IF NOT EXISTS retire_uuid_on_grant_delete
AFTER DELETE ON grants
WHEN old.client_uuid IS NOT NULL
BEGIN
    INSERT OR IGNORE INTO retired_user_uuids (uuid) VALUES (old.client_uuid);
END;

CREATE TRIGGER IF NOT EXISTS retire_uuid_on_grant_uuid_change
AFTER UPDATE OF client_uuid ON grants
WHEN old.client_uuid IS NOT NULL AND old.client_uuid IS NOT new.client_uuid
BEGIN
    INSERT OR IGNORE INTO retired_user_uuids (uuid) VALUES (old.client_uuid);
END;
