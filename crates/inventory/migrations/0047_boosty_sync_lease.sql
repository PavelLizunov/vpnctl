ALTER TABLE boosty_settings ADD COLUMN sync_lease_owner TEXT;
ALTER TABLE boosty_settings ADD COLUMN sync_lease_until INTEGER NOT NULL DEFAULT 0;
