-- Grace period and safe automatic provisioning for the Boosty bridge.

ALTER TABLE users ADD COLUMN boosty_lapsed_since INTEGER;

ALTER TABLE boosty_settings
    ADD COLUMN grace_days INTEGER NOT NULL DEFAULT 14
        CHECK (grace_days BETWEEN 0 AND 365);

ALTER TABLE boosty_settings
    ADD COLUMN auto_create_users INTEGER NOT NULL DEFAULT 0
        CHECK (auto_create_users IN (0, 1));
