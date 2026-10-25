-- Independent signing material for admin sessions; populated from OS randomness
-- on first inventory open and included in ordinary inventory backups.
CREATE TABLE admin_auth_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    session_secret TEXT NOT NULL CHECK (length(session_secret) = 43)
);
