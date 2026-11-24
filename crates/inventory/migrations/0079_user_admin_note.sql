CREATE TABLE user_admin_notes (
    user_id TEXT PRIMARY KEY NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    note TEXT NOT NULL
);
