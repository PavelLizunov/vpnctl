CREATE TABLE new_server_bandwidth_default (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    mbps INTEGER NOT NULL CHECK (mbps BETWEEN 1 AND 4294967295),
    boosty_policy TEXT NOT NULL CHECK (json_valid(boosty_policy) AND json_type(boosty_policy) = 'object')
);
