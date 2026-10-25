-- Keep every arm of the per-server audit timeline eligible for indexed lookup.
-- Grant/revoke events, including user removal, identify the server as $.server.
CREATE INDEX IF NOT EXISTS idx_audit_payload_server_name
    ON audit_log(json_extract(payload, '$.server'));
