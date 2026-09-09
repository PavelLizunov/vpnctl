-- Preserve all historical telemetry, including pre-provisioning failures.
-- Legacy populations cannot be reconstructed from counts; NULL identifies
-- unpartitioned history, which remains available through the raw history API.
ALTER TABLE server_quality_samples ADD COLUMN target_identity TEXT;
ALTER TABLE server_quality_samples ADD COLUMN measurement_epoch TEXT;
CREATE INDEX idx_server_quality_samples_epoch
    ON server_quality_samples(server_id, measurement_epoch, ts);

-- Audit history intentionally survives deleting a server. New incarnations
-- must not inherit its old successful deploy, even within one millisecond.
ALTER TABLE servers ADD COLUMN quality_deploy_audit_floor INTEGER NOT NULL DEFAULT 0;
-- Exclude ambiguous same-millisecond historical deploys conservatively: their
-- incarnation is unknowable, so quality stays unknown until a new deploy.
-- Future inserts use monotonic audit IDs and do not have that ambiguity.
UPDATE servers SET quality_deploy_audit_floor = COALESCE((
    SELECT MAX(id) FROM audit_log
    WHERE target = servers.id AND julianday(ts) <= julianday(servers.created_at)
), 0);
CREATE TRIGGER server_quality_new_incarnation AFTER INSERT ON servers
BEGIN
    UPDATE servers SET quality_deploy_audit_floor =
        (SELECT COALESCE(MAX(id), 0) FROM audit_log)
    WHERE id = NEW.id;
END;
