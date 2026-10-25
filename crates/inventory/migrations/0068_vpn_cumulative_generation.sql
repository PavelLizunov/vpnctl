-- NULL retains the legacy uptime/counter restart heuristic until a token is known.
ALTER TABLE vpn_server_counter_baselines ADD COLUMN generation TEXT;

CREATE TRIGGER vpn_counter_generation_insert_audit
AFTER INSERT ON vpn_server_counter_baselines
WHEN NEW.generation IS NOT NULL
BEGIN
    INSERT INTO audit_log (actor, action, target)
    VALUES ('system', 'vpn_stats.generation', NEW.server_id);
END;

CREATE TRIGGER vpn_counter_generation_update_audit
AFTER UPDATE OF generation ON vpn_server_counter_baselines
WHEN OLD.generation IS NOT NEW.generation
BEGIN
    INSERT INTO audit_log (actor, action, target)
    VALUES ('system', 'vpn_stats.generation', NEW.server_id);
END;
