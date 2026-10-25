-- Preserve the enabled, granted users_for_server ordering, including peers
-- without WireGuard keys. Disabled grants receive an address lazily on enable.
ALTER TABLE grants ADD COLUMN wg_octet INTEGER;

CREATE UNIQUE INDEX idx_grants_server_wg_octet
    ON grants(server_id, wg_octet) WHERE wg_octet IS NOT NULL;

WITH ranked AS (
    SELECT g.user_id, g.server_id,
           1 + ROW_NUMBER() OVER (PARTITION BY g.server_id ORDER BY u.id) AS octet
    FROM grants g JOIN users u ON u.id = g.user_id
    WHERE u.disabled = 0
)
UPDATE grants SET wg_octet = (
    SELECT octet FROM ranked
    WHERE ranked.user_id = grants.user_id AND ranked.server_id = grants.server_id
)
WHERE user_id IN (SELECT id FROM users WHERE disabled = 0);

INSERT INTO audit_log (actor, action, target, payload)
SELECT 'system', 'grant.wg_octet.assign', user_id,
       json_object('server', server_id, 'wg_octet', wg_octet, 'source', 'migration.0066')
FROM grants WHERE wg_octet IS NOT NULL;
