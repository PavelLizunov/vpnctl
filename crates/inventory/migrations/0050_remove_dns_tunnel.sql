-- Migration 0050 — Remove dns-tunnel protocol, kernel, and grant overrides.
--
-- Preserves all dns-tunnel:* secrets as rollback material (does not delete them).
-- For each server with active dns-tunnel data (server_protocols, server_kernels,
-- or grant_protocol_overrides), insert one audit log row with action
-- 'protocol.remove_dns_tunnel' and payload JSON recording counts of removed entities
-- and retained server secrets.
-- Then safely delete grant overrides, server_protocols, and server_kernels.
-- Historical audit log rows are preserved. Empty / non-dns-tunnel databases receive zero audit rows.
-- A server with only stale secrets receives no audit row.

WITH affected_servers AS (
    SELECT server_id FROM server_protocols WHERE protocol_id = 'dns-tunnel'
    UNION
    SELECT server_id FROM server_kernels WHERE kernel_id = 'dns-tunnel'
    UNION
    SELECT server_id FROM grant_protocol_overrides WHERE protocol_id = 'dns-tunnel'
),
counts AS (
    SELECT
        a.server_id AS server_id,
        (SELECT COUNT(*) FROM grant_protocol_overrides gpo WHERE gpo.server_id = a.server_id AND gpo.protocol_id = 'dns-tunnel') AS grant_overrides,
        (SELECT COUNT(*) FROM server_protocols sp WHERE sp.server_id = a.server_id AND sp.protocol_id = 'dns-tunnel') AS server_protocols,
        (SELECT COUNT(*) FROM server_kernels sk WHERE sk.server_id = a.server_id AND sk.kernel_id = 'dns-tunnel') AS server_kernels,
        (SELECT COUNT(*) FROM server_secrets ss WHERE ss.server_id = a.server_id AND ss.key LIKE 'dns-tunnel:%') AS retained_server_secrets
    FROM affected_servers a
)
INSERT INTO audit_log (actor, action, target, payload)
SELECT
    'system',
    'protocol.remove_dns_tunnel',
    server_id,
    json_object(
        'server_id', server_id,
        'grant_overrides', grant_overrides,
        'server_protocols', server_protocols,
        'server_kernels', server_kernels,
        'retained_server_secrets', retained_server_secrets
    )
FROM counts
WHERE (grant_overrides + server_protocols + server_kernels) > 0
ORDER BY server_id ASC;

DELETE FROM grant_protocol_overrides WHERE protocol_id = 'dns-tunnel';
DELETE FROM server_protocols WHERE protocol_id = 'dns-tunnel';
DELETE FROM server_kernels WHERE kernel_id = 'dns-tunnel';
