-- Client 2-hop VPN detour: inventory-only policy where target server outbounds dial via upstream server.
ALTER TABLE servers ADD COLUMN client_detour_via TEXT REFERENCES servers(id) ON DELETE SET NULL;

CREATE TRIGGER trg_server_rejects_invalid_client_detour_insert
BEFORE INSERT ON servers
WHEN NEW.client_detour_via IS NOT NULL AND (
  NEW.client_detour_via = NEW.id
  OR NEW.role != 'vpn-exit'
  OR (SELECT role FROM servers WHERE id = NEW.client_detour_via) != 'vpn-exit'
  OR EXISTS (SELECT 1 FROM servers u WHERE u.id = NEW.client_detour_via AND u.client_detour_via IS NOT NULL)
  OR EXISTS (SELECT 1 FROM servers d WHERE d.client_detour_via = NEW.id)
)
BEGIN
  SELECT RAISE(ABORT, 'invalid client_detour_via configuration');
END;

CREATE TRIGGER trg_server_rejects_invalid_client_detour_update
BEFORE UPDATE OF client_detour_via, role ON servers
WHEN NEW.client_detour_via IS NOT NULL AND (
  NEW.client_detour_via = NEW.id
  OR NEW.role != 'vpn-exit'
  OR (SELECT role FROM servers WHERE id = NEW.client_detour_via) != 'vpn-exit'
  OR EXISTS (SELECT 1 FROM servers u WHERE u.id = NEW.client_detour_via AND u.client_detour_via IS NOT NULL)
  OR EXISTS (SELECT 1 FROM servers d WHERE d.client_detour_via = NEW.id AND d.id != NEW.id)
)
BEGIN
  SELECT RAISE(ABORT, 'invalid client_detour_via configuration');
END;

CREATE TRIGGER trg_workload_role_rejects_client_detour
BEFORE UPDATE OF role ON servers
WHEN NEW.role = 'workload-only' AND (
  NEW.client_detour_via IS NOT NULL
  OR EXISTS (SELECT 1 FROM servers WHERE client_detour_via = NEW.id)
)
BEGIN
  SELECT RAISE(ABORT, 'workload-only server cannot participate in client detour');
END;
