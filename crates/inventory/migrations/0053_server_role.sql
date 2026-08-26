-- Server role: 'vpn-exit' (default) vs 'workload-only' (inventory-only, no VPN grants/subscription).
ALTER TABLE servers ADD COLUMN role TEXT NOT NULL DEFAULT 'vpn-exit' CHECK (role IN ('vpn-exit', 'workload-only'));

CREATE TRIGGER trg_workload_role_rejects_grants
BEFORE UPDATE OF role ON servers
WHEN NEW.role = 'workload-only' AND EXISTS (SELECT 1 FROM grants WHERE server_id = NEW.id)
BEGIN
  SELECT RAISE(ABORT, 'workload-only server cannot retain grants');
END;

CREATE TRIGGER trg_server_rejects_nested_jump_insert
BEFORE INSERT ON servers
WHEN NEW.jump_via IS NOT NULL AND (
  NEW.jump_via = NEW.id
  OR EXISTS (SELECT 1 FROM servers j WHERE j.id = NEW.jump_via AND j.jump_via IS NOT NULL)
)
BEGIN
  SELECT RAISE(ABORT, 'nested or self jump routes are not allowed');
END;

CREATE TRIGGER trg_server_rejects_nested_jump
BEFORE UPDATE OF jump_via ON servers
WHEN NEW.jump_via IS NOT NULL AND (
  NEW.jump_via = NEW.id
  OR EXISTS (SELECT 1 FROM servers j WHERE j.id = NEW.jump_via AND j.jump_via IS NOT NULL)
  OR EXISTS (SELECT 1 FROM servers d WHERE d.jump_via = NEW.id)
)
BEGIN
  SELECT RAISE(ABORT, 'nested jump routes are not allowed');
END;

CREATE TRIGGER trg_grant_rejects_workload_role
BEFORE INSERT ON grants
WHEN (SELECT role FROM servers WHERE id = NEW.server_id) = 'workload-only'
BEGIN
  SELECT RAISE(ABORT, 'workload-only server cannot receive grants');
END;
