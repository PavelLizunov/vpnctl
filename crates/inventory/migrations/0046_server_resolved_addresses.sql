-- Canonical IPs currently resolved for each server address.
--
-- `servers.address` accepts hostnames, while request peers and clash
-- metadata arrive as canonical IP strings. Cache the resolved identities so
-- rate limiting and sharing detection use the same server-address set.
CREATE TABLE server_resolved_addresses (
    server_id TEXT NOT NULL,
    address   TEXT NOT NULL,
    PRIMARY KEY (server_id, address),
    FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE
);

CREATE INDEX idx_server_resolved_addresses_address
    ON server_resolved_addresses(address);

DROP TRIGGER IF EXISTS sub_access_log_mark_vpn_egress;
CREATE TRIGGER sub_access_log_mark_vpn_egress
AFTER INSERT ON sub_access_log
WHEN NEW.ip IN (SELECT address FROM servers)
  OR NEW.ip IN (SELECT address FROM server_resolved_addresses)
BEGIN
    UPDATE sub_access_log SET is_vpn_egress = 1 WHERE id = NEW.id;
END;
