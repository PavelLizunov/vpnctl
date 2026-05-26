-- 2026-05-26 — per-server «reserved ports» list (Pavel:
-- «важно конкретно для этого сервера заблокировать часть
-- функционала, чтоб через админку нельзя было что-то перетереть»).
--
-- Background: 194.87.222.111 runs a legacy 3x-ui Docker container
-- on :443 (xray VLESS-Reality) + :2053/:2096 (panel + sub) that
-- vpnctl must NEVER touch. The old plain sing-box on the same host
-- on :8443/:2083 is fair game (sole operator, expendable). vpnctl
-- can deploy its own sing-box on the free ports, but a future
-- accidental operator action (adding a protocol that defaults to
-- :443, restoring an older config snapshot, etc.) could overwrite
-- the 3x-ui inbound and silently break ~all clients on that host.
--
-- This column stores a JSON array of TCP/UDP port numbers (u16) that
-- the daemon refuses to bind via sing-box on this server. The
-- enforcement lives in `kernels::sing_box::validate_config_excludes_ports`
-- (DG-1-style pre-apply guard) called from every `apply_config` site
-- (CLI deploy, daemon deploy, wizard bootstrap). Empty array = no
-- reservation = current behaviour, byte-identical for existing
-- de/fi/is servers.
--
-- Format: JSON array of u16 (e.g. `[443, 2053, 2096]`). Empty list
-- is `'[]'`. Validation lives in the inventory layer
-- (`set_reserved_ports`) — column TEXT keeps the schema flexible
-- without an extra CHECK constraint.

ALTER TABLE servers
    ADD COLUMN reserved_ports TEXT NOT NULL DEFAULT '[]';
