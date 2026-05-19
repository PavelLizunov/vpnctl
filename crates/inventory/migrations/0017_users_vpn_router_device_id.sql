-- 0017_users_vpn_router_device_id.sql — Phase 3 of the ninitux
-- subscription-server absorption (see docs/COMPREHENSIVE_AUDIT_2026-05-19.md).
--
-- Adds an OPTIONAL 32-hex device-id column to `users`. Populated by
-- the Phase 2 import script for users that already exist in
-- subscription-server's `clients.device_id`. The new vpn-router
-- compatibility handler (`GET /api/v1/app/config/{device_id}` in
-- `daemon/src/handlers/vpn_router.rs`) looks up users via this
-- column — `device_id` is the canonical lookup key in the legacy
-- ninitux URL format (e.g.
-- `https://ninitux.com/api/v1/app/config/a92b915032b48a2ed45ef72f4171e5f4`).
--
-- Column is NULLABLE because:
--   * users created via vpnctld web UI (post-migration) have no
--     ninitux equivalent yet — they get NULL and aren't reachable
--     via the compat endpoint until/unless an operator pins a
--     device_id for them
--   * the Phase 2 backfill only touches the 33 users whose names
--     match subscription-server's clients table — anyone else
--     (brat-deleted earlier, claude-chat-proxy, tester) stays NULL
--
-- Partial UNIQUE index (WHERE NOT NULL) lets multiple users have
-- NULL device_id but enforces that no two users can share the same
-- non-NULL device_id. Sing-box one-to-one (user, server, uuid)
-- model gives us 1:1 (user, device_id) here too.

ALTER TABLE users ADD COLUMN vpn_router_device_id TEXT;

CREATE UNIQUE INDEX idx_users_vpn_router_device_id
    ON users(vpn_router_device_id)
    WHERE vpn_router_device_id IS NOT NULL;
