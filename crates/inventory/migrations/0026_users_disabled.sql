-- 0026_users_disabled.sql — temporary user suspension flag (audit B1.user).
--
-- Pre-2026-05-22 the only way an operator could «pause» a user
-- without rotating their secrets was to revoke every grant — then
-- re-grant later, which lost the per-(user,server) protocol-override
-- state and forced cache invalidation on every client. The
-- `disabled` flag is a soft mute on the subscription pipeline:
-- when true, `/sub/<token>` and `/api/v1/app/config/<device_id>`
-- render an EMPTY config (no protocols visible). The user's
-- secrets, UUID, sub_token, WG keypair, and grants all stay
-- intact, so flipping `disabled` back to false restores access
-- byte-for-byte.
--
-- Default NOT disabled (`0`) so the schema change is observable-
-- behaviour-neutral on rollout — every existing row reads as
-- `disabled = 0`. No backfill needed.
--
-- BOOLEAN-as-INTEGER follows the existing convention
-- (`server_protocols.hidden`, `node_health.sing_box_active`).

ALTER TABLE users
    ADD COLUMN disabled INTEGER NOT NULL DEFAULT 0;

-- Partial index on the (admittedly small) set of disabled users —
-- both the sub-render filter («skip this user's protocols if
-- disabled») and the dashboard «N disabled users» tile (future
-- bundle) want a fast scan of just the disabled rows. Empty index
-- on a fleet with zero disabled users → ~free.
CREATE INDEX idx_users_disabled_partial
    ON users(id)
    WHERE disabled = 1;
