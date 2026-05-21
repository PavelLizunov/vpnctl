-- Phase 4a: VPN-egress flag on sub_access_log.
--
-- Pavel 2026-05-21: «хочу видеть только настоящий ip». When a user
-- in full-tunnel mode opens /api/v1/app/config/<device_id> from the
-- VPNRouter app, the request's src IP is the IP of the VPN server
-- they're currently routed through — NOT the user's real device IP.
-- That's expected wire behaviour (the whole point of full-tunnel),
-- but it noisily pollutes the per-user IP timeline on
-- /admin/users/<id> with our OWN server addresses, which carry zero
-- operator-actionable signal.
--
-- Concrete numbers on 192.168.0.236 the day of this migration:
--   * 65 / 246 rows in sub_access_log have src IP matching one of
--     the 3 production VPN-server addresses
--     (104.194.156.93, 84.19.3.104, 93.95.226.167) = 26%.
--   * 10 / 33 distinct users affected.
-- Without the flag these 26% drown the genuine signal — admin sees
-- the same VPN-server IP repeated for every full-tunnel session.
--
-- Storage: one INTEGER NOT NULL DEFAULT 0 column. 0 = client
-- contacted us directly (real device IP), 1 = client's full-tunnel
-- egress hit us through one of our own VPN servers.
--
-- Maintenance: a SQL trigger AFTER INSERT auto-flags new rows by
-- comparing NEW.ip against `servers.address` set. This means:
--   * adding a new VPN server in inventory → flag works immediately
--     for that server's IP without any vpnctld restart (the trigger
--     reads servers table on every insert),
--   * removing a server → its old IP stops being flagged on new
--     inserts (existing rows keep their flag — historical view
--     stays correct),
--   * NO Rust-side cache state to invalidate. The whole feature
--     is pure-SQL apart from the rendering toggle.
--
-- Backfill: UPDATE existing rows once at migration time so the
-- pre-migration history immediately gains the flag for the
-- currently-known server addresses. Cost: one indexed scan.
--
-- Index: partial index on `is_vpn_egress = 0` so the default-render
-- query (which filters egress rows OUT) doesn't pay for them. The
-- 0-row subset is the hot path; 1-row subset only loads when the
-- operator clicks «show VPN-egress».
--
-- Keyed by `(user_id, id DESC)` because the user-detail handler's
-- query orders by `id DESC` (= insertion order, monotone autoincrement
-- ≈ ts DESC but resolved on the rowid index without a sort step).
-- An earlier draft used `ts DESC` which made SQLite still sort the
-- result set (review-agent Phase 4a, finding #2); the id-DESC variant
-- can serve the ORDER BY straight from the index.

ALTER TABLE sub_access_log ADD COLUMN is_vpn_egress INTEGER NOT NULL DEFAULT 0;

-- Trigger: auto-flag new rows whose src IP matches any current
-- VPN server's address. AFTER INSERT (NOT BEFORE INSERT) because:
--   * SQLite's NEW.* is read-only inside BEFORE INSERT triggers on
--     real tables (writability is a property of INSTEAD OF triggers
--     on VIEWs only, despite what some 3rd-party docs suggest).
--   * Generated columns (`GENERATED ALWAYS AS …`) would let us
--     avoid the trigger entirely, but SQLite forbids subqueries
--     inside generated-column expressions.
-- So an AFTER-INSERT UPDATE is the cleanest pure-SQL path. Write
-- amplification = 2 writes per insert ONLY for egress rows
-- (gated by the WHEN clause); real-client rows pay one write,
-- same as before. Recursion impossible — no UPDATE trigger on
-- this table, and SQLite default `recursive_triggers = OFF`.
CREATE TRIGGER sub_access_log_mark_vpn_egress
AFTER INSERT ON sub_access_log
WHEN NEW.ip IN (SELECT address FROM servers)
BEGIN
    UPDATE sub_access_log SET is_vpn_egress = 1 WHERE id = NEW.id;
END;

-- Backfill — one-shot at migration time for the pre-existing
-- history. Subsequent inserts go through the trigger above.
UPDATE sub_access_log
SET is_vpn_egress = 1
WHERE ip IN (SELECT address FROM servers);

-- Partial index — the default per-user view filters egress out, so
-- this index covers the hot path with no entries for the 26% we
-- normally hide.
CREATE INDEX idx_sub_access_log_user_id_real
ON sub_access_log (user_id, id DESC)
WHERE is_vpn_egress = 0;
