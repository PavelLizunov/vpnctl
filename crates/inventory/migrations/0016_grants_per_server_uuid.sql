-- 0016_grants_per_server_uuid.sql — per-server VLESS UUIDs (Phase 1
-- of the ninitux subscription-server absorption — see
-- docs/COMPREHENSIVE_AUDIT_2026-05-19.md).
--
-- Why this column exists
-- ----------------------
-- Until this migration, vpnctl assumed ONE VLESS uuid per user
-- (`users.uuid`), rendered into every server's sing-box config + every
-- vless:// share-link. That assumption was incompatible with the way
-- the bash project's successor (`ninitux.com / subscription-server`)
-- assigned identities: distinct uuid per (user, server) pair so that
--   (a) per-server revocation works without touching other servers,
--   (b) clash-api traffic stats key cleanly to (server, uuid → user),
--   (c) a leaked uuid set on one server is isolated from the others.
--
-- The 2026-05-18 vps-de-01 incident happened because vpnctld kept
-- pushing the vps-is-01-column uuids it had imported from bash to
-- a server whose live config carried the ninitux vps-de-01-column
-- uuids — silent UUID divergence took 22 of 23 ninitux user URLs
-- out for a day before Pavel noticed.
--
-- What this migration does
-- ------------------------
-- Adds a nullable `client_uuid` column to `grants`. The render path
-- treats it as the per-server UUID override:
--
--   effective_uuid_for_grant = COALESCE(grants.client_uuid, users.uuid)
--
-- Backfill sets every existing grant's `client_uuid` to the user's
-- global uuid — preserves current byte-for-byte rendering of every
-- /sub/<token> response. AFTER the backfill, an import script
-- (Phase 2) overwrites `client_uuid` for the per-server distinct
-- uuids harvested from subscription-server's `client_server_links`
-- table — at THAT point share-links diverge per server, by design.
--
-- Rollback: drop the column. Renderer falls back to users.uuid.
-- Safe as long as the live sing-box config on each managed server
-- doesn't yet carry per-server uuids vpnctld doesn't also know.

ALTER TABLE grants ADD COLUMN client_uuid TEXT;

-- Backfill from users.uuid — every existing grant gets the user's
-- current global uuid as its effective per-server uuid. NO rendering
-- change: COALESCE(g.client_uuid, u.uuid) equals u.uuid for every
-- row before AND after the backfill — but after the backfill the
-- column is populated, so a later Phase 2 import can change individual
-- entries without touching `users.uuid` (which stays the user's
-- identity, not their auth secret).
UPDATE grants
SET client_uuid = (SELECT uuid FROM users WHERE users.id = grants.user_id)
WHERE client_uuid IS NULL;

-- Orphan-grant invariant: the FK ON DELETE CASCADE in 0001_init.sql
-- guarantees a grant cannot survive its user — so the UPDATE above
-- always finds a `users.uuid` to copy and never leaves NULL. If a
-- future migration ever DROPs that FK (or someone toggled
-- `PRAGMA foreign_keys=OFF` during a prior schema change), an orphan
-- row would slip through here with `client_uuid` still NULL; the
-- runtime read path falls back to `users.uuid` via COALESCE, and for
-- an orphan that lookup returns NULL too — which sing-box would
-- reject on next deploy as «empty uuid». Diagnosed at deploy time,
-- not at migration time. (Earlier draft used `SELECT RAISE(ABORT, …)`
-- to fail the migration loudly here, but SQLite forbids `RAISE()`
-- outside trigger bodies — caught by the inventory test suite.)
