-- Migration 0009 — multi-kernel servers.
--
-- Why: one physical VPS can host multiple kernel daemons simultaneously
--   (sing-box on :443/TCP + amneziawg on :51820/UDP, different binaries,
--   different systemd units, no port conflict). Pre-this commit the
--   single `servers.kernel` column forced a 1:1 mapping, so an operator
--   wanting both sing-box and amneziawg on one node had to add the same
--   IP twice as two server records — a structural mismatch with reality
--   (Pavel 2026-05-16: «а что на 1 сервере не может быть 2 ядра?»).
--
-- Schema delta:
--   * New table `server_kernels(server_id, kernel_id)` — PK on the pair,
--     FK CASCADE on server delete so kernel rows can't outlive their
--     server.
--   * Drop `servers.kernel` column; the `server_kernels` table is now
--     the single source of truth.
--
-- Data migration:
--   * Every existing `servers.kernel = '<k>'` row becomes
--     `server_kernels (id, '<k>')`. Net effect for existing operators:
--     identical behaviour (each server still has its one kernel), the
--     only difference is the storage layer.
--
-- SQLite specifics:
--   * `ALTER TABLE … DROP COLUMN` requires SQLite ≥ 3.35.0 (March 2021).
--     Bookworm ships 3.40.x, so this is safe on our deployment target.
--     If a downstream user runs an older SQLite, the migration fails
--     loud at apply time — better than silent data loss.
--   * We do NOT use the "rename + recreate + copy" workaround because
--     it would break ongoing transactions across the FK from
--     `grants.server_id` to `servers.id` (the FK target row would
--     change identity).

CREATE TABLE IF NOT EXISTS server_kernels (
    server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    kernel_id TEXT NOT NULL,
    PRIMARY KEY (server_id, kernel_id)
);

-- Migrate existing single-kernel rows. SELECT id, kernel may include
-- the same id twice if anything weird happened, but the PK on the new
-- table makes duplicates a no-op via the implicit unique constraint.
INSERT OR IGNORE INTO server_kernels (server_id, kernel_id)
    SELECT id, kernel FROM servers;

-- Drop the now-redundant column. After this, the only way to read a
-- server's kernels is the new table — application code MUST be
-- updated in the same release.
ALTER TABLE servers DROP COLUMN kernel;
