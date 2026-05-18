-- Phase G — operator-facing infra alerts.
--
-- Written by `daemon::health_monitor::scan_state_changes` on every
-- tick when a node_health snapshot's `sing_box_active` /
-- `fail2ban_active` flips relative to the previous snapshot, OR when
-- `disk_pct >= 90` / `mem_used_pct >= 95` / `sing_box_log_bytes >
-- 500 MiB` thresholds are crossed. One row per state-change event
-- (NOT per tick — quiet ticks stay quiet).
--
-- Operator-visible surfaces:
--   * dashboard tile «N unacked alerts» (linked to /admin/alerts)
--   * /admin/alerts feed (newest first, filterable, ack button)
--   * future: webhook transport (Telegram / ntfy / journald) gated
--     behind `VPNCTLD_NOTIFY_WEBHOOK_URL` env — deferred until Pavel
--     picks one transport, schema is forward-compatible.
--
-- Why an explicit table (not just audit_log):
--   * Alerts need an `acked_at` state column so the dashboard tile
--     knows the unacked count without joining audit twice.
--   * `severity` is structured so the UI can colour-code (warning /
--     critical) without parsing the summary string.
--   * audit_log row is STILL written for every alert (with
--     `action='alert.fire'` + payload) so the full timeline view
--     stays coherent; admin_alerts is the operator-action surface.
--
-- Retention: handled by the existing retention scheduler in
-- `daemon::app::spawn_retention_purger` — `purge_alerts_older_than`
-- drops ACKED alerts older than the 30-day window. UNACKED alerts
-- are NEVER auto-purged (operator must explicitly ack); without
-- this rule an alert that fires once and is forgotten would vanish
-- in 30 days with no audit trail of "operator saw + dismissed".

CREATE TABLE IF NOT EXISTS admin_alerts (
    -- Surrogate id so the ack route can take a stable opaque token.
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    -- Wall-clock at INSERT, ISO-8601 with millis (matches the rest
    -- of the schema for bucket-helper reuse).
    created_at TEXT NOT NULL
        DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),

    -- One of the well-known kinds the state-machine produces:
    --   'server.singbox.down'         — sing_box_active true → false
    --   'server.singbox.up'           — sing_box_active false → true
    --   'server.fail2ban.down'        — fail2ban_active true → false
    --   'server.fail2ban.up'          — fail2ban_active false → true
    --   'server.disk.pressure'        — disk_pct crossed 90
    --   'server.disk.recovered'       — disk_pct dropped below 85
    --   'server.mem.pressure'         — mem_used_pct crossed 95
    --   'server.mem.recovered'        — mem_used_pct dropped below 90
    --   'server.singbox.log.too_big'  — log_bytes crossed 500 MiB
    --
    -- Future kinds (Phase G chunk 2): server.unreachable (SSH timeout
    -- for N consecutive ticks), server.fail2ban.banned_self (parse
    -- `fail2ban-client status sshd` + compare to our IP).
    --
    -- TEXT not enum (SQLite has no enum) — new kinds can land without
    -- a schema migration.
    kind TEXT NOT NULL,

    -- The server this alert is about. NULLable for future global
    -- alerts (e.g. `vpnctld.disk.pressure` on the homelab host itself
    -- — Phase G chunk 3). FK CASCADE so deleting a server drops its
    -- alert history; we intentionally don't keep alerts for
    -- decommissioned servers (the audit_log row is the historical
    -- record).
    server_id TEXT
        REFERENCES servers(id) ON DELETE CASCADE,

    -- 'info' | 'warning' | 'critical'. UI uses for colour + sort
    -- priority. Recovery alerts ('*.up' / '*.recovered') are 'info';
    -- pressure thresholds are 'warning'; service-down is 'critical'.
    severity TEXT NOT NULL DEFAULT 'warning',

    -- Human-readable one-liner the operator sees in the feed. The
    -- structured `payload_json` carries the numbers (current pct,
    -- prior pct, etc) for the detail expander.
    summary TEXT NOT NULL,

    -- Optional structured context. Examples:
    --   {"sing_box_active":false,"prior":true,"observed_at":"..."}
    --   {"disk_pct":92,"prior_pct":74,"threshold":90}
    payload_json TEXT,

    -- NULL until the operator explicitly acks via /admin/alerts/{id}/ack.
    -- Once acked, the row enters the 30-day retention window. The
    -- dashboard tile filters by `acked_at IS NULL`.
    acked_at TEXT
);

-- Dashboard tile reads `COUNT(*) WHERE acked_at IS NULL` very
-- frequently (one query per dashboard render). Partial index limits
-- the index size to only currently-unacked rows AND lets SQLite
-- satisfy the COUNT from the index alone (no row visits).
CREATE INDEX IF NOT EXISTS idx_admin_alerts_unacked
    ON admin_alerts(id) WHERE acked_at IS NULL;

-- Feed page `ORDER BY id DESC LIMIT N` uses the PK index directly,
-- so no extra index needed for that path. But `?show=all` filter
-- by acked status benefits from an index on `acked_at` (rare path,
-- kept cheap).
CREATE INDEX IF NOT EXISTS idx_admin_alerts_acked_at
    ON admin_alerts(acked_at);

-- Per-server filter on the feed page (future Phase G chunk 2 will
-- add `?server=<id>` to alerts URL).
CREATE INDEX IF NOT EXISTS idx_admin_alerts_server
    ON admin_alerts(server_id, id DESC);
