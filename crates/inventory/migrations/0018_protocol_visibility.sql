-- 0018_protocol_visibility.sql — per-(server, protocol) hidden flag
-- + per-(user, server, protocol) deny override.
--
-- Pavel 2026-05-20: «нужно наверное чтоб была отдельная настройка
-- которая позволяет добавлять у убирать конкретный протокол с
-- конкретной подписки и или скрывать его на сервер без явного
-- удаления».
--
-- Two orthogonal axes, two storage shapes:
--
--   1. Per-SERVER hide flag — additive `hidden` column on the
--      existing `server_protocols` junction. `hidden=1` keeps the
--      inbound running on the node (kernel render path still sees
--      the row in `server.enabled_protocols`) but suppresses the
--      protocol from EVERY rendered subscription URL for EVERY
--      user. "Soft delete from the public side" — distinct from
--      the existing add/remove buttons which write/delete the row
--      entirely.
--
--   2. Per-(USER, SERVER, PROTOCOL) override — new sparse table
--      `grant_protocol_overrides`. Absence = inherit server-side
--      (visible unless `hidden=1`). Presence with state='disabled'
--      = explicit per-user deny on top of an otherwise-visible
--      protocol. Composite FK to `grants(user_id, server_id)`
--      auto-cleans overrides on revoke — no orphan rows.
--
-- Backwards-compat (Q3 of design): empty `grant_protocol_overrides`
-- + every existing row in `server_protocols` defaults `hidden=0`,
-- so the 33 production users × 3 servers × 8 protocols set
-- renders byte-for-byte identical to pre-migration output. Pinned
-- by a regression test that opens a pre-0018 snapshot and asserts
-- `/sub/<token>` returns the same bytes pre- and post-migration.
--
-- Why the `state` column is a `CHECK` enum instead of BOOL:
-- leaves room for a future 'force-enabled' value (operator wants
-- protocol X for user Y even when server-hidden) without another
-- migration. Resolution rule when both axes meet:
--   server.hidden=1 AND override.state='disabled' → hidden
--   server.hidden=1 AND override absent              → hidden
--   server.hidden=0 AND override.state='disabled'    → hidden
--   server.hidden=0 AND override absent              → visible
--   server.hidden=1 AND override.state='force-enabled' → visible (future)
--
-- Sing-box node-side users[] (Q7): UNCHANGED. `users_for_server`
-- still emits one entry per (user, server) grant. Visibility
-- filters ONLY the rendered subscription URL — the inbound users
-- table on the live node keeps every UUID. This preserves DG-1's
-- "no unexpected user removals" invariant + lets a previously-
-- subscribed client keep working from a cached URL after the
-- operator hides the protocol (existing connections are not torn
-- down, the operator just stops handing the URI out).

ALTER TABLE server_protocols ADD COLUMN hidden INTEGER NOT NULL DEFAULT 0;

CREATE TABLE grant_protocol_overrides (
    user_id     TEXT NOT NULL,
    server_id   TEXT NOT NULL,
    protocol_id TEXT NOT NULL,
    state       TEXT NOT NULL CHECK (state IN ('disabled')),
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (user_id, server_id, protocol_id),
    -- Composite FK to grants: deleting a grant (user revokes their
    -- access to a server) drops every per-protocol override for
    -- that (user, server) pair. Avoids orphan-cleanup queries.
    FOREIGN KEY (user_id, server_id)
        REFERENCES grants(user_id, server_id)
        ON UPDATE CASCADE
        ON DELETE CASCADE
);

CREATE INDEX idx_grant_protocol_overrides_user
    ON grant_protocol_overrides(user_id);
