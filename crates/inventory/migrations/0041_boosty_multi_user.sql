-- 0041_boosty_multi_user.sql — allow ONE Boosty subscriber to gate SEVERAL
-- vpnctl users.
--
-- Migration 0040 put a partial UNIQUE index on users.boosty_subscriber_id,
-- enforcing one-subscriber → one-user. But a single paying person can hold
-- several vpnctl accounts (one per device — e.g. Natasha's demonnot-1..5),
-- and the operator wants that person's ONE Boosty subscription to gate ALL
-- of their devices at once. So the link becomes many-users → one-subscriber.
--
-- The reconciler already evaluates each (user, subscriber) link independently
-- (see `vpnctl-boosty-bridge::reconcile`), so N users sharing a subscriber id
-- all follow that subscriber's active state with no logic change — only this
-- uniqueness constraint stood in the way.
--
-- Drop the UNIQUE index; replace with a plain partial index so the
-- subscriber-id lookups in the link/list paths stay fast.

DROP INDEX IF EXISTS idx_users_boosty_subscriber_id;

CREATE INDEX IF NOT EXISTS idx_users_boosty_subscriber_id
    ON users(boosty_subscriber_id)
    WHERE boosty_subscriber_id IS NOT NULL;
