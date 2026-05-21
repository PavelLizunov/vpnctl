-- Phase 5a-2 — reverse DNS (PTR) cache.
--
-- sing-box's clash-api gives us destination IPs for every active
-- connection but rarely resolves them to hostnames on its own
-- (only HTTPS SNI / HTTP Host headers populate the `host` field,
-- and even then only for some protocols). Result: admin UI shows
-- top destinations as `35.217.1.178:50005` instead of the much
-- more readable `r3.googlevideo.com:50005`.
--
-- This table caches the result of `getent hosts <ip>` lookups so
-- the render path is O(1) HashMap probe instead of a synchronous
-- DNS query per row (which would block the admin UI for seconds
-- on a node with many active connections).
--
-- The resolver task (daemon/src/dns_resolver.rs) walks unresolved
-- IPs from the latest snapshots on every tick, calls `getent` via
-- std::process + spawn_blocking, and UPSERTs the result. NULL
-- hostname = "we tried and got no answer" (no PTR record); we
-- store the row anyway so we don't re-query the same IP for the
-- TTL window.
--
-- Retention: 7-day TTL. PTR records change rarely (ISP renames,
-- CDN failovers) but not never; weekly refresh keeps the cache
-- accurate without thrashing. Pruned by the existing hourly
-- retention scheduler.
--
-- Storage: ~1 row per unique destination IP across all servers.
-- At ~150 unique dests per server-tick × 3 servers × ~24 hours
-- of distinct dests/day = a few thousand rows max. Trivial.

CREATE TABLE dns_ptr_cache (
    -- IP as a string (matches clash-api wire format + the rest
    -- of our schema). PRIMARY KEY because lookup is always by IP.
    ip          TEXT    PRIMARY KEY,
    -- Resolved hostname, or NULL if `getent` returned nothing
    -- (no PTR record exists or DNS server didn't answer). We
    -- intentionally store the NULL row so we don't re-query.
    hostname    TEXT,
    -- ISO-8601 UTC. Driver for the 7-day TTL purge.
    resolved_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- Index for the TTL sweep — typical purge "WHERE resolved_at <
-- (now - 7 days)" benefits from a sorted index.
CREATE INDEX idx_dns_ptr_cache_resolved_at ON dns_ptr_cache (resolved_at);
