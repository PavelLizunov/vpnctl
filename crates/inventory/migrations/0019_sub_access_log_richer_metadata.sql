-- Phase Track-1.2 — richer per-request metadata on sub_access_log.
--
-- Pavel 2026-05-21: «можно больше инфы по девайсу получить» after a
-- 127.0.0.1 row in the Subscription-access table looked suspicious
-- (turned out to be phase6-monitor's own canary curl — see
-- /etc/cron.d/phase6-monitor on the daemon host). The investigation
-- exposed that today's schema (ts, user_id, ip, ua, status, bytes)
-- doesn't carry enough signal to distinguish operator scripts from
-- real clients, let alone fingerprint a device through a network
-- change. This migration adds 5 nullable TEXT columns that the
-- handlers + writer fill on new writes; old rows stay NULL.
--
-- Why each column:
--
--   accept_language — raw Accept-Language header (truncated ≤120
--   chars in the handler). Same physical device tends to keep the
--   same A-L through an IP change; correlates clients through
--   roaming. Common shape: `ru-RU,ru;q=0.9,en;q=0.8`.
--
--   http_version — `HTTP/1.0` / `HTTP/1.1` / `HTTP/2.0` / `HTTP/3.0`
--   from `request.version()`. Modern mobile clients negotiate
--   HTTP/2 or /3; curl/wget default to /1.1; v2rayN historically
--   /1.1. Helps split "real mobile client" vs "operator script".
--
--   device_class — snapshot of `parse_ua_short(ua)` at write time.
--   Persisting it (vs re-computing on every render) means:
--     a) SQL aggregations like "how many distinct device classes
--        per user in 24h" become trivial,
--     b) future UA-parser changes don't retroactively rewrite history.
--
--   geo_country — ISO-3166 alpha-2 from a GeoIP lookup in the
--   writer task (not the handler — keeps handler latency stable).
--   NULL when the GeoIP DB isn't installed yet (homelab default).
--
--   geo_asn — `AS24940 Hetzner Online` style, also writer-side.
--   Single column instead of split number+name because the
--   /admin render shows them together anyway; saves an ASN-only
--   lookup branch later.
--
-- All columns are nullable; old rows are valid as-is. Renderers
-- use `Option<&str>` and fall back to "—" / hide when None.

ALTER TABLE sub_access_log ADD COLUMN accept_language TEXT;
ALTER TABLE sub_access_log ADD COLUMN http_version    TEXT;
ALTER TABLE sub_access_log ADD COLUMN device_class    TEXT;
ALTER TABLE sub_access_log ADD COLUMN geo_country     TEXT;
ALTER TABLE sub_access_log ADD COLUMN geo_asn         TEXT;
