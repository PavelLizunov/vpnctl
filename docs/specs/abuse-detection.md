# Contract: abuse detection (three-layer visibility model)

## 1. Intent & Invariants

- What: the operator must spot abuse — primarily a subscription URL shared past
  one human, secondarily a single client racking up unreasonable traffic.
  Three independent surfaces, each catching a different bug class.
- Invariants:
  - No layer may block or slow the subscription endpoints; observation is
    best-effort (`try_send` into bounded channels, dedicated writers).
  - Failed lookups and probe paths are NOT logged (anti-probing posture).

## 2. The three layers

| Layer | Source | Catches | Misses |
|---|---|---|---|
| 1. Sub-fetch log | vpnctld access log → `sub_access_log` | URL leaked/shared (many ASNs per user), scrapers on tight loops, UA fingerprinting | real-time connections; devices behind NAT |
| 2. VPN protocol stats | cumulative V2Ray Stats + Clash live metadata, polled via SSH → `vpn_connection_stats` (AmneziaWG polled independently) | active connections, up/down traffic | NAT; SSH polling overhead |
| 3. UA fingerprint | UA + IP/time/ASN clustering on layer-1 data | same-device roaming vs many-device sharing heuristic | never exact; UA-less clients invisible |

A device count behind NAT is roughly impossible server-side without client
cooperation; layer 3 is the best available signal.

The managed sing-box build includes the Clash `user` attribution patch, so
live metadata can be associated with users. Cumulative V2Ray Stats supplies
per-user byte counters through the node helper; `vpn_connection_stats.user_id`
is populated for attributed users and remains NULL for server-wide totals.
Missing Clash user metadata limits live attribution, not the separate
cumulative byte source. See [traffic accounting](traffic-accounting-v2.md).

Related contracts: `/api/v1/app/config` rate-limiting is per-`device_id`
(post-resolve — not spoofable) with per-IP anti-flood only for non-egress IPs
(a VPN-connected client refreshes through its node, so many users collapse into
one server IP — never naive per-IP limit there); throttle-only, no bans.
Access-log IPs, GeoIP enrichment, and sharing signals use the same trusted
resolver as security decisions: `X-Real-IP` from a configured trusted proxy,
otherwise the peer address (also used when `X-Real-IP` is missing or invalid).
`X-Forwarded-For` never supplies the logged IP. The proxy must overwrite
`X-Real-IP` as specified in `deployment.md`.

## 3. Verification Checklist

- [ ] Layer-1 rows carry the REAL client IP through the trusted proxy
      (not the proxy's LAN address).
- [ ] Spoofed leftmost XFF cannot change logged IPs; missing or invalid
      `X-Real-IP` falls back to the peer address, never XFF.
- [ ] A shared-URL scenario produces a visible UA/IP cluster on user-detail.
- [ ] Rate-limit flood returns 429 for the abuser without affecting real users.
