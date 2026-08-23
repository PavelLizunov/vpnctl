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
| 2. VPN protocol stats | clash-api on each node, polled via SSH → `vpn_connection_stats` | active connections, up/down traffic | NAT; SSH polling overhead |
| 3. UA fingerprint | UA + IP/time/ASN clustering on layer-1 data | same-device roaming vs many-device sharing heuristic | never exact; UA-less clients invisible |

A device count behind NAT is roughly impossible server-side without client
cooperation; layer 3 is the best available signal.

Known upstream gate (NOT fixable in vpnctl): sing-box's clash-api tracker
omits `User` from its JSON, so `vpn_connection_stats.user_id` stays NULL until
the upstream patch lands (SagerNet/sing-box#4159 — emit `"user"` in
`TrackerMetadata.MarshalJSON`). Server-wide dashboard totals work meanwhile.

Related contracts: `/api/v1/app/config` rate-limiting is per-`device_id`
(post-resolve — not spoofable) with per-IP anti-flood only for non-egress IPs
(a VPN-connected client refreshes through its node, so many users collapse into
one server IP — never naive per-IP limit there); throttle-only, no bans.
Logged IPs behind the appending proxy are only as trustworthy as the proxy's
`X-Real-IP` handling (see `deployment.md`).

## 3. Verification Checklist

- [ ] Layer-1 rows carry the REAL client IP through the trusted proxy
      (not the proxy's LAN address).
- [ ] A shared-URL scenario produces a visible UA/IP cluster on user-detail.
- [ ] Rate-limit flood returns 429 for the abuser without affecting real users.
