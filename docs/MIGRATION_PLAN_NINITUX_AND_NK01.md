# Migration plan — ninitux.com `vpn-router` + vps-nk-01 (194.87.222.111)

**Drafted: 2026-05-19.** Discovered during the audit of
`194.87.222.111` Pavel asked me to look at.

## TL;DR for future-self

You thought vpnctld was the ONLY thing managing your VPN servers.
**It is not.** There is a parallel Python service called
`subscription-server` (image `subscription-server-subscription-server`)
that runs on `192.168.0.207:8100` behind nginx, accessed publicly
as `https://ninitux.com/api/v1/app/config/<device_id>`. It calls
itself `vpn-router v2.4.1`. It manages the SAME three physical VPN
servers (vps-de-01 / vps-is-01 / vps-nk-01) via its own SQLCipher-
encrypted DB at `/var/lib/docker/volumes/subscription-server_sub-data/_data/subscriptions.db`,
and it has its own SSH-deploy path to those boxes. Pavel's users
in production today use links of shape
`https://ninitux.com/api/v1/app/config/<hash>`, NOT vpnctld's
`/sub/<token>` URLs.

Two managers can — and on 2026-05-18 DID — clobber each other's
config. The diff guard from `e55877f` helps, but the real fix is
to pick ONE manager and decommission the other.

## What ninitux.com `vpn-router` does

| Surface | Endpoint | What it returns |
|---|---|---|
| **App-config probe** | `GET /api/v1/app/config/<device_id>` | `{"status":"ok","app":"vpn-router","version":"2.4.1","update_available":false,"config":"<base64 newline-joined vless:// URLs>","check_interval":3600,"timestamp":<unix>}` |
| **Health** | `GET /health` | `{"status":"ok"}` |
| **Admin** (TBD) | `app.routers.admin` exists in source | not yet probed |

**Subscriptions DB tables (12 total)**:
- `clients` (34 rows): `device_id` (32-hex), `name`, `active`, `tier`, `allowed_platforms`, `max_devices`, `last_fetch`, `created_at`
- `servers` (3 rows): vps-de-01 / vps-is-01 / vps-nk-01 with full
  `config_template` JSON, ssh creds (`ssh_host`, `ssh_port`,
  `ssh_user`, `ssh_key_path=/ssh/id_ed25519`), `reality_public_key`,
  `inbound_id`, `panel_url/user/pass` (legacy 3x-ui mgmt fields,
  null on all 3)
- `client_server_links` (92): the actual per-(client,server) UUIDs
  that get rendered as vless:// URLs
- `block_log`, `traffic_snapshots` (35k), `traffic_alerts` (149),
  `traffic_daily`, `subscription_fetches` (4.5k),
  `connection_events` (1.86M), `links_snapshots`, `sync_jobs`

**DB encryption key** is at `subscription-server`'s env
`DB_ENCRYPTION_KEY=<redacted>`.
Tooling is `sqlcipher3` Python module. Plain `sqlite3` cannot
open the file.

## How it pushes config to VPN boxes

Each server row carries a full `config_template` (sing-box JSON
shape, with `users: []` placeholder per VLESS inbound). At sync
time, `subscription-server` (via `app.ssh_manager`):

1. Looks up the server's row
2. Pulls active clients from `client_server_links` for that server
3. Fills `users` array with `{name, uuid, flow}` per client
4. SSHes into the box (using key mounted at `/ssh/id_ed25519`
   inside the container — bind from `/home/user/.ssh-container/id_ed25519`
   on host 192.168.0.207)
5. Atomically swaps `/etc/sing-box/config.json` + reloads

So **`subscription-server` is doing exactly what vpnctld's
`SingBox::apply_config` does**, but with its own user list and its
own ssh path.

## Why this clashes with vpnctld

When BOTH systems push to the same `/etc/sing-box/config.json`:
- subscription-server has 34 clients in DB, knows their per-server UUIDs
- vpnctld inventory has 35-ish users with potentially the SAME names
  but DIFFERENT UUIDs

If subscription-server pushes first, then vpnctld pushes second, the
file ends up with vpnctld's UUIDs — breaking users who fetched
their subscription via ninitux.com (their config has the old UUIDs).
This is the EXACT mechanism that broke claude-chat-proxy on
2026-05-18.

The `e55877f` diff guard catches DELETIONS (vpnctld won't drop
users that exist on the server but not in inventory). It does NOT
catch **UUID MISMATCHES** — if both DBs have a user named «brat»
with different UUIDs, whoever pushes last wins and the other side's
users break.

## Three migration paths

### A. ONE PUSHER — vpnctld absorbs subscription-server (recommended)

vpnctld becomes the sole writer to the three VPN boxes. ninitux.com
becomes a thin read-only compatibility shim until users migrate.

**Concrete steps:**

1. **One-time import**: write a Python script (with access to the
   container's sqlcipher key) that:
   - reads all 34 clients + 92 client_server_links + 3 servers from
     `subscriptions.db`
   - emits SQL for vpnctld's inv.db:
     - `INSERT INTO users` with **device_id stored as a new column**
       `vpn_router_device_id TEXT UNIQUE` (additive migration —
       requires a vpnctl-inventory migration)
     - `INSERT INTO grants` for every (client, server) pair
     - For users that already exist in vpnctld by NAME but with a
       different UUID → flag as conflicts; operator must pick one
       UUID and rebind clients. Or auto-prefer the ninitux UUID
       (it's what production clients actually use today).
2. **Compat endpoint**: implement `daemon/src/handlers/vpn_router.rs`
   with one route `GET /api/v1/app/config/{device_id}` that mimics
   ninitux's response shape byte-for-byte (`status`, `app`,
   `version`, `update_available`, `config` (base64), `check_interval`,
   `timestamp`). vpnctld looks up `vpn_router_device_id` → user_id →
   `users_for_server` → renders vless:// per granted server →
   joins with `\n` → base64.
3. **Reverse-proxy cutover**: change `wb-nginx` config on 192.168.0.207
   so that requests to `ninitux.com/api/v1/app/config/...` go to
   vpnctld (192.168.0.236:18402) instead of `subscription-server:8100`.
   Verify: send a few real device_ids through, decode the base64,
   confirm vless:// URLs are byte-identical to what
   subscription-server returned.
4. **Decommission**: `docker stop subscription-server` (keep the
   image + the encrypted DB backed up off-site for at least 30 days).
5. **Reverse-proxy long-term**: keep nginx routing `ninitux.com/api/v1/app/config/`
   → vpnctld indefinitely. The URL format stays alive forever, so
   any user with a saved `vpn-router` config link in their app
   keeps working without ever knowing about the cutover.

Trade-off: **vpnctld becomes the only system mutating VPN
configs**. Clear ownership, single guard layer (the diff-guard),
single audit log. But it ALSO means every feature that
subscription-server has (traffic_snapshots, traffic_alerts, sync
jobs, block_log) must either be ported into vpnctld OR explicitly
deprecated. Significant work — estimate 2-4 sessions.

### B. ONE PUSHER — subscription-server absorbs vpnctld (NOT recommended)

The reverse. Move every vpnctld feature into Python land. Bad
because: (a) we just shipped a lot of Rust kernel code (sing-box,
amneziawg, wgturn), (b) the diff-guard methodology is mature in
vpnctld, (c) you've been investing time in vpnctld as the future.

### C. COEXISTENCE with read-only vpnctld

Make vpnctld INVENTORY-VIEW-ONLY for these three boxes. Disable
all kernel/protocol toggle handlers + the deploy button for any
server flagged `managed_by="ninitux"`. vpnctld only does
observability (probes, audit, health UI), subscription-server
keeps doing pushes. Diff guard is still useful to refuse a
deploy if somehow triggered.

Trade-off: weird UX (some servers in vpnctld are mutable, others
aren't), and we end up maintaining BOTH systems forever. Easy
short-term, painful long-term.

## Answer to «vps-de-01 + vps-is-01 fully migrated?»

**Counted by VLESS user UUIDs only — yes:**
- vps-de-01: 25 grants in vpnctld === 25 VLESS users in live config
- vps-is-01: 33 grants in vpnctld === 33 VLESS users in live config

**But this is misleading.** Looking at vps-de-01's config_template
(via subscription-server):
- 25 VLESS-Reality users on :443 (these are what vpnctld inventory
  carries grants for)
- 9 hardcoded TUIC users on :8443/UDP (brat-pc, brat-mac, brat-mobile,
  nini-pc, nini-mobile, liza-pc, liza-mobile, sezam104, nini) —
  baked into ninitux's `config_template`, not in vpnctld inventory
- vps-is-01 has additionally:
  - 1 Hysteria2-salamander inbound on :9443 with 2 users (main-brat,
    ninitux)
  - 1 TUIC-v5 inbound on :9444 with 2 users (main-brat, ninitux)
  - VLESS-gRPC on :8444 with SNI=www.bing.com (3rd Reality endpoint)

So **TUIC + Hy2 users are NOT in vpnctld inventory.** The diff
guard only checks `inbounds[*].users[*].uuid`, which covers TUIC
(they have uuid field) but not Hy2-salamander (those have only
`password`, no uuid). A vpnctld-rendered config WOULD lose the
Hy2 users silently — and we wouldn't catch it with the current
guard.

**Action items for «full migration»:**
1. Import 9 TUIC users of vps-de-01 into vpnctld inventory with
   their CURRENT UUIDs from subscription-server's template
2. Import the 2 Hy2 + 2 TUIC-v5 users of vps-is-01 (with passwords
   + UUIDs)
3. Extend `sing-box apply_config` diff guard to ALSO compare Hy2
   `users[*].password` set OR fall back to a generic «total user
   count must not decrease» heuristic

These users likely correspond to multi-device setups (brat-pc =
phone, brat-mac = laptop, brat-mobile = tablet) and are real
production. Until they're in vpnctld inventory, every vpnctld
deploy is a potential break.

## Action items I'm NOT executing today

(Per Pavel: «нужна комплексная проверка и нужно придумать что
с ним делать». This doc is the «придумать». Execution waits for
explicit go-ahead.)

- [ ] One-time SQL importer (subscription-server clients → vpnctld
      users) — needs DB migration for new `vpn_router_device_id`
      column
- [ ] Inventory migration: add columns for `vpn_router_device_id`
      + TUIC/Hy2 multi-device users
- [ ] `GET /api/v1/app/config/<device_id>` compat handler in vpnctld
- [ ] wb-nginx config swap for ninitux.com routing
- [ ] Hy2-password diff-guard extension
- [ ] Decision on path A vs B vs C — needs Pavel sign-off

## Answer to «vps-nk-01 (194.87.222.111) plan»

**Don't add to vpnctld inventory yet.** ninitux.com already
manages it (3x-ui Docker container on :443 with 25 legacy users +
sing-box host install on :8443/:2083 with users from
subscription-server). Adding it to vpnctld now and clicking deploy
would be a third config-pusher fighting the existing two.

Wait for path A migration to complete. After that, vps-nk-01
joins as a normal vpnctld-managed server, and we tackle the
3x-ui-only 25 legacy users separately (their direct-config links
can't be regenerated without rotating their UUIDs).
