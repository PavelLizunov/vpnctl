# Comprehensive infra audit + unified migration plan — 2026-05-19

**Triggered by Pavel: «сделай еще одну комплексную проверку и составь план»**

This document supersedes `MIGRATION_PLAN_NINITUX_AND_NK01.md` (which
was correct but incomplete — it missed the active prod incident
discovered in this audit).

## 🚨 Active prod incident — fix BEFORE any new deploy

Yesterday's vpnctld deploy on vps-de-01 (audit row 2026-05-18T14:22)
silently broke **22 of 23 ninitux-managed user UUIDs** on
`104.194.156.93`. Pavel noticed only one (claude-chat-proxy)
because that's the HTTPS-proxy egress route his containers use.
The other 21 affected users haven't complained — almost certainly
because the `vpn-router` client app silently fails over to
vps-is-01 / vps-nk-01 on TLS reject.

**Root cause**: vpnctld inventory was imported from old bash
`inventory/<IP>.env` files for vps-is-01 only. So ALL 33 users in
vpnctld inventory carry their `ninitux-vps-is-01-column` UUIDs.
ninitux has a DIFFERENT UUID per (user, server) — 3 columns. When
vpnctld renders sing-box config for vps-de-01, it embeds the
vps-is-01-column UUIDs, which the vps-de-01 server has never seen.
ninitux-issued vless:// URLs to vps-de-01 carry the
ninitux-vps-de-01-column UUIDs — those get dropped from the server
on every vpnctld push.

**Live evidence** (collected this session):

| Source | gelios's UUID on vps-de-01 | Match? |
|---|---|---|
| vpnctld inventory | `68d95b3f-…` (= vps-is-01 column) | ✗ |
| ninitux DB row for vps-de-01 | `6c713d37-…` | ✗ |
| LIVE `/etc/sing-box/config.json` on 104 | `68d95b3f-…` (from vpnctld's push) | matches inventory, **NOT** ninitux |

So a gelios-the-user clicking «de-01» in vpn-router app gets a
vless URL with UUID `6c713d37-…` → vps-de-01 sing-box rejects it
silently → vpn-router falls back to is-01/nk-01 (silent failover).

**Affected users on vps-de-01**: 22 of 23 (everyone except
main-brat, because main-brat's vps-de-01 ninitux UUID happens to
be `b25684c3-…` which is the same one I added back yesterday as
«claude-chat-proxy» without realising the connection).

### Immediate fix proposal (NOT yet executed — needs Pavel go-ahead)

The cleanest 1-step rollback:

```bash
# On 192.168.0.207, trigger subscription-server to re-push vps-de-01
# config from its own DB. This restores the 23 ninitux UUIDs and
# preserves main-brat = b25684c3-… (so the http-proxy keeps working).
curl -X POST -H "X-API-Key: $SUB_ADMIN_KEY" \
  http://192.168.0.207:8100/admin/servers/2/sync
```

Side-effect: drops `brat` (vpnctld test user, UUID `a61699c6-…` —
no ninitux equivalent, not a real production user per Pavel) AND
drops the standalone `claude-chat-proxy` name (but its UUID
`b25684c3-…` lives on under name `main-brat`, so the http-proxy
authentication keeps working — VLESS auth is UUID-only, names are
labels).

After this fix: vpnctld and ninitux pushes are aligned for the
duration; do NOT click vpnctld's «deploy →» button on vps-de-01
again until the unified-inventory work below is done.

## 1. The infrastructure as it actually exists

### Three independent VPN-config writers — they fight

| Writer | Host | Push key | Targets | Triggers |
|---|---|---|---|---|
| **`vpnctld`** | 192.168.0.236 | `/var/lib/vpnctl/.ssh/id_ed25519` (label `vpnctld-deploy`) | vps-is-01, vps-de-01, stg | admin UI «deploy →» button (manual) |
| **`subscription-server`** (FastAPI in Docker) | 192.168.0.207 | `/home/user/.ssh-container/id_ed25519` (label `homelab1-user`) | vps-de-01, vps-is-01, vps-nk-01 | (a) every admin-API mutation; (b) snapshot rollback; (c) manual `POST /admin/servers/{id}/sync`. **No periodic re-push.** |
| **Human SSH (Pavel + claude-dev keys)** | claude-chat container, laptop | various keys | all 3 VPS | manual edits (e.g. yesterday 13:19 claude-chat-proxy restore) |

Both bots use **the same authorised pubkey on the VPN servers**
(same fingerprint `AAAAIL7MjcaRD4KtDbHYhu6KPY44nClRcIHQ1EQ9HRrEcORy`
under different names) — compromising one = compromising both.

### Both pushers run «cat → mv → reload» on `/etc/sing-box/config.json`

vpnctld's path (`SingBox::apply_config`):
```
sing-box check -c /etc/sing-box/config.json.new
mv .../config.json.new /etc/sing-box/config.json
systemctl reload-or-restart sing-box
```

ninitux's path (`ssh_manager.py::_REMOTE_APPLY`):
```
cat > /tmp/.sing-box-pending.json
sing-box check -c /tmp/.sing-box-pending.json
cp /etc/sing-box/config.json /etc/sing-box/config.json.bak
mv /tmp/.sing-box-pending.json /etc/sing-box/config.json
chown sing-box:sing-box /etc/sing-box/config.json
systemctl reload sing-box
```

Identical effect. Whichever ran last wins. **No mutual lock.** The
2026-05-18 14:22 incident is the predictable consequence.

### What lives where (containers / services / keys)

(Distilled from the topology-audit agent — full report on file.)

**192.168.0.207** (homelab core):
- `subscription-server` (FastAPI on :8100) — **HIGH risk, the rogue pusher**
- `wb-nginx` reverse-proxies `ninitux.com` → `subscription-server`
  (and `analytics.ninitux.com` → `umami`, `yt.ninitux.com` etc)
- `ninitux-auth-{web,bot,xray}` — Telegram OTP for ninitux.com
  sub-domains. Does NOT push VPN configs.
- `vk-turn-server` container — the wgturn relay actually runs HERE
  (not on a VPN server — was that the design?). Has its own wg0.conf
  with 7+ peers. Surprise.
- `forgejo` + `forgejo-runner` — git host. If any repo gets a
  «deploy on push» CI workflow, runner becomes a 4th pusher.
- `bizone-vpn` (OpenVPN client, currently unhealthy), `yt-xray`,
  `musicbot-xray`, `soc-crypto` — none push VPN configs.

**192.168.0.236** (vpnctld + Forgejo client side):
- `vpnctld.service` — our daemon
- `vpnctl-backup.timer` — read-only daily snapshot at 03:00 UTC

**192.168.0.142** (token-service + Chrome + proxies):
- gost proxy on :18080 — egress for claude-chat (uses
  main-brat-de-01 UUID b25684c3-…)
- Headless Chrome on :9222 — used by `visual_check.py`,
  `layout_check.py`, AND wgturn-cli's `--vk-chrome-url`
- `autossh tunnel@45.76.19.146` (Vultr Sezam) — outbound surface

**192.168.0.200** (claude-chat host):
- No SSH from this container; not directly auditable

**Each VPN server** (`104.194.156.93`, `93.95.226.167`,
`194.87.222.111`):
- `sing-box.service` — actual VPN
- One unknown ssh-rsa key on 194.87.222.111's root authorized_keys —
  not in any CLAUDE.md inventory, no comment field. Investigate
  before any production move.

## 2. The unified inventory problem (the actual blocker)

vpnctld inventory schema today:
```
users(id PK, uuid UNIQUE, …)            -- one UUID per user
grants(user_id, server_id)              -- many-to-many
```

But ninitux operates with:
```
clients(device_id PK, name, …)          -- one row per user
servers(id PK, …)
client_server_links(device_id, server_id, client_uuid)  -- DISTINCT UUID per (user, server)
```

**Why ninitux uses per-server UUIDs** (Pavel's design call, per the
ssh_manager source): every VPN server has its OWN Reality keypair.
A user's `vless://uuid@server` URL works only on the server that
knows that UUID. Issuing distinct UUIDs per server gives:
- Per-server revocation (delete from one inbound list, others
  untouched)
- Traffic accounting per server-keyed UUID (matched in clash-api
  stats: «this UUID = this user on this server»)
- Server compromise isolation (if one server's UUIDs leak, the
  other two aren't affected for the same users)

vpnctld's single-UUID model **cannot represent this faithfully.**
Until vpnctld grows per-(user, server) UUIDs, any vpnctld deploy
to a server diverges from the ninitux URLs that users actually
hold.

## 3. The unified migration plan (3 phases, ordered + rollback-able)

### Phase 0 — Immediate stabilisation (today, 30 min)

Goal: stop the bleeding without writing any code.

1. **Restore vps-de-01 ninitux UUIDs** — `POST /admin/servers/2/sync`
   on subscription-server (the curl above). Verify with
   `jq` on vps-de-01 that the 22 missing UUIDs are back.
2. **Disable vpnctld auto-deploy on vps-de-01 and vps-is-01** by
   setting `usage_coefficient = 0` in inventory (operator-side
   marker). Add a UI banner on the server-detail page saying
   «managed externally by ninitux subscription-server — do not
   click deploy». (Optional polish; the diff guard already protects
   against accidental damage; this is operator-facing UX.)
3. **Document the kill-switches**: how to stop subscription-server
   in emergency (`docker stop subscription-server`), how to point
   nginx at vpnctld instead. Don't execute, just write down.

Rollback: trivial — none of the above are destructive.

### Phase 1 — vpnctld schema for per-server UUIDs (next session, 1-2 days)

Add a `grants.client_uuid TEXT` column. Backfill from current
state: for each grant, copy `users.uuid` into `grants.client_uuid`
(preserves current behaviour byte-for-byte). Then the
sing-box render path takes the UUID from `grants` instead of
`users`. The diff guard already operates on UUIDs from the live
config; no change needed there.

Once that's in: a one-time SQL import from ninitux's
`client_server_links` table sets the CORRECT per-server UUIDs in
vpnctld's grants — matching what every server actually has live.
After the import, vpnctld deploys are byte-identical to
ninitux's pushes on the same data.

Rollback: drop the column, fall back to `users.uuid` rendering.

### Phase 2 — vpnctld absorbs the `/api/v1/app/config/<device_id>` endpoint (1-2 days after Phase 1)

Implement the FastAPI handler in Rust — the spec from the
subscription-server source-deep-dive agent is now in this repo's
docs (see «subscription-server compat spec»). Byte-equivalent
response (key order, base64, no trailing newline, content
negotiation by User-Agent). New columns:
`users.vpn_router_device_id TEXT UNIQUE` (= ninitux's device_id).

Side-step gradual: ship the endpoint, run BOTH systems live for a
week, A/B-compare every device_id's response. Once 100% match,
flip nginx routing for `ninitux.com/api/v1/app/config/` from
subscription-server (192.168.0.207:8100) to vpnctld
(192.168.0.236:18402). Verify with synthetic test devices.

Rollback: flip nginx back. The subscription-server keeps running
the whole time.

### Phase 3 — Decommission subscription-server (1-2 weeks after Phase 2 cutover)

After 2 weeks of clean A/B + 0 user complaints + verified all 3
VPN servers stable:
1. `docker update --restart=no subscription-server`
2. `docker stop subscription-server`
3. Keep the encrypted DB backed up off-site for 90 days
4. Remove the `homelab1-user` ssh key from VPN server
   authorized_keys (eliminates the alternative push path)
5. Document the decommission in CLAUDE.md + close the
   subscription-server Forgejo repo

Rollback (in the 90-day window): `docker start subscription-server`
+ re-add the ssh key. After 90 days: rollback requires repopulating
the DB from off-site backup.

## 4. Out of scope (handled separately or deferred)

- **vps-nk-01 (194.87.222.111)** — has 3x-ui Docker AND sing-box;
  3x-ui has 25 «direct-config» users orthogonal to ninitux.
  Documented in `MIGRATION_PLAN_NINITUX_AND_NK01.md`. Don't touch
  during Phases 0-3. Final 3x-ui cleanup: contact each of the 25
  users with a new ninitux-based config; once all migrated,
  `docker stop 3x-ui`.
- **TUIC / Hysteria2 inbounds on vps-is-01 / vps-de-01** — 9 TUIC
  users on de-01 :8443/UDP, 2 Hy2-salamander + 2 TUIC-v5 users on
  is-01 :9443/:9444. Hardcoded in ninitux's `config_template` (NOT
  in `client_server_links`). When vpnctld absorbs in Phase 1,
  must port these into vpnctld inventory too. Extend diff guard to
  cover Hy2 `users[*].password` set (UUID-less protocol).
- **wgturn live test from end-user device** — VK captcha step Pavel
  has to do interactively; the integration is functionally
  complete (verified `wgturn-cli connect-url` reaches VK auth).
- **Cutting NEW features in vpnctld** — frozen until Phases 0-2
  done. We have a working live system, two pushers fighting; first
  consolidate, then build new.

## 5. Decision points Pavel must make

1. **Go-ahead for Phase 0** (the immediate vps-de-01 restore). I
   have the admin API key path identified but haven't called
   anything destructive — needs explicit «да».
2. **Per-server-UUID schema migration (Phase 1)** — this is an
   inventory schema change that's not rollback-able without a SQL
   re-import. Confirm we want vpnctld to own this universe.
3. **`brat` test user fate** — gets dropped in Phase 0 (its UUID
   `a61699c6-…` has no ninitux equivalent). Confirm OK to drop or
   need to preserve as a separate inventory entry.
4. **`vps-nk-01` long-term ownership** — vpnctld absorbs ninitux's
   role for is-01 / de-01 in Phases 1-2. Does the same apply to
   nk-01? Or leave nk-01 dual-managed (ninitux + 3x-ui) until 3x-ui
   cleanup is done?
5. **Unknown ssh-rsa key on 194.87.222.111 root** — who owns it?
   Audit log doesn't say. Pavel needs to confirm OR remove.
