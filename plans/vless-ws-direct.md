# Goal — VLESS+ws-direct (caddy-fronted, no CDN)

**Status:** planned (2026-06-25). Design: workflow `wwc5b2lla` / task #8.

## Why (problem)

RU TSPU now blocks **VLESS+Reality** at the connection/volume level —
SNI-independent, port-443, lifts after ~60 s (net4people/bbs #546).
**Cloudflare-proxied** traffic is throttled to ~16 KB/connection across RU
fixed+mobile since 2025-06-09 with no vendor fix — so CDN-fronting and WARP are
dead ends for RU. The proven-working posture is a **DIRECT real-domain TLS
proxy** (our `naive` on `cdn.ninitux.top` already does exactly this, direct, no
CF). **VLESS+ws** is the one transport that is BOTH direct-domain-DPI-resistant
AND **client-universal** — it imports on v2rayNG / v2RayTun / Happ / sing-box,
unlike hysteria2/tuic which the v2ray-core family cannot parse. It closes the
v2RayTun fallback gap the hysteria2 rollout left open.

## Objective

Ship a new `vless-ws` protocol: **Caddy** terminates a real Let's-Encrypt TLS
cert on a per-node alt-port, serves a **decoy site** at `/`, and
`reverse_proxy`s ONE secret path to a **plaintext sing-box VLESS+ws inbound on
127.0.0.1**. The **caddy kernel owns both units** (Caddyfile + loopback
sing-box) via the `BUNDLE_DELIMITER` + second-systemd-unit pattern that
`dns_tunnel` already runs in prod — **no new cross-kernel API**. Runs
**alongside** REALITY on :443, which stays untouched.

## Definition of Done

1. A user granted `vless-ws` on de/is/nl gets a
   `vless://…@<sub>.ninitux.top:<port>?type=ws&security=tls&sni=<sub>&host=<sub>&path=/<secret>&fp=…`
   link in BOTH `/sub` and the `/api/v1/app/config` (ninitux) endpoint.
2. The link **imports and connects** on v2rayNG, v2RayTun, Happ, sing-box.
3. `https://<sub>.ninitux.top:<port>/` returns a real **decoy** HTTP 200
   (active-probe-resistant); the secret path proxies to the ws backend; a wrong
   path returns the decoy 404 — never a bare-proxy fingerprint.
4. **REALITY on :443 is byte-for-byte unchanged** (existing clients unaffected;
   the DG-1 uuid-diff guard passes).
5. The backend sing-box (loopback) carries **no `tls`** and **no `flow`** key;
   Caddy is the sole TLS edge, with a valid LE cert per node subdomain.
6. **Verified from RU** (operator's phone): connects and passes traffic where
   raw Reality is currently blocked.

## Invariants (must hold)

- Kernel×Protocol orthogonality: touch only `crates/protocols/`, the `caddy`
  kernel, the registry (+ daemon twin `build_registry`),
  `vpn_router::EXTRA_PROTOCOLS`, and one admin handler. **No** changes to
  `core`/`ssh`/`crypto`; no inventory schema change beyond per-server secrets.
- Protocol **stateless**; per-server params via `RenderCtx` secrets:
  `vlessws.domain`, `vlessws.acme_email`, `vlessws.path` (auto-minted lowercase
  `[a-z0-9]{16}`), `vlessws.listen_port`, `vlessws.backend_port`.
- `vless-ws` declares **no static `listen_ports()`** → coexists with REALITY on
  :443 (front 8443 on de/is, 2087 on nl; backend `127.0.0.1:11443`, never in a
  firewall rule).
- No `unwrap`/`expect`/`panic`/`unsafe` outside tests; `domain` and `path`
  injection-guarded.
- **Web is THE operator surface:** an admin button configures vless-ws
  (domain / path / port), mirroring `server_set_naive_config`.

## Out of scope (separate goals)

`cdn` (already naive); per-connection SNI; AmneziaWG as a third leg;
IP-reputation / node-IP rotation (the `is`-class CIDR-block problem — orthogonal
to transport).

## Verification & methodology

spec-tests (test-writer-agent, spec-only, no impl) → independent review-agent
over the diff → full CI (`fmt` / `clippy -D` / `test`) → **live-deploy on de
FIRST**, verify decoy + ws + RU-client, then roll to is/nl. Deploy via the
**daemon admin API** (the on-host CLI is migration-stale). Clients pick up the
new line on next `/sub` re-fetch — no break to existing transports.

## Prerequisite (operator)

DNS A-records direct to nodes (grey-cloud, no CF):
`de.ninitux.top → 104.194.156.93`, `is.ninitux.top → 93.95.226.167`,
`nl.ninitux.top → 194.87.222.111`. *(created 2026-06-25, propagating.)*

## Effort

~6 days, methodology-gated. Client compatibility is maximal
(v2rayNG / v2RayTun / Happ / sing-box).
