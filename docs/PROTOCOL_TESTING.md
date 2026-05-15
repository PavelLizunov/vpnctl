# Protocol testing methodology

**Audience:** future Claude session (or Pavel) tasked with adding a new
protocol/kernel to vpnctl, or verifying a behavior change in an
existing one. Read this first; it captures hard-won contract about
WHO does what + HOW MUCH TIME each layer costs.

**Why this exists.** Adding a VPN protocol to a Rust workspace looks
small in code (one file, ~200 LOC, copy-paste from a sibling). The
real cost is **proving it works** — handshake against a real client,
survives DPI, survives 24h of traffic. We've shipped 5 protocols
since v0.1; this is what it actually takes per protocol, distilled.

---

## The six-layer pyramid

Each layer catches a strict subset of bugs the next layer up cannot.
Skip a layer = ship a class of bug the others can't find. Time is
"per protocol, first time"; on repeat additions a layer drops to
~30% of the listed cost due to copy-paste from siblings.

| # | Layer | Catches | Actor | Time |
|---|---|---|---|---|
| 1 | `cargo build` + `cargo clippy --workspace -D warnings` | Type errors, dead code, `unwrap`/`expect`/`panic` outside tests, lint regressions | Claude (autonomous) | 30s |
| 2 | In-module unit tests (`#[cfg(test)] mod tests`) | Pure-function correctness: percent-encoding sets, INI assembly, key-shape validators | Claude (autonomous) | 2–5 min |
| 3 | Spec tests via `test-writer-agent` | Public-API contract: missing-secret errors, malformed-input rejection, byte-stability across runs, edge cases the author would skip | Claude orchestrates → independent agent writes (spec-only prompt, NO impl) → Claude runs | 10–15 min |
| 4 | `review-agent` on the diff | Logic bugs, race conditions, command injection in shell scripts, swallowed errors, audit-log gaps | Claude orchestrates → independent agent reviews | 5–10 min |
| 5 | **Live deploy to staging** (`84.19.3.104:22`) | apt repo signing keys, log-file ownership, kernel-module DKMS rebuild, systemd race conditions — bugs from ENVIRONMENT assumptions that code review can't see | Claude SSH → server-side validation → handshake against `sing-box run -c client.json` looped back to itself | 15–30 min |
| 6 | **Real-client smoke** (Pavel's phone, browser, AmneziaVPN app) | Client-side parser quirks, QR rendering, UA strings, share-link format compat across mobile + desktop apps | **Pavel** (Claude prepares the share-link + QR, Pavel scans + reports) | 5 min per client (Pavel time) |

Plus two **out-of-band** layers, episodic not per-commit:

| Layer | What | When |
|---|---|---|
| 7 — Long-haul stability | 24h passive run, journald grep for crashes, traffic-counter sanity | Weekly or after a kernel/protocol upgrade. **Claude** can set up the soak; **Pavel** reviews the daily summary. |
| 8 — Anti-censorship validation | Real RU/CN/IR client testing, DPI fingerprinting via `zapret`-equivalent on the client side | Pavel-only, manual. Quarterly or after a known blocking event. |

Total **first-time** cost per protocol if all layers run: **~45 min of Claude wall-clock + 5 min of Pavel attention**.

---

## Layer 5 — staging server contract (`84.19.3.104:22`)

This is where the "lessons from the first real staging deploy"
(CLAUDE.md, Lessons table) get caught. Hardware as of 2026-05-15:

| | |
|---|---|
| Host | `84.19.3.104:22` (Debian 12, kernel 6.1.0-28-amd64) |
| RAM | 960 MiB total, ~680 MiB available |
| Disk | 20 GB, ~17 GB free |
| sing-box | 1.13.11 (from SagerNet stable APT) |
| Existing inbounds | TUIC on `:8443/UDP`, VLESS+REALITY on `:443/TCP` |
| Existing user | `tester` |
| Access | SSH key `claude-dev` (lives at `/home/user/.ssh/id_ed25519` in the container) |

**Hard rules:**

1. **Never touch** non-staging VPN servers from autonomous mode
   (safety rail #5 in `docs/AUTONOMOUS_PLAN.md`). Production VPN
   migration is Pavel-present-only.
2. Every config edit is wrapped in **upload-to-tmp + sing-box check + atomic mv + systemctl reload-or-restart + 8s is-active poll**. Sketch:
   ```bash
   scp config.json root@84.19.3.104:/tmp/sb-new.json
   ssh root@84.19.3.104 'sing-box check -c /tmp/sb-new.json \
     && cp /etc/sing-box/config.json /etc/sing-box/config.json.bak.$(date +%s) \
     && mv /tmp/sb-new.json /etc/sing-box/config.json \
     && chown sing-box:sing-box /etc/sing-box/config.json \
     && chmod 0640 /etc/sing-box/config.json \
     && systemctl reload-or-restart sing-box \
     && for i in 1 2 3 4 5 6 7 8; do
          state=$(systemctl is-active sing-box || true);
          [ "$state" = "active" ] && exit 0;
          sleep 1;
        done; journalctl -u sing-box -n 30 --no-pager; exit 1'
   ```
3. Bring back the prior config via `*.bak.<ts>` on any failure (the bak is the rollback handle).
4. **Test loopback handshake** before declaring success: spawn a
   sing-box client config on the same machine targeting `127.0.0.1`,
   record `sing-box run` exit code + connection log. This proves the
   wire-level handshake without needing a real client device.

---

## Per-protocol checklist (apply for every new addition)

Tick each item, in order. Skipping = leaving a bug class uncovered.

### A. Spec + design

- [ ] **Read the official docs** for the inbound type on
  `https://sing-box.sagernet.org/configuration/inbound/<type>/`. Quote
  the exact JSON field names + verify version requirement
  ("Since sing-box X.Y.Z") in the module doc-comment.
- [ ] **Read the wire-format spec** (e.g. SIP002 for Shadowsocks,
  RFC 9000 for QUIC-based, AmneziaWG project docs). Note any
  client-side quirks (base64url-no-pad vs base64 vs plain).
- [ ] **Decide single-user vs multi-user.** If multi-user requires
  fixed-length per-user keys we can't mint from existing material,
  ship single-user first + document the limitation.
- [ ] **Pick the secret keys** in `RenderCtx::secrets` convention.
  Namespace prefix matches the protocol's filename (e.g.
  `ss2022.psk`, `amneziawg.jc`). Document in the module's header
  doc-comment.
- [ ] **`Protocol::id()` value** is the canonical protocol name
  with hyphens (e.g. `"shadowsocks-2022"`, NOT `"ss-2022"` or
  `"shadowsocks_2022"`). Match what sing-box prints when it loads
  the config — that's the user-facing string in logs.

### B. Implementation

- [ ] One file `crates/protocols/src/<name>.rs` with `impl Protocol`.
- [ ] `Protocol::server_inbound` returns:
   - Sing-box inbound block JSON for a sing-box-served protocol.
   - **A stable JSON envelope** (NOT the kernel's native config) for
     a protocol served by a non-JSON kernel (e.g. AmneziaWG's INI).
     The envelope schema goes in the module header.
- [ ] `Protocol::client_config` is the matching outbound JSON or
  envelope. CLIENT secrets that vpnctl never sees (e.g. WG private
  key) are emitted as `<PASTE YOUR PRIVATE KEY HERE>`-style
  placeholders.
- [ ] `Protocol::share_link` returns the canonical wire share URI for
  this protocol. Trailing `#<user-id>` percent-encoded.
- [ ] `lib.rs` re-exports the type + any public constants.
- [ ] `cli/src/registry.rs` AND `daemon/src/app.rs::build_registry`
  each get **one line** `register_protocol(Box::new(MyProto::new()))?;`.
  Nothing else in `core` / `ssh` / `crypto` / `inventory` should
  change — if they do, the kernel/protocol orthogonality invariant
  was violated, fix it.

### C. Tests (the methodology layers above)

- [ ] Layer 1: `cargo clippy --workspace --all-targets -- -D warnings` is clean.
- [ ] Layer 2: in-module unit tests for any pure helper (validators,
  encoders, parsers). At least 3 tests per helper.
- [ ] Layer 3: `test-writer-agent` writes `tests/spec_<protocol>.rs`
  with the spec-only prompt. The prompt template is in `CLAUDE.md`
  under "test-writer-agent prompt template". Coverage target:
  * `<proto>_id_is_<name>` — pin the ProtocolId string
  * `<proto>_server_inbound_default_<key>` — every default value
  * `<proto>_server_inbound_override_<key>_via_secret` — each secret key
  * `<proto>_server_inbound_missing_required_secret_returns_missing_secret_error` — every `ctx.require()`
  * `<proto>_share_link_format_<feature>` — the share URI shape
  * `<proto>_share_link_byte_stable_across_runs` — pin against HashMap-iteration order bugs
  * `<proto>_share_link_special_chars_get_percent_encoded` — pin against unescaped URL injection
- [ ] Layer 4: `review-agent` on `git diff <base>..HEAD` with the
  template in `CLAUDE.md`. Fix `critical` + `important` inline.

### D. Live staging (this is the lesson-amplifier)

Run all of these on `84.19.3.104`. Don't skip even when "trivial" —
the lessons in `CLAUDE.md`'s "Lessons from the first real staging
deploy" (curl missing, log-file perms, systemctl racing) ALL surfaced
only at this layer.

- [ ] **Generate the secrets** the protocol needs on the staging box
  itself, using `sing-box generate` tools:
  ```bash
  # Shadowsocks-2022 PSK (16 bytes for aes-128-gcm)
  ssh root@84.19.3.104 'sing-box generate rand --base64 16'
  # WireGuard server keypair
  ssh root@84.19.3.104 'sing-box generate wg-keypair'
  # REALITY keypair (for VLESS+REALITY)
  ssh root@84.19.3.104 'sing-box generate reality-keypair'
  # UUID for VLESS users
  ssh root@84.19.3.104 'sing-box generate uuid'
  ```
- [ ] **Render the config** locally using a one-shot Rust program that
  exercises `Protocol::server_inbound` against a `RenderCtx` with the
  generated secrets. Save to `/tmp/staging-<protocol>.json`.
- [ ] **Validate**: `sing-box check -c /tmp/staging-<protocol>.json`.
  Exit non-zero = config is wrong, fix before pushing.
- [ ] **Atomic-deploy** (see "Layer 5" sketch above).
- [ ] **Verify `systemctl is-active sing-box`** comes back to `active`
  within 8s of restart.
- [ ] **Tail journalctl** (`journalctl -u sing-box -n 20 --no-pager`)
  for the first 10s after restart. Any line containing `error` /
  `panic` / `failed` aborts the test.
- [ ] **Handshake loopback test**: on the staging box itself, run
  `sing-box run -c /tmp/client-<protocol>.json &` with the matching
  `client_config`, then `curl -x socks5h://127.0.0.1:1080
  https://www.google.com` (sing-box exposes a SOCKS5 listener if
  configured). Exit 0 + non-empty HTML = wire-level handshake works.
- [ ] **Rollback drill**: re-deploy the prior config from
  `*.bak.<ts>` and verify the original inbounds (TUIC, VLESS) still
  work. Pavel keeps clients on the staging server for incident-response
  practice.

### E. Real-client smoke (Pavel)

- [ ] Pavel scans the share-link QR with AmneziaVPN (or whatever
  client matches the protocol) on phone.
- [ ] Pavel reports: handshake succeeded? Speedtest > 5 Mbps?
  Connection survives 5-min idle?
- [ ] If new protocol: Pavel toggles between this and an existing
  protocol (VLESS) on the same device 3× to verify no
  network-stack state lingers.

### F. Commit + push

- [ ] Commit message follows the long-form pattern from prior
  commits (root cause / what ships / tests / live-staging /
  what's NOT in this commit / co-author trailer).
- [ ] `gh run watch <id> --exit-status` to confirm CI is green
  before moving on (`CLAUDE.md` workflow rule #4).

---

## The matrix — every sing-box inbound + our position

sing-box 1.13.11 supports these inbound types. We've shipped 5 of
them; the rest are tabled with explicit decisions.

| Inbound | Wire | Anti-DPI? | Use case | Status in vpnctl | Recommendation |
|---|---|---|---|---|---|
| `vless` (+REALITY) | TCP/443 | ✅ TLS-mimics microsoft.com | Censorship-circumvention primary | ✅ shipped | keep as default |
| `tuic` v5 | UDP | ⚠️ self-signed TLS, no SNI mimic | Low-latency UDP-friendly net | ✅ shipped | keep as secondary |
| `hysteria2` | UDP/QUIC | ⚠️ fingerprintable; ✅ with Salamander obfs (just shipped) | LTE/satellite + censored networks | ✅ shipped + Realm + Salamander | promote when Pavel has rendezvous server |
| `shadowsocks` (2022) | TCP/UDP | ⚠️ different fingerprint than VLESS | Fallback channel | ✅ shipped (single-user) | wire multi-user via new `User.shadowsocks_2022_psk` column |
| `wireguard` (via AmneziaWG) | UDP | ✅ with AmneziaWG obfs params | Homelab hosting + RU resilience | ✅ shipped | needs `--wireguard-pubkey` CLI plumbing (open follow-up) |
| **`anytls`** | TCP/443 | ✅ multipath-TLS (sing-box 1.10+) | New-gen REALITY successor; harder for DPI than vanilla TLS-mimic | ❌ NOT shipped | **add — high priority**; ~200 LOC, matches REALITY's slot |
| **`shadowtls`** v3 | TCP/443 | ✅ wraps SS in real TLS handshake to a legit host | When REALITY proxy-prober gives a different fingerprint than expected | ❌ NOT shipped | **add — medium**; secondary to AnyTLS, similar threat model |
| `vmess` | TCP | ❌ deprecated by upstream, fingerprintable | Legacy compat for old clients | ❌ NOT shipped | **skip** — V2Ray's own users moved away |
| `trojan` | TCP/443 | ⚠️ TLS-mimic-like, simpler than REALITY | Backup channel | ❌ NOT shipped | **add — low priority**; nice to have but largely subsumed by VLESS+REALITY |
| `naive` | TCP/443 | ⚠️ Chrome fingerprint mimic | Niche, harder to detect on networks that don't whitelist Chrome | ❌ NOT shipped | **skip for now**; client support narrow |
| `mixed` / `socks` / `http` | TCP | n/a | Local debugging proxy | ❌ NOT shipped | **skip** — wrong abstraction (these are local proxies, not VPN inbounds) |
| `direct` | TCP/UDP | n/a | Tunneling raw | ❌ NOT shipped | **skip** — port-forward use case, not VPN |
| `tun` / `redirect` / `tproxy` | OS-level | n/a | Transparent VPN client | ❌ NOT shipped | **skip** — client-side feature, not server inbound |

**Net add to the roadmap:**

| Order | Inbound | Effort | Threat-model gap closed |
|---|---|---|---|
| 1 | AnyTLS | ~200 LOC + tests | DPI catching REALITY's specific pattern; AnyTLS uses different TLS extension fingerprint |
| 2 | ShadowTLS v3 | ~250 LOC + tests | TLS-mimic with different shape than REALITY's proxy-rotation |
| 3 | Trojan | ~150 LOC + tests | "I need yet another channel" insurance |
| — | VMess, Naive, mixed, direct, tun | — | **skip** — see table above |

---

## Roles — who does what

| Actor | Owns | Touches |
|---|---|---|
| **Claude** (this agent) | Layers 1-5 + 7 setup. Code, tests, agent orchestration, SSH-deploys, staging server config, journalctl forensics, retention/cleanup. | `~/vpn-control/vpnctl/**`, `84.19.3.104` (SSH root). |
| **Sub-agents** (orchestrated by Claude) | Layer 3 (`test-writer-agent` — spec only, no impl), Layer 4 (`review-agent` — diff only, no design context), Plan-agent (Phase architecture). | Their prompt's bounded view only; never see the codebase outside what Claude pastes. |
| **Pavel** | Layer 6 (real clients) + Layer 8 (anti-censorship validation) + production decisions + secrets Claude can't have (Telegram token, GPG key fingerprints from external sources, AmneziaVPN PPA verifications). | His laptop, his phone, production VPN nodes (per safety rail #5). |
| **CI** (GitHub Actions) | Layer 1 + Layer 2 on every push. | `main` branch enforcement. |
| **Retention purger** (in `vpnctld`) | Hourly cleanup of `sub_access_log` and `vpn_connection_stats`. | `/var/lib/vpnctl/inv.db` on `192.168.0.236`. |

---

## Time budgets — realistic burst planning

Use these to size autonomous-mode burst plans.

| Task class | Time | Notes |
|---|---|---|
| Add a new sibling protocol (copy-paste from VLESS/TUIC/Hysteria2) | 30–45 min | New protocol that doesn't need new traits / new kernel. AnyTLS, Trojan, ShadowTLS all fit here. |
| Add a new kernel (sing-box → wgturn → xray) | 90–120 min | Plan-agent + new dep handling + ensure_installed shell script + 3 staging deploys to catch lessons. AmneziaWG took ~90 min in burst (audit + impl + tests, no live staging yet). |
| Audit-fix from review-agent output | 15–25 min | Per finding: 5 min to understand, 5 min to fix, 5 min to test. 4 findings = 30 min worst case. |
| Live staging deploy with new protocol | 15–30 min | First time on a fresh node = 30 min. Re-running on a node that's already bootstrapped = 10–15 min. |
| Wizard/UI work (Phase E) | 60–90 min per sub-iter | SSE handler, axum extractors, copy-contract test rounds — much higher per-LOC cost than backend work. |
| Read-only feature (UI section, log surface) | 30–60 min | Phase Track-4 UA fingerprint took ~45 min in burst. |
| Schema migration + inventory method + UI | 90–120 min | Track-3 chunks 1–3 — three commits, ~90 min combined. |

---

## Anti-patterns we've already paid for

| Anti-pattern | What it bought us | When it surfaced |
|---|---|---|
| Skipping live staging for "trivial" config changes | `sing-box: open /var/log/sing-box.log: permission denied` on first real deploy | Lessons table in CLAUDE.md |
| `sing-box check` returns 0 but service silently exits | Deploy "succeeds" while sing-box crash-loops; 10 min of "why isn't it working" | Same lessons table; fix is the 8s `is-active` poll |
| Trusting `cargo test` alone for a new public API | review-agent caught a per-user double-count bug in `clash_poller` that all 7 in-module tests missed | `ebb2d7f` commit message |
| `HashMap` iteration for share-link assembly | Hypothetical (caught by spec test before shipping): `BTreeMap` or sort-then-emit is mandatory for byte-stable links | `wg_share_link_byte_stable_across_runs` test |
| Including `:` in SS-2022 password without splitting method-encode + password-encode | First-run failure in agent-written spec test for Shadowsocks-2022 | `7708716` commit message |

---

## Future of this doc

Append to "Anti-patterns" every time a real-staging test catches
something this doc didn't warn about. The doc is the institutional
memory; if a future commit pays a 30-min debugging cost for
something this doc could have prevented, write the lesson here.

---

## First application — 2026-05-15 staging session on 84.19.3.104

Validated the methodology by running it end-to-end against the three
protocols added in the prior burst (Salamander obfs, Shadowsocks-2022,
AmneziaWG). Time costs measured live so future sessions can plan.

### Salamander obfs (Hysteria2)
- **Time:** 8 min total (2 min config render + push, 1 min validate +
  restart, 5 min loopback handshake test + negative test)
- **Result:** ✅ HTTP 200 through `client → SOCKS5 → Hysteria2+Salamander
  → server → google.com`. Wrong-obfs-password handshake fails as
  expected.
- **Live state on staging:** Hysteria2 inbound on `:8444/UDP`, alongside
  TUIC + VLESS. obfs password generated via `sing-box generate rand
  --base64 16`.

### Shadowsocks-2022
- **Time:** 6 min total
- **Result:** ✅ HTTP 200 through `client → SOCKS5 → SS-2022(2022-blake3-aes-128-gcm)
  → server → google.com`. Wrong-PSK handshake fails as expected.
- **Live state on staging:** Shadowsocks-2022 inbound on `:8388/TCP+UDP`.
  PSK generated via `sing-box generate rand --base64 16`.

### AmneziaWG (full kernel install + handshake)
- **Time:** ~50 min (target was 30, real was 50 — three live-staging
  lessons added below)
- **Result:** ✅ "latest handshake: Now" + 0% packet loss on ping
  through tunnel. All 9 obfs params (Jc/Jmin/Jmax/S1/S2/H1-H4) loaded
  on both server + client per `awg show` output.
- **Live state on staging:** `amneziawg` + `amneziawg-tools` packages
  installed from the AmneziaVPN PPA. `awg0.conf` saved (interface
  torn down to free port 51820 — easy to bring back up).

### Three new live-staging lessons (now baked into `kernels::amnezia_wg::ensure_installed`)

| # | Symptom | Root cause | Fix |
|---|---|---|---|
| L1 | `add-apt-repository -y ppa:amnezia/ppa` → `AttributeError: 'NoneType' object has no attribute 'people'` | `softwareproperties.ppa.lpteam` returns None when launchpadlib's API auth is broken on stock Debian 12 | Skip add-apt-repository entirely; manual `gpg --keyserver ... --recv-keys <FPR>` + `gpg --export > /usr/share/keyrings/amnezia.gpg` + manual `/etc/apt/sources.list.d/amnezia.list`. Pinned fingerprint `75C9DD72C799870E310542E24166F2C257290828` (confirmed via Launchpad API on 2026-05-15). |
| L2 | `awg-quick up awg0` → "Module amneziawg not found in directory /lib/modules/6.1.0-28-amd64" | `linux-headers-amd64` meta package installs headers for the LATEST kernel Debian ships (e.g. 6.1.0-48), not the running kernel (6.1.0-28). DKMS builds the module for the headers it can find — wrong kernel ABI for runtime. | Detect mismatch in `ensure_installed` after install; exit 2 with a clear "reboot required" message. The operator decides when to reboot. After reboot, `modprobe amneziawg` succeeds. |
| L3 | `gpg --keyserver ... --recv-keys` → "can't connect to the agent: Configuration error" | Stock Debian 12 ships `gnupg` but not `dirmngr` (the GPG keyserver client). `gpg` can't reach a keyserver without it. | `apt-get install -y dirmngr` before any `gpg --recv-keys`. |

These three lessons mirror the three from the original sing-box
deploy (curl missing / log-file perms / systemctl racing). The
pattern repeats: **every new kernel ships ~3 environmental bugs
that only surface live**. Budget for them.

### Methodology validation

The six-layer pyramid worked as designed:
- Layer 1-2 (cargo + clippy) caught nothing (the impl was already
  clean from the prior burst).
- Layer 3 (spec tests) caught nothing (we'd already fixed the SS-2022
  `:` bug there).
- Layer 4 (review-agent) caught nothing new in this validation pass
  (the prior `ebb2d7f` audit already cleared the burst).
- **Layer 5 (live staging) caught all three AmneziaWG lessons.**
- Layer 6 (real client) — pending Pavel's phone test of the
  AmneziaWG `.conf` he can paste into AmneziaVPN.

The methodology is consistent with the per-protocol time budget
in the table above: AmneziaWG took 50 min not 30, because it's a
new kernel + first-time-on-staging combo (the budget table does
say 90-120 min for "add a new kernel" — 50 min for live-staging
alone fits that envelope).
