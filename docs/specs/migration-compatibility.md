# Contract: migration & client compatibility

## 1. Intent & Invariants

- What: vpnctl replaced a bash toolkit (`vpn-control`) and a Python
  subscription-server WITHOUT re-onboarding a single client. Old phones holding
  `vless://` / `tuic://` links keep working byte-for-byte after any switch.
- Invariants:
  - `Protocol::share_link()` produces output byte-identical to the bash
    scripts for the same secret material — including query-param ORDER
    (e.g. vless reality: `encryption=none` first, then the bash order) and
    fragment naming.
  - `GET /api/v1/app/config/{device_id}` is byte-equivalent to the legacy
    subscription-server on the primary URI; per-(user, server) UUID continuity
    is carried by `grants.client_uuid`.
  - Restore must not change rendered output: after `vpnctl restore`,
    `/api/v1/app/config/<id>` is byte-identical for every user (CI-enforced).
  - `GET /sub/<token>` keeps its User-Agent-selected bytes unchanged. New client
    capabilities use explicit query-selected formats; `format=sing-box` is an
    additive stock sing-box JSON response and never changes the default URL.

## 2. Interface / Data Contract

```rust
// crates/protocols — every protocol pins its exact wire string.
// Regression tests: *_byte_equal* (share links, subscription bodies).
// Render naming: URI fragment "{Label} {PROTO} ~{client_name}".
// Label = servers.display_name (operator-settable) → country map → upper id.
// '~' is the separator: the only ASCII char unreserved by RFC 3986 AND absent
// from every production user id.
```

Behavior rules:
- UUIDs and password material migrate verbatim (`vpnctl migrate from-bash`);
  overwriting an existing server address requires the
  `--i-really-mean-overwrite-address` gate. Existing server secrets are retained
  unless `--overwrite-existing` is set. User replacement is transactional;
  other-server grants retain their effective UUIDs. Sequential server plans
  preserve each imported server's UUID through `grants.client_uuid`.
- Hidden protocols stay running on the node (cached client URIs keep working);
  hiding only removes them from fresh renders.
- Disabled users get an empty config envelope; re-enabling restores
  byte-for-byte.
- App-config extra protocols resolve UUIDs with
  `COALESCE(grants.client_uuid, users.uuid)`, just like `/sub`. Correcting a
  per-server override changes only UUID-bearing links for that server; users
  without overrides keep identical bytes.
- Sing-box tags and Mihomo names keep `{Label} {PROTO} ~{client_name}` when
  unique among emitted outbounds. Colliding names gain ` ({server_id})` in
  server-ID order (a numeric suffix resolves any remaining collision).
  Selectors, groups, and detours use the resolved names. This deliberately
  repairs previously ambiguous configurations; unrelated tags keep their bytes.
- The admin WireGuard `.conf` download requires an enabled user with a grant,
  a VPN-exit server, a visible WireGuard protocol without a disabled grant
  override, no active auto-suppression, and no client detour. These visibility
  and routing exclusions return `400` with an admin settings message; allowed files retain
  their existing bytes. AmneziaWG 2/3 downloads retain their existing checks.

## 3. Verification Checklist

- [ ] `*_byte_equal*` tests pass; `just mutants-protocols` shows the tests
      catch inverted rendering.
- [ ] `daemon/tests/restore_e2e.rs`: pre-mutation output ≠ post-mutation AND
      pre-mutation output == restored output (guards against vacuous pass).
- [ ] Any deliberate output change ships WITH an updated pinned expectation and
      a migration note — never as a silent by-product.
