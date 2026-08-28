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
  `--i-really-mean-overwrite-address` gate.
- Hidden protocols stay running on the node (cached client URIs keep working);
  hiding only removes them from fresh renders.
- Disabled users get an empty config envelope; re-enabling restores
  byte-for-byte.

## 3. Verification Checklist

- [ ] `*_byte_equal*` tests pass; `just mutants-protocols` shows the tests
      catch inverted rendering.
- [ ] `daemon/tests/restore_e2e.rs`: pre-mutation output ≠ post-mutation AND
      pre-mutation output == restored output (guards against vacuous pass).
- [ ] Any deliberate output change ships WITH an updated pinned expectation and
      a migration note — never as a silent by-product.
