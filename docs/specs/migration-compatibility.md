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
    Empty sing-box and Mihomo responses deliberately change to fail closed
    as described below; non-empty responses retain their bytes.

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
- `migrate from-bash` verifies the SSH host key before authentication or file
  reads. It uses inventory pins found by server ID or address; conflicting pins
  fail closed. Without an inventory pin, import one server at a time with
  `--server <IP> --trusted-fingerprint <SHA256:...>` obtained from the hoster's
  console. The explicit fingerprint cannot override an inventory pin. Successful
  apply retains the verified pin (audited when adding a pin to an existing row).
  Dry runs consult existing inventory through normal inventory-open maintenance
  but never apply servers, users, grants, secrets, or new pins.
- UUIDs and password material migrate verbatim (`vpnctl migrate from-bash`);
  overwriting an existing server address requires the
  `--i-really-mean-overwrite-address` gate. Existing server secrets are retained
  unless `--overwrite-existing` is set. User replacement is transactional;
  other-server grants retain their effective UUIDs. Sequential server plans
  preserve each imported server's UUID through `grants.client_uuid`.
- Hidden protocols stay running on the node (cached client URIs keep working);
  hiding only removes them from fresh renders.
- After sing-box deployment collects `tls.cert_sha256`, fresh Hysteria2 links
  add `pinSHA256`; Mihomo adds certificate fingerprints and enables pinned
  Trojan, AnyTLS and TUIC proxies. Existing certificates, credentials and
  insecure flags remain unchanged, so previously imported profiles keep working.
  No-pin output, other share links and sing-box JSON retain their bytes.
  See [self-signed TLS pinning](self-signed-tls-pinning.md).
- Disabled users and users with no usable routes get an empty config envelope.
  Empty sing-box responses route DNS and final traffic to the existing `block`
  outbound; empty Mihomo responses put only `REJECT` in the `VPN` group with
  `MATCH,VPN`. This deliberately replaces the former direct fallback only in
  empty responses. Re-enabling or restoring routes restores the non-empty
  response byte-for-byte. Already imported profiles change on subscription
  refresh; this does not rewrite cached profiles on clients.
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

- [ ] Migration reuses inventory pins by ID and address, rejects conflicting or
      missing trust before SSH/import, and persists first-import pins on apply.
- [ ] `*_byte_equal*` tests pass; `just mutants-protocols` shows the tests
      catch inverted rendering.
- [ ] `daemon/tests/restore_e2e.rs`: pre-mutation output ≠ post-mutation AND
      pre-mutation output == restored output (guards against vacuous pass).
- [ ] Any deliberate output change ships WITH an updated pinned expectation and
      a migration note — never as a silent by-product.

## Shadowsocks-2022 per-user keys (D7-01)

### Intent & invariants

Existing SS2022 profiles keep their bytes and work until the operator explicitly
switches modes. Rendering owns no inventory state. User removal, disabling or
UUID rotation revokes that user's per-user key on the next deploy.

### Interface / data contract

- Per-server `ss2022.mode` is `shared` (also the default when absent) or
  `multi-user`. Shared mode retains the previous inbound, client config and
  share-link bytes for all three methods.
- Multi-user mode supports only `2022-blake3-aes-128-gcm` and
  `2022-blake3-aes-256-gcm`. ChaCha20 and unknown modes are rejected before
  saving settings and by renderers.
- The inbound retains the server PSK as `password` and adds `users`, containing
  `name` (user ID) and `password` (user PSK) for each rendered user, including
  an empty list when no users remain. The user PSK is standard padded base64
  of the first 16 / 32 bytes of HMAC-SHA256, keyed by the decoded server PSK,
  over `b"vpnctl-ss2022-user\0" || user.uuid.as_bytes()`. UUIDs include the
  existing per-server grant override. No user secrets are stored.
- Client passwords are `<server PSK>:<user PSK>`; share links apply the existing
  percent encoding to the combined password.
- `POST /admin/servers/{id}/ss2022-mode`, form field `mode`, requires an enabled
  SS2022 protocol and existing admin auth / same-origin CSRF protection.
  Changes use `set_server_secrets_audited` (`server.secret.set`) and mark the
  server pending deploy. Equal saves, including absent mode → shared, do not
  mutate or audit. The Protocols tab offers both directions with EN/RU copy:
  after the next deploy every SS2022 user must re-import their profile.
- New enables remain shared: the common bootstrap also runs for existing
  servers, and protocol secret declarations currently mint random material,
  without a hook for constant defaults exclusively on first enable. It must
  not silently switch an existing server during a deploy.
- Mihomo and app-config currently omit SS2022; their bytes remain unchanged.

### Verification

- Protocol tests pin complete inbound, client config and share-link bytes for
  shared / absent mode and both multi-user AES methods, with independent HMAC
  known answers; cover removal, UUID rotation and ChaCha20 rejection.
- Admin tests cover EN/RU forms, both switches, missing/disabled servers,
  invalid modes, CSRF, audit, pending deploy and equal saves.
- HTTP regression tests compare complete `/sub` bodies in URL and sing-box
  formats and unchanged `/api/v1/sub` / app-config bodies, including per-server
  UUID overrides, disabled users and deleted users in deploy render inputs.
