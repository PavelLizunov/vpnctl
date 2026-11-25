# RF DPI / DNS / SNI Hardening

## 1. Intent & Invariants

Harden `vpnctl` against Russian TSPU/DPI filtering and DNS leaks/hijacking while
preserving byte-for-byte compatibility for existing servers and legacy client
profiles unless explicitly opted in (with one deliberate security fix to
non-empty sing-box client subscriptions documented in
`migration-compatibility.md`).

Invariants:
- Legacy servers without newly introduced secret keys (`vless.fp`,
  `vless.handshake_server`, `vless.handshake_port`, `tls.server_name`) MUST
  continue rendering byte-identical `server_inbound`, `client_config`,
  `share_link`, and `/api/v1/app/config/{device_id}` outputs (`yahoo.com` SNI,
  `randomized` uTLS fingerprint, handshake target `(sni, 443)`, no QUIC
  `server_name`).
- Newly registered servers (`register_new_server`, used by quick-add and the
  bootstrap wizard) persist `vless.sni = "www.apple.com"` and
  `vless.fp = "chrome"` so new deployments avoid Russian SNI domains on foreign
  VPS hosts and avoid the `randomized` uTLS fingerprint.
- Protocol rendering owns no mutable inventory state; all configuration arrives
  via `RenderCtx`.
- Every admin configuration mutation is validated fail-closed before saving,
  uses `set_server_secrets_audited`, and emits zero audit rows and zero
  pending-deploy markers on no-op saves.
- Newly generated node self-signed certificates use `/CN=localhost` instead of
  `/CN=sing-box`; existing certificates on disk are never rotated.
- Server-side `sing-box` configs explicitly declare upstream DNS (`1.1.1.1` +
  `9.9.9.9`, `strategy: "prefer_ipv4"`) with `route.default_domain_resolver: "dns-cf"`
  so exit nodes never depend on hoster-provided resolvers.
- Non-empty client `sing-box` subscriptions (`/sub/<token>` and
  `/sub/<token>?format=sing-box`) route DNS through the tunnel (`vpn-dns` DoH
  `1.1.1.1` via `proxy`) and hijack DNS (`sniff` + `hijack-dns`), using
  `local-dns` (`type: "local"`) strictly as `route.default_domain_resolver`.
  Empty fail-closed responses (disabled or ungranted users) remain unchanged.
- Firewall reconciliation (`reconcile_firewall`) warns when UFW is absent or
  inactive and an active `nftables` `input` chain with `policy drop` lacks an
  explicit allow rule for any protected port.

## 2. Interface / Data Contract

### `vpnctl_protocols` public API (`crates/protocols/src/lib.rs`)

Constants:
```rust
pub const DEFAULT_REALITY_SNI: &str = "yahoo.com";
pub const NEW_SERVER_REALITY_SNI: &str = "www.apple.com";
pub const DEFAULT_REALITY_FP: &str = "randomized";
pub const NEW_SERVER_REALITY_FP: &str = "chrome";
pub const VALID_REALITY_FPS: &[&str] = &[
    "chrome",
    "firefox",
    "safari",
    "ios",
    "android",
    "edge",
    "360",
    "qq",
    "random",
    "randomized",
];
```

Functions:
```rust
/// Returns true iff `value` is an exact member of `VALID_REALITY_FPS`.
pub fn is_valid_reality_fp(value: &str) -> bool;

/// Returns `vless.fp` from `secrets` when present and valid per
/// `is_valid_reality_fp`, otherwise `DEFAULT_REALITY_FP` ("randomized").
pub fn reality_fp(secrets: &std::collections::HashMap<String, String>) -> &str;

/// Returns true iff `sni` is a valid non-IP ASCII hostname (1..=253 bytes,
/// dot-separated 1..=63-char labels of `[A-Za-z0-9-]` not starting or ending
/// with `-`, rejecting IPv4/IPv6 literals).
pub fn is_valid_reality_sni(sni: &str) -> bool;

/// Returns true iff `server` is a valid REALITY handshake destination host:
/// either a literal IPv4/IPv6 address (e.g. `127.0.0.1`, `::1`) or a valid
/// hostname per `is_valid_reality_sni`.
pub fn is_valid_reality_handshake_server(server: &str) -> bool;

/// Resolves the REALITY handshake target `(server, port)` for `server_inbound`.
/// - `server`: trimmed `vless.handshake_server` when valid per
///   `is_valid_reality_handshake_server`, otherwise `sni`.
/// - `port`: trimmed `vless.handshake_port` parsed as `u16` in `1..=65535`,
///   otherwise `443`.
pub fn reality_handshake_target<'a>(
    secrets: &'a std::collections::HashMap<String, String>,
    sni: &'a str,
) -> (&'a str, u16);

/// Returns trimmed `tls.server_name` from `secrets` when valid per
/// `is_valid_reality_sni`, otherwise `None`.
pub fn tls_server_name(
    secrets: &std::collections::HashMap<String, String>,
) -> Option<&str>;
```

Protocol rendering rules:
- `VlessReality`:
  - `server_inbound`: `tls.server_name` = `sni`; `tls.reality.handshake` =
    `{ "server": handshake_server, "server_port": handshake_port }` from
    `reality_handshake_target(ctx.secrets, sni)`.
  - `client_config`: `tls.utls.fingerprint` = `reality_fp(ctx.secrets)`.
  - `share_link`: `fp=<reality_fp(ctx.secrets)>` in the existing query-param
    order.
- `VlessXhttp`:
  - `server_inbound`: `streamSettings.realitySettings.serverNames` = `[sni]`;
    `streamSettings.realitySettings.dest` =
    `format!("{}:{handshake_port}", host_for_url(handshake_server))` (IPv6
    literals bracketed, e.g. `[::1]:8443`).
  - `client_config`: `tls.utls.fingerprint` = `reality_fp(ctx.secrets)`.
  - `share_link`: `fp=<reality_fp(ctx.secrets)>` in the existing query-param
    order.
- `TuicV5` and `Hysteria2`:
  - `client_config`: when `tls_server_name(ctx.secrets)` is `Some(name)`, sets
    `tls.server_name = name`. When `None`, `tls.server_name` is omitted
    (preserving legacy bytes).
- App-config VLESS URI collector (`collect_vless_uris_for_user` /
  `/api/v1/app/config/{device_id}`): emits `fp=<reality_fp(secrets)>` in the
  existing parameter position.

### `vpnctl_kernels` contracts

- `SingBox::render_config`:
  - Always emits top-level `"dns"`:
    ```json
    {
      "servers": [
        { "tag": "dns-cf", "type": "udp", "server": "1.1.1.1" }
      ],
      "final": "dns-cf",
      "strategy": "prefer_ipv4"
    }
    ```
  - Always sets `"default_domain_resolver": "dns-cf"` inside `"route"` (even
    when `inbounds` and `endpoints` are empty).
- `SING_BOX_SETUP_SCRIPT`: generates missing `/etc/sing-box/cert.pem` with
  `-subj '/CN=localhost'` (keeping the `[ ! -f /etc/sing-box/cert.pem ] || [ ! -f /etc/sing-box/key.pem ]` guard).
- `reconcile_firewall`:
  - Preserves the single privileged SSH `exec` contract ending with
    `cleanup <sorted deduplicated tcp:PORT/udp:PORT tokens>`.
  - When UFW is absent or inactive and `nft -j list ruleset` reports an
    `input` chain with `policy drop` missing an explicit accept rule for any
    protected port, prints `nft-blocked:<proto>:<port>` tokens on stdout.
  - `reconcile_firewall` parses `nft-blocked:tcp:PORT` / `nft-blocked:udp:PORT`
    tokens (without echoing arbitrary stdout) and returns `Some(...)` naming
    the blocked ports (`"nftables input chain has policy drop without an explicit accept rule for: <ports> (UFW is inactive or not installed)"`),
    combining with any UFW unmarked-allowance warning via `"; "`.

### Daemon HTTP & Admin UI contracts

- Non-empty `/sub/<token>` (sing-box JSON) and `/sub/<token>?format=sing-box`:
  - Emits `"dns"` with `vpn-dns` (`type: "https"`, `server: "1.1.1.1"`,
    `path: "/dns-query"`, `detour: "proxy"`) and `local-dns` (`type: "local"`),
    `"final": "vpn-dns"`.
  - Emits `"route"` with `"rules": [{"action": "sniff"}, {"protocol": "dns", "action": "hijack-dns"}]`,
    `"final": "proxy"`, `"auto_detect_interface": true`,
    `"default_domain_resolver": "local-dns"`.
  - Empty sing-box configs (disabled/no-grant users) keep their existing
    fail-closed bytes.
- `POST /admin/servers/{id}/reality-config`:
  - Existing fields `listen_port`, `sni` keep their exact behavior (omitted
    field preserves stored secret; empty `sni` returns `400`).
  - Optional new fields (only modified when present in the form body):
    - `fp`: empty clears `vless.fp` (no-op if unset); non-empty must satisfy
      `is_valid_reality_fp`, else `400`.
    - `handshake_server`: empty clears `vless.handshake_server` (no-op if
      unset); non-empty must satisfy `is_valid_reality_handshake_server`, else
      `400`.
    - `handshake_port`: empty clears `vless.handshake_port` (no-op if unset);
      non-empty must parse as `u16` in `1..=65535`, else `400`.
  - Audited under `server.reality.set` on actual mutation only.
- `POST /admin/servers/{id}/quic-tls-config`:
  - Requires existing server with `tuic-v5` or `hysteria2` enabled (else `404`
    or `400`), protected by existing admin auth & same-origin CSRF.
  - Form field `server_name`: empty clears `tls.server_name` (no-op if unset);
    non-empty must satisfy `is_valid_reality_sni`, else `400`.
  - Audited under `server.quic_tls.set` on actual mutation only; redirects
    `303` to `/admin/servers/{id}/protocols`.
- Protocols tab renders localized EN/RU controls for `fp`, `handshake_server`,
  `handshake_port` inside the REALITY form, and a QUIC TLS SNI form when
  `tuic-v5` or `hysteria2` is enabled.

## 3. Verification Checklist

- [ ] Legacy byte-equality tests pass unchanged when new secrets are unset
      (`vless.fp`, `vless.handshake_server`, `vless.handshake_port`,
      `tls.server_name`).
- [ ] Spec-tests (written from this spec alone) verify all new public
      `vpnctl_protocols` helpers, IPv6 bracketed XHTTP `dest`, `vless.fp`
      rendering across `VlessReality`, `VlessXhttp`, and app-config, QUIC
      `tls.server_name`, `SingBox` server DNS + `default_domain_resolver`,
      `reconcile_firewall` nftables drop-policy warnings, and admin HTTP
      validation/audit/no-op behavior for `reality-config` and
      `quic-tls-config`.
- [ ] Sing-box client subscription tests pin the non-leaking DNS envelope and
      preserve empty fail-closed bytes.
- [ ] New server registration persists `vless.sni = "www.apple.com"` and
      `vless.fp = "chrome"`.
- [ ] Independent review-agent finds zero unresolved `critical` / `important`
      issues; `cargo fmt --all -- --check`, `gitleaks`, and full GitHub Actions
      CI pass.
