# Spec: AWG3 Delivery in VPNRouter Subscriptions

## 1. Intent & Invariants
- **What:** Deliver AmneziaWG 3.0/3.1 (`amneziawg3`) links with `awg3://` scheme in the `/api/v1/app/config/<device_id>` subscription endpoint for `VPNRouter` clients.
- **Invariants:**
  - Strict UA-gating: `awg3://` URIs are delivered ONLY to clients matching `is_vpnrouter_client_ua(ua)` (`VPNRouter`). Generic clients (`v2ray`, `clash`, `sing-box`, etc.) never see `awg3://` lines.
  - Non-interference: Existing links (`vless://`, `hysteria2://`, `awg://` for AWG2, `vless://...?type=xhttp`) remain byte-for-byte intact and in stable order.
  - Failure-isolation: A render error on an `amneziawg3` server (e.g. missing header protection key or keypair) is logged as a warning and skipped, never dropping the user's working links.
  - Server-role & auto-suppress & visibility: `amneziawg3` respects `is_server_auto_suppressed`, `visible_protocols_for_subscription`, client detour exclusion, and user disabled flags.
  - Pure Class A control-plane change: zero remote VPN node downtime, no node service restart, zero token invalidation.

## 2. Interface / Data Contract
- **Protocol ID:** `amneziawg3` (UDP port 51822, subnet `10.73.0.0/16`).
- **URI Scheme:** `awg3://`
- **URI Format:**
  `awg3://<server_public_key>@<host>:51822?private_key=<client_private_key>&address=<client_ip>/32&keepalive=25&jc=<jc>&jmin=<jmin>&jmax=<jmax>&s1=<s1>&s2=<s2>&s3=<s3>&s4=<s4>&h1=<h1-range>&h2=<h2-range>&h3=<h3-range>&h4=<h4-range>&header_protection_key=<hpk_hex>&content_padding_addition=0-32&random_trailers=true&disable_cookies=true#<label>%20AWG3%20~<user>`
- **Exported API:**
  - `vpnctl_protocols::awg3_share_link(&RenderCtx, &User) -> Result<String>` in `crates/protocols/src/amneziawg.rs` and re-exported in `crates/protocols/src/lib.rs`.
- **Subscription Collector:**
  - `collect_awg_subscription_uris` in `daemon/src/handlers/vpn_router/collectors.rs` supports `amneziawg3` alongside `amneziawg2` and legacy `wireguard`.
  - When both `amneziawg2` and `amneziawg3` are enabled on a node, both links are appended in version order (`AWG` then `AWG3`).

## 3. Verification Checklist (Definition of Done)
- [ ] Unit tests in `crates/protocols/src/amneziawg/tests.rs` verify `awg3_share_link` generates valid `awg3://` URI with all 14 parameters, and fails closed when keys/secrets are missing.
- [ ] Integration test in `daemon/tests/vpn_router_endpoint/protocols.rs` verifies `awg3://` delivered to `VPNRouter`.
- [ ] Test verifies generic client does NOT receive `awg3://`.
- [ ] Test verifies servers with both `amneziawg2` and `amneziawg3` emit both links with correct ports and fragments.
- [ ] Full `cargo check`, `cargo fmt`, `cargo clippy`, `cargo test`, `cargo deny check`, `gitleaks` clean.
- [ ] Independent diff review passes with no critical/important issues.
- [ ] PR merged to `main`, built on `debian-xfce`, and deployed to production controller with live subscription verification.
