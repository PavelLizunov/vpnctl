# Spec: VLESS Reality XUDP

## 1. Intent & Invariants

- What: make every vpnctl-issued VLESS Reality client artefact explicitly enable XUDP so UDP applications such as Discord voice work through the existing TCP/REALITY session.
- Invariants: existing user UUIDs, subscription tokens, REALITY keys, server inbounds, TCP behaviour, port selection, SNI, flow and fingerprints remain unchanged.
- The canonical `/sub` renderer and the vpn-router/ninitux URI renderer must not drift.

## 2. Interface / Data Contract

```rust
// sing-box outbound
{"type":"vless", "flow":"xtls-rprx-vision", "packet_encoding":"xudp"}

// vless:// import URI query
packetEncoding=xudp
```

## 3. Verification Checklist

- [ ] `VlessReality::client_config` emits `packet_encoding: "xudp"`.
- [ ] `VlessReality::share_link` emits `packetEncoding=xudp` in pinned order.
- [ ] vpn-router/ninitux VLESS URIs emit the same import parameter.
- [ ] Existing server inbound and credentials are byte/semantically unchanged.
- [ ] Byte-level compatibility tests pin the intentional URI change.
- [ ] Protocol and vpn-router tests pass.
- [ ] Independent diff review reports no critical/important findings.
- [ ] `cargo fmt --all`, `just ci`, secret scan and GitHub Actions pass.
- [ ] Production deploy has binary backup, active systemd, health 200 and end-to-end UDP verification.
