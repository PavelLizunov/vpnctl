# VMess WebSocket over TLS

## Intent and invariants

Enable VMess on a VPN exit through the Protocols page. Users with a grant
receive VMess when they refresh their existing subscription. The server uses
the managed sing-box kernel and its ordinary per-server client UUIDs. New
nodes keep the existing default protocols.

## Interface and data contract

- Enter a TLS hostname, matching PEM certificate chain and private key on the
  Protocols page. The TCP port defaults to 443. Deploy validates the endpoint
  and applies the configuration. Reserve the hostname for this node and use
  the same hostname for DNS, certificate, TLS and the WebSocket Host. The
  fixed WebSocket path is `/vmess`. Certificate renewals use the same settings.
- Standard sing-box subscriptions emit native VMess JSON. V2Ray links are
  `vmess://` followed by standard Base64 JSON. Both use AEAD and
  `aes-128-gcm`. Grants and visibility apply as they do to other protocols.
- VPNRouter sends `vmess-v1` for VMess app-config rows. With `detour-v1`
  and an optional configured entry, the feed also emits a labeled two-hop
  profile. The entry must be a visible, direct VLESS Reality route already
  granted to that user. The target uses the VMess origin IP while keeping the
  TLS hostname. The independent direct profile uses the TLS hostname.
  A server-wide detour policy requires the chain and suppresses the direct
  profile. Existing clients keep their previous subscription bytes.

## Verification

- Pin the VMess link and native config. Test grant, visibility, both
  capabilities and the entry requirement through the subscription endpoints.
- After applying the configuration, refresh the same subscription in
  VPNRouter and verify the endpoint appears. Use the Windows client to make an
  authenticated HTTPS request and verify the expected exit IP.
