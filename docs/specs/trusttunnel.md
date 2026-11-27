# TrustTunnel

## Intent and invariants

TrustTunnel is opt-in on nodes with managed sing-box. It uses TLS over HTTP/2
and can also listen for HTTP/3 on the same UDP port. Usernames are inventory
IDs and passwords are the UUIDs issued for the corresponding server grants.
Disabled users, denied grants, and invalid credentials are excluded from the
inbound. The listener starts once there is an eligible user.

## Interface and data contract

- The default listener is TCP and UDP on port 8444. Configure
  `trusttunnel.listen_port` in 1–65535 and set `trusttunnel.quic=false`
  to close the HTTP/3 listener. `trusttunnel.udp` controls UDP forwarding
  and defaults to true. `trusttunnel.client_quic` defaults to false.
- Managed TLS uses the node's sing-box certificate and key, honoring
  `tuic.cert_path` and `tuic.key_path`. SNI comes from `trusttunnel.sni`,
  `tls.server_name`, or the node address. Issuance requires the observed
  leaf SPKI SHA-256 digest. A custom CA certificate requires a DNS domain,
  a PEM chain that covers the domain, and a matching unencrypted PEM private
  key together. Clients verify custom certificates with their trust stores.
- VPNRouter clients advertise `trusttunnel-v1` to receive
  `trusttunnel://` links. Only visible, direct grants are eligible.
  Managed TLS links carry the lowercase hex SPKI digest in `pk_sha256`.
  The native outbound encodes the same digest in base64.

## Verification checklist

- Validate transport, port, credentials, TLS material, and both pin encodings.
- Compare legacy subscription bytes with and without an enabled inbound.
- Exercise the admin toggle, settings form, and listener conflict checks.
