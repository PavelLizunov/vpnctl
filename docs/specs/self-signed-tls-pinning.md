# Self-signed TLS certificate pinning (D7-03)

## Intent & invariants

Successful sing-box deployment observes the node's certificate over the existing
SSH transport. Fresh Hysteria2 and TUIC profiles require a certificate or public
key pin in a format supported by the client. Previously imported local profiles
need a refresh or reimport to acquire the new TLS settings. Protocol rendering
remains stateless and uses existing inventory fields.

## Interface / data contract

- `Kernel::deployed_server_secrets` defaults to an empty batch. Sing-box reads
  `tuic.cert_path` (default `/etc/sing-box/cert.pem`) with `openssl x509` after
  apply and firewall success. It reads one leaf and derives two SHA-256 hashes
  from it, the DER certificate fingerprint in `tls.cert_sha256` and the DER
  SubjectPublicKeyInfo hash in `observed.tls.cert_public_key_sha256`. Both
  must parse completely before the batch is saved as lowercase hex.
- Inventory's `refresh_deployed_server_secrets` uses the existing audited
  compare-and-set batch helper. Only changed observations write
  `server.deployed_secrets.set`, containing key names only. Read/validation/write
  failures fail the deploy. Bootstrap, redeploy, admin deploy and CLI deploy all
  call it. These observations are excluded from deploy inputs. Redeploy the
  node after changing its certificate so fresh profiles pick up the observed
  values. Before rollout, read both hashes through the existing pinned SSH
  route and seed them through the existing `server secret` operation, or
  coordinate node redeploys so new profiles receive the pins immediately.
- Native sing-box 1.13+ Hysteria2 and TUIC outbounds set `insecure: false`
  and `certificate_public_key_sha256` to an array containing the base64 SPKI
  hash. These outbounds are omitted when the pin is missing or invalid and
  when the request identifies an older core. Legacy JSON requests must identify
  a compatible `sing-box` or `singbox` core. Use `?format=sing-box` to request
  native JSON explicitly with a compatible client. A prerelease of the minimum
  version does not qualify.
- Mihomo Hysteria2 and TUIC proxies require a leaf `fingerprint` and set
  `skip-cert-verify: false`. Requests must identify a Mihomo or Clash.Meta
  core at version 1.19.20 or later to receive these proxies. A prerelease of
  1.19.20 does not qualify. The pin follows
  server identity, including on same-address hosts and client detours.
- Hysteria2 and TUIC use pinned subscriptions. Generic URI exports omit both
  protocols because URI importers can ignore a pin or lack a compatible pin
  parameter. App-config keeps NaiveProxy routes and omits the URI pairing tag
  when no Hysteria2 URI can be delivered.

## Verification

- Strict parsing accepts OpenSSL label casing and normalizes hex. It rejects
  wrong digest size, algorithm, separators, non-hex and extra output.
- Deployment observation persists once, is a no-op for the same certificate,
  audits rotation once, and preserves the old pin on read/validation failure.
  Observation does not invalidate the deploy revision; real input changes do.
- Byte-level tests cover pinned and omitted routes, older clients, unrelated
  REALITY proxies, same-address servers and client detours. Native Hysteria2
  tests cover both Salamander settings. App-config tests verify the omitted
  QUIC profiles and identical REALITY payload bytes.
