# Self-signed TLS certificate pinning (D7-03)

## Intent & invariants

Successful sing-box deployment observes the node's certificate over the existing
SSH transport. Existing certificates, credentials and insecure flags stay intact;
already imported profiles continue working. Protocol rendering remains stateless.
No schema migration is needed.

## Interface / data contract

- `Kernel::deployed_server_secrets` defaults to an empty batch. Sing-box reads
  `tuic.cert_path` (default `/etc/sing-box/cert.pem`) with `openssl x509` after
  apply and firewall success. It accepts only an OpenSSL SHA-256 fingerprint
  line containing exactly 32 colon-separated hex octets and normalizes it to
  64 lowercase hex characters under `tls.cert_sha256`.
- Inventory's `refresh_deployed_server_secrets` uses the existing audited
  compare-and-set batch helper. Only changed observations write
  `server.deployed_secrets.set`, containing key names only. Read/validation/write
  failures fail the deploy. Bootstrap, redeploy, admin deploy and CLI deploy all
  call it. This derived certificate observation is excluded from deploy input
  revisions and does not create pending-deploy state.
- Mihomo adds `fingerprint` to Hysteria2 and enables pinned Trojan, AnyTLS and
  TUIC proxies. Without the secret its previous output, including omissions,
  remains byte-identical. The pin follows server identity, never host/address
  matching, including when two servers share an address or use a client detour.
- Hysteria2 share links append `&pinSHA256=<64 lowercase hex>` before the fragment
  when the secret exists, preserving `insecure=1` and obfuscation parameters.
  The [official URI scheme](https://v2.hysteria.network/docs/developers/URI-Scheme/)
  accepts hex without colons.
- `/sub` sing-box JSON and stock sing-box JSON receive no new fields: older
  Hiddify/sing-box parsers reject unknown TLS pin fields. The app-config JSON
  wrapper keeps its fields; its base64 URI payload receives the Hysteria2 pin.
  Other share links retain their existing bytes and insecure flags.

## Verification

- Strict parsing accepts OpenSSL label casing and normalizes hex; rejects wrong
  digest size, algorithm, separators, non-hex and extra output.
- Deployment observation persists once, is a no-op for the same certificate,
  audits rotation once, and preserves the old pin on read/validation failure.
  Observation does not invalidate the deploy revision; real input changes do.
- Byte-level Mihomo tests cover pinned/unpinned output, all four protocols,
  unrelated REALITY proxies and same-address servers. Hysteria2 URI tests pin
  both variants with/without Salamander. Sing-box JSON stays identical; app-config
  tests pin the changed Hysteria2 payload and unchanged REALITY payload.
- Compilation and Rust test execution are delegated to the lead for this task.
