# Spec: AWG2 and AWG3 on is-new

## 1. Intent & Invariants
- Add AmneziaWG 2.0 and 3.1 using the existing sing-box-vpnctl kernel; both versions are independently managed in the admin UI.
- Preserve working VLESS, Hysteria2, XHTTP and existing client output byte-for-byte. Do not modify old is or grant production users access automatically.
- Retain strict SSH host verification, audit every inventory mutation, and reject unsupported client formats rather than silently downgrade versions.

## 2. Interface / Data Contract
- Protocol IDs: `amneziawg2` and `amneziawg3`, with separate UDP ports and tunnel subnets and conflict checks.
- Server-generated keys and version-specific parameters live in inventory and remain stable across redeploys.
- Each authorized user receives one ready-to-import client configuration file from the admin UI, identifying the version and compatible client.
- Reuse current kernel and vpnctl facilities; do not install a third-party panel. All protocol lifecycle actions have web controls.

## 3. Verification Checklist (Definition of Done)
- [ ] Both versions can be enabled and deployed from the admin UI.
- [ ] Key generation, parameter persistence and user authorization are tested.
- [ ] Isolated AWG2 and AWG3 clients complete real handshakes and data transfers, not merely port checks.
- [ ] Byte-level regression tests preserve existing subscriptions.
- [ ] Independent review, security review and required local/CI gates pass.
- [ ] Production backup/rollback precede deployment; all five protocols and SSH key access are checked afterward.
- [ ] Request separate authorization before creating any production test access.
