# Spec: Mihomo YAML subscription

## 1. Intent & Invariants
- What: add a ready Mihomo configuration for Omarchy using the existing grants, token validation, suppression, visibility, rate-limit, and access-log path.
- Existing `/sub/{token}` default sing-box/UA behavior, `?format=sing-box`, and `/api/v1/app/config/*` responses remain byte-for-byte unchanged.
- The canonical public URL `GET /api/v1/sub/{token}` defaults to Mihomo YAML without requiring query parameters, while preserving full compatibility with legacy `?format=mihomo` query parameters.
- Protocol scope is strictly bounded to VLESS+REALITY and Hysteria2; unsupported protocols (XHTTP, VLESS-WS, Trojan, Naive, TUIC-v5, SS-2022, WireGuard) are omitted and not claimed.
- Distinct server records are never deduplicated by address: an S5 target and its entry remain separate proxies even when both use the same IP.
- A chained target is emitted only with a usable upstream through Mihomo `dialer-proxy`; direct target fallback is forbidden.
- A disabled user receives a valid empty config using `DIRECT`; an unknown token keeps the existing `404`.
- No database migration or grant mutation.

## 2. Interface / Data Contract
```text
GET /sub/{token}                              # unchanged legacy sing-box/UA behavior
GET /sub/{token}?format=sing-box              # unchanged
GET /sub/{token}?format=mihomo                # internal/LAN alias (compatibility)
GET /api/v1/sub/{token}                       # canonical public URL (defaults to Mihomo YAML without query)
GET /api/v1/sub/{token}?format=mihomo         # canonical public URL (old query URL compatibility)
Content-Type: text/yaml
```

```yaml
proxies:
  - { name: Iceland VLESS, type: vless }
  - { name: S5 VLESS, type: vless, dialer-proxy: Iceland VLESS }
  - { name: Iceland HY2, type: hysteria2 }
proxy-groups:
  - name: VPN
    type: select
    proxies: [Iceland VLESS, S5 VLESS, Iceland HY2]
rules:
  - MATCH,VPN
```
- Admin **Delivery** shows the canonical public Mihomo URL (`https://ninitux.com/api/v1/sub/<token>`) without query parameter and its QR code.
- S5 target and entry identity is based on server ID and proxy tag, never on address uniqueness.
- Production ingress forwards the strict `/api/v1/sub/<token>` path if its current matcher does not already do so.

## 3. Verification Checklist (Definition of Done)
- [ ] Endpoint returns `200`, exact `text/yaml`, not Base64 and not a JSON wrapper.
- [ ] Canonical public URL `https://ninitux.com/api/v1/sub/<token>` returns Mihomo YAML without query parameters.
- [ ] Compatibility verified for legacy query URLs (`?format=mihomo`).
- [ ] Same-address S5 target and entry both remain present, with the target using `dialer-proxy`.
- [ ] Response parses with an independent YAML parser and passes `mihomo -t`.
- [ ] Every permitted usable VLESS/Reality and Hysteria2 grant is present.
- [ ] Hidden, denied, suppressed, and unsupported protocols are absent (no unsupported protocols claimed).
- [ ] A chained target carries `dialer-proxy`; missing or nested upstream hides the target.
- [ ] Spec-only tests and independent review leave no unresolved important findings.
- [ ] README, admin Delivery URL/QR (without query parameter), and byte-regression tests are current.
- [ ] Full Cargo/CI/Docker/gitleaks/deny gates pass.
- [ ] After merge: backup, `scripts/deploy.sh`, restart, health/version/public endpoint, and rollback are verified without exposing tokens.
- [ ] Flowpool and VM 226 remain untouched.
