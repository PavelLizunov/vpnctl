# Spec: Mihomo YAML subscription

## 1. Intent & Invariants
- What: add a ready Mihomo configuration for Omarchy using the existing grants, token validation, suppression, visibility, rate-limit, and access-log path.
- Existing `/sub/{token}`, `?format=sing-box`, and `/api/v1/app/config/*` responses remain byte-for-byte unchanged.
- Initial protocol scope is VLESS+REALITY and Hysteria2; XHTTP and other protocols are omitted.
- A chained target is emitted only with a usable upstream through Mihomo `dialer-proxy`; direct target fallback is forbidden.
- A disabled user receives a valid empty config using `DIRECT`; an unknown token keeps the existing `404`.
- No database migration or grant mutation.

## 2. Interface / Data Contract
```text
GET /sub/{token}                              # unchanged
GET /sub/{token}?format=sing-box              # unchanged
GET /sub/{token}?format=mihomo                # internal/LAN alias
GET /api/v1/sub/{token}?format=mihomo         # canonical public URL
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
- Admin **Delivery** shows the public Mihomo URL and QR.
- Production ingress forwards the strict `/api/v1/sub/<token>` path if its current matcher does not already do so.

## 3. Verification Checklist (Definition of Done)
- [ ] Endpoint returns `200`, exact `text/yaml`, not Base64 and not a JSON wrapper.
- [ ] Response parses with an independent YAML parser and passes `mihomo -t`.
- [ ] Every permitted usable VLESS/Reality and Hysteria2 grant is present.
- [ ] Hidden, denied, suppressed, and unsupported protocols are absent.
- [ ] A chained target carries `dialer-proxy`; missing or nested upstream hides the target.
- [ ] Spec-only tests and independent review leave no unresolved important findings.
- [ ] README, admin Delivery URL/QR, and byte-regression tests are current.
- [ ] Full Cargo/CI/Docker/gitleaks/deny gates pass.
- [ ] After merge: backup, `scripts/deploy.sh`, restart, health/version/public endpoint, and rollback are verified without exposing tokens.
- [ ] Flowpool and VM 226 remain untouched.
