# Spec: VPNRouter app-config client detour

## 1. Intent & Invariants
- What: expose a VLESS chained target through `/api/v1/app/config/{device_id}` only to a VPNRouter client that explicitly advertises detour support.
- Existing VPNRouter, browser, and standard VPN-client responses remain unchanged.
- A chained target is omitted unless its granted, visible, usable upstream entry is present in the same payload.
- No direct S5 URI is ever published; missing upstream fails closed.
- Initial scope is VLESS+REALITY; chained XHTTP remains omitted.

## 2. Interface / Data Contract
```text
GET /api/v1/app/config/{device_id}
User-Agent: VPNRouter
X-VPNRouter-Capabilities: detour-v1

vless://...?...&outbound=is#Iceland...
vless://...?...&outbound=play2go-gflow&detour=is#S5...
```
- `outbound` is an opaque server ID used only to resolve another URI in the same payload.
- `detour` references the upstream URI's `outbound` value.
- Metadata is appended only to members of a valid chain and only for the capability-aware VPNRouter response.
- Without the capability header, the chained target remains omitted exactly as before.

## 3. Verification Checklist (Definition of Done)
- [ ] Old VPNRouter and generic UAs continue to omit chained targets.
- [ ] Capability-aware VPNRouter receives both entry and target metadata.
- [ ] No-chain output is byte-for-byte unchanged even with the capability header.
- [ ] Ungranted, hidden, denied, suppressed, unusable, self/nested, or missing entry omits the target.
- [ ] Existing rate limits and anti-fingerprinting response shapes remain unchanged.
- [ ] Independent spec tests and full Rust gates pass.
- [ ] Coordinated VPNRouter client tests prove exact sing-box `detour` generation.
