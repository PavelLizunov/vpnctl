# Spec: Chain-Capable S5 Subscription

## 1. Intent & Invariants
- What: make S5 visible in a separate sing-box subscription as **S5 via Iceland**.
- The ordinary `/sub/{token}` remains unchanged and keeps its current URI-list behavior.
- A direct S5 URI is never published because URI formats cannot safely encode `detour`.
- The chain uses a separate `/sub/{token}?format=sing-box` URL.
- Raw JSON lists Iceland and S5 in its selector; every S5 outbound detours through Iceland.
- If Iceland is unavailable to the user, S5 disappears completely.
- `vless+xhttp`, which targets sing-box-lx/VPNRouter, is excluded from stock sing-box JSON.
- Flowpool is out of scope and must not be touched.
- Verdict: **Extend — existing sing-box renderer — separate URL without changing working subscriptions.**

## 2. Interface / Data Contract
```http
GET /sub/{token}
# Existing behavior and bytes remain unchanged.
# Chained S5 is absent because URI output cannot encode detour.

GET /sub/{token}?format=sing-box
200 application/json
```

```json
{
  "outbounds": [
    { "type": "selector", "tag": "proxy", "outbounds": ["Iceland VLESS", "S5 VLESS"] },
    { "tag": "Iceland VLESS" },
    { "tag": "S5 VLESS", "detour": "Iceland VLESS" }
  ]
}
```

- Web UI exposes a separate **“Sing-box: S5 via Iceland”** URL/QR.
- This URL is a standalone subscription to import when the user needs S5.
- All other users continue using the ordinary URL.

## 3. Verification Checklist (Definition of Done)
- [ ] Ordinary subscriptions remain byte-for-byte unchanged.
- [ ] S5 appears in the raw sing-box selector.
- [ ] Selecting S5 exits through S5’s public IP.
- [ ] Missing/hidden/denied Iceland removes S5 fail-closed.
- [ ] Stock sing-box 1.13.19 accepts the JSON with `sing-box check`.
- [ ] XHTTP is absent only from stock sing-box JSON and remains available to VPNRouter/sing-box-lx.
- [ ] The explicit URL is imported in Hiddify or another actual target application.
- [ ] Web provides one ready URL/QR with no manual editing.
- [ ] Independent tests, review, and GitHub Actions pass.
- [ ] Production canary passes and is cleaned up; permanent S5 activation remains a separate decision.
