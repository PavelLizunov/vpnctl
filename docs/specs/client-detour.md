# Spec: Client 2-hop VPN chains

## 1. Intent & Invariants
- What: add an SSH-independent `client_detour_via` policy so a target VPN outbound dials through an entry server outbound.
- `jump_via` remains exclusively an SSH ProxyJump setting.
- Both servers must be `vpn-exit` and granted to the user; production roles and grants are never changed automatically.
- Maximum one client hop; self-reference, cycles, and nested chains are rejected.
- Subscriptions with no client detour remain byte-for-byte unchanged.
- If the entry server or its usable outbound is unavailable, hidden, suppressed, or not granted, the target is omitted with no direct fallback.
- URI-only formats that cannot represent chaining omit chained targets instead of leaking a direct route.
- Flowpool and VM 226 are outside this feature.

## 2. Interface / Data Contract
```rust
// Inventory-only policy; Server and RenderCtx remain unchanged.
pub async fn client_detour_via(
    &self,
    server: &ServerId,
) -> Result<Option<ServerId>>;

pub async fn set_client_detour_via_as(
    &self,
    actor: &str,
    server: &ServerId,
    upstream: Option<&ServerId>,
) -> Result<()>;
```

```json
{"type":"vless","tag":"S5 VLESS ~user","detour":"Iceland VLESS ~user"}
```

- The entry is deterministic: the first usable sing-box outbound in the upstream server's `enabled_protocols` order.
- A real mutation writes `server.client_detour.set`; a no-op writes no audit row.
- Web exposes “Client entry / Входной сервер” on server detail.
- CLI exposes `vpnctl server set-client-detour-via <target> <upstream>` and `--clear`.

## 3. Verification Checklist (Definition of Done)
- [ ] Migration preserves/restores the relationship and rejects self/cycle/nested chains.
- [ ] `/sub` contains both outbounds and the target has the exact entry outbound tag in `detour`.
- [ ] The chained target is absent when the entry is unusable and never falls back direct.
- [ ] V2Ray and `/api/v1/app/config` do not publish a chained target directly.
- [ ] Existing `/sub` and app-config fixtures remain byte-identical without a chain.
- [ ] Web and CLI set/clear the policy with correct audit behavior.
- [ ] Independent review, `just ci`, push, and GitHub Actions CI pass.
