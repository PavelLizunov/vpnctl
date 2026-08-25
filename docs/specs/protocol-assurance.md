# Spec: Protocol Assurance and Alert Coverage

## 1. Intent & Invariants
- What: track each active server×protocol from render through external client handshake/data transfer, and alert on the exact failing layer.
- Invariants: config generation remains deterministic and offline-capable; local listener never implies external reachability; the external runner owns a separate probe identity and never receives production credentials/client configs from vpnctld; existing artifacts are not auto-revoked on probe failure.

## 2. Interface / Data Contract
```rust
pub enum AssuranceStage { Render, ServerConfig, Listener, ExternalPath, ClientImport, Handshake, Transfer }
pub enum AssuranceState { Verified, Degraded, Blocked, Unknown }
pub struct ProtocolAssuranceSample {
    pub server_id: ServerId,
    pub protocol_id: ProtocolId,
    pub client_kind: String,
    pub stage: AssuranceStage,
    pub state: AssuranceState,
    pub latency_ms: Option<u64>,
    pub failure_code: Option<String>,
    pub checked_at: DateTime<Utc>,
}
// Alert kinds: protocol.assurance.failed / protocol.assurance.recovered
```

## 3. Verification Checklist
- [ ] Existing health/quality/alert mechanisms mapped and reused.
- [ ] HY2/TUIC use protocol-aware UDP handshakes; TCP connect is not enough.
- [ ] Reality/XHTTP/WS perform handshake plus HTTPS transfer.
- [ ] XHTTP uses Xray/sing-box-lx client compatibility.
- [ ] Provider-closed-port and missing-listener failures classify differently.
- [ ] Failure dedupes to one open alert; recovery closes/edits it.
- [ ] Admin UI shows latest state, failure layer and age.
- [ ] Subscription rendering remains available but marks unverified/degraded protocols.
- [ ] No credentials/config bodies stored in samples, alerts or logs.
- [ ] Runner request contains only server/protocol/ports; production credentials are never exported.
- [ ] Temporary probe processes/configs are removed.
- [ ] Full CI and independent review pass.
