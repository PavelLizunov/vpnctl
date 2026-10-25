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

### Alert hygiene
- A failed external handshake is retried up to 3 times in one tick (2 s apart), the way a real client reconnects. With `fp=randomized` a single xray REALITY handshake fails about 10% of the time; a real outage fails every attempt. Only a failed tick counts towards the 3-tick alert threshold.
- `probe_config_missing` from the runner means "no probe template for this server/protocol". It is not a protocol failure. The poller falls back to the built-in TCP path check and records the result as `Unknown` with `probe_template_missing`. That code neither opens nor recovers an alert, so losing templates never fakes a recovery. An alert opened earlier by a real failure stays open until a verified recovery or the operator acks it.
- Only `Verified` recovers an open assurance failure. All `Unknown` results, including `tcp_path_only`, `udp_path_unverified`, and `no_probe_identity`, preserve the open alert because they cannot disprove a definitive handshake failure.
- An open `protocol.assurance.failed.*` alert whose server×protocol is no longer probed (protocol disabled, server leaves the fleet) is auto-acked at the end of the tick and audited as `alert.auto_ack`.
- `server.singbox.restarted` is a one-shot event. It is written as already-acked history, deduplicated by the source sample pair even across daemon restarts, so it never stays open and never swallows the next crash. Telegram pushes for it are throttled to one per server per 30 min, counted from the last push.

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
