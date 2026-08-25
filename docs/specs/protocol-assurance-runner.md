# Spec: Production Protocol Assurance Runner

## 1. Intent & Invariants
- What: run real protocol client handshakes/data transfer for the protocol assurance poller using official sing-box/Xray engines.
- Invariants: runner receives no production credentials from vpnctld; probe templates are owned by daemon user at 0700/0600; executable/engines are trusted; output is one sanitized JSON result; temporary configs/processes are always removed.

## 2. Interface / Data Contract
```text
stdin:  {"server":"...","protocol":"...","ports":[["udp",8444]]}
template: {"engine":"sing-box|xray","config":{..."__PORT__"...}}
stdout: {"stage":"transfer","state":"verified|blocked","latency_ms":123,
         "failure_code":null|"handshake_timeout","client_kind":"sing-box|xray"}
```

## 3. Verification Checklist
- [x] Missing/unsafe config fails closed.
- [x] Config directory owner/mode and engine owner/mode/type checked.
- [x] Ambient environment/proxies/curlrc cannot influence probes.
- [x] Engine process group killed/reaped and temporary config removed.
- [x] Sing-box and Xray launch contracts tested.
- [x] 204 success, non-204 transfer failure and curl failure tested.
- [ ] Static engine SHA-256 pinned during production installation.
- [ ] Probe identity/templates provisioned and all active protocols verified.
