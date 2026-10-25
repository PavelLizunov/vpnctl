# Spec: Production Protocol Assurance Runner

## 1. Intent & Invariants
- What: run real protocol client handshakes/data transfer for the protocol assurance poller using official sing-box/Xray engines.
- Invariants: runner receives no production credentials from vpnctld; probe templates are owned by daemon user at 0700/0600; executable/engines are trusted; output is one sanitized JSON result; temporary configs/processes are removed on normal completion and daemon-enforced timeout.
- The daemon starts the external runner in its own process group and kills the
  group on timeout, wait failure, or main-process exit. Process and pipe-thread
  waits share one deadline, including when a descendant keeps stdout open.
- Engines inherit the runner's process group. Normal Python cleanup terminates
  and reaps the engine directly; engines must not daemonize or create a new
  session. The daemon owns a private per-attempt directory, passes it as
  `TMPDIR`, and removes it after group termination even if the Python runner
  was stopped or killed before its cleanup could execute. Standalone runner
  callers must provide the same group termination and directory ownership
  when imposing an external timeout. Daemon host/process failure is outside
  this per-attempt cleanup guarantee.

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
- [ ] Real Python runner's engine dies on outer group kill even when the
      runner is stopped after engine launch.
- [ ] Daemon-owned temporary credentials removed after a stopped runner times out.
- [ ] Daemon runner exit/timeout kills background stdout holders; pipe-thread
  joins stop at the runner deadline even without EOF.
- [x] Sing-box and Xray launch contracts tested.
- [x] 204 success, non-204 transfer failure and curl failure tested.
- [ ] Static engine SHA-256 pinned during production installation.
- [ ] Probe identity/templates provisioned and all active protocols verified.
