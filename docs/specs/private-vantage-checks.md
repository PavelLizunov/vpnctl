# Private network vantage checks

## Intent and invariants

Provide an operator-visible, private check of each configured VPN server from controlled network vantage points. Never send server addresses or credentials to Cheburcheck or other third-party checking services. A TCP connection confirms only transport reachability, never a VPN handshake or unblocked status; UDP and end-to-end transfer require protocol-aware checks and must remain explicitly unverified if unavailable. Do not change VPN configurations, subscribers, routes or existing assurance/alert semantics. Reuse trusted SSH/host-key configuration and existing inventory; no arbitrary targets or command injection.

## Interface and data contract

Show source, server, transport/port, last check time, latency and precise result in the web UI, including unavailable and stale states. Use only configured servers and effective protocol ports. Failed or offline vantage checks must not be treated as server blocks. Results from different sources must not overwrite existing protocol assurance rows. Provide an operator-triggered check; background operation if practical without affecting availability. The first mandatory vantage is the controller's direct network; other controlled machines can be added only where their access and network path are established.

## Verification

- Unit/integration tests cover success, timeout/refusal, unavailable vantage and stale/no result, protocol transport semantics, target validation and UI escaping/authentication.
- Check actual user-facing result on production after deployment; independently validate at least one direct network comparison.
- Existing VPN operation, credentials and configuration remain unchanged; no public Cheburcheck requests.
- Document retained limitations, exact source of each observation, and upstream code/license if incorporated.

## Decision and progress

Verdict: Extend — existing VPNctl monitoring and protocol registry. Cheburcheck's public MQTT probes disclose targets to its operator and its generic TLS test is not a VPN handshake; no upstream code was copied. A manual, bounded controller-only TCP sweep stores ephemeral results separately from existing assurance. Additional vantages and real VPN/UDP data-path tests remain future work; Mac mini's utun route does not represent an independent physical network. Review identified stale results after failed sweeps; clear results at start and on failure. Formatting and project-map checks pass; executable tests and deployment pending. Linux worker 101 is queued behind a different owner's active VM107 lease; request vpnctl-private-checks-20261101 was cancelled without disturbing that owner. Harness-test's Cargo guard blocks compilation on the control-plane. Independent review's important stale-result issue was addressed by clearing results before and after unsuccessful sweeps; its other race concern is mitigated by clearing on outer timeout and acquire/release flag ordering. No production changes made.

## Open questions

- Which existing scheduler, web action and remote-probe patterns can be reused without changing alert semantics?
- Which other controlled machines are accessible noninteractively and independent of the controller's network? Mac mini currently routes server traffic through utun99, and Omarchy SSH is unavailable.
