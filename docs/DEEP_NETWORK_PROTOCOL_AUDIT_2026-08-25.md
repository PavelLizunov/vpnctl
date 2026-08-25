# Deep network, protocol and kernel audit — 2026-08-25

## Scope and evidence model

Production VM 119 and all four inventory servers were audited. Server identities are represented only as S1–S4 in stable inventory order.

The audit separated four layers:

1. port declared by inventory/protocol registry;
2. local listener and owning process;
3. host firewall policy;
4. reachability and protocol handshake from independent networks.

A pre-audit SQLite snapshot passed integrity and foreign-key checks. No production VPN service, firewall or inventory row was changed. Existing user credentials were used transiently for handshakes; no user/grant was created. Temporary configs, processes, helpers, sockets, network namespaces and worker networking changes were removed and rechecked.

## Executive result

| Area | Result |
|---|---|
| Declared TCP reachability | PASS |
| Protocol handshakes | PASS, WireGuard live-now NOT TESTED |
| Kernel configs and managed units | PASS |
| Required-port inventory | PASS |
| Host firewall posture | FAIL |
| SSH hardening | FAIL on S2/S3 |
| Unexpected public name services | FAIL |
| Legacy service residue | FAIL on S4 |
| IPv6 coverage | NOT TESTED — nodes are IPv4-addressed only |

## Required public port pool

These are the minimum service ports justified by current inventory and verified protocol behavior.

| Node | Transport | Ports | Purpose |
|---|---|---|---|
| S1 | TCP | 22, 443, 9443 | SSH, VLESS Reality, VLESS XHTTP |
| S1 | UDP | 8444 | Hysteria2 |
| S2 | TCP | 22, 443, 9443 | SSH, VLESS Reality, VLESS XHTTP |
| S2 | UDP | 8444 | Hysteria2 |
| S3 | TCP | 22, 443, 9443 | SSH, VLESS Reality, VLESS XHTTP |
| S3 | UDP | 8444 | Hysteria2 |
| S4 | TCP | 22, 80, 443, 8443, 9443 | SSH, Caddy HTTP/ACME, VLESS Reality, VLESS-WS, XHTTP |
| S4 | UDP | 8443, 8444, 51822 | TUIC v5, Hysteria2, inventory AmneziaWG |

Local-only listeners that must not be publicly exposed include sing-box controller 9090, Caddy admin 2019, the S4 VLESS-WS backend 11443, BIND control 953, DNS stubs and container runtime sockets.

## External reachability

All declared TCP ports were reachable from macOS and from three separate cross-provider production nodes. No declared TCP port showed evidence of provider ingress blocking.

The Linux worker blocked egress to every audited node, including SSH. Its negative results were excluded because they represent worker egress policy, not server/provider ingress filtering.

All inventory addresses resolved or were configured as IPv4 only. IPv6 external reachability therefore remains not tested rather than failed.

## Real protocol handshakes

Each test used an isolated temporary client config, a local proxy or native client, HTTPS status 204 as data-transfer proof, and cleanup via trap.

| Protocol | Coverage | Result |
|---|---:|---|
| Hysteria2 | S1–S4 | PASS 4/4 |
| VLESS Reality | S1–S4 | PASS 4/4 |
| VLESS XHTTP | S1–S4 | PASS 4/4 with Xray client |
| TUIC v5 | S4 | PASS |
| VLESS-WS | S4 | PASS |
| AmneziaWG | S4 | NOT TESTED live-now |

The first S3 Hysteria2 attempt timed out once; repeat handshakes from three different providers passed with successful data transfer. It is classified as a transient sample, not a persistent blocked port.

Upstream sing-box rejected XHTTP locally because production artifacts intentionally target sing-box-lx/Xray XHTTP semantics. Native Xray 26.3.27 completed XHTTP handshakes on all four nodes, proving that TCP 9443 and server configurations work.

AmneziaWG is active on S4's configured UDP port. Existing peers showed historical handshakes and non-zero traffic. A new synthetic client handshake was not automated because the available macOS client requires GUI/Keychain authorization and the Linux worker lacks the `awg` userspace client. No worker package or kernel changes were made.

## Kernel and service correctness

- sing-box validators passed on S1–S4.
- Xray validators passed on S1–S4.
- Caddy validator passed on S4.
- Managed sing-box, Xray and Caddy units were active/enabled with restart count zero.
- Clocks reported synchronized.
- Observed interface MTUs were 1500; S4 additionally used 1420 for tunnel interfaces.
- VLESS-WS DNS resolution and TLS certificate validation succeeded from control and macOS vantage points; the certificate was valid through November 2026 at audit time.

Active PMTU probing was inconclusive because the control environment did not provide usable ICMP DF responses. This is recorded as an evidence gap, not an MTU failure.

## Remediation status — 2026-08-25

| Finding | Status | Evidence |
|---|---|---|
| NET-001 default-accept firewall | FIXED S1–S4 | S1/S2/S4 use persistent iptables-nft INPUT DROP; S3 uses persistent nftables INPUT DROP. Required protocol and management ports remain reachable. |
| NET-002 public LLMNR | FIXED S1/S2 | resolved has LLMNR disabled and TCP/UDP 5355 listeners are absent. |
| NET-003 public mDNS | FIXED S2 | Avahi service and socket disabled; firewall does not allow UDP 5353. |
| SEC-001 S2 SSH/fail2ban | FIXED | Key-only root SSH, password authentication disabled, python3-systemd installed, fail2ban active/enabled/systemd-owned. |
| SEC-002 S3 SSH | FIXED | Key-only root SSH, password authentication disabled, fail2ban active alongside vpnctl nftables policy. |
| NET-004 S4 recursive DNS | FIXED externally | Public TCP/UDP 53 removed from allowlist; BIND remains active for loopback and awg0 tunnel clients. |
| LEGACY-001 S4 WgTurn | FIXED | Frontend/backend units and configs removed; UDP 56000 and legacy interface absent. |
| LEGACY-002 S4 WireGuard 51820 | FIXED | Legacy wg0 removed; inventory AmneziaWG awg0/UDP 51822 preserved. |

S1–S3 passed 15-minute stability checks with deploy-key reachability, zero sing-box/Xray restarts and successful Hysteria2/Reality handshakes. S4 passed all HY2, TUIC, Reality, VLESS-WS and XHTTP gates plus its 15-minute deploy-key stability check. S1 external Hysteria2 was verified from VM119, S2 and S3 after the provider security group added inbound UDP 8444.

### S1 provider UDP 8444 return path — FIXED

The provider security group lacked inbound UDP 8444 (nearby rules covered other ports). After adding IPv4 UDP 8444 from `0.0.0.0/0`, Hysteria2 passed from VM119, S2 and S3. S1 was then hardened to persistent INPUT DROP with TCP 22/443/9443, UDP 8444, essential ICMP/ICMPv6, loopback and established/related traffic; LLMNR/mDNS were disabled.

## Confirmed findings

### NET-001 — default-accept host firewalls

S1–S4 did not present a restrictive default-drop INPUT posture during canonical checks. Some nodes had fail2ban chains, but these protect SSH sources and are not a service allowlist.

Risk: any process binding a wildcard address becomes externally reachable unless the provider separately filters it. This was demonstrated by the audit-created S1 HTTP residue and by public name-service listeners.

Recommended remediation: default-drop IPv4/IPv6 INPUT policies with explicit allows for loopback, established/related traffic, the required port pool, and a reviewed essential ICMP/ICMPv6 ruleset (including PMTU and IPv6 neighbor discovery). Apply one node at a time only after deploy-key verification and provider-console rollback preparation.

### NET-002 — public LLMNR on S1 and S2

`systemd-resolved` listens on wildcard TCP/UDP 5355. TCP 5355 was externally reachable and returned LLMNR responses from the macOS vantage. UDP 5355 is wildcard-bound behind a default-accept host firewall, but provider-level UDP ingress was not directly proven.

Recommended remediation: set `LLMNR=no`, restart resolved in a controlled wave, and block TCP/UDP 5355 at the host firewall.

### NET-003 — public mDNS on S2

Avahi is active and wildcard-bound on UDP 5353 behind a default-accept host firewall. Provider-level external UDP response was not directly proven.

Recommended remediation: disable Avahi if unused, or bind it only to a private interface and block public UDP 5353.

### SEC-001 — S2 SSH and fail2ban posture

S2 permits `PasswordAuthentication yes` and `PermitRootLogin yes`. The baseline systemd fail2ban unit was failed. Its configuration test passed, so the persistent failure requires a dedicated repair/start/log verification wave.

Recommended remediation: first prove deploy-key and console access, then set `PasswordAuthentication no` and `PermitRootLogin prohibit-password` so vpnctld retains key-only root access; repair fail2ban under systemd and verify its jail/firewall integration.

### SEC-002 — S3 SSH hardening

S3 permits password authentication and root login. Fail2ban is active, but default-accept firewall and password/root login still broaden the attack surface.

Recommended remediation: disable password auth and set root login to key-only after console/deploy-key rollback preparation.

### NET-004 — S4 public recursive DNS

BIND is active and listens on public TCP/UDP 53. A standard UDP recursive query from the macOS vantage returned an answer with recursion available. Separate TCP connection probes confirmed TCP 53 externally reachable. Port 53 is not declared by vpnctl protocols.

Recommended remediation: determine whether S4 is intentionally authoritative. If not required, stop public DNS and close port 53. If authoritative DNS is required, restrict recursion/cache access to private ranges and expose only authoritative service.

### LEGACY-001 — S4 WgTurn residue

`wgturn-cli.service` remains active on UDP 56000 despite WgTurn removal from the vpnctl code and inventory. It reported no active sessions during the audit.

Recommended remediation: identify and stop/disable/remove the observed frontend unit plus any `wg-quick@wgturn-be` backend. Then verify UDP 56000, legacy interfaces, routes, firewall rules and configuration residue are absent, using a provider-console rollback plan.

### LEGACY-002 — S4 untracked WireGuard listener

The inventory AmneziaWG service uses UDP 51822. A second kernel WireGuard listener remains on UDP 51820 but is not part of the current vpnctl protocol declaration.

Recommended remediation: identify the owner/config of the standard WireGuard interface. Remove it and close UDP 51820 if legacy; otherwise document it as an explicit non-vpnctl dependency.

## Extra and internal listeners

| Node | Port | Classification |
|---|---|---|
| S1 | TCP 5355 | EXTRA_EXPOSED — externally verified LLMNR |
| S1 | UDP 5355 | POTENTIAL_EXTRA — wildcard listener, external UDP not proven |
| S2 | TCP 5355 | EXTRA_EXPOSED — externally verified LLMNR |
| S2 | UDP 5355 | POTENTIAL_EXTRA — wildcard listener, external UDP not proven |
| S2 | UDP 5353 | POTENTIAL_EXTRA — wildcard mDNS, external UDP not proven |
| S4 | TCP/UDP 53 | EXTRA_EXPOSED — recursive DNS unless explicitly required |
| S4 | UDP 51820 | UNKNOWN/LEGACY — standard WireGuard |
| S4 | UDP 56000 | LEGACY — WgTurn residue |
| S1–S4 | TCP 9090 | LOCAL_ONLY — sing-box API |
| S4 | TCP 953, 2019, 11443 | LOCAL_ONLY |

High-numbered UDP sockets owned by proxy daemons were treated as ephemeral outbound sockets, not required ingress ports.

## Audit safety incidents and cleanup

The audit itself exposed several process-discipline issues, all cleaned and recorded in the incident ledger:

- temporary strict-host-key bypass in two diagnostic commands;
- public peer identifiers printed by an over-broad WireGuard command;
- a swarm worker left a public Python HTTP listener on S1;
- a failed namespace test temporarily enabled Linux-worker IP forwarding;
- a diagnostic fail2ban command started a standalone daemon outside systemd;
- an AmneziaVPN help probe started daemon initialization on macOS.

Final cleanup verification found:

- no S1 HTTP listener/process/log;
- no standalone S2 fail2ban daemon/socket;
- no worker network namespace, veth, NAT rule or forwarding change;
- no Amnezia daemon/socket/PF anchor on macOS;
- no temporary subscription, VPN config, client binary or audit helper residue;
- no production VPN service restart.

## Recommended remediation order

1. Remove S4 WgTurn and investigate UDP 51820 legacy WireGuard.
2. Close public recursive DNS or restrict it to authoritative/private use.
3. Disable LLMNR/mDNS exposure.
4. Establish default-drop host firewalls from the required port pool.
5. Harden S2/S3 SSH and repair S2 fail2ban.
6. Perform a human-authorized AmneziaVPN live handshake for UDP 51822.
7. Add periodic external protocol-aware probes so provider filtering/drift becomes observable.

No remediation above was applied by this audit.
