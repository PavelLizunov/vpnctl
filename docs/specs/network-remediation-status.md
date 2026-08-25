# Spec: Production Network Remediation Status

## 1. Intent & Invariants
- What: record the applied S2–S4 security waves and the S1 provider blocker.
- Invariants: key-only root access remains available to vpnctld; VPN credentials and grants are unchanged; every accepted wave has rollback state and protocol-aware checks.

## 2. Interface / Data Contract
```text
S1: baseline restored; INPUT ACCEPT; LLMNR present; UDP8444 provider blocker
S2: iptables-nft INPUT DROP; TCP 22/443/9443; UDP 8444; LLMNR/mDNS off; key-only SSH; fail2ban active
S3: nft INPUT DROP; TCP 22/443/9443; UDP 8444; key-only SSH; fail2ban active
S4: iptables-nft INPUT/FORWARD DROP; TCP 22/80/443/8443/9443; UDP 8443/8444/51822; BIND tunnel-only; WgTurn/wg0 removed
```

## 3. Verification Checklist
- [x] Provider-console recovery confirmed for S1–S4.
- [x] Exact pre-change firewall/config backups and rollback scripts created.
- [x] S2 deploy key, HY2, Reality, persistence and 15-minute stability passed.
- [x] S3 deploy key, HY2, Reality, persistence and 15-minute stability passed.
- [x] S4 deploy key and all proxy protocol gates passed; legacy ports absent.
- [x] S4 15-minute watcher complete.
- [ ] S1 provider UDP 8444 return path fixed and verified externally.
- [ ] S1 LLMNR/firewall wave reapplied and accepted.
