# Spec: Production Network Remediation Status

## 1. Intent & Invariants
- What: record the completed S1–S4 production network security remediation waves.
- Invariants: key-only root access remains available to vpnctld; VPN credentials and grants are unchanged; every accepted wave has rollback state and protocol-aware checks.

## 2. Interface / Data Contract
```text
S1: iptables-nft INPUT DROP; TCP 22/443/9443; UDP 8444; LLMNR/mDNS off; external HY2 verified
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
- [x] S1 provider UDP 8444 return path fixed and verified externally.
- [x] S1 LLMNR/firewall wave reapplied and accepted.
- [x] S1 15-minute watcher complete.
