# AWG2 / AWG3 rollout acceptance — 2026-09-06

## Delivered source and production

- Kernel PR: https://github.com/PavelLizunov/sing-box-vpnctl/pull/1
- Released kernel: https://github.com/PavelLizunov/sing-box-vpnctl/releases/tag/v1.14.0-vpnctl.4
- Kernel source/tag: `91068e67ea244f4cdfea991f33cf3dfa2a259511`.
- Actual published and deployed Linux amd64 binary SHA256: `ae9467274b34251997f73df871b2bdc0ab6f3c9097fdfb962348e2716227d926`.
- vpnctl integration PR208 and corrective PR209 merged. Final main: `0368185b364d203d05964267d00f4470d435d0c3`.
- Production daemon and CLI: `0.9.0+b47f36f`, source `b47f36fd23b6f60c963adf1c55726a1db21f2832`; tree identical to final main. Static musl artifacts built from exact committed worker checkout.
- Deployed through the repository's atomic `scripts/deploy.sh`; only vpnctld restarted on the control plane. Node changes restricted to is-new.

## Verification evidence

- Independent specification-derived tests and diff reviews completed. All critical/important findings resolved. Kernel wire, secret-redaction, integration, runtime-control, release-pin and auto-deploy correction reviews were separate scoped reviews.
- Kernel PR/main CI and release workflow `34037178952`: success.
- Final vpnctl PR CI `34040833002`, main CI `34041047282`: success, watched to terminal exit 0. Includes fmt, check, Clippy, tests, cargo-deny, gitleaks, managed artifacts and Docker SSH tests.
- Local full `just ci` passed on final implementation; final exact router regression passed. Stale-snapshot regressions failed three cases on baseline and passed all four after correction, including retry secret-map stability.
- Published kernel artifact: official AmneziaWG reference interoperability 16/16 cases passed, both client/server roles, correct HP positive and wrong-HP controlled negative.
- Actual vpnctl-rendered native AWG2/AWG3 files imported by official tools. TCP/UDP over IPv4 and IPv6 passed. Four guarded/missing-guard mutation cases passed: same management targets reachable without guards, rejected with guards.
- On is-new, four sequential automatic operations passed: AWG2 disable/enable, then AWG3 disable/enable. Each operation produced a successful targeted automatic-deploy audit and unchanged complete server-secret map.
- Final sing-box/Xray/fail2ban active; sing-box and Xray NRestarts=0. Pinned deploy-key SSH works and sshd syntax valid.
- Final listeners: VLESS TCP443, Hysteria2 UDP8444, XHTTP TCP9443, AWG2 UDP51821, AWG3 UDP51822. Stats TCP9090/10085 and MySQL TCP3306 remain loopback-only.
- Before/after private comparisons: legacy sing-box inbound objects identical, complete Xray configuration bytes identical, all grants unchanged, all prior server secrets preserved. Old-is server/protocol inventory unchanged. Final two AWG endpoints have empty peer lists.

## Recovery and operational correction

- Pre-rollout inventory backup: `/var/lib/vpnctl/backups/inv.db.2026-09-06T14-19-20.398Z.bak`; restored disposable copy passed SQLite integrity and foreign-key checks.
- Post-AWG/pre-correction backup: `/var/lib/vpnctl/backups/inv.db.2026-09-06T14-59-34.017Z.bak`; same restore checks passed.
- Prior daemon/CLI/artifacts retained in `/var/lib/vpnctl/backups/awg-predeploy-20260906T1420` and `/var/lib/vpnctl/backups/awg-correction-predeploy-20260906T1502`. Protected control assets archive includes deploy key, environment and systemd unit; key membership verified without disclosure.
- Node rollback archive: `/root/is-new-awg-predeploy-20260906T1426.tar.gz`. Earlier 1425 archive is incomplete and must not be used. Includes sing-box/Xray configs and binaries plus SSH config.
- Protected off-site inventory/control-assets copy retained on is-new under `/root/vpnctl-awg-recovery/`.
- A stale pre-toggle snapshot defect was fixed centrally before secret bootstrap, with membership-change fencing before SSH. Candidate incident INC-1345 records it.
- Live re-enable initially encountered an unrelated broken Sury PHP APT repository. Only `/etc/apt/sources.list.d/php.list` was moved to `php.list.disabled-vpnctl`, with backup `/root/php.list.pre-awg-20260906`; no PHP/MySQL packages removed. This VPN-only node then passed all four automatic lifecycle checks.

## Explicit limits

No production user grants were created. Consequently no authorized production client transfer or production client file was manufactured: live verification establishes deployment, independent lifecycle controls, preserved configuration/identities and service/SSH health. Actual authorized exports and traffic were verified with synthetic users and isolated peers using the same published kernel binary.

Runtime management-destination negative tests cover IPv4, not IPv6; positive transfers cover both families. Native config default routes were imported and checked, but the test installs exact policy routes rather than exercising awg-quick system-wide default-route installation. is-new has one public IPv4 and no global IPv6 address. Concurrent operator changes can still leave an honest pending state requiring the web retry button after bounded retries; no universal race-free or DoS-protection claim is made.
