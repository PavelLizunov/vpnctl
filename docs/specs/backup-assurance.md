# Spec: надёжное резервирование и покрытие VPN-проверками

## 1. Intent & Invariants
- Approved by operator on 2026-09-10: reliable scheduled backup and truthful delivery status; verify real VPN probes without using customer credentials.
- Preserve archives, pinned SSH trust and customer identities. No bulk Deploy, daemon restart, guard bypass or unapproved destination transfer.
- Installed backup may differ from repository: inspect and preserve intentional differences before replacement.
- Confirm any new off-site destination and host key separately before transfer. Stop before node Deploy and obtain node/window approval for test access.

## 2. Interface / Data Contract
- Reuse scripts/vpnctl-backup.sh and existing systemd/Web backup surfaces; no new backup platform or dependencies.
- Measure faster compression on copied data; apply minimum safe change within existing job timeout.
- Required deploy key must be present in a usable recovery archive. Archive creation and each delivery/retention stage must be distinguishable; partial delivery must not be advertised as complete success.
- Encrypted archives stay protected; no secrets, raw profiles or DB in Git/logs/chat. Trusted destinations verified via hashes; missing trust blocks access, not bypasses it.
- Separate probe identities/templates and compatible engines for protocol checks. No new production grants without agreed deployment window.
- Rollback restores previous script/config, never deletes fresh archives.

## 3. Verification Checklist
- [ ] Script regressions cover archive survival, mandatory key, compression, delivery failures and accurate job result.
- [ ] Compression measured with real copied input and adequate time margin.
- [ ] Independent review and canonical local/GitHub CI pass for exact revision.
- [ ] Controlled backup-only installation confirmed without VPN/controller restart.
- [ ] Local/LAN/off-site hashes match for separately trusted and approved destinations; unverified destinations explicitly blocked.
- [ ] Decryption, required key presence and isolated DB restoration verified; unavailable decryption identity reported explicitly.
- [ ] Each configured VPN probe has verified VPN route, handshake and HTTPS response; unsupported/missing templates reported, no invented full coverage.
- [ ] Second independent network and per-node/window approval recorded as separate requirements where needed.
