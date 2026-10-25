# Contract: SSH and deploy lifecycle defect fixes

## Intent & Invariants

- Password SSH respects an inventory host-key pin, including reference-key
  fallback. Unpinned first contact retains trust on first use.
- Password SSH uses the same child-process deadline and process-group kill as
  key authentication (`VPNCTLD_SSH_TIMEOUT_SECS`, default 300 seconds).
- Cancelling the synchronous deploy HTTP handler must not release its operation
  lock while its background deploy is still running.
- Deploy reconciles kernels the operator disabled on the server (any
  `server.kernel.disable` audit row for it) and that are not enabled again,
  through kernel-owned systemd unit metadata; it stops and disables their
  installed services, including auxiliary units. Units of kernels vpnctl never
  managed on that server are never touched. No inventory schema or client wire
  format changes are introduced.
- Hostname wizard targets omit AWG2/AWG3 with a visible progress note. IPv4 and
  IPv6 literals retain the complete default protocol list unless an SSH port
  conflicts as described below.
- The wizard pins the host key recorded by its first successful password login
  before any further connection, including the non-root sudo probe. A later
  keyscan only supplies a key matching that pin; it never establishes trust.
  Missing local known_hosts entries stop the wizard before another password is
  sent. With several accepted keys, pin the currently presented key only if its
  canonical fingerprint is already in that accepted set; a missing match or
  keyscan failure stops the wizard. Hashed entries and non-default ports are
  supported. This is the owning wizard host-key selection contract.
- Before registration, the wizard skips protocols whose default TCP listener
  collides with the connected SSH port and emits a progress note for each.
  UDP listeners using the same numeric port remain enabled.
- The fail2ban sshd jail covers the connected inventory SSH port and every port
  reported by `sshd -T`, deduplicated. Config-file detection and port 22 remain
  fallbacks when the transport/configuration supplies no port.
- Fleet kernel updates emit a terminal error if any server failed.
- AWG, sing-box and Xray apply must finish copying the live configuration to a
  temporary snapshot and rename it to `.bak` before replacing the live file.
  Snapshot failure aborts without changing the live file or its previous backup.
- Firewall setup is a no-op when UFW is absent or inactive. With active UFW,
  failure to allow any required port fails deployment. Web deploy and redeploy
  record it in `ssh_errors` and cannot advance the successful deploy baseline;
  bootstrap and CLI deploy return an error. Caddy provisioning checks ACME
  port rules too; a firewall failure after VLESS-WS config swaps invokes the
  existing configuration rollback.

## Interface / Data Contract

`Kernel::service_units` declares managed units. All production kernels provide it;
reconciliation fails for an undeclared disabled kernel instead of silently leaving
it running. Absent units require no change. SSH shutdown errors fail the deploy.
`SubprocessSshTransport::exec_password` reuses direct host pinning and bounded
child execution. It rejects jump routes; password jump authentication remains
unsupported. The synchronous deploy task owns its guard through completion.
`SshTransport::target_port() -> Option<u16>` exposes target connection metadata
without a kernel-specific dependency: subprocess and russh transports return the
port supplied from inventory, including through a jump host; transports without
this metadata default to `None`. The sing-box setup script receives it as
`VPNCTL_SSH_PORT` inside the privileged command, so sudo environment filtering
cannot discard it.

## Verification Checklist

- [ ] Matching pin works without shared known_hosts; mismatched pin prevents
      sshpass execution, including reference-key fallback; unpinned mode uses TOFU.
- [ ] Wizard keyscan mismatch prevents a second password login for root and
      non-root users; key authentication retains the first-login pin. Missing
      accepted keys fail closed; matching plain/hashed entries retain TOFU.
- [ ] Several accepted key types select the presented, already accepted key;
      an unaccepted presented key fails closed.
- [ ] Wizard skips REALITY on SSH 443 and other TCP port collisions before
      registration, reports the skipped protocol, and preserves UDP defaults.
- [ ] Rendered fail2ban script includes the connected and all configured ports,
      removes duplicates, and retains port 22 as the last fallback.
- [ ] Hung password command is killed within the deadline, with no surviving child.
- [ ] Cancelled HTTP deploy retains its lock until SSH work completes.
- [ ] Retired kernel services are stopped/disabled; enabled, never-retired and
      absent units are untouched; shutdown errors propagate.
- [ ] Hostname filtering excludes only AWG2/AWG3 and preserves literal-IP defaults.
- [ ] Failed/locked fleet updates end with `error`; empty successful fleet with `ok`.
- [ ] Partial snapshot copy leaves live/staged configuration and the previous
      backup unchanged, without attempting service changes.
- [ ] All kernels propagate active UFW allow failures; absent/inactive UFW is a
      no-op. Redeploy records a failed audit and leaves the server pending.
