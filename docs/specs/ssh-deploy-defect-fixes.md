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
  IPv6 literals retain the complete default protocol list.
- Fleet kernel updates emit a terminal error if any server failed.

## Interface / Data Contract

`Kernel::service_units` declares managed units. All production kernels provide it;
reconciliation fails for an undeclared disabled kernel instead of silently leaving
it running. Absent units require no change. SSH shutdown errors fail the deploy.
`SubprocessSshTransport::exec_password` reuses direct host pinning and bounded
child execution. It rejects jump routes; password jump authentication remains
unsupported. The synchronous deploy task owns its guard through completion.

## Verification Checklist

- [ ] Matching pin works without shared known_hosts; mismatched pin prevents
      sshpass execution, including reference-key fallback; unpinned mode uses TOFU.
- [ ] Hung password command is killed within the deadline, with no surviving child.
- [ ] Cancelled HTTP deploy retains its lock until SSH work completes.
- [ ] Retired kernel services are stopped/disabled; enabled, never-retired and
      absent units are untouched; shutdown errors propagate.
- [ ] Hostname filtering excludes only AWG2/AWG3 and preserves literal-IP defaults.
- [ ] Failed/locked fleet updates end with `error`; empty successful fleet with `ok`.
