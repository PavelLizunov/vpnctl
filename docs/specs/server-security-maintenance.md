# Server security maintenance

## Intent and invariants

An operator can see pending operating-system security updates across the fleet,
identify servers that need attention for the November 2026 NGINX HTTP/2
advisories, and apply an exact update set to one server from the Web admin.
Scheduled checks refresh APT metadata only. Updating packages can restart
services. Bulk installation, automatic reboot, changes to NGINX configuration
and updates to VPN-managed binaries are outside this workflow.

## Interface and data

- `GET /admin/monitoring/security` opens the fleet summary.
  `GET /admin/servers/{id}/security` opens the server report.
  `POST /admin/servers/{id}/security/check` queues a refresh and redirects to
  that report. The existing admin authentication and CSRF rules apply.
- Checks run at startup and every six hours on Debian and Ubuntu over the
  inventory's pinned SSH route. They require system Python, python3-apt,
  gpgv, and the installed Debian or Ubuntu archive keyring.
  Persist the completed observation and its time and invalidate it if the SSH
  route changes. Display unavailable, unsupported, stale and pending separately
  from a successful check with zero security updates. Failed or partial APT
  refreshes, unsettled dpkg state and missing authenticated security indexes
  are unavailable. Ubuntu Pro and third-party repositories are out of scope.
- Show installed and proposed package versions using authenticated APT origins
  for the OS release and dpkg version semantics. Show held and policy-blocked
  updates without an install option. Exclude vpnctl-managed binaries.
- `POST /admin/servers/{id}/security/apply` accepts the displayed report's
  `revision`, one or more repeated `package` selections and `confirm=yes`.
  Invalid, expired or moved reports, missing confirmation and unlisted or
  blocked packages never start an install. Start asynchronously and redirect.
  Under the package manager's lock, revalidate versions, origin, holds and the
  exact transaction. Refuse removals, new packages and extra changes. Record
  the attempted transaction and its observed outcome. Verify installed
  versions and display whether the OS requests a reboot.
- Show NGINX process/version and indications of HTTP/2 in its on-disk
  configuration alongside CVE-2026-123007 and CVE-2026-123633. Indicate that
  distribution backports and live exposure require separate evidence. Never
  transmit raw configuration or classify absence of a patch as absence of a
  vulnerability. This release tracks distribution security updates plus these
  specific NGINX advisories.

## Verification

- Confirm a failed refresh, missing security origin or changed SSH route never
  presents a clean or actionable report. Verify reports survive restart.
- Verify pinned versions, duplicate submission, holds, extra dependency
  changes, and failed or partial installation. Exercise both APT origin
  families and verify NGINX config text never leaves the node.
- Pin fleet/detail copy, authentication and CSRF behavior at the router.
