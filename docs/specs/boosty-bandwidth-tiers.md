# Per-user speed from Boosty tiers

## Intent and invariants

An operator can apply different sing-box rates on one server from the current
Boosty dashboard roster. Each authenticated vpnctl account gets one budget for
its TCP and UDP payload on that node. Existing flat rates and client profiles
keep their current behavior. Applying on one node never schedules another node.

## Interface and data contract

The server's Protocols tab lists Boosty levels by name and exact ID. Set a
positive default rate for accounts without an override and an optional rate
per level. Blank level rates inherit the default. Save and apply reads the
local dashboard's `/api/v1/roster`, checks the complete fresh snapshot across
all pages, and joins active paid subscribers to vpnctl accounts. Explicit
links take precedence over the `boosty-<subscriber-id>` names used by panel
delivery. Multiple VPN accounts explicitly linked to a subscriber get the
same rate with separate budgets. An unavailable, inconsistent or stale roster
leaves the saved policy unchanged. Saving the uniform rate returns that server
to a uniform policy.

The current overrides and policy are saved together with an audited mutation.
Reapply the policy on the same form to refresh it after subscription changes.
The operation uses no Boosty credentials and does not run the legacy poller.
The daemon passes named overrides in `route.vpnctl_user_bandwidth.user_bits_per_second`.
A node must pass the override-aware capability check before the config is uploaded.

## Verification

- Different levels with the same name can have different configured rates.
- Unlinked, inactive and unpaid accounts inherit the default. Rate selection
  also works for mapped WireGuard peers.
- Stale and mixed snapshots do not alter saved rates or queue a deploy.
- An older kernel that ignores the override field cannot accept a staged config.
- Same-rate saves are idempotent. The legacy rate-only form still works.
