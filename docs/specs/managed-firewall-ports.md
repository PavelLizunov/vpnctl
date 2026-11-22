# Managed firewall ports

## Intent and invariants

- Deploy manages owned inbound UFW rules on nodes with an active UFW firewall.
  Setup continues without changes to firewall policy if UFW is absent or inactive.
- New VPN ingress rules carry a vpnctl comment. An existing rule with the same
  match retains its action and comment. An exact deny or reject fails the deploy.
  Unmarked single-port allowances with no public listener are retained and
  reported in deployment output and audit details.
- Keep the configured SSH port, the active SSH connection's server port,
  non-loopback listeners, enabled protocol ports and TCP 80 for Caddy's ACME HTTP challenge.
  Keep IPv4 and IPv6 rules independent so a manual rule in one family does not
  become owned when vpnctl opens the other family.

## Interface and data

- The existing web deploy, redeploy and protocol actions and CLI deploy remove
  obsolete rules after all service changes succeed, including when the last
  protocol is disabled. A stale inventory revision or a failed service change
  skips deletion. Firewall errors use the existing deploy failure paths.
- The node-local UFW comment is the ownership record. It covers single-port
  inbound allows, including DNSTT's address-scoped UDP 53. The previous DNSTT
  comment is recognized for that rule shape. Read and change rules under UFW's
  lock. Delete exact owned rules and leave provider firewall policy intact.
- Caddy opens its selected front port and HTTP challenge port within its apply
  transaction. Provisioning the binary no longer opens ports.

## Verification

- Change an effective port and disable the last protocol. Confirm obsolete
  owned allowances are removed and repeated deploys are idempotent.
- Exercise IPv4/IPv6, manual allows and denies, the scoped legacy DNSTT rule,
  Caddy custom ports, live listeners, SSH, and absent or inactive UFW.
- On a failed apply or socket inventory read, retain old allowances and report
  the failure through the deploy surface.
