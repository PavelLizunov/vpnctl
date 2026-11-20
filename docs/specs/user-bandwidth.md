# Per-user speed on sing-box nodes

## Intent and invariants

Limit routed payload on a node by the authenticated vpnctl user. On a node set
to 40 Mbit/s, all of a user's sing-box TCP and UDP flows share one 40 Mbit/s
budget across upload and download. Users receive independent budgets.

## Interface and data contract

On a server's Protocols tab, save the per-user cap in Mbit/s. The value is
audited and applied through the usual node redeploy. Zero leaves speed
unlimited. Allowed values are 0–4000. The deploy checks that the installed node artifact recognizes and validates
`route.vpnctl_user_bandwidth` before replacing the live configuration. A node config with a cap maps each userspace
WireGuard peer's assigned host addresses to the same user ID used by proxy
inbounds. Client profiles and monthly traffic accounting are unchanged.
The cap is local to sing-box on that node. Xray, DNSTT, untracked traffic and
other processes have their own data paths.

## Verification

- An enabled setting renders the bit rate and authorized peer bindings.
- Invalid values fail before mutation. No-op submissions add no audit or deploy.
- Parallel streams for one user share a budget and other users keep their own.
- On the pilot node, verify authenticated traffic and existing listener health.
