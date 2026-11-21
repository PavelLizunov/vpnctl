# On-demand DNSTT availability

## Intent and invariants

The server Status page can run one DNSTT transfer check and show its result in
Availability. Run the tunnel check only after an operator starts it. Existing
scheduled assurance for other protocols continues unchanged.

## Interface and data contract

- Set `VPNCTLD_DNSTT_CHECK_RUNNER` to the absolute path of a trusted executable
  to enable the action beside Availability for DNSTT servers. The action uses
  the existing authenticated, one-use SSE start ticket.
- In this mode the scheduled poller leaves DNSTT results to the manual action.
  Each action shares the node operation lock with deployment and invokes its
  runner once with the selected server address. The bounded runner records a
  result in the existing protocol-assurance history. A completed transfer
  check expires after the normal assurance freshness window.
- The adapter `scripts/dnstt-assurance-on-demand.py` calls the installed
  one-shot `/usr/local/libexec/vpnctl/dnstt-assurance-check`. It identifies the
  existing private template by the digest of the node's literal IPv4 address.
  That probe owns the choice of
  client, dedicated identity and operator-controlled HTTPS endpoint.
  Only sanitized outcomes are returned. Missing or rejected local probe inputs
  yield unknown, while an unsuccessful tunnel transfer yields degraded.

## Verification

- Posting a ticket for this action requires same-origin admin access. Opening
  the stream without a valid ticket never invokes the runner.
- Assert that the runner is called once for the selected endpoint, that a VPN
  transfer result updates both fleet and node Availability, and that local
  failures remain unknown.
- Confirm that subsequent scheduled rounds leave this DNSTT result intact.
