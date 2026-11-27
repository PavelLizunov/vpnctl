# Mieru

## Intent and invariants

Mieru is opt-in on nodes with managed sing-box. Usernames are inventory IDs
and passwords are the UUIDs issued for the corresponding server grants.
Disabled users, denied grants, and invalid credentials are excluded from the
inbound. The listener starts once there is an eligible user.

## Interface and data contract

- The default listener is TCP on port 8445. Configure `mieru.listen_port`
  in 1–65535 and choose `tcp` or `udp` with `mieru.transport`.
- `mieru.multiplexing` accepts `default`, `off`, `low`, `middle`, or
  `high` and defaults to `middle`. `mieru.handshake_mode` accepts
  `default`, `standard`, or `no_wait` and defaults to `standard`.
- VPNRouter clients advertise `mieru-v1` to receive `mieru://` links.
  Only visible, direct grants are eligible. Links encode the transport,
  multiplexing level, and handshake mode in the query.

## Verification checklist

- Validate both transports, port boundaries, credentials, and client options.
- Verify capability gating and byte preservation for legacy subscriptions.
- Exercise the admin toggle, settings form, and listener conflict checks.
