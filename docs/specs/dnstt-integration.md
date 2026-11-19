# Managed DNSTT through SSH

## Intent and invariants

A VPN exit may run an optional DNSTT endpoint for TCP egress through SSH. Its
systemd units and DNS delegation are independent of existing VPN listeners.
Existing subscription URLs, tokens, scheme order and uncapped response bytes
stay intact. The node advertises no browser HTTPS service for the tunnel zone.

## Interface and data contract

- `dnstt` is an optional protocol and separate kernel. It owns two systemd
  units, the authoritative UDP 53 listener and a loopback-only SSH listener.
  Node installs reuse a verified architecture-specific `dnstt-server` artifact.
  Build the three pinned binaries on a build host using
  `tools/dnstt-server/build.sh <output-directory>` and install them root-owned
  under `/opt/vpnctl/node-artifacts/` on the controller before enabling DNSTT.
- Configure a DNS-only delegated zone and an IPv4 UDP resolver in the server's
  Protocols settings. Validate them before deployment. The registry owns port
  conflicts, secret declarations and unit lifecycle. Never recreate credentials
  on an ordinary deploy. Per-user SSH keys follow effective grant identity;
  disabled users or disabled protocol grants lose their forwarding key on apply.
  All deploy entry points use the same protocol-filtered grant query for DNSTT,
  since a removed profile alone cannot revoke a cached SSH key. Other protocols
  retain their existing deploy-user selection.
- Publish only from a visible, granted VPN-exit node after successful apply,
  with a valid Noise public key, a pinned SSH host key and the user public key
  in the observed deployed allow-list. Skip missing or
  unusable DNSTT inputs without affecting existing entries. Status distinguishes
  configured, not deployed and service health from the external tunnel check.
- The existing app-config endpoint appends `dnstt://<base64url-json>#<label>`
  only for a VPNRouter request with capability `dnstt-v1`. The unpadded UTF-8
  JSON payload has `id`, `resolver`, `port`, `domain`, `noise_key`,
  `ssh_host_key` and `ssh_private_key`. The SSH username and backend port are
  fixed to `vpnctldnstt` and `22054`. The relay and SSH form one selectable
  profile. General `/sub`, stock sing-box, Mihomo and old VPNRouter clients
  keep their existing formats and contents.

## Verification

- Pin old subscription bodies and confirm opt-in, incomplete state and access
  revocation behavior using synthetic identities. Verify keys differ per grant.
- Verify port collision handling, allow-list management and service status.
- From an independent network, refresh the same URL with and without the new
  capability. Prove HTTPS egress through the managed Senko deployment and
  confirm loopback/private TCP is rejected.
