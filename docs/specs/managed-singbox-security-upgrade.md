# Managed sing-box 1.14.2 security upgrade

## Intent and invariants

Replace the stale `1.14.0-vpnctl.5` acquisition pin with the managed fork's
`1.14.2-vpnctl.2` release (`f62085aa7cc0f3ee665ac3043d35698760a386e9`).
Keep the APT bootstrap floor unchanged: managed artifacts, not an upstream
package upgrade, supply the fork's features. Preserve node configuration,
credentials, subscriptions and the existing binary/helper rollback mechanism.
An active `caddy-vlessws` unit shares the managed binary: restart and check it
when that binary changes, and restart it after restoring the previous artifacts
on failure. Leave an inactive or absent backend inactive.
Do not change Xray's already-current `26.3.27` pin or reboot node operating systems.

## Interface and data contract

No public API or renderer changes. Rust release metadata, the acquisition script
and documented archive digests must agree for amd64, arm64 and armv7. SHA256
verification remains mandatory. The previous AWG interop result is historical,
not evidence that the new release has passed native AWG client verification.

The installed control-plane artifact supplies subsequent Web and scheduled
kernel updates. Replacing code constants without replacing that artifact does
not update nodes. Installed binaries and running `/proc/<pid>/exe` must match.

## Verification checklist

- [ ] Release archives match their pinned SHA256 values for all architectures.
- [ ] Pin consistency regression fails on a stale acquisition-script digest.
- [ ] Independent diff review; five canonical Cargo checks and `just ci`; CI.
- [ ] Candidate validates every node's existing configuration before installation.
- [ ] Canary, then sequential rollout with real client transfer checks and Stats API.
- [ ] Configuration digests and existing subscription bytes remain unchanged.
- [ ] Actual running binary digests match the managed artifact on every node.
- [ ] Record native AWG interop as not-run unless exercised against the new release.
