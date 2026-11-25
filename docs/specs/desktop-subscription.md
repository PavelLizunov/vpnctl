# Desktop VPNRouter subscription policy

## Intent and invariants

An operator can restrict one node's profile delivery to desktop VPNRouter
clients reporting a specific managed sing-box version. The policy is optional
and keeps existing subscriptions unchanged until enabled on a node. Grants,
node configuration, and credentials already delivered remain valid.

## Contract

- Server Setup accepts an exact managed core version such as
  `1.14.4-vpnctl.3`. An empty value clears the filter. A changed value
  is audited and takes effect on subsequent requests.
- The device-ID endpoint requires an active grant and single values for
  `User-Agent`, `X-VPNRouter-Platform`, and `X-VPNRouter-Core-Version`.
  The first User-Agent product identifies the edition, optionally followed by
  its app version. `VPNRouter` supports `windows`, `macos`, and `linux`.
  `VPNRouterBusiness` supports `windows`. Product names are ASCII
  case-insensitive. The selected core must match the node's exact pin.
  DNSTT profiles additionally require the `dnstt-v1` capability.
  Ineligible requests and ordinary token subscriptions omit the restricted node.
- Client headers describe the selected local runtime. They are client claims
  and can be reproduced by other callers holding the device token.

## Verification

- [ ] The expected platform and version receive the restricted profile.
- [ ] Old, missing, duplicate, mobile and non-VPNRouter headers omit it.
- [ ] Token subscription formats omit it while retaining unrestricted profiles.
- [ ] Invalid policy input leaves the saved value intact. Clearing it restores
  ordinary delivery.
