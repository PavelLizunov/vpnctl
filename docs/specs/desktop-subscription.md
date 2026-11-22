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
- The device-ID endpoint requires an active grant, a VPNRouter User-Agent, one
  `X-VPNRouter-Platform` value of `windows`, `macos`, or `linux`, and one
  matching `X-VPNRouter-Core-Version` value. Ineligible requests omit the
  restricted server. Ordinary token subscription formats omit that server.
- Client headers describe the selected local runtime. They are client claims
  and can be reproduced by other callers holding the device token.

## Verification

- [ ] The expected platform and version receive the restricted profile.
- [ ] Old, missing, duplicate, mobile and non-VPNRouter headers omit it.
- [ ] Token subscription formats omit it while retaining unrestricted profiles.
- [ ] Invalid policy input leaves the saved value intact. Clearing it restores
  ordinary delivery.
