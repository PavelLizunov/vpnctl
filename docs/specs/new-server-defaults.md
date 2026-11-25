# Defaults for newly registered VPN nodes

## Intent and invariants

New nodes use `www.apple.com` as their REALITY handshake domain and `chrome` as
their REALITY uTLS fingerprint (`vless.fp`). Save both on registration so
existing server configurations and issued profiles keep the handshake name and
fingerprint they already use (`yahoo.com` / `randomized`). An operator can
change either setting for an individual node.

## Interface and data contract

- Registration accepts initial server settings and commits them with the
  server and the existing registration audit. Invalid duplicate keys roll
  back registration.
- A sing-box node with a saved Boosty tier policy offers **Use as default for
  new nodes** in Protocols. The action records the node's base speed, account
  and tier rates as the fleet's onboarding policy. It leaves saved user
  overrides out of the template.
- The password wizard and quick add use the saved onboarding policy for new
  sing-box nodes. They calculate user overrides against the fresh roster for
  that account. If the roster is unavailable, stale or for another account,
  the node receives the base speed and stored tier settings. Its Protocols
  tab shows that tier limits need a fresh snapshot. The existing Apply Boosty
  rates action completes this step.
- A fresh installation starts with no fleet policy. Setting one is audited
  once per change. Existing nodes and their manual settings are unaffected.

## Verification

- Old links keep their byte-exact SNI and `fp=randomized`. A new node uses
  `www.apple.com` and `chrome` in its client and server configuration.
- Fresh roster registration prepares matching per-user rates. Unavailable or
  mismatched rosters leave a usable base limit and an operator-visible status.
- Changing the fleet template affects later registrations only. No-op saves
  and failed registration add no audit rows.
