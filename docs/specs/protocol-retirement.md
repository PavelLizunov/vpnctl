# Retire legacy VPN protocols

## Intent and invariants

Withdraw Trojan, AnyTLS, Shadowsocks 2022 and AmneziaWG 2.0 from new provisioning.
Existing enabled instances remain renderable until the operator disables them.
Hiding AWG 2.0 profiles allows existing imports to keep working. Verify AWG 3.1
on the affected client networks before stopping 2.0.

## Interface and data contract

The CLI registry and web protocol picker advertise active protocols. The picker
also shows retired protocols already enabled on the node so operators can hide
or disable them. Web enable and CLI server creation reject new instances.
Retirement preserves inventory, credentials and existing subscription bytes.

## Verification

- Canonical registry enumeration excludes retired IDs. Exact lookup still works.
- An existing retired protocol can be disabled. Enabling a new one is rejected.
- Output for active protocols remains byte-for-byte stable.
