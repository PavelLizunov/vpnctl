# New server protocol defaults

## Intent & Invariants

New nodes start with only VLESS+REALITY (`vless+reality`) enabled. Supporting a
protocol in a kernel must not automatically enable it. Existing nodes, grants,
secrets and client artifacts retain their current settings and wire formats.
Other registered protocols remain available through the server Protocols page.

## Interface / Data contract

- The web add-server wizard and quick-add select only `vless+reality` from the
  sing-box-supported protocol list, for IPv4, IPv6 and hostname targets.
- Both web paths retain the SSH TCP listener collision guard: SSH on port 443
  leaves the enabled set empty, without selecting a fallback. UI copy explains
  how to choose a different VLESS listen port on the Protocols page; the wizard
  also reports the skip in its progress log.
- CLI `server add` and `bootstrap` default `--protocols` to `vless+reality` only.
  Explicit `--protocols` still replaces the default, preserving automation.
- Registration and its audit payload use the same selected protocol list. No
  migration, existing-node rewrite or automatic fleet redeploy is introduced.

## Verification checklist

- [ ] Full kernel support selects exactly REALITY, not TUIC/HY2/AWG/Trojan/AnyTLS.
- [ ] Missing REALITY support and SSH TCP 443 produce no alternative protocol.
- [ ] Web quick-add covers IPv4, IPv6, hostname, SSH conflict and audited selection.
- [ ] CLI defaults and explicit protocol selections are covered for both commands.
- [ ] Web wizard and quick-add copy describe the default and SSH conflict.
