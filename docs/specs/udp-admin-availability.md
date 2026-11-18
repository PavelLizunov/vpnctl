# UDP VPN availability in the admin UI

## Intent and invariants

The current availability badge covers servers that expose only UDP VPN
protocols. TCP path measurements and TCP incident history retain their
existing meaning. The badge consumes existing observations and has no
side effects.

## Interface and evidence

- A server is UDP-only when every enabled protocol is registered and declares
  at least one port, with all declared transports UDP. Empty, unknown and
  mixed configurations use the TCP path status.
- For UDP-only servers, count the latest assurance sample for each enabled
  protocol. Future samples and samples older than two assurance cycles plus
  30 seconds are excluded. A verified transfer confirms a protocol. Failed
  handshakes or transfers contribute to the failure count.
- A confirmed transfer establishes UDP availability for the tested protocol.
  Display the observed coverage and failures so a second protocol can remain
  unverified or show a failure. When no transfer passes, distinguish observed
  failures from a lack of fresh external results. Show the newest relevant
  result time.
- Use the same status in the server detail, server list and dashboard. Link
  to the existing protocol checks from the server detail.

## Verification

- [x] Fresh AWG2 transfer and unchecked HY2 display UDP availability with
  one of two protocols verified across all three admin surfaces.
- [x] Stale, future, disabled or listener-only samples cannot confirm
  reachability. A failed external check is visible.
- [x] A TCP protocol retains the TCP badge and its applicable history.
