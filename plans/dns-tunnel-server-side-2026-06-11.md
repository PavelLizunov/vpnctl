# dns-tunnel server-side investigation — 2026-06-11

> **Status:** DEPRECATED & REMOVED (2026-08-24). The `dns-tunnel` protocol and kernel have been removed from the active codebase via migration `0050_remove_dns_tunnel.sql`. Legacy `dns-tunnel.service` and `dns-tunnel-singbox.service` units are decommissioned via hoster console. `dns-tunnel:*` server secrets are retained in SQLite during the transition release for rollback safety and scheduled for later purge. This document is preserved for historical context.

Server-side diagnosis that motivated the two hardening changes in
`feat/dns-tunnel-auth-and-idle` (authoritative endpoint in the share-link
+ slipstream `--idle-timeout-seconds` bump).

## Symptom

The dns-tunnel transport carries traffic for **~1.5–3 minutes** and then
stalls. On the client side, `slipstream-client` logs:

- `local_error=0x433` — `PICOQUIC_ERROR_IDLE_TIMEOUT` (the QUIC
  connection hit its idle timeout and was torn down), then
- `Path for resolver [195.208.4.1]:53 became unavailable`,

after which the client enters its internal reconnect backoff and the
session is interrupted until a fresh re-handshake succeeds.

## Server diagnosis (213.155.15.93, 2026-06-11)

The server side was inspected end-to-end and found **healthy**:

- **slipstream-server** is stable: `systemctl show` reports
  `NRestarts=0`; it listens on `*:53` as expected.
- **sing-box VLESS inbound** on `127.0.0.1:9001` is active and accepting
  connections (the loopback forward-target the relay decapsulates onto).
- **Box egress** is healthy. A transient `i/o timeout` to `:443` at
  22:07 was a brief hoster network blip and recovered on its own — not a
  persistent egress fault.
- **conntrack** is at **69/8192** — nowhere near saturation, so this is
  not a connection-table-exhaustion stall.
- The server's slipstream `--idle-timeout-seconds` was the **upstream
  default 60s** (the kernel did not render the flag, so slipstream used
  its built-in default).
- An **authoritative endpoint is available**: the box is bound to the
  public `213.155.15.93:53`, so a client could query it directly rather
  than going through the recursive resolvers.
- The **server log** shows the client's VLESS mux closing with **EOF at
  ~3–4 min** — i.e. the close is **client-initiated**; the server does
  not close the connection.

## Root cause

The recursive **НСДИ** resolver (`195.208.4.1` / `195.208.5.1`) stops
relaying the covert-DNS stream after a few minutes — a rate-limit /
state-eviction behaviour of the recursor. This is an **inherent NSDI
property**, not a server bug and not a client-routing bug. It is
confirmed by the client's own `Path for resolver ... became unavailable`
log line: the path the client gives up on is the recursor path, not the
box.

When the recursor stalls the stream, no DNS packets flow for long enough
to trip QUIC's 60s idle timeout, the connection is torn down
(`local_error=0x433`), and the client must perform a full re-handshake.

## Mitigations (this PR)

1. **Ship an `auth` authoritative endpoint in the share-link.** When the
   operator sets `dns-tunnel:authoritative`, the link gains an `auth`
   field carrying the box's authoritative DNS endpoint(s)
   (`213.155.15.93:53`). An r6+ client can then run
   `slipstream-client --authoritative 213.155.15.93:53`, bypassing the
   recursive НСДИ resolver entirely. This path is **stable**, but DNS
   goes straight to the box IP, so it is **NOT whitelist/DPI-resistant** —
   use it on non-censored networks or for testing. The `r` (resolver)
   list stays in the link **always** as the censorship-network fallback;
   `auth` is purely additive.

2. **Bump slipstream `--idle-timeout-seconds` to 180** (from upstream's
   60). A longer idle window lets the QUIC connection survive a short
   resolver hiccup and recover without a full re-handshake. Operator-
   overridable via `dns-tunnel:idle_timeout_seconds`; default 180.

## Open

For the production NSDI path the recursor drop is **inherent** — the
180s bump softens short hiccups but does not eliminate the multi-minute
eviction. Further mitigation lives in lower QPS / keep-alive tuning /
multipath and is tracked **separately**.
