# Contract: Boosty bookmarklet origin

## Intent & invariants

Quick Connect returns the operator from Boosty to the administrative address
where the bookmarklet was obtained. Header parsing must not construct a malformed
URL, invent a different authority by deleting characters, or trust a forwarded
scheme supplied by an untrusted peer. Existing DNS, IPv4 and bracketed IPv6
addresses with optional ports must keep working. This is authority validation,
not a configured hostname allowlist or a change to administrator authentication.

## Interface / data contract

- GET `/admin/boosty` obtains the transport peer from `ConnectInfo<SocketAddr>`.
- `X-Forwarded-Proto` is read through the existing trusted-proxy resolver.
  Only the exact validated value `https` enables HTTPS; every other case uses
  HTTP. Missing peer information never grants trust.
- Host is accepted only as a complete HTTP URL authority: ASCII hostname/IP
  syntax, at most 259 bytes including a port, and a valid parsed HTTP URL.
  IPv6 brackets and the original accepted spelling/port are preserved.
  Missing or invalid input falls back to `vpnctld`, without character deletion.
- The public subscription base URL does not select the administrative origin.
  JSON/HTML escaping, fragment-only token transport, explicit operator consent,
  stored settings, client artifacts and VPN nodes are unchanged.

## Verification checklist

- [ ] DNS, IPv4 and bracketed IPv6, with and without ports, preserve the origin.
- [ ] Userinfo, separators, invalid ports/IPv6, whitespace and oversized or
  missing Host cannot select a malformed authority.
- [ ] Trusted HTTPS works; untrusted HTTPS, missing peers and invalid/multiple
  scheme values cannot select HTTPS or another scheme.
- [ ] Router tests exercise untrusted peers and real IPv6 rendering.
- [ ] Independent review and all canonical/target CI gates pass on the candidate.
