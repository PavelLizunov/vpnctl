# TurnRelay exit profiles

## Intent and invariants

A VPN exit may run `turnrelay-server` as an optional UDP tunnel that clients
reach through a TURN provider. Every issued profile pins the exit's persistent
DTLS certificate and carries the pre-shared exit password, so one import gives
the user a working outbound without client-side key generation. Direct
subscription bytes, `/sub`, Mihomo, stock sing-box and VPNRouter clients that do
not advertise `turnrelay-v1` stay byte-for-byte unchanged.

- `turnrelay` is an optional protocol served by its own kernel; it never
  appears in sing-box or stock sing-box subscriptions.
- The exit password is minted once and never rotated by an ordinary deploy.
- A profile is issued only for a visible, granted, non-suppressed, non-detoured
  exit whose `observed.turnrelay.applied` digest matches the current settings
  and whose `observed.turnrelay.cert_sha256` is 64 lowercase hex.
- Relayed VLESS copies reuse the existing `outbound=` and `detour=` query
  params; there is no new `relay=` parameter. `detour` matches the
  `turnrelay://` profile id `turnrelay-<exit_sid>` exactly. Every composed
  outbound tag is capped at 64 characters; an over-long id is truncated and
  suffixed with `-` plus eight hex characters of its SHA-256, and the hop `id`
  and VLESS `detour` are always produced by the same helper.
- `turnrelay.turn_server` is at most 255 characters, matching VPNRouter's
  parser.

## Interface and data contract

Settings live in `server_secrets`:

| Key | Meaning |
|---|---|
| `turnrelay.listen_port` | UDP listener, default `53492` |
| `turnrelay.mode` | `dtls` (default) or `srtp` |
| `turnrelay.turn_server` | TURN `host:port` |
| `turnrelay.turn_username` / `turnrelay.turn_password` | TURN credentials |
| `turnrelay.connections` | allocations, `1..=60`, default `2` |
| `turnrelay.udp` | carry UDP, default `true` |
| `turnrelay.publish` | publish list; `vless+reality` enables relaying |
| `turnrelay.publish_targets` | comma-separated server IDs or `*` |
| `turnrelay.password` | minted exit secret |
| `observed.turnrelay.cert_sha256` | SHA-256 of the leaf certificate DER |
| `observed.turnrelay.applied` | digest of every server-affecting setting |

The wire profile is
`turnrelay://<URL_SAFE_NO_PAD(json)>#<percent-encoded-label>`. The JSON object
is exactly:

```json
{"id":"turnrelay-<sid>","provider":"static","server_type":"exit",
 "server":"<literal exit IP>","server_port":53492,
 "turn_server":"<host:port>","turn_username":"<user>",
 "turn_password":"<pass>","password":"<exit secret>",
 "server_fingerprint":"<64 lowercase hex>","connections":2,
 "mode":"dtls","udp":true}
```

Capability: `turnrelay-v1`, exact-match token in
`X-VPNRouter-Capabilities`, and only for a VPNRouter user agent. Repeated
headers are accepted; `turnrelay-v10` and non-VPNRouter UAs are ignored.

Issuance, only when the capability is present:

1. For each eligible exit with visible `vless+reality`, append a relayed VLESS
   duplicate with `outbound=vless-turnrelay-<exit_sid>&detour=turnrelay-<exit_sid>`
   and fragment `"{Label} VLESS · TurnRelay ~{user}"`.
2. For each eligible target (same-server, or a `publish_targets` match), append
   a duplicate built from the target's VLESS values with
   `outbound=vless-turnrelay-<target_sid>-via-<exit_sid>&detour=turnrelay-<exit_sid>`
   and fragment `"{TargetLabel} VLESS · TurnRelay ({ExitLabel}) ~{user}"`.
3. Append one deduplicated `turnrelay://` hop per exit that emitted at least
   one duplicate, labelled `"{ExitLabel} TurnRelay ~{user}"`.

Build node artifacts with `tools/turnrelay-server/build.sh <output-directory>`
(upstream commit `4c3dc7ad`, plus the patched files listed in
`SING_BOX_VPNCTL_DIR/protocol/turnrelay/UPSTREAM`, defaulting to the sibling
`sing-box-vpnctl` checkout or `/var/lib/dsh/Project/sing-box-vpnctl`; the
script fails closed when the manifest or a listed file is missing). Install the
three binaries with their `.sha256` sidecars under
`/opt/vpnctl/node-artifacts/`. `scripts/deploy.sh` builds and stages them in a
checkout deploy when the patched checkout is available, or accepts a prebuilt
directory via `VPNCTL_TURNRELAY_SRC`; without either it skips them explicitly.

## Verification

- Byte-equal capability-less app-config, `/sub`, Mihomo and stock sing-box
  regressions, plus `turnrelay-v10` and non-VPNRouter rejection.
- Same-server and cross-server duplicates assert the exact `outbound`/`detour`
  values, fragments, and exactly one hop per exit.
- Omission cases: hidden, suppressed, revoked, detoured, undeployed, missing
  certificate, rotated exit password, rotated TURN credentials, publish off.
- Desktop core pin honored for `VPNRouter` Windows/macOS/Linux and
  `VPNRouterBusiness` Windows only; Android and other platforms are
  capability-only.
- Protocol spec tests cover defaults, override ranges, missing secrets,
  fingerprint shape, applied-digest invalidation and share-link byte stability.

### Managed entries

Enable the matching kernel on the entry node, then enable
`turnrelay-relay` under **Protocols**. The controller mints its TURN username and password on
enable. The service listens on the node's IPv4 address over TCP and UDP on
port 53491 by default. It accepts TURN peers only at the IPv4 addresses of
linked exits. An entry with no exits denies every peer.

When enabling `turnrelay` on an exit with empty TURN settings, the controller
chooses the entry with the fewest enabled exits, breaking ties by server ID.
An existing managed assignment takes priority. The exit settings also let
operators select a specific entry or set an external host and credentials.
Managed assignments default `turnrelay.publish` to `vless+reality` when blank.

| Setting | Meaning |
| --- | --- |
| `turnrelay.relay_server_id` | Optional managed entry ID |
| `turnrelay_relay.listen_port` | Entry TCP and UDP port, default `53491` |
| `turnrelay_relay.username` / `turnrelay_relay.password` | Minted TURN credentials |
| `turnrelay_relay.realm` | Long-term auth realm, default `turnrelay` |
| `turnrelay_relay.allowed_exits` | Controller-maintained IPv4 CSV, empty by default |

The controller recomputes allowlists after enable, disable, and settings
changes and queues redeploys for changed nodes. A legacy external setting
pointing to a managed entry address counts as a linked exit. Changing a
managed entry's port refreshes exits that reference its ID. The Dashboard,
Servers list, and server detail header show both TURN and client-detour links.

Build entry artifacts with `tools/turnrelay-relay/build.sh <output-directory>`.
Pass that directory as `VPNCTL_TURNRELAY_RELAY_SRC` to `scripts/deploy.sh` to
install the binaries and checksum sidecars alongside the exit artifacts.

Verification covers TURN peer allow/deny, closed-by-default startup, node
configuration and shutdown, automatic assignment and reassignments, manual
credentials, localized topology labels, and existing subscription byte
compatibility.
