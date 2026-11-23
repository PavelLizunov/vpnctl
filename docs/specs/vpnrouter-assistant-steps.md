# VPNRouter assistant steps

`POST /api/v1/assistant/vpnrouter/step` uses the same subscription/device
authentication, gateway and no-store response header as `/plan`. The two
paths share the account quota. Existing `/plan` requests remain valid.

The desktop sends the user goal and a bounded view of the current window.

```json
{
  "schema": 2,
  "locale": "en",
  "goal": "Enable VPN",
  "connected": false,
  "busy": false,
  "simple": true,
  "controls": [{"id": 1, "name": "SmpToggleConnectCommand", "kind": "press"}]
}
```

The request has a 2048 byte body limit and rejects unknown fields. The goal
uses the existing 768 UTF-8 byte rule. Control IDs must be unique in 1..32
and names must be 1..72 ASCII letters, digits, periods, hyphens or
underscores. The inventory contains at most 32 entries. Optional
`previous` identifies the last control by name. A toggle or selection can
report its optional boolean `active` state. The desktop sends no text field
values in observations.

An inventory with the `SetVpnConnected` toggle opts into instructions for
desktop commands that accept a desired state. `RouteApplicationDirect`
keeps unrelated app routes. `RouteOnlyApplication` sets exclusive VPN
routing. Both take a process basename as text and are available only when
advertised. When neither route control is advertised, the instructions
require a clarification for a routing request. Setters take the requested
boolean state. The desktop verifies the result locally. Inventories without
the marker retain the original instructions. Crash diagnosis uses its own
instructions.

The gateway can return a single advertised control action.

```json
{"schema":2,"result":{"operation":"act","id":1}}
```

The model response contains only the inner result. `press`, `select` and
`expand` accept no value. `toggle` requires a boolean value for the desired
state. `text` requires a string value with no control or bidirectional
formatting characters and at most 384 UTF-8 bytes. Unknown or unadvertised
action IDs, unexpected fields or wrong value types return 502. Terminal
model operations are the exact objects `{"operation":"finish"}` and
`{"operation":"clarify"}`. The desktop holds the control handles and checks
the window again before executing the reply.

For an explicitly requested crash analysis, the desktop sends the same
envelope with empty controls, no previous action, and an additional
`crash` object:

```json
{"fatal":true,"fault":"invalid_operation","area":"startup","signal":"tun_busy"}
```

The allowed faults are `unknown`, `null_reference`, `invalid_operation`,
`io`, `access_denied`, `out_of_memory`, `network`, `configuration`, and
`native`. Areas are `unknown`, `ui`, `startup`, `routing`, and `settings`.
Signals are `none`, `proxy_unreachable`, `tun_busy`, and `stop_unconfirmed`.
All four fields are required. The gateway rejects other fields and codes.
The original report and raw log messages stay on the device.

The only permitted result for this request is
`{"operation":"diagnosis","summary":"..."}`. The summary is 1 to 384 UTF-8
bytes after trimming and permits no control or bidirectional formatting
characters or credential echoes. Other requests cannot return a diagnosis.
