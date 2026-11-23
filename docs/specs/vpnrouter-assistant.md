# VPNRouter setup assistant

## Intent and invariants

VPNRouter submits typed requests and uses the returned typed operation or profile ID to configure local application routing. vpnctl authorizes access and interprets the input. VPNRouter owns target resolution, installed and approved profile discovery, settings revision validation, Apply, verification and undo.

The zapret profile route only orders IDs from `candidates`. It never installs or activates a profile, executes model text, or changes server networking. The client remains responsible for verifying that every candidate is locally installed and operator-approved.

## Interface

Both routes accept `Authorization: Bearer <credential>` and `X-Vpnctl-Identity: device|subscription` using the [NINA identity contract](nina-assistant.md). Resolve both kinds against the same current user on every request. Each route uses separate account and IP quota buckets, at six per user and 120 per source in 60 seconds. Both return `Cache-Control: no-store`, cap the request body at 2048 bytes and use the error contract below.

### Route planning

`POST /api/v1/assistant/vpnrouter/plan` accepts four required fields. Reject unknown and duplicate fields. `schema` is `1`, `locale` is `en` or `ru`, `goal` is 1–768 UTF-8 bytes after trimming and `target_available` reports whether the client resolved exactly one target for this goal. Allow ordinary text, LF and tab. Reject other control characters, directional formatting controls and a goal containing the caller credential of eight or more bytes. App identity and paths stay local.

The model receives the typed request and a system prompt. The server returns either:

- `{"schema":1,"result":{"operation":"route_only_app"}}` when the goal asks to route only the resolved app through the VPN and `target_available` is true.
- `{"schema":1,"result":{"operation":"clarify","reason":"app_selection"}}` when the user must identify an app.
- `{"schema":1,"result":{"operation":"clarify","reason":"unsupported_goal"}}` when the current operation cannot fulfil the goal.

The model returns the inner object only. Reject extra fields, unknown operations or reasons, or a routing operation without a resolved target.

### Zapret profile selection

`POST /api/v1/assistant/vpnrouter/zapret/next` orders locally installed and approved connectivity profiles for one target. The request has four required fields:

```json
{
  "schema": 1,
  "target": "discord_gateway",
  "candidates": ["profile-a", "profile-b"],
  "attempts": [
    {"profile": "profile-c", "target_ok": false, "controls_ok": true}
  ]
}
```

- `target` is `discord_gateway` or `youtube_media`.
- `candidates` contains 1–5 unique profile IDs.
- `attempts` contains at most four earlier attempts with distinct profile IDs, all disjoint from `candidates`.
- Every profile ID matches `[a-z][a-z0-9-]{0,31}`.
- Reject duplicate or unknown fields at every level, and reject any profile ID containing the caller credential of eight or more bytes.

The model receives only this typed object and a system prompt. It returns only `{"profile":"<candidate-id>"}` or `{"profile":null}`. A valid request returns `200 OK` with `{"schema":1,"profile":"<candidate-id>"}` or `{"schema":1,"profile":null}`. Reject a missing `profile` field, unknown fields, malformed JSON and any ID outside `candidates`. Never execute model text.

### Errors and status

- `401 unauthorized` for missing, malformed or unknown credentials.
- `403 subscription_disabled` for disabled accounts.
- `400 invalid_report` for an invalid request.
- `413 report_too_large` above 2048 bytes.
- `429 quota_exceeded` with `Retry-After`.
- `503 unavailable` when the gateway is unconfigured or inventory lookup fails.
- `502 gateway_error` for provider failures or rejected model output.

Error bodies contain only the error code. Provider text and credentials stay out of responses.

## Deployment

Both routes use the same gateway settings: `VPNCTLD_VPNROUTER_GATEWAY_URL`, `VPNCTLD_VPNROUTER_GATEWAY_MODEL` and `VPNCTLD_VPNROUTER_GATEWAY_KEY_FILE`. No additional gateway configuration is required.

Route the exact POST paths `/api/v1/assistant/vpnrouter/plan` and `/api/v1/assistant/vpnrouter/zapret/next` to vpnctld and set the trusted `X-Real-IP` header as described in [deployment.md](deployment.md). The server does not change its own networking for either route.

## Verification

- Exercise valid and disabled credentials for both subscription forms, separate account quotas and body limits.
- Verify a valid action, both clarification reasons, unknown fields and refusal of a routing action without a target.
- Verify a selected candidate, a `null` selection, missing and unknown model fields, a selection outside `candidates`, malformed model JSON and provider failures.
- Verify profile ID bounds, candidate and attempt uniqueness, attempt/candidate disjointness, attempt limits and credential rejection.
- Verify that only the typed request fields reach the mock model and that responses keep `Cache-Control: no-store`.
