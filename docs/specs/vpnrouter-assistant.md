# VPNRouter setup assistant

## Intent and invariants

VPNRouter submits one user goal and uses the returned typed operation to configure local application routing. vpnctl authorizes access and interprets the goal. VPNRouter owns target resolution, settings revision validation, Apply, verification and undo.

## Interface

`POST /api/v1/assistant/vpnrouter/plan` accepts `Authorization: Bearer <credential>` and `X-Vpnctl-Identity: device|subscription` using the [NINA identity contract](nina-assistant.md). Resolve both kinds against the same current user on every request. Use separate VPNRouter account and IP quota buckets, at six per user and 120 per source in 60 seconds. Return `Cache-Control: no-store`.

The request object has four required fields and a 2048-byte body cap. Reject unknown fields. `schema` is `1`, `locale` is `en` or `ru`, `goal` is 1–768 UTF-8 bytes after trimming and `target_available` reports whether the client resolved exactly one target for this goal. Allow ordinary text, LF and tab. Reject other control characters, directional formatting controls and a goal containing the caller credential of eight or more bytes. App identity and paths stay local.

The model receives the typed request and a system prompt. The server returns either:

- `{"schema":1,"result":{"operation":"route_only_app"}}` when the goal asks to route only the resolved app through the VPN and `target_available` is true.
- `{"schema":1,"result":{"operation":"clarify","reason":"app_selection"}}` when the user must identify an app.
- `{"schema":1,"result":{"operation":"clarify","reason":"unsupported_goal"}}` when the current operation cannot fulfil the goal.

The model returns the inner object only. Reject extra fields, unknown operations or reasons, or a routing operation without a resolved target. The API uses the existing NINA status/error contract for invalid credentials, disabled accounts, invalid reports, body limits, quota and provider failures. Keep provider errors and credentials out of client output. Configure the new route independently with `VPNCTLD_VPNROUTER_GATEWAY_URL`, `VPNCTLD_VPNROUTER_GATEWAY_MODEL` and `VPNCTLD_VPNROUTER_GATEWAY_KEY_FILE`. A valid request with no configured gateway receives 503.

## Verification

- Exercise valid and disabled credentials for both subscription forms, shared account quota and body limits.
- Verify a valid action, both clarification reasons, unknown fields and refusal of a routing action without a target.
- Verify that only the request fields reach the mock model. Check provider failures and preserve the deployed NINA contract.
