# NINA assistant access

`POST /api/v1/assistant/diagnose` authenticates the saved NINA subscription
with `Authorization: Bearer <credential>` and `X-Vpnctl-Identity`.
`subscription` uses the existing subscription token and `device` uses the
existing VPNRouter device ID. vpnctld resolves either credential against its
inventory on each request. Unknown or malformed credentials return 401 and
disabled users return 403. The two credential forms share a quota of six
requests per user per 60 seconds. vpnctld also limits requests per source IP.

The application sends a JSON object with schema `1`, service `state`,
boolean or null `enabled`, and six distinct `checks`. Each check contains
only an `id` and a boolean `ok`. The IDs are `dns.youtube`, `dns.discord`,
`dns.control`, `https.youtube`, `https.discord`, and `public_ipv4`.
Invalid reports return 400. Bodies above 2048 bytes return 413.

The configured model receives the report and a system prompt. The upstream
request uses a dedicated server-side gateway key. On success vpnctld returns
`{"schema":1,"explanation":"…"}` with up to 4096 UTF-8 bytes. Quota
exhaustion returns 429. An unconfigured gateway or inventory failure returns
503 and other upstream failures return 502. Responses use `Cache-Control:
no-store`.

## Deployment

Set `VPNCTLD_NINA_GATEWAY_URL` to an HTTPS OpenAI-compatible chat completions
endpoint, `VPNCTLD_NINA_GATEWAY_MODEL` to its model ID, and
`VPNCTLD_NINA_GATEWAY_KEY_FILE` to a private key file readable by vpnctld.
HTTP is accepted for loopback endpoints. The gateway client uses a
12-second deadline and keeps authentication on the configured endpoint.
Route the exact POST path to vpnctld and set the trusted `X-Real-IP`
header as described in [deployment.md](deployment.md).

For the owner's OpenCode Go account, set the URL to
`https://opencode.ai/inference/go/openai/v1/chat/completions` and the
model to `deepseek-v4.1-flash`. vpnctld identifies itself as NINA, sends a
fresh OpenCode session ID for each diagnostic explanation, and disables
the reasoning phase so the bounded response contains user-facing text.
It verifies the upstream model ID before returning that text. Other gateway
configurations use the standard chat completions request.
