# Corp diagnostics bridge v1

## Intent and invariants

Add an authenticated Russian diagnostics inbox without changing policy, reader,
login or operator behavior. This standalone micro-spec freezes the bridge portion
of VPNRouter's [runtime contract](https://github.com/PavelLizunov/VPNRouter/blob/business/docs/business-diagnostics-runtime-contract.md)
and [analyzer result contract](https://github.com/PavelLizunov/VPNRouter/blob/business/docs/business-diagnostics-analyzer.md).
The task publication records their exact source SHA. Analysis is advisory and
never executes actions or publishes configuration.

## Interface and authorization

GET /diagnostics uses the existing Corp host, enabled user/binding, fresh verified
exit IP and configuration fingerprint, password and session-generation gates.
Unauthenticated eligible visitors see login. Static GET
/assets/corp-diagnostics.js contains no secrets. Navigation links Rules and
Diagnostics. Russian loading, empty, failure and insufficient-data states remain
usable at 320/420px and by keyboard; all remote text uses textContent.

Authenticated GET /api/corp/reports accepts only limit (integer 1..100) and cursor
(64 lowercase hexadecimal report ID). GET /api/corp/reports/ID returns detail.
POST /api/corp/reports/ID/retry requires existing same-origin plus session CSRF
checks and an empty JSON object. Every request passes the existing gates before
upstream access. Unknown and foreign IDs have identical safe 404 responses;
invalid queries are 400, active retry is 409, accepted retry is 202. Other upstream
failures return a safe unavailable message, never upstream body/URL/credentials.

AppState.corp_diagnostics is Option<Arc<Client>>, None in existing test-state
constructors. Public Client::new(base_url: &str, bearer: &str) returns
Result<Client, ConfigError>; Debug hides credentials. Production loads
VPNCTLD_CORP_DIAGNOSTICS_BASE_URL and VPNCTLD_CORP_DIAGNOSTICS_TOKEN_FILE once.
Missing/invalid config disables this integration only. Accept HTTPS, or HTTP for
literal private/loopback IPs only. Reject URL userinfo/query/fragment and invalid
32..512-character ASCII bearer. Disable redirects and ambient proxies; bound
connection to 3 seconds, whole request to 10 seconds and response to 256 KiB.
Forward only service bearer to /internal/corp-diagnostics/reports[/ID[/retry]],
never browser credentials, forwarding headers or arbitrary destinations.

## Whitelisted data

List: {schema:1,reports:[SUMMARY],next_cursor:ID|null}.
Detail: {schema:1,report:SUMMARY,analysis:RESULT|null,provenance:OBJECT|null}.
Retry: {schema:1,state:"pending"}.

SUMMARY fields: report_id, received_utc, bytes, device_label (bounded plain text
or null, explicitly client-reported), analysis_state, verdict, summary_ru, model,
updated_utc. analysis_state is received/pending/running/ready/failed/unavailable.
verdict is nullable problem_found/no_problem_evidenced/insufficient_data. Model,
summary and update time may be null before analysis. No raw logs, identity hashes,
local paths, credentials or archive/download links; discard unknown fields.

RESULT (maximum 24 KiB) has schema "corp-diagnosis/1", assessments (at most four),
confirmed/probable/unknown findings, chronology, owner_explanation (at most 2000
characters), next_steps_ru (at most three), public_analysis. Assessment fields:
scope (update_delivery/client_runtime/tunnel_and_policy/evidence_quality), verdict,
confidence (high/medium/low), time_scope (current/unknown), explanation_ru, evidence.
Finding fields: statement,time_scope (current/historical/unknown),evidence.
Chronology fields: statement,evidence. Evidence is exactly one of
{kind:"log",file,line}, {kind:"operator_fact",field}, {kind:"packet",field}.
Public analysis: version:1,state:pending/ready/unavailable, optional message_ru
and message_en (at most 300 Unicode characters and UTF-16 units). Ready requires
one message. The upstream publisher owns reference resolution, current-vs-history
semantics, secret sanitization and its exact public-text oracle. The bridge
validates typed structure/bounds and strips extra fields at every nesting level.

Provenance whitelists nullable bounded strings: requested_model, returned_model,
prompt_sha256, input_sha256, run_id, started_utc, completed_utc, prompt_version,
status. Digests are lowercase SHA-256 hex. Never silently substitute models.
UI presents processing state, client-reported device, receive/update times,
conclusion, assessments, confirmed/probable/unknown findings, evidence, chronology,
provenance and retry when no active job is shown. Existing valid results remain
visible while upstream owns retry retention/generation safety.

## Verification checklist

- Independent spec tests cover constructor validation, gates, safe forwarding,
  bounded responses, nested whitelist, retry origin/CSRF and safe errors.
- Local rustfmt, diff whitespace and JavaScript syntax checks; compilation,
  full tests and CI deferred under the control-plane host publication exception.
- Independent diff review before commit; production activation additionally
  requires exact-source CI and authenticated upload-to-inbox verification.
