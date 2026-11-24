# VPNRouter source-backed diagnosis

The Standard desktop client requests this read-only operation explicitly. It derives the build commit from installed assembly metadata and sends one classified crash or manual connection failure. No raw report, URL, goal, paths, account name or tool controls are inputs.

## Wire contract

POST /api/v1/assistant/vpnrouter/source-diagnosis uses the same subscription/device authentication and JSON transport as /step. Strict JSON fields:

    {"schema":1,"locale":"ru","version":"2.51.0-r2","commit":"<40 lowercase hex>","platform":"windows","arch":"x64","crash":{"fatal":true,"fault":"io","area":"settings","signal":"none"}}

Use existing snake_case crash enums from /step. Platform is windows, linux or macos. Architecture is x64 or arm64. Locale is ru or en. Version is a bounded numeric three-component release string with optional -rN. The service must match version, commit, platform and architecture against a trusted, locally provisioned release catalog. An authorized valid request for an unregistered build returns HTTP 200 with exactly {"schema":1,"result":{"operation":"unknown_build"}}. For a registered build with unrecognized crash evidence or no matching excerpt the exact result is {"schema":1,"result":{"operation":"insufficient_evidence"}}. Neither case calls the provider. Old gateways may return 404. Authentication errors, limits and unavailability use existing HTTP conventions.

A difficult connection failure can occur while the desktop application stays open. The same explicit read-only operation then substitutes one `connection` string for the `crash` object. Exactly one evidence field is required. Null, both fields, extra keys and unknown codes are invalid. The four connection codes are `startup_timeout` (engine startup deadline), `readiness_timeout` (dataplane readiness deadline), `unexpected_stop` (engine stopped during the attempt) and `tun_busy` (adapter already owned). The client obtains these from a completed manual attempt in the same process and presents the observed event and local time before sending it. A later attempt or success clears its predecessor. The provider receives the observed connection code as such, with relevant source slices; it does not receive a fabricated exception or fatal crash. The response shape and trusted build match are identical.

Successful 200 reply (exact fields at every level):

    {"schema":1,"result":{"operation":"source_diagnosis","hypothesis":"...","basis":"...","confidence":"low","check":"view_connection_status","citations":[{"commit":"<requested commit>","path":"VPNRouter.Core/Services/Example.cs","first":15,"last":23}]}}

Hypothesis and basis are plain single-line text each 1..384 UTF-8 bytes. Confidence is low, medium or high. Check is one of view_connection_status, review_settings, view_last_crash. Desktop renders that check as localized advice. Citations count is 1..3, distinct; each must exactly match one supplied public source excerpt, with positive inclusive line numbers, length <= 48, revision equal to the installed commit and normalized repository-relative .cs path under VPNRouter.Core/ or VPNRouter.App/. The server rejects extra fields, invented lines and unknown selections; client validates the response shape and renders citation text without following URLs or executing commands.

## Source provenance and resource limits

Catalog provisioning belongs to release operations. Extract selected excerpts from committed Git blobs on an independently verified exact release revision, recording version and supported platform/arch pairs. Review the selected public lines for disclosure to the provider and scan their decoded text with Gitleaks before publishing. An empty catalog is invalid. Load locally trusted data from a service-controlled path; never accept model- or client-specified paths, URLs or shell. Cap file size, input/output, number and size of excerpts and provider concurrency/requests. Use a distinct account quota for this endpoint and a read-only provider prompt. At most one provider call per account and two per daemon can be in progress. A busy slot returns HTTP 429 with `{"error":"diagnosis_busy"}` and `Retry-After: 1` before charging the account quota. Exhausting the rate limit returns `quota_exceeded`. If no mapped source is available, report it explicitly. Keep credentials and private data out of provider requests and logs.

## Verification

Check known and unknown builds, differing commits for the same version, wrong arch, malformed or extra fields, forged/out-of-range citations, provider actions and credential-bearing text, quota, service unavailability and backward compatibility with /step. Verify opt-in and absence of settings/process mutation on the installed product.
