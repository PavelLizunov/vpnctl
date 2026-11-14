# Corp policy portal

## Intent and invariants

Add the approved corporate site-rule portal at `admin.corp.ninitux.com` to
vpnctld. This is one fixed Corp subscription bound to an existing UserId, not a
general tenancy or operator-role redesign. The owner approved implementation on
2026-11-14. Base: `cc071d3143886ccf1cd0869011a694ab67882181`; PR targets `main`.
The VPNRouter client is green at `b874f33faea7daf464ada1e5cf73750bdfd573a2` in
[VPNRouter #675](https://github.com/PavelLizunov/VPNRouter/pull/675), targeting
`business`. No merge, release, deployment or activation is authorized here.

- Browser access requires an eligible Corp VPN server's verified exit IP,
  followed by a separate Corp password. Check eligibility on every protected
  request, including after login. IP access alone is not subscription ownership.
- Canonical Corp host dispatch never falls through to operator routes, even
  when Corp is disabled or the requested path is unknown. Reader credentials,
  Corp browser sessions and operator sessions are separate capabilities.
- Reader GET uses a dedicated bearer credential and remains usable while the
  client's VPN is stopped. It cannot publish, authenticate a browser or select
  an organization through query/path parameters.
- Complete signed policies replace editable seeded domains, including deletions
  and an empty list. UIS/telephony, process rules and the portal's VPN direction
  stay protected. Both Business routing modes consume the same signed contract.
- Default publication timing is next connection. Apply-now needs explicit
  interruption confirmation. The portal reports publication, not application
  by every client. Offline clients fetch later.
- SQLite publication, monotonic revision and audit commit together. Credential
  rotation and content restore never reset policy identity or revision. Restore
  publishes a new greater revision. Preserve history after user deletion.

## Interface and data contract

The wire format and shared fixtures follow VPNRouter
`docs/business-policy-wire-v1.md` at the exact client SHA above. Backend public
helper APIs and persistence behavior are specified in
`corp-policy-wire.md` and `corp-policy-store.md` before their implementation.

The browser flow is VPN instruction -> password -> searchable site list.
Choices are "Без VPN" / "Через VPN". Adding a pasted URL first shows its
normalized hostname. Invalid input cannot partially publish. A signed empty
managed list is distinct from a failed or empty HTTP response.

The fixed Business eligibility profile follows the issued client: renderable
direct VLESS variants only, with disabled-user, grant, protocol visibility,
suppression and detour restrictions from current subscription inputs. Browser
User-Agent never changes this profile. Resolve the request address through the
trusted-peer path, normalize mapped IPv6, and deny missing/ambiguous evidence.
Verified egress mappings are explicit; inventory/DNS addresses and employee
source addresses never populate them automatically.

Use separate revocable server-side sessions, exact HTTPS Origin plus session
CSRF on writes/logout, host-only Secure/HttpOnly/SameSite=Strict cookies and
bounded password work. Serve escaped responsive Russian markup with a
restrictive CSP. Corp request bodies have a scoped 64 KiB bound; legacy limits
remain unchanged. Operator setup, revocation, credential rotation, egress
verification and provisioning export have authenticated operator web actions.
Do not expose signing private keys/passwords in the client export or logs.

## Verification and delivery

1. Storage/wire foundation: exact public APIs, spec-only independent tests,
   independent diff review, formatting, generated map and secret checks.
2. Portal integration: host/auth/IP/CSRF isolation, current eligibility,
   password/session revocation, publication conflicts, history/restore,
   normalized editor UX and operator provisioning controls.
3. CI: all five canonical Cargo gates, `just ci`, applicable HTTP/UI and
   compatibility suites at the exact PR SHA. No local compile/build/package/
   full tests or SDK installs; use the publication exception in
   [agent-workflow.md](agent-workflow.md). Draft until the required checks pass.
4. Prepare trusted client provisioning migration, DNS/ingress, verified egress,
   backup/restore and rollback runbooks. Activation and shipped-client live
   verification remain explicit later operations, not inferred from CI.

## Outcome

Implementation in progress. Client CI was independently checked: 13 successes
and three expected skipped manual delivery jobs at `b874f33`. Backend source
reconnaissance is recorded in [corp-policy-findings.md](corp-policy-findings.md).
Backend compilation, tests, UI and live verification have not run.

The first backend publication contains wire signing/validation and durable SQLite
storage only. It does not register HTTP routes or enable the portal. Independent
diff-only wire review returned no findings. Storage review found the missing
payload/envelope/digest binding; the lead tightened persistence validation and
the contract, then source-checked the bounded correction. Findings remain open
pending exact-head CI, as recorded in the ledger.

An independent implementation-blind test writer authored 61 tests: 28 wire,
32 storage and one genuine P-256 signing/storage/reopen/verification roundtrip.
They cover shared client vectors, domain limits, replay/concurrency, credential
and user revocation, audit rollback, counter exhaustion and inconsistent exact
publication bytes. No tests have been executed on the control-plane workstation.

Local publication checks on 2026-11-15: `cargo fmt --all`, format check,
`git diff --check`, generated project-map and CSS checks, metadata validation
(`--locked --offline --no-deps`) and gitleaks 8.30.1 whole-tree scan all exited 0.
The copied wire/domain/seed/PSL fixtures match the pinned client bytes. Offline
dependency fetching exited 101 because `russh v0.65.1` is not cached; it was not a
compilation/test attempt. Check, Clippy, test, deny and `just ci` are not run
locally under the control-plane publication exception and must pass in GitHub
Actions before the next product block. The PR remains draft.

Next: isolated HTTP/browser/operator surfaces and verified-egress eligibility,
then client provisioning and activation runbooks. Current source and CI evidence
does not establish a live site or migrated clients.

First CI at `fca36dfe2535082f80d7fd43f811cdd2c8b89159` passed compilation,
formatting, dependency policy, secret scanning, static musl release and Docker
SSH suites. Clippy stopped on a manual divisibility predicate; the storage suite
passed 31 of 32 tests and exposed acceptance of a noncanonical CSRF token. Both
findings were recorded before correction. The follow-up keeps the original
tests, uses the standard divisibility predicate and strictly validates the
32-byte URL-safe CSRF encoding. Its independent diff-only review returned no
findings; formatting, generated files, whitespace and diff secret checks pass.
Fresh exact-head CI is required. Other test suites after the failed inventory
suite are not claimed as executed by the stopped `cargo test` job.

At `e3554372b9c95e0ba046dbeb590ebdbbe461da42`, Clippy and all 32 Corp storage
tests passed. The existing inventory transaction guard then rejected the new
deferred current-policy read transaction. The one-line follow-up adopts the
repository's `BEGIN IMMEDIATE` convention while preserving the credential and
publication snapshot; no test is changed. This uses the documented single-surface
small-hotfix review exception. Full exact-head CI remains required.
