# Corp policy portal

## Intent and invariants

Add the approved corporate site-rule portal at `admin.corp.ninitux.com` to
vpnctld. This is one fixed Corp subscription bound to an existing UserId, not a
general tenancy or operator-role redesign. The owner approved implementation on
2026-11-14. Base: `cc071d3143886ccf1cd0869011a694ab67882181`; PR targets `main`.
The VPNRouter client is green at `b4703c1228ae8f4b2ca12bccf084db4a25f55360` in
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

Client PR #675 is green at `b4703c1228ae8f4b2ca12bccf084db4a25f55360`:
13 applicable successes and three expected skipped manual private-delivery jobs.
The lead inspected all four retained Windows/Linux synthetic 340/420 px client
screenshots. Source/CI evidence does not establish a live portal, released
installer or migrated clients.

Backend foundation is green at `908bcacd9a1c2e41ddc058eb1d6aca47516d10da`,
run `43650614943`: all 11 checks succeeded. The canonical gate log records
exit code 0 for check, formatting, Clippy, tests, deny and `just ci`; static musl
and Docker SSH suites also passed. The foundation has 61 independently authored
spec tests: 28 wire, 32 storage and one signing/storage/reopen roundtrip.
Earlier CI findings and their corrections are recorded in
[corp-policy-findings.md](corp-policy-findings.md).

The next publication adds the isolated Corp HTTP/browser surface and fixed
Business eligibility, following [HTTP](corp-policy-http.md) and
[eligibility](corp-policy-eligibility.md) contracts. It includes the Russian
editor, signed complete-list publication, history/restore, separate sessions,
and the independent read-only client capability. The binding remains disabled
until explicitly configured; this block adds no operator setup or activation.

Independent diff-only eligibility review returned no findings. HTTP review found
a timeout outside response hardening and a missing uncertain-publication state
for 408 replies. Both were recorded before correction: each host branch now
owns its timeout, Corp hardens the normalized timeout reply, and the editor
requires reconciliation after a publication timeout. The lead source-checked
these bounded corrections. There is no claim of an independent final-feature
review or of runtime verification for an unpublished diff.

An implementation-blind test writer added 51 tests: 32 HTTP and 19 eligibility.
They exercise real router login, signing, storage, revocation, limits, conflicts,
restore, expiry, current grants/configuration, fixed client selection and
fingerprint invalidation. A delayed body checks the 408 boundary. Synthetic
router page exports contain only selected security headers and scrubbed markup;
they support the separate CI browser interaction and narrow-width screenshot
job. Its scenarios include publication timeouts both before and after commit.

No builds, tests, browser rendering or SDK installations run on the control-plane
workstation. Local publication checks on 2026-11-15 exited 0: formatting and
format check, locked offline metadata, generated project map and CSS checks,
JavaScript syntax checks, workflow YAML parsing, working/staged whitespace and
gitleaks 8.30.1 over the complete staged diff. The independent browser-test review
identified missing WebSocket interception; the lead recorded and corrected it
before these final checks. All runtime gates for this HTTP block remain pending
exact-head CI. The PR stays draft. Offline Cargo dependency resolution
updated the SQLx dev-dependency lock entry, then exited 101 because russh 0.65.1
is not cached; it was not a compilation or test attempt.

Remaining implementation: authenticated operator web controls for setup,
password/reader/signer rotation, session revocation and protected provisioning
export; genuine fresh egress verification tied to the effective Corp connection;
trusted client provisioning/migration and ingress/backup/rollback runbooks.
Same-host TCP and UDP transport siblings must be covered by egress proof or by an
explicit portal transport constraint before activation. With no Reality flow
partition, the client can group WS/XHTTP with non-VLESS siblings for TCP too;
first-selected-VLESS eligibility alone does not establish portal egress.
No address is approved merely
because it appears in inventory, DNS or an SSH curl. Merge, release, deployment
and activation remain separate owner commands.
