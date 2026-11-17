# Independent corporate companies

## Owner intent and present constraints

Each company is one existing vpnctl subscription user, selected by username,
with its own portal password, signed site and phone rules, categories and
reports. The operator remains one owner; this is not multi-operator RBAC.
The owner confirmed this model on2026-11-17. Existing company data must survive.
The current instruction forbids compiled rebuilds; the delivered VoIP exception
is complete. This record prepares a concrete backend change; it does not claim
multi-company support is implemented or deploy a database migration.

## Confirmed defects

The legacy navigation points to relative /admin/corp on HTTP vpnctld. The
operator subtree deliberately accepts only its configured HTTPS authority;
HTTP opens a400 whose recovery link repeats the request. Production's canonical
HTTPS route instead reaches the expected401 operator challenge. Preserve the
Host, exact Origin, duplicate-header, operator-auth and CSRF checks.

The database is singleton by design:0071 settings CHECK(id=1), globally keyed
site revisions, global sessions and egress;0074 singleton phone floor and
journal. Store/portal/operator methods select one record. Security changes and
user triggers can revoke all sessions. The receiver supports many upload
identities but one configured inbox capability; categories already use that
capability's identity hash. Adding a username selector alone cannot isolate data.

## Immediate no-build entry repair

Render deploy/corp-operator-entry.html with the configured operator HTTPS URL,
never an arbitrary request Host or query value. Mount that file only at the
legacy HTTP /admin/corp entry in the existing Tailscale Serve HTTP handler.
It performs a fixed HTML refresh and offers an explicit HTTPS link. It does
not proxy forms or confer operator access. Preserve all existing proxy routes,
the separate HTTPS origin, API listener, credentials and running daemon.
Archive the complete Serve configuration and any prior file before changing it.
Verify the real legacy browser navigation arrives at HTTPS, unauthorized access
remains401 and authorized read-only GET succeeds. No Corp form is submitted.

## Target data and API boundaries

1. Add an immutable internal company ID, with unique existing user_id and
   policy_id. Username selects the existing subscription; it is not a storage
   key, so renaming a user cannot orphan data. Retain company history when its
   subscription is deleted; disable only that company.
2. Key site and phone journals by(company_id, revision); keep per-company site
   and phone floors, auth_generation, config_version, credentials and password.
   Key egress proof by(company_id, server_id, ip). Scope scheduled probes, job
   status, fingerprints and completion authority to the intended company;
   actual helper resource limits can remain shared.
3. Sessions keep globally unique token hashes plus company_id. Every session,
   CSRF check, rule/category/report operation and expected-revision comparison
   resolves an authenticated company before reading or writing. Security changes,
   user deletion/disable, retention and audit targets affect that company only.
4. Browser login accepts username and company password. Do not publish a company
   list on the unauthenticated site. Check the selected company's enabled user
   and verified VPN exit before admitting the login/session. Shared VPN exit IPs
   are an additional access condition; they never select a company. A session
   cannot switch company from a query parameter or a browser-supplied header.
5. Preserve existing reader URLs. Resolve their company from a unique verified
   reader capability; reject ambiguous matches. Do not introduce a fallback to
   the first company. Capability overlap and signing-key rotation stay scoped.
6. Replace the single diagnostics bridge capability with per-company trusted
   capabilities bound to receiver upload identities. Preserve the existing
   namespace. Scope report list/detail/retry/delete, analyzer inputs/results,
   quotas and categories; a browser-supplied identity never grants authority.
   The edge must pass company identity only from a validated server context or
   a matching private service capability, not from a caller-chosen username.

## Operator and client experience

The Corp operator entry becomes a company list: company label, subscription
username, access state and rules status; Add company selects an existing user.
Each detail page owns password rotation, readers, keys, export, verified exits,
site/phone revisions and session revocation. Display the selected company on
all detail screens and destructive confirmations. Reuse the established admin
layout rather than create another independent visual shell.

The public portal keeps its existing Rules/Diagnostics workspace. After login,
show the company name/username beside the account action; rules/categories and
reports belong to that session only. Existing company bookmarks stay usable.
New-company private provisioning must include that company's policy reader,
public trust and diagnostic identity; never reuse the first company's bundle.

## Migration and compatibility

Apply a new migration atomically; never rewrite already accepted migrations.
Copy the current binding, floors, credentials, egress, session ownership and
all history into one company without reissuing any policy ID or changing any
signed payload/envelope byte. Preserve current namespace/category revision,
reports, passwords, keys, reader tokens and client replay floors. Existing
sessions can be attributed to that one company during migration. Keep existing
signed wire formats and legacy reader endpoint behavior for their own token.

Before activation take a consistent database/service/receiver backup. Exercise
restore before accepting the migration. Never lower delivered revision floors
or roll back only one component after a new policy has been published.

## Acceptance and implementation stages

1. Implement migration, scoped inventory methods/triggers and independent
   spec-derived storage tests. Compare migrated envelopes byte-for-byte.
2. Implement operator selection, browser username/session/CSRF selection,
   reader lookup and company-scoped egress/probe lifecycle. Keep old clients
   reading exactly their current signed policy under their existing token.
3. Implement trusted per-company receiver capabilities, categories and reports;
   preserve the current private namespace and the existing interpreted worker.
4. Run narrow isolation/migration tests and the required exact-SHA server gate
   after a server-build exception is explicitly granted. A Windows build is not
   a prerequisite unless actual client compatibility inspection finds a change.
5. Rehearse two synthetic companies sharing the same VPN exit: same revision
   numbers, independent rules/passwords/readers/categories/reports. Reject wrong
   company password, session/CSRF reuse, foreign reader capability access, report
   detail/retry/delete and category writes. Revoking/deleting company A must not
   affect B. Verify subscriber rename/disable/delete and concurrent CAS saves.
6. Activate one compatible server/receiver update, then inspect both companies
   through the real browser and verify current clients and protected state.

No company is created and no production credential or routing policy is changed
by this preparation. Current production supports only the existing company.

## Verified outcome

The no-build legacy entry is live from49ae420c. Actual browser navigation from
HTTP vpnctld/admin/corp arrives at the canonical HTTPS operator page; absent
authentication remains401 and an authenticated read-only GET returns200 with
current controls. Only the HTTP entry was added to Serve: existing HTTPS and
other proxy handlers, daemon PIDs and credential files were preserved. No Corp
form was submitted, no compiled build ran and no build-triggering PR was opened.
The source branch is published; it is not merged into main.

An independent Terra research pass confirmed the singleton/session/namespace
findings and proposed migration boundaries. This was research, not an independent
implementation review. Multiple-company implementation remains pending a specific
server-build exception to the owner's existing no-rebuild instruction; no second
company has been created or reported as ready.
