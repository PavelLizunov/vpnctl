# Corp rule categories

## Owner intent and authority

Use one Rules workspace and a separate Diagnostics page. Sites and Telephony
become ordinary editable categories, not hardcoded top-level tabs. The owner
explicitly requests removing notes from the UI and clearing current saved note
text. Preserve routing values/actions, private identity and existing reports.
No compiled rebuilds or broad test runs are authorized for this web work.

## Persistence contract

Categories are server-persisted metadata in the existing Python receiver,
independent of both signed routing feeds. Never encode metadata in comments or
localStorage. Each rule key is {source: site|phone, value: canonical address}.
Changing category never changes the rule's source or routing action.

All metadata requests use POST /api/corp/categories/state or /save, with JSON
and the existing X-Corp-CSRF. The edge captures a bounded request body, replaces
it with harmless normalization JSON, calls the existing POST authorization
route, and restores the body only after HTTP200. The inner hop strips browser
headers and injects the existing private service capability and expected byte
length. Preserve exact Origin/session/CSRF/verified egress checks.

State is {schema:1, revision:int, categories:[{id,name}], assignments:[{source,
value,category:id|null}]}. Revision0 defaults to sites/Sites and telephony/
Telephony. Save body is {expected_revision,categories,assignments}; compare and
swap, increment only on actual change, reject duplicates/unknown fields and
invalid references. At most32 categories,576 assignments,256KiB body; names
are nonempty trimmed Unicode text up to64 code points/256 UTF8 bytes without
controls. Rule values are nonempty bounded ASCII without controls. IDs match
[a-z][a-z0-9-]{0,39}. Preserve an explicit null assignment when a category is
deleted. Missing assignments fall back to the matching surviving default.
An attempted revision increment beyond the JavaScript safe integer limit is400;
stale expected_revision is409. A no-op at the maximum revision remains valid.

Only an authenticated current corporate session reaches this one-corporation
metadata namespace; current auth generation is checked by the existing gate.
No automatic namespace reset or cross-organization interpretation is added.

## Interface

Top navigation Rules/Diagnostics. Desktop category rail; mobile labelled picker.
Show All, default/custom categories, Uncategorized and Add category. Support
create/rename/delete; deletion moves rules to Uncategorized, not policy deletion.
Rule list shows address, compact native radio direction group and row actions.
Move selected rule to a category without publishing a routing revision.
No note field, note toggle, note column or note-based search. One bottom pager
with range, previous/page/next; page bottom padding and plain history disclosure.

Keep main and phone revision CAS independent when changing actual routes. Clear
comments through ordinary authenticated policy save with next_connection after
full snapshot/archive; verify all addresses/actions/counts unchanged afterward.

## Verification

Focused Python metadata boundary/CAS/persistence tests, JavaScript syntax,
independent diff review and rendered desktop/mobile inspection. No Rust/.NET
build, packaging or broad suites. Exercise category persistence in a second
browser session; validate failed auth/CSRF and stale metadata save. Do not leave
test categories or change owner routes. Archive originals before deployments.

## Outcome

Independent editor review found three issues before activation: preserve initial
revision0 publication eligibility; prune abandoned draft assignments while
retaining live rule assignments; retain category names and the form on failed
saves. Record before corrections. Metadata boundary tests15/15 pass after
clarifying overflow400 versus stale409. Current comments cleared through the
ordinary API: main7->8/33rules, phone7/5 unchanged; addresses/actions identical.

Candidate browser acceptance passed real UTF8 category create/rename/move/delete,
separate incognito-session persistence, stale409 and invalid-CSRF403 checks.
Test metadata was removed: revision6 contains the two defaults and no explicit
assignments; main8/33 and phone7/5 routing data remained unchanged. Draft addition
and discard produced no metadata or routing write. Isolated browser mocks also
passed first revision0 publication and partial site-success/phone-conflict draft
retention. Rendered widths320/390/800/1000/1280 had no horizontal overflow.

The receiver is live from VPNRouter commit40b3fc26997f665c7435fc9ad248e17ffd3de469.
Source publication uses scoped branches without a PR because opening the current
workflows would trigger the owner's forbidden compiled builds. No Cargo/.NET,
installer or broad CI gate ran. Final static activation and fresh-page evidence
are retained privately under corp-rule-categories-20261117; candidate injection
alone is not proof that a static release is live. Historical signed rule versions
remain immutable; only current comments were cleared.
