# Corp interface consistency

## Intent and invariants

Make Sites, Telephony and Diagnostics behave as one task-oriented interface.
Keep the current palette and all policy, authentication, diagnostics and deletion
contracts. The owner requires presentation-only delivery without rebuilding the
Windows application or server and without broad Cargo test runs.

The existing HTML loads corp.js on all pages. Bootstrap the common shell there
and deliver the four existing CSS/JS assets through the edge static override.
Do not change Rust, migrations, credentials, production rules or the update feed.

## Confirmed problems before changes

- Diagnostics omits telephony from its navigation; returning loses the section.
- Telephony retains site-specific header and draft status alongside phone status.
- Related save/apply controls have different placement and confirmation flows.
- Site chrome pushes the first rule below the initial 1280x800 viewport.
- Phone rows retain wide minimum columns until a late mobile breakpoint.
- Notes controls are hidden inside unrelated help or indistinguishable disclosures.
- Route terminology and list/search/pagination patterns differ between editors.
- Diagnostics search covers loaded reports without a sufficiently clear next step.

## Interface contract

Use the same three navigation links, title area, spacing scale, typography,
field labels, control sizes, rule table, pagination and save footer. Preserve
independent site/phone drafts and revisions. Hash links identify Sites and
Telephony; Diagnostics uses its existing route. Navigation never saves a draft.
Use the same direct/VPN wording and explicit interruption consent. Notes remain
optional and discoverable without making empty comments a default task.

Common browser helpers live in corp.js and are available before phone and
diagnostics scripts: node(), field(), routeOptions, createPager(id, onPage),
confirmAction(options). Rule editors share CSS vocabulary and a ten-row page.

## Verification and delivery

Inspect all three rendered sections at desktop, intermediate and narrow sizes.
Check keyboard focus, long values, empty/search states, pagination and unsaved
navigation. Run JavaScript syntax, static design scan, scoped browser checks and
independent diff review. Do not publish real rule changes or delete owner reports
for layout acceptance. Keep screenshots free of credentials and raw logs.

Use an exact committed static release with prior asset/config archive, validate
Caddy and reload it without restarting vpnctld. Compare live asset bytes and
recheck the actual pages. Roll back by restoring the prior static root/matcher.
No build or package workflow is dispatched. The current mandatory PR workflow
compiles Rust even for assets, so retain the branch and review evidence without
opening a build-triggering PR under this explicit no-build instruction.

## Outcome

Delivered static source e44f9087888c1eb765bf9d26580deea3c0dab9aa. All four
public asset hashes match that source; Caddy reloaded with the same PID and
vpnctld and compiled binaries were unchanged. Full previous edge configuration,
service capability and assets were permanently archived before each activation.

Sites, Telephony and Diagnostics were inspected at 1280, 800, 390 and 320 CSS
pixels with no horizontal overflow. Their navigation and typography match;
desktop rule filter labels align. The first desktop site rule moved from about
876px to 503px. Search, pagination, independent drafts, discard, explicit
interruption consent and diagnostics deletion cancellation were exercised without
publishing rules or deleting reports. Main and phone revisions remain 7, with
33 sites and 5 phone rules; both original reports remain visible.

Independent UX/source and mechanical assessments completed. The Impeccable
layout scan returned no findings; this is not a substitute for rendered review.
Independent diff review found the extracted phone history control scope issue;
it was recorded, fixed and verified with a browser-local simulated read conflict.
History disables while stale and reload remains usable. Rendered label/pagination
alignment and native dialog centering findings were recorded before correction;
the deployed native dialog is centered in the viewport.

All three JavaScript syntax checks and scoped secret scanning passed. No Cargo,
application build, packaging, model analysis or full test run was performed.
The reviewed source branch is published but not merged into main; the blanket
build-triggering PR workflow was not started under the owner's no-build scope.
Private receipts and screenshots are retained outside Git under
corp-interface-consistency-20261117.
