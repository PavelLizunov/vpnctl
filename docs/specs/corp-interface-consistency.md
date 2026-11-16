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

Independent diff review found that moving phone history outside its editor
requires its controls to join the same busy/ready/stale disabling scope.
Confirmed before correction; keep reload available for stale recovery.
Rendered verification and static activation remain in progress.
