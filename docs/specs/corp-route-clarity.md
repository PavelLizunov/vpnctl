# Corp route labels

## Intent and invariants

Make the rules editor understandable to an owner who needs to distinguish sites
that bypass VPN from sites that use Corp VPN. This changes presentation only:
direct/proxy values, request shapes, ordering, publication, authentication and
all stored policy, subscription and diagnostic data remain unchanged.

Design read: a working rules editor for nontechnical corporate users, following
the existing quiet green/neutral palette and system typography. ENERGY 1,
RHYTHM 1, MOTION 1. The owner's requested distinction takes priority over generic
visual style rules; apply anti-slop in DURING mode, then report measured gates.

## Interface contract

- A brief explanation identifies "Напрямую" as ordinary internet without VPN
  and "Через VPN" as the corporate server. Clarify that Corp VPN stays enabled.
- The add-rule preview and every existing rule show the same native route
  control plus a visible, associated explanation of its currently selected value.
- Reuse the existing neutral styling for direct and existing green accent for
  VPN. This aids scanning without adding colors; the text must carry the same
  distinction without color. No new animation, pills, icons or decorative panels.
- Route descriptions and styling update immediately when the selection changes,
  including keyboard changes, and remain correct after search and rerender.
- Keep native keyboard selection, visible focus and 44px minimum controls.
  New text must wrap without horizontal overflow at 320/420px and desktop width.

## Verification and delivery

Extend existing CI browser scenarios to exercise both selections in the preview
and list, keyboard changes, rerender and retained publication payloads. Measure
contrast on the modified controls and explanations and inspect screenshots.
Existing save, conflict, retry, history, session-loss and diagnostics checks remain
applicable. No new public API or database migration is introduced.

Before committing, obtain independent diff-only review. Use the control-plane
publication exception: format/static/generated-file/secret checks locally;
compilation, full Cargo gates, just ci, browser scenarios and candidate packaging
run only in GitHub CI at the exact SHA. Deploy only the accepted candidate via
deploy.sh, preserve protected state and verify actual served UI. Rollback uses
the previous binary/assets; no state restoration or Windows operation is needed.

## Outcome

Implementation review found that add-site resets the native value to direct
programmatically; its new explanation and visual state must reset in the same
operation. Recorded before correction; cover adding a proxy rule then opening
the next preview so a stale VPN explanation cannot survive.

Pre-publication checks also identified the expected generated Rust LOC inventory
delta and the existing HTTP copy assertion for the old "Маршрут" heading.
Regenerate inventory and update that copy assertion to the requested wording;
retain all authentication and payload assertions unchanged.

The editor now pairs native route choices with associated explanations in both
the preview and existing list. The preview resets its explanation with its value
after adding a site. Browser scenarios cover keyboard selection, search rerender,
the next preview, unchanged complete publication payloads and 320/420/1280 layouts.

Pre-publication results: formatting, JavaScript syntax, generated inventory,
whitespace and redacted secret scan pass. Independent diff-only review returned
no findings. The narrow existing HTTP copy pin was then reconciled by the lead;
no authentication assertion changed. Compilation/full tests/browser execution
are not run on the control-plane host and must pass at the PR's exact SHA.
Deployment and final measured anti-slop gates are recorded in the PR acceptance
receipt after CI; these source statements do not claim those checks already ran.
