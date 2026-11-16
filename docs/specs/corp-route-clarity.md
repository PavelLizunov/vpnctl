# Corp route labels

## Intent and invariants

Make the rules editor understandable to an owner who needs to distinguish sites
that bypass VPN from sites that use Corp VPN. This changes presentation only:
direct/proxy values, request shapes, ordering, publication, authentication and
all stored policy, subscription and diagnostic data remain unchanged.

Design read: a working rules editor for nontechnical corporate users, following
vpnctl's shared paper/ink/accent palette and typography. ENERGY 1,
RHYTHM 1, MOTION 1. The owner's requested distinction takes priority over generic
visual style rules; apply anti-slop in DURING mode, then report measured gates.

## Interface contract

- Owner steering after the first browser pass: Corp must inherit vpnctl's
  interface so the relationship is visible. Reuse the actual shared theme
  stylesheet and its paper/ink/accent/type tokens; show vpnctl and Corp in the
  common masthead. This supersedes preserving the separate green Corp palette.
  Keep a readable, mobile-sized portal rather than importing operator-only
  navigation or controls. Theme/font stacks are shared; no font download or
  theme-toggle capability is implied.
- A brief explanation identifies "Напрямую" as ordinary internet without VPN
  and "Через VPN" as the corporate server. Clarify that Corp VPN stays enabled.
- The add-rule preview and every existing rule show the same native route
  control plus a visible, associated explanation of its currently selected value.
- Reuse the shared neutral styling for direct and vpnctl accent for
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

First source 20830876 passed the real browser scenarios, including contrast,
keyboard changes, preview reset and all three widths. The lead inspected the
320/1280 screenshots. This is prior-source evidence: the owner's subsequent
request for inherited vpnctl styling requires fresh review/browser acceptance.

Theme integration review identified that the diagnostics browser fixture also
pins the exact CSS payload. It must expect the same shared-theme-plus-portal
composition as the editor fixture; record this before adapting that source
assertion. Keep exact-byte matching rather than weakening it.

Owner steering also asks for proportional checks. Source inspection found that
the check job repeats fmt/clippy/test/deny through just ci while their dedicated
jobs run concurrently. Remove only that aggregate repeat; retain cargo check,
all four dedicated Cargo jobs, project-map and CSS-bundle generated-file checks,
browser coverage and candidate construction. Local just ci remains available.
No path filter or false-green substitute is introduced. Each canonical command
still runs on the candidate; the aggregate is no longer a second requirement.
