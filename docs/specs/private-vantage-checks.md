# Private network vantage checks

## Intent and invariants

Provide an operator-visible, private check of each configured VPN server from controlled network vantage points. This private sweep does not send addresses or credentials to third-party checking services. The owner's 2026-11-05 request adds a separate targeted public-IP [Cheburcheck action](cheburcheck.md); it supersedes the earlier global exclusion without changing this sweep. A TCP connection confirms only transport reachability, never a VPN handshake or unblocked status; UDP and end-to-end transfer require protocol-aware checks and must remain explicitly unverified if unavailable. Do not change VPN configurations, subscribers, routes or existing assurance/alert semantics. Reuse trusted SSH/host-key configuration and existing inventory; no arbitrary targets or command injection.

## Interface and data contract

Show source, server, transport/port, last check time, latency and precise result in the web UI, including unavailable and stale states. Use only configured servers and effective protocol ports. Failed or offline vantage checks must not be treated as server blocks. Results from different sources must not overwrite existing protocol assurance rows. Provide an operator-triggered check; background operation if practical without affecting availability. The first mandatory vantage is the controller's direct network; other controlled machines can be added only where their access and network path are established.

## Verification

- Unit/integration tests cover success, timeout/refusal, unavailable vantage and stale/no result, protocol transport semantics, target validation and UI escaping/authentication.
- Check actual user-facing result on production after deployment; independently validate at least one direct network comparison.
- Existing VPN operation, credentials and configuration remain unchanged; this private sweep makes no public Cheburcheck requests.
- Document retained limitations, exact source of each observation, and upstream code/license if incorporated.

## Decision and progress

Verdict: Extend existing VPNctl monitoring and protocol registry. Cheburcheck's public MQTT probes disclose targets to its operator and its generic TLS test is not a VPN handshake; no upstream code was copied. A manual, bounded controller-only TCP sweep stores ephemeral results separately from existing assurance. Independent review identified stale results after failed sweeps; results are cleared at start and on failure. The initial implementation at c6b99ec passed GitHub CI and is deployed; an authenticated production sweep returned six successful TCP and seven unchecked UDP rows. End-to-end VPN/UDP data-path tests are distinct from TCP checks.

## Design and implementation refinement (owner request, 2026-11-01)

- Outcome: replace the repeated flat list with a readable comparison by node and TCP port, source columns on desktop and labelled stacked results on narrow screens. Put measured TCP totals and last-run time first; separate unsupported UDP ports in a disclosure. Use existing editorial typography, theme tokens and native controls (calm/utilitarian, energy 1, rhythm 2, motion 1).
- Distinguish self checks, missing target addresses and unavailable source measurements; never style them as target failures. Display server names with stable identifiers where useful. Keep the caution that TCP is not VPN or censorship verification, with technical limits in a concise expandable note.
- Separate the existing module into state/orchestration, probing and rendering. Use typed source identity and one snapshot for run metadata/results/rotation rather than display strings and unrelated atomics. Preserve auth/CSRF, pinned SSH, constant remote program, timeout and concurrency caps, batch coverage, and waiting for all workers. Do not change shared SSH or VPN configuration.
- Run feedback must be visible and update without repeated manual reloads; retain an ordinary form/manual refresh fallback. Empty, running, failed, partial and stale states are explicit. No external services or new production dependencies.
- Verify pure rendering/state tests, auth/CSRF and existing tests, CI and independent diff review. Exercise the real page at desktop/mobile widths in light/dark themes, check keyboard controls, overflow and the actual run-to-result flow. If browser access is unavailable, record that limit rather than claiming visual verification.

## Monitoring entry follow-up (owner screenshot, 2026-11-01)

The reachability link has an isolated inline 44px content-box minimum while the adjacent probe button is compact, so it renders as a tall box with top-aligned text. Scope: only the monitoring header action group. Remove the one-off inline height and apply a shared scoped inline-flex/border-box treatment to its link and button: 32px desktop height, centred labels, 44px mobile touch targets and wrapping without overflow. Keep both URLs, POST/auth/CSRF, labels, and all other admin buttons unchanged. Verify the original height mismatch and the fix in Chromium at desktop/mobile widths, keyboard entry navigation, CI, and the actual deployed monitoring page.

## Additional controlled network sources

Extend the manual sweep to use inventory-managed servers as remote SSH vantage points, independently identified in each in-memory result. Reuse deploy-key, pinned host fingerprint, jump-host handling and inventory-derived IP/ports. A remote source never tests itself: that result is unavailable, not success or failure. SSH, missing runtime, incomplete or malformed probe results mean that source is unavailable, not that the target is blocked. UDP remains unchecked. Run a fixed probe program with typed addresses and ports passed as data, not interpolated into shell commands; cap inputs, time and concurrency. Keep results separate from quality score, assurance, alerts and persisted health measurements. Remote server observations can be useful controls, but do not represent a Russian residential network or an independent end-to-end VPN test. Each run covers a rotating batch of up to 32 target rows and four concurrent server sources; repeated runs cover all batches while inventory remains stable. The interface displays only the latest batch, and the rotation resets on restart. The sweep holds its lock until all local SSH workers exit; subprocess stages have separate timeouts, so their sum is not a 60-second global deadline. A remote process also has its own time limit.

Verification: exercise source identity, self exclusion, unavailable source, TCP outcomes, UDP and parser validation; CI and independent review; after deployment compare authenticated UI results with independent probes from at least one accessible remote source. Production baseline c6b99ec is deployed and health 200. Its initial failed Ubuntu 26 build was rolled back and replaced after Ubuntu 24 x86-64 baseline passed an isolated no-AVX target smoke; see incident INC-1524. Mac mini routes target traffic via utun99 and Omarchy SSH is unavailable.
