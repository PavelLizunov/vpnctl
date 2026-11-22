# Spec: operator provisioning readiness and single-artifact delivery

## Intent & invariants

- The Servers page presents the add/connect wizard as the primary way to add a
  node. Register-only stays available as an advanced accordion; it never
  pretends to install the deploy key or deploy a config.
- A new web grant requires a fresh successful deploy-key SSH observation on the
  route vpnctld will actually use: direct, or the configured jump when present.
  Workload-only servers and servers without that proof are not grant targets.
- Existing grants, revokes, CLI grants and inventory imports are unchanged. A
  no-op re-grant remains idempotent even if the SSH observation has gone stale;
  only a genuinely new pair is gated.
- Delivery shows one recommended import artefact only when the user is enabled,
  at least one grant is renderable, deployment evidence exists, and the
  recipient host is not obviously local to the daemon. Disabled, zero-grant,
  empty-artefact and loopback/invalid states get an explanation and a web
  action instead of a dead link.
- Private, LAN, CGNAT and Tailscale-style origins are legitimate recipients.
  They keep one-click copy and receive a network-scope hint. The UI never
  asserts actual reachability from host syntax.
- In an applied mixed fleet, the primary artefact remains available for the
  applied nodes and the pending nodes are named explicitly. If every granted
  node is pending, no primary artefact is recommended.
- The recommended card passes the existing URL through byte-for-byte. It never
  edits `/sub`, `/api/v1/sub`, `/api/v1/app/config` or their responses. It does
  not promise that the subscription contains every grant; all existing client
  flows and per-server links remain reachable.
- The grant gate is web-only and deferred remediation works: inventory/CLI
  grants stay unchanged, and a later successful SSH check immediately enables
  web grants without a controller change.

## Interface / data contract

```text
grant_targets::GrantReadiness
  Eligible | WorkloadOnly | Unverified{route,failure} | Unknown{route}
  read(server) uses ssh_access_for_server(max_age = SSH_CHECK_INTERVAL*2)
  evaluate(server, role, status) picks direct when no jump, jump when configured

web grant mutation paths (new grants only)
  POST /admin/users/{uid}/grants/{sid}
  POST /admin/servers/{sid}/grants/{uid}
  POST /admin/servers/{sid}/grants          (user_id form)
  POST /admin/servers/{sid}/grants/_grant-all
  POST /admin/users                         (grant_all=1 -> skip unready)
  reject with 400 "no verified SSH deploy-key path ..." and the web check/push URLs

delivery readiness
  primary: subscription URL when present, else app-config URL
  renderable: at least one direct share link or AmneziaWG link/file on an
              APPLIED node in the plain token-subscription set (desktop policy
              filters and chain-only targets do not make the primary `/sub`
              recommendation; the chain card stays below)
  ready: !disabled && !servers.empty && pending_deploy_known && renderable
         && at least one applied node && recipient_scope(url).blocks_copy() == false
  recipient_scope: public | private | loopback | unspecified | invalid
    private (RFC1918, link-local, CGNAT/Tailscale, ULA, .lan/.internal):
      copy stays, network-scope hint is shown, no reachability claim
    loopback/unspecified/invalid: no copy, explanation + public-address action
  mixed fleet: applied nodes keep the primary item; pending nodes are listed
  copy: [data-copy-recommended] copies the exact textarea value and writes
        "Copied"/"Скопировано" into [data-copy-status]
```

## Verification checklist

- [ ] Servers page wizard precedes the register-only accordion and register-only
      is a secondary action with an explicit bootstrap caveat.
- [ ] Add-user shows ready/skipped targets and grant-all creates grants only on
      verified servers.
- [ ] Both user-side and server-side web grant paths reject unverified servers;
      jump-configured servers require the jump check; bulk grant-all rejects
      unverified but reports a no-op on already-granted users.
- [ ] Access tab omits the grant form for unverified servers and links to the
      SSH check.
- [ ] Delivery recommends one copyable artefact for a ready user and explains
      disabled, zero-grant, empty-artefact, all-pending and loopback states.
- [ ] Private LAN/Tailscale origins keep copy with a scope hint; no text claims
      that syntax proves reachability.
- [ ] A mixed applied/pending fleet keeps one primary item and names pending
      nodes; an all-pending fleet recommends nothing.
- [ ] Web-only deferred remediation: CLI/inventory grant still works while
      unverified, and a later successful SSH check enables the web grant.
- [ ] Existing share-link/subscription/app-config bodies are byte-identical;
      no changes to their renderers or routes.
