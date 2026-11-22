# Server deletion from the admin UI

## Intent and invariants

Removing a server can cascade through millions of traffic samples. The database
deletion and its existing dependency checks run under the node operation lock,
even when the submitting browser disconnects. The lock also prevents a second
admin deletion or deployment for the same node during the operation.

## Interface

- The existing form still requires the exact server ID and same-origin POST.
- If the result is ready within two seconds, the POST returns the existing
  success redirect or error status. A longer operation redirects to the
  existing confirmation URL with `?deletion=pending`.
- The status page refreshes while deletion runs and provides a manual check.
  Completion redirects to the server list. A failure returns an error status.
  After a restart or status expiry, the page checks the current inventory.

## Verification

- [ ] A held SQLite write lock causes a progress redirect. After the lock
  releases, the user reaches the list and the inventory has one removal audit.
- [ ] Confirmation, deploy conflicts, client-detour conflicts, cascade scope,
  and the immediate success redirect continue to pass the admin smoke tests.
- [ ] A deletion with production-sized history finishes on an isolated copy.
