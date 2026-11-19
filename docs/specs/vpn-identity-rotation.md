# VPN identity rotation

## Intent and invariants

Reissue one user's global VPN UUID after disclosure. Keep the same account,
subscription token, device ID, VPN passwords, WireGuard keys and grants.
Replace any grant override equal to the previous global UUID. Preserve
different overrides. Affected nodes must receive a freshly rendered config
before revocation is complete. Existing imported profiles must refresh.

## Interface and data contract

- `SqliteInventory::rotate_user_uuid(&UserId, expected_sha256: &str,
  replacement: &str, actor: &str) -> Result<Vec<ServerId>>` accepts a
  canonical UUID and the SHA-256 of the lowercase current UUID.
- Rotate and record `user.uuid.rotate` in one SQLite transaction. The payload
  has counts only. The inventory's retired-UUID triggers keep the old UUID
  known to the existing deploy guard.
- Retrying with the exact replacement currently active returns the same
  current grant server IDs and writes no additional audit entry. A stale
  fingerprint or a replacement assigned to a different identity or retired
  identity fails before any mutation.
- POST `/admin/users/{id}/uuid/rotate` uses the existing protected operator
  flow, accepts the same fingerprint, and queues existing targeted redeploy.
  The handler generates the replacement when the form omits it. Authorized
  automation can submit a replacement already retained in the owner archive.
- The rotation audit event keeps affected grants pending until a successful
  deployment. After a failed or interrupted attempt, the user's existing
  deploy-pending action reapplies the current inventory on those servers.

## Verification

- Synthetic tests prove grant override behavior, unchanged credentials,
  retirement, one audit without UUIDs and replay without further mutation.
- Invalid, reused or stale inputs preserve the inventory.
- Verify each affected node's effective running config and the existing
  subscription route after deployment.
