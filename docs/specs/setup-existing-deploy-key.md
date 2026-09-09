# Spec: Verify an already-installed deploy key

## 1. Intent & Invariants
- Existing-server setup supports an already-installed daemon deploy key with a chosen SSH user (including `debian`) without password or reference-key configuration.
- Verification never installs keys, deploys configurations, changes grants, or restarts services.
- Require an inventory-pinned target host key for verification (no trust-on-first-use); preserve trusted host-key checking and jump-host routing. Non-root verification uses the transport's exact `sudo -n sh -c` primitive.
- Save the SSH user with mutation audit only after successful verification; failures preserve the old login. Repeated unchanged success creates no mutation audit.

## 2. Interface / Data Contract
- `POST /admin/servers/{id}/push-deploy-key`: `auth_method=deploy-key&ssh_user=debian` selects verification-only authentication with vpnctld's deploy key.
- An omitted `auth_method` preserves existing password/reference-key installation behavior. Unknown methods are rejected before SSH.
- Setup exposes a separate password-free form, “Check key and save”, with an SSH username field and EN/RU explanations.
- Success redirects to setup; errors explain verification failure without exposing secrets. Invalid usernames are rejected before SSH.
- Production deployment and changes to Infomaniak require separate approval.

## 3. Verification Checklist (Definition of Done)
- [ ] Successful key + non-root passwordless sudo saves username without password/reference key.
- [ ] Key, sudo, host-key and timeout failures preserve username; invalid input never connects.
- [ ] No remote mutation, grant changes or no-op mutation audit from verification.
- [ ] Existing password/reference-key behavior remains covered.
- [ ] Independent spec tests, diff review, security review and mandatory local/CI checks.
