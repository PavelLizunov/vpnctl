use crate::sqlite::{SqliteInventory, SqliteInventoryError};

use super::types::{MigrationOutcome, MigrationPlan};

/// Apply a `MigrationPlan` against an open `SqliteInventory`. Each
/// step writes its own audit row so the operator can replay the
/// timeline post-hoc. Idempotent at the SQL layer:
///   * `add_server` already-exists → updated with current secrets +
///     additional users (won't drop existing grants),
///   * `add_user` already-exists → depends on `overwrite_existing`:
///     - `false` (default): SKIP the user (preserves any vpnctl-side
///       state like wireguard keypair or hand-set sub_token);
///     - `true`: `remove_user` then `add_user` with bash data
///       (drops vpnctl-only state including WG keypair, restored
///       sub_token, traffic-limit). Required when the operator
///       had test users in vpnctl with random UUIDs that DON'T
///       match the bash production data — overwrite forces vpnctl
///       to mirror bash's UUIDs so subsequent `/sub/<token>` calls
///       return links that match the existing phone scans.
///   * `grant` already-exists → silently no-op.
///
/// Returns a `MigrationOutcome` summary (counts of created vs
/// overwritten vs skipped — surfaced by the CLI's final report line).
pub async fn apply_migration_plan(
    inv: &SqliteInventory,
    plan: &MigrationPlan,
    overwrite_existing: bool,
) -> Result<MigrationOutcome, SqliteInventoryError> {
    let mut outcome = MigrationOutcome::default();

    // Server first. If it already exists, AlreadyExists is the
    // signal — we still try to update the secrets in case the
    // operator is re-running migration after a fix.
    match inv.add_server(&plan.server).await {
        Ok(()) => {
            outcome.server_created = true;
        }
        Err(SqliteInventoryError::AlreadyExists(_)) => {
            outcome.server_already_existed = true;
            // In overwrite mode, ALSO correct the address/port/user
            // — a pre-existing server with the same id may have a
            // stale IP from an earlier wizard test; without this
            // update vpnctl's view stays inconsistent (correct
            // REALITY pair pointing at the wrong IP). Outside
            // overwrite mode we leave the existing address alone
            // — silently mutating it would surprise the operator.
            if overwrite_existing {
                inv.update_server_address(
                    &plan.server.id,
                    &plan.server.address,
                    plan.server.ssh_port,
                    &plan.server.ssh_user,
                )
                .await?;
                outcome.server_address_updated = true;
            }
        }
        Err(e) => return Err(e),
    }

    for (key, value) in &plan.server_secrets {
        inv.set_server_secret(&plan.server.id, key, value).await?;
        outcome.secrets_set += 1;
    }

    for user in &plan.users_to_import {
        match inv.get_user(&user.id).await? {
            Some(_existing) => {
                if overwrite_existing {
                    // remove_user CASCADEs through the grants FK —
                    // that would silently drop the user's grants
                    // for EVERY other server, not just the one
                    // we're migrating. Snapshot the full grant set
                    // BEFORE the remove, then re-grant after the
                    // add_user (the bash server's own grant is
                    // re-added by the plan.grants loop below; we
                    // restore the OTHER servers' grants here).
                    //
                    // Caught by review-agent 2026-05-17 — a real
                    // grant (`main-brat`→`stg`) was lost on the
                    // first production run; this is the fix.
                    let prev_grants = inv.servers_for_user(&user.id).await?;
                    inv.remove_user(&user.id).await?;
                    inv.add_user(user).await?;
                    let new_server = plan.server.id.clone();
                    for s in prev_grants {
                        if s.id == new_server {
                            // The plan.grants loop below re-adds
                            // this one — don't double-grant (it's
                            // idempotent at SQL but the audit
                            // would be misleading).
                            continue;
                        }
                        inv.grant(&user.id, &s.id).await?;
                        outcome.other_server_grants_preserved.push(format!(
                            "{user}|{server}",
                            user = user.id.0,
                            server = s.id.0
                        ));
                    }
                    outcome.users_overwritten.push(user.id.0.clone());
                } else {
                    outcome.users_skipped_existing.push(user.id.0.clone());
                }
            }
            None => {
                inv.add_user(user).await?;
                outcome.users_created += 1;
                // I1 unification (audit 2026-05-22): emit a
                // per-user `user.add` row alongside the summary
                // `migrate.from_bash` row below. Without these,
                // audit-driven dashboards undercount imported
                // users — `WHERE action = 'user.add'` would miss
                // every bash-import. Same payload shape the CLI
                // and web paths emit. `actor = "migrate"` keeps
                // the source filterable.
                let _ = inv
                    .audit(
                        "migrate",
                        "user.add",
                        Some(&user.id.0),
                        Some(&serde_json::json!({
                            "uuid": user.uuid,
                            "wg_pubkey_set": user.wireguard_pubkey.is_some(),
                            "wg_keypair_provenance": if user.wireguard_pubkey.is_some() {
                                "operator-provided"
                            } else {
                                "absent"
                            },
                        })),
                    )
                    .await;
            }
        }
    }

    for (uid, sid) in &plan.grants {
        // grant is upsert-y (PRIMARY KEY (user_id, server_id) + IGNORE)
        // so re-runs are safe. If `overwrite_existing` removed +
        // re-added the user, this re-creates the grant.
        inv.grant(uid, sid).await?;
        outcome.grants_made += 1;
    }

    // Audit row — one per migration application, summarising the
    // counts. NOT per-row (that would flood the timeline).
    inv.audit(
        "admin",
        "migrate.from_bash",
        Some(&plan.server.id.0),
        Some(&serde_json::json!({
            "server_address": plan.server.address,
            "server_created": outcome.server_created,
            "server_already_existed": outcome.server_already_existed,
            "secrets_set": outcome.secrets_set,
            "users_created": outcome.users_created,
            "users_overwritten": outcome.users_overwritten,
            "users_skipped_existing": outcome.users_skipped_existing,
            "grants_made": outcome.grants_made,
            "other_server_grants_preserved": outcome.other_server_grants_preserved,
            "server_address_updated": outcome.server_address_updated,
            "overwrite_existing_mode": overwrite_existing,
            "skipped": plan.skipped.iter().map(|s| serde_json::json!({"name": s.name, "reason": s.reason})).collect::<Vec<_>>(),
            "warnings": plan.warnings,
        })),
    )
    .await?;

    Ok(outcome)
}
