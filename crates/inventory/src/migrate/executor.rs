use crate::sqlite::{SqliteInventory, SqliteInventoryError};

use super::types::{MigrationOutcome, MigrationPlan};

pub async fn apply_migration_plan(
    inv: &SqliteInventory,
    plan: &MigrationPlan,
    overwrite_existing: bool,
) -> Result<MigrationOutcome, SqliteInventoryError> {
    let mut outcome = MigrationOutcome::default();

    match inv.add_server(&plan.server).await {
        Ok(()) => {
            outcome.server_created = true;
        }
        Err(SqliteInventoryError::AlreadyExists(_)) => {
            outcome.server_already_existed = true;
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
                    let prev_grants = inv.servers_for_user(&user.id).await?;
                    inv.remove_user(&user.id).await?;
                    inv.add_user(user).await?;
                    let new_server = plan.server.id.clone();
                    for s in prev_grants {
                        if s.id == new_server {
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
        inv.grant(uid, sid).await?;
        outcome.grants_made += 1;
    }

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
