use crate::sqlite::{SqliteInventory, SqliteInventoryError};

use super::types::{MigrationOutcome, MigrationPlan};

pub async fn apply_migration_plan(
    inv: &SqliteInventory,
    plan: &MigrationPlan,
    overwrite_existing: bool,
) -> Result<MigrationOutcome, SqliteInventoryError> {
    let mut outcome = MigrationOutcome::default();
    let mut grant_uuid_changed = false;

    match inv.add_server(&plan.server).await {
        Ok(()) => {
            outcome.server_created = true;
            inv.audit("migrate", "server.add", Some(&plan.server.id.0), None)
                .await?;
        }
        Err(SqliteInventoryError::AlreadyExists(_)) => {
            outcome.server_already_existed = true;
            if overwrite_existing
                && let Some(existing) = inv.get_server(&plan.server.id).await?
                && (existing.address != plan.server.address
                    || existing.ssh_port != plan.server.ssh_port
                    || existing.ssh_user != plan.server.ssh_user)
            {
                inv.update_server_address(
                    &plan.server.id,
                    &plan.server.address,
                    plan.server.ssh_port,
                    &plan.server.ssh_user,
                )
                .await?;
                outcome.server_address_updated = true;
                inv.audit(
                    "migrate",
                    "server.address.update",
                    Some(&plan.server.id.0),
                    None,
                )
                .await?;
            }
        }
        Err(e) => return Err(e),
    }

    for (key, value) in &plan.server_secrets {
        let mut tx = inv.pool.begin_with("BEGIN IMMEDIATE").await?;
        let changed = sqlx::query(
            "INSERT INTO server_secrets (server_id, key, value) VALUES (?1, ?2, ?3)
             ON CONFLICT(server_id, key) DO UPDATE SET value = excluded.value
             WHERE ?4 AND server_secrets.value IS NOT excluded.value",
        )
        .bind(&plan.server.id.0)
        .bind(key)
        .bind(value)
        .bind(overwrite_existing)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if changed > 0 {
            sqlx::query(
                "INSERT INTO audit_log (actor, action, target, payload)
                 VALUES ('migrate', 'server.secret.set', ?1, ?2)",
            )
            .bind(&plan.server.id.0)
            .bind(serde_json::json!({ "key": key }).to_string())
            .execute(&mut *tx)
            .await?;
            outcome.secrets_set += 1;
        }
        tx.commit().await?;
    }

    for user in &plan.users_to_import {
        match inv.get_user(&user.id).await? {
            Some(_existing) => {
                if overwrite_existing {
                    outcome
                        .other_server_grants_preserved
                        .extend(replace_user(inv, user, &plan.server.id).await?);
                    outcome.users_overwritten.push(user.id.0.clone());
                } else {
                    outcome.users_skipped_existing.push(user.id.0.clone());
                }
            }
            None => {
                inv.add_user(user).await?;
                outcome.users_created += 1;
                inv.audit(
                    "migrate",
                    "user.add",
                    Some(&user.id.0),
                    Some(&serde_json::json!({
                        "uuid_set": true,
                        "wg_pubkey_set": user.wireguard_pubkey.is_some(),
                        "wg_keypair_provenance": if user.wireguard_pubkey.is_some() {
                            "operator-provided"
                        } else {
                            "absent"
                        },
                    })),
                )
                .await?;
            }
        }
    }

    for (uid, sid) in &plan.grants {
        let imported_uuid = plan
            .users_to_import
            .iter()
            .find(|u| &u.id == uid)
            .map(|u| u.uuid.as_str());
        let (created, changed) =
            import_grant(inv, uid, sid, imported_uuid, overwrite_existing).await?;
        if created {
            outcome.grants_made += 1;
        }
        grant_uuid_changed |= changed;
    }

    if !outcome.server_created
        && !outcome.server_address_updated
        && outcome.secrets_set == 0
        && outcome.users_created == 0
        && outcome.users_overwritten.is_empty()
        && outcome.grants_made == 0
        && !grant_uuid_changed
    {
        return Ok(outcome);
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

// Insert a grant with its imported identity atomically; never expose the global
// UUID as a temporary identity on a second server.
async fn import_grant(
    inv: &SqliteInventory,
    user: &vpnctl_core::UserId,
    server: &vpnctl_core::ServerId,
    imported_uuid: Option<&str>,
    overwrite_existing: bool,
) -> Result<(bool, bool), SqliteInventoryError> {
    let mut tx = inv.pool.begin_with("BEGIN IMMEDIATE").await?;
    let identity: Option<(String, String)> = sqlx::query_as(
        "SELECT u.uuid, s.role FROM users u CROSS JOIN servers s
         WHERE u.id = ?1 AND s.id = ?2",
    )
    .bind(&user.0)
    .bind(&server.0)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((global_uuid, role)) = identity else {
        return Err(SqliteInventoryError::Invalid(
            "no such user or server; cannot import grant".into(),
        ));
    };
    if role == "workload-only" {
        return Err(SqliteInventoryError::Invalid(format!(
            "cannot grant access to workload-only server '{}'",
            server.0
        )));
    }
    let existing: Option<(Option<String>,)> =
        sqlx::query_as("SELECT client_uuid FROM grants WHERE user_id = ?1 AND server_id = ?2")
            .bind(&user.0)
            .bind(&server.0)
            .fetch_optional(&mut *tx)
            .await?;
    let client_uuid = imported_uuid.filter(|uuid| *uuid != global_uuid.as_str());
    // Without --overwrite-existing a grant that already pins its own UUID
    // keeps it: the live node accepts that UUID, not the imported one.
    if let Some((old_uuid,)) = &existing
        && (client_uuid.is_none()
            || old_uuid.as_deref() == client_uuid
            || (old_uuid.is_some() && !overwrite_existing))
    {
        tx.commit().await?;
        return Ok((false, false));
    }
    if let Some(uuid) = client_uuid
        && !vpnctl_crypto::is_valid_uuid(uuid)
    {
        return Err(SqliteInventoryError::Invalid(
            "imported client_uuid is not a valid UUID; refusing to write".into(),
        ));
    }
    let collision: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM grants g JOIN users u ON u.id = g.user_id
         WHERE g.server_id = ?1 AND g.user_id <> ?2
           AND COALESCE(g.client_uuid, u.uuid) = ?3",
    )
    .bind(&server.0)
    .bind(&user.0)
    .bind(client_uuid.unwrap_or(&global_uuid))
    .fetch_one(&mut *tx)
    .await?;
    if collision.0 > 0 {
        return Err(SqliteInventoryError::AlreadyExists(
            "imported UUID conflicts with another user on the importing server".into(),
        ));
    }
    let octet = if existing.is_none() {
        SqliteInventory::next_wg_octet(&mut tx, server)
            .await?
            .map(i64::from)
    } else {
        None
    };
    sqlx::query(
        "INSERT INTO grants (user_id, server_id, client_uuid, granted_at, wg_octet)
         VALUES (?1, ?2, ?3, datetime('now'), ?4)
         ON CONFLICT(user_id, server_id) DO UPDATE SET client_uuid = excluded.client_uuid",
    )
    .bind(&user.0)
    .bind(&server.0)
    .bind(client_uuid)
    .bind(octet)
    .execute(&mut *tx)
    .await?;
    let (action, payload) = match &existing {
        Some((old_uuid,)) => (
            "grant.set_client_uuid",
            serde_json::json!({
                "server_id": server.0,
                "old_client_uuid_set": old_uuid.is_some(),
                "new_client_uuid_set": client_uuid.is_some(),
            }),
        ),
        None => (
            "user.grant",
            serde_json::json!({ "server": server.0, "wg_octet": octet }),
        ),
    };
    sqlx::query(
        "INSERT INTO audit_log (actor, action, target, payload) VALUES ('migrate', ?1, ?2, ?3)",
    )
    .bind(action)
    .bind(&user.0)
    .bind(payload.to_string())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok((existing.is_none(), existing.is_some()))
}

// Replace the user and restore other-server grants in one transaction. Pin each
// preserved grant's effective UUID before changing the global identity.
async fn replace_user(
    inv: &SqliteInventory,
    user: &vpnctl_core::User,
    importing_server: &vpnctl_core::ServerId,
) -> Result<Vec<String>, SqliteInventoryError> {
    let token = match user.sub_token.as_deref() {
        Some(token) if !token.is_empty() => token.to_string(),
        _ => vpnctl_crypto::gen_sub_token().map_err(SqliteInventoryError::CryptoIo)?,
    };
    let mut tx = inv.pool.begin_with("BEGIN IMMEDIATE").await?;
    type PreservedGrant = (String, String, String, Option<String>, Option<i64>);
    let grants: Vec<PreservedGrant> = sqlx::query_as(
        "SELECT g.server_id, COALESCE(g.client_uuid, u.uuid), g.created_at, g.granted_at, g.wg_octet
         FROM grants g JOIN users u ON u.id = g.user_id
         WHERE g.user_id = ?1 ORDER BY g.server_id",
    )
    .bind(&user.id.0)
    .fetch_all(&mut *tx)
    .await?;
    if grants
        .iter()
        .any(|(server, _, _, _, _)| server == &importing_server.0)
    {
        let collision: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM grants g JOIN users u ON u.id = g.user_id
             WHERE g.server_id = ?1 AND g.user_id <> ?2
               AND COALESCE(g.client_uuid, u.uuid) = ?3",
        )
        .bind(&importing_server.0)
        .bind(&user.id.0)
        .bind(&user.uuid)
        .fetch_one(&mut *tx)
        .await?;
        if collision.0 > 0 {
            return Err(SqliteInventoryError::AlreadyExists(
                "imported UUID conflicts with another user on the importing server".into(),
            ));
        }
    }
    sqlx::query("DELETE FROM users WHERE id = ?1")
        .bind(&user.id.0)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO users (id, uuid, tuic_password, wireguard_pubkey, wireguard_private,
                            sub_token, vpn_router_device_id, disabled)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
    )
    .bind(&user.id.0)
    .bind(&user.uuid)
    .bind(&user.tuic_password)
    .bind(&user.wireguard_pubkey)
    .bind(&user.wireguard_private)
    .bind(&token)
    .bind(&user.vpn_router_device_id)
    .bind(user.disabled)
    .execute(&mut *tx)
    .await?;
    let mut preserved = Vec::with_capacity(grants.len());
    for (server, uuid, created_at, granted_at, wg_octet) in grants {
        let importing = server == importing_server.0;
        let uuid = if importing { user.uuid.clone() } else { uuid };
        sqlx::query(
            "INSERT INTO grants (user_id, server_id, client_uuid, created_at, granted_at, wg_octet)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )
        .bind(&user.id.0)
        .bind(&server)
        .bind(uuid)
        .bind(created_at)
        .bind(granted_at)
        .bind(wg_octet)
        .execute(&mut *tx)
        .await?;
        if !importing {
            preserved.push(format!("{}|{server}", user.id.0));
        }
    }
    sqlx::query(
        "INSERT INTO audit_log (actor, action, target)
         VALUES ('migrate', 'user.replace', ?1)",
    )
    .bind(&user.id.0)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(preserved)
}
