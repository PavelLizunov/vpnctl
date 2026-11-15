use super::{Result, SqliteInventory, SqliteInventoryError};
use crate::{SshAccessCheck, SshAccessFailure, SshAccessRoute, SshAccessState, SshAccessStatus};
use chrono::{DateTime, Utc};
use sqlx::Row;
use vpnctl_core::{Server, ServerId};

fn route_name(route: SshAccessRoute) -> &'static str {
    match route {
        SshAccessRoute::Direct => "direct",
        SshAccessRoute::Jump => "jump",
    }
}

fn route_identity(target: &Server, route: SshAccessRoute, jump: Option<&Server>) -> Result<String> {
    let endpoint = |s: &Server| {
        serde_json::json!([
            s.id.0,
            s.address,
            s.ssh_port,
            s.ssh_user,
            s.trusted_host_fingerprint
        ])
    };
    match route {
        SshAccessRoute::Direct if jump.is_none() => Ok(endpoint(target).to_string()),
        SshAccessRoute::Jump
            if target.jump_via.is_some()
                && jump.is_none_or(|s| Some(&s.id) == target.jump_via.as_ref()) =>
        {
            Ok(
                serde_json::json!([endpoint(target), target.jump_via, jump.map(endpoint)])
                    .to_string(),
            )
        }
        _ => Err(SqliteInventoryError::Invalid(
            "invalid SSH observation route".into(),
        )),
    }
}

impl SqliteInventory {
    pub async fn record_ssh_access(
        &self,
        target: &Server,
        route: SshAccessRoute,
        jump: Option<&Server>,
        check: &SshAccessCheck,
    ) -> Result<()> {
        if check.checked_at > Utc::now()
            || (check.state == SshAccessState::Available && check.failure.is_some())
            || (check.state == SshAccessState::Unavailable && check.failure.is_none())
            || (route == SshAccessRoute::Jump
                && jump.is_none()
                && check.state != SshAccessState::Unknown)
        {
            return Err(SqliteInventoryError::Invalid(
                "invalid SSH observation".into(),
            ));
        }
        route_identity(target, route, jump)?;
        let resolved_jump = if route == SshAccessRoute::Jump && jump.is_none() {
            match target.jump_via.as_ref() {
                Some(id) => self.get_server(id).await?,
                None => None,
            }
        } else {
            None
        };
        let identity = route_identity(target, route, jump.or(resolved_jump.as_ref()))?;
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM servers WHERE id = ?1)")
            .bind(&target.id.0)
            .fetch_one(&mut *tx)
            .await?;
        if !exists {
            return Err(SqliteInventoryError::Invalid(
                "SSH observation target is missing".into(),
            ));
        }
        let previous = sqlx::query(
            "SELECT route_identity, check_json FROM ssh_access_checks WHERE server_id = ?1 AND route = ?2",
        ).bind(&target.id.0).bind(route_name(route)).fetch_optional(&mut *tx).await?;
        let mut changed = true;
        if let Some(row) = previous {
            let old: SshAccessCheck = serde_json::from_str(row.try_get("check_json")?)?;
            if check.checked_at <= old.checked_at {
                return Ok(());
            }
            changed = row.try_get::<String, _>("route_identity")? != identity
                || old.state != check.state
                || old.failure != check.failure;
        }
        sqlx::query(
            "INSERT INTO ssh_access_checks (server_id, route, route_identity, check_json) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (server_id, route) DO UPDATE SET route_identity = excluded.route_identity, check_json = excluded.check_json",
        ).bind(&target.id.0).bind(route_name(route)).bind(identity).bind(serde_json::to_string(check)?)
            .execute(&mut *tx).await?;
        if changed {
            sqlx::query("INSERT INTO audit_log (actor, action, target, payload) VALUES ('system', 'server.ssh_access.changed', ?1, ?2)")
                .bind(&target.id.0)
                .bind(serde_json::json!({"route": route, "state": check.state, "failure": check.failure, "checked_at": check.checked_at}).to_string())
                .execute(&mut *tx).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn ssh_access_for_server(
        &self,
        server_id: &ServerId,
        now: DateTime<Utc>,
        max_age_secs: u64,
    ) -> Result<SshAccessStatus> {
        let target = self.get_server(server_id).await?.ok_or_else(|| {
            SqliteInventoryError::Invalid("SSH observation target is missing".into())
        })?;
        let jump = match target.jump_via.as_ref() {
            Some(id) => self.get_server(id).await?,
            None => None,
        };
        let rows = sqlx::query(
            "SELECT route, route_identity, check_json FROM ssh_access_checks WHERE server_id = ?1",
        )
        .bind(&server_id.0)
        .fetch_all(&self.pool)
        .await?;
        let max_age = chrono::Duration::seconds(
            i64::try_from(max_age_secs)
                .unwrap_or(i64::MAX / 1000)
                .min(i64::MAX / 1000),
        );
        let mut status = SshAccessStatus::default();
        for row in rows {
            let route = match row.try_get::<&str, _>("route")? {
                "direct" => SshAccessRoute::Direct,
                "jump" if target.jump_via.is_some() => SshAccessRoute::Jump,
                _ => continue,
            };
            let expected = route_identity(
                &target,
                route,
                if route == SshAccessRoute::Jump {
                    jump.as_ref()
                } else {
                    None
                },
            )?;
            if row.try_get::<String, _>("route_identity")? != expected {
                continue;
            }
            let mut check: SshAccessCheck = serde_json::from_str(row.try_get("check_json")?)?;
            let age = now.signed_duration_since(check.checked_at);
            if age < chrono::Duration::zero() || age > max_age {
                check.state = SshAccessState::Unknown;
                check.failure = Some(SshAccessFailure::Stale);
            }
            match route {
                SshAccessRoute::Direct => status.direct = Some(check),
                SshAccessRoute::Jump => status.jump = Some(check),
            }
        }
        Ok(status)
    }
}
