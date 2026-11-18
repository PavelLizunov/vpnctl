use super::{Result, SqliteInventory};
use std::collections::HashMap;
use vpnctl_core::ServerId;

#[derive(Debug, sqlx::FromRow)]
pub struct ServerSecurityReport {
    pub route_fingerprint: String,
    pub revision: i64,
    pub report_json: String,
}

impl SqliteInventory {
    pub async fn server_security_report(
        &self,
        id: &ServerId,
    ) -> Result<Option<ServerSecurityReport>> {
        Ok(sqlx::query_as(
            "SELECT route_fingerprint, revision, report_json
             FROM server_security_reports WHERE server_id = ?",
        )
        .bind(&id.0)
        .fetch_optional(&self.pool)
        .await?)
    }

    pub async fn server_security_reports(&self) -> Result<HashMap<ServerId, ServerSecurityReport>> {
        let rows: Vec<(String, String, i64, String)> = sqlx::query_as(
            "SELECT server_id, route_fingerprint, revision, report_json FROM server_security_reports",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|(id, route_fingerprint, revision, report_json)| {
                (
                    ServerId(id),
                    ServerSecurityReport {
                        route_fingerprint,
                        revision,
                        report_json,
                    },
                )
            })
            .collect())
    }

    pub async fn record_server_security_report(
        &self,
        id: &ServerId,
        report: &ServerSecurityReport,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO server_security_reports (server_id, route_fingerprint, revision, report_json)
             SELECT id, ?, ?, ? FROM servers WHERE id = ?
             ON CONFLICT(server_id) DO UPDATE SET route_fingerprint = excluded.route_fingerprint,
                 revision = excluded.revision, report_json = excluded.report_json
             WHERE server_security_reports.revision < excluded.revision",
        )
        .bind(&report.route_fingerprint)
        .bind(report.revision)
        .bind(&report.report_json)
        .bind(&id.0)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
