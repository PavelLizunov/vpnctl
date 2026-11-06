#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{HeaderMap, Request, StatusCode};
use serde_json::Value;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use tower::ServiceExt;
use vpnctl_core::{ServerId, User, UserId};
use vpnctl_inventory::SqliteInventory;

#[derive(Clone, Copy)]
pub(super) struct Sample {
    pub total: Option<i64>,
    pub available: Option<i64>,
    pub load_x100: Option<i64>,
    pub observed_at: i64,
}

pub(super) struct UserFixture {
    pub device_id: String,
    pub sub_token: String,
    id: UserId,
}

pub(super) struct NodeFixture {
    id: ServerId,
}

pub(super) struct Fixture {
    router: Router,
    inv: SqliteInventory,
    pool: sqlx::SqlitePool,
    next: AtomicU64,
    writer: tokio::task::JoinHandle<()>,
    _dir: tempfile::TempDir,
}

impl Fixture {
    pub(super) async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("metadata-test.db");
        let inv = SqliteInventory::open(&path).await.unwrap();
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(
                SqliteConnectOptions::new()
                    .filename(&path)
                    .foreign_keys(true),
            )
            .await
            .unwrap();
        let registry = Arc::new(crate::app::build_registry().unwrap());
        let (state, writer) = crate::app::make_app_state_for_tests(inv.clone(), registry);
        // Route registration and all response middleware are exercised here.
        let router = crate::app::router(state);
        Self {
            router,
            inv,
            pool,
            next: AtomicU64::new(1),
            writer,
            _dir: dir,
        }
    }

    pub(super) async fn user(&self, disabled: bool) -> UserFixture {
        let n = self.next.fetch_add(1, Ordering::Relaxed);
        let device_id = format!("{n:032x}");
        let sub_token = format!("synthetic-subscription-{n}");
        let id = UserId(format!("synthetic-user-{n}"));
        self.inv
            .add_user(&User {
                id: id.clone(),
                uuid: vpnctl_crypto::gen_uuid(),
                tuic_password: None,
                wireguard_pubkey: None,
                wireguard_private: None,
                sub_token: Some(sub_token.clone()),
                vpn_router_device_id: Some(device_id.clone()),
                disabled,
            })
            .await
            .unwrap();
        UserFixture {
            device_id,
            sub_token,
            id,
        }
    }

    pub(super) async fn node(&self, endpoint_host: &str, visible: bool, role: &str) -> NodeFixture {
        let n = self.next.fetch_add(1, Ordering::Relaxed);
        let id = ServerId(format!("synthetic-node-{n}"));
        // The production add_server helper refreshes DNS for hostnames. Seed
        // the actual tables directly so synthetic tests never perform lookups.
        sqlx::query("INSERT INTO servers (id, address, ssh_user, hoster, role) VALUES (?1, ?2, 'synthetic-operator', 'synthetic-provider', ?3)")
            .bind(&id.0)
            .bind(endpoint_host)
            .bind(role)
            .execute(&self.pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO server_kernels (server_id, kernel_id) VALUES (?1, 'sing-box')")
            .bind(&id.0)
            .execute(&self.pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO server_protocols (server_id, protocol_id, hidden) VALUES (?1, 'vless+reality', ?2)")
            .bind(&id.0)
            .bind(!visible)
            .execute(&self.pool)
            .await
            .unwrap();
        // A hidden enabled WG protocol exposes accidental allocating render
        // reads without adding a second client-visible protocol.
        sqlx::query("INSERT INTO server_protocols (server_id, protocol_id, hidden) VALUES (?1, 'wireguard', 1)")
            .bind(&id.0)
            .execute(&self.pool)
            .await
            .unwrap();
        if let Ok(ip) = endpoint_host.parse::<std::net::IpAddr>() {
            sqlx::query(
                "INSERT INTO server_resolved_addresses (server_id, address) VALUES (?1, ?2)",
            )
            .bind(&id.0)
            .bind(ip.to_string())
            .execute(&self.pool)
            .await
            .unwrap();
        }
        NodeFixture { id }
    }

    pub(super) async fn grant(&self, user: &UserFixture, node: &NodeFixture) {
        // Null WG allocation makes any accidental allocating render read visible.
        sqlx::query("INSERT INTO grants (user_id, server_id, wg_octet) VALUES (?1, ?2, NULL)")
            .bind(&user.id.0)
            .bind(&node.id.0)
            .execute(&self.pool)
            .await
            .unwrap();
    }

    pub(super) async fn revoke(&self, user: &UserFixture, node: &NodeFixture) {
        self.inv.revoke(&user.id, &node.id).await.unwrap();
    }

    pub(super) async fn protocol_alias(&self, node: &NodeFixture, protocol: &str, host: &str) {
        let key = match protocol {
            "naive" => "naive.domain",
            "vless-ws" => "vlessws.domain",
            _ => panic!("unsupported synthetic protocol alias"),
        };
        sqlx::query(
            "INSERT INTO server_protocols (server_id, protocol_id, hidden) VALUES (?1, ?2, 0)",
        )
        .bind(&node.id.0)
        .bind(protocol)
        .execute(&self.pool)
        .await
        .unwrap();
        self.inv
            .set_server_secret(&node.id, key, host)
            .await
            .unwrap();
    }

    pub(super) async fn seed_legacy_workload_grant(&self, user: &UserFixture, node: &NodeFixture) {
        let role: String = sqlx::query_scalar("SELECT role FROM servers WHERE id = ?1")
            .bind(&node.id.0)
            .fetch_one(&self.pool)
            .await
            .unwrap();
        assert_eq!(role, "workload-only");
        // This fixture owns a unique temporary database. Model an inconsistent
        // legacy grant so the endpoint's role filter is exercised independently
        // of the normal insert guard, without weakening production constraints.
        sqlx::query("DROP TRIGGER trg_grant_rejects_workload_role")
            .execute(&self.pool)
            .await
            .unwrap();
        self.grant(user, node).await;
    }

    pub(super) async fn sample(&self, node: &NodeFixture, sample: Sample) {
        let timestamp = chrono::DateTime::from_timestamp(sample.observed_at, 0)
            .unwrap()
            .to_rfc3339();
        sqlx::query(
            "INSERT INTO node_health (server_id, ts, mem_total_mib,
             mem_available_mib, load_1min_x100, sample_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )
        .bind(&node.id.0)
        .bind(timestamp)
        .bind(sample.total)
        .bind(sample.available)
        .bind(sample.load_x100)
        .bind(vpnctl_crypto::gen_uuid())
        .execute(&self.pool)
        .await
        .unwrap();
    }

    pub(super) async fn nic_sample(&self, node: &NodeFixture, observed_at: i64, rx: i64, tx: i64) {
        sqlx::query("INSERT INTO node_health(server_id,ts,sample_id,nic_iface,nic_rx_bytes,nic_tx_bytes) VALUES(?1,?2,?3,'eth0',?4,?5)")
            .bind(&node.id.0).bind(chrono::DateTime::from_timestamp(observed_at, 0).unwrap().to_rfc3339())
            .bind(vpnctl_crypto::gen_uuid()).bind(rx).bind(tx).execute(&self.pool).await.unwrap();
    }

    pub(super) fn now(&self) -> i64 {
        chrono::Utc::now().timestamp()
    }

    pub(super) fn ttl(&self) -> u64 {
        super::metadata_ttl()
    }

    pub(super) async fn request(&self, path: &str) -> (StatusCode, HeaderMap, Value) {
        let response = self
            .router
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, headers, value)
    }

    pub(super) async fn read_only_counts(&self) -> Value {
        let mut counts = serde_json::Map::new();
        for (name, query) in [
            ("peers", "SELECT COUNT(*) FROM users"),
            ("grants", "SELECT COUNT(*) FROM grants"),
            ("wg_allocations", "SELECT COUNT(wg_octet) FROM grants"),
            (
                "wg_allocation_sum",
                "SELECT COALESCE(SUM(wg_octet), 0) FROM grants",
            ),
            ("audit", "SELECT COUNT(*) FROM audit_log"),
            ("subscription_access", "SELECT COUNT(*) FROM sub_access_log"),
            ("persistent_bans", "SELECT COUNT(*) FROM sub_rate_bans"),
            ("health_samples", "SELECT COUNT(*) FROM node_health"),
            (
                "resolved_addresses",
                "SELECT COUNT(*) FROM server_resolved_addresses",
            ),
        ] {
            let count: i64 = sqlx::query_scalar(query)
                .fetch_one(&self.pool)
                .await
                .unwrap();
            counts.insert(name.into(), Value::from(count));
        }
        Value::Object(counts)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.writer.abort();
    }
}
