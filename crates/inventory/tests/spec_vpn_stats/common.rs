use std::path::PathBuf;

use tempfile::TempDir;
use vpnctl_core::{KernelId, Server, ServerId, User, UserId};
use vpnctl_inventory::{SqliteInventory, VpnStatsDelta};

pub(crate) fn db_path(dir: &TempDir) -> PathBuf {
    dir.path().join("inventory.db")
}

pub(crate) async fn open(dir: &TempDir) -> SqliteInventory {
    SqliteInventory::open(&db_path(dir)).await.expect("open")
}

pub(crate) fn server(id: &str) -> Server {
    Server {
        id: ServerId(id.to_string()),
        address: format!("{id}.example.com"),
        ssh_port: 22,
        ssh_user: "root".to_string(),
        kernels: vec![KernelId("sing-box".to_string())],
        enabled_protocols: vec![],
        trusted_host_fingerprint: None,
        hoster: "generic".to_string(),
        jump_via: None,
        usage_coefficient: 1.0,
    }
}

/// Like `server`, but with an explicit Marzban-style traffic
/// multiplier so the usage-coefficient weighting can be exercised.
pub(crate) fn server_coeff(id: &str, usage_coefficient: f64) -> Server {
    Server {
        usage_coefficient,
        ..server(id)
    }
}

pub(crate) fn user(id: &str) -> User {
    User {
        id: UserId(id.to_string()),
        uuid: format!("uuid-{id}"),
        tuic_password: None,
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: None,
        vpn_router_device_id: None,
        disabled: false,
    }
}

pub(crate) fn ud(uid: Option<&str>, up: u64, down: u64, conns: u32) -> VpnStatsDelta {
    VpnStatsDelta {
        user_id: uid.map(|s| UserId(s.to_string())),
        upload_bytes: up,
        download_bytes: down,
        active_connections: conns,
    }
}
