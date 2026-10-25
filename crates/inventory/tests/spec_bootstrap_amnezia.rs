#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashSet;

use tempfile::TempDir;
use vpnctl_core::{KernelId, Registry, Server, ServerId};
use vpnctl_inventory::{SqliteInventory, bootstrap_server_secrets};

async fn open(dir: &TempDir) -> SqliteInventory {
    SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .expect("open")
}

fn srv(id: &str, kernels: &[&str]) -> Server {
    Server {
        id: ServerId(id.into()),
        address: "203.0.113.7".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: kernels.iter().map(|k| KernelId((*k).into())).collect(),
        enabled_protocols: vec![],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    }
}

fn num(secrets: &std::collections::HashMap<String, String>, k: &str) -> u32 {
    secrets
        .get(&format!("amneziawg.{k}"))
        .unwrap_or_else(|| panic!("missing amneziawg.{k}"))
        .parse::<u32>()
        .unwrap_or_else(|_| panic!("amneziawg.{k} not a u32"))
}

#[tokio::test]
async fn partial_legacy_obfs_is_completed_without_rotation_and_audited_once() {
    for missing_h1 in [false, true] {
        let dir = TempDir::new().unwrap();
        let inv = open(&dir).await;
        let s = srv("legacy-awg", &["amneziawg"]);
        inv.add_server(&s).await.unwrap();
        inv.set_server_secret(&s.id, "amneziawg.s1", "37")
            .await
            .unwrap();
        if !missing_h1 {
            inv.set_server_secret(&s.id, "amneziawg.h1", "123456789")
                .await
                .unwrap();
        }
        let before = inv.list_server_secrets(&s.id).await.unwrap();
        let audit_before = inv.recent_audit(100).await.unwrap().len();
        let (secrets, minted) = bootstrap_server_secrets(&inv, &s, &Registry::new())
            .await
            .unwrap();
        let expected: std::collections::HashMap<_, _> =
            vpnctl_core::amneziawg::effective_params(&before)
                .into_iter()
                .map(|(key, value)| {
                    (
                        format!("amneziawg.{}", key.to_ascii_lowercase()),
                        value.to_string(),
                    )
                })
                .collect();
        assert_eq!(secrets, expected);
        assert_eq!(inv.list_server_secrets(&s.id).await.unwrap(), expected);
        assert_eq!(minted, vec!["amneziawg obfs params"]);
        let audit_after = inv.recent_audit(100).await.unwrap().len();
        assert_eq!(audit_after - audit_before, 9 - before.len());
        let (repeated, minted) = bootstrap_server_secrets(&inv, &s, &Registry::new())
            .await
            .unwrap();
        assert_eq!(repeated, expected);
        assert!(minted.is_empty());
        assert_eq!(inv.recent_audit(100).await.unwrap().len(), audit_after);
    }
}

#[tokio::test]
async fn amneziawg_kernel_server_mints_nine_coherent_obfs_params() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    let s = srv("awgnode", &["amneziawg"]);
    inv.add_server(&s).await.unwrap();

    let (secrets, minted) = bootstrap_server_secrets(&inv, &s, &Registry::new())
        .await
        .expect("bootstrap");

    for k in ["jc", "jmin", "jmax", "s1", "s2", "h1", "h2", "h3", "h4"] {
        assert!(
            secrets.contains_key(&format!("amneziawg.{k}")),
            "missing amneziawg.{k}"
        );
    }
    assert_ne!(
        num(&secrets, "s2"),
        num(&secrets, "s1") + 56,
        "s2==s1+56 tell"
    );
    let hs = [
        num(&secrets, "h1"),
        num(&secrets, "h2"),
        num(&secrets, "h3"),
        num(&secrets, "h4"),
    ];
    for h in hs {
        assert!(h >= 5, "h {h} collides with a real WG msg type (1-4)");
    }
    assert_eq!(
        hs.iter().collect::<HashSet<_>>().len(),
        4,
        "h1-h4 must be distinct: {hs:?}"
    );
    assert!(
        minted.contains(&"amneziawg obfs params"),
        "mint must be reported: {minted:?}"
    );
}

#[tokio::test]
async fn non_amneziawg_server_mints_no_obfs() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    let s = srv("sbnode", &["sing-box"]);
    inv.add_server(&s).await.unwrap();

    let (secrets, minted) = bootstrap_server_secrets(&inv, &s, &Registry::new())
        .await
        .expect("bootstrap");
    assert!(
        !secrets.contains_key("amneziawg.h1"),
        "no obfs on non-awg node"
    );
    assert!(!minted.contains(&"amneziawg obfs params"));
}

#[tokio::test]
async fn obfs_mint_is_idempotent_never_rotates() {
    let dir = TempDir::new().unwrap();
    let inv = open(&dir).await;
    let s = srv("awgnode2", &["amneziawg"]);
    inv.add_server(&s).await.unwrap();

    let (first, _) = bootstrap_server_secrets(&inv, &s, &Registry::new())
        .await
        .expect("bootstrap 1");
    let h1_first = first["amneziawg.h1"].clone();

    let (second, minted2) = bootstrap_server_secrets(&inv, &s, &Registry::new())
        .await
        .expect("bootstrap 2");
    assert_eq!(second["amneziawg.h1"], h1_first, "obfs must not rotate");
    assert!(
        !minted2.contains(&"amneziawg obfs params"),
        "second run must mint nothing: {minted2:?}"
    );
}
