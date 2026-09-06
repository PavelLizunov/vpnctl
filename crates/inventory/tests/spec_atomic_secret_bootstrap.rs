//! Approved stable-secret contract, exercised through real SQLite inventory
//! and generic protocol declarations, with no dependency on AWG renderers.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use serde_json::{Value, json};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use tempfile::TempDir;
use vpnctl_core::{
    KernelId, Protocol, ProtocolId, Registry, RenderCtx, Server, ServerId, ServerSecretSpec, User,
};
use vpnctl_inventory::{SqliteInventory, bootstrap_server_secrets};

const PRIVATE: &str = "fixture.private_key";
const PUBLIC: &str = "fixture.public_key";
const SEED: &str = "fixture.profile_seed";

#[derive(Debug, Default)]
struct SnapshotRendezvous {
    arrivals: Mutex<usize>,
    ready: Condvar,
}

impl SnapshotRendezvous {
    fn wait(&self) {
        let mut arrivals = self.arrivals.lock().expect("snapshot rendezvous lock");
        *arrivals += 1;
        self.ready.notify_all();
        let (arrivals, _) = self
            .ready
            .wait_timeout_while(arrivals, Duration::from_secs(5), |count| *count < 2)
            .expect("snapshot rendezvous wait");
        assert_eq!(
            *arrivals, 2,
            "concurrent bootstrap peer did not reach its snapshot within 5 seconds"
        );
    }
}

#[derive(Debug)]
struct DeclaredSecrets {
    specs: Vec<ServerSecretSpec>,
    snapshot_barrier: Option<Arc<SnapshotRendezvous>>,
}

impl Protocol for DeclaredSecrets {
    fn id(&self) -> ProtocolId {
        ProtocolId("fixture-declared-secrets".into())
    }

    fn server_secret_specs(&self) -> Vec<ServerSecretSpec> {
        if let Some(barrier) = &self.snapshot_barrier {
            // Bootstrap reads its initial map before asking for declarations.
            // Force both concurrent callers to hold an empty snapshot, rather
            // than depending on a scheduler race to exercise winner rereads.
            barrier.wait();
        }
        self.specs.clone()
    }

    fn server_inbound(&self, _: &RenderCtx<'_>, _: &[User]) -> vpnctl_core::Result<Value> {
        unreachable!("bootstrap does not render")
    }

    fn client_config(&self, _: &RenderCtx<'_>, _: &User) -> vpnctl_core::Result<Value> {
        unreachable!("bootstrap does not render")
    }

    fn share_link(&self, _: &RenderCtx<'_>, _: &User) -> vpnctl_core::Result<String> {
        unreachable!("bootstrap does not render")
    }
}

fn specs() -> Vec<ServerSecretSpec> {
    vec![
        ServerSecretSpec::WireguardKeypair {
            private_key: PRIVATE,
            public_key: PUBLIC,
        },
        ServerSecretSpec::Base64Key {
            key: SEED,
            key_bytes: 32,
        },
    ]
}

fn registry(
    specs: Vec<ServerSecretSpec>,
    snapshot_barrier: Option<Arc<SnapshotRendezvous>>,
) -> Registry {
    let mut registry = Registry::new();
    registry
        .register_protocol(Box::new(DeclaredSecrets {
            specs,
            snapshot_barrier,
        }))
        .unwrap();
    registry
}

async fn fixture() -> (TempDir, SqliteInventory, Server) {
    let dir = TempDir::new().unwrap();
    let inv = SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .unwrap();
    let server = Server {
        id: ServerId("fixture-server".into()),
        address: "203.0.113.7".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![ProtocolId("fixture-declared-secrets".into())],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    };
    inv.add_server(&server).await.unwrap();
    (dir, inv, server)
}

async fn audit_ids(inv: &SqliteInventory) -> Vec<i64> {
    inv.recent_audit(100)
        .await
        .unwrap()
        .into_iter()
        .map(|row| row.id)
        .collect()
}

async fn assert_secret_audits(inv: &SqliteInventory, server: &Server, expected_keys: &[&str]) {
    let rows = inv.recent_audit(100).await.unwrap();
    let rows: Vec<_> = rows
        .iter()
        .filter(|row| row.action == "server.secret.set")
        .collect();
    assert_eq!(rows.len(), expected_keys.len());
    for key in expected_keys {
        let expected = Some(json!({ "key": key }));
        assert_eq!(rows.iter().filter(|row| row.payload == expected).count(), 1);
    }
    for row in rows {
        assert_eq!(row.actor, "system");
        assert_eq!(row.target.as_deref(), Some(server.id.0.as_str()));
        // The exact one-field payload checks above exclude secret values,
        // including public keys, rather than relying on a redaction heuristic.
    }
}

#[tokio::test]
async fn repeated_bootstrap_and_reopen_preserve_every_byte_and_emit_no_noop_audit() {
    let (dir, inv, server) = fixture().await;
    let registry = registry(specs(), None);
    let (first, minted) = bootstrap_server_secrets(&inv, &server, &registry)
        .await
        .unwrap();
    assert_eq!(minted, vec![PRIVATE, SEED]);
    assert_eq!(first.len(), 3);
    for key in [PRIVATE, PUBLIC, SEED] {
        assert_eq!(first[key].len(), 44);
        assert!(first[key].ends_with('='));
    }
    assert_secret_audits(&inv, &server, &[PRIVATE, PUBLIC, SEED]).await;
    let audit_before = audit_ids(&inv).await;
    let (second, minted) = bootstrap_server_secrets(&inv, &server, &registry)
        .await
        .unwrap();
    assert!(first == second, "repeat rotated a secret");
    assert!(minted.is_empty());
    assert_eq!(audit_ids(&inv).await, audit_before);
    inv.close().await;

    let inv = SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .unwrap();
    let (reopened, minted) = bootstrap_server_secrets(&inv, &server, &registry)
        .await
        .unwrap();
    assert!(first == reopened, "reopen rotated a secret");
    assert!(minted.is_empty());
    assert_eq!(audit_ids(&inv).await, audit_before);
}

#[tokio::test]
async fn either_partial_pair_fails_closed_without_mutation_or_audit() {
    for existing_key in [PRIVATE, PUBLIC] {
        let (_dir, inv, server) = fixture().await;
        inv.set_server_secret(&server.id, existing_key, "existing-test-placeholder")
            .await
            .unwrap();
        let before = inv.list_server_secrets(&server.id).await.unwrap();
        let audit_before = audit_ids(&inv).await;
        let result = bootstrap_server_secrets(&inv, &server, &registry(specs(), None)).await;
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("partial pair must be rejected"),
        };
        assert!(error.contains("incomplete server secret set"));
        assert!(error.contains(PRIVATE) && error.contains(PUBLIC));
        assert!(!error.contains("existing-test-placeholder"));
        assert!(before == inv.list_server_secrets(&server.id).await.unwrap());
        assert_eq!(audit_ids(&inv).await, audit_before);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_empty_snapshots_across_pools_return_one_coherent_winner() {
    let (dir, inv, server) = fixture().await;
    let other = SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .unwrap();
    let barrier = Arc::new(SnapshotRendezvous::default());
    let first_registry = registry(specs(), Some(Arc::clone(&barrier)));
    let second_registry = registry(specs(), Some(barrier));
    let first_inv = inv.clone();
    let first_server = server.clone();
    let mut first = tokio::spawn(async move {
        bootstrap_server_secrets(&first_inv, &first_server, &first_registry).await
    });
    let second_server = server.clone();
    let mut second = tokio::spawn(async move {
        bootstrap_server_secrets(&other, &second_server, &second_registry).await
    });
    // Bound BOTH handles together, including when one fails before reaching
    // the synchronous rendezvous. Its own timeout releases blocked workers;
    // an outer async timeout alone cannot interrupt a synchronous wait.
    let joined = tokio::time::timeout(Duration::from_secs(15), async {
        tokio::join!(&mut first, &mut second)
    })
    .await;
    let (first_result, second_result) = match joined {
        Ok(results) => results,
        Err(_) => {
            first.abort();
            second.abort();
            panic!("concurrent bootstrap tasks did not finish within 15 seconds");
        }
    };
    let (first, first_minted) = first_result.expect("first bootstrap task").unwrap();
    let (second, second_minted) = second_result.expect("second bootstrap task").unwrap();
    let persisted = inv.list_server_secrets(&server.id).await.unwrap();
    assert_eq!(persisted.len(), 3);
    assert!(vpnctl_crypto::wireguard_keypair_matches(
        &persisted[PRIVATE],
        &persisted[PUBLIC]
    ));
    assert!(
        first == second,
        "concurrent bootstraps returned different secrets"
    );
    assert!(
        first == persisted,
        "bootstrap did not return the stored winner"
    );
    for key in [PRIVATE, SEED] {
        assert_eq!(
            first_minted
                .iter()
                .chain(&second_minted)
                .filter(|k| **k == key)
                .count(),
            1,
            "only one caller may report minting {key}"
        );
    }
    assert_secret_audits(&inv, &server, &[PRIVATE, PUBLIC, SEED]).await;
}

#[tokio::test]
async fn existing_seed_is_preserved_when_pair_is_new() {
    let (_dir, inv, server) = fixture().await;
    let seed = vpnctl_crypto::gen_base64_key(32).unwrap();
    inv.set_server_secret(&server.id, SEED, &seed)
        .await
        .unwrap();
    let (secrets, minted) = bootstrap_server_secrets(&inv, &server, &registry(specs(), None))
        .await
        .unwrap();
    assert!(secrets[SEED] == seed);
    assert_eq!(minted, vec![PRIVATE]);
    assert_secret_audits(&inv, &server, &[PRIVATE, PUBLIC]).await;
}

#[tokio::test]
async fn existing_coherent_pair_is_preserved_when_seed_is_new() {
    let (_dir, inv, server) = fixture().await;
    let (private, public) = vpnctl_crypto::gen_wireguard_keypair();
    inv.set_server_secret(&server.id, PRIVATE, &private)
        .await
        .unwrap();
    inv.set_server_secret(&server.id, PUBLIC, &public)
        .await
        .unwrap();
    let (secrets, minted) = bootstrap_server_secrets(&inv, &server, &registry(specs(), None))
        .await
        .unwrap();
    assert!(secrets[PRIVATE] == private && secrets[PUBLIC] == public);
    assert_eq!(minted, vec![SEED]);
    assert_secret_audits(&inv, &server, &[SEED]).await;
}

#[tokio::test]
async fn audit_failure_rolls_back_the_entire_pair_or_seed() {
    for (declarations, rejected_key) in [
        (vec![specs().remove(0)], PUBLIC),
        (vec![specs().remove(1)], SEED),
    ] {
        let (dir, inv, server) = fixture().await;
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(SqliteConnectOptions::new().filename(dir.path().join("inv.db")))
            .await
            .unwrap();
        // For pairs, reject the SECOND audit: the first key and its audit have
        // already been inserted inside the transaction and must roll back too.
        sqlx::query(&format!(
            "CREATE TRIGGER reject_secret_audit BEFORE INSERT ON audit_log
             WHEN NEW.action = 'server.secret.set'
              AND json_extract(NEW.payload, '$.key') = '{rejected_key}'
             BEGIN SELECT RAISE(ABORT, 'fixture audit failure'); END"
        ))
        .execute(&pool)
        .await
        .unwrap();
        let audit_before = audit_ids(&inv).await;
        let result = bootstrap_server_secrets(&inv, &server, &registry(declarations, None)).await;
        assert!(result.is_err(), "audit failure must fail bootstrap");
        assert!(
            inv.list_server_secrets(&server.id)
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(audit_ids(&inv).await, audit_before);
        pool.close().await;
    }
}

#[tokio::test]
async fn fully_seeded_legacy_namespaces_are_returned_unchanged_without_audit() {
    let (_dir, inv, mut server) = fixture().await;
    server.kernels = vec![KernelId("amneziawg".into())];
    let declarations = vec![
        ServerSecretSpec::WireguardKeypair {
            private_key: "wireguard.server_private_key",
            public_key: "wireguard.server_public_key",
        },
        ServerSecretSpec::Base64Key {
            key: "ss2022.psk",
            key_bytes: 16,
        },
        ServerSecretSpec::X25519Keypair {
            private_key: "vless.private_key",
            public_key: "vless.public_key",
        },
        ServerSecretSpec::ShortId {
            key: "vless.short_id",
        },
        ServerSecretSpec::Password {
            key: "hysteria2.obfs.password",
            entropy_bytes: 24,
        },
    ];
    let mut expected = HashMap::new();
    for key in [
        "wireguard.server_private_key",
        "wireguard.server_public_key",
        "ss2022.psk",
        "vless.private_key",
        "vless.public_key",
        "vless.short_id",
        "hysteria2.obfs.password",
        "amneziawg.jc",
        "amneziawg.jmin",
        "amneziawg.jmax",
        "amneziawg.s1",
        "amneziawg.s2",
        "amneziawg.h1",
        "amneziawg.h2",
        "amneziawg.h3",
        "amneziawg.h4",
        "unrelated.fixture",
    ] {
        let value = format!("legacy-fixture-{key}");
        inv.set_server_secret(&server.id, key, &value)
            .await
            .unwrap();
        expected.insert(key.to_string(), value);
    }
    let audit_before = audit_ids(&inv).await;
    let (actual, minted) = bootstrap_server_secrets(&inv, &server, &registry(declarations, None))
        .await
        .unwrap();
    assert!(actual == expected, "legacy seeded map changed");
    assert!(minted.is_empty());
    assert_eq!(audit_ids(&inv).await, audit_before);
    assert!(expected == inv.list_server_secrets(&server.id).await.unwrap());
}
