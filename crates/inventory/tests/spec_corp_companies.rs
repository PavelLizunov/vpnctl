#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Company isolation contracts. All identities and credentials are synthetic.
use base64::{Engine as _, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};
use vpnctl_core::{Server, ServerId, User, UserId};
use vpnctl_inventory::{
    CorpCredentials, CorpPublication, CorpReaderToken, CorpSessionInput, CorpSetup, CorpSigningKey,
    CorpVerifiedEgress, SqliteInventory,
};

fn user(name: &str, uuid: &str) -> User {
    User {
        id: UserId(name.into()),
        uuid: uuid.into(),
        tuic_password: None,
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: None,
        vpn_router_device_id: None,
        disabled: false,
    }
}

fn setup(name: &str, policy: &str) -> CorpSetup {
    CorpSetup {
        user_id: UserId(name.into()), policy_id: policy.into(),
        credentials: CorpCredentials {
            password_phc: "$argon2id$v=19$m=19456,t=2,p=1$c3ludGhldGljc2FsdA$c3ludGhldGljaGFzaHN5bnRoZXRpY2hhc2g".into(),
            reader_tokens: vec![CorpReaderToken { id: "reader-1".into(), token: "r".repeat(43) }],
            signing_keys: vec![CorpSigningKey { id: "key-1".into(), pkcs8: STANDARD.encode([1u8; 48]), spki: STANDARD.encode([2u8; 44]) }],
            active_key_id: "key-1".into(),
        },
    }
}

fn session(byte: char) -> CorpSessionInput {
    CorpSessionInput {
        token_hash: byte.to_string().repeat(64),
        csrf_token: "c".repeat(43),
        expires_at: 1_700_003_600,
    }
}

fn credentials_json(credentials: &CorpCredentials) -> String {
    serde_json::json!({
        "password_phc":credentials.password_phc,"active_key_id":credentials.active_key_id,
        "reader_tokens":credentials.reader_tokens.iter().map(|reader| serde_json::json!({"id":reader.id,"token":reader.token})).collect::<Vec<_>>(),
        "signing_keys":credentials.signing_keys.iter().map(|key| serde_json::json!({"id":key.id,"pkcs8":key.pkcs8,"spki":key.spki})).collect::<Vec<_>>()
    }).to_string()
}

fn publication(
    policy: &str,
    marker: &str,
    expected_revision: u64,
    config: u64,
    phone: bool,
) -> CorpPublication {
    let rule = if phone {
        serde_json::json!({"type":"domain_suffix","value":format!("{marker}.example.invalid"),"action":"direct","comment":""})
    } else {
        serde_json::json!({"domain":format!("{marker}.example.invalid"),"action":"direct","comment":""})
    };
    let mut body = serde_json::json!({"schema":1,"policy_id":policy,"key_id":"key-1","revision":expected_revision+1,
        "published_at":1_700_000_000i64,"apply":"next_connection","rules":[rule]});
    if phone {
        body["kind"] = serde_json::json!("telephony");
    }
    let payload = serde_json::to_vec(&body).unwrap();
    let envelope = serde_json::to_vec(&serde_json::json!({"payload":STANDARD.encode(&payload),"signature":STANDARD.encode([3u8;64])})).unwrap();
    CorpPublication {
        expected_revision,
        expected_config_version: config,
        key_id: "key-1".into(),
        published_at: 1_700_000_000,
        payload_sha256: format!("{:x}", Sha256::digest(&payload)),
        payload,
        envelope,
    }
}

const POLICY_A: &str = "11111111-1111-4111-8111-111111111111";
const POLICY_B: &str = "22222222-2222-4222-8222-222222222222";

#[tokio::test]
async fn company_journals_sessions_egress_and_legacy_are_isolated() {
    let dir = tempfile::tempdir().unwrap();
    let db = SqliteInventory::open(&dir.path().join("inventory.db"))
        .await
        .unwrap();
    db.add_user(&user("alice", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"))
        .await
        .unwrap();
    db.add_user(&user("bob", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"))
        .await
        .unwrap();
    db.add_server(&Server {
        id: ServerId("server-1".into()),
        address: "192.0.2.1".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![],
        enabled_protocols: vec![],
        trusted_host_fingerprint: None,
        hoster: "fixture".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    })
    .await
    .unwrap();
    let a = db.corp_for("company-a");
    let b = db.corp_for("company-b");
    let sa = a
        .create_corp(&setup("alice", POLICY_A), "test")
        .await
        .unwrap();
    let sb = b
        .create_corp(&setup("bob", POLICY_B), "test")
        .await
        .unwrap();
    assert!(db.corp_record().await.unwrap().is_none());
    assert_eq!(
        db.corp_company_for_username("alice")
            .await
            .unwrap()
            .unwrap()
            .company_id,
        "company-a"
    );
    assert_eq!(
        db.corp_company_for_username("bob")
            .await
            .unwrap()
            .unwrap()
            .company_id,
        "company-b"
    );
    assert!(
        db.corp_company_for_username("Alice")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        db.corp_company_for_username(" alice")
            .await
            .unwrap()
            .is_none()
    );

    let sa = a
        .update_corp_security(
            sa.config_version,
            true,
            &setup("alice", POLICY_A).credentials,
            "test",
        )
        .await
        .unwrap();
    let sb = b
        .update_corp_security(
            sb.config_version,
            true,
            &setup("bob", POLICY_B).credentials,
            "test",
        )
        .await
        .unwrap();
    let site_a = publication(POLICY_A, "site-a", 0, sa.config_version, false);
    let site_b = publication(POLICY_B, "site-b", 0, sb.config_version, false);
    let phone_a = publication(POLICY_A, "phone-a", 0, sa.config_version, true);
    let phone_b = publication(POLICY_B, "phone-b", 0, sb.config_version, true);
    a.publish_corp_policy(&site_a, "test").await.unwrap();
    b.publish_corp_policy(&site_b, "test").await.unwrap();
    a.publish_corp_phone_policy(&phone_a, "test").await.unwrap();
    b.publish_corp_phone_policy(&phone_b, "test").await.unwrap();
    assert_eq!(
        a.corp_revision(1).await.unwrap().unwrap().envelope,
        site_a.envelope
    );
    assert_eq!(
        b.corp_current_policy(sb.config_version)
            .await
            .unwrap()
            .unwrap()
            .payload,
        site_b.payload
    );
    assert_eq!(
        a.corp_current_phone_policy(sa.config_version)
            .await
            .unwrap()
            .unwrap()
            .payload,
        phone_a.payload
    );
    assert_eq!(
        b.corp_phone_revision(1).await.unwrap().unwrap().envelope,
        phone_b.envelope
    );
    assert_eq!(a.corp_history(10).await.unwrap().len(), 1);
    assert_eq!(b.corp_phone_history(10).await.unwrap().len(), 1);
    let phone_a2 = publication(POLICY_A, "phone-a2", 1, sa.config_version, true);
    a.publish_corp_phone_policy(&phone_a2, "test")
        .await
        .unwrap();
    assert_eq!(
        a.corp_current_phone_policy(sa.config_version)
            .await
            .unwrap()
            .unwrap()
            .revision,
        2
    );
    assert_eq!(
        b.corp_current_phone_policy(sb.config_version)
            .await
            .unwrap()
            .unwrap()
            .revision,
        1
    );
    assert!(a.publish_corp_policy(&site_a, "test").await.is_err());
    assert!(a.publish_corp_phone_policy(&phone_a, "test").await.is_err());
    assert_eq!(
        b.corp_revision(1).await.unwrap().unwrap().payload,
        site_b.payload
    );
    assert_eq!(
        b.corp_phone_revision(1).await.unwrap().unwrap().payload,
        phone_b.payload
    );

    let egress = CorpVerifiedEgress {
        server_id: ServerId("server-1".into()),
        ip: "192.0.2.10".parse().unwrap(),
        configuration_fingerprint: "a".repeat(64),
        verified_at: 1_700_000_000,
    };
    let sa = a
        .replace_corp_egress(sa.config_version, &[egress], "test")
        .await
        .unwrap();
    assert_eq!(a.corp_verified_egress().await.unwrap().len(), 1);
    assert!(b.corp_verified_egress().await.unwrap().is_empty());
    assert!(
        a.replace_corp_egress(sa.config_version - 1, &[], "test")
            .await
            .is_err()
    );
    assert!(b.corp_verified_egress().await.unwrap().is_empty());

    // Enable each company before issuing sessions.
    let sa = a
        .update_corp_security(
            sa.config_version,
            true,
            &setup("alice", POLICY_A).credentials,
            "test",
        )
        .await
        .unwrap();
    let sb = b
        .update_corp_security(
            sb.config_version,
            true,
            &setup("bob", POLICY_B).credentials,
            "test",
        )
        .await
        .unwrap();
    let ta = session('a');
    let tb = session('b');
    a.issue_corp_session(sa.auth_generation, &ta, 1_700_000_001, "test")
        .await
        .unwrap();
    assert!(
        b.issue_corp_session(sb.auth_generation, &ta, 1_700_000_001, "test")
            .await
            .is_err()
    );
    b.issue_corp_session(sb.auth_generation, &tb, 1_700_000_001, "test")
        .await
        .unwrap();
    assert!(
        a.corp_session(&tb.token_hash, 1_700_000_001)
            .await
            .unwrap()
            .is_none()
    );
    assert!(!a.revoke_corp_session(&tb.token_hash, "test").await.unwrap());
    assert_eq!(
        db.corp_company_session(&tb.token_hash, 1_700_000_001)
            .await
            .unwrap()
            .unwrap()
            .company_id,
        "company-b"
    );
    a.update_corp_security(
        sa.config_version,
        false,
        &setup("alice", POLICY_A).credentials,
        "test",
    )
    .await
    .unwrap();
    assert!(
        a.corp_session(&ta.token_hash, 1_700_000_001)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        b.corp_session(&tb.token_hash, 1_700_000_001)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        db.corp_session(&tb.token_hash, 1_700_000_001)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn disabling_and_deleting_bound_users_only_revoke_their_own_sessions() {
    use sqlx::Connection as _;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("inventory.db");
    let db = SqliteInventory::open(&path).await.unwrap();
    db.add_user(&user("alice", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"))
        .await
        .unwrap();
    db.add_user(&user("bob", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"))
        .await
        .unwrap();
    let a = db.corp_for("company-a");
    let b = db.corp_for("company-b");
    let ca = setup("alice", POLICY_A);
    let cb = setup("bob", POLICY_B);
    let sa = a.create_corp(&ca, "test").await.unwrap();
    let sb = b.create_corp(&cb, "test").await.unwrap();
    let sa = a
        .update_corp_security(sa.config_version, true, &ca.credentials, "test")
        .await
        .unwrap();
    let sb = b
        .update_corp_security(sb.config_version, true, &cb.credentials, "test")
        .await
        .unwrap();
    let ta = session('a');
    let tb = session('b');
    a.issue_corp_session(sa.auth_generation, &ta, 1_700_000_001, "test")
        .await
        .unwrap();
    b.issue_corp_session(sb.auth_generation, &tb, 1_700_000_001, "test")
        .await
        .unwrap();
    let mut conn = sqlx::SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new().filename(&path),
    )
    .await
    .unwrap();
    sqlx::query("UPDATE users SET disabled = 1 WHERE id = 'alice'")
        .execute(&mut conn)
        .await
        .unwrap();
    assert!(
        a.corp_session(&ta.token_hash, 1_700_000_001)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        b.corp_session(&tb.token_hash, 1_700_000_001)
            .await
            .unwrap()
            .is_some()
    );
    sqlx::query("UPDATE users SET disabled = 0 WHERE id = 'alice'")
        .execute(&mut conn)
        .await
        .unwrap();
    let current = a.corp_record().await.unwrap().unwrap().status;
    a.issue_corp_session(current.auth_generation, &ta, 1_700_000_001, "test")
        .await
        .unwrap();
    sqlx::query("DELETE FROM users WHERE id = 'alice'")
        .execute(&mut conn)
        .await
        .unwrap();
    assert!(
        a.corp_session(&ta.token_hash, 1_700_000_001)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        b.corp_session(&tb.token_hash, 1_700_000_001)
            .await
            .unwrap()
            .is_some()
    );
    assert!(a.corp_record().await.unwrap().is_some());
    assert_eq!(
        b.corp_record().await.unwrap().unwrap().status.user_id.0,
        "bob"
    );
}

#[tokio::test]
async fn populated_pre0075_legacy_state_survives_migration() {
    use sqlx::{Connection as _, migrate::Migrate as _};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("old.db");
    let options = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(&path)
        .create_if_missing(true);
    let mut conn = sqlx::SqliteConnection::connect_with(&options)
        .await
        .unwrap();
    conn.ensure_migrations_table().await.unwrap();
    let migrator = sqlx::migrate!("./migrations");
    for migration in migrator.iter().filter(|m| m.version <= 74) {
        conn.apply(migration).await.unwrap();
    }
    let legacy = setup("alice", POLICY_A);
    let credentials = credentials_json(&legacy.credentials);
    let site = publication(POLICY_A, "old-site", 6, 9, false);
    let phone = publication(POLICY_A, "old-phone", 3, 9, true);
    let token = session('a');
    sqlx::query("INSERT INTO users (id, uuid) VALUES (?, ?)")
        .bind("alice")
        .bind("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
        .execute(&mut conn)
        .await
        .unwrap();
    sqlx::query("INSERT INTO corp_policy_settings (id,user_id,policy_id,enabled,auth_generation,config_version,revision,active_key_id,credentials_json) VALUES (1,?,?,1,5,9,7,'key-1',?)")
        .bind("alice").bind(POLICY_A).bind(&credentials).execute(&mut conn).await.unwrap();
    for (table, p, revision) in [
        ("corp_policy_revisions", &site, 7i64),
        ("corp_policy_phone_revisions", &phone, 4i64),
    ] {
        let query = format!(
            "INSERT INTO {table} (revision,key_id,published_at,payload_sha256,payload,envelope) VALUES (?,?,?,?,?,?)"
        );
        sqlx::query(&query)
            .bind(revision)
            .bind(&p.key_id)
            .bind(p.published_at)
            .bind(&p.payload_sha256)
            .bind(&p.payload)
            .bind(&p.envelope)
            .execute(&mut conn)
            .await
            .unwrap();
    }
    sqlx::query("UPDATE corp_policy_phone_settings SET revision = 4 WHERE id = 1")
        .execute(&mut conn)
        .await
        .unwrap();
    sqlx::query("INSERT INTO corp_policy_sessions (token_hash,csrf_token,expires_at,auth_generation) VALUES (?,?,?,5)")
        .bind(&token.token_hash).bind(&token.csrf_token).bind(token.expires_at).execute(&mut conn).await.unwrap();
    conn.close().await.unwrap();

    let db = SqliteInventory::open(&path).await.unwrap();
    let record = db.corp_record().await.unwrap().unwrap();
    assert_eq!(record.status.policy_id, POLICY_A);
    assert_eq!(
        (
            record.status.auth_generation,
            record.status.config_version,
            record.status.revision
        ),
        (5, 9, 7)
    );
    assert_eq!(record.credentials, legacy.credentials);
    let actual_site = db.corp_revision(7).await.unwrap().unwrap();
    let actual_phone = db.corp_phone_revision(4).await.unwrap().unwrap();
    assert_eq!(
        (actual_site.payload, actual_site.envelope),
        (site.payload, site.envelope)
    );
    assert_eq!(
        (actual_phone.payload, actual_phone.envelope),
        (phone.payload, phone.envelope)
    );
    let restored = db
        .corp_session(&token.token_hash, 1_700_000_001)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(restored.expires_at, token.expires_at);
    assert_eq!(restored.csrf_token, token.csrf_token);
    assert_eq!(
        db.corp_company_session(&token.token_hash, 1_700_000_001)
            .await
            .unwrap()
            .unwrap()
            .company_id,
        "legacy"
    );
    assert!(
        db.publish_corp_phone_policy(&publication(POLICY_A, "stale", 0, 9, true), "test")
            .await
            .is_err()
    );
    assert_eq!(
        db.corp_current_phone_policy(9)
            .await
            .unwrap()
            .unwrap()
            .revision,
        4
    );
}
