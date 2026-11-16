// Independent tests derived from docs/specs/corp-policy-store.md.
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod spec {
    use std::{net::IpAddr, path::PathBuf};

    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use sqlx::{Connection, Row, SqliteConnection, sqlite::SqliteConnectOptions};
    use tempfile::TempDir;
    use vpnctl_core::{Server, ServerId, User, UserId};
    use vpnctl_inventory::{
        CORP_MAX_REVISION, CorpCredentials, CorpPublication, CorpReaderToken, CorpSessionInput,
        CorpSetup, CorpSigningKey, CorpStatus, CorpStoreError, CorpVerifiedEgress, SqliteInventory,
    };

    const NOW: i64 = 1_794_657_600;
    const ACTOR: &str = "spec-operator";
    const PASSWORD: &str = "$argon2id$v=19$m=19456,t=2,p=1$c3BlYy1zYWx0$c3BlYy1wYXNzd29yZA";
    const READER: &str = "synthetic_reader_token_0123456789abcdef0123456789";
    const PRIVATE_KEY: &str = "c3ludGhldGljLXByaXZhdGUta2V5LWZvci1zdG9yYWdlLXRlc3Rz";
    const CSRF: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    struct State {
        _dir: TempDir,
        path: PathBuf,
        inv: SqliteInventory,
    }

    fn user() -> User {
        User {
            id: UserId("corp-spec-user".to_owned()),
            uuid: "01234567-89ab-4cde-8fab-0123456789ab".to_owned(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: false,
        }
    }

    fn server() -> Server {
        Server {
            id: ServerId("corp-spec-server".to_owned()),
            address: "192.0.2.10".to_owned(),
            ssh_port: 22,
            ssh_user: "root".to_owned(),
            kernels: Vec::new(),
            enabled_protocols: Vec::new(),
            trusted_host_fingerprint: None,
            hoster: "synthetic".to_owned(),
            jump_via: None,
            usage_coefficient: 1.0,
        }
    }

    fn credentials() -> CorpCredentials {
        CorpCredentials {
            password_phc: PASSWORD.to_owned(),
            reader_tokens: vec![CorpReaderToken {
                id: "reader-1".to_owned(),
                token: READER.to_owned(),
            }],
            signing_keys: vec![CorpSigningKey {
                id: "key-1".to_owned(),
                pkcs8: PRIVATE_KEY.to_owned(),
                spki: "c3ludGhldGljLXB1YmxpYy1rZXk=".to_owned(),
            }],
            active_key_id: "key-1".to_owned(),
        }
    }

    fn setup() -> CorpSetup {
        CorpSetup {
            user_id: user().id,
            policy_id: "spec-policy".to_owned(),
            credentials: credentials(),
        }
    }

    async fn state() -> State {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("inventory.db");
        let inv = SqliteInventory::open(&path).await.unwrap();
        inv.add_user(&user()).await.unwrap();
        State {
            _dir: dir,
            path,
            inv,
        }
    }

    async fn enabled_state() -> (State, CorpStatus) {
        let state = state().await;
        let status = state.inv.create_corp(&setup(), ACTOR).await.unwrap();
        let enabled = state
            .inv
            .update_corp_security(status.config_version, true, &credentials(), ACTOR)
            .await
            .unwrap();
        (state, enabled)
    }

    async fn sql_connection(state: &State) -> SqliteConnection {
        SqliteConnection::connect_with(&SqliteConnectOptions::new().filename(&state.path))
            .await
            .unwrap()
    }

    async fn audit_count(state: &State) -> i64 {
        let mut connection = sql_connection(state).await;
        sqlx::query_scalar("SELECT COUNT(*) FROM audit_log")
            .fetch_one(&mut connection)
            .await
            .unwrap()
    }

    async fn fail_audit(state: &State) {
        let mut connection = sql_connection(state).await;
        sqlx::query("CREATE TRIGGER spec_reject_audit BEFORE INSERT ON audit_log BEGIN SELECT RAISE(ABORT, 'synthetic audit failure'); END")
            .execute(&mut connection).await.unwrap();
    }

    async fn allow_audit(state: &State) {
        let mut connection = sql_connection(state).await;
        sqlx::query("DROP TRIGGER spec_reject_audit")
            .execute(&mut connection)
            .await
            .unwrap();
    }

    fn status_snapshot(status: &CorpStatus) -> (String, String, bool, u64, u64, u64, String) {
        (
            status.user_id.0.clone(),
            status.policy_id.clone(),
            status.enabled,
            status.auth_generation,
            status.config_version,
            status.revision,
            status.active_key_id.clone(),
        )
    }

    fn session(number: u64, expires_at: i64) -> CorpSessionInput {
        CorpSessionInput {
            token_hash: format!("{number:064x}"),
            csrf_token: CSRF.to_owned(),
            expires_at,
        }
    }

    fn bind_publication_bytes(publication: &mut CorpPublication) {
        publication.payload_sha256 = format!("{:x}", Sha256::digest(&publication.payload));
        // Storage validates the byte binding; signature verification belongs to the daemon.
        publication.envelope = format!(
            " {{ \"signature\": \"{}\", \"payload\": \"{}\" }} ",
            STANDARD.encode([0xfb_u8; 64]),
            STANDARD.encode(&publication.payload),
        )
        .into_bytes();
    }

    fn publication(status: &CorpStatus) -> CorpPublication {
        let payload = format!(
            " {{\"schema\":1,\"policy_id\":\"{}\",\"key_id\":\"{}\",\"revision\":{},\"published_at\":{},\"apply\":\"now\",\"rules\":[]}} ",
            status.policy_id, status.active_key_id, status.revision + 1, NOW,
        ).into_bytes();
        let mut publication = CorpPublication {
            expected_revision: status.revision,
            expected_config_version: status.config_version,
            key_id: status.active_key_id.clone(),
            published_at: NOW,
            payload_sha256: String::new(),
            payload,
            envelope: Vec::new(),
        };
        bind_publication_bytes(&mut publication);
        publication
    }

    async fn published_state() -> (State, CorpStatus) {
        let (state, status) = enabled_state().await;
        state
            .inv
            .publish_corp_policy(&publication(&status), ACTOR)
            .await
            .unwrap();
        let status = state.inv.corp_record().await.unwrap().unwrap().status;
        (state, status)
    }

    async fn assert_invalid_publication_unchanged(state: &State, publication: &CorpPublication) {
        let before = state.inv.corp_record().await.unwrap().unwrap().status;
        let history_before = state.inv.corp_history(100).await.unwrap();
        let audit_before = audit_count(state).await;
        assert!(matches!(
            state.inv.publish_corp_policy(publication, ACTOR).await,
            Err(CorpStoreError::InvalidInput(_))
        ));
        let after = state.inv.corp_record().await.unwrap().unwrap().status;
        assert_eq!(status_snapshot(&after), status_snapshot(&before));
        let history_after = state.inv.corp_history(100).await.unwrap();
        assert_eq!(history_after.len(), history_before.len());
        for (after, before) in history_after.iter().zip(&history_before) {
            assert_eq!(after.revision, before.revision);
            assert_eq!(after.key_id, before.key_id);
            assert_eq!(after.published_at, before.published_at);
            assert_eq!(after.payload_sha256, before.payload_sha256);
            assert_eq!(after.payload, before.payload);
            assert_eq!(after.envelope, before.envelope);
        }
        assert_eq!(audit_count(state).await, audit_before);
    }

    fn egress(ip: &str) -> CorpVerifiedEgress {
        CorpVerifiedEgress {
            server_id: server().id,
            ip: ip.parse::<IpAddr>().unwrap(),
            configuration_fingerprint: "a".repeat(64),
            verified_at: NOW,
        }
    }

    #[tokio::test]
    async fn singleton_starts_disabled_and_survives_database_reopen() {
        let state = state().await;
        assert!(state.inv.corp_record().await.unwrap().is_none());
        assert!(state.inv.corp_verified_egress().await.unwrap().is_empty());
        assert!(state.inv.corp_history(100).await.unwrap().is_empty());
        let before = audit_count(&state).await;
        let status = state.inv.create_corp(&setup(), ACTOR).await.unwrap();
        assert_eq!(status.user_id.0, "corp-spec-user");
        assert_eq!(status.policy_id, "spec-policy");
        assert!(!status.enabled);
        assert_eq!(
            (
                status.revision,
                status.config_version,
                status.auth_generation
            ),
            (0, 1, 1)
        );
        assert_eq!(status.active_key_id, "key-1");
        assert_eq!(audit_count(&state).await, before + 1);
        assert!(matches!(
            state.inv.create_corp(&setup(), ACTOR).await,
            Err(CorpStoreError::Conflict)
        ));
        assert_eq!(audit_count(&state).await, before + 1);
        let reopened = SqliteInventory::open(&state.path).await.unwrap();
        let restored = reopened.corp_record().await.unwrap().unwrap();
        assert_eq!(status_snapshot(&restored.status), status_snapshot(&status));
        assert_eq!(restored.credentials.password_phc, PASSWORD);
        assert_eq!(restored.credentials.reader_tokens[0].token, READER);
        assert_eq!(restored.credentials.signing_keys[0].pkcs8, PRIVATE_KEY);
        assert!(matches!(
            reopened.corp_current_policy(status.config_version).await,
            Err(CorpStoreError::Unavailable)
        ));
    }

    #[tokio::test]
    async fn create_requires_existing_enabled_user_and_rolls_back_if_audit_fails() {
        let state = state().await;
        let mut missing = setup();
        missing.user_id = UserId("missing".to_owned());
        assert!(state.inv.create_corp(&missing, ACTOR).await.is_err());
        state.inv.set_user_disabled(&user().id, true).await.unwrap();
        assert!(state.inv.create_corp(&setup(), ACTOR).await.is_err());
        state
            .inv
            .set_user_disabled(&user().id, false)
            .await
            .unwrap();
        let before = audit_count(&state).await;
        fail_audit(&state).await;
        assert!(state.inv.create_corp(&setup(), ACTOR).await.is_err());
        assert!(state.inv.corp_record().await.unwrap().is_none());
        assert_eq!(audit_count(&state).await, before);
        allow_audit(&state).await;
        assert_eq!(
            state
                .inv
                .create_corp(&setup(), ACTOR)
                .await
                .unwrap()
                .revision,
            0
        );
    }

    #[tokio::test]
    async fn setup_rejects_invalid_identity_actor_and_credentials_without_mutation() {
        let state = state().await;
        let before = audit_count(&state).await;
        for id in [
            "".to_owned(),
            "x".repeat(65),
            "bad/name".to_owned(),
            "политика".to_owned(),
        ] {
            let mut invalid = setup();
            invalid.policy_id = id;
            assert!(state.inv.create_corp(&invalid, ACTOR).await.is_err());
        }
        for actor in [
            "".to_owned(),
            "x".repeat(129),
            "a\nb".to_owned(),
            "é".repeat(65),
        ] {
            assert!(state.inv.create_corp(&setup(), &actor).await.is_err());
        }
        let mut invalid_credentials = Vec::new();
        let mut c = credentials();
        c.password_phc = "$argon2id$short".to_owned();
        invalid_credentials.push(c);
        let mut c = credentials();
        c.password_phc = "a".repeat(64);
        invalid_credentials.push(c);
        let mut c = credentials();
        c.password_phc = format!("$argon2id${}", "x".repeat(504));
        invalid_credentials.push(c);
        let mut c = credentials();
        c.reader_tokens.clear();
        invalid_credentials.push(c);
        let mut c = credentials();
        c.reader_tokens[0].token = "a".repeat(31);
        invalid_credentials.push(c);
        let mut c = credentials();
        c.reader_tokens[0].token = "a".repeat(513);
        invalid_credentials.push(c);
        let mut c = credentials();
        c.reader_tokens[0].token = "contains a space and has over 32 bytes".to_owned();
        invalid_credentials.push(c);
        let mut c = credentials();
        c.reader_tokens.push(c.reader_tokens[0].clone());
        invalid_credentials.push(c);
        let mut c = credentials();
        c.reader_tokens.push(CorpReaderToken {
            id: "reader-2".to_owned(),
            token: READER.to_owned(),
        });
        invalid_credentials.push(c);
        let mut c = credentials();
        c.signing_keys.clear();
        invalid_credentials.push(c);
        let mut c = credentials();
        c.signing_keys.push(c.signing_keys[0].clone());
        invalid_credentials.push(c);
        let mut c = credentials();
        let mut duplicate_spki = c.signing_keys[0].clone();
        duplicate_spki.id = "key-2".to_owned();
        c.signing_keys.push(duplicate_spki);
        invalid_credentials.push(c);
        let mut c = credentials();
        c.active_key_id = "absent".to_owned();
        invalid_credentials.push(c);
        let mut c = credentials();
        c.signing_keys[0].pkcs8.clear();
        invalid_credentials.push(c);
        let mut c = credentials();
        c.signing_keys[0].pkcs8 = "A".repeat(8196);
        invalid_credentials.push(c);
        let mut c = credentials();
        c.signing_keys[0].spki = "A".repeat(2052);
        invalid_credentials.push(c);
        let mut c = credentials();
        c.signing_keys[0].spki = "not base64!".to_owned();
        invalid_credentials.push(c);
        for credentials in invalid_credentials {
            let mut invalid = setup();
            invalid.credentials = credentials;
            assert!(state.inv.create_corp(&invalid, ACTOR).await.is_err());
            assert!(state.inv.corp_record().await.unwrap().is_none());
        }
        assert_eq!(audit_count(&state).await, before);
    }

    #[tokio::test]
    async fn overlap_and_storage_length_boundaries_allow_maximum_then_reject_excess() {
        let state = state().await;
        let mut input = setup();
        input.policy_id = "p".repeat(64);
        input.credentials.password_phc =
            format!("$argon2id${}", "x".repeat(512 - "$argon2id$".len()));
        input.credentials.reader_tokens = vec![
            CorpReaderToken {
                id: "r".repeat(64),
                token: "a".repeat(32),
            },
            CorpReaderToken {
                id: "reader-2".to_owned(),
                token: "b".repeat(512),
            },
        ];
        input.credentials.signing_keys = (0..4)
            .map(|n| CorpSigningKey {
                id: format!("key-{n}"),
                pkcs8: "A".repeat(8192),
                spki: char::from(b'A' + n).to_string().repeat(2048),
            })
            .collect();
        input.credentials.active_key_id = "key-0".to_owned();
        let status = state
            .inv
            .create_corp(&input, &"é".repeat(64))
            .await
            .unwrap();
        let before = audit_count(&state).await;
        let mut too_many_readers = input.credentials.clone();
        too_many_readers.reader_tokens.push(CorpReaderToken {
            id: "reader-3".to_owned(),
            token: "c".repeat(32),
        });
        assert!(
            state
                .inv
                .update_corp_security(status.config_version, false, &too_many_readers, ACTOR)
                .await
                .is_err()
        );
        let mut too_many_signers = input.credentials.clone();
        too_many_signers.signing_keys.push(CorpSigningKey {
            id: "key-5".to_owned(),
            pkcs8: "AQID".to_owned(),
            spki: "BAUG".to_owned(),
        });
        assert!(
            state
                .inv
                .update_corp_security(status.config_version, false, &too_many_signers, ACTOR)
                .await
                .is_err()
        );
        assert_eq!(audit_count(&state).await, before);
        assert_eq!(
            state
                .inv
                .corp_record()
                .await
                .unwrap()
                .unwrap()
                .credentials
                .reader_tokens
                .len(),
            2
        );
    }

    #[tokio::test]
    async fn security_noop_preserves_sessions_and_change_increments_both_generations_once() {
        let (state, status) = enabled_state().await;
        let input = session(1, NOW + 3600);
        state
            .inv
            .issue_corp_session(status.auth_generation, &input, NOW, ACTOR)
            .await
            .unwrap();
        let before = audit_count(&state).await;
        let unchanged = state
            .inv
            .update_corp_security(status.config_version, true, &credentials(), ACTOR)
            .await
            .unwrap();
        assert_eq!(status_snapshot(&unchanged), status_snapshot(&status));
        assert_eq!(audit_count(&state).await, before);
        assert!(
            state
                .inv
                .corp_session(&input.token_hash, NOW)
                .await
                .unwrap()
                .is_some()
        );
        let mut rotated = credentials();
        rotated.reader_tokens[0].token = "rotated_reader_0123456789abcdef0123456789".to_owned();
        let changed = state
            .inv
            .update_corp_security(status.config_version, true, &rotated, ACTOR)
            .await
            .unwrap();
        assert_eq!(changed.config_version, status.config_version + 1);
        assert_eq!(changed.auth_generation, status.auth_generation + 1);
        assert_eq!(changed.policy_id, status.policy_id);
        assert_eq!(changed.revision, status.revision);
        assert_eq!(audit_count(&state).await, before + 1);
        assert!(
            state
                .inv
                .corp_session(&input.token_hash, NOW)
                .await
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            state
                .inv
                .update_corp_security(status.config_version, true, &credentials(), ACTOR)
                .await,
            Err(CorpStoreError::Conflict)
        ));
        assert!(matches!(
            state
                .inv
                .issue_corp_session(status.auth_generation, &session(2, NOW + 3600), NOW, ACTOR)
                .await,
            Err(CorpStoreError::Conflict)
        ));
    }

    #[tokio::test]
    async fn failed_security_audit_restores_credentials_generations_and_existing_session() {
        let (state, status) = enabled_state().await;
        let input = session(3, NOW + 3600);
        state
            .inv
            .issue_corp_session(status.auth_generation, &input, NOW, ACTOR)
            .await
            .unwrap();
        let before = audit_count(&state).await;
        fail_audit(&state).await;
        let mut rotated = credentials();
        rotated.password_phc.push('x');
        assert!(
            state
                .inv
                .update_corp_security(status.config_version, false, &rotated, ACTOR)
                .await
                .is_err()
        );
        let record = state.inv.corp_record().await.unwrap().unwrap();
        assert_eq!(status_snapshot(&record.status), status_snapshot(&status));
        assert_eq!(record.credentials.password_phc, PASSWORD);
        assert!(
            state
                .inv
                .corp_session(&input.token_hash, NOW)
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(audit_count(&state).await, before);
    }

    #[tokio::test]
    async fn egress_replacement_is_cas_canonicalizes_mapped_ip_and_revokes_sessions() {
        let (state, status) = enabled_state().await;
        state.inv.add_server(&server()).await.unwrap();
        assert!(state.inv.corp_verified_egress().await.unwrap().is_empty());
        let login = session(4, NOW + 3600);
        state
            .inv
            .issue_corp_session(status.auth_generation, &login, NOW, ACTOR)
            .await
            .unwrap();
        let before = audit_count(&state).await;
        let changed = state
            .inv
            .replace_corp_egress(status.config_version, &[egress("::ffff:192.0.2.25")], ACTOR)
            .await
            .unwrap();
        let stored = state.inv.corp_verified_egress().await.unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].ip, "192.0.2.25".parse::<IpAddr>().unwrap());
        assert_eq!(stored[0].configuration_fingerprint, "a".repeat(64));
        assert_eq!(stored[0].verified_at, NOW);
        assert_eq!(changed.config_version, status.config_version + 1);
        assert_eq!(changed.auth_generation, status.auth_generation + 1);
        assert!(
            state
                .inv
                .corp_session(&login.token_hash, NOW)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(audit_count(&state).await, before + 1);
        let same = state
            .inv
            .replace_corp_egress(changed.config_version, &[egress("192.0.2.25")], ACTOR)
            .await
            .unwrap();
        assert_eq!(status_snapshot(&same), status_snapshot(&changed));
        assert_eq!(audit_count(&state).await, before + 1);
        assert!(matches!(
            state
                .inv
                .replace_corp_egress(status.config_version, &[], ACTOR)
                .await,
            Err(CorpStoreError::Conflict)
        ));
        let cleared = state
            .inv
            .replace_corp_egress(changed.config_version, &[], ACTOR)
            .await
            .unwrap();
        assert_eq!(cleared.config_version, changed.config_version + 1);
        assert!(state.inv.corp_verified_egress().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn egress_rejects_missing_servers_duplicates_invalid_fingerprints_and_time() {
        let (state, status) = enabled_state().await;
        state.inv.add_server(&server()).await.unwrap();
        let before = audit_count(&state).await;
        let mut invalid = Vec::new();
        let mut entry = egress("192.0.2.1");
        entry.server_id = ServerId("absent".to_owned());
        invalid.push(vec![entry]);
        invalid.push(vec![egress("192.0.2.1"), egress("::ffff:192.0.2.1")]);
        for fingerprint in ["A".repeat(64), "a".repeat(63), "g".repeat(64)] {
            let mut entry = egress("192.0.2.1");
            entry.configuration_fingerprint = fingerprint;
            invalid.push(vec![entry]);
        }
        for time in [0, -1, 253_402_300_800] {
            let mut entry = egress("192.0.2.1");
            entry.verified_at = time;
            invalid.push(vec![entry]);
        }
        for entries in invalid {
            assert!(
                state
                    .inv
                    .replace_corp_egress(status.config_version, &entries, ACTOR)
                    .await
                    .is_err()
            );
        }
        assert_eq!(audit_count(&state).await, before);
        let mut valid = egress("2001:db8::1");
        valid.verified_at = 253_402_300_799;
        let changed = state
            .inv
            .replace_corp_egress(status.config_version, &[valid], ACTOR)
            .await
            .unwrap();
        fail_audit(&state).await;
        assert!(
            state
                .inv
                .replace_corp_egress(changed.config_version, &[], ACTOR)
                .await
                .is_err()
        );
        let stored = state.inv.corp_verified_egress().await.unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].ip, "2001:db8::1".parse::<IpAddr>().unwrap());
    }

    #[tokio::test]
    async fn egress_allows_512_unique_addresses_and_rejects_513_without_changes() {
        let (state, status) = enabled_state().await;
        state.inv.add_server(&server()).await.unwrap();
        let mut entries: Vec<_> = (0..512)
            .map(|i| egress(&format!("2001:db8::{i:x}")))
            .collect();
        let changed = state
            .inv
            .replace_corp_egress(status.config_version, &entries, ACTOR)
            .await
            .unwrap();
        assert_eq!(state.inv.corp_verified_egress().await.unwrap().len(), 512);
        entries.push(egress("2001:db8::ffff"));
        assert!(
            state
                .inv
                .replace_corp_egress(changed.config_version, &entries, ACTOR)
                .await
                .is_err()
        );
        assert_eq!(state.inv.corp_verified_egress().await.unwrap().len(), 512);
    }

    #[tokio::test]
    async fn sessions_enforce_expiration_boundaries_duplicate_digests_and_single_revoke_audit() {
        let (state, status) = enabled_state().await;
        assert!(
            state
                .inv
                .corp_session(&format!("{:064x}", 99), NOW)
                .await
                .unwrap()
                .is_none()
        );
        for (number, duration) in [(5, 1), (6, 86_400)] {
            let input = session(number, NOW + duration);
            state
                .inv
                .issue_corp_session(status.auth_generation, &input, NOW, ACTOR)
                .await
                .unwrap();
            let stored = state
                .inv
                .corp_session(&input.token_hash, NOW)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(stored.auth_generation, status.auth_generation);
            assert_eq!(stored.config_version, status.config_version);
            assert_eq!(stored.csrf_token, CSRF);
            assert_eq!(stored.expires_at, NOW + duration);
            assert!(
                state
                    .inv
                    .corp_session(&input.token_hash, NOW + duration)
                    .await
                    .unwrap()
                    .is_none()
            );
        }
        let input = session(7, NOW + 3600);
        state
            .inv
            .issue_corp_session(status.auth_generation, &input, NOW, ACTOR)
            .await
            .unwrap();
        assert!(matches!(
            state
                .inv
                .issue_corp_session(status.auth_generation, &input, NOW, ACTOR)
                .await,
            Err(CorpStoreError::Conflict)
        ));
        let before = audit_count(&state).await;
        assert!(
            state
                .inv
                .revoke_corp_session(&input.token_hash, ACTOR)
                .await
                .unwrap()
        );
        assert_eq!(audit_count(&state).await, before + 1);
        assert!(
            state
                .inv
                .corp_session(&input.token_hash, NOW)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            !state
                .inv
                .revoke_corp_session(&input.token_hash, ACTOR)
                .await
                .unwrap()
        );
        assert_eq!(audit_count(&state).await, before + 1);
    }

    #[tokio::test]
    async fn sessions_reject_bad_hash_csrf_clock_lifetime_and_stale_generation() {
        let (state, status) = enabled_state().await;
        let before = audit_count(&state).await;
        for hash in [
            "a".repeat(63),
            "A".repeat(64),
            "g".repeat(64),
            "a".repeat(65),
        ] {
            let mut input = session(8, NOW + 3600);
            input.token_hash = hash;
            assert!(
                state
                    .inv
                    .issue_corp_session(status.auth_generation, &input, NOW, ACTOR)
                    .await
                    .is_err()
            );
        }
        for csrf in [
            "A".repeat(42),
            "A".repeat(44),
            format!("{}=", "A".repeat(42)),
            format!("{}+", "A".repeat(42)),
            format!("{}B", "A".repeat(42)),
        ] {
            let mut input = session(8, NOW + 3600);
            input.csrf_token = csrf;
            assert!(
                state
                    .inv
                    .issue_corp_session(status.auth_generation, &input, NOW, ACTOR)
                    .await
                    .is_err()
            );
        }
        for expires_at in [NOW - 1, NOW, NOW + 86_401] {
            assert!(
                state
                    .inv
                    .issue_corp_session(status.auth_generation, &session(8, expires_at), NOW, ACTOR)
                    .await
                    .is_err()
            );
        }
        for now in [0, -1, 253_402_300_800] {
            assert!(
                state
                    .inv
                    .issue_corp_session(status.auth_generation, &session(8, now + 1), now, ACTOR)
                    .await
                    .is_err()
            );
        }
        assert!(matches!(
            state
                .inv
                .issue_corp_session(status.auth_generation + 1, &session(8, NOW + 1), NOW, ACTOR)
                .await,
            Err(CorpStoreError::Conflict)
        ));
        assert_eq!(audit_count(&state).await, before);
    }

    #[tokio::test]
    async fn sessions_cap_at_128_and_expired_sessions_are_reclaimed_during_issue() {
        let (state, status) = enabled_state().await;
        for number in 0..128 {
            state
                .inv
                .issue_corp_session(
                    status.auth_generation,
                    &session(number, NOW + 1),
                    NOW,
                    ACTOR,
                )
                .await
                .unwrap();
        }
        let before = audit_count(&state).await;
        assert!(
            state
                .inv
                .issue_corp_session(status.auth_generation, &session(128, NOW + 2), NOW, ACTOR)
                .await
                .is_err()
        );
        assert_eq!(audit_count(&state).await, before);
        state
            .inv
            .issue_corp_session(
                status.auth_generation,
                &session(129, NOW + 2),
                NOW + 1,
                ACTOR,
            )
            .await
            .unwrap();
        assert_eq!(audit_count(&state).await, before + 1);
        assert!(
            state
                .inv
                .corp_session(&session(0, NOW + 1).token_hash, NOW + 1)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            state
                .inv
                .corp_session(&session(129, NOW + 2).token_hash, NOW + 1)
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn revoke_all_changes_both_generations_even_without_sessions_and_rolls_back_on_audit_failure()
     {
        let (state, status) = enabled_state().await;
        let before = audit_count(&state).await;
        let changed = state
            .inv
            .revoke_corp_sessions(status.config_version, ACTOR)
            .await
            .unwrap();
        assert_eq!(changed.auth_generation, status.auth_generation + 1);
        assert_eq!(changed.config_version, status.config_version + 1);
        assert_eq!(audit_count(&state).await, before + 1);
        assert!(matches!(
            state
                .inv
                .revoke_corp_sessions(status.config_version, ACTOR)
                .await,
            Err(CorpStoreError::Conflict)
        ));
        let input = session(10, NOW + 3600);
        state
            .inv
            .issue_corp_session(changed.auth_generation, &input, NOW, ACTOR)
            .await
            .unwrap();
        fail_audit(&state).await;
        assert!(
            state
                .inv
                .revoke_corp_sessions(changed.config_version, ACTOR)
                .await
                .is_err()
        );
        assert!(
            state
                .inv
                .corp_session(&input.token_hash, NOW)
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(
            status_snapshot(&state.inv.corp_record().await.unwrap().unwrap().status),
            status_snapshot(&changed)
        );
        assert!(
            state
                .inv
                .revoke_corp_session(&input.token_hash, ACTOR)
                .await
                .is_err()
        );
        assert!(
            state
                .inv
                .corp_session(&input.token_hash, NOW)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            state
                .inv
                .issue_corp_session(
                    changed.auth_generation,
                    &session(11, NOW + 3600),
                    NOW,
                    ACTOR
                )
                .await
                .is_err()
        );
        assert!(
            state
                .inv
                .corp_session(&session(11, NOW + 3600).token_hash, NOW)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn disabled_user_invalidates_sessions_permanently_and_allows_secret_repair() {
        let (state, status) = enabled_state().await;
        let input = session(12, NOW + 3600);
        state
            .inv
            .issue_corp_session(status.auth_generation, &input, NOW, ACTOR)
            .await
            .unwrap();
        state.inv.set_user_disabled(&user().id, true).await.unwrap();
        assert!(
            state
                .inv
                .corp_session(&input.token_hash, NOW)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            state
                .inv
                .issue_corp_session(status.auth_generation, &session(13, NOW + 3600), NOW, ACTOR)
                .await
                .is_err()
        );
        let current = state.inv.corp_record().await.unwrap().unwrap().status;
        assert!(
            state
                .inv
                .update_corp_security(current.config_version, true, &credentials(), ACTOR)
                .await
                .is_err()
        );
        let mut repaired = credentials();
        repaired.password_phc.push('x');
        let disabled = state
            .inv
            .update_corp_security(current.config_version, false, &repaired, ACTOR)
            .await
            .unwrap();
        assert!(!disabled.enabled);
        state
            .inv
            .set_user_disabled(&user().id, false)
            .await
            .unwrap();
        assert!(
            state
                .inv
                .corp_session(&input.token_hash, NOW)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            state
                .inv
                .corp_record()
                .await
                .unwrap()
                .unwrap()
                .status
                .auth_generation
                > status.auth_generation
        );
    }

    #[tokio::test]
    async fn publication_retains_exact_bytes_metadata_and_durable_current_history() {
        let (state, status) = enabled_state().await;
        assert!(
            state
                .inv
                .corp_current_policy(status.config_version)
                .await
                .unwrap()
                .is_none()
        );
        let input = publication(&status);
        let before = audit_count(&state).await;
        let revision = state.inv.publish_corp_policy(&input, ACTOR).await.unwrap();
        assert_eq!(revision.revision, 1);
        assert_eq!(revision.key_id, status.active_key_id);
        assert_eq!(revision.published_at, NOW);
        assert_eq!(revision.payload_sha256, input.payload_sha256);
        assert_eq!(revision.payload, input.payload);
        assert_eq!(revision.envelope, input.envelope);
        assert_eq!(audit_count(&state).await, before + 1);
        let current = state
            .inv
            .corp_current_policy(status.config_version)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(current.payload, input.payload);
        assert_eq!(current.envelope, input.envelope);
        assert_eq!(
            state.inv.corp_revision(1).await.unwrap().unwrap().payload,
            input.payload
        );
        assert!(state.inv.corp_revision(999).await.unwrap().is_none());
        assert_eq!(state.inv.corp_history(1).await.unwrap()[0].revision, 1);
        let reopened = SqliteInventory::open(&state.path).await.unwrap();
        assert_eq!(
            reopened
                .corp_current_policy(status.config_version)
                .await
                .unwrap()
                .unwrap()
                .envelope,
            input.envelope
        );
        assert_eq!(
            reopened
                .corp_record()
                .await
                .unwrap()
                .unwrap()
                .status
                .revision,
            1
        );
        assert_eq!(CORP_MAX_REVISION, 9_007_199_254_740_991);
    }

    #[tokio::test]
    async fn concurrent_publication_cas_allows_exactly_one_writer_and_one_audit() {
        let (state, status) = enabled_state().await;
        let first = publication(&status);
        let mut second = publication(&status);
        second.payload = String::from_utf8(second.payload)
            .unwrap()
            .replace("\"now\"", "\"next_connection\"")
            .into_bytes();
        bind_publication_bytes(&mut second);
        let before = audit_count(&state).await;
        let (a, b) = tokio::join!(
            state.inv.publish_corp_policy(&first, ACTOR),
            state.inv.publish_corp_policy(&second, ACTOR)
        );
        assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
        assert!(matches!(
            (&a, &b),
            (Ok(_), Err(CorpStoreError::Conflict)) | (Err(CorpStoreError::Conflict), Ok(_))
        ));
        assert_eq!(audit_count(&state).await, before + 1);
        assert_eq!(
            state
                .inv
                .corp_record()
                .await
                .unwrap()
                .unwrap()
                .status
                .revision,
            1
        );
        assert_eq!(state.inv.corp_history(100).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn publications_reject_stale_config_revision_signer_and_mismatched_metadata() {
        let (state, status) = enabled_state().await;
        let before = audit_count(&state).await;
        let original = publication(&status);
        let mut invalid = Vec::new();
        let mut p = original.clone();
        p.expected_config_version += 1;
        invalid.push(p);
        let mut p = original.clone();
        p.expected_revision += 1;
        invalid.push(p);
        let mut p = original.clone();
        p.expected_revision = CORP_MAX_REVISION;
        invalid.push(p);
        let mut p = original.clone();
        p.key_id = "other-key".to_owned();
        invalid.push(p);
        let mut p = original.clone();
        p.payload.clear();
        bind_publication_bytes(&mut p);
        invalid.push(p);
        let mut p = original.clone();
        p.payload = vec![b' '; 49_153];
        bind_publication_bytes(&mut p);
        invalid.push(p);
        let mut p = original.clone();
        p.envelope.clear();
        invalid.push(p);
        let mut p = original.clone();
        p.envelope = vec![b' '; 65_537];
        invalid.push(p);
        let mut p = original.clone();
        p.envelope = b"[]".to_vec();
        invalid.push(p);
        for (field, wrong) in [
            ("schema", json!(2)),
            ("policy_id", json!("different")),
            ("key_id", json!("other-key")),
            ("revision", json!(2)),
            ("published_at", json!(NOW + 1)),
            ("apply", json!("later")),
            (
                "rules",
                json!(vec![
                    json!({"domain": "example.com", "action": "direct", "comment": ""});
                    513
                ]),
            ),
        ] {
            let mut p = original.clone();
            let mut value: Value = serde_json::from_slice(&p.payload).unwrap();
            value[field] = wrong;
            p.payload = serde_json::to_vec(&value).unwrap();
            bind_publication_bytes(&mut p);
            invalid.push(p);
        }
        for p in invalid {
            assert!(state.inv.publish_corp_policy(&p, ACTOR).await.is_err());
        }
        assert_eq!(audit_count(&state).await, before);
        assert_eq!(
            state
                .inv
                .corp_record()
                .await
                .unwrap()
                .unwrap()
                .status
                .revision,
            0
        );
        assert!(state.inv.corp_history(100).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn publication_requires_byte_equal_envelope_payload_even_for_equivalent_json() {
        let (state, status) = published_state().await;
        let original = publication(&status);
        let equivalent = String::from_utf8(original.payload.clone())
            .unwrap()
            .trim()
            .as_bytes()
            .to_vec();
        assert_ne!(equivalent, original.payload);
        assert_eq!(
            serde_json::from_slice::<Value>(&equivalent).unwrap(),
            serde_json::from_slice::<Value>(&original.payload).unwrap()
        );

        let mut changed_envelope = original.clone();
        let mut envelope: Value = serde_json::from_slice(&changed_envelope.envelope).unwrap();
        envelope["payload"] = json!(STANDARD.encode(&equivalent));
        changed_envelope.envelope = serde_json::to_vec(&envelope).unwrap();
        assert_invalid_publication_unchanged(&state, &changed_envelope).await;

        let mut changed_payload = original.clone();
        changed_payload.payload = equivalent;
        changed_payload.payload_sha256 = format!("{:x}", Sha256::digest(&changed_payload.payload));
        assert_invalid_publication_unchanged(&state, &changed_payload).await;

        let mut unrelated_payload = original;
        envelope["payload"] = json!(STANDARD.encode(b"{}"));
        unrelated_payload.envelope = serde_json::to_vec(&envelope).unwrap();
        assert_invalid_publication_unchanged(&state, &unrelated_payload).await;
    }

    #[tokio::test]
    async fn publication_digest_must_be_exact_lowercase_sha256_of_supplied_bytes() {
        let (state, status) = published_state().await;
        let original = publication(&status);
        let equivalent = String::from_utf8(original.payload.clone())
            .unwrap()
            .trim()
            .as_bytes()
            .to_vec();
        let digest_of_other_bytes = format!("{:x}", Sha256::digest(&equivalent));
        assert_ne!(digest_of_other_bytes, original.payload_sha256);
        let uppercase = original.payload_sha256.to_ascii_uppercase();
        assert_ne!(uppercase, original.payload_sha256);
        for digest in [
            "0".repeat(64),
            uppercase,
            "g".repeat(64),
            "a".repeat(63),
            "a".repeat(65),
            String::new(),
            digest_of_other_bytes,
        ] {
            let mut invalid = original.clone();
            invalid.payload_sha256 = digest;
            assert_invalid_publication_unchanged(&state, &invalid).await;
        }
    }

    #[tokio::test]
    async fn publication_envelope_rejects_duplicate_fields_including_escaped_names() {
        let (state, status) = published_state().await;
        let original = publication(&status);
        let envelope: Value = serde_json::from_slice(&original.envelope).unwrap();
        let payload = serde_json::to_string(&envelope["payload"]).unwrap();
        let signature = serde_json::to_string(&envelope["signature"]).unwrap();
        for encoded in [
            format!("{{\"payload\":{payload},\"payload\":{payload},\"signature\":{signature}}}"),
            format!(
                "{{\"payload\":{payload},\"signature\":{signature},\"signature\":{signature}}}"
            ),
            format!(
                "{{\"pay\\u006coad\":{payload},\"payload\":{payload},\"signature\":{signature}}}"
            ),
            format!(
                "{{\"payload\":{payload},\"signat\\u0075re\":{signature},\"signature\":{signature}}}"
            ),
        ] {
            let mut invalid = original.clone();
            invalid.envelope = encoded.into_bytes();
            assert_invalid_publication_unchanged(&state, &invalid).await;
        }
    }

    #[tokio::test]
    async fn publication_envelope_requires_canonical_base64_and_exact_64_byte_signature() {
        let (state, status) = published_state().await;
        let mut original = publication(&status);
        while original.payload.len() % 3 != 1 {
            original.payload.push(b' ');
        }
        bind_publication_bytes(&mut original);
        let envelope: Value = serde_json::from_slice(&original.envelope).unwrap();
        for field in ["payload", "signature"] {
            let encoded = envelope[field].as_str().unwrap();
            assert!(encoded.ends_with("=="));
            let mut nonzero_pad_bits = encoded.as_bytes().to_vec();
            let last_data = nonzero_pad_bits.len() - 3;
            let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let value = alphabet
                .iter()
                .position(|&byte| byte == nonzero_pad_bits[last_data])
                .unwrap();
            nonzero_pad_bits[last_data] = alphabet[value + 1];
            for invalid_encoding in [
                encoded.trim_end_matches('=').to_owned(),
                format!(" {encoded}"),
                format!("{encoded}\n"),
                format!("{encoded}="),
                String::from_utf8(nonzero_pad_bits).unwrap(),
                String::new(),
            ] {
                let mut invalid = original.clone();
                let mut invalid_envelope = envelope.clone();
                invalid_envelope[field] = json!(invalid_encoding);
                invalid.envelope = serde_json::to_vec(&invalid_envelope).unwrap();
                assert_invalid_publication_unchanged(&state, &invalid).await;
            }
        }
        let encoded_signature = envelope["signature"].as_str().unwrap();
        let url_safe_signature = encoded_signature.replace('+', "-").replace('/', "_");
        assert_ne!(url_safe_signature, encoded_signature);
        for signature in [
            url_safe_signature,
            STANDARD.encode([0xfb_u8; 63]),
            STANDARD.encode([0xfb_u8; 65]),
        ] {
            let mut invalid = original.clone();
            let mut invalid_envelope = envelope.clone();
            invalid_envelope["signature"] = json!(signature);
            invalid.envelope = serde_json::to_vec(&invalid_envelope).unwrap();
            assert_invalid_publication_unchanged(&state, &invalid).await;
        }
        let valid = state
            .inv
            .publish_corp_policy(&original, ACTOR)
            .await
            .unwrap();
        assert_eq!(valid.payload, original.payload);
        assert_eq!(valid.envelope, original.envelope);
    }

    #[tokio::test]
    async fn publication_accepts_exact_envelope_size_limit_without_reserialization() {
        let (state, status) = published_state().await;
        let mut exact = publication(&status);
        exact.envelope.resize(65_536, b' ');
        let stored = state.inv.publish_corp_policy(&exact, ACTOR).await.unwrap();
        assert_eq!(stored.envelope, exact.envelope);
        assert_eq!(stored.payload, exact.payload);
        let current = state.inv.corp_record().await.unwrap().unwrap().status;
        let mut oversized = publication(&current);
        oversized.envelope.resize(65_537, b' ');
        assert_invalid_publication_unchanged(&state, &oversized).await;
    }

    #[tokio::test]
    async fn signer_rotation_invalidates_inflight_publication_and_reader_config_snapshot() {
        let (state, status) = enabled_state().await;
        let stale = publication(&status);
        let mut rotated = credentials();
        rotated.signing_keys.push(CorpSigningKey {
            id: "key-2".to_owned(),
            pkcs8: "AQIDBA==".to_owned(),
            spki: "BQYHCA==".to_owned(),
        });
        rotated.active_key_id = "key-2".to_owned();
        let current = state
            .inv
            .update_corp_security(status.config_version, true, &rotated, ACTOR)
            .await
            .unwrap();
        assert!(matches!(
            state.inv.publish_corp_policy(&stale, ACTOR).await,
            Err(CorpStoreError::Conflict)
        ));
        assert!(matches!(
            state.inv.corp_current_policy(status.config_version).await,
            Err(CorpStoreError::Conflict)
        ));
        assert!(
            state
                .inv
                .corp_current_policy(current.config_version)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            state
                .inv
                .publish_corp_policy(&publication(&current), ACTOR)
                .await
                .unwrap()
                .key_id,
            "key-2"
        );
    }

    #[tokio::test]
    async fn history_keeps_newest_100_and_audit_failure_neither_advances_nor_prunes() {
        let (state, mut status) = enabled_state().await;
        for expected in 1..=100 {
            let revision = state
                .inv
                .publish_corp_policy(&publication(&status), ACTOR)
                .await
                .unwrap();
            assert_eq!(revision.revision, expected);
            status.revision = expected;
        }
        let before = audit_count(&state).await;
        fail_audit(&state).await;
        assert!(
            state
                .inv
                .publish_corp_policy(&publication(&status), ACTOR)
                .await
                .is_err()
        );
        assert_eq!(
            state
                .inv
                .corp_record()
                .await
                .unwrap()
                .unwrap()
                .status
                .revision,
            100
        );
        assert!(state.inv.corp_revision(1).await.unwrap().is_some());
        assert!(state.inv.corp_revision(101).await.unwrap().is_none());
        assert_eq!(audit_count(&state).await, before);
        allow_audit(&state).await;
        assert_eq!(
            state
                .inv
                .publish_corp_policy(&publication(&status), ACTOR)
                .await
                .unwrap()
                .revision,
            101
        );
        let history = state.inv.corp_history(100).await.unwrap();
        assert_eq!(
            history.iter().map(|row| row.revision).collect::<Vec<_>>(),
            (2..=101).rev().collect::<Vec<_>>()
        );
        assert!(state.inv.corp_revision(1).await.unwrap().is_none());
        assert_eq!(state.inv.corp_history(1).await.unwrap()[0].revision, 101);
        assert!(state.inv.corp_history(0).await.is_err());
        assert!(state.inv.corp_history(101).await.is_err());
        status.revision = 101;
        let restored = state
            .inv
            .publish_corp_policy(&publication(&status), ACTOR)
            .await
            .unwrap();
        assert_eq!(restored.revision, 102);
    }

    #[tokio::test]
    async fn user_deletion_preserves_identity_history_floor_and_prevents_silent_reenable() {
        let (state, status) = enabled_state().await;
        let published = state
            .inv
            .publish_corp_policy(&publication(&status), ACTOR)
            .await
            .unwrap();
        let login = session(14, NOW + 3600);
        state
            .inv
            .issue_corp_session(status.auth_generation, &login, NOW, ACTOR)
            .await
            .unwrap();
        let before = audit_count(&state).await;
        state.inv.remove_user(&user().id).await.unwrap();
        assert_eq!(audit_count(&state).await, before + 1);
        assert!(state.inv.get_user(&user().id).await.unwrap().is_none());
        let record = state.inv.corp_record().await.unwrap().unwrap();
        assert_eq!(record.status.user_id.0, status.user_id.0);
        assert_eq!(record.status.policy_id, status.policy_id);
        assert_eq!(record.status.revision, 1);
        assert!(!record.status.enabled);
        assert!(record.status.auth_generation > status.auth_generation);
        assert!(
            state
                .inv
                .corp_session(&login.token_hash, NOW)
                .await
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            state
                .inv
                .corp_current_policy(record.status.config_version)
                .await,
            Err(CorpStoreError::Unavailable)
        ));
        assert_eq!(
            state.inv.corp_history(100).await.unwrap()[0].payload,
            published.payload
        );
        assert_eq!(
            state.inv.corp_revision(1).await.unwrap().unwrap().envelope,
            published.envelope
        );
        assert!(matches!(
            state.inv.create_corp(&setup(), ACTOR).await,
            Err(CorpStoreError::Conflict)
        ));
        assert!(
            state
                .inv
                .update_corp_security(record.status.config_version, true, &credentials(), ACTOR)
                .await
                .is_err()
        );
        let mut repaired = credentials();
        repaired.password_phc.push('x');
        let disabled = state
            .inv
            .update_corp_security(record.status.config_version, false, &repaired, ACTOR)
            .await
            .unwrap();
        assert!(!disabled.enabled);
        state.inv.add_user(&user()).await.unwrap();
        assert!(
            !state
                .inv
                .corp_record()
                .await
                .unwrap()
                .unwrap()
                .status
                .enabled
        );
        assert!(
            state
                .inv
                .corp_session(&login.token_hash, NOW)
                .await
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            state.inv.create_corp(&setup(), ACTOR).await,
            Err(CorpStoreError::Conflict)
        ));
        let enabled = state
            .inv
            .update_corp_security(disabled.config_version, true, &repaired, ACTOR)
            .await
            .unwrap();
        assert_eq!(
            state
                .inv
                .publish_corp_policy(&publication(&enabled), ACTOR)
                .await
                .unwrap()
                .revision,
            2
        );
    }

    #[tokio::test]
    async fn disabled_corp_blocks_login_current_reads_and_publication_but_keeps_operator_history() {
        let (state, status) = enabled_state().await;
        state
            .inv
            .publish_corp_policy(&publication(&status), ACTOR)
            .await
            .unwrap();
        let current = state.inv.corp_record().await.unwrap().unwrap().status;
        let disabled = state
            .inv
            .update_corp_security(current.config_version, false, &credentials(), ACTOR)
            .await
            .unwrap();
        assert!(matches!(
            state
                .inv
                .issue_corp_session(
                    disabled.auth_generation,
                    &session(15, NOW + 3600),
                    NOW,
                    ACTOR
                )
                .await,
            Err(CorpStoreError::Unavailable)
        ));
        assert!(matches!(
            state.inv.corp_current_policy(disabled.config_version).await,
            Err(CorpStoreError::Unavailable)
        ));
        assert!(matches!(
            state
                .inv
                .publish_corp_policy(&publication(&disabled), ACTOR)
                .await,
            Err(CorpStoreError::Unavailable)
        ));
        assert_eq!(state.inv.corp_history(100).await.unwrap().len(), 1);
        assert!(state.inv.corp_revision(1).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn reordered_credentials_and_egress_are_noops_without_session_or_audit_changes() {
        let state = state().await;
        state.inv.add_server(&server()).await.unwrap();
        let mut input = setup();
        input.credentials.reader_tokens.push(CorpReaderToken {
            id: "reader-2".to_owned(),
            token: "second_reader_0123456789abcdef0123456789==".to_owned(),
        });
        input.credentials.signing_keys.push(CorpSigningKey {
            id: "key-2".to_owned(),
            pkcs8: "AQIDBA==".to_owned(),
            spki: "BQYHCA==".to_owned(),
        });
        let initial = state.inv.create_corp(&input, ACTOR).await.unwrap();
        let enabled = state
            .inv
            .update_corp_security(initial.config_version, true, &input.credentials, ACTOR)
            .await
            .unwrap();
        let entries = [egress("192.0.2.25"), egress("2001:db8::25")];
        let status = state
            .inv
            .replace_corp_egress(enabled.config_version, &entries, ACTOR)
            .await
            .unwrap();
        let login = session(17, NOW + 3600);
        state
            .inv
            .issue_corp_session(status.auth_generation, &login, NOW, ACTOR)
            .await
            .unwrap();
        let before = audit_count(&state).await;
        input.credentials.reader_tokens.reverse();
        input.credentials.signing_keys.reverse();
        let same = state
            .inv
            .update_corp_security(status.config_version, true, &input.credentials, ACTOR)
            .await
            .unwrap();
        assert_eq!(status_snapshot(&same), status_snapshot(&status));
        let reordered = [egress("2001:db8::25"), egress("::ffff:192.0.2.25")];
        let same = state
            .inv
            .replace_corp_egress(status.config_version, &reordered, ACTOR)
            .await
            .unwrap();
        assert_eq!(status_snapshot(&same), status_snapshot(&status));
        assert_eq!(audit_count(&state).await, before);
        assert!(
            state
                .inv
                .corp_session(&login.token_hash, NOW)
                .await
                .unwrap()
                .is_some()
        );
        let mut invalid = input.credentials;
        invalid.reader_tokens[0].token = "invalid=interior_padding_0123456789abcdef".to_owned();
        assert!(
            state
                .inv
                .update_corp_security(status.config_version, true, &invalid, ACTOR)
                .await
                .is_err()
        );
        assert_eq!(audit_count(&state).await, before);
    }

    #[tokio::test]
    async fn counter_exhaustion_cannot_reauthorize_inflight_login_after_user_reenable() {
        for column in ["auth_generation", "config_version"] {
            let (state, status) = enabled_state().await;
            let mut connection = sql_connection(&state).await;
            sqlx::query(&format!(
                "UPDATE corp_policy_settings SET {column} = ? WHERE id = 1"
            ))
            .bind(i64::try_from(CORP_MAX_REVISION).unwrap())
            .execute(&mut connection)
            .await
            .unwrap();
            drop(connection);
            let at_limit = state.inv.corp_record().await.unwrap().unwrap().status;
            let login = session(18, NOW + 3600);
            state
                .inv
                .issue_corp_session(at_limit.auth_generation, &login, NOW, ACTOR)
                .await
                .unwrap();
            assert!(matches!(
                state
                    .inv
                    .revoke_corp_sessions(at_limit.config_version, ACTOR)
                    .await,
                Err(CorpStoreError::Conflict)
            ));
            let mut changed_credentials = credentials();
            changed_credentials.password_phc.push('x');
            assert!(matches!(
                state
                    .inv
                    .update_corp_security(
                        at_limit.config_version,
                        true,
                        &changed_credentials,
                        ACTOR
                    )
                    .await,
                Err(CorpStoreError::Conflict)
            ));
            state.inv.set_user_disabled(&user().id, true).await.unwrap();
            state
                .inv
                .set_user_disabled(&user().id, false)
                .await
                .unwrap();
            let after = state.inv.corp_record().await.unwrap().unwrap().status;
            assert!(
                !after.enabled,
                "exhausted {column} must leave Corp disabled"
            );
            assert!(after.auth_generation >= status.auth_generation);
            assert!(after.config_version >= status.config_version);
            assert!(
                state
                    .inv
                    .corp_session(&login.token_hash, NOW)
                    .await
                    .unwrap()
                    .is_none()
            );
            assert!(
                state
                    .inv
                    .issue_corp_session(
                        at_limit.auth_generation,
                        &session(19, NOW + 3600),
                        NOW,
                        ACTOR
                    )
                    .await
                    .is_err()
            );
            assert!(
                state
                    .inv
                    .update_corp_security(after.config_version, true, &credentials(), ACTOR)
                    .await
                    .is_err()
            );
        }
    }

    #[tokio::test]
    async fn last_revision_is_publishable_once_and_floor_never_wraps() {
        let (state, _) = enabled_state().await;
        let mut connection = sql_connection(&state).await;
        sqlx::query("UPDATE corp_policy_settings SET revision = ? WHERE id = 1")
            .bind(i64::try_from(CORP_MAX_REVISION - 1).unwrap())
            .execute(&mut connection)
            .await
            .unwrap();
        drop(connection);
        let near_limit = state.inv.corp_record().await.unwrap().unwrap().status;
        let last = state
            .inv
            .publish_corp_policy(&publication(&near_limit), ACTOR)
            .await
            .unwrap();
        assert_eq!(last.revision, CORP_MAX_REVISION);
        let at_limit = state.inv.corp_record().await.unwrap().unwrap().status;
        let before = audit_count(&state).await;
        assert!(matches!(
            state
                .inv
                .publish_corp_policy(&publication(&at_limit), ACTOR)
                .await,
            Err(CorpStoreError::Conflict)
        ));
        assert_eq!(
            state
                .inv
                .corp_record()
                .await
                .unwrap()
                .unwrap()
                .status
                .revision,
            CORP_MAX_REVISION
        );
        assert_eq!(audit_count(&state).await, before);
        assert_eq!(
            state
                .inv
                .corp_revision(CORP_MAX_REVISION)
                .await
                .unwrap()
                .unwrap()
                .revision,
            CORP_MAX_REVISION
        );
        assert!(matches!(
            state.inv.corp_revision(0).await,
            Err(CorpStoreError::InvalidInput(_))
        ));
        assert!(matches!(
            state.inv.corp_revision(CORP_MAX_REVISION + 1).await,
            Err(CorpStoreError::InvalidInput(_))
        ));
    }

    #[tokio::test]
    async fn failed_user_mutation_audit_restores_user_authority_and_history() {
        let (state, status) = enabled_state().await;
        state
            .inv
            .publish_corp_policy(&publication(&status), ACTOR)
            .await
            .unwrap();
        let current = state.inv.corp_record().await.unwrap().unwrap().status;
        let login = session(20, NOW + 3600);
        state
            .inv
            .issue_corp_session(current.auth_generation, &login, NOW, ACTOR)
            .await
            .unwrap();
        let before = audit_count(&state).await;
        fail_audit(&state).await;
        assert!(state.inv.remove_user(&user().id).await.is_err());
        assert!(state.inv.get_user(&user().id).await.unwrap().is_some());
        assert_eq!(
            status_snapshot(&state.inv.corp_record().await.unwrap().unwrap().status),
            status_snapshot(&current)
        );
        assert!(
            state
                .inv
                .corp_session(&login.token_hash, NOW)
                .await
                .unwrap()
                .is_some()
        );
        assert!(state.inv.corp_revision(1).await.unwrap().is_some());
        assert!(state.inv.set_user_disabled(&user().id, true).await.is_err());
        assert!(
            !state
                .inv
                .get_user(&user().id)
                .await
                .unwrap()
                .unwrap()
                .disabled
        );
        assert!(
            state
                .inv
                .corp_session(&login.token_hash, NOW)
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(audit_count(&state).await, before);
    }

    #[tokio::test]
    async fn audit_records_never_include_recoverable_credentials_csrf_or_policy_bodies() {
        let (state, status) = enabled_state().await;
        state
            .inv
            .issue_corp_session(status.auth_generation, &session(21, NOW + 3600), NOW, ACTOR)
            .await
            .unwrap();
        let mut input = publication(&status);
        let mut body: Value = serde_json::from_slice(&input.payload).unwrap();
        body["rules"] = json!([{"domain": "example.com", "action": "direct", "comment": "SENSITIVE_SYNTHETIC_RULE_COMMENT"}]);
        input.payload = serde_json::to_vec(&body).unwrap();
        bind_publication_bytes(&mut input);
        state.inv.publish_corp_policy(&input, ACTOR).await.unwrap();
        let mut connection = sql_connection(&state).await;
        let rows = sqlx::query("SELECT * FROM audit_log")
            .fetch_all(&mut connection)
            .await
            .unwrap();
        let mut text = String::new();
        for row in rows {
            for index in 0..row.columns().len() {
                if let Ok(value) = row.try_get::<String, _>(index) {
                    text.push_str(&value);
                }
            }
        }
        for secret in [
            PASSWORD,
            READER,
            PRIVATE_KEY,
            CSRF,
            "SENSITIVE_SYNTHETIC_RULE_COMMENT",
        ] {
            assert!(
                !text.contains(secret),
                "audit contains a synthetic secret or body"
            );
        }
    }

    #[tokio::test]
    async fn debug_output_redacts_credentials_sessions_and_exact_publication_bodies() {
        let (state, status) = enabled_state().await;
        let setup = setup();
        let record = state.inv.corp_record().await.unwrap().unwrap();
        let input = session(16, NOW + 3600);
        state
            .inv
            .issue_corp_session(status.auth_generation, &input, NOW, ACTOR)
            .await
            .unwrap();
        let stored = state
            .inv
            .corp_session(&input.token_hash, NOW)
            .await
            .unwrap()
            .unwrap();
        for debug in [
            format!("{setup:?}"),
            format!("{record:?}"),
            format!("{:?}", setup.credentials),
            format!("{:?}", setup.credentials.reader_tokens[0]),
            format!("{:?}", setup.credentials.signing_keys[0]),
            format!("{input:?}"),
            format!("{stored:?}"),
        ] {
            for secret in [PASSWORD, READER, PRIVATE_KEY, CSRF] {
                assert!(
                    !debug.contains(secret),
                    "Debug revealed a synthetic credential"
                );
            }
        }
        let publication = publication(&status);
        let revision = state
            .inv
            .publish_corp_policy(&publication, ACTOR)
            .await
            .unwrap();
        let debug = format!("{revision:?}");
        assert!(!debug.contains(&String::from_utf8(publication.payload.clone()).unwrap()));
        assert!(!debug.contains(&format!("{:?}", publication.payload)));
        assert!(!debug.contains(&String::from_utf8(publication.envelope.clone()).unwrap()));
        assert!(!debug.contains(&format!("{:?}", publication.envelope)));
    }

    fn egress_snapshot(rows: &[CorpVerifiedEgress]) -> Vec<(String, IpAddr, String, i64)> {
        let mut rows = rows
            .iter()
            .map(|row| {
                (
                    row.server_id.0.clone(),
                    row.ip,
                    row.configuration_fingerprint.clone(),
                    row.verified_at,
                )
            })
            .collect::<Vec<_>>();
        rows.sort();
        rows
    }

    async fn refresh_state() -> (State, CorpStatus, Vec<CorpVerifiedEgress>) {
        let (state, status) = enabled_state().await;
        state.inv.add_server(&server()).await.unwrap();
        let rows = vec![egress("192.0.2.25"), egress("2001:db8::25")];
        let status = state
            .inv
            .replace_corp_egress(status.config_version, &rows, ACTOR)
            .await
            .unwrap();
        (state, status, rows)
    }

    #[tokio::test]
    async fn refresh_changes_only_timestamps_preserves_session_credentials_and_exact_history() {
        let (state, status, previous) = refresh_state().await;
        let published = state
            .inv
            .publish_corp_policy(&publication(&status), ACTOR)
            .await
            .unwrap();
        let record = state.inv.corp_record().await.unwrap().unwrap();
        let login = session(71, NOW + 3600);
        state
            .inv
            .issue_corp_session(record.status.auth_generation, &login, NOW, ACTOR)
            .await
            .unwrap();
        let before = audit_count(&state).await;
        let mut refreshed = previous.clone();
        refreshed[0].verified_at += 10;
        refreshed[1].verified_at += 20;
        let result = state
            .inv
            .refresh_corp_egress(record.status.config_version, &previous, &refreshed, ACTOR)
            .await
            .unwrap();
        assert_eq!(status_snapshot(&result), status_snapshot(&record.status));
        let after = state.inv.corp_record().await.unwrap().unwrap();
        assert_eq!(
            after.credentials.password_phc,
            record.credentials.password_phc
        );
        assert_eq!(
            after.credentials.reader_tokens[0].token,
            record.credentials.reader_tokens[0].token
        );
        assert_eq!(
            after.credentials.signing_keys[0].pkcs8,
            record.credentials.signing_keys[0].pkcs8
        );
        assert_eq!(
            after.credentials.signing_keys[0].spki,
            record.credentials.signing_keys[0].spki
        );
        assert_eq!(
            egress_snapshot(&state.inv.corp_verified_egress().await.unwrap()),
            egress_snapshot(&refreshed)
        );
        let retained = state
            .inv
            .corp_session(&login.token_hash, NOW)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(retained.auth_generation, record.status.auth_generation);
        assert_eq!(retained.config_version, record.status.config_version);
        assert_eq!(retained.csrf_token, login.csrf_token);
        assert_eq!(retained.expires_at, login.expires_at);
        let history = state.inv.corp_history(100).await.unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].payload, published.payload);
        assert_eq!(history[0].envelope, published.envelope);
        assert_eq!(history[0].payload_sha256, published.payload_sha256);
        assert_eq!(audit_count(&state).await, before + 1);
        let mut connection = sql_connection(&state).await;
        let audit = sqlx::query("SELECT * FROM audit_log")
            .fetch_all(&mut connection)
            .await
            .unwrap();
        let refresh_rows = audit
            .iter()
            .filter(|row| {
                (0..row.columns().len()).any(|i| {
                    row.try_get::<String, _>(i)
                        .is_ok_and(|s| s == "corp.egress.refresh")
                })
            })
            .count();
        assert_eq!(refresh_rows, 1);
        drop(connection);
        // An identity replacement retains its stronger authority/session invalidation.
        refreshed[0].configuration_fingerprint = "b".repeat(64);
        let replaced = state
            .inv
            .replace_corp_egress(result.config_version, &refreshed, ACTOR)
            .await
            .unwrap();
        assert_eq!(replaced.config_version, result.config_version + 1);
        assert_eq!(replaced.auth_generation, result.auth_generation + 1);
        assert!(
            state
                .inv
                .corp_session(&login.token_hash, NOW)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn refresh_normalized_noop_and_empty_disabled_binding_do_not_write_audit() {
        let (state, status, previous) = refresh_state().await;
        let normalized = [egress("2001:db8::25"), egress("::ffff:192.0.2.25")];
        let before = audit_count(&state).await;
        // Audit rejection also proves a normalized no-op never attempts an insert.
        fail_audit(&state).await;
        let same = state
            .inv
            .refresh_corp_egress(status.config_version, &normalized, &previous, ACTOR)
            .await
            .unwrap();
        assert_eq!(status_snapshot(&same), status_snapshot(&status));
        assert_eq!(audit_count(&state).await, before);
        allow_audit(&state).await;
        let empty = self::state().await;
        let disabled = empty.inv.create_corp(&setup(), ACTOR).await.unwrap();
        let before = audit_count(&empty).await;
        let same = empty
            .inv
            .refresh_corp_egress(disabled.config_version, &[], &[], ACTOR)
            .await
            .unwrap();
        assert_eq!(status_snapshot(&same), status_snapshot(&disabled));
        assert_eq!(audit_count(&empty).await, before);
        empty.inv.add_server(&server()).await.unwrap();
        let status = empty
            .inv
            .replace_corp_egress(disabled.config_version, &previous, ACTOR)
            .await
            .unwrap();
        let mut refreshed = previous.clone();
        refreshed[0].verified_at += 1;
        assert!(
            !empty
                .inv
                .refresh_corp_egress(status.config_version, &previous, &refreshed, ACTOR)
                .await
                .unwrap()
                .enabled
        );
    }

    #[tokio::test]
    async fn refresh_requires_exact_version_and_previous_timestamps_without_audit() {
        let (state, status, previous) = refresh_state().await;
        let mut refreshed = previous.clone();
        refreshed[0].verified_at += 2;
        let before = audit_count(&state).await;
        assert!(matches!(
            state
                .inv
                .refresh_corp_egress(status.config_version - 1, &previous, &refreshed, ACTOR)
                .await,
            Err(CorpStoreError::Conflict)
        ));
        let mut stale = previous.clone();
        stale[0].verified_at -= 1;
        assert!(matches!(
            state
                .inv
                .refresh_corp_egress(status.config_version, &stale, &refreshed, ACTOR)
                .await,
            Err(CorpStoreError::Conflict)
        ));
        assert!(matches!(
            state
                .inv
                .refresh_corp_egress(status.config_version, &[], &[], ACTOR)
                .await,
            Err(CorpStoreError::Conflict)
        ));
        assert_eq!(audit_count(&state).await, before);
        assert_eq!(
            egress_snapshot(&state.inv.corp_verified_egress().await.unwrap()),
            egress_snapshot(&previous)
        );
    }

    #[tokio::test]
    async fn refresh_rejects_identity_changes_backdating_duplicates_and_actor_bounds() {
        let (state, status, previous) = refresh_state().await;
        let mut invalid = Vec::new();
        let mut row = previous[0].clone();
        row.ip = "192.0.2.26".parse().unwrap();
        invalid.push(vec![row, previous[1].clone()]);
        let mut row = previous[0].clone();
        row.configuration_fingerprint = "b".repeat(64);
        invalid.push(vec![row, previous[1].clone()]);
        let mut row = previous[0].clone();
        row.server_id = ServerId("different-server".to_owned());
        invalid.push(vec![row, previous[1].clone()]);
        invalid.push(vec![previous[0].clone()]);
        invalid.push(vec![previous[0].clone(), egress("::ffff:192.0.2.25")]);
        for timestamp in [NOW - 1, 0, 253_402_300_800] {
            let mut rows = previous.clone();
            rows[0].verified_at = timestamp;
            invalid.push(rows);
        }
        for fingerprint in ["A".repeat(64), "a".repeat(63), "g".repeat(64)] {
            let mut rows = previous.clone();
            rows[0].configuration_fingerprint = fingerprint;
            invalid.push(rows);
        }
        let before = audit_count(&state).await;
        for rows in invalid {
            assert!(matches!(
                state
                    .inv
                    .refresh_corp_egress(status.config_version, &previous, &rows, ACTOR)
                    .await,
                Err(CorpStoreError::InvalidInput(_))
            ));
        }
        // Invalid previous input is validated independently, before the row CAS.
        for rows in [
            vec![previous[0].clone(), egress("::ffff:192.0.2.25")],
            vec![CorpVerifiedEgress {
                verified_at: 0,
                ..previous[0].clone()
            }],
        ] {
            assert!(matches!(
                state
                    .inv
                    .refresh_corp_egress(status.config_version, &rows, &rows, ACTOR)
                    .await,
                Err(CorpStoreError::InvalidInput(_))
            ));
        }
        for actor in [
            "".to_owned(),
            "a".repeat(129),
            "line\nbreak".to_owned(),
            "é".repeat(65),
        ] {
            assert!(matches!(
                state
                    .inv
                    .refresh_corp_egress(status.config_version, &previous, &previous, &actor)
                    .await,
                Err(CorpStoreError::InvalidInput(_))
            ));
        }
        assert_eq!(audit_count(&state).await, before);
        assert_eq!(
            egress_snapshot(&state.inv.corp_verified_egress().await.unwrap()),
            egress_snapshot(&previous)
        );
        assert!(
            state
                .inv
                .refresh_corp_egress(status.config_version, &previous, &previous, &"é".repeat(64))
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn refresh_requires_existing_binding_and_enabled_existing_user_even_for_noop() {
        let empty = state().await;
        assert!(matches!(
            empty.inv.refresh_corp_egress(1, &[], &[], ACTOR).await,
            Err(CorpStoreError::Unavailable)
        ));
        for deleted in [false, true] {
            let (state, _, previous) = refresh_state().await;
            if deleted {
                state.inv.remove_user(&user().id).await.unwrap();
            } else {
                state.inv.set_user_disabled(&user().id, true).await.unwrap();
            }
            let status = state.inv.corp_record().await.unwrap().unwrap().status;
            let before = audit_count(&state).await;
            assert!(matches!(
                state
                    .inv
                    .refresh_corp_egress(status.config_version, &previous, &previous, ACTOR)
                    .await,
                Err(CorpStoreError::Unavailable)
            ));
            assert_eq!(audit_count(&state).await, before);
        }
    }

    #[tokio::test]
    async fn refresh_audit_failure_rolls_back_all_timestamps_and_preserves_sessions() {
        let (state, status, previous) = refresh_state().await;
        let login = session(72, NOW + 3600);
        state
            .inv
            .issue_corp_session(status.auth_generation, &login, NOW, ACTOR)
            .await
            .unwrap();
        let before = audit_count(&state).await;
        let mut refreshed = previous.clone();
        for row in &mut refreshed {
            row.verified_at += 1;
        }
        fail_audit(&state).await;
        assert!(matches!(
            state
                .inv
                .refresh_corp_egress(status.config_version, &previous, &refreshed, ACTOR)
                .await,
            Err(CorpStoreError::Inventory(_))
        ));
        assert_eq!(
            egress_snapshot(&state.inv.corp_verified_egress().await.unwrap()),
            egress_snapshot(&previous)
        );
        assert_eq!(
            status_snapshot(&state.inv.corp_record().await.unwrap().unwrap().status),
            status_snapshot(&status)
        );
        assert!(
            state
                .inv
                .corp_session(&login.token_hash, NOW)
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(audit_count(&state).await, before);
        allow_audit(&state).await;
        state
            .inv
            .refresh_corp_egress(status.config_version, &previous, &refreshed, ACTOR)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn concurrent_refreshes_of_same_previous_rows_have_one_winner() {
        let (state, status, previous) = refresh_state().await;
        let second = SqliteInventory::open(&state.path).await.unwrap();
        let mut first_rows = previous.clone();
        let mut second_rows = previous.clone();
        for row in &mut first_rows {
            row.verified_at += 10;
        }
        for row in &mut second_rows {
            row.verified_at += 20;
        }
        let before = audit_count(&state).await;
        let (a, b) = tokio::join!(
            state
                .inv
                .refresh_corp_egress(status.config_version, &previous, &first_rows, ACTOR),
            second.refresh_corp_egress(status.config_version, &previous, &second_rows, ACTOR),
        );
        assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
        assert!(matches!(
            (&a, &b),
            (Ok(_), Err(CorpStoreError::Conflict)) | (Err(CorpStoreError::Conflict), Ok(_))
        ));
        let winner = if a.is_ok() { first_rows } else { second_rows };
        assert_eq!(
            egress_snapshot(&state.inv.corp_verified_egress().await.unwrap()),
            egress_snapshot(&winner)
        );
        assert_eq!(audit_count(&state).await, before + 1);
        assert_eq!(
            status_snapshot(&state.inv.corp_record().await.unwrap().unwrap().status),
            status_snapshot(&status)
        );
    }

    #[tokio::test]
    async fn refresh_accepts_512_rows_maximum_timestamp_and_exhausted_authority_counters() {
        let (state, _) = enabled_state().await;
        state.inv.add_server(&server()).await.unwrap();
        let previous = (1..=512)
            .map(|i| CorpVerifiedEgress {
                verified_at: 1,
                ..egress(&format!("2001:db8::{i:x}"))
            })
            .collect::<Vec<_>>();
        let status = state.inv.corp_record().await.unwrap().unwrap().status;
        state
            .inv
            .replace_corp_egress(status.config_version, &previous, ACTOR)
            .await
            .unwrap();
        let mut connection = sql_connection(&state).await;
        sqlx::query(
            "UPDATE corp_policy_settings SET auth_generation = ?, config_version = ? WHERE id = 1",
        )
        .bind(i64::try_from(CORP_MAX_REVISION).unwrap())
        .bind(i64::try_from(CORP_MAX_REVISION).unwrap())
        .execute(&mut connection)
        .await
        .unwrap();
        drop(connection);
        let status = state.inv.corp_record().await.unwrap().unwrap().status;
        let mut refreshed = previous.clone();
        for row in &mut refreshed {
            row.verified_at = 253_402_300_799;
        }
        let same = state
            .inv
            .refresh_corp_egress(status.config_version, &previous, &refreshed, ACTOR)
            .await
            .unwrap();
        assert_eq!(status_snapshot(&same), status_snapshot(&status));
        assert_eq!(
            egress_snapshot(&state.inv.corp_verified_egress().await.unwrap()),
            egress_snapshot(&refreshed)
        );
        let mut oversized = refreshed.clone();
        oversized.push(egress("2001:db8::ffff"));
        assert!(matches!(
            state
                .inv
                .refresh_corp_egress(status.config_version, &oversized, &oversized, ACTOR)
                .await,
            Err(CorpStoreError::InvalidInput(_))
        ));
    }

    // Additive telephony cases reuse the established isolated inventory fixture.
    fn phone_publication(status: &CorpStatus, revision: u64, rules: Value) -> CorpPublication {
        let mut value = publication(status);
        value.expected_revision = revision;
        value.payload = serde_json::to_vec(&json!({
            "schema":1, "kind":"telephony", "policy_id":status.policy_id,
            "key_id":status.active_key_id, "revision":revision + 1,
            "published_at":NOW, "apply":"next_connection", "rules":rules,
        }))
        .unwrap();
        bind_publication_bytes(&mut value);
        value
    }

    #[tokio::test]
    async fn phone_publication_preserves_site_bytes_and_reopens_authoritative_empty() {
        let (state, status) = published_state().await;
        let site = state
            .inv
            .corp_current_policy(status.config_version)
            .await
            .unwrap()
            .unwrap();
        assert!(
            state
                .inv
                .corp_current_phone_policy(status.config_version)
                .await
                .unwrap()
                .is_none()
        );
        let phone = phone_publication(&status, 0, json!([]));
        let stored = state
            .inv
            .publish_corp_phone_policy(&phone, ACTOR)
            .await
            .unwrap();
        assert_eq!(stored.envelope, phone.envelope);
        assert_eq!(stored.payload, phone.payload);
        let reopened = SqliteInventory::open(&state.path).await.unwrap();
        let current = reopened
            .corp_current_phone_policy(status.config_version)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(current.revision, 1);
        assert_eq!(current.envelope, phone.envelope);
        assert_eq!(
            reopened
                .corp_current_policy(status.config_version)
                .await
                .unwrap()
                .unwrap()
                .envelope,
            site.envelope
        );
        assert_eq!(
            reopened
                .corp_record()
                .await
                .unwrap()
                .unwrap()
                .status
                .revision,
            status.revision
        );
        assert_eq!(reopened.corp_phone_history(100).await.unwrap().len(), 1);
        assert_eq!(reopened.corp_history(100).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn phone_cas_writers_audit_failure_and_rotation_preserve_both_floors() {
        let (state, status) = enabled_state().await;
        let input = phone_publication(&status, 0, json!([]));
        fail_audit(&state).await;
        assert!(
            state
                .inv
                .publish_corp_phone_policy(&input, ACTOR)
                .await
                .is_err()
        );
        assert!(state.inv.corp_phone_history(100).await.unwrap().is_empty());
        allow_audit(&state).await;
        let (left, right) = tokio::join!(
            state.inv.publish_corp_phone_policy(&input, ACTOR),
            state.inv.publish_corp_phone_policy(&input, ACTOR),
        );
        assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
        assert!(
            matches!(left, Err(CorpStoreError::Conflict))
                || matches!(right, Err(CorpStoreError::Conflict))
        );
        let stale = phone_publication(&status, 1, json!([]));
        let mut rotated = credentials();
        rotated.reader_tokens[0].token.push('x');
        let updated = state
            .inv
            .update_corp_security(status.config_version, true, &rotated, ACTOR)
            .await
            .unwrap();
        assert!(matches!(
            state.inv.publish_corp_phone_policy(&stale, ACTOR).await,
            Err(CorpStoreError::Conflict)
        ));
        assert!(matches!(
            state
                .inv
                .corp_current_phone_policy(status.config_version)
                .await,
            Err(CorpStoreError::Conflict)
        ));
        assert_eq!(
            state
                .inv
                .corp_current_phone_policy(updated.config_version)
                .await
                .unwrap()
                .unwrap()
                .revision,
            1
        );
        assert_eq!(updated.revision, 0);
        let mut replacement = rotated.clone();
        replacement.signing_keys[0].spki = "BQYHCA==".into();
        assert!(matches!(
            state
                .inv
                .update_corp_security(updated.config_version, true, &replacement, ACTOR)
                .await,
            Err(CorpStoreError::Conflict)
        ));
    }

    #[tokio::test]
    async fn phone_history_pruning_lookup_bounds_and_envelope_binding_are_independent() {
        let (state, status) = enabled_state().await;
        let mut invalid = phone_publication(&status, 0, json!([]));
        invalid.envelope[0] ^= 1;
        assert!(
            state
                .inv
                .publish_corp_phone_policy(&invalid, ACTOR)
                .await
                .is_err()
        );
        let mut wrong_kind = phone_publication(&status, 0, json!([]));
        let mut payload: Value = serde_json::from_slice(&wrong_kind.payload).unwrap();
        payload["kind"] = json!("sites");
        wrong_kind.payload = serde_json::to_vec(&payload).unwrap();
        bind_publication_bytes(&mut wrong_kind);
        assert!(matches!(
            state
                .inv
                .publish_corp_phone_policy(&wrong_kind, ACTOR)
                .await,
            Err(CorpStoreError::InvalidInput(_))
        ));
        for revision in 0..101 {
            state
                .inv
                .publish_corp_phone_policy(&phone_publication(&status, revision, json!([])), ACTOR)
                .await
                .unwrap();
        }
        let history = state.inv.corp_phone_history(100).await.unwrap();
        assert_eq!(history.len(), 100);
        assert_eq!(history[0].revision, 101);
        assert_eq!(history[99].revision, 2);
        assert!(state.inv.corp_phone_revision(1).await.unwrap().is_none());
        assert!(state.inv.corp_phone_revision(102).await.unwrap().is_none());
        for revision in [0, CORP_MAX_REVISION + 1] {
            assert!(state.inv.corp_phone_revision(revision).await.is_err());
        }
        for limit in [0, 101] {
            assert!(state.inv.corp_phone_history(limit).await.is_err());
        }
        assert!(state.inv.corp_history(100).await.unwrap().is_empty());
    }
}
