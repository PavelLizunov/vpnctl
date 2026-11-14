// Independent cross-layer tests derived only from the wire and storage contracts.
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod spec {
    use std::collections::BTreeMap;

    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use tempfile::TempDir;
    use vpnctl_core::{User, UserId};
    use vpnctl_inventory::{
        CorpCredentials, CorpPublication, CorpReaderToken, CorpSetup, CorpSigningKey,
        CorpStoreError, SqliteInventory,
    };
    use vpnctld::corp_policy::{PolicyPayload, PolicyRule, PolicySigningKey, verify_envelope};

    #[tokio::test]
    async fn signed_policies_survive_storage_reopen_with_exact_bytes_and_monotonic_cas() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("signed-policy.db");
        let inv = SqliteInventory::open(&path).await.unwrap();
        let user = User {
            id: UserId("signed-spec-user".to_owned()),
            uuid: "12345678-9abc-4def-8abc-123456789abc".to_owned(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: false,
        };
        inv.add_user(&user).await.unwrap();
        let key = PolicySigningKey::generate().unwrap();
        let spki = key.spki_base64().unwrap();
        let credentials = CorpCredentials {
            password_phc: "$argon2id$v=19$m=19456,t=2,p=1$c3BlYy1zYWx0$c3BlYy1wYXNzd29yZA"
                .to_owned(),
            reader_tokens: vec![CorpReaderToken {
                id: "reader-1".to_owned(),
                token: "roundtrip_reader_0123456789abcdef0123456789".to_owned(),
            }],
            signing_keys: vec![CorpSigningKey {
                id: "signer-1".to_owned(),
                pkcs8: STANDARD.encode(key.export_pkcs8_der().unwrap().as_bytes()),
                spki: spki.clone(),
            }],
            active_key_id: "signer-1".to_owned(),
        };
        let created = inv
            .create_corp(
                &CorpSetup {
                    user_id: user.id,
                    policy_id: "signed-policy".to_owned(),
                    credentials: credentials.clone(),
                },
                "spec",
            )
            .await
            .unwrap();
        let status = inv
            .update_corp_security(created.config_version, true, &credentials, "spec")
            .await
            .unwrap();
        let keys = BTreeMap::from([("signer-1".to_owned(), spki)]);
        let mut payload = PolicyPayload {
            schema: 1,
            policy_id: "signed-policy".to_owned(),
            key_id: "signer-1".to_owned(),
            revision: 1,
            published_at: 1_794_657_600,
            apply: "next_connection".to_owned(),
            rules: vec![PolicyRule {
                domain: "example.com".to_owned(),
                action: "direct".to_owned(),
                comment: "Synthetic company site".to_owned(),
            }],
        };
        let first = key.sign(&payload).unwrap();
        let publication = CorpPublication {
            expected_revision: 0,
            expected_config_version: status.config_version,
            key_id: "signer-1".to_owned(),
            published_at: i64::try_from(payload.published_at).unwrap(),
            payload_sha256: first.payload_sha256.to_ascii_lowercase(),
            payload: first.payload_bytes.clone(),
            envelope: first.envelope.clone(),
        };
        let committed = inv.publish_corp_policy(&publication, "spec").await.unwrap();
        assert_eq!(committed.revision, 1);
        assert_eq!(committed.payload, first.payload_bytes);
        assert_eq!(committed.envelope, first.envelope);
        assert_eq!(
            committed.payload_sha256,
            first.payload_sha256.to_ascii_lowercase()
        );
        assert!(matches!(
            inv.publish_corp_policy(&publication, "spec").await,
            Err(CorpStoreError::Conflict)
        ));

        let reopened = SqliteInventory::open(&path).await.unwrap();
        let stored = reopened
            .corp_current_policy(status.config_version)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.payload, first.payload_bytes);
        assert_eq!(stored.envelope, first.envelope);
        assert_eq!(
            verify_envelope(&stored.envelope, "signed-policy", &keys).unwrap(),
            first
        );

        payload.revision = 2;
        payload.apply = "now".to_owned();
        payload.rules.clear();
        let second = key.sign(&payload).unwrap();
        let next = CorpPublication {
            expected_revision: 1,
            expected_config_version: status.config_version,
            key_id: "signer-1".to_owned(),
            published_at: i64::try_from(payload.published_at).unwrap(),
            payload_sha256: second.payload_sha256.to_ascii_lowercase(),
            payload: second.payload_bytes.clone(),
            envelope: second.envelope.clone(),
        };
        let committed = reopened.publish_corp_policy(&next, "spec").await.unwrap();
        assert_eq!(committed.revision, 2);
        assert_eq!(
            verify_envelope(&committed.envelope, "signed-policy", &keys).unwrap(),
            second
        );
        assert_eq!(
            inv.corp_current_policy(status.config_version)
                .await
                .unwrap()
                .unwrap()
                .envelope,
            second.envelope
        );
        let old = reopened.corp_revision(1).await.unwrap().unwrap();
        assert_eq!(
            verify_envelope(&old.envelope, "signed-policy", &keys).unwrap(),
            first
        );
        assert_eq!(
            reopened
                .corp_history(100)
                .await
                .unwrap()
                .iter()
                .map(|row| row.revision)
                .collect::<Vec<_>>(),
            [2, 1]
        );
    }
}
