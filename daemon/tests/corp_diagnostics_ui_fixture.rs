//! Synthetic real-router HTML export for isolated CI browser verification.
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod fixture {
    use std::{net::SocketAddr, sync::Arc};

    use axum::{
        body::{Body, to_bytes},
        extract::ConnectInfo,
        http::{Request, StatusCode},
    };
    use base64::{
        Engine as _,
        engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    };
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use tower::ServiceExt;
    use vpnctl_core::{KernelId, ProtocolId, Server, ServerId, User, UserId};
    use vpnctl_inventory::{
        CorpCredentials, CorpReaderToken, CorpSessionInput, CorpSetup, CorpSigningKey,
        CorpVerifiedEgress, SqliteInventory,
    };
    use vpnctld::{app, corp_policy::PolicySigningKey, corp_portal::eligibility};

    #[tokio::test]
    async fn export_real_diagnostics_page_and_assets_for_ci_browser() {
        let Some(directory) = std::env::var_os("CORP_DIAGNOSTICS_UI_OUTPUT_DIR") else {
            return;
        };
        let directory = std::path::PathBuf::from(directory);
        let temp = tempfile::tempdir().unwrap();
        let inv = SqliteInventory::open(&temp.path().join("inventory.db"))
            .await
            .unwrap();
        let user = User {
            id: UserId("diagnostics-ui-synthetic-user".into()),
            uuid: "15450643-1c7b-4a5f-aa91-9454c13f84ae".into(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: false,
        };
        let server = Server {
            id: ServerId("diagnostics-ui-synthetic-server".into()),
            address: "192.0.2.71".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![ProtocolId("vless+reality".into())],
            trusted_host_fingerprint: None,
            hoster: "synthetic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        };
        inv.add_user(&user).await.unwrap();
        inv.add_server(&server).await.unwrap();
        inv.grant(&user.id, &server.id).await.unwrap();
        for (name, value) in [
            ("vless.public_key", URL_SAFE_NO_PAD.encode([7_u8; 32])),
            ("vless.short_id", "12345678".into()),
            ("vless.sni", "www.example.com".into()),
        ] {
            inv.set_server_secret(&server.id, name, &value)
                .await
                .unwrap();
        }
        let signer = PolicySigningKey::generate().unwrap();
        let credentials = CorpCredentials {
            password_phc: "$argon2id$v=19$m=8192,t=1,p=1$c3ludGhldGljc2FsdDEyMw$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            reader_tokens: vec![CorpReaderToken { id: "reader".into(), token: "synthetic-reader-token-01234567890123456789".into() }],
            signing_keys: vec![CorpSigningKey { id: "signer".into(), pkcs8: STANDARD.encode(signer.export_pkcs8_der().unwrap().as_bytes()), spki: signer.spki_base64().unwrap() }],
            active_key_id: "signer".into(),
        };
        let status = inv
            .create_corp(
                &CorpSetup {
                    user_id: user.id.clone(),
                    policy_id: "diagnostics-ui-synthetic".into(),
                    credentials: credentials.clone(),
                },
                "fixture",
            )
            .await
            .unwrap();
        inv.update_corp_security(status.config_version, true, &credentials, "fixture")
            .await
            .unwrap();
        let (state, job) = app::make_app_state_for_tests(
            inv.clone(),
            Arc::new(vpnctl_kernels::build_registry().unwrap()),
        );
        let eligible = eligibility::eligible_servers(&state, &user.id)
            .await
            .unwrap();
        assert_eq!(eligible.len(), 1);
        let status = inv.corp_record().await.unwrap().unwrap().status;
        let status = inv
            .replace_corp_egress(
                status.config_version,
                &[CorpVerifiedEgress {
                    server_id: server.id,
                    ip: "198.51.100.27".parse().unwrap(),
                    configuration_fingerprint: eligible[0].configuration_fingerprint.clone(),
                    verified_at: chrono::Utc::now().timestamp(),
                }],
                "fixture",
            )
            .await
            .unwrap();
        let token = URL_SAFE_NO_PAD.encode([9_u8; 32]);
        inv.issue_corp_session(
            status.auth_generation,
            &CorpSessionInput {
                token_hash: format!("{:x}", Sha256::digest(token.as_bytes())),
                csrf_token: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
                expires_at: chrono::Utc::now().timestamp() + 3600,
            },
            chrono::Utc::now().timestamp(),
            "fixture",
        )
        .await
        .unwrap();
        let router = app::router(state);
        std::fs::create_dir_all(directory.join("assets")).unwrap();
        for (name, route) in [
            ("diagnostics.html", "/diagnostics"),
            ("assets/corp.css", "/assets/corp.css"),
            ("assets/corp.js", "/assets/corp.js"),
            ("assets/corp-phone.js", "/assets/corp-phone.js"),
            ("assets/corp-diagnostics.js", "/assets/corp-diagnostics.js"),
        ] {
            let mut request = Request::builder()
                .uri(route)
                .header("host", "admin.corp.ninitux.com")
                .header("cookie", format!("__Host-vpnctl_corp={token}"))
                .body(Body::empty())
                .unwrap();
            request.extensions_mut().insert(ConnectInfo(SocketAddr::new(
                "198.51.100.27".parse().unwrap(),
                40123,
            )));
            let response = router.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            if route == "/diagnostics" {
                let mut headers = serde_json::Map::new();
                for key in [
                    "content-type",
                    "cache-control",
                    "x-content-type-options",
                    "x-frame-options",
                    "referrer-policy",
                    "x-robots-tag",
                    "content-security-policy",
                ] {
                    headers.insert(key.into(), json!(response.headers()[key].to_str().unwrap()));
                }
                assert!(!response.headers().contains_key("set-cookie"));
                std::fs::write(
                    directory.join("diagnostics.json"),
                    serde_json::to_vec_pretty(&json!({"status":200,"headers":headers})).unwrap(),
                )
                .unwrap();
            }
            let bytes = to_bytes(response.into_body(), 256 * 1024).await.unwrap();
            assert!(!String::from_utf8_lossy(&bytes).contains(&token));
            std::fs::write(directory.join(name), bytes).unwrap();
        }
        job.abort();
    }
}
