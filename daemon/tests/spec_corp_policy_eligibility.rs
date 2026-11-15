// Independent fixtures and assertions derived only from corp-policy-eligibility.md.
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod spec {
    use std::{collections::HashMap, sync::Arc};

    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use sqlx::{Connection, SqliteConnection, sqlite::SqliteConnectOptions};
    use tempfile::TempDir;
    use tokio::task::JoinHandle;
    use vpnctl_core::{KernelId, Protocol, ProtocolId, RenderCtx, Server, ServerId, User, UserId};
    use vpnctl_inventory::{ServerRole, SqliteInventory};
    use vpnctld::{
        AppState, app,
        corp_portal::eligibility::{
            CorpEligibleServer, EligibilityError, eligible_servers, probe_plan,
        },
    };

    struct Fixture {
        _dir: TempDir,
        state: AppState,
        job: JoinHandle<()>,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            self.job.abort();
        }
    }

    fn user(id: &str) -> User {
        User {
            id: UserId(id.to_owned()),
            uuid: if id == "other" {
                "22222222-2222-4222-8222-222222222222"
            } else {
                "11111111-1111-4111-8111-111111111111"
            }
            .to_owned(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: false,
        }
    }

    fn server(id: &str, address: &str, protocols: &[&str]) -> Server {
        Server {
            id: ServerId(id.to_owned()),
            address: address.to_owned(),
            ssh_port: 22,
            ssh_user: "root".to_owned(),
            kernels: vec![KernelId("xray".to_owned())],
            enabled_protocols: protocols
                .iter()
                .map(|id| ProtocolId((*id).to_owned()))
                .collect(),
            trusted_host_fingerprint: None,
            hoster: "synthetic".to_owned(),
            jump_via: None,
            usage_coefficient: 1.0,
        }
    }

    impl Fixture {
        async fn new() -> Self {
            let dir = TempDir::new().unwrap();
            let inv = SqliteInventory::open(&dir.path().join("inventory.db"))
                .await
                .unwrap();
            inv.add_user(&user("bound")).await.unwrap();
            let (state, job) = app::make_app_state_for_tests(
                inv,
                Arc::new(vpnctl_kernels::build_registry().unwrap()),
            );
            Self {
                _dir: dir,
                state,
                job,
            }
        }

        async fn add(&self, server: &Server, grant: bool) {
            self.state.inv.add_server(server).await.unwrap();
            if grant {
                self.state
                    .inv
                    .grant(&user("bound").id, &server.id)
                    .await
                    .unwrap();
            }
        }

        async fn reality(&self, id: &ServerId) {
            self.state
                .inv
                .set_server_secret(id, "vless.public_key", &URL_SAFE_NO_PAD.encode([7_u8; 32]))
                .await
                .unwrap();
            self.state
                .inv
                .set_server_secret(id, "vless.short_id", "12345678")
                .await
                .unwrap();
            self.state
                .inv
                .set_server_secret(id, "vless.sni", "www.example.com")
                .await
                .unwrap();
        }

        async fn ws(&self, id: &ServerId, host: &str) {
            self.state
                .inv
                .set_server_secret(id, "vlessws.domain", host)
                .await
                .unwrap();
            self.state
                .inv
                .set_server_secret(id, "vlessws.path", "route123")
                .await
                .unwrap();
        }

        async fn choices(&self) -> Vec<CorpEligibleServer> {
            eligible_servers(&self.state, &user("bound").id)
                .await
                .unwrap()
        }
    }

    #[tokio::test]
    async fn missing_disabled_and_ungranted_users_have_no_eligible_servers() {
        let fixture = Fixture::new().await;
        assert!(
            eligible_servers(&fixture.state, &UserId("missing".to_owned()))
                .await
                .unwrap()
                .is_empty()
        );
        let node = server("node", "192.0.2.10", &["vless+reality"]);
        fixture.add(&node, false).await;
        fixture.reality(&node.id).await;
        assert!(fixture.choices().await.is_empty());
        fixture
            .state
            .inv
            .grant(&user("bound").id, &node.id)
            .await
            .unwrap();
        assert_eq!(fixture.choices().await.len(), 1);
        fixture
            .state
            .inv
            .set_user_disabled(&user("bound").id, true)
            .await
            .unwrap();
        assert!(fixture.choices().await.is_empty());
        fixture
            .state
            .inv
            .set_user_disabled(&user("bound").id, false)
            .await
            .unwrap();
        assert_eq!(fixture.choices().await.len(), 1);
        fixture
            .state
            .inv
            .revoke(&user("bound").id, &node.id)
            .await
            .unwrap();
        assert!(fixture.choices().await.is_empty());
    }

    #[tokio::test]
    async fn missing_render_keys_omit_endpoints_and_reality_fingerprint_has_public_safe_shape() {
        let fixture = Fixture::new().await;
        let node = server("node", "Exit.Example", &["vless+reality"]);
        fixture.add(&node, true).await;
        assert!(fixture.choices().await.is_empty());
        fixture.reality(&node.id).await;
        let choices = fixture.choices().await;
        assert_eq!(choices.len(), 1);
        assert_eq!(choices[0].server_id, node.id);
        assert_eq!(choices[0].hosts, ["exit.example"]);
        let fingerprint = &choices[0].configuration_fingerprint;
        assert_eq!(fingerprint.len(), 64);
        assert!(
            fingerprint
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        );
        let debug = format!("{:?}", choices[0]);
        for secret in [
            user("bound").uuid,
            URL_SAFE_NO_PAD.encode([7_u8; 32]),
            "12345678".to_owned(),
            "vless://".to_owned(),
        ] {
            assert!(!debug.contains(&secret));
        }
    }

    #[tokio::test]
    async fn protocol_visibility_per_user_override_and_suppression_remove_choices() {
        let fixture = Fixture::new().await;
        let node = server("node", "192.0.2.10", &["vless+reality"]);
        fixture.add(&node, true).await;
        fixture.reality(&node.id).await;
        let protocol = ProtocolId("vless+reality".to_owned());
        fixture
            .state
            .inv
            .set_server_protocol_hidden(&node.id, &protocol, true)
            .await
            .unwrap();
        assert!(fixture.choices().await.is_empty());
        fixture
            .state
            .inv
            .set_server_protocol_hidden(&node.id, &protocol, false)
            .await
            .unwrap();
        assert_eq!(fixture.choices().await.len(), 1);
        fixture
            .state
            .inv
            .set_grant_protocol_override(&user("bound").id, &node.id, &protocol, true)
            .await
            .unwrap();
        assert!(fixture.choices().await.is_empty());
        fixture
            .state
            .inv
            .set_grant_protocol_override(&user("bound").id, &node.id, &protocol, false)
            .await
            .unwrap();
        assert_eq!(fixture.choices().await.len(), 1);
        fixture
            .state
            .inv
            .set_server_suppressed(&node.id, true)
            .await
            .unwrap();
        assert_eq!(fixture.choices().await.len(), 1);
        fixture
            .state
            .inv
            .set_server_auto_suppress(&node.id, true)
            .await
            .unwrap();
        assert!(fixture.choices().await.is_empty());
        fixture
            .state
            .inv
            .set_server_suppressed(&node.id, false)
            .await
            .unwrap();
        assert_eq!(fixture.choices().await.len(), 1);
    }

    #[tokio::test]
    async fn detoured_server_is_not_a_direct_business_choice() {
        let fixture = Fixture::new().await;
        let node = server("node", "192.0.2.10", &["vless+reality"]);
        let detour = server("detour", "192.0.2.11", &["vless+reality"]);
        for entry in [&node, &detour] {
            fixture.add(entry, true).await;
            fixture.reality(&entry.id).await;
        }
        assert_eq!(fixture.choices().await.len(), 2);
        fixture
            .state
            .inv
            .set_client_detour_via_as("spec", &node.id, Some(&detour.id))
            .await
            .unwrap();
        assert!(
            fixture
                .choices()
                .await
                .iter()
                .all(|choice| choice.server_id != node.id)
        );
    }

    #[tokio::test]
    async fn malformed_reality_credentials_fail_with_static_sanitized_errors() {
        for (name, value) in [
            ("vless.public_key", "SENSITIVE_NOT_A_REALITY_KEY".to_owned()),
            ("vless.public_key", URL_SAFE_NO_PAD.encode([7_u8; 31])),
            ("vless.public_key", URL_SAFE_NO_PAD.encode([7_u8; 33])),
            ("vless.short_id", "abc".to_owned()),
            ("vless.short_id", "zz".to_owned()),
            ("vless.short_id", "12".repeat(9)),
        ] {
            let fixture = Fixture::new().await;
            let node = server("node", "192.0.2.10", &["vless+reality"]);
            fixture.add(&node, true).await;
            fixture.reality(&node.id).await;
            fixture
                .state
                .inv
                .set_server_secret(&node.id, name, &value)
                .await
                .unwrap();
            let error = eligible_servers(&fixture.state, &user("bound").id)
                .await
                .unwrap_err();
            assert_eq!(error, EligibilityError::InvalidConfiguration);
            assert!(!format!("{error:?} {error}").contains(&value));
            assert!(!format!("{error:?} {error}").contains(&user("bound").uuid));
        }
    }

    #[tokio::test]
    async fn reality_accepts_empty_and_maximum_even_hex_short_id_but_drops_client_placeholders() {
        let fixture = Fixture::new().await;
        let node = server("node", "192.0.2.10", &["vless+reality"]);
        fixture.add(&node, true).await;
        fixture.reality(&node.id).await;
        for short in ["", "aB0123456789cDEF"] {
            fixture
                .state
                .inv
                .set_server_secret(&node.id, "vless.short_id", short)
                .await
                .unwrap();
            assert_eq!(fixture.choices().await.len(), 1);
        }
        for short in ["78ca7952", "78CA7952"] {
            fixture
                .state
                .inv
                .set_server_secret(&node.id, "vless.short_id", short)
                .await
                .unwrap();
            assert!(fixture.choices().await.is_empty());
        }
        fixture
            .state
            .inv
            .set_server_secret(&node.id, "vless.short_id", "12345678")
            .await
            .unwrap();
        for placeholder in [
            "DnT9hIvt5QEx07unHUeXbWxN4Qo1gnecN4p0s62nckU".to_owned(),
            "DnT9hIvt5QEx07unHUeXbWxN4Qo1gnecN4p0s62nckU".to_ascii_lowercase(),
            "DnT9hIvt5QEx07unHUeXbWxN4Qo1gnecN4p0s62nckU".to_ascii_uppercase(),
        ] {
            fixture
                .state
                .inv
                .set_server_secret(&node.id, "vless.public_key", &placeholder)
                .await
                .unwrap();
            assert!(fixture.choices().await.is_empty());
        }
        let address_fixture = Fixture::new().await;
        let placeholder = server("placeholder", "195.135.255.216", &["vless+reality"]);
        address_fixture.add(&placeholder, true).await;
        address_fixture.reality(&placeholder.id).await;
        assert!(address_fixture.choices().await.is_empty());
    }

    #[tokio::test]
    async fn websocket_uses_rendered_domain_instead_of_inventory_address_and_groups_hosts() {
        let fixture = Fixture::new().await;
        let node = server("node", "192.0.2.10", &["vless+reality", "vless-ws"]);
        fixture.add(&node, true).await;
        fixture.reality(&node.id).await;
        fixture.ws(&node.id, "EDGE.Example.NET").await;
        let choices = fixture.choices().await;
        assert_eq!(choices.len(), 1);
        assert_eq!(choices[0].hosts, ["192.0.2.10", "edge.example.net"]);
        fixture
            .state
            .inv
            .set_server_protocol_hidden(&node.id, &ProtocolId("vless+reality".to_owned()), true)
            .await
            .unwrap();
        let ws_only = fixture.choices().await;
        assert_eq!(ws_only[0].hosts, ["edge.example.net"]);
        assert_ne!(
            ws_only[0].configuration_fingerprint,
            choices[0].configuration_fingerprint
        );
    }

    #[tokio::test]
    async fn protocol_major_order_keeps_reality_before_websocket_across_servers() {
        let fixture = Fixture::new().await;
        let ws = server("a-websocket", "192.0.2.10", &["vless-ws"]);
        fixture.add(&ws, true).await;
        fixture.ws(&ws.id, "shared.example.net").await;
        let reality = server("z-reality", "shared.example.net", &["vless+reality"]);
        fixture.add(&reality, true).await;
        fixture.reality(&reality.id).await;
        let choices = fixture.choices().await;
        assert_eq!(choices.len(), 1);
        assert_eq!(choices[0].server_id, reality.id);
        assert_eq!(choices[0].hosts, ["shared.example.net"]);
    }

    #[tokio::test]
    async fn label_changes_do_not_change_fingerprint_and_are_trimmed() {
        let fixture = Fixture::new().await;
        let node = server("node", "192.0.2.10", &["vless+reality"]);
        fixture.add(&node, true).await;
        fixture.reality(&node.id).await;
        let before = fixture.choices().await;
        fixture
            .state
            .inv
            .set_server_display_name(&node.id, Some("  Synthetic office  "))
            .await
            .unwrap();
        let after = fixture.choices().await;
        assert_eq!(after[0].label, "Synthetic office");
        assert_eq!(
            after[0].configuration_fingerprint,
            before[0].configuration_fingerprint
        );
        assert_eq!(after[0].hosts, before[0].hosts);
    }

    #[tokio::test]
    async fn other_user_credentials_do_not_change_bound_user_fingerprint() {
        let fixture = Fixture::new().await;
        let node = server("node", "192.0.2.10", &["vless+reality"]);
        fixture.add(&node, true).await;
        fixture.reality(&node.id).await;
        let before = fixture.choices().await;
        let other = user("other");
        fixture.state.inv.add_user(&other).await.unwrap();
        fixture.state.inv.grant(&other.id, &node.id).await.unwrap();
        let after = fixture.choices().await;
        assert_eq!(
            after[0].configuration_fingerprint,
            before[0].configuration_fingerprint
        );
        fixture.state.inv.remove_user(&other.id).await.unwrap();
        let mut changed_other = other;
        changed_other.uuid = "33333333-3333-4333-8333-333333333333".to_owned();
        fixture.state.inv.add_user(&changed_other).await.unwrap();
        fixture
            .state
            .inv
            .grant(&changed_other.id, &node.id)
            .await
            .unwrap();
        assert_eq!(
            fixture.choices().await[0].configuration_fingerprint,
            before[0].configuration_fingerprint
        );
    }

    #[tokio::test]
    async fn selected_credential_and_transport_setting_changes_change_fingerprint() {
        let fixture = Fixture::new().await;
        let node = server("node", "192.0.2.10", &["vless+reality"]);
        fixture.add(&node, true).await;
        fixture.reality(&node.id).await;
        let before = fixture.choices().await;
        fixture
            .state
            .inv
            .set_server_secret(&node.id, "vless.short_id", "abcd5678")
            .await
            .unwrap();
        let changed = fixture.choices().await;
        assert_ne!(
            changed[0].configuration_fingerprint,
            before[0].configuration_fingerprint
        );
        fixture
            .state
            .inv
            .set_server_secret(&node.id, "vless.sni", "other.example.com")
            .await
            .unwrap();
        let changed_again = fixture.choices().await;
        assert_ne!(
            changed_again[0].configuration_fingerprint,
            changed[0].configuration_fingerprint
        );
        fixture
            .state
            .inv
            .set_server_secret(
                &node.id,
                "vless.public_key",
                &URL_SAFE_NO_PAD.encode([8_u8; 32]),
            )
            .await
            .unwrap();
        assert_ne!(
            fixture.choices().await[0].configuration_fingerprint,
            changed_again[0].configuration_fingerprint
        );
    }

    #[tokio::test]
    async fn secret_insertion_order_does_not_change_fingerprint() {
        let first = Fixture::new().await;
        let second = Fixture::new().await;
        let node = server("node", "192.0.2.10", &["vless+reality"]);
        first.add(&node, true).await;
        second.add(&node, true).await;
        first.reality(&node.id).await;
        second
            .state
            .inv
            .set_server_secret(&node.id, "vless.sni", "www.example.com")
            .await
            .unwrap();
        second
            .state
            .inv
            .set_server_secret(&node.id, "vless.short_id", "12345678")
            .await
            .unwrap();
        second
            .state
            .inv
            .set_server_secret(
                &node.id,
                "vless.public_key",
                &URL_SAFE_NO_PAD.encode([7_u8; 32]),
            )
            .await
            .unwrap();
        assert_eq!(
            first.choices().await[0].configuration_fingerprint,
            second.choices().await[0].configuration_fingerprint
        );
    }

    #[tokio::test]
    async fn inventory_failure_returns_sanitized_error_without_stale_eligibility() {
        let fixture = Fixture::new().await;
        let node = server("node", "192.0.2.10", &["vless+reality"]);
        fixture.add(&node, true).await;
        fixture.reality(&node.id).await;
        assert_eq!(fixture.choices().await.len(), 1);
        let path = fixture._dir.path().join("inventory.db");
        let mut connection =
            SqliteConnection::connect_with(&SqliteConnectOptions::new().filename(&path))
                .await
                .unwrap();
        sqlx::query("ALTER TABLE users RENAME TO spec_unavailable_users")
            .execute(&mut connection)
            .await
            .unwrap();
        drop(connection);
        let error = eligible_servers(&fixture.state, &user("bound").id)
            .await
            .unwrap_err();
        assert_eq!(error, EligibilityError::InventoryUnavailable);
        let text = format!("{error:?} {error}");
        for private in ["sqlite", "inventory.db", "vless://", &user("bound").uuid] {
            assert!(!text.contains(private));
        }
    }

    #[tokio::test]
    async fn same_host_deduplicates_across_server_ids_ports_and_transports_in_server_order() {
        let fixture = Fixture::new().await;
        let first = server(
            "a-first",
            "same.example.net",
            &["vless+reality", "vless-ws"],
        );
        let second = server("z-second", "same.example.net", &["vless+reality"]);
        fixture.add(&second, true).await;
        fixture.reality(&second.id).await;
        fixture.add(&first, true).await;
        fixture.reality(&first.id).await;
        fixture.ws(&first.id, "SAME.EXAMPLE.NET").await;
        fixture
            .state
            .inv
            .set_server_secret(&first.id, "vlessws.listen_port", "8443")
            .await
            .unwrap();
        let choices = fixture.choices().await;
        assert_eq!(choices.len(), 1);
        assert_eq!(choices[0].server_id, first.id);
        assert_eq!(choices[0].hosts, ["same.example.net"]);
        fixture
            .state
            .inv
            .set_server_secret(&first.id, "vlessws.path", "different123")
            .await
            .unwrap();
        assert_eq!(
            fixture.choices().await[0].configuration_fingerprint,
            choices[0].configuration_fingerprint
        );
    }

    #[tokio::test]
    async fn ipv6_authority_is_normalized_without_brackets() {
        let fixture = Fixture::new().await;
        let node = server("node", "2001:db8::10", &["vless+reality"]);
        fixture.add(&node, true).await;
        fixture.reality(&node.id).await;
        assert_eq!(fixture.choices().await[0].hosts, ["2001:db8::10"]);
    }

    #[tokio::test]
    async fn selected_host_ssh_port_user_pin_and_kernel_changes_invalidate_fingerprint() {
        let fixture = Fixture::new().await;
        let node = server("node", "192.0.2.10", &["vless+reality"]);
        fixture.add(&node, true).await;
        fixture.reality(&node.id).await;
        let first = fixture.choices().await[0].configuration_fingerprint.clone();
        fixture
            .state
            .inv
            .update_server_address(&node.id, "192.0.2.11", 22, "root")
            .await
            .unwrap();
        let second = fixture.choices().await[0].configuration_fingerprint.clone();
        assert_ne!(second, first);
        fixture
            .state
            .inv
            .update_server_address(&node.id, "192.0.2.11", 2222, "root")
            .await
            .unwrap();
        let third = fixture.choices().await[0].configuration_fingerprint.clone();
        assert_ne!(third, second);
        fixture
            .state
            .inv
            .update_server_address(&node.id, "192.0.2.11", 2222, "operator")
            .await
            .unwrap();
        let fourth = fixture.choices().await[0].configuration_fingerprint.clone();
        assert_ne!(fourth, third);
        fixture
            .state
            .inv
            .update_trusted_fingerprint(
                &node.id,
                "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            )
            .await
            .unwrap();
        let fifth = fixture.choices().await[0].configuration_fingerprint.clone();
        assert_ne!(fifth, fourth);
        fixture
            .state
            .inv
            .add_server_kernel(&node.id, &KernelId("sing-box".to_owned()))
            .await
            .unwrap();
        assert_ne!(fixture.choices().await[0].configuration_fingerprint, fifth);
    }

    #[tokio::test]
    async fn ws_host_port_and_path_changes_invalidate_selected_transport_fingerprint() {
        let fixture = Fixture::new().await;
        let node = server("node", "192.0.2.10", &["vless-ws"]);
        fixture.add(&node, true).await;
        fixture.ws(&node.id, "first.example.net").await;
        let first = fixture.choices().await[0].configuration_fingerprint.clone();
        fixture
            .state
            .inv
            .set_server_secret(&node.id, "vlessws.domain", "second.example.net")
            .await
            .unwrap();
        let changed_host = fixture.choices().await;
        assert_eq!(changed_host[0].hosts, ["second.example.net"]);
        assert_ne!(changed_host[0].configuration_fingerprint, first);
        fixture
            .state
            .inv
            .set_server_secret(&node.id, "vlessws.listen_port", "8443")
            .await
            .unwrap();
        let changed_port = fixture.choices().await[0].configuration_fingerprint.clone();
        assert_ne!(changed_port, changed_host[0].configuration_fingerprint);
        fixture
            .state
            .inv
            .set_server_secret(&node.id, "vlessws.path", "changed123")
            .await
            .unwrap();
        assert_ne!(
            fixture.choices().await[0].configuration_fingerprint,
            changed_port
        );
    }

    #[tokio::test]
    async fn business_xhttp_is_selected_when_reality_is_hidden_and_tracks_mode_changes() {
        let fixture = Fixture::new().await;
        let node = server("node", "192.0.2.10", &["vless+reality", "vless+xhttp"]);
        fixture.add(&node, true).await;
        fixture.reality(&node.id).await;
        fixture
            .state
            .inv
            .set_server_secret(&node.id, "vlessxhttp.path", "xroute123")
            .await
            .unwrap();
        let reality_first = fixture.choices().await;
        assert_eq!(reality_first[0].hosts, ["192.0.2.10"]);
        fixture
            .state
            .inv
            .set_server_protocol_hidden(&node.id, &ProtocolId("vless+reality".to_owned()), true)
            .await
            .unwrap();
        let xhttp = fixture.choices().await;
        assert_eq!(xhttp.len(), 1);
        assert_eq!(xhttp[0].hosts, ["192.0.2.10"]);
        assert_ne!(
            xhttp[0].configuration_fingerprint,
            reality_first[0].configuration_fingerprint
        );
        fixture
            .state
            .inv
            .set_server_secret(&node.id, "vlessxhttp.mode", "stream-up")
            .await
            .unwrap();
        assert_ne!(
            fixture.choices().await[0].configuration_fingerprint,
            xhttp[0].configuration_fingerprint
        );
    }

    #[tokio::test]
    async fn resolved_pinned_ssh_jump_route_and_its_changes_invalidate_fingerprint() {
        let fixture = Fixture::new().await;
        let mut jump = server("jump", "192.0.2.11", &[]);
        jump.trusted_host_fingerprint =
            Some("SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned());
        let mut target = server("target", "192.0.2.10", &["vless+reality"]);
        target.trusted_host_fingerprint = jump.trusted_host_fingerprint.clone();
        fixture.add(&jump, false).await;
        fixture.add(&target, true).await;
        fixture.reality(&target.id).await;
        let direct = fixture.choices().await[0].configuration_fingerprint.clone();
        fixture
            .state
            .inv
            .set_server_routing_policy_as("spec", &target.id, ServerRole::VpnExit, Some(&jump.id))
            .await
            .unwrap();
        let routed = fixture.choices().await;
        assert_eq!(routed.len(), 1);
        assert_eq!(routed[0].server_id, target.id);
        assert_ne!(routed[0].configuration_fingerprint, direct);
        fixture
            .state
            .inv
            .update_server_address(&jump.id, "192.0.2.11", 2222, "root")
            .await
            .unwrap();
        let changed_port = fixture.choices().await[0].configuration_fingerprint.clone();
        assert_ne!(changed_port, routed[0].configuration_fingerprint);
        fixture
            .state
            .inv
            .update_trusted_fingerprint(
                &jump.id,
                &format!("SHA256:{}", URL_SAFE_NO_PAD.encode([1_u8; 32])),
            )
            .await
            .unwrap();
        assert_ne!(
            fixture.choices().await[0].configuration_fingerprint,
            changed_port
        );
    }

    async fn plan(
        fixture: &Fixture,
        id: &ServerId,
    ) -> vpnctld::corp_portal::eligibility::CorpProbePlan {
        let plan = probe_plan(&fixture.state, &user("bound").id, id)
            .await
            .unwrap()
            .unwrap();
        let safe = fixture.choices().await;
        assert_eq!(
            &plan.server,
            safe.iter().find(|row| &row.server_id == id).unwrap()
        );
        assert_eq!(plan.outbounds.len(), plan.server.hosts.len());
        for (outbound, host) in plan.outbounds.iter().zip(&plan.server.hosts) {
            assert!(outbound.is_object());
            assert_eq!(outbound["type"], "vless");
            assert!(!outbound["uuid"].as_str().unwrap().is_empty());
            assert!(outbound.get("detour").is_none());
            assert!((1..=65535).contains(&outbound["server_port"].as_u64().unwrap()));
            let actual = outbound["server"]
                .as_str()
                .unwrap()
                .trim_matches(['[', ']'])
                .to_ascii_lowercase();
            let actual = actual
                .parse::<std::net::IpAddr>()
                .map_or(actual.clone(), |ip| ip.to_string());
            assert_eq!(&actual, host);
        }
        plan
    }

    #[tokio::test]
    async fn probe_plan_covers_every_selected_host_with_exact_renderer_json_and_per_server_uuid() {
        let fixture = Fixture::new().await;
        let node = server(
            "node",
            "Exit.Example",
            &["vless+reality", "vless-ws", "vless+xhttp"],
        );
        fixture.add(&node, true).await;
        fixture.reality(&node.id).await;
        fixture.ws(&node.id, "EDGE.Example.NET").await;
        fixture
            .state
            .inv
            .set_server_secret(&node.id, "vlessxhttp.path", "xroute123")
            .await
            .unwrap();
        let override_uuid = "33333333-3333-4333-8333-333333333333";
        fixture
            .state
            .inv
            .set_grant_client_uuid(&user("bound").id, &node.id, override_uuid)
            .await
            .unwrap();
        let before_audit = fixture.state.inv.recent_audit(100).await.unwrap().len();
        let selected = plan(&fixture, &node.id).await;
        assert_eq!(selected.server.hosts, ["exit.example", "edge.example.net"]);
        let mut secrets = HashMap::from([
            (
                "vless.public_key".to_owned(),
                URL_SAFE_NO_PAD.encode([7_u8; 32]),
            ),
            ("vless.short_id".to_owned(), "12345678".to_owned()),
            ("vless.sni".to_owned(), "www.example.com".to_owned()),
            ("vlessws.domain".to_owned(), "EDGE.Example.NET".to_owned()),
            ("vlessws.path".to_owned(), "route123".to_owned()),
            ("vlessxhttp.path".to_owned(), "xroute123".to_owned()),
        ]);
        let mut subscriber = user("bound");
        subscriber.uuid = override_uuid.to_owned();
        let context = RenderCtx::new(&node, &secrets);
        // Whole-value equality catches loss of tags, TLS/uTLS/Reality, flow and WS Host/path.
        assert_eq!(
            selected.outbounds,
            vec![
                vpnctl_protocols::VlessReality::new()
                    .client_config(&context, &subscriber)
                    .unwrap(),
                vpnctl_protocols::VlessWs::new()
                    .client_config(&context, &subscriber)
                    .unwrap(),
            ]
        );
        assert_eq!(
            fixture.state.inv.recent_audit(100).await.unwrap().len(),
            before_audit
        );
        assert!(fixture.state.inv.corp_record().await.unwrap().is_none());
        assert!(
            fixture
                .state
                .inv
                .corp_verified_egress()
                .await
                .unwrap()
                .is_empty()
        );
        // Same-host XHTTP is omitted until Reality stops winning that host.
        fixture
            .state
            .inv
            .set_server_protocol_hidden(&node.id, &ProtocolId("vless+reality".to_owned()), true)
            .await
            .unwrap();
        fixture
            .state
            .inv
            .set_server_secret(&node.id, "vlessxhttp.mode", "stream-up")
            .await
            .unwrap();
        secrets.insert("vlessxhttp.mode".to_owned(), "stream-up".to_owned());
        let xhttp = plan(&fixture, &node.id).await;
        assert_eq!(xhttp.server.hosts, ["edge.example.net", "exit.example"]);
        let context = RenderCtx::new(&node, &secrets);
        assert_eq!(
            xhttp.outbounds,
            vec![
                vpnctl_protocols::VlessWs::new()
                    .client_config(&context, &subscriber)
                    .unwrap(),
                vpnctl_protocols::VlessXhttp::new()
                    .client_config(&context, &subscriber)
                    .unwrap(),
            ]
        );
        assert_ne!(
            xhttp.server.configuration_fingerprint,
            selected.server.configuration_fingerprint
        );
    }

    #[tokio::test]
    async fn probe_plan_first_wins_is_global_protocol_major_and_omits_losing_servers() {
        let fixture = Fixture::new().await;
        let ws = server("a-ws", "192.0.2.10", &["vless-ws"]);
        let first = server(
            "b-first",
            "SHARED.Example",
            &["vless+reality", "vless-ws", "vless+xhttp"],
        );
        let last = server("z-last", "shared.example", &["vless+reality"]);
        for node in [&ws, &first, &last] {
            fixture.add(node, true).await;
        }
        fixture.ws(&ws.id, "shared.example").await;
        fixture.reality(&first.id).await;
        fixture.reality(&last.id).await;
        fixture.ws(&first.id, "shared.example").await;
        fixture
            .state
            .inv
            .set_server_secret(&first.id, "vlessxhttp.path", "xroute123")
            .await
            .unwrap();
        let selected = plan(&fixture, &first.id).await;
        assert_eq!(selected.outbounds.len(), 1);
        assert_eq!(selected.outbounds[0]["uuid"], user("bound").uuid);
        for id in [&ws.id, &last.id] {
            assert!(
                probe_plan(&fixture.state, &user("bound").id, id)
                    .await
                    .unwrap()
                    .is_none()
            );
        }
    }

    #[tokio::test]
    async fn probe_plan_is_none_for_every_ineligibility_and_never_adds_non_vless_siblings() {
        let fixture = Fixture::new().await;
        let node = server("node", "192.0.2.10", &["vless+reality", "trojan"]);
        fixture.add(&node, false).await;
        assert!(
            probe_plan(&fixture.state, &user("bound").id, &node.id)
                .await
                .unwrap()
                .is_none()
        );
        fixture
            .state
            .inv
            .grant(&user("bound").id, &node.id)
            .await
            .unwrap();
        assert!(
            probe_plan(&fixture.state, &user("bound").id, &node.id)
                .await
                .unwrap()
                .is_none()
        );
        fixture.reality(&node.id).await;
        assert_eq!(plan(&fixture, &node.id).await.outbounds.len(), 1);
        assert!(
            probe_plan(&fixture.state, &UserId("missing".to_owned()), &node.id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            probe_plan(
                &fixture.state,
                &user("bound").id,
                &ServerId("missing".to_owned())
            )
            .await
            .unwrap()
            .is_none()
        );
        let protocol = ProtocolId("vless+reality".to_owned());
        fixture
            .state
            .inv
            .set_server_protocol_hidden(&node.id, &protocol, true)
            .await
            .unwrap();
        assert!(
            probe_plan(&fixture.state, &user("bound").id, &node.id)
                .await
                .unwrap()
                .is_none()
        );
        fixture
            .state
            .inv
            .set_server_protocol_hidden(&node.id, &protocol, false)
            .await
            .unwrap();
        fixture
            .state
            .inv
            .set_grant_protocol_override(&user("bound").id, &node.id, &protocol, true)
            .await
            .unwrap();
        assert!(
            probe_plan(&fixture.state, &user("bound").id, &node.id)
                .await
                .unwrap()
                .is_none()
        );
        fixture
            .state
            .inv
            .set_grant_protocol_override(&user("bound").id, &node.id, &protocol, false)
            .await
            .unwrap();
        fixture
            .state
            .inv
            .set_server_auto_suppress(&node.id, true)
            .await
            .unwrap();
        fixture
            .state
            .inv
            .set_server_suppressed(&node.id, true)
            .await
            .unwrap();
        assert!(
            probe_plan(&fixture.state, &user("bound").id, &node.id)
                .await
                .unwrap()
                .is_none()
        );
        fixture
            .state
            .inv
            .set_server_suppressed(&node.id, false)
            .await
            .unwrap();
        assert_eq!(plan(&fixture, &node.id).await.outbounds.len(), 1);
        fixture
            .state
            .inv
            .set_user_disabled(&user("bound").id, true)
            .await
            .unwrap();
        assert!(
            probe_plan(&fixture.state, &user("bound").id, &node.id)
                .await
                .unwrap()
                .is_none()
        );
        fixture
            .state
            .inv
            .set_user_disabled(&user("bound").id, false)
            .await
            .unwrap();
        let detour = server("detour", "192.0.2.11", &["vless+reality"]);
        fixture.add(&detour, true).await;
        fixture.reality(&detour.id).await;
        fixture
            .state
            .inv
            .set_client_detour_via_as("spec", &node.id, Some(&detour.id))
            .await
            .unwrap();
        assert!(
            probe_plan(&fixture.state, &user("bound").id, &node.id)
                .await
                .unwrap()
                .is_none()
        );
        fixture
            .state
            .inv
            .remove_user(&user("bound").id)
            .await
            .unwrap();
        assert!(
            probe_plan(&fixture.state, &user("bound").id, &detour.id)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn probe_plan_fingerprint_binds_uuid_settings_and_tracks_safe_label_stability() {
        let fixture = Fixture::new().await;
        let node = server("node", "192.0.2.10", &["vless-ws"]);
        fixture.add(&node, true).await;
        fixture.ws(&node.id, "edge.example.net").await;
        let before = plan(&fixture, &node.id).await;
        fixture
            .state
            .inv
            .set_server_display_name(&node.id, Some("  Office  "))
            .await
            .unwrap();
        let renamed = plan(&fixture, &node.id).await;
        assert_eq!(renamed.server.label, "Office");
        assert_eq!(
            renamed.server.configuration_fingerprint,
            before.server.configuration_fingerprint
        );
        assert_eq!(renamed.outbounds, before.outbounds);
        fixture
            .state
            .inv
            .set_grant_client_uuid(
                &user("bound").id,
                &node.id,
                "44444444-4444-4444-8444-444444444444",
            )
            .await
            .unwrap();
        let changed = plan(&fixture, &node.id).await;
        assert_eq!(
            changed.outbounds[0]["uuid"],
            "44444444-4444-4444-8444-444444444444"
        );
        assert_ne!(
            changed.server.configuration_fingerprint,
            before.server.configuration_fingerprint
        );
        fixture
            .state
            .inv
            .set_server_secret(&node.id, "vlessws.path", "updatedpath")
            .await
            .unwrap();
        let path = plan(&fixture, &node.id).await;
        assert_ne!(path.outbounds, changed.outbounds);
        assert_ne!(
            path.server.configuration_fingerprint,
            changed.server.configuration_fingerprint
        );
    }

    #[tokio::test]
    async fn probe_plan_accepts_normalized_ipv6_authority_without_rewriting_renderer_json() {
        let fixture = Fixture::new().await;
        let node = server(
            "node",
            "2001:0db8:0000:0000:0000:0000:0000:0010",
            &["vless+reality"],
        );
        fixture.add(&node, true).await;
        fixture.reality(&node.id).await;
        let selected = plan(&fixture, &node.id).await;
        assert_eq!(selected.server.hosts, ["2001:db8::10"]);
        assert_eq!(selected.outbounds[0]["server"], node.address);
    }

    #[tokio::test]
    async fn probe_plan_errors_are_sanitized_and_inventory_failure_has_no_stale_fallback() {
        let fixture = Fixture::new().await;
        let node = server("node", "192.0.2.10", &["vless+reality"]);
        fixture.add(&node, true).await;
        fixture.reality(&node.id).await;
        assert_eq!(plan(&fixture, &node.id).await.outbounds.len(), 1);
        let sensitive = "SENSITIVE_INVALID_REALITY_KEY";
        fixture
            .state
            .inv
            .set_server_secret(&node.id, "vless.public_key", sensitive)
            .await
            .unwrap();
        let result = probe_plan(&fixture.state, &user("bound").id, &node.id).await;
        // Do not require Debug on the credential-bearing success type.
        assert!(matches!(
            result,
            Err(EligibilityError::InvalidConfiguration)
        ));
        if let Err(error) = result {
            for secret in [sensitive, &user("bound").uuid, "vless://"] {
                assert!(!format!("{error:?} {error}").contains(secret));
            }
        }
        let path = fixture._dir.path().join("inventory.db");
        let mut connection =
            SqliteConnection::connect_with(&SqliteConnectOptions::new().filename(&path))
                .await
                .unwrap();
        sqlx::query("ALTER TABLE users RENAME TO spec_unavailable_users")
            .execute(&mut connection)
            .await
            .unwrap();
        drop(connection);
        let result = probe_plan(&fixture.state, &user("bound").id, &node.id).await;
        assert!(matches!(
            result,
            Err(EligibilityError::InventoryUnavailable)
        ));
        if let Err(error) = result {
            for private in ["sqlite", "inventory.db", sensitive, &user("bound").uuid] {
                assert!(!format!("{error:?} {error}").contains(private));
            }
        }
    }

    #[derive(Debug)]
    enum SelectedRealityRenderer {
        Outbound(serde_json::Value),
        Failure,
    }

    impl Protocol for SelectedRealityRenderer {
        fn id(&self) -> ProtocolId {
            ProtocolId("vless+reality".to_owned())
        }

        fn server_inbound(
            &self,
            _ctx: &RenderCtx<'_>,
            _users: &[User],
        ) -> vpnctl_core::Result<serde_json::Value> {
            Err(vpnctl_core::CoreError::Render(
                "unused spec inbound".to_owned(),
            ))
        }

        fn client_config(
            &self,
            _ctx: &RenderCtx<'_>,
            _user: &User,
        ) -> vpnctl_core::Result<serde_json::Value> {
            match self {
                Self::Outbound(value) => Ok(value.clone()),
                Self::Failure => Err(vpnctl_core::CoreError::Render(
                    "SENSITIVE_RENDER_FAILURE_vless://synthetic".to_owned(),
                )),
            }
        }

        fn share_link(&self, ctx: &RenderCtx<'_>, user: &User) -> vpnctl_core::Result<String> {
            vpnctl_protocols::VlessReality::new().share_link(ctx, user)
        }
    }

    fn install_selected_renderer(fixture: &mut Fixture, renderer: SelectedRealityRenderer) {
        let mut registry = vpnctl_core::Registry::new();
        registry.register_protocol(Box::new(renderer)).unwrap();
        fixture.state.registry = Arc::new(registry);
    }

    #[tokio::test]
    async fn renderer_only_changes_bind_full_json_preserve_object_order_stability_and_array_order()
    {
        let mut fixture = Fixture::new().await;
        let node = server("node", "192.0.2.10", &["vless+reality"]);
        fixture.add(&node, true).await;
        fixture.reality(&node.id).await;
        let baseline = plan(&fixture, &node.id).await;
        let mut outbound = baseline.outbounds[0].clone();
        outbound["spec_renderer_extension"] =
            serde_json::from_str(r#"{"outer":{"z":2,"a":1},"ordered":["first","second"]}"#)
                .unwrap();
        install_selected_renderer(
            &mut fixture,
            SelectedRealityRenderer::Outbound(outbound.clone()),
        );
        let extended = plan(&fixture, &node.id).await;
        assert_eq!(extended.outbounds, [outbound.clone()]);
        assert_ne!(
            extended.server.configuration_fingerprint,
            baseline.server.configuration_fingerprint
        );
        // The share link, selected host, inventory and secrets have not changed.
        outbound["spec_renderer_extension"] =
            serde_json::from_str(r#"{"ordered":["first","second"],"outer":{"a":1,"z":2}}"#)
                .unwrap();
        install_selected_renderer(
            &mut fixture,
            SelectedRealityRenderer::Outbound(outbound.clone()),
        );
        let reordered_keys = plan(&fixture, &node.id).await;
        assert_eq!(
            reordered_keys.server.configuration_fingerprint,
            extended.server.configuration_fingerprint
        );
        outbound["spec_renderer_extension"]["ordered"] = serde_json::json!(["second", "first"]);
        install_selected_renderer(
            &mut fixture,
            SelectedRealityRenderer::Outbound(outbound.clone()),
        );
        let reordered_array = plan(&fixture, &node.id).await;
        assert_eq!(reordered_array.outbounds, [outbound]);
        assert_ne!(
            reordered_array.server.configuration_fingerprint,
            extended.server.configuration_fingerprint
        );
    }

    async fn assert_plan_configuration_failure(fixture: &Fixture, id: &ServerId) {
        let result = probe_plan(&fixture.state, &user("bound").id, id).await;
        assert!(matches!(
            result,
            Err(EligibilityError::InvalidConfiguration)
        ));
        if let Err(error) = result {
            let text = format!("{error:?} {error}");
            for private in [
                "SENSITIVE_RENDER_FAILURE",
                "vless://",
                "SENSITIVE_OUTBOUND_UUID",
                "unrelated.example",
                &user("bound").uuid,
            ] {
                assert!(!text.contains(private));
            }
        }
        assert_eq!(
            eligible_servers(&fixture.state, &user("bound").id)
                .await
                .unwrap_err(),
            EligibilityError::InvalidConfiguration
        );
    }

    #[tokio::test]
    async fn malformed_or_failed_selected_renderer_is_sanitized_without_stale_or_repaired_plan() {
        let mut fixture = Fixture::new().await;
        let node = server("node", "192.0.2.10", &["vless+reality"]);
        fixture.add(&node, true).await;
        fixture.reality(&node.id).await;
        let baseline = plan(&fixture, &node.id).await;
        let outbound = baseline.outbounds[0].clone();
        let mut malformed = vec![serde_json::Value::Null, serde_json::json!([])];
        for (key, value) in [
            ("type", serde_json::json!("direct")),
            ("uuid", serde_json::json!("")),
            ("uuid", serde_json::Value::Null),
            ("server_port", serde_json::json!(0)),
            ("server_port", serde_json::json!(65536)),
            ("server_port", serde_json::json!(443.5)),
            ("server", serde_json::json!("unrelated.example")),
            ("detour", serde_json::json!("SENSITIVE_DETOUR")),
        ] {
            let mut value_outbound = outbound.clone();
            value_outbound["uuid"] = serde_json::json!("SENSITIVE_OUTBOUND_UUID");
            value_outbound[key] = value;
            malformed.push(value_outbound);
        }
        for malformed in malformed {
            install_selected_renderer(&mut fixture, SelectedRealityRenderer::Outbound(malformed));
            assert_plan_configuration_failure(&fixture, &node.id).await;
        }
        install_selected_renderer(&mut fixture, SelectedRealityRenderer::Failure);
        assert_plan_configuration_failure(&fixture, &node.id).await;
        // A selected share-link choice without its trusted renderer is an error.
        fixture.state.registry = Arc::new(vpnctl_core::Registry::new());
        assert_plan_configuration_failure(&fixture, &node.id).await;
        // Recovering the renderer must return the original current plan, never cached errors.
        install_selected_renderer(&mut fixture, SelectedRealityRenderer::Outbound(outbound));
        let recovered = plan(&fixture, &node.id).await;
        assert_eq!(
            recovered.server.configuration_fingerprint,
            baseline.server.configuration_fingerprint
        );
        assert_eq!(recovered.outbounds, baseline.outbounds);
    }

    #[test]
    fn probe_plan_debug_redacts_every_field_in_ordinary_and_pretty_output() {
        let plan = vpnctld::corp_portal::eligibility::CorpProbePlan {
            server: CorpEligibleServer {
                server_id: ServerId("SENSITIVE_SERVER_ID".to_owned()),
                label: "SENSITIVE_SERVER_LABEL".to_owned(),
                hosts: vec!["sensitive-host.example".to_owned()],
                configuration_fingerprint: "SENSITIVE_FINGERPRINT".to_owned(),
            },
            outbounds: vec![serde_json::json!({
                "type": "vless",
                "tag": "SENSITIVE_OUTBOUND_TAG",
                "server": "sensitive-outbound.example",
                "server_port": 443,
                "uuid": "SENSITIVE_OUTBOUND_UUID",
                "tls": {"reality": {"public_key": "SENSITIVE_REALITY_KEY"}},
                "transport": {"path": "/SENSITIVE_TRANSPORT_PATH"}
            })],
        };
        for debug in [format!("{plan:?}"), format!("{plan:#?}")] {
            assert_eq!(debug, "CorpProbePlan { .. }");
        }
    }
}
