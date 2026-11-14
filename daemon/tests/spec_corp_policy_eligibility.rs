// Independent fixtures and assertions derived only from corp-policy-eligibility.md.
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod spec {
    use std::sync::Arc;

    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use sqlx::{Connection, SqliteConnection, sqlite::SqliteConnectOptions};
    use tempfile::TempDir;
    use tokio::task::JoinHandle;
    use vpnctl_core::{KernelId, ProtocolId, Server, ServerId, User, UserId};
    use vpnctl_inventory::{ServerRole, SqliteInventory};
    use vpnctld::{
        AppState, app,
        corp_portal::eligibility::{CorpEligibleServer, EligibilityError, eligible_servers},
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
}
