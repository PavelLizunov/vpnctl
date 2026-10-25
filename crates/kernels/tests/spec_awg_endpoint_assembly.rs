use serde_json::{Value, json};
use std::collections::HashMap;
use vpnctl_core::{Kernel, KernelId, Protocol, ProtocolId, RenderCtx, Server, ServerId, User};
use vpnctl_kernels::SingBox;

#[derive(Debug)]
struct Fragment(&'static str, Option<&'static str>);
impl Protocol for Fragment {
    fn id(&self) -> ProtocolId {
        ProtocolId(self.0.into())
    }
    fn server_inbound(&self, _: &RenderCtx<'_>, _: &[User]) -> vpnctl_core::Result<Value> {
        let mut value = json!({"type":self.0,"listen_port":51821});
        if let Some(tag) = self.1 {
            value["tag"] = json!(tag);
        }
        Ok(value)
    }
    fn client_config(&self, _: &RenderCtx<'_>, _: &User) -> vpnctl_core::Result<Value> {
        Ok(Value::Null)
    }
    fn share_link(&self, _: &RenderCtx<'_>, _: &User) -> vpnctl_core::Result<String> {
        Ok(String::new())
    }
}
fn server() -> Server {
    Server {
        id: ServerId("test".into()),
        address: "203.0.113.1".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("sing-box".into())],
        enabled_protocols: vec![],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    }
}
fn denied(extra: &[&str]) -> Vec<String> {
    vpnctl_kernels::USER_TRAFFIC_DENIED_CIDRS
        .iter()
        .chain(extra)
        .map(|cidr| (*cidr).to_owned())
        .collect()
}

#[test]
fn only_sing_box_serves_both_new_awg_versions() {
    let supported = SingBox::new().supported_protocols();
    let legacy = vpnctl_kernels::AmneziaWg::new().supported_protocols();
    for id in ["amneziawg2", "amneziawg3"] {
        assert!(supported.contains(&ProtocolId(id.into())));
        assert!(!legacy.contains(&ProtocolId(id.into())));
    }
}

#[test]
fn wireguard_fragments_are_endpoints_and_private_destinations_are_denied()
-> Result<(), Box<dyn std::error::Error>> {
    let s = server();
    let secrets = HashMap::new();
    let ctx = RenderCtx::new(&s, &secrets);
    let config = SingBox::new().render_config(
        &ctx,
        &[],
        &[
            &Fragment("wireguard", Some("awg2-in")),
            &Fragment("vless", Some("vless-in")),
        ],
    )?;
    let cfg: Value = serde_json::from_slice(&config)?;
    assert_eq!(cfg["endpoints"][0]["tag"], "awg2-in");
    assert_eq!(cfg["inbounds"].as_array().map(Vec::len), Some(1));
    assert_eq!(
        cfg["experimental"]["v2ray_api"]["stats"]["inbounds"],
        json!(["vless-in"])
    );
    assert_eq!(
        cfg["route"],
        json!({"rules":[
            {"inbound":["vless-in"],"action":"resolve"},
            {"inbound":["vless-in","awg2-in"],"ip_is_private":true,"action":"reject"},
            {"inbound":["vless-in","awg2-in"],"ip_cidr":denied(&["203.0.113.1/32"]),"action":"reject"}
        ],"final":"direct"})
    );
    assert!(
        SingBox::new()
            .render_config(&ctx, &[], &[&Fragment("wireguard", None)])
            .is_err()
    );
    Ok(())
}
#[test]
fn hostname_servers_keep_private_isolation_but_awg_needs_a_literal_ip()
-> Result<(), Box<dyn std::error::Error>> {
    let mut s = server();
    s.address = "vpn.example.com".into();
    let secrets = HashMap::new();
    let ctx = RenderCtx::new(&s, &secrets);
    assert!(
        SingBox::new()
            .render_config(&ctx, &[], &[&Fragment("wireguard", Some("awg2-in"))])
            .is_err()
    );
    let config =
        SingBox::new().render_config(&ctx, &[], &[&Fragment("vless", Some("vless-in"))])?;
    let cfg: serde_json::Value = serde_json::from_slice(&config)?;
    assert_eq!(
        cfg["route"]["rules"],
        json!([
            {"inbound":["vless-in"],"action":"resolve"},
            {"inbound":["vless-in"],"ip_is_private":true,"action":"reject"},
            {"inbound":["vless-in"],"ip_cidr":denied(&[]),"action":"reject"}
        ])
    );
    Ok(())
}

#[test]
fn proxy_only_config_resolves_before_isolation() -> Result<(), Box<dyn std::error::Error>> {
    let s = server();
    let secrets = HashMap::new();
    let ctx = RenderCtx::new(&s, &secrets);
    let config =
        SingBox::new().render_config(&ctx, &[], &[&Fragment("vless", Some("vless-in"))])?;
    let expected = json!({
        "log":{"level":"info","output":"/var/log/sing-box.log","timestamp":true},
        "inbounds":[{"type":"vless","listen_port":51821,"tag":"vless-in"}],
        "outbounds":[{"type":"direct","tag":"direct"},{"type":"block","tag":"block"}],
        "route":{"rules":[
            {"inbound":["vless-in"],"action":"resolve"},
            {"inbound":["vless-in"],"ip_is_private":true,"action":"reject"},
            {"inbound":["vless-in"],"ip_cidr":denied(&["203.0.113.1/32"]),"action":"reject"}
        ],"final":"direct"},
        "experimental":{"clash_api":{"external_controller":"127.0.0.1:9090"},"v2ray_api":{"listen":"127.0.0.1:10085","stats":{"enabled":true,"inbounds":["vless-in"],"users":[]}}}
    });
    assert_eq!(config, serde_json::to_vec_pretty(&expected)?);
    Ok(())
}

#[test]
fn every_proxy_inbound_resolves_before_ipv6_server_isolation()
-> Result<(), Box<dyn std::error::Error>> {
    let mut s = server();
    s.address = "2001:db8::1".into();
    let secrets = HashMap::new();
    let ctx = RenderCtx::new(&s, &secrets);
    let fragments = [
        Fragment("vless", Some("vless-in")),
        Fragment("tuic", Some("tuic-in")),
        Fragment("hysteria2", Some("hy2-in")),
        Fragment("shadowsocks", Some("ss22-in")),
        Fragment("anytls", Some("anytls-in")),
        Fragment("trojan", Some("trojan-in")),
        Fragment("wireguard", Some("awg2-in")),
        Fragment("wireguard", Some("awg3-in")),
    ];
    let protocols: Vec<&dyn Protocol> = fragments.iter().map(|p| p as &dyn Protocol).collect();
    let config = SingBox::new().render_config(&ctx, &[], &protocols)?;
    let cfg: Value = serde_json::from_slice(&config)?;
    let proxy_tags = json!([
        "vless-in",
        "tuic-in",
        "hy2-in",
        "ss22-in",
        "anytls-in",
        "trojan-in"
    ]);
    let all_tags = json!([
        "vless-in",
        "tuic-in",
        "hy2-in",
        "ss22-in",
        "anytls-in",
        "trojan-in",
        "awg2-in",
        "awg3-in"
    ]);
    assert_eq!(
        cfg["route"],
        json!({"rules":[
            {"inbound":proxy_tags,"action":"resolve"},
            {"inbound":all_tags,"ip_is_private":true,"action":"reject"},
            {"inbound":all_tags,"ip_cidr":denied(&["2001:db8::1/128"]),"action":"reject"}
        ],"final":"direct"})
    );
    Ok(())
}

#[test]
fn awg_only_isolation_rules_remain_unchanged() -> Result<(), Box<dyn std::error::Error>> {
    let s = server();
    let secrets = HashMap::new();
    let ctx = RenderCtx::new(&s, &secrets);
    let config =
        SingBox::new().render_config(&ctx, &[], &[&Fragment("wireguard", Some("awg2-in"))])?;
    let cfg: Value = serde_json::from_slice(&config)?;
    assert_eq!(
        cfg["route"],
        json!({"rules":[
            {"inbound":["awg2-in"],"ip_is_private":true,"action":"reject"},
            {"inbound":["awg2-in"],"ip_cidr":denied(&["203.0.113.1/32"]),"action":"reject"}
        ],"final":"direct"})
    );
    Ok(())
}

#[test]
fn proxy_isolation_rejects_missing_or_empty_inbound_tags() {
    let s = server();
    let secrets = HashMap::new();
    let ctx = RenderCtx::new(&s, &secrets);
    for tag in [None, Some("")] {
        assert!(
            SingBox::new()
                .render_config(&ctx, &[], &[&Fragment("vless", tag)])
                .is_err()
        );
    }
}
