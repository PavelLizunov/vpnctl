//! Native endpoint assembly and unchanged legacy serialization contract.
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
            {"inbound":["awg2-in"],"ip_is_private":true,"action":"reject"},
            {"inbound":["awg2-in"],"ip_cidr":["203.0.113.1/32"],"action":"reject"}
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
fn awg_hostname_servers_fail_closed_without_local_ip_inventory() {
    let mut s = server();
    s.address = "vpn.example.com".into();
    let secrets = HashMap::new();
    let ctx = RenderCtx::new(&s, &secrets);
    assert!(
        SingBox::new()
            .render_config(&ctx, &[], &[&Fragment("wireguard", Some("awg2-in"))])
            .is_err()
    );
    assert!(
        SingBox::new()
            .render_config(&ctx, &[], &[&Fragment("vless", Some("vless-in"))])
            .is_ok()
    );
}

#[test]
fn no_endpoint_preserves_the_entire_legacy_config_bytes() -> Result<(), Box<dyn std::error::Error>>
{
    let s = server();
    let secrets = HashMap::new();
    let ctx = RenderCtx::new(&s, &secrets);
    let config =
        SingBox::new().render_config(&ctx, &[], &[&Fragment("vless", Some("vless-in"))])?;
    let expected = json!({
        "log":{"level":"info","output":"/var/log/sing-box.log","timestamp":true},
        "inbounds":[{"type":"vless","listen_port":51821,"tag":"vless-in"}],
        "outbounds":[{"type":"direct","tag":"direct"},{"type":"block","tag":"block"}],
        "experimental":{"clash_api":{"external_controller":"127.0.0.1:9090"},"v2ray_api":{"listen":"127.0.0.1:10085","stats":{"enabled":true,"inbounds":["vless-in"],"users":[]}}}
    });
    assert_eq!(config, serde_json::to_vec_pretty(&expected)?);
    Ok(())
}
