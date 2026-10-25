use std::collections::HashMap;

use crate::error::{CoreError, Result};
use crate::id::{KernelId, ProtocolId};
use crate::kernel::Kernel;
use crate::models::Server;
use crate::protocol::Protocol;

#[derive(Debug, Default)]
pub struct Registry {
    kernels: Vec<Box<dyn Kernel>>,
    protocols: Vec<Box<dyn Protocol>>,
}

impl Registry {
    pub fn new() -> Self {
        Self {
            kernels: Vec::new(),
            protocols: Vec::new(),
        }
    }

    pub fn register_kernel(&mut self, k: Box<dyn Kernel>) -> Result<()> {
        let id = k.id();
        if self.kernels.iter().any(|existing| existing.id() == id) {
            return Err(CoreError::DuplicateKernel(id));
        }
        self.kernels.push(k);
        Ok(())
    }

    pub fn register_protocol(&mut self, p: Box<dyn Protocol>) -> Result<()> {
        let id = p.id();
        if self.protocols.iter().any(|existing| existing.id() == id) {
            return Err(CoreError::DuplicateProtocol(id));
        }
        self.protocols.push(p);
        Ok(())
    }

    pub fn kernel(&self, id: &KernelId) -> Option<&dyn Kernel> {
        self.kernels
            .iter()
            .find(|k| &k.id() == id)
            .map(|k| k.as_ref())
    }

    pub fn protocol(&self, id: &ProtocolId) -> Option<&dyn Protocol> {
        self.protocols
            .iter()
            .find(|p| &p.id() == id)
            .map(|p| p.as_ref())
    }

    pub fn protocol_ids(&self) -> Vec<ProtocolId> {
        self.protocols.iter().map(|p| p.id()).collect()
    }

    pub fn kernel_ids(&self) -> Vec<KernelId> {
        self.kernels.iter().map(|k| k.id()).collect()
    }

    pub fn validate_server_support(&self, server: &Server) -> Result<()> {
        if server.kernels.is_empty() {
            return Err(CoreError::Render(format!(
                "server '{}' has no kernels assigned — assign at least one (sing-box, amneziawg, …)",
                server.id
            )));
        }
        let mut resolved = Vec::with_capacity(server.kernels.len());
        for kid in &server.kernels {
            let k = self
                .kernel(kid)
                .ok_or_else(|| CoreError::Render(format!("unknown kernel {kid}")))?;
            k.validate_server_support(server)?;
            resolved.push((kid.clone(), k.supported_protocols()));
        }
        for proto in &server.enabled_protocols {
            if !resolved.iter().any(|(_, sup)| sup.contains(proto)) {
                return Err(CoreError::UnsupportedProtocol {
                    kernels: server
                        .kernels
                        .iter()
                        .map(|k| k.0.as_str())
                        .collect::<Vec<_>>()
                        .join(", "),
                    protocol: proto.clone(),
                });
            }
        }
        Ok(())
    }

    pub fn validate_server(
        &self,
        server: &Server,
        secrets: &HashMap<String, String>,
    ) -> Result<()> {
        self.validate_server_support(server)?;

        let mut bound: HashMap<(&str, u16), &ProtocolId> = HashMap::new();
        for pid in &server.enabled_protocols {
            let Some(proto) = self.protocol(pid) else {
                continue;
            };
            proto.validate_server(&crate::models::RenderCtx::new(server, secrets))?;
            for (transport, port) in proto.effective_listen_ports(secrets) {
                if let Some(prev) = bound.insert((transport, port), pid) {
                    return Err(CoreError::Render(format!(
                        "port conflict on {transport}/{port}: protocols '{prev}' and \
                         '{pid}' both bind it on server '{}'. Move one of them to a \
                         different port via its per-server `*.listen_port` secret \
                         (vless.listen_port, vlessws.listen_port, wireguard.listen_port) \
                         or to a dedicated node.",
                        server.id
                    )));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod validate_server_port_conflict {
    use super::*;
    use crate::id::ServerId;
    use crate::kernel::KernelStatus;
    use crate::models::{RenderCtx, User};
    use crate::transport::SshTransport;
    use async_trait::async_trait;

    #[derive(Debug)]
    struct FakeProto {
        id: &'static str,
        ports: &'static [(&'static str, u16)],
    }
    impl Protocol for FakeProto {
        fn id(&self) -> ProtocolId {
            ProtocolId(self.id.to_string())
        }
        fn server_inbound(&self, _: &RenderCtx<'_>, _: &[User]) -> Result<serde_json::Value> {
            Ok(serde_json::Value::Null)
        }
        fn client_config(&self, _: &RenderCtx<'_>, _: &User) -> Result<serde_json::Value> {
            Ok(serde_json::Value::Null)
        }
        fn share_link(&self, _: &RenderCtx<'_>, _: &User) -> Result<String> {
            Ok(String::new())
        }
        fn listen_ports(&self) -> &'static [(&'static str, u16)] {
            self.ports
        }
    }

    #[derive(Debug)]
    struct FakeKernel {
        supports: Vec<&'static str>,
    }
    #[async_trait]
    impl Kernel for FakeKernel {
        fn id(&self) -> KernelId {
            KernelId("fake".to_string())
        }
        fn supported_protocols(&self) -> Vec<ProtocolId> {
            self.supports
                .iter()
                .map(|s| ProtocolId(s.to_string()))
                .collect()
        }
        async fn ensure_installed(&self, _: &dyn SshTransport) -> Result<()> {
            Ok(())
        }
        fn render_config(
            &self,
            _: &RenderCtx<'_>,
            _: &[User],
            _: &[&dyn Protocol],
        ) -> Result<Vec<u8>> {
            Ok(Vec::new())
        }
        async fn apply_config(&self, _: &dyn SshTransport, _: &[u8]) -> Result<()> {
            Ok(())
        }
        async fn restart(&self, _: &dyn SshTransport) -> Result<()> {
            Ok(())
        }
        async fn status(&self, _: &dyn SshTransport) -> Result<KernelStatus> {
            Ok(KernelStatus {
                active: false,
                version: None,
                uptime_seconds: None,
            })
        }
    }

    fn registry(protos: Vec<(&'static str, &'static [(&'static str, u16)])>) -> Registry {
        let mut r = Registry::new();
        let supports: Vec<&'static str> = protos.iter().map(|(id, _)| *id).collect();
        r.register_kernel(Box::new(FakeKernel { supports }))
            .unwrap();
        for (id, ports) in protos {
            r.register_protocol(Box::new(FakeProto { id, ports }))
                .unwrap();
        }
        r
    }

    fn server(protos: &[&'static str]) -> Server {
        Server {
            id: ServerId("s1".into()),
            address: "1.2.3.4".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("fake".into())],
            enabled_protocols: protos.iter().map(|p| ProtocolId(p.to_string())).collect(),
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        }
    }

    fn no_secrets() -> HashMap<String, String> {
        HashMap::new()
    }

    #[test]
    fn same_transport_and_port_conflicts() {
        let reg = registry(vec![("vless", &[("tcp", 443)]), ("naive", &[("tcp", 443)])]);
        let err = reg
            .validate_server(&server(&["vless", "naive"]), &no_secrets())
            .unwrap_err();
        match err {
            CoreError::Render(m) => {
                assert!(m.contains("port conflict"), "msg: {m}");
                assert!(m.contains("443"), "msg: {m}");
                assert!(m.contains("vless") && m.contains("naive"), "msg: {m}");
            }
            other => panic!("expected Render, got {other:?}"),
        }
    }

    #[test]
    fn distinct_ports_ok() {
        let reg = registry(vec![("vless", &[("tcp", 443)]), ("tuic", &[("udp", 8443)])]);
        assert!(
            reg.validate_server(&server(&["vless", "tuic"]), &no_secrets())
                .is_ok()
        );
    }

    #[test]
    fn same_port_different_transport_ok() {
        let reg = registry(vec![("a", &[("tcp", 443)]), ("b", &[("udp", 443)])]);
        assert!(
            reg.validate_server(&server(&["a", "b"]), &no_secrets())
                .is_ok()
        );
    }

    #[test]
    fn protocol_without_declared_ports_never_conflicts() {
        let reg = registry(vec![("vless", &[("tcp", 443)]), ("portless", &[])]);
        assert!(
            reg.validate_server(&server(&["vless", "portless"]), &no_secrets())
                .is_ok()
        );
    }

    #[test]
    fn secret_override_frees_default_port() {
        #[derive(Debug)]
        struct OverridableVless;
        impl Protocol for OverridableVless {
            fn id(&self) -> ProtocolId {
                ProtocolId("vless".to_string())
            }
            fn server_inbound(&self, _: &RenderCtx<'_>, _: &[User]) -> Result<serde_json::Value> {
                Ok(serde_json::Value::Null)
            }
            fn client_config(&self, _: &RenderCtx<'_>, _: &User) -> Result<serde_json::Value> {
                Ok(serde_json::Value::Null)
            }
            fn share_link(&self, _: &RenderCtx<'_>, _: &User) -> Result<String> {
                Ok(String::new())
            }
            fn listen_ports(&self) -> &'static [(&'static str, u16)] {
                &[("tcp", 443)]
            }
            fn effective_listen_ports(
                &self,
                secrets: &HashMap<String, String>,
            ) -> Vec<(&'static str, u16)> {
                let port: u16 = secrets
                    .get("vless.listen_port")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(443);
                vec![("tcp", port)]
            }
        }
        let mut reg = Registry::new();
        reg.register_kernel(Box::new(FakeKernel {
            supports: vec!["vless", "naive"],
        }))
        .unwrap();
        reg.register_protocol(Box::new(OverridableVless)).unwrap();
        reg.register_protocol(Box::new(FakeProto {
            id: "naive",
            ports: &[("tcp", 443)],
        }))
        .unwrap();

        assert!(
            reg.validate_server(&server(&["vless", "naive"]), &no_secrets())
                .is_err()
        );

        let mut overridden = no_secrets();
        overridden.insert("vless.listen_port".into(), "8443".into());
        assert!(
            reg.validate_server(&server(&["vless", "naive"]), &overridden)
                .is_ok()
        );

        reg.register_protocol(Box::new(FakeProto {
            id: "squat",
            ports: &[("tcp", 8443)],
        }))
        .unwrap();
        let reg2 = {
            let mut r = Registry::new();
            r.register_kernel(Box::new(FakeKernel {
                supports: vec!["vless", "naive", "squat"],
            }))
            .unwrap();
            r.register_protocol(Box::new(OverridableVless)).unwrap();
            r.register_protocol(Box::new(FakeProto {
                id: "naive",
                ports: &[("tcp", 443)],
            }))
            .unwrap();
            r.register_protocol(Box::new(FakeProto {
                id: "squat",
                ports: &[("tcp", 8443)],
            }))
            .unwrap();
            r
        };
        let err = reg2
            .validate_server(&server(&["vless", "naive", "squat"]), &overridden)
            .unwrap_err();
        match err {
            CoreError::Render(m) => assert!(m.contains("8443"), "msg: {m}"),
            other => panic!("expected Render, got {other:?}"),
        }
    }

    #[test]
    fn secret_driven_front_port_conflicts_with_reality_override() {
        #[derive(Debug)]
        struct WsLike;
        impl Protocol for WsLike {
            fn id(&self) -> ProtocolId {
                ProtocolId("ws".to_string())
            }
            fn server_inbound(&self, _: &RenderCtx<'_>, _: &[User]) -> Result<serde_json::Value> {
                Ok(serde_json::Value::Null)
            }
            fn client_config(&self, _: &RenderCtx<'_>, _: &User) -> Result<serde_json::Value> {
                Ok(serde_json::Value::Null)
            }
            fn share_link(&self, _: &RenderCtx<'_>, _: &User) -> Result<String> {
                Ok(String::new())
            }
            fn effective_listen_ports(
                &self,
                secrets: &HashMap<String, String>,
            ) -> Vec<(&'static str, u16)> {
                let port: u16 = secrets
                    .get("front.listen_port")
                    .and_then(|s| s.parse().ok())
                    .filter(|&p| p != 0)
                    .unwrap_or(8443);
                vec![("tcp", port)]
            }
        }
        #[derive(Debug)]
        struct RealityLike;
        impl Protocol for RealityLike {
            fn id(&self) -> ProtocolId {
                ProtocolId("reality".to_string())
            }
            fn server_inbound(&self, _: &RenderCtx<'_>, _: &[User]) -> Result<serde_json::Value> {
                Ok(serde_json::Value::Null)
            }
            fn client_config(&self, _: &RenderCtx<'_>, _: &User) -> Result<serde_json::Value> {
                Ok(serde_json::Value::Null)
            }
            fn share_link(&self, _: &RenderCtx<'_>, _: &User) -> Result<String> {
                Ok(String::new())
            }
            fn listen_ports(&self) -> &'static [(&'static str, u16)] {
                &[("tcp", 443)]
            }
            fn effective_listen_ports(
                &self,
                secrets: &HashMap<String, String>,
            ) -> Vec<(&'static str, u16)> {
                let port: u16 = secrets
                    .get("vless.listen_port")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(443);
                vec![("tcp", port)]
            }
        }

        let reg = {
            let mut r = Registry::new();
            r.register_kernel(Box::new(FakeKernel {
                supports: vec!["ws", "reality"],
            }))
            .unwrap();
            r.register_protocol(Box::new(WsLike)).unwrap();
            r.register_protocol(Box::new(RealityLike)).unwrap();
            r
        };

        let mut clash = no_secrets();
        clash.insert("vless.listen_port".into(), "8443".into());
        let err = reg
            .validate_server(&server(&["ws", "reality"]), &clash)
            .unwrap_err();
        match err {
            CoreError::Render(m) => assert!(m.contains("8443"), "msg: {m}"),
            other => panic!("expected Render, got {other:?}"),
        }

        assert!(
            reg.validate_server(&server(&["ws", "reality"]), &no_secrets())
                .is_ok()
        );

        let mut apart = no_secrets();
        apart.insert("vless.listen_port".into(), "8443".into());
        apart.insert("front.listen_port".into(), "2087".into());
        assert!(
            reg.validate_server(&server(&["ws", "reality"]), &apart)
                .is_ok()
        );
    }

    #[test]
    fn support_only_validation_skips_port_gate() {
        let reg = registry(vec![("vless", &[("tcp", 443)]), ("naive", &[("tcp", 443)])]);
        assert!(
            reg.validate_server_support(&server(&["vless", "naive"]))
                .is_ok()
        );
        assert!(
            reg.validate_server(&server(&["vless", "naive"]), &no_secrets())
                .is_err()
        );
        assert!(reg.validate_server_support(&server(&["ghost"])).is_err());
    }
}
