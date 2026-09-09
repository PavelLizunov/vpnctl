use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::Barrier;
use vpnctl_core::{
    Kernel, KernelId, KernelStatus, Protocol, ProtocolId, RenderCtx, ServerId, SshTransport, User,
    UserId,
};

#[derive(Debug)]
struct TestProtocol;
impl Protocol for TestProtocol {
    fn id(&self) -> ProtocolId {
        ProtocolId("coalescer-test".into())
    }
    fn server_inbound(
        &self,
        _: &RenderCtx<'_>,
        _: &[User],
    ) -> vpnctl_core::Result<serde_json::Value> {
        Ok(serde_json::Value::Null)
    }
    fn client_config(&self, _: &RenderCtx<'_>, _: &User) -> vpnctl_core::Result<serde_json::Value> {
        Ok(serde_json::Value::Null)
    }
    fn share_link(&self, _: &RenderCtx<'_>, _: &User) -> vpnctl_core::Result<String> {
        Ok(String::new())
    }
}

#[derive(Debug)]
struct BarrierKernel {
    entered: Arc<Barrier>,
    released: Arc<Barrier>,
    applications: Arc<Mutex<Vec<serde_json::Value>>>,
    calls: AtomicUsize,
}
#[async_trait::async_trait]
impl Kernel for BarrierKernel {
    fn id(&self) -> KernelId {
        KernelId("coalescer-test".into())
    }
    fn supported_protocols(&self) -> Vec<ProtocolId> {
        vec![TestProtocol.id()]
    }
    async fn ensure_installed(&self, _: &dyn SshTransport) -> vpnctl_core::Result<()> {
        Ok(())
    }
    fn render_config(
        &self,
        _: &RenderCtx<'_>,
        users: &[User],
        protocols: &[&dyn Protocol],
    ) -> vpnctl_core::Result<Vec<u8>> {
        Ok(serde_json::to_vec(&serde_json::json!({
            "users": users.iter().map(|u| &u.id.0).collect::<Vec<_>>(),
            "protocols": protocols.iter().map(|p| p.id().0).collect::<Vec<_>>()
        }))
        .unwrap())
    }
    async fn apply_config(&self, _: &dyn SshTransport, config: &[u8]) -> vpnctl_core::Result<()> {
        self.applications
            .lock()
            .unwrap()
            .push(serde_json::from_slice(config).unwrap());
        if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            self.entered.wait().await;
            self.released.wait().await;
        }
        Ok(())
    }
    async fn restart(&self, _: &dyn SshTransport) -> vpnctl_core::Result<()> {
        Ok(())
    }
    async fn status(&self, _: &dyn SshTransport) -> vpnctl_core::Result<KernelStatus> {
        unreachable!("status must not be used")
    }
}

#[tokio::test]
async fn revoke_and_last_protocol_removal_during_remote_apply_converge_via_canonical_audit() {
    let dir = tempfile::tempdir().unwrap();
    let inv = SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .unwrap();
    let key = dir.path().join("fake-key");
    std::fs::write(&key, "not a real key; mock kernel never calls transport").unwrap();
    let server = Server {
        id: ServerId("autodeploy-pipeline-revoke".into()),
        address: "203.0.113.7".into(),
        ssh_port: 22,
        ssh_user: "root".into(),
        kernels: vec![KernelId("coalescer-test".into())],
        enabled_protocols: vec![TestProtocol.id()],
        trusted_host_fingerprint: None,
        hoster: "generic".into(),
        jump_via: None,
        usage_coefficient: 1.0,
    };
    let user = User {
        id: UserId("test-user".into()),
        uuid: "00000000-0000-4000-8000-000000000001".into(),
        tuic_password: None,
        wireguard_pubkey: None,
        wireguard_private: None,
        sub_token: None,
        vpn_router_device_id: None,
        disabled: false,
    };
    inv.add_server(&server).await.unwrap();
    inv.add_user(&user).await.unwrap();
    inv.grant(&user.id, &server.id).await.unwrap();
    let entered = Arc::new(Barrier::new(2));
    let released = Arc::new(Barrier::new(2));
    let applications = Arc::new(Mutex::new(Vec::new()));
    let mut registry = Registry::new();
    registry.register_protocol(Box::new(TestProtocol)).unwrap();
    registry
        .register_kernel(Box::new(BarrierKernel {
            entered: Arc::clone(&entered),
            released: Arc::clone(&released),
            applications: Arc::clone(&applications),
            calls: AtomicUsize::new(0),
        }))
        .unwrap();
    let registry = Arc::new(registry);
    let coordinator = Arc::new(Coordinator::default());
    let (mut completion, worker) = coordinator.request(server.id.0.clone());
    let task = tokio::spawn(worker.unwrap().run(
        {
            let server = server.clone();
            let inv = inv.clone();
            let registry = Arc::clone(&registry);
            let key = key.clone();
            move || {
                attempt(
                    server.clone(),
                    inv.clone(),
                    Arc::clone(&registry),
                    key.clone(),
                )
            }
        },
        || std::future::ready(()),
    ));
    entered.wait().await;
    assert!(
        crate::wizard_bootstrap::DeployGuard::try_acquire(&server.id.0).is_none(),
        "manual/CLI lock must remain exclusive during remote apply"
    );
    inv.revoke(&user.id, &server.id).await.unwrap();
    inv.remove_server_protocol(&server.id, &TestProtocol.id())
        .await
        .unwrap();
    inv.audit(
        "admin",
        "server.protocol.disable",
        Some(&server.id.0),
        Some(&serde_json::json!({"protocol": TestProtocol.id().0})),
    )
    .await
    .unwrap();
    let (_, duplicate) = coordinator.request(server.id.0.clone());
    assert!(duplicate.is_none());
    released.wait().await;
    task.await.unwrap();
    assert_eq!(*completion.borrow_and_update(), Some(Ok(())));
    {
        let applied = applications.lock().unwrap();
        assert_eq!(applied.len(), 2);
        assert_eq!(applied[0]["users"], serde_json::json!(["test-user"]));
        assert_eq!(
            applied[0]["protocols"],
            serde_json::json!(["coalescer-test"])
        );
        assert_eq!(
            applied[1],
            serde_json::json!({ "users": [], "protocols": [] })
        );
    }
    let audit = inv.audit_for_server(&server.id.0, 100).await.unwrap();
    assert_eq!(
        audit
            .iter()
            .filter(|row| row.action == "server.deploy.stale")
            .count(),
        1
    );
    assert_eq!(
        audit
            .iter()
            .filter(|row| row.action == "server.deploy")
            .count(),
        1
    );
    assert!(!inv.server_pending_deploy(&server.id).await.unwrap());
    // A fresh coordinator cannot fabricate applied evidence after restart.
    inv.add_server_protocol(&server.id, &TestProtocol.id())
        .await
        .unwrap();
    // Protocol setters deliberately leave auditing to their admin caller.
    inv.audit(
        "admin",
        "server.protocol.enable",
        Some(&server.id.0),
        Some(&serde_json::json!({"protocol": TestProtocol.id().0})),
    )
    .await
    .unwrap();
    assert_eq!(Coordinator::default().status(&server.id.0), None);
    let reopened = SqliteInventory::open(&dir.path().join("inv.db"))
        .await
        .unwrap();
    assert!(reopened.server_pending_deploy(&server.id).await.unwrap());
}
