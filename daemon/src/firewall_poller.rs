use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest, Sha256};
use vpnctl_core::{Registry, RenderCtx, ServerId, SshTransport};
use vpnctl_inventory::SqliteInventory;

use crate::ssh_subprocess::SubprocessSshTransport;
use crate::wizard_bootstrap::DeployGuard;

const SWEEP_INTERVAL: Duration = Duration::from_secs(10 * 60);

struct Observation {
    inputs: [u8; 32],
    ports: BTreeSet<(&'static str, u16)>,
}

pub(crate) fn spawn_poller(
    inv: SqliteInventory,
    registry: Arc<Registry>,
    deploy_key: PathBuf,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(SWEEP_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut observations = HashMap::new();
        loop {
            tick.tick().await;
            let previous = std::mem::take(&mut observations);
            if !deploy_key.is_file() {
                continue;
            }
            let servers = match inv.list_servers().await {
                Ok(servers) => servers,
                Err(error) => {
                    tracing::warn!(target: "vpnctld::firewall", %error, "could not list nodes for firewall sweep");
                    continue;
                }
            };
            for server in servers {
                let id = server.id;
                match sweep_node(&inv, &registry, &deploy_key, &id, previous.get(&id), None).await {
                    Ok(Some(observation)) => {
                        observations.insert(id, observation);
                    }
                    Ok(None) => {}
                    Err(error) => {
                        tracing::warn!(target: "vpnctld::firewall", server = %id, %error, "node firewall sweep failed");
                    }
                }
            }
        }
    })
}

async fn sweep_node(
    inv: &SqliteInventory,
    registry: &Registry,
    deploy_key: &Path,
    id: &ServerId,
    previous: Option<&Observation>,
    transport: Option<&dyn SshTransport>,
) -> anyhow::Result<Option<Observation>> {
    let Some(_guard) = DeployGuard::try_acquire(&id.0) else {
        return Ok(None);
    };
    let revision = inv.deploy_input_revision(id).await?;
    let Some(server) = inv.get_server(id).await? else {
        return Ok(None);
    };
    if server.kernels.is_empty() || inv.server_pending_deploy(id).await? {
        return Ok(None);
    }

    let secrets = inv.list_server_secrets(id).await?;
    registry.validate_server(&server, &secrets)?;
    let reserved = inv.get_reserved_ports(id).await?;
    let jump = inv.resolve_jump_host(&server).await?;
    let inputs = Sha256::digest(serde_json::to_vec(&(
        &revision,
        &server.trusted_host_fingerprint,
        &jump,
    ))?)
    .into();
    if inv.deploy_input_revision(id).await? != revision {
        return Ok(None);
    }

    let ssh = SubprocessSshTransport::new(&server.address, &server.ssh_user, deploy_key.to_owned())
        .port(server.ssh_port)
        .trusted_fingerprint(server.trusted_host_fingerprint.clone())
        .with_jump(jump);
    let empty = BTreeSet::new();
    let confirmed = previous
        .filter(|sample| sample.inputs == inputs)
        .map_or(&empty, |sample| &sample.ports);
    let ctx = RenderCtx::new(&server, &secrets);
    let result = vpnctl_kernels::sweep_firewall(
        transport.unwrap_or(&ssh),
        registry,
        &ctx,
        &reserved,
        confirmed,
    )
    .await?;
    if !result.removed.is_empty() {
        inv.audit(
            "system",
            "server.firewall.cleanup",
            Some(&id.0),
            Some(&serde_json::json!({ "ports": result.removed })),
        )
        .await?;
    }
    if let Some((transport, port)) = result.failed {
        anyhow::bail!("UFW failed to remove {transport}:{port}");
    }
    Ok((!result.idle_unmarked.is_empty()).then_some(Observation {
        inputs,
        ports: result.idle_unmarked,
    }))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct FixtureTransport {
        fail_after_remove: bool,
    }

    #[async_trait::async_trait]
    impl SshTransport for FixtureTransport {
        async fn exec(&self, command: &str) -> vpnctl_core::Result<String> {
            let response = if command.ends_with(" -- tcp4:8443\n") {
                if self.fail_after_remove {
                    "removed tcp4:8443\nfailed udp6:9443\n"
                } else {
                    "removed tcp4:8443\n"
                }
            } else {
                "idle tcp4:8443\n"
            };
            Ok(response.into())
        }

        async fn exec_unprivileged(&self, _: &str) -> vpnctl_core::Result<String> {
            Err(vpnctl_core::CoreError::Transport(
                "unexpected unprivileged command".into(),
            ))
        }

        async fn upload(&self, _: &str, _: &[u8]) -> vpnctl_core::Result<()> {
            Err(vpnctl_core::CoreError::Transport(
                "unexpected upload".into(),
            ))
        }

        async fn read_file(&self, _: &str) -> vpnctl_core::Result<Vec<u8>> {
            Err(vpnctl_core::CoreError::Transport(
                "unexpected file read".into(),
            ))
        }
    }

    #[tokio::test]
    async fn changed_or_busy_nodes_cannot_reuse_an_old_idle_observation() {
        let dir = tempfile::tempdir().unwrap();
        let inv = SqliteInventory::open(&dir.path().join("inventory.db"))
            .await
            .unwrap();
        let registry = crate::app::build_registry().unwrap();
        let server = vpnctl_core::Server {
            id: ServerId("firewall-poller-observation".into()),
            address: "192.0.2.7".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![vpnctl_core::KernelId("sing-box".into())],
            enabled_protocols: Vec::new(),
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        };
        inv.add_server(&server).await.unwrap();
        let id = &server.id;
        let key = dir.path().join("fixture-key");
        let ssh = FixtureTransport {
            fail_after_remove: false,
        };
        let observation = sweep_node(&inv, &registry, &key, id, None, Some(&ssh))
            .await
            .unwrap()
            .unwrap();

        let guard = DeployGuard::try_acquire(&id.0).unwrap();
        assert!(
            sweep_node(&inv, &registry, &key, id, Some(&observation), Some(&ssh))
                .await
                .unwrap()
                .is_none()
        );
        drop(guard);

        inv.set_reserved_ports(id, &[8888]).await.unwrap();
        assert!(
            sweep_node(&inv, &registry, &key, id, Some(&observation), Some(&ssh))
                .await
                .unwrap()
                .is_none(),
            "pending deployment must skip cleanup"
        );
        inv.audit("test", "server.deploy", Some(&id.0), None)
            .await
            .unwrap();

        let fresh = sweep_node(&inv, &registry, &key, id, Some(&observation), Some(&ssh))
            .await
            .unwrap()
            .unwrap();
        assert_ne!(observation.inputs, fresh.inputs);
        let partial = FixtureTransport {
            fail_after_remove: true,
        };
        let error = sweep_node(&inv, &registry, &key, id, Some(&fresh), Some(&partial))
            .await
            .err()
            .unwrap();
        assert!(error.to_string().contains("UFW failed to remove udp6:9443"));
        let audit = inv.audit_for_server(&id.0, 10).await.unwrap();
        let removals: Vec<_> = audit
            .iter()
            .filter(|entry| entry.action == "server.firewall.cleanup")
            .collect();
        assert_eq!(removals.len(), 1);
        assert_eq!(
            removals[0].payload,
            Some(serde_json::json!({"ports": [["tcp4", 8443]]}))
        );
    }
}
