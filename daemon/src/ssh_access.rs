use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use tokio::sync::Semaphore;
use vpnctl_core::{Server, ServerId};
use vpnctl_inventory::{
    SqliteInventory, SshAccessCheck, SshAccessFailure, SshAccessRoute, SshAccessState,
};

type CheckKey = (String, ServerId);
static RUNNING: OnceLock<Mutex<HashSet<CheckKey>>> = OnceLock::new();
static SLOTS: Semaphore = Semaphore::const_new(3);

fn running() -> &'static Mutex<HashSet<CheckKey>> {
    RUNNING.get_or_init(Mutex::default)
}

fn check_key(inv: &SqliteInventory, server: &ServerId) -> CheckKey {
    (inv.coordination_identity().to_string(), server.clone())
}

struct CheckLease(CheckKey);

impl CheckLease {
    fn acquire(key: CheckKey) -> Option<Self> {
        let mut active = running().lock().unwrap_or_else(|e| e.into_inner());
        if active.insert(key.clone()) {
            Some(Self(key))
        } else {
            None
        }
    }
}

impl Drop for CheckLease {
    fn drop(&mut self) {
        running()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.0);
    }
}

pub(crate) fn is_checking(inv: &SqliteInventory, server: &ServerId) -> bool {
    running()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .contains(&check_key(inv, server))
}

fn interval_secs() -> u64 {
    crate::config::parse_positive_secs("VPNCTLD_SSH_CHECK_INTERVAL_SECS", 300)
}

pub(crate) fn max_age_secs() -> u64 {
    interval_secs().saturating_mul(2)
}

pub(crate) fn start_check(inv: SqliteInventory, server: Server) {
    let Some(lease) = CheckLease::acquire(check_key(&inv, &server.id)) else {
        return;
    };
    tokio::spawn(async move {
        let _lease = lease;
        let Ok(_slot) = SLOTS.acquire().await else {
            return;
        };
        let jump = match server.jump_via.as_ref() {
            Some(id) => match inv.get_server(id).await {
                Ok(value) => value,
                Err(_) => {
                    tracing::warn!(target = "vpnctld::ssh_access", server = %server.id, "could not load SSH jump configuration");
                    None
                }
            },
            None => None,
        };
        for route in [SshAccessRoute::Direct, SshAccessRoute::Jump] {
            if route == SshAccessRoute::Jump && server.jump_via.is_none() {
                continue;
            }
            let via = if route == SshAccessRoute::Jump {
                jump.as_ref()
            } else {
                None
            };
            let check = observe(&server, route, via, &crate::app::deploy_key_path()).await;
            if inv
                .record_ssh_access(&server, route, via, &check)
                .await
                .is_err()
            {
                tracing::warn!(target = "vpnctld::ssh_access", server = %server.id, ?route, "could not persist SSH access result");
            }
        }
    });
}

pub(crate) fn spawn_poller(inv: SqliteInventory) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(interval_secs()));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            match inv.list_servers().await {
                Ok(servers) => {
                    for server in servers {
                        start_check(inv.clone(), server);
                    }
                }
                Err(_) => tracing::warn!(
                    target = "vpnctld::ssh_access",
                    "could not list servers for SSH checks"
                ),
            }
        }
    })
}

fn transport_for_route(
    target: &Server,
    route: SshAccessRoute,
    jump: Option<&Server>,
    key: PathBuf,
) -> Result<crate::ssh_subprocess::SubprocessSshTransport, SshAccessFailure> {
    if target
        .trusted_host_fingerprint
        .as_deref()
        .and_then(vpnctl_host_fingerprint::canonicalize_sha256)
        .is_none()
    {
        return Err(SshAccessFailure::InvalidRoute);
    }
    let hop = match route {
        SshAccessRoute::Direct => None,
        SshAccessRoute::Jump => Some(
            vpnctl_inventory::resolve_jump_host(target, jump)
                .map_err(|_| SshAccessFailure::InvalidRoute)?
                .ok_or(SshAccessFailure::InvalidRoute)?,
        ),
    };
    Ok(
        crate::ssh_subprocess::SubprocessSshTransport::new(&target.address, &target.ssh_user, key)
            .port(target.ssh_port)
            .trusted_fingerprint(target.trusted_host_fingerprint.clone())
            .with_jump(hop)
            .timeout(Duration::from_secs(20)),
    )
}

async fn observe(
    target: &Server,
    route: SshAccessRoute,
    jump: Option<&Server>,
    key: &Path,
) -> SshAccessCheck {
    let result = if !key.is_file() {
        Err((SshAccessState::Unknown, SshAccessFailure::MissingKey))
    } else {
        match transport_for_route(target, route, jump, key.to_path_buf()) {
            Err(reason) => Err((SshAccessState::Unknown, reason)),
            Ok(ssh) => ssh
                .exec_unprivileged("true")
                .await
                .map(|_| ())
                .map_err(|error| {
                    (
                        SshAccessState::Unavailable,
                        failure_reason(&error.to_string()),
                    )
                }),
        }
    };
    let (state, failure) = match result {
        Ok(()) => (SshAccessState::Available, None),
        Err((state, reason)) => (state, Some(reason)),
    };
    SshAccessCheck {
        state,
        failure,
        checked_at: chrono::Utc::now(),
    }
}

fn failure_reason(message: &str) -> SshAccessFailure {
    let message = message.to_ascii_lowercase();
    if message.contains("timed out") || message.contains("timeout") {
        SshAccessFailure::Timeout
    } else if message.contains("permission denied") || message.contains("authentication failed") {
        SshAccessFailure::Authentication
    } else if message.contains("host key verification failed")
        || message.contains("host identification")
        || message.contains("did not present its pinned host key")
        || message.contains("did not present its inventory-pinned host key")
    {
        SshAccessFailure::HostKey
    } else {
        SshAccessFailure::Connection
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> Server {
        Server {
            id: ServerId("target".into()),
            address: "192.0.2.1".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![],
            enabled_protocols: vec![],
            trusted_host_fingerprint: Some(
                "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            ),
            hoster: "generic".into(),
            jump_via: Some(ServerId("gateway".into())),
            usage_coefficient: 1.0,
        }
    }

    #[test]
    fn direct_probe_ignores_the_targets_configured_jump() {
        let result = transport_for_route(
            &target(),
            SshAccessRoute::Direct,
            None,
            "/tmp/fixture-key".into(),
        );
        assert!(matches!(result, Ok(transport) if format!("{transport:?}").contains("jump: None")));
    }

    #[test]
    fn invalid_jump_never_falls_back_to_a_direct_probe() {
        assert!(matches!(
            transport_for_route(
                &target(),
                SshAccessRoute::Jump,
                None,
                "/tmp/fixture-key".into()
            ),
            Err(SshAccessFailure::InvalidRoute)
        ));
        let mut gateway = target();
        gateway.id = ServerId("gateway".into());
        gateway.address = "192.0.2.2".into();
        gateway.jump_via = None;
        assert!(
            matches!(transport_for_route(&target(), SshAccessRoute::Jump, Some(&gateway), "/tmp/fixture-key".into()), Ok(transport) if format!("{transport:?}").contains("jump: Some("))
        );
    }

    #[test]
    fn concurrent_requests_share_one_lease_until_completion() {
        let key = ("ssh-coalescing-test".into(), ServerId("node".into()));
        let first = CheckLease::acquire(key.clone());
        assert!(first.is_some());
        assert!(CheckLease::acquire(key.clone()).is_none());
        drop(first);
        assert!(CheckLease::acquire(key).is_some());
    }

    #[test]
    fn failure_reasons_never_retain_command_output() {
        for (error, expected) in [
            ("ssh timed out: sensitive-output", SshAccessFailure::Timeout),
            (
                "Permission denied (publickey): sensitive-output",
                SshAccessFailure::Authentication,
            ),
            (
                "target did not present its inventory-pinned host key",
                SshAccessFailure::HostKey,
            ),
            (
                "Connection refused: sensitive-output",
                SshAccessFailure::Connection,
            ),
        ] {
            assert_eq!(failure_reason(error), expected);
        }
    }

    #[test]
    fn keyscan_connection_failures_do_not_imply_a_host_key_mismatch() {
        for error in [
            "ssh pinned host keyscan exit=Some(1) stderr=",
            "ssh-keyscan for pinned host returned no keys",
        ] {
            assert_eq!(failure_reason(error), SshAccessFailure::Connection);
        }
        assert_eq!(
            failure_reason("Host key verification failed."),
            SshAccessFailure::HostKey
        );
        assert_eq!(
            failure_reason("ssh pinned host keyscan timed out after 12s"),
            SshAccessFailure::Timeout
        );
    }
}
