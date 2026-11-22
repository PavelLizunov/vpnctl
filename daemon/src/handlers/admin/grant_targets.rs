//! Server readiness for user grants.
//!
//! A grant is only useful when a deploy can actually reach the node with the
//! vpnctld deploy key. The SSH access observer records that proof separately
//! for direct and jump routes; this module turns the fresh observation into a
//! single operator-facing readiness value. Inventory and CLI grants stay
//! unchanged; only the web mutation paths consult this helper.

use std::collections::HashMap;

use vpnctl_core::{Server, ServerId};
use vpnctl_inventory::{
    ServerRole, SshAccessFailure, SshAccessRoute, SshAccessState, SshAccessStatus,
};

use crate::AppState;
use crate::i18n::{Locale, tr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GrantReadiness {
    Eligible,
    WorkloadOnly,
    Unverified {
        route: SshAccessRoute,
        failure: Option<SshAccessFailure>,
    },
    Unknown {
        route: SshAccessRoute,
    },
}

impl GrantReadiness {
    pub(crate) fn is_eligible(self) -> bool {
        matches!(self, Self::Eligible)
    }

    pub(crate) fn reason(self, lang: Locale) -> String {
        match self {
            Self::Eligible => tr(lang, "ready", "готова").to_string(),
            Self::WorkloadOnly => {
                tr(lang, "workload-only server", "сервер workload-only").to_string()
            }
            Self::Unverified { route, failure } => {
                let route_label = route_label(route, lang);
                match failure {
                    Some(failure) => format!(
                        "{route_label}: {}",
                        crate::handlers::admin::ssh_access::failure_label(failure, lang)
                    ),
                    None => format!("{route_label}: {}", tr(lang, "not verified", "не проверен")),
                }
            }
            Self::Unknown { route } => format!(
                "{}: {}",
                route_label(route, lang),
                tr(lang, "not verified", "не проверен")
            ),
        }
    }

    pub(crate) fn check_href(server: &ServerId) -> String {
        format!(
            "/admin/servers/{}/status#ssh-access",
            crate::http_util::path_segment_encode(&server.0)
        )
    }

    pub(crate) fn push_key_href(server: &ServerId) -> String {
        format!(
            "/admin/servers/{}/setup#push-deploy-key",
            crate::http_util::path_segment_encode(&server.0)
        )
    }
}

fn route_for(server: &Server) -> SshAccessRoute {
    if server.jump_via.is_some() {
        SshAccessRoute::Jump
    } else {
        SshAccessRoute::Direct
    }
}

fn route_label(route: SshAccessRoute, lang: Locale) -> &'static str {
    match route {
        SshAccessRoute::Direct => tr(lang, "direct SSH", "SSH напрямую"),
        SshAccessRoute::Jump => tr(lang, "SSH via jump", "SSH через jump"),
    }
}

/// Evaluate a server against an already-loaded SSH access status.
///
/// Deploy uses the configured jump route when one exists, so the jump
/// observation is authoritative in that case; a healthy direct route cannot
/// substitute for it. Servers without a jump use the direct observation.
pub(crate) fn evaluate(
    server: &Server,
    role: ServerRole,
    status: Option<&SshAccessStatus>,
) -> GrantReadiness {
    if role == ServerRole::WorkloadOnly {
        return GrantReadiness::WorkloadOnly;
    }
    let route = route_for(server);
    let check = status.and_then(|status| match route {
        SshAccessRoute::Direct => status.direct.as_ref(),
        SshAccessRoute::Jump => status.jump.as_ref(),
    });
    match check {
        Some(check) if check.state == SshAccessState::Available => GrantReadiness::Eligible,
        Some(check) => GrantReadiness::Unverified {
            route,
            failure: check.failure,
        },
        None => GrantReadiness::Unknown { route },
    }
}

/// Read the fresh SSH access observation for one server.
///
/// A failed read is treated as unverified: a grant must never slip through
/// because the readiness lookup itself failed.
pub(crate) async fn read(state: &AppState, server: &Server) -> GrantReadiness {
    let role = match state.inv.get_server_role(&server.id).await {
        Ok(role) => role,
        Err(error) => {
            tracing::warn!(
                target = "vpnctld::admin",
                server = %server.id,
                error = %error,
                "grant readiness: server role read failed; treating as unverified"
            );
            return GrantReadiness::Unknown {
                route: route_for(server),
            };
        }
    };
    if role == ServerRole::WorkloadOnly {
        return GrantReadiness::WorkloadOnly;
    }
    let status = state
        .inv
        .ssh_access_for_server(
            &server.id,
            chrono::Utc::now(),
            crate::ssh_access::max_age_secs(),
        )
        .await
        .ok();
    evaluate(server, role, status.as_ref())
}

pub(crate) async fn read_many(
    state: &AppState,
    servers: &[Server],
) -> HashMap<ServerId, GrantReadiness> {
    let mut out = HashMap::with_capacity(servers.len());
    for server in servers {
        out.insert(server.id.clone(), read(state, server).await);
    }
    out
}

pub(crate) fn blocked_message(server: &Server, readiness: GrantReadiness) -> String {
    if matches!(readiness, GrantReadiness::WorkloadOnly) {
        return format!(
            "grant rejected: server '{}' is workload-only and cannot receive user grants.",
            server.id.0
        );
    }
    let check_href = GrantReadiness::check_href(&server.id);
    let push_href = GrantReadiness::push_key_href(&server.id);
    format!(
        "grant rejected: server '{}' has no verified SSH deploy-key path ({}). \
         New grants stay disabled until a fresh Check SSH access at {check_href} reports \
         Available; if the deploy key was never installed, push it from {push_href}.",
        server.id.0,
        readiness.reason(Locale::En),
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use chrono::Utc;
    use vpnctl_inventory::SshAccessCheck;

    fn server(id: &str, jump_via: Option<&str>) -> Server {
        Server {
            id: ServerId(id.into()),
            address: "203.0.113.10".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: Vec::new(),
            enabled_protocols: Vec::new(),
            trusted_host_fingerprint: Some(
                "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            ),
            hoster: "generic".into(),
            jump_via: jump_via.map(|id| ServerId(id.into())),
            usage_coefficient: 1.0,
        }
    }

    fn check(state: SshAccessState, failure: Option<SshAccessFailure>) -> SshAccessCheck {
        SshAccessCheck {
            state,
            failure,
            checked_at: Utc::now(),
        }
    }

    #[test]
    fn available_direct_check_makes_a_direct_server_eligible() {
        let status = SshAccessStatus {
            direct: Some(check(SshAccessState::Available, None)),
            jump: None,
        };
        assert_eq!(
            evaluate(&server("s", None), ServerRole::VpnExit, Some(&status)),
            GrantReadiness::Eligible
        );
    }

    #[test]
    fn jump_server_requires_the_jump_observation_even_when_direct_is_available() {
        let status = SshAccessStatus {
            direct: Some(check(SshAccessState::Available, None)),
            jump: None,
        };
        assert_eq!(
            evaluate(
                &server("s", Some("gateway")),
                ServerRole::VpnExit,
                Some(&status)
            ),
            GrantReadiness::Unknown {
                route: SshAccessRoute::Jump
            }
        );
    }

    #[test]
    fn failed_or_missing_checks_are_not_eligible() {
        let status = SshAccessStatus {
            direct: Some(check(
                SshAccessState::Unavailable,
                Some(SshAccessFailure::Authentication),
            )),
            jump: None,
        };
        assert_eq!(
            evaluate(&server("s", None), ServerRole::VpnExit, Some(&status)),
            GrantReadiness::Unverified {
                route: SshAccessRoute::Direct,
                failure: Some(SshAccessFailure::Authentication),
            }
        );
        assert_eq!(
            evaluate(&server("s", None), ServerRole::VpnExit, None),
            GrantReadiness::Unknown {
                route: SshAccessRoute::Direct
            }
        );
    }

    #[test]
    fn workload_only_servers_are_never_grant_targets() {
        assert_eq!(
            evaluate(&server("s", None), ServerRole::WorkloadOnly, None),
            GrantReadiness::WorkloadOnly
        );
    }

    #[test]
    fn blocked_message_names_the_checked_route_and_web_actions() {
        let message = blocked_message(
            &server("fra-01", Some("gateway")),
            GrantReadiness::Unverified {
                route: SshAccessRoute::Jump,
                failure: Some(SshAccessFailure::Stale),
            },
        );
        assert!(message.contains("/admin/servers/fra-01/status#ssh-access"));
        assert!(message.contains("/admin/servers/fra-01/setup#push-deploy-key"));
        assert!(message.contains("SSH via jump"));
        assert!(message.contains("No fresh measurement"));
    }
}
