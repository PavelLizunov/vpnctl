use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::Ipv4Addr;

use axum::response::Response;
use tokio::sync::Mutex;
use vpnctl_core::{Server, ServerId};
use vpnctl_inventory::{SqliteInventory, SqliteInventoryError};

use super::helpers::{bad_request, internal_error};
use super::legacy::spawn_user_servers_redeploy;
use crate::AppState;

pub(super) const ENTRY: &str = "turnrelay-relay";
pub(super) const EXIT: &str = "turnrelay";
pub(super) const RELAY_ID: &str = "turnrelay.relay_server_id";
pub(super) const PORT: &str = "turnrelay_relay.listen_port";
const HOST: &str = "turnrelay.turn_server";
const USERNAME: &str = "turnrelay_relay.username";
const PASSWORD: &str = "turnrelay_relay.password";
const ALLOWED: &str = "turnrelay_relay.allowed_exits";
pub(super) const WIRING_KEYS: [&str; 5] = [
    RELAY_ID,
    HOST,
    "turnrelay.turn_username",
    "turnrelay.turn_password",
    "turnrelay.publish",
];

// All managed TURN admin writes share this lock so concurrent enables see
// the previous assignment and cannot overwrite a newer allowlist snapshot.
pub(super) static MUTATIONS: Mutex<()> = Mutex::const_new(());

pub(super) fn enabled(server: &Server, protocol: &str) -> bool {
    server.enabled_protocols.iter().any(|id| id.0 == protocol)
}

type Secrets = HashMap<String, String>;

fn value<'a>(secrets: &'a Secrets, key: &str) -> &'a str {
    secrets.get(key).map_or("", |value| value.trim())
}

pub(super) fn relay_for<'a>(
    exit: &Server,
    secrets: &Secrets,
    entries: &[&'a Server],
) -> Option<&'a Server> {
    let id = value(secrets, RELAY_ID);
    let host = value(secrets, HOST).rsplit_once(':').map(|(host, _)| host);
    entries.iter().copied().find(|entry| {
        entry.id != exit.id
            && if id.is_empty() {
                host == Some(entry.address.as_str())
            } else {
                id == entry.id.0
            }
    })
}

pub(super) struct Fleet {
    pub(super) servers: Vec<Server>,
    pub(super) secrets: HashMap<ServerId, Secrets>,
}

impl Fleet {
    pub(super) async fn load(inv: &SqliteInventory) -> Result<Self, SqliteInventoryError> {
        let servers = inv.list_servers().await?;
        let mut secrets = HashMap::new();
        for server in &servers {
            if enabled(server, ENTRY) || enabled(server, EXIT) {
                secrets.insert(
                    server.id.clone(),
                    inv.list_server_secrets(&server.id).await?,
                );
            }
        }
        Ok(Self { servers, secrets })
    }

    pub(super) fn entries(&self) -> Vec<&Server> {
        self.servers.iter().filter(|s| enabled(s, ENTRY)).collect()
    }

    pub(super) fn links<'a>(&'a self, entries: &[&'a Server]) -> Vec<(&'a Server, &'a Server)> {
        self.servers
            .iter()
            .filter(|s| enabled(s, EXIT))
            .filter_map(|exit| {
                relay_for(exit, self.secrets.get(&exit.id)?, entries).map(|entry| (exit, entry))
            })
            .collect()
    }
}

fn wire(secrets: &mut Secrets, entry: &Server, source: &Secrets) {
    let port = source
        .get(PORT)
        .and_then(|port| port.parse::<u16>().ok())
        .filter(|port| *port > 0)
        .unwrap_or(vpnctl_protocols::TURNRELAY_RELAY_PORT);
    for (key, value) in [
        (RELAY_ID, entry.id.0.clone()),
        (HOST, format!("{}:{port}", entry.address)),
        (
            "turnrelay.turn_username",
            value(source, USERNAME).to_owned(),
        ),
        (
            "turnrelay.turn_password",
            value(source, PASSWORD).to_owned(),
        ),
    ] {
        secrets.insert(key.into(), value);
    }
    if value(secrets, "turnrelay.publish").is_empty() {
        secrets.insert("turnrelay.publish".into(), "vless+reality".into());
    }
}

pub(super) async fn wire_exit(
    state: &AppState,
    exit: &Server,
    secrets: &mut Secrets,
    selected_entry: Option<&str>,
) -> Result<(), Response> {
    let desired = selected_entry.unwrap_or_else(|| value(secrets, RELAY_ID));
    let strict = selected_entry.is_some_and(|id| !id.is_empty());
    if desired.is_empty() && !value(secrets, HOST).is_empty() {
        return Ok(());
    }
    let fleet = Fleet::load(&state.inv)
        .await
        .map_err(|err| internal_error(err.into()))?;
    let entries: Vec<_> = fleet
        .entries()
        .into_iter()
        .filter(|entry| {
            entry.id != exit.id
                && fleet.secrets.get(&entry.id).is_some_and(|settings| {
                    !value(settings, USERNAME).is_empty() && !value(settings, PASSWORD).is_empty()
                })
        })
        .collect();
    let links = fleet.links(&entries);
    let entry = entries
        .iter()
        .copied()
        .find(|entry| entry.id.0 == desired)
        .or_else(|| {
            if strict {
                return None;
            }
            entries.iter().copied().min_by_key(|entry| {
                (
                    links
                        .iter()
                        .filter(|(assigned_exit, relay)| {
                            assigned_exit.id != exit.id && relay.id == entry.id
                        })
                        .count(),
                    &entry.id.0,
                )
            })
        });
    if let Some((entry, source)) =
        entry.and_then(|entry| fleet.secrets.get(&entry.id).map(|source| (entry, source)))
    {
        if exit.address.parse::<Ipv4Addr>().is_err() {
            return Err(bad_request(
                "Managed TurnRelay exits need an IPv4 node address",
            ));
        }
        wire(secrets, entry, source);
        return Ok(());
    }
    if strict {
        return Err(bad_request("Selected TURN entry is unavailable"));
    }
    Err(bad_request(
        "Enable turnrelay-relay on an entry server first, or enter manual TURN credentials in TurnRelay settings below.",
    ))
}

pub(super) async fn sync_turnrelay_relay_allowlists(
    state: &AppState,
    subject: &ServerId,
    updated_entry: bool,
    mut redeploy: Vec<Server>,
    trigger: &'static str,
) -> Result<(), Response> {
    let result = reconcile_fleet(state, updated_entry.then_some(subject), &mut redeploy).await;
    // Schedule every committed change even if a later write needs a retry.
    let mut unique = HashSet::new();
    redeploy.retain(|server| unique.insert(server.id.clone()));
    spawn_user_servers_redeploy(state, redeploy, subject.0.clone(), trigger);
    result.map_err(|error| internal_error(error.into()))
}

async fn reconcile_fleet(
    state: &AppState,
    updated_entry: Option<&ServerId>,
    redeploy: &mut Vec<Server>,
) -> Result<(), SqliteInventoryError> {
    let fleet = Fleet::load(&state.inv).await?;
    let entries = fleet.entries();
    let links = fleet.links(&entries);
    for entry in entries {
        let exits = links.iter().filter(|(_, relay)| relay.id == entry.id);
        let allowed = exits
            .clone()
            .filter_map(|(exit, _)| exit.address.parse::<Ipv4Addr>().ok())
            .map(|address| address.to_string())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
            .join(",");
        if fleet
            .secrets
            .get(&entry.id)
            .is_some_and(|old| value(old, ALLOWED) != allowed)
            && state
                .inv
                .set_server_secrets_audited(
                    &entry.id,
                    "admin",
                    "server.turnrelay_relay.allowlist",
                    &[(ALLOWED, &allowed)],
                )
                .await?
        {
            redeploy.push(entry.clone());
        }
        if updated_entry == Some(&entry.id)
            && let Some(source) = fleet.secrets.get(&entry.id).filter(|secrets| {
                !value(secrets, USERNAME).is_empty() && !value(secrets, PASSWORD).is_empty()
            })
        {
            for (exit, _) in exits {
                if let Some(settings) = fleet.secrets.get(&exit.id)
                    && value(settings, RELAY_ID) == entry.id.0
                {
                    let mut settings = settings.clone();
                    wire(&mut settings, entry, source);
                    if state
                        .inv
                        .set_server_secrets_audited(
                            &exit.id,
                            "admin",
                            "server.turnrelay.wire",
                            &wiring_values(&settings),
                        )
                        .await?
                    {
                        redeploy.push((*exit).clone());
                    }
                }
            }
        }
    }
    Ok(())
}

pub(super) fn wiring_values(secrets: &Secrets) -> Vec<(&'static str, &str)> {
    WIRING_KEYS
        .iter()
        .filter_map(|&key| secrets.get(key).map(|value| (key, value.as_str())))
        .collect()
}
