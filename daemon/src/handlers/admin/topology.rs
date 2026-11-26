use std::collections::{BTreeSet, HashMap};

use axum::response::Response;
use maud::{Markup, html};
use vpnctl_core::{Server, ServerId};
use vpnctl_inventory::SqliteInventory;

use super::helpers::{ServerNames, internal_error};
use super::turnrelay::{self, ENTRY, EXIT};
use crate::http_util::path_segment_encode;
use crate::i18n::{Locale, tr};

#[derive(Default)]
struct Roles {
    entry: bool,
    exit: bool,
    entries: BTreeSet<String>,
    exits: BTreeSet<String>,
}

#[derive(Default)]
pub(super) struct Topology {
    roles: HashMap<ServerId, Roles>,
    pub(super) relay_exits: HashMap<ServerId, BTreeSet<String>>,
}

impl Topology {
    pub(super) async fn load(inv: &SqliteInventory, servers: &[Server]) -> Result<Self, Response> {
        let mut topology = Self::default();
        let entries: Vec<_> = servers
            .iter()
            .filter(|s| turnrelay::enabled(s, ENTRY))
            .collect();
        for server in servers {
            let role = topology.roles.entry(server.id.clone()).or_default();
            role.entry |= turnrelay::enabled(server, ENTRY);
            role.exit |= turnrelay::enabled(server, EXIT);
            let detour = inv
                .client_detour_via(&server.id)
                .await
                .map_err(|error| internal_error(error.into()))?;
            if let Some(detour) = detour {
                topology.link(&server.id, &detour);
            }
            if turnrelay::enabled(server, EXIT) && !entries.is_empty() {
                let settings = inv
                    .list_server_secrets(&server.id)
                    .await
                    .map_err(|error| internal_error(error.into()))?;
                if let Some(entry) = turnrelay::relay_for(server, &settings, &entries) {
                    topology.link(&server.id, &entry.id);
                    topology
                        .relay_exits
                        .entry(entry.id.clone())
                        .or_default()
                        .insert(server.id.0.clone());
                }
            }
        }
        Ok(topology)
    }

    fn link(&mut self, exit: &ServerId, entry: &ServerId) {
        let role = self.roles.entry(exit.clone()).or_default();
        role.exit = true;
        role.entries.insert(entry.0.clone());
        let role = self.roles.entry(entry.clone()).or_default();
        role.entry = true;
        role.exits.insert(exit.0.clone());
    }

    pub(super) fn badges(&self, id: &ServerId, names: &ServerNames, lang: Locale) -> Markup {
        let Some(roles) = self.roles.get(id) else {
            return html! {};
        };
        html! {
            @if roles.entry || roles.exit {
                div.ed-role-badges {
                    @if roles.entry {
                        span.ed-role-line {
                            span.ed-role-badge.ed-role-badge--entry { (tr(lang, "ENTRY", "ВХОД")) }
                            @for peer in &roles.exits { (peer_link(peer, names, "→")) }
                        }
                    }
                    @if roles.exit {
                        span.ed-role-line {
                            span.ed-role-badge.ed-role-badge--exit { (tr(lang, "EXIT", "ВЫХОД")) }
                            @for peer in &roles.entries { (peer_link(peer, names, "←")) }
                        }
                    }
                }
            }
        }
    }
}

fn peer_link(id: &str, names: &ServerNames, direction: &str) -> Markup {
    html! {
        a.ed-role-peer href=(format!("/admin/servers/{}", path_segment_encode(id))) {
            (direction) " " (names.get(&ServerId(id.into())).map_or(id, String::as_str))
        }
    }
}
