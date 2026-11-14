use std::collections::{BTreeMap, HashMap, HashSet};

use base64::Engine;
use base64::alphabet::STANDARD;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use serde_json::json;
use sha2::{Digest, Sha256};
use url::Url;
use vpnctl_core::{ProtocolId, RenderCtx, ServerId, User, UserId};
use vpnctl_inventory::sqlite::SubscriptionServer;

use crate::AppState;
use crate::handlers::vpn_router::{
    collect_extra_protocol_uris, collect_vless_uris_for_user, server_display_label,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CorpEligibleServer {
    pub server_id: ServerId,
    pub label: String,
    pub hosts: Vec<String>,
    pub configuration_fingerprint: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum EligibilityError {
    #[error("corporate eligibility inventory is unavailable")]
    InventoryUnavailable,
    #[error("corporate subscription configuration is invalid")]
    InvalidConfiguration,
}

// These contain client credentials and deliberately have no Debug implementation.
struct Choice {
    input_index: usize,
    protocol: &'static str,
    host: String,
    connection: String,
}

const PROFILES: [(&str, &str, Option<&str>); 3] = [
    ("vless+reality", "VLESS", None),
    ("vless-ws", "WS", Some("vlessws.domain")),
    ("vless+xhttp", "XHTTP", Some("vlessxhttp.path")),
];

pub async fn eligible_servers(
    state: &AppState,
    user_id: &UserId,
) -> Result<Vec<CorpEligibleServer>, EligibilityError> {
    let Some(user) = enabled_user(state, user_id).await? else {
        return Ok(Vec::new());
    };
    let inputs = state
        .inv
        .subscription_render_inputs(user_id, false)
        .await
        .map_err(|_| EligibilityError::InventoryUnavailable)?;
    let choices = collect_choices(state, &inputs, &user)?;
    let mut groups: Vec<(usize, Vec<Choice>)> = Vec::new();
    let mut positions = HashMap::new();
    for choice in choices {
        let position = *positions.entry(choice.input_index).or_insert_with(|| {
            let position = groups.len();
            groups.push((choice.input_index, Vec::new()));
            position
        });
        groups[position].1.push(choice);
    }
    let mut result = Vec::with_capacity(groups.len());
    for (index, choices) in groups {
        let input = &inputs[index];
        let fingerprint = configuration_fingerprint(state, user_id, input, &choices).await?;
        result.push(CorpEligibleServer {
            server_id: input.server.id.clone(),
            label: server_display_label(&input.server.id.0, input.display_name.as_deref()),
            hosts: choices.into_iter().map(|choice| choice.host).collect(),
            configuration_fingerprint: fingerprint,
        });
    }
    if enabled_user(state, user_id).await?.is_none() {
        return Ok(Vec::new());
    }
    Ok(result)
}

async fn enabled_user(
    state: &AppState,
    user_id: &UserId,
) -> Result<Option<User>, EligibilityError> {
    state
        .inv
        .get_user(user_id)
        .await
        .map(|user| user.filter(|user| !user.disabled))
        .map_err(|_| EligibilityError::InventoryUnavailable)
}

fn collect_choices(
    state: &AppState,
    inputs: &[SubscriptionServer],
    user: &User,
) -> Result<Vec<Choice>, EligibilityError> {
    let mut choices = Vec::new();
    let mut hosts = HashSet::new();
    for (protocol, label, required_secret) in PROFILES {
        let id = ProtocolId(protocol.to_owned());
        for (input_index, input) in inputs.iter().enumerate() {
            if input.suppressed || input.detour_via.is_some() || !input.visible.contains(&id) {
                continue;
            }
            let links = if protocol == "vless+reality" {
                collect_vless_uris_for_user(std::slice::from_ref(input), &user.id.0, false)
            } else {
                // A failing share-link renderer can include secret values in its
                // error. Preflight it without logging before using the collector.
                let Some(renderer) = state.registry.protocol(&id) else {
                    continue;
                };
                let client = user.with_per_server_uuid(&input.client_uuid);
                let context = RenderCtx::new(&input.server, &input.secrets);
                if renderer.share_link(&context, &client).is_err() {
                    continue;
                }
                collect_extra_protocol_uris(
                    state,
                    std::slice::from_ref(input),
                    user,
                    &id,
                    label,
                    required_secret,
                )
            };
            for link in links {
                let Some((host, connection)) = parse_choice(&link)? else {
                    continue;
                };
                if hosts.insert(host.clone()) {
                    choices.push(Choice {
                        input_index,
                        protocol,
                        host,
                        connection,
                    });
                }
            }
        }
    }
    Ok(choices)
}

fn parse_choice(link: &str) -> Result<Option<(String, String)>, EligibilityError> {
    let rest = link
        .strip_prefix("vless://")
        .ok_or(EligibilityError::InvalidConfiguration)?;
    let mut parsed = Url::parse(&format!("https://{rest}"))
        .map_err(|_| EligibilityError::InvalidConfiguration)?;
    let host = parsed
        .host_str()
        .map(|host| {
            host.trim_start_matches('[')
                .trim_end_matches(']')
                .to_ascii_lowercase()
        })
        .filter(|host| !host.is_empty())
        .ok_or(EligibilityError::InvalidConfiguration)?;
    let identity = percent_encoding::percent_decode_str(parsed.username())
        .decode_utf8()
        .map_err(|_| EligibilityError::InvalidConfiguration)?;
    if identity.trim().is_empty()
        || parsed.password().is_some()
        || parsed.port_or_known_default().is_none_or(|port| port == 0)
    {
        return Err(EligibilityError::InvalidConfiguration);
    }
    let mut query = BTreeMap::new();
    for (key, value) in parsed.query_pairs() {
        if query.insert(key.into_owned(), value.into_owned()).is_some() {
            return Err(EligibilityError::InvalidConfiguration);
        }
    }
    let public_key = query.get("pbk").map(String::as_str).unwrap_or_default();
    let short_id = query.get("sid").map(String::as_str).unwrap_or_default();
    // Pinned to the shipped client's PlaceholderDefense, not a network inventory.
    if host == "195.135.255.216"
        || public_key.eq_ignore_ascii_case("DnT9hIvt5QEx07unHUeXbWxN4Qo1gnecN4p0s62nckU")
        || short_id.eq_ignore_ascii_case("78ca7952")
    {
        return Ok(None);
    }
    if query
        .get("security")
        .is_some_and(|security| security.eq_ignore_ascii_case("reality"))
        && (!valid_public_key(public_key)
            || short_id.len() > 16
            || !short_id.len().is_multiple_of(2)
            || !short_id.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        return Err(EligibilityError::InvalidConfiguration);
    }
    parsed.set_fragment(None);
    Ok(Some((host, parsed.into())))
}

fn valid_public_key(value: &str) -> bool {
    if value.is_empty() || !value.is_ascii() || value.len() % 4 == 1 {
        return false;
    }
    let mut value = value.replace('-', "+").replace('_', "/");
    match value.len() % 4 {
        2 => value.push_str("=="),
        3 => value.push('='),
        _ => {}
    }
    value.retain(|c| !matches!(c, ' ' | '\r' | '\n' | '\t'));
    let engine = GeneralPurpose::new(
        &STANDARD,
        GeneralPurposeConfig::new()
            .with_decode_padding_mode(DecodePaddingMode::RequireCanonical)
            .with_decode_allow_trailing_bits(true),
    );
    engine.decode(value).is_ok_and(|bytes| bytes.len() == 32)
}

async fn configuration_fingerprint(
    state: &AppState,
    user_id: &UserId,
    input: &SubscriptionServer,
    choices: &[Choice],
) -> Result<String, EligibilityError> {
    let server = &input.server;
    let jump = state
        .inv
        .resolve_jump_host(server)
        .await
        .map_err(|_| EligibilityError::InventoryUnavailable)?;
    let mut kernels: Vec<_> = server
        .kernels
        .iter()
        .map(|kernel| kernel.0.as_str())
        .collect();
    kernels.sort_unstable();
    let endpoints: Vec<_> = choices
        .iter()
        .map(|choice| {
            let secrets: BTreeMap<_, _> = input
                .secrets
                .iter()
                .filter(|(key, _)| match choice.protocol {
                    "vless-ws" => key.starts_with("vlessws."),
                    "vless+xhttp" => key.starts_with("vless.") || key.starts_with("vlessxhttp."),
                    _ => key.starts_with("vless."),
                })
                .collect();
            json!({
                "protocol": choice.protocol,
                "host": choice.host,
                "connection": choice.connection,
                "secrets": secrets,
            })
        })
        .collect();
    let material = json!({
        "profile": "vpnrouter-business-direct-vless-v1",
        "user": user_id.0,
        "server": server.id.0,
        "address": server.address,
        "ssh_port": server.ssh_port,
        "ssh_user": server.ssh_user,
        "trusted_host_fingerprint": server.trusted_host_fingerprint,
        "jump_via": server.jump_via,
        "pinned_jump": jump,
        "kernels": kernels,
        "endpoints": endpoints,
    });
    let bytes =
        serde_json::to_vec(&material).map_err(|_| EligibilityError::InvalidConfiguration)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}
