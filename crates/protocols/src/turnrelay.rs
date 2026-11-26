//! TurnRelay exit protocol (`turnrelay`).
//!
//! A node runs `turnrelay-server`, which terminates the obfuscated TURN
//! transport on UDP and dials destinations itself. Clients reach it through a
//! TURN provider. The controller resolves an optional `turnrelay.relay_server_id`
//! to concrete TURN credentials before rendering. The locked v1 profile is a
//! self-contained `turnrelay://<base64url-json>#<label>` URI that VPNRouter imports as a
//! native outbound. The server authenticates clients with one pre-shared exit
//! password (`turnrelay.password`, minted once) and pins its persistent DTLS
//! certificate; `observed.turnrelay.cert_sha256` is the SHA-256 of the leaf
//! DER certificate and `observed.turnrelay.applied` is a digest of every
//! client-visible server setting, so a profile is issued only after the node
//! has actually applied the current configuration.

use std::collections::HashMap;
use std::net::IpAddr;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use vpnctl_core::{
    CoreError, DpiRisk, Protocol, ProtocolId, RenderCtx, Result, ServerSecretSpec, User,
};

pub const TURNRELAY_PORT: u16 = 53492;
pub const TURNRELAY_DEFAULT_MODE: &str = "dtls";
pub const TURNRELAY_DEFAULT_CONNECTIONS: u8 = 2;
/// Maximum length of a sing-box outbound tag. TurnRelay hop ids and every
/// relayed VLESS `outbound`/`detour` value must stay inside this bound.
pub const TURNRELAY_OUTBOUND_ID_MAX: usize = 64;

const LISTEN_PORT: &str = "turnrelay.listen_port";
const MODE: &str = "turnrelay.mode";
const TURN_SERVER: &str = "turnrelay.turn_server";
const TURN_USERNAME: &str = "turnrelay.turn_username";
const TURN_PASSWORD: &str = "turnrelay.turn_password";
const CONNECTIONS: &str = "turnrelay.connections";
const UDP: &str = "turnrelay.udp";
const EXIT_PASSWORD: &str = "turnrelay.password";
const CERT_SHA256: &str = "observed.turnrelay.cert_sha256";
const APPLIED: &str = "observed.turnrelay.applied";

const FRAGMENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

#[derive(Debug, Default)]
pub struct TurnRelay;

struct Settings<'a> {
    address: &'a str,
    port: u16,
    turn_server: &'a str,
    turn_username: &'a str,
    turn_password: &'a str,
    mode: &'a str,
    connections: u8,
    udp: bool,
}

impl std::fmt::Debug for Settings<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The exit password is never stored in Settings, but keep both
        // credential fields redacted so a future field cannot leak it.
        f.debug_struct("Settings")
            .field("address", &self.address)
            .field("port", &self.port)
            .field("turn_server", &self.turn_server)
            .field("turn_username", &self.turn_username)
            .field("turn_password", &"[redacted]")
            .field("password", &"[redacted]")
            .field("mode", &self.mode)
            .field("connections", &self.connections)
            .field("udp", &self.udp)
            .finish()
    }
}

/// Deterministic, always-valid sing-box outbound tag.
///
/// Server ids are normally short slugs, but a 64-character id would push a
/// prefixed tag past sing-box's 64-byte cap and break the whole config. When
/// the composed value is too long, truncate it and append `-` plus the first
/// eight hex characters of its SHA-256. The same helper feeds the `turnrelay`
/// hop `id` and the VLESS `detour`, so they can never drift apart.
fn capped_outbound_id(raw: &str) -> String {
    let mut cleaned = String::with_capacity(raw.len());
    for character in raw.chars() {
        if character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | ':' | '-') {
            cleaned.push(character);
        } else {
            cleaned.push('_');
        }
    }
    if cleaned.len() <= TURNRELAY_OUTBOUND_ID_MAX {
        return cleaned;
    }
    let digest = hex::encode(Sha256::digest(raw.as_bytes()));
    let suffix = &digest[..8];
    let keep = TURNRELAY_OUTBOUND_ID_MAX - 1 - suffix.len();
    format!("{}-{suffix}", &cleaned[..keep])
}

/// Outbound tag of the `turnrelay://` hop for an exit server.
pub fn turnrelay_outbound_id(server_id: &str) -> String {
    capped_outbound_id(&format!("turnrelay-{server_id}"))
}

/// Outbound tag of a relayed VLESS duplicate whose target is the exit itself.
pub fn turnrelay_vless_outbound_id(server_id: &str) -> String {
    capped_outbound_id(&format!("vless-turnrelay-{server_id}"))
}

/// Outbound tag of a relayed VLESS duplicate routed through another exit.
pub fn turnrelay_relayed_vless_outbound_id(target_id: &str, exit_id: &str) -> String {
    capped_outbound_id(&format!("vless-turnrelay-{target_id}-via-{exit_id}"))
}

fn optional<'a>(secrets: &'a HashMap<String, String>, key: &str) -> Option<&'a str> {
    secrets
        .get(key)
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn required<'a>(ctx: &RenderCtx<'a>, key: &str) -> Result<&'a str> {
    optional(ctx.secrets, key).ok_or_else(|| CoreError::MissingSecret {
        server: ctx.server.id.clone(),
        key: key.to_owned(),
    })
}

fn valid_text(value: &str, max_len: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && !value.chars().any(|character| character.is_control())
}

fn valid_turn_server(value: &str) -> bool {
    if !valid_text(value, 255) {
        return false;
    }
    let Some((host, port)) = value.rsplit_once(':') else {
        return false;
    };
    if host.is_empty()
        || host.chars().any(|character| {
            character.is_whitespace() || matches!(character, '/' | '?' | '#' | '@' | '{' | '}')
        })
    {
        return false;
    }
    if host.starts_with('[') || host.ends_with(']') {
        let bracketed = host.starts_with('[') && host.ends_with(']');
        if !bracketed
            || host[1..host.len() - 1]
                .parse::<std::net::Ipv6Addr>()
                .is_err()
        {
            return false;
        }
    } else if host.contains(':') {
        return false;
    }
    port.parse::<u16>().is_ok_and(|port| port != 0)
}

/// Strict pinned-certificate shape: exactly 64 lowercase hexadecimal bytes.
pub fn is_valid_turnrelay_fingerprint(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn settings<'a>(ctx: &RenderCtx<'a>) -> Result<Settings<'a>> {
    let address = ctx.server.address.trim();
    let parsed = address
        .parse::<IpAddr>()
        .map_err(|_| CoreError::Render("TurnRelay needs a literal IP node address".into()))?;
    if parsed.is_unspecified() || parsed.is_multicast() {
        return Err(CoreError::Render(
            "TurnRelay node address must be a routable literal IP".into(),
        ));
    }
    let port = match optional(ctx.secrets, LISTEN_PORT) {
        Some(value) => value
            .parse::<u16>()
            .ok()
            .filter(|port| *port != 0)
            .ok_or_else(|| {
                CoreError::Render("invalid turnrelay.listen_port (expected 1..=65535)".into())
            })?,
        None => TURNRELAY_PORT,
    };
    if port == ctx.server.ssh_port {
        return Err(CoreError::Render(
            "TurnRelay UDP port conflicts with SSH".into(),
        ));
    }
    let turn_server = required(ctx, TURN_SERVER)?;
    if !valid_turn_server(turn_server) {
        return Err(CoreError::Render(
            "invalid TurnRelay TURN server (expected host:port)".into(),
        ));
    }
    let turn_username = required(ctx, TURN_USERNAME)?;
    if !valid_text(turn_username, 256) {
        return Err(CoreError::Render("invalid TurnRelay TURN username".into()));
    }
    let turn_password = required(ctx, TURN_PASSWORD)?;
    if !valid_text(turn_password, 512) {
        return Err(CoreError::Render("invalid TurnRelay TURN password".into()));
    }
    let mode = match optional(ctx.secrets, MODE) {
        None => TURNRELAY_DEFAULT_MODE,
        Some(value @ ("dtls" | "srtp")) => value,
        Some(_) => {
            return Err(CoreError::Render(
                "invalid turnrelay.mode (expected dtls or srtp)".into(),
            ));
        }
    };
    let connections = match optional(ctx.secrets, CONNECTIONS) {
        None => TURNRELAY_DEFAULT_CONNECTIONS,
        Some(value) => value
            .parse::<u8>()
            .ok()
            .filter(|connections| (1..=60).contains(connections))
            .ok_or_else(|| {
                CoreError::Render("invalid turnrelay.connections (expected 1..=60)".into())
            })?,
    };
    let udp = match optional(ctx.secrets, UDP) {
        None => true,
        Some(value) if value.eq_ignore_ascii_case("true") || value == "1" => true,
        Some(value) if value.eq_ignore_ascii_case("false") || value == "0" => false,
        Some(_) => {
            return Err(CoreError::Render(
                "invalid turnrelay.udp (expected true or false)".into(),
            ));
        }
    };
    Ok(Settings {
        address,
        port,
        turn_server,
        turn_username,
        turn_password,
        mode,
        connections,
        udp,
    })
}

fn applied_digest_for(settings: &Settings<'_>, password: &str) -> String {
    let mut material = String::from("turnrelay-v1");
    for part in [
        settings.address,
        settings.turn_server,
        settings.turn_username,
        settings.turn_password,
        password,
        settings.mode,
    ] {
        material.push('\0');
        material.push_str(part);
    }
    material.push('\0');
    material.push_str(&settings.port.to_string());
    material.push('\0');
    material.push_str(&settings.connections.to_string());
    material.push('\0');
    material.push_str(if settings.udp { "true" } else { "false" });
    hex::encode(Sha256::digest(material.as_bytes()))
}

/// Digest of every server-affecting setting plus the exit password. The node
/// publishes it as `observed.turnrelay.applied`; issuance requires an exact
/// match, so changing any field (including rotating the exit password)
/// invalidates profiles until the next successful deploy.
pub fn turnrelay_applied_digest(ctx: &RenderCtx<'_>) -> Result<String> {
    let settings = settings(ctx)?;
    let password = required(ctx, EXIT_PASSWORD)?;
    Ok(applied_digest_for(&settings, password))
}

fn ready<'a>(ctx: &RenderCtx<'a>) -> Result<(Settings<'a>, &'a str, &'a str)> {
    let settings = settings(ctx)?;
    let password = required(ctx, EXIT_PASSWORD)?;
    let applied = required(ctx, APPLIED)?;
    if applied != applied_digest_for(&settings, password) {
        return Err(CoreError::Render(
            "TurnRelay is not deployed for these settings".into(),
        ));
    }
    let fingerprint = required(ctx, CERT_SHA256)?;
    if !is_valid_turnrelay_fingerprint(fingerprint) {
        return Err(CoreError::Render(
            "TurnRelay certificate fingerprint is not 64 lowercase hex characters".into(),
        ));
    }
    Ok((settings, password, fingerprint))
}

impl Protocol for TurnRelay {
    fn id(&self) -> ProtocolId {
        ProtocolId("turnrelay".into())
    }

    fn listen_ports(&self) -> &'static [(&'static str, u16)] {
        &[("udp", TURNRELAY_PORT)]
    }

    fn effective_listen_ports(
        &self,
        secrets: &HashMap<String, String>,
    ) -> Vec<(&'static str, u16)> {
        let port = optional(secrets, LISTEN_PORT)
            .and_then(|value| value.parse::<u16>().ok())
            .filter(|port| *port != 0)
            .unwrap_or(TURNRELAY_PORT);
        vec![("udp", port)]
    }

    fn appears_in_sing_box_sub(&self) -> bool {
        false
    }

    fn appears_in_stock_sing_box_sub(&self) -> bool {
        false
    }

    fn dpi_risk(&self) -> DpiRisk {
        DpiRisk::Strong
    }

    fn validate_server(&self, ctx: &RenderCtx<'_>) -> Result<()> {
        settings(ctx).map(|_| ())
    }

    fn server_secret_specs(&self) -> Vec<ServerSecretSpec> {
        vec![ServerSecretSpec::Password {
            key: EXIT_PASSWORD,
            entropy_bytes: 32,
        }]
    }

    fn server_inbound(&self, ctx: &RenderCtx<'_>, _users: &[User]) -> Result<Value> {
        let settings = settings(ctx)?;
        let password = required(ctx, EXIT_PASSWORD)?;
        let relay_ip = settings
            .turn_server
            .rsplit_once(':')
            .and_then(|(host, _)| host.parse::<std::net::Ipv4Addr>().ok());
        Ok(json!({
            "address": settings.address,
            "relay_ip": relay_ip,
            "listen_port": settings.port,
            "mode": settings.mode,
            "password": password,
            "connections": settings.connections,
            "udp": settings.udp,
            "applied": applied_digest_for(&settings, password),
        }))
    }

    fn client_config(&self, ctx: &RenderCtx<'_>, user: &User) -> Result<Value> {
        if user.disabled {
            return Err(CoreError::Render(
                "TurnRelay is disabled for this user".into(),
            ));
        }
        let (settings, password, fingerprint) = ready(ctx)?;
        Ok(json!({
            "id": turnrelay_outbound_id(&ctx.server.id.0),
            "provider": "static",
            "server_type": "exit",
            "server": settings.address,
            "server_port": settings.port,
            "turn_server": settings.turn_server,
            "turn_username": settings.turn_username,
            "turn_password": settings.turn_password,
            "password": password,
            "server_fingerprint": fingerprint,
            "connections": settings.connections,
            "mode": settings.mode,
            "udp": settings.udp,
        }))
    }

    fn share_link(&self, ctx: &RenderCtx<'_>, user: &User) -> Result<String> {
        let value = self.client_config(ctx, user)?;
        let label = format!("{} TurnRelay ~{}", ctx.server.id.0, user.id.0);
        Ok(format!(
            "turnrelay://{}#{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&value)?),
            utf8_percent_encode(&label, FRAGMENT)
        ))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use vpnctl_core::{KernelId, Server, ServerId, UserId};

    fn server() -> Server {
        Server {
            id: ServerId("de".into()),
            address: "192.0.2.10".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("turnrelay".into())],
            enabled_protocols: vec![ProtocolId("turnrelay".into())],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        }
    }

    fn user() -> User {
        User {
            id: UserId("alice".into()),
            uuid: "11111111-1111-4111-8111-111111111111".into(),
            tuic_password: None,
            wireguard_pubkey: None,
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: false,
        }
    }

    fn secrets() -> HashMap<String, String> {
        let mut secrets = HashMap::new();
        secrets.insert(TURN_SERVER.into(), "turn.example.org:3478".into());
        secrets.insert(TURN_USERNAME.into(), "turn-user".into());
        secrets.insert(TURN_PASSWORD.into(), "turn-pass".into());
        secrets.insert(EXIT_PASSWORD.into(), "exit-pass".into());
        secrets
    }

    fn deployed() -> HashMap<String, String> {
        let mut secrets = secrets();
        let server = server();
        let ctx = RenderCtx::new(&server, &secrets);
        let applied = turnrelay_applied_digest(&ctx).unwrap();
        secrets.insert(APPLIED.into(), applied);
        secrets.insert(CERT_SHA256.into(), "ab".repeat(32));
        secrets
    }

    #[test]
    fn defaults_are_locked() {
        let server = server();
        let secrets = secrets();
        let settings = settings(&RenderCtx::new(&server, &secrets)).unwrap();
        assert_eq!(settings.port, TURNRELAY_PORT);
        assert_eq!(settings.mode, "dtls");
        assert_eq!(settings.connections, 2);
        assert!(settings.udp);
    }

    #[test]
    fn invalid_overrides_are_rejected() {
        for (key, value) in [
            (LISTEN_PORT, "0"),
            (LISTEN_PORT, "junk"),
            (MODE, "wrap"),
            (CONNECTIONS, "0"),
            (CONNECTIONS, "61"),
            (UDP, "sometimes"),
            (TURN_SERVER, "turn.example.org"),
            (TURN_SERVER, "turn.example.org:0"),
            (TURN_SERVER, "[::1]"),
        ] {
            let mut secrets = secrets();
            secrets.insert(key.into(), value.into());
            assert!(
                settings(&RenderCtx::new(&server(), &secrets)).is_err(),
                "{key}={value}"
            );
        }
    }

    #[test]
    fn fingerprint_requires_lowercase_hex() {
        assert!(is_valid_turnrelay_fingerprint(&"ab".repeat(32)));
        assert!(!is_valid_turnrelay_fingerprint(&"AB".repeat(32)));
        assert!(!is_valid_turnrelay_fingerprint(&"ab".repeat(31)));
        assert!(!is_valid_turnrelay_fingerprint(&"zz".repeat(32)));
    }

    #[test]
    fn turn_server_accepts_255_and_rejects_256_characters() {
        let host = |len: usize| "a".repeat(len - ":3478".len());
        let ok = format!("{}:3478", host(255));
        assert_eq!(ok.len(), 255);
        let mut accepted_secrets = secrets();
        accepted_secrets.insert(TURN_SERVER.into(), ok);
        assert!(settings(&RenderCtx::new(&server(), &accepted_secrets)).is_ok());

        let too_long = format!("{}:3478", host(256));
        assert_eq!(too_long.len(), 256);
        let mut rejected_secrets = secrets();
        rejected_secrets.insert(TURN_SERVER.into(), too_long);
        assert!(settings(&RenderCtx::new(&server(), &rejected_secrets)).is_err());
    }

    #[test]
    fn outbound_ids_are_capped_and_share_one_helper() {
        let short = "de";
        assert_eq!(turnrelay_outbound_id(short), "turnrelay-de");
        assert_eq!(turnrelay_vless_outbound_id(short), "vless-turnrelay-de");
        assert_eq!(
            turnrelay_relayed_vless_outbound_id("is", short),
            "vless-turnrelay-is-via-de"
        );

        let long = "a".repeat(64);
        let hop = turnrelay_outbound_id(&long);
        let vless = turnrelay_vless_outbound_id(&long);
        let relayed = turnrelay_relayed_vless_outbound_id(&long, &long);
        for id in [&hop, &vless, &relayed] {
            assert!(id.len() <= TURNRELAY_OUTBOUND_ID_MAX, "{id}");
            assert!(
                id.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '-')),
                "{id}"
            );
        }
        assert_ne!(hop, turnrelay_outbound_id(&"b".repeat(64)));
        let raw = format!("turnrelay-{long}");
        assert!(hop.ends_with(&hex::encode(&Sha256::digest(raw.as_bytes())[..4])));
    }

    #[test]
    fn settings_debug_redacts_credentials() {
        let server = server();
        let secrets = secrets();
        let settings = settings(&RenderCtx::new(&server, &secrets)).unwrap();
        let debug = format!("{settings:?}");
        assert!(debug.contains("[redacted]"));
        assert!(!debug.contains("turn-pass"));
        assert!(!debug.contains("exit-pass"));
    }

    #[test]
    fn client_config_requires_an_exact_applied_digest() {
        let server = server();
        let secrets = deployed();
        let ctx = RenderCtx::new(&server, &secrets);
        let value = TurnRelay.client_config(&ctx, &user()).unwrap();
        assert_eq!(value["id"], "turnrelay-de");
        assert_eq!(value["server"], "192.0.2.10");
        assert_eq!(value["server_port"], TURNRELAY_PORT);
        assert_eq!(value["connections"], 2);
        assert_eq!(value["mode"], "dtls");
        assert_eq!(value["udp"], true);

        let mut rotated = secrets;
        rotated.insert(EXIT_PASSWORD.into(), "rotated".into());
        assert!(
            TurnRelay
                .client_config(&RenderCtx::new(&server, &rotated), &user())
                .is_err()
        );
    }

    #[test]
    fn share_link_is_base64url_json_with_encoded_label() {
        let server = server();
        let secrets = deployed();
        let link = TurnRelay
            .share_link(&RenderCtx::new(&server, &secrets), &user())
            .unwrap();
        let rest = link.strip_prefix("turnrelay://").unwrap();
        let (payload, label) = rest.split_once('#').unwrap();
        assert_eq!(label, "de%20TurnRelay%20~alice");
        let profile: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap();
        assert_eq!(profile["provider"], "static");
        assert_eq!(profile["server_type"], "exit");
        assert_eq!(profile["server_fingerprint"], "ab".repeat(32));
    }
}
