use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::collections::HashSet;
use std::net::IpAddr;
use vpnctl_core::url_host::host_for_url;
use vpnctl_core::{CoreError, Protocol, ProtocolId, RenderCtx, Result, ServerSecretSpec, User};

#[derive(Clone, Copy)]
struct Version {
    number: u8,
    id: &'static str,
    port: u16,
    network: u8,
    private_key: &'static str,
    public_key: &'static str,
    profile_seed: &'static str,
}

const V2: Version = Version {
    number: 2,
    id: "amneziawg2",
    port: 51821,
    network: 72,
    private_key: "amneziawg2.server_private_key",
    public_key: "amneziawg2.server_public_key",
    profile_seed: "amneziawg2.profile_seed",
};
const V3: Version = Version {
    number: 3,
    id: "amneziawg3",
    port: 51822,
    network: 73,
    private_key: "amneziawg3.server_private_key",
    public_key: "amneziawg3.server_public_key",
    profile_seed: "amneziawg3.profile_seed",
};
const HEADER_KEY: &str = "amneziawg3.header_protection_key";

macro_rules! impl_protocol {
    ($name:ident, $version:ident) => {
        #[derive(Debug, Default)]
        pub struct $name;

        impl $name {
            pub fn new() -> Self {
                Self
            }
        }

        impl Protocol for $name {
            fn id(&self) -> ProtocolId {
                ProtocolId($version.id.into())
            }

            fn listen_ports(&self) -> &'static [(&'static str, u16)] {
                &[("udp", $version.port)]
            }

            fn server_secret_specs(&self) -> Vec<ServerSecretSpec> {
                secret_specs($version)
            }

            fn server_inbound(&self, ctx: &RenderCtx<'_>, users: &[User]) -> Result<Value> {
                server_endpoint($version, ctx, users)
            }

            fn client_config(&self, ctx: &RenderCtx<'_>, user: &User) -> Result<Value> {
                client_endpoint($version, ctx, user)
            }

            fn appears_in_sing_box_sub(&self) -> bool {
                false
            }

            fn appears_in_stock_sing_box_sub(&self) -> bool {
                false
            }

            fn share_link(&self, _ctx: &RenderCtx<'_>, _user: &User) -> Result<String> {
                Err(render_error(
                    "share links are unsupported; use the ready-to-import AmneziaWG .conf download with a client supporting the specified version",
                ))
            }
        }
    };
}

impl_protocol!(AmneziaWg2, V2);
impl_protocol!(AmneziaWg3, V3);

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;

fn render_error(message: &str) -> CoreError {
    CoreError::Render(format!("AmneziaWG: {message}"))
}

fn secret_specs(version: Version) -> Vec<ServerSecretSpec> {
    let mut specs = vec![
        ServerSecretSpec::WireguardKeypair {
            private_key: version.private_key,
            public_key: version.public_key,
        },
        ServerSecretSpec::Base64Key {
            key: version.profile_seed,
            key_bytes: 32,
        },
    ];
    if version.number == 3 {
        specs.push(ServerSecretSpec::Base64Key {
            key: HEADER_KEY,
            key_bytes: 32,
        });
    }
    specs
}

fn decode_32(value: &str, nonzero: bool) -> Result<[u8; 32]> {
    if value.len() != 44 {
        return Err(render_error(
            "invalid standard-base64 material; expected exactly 32 bytes",
        ));
    }
    let bytes: [u8; 32] = STANDARD
        .decode(value)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| {
            render_error("invalid standard-base64 material; expected exactly 32 bytes")
        })?;
    if nonzero && bytes == [0; 32] {
        return Err(render_error("zero key material is not allowed"));
    }
    Ok(bytes)
}

fn parameters(
    version: Version,
    ctx: &RenderCtx<'_>,
) -> Result<Vec<(&'static str, &'static str, Value)>> {
    let seed = decode_32(ctx.require(version.profile_seed)?, true)?;
    let padding = |index: usize| 16 + seed[if version.number == 3 { 3 } else { index }] % 32;
    let mut fields = vec![
        ("jc", "Jc", json!(3 + seed[0] % 6)),
        ("jmin", "Jmin", json!(32 + u16::from(seed[1]) % 33)),
        ("jmax", "Jmax", json!(96 + u16::from(seed[2]) % 161)),
        ("s1", "S1", json!(padding(3))),
        ("s2", "S2", json!(padding(4))),
        ("s3", "S3", json!(padding(5))),
        ("s4", "S4", json!(padding(6))),
    ];
    for ((key, ini), (base, chunk)) in [("h1", "H1"), ("h2", "H2"), ("h3", "H3"), ("h4", "H4")]
        .into_iter()
        .zip(
            [1_u32, 0x4000_0001, 0x8000_0001, 0xc000_0001]
                .into_iter()
                .zip(seed[8..24].as_chunks::<4>().0),
        )
    {
        let offset = u32::from_be_bytes(*chunk) % 0x3fff_ff00;
        let start = base + offset;
        fields.push((key, ini, json!(format!("{start}-{}", start + 255))));
    }
    if version.number == 3 {
        let key = decode_32(ctx.require(HEADER_KEY)?, true)?;
        let hex: String = key.iter().map(|byte| format!("{byte:02x}")).collect();
        fields.extend([
            ("header_protection_key", "HeaderProtectionKey", json!(hex)),
            ("random_trailers", "RandomTrailers", json!(true)),
            ("disable_cookies", "DisableCookies", json!(true)),
            (
                "content_padding_addition",
                "ContentPaddingAddition",
                json!("0-32"),
            ),
        ]);
    }
    Ok(fields)
}

fn peer_host(public_key: &[u8; 32]) -> u16 {
    u16::from_be_bytes([public_key[0], public_key[1]]) % 65533 + 2
}

fn peer_cidrs(version: Version, host: u16) -> [String; 2] {
    [
        format!("10.{}.{}.{}/32", version.network, host >> 8, host & 255),
        format!("fd{}:{}::{host:x}/128", version.network, version.network),
    ]
}

fn validate_peers(users: &[User]) -> Result<()> {
    let mut ids = HashSet::new();
    let mut keys = HashSet::new();
    let mut addresses = HashSet::new();
    for user in users {
        if !ids.insert(&user.id) {
            return Err(render_error("duplicate user ID in granted peers"));
        }
        if user.disabled {
            continue;
        }
        let Some(public) = user.wireguard_pubkey.as_deref() else {
            continue;
        };
        let key = decode_32(public, true)?;
        if !keys.insert(key) {
            return Err(render_error("duplicate public key in granted peers"));
        }
        if !addresses.insert(peer_host(&key)) {
            return Err(render_error("assigned address collision in granted peers"));
        }
    }
    Ok(())
}

fn validate_host(host: &str) -> Result<()> {
    if host.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    let dns = host.strip_suffix('.').unwrap_or(host);
    let valid = !dns.is_empty()
        && dns.len() <= 253
        && !dns.bytes().all(|b| b.is_ascii_digit() || b == b'.')
        && dns.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        });
    if !valid {
        return Err(render_error(
            "invalid server host; expected an IPv4, IPv6 or hostname without controls",
        ));
    }
    Ok(())
}

fn server_endpoint(version: Version, ctx: &RenderCtx<'_>, users: &[User]) -> Result<Value> {
    let private = ctx.require(version.private_key)?;
    decode_32(private, true)?;
    decode_32(ctx.require(version.public_key)?, true)?;
    validate_peers(users)?;
    let mut peers = Vec::new();
    for user in users.iter().filter(|user| !user.disabled) {
        let Some(public) = user.wireguard_pubkey.as_deref() else {
            continue;
        };
        peers.push(json!({
            "public_key": public,
            "allowed_ips": peer_cidrs(version, peer_host(&decode_32(public, true)?)),
        }));
    }
    let mut endpoint = json!({
        "type": "wireguard",
        "tag": format!("awg{}-in", version.number),
        "system": false,
        "address": peer_cidrs(version, 1),
        "listen_port": version.port,
        "private_key": private,
        "mtu": 1280,
        "peers": peers,
    });
    for (name, _, value) in parameters(version, ctx)? {
        endpoint[name] = value;
    }
    Ok(endpoint)
}

fn client_material<'a>(
    version: Version,
    ctx: &'a RenderCtx<'_>,
    user: &'a User,
) -> Result<(&'a str, &'a str, [String; 2])> {
    if user.disabled {
        return Err(render_error(
            "disabled users cannot receive client configurations",
        ));
    }
    validate_host(&ctx.server.address)?;
    validate_peers(ctx.peers)?;
    let grant = ctx
        .peers
        .iter()
        .find(|peer| peer.id == user.id && !peer.disabled)
        .ok_or_else(|| render_error("user is not present in the enabled granted-peers list"))?;
    let public = user
        .wireguard_pubkey
        .as_deref()
        .ok_or_else(|| render_error("client is missing a public key"))?;
    let decoded = decode_32(public, true)?;
    if grant.wireguard_pubkey.as_deref() != Some(public) {
        return Err(render_error(
            "client public key does not match the granted peer",
        ));
    }
    let private = user.wireguard_private.as_deref().ok_or_else(|| {
        render_error(
            "client is missing a private key; a ready-to-import configuration requires both keys",
        )
    })?;
    decode_32(private, true)?;
    decode_32(ctx.require(version.private_key)?, true)?;
    let server_public = ctx.require(version.public_key)?;
    decode_32(server_public, true)?;
    Ok((
        private,
        server_public,
        peer_cidrs(version, peer_host(&decoded)),
    ))
}

fn client_endpoint(version: Version, ctx: &RenderCtx<'_>, user: &User) -> Result<Value> {
    let (private, server_public, address) = client_material(version, ctx, user)?;
    let mut endpoint = json!({
        "type": "wireguard",
        "tag": format!("awg{}-out", version.number),
        "system": false,
        "address": address,
        "private_key": private,
        "mtu": 1280,
        "peers": [{
            "address": ctx.server.address,
            "port": version.port,
            "public_key": server_public,
            "allowed_ips": ["0.0.0.0/0", "::/0"],
            "persistent_keepalive_interval": 25,
        }],
    });
    for (name, _, value) in parameters(version, ctx)? {
        endpoint[name] = value;
    }
    Ok(endpoint)
}

pub fn render_amnezia_conf(version: u8, ctx: &RenderCtx<'_>, user: &User) -> Result<String> {
    let version = match version {
        2 => V2,
        3 => V3,
        _ => {
            return Err(render_error(
                "unsupported version; expected 2 (2.0) or 3 (3.1)",
            ));
        }
    };
    let (private, public, addresses) = client_material(version, ctx, user)?;
    let address = addresses.join(", ");
    let label = if version.number == 2 { "2.0" } else { "3.1" };
    let mut conf = format!(
        "# AmneziaWG {label} client configuration (vpnctl).\n\
         # Requires a client supporting AmneziaWG {label}; not stock WireGuard.\n\n\
         [Interface]\nPrivateKey = {private}\nAddress = {address}\nDNS = 1.1.1.1\nMTU = 1280\n"
    );
    for (key, name, value) in parameters(version, ctx)? {
        let value = if key == "header_protection_key" {
            STANDARD.encode(decode_32(ctx.require(HEADER_KEY)?, true)?)
        } else {
            match value {
                Value::String(s) => s,
                Value::Bool(true) => "on".into(),
                Value::Bool(false) => "off".into(),
                other => other.to_string(),
            }
        };
        conf.push_str(&format!("{name} = {value}\n"));
    }
    conf.push_str(&format!(
        "\n[Peer]\nPublicKey = {public}\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = {}:{}\nPersistentKeepalive = 25\n",
        host_for_url(&ctx.server.address), version.port,
    ));
    Ok(conf)
}

pub fn awg2_share_link(ctx: &RenderCtx<'_>, user: &User) -> Result<String> {
    let (private, server_public, addresses) = client_material(V2, ctx, user)?;
    let address = addresses
        .first()
        .ok_or_else(|| render_error("missing client address"))?;
    let host = host_for_url(&ctx.server.address);
    let port = V2.port;
    let params = parameters(V2, ctx)?;
    let require_param = |k: &str| -> Result<String> {
        params
            .iter()
            .find(|(name, _, _)| name.eq_ignore_ascii_case(k))
            .map(|(_, _, v)| match v {
                Value::Number(n) => n.to_string(),
                Value::String(s) => s.clone(),
                Value::Bool(b) => b.to_string(),
                other => other.to_string(),
            })
            .filter(|s| !s.is_empty())
            .ok_or_else(|| render_error(&format!("missing required obfuscation parameter '{k}'")))
    };
    let tag = percent_encoding::utf8_percent_encode(&user.id.0, crate::encoding::FRAGMENT);
    Ok(format!(
        "awg://{server_public}@{host}:{port}?private_key={private}\
         &address={address}&keepalive=25\
         &jc={jc}&jmin={jmin}&jmax={jmax}&s1={s1}&s2={s2}&s3={s3}&s4={s4}\
         &h1={h1}&h2={h2}&h3={h3}&h4={h4}#{tag}",
        jc = require_param("jc")?,
        jmin = require_param("jmin")?,
        jmax = require_param("jmax")?,
        s1 = require_param("s1")?,
        s2 = require_param("s2")?,
        s3 = require_param("s3")?,
        s4 = require_param("s4")?,
        h1 = require_param("h1")?,
        h2 = require_param("h2")?,
        h3 = require_param("h3")?,
        h4 = require_param("h4")?,
    ))
}

pub fn awg3_share_link(ctx: &RenderCtx<'_>, user: &User) -> Result<String> {
    let (private, server_public, addresses) = client_material(V3, ctx, user)?;
    let address = addresses
        .first()
        .ok_or_else(|| render_error("missing client address"))?;
    let host = host_for_url(&ctx.server.address);
    let port = V3.port;
    let params = parameters(V3, ctx)?;
    let require_param = |k: &str| -> Result<String> {
        params
            .iter()
            .find(|(name, _, _)| name.eq_ignore_ascii_case(k))
            .map(|(_, _, v)| match v {
                Value::Number(n) => n.to_string(),
                Value::String(s) => s.clone(),
                Value::Bool(b) => b.to_string(),
                other => other.to_string(),
            })
            .filter(|s| !s.is_empty())
            .ok_or_else(|| render_error(&format!("missing required obfuscation parameter '{k}'")))
    };
    let tag = percent_encoding::utf8_percent_encode(&user.id.0, crate::encoding::FRAGMENT);
    Ok(format!(
        "awg3://{server_public}@{host}:{port}?private_key={private}\
         &address={address}&keepalive=25\
         &jc={jc}&jmin={jmin}&jmax={jmax}&s1={s1}&s2={s2}&s3={s3}&s4={s4}\
         &h1={h1}&h2={h2}&h3={h3}&h4={h4}\
         &header_protection_key={hpk}\
         &content_padding_addition={cpa}\
         &random_trailers={rt}\
         &disable_cookies={dc}#{tag}",
        jc = require_param("jc")?,
        jmin = require_param("jmin")?,
        jmax = require_param("jmax")?,
        s1 = require_param("s1")?,
        s2 = require_param("s2")?,
        s3 = require_param("s3")?,
        s4 = require_param("s4")?,
        h1 = require_param("h1")?,
        h2 = require_param("h2")?,
        h3 = require_param("h3")?,
        h4 = require_param("h4")?,
        hpk = require_param("header_protection_key")?,
        cpa = require_param("content_padding_addition")?,
        rt = require_param("random_trailers")?,
        dc = require_param("disable_cookies")?,
    ))
}
