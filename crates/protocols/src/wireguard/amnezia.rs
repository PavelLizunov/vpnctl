use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use percent_encoding::utf8_percent_encode;
use serde_json::json;
use vpnctl_core::url_host::host_for_url;
use vpnctl_core::{CoreError, RenderCtx, Result, User};

use super::helpers::{
    CLIENT_PRIVKEY_PLACEHOLDER, FRAGMENT, is_valid_wg_pubkey, listen_port, peer_octet_for,
};
use super::render::render_client_conf;

pub(crate) fn amneziawg_block(ctx: &RenderCtx<'_>) -> Option<serde_json::Value> {
    let keys = [
        "amneziawg.jc",
        "amneziawg.jmin",
        "amneziawg.jmax",
        "amneziawg.s1",
        "amneziawg.s2",
        "amneziawg.h1",
        "amneziawg.h2",
        "amneziawg.h3",
        "amneziawg.h4",
    ];
    for k in &keys {
        ctx.secrets.get(*k)?;
    }
    Some(json!({
        "jc":   ctx.secrets.get("amneziawg.jc"),
        "jmin": ctx.secrets.get("amneziawg.jmin"),
        "jmax": ctx.secrets.get("amneziawg.jmax"),
        "s1":   ctx.secrets.get("amneziawg.s1"),
        "s2":   ctx.secrets.get("amneziawg.s2"),
        "h1":   ctx.secrets.get("amneziawg.h1"),
        "h2":   ctx.secrets.get("amneziawg.h2"),
        "h3":   ctx.secrets.get("amneziawg.h3"),
        "h4":   ctx.secrets.get("amneziawg.h4"),
    }))
}

pub fn amnezia_share_link(ctx: &RenderCtx<'_>, user: &User) -> Result<String> {
    let user_pub = user.wireguard_pubkey.as_deref().ok_or_else(|| {
        CoreError::Render(format!(
            "user '{}' has no wireguard_pubkey — cannot mint an AmneziaVPN link",
            user.id.0
        ))
    })?;
    if !is_valid_wg_pubkey(user_pub) {
        return Err(CoreError::Render(format!(
            "user '{}' has malformed wireguard pubkey: {user_pub:?}",
            user.id.0
        )));
    }
    let server_pub = ctx.require("wireguard.server_public_key")?;
    let listen_port: u16 = listen_port(ctx.secrets);
    let peer_octet = peer_octet_for(ctx, user)?;
    let client_ip = format!("10.66.0.{peer_octet}");

    let nat_conf = render_client_conf(ctx, user)?;
    let mut last_config = serde_json::Map::new();
    last_config.insert("config".into(), json!(nat_conf));
    last_config.insert("hostName".into(), json!(ctx.server.address));
    last_config.insert("port".into(), json!(listen_port));
    last_config.insert("client_ip".into(), json!(client_ip));
    last_config.insert(
        "client_priv_key".into(),
        json!(
            user.wireguard_private
                .as_deref()
                .unwrap_or(CLIENT_PRIVKEY_PLACEHOLDER)
        ),
    );
    last_config.insert("client_pub_key".into(), json!(user_pub));
    last_config.insert("server_pub_key".into(), json!(server_pub));
    last_config.insert(
        "allowed_ips".into(),
        json!(["0.0.0.0/0".to_string(), "::/0".to_string()]),
    );
    last_config.insert("persistent_keep_alive".into(), json!("25"));

    let wireguard_obj = json!({
        "port": listen_port.to_string(),
        "transport_proto": "udp",
        "subnet_address": "10.66.0.0",
        "last_config": serde_json::to_string(&serde_json::Value::Object(last_config))
            .map_err(|e| CoreError::Render(format!("amnezia last_config serialise: {e}")))?,
    });

    let top = json!({
        "containers": [
            {
                "container": "amnezia-wireguard",
                "wireguard": wireguard_obj,
            }
        ],
        "defaultContainer": "amnezia-wireguard",
        "description": user.id.0,
        "dns1": "1.1.1.1",
        "dns2": "1.0.0.1",
        "hostName": ctx.server.address,
    });

    let json_bytes = serde_json::to_vec(&top)
        .map_err(|e| CoreError::Render(format!("amnezia top JSON serialise: {e}")))?;
    let compressed = qcompress_zlib(&json_bytes)?;
    let b64 = URL_SAFE_NO_PAD.encode(&compressed);
    Ok(format!("vpn://{b64}"))
}

pub(crate) fn qcompress_zlib(data: &[u8]) -> Result<Vec<u8>> {
    use flate2::Compression;
    use flate2::write::ZlibEncoder;
    use std::io::Write;

    let len = u32::try_from(data.len())
        .map_err(|_| CoreError::Render("amnezia payload >4 GiB — refuse to compress".into()))?;
    let mut out = Vec::with_capacity(data.len() / 4 + 16);
    out.extend_from_slice(&len.to_be_bytes());
    let mut enc = ZlibEncoder::new(&mut out, Compression::new(8));
    enc.write_all(data)
        .map_err(|e| CoreError::Render(format!("amnezia zlib write: {e}")))?;
    enc.finish()
        .map_err(|e| CoreError::Render(format!("amnezia zlib finish: {e}")))?;
    Ok(out)
}

pub fn awg_share_link(ctx: &RenderCtx<'_>, user: &User) -> Result<String> {
    let server_pub = ctx.require("wireguard.server_public_key")?;
    let client_priv = user.wireguard_private.as_deref().ok_or_else(|| {
        CoreError::Render(format!(
            "user '{}' has no server-generated wireguard private key — \
             an awg:// link can't be one-tap without it (use --gen-wireguard)",
            user.id.0
        ))
    })?;
    let user_pub = user.wireguard_pubkey.as_deref().ok_or_else(|| {
        CoreError::Render(format!(
            "user '{}' has wireguard_private but no wireguard_pubkey — \
             the server [Peer] block can't authenticate this client",
            user.id.0
        ))
    })?;
    if !is_valid_wg_pubkey(user_pub) {
        return Err(CoreError::Render(format!(
            "user '{}' has malformed wireguard pubkey: {user_pub:?}",
            user.id.0
        )));
    }
    let listen_port: u16 = listen_port(ctx.secrets);
    let peer_octet = peer_octet_for(ctx, user)?;
    let address = format!("10.66.0.{peer_octet}/32");

    let obfs = amneziawg_block(ctx).ok_or_else(|| {
        CoreError::Render(
            "server has no AmneziaWG obfuscation params minted — \
             an awg:// link requires them (deploy the amneziawg kernel so \
             bootstrap mints amneziawg.{jc,jmin,jmax,s1,s2,h1-h4})"
                .into(),
        )
    })?;
    let m = obfs
        .as_object()
        .ok_or_else(|| CoreError::Render("amneziawg block must be a JSON object".into()))?;
    let g = |k: &str| -> &str { m.get(k).and_then(|v| v.as_str()).unwrap_or("0") };

    let host = host_for_url(&ctx.server.address);
    let tag = utf8_percent_encode(&user.id.0, FRAGMENT);
    Ok(format!(
        "awg://{server_pub}@{host}:{listen_port}?private_key={client_priv}\
         &address={address}&keepalive=25\
         &jc={jc}&jmin={jmin}&jmax={jmax}&s1={s1}&s2={s2}&s3=0&s4=0\
         &h1={h1}&h2={h2}&h3={h3}&h4={h4}#{tag}",
        jc = g("jc"),
        jmin = g("jmin"),
        jmax = g("jmax"),
        s1 = g("s1"),
        s2 = g("s2"),
        h1 = g("h1"),
        h2 = g("h2"),
        h3 = g("h3"),
        h4 = g("h4"),
    ))
}
