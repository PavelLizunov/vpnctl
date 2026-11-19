use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::Sha256;
use ssh_key::{LineEnding, PrivateKey, PublicKey, private::Ed25519Keypair};
use std::net::Ipv4Addr;
use vpnctl_core::{
    CoreError, DpiRisk, Protocol, ProtocolId, RenderCtx, Result, ServerSecretSpec, User,
};

const DOMAIN: &str = "dnstt.domain";
const RESOLVER: &str = "dnstt.resolver";
const NOISE_PRIVATE: &str = "dnstt.private_key";
const NOISE_PUBLIC: &str = "dnstt.public_key";
const SSH_SEED: &str = "dnstt.ssh_seed";
const SSH_HOST_KEY: &str = "dnstt.ssh_host_key";
const APPLIED: &str = "dnstt.applied";

#[derive(Debug, Default)]
pub struct Dnstt;

fn secret<'a>(ctx: &RenderCtx<'a>, key: &str) -> Result<&'a str> {
    ctx.secrets
        .get(key)
        .map(String::as_str)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| CoreError::MissingSecret {
            server: ctx.server.id.clone(),
            key: key.to_owned(),
        })
}

fn key(ctx: &RenderCtx<'_>, name: &str) -> Result<[u8; 32]> {
    let input = secret(ctx, name)?;
    URL_SAFE_NO_PAD
        .decode(input)
        .or_else(|_| STANDARD.decode(input))
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| CoreError::Render(format!("invalid {name} key shape")))
}

fn settings<'a>(ctx: &RenderCtx<'a>) -> Result<(&'a str, Ipv4Addr)> {
    let domain = secret(ctx, DOMAIN)?;
    if domain.len() > 100
        || !domain.contains('.')
        || !domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return Err(CoreError::Render("invalid DNSTT delegated DNS name".into()));
    }
    let resolver = secret(ctx, RESOLVER)?
        .parse::<Ipv4Addr>()
        .map_err(|_| CoreError::Render("DNSTT resolver must be an IPv4 address".into()))?;
    if resolver.is_unspecified() || resolver.is_multicast() || resolver.is_broadcast() {
        return Err(CoreError::Render("invalid DNSTT resolver address".into()));
    }
    Ok((domain, resolver))
}

fn client_key(seed: &[u8; 32], user: &User) -> Result<PrivateKey> {
    let mut mac = Hmac::<Sha256>::new_from_slice(seed)
        .map_err(|_| CoreError::Render("invalid DNSTT SSH seed".into()))?;
    mac.update(b"vpnctl-dnstt-ssh-client-v1\0");
    mac.update(user.id.0.as_bytes());
    mac.update(b"\0");
    mac.update(user.uuid.as_bytes());
    Ok(PrivateKey::from(Ed25519Keypair::from_seed(
        &mac.finalize().into_bytes().into(),
    )))
}

fn host_key(seed: &[u8; 32]) -> Result<PrivateKey> {
    let mut mac = Hmac::<Sha256>::new_from_slice(seed)
        .map_err(|_| CoreError::Render("invalid DNSTT SSH seed".into()))?;
    mac.update(b"vpnctl-dnstt-ssh-host-v1");
    Ok(PrivateKey::from(Ed25519Keypair::from_seed(
        &mac.finalize().into_bytes().into(),
    )))
}

impl Protocol for Dnstt {
    fn id(&self) -> ProtocolId {
        ProtocolId("dnstt".into())
    }

    fn listen_ports(&self) -> &'static [(&'static str, u16)] {
        &[("udp", 53)]
    }

    fn appears_in_sing_box_sub(&self) -> bool {
        false
    }

    fn dpi_risk(&self) -> DpiRisk {
        DpiRisk::Weak
    }

    fn validate_server(&self, ctx: &RenderCtx<'_>) -> Result<()> {
        settings(ctx)?;
        ctx.server
            .address
            .parse::<Ipv4Addr>()
            .map_err(|_| CoreError::Render("DNSTT needs a literal IPv4 node address".into()))?;
        Ok(())
    }

    fn server_secret_specs(&self) -> Vec<ServerSecretSpec> {
        vec![
            ServerSecretSpec::X25519Keypair {
                private_key: NOISE_PRIVATE,
                public_key: NOISE_PUBLIC,
            },
            ServerSecretSpec::Base64Key {
                key: SSH_SEED,
                key_bytes: 32,
            },
        ]
    }

    fn server_inbound(&self, ctx: &RenderCtx<'_>, users: &[User]) -> Result<Value> {
        self.validate_server(ctx)?;
        let (domain, resolver) = settings(ctx)?;
        let seed = key(ctx, SSH_SEED)?;
        let host = host_key(&seed)?
            .to_openssh(LineEnding::LF)
            .map_err(|_| CoreError::Render("cannot encode DNSTT SSH host key".into()))?;
        let mut authorized = Vec::new();
        for user in users.iter().filter(|user| !user.disabled) {
            let public = client_key(&seed, user)?
                .public_key()
                .to_openssh()
                .map_err(|_| CoreError::Render("cannot encode DNSTT authorized key".into()))?;
            authorized.push(public);
        }
        Ok(
            json!({"domain":domain,"resolver":resolver,"address":ctx.server.address,
                  "noise_private":hex::encode(key(ctx, NOISE_PRIVATE)?),"ssh_host_private":host.as_str(),"authorized_keys":authorized}),
        )
    }

    fn client_config(&self, ctx: &RenderCtx<'_>, user: &User) -> Result<Value> {
        let (domain, resolver) = settings(ctx)?;
        let noise_public = secret(ctx, NOISE_PUBLIC)?;
        if user.disabled || secret(ctx, APPLIED)? != format!("{domain}+{resolver}+{noise_public}") {
            return Err(CoreError::Render(
                "DNSTT is not deployed for these settings".into(),
            ));
        }
        key(ctx, NOISE_PRIVATE)?;
        let host = PublicKey::from_openssh(secret(ctx, SSH_HOST_KEY)?)
            .map_err(|_| CoreError::Render("invalid DNSTT SSH host key".into()))?;
        if host.algorithm() != ssh_key::Algorithm::Ed25519 {
            return Err(CoreError::Render(
                "DNSTT SSH host key must be Ed25519".into(),
            ));
        }
        let client = client_key(&key(ctx, SSH_SEED)?, user)?;
        let authorized = client
            .public_key()
            .to_openssh()
            .map_err(|_| CoreError::Render("cannot encode DNSTT client public key".into()))?;
        if !secret(ctx, "dnstt.authorized_keys")?
            .lines()
            .any(|line| line.trim() == authorized)
        {
            return Err(CoreError::Render(
                "DNSTT grant has not been applied on the node".into(),
            ));
        }
        let client = client
            .to_openssh(LineEnding::LF)
            .map_err(|_| CoreError::Render("cannot encode DNSTT client SSH key".into()))?;
        Ok(
            json!({"id":ctx.server.id.0,"resolver":resolver,"port":53,"domain":domain,
                  "noise_key":hex::encode(key(ctx, NOISE_PUBLIC)?),
                  "ssh_host_key":secret(ctx, SSH_HOST_KEY)?,"ssh_private_key":client.as_str()}),
        )
    }

    fn share_link(&self, ctx: &RenderCtx<'_>, user: &User) -> Result<String> {
        let value = self.client_config(ctx, user)?;
        Ok(format!(
            "dnstt://{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&value)?)
        ))
    }
}
