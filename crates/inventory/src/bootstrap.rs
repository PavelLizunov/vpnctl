use std::collections::HashMap;

use vpnctl_core::{Registry, Server, ServerId, ServerSecretSpec};

use crate::SqliteInventory;

pub async fn bootstrap_server_secrets(
    inv: &SqliteInventory,
    server: &Server,
    registry: &Registry,
) -> Result<(HashMap<String, String>, Vec<&'static str>), String> {
    let mut secrets = inv
        .list_server_secrets(&server.id)
        .await
        .map_err(|e| format!("list_server_secrets: {e}"))?;
    let mut minted: Vec<&'static str> = Vec::new();

    for pid in &server.enabled_protocols {
        let Some(proto) = registry.protocol(pid) else {
            continue;
        };
        for spec in proto
            .server_secret_specs_for(&secrets)
            .map_err(|e| format!("server_secret_specs {pid}: {e}"))?
        {
            mint_secret_spec(inv, &server.id, spec, &mut secrets, &mut minted).await?;
        }
    }

    let needs_amnezia_obfs = server.kernels.iter().any(|k| k.0 == "amneziawg");
    let effective_obfs: Vec<_> = vpnctl_core::amneziawg::effective_params(&secrets)
        .into_iter()
        .map(|(key, value)| {
            (
                format!("amneziawg.{}", key.to_ascii_lowercase()),
                value.to_string(),
            )
        })
        .collect();
    let has_obfs = effective_obfs
        .iter()
        .any(|(key, _)| secrets.contains_key(key));
    if needs_amnezia_obfs && !has_obfs {
        let o = vpnctl_crypto::gen_amnezia_obfs().map_err(|e| format!("gen_amnezia_obfs: {e}"))?;
        let candidates: Vec<_> = [
            ("amneziawg.jc", o.jc),
            ("amneziawg.jmin", o.jmin),
            ("amneziawg.jmax", o.jmax),
            ("amneziawg.s1", o.s1),
            ("amneziawg.s2", o.s2),
            ("amneziawg.h1", o.h1),
            ("amneziawg.h2", o.h2),
            ("amneziawg.h3", o.h3),
            ("amneziawg.h4", o.h4),
        ]
        .into_iter()
        .map(|(key, value)| (key, value.to_string()))
        .collect();
        let (stored, did_mint) = inv
            .initialize_server_secret_set(&server.id, &candidates)
            .await
            .map_err(|e| format!("initialize amneziawg obfs params: {e}"))?;
        secrets.extend(stored);
        if did_mint {
            minted.push("amneziawg obfs params");
        }
    } else if needs_amnezia_obfs {
        let mut did_mint_any = false;
        for (key, value) in effective_obfs {
            if secrets.contains_key(&key) {
                continue;
            }
            let (stored, did_mint) = inv
                .initialize_server_secret_set(&server.id, &[(key.as_str(), value)])
                .await
                .map_err(|e| format!("initialize {key}: {e}"))?;
            secrets.extend(stored);
            did_mint_any |= did_mint;
        }
        if did_mint_any {
            minted.push("amneziawg obfs params");
        }
    }

    Ok((secrets, minted))
}

async fn persist_secret(
    inv: &SqliteInventory,
    server_id: &ServerId,
    key: &'static str,
    value: String,
    secrets: &mut HashMap<String, String>,
) -> Result<(), String> {
    inv.set_server_secret(server_id, key, &value)
        .await
        .map_err(|e| format!("set_server_secret {key}: {e}"))?;
    secrets.insert(key.to_string(), value);
    Ok(())
}

async fn mint_secret_spec(
    inv: &SqliteInventory,
    server_id: &ServerId,
    spec: ServerSecretSpec,
    secrets: &mut HashMap<String, String>,
    minted: &mut Vec<&'static str>,
) -> Result<(), String> {
    use ServerSecretSpec as S;
    match spec {
        S::Password { key, entropy_bytes } => {
            if !secrets.contains_key(key) {
                let v = vpnctl_crypto::gen_password(entropy_bytes)
                    .map_err(|e| format!("gen_password {key}: {e}"))?;
                persist_secret(inv, server_id, key, v, secrets).await?;
                minted.push(key);
            }
        }
        S::Base64Key { key, key_bytes } => {
            if !secrets.contains_key(key) {
                let v = vpnctl_crypto::gen_base64_key(key_bytes)
                    .map_err(|e| format!("gen_base64_key {key}: {e}"))?;
                let (stored, did_mint) = inv
                    .initialize_server_secret_set(server_id, &[(key, v)])
                    .await
                    .map_err(|e| format!("initialize_server_secret {key}: {e}"))?;
                secrets.extend(stored);
                if did_mint {
                    minted.push(key);
                }
            }
        }
        S::X25519Keypair {
            private_key,
            public_key,
        } => {
            if !secrets.contains_key(private_key) || !secrets.contains_key(public_key) {
                let (priv_k, pub_k) = vpnctl_crypto::gen_x25519_keypair();
                persist_secret(inv, server_id, private_key, priv_k, secrets).await?;
                persist_secret(inv, server_id, public_key, pub_k, secrets).await?;
                minted.push(private_key);
            }
        }
        S::WireguardKeypair {
            private_key,
            public_key,
        } => {
            if !secrets.contains_key(private_key) || !secrets.contains_key(public_key) {
                let (priv_k, pub_k) = vpnctl_crypto::gen_wireguard_keypair();
                let (stored, did_mint) = inv
                    .initialize_server_secret_set(
                        server_id,
                        &[(private_key, priv_k), (public_key, pub_k)],
                    )
                    .await
                    .map_err(|e| format!("initialize_server_secret {private_key}: {e}"))?;
                secrets.extend(stored);
                if did_mint {
                    minted.push(private_key);
                }
            }
        }
        S::ShortId { key } => {
            if !secrets.contains_key(key) {
                let v = vpnctl_crypto::gen_short_id()
                    .map_err(|e| format!("gen_short_id {key}: {e}"))?;
                persist_secret(inv, server_id, key, v, secrets).await?;
                minted.push(key);
            }
        }
    }
    Ok(())
}
