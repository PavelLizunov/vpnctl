//! Declarative per-server secret bootstrap — the single source of truth
//! for minting the server-side secrets each enabled protocol needs to
//! render its config (REALITY keypair + short_id, WireGuard server
//! keypair, Hysteria2 obfs password, Shadowsocks-2022 PSK, …).
//!
//! Shared by BOTH deploy surfaces so they can never drift:
//!   * the daemon's wizard / web `Deploy` button
//!     (`daemon/src/wizard_bootstrap.rs`, `handlers/admin.rs`);
//!   * the CLI `vpnctl deploy` (`cli/src/cmd/deploy.rs`).
//!
//! Lived in the daemon crate until 2026-06-04; the CLI couldn't reach it
//! and hand-rolled its own vless/wireguard/tuic minting that silently
//! omitted `ss2022.psk` (hard render failure for shadowsocks-2022) and
//! `hysteria2.obfs.password` (silent Salamander-obfs degradation). Moved
//! here — the lowest crate both deploy paths already depend on — so the
//! declarative `Protocol::server_secret_specs()` walk is the ONE minter.

use std::collections::HashMap;

use vpnctl_core::{Registry, Server, ServerId, ServerSecretSpec};

use crate::SqliteInventory;

/// Mint the per-protocol server-side secrets a Server needs to render
/// configs. Idempotent: only mints what's missing from
/// `inv.list_server_secrets`, so re-running against a partially-
/// bootstrapped server picks up where the last run left off and NEVER
/// rotates a secret out from under live clients.
///
/// Returns the full (existing + freshly minted) secret map plus a list
/// of human-readable "what we minted" labels the caller can surface in
/// progress logs / audit payload.
///
/// # Orthogonal secret minting
///
/// Each `Protocol` declares the server-side secrets it needs via
/// `Protocol::server_secret_specs()`; this function iterates the server's
/// enabled protocols, resolves each through `registry`, and mints +
/// persists any declared key that's absent. Adding a secret-bearing
/// protocol is a one-line spec in its own file — ZERO edits here (the
/// kernel/protocol orthogonality invariant).
///
/// Replaces the previous per-surface hardcoded vless/wireguard/hysteria2
/// blocks, which silently omitted `shadowsocks-2022`'s `ss2022.psk` (and
/// any future protocol's secret) → the `kg` deploy 2026-05-30 failed at
/// render with `MissingSecret { key: "ss2022.psk" }`. The amneziawg KERNEL
/// secret stays below the loop — it's keyed on `server.kernels`, not
/// `enabled_protocols`.
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

    // Protocol-declared server secrets (REALITY keypair + short_id,
    // Hysteria2 obfs password, Shadowsocks-2022 PSK, WireGuard server
    // keypair). Driven by each Protocol's `server_secret_specs()`, so a
    // new secret-bearing protocol needs zero edits here.
    for pid in &server.enabled_protocols {
        let Some(proto) = registry.protocol(pid) else {
            // Unknown id in inventory — `validate_server` rejects genuine
            // misconfig before deploy; skip defensively.
            continue;
        };
        for spec in proto.server_secret_specs() {
            mint_secret_spec(inv, &server.id, spec, &mut secrets, &mut minted).await?;
        }
    }


    // AmneziaWG obfuscation params — per-server, keyed on the `amneziawg`
    // KERNEL (not the wireguard PROTOCOL): obfs is a property of the
    // AmneziaWG daemon. A future vanilla wg-quick kernel serving the same
    // `wireguard` protocol must NOT get obfs — it can't speak it, the
    // handshake would fail. Minted as a COHERENT 9-param set (the
    // bidirectional s1/s2/h1-h4 must stay internally consistent + reach
    // the client artefact identically) — anchor on `amneziawg.h1`: absent
    // ⇒ never minted ⇒ generate all 9; present ⇒ leave intact (idempotent,
    // never rotate live clients). Closes the standing backlog bug: the
    // kernel's hardcoded H1=1..H4=4 default otherwise bakes ONE DPI
    // fingerprint into every vpnctl-deployed AmneziaWG node.
    let needs_amnezia_obfs = server.kernels.iter().any(|k| k.0 == "amneziawg");
    if needs_amnezia_obfs && !secrets.contains_key("amneziawg.h1") {
        let o = vpnctl_crypto::gen_amnezia_obfs().map_err(|e| format!("gen_amnezia_obfs: {e}"))?;
        for (k, val) in [
            ("amneziawg.jc", o.jc),
            ("amneziawg.jmin", o.jmin),
            ("amneziawg.jmax", o.jmax),
            ("amneziawg.s1", o.s1),
            ("amneziawg.s2", o.s2),
            ("amneziawg.h1", o.h1),
            ("amneziawg.h2", o.h2),
            ("amneziawg.h3", o.h3),
            ("amneziawg.h4", o.h4),
        ] {
            let v = val.to_string();
            inv.set_server_secret(&server.id, k, &v)
                .await
                .map_err(|e| format!("set_server_secret {k}: {e}"))?;
            secrets.insert(k.to_string(), v);
        }
        minted.push("amneziawg obfs params");
    }

    Ok((secrets, minted))
}

/// Persist one secret to inventory + the in-memory map. Helper for
/// [`mint_secret_spec`]; takes the value by-value to avoid a clone.
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

/// Mint one [`ServerSecretSpec`] if its key(s) are absent: generate via
/// the matching crypto primitive, persist, and record the primary key
/// name in `minted`. Idempotent — a present key is skipped, never rotated
/// (protects live clients on re-deploy). Each match arm uses the SAME
/// crypto primitive the old hardcoded blocks did, so the byte-shape of
/// every generated secret is unchanged.
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
                persist_secret(inv, server_id, key, v, secrets).await?;
                minted.push(key);
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
                persist_secret(inv, server_id, private_key, priv_k, secrets).await?;
                persist_secret(inv, server_id, public_key, pub_k, secrets).await?;
                minted.push(private_key);
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
