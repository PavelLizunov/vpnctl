//! Synthetic AWG integration fixture, using the same public renderers as delivery.
//!
//! Run the already-built example with no arguments. Stdout contains only a JSON
//! manifest naming a new 0700 temporary directory; its four artifacts are 0600.
//! The caller owns/removes that directory after probing both versions. No live
//! inventory is read. Keys below are PUBLIC RFC 7748 section 6.1 test vectors,
//! not credentials: these fixtures must never be deployed or exposed to a network.

use std::collections::HashMap;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use vpnctl_core::{
    Kernel, KernelId, Protocol, ProtocolId, RenderCtx, Server, ServerId, User, UserId,
};
use vpnctl_kernels::SingBox;
use vpnctl_protocols::{AmneziaWg2, AmneziaWg3, render_amnezia_conf};

// Alice = server, Bob = client; matching X25519 pairs from the public RFC.
const SERVER_PRIVATE: &str = "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo=";
const SERVER_PUBLIC: &str = "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=";
const CLIENT_PRIVATE: &str = "XasIfmJKikt54X+Lg4AO5m87sSkmGLb9HC+LJ/+I4Os=";
const CLIENT_PUBLIC: &str = "3p7bfXt9wbTTW2HC7OQ1Nz+DQ8hbeGdNrfx+FG+IK08=";

fn temporary_directory() -> io::Result<PathBuf> {
    // Atomic creation (never reuse/follow an existing path), mode set at creation.
    // Predictability is harmless: collisions are skipped, never opened.
    for attempt in 0..1000 {
        let path = std::env::temp_dir().join(format!(
            "vpnctl-awg-rendered-{}-{attempt}",
            std::process::id()
        ));
        match DirBuilder::new().mode(0o700).create(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::other("temporary directory unavailable"))
}

fn private_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

fn render(directory: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let user = User {
        id: UserId("synthetic-awg-peer".into()),
        uuid: "00000000-0000-4000-8000-000000000001".into(),
        tuic_password: None,
        wireguard_pubkey: Some(CLIENT_PUBLIC.into()),
        wireguard_private: Some(CLIENT_PRIVATE.into()),
        sub_token: None,
        vpn_router_device_id: None,
        disabled: false,
    };
    let peers = [user];
    for version in [2, 3] {
        let id = format!("amneziawg{version}");
        let server = Server {
            id: ServerId("synthetic-awg-node".into()),
            address: "198.18.0.1".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: vec![ProtocolId(id.clone())],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        };
        let mut secrets = HashMap::from([
            (format!("{id}.server_private_key"), SERVER_PRIVATE.into()),
            (format!("{id}.server_public_key"), SERVER_PUBLIC.into()),
            // Public nonzero vectors also supply reproducible profile material.
            (format!("{id}.profile_seed"), CLIENT_PUBLIC.into()),
        ]);
        if version == 3 {
            secrets.insert(
                "amneziawg3.header_protection_key".into(),
                SERVER_PUBLIC.into(),
            );
        }
        let protocol: Box<dyn Protocol> = if version == 2 {
            Box::new(AmneziaWg2::new())
        } else {
            Box::new(AmneziaWg3::new())
        };
        let ctx = RenderCtx::with_peers(&server, &secrets, &peers);
        // No hand-built endpoint, port substitution, or changes to route guards.
        let server_json = SingBox::new().render_config(&ctx, &peers, &[protocol.as_ref()])?;
        let native_conf = render_amnezia_conf(version, &ctx, &peers[0])?;
        private_file(
            &directory.join(format!("awg{version}.server.json")),
            &server_json,
        )?;
        private_file(
            &directory.join(format!("awg{version}.conf")),
            native_conf.as_bytes(),
        )?;
    }
    Ok(())
}

fn main() -> ExitCode {
    if std::env::args_os().len() != 1 {
        println!("{{\"kind\":\"fixture\",\"pass\":false,\"failure\":\"arguments\"}}");
        return ExitCode::FAILURE;
    }
    let result = temporary_directory().and_then(|directory| {
        if render(&directory).is_err() {
            let _ = fs::remove_dir_all(&directory);
            return Err(io::Error::other("fixture render failed"));
        }
        Ok(directory)
    });
    match result {
        Ok(directory) => {
            println!(
                "{}",
                serde_json::json!({
                    "kind": "fixture", "pass": true, "directory": directory,
                    "versions": [2, 3], "synthetic_only": true,
                })
            );
            ExitCode::SUCCESS
        }
        Err(_) => {
            // Renderer and IO errors may contain material or paths; never print them.
            println!("{{\"kind\":\"fixture\",\"pass\":false,\"failure\":\"fixture_failed\"}}");
            ExitCode::FAILURE
        }
    }
}
