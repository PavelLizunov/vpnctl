//! AmneziaWG — WireGuard kernel module fork with anti-DPI obfuscation.
//!
//! AmneziaWG IS WireGuard at the wire level — same Noise IK handshake,
//! same UDP transport, same chacha20-poly1305 — with extra
//! parameters in the `[Interface]` block (Jc/Jmin/Jmax/S1/S2/H1-H4)
//! that pad packets and mask handshake structure so DPI can't
//! fingerprint the protocol.
//!
//! # Why a separate Kernel
//!
//! The wire format is WireGuard, so the **Protocol** is `WireGuard`
//! (one impl, shared between this kernel and a future
//! `WireGuardKernel` for vanilla wg-quick). What differs is the
//! daemon: AmneziaWG ships its own apt packages (`amneziawg`,
//! `amneziawg-tools`) with the `awg` / `awg-quick` binaries replacing
//! `wg` / `wg-quick`. Different daemon = different Kernel.
//!
//! # Trait-impedance fix (see crates/protocols/src/wireguard.rs)
//!
//! sing-box's Kernel renders JSON. AmneziaWG renders INI. The
//! `Protocol::server_inbound` returns a STABLE ENVELOPE (JSON
//! describing the data, not the final config); this kernel
//! deserialises that envelope into a typed struct, then assembles
//! INI itself plus the obfuscation block from `RenderCtx::secrets`.
//!
//! # Obfuscation params
//!
//! Read from `RenderCtx::secrets["amneziawg.{jc,jmin,jmax,s1,s2,h1,h2,h3,h4}"]`.
//! See `DEFAULT_AMNEZIA_PARAMS` for fallbacks. Bootstrap should
//! generate random H1-H4 per server (otherwise every vpnctl deploy
//! has identical magic constants) — that's a separate commit; the
//! defaults here exist so unit tests don't need RNG.
//!
//! # Versions
//!
//! Tested against `amneziawg-tools` from the AmneziaVPN PPA. DKMS
//! kernel module — broken if the operator skips
//! `linux-headers-$(uname -r)`. `ensure_installed` installs them.

use async_trait::async_trait;
use serde::Deserialize;
use vpnctl_core::{
    CoreError, Kernel, KernelId, KernelStatus, Protocol, ProtocolId, RenderCtx, Result,
    SshTransport, User,
};

#[derive(Debug, Default)]
pub struct AmneziaWg;

impl AmneziaWg {
    pub fn new() -> Self {
        Self
    }
}

/// Default AmneziaWG obfuscation parameters. **H1-H4 should be
/// randomized per server at bootstrap time** — these literal
/// defaults exist so render tests don't need RNG and so a
/// half-provisioned node still produces a syntactically-valid
/// config. Production nodes MUST override via secrets to avoid
/// fingerprinting all vpnctl-deployed servers identically.
const DEFAULT_AMNEZIA_PARAMS: &[(&str, &str)] = &[
    ("Jc", "4"),
    ("Jmin", "40"),
    ("Jmax", "70"),
    ("S1", "50"),
    ("S2", "100"),
    ("H1", "1"),
    ("H2", "2"),
    ("H3", "3"),
    ("H4", "4"),
];

/// JSON envelope returned by `WireGuard::server_inbound`. We
/// deserialize into this typed struct then walk fields to assemble
/// INI. Keeping the struct private to the kernel: the contract is
/// "consume the protocol's envelope shape", not "expose internal
/// schema".
#[derive(Debug, Deserialize)]
struct WireGuardEnvelope {
    listen_port: u16,
    private_key: String,
    address_cidr: String,
    peers: Vec<EnvelopePeer>,
}

#[derive(Debug, Deserialize)]
struct EnvelopePeer {
    name: String,
    public_key: String,
    allowed_ips: String,
}

#[async_trait]
impl Kernel for AmneziaWg {
    fn id(&self) -> KernelId {
        KernelId("amneziawg".to_string())
    }

    fn supported_protocols(&self) -> Vec<ProtocolId> {
        vec![ProtocolId("wireguard".to_string())]
    }

    async fn ensure_installed(&self, ssh: &dyn SshTransport) -> Result<()> {
        // Same lessons as sing_box::ensure_installed (CLAUDE.md
        // staging-deploy table): pre-install curl/gpg/ca-certificates,
        // pre-create dirs, final assertion via `command -v`.
        //
        // AmneziaWG specifics:
        //   * DKMS kernel module needs `linux-headers-$(uname -r)`,
        //     otherwise the package post-install silently leaves the
        //     module unbuilt and `awg-quick up` fails at runtime.
        //   * The PPA is hosted on Launchpad (Ubuntu PPA format),
        //     which works on Debian via `signed-by=` entries.
        //   * `apt-key` is deprecated; we install the keyring file
        //     directly.
        //
        // GPG fingerprint pinning: the AmneziaVPN PPA's signing key
        // fingerprint is fetched from keyserver.ubuntu.com on first
        // install. TODO(Pavel): confirm fingerprint after first
        // staging deploy and pin verbatim here so a compromised
        // keyserver can't substitute a hostile signer.
        let script = r#"
            set -eu
            export DEBIAN_FRONTEND=noninteractive
            if ! command -v awg-quick >/dev/null; then
                apt-get update -qq
                apt-get install -y --no-install-recommends \
                    curl gpg ca-certificates iptables \
                    software-properties-common \
                    "linux-headers-$(uname -r)"
                # Install Launchpad signing key. add-apt-repository would
                # do this for us but pulls Python; manual is leaner.
                install -d -m 0755 /usr/share/keyrings
                curl -fsSL "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x57290828bb0a2320821bb9b2d101bb74cb98a1d0" \
                    | gpg --dearmor -o /usr/share/keyrings/amnezia.gpg
                echo "deb [signed-by=/usr/share/keyrings/amnezia.gpg] https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu focal main" \
                    > /etc/apt/sources.list.d/amnezia.list
                apt-get update -qq
                apt-get install -y amneziawg amneziawg-tools
            fi
            install -d -m 0700 /etc/amnezia/amneziawg
            systemctl daemon-reload >/dev/null
            command -v awg-quick
            command -v awg
            test -d /etc/amnezia/amneziawg
        "#;
        ssh.exec(script).await?;
        Ok(())
    }

    fn render_config(
        &self,
        ctx: &RenderCtx<'_>,
        users: &[User],
        protocols: &[&dyn Protocol],
    ) -> Result<Vec<u8>> {
        // Locate the WireGuard protocol — we cannot serve anything
        // else. Fail loud if a misconfigured server has the wrong
        // protocol declared (Registry::validate_server should have
        // caught this earlier; this is the defense-in-depth layer).
        let wg_proto = protocols
            .iter()
            .find(|p| p.id() == ProtocolId("wireguard".to_string()))
            .ok_or_else(|| {
                CoreError::Render(
                    "amneziawg kernel requires the wireguard protocol in `protocols`".into(),
                )
            })?;

        // Pull envelope from the Protocol. JSON shape is documented
        // in crates/protocols/src/wireguard.rs's module header.
        let envelope_json = wg_proto.server_inbound(ctx, users)?;
        let env: WireGuardEnvelope = serde_json::from_value(envelope_json)
            .map_err(|e| CoreError::Render(format!("wireguard envelope parse: {e}")))?;

        // Assemble INI. LF newlines, 0600-target permissions
        // (enforced by `apply_config`'s chmod), warning header so a
        // future maintainer doesn't hand-edit and lose changes.
        let mut out = String::with_capacity(1024);
        out.push_str("# Rendered by vpnctl. Do not hand-edit \u{2014} your changes will be\n");
        out.push_str("# overwritten on next `vpnctl deploy`.\n");
        out.push_str("[Interface]\n");
        out.push_str(&format!("PrivateKey = {}\n", env.private_key));
        out.push_str(&format!("ListenPort = {}\n", env.listen_port));
        out.push_str(&format!("Address = {}\n", env.address_cidr));

        // AmneziaWG obfuscation params — read from secrets (each can
        // be overridden) with the documented defaults.
        for (ini_key, default) in DEFAULT_AMNEZIA_PARAMS {
            // Map INI key (uppercase) → secret key (lowercase).
            // e.g. "Jc" → "amneziawg.jc"
            let secret_key = format!("amneziawg.{}", ini_key.to_ascii_lowercase());
            let value = ctx.or_default(&secret_key, default);
            out.push_str(&format!("{ini_key} = {value}\n"));
        }

        // PostUp / PostDown for NAT'ing outbound traffic. Idempotent
        // would be `iptables -C ... || iptables -A ...` but
        // wg-quick's PostUp runs once on `up`, so plain `-A` is fine
        // and `PostDown` cleans up.
        out.push_str(
            "PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE\n",
        );
        out.push_str(
            "PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE\n",
        );

        // [Peer] blocks — one per envelope peer. Skip-with-comment
        // approach so the config-render-time order is stable AND
        // operators looking at the conf file can spot a missing
        // peer entry attributable to a missing pubkey.
        for peer in &env.peers {
            out.push('\n');
            out.push_str("[Peer]\n");
            out.push_str(&format!("# user: {}\n", peer.name));
            out.push_str(&format!("PublicKey = {}\n", peer.public_key));
            out.push_str(&format!("AllowedIPs = {}\n", peer.allowed_ips));
        }

        Ok(out.into_bytes())
    }

    async fn apply_config(&self, ssh: &dyn SshTransport, config: &[u8]) -> Result<()> {
        ssh.upload("/etc/amnezia/amneziawg/awg0.conf.new", config)
            .await?;
        // Validate via `awg-quick strip` (exits non-zero on parse error
        // and prints a useful error). Atomic-rename. Lock perms.
        // Restart + verify-active poll, exact same pattern as sing-box's
        // apply_config (CLAUDE.md staging-deploy lesson #3).
        let cmd = r#"
            set -eu
            awg-quick strip /etc/amnezia/amneziawg/awg0.conf.new > /dev/null
            mv /etc/amnezia/amneziawg/awg0.conf.new /etc/amnezia/amneziawg/awg0.conf
            chown root:root /etc/amnezia/amneziawg/awg0.conf
            chmod 0600 /etc/amnezia/amneziawg/awg0.conf

            systemctl enable awg-quick@awg0 >/dev/null 2>&1 || true
            systemctl reload-or-restart awg-quick@awg0

            # Wait up to 8 seconds for the service to settle. systemd's
            # auto-restart back-off kicks in every 10s, so 8s is past
            # the first attempt — not "active" by then = crash loop.
            for i in 1 2 3 4 5 6 7 8; do
                state=$(systemctl is-active awg-quick@awg0 || true)
                [ "$state" = "active" ] && exit 0
                sleep 1
            done

            echo "awg-quick@awg0 did not become active. Last 20 log lines:" >&2
            journalctl -u awg-quick@awg0 --no-pager -n 20 >&2 || true
            echo "--- attempted config (post-strip) ---" >&2
            awg-quick strip /etc/amnezia/amneziawg/awg0.conf >&2 || true
            exit 1
        "#;
        ssh.exec(cmd).await?;
        Ok(())
    }

    async fn restart(&self, ssh: &dyn SshTransport) -> Result<()> {
        ssh.exec("systemctl restart awg-quick@awg0").await?;
        Ok(())
    }

    async fn status(&self, ssh: &dyn SshTransport) -> Result<KernelStatus> {
        let active = ssh
            .exec("systemctl is-active awg-quick@awg0")
            .await?
            .trim()
            .eq("active");
        // `awg --version` outputs a single line like
        // "wireguard-tools v1.0.20210914-amneziawg-... - userspace go ..."
        let version = ssh.exec("awg --version 2>&1 | head -1").await.ok();
        Ok(KernelStatus {
            active,
            version,
            uptime_seconds: None,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use vpnctl_core::{Server, ServerId, UserId};
    use vpnctl_protocols::WireGuard;

    fn dummy_server() -> Server {
        Server {
            id: ServerId("awg-node-1".into()),
            address: "203.0.113.7".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernel: KernelId("amneziawg".into()),
            enabled_protocols: vec![ProtocolId("wireguard".into())],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        }
    }

    fn user_with_pubkey(name: &str, pubkey: Option<&str>) -> User {
        User {
            id: UserId(name.into()),
            uuid: format!("uuid-{name}"),
            tuic_password: None,
            wireguard_pubkey: pubkey.map(str::to_string),
            sub_token: None,
        }
    }

    /// Sample valid base64 WG pubkey shape (44 chars, ends '=').
    const PUBKEY_A: &str = "qXFvJL5KLmM3Of9hVo5GmJ4n0LB9rWYfV4ZE1XGZJks=";
    const PUBKEY_B: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAaaa=";

    fn server_secrets() -> HashMap<String, String> {
        let mut s = HashMap::new();
        s.insert(
            "wireguard.server_private_key".into(),
            "AAABBBCCCDDDEEEFFFGGGHHHIIIJJJKKKLLLMMMNNNn=".into(),
        );
        s
    }

    #[test]
    fn id_returns_amneziawg() {
        assert_eq!(AmneziaWg::new().id(), KernelId("amneziawg".into()));
    }

    #[test]
    fn supported_protocols_only_wireguard() {
        assert_eq!(
            AmneziaWg::new().supported_protocols(),
            vec![ProtocolId("wireguard".into())]
        );
    }

    #[test]
    fn render_config_missing_protocol_returns_render_error() {
        let s = dummy_server();
        let secrets = server_secrets();
        let ctx = RenderCtx::new(&s, &secrets);
        let err = AmneziaWg::new().render_config(&ctx, &[], &[]).unwrap_err();
        match err {
            CoreError::Render(msg) => {
                assert!(
                    msg.contains("wireguard"),
                    "msg should mention wireguard: {msg}"
                );
            }
            other => panic!("expected Render error, got {other:?}"),
        }
    }

    #[test]
    fn render_config_emits_warning_header_and_interface_block() {
        let s = dummy_server();
        let secrets = server_secrets();
        let ctx = RenderCtx::new(&s, &secrets);
        let wg = WireGuard::new();
        let bytes = AmneziaWg::new()
            .render_config(&ctx, &[], &[&wg as &dyn Protocol])
            .unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(
            text.starts_with("# Rendered by vpnctl"),
            "must lead with do-not-edit warning"
        );
        assert!(text.contains("[Interface]\n"));
        assert!(text.contains("PrivateKey = AAABBBCCCDDDEEEFFFGGGHHHIIIJJJKKKLLLMMMNNNn="));
        assert!(text.contains("ListenPort = 51820"));
        // /24 default address.
        assert!(text.contains("Address = 10.66.0.1/24"));
    }

    #[test]
    fn render_config_includes_all_nine_amnezia_obfuscation_keys_with_defaults() {
        let s = dummy_server();
        let secrets = server_secrets();
        let ctx = RenderCtx::new(&s, &secrets);
        let wg = WireGuard::new();
        let bytes = AmneziaWg::new()
            .render_config(&ctx, &[], &[&wg as &dyn Protocol])
            .unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        for (key, default) in DEFAULT_AMNEZIA_PARAMS {
            let expected = format!("{key} = {default}\n");
            assert!(
                text.contains(&expected),
                "missing default obfuscation key: {expected:?}"
            );
        }
    }

    #[test]
    fn render_config_overrides_obfs_params_via_secrets() {
        let s = dummy_server();
        let mut secrets = server_secrets();
        secrets.insert("amneziawg.jc".into(), "9".into());
        secrets.insert("amneziawg.h1".into(), "1234567890".into());
        let ctx = RenderCtx::new(&s, &secrets);
        let wg = WireGuard::new();
        let bytes = AmneziaWg::new()
            .render_config(&ctx, &[], &[&wg as &dyn Protocol])
            .unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(text.contains("Jc = 9\n"));
        assert!(text.contains("H1 = 1234567890\n"));
        // Defaults for non-overridden keys still present.
        assert!(text.contains("Jmin = 40\n"));
    }

    #[test]
    fn render_config_emits_one_peer_block_per_user_with_pubkey() {
        let s = dummy_server();
        let secrets = server_secrets();
        let ctx = RenderCtx::new(&s, &secrets);
        let wg = WireGuard::new();
        let users = [
            user_with_pubkey("alice", Some(PUBKEY_A)),
            user_with_pubkey("bob", Some(PUBKEY_B)),
        ];
        let bytes = AmneziaWg::new()
            .render_config(&ctx, &users, &[&wg as &dyn Protocol])
            .unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert_eq!(
            text.matches("[Peer]\n").count(),
            2,
            "expected 2 [Peer] blocks; got conf:\n{text}"
        );
        assert!(text.contains(&format!("PublicKey = {PUBKEY_A}\n")));
        assert!(text.contains(&format!("PublicKey = {PUBKEY_B}\n")));
        // Per-peer comment carries the user id (operator-readable).
        assert!(text.contains("# user: alice"));
        assert!(text.contains("# user: bob"));
        // /32 per peer, indexed.
        assert!(text.contains("AllowedIPs = 10.66.0.2/32\n"));
        assert!(text.contains("AllowedIPs = 10.66.0.3/32\n"));
    }

    #[test]
    fn render_config_skips_users_without_pubkey() {
        let s = dummy_server();
        let secrets = server_secrets();
        let ctx = RenderCtx::new(&s, &secrets);
        let wg = WireGuard::new();
        let users = [
            user_with_pubkey("alice", Some(PUBKEY_A)),
            user_with_pubkey("nopubkey", None),
            user_with_pubkey("bob", Some(PUBKEY_B)),
        ];
        let bytes = AmneziaWg::new()
            .render_config(&ctx, &users, &[&wg as &dyn Protocol])
            .unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert_eq!(text.matches("[Peer]\n").count(), 2);
        assert!(!text.contains("# user: nopubkey"));
    }

    #[test]
    fn render_config_uses_lf_only_no_crlf() {
        let s = dummy_server();
        let secrets = server_secrets();
        let ctx = RenderCtx::new(&s, &secrets);
        let wg = WireGuard::new();
        let bytes = AmneziaWg::new()
            .render_config(
                &ctx,
                &[user_with_pubkey("alice", Some(PUBKEY_A))],
                &[&wg as &dyn Protocol],
            )
            .unwrap();
        assert_eq!(
            bytes.iter().filter(|&&b| b == b'\r').count(),
            0,
            "no CRLF allowed in INI output"
        );
    }

    #[test]
    fn render_config_byte_stable_across_runs() {
        let s = dummy_server();
        let secrets = server_secrets();
        let ctx = RenderCtx::new(&s, &secrets);
        let wg = WireGuard::new();
        let users = [
            user_with_pubkey("alice", Some(PUBKEY_A)),
            user_with_pubkey("bob", Some(PUBKEY_B)),
        ];
        let a = AmneziaWg::new()
            .render_config(&ctx, &users, &[&wg as &dyn Protocol])
            .unwrap();
        let b = AmneziaWg::new()
            .render_config(&ctx, &users, &[&wg as &dyn Protocol])
            .unwrap();
        assert_eq!(a, b, "render_config must be byte-stable across runs");
    }
}
