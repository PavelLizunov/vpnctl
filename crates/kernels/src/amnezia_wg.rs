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

/// Minimum acceptable `amneziawg-tools` package version (the dpkg
/// `Version` field, queried via `dpkg-query`). `ensure_installed`
/// installs/upgrades the AmneziaWG userspace tools when the node is
/// ABSENT or BELOW this floor; it no-ops at/above.
///
/// History (same class as the sing-box gate in #27): before this floor
/// the install was gated purely on PRESENCE (`if ! command -v
/// awg-quick`), so once ANY `awg-quick` was on PATH `vpnctl deploy`
/// never upgraded `amneziawg`/`amneziawg-tools` — the fleet would
/// drift. The fix converges every node to ≥ floor on each deploy.
///
/// Why this value: the AmneziaVPN PPA publishes the userspace package
/// as `1.0.20210914-0~<buildmeta>~ubuntu20.04.1` (the `awg`/`awg-quick`
/// tools are the amneziawg fork of `wireguard-tools 1.0.20210914`).
/// Debian version ordering makes `~` sort BEFORE end-of-string, so the
/// PPA's `1.0.20210914-0~…` build compares LOWER than a bare
/// `1.0.20210914`; gating on the bare upstream string (or on the
/// volatile `-0~<buildmeta>` suffix) would spuriously reinstall on
/// every deploy / every PPA rebuild. `1.0.20210913` is the upstream
/// `1.0.20210914` line expressed one day below, so the real PPA build
/// satisfies `dpkg --compare-versions … ge`, it is independent of the
/// build suffix (no churn), and it still rejects genuinely-old tools.
/// This is a MINIMUM, not an exact pin (the PPA candidate ≥ floor is
/// acceptable), and it is operator-tunable: bump it when the PPA's
/// upstream base moves past 1.0.20210914.
const AMNEZIAWG_MIN_VERSION: &str = "1.0.20210913";

/// Idempotent node-setup script run by [`AmneziaWg::ensure_installed`]
/// on EVERY deploy (CLI `vpnctl deploy` and the daemon web/SSE paths
/// both call `ensure_installed` before render/apply). Installs (or
/// upgrades, when below [`AMNEZIAWG_MIN_VERSION`]) the AmneziaWG apt
/// packages + their prereqs, provisions the config dir, and detects a
/// DKMS/running-kernel mismatch.
///
/// Built once via `LazyLock`: only the version-gate floor (from
/// [`AMNEZIAWG_MIN_VERSION`]) is interpolated; the rest is a static raw
/// string. The composed script can be asserted directly in tests
/// (`AMNEZIAWG_SETUP_SCRIPT.as_str()` yields `&str`), so the gate is
/// covered without an SSH round-trip — same idiom as
/// `sing_box::SING_BOX_SETUP_SCRIPT`.
static AMNEZIAWG_SETUP_SCRIPT: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    // VERSION-AWARE INSTALL GATE (same class as sing_box #27).
    // Install/upgrade only when the AmneziaWG userspace tools are
    // ABSENT or BELOW AMNEZIAWG_MIN_VERSION; no-op at/above. `awg` /
    // `awg-quick` expose only a brittle `wireguard-tools
    // vX-amneziawg…` banner (see `status()`), so the comparison is on
    // the dpkg PACKAGE version of `amneziawg-tools` — the node has
    // dpkg, and `dpkg --compare-versions` does the compare. `$CUR` is
    // quoted and may be EMPTY (package absent, or dpkg-query prints
    // nothing): an empty version compares LOWER than any real floor,
    // so `ge` fails and NEED=1 (install), the safe default. `|| NEED=1`
    // keeps the non-zero compare from tripping `set -e`. The floor is a
    // const — no injection. `apt-get install -y amneziawg
    // amneziawg-tools` pulls the PPA CANDIDATE (≥ the floor).
    format!(
        r#"
            set -eu
            export DEBIAN_FRONTEND=noninteractive
            NEED=0
            if ! command -v awg-quick >/dev/null 2>&1; then
                NEED=1
            else
                CUR=$(dpkg-query -W -f='${{Version}}' amneziawg-tools 2>/dev/null || true)
                # Upgrade when the installed version is BELOW the floor.
                dpkg --compare-versions "$CUR" ge "{min}" || NEED=1
            fi
            if [ "$NEED" = 1 ]; then
                apt-get update -qq
                # Lesson #2: linux-headers-amd64 is the meta — it
                # tracks the LATEST shipped kernel, not the running one.
                # Lesson #3: dirmngr is the missing piece for gpg
                # --recv-keys to work.
                apt-get install -y --no-install-recommends \
                    curl gpg dirmngr ca-certificates iptables \
                    linux-headers-amd64
                install -d -m 0755 /usr/share/keyrings
                # Lesson #1: manual keyring (apt-key is deprecated and
                # add-apt-repository is broken on Debian 12).
                gpg --keyserver hkp://keyserver.ubuntu.com:80 \
                    --recv-keys 75C9DD72C799870E310542E24166F2C257290828
                gpg --export 75C9DD72C799870E310542E24166F2C257290828 \
                    > /usr/share/keyrings/amnezia.gpg
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
            # Lesson #2: detect kernel mismatch BEFORE someone tries
            # `awg-quick up` and gets a cryptic modprobe failure. The
            # message tells the operator exactly what to do.
            running_kernel=$(uname -r)
            if [ ! -d "/lib/modules/${{running_kernel}}/updates/dkms" ] \
                && ! lsmod | grep -q amneziawg; then
                echo "WARNING: amneziawg DKMS module built for newer kernel" >&2
                echo "than running ${{running_kernel}}. Reboot required." >&2
                echo "After reboot: \`modprobe amneziawg && lsmod | grep amneziawg\`" >&2
                exit 2
            fi
        "#,
        min = AMNEZIAWG_MIN_VERSION,
    )
});

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

/// Shell script run by [`AmneziaWg::apply_config`] after uploading the
/// rendered config to `awg0.conf.new`: validate, atomically install, then
/// (re)start `awg-quick@awg0` and poll it active. Fully static (no
/// interpolation) so it can be unit-tested for the validation contract.
///
/// The validation copies the temp file to a path NAMED `awg0.conf` before
/// running `awg-quick strip`, because `awg-quick strip` rejects any path
/// not ending in `<iface>.conf` (a `.conf.new` name dies with "must be a
/// valid interface name, followed by .conf"). Caught on the first live
/// amneziawg deploy (de, 2026-06-27).
const APPLY_CONFIG_CMD: &str = r#"
            set -eu
            _awgval=$(mktemp -d)
            cp /etc/amnezia/amneziawg/awg0.conf.new "$_awgval/awg0.conf"
            awg-quick strip "$_awgval/awg0.conf" > /dev/null
            rm -rf "$_awgval"
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
        // staging-deploy table) PLUS three AmneziaWG-specific ones
        // captured live on 84.19.3.104 on 2026-05-15:
        //
        //   * **Lesson #1 (SagerNet equivalent):** `add-apt-repository`
        //     is broken on Debian 12 (launchpadlib's API auth bug,
        //     `AttributeError: 'NoneType' object has no attribute
        //     'people'`). Manual `gpg --dearmor` keyring install with
        //     a pinned fingerprint is the only reliable path.
        //
        //   * **Lesson #2 (DKMS reality):** the `amneziawg` package
        //     installs via DKMS, which builds against the LATEST
        //     installed kernel headers — NOT the running kernel.
        //     `linux-headers-amd64` (meta) installs whatever kernel
        //     headers Debian currently ships (e.g. 6.1.0-48 even when
        //     the box is running 6.1.0-28). `modprobe amneziawg` on
        //     the running kernel then fails with "Module amneziawg
        //     not found in directory /lib/modules/<running-kernel>".
        //     Fix: detect mismatch + reboot. We do the detection
        //     after install and ABORT with a clear error message —
        //     the operator decides whether to reboot now or later.
        //
        //   * **Lesson #3 (gpg ecosystem):** stock Debian 12 ships
        //     `gnupg` but not `dirmngr`, so `gpg --keyserver ...
        //     --recv-keys` fails with "can't connect to the agent".
        //     Install `dirmngr` explicitly.
        //
        // **PPA signing key fingerprint:** `75C9DD72C799870E310542E24166F2C257290828`
        // Confirmed on 2026-05-15 from the Launchpad API
        // (`https://api.launchpad.net/1.0/~amnezia/+archive/ubuntu/ppa`
        // → `signing_key_fingerprint`). Pinned in this script — a
        // compromised keyserver can't substitute a different signer.
        //
        // The script body (including the version-aware install gate) is
        // built once in [`AMNEZIAWG_SETUP_SCRIPT`] so it can be asserted
        // directly in tests without an SSH round-trip.
        ssh.exec(AMNEZIAWG_SETUP_SCRIPT.as_str()).await?;
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
        ssh.exec(APPLY_CONFIG_CMD).await?;
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
            kernels: vec![KernelId("amneziawg".into())],
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
            wireguard_private: None,
            sub_token: None,
            vpn_router_device_id: None,
            disabled: false,
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

    /// The AmneziaWG install must be gated on a MINIMUM VERSION, not on
    /// bare presence. Before this gate, `if ! command -v awg-quick`
    /// wrapped the apt install directly, so once ANY `awg-quick` was on
    /// PATH `vpnctl deploy` never upgraded `amneziawg`/`amneziawg-tools`
    /// (latent fleet skew, same class as sing-box #27). Mirrors
    /// `sing_box::sing_box_setup_script_gates_install_on_min_version`.
    #[test]
    fn amneziawg_setup_gates_install_on_min_version() {
        let s = AMNEZIAWG_SETUP_SCRIPT.as_str();
        // The version comparison is present and uses the node's dpkg.
        assert!(
            s.contains("dpkg --compare-versions"),
            "install must be gated on a dpkg version comparison, not bare presence: {s}"
        );
        // The comparison reads the dpkg package version (no brittle
        // `awg --version` banner parsing).
        assert!(
            s.contains("dpkg-query -W -f='${Version}' amneziawg-tools"),
            "the floor must compare against the dpkg amneziawg-tools package version: {s}"
        );
        // The declared floor is injected literally (no hard-coded copy).
        assert!(
            s.contains(AMNEZIAWG_MIN_VERSION),
            "the AMNEZIAWG_MIN_VERSION floor ({AMNEZIAWG_MIN_VERSION}) must appear in the rendered script: {s}"
        );
        // …and it is the right-hand side of the `ge` comparison.
        assert!(
            s.contains(&format!("ge \"{AMNEZIAWG_MIN_VERSION}\"")),
            "the floor must be the `ge` operand of the version compare: {s}"
        );
        // The bare-presence-only gate is GONE: the old wording wrapped
        // the apt install directly in `if ! command -v awg-quick …; then`.
        // Its absence proves the apt path is no longer skipped whenever
        // any awg-quick is on PATH.
        assert!(
            !s.contains("if ! command -v awg-quick >/dev/null; then"),
            "the bare-presence-only install gate must be gone: {s}"
        );
        // The apt install is now reached via the version-aware NEED gate.
        assert!(
            s.contains(r#"if [ "$NEED" = 1 ]; then"#),
            "apt install must be reached via the version-aware NEED gate: {s}"
        );
        // The PPA repo/key setup and the package install are retained
        // inside the gate (the bootstrap is otherwise UNCHANGED).
        assert!(
            s.contains("75C9DD72C799870E310542E24166F2C257290828")
                && s.contains("ppa.launchpadcontent.net/amnezia/ppa/ubuntu")
                && s.contains("apt-get install -y amneziawg amneziawg-tools"),
            "PPA keyring/repo setup + apt install must be retained inside the gate: {s}"
        );
        // Fail-fast shell flags survive the refactor.
        assert!(s.contains("set -eu"), "fail-fast shell flags: {s}");
        // The post-install assertions and the DKMS/kernel-mismatch
        // detection are untouched by the gate change.
        assert!(
            s.contains("command -v awg-quick")
                && s.contains("command -v awg")
                && s.contains("WARNING: amneziawg DKMS module built for newer kernel"),
            "post-install assertions + kernel-mismatch detection must remain: {s}"
        );
    }

    #[test]
    fn apply_config_validates_via_conf_named_temp_not_conf_new() {
        let s = APPLY_CONFIG_CMD;
        // REGRESSION (de 2026-06-27, first live amneziawg deploy): the
        // original code ran `awg-quick strip .../awg0.conf.new`, which
        // awg-quick rejects ("must be a valid interface name, followed by
        // .conf"), failing the deploy before the config was installed. The
        // validated path MUST end in `<iface>.conf`, never `.conf.new`.
        assert!(
            !s.contains("awg-quick strip /etc/amnezia/amneziawg/awg0.conf.new"),
            "must NOT validate the .conf.new temp file directly: {s}"
        );
        // Validation runs on a temp copy NAMED awg0.conf (a path with a
        // slash → awg-quick treats it as a file, not a bare iface name).
        assert!(
            s.contains(r#"cp /etc/amnezia/amneziawg/awg0.conf.new "$_awgval/awg0.conf""#)
                && s.contains(r#"awg-quick strip "$_awgval/awg0.conf""#),
            "must validate a temp copy named awg0.conf: {s}"
        );
        // Only after validation is the real temp atomically installed and
        // the service (re)started + polled active.
        assert!(
            s.contains("mv /etc/amnezia/amneziawg/awg0.conf.new /etc/amnezia/amneziawg/awg0.conf")
                && s.contains("systemctl reload-or-restart awg-quick@awg0"),
            "atomic install + service restart must remain: {s}"
        );
        assert!(s.contains("set -eu"), "fail-fast shell flags: {s}");
    }
}
