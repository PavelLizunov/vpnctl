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
    CoreError, Kernel, KernelId, KernelStatus, KernelVersionPolicy, KernelVersionRequirement,
    Protocol, ProtocolId, RenderCtx, Result, SshTransport, User,
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

/// Placeholder token emitted by `render_config` in PostUp/PostDown
/// NAT rules. The apply script replaces it with the node's actual
/// default egress interface (detected via `ip route`), so the
/// rendered config is deterministic/testable while the real
/// interface is resolved at apply time on the node.
const EGRESS_IFACE_PLACEHOLDER: &str = "__EGRESS_IFACE__";

/// Shell script run by [`AmneziaWg::apply_config`] after uploading the
/// rendered config to `awg0.conf.new`: validate, detect the default
/// egress interface, persist IPv4 forwarding, atomically install, then
/// (re)start `awg-quick@awg0` and poll it active. On failure, ROLL
/// BACK to the previous config snapshot (same discipline as
/// `sing_box_apply_script` / `xray_apply_script`).
///
/// The validation copies the temp file to a path NAMED `awg0.conf` before
/// running `awg-quick strip`, because `awg-quick strip` rejects any path
/// not ending in `<iface>.conf` (a `.conf.new` name dies with "must be a
/// valid interface name, followed by .conf"). Caught on the first live
/// amneziawg deploy (de, 2026-06-27).
fn awg_apply_script() -> String {
    format!(
        r#"
            set -eu

            # ── Detect the default egress interface (safe fixed
            #    pipeline — no untrusted shell text). Falls back to
            #    eth0 when no default route exists yet (fresh LXC).
            EGRESS=$(ip -o -4 route show to default 2>/dev/null | awk '{{print $5; exit}}')
            EGRESS=${{EGRESS:-eth0}}

            # ── Validate the detected name before interpolating into
            #    sed/iptables. Conservative Linux iface charset only.
            case "$EGRESS" in
                *[!a-zA-Z0-9._-]*)
                    echo "egress interface name failed validation: $EGRESS" >&2
                    exit 1
                    ;;
            esac

            # ── Replace the render-time placeholder with the real
            #    interface so PostUp/PostDown NAT rules target the
            #    correct egress.
            sed -i "s/{placeholder}/$EGRESS/g" /etc/amnezia/amneziawg/awg0.conf.new

            # ── Persist + activate IPv4 forwarding (idempotent).
            sysctl -w net.ipv4.ip_forward=1 >/dev/null
            install -d -m 0755 /etc/sysctl.d
            echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-vpnctl-forward.conf

            # ── Validate via awg-quick strip (must see a path ending
            #    in <iface>.conf, not .conf.new).
            _awgval=$(mktemp -d)
            cp /etc/amnezia/amneziawg/awg0.conf.new "$_awgval/awg0.conf"
            awg-quick strip "$_awgval/awg0.conf" > /dev/null
            rm -rf "$_awgval"

            # ── Snapshot the live config for rollback (only if it
            #    exists — first deploy has none; -a preserves perms).
            HAD_PREV=0
            if [ -f /etc/amnezia/amneziawg/awg0.conf ]; then
                if cp -a /etc/amnezia/amneziawg/awg0.conf /etc/amnezia/amneziawg/awg0.conf.bak 2>/dev/null; then
                    HAD_PREV=1
                fi
            fi

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
                if [ "$state" = "active" ]; then
                    rm -f /etc/amnezia/amneziawg/awg0.conf.bak
                    exit 0
                fi
                sleep 1
            done

            # Failed to come up. Dump diagnostics, then ROLL BACK.
            echo "awg-quick@awg0 did not become active. Last 20 log lines:" >&2
            journalctl -u awg-quick@awg0 --no-pager -n 20 >&2 || true
            echo "--- attempted config (post-strip) ---" >&2
            awg-quick strip /etc/amnezia/amneziawg/awg0.conf >&2 || true
            if [ "$HAD_PREV" = 1 ] && [ -f /etc/amnezia/amneziawg/awg0.conf.bak ]; then
                echo "rolling back to previous awg0 config" >&2
                mv /etc/amnezia/amneziawg/awg0.conf.bak /etc/amnezia/amneziawg/awg0.conf || true
                chown root:root /etc/amnezia/amneziawg/awg0.conf || true
                chmod 0600 /etc/amnezia/amneziawg/awg0.conf || true
                systemctl reload-or-restart awg-quick@awg0 || true
            else
                echo "no previous config — removing failed deploy" >&2
                systemctl stop awg-quick@awg0 || true
                systemctl disable awg-quick@awg0 || true
                rm -f /etc/amnezia/amneziawg/awg0.conf
            fi
            exit 1
        "#,
        placeholder = EGRESS_IFACE_PLACEHOLDER,
    )
}

#[async_trait]
impl Kernel for AmneziaWg {
    fn id(&self) -> KernelId {
        KernelId("amneziawg".to_string())
    }

    fn supported_protocols(&self) -> Vec<ProtocolId> {
        vec![ProtocolId("wireguard".to_string())]
    }

    fn version_requirement(&self) -> Option<KernelVersionRequirement> {
        Some(KernelVersionRequirement {
            policy: KernelVersionPolicy::Floor,
            value: AMNEZIAWG_MIN_VERSION,
        })
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

        // PostUp / PostDown for NAT'ing outbound traffic. The egress
        // interface is a PLACEHOLDER token that the apply script
        // replaces with the node's actual default-route interface
        // (detected via `ip route` at apply time), so hosts with
        // ens18/ens3/etc. get correct MASQUERADE rules. Symmetric:
        // PostDown deletes exactly what PostUp added.
        out.push_str(&format!(
            "PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o {EGRESS_IFACE_PLACEHOLDER} -j MASQUERADE\n",
        ));
        out.push_str(&format!(
            "PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o {EGRESS_IFACE_PLACEHOLDER} -j MASQUERADE\n",
        ));

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
        // and prints a useful error). Detect the real egress interface,
        // persist IPv4 forwarding, atomic-rename, lock perms, restart +
        // verify-active poll + ROLLBACK on failure — same discipline as
        // sing_box_apply_script / xray_apply_script (CLAUDE.md staging-
        // deploy lesson #3).
        ssh.exec(&awg_apply_script()).await?;
        Ok(())
    }

    async fn restart(&self, ssh: &dyn SshTransport) -> Result<()> {
        ssh.exec("systemctl restart awg-quick@awg0").await?;
        Ok(())
    }

    async fn status(&self, ssh: &dyn SshTransport) -> Result<KernelStatus> {
        let active = ssh
            .exec("systemctl is-active awg-quick@awg0 2>/dev/null || true")
            .await?
            .trim()
            .eq("active");
        let version = ssh
            .exec("dpkg-query -W -f='${Version}' amneziawg-tools 2>/dev/null")
            .await
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty());
        Ok(KernelStatus {
            active,
            version,
            uptime_seconds: None,
        })
    }
}

#[cfg(test)]
#[path = "amnezia_wg_tests.rs"]
mod tests;
