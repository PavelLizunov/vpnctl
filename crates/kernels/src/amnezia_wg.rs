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

const AMNEZIAWG_MIN_VERSION: &str = "1.0.20210913";

static AMNEZIAWG_SETUP_SCRIPT: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
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

const EGRESS_IFACE_PLACEHOLDER: &str = "__EGRESS_IFACE__";

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
            # A failed reload/restart goes straight to the rollback below: under
            # set -eu it would otherwise exit first, and an old interface that is
            # still active must not pass for the new config.
            restart_rc=0
            systemctl reload-or-restart awg-quick@awg0 || restart_rc=$?

            # Wait up to 8 seconds for the service to settle. systemd's
            # auto-restart back-off kicks in every 10s, so 8s is past
            # the first attempt — not "active" by then = crash loop.
            if [ "$restart_rc" -eq 0 ]; then
                for i in 1 2 3 4 5 6 7 8; do
                    state=$(systemctl is-active awg-quick@awg0 || true)
                    if [ "$state" = "active" ]; then
                        rm -f /etc/amnezia/amneziawg/awg0.conf.bak
                        exit 0
                    fi
                    sleep 1
                done
            fi

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
        ssh.exec(AMNEZIAWG_SETUP_SCRIPT.as_str()).await?;
        Ok(())
    }

    fn render_config(
        &self,
        ctx: &RenderCtx<'_>,
        users: &[User],
        protocols: &[&dyn Protocol],
    ) -> Result<Vec<u8>> {
        let wg_proto = protocols
            .iter()
            .find(|p| p.id() == ProtocolId("wireguard".to_string()))
            .ok_or_else(|| {
                CoreError::Render(
                    "amneziawg kernel requires the wireguard protocol in `protocols`".into(),
                )
            })?;

        let envelope_json = wg_proto.server_inbound(ctx, users)?;
        let env: WireGuardEnvelope = serde_json::from_value(envelope_json)
            .map_err(|e| CoreError::Render(format!("wireguard envelope parse: {e}")))?;

        let mut out = String::with_capacity(1024);
        out.push_str("# Rendered by vpnctl. Do not hand-edit \u{2014} your changes will be\n");
        out.push_str("# overwritten on next `vpnctl deploy`.\n");
        out.push_str("[Interface]\n");
        out.push_str(&format!("PrivateKey = {}\n", env.private_key));
        out.push_str(&format!("ListenPort = {}\n", env.listen_port));
        out.push_str(&format!("Address = {}\n", env.address_cidr));

        for (ini_key, default) in DEFAULT_AMNEZIA_PARAMS {
            let secret_key = format!("amneziawg.{}", ini_key.to_ascii_lowercase());
            let value = ctx.or_default(&secret_key, default);
            out.push_str(&format!("{ini_key} = {value}\n"));
        }

        out.push_str(&format!(
            "PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o {EGRESS_IFACE_PLACEHOLDER} -j MASQUERADE\n",
        ));
        out.push_str(&format!(
            "PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o {EGRESS_IFACE_PLACEHOLDER} -j MASQUERADE\n",
        ));

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
