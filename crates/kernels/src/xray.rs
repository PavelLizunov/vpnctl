//! Xray-core — prebuilt static-binary kernel serving VLESS+Reality+xhttp.
//!
//! ## Why a separate Kernel (not sing-box)
//!
//! sing-box has no server-side xhttp inbound — sing-box-lx's xhttp/AWG
//! additions are CLIENT-only (see plans/xray-xhttp.md §2). Xray-core
//! (XTLS/Xray-core) is the only daemon that serves xhttp server-side.
//! Different daemon ⇒ different Kernel, same split as amneziawg / caddy
//! vs sing-box.
//!
//! ## Install — prebuilt GitHub-release static binary (NOT apt, NOT an
//! on-node build)
//!
//! `XTLS/Xray-core/releases/download/<tag>/Xray-linux-<arch>.zip`. A
//! single static binary (no CGO), small enough (~20 MB) that curl-on-node
//! is fine — unlike caddy's Go build, there's no on-node-build
//! RAM pressure to work around with a control-host cache. Installed to
//! `/usr/local/bin/xray` + a hardened `xray.service` unit + config at
//! `/usr/local/etc/xray/config.json`.
//!
//! [`XRAY_VERSION`] is an EXACT pin, not a floor — unlike sing-box/
//! amneziawg's apt-channel "candidate ≥ floor" idiom, every fresh install
//! here downloads the SAME pinned release asset, so the install gate
//! compares for equality (reinstall on absent OR mismatched version, not
//! "below a floor").
//!
//! ## Port
//!
//! 9443/TCP, standalone — NOT 443 (sing-box vless+reality owns it on
//! every node that runs sing-box) and NOT 8443 (double-claimed on the
//! `is` pilot: caddy/vless-ws TCP/8443 + sing-box tuic-v5 UDP/8443).
//! See plans/xray-xhttp.md §6 (resolved: standalone port, option A).
//!
//! ## Kernel × Protocol orthogonality
//!
//! Adding this kernel touches ONLY this file, `crates/kernels/src/lib.rs`
//! (`mod` + `pub use`), the companion `crates/protocols/src/vless_xhttp.rs`
//! and its `lib.rs` entry, and one `register_kernel` line each in
//! `daemon/src/app.rs::build_registry()` / `cli/src/registry.rs`. No edits
//! to `core`, `ssh`, `crypto`, `inventory`, or `cli` beyond the
//! registration line, per CLAUDE.md's Kernel × Protocol invariant.

use async_trait::async_trait;
use serde_json::json;
use vpnctl_core::{
    CoreError, Kernel, KernelId, KernelStatus, KernelVersionPolicy, KernelVersionRequirement,
    Protocol, ProtocolId, RenderCtx, Result, SshTransport, User,
};

#[derive(Debug, Default)]
pub struct Xray;

impl Xray {
    pub fn new() -> Self {
        Self
    }
}

/// Pinned `XTLS/Xray-core` release tag — the download URL embeds this
/// exact tag (NOT "latest"), so every fresh install is reproducible.
/// Confirmed live against the GitHub releases API on 2026-06-30 (asset
/// names `Xray-linux-64.zip` / `Xray-linux-arm64-v8a.zip`). Bump
/// deliberately; re-verify asset names haven't changed before bumping.
const XRAY_VERSION: &str = "v26.3.27";

/// Pinned SHA-256 digests for the Xray release archives, per
/// architecture. Verified against the official `.dgst` sidecar
/// assets published alongside each release archive at
/// `https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-linux-{64,arm64-v8a}.zip.dgst`
/// (fetched 2026-07-29; the `.dgst` files carry MD5/SHA1/SHA2-256/
/// SHA2-512 — we pin SHA2-256). Bumping [`XRAY_VERSION`] REQUIRES
/// re-fetching the new `.dgst` values from the same URL pattern.
const XRAY_SHA256_LINUX_64: &str =
    "23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae";
const XRAY_SHA256_LINUX_ARM64: &str =
    "4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c";

const XRAY_BIN: &str = "/usr/local/bin/xray";
const XRAY_CONFIG_DIR: &str = "/usr/local/etc/xray";
const XRAY_CONFIG_PATH: &str = "/usr/local/etc/xray/config.json";
const XRAY_RESTART_IF_ACTIVE: &str =
    "if systemctl is-active --quiet xray; then systemctl restart xray; fi";

/// Staging path for the uploaded-but-not-yet-applied config. MUST end in
/// `.json` — unlike sing-box/amneziawg's validators, Xray-core's `run
/// -test` auto-detects the config FORMAT from the file extension (see
/// `main/run.go`'s `getRegepxByFormat`), so a `config.json.new`-style
/// staging name fails with "Failed to get format of ..." even though the
/// content is valid JSON. Caught live on the `is` pilot 2026-06-30 — same
/// bug class as the AWG2 `apply_config` fix (PR #74): a CLI tool that
/// infers behavior from the path string, not just its content.
const XRAY_CONFIG_STAGING_PATH: &str = "/usr/local/etc/xray/config.staging.json";

/// Idempotent node-setup script run by [`Xray::ensure_installed`] on
/// every deploy. Installs the pinned [`XRAY_VERSION`] release binary when
/// ABSENT or at a DIFFERENT version (exact-pin equality, not a floor —
/// see this module's doc comment), provisions a dedicated `xray` system
/// user + config dir, and writes a hardened systemd unit (as a prebuilt-binary
/// kernel with no apt-packaged unit to inherit from).
///
/// Built once via `LazyLock` so the version pin is interpolated exactly
/// once and the composed script can be asserted directly in tests
/// (`XRAY_SETUP_SCRIPT.as_str()`) without an SSH round-trip — same idiom
/// as `sing_box::SING_BOX_SETUP_SCRIPT` / `amnezia_wg::AMNEZIAWG_SETUP_SCRIPT`.
static XRAY_SETUP_SCRIPT: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    format!(
        r#"
            set -eu
            export DEBIAN_FRONTEND=noninteractive
            NEED=0
            if ! command -v xray >/dev/null 2>&1; then
                NEED=1
            else
                CUR=$(xray version 2>/dev/null | head -1 | awk '{{print $2}}')
                [ "$CUR" = "{bare_version}" ] || NEED=1
            fi
            if [ "$NEED" = 1 ]; then
                apt-get update -qq
                apt-get install -y --no-install-recommends curl unzip ca-certificates
                ARCH=$(uname -m)
                case "$ARCH" in
                    x86_64)
                        XASSET="Xray-linux-64.zip"
                        XSHA256="{sha256_64}"
                        ;;
                    aarch64)
                        XASSET="Xray-linux-arm64-v8a.zip"
                        XSHA256="{sha256_arm64}"
                        ;;
                    *) echo "unsupported arch '$ARCH' for Xray-core" >&2; exit 1 ;;
                esac
                TMPDIR=$(mktemp -d)
                curl -fsSL -o "$TMPDIR/xray.zip" \
                    "https://github.com/XTLS/Xray-core/releases/download/{version}/${{XASSET}}"
                # Verify the archive digest BEFORE extracting/installing.
                # The pinned SHA-256 comes from the official .dgst sidecar
                # asset (see XRAY_SHA256_* constants). A mismatch aborts
                # the deploy — a compromised CDN or MITM can't substitute
                # a tampered binary.
                echo "$XSHA256  $TMPDIR/xray.zip" | sha256sum -c - >/dev/null
                unzip -o -q "$TMPDIR/xray.zip" -d "$TMPDIR"
                install -o root -g root -m 0755 "$TMPDIR/xray" {bin}
                rm -rf "$TMPDIR"
            fi

            id -u xray >/dev/null 2>&1 \
                || useradd --system --no-create-home --shell /usr/sbin/nologin xray
            install -d -m 0750 -o xray -g xray {config_dir}

            cat > /etc/systemd/system/xray.service <<'UNIT'
[Unit]
Description=Xray-core (vpnctl-managed VLESS+Reality+xhttp)
Documentation=https://github.com/XTLS/Xray-core
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=xray
Group=xray
ExecStart={bin} run -c {config_path}
Restart=on-failure
RestartSec=5

NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths={config_dir}
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectClock=true
ProtectControlGroups=true
ProtectHostname=true
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
CapabilityBoundingSet=
AmbientCapabilities=
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources @obsolete @raw-io @reboot @swap @debug @cpu-emulation @mount
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
UMask=0077

[Install]
WantedBy=multi-user.target
UNIT
            systemctl daemon-reload
            systemctl enable xray >/dev/null 2>&1 || true
            if [ "$NEED" = 1 ]; then
                {restart_if_active}
            fi

            command -v xray
            test -x {bin}
        "#,
        version = XRAY_VERSION,
        bare_version = XRAY_VERSION.trim_start_matches('v'),
        sha256_64 = XRAY_SHA256_LINUX_64,
        sha256_arm64 = XRAY_SHA256_LINUX_ARM64,
        restart_if_active = XRAY_RESTART_IF_ACTIVE,
        bin = XRAY_BIN,
        config_dir = XRAY_CONFIG_DIR,
        config_path = XRAY_CONFIG_PATH,
    )
});

/// Validate-before-swap apply script: `xray run -test` rejects a
/// malformed config BEFORE it touches the live file (Xray-core's `-test`
/// flag — "Test config file only, without launching the server", verified
/// against `main/run.go` source 2026-06-30); snapshot-swap-poll-rollback
/// otherwise mirrors `sing_box_apply_script` / `amnezia_wg`'s
/// `apply_config` byte-for-byte (CLAUDE.md staging-deploy lesson #3:
/// `reload-or-restart` returning 0 does NOT mean the service stayed up).
///
/// Validates [`XRAY_CONFIG_STAGING_PATH`] (a `.json`-suffixed path), NOT
/// `{config_path}.new` — see that constant's doc comment for why the
/// extension matters to Xray-core's own format auto-detection. The `1>&2`
/// on the test invocation matters too: Xray prints its actual failure
/// reason ("Failed to start: ...") via `fmt.Println` to STDOUT, not
/// stderr, so without the redirect a failed validation surfaces an empty
/// `stderr=""` in the deploy's error payload — exactly what happened on
/// the live `is` failure this fixes (the real reason was invisible until
/// reproduced manually over SSH).
fn xray_apply_script() -> String {
    format!(
        r#"
            set -eu
            xray run -test -c {staging_path} 1>&2
            if [ -f {config_path} ]; then
                cp -a {config_path} {config_path}.bak 2>/dev/null || true
            fi
            mv {staging_path} {config_path}
            chown xray:xray {config_path}
            chmod 0640 {config_path}
            systemctl reload-or-restart xray

            for i in 1 2 3 4 5 6 7 8; do
                state=$(systemctl is-active xray || true)
                if [ "$state" = "active" ]; then
                    rm -f {config_path}.bak
                    exit 0
                fi
                sleep 1
            done

            echo "xray did not become active. Last 20 log lines:" >&2
            journalctl -u xray --no-pager -n 20 >&2 || true
            if [ -f {config_path}.bak ]; then
                echo "rolling back to previous xray config" >&2
                mv {config_path}.bak {config_path} || true
                chown xray:xray {config_path} || true
                chmod 0640 {config_path} || true
                systemctl reload-or-restart xray || true
            fi
            exit 1
        "#,
        staging_path = XRAY_CONFIG_STAGING_PATH,
        config_path = XRAY_CONFIG_PATH,
    )
}

/// Idempotent, ufw-guarded shell snippet opening every `(transport, port)`
/// in `ports`. Deliberately duplicated from `sing_box::firewall_open_script`
/// rather than shared — this codebase prefers small duplication over
/// cross-kernel coupling at this boundary.
fn firewall_open_script(ports: &[(&str, u16)]) -> Option<String> {
    let uniq: std::collections::BTreeSet<(&str, u16)> = ports.iter().copied().collect();
    if uniq.is_empty() {
        return None;
    }
    let mut s = String::from("if command -v ufw >/dev/null 2>&1; then\n");
    for (transport, port) in &uniq {
        s.push_str(&format!(
            "  ufw allow {port}/{transport} >/dev/null 2>&1 || true\n"
        ));
    }
    s.push_str("fi\n");
    Some(s)
}

#[async_trait]
impl Kernel for Xray {
    fn id(&self) -> KernelId {
        KernelId("xray".to_string())
    }

    fn supported_protocols(&self) -> Vec<ProtocolId> {
        vec![ProtocolId("vless+xhttp".to_string())]
    }

    fn version_requirement(&self) -> Option<KernelVersionRequirement> {
        Some(KernelVersionRequirement {
            policy: KernelVersionPolicy::Pin,
            value: XRAY_VERSION,
        })
    }

    async fn ensure_installed(&self, ssh: &dyn SshTransport) -> Result<()> {
        ssh.exec(XRAY_SETUP_SCRIPT.as_str()).await?;
        Ok(())
    }

    fn render_config(
        &self,
        ctx: &RenderCtx<'_>,
        users: &[User],
        protocols: &[&dyn Protocol],
    ) -> Result<Vec<u8>> {
        // Locate the vless+xhttp protocol — this kernel serves nothing
        // else. Registry::validate_server should have caught a mismatch
        // earlier; this is the defense-in-depth layer (mirrors
        // amnezia_wg::render_config).
        let proto = protocols
            .iter()
            .find(|p| p.id() == ProtocolId("vless+xhttp".to_string()))
            .ok_or_else(|| {
                CoreError::Render(
                    "xray kernel requires the vless+xhttp protocol in `protocols`".into(),
                )
            })?;
        let inbound = proto.server_inbound(ctx, users)?;

        // Xray-core's top-level config shape differs from sing-box's:
        // `log.loglevel` (not `log.level`), `outbounds[].protocol` (not
        // `.type`) — verified against `infra/conf` 2026-06-30, NOT a
        // copy-paste of the sing-box shape.
        let cfg = json!({
            "log": { "loglevel": "warning" },
            "inbounds": [inbound],
            "outbounds": [{ "protocol": "freedom", "tag": "direct" }]
        });
        serde_json::to_vec_pretty(&cfg).map_err(CoreError::from)
    }

    async fn apply_config(&self, ssh: &dyn SshTransport, config: &[u8]) -> Result<()> {
        ssh.upload(XRAY_CONFIG_STAGING_PATH, config).await?;
        ssh.exec(&xray_apply_script()).await?;
        Ok(())
    }

    async fn open_firewall(
        &self,
        ssh: &dyn SshTransport,
        ctx: &RenderCtx<'_>,
        protocols: &[&dyn Protocol],
    ) -> Result<()> {
        let ports: Vec<(&str, u16)> = protocols
            .iter()
            .flat_map(|p| p.effective_listen_ports(ctx.secrets))
            .collect();
        if let Some(script) = firewall_open_script(&ports) {
            ssh.exec(&script).await?;
        }
        Ok(())
    }

    async fn restart(&self, ssh: &dyn SshTransport) -> Result<()> {
        ssh.exec("systemctl restart xray").await?;
        Ok(())
    }

    async fn status(&self, ssh: &dyn SshTransport) -> Result<KernelStatus> {
        let active = ssh
            .exec("systemctl is-active xray 2>/dev/null || true")
            .await?
            .trim()
            .eq("active");
        let version = ssh
            .exec("xray version 2>/dev/null | awk 'NR==1 {print $2}'")
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
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use vpnctl_core::{Server, ServerId};

    fn dummy_server() -> Server {
        Server {
            id: ServerId("xray-node-1".into()),
            address: "203.0.113.9".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            kernels: vec![KernelId("xray".into())],
            enabled_protocols: vec![ProtocolId("vless+xhttp".into())],
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        }
    }

    #[test]
    fn id_returns_xray() {
        assert_eq!(Xray::new().id(), KernelId("xray".into()));
    }

    #[test]
    fn supported_protocols_only_vless_xhttp() {
        assert_eq!(
            Xray::new().supported_protocols(),
            vec![ProtocolId("vless+xhttp".into())]
        );
    }

    #[test]
    fn render_config_missing_protocol_returns_render_error() {
        let s = dummy_server();
        let secrets = HashMap::new();
        let ctx = RenderCtx::new(&s, &secrets);
        let err = Xray::new().render_config(&ctx, &[], &[]).unwrap_err();
        match err {
            CoreError::Render(msg) => {
                assert!(
                    msg.contains("vless+xhttp"),
                    "msg should mention vless+xhttp: {msg}"
                );
            }
            other => panic!("expected Render error, got {other:?}"),
        }
    }

    #[test]
    fn render_config_happy_path_uses_xray_top_level_shape() {
        use vpnctl_protocols::VlessXhttp;

        let s = dummy_server();
        let mut secrets = HashMap::new();
        secrets.insert("vless.private_key".into(), "priv".into());
        secrets.insert("vless.public_key".into(), "pub".into());
        secrets.insert("vless.short_id".into(), "deadbeef".into());
        secrets.insert("vlessxhttp.path".into(), "Ab3x9Zq2Kp7Lm".into());
        let ctx = RenderCtx::new(&s, &secrets);
        let proto = VlessXhttp::new();
        let bytes = Xray::new()
            .render_config(&ctx, &[], &[&proto as &dyn Protocol])
            .unwrap();
        let cfg: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        // Xray-core shape, NOT sing-box's (log.loglevel not log.level,
        // outbounds[].protocol not .type).
        assert_eq!(cfg["log"]["loglevel"], "warning");
        assert_eq!(cfg["outbounds"][0]["protocol"], "freedom");
        assert_eq!(cfg["inbounds"][0]["protocol"], "vless");
        assert_eq!(cfg["inbounds"][0]["port"], 9443);
        assert_eq!(cfg["inbounds"][0]["streamSettings"]["network"], "xhttp");
        // Kernel passes the protocol's envelope through untouched —
        // single-inbound passthrough, no merging.
        assert_eq!(cfg["inbounds"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn setup_script_pins_exact_version_not_a_floor() {
        let s = XRAY_SETUP_SCRIPT.as_str();
        assert!(
            s.contains(&format!(
                "[ \"$CUR\" = \"{}\" ]",
                XRAY_VERSION.trim_start_matches('v')
            )),
            "install gate must compare for EXACT equality against the bare pinned version: {s}"
        );
        assert!(
            !s.contains("dpkg --compare-versions"),
            "xray is not apt-installed — no package version to compare against a floor: {s}"
        );
        assert!(
            s.contains(XRAY_VERSION),
            "the pinned tag must appear in the download URL: {s}"
        );
        assert!(s.contains("Xray-linux-64.zip"), "x86_64 asset name: {s}");
        assert!(
            s.contains("Xray-linux-arm64-v8a.zip"),
            "arm64 asset name: {s}"
        );
        assert!(s.contains("set -eu"), "fail-fast shell flags: {s}");
    }

    #[test]
    fn setup_script_verifies_sha256_before_unzip() {
        let s = XRAY_SETUP_SCRIPT.as_str();
        // Both per-arch SHA-256 constants are embedded.
        assert!(
            s.contains(XRAY_SHA256_LINUX_64),
            "x86_64 SHA-256 must be pinned in the script: {s}"
        );
        assert!(
            s.contains(XRAY_SHA256_LINUX_ARM64),
            "arm64 SHA-256 must be pinned in the script: {s}"
        );
        // Verification uses sha256sum -c BEFORE unzip.
        assert!(
            s.contains("sha256sum -c -"),
            "must verify the archive digest via sha256sum -c: {s}"
        );
        let verify = s
            .find("sha256sum -c -")
            .expect("sha256sum verification missing");
        let unzip = s.find("unzip -o -q").expect("unzip step missing");
        assert!(
            verify < unzip,
            "SHA-256 verification must happen BEFORE unzip/install: {s}"
        );
        // The checksums are 64-char lowercase hex (valid SHA-256).
        for digest in [XRAY_SHA256_LINUX_64, XRAY_SHA256_LINUX_ARM64] {
            assert_eq!(digest.len(), 64, "SHA-256 must be 64 hex chars");
            assert!(
                digest.chars().all(|c| c.is_ascii_hexdigit()),
                "SHA-256 must be all hex: {digest}"
            );
        }
    }

    #[test]
    fn setup_script_provisions_dedicated_system_user_and_hardened_unit() {
        let s = XRAY_SETUP_SCRIPT.as_str();
        assert!(s.contains("useradd --system"), "must not run as root: {s}");
        assert!(s.contains("User=xray") && s.contains("Group=xray"));
        assert!(s.contains("NoNewPrivileges=true"));
        assert!(s.contains("ProtectSystem=strict"));
    }

    #[test]
    fn apply_script_validates_before_swap() {
        let s = xray_apply_script();
        let test_idx = s.find("xray run -test").expect("must validate before swap");
        let swap_idx = s.find("mv ").expect("must swap the config into place");
        assert!(
            test_idx < swap_idx,
            "validation must happen BEFORE the mv swap: {s}"
        );
    }

    #[test]
    fn apply_script_validates_a_json_suffixed_staging_path_not_dot_new() {
        // Regression guard for the live `is` failure (2026-06-30): Xray-
        // core's `run -test` infers config FORMAT from the file
        // extension, so validating a `.new`-suffixed path fails with
        // "Failed to get format of ..." even on valid JSON content. The
        // staging path must end in `.json`.
        let s = xray_apply_script();
        assert!(
            s.contains("xray run -test -c /usr/local/etc/xray/config.staging.json"),
            "must validate the .json-suffixed staging path, not a .new-suffixed one: {s}"
        );
        assert!(
            !s.contains("config.json.new"),
            "must not reintroduce the .new-suffixed staging path: {s}"
        );
    }

    #[test]
    fn apply_script_redirects_test_command_stdout_to_stderr() {
        // Xray prints its real failure reason ("Failed to start: ...")
        // via fmt.Println to STDOUT, not stderr — without `1>&2` on this
        // exact command, a failed validation surfaces an empty stderr to
        // the operator (exactly what happened on the live `is` failure
        // this regression test pins).
        let s = xray_apply_script();
        assert!(
            s.contains("xray run -test -c /usr/local/etc/xray/config.staging.json 1>&2"),
            "the validate command must redirect its stdout to stderr: {s}"
        );
    }

    #[test]
    fn apply_script_snapshots_before_overwrite_and_rolls_back_on_failure() {
        let s = xray_apply_script();
        assert!(s.contains("cp -a"), "must snapshot the live config: {s}");
        assert!(s.contains(".bak"), "snapshot must use a .bak suffix: {s}");
        assert!(
            s.contains("rolling back"),
            "must roll back on activation failure: {s}"
        );
        assert!(
            s.contains("journalctl -u xray"),
            "must dump diagnostics on failure: {s}"
        );
    }

    #[test]
    fn firewall_open_script_opens_each_port_idempotently_guarded() {
        let s = firewall_open_script(&[("tcp", 9443)]).unwrap();
        assert!(s.contains("command -v ufw"));
        assert!(s.contains("ufw allow 9443/tcp"));
        assert!(s.contains("|| true"));
    }

    #[test]
    fn firewall_open_script_empty_ports_is_none() {
        assert!(firewall_open_script(&[]).is_none());
    }
}
