//! Single source of truth for kernel/protocol registration. Both the CLI's
//! `registry` subcommand and (in v0.2 Phase 3b) `deploy` will pull from here.

use vpnctl_core::Registry;
use vpnctl_kernels::{AmneziaWg, SingBox, WgTurn as WgTurnKernel};
use vpnctl_protocols::{
    AnyTls, Hysteria2, Shadowsocks2022, Trojan, TuicV5, VlessReality, WgTurn as WgTurnProtocol,
    WireGuard,
};

/// Build the canonical Registry. Add new kernels/protocols here.
pub(crate) fn build() -> anyhow::Result<Registry> {
    let mut reg = Registry::new();

    // ─── ЯДРА ────────────────────────────────────────────────────────────
    reg.register_kernel(Box::new(SingBox::new()))?;
    // AmneziaWG — anti-DPI WireGuard fork. Apt-installed from the
    // AmneziaVPN PPA; obfuscation params live in
    // RenderCtx::secrets["amneziawg.{jc,jmin,jmax,s1,s2,h1,h2,h3,h4}"].
    reg.register_kernel(Box::new(AmneziaWg::new()))?;
    // wgturn-core — VK-TURN-relayed WireGuard «emergency channel».
    // ~200 KB/s ceiling per device (VK rate-limits); position as a
    // fallback when REALITY / WireGuard direct are blocked. Secrets:
    // `wgturn:server_wg_private`, `wgturn:vk_link`,
    // `wgturn:listen_port` (opt), `wgturn:mode` (opt).
    reg.register_kernel(Box::new(WgTurnKernel::new()))?;

    // ─── ПРОТОКОЛЫ ───────────────────────────────────────────────────────
    // All stateless — real REALITY keys / TUIC certs / WG private keys
    // live in inventory.server_secrets and arrive via RenderCtx at
    // deploy time.
    reg.register_protocol(Box::new(VlessReality::new()))?;
    reg.register_protocol(Box::new(TuicV5::new()))?;
    reg.register_protocol(Box::new(Hysteria2::new()))?;
    reg.register_protocol(Box::new(Shadowsocks2022::new()))?;
    // WireGuard wire-format — served by AmneziaWg today, future
    // WireGuardKernel (vanilla wg-quick) too.
    reg.register_protocol(Box::new(WireGuard::new()))?;
    // AnyTLS — REALITY successor; different TLS fingerprint, useful
    // as fallback channel when REALITY gets DPI'd. Sing-box ≥ 1.12.
    reg.register_protocol(Box::new(AnyTls::new()))?;
    // Trojan — venerable TLS-mimic. Third "TLS-looking" channel
    // for protocol diversity; many older clients know Trojan but
    // not REALITY/AnyTLS.
    reg.register_protocol(Box::new(Trojan::new()))?;
    // wgturn — companion to the wgturn-core kernel. Phase 1 stub:
    // `share_link` returns a render-error pointing at the
    // server-side `wgturn-cli provision-url` flow; the URL encoder
    // is pending pkg/wgshare → Rust port (phase 2).
    reg.register_protocol(Box::new(WgTurnProtocol::new()))?;

    Ok(reg)
}
