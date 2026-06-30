//! Single source of truth for kernel/protocol registration. Both the CLI's
//! `registry` subcommand and (in v0.2 Phase 3b) `deploy` will pull from here.

use vpnctl_core::Registry;
use vpnctl_kernels::{
    AmneziaWg, Caddy, DnsTunnel as DnsTunnelKernel, SingBox, WgTurn as WgTurnKernel, Xray,
};
use vpnctl_protocols::{
    AnyTls, DnsTunnel as DnsTunnelProtocol, Hysteria2, Naive, Shadowsocks2022, Trojan, TuicV5,
    VlessReality, VlessWs, VlessXhttp, WgTurn as WgTurnProtocol, WireGuard,
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
    // Caddy + forwardproxy@naive — serves the `naive` protocol with a
    // real masquerade website (HTTP 200 to probes, tunnel to authed
    // clients). Built from source on-node (xcaddy); ACME built into
    // Caddy. Binds 80+443 → a naive node must not also run a 443-TCP
    // sing-box protocol. Secrets: `naive.domain`, `naive.acme_email`.
    reg.register_kernel(Box::new(Caddy::new()))?;
    // dns-tunnel — slipstream-rust DNS-over-НСДИ last-resort transport
    // (4th fallback after VLESS-REALITY / TUIC / NAIVE). Owns TWO units:
    // `dns-tunnel` (slipstream-server UDP:53) + `dns-tunnel-singbox`
    // (loopback-only TLS-less VLESS on 127.0.0.1:9001). Binary is a
    // prebuilt amd64 cache (≥2 GB RAM build → no on-node build). Secrets:
    // `dns-tunnel:domain`, `dns-tunnel:loopback_uuid`,
    // `dns-tunnel:fingerprint`, `dns-tunnel:resolvers` (opt),
    // `dns-tunnel:engine` (opt).
    reg.register_kernel(Box::new(DnsTunnelKernel::new()))?;
    // Xray-core — see crates/kernels/src/xray.rs module doc-comment.
    reg.register_kernel(Box::new(Xray::new()))?;

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
    // naive — Chromium-fingerprint proxy served by the Caddy kernel.
    // Strongest active-probe resistance (real cover website). Reuses
    // `User.tuic_password` for HTTP Basic; server params
    // `naive.domain` / `naive.acme_email` in inventory.server_secrets.
    reg.register_protocol(Box::new(Naive::new()))?;
    // vless-ws — VLESS over WebSocket+TLS, DIRECT (no CDN), also served
    // by the Caddy kernel (real LE cert on an alt-port + decoy site +
    // reverse_proxy of one secret path → loopback sing-box ws inbound).
    // RU-DPI-resistant AND client-universal (v2rayNG/v2RayTun/Happ/
    // sing-box). No static listen_port → coexists with REALITY on :443.
    // Server params `vlessws.domain` / `vlessws.acme_email` /
    // `vlessws.listen_port`; `vlessws.path` auto-minted.
    reg.register_protocol(Box::new(VlessWs::new()))?;
    // dns-tunnel — companion stub to the dns-tunnel kernel. Two-process
    // client (slipstream-client + loopback VLESS), so
    // `appears_in_sing_box_sub()` is false; `share_link` emits the
    // `dns-tunnel://` bundle (domain + resolvers + cert fp pin + the
    // user's per-user `User.uuid`, same one used for VLESS-REALITY). DPI
    // risk Moderate (last-resort; НСДИ is monitored).
    reg.register_protocol(Box::new(DnsTunnelProtocol::new()))?;
    // vless+xhttp — see crates/protocols/src/vless_xhttp.rs.
    reg.register_protocol(Box::new(VlessXhttp::new()))?;

    Ok(reg)
}
