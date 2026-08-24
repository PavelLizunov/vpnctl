//! Canonical protocol and kernel registry construction for the daemon.

use vpnctl_core::Registry;

/// Same canonical Registry as the CLI uses. Kept in a tiny helper so a
/// future shared `crate vpnctl-registry` can replace this without changing
/// callers. `pub(crate)` so secret-minting tests (and any other in-crate
/// caller that needs the canonical protocol set) build the real registry
/// rather than a hand-rolled subset that could drift.
pub(crate) fn build_registry() -> anyhow::Result<Registry> {
    use vpnctl_kernels::{
        AmneziaWg, Caddy, DnsTunnel as DnsTunnelKernel, SingBox, WgTurn as WgTurnKernel, Xray,
    };
    use vpnctl_protocols::{
        AnyTls, DnsTunnel as DnsTunnelProtocol, Hysteria2, Naive, Shadowsocks2022, Trojan, TuicV5,
        VlessReality, VlessWs, VlessXhttp, WgTurn as WgTurnProtocol, WireGuard,
    };

    let mut reg = Registry::new();
    reg.register_kernel(Box::new(SingBox::new()))?;
    reg.register_kernel(Box::new(AmneziaWg::new()))?;
    // wgturn-core — VK-TURN-relayed WireGuard emergency channel.
    // Mirrors `cli/src/registry.rs::build`. The duplication is
    // pre-existing (see this function's doc-comment); a future
    // `vpnctl-registry` crate consolidates both sites.
    reg.register_kernel(Box::new(WgTurnKernel::new()))?;
    // Caddy + forwardproxy@naive — serves the `naive` protocol with a
    // real masquerade website. MUST stay in lockstep with cli/registry.rs.
    reg.register_kernel(Box::new(Caddy::new()))?;
    // dns-tunnel — slipstream-rust DNS-over-НСДИ last-resort transport.
    // Owns TWO units (slipstream-server UDP:53 + loopback VLESS sing-box).
    // MUST stay in lockstep with cli/registry.rs.
    reg.register_kernel(Box::new(DnsTunnelKernel::new()))?;
    // Xray-core — serves VLESS+Reality+xhttp on a standalone port
    // (9443/TCP), companion to sing-box-lx's client-side xhttp support.
    // MUST stay in lockstep with cli/registry.rs.
    reg.register_kernel(Box::new(Xray::new()))?;
    reg.register_protocol(Box::new(VlessReality::new()))?;
    reg.register_protocol(Box::new(TuicV5::new()))?;
    reg.register_protocol(Box::new(Hysteria2::new()))?;
    reg.register_protocol(Box::new(Shadowsocks2022::new()))?;
    reg.register_protocol(Box::new(WireGuard::new()))?;
    reg.register_protocol(Box::new(AnyTls::new()))?;
    reg.register_protocol(Box::new(Trojan::new()))?;
    reg.register_protocol(Box::new(WgTurnProtocol::new()))?;
    // naive — Chromium-fingerprint proxy served by the Caddy kernel.
    // Without this the daemon's /sub render + admin dpi-chip silently
    // drop naive (the CLI deploy still worked, hiding the gap).
    reg.register_protocol(Box::new(Naive::new()))?;
    // vless-ws — VLESS/WebSocket+TLS direct (Caddy kernel). Without this
    // the daemon's /sub + ninitux render + admin dpi-chip silently drop
    // it. MUST stay in lockstep with cli/registry.rs.
    reg.register_protocol(Box::new(VlessWs::new()))?;
    // dns-tunnel — companion stub to the dns-tunnel kernel. Two-process
    // client → appears_in_sing_box_sub() is false. MUST stay in lockstep
    // with cli/registry.rs.
    reg.register_protocol(Box::new(DnsTunnelProtocol::new()))?;
    // vless+xhttp — Xray-core-served xhttp transport, reuses the REALITY
    // keypair vless+reality already mints. MUST stay in lockstep with
    // cli/registry.rs.
    reg.register_protocol(Box::new(VlessXhttp::new()))?;
    Ok(reg)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod registry_drift_guard {
    use super::build_registry;

    /// The daemon's registry MUST stay in lockstep with
    /// `cli/src/registry.rs::build` — the `/sub` render and the admin
    /// dpi-chip resolve protocols through THIS registry, so anything
    /// registered in the CLI but not here is silently dropped from every
    /// subscription (exactly what happened to `naive` until 2026-06-04).
    /// Full-set pin: adding/removing a protocol or kernel at one site
    /// without the other (or this list) trips the assert.
    #[test]
    fn build_registry_matches_canonical_set() {
        let reg = build_registry().unwrap();
        let mut protos: Vec<String> = reg.protocol_ids().into_iter().map(|p| p.0).collect();
        let mut kernels: Vec<String> = reg.kernel_ids().into_iter().map(|k| k.0).collect();
        protos.sort();
        kernels.sort();

        let mut want_protos = [
            "anytls",
            "dns-tunnel",
            "hysteria2",
            "naive",
            "shadowsocks-2022",
            "trojan",
            "tuic-v5",
            "vless+reality",
            "vless+xhttp",
            "vless-ws",
            "wgturn",
            "wireguard",
        ]
        .map(String::from)
        .to_vec();
        want_protos.sort();

        let mut want_kernels = [
            "amneziawg",
            "caddy",
            "dns-tunnel",
            "sing-box",
            "wgturn",
            "xray",
        ]
        .map(String::from)
        .to_vec();
        want_kernels.sort();

        assert_eq!(protos, want_protos, "daemon protocol registry drifted");
        assert_eq!(kernels, want_kernels, "daemon kernel registry drifted");
    }
}
