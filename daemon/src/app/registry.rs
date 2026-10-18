use vpnctl_core::Registry;

pub(crate) fn build_registry() -> anyhow::Result<Registry> {
    use vpnctl_kernels::{AmneziaWg, Caddy, SingBox, Xray};
    use vpnctl_protocols::{
        AnyTls, Hysteria2, Naive, Shadowsocks2022, Trojan, TuicV5, VlessReality, VlessWs,
        VlessXhttp, WireGuard,
    };

    let mut reg = Registry::new();
    reg.register_kernel(Box::new(SingBox::new()))?;
    reg.register_kernel(Box::new(AmneziaWg::new()))?;
    reg.register_kernel(Box::new(Caddy::new()))?;
    reg.register_kernel(Box::new(Xray::new()))?;
    reg.register_protocol(Box::new(VlessReality::new()))?;
    reg.register_protocol(Box::new(TuicV5::new()))?;
    reg.register_protocol(Box::new(Hysteria2::new()))?;
    reg.register_protocol(Box::new(Shadowsocks2022::new()))?;
    reg.register_protocol(Box::new(WireGuard::new()))?;
    reg.register_protocol(Box::new(vpnctl_protocols::AmneziaWg2::new()))?;
    reg.register_protocol(Box::new(vpnctl_protocols::AmneziaWg3::new()))?;
    reg.register_protocol(Box::new(AnyTls::new()))?;
    reg.register_protocol(Box::new(Trojan::new()))?;
    reg.register_protocol(Box::new(Naive::new()))?;
    reg.register_protocol(Box::new(VlessWs::new()))?;
    reg.register_protocol(Box::new(VlessXhttp::new()))?;
    Ok(reg)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod registry_drift_guard {
    use super::build_registry;

    #[test]
    fn build_registry_matches_canonical_set() {
        let reg = build_registry().unwrap();
        let mut protos: Vec<String> = reg.protocol_ids().into_iter().map(|p| p.0).collect();
        let mut kernels: Vec<String> = reg.kernel_ids().into_iter().map(|k| k.0).collect();
        protos.sort();
        kernels.sort();

        let mut want_protos = [
            "amneziawg2",
            "amneziawg3",
            "anytls",
            "hysteria2",
            "naive",
            "shadowsocks-2022",
            "trojan",
            "tuic-v5",
            "vless+reality",
            "vless+xhttp",
            "vless-ws",
            "wireguard",
        ]
        .map(String::from)
        .to_vec();
        want_protos.sort();

        let mut want_kernels = ["amneziawg", "caddy", "sing-box", "xray"]
            .map(String::from)
            .to_vec();
        want_kernels.sort();

        assert_eq!(protos, want_protos, "daemon protocol registry drifted");
        assert_eq!(kernels, want_kernels, "daemon kernel registry drifted");
    }
}
