use crate::{AmneziaWg, Caddy, SingBox, Xray};
use vpnctl_core::Registry;
use vpnctl_protocols::{
    AnyTls, Hysteria2, Naive, Shadowsocks2022, Trojan, TuicV5, VlessReality, VlessWs, VlessXhttp,
    WireGuard,
};

/// Build the canonical kernel and protocol registry shared by CLI and daemon.
pub fn build_registry() -> vpnctl_core::Result<Registry> {
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
mod tests {
    use super::build_registry;

    #[test]
    fn build_registry_matches_canonical_set() {
        let registry = build_registry().unwrap();
        let protocols: Vec<String> = registry.protocol_ids().into_iter().map(|id| id.0).collect();
        let kernels: Vec<String> = registry.kernel_ids().into_iter().map(|id| id.0).collect();
        assert_eq!(
            protocols,
            [
                "vless+reality",
                "tuic-v5",
                "hysteria2",
                "shadowsocks-2022",
                "wireguard",
                "amneziawg2",
                "amneziawg3",
                "anytls",
                "trojan",
                "naive",
                "vless-ws",
                "vless+xhttp",
            ]
            .map(String::from)
            .to_vec(),
            "protocol registry membership and output order must stay stable"
        );
        assert_eq!(
            kernels,
            ["sing-box", "amneziawg", "caddy", "xray"]
                .map(String::from)
                .to_vec(),
            "kernel registry membership and output order must stay stable"
        );
    }

    #[test]
    fn protocol_testing_matrix_matches_registry() {
        let matrix = include_str!("../../../docs/PROTOCOL_TESTING.md");
        let mut shipped: Vec<String> = matrix
            .lines()
            .filter(|line| line.contains("| ✅ shipped"))
            .map(|line| {
                line.split('|')
                    .nth(1)
                    .unwrap()
                    .trim()
                    .trim_matches('`')
                    .to_string()
            })
            .collect();
        let mut registered: Vec<String> = build_registry()
            .unwrap()
            .protocol_ids()
            .into_iter()
            .map(|id| id.0)
            .collect();
        shipped.sort();
        registered.sort();
        assert_eq!(shipped, registered);
    }

    #[test]
    fn readme_protocol_counts_and_dpi_tiers_match_registry() {
        use vpnctl_core::DpiRisk;

        let readme = include_str!("../../../README.md");
        let registry = build_registry().unwrap();
        let count = registry.protocol_ids().len();
        assert!(readme.contains(&format!("**{count} protocols**")));
        assert!(readme.contains(&format!("✅ ({count} across 4 kernels)")));
        for (label, risk) in [
            ("Strong", DpiRisk::Strong),
            ("Moderate", DpiRisk::Moderate),
            ("Weak", DpiRisk::Weak),
        ] {
            let mut ids: Vec<String> = registry
                .protocol_ids()
                .into_iter()
                .filter(|id| registry.protocol(id).unwrap().dpi_risk() == risk)
                .map(|id| format!("`{id}`"))
                .collect();
            ids.sort();
            assert!(readme.contains(&format!("{label}: {}", ids.join(", "))));
        }
        let manifest = include_str!("../../../Cargo.toml");
        let msrv = manifest
            .lines()
            .find(|line| line.starts_with("rust-version = "))
            .unwrap()
            .split('"')
            .nth(1)
            .unwrap();
        assert!(readme.contains(&format!("rust-{msrv}%2B")));
        assert!(readme.contains(&format!("Rust **{msrv}+**")));
    }
}
