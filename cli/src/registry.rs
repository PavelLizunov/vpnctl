use vpnctl_core::Registry;
use vpnctl_kernels::{AmneziaWg, Caddy, SingBox, Xray};
use vpnctl_protocols::{
    AnyTls, Hysteria2, Naive, Shadowsocks2022, Trojan, TuicV5, VlessReality, VlessWs, VlessXhttp,
    WireGuard,
};

pub(crate) fn build() -> anyhow::Result<Registry> {
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
