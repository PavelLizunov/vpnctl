//! Single source of truth for kernel/protocol registration. Both the CLI's
//! `registry` subcommand and (in v0.2 Phase 3b) `deploy` will pull from here.

use vpnctl_core::Registry;
use vpnctl_kernels::SingBox;
use vpnctl_protocols::{Hysteria2, Shadowsocks2022, TuicV5, VlessReality};

/// Build the canonical Registry. Add new kernels/protocols here.
pub(crate) fn build() -> anyhow::Result<Registry> {
    let mut reg = Registry::new();

    // ─── ЯДРА ────────────────────────────────────────────────────────────
    reg.register_kernel(Box::new(SingBox::new()))?;
    // To add wgturn:
    // reg.register_kernel(Box::new(Wgturn::new()))?;

    // ─── ПРОТОКОЛЫ ───────────────────────────────────────────────────────
    // All stateless — real REALITY keys / TUIC certs live in
    // inventory.server_secrets and arrive via RenderCtx at deploy time.
    reg.register_protocol(Box::new(VlessReality::new()))?;
    reg.register_protocol(Box::new(TuicV5::new()))?;
    reg.register_protocol(Box::new(Hysteria2::new()))?;
    reg.register_protocol(Box::new(Shadowsocks2022::new()))?;

    Ok(reg)
}
