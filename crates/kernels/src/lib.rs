//! Реализации `Kernel`. Каждое ядро — отдельный модуль.
//!
//! Чтобы добавить новое ядро (xray, hysteria-server и т.п.):
//!
//!   1. Создаёшь `crates/kernels/src/<my_kernel>.rs` с `impl Kernel for MyKernel`.
//!   2. `pub use <my_kernel>::MyKernel;` ниже.
//!   3. В `cli/src/registry.rs` (и `daemon/src/app.rs::build_registry()`)
//!      добавляешь одну строку `reg.register_kernel(...)`.
//!
//! Никакие другие крейты править не надо.

mod amnezia_wg;
mod caddy;
mod sing_box;
mod xray;

pub use amnezia_wg::AmneziaWg;
pub use caddy::Caddy;
pub use sing_box::SingBox;
pub use xray::Xray;

/// Reserved-ports pre-apply guard (migration 0028). Re-exported here
/// so the daemon's deploy handler + the CLI's `vpnctl deploy` can
/// call it BEFORE invoking the trait `apply_config`. The validator
/// is sing-box-specific (walks `inbounds[].listen_port`), so it
/// lives next to that kernel rather than as a generic Kernel trait
/// method — other kernels (amnezia_wg) bind a different
/// shape and would need their own validators if they ever need
/// reserved-port enforcement.
pub use sing_box::validate_config_excludes_ports;

/// PR-Q read helper: the set of user UUIDs a live sing-box config
/// declares (sorted). Re-exported here so the daemon's drift-detail
/// card can compare on-node vs inventory-expected users. Pure read over
/// already-fetched config bytes — no new kernel/protocol coupling.
pub use sing_box::live_config_user_uuids;
