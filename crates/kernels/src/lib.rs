//! Реализации `Kernel`. Каждое ядро — отдельный модуль.
//!
//! Чтобы добавить новое ядро (wgturn, xray, hysteria-server и т.п.):
//!
//!   1. Создаёшь `crates/kernels/src/<my_kernel>.rs` с `impl Kernel for MyKernel`.
//!   2. `pub use <my_kernel>::MyKernel;` ниже.
//!   3. В `cli/src/main.rs` добавляешь одну строку `reg.register_kernel(...)`.
//!
//! Никакие другие крейты править не надо.

mod amnezia_wg;
mod sing_box;
mod wgturn;

pub use amnezia_wg::AmneziaWg;
pub use sing_box::SingBox;
pub use wgturn::WgTurn;
