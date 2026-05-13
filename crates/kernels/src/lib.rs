//! Реализации `Kernel`. Каждое ядро — отдельный модуль.
//!
//! Чтобы добавить новое ядро (wgturn, xray, hysteria-server и т.п.):
//!
//!   1. Создаёшь `crates/kernels/src/<my_kernel>.rs` с `impl Kernel for MyKernel`.
//!   2. `pub use <my_kernel>::MyKernel;` ниже.
//!   3. В `cli/src/main.rs` добавляешь одну строку `reg.register_kernel(...)`.
//!
//! Никакие другие крейты править не надо.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

mod sing_box;

pub use sing_box::SingBox;
