//! Реализации `Protocol`. Каждый протокол — отдельный файл-модуль.
//! Добавить новый = новый файл + строка регистрации в `cli`.

mod hysteria2;
mod tuic_v5;
mod vless_reality;

pub use hysteria2::Hysteria2;
pub use tuic_v5::TuicV5;
pub use vless_reality::VlessReality;
