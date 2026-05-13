//! Реализации `Protocol`. Каждый протокол — отдельный файл-модуль.
//! Добавить новый = новый файл + строка регистрации в `cli`.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

mod vless_reality;
mod tuic_v5;

pub use tuic_v5::TuicV5;
pub use vless_reality::VlessReality;
