//! Реализации `Protocol`. Каждый протокол — отдельный файл-модуль.
//! Добавить новый = новый файл + строка регистрации в `cli`.

mod anytls;
mod hysteria2;
mod shadowsocks2022;
mod trojan;
mod tuic_v5;
mod vless_reality;
mod wireguard;

pub use anytls::{ANYTLS_PORT, AnyTls};
pub use hysteria2::Hysteria2;
pub use shadowsocks2022::{SS_2022_PORT, Shadowsocks2022};
pub use trojan::{TROJAN_PORT, Trojan};
pub use tuic_v5::TuicV5;
pub use vless_reality::VlessReality;
pub use wireguard::{CLIENT_PRIVKEY_PLACEHOLDER, WIREGUARD_PORT, WireGuard, is_valid_wg_pubkey};
