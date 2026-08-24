//! Реализации `Protocol`. Каждый протокол — отдельный файл-модуль.
//! Добавить новый = новый файл + строка регистрации в `cli`.

mod anytls;
mod hysteria2;
mod naive;
mod shadowsocks2022;
mod trojan;
mod tuic_v5;
mod vless_reality;
mod vless_ws;
mod vless_xhttp;
mod wg_addressing;
mod wireguard;

pub use anytls::{ANYTLS_PORT, AnyTls};
pub use hysteria2::Hysteria2;
pub use naive::{NAIVE_PORT, Naive};
pub use shadowsocks2022::{SS_2022_PORT, Shadowsocks2022};
pub use trojan::{TROJAN_PORT, Trojan};
pub use tuic_v5::TuicV5;
pub use vless_reality::{
    DEFAULT_REALITY_SNI, VLESS_PACKET_ENCODING, VlessReality,
    listen_port as reality_listen_port,
};
pub use vless_ws::{DEFAULT_FRONT_PORT as VLESS_WS_DEFAULT_FRONT_PORT, VlessWs};
pub use vless_xhttp::{VLESS_XHTTP_PORT, VlessXhttp};
pub use wireguard::{
    CLIENT_PRIVKEY_PLACEHOLDER, WIREGUARD_PORT, WireGuard, amnezia_share_link, awg_share_link,
    is_valid_wg_pubkey, render_client_conf_public,
};
