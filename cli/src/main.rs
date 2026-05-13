//! Тонкий CLI поверх крейтов. Архитектурное правило: бизнес-логики здесь нет —
//! только парсинг аргументов, вызов крейтов, форматирование вывода.

use clap::{Parser, Subcommand};
use vpnctl_core::Registry;
use vpnctl_kernels::SingBox;
use vpnctl_protocols::{TuicV5, VlessReality};

#[derive(Parser)]
#[command(name = "vpnctl", version, about = "VPN infrastructure control")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Показать зарегистрированные ядра и протоколы.
    Registry,
    /// Сгенерировать UUID v4 (для smoke-теста криптокрейта).
    Uuid,
}

fn build_registry() -> Registry {
    let mut reg = Registry::new();
    // ─── ЯДРА ────────────────────────────────────────────────────────────
    reg.register_kernel(Box::new(SingBox::new()));
    // Чтобы добавить wgturn — раскомментируй и положи crates/kernels/src/wgturn.rs:
    // reg.register_kernel(Box::new(Wgturn::new()));

    // ─── ПРОТОКОЛЫ ───────────────────────────────────────────────────────
    // Заглушечные ключи REALITY: реальные значения берутся из inventory при
    // сборке конфига для конкретного сервера.
    reg.register_protocol(Box::new(VlessReality::new(
        "www.microsoft.com".into(),
        "00000000".into(),
        "PUBKEY_PLACEHOLDER".into(),
        "PRIVKEY_PLACEHOLDER".into(),
    )));
    reg.register_protocol(Box::new(TuicV5::new()));
    reg
}

fn main() {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Registry => {
            let reg = build_registry();
            // Для смок-теста просто выведем что-то осмысленное.
            // Полноценный list-вывод появится, когда добавим публичные геттеры
            // в Registry (это вторая итерация).
            let _ = reg;
            println!("registry built ok");
            println!("kernel: sing-box (vless+reality, tuic-v5, hysteria2, shadowsocks-2022)");
            println!("protocols: vless+reality, tuic-v5");
        }
        Cmd::Uuid => {
            println!("{}", vpnctl_crypto::gen_uuid());
        }
    }
}
