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

fn build_registry() -> Result<Registry, vpnctl_core::CoreError> {
    let mut reg = Registry::new();

    // ─── ЯДРА ────────────────────────────────────────────────────────────
    reg.register_kernel(Box::new(SingBox::new()))?;
    // Чтобы добавить wgturn — раскомментируй и положи crates/kernels/src/wgturn.rs:
    // reg.register_kernel(Box::new(Wgturn::new()))?;

    // ─── ПРОТОКОЛЫ ───────────────────────────────────────────────────────
    // Stateless — реальные ключи (REALITY private/public/short_id, TUIC cert
    // paths) приходят из inventory.server_secrets через RenderCtx во время
    // деплоя. Здесь — просто declarative registration.
    reg.register_protocol(Box::new(VlessReality::new()))?;
    reg.register_protocol(Box::new(TuicV5::new()))?;

    Ok(reg)
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Registry => match build_registry() {
            Ok(_reg) => {
                // TODO(v0.3): пройтись по reg и вывести фактический список.
                // Сейчас Registry не имеет публичных геттеров для списка.
                println!("registry built ok");
                println!("kernel: sing-box (vless+reality, tuic-v5, hysteria2, shadowsocks-2022)");
                println!("protocols: vless+reality, tuic-v5");
                std::process::ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("error: {e}");
                std::process::ExitCode::FAILURE
            }
        },
        Cmd::Uuid => {
            println!("{}", vpnctl_crypto::gen_uuid());
            std::process::ExitCode::SUCCESS
        }
    }
}
