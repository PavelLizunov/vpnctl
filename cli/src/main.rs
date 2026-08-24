//! `vpnctl` — тонкий CLI поверх крейтов. Бизнес-логика живёт в крейтах,
//! здесь только парсинг аргументов, dispatch и форматирование вывода.

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

mod cmd;
mod key_path;
mod registry;
mod ui;

#[derive(Parser, Debug)]
// `version` reports build provenance `<semver>+<short-git-sha>` (or
// `+unknown` outside a Git checkout) so `vpnctl --version` on a node
// identifies the exact deployed commit — the same stamp the daemon
// health endpoint and admin footer show. Single source of truth:
// `vpnctl_core::build_version()` (SemVer from CARGO_PKG_VERSION plus the
// compile-time VPNCTL_BUILD_SHA the deploy script exports; no runtime git).
#[command(
    name = "vpnctl",
    version = vpnctl_core::build_version(),
    about = "VPN infrastructure control"
)]
struct Cli {
    /// Path to the SQLite inventory file. Created on first use.
    #[arg(long, env = "VPNCTL_DB", global = true)]
    db: Option<PathBuf>,

    /// Output format for list/show commands.
    #[arg(long, short, global = true, default_value = "text", value_enum)]
    output: OutputFormat,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
pub(crate) enum OutputFormat {
    Text,
    Json,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Generate a fresh UUID v4 (smoke).
    Uuid,
    /// Show registered kernels and protocols.
    Registry,
    /// Manage servers in the inventory.
    Server {
        #[command(subcommand)]
        cmd: cmd::server::ServerCmd,
    },
    /// Manage users in the inventory.
    User {
        #[command(subcommand)]
        cmd: cmd::user::UserCmd,
    },
    /// Manage the Boosty → VPN subscription bridge.
    Boosty {
        #[command(subcommand)]
        cmd: cmd::boosty::BoostyCmd,
    },
    /// Grant a user access to a server.
    Grant { user: String, server: String },
    /// Revoke a user's access to a server.
    Revoke { user: String, server: String },
    /// Push current inventory state to a server (install kernel, generate
    /// missing REALITY keys / TUIC cert, render & apply config, restart).
    Deploy {
        server: String,
        /// SSH private key path (default: ~/.ssh/id_ed25519).
        #[arg(long)]
        key: Option<PathBuf>,
    },
    /// Query a server for kernel runtime status.
    Status {
        server: String,
        #[arg(long)]
        key: Option<PathBuf>,
    },
    /// Upgrade node kernel binaries to their version floor WITHOUT
    /// rendering/applying config. Runs each declared kernel's
    /// `ensure_installed` (the version-gated apt upgrade) only — it
    /// never enters `apply_config`, so it bypasses the DG-1 UUID-removal
    /// diff-guard and works on inventory-drift nodes where `deploy` is
    /// blocked. The on-disk config is left untouched; only the kernel
    /// binary (and the service apt restarts against it) moves.
    UpdateKernels {
        /// Server id to upgrade. Mutually exclusive with `--all`; exactly
        /// one of the two must be given.
        server: Option<String>,
        /// Upgrade every server in the inventory.
        #[arg(long)]
        all: bool,
        /// SSH private key path (default: ~/.ssh/id_ed25519).
        #[arg(long)]
        key: Option<PathBuf>,
    },
    /// Print share links (vless://, tuic://, ...) for every server×protocol
    /// the user has been granted access to. Applies the same subscription
    /// policy as the live `/sub` endpoint (disabled user → empty;
    /// auto-suppressed servers + hidden / per-user-denied protocols
    /// filtered).
    Sub {
        user: String,
        /// Render an ASCII QR code under each link (for phone scanning).
        #[arg(long)]
        qr: bool,
        /// Bypass subscription policy and print every raw link, including
        /// those the live `/sub` endpoint would suppress (disabled user,
        /// hidden / per-user-denied protocols, auto-suppressed servers).
        /// For debugging only.
        #[arg(long)]
        ignore_policy: bool,
    },
    /// Provision a brand-new node: install our SSH key (using root password
    /// once), record the host fingerprint, and add the server to inventory.
    /// After this, `vpnctl deploy <id>` works key-only.
    Bootstrap(cmd::bootstrap::BootstrapArgs),
    /// Render the kernel-native config for a server to STDOUT without
    /// touching SSH. Useful for offline review + live-staging tests
    /// (closes the methodology TODO in docs/PROTOCOL_TESTING.md).
    Render { server: String },
    /// Manage `inv.db` snapshots (Phase C-4 backups). Subcommands:
    /// `snapshot` (take one now), `list` (newest-first), `prune`
    /// (apply default retention).
    Backup {
        #[command(subcommand)]
        cmd: cmd::backup::BackupCmd,
    },
    /// Restore the inventory from a snapshot file. **Daemon MUST be
    /// stopped first** — replacing the open DB while vpnctld holds it
    /// silently corrupts state. Sequence:
    ///   1. sudo systemctl stop vpnctld
    ///   2. vpnctl restore /var/lib/vpnctl/backups/inv.db.<ts>.bak
    ///   3. sudo systemctl start vpnctld
    Restore {
        /// Path to the snapshot file produced by `vpnctl backup snapshot`
        /// or downloaded from the Settings page.
        snapshot: PathBuf,
    },
    /// Migrate state from the legacy bash `vpn-control` project (Phase
    /// C-5). Subcommand `from-bash <dir>` reads each `<IP>.env`, SSHs
    /// to each server read-only to pull `/etc/sing-box/{config.json,keys.env}`,
    /// builds a plan, and (with `--apply`) inserts servers/users/grants
    /// into vpnctl's inv.db preserving UUIDs + TUIC passwords. Default
    /// is dry-run.
    Migrate {
        #[command(subcommand)]
        cmd: MigrateCmd,
    },
    /// Download + atomic-install the current month's DB-IP Lite City +
    /// ASN MaxMind-compatible MMDB files into `VPNCTLD_GEOIP_DIR`
    /// (default `/var/lib/vpnctl/geoip`). DB-IP Lite is CC-BY 4.0 +
    /// no signup — pure-Rust reqwest download, no curl shell-out.
    /// Restart vpnctld after to load the new DBs.
    GeoipUpdate {
        /// Override target dir (default reads `VPNCTLD_GEOIP_DIR` env
        /// var, falls back to `/var/lib/vpnctl/geoip`).
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// `vpnctld` admin-side utilities. Today: hash an admin password
    /// into the Argon2id PHC format expected by
    /// `VPNCTLD_ADMIN_PASSWORD`. Was referenced in `daemon/handlers/
    /// auth.rs` doc-comment for 9 months without an actual implementation
    /// (audit B2, 2026-05-22) — anyone following the docs got
    /// «unrecognized subcommand». Now real.
    Admin {
        #[command(subcommand)]
        cmd: AdminCmd,
    },
}

#[derive(Subcommand, Debug)]
enum AdminCmd {
    /// Hash a plaintext admin password to Argon2id PHC format. Read
    /// the plaintext from stdin (recommended — never appears on the
    /// process command line) or `--password <plain>` for ad-hoc use.
    /// Writes the `$argon2id$v=19$…` line to stdout; paste into
    /// `/etc/vpnctl/vpnctld.env` as `VPNCTLD_ADMIN_PASSWORD=…`.
    HashPassword {
        /// Plaintext password. If omitted, read one line from stdin.
        /// Prefer stdin — passing on the command line leaves the
        /// password in shell history + `/proc/<pid>/cmdline`.
        /// Opaque value: allow a leading `-` instead of mis-parsing it as a flag.
        #[arg(long, allow_hyphen_values = true)]
        password: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum MigrateCmd {
    /// Pull state out of a bash `vpn-control` inventory + servers.
    FromBash(cmd::migrate::MigrateFromBashArgs),
}

/// Validate the `update-kernels` exactly-one-of(server, --all) contract
/// and map it to an [`cmd::update_kernels::UpdateTarget`]. A positional
/// `server` and `--all` are mutually exclusive, and at least one must be
/// given — otherwise the command has no idea what to upgrade.
fn resolve_update_target(
    server: Option<String>,
    all: bool,
) -> anyhow::Result<cmd::update_kernels::UpdateTarget> {
    match (server, all) {
        (Some(_), true) => {
            anyhow::bail!("pass either a server id or --all, not both")
        }
        (None, false) => {
            anyhow::bail!("specify a server id or --all")
        }
        (Some(id), false) => Ok(cmd::update_kernels::UpdateTarget::One(id)),
        (None, true) => Ok(cmd::update_kernels::UpdateTarget::All),
    }
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let cli = Cli::parse();

    let res: anyhow::Result<()> = match cli.cmd {
        Cmd::Uuid => {
            println!("{}", vpnctl_crypto::gen_uuid());
            Ok(())
        }
        Cmd::Registry => cmd::registry_cmd::run(cli.output),
        Cmd::Server { cmd } => cmd::server::run(cmd, cli.db, cli.output).await,
        Cmd::User { cmd } => cmd::user::run(cmd, cli.db, cli.output).await,
        Cmd::Boosty { cmd } => cmd::boosty::run(cmd, cli.db, cli.output).await,
        Cmd::Grant { user, server } => cmd::grant::run_grant(&user, &server, cli.db).await,
        Cmd::Revoke { user, server } => cmd::grant::run_revoke(&user, &server, cli.db).await,
        Cmd::Deploy { server, key } => cmd::deploy::run(&server, key, cli.db).await,
        Cmd::Status { server, key } => cmd::status::run(&server, key, cli.db, cli.output).await,
        Cmd::UpdateKernels { server, all, key } => match resolve_update_target(server, all) {
            Ok(target) => cmd::update_kernels::run(target, key, cli.db, cli.output).await,
            Err(e) => Err(e),
        },
        Cmd::Sub {
            user,
            qr,
            ignore_policy,
        } => cmd::sub::run(&user, qr, ignore_policy, cli.db, cli.output).await,
        Cmd::Bootstrap(args) => cmd::bootstrap::run(args, cli.db).await,
        Cmd::Render { server } => cmd::render::run(&server, cli.db).await,
        Cmd::Backup { cmd } => cmd::backup::run(cmd, cli.db, cli.output).await,
        Cmd::Restore { snapshot } => cmd::backup::run_restore(snapshot, cli.db, cli.output).await,
        Cmd::Migrate { cmd } => match cmd {
            MigrateCmd::FromBash(args) => {
                cmd::migrate::run_from_bash(args, cli.db, cli.output).await
            }
        },
        Cmd::GeoipUpdate { dir } => cmd::geoip::run(dir).await,
        Cmd::Admin { cmd } => match cmd {
            AdminCmd::HashPassword { password } => cmd::admin::hash_password(password),
        },
    };

    match res {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    //! clap-parse regression net for the leading-`-` footgun (bug #3).
    //! URL-safe base64 secrets (what `crypto::gen_password` emits) legitimately
    //! start with `-`/`_`. Without `allow_hyphen_values` clap rejects them with
    //! a generic "unexpected argument" instead of binding the value, so the
    //! operator can't even pass a freshly-minted secret. These tests assert the
    //! opaque-value args accept a leading hyphen and bind it verbatim.

    use super::*;

    #[test]
    fn server_secret_accepts_leading_hyphen_value() {
        let cli = Cli::try_parse_from([
            "vpnctl",
            "server",
            "secret",
            "srv",
            "tuic.password",
            "-AbCdef",
        ])
        .expect("leading-`-` secret value must parse, not be mistaken for a flag");
        match cli.cmd {
            Cmd::Server {
                cmd: cmd::server::ServerCmd::Secret { server, key, value },
            } => {
                assert_eq!(server, "srv");
                assert_eq!(key, "tuic.password");
                assert_eq!(value, "-AbCdef", "value must bind verbatim");
            }
            other => panic!("expected `server secret`, got {other:?}"),
        }
    }

    #[test]
    fn user_add_accepts_leading_hyphen_tuic_password_and_uuid() {
        let cli = Cli::try_parse_from([
            "vpnctl",
            "user",
            "add",
            "alex-laptop",
            "--tuic-password",
            "-_pw0",
            "--uuid",
            "-deadbeef",
        ])
        .expect("leading-`-` --tuic-password / --uuid must parse");
        match cli.cmd {
            Cmd::User {
                cmd:
                    cmd::user::UserCmd::Add {
                        id,
                        uuid,
                        tuic_password,
                        ..
                    },
            } => {
                assert_eq!(id, "alex-laptop");
                assert_eq!(tuic_password.as_deref(), Some("-_pw0"));
                assert_eq!(uuid.as_deref(), Some("-deadbeef"));
            }
            other => panic!("expected `user add`, got {other:?}"),
        }
    }

    #[test]
    fn bootstrap_accepts_leading_hyphen_root_password() {
        let cli = Cli::try_parse_from([
            "vpnctl",
            "bootstrap",
            "node-01",
            "--address",
            "203.0.113.10",
            "--root-password",
            "-rootpw",
        ])
        .expect("leading-`-` --root-password must parse");
        match cli.cmd {
            Cmd::Bootstrap(args) => {
                assert_eq!(args.root_password, "-rootpw");
            }
            other => panic!("expected `bootstrap`, got {other:?}"),
        }
    }

    #[test]
    fn admin_hash_password_accepts_leading_hyphen() {
        let cli = Cli::try_parse_from([
            "vpnctl",
            "admin",
            "hash-password",
            "--password",
            "-secretpw",
        ])
        .expect("leading-`-` --password must parse");
        match cli.cmd {
            Cmd::Admin {
                cmd: AdminCmd::HashPassword { password },
            } => assert_eq!(password.as_deref(), Some("-secretpw")),
            other => panic!("expected `admin hash-password`, got {other:?}"),
        }
    }

    #[test]
    fn boosty_status_accepts_global_json_output_after_subcommand() {
        let cli = Cli::try_parse_from(["vpnctl", "boosty", "status", "--output", "json"])
            .expect("global --output must parse after `boosty status`");
        assert!(matches!(cli.output, OutputFormat::Json));
        assert!(matches!(
            cli.cmd,
            Cmd::Boosty {
                cmd: cmd::boosty::BoostyCmd::Status
            }
        ));
    }

    #[test]
    fn update_kernels_single_server_binds_positional() {
        let cli = Cli::try_parse_from(["vpnctl", "update-kernels", "de"])
            .expect("`update-kernels de` must parse");
        match cli.cmd {
            Cmd::UpdateKernels { server, all, key } => {
                assert_eq!(server.as_deref(), Some("de"));
                assert!(!all);
                assert!(key.is_none());
            }
            other => panic!("expected `update-kernels`, got {other:?}"),
        }
    }

    #[test]
    fn update_kernels_all_flag_parses() {
        let cli = Cli::try_parse_from(["vpnctl", "update-kernels", "--all"])
            .expect("`update-kernels --all` must parse");
        match cli.cmd {
            Cmd::UpdateKernels { server, all, .. } => {
                assert!(server.is_none());
                assert!(all);
            }
            other => panic!("expected `update-kernels`, got {other:?}"),
        }
    }

    #[test]
    fn update_kernels_binds_key_flag() {
        let cli = Cli::try_parse_from(["vpnctl", "update-kernels", "de", "--key", "/x"])
            .expect("`update-kernels de --key /x` must parse");
        match cli.cmd {
            Cmd::UpdateKernels { server, key, .. } => {
                assert_eq!(server.as_deref(), Some("de"));
                assert_eq!(key, Some(PathBuf::from("/x")));
            }
            other => panic!("expected `update-kernels`, got {other:?}"),
        }
    }

    #[test]
    fn update_kernels_target_neither_is_rejected() {
        // Clap parses `update-kernels` with no args (both optional); the
        // run-side validation is what rejects "neither server nor --all".
        let err = resolve_update_target(None, false)
            .expect_err("neither server nor --all must be rejected");
        assert!(err.to_string().contains("--all"), "got: {err}");
    }

    #[test]
    fn update_kernels_target_both_is_rejected() {
        let err = resolve_update_target(Some("de".into()), true)
            .expect_err("server + --all must be rejected");
        assert!(err.to_string().contains("not both"), "got: {err}");
    }

    #[test]
    fn update_kernels_target_maps_single_and_all() {
        match resolve_update_target(Some("de".into()), false).expect("single ok") {
            cmd::update_kernels::UpdateTarget::One(id) => assert_eq!(id, "de"),
            other => panic!("expected One, got {other:?}"),
        }
        match resolve_update_target(None, true).expect("all ok") {
            cmd::update_kernels::UpdateTarget::All => {}
            other => panic!("expected All, got {other:?}"),
        }
    }
}
