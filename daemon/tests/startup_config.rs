#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::net::{SocketAddr, TcpListener};
    use std::path::Path;
    use std::process::Command;

    fn startup_command(root: &Path, addr: SocketAddr) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_vpnctld"));
        command
            .current_dir(root)
            .arg("--db")
            .arg(root.join("inv.db"))
            .arg("--addr")
            .arg(addr.to_string())
            .env_remove("VPNCTLD_TRUSTED_PROXIES")
            .env_remove("VPNCTLD_ADMIN_USER")
            .env_remove("VPNCTLD_ADMIN_PASSWORD")
            .env("VPNCTLD_DEPLOY_KEY", root.join("deploy"))
            .env("VPNCTLD_BACKUP_DIR", root.join("backups"));
        command
    }

    #[test]
    fn startup_rejects_invalid_trusted_proxy_before_opening_inventory() {
        let dir = tempfile::tempdir().unwrap();
        // An occupied address guarantees exit even if startup validation regresses.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let output = startup_command(dir.path(), listener.local_addr().unwrap())
            .env("VPNCTLD_TRUSTED_PROXIES", "127.0.0.1,10.0.0.0/33")
            .output()
            .unwrap();
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success());
        assert!(error.contains("VPNCTLD_TRUSTED_PROXIES"), "{error}");
        assert!(error.contains("10.0.0.0/33"), "{error}");
        assert!(!dir.path().join("inv.db").exists());
        assert!(!dir.path().join("deploy").exists());
    }

    #[test]
    fn startup_rejects_each_missing_required_admin_asset() {
        for missing in ["admin.js", "admin.css", "icons.svg", "favicon.svg"] {
            let dir = tempfile::tempdir().unwrap();
            let assets = dir.path().join("assets");
            std::fs::create_dir(&assets).unwrap();
            for name in ["admin.js", "admin.css", "icons.svg", "favicon.svg"] {
                if name != missing {
                    std::fs::write(assets.join(name), "test asset").unwrap();
                }
            }
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let output = startup_command(dir.path(), listener.local_addr().unwrap())
                .output()
                .unwrap();
            let error = String::from_utf8_lossy(&output.stderr);
            assert!(!output.status.success());
            assert!(error.contains("required admin asset"), "{error}");
            assert!(error.contains(missing), "{error}");
            assert!(!dir.path().join("inv.db").exists());
            assert!(!dir.path().join("deploy").exists());
        }
    }
}
