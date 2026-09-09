//! Synthetic router responses for offline browser review; never starts a server.

use std::path::{Path, PathBuf};

use tempfile::TempDir;
use vpnctld::router;

use crate::common::{fetch_html_with_cookie, seed, seed_dashboard_signals, state};

pub(crate) const ICON_PAGES: &[(&str, &str)] = &[
    ("dashboard", "/admin/"),
    ("servers", "/admin/servers"),
    ("server-status", "/admin/servers/s0"),
    ("server-activity", "/admin/servers/s0/activity"),
    ("server-protocols", "/admin/servers/s0/protocols"),
    ("server-grants", "/admin/servers/s0/grants"),
    ("server-setup", "/admin/servers/s0/setup"),
    ("users", "/admin/users"),
    ("user-overview", "/admin/users/u0"),
    ("user-delivery", "/admin/users/u0/delivery"),
    ("user-access", "/admin/users/u0/access"),
    ("user-activity", "/admin/users/u0/activity"),
    ("user-traffic", "/admin/users/u0/traffic"),
    ("monitoring", "/admin/monitoring"),
    ("alerts", "/admin/alerts"),
    ("audit", "/admin/audit"),
    ("settings", "/admin/settings"),
    ("settings-backups", "/admin/settings/backups"),
    ("settings-notifications", "/admin/settings/notifications"),
    ("settings-system", "/admin/settings/system"),
    ("boosty", "/admin/boosty"),
    ("wizard-start", "/admin/servers/new"),
    ("wizard-progress", "/admin/servers/new/step-2"),
];

/// Run only with an explicit output directory and an absent fixture-local key:
/// `VPNCTL_ICON_FIXTURES=/tmp/icons VPNCTLD_DEPLOY_KEY=/tmp/icons/absent-key \
/// cargo test -p vpnctld --test admin_smoke icon_fixtures::export_icon_fixtures \
/// -- --ignored --exact --nocapture`
///
/// Browser tooling should fulfill routes from manifest.json, serve repository
/// assets at /admin/assets/*, and mock EventSource BEFORE loading these pages.
/// Do not follow forms or live-drift links against a daemon. HTML is unmodified.
#[tokio::test]
#[ignore = "exports synthetic HTML for offline browser review"]
async fn export_icon_fixtures() {
    let output = PathBuf::from(
        std::env::var_os("VPNCTL_ICON_FIXTURES")
            .expect("set VPNCTL_ICON_FIXTURES to an explicit fixture output directory"),
    );
    std::fs::create_dir_all(&output).unwrap();
    let output = output.canonicalize().unwrap();
    // Settings currently reads the deploy public key and lists backups even on
    // its appearance tab. Fail closed rather than touch any host's live data.
    let key = vpnctld::app::deploy_key_path();
    assert_eq!(
        key,
        output.join("absent-key"),
        "set VPNCTLD_DEPLOY_KEY to <canonical fixture directory>/absent-key"
    );
    assert!(
        std::fs::symlink_metadata(&key).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
    );
    assert!(
        std::fs::symlink_metadata(key.with_extension("pub"))
            .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
    );
    assert!(
        std::fs::symlink_metadata(Path::new(vpnctld::app::DEFAULT_BACKUP_DIR))
            .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "export on a development host without a live backup directory"
    );
    assert!(
        std::env::var_os("VPNCTLD_REFERENCE_SSH_KEY").is_none(),
        "unset VPNCTLD_REFERENCE_SSH_KEY for synthetic fixtures"
    );

    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 2, 2, &[(0, 0), (1, 0), (1, 1)]).await;
    seed_dashboard_signals(&s.inv).await;
    let placeholder_password = "SYNTHETIC-NOT-A-CREDENTIAL";
    let session = s.wizard.insert(
        "192.0.2.42".into(),
        "root".into(),
        placeholder_password.into(),
        22,
    );
    let app = router(s);
    let mut pages = Vec::new();
    for theme in ["default", "newsprint", "foxed", "ink"] {
        for lang in ["en", "ru"] {
            let relative_dir = format!("{theme}/{lang}");
            std::fs::create_dir_all(output.join(&relative_dir)).unwrap();
            let cookie =
                format!("vpnctl_theme={theme}; vpnctl_lang={lang}; vpnctl_wizard={session}");
            for &(name, route) in ICON_PAGES {
                // GET only: no SSE, POST, drift=live, startup pollers or SSH.
                let html = fetch_html_with_cookie(app.clone(), route, &cookie).await;
                assert!(!html.contains(placeholder_password));
                assert!(html.contains(&format!("<html lang=\"{lang}\"")));
                let file = format!("{relative_dir}/{name}.html");
                std::fs::write(output.join(&file), html).unwrap();
                pages.push(serde_json::json!({
                    "name": name, "route": route, "theme": theme, "lang": lang, "file": file,
                }));
            }
        }
    }
    let manifest = serde_json::json!({
        "synthetic": true,
        "html": "unmodified router responses from common::state/seed",
        "assets": {"url_prefix": "/admin/assets/", "repository_directory": "daemon/assets/"},
        "browser": {"mock_event_source": true, "block_unmapped_requests": true},
        "pages": pages,
    });
    std::fs::write(
        output.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
    println!(
        "Exported {} synthetic HTML pages to {}",
        pages.len(),
        output.display()
    );
}
