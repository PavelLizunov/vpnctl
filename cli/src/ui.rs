use crate::OutputFormat;
use comfy_table::{Cell, Row, Table, presets::UTF8_FULL};
use serde::Serialize;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

pub(crate) fn resolve_db_path(flag: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    if let Some(p) = flag {
        if let Some(parent) = p.parent()
            && !parent.as_os_str().is_empty()
        {
            ensure_dir(parent)?;
        }
        return Ok(p);
    }
    let dir = dirs::data_dir()
        .ok_or_else(|| anyhow::anyhow!("cannot resolve XDG data dir; pass --db explicitly"))?
        .join("vpnctl");
    ensure_dir(&dir)?;
    Ok(dir.join("inv.db"))
}

fn ensure_dir(p: &Path) -> anyhow::Result<()> {
    if !p.as_os_str().is_empty() && !p.exists() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(p)?;
    }
    Ok(())
}

pub(crate) fn print<T, F>(format: OutputFormat, val: &T, f: F) -> anyhow::Result<()>
where
    T: Serialize,
    F: FnOnce(&T) -> anyhow::Result<()>,
{
    match format {
        OutputFormat::Json => {
            let s = serde_json::to_string(val)?;
            println!("{s}");
            Ok(())
        }
        OutputFormat::Text => f(val),
    }
}

pub(crate) fn table<H, R>(headers: H, rows: impl IntoIterator<Item = R>) -> Table
where
    H: IntoIterator,
    H::Item: Into<Cell>,
    R: IntoIterator,
    R::Item: Into<Cell>,
{
    let mut t = Table::new();
    t.load_preset(UTF8_FULL);
    t.set_header(headers.into_iter().map(Into::into));
    for row in rows {
        let mut r = Row::new();
        for c in row {
            r.add_cell(c.into());
        }
        t.add_row(r);
    }
    t
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn resolve_db_path_bare_relative_path_does_not_fail() {
        let p = PathBuf::from("inv.db");
        let resolved = resolve_db_path(Some(p.clone())).expect("bare relative path must succeed");
        assert_eq!(resolved, p);
    }

    #[test]
    fn resolve_db_path_nested_relative_path_creates_parent() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let target = tmp.path().join("nested").join("sub").join("inv.db");
        assert!(!target.parent().unwrap().exists());
        let resolved = resolve_db_path(Some(target.clone())).expect("nested path must succeed");
        assert_eq!(resolved, target);
        assert!(target.parent().unwrap().exists());
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(target.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }

    #[test]
    fn resolve_db_path_none_resolves_to_xdg_default() {
        let resolved = resolve_db_path(None).expect("default resolution");
        assert!(resolved.ends_with(Path::new("vpnctl").join("inv.db")));
    }
}
