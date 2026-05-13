//! Helpers for human / JSON output.

use crate::OutputFormat;
use comfy_table::{Cell, Row, Table, presets::UTF8_FULL};
use serde::Serialize;
use std::path::{Path, PathBuf};

/// Resolve the inventory DB path. Order:
///
/// 1. `--db <path>` flag (passed in)
/// 2. `VPNCTL_DB` env (already merged by clap into the flag)
/// 3. `$XDG_DATA_HOME/vpnctl/inv.db` (or `~/.local/share/vpnctl/inv.db`)
pub(crate) fn resolve_db_path(flag: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    if let Some(p) = flag {
        if let Some(parent) = p.parent() {
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
    if !p.exists() {
        std::fs::create_dir_all(p)?;
    }
    Ok(())
}

/// Print `val` either as JSON (single-line stable order) or via `f` (text).
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

/// Build a comfy-table with a UTF-8 preset and given headers + rows.
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
