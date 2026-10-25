//! Inventory transactions must start with `BEGIN IMMEDIATE`.
//!
//! A deferred `BEGIN` that reads and then writes fails at once with
//! `SQLITE_BUSY` ("database is locked") in WAL mode when another connection
//! commits in between (e.g. the access-log writer after a `/sub` hit);
//! `busy_timeout` does not help because SQLite cannot wait out a stale snapshot.
//! `BEGIN IMMEDIATE` takes the write lock up front, so contenders wait instead.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;

fn rust_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn inventory_transactions_take_the_write_lock_up_front() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    let offenders: Vec<String> = files
        .iter()
        .flat_map(|path| {
            std::fs::read_to_string(path)
                .unwrap()
                .lines()
                .enumerate()
                .filter(|(_, line)| line.contains(".begin()"))
                .map(|(n, _)| format!("{}:{}", path.display(), n + 1))
                .collect::<Vec<_>>()
        })
        .collect();
    assert!(
        offenders.is_empty(),
        "use begin_with(\"BEGIN IMMEDIATE\") instead of a deferred begin(): {offenders:?}"
    );
}
