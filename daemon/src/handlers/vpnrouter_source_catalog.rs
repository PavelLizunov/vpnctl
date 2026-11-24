use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, ensure};
use serde::{Deserialize, Serialize};

use super::vpnrouter_assistant_step::{CrashArea, CrashEvidence, CrashFault, CrashSignal};

pub(super) const MAX_CATALOG_BYTES: usize = 512 * 1024;
pub(super) const MAX_RELEASES: usize = 64;
pub(super) const MAX_TARGETS: usize = 8;
pub(super) const MAX_EXCERPTS: usize = 24;
pub(super) const MAX_EXCERPT_LINES: u32 = 48;
pub(super) const MAX_EXCERPT_BYTES: usize = 4096;
pub(super) const MAX_PROMPT_EXCERPTS: usize = 12;
pub(super) const MAX_PROMPT_SOURCE_BYTES: usize = 24 * 1024;

const ENV_NAME: &str = "VPNCTLD_VPNROUTER_SOURCE_CATALOG";

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub(super) enum Platform {
    Windows,
    Linux,
    Macos,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub(super) enum Arch {
    X64,
    Arm64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogFile {
    schema: u32,
    releases: Vec<Release>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Release {
    pub(super) version: String,
    pub(super) commit: String,
    pub(super) targets: Vec<Target>,
    pub(super) excerpts: Vec<Excerpt>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Target {
    platform: Platform,
    arch: Arch,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Excerpt {
    pub(super) path: String,
    pub(super) first: u32,
    pub(super) last: u32,
    pub(super) text: String,
    #[serde(default)]
    pub(super) areas: Vec<CrashArea>,
    #[serde(default)]
    pub(super) signals: Vec<CrashSignal>,
    #[serde(default)]
    pub(super) faults: Vec<CrashFault>,
}

type BuildKey = (String, String, Platform, Arch);

#[derive(Debug)]
pub(super) struct SourceCatalog {
    releases: Vec<Release>,
    index: HashMap<BuildKey, usize>,
}

pub(super) enum CatalogStatus {
    Disabled,
    Unavailable,
    Ready(Arc<SourceCatalog>),
}

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct EvidenceSelection {
    pub(super) fault: Option<CrashFault>,
    pub(super) area: Option<CrashArea>,
    pub(super) signal: Option<CrashSignal>,
}

impl EvidenceSelection {
    pub(super) fn from_crash(crash: &CrashEvidence) -> Self {
        Self {
            fault: (!matches!(crash.fault, CrashFault::Unknown)).then_some(crash.fault),
            area: (!matches!(crash.area, CrashArea::Unknown)).then_some(crash.area),
            signal: (!matches!(crash.signal, CrashSignal::None)).then_some(crash.signal),
        }
    }
}

impl SourceCatalog {
    pub(super) fn from_env() -> CatalogStatus {
        let Some(path) = std::env::var_os(ENV_NAME) else {
            return CatalogStatus::Disabled;
        };
        let path = PathBuf::from(path);
        match Self::load_trusted(&path) {
            Ok(catalog) => CatalogStatus::Ready(Arc::new(catalog)),
            Err(error) => {
                tracing::warn!(
                    target: "vpnctld::assistant",
                    path = %path.display(),
                    %error,
                    "VPNRouter source catalog is unavailable"
                );
                CatalogStatus::Unavailable
            }
        }
    }

    pub(super) fn parse(bytes: &[u8]) -> anyhow::Result<Self> {
        ensure!(
            bytes.len() <= MAX_CATALOG_BYTES,
            "source catalog exceeds {MAX_CATALOG_BYTES} bytes"
        );
        let file: CatalogFile =
            serde_json::from_slice(bytes).context("source catalog is not valid JSON")?;
        ensure!(file.schema == 1, "unsupported source catalog schema");
        ensure!(
            (1..=MAX_RELEASES).contains(&file.releases.len()),
            "source catalog requires 1..={MAX_RELEASES} releases"
        );

        let mut releases = Vec::with_capacity(file.releases.len());
        let mut index = HashMap::new();
        for release in file.releases {
            release.validate()?;
            let release_index = releases.len();
            for target in &release.targets {
                let key = (
                    release.version.clone(),
                    release.commit.clone(),
                    target.platform,
                    target.arch,
                );
                ensure!(
                    index.insert(key, release_index).is_none(),
                    "source catalog contains a duplicate build mapping"
                );
            }
            releases.push(release);
        }
        Ok(Self { releases, index })
    }

    pub(super) fn lookup(
        &self,
        version: &str,
        commit: &str,
        platform: Platform,
        arch: Arch,
    ) -> Option<&Release> {
        let key = (version.to_owned(), commit.to_owned(), platform, arch);
        self.index
            .get(&key)
            .and_then(|index| self.releases.get(*index))
    }

    fn load_trusted(path: &Path) -> anyhow::Result<Self> {
        ensure!(path.is_absolute(), "source catalog path must be absolute");
        let metadata = std::fs::symlink_metadata(path)
            .with_context(|| format!("source catalog {} is not readable", path.display()))?;
        ensure!(
            !metadata.file_type().is_symlink(),
            "source catalog must not be a symlink"
        );
        // Reject a symlinked or writable parent before canonicalization can
        // redirect the read outside the service-controlled path.
        check_trusted_ancestors(path)?;
        check_trusted(&metadata, false)?;
        let path = std::fs::canonicalize(path)
            .with_context(|| format!("source catalog {} is not readable", path.display()))?;
        check_trusted_ancestors(&path)?;

        let file = std::fs::File::open(&path)
            .with_context(|| format!("source catalog {} is not readable", path.display()))?;
        let metadata = file.metadata().with_context(|| {
            format!("source catalog {} metadata is unavailable", path.display())
        })?;
        check_trusted(&metadata, false)?;
        let mut bytes = Vec::new();
        file.take((MAX_CATALOG_BYTES as u64) + 1)
            .read_to_end(&mut bytes)
            .with_context(|| format!("source catalog {} is not readable", path.display()))?;
        Self::parse(&bytes)
    }
}

impl Release {
    pub(super) fn prompt_excerpts(&self, selection: &EvidenceSelection) -> Vec<&Excerpt> {
        let mut candidates: Vec<(u8, usize, &Excerpt)> = self
            .excerpts
            .iter()
            .enumerate()
            .filter_map(|(index, excerpt)| {
                let score = excerpt.score(selection);
                (score > 0).then_some((score, index, excerpt))
            })
            .collect();
        candidates.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(&right.1)));

        let mut selected = Vec::new();
        let mut bytes = 0usize;
        for (_, _, excerpt) in candidates {
            if selected.len() >= MAX_PROMPT_EXCERPTS {
                break;
            }
            let Some(next) = bytes.checked_add(excerpt.text.len()) else {
                break;
            };
            if next > MAX_PROMPT_SOURCE_BYTES {
                continue;
            }
            bytes = next;
            selected.push(excerpt);
        }
        selected
    }

    fn validate(&self) -> anyhow::Result<()> {
        ensure!(
            valid_version(&self.version),
            "invalid source catalog version"
        );
        ensure!(valid_commit(&self.commit), "invalid source catalog commit");
        ensure!(
            !self.targets.is_empty() && self.targets.len() <= MAX_TARGETS,
            "invalid source catalog target count"
        );
        let mut targets = HashSet::new();
        for target in &self.targets {
            ensure!(
                targets.insert((target.platform, target.arch)),
                "source catalog contains a duplicate target"
            );
        }
        ensure!(
            !self.excerpts.is_empty() && self.excerpts.len() <= MAX_EXCERPTS,
            "invalid source catalog excerpt count"
        );
        let mut excerpts = HashSet::new();
        for excerpt in &self.excerpts {
            excerpt.validate()?;
            ensure!(
                excerpts.insert((excerpt.path.as_str(), excerpt.first, excerpt.last)),
                "source catalog contains a duplicate excerpt"
            );
        }
        Ok(())
    }
}

impl Excerpt {
    fn score(&self, selection: &EvidenceSelection) -> u8 {
        if self.areas.is_empty() && self.signals.is_empty() && self.faults.is_empty() {
            return 1;
        }
        let mut score = 0;
        if selection
            .area
            .is_some_and(|area| self.areas.contains(&area))
        {
            score += 4;
        }
        if selection
            .signal
            .is_some_and(|signal| self.signals.contains(&signal))
        {
            score += 8;
        }
        if selection
            .fault
            .is_some_and(|fault| self.faults.contains(&fault))
        {
            score += 2;
        }
        score
    }

    fn validate(&self) -> anyhow::Result<()> {
        ensure!(valid_source_path(&self.path), "invalid source excerpt path");
        ensure!(
            self.areas.len() <= 5
                && self
                    .areas
                    .iter()
                    .enumerate()
                    .all(|(index, area)| !self.areas[..index].contains(area)),
            "source excerpt has invalid area selectors"
        );
        ensure!(
            self.signals.len() <= 4
                && self
                    .signals
                    .iter()
                    .enumerate()
                    .all(|(index, signal)| !self.signals[..index].contains(signal)),
            "source excerpt has invalid signal selectors"
        );
        ensure!(
            self.faults.len() <= 9
                && self
                    .faults
                    .iter()
                    .enumerate()
                    .all(|(index, fault)| !self.faults[..index].contains(fault)),
            "source excerpt has invalid fault selectors"
        );
        ensure!(self.first >= 1, "invalid source excerpt line number");
        ensure!(self.last >= self.first, "invalid source excerpt line range");
        let lines = u64::from(self.last) - u64::from(self.first) + 1;
        ensure!(
            lines <= u64::from(MAX_EXCERPT_LINES),
            "source excerpt exceeds {MAX_EXCERPT_LINES} lines"
        );
        ensure!(
            !self.text.is_empty() && self.text.len() <= MAX_EXCERPT_BYTES,
            "source excerpt exceeds {MAX_EXCERPT_BYTES} bytes"
        );
        ensure!(
            self.text.split('\n').count() as u64 == lines,
            "source excerpt text does not match its line range"
        );
        ensure!(
            !self.text.contains('\r'),
            "source excerpt text must use LF line endings"
        );
        ensure!(
            self.text
                .chars()
                .all(|ch| !ch.is_control() || matches!(ch, '\n' | '\t')),
            "source excerpt contains a control character"
        );
        Ok(())
    }
}

pub(super) fn valid_version(version: &str) -> bool {
    if version.is_empty() || version.len() > 32 {
        return false;
    }
    let (core, revision) = match version.split_once("-r") {
        Some((core, revision)) => (core, Some(revision)),
        None => (version, None),
    };
    if core.contains('-') {
        return false;
    }
    if let Some(revision) = revision
        && (revision.is_empty()
            || revision.len() > 6
            || !revision.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return false;
    }
    let mut components = core.split('.');
    let (Some(major), Some(minor), Some(patch), None) = (
        components.next(),
        components.next(),
        components.next(),
        components.next(),
    ) else {
        return false;
    };
    [major, minor, patch].into_iter().all(|component| {
        !component.is_empty()
            && component.len() <= 6
            && component.bytes().all(|byte| byte.is_ascii_digit())
    })
}

pub(super) fn valid_commit(commit: &str) -> bool {
    commit.len() == 40
        && commit
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

pub(super) fn valid_source_path(path: &str) -> bool {
    (1..=200).contains(&path.len())
        && (path.starts_with("VPNRouter.Core/") || path.starts_with("VPNRouter.App/"))
        && path.ends_with(".cs")
        && !path.contains('\\')
        && path.split('/').all(|component| {
            !component.is_empty()
                && component != "."
                && component != ".."
                && component
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
        })
}

#[cfg(unix)]
fn check_trusted(metadata: &std::fs::Metadata, directory: bool) -> anyhow::Result<()> {
    use std::os::unix::fs::MetadataExt;

    ensure!(metadata.uid() == 0, "source catalog must be root-owned");
    ensure!(
        metadata.mode() & 0o022 == 0,
        "source catalog must not be group/world writable"
    );
    ensure!(
        if directory {
            metadata.is_dir()
        } else {
            metadata.is_file()
        },
        "source catalog has the wrong file type"
    );
    Ok(())
}

#[cfg(not(unix))]
fn check_trusted(metadata: &std::fs::Metadata, directory: bool) -> anyhow::Result<()> {
    ensure!(
        if directory {
            metadata.is_dir()
        } else {
            metadata.is_file()
        },
        "source catalog has the wrong file type"
    );
    Ok(())
}

fn check_trusted_ancestors(path: &Path) -> anyhow::Result<()> {
    for parent in path
        .ancestors()
        .skip(1)
        .take_while(|parent| !parent.as_os_str().is_empty())
    {
        let metadata = std::fs::symlink_metadata(parent).with_context(|| {
            format!("source catalog parent {} is not readable", parent.display())
        })?;
        ensure!(
            !metadata.file_type().is_symlink(),
            "source catalog parent must not be a symlink"
        );
        check_trusted(&metadata, true)?;
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn catalog() -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schema": 1,
            "releases": [{
                "version": "2.51.0-r2",
                "commit": "0123456789abcdef0123456789abcdef01234567",
                "targets": [
                    {"platform": "windows", "arch": "x64"},
                    {"platform": "linux", "arch": "arm64"}
                ],
                "excerpts": [{
                    "path": "VPNRouter.Core/Services/Example.cs",
                    "first": 15,
                    "last": 17,
                    "text": "line 15\nline 16\nline 17"
                }]
            }]
        }))
        .unwrap()
    }

    fn crash(fault: CrashFault, area: CrashArea, signal: CrashSignal) -> CrashEvidence {
        CrashEvidence {
            fatal: true,
            fault,
            area,
            signal,
        }
    }

    #[test]
    fn lookup_requires_the_exact_version_commit_platform_and_arch() {
        let catalog = SourceCatalog::parse(&catalog()).unwrap();
        let commit = "0123456789abcdef0123456789abcdef01234567";
        assert!(
            catalog
                .lookup("2.51.0-r2", commit, Platform::Windows, Arch::X64)
                .is_some()
        );
        assert!(
            catalog
                .lookup("2.51.0-r2", commit, Platform::Linux, Arch::Arm64)
                .is_some()
        );
        for (version, candidate, platform, arch) in [
            ("2.51.0-r3", commit, Platform::Windows, Arch::X64),
            (
                "2.51.0-r2",
                "1123456789abcdef0123456789abcdef01234567",
                Platform::Windows,
                Arch::X64,
            ),
            ("2.51.0-r2", commit, Platform::Macos, Arch::X64),
            ("2.51.0-r2", commit, Platform::Windows, Arch::Arm64),
        ] {
            assert!(
                catalog.lookup(version, candidate, platform, arch).is_none(),
                "{version} {candidate} {platform:?} {arch:?}"
            );
        }
    }

    #[test]
    fn catalog_rejects_unsafe_paths_ranges_text_and_duplicates() {
        for (path, first, last, text) in [
            ("VPNRouter.Core/../Secrets.cs", 1, 1, "secret".to_owned()),
            ("Other/Example.cs", 1, 1, "line".to_owned()),
            ("VPNRouter.Core/Example.cs", 0, 1, "line".to_owned()),
            ("VPNRouter.Core/Example.cs", 2, 1, "line".to_owned()),
            (
                "VPNRouter.Core/Example.cs",
                1,
                2,
                "only one line".to_owned(),
            ),
            ("VPNRouter.Core/Example.cs", 1, 1, "bad\rline".to_owned()),
            (
                "VPNRouter.Core/Example.cs",
                1,
                1,
                "bad\u{0007}line".to_owned(),
            ),
            (
                "VPNRouter.Core/Example.cs",
                1,
                49,
                (1..=49)
                    .map(|n| n.to_string())
                    .collect::<Vec<_>>()
                    .join("\n"),
            ),
        ] {
            let mut value: serde_json::Value = serde_json::from_slice(&catalog()).unwrap();
            value["releases"][0]["excerpts"][0]["path"] = serde_json::json!(path);
            value["releases"][0]["excerpts"][0]["first"] = serde_json::json!(first);
            value["releases"][0]["excerpts"][0]["last"] = serde_json::json!(last);
            value["releases"][0]["excerpts"][0]["text"] = serde_json::json!(text);
            assert!(
                SourceCatalog::parse(&serde_json::to_vec(&value).unwrap()).is_err(),
                "{path} {first}..{last}"
            );
        }

        let mut duplicate: serde_json::Value = serde_json::from_slice(&catalog()).unwrap();
        duplicate["releases"][0]["targets"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({"platform": "windows", "arch": "x64"}));
        assert!(SourceCatalog::parse(&serde_json::to_vec(&duplicate).unwrap()).is_err());

        let mut duplicate_selector: serde_json::Value = serde_json::from_slice(&catalog()).unwrap();
        duplicate_selector["releases"][0]["excerpts"][0]["areas"] =
            serde_json::json!(["routing", "routing"]);
        assert!(SourceCatalog::parse(&serde_json::to_vec(&duplicate_selector).unwrap()).is_err());

        let mut duplicate: serde_json::Value = serde_json::from_slice(&catalog()).unwrap();
        let excerpt = duplicate["releases"][0]["excerpts"][0].clone();
        duplicate["releases"][0]["excerpts"]
            .as_array_mut()
            .unwrap()
            .push(excerpt);
        assert!(SourceCatalog::parse(&serde_json::to_vec(&duplicate).unwrap()).is_err());

        let mut duplicate: serde_json::Value = serde_json::from_slice(&catalog()).unwrap();
        let first = duplicate["releases"][0].clone();
        duplicate["releases"].as_array_mut().unwrap().push(first);
        assert!(SourceCatalog::parse(&serde_json::to_vec(&duplicate).unwrap()).is_err());
    }

    #[test]
    fn catalog_rejects_unknown_fields_and_invalid_versions() {
        let mut value: serde_json::Value = serde_json::from_slice(&catalog()).unwrap();
        value["extra"] = serde_json::json!(true);
        assert!(SourceCatalog::parse(&serde_json::to_vec(&value).unwrap()).is_err());

        for version in [
            "",
            "2.51",
            "2.51.0.1",
            "2.51.0-r",
            "2.51.0-rx",
            "2.51.0-rc2",
            "2..0",
            "2.51.0-r2-extra",
        ] {
            assert!(!valid_version(version), "{version}");
        }
        for version in ["0.0.0", "2.51.0", "2.51.0-r2", "2026.11.24-r12"] {
            assert!(valid_version(version), "{version}");
        }
    }

    #[test]
    fn catalog_enforces_the_exact_file_and_entry_count_bounds() {
        let mut bytes = catalog();
        bytes.resize(MAX_CATALOG_BYTES, b' ');
        assert_eq!(bytes.len(), MAX_CATALOG_BYTES);
        assert!(SourceCatalog::parse(&bytes).is_ok());
        bytes.push(b' ');
        assert!(SourceCatalog::parse(&bytes).is_err());

        let mut releases = Vec::new();
        for index in 0..MAX_RELEASES {
            releases.push(serde_json::json!({
                "version": format!("2.51.{index}"),
                "commit": "0123456789abcdef0123456789abcdef01234567",
                "targets": [{"platform": "windows", "arch": "x64"}],
                "excerpts": [{
                    "path": "VPNRouter.Core/Services/Example.cs",
                    "first": 1,
                    "last": 1,
                    "text": "line"
                }]
            }));
        }
        let mut value = serde_json::json!({"schema": 1, "releases": releases});
        assert!(SourceCatalog::parse(&serde_json::to_vec(&value).unwrap()).is_ok());
        value["releases"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({
                "version": "2.51.64",
                "commit": "0123456789abcdef0123456789abcdef01234567",
                "targets": [{"platform": "windows", "arch": "x64"}],
                "excerpts": [{
                    "path": "VPNRouter.Core/Services/Example.cs",
                    "first": 1,
                    "last": 1,
                    "text": "line"
                }]
            }));
        assert!(SourceCatalog::parse(&serde_json::to_vec(&value).unwrap()).is_err());

        let mut value: serde_json::Value = serde_json::from_slice(&catalog()).unwrap();
        value["releases"] = serde_json::json!([]);
        assert!(SourceCatalog::parse(&serde_json::to_vec(&value).unwrap()).is_err());

        let mut excerpts = Vec::new();
        for index in 0..MAX_EXCERPTS {
            excerpts.push(serde_json::json!({
                "path": format!("VPNRouter.Core/Services/Excerpt{index}.cs"),
                "first": 1,
                "last": 1,
                "text": "line"
            }));
        }
        let mut value: serde_json::Value = serde_json::from_slice(&catalog()).unwrap();
        value["releases"][0]["excerpts"] = serde_json::json!(excerpts);
        assert!(SourceCatalog::parse(&serde_json::to_vec(&value).unwrap()).is_ok());
        value["releases"][0]["excerpts"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({
                "path": "VPNRouter.Core/Services/Overflow.cs",
                "first": 1,
                "last": 1,
                "text": "line"
            }));
        assert!(SourceCatalog::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    }

    #[test]
    fn excerpt_caps_allow_exactly_4096_bytes_and_48_lines() {
        let mut value: serde_json::Value = serde_json::from_slice(&catalog()).unwrap();
        value["releases"][0]["excerpts"][0]["text"] =
            serde_json::json!("a".repeat(MAX_EXCERPT_BYTES));
        value["releases"][0]["excerpts"][0]["first"] = serde_json::json!(1);
        value["releases"][0]["excerpts"][0]["last"] = serde_json::json!(1);
        assert!(SourceCatalog::parse(&serde_json::to_vec(&value).unwrap()).is_ok());

        value["releases"][0]["excerpts"][0]["text"] =
            serde_json::json!("a".repeat(MAX_EXCERPT_BYTES + 1));
        assert!(SourceCatalog::parse(&serde_json::to_vec(&value).unwrap()).is_err());

        let lines = |count: u32| {
            (1..=count)
                .map(|line| line.to_string())
                .collect::<Vec<_>>()
                .join("\n")
        };
        value["releases"][0]["excerpts"][0]["text"] = serde_json::json!(lines(MAX_EXCERPT_LINES));
        value["releases"][0]["excerpts"][0]["last"] = serde_json::json!(MAX_EXCERPT_LINES);
        assert!(SourceCatalog::parse(&serde_json::to_vec(&value).unwrap()).is_ok());

        value["releases"][0]["excerpts"][0]["text"] =
            serde_json::json!(lines(MAX_EXCERPT_LINES + 1));
        value["releases"][0]["excerpts"][0]["last"] = serde_json::json!(MAX_EXCERPT_LINES + 1);
        assert!(SourceCatalog::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    }

    #[test]
    fn prompt_selection_allows_exactly_24_kib_and_skips_the_next_excerpt() {
        let text = "a".repeat(MAX_EXCERPT_BYTES);
        let mut excerpts = Vec::new();
        for index in 0..(MAX_PROMPT_SOURCE_BYTES / MAX_EXCERPT_BYTES) {
            excerpts.push(serde_json::json!({
                "path": format!("VPNRouter.Core/Services/Budget{index}.cs"),
                "first": 1,
                "last": 1,
                "text": text.clone()
            }));
        }
        let mut value: serde_json::Value = serde_json::from_slice(&catalog()).unwrap();
        value["releases"][0]["excerpts"] = serde_json::json!(excerpts);
        let catalog = SourceCatalog::parse(&serde_json::to_vec(&value).unwrap()).unwrap();
        let selected = catalog.releases[0].prompt_excerpts(&EvidenceSelection::default());
        assert_eq!(selected.len(), MAX_PROMPT_SOURCE_BYTES / MAX_EXCERPT_BYTES);
        assert_eq!(
            selected
                .iter()
                .map(|excerpt| excerpt.text.len())
                .sum::<usize>(),
            MAX_PROMPT_SOURCE_BYTES
        );

        value["releases"][0]["excerpts"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({
                "path": "VPNRouter.Core/Services/BudgetExtra.cs",
                "first": 1,
                "last": 1,
                "text": "x"
            }));
        let catalog = SourceCatalog::parse(&serde_json::to_vec(&value).unwrap()).unwrap();
        let selected = catalog.releases[0].prompt_excerpts(&EvidenceSelection::default());
        assert_eq!(selected.len(), MAX_PROMPT_SOURCE_BYTES / MAX_EXCERPT_BYTES);
        assert_eq!(
            selected
                .iter()
                .map(|excerpt| excerpt.text.len())
                .sum::<usize>(),
            MAX_PROMPT_SOURCE_BYTES
        );
    }

    #[test]
    fn prompt_selection_is_bounded_and_skips_oversized_excerpts() {
        let mut value: serde_json::Value = serde_json::from_slice(&catalog()).unwrap();
        let excerpt = value["releases"][0]["excerpts"][0].clone();
        value["releases"][0]["excerpts"] = serde_json::json!([]);
        for index in 0..(MAX_PROMPT_EXCERPTS + 2) {
            let mut excerpt = excerpt.clone();
            excerpt["first"] = serde_json::json!(index + 1);
            excerpt["last"] = serde_json::json!(index + 3);
            value["releases"][0]["excerpts"]
                .as_array_mut()
                .unwrap()
                .push(excerpt);
        }
        let catalog = SourceCatalog::parse(&serde_json::to_vec(&value).unwrap()).unwrap();
        let release = &catalog.releases[0];
        let selected = release.prompt_excerpts(&EvidenceSelection::from_crash(&crash(
            CrashFault::Io,
            CrashArea::Routing,
            CrashSignal::None,
        )));
        assert_eq!(selected.len(), MAX_PROMPT_EXCERPTS);
        assert!(
            selected
                .iter()
                .map(|excerpt| excerpt.text.len())
                .sum::<usize>()
                <= MAX_PROMPT_SOURCE_BYTES
        );
    }

    #[test]
    fn prompt_selection_prioritizes_the_observed_area_and_signal_beyond_the_budget() {
        let mut value: serde_json::Value = serde_json::from_slice(&catalog()).unwrap();
        value["releases"][0]["excerpts"] = serde_json::json!([]);
        for index in 0..12 {
            value["releases"][0]["excerpts"]
                .as_array_mut()
                .unwrap()
                .push(serde_json::json!({
                    "path": format!("VPNRouter.Core/Services/Routing{index}.cs"),
                    "first": 1,
                    "last": 3,
                    "text": "one\ntwo\nthree",
                    "areas": ["routing"]
                }));
        }
        for index in 0..2 {
            value["releases"][0]["excerpts"]
                .as_array_mut()
                .unwrap()
                .push(serde_json::json!({
                    "path": format!("VPNRouter.Core/Services/Startup{index}.cs"),
                    "first": 1,
                    "last": 3,
                    "text": "one\ntwo\nthree",
                    "areas": ["startup"],
                    "signals": ["tun_busy"]
                }));
        }
        let catalog = SourceCatalog::parse(&serde_json::to_vec(&value).unwrap()).unwrap();
        let release = &catalog.releases[0];

        let routing = release.prompt_excerpts(&EvidenceSelection::from_crash(&crash(
            CrashFault::Io,
            CrashArea::Routing,
            CrashSignal::None,
        )));
        assert_eq!(routing.len(), 12);
        assert!(
            routing
                .iter()
                .all(|excerpt| excerpt.path.contains("Routing"))
        );

        let startup = release.prompt_excerpts(&EvidenceSelection::from_crash(&crash(
            CrashFault::Network,
            CrashArea::Startup,
            CrashSignal::TunBusy,
        )));
        assert_eq!(startup.len(), 2);
        assert!(
            startup
                .iter()
                .all(|excerpt| excerpt.path.contains("Startup"))
        );
    }

    #[test]
    fn a_fault_only_match_outranks_twelve_preceding_fallbacks() {
        let mut excerpts = Vec::new();
        for index in 0..MAX_PROMPT_EXCERPTS {
            excerpts.push(serde_json::json!({
                "path": format!("VPNRouter.Core/Services/Fallback{index}.cs"),
                "first": 1,
                "last": 1,
                "text": "line"
            }));
        }
        excerpts.push(serde_json::json!({
            "path": "VPNRouter.Core/Services/FaultOnly.cs",
            "first": 1,
            "last": 1,
            "text": "line",
            "faults": ["io"]
        }));
        let mut value: serde_json::Value = serde_json::from_slice(&catalog()).unwrap();
        value["releases"][0]["excerpts"] = serde_json::json!(excerpts);
        let catalog = SourceCatalog::parse(&serde_json::to_vec(&value).unwrap()).unwrap();
        let selected = catalog.releases[0].prompt_excerpts(&EvidenceSelection::from_crash(&crash(
            CrashFault::Io,
            CrashArea::Unknown,
            CrashSignal::None,
        )));

        let expected: Vec<String> =
            std::iter::once("VPNRouter.Core/Services/FaultOnly.cs".to_owned())
                .chain(
                    (0..MAX_PROMPT_EXCERPTS - 1)
                        .map(|index| format!("VPNRouter.Core/Services/Fallback{index}.cs")),
                )
                .collect();
        assert_eq!(
            selected
                .iter()
                .map(|excerpt| excerpt.path.as_str())
                .collect::<Vec<_>>(),
            expected.iter().map(String::as_str).collect::<Vec<_>>()
        );
    }

    #[cfg(unix)]
    #[test]
    fn trusted_loading_rejects_relative_missing_and_symlinked_paths() {
        assert!(SourceCatalog::load_trusted(Path::new("relative.json")).is_err());
        let directory = tempfile::tempdir().unwrap();
        assert!(SourceCatalog::load_trusted(&directory.path().join("missing.json")).is_err());
        let target = directory.path().join("catalog.json");
        std::fs::write(&target, catalog()).unwrap();
        let link = directory.path().join("link.json");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(SourceCatalog::load_trusted(&link).is_err());

        let real_parent = directory.path().join("real-parent");
        std::fs::create_dir(&real_parent).unwrap();
        std::fs::write(real_parent.join("catalog.json"), catalog()).unwrap();
        let linked_parent = directory.path().join("linked-parent");
        std::os::unix::fs::symlink(&real_parent, &linked_parent).unwrap();
        let error = SourceCatalog::load_trusted(&linked_parent.join("catalog.json"))
            .unwrap_err()
            .to_string();
        assert!(error.contains("parent must not be a symlink"), "{error}");
    }
}
