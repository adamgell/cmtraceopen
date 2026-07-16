//! Fixed-scope deployment-log discovery for ESP diagnostics.
//!
//! Discovery consumes only the embedded collector profile, the application's
//! existing Windows known-source catalog, fixed runtime temp roots, and log
//! paths observed on allowlisted installer processes. It has no user-supplied
//! filesystem root and never recurses.

use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{self, File, Metadata};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use cmtraceopen_parser::collector::env_expand::expand_env_vars;
use cmtraceopen_parser::collector::types::CollectionProfile;
use glob::{MatchOptions, Pattern};

pub const MAX_ROTATIONS_PER_KNOWN_LOG: usize = 3;
pub const MAX_KNOWN_ENTRIES_PROBED_PER_ROOT: usize = 512;
pub const MAX_TEMP_ENTRIES_INSPECTED_PER_ROOT: usize = 128;
pub const MAX_TEMP_ENTRIES_PROBED_PER_ROOT: usize = 4_096;
pub const MAX_ACTIVE_TAILS: usize = 16;
pub const MAX_INITIAL_READ_BYTES: u64 = 8 * 1024 * 1024;
pub const TEMP_LOOKBACK: Duration = Duration::from_secs(30 * 60);
pub const DISCOVERY_INTERVAL: Duration = Duration::from_secs(2);
pub const UPDATE_DEBOUNCE: Duration = Duration::from_millis(250);
pub const MAX_SESSION_DURATION: Duration = Duration::from_secs(8 * 60 * 60);

const SIGNATURE_BYTES: u64 = 4 * 1024;
#[cfg(any(target_os = "windows", test))]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

const PROFILE_FAMILIES: &[&str] = &[
    "intune-ime",
    "configmgr",
    "msi",
    "panther",
    "setup",
    "windows-update",
    "wpm",
];

#[cfg(target_os = "windows")]
const CURATED_WINDOWS_SOURCE_IDS: &[&str] = &[
    "windows-intune-ime-logs",
    "windows-configmgr-ccm-logs",
    "windows-configmgr-ccmsetup-logs",
    "windows-panther-setupact-log",
    "windows-panther-setuperr-log",
    "windows-reporting-events-log",
    "windows-deployment-logs-software",
    "windows-deployment-psadt",
    "windows-deployment-patchmypc-logs",
    "windows-deployment-patchmypc-install-logs",
    "windows-deployment-patchmypc-intune-logs",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoverySourceOrigin {
    EmbeddedKnown,
    CuratedKnown,
    Temp,
    ActiveProcess,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryRootKind {
    Known,
    Temp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryRootState {
    Available,
    Missing,
    PermissionDenied,
    ReparseRejected,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryRootCoverage {
    pub root: PathBuf,
    pub source_id: Option<String>,
    pub kind: DiscoveryRootKind,
    pub state: DiscoveryRootState,
    pub detail: Option<String>,
    /// Directory entries whose metadata/path safety was evaluated.
    pub entries_probed: usize,
    /// Safe candidates inspected by the source-specific bounded classifier.
    pub entries_inspected: usize,
    /// Candidates matched before cross-root canonical deduplication.
    pub entries_matched: usize,
    /// Entries rejected because enumeration, metadata, or path safety failed.
    pub entries_rejected: usize,
    pub truncated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KnownSourcePathKind {
    File,
    Folder,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownSourceSpec {
    pub source_id: String,
    pub family: String,
    pub root: PathBuf,
    pub patterns: Vec<String>,
    path_kind: KnownSourcePathKind,
    origin: DiscoverySourceOrigin,
}

impl KnownSourceSpec {
    pub fn folder<I, S>(
        source_id: impl Into<String>,
        family: impl Into<String>,
        root: impl AsRef<Path>,
        patterns: I,
    ) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            source_id: source_id.into(),
            family: family.into(),
            root: root.as_ref().to_path_buf(),
            patterns: patterns.into_iter().map(Into::into).collect(),
            path_kind: KnownSourcePathKind::Folder,
            origin: DiscoverySourceOrigin::CuratedKnown,
        }
    }

    fn file(
        source_id: impl Into<String>,
        family: impl Into<String>,
        path: impl AsRef<Path>,
        origin: DiscoverySourceOrigin,
    ) -> Option<Self> {
        let path = path.as_ref();
        Some(Self {
            source_id: source_id.into(),
            family: family.into(),
            root: path.parent()?.to_path_buf(),
            patterns: vec![path.file_name()?.to_string_lossy().into_owned()],
            path_kind: KnownSourcePathKind::File,
            origin,
        })
    }

    fn embedded_folder(
        source_id: impl Into<String>,
        family: impl Into<String>,
        root: impl AsRef<Path>,
        pattern: impl Into<String>,
    ) -> Self {
        Self {
            source_id: source_id.into(),
            family: family.into(),
            root: root.as_ref().to_path_buf(),
            patterns: vec![pattern.into()],
            path_kind: KnownSourcePathKind::Folder,
            origin: DiscoverySourceOrigin::EmbeddedKnown,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DiscoveryInput {
    pub known_sources: Vec<KnownSourceSpec>,
    pub temp_roots: Vec<PathBuf>,
    pub active_process_logs: Vec<PathBuf>,
    pub now: SystemTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredLogSource {
    pub path: PathBuf,
    pub source_id: String,
    pub family: String,
    pub origin: DiscoverySourceOrigin,
    pub priority: u8,
    pub is_current: bool,
    pub modified: Option<SystemTime>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DiscoveryResult {
    pub sources: Vec<DiscoveredLogSource>,
    pub temp_entries_probed: usize,
    pub temp_entries_inspected: usize,
    pub root_coverage: Vec<DiscoveryRootCoverage>,
}

#[derive(Debug, Clone)]
struct Candidate {
    source: DiscoveredLogSource,
    identity_key: String,
    rotation_key: String,
}

/// Converts the embedded profile's stable deployment families into fixed,
/// non-recursive source specifications. The profile remains the source of
/// truth for paths; discovery does not duplicate its catalog.
pub fn embedded_known_source_specs() -> Vec<KnownSourceSpec> {
    let profile = CollectionProfile::embedded();
    profile
        .logs
        .into_iter()
        .filter(|item| PROFILE_FAMILIES.contains(&item.family.as_str()))
        .filter_map(|item| {
            let expanded = native_path(&expand_env_vars(&item.source_pattern));
            let file_name = expanded.file_name()?.to_string_lossy().into_owned();
            let root = expanded.parent()?.to_path_buf();
            if path_has_wildcard(&root) {
                return None;
            }
            if has_wildcard(&file_name) {
                Some(KnownSourceSpec::embedded_folder(
                    item.id,
                    item.family,
                    root,
                    file_name,
                ))
            } else {
                KnownSourceSpec::file(
                    item.id,
                    item.family,
                    expanded,
                    DiscoverySourceOrigin::EmbeddedKnown,
                )
            }
        })
        .collect()
}

/// Returns the full production known-source set. Windows augments the embedded
/// profile with deployment entries from the app's existing known-source menu;
/// no second path catalog is maintained here.
pub fn default_known_source_specs() -> Vec<KnownSourceSpec> {
    let specs = embedded_known_source_specs();
    #[cfg(target_os = "windows")]
    {
        let mut specs = specs;
        specs.extend(curated_windows_known_source_specs());
        specs
    }
    #[cfg(not(target_os = "windows"))]
    {
        specs
    }
}

#[cfg(target_os = "windows")]
fn curated_windows_known_source_specs() -> Vec<KnownSourceSpec> {
    use crate::commands::file_ops::LogSource;
    use crate::commands::known_sources::{
        build_known_log_sources, KnownSourcePathKind as AppPathKind,
    };

    build_known_log_sources()
        .into_iter()
        .filter(|source| CURATED_WINDOWS_SOURCE_IDS.contains(&source.id.as_str()))
        .filter_map(|source| {
            let family = source
                .grouping
                .as_ref()
                .map(|grouping| grouping.family_id.clone())
                .unwrap_or_else(|| "windows-deployment".to_string());
            let LogSource::Known {
                default_path,
                path_kind,
                ..
            } = source.source
            else {
                return None;
            };
            match path_kind {
                AppPathKind::Folder => Some(KnownSourceSpec {
                    source_id: source.id,
                    family,
                    root: PathBuf::from(default_path),
                    patterns: source.file_patterns,
                    path_kind: KnownSourcePathKind::Folder,
                    origin: DiscoverySourceOrigin::CuratedKnown,
                }),
                AppPathKind::File => KnownSourceSpec::file(
                    source.id,
                    family,
                    default_path,
                    DiscoverySourceOrigin::CuratedKnown,
                ),
            }
        })
        .collect()
}

/// Builds only the four approved temp-root categories. `profile_directories`
/// comes from active ProfileList evidence and is converted to each user's
/// `AppData\\Local\\Temp`; no caller-provided search root is accepted by IPC.
pub fn build_runtime_temp_roots(
    windows_directory: &Path,
    current_temp: Option<&Path>,
    profile_directories: &[PathBuf],
) -> Vec<PathBuf> {
    let mut roots = vec![
        windows_directory.join("Temp"),
        windows_directory.join("System32/config/systemprofile/AppData/Local/Temp"),
    ];
    if let Some(current_temp) = current_temp {
        roots.push(current_temp.to_path_buf());
    }
    roots.extend(
        profile_directories
            .iter()
            .map(|profile| profile.join("AppData/Local/Temp")),
    );
    deduplicate_paths(roots)
}

pub fn runtime_discovery_input(
    profile_directories: &[PathBuf],
    active_process_logs: Vec<PathBuf>,
) -> DiscoveryInput {
    let windows_directory = std::env::var_os("WINDIR")
        .or_else(|| std::env::var_os("SystemRoot"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
    let current_temp = std::env::var_os("TEMP").map(PathBuf::from);
    DiscoveryInput {
        known_sources: default_known_source_specs(),
        temp_roots: build_runtime_temp_roots(
            &windows_directory,
            current_temp.as_deref(),
            profile_directories,
        ),
        active_process_logs,
        now: SystemTime::now(),
    }
}

pub fn discover_bounded_logs(input: &DiscoveryInput) -> DiscoveryResult {
    let mut candidates = Vec::new();
    let mut root_coverage = Vec::new();
    for spec in &input.known_sources {
        root_coverage.push(collect_known_candidates(spec, &mut candidates));
    }

    let mut temp_entries_probed = 0;
    let mut temp_entries_inspected = 0;
    for root in &input.temp_roots {
        let coverage = collect_temp_candidates(root, input.now, &mut candidates);
        temp_entries_probed += coverage.entries_probed;
        temp_entries_inspected += coverage.entries_inspected;
        root_coverage.push(coverage);
    }

    for path in &input.active_process_logs {
        if let Some((safe_path, metadata)) = safe_regular_file(path, None) {
            candidates.push(candidate(
                safe_path,
                "active-process-log".to_string(),
                "installer".to_string(),
                DiscoverySourceOrigin::ActiveProcess,
                metadata.modified().ok(),
            ));
        }
    }

    let mut best_by_path = BTreeMap::<String, Candidate>::new();
    for candidate in candidates {
        match best_by_path.get(&candidate.identity_key) {
            Some(existing) if candidate_cmp(existing, &candidate) != Ordering::Greater => {}
            _ => {
                best_by_path.insert(candidate.identity_key.clone(), candidate);
            }
        }
    }

    let mut candidates = best_by_path.into_values().collect::<Vec<_>>();
    candidates.sort_by(candidate_cmp);
    let mut rotation_counts = HashMap::<String, usize>::new();
    let mut sources = Vec::new();
    for candidate in candidates {
        if matches!(
            candidate.source.origin,
            DiscoverySourceOrigin::EmbeddedKnown | DiscoverySourceOrigin::CuratedKnown
        ) && !candidate.source.is_current
        {
            let count = rotation_counts
                .entry(candidate.rotation_key.clone())
                .or_default();
            if *count >= MAX_ROTATIONS_PER_KNOWN_LOG {
                continue;
            }
            *count += 1;
        }
        sources.push(candidate.source);
    }

    DiscoveryResult {
        sources,
        temp_entries_probed,
        temp_entries_inspected,
        root_coverage,
    }
}

fn collect_known_candidates(
    spec: &KnownSourceSpec,
    output: &mut Vec<Candidate>,
) -> DiscoveryRootCoverage {
    let mut coverage = DiscoveryRootCoverage {
        root: spec.root.clone(),
        source_id: Some(spec.source_id.clone()),
        kind: DiscoveryRootKind::Known,
        state: DiscoveryRootState::Available,
        detail: None,
        entries_probed: 0,
        entries_inspected: 0,
        entries_matched: 0,
        entries_rejected: 0,
        truncated: false,
    };
    let root_canonical = match safe_directory_root(&spec.root) {
        Ok(root) => root,
        Err(error) => {
            coverage.state = discovery_root_state(&error);
            coverage.detail = Some(error.to_string());
            return coverage;
        }
    };
    coverage.root = root_canonical.clone();

    let paths = match spec.path_kind {
        KnownSourcePathKind::File => {
            coverage.entries_probed = usize::from(!spec.patterns.is_empty());
            spec.patterns
                .first()
                .map(|file_name| vec![spec.root.join(file_name)])
                .unwrap_or_default()
        }
        KnownSourcePathKind::Folder => match fs::read_dir(&spec.root) {
            Ok(mut entries) => {
                let mut paths = Vec::new();
                while coverage.entries_probed < MAX_KNOWN_ENTRIES_PROBED_PER_ROOT {
                    let Some(entry) = entries.next() else {
                        break;
                    };
                    coverage.entries_probed += 1;
                    match entry {
                        Ok(entry) => paths.push(entry.path()),
                        Err(_) => coverage.entries_rejected += 1,
                    }
                }
                if entries.next().is_some() {
                    coverage.truncated = true;
                    coverage.detail = Some(format!(
                        "probed the bounded first {MAX_KNOWN_ENTRIES_PROBED_PER_ROOT} directory entries; known-source coverage is partial"
                    ));
                }
                paths
            }
            Err(error) => {
                coverage.state = discovery_root_state(&error);
                coverage.detail = Some(error.to_string());
                return coverage;
            }
        },
    };

    let matched_before = output.len();
    for path in paths {
        let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !matches_any_pattern(file_name, &spec.patterns) || !is_known_log_file(file_name) {
            continue;
        }
        let Some((safe_path, metadata)) = safe_regular_file(&path, Some(&root_canonical)) else {
            coverage.entries_rejected += 1;
            continue;
        };
        output.push(candidate(
            safe_path,
            spec.source_id.clone(),
            spec.family.clone(),
            spec.origin,
            metadata.modified().ok(),
        ));
        coverage.entries_inspected += 1;
    }
    coverage.entries_matched = output.len() - matched_before;
    coverage
}

fn collect_temp_candidates(
    root: &Path,
    now: SystemTime,
    output: &mut Vec<Candidate>,
) -> DiscoveryRootCoverage {
    let mut coverage = DiscoveryRootCoverage {
        root: root.to_path_buf(),
        source_id: None,
        kind: DiscoveryRootKind::Temp,
        state: DiscoveryRootState::Available,
        detail: None,
        entries_probed: 0,
        entries_inspected: 0,
        entries_matched: 0,
        entries_rejected: 0,
        truncated: false,
    };
    let root_canonical = match safe_directory_root(root) {
        Ok(root) => root,
        Err(error) => {
            coverage.state = discovery_root_state(&error);
            coverage.detail = Some(error.to_string());
            return coverage;
        }
    };
    coverage.root = root_canonical.clone();
    let mut directory = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) => {
            coverage.state = discovery_root_state(&error);
            coverage.detail = Some(error.to_string());
            return coverage;
        }
    };
    let mut entries = Vec::new();
    while coverage.entries_probed < MAX_TEMP_ENTRIES_PROBED_PER_ROOT {
        let Some(entry) = directory.next() else {
            break;
        };
        coverage.entries_probed += 1;
        let Ok(entry) = entry else {
            coverage.entries_rejected += 1;
            continue;
        };
        let path = entry.path();
        let Some((safe_path, metadata)) = safe_regular_file(&path, Some(&root_canonical)) else {
            coverage.entries_rejected += 1;
            continue;
        };
        let Ok(modified) = metadata.modified() else {
            coverage.entries_rejected += 1;
            continue;
        };
        entries.push((safe_path, metadata, modified));
    }
    if directory.next().is_some() {
        coverage.truncated = true;
        coverage.detail = Some(format!(
            "probed the bounded first {MAX_TEMP_ENTRIES_PROBED_PER_ROOT} directory entries; newest coverage is partial"
        ));
    }
    entries.sort_by(|left, right| {
        right
            .2
            .cmp(&left.2)
            .then_with(|| path_identity(&left.0).cmp(&path_identity(&right.0)))
    });
    entries.truncate(MAX_TEMP_ENTRIES_INSPECTED_PER_ROOT);
    coverage.entries_inspected = entries.len();

    let matched_before = output.len();
    for (path, _metadata, modified) in entries {
        let age = now.duration_since(modified).unwrap_or(Duration::ZERO);
        if age > TEMP_LOOKBACK {
            continue;
        }
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        if !is_high_signal_temp_name(file_name) && !has_installer_signature(&path) {
            continue;
        }
        output.push(candidate(
            path,
            "bounded-temp-log".to_string(),
            "temp-installer".to_string(),
            DiscoverySourceOrigin::Temp,
            Some(modified),
        ));
    }
    coverage.entries_matched = output.len() - matched_before;
    coverage
}

fn discovery_root_state(error: &std::io::Error) -> DiscoveryRootState {
    match error.kind() {
        std::io::ErrorKind::NotFound => DiscoveryRootState::Missing,
        std::io::ErrorKind::PermissionDenied => DiscoveryRootState::PermissionDenied,
        std::io::ErrorKind::InvalidInput if error.to_string().contains("reparse") => {
            DiscoveryRootState::ReparseRejected
        }
        _ => DiscoveryRootState::Failed,
    }
}

fn candidate(
    path: PathBuf,
    source_id: String,
    family: String,
    origin: DiscoverySourceOrigin,
    modified: Option<SystemTime>,
) -> Candidate {
    let is_current = is_current_log(&path, &family);
    let priority = match origin {
        DiscoverySourceOrigin::EmbeddedKnown | DiscoverySourceOrigin::CuratedKnown
            if family == "intune-ime" && is_current =>
        {
            0
        }
        DiscoverySourceOrigin::EmbeddedKnown | DiscoverySourceOrigin::CuratedKnown
            if family == "intune-ime" =>
        {
            2
        }
        DiscoverySourceOrigin::ActiveProcess => 1,
        DiscoverySourceOrigin::EmbeddedKnown | DiscoverySourceOrigin::CuratedKnown
            if is_current =>
        {
            3
        }
        DiscoverySourceOrigin::EmbeddedKnown | DiscoverySourceOrigin::CuratedKnown => 4,
        DiscoverySourceOrigin::Temp => 5,
    };
    Candidate {
        identity_key: path_identity(&path),
        rotation_key: rotation_identity(&path, &family),
        source: DiscoveredLogSource {
            path,
            source_id,
            family,
            origin,
            priority,
            is_current,
            modified,
        },
    }
}

fn candidate_cmp(left: &Candidate, right: &Candidate) -> Ordering {
    left.source
        .priority
        .cmp(&right.source.priority)
        .then_with(|| right.source.is_current.cmp(&left.source.is_current))
        .then_with(|| right.source.modified.cmp(&left.source.modified))
        .then_with(|| left.identity_key.cmp(&right.identity_key))
}

fn safe_regular_file(path: &Path, allowed_root: Option<&Path>) -> Option<(PathBuf, Metadata)> {
    let link_metadata = fs::symlink_metadata(path).ok()?;
    if link_metadata.file_type().is_symlink() || is_reparse_point(&link_metadata) {
        return None;
    }
    if !link_metadata.is_file() {
        return None;
    }
    let canonical = fs::canonicalize(path).ok()?;
    if let Some(root) = allowed_root {
        if !path_is_within_root_for_platform(&canonical, root, cfg!(target_os = "windows")) {
            return None;
        }
    }
    Some((canonical, link_metadata))
}

fn safe_directory_root(path: &Path) -> std::io::Result<PathBuf> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "discovery root is a symlink or reparse point",
        ));
    }
    if !metadata.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "discovery root is not a directory",
        ));
    }
    fs::canonicalize(path)
}

#[cfg(target_os = "windows")]
fn is_reparse_point(metadata: &Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    file_attributes_indicate_reparse(metadata.file_attributes())
}

#[cfg(not(target_os = "windows"))]
fn is_reparse_point(_metadata: &Metadata) -> bool {
    false
}

#[cfg(any(target_os = "windows", test))]
fn file_attributes_indicate_reparse(file_attributes: u32) -> bool {
    file_attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

fn matches_any_pattern(file_name: &str, patterns: &[String]) -> bool {
    let options = MatchOptions {
        case_sensitive: false,
        require_literal_separator: true,
        require_literal_leading_dot: false,
    };
    patterns.iter().any(|pattern| {
        Pattern::new(pattern)
            .map(|pattern| pattern.matches_with(file_name, options))
            .unwrap_or_else(|_| pattern.eq_ignore_ascii_case(file_name))
    })
}

fn is_known_log_file(file_name: &str) -> bool {
    let lower = file_name.to_ascii_lowercase();
    [".log", ".log.old", ".lo_", ".txt"]
        .iter()
        .any(|extension| lower.ends_with(extension))
        || lower.contains(".log.")
}

fn is_high_signal_temp_name(file_name: &str) -> bool {
    let lower = file_name.to_ascii_lowercase();
    [
        "msi",
        "setup",
        "install",
        "uninstall",
        "patchmypc",
        "psappdeploy",
        "appdeploy",
        "winget",
    ]
    .iter()
    .any(|signal| lower.contains(signal))
}

fn has_installer_signature(path: &Path) -> bool {
    let Some((canonical, _metadata)) = safe_regular_file(path, None) else {
        return false;
    };
    let mut bytes = Vec::new();
    if File::open(canonical)
        .and_then(|file| file.take(SIGNATURE_BYTES).read_to_end(&mut bytes))
        .is_err()
    {
        return false;
    }
    let text = String::from_utf8_lossy(&bytes).to_ascii_lowercase();
    [
        "windows installer",
        "=== verbose logging started",
        "msi (s)",
        "msiexec.exe",
        "psappdeploytoolkit",
        "patchmypc",
    ]
    .iter()
    .any(|signature| text.contains(signature))
}

fn is_current_log(path: &Path, family: &str) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let lower = name.to_ascii_lowercase();
    !(lower.ends_with(".old")
        || lower.ends_with(".lo_")
        || lower
            .rsplit_once(".log.")
            .is_some_and(|(_, suffix)| suffix.chars().all(|character| character.is_ascii_digit()))
        || (family == "intune-ime" && ime_timestamped_rotation_base(&lower).is_some()))
}

fn rotation_identity(path: &Path, family: &str) -> String {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let timestamped_base = if family == "intune-ime" {
        ime_timestamped_rotation_base(&name)
    } else {
        None
    };
    let base = if let Some(base) = timestamped_base {
        base
    } else if let Some(prefix) = name.strip_suffix(".log.old") {
        format!("{prefix}.log")
    } else if let Some((prefix, suffix)) = name.rsplit_once(".log.") {
        if suffix.chars().all(|character| character.is_ascii_digit()) {
            format!("{prefix}.log")
        } else {
            name
        }
    } else if let Some(prefix) = name.strip_suffix(".lo_") {
        format!("{prefix}.log")
    } else {
        name
    };
    let parent = path.parent().map(path_identity).unwrap_or_default();
    format!("{parent}/{base}")
}

fn ime_timestamped_rotation_base(file_name: &str) -> Option<String> {
    let stem = file_name.strip_suffix(".log")?;
    let (dated_stem, time) = stem.rsplit_once('-')?;
    let (base, date) = dated_stem.rsplit_once('-')?;
    if base.is_empty()
        || date.len() != 8
        || time.len() != 6
        || !date.chars().all(|character| character.is_ascii_digit())
        || !time.chars().all(|character| character.is_ascii_digit())
    {
        return None;
    }
    Some(format!("{base}.log"))
}

fn path_identity(path: &Path) -> String {
    path_identity_for_platform(path, cfg!(target_os = "windows"))
}

fn path_identity_for_platform(path: &Path, windows_semantics: bool) -> String {
    let value = path.to_string_lossy().replace('\\', "/");
    if windows_semantics {
        let value = value.to_ascii_lowercase();
        if let Some(unc) = value.strip_prefix("//?/unc/") {
            format!("//{unc}")
        } else {
            value.strip_prefix("//?/").unwrap_or(&value).to_string()
        }
    } else {
        value
    }
}

fn path_is_within_root_for_platform(path: &Path, root: &Path, windows_semantics: bool) -> bool {
    if !windows_semantics {
        return path.starts_with(root);
    }
    let path = path_identity_for_platform(path, true);
    let root = path_identity_for_platform(root, true);
    path == root || path.starts_with(&format!("{}/", root.trim_end_matches('/')))
}

fn native_path(value: &str) -> PathBuf {
    if cfg!(target_os = "windows") {
        PathBuf::from(value.replace('/', "\\"))
    } else {
        PathBuf::from(value.replace('\\', "/"))
    }
}

fn has_wildcard(value: &str) -> bool {
    value.contains(['*', '?', '['])
}

fn path_has_wildcard(path: &Path) -> bool {
    path.components()
        .any(|component| has_wildcard(&component.as_os_str().to_string_lossy()))
}

fn deduplicate_paths(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut seen = HashSet::new();
    paths
        .into_iter()
        .filter(|path| seen.insert(path_identity(path)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_denied_io_error_maps_to_permission_denied_coverage() {
        let error = std::io::Error::from(std::io::ErrorKind::PermissionDenied);

        assert_eq!(
            discovery_root_state(&error),
            DiscoveryRootState::PermissionDenied
        );
    }

    #[test]
    fn windows_path_identity_is_case_insensitive_and_ignores_verbatim_prefix() {
        let ordinary = path_identity_for_platform(Path::new(r"C:\Temp\MSI123.log"), true);
        let verbatim = path_identity_for_platform(Path::new(r"\\?\c:\temp\msi123.LOG"), true);

        assert_eq!(ordinary, verbatim);
    }

    #[test]
    fn windows_reparse_attribute_is_detected_without_windows_runtime() {
        assert!(!file_attributes_indicate_reparse(0));
        assert!(file_attributes_indicate_reparse(0x400));
        assert!(file_attributes_indicate_reparse(0x400 | 0x20));
    }

    #[test]
    fn windows_containment_is_case_insensitive_and_component_bounded() {
        let root = Path::new(r"C:\Temp");

        assert!(path_is_within_root_for_platform(
            Path::new(r"\\?\c:\TEMP\MSI123.log"),
            root,
            true
        ));
        assert!(!path_is_within_root_for_platform(
            Path::new(r"C:\Temp-Escape\MSI123.log"),
            root,
            true
        ));
    }

    #[cfg(unix)]
    #[test]
    fn installer_signature_reopen_rejects_symlink() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().expect("signature root");
        let outside = tempfile::tempdir().expect("signature outside root");
        let target = outside.path().join("outside.log");
        fs::write(&target, b"Windows Installer").expect("write signature target");
        let link = root.path().join("candidate.log");
        symlink(&target, &link).expect("create signature symlink");

        assert!(!has_installer_signature(&link));
    }
}
