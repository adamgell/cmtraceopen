//! Fixed-scope deployment-log discovery for ESP diagnostics.
//!
//! Discovery consumes only the embedded collector profile, the application's
//! existing Windows known-source catalog, fixed runtime temp roots, and log
//! paths observed on allowlisted installer processes. It has no user-supplied
//! filesystem root and never recurses.

use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap, HashSet};
#[cfg(not(unix))]
use std::fs::OpenOptions;
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
pub const MAX_DISCOVERY_PATH_FAILURES: usize = 256;
pub const WINDOWS_SHARED_READ_WRITE_DELETE: u32 = 0x1 | 0x2 | 0x4;

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
pub enum DiscoveryPathFailureKind {
    Missing,
    PermissionDenied,
    ReparseRejected,
    OutsideAllowedRoot,
    NotRegularFile,
    ResourceLimit,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryPathFailure {
    pub path: PathBuf,
    pub source_id: Option<String>,
    pub origin: DiscoverySourceOrigin,
    pub kind: DiscoveryPathFailureKind,
    pub detail: String,
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
    pub path_failures: Vec<DiscoveryPathFailure>,
    pub path_failures_truncated: bool,
}

#[derive(Debug, Clone)]
struct Candidate {
    source: DiscoveredLogSource,
    identity_key: String,
    rotation_key: String,
}

#[derive(Debug, Default)]
struct PathFailureCollector {
    failures: Vec<DiscoveryPathFailure>,
    truncated: bool,
}

impl PathFailureCollector {
    fn push(&mut self, failure: DiscoveryPathFailure) {
        if self.failures.len() < MAX_DISCOVERY_PATH_FAILURES {
            self.failures.push(failure);
        } else {
            self.truncated = true;
        }
    }
}

#[derive(Debug)]
struct PathInspectionFailure {
    kind: DiscoveryPathFailureKind,
    detail: String,
}

#[derive(Debug)]
pub(crate) struct VerifiedFileOpenFailure {
    pub(crate) kind: DiscoveryPathFailureKind,
    pub(crate) detail: String,
}

impl VerifiedFileOpenFailure {
    fn from_io(operation: &str, error: std::io::Error) -> Self {
        #[cfg(unix)]
        let no_follow_reparse = error.raw_os_error() == Some(libc::ELOOP);
        #[cfg(not(unix))]
        let no_follow_reparse = false;
        let kind = if no_follow_reparse {
            DiscoveryPathFailureKind::ReparseRejected
        } else {
            match error.kind() {
                std::io::ErrorKind::NotFound => DiscoveryPathFailureKind::Missing,
                std::io::ErrorKind::PermissionDenied => DiscoveryPathFailureKind::PermissionDenied,
                _ => DiscoveryPathFailureKind::Failed,
            }
        };
        Self {
            kind,
            detail: format!("{operation} failed: {error}"),
        }
    }

    #[cfg(unix)]
    fn from_unix_component_open(
        path: &Path,
        component: &std::ffi::OsStr,
        is_directory: bool,
        error: std::io::Error,
    ) -> Self {
        if error.raw_os_error() == Some(libc::ELOOP)
            || (is_directory && error.raw_os_error() == Some(libc::ENOTDIR))
        {
            return Self {
                kind: DiscoveryPathFailureKind::ReparseRejected,
                detail: format!(
                    "component-safe open rejected changed or linked component {:?} in {}: {error}",
                    component,
                    path.display()
                ),
            };
        }
        Self::from_io("component-safe open", error)
    }
}

impl From<VerifiedFileOpenFailure> for PathInspectionFailure {
    fn from(failure: VerifiedFileOpenFailure) -> Self {
        Self {
            kind: failure.kind,
            detail: failure.detail,
        }
    }
}

impl PathInspectionFailure {
    fn from_io(operation: &str, error: std::io::Error) -> Self {
        let kind = match error.kind() {
            std::io::ErrorKind::NotFound => DiscoveryPathFailureKind::Missing,
            std::io::ErrorKind::PermissionDenied => DiscoveryPathFailureKind::PermissionDenied,
            _ => DiscoveryPathFailureKind::Failed,
        };
        Self {
            kind,
            detail: format!("{operation} failed: {error}"),
        }
    }

    fn coverage(
        self,
        path: &Path,
        source_id: Option<String>,
        origin: DiscoverySourceOrigin,
    ) -> DiscoveryPathFailure {
        DiscoveryPathFailure {
            path: path.to_path_buf(),
            source_id,
            origin,
            kind: self.kind,
            detail: self.detail,
        }
    }
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
    let mut path_failures = PathFailureCollector::default();
    for spec in &input.known_sources {
        root_coverage.push(collect_known_candidates(
            spec,
            &mut candidates,
            &mut path_failures,
        ));
    }

    let mut temp_entries_probed = 0;
    let mut temp_entries_inspected = 0;
    for root in &input.temp_roots {
        let coverage =
            collect_temp_candidates(root, input.now, &mut candidates, &mut path_failures);
        temp_entries_probed += coverage.entries_probed;
        temp_entries_inspected += coverage.entries_inspected;
        root_coverage.push(coverage);
    }

    for path in &input.active_process_logs {
        match safe_regular_file(path, None) {
            Ok((safe_path, metadata)) => candidates.push(candidate(
                safe_path,
                "active-process-log".to_string(),
                "installer".to_string(),
                DiscoverySourceOrigin::ActiveProcess,
                metadata.modified().ok(),
            )),
            Err(failure) => path_failures.push(failure.coverage(
                path,
                Some("active-process-log".to_string()),
                DiscoverySourceOrigin::ActiveProcess,
            )),
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
        path_failures: path_failures.failures,
        path_failures_truncated: path_failures.truncated,
    }
}

fn collect_known_candidates(
    spec: &KnownSourceSpec,
    output: &mut Vec<Candidate>,
    path_failures: &mut PathFailureCollector,
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
        let (safe_path, metadata) = match safe_regular_file(&path, Some(&root_canonical)) {
            Ok(file) => file,
            Err(failure) => {
                coverage.entries_rejected += 1;
                path_failures.push(failure.coverage(
                    &path,
                    Some(spec.source_id.clone()),
                    spec.origin,
                ));
                continue;
            }
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
    path_failures: &mut PathFailureCollector,
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
        let high_signal_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(is_high_signal_temp_name);
        let (safe_path, metadata) = match safe_regular_file(&path, Some(&root_canonical)) {
            Ok(file) => file,
            Err(failure) => {
                coverage.entries_rejected += 1;
                if high_signal_name {
                    path_failures.push(failure.coverage(
                        &path,
                        Some("bounded-temp-log".to_string()),
                        DiscoverySourceOrigin::Temp,
                    ));
                }
                continue;
            }
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
        if !is_high_signal_temp_name(file_name) {
            match has_installer_signature(&path) {
                Ok(true) => {}
                Ok(false) => continue,
                Err(failure) => {
                    coverage.entries_rejected += 1;
                    path_failures.push(failure.coverage(
                        &path,
                        Some("bounded-temp-log".to_string()),
                        DiscoverySourceOrigin::Temp,
                    ));
                    continue;
                }
            }
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

fn safe_regular_file(
    path: &Path,
    allowed_root: Option<&Path>,
) -> Result<(PathBuf, Metadata), PathInspectionFailure> {
    let link_metadata = fs::symlink_metadata(path)
        .map_err(|error| PathInspectionFailure::from_io("metadata", error))?;
    if link_metadata.file_type().is_symlink() || is_reparse_point(&link_metadata) {
        return Err(PathInspectionFailure {
            kind: DiscoveryPathFailureKind::ReparseRejected,
            detail: "path is a symlink or reparse point".to_string(),
        });
    }
    if !link_metadata.is_file() {
        return Err(PathInspectionFailure {
            kind: DiscoveryPathFailureKind::NotRegularFile,
            detail: "path is not a regular file".to_string(),
        });
    }
    let canonical = fs::canonicalize(path)
        .map_err(|error| PathInspectionFailure::from_io("canonicalize", error))?;
    if let Some(root) = allowed_root {
        if !path_is_within_root_for_platform(&canonical, root, cfg!(target_os = "windows")) {
            return Err(PathInspectionFailure {
                kind: DiscoveryPathFailureKind::OutsideAllowedRoot,
                detail: "canonical path escapes the approved discovery root".to_string(),
            });
        }
    }
    Ok((canonical, link_metadata))
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

pub(crate) fn metadata_is_reparse_point(metadata: &Metadata) -> bool {
    metadata.file_type().is_symlink() || is_reparse_point(metadata)
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
        || lower.rsplit_once(".log.").is_some_and(|(_, suffix)| {
            !suffix.is_empty() && suffix.chars().all(|character| character.is_ascii_digit())
        })
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

pub(crate) fn open_verified_regular_file(path: &Path) -> Result<File, VerifiedFileOpenFailure> {
    let file = open_no_follow_components(path)?;
    let metadata = file
        .metadata()
        .map_err(|error| VerifiedFileOpenFailure::from_io("inspect opened file", error))?;
    if metadata_is_reparse_point(&metadata) {
        return Err(VerifiedFileOpenFailure {
            kind: DiscoveryPathFailureKind::ReparseRejected,
            detail: "opened path is a symlink or reparse point".to_string(),
        });
    }
    if !metadata.is_file() {
        return Err(VerifiedFileOpenFailure {
            kind: DiscoveryPathFailureKind::NotRegularFile,
            detail: "opened path is not a regular file".to_string(),
        });
    }
    Ok(file)
}

#[cfg(unix)]
fn open_no_follow_components(path: &Path) -> Result<File, VerifiedFileOpenFailure> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::path::Component;

    let mut components = path.components();
    if !matches!(components.next(), Some(Component::RootDir)) {
        return Err(VerifiedFileOpenFailure {
            kind: DiscoveryPathFailureKind::Failed,
            detail: format!(
                "component-safe open requires an absolute canonical path: {}",
                path.display()
            ),
        });
    }
    let mut parts = Vec::new();
    for component in components {
        match component {
            Component::Normal(part) => parts.push(part),
            _ => {
                return Err(VerifiedFileOpenFailure {
                    kind: DiscoveryPathFailureKind::Failed,
                    detail: format!(
                        "component-safe open rejected a non-canonical path: {}",
                        path.display()
                    ),
                });
            }
        }
    }
    if parts.is_empty() {
        return Err(VerifiedFileOpenFailure {
            kind: DiscoveryPathFailureKind::NotRegularFile,
            detail: "component-safe open cannot tail the filesystem root".to_string(),
        });
    }

    let mut directory = File::open(Path::new("/"))
        .map_err(|error| VerifiedFileOpenFailure::from_io("open filesystem root", error))?;
    for (index, part) in parts.iter().enumerate() {
        let is_last = index + 1 == parts.len();
        let component = CString::new(part.as_bytes()).map_err(|_| VerifiedFileOpenFailure {
            kind: DiscoveryPathFailureKind::Failed,
            detail: format!(
                "component-safe open rejected a path component containing NUL: {}",
                path.display()
            ),
        })?;
        let mut flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK;
        if !is_last {
            flags |= libc::O_DIRECTORY;
        }
        // SAFETY: `directory` is a live directory descriptor, `component` is
        // NUL-terminated, and the returned descriptor is immediately owned by
        // a `File` on success.
        let descriptor = unsafe { libc::openat(directory.as_raw_fd(), component.as_ptr(), flags) };
        if descriptor < 0 {
            return Err(VerifiedFileOpenFailure::from_unix_component_open(
                path,
                part,
                !is_last,
                std::io::Error::last_os_error(),
            ));
        }
        // SAFETY: `openat` returned a new owned descriptor on success.
        let opened = unsafe { File::from_raw_fd(descriptor) };
        if is_last {
            return Ok(opened);
        }
        directory = opened;
    }
    unreachable!("a non-empty component list returns from its final component")
}

#[cfg(target_os = "windows")]
fn open_no_follow_components(path: &Path) -> Result<File, VerifiedFileOpenFailure> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;

    let mut options = OpenOptions::new();
    options
        .read(true)
        .share_mode(WINDOWS_SHARED_READ_WRITE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0);
    let file = options
        .open(path)
        .map_err(|error| VerifiedFileOpenFailure::from_io("open verified file", error))?;
    let opened_path = windows_final_path(&file)
        .map_err(|error| VerifiedFileOpenFailure::from_io("resolve opened file handle", error))?;
    if !opened_path_matches_expected_for_platform(path, &opened_path, true) {
        return Err(VerifiedFileOpenFailure {
            kind: DiscoveryPathFailureKind::ReparseRejected,
            detail: format!(
                "opened file resolved outside its approved canonical path (expected {}, opened {})",
                path.display(),
                opened_path.display()
            ),
        });
    }
    Ok(file)
}

#[cfg(target_os = "windows")]
fn windows_final_path(file: &File) -> std::io::Result<PathBuf> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Storage::FileSystem::{
        GetFinalPathNameByHandleW, FILE_NAME_NORMALIZED, GETFINALPATHNAMEBYHANDLE_FLAGS,
        VOLUME_NAME_DOS,
    };

    let mut buffer = vec![0u16; 512];
    loop {
        // SAFETY: the handle is borrowed from the live `File`, and `buffer`
        // remains valid and writable for the duration of the call.
        let length = unsafe {
            GetFinalPathNameByHandleW(
                HANDLE(file.as_raw_handle()),
                &mut buffer,
                GETFINALPATHNAMEBYHANDLE_FLAGS(FILE_NAME_NORMALIZED.0 | VOLUME_NAME_DOS.0),
            )
        };
        if length == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let length = length as usize;
        if length < buffer.len() {
            return Ok(PathBuf::from(OsString::from_wide(&buffer[..length])));
        }
        buffer.resize(length.saturating_add(1), 0);
    }
}

#[cfg(not(any(unix, target_os = "windows")))]
fn open_no_follow_components(path: &Path) -> Result<File, VerifiedFileOpenFailure> {
    OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|error| VerifiedFileOpenFailure::from_io("open verified file", error))
}

#[cfg(any(target_os = "windows", test))]
fn opened_path_matches_expected_for_platform(
    expected: &Path,
    opened: &Path,
    windows_semantics: bool,
) -> bool {
    path_identity_for_platform(expected, windows_semantics)
        == path_identity_for_platform(opened, windows_semantics)
}

fn has_installer_signature(path: &Path) -> Result<bool, PathInspectionFailure> {
    let file = open_verified_regular_file(path).map_err(PathInspectionFailure::from)?;

    let mut bytes = Vec::new();
    file.take(SIGNATURE_BYTES)
        .read_to_end(&mut bytes)
        .map_err(|error| PathInspectionFailure::from_io("read installer signature", error))?;
    let text = String::from_utf8_lossy(&bytes).to_ascii_lowercase();
    Ok([
        "windows installer",
        "=== verbose logging started",
        "msi (s)",
        "msiexec.exe",
        "psappdeploytoolkit",
        "patchmypc",
    ]
    .iter()
    .any(|signature| text.contains(signature)))
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

    #[cfg(unix)]
    #[test]
    fn installer_signature_rejects_replaced_parent_component() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().expect("approved root");
        let approved_parent = root.path().join("approved");
        fs::create_dir(&approved_parent).expect("create approved parent");
        let approved_path = approved_parent.join("candidate.data");
        fs::write(&approved_path, b"approved content without a signature\n")
            .expect("write approved candidate");
        let canonical_approved = fs::canonicalize(&approved_path).expect("canonical candidate");

        let outside = tempfile::tempdir().expect("outside root");
        fs::write(
            outside.path().join("candidate.data"),
            b"=== Verbose Logging Started\n",
        )
        .expect("write outside signature");
        fs::rename(&approved_parent, root.path().join("approved-original"))
            .expect("move approved parent");
        symlink(outside.path(), &approved_parent).expect("replace parent with symlink");

        let failure = has_installer_signature(&canonical_approved)
            .expect_err("parent replacement must not expose the outside signature");

        assert_eq!(failure.kind, DiscoveryPathFailureKind::ReparseRejected);
    }

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
    fn windows_handle_path_validation_rejects_redirected_parent() {
        let expected = Path::new(r"\\?\C:\Users\Alice\AppData\Local\Temp\MSI123.log");

        assert!(opened_path_matches_expected_for_platform(
            expected,
            Path::new(r"c:\users\alice\appdata\local\temp\msi123.LOG"),
            true
        ));
        assert!(!opened_path_matches_expected_for_platform(
            expected,
            Path::new(r"\\?\C:\Windows\System32\config\SAM"),
            true
        ));
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

    #[test]
    fn regular_file_outside_allowed_root_has_typed_containment_failure() {
        let allowed = tempfile::tempdir().expect("allowed root");
        let outside = tempfile::tempdir().expect("outside root");
        let path = outside.path().join("outside.log");
        fs::write(&path, b"outside").expect("write outside fixture");
        let allowed = fs::canonicalize(allowed.path()).expect("canonical allowed root");

        let failure = safe_regular_file(&path, Some(&allowed)).expect_err("reject outside file");

        assert_eq!(failure.kind, DiscoveryPathFailureKind::OutsideAllowedRoot);
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

        assert!(has_installer_signature(&link).is_err());
    }
}
