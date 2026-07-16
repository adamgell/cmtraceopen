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
pub const MAX_TEMP_ENTRIES_INSPECTED_PER_ROOT: usize = 128;
pub const MAX_ACTIVE_TAILS: usize = 16;
pub const MAX_INITIAL_READ_BYTES: u64 = 8 * 1024 * 1024;
pub const TEMP_LOOKBACK: Duration = Duration::from_secs(30 * 60);
pub const DISCOVERY_INTERVAL: Duration = Duration::from_secs(2);
pub const UPDATE_DEBOUNCE: Duration = Duration::from_millis(250);
pub const MAX_SESSION_DURATION: Duration = Duration::from_secs(8 * 60 * 60);

const MAX_KNOWN_ENTRIES_ENUMERATED_PER_ROOT: usize = 512;
const MAX_TEMP_ENTRIES_ENUMERATED_PER_ROOT: usize = 4_096;
const SIGNATURE_BYTES: u64 = 4 * 1024;

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
    pub temp_entries_inspected: usize,
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
    for spec in &input.known_sources {
        collect_known_candidates(spec, &mut candidates);
    }

    let mut temp_entries_inspected = 0;
    for root in &input.temp_roots {
        temp_entries_inspected += collect_temp_candidates(root, input.now, &mut candidates);
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
        ) {
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
        temp_entries_inspected,
    }
}

fn collect_known_candidates(spec: &KnownSourceSpec, output: &mut Vec<Candidate>) {
    let root_canonical = match safe_directory_root(&spec.root) {
        Ok(root) => root,
        Err(_) => return,
    };

    let paths = match spec.path_kind {
        KnownSourcePathKind::File => spec
            .patterns
            .first()
            .map(|file_name| vec![spec.root.join(file_name)])
            .unwrap_or_default(),
        KnownSourcePathKind::Folder => match fs::read_dir(&spec.root) {
            Ok(entries) => entries
                .take(MAX_KNOWN_ENTRIES_ENUMERATED_PER_ROOT)
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .collect(),
            Err(_) => return,
        },
    };

    for path in paths {
        let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !matches_any_pattern(file_name, &spec.patterns) || !is_known_log_file(file_name) {
            continue;
        }
        let Some((safe_path, metadata)) = safe_regular_file(&path, Some(&root_canonical)) else {
            continue;
        };
        output.push(candidate(
            safe_path,
            spec.source_id.clone(),
            spec.family.clone(),
            spec.origin,
            metadata.modified().ok(),
        ));
    }
}

fn collect_temp_candidates(root: &Path, now: SystemTime, output: &mut Vec<Candidate>) -> usize {
    let root_canonical = match safe_directory_root(root) {
        Ok(root) => root,
        Err(_) => return 0,
    };
    let mut entries = match fs::read_dir(root) {
        Ok(entries) => entries
            .take(MAX_TEMP_ENTRIES_ENUMERATED_PER_ROOT)
            .filter_map(Result::ok)
            .filter_map(|entry| {
                let path = entry.path();
                let (safe_path, metadata) = safe_regular_file(&path, Some(&root_canonical))?;
                let modified = metadata.modified().ok()?;
                Some((safe_path, metadata, modified))
            })
            .collect::<Vec<_>>(),
        Err(_) => return 0,
    };
    entries.sort_by(|left, right| {
        right
            .2
            .cmp(&left.2)
            .then_with(|| path_identity(&left.0).cmp(&path_identity(&right.0)))
    });
    entries.truncate(MAX_TEMP_ENTRIES_INSPECTED_PER_ROOT);
    let inspected = entries.len();

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
    inspected
}

fn candidate(
    path: PathBuf,
    source_id: String,
    family: String,
    origin: DiscoverySourceOrigin,
    modified: Option<SystemTime>,
) -> Candidate {
    let is_current = is_current_log(&path);
    let priority = match origin {
        DiscoverySourceOrigin::EmbeddedKnown | DiscoverySourceOrigin::CuratedKnown
            if family == "intune-ime" && is_current =>
        {
            0
        }
        DiscoverySourceOrigin::EmbeddedKnown | DiscoverySourceOrigin::CuratedKnown
            if family == "intune-ime" =>
        {
            1
        }
        DiscoverySourceOrigin::ActiveProcess => 2,
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
        rotation_key: rotation_identity(&path),
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
        if !canonical.starts_with(root) {
            return None;
        }
    }
    Some((path.to_path_buf(), link_metadata))
}

fn safe_directory_root(path: &Path) -> std::io::Result<PathBuf> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || is_reparse_point(&metadata) || !metadata.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "discovery root is not a direct directory",
        ));
    }
    fs::canonicalize(path)
}

#[cfg(target_os = "windows")]
fn is_reparse_point(metadata: &Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(target_os = "windows"))]
fn is_reparse_point(_metadata: &Metadata) -> bool {
    false
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
    let mut bytes = Vec::new();
    if File::open(path)
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

fn is_current_log(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let lower = name.to_ascii_lowercase();
    !lower.ends_with(".old")
        && !lower.ends_with(".lo_")
        && !lower
            .rsplit_once(".log.")
            .is_some_and(|(_, suffix)| suffix.chars().all(|character| character.is_ascii_digit()))
}

fn rotation_identity(path: &Path) -> String {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let base = if let Some((prefix, suffix)) = name.rsplit_once(".log.") {
        if suffix.chars().all(|character| character.is_ascii_digit()) {
            format!("{prefix}.log")
        } else {
            name
        }
    } else if let Some(prefix) = name.strip_suffix(".log.old") {
        format!("{prefix}.log")
    } else if let Some(prefix) = name.strip_suffix(".lo_") {
        format!("{prefix}.log")
    } else {
        name
    };
    let parent = path.parent().map(path_identity).unwrap_or_default();
    format!("{parent}/{base}")
}

fn path_identity(path: &Path) -> String {
    let value = path.to_string_lossy().replace('\\', "/");
    if cfg!(target_os = "windows") {
        value.to_ascii_lowercase()
    } else {
        value
    }
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
