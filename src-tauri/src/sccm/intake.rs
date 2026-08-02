use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use cmtraceopen_parser::sccm::{
    classify_artifact_name, declared_client_source_groups, SccmCoverageState, SccmRole,
    SccmRotation,
};
use sha2::{Digest, Sha256};

use crate::error::AppError;

use super::manifest::SccmManifestSourceState;

const MAX_CANDIDATE_ROOTS: usize = 32;
const MAX_SOURCE_SPECS: usize = 128;
const MAX_SAFE_ID_CHARS: usize = 160;

/// A caller-selectable view of the authoritative pure client catalog.
///
/// Every supplied logical group and basename is validated against
/// `declared_client_source_groups`; callers may select a bounded subset for a
/// dry run or test, but cannot invent a source contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SccmClientSourceSpec {
    pub catalog_entry_id: String,
    pub logical_artifact_id: String,
    pub basenames: Vec<String>,
    pub enabled: bool,
}

#[derive(Debug, Clone)]
pub struct SccmClientDiscoveryInput {
    pub candidate_roots: Vec<PathBuf>,
    pub source_catalog: Vec<SccmClientSourceSpec>,
    pub max_files_per_source: usize,
    pub max_bytes_per_source: u64,
    /// Testable status-provider boundary. Production callers leave this map
    /// empty and receive states from filesystem operations. A physical
    /// `ParseFailed` override retains the bounded bytes while pinning the
    /// normalization coverage state.
    pub access_status_overrides: BTreeMap<PathBuf, SccmCoverageState>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SccmClientSourceState {
    pub catalog_entry_id: String,
    pub logical_artifact_ids: Vec<String>,
    pub source_handle: Option<String>,
    pub root_handle: Option<String>,
    pub path_fingerprint: Option<String>,
    pub rotation_lineage: Option<String>,
    pub basename: String,
    pub rotation: SccmRotation,
    pub state: SccmManifestSourceState,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SccmClientDiscoveredArtifact {
    pub catalog_entry_id: String,
    pub logical_artifact_ids: Vec<String>,
    pub source_handle: String,
    pub root_handle: String,
    pub path_fingerprint: String,
    pub rotation_lineage: String,
    pub basename: String,
    pub canonical_basename: String,
    pub rotation: SccmRotation,
    pub state: SccmManifestSourceState,
    pub source_bytes: u64,
    pub copy_bytes: u64,
    pub(crate) canonical_root: PathBuf,
    pub(crate) canonical_path: PathBuf,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct SccmClientDiscoveryResult {
    pub artifacts: Vec<SccmClientDiscoveredArtifact>,
    pub source_states: Vec<SccmClientSourceState>,
}

#[derive(Debug, Clone)]
struct CatalogSelection {
    basename: String,
    logical_artifact_ids: Vec<String>,
    enabled: bool,
}

#[derive(Debug)]
enum RootState {
    Ready(PathBuf),
    Absent,
    AccessDenied,
    Unsafe,
    Unsupported,
}

#[derive(Debug)]
struct InspectedRoot {
    root_handle: String,
    state: RootState,
}

pub fn authoritative_client_source_catalog() -> Vec<SccmClientSourceSpec> {
    declared_client_source_groups()
        .into_iter()
        .map(|group| SccmClientSourceSpec {
            catalog_entry_id: source_group_catalog_entry_id(&group.logical_artifact_id),
            logical_artifact_id: group.logical_artifact_id,
            basenames: group.accepted_basenames,
            enabled: true,
        })
        .collect()
}

pub fn discover_client_sources(
    input: &SccmClientDiscoveryInput,
) -> Result<SccmClientDiscoveryResult, AppError> {
    let catalog = validated_catalog_view(input)?;
    let roots = inspect_roots(&input.candidate_roots);
    let mut artifacts = Vec::new();
    let mut source_states = Vec::new();

    for source in catalog.values() {
        if !source.enabled {
            source_states.push(source_state(
                source,
                &source.basename,
                SccmRotation::Current,
                SccmManifestSourceState::Skipped,
                None,
            ));
            continue;
        }
        if roots.is_empty() {
            source_states.push(source_state(
                source,
                &source.basename,
                SccmRotation::Current,
                SccmManifestSourceState::Absent,
                None,
            ));
            continue;
        }

        let mut candidates = Vec::new();
        for root in &roots {
            discover_source_under_root(input, source, root, &mut candidates, &mut source_states);
        }

        candidates.sort_by(discovered_artifact_order);
        let mut consumed_files = 0_usize;
        let mut consumed_bytes = 0_u64;
        for mut candidate in candidates {
            let remaining = input.max_bytes_per_source.saturating_sub(consumed_bytes);
            if consumed_files >= input.max_files_per_source {
                candidate.state = SccmManifestSourceState::Capped;
                candidate.copy_bytes = 0;
            } else if candidate.source_bytes > remaining
                || candidate.state == SccmManifestSourceState::Capped
            {
                candidate.state = SccmManifestSourceState::Capped;
                candidate.copy_bytes = candidate.source_bytes.min(remaining);
                consumed_files += 1;
                consumed_bytes = consumed_bytes.saturating_add(candidate.copy_bytes);
            } else {
                candidate.copy_bytes = candidate.source_bytes;
                consumed_files += 1;
                consumed_bytes = consumed_bytes.saturating_add(candidate.copy_bytes);
            }
            source_states.push(source_state(
                source,
                &candidate.basename,
                candidate.rotation.clone(),
                candidate.state,
                Some(&candidate.root_handle),
            ));
            artifacts.push(candidate);
        }
    }

    artifacts.sort_by(discovered_artifact_order);
    source_states.sort_by(source_state_order);
    Ok(SccmClientDiscoveryResult {
        artifacts,
        source_states,
    })
}

fn inspect_roots(candidate_roots: &[PathBuf]) -> Vec<InspectedRoot> {
    let mut seen = BTreeSet::new();
    let mut roots = Vec::new();
    for configured_root in candidate_roots {
        let state = inspect_root(configured_root);
        let identity_path = match &state {
            RootState::Ready(canonical_root) => canonical_root.as_path(),
            _ => configured_root.as_path(),
        };
        let root_handle = format!("root-{}", sha256_path(identity_path));
        if seen.insert(root_handle.clone()) {
            roots.push(InspectedRoot { root_handle, state });
        }
    }
    roots
}

fn discover_source_under_root(
    input: &SccmClientDiscoveryInput,
    source: &CatalogSelection,
    root: &InspectedRoot,
    candidates: &mut Vec<SccmClientDiscoveredArtifact>,
    states: &mut Vec<SccmClientSourceState>,
) {
    let canonical_root = match &root.state {
        RootState::Ready(root) => root,
        RootState::Absent => {
            states.push(source_state(
                source,
                &source.basename,
                SccmRotation::Current,
                SccmManifestSourceState::Absent,
                Some(&root.root_handle),
            ));
            return;
        }
        RootState::AccessDenied => {
            states.push(source_state(
                source,
                &source.basename,
                SccmRotation::Current,
                SccmManifestSourceState::AccessDenied,
                Some(&root.root_handle),
            ));
            return;
        }
        RootState::Unsafe => {
            states.push(source_state(
                source,
                &source.basename,
                SccmRotation::Current,
                SccmManifestSourceState::UnsafePath,
                Some(&root.root_handle),
            ));
            return;
        }
        RootState::Unsupported => {
            states.push(source_state(
                source,
                &source.basename,
                SccmRotation::Current,
                SccmManifestSourceState::Unsupported,
                Some(&root.root_handle),
            ));
            return;
        }
    };

    if let Some(override_state) = status_override(input, canonical_root, &source.basename) {
        let mapped = manifest_state(override_state);
        if !mapped.is_physical() {
            states.push(source_state(
                source,
                &source.basename,
                SccmRotation::Current,
                mapped,
                Some(&root.root_handle),
            ));
            return;
        }
    }

    let entries = match fs::read_dir(canonical_root) {
        Ok(entries) => entries,
        Err(error) => {
            states.push(source_state(
                source,
                &source.basename,
                SccmRotation::Current,
                if error.kind() == std::io::ErrorKind::PermissionDenied {
                    SccmManifestSourceState::AccessDenied
                } else {
                    SccmManifestSourceState::FailedUnknownDetail
                },
                Some(&root.root_handle),
            ));
            return;
        }
    };

    let mut matched = false;
    let mut enumeration_gap = None;
    let initial_state_count = states.len();
    let initial_candidate_count = candidates.len();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                enumeration_gap = Some(if error.kind() == std::io::ErrorKind::PermissionDenied {
                    SccmManifestSourceState::AccessDenied
                } else {
                    SccmManifestSourceState::FailedUnknownDetail
                });
                continue;
            }
        };
        let Ok(observed_basename) = entry.file_name().into_string() else {
            continue;
        };
        let Some(rotation) = rotation_for_source(&observed_basename, &source.basename) else {
            continue;
        };
        matched = true;
        let source_path = entry.path();
        let metadata = match fs::symlink_metadata(&source_path) {
            Ok(metadata) => metadata,
            Err(error) => {
                states.push(source_state(
                    source,
                    &observed_basename,
                    rotation,
                    if error.kind() == std::io::ErrorKind::PermissionDenied {
                        SccmManifestSourceState::AccessDenied
                    } else {
                        SccmManifestSourceState::FailedUnknownDetail
                    },
                    Some(&root.root_handle),
                ));
                continue;
            }
        };
        if is_reparse_point(&metadata) || !metadata.is_file() {
            states.push(source_state(
                source,
                &observed_basename,
                rotation,
                SccmManifestSourceState::UnsafePath,
                Some(&root.root_handle),
            ));
            continue;
        }
        let canonical_path = match source_path.canonicalize() {
            Ok(path) if path.starts_with(canonical_root) => path,
            _ => {
                states.push(source_state(
                    source,
                    &observed_basename,
                    rotation,
                    SccmManifestSourceState::UnsafePath,
                    Some(&root.root_handle),
                ));
                continue;
            }
        };
        let state = status_override(input, canonical_root, &observed_basename)
            .map(manifest_state)
            .unwrap_or(SccmManifestSourceState::Captured);
        if !state.is_physical() {
            states.push(source_state(
                source,
                &observed_basename,
                rotation,
                state,
                Some(&root.root_handle),
            ));
            continue;
        }
        let source_digest = source_identity_digest(
            root.root_handle
                .strip_prefix("root-")
                .expect("inspected roots always have a versioned handle"),
            &source.basename,
        );
        candidates.push(SccmClientDiscoveredArtifact {
            catalog_entry_id: catalog_entry_id(&source.basename),
            logical_artifact_ids: source.logical_artifact_ids.clone(),
            source_handle: format!("cmtraceopen.source.sha256.v1:{source_digest}"),
            root_handle: root.root_handle.clone(),
            path_fingerprint: format!("sha256:{source_digest}"),
            rotation_lineage: format!(
                "cmtraceopen.lineage.sha256.v1:{}",
                sha256_bytes(format!("lineage:v1:{source_digest}").as_bytes())
            ),
            basename: observed_basename,
            canonical_basename: source.basename.clone(),
            rotation,
            state,
            source_bytes: metadata.len(),
            copy_bytes: metadata.len(),
            canonical_root: canonical_root.clone(),
            canonical_path,
        });
    }

    if !matched {
        states.push(source_state(
            source,
            &source.basename,
            SccmRotation::Current,
            enumeration_gap.unwrap_or(SccmManifestSourceState::Absent),
            Some(&root.root_handle),
        ));
    } else if let Some(gap) = enumeration_gap {
        let current_already_described = states[initial_state_count..]
            .iter()
            .any(|state| state.rotation == SccmRotation::Current)
            || candidates[initial_candidate_count..]
                .iter()
                .any(|artifact| artifact.rotation == SccmRotation::Current);
        if !current_already_described {
            states.push(source_state(
                source,
                &source.basename,
                SccmRotation::Current,
                gap,
                Some(&root.root_handle),
            ));
        }
    }
}

fn validated_catalog_view(
    input: &SccmClientDiscoveryInput,
) -> Result<BTreeMap<String, CatalogSelection>, AppError> {
    if input.candidate_roots.len() > MAX_CANDIDATE_ROOTS {
        return Err(AppError::InvalidInput(
            "SCCM client discovery has too many candidate roots".to_owned(),
        ));
    }
    if input.source_catalog.len() > MAX_SOURCE_SPECS {
        return Err(AppError::InvalidInput(
            "SCCM client discovery has too many source specifications".to_owned(),
        ));
    }

    let declared = declared_client_source_groups();
    let mut seen_groups = BTreeSet::new();
    let mut selected_basenames = BTreeMap::<String, bool>::new();
    for spec in &input.source_catalog {
        if !is_safe_input_id(&spec.catalog_entry_id)
            || !is_safe_input_id(&spec.logical_artifact_id)
            || spec.catalog_entry_id != source_group_catalog_entry_id(&spec.logical_artifact_id)
            || !seen_groups.insert(spec.logical_artifact_id.clone())
        {
            return Err(AppError::InvalidInput(
                "SCCM client source catalog identity is invalid or duplicated".to_owned(),
            ));
        }
        let group = declared
            .iter()
            .find(|group| group.logical_artifact_id == spec.logical_artifact_id)
            .ok_or_else(|| {
                AppError::InvalidInput(
                    "SCCM client source group is not in the authoritative catalog".to_owned(),
                )
            })?;
        if spec.basenames.is_empty() {
            return Err(AppError::InvalidInput(
                "SCCM client source group has no selected basenames".to_owned(),
            ));
        }
        let mut seen = BTreeSet::new();
        for basename in &spec.basenames {
            if !seen.insert(basename) || !group.accepted_basenames.contains(basename) {
                return Err(AppError::InvalidInput(
                    "SCCM client source basename is not in the authoritative catalog".to_owned(),
                ));
            }
            selected_basenames
                .entry(basename.clone())
                .and_modify(|enabled| *enabled |= spec.enabled)
                .or_insert(spec.enabled);
        }
    }

    let mut selections = BTreeMap::new();
    for (basename, enabled) in selected_basenames {
        let mut logical_artifact_ids = declared
            .iter()
            .filter(|group| group.accepted_basenames.contains(&basename))
            .map(|group| group.logical_artifact_id.clone())
            .collect::<Vec<_>>();
        logical_artifact_ids.sort();
        selections.insert(
            basename.clone(),
            CatalogSelection {
                basename,
                logical_artifact_ids,
                enabled,
            },
        );
    }
    Ok(selections)
}

fn inspect_root(root: &Path) -> RootState {
    let metadata = match fs::symlink_metadata(root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return RootState::Absent,
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            return RootState::AccessDenied;
        }
        Err(_) => return RootState::Unsupported,
    };
    if is_reparse_point(&metadata) || !metadata.is_dir() {
        return RootState::Unsafe;
    }
    match root.canonicalize() {
        Ok(path) => RootState::Ready(path),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            RootState::AccessDenied
        }
        Err(_) => RootState::Unsupported,
    }
}

fn rotation_for_source(observed: &str, canonical: &str) -> Option<SccmRotation> {
    let classified = classify_artifact_name(observed, SccmRole::Client);
    (classified.supported_for_diagnosis
        && classified.basename == canonical
        && observed == expected_rotated_name(canonical, &classified.rotation)?)
    .then_some(classified.rotation)
}

fn expected_rotated_name(basename: &str, rotation: &SccmRotation) -> Option<String> {
    match rotation {
        SccmRotation::Current => Some(basename.to_owned()),
        SccmRotation::LoUnderscore => basename
            .strip_suffix(".log")
            .map(|stem| format!("{stem}.lo_")),
        SccmRotation::Numbered(number) if *number > 0 => Some(format!("{basename}.{number}")),
        SccmRotation::Timestamped(timestamp) => Some(format!("{basename}.{timestamp}")),
        SccmRotation::Numbered(_) | SccmRotation::Unknown(_) => None,
    }
}

fn source_state(
    source: &CatalogSelection,
    basename: &str,
    rotation: SccmRotation,
    state: SccmManifestSourceState,
    root_handle: Option<&str>,
) -> SccmClientSourceState {
    let provenance = root_handle.map(|root_handle| {
        let root_digest = root_handle
            .strip_prefix("root-")
            .expect("inspected roots always have a versioned handle");
        let source_digest = source_identity_digest(root_digest, &source.basename);
        (
            format!("cmtraceopen.source.sha256.v1:{source_digest}"),
            root_handle.to_owned(),
            format!("sha256:{source_digest}"),
            format!(
                "cmtraceopen.lineage.sha256.v1:{}",
                sha256_bytes(format!("lineage:v1:{source_digest}").as_bytes())
            ),
        )
    });
    SccmClientSourceState {
        catalog_entry_id: catalog_entry_id(&source.basename),
        logical_artifact_ids: source.logical_artifact_ids.clone(),
        source_handle: provenance.as_ref().map(|value| value.0.clone()),
        root_handle: provenance.as_ref().map(|value| value.1.clone()),
        path_fingerprint: provenance.as_ref().map(|value| value.2.clone()),
        rotation_lineage: provenance.map(|value| value.3),
        basename: basename.to_owned(),
        rotation,
        state,
    }
}

fn source_state_order(
    left: &SccmClientSourceState,
    right: &SccmClientSourceState,
) -> std::cmp::Ordering {
    left.logical_artifact_ids
        .cmp(&right.logical_artifact_ids)
        .then_with(|| {
            left.path_fingerprint
                .as_deref()
                .unwrap_or_default()
                .cmp(right.path_fingerprint.as_deref().unwrap_or_default())
        })
        .then_with(|| rotation_order(&left.rotation, &right.rotation))
        .then_with(|| left.basename.cmp(&right.basename))
        .then_with(|| state_rank(left.state).cmp(&state_rank(right.state)))
}

fn source_group_catalog_entry_id(logical_artifact_id: &str) -> String {
    format!("sccm-client-group:v1:{logical_artifact_id}")
}

pub(super) fn catalog_entry_id(basename: &str) -> String {
    format!(
        "sccm-client-source:v1:sha256:{}",
        sha256_bytes(basename.as_bytes())
    )
}

pub(super) fn logical_artifact_ids_for_basename(basename: &str) -> Vec<String> {
    let mut values = declared_client_source_groups()
        .into_iter()
        .filter(|group| {
            group
                .accepted_basenames
                .iter()
                .any(|value| value == basename)
        })
        .map(|group| group.logical_artifact_id)
        .collect::<Vec<_>>();
    values.sort();
    values
}

fn manifest_state(coverage: SccmCoverageState) -> SccmManifestSourceState {
    match coverage {
        SccmCoverageState::Captured => SccmManifestSourceState::Captured,
        SccmCoverageState::Absent => SccmManifestSourceState::Absent,
        SccmCoverageState::AccessDenied => SccmManifestSourceState::AccessDenied,
        SccmCoverageState::Capped => SccmManifestSourceState::Capped,
        SccmCoverageState::Skipped => SccmManifestSourceState::Skipped,
        SccmCoverageState::Unsupported => SccmManifestSourceState::Unsupported,
        SccmCoverageState::ParseFailed => SccmManifestSourceState::ParseFailed,
    }
}

fn status_override(
    input: &SccmClientDiscoveryInput,
    canonical_root: &Path,
    basename: &str,
) -> Option<SccmCoverageState> {
    input
        .access_status_overrides
        .iter()
        .find(|(path, _)| {
            path.file_name().and_then(|value| value.to_str()) == Some(basename)
                && path
                    .parent()
                    .and_then(|parent| parent.canonicalize().ok())
                    .as_deref()
                    == Some(canonical_root)
        })
        .map(|(_, state)| state.clone())
}

fn state_rank(state: SccmManifestSourceState) -> u8 {
    match state {
        SccmManifestSourceState::Captured => 0,
        SccmManifestSourceState::Absent => 1,
        SccmManifestSourceState::Unsupported => 2,
        SccmManifestSourceState::Skipped => 3,
        SccmManifestSourceState::Capped => 4,
        SccmManifestSourceState::AccessDenied => 5,
        SccmManifestSourceState::UnsafePath => 6,
        SccmManifestSourceState::FailedUnknownDetail => 7,
        SccmManifestSourceState::ParseFailed => 8,
    }
}

pub(super) fn rotation_order(left: &SccmRotation, right: &SccmRotation) -> std::cmp::Ordering {
    rotation_kind_rank(left)
        .cmp(&rotation_kind_rank(right))
        .then_with(|| match (left, right) {
            (SccmRotation::Numbered(left), SccmRotation::Numbered(right)) => left.cmp(right),
            (SccmRotation::Timestamped(left), SccmRotation::Timestamped(right)) => left.cmp(right),
            _ => std::cmp::Ordering::Equal,
        })
}

fn rotation_kind_rank(rotation: &SccmRotation) -> u8 {
    match rotation {
        SccmRotation::Current => 0,
        SccmRotation::LoUnderscore => 1,
        SccmRotation::Numbered(_) => 2,
        SccmRotation::Timestamped(_) => 3,
        SccmRotation::Unknown(_) => 4,
    }
}

fn discovered_artifact_order(
    left: &SccmClientDiscoveredArtifact,
    right: &SccmClientDiscoveredArtifact,
) -> std::cmp::Ordering {
    left.canonical_basename
        .cmp(&right.canonical_basename)
        .then_with(|| left.path_fingerprint.cmp(&right.path_fingerprint))
        .then_with(|| rotation_order(&left.rotation, &right.rotation))
        .then_with(|| left.basename.cmp(&right.basename))
}

fn source_identity_digest(root_digest: &str, basename: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"cmtraceopen.sccm.source.v1\0");
    digest.update(root_digest.as_bytes());
    digest.update(b"\0");
    digest.update(basename.as_bytes());
    hex_digest(digest.finalize().as_slice())
}

#[cfg(unix)]
fn sha256_path(path: &Path) -> String {
    use std::os::unix::ffi::OsStrExt;

    sha256_bytes(path.as_os_str().as_bytes())
}

#[cfg(windows)]
fn sha256_path(path: &Path) -> String {
    use std::os::windows::ffi::OsStrExt;

    let mut digest = Sha256::new();
    for unit in path.as_os_str().encode_wide() {
        digest.update(unit.to_le_bytes());
    }
    hex_digest(digest.finalize().as_slice())
}

#[cfg(not(any(unix, windows)))]
fn sha256_path(path: &Path) -> String {
    sha256_bytes(path.to_string_lossy().as_bytes())
}

pub(super) fn sha256_bytes(value: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(value);
    hex_digest(digest.finalize().as_slice())
}

fn hex_digest(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn is_safe_input_id(value: &str) -> bool {
    !value.is_empty()
        && value == value.trim()
        && value.chars().count() <= MAX_SAFE_ID_CHARS
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "-._:".contains(character))
}

pub(super) fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn native_unix_path_bytes_do_not_collapse_under_lossy_utf8() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let path_a = PathBuf::from(OsString::from_vec(vec![b'r', 0x80]));
        let path_b = PathBuf::from(OsString::from_vec(vec![b'r', 0x81]));
        assert_eq!(path_a.to_string_lossy(), path_b.to_string_lossy());
        assert_ne!(sha256_path(&path_a), sha256_path(&path_b));
    }

    #[cfg(windows)]
    #[test]
    fn native_windows_path_units_do_not_collapse_under_lossy_utf16() {
        use std::ffi::OsString;
        use std::os::windows::ffi::OsStringExt;

        let path_a = PathBuf::from(OsString::from_wide(&[b'r' as u16, 0xd800]));
        let path_b = PathBuf::from(OsString::from_wide(&[b'r' as u16, 0xd801]));
        assert_eq!(path_a.to_string_lossy(), path_b.to_string_lossy());
        assert_ne!(sha256_path(&path_a), sha256_path(&path_b));
    }
}
