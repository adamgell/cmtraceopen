use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use cmtraceopen_parser::sccm::{SccmCoverageState, SccmRotation};
use sha2::{Digest, Sha256};

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
    /// A testable status provider boundary. Production callers leave this
    /// empty and receive statuses from bounded filesystem operations.
    pub access_status_overrides: BTreeMap<PathBuf, SccmCoverageState>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SccmClientSourceState {
    pub catalog_entry_id: String,
    pub logical_artifact_id: String,
    pub coverage: SccmCoverageState,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SccmClientDiscoveredArtifact {
    pub catalog_entry_id: String,
    pub logical_artifact_id: String,
    pub source_path: PathBuf,
    pub canonical_path: PathBuf,
    pub path_fingerprint: String,
    pub basename: String,
    pub rotation: SccmRotation,
    pub rotation_rank: u8,
    pub bytes: u64,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct SccmClientDiscoveryResult {
    pub artifacts: Vec<SccmClientDiscoveredArtifact>,
    pub source_states: Vec<SccmClientSourceState>,
}

pub fn discover_client_sources(input: &SccmClientDiscoveryInput) -> SccmClientDiscoveryResult {
    let canonical_roots = input
        .candidate_roots
        .iter()
        .filter_map(|root| canonical_root(root).ok())
        .collect::<Vec<_>>();
    let mut artifacts = Vec::new();
    let mut source_states = Vec::new();

    for spec in &input.source_catalog {
        if !spec.enabled {
            source_states.push(source_state(spec, SccmCoverageState::Skipped));
            continue;
        }

        if is_access_denied(spec, input) {
            source_states.push(source_state(spec, SccmCoverageState::AccessDenied));
            continue;
        }

        let mut candidates = Vec::new();
        let mut unsafe_candidate = false;
        for root in &canonical_roots {
            let entries = match fs::read_dir(root) {
                Ok(entries) => entries,
                Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                    unsafe_candidate = true;
                    continue;
                }
                Err(_) => continue,
            };
            for entry in entries.flatten() {
                let source_path = entry.path();
                let basename = match entry.file_name().into_string() {
                    Ok(name) => name,
                    Err(_) => continue,
                };
                let Some((rotation, rotation_rank)) = classify_rotation(&basename, &spec.basenames)
                else {
                    continue;
                };
                let metadata = match fs::symlink_metadata(&source_path) {
                    Ok(metadata) => metadata,
                    Err(_) => {
                        unsafe_candidate = true;
                        continue;
                    }
                };
                if metadata.file_type().is_symlink() || !metadata.is_file() {
                    unsafe_candidate = true;
                    continue;
                }
                let canonical_path = match source_path.canonicalize() {
                    Ok(path) if path.starts_with(root) => path,
                    _ => {
                        unsafe_candidate = true;
                        continue;
                    }
                };
                candidates.push(SccmClientDiscoveredArtifact {
                    catalog_entry_id: spec.catalog_entry_id.clone(),
                    logical_artifact_id: spec.logical_artifact_id.clone(),
                    path_fingerprint: path_fingerprint(&canonical_path),
                    source_path,
                    canonical_path,
                    basename,
                    rotation,
                    rotation_rank,
                    bytes: metadata.len(),
                });
            }
        }
        candidates.sort_by(discovered_artifact_order);

        let mut bytes = 0_u64;
        let mut capped = false;
        let mut retained = Vec::new();
        for candidate in candidates {
            if retained.len() >= input.max_files_per_source
                || candidate.bytes > input.max_bytes_per_source.saturating_sub(bytes)
            {
                capped = true;
                continue;
            }
            bytes = bytes.saturating_add(candidate.bytes);
            retained.push(candidate);
        }
        if capped {
            source_states.push(source_state(spec, SccmCoverageState::Capped));
        } else if retained.is_empty() {
            source_states.push(source_state(
                spec,
                if unsafe_candidate {
                    SccmCoverageState::Unsupported
                } else {
                    SccmCoverageState::Absent
                },
            ));
        } else {
            source_states.push(source_state(spec, SccmCoverageState::Captured));
        }
        artifacts.extend(retained);
    }
    artifacts.sort_by(discovered_artifact_order);
    source_states.sort_by(|left, right| {
        left.catalog_entry_id
            .cmp(&right.catalog_entry_id)
            .then_with(|| left.logical_artifact_id.cmp(&right.logical_artifact_id))
    });
    SccmClientDiscoveryResult {
        artifacts,
        source_states,
    }
}

fn canonical_root(root: &Path) -> Result<PathBuf, std::io::Error> {
    let metadata = fs::symlink_metadata(root)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "candidate root must be a real directory",
        ));
    }
    root.canonicalize()
}

fn source_state(spec: &SccmClientSourceSpec, coverage: SccmCoverageState) -> SccmClientSourceState {
    SccmClientSourceState {
        catalog_entry_id: spec.catalog_entry_id.clone(),
        logical_artifact_id: spec.logical_artifact_id.clone(),
        coverage,
    }
}

fn is_access_denied(spec: &SccmClientSourceSpec, input: &SccmClientDiscoveryInput) -> bool {
    input.candidate_roots.iter().any(|root| {
        spec.basenames.iter().any(|basename| {
            input
                .access_status_overrides
                .get(&root.join(basename))
                .is_some_and(|state| *state == SccmCoverageState::AccessDenied)
        })
    })
}

fn classify_rotation(basename: &str, allowed_basenames: &[String]) -> Option<(SccmRotation, u8)> {
    for allowed in allowed_basenames {
        if basename.eq_ignore_ascii_case(allowed) {
            return Some((SccmRotation::Current, 0));
        }
        if let Some(stem) = allowed.strip_suffix(".log") {
            if basename.eq_ignore_ascii_case(&format!("{stem}.lo_")) {
                return Some((SccmRotation::LoUnderscore, 1));
            }
        }
        let Some(suffix) = basename.strip_prefix(&format!("{allowed}.")) else {
            continue;
        };
        if !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit()) {
            let number = suffix.parse::<u32>().ok()?;
            if number > 0 {
                return Some((SccmRotation::Numbered(number), 2));
            }
        }
    }
    None
}

fn path_fingerprint(path: &Path) -> String {
    let mut digest = Sha256::new();
    digest.update(path.to_string_lossy().as_bytes());
    format!("sha256:{}", hex_digest(digest.finalize().as_slice()))
}

fn hex_digest(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn discovered_artifact_order(
    left: &SccmClientDiscoveredArtifact,
    right: &SccmClientDiscoveredArtifact,
) -> std::cmp::Ordering {
    left.catalog_entry_id
        .cmp(&right.catalog_entry_id)
        .then_with(|| left.path_fingerprint.cmp(&right.path_fingerprint))
        .then_with(|| left.rotation_rank.cmp(&right.rotation_rank))
        .then_with(|| left.basename.cmp(&right.basename))
        .then_with(|| left.source_path.cmp(&right.source_path))
}
