use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::constants::DEFAULT_BUNDLE_PRIMARY_ENTRY_POINTS;
use crate::intune::models::{EvidenceBundleArtifactCounts, EvidenceBundleMetadata};

use super::intune::{IME_LOG_PATTERNS, ResolvedIntuneInput};

pub(crate) fn describe_path_access_error(path: &Path, error: &std::io::Error) -> String {
    match error.kind() {
        std::io::ErrorKind::NotFound => {
            format!(
                "The selected Intune source was not found: '{}'",
                path.display()
            )
        }
        std::io::ErrorKind::PermissionDenied => format!(
            "The selected Intune source could not be accessed because permission was denied: '{}'",
            path.display()
        ),
        _ => format!(
            "The selected Intune source could not be accessed: '{}' ({})",
            path.display(),
            error
        ),
    }
}

pub(crate) fn describe_directory_read_error(path: &Path, error: &std::io::Error) -> String {
    match error.kind() {
        std::io::ErrorKind::PermissionDenied => format!(
            "The selected Intune folder could not be read because permission was denied: '{}'",
            path.display()
        ),
        _ => format!(
            "The selected Intune folder could not be read: '{}' ({})",
            path.display(),
            error
        ),
    }
}

pub(crate) fn resolve_intune_input(path: &Path) -> Result<ResolvedIntuneInput, String> {
    let metadata = fs::metadata(path).map_err(|error| describe_path_access_error(path, &error))?;

    if metadata.is_file() {
        return Ok(ResolvedIntuneInput {
            source_paths: vec![path.to_path_buf()],
            evidence_bundle: None,
        });
    }

    if !metadata.is_dir() {
        return Err(format!(
            "The selected Intune source is neither a file nor a folder: '{}'",
            path.display()
        ));
    }

    if let Some(bundle_input) = resolve_evidence_bundle_input(path)? {
        return Ok(bundle_input);
    }

    Ok(ResolvedIntuneInput {
        source_paths: collect_directory_log_paths(path)?,
        evidence_bundle: None,
    })
}

/// Resolve a single file or a directory of Intune logs into a deterministic file list.
#[cfg(test)]
pub(crate) fn collect_input_paths(path: &Path) -> Result<Vec<PathBuf>, String> {
    Ok(resolve_intune_input(path)?.source_paths)
}

pub(crate) fn collect_directory_log_paths(path: &Path) -> Result<Vec<PathBuf>, String> {
    let entries =
        fs::read_dir(path).map_err(|error| describe_directory_read_error(path, &error))?;

    let mut files: Vec<PathBuf> = entries
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|entry_path| entry_path.is_file())
        .collect();

    files.sort_by_key(|p| {
        p.file_name()
            .map(|name| name.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default()
    });

    let mut ime_files: Vec<PathBuf> = files
        .iter()
        .filter(|p| is_ime_related_log_file(p))
        .cloned()
        .collect();

    if ime_files.is_empty() {
        ime_files = files.iter().filter(|p| is_log_file(p)).cloned().collect();
    }

    if ime_files.is_empty() {
        return Err(format!(
            "The selected folder does not contain any .log files to analyze: '{}'",
            path.display()
        ));
    }

    Ok(ime_files)
}

pub(crate) fn resolve_evidence_bundle_input(path: &Path) -> Result<Option<ResolvedIntuneInput>, String> {
    let manifest_path = path.join("manifest.json");
    if !manifest_path.is_file() {
        return Ok(None);
    }

    let manifest = match fs::read_to_string(&manifest_path) {
        Ok(content) => match serde_json::from_str::<Value>(&content) {
            Ok(value) => value,
            Err(error) => {
                log::error!(
                    "event=intune_bundle_manifest_parse_failed path=\"{}\" error=\"{}\"",
                    manifest_path.display(),
                    error
                );
                return Ok(None);
            }
        },
        Err(error) => {
            log::error!(
                "event=intune_bundle_manifest_read_failed path=\"{}\" error=\"{}\"",
                manifest_path.display(),
                error
            );
            return Ok(None);
        }
    };

    let evidence_bundle = build_evidence_bundle_metadata(path, &manifest);
    let source_paths = collect_bundle_log_paths(path, &manifest, &evidence_bundle)?;

    log::info!(
        "event=intune_bundle_resolved bundle_id=\"{}\" path=\"{}\" source_count={} available_primary_entry_points={}",
        evidence_bundle.bundle_id.as_deref().unwrap_or("unknown"),
        path.display(),
        source_paths.len(),
        evidence_bundle.available_primary_entry_points.len()
    );

    Ok(Some(ResolvedIntuneInput {
        source_paths,
        evidence_bundle: Some(evidence_bundle),
    }))
}

fn build_evidence_bundle_metadata(bundle_root: &Path, manifest: &Value) -> EvidenceBundleMetadata {
    let manifest_path = bundle_root.join("manifest.json");
    let notes_path = resolve_bundle_hint_path(
        bundle_root,
        json_string_at(manifest, &["intakeHints", "notesPath"]).as_deref(),
    )
    .or_else(|| {
        let default_path = bundle_root.join("notes.md");
        default_path.is_file().then_some(default_path)
    });
    let evidence_root = resolve_bundle_hint_path(
        bundle_root,
        json_string_at(manifest, &["intakeHints", "evidenceRoot"]).as_deref(),
    )
    .or_else(|| {
        let default_path = bundle_root.join("evidence");
        default_path.is_dir().then_some(default_path)
    });

    let mut primary_entry_points = resolve_bundle_primary_entry_points(bundle_root, manifest);
    if primary_entry_points.is_empty() {
        primary_entry_points = DEFAULT_BUNDLE_PRIMARY_ENTRY_POINTS
            .iter()
            .map(|relative| bundle_root.join(relative))
            .collect();
    }

    let available_primary_entry_points = primary_entry_points
        .iter()
        .filter(|entry| entry.exists())
        .map(|entry| entry.to_string_lossy().to_string())
        .collect();

    EvidenceBundleMetadata {
        manifest_path: manifest_path.to_string_lossy().to_string(),
        notes_path: notes_path.map(|value| value.to_string_lossy().to_string()),
        evidence_root: evidence_root.map(|value| value.to_string_lossy().to_string()),
        primary_entry_points: primary_entry_points
            .iter()
            .map(|entry| entry.to_string_lossy().to_string())
            .collect(),
        available_primary_entry_points,
        bundle_id: json_string_at(manifest, &["bundle", "bundleId"]),
        bundle_label: json_string_at(manifest, &["bundle", "bundleLabel"]),
        created_utc: json_string_at(manifest, &["bundle", "createdUtc"]),
        case_reference: json_string_at(manifest, &["bundle", "caseReference"]),
        summary: json_string_at(manifest, &["bundle", "summary"]),
        collector_profile: json_string_at(manifest, &["collection", "collectorProfile"]),
        collector_version: json_string_at(manifest, &["collection", "collectorVersion"]),
        collected_utc: json_string_at(manifest, &["collection", "collectedUtc"]),
        device_name: json_string_at(manifest, &["bundle", "device", "deviceName"]),
        primary_user: json_string_at(manifest, &["bundle", "device", "primaryUser"]),
        platform: json_string_at(manifest, &["bundle", "device", "platform"]),
        os_version: json_string_at(manifest, &["bundle", "device", "osVersion"]),
        tenant: json_string_at(manifest, &["bundle", "device", "tenant"]),
        artifact_counts: build_bundle_artifact_counts(manifest),
    }
}

fn build_bundle_artifact_counts(manifest: &Value) -> Option<EvidenceBundleArtifactCounts> {
    Some(EvidenceBundleArtifactCounts {
        collected: json_u64_at(
            manifest,
            &["collection", "results", "artifactCounts", "collected"],
        )?,
        missing: json_u64_at(
            manifest,
            &["collection", "results", "artifactCounts", "missing"],
        )?,
        failed: json_u64_at(
            manifest,
            &["collection", "results", "artifactCounts", "failed"],
        )?,
        skipped: json_u64_at(
            manifest,
            &["collection", "results", "artifactCounts", "skipped"],
        )?,
    })
}

fn collect_bundle_log_paths(
    bundle_root: &Path,
    manifest: &Value,
    evidence_bundle: &EvidenceBundleMetadata,
) -> Result<Vec<PathBuf>, String> {
    let primary_entry_points: Vec<PathBuf> = evidence_bundle
        .primary_entry_points
        .iter()
        .map(PathBuf::from)
        .collect();
    let mut seen = HashSet::new();
    let mut manifest_candidates = Vec::new();

    if let Some(artifacts) = manifest.get("artifacts").and_then(Value::as_array) {
        for artifact in artifacts {
            let Some(relative_path) = artifact.get("relativePath").and_then(Value::as_str) else {
                continue;
            };

            let candidate_path = bundle_root.join(relative_path);
            if !candidate_path.is_file() || !is_log_file(&candidate_path) {
                continue;
            }

            // Guard against path traversal via malicious relativePath values
            if let (Ok(canonical_root), Ok(canonical_candidate)) =
                (bundle_root.canonicalize(), candidate_path.canonicalize())
            {
                if !canonical_candidate.starts_with(&canonical_root) {
                    log::warn!(
                        "event=artifact_path_traversal_blocked relative_path=\"{}\" resolved=\"{}\"",
                        relative_path,
                        canonical_candidate.display()
                    );
                    continue;
                }
            }

            if !primary_entry_points.is_empty()
                && !primary_entry_points
                    .iter()
                    .any(|entry_point| candidate_path.starts_with(entry_point))
            {
                continue;
            }

            let key = candidate_path.to_string_lossy().to_string();
            if seen.insert(key) {
                manifest_candidates.push(candidate_path);
            }
        }
    }

    let mut selected = prioritize_ime_log_paths(manifest_candidates);
    if !selected.is_empty() {
        return Ok(selected);
    }

    let mut scanned_candidates = Vec::new();
    for entry_point in primary_entry_points {
        if !entry_point.is_dir() {
            continue;
        }

        let read_dir = fs::read_dir(&entry_point)
            .map_err(|error| describe_directory_read_error(&entry_point, &error))?;

        let mut entries: Vec<PathBuf> = read_dir
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|path| path.is_file() && is_log_file(path))
            .collect();

        entries.sort_by_key(|candidate| {
            candidate
                .file_name()
                .map(|value| value.to_string_lossy().to_ascii_lowercase())
                .unwrap_or_default()
        });

        for candidate in entries {
            let key = candidate.to_string_lossy().to_string();
            if seen.insert(key) {
                scanned_candidates.push(candidate);
            }
        }
    }

    selected = prioritize_ime_log_paths(scanned_candidates);
    Ok(selected)
}

fn prioritize_ime_log_paths(candidates: Vec<PathBuf>) -> Vec<PathBuf> {
    let ime_files: Vec<PathBuf> = candidates
        .iter()
        .filter(|path| is_ime_related_log_file(path))
        .cloned()
        .collect();

    if !ime_files.is_empty() {
        return ime_files;
    }

    candidates
}

fn resolve_bundle_primary_entry_points(bundle_root: &Path, manifest: &Value) -> Vec<PathBuf> {
    let manifest_entry_points =
        json_string_array_at(manifest, &["intakeHints", "primaryEntryPoints"]);
    let entry_points = if manifest_entry_points.is_empty() {
        DEFAULT_BUNDLE_PRIMARY_ENTRY_POINTS
            .iter()
            .map(|value| (*value).to_string())
            .collect()
    } else {
        manifest_entry_points
    };

    entry_points
        .iter()
        .filter_map(|entry| resolve_bundle_hint_path(bundle_root, Some(entry.as_str())))
        .collect()
}

fn resolve_bundle_hint_path(bundle_root: &Path, raw_path: Option<&str>) -> Option<PathBuf> {
    let raw_path = raw_path?.trim();
    if raw_path.is_empty() {
        return None;
    }

    let path = PathBuf::from(raw_path);
    let resolved = if path.is_absolute() {
        path
    } else {
        bundle_root.join(path)
    };

    // Canonicalize both paths to resolve symlinks and ".." components,
    // then verify the resolved path stays within the bundle root.
    let canonical_root = bundle_root.canonicalize().ok()?;
    let canonical_resolved = resolved.canonicalize().ok()?;
    if !canonical_resolved.starts_with(&canonical_root) {
        log::warn!(
            "event=path_traversal_blocked resolved=\"{}\" bundle_root=\"{}\"",
            canonical_resolved.display(),
            canonical_root.display()
        );
        return None;
    }

    Some(resolved)
}

fn json_value_at<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut current = value;
    for segment in path {
        current = current.get(*segment)?;
    }
    Some(current)
}

fn json_string_at(value: &Value, path: &[&str]) -> Option<String> {
    json_value_at(value, path)
        .and_then(Value::as_str)
        .map(|value| value.to_string())
}

fn json_u64_at(value: &Value, path: &[&str]) -> Option<u64> {
    json_value_at(value, path).and_then(Value::as_u64)
}

fn json_string_array_at(value: &Value, path: &[&str]) -> Vec<String> {
    json_value_at(value, path)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(|value| value.to_string())
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn is_log_file(path: &Path) -> bool {
    path.extension()
        .map(|ext| ext.to_string_lossy().eq_ignore_ascii_case("log"))
        .unwrap_or(false)
}

pub(crate) fn is_ime_related_log_file(path: &Path) -> bool {
    if !is_log_file(path) {
        return false;
    }

    path.file_name()
        .map(|name| {
            let name = name.to_string_lossy().to_ascii_lowercase();
            IME_LOG_PATTERNS
                .iter()
                .any(|pattern| name.contains(pattern))
        })
        .unwrap_or(false)
}
