use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::constants::DEFAULT_BUNDLE_PRIMARY_ENTRY_POINTS;
#[cfg(feature = "dsregcmd")]
use crate::dsregcmd::registry::{inspect_registry_snapshot_file, RegistrySnapshotSummary};
use crate::intune::models::{EvidenceBundleArtifactCounts, EvidenceBundleMetadata};
use crate::models::log_entry::{ParseQuality, ParserKind, ParserSelectionInfo, ParserSpecialization};
use crate::parser;

use super::file_ops::{normalize_path_string, metadata_modified_unix_ms, FolderEntry};

#[cfg(not(feature = "dsregcmd"))]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RegistrySnapshotValuePreview {
    pub name: String,
    pub value_type: String,
    pub value: String,
}

#[cfg(not(feature = "dsregcmd"))]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RegistrySnapshotKeyPreview {
    pub path: String,
    pub value_count: u32,
    pub values: Vec<RegistrySnapshotValuePreview>,
}

#[cfg(not(feature = "dsregcmd"))]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RegistrySnapshotSummary {
    pub key_count: u32,
    pub value_count: u32,
    pub keys: Vec<RegistrySnapshotKeyPreview>,
}

#[cfg(not(feature = "dsregcmd"))]
fn inspect_registry_snapshot_file(_path: &Path) -> Option<RegistrySnapshotSummary> {
    None
}

// ── Types ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceArtifactTimeCoverage {
    pub start_utc: Option<String>,
    pub end_utc: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum EvidenceArtifactIntakeKind {
    Log,
    RegistrySnapshot,
    EventLogExport,
    CommandOutput,
    Screenshot,
    Export,
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum EvidenceArtifactIntakeStatus {
    Recognized,
    Generic,
    Unsupported,
    Missing,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceArtifactIntake {
    pub kind: EvidenceArtifactIntakeKind,
    pub status: EvidenceArtifactIntakeStatus,
    pub recognized_as: Option<String>,
    pub summary: String,
    pub parser_selection: Option<ParserSelectionInfo>,
    pub parse_diagnostics: Option<EvidenceArtifactParseDiagnostics>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceArtifactParseDiagnostics {
    pub total_lines: u32,
    pub entry_count: u32,
    pub parse_errors: u32,
    pub clean_parse: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceArtifactRecord {
    pub artifact_id: Option<String>,
    pub category: String,
    pub family: Option<String>,
    pub relative_path: String,
    pub absolute_path: Option<String>,
    pub origin_path: Option<String>,
    pub collected_utc: Option<String>,
    pub status: String,
    #[serde(default)]
    pub parse_hints: Vec<String>,
    pub notes: Option<String>,
    pub time_coverage: Option<EvidenceArtifactTimeCoverage>,
    pub sha256: Option<String>,
    pub exists_on_disk: bool,
    pub intake: EvidenceArtifactIntake,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExpectedEvidenceRecord {
    pub category: String,
    pub relative_path: String,
    pub required: bool,
    pub reason: Option<String>,
    pub available: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceBundleDetails {
    pub bundle_root_path: String,
    pub metadata: EvidenceBundleMetadata,
    pub manifest_content: String,
    pub notes_content: Option<String>,
    #[serde(default)]
    pub artifacts: Vec<EvidenceArtifactRecord>,
    #[serde(default)]
    pub expected_evidence: Vec<ExpectedEvidenceRecord>,
    #[serde(default)]
    pub observed_gaps: Vec<String>,
    #[serde(default)]
    pub priority_questions: Vec<String>,
    pub handoff_summary: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceEventLogExportPreview {
    pub channel: Option<String>,
    pub file_size_bytes: Option<u64>,
    pub modified_unix_ms: Option<u64>,
    pub export_format: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceArtifactPreview {
    pub path: String,
    pub intake_kind: EvidenceArtifactIntakeKind,
    pub summary: String,
    pub registry_snapshot: Option<RegistrySnapshotSummary>,
    pub event_log_export: Option<EvidenceEventLogExportPreview>,
}

// ── Constants ───────────────────────────────────────────────────────────

/// File extensions that are binary / non-parseable as text logs.
/// These are skipped during recursive bundle collection.
const BINARY_EXTENSIONS: &[&str] = &[
    "etl", "dat", "zip", "cab", "tmp", "dir", "que", "evtx",
];

/// Maximum file size (in bytes) to include in batch aggregate parsing.
/// Files larger than this are still listed in the sidebar but excluded from
/// the automatic batch load to avoid long stalls (e.g. 180 MB CBS logs).
/// Users can still open them individually.
const BUNDLE_BATCH_MAX_FILE_SIZE: u64 = 50 * 1024 * 1024; // 50 MB

// ── Tauri Commands ──────────────────────────────────────────────────────

#[tauri::command]
pub fn inspect_evidence_bundle(path: String) -> Result<EvidenceBundleDetails, crate::error::AppError> {
    inspect_evidence_bundle_details(Path::new(&path))
}

#[tauri::command]
pub fn inspect_evidence_artifact(
    path: String,
    intake_kind: EvidenceArtifactIntakeKind,
    origin_path: Option<String>,
) -> Result<EvidenceArtifactPreview, crate::error::AppError> {
    inspect_evidence_artifact_preview(Path::new(&path), intake_kind, origin_path)
}

// ── Public helpers (used by file_ops::list_log_folder) ──────────────────

/// Recursively collects all **text-parseable files** under `root`, returning
/// them as flat `FolderEntry` items (no directory entries).  Used when opening
/// an evidence bundle so that every nested artifact is included in the listing.
///
/// Files with known binary extensions and files exceeding
/// `BUNDLE_BATCH_MAX_FILE_SIZE` are excluded from the listing and logged as
/// skipped.  They remain accessible from the sidebar for individual opening.
pub(crate) fn collect_files_recursive(root: &Path) -> Vec<FolderEntry> {
    let mut out = Vec::new();
    let mut skipped_binary = 0u32;
    let mut skipped_large = 0u32;
    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];

    while let Some(dir) = stack.pop() {
        let read_dir = match fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(e) => {
                log::warn!(
                    "event=collect_files_recursive_skip reason=read_dir_error path=\"{}\" error=\"{e}\"",
                    dir.display()
                );
                continue;
            }
        };

        for entry_result in read_dir {
            let entry = match entry_result {
                Ok(v) => v,
                Err(e) => {
                    log::warn!(
                        "event=collect_files_recursive_skip reason=entry_error dir=\"{}\" error=\"{e}\"",
                        dir.display()
                    );
                    continue;
                }
            };

            let entry_path = entry.path();
            let metadata = match entry.metadata() {
                Ok(m) => m,
                Err(e) => {
                    log::warn!(
                        "event=collect_files_recursive_skip reason=metadata_error path=\"{}\" error=\"{e}\"",
                        entry_path.display()
                    );
                    continue;
                }
            };

            if metadata.is_dir() {
                stack.push(entry_path);
                continue;
            }

            // Skip known binary extensions
            if let Some(ext) = entry_path.extension().and_then(|e| e.to_str()) {
                if BINARY_EXTENSIONS.iter().any(|b| b.eq_ignore_ascii_case(ext)) {
                    skipped_binary += 1;
                    log::debug!(
                        "event=collect_files_recursive_skip reason=binary_extension path=\"{}\"",
                        entry_path.display()
                    );
                    continue;
                }
            }

            // Skip files exceeding the size cap
            let size = metadata.len();
            if size > BUNDLE_BATCH_MAX_FILE_SIZE {
                skipped_large += 1;
                log::debug!(
                    "event=collect_files_recursive_skip reason=file_too_large path=\"{}\" size={size}",
                    entry_path.display()
                );
                continue;
            }

            out.push(FolderEntry {
                name: entry.file_name().to_string_lossy().to_string(),
                path: normalize_path_string(&entry_path),
                is_dir: false,
                size_bytes: Some(size),
                modified_unix_ms: metadata_modified_unix_ms(&metadata),
            });
        }
    }

    log::info!(
        "event=collect_files_recursive_done root=\"{}\" included={} skipped_binary={skipped_binary} skipped_large={skipped_large}",
        root.display(),
        out.len()
    );

    out
}

pub(crate) fn detect_evidence_bundle_metadata(path: &Path) -> Option<EvidenceBundleMetadata> {
    let manifest_path = path.join("manifest.json");
    if !manifest_path.is_file() {
        return None;
    }

    let manifest_content = fs::read_to_string(&manifest_path).ok()?;
    let manifest = serde_json::from_str::<Value>(&manifest_content).ok()?;

    let mut primary_entry_points = resolve_bundle_primary_entry_points(path, &manifest);
    if primary_entry_points.is_empty() {
        primary_entry_points = DEFAULT_BUNDLE_PRIMARY_ENTRY_POINTS
            .iter()
            .map(|relative| path.join(relative))
            .collect();
    }

    Some(EvidenceBundleMetadata {
        manifest_path: manifest_path.to_string_lossy().to_string(),
        notes_path: resolve_bundle_hint_path(
            path,
            json_string_at(&manifest, &["intakeHints", "notesPath"]).as_deref(),
        )
        .or_else(|| {
            let default_path = path.join("notes.md");
            default_path.is_file().then_some(default_path)
        })
        .map(|value| value.to_string_lossy().to_string()),
        evidence_root: resolve_bundle_hint_path(
            path,
            json_string_at(&manifest, &["intakeHints", "evidenceRoot"]).as_deref(),
        )
        .or_else(|| {
            let default_path = path.join("evidence");
            default_path.is_dir().then_some(default_path)
        })
        .map(|value| value.to_string_lossy().to_string()),
        primary_entry_points: primary_entry_points
            .iter()
            .map(|entry| entry.to_string_lossy().to_string())
            .collect(),
        available_primary_entry_points: primary_entry_points
            .iter()
            .filter(|entry| entry.exists())
            .map(|entry| entry.to_string_lossy().to_string())
            .collect(),
        bundle_id: json_string_at(&manifest, &["bundle", "bundleId"]),
        bundle_label: json_string_at(&manifest, &["bundle", "bundleLabel"]),
        created_utc: json_string_at(&manifest, &["bundle", "createdUtc"]),
        case_reference: json_string_at(&manifest, &["bundle", "caseReference"]),
        summary: json_string_at(&manifest, &["bundle", "summary"]),
        collector_profile: json_string_at(&manifest, &["collection", "collectorProfile"]),
        collector_version: json_string_at(&manifest, &["collection", "collectorVersion"]),
        collected_utc: json_string_at(&manifest, &["collection", "collectedUtc"]),
        device_name: json_string_at(&manifest, &["bundle", "device", "deviceName"]),
        primary_user: json_string_at(&manifest, &["bundle", "device", "primaryUser"]),
        platform: json_string_at(&manifest, &["bundle", "device", "platform"]),
        os_version: json_string_at(&manifest, &["bundle", "device", "osVersion"]),
        tenant: json_string_at(&manifest, &["bundle", "device", "tenant"]),
        artifact_counts: Some(EvidenceBundleArtifactCounts {
            collected: json_u64_at(
                &manifest,
                &["collection", "results", "artifactCounts", "collected"],
            )?,
            missing: json_u64_at(
                &manifest,
                &["collection", "results", "artifactCounts", "missing"],
            )?,
            failed: json_u64_at(
                &manifest,
                &["collection", "results", "artifactCounts", "failed"],
            )?,
            skipped: json_u64_at(
                &manifest,
                &["collection", "results", "artifactCounts", "skipped"],
            )?,
        }),
    })
}

// ── Private helpers ─────────────────────────────────────────────────────

fn inspect_evidence_bundle_details(path: &Path) -> Result<EvidenceBundleDetails, crate::error::AppError> {
    if !path.exists() {
        return Err(crate::error::AppError::InvalidInput(format!("bundle path does not exist: {}", path.display())));
    }

    if !path.is_dir() {
        return Err(crate::error::AppError::InvalidInput(format!("bundle path is not a folder: {}", path.display())));
    }

    let manifest_path = path.join("manifest.json");
    if !manifest_path.is_file() {
        return Err(crate::error::AppError::InvalidInput(format!(
            "manifest.json was not found under {}",
            path.display()
        )));
    }

    let manifest_content = fs::read_to_string(&manifest_path)
        .map_err(crate::error::AppError::Io)?;
    let manifest = serde_json::from_str::<Value>(&manifest_content)
        .map_err(|error| crate::error::AppError::Internal(format!("failed to parse {}: {}", manifest_path.display(), error)))?;
    let metadata = detect_evidence_bundle_metadata(path)
        .ok_or_else(|| crate::error::AppError::Internal(format!("{} is not a recognized evidence bundle", path.display())))?;

    let artifacts = json_value_at(&manifest, &["artifacts"])
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| parse_evidence_artifact_record(path, item))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let expected_evidence = json_value_at(&manifest, &["expectedEvidence"])
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| parse_expected_evidence_record(path, &artifacts, item))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let notes_content = metadata
        .notes_path
        .as_ref()
        .and_then(|notes_path| fs::read_to_string(notes_path).ok());

    Ok(EvidenceBundleDetails {
        bundle_root_path: normalize_path_string(path),
        metadata,
        manifest_content,
        notes_content,
        artifacts,
        expected_evidence,
        observed_gaps: json_string_array_at(&manifest, &["analysis", "observedGaps"]),
        priority_questions: json_string_array_at(&manifest, &["analysis", "priorityQuestions"]),
        handoff_summary: json_string_at(&manifest, &["analysis", "handoffSummary"]),
    })
}

fn parse_evidence_artifact_record(
    bundle_root: &Path,
    value: &Value,
) -> Option<EvidenceArtifactRecord> {
    let relative_path = json_string_at(value, &["relativePath"])?;
    let absolute_path = resolve_bundle_hint_path(bundle_root, Some(relative_path.as_str()));
    let exists_on_disk = absolute_path.as_ref().is_some_and(|path| path.exists());
    let category = json_string_at(value, &["category"]).unwrap_or_else(|| "unknown".to_string());
    let family = json_string_at(value, &["family"]);
    let parse_hints = json_string_array_at(value, &["parseHints"]);
    let intake = detect_artifact_intake(
        &category,
        family.as_deref(),
        &relative_path,
        absolute_path.as_deref(),
        exists_on_disk,
        &parse_hints,
    );

    Some(EvidenceArtifactRecord {
        artifact_id: json_string_at(value, &["artifactId"]),
        category,
        family,
        relative_path,
        absolute_path: absolute_path.map(|value| value.to_string_lossy().to_string()),
        origin_path: json_string_at(value, &["originPath"]),
        collected_utc: json_string_at(value, &["collectedUtc"]),
        status: json_string_at(value, &["status"])
            .map(|value| value.to_ascii_lowercase())
            .unwrap_or_else(|| "unknown".to_string()),
        parse_hints,
        notes: json_string_at(value, &["notes"]),
        time_coverage: parse_artifact_time_coverage(value),
        sha256: json_string_at(value, &["hashes", "sha256"]),
        exists_on_disk,
        intake,
    })
}

fn detect_artifact_intake(
    category: &str,
    family: Option<&str>,
    relative_path: &str,
    absolute_path: Option<&Path>,
    exists_on_disk: bool,
    parse_hints: &[String],
) -> EvidenceArtifactIntake {
    if !exists_on_disk {
        return EvidenceArtifactIntake {
            kind: classify_artifact_intake_kind(category),
            status: EvidenceArtifactIntakeStatus::Missing,
            recognized_as: None,
            summary: "Artifact is not available on disk in this bundle.".to_string(),
            parser_selection: None,
            parse_diagnostics: None,
        };
    }

    match classify_artifact_intake_kind(category) {
        EvidenceArtifactIntakeKind::Log => detect_log_artifact_intake(relative_path, absolute_path),
        EvidenceArtifactIntakeKind::RegistrySnapshot => EvidenceArtifactIntake {
            kind: EvidenceArtifactIntakeKind::RegistrySnapshot,
            status: EvidenceArtifactIntakeStatus::Recognized,
            recognized_as: Some("Registry snapshot".to_string()),
            summary: "Captured as structured registry evidence for offline inspection.".to_string(),
            parser_selection: None,
            parse_diagnostics: None,
        },
        EvidenceArtifactIntakeKind::EventLogExport => EvidenceArtifactIntake {
            kind: EvidenceArtifactIntakeKind::EventLogExport,
            status: EvidenceArtifactIntakeStatus::Recognized,
            recognized_as: Some("Curated event evidence".to_string()),
            summary: "Captured as event-log evidence for correlation outside the log parser."
                .to_string(),
            parser_selection: None,
            parse_diagnostics: None,
        },
        EvidenceArtifactIntakeKind::CommandOutput => {
            detect_command_output_artifact_intake(relative_path, family, parse_hints)
        }
        EvidenceArtifactIntakeKind::Screenshot => EvidenceArtifactIntake {
            kind: EvidenceArtifactIntakeKind::Screenshot,
            status: EvidenceArtifactIntakeStatus::Recognized,
            recognized_as: Some("Screenshot capture".to_string()),
            summary: "Captured as visual supporting evidence.".to_string(),
            parser_selection: None,
            parse_diagnostics: None,
        },
        EvidenceArtifactIntakeKind::Export => EvidenceArtifactIntake {
            kind: EvidenceArtifactIntakeKind::Export,
            status: EvidenceArtifactIntakeStatus::Recognized,
            recognized_as: Some("Exported evidence".to_string()),
            summary: "Captured as exported supporting evidence.".to_string(),
            parser_selection: None,
            parse_diagnostics: None,
        },
        EvidenceArtifactIntakeKind::Unknown => EvidenceArtifactIntake {
            kind: EvidenceArtifactIntakeKind::Unknown,
            status: EvidenceArtifactIntakeStatus::Unsupported,
            recognized_as: None,
            summary: "Captured artifact category is not yet classified by the app.".to_string(),
            parser_selection: None,
            parse_diagnostics: None,
        },
    }
}

fn classify_artifact_intake_kind(category: &str) -> EvidenceArtifactIntakeKind {
    match category.to_ascii_lowercase().as_str() {
        "logs" => EvidenceArtifactIntakeKind::Log,
        "registry" => EvidenceArtifactIntakeKind::RegistrySnapshot,
        "event-log" | "event-logs" => EvidenceArtifactIntakeKind::EventLogExport,
        "command-output" => EvidenceArtifactIntakeKind::CommandOutput,
        "screenshots" => EvidenceArtifactIntakeKind::Screenshot,
        "exports" => EvidenceArtifactIntakeKind::Export,
        _ => EvidenceArtifactIntakeKind::Unknown,
    }
}

fn inspect_evidence_artifact_preview(
    path: &Path,
    intake_kind: EvidenceArtifactIntakeKind,
    origin_path: Option<String>,
) -> Result<EvidenceArtifactPreview, crate::error::AppError> {
    if !path.exists() {
        return Err(crate::error::AppError::InvalidInput(format!("artifact path does not exist: {}", path.display())));
    }

    if !path.is_file() {
        return Err(crate::error::AppError::InvalidInput(format!("artifact path is not a file: {}", path.display())));
    }

    match intake_kind {
        EvidenceArtifactIntakeKind::RegistrySnapshot => {
            let Some(registry_snapshot) = inspect_registry_snapshot_file(path) else {
                return Ok(EvidenceArtifactPreview {
                    path: normalize_path_string(path),
                    intake_kind,
                    summary:
                        "Registry snapshot preview is not available in lite builds. Use a full build with the dsregcmd feature enabled."
                            .to_string(),
                    registry_snapshot: None,
                    event_log_export: None,
                });
            };
            let summary = format!(
                "Parsed {} registry key{} and {} value{} from this exported snapshot.",
                registry_snapshot.key_count,
                if registry_snapshot.key_count == 1 { "" } else { "s" },
                registry_snapshot.value_count,
                if registry_snapshot.value_count == 1 { "" } else { "s" }
            );

            Ok(EvidenceArtifactPreview {
                path: normalize_path_string(path),
                intake_kind,
                summary,
                registry_snapshot: Some(registry_snapshot),
                event_log_export: None,
            })
        }
        EvidenceArtifactIntakeKind::EventLogExport => {
            let metadata = fs::metadata(path)
                .map_err(crate::error::AppError::Io)?;
            let export_format = path
                .extension()
                .and_then(|extension| extension.to_str())
                .map(|extension| extension.to_ascii_lowercase())
                .unwrap_or_else(|| "unknown".to_string());
            let channel_summary = origin_path
                .as_deref()
                .map(|channel| format!("Captured from {}.", channel))
                .unwrap_or_else(|| "Captured as a curated event-log export.".to_string());

            Ok(EvidenceArtifactPreview {
                path: normalize_path_string(path),
                intake_kind,
                summary: format!(
                    "{} Review stays bundle-first here; full event extraction is a later Push 2 follow-on.",
                    channel_summary
                ),
                registry_snapshot: None,
                event_log_export: Some(EvidenceEventLogExportPreview {
                    channel: origin_path,
                    file_size_bytes: Some(metadata.len()),
                    modified_unix_ms: metadata_modified_unix_ms(&metadata),
                    export_format,
                }),
            })
        }
        _ => Err(crate::error::AppError::InvalidInput("artifact preview is currently supported for registry snapshots and event-log exports only".to_string())),
    }
}

fn detect_log_artifact_intake(
    relative_path: &str,
    absolute_path: Option<&Path>,
) -> EvidenceArtifactIntake {
    let Some(absolute_path) = absolute_path else {
        return EvidenceArtifactIntake {
            kind: EvidenceArtifactIntakeKind::Log,
            status: EvidenceArtifactIntakeStatus::Missing,
            recognized_as: None,
            summary: "Artifact is not available on disk in this bundle.".to_string(),
            parser_selection: None,
            parse_diagnostics: None,
        };
    };

    if !is_text_like_artifact_path(absolute_path) {
        return EvidenceArtifactIntake {
            kind: EvidenceArtifactIntakeKind::Log,
            status: EvidenceArtifactIntakeStatus::Unsupported,
            recognized_as: Some("Non-text log artifact".to_string()),
            summary:
                "This log artifact is not a text log that the current parser pipeline can inspect."
                    .to_string(),
            parser_selection: None,
            parse_diagnostics: None,
        };
    }

    let content = match fs::read_to_string(absolute_path) {
        Ok(content) => content,
        Err(_) => {
            return EvidenceArtifactIntake {
                kind: EvidenceArtifactIntakeKind::Log,
                status: EvidenceArtifactIntakeStatus::Unsupported,
                recognized_as: Some("Unreadable text log".to_string()),
                summary: "The artifact could not be read as UTF-8 text for intake classification."
                    .to_string(),
                parser_selection: None,
                parse_diagnostics: None,
            };
        }
    };

    let resolved_parser = parser::detect::detect_parser(relative_path, &content);
    let parsed_chunk =
        parser::parse_content_with_selection(&content, relative_path, &resolved_parser);
    let parser_selection = resolved_parser.to_info();
    let recognized_as = Some(describe_parser_selection(&parser_selection));
    let status = if parser_selection.parse_quality == ParseQuality::TextFallback {
        EvidenceArtifactIntakeStatus::Generic
    } else {
        EvidenceArtifactIntakeStatus::Recognized
    };
    let entry_count = u32::try_from(parsed_chunk.entries.len()).unwrap_or(u32::MAX);
    let parse_diagnostics = EvidenceArtifactParseDiagnostics {
        total_lines: parsed_chunk.total_lines,
        entry_count,
        parse_errors: parsed_chunk.parse_errors,
        clean_parse: parsed_chunk.parse_errors == 0,
    };
    let summary = if status == EvidenceArtifactIntakeStatus::Recognized {
        if parse_diagnostics.clean_parse {
            format!(
                "Recognized as {} and parsed cleanly across {} line{}.",
                recognized_as.as_deref().unwrap_or("a known log source"),
                parse_diagnostics.total_lines,
                if parse_diagnostics.total_lines == 1 {
                    ""
                } else {
                    "s"
                }
            )
        } else {
            format!(
                "Recognized as {} with {} parse issue{} across {} line{}.",
                recognized_as.as_deref().unwrap_or("a known log source"),
                parse_diagnostics.parse_errors,
                if parse_diagnostics.parse_errors == 1 {
                    ""
                } else {
                    "s"
                },
                parse_diagnostics.total_lines,
                if parse_diagnostics.total_lines == 1 {
                    ""
                } else {
                    "s"
                }
            )
        }
    } else {
        "Read as text, but only generic text fallback was recognized for this artifact.".to_string()
    };

    EvidenceArtifactIntake {
        kind: EvidenceArtifactIntakeKind::Log,
        status,
        recognized_as,
        summary,
        parser_selection: Some(parser_selection),
        parse_diagnostics: Some(parse_diagnostics),
    }
}

fn detect_command_output_artifact_intake(
    relative_path: &str,
    family: Option<&str>,
    parse_hints: &[String],
) -> EvidenceArtifactIntake {
    let recognized_as =
        if text_matches_any(relative_path, &["dsregcmd", "entra", "azuread", "join"])
            || family.is_some_and(|value| {
                text_matches_any(value, &["dsregcmd", "entra", "azuread", "join"])
            })
            || parse_hints
                .iter()
                .any(|value| text_matches_any(value, &["dsregcmd", "entra", "azuread", "join"]))
        {
            Some("dsregcmd command output".to_string())
        } else {
            family
                .filter(|value| !value.trim().is_empty())
                .map(|value| format!("{} command output", value.trim()))
                .or_else(|| Some("Command output".to_string()))
        };

    EvidenceArtifactIntake {
        kind: EvidenceArtifactIntakeKind::CommandOutput,
        status: EvidenceArtifactIntakeStatus::Recognized,
        recognized_as,
        summary: "Captured as command-output evidence for read-only review.".to_string(),
        parser_selection: None,
        parse_diagnostics: None,
    }
}

fn describe_parser_selection(parser_selection: &ParserSelectionInfo) -> String {
    match parser_selection.specialization {
        Some(ParserSpecialization::Ime) => "Intune IME log".to_string(),
        None => match parser_selection.parser {
            ParserKind::Ccm => "CCM-style log".to_string(),
            ParserKind::Simple => "Simple format log".to_string(),
            ParserKind::Timestamped => "Generic timestamped log".to_string(),
            ParserKind::Plain => "Plain text log".to_string(),
            ParserKind::Panther => "Windows Panther log".to_string(),
            ParserKind::Cbs => "CBS servicing log".to_string(),
            ParserKind::Dism => "DISM servicing log".to_string(),
            ParserKind::ReportingEvents => "Windows Update reporting log".to_string(),
            ParserKind::Msi => "MSI verbose log".to_string(),
            ParserKind::PsadtLegacy => "PSADT Legacy format log".to_string(),
            ParserKind::IntuneMacOs => "Intune macOS MDM log".to_string(),
            ParserKind::Dhcp => "Windows DHCP Server log".to_string(),
            ParserKind::Burn => "WiX/Burn bootstrapper log".to_string(),
            ParserKind::Registry => "Windows Registry export".to_string(),
        },
    }
}

fn text_matches_any(value: &str, terms: &[&str]) -> bool {
    let normalized = value.to_ascii_lowercase();
    terms.iter().any(|term| normalized.contains(term))
}

fn is_text_like_artifact_path(path: &Path) -> bool {
    matches!(
        path.extension()
            .and_then(|extension| extension.to_str())
            .map(|extension| extension.to_ascii_lowercase()),
        Some(extension) if extension == "log" || extension == "lo_" || extension == "txt"
    )
}

fn parse_artifact_time_coverage(value: &Value) -> Option<EvidenceArtifactTimeCoverage> {
    let time_coverage = json_value_at(value, &["timeCoverage"])?;
    let start_utc = json_string_at(time_coverage, &["startUtc"]);
    let end_utc = json_string_at(time_coverage, &["endUtc"]);

    if start_utc.is_none() && end_utc.is_none() {
        return None;
    }

    Some(EvidenceArtifactTimeCoverage { start_utc, end_utc })
}

fn parse_expected_evidence_record(
    bundle_root: &Path,
    artifacts: &[EvidenceArtifactRecord],
    value: &Value,
) -> Option<ExpectedEvidenceRecord> {
    let category = json_string_at(value, &["category"])?;
    let relative_path = json_string_at(value, &["relativePath"])?;
    let candidate_path = resolve_bundle_hint_path(bundle_root, Some(relative_path.as_str()));
    let available = artifacts
        .iter()
        .any(|artifact| artifact.relative_path == relative_path && artifact.status == "collected")
        || candidate_path.as_ref().is_some_and(|path| path.exists());

    Some(ExpectedEvidenceRecord {
        category,
        relative_path,
        required: json_bool_at(value, &["required"]).unwrap_or(false),
        reason: json_string_at(value, &["reason"]),
        available,
    })
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
    if path.is_absolute() {
        Some(path)
    } else {
        Some(bundle_root.join(path))
    }
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

fn json_bool_at(value: &Value, path: &[&str]) -> Option<bool> {
    json_value_at(value, path).and_then(Value::as_bool)
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

#[cfg(test)]
mod tests {
    use super::{
        inspect_evidence_artifact, inspect_evidence_bundle,
        EvidenceArtifactIntakeKind,
    };
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn inspect_evidence_bundle_returns_inventory_and_notes_preview() {
        let bundle_dir = create_temp_dir("bundle-ops-bundle-details");
        fs::create_dir_all(bundle_dir.join("evidence").join("logs")).expect("create logs dir");
        fs::create_dir_all(bundle_dir.join("evidence").join("registry"))
            .expect("create registry dir");
        fs::write(
            bundle_dir.join("evidence").join("logs").join("IntuneManagementExtension.log"),
            "<![LOG[[Win32App] Processing policy]LOG]!><time=\"11:48:12.2482476\" date=\"3-12-2025\" component=\"IntuneManagementExtension\" context=\"\" type=\"1\" thread=\"14\" file=\"\">",
        )
        .expect("write log");
        fs::write(bundle_dir.join("notes.md"), "bundle notes").expect("write notes");
        fs::write(bundle_dir.join("manifest.json"), sample_bundle_manifest())
            .expect("write manifest");

        let result = inspect_evidence_bundle(bundle_dir.to_string_lossy().to_string())
            .expect("inspect bundle");
        let log_artifact = result
            .artifacts
            .iter()
            .find(|artifact| artifact.category == "logs")
            .expect("log artifact");
        let registry_artifact = result
            .artifacts
            .iter()
            .find(|artifact| artifact.category == "registry")
            .expect("registry artifact");

        assert_eq!(
            result.bundle_root_path,
            bundle_dir.to_string_lossy().to_string()
        );
        assert_eq!(result.notes_content.as_deref(), Some("bundle notes"));
        assert_eq!(result.artifacts.len(), 2);
        assert!(result
            .artifacts
            .iter()
            .any(|artifact| artifact.exists_on_disk));
        assert_eq!(
            log_artifact.intake.kind,
            super::EvidenceArtifactIntakeKind::Log
        );
        assert_eq!(
            log_artifact.intake.status,
            super::EvidenceArtifactIntakeStatus::Recognized
        );
        assert_eq!(
            log_artifact.intake.recognized_as.as_deref(),
            Some("Intune IME log")
        );
        assert!(log_artifact.intake.parser_selection.is_some());
        assert_eq!(
            log_artifact
                .intake
                .parse_diagnostics
                .as_ref()
                .map(|diagnostics| diagnostics.parse_errors),
            Some(0)
        );
        assert_eq!(
            registry_artifact.intake.kind,
            super::EvidenceArtifactIntakeKind::RegistrySnapshot
        );
        assert_eq!(
            registry_artifact.intake.status,
            super::EvidenceArtifactIntakeStatus::Missing
        );
        assert_eq!(result.expected_evidence.len(), 2);
        assert!(result.expected_evidence.iter().any(|entry| entry.available));
        assert!(result
            .observed_gaps
            .iter()
            .any(|gap| gap.contains("registry")));
        assert!(result
            .priority_questions
            .iter()
            .any(|question| question.contains("policy")));

        fs::remove_dir_all(&bundle_dir).expect("remove temp bundle dir");
    }

    #[test]
    fn inspect_evidence_artifact_previews_registry_and_event_exports() {
        let bundle_dir = create_temp_dir("bundle-ops-artifact-preview");
        let registry_dir = bundle_dir.join("evidence").join("registry");
        let event_dir = bundle_dir.join("evidence").join("event-logs");
        fs::create_dir_all(&registry_dir).expect("create registry dir");
        fs::create_dir_all(&event_dir).expect("create event dir");

        let registry_path = registry_dir.join("policymanager-device.reg");
        fs::write(
            &registry_path,
            r#"Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\Current\Device\PassportForWork\Policies]
"UsePassportForWork"=dword:00000001
"TenantName"="Contoso"
"#,
        )
        .expect("write registry export");

        let event_path = event_dir.join("device-management-admin.evtx");
        fs::write(&event_path, b"EVTX").expect("write event log export");

        let registry_preview = inspect_evidence_artifact(
            registry_path.to_string_lossy().to_string(),
            EvidenceArtifactIntakeKind::RegistrySnapshot,
            Some("HKLM\\SOFTWARE\\Microsoft\\PolicyManager".to_string()),
        )
        .expect("inspect registry artifact");
        let event_preview = inspect_evidence_artifact(
            event_path.to_string_lossy().to_string(),
            EvidenceArtifactIntakeKind::EventLogExport,
            Some(
                "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin"
                    .to_string(),
            ),
        )
        .expect("inspect event artifact");

        #[cfg(feature = "dsregcmd")]
        {
            assert!(registry_preview.registry_snapshot.is_some());
            assert!(registry_preview.summary.contains("registry key"));
        }

        #[cfg(not(feature = "dsregcmd"))]
        {
            assert!(registry_preview.registry_snapshot.is_none());
            assert!(registry_preview
                .summary
                .contains("not available in lite builds"));
        }
        assert!(event_preview.event_log_export.is_some());
        assert_eq!(
            event_preview
                .event_log_export
                .as_ref()
                .and_then(|preview| preview.channel.as_deref()),
            Some("Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin")
        );

        fs::remove_dir_all(&bundle_dir).expect("remove temp bundle dir");
    }

    fn create_temp_dir(prefix: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("{}-{}", prefix, unique));
        fs::create_dir_all(&path).expect("create temp dir");
        path
    }

    fn sample_bundle_manifest() -> &'static str {
        r#"{
    "bundle": {
        "bundleId": "CMTRACE-123",
        "bundleLabel": "intune-endpoint-evidence",
        "createdUtc": "2026-03-12T16:00:54Z",
        "caseReference": "case-123",
        "summary": "Curated endpoint evidence bundle.",
        "device": {
            "deviceName": "GELL-VM-5879648",
            "primaryUser": "AzureAD\\AdamGell",
            "platform": "Windows",
            "osVersion": "Windows 11",
            "tenant": "CDWWorkspaceLab"
        }
    },
    "collection": {
        "collectorProfile": "intune-windows-endpoint-v1",
        "collectorVersion": "1.1.0",
        "collectedUtc": "2026-03-12T16:00:54Z",
        "results": {
            "artifactCounts": {
                "collected": 55,
                "missing": 7,
                "failed": 2,
                "skipped": 0
            }
        }
    },
    "artifacts": [
        {
            "artifactId": "ime-log",
            "category": "logs",
            "family": "intune-ime",
            "relativePath": "evidence/logs/IntuneManagementExtension.log",
            "originPath": "C:\\ProgramData\\Microsoft\\IntuneManagementExtension\\Logs\\IntuneManagementExtension.log",
            "collectedUtc": "2026-03-12T16:00:54Z",
            "status": "collected",
            "parseHints": ["intune-ime", "cmtrace"],
            "timeCoverage": {
                "startUtc": "2026-03-12T15:00:00Z",
                "endUtc": "2026-03-12T16:00:00Z"
            },
            "hashes": {
                "sha256": "abc123"
            },
            "notes": "Primary IME log"
        },
        {
            "artifactId": "device-registry",
            "category": "registry",
            "family": "enrollment",
            "relativePath": "evidence/registry/device.reg",
            "originPath": "HKLM\\Software\\Microsoft",
            "collectedUtc": "2026-03-12T16:01:12Z",
            "status": "missing",
            "parseHints": ["reg-export"],
            "notes": "Registry export missing on device"
        }
    ],
    "expectedEvidence": [
        {
            "category": "logs",
            "relativePath": "evidence/logs/IntuneManagementExtension.log",
            "required": true,
            "reason": "Primary Intune IME execution trace"
        },
        {
            "category": "registry",
            "relativePath": "evidence/registry/device.reg",
            "required": true,
            "reason": "Enrollment registry state"
        }
    ],
    "analysis": {
        "observedGaps": [
            "Expected registry export was not collected."
        ],
        "priorityQuestions": [
            "Did policy evaluation fail before IME content download?"
        ],
        "handoffSummary": "Start with the IME log, then confirm registry enrollment state."
    },
    "intakeHints": {
        "notesPath": "notes.md",
        "evidenceRoot": "evidence",
        "primaryEntryPoints": [
            "evidence/logs",
            "evidence/registry",
            "evidence/event-logs",
            "evidence/exports",
            "evidence/screenshots",
            "evidence/command-output"
        ]
    }
}"#
    }
}
