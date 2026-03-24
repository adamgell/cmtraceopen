use std::cmp::Ordering;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tauri::State;

use crate::dsregcmd::registry::{inspect_registry_snapshot_file, RegistrySnapshotSummary};
use crate::intune::models::{EvidenceBundleArtifactCounts, EvidenceBundleMetadata};
use crate::models::log_entry::{
    AggregateParseResult, AggregateParsedFileResult, LogEntry, ParseQuality, ParseResult,
    ParserKind, ParserSelectionInfo, ParserSpecialization,
};
use crate::parser;
use crate::state::app_state::{AppState, OpenFile};

const DEFAULT_BUNDLE_PRIMARY_ENTRY_POINTS: &[&str] = &[
    "evidence/logs",
    "evidence/registry",
    "evidence/event-logs",
    "evidence/exports",
    "evidence/screenshots",
    "evidence/command-output",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum LogSourceKind {
    File,
    Folder,
    Known,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PathKind {
    File,
    Folder,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum KnownSourcePathKind {
    File,
    Folder,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PlatformKind {
    All,
    Windows,
    Macos,
    Linux,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum KnownSourceDefaultFileSelectionBehavior {
    None,
    PreferFileName,
    PreferFileNameThenPattern,
    PreferPattern,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KnownSourceGroupingMetadata {
    pub family_id: String,
    pub family_label: String,
    pub group_id: String,
    pub group_label: String,
    pub group_order: u32,
    pub source_order: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KnownSourceDefaultFileIntent {
    pub selection_behavior: KnownSourceDefaultFileSelectionBehavior,
    pub preferred_file_names: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum LogSource {
    File {
        path: String,
    },
    Folder {
        path: String,
    },
    Known {
        #[serde(rename = "sourceId")]
        source_id: String,
        #[serde(rename = "defaultPath")]
        default_path: String,
        #[serde(rename = "pathKind")]
        path_kind: KnownSourcePathKind,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FolderEntry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub size_bytes: Option<u64>,
    pub modified_unix_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FolderListingResult {
    pub source_kind: LogSourceKind,
    pub source: LogSource,
    pub entries: Vec<FolderEntry>,
    #[serde(default)]
    pub bundle_metadata: Option<EvidenceBundleMetadata>,
}

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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KnownSourceMetadata {
    pub id: String,
    pub label: String,
    pub description: String,
    pub platform: PlatformKind,
    pub source_kind: LogSourceKind,
    pub source: LogSource,
    pub file_patterns: Vec<String>,
    #[serde(default)]
    pub grouping: Option<KnownSourceGroupingMetadata>,
    #[serde(default)]
    pub default_file_intent: Option<KnownSourceDefaultFileIntent>,
}

/// Open and parse a log file, auto-detecting its format.
/// Stores the backend parser selection in AppState for tail reading.
#[tauri::command]
pub fn open_log_file(path: String, state: State<'_, AppState>) -> Result<ParseResult, String> {
    let (result, parser_selection) = parser::parse_file(&path)?;

    // Store in AppState so tail parsing reuses the same backend parser selection.
    let mut open_files = state.open_files.lock().map_err(|e| e.to_string())?;
    open_files.insert(
        PathBuf::from(&path),
        OpenFile {
            path: PathBuf::from(&path),
            entries: vec![], // entries live in the frontend
            parser_selection,
            byte_offset: result.byte_offset,
        },
    );

    Ok(result)
}

/// Open and parse every file in a folder, returning one combined log stream.
/// Stores backend parser selections in AppState so each included file can be tailed.
#[tauri::command]
pub fn open_log_folder_aggregate(
    path: String,
    state: State<'_, AppState>,
) -> Result<AggregateParseResult, String> {
    let listing = list_log_folder(path.clone())?;
    let file_entries: Vec<&FolderEntry> = listing.entries.iter().filter(|entry| !entry.is_dir).collect();

    let mut aggregate_entries: Vec<LogEntry> = Vec::new();
    let mut aggregate_files = Vec::with_capacity(file_entries.len());
    let mut open_file_states = Vec::with_capacity(file_entries.len());
    let mut total_lines = 0u32;
    let mut parse_errors = 0u32;

    for entry in file_entries {
        let (result, parser_selection) = parser::parse_file(&entry.path)?;

        total_lines = total_lines.saturating_add(result.total_lines);
        parse_errors = parse_errors.saturating_add(result.parse_errors);
        aggregate_entries.extend(result.entries);
        aggregate_files.push(AggregateParsedFileResult {
            file_path: result.file_path.clone(),
            total_lines: result.total_lines,
            parse_errors: result.parse_errors,
            file_size: result.file_size,
            byte_offset: result.byte_offset,
        });
        open_file_states.push((
            PathBuf::from(&result.file_path),
            parser_selection,
            result.byte_offset,
        ));
    }

    let file_order: std::collections::HashMap<String, usize> = aggregate_files
        .iter()
        .enumerate()
        .map(|(index, file)| (file.file_path.clone(), index))
        .collect();

    aggregate_entries.sort_by(|left, right| compare_aggregate_entries(left, right, &file_order));

    for (index, entry) in aggregate_entries.iter_mut().enumerate() {
        entry.id = index as u64;
    }

    let mut open_files = state.open_files.lock().map_err(|e| e.to_string())?;
    for (path_buf, parser_selection, byte_offset) in open_file_states {
        open_files.insert(
            path_buf.clone(),
            OpenFile {
                path: path_buf,
                entries: vec![],
                parser_selection,
                byte_offset,
            },
        );
    }

    Ok(AggregateParseResult {
        entries: aggregate_entries,
        total_lines,
        parse_errors,
        folder_path: path,
        files: aggregate_files,
    })
}

#[tauri::command]
pub fn inspect_path_kind(path: String) -> Result<PathKind, String> {
    let requested_path = PathBuf::from(&path);

    if !requested_path.exists() {
        return Ok(PathKind::Unknown);
    }

    if requested_path.is_dir() {
        return Ok(PathKind::Folder);
    }

    if requested_path.is_file() {
        return Ok(PathKind::File);
    }

    Ok(PathKind::Unknown)
}

#[tauri::command]
pub fn write_text_output_file(path: String, contents: String) -> Result<(), String> {
    fs::write(&path, contents).map_err(|error| format!("failed to write file {}: {}", path, error))
}

/// Returns the file path passed as a CLI argument at startup via OS file association.
///
/// When the user opens a `.log` or `.lo_` file with CMTrace Open (e.g. by
/// double-clicking it in Explorer or right-clicking and choosing "Open with"),
/// the OS launches the application with the file path as a command-line
/// argument. This command retrieves that path so the frontend can open it.
/// The path is consumed on the first call so it is only processed once.
#[tauri::command]
pub fn get_initial_file_path(state: State<'_, AppState>) -> Result<Option<String>, String> {
    let mut guard = state.initial_file_path.lock().map_err(|e| e.to_string())?;
    Ok(guard.take())
}

fn normalize_path_string(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

fn metadata_modified_unix_ms(metadata: &fs::Metadata) -> Option<u64> {
    let duration = metadata.modified().ok()?.duration_since(UNIX_EPOCH).ok()?;
    u64::try_from(duration.as_millis()).ok()
}

fn compare_folder_entries(left: &FolderEntry, right: &FolderEntry) -> Ordering {
    match (left.is_dir, right.is_dir) {
        (true, false) => Ordering::Less,
        (false, true) => Ordering::Greater,
        _ => {
            let left_lower = left.name.to_lowercase();
            let right_lower = right.name.to_lowercase();

            left_lower
                .cmp(&right_lower)
                .then_with(|| left.name.cmp(&right.name))
                .then_with(|| left.path.cmp(&right.path))
        }
    }
}

fn compare_aggregate_entries(
    left: &LogEntry,
    right: &LogEntry,
    file_order: &std::collections::HashMap<String, usize>,
) -> Ordering {
    match (left.timestamp, right.timestamp) {
        (Some(left_ts), Some(right_ts)) if left_ts != right_ts => left_ts.cmp(&right_ts),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        _ => file_order
            .get(&left.file_path)
            .copied()
            .unwrap_or(usize::MAX)
            .cmp(&file_order.get(&right.file_path).copied().unwrap_or(usize::MAX))
            .then_with(|| left.line_number.cmp(&right.line_number))
            .then_with(|| left.message.cmp(&right.message)),
    }
}

fn bundle_entry_rank(entry: &FolderEntry) -> usize {
    match entry.name.to_ascii_lowercase().as_str() {
        "manifest.json" => 0,
        "notes.md" => 1,
        "evidence" => 2,
        _ => 3,
    }
}

fn compare_bundle_folder_entries(left: &FolderEntry, right: &FolderEntry) -> Ordering {
    bundle_entry_rank(left)
        .cmp(&bundle_entry_rank(right))
        .then_with(|| compare_folder_entries(left, right))
}

fn detect_evidence_bundle_metadata(path: &Path) -> Option<EvidenceBundleMetadata> {
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

fn inspect_evidence_bundle_details(path: &Path) -> Result<EvidenceBundleDetails, String> {
    if !path.exists() {
        return Err(format!("bundle path does not exist: {}", path.display()));
    }

    if !path.is_dir() {
        return Err(format!("bundle path is not a folder: {}", path.display()));
    }

    let manifest_path = path.join("manifest.json");
    if !manifest_path.is_file() {
        return Err(format!(
            "manifest.json was not found under {}",
            path.display()
        ));
    }

    let manifest_content = fs::read_to_string(&manifest_path)
        .map_err(|error| format!("failed to read {}: {}", manifest_path.display(), error))?;
    let manifest = serde_json::from_str::<Value>(&manifest_content)
        .map_err(|error| format!("failed to parse {}: {}", manifest_path.display(), error))?;
    let metadata = detect_evidence_bundle_metadata(path)
        .ok_or_else(|| format!("{} is not a recognized evidence bundle", path.display()))?;

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
) -> Result<EvidenceArtifactPreview, String> {
    if !path.exists() {
        return Err(format!("artifact path does not exist: {}", path.display()));
    }

    if !path.is_file() {
        return Err(format!("artifact path is not a file: {}", path.display()));
    }

    match intake_kind {
        EvidenceArtifactIntakeKind::RegistrySnapshot => {
            let registry_snapshot = inspect_registry_snapshot_file(path)
                .ok_or_else(|| format!("failed to inspect registry snapshot {}", path.display()))?;
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
                .map_err(|error| format!("failed to read {} metadata: {}", path.display(), error))?;
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
        _ => Err("artifact preview is currently supported for registry snapshots and event-log exports only".to_string()),
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

/// List top-level entries for a folder source.
#[tauri::command]
pub fn list_log_folder(path: String) -> Result<FolderListingResult, String> {
    eprintln!("event=list_log_folder_start path=\"{}\"", path);

    let requested_path = PathBuf::from(&path);

    if !requested_path.exists() {
        return Err(format!(
            "folder does not exist: {}",
            requested_path.display()
        ));
    }

    if !requested_path.is_dir() {
        return Err(format!(
            "path is not a folder: {}",
            requested_path.display()
        ));
    }

    let read_dir = fs::read_dir(&requested_path)
        .map_err(|e| format!("failed to read folder {}: {e}", requested_path.display()))?;

    let mut entries: Vec<FolderEntry> = Vec::new();

    for entry_result in read_dir {
        let entry = match entry_result {
            Ok(value) => value,
            Err(error) => {
                eprintln!(
                    "event=list_log_folder_skip reason=read_dir_entry_error path=\"{}\" error=\"{}\"",
                    requested_path.display(),
                    error
                );
                continue;
            }
        };

        let entry_path = entry.path();
        let metadata = match entry.metadata() {
            Ok(value) => value,
            Err(error) => {
                eprintln!(
                    "event=list_log_folder_skip reason=metadata_error entry_path=\"{}\" error=\"{}\"",
                    entry_path.display(),
                    error
                );
                continue;
            }
        };

        entries.push(FolderEntry {
            name: entry.file_name().to_string_lossy().to_string(),
            path: normalize_path_string(&entry_path),
            is_dir: metadata.is_dir(),
            size_bytes: if metadata.is_file() {
                Some(metadata.len())
            } else {
                None
            },
            modified_unix_ms: metadata_modified_unix_ms(&metadata),
        });
    }

    let bundle_metadata = detect_evidence_bundle_metadata(&requested_path);
    if bundle_metadata.is_some() {
        entries.sort_by(compare_bundle_folder_entries);
    } else {
        entries.sort_by(compare_folder_entries);
    }

    eprintln!(
        "event=list_log_folder_complete path=\"{}\" entry_count={}",
        requested_path.display(),
        entries.len()
    );

    Ok(FolderListingResult {
        source_kind: LogSourceKind::Folder,
        source: LogSource::Folder {
            path: normalize_path_string(&requested_path),
        },
        entries,
        bundle_metadata,
    })
}

#[tauri::command]
pub fn inspect_evidence_bundle(path: String) -> Result<EvidenceBundleDetails, String> {
    inspect_evidence_bundle_details(Path::new(&path))
}

#[tauri::command]
pub fn inspect_evidence_artifact(
    path: String,
    intake_kind: EvidenceArtifactIntakeKind,
    origin_path: Option<String>,
) -> Result<EvidenceArtifactPreview, String> {
    inspect_evidence_artifact_preview(Path::new(&path), intake_kind, origin_path)
}

#[cfg(target_os = "windows")]
#[allow(clippy::too_many_arguments)]
fn windows_known_source(
    id: &str,
    label: &str,
    description: &str,
    path_kind: KnownSourcePathKind,
    default_path: &str,
    file_patterns: &[&str],
    grouping: KnownSourceGroupingMetadata,
    default_file_intent: Option<KnownSourceDefaultFileIntent>,
) -> KnownSourceMetadata {
    let id_text = id.to_string();

    KnownSourceMetadata {
        id: id_text.clone(),
        label: label.to_string(),
        description: description.to_string(),
        platform: PlatformKind::Windows,
        source_kind: LogSourceKind::Known,
        source: LogSource::Known {
            source_id: id_text,
            default_path: default_path.to_string(),
            path_kind,
        },
        file_patterns: file_patterns
            .iter()
            .map(|value| (*value).to_string())
            .collect(),
        grouping: Some(grouping),
        default_file_intent,
    }
}

#[cfg(target_os = "windows")]
fn windows_known_log_sources() -> Vec<KnownSourceMetadata> {
    vec![
        windows_known_source(
            "windows-intune-ime-logs",
            "Intune IME Logs Folder",
            "Known log source for Intune Management Extension (IME) app and script diagnostics.",
            KnownSourcePathKind::Folder,
            "C:\\ProgramData\\Microsoft\\IntuneManagementExtension\\Logs",
            &[
                "IntuneManagementExtension.log",
                "AppWorkload.log",
                "AppActionProcessor.log",
                "AgentExecutor.log",
                "HealthScripts.log",
                "*.log",
            ],
            KnownSourceGroupingMetadata {
                family_id: "windows-intune".to_string(),
                family_label: "Windows Intune".to_string(),
                group_id: "intune-ime".to_string(),
                group_label: "Intune IME".to_string(),
                group_order: 10,
                source_order: 10,
            },
            Some(KnownSourceDefaultFileIntent {
                selection_behavior:
                    KnownSourceDefaultFileSelectionBehavior::PreferFileNameThenPattern,
                preferred_file_names: vec![
                    "IntuneManagementExtension.log".to_string(),
                    "AppWorkload.log".to_string(),
                    "AppActionProcessor.log".to_string(),
                    "AgentExecutor.log".to_string(),
                    "HealthScripts.log".to_string(),
                ],
            }),
        ),
        windows_known_source(
            "windows-intune-ime-intunemanagementextension-log",
            "Intune IME: IntuneManagementExtension.log",
            "Primary IME log for check-ins, policy processing, and app orchestration.",
            KnownSourcePathKind::File,
            "C:\\ProgramData\\Microsoft\\IntuneManagementExtension\\Logs\\IntuneManagementExtension.log",
            &["IntuneManagementExtension*.log"],
            KnownSourceGroupingMetadata {
                family_id: "windows-intune".to_string(),
                family_label: "Windows Intune".to_string(),
                group_id: "intune-ime".to_string(),
                group_label: "Intune IME".to_string(),
                group_order: 10,
                source_order: 20,
            },
            None,
        ),
        windows_known_source(
            "windows-intune-ime-appworkload-log",
            "Intune IME: AppWorkload.log",
            "Win32 and WinGet app download/staging/install diagnostics.",
            KnownSourcePathKind::File,
            "C:\\ProgramData\\Microsoft\\IntuneManagementExtension\\Logs\\AppWorkload.log",
            &["AppWorkload*.log"],
            KnownSourceGroupingMetadata {
                family_id: "windows-intune".to_string(),
                family_label: "Windows Intune".to_string(),
                group_id: "intune-ime".to_string(),
                group_label: "Intune IME".to_string(),
                group_order: 10,
                source_order: 30,
            },
            None,
        ),
        windows_known_source(
            "windows-intune-ime-agentexecutor-log",
            "Intune IME: AgentExecutor.log",
            "Script execution and remediation output with exit code tracking.",
            KnownSourcePathKind::File,
            "C:\\ProgramData\\Microsoft\\IntuneManagementExtension\\Logs\\AgentExecutor.log",
            &["AgentExecutor*.log"],
            KnownSourceGroupingMetadata {
                family_id: "windows-intune".to_string(),
                family_label: "Windows Intune".to_string(),
                group_id: "intune-ime".to_string(),
                group_label: "Intune IME".to_string(),
                group_order: 10,
                source_order: 40,
            },
            None,
        ),
        windows_known_source(
            "windows-dmclient-logs",
            "DMClient Local Logs",
            "MDM DMClient log folder used for local sync diagnostics.",
            KnownSourcePathKind::Folder,
            "C:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\mdm",
            &["*.log"],
            KnownSourceGroupingMetadata {
                family_id: "windows-intune".to_string(),
                family_label: "Windows Intune".to_string(),
                group_id: "intune-mdm".to_string(),
                group_label: "MDM and Enrollment".to_string(),
                group_order: 20,
                source_order: 10,
            },
            Some(KnownSourceDefaultFileIntent {
                selection_behavior: KnownSourceDefaultFileSelectionBehavior::PreferPattern,
                preferred_file_names: Vec::new(),
            }),
        ),
        windows_known_source(
            "windows-panther-setupact-log",
            "setupact.log (Panther)",
            "Primary Windows setup and Autopilot/OOBE action log.",
            KnownSourcePathKind::File,
            "C:\\Windows\\Panther\\setupact.log",
            &["setupact.log"],
            KnownSourceGroupingMetadata {
                family_id: "windows-setup".to_string(),
                family_label: "Windows Setup".to_string(),
                group_id: "setup-panther".to_string(),
                group_label: "Panther".to_string(),
                group_order: 30,
                source_order: 10,
            },
            None,
        ),
        windows_known_source(
            "windows-panther-setuperr-log",
            "setuperr.log (Panther)",
            "Error-focused Windows setup and Autopilot/OOBE triage log.",
            KnownSourcePathKind::File,
            "C:\\Windows\\Panther\\setuperr.log",
            &["setuperr.log"],
            KnownSourceGroupingMetadata {
                family_id: "windows-setup".to_string(),
                family_label: "Windows Setup".to_string(),
                group_id: "setup-panther".to_string(),
                group_label: "Panther".to_string(),
                group_order: 30,
                source_order: 20,
            },
            None,
        ),
        windows_known_source(
            "windows-cbs-log",
            "CBS.log",
            "Component-Based Servicing log for update and servicing failures.",
            KnownSourcePathKind::File,
            "C:\\Windows\\Logs\\CBS\\CBS.log",
            &["CBS.log"],
            KnownSourceGroupingMetadata {
                family_id: "windows-servicing".to_string(),
                family_label: "Windows Servicing".to_string(),
                group_id: "servicing-core".to_string(),
                group_label: "CBS and DISM".to_string(),
                group_order: 40,
                source_order: 10,
            },
            None,
        ),
        windows_known_source(
            "windows-dism-log",
            "DISM.log",
            "Deployment Image Servicing and Management diagnostics log.",
            KnownSourcePathKind::File,
            "C:\\Windows\\Logs\\DISM\\dism.log",
            &["dism.log"],
            KnownSourceGroupingMetadata {
                family_id: "windows-servicing".to_string(),
                family_label: "Windows Servicing".to_string(),
                group_id: "servicing-core".to_string(),
                group_label: "CBS and DISM".to_string(),
                group_order: 40,
                source_order: 20,
            },
            None,
        ),
        windows_known_source(
            "windows-reporting-events-log",
            "ReportingEvents.log",
            "Windows Update transaction history in tab-delimited text.",
            KnownSourcePathKind::File,
            "C:\\Windows\\SoftwareDistribution\\ReportingEvents.log",
            &["ReportingEvents.log"],
            KnownSourceGroupingMetadata {
                family_id: "windows-servicing".to_string(),
                family_label: "Windows Servicing".to_string(),
                group_id: "servicing-update".to_string(),
                group_label: "Windows Update".to_string(),
                group_order: 40,
                source_order: 30,
            },
            None,
        ),
    ]
}

#[cfg(target_os = "macos")]
#[allow(clippy::too_many_arguments)]
fn macos_known_source(
    id: &str,
    label: &str,
    description: &str,
    path_kind: KnownSourcePathKind,
    default_path: &str,
    file_patterns: &[&str],
    grouping: KnownSourceGroupingMetadata,
    default_file_intent: Option<KnownSourceDefaultFileIntent>,
) -> KnownSourceMetadata {
    let id_text = id.to_string();

    KnownSourceMetadata {
        id: id_text.clone(),
        label: label.to_string(),
        description: description.to_string(),
        platform: PlatformKind::Macos,
        source_kind: LogSourceKind::Known,
        source: LogSource::Known {
            source_id: id_text,
            default_path: default_path.to_string(),
            path_kind,
        },
        file_patterns: file_patterns
            .iter()
            .map(|value| (*value).to_string())
            .collect(),
        grouping: Some(grouping),
        default_file_intent,
    }
}

#[cfg(target_os = "macos")]
fn macos_known_log_sources() -> Vec<KnownSourceMetadata> {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());

    vec![
        // --- macOS Intune: System-level MDM daemon logs ---
        macos_known_source(
            "macos-intune-system-logs",
            "Intune System Logs",
            "System-level MDM daemon logs for PKG/DMG installs and root script execution.",
            KnownSourcePathKind::Folder,
            "/Library/Logs/Microsoft/Intune",
            &["*.log"],
            KnownSourceGroupingMetadata {
                family_id: "macos-intune".to_string(),
                family_label: "macOS Intune".to_string(),
                group_id: "intune-logs".to_string(),
                group_label: "Intune Logs".to_string(),
                group_order: 10,
                source_order: 10,
            },
            Some(KnownSourceDefaultFileIntent {
                selection_behavior:
                    KnownSourceDefaultFileSelectionBehavior::PreferFileNameThenPattern,
                preferred_file_names: vec![
                    "IntuneMDMDaemon.log".to_string(),
                ],
            }),
        ),
        // --- macOS Intune: User-level MDM agent logs ---
        macos_known_source(
            "macos-intune-user-logs",
            "Intune User Agent Logs",
            "User-level MDM agent logs for user-context scripts and policies.",
            KnownSourcePathKind::Folder,
            &format!("{}/Library/Logs/Microsoft/Intune", home),
            &["*.log"],
            KnownSourceGroupingMetadata {
                family_id: "macos-intune".to_string(),
                family_label: "macOS Intune".to_string(),
                group_id: "intune-logs".to_string(),
                group_label: "Intune Logs".to_string(),
                group_order: 10,
                source_order: 20,
            },
            None,
        ),
        // --- macOS Intune: Script execution logs ---
        macos_known_source(
            "macos-intune-scripts-logs",
            "Intune Script Logs",
            "Shell script execution logs from Intune script deployments.",
            KnownSourcePathKind::Folder,
            "/Library/Logs/Microsoft/IntuneScripts",
            &["*.log"],
            KnownSourceGroupingMetadata {
                family_id: "macos-intune".to_string(),
                family_label: "macOS Intune".to_string(),
                group_id: "intune-logs".to_string(),
                group_label: "Intune Logs".to_string(),
                group_order: 10,
                source_order: 30,
            },
            None,
        ),
        // --- Company Portal ---
        macos_known_source(
            "macos-company-portal-logs",
            "Company Portal Logs",
            "Company Portal app logs for enrollment, device info, and user registration.",
            KnownSourcePathKind::Folder,
            &format!("{}/Library/Logs/CompanyPortal", home),
            &["*.log"],
            KnownSourceGroupingMetadata {
                family_id: "macos-intune".to_string(),
                family_label: "macOS Intune".to_string(),
                group_id: "intune-portal".to_string(),
                group_label: "Company Portal".to_string(),
                group_order: 20,
                source_order: 10,
            },
            Some(KnownSourceDefaultFileIntent {
                selection_behavior:
                    KnownSourceDefaultFileSelectionBehavior::PreferFileNameThenPattern,
                preferred_file_names: vec![
                    "CompanyPortal.log".to_string(),
                ],
            }),
        ),
        // --- macOS install.log ---
        macos_known_source(
            "macos-install-log",
            "install.log",
            "macOS installer log — PKG installs from Intune and Software Update show up here.",
            KnownSourcePathKind::File,
            "/var/log/install.log",
            &["install.log"],
            KnownSourceGroupingMetadata {
                family_id: "macos-system".to_string(),
                family_label: "macOS System".to_string(),
                group_id: "system-logs".to_string(),
                group_label: "System Logs".to_string(),
                group_order: 30,
                source_order: 10,
            },
            None,
        ),
        // --- macOS system.log ---
        macos_known_source(
            "macos-system-log",
            "system.log",
            "macOS system log — MDM profile installs, daemon crashes, and system events.",
            KnownSourcePathKind::File,
            "/var/log/system.log",
            &["system.log"],
            KnownSourceGroupingMetadata {
                family_id: "macos-system".to_string(),
                family_label: "macOS System".to_string(),
                group_id: "system-logs".to_string(),
                group_label: "System Logs".to_string(),
                group_order: 30,
                source_order: 20,
            },
            None,
        ),
        // --- macOS wifi.log ---
        macos_known_source(
            "macos-wifi-log",
            "Wi-Fi Log",
            "macOS Wi-Fi diagnostic log",
            KnownSourcePathKind::File,
            "/var/log/wifi.log",
            &["wifi.log"],
            KnownSourceGroupingMetadata {
                family_id: "macos-system".to_string(),
                family_label: "macOS System".to_string(),
                group_id: "system-logs".to_string(),
                group_label: "System Logs".to_string(),
                group_order: 30,
                source_order: 30,
            },
            None,
        ),
        // --- macOS appfirewall.log ---
        macos_known_source(
            "macos-appfirewall-log",
            "Application Firewall Log",
            "macOS application firewall log",
            KnownSourcePathKind::File,
            "/var/log/appfirewall.log",
            &["appfirewall.log"],
            KnownSourceGroupingMetadata {
                family_id: "macos-system".to_string(),
                family_label: "macOS System".to_string(),
                group_id: "system-logs".to_string(),
                group_label: "System Logs".to_string(),
                group_order: 30,
                source_order: 40,
            },
            None,
        ),
        // --- Microsoft Defender logs ---
        macos_known_source(
            "macos-defender-logs",
            "Defender Logs",
            "Microsoft Defender for Endpoint install and error logs.",
            KnownSourcePathKind::Folder,
            "/Library/Logs/Microsoft/mdatp",
            &["*.log"],
            KnownSourceGroupingMetadata {
                family_id: "macos-defender".to_string(),
                family_label: "macOS Defender".to_string(),
                group_id: "defender-logs".to_string(),
                group_label: "Defender Logs".to_string(),
                group_order: 40,
                source_order: 10,
            },
            Some(KnownSourceDefaultFileIntent {
                selection_behavior:
                    KnownSourceDefaultFileSelectionBehavior::PreferFileNameThenPattern,
                preferred_file_names: vec![
                    "microsoft_defender_core_err.log".to_string(),
                    "install.log".to_string(),
                ],
            }),
        ),
    ]
}

pub fn build_known_log_sources() -> Vec<KnownSourceMetadata> {
    #[cfg(target_os = "windows")]
    {
        windows_known_log_sources()
    }

    #[cfg(target_os = "macos")]
    {
        macos_known_log_sources()
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        Vec::new()
    }
}

/// Return known platform log source metadata.
#[tauri::command]
pub fn get_known_log_sources() -> Result<Vec<KnownSourceMetadata>, String> {
    let sources = build_known_log_sources();

    eprintln!("event=get_known_log_sources count={}", sources.len());

    Ok(sources)
}

#[cfg(test)]
mod tests {
    use super::{
        inspect_evidence_artifact, inspect_evidence_bundle, list_log_folder,
        EvidenceArtifactIntakeKind,
    };
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn list_log_folder_marks_evidence_bundle_and_exposes_primary_entry_points() {
        let bundle_dir = create_temp_dir("file-ops-bundle");
        fs::create_dir_all(bundle_dir.join("evidence").join("logs")).expect("create logs dir");
        fs::create_dir_all(bundle_dir.join("evidence").join("registry"))
            .expect("create registry dir");
        fs::write(bundle_dir.join("notes.md"), "notes").expect("write notes");
        fs::write(bundle_dir.join("manifest.json"), sample_bundle_manifest())
            .expect("write manifest");

        let result =
            list_log_folder(bundle_dir.to_string_lossy().to_string()).expect("list folder");
        let bundle_metadata = result.bundle_metadata.expect("bundle metadata");

        assert_eq!(bundle_metadata.bundle_id.as_deref(), Some("CMTRACE-123"));
        assert_eq!(
            result.entries.first().map(|entry| entry.name.as_str()),
            Some("manifest.json")
        );
        assert!(bundle_metadata
            .available_primary_entry_points
            .iter()
            .any(|path| path.ends_with("evidence\\logs") || path.ends_with("evidence/logs")));
        assert!(bundle_metadata
            .available_primary_entry_points
            .iter()
            .any(
                |path| path.ends_with("evidence\\registry") || path.ends_with("evidence/registry")
            ));

        fs::remove_dir_all(&bundle_dir).expect("remove temp bundle dir");
    }

    #[test]
    fn list_log_folder_bundle_metadata_filters_missing_manifest_entry_points() {
        let bundle_dir = create_temp_dir("file-ops-bundle-missing");
        fs::create_dir_all(bundle_dir.join("evidence").join("logs")).expect("create logs dir");
        fs::write(
            bundle_dir.join("manifest.json"),
            sample_bundle_manifest_with_missing_entry(),
        )
        .expect("write manifest");

        let result =
            list_log_folder(bundle_dir.to_string_lossy().to_string()).expect("list folder");
        let bundle_metadata = result.bundle_metadata.expect("bundle metadata");

        assert_eq!(bundle_metadata.primary_entry_points.len(), 2);
        assert!(bundle_metadata
            .primary_entry_points
            .iter()
            .any(|path| path.ends_with("evidence\\logs") || path.ends_with("evidence/logs")));
        assert!(bundle_metadata
            .primary_entry_points
            .iter()
            .any(|path| path.ends_with("evidence\\missing") || path.ends_with("evidence/missing")));
        assert_eq!(bundle_metadata.available_primary_entry_points.len(), 1);
        assert!(bundle_metadata
            .available_primary_entry_points
            .iter()
            .all(
                |path| !path.ends_with("evidence\\missing") && !path.ends_with("evidence/missing")
            ));

        fs::remove_dir_all(&bundle_dir).expect("remove temp bundle dir");
    }

    #[test]
    fn inspect_evidence_bundle_returns_inventory_and_notes_preview() {
        let bundle_dir = create_temp_dir("file-ops-bundle-details");
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
        let bundle_dir = create_temp_dir("file-ops-artifact-preview");
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

        assert!(registry_preview.registry_snapshot.is_some());
        assert!(registry_preview.summary.contains("registry key"));
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

    fn sample_bundle_manifest_with_missing_entry() -> &'static str {
        r#"{
    "bundle": {
        "bundleId": "CMTRACE-456",
        "bundleLabel": "intune-endpoint-evidence",
        "createdUtc": "2026-03-12T16:00:54Z",
        "device": {
            "deviceName": "GELL-VM-5879648",
            "platform": "Windows"
        }
    },
    "collection": {
        "results": {
            "artifactCounts": {
                "collected": 1,
                "missing": 1,
                "failed": 0,
                "skipped": 0
            }
        }
    },
    "intakeHints": {
        "primaryEntryPoints": [
            "evidence/logs",
            "evidence/missing"
        ]
    }
}"#
    }
}
