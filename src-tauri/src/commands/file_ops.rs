use std::cmp::Ordering;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering as AtomicOrdering};
use std::time::UNIX_EPOCH;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, State};

use crate::intune::models::EvidenceBundleMetadata;
use crate::models::log_entry::{
    AggregateParseResult, AggregateParsedFileResult, LogEntry, ParseResult,
};
use crate::parser;
use crate::state::app_state::{AppState, OpenFile};

use super::bundle_ops::{collect_files_recursive, detect_evidence_bundle_metadata};
use super::known_sources::KnownSourcePathKind;

// ── Types ───────────────────────────────────────────────────────────────

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

// ── Tauri Commands ──────────────────────────────────────────────────────

/// Open and parse a log file, auto-detecting its format.
/// Stores the backend parser selection in AppState for tail reading.
#[tauri::command]
pub fn open_log_file(path: String, state: State<'_, AppState>) -> Result<ParseResult, crate::error::AppError> {
    let (result, parser_selection) = parser::parse_file(&path)?;

    // Store in AppState so tail parsing reuses the same backend parser selection.
    let mut open_files = state.open_files.lock().map_err(|e| crate::error::AppError::State(e.to_string()))?;
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

/// Parse multiple files in parallel using Rayon, returning all results in a single
/// IPC response. This eliminates N-1 IPC round-trips compared to calling
/// `open_log_file` N times individually from the frontend.
///
/// Each file is parsed independently and its backend parser selection is stored
/// in AppState for future tail reading.
/// Payload emitted as `"parse-progress"` for each file that finishes parsing.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ParseProgressPayload {
    file_path: String,
    file_name: String,
    completed: u32,
    total: u32,
    entries: u32,
    file_size: u64,
    parse_ms: u64,
}

#[tauri::command]
pub fn parse_files_batch(
    paths: Vec<String>,
    state: State<'_, AppState>,
    app: AppHandle,
) -> Result<Vec<ParseResult>, crate::error::AppError> {
    use rayon::prelude::*;

    let total = paths.len() as u32;
    log::info!("event=parse_files_batch_start file_count={total}");
    for (i, path) in paths.iter().enumerate() {
        log::debug!("  batch_file[{i}] = \"{path}\"");
    }

    let batch_start = std::time::Instant::now();
    let completed = AtomicU32::new(0);

    // Parse all files in parallel on Rayon's thread pool (lock-free)
    let results: Vec<Result<(ParseResult, crate::parser::ResolvedParser, String), crate::error::AppError>> = paths
        .par_iter()
        .map(|path| {
            let file_start = std::time::Instant::now();
            let (result, parser_selection) = parser::parse_file(path)?;
            let file_ms = file_start.elapsed().as_millis() as u64;

            let done = completed.fetch_add(1, AtomicOrdering::Relaxed) + 1;
            let file_name = Path::new(path)
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();

            log::info!(
                "  event=parse_file_done [{done}/{total}] path=\"{path}\" entries={} lines={} size={} ms={file_ms}",
                result.entries.len(),
                result.total_lines,
                result.file_size,
            );

            // Fire-and-forget progress event to the frontend
            let _ = app.emit(
                "parse-progress",
                ParseProgressPayload {
                    file_path: path.clone(),
                    file_name,
                    completed: done,
                    total,
                    entries: result.entries.len() as u32,
                    file_size: result.file_size,
                    parse_ms: file_ms,
                },
            );

            Ok((result, parser_selection, path.clone()))
        })
        .collect();

    let parse_ms = batch_start.elapsed().as_millis();
    log::info!(
        "event=parse_files_batch_parsed file_count={} ms={parse_ms}",
        results.len()
    );

    // Collect successes and store parser state (requires lock, done sequentially)
    let mut parse_results = Vec::with_capacity(results.len());
    let mut open_files = state.open_files.lock().map_err(|e| crate::error::AppError::State(e.to_string()))?;

    for item in results {
        let (result, parser_selection, path) = item?;
        open_files.insert(
            PathBuf::from(&path),
            OpenFile {
                path: PathBuf::from(&path),
                entries: vec![],
                parser_selection,
                byte_offset: result.byte_offset,
            },
        );
        parse_results.push(result);
    }

    let total_ms = batch_start.elapsed().as_millis();
    log::info!(
        "event=parse_files_batch_complete file_count={} results={} total_ms={total_ms}",
        paths.len(),
        parse_results.len()
    );

    Ok(parse_results)
}

/// Open and parse every file in a folder, returning one combined log stream.
/// Stores backend parser selections in AppState so each included file can be tailed.
#[tauri::command]
pub fn open_log_folder_aggregate(
    path: String,
    state: State<'_, AppState>,
) -> Result<AggregateParseResult, crate::error::AppError> {
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

    let mut open_files = state.open_files.lock().map_err(|e| crate::error::AppError::State(e.to_string()))?;
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
pub fn inspect_path_kind(path: String) -> Result<PathKind, crate::error::AppError> {
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
pub fn write_text_output_file(path: String, contents: String) -> Result<(), crate::error::AppError> {
    fs::write(&path, contents).map_err(crate::error::AppError::Io)
}

/// Returns file paths passed as CLI arguments at startup via OS file association.
///
/// When the user opens `.log` files with CMTrace Open (e.g. by selecting
/// multiple files and choosing "Open with"), the OS launches the application
/// with the file paths as command-line arguments. This command retrieves those
/// paths so the frontend can open them. Consumed on the first call.
#[tauri::command]
pub fn get_initial_file_paths(state: State<'_, AppState>) -> Result<Vec<String>, crate::error::AppError> {
    let mut guard = state.initial_file_paths.lock().map_err(|e| crate::error::AppError::State(e.to_string()))?;
    let paths = std::mem::take(&mut *guard);
    Ok(paths)
}

/// List top-level entries for a folder source.
#[tauri::command]
pub fn list_log_folder(path: String) -> Result<FolderListingResult, crate::error::AppError> {
    log::info!("event=list_log_folder_start path=\"{}\"", path);

    let requested_path = PathBuf::from(&path);

    if !requested_path.exists() {
        return Err(crate::error::AppError::InvalidInput(format!(
            "folder does not exist: {}",
            requested_path.display()
        )));
    }

    if !requested_path.is_dir() {
        return Err(crate::error::AppError::InvalidInput(format!(
            "path is not a folder: {}",
            requested_path.display()
        )));
    }

    let read_dir = fs::read_dir(&requested_path)
        .map_err(crate::error::AppError::Io)?;

    let mut entries: Vec<FolderEntry> = Vec::new();

    for entry_result in read_dir {
        let entry = match entry_result {
            Ok(value) => value,
            Err(error) => {
                log::warn!(
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
                log::warn!(
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
        // For evidence bundles, recursively collect all files from the entire
        // directory tree so that every nested artifact is loaded.
        entries = collect_files_recursive(&requested_path);
        entries.sort_by(compare_folder_entries);
    } else {
        entries.sort_by(compare_folder_entries);
    }

    log::info!(
        "event=list_log_folder_complete path=\"{}\" entry_count={} is_bundle={}",
        requested_path.display(),
        entries.len(),
        bundle_metadata.is_some(),
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

// ── Shared helpers (pub(crate) for sibling command modules) ─────────────

pub(crate) fn normalize_path_string(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

pub(crate) fn metadata_modified_unix_ms(metadata: &fs::Metadata) -> Option<u64> {
    let duration = metadata.modified().ok()?.duration_since(UNIX_EPOCH).ok()?;
    u64::try_from(duration.as_millis()).ok()
}

// ── Private helpers ─────────────────────────────────────────────────────

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

#[derive(Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileHashResult {
    pub hash: String,
    pub size_bytes: u64,
}

#[tauri::command]
pub fn compute_file_hash(path: String) -> Result<FileHashResult, crate::error::AppError> {
    use sha2::{Sha256, Digest};
    use std::io::Read;

    let mut file = std::fs::File::open(&path)
        .map_err(crate::error::AppError::Io)?;

    let metadata = file.metadata()
        .map_err(crate::error::AppError::Io)?;
    let size_bytes = metadata.len();

    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let bytes_read = file.read(&mut buffer)
            .map_err(crate::error::AppError::Io)?;
        if bytes_read == 0 { break; }
        hasher.update(&buffer[..bytes_read]);
    }

    let hash = format!("sha256:{:x}", hasher.finalize());
    Ok(FileHashResult { hash, size_bytes })
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

#[cfg(test)]
mod tests {
    use super::list_log_folder;
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
