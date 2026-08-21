use std::cmp::Ordering;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering as AtomicOrdering};
use std::time::UNIX_EPOCH;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, State};

use super::bundle_ops::{
    collect_files_recursive, detect_evidence_bundle_metadata, unsafe_ancestor_reason,
    unsafe_entry_reason,
};
use super::known_sources::KnownSourcePathKind;
use crate::intune::models::EvidenceBundleMetadata;
use crate::models::log_entry::{
    AggregateParseResult, AggregateParsedFileResult, LogEntry, ParseResult, PathDiagnostic,
};
use crate::parser;
use crate::state::app_state::{AppState, OpenFile};
use crate::watcher::tail::InitialLogicalRecord;
const MAX_FOLDER_LISTING_ENTRIES: usize = 4_096;
const MAX_FOLDER_LISTING_WORK: usize = 16_384;
const MAX_FOLDER_LISTING_ERRORS: usize = 4_096;
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
    pub child_errors: Vec<PathDiagnostic>,
    #[serde(default)]
    pub bundle_metadata: Option<EvidenceBundleMetadata>,
}

// ── Helpers ─────────────────────────────────────────────────────────────

/// Recovers the OS error kind behind a failed open.
///
/// `parser::parse_file` flattens every failure to a `String`, which discards the
/// `io::ErrorKind` the elevation offer depends on. Rather than reshape that
/// signature and every caller with it, re-probe the path on the failure path
/// only: the success path pays nothing, and the probe answers the one question
/// that matters, which is whether the operating system refused access.
///
/// The path's *kind* is established first, and that ordering is load-bearing.
/// On Windows `CreateFileW` without `FILE_FLAG_BACKUP_SEMANTICS` — which is what
/// `fs::File::open` issues — fails on a directory with `ERROR_ACCESS_DENIED`
/// (5), and std maps 5 to `ErrorKind::PermissionDenied`. Probing the open before
/// the kind therefore reported every folder that reached the file lane as Access
/// Denied, which raised a spurious "Restart as administrator?" prompt whose
/// elevated retry re-attempted the folder as a file and failed again. Statting
/// first also makes the answer platform-independent: `fs::metadata` uses
/// `FILE_FLAG_BACKUP_SEMANTICS` on Windows and succeeds on directories, so the
/// folder verdict is the same on every host.
///
/// Anything other than a permission refusal keeps the parser's own message,
/// which is more specific than a generic I/O error would be.
fn classify_open_failure(path: &str, reason: String) -> crate::error::AppError {
    match fs::metadata(path) {
        Ok(metadata) if metadata.is_dir() => {
            // Mirrors `list_log_folder`'s "path is not a folder": the two lanes
            // now reject each other's kind the same way, and neither can dress a
            // kind mismatch up as a permission problem.
            return crate::error::AppError::InvalidInput(format!(
                "path is a folder, not a file: {path}"
            ));
        }
        Ok(_) => {}
        Err(error) => {
            // The stat itself was refused, so the kind is genuinely unknowable
            // and the refusal is the real failure. `fs::metadata` needs traverse
            // permission on the parent, not read permission on the target, so an
            // unreadable file still stats fine and falls through to the open
            // probe below.
            if let denied @ crate::error::AppError::AccessDenied { .. } =
                crate::error::AppError::from_source_io(
                    error,
                    crate::error::SourceOperation::ReadFile,
                    Some(path),
                )
            {
                return denied;
            }
            // Missing, or any other stat failure: the parser's message is more
            // specific than a re-probe would be.
            return crate::error::AppError::Internal(reason);
        }
    }

    let Err(error) = fs::File::open(path) else {
        // Readable now, so this was a genuine parse failure, not a permission one.
        return crate::error::AppError::Internal(reason);
    };

    match crate::error::AppError::from_source_io(
        error,
        crate::error::SourceOperation::ReadFile,
        Some(path),
    ) {
        access_denied @ crate::error::AppError::AccessDenied { .. } => access_denied,
        _ => crate::error::AppError::Internal(reason),
    }
}

// ── Tauri Commands ──────────────────────────────────────────────────────

/// Open and parse a log file, auto-detecting its format.
/// Stores the backend parser selection in AppState for tail reading.
#[tauri::command]
pub fn open_log_file(
    path: String,
    state: State<'_, AppState>,
) -> Result<ParseResult, crate::error::AppError> {
    let (result, parser_selection) = match parser::parse_file(&path) {
        Ok(value) => value,
        Err(reason) => return Err(classify_open_failure(&path, reason)),
    };
    let initial_logical_record =
        InitialLogicalRecord::from_parse_result(&result, &parser_selection);

    // Store in AppState so tail parsing reuses the same backend parser selection.
    let mut open_files = state
        .open_files
        .lock()
        .map_err(|e| crate::error::AppError::State(e.to_string()))?;
    open_files.insert(
        PathBuf::from(&path),
        OpenFile {
            path: PathBuf::from(&path),
            parser_selection,
            initial_logical_record,
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
    request_id: u64,
    file_path: String,
    file_name: String,
    completed: u32,
    global_completed: u32,
    total: u32,
    entries: u32,
    file_size: u64,
    parse_ms: u64,
}

#[tauri::command]
pub fn parse_files_batch(
    paths: Vec<String>,
    request_id: u64,
    completed_offset: u32,
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

    // Parse all files in parallel on Rayon's thread pool (lock-free).
    // Per-file failures are logged + emitted as progress inside the closure
    // (where `path` is in scope) so the UI's progress counter still advances
    // when files are skipped, and the warn log includes the offending path.
    let results: Vec<Result<(ParseResult, crate::parser::ResolvedParser, String), crate::error::AppError>> = paths
        .par_iter()
        .map(|path| {
            let file_start = std::time::Instant::now();
            let parse_outcome = parser::parse_file(path);
            let file_ms = file_start.elapsed().as_millis() as u64;

            let done = completed.fetch_add(1, AtomicOrdering::Relaxed) + 1;
            let file_name = Path::new(path)
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();

            match parse_outcome {
                Ok((result, parser_selection)) => {
                    log::info!(
                        "  event=parse_file_done [{done}/{total}] path=\"{path}\" entries={} lines={} size={} ms={file_ms}",
                        result.entries.len(),
                        result.total_lines,
                        result.file_size,
                    );

                    let _ = app.emit(
                        "parse-progress",
                        ParseProgressPayload {
                            request_id,
                            file_path: path.clone(),
                            file_name,
                            completed: done,
                            global_completed: completed_offset.saturating_add(done),
                            total,
                            entries: result.entries.len() as u32,
                            file_size: result.file_size,
                            parse_ms: file_ms,
                        },
                    );

                    Ok((result, parser_selection, path.clone()))
                }
                Err(error) => {
                    log::warn!(
                        "  event=parse_file_skip [{done}/{total}] path=\"{path}\" error=\"{error}\""
                    );

                    // Emit progress for the skip so the UI counter still
                    // advances and doesn't stall below `total`.
                    let _ = app.emit(
                        "parse-progress",
                        ParseProgressPayload {
                            request_id,
                            file_path: path.clone(),
                            file_name,
                            completed: done,
                            global_completed: completed_offset.saturating_add(done),
                            total,
                            entries: 0,
                            file_size: 0,
                            parse_ms: file_ms,
                        },
                    );

                    Err(crate::error::AppError::from(error))
                }
            }
        })
        .collect();

    let parse_ms = batch_start.elapsed().as_millis();
    log::info!(
        "event=parse_files_batch_parsed file_count={} ms={parse_ms}",
        results.len()
    );

    // Collect successes and store parser state (requires lock, done sequentially).
    let mut parse_results = Vec::with_capacity(results.len());
    let mut skipped = 0u32;
    let mut open_files = state
        .open_files
        .lock()
        .map_err(|e| crate::error::AppError::State(e.to_string()))?;

    for item in results {
        match item {
            Ok((result, parser_selection, path)) => {
                let initial_logical_record =
                    InitialLogicalRecord::from_parse_result(&result, &parser_selection);
                open_files.insert(
                    PathBuf::from(&path),
                    OpenFile {
                        path: PathBuf::from(&path),
                        parser_selection,
                        initial_logical_record,
                        byte_offset: result.byte_offset,
                    },
                );
                parse_results.push(result);
            }
            Err(_) => {
                skipped = skipped.saturating_add(1);
            }
        }
    }

    let total_ms = batch_start.elapsed().as_millis();
    log::info!(
        "event=parse_files_batch_complete file_count={} results={} skipped={skipped} total_ms={total_ms}",
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
    open_log_folder_aggregate_impl(path, &state)
}

/// Command body, split from the `#[tauri::command]` wrapper so unit tests can
/// drive it with a plain `AppState`. Constructing a `tauri::State` in tests
/// needs `tauri::test::mock_app()`, and on Windows that statically anchors the
/// runtime's windowing stack (comctl32 v6's `TaskDialogIndirect`, menus, DWM)
/// into the unit-test exe, which has no comctl32-v6 manifest and therefore
/// fails to load with STATUS_ENTRYPOINT_NOT_FOUND before any test runs.
fn open_log_folder_aggregate_impl(
    path: String,
    state: &AppState,
) -> Result<AggregateParseResult, crate::error::AppError> {
    let listing = list_log_folder(path.clone())?;
    let file_entries: Vec<&FolderEntry> = listing
        .entries
        .iter()
        .filter(|entry| !entry.is_dir)
        .collect();

    let mut aggregate_entries: Vec<LogEntry> = Vec::new();
    let mut aggregate_files = Vec::with_capacity(file_entries.len());
    let mut aggregate_child_errors = listing.child_errors.clone();
    let mut open_file_states = Vec::with_capacity(file_entries.len());
    let mut total_lines = 0u32;
    let mut parse_errors = 0u32;
    for entry in file_entries {
        // Skip files we can't read (permission denied, missing, etc.) so a
        // single inaccessible file doesn't abort the whole folder load.
        let (result, parser_selection) = match parser::parse_file(&entry.path) {
            Ok(value) => value,
            Err(error) => {
                log::warn!(
                    "event=open_log_folder_aggregate_skip path=\"{}\" error=\"{error}\"",
                    entry.path
                );
                aggregate_child_errors.push(PathDiagnostic {
                    path: entry.path.clone(),
                    reason: error.to_string(),
                });
                parse_errors = parse_errors.saturating_add(1);
                continue;
            }
        };
        let final_entry_line_number = result.entries.last().map(|entry| entry.line_number);

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
            result.file_path.clone(),
            parser_selection,
            result.byte_offset,
            result.total_lines,
            final_entry_line_number,
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

    {
        let aggregate_entry_lookup = index_aggregate_entries(&aggregate_entries)?;

        let mut open_files = state
            .open_files
            .lock()
            .map_err(|e| crate::error::AppError::State(e.to_string()))?;
        for (
            path_buf,
            file_path,
            parser_selection,
            byte_offset,
            file_total_lines,
            final_entry_line_number,
        ) in open_file_states
        {
            let initial_logical_record = if InitialLogicalRecord::supports_parser(&parser_selection)
            {
                final_entry_line_number
                    .and_then(|line_number| {
                        aggregate_entry_lookup
                            .get(&(file_path.as_str(), line_number))
                            .copied()
                    })
                    .and_then(|entry| {
                        InitialLogicalRecord::from_entry(entry, file_total_lines, &parser_selection)
                    })
            } else {
                None
            };
            open_files.insert(
                path_buf.clone(),
                OpenFile {
                    path: path_buf,
                    parser_selection,
                    initial_logical_record,
                    byte_offset,
                },
            );
        }
    }

    Ok(AggregateParseResult {
        entries: aggregate_entries,
        total_lines,
        parse_errors,
        folder_path: path,
        files: aggregate_files,
        child_errors: aggregate_child_errors,
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
pub fn write_text_output_file(
    path: String,
    contents: String,
) -> Result<(), crate::error::AppError> {
    fs::write(&path, contents).map_err(crate::error::AppError::Io)
}

/// Returns file paths passed as CLI arguments at startup via OS file association.
///
/// When the user opens `.log` files with CMTrace Open (e.g. by selecting
/// multiple files and choosing "Open with"), the OS launches the application
/// with the file paths as command-line arguments. This command retrieves those
/// paths so the frontend can open them. Consumed on the first call.
#[tauri::command]
pub fn get_initial_file_paths(
    state: State<'_, AppState>,
) -> Result<Vec<String>, crate::error::AppError> {
    let mut guard = state
        .initial_file_paths
        .lock()
        .map_err(|e| crate::error::AppError::State(e.to_string()))?;
    let paths = std::mem::take(&mut *guard);
    Ok(paths)
}

/// Returns the validated app-owned workspace requested at startup.
///
/// This is intentionally separate from positional file paths so an internal
/// relaunch option can never be interpreted as evidence to open. Consumed on
/// the first call.
#[tauri::command]
pub fn get_initial_workspace(
    state: State<'_, AppState>,
) -> Result<Option<String>, crate::error::AppError> {
    let mut guard = state
        .initial_workspace
        .lock()
        .map_err(|error| crate::error::AppError::State(error.to_string()))?;
    Ok(guard.take())
}

/// List top-level entries for a folder source.
#[tauri::command]
pub fn list_log_folder(path: String) -> Result<FolderListingResult, crate::error::AppError> {
    log::info!("event=list_log_folder_start path=\"{}\"", path);

    let requested_path = PathBuf::from(&path);

    match unsafe_ancestor_reason(&requested_path) {
        Ok(Some(reason)) => {
            return Err(crate::error::AppError::InvalidInput(format!(
                "{reason}: {}",
                requested_path.display()
            )));
        }
        Ok(None) => {}
        Err(error) => {
            return Err(crate::error::AppError::from_source_io(
                error,
                crate::error::SourceOperation::ListFolder,
                Some(&path),
            ));
        }
    }

    // The no-follow ancestor check above must happen before this metadata call:
    // `metadata` follows a root symlink and would otherwise move the selection
    // outside the user's requested tree.
    let metadata = match fs::metadata(&requested_path) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(crate::error::AppError::InvalidInput(format!(
                "folder does not exist: {}",
                requested_path.display()
            )));
        }
        Err(error) => {
            return Err(crate::error::AppError::from_source_io(
                error,
                crate::error::SourceOperation::ListFolder,
                Some(&path),
            ));
        }
    };
    if !metadata.is_dir() {
        return Err(crate::error::AppError::InvalidInput(format!(
            "path is not a folder: {}",
            requested_path.display()
        )));
    }

    let read_dir = fs::read_dir(&requested_path).map_err(|error| {
        crate::error::AppError::from_source_io(
            error,
            crate::error::SourceOperation::ListFolder,
            Some(&path),
        )
    })?;
    let mut entries: Vec<FolderEntry> = Vec::new();
    let mut child_errors: Vec<PathDiagnostic> = Vec::new();
    let mut candidates = Vec::new();
    let mut listing_work = 0usize;
    let mut entry_limit_reached = false;
    let mut work_limit_reached = false;
    let mut diagnostic_limit_reached = false;
    for entry_result in read_dir {
        listing_work += 1;
        if listing_work > MAX_FOLDER_LISTING_WORK {
            work_limit_reached = true;
            break;
        }
        match entry_result {
            Ok(entry) => candidates.push(entry),
            Err(error) => push_folder_error(
                &mut child_errors,
                &mut diagnostic_limit_reached,
                &requested_path,
                &format!("child directory entry could not be read: {error}"),
            ),
        }
    }
    candidates.sort_by(|left, right| {
        let left_name = left.file_name().to_string_lossy().to_string();
        let right_name = right.file_name().to_string_lossy().to_string();
        left_name
            .to_ascii_lowercase()
            .cmp(&right_name.to_ascii_lowercase())
            .then_with(|| left_name.cmp(&right_name))
            .then_with(|| left.path().cmp(&right.path()))
    });
    if candidates.len() > MAX_FOLDER_LISTING_ENTRIES {
        candidates.truncate(MAX_FOLDER_LISTING_ENTRIES);
        entry_limit_reached = true;
    }
    for entry in candidates {
        let entry_path = entry.path();
        let unsafe_reason = match unsafe_entry_reason(&entry_path) {
            Ok(value) => value,
            Err(error) => {
                push_folder_error(
                    &mut child_errors,
                    &mut diagnostic_limit_reached,
                    &entry_path,
                    &error.to_string(),
                );
                continue;
            }
        };
        if let Some(reason) = unsafe_reason {
            push_folder_error(
                &mut child_errors,
                &mut diagnostic_limit_reached,
                &entry_path,
                reason,
            );
            continue;
        }
        let metadata = match fs::symlink_metadata(&entry_path) {
            Ok(value) => value,
            Err(error) => {
                push_folder_error(
                    &mut child_errors,
                    &mut diagnostic_limit_reached,
                    &entry_path,
                    &format!("child metadata could not be read: {error}"),
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
    if entry_limit_reached || work_limit_reached || diagnostic_limit_reached {
        if child_errors.len() >= MAX_FOLDER_LISTING_ERRORS {
            child_errors.truncate(MAX_FOLDER_LISTING_ERRORS - 1);
        }
        let mut causes = Vec::new();
        if entry_limit_reached {
            causes.push(format!(
                "folder listing reached the {MAX_FOLDER_LISTING_ENTRIES}-entry limit"
            ));
        }
        if work_limit_reached {
            causes.push(format!(
                "folder listing reached the {MAX_FOLDER_LISTING_WORK}-entry work limit"
            ));
        }
        if diagnostic_limit_reached {
            causes.push(format!(
                "folder listing reached the {MAX_FOLDER_LISTING_ERRORS}-diagnostic limit"
            ));
        }
        child_errors.push(PathDiagnostic {
            path: normalize_path_string(&requested_path),
            reason: causes.join("; "),
        });
    }
    let bundle_metadata = detect_evidence_bundle_metadata(&requested_path);
    if bundle_metadata.is_some() {
        // For evidence bundles, recursively collect all files from the entire
        // directory tree so that every nested artifact is loaded.
        let collected = collect_files_recursive(&requested_path);
        entries = collected.entries;
        child_errors = collected.child_errors;
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
        child_errors,
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

fn push_folder_error(
    errors: &mut Vec<PathDiagnostic>,
    diagnostic_limit_reached: &mut bool,
    path: &Path,
    reason: &str,
) {
    if errors.len() < MAX_FOLDER_LISTING_ERRORS {
        errors.push(PathDiagnostic {
            path: normalize_path_string(path),
            reason: reason.to_string(),
        });
    } else {
        *diagnostic_limit_reached = true;
    }
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

#[derive(Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileHashResult {
    pub hash: String,
    pub size_bytes: u64,
}

#[tauri::command]
pub fn compute_file_hash(path: String) -> Result<FileHashResult, crate::error::AppError> {
    use sha2::{Digest, Sha256};
    use std::fmt::Write as _;
    use std::io::Read;

    let mut file = std::fs::File::open(&path).map_err(crate::error::AppError::Io)?;

    let metadata = file.metadata().map_err(crate::error::AppError::Io)?;
    let size_bytes = metadata.len();

    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let bytes_read = file.read(&mut buffer).map_err(crate::error::AppError::Io)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    // Formatted byte-by-byte rather than with `{:x}`: sha2 0.11 returns a
    // hybrid-array `Array`, which (unlike generic-array) has no `LowerHex` impl.
    // Output is byte-identical to the old `{:x}`.
    let mut hash = String::from("sha256:");
    for byte in hasher.finalize() {
        let _ = write!(&mut hash, "{byte:02x}");
    }
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
            .cmp(
                &file_order
                    .get(&right.file_path)
                    .copied()
                    .unwrap_or(usize::MAX),
            )
            .then_with(|| left.line_number.cmp(&right.line_number))
            .then_with(|| left.message.cmp(&right.message)),
    }
}

fn index_aggregate_entries(
    entries: &[LogEntry],
) -> Result<std::collections::HashMap<(&str, u32), &LogEntry>, crate::error::AppError> {
    let mut lookup = std::collections::HashMap::new();
    for entry in entries {
        if lookup
            .insert((entry.file_path.as_str(), entry.line_number), entry)
            .is_some()
        {
            return Err(crate::error::AppError::Internal(format!(
                "duplicate aggregate entry for {} at physical line {}",
                entry.file_path, entry.line_number
            )));
        }
    }
    Ok(lookup)
}

#[cfg(test)]
mod tests {
    use super::{index_aggregate_entries, list_log_folder, open_log_folder_aggregate_impl};
    use crate::state::app_state::AppState;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    /// Proves the wiring, not just the classifier: an unreadable folder must
    /// reach the frontend as `AccessDenied` rather than as "folder does not
    /// exist", which is what `Path::exists` used to turn it into.
    #[cfg(unix)]
    #[test]
    fn list_log_folder_reports_an_unreadable_folder_as_access_denied() {
        use std::os::unix::fs::PermissionsExt;

        // Root ignores the permission bits, so the refusal never happens.
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("skipping: running as root, permission bits are not enforced");
            return;
        }

        let dir = create_temp_dir("file-ops-denied");
        let locked = dir.join("locked");
        fs::create_dir(&locked).expect("create locked dir");
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).expect("drop permissions");

        let result = list_log_folder(locked.to_string_lossy().to_string());

        // Restore before asserting so a failure still leaves a removable tree.
        let _ = fs::set_permissions(&locked, fs::Permissions::from_mode(0o755));

        match result {
            Err(crate::error::AppError::AccessDenied { operation, path }) => {
                assert_eq!(operation, crate::error::SourceOperation::ListFolder);
                assert_eq!(path.as_deref(), Some(locked.to_string_lossy().as_ref()));
            }
            other => panic!("expected AccessDenied, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn open_log_file_reports_an_unreadable_file_as_access_denied() {
        use std::os::unix::fs::PermissionsExt;

        if unsafe { libc::geteuid() } == 0 {
            eprintln!("skipping: running as root, permission bits are not enforced");
            return;
        }

        let dir = create_temp_dir("file-ops-denied-file");
        let locked = dir.join("locked.log");
        fs::write(&locked, "2026-07-31 log line").expect("write log");
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).expect("drop permissions");

        let error = super::classify_open_failure(
            locked.to_string_lossy().as_ref(),
            "parser said something less specific".to_string(),
        );

        let _ = fs::set_permissions(&locked, fs::Permissions::from_mode(0o644));

        assert!(
            matches!(
                error,
                crate::error::AppError::AccessDenied {
                    operation: crate::error::SourceOperation::ReadFile,
                    ..
                }
            ),
            "expected AccessDenied, got {error:?}"
        );
    }

    #[test]
    fn a_readable_file_that_fails_to_parse_is_not_access_denied() {
        let dir = create_temp_dir("file-ops-parse-fail");
        let readable = dir.join("readable.log");
        fs::write(&readable, "content").expect("write log");

        let error = super::classify_open_failure(
            readable.to_string_lossy().as_ref(),
            "unsupported format".to_string(),
        );

        // The file opens fine, so the parser's own message survives and no
        // elevation offer can be produced.
        assert!(
            matches!(error, crate::error::AppError::Internal(reason) if reason == "unsupported format")
        );
    }

    #[test]
    fn aggregate_tail_seed_uses_the_frontend_visible_entry_id() {
        let dir = create_temp_dir("file-ops-aggregate-tail-seed");
        let later_path = dir.join("Log_1.log");
        let earlier_path = dir.join("Log_2.log");
        fs::write(
            &later_path,
            "2026-05-04T08:12:32.0020000Z  INFO      Event       None        1    \
             1a2b3c4d-0001-4000-8000-000000000001  12-0-0  [App Catalog] later\n",
        )
        .expect("write later Company Portal log");
        fs::write(
            &earlier_path,
            "2026-05-04T08:12:31.4410000Z  INFO      Event       None        0    \
             1a2b3c4d-0001-4000-8000-000000000002  12-0-0  [App Catalog] earlier\n",
        )
        .expect("write earlier Company Portal log");

        // A plain AppState, not tauri::test::mock_app(): building a mock app
        // statically anchors the runtime's windowing stack into the unit-test
        // exe, which cannot load on Windows (no comctl32-v6 manifest).
        let state = AppState::default();
        let result = open_log_folder_aggregate_impl(dir.to_string_lossy().to_string(), &state)
            .expect("open aggregate folder");
        let later_path = later_path.to_string_lossy();
        let visible_entry_id = result
            .entries
            .iter()
            .find(|entry| entry.file_path == later_path)
            .expect("later aggregate entry")
            .id;
        let stored_seed_id = state
            .open_files
            .lock()
            .expect("open files lock")
            .get(PathBuf::from(later_path.as_ref()).as_path())
            .and_then(|open_file| open_file.initial_logical_record.as_ref())
            .expect("later aggregate tail seed")
            .entry_id_for_test();

        fs::remove_dir_all(&dir).expect("remove temp aggregate folder");

        assert_eq!(visible_entry_id, 1, "fixture must reorder the later record");
        assert_eq!(stored_seed_id, visible_entry_id);
    }

    #[test]
    fn aggregate_tail_seed_index_rejects_duplicate_source_lines() {
        let dir = create_temp_dir("file-ops-aggregate-duplicate-seed");
        let path = dir.join("Log_1.log");
        fs::write(
            &path,
            "2026-05-04T08:12:31.4410000Z  INFO      Event       None        0    \
             1a2b3c4d-0001-4000-8000-000000000002  12-0-0  [App Catalog] entry\n",
        )
        .expect("write Company Portal log");
        let (result, _) = crate::parser::parse_file(path.to_string_lossy().as_ref())
            .expect("parse Company Portal log");
        let entry = result.entries.first().expect("parsed entry").clone();
        let entries = [entry.clone(), entry];

        let error = index_aggregate_entries(&entries).expect_err("duplicate key must fail");

        fs::remove_dir_all(&dir).expect("remove temp aggregate folder");
        assert!(
            matches!(error, crate::error::AppError::Internal(message) if message.contains("duplicate aggregate entry")),
            "duplicate source coordinates must fail clearly"
        );
    }

    /// A folder reaching the file lane must be classified by its kind, never by
    /// whatever the failed open happened to report.
    ///
    /// Deliberately ungated. On Windows `CreateFileW` without
    /// `FILE_FLAG_BACKUP_SEMANTICS` fails a directory with
    /// `ERROR_ACCESS_DENIED` (5), which std maps to `PermissionDenied`, so
    /// probing the open first reported every dropped folder as Access Denied and
    /// raised a spurious "Restart as administrator?" prompt. On Unix the same
    /// probe succeeds and the parser's message survives. Establishing the kind
    /// first is what makes one assertion hold on both.
    #[test]
    fn a_directory_is_classified_by_its_kind_not_by_the_failed_open() {
        let dir = create_temp_dir("file-ops-directory");

        let error = super::classify_open_failure(
            dir.to_string_lossy().as_ref(),
            "parser said something less specific".to_string(),
        );

        match error {
            crate::error::AppError::InvalidInput(message) => {
                assert!(
                    message.contains("folder"),
                    "the verdict must name the kind mismatch: {message}"
                );
            }
            other => panic!("expected a folder verdict, got {other:?}"),
        }

        fs::remove_dir_all(&dir).expect("remove temp dir");
    }

    #[test]
    fn ordinary_manifest_folder_keeps_evtx_children_and_is_not_bundle() {
        let dir = create_temp_dir("file-ops-ordinary-manifest");
        fs::write(dir.join("manifest.json"), r#"{"notes":"ordinary folder"}"#)
            .expect("write ordinary manifest");
        fs::write(dir.join("Application.evtx"), b"evtx").expect("write evtx");

        let result = list_log_folder(dir.to_string_lossy().to_string()).expect("list folder");
        assert!(result.bundle_metadata.is_none());
        assert!(result
            .entries
            .iter()
            .any(|entry| entry.name == "Application.evtx"));

        fs::remove_dir_all(&dir).expect("remove ordinary folder");
    }

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
    fn bundle_listing_includes_nested_evtx_and_bounds_recursive_entries() {
        let bundle_dir = create_temp_dir("file-ops-bundle-eventlog-cap");
        let nested = bundle_dir.join("evidence").join("logs").join("nested");
        fs::create_dir_all(&nested).expect("create nested logs");
        fs::write(bundle_dir.join("manifest.json"), sample_bundle_manifest())
            .expect("write manifest");
        let evtx = nested.join("Application.evtx");
        fs::write(&evtx, b"evtx").expect("write event log");
        for index in 0..4100 {
            fs::write(nested.join(format!("artifact-{index}.log")), b"log")
                .expect("write artifact");
        }

        let result =
            list_log_folder(bundle_dir.to_string_lossy().to_string()).expect("list bundle");
        assert!(result.entries.len() <= 4096);
        assert!(result
            .entries
            .iter()
            .any(|entry| entry.path == evtx.to_string_lossy()));
        fs::remove_dir_all(&bundle_dir).expect("remove temp bundle");
    }
    #[cfg(unix)]
    #[test]
    fn bundle_listing_rejects_symlinked_directories_with_child_coverage() {
        use std::os::unix::fs::symlink;

        let bundle_dir = create_temp_dir("file-ops-bundle-symlink");
        let outside = create_temp_dir("file-ops-bundle-symlink-target");
        fs::write(outside.join("outside.log"), b"outside").expect("write outside log");
        fs::create_dir_all(bundle_dir.join("evidence")).expect("create evidence");
        fs::write(bundle_dir.join("manifest.json"), sample_bundle_manifest())
            .expect("write manifest");
        symlink(&outside, bundle_dir.join("evidence").join("linked"))
            .expect("create directory symlink");

        let result =
            list_log_folder(bundle_dir.to_string_lossy().to_string()).expect("list bundle");
        assert!(result
            .child_errors
            .iter()
            .any(|error| error.reason.contains("symbolic link")));
        assert!(!result
            .entries
            .iter()
            .any(|entry| entry.path.ends_with("outside.log")));

        fs::remove_dir_all(&bundle_dir).expect("remove bundle");
        fs::remove_dir_all(&outside).expect("remove target");
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
