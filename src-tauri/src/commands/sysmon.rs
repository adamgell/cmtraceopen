use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

use rayon::prelude::*;
use serde::Serialize;
use tauri::{async_runtime, AppHandle, Emitter};

use crate::sysmon::evtx_parser;
use crate::sysmon::models::SysmonAnalysisResult;

const SYSMON_ANALYSIS_PROGRESS_EVENT: &str = "sysmon-analysis-progress";

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct SysmonAnalysisProgress {
    request_id: String,
    stage: &'static str,
    message: String,
    completed_files: usize,
    total_files: usize,
}

/// Analyze Sysmon EVTX files and return structured results.
///
/// Accepts either:
/// - A single .evtx file path
/// - A directory containing .evtx files
#[tauri::command]
pub async fn analyze_sysmon_logs(
    path: String,
    request_id: String,
    app: AppHandle,
) -> Result<SysmonAnalysisResult, crate::error::AppError> {
    async_runtime::spawn_blocking(move || {
        analyze_sysmon_blocking(path, request_id, app)
    })
    .await
    .map_err(|error| {
        crate::error::AppError::Internal(format!("Sysmon analysis task failed: {}", error))
    })?
}

fn analyze_sysmon_blocking(
    path: String,
    request_id: String,
    app: AppHandle,
) -> Result<SysmonAnalysisResult, crate::error::AppError> {
    let source_path = Path::new(&path);

    // Emit: discovery stage
    let _ = app.emit(
        SYSMON_ANALYSIS_PROGRESS_EVENT,
        SysmonAnalysisProgress {
            request_id: request_id.clone(),
            stage: "discovery",
            message: "Discovering EVTX files...".to_string(),
            completed_files: 0,
            total_files: 0,
        },
    );

    // Discover files
    let evtx_files = if source_path.is_file() {
        vec![source_path.to_path_buf()]
    } else if source_path.is_dir() {
        evtx_parser::discover_sysmon_evtx_files(source_path)
    } else {
        return Err(crate::error::AppError::InvalidInput(format!(
            "Path does not exist: {}",
            path
        )));
    };

    if evtx_files.is_empty() {
        return Err(crate::error::AppError::InvalidInput(
            "No .evtx files found at the specified path".to_string(),
        ));
    }

    // Filter to only Sysmon EVTX files (if directory, validate provider)
    let sysmon_files: Vec<_> = if source_path.is_file() {
        // Single file — trust the user
        evtx_files
    } else {
        evtx_files
            .into_iter()
            .filter(|f| evtx_parser::is_sysmon_evtx(f))
            .collect()
    };

    if sysmon_files.is_empty() {
        return Err(crate::error::AppError::InvalidInput(
            "No Sysmon EVTX files found. Ensure the file contains Microsoft-Windows-Sysmon events."
                .to_string(),
        ));
    }

    let total_files = sysmon_files.len();

    // Emit: parsing stage
    let _ = app.emit(
        SYSMON_ANALYSIS_PROGRESS_EVENT,
        SysmonAnalysisProgress {
            request_id: request_id.clone(),
            stage: "parsing",
            message: format!("Parsing {} Sysmon EVTX file(s)...", total_files),
            completed_files: 0,
            total_files,
        },
    );

    // Parse files in parallel
    let completed = AtomicUsize::new(0);
    let parse_results: Vec<_> = sysmon_files
        .par_iter()
        .enumerate()
        .filter_map(|(idx, file_path)| {
            let id_offset = (idx as u64) * 100_000;
            match evtx_parser::parse_sysmon_evtx(file_path, id_offset) {
                Ok(events) => {
                    let done = completed.fetch_add(1, Ordering::Relaxed) + 1;
                    let _ = app.emit(
                        SYSMON_ANALYSIS_PROGRESS_EVENT,
                        SysmonAnalysisProgress {
                            request_id: request_id.clone(),
                            stage: "parsing",
                            message: format!(
                                "Parsed {} ({}/{})",
                                file_path.file_name().unwrap_or_default().to_string_lossy(),
                                done,
                                total_files
                            ),
                            completed_files: done,
                            total_files,
                        },
                    );
                    Some((events, 0u64))
                }
                Err(e) => {
                    log::warn!("event=sysmon_file_error file=\"{}\" error=\"{}\"", file_path.display(), e);
                    let done = completed.fetch_add(1, Ordering::Relaxed) + 1;
                    let _ = app.emit(
                        SYSMON_ANALYSIS_PROGRESS_EVENT,
                        SysmonAnalysisProgress {
                            request_id: request_id.clone(),
                            stage: "parsing",
                            message: format!(
                                "Error parsing {} ({}/{})",
                                file_path.file_name().unwrap_or_default().to_string_lossy(),
                                done,
                                total_files
                            ),
                            completed_files: done,
                            total_files,
                        },
                    );
                    Some((Vec::new(), 1u64))
                }
            }
        })
        .collect();

    // Merge all events
    let mut all_events = Vec::new();
    let mut total_errors = 0u64;
    for (events, errors) in parse_results {
        all_events.extend(events);
        total_errors += errors;
    }

    // Sort by timestamp_ms when available, falling back to timestamp and then record_id for stable ordering
    all_events.sort_by(|a, b| {
        match (a.timestamp_ms, b.timestamp_ms) {
            (Some(ta), Some(tb)) => ta
                .cmp(&tb)
                .then_with(|| a.record_id.cmp(&b.record_id)),
            _ => a.timestamp
                .cmp(&b.timestamp)
                .then_with(|| a.record_id.cmp(&b.record_id)),
        }
    });

    // Reassign sequential IDs after sorting
    for (i, event) in all_events.iter_mut().enumerate() {
        event.id = i as u64;
    }

    let source_files: Vec<String> = sysmon_files
        .iter()
        .map(|f| f.to_string_lossy().to_string())
        .collect();

    // Build summary
    let summary = evtx_parser::build_summary(&all_events, source_files, total_errors);

    // Extract configuration
    let config = evtx_parser::extract_config(&all_events, &summary);

    // Emit: complete
    let _ = app.emit(
        SYSMON_ANALYSIS_PROGRESS_EVENT,
        SysmonAnalysisProgress {
            request_id: request_id.clone(),
            stage: "complete",
            message: format!("Analysis complete: {} events from {} file(s)", all_events.len(), total_files),
            completed_files: total_files,
            total_files,
        },
    );

    Ok(SysmonAnalysisResult {
        events: all_events,
        summary,
        config,
        source_path: path,
    })
}
