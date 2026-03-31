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
/// - When `include_live_event_logs` is true, also queries the live Windows Event Log
#[tauri::command]
pub async fn analyze_sysmon_logs(
    path: String,
    request_id: String,
    include_live_event_logs: bool,
    app: AppHandle,
) -> Result<SysmonAnalysisResult, crate::error::AppError> {
    async_runtime::spawn_blocking(move || {
        analyze_sysmon_blocking(path, request_id, include_live_event_logs, app)
    })
    .await
    .map_err(|error| {
        crate::error::AppError::Internal(format!("Sysmon analysis task failed: {}", error))
    })?
}

/// Sentinel path value used by known-source presets to indicate "query the live
/// Windows Event Log rather than reading files from disk".
const LIVE_EVENT_LOG_SENTINEL: &str = "live-event-log";

fn is_live_only_source(path: &str) -> bool {
    path == LIVE_EVENT_LOG_SENTINEL || path.is_empty()
}

fn analyze_sysmon_blocking(
    path: String,
    request_id: String,
    include_live_event_logs: bool,
    app: AppHandle,
) -> Result<SysmonAnalysisResult, crate::error::AppError> {
    let live_only = is_live_only_source(&path);

    // --- File-based events (skip when live-only) ---
    let mut all_events = Vec::new();
    let mut total_errors = 0u64;
    let mut source_files: Vec<String> = Vec::new();
    let mut total_files = 0usize;

    if !live_only {
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

        if evtx_files.is_empty() && !include_live_event_logs {
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

        if sysmon_files.is_empty() && !include_live_event_logs {
            return Err(crate::error::AppError::InvalidInput(
                "No Sysmon EVTX files found. Ensure the file contains Microsoft-Windows-Sysmon events."
                    .to_string(),
            ));
        }

        total_files = sysmon_files.len();

        if total_files > 0 {
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

            for (events, errors) in parse_results {
                all_events.extend(events);
                total_errors += errors;
            }

            source_files = sysmon_files
                .iter()
                .map(|f| f.to_string_lossy().to_string())
                .collect();
        }
    }

    // --- Live event log events ---
    if include_live_event_logs {
        let _ = app.emit(
            SYSMON_ANALYSIS_PROGRESS_EVENT,
            SysmonAnalysisProgress {
                request_id: request_id.clone(),
                stage: "live-query",
                message: "Querying live Sysmon event log...".to_string(),
                completed_files: total_files,
                total_files,
            },
        );

        match evtx_parser::parse_sysmon_live_events() {
            Ok(live_events) => {
                log::info!(
                    "event=sysmon_live_query_success count={}",
                    live_events.len()
                );
                if !live_events.is_empty() {
                    if let Some(first) = live_events.first() {
                        source_files.push(first.source_file.clone());
                    }
                }
                all_events.extend(live_events);
            }
            Err(e) => {
                log::warn!("event=sysmon_live_query_failed error=\"{}\"", e);
                if live_only {
                    return Err(crate::error::AppError::Internal(e));
                }
                // Non-fatal when combined with file-based events
                total_errors += 1;
            }
        }
    }

    if all_events.is_empty() {
        return Err(crate::error::AppError::InvalidInput(
            "No Sysmon events found from files or live event log.".to_string(),
        ));
    }

    // Sort by timestamp_ms when available, falling back to timestamp and then record_id for stable ordering
    all_events.sort_by(|a, b| {
        match (a.timestamp_ms, b.timestamp_ms) {
            (Some(ta), Some(tb)) => ta
                .cmp(&tb)
                .then_with(|| a.record_id.cmp(&b.record_id)),
            (Some(_), None) => std::cmp::Ordering::Less,    // nulls last
            (None, Some(_)) => std::cmp::Ordering::Greater,  // nulls last
            (None, None) => a.timestamp
                .cmp(&b.timestamp)
                .then_with(|| a.record_id.cmp(&b.record_id)),
        }
    });

    // Reassign sequential IDs after sorting
    for (i, event) in all_events.iter_mut().enumerate() {
        event.id = i as u64;
    }

    // Build summary
    let summary = evtx_parser::build_summary(&all_events, source_files, total_errors);

    // Extract configuration
    let config = evtx_parser::extract_config(&all_events, &summary);

    // Build dashboard aggregations
    let dashboard = evtx_parser::build_dashboard_data(&all_events);

    let total_source_count = if include_live_event_logs { total_files + 1 } else { total_files };

    // Emit: complete
    let _ = app.emit(
        SYSMON_ANALYSIS_PROGRESS_EVENT,
        SysmonAnalysisProgress {
            request_id: request_id.clone(),
            stage: "complete",
            message: format!("Analysis complete: {} events from {} source(s)", all_events.len(), total_source_count),
            completed_files: total_source_count,
            total_files: total_source_count,
        },
    );

    Ok(SysmonAnalysisResult {
        events: all_events,
        summary,
        config,
        dashboard,
        source_path: path,
    })
}
