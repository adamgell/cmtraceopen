use super::models::{EvtxChannelInfo, EvtxParseResult};
use super::parser::{self, EventLogSourceManifest};
use crate::state::app_state::AppState;
#[cfg(target_os = "windows")]
use serde::Serialize;
#[cfg(target_os = "windows")]
use tauri::Emitter;
use super::models::{
    EvtxChannelInfo, EvtxClearResult, EvtxClearStatus, EvtxLiveMode, EvtxParseResult,
    EvtxTailStatus,
};
use super::parser::{self, EventLogSourceManifest};
use crate::state::app_state::AppState;
#[cfg(target_os = "windows")]
use serde::Serialize;
#[cfg(target_os = "windows")]
use tauri::Emitter;
use tauri::{AppHandle, Manager};

#[cfg(target_os = "windows")]
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct EvtxQueryProgress {
    request_id: String,
    channel: String,
    fetched: usize,
}

/// A batch of records on its way to the frontend before the query has finished.
///
/// One channel can be most of a scan: a reply that waits for the channel to finish leaves an
/// operator watching an empty list for the duration of the scan. Batches are emitted as they are
/// read instead.
///
/// `sequence` numbers the batches for one channel from zero. The receiver uses it to notice a batch
/// it never got: an event channel offers no delivery guarantee, and events that quietly failed to
/// arrive would look exactly like events that do not exist. `request_id` prevents a late batch from
/// a superseded local/remote source query being merged into the current view.
#[cfg(target_os = "windows")]
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct EvtxRecordBatch {
    request_id: String,
    channel: String,
    sequence: usize,
    records: Vec<super::models::EvtxRecord>,
}
#[cfg(target_os = "windows")]
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct EvtxRecordStreamComplete {
    channel: String,
    request_id: String,
    sequence_count: usize,
    total_records: usize,
}

/// Expands folder, wildcard, archive, and VSS selections before parsing.
#[tauri::command]
pub fn evtx_expand_sources(
    sources: Vec<parser::EventLogSourceSelection>,
) -> Result<EventLogSourceManifest, String> {
    parser::build_source_manifest_for_selections(&sources)
}

#[tauri::command]
pub async fn evtx_parse_files(
    paths: Vec<String>,
    state: tauri::State<'_, AppState>,
) -> Result<EvtxParseResult, String> {
    let maps = state.event_maps.clone();
    let providers = state.provider_store.clone();
    tokio::task::spawn_blocking(move || {
        let manifest = parser::build_source_manifest(&paths)?;
        parser::parse_evtx_manifest(&manifest, &maps, &providers)
    })
    .await
    .map_err(|e| format!("Task join error: {}", e))?
}

/// Parses an already-expanded manifest without rebuilding it from paths.
#[tauri::command]
pub async fn evtx_parse_manifest(
    manifest: EventLogSourceManifest,
    state: tauri::State<'_, AppState>,
) -> Result<EvtxParseResult, String> {
    let maps = state.event_maps.clone();
    let providers = state.provider_store.clone();
    tokio::task::spawn_blocking(move || parser::parse_evtx_manifest(&manifest, &maps, &providers))
        .await
        .map_err(|e| format!("Task join error: {}", e))?
}

#[tauri::command]
pub async fn evtx_enumerate_channels() -> Result<Vec<EvtxChannelInfo>, String> {
    #[cfg(target_os = "windows")]
    {
        tokio::task::spawn_blocking(super::live::enumerate_channels)
            .await
            .map_err(|e| format!("Task join error: {}", e))?
    }
    #[cfg(not(target_os = "windows"))]
    {
        Err("Live event log queries are only available on Windows.".to_string())
    }
}

#[tauri::command]
pub async fn evtx_enumerate_remote_channels(
    machine: String,
) -> Result<Vec<EvtxChannelInfo>, String> {
    #[cfg(target_os = "windows")]
    {
        tokio::task::spawn_blocking(move || super::live::enumerate_remote_channels(&machine))
            .await
            .map_err(|e| format!("Task join error: {e}"))?
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = machine;
        Err("Remote event log queries are only available on Windows.".to_string())
    }
}

#[cfg(target_os = "windows")]
fn query_source_channel(
    remote_machine: Option<&str>,
    channel: &str,
    filter: &cmtraceopen_parser::event_query::EventQueryFilter,
    maps: &cmtraceopen_parser::eventmap::MapRegistry,
    max_events: Option<u64>,
    on_progress: impl Fn(usize, Option<usize>),
    on_batch: impl FnMut(&mut Vec<super::models::EvtxRecord>),
) -> Result<super::live::ChannelScan, String> {
    match remote_machine {
        Some(machine) => super::live::query_remote_channel_streamed(
            machine,
            channel,
            filter,
            maps,
            max_events,
            on_progress,
            on_batch,
        ),
        None => super::live::query_channel_streamed(
            channel,
            filter,
            maps,
            max_events,
            on_progress,
            on_batch,
        ),
    }
}
async fn query_channels_impl(
    channels: Vec<String>,
    max_events: Option<u64>,
    filter: Option<cmtraceopen_parser::event_query::EventQueryFilter>,
    app: AppHandle,
    state: tauri::State<'_, AppState>,
    remote_machine: Option<String>,
    request_id: String,
) -> Result<EvtxParseResult, String> {
    #[cfg(target_os = "windows")]
    {
        let registry = state.event_maps.clone();
        tokio::task::spawn_blocking(move || {
            use rayon::prelude::*;

            let maps = registry
                .read()
                .map_err(|_| "map registry lock was poisoned".to_string())?;
            let query_filter = filter.unwrap_or_default();
            let source_type = remote_machine
                .as_ref()
                .map(|machine| super::models::ChannelSourceType::Remote {
                    machine: machine.clone(),
                })
                .unwrap_or(super::models::ChannelSourceType::Live);

            let per_channel: Vec<(String, Result<super::live::ChannelScan, String>)> = channels
                .par_iter()
                .map(|channel| {
                    let app_ref = &app;
                    let batch_request_id = request_id.clone();
                    let ch_name = channel.clone();
                    let batch_channel = channel.clone();
                    let mut sequence = 0usize;
                    let outcome = query_source_channel(
                        remote_machine.as_deref(),
                        channel,
                        &query_filter,
                        &maps,
                        max_events,
                        |fetched, _| {
                            let _ = app_ref.emit(
                                "evtx-query-progress",
                                EvtxQueryProgress {
                                    request_id: batch_request_id.clone(),
                                    channel: ch_name.clone(),
                                    fetched,
                                },
                            );
                        },
                        |batch| {
                            if batch.is_empty() {
                                return;
                            }
                            let records = std::mem::take(batch);
                            if let Err(error) = app_ref.emit(
                                "evtx-record-batch",
                                EvtxRecordBatch {
                                    request_id: batch_request_id.clone(),
                                    channel: batch_channel.clone(),
                                    sequence,
                                    records,
                                },
                            ) {
                                log::warn!(
                                    "event=evtx_batch_emit_failed channel=\"{batch_channel}\" \
                                     sequence={sequence} error=\"{error}\""
                                );
                            }
                            sequence += 1;
                        },
                    );
                    let sequence_count = sequence;
                    let total_records = outcome.as_ref().map(|scan| scan.delivered).unwrap_or(0);
                    if let Err(error) = app_ref.emit(
                        "evtx-record-stream-complete",
                        EvtxRecordStreamComplete {
                            channel: batch_channel.clone(),
                            request_id: batch_request_id.clone(),
                            sequence_count,
                            total_records,
                        },
                    ) {
                        log::warn!(
                            "event=evtx_stream_complete_emit_failed channel=\"{batch_channel}\" \
                             error=\"{error}\""
                        );
                    }
                    (channel.clone(), outcome)
                })
                .collect();

            let mut all_records = Vec::new();
            let mut channel_infos = Vec::new();
            let mut parse_errors = 0u32;
            let mut error_messages = Vec::new();
            let mut streamed = 0usize;

            for (channel, outcome) in per_channel {
                match outcome {
                    Ok(scan) => {
                        channel_infos.push(EvtxChannelInfo {
                            name: channel.clone(),
                            event_count: scan.delivered as u64,
                            source_type: source_type.clone(),
                        });
                        streamed += scan.delivered;
                        if !scan.gaps.is_empty() {
                            parse_errors += scan.gaps.len() as u32;
                            error_messages.extend(scan.gaps);
                        }
                        all_records.extend(scan.records);
                    }
                    Err(error) => {
                        log::warn!(
                            "event=evtx_channel_query_error channel=\"{}\" error=\"{}\"",
                            channel,
                            error
                        );
                        error_messages.push(format!("{channel}: {error}"));
                        channel_infos.push(EvtxChannelInfo {
                            name: channel,
                            event_count: 0,
                            source_type: source_type.clone(),
                        });
                        parse_errors += 1;
                    }
                }
            }

            all_records.sort_by_key(|record| record.timestamp_epoch);
            let total_records = (streamed + all_records.len()) as u64;
            Ok(EvtxParseResult {
                records: all_records,
                channels: channel_infos,
                total_records,
                parse_errors,
                error_messages,
                coverage_gaps: Vec::new(),
                coverage: Vec::new(),
            })
        })
        .await
        .map_err(|error| format!("Task join error: {error}"))?;
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (
            channels,
            max_events,
            filter,
            app,
            state,
            remote_machine,
            request_id,
        );
        Err("Live event log queries are only available on Windows.".to_string())
    }
}

#[tauri::command]
pub async fn evtx_query_channels(
    channels: Vec<String>,
    max_events: Option<u64>,
    filter: Option<cmtraceopen_parser::event_query::EventQueryFilter>,
    request_id: String,
    app: AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<EvtxParseResult, String> {
    query_channels_impl(channels, max_events, filter, app, state, None, request_id).await
}

#[tauri::command]
pub async fn evtx_query_remote_channels(
    machine: String,
    channels: Vec<String>,
    max_events: Option<u64>,
    filter: Option<cmtraceopen_parser::event_query::EventQueryFilter>,
    request_id: String,
    app: AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<EvtxParseResult, String> {
    #[cfg(target_os = "windows")]
    let machine = super::live::normalize_remote_machine_name(&machine)?;
    query_channels_impl(
        channels,
        max_events,
        filter,
        app,
        state,
        Some(machine),
        request_id,
    )
    .await
}

/// Start a live tail for one channel. Windows prefers EvtSubscribe and reports polling only when
/// the service does not expose subscription support.
#[tauri::command]
pub async fn evtx_start_tail(
    channel: String,
    request_id: String,
    filter: Option<cmtraceopen_parser::event_query::EventQueryFilter>,
    remote_machine: Option<String>,
    app: AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<EvtxTailStatus, String> {
    #[cfg(target_os = "windows")]
    {
        let remote_machine = remote_machine
            .as_deref()
            .map(super::live::normalize_remote_machine_name)
            .transpose()?;
        let maps = state.event_maps.clone();
        let query_filter = filter.unwrap_or_default();
        tokio::task::spawn_blocking(move || {
            super::live::start_channel_tail(
                app,
                request_id,
                channel,
                query_filter,
                maps,
                remote_machine,
            )
        })
        .await
        .map_err(|error| format!("Task join error: {error}"))?
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (filter, remote_machine, app, state);
        Ok(EvtxTailStatus {
            request_id,
            channel,
            mode: EvtxLiveMode::Unsupported,
            active: false,
            next_sequence: 0,
            coverage_gaps: vec!["Live event log tails are only available on Windows.".to_string()],
        })
    }
}

/// Stop a live tail and release any subscription or polling worker.
#[tauri::command]
pub async fn evtx_stop_tail(request_id: String, channel: String) -> Result<EvtxTailStatus, String> {
    #[cfg(target_os = "windows")]
    {
        let request_for_task = request_id.clone();
        let channel_for_task = channel.clone();
        tokio::task::spawn_blocking(move || {
            super::live::stop_channel_tail(&request_for_task, &channel_for_task).unwrap_or(
                EvtxTailStatus {
                    request_id: request_for_task,
                    channel: channel_for_task,
                    mode: EvtxLiveMode::Unsupported,
                    active: false,
                    next_sequence: 0,
                    coverage_gaps: Vec::new(),
                },
            )
        })
        .await
        .map_err(|error| format!("Task join error: {error}"))?
    }
    #[cfg(not(target_os = "windows"))]
    {
        Ok(EvtxTailStatus {
            request_id,
            channel,
            mode: EvtxLiveMode::Unsupported,
            active: false,
            next_sequence: 0,
            coverage_gaps: vec!["Live event log tails are only available on Windows.".to_string()],
        })
    }
}

/// Clear one live channel after an explicit frontend confirmation. The backend repeats the
/// confirmation guard and requires the existing process to be elevated before EvtClearLog.
#[tauri::command]
pub async fn evtx_clear_channel(
    channel: String,
    confirmed: bool,
) -> Result<EvtxClearResult, String> {
    if !confirmed {
        return Ok(EvtxClearResult {
            channel,
            result: EvtxClearStatus::Cancelled,
        });
    }
    #[cfg(target_os = "windows")]
    {
        tokio::task::spawn_blocking(move || super::live::clear_channel(&channel, confirmed))
            .await
            .map_err(|error| format!("Task join error: {error}"))?
    }
    #[cfg(not(target_os = "windows"))]
    {
        Ok(EvtxClearResult {
            channel,
            result: EvtxClearStatus::Unsupported {
                detail: "Clearing event channels is only available on Windows.".to_string(),
            },
        })
    }
}

/// Writes `records` to `destination` in `format`.
///
/// The records travel from the frontend rather than being re-queried, so what is exported is
/// exactly what the operator was looking at, including any client-side filtering they had applied.
/// Re-querying would risk exporting a different set than the one on screen.
#[tauri::command]
pub async fn evtx_export_records(
    records: Vec<super::models::EvtxRecord>,
    format: super::export::ExportFormat,
    destination: String,
    source_paths: Vec<String>,
) -> Result<u64, String> {
    let record_count = records.len();
    let destination_path = std::path::PathBuf::from(&destination);
    super::writer::reject_source_destination(&source_paths, Some(&destination_path))?;
    let destination_for_log = destination.clone();
    let rendered = tokio::task::spawn_blocking(move || {
        super::writer::write_records_to_destination(&records, format, Some(&destination_path))
            .map(|stats| stats.bytes)
    })
    .await
    .map_err(|error| format!("export task failed: {error}"))??;
    log::info!(
        "event=evtx_export destination=\"{destination_for_log}\" records={record_count} bytes={rendered}"
    );
    Ok(rendered)
}

/// Loads EvtxECmd `.map` files from `directory` into the application's registry.
///
/// Returns what loaded, what was superseded, and what failed, so an operator can see why an event
/// type is not being mapped rather than being left guessing.
#[tauri::command]
pub async fn evtx_load_event_maps(
    directory: String,
    state: tauri::State<'_, AppState>,
) -> Result<super::maps::MapLoadOutcome, String> {
    let path = std::path::PathBuf::from(&directory);
    let maps = state.event_maps.clone();
    tokio::task::spawn_blocking(move || {
        // Read from disk first, then swap. Holding the write lock across the read would block
        // every in-flight parse for as long as the directory takes to load.
        let (registry, outcome) = super::maps::load_maps_from_dir(&path)?;
        *maps
            .write()
            .map_err(|_| "map registry lock was poisoned".to_string())? = registry;
        Ok(outcome)
    })
    .await
    .map_err(|error| format!("map load task failed: {error}"))?
}

/// Number of maps currently in effect.
#[tauri::command]
pub async fn evtx_loaded_map_count(state: tauri::State<'_, AppState>) -> Result<u64, String> {
    Ok(state
        .event_maps
        .read()
        .map_err(|_| "map registry lock was poisoned".to_string())?
        .len() as u64)
}

/// Registers every provider database in `directory` for description rendering.
///
/// Returns a summary per database so an operator can see what coverage was actually gained rather
/// than assuming a directory full of files worked.
#[tauri::command]
pub async fn evtx_load_provider_databases(
    directory: String,
    state: tauri::State<'_, AppState>,
) -> Result<super::provider_db::ProviderDbLoadOutcome, String> {
    let path = std::path::PathBuf::from(&directory);
    let providers = state.provider_store.clone();
    tokio::task::spawn_blocking(
        move || -> Result<super::provider_db::ProviderDbLoadOutcome, String> {
            // Scanned into a fresh store first, then swapped, so the write lock is held for the
            // assignment rather than for the whole directory walk. Any parse in flight would
            // otherwise block on its read guard for as long as opening every database takes. Same
            // rule the map registry follows above.
            let mut loaded = super::provider_db::ProviderStore::default();
            let info = loaded.load_directory(&path)?;
            *providers
                .write()
                .map_err(|_| "provider store lock was poisoned".to_string())? = loaded;
            Ok(info)
        },
    )
    .await
    .map_err(|error| format!("provider database load task failed: {error}"))?
}

/// Provider databases currently registered.
#[tauri::command]
pub async fn evtx_provider_databases(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<super::provider_db::ProviderDbInfo>, String> {
    Ok(state
        .provider_store
        .read()
        .map_err(|_| "provider store lock was poisoned".to_string())?
        .registered())
}

/// Imports one provider database into the active renderer registry.
#[tauri::command]
pub async fn evtx_import_provider_database(
    path: String,
    state: tauri::State<'_, AppState>,
) -> Result<super::provider_db::ProviderDbLoadOutcome, String> {
    let path = std::path::PathBuf::from(path);
    let providers = state.provider_store.clone();
    tokio::task::spawn_blocking(move || {
        let mut loaded = super::provider_db::ProviderStore::default();
        let outcome = loaded.load_database(&path)?;
        *providers
            .write()
            .map_err(|_| "provider store lock was poisoned".to_string())? = loaded;
        Ok(outcome)
    })
    .await
    .map_err(|error| format!("provider database import task failed: {error}"))?
}

/// Exports a provider database without reconstructing or dropping canonical ProviderDetails
/// columns.
#[tauri::command]
pub async fn evtx_export_provider_database(
    source: String,
    destination: String,
) -> Result<super::provider_db::ProviderDbInfo, String> {
    let source = std::path::PathBuf::from(source);
    let destination = std::path::PathBuf::from(destination);
    tokio::task::spawn_blocking(move || {
        super::provider_db::export_provider_database(&source, &destination)
    })
    .await
    .map_err(|error| format!("provider database export task failed: {error}"))?
}

/// Loads a curated provider database bundled with the application.
///
/// When no real Windows capture has been checked in, the command reports that prerequisite instead
/// of fabricating a small database and making packaged coverage look complete.
#[tauri::command]
pub async fn evtx_load_packaged_provider_databases(
    app: AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<super::provider_db::ProviderDbLoadOutcome, String> {
    let resource_dir = app
        .path()
        .resource_dir()
        .map_err(|error| format!("cannot locate packaged resources: {error}"))?;
    let directory = super::provider_db::packaged_provider_directory(&resource_dir)?;
    let providers = state.provider_store.clone();
    tokio::task::spawn_blocking(move || {
        let mut loaded = super::provider_db::ProviderStore::default();
        let outcome = loaded.load_directory(&directory)?;
        *providers
            .write()
            .map_err(|_| "provider store lock was poisoned".to_string())? = loaded;
        Ok(outcome)
    })
    .await
    .map_err(|error| format!("packaged provider database load task failed: {error}"))?
}

/// Calls the provider-capture seam. The Windows traversal itself lives in the provider-capture
/// lane; this command stays a real IPC entry point in every build.
#[tauri::command]
pub async fn evtx_capture_provider_databases(
    db_path: String,
    _state: tauri::State<'_, AppState>,
) -> Result<(), super::capture::CaptureError> {
    let path = std::path::PathBuf::from(db_path);
    tokio::task::spawn_blocking(move || super::capture::capture_providers_to_db(&path))
        .await
        .map_err(|error| super::capture::CaptureError {
            kind: super::capture::CaptureErrorKind::Traversal,
            message: format!("provider capture task failed: {error}"),
            failures: Vec::new(),
        })?
}
/// Merges already-loaded log entries and event records into one chronological timeline.
///
/// Both sides arrive from the frontend rather than being re-read, so the timeline covers exactly
/// what the operator has open. Re-reading would risk building a timeline from a different set than
/// the one on screen.
#[tauri::command]
pub async fn evtx_build_unified_timeline(
    entries: Vec<cmtraceopen_parser::models::log_entry::LogEntry>,
    records: Vec<super::models::EvtxRecord>,
) -> Result<cmtraceopen_parser::unified_timeline::UnifiedTimeline, String> {
    let timeline = tokio::task::spawn_blocking(move || super::timeline::build(&entries, &records))
        .await
        .map_err(|error| format!("timeline build task failed: {error}"))?;
    log::info!(
        "event=unified_timeline items={} unplaced={}",
        timeline.items.len(),
        timeline.unplaced.len()
    );
    Ok(timeline)
}

#[cfg(test)]
mod tests {
    #[test]
    fn command_contract_rejects_placeholder_successes() {
        let source = include_str!("commands.rs");
        let forbidden = [
            ["Ok(", "vec![]", ")"].concat(),
            ["Ok(", "0", ")"].concat(),
            ["entries:", "vec![]"].concat(),
            ["records:", "Vec::new()"].concat(),
            ["channels:", "Vec::new()"].concat(),
            ["total_records:", "0"].concat(),
        ];

        for pattern in forbidden {
            assert!(
                !source.contains(pattern.as_str()),
                "event-log command surface contains placeholder success: {pattern}"
            );
        }
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn remote_enumeration_is_explicitly_unsupported_outside_windows() {
        let result = tauri::async_runtime::block_on(super::evtx_enumerate_remote_channels(
            "lab-host".to_string(),
        ));
        assert_eq!(
            result.expect_err("remote enumeration must be unsupported"),
            "Remote event log queries are only available on Windows."
        );
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn channel_clear_reports_structured_unsupported_result() {
        let result = tauri::async_runtime::block_on(super::evtx_clear_channel(
            "Application".to_string(),
            true,
        ))
        .expect("portable clear command should return a structured result");
        assert!(matches!(
            result.result,
            super::super::models::EvtxClearStatus::Unsupported { .. }
        ));
    }

    #[test]
    fn channel_clear_never_runs_without_confirmation() {
        let result = tauri::async_runtime::block_on(super::evtx_clear_channel(
            "Application".to_string(),
            false,
        ))
        .expect("cancelled clear should be a result, not an IPC failure");
        assert!(matches!(
            result.result,
            super::super::models::EvtxClearStatus::Cancelled
        ));
    }
}
