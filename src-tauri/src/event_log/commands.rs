#[cfg(not(target_os = "windows"))]
use super::models::EvtxLiveMode;
use super::models::{
    EvtxChannelInfo, EvtxClearResult, EvtxClearStatus, EvtxCoverageGap, EvtxCoverageGapKind,
    EvtxParseResult, EvtxTailStatus, MAX_SAFE_EVENT_RECORD_ID,
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

const MAX_QUERY_CHANNELS: usize = 256;
const MAX_QUERY_CHANNEL_NAME_CHARS: usize = 32_767;
const MAX_REQUEST_ID_CHARS: usize = 128;

// Diagnosis is a presentation boundary: keep enough input for useful analysis while making the
// amount of CPU and memory work independent of an arbitrarily large frontend payload.
const MAX_DIAGNOSIS_EVENT_RECORDS: usize = 25_000;
const MAX_DIAGNOSIS_ARCHIVE_TEXT_RECORDS: usize = 25_000;
const MAX_DIAGNOSIS_TEXT_ENTRIES: usize = 25_000;
const MAX_DIAGNOSIS_TIMELINE_EDGES: usize = 25_000;
const MAX_DIAGNOSIS_INPUT_TIMELINE_EDGES: usize = MAX_DIAGNOSIS_TIMELINE_EDGES * 2;
const MAX_DIAGNOSIS_INPUT_RECORDS: usize =
    MAX_DIAGNOSIS_EVENT_RECORDS + MAX_DIAGNOSIS_ARCHIVE_TEXT_RECORDS;
const MAX_DIAGNOSIS_INPUT_TEXT_ENTRIES: usize = MAX_DIAGNOSIS_TEXT_ENTRIES * 2;

fn validate_query_channels(channels: &[String]) -> Result<(), String> {
    if channels.is_empty() {
        return Err("at least one event log channel is required".to_string());
    }
    if channels.len() > MAX_QUERY_CHANNELS {
        return Err(format!(
            "event log queries support at most {MAX_QUERY_CHANNELS} channels"
        ));
    }
    for channel in channels {
        if channel.trim().is_empty() {
            return Err("event log channel names must not be empty".to_string());
        }
        if channel.chars().count() > MAX_QUERY_CHANNEL_NAME_CHARS {
            return Err(format!(
                "event log channel names must be at most {MAX_QUERY_CHANNEL_NAME_CHARS} characters"
            ));
        }
        if channel.chars().any(char::is_control) {
            return Err("event log channel names must not contain control characters".to_string());
        }
    }
    Ok(())
}
fn validate_request_id(request_id: &str) -> Result<(), String> {
    if request_id.trim().is_empty() {
        return Err("event log request IDs must not be empty".to_string());
    }
    if request_id.chars().count() > MAX_REQUEST_ID_CHARS {
        return Err(format!(
            "event log request IDs must be at most {MAX_REQUEST_ID_CHARS} characters"
        ));
    }
    if request_id.chars().any(char::is_control) {
        return Err("event log request IDs must not contain control characters".to_string());
    }
    Ok(())
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
    on_batch: impl FnMut(&mut Vec<super::models::EvtxRecord>) -> Result<(), String>,
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
    validate_query_channels(&channels)?;
    validate_request_id(&request_id)?;

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
                                return Ok(());
                            }
                            let records = std::mem::take(batch);
                            app_ref
                                .emit(
                                    "evtx-record-batch",
                                    EvtxRecordBatch {
                                        request_id: batch_request_id.clone(),
                                        channel: batch_channel.clone(),
                                        sequence,
                                        records,
                                    },
                                )
                                .map_err(|error| {
                                    format!(
                                        "event=evtx_batch_emit_failed channel=\"{batch_channel}\" \
                                         sequence={sequence} error=\"{error}\""
                                    )
                                })?;
                            sequence += 1;
                            Ok(())
                        },
                    );
                    let sequence_count = sequence;
                    let total_records = outcome.as_ref().map(|scan| scan.delivered).unwrap_or(0);
                    let terminal_emit = app_ref
                        .emit(
                            "evtx-record-stream-complete",
                            EvtxRecordStreamComplete {
                                channel: batch_channel.clone(),
                                request_id: batch_request_id.clone(),
                                sequence_count,
                                total_records,
                            },
                        )
                        .map_err(|error| {
                            format!(
                                "event=evtx_stream_complete_emit_failed channel=\"{batch_channel}\" \
                                 error=\"{error}\""
                            )
                        });
                    let outcome = match terminal_emit {
                        Ok(()) => outcome,
                        Err(terminal_error) => match outcome {
                            Ok(_) => Err(terminal_error),
                            Err(query_error) => {
                                Err(format!("{query_error}; {terminal_error}"))
                            }
                        },
                    };
                    (channel.clone(), outcome)
                })
                .collect();

            let mut all_records = Vec::new();
            let mut channel_infos = Vec::new();
            let mut parse_errors = 0u32;
            let mut error_messages = Vec::new();
            let mut coverage_gaps = Vec::new();
            let mut streamed = 0usize;

            for (channel, outcome) in per_channel {
                let coverage_source = remote_machine
                    .as_deref()
                    .map(|machine| format!("{machine}/{channel}"))
                    .unwrap_or_else(|| channel.clone());
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
                            error_messages.extend(scan.gaps.iter().cloned());
                            coverage_gaps.extend(scan.gaps.into_iter().map(|gap| {
                                let reason = gap
                                    .strip_prefix(&format!("{coverage_source}: "))
                                    .unwrap_or(&gap)
                                    .to_string();
                                EvtxCoverageGap::new(
                                    coverage_source.clone(),
                                    EvtxCoverageGapKind::Record,
                                    reason,
                                )
                            }));
                        }
                        all_records.extend(scan.records);
                    }
                    Err(error) => {
                        log::warn!(
                            "event=evtx_channel_query_error channel=\"{}\" error=\"{}\"",
                            channel,
                            error
                        );
                        error_messages.push(format!("{coverage_source}: {error}"));
                        coverage_gaps.push(EvtxCoverageGap::new(
                            coverage_source,
                            EvtxCoverageGapKind::File,
                            error,
                        ));
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
            let total_records = streamed as u64;
            Ok(EvtxParseResult {
                records: all_records,
                channels: channel_infos,
                total_records,
                parse_errors,
                error_messages,
                coverage_gaps,
                coverage: Vec::new(),
                archive_members: Vec::new(),
            })
        })
        .await
        .map_err(|error| format!("Task join error: {error}"))?
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
    validate_request_id(&request_id)?;

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
    validate_request_id(&request_id)?;

    #[cfg(target_os = "windows")]
    {
        let request_for_task = request_id.clone();
        let channel_for_task = channel.clone();
        tokio::task::spawn_blocking(move || {
            super::live::stop_channel_tail(&request_for_task, &channel_for_task)
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
    remote_machine: Option<String>,
) -> Result<EvtxClearResult, String> {
    if !confirmed {
        return Ok(EvtxClearResult {
            channel,
            result: EvtxClearStatus::Cancelled,
        });
    }
    #[cfg(target_os = "windows")]
    {
        let remote_machine = remote_machine
            .as_deref()
            .map(super::live::normalize_remote_machine_name)
            .transpose()?;
        Ok(tokio::task::spawn_blocking(move || {
            super::live::clear_channel(&channel, confirmed, remote_machine.as_deref())
        })
        .await
        .map_err(|error| format!("Task join error: {error}"))?)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = remote_machine;
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
    let mut protected_sources = source_paths;
    protected_sources.extend(records.iter().map(|record| record.source_label.clone()));
    super::writer::reject_source_destination(&protected_sources, Some(&destination_path))?;
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
    tokio::task::spawn_blocking(move || -> Result<_, String> {
        let (_, identities) = validate_diagnosis_inputs(&records, &[], &entries)?;
        let timeline = build_canonical_diagnosis_timeline(&entries, &records, &identities);
        if timeline.items.len().saturating_add(timeline.unplaced.len())
            > MAX_DIAGNOSIS_TIMELINE_ITEMS
        {
            return Err(format!(
                "timeline items exceed the {MAX_DIAGNOSIS_TIMELINE_ITEMS}-item diagnosis limit"
            ));
        }
        if timeline.edges.len() > MAX_DIAGNOSIS_INPUT_TIMELINE_EDGES {
            return Err(format!(
                "timeline edges exceed the {MAX_DIAGNOSIS_INPUT_TIMELINE_EDGES}-item input limit"
            ));
        }
        log::info!(
            "event=unified_timeline items={} unplaced={}",
            timeline.items.len(),
            timeline.unplaced.len()
        );
        Ok(timeline)
    })
    .await
    .map_err(|error| format!("timeline build task failed: {error}"))?
}
const MAX_DIAGNOSIS_RAW_XML_BYTES: usize = 256 * 1024;
const MAX_DIAGNOSIS_STRING_BYTES: usize = 256 * 1024;
const MAX_DIAGNOSIS_EVENT_DATA_FIELDS: usize = 4_096;
const MAX_DIAGNOSIS_EVENT_DATA_BYTES: usize = 4 * 1024 * 1024;
const MAX_DIAGNOSIS_NESTED_ITEMS: usize = 4_096;
const MAX_DIAGNOSIS_TIMELINE_ITEMS: usize = 50_000;
const MAX_DIAGNOSIS_TOTAL_INPUT_BYTES: usize = 64 * 1024 * 1024;

fn bounded_diagnosis_string(
    value: &str,
    label: &str,
    max_bytes: usize,
    total_bytes: &mut usize,
) -> Result<(), String> {
    if value.len() > max_bytes {
        return Err(format!(
            "{label} exceeds the {max_bytes}-byte diagnosis limit"
        ));
    }
    *total_bytes = total_bytes.saturating_add(value.len());
    if *total_bytes > MAX_DIAGNOSIS_TOTAL_INPUT_BYTES {
        return Err(format!(
            "diagnosis input exceeds the {MAX_DIAGNOSIS_TOTAL_INPUT_BYTES}-byte limit"
        ));
    }
    Ok(())
}

#[derive(Debug, Clone)]
enum DiagnosisRecordIdentity {
    Valid { id: u64, text: Option<String> },
    Malformed { detail: String },
}

fn diagnosis_record_identity(record: &super::models::EvtxRecord) -> DiagnosisRecordIdentity {
    match record.event_record_id_text.as_deref() {
        Some(value) if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) => {
            DiagnosisRecordIdentity::Malformed {
                detail: "EventRecordID text must be a non-empty decimal value".to_string(),
            }
        }
        Some(value) => match value.parse::<u64>() {
            Ok(parsed)
                if record.event_record_id <= MAX_SAFE_EVENT_RECORD_ID
                    && parsed != record.event_record_id =>
            {
                DiagnosisRecordIdentity::Malformed {
                    detail: "EventRecordID text conflicts with the numeric identity".to_string(),
                }
            }
            Ok(parsed) => DiagnosisRecordIdentity::Valid {
                id: parsed,
                text: Some(value.to_string()),
            },
            Err(_) => DiagnosisRecordIdentity::Malformed {
                detail: "EventRecordID text is outside the u64 range".to_string(),
            },
        },
        None if record.event_record_id > MAX_SAFE_EVENT_RECORD_ID => {
            DiagnosisRecordIdentity::Malformed {
                detail:
                    "EventRecordID exceeds JavaScript safe integer precision without exact text"
                        .to_string(),
            }
        }
        None => DiagnosisRecordIdentity::Valid {
            id: record.event_record_id,
            text: None,
        },
    }
}

fn diagnosis_identity_finding(detail: String) -> cmtraceopen_parser::diagnosis::DiagnosisFinding {
    cmtraceopen_parser::diagnosis::finding_for_coverage(
        "event-record-identity",
        cmtraceopen_parser::diagnosis::CoverageState::Malformed,
        detail,
    )
}

fn validate_diagnosis_record(
    record: &super::models::EvtxRecord,
    total_bytes: &mut usize,
) -> Result<DiagnosisRecordIdentity, String> {
    if let Some(value) = record.event_record_id_text.as_deref() {
        bounded_diagnosis_string(value, "EventRecordID text", 32, total_bytes)?;
    }
    let identity = diagnosis_record_identity(record);
    for (label, value) in [
        ("timestamp", record.timestamp.as_str()),
        ("provider", record.provider.as_str()),
        ("channel", record.channel.as_str()),
        ("computer", record.computer.as_str()),
        ("message", record.message.as_str()),
        ("sourceLabel", record.source_label.as_str()),
        (
            "activityId",
            record.activity_id.as_deref().unwrap_or_default(),
        ),
        (
            "relatedActivityId",
            record.related_activity_id.as_deref().unwrap_or_default(),
        ),
        (
            "sessionId",
            record.session_id.as_deref().unwrap_or_default(),
        ),
        ("deviceId", record.device_id.as_deref().unwrap_or_default()),
        ("userId", record.user_id.as_deref().unwrap_or_default()),
        (
            "processStartTime",
            record.process_start_time.as_deref().unwrap_or_default(),
        ),
        ("userSid", record.user_sid.as_deref().unwrap_or_default()),
        ("keywords", record.keywords.as_deref().unwrap_or_default()),
    ] {
        bounded_diagnosis_string(value, label, MAX_DIAGNOSIS_STRING_BYTES, total_bytes)?;
    }
    bounded_diagnosis_string(
        &record.raw_xml,
        "rawXml",
        MAX_DIAGNOSIS_RAW_XML_BYTES,
        total_bytes,
    )?;
    if record.event_data.len() > MAX_DIAGNOSIS_EVENT_DATA_FIELDS {
        return Err(format!(
            "eventData exceeds the {MAX_DIAGNOSIS_EVENT_DATA_FIELDS}-field diagnosis limit"
        ));
    }
    let mut event_data_bytes = 0usize;
    for field in &record.event_data {
        bounded_diagnosis_string(
            &field.name,
            "eventData field name",
            MAX_DIAGNOSIS_STRING_BYTES,
            &mut event_data_bytes,
        )?;
        bounded_diagnosis_string(
            &field.value,
            "eventData field value",
            MAX_DIAGNOSIS_STRING_BYTES,
            &mut event_data_bytes,
        )?;
    }
    if event_data_bytes > MAX_DIAGNOSIS_EVENT_DATA_BYTES {
        return Err(format!(
            "eventData exceeds the {MAX_DIAGNOSIS_EVENT_DATA_BYTES}-byte diagnosis limit"
        ));
    }
    *total_bytes = total_bytes.saturating_add(event_data_bytes);
    if *total_bytes > MAX_DIAGNOSIS_TOTAL_INPUT_BYTES {
        return Err(format!(
            "diagnosis input exceeds the {MAX_DIAGNOSIS_TOTAL_INPUT_BYTES}-byte limit"
        ));
    }
    if record.mapped.len() > MAX_DIAGNOSIS_NESTED_ITEMS {
        return Err(format!(
            "mapped columns exceed the {MAX_DIAGNOSIS_NESTED_ITEMS}-item diagnosis limit"
        ));
    }
    for mapped in &record.mapped {
        bounded_diagnosis_string(
            &mapped.property,
            "mapped property",
            MAX_DIAGNOSIS_STRING_BYTES,
            total_bytes,
        )?;
        bounded_diagnosis_string(
            &mapped.text,
            "mapped text",
            MAX_DIAGNOSIS_STRING_BYTES,
            total_bytes,
        )?;
    }
    Ok(identity)
}
fn validate_diagnosis_log_entry(
    entry: &cmtraceopen_parser::models::log_entry::LogEntry,
    total_bytes: &mut usize,
) -> Result<(), String> {
    if entry.id > MAX_SAFE_EVENT_RECORD_ID {
        return Err(
            "log entry ID exceeds JavaScript safe integer precision without exact text".to_string(),
        );
    }
    for (label, value) in [
        ("log message", entry.message.as_str()),
        ("log filePath", entry.file_path.as_str()),
        (
            "log component",
            entry.component.as_deref().unwrap_or_default(),
        ),
        (
            "log timestampDisplay",
            entry.timestamp_display.as_deref().unwrap_or_default(),
        ),
        (
            "log threadDisplay",
            entry.thread_display.as_deref().unwrap_or_default(),
        ),
        (
            "log sourceFile",
            entry.source_file.as_deref().unwrap_or_default(),
        ),
        (
            "log ipAddress",
            entry.ip_address.as_deref().unwrap_or_default(),
        ),
        (
            "log hostName",
            entry.host_name.as_deref().unwrap_or_default(),
        ),
        (
            "log macAddress",
            entry.mac_address.as_deref().unwrap_or_default(),
        ),
        (
            "log resultCode",
            entry.result_code.as_deref().unwrap_or_default(),
        ),
        ("log gleCode", entry.gle_code.as_deref().unwrap_or_default()),
        (
            "log setupPhase",
            entry.setup_phase.as_deref().unwrap_or_default(),
        ),
        (
            "log operationName",
            entry.operation_name.as_deref().unwrap_or_default(),
        ),
        (
            "log httpMethod",
            entry.http_method.as_deref().unwrap_or_default(),
        ),
        ("log uriStem", entry.uri_stem.as_deref().unwrap_or_default()),
        (
            "log uriQuery",
            entry.uri_query.as_deref().unwrap_or_default(),
        ),
        (
            "log clientIp",
            entry.client_ip.as_deref().unwrap_or_default(),
        ),
        (
            "log serverIp",
            entry.server_ip.as_deref().unwrap_or_default(),
        ),
        (
            "log userAgent",
            entry.user_agent.as_deref().unwrap_or_default(),
        ),
        (
            "log username",
            entry.username.as_deref().unwrap_or_default(),
        ),
        (
            "log queryName",
            entry.query_name.as_deref().unwrap_or_default(),
        ),
        (
            "log queryType",
            entry.query_type.as_deref().unwrap_or_default(),
        ),
        (
            "log responseCode",
            entry.response_code.as_deref().unwrap_or_default(),
        ),
        (
            "log dnsDirection",
            entry.dns_direction.as_deref().unwrap_or_default(),
        ),
        (
            "log dnsProtocol",
            entry.dns_protocol.as_deref().unwrap_or_default(),
        ),
        (
            "log sourceIp",
            entry.source_ip.as_deref().unwrap_or_default(),
        ),
        (
            "log dnsFlags",
            entry.dns_flags.as_deref().unwrap_or_default(),
        ),
        (
            "log zoneName",
            entry.zone_name.as_deref().unwrap_or_default(),
        ),
        (
            "log sectionName",
            entry.section_name.as_deref().unwrap_or_default(),
        ),
        (
            "log sectionColor",
            entry.section_color.as_deref().unwrap_or_default(),
        ),
        (
            "log iteration",
            entry.iteration.as_deref().unwrap_or_default(),
        ),
    ] {
        bounded_diagnosis_string(value, label, MAX_DIAGNOSIS_STRING_BYTES, total_bytes)?;
    }
    if entry.error_code_spans.len() > MAX_DIAGNOSIS_NESTED_ITEMS {
        return Err(format!(
            "log errorCodeSpans exceed the {MAX_DIAGNOSIS_NESTED_ITEMS}-item diagnosis limit"
        ));
    }
    for span in &entry.error_code_spans {
        for (label, value) in [
            ("log error code hex", &span.code_hex),
            ("log error code decimal", &span.code_decimal),
            ("log error description", &span.description),
            ("log error category", &span.category),
        ] {
            bounded_diagnosis_string(value, label, MAX_DIAGNOSIS_STRING_BYTES, total_bytes)?;
        }
    }
    if let Some(tags) = &entry.tags {
        if tags.len() > MAX_DIAGNOSIS_NESTED_ITEMS {
            return Err(format!(
                "log tags exceed the {MAX_DIAGNOSIS_NESTED_ITEMS}-item diagnosis limit"
            ));
        }
        for tag in tags {
            bounded_diagnosis_string(tag, "log tag", MAX_DIAGNOSIS_STRING_BYTES, total_bytes)?;
        }
    }
    Ok(())
}

fn diagnosis_timeline_edge_key(
    edge: &cmtraceopen_parser::unified_timeline::TimelineCorrelationEdge,
) -> Result<String, String> {
    serde_json::to_string(&(
        &edge.from_id,
        &edge.to_id,
        &edge.key,
        &edge.strength,
        &edge.confidence,
        &edge.candidate_ids,
        &edge.evidence,
        &edge.coverage,
    ))
    .map_err(|error| format!("failed to serialize timeline edge for validation: {error}"))
}
fn validate_diagnosis_timeline(
    timeline: &cmtraceopen_parser::unified_timeline::UnifiedTimeline,
    canonical_timeline: &cmtraceopen_parser::unified_timeline::UnifiedTimeline,
    total_bytes: &mut usize,
) -> Result<(), String> {
    let canonical_edge_keys = canonical_timeline
        .edges
        .iter()
        .map(diagnosis_timeline_edge_key)
        .collect::<Result<std::collections::HashSet<_>, _>>()?;
    let mut canonical_coverage_gaps = canonical_timeline
        .coverage_gaps
        .iter()
        .map(|gap| (gap.source.as_str(), gap.reason.as_str()))
        .collect::<Vec<_>>();
    canonical_coverage_gaps.sort_unstable();
    let canonical_ids = canonical_timeline
        .items
        .iter()
        .map(|item| cmtraceopen_parser::unified_timeline::origin_id(&item.origin))
        .chain(
            canonical_timeline
                .unplaced
                .iter()
                .map(|item| cmtraceopen_parser::unified_timeline::origin_id(&item.origin)),
        )
        .collect::<std::collections::HashSet<_>>();
    let supplied_ids = timeline
        .items
        .iter()
        .map(|item| cmtraceopen_parser::unified_timeline::origin_id(&item.origin))
        .chain(
            timeline
                .unplaced
                .iter()
                .map(|item| cmtraceopen_parser::unified_timeline::origin_id(&item.origin)),
        )
        .collect::<std::collections::HashSet<_>>();
    if supplied_ids != canonical_ids {
        return Err("timeline origins do not match canonical diagnosis input".to_string());
    }
    if timeline.items.len() + timeline.unplaced.len() > MAX_DIAGNOSIS_TIMELINE_ITEMS {
        return Err(format!(
            "timeline items exceed the {MAX_DIAGNOSIS_TIMELINE_ITEMS}-item diagnosis limit"
        ));
    }
    if timeline.edges.len() > MAX_DIAGNOSIS_INPUT_TIMELINE_EDGES {
        return Err(format!(
            "timeline edges exceed the {MAX_DIAGNOSIS_INPUT_TIMELINE_EDGES}-item input limit"
        ));
    }
    if timeline.coverage_gaps.len() > MAX_DIAGNOSIS_NESTED_ITEMS {
        return Err(format!(
            "timeline coverage gaps exceed the {MAX_DIAGNOSIS_NESTED_ITEMS}-item diagnosis limit"
        ));
    }
    let mut supplied_coverage_gaps = timeline
        .coverage_gaps
        .iter()
        .map(|gap| (gap.source.as_str(), gap.reason.as_str()))
        .collect::<Vec<_>>();
    supplied_coverage_gaps.sort_unstable();
    if supplied_coverage_gaps != canonical_coverage_gaps {
        return Err("timeline coverage gaps do not match canonical correlation".to_string());
    }
    for item in &timeline.items {
        bounded_diagnosis_string(
            &item.message,
            "timeline message",
            MAX_DIAGNOSIS_STRING_BYTES,
            total_bytes,
        )?;
    }
    for gap in &timeline.coverage_gaps {
        bounded_diagnosis_string(
            &gap.source,
            "timeline coverage source",
            MAX_DIAGNOSIS_STRING_BYTES,
            total_bytes,
        )?;
        bounded_diagnosis_string(
            &gap.reason,
            "timeline coverage reason",
            MAX_DIAGNOSIS_STRING_BYTES,
            total_bytes,
        )?;
    }
    for item in timeline
        .items
        .iter()
        .map(|item| &item.origin)
        .chain(timeline.unplaced.iter().map(|item| &item.origin))
    {
        let origin_id = cmtraceopen_parser::unified_timeline::origin_id(item);
        bounded_diagnosis_string(
            &origin_id,
            "timeline origin",
            MAX_DIAGNOSIS_STRING_BYTES,
            total_bytes,
        )?;
        match item {
            cmtraceopen_parser::unified_timeline::TimelineOrigin::Log {
                file,
                component,
                source,
                machine,
                bundle,
                ..
            } => {
                for (label, value) in [
                    ("timeline log file", file.as_str()),
                    ("timeline log source", source.as_str()),
                    (
                        "timeline log component",
                        component.as_deref().unwrap_or_default(),
                    ),
                    (
                        "timeline log machine",
                        machine.as_deref().unwrap_or_default(),
                    ),
                    ("timeline log bundle", bundle.as_deref().unwrap_or_default()),
                ] {
                    bounded_diagnosis_string(
                        value,
                        label,
                        MAX_DIAGNOSIS_STRING_BYTES,
                        total_bytes,
                    )?;
                }
            }
            cmtraceopen_parser::unified_timeline::TimelineOrigin::Event {
                stable_id,
                source,
                machine,
                bundle,
                channel,
                provider,
                activity_id,
                related_activity_id,
                session_id,
                device_id,
                user_id,
                process_start_time,
                identity_conflicts,
                record_id,
                record_id_text,
                ..
            } => {
                if *record_id > MAX_SAFE_EVENT_RECORD_ID && record_id_text.is_none() {
                    return Err(
                        "timeline event ID exceeds JavaScript safe integer precision without exact text"
                            .to_string(),
                    );
                }
                if let Some(value) = record_id_text {
                    let parsed = value
                        .parse::<u64>()
                        .map_err(|_| "timeline event recordIdText must be decimal".to_string())?;
                    if *record_id <= MAX_SAFE_EVENT_RECORD_ID && parsed != *record_id {
                        return Err(
                            "timeline event recordIdText conflicts with numeric identity"
                                .to_string(),
                        );
                    }
                }
                for (label, value) in [
                    ("timeline event stableId", stable_id.as_str()),
                    ("timeline event source", source.as_str()),
                    (
                        "timeline event machine",
                        machine.as_deref().unwrap_or_default(),
                    ),
                    (
                        "timeline event bundle",
                        bundle.as_deref().unwrap_or_default(),
                    ),
                    ("timeline event channel", channel.as_str()),
                    ("timeline event provider", provider.as_str()),
                    (
                        "timeline event activityId",
                        activity_id.as_deref().unwrap_or_default(),
                    ),
                    (
                        "timeline event relatedActivityId",
                        related_activity_id.as_deref().unwrap_or_default(),
                    ),
                    (
                        "timeline event sessionId",
                        session_id.as_deref().unwrap_or_default(),
                    ),
                    (
                        "timeline event deviceId",
                        device_id.as_deref().unwrap_or_default(),
                    ),
                    (
                        "timeline event userId",
                        user_id.as_deref().unwrap_or_default(),
                    ),
                    (
                        "timeline event processStartTime",
                        process_start_time.as_deref().unwrap_or_default(),
                    ),
                    (
                        "timeline event recordIdText",
                        record_id_text.as_deref().unwrap_or_default(),
                    ),
                ] {
                    bounded_diagnosis_string(
                        value,
                        label,
                        MAX_DIAGNOSIS_STRING_BYTES,
                        total_bytes,
                    )?;
                }
                if identity_conflicts.len() > MAX_DIAGNOSIS_NESTED_ITEMS {
                    return Err(format!(
                        "timeline identity conflicts exceed the {MAX_DIAGNOSIS_NESTED_ITEMS}-item diagnosis limit"
                    ));
                }
                for conflict in identity_conflicts {
                    bounded_diagnosis_string(
                        conflict,
                        "timeline identity conflict",
                        MAX_DIAGNOSIS_STRING_BYTES,
                        total_bytes,
                    )?;
                }
            }
            _ => return Err("unsupported timeline origin".to_string()),
        }
    }
    for edge in &timeline.edges {
        if !canonical_ids.contains(&edge.from_id)
            || edge
                .to_id
                .as_ref()
                .is_some_and(|id| !canonical_ids.contains(id))
            || edge
                .candidate_ids
                .iter()
                .any(|id| !canonical_ids.contains(id))
            || edge
                .evidence
                .iter()
                .any(|evidence| !canonical_ids.contains(&evidence.origin_id))
        {
            return Err("timeline edge references an unrelated diagnosis identity".to_string());
        }
        if edge.candidate_ids.len() > MAX_DIAGNOSIS_NESTED_ITEMS
            || edge.evidence.len() > MAX_DIAGNOSIS_NESTED_ITEMS
        {
            return Err(format!(
                "timeline edge nested payload exceeds the {MAX_DIAGNOSIS_NESTED_ITEMS}-item diagnosis limit"
            ));
        }
        for (label, value) in [
            ("timeline edge id", &edge.id),
            ("timeline edge fromId", &edge.from_id),
            ("timeline edge key", &edge.key.value),
        ] {
            bounded_diagnosis_string(value, label, MAX_DIAGNOSIS_STRING_BYTES, total_bytes)?;
        }
        if let Some(value) = &edge.to_id {
            bounded_diagnosis_string(
                value,
                "timeline edge toId",
                MAX_DIAGNOSIS_STRING_BYTES,
                total_bytes,
            )?;
        }
        for value in &edge.candidate_ids {
            bounded_diagnosis_string(
                value,
                "timeline edge candidate",
                MAX_DIAGNOSIS_STRING_BYTES,
                total_bytes,
            )?;
        }
        for evidence in &edge.evidence {
            for (label, value) in [
                ("timeline evidence origin", &evidence.origin_id),
                ("timeline evidence field", &evidence.field),
                ("timeline evidence value", &evidence.value),
            ] {
                bounded_diagnosis_string(value, label, MAX_DIAGNOSIS_STRING_BYTES, total_bytes)?;
            }
        }
        if let Some(gap) = &edge.coverage.gap {
            for (label, value) in [
                ("timeline edge coverage source", &gap.source),
                ("timeline edge coverage reason", &gap.reason),
            ] {
                bounded_diagnosis_string(value, label, MAX_DIAGNOSIS_STRING_BYTES, total_bytes)?;
            }
        }
        let edge_key = diagnosis_timeline_edge_key(edge)?;
        if !canonical_edge_keys.contains(&edge_key) {
            return Err("timeline edge does not match canonical correlation".to_string());
        }
    }
    Ok(())
}

fn validate_diagnosis_inputs(
    records: &[super::models::EvtxRecord],
    coverage_gaps: &[EvtxCoverageGap],
    text_entries: &[cmtraceopen_parser::models::log_entry::LogEntry],
) -> Result<(usize, Vec<DiagnosisRecordIdentity>), String> {
    if records.len() > MAX_DIAGNOSIS_INPUT_RECORDS {
        return Err(format!(
            "diagnosis records exceed the {MAX_DIAGNOSIS_INPUT_RECORDS}-item input limit"
        ));
    }
    if text_entries.len() > MAX_DIAGNOSIS_INPUT_TEXT_ENTRIES {
        return Err(format!(
            "diagnosis text entries exceed the {MAX_DIAGNOSIS_INPUT_TEXT_ENTRIES}-item input limit"
        ));
    }
    let mut total_bytes = 0usize;
    let mut identities = Vec::with_capacity(records.len());
    for record in records {
        identities.push(validate_diagnosis_record(record, &mut total_bytes)?);
    }
    if coverage_gaps.len() > MAX_DIAGNOSIS_NESTED_ITEMS {
        return Err(format!(
            "diagnosis coverage gaps exceed the {MAX_DIAGNOSIS_NESTED_ITEMS}-item limit"
        ));
    }
    for gap in coverage_gaps {
        if gap
            .event_record_id
            .is_some_and(|value| value > MAX_SAFE_EVENT_RECORD_ID)
        {
            return Err(
                "coverage event ID exceeds JavaScript safe integer precision without exact text"
                    .to_string(),
            );
        }
        if gap.source.trim().is_empty() {
            return Err("coverage source must not be empty".to_string());
        }
        if gap.reason.trim().is_empty() {
            return Err("coverage reason must not be empty".to_string());
        }
        bounded_diagnosis_string(
            &gap.source,
            "coverage source",
            MAX_DIAGNOSIS_STRING_BYTES,
            &mut total_bytes,
        )?;
        bounded_diagnosis_string(
            &gap.reason,
            "coverage reason",
            MAX_DIAGNOSIS_STRING_BYTES,
            &mut total_bytes,
        )?;
    }
    for entry in text_entries {
        validate_diagnosis_log_entry(entry, &mut total_bytes)?;
    }
    Ok((total_bytes, identities))
}

fn build_canonical_diagnosis_timeline(
    entries: &[cmtraceopen_parser::models::log_entry::LogEntry],
    records: &[super::models::EvtxRecord],
    identities: &[DiagnosisRecordIdentity],
) -> cmtraceopen_parser::unified_timeline::UnifiedTimeline {
    let valid_records = records
        .iter()
        .zip(identities)
        .filter_map(|(record, identity)| {
            let malformed_event =
                matches!(record.origin_kind, super::models::EvtxOriginKind::Event)
                    && matches!(identity, DiagnosisRecordIdentity::Malformed { .. });
            (!malformed_event).then_some(record.clone())
        })
        .collect::<Vec<_>>();
    let mut timeline = super::timeline::build(entries, &valid_records);
    timeline
        .coverage_gaps
        .extend(
            records
                .iter()
                .zip(identities)
                .filter_map(|(record, identity)| {
                    if !matches!(record.origin_kind, super::models::EvtxOriginKind::Event) {
                        return None;
                    }
                    let DiagnosisRecordIdentity::Malformed { detail } = identity else {
                        return None;
                    };
                    Some(cmtraceopen_parser::unified_timeline::TimelineCoverageGap {
                        source: "event-record-identity".to_string(),
                        reason: detail.clone(),
                    })
                }),
        );
    timeline
}

/// Produces portable operational diagnosis for the records currently visible in the event viewer.
#[tauri::command]
pub async fn evtx_diagnose_records(
    records: Vec<super::models::EvtxRecord>,
    coverage_gaps: Option<Vec<EvtxCoverageGap>>,
    timeline: Option<cmtraceopen_parser::unified_timeline::UnifiedTimeline>,
    text_entries: Option<Vec<cmtraceopen_parser::models::log_entry::LogEntry>>,
) -> Result<cmtraceopen_parser::diagnosis::DiagnosisSummary, String> {
    tokio::task::spawn_blocking(move || -> Result<_, String> {
        let (validated_total_bytes, identities) = validate_diagnosis_inputs(
            &records,
            coverage_gaps.as_deref().unwrap_or(&[]),
            text_entries.as_deref().unwrap_or(&[]),
        )?;
        let mut total_bytes = validated_total_bytes;
        let canonical_timeline = build_canonical_diagnosis_timeline(
            text_entries.as_deref().unwrap_or(&[]),
            &records,
            &identities,
        );
        if let Some(value) = timeline.as_ref() {
            validate_diagnosis_timeline(value, &canonical_timeline, &mut total_bytes)?;
        }
        let mut text_findings = Vec::new();
        let mut events = Vec::with_capacity(records.len().min(MAX_DIAGNOSIS_EVENT_RECORDS));
        let mut identity_findings = Vec::new();
        let mut omitted_event_records = 0usize;
        let mut omitted_archive_text_records = 0usize;
        let mut event_count = 0usize;
        let mut archive_text_count = 0usize;

        for (record_index, record) in records.into_iter().enumerate() {
            match record.origin_kind {
                super::models::EvtxOriginKind::Event => {
                    if event_count >= MAX_DIAGNOSIS_EVENT_RECORDS {
                        omitted_event_records += 1;
                        continue;
                    }
                    event_count += 1;
                    let (event_record_id, event_record_id_text) = match &identities[record_index] {
                        DiagnosisRecordIdentity::Valid { id, text } => (*id, text.clone()),
                        DiagnosisRecordIdentity::Malformed { detail } => {
                            identity_findings.push(diagnosis_identity_finding(detail.clone()));
                            continue;
                        }
                    };
                    let severity = match record.level {
                        super::models::EvtxLevel::Critical => {
                            cmtraceopen_parser::intune::models::EventLogSeverity::Critical
                        }
                        super::models::EvtxLevel::Error => {
                            cmtraceopen_parser::intune::models::EventLogSeverity::Error
                        }
                        super::models::EvtxLevel::Warning => {
                            cmtraceopen_parser::intune::models::EventLogSeverity::Warning
                        }
                        super::models::EvtxLevel::Information => {
                            cmtraceopen_parser::intune::models::EventLogSeverity::Information
                        }
                        super::models::EvtxLevel::Verbose => {
                            cmtraceopen_parser::intune::models::EventLogSeverity::Verbose
                        }
                    };
                    let raw_xml = record.raw_xml;
                    let event_data = record
                        .event_data
                        .into_iter()
                        .map(|field| format!("{}={}", field.name, field.value))
                        .collect::<Vec<_>>();
                    let entry = cmtraceopen_parser::intune::models::EventLogEntry {
                        id: event_record_id,
                        channel:
                            cmtraceopen_parser::intune::models::EventLogChannel::from_channel_string(
                                &record.channel,
                            ),
                        channel_display: record.channel.clone(),
                        provider: record.provider,
                        event_id: record.event_id,
                        severity,
                        timestamp: record.timestamp,
                        computer: Some(record.computer),
                        message: record.message,
                        correlation_activity_id: record.activity_id,
                        source_file: record.source_label,
                    };
                    let mut diagnosis =
                        cmtraceopen_parser::diagnosis::adapt_event_entry_with_data_and_raw_xml(
                            entry,
                            &event_data,
                            &raw_xml,
                        );
                    if let Some(cmtraceopen_parser::diagnosis::EvidenceRef::Event(evidence)) =
                        diagnosis.evidence.first_mut()
                    {
                        evidence.record_id_text =
                            event_record_id_text.or_else(|| evidence.record_id_text.clone());
                    }
                    events.push(diagnosis);
                }
                super::models::EvtxOriginKind::Log => {
                    if archive_text_count >= MAX_DIAGNOSIS_ARCHIVE_TEXT_RECORDS {
                        omitted_archive_text_records += 1;
                        continue;
                    }
                    archive_text_count += 1;
                    if let Some(finding) =
                        cmtraceopen_parser::diagnosis::adapt_log_entry(evtx_log_entry(record))
                    {
                        text_findings.push(finding);
                    }
                }
            }
        }

        let mut omitted_text_entries = 0usize;
        if let Some(entries) = text_entries {
            for (index, entry) in entries.into_iter().enumerate() {
                if index >= MAX_DIAGNOSIS_TEXT_ENTRIES {
                    omitted_text_entries += 1;
                    continue;
                }
                if let Some(finding) = cmtraceopen_parser::diagnosis::adapt_log_entry(entry) {
                    text_findings.push(finding);
                }
            }
        }

        let omitted_timeline_edges = canonical_timeline
            .edges
            .len()
            .saturating_sub(MAX_DIAGNOSIS_TIMELINE_EDGES);
        let correlations = canonical_timeline
            .edges
            .iter()
            .take(MAX_DIAGNOSIS_TIMELINE_EDGES)
            .map(cmtraceopen_parser::diagnosis::adapt_timeline_edge)
            .collect::<Vec<_>>();

        let mut coverage_findings: Vec<cmtraceopen_parser::diagnosis::DiagnosisFinding> =
            coverage_gaps
                .unwrap_or_default()
                .into_iter()
                .map(|gap| {
                    let detail = match (gap.chunk_id, gap.event_record_id) {
                        (Some(chunk_id), Some(event_record_id)) => {
                            format!(
                                "{} (chunk {chunk_id}, event record {event_record_id})",
                                gap.reason
                            )
                        }
                        (Some(chunk_id), None) => {
                            format!("{} (chunk {chunk_id})", gap.reason)
                        }
                        (None, Some(event_record_id)) => {
                            format!("{} (event record {event_record_id})", gap.reason)
                        }
                        (None, None) => gap.reason,
                    };
                    cmtraceopen_parser::diagnosis::finding_for_coverage(
                        gap.source,
                        diagnosis_coverage_state(gap.kind),
                        detail,
                    )
                })
                .collect();
        coverage_findings.extend(identity_findings);
        coverage_findings.extend(canonical_timeline.coverage_gaps.iter().map(|gap| {
            cmtraceopen_parser::diagnosis::finding_for_coverage(
                format!("timeline:{}", gap.source),
                timeline_coverage_state(&gap.reason),
                gap.reason.clone(),
            )
        }));
        append_diagnosis_cap_finding(
            &mut coverage_findings,
            "event-records",
            omitted_event_records,
            MAX_DIAGNOSIS_EVENT_RECORDS,
            "event records",
        );
        append_diagnosis_cap_finding(
            &mut coverage_findings,
            "archive-text-records",
            omitted_archive_text_records,
            MAX_DIAGNOSIS_ARCHIVE_TEXT_RECORDS,
            "archive text records",
        );
        append_diagnosis_cap_finding(
            &mut coverage_findings,
            "text-entries",
            omitted_text_entries,
            MAX_DIAGNOSIS_TEXT_ENTRIES,
            "supplied text entries",
        );
        append_diagnosis_cap_finding(
            &mut coverage_findings,
            "timeline-correlation-edges",
            omitted_timeline_edges,
            MAX_DIAGNOSIS_TIMELINE_EDGES,
            "timeline correlation edges",
        );
        text_findings.extend(coverage_findings);
        let summary = cmtraceopen_parser::diagnosis::summarize_cross_source(
            events,
            text_findings,
            correlations,
        );
        Ok(cmtraceopen_parser::diagnosis::redacted_display_projection(
            summary,
        ))
    })
    .await
    .map_err(|error| format!("diagnosis task failed: {error}"))?
}

fn evtx_log_entry(
    record: super::models::EvtxRecord,
) -> cmtraceopen_parser::models::log_entry::LogEntry {
    let event_record_id = record
        .event_record_id_text
        .as_deref()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(record.event_record_id);
    let line_number = u32::try_from(event_record_id).unwrap_or(u32::MAX);
    cmtraceopen_parser::models::log_entry::LogEntry {
        id: event_record_id,
        line_number,
        message: record.message,
        component: Some(record.provider),
        timestamp: Some(record.timestamp_epoch),
        timestamp_display: Some(record.timestamp),
        severity: match record.level {
            super::models::EvtxLevel::Critical | super::models::EvtxLevel::Error => {
                cmtraceopen_parser::models::log_entry::Severity::Error
            }
            super::models::EvtxLevel::Warning => {
                cmtraceopen_parser::models::log_entry::Severity::Warning
            }
            super::models::EvtxLevel::Information | super::models::EvtxLevel::Verbose => {
                cmtraceopen_parser::models::log_entry::Severity::Info
            }
        },
        thread: record.thread_id,
        source_file: Some(record.source_label.clone()),
        file_path: record.source_label,
        ..Default::default()
    }
}

fn append_diagnosis_cap_finding(
    findings: &mut Vec<cmtraceopen_parser::diagnosis::DiagnosisFinding>,
    source: &str,
    omitted: usize,
    cap: usize,
    item_kind: &str,
) {
    if omitted > 0 {
        findings.push(cmtraceopen_parser::diagnosis::finding_for_coverage(
            source,
            cmtraceopen_parser::diagnosis::CoverageState::Capped,
            format!("{omitted} {item_kind} omitted after the diagnosis cap of {cap}."),
        ));
    }
}

fn timeline_coverage_state(reason: &str) -> cmtraceopen_parser::diagnosis::CoverageState {
    match cmtraceopen_parser::unified_timeline::coverage_state(reason) {
        cmtraceopen_parser::unified_timeline::TimelineCoverageState::Skipped => {
            cmtraceopen_parser::diagnosis::CoverageState::Skipped
        }
        cmtraceopen_parser::unified_timeline::TimelineCoverageState::Absent => {
            cmtraceopen_parser::diagnosis::CoverageState::Absent
        }
        cmtraceopen_parser::unified_timeline::TimelineCoverageState::Malformed => {
            cmtraceopen_parser::diagnosis::CoverageState::Malformed
        }
        cmtraceopen_parser::unified_timeline::TimelineCoverageState::Capped => {
            cmtraceopen_parser::diagnosis::CoverageState::Capped
        }
        cmtraceopen_parser::unified_timeline::TimelineCoverageState::Unsupported => {
            cmtraceopen_parser::diagnosis::CoverageState::Unsupported
        }
        cmtraceopen_parser::unified_timeline::TimelineCoverageState::Unknown => {
            cmtraceopen_parser::diagnosis::CoverageState::Unknown
        }
        _ => cmtraceopen_parser::diagnosis::CoverageState::Unknown,
    }
}

fn diagnosis_coverage_state(
    kind: EvtxCoverageGapKind,
) -> cmtraceopen_parser::diagnosis::CoverageState {
    match kind {
        EvtxCoverageGapKind::Unsupported => {
            cmtraceopen_parser::diagnosis::CoverageState::Unsupported
        }
        EvtxCoverageGapKind::AccessDenied => {
            cmtraceopen_parser::diagnosis::CoverageState::AccessDenied
        }
        EvtxCoverageGapKind::Missing | EvtxCoverageGapKind::Empty => {
            cmtraceopen_parser::diagnosis::CoverageState::Absent
        }
        EvtxCoverageGapKind::LimitReached | EvtxCoverageGapKind::Limit => {
            cmtraceopen_parser::diagnosis::CoverageState::Capped
        }
        EvtxCoverageGapKind::InvalidPattern => {
            cmtraceopen_parser::diagnosis::CoverageState::Malformed
        }
        EvtxCoverageGapKind::File
        | EvtxCoverageGapKind::Chunk
        | EvtxCoverageGapKind::Record
        | EvtxCoverageGapKind::Xml
        | EvtxCoverageGapKind::Provider => {
            cmtraceopen_parser::diagnosis::CoverageState::ParseFailed
        }
    }
}

#[cfg(test)]
mod tests {
    fn diagnosis_record(
        origin_kind: super::super::models::EvtxOriginKind,
        message: &str,
    ) -> super::super::models::EvtxRecord {
        super::super::models::EvtxRecord {
            id: 1,
            event_record_id: 1,
            event_record_id_text: Some("1".into()),
            timestamp: "2026-08-18T12:00:00Z".into(),
            timestamp_epoch: 1_755_523_200_000,
            provider: "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider".into(),
            channel: "Application".into(),
            event_id: 75,
            level: super::super::models::EvtxLevel::Information,
            computer: "WIN-TEST".into(),
            message: message.into(),
            event_data: Vec::new(),
            raw_xml: String::new(),
            source_label: "Application.evtx".into(),
            origin_kind,
            task: None,
            opcode: None,
            process_id: None,
            activity_id: None,
            related_activity_id: None,
            session_id: None,
            device_id: None,
            user_id: None,
            process_start_time: None,
            thread_id: None,
            user_sid: None,
            keywords: None,
            mapped: Vec::new(),
        }
    }

    #[test]
    fn unified_timeline_rejects_oversized_record_payloads() {
        let mut record = diagnosis_record(
            super::super::models::EvtxOriginKind::Event,
            "Enrollment failed",
        );
        record.raw_xml = "x".repeat(super::MAX_DIAGNOSIS_RAW_XML_BYTES + 1);

        let result = tauri::async_runtime::block_on(super::evtx_build_unified_timeline(
            Vec::new(),
            vec![record],
        ));

        assert!(
            result
                .expect_err("oversized timeline input must be rejected")
                .contains("rawXml"),
            "timeline rejection should identify the oversized field"
        );
    }
    #[test]
    fn export_rejects_record_source_when_source_paths_are_omitted() {
        let source = std::env::temp_dir().join(format!(
            "cmtraceopen-event-export-source-{}.evtx",
            std::process::id()
        ));
        let mut record = diagnosis_record(
            super::super::models::EvtxOriginKind::Event,
            "Enrollment failed",
        );
        record.source_label = source.to_string_lossy().into_owned();

        let error = tauri::async_runtime::block_on(super::evtx_export_records(
            vec![record],
            super::super::export::ExportFormat::Csv,
            source.to_string_lossy().into_owned(),
            Vec::new(),
        ))
        .expect_err("record source must remain protected even without source_paths");

        assert!(error.contains("cannot overwrite"));
    }
    #[test]
    fn diagnosis_reports_omitted_text_entries_after_output_cap() {
        let text_entries = vec![
            cmtraceopen_parser::models::log_entry::LogEntry::default();
            super::MAX_DIAGNOSIS_TEXT_ENTRIES + 1
        ];

        let summary = tauri::async_runtime::block_on(super::evtx_diagnose_records(
            Vec::new(),
            None,
            None,
            Some(text_entries),
        ))
        .expect("input below the diagnosis input limit must be accepted");

        let cap_gap = summary
            .coverage_gaps
            .iter()
            .find(|gap| gap.source == "text-entries")
            .expect("text entry truncation must remain visible as a coverage gap");
        assert!(cap_gap.detail.contains("1 supplied text entries omitted"));
    }

    #[test]
    fn diagnosis_rejects_text_entries_above_input_limit() {
        let text_entries = vec![
            cmtraceopen_parser::models::log_entry::LogEntry::default();
            super::MAX_DIAGNOSIS_INPUT_TEXT_ENTRIES + 1
        ];

        let error = tauri::async_runtime::block_on(super::evtx_diagnose_records(
            Vec::new(),
            None,
            None,
            Some(text_entries),
        ))
        .expect_err("text entries above the input limit must be rejected");

        assert!(error.contains("text entries exceed"));
    }

    #[test]
    fn diagnosis_rejects_oversized_coverage_payloads() {
        let coverage = (0..=super::MAX_DIAGNOSIS_NESTED_ITEMS)
            .map(|index| {
                super::super::models::EvtxCoverageGap::new(
                    format!("source-{index}"),
                    super::super::models::EvtxCoverageGapKind::Record,
                    "coverage gap",
                )
            })
            .collect();

        let error = tauri::async_runtime::block_on(super::evtx_diagnose_records(
            Vec::new(),
            Some(coverage),
            None,
            None,
        ))
        .expect_err("oversized diagnosis coverage input must be rejected");

        assert!(error.contains("coverage gaps"));
    }

    #[test]
    fn diagnosis_keeps_event_records_separate_and_admits_archive_text() {
        let summary = tauri::async_runtime::block_on(super::evtx_diagnose_records(
            vec![
                diagnosis_record(
                    super::super::models::EvtxOriginKind::Event,
                    "Enrollment failed",
                ),
                diagnosis_record(
                    super::super::models::EvtxOriginKind::Log,
                    "Enrollment failed",
                ),
            ],
            None,
            None,
            None,
        ))
        .expect("diagnosis should succeed");
        assert_eq!(summary.events.len(), 1);
        assert!(summary.findings.iter().any(|finding| {
            finding.evidence.iter().any(|evidence| {
                matches!(
                    evidence,
                    cmtraceopen_parser::diagnosis::EvidenceRef::TextLog(value)
                        if value.source == "Application.evtx"
                            && value.line_number == 1
                            && value.entry_id == 1
                )
            })
        }));
    }

    #[test]
    fn diagnosis_command_returns_redacted_display_strings() {
        let mut record = diagnosis_record(
            super::super::models::EvtxOriginKind::Event,
            "Enrollment failed for jane.doe@example.invalid PASSWORD=hunter2",
        );
        record.computer = "DESKTOP-JANE".into();
        record.source_label = r"C:\Users\Jane Doe\AppData\Local\event.evtx".into();
        record.event_data = vec![super::super::models::EvtxField {
            name: "Password".into(),
            value: "hunter2".into(),
        }];

        let summary = tauri::async_runtime::block_on(super::evtx_diagnose_records(
            vec![record],
            None,
            None,
            None,
        ))
        .expect("diagnosis should succeed");
        let serialized = serde_json::to_string(&summary).expect("diagnosis serializes");

        assert!(
            !serialized.contains("jane.doe@example.invalid"),
            "{serialized}"
        );
        assert!(!serialized.contains("Jane Doe"), "{serialized}");
        assert!(!serialized.contains("DESKTOP-JANE"), "{serialized}");
        assert!(!serialized.contains("hunter2"), "{serialized}");
        assert!(serialized.contains("Enrollment failed"), "{serialized}");
    }

    #[test]
    fn diagnosis_uses_lossless_event_record_text_for_finding_identity() {
        let mut first = diagnosis_record(
            super::super::models::EvtxOriginKind::Event,
            "Enrollment failed",
        );
        first.event_record_id = 9_007_199_254_740_993;
        first.event_record_id_text = Some("9007199254740993".into());
        let mut second = first.clone();
        second.event_record_id = 9_007_199_254_740_994;
        second.event_record_id_text = Some("9007199254740994".into());

        let summary = tauri::async_runtime::block_on(super::evtx_diagnose_records(
            vec![first, second],
            None,
            None,
            None,
        ))
        .expect("diagnosis should succeed");

        assert_eq!(summary.events.len(), 2);
        let first_evidence = &summary.events[0].evidence[0];
        let second_evidence = &summary.events[1].evidence[0];
        assert_ne!(first_evidence.stable_id(), second_evidence.stable_id());
        assert!(matches!(
            first_evidence,
            cmtraceopen_parser::diagnosis::EvidenceRef::Event(value)
                if value.record_id_text.as_deref() == Some("9007199254740993")
        ));
        assert!(matches!(
            second_evidence,
            cmtraceopen_parser::diagnosis::EvidenceRef::Event(value)
                if value.record_id_text.as_deref() == Some("9007199254740994")
        ));
        assert_eq!(summary.findings.len(), 2);
        assert_ne!(
            summary.findings[0].finding_id,
            summary.findings[1].finding_id
        );
    }

    #[test]
    fn diagnosis_surfaces_unsafe_numeric_event_id_as_coverage() {
        let mut record = diagnosis_record(
            super::super::models::EvtxOriginKind::Event,
            "Enrollment failed",
        );
        record.event_record_id = 9_007_199_254_740_992;
        record.event_record_id_text = None;

        let summary = tauri::async_runtime::block_on(super::evtx_diagnose_records(
            vec![record],
            None,
            None,
            None,
        ))
        .expect("unsafe identity should become coverage");

        assert!(summary.events.is_empty());
        assert!(summary.coverage_gaps.iter().any(|gap| {
            gap.state == cmtraceopen_parser::diagnosis::CoverageState::Malformed
                && gap.detail.contains("EventRecordID")
        }));
    }

    #[test]
    fn diagnosis_surfaces_conflicting_and_non_decimal_record_id_text_as_coverage() {
        for (numeric_id, text_id) in [(41_u64, "42"), (41_u64, "not-a-decimal")] {
            let mut record = diagnosis_record(
                super::super::models::EvtxOriginKind::Event,
                "Enrollment failed",
            );
            record.event_record_id = numeric_id;
            record.event_record_id_text = Some(text_id.to_string());

            let summary = tauri::async_runtime::block_on(super::evtx_diagnose_records(
                vec![record],
                None,
                None,
                None,
            ))
            .expect("malformed identity should become coverage");

            assert!(summary.events.is_empty());
            assert!(summary.coverage_gaps.iter().any(|gap| {
                gap.state == cmtraceopen_parser::diagnosis::CoverageState::Malformed
                    && gap.detail.contains("EventRecordID")
            }));
        }
    }

    #[test]
    fn diagnosis_surfaces_raw_xml_errors_and_malformed_identity_as_coverage() {
        let mut malformed = diagnosis_record(
            super::super::models::EvtxOriginKind::Event,
            "Enrollment event",
        );
        malformed.event_record_id = 9_007_199_254_740_992;
        malformed.event_record_id_text = Some("not-a-decimal".into());
        let mut valid = diagnosis_record(
            super::super::models::EvtxOriginKind::Event,
            "Enrollment event",
        );
        valid.event_record_id = 7;
        valid.event_record_id_text = Some("7".into());
        valid.raw_xml =
            r#"<Event><EventData><Data Name="HRESULT">0x80070005</Data></EventData></Event>"#
                .into();

        let summary = tauri::async_runtime::block_on(super::evtx_diagnose_records(
            vec![malformed, valid],
            None,
            None,
            None,
        ))
        .expect("malformed identity must remain visible as a coverage result");

        assert_eq!(summary.events.len(), 1);
        assert!(summary.coverage_gaps.iter().any(|gap| {
            gap.state == cmtraceopen_parser::diagnosis::CoverageState::Malformed
                && gap.detail.contains("EventRecordID")
        }));
        assert!(summary.events[0]
            .error_tokens
            .iter()
            .any(|token| token.raw.eq_ignore_ascii_case("0x80070005")));
    }

    #[test]
    fn diagnosis_rejects_timeline_without_current_record_origins() {
        let result = tauri::async_runtime::block_on(super::evtx_diagnose_records(
            vec![diagnosis_record(
                super::super::models::EvtxOriginKind::Event,
                "Enrollment failed",
            )],
            None,
            Some(cmtraceopen_parser::unified_timeline::UnifiedTimeline {
                items: Vec::new(),
                unplaced: Vec::new(),
                edges: Vec::new(),
                coverage_gaps: Vec::new(),
            }),
            None,
        ));

        assert!(
            result
                .expect_err("a stale empty timeline must be rejected")
                .contains("timeline origins"),
            "stale timeline rejection should identify the origin mismatch"
        );
    }

    #[test]
    fn diagnosis_rejects_timeline_edges_with_unknown_endpoints() {
        let timeline = cmtraceopen_parser::unified_timeline::UnifiedTimeline {
            items: Vec::new(),
            unplaced: Vec::new(),
            edges: vec![
                cmtraceopen_parser::unified_timeline::TimelineCorrelationEdge {
                    id: "edge-1".into(),
                    from_id: "missing-left".into(),
                    to_id: Some("missing-right".into()),
                    key: cmtraceopen_parser::unified_timeline::TimelineCorrelationKey {
                        kind: cmtraceopen_parser::unified_timeline::TimelineCorrelationKeyKind::ActivityId,
                        value: "activity-1".into(),
                    },
                    strength:
                        cmtraceopen_parser::unified_timeline::TimelineCorrelationStrength::Exact,
                    confidence:
                        cmtraceopen_parser::unified_timeline::TimelineCorrelationConfidence::High,
                    candidate_ids: Vec::new(),
                    evidence: Vec::new(),
                    coverage:
                        cmtraceopen_parser::unified_timeline::TimelineCorrelationCoverage {
                            state: cmtraceopen_parser::unified_timeline::TimelineCorrelationCoverageState::Covered,
                            gap: None,
                        },
                },
            ],
            coverage_gaps: Vec::new(),
        };

        let result = tauri::async_runtime::block_on(super::evtx_diagnose_records(
            Vec::new(),
            None,
            Some(timeline),
            None,
        ));

        assert!(
            result.is_err(),
            "timeline edges must not cross diagnosis IPC with unknown endpoints"
        );
    }

    #[test]
    fn diagnosis_accepts_coalesced_duplicate_origin_references() {
        let mut first = diagnosis_record(
            super::super::models::EvtxOriginKind::Event,
            "first duplicate",
        );
        first.activity_id = Some("activity-1".into());
        let mut second = first.clone();
        second.message = "second duplicate".into();
        let mut counterpart =
            diagnosis_record(super::super::models::EvtxOriginKind::Event, "counterpart");
        counterpart.id = 2;
        counterpart.event_record_id = 2;
        counterpart.event_record_id_text = Some("2".into());
        counterpart.related_activity_id = Some("activity-1".into());

        let timeline = super::super::timeline::build(&[], &[first, second, counterpart]);
        assert!(
            timeline.edges.iter().any(|edge| {
                edge.from_id.contains("record1")
                    && edge
                        .to_id
                        .as_deref()
                        .is_some_and(|id| id.contains("record2"))
            }),
            "duplicate origin must still correlate through its canonical base ID"
        );
        let mut total_bytes = 0;
        super::validate_diagnosis_timeline(&timeline, &timeline, &mut total_bytes)
            .expect("coalesced duplicate references must satisfy diagnosis validation");
        assert!(timeline
            .edges
            .iter()
            .flat_map(|edge| {
                std::iter::once(&edge.from_id)
                    .chain(edge.to_id.as_ref())
                    .chain(edge.candidate_ids.iter())
                    .chain(edge.evidence.iter().map(|evidence| &evidence.origin_id))
            })
            .all(|id| !id.contains("#occurrence-")));
        assert!(timeline
            .coverage_gaps
            .iter()
            .all(|gap| !gap.source.contains("#occurrence-")));
    }

    #[test]
    fn diagnosis_rejects_timeline_coverage_gap_not_in_canonical_timeline() {
        let timeline = cmtraceopen_parser::unified_timeline::UnifiedTimeline {
            items: Vec::new(),
            unplaced: Vec::new(),
            edges: Vec::new(),
            coverage_gaps: vec![cmtraceopen_parser::unified_timeline::TimelineCoverageGap {
                source: "forged-source".into(),
                reason: "forged reason".into(),
            }],
        };

        let result = tauri::async_runtime::block_on(super::evtx_diagnose_records(
            Vec::new(),
            None,
            Some(timeline),
            None,
        ));

        assert!(result
            .expect_err("forged timeline coverage must be rejected")
            .contains("timeline coverage gaps"));
    }

    #[test]
    fn diagnosis_accepts_frontend_timeline_with_malformed_event_identity_gap() {
        let mut malformed = diagnosis_record(
            super::super::models::EvtxOriginKind::Event,
            "Malformed identity",
        );
        malformed.event_record_id_text = Some("not-a-number".into());
        let mut valid = diagnosis_record(
            super::super::models::EvtxOriginKind::Event,
            "Enrollment failed",
        );
        valid.id = 2;
        valid.event_record_id = 2;
        valid.event_record_id_text = Some("2".into());
        let records = vec![malformed, valid];
        let timeline = tauri::async_runtime::block_on(super::evtx_build_unified_timeline(
            Vec::new(),
            records.clone(),
        ))
        .expect("frontend timeline should preserve malformed identity coverage");

        let summary = tauri::async_runtime::block_on(super::evtx_diagnose_records(
            records,
            None,
            Some(timeline),
            None,
        ))
        .expect("diagnosis should accept its own malformed identity coverage");
        assert!(summary
            .coverage_gaps
            .iter()
            .any(|gap| gap.source == "event-record-identity"));
    }
    #[test]
    fn diagnosis_rejects_timeline_missing_malformed_event_identity_gap() {
        let mut malformed = diagnosis_record(
            super::super::models::EvtxOriginKind::Event,
            "Malformed identity",
        );
        malformed.event_record_id_text = Some("not-a-number".into());
        let records = vec![malformed];
        let mut timeline = tauri::async_runtime::block_on(super::evtx_build_unified_timeline(
            Vec::new(),
            records.clone(),
        ))
        .expect("frontend timeline should preserve malformed identity coverage");
        assert!(timeline
            .coverage_gaps
            .iter()
            .any(|gap| gap.source == "event-record-identity"));
        timeline.coverage_gaps.clear();

        let error = tauri::async_runtime::block_on(super::evtx_diagnose_records(
            records,
            None,
            Some(timeline),
            None,
        ))
        .expect_err("a timeline missing identity coverage must be rejected");
        assert!(error.contains("timeline coverage gaps"));
    }

    #[test]
    fn diagnosis_reports_capped_inputs_as_coverage() {
        let mut records = Vec::with_capacity(super::MAX_DIAGNOSIS_EVENT_RECORDS + 1);
        for _ in 0..=super::MAX_DIAGNOSIS_EVENT_RECORDS {
            records.push(diagnosis_record(
                super::super::models::EvtxOriginKind::Event,
                "Enrollment failed",
            ));
        }

        let summary =
            tauri::async_runtime::block_on(super::evtx_diagnose_records(records, None, None, None))
                .expect("diagnosis should succeed");

        assert!(summary.coverage_gaps.iter().any(|gap| {
            gap.source == "event-records"
                && gap.state == cmtraceopen_parser::diagnosis::CoverageState::Capped
                && gap.detail.contains("1 event records omitted")
        }));
    }

    #[test]
    fn diagnosis_uses_canonical_timeline_for_stale_edge_subsets() {
        let mut first = diagnosis_record(
            super::super::models::EvtxOriginKind::Event,
            "Enrollment started",
        );
        first.event_record_id = 1;
        first.event_record_id_text = Some("1".into());
        first.activity_id = Some("{activity}".into());
        let mut second = diagnosis_record(
            super::super::models::EvtxOriginKind::Event,
            "Enrollment failed",
        );
        second.event_record_id = 2;
        second.event_record_id_text = Some("2".into());
        second.activity_id = Some("{activity}".into());
        let records = vec![first, second];
        let canonical = super::super::timeline::build(&[], &records);
        assert_eq!(canonical.edges.len(), 1);

        let stale_timeline = cmtraceopen_parser::unified_timeline::UnifiedTimeline {
            items: canonical.items.clone(),
            unplaced: canonical.unplaced.clone(),
            edges: Vec::new(),
            coverage_gaps: canonical.coverage_gaps.clone(),
        };
        let summary = tauri::async_runtime::block_on(super::evtx_diagnose_records(
            records,
            None,
            Some(stale_timeline),
            None,
        ))
        .expect("diagnosis should use the canonical timeline");

        assert_eq!(summary.correlations.len(), 1);
    }

    #[test]
    fn diagnosis_classifies_correlation_budget_gaps_as_capped() {
        assert_eq!(
            super::timeline_coverage_state("correlation relation budget of 25000 was reached"),
            cmtraceopen_parser::diagnosis::CoverageState::Capped
        );
    }
    #[test]
    fn diagnosis_rejects_empty_and_whitespace_coverage_identity_fields() {
        for (source, reason, field) in [
            ("", "missing reason", "source"),
            ("   ", "missing reason", "source"),
            ("\t\n", "missing reason", "source"),
            ("source", "", "reason"),
            ("source", "   ", "reason"),
            ("source", "\r\t", "reason"),
        ] {
            let gap = super::super::models::EvtxCoverageGap::new(
                source,
                super::super::models::EvtxCoverageGapKind::Missing,
                reason,
            );
            let error = super::validate_diagnosis_inputs(&[], &[gap], &[])
                .expect_err("blank coverage identity fields must be rejected");
            assert!(
                error.contains(field),
                "validation error should identify the blank {field}: {error}"
            );
        }
    }

    #[test]
    fn diagnosis_classifies_timeline_coverage_reasons() {
        let cases = [
            (
                "conflicting explicit identity aliases for activityId",
                cmtraceopen_parser::diagnosis::CoverageState::Skipped,
            ),
            (
                "process start identity was present but its timestamp was invalid",
                cmtraceopen_parser::diagnosis::CoverageState::Malformed,
            ),
            (
                "process start identity was unavailable for a nonzero process id",
                cmtraceopen_parser::diagnosis::CoverageState::Absent,
            ),
            (
                "process start identity requires a nonzero process id",
                cmtraceopen_parser::diagnosis::CoverageState::Absent,
            ),
            (
                "multiple exact identity candidates remain: event-2, event-3",
                cmtraceopen_parser::diagnosis::CoverageState::Skipped,
            ),
            (
                "no explicit identity keys were present; timestamp-only correlation is not causal",
                cmtraceopen_parser::diagnosis::CoverageState::Skipped,
            ),
            (
                "only secondary identity was present; correlation remains low confidence",
                cmtraceopen_parser::diagnosis::CoverageState::Skipped,
            ),
            (
                "machine identity unavailable; exact correlation is restricted",
                cmtraceopen_parser::diagnosis::CoverageState::Absent,
            ),
            (
                "exact activityid identity group exceeds the 256-member correlation limit",
                cmtraceopen_parser::diagnosis::CoverageState::Capped,
            ),
            (
                "secondary process identity group exceeds the 256-member correlation limit",
                cmtraceopen_parser::diagnosis::CoverageState::Capped,
            ),
            (
                "correlation relation budget of 25000 was reached",
                cmtraceopen_parser::diagnosis::CoverageState::Capped,
            ),
            (
                "unrecognized correlation note",
                cmtraceopen_parser::diagnosis::CoverageState::Unsupported,
            ),
        ];

        for (reason, expected) in cases {
            assert_eq!(super::timeline_coverage_state(reason), expected, "{reason}");
        }
    }

    #[test]
    fn diagnosis_timeline_coverage_precedence_prefers_conflicts() {
        assert_eq!(
            super::timeline_coverage_state(
                "conflicting explicit identity aliases for invalid processStartTime"
            ),
            cmtraceopen_parser::diagnosis::CoverageState::Skipped
        );
    }

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
    fn remote_channel_clear_reports_structured_unsupported_result() {
        let result = tauri::async_runtime::block_on(super::evtx_clear_channel(
            "Application".to_string(),
            true,
            Some("remote-host".to_string()),
        ))
        .expect("portable clear command should return a structured result");
        assert_eq!(result.channel, "Application");
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
            Some("remote-host".to_string()),
        ))
        .expect("cancelled clear should be a result, not an IPC failure");
        assert!(matches!(
            result.result,
            super::super::models::EvtxClearStatus::Cancelled
        ));
    }

    #[test]
    fn query_boundary_rejects_empty_or_controlled_channels() {
        let empty = vec!["   ".to_string()];
        assert!(super::validate_query_channels(&empty)
            .expect_err("blank channel names must be rejected")
            .contains("must not be empty"));

        let controlled = vec!["Application\n".to_string()];
        assert!(super::validate_query_channels(&controlled)
            .expect_err("control characters must be rejected")
            .contains("control characters"));
    }

    #[test]
    fn query_boundary_rejects_excessive_channel_fanout() {
        let channels = (0..=super::MAX_QUERY_CHANNELS)
            .map(|index| format!("Channel-{index}"))
            .collect::<Vec<_>>();
        assert!(super::validate_query_channels(&channels)
            .expect_err("excessive channel fanout must be rejected")
            .contains("at most"));
    }
    #[test]
    fn request_boundary_rejects_unbounded_request_ids() {
        assert!(super::validate_request_id("")
            .expect_err("empty request IDs must be rejected")
            .contains("must not be empty"));
        assert!(super::validate_request_id("request\nid")
            .expect_err("control characters must be rejected")
            .contains("control characters"));
        let oversized = "r".repeat(super::MAX_REQUEST_ID_CHARS + 1);
        assert!(super::validate_request_id(&oversized)
            .expect_err("oversized request IDs must be rejected")
            .contains("at most"));
    }
}
