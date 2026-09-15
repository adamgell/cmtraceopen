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
pub(crate) const MAX_DIAGNOSIS_EVENT_RECORDS: usize = 25_000;
pub(crate) const MAX_DIAGNOSIS_ARCHIVE_TEXT_RECORDS: usize = 25_000;
pub(crate) const MAX_DIAGNOSIS_TEXT_ENTRIES: usize = 25_000;
pub(crate) const MAX_DIAGNOSIS_TIMELINE_EDGES: usize = 25_000;

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

#[cfg(any(target_os = "windows", test))]
#[derive(Default)]
struct QueryAggregation {
    records: Vec<super::models::EvtxRecord>,
    parse_errors: u32,
    error_messages: Vec<String>,
    coverage_gaps: Vec<EvtxCoverageGap>,
}

#[cfg(any(target_os = "windows", test))]
impl QueryAggregation {
    fn absorb_scan(&mut self, coverage_source: &str, scan: super::live::ChannelScan) {
        self.parse_errors = self.parse_errors.saturating_add(scan.gaps.len() as u32);
        self.error_messages.extend(scan.gaps.iter().cloned());
        self.coverage_gaps.extend(scan.gaps.into_iter().map(|gap| {
            let reason = gap
                .strip_prefix(&format!("{coverage_source}: "))
                .unwrap_or(&gap)
                .to_string();
            EvtxCoverageGap::new(
                coverage_source.to_string(),
                EvtxCoverageGapKind::Record,
                reason,
            )
        }));
        self.error_messages.extend(
            scan.provider_gaps
                .iter()
                .map(super::live::format_provider_gap),
        );
        self.coverage_gaps.extend(scan.provider_gaps);
        self.records.extend(scan.records);
    }
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
#[allow(clippy::too_many_arguments)]
fn query_source_channel(
    remote_machine: Option<&str>,
    channel: &str,
    filter: &cmtraceopen_parser::event_query::EventQueryFilter,
    maps: &cmtraceopen_parser::eventmap::MapRegistry,
    providers: &std::sync::RwLock<super::provider_db::ProviderStore>,
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
            providers,
            max_events,
            on_progress,
            on_batch,
        ),
        None => super::live::query_channel_streamed(
            channel,
            filter,
            maps,
            providers,
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
        let providers = state.provider_store.clone();
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
                        &providers,
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

            let mut aggregation = QueryAggregation::default();
            let mut channel_infos = Vec::new();
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
                        aggregation.absorb_scan(&coverage_source, scan);
                    }
                    Err(error) => {
                        log::warn!(
                            "event=evtx_channel_query_error channel=\"{}\" error=\"{}\"",
                            channel,
                            error
                        );
                        aggregation
                            .error_messages
                            .push(format!("{coverage_source}: {error}"));
                        aggregation.coverage_gaps.push(EvtxCoverageGap::new(
                            coverage_source,
                            EvtxCoverageGapKind::File,
                            error,
                        ));
                        channel_infos.push(EvtxChannelInfo {
                            name: channel,
                            event_count: 0,
                            source_type: source_type.clone(),
                        });
                        aggregation.parse_errors = aggregation.parse_errors.saturating_add(1);
                    }
                }
            }

            aggregation
                .records
                .sort_by_key(|record| record.timestamp_epoch);
            let total_records = streamed as u64;
            Ok(EvtxParseResult {
                records: aggregation.records,
                channels: channel_infos,
                total_records,
                parse_errors: aggregation.parse_errors,
                error_messages: aggregation.error_messages,
                coverage_gaps: aggregation.coverage_gaps,
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
        let providers = state.provider_store.clone();
        let query_filter = filter.unwrap_or_default();
        tokio::task::spawn_blocking(move || {
            super::live::start_channel_tail(
                app,
                request_id,
                channel,
                query_filter,
                maps,
                providers,
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
        let result = tokio::task::spawn_blocking(move || {
            super::live::clear_channel(&channel, confirmed, remote_machine.as_deref())
        })
        .await
        .map_err(|error| format!("Task join error: {error}"))?;
        Ok(result)
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
const MAX_DIAGNOSIS_RAW_XML_BYTES: usize = 256 * 1024;
const MAX_DIAGNOSIS_STRING_BYTES: usize = 256 * 1024;
const MAX_DIAGNOSIS_EVENT_DATA_FIELDS: usize = 4_096;
const MAX_DIAGNOSIS_EVENT_DATA_BYTES: usize = 4 * 1024 * 1024;
const MAX_DIAGNOSIS_NESTED_ITEMS: usize = 4_096;
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
pub(crate) enum DiagnosisRecordIdentity {
    Valid { id: u64, text: Option<String> },
    Malformed { detail: String },
}

pub(crate) fn diagnosis_record_identity(
    record: &super::models::EvtxRecord,
) -> DiagnosisRecordIdentity {
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

pub(crate) fn diagnosis_identity_finding(
    detail: String,
) -> cmtraceopen_parser::diagnosis::DiagnosisFinding {
    cmtraceopen_parser::diagnosis::finding_for_coverage(
        "event-record-identity",
        cmtraceopen_parser::diagnosis::CoverageState::Malformed,
        detail,
    )
}

pub(crate) fn validate_diagnosis_record(
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
pub(crate) fn validate_diagnosis_log_entry(
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

pub(crate) fn validate_diagnosis_coverage_gaps(
    coverage_gaps: &[EvtxCoverageGap],
) -> Result<(), String> {
    if coverage_gaps.len() > MAX_DIAGNOSIS_NESTED_ITEMS {
        return Err(format!(
            "diagnosis coverage gaps exceed the {MAX_DIAGNOSIS_NESTED_ITEMS}-item limit"
        ));
    }
    let mut total_bytes = 0usize;
    for gap in coverage_gaps {
        let exact_event_record_id = if let Some(value) = gap.event_record_id_text.as_deref() {
            bounded_diagnosis_string(value, "coverage event ID text", 20, &mut total_bytes)?;
            let parsed = value.parse::<u64>().map_err(|_| {
                "coverage event ID text must be a canonical unsigned decimal value".to_string()
            })?;
            if parsed.to_string() != value {
                return Err(
                    "coverage event ID text must be a canonical unsigned decimal value".to_string(),
                );
            }
            if gap
                .event_record_id
                .is_some_and(|numeric| numeric <= MAX_SAFE_EVENT_RECORD_ID && numeric != parsed)
            {
                return Err(
                    "coverage event ID text conflicts with the numeric identity".to_string()
                );
            }
            Some(parsed)
        } else {
            None
        };
        if exact_event_record_id.is_none()
            && gap
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
        if let Some(provider_message) = gap.provider_message.as_deref() {
            bounded_diagnosis_string(
                &provider_message.provider,
                "coverage provider",
                MAX_DIAGNOSIS_STRING_BYTES,
                &mut total_bytes,
            )?;
        }
    }
    Ok(())
}

/// Normalized diagnosis input extracted from one validated native event record.
pub(crate) struct DiagnosisEventInput {
    pub(crate) entry: cmtraceopen_parser::intune::models::EventLogEntry,
    pub(crate) event_data: Vec<String>,
    pub(crate) raw_xml: String,
    pub(crate) record_id_text: Option<String>,
}

/// Consumes one validated native event record into parser-owned incremental diagnosis input.
pub(crate) fn diagnosis_event_input(
    record: super::models::EvtxRecord,
    identity: &DiagnosisRecordIdentity,
) -> Result<DiagnosisEventInput, Box<cmtraceopen_parser::diagnosis::DiagnosisFinding>> {
    let (event_record_id, event_record_id_text) = match identity {
        DiagnosisRecordIdentity::Valid { id, text } => (*id, text.clone()),
        DiagnosisRecordIdentity::Malformed { detail } => {
            return Err(Box::new(diagnosis_identity_finding(detail.clone())));
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
    let channel =
        cmtraceopen_parser::intune::models::EventLogChannel::from_channel_string(&record.channel);
    let entry = cmtraceopen_parser::intune::models::EventLogEntry {
        id: event_record_id,
        channel,
        channel_display: record.channel,
        provider: record.provider,
        event_id: record.event_id,
        severity,
        timestamp: record.timestamp,
        computer: Some(record.computer),
        message: record.message,
        correlation_activity_id: record.activity_id,
        source_file: record.source_label,
    };
    let relevant = !matches!(
        cmtraceopen_parser::diagnosis::event_family(&entry),
        cmtraceopen_parser::diagnosis::EventFamily::Other
    );
    let event_data = if relevant {
        record
            .event_data
            .into_iter()
            .map(|field| format!("{}={}", field.name, field.value))
            .collect()
    } else {
        Vec::new()
    };
    let raw_xml = if relevant {
        record.raw_xml
    } else {
        String::new()
    };
    Ok(DiagnosisEventInput {
        entry,
        event_data,
        raw_xml,
        record_id_text: event_record_id_text,
    })
}

pub(crate) fn diagnosis_finding_for_gap(
    gap: EvtxCoverageGap,
) -> cmtraceopen_parser::diagnosis::DiagnosisFinding {
    let event_record_id = gap
        .event_record_id_text
        .clone()
        .or_else(|| gap.event_record_id.map(|value| value.to_string()));
    let detail = match (gap.chunk_id, event_record_id) {
        (Some(chunk_id), Some(event_record_id)) => {
            format!(
                "{} (chunk {chunk_id}, event record {event_record_id})",
                gap.reason
            )
        }
        (Some(chunk_id), None) => format!("{} (chunk {chunk_id})", gap.reason),
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
}

pub(crate) fn evtx_log_entry(
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

pub(crate) fn append_diagnosis_cap_finding(
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

pub(crate) fn timeline_coverage_state(
    reason: &str,
) -> cmtraceopen_parser::diagnosis::CoverageState {
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

pub(crate) fn diagnosis_coverage_state(
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
        | EvtxCoverageGapKind::Xml => cmtraceopen_parser::diagnosis::CoverageState::ParseFailed,
        EvtxCoverageGapKind::Provider => {
            cmtraceopen_parser::diagnosis::CoverageState::ProviderDescriptionUnavailable
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn provider_gaps_do_not_count_as_record_loss_but_record_gaps_do() {
        let record = diagnosis_record(super::super::models::EvtxOriginKind::Event, "raw fallback");
        let provider_gap = super::super::live::provider_message_gap(
            "remote-host/ForwardedEvents",
            "Example.Provider",
            super::super::models::ProviderMessageStage::FormatMessage,
            15027,
        );
        let mut aggregation = super::QueryAggregation::default();
        aggregation.absorb_scan(
            "remote-host/ForwardedEvents",
            super::super::live::ChannelScan {
                records: vec![record],
                delivered: 1,
                gaps: Vec::new(),
                provider_gaps: vec![provider_gap.clone()],
            },
        );

        assert_eq!(aggregation.records.len(), 1);
        assert_eq!(aggregation.parse_errors, 0);
        assert_eq!(aggregation.coverage_gaps, vec![provider_gap]);
        let provider_diagnostic =
            "remote-host/ForwardedEvents: provider message for Example.Provider could not be \
             rendered at EvtFormatMessage (Windows error 15027); raw event data is shown instead"
                .to_string();
        assert_eq!(
            aggregation.error_messages,
            vec![provider_diagnostic.clone()]
        );

        aggregation.absorb_scan(
            "remote-host/ForwardedEvents",
            super::super::live::ChannelScan {
                records: Vec::new(),
                delivered: 0,
                gaps: vec![
                    "remote-host/ForwardedEvents: one event could not be read and is missing"
                        .to_string(),
                ],
                provider_gaps: Vec::new(),
            },
        );

        assert_eq!(aggregation.parse_errors, 1);
        assert_eq!(
            aggregation.error_messages,
            vec![
                provider_diagnostic,
                "remote-host/ForwardedEvents: one event could not be read and is missing"
                    .to_string()
            ]
        );
        assert_eq!(
            aggregation.coverage_gaps[1].kind,
            super::super::models::EvtxCoverageGapKind::Record
        );
    }

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
            let error = super::validate_diagnosis_coverage_gaps(&[gap])
                .expect_err("blank coverage identity fields must be rejected");
            assert!(
                error.contains(field),
                "validation error should identify the blank {field}: {error}"
            );
        }
    }

    #[test]
    fn diagnosis_rejects_oversized_provider_message_identity() {
        let mut gap = super::super::models::EvtxCoverageGap::new(
            "Application",
            super::super::models::EvtxCoverageGapKind::Provider,
            "provider description unavailable",
        );
        gap.provider_message = Some(Box::new(super::super::models::ProviderMessageCoverage {
            provider: "x".repeat(super::MAX_DIAGNOSIS_STRING_BYTES + 1),
            stage: super::super::models::ProviderMessageStage::FormatMessage,
            error_code: 15_027,
        }));

        let error = super::validate_diagnosis_coverage_gaps(&[gap])
            .expect_err("oversized provider identity must be rejected");

        assert!(error.contains("coverage provider"));
        assert!(error.contains("diagnosis limit"));
    }

    #[test]
    fn diagnosis_rejects_noncanonical_or_oversized_coverage_event_id_text() {
        for value in ["00042".to_string(), "9".repeat(256 * 1024)] {
            let mut gap = super::super::models::EvtxCoverageGap::new(
                "Application",
                super::super::models::EvtxCoverageGapKind::Record,
                "record unavailable",
            );
            gap.event_record_id_text = Some(value);

            let error = super::validate_diagnosis_coverage_gaps(&[gap])
                .expect_err("untrusted coverage identity text must be bounded and canonical");

            assert!(error.contains("coverage event ID text"));
        }
    }

    #[test]
    fn diagnosis_accepts_exact_text_for_unsafe_coverage_event_id() {
        let exact = "9007199254740993";
        let mut gap = super::super::models::EvtxCoverageGap::new(
            "Application",
            super::super::models::EvtxCoverageGapKind::Provider,
            "provider description unavailable",
        );
        // The JavaScript numeric transport can be rounded; exact text is authoritative above the
        // safe-integer boundary.
        gap.event_record_id = Some(9_007_199_254_740_992);
        gap.event_record_id_text = Some(exact.to_string());

        super::validate_diagnosis_coverage_gaps(&[gap.clone()]).unwrap();
        let finding = super::diagnosis_finding_for_gap(gap);

        assert!(finding.summary.contains(exact));
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
