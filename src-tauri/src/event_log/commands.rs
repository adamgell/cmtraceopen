#[cfg(target_os = "windows")]
use serde::Serialize;
use tauri::AppHandle;
#[cfg(target_os = "windows")]
use tauri::Emitter;

use super::models::{EvtxChannelInfo, EvtxParseResult};
use super::parser::{self, EventLogSourceManifest};
use crate::state::app_state::AppState;

#[cfg(target_os = "windows")]
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct EvtxQueryProgress {
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
/// arrive would look exactly like events that do not exist.
#[cfg(target_os = "windows")]
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct EvtxRecordBatch {
    channel: String,
    sequence: usize,
    records: Vec<super::models::EvtxRecord>,
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
pub async fn evtx_query_channels(
    channels: Vec<String>,
    max_events: Option<u64>,
    filter: Option<cmtraceopen_parser::event_query::EventQueryFilter>,
    app: AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<EvtxParseResult, String> {
    #[cfg(target_os = "windows")]
    {
        // Cloned before the blocking work, so a long channel scan never runs with a state lock
        // held. Channels are then read under one shared guard rather than locking per record.
        let registry = state.event_maps.clone();
        tokio::task::spawn_blocking(move || {
            use rayon::prelude::*;

            let maps = registry
                .read()
                .map_err(|_| "map registry lock was poisoned".to_string())?;

            // Absent means unfiltered, which keeps the query as "*" and preserves prior behaviour
            // for callers that have not adopted server-side filtering yet.
            let query_filter = filter.unwrap_or_default();

            // Channels are queried concurrently. Each one is an independent conversation with the
            // Event Log service that spends nearly all its time waiting on RPC, so serializing
            // them leaves the machine idle. Results are collected per channel and ordered
            // afterwards, so concurrency cannot affect the output.
            let per_channel: Vec<(String, Result<super::live::ChannelScan, String>)> = channels
                .par_iter()
                .map(|channel| {
                    let app_ref = &app;
                    let ch_name = channel.clone();
                    let batch_channel = channel.clone();
                    let mut sequence = 0usize;
                    let outcome = super::live::query_channel_streamed(
                        channel,
                        &query_filter,
                        &maps,
                        max_events,
                        |fetched, _| {
                            let _ = app_ref.emit(
                                "evtx-query-progress",
                                EvtxQueryProgress {
                                    channel: ch_name.clone(),
                                    fetched,
                                },
                            );
                        },
                        |batch| {
                            if batch.is_empty() {
                                return;
                            }
                            // Taken from the batch rather than copied out of it. Leaving the records
                            // behind would send them and also accumulate them, which is the memory
                            // this exists to avoid.
                            let records = std::mem::take(batch);
                            let emitted = app_ref.emit(
                                "evtx-record-batch",
                                EvtxRecordBatch {
                                    channel: batch_channel.clone(),
                                    sequence,
                                    records,
                                },
                            );
                            sequence += 1;
                            if let Err(error) = emitted {
                                // The records are gone: they were moved into the payload. Say so
                                // rather than letting the count quietly disagree with the view.
                                log::warn!(
                                    "event=evtx_batch_emit_failed channel=\"{batch_channel}\" \
                                     sequence={sequence} error=\"{error}\""
                                );
                            }
                        },
                    );
                    (channel.clone(), outcome)
                })
                .collect();

            let mut all_records = Vec::new();
            let mut channel_infos = Vec::new();
            let mut parse_errors = 0u32;
            let mut error_messages = Vec::new();
            // Emitted in batches rather than carried in this reply. Reported so the receiver can
            // check what it actually assembled against what was sent, instead of assuming an
            // event channel delivered everything.
            let mut streamed = 0usize;

            for (channel, outcome) in per_channel {
                match outcome {
                    Ok(scan) => {
                        // `delivered`, not `records.len()`: the records were emitted in batches and
                        // taken out of the vector on the way. Counting what is left would report a
                        // fully read channel as empty.
                        channel_infos.push(EvtxChannelInfo {
                            name: channel.clone(),
                            event_count: scan.delivered as u64,
                            source_type: super::models::ChannelSourceType::Live,
                        });
                        streamed += scan.delivered;
                        // A channel can be read partly. Those gaps travel with the records so a
                        // truncated channel is not presented as a complete one, which is what
                        // happened while the query returned records alone.
                        if !scan.gaps.is_empty() {
                            parse_errors += scan.gaps.len() as u32;
                            error_messages.extend(scan.gaps);
                        }
                        all_records.extend(scan.records);
                    }
                    Err(e) => {
                        log::warn!(
                            "event=evtx_channel_query_error channel=\"{}\" error=\"{}\"",
                            channel,
                            e
                        );
                        error_messages.push(format!("{}: {}", channel, e));
                        // A failed channel is still reported with 0 events so the gap stays visible
                        // rather than looking like a channel that simply had nothing in it.
                        channel_infos.push(EvtxChannelInfo {
                            name: channel.clone(),
                            event_count: 0,
                            source_type: super::models::ChannelSourceType::Live,
                        });
                        parse_errors += 1;
                    }
                }
            }

            // `all_records` holds only what the batch hook left behind, which is nothing while the
            // records are being streamed. `total_records` counts what was sent, so the receiver has
            // something to check its own tally against.
            all_records.sort_by_key(|r| r.timestamp_epoch);
            let total_records = (streamed + all_records.len()) as u64;

            Ok(EvtxParseResult {
                records: all_records,
                channels: channel_infos,
                total_records,
                parse_errors,
                error_messages,
                coverage_gaps: Vec::new(),
            })
        })
        .await
        .map_err(|e| format!("Task join error: {}", e))?
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (channels, max_events, filter, app, state);
        Err("Live event log queries are only available on Windows.".to_string())
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
) -> Result<u64, String> {
    let record_count = records.len();
    // Rendered on a blocking thread, like every other heavy command here. The XML format
    // concatenates raw_xml for up to a hundred thousand records into one String, which can occupy
    // a runtime worker for seconds and stall unrelated IPC.
    let rendered =
        tokio::task::spawn_blocking(move || super::export::export_records(&records, format))
            .await
            .map_err(|error| format!("export task failed: {error}"))??;
    let byte_count = rendered.len() as u64;
    tokio::fs::write(&destination, rendered)
        .await
        .map_err(|error| format!("cannot write {destination}: {error}"))?;
    log::info!(
        "event=evtx_export destination=\"{destination}\" records={record_count} bytes={byte_count}"
    );
    Ok(byte_count)
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

/// Calls the provider-capture seam. The Windows traversal itself lives in the provider-capture
/// lane; this command stays a real IPC entry point in every build.
#[tauri::command]
pub async fn evtx_capture_provider_databases(
    db_path: String,
    _state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    let path = std::path::PathBuf::from(db_path);
    super::capture::capture_providers_to_db(&path).map_err(|error| error.to_string())
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
}
