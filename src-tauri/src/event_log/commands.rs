#[cfg(target_os = "windows")]
use serde::Serialize;
use tauri::AppHandle;
#[cfg(target_os = "windows")]
use tauri::Emitter;

use super::models::{EvtxChannelInfo, EvtxParseResult};
use super::parser;

#[cfg(target_os = "windows")]
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct EvtxQueryProgress {
    channel: String,
    fetched: usize,
}

#[tauri::command]
pub async fn evtx_parse_files(paths: Vec<String>) -> Result<EvtxParseResult, String> {
    tokio::task::spawn_blocking(move || parser::parse_evtx_files(&paths))
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
        Ok(Vec::new())
    }
}

#[tauri::command]
pub async fn evtx_query_channels(
    channels: Vec<String>,
    max_events: Option<u64>,
    filter: Option<cmtraceopen_parser::event_query::EventQueryFilter>,
    app: AppHandle,
) -> Result<EvtxParseResult, String> {
    #[cfg(target_os = "windows")]
    {
        tokio::task::spawn_blocking(move || {
            use rayon::prelude::*;

            // Absent means unfiltered, which keeps the query as "*" and preserves prior behaviour
            // for callers that have not adopted server-side filtering yet.
            let query_filter = filter.unwrap_or_default();

            // Channels are queried concurrently. Each one is an independent conversation with the
            // Event Log service that spends nearly all its time waiting on RPC, so serializing
            // them leaves the machine idle. Results are collected per channel and ordered
            // afterwards, so concurrency cannot affect the output.
            let per_channel: Vec<(String, Result<Vec<super::models::EvtxRecord>, String>)> =
                channels
                    .par_iter()
                    .map(|channel| {
                        let app_ref = &app;
                        let ch_name = channel.clone();
                        let outcome = super::live::query_channel_filtered_with_progress(
                            channel,
                            &query_filter,
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
                        );
                        (channel.clone(), outcome)
                    })
                    .collect();

            let mut all_records = Vec::new();
            let mut channel_infos = Vec::new();
            let mut parse_errors = 0u32;
            let mut error_messages = Vec::new();

            for (channel, outcome) in per_channel {
                match outcome {
                    Ok(records) => {
                        channel_infos.push(super::models::EvtxChannelInfo {
                            name: channel.clone(),
                            event_count: records.len() as u64,
                            source_type: super::models::ChannelSourceType::Live,
                        });
                        all_records.extend(records);
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
                        channel_infos.push(super::models::EvtxChannelInfo {
                            name: channel.clone(),
                            event_count: 0,
                            source_type: super::models::ChannelSourceType::Live,
                        });
                        parse_errors += 1;
                    }
                }
            }

            all_records.sort_by_key(|r| r.timestamp_epoch);
            for (i, record) in all_records.iter_mut().enumerate() {
                record.id = i as u64;
            }

            let total_records = all_records.len() as u64;

            Ok(EvtxParseResult {
                records: all_records,
                channels: channel_infos,
                total_records,
                parse_errors,
                error_messages,
            })
        })
        .await
        .map_err(|e| format!("Task join error: {}", e))?
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (channels, max_events, filter, app);
        Ok(EvtxParseResult {
            records: Vec::new(),
            channels: Vec::new(),
            total_records: 0,
            parse_errors: 0,
            error_messages: vec![],
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
) -> Result<u64, String> {
    let rendered = super::export::export_records(&records, format)?;
    let byte_count = rendered.len() as u64;
    tokio::fs::write(&destination, rendered)
        .await
        .map_err(|error| format!("cannot write {destination}: {error}"))?;
    log::info!(
        "event=evtx_export destination=\"{destination}\" records={} bytes={byte_count}",
        records.len()
    );
    Ok(byte_count)
}
