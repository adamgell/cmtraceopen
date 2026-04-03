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
    app: AppHandle,
) -> Result<EvtxParseResult, String> {
    #[cfg(target_os = "windows")]
    {
        tokio::task::spawn_blocking(move || {
            let mut all_records = Vec::new();
            let mut channel_infos = Vec::new();
            let mut parse_errors = 0u32;
            let mut error_messages = Vec::new();

            for channel in &channels {
                let app_ref = &app;
                let ch_name = channel.clone();
                match super::live::query_channel_with_progress(channel, max_events, |fetched, _| {
                    let _ = app_ref.emit("evtx-query-progress", EvtxQueryProgress {
                        channel: ch_name.clone(),
                        fetched,
                    });
                }) {
                    Ok(records) => {
                        channel_infos.push(super::models::EvtxChannelInfo {
                            name: channel.clone(),
                            event_count: records.len() as u64,
                            source_type: super::models::ChannelSourceType::Live,
                        });
                        all_records.extend(records);
                    }
                    Err(e) => {
                        log::warn!("event=evtx_channel_query_error channel=\"{}\" error=\"{}\"", channel, e);
                        error_messages.push(format!("{}: {}", channel, e));
                        // Still include channel in results with 0 events so frontend knows it was attempted
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
        let _ = (channels, max_events, app);
        Ok(EvtxParseResult {
            records: Vec::new(),
            channels: Vec::new(),
            total_records: 0,
            parse_errors: 0,
            error_messages: vec![],
        })
    }
}
