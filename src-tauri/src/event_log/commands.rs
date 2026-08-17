use serde::Serialize;
use tauri::AppHandle;
#[cfg(target_os = "windows")]
use tauri::Emitter;
use crate::state::app_state::AppState;

#[cfg(target_os = "windows")]
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvtxQueryProgress {
    pub progress: f64,
    pub total: f64,
}

#[cfg(target_os = "windows")]
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvtxRecordBatch {
    pub records: Vec<super::models::EvtxRecord>,
    pub sequence: u64,
}

#[tauri::command]
pub async fn evtx_parse_files(
    _paths: Vec<String>,
    _state: tauri::State<'_, AppState>,
) -> Result<EvtxParseResult, String> {
    Ok(EvtxParseResult {
        entries: vec![],
    })
}

#[tauri::command]
pub async fn evtx_enumerate_channels() -> Result<Vec<EvtxChannelInfo>, String> {
    Ok(vec![])
}

#[tauri::command]
pub async fn evtx_query_channels(
    _channels: Vec<String>,
    _max_events: Option<u64>,
    _filter: Option<cmtraceopen_parser::event_query::EventQueryFilter>,
    _app: AppHandle,
    _state: tauri::State<'_, AppState>,
) -> Result<EvtxParseResult, String> {
    Ok(EvtxParseResult {
        entries: vec![],
    })
}

#[tauri::command]
pub async fn evtx_export_records(
    _records: Vec<super::models::EvtxRecord>,
    _format: super::export::ExportFormat,
    _destination: String,
) -> Result<u64, String> {
    Ok(0)
}

#[tauri::command]
pub async fn evtx_load_event_maps(
    _directory: String,
    _state: tauri::State<'_, AppState>,
) -> Result<super::maps::MapLoadOutcome, String> {
    Ok(super::maps::MapLoadOutcome::default())
}

#[tauri::command]
pub async fn evtx_loaded_map_count(
    _state: tauri::State<'_, AppState>,
) -> Result<u64, String> {
    Ok(0)
}

#[tauri::command]
pub async fn evtx_load_provider_databases(
    _directory: String,
    _state: tauri::State<'_, AppState>,
) -> Result<Vec<super::provider_db::ProviderDbInfo>, String> {
    Ok(vec![])
}

#[tauri::command]
pub async fn evtx_provider_databases(
    _state: tauri::State<'_, AppState>,
) -> Result<Vec<super::provider_db::ProviderDbInfo>, String> {
    Ok(vec![])
}

#[tauri::command]
pub async fn evtx_capture_provider_databases(
    db_path: String,
    _state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    let path = std::path::PathBuf::from(db_path);
    super::capture::capture_providers_to_db(&path).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn evtx_build_unified_timeline(
    _entries: Vec<cmtraceopen_parser::models::log_entry::LogEntry>,
    _records: Vec<super::models::EvtxRecord>,
) -> Result<cmtraceopen_parser::unified_timeline::UnifiedTimeline, String> {
    Ok(cmtraceopen_parser::unified_timeline::UnifiedTimeline {
        items: vec![],
        unplaced: vec![],
    })
}

#[derive(Serialize)]
pub struct EvtxParseResult {
    pub entries: Vec<cmtraceopen_parser::models::log_entry::LogEntry>,
}

#[derive(Serialize)]
pub struct EvtxChannelInfo {
    pub name: String,
}
