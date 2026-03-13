use std::path::PathBuf;

use serde::Serialize;
use tauri::{AppHandle, Emitter, State};

use crate::models::log_entry::{LogEntry, LogFormat};
use crate::state::app_state::AppState;
use crate::watcher::tail;

/// Payload emitted to the frontend when new tail entries arrive.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TailPayload {
    pub entries: Vec<LogEntry>,
    pub file_path: String,
}

/// Start tailing a file for new log entries.
/// The file must have been opened first via `open_log_file`.
#[tauri::command]
pub fn start_tail(
    path: String,
    _format: LogFormat,
    byte_offset: u64,
    next_id: u64,
    next_line: u32,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let path_buf = PathBuf::from(&path);

    // Stop any existing session for this file
    {
        let mut sessions = state.tail_sessions.lock().map_err(|e| e.to_string())?;
        if let Some(old_session) = sessions.remove(&path_buf) {
            old_session.stop();
        }
    }

    // Tailing reuses the backend-owned parser selection stored during open_log_file.
    let parser_selection = {
        let open_files = state.open_files.lock().map_err(|e| e.to_string())?;
        open_files
            .get(&path_buf)
            .map(|f| f.parser_selection.clone())
            .ok_or_else(|| format!("file is not open: {}", path))?
    };

    let file_path_for_event = path.clone();
    let session = tail::start_tail_session(
        path_buf.clone(),
        byte_offset,
        parser_selection,
        next_id,
        next_line,
        move |entries| {
            let payload = TailPayload {
                entries,
                file_path: file_path_for_event.clone(),
            };
            if let Err(e) = app.emit("tail-new-entries", &payload) {
                log::error!("Failed to emit tail entries: {}", e);
            }
        },
    )?;

    let mut sessions = state.tail_sessions.lock().map_err(|e| e.to_string())?;
    sessions.insert(path_buf, session);

    Ok(())
}

/// Stop tailing a file.
#[tauri::command]
pub fn stop_tail(path: String, state: State<'_, AppState>) -> Result<(), String> {
    let path_buf = PathBuf::from(&path);
    let mut sessions = state.tail_sessions.lock().map_err(|e| e.to_string())?;
    if let Some(session) = sessions.remove(&path_buf) {
        session.stop();
    }
    Ok(())
}

/// Pause tailing — stop receiving new entries but keep watching.
#[tauri::command]
pub fn pause_tail(path: String, state: State<'_, AppState>) -> Result<(), String> {
    let path_buf = PathBuf::from(&path);
    let sessions = state.tail_sessions.lock().map_err(|e| e.to_string())?;
    if let Some(session) = sessions.get(&path_buf) {
        session.set_paused(true);
    }
    Ok(())
}

/// Resume tailing — start receiving new entries again.
#[tauri::command]
pub fn resume_tail(path: String, state: State<'_, AppState>) -> Result<(), String> {
    let path_buf = PathBuf::from(&path);
    let sessions = state.tail_sessions.lock().map_err(|e| e.to_string())?;
    if let Some(session) = sessions.get(&path_buf) {
        session.set_paused(false);
    }
    Ok(())
}
