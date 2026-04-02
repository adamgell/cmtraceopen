use tauri::Manager;

use crate::error::{AppError, CmdResult};
use crate::graph_api::{self, GraphAppInfo, GraphAuthState, GraphAuthStatus, GraphResolutionResult};

/// Get the HWND of the main Tauri window for WAM dialog parenting.
fn get_main_hwnd(app: &tauri::AppHandle) -> Result<isize, AppError> {
    let window = app
        .get_webview_window("main")
        .ok_or_else(|| AppError::Internal("No main window found".into()))?;

    #[cfg(target_os = "windows")]
    {
        let hwnd = window.hwnd()
            .map_err(|e| AppError::Internal(format!("Failed to get HWND: {e}")))?;
        Ok(hwnd.0 as isize)
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = window;
        Ok(0)
    }
}

#[tauri::command]
pub fn graph_authenticate(
    app: tauri::AppHandle,
    state: tauri::State<'_, GraphAuthState>,
) -> CmdResult<GraphAuthStatus> {
    let hwnd = get_main_hwnd(&app)?;
    graph_api::authenticate(&state, hwnd)
}

#[tauri::command]
pub fn graph_get_auth_status(
    state: tauri::State<'_, GraphAuthState>,
) -> GraphAuthStatus {
    graph_api::get_auth_status(&state)
}

#[tauri::command]
pub fn graph_sign_out(state: tauri::State<'_, GraphAuthState>) {
    graph_api::sign_out(&state);
}

#[tauri::command]
pub fn graph_resolve_guids(
    guids: Vec<String>,
    state: tauri::State<'_, GraphAuthState>,
) -> CmdResult<GraphResolutionResult> {
    graph_api::resolve_guids(&state, &guids)
}

#[tauri::command]
pub fn graph_fetch_all_apps(
    state: tauri::State<'_, GraphAuthState>,
) -> CmdResult<Vec<GraphAppInfo>> {
    graph_api::fetch_all_apps(&state)
}
