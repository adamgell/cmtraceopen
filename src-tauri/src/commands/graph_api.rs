#[cfg(target_os = "windows")]
use tauri::Manager;

use crate::error::{AppError, CmdResult};
#[cfg(all(feature = "esp-diagnostics", target_os = "windows"))]
use crate::graph_api::esp::EspGraphRequest;
#[cfg(target_os = "windows")]
use crate::graph_api::{
    self, GraphAppInfo, GraphAuthState, GraphAuthStatus, GraphResolutionResult,
};
#[cfg(feature = "esp-diagnostics")]
use cmtraceopen_parser::esp::EspGraphOverlay;

/// Get the HWND of the main Tauri window for WAM dialog parenting.
#[cfg(target_os = "windows")]
fn get_main_hwnd(app: &tauri::AppHandle) -> Result<isize, AppError> {
    let window = app
        .get_webview_window("main")
        .ok_or_else(|| AppError::Internal("No main window found".into()))?;

    #[cfg(target_os = "windows")]
    {
        let hwnd = window
            .hwnd()
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
#[cfg(target_os = "windows")]
pub fn graph_authenticate(
    app: tauri::AppHandle,
    state: tauri::State<'_, GraphAuthState>,
) -> CmdResult<GraphAuthStatus> {
    let hwnd = get_main_hwnd(&app)?;
    graph_api::authenticate(&state, hwnd)
}

#[tauri::command]
#[cfg(target_os = "windows")]
pub fn graph_get_auth_status(state: tauri::State<'_, GraphAuthState>) -> GraphAuthStatus {
    graph_api::get_auth_status(&state)
}

#[tauri::command]
#[cfg(target_os = "windows")]
pub fn graph_sign_out(state: tauri::State<'_, GraphAuthState>) {
    graph_api::sign_out(&state);
}

#[tauri::command]
#[cfg(target_os = "windows")]
pub fn graph_resolve_guids(
    guids: Vec<String>,
    state: tauri::State<'_, GraphAuthState>,
) -> CmdResult<GraphResolutionResult> {
    graph_api::resolve_guids(&state, &guids)
}

#[tauri::command]
#[cfg(target_os = "windows")]
pub fn graph_fetch_all_apps(
    state: tauri::State<'_, GraphAuthState>,
) -> CmdResult<Vec<GraphAppInfo>> {
    graph_api::fetch_all_apps(&state)
}

#[tauri::command]
#[cfg(all(feature = "esp-diagnostics", target_os = "windows"))]
pub async fn graph_fetch_esp_diagnostics(
    request: EspGraphRequest,
    state: tauri::State<'_, GraphAuthState>,
) -> CmdResult<EspGraphOverlay> {
    let prepared = graph_api::prepare_esp_diagnostics(&state, request)?;
    tauri::async_runtime::spawn_blocking(move || prepared.execute())
        .await
        .map_err(|error| AppError::Internal(format!("GraphEspTaskFailed: {error}")))
}

#[tauri::command]
#[cfg(all(feature = "esp-diagnostics", not(target_os = "windows")))]
pub async fn graph_fetch_esp_diagnostics(
    request: crate::graph_api::esp::EspGraphRequest,
) -> CmdResult<EspGraphOverlay> {
    let _ = request;
    Err(AppError::PlatformUnsupported(
        "GraphEspDiagnostics".to_string(),
    ))
}

#[tauri::command]
#[cfg(all(feature = "esp-diagnostics", target_os = "windows"))]
pub fn graph_cancel_esp_diagnostics(
    request_id: String,
    state: tauri::State<'_, GraphAuthState>,
) -> CmdResult<()> {
    graph_api::cancel_esp_diagnostics(&state, &request_id);
    Ok(())
}

#[tauri::command]
#[cfg(all(feature = "esp-diagnostics", not(target_os = "windows")))]
pub fn graph_cancel_esp_diagnostics(request_id: String) -> CmdResult<()> {
    let _ = request_id;
    Err(AppError::PlatformUnsupported(
        "GraphEspDiagnostics".to_string(),
    ))
}

#[cfg(all(test, feature = "esp-diagnostics", not(target_os = "windows")))]
mod tests {
    use super::*;

    #[test]
    fn non_windows_graph_esp_cancellation_is_typed_unsupported() {
        assert!(matches!(
            graph_cancel_esp_diagnostics("request-a".to_string()),
            Err(AppError::PlatformUnsupported(capability))
                if capability == "GraphEspDiagnostics"
        ));
    }
}
