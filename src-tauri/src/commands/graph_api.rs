#[cfg(target_os = "windows")]
use tauri::Manager;

use crate::error::{AppError, CmdResult};
#[cfg(all(feature = "esp-diagnostics", target_os = "windows"))]
use crate::graph_api::esp::EspGraphRequest;
#[cfg(target_os = "windows")]
use crate::graph_api::models::GraphPermissionUpgradeResult;
#[cfg(target_os = "windows")]
use crate::graph_api::{
    self, GraphAppInfo, GraphAuthAttemptResult, GraphAuthState, GraphAuthStatus,
    GraphHostCapability, GraphResolutionResult,
};
#[cfg(feature = "esp-diagnostics")]
use cmtraceopen_parser::esp::EspGraphOverlay;

/// Owns the main window for the duration of an interactive WAM sign-in.
///
/// The account-picker dialog belongs to the Entra broker process. Windows
/// parents it to the HWND we hand over — which disables our window while it is
/// up — but cross-process ownership does not make it topmost, and the broker
/// cannot steal the foreground on its own. Left alone, the dialog is drawn
/// behind an always-on-top main window that the user then cannot move or
/// dismiss. So for the length of the call we drop the always-on-top pin, hand
/// the broker permission to foreground itself, and restore the pin on drop.
#[cfg(target_os = "windows")]
struct InteractiveAuthWindow {
    window: tauri::WebviewWindow,
    hwnd: isize,
    restore_always_on_top: bool,
}

#[cfg(target_os = "windows")]
impl InteractiveAuthWindow {
    fn acquire(app: &tauri::AppHandle) -> Result<Self, AppError> {
        use windows::Win32::UI::WindowsAndMessaging::{AllowSetForegroundWindow, ASFW_ANY};

        let window = app
            .get_webview_window("main")
            .ok_or_else(|| AppError::Internal("No main window found".into()))?;
        let hwnd = window
            .hwnd()
            .map_err(|e| AppError::Internal(format!("Failed to get HWND: {e}")))?
            .0 as isize;

        let restore_always_on_top = crate::commands::system_preferences::always_on_top_enabled();
        if restore_always_on_top {
            // Failing to unpin is fatal for this flow: proceeding would raise
            // the dialog behind a window the user cannot interact with, which
            // is the very bug this guard exists to prevent.
            window.set_always_on_top(false).map_err(|error| {
                AppError::Internal(format!(
                    "Failed to suspend always-on-top for the sign-in dialog: {error}"
                ))
            })?;
            crate::commands::system_preferences::remember_always_on_top(false);
        }

        // Let the broker process bring its dialog to the foreground; without
        // this the foreground lock keeps it behind us even unpinned.
        let _ = unsafe { AllowSetForegroundWindow(ASFW_ANY) };
        let _ = window.set_focus();

        Ok(Self {
            window,
            hwnd,
            restore_always_on_top,
        })
    }

    fn hwnd(&self) -> isize {
        self.hwnd
    }
}

#[cfg(target_os = "windows")]
impl Drop for InteractiveAuthWindow {
    fn drop(&mut self) {
        // Drop cannot report failure, so keep the mirror on whatever the window
        // ended up in: if re-pinning fails (a closed window, say), the pin is
        // genuinely off and the mirror must say so.
        if self.restore_always_on_top && self.window.set_always_on_top(true).is_ok() {
            crate::commands::system_preferences::remember_always_on_top(true);
        }
    }
}

#[tauri::command]
#[cfg(target_os = "windows")]
pub async fn graph_authenticate(
    request_id: String,
    app: tauri::AppHandle,
    state: tauri::State<'_, GraphAuthState>,
) -> CmdResult<GraphAuthAttemptResult> {
    let state = state.inner().clone();
    let lease = state.begin_interactive_operation(request_id)?;
    let window = InteractiveAuthWindow::acquire(&app)?;
    let hwnd = window.hwnd();
    tauri::async_runtime::spawn_blocking(move || graph_api::authenticate(&state, hwnd, &lease))
        .await
        .map_err(|error| AppError::Internal(format!("GraphAuthenticationTaskFailed: {error}")))
}

#[tauri::command]
#[cfg(target_os = "windows")]
pub async fn graph_probe_capability() -> CmdResult<GraphHostCapability> {
    tauri::async_runtime::spawn_blocking(graph_api::probe_host_capability)
        .await
        .map_err(|error| AppError::Internal(format!("GraphCapabilityTaskFailed: {error}")))
}

#[tauri::command]
#[cfg(target_os = "windows")]
pub fn graph_cancel_authentication(
    request_id: String,
    state: tauri::State<'_, GraphAuthState>,
) -> bool {
    state.cancel_interactive_operation(&request_id)
}

#[tauri::command]
#[cfg(target_os = "windows")]
pub async fn graph_request_missing_permissions(
    request_id: String,
    app: tauri::AppHandle,
    state: tauri::State<'_, GraphAuthState>,
) -> CmdResult<GraphPermissionUpgradeResult> {
    let state = state.inner().clone();
    let lease = state.begin_interactive_operation(request_id)?;
    // The guard is held across the await and restores the pin on scope exit,
    // including the `?` early return below.
    let window = InteractiveAuthWindow::acquire(&app)?;
    let hwnd = window.hwnd();
    tauri::async_runtime::spawn_blocking(move || {
        graph_api::request_missing_permissions(&state, hwnd, &lease)
    })
    .await
    .map_err(|error| AppError::Internal(format!("GraphPermissionTaskFailed: {error}")))?
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
            graph_cancel_esp_diagnostics(
                "30000000-0000-4000-8000-000000000001".to_string()
            ),
            Err(AppError::PlatformUnsupported(capability))
                if capability == "GraphEspDiagnostics"
        ));
    }
}
