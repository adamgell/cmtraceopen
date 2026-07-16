//! Thin Tauri IPC surface for local-only ESP diagnostic sessions.
//!
//! Optional Graph enrichment is intentionally not part of this manager. The
//! existing authenticated Graph/WAM coordinator runs separately in the
//! frontend and overlays its result only when the user has enabled Graph.

use std::sync::Arc;

use tauri::{AppHandle, Emitter, Manager, State};

use crate::esp::live_session::native_session_dependencies;
use crate::esp::relaunch::{
    restart_with_provider, EspRelaunchError, EspRelaunchResult, NativeEspRelaunchProvider,
};
use crate::esp::session::{
    EspSessionEnvelope, EspSessionError, EspSessionEventSink, EspSessionManager, EspSessionUpdate,
    ESP_SESSION_UPDATE_EVENT,
};
use crate::esp::{acquisition_capability, EspAcquisitionCapability};
use crate::state::app_state::AppState;

struct TauriEspSessionEventSink {
    app: AppHandle,
}

impl EspSessionEventSink for TauriEspSessionEventSink {
    fn emit(&self, update: EspSessionUpdate) -> Result<(), String> {
        self.app
            .emit(ESP_SESSION_UPDATE_EVENT, update)
            .map_err(|error| error.to_string())
    }
}

pub fn initialize_esp_session_manager(app: &AppHandle) -> Result<(), EspSessionError> {
    let sink = Arc::new(TauriEspSessionEventSink { app: app.clone() });
    let manager = Arc::new(EspSessionManager::new(native_session_dependencies(sink)));
    app.state::<AppState>().install_esp_session_manager(manager)
}

pub fn shutdown_esp_session_manager(app: &AppHandle) -> Result<(), EspSessionError> {
    app.state::<AppState>().shutdown_esp_session_manager()
}

#[tauri::command]
pub fn get_esp_diagnostics_capability() -> EspAcquisitionCapability {
    acquisition_capability()
}

#[tauri::command]
pub async fn start_esp_diagnostics_session(
    request_id: String,
    state: State<'_, AppState>,
) -> Result<EspSessionEnvelope, EspSessionError> {
    let manager = state.esp_session_manager()?;
    tauri::async_runtime::spawn_blocking(move || manager.start(&request_id))
        .await
        .map_err(runtime_join_error)?
}

#[tauri::command]
pub fn get_esp_diagnostics_session(
    session_id: String,
    state: State<'_, AppState>,
) -> Result<EspSessionEnvelope, EspSessionError> {
    state.esp_session_manager()?.get(&session_id)
}

#[tauri::command]
pub async fn stop_esp_diagnostics_session(
    session_id: String,
    state: State<'_, AppState>,
) -> Result<(), EspSessionError> {
    let manager = state.esp_session_manager()?;
    tauri::async_runtime::spawn_blocking(move || manager.stop(&session_id).map(|_| ()))
        .await
        .map_err(runtime_join_error)?
}

#[tauri::command]
pub async fn restart_esp_as_administrator(
    app: AppHandle,
) -> Result<EspRelaunchResult, EspRelaunchError> {
    let result = tauri::async_runtime::spawn_blocking(move || {
        restart_with_provider(&NativeEspRelaunchProvider)
    })
    .await
    .map_err(|_| EspRelaunchError::LaunchFailed {
        message: "administrator restart task failed".to_string(),
    })??;
    if result.launched {
        app.exit(0);
    }
    Ok(result)
}

fn runtime_join_error(error: impl std::fmt::Display) -> EspSessionError {
    EspSessionError::Worker {
        message: format!("ESP diagnostics blocking task failed: {error}"),
    }
}

#[cfg(test)]
mod tests {
    use super::get_esp_diagnostics_capability;

    #[test]
    fn capability_command_reports_portable_offline_and_platform_live_support() {
        let capability = get_esp_diagnostics_capability();
        assert!(capability.offline_analysis_supported);
        assert_eq!(
            capability.live_acquisition_supported,
            cfg!(target_os = "windows")
        );
        assert_eq!(
            capability.live_acquisition_detail.is_none(),
            cfg!(target_os = "windows")
        );
    }
}
