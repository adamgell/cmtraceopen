//! Thin Tauri IPC surface for local-only ESP diagnostic sessions.
//!
//! Optional Graph enrichment is intentionally not part of this manager. The
//! existing authenticated Graph/WAM coordinator runs separately in the
//! frontend and overlays its result only when the user has enabled Graph.

use std::path::Path;
use std::sync::Arc;

use cmtraceopen_parser::esp::{
    EspDiagnosticsSnapshot, EspElevationState, EspSessionCapture, EspSessionCaptureMeta,
};
use tauri::{AppHandle, Emitter, Manager, State};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::commands::elevation::ElevationCommandError;
use crate::elevation::relaunch::{RelaunchError, RelaunchReason, RelaunchResult};
use crate::elevation::{AppWorkspace, ElevationReason, ElevationRequest, RestoreTarget};
use crate::esp::bundle::{analyze_captured_evidence, BundleError};
use crate::esp::live_session::native_session_dependencies;
use crate::esp::remediation::{
    flip_app_installed, restore_app_state, EspAppFlipBackup, EspAppFlipResult,
};
use crate::esp::session::{
    EspSessionEnvelope, EspSessionError, EspSessionEventSink, EspSessionManager, EspSessionUpdate,
    ESP_SESSION_UPDATE_EVENT,
};
use crate::esp::system::current_elevation_state;
use crate::esp::{acquisition_capability, EspAcquisitionCapability};
use crate::state::app_state::AppState;

/// Wire types for the compatibility ESP relaunch command.
///
/// These stay ESP-shaped so an older frontend build keeps deserializing the same
/// payload. They are a projection of the generic relaunch result, not a second
/// model: nothing here decides relaunch behavior.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum EspRelaunchReason {
    Launched,
    AlreadyElevated,
    ElevationCancelled,
    UnsupportedPlatform,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EspRelaunchResult {
    pub launched: bool,
    pub reason: EspRelaunchReason,
}

#[derive(Debug, Clone, Serialize, Error, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum EspRelaunchError {
    #[error("an unsafe startup argument prevented administrator restart")]
    UnsafeArgument,
    #[error("administrator restart failed: {message}")]
    LaunchFailed { message: String },
}

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
pub fn get_esp_elevation_state() -> EspElevationState {
    current_elevation_state()
}

#[tauri::command]
pub async fn analyze_esp_evidence(
    path: String,
    request_id: String,
) -> Result<EspDiagnosticsSnapshot, BundleError> {
    tauri::async_runtime::spawn_blocking(move || {
        analyze_captured_evidence(Path::new(&path), &request_id)
    })
    .await
    .map_err(|error| BundleError::SourceAccess {
        message: format!("captured ESP analysis task failed: {error}"),
    })?
}

/// Errors the ESP session export can fail with.
#[derive(Debug, Clone, Serialize, Error, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum EspExportError {
    #[error("the ESP session capture could not be serialized: {message}")]
    Serialize { message: String },
    #[error("the ESP session capture could not be written: {message}")]
    Write { message: String },
}

/// Write a redacted ESP session capture to a user-chosen file.
///
/// The frontend hands over the session it is displaying and never serializes
/// one itself: [`EspSessionCapture`] is the only exportable shape and applies
/// the crate's export projection on construction, so the bytes written here
/// cannot carry local values (issue #549).
#[tauri::command]
pub async fn export_esp_session(
    destination: String,
    snapshot: EspDiagnosticsSnapshot,
    meta: EspSessionCaptureMeta,
) -> Result<(), EspExportError> {
    let contents = EspSessionCapture::from_snapshot(&snapshot, meta)
        .to_json()
        .map_err(|error| EspExportError::Serialize {
            message: error.to_string(),
        })?;

    // Written to a sibling temporary file and renamed into place, so a failed
    // write cannot truncate a prior capture already at `destination`. The
    // temporary file sits beside the destination rather than in a scratch
    // directory because rename is only atomic within one filesystem. The
    // process id plus a nanosecond timestamp makes the name unique per call, so
    // two concurrent exports to the same destination cannot share a temporary
    // file.
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let tmp = format!("{destination}.{}.{nonce}.tmp", std::process::id());
    tokio::fs::write(&tmp, &contents)
        .await
        .map_err(|error| EspExportError::Write {
            message: error.to_string(),
        })?;
    match tokio::fs::rename(&tmp, &destination).await {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = tokio::fs::remove_file(&tmp).await;
            Err(EspExportError::Write {
                message: error.to_string(),
            })
        }
    }
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

/// Compatibility wrapper over the application-wide elevation command.
///
/// Kept so an older frontend build still has a command to call, but it owns no
/// relaunch behavior: it forwards to `restart_as_administrator` with the ESP
/// workspace and no source, which is exactly what the migrated ESP banner sends.
/// The ESP-specific `ShellExecute` implementation this used to call has been
/// removed; there is one relaunch owner.
#[tauri::command]
pub async fn restart_esp_as_administrator(
    app: AppHandle,
) -> Result<EspRelaunchResult, EspRelaunchError> {
    let request = ElevationRequest {
        reason: ElevationReason::CoverageRecommended,
        workspace: AppWorkspace::EspDiagnostics,
        target: RestoreTarget::Workspace,
    };

    crate::commands::elevation::restart_as_administrator(app, request)
        .await
        .map(esp_relaunch_result)
        .map_err(esp_relaunch_error)
}

fn esp_relaunch_result(result: RelaunchResult) -> EspRelaunchResult {
    EspRelaunchResult {
        launched: result.launched,
        reason: match result.reason {
            RelaunchReason::Launched => EspRelaunchReason::Launched,
            RelaunchReason::AlreadyElevated => EspRelaunchReason::AlreadyElevated,
            RelaunchReason::ElevationCancelled => EspRelaunchReason::ElevationCancelled,
            RelaunchReason::UnsupportedPlatform => EspRelaunchReason::UnsupportedPlatform,
        },
    }
}

/// Flattens the generic error into the two shapes the ESP wire type has.
///
/// `Display` is used rather than the variant name so the caller still sees the
/// real reason instead of a humanized enum label.
fn esp_relaunch_error(error: ElevationCommandError) -> EspRelaunchError {
    match error {
        ElevationCommandError::Relaunch {
            source: RelaunchError::UnsafeArgument,
        } => EspRelaunchError::UnsafeArgument,
        other => EspRelaunchError::LaunchFailed {
            message: other.to_string(),
        },
    }
}

/// Force a failed ESP-tracked app past the Enrollment Status Page by flipping its
/// Sidecar InstallationState 4 -> 3 and clearing ErrorHresult. WRITES to HKLM
/// (Windows-only, requires elevation). Returns the prior values as a backup so the
/// change can be undone. Does not install the app.
#[tauri::command]
pub async fn esp_flip_app_installed(app_id: String) -> Result<EspAppFlipResult, String> {
    tauri::async_runtime::spawn_blocking(move || flip_app_installed(&app_id))
        .await
        .map_err(|error| format!("ESP flip task failed: {error}"))?
}

/// Restore an app's Sidecar tracking values from a backup returned by
/// `esp_flip_app_installed`. WRITES to HKLM (Windows-only, requires elevation).
#[tauri::command]
pub async fn esp_restore_app_state(backup: EspAppFlipBackup) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || restore_app_state(&backup))
        .await
        .map_err(|error| format!("ESP restore task failed: {error}"))?
}

fn runtime_join_error(error: impl std::fmt::Display) -> EspSessionError {
    EspSessionError::Worker {
        message: format!("ESP diagnostics blocking task failed: {error}"),
    }
}

#[cfg(test)]
mod tests {
    use super::{get_esp_diagnostics_capability, get_esp_elevation_state};

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

    #[test]
    fn elevation_command_reports_platform_restart_capability() {
        let elevation = get_esp_elevation_state();
        assert_eq!(elevation.restart_supported, cfg!(target_os = "windows"));
    }
}
