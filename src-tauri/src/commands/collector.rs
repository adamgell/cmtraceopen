use tauri::AppHandle;

use crate::collector::types::CollectionResult;

/// Collect system diagnostics into an evidence bundle.
///
/// This is a long-running command that emits `collection-progress` events
/// to the frontend as artifacts are collected. All five collection categories
/// (logs, registry, event logs, exports, commands) run concurrently.
///
/// Windows-only. Returns an error on other platforms.
#[tauri::command]
pub async fn collect_diagnostics(
    request_id: String,
    output_root: Option<String>,
    enabled_families: Option<Vec<String>>,
    app: AppHandle,
) -> Result<CollectionResult, crate::error::AppError> {
    collect_diagnostics_impl(request_id, output_root, enabled_families, app).await
}

#[cfg(target_os = "windows")]
async fn collect_diagnostics_impl(
    request_id: String,
    output_root: Option<String>,
    enabled_families: Option<Vec<String>>,
    app: AppHandle,
) -> Result<CollectionResult, crate::error::AppError> {
    tokio::task::spawn_blocking(move || {
        crate::collector::engine::run_collection(request_id, output_root, enabled_families, app)
    })
    .await
    .map_err(|e| {
        if e.is_panic() {
            crate::error::AppError::Internal(format!("collection task panicked: {e}"))
        } else if e.is_cancelled() {
            crate::error::AppError::Internal("collection task was cancelled".to_string())
        } else {
            crate::error::AppError::Internal(format!("collection task failed to join: {e}"))
        }
    })?
}

#[cfg(not(target_os = "windows"))]
async fn collect_diagnostics_impl(
    _request_id: String,
    _output_root: Option<String>,
    _enabled_families: Option<Vec<String>>,
    _app: AppHandle,
) -> Result<CollectionResult, crate::error::AppError> {
    Err(crate::error::AppError::PlatformUnsupported(
        "Diagnostics collection is only supported on Windows.".to_string(),
    ))
}
