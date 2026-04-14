use std::fs;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Manager};

use crate::error::AppError;

// ── Types ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MarkerCategory {
    pub id: String,
    pub label: String,
    pub color: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Marker {
    pub line_id: u64,
    pub category: String,
    pub color: String,
    pub added: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MarkerFile {
    pub version: u32,
    pub source_path: String,
    pub source_size: u64,
    pub created: String,
    pub modified: String,
    pub markers: Vec<Marker>,
    pub categories: Vec<MarkerCategory>,
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Compute a lowercase hex SHA-256 hash of a file path string.
fn hash_file_path(file_path: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(file_path.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Resolve the path `markers/<hash>.json` inside the app data directory.
fn marker_file_path(app: &AppHandle, file_path: &str) -> Result<std::path::PathBuf, AppError> {
    let hash = hash_file_path(file_path);
    let mut path = app
        .path()
        .app_data_dir()
        .map_err(|e| AppError::Internal(e.to_string()))?;
    path.push("markers");
    path.push(format!("{hash}.json"));
    Ok(path)
}

// ── Commands ─────────────────────────────────────────────────────────────────

/// Load persisted markers for a file. Returns `None` if no marker file exists.
#[tauri::command]
pub fn load_markers(
    file_path: String,
    app: AppHandle,
) -> Result<Option<MarkerFile>, AppError> {
    let path = marker_file_path(&app, &file_path)?;

    if !path.exists() {
        return Ok(None);
    }

    let content = fs::read_to_string(&path)?;
    let marker_file: MarkerFile = serde_json::from_str(&content).map_err(|e| AppError::Parse {
        file: path.to_string_lossy().into_owned(),
        reason: e.to_string(),
    })?;

    Ok(Some(marker_file))
}

/// Persist markers for a file, creating the markers directory if needed.
#[tauri::command]
pub fn save_markers(
    file_path: String,
    marker_file: MarkerFile,
    app: AppHandle,
) -> Result<(), AppError> {
    let path = marker_file_path(&app, &file_path)?;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let content = serde_json::to_string_pretty(&marker_file).map_err(|e| AppError::Parse {
        file: path.to_string_lossy().into_owned(),
        reason: e.to_string(),
    })?;

    fs::write(&path, content)?;
    Ok(())
}

/// Delete the persisted marker file for a given source file, if it exists.
#[tauri::command]
pub fn delete_markers(file_path: String, app: AppHandle) -> Result<(), AppError> {
    let path = marker_file_path(&app, &file_path)?;

    if path.exists() {
        fs::remove_file(&path)?;
    }

    Ok(())
}
