use std::fmt::Write as _;
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
    // Formatted byte-by-byte rather than with `{:x}`: sha2 0.11 returns a
    // hybrid-array `Array`, which (unlike generic-array) has no `LowerHex` impl.
    // Output is byte-identical to the old `{:x}`, so existing marker keys survive.
    hasher
        .finalize()
        .iter()
        .fold(String::with_capacity(64), |mut acc, byte| {
            let _ = write!(acc, "{byte:02x}");
            acc
        })
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
pub fn load_markers(file_path: String, app: AppHandle) -> Result<Option<MarkerFile>, AppError> {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// `hash_file_path` names the on-disk marker file, so its output is a storage
    /// key: any change to the encoding orphans every marker a user has saved.
    /// This pins the exact lowercase, zero-padded, 64-char form that `{:x}`
    /// produced before the sha2 0.11 / hybrid-array migration.
    #[test]
    fn hash_file_path_encoding_is_stable() {
        assert_eq!(
            hash_file_path(r"C:\logs\test.log"),
            "2a6f96d670395f2b2072bedc3553e06131f7887b9f943e3971496d0c3f1b1240"
        );
    }

    #[test]
    fn hash_file_path_pads_leading_zero_nibble() {
        // "marker-5" hashes to a digest whose first byte is 0x0b. Formatting per
        // byte with `{:x}` instead of `{:02x}` would emit "b" for that byte and
        // yield a 63-char string, so this pins the zero padding.
        let hash = hash_file_path("marker-5");
        assert_eq!(hash.len(), 64);
        assert_eq!(
            hash,
            "0b58d27bafce39bac0c607e45047a13f95f4ff3d443d447472b9c00a23840d64"
        );
    }
}
