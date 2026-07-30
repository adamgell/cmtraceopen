use std::path::PathBuf;

use crate::error::AppError;
use crate::jamf::models::{
    JamfConnectEvent, JamfEnvironment, JamfLogScanResult, JamfPolicyLogResult,
    JamfProfilesResult, JamfSelfServiceEvent,
};
use crate::jamf::paths;
use crate::macos_diag::environment::scan_log_directory;
use crate::macos_diag::models::MacosLogFileEntry;

#[tauri::command]
pub fn jamf_collect_environment() -> Result<JamfEnvironment, AppError> {
    crate::jamf::detect::collect_environment_impl()
}

/// Treats `Some("")` the same as `None`, so a cleared input field falls back to
/// the canonical path instead of trying to open the current directory. Expands a
/// leading `~/` against `$HOME`.
fn resolve_path(path: Option<String>, default: impl FnOnce() -> PathBuf) -> PathBuf {
    path.map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .map(|s| match s.strip_prefix("~/") {
            Some(rest) => paths::home_dir().join(rest),
            None => PathBuf::from(s),
        })
        .unwrap_or_else(default)
}

#[tauri::command]
pub fn jamf_parse_policy_log(path: Option<String>) -> Result<JamfPolicyLogResult, AppError> {
    let p = resolve_path(path, || PathBuf::from(paths::JAMF_LOG));
    crate::jamf::policy_log::parse_policy_log_impl(&p)
}

#[tauri::command]
pub fn jamf_parse_self_service_log(
    path: Option<String>,
) -> Result<Vec<JamfSelfServiceEvent>, AppError> {
    let p = resolve_path(path, paths::self_service_log_file);
    crate::jamf::self_service::parse_self_service_log_impl(&p)
}

#[tauri::command]
pub fn jamf_parse_connect_log(path: Option<String>) -> Result<Vec<JamfConnectEvent>, AppError> {
    let p = resolve_path(path, || PathBuf::from(paths::JAMF_CONNECT_LOG_SYSTEM));
    crate::jamf::connect::parse_connect_log_impl(&p)
}

#[tauri::command]
pub fn jamf_scan_logs() -> Result<JamfLogScanResult, AppError> {
    let mut all_files: Vec<MacosLogFileEntry> = Vec::new();
    let mut scanned: Vec<String> = Vec::new();
    let mut total: u64 = 0;

    let candidates: Vec<PathBuf> = vec![
        paths::jamf_app_logs_dir(),
        paths::jamf_user_logs_dir(),
        paths::connect_user_logs_dir(),
    ];

    for dir in candidates {
        let dir_str = dir.to_string_lossy();
        let files = scan_log_directory(dir_str.as_ref());
        if !files.is_empty() {
            for f in &files {
                total = total.saturating_add(f.size_bytes);
            }
            scanned.push(dir_str.into_owned());
            all_files.extend(files);
        }
    }

    // Standalone files (jamf.log, JAMFConnect.log) — wrap as MacosLogFileEntry.
    for path in [paths::JAMF_LOG, paths::JAMF_CONNECT_LOG_SYSTEM] {
        let p = PathBuf::from(path);
        if p.is_file() {
            if let Ok(meta) = std::fs::metadata(&p) {
                let size = meta.len();
                total = total.saturating_add(size);
                all_files.push(MacosLogFileEntry {
                    path: p.to_string_lossy().into_owned(),
                    file_name: p
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default(),
                    size_bytes: size,
                    modified_unix_ms: meta
                        .modified()
                        .ok()
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|d| d.as_millis() as u64),
                    source_directory: p
                        .parent()
                        .map(|d| d.to_string_lossy().into_owned())
                        .unwrap_or_default(),
                });
            }
        }
    }

    Ok(JamfLogScanResult {
        files: all_files,
        scanned_directories: scanned,
        total_size_bytes: total,
    })
}

#[tauri::command]
pub fn jamf_filter_profiles(
    expected_organization: Option<String>,
) -> Result<JamfProfilesResult, AppError> {
    let macos_result = crate::macos_diag::profiles::list_profiles_impl()?;
    crate::jamf::profiles::filter_jamf_profiles_impl(
        macos_result.profiles,
        expected_organization.as_deref(),
    )
}
