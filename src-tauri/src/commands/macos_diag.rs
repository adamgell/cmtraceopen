use crate::macos_diag::models::*;

#[tauri::command]
pub fn macos_scan_environment() -> Result<MacosDiagEnvironment, crate::error::AppError> {
    crate::macos_diag::environment::scan_environment_impl()
}

#[tauri::command]
pub fn macos_scan_intune_logs() -> Result<MacosIntuneLogScanResult, crate::error::AppError> {
    macos_scan_intune_logs_impl()
}

#[tauri::command]
pub fn macos_list_profiles() -> Result<MacosProfilesResult, crate::error::AppError> {
    crate::macos_diag::profiles::list_profiles_impl()
}

#[tauri::command]
pub fn macos_inspect_defender() -> Result<MacosDefenderResult, crate::error::AppError> {
    crate::macos_diag::defender::inspect_defender_impl()
}

#[tauri::command]
pub fn macos_list_packages() -> Result<MacosPackagesResult, crate::error::AppError> {
    crate::macos_diag::packages::list_packages_impl()
}

#[tauri::command]
pub fn macos_get_package_info(
    package_id: String,
) -> Result<MacosPackageInfo, crate::error::AppError> {
    crate::macos_diag::packages::get_package_info_impl(&package_id)
}

#[tauri::command]
pub fn macos_get_package_files(
    package_id: String,
) -> Result<MacosPackageFiles, crate::error::AppError> {
    crate::macos_diag::packages::get_package_files_impl(&package_id)
}

#[tauri::command]
pub fn macos_query_unified_log(
    preset_id: String,
    time_range: Option<MacosUnifiedLogTimeRange>,
    result_cap: Option<usize>,
) -> Result<MacosUnifiedLogResult, crate::error::AppError> {
    // Clamp result_cap to a reasonable range to avoid excessive resource usage
    let capped = result_cap.unwrap_or(5000).clamp(1, 50_000);

    crate::macos_diag::unified_log::query_unified_log_impl(&preset_id, time_range, capped)
}

#[tauri::command]
pub fn macos_open_system_settings() -> Result<(), crate::error::AppError> {
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg("x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles")
            .spawn()
            .map_err(|e| {
                crate::error::AppError::Internal(format!("Failed to open System Settings: {}", e))
            })?;
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err(crate::error::AppError::PlatformUnsupported(
            "Opening System Settings is only available on macOS.".to_string(),
        ))
    }
}

// ---------------------------------------------------------------------------
// Intune log scanning
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
fn macos_scan_intune_logs_impl() -> Result<MacosIntuneLogScanResult, crate::error::AppError> {
    use crate::macos_diag::environment::scan_log_directory;

    log::info!("Scanning Intune log directories on macOS");

    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());

    let directories = vec![
        "/Library/Logs/Microsoft/Intune/".to_string(),
        format!("{}/Library/Logs/Microsoft/Intune/", home),
        format!("{}/Library/Logs/CompanyPortal/", home),
        "/Library/Logs/Microsoft/IntuneScripts/".to_string(),
    ];

    let mut all_files: Vec<MacosLogFileEntry> = Vec::new();
    let mut scanned_directories: Vec<String> = Vec::new();

    for dir in &directories {
        let files = scan_log_directory(dir);
        if !files.is_empty() {
            scanned_directories.push(dir.clone());
        }
        all_files.extend(files);
    }

    // Also add directories that exist but have no files
    for dir in &directories {
        if std::path::Path::new(dir).is_dir() && !scanned_directories.contains(dir) {
            scanned_directories.push(dir.clone());
        }
    }

    let total_size_bytes: u64 = all_files.iter().map(|f| f.size_bytes).sum();

    Ok(MacosIntuneLogScanResult {
        files: all_files,
        scanned_directories,
        total_size_bytes,
    })
}

#[cfg(not(target_os = "macos"))]
fn macos_scan_intune_logs_impl() -> Result<MacosIntuneLogScanResult, crate::error::AppError> {
    Err(crate::error::AppError::PlatformUnsupported(
        "macOS Diagnostics is only available on macOS.".to_string(),
    ))
}
