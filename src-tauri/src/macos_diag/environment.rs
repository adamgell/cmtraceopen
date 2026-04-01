use super::models::MacosDiagEnvironment;
#[cfg(target_os = "macos")]
use super::models::{FdaStatus, MacosDiagDirectoryStatus, MacosDiagToolAvailability};
use super::models::MacosLogFileEntry;
use std::path::Path;
use std::time::UNIX_EPOCH;

// ---------------------------------------------------------------------------
// Parsing helpers (cross-platform, always compiled, fully testable)
// ---------------------------------------------------------------------------

/// Parses the combined output of `sw_vers` into (version, build).
///
/// Expected format:
/// ```text
/// ProductName:    macOS
/// ProductVersion: 14.5
/// BuildVersion:   23F79
/// ```
pub fn parse_sw_vers_output(output: &str) -> (String, String) {
    let mut version = String::new();
    let mut build = String::new();

    for line in output.lines() {
        let line = line.trim();
        if let Some(val) = line.strip_prefix("ProductVersion:") {
            version = val.trim().to_string();
        } else if let Some(val) = line.strip_prefix("BuildVersion:") {
            build = val.trim().to_string();
        }
    }

    (version, build)
}

/// Scans a directory for log files and returns an entry for each regular file.
///
/// This function is intentionally NOT cfg-gated so it can be unit-tested on any
/// platform. It is used by both the Intune logs and Defender tabs.
pub fn scan_log_directory(dir: &str) -> Vec<MacosLogFileEntry> {
    let dir_path = Path::new(dir);
    if !dir_path.is_dir() {
        return Vec::new();
    }

    let mut entries = Vec::new();
    let read_dir = match std::fs::read_dir(dir_path) {
        Ok(rd) => rd,
        Err(e) => {
            log::warn!("Unable to read directory {}: {}", dir, e);
            return Vec::new();
        }
    };

    for entry_result in read_dir {
        let entry = match entry_result {
            Ok(e) => e,
            Err(_) => continue,
        };

        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        let file_name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        let metadata = match std::fs::metadata(&path) {
            Ok(m) => m,
            Err(_) => continue,
        };

        let size_bytes = metadata.len();
        let modified_unix_ms = metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_millis() as u64);

        entries.push(MacosLogFileEntry {
            path: path.to_string_lossy().to_string(),
            file_name,
            size_bytes,
            modified_unix_ms,
            source_directory: dir.to_string(),
        });
    }

    // Sort newest first
    entries.sort_by(|a, b| b.modified_unix_ms.cmp(&a.modified_unix_ms));
    entries
}

// ---------------------------------------------------------------------------
// Resolve home-relative paths
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
fn resolve_home(path: &str) -> String {
    if path.starts_with("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return format!("{}{}", home, &path[1..]);
        }
    }
    path.to_string()
}

// ---------------------------------------------------------------------------
// macOS implementation
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
pub fn scan_environment_impl() -> Result<MacosDiagEnvironment, crate::error::AppError> {
    use std::process::Command;

    log::info!("Scanning macOS diagnostics environment");

    // --- macOS version via sw_vers ---
    let (macos_version, macos_build) = {
        let output = Command::new("sw_vers")
            .output()
            .map_err(crate::error::AppError::Io)?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        parse_sw_vers_output(&stdout)
    };

    // --- Full Disk Access check ---
    let full_disk_access = match std::fs::metadata(
        "/Library/Application Support/com.apple.TCC/TCC.db",
    ) {
        Ok(_) => FdaStatus::Granted,
        Err(e) => {
            let raw = e.raw_os_error();
            if e.kind() == std::io::ErrorKind::PermissionDenied || raw == Some(1) {
                FdaStatus::NotGranted
            } else {
                FdaStatus::Unknown
            }
        }
    };

    // --- Tool availability ---
    let tool_available = |name: &str| -> bool {
        Command::new("which")
            .arg(name)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    };

    let tools = MacosDiagToolAvailability {
        profiles: tool_available("profiles"),
        mdatp: tool_available("mdatp"),
        pkgutil: tool_available("pkgutil"),
        log_command: tool_available("log"),
    };

    // --- Directory presence ---
    let dir_exists = |p: &str| -> bool { Path::new(&resolve_home(p)).is_dir() };

    let directories = MacosDiagDirectoryStatus {
        intune_system_logs: dir_exists("/Library/Logs/Microsoft/Intune/"),
        intune_user_logs: dir_exists("~/Library/Logs/Microsoft/Intune/"),
        company_portal_logs: dir_exists("~/Library/Logs/CompanyPortal/"),
        intune_scripts_logs: dir_exists("/Library/Logs/Microsoft/IntuneScripts/"),
        defender_logs: dir_exists("/Library/Logs/Microsoft/mdatp/"),
        defender_diag: dir_exists(
            "/Library/Application Support/Microsoft/Defender/wdavdiag/",
        ),
    };

    // --- Build summary ---
    let mut issues: Vec<String> = Vec::new();
    if matches!(full_disk_access, FdaStatus::NotGranted) {
        issues.push("Full Disk Access not granted — some logs may be unreadable".into());
    }
    if !tools.profiles {
        issues.push("'profiles' command not found".into());
    }
    if !tools.mdatp {
        issues.push("'mdatp' command not found — Defender may not be installed".into());
    }

    let summary = if issues.is_empty() {
        format!(
            "macOS {} ({}) — all tools available",
            macos_version, macos_build
        )
    } else {
        format!(
            "macOS {} ({}) — {} issue(s): {}",
            macos_version,
            macos_build,
            issues.len(),
            issues.join("; ")
        )
    };

    Ok(MacosDiagEnvironment {
        macos_version,
        macos_build,
        full_disk_access,
        tools,
        directories,
        summary,
    })
}

#[cfg(not(target_os = "macos"))]
pub fn scan_environment_impl() -> Result<MacosDiagEnvironment, crate::error::AppError> {
    Err(crate::error::AppError::PlatformUnsupported("macOS Diagnostics is only available on macOS.".to_string()))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_sw_vers_output() {
        let input = "ProductName:\tmacOS\nProductVersion:\t14.5\nBuildVersion:\t23F79\n";
        let (version, build) = parse_sw_vers_output(input);
        assert_eq!(version, "14.5");
        assert_eq!(build, "23F79");
    }

    #[test]
    fn test_parse_sw_vers_output_empty() {
        let (version, build) = parse_sw_vers_output("");
        assert!(version.is_empty());
        assert!(build.is_empty());
    }

    #[test]
    fn test_parse_sw_vers_with_spaces() {
        let input = "ProductName:    macOS\nProductVersion:    15.0.1\nBuildVersion:    24A348\n";
        let (version, build) = parse_sw_vers_output(input);
        assert_eq!(version, "15.0.1");
        assert_eq!(build, "24A348");
    }

    #[test]
    fn test_scan_log_directory_nonexistent() {
        let entries = scan_log_directory("/this/path/does/not/exist/at/all");
        assert!(entries.is_empty());
    }
}
