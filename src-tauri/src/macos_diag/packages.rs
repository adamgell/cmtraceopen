use super::models::{MacosPackageFiles, MacosPackageInfo, MacosPackagesResult};
use regex::Regex;
use std::sync::OnceLock;

fn pkg_id_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| Regex::new(r"^[a-zA-Z0-9._-]+$").unwrap())
}

// ---------------------------------------------------------------------------
// Parsing helpers (cross-platform, always compiled, fully testable)
// ---------------------------------------------------------------------------

/// Parses the output of `pkgutil --pkgs` — one package ID per line.
pub fn parse_pkgutil_pkgs_output(output: &str) -> Vec<String> {
    output
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect()
}

/// Filters a list of package IDs down to Microsoft-related ones.
///
/// Matches packages whose ID contains "microsoft" (case-insensitive) or
/// the Apple mobile-device package that is relevant to MDM workflows.
pub fn filter_microsoft_packages(packages: &[String]) -> Vec<String> {
    packages
        .iter()
        .filter(|pkg| {
            let lower = pkg.to_lowercase();
            lower.contains("microsoft") || lower == "com.apple.pkg.mobiledevice"
        })
        .cloned()
        .collect()
}

/// Parses the output of `pkgutil --pkg-info <id>`.
///
/// Example:
/// ```text
/// package-id: com.microsoft.wdav
/// version: 101.25012.0002
/// volume: /
/// location: /
/// install-time: 1710789785
/// ```
pub fn parse_pkgutil_pkg_info(output: &str) -> MacosPackageInfo {
    let mut package_id = String::new();
    let mut version = String::new();
    let mut volume: Option<String> = None;
    let mut location: Option<String> = None;
    let mut install_time: Option<String> = None;

    for line in output.lines() {
        let line = line.trim();
        if let Some((key, value)) = line.split_once(':') {
            let key = key.trim();
            let value = value.trim();
            match key {
                "package-id" => package_id = value.to_string(),
                "version" => version = value.to_string(),
                "volume" => volume = Some(value.to_string()),
                "location" => location = Some(value.to_string()),
                "install-time" => install_time = Some(value.to_string()),
                _ => {}
            }
        }
    }

    MacosPackageInfo {
        package_id,
        version,
        volume,
        location,
        install_time,
    }
}

/// Parses the output of `pkgutil --files <id>` — one file path per line.
pub fn parse_pkgutil_files(output: &str, package_id: &str) -> MacosPackageFiles {
    let files: Vec<String> = output
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();
    let file_count = files.len();
    MacosPackageFiles {
        package_id: package_id.to_string(),
        files,
        file_count,
    }
}

/// Validates that a package ID contains only safe characters before passing
/// it to a shell command. Prevents command injection.
pub fn validate_package_id(id: &str) -> Result<(), crate::error::AppError> {
    if pkg_id_re().is_match(id) {
        Ok(())
    } else {
        Err(crate::error::AppError::InvalidInput(format!(
            "Invalid package ID '{}': must contain only alphanumeric characters, dots, hyphens, and underscores",
            id
        )))
    }
}

// ---------------------------------------------------------------------------
// macOS implementation
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
pub fn list_packages_impl() -> Result<MacosPackagesResult, crate::error::AppError> {
    use std::process::Command;

    log::info!("Listing installed packages via pkgutil");

    let output = Command::new("pkgutil")
        .arg("--pkgs")
        .output()
        .map_err(crate::error::AppError::Io)?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(crate::error::AppError::Internal(format!(
            "pkgutil --pkgs failed: {}",
            stderr
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let all_packages = parse_pkgutil_pkgs_output(&stdout);
    let total_count = all_packages.len();

    let ms_ids = filter_microsoft_packages(&all_packages);
    let microsoft_count = ms_ids.len();

    // Get detailed info for each Microsoft package
    let mut packages: Vec<MacosPackageInfo> = Vec::new();
    for pkg_id in &ms_ids {
        let info_output = Command::new("pkgutil")
            .args(["--pkg-info", pkg_id])
            .output();

        match info_output {
            Ok(out) if out.status.success() => {
                let info_str = String::from_utf8_lossy(&out.stdout);
                packages.push(parse_pkgutil_pkg_info(&info_str));
            }
            Ok(out) => {
                log::warn!(
                    "pkgutil --pkg-info {} exited {}: {}",
                    pkg_id,
                    out.status,
                    String::from_utf8_lossy(&out.stderr)
                );
                // Still add a minimal entry
                packages.push(MacosPackageInfo {
                    package_id: pkg_id.clone(),
                    version: String::new(),
                    volume: None,
                    location: None,
                    install_time: None,
                });
            }
            Err(e) => {
                log::warn!("Failed to get info for {}: {}", pkg_id, e);
            }
        }
    }

    Ok(MacosPackagesResult {
        packages,
        total_count,
        microsoft_count,
    })
}

#[cfg(target_os = "macos")]
pub fn get_package_info_impl(package_id: &str) -> Result<MacosPackageInfo, crate::error::AppError> {
    use std::process::Command;

    validate_package_id(package_id)?;

    log::info!("Getting package info for: {}", package_id);

    let output = Command::new("pkgutil")
        .args(["--pkg-info", package_id])
        .output()
        .map_err(crate::error::AppError::Io)?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(crate::error::AppError::Internal(format!(
            "pkgutil --pkg-info {} failed: {}",
            package_id, stderr
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_pkgutil_pkg_info(&stdout))
}

#[cfg(target_os = "macos")]
pub fn get_package_files_impl(
    package_id: &str,
) -> Result<MacosPackageFiles, crate::error::AppError> {
    use std::process::Command;

    validate_package_id(package_id)?;

    log::info!("Getting package files for: {}", package_id);

    let output = Command::new("pkgutil")
        .args(["--files", package_id])
        .output()
        .map_err(crate::error::AppError::Io)?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(crate::error::AppError::Internal(format!(
            "pkgutil --files {} failed: {}",
            package_id, stderr
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_pkgutil_files(&stdout, package_id))
}

// ---------------------------------------------------------------------------
// Non-macOS stubs
// ---------------------------------------------------------------------------

#[cfg(not(target_os = "macos"))]
pub fn list_packages_impl() -> Result<MacosPackagesResult, crate::error::AppError> {
    Err(crate::error::AppError::PlatformUnsupported(
        "macOS Diagnostics is only available on macOS.".to_string(),
    ))
}

#[cfg(not(target_os = "macos"))]
pub fn get_package_info_impl(
    _package_id: &str,
) -> Result<MacosPackageInfo, crate::error::AppError> {
    Err(crate::error::AppError::PlatformUnsupported(
        "macOS Diagnostics is only available on macOS.".to_string(),
    ))
}

#[cfg(not(target_os = "macos"))]
pub fn get_package_files_impl(
    _package_id: &str,
) -> Result<MacosPackageFiles, crate::error::AppError> {
    Err(crate::error::AppError::PlatformUnsupported(
        "macOS Diagnostics is only available on macOS.".to_string(),
    ))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_pkgutil_pkgs_output() {
        let input = "com.apple.pkg.Core\ncom.microsoft.wdav\ncom.microsoft.teams\n";
        let pkgs = parse_pkgutil_pkgs_output(input);
        assert_eq!(pkgs.len(), 3);
        assert_eq!(pkgs[0], "com.apple.pkg.Core");
        assert_eq!(pkgs[1], "com.microsoft.wdav");
    }

    #[test]
    fn test_parse_pkgutil_pkgs_empty() {
        let pkgs = parse_pkgutil_pkgs_output("");
        assert!(pkgs.is_empty());
    }

    #[test]
    fn test_filter_microsoft_packages() {
        let all = vec![
            "com.apple.pkg.Core".to_string(),
            "com.microsoft.wdav".to_string(),
            "com.Microsoft.Teams".to_string(),
            "com.apple.pkg.MobileDevice".to_string(),
            "com.google.chrome".to_string(),
        ];
        let filtered = filter_microsoft_packages(&all);
        assert_eq!(filtered.len(), 3);
        assert!(filtered.contains(&"com.microsoft.wdav".to_string()));
        assert!(filtered.contains(&"com.Microsoft.Teams".to_string()));
        assert!(filtered.contains(&"com.apple.pkg.MobileDevice".to_string()));
    }

    #[test]
    fn test_parse_pkgutil_pkg_info() {
        let input = "package-id: com.microsoft.wdav\nversion: 101.25012.0002\nvolume: /\nlocation: /\ninstall-time: 1710789785\n";
        let info = parse_pkgutil_pkg_info(input);
        assert_eq!(info.package_id, "com.microsoft.wdav");
        assert_eq!(info.version, "101.25012.0002");
        assert_eq!(info.volume.as_deref(), Some("/"));
        assert_eq!(info.location.as_deref(), Some("/"));
        assert_eq!(info.install_time.as_deref(), Some("1710789785"));
    }

    #[test]
    fn test_parse_pkgutil_files() {
        let input = "usr/local/bin/mdatp\nusr/local/share/mdatp/config.json\n";
        let files = parse_pkgutil_files(input, "com.microsoft.wdav");
        assert_eq!(files.package_id, "com.microsoft.wdav");
        assert_eq!(files.file_count, 2);
        assert_eq!(files.files[0], "usr/local/bin/mdatp");
    }

    #[test]
    fn test_validate_package_id_valid() {
        assert!(validate_package_id("com.microsoft.wdav").is_ok());
        assert!(validate_package_id("com.apple.pkg.Core").is_ok());
        assert!(validate_package_id("my-package_1.0").is_ok());
    }

    #[test]
    fn test_validate_package_id_invalid() {
        assert!(validate_package_id("com.evil; rm -rf /").is_err());
        assert!(validate_package_id("$(whoami)").is_err());
        assert!(validate_package_id("pkg id with spaces").is_err());
        assert!(validate_package_id("").is_err());
    }
}
