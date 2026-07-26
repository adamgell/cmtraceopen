use super::models::{MacosDefenderHealthStatus, MacosDefenderResult};
#[cfg(target_os = "macos")]
use super::{environment::scan_log_directory, models::MacosLogFileEntry};

// ---------------------------------------------------------------------------
// Parsing helpers (cross-platform, always compiled, fully testable)
// ---------------------------------------------------------------------------

/// Parses the key-value output of `mdatp health`.
///
/// Example:
/// ```text
/// healthy                                     : true
/// health_issues                               : []
/// licensed                                    : true
/// engine_version                              : "1.1.24050.7"
/// app_version                                 : "101.24052.0002"
/// real_time_protection_enabled                : true
/// definitions_status                          : "up_to_date"
/// ```
pub fn parse_mdatp_health_output(output: &str) -> MacosDefenderHealthStatus {
    let mut healthy: Option<bool> = None;
    let mut health_issues: Vec<String> = Vec::new();
    let mut real_time_protection_enabled: Option<bool> = None;
    let mut definitions_status: Option<String> = None;
    let mut engine_version: Option<String> = None;
    let mut app_version: Option<String> = None;

    for line in output.lines() {
        let line = line.trim();
        // Split on " : " (with surrounding spaces) to separate key from value
        let parts: Vec<&str> = line.splitn(2, ':').collect();
        if parts.len() != 2 {
            continue;
        }
        let key = parts[0].trim();
        let value = parts[1].trim().trim_matches('"');

        match key {
            "healthy" => {
                healthy = Some(value.eq_ignore_ascii_case("true"));
            }
            "health_issues" => {
                // Value is like [] or ["issue1","issue2"]
                let inner = value.trim_start_matches('[').trim_end_matches(']').trim();
                if !inner.is_empty() {
                    for issue in inner.split(',') {
                        let issue = issue.trim().trim_matches('"').trim();
                        if !issue.is_empty() {
                            health_issues.push(issue.to_string());
                        }
                    }
                }
            }
            "real_time_protection_enabled" => {
                real_time_protection_enabled = Some(value.eq_ignore_ascii_case("true"));
            }
            "definitions_status" => {
                definitions_status = Some(value.to_string());
            }
            "engine_version" => {
                engine_version = Some(value.to_string());
            }
            "app_version" => {
                app_version = Some(value.to_string());
            }
            _ => {}
        }
    }

    MacosDefenderHealthStatus {
        healthy,
        health_issues,
        real_time_protection_enabled,
        definitions_status,
        engine_version,
        app_version,
        raw_output: output.to_string(),
    }
}

// ---------------------------------------------------------------------------
// macOS implementation
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
pub fn inspect_defender_impl() -> Result<MacosDefenderResult, crate::error::AppError> {
    use std::process::Command;

    log::info!("Inspecting Microsoft Defender for macOS");

    // --- Health ---
    let health = {
        let output = Command::new("mdatp").arg("health").output();
        match output {
            Ok(out) if out.status.success() => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                Some(parse_mdatp_health_output(&stdout))
            }
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                log::warn!("mdatp health exited with status {}: {}", out.status, stderr);
                // Still try to parse whatever output we got
                let stdout = String::from_utf8_lossy(&out.stdout);
                if stdout.trim().is_empty() {
                    None
                } else {
                    Some(parse_mdatp_health_output(&stdout))
                }
            }
            Err(e) => {
                log::info!("mdatp not available: {}", e);
                None
            }
        }
    };

    // --- Log files ---
    let log_files: Vec<MacosLogFileEntry> = scan_log_directory("/Library/Logs/Microsoft/mdatp/");

    // --- Diagnostic files ---
    let diag_files: Vec<MacosLogFileEntry> =
        scan_log_directory("/Library/Application Support/Microsoft/Defender/wdavdiag/");

    Ok(MacosDefenderResult {
        health,
        log_files,
        diag_files,
    })
}

#[cfg(not(target_os = "macos"))]
pub fn inspect_defender_impl() -> Result<MacosDefenderResult, crate::error::AppError> {
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
    fn test_parse_mdatp_health_healthy() {
        let input = r#"healthy                                     : true
health_issues                               : []
licensed                                    : true
engine_version                              : "1.1.24050.7"
app_version                                 : "101.24052.0002"
real_time_protection_enabled                : true
definitions_status                          : "up_to_date"
"#;
        let result = parse_mdatp_health_output(input);
        assert_eq!(result.healthy, Some(true));
        assert!(result.health_issues.is_empty());
        assert_eq!(result.real_time_protection_enabled, Some(true));
        assert_eq!(result.definitions_status.as_deref(), Some("up_to_date"));
        assert_eq!(result.engine_version.as_deref(), Some("1.1.24050.7"));
        assert_eq!(result.app_version.as_deref(), Some("101.24052.0002"));
    }

    #[test]
    fn test_parse_mdatp_health_unhealthy() {
        let input = r#"healthy                                     : false
health_issues                               : ["no license found","definitions out of date"]
real_time_protection_enabled                : false
"#;
        let result = parse_mdatp_health_output(input);
        assert_eq!(result.healthy, Some(false));
        assert_eq!(result.health_issues.len(), 2);
        assert_eq!(result.health_issues[0], "no license found");
        assert_eq!(result.health_issues[1], "definitions out of date");
        assert_eq!(result.real_time_protection_enabled, Some(false));
    }

    #[test]
    fn test_parse_mdatp_health_empty() {
        let result = parse_mdatp_health_output("");
        assert!(result.healthy.is_none());
        assert!(result.health_issues.is_empty());
        assert!(result.real_time_protection_enabled.is_none());
    }
}
