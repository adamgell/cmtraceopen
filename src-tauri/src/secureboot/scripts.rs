use super::models::ScriptExecutionResult;
use crate::error::AppError;

const DETECT_SCRIPT: &str =
    include_str!("scripts/Detect-SecureBootCertificateUpdate.ps1");

const REMEDIATE_SCRIPT: &str =
    include_str!("scripts/Remediate-SecureBootCertificateUpdate.ps1");

/// Run the Secure Boot certificate **detection** script.
///
/// Windows-only. On non-Windows platforms returns `AppError::PlatformUnsupported`.
pub fn run_detection() -> Result<ScriptExecutionResult, AppError> {
    run_script(DETECT_SCRIPT)
}

/// Run the Secure Boot certificate **remediation** script.
///
/// Windows-only. On non-Windows platforms returns `AppError::PlatformUnsupported`.
pub fn run_remediation() -> Result<ScriptExecutionResult, AppError> {
    run_script(REMEDIATE_SCRIPT)
}

// ---------------------------------------------------------------------------
// Platform implementation
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
fn run_script(script_content: &str) -> Result<ScriptExecutionResult, AppError> {
    use std::io::Write as _;

    // Write script to a temporary file.
    let mut temp_file = tempfile::Builder::new()
        .suffix(".ps1")
        .tempfile()
        .map_err(|e| AppError::Io(e.into()))?;

    temp_file
        .write_all(script_content.as_bytes())
        .map_err(|e| AppError::Io(e))?;

    // Persist the path so we can pass it to powershell.exe, then delete afterwards.
    let temp_path = temp_file
        .into_temp_path();

    let path_str = temp_path.to_string_lossy().to_string();

    let output = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            &path_str,
        ])
        .output()
        .map_err(AppError::Io)?;

    // temp_path drops here, deleting the file.
    drop(temp_path);

    Ok(ScriptExecutionResult {
        exit_code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

#[cfg(not(target_os = "windows"))]
fn run_script(_script_content: &str) -> Result<ScriptExecutionResult, AppError> {
    Err(AppError::PlatformUnsupported(
        "Secure Boot script execution requires Windows".to_string(),
    ))
}
