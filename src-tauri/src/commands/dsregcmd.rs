use crate::dsregcmd::{analyze_text, DsregcmdAnalysisResult};

#[tauri::command]
pub fn analyze_dsregcmd(input: String) -> Result<DsregcmdAnalysisResult, String> {
    eprintln!(
        "event=dsregcmd_analysis_start input_chars={} input_lines={}",
        input.len(),
        input.lines().count()
    );

    let result = analyze_text(&input)?;

    eprintln!(
        "event=dsregcmd_analysis_complete diagnostics_count={} join_type={:?}",
        result.diagnostics.len(),
        result.derived.join_type
    );

    Ok(result)
}

#[tauri::command]
pub fn capture_dsregcmd() -> Result<String, String> {
    capture_dsregcmd_impl()
}

#[cfg(target_os = "windows")]
fn capture_dsregcmd_impl() -> Result<String, String> {
    eprintln!("event=dsregcmd_capture_start platform=windows");

    let output = std::process::Command::new("dsregcmd.exe")
        .arg("/status")
        .output()
        .map_err(|error| format!("Failed to execute dsregcmd.exe /status: {}", error))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let exit_code = output.status.code().unwrap_or_default();
        return Err(if stderr.is_empty() {
            format!("dsregcmd.exe /status failed with exit code {}", exit_code)
        } else {
            format!(
                "dsregcmd.exe /status failed with exit code {}: {}",
                exit_code, stderr
            )
        });
    }

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    eprintln!(
        "event=dsregcmd_capture_complete platform=windows stdout_chars={} stdout_lines={}",
        stdout.len(),
        stdout.lines().count()
    );
    Ok(stdout)
}

#[cfg(not(target_os = "windows"))]
fn capture_dsregcmd_impl() -> Result<String, String> {
    Err("dsregcmd capture is only supported on Windows.".to_string())
}

#[cfg(test)]
mod tests {
    use super::capture_dsregcmd;

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn capture_command_returns_clear_error_on_unsupported_platform() {
        let error = capture_dsregcmd().expect_err("expected unsupported platform error");
        assert!(error.contains("only supported on Windows"));
    }
}
