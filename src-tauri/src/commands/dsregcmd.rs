use crate::dsregcmd::{analyze_text, DsregcmdAnalysisResult};

#[cfg(target_os = "windows")]
use std::path::{Path, PathBuf};

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

    let dsregcmd_path = resolve_system32_binary("dsregcmd.exe")?;
    verify_dsregcmd_signature(&dsregcmd_path)?;

    let output = std::process::Command::new(&dsregcmd_path)
        .arg("/status")
        .output()
        .map_err(|error| {
            format!(
                "Failed to execute '{}' /status: {}",
                dsregcmd_path.display(),
                error
            )
        })?;

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

#[cfg(target_os = "windows")]
fn resolve_system32_binary(file_name: &str) -> Result<PathBuf, String> {
    let Some(windir) = std::env::var_os("WINDIR") else {
        return Err("WINDIR is not set; could not resolve the Windows system path.".to_string());
    };

    let path = PathBuf::from(windir).join("System32").join(file_name);
    if !path.is_file() {
        return Err(format!(
            "Expected Windows system binary was not found at '{}'.",
            path.display()
        ));
    }

    Ok(path)
}

#[cfg(target_os = "windows")]
fn verify_dsregcmd_signature(dsregcmd_path: &Path) -> Result<(), String> {
    let powershell_path = resolve_system32_binary(r"WindowsPowerShell\v1.0\powershell.exe")?;
    let script = r#"
$sig = Get-AuthenticodeSignature -LiteralPath $args[0]
[pscustomobject]@{
  Status = $sig.Status.ToString()
  Subject = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { $null }
} | ConvertTo-Json -Compress
"#;

    let output = std::process::Command::new(&powershell_path)
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .arg(dsregcmd_path)
        .output()
        .map_err(|error| {
            format!(
                "Failed to verify the digital signature of '{}': {}",
                dsregcmd_path.display(),
                error
            )
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let exit_code = output.status.code().unwrap_or_default();
        return Err(if stderr.is_empty() {
            format!(
                "Digital signature verification failed for '{}' with exit code {}.",
                dsregcmd_path.display(),
                exit_code
            )
        } else {
            format!(
                "Digital signature verification failed for '{}' with exit code {}: {}",
                dsregcmd_path.display(),
                exit_code,
                stderr
            )
        });
    }

    let signature = serde_json::from_slice::<WindowsSignatureCheck>(&output.stdout).map_err(|error| {
        format!(
            "Could not parse the digital signature check output for '{}': {}",
            dsregcmd_path.display(),
            error
        )
    })?;

    if is_expected_dsregcmd_signature(
        signature.status.as_str(),
        signature.subject.as_deref(),
    ) {
        return Ok(());
    }

    Err(format!(
        "Refusing to execute '{}': expected a valid Microsoft digital signature but got status '{}' and subject '{}'.",
        dsregcmd_path.display(),
        signature.status,
        signature.subject.unwrap_or_else(|| "(missing signer subject)".to_string())
    ))
}

#[cfg(target_os = "windows")]
#[derive(serde::Deserialize)]
struct WindowsSignatureCheck {
    #[serde(rename = "Status")]
    status: String,
    #[serde(rename = "Subject")]
    subject: Option<String>,
}

#[cfg(target_os = "windows")]
fn is_expected_dsregcmd_signature(status: &str, subject: Option<&str>) -> bool {
    if !status.eq_ignore_ascii_case("Valid") {
        return false;
    }

    let Some(subject) = subject else {
        return false;
    };

    subject.to_ascii_lowercase().contains("microsoft")
}

#[cfg(test)]
mod tests {
    #[cfg(not(target_os = "windows"))]
    use super::capture_dsregcmd;
    #[cfg(target_os = "windows")]
    use super::is_expected_dsregcmd_signature;

    #[cfg(target_os = "windows")]
    #[test]
    fn expected_signature_requires_valid_microsoft_subject() {
        assert!(is_expected_dsregcmd_signature(
            "Valid",
            Some("CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US")
        ));
        assert!(!is_expected_dsregcmd_signature("UnknownError", Some("CN=Microsoft Windows")));
        assert!(!is_expected_dsregcmd_signature("Valid", Some("CN=Contoso Test")));
        assert!(!is_expected_dsregcmd_signature("Valid", None));
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn capture_command_returns_clear_error_on_unsupported_platform() {
        let error = capture_dsregcmd().expect_err("expected unsupported platform error");
        assert!(error.contains("only supported on Windows"));
    }
}
