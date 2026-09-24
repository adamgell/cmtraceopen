use super::models::ScriptExecutionResult;
use crate::error::AppError;

const DETECT_SCRIPT: &str = include_str!("scripts/Detect-SecureBootCertificateUpdate.ps1");

const REMEDIATE_SCRIPT: &str = include_str!("scripts/Remediate-SecureBootCertificateUpdate.ps1");

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

/// Quote a value for interpolation inside a single-quoted PowerShell string.
///
/// PowerShell escapes a literal `'` by doubling it, so `O'Brien` becomes
/// `'O''Brien'`. Temp paths carry the user name, so an apostrophe in it would
/// otherwise terminate the string early and turn path text into PowerShell
/// syntax — inside a process that runs elevated.
#[cfg(any(target_os = "windows", test))]
fn ps_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

// ---------------------------------------------------------------------------
// Platform implementation
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
fn run_script(script_content: &str) -> Result<ScriptExecutionResult, AppError> {
    use std::io::Write as _;

    // Write the actual script to a temporary .ps1 file.
    let mut script_file = tempfile::Builder::new()
        .suffix(".ps1")
        .tempfile()
        .map_err(|e: std::io::Error| AppError::Io(e))?;

    script_file
        .write_all(script_content.as_bytes())
        .map_err(AppError::Io)?;

    let script_path = script_file.into_temp_path();
    let script_path_str = script_path.to_string_lossy().to_string();

    // Temp files for capturing output from the elevated process.
    // Start-Process -Verb RunAs cannot use -RedirectStandardOutput, so the
    // elevated child writes to these files itself via a wrapper script.
    let stdout_path = tempfile::Builder::new()
        .suffix(".stdout")
        .tempfile()
        .map_err(AppError::Io)?
        .into_temp_path();
    let stderr_path = tempfile::Builder::new()
        .suffix(".stderr")
        .tempfile()
        .map_err(AppError::Io)?
        .into_temp_path();
    let exitcode_path = tempfile::Builder::new()
        .suffix(".exitcode")
        .tempfile()
        .map_err(AppError::Io)?
        .into_temp_path();

    let stdout_str = stdout_path.to_string_lossy().to_string();
    let stderr_str = stderr_path.to_string_lossy().to_string();
    let exitcode_str = exitcode_path.to_string_lossy().to_string();

    // Write a small wrapper script that the elevated process will execute.
    // It runs the real script, redirects all streams (including Write-Host
    // via *>&1) to the stdout capture file, and writes the exit code.
    let wrapper_content = format!(
        "& {} *> {} 2> {}\r\n\
         $LASTEXITCODE | Out-File -FilePath {} -Encoding ascii -NoNewline\r\n",
        ps_single_quote(&script_path_str),
        ps_single_quote(&stdout_str),
        ps_single_quote(&stderr_str),
        ps_single_quote(&exitcode_str),
    );

    let mut wrapper_file = tempfile::Builder::new()
        .suffix("_wrapper.ps1")
        .tempfile()
        .map_err(AppError::Io)?;

    wrapper_file
        .write_all(wrapper_content.as_bytes())
        .map_err(AppError::Io)?;

    let wrapper_path = wrapper_file.into_temp_path();
    let wrapper_path_str = wrapper_path.to_string_lossy().to_string();

    // Launch the wrapper elevated via Start-Process -Verb RunAs.
    // This triggers the UAC prompt. The outer (non-elevated) PowerShell
    // blocks on -Wait until the elevated process exits.
    let _output = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            &format!(
                "Start-Process -FilePath 'powershell.exe' \
                 -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File',{} \
                 -Verb RunAs -WindowStyle Hidden -Wait",
                ps_single_quote(&wrapper_path_str),
            ),
        ])
        .output()
        .map_err(AppError::Io)?;

    // Read captured output from the temp files.
    let stdout_content = std::fs::read_to_string(&*stdout_path).unwrap_or_default();
    let stderr_content = std::fs::read_to_string(&*stderr_path).unwrap_or_default();
    let exit_code = std::fs::read_to_string(&*exitcode_path)
        .ok()
        .and_then(|s| s.trim().parse::<i32>().ok())
        .unwrap_or(-1);

    // Temp paths are cleaned up on drop.
    drop(script_path);
    drop(stdout_path);
    drop(stderr_path);
    drop(exitcode_path);
    drop(wrapper_path);

    Ok(ScriptExecutionResult {
        exit_code,
        stdout: stdout_content,
        stderr: stderr_content,
    })
}

#[cfg(not(target_os = "windows"))]
fn run_script(_script_content: &str) -> Result<ScriptExecutionResult, AppError> {
    Err(AppError::PlatformUnsupported(
        "Secure Boot script execution requires Windows".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::ps_single_quote;

    #[test]
    fn quotes_a_plain_path() {
        assert_eq!(
            ps_single_quote(r"C:\Windows\Temp\script.ps1"),
            r"'C:\Windows\Temp\script.ps1'"
        );
    }

    #[test]
    fn doubles_an_apostrophe_so_the_string_does_not_terminate_early() {
        // A user name reaches every temp path. `O'Brien` would otherwise close
        // the PowerShell string at the apostrophe and turn the rest of the
        // path into syntax, inside a process launched elevated.
        assert_eq!(
            ps_single_quote(r"C:\Users\O'Brien\AppData\Local\Temp\x.ps1"),
            r"'C:\Users\O''Brien\AppData\Local\Temp\x.ps1'"
        );
    }

    #[test]
    fn output_quotes_stay_balanced_for_a_realistic_temp_path() {
        // The observable invariant: an unescaped apostrophe leaves an odd
        // number of single quotes, which is what breaks the interpreter.
        let quoted = ps_single_quote(r"C:\Users\O'Brien\AppData\Local\Temp\wrapper.ps1");
        assert_eq!(quoted.matches('\'').count() % 2, 0, "{quoted}");
    }

    #[test]
    fn handles_a_value_that_is_only_an_apostrophe() {
        assert_eq!(ps_single_quote("'"), "''''");
    }
}
