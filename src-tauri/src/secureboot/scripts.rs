use super::models::ScriptExecutionResult;
use crate::error::AppError;

const DETECT_SCRIPT: &str = include_str!("scripts/Detect-SecureBootCertificateUpdate.ps1");

const REMEDIATE_SCRIPT: &str = include_str!("scripts/Remediate-SecureBootCertificateUpdate.ps1");

/// The elevated child's wrapper: runs the requested script, captures its
/// streams and exit code. Static, and parameterised, so no path is ever part
/// of its text.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
const RUN_CAPTURED_SCRIPT: &str = include_str!("scripts/Run-Captured.ps1");

/// Launches the wrapper elevated. Separate from `run_script` so the paths
/// travel as arguments rather than inside a `-Command` string.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
const LAUNCH_ELEVATED_SCRIPT: &str = include_str!("scripts/Launch-Elevated.ps1");

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
    let mut wrapper_file = tempfile::Builder::new()
        .suffix("_wrapper.ps1")
        .tempfile()
        .map_err(AppError::Io)?;

    wrapper_file
        .write_all(wrapper_script().as_bytes())
        .map_err(AppError::Io)?;

    let wrapper_path = wrapper_file.into_temp_path();
    let wrapper_path_str = wrapper_path.to_string_lossy().to_string();

    let mut launcher_file = tempfile::Builder::new()
        .suffix("_launch.ps1")
        .tempfile()
        .map_err(AppError::Io)?;

    launcher_file
        .write_all(LAUNCH_ELEVATED_SCRIPT.as_bytes())
        .map_err(AppError::Io)?;

    let launcher_path = launcher_file.into_temp_path();
    let launcher_path_str = launcher_path.to_string_lossy().to_string();

    // Launch the wrapper elevated via Start-Process -Verb RunAs.
    // This triggers the UAC prompt. The outer (non-elevated) PowerShell
    // blocks on -Wait until the elevated process exits.
    let _output = std::process::Command::new("powershell.exe")
        .args(launch_args(
            &launcher_path_str,
            &wrapper_path_str,
            &script_path_str,
            &stdout_str,
            &stderr_str,
            &exitcode_str,
        ))
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
    drop(launcher_path);

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

// ---------------------------------------------------------------------------
// Command text
// ---------------------------------------------------------------------------

/// The wrapper script the elevated process runs.
///
/// Static text: every path arrives as a parameter, so nothing here can be
/// turned into syntax by a path that contains a quote character.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn wrapper_script() -> &'static str {
    RUN_CAPTURED_SCRIPT
}

/// The argument vector that launches the wrapper elevated.
///
/// The paths are arguments, not text. `Start-Process -Verb RunAs` needs a
/// command string, which is why the launcher is a file: this vector names it
/// and hands it the paths, and the launcher passes them on as an argument
/// array that PowerShell builds the child command line from.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn launch_args(
    launcher_path: &str,
    wrapper_path: &str,
    script_path: &str,
    stdout_path: &str,
    stderr_path: &str,
    exitcode_path: &str,
) -> Vec<String> {
    [
        ("-NoProfile", None),
        ("-ExecutionPolicy", None),
        ("Bypass", None),
        ("-File", Some(launcher_path)),
        ("-WrapperPath", Some(wrapper_path)),
        ("-ScriptPath", Some(script_path)),
        ("-StdoutPath", Some(stdout_path)),
        ("-StderrPath", Some(stderr_path)),
        ("-ExitCodePath", Some(exitcode_path)),
    ]
    .iter()
    .flat_map(|(flag, value)| {
        let mut parts = vec![(*flag).to_string()];
        // `-ExecutionPolicy Bypass` is flag-then-value; the rest carry a path.
        parts.extend(value.map(|value| value.to_string()));
        parts
    })
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `%TEMP%` contains the user name, so a user named `O'Brien` produces a
    /// path with an apostrophe in it. Whatever carries that path to PowerShell,
    /// an apostrophe must not be able to end the string that carries it.
    const AWKWARD_PATH: &str = r"C:\Users\O'Brien\AppData\Local\Temp\script.ps1";

    #[test]
    fn neither_script_carries_a_path_as_text() {
        for script in [RUN_CAPTURED_SCRIPT, LAUNCH_ELEVATED_SCRIPT] {
            assert!(
                script.contains("param("),
                "each script must take its paths as parameters"
            );
            assert!(
                !script.contains(":\\"),
                "a literal path must not appear in the script text"
            );
            assert!(!script.contains(AWKWARD_PATH));
        }
    }

    #[test]
    fn an_awkward_path_is_delivered_as_one_argument() {
        let args = launch_args(
            AWKWARD_PATH,
            AWKWARD_PATH,
            AWKWARD_PATH,
            "out",
            "err",
            "code",
        );

        // The path arrives whole. Without this the assertion above could be
        // satisfied by dropping the path rather than by carrying it safely.
        assert_eq!(
            args.iter().filter(|arg| *arg == AWKWARD_PATH).count(),
            3,
            "each path must be its own argument: {args:?}"
        );

        // Nothing was concatenated into a larger string: every element is a
        // single value, so no element can be re-parsed as more than one.
        assert!(
            args.iter().all(|arg| !arg.contains(' ')),
            "no argument may hold more than one value: {args:?}"
        );

        // And the flags that carry a path are present rather than positional.
        for flag in [
            "-WrapperPath",
            "-ScriptPath",
            "-StdoutPath",
            "-StderrPath",
            "-ExitCodePath",
        ] {
            assert!(
                args.iter().any(|arg| arg == flag),
                "missing {flag}: {args:?}"
            );
        }
    }
}
