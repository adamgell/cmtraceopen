use crate::secureboot::{self, models::SecureBootAnalysisResult, rules, scanner, scripts, stage};

/// Analyze Secure Boot certificate state from an optional log file path.
///
/// If `path` is provided the log file is imported and parsed.
/// If `path` is `None` a live device scan is performed and the default IME
/// log path is auto-discovered.
#[tauri::command]
pub fn analyze_secureboot(
    path: Option<String>,
) -> Result<SecureBootAnalysisResult, crate::error::AppError> {
    log::info!(
        "event=secureboot_analyze path={:?}",
        path.as_deref().unwrap_or("<live scan>")
    );
    secureboot::analyze(path.as_deref())
}

/// Re-scan the device live without using any cached data or log file.
///
/// Runs the Windows registry/WMI scanner, determines the stage from that
/// fresh scan state, evaluates all diagnostic rules, and returns the result.
#[tauri::command]
pub fn rescan_secureboot() -> Result<SecureBootAnalysisResult, crate::error::AppError> {
    log::info!("event=secureboot_rescan");

    let scan_state = scanner::scan_device()?;
    let stage = stage::determine_stage(&scan_state);
    let diagnostics = rules::evaluate_all(&scan_state, stage, &[]);

    Ok(SecureBootAnalysisResult {
        stage,
        data_source: crate::secureboot::models::DataSource::LiveScan,
        scan_state,
        sessions: vec![],
        timeline: vec![],
        diagnostics,
        script_result: None,
    })
}

/// Execute the Secure Boot detection script and return a full re-analysis.
///
/// Runs `Detect-SecureBootCertificateUpdate.ps1`, then performs a full
/// `analyze(None)` so the result includes the latest live scan state with
/// the script's stdout/stderr attached.
#[tauri::command]
pub fn run_secureboot_detection() -> Result<SecureBootAnalysisResult, crate::error::AppError> {
    log::info!("event=secureboot_run_detection");

    let script_result = scripts::run_detection()?;
    let mut result = secureboot::analyze(None)?;
    result.script_result = Some(script_result);
    Ok(result)
}

/// Execute the Secure Boot remediation script and return a full re-analysis.
///
/// Runs `Remediate-SecureBootCertificateUpdate.ps1`, then performs a full
/// `analyze(None)` so the result includes the post-remediation live scan
/// state with the script's stdout/stderr attached.
#[tauri::command]
pub fn run_secureboot_remediation() -> Result<SecureBootAnalysisResult, crate::error::AppError> {
    log::info!("event=secureboot_run_remediation");

    let script_result = scripts::run_remediation()?;
    let mut result = secureboot::analyze(None)?;
    result.script_result = Some(script_result);
    Ok(result)
}
