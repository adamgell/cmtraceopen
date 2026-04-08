pub mod log_parser;
pub mod models;
pub mod rules;
pub mod scanner;
pub mod scripts;
pub mod stage;

use models::{DataSource, SecureBootAnalysisResult, SecureBootScanState};

/// High-level analysis entry point.
///
/// - If `path` is `Some`: read the log file at that path, parse it, determine
///   stage from the log sessions, run rules against a default scan state, and
///   return a `LogImport`-sourced result.
/// - If `path` is `None`: run a live device scan, attempt to auto-discover the
///   default IME log at `%ProgramData%\Microsoft\IntuneManagementExtension\Logs\
///   SecureBootCertificateUpdate.log`, parse it if found, determine stage (scan
///   takes precedence if both are available), run rules, and return a `Both`- or
///   `LiveScan`-sourced result.
pub fn analyze(path: Option<&str>) -> Result<SecureBootAnalysisResult, crate::error::AppError> {
    if let Some(log_path) = path {
        // --- Log-import path ---------------------------------------------------
        let content = std::fs::read_to_string(log_path)
            .map_err(crate::error::AppError::Io)?;

        let (sessions, timeline) = log_parser::parse_log(&content);
        let stage = stage::determine_stage_from_log(&sessions);
        let scan_state = SecureBootScanState::default();
        let diagnostics = rules::evaluate_all(&scan_state, stage, &sessions);

        Ok(SecureBootAnalysisResult {
            stage,
            data_source: DataSource::LogImport,
            scan_state,
            sessions,
            timeline,
            diagnostics,
            script_result: None,
        })
    } else {
        // --- Live-scan path ---------------------------------------------------
        let scan_state = scanner::scan_device()?;

        // Try auto-discover the default log location.
        let auto_log_path = {
            #[cfg(target_os = "windows")]
            {
                std::env::var("ProgramData").ok().map(|pd| {
                    std::path::Path::new(&pd)
                        .join(r"Microsoft\IntuneManagementExtension\Logs\SecureBootCertificateUpdate.log")
                        .to_string_lossy()
                        .into_owned()
                })
            }
            #[cfg(not(target_os = "windows"))]
            {
                None::<String>
            }
        };

        let (sessions, timeline, data_source) = if let Some(ref lp) = auto_log_path {
            if let Ok(content) = std::fs::read_to_string(lp) {
                let (s, t) = log_parser::parse_log(&content);
                (s, t, DataSource::Both)
            } else {
                (vec![], vec![], DataSource::LiveScan)
            }
        } else {
            (vec![], vec![], DataSource::LiveScan)
        };

        // Live scan stage takes precedence; fall back to log stage if scan is ambiguous.
        let stage = stage::determine_stage(&scan_state);
        let diagnostics = rules::evaluate_all(&scan_state, stage, &sessions);

        Ok(SecureBootAnalysisResult {
            stage,
            data_source,
            scan_state,
            sessions,
            timeline,
            diagnostics,
            script_result: None,
        })
    }
}
