//! Software Deployment workspace backend.
//!
//! Scans a folder recursively for deployment logs (MSI, PSADT, Burn, PatchMyPC),
//! classifies each file's format and outcome, extracts exit codes and error context,
//! and returns structured results for the frontend workspace.

use rayon::prelude::*;
use regex::Regex;
use serde::Serialize;
use std::path::Path;

use crate::error_db::lookup::lookup_error_code;
use crate::models::log_entry::{LogEntry, ParserKind, Severity};
use crate::parser;
use crate::parser::burn;
use std::sync::OnceLock;

// ── Types ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub enum DeploymentFormat {
    #[serde(rename = "psadt-cmtrace")]
    PsadtCmtrace,
    #[serde(rename = "psadt-legacy")]
    PsadtLegacy,
    #[serde(rename = "msi-verbose")]
    MsiVerbose,
    #[serde(rename = "psadt-wrapper")]
    PsadtWrapper,
    #[serde(rename = "burn")]
    Burn,
    #[serde(rename = "patchmypc")]
    PatchMyPc,
    #[serde(rename = "unknown")]
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub enum DeploymentOutcome {
    #[serde(rename = "success")]
    Success,
    #[serde(rename = "failure")]
    Failure,
    #[serde(rename = "deferred")]
    Deferred,
    #[serde(rename = "unknown")]
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentErrorLine {
    pub line_number: u32,
    pub message: String,
    pub severity: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentLogFile {
    pub path: String,
    pub file_name: String,
    pub format: DeploymentFormat,
    pub outcome: DeploymentOutcome,
    pub exit_code: Option<i32>,
    pub error_summary: Option<String>,
    pub error_lines: Vec<DeploymentErrorLine>,
    pub app_name: Option<String>,
    pub app_version: Option<String>,
    pub deploy_type: Option<String>,
    pub start_time: Option<String>,
    pub end_time: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentAnalysisResult {
    pub folder_path: String,
    pub files: Vec<DeploymentLogFile>,
    pub total_files: usize,
    pub succeeded: usize,
    pub failed: usize,
    pub deferred: usize,
    pub unknown: usize,
}

// ── Regex patterns ───────────────────────────────────────────────────────

fn msi_main_engine_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
    Regex::new(r"MainEngineThread is returning (\d+)").unwrap()
})
}

fn msi_return_value_3_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
    Regex::new(r"Return value 3\b").unwrap()
})
}

fn psadt_exit_code_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
    Regex::new(r"(?i)exit\s*code\s*[\[:\s]*(\d+)").unwrap()
})
}

/// Burn exit code: "Exit code: 0x0" or "Exit code: 0x80070005" (hex)
fn burn_exit_code_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
    Regex::new(r"(?i)exit\s*code:\s*0x([0-9A-Fa-f]+)").unwrap()
})
}

// MSI metadata: Property(S): ProductName = <value>
fn msi_product_name_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
    Regex::new(r"Property\(S\):\s*ProductName\s*=\s*(.+)").unwrap()
})
}

fn msi_product_version_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
    Regex::new(r"Property\(S\):\s*ProductVersion\s*=\s*(.+)").unwrap()
})
}

// PSADT: Open-ADTSession message contains [Vendor Name Version]
// e.g., "Open-ADTSession [Contoso Foo App 1.2.3]" or in component field
fn psadt_session_info_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
    Regex::new(r"\[([^\]]+)\]").unwrap()
})
}

// Burn: first i001 line e.g. "Burn v3.14.1.8722, Windows v10.0"
fn burn_version_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
    Regex::new(r"Burn v([\d.]+)").unwrap()
})
}

// PatchMyPC: "Starting UserNotification V2.1.100.317"
fn patchmypc_version_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
    Regex::new(r"(?i)Starting\s+UserNotification\s+V([\d.]+)").unwrap()
})
}

// MSI command line: /i = install, /x = uninstall, /f = repair
fn msi_cmdline_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
    Regex::new(r"(?i)CommandLine:\s+(.*)").unwrap()
})
}

// PSADT deploy type: "installationType [Install]" or in the session message
fn psadt_deploy_type_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
    Regex::new(r"(?i)(?:deployment\s*type|installation\s*type|deploy\s*mode)\s*[:\s]*\[?\s*(Install|Uninstall|Repair)\b").unwrap()
})
}

// ── PSADT keywords ──────────────────────────────────────────────────────

const PSADT_KEYWORDS: &[&str] = &[
    "Open-ADTSession",
    "Close-ADTSession",
    "PSAppDeployToolkit",
    "Start-ADTMsiProcess",
    "ADTSession",
];

// ── Format classification ───────────────────────────────────────────────

fn classify_format(
    parser_kind: ParserKind,
    entries: &[LogEntry],
    file_path: &str,
) -> DeploymentFormat {
    match parser_kind {
        ParserKind::Msi => DeploymentFormat::MsiVerbose,
        ParserKind::PsadtLegacy => DeploymentFormat::PsadtLegacy,
        ParserKind::Burn => DeploymentFormat::Burn,
        ParserKind::Ccm => {
            let has_psadt = entries.iter().any(|e| {
                PSADT_KEYWORDS.iter().any(|kw| e.message.contains(kw))
                    || e.component
                        .as_deref()
                        .is_some_and(|c| PSADT_KEYWORDS.iter().any(|kw| c.contains(kw)))
            });
            if has_psadt {
                DeploymentFormat::PsadtCmtrace
            } else if file_path.to_ascii_lowercase().contains("patchmypc") {
                DeploymentFormat::PatchMyPc
            } else {
                DeploymentFormat::PsadtWrapper
            }
        }
        // Burn logs may be detected as Timestamped or Plain when the first 20
        // lines don't contain enough `[hex:hex][ISO-date]` records. Fall back
        // to a content scan of the raw entry messages.
        ParserKind::Timestamped | ParserKind::Plain => {
            let burn_matches = entries
                .iter()
                .take(50)
                .filter(|e| burn::matches_burn_record(e.message.trim()))
                .count();
            if burn_matches >= 2 {
                DeploymentFormat::Burn
            } else {
                DeploymentFormat::Unknown
            }
        }
        _ => DeploymentFormat::Unknown,
    }
}

// ── App metadata extraction ─────────────────────────────────────────────

fn extract_app_metadata(
    format: &DeploymentFormat,
    entries: &[LogEntry],
) -> (Option<String>, Option<String>) {
    match format {
        DeploymentFormat::MsiVerbose => {
            let mut name = None;
            let mut version = None;
            for entry in entries.iter() {
                if name.is_none() {
                    if let Some(caps) = msi_product_name_re().captures(&entry.message) {
                        name = Some(caps[1].trim().to_string());
                    }
                }
                if version.is_none() {
                    if let Some(caps) = msi_product_version_re().captures(&entry.message) {
                        version = Some(caps[1].trim().to_string());
                    }
                }
                if name.is_some() && version.is_some() {
                    break;
                }
            }
            (name, version)
        }
        DeploymentFormat::PsadtCmtrace | DeploymentFormat::PsadtWrapper => {
            // Look for Open-ADTSession in message text
            for entry in entries.iter() {
                if entry.message.contains("Open-ADTSession") {
                    if let Some(caps) = psadt_session_info_re().captures(&entry.message) {
                        let info = caps[1].trim().to_string();
                        return parse_psadt_app_info(&info);
                    }
                }
            }
            (None, None)
        }
        DeploymentFormat::PsadtLegacy => {
            // Component field is the source function name
            for entry in entries.iter() {
                let is_open = entry
                    .component
                    .as_deref()
                    .is_some_and(|c| c.contains("Open-ADTSession"));
                if is_open {
                    if let Some(caps) = psadt_session_info_re().captures(&entry.message) {
                        let info = caps[1].trim().to_string();
                        return parse_psadt_app_info(&info);
                    }
                }
            }
            (None, None)
        }
        DeploymentFormat::Burn => {
            // First i001 message: "Burn v3.14.1.8722, Windows v10.0..."
            for entry in entries.iter() {
                let is_i001 = entry
                    .component
                    .as_deref()
                    .is_some_and(|c| c == "i001");
                if is_i001 {
                    let version = burn_version_re()
                        .captures(&entry.message)
                        .map(|c| c[1].to_string());
                    // Use the full message as app name (it often has the product info)
                    let name = Some(entry.message.clone());
                    return (name, version);
                }
            }
            (None, None)
        }
        DeploymentFormat::PatchMyPc => {
            for entry in entries.iter() {
                if let Some(caps) = patchmypc_version_re().captures(&entry.message) {
                    return (
                        Some("PatchMyPC UserNotification".to_string()),
                        Some(caps[1].to_string()),
                    );
                }
            }
            (Some("PatchMyPC".to_string()), None)
        }
        DeploymentFormat::Unknown => (None, None),
    }
}

/// Parse PSADT app info from "[Vendor Name Version]" bracket content.
/// The convention is "Vendor AppName Version" but the fields aren't quoted.
/// Heuristic: if the last token looks like a version (digits/dots), split it off.
fn parse_psadt_app_info(info: &str) -> (Option<String>, Option<String>) {
    let parts: Vec<&str> = info.rsplitn(2, ' ').collect();
    if parts.len() == 2 {
        let maybe_version = parts[0];
        let maybe_name = parts[1];
        // Check if last token looks like a version (starts with a digit)
        if maybe_version.starts_with(|c: char| c.is_ascii_digit()) {
            return (Some(maybe_name.to_string()), Some(maybe_version.to_string()));
        }
    }
    // Can't split — return the whole thing as the app name
    (Some(info.to_string()), None)
}

// ── Deploy type extraction ──────────────────────────────────────────────

fn extract_deploy_type(format: &DeploymentFormat, entries: &[LogEntry]) -> Option<String> {
    match format {
        DeploymentFormat::MsiVerbose => {
            for entry in entries.iter() {
                if let Some(caps) = msi_cmdline_re().captures(&entry.message) {
                    let cmd = caps[1].to_ascii_lowercase();
                    if cmd.contains("/x") || cmd.contains("remove=all") {
                        return Some("Uninstall".to_string());
                    }
                    if cmd.contains("/f") {
                        return Some("Repair".to_string());
                    }
                    if cmd.contains("/i") || cmd.contains("/qn") || cmd.contains("/qb") {
                        return Some("Install".to_string());
                    }
                }
            }
            // Default for MSI with no clear command line
            Some("Install".to_string())
        }
        DeploymentFormat::PsadtCmtrace
        | DeploymentFormat::PsadtWrapper
        | DeploymentFormat::PsadtLegacy => {
            for entry in entries.iter() {
                let text = &entry.message;
                if let Some(caps) = psadt_deploy_type_re().captures(text) {
                    let dt = caps[1].to_string();
                    // Capitalize first letter
                    let mut chars = dt.chars();
                    let capitalized = match chars.next() {
                        Some(c) => c.to_uppercase().collect::<String>() + &chars.as_str().to_lowercase(),
                        None => dt,
                    };
                    return Some(capitalized);
                }
            }
            None
        }
        _ => None,
    }
}

// ── Timestamp extraction ────────────────────────────────────────────────

fn extract_timestamps(entries: &[LogEntry]) -> (Option<String>, Option<String>) {
    let start = entries
        .iter()
        .find(|e| e.timestamp_display.is_some())
        .and_then(|e| e.timestamp_display.clone());
    let end = entries
        .iter()
        .rev()
        .find(|e| e.timestamp_display.is_some())
        .and_then(|e| e.timestamp_display.clone());
    (start, end)
}

// ── Exit code extraction ────────────────────────────────────────────────

fn extract_exit_code(format: &DeploymentFormat, entries: &[LogEntry]) -> Option<i32> {
    match format {
        DeploymentFormat::MsiVerbose => {
            for entry in entries.iter().rev() {
                if let Some(caps) = msi_main_engine_re().captures(&entry.message) {
                    if let Ok(code) = caps[1].parse::<i32>() {
                        return Some(code);
                    }
                }
            }
            None
        }
        DeploymentFormat::PsadtCmtrace | DeploymentFormat::PsadtWrapper | DeploymentFormat::PatchMyPc => {
            // Search for Close-ADTSession with exit code
            for entry in entries.iter().rev() {
                if entry.message.contains("Close-ADTSession") || entry.message.contains("ADTSession") {
                    if let Some(caps) = psadt_exit_code_re().captures(&entry.message) {
                        if let Ok(code) = caps[1].parse::<i32>() {
                            return Some(code);
                        }
                    }
                }
            }
            // Fallback: any exit code pattern
            for entry in entries.iter().rev() {
                if let Some(caps) = psadt_exit_code_re().captures(&entry.message) {
                    if let Ok(code) = caps[1].parse::<i32>() {
                        return Some(code);
                    }
                }
            }
            None
        }
        DeploymentFormat::PsadtLegacy => {
            // Component field is the source function name
            for entry in entries.iter().rev() {
                let is_close = entry
                    .component
                    .as_deref()
                    .is_some_and(|c| c.contains("Close-ADTSession"));
                if is_close {
                    if let Some(caps) = psadt_exit_code_re().captures(&entry.message) {
                        if let Ok(code) = caps[1].parse::<i32>() {
                            return Some(code);
                        }
                    }
                }
            }
            for entry in entries.iter().rev() {
                if let Some(caps) = psadt_exit_code_re().captures(&entry.message) {
                    if let Ok(code) = caps[1].parse::<i32>() {
                        return Some(code);
                    }
                }
            }
            None
        }
        DeploymentFormat::Burn => {
            // Burn exit line: "Exit code: 0xN" (any severity, typically i007)
            for entry in entries.iter().rev() {
                if let Some(caps) = burn_exit_code_re().captures(&entry.message) {
                    if let Ok(code) = u32::from_str_radix(&caps[1], 16) {
                        return Some(code as i32);
                    }
                }
            }
            None
        }
        DeploymentFormat::Unknown => None,
    }
}

// ── Outcome classification ──────────────────────────────────────────────

fn classify_outcome(exit_code: Option<i32>) -> DeploymentOutcome {
    match exit_code {
        Some(0) | Some(3010) | Some(1641) => DeploymentOutcome::Success,
        Some(1602) | Some(1604) | Some(60012) | Some(70001) => DeploymentOutcome::Deferred,
        Some(_) => DeploymentOutcome::Failure,
        None => DeploymentOutcome::Unknown,
    }
}

// ── Error context extraction ────────────────────────────────────────────

fn extract_error_lines(format: &DeploymentFormat, entries: &[LogEntry]) -> Vec<DeploymentErrorLine> {
    let mut lines = Vec::new();

    match format {
        DeploymentFormat::MsiVerbose => {
            // Find "Return value 3" lines with context
            for (i, entry) in entries.iter().enumerate() {
                if msi_return_value_3_re().is_match(&entry.message) {
                    let start = i.saturating_sub(3);
                    for ctx in &entries[start..=i] {
                        lines.push(DeploymentErrorLine {
                            line_number: ctx.line_number,
                            message: ctx.message.clone(),
                            severity: "Error".to_string(),
                        });
                    }
                }
            }
            // Include MainEngineThread line
            for entry in entries.iter() {
                if msi_main_engine_re().is_match(&entry.message) {
                    lines.push(DeploymentErrorLine {
                        line_number: entry.line_number,
                        message: entry.message.clone(),
                        severity: "Error".to_string(),
                    });
                }
            }
        }
        _ => {
            for entry in entries.iter() {
                match entry.severity {
                    Severity::Error => {
                        lines.push(DeploymentErrorLine {
                            line_number: entry.line_number,
                            message: entry.message.clone(),
                            severity: "Error".to_string(),
                        });
                    }
                    Severity::Warning => {
                        lines.push(DeploymentErrorLine {
                            line_number: entry.line_number,
                            message: entry.message.clone(),
                            severity: "Warning".to_string(),
                        });
                    }
                    _ => {}
                }
            }
        }
    }

    lines.truncate(50);
    lines
}

// ── Error summary ───────────────────────────────────────────────────────

fn generate_error_summary(
    format: &DeploymentFormat,
    exit_code: Option<i32>,
    outcome: &DeploymentOutcome,
) -> Option<String> {
    match outcome {
        DeploymentOutcome::Success | DeploymentOutcome::Unknown => return None,
        _ => {}
    }

    let code = exit_code?;
    let lookup = lookup_error_code(&code.to_string());

    let prefix = match format {
        DeploymentFormat::MsiVerbose => "MSI",
        DeploymentFormat::PsadtCmtrace | DeploymentFormat::PsadtLegacy | DeploymentFormat::PsadtWrapper => "PSADT",
        DeploymentFormat::Burn => "Burn",
        DeploymentFormat::PatchMyPc => "PatchMyPC",
        DeploymentFormat::Unknown => "Deployment",
    };

    if lookup.found {
        Some(format!("{} exit code {}: {}", prefix, code, lookup.description))
    } else {
        Some(format!("{} exit code {}", prefix, code))
    }
}

// ── Single file analysis ────────────────────────────────────────────────

fn analyze_single_file(file_path: &str) -> DeploymentLogFile {
    let path_obj = Path::new(file_path);
    let file_name = path_obj
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| file_path.to_string());

    match parser::parse_file(file_path) {
        Ok((result, resolved)) => {
            let format = classify_format(resolved.parser, &result.entries, file_path);
            let exit_code = extract_exit_code(&format, &result.entries);
            let outcome = classify_outcome(exit_code);
            let error_summary = generate_error_summary(&format, exit_code, &outcome);
            let error_lines = match outcome {
                DeploymentOutcome::Failure | DeploymentOutcome::Deferred => {
                    extract_error_lines(&format, &result.entries)
                }
                _ => Vec::new(),
            };
            let (app_name, app_version) = extract_app_metadata(&format, &result.entries);
            let deploy_type = extract_deploy_type(&format, &result.entries);
            let (start_time, end_time) = extract_timestamps(&result.entries);

            DeploymentLogFile {
                path: file_path.to_string(),
                file_name,
                format,
                outcome,
                exit_code,
                error_summary,
                error_lines,
                app_name,
                app_version,
                deploy_type,
                start_time,
                end_time,
            }
        }
        Err(_) => DeploymentLogFile {
            path: file_path.to_string(),
            file_name,
            format: DeploymentFormat::Unknown,
            outcome: DeploymentOutcome::Unknown,
            exit_code: None,
            error_summary: None,
            error_lines: Vec::new(),
            app_name: None,
            app_version: None,
            deploy_type: None,
            start_time: None,
            end_time: None,
        },
    }
}

// ── Recursive file enumeration ──────────────────────────────────────────

fn collect_log_files(dir: &Path, out: &mut Vec<String>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_log_files(&path, out);
        } else if path.is_file() {
            if let Some(ext) = path.extension() {
                if ext.to_string_lossy().to_ascii_lowercase() == "log" {
                    out.push(path.to_string_lossy().to_string());
                }
            }
        }
    }
}

// ── Tauri command ───────────────────────────────────────────────────────

#[tauri::command]
pub fn analyze_deployment_folder(
    folder_path: String,
) -> Result<DeploymentAnalysisResult, crate::error::AppError> {
    let dir = Path::new(&folder_path);
    if !dir.is_dir() {
        return Err(crate::error::AppError::InvalidInput(format!("Not a directory: {}", folder_path)));
    }

    let mut log_files = Vec::new();
    collect_log_files(dir, &mut log_files);

    if log_files.is_empty() {
        return Ok(DeploymentAnalysisResult {
            folder_path,
            files: Vec::new(),
            total_files: 0,
            succeeded: 0,
            failed: 0,
            deferred: 0,
            unknown: 0,
        });
    }

    // Parse all files in parallel
    let files: Vec<DeploymentLogFile> = log_files
        .par_iter()
        .map(|p| analyze_single_file(p))
        .collect();

    let mut succeeded = 0usize;
    let mut failed = 0usize;
    let mut deferred = 0usize;
    let mut unknown = 0usize;

    for file in &files {
        match file.outcome {
            DeploymentOutcome::Success => succeeded += 1,
            DeploymentOutcome::Failure => failed += 1,
            DeploymentOutcome::Deferred => deferred += 1,
            DeploymentOutcome::Unknown => unknown += 1,
        }
    }

    let total_files = files.len();

    Ok(DeploymentAnalysisResult {
        folder_path,
        files,
        total_files,
        succeeded,
        failed,
        deferred,
        unknown,
    })
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::log_entry::LogFormat;

    fn make_entry(msg: &str, sev: Severity) -> LogEntry {
        make_entry_with_component(msg, sev, None)
    }

    fn make_entry_with_component(msg: &str, sev: Severity, component: Option<&str>) -> LogEntry {
        LogEntry {
            id: 0,
            line_number: 1,
            message: msg.to_string(),
            component: component.map(|s| s.to_string()),
            timestamp: None,
            timestamp_display: None,
            severity: sev,
            thread: None,
            thread_display: None,
            source_file: None,
            format: LogFormat::Plain,
            file_path: "test.log".to_string(),
            timezone_offset: None,
            error_code_spans: Vec::new(),
            ip_address: None,
            host_name: None,
            mac_address: None,
            result_code: None,
            gle_code: None,
            setup_phase: None,
            operation_name: None,
        }
    }

    #[test]
    fn test_outcome_success() {
        assert!(matches!(classify_outcome(Some(0)), DeploymentOutcome::Success));
        assert!(matches!(classify_outcome(Some(3010)), DeploymentOutcome::Success));
        assert!(matches!(classify_outcome(Some(1641)), DeploymentOutcome::Success));
    }

    #[test]
    fn test_outcome_deferred() {
        assert!(matches!(classify_outcome(Some(1602)), DeploymentOutcome::Deferred));
        assert!(matches!(classify_outcome(Some(60012)), DeploymentOutcome::Deferred));
    }

    #[test]
    fn test_outcome_failure() {
        assert!(matches!(classify_outcome(Some(1603)), DeploymentOutcome::Failure));
        assert!(matches!(classify_outcome(Some(1)), DeploymentOutcome::Failure));
    }

    #[test]
    fn test_outcome_unknown() {
        assert!(matches!(classify_outcome(None), DeploymentOutcome::Unknown));
    }

    #[test]
    fn test_msi_exit_code() {
        let entries = vec![make_entry("MainEngineThread is returning 1603", Severity::Error)];
        assert_eq!(extract_exit_code(&DeploymentFormat::MsiVerbose, &entries), Some(1603));
    }

    #[test]
    fn test_psadt_exit_code() {
        let entries = vec![make_entry("Close-ADTSession completed with exit code [0]", Severity::Info)];
        assert_eq!(extract_exit_code(&DeploymentFormat::PsadtCmtrace, &entries), Some(0));
    }

    #[test]
    fn test_format_msi_direct() {
        let entries = vec![make_entry("test", Severity::Info)];
        assert!(matches!(classify_format(ParserKind::Msi, &entries, "test.log"), DeploymentFormat::MsiVerbose));
    }

    #[test]
    fn test_format_burn_direct() {
        let entries = vec![make_entry("test", Severity::Info)];
        assert!(matches!(classify_format(ParserKind::Burn, &entries, "test.log"), DeploymentFormat::Burn));
    }

    #[test]
    fn test_format_burn_fallback_from_timestamped() {
        let entries = vec![
            make_entry("[07A4:0CBC][2025-11-25T01:55:42]i001: Burn v3.14.1.8722, Windows v10.0", Severity::Info),
            make_entry("[07A4:0CBC][2025-11-25T01:55:43]i000: Initializing", Severity::Info),
        ];
        assert!(matches!(
            classify_format(ParserKind::Timestamped, &entries, "setup.exe.log"),
            DeploymentFormat::Burn
        ));
    }

    #[test]
    fn test_format_burn_fallback_from_plain() {
        let entries = vec![
            make_entry("[1234:5678][2025-11-25T01:55:42]i001: Started bootstrapper", Severity::Info),
            make_entry("[1234:5678][2025-11-25T01:55:43]e000: Error occurred", Severity::Error),
        ];
        assert!(matches!(
            classify_format(ParserKind::Plain, &entries, "installer.exe.log"),
            DeploymentFormat::Burn
        ));
    }

    #[test]
    fn test_format_plain_stays_unknown() {
        let entries = vec![
            make_entry("Just some plain text", Severity::Info),
            make_entry("No burn patterns here", Severity::Info),
        ];
        assert!(matches!(
            classify_format(ParserKind::Plain, &entries, "random.log"),
            DeploymentFormat::Unknown
        ));
    }

    #[test]
    fn test_format_ccm_with_psadt() {
        let entries = vec![make_entry("Open-ADTSession starting", Severity::Info)];
        assert!(matches!(classify_format(ParserKind::Ccm, &entries, "test.log"), DeploymentFormat::PsadtCmtrace));
    }

    #[test]
    fn test_format_ccm_patchmypc() {
        let entries = vec![make_entry("starting up", Severity::Info)];
        assert!(matches!(
            classify_format(ParserKind::Ccm, &entries, "C:\\PatchMyPC\\Logs\\test.log"),
            DeploymentFormat::PatchMyPc
        ));
    }

    #[test]
    fn test_error_summary_with_known_code() {
        let summary = generate_error_summary(&DeploymentFormat::MsiVerbose, Some(1603), &DeploymentOutcome::Failure);
        assert!(summary.is_some());
        assert!(summary.unwrap().contains("1603"));
    }

    #[test]
    fn test_error_summary_success_none() {
        assert!(generate_error_summary(&DeploymentFormat::MsiVerbose, Some(0), &DeploymentOutcome::Success).is_none());
    }

    #[test]
    fn test_msi_app_metadata() {
        let entries = vec![
            make_entry("Property(S): ProductName = Contoso Widget", Severity::Info),
            make_entry("Property(S): ProductVersion = 2.3.1", Severity::Info),
        ];
        let (name, version) = extract_app_metadata(&DeploymentFormat::MsiVerbose, &entries);
        assert_eq!(name.as_deref(), Some("Contoso Widget"));
        assert_eq!(version.as_deref(), Some("2.3.1"));
    }

    #[test]
    fn test_psadt_app_metadata() {
        let entries = vec![
            make_entry("Open-ADTSession [Contoso Foo App 1.2.3]", Severity::Info),
        ];
        let (name, version) = extract_app_metadata(&DeploymentFormat::PsadtCmtrace, &entries);
        assert_eq!(name.as_deref(), Some("Contoso Foo App"));
        assert_eq!(version.as_deref(), Some("1.2.3"));
    }

    #[test]
    fn test_burn_app_metadata() {
        let entries = vec![
            make_entry_with_component("Burn v3.14.1.8722, Windows v10.0 (Build 26100)", Severity::Info, Some("i001")),
        ];
        let (name, version) = extract_app_metadata(&DeploymentFormat::Burn, &entries);
        assert!(name.is_some());
        assert!(name.unwrap().contains("Burn v3.14.1.8722"));
        assert_eq!(version.as_deref(), Some("3.14.1.8722"));
    }

    #[test]
    fn test_patchmypc_app_metadata() {
        let entries = vec![
            make_entry("Starting UserNotification V2.1.100.317", Severity::Info),
        ];
        let (name, version) = extract_app_metadata(&DeploymentFormat::PatchMyPc, &entries);
        assert_eq!(name.as_deref(), Some("PatchMyPC UserNotification"));
        assert_eq!(version.as_deref(), Some("2.1.100.317"));
    }

    #[test]
    fn test_psadt_app_info_no_version() {
        let (name, version) = parse_psadt_app_info("SingleName");
        assert_eq!(name.as_deref(), Some("SingleName"));
        assert!(version.is_none());
    }

    #[test]
    fn test_msi_deploy_type_install() {
        let entries = vec![
            make_entry("CommandLine: /i setup.msi /qn", Severity::Info),
        ];
        assert_eq!(
            extract_deploy_type(&DeploymentFormat::MsiVerbose, &entries).as_deref(),
            Some("Install")
        );
    }

    #[test]
    fn test_msi_deploy_type_uninstall() {
        let entries = vec![
            make_entry("CommandLine: /x {GUID} /qn", Severity::Info),
        ];
        assert_eq!(
            extract_deploy_type(&DeploymentFormat::MsiVerbose, &entries).as_deref(),
            Some("Uninstall")
        );
    }

    #[test]
    fn test_psadt_deploy_type() {
        let entries = vec![
            make_entry("Deployment Type [Install]", Severity::Info),
        ];
        assert_eq!(
            extract_deploy_type(&DeploymentFormat::PsadtCmtrace, &entries).as_deref(),
            Some("Install")
        );
    }

    #[test]
    fn test_timestamps_extraction() {
        let mut e1 = make_entry("first", Severity::Info);
        e1.timestamp_display = Some("2025-11-25 01:55:42.000".to_string());
        let mut e2 = make_entry("last", Severity::Info);
        e2.timestamp_display = Some("2025-11-25 02:10:00.000".to_string());
        let (start, end) = extract_timestamps(&[e1, e2]);
        assert_eq!(start.as_deref(), Some("2025-11-25 01:55:42.000"));
        assert_eq!(end.as_deref(), Some("2025-11-25 02:10:00.000"));
    }
}
