use regex::Regex;

use super::severity::detect_severity_from_text;
use crate::models::log_entry::{LogEntry, LogFormat, Severity};
use std::sync::OnceLock;

fn panther_prefix_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
    Regex::new(r"^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2},").unwrap()
})
}

/// Matches a bracketed executable tag at the start of the message, e.g. `[SetupPlatform.exe]`.
fn exe_tag_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
    Regex::new(r"^\[([^\]]+\.[Ee][Xx][Ee])\]\s*").unwrap()
})
}

/// Matches C++ class::method patterns, e.g. `CSetupManager::GetWuIdFromRegistry(13192):`.
fn class_method_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
    Regex::new(r"^([A-Z][A-Za-z0-9_]*(?:::[A-Za-z_]\w*)+)(?:\(\d+\))?:\s*").unwrap()
})
}

/// Matches DISM-style thread IDs embedded in the message, e.g. `PID=1452 TID=776`.
fn tid_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
    Regex::new(r"TID=(\d+)").unwrap()
})
}

/// Matches a primary result/error/status code, e.g.:
///   `Result = 0x80070490`, `Error: 0x80070002`, `Status: 0xC000000F`
fn result_code_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
    Regex::new(r"(?:Result\s*=|Error:|Status:)\s*(0x[0-9A-Fa-f]+)").unwrap()
})
}

/// Matches a GetLastError annotation, e.g. `[gle=0x00000002]`.
fn gle_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
    Regex::new(r"\[gle=(0x[0-9A-Fa-f]+)\]").unwrap()
})
}

/// Matches the current setup phase, e.g. `CurrentSetupPhase [SetupPhaseInstall]`.
fn setup_phase_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
    Regex::new(r"CurrentSetupPhase\s+\[([A-Za-z0-9]+)\]").unwrap()
})
}

/// Matches an operation being executed or completed, e.g.:
///   `Executing operation: Apply Drivers`
///   `Operation completed successfully: Apply Drivers`
fn operation_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
    Regex::new(r"(?:Executing operation|Operation completed successfully):\s*(.+)").unwrap()
})
}

fn panther_header_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
    Regex::new(
        r"^(\d{4})-(\d{2})-(\d{2})\s+(\d{2}):(\d{2}):(\d{2}),\s+(Info|Warning|Error|Fatal Error|Perf)\s+(?:(\[0x[0-9A-Fa-f]+\])\s+)?(?:([A-Z][A-Z0-9_.-]{1,31})\s+)?(.*)$",
    )
    .unwrap()
})
}

fn panther_relaxed_header_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
    Regex::new(
        r"^(\d{4})-(\d{2})-(\d{2})\s+(\d{2}):(\d{2}):(\d{2}),\s+([A-Za-z][A-Za-z0-9_-]{1,31})\s+(?:(\[0x[0-9A-Fa-f]+\])\s+)?(?:([A-Z][A-Z0-9_.-]{1,31})\s+)?(.*)$",
    )
    .unwrap()
})
}

struct PendingEntry {
    entry: LogEntry,
    start_line: u32,
}

pub fn matches_panther_record(line: &str) -> bool {
    panther_header_re().is_match(line)
}

pub fn parse_lines(lines: &[&str], file_path: &str) -> (Vec<LogEntry>, u32) {
    let mut entries = Vec::new();
    let mut parse_errors = 0;
    let mut next_id = 0;
    let mut pending: Option<PendingEntry> = None;

    for (index, line) in lines.iter().enumerate() {
        let line_number = (index + 1) as u32;

        if let Some(entry) = parse_header(line, file_path) {
            flush_pending(&mut entries, &mut pending, &mut next_id);
            pending = Some(PendingEntry {
                entry,
                start_line: line_number,
            });
            continue;
        }

        if panther_prefix_re().is_match(line) {
            flush_pending(&mut entries, &mut pending, &mut next_id);
            entries.push(fallback_entry(next_id, line_number, line, file_path));
            next_id += 1;
            parse_errors += 1;
            continue;
        }

        let trimmed_end = line.trim_end();
        if trimmed_end.is_empty() {
            continue;
        }

        if let Some(pending_entry) = pending.as_mut() {
            if !pending_entry.entry.message.is_empty() {
                pending_entry.entry.message.push('\n');
            }
            pending_entry.entry.message.push_str(trimmed_end);
        } else {
            entries.push(fallback_entry(next_id, line_number, trimmed_end, file_path));
            next_id += 1;
            parse_errors += 1;
        }
    }

    flush_pending(&mut entries, &mut pending, &mut next_id);

    (entries, parse_errors)
}

fn parse_header(line: &str, file_path: &str) -> Option<LogEntry> {
    if let Some(caps) = panther_header_re().captures(line) {
        return build_entry_from_caps(&caps, file_path);
    }

    let caps = panther_relaxed_header_re().captures(line)?;
    build_entry_from_caps(&caps, file_path)
}

fn build_entry_from_caps(caps: &regex::Captures<'_>, file_path: &str) -> Option<LogEntry> {

    let year: i32 = caps.get(1)?.as_str().parse().ok()?;
    let month: u32 = caps.get(2)?.as_str().parse().ok()?;
    let day: u32 = caps.get(3)?.as_str().parse().ok()?;
    let hour: u32 = caps.get(4)?.as_str().parse().ok()?;
    let minute: u32 = caps.get(5)?.as_str().parse().ok()?;
    let second: u32 = caps.get(6)?.as_str().parse().ok()?;
    let level = caps.get(7)?.as_str();
    let code = caps.get(8).map(|m| m.as_str());
    let component = caps.get(9).map(|m| m.as_str().to_string());
    let raw_message = caps.get(10).map(|m| m.as_str()).unwrap_or("").trim_end();
    let message = match code {
        Some(code) if raw_message.is_empty() => code.to_string(),
        Some(code) => format!("{} {}", code, raw_message),
        None => raw_message.to_string(),
    };

    let timestamp = chrono::NaiveDate::from_ymd_opt(year, month, day)
        .and_then(|date| date.and_hms_opt(hour, minute, second))
        .map(|dt| dt.and_utc().timestamp_millis());

    let mut entry = LogEntry {
        id: 0,
        line_number: 0,
        message,
        component,
        timestamp,
        timestamp_display: Some(format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.000",
            year, month, day, hour, minute, second
        )),
        severity: severity_from_level(level, raw_message),
        thread: None,
        thread_display: None,
        source_file: None,
        format: LogFormat::Timestamped,
        file_path: file_path.to_string(),
        timezone_offset: None,
        error_code_spans: Vec::new(),
        ip_address: None,
        host_name: None,
        mac_address: None,
        result_code: None,
        gle_code: None,
        setup_phase: None,
        operation_name: None,
    };

    post_process_entry(&mut entry);

    Some(entry)
}

/// Extract additional structured fields from the message text.
fn post_process_entry(entry: &mut LogEntry) {
    // 1. Extract bracketed exe tag → source_file + component fallback
    if let Some(caps) = exe_tag_re().captures(&entry.message) {
        let exe_name = caps.get(1).unwrap().as_str().to_string();
        // Strip the tag from the message
        entry.message = entry.message[caps.get(0).unwrap().end()..].to_string();
        // Use as component fallback when none was matched by the header regex
        if entry.component.is_none() {
            entry.component = Some(exe_name.trim_end_matches(".exe").to_string());
        }
        entry.source_file = Some(exe_name);
    }

    // 2. Extract C++ Class::Method as source_file (keep in message for context)
    if entry.source_file.is_none() {
        if let Some(caps) = class_method_re().captures(&entry.message) {
            entry.source_file = Some(caps.get(1).unwrap().as_str().to_string());
        }
    }

    // 3. Extract DISM TID as thread
    if entry.thread.is_none() {
        if let Some(caps) = tid_re().captures(&entry.message) {
            if let Ok(tid) = caps.get(1).unwrap().as_str().parse::<u32>() {
                entry.thread = Some(tid);
                entry.thread_display = Some(format!("{} (0x{:04X})", tid, tid));
            }
        }
    }

    // 4. Extract primary result/error/status code
    if let Some(caps) = result_code_re().captures(&entry.message) {
        entry.result_code = Some(caps.get(1).unwrap().as_str().to_uppercase());
    }

    // 5. Extract GetLastError code
    if let Some(caps) = gle_re().captures(&entry.message) {
        entry.gle_code = Some(caps.get(1).unwrap().as_str().to_uppercase());
    }

    // 6. Extract current setup phase
    if let Some(caps) = setup_phase_re().captures(&entry.message) {
        entry.setup_phase = Some(caps.get(1).unwrap().as_str().to_string());
    }

    // 7. Extract operation name from execution/completion lines
    if let Some(caps) = operation_re().captures(&entry.message) {
        entry.operation_name = Some(caps.get(1).unwrap().as_str().trim().to_string());
    }
}

fn severity_from_level(level: &str, message: &str) -> Severity {
    match level {
        "Error" | "Fatal Error" => Severity::Error,
        "Warning" => Severity::Warning,
        "Perf" | "Info" => Severity::Info,
        _ => detect_severity_from_text(message),
    }
}

fn flush_pending(entries: &mut Vec<LogEntry>, pending: &mut Option<PendingEntry>, next_id: &mut u64) {
    if let Some(mut pending_entry) = pending.take() {
        pending_entry.entry.id = *next_id;
        pending_entry.entry.line_number = pending_entry.start_line;
        entries.push(pending_entry.entry);
        *next_id += 1;
    }
}

fn fallback_entry(id: u64, line_number: u32, line: &str, file_path: &str) -> LogEntry {
    LogEntry {
        id,
        line_number,
        message: line.trim_end().to_string(),
        component: None,
        timestamp: None,
        timestamp_display: None,
        severity: detect_severity_from_text(line),
        thread: None,
        thread_display: None,
        source_file: None,
        format: LogFormat::Timestamped,
        file_path: file_path.to_string(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matches_panther_record() {
        assert!(matches_panther_record(
            "2024-01-15 08:00:00, Info [0x080489] MIG Setting system object filter context (System)"
        ));
        assert!(!matches_panther_record("plain text"));
    }

    #[test]
    fn test_parse_lines_groups_continuations() {
        let lines = [
            "2024-01-15 08:00:00, Info [0x080489] MIG Gather started",
            "Additional migration detail",
            "    indented continuation",
            "2024-01-15 08:00:05, Warning SP Retry required",
        ];

        let (entries, parse_errors) = parse_lines(&lines, "C:/Windows/Panther/setupact.log");

        assert_eq!(parse_errors, 0);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].component.as_deref(), Some("MIG"));
        assert_eq!(entries[0].message, "[0x080489] Gather started\nAdditional migration detail\n    indented continuation");
        assert_eq!(entries[0].line_number, 1);
        assert_eq!(entries[1].severity, Severity::Warning);
    }

    #[test]
    fn test_parse_lines_salvages_structural_segments_with_unexpected_levels() {
        let lines = [
            "orphan preamble",
            "2024-01-15 08:00:00, Info SP Setup started",
            "continuation detail",
            "2024-01-15 08:00:01, UnexpectedLevel SP malformed header",
            "2024-01-15 08:00:02, Error SP Setup failed",
        ];

        let (entries, parse_errors) = parse_lines(&lines, "C:/Windows/Panther/setuperr.log");

        assert_eq!(parse_errors, 1);
        assert_eq!(entries.len(), 4);
        assert_eq!(entries[0].message, "orphan preamble");
        assert_eq!(entries[1].message, "Setup started\ncontinuation detail");
        assert_eq!(entries[2].message, "malformed header");
        assert_eq!(entries[2].component.as_deref(), Some("SP"));
        assert_eq!(entries[3].severity, Severity::Error);
        assert_eq!(entries[3].component.as_deref(), Some("SP"));
    }

    #[test]
    fn test_parse_lines_handles_missing_component() {
        let lines = ["2024-01-15 08:00:08, Error                  Gather failed. Last error: 0x00000000"];

        let (entries, parse_errors) = parse_lines(&lines, "C:/Windows/Panther/setupact.log");

        assert_eq!(parse_errors, 0);
        assert_eq!(entries.len(), 1);
        assert!(entries[0].component.is_none());
        assert_eq!(entries[0].severity, Severity::Error);
    }

    #[test]
    fn test_exe_tag_extracted_as_source_file_and_component_fallback() {
        let lines =
            ["2024-01-15 08:00:00, Error                  [SetupPlatform.exe] System disks found"];

        let (entries, _) = parse_lines(&lines, "C:/Windows/Panther/setuperr.log");

        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].source_file.as_deref(),
            Some("SetupPlatform.exe")
        );
        assert_eq!(
            entries[0].component.as_deref(),
            Some("SetupPlatform")
        );
        assert_eq!(entries[0].message, "System disks found");
    }

    #[test]
    fn test_exe_tag_does_not_overwrite_existing_component() {
        let lines = [
            "2024-01-15 08:00:00, Warning               MOUPG  [SetupHost.exe] Something happened",
        ];

        let (entries, _) = parse_lines(&lines, "C:/Windows/Panther/setupact.log");

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].component.as_deref(), Some("MOUPG"));
        assert_eq!(entries[0].source_file.as_deref(), Some("SetupHost.exe"));
    }

    #[test]
    fn test_class_method_extracted_as_source_file() {
        let lines = [
            "2024-01-15 08:00:00, Error                 MOUPG  CUnattendManager::Initialize(90): Result = 0x80070490",
        ];

        let (entries, _) = parse_lines(&lines, "C:/Windows/Panther/setuperr.log");

        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].source_file.as_deref(),
            Some("CUnattendManager::Initialize")
        );
        // Message should still contain the full text for context
        assert!(entries[0].message.contains("CUnattendManager::Initialize"));
    }

    #[test]
    fn test_dism_tid_extracted_as_thread() {
        let lines = [
            "2024-01-15 08:00:00, Info                  DISM   API: PID=1452 TID=776 DismApi.dll: session started",
        ];

        let (entries, _) = parse_lines(&lines, "C:/Windows/Panther/setupact.log");

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].thread, Some(776));
        assert_eq!(entries[0].thread_display.as_deref(), Some("776 (0x0308)"));
    }

    #[test]
    fn test_perf_severity_mapped_to_info() {
        let lines = ["2024-01-15 08:00:00, Perf                   SP     Timing checkpoint reached"];

        let (entries, _) = parse_lines(&lines, "C:/Windows/Panther/setupact.log");

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].severity, Severity::Info);
    }
}