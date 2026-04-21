//! CmtLog format parser.
//!
//! Extends CCM's `<![LOG[...]LOG]!>` line format with reserved component names
//! (`__HEADER__`, `__SECTION__`, `__ITERATION__`) and optional extended attributes
//! (`section`, `tag`, `whatif`, `iteration`, `color`).
//!
//! Uses a relaxed CCM regex that allows trailing key="value" attributes after the
//! standard `file=""` field, then post-processes entries to extract extended
//! attributes and classify by component name.

use regex::Regex;
use std::sync::OnceLock;

use super::ccm;
use super::severity::detect_severity_from_text;
use crate::models::log_entry::{EntryKind, LogEntry, LogFormat, Severity};

/// Reserved component names that signal CmtLog structured entries.
const HEADER_COMPONENT: &str = "__HEADER__";
const SECTION_COMPONENT: &str = "__SECTION__";
const ITERATION_COMPONENT: &str = "__ITERATION__";

/// Compiled regex for extracting key="value" pairs from raw log lines.
fn attr_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| Regex::new(r#"(\w+)="([^"]*)""#).expect("attr regex must compile"))
}

/// Relaxed CCM regex that allows arbitrary trailing attributes after `file=""`.
///
/// Standard CCM regex requires `>` immediately after the optional `file` field.
/// CmtLog lines contain additional key="value" pairs (script, version, color,
/// section, etc.) between `file=""` and `>`.  This regex uses `[^>]*>` to
/// tolerate those extra attributes.
fn cmtlog_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(concat!(
            r#"<!\[LOG\[(?P<msg>[\s\S]*?)\]LOG\]!>"#,
            r#"<time="(?P<h>\d{1,2}):(?P<m>\d{1,2}):(?P<s>\d{1,2})\.(?P<ms>\d+)(?P<tz>[+-]*\d+)""#,
            r#"\s+date="(?P<mon>\d{1,2})-(?P<day>\d{1,2})-(?P<yr>\d{4})""#,
            r#"\s+component="(?P<comp>[^"]*)""#,
            r#"\s+context="[^"]*""#,
            r#"\s+type="(?P<typ>\d)""#,
            r#"\s+thread="(?P<thr>\d+)""#,
            r#"[^>]*>"#,
        ))
        .expect("CmtLog regex must compile")
    })
}

/// Returns true if the line contains a CmtLog reserved `component="..."` attribute,
/// indicating the file uses the CmtLog format rather than plain CCM.
///
/// Checks for exact attribute syntax to avoid false positives when reserved
/// names appear in log message text.
pub fn matches_cmtlog_record(line: &str) -> bool {
    line.contains(&format!("component=\"{}\"", HEADER_COMPONENT))
        || line.contains(&format!("component=\"{}\"", SECTION_COMPONENT))
        || line.contains(&format!("component=\"{}\"", ITERATION_COMPONENT))
}

/// Extract extended attributes from a raw CmtLog line.
///
/// Scans for `key="value"` pairs and returns the ones relevant to CmtLog:
/// `section`, `color`, `tag`, `whatif`, `iteration`.
fn extract_attrs(line: &str) -> ExtractedAttrs {
    let mut attrs = ExtractedAttrs::default();
    for caps in attr_re().captures_iter(line) {
        let key = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        let value = caps.get(2).map(|m| m.as_str()).unwrap_or("");
        match key {
            "section" => attrs.section = Some(value.to_string()),
            "color" => attrs.color = Some(value.to_string()),
            "tag" => attrs.tag = Some(value.to_string()),
            "whatif" => attrs.whatif = Some(value.to_string()),
            "iteration" => attrs.iteration = Some(value.to_string()),
            _ => {}
        }
    }
    attrs
}

#[derive(Default)]
struct ExtractedAttrs {
    section: Option<String>,
    color: Option<String>,
    tag: Option<String>,
    whatif: Option<String>,
    iteration: Option<String>,
}

/// Parse a single CmtLog line using the relaxed regex.
fn parse_cmtlog_line(line: &str) -> Option<CmtLogParsed> {
    let caps = cmtlog_re().captures(line)?;

    let message = caps.name("msg").map(|m| m.as_str().to_string())?;
    let component_str = caps.name("comp").map(|m| m.as_str().to_string());
    let severity_type = caps
        .name("typ")
        .and_then(|m| m.as_str().parse::<u32>().ok());
    let severity = ccm::severity_from_type_field(severity_type, &message);

    let thread = caps
        .name("thr")
        .and_then(|m| m.as_str().parse::<u32>().ok())
        .unwrap_or(0);
    let thread_display = Some(ccm::format_thread_display(thread));

    let h: u32 = caps.name("h").and_then(|m| m.as_str().parse().ok()).unwrap_or(0);
    let min: u32 = caps.name("m").and_then(|m| m.as_str().parse().ok()).unwrap_or(0);
    let s: u32 = caps.name("s").and_then(|m| m.as_str().parse().ok()).unwrap_or(0);
    let ms: u32 = caps.name("ms").and_then(|m| m.as_str().parse().ok()).unwrap_or(0);
    let tz_str = caps.name("tz").map(|m| m.as_str()).unwrap_or("0");
    let tz_offset: i32 = tz_str.replace("+-", "-").parse().unwrap_or(0);
    let mon: u32 = caps.name("mon").and_then(|m| m.as_str().parse().ok()).unwrap_or(1);
    let day: u32 = caps.name("day").and_then(|m| m.as_str().parse().ok()).unwrap_or(1);
    let yr: i32 = caps.name("yr").and_then(|m| m.as_str().parse().ok()).unwrap_or(2000);

    let (timestamp, timestamp_display) =
        ccm::build_timestamp(mon, day, yr, h, min, s, ms, Some(tz_offset));

    Some(CmtLogParsed {
        message,
        component: component_str,
        timestamp,
        timestamp_display,
        severity,
        thread,
        thread_display,
        timezone_offset: tz_offset,
    })
}

struct CmtLogParsed {
    message: String,
    component: Option<String>,
    timestamp: Option<i64>,
    timestamp_display: Option<String>,
    severity: Severity,
    thread: u32,
    thread_display: Option<String>,
    timezone_offset: i32,
}

/// Parse all lines as CmtLog format.
///
/// Uses a relaxed CCM regex that tolerates extra key="value" attributes, then
/// post-processes entries to extract CmtLog-specific attributes and classify
/// by component name.
///
/// Returns `(entries, parse_error_count)`.
pub fn parse_lines(lines: &[&str], file_path: &str) -> (Vec<LogEntry>, u32) {
    let mut entries = Vec::with_capacity(lines.len());
    let mut errors = 0u32;
    let mut id_counter = 0u64;

    // Track current section context for propagation to child entries.
    let mut current_section_name: Option<String> = None;
    let mut current_section_color: Option<String> = None;

    for (i, line) in lines.iter().enumerate() {
        if line.trim().is_empty() {
            continue;
        }

        let attrs = extract_attrs(line);

        let (base_entry, component_str) = match parse_cmtlog_line(line) {
            Some(parsed) => {
                let comp = parsed.component.clone();
                let entry = LogEntry {
                    id: id_counter,
                    line_number: (i + 1) as u32,
                    message: parsed.message,
                    component: parsed.component,
                    timestamp: parsed.timestamp,
                    timestamp_display: parsed.timestamp_display,
                    severity: parsed.severity,
                    thread: Some(parsed.thread),
                    thread_display: parsed.thread_display,
                    source_file: None,
                    format: LogFormat::CmtLog,
                    file_path: file_path.to_string(),
                    timezone_offset: Some(parsed.timezone_offset),
                    error_code_spans: Vec::new(),
                    ip_address: None,
                    host_name: None,
                    mac_address: None,
                    result_code: None,
                    gle_code: None,
                    setup_phase: None,
                    operation_name: None,
                    http_method: None,
                    uri_stem: None,
                    uri_query: None,
                    status_code: None,
                    sub_status: None,
                    time_taken_ms: None,
                    client_ip: None,
                    server_ip: None,
                    user_agent: None,
                    server_port: None,
                    username: None,
                    win32_status: None,
                    query_name: None,
                    query_type: None,
                    response_code: None,
                    dns_direction: None,
                    dns_protocol: None,
                    source_ip: None,
                    dns_flags: None,
                    dns_event_id: None,
                    zone_name: None,
                    entry_kind: None,
                    whatif: None,
                    section_name: None,
                    section_color: None,
                    iteration: None,
                    tags: None,
                };
                (entry, comp.unwrap_or_default())
            }
            None => {
                errors += 1;
                let entry = LogEntry {
                    id: id_counter,
                    line_number: (i + 1) as u32,
                    message: line.to_string(),
                    component: None,
                    timestamp: None,
                    timestamp_display: None,
                    severity: detect_severity_from_text(line),
                    thread: None,
                    thread_display: None,
                    source_file: None,
                    format: LogFormat::CmtLog,
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
                    http_method: None,
                    uri_stem: None,
                    uri_query: None,
                    status_code: None,
                    sub_status: None,
                    time_taken_ms: None,
                    client_ip: None,
                    server_ip: None,
                    user_agent: None,
                    server_port: None,
                    username: None,
                    win32_status: None,
                    query_name: None,
                    query_type: None,
                    response_code: None,
                    dns_direction: None,
                    dns_protocol: None,
                    source_ip: None,
                    dns_flags: None,
                    dns_event_id: None,
                    zone_name: None,
                    entry_kind: None,
                    whatif: None,
                    section_name: None,
                    section_color: None,
                    iteration: None,
                    tags: None,
                };
                (entry, String::new())
            }
        };

        let mut entry = base_entry;

        // Classify by component name and extract CmtLog-specific attributes
        match component_str.as_str() {
            HEADER_COMPONENT => {
                entry.entry_kind = Some(EntryKind::Header);
            }
            SECTION_COMPONENT => {
                entry.entry_kind = Some(EntryKind::Section);
                current_section_name = Some(entry.message.clone());
                current_section_color = attrs.color.clone();
                entry.section_name = Some(entry.message.clone());
                entry.section_color = attrs.color;
            }
            ITERATION_COMPONENT => {
                entry.entry_kind = Some(EntryKind::Iteration);
                entry.iteration = attrs.iteration;
                entry.section_color = attrs.color.or_else(|| current_section_color.clone());
                entry.section_name = current_section_name.clone();
            }
            _ => {
                entry.entry_kind = Some(EntryKind::Log);
                entry.section_name = attrs
                    .section
                    .or_else(|| current_section_name.clone());
                entry.section_color = current_section_color.clone();
                entry.whatif = attrs.whatif.map(|v| v == "1");
                entry.iteration = attrs.iteration;
                entry.tags = attrs.tag.map(|t| {
                    t.split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect()
                });
            }
        }

        entries.push(entry);
        id_counter += 1;
    }

    (entries, errors)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::log_entry::Severity;

    fn sample_lines() -> Vec<String> {
        vec![
            r##"<![LOG[Script started: Detect-WDAC.ps1 v2.1.0]LOG]!><time="10:30:00.000+000" date="04-13-2026" component="__HEADER__" context="" type="1" thread="0" file="" script="Detect-WDAC.ps1" version="2.1.0">"##.to_string(),
            r##"<![LOG[Detection Phase]LOG]!><time="10:32:01.000+000" date="04-13-2026" component="__SECTION__" context="" type="1" thread="0" file="" color="#5b9aff">"##.to_string(),
            r##"<![LOG[Scanning policy files]LOG]!><time="10:32:01.123+000" date="04-13-2026" component="Detect-WDAC" context="CONTOSO\admin" type="1" thread="1234" file="" section="detection" tag="phase:scan">"##.to_string(),
        ]
    }

    #[test]
    fn test_matches_cmtlog_record() {
        assert!(matches_cmtlog_record(
            r#"component="__HEADER__" context="" type="1""#
        ));
        assert!(matches_cmtlog_record(
            r#"component="__SECTION__" context="" type="1""#
        ));
        assert!(matches_cmtlog_record(
            r#"component="__ITERATION__" context="" type="1""#
        ));
        assert!(!matches_cmtlog_record(
            r#"component="TestComp" context="" type="1""#
        ));
    }

    #[test]
    fn test_header_classification() {
        let lines = sample_lines();
        let line_refs: Vec<&str> = lines.iter().map(|s| s.as_str()).collect();
        let (entries, _) = parse_lines(&line_refs, "test.cmtlog");
        assert_eq!(entries[0].entry_kind, Some(EntryKind::Header));
        assert_eq!(entries[0].format, LogFormat::CmtLog);
    }

    #[test]
    fn test_section_classification() {
        let lines = sample_lines();
        let line_refs: Vec<&str> = lines.iter().map(|s| s.as_str()).collect();
        let (entries, _) = parse_lines(&line_refs, "test.cmtlog");
        assert_eq!(entries[1].entry_kind, Some(EntryKind::Section));
        assert_eq!(entries[1].section_name.as_deref(), Some("Detection Phase"));
        assert_eq!(entries[1].section_color.as_deref(), Some("#5b9aff"));
    }

    #[test]
    fn test_log_inherits_section_context() {
        let lines = sample_lines();
        let line_refs: Vec<&str> = lines.iter().map(|s| s.as_str()).collect();
        let (entries, _) = parse_lines(&line_refs, "test.cmtlog");
        assert_eq!(entries[2].entry_kind, Some(EntryKind::Log));
        // Explicit section attr overrides inherited section name
        assert_eq!(entries[2].section_name.as_deref(), Some("detection"));
        // Color is inherited from the current section
        assert_eq!(entries[2].section_color.as_deref(), Some("#5b9aff"));
        assert_eq!(
            entries[2].tags,
            Some(vec!["phase:scan".to_string()])
        );
    }

    #[test]
    fn test_severity_mapping() {
        let lines = vec![
            r#"<![LOG[Policy validation failed]LOG]!><time="10:32:01.456+000" date="04-13-2026" component="Detect-WDAC" context="" type="3" thread="1234" file="">"#.to_string(),
        ];
        let line_refs: Vec<&str> = lines.iter().map(|s| s.as_str()).collect();
        let (entries, _) = parse_lines(&line_refs, "test.cmtlog");
        assert_eq!(entries[0].severity, Severity::Error);
    }
}
