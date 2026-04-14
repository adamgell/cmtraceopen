//! CmtLog format parser.
//!
//! Extends CCM's `<![LOG[...]LOG]!>` line format with reserved component names
//! (`__HEADER__`, `__SECTION__`, `__ITERATION__`) and optional extended attributes
//! (`section`, `tag`, `whatif`, `iteration`, `color`).
//!
//! Delegates core CCM line parsing to `ccm::parse_lines`, then post-processes
//! entries to extract extended attributes and classify by component name.

use regex::Regex;
use std::sync::OnceLock;

use super::ccm;
use crate::models::log_entry::{EntryKind, LogEntry, LogFormat};

/// Reserved component names that signal CmtLog structured entries.
const HEADER_COMPONENT: &str = "__HEADER__";
const SECTION_COMPONENT: &str = "__SECTION__";
const ITERATION_COMPONENT: &str = "__ITERATION__";

/// Compiled regex for extracting key="value" pairs from raw log lines.
fn attr_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| Regex::new(r#"(\w+)="([^"]*)""#).expect("attr regex must compile"))
}

/// Returns true if the line contains any CmtLog reserved component name,
/// indicating the file uses the CmtLog format rather than plain CCM.
pub fn matches_cmtlog_record(line: &str) -> bool {
    line.contains(HEADER_COMPONENT)
        || line.contains(SECTION_COMPONENT)
        || line.contains(ITERATION_COMPONENT)
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

/// Parse all lines as CmtLog format.
///
/// Delegates to `ccm::parse_lines` for base parsing, then post-processes each
/// entry to extract CmtLog-specific attributes and classify by component name.
///
/// Returns `(entries, parse_error_count)`.
pub fn parse_lines(lines: &[&str], file_path: &str) -> (Vec<LogEntry>, u32) {
    let (mut entries, parse_errors) = ccm::parse_lines(lines, file_path);

    // Track current section context for propagation to child entries.
    let mut current_section_name: Option<String> = None;
    let mut current_section_color: Option<String> = None;

    for (entry, raw_line) in entries.iter_mut().zip(lines.iter()) {
        // Override format to CmtLog for all entries.
        entry.format = LogFormat::CmtLog;

        let attrs = extract_attrs(raw_line);
        let component = entry.component.as_deref().unwrap_or("");

        match component {
            HEADER_COMPONENT => {
                entry.entry_kind = Some(EntryKind::Header);
            }
            SECTION_COMPONENT => {
                entry.entry_kind = Some(EntryKind::Section);
                // The message IS the section name.
                current_section_name = Some(entry.message.clone());
                current_section_color = attrs.color.clone();
                entry.section_name = Some(entry.message.clone());
                entry.section_color = attrs.color;
            }
            ITERATION_COMPONENT => {
                entry.entry_kind = Some(EntryKind::Iteration);
                entry.iteration = attrs.iteration;
                // Inherit parent section color if no explicit color.
                entry.section_color = attrs.color.or_else(|| current_section_color.clone());
                entry.section_name = current_section_name.clone();
            }
            _ => {
                // Regular log entry — propagate section context.
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
    }

    (entries, parse_errors)
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
