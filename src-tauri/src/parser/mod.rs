pub mod cbs;
pub mod panther;
pub mod ccm;
pub mod detect;
pub mod dism;
pub mod plain;
pub mod reporting_events;
pub mod severity;
pub mod simple;
pub mod timestamped;

use crate::models::log_entry::{LogEntry, ParseResult};
use std::path::Path;

pub use detect::ResolvedParser;

/// Result of parsing a single batch of records with a preselected parser.
pub struct ParsedChunk {
    pub entries: Vec<LogEntry>,
    pub total_lines: u32,
    pub parse_errors: u32,
}

/// Parse a log file, auto-detecting its format.
/// Returns the parse result and the backend-owned parser selection used for it.
pub fn parse_file(path: &str) -> Result<(ParseResult, ResolvedParser), String> {
    let path_obj = Path::new(path);
    let content = read_file_content(path)?;
    let file_size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);

    let selection = detect::detect_parser(path, &content);
    let parsed_chunk = parse_content_with_selection(&content, path, &selection);

    let result = ParseResult {
        entries: parsed_chunk.entries,
        format_detected: selection.compatibility_format(),
        parser_selection: selection.to_info(),
        total_lines: parsed_chunk.total_lines,
        parse_errors: parsed_chunk.parse_errors,
        file_path: path_obj.to_string_lossy().to_string(),
        file_size,
        // After initial parse, the byte offset is the file size
        byte_offset: file_size,
    };

    Ok((result, selection))
}

/// Parse already-split lines using the backend-owned parser selection.
pub fn parse_lines_with_selection(
    lines: &[&str],
    file_path: &str,
    selection: &ResolvedParser,
) -> (Vec<LogEntry>, u32) {
    match selection.implementation {
        crate::models::log_entry::ParserImplementation::Ccm => {
            ccm::parse_lines_with_specialization(lines, file_path, selection.specialization)
        }
        crate::models::log_entry::ParserImplementation::Simple => {
            simple::parse_lines(lines, file_path)
        }
        crate::models::log_entry::ParserImplementation::ReportingEvents => {
            reporting_events::parse_lines(lines, file_path)
        }
        crate::models::log_entry::ParserImplementation::PlainText => {
            plain::parse_lines(lines, file_path)
        }
        crate::models::log_entry::ParserImplementation::GenericTimestamped => match selection.parser {
            crate::models::log_entry::ParserKind::Cbs => cbs::parse_lines(lines, file_path),
            crate::models::log_entry::ParserKind::Dism => dism::parse_lines(lines, file_path),
            crate::models::log_entry::ParserKind::Panther => {
                panther::parse_lines(lines, file_path)
            }
            _ => timestamped::parse_lines(lines, file_path, selection.date_order),
        },
    }
}

/// Parse text content using the backend-owned parser selection.
pub fn parse_content_with_selection(
    content: &str,
    file_path: &str,
    selection: &ResolvedParser,
) -> ParsedChunk {
    let total_lines = content.lines().count() as u32;
    let (entries, parse_errors) = match selection.implementation {
        crate::models::log_entry::ParserImplementation::Ccm => {
            ccm::parse_content(content, file_path, selection.specialization)
        }
        _ => {
            let lines: Vec<&str> = content.lines().collect();
            parse_lines_with_selection(&lines, file_path, selection)
        }
    };

    ParsedChunk {
        entries,
        total_lines,
        parse_errors,
    }
}

/// Read file content, handling BOM and encoding fallback.
fn read_file_content(path: &str) -> Result<String, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("Failed to read file {}: {}", path, e))?;

    // Try UTF-8 first (strip BOM if present)
    let bytes_no_bom = if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        &bytes[3..]
    } else {
        &bytes
    };

    match std::str::from_utf8(bytes_no_bom) {
        Ok(s) => Ok(s.to_string()),
        Err(_) => {
            // Fallback to Windows-1252 (common for SCCM logs)
            let (cow, _, had_errors) = encoding_rs::WINDOWS_1252.decode(bytes_no_bom);
            if had_errors {
                log::warn!("Encoding errors while reading {}", path);
            }
            Ok(cow.into_owned())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::log_entry::{ParseQuality, ParserImplementation, ParserKind, ParserProvenance, ParserSpecialization, RecordFraming};
    use crate::parser::timestamped::DateOrder;

    #[test]
    fn test_parse_lines_with_selection_uses_timestamp_date_order() {
        let selection = ResolvedParser::generic_timestamped(DateOrder::DayFirst);
        let lines = ["15/01/2024 08:00:00 Processing request"];

        let (entries, parse_errors) = parse_lines_with_selection(&lines, "sample.log", &selection);

        assert_eq!(parse_errors, 0);
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].timestamp_display.as_deref(),
            Some("2024-01-15 08:00:00.000")
        );
    }

    #[test]
    fn test_parse_lines_with_selection_can_use_panther_selection() {
        let selection = ResolvedParser::new(
            ParserKind::Panther,
            ParserImplementation::GenericTimestamped,
            ParserProvenance::Dedicated,
            ParseQuality::SemiStructured,
            RecordFraming::LogicalRecord,
            DateOrder::MonthFirst,
            None,
        );
        let lines = ["2024-01-15 08:00:00, Info SP Setup complete"];

        let (entries, parse_errors) = parse_lines_with_selection(&lines, "setupact.log", &selection);

        assert_eq!(parse_errors, 0);
        assert_eq!(entries.len(), 1);
        assert_eq!(selection.compatibility_format(), crate::models::log_entry::LogFormat::Timestamped);
        assert_eq!(entries[0].message, "Setup complete");
        assert_eq!(entries[0].component.as_deref(), Some("SP"));
    }

    #[test]
    fn test_parse_lines_with_selection_can_use_cbs_selection() {
        let selection = ResolvedParser::new(
            ParserKind::Cbs,
            ParserImplementation::GenericTimestamped,
            ParserProvenance::Dedicated,
            ParseQuality::SemiStructured,
            RecordFraming::LogicalRecord,
            DateOrder::MonthFirst,
            None,
        );
        let lines = [
            "2024-01-15 08:00:00, Info                  CBS    Exec: Started servicing",
            "Continuation detail",
        ];

        let (entries, parse_errors) = parse_lines_with_selection(&lines, "CBS.log", &selection);

        assert_eq!(parse_errors, 0);
        assert_eq!(entries.len(), 1);
        assert_eq!(selection.compatibility_format(), crate::models::log_entry::LogFormat::Timestamped);
        assert_eq!(entries[0].component.as_deref(), Some("CBS"));
        assert_eq!(entries[0].message, "Exec: Started servicing\nContinuation detail");
    }

    #[test]
    fn test_parse_lines_with_selection_can_use_dism_selection() {
        let selection = ResolvedParser::new(
            ParserKind::Dism,
            ParserImplementation::GenericTimestamped,
            ParserProvenance::Dedicated,
            ParseQuality::SemiStructured,
            RecordFraming::LogicalRecord,
            DateOrder::MonthFirst,
            None,
        );
        let lines = [
            "2024-01-15 08:00:00, Warning               DISM   DISM Package Manager: Retry needed",
            "Extra context",
        ];

        let (entries, parse_errors) = parse_lines_with_selection(&lines, "DISM.log", &selection);

        assert_eq!(parse_errors, 0);
        assert_eq!(entries.len(), 1);
        assert_eq!(selection.compatibility_format(), crate::models::log_entry::LogFormat::Timestamped);
        assert_eq!(entries[0].component.as_deref(), Some("DISM"));
        assert_eq!(entries[0].message, "DISM Package Manager: Retry needed\nExtra context");
    }

    #[test]
    fn test_parse_lines_with_selection_can_use_reporting_events_selection() {
        let selection = ResolvedParser::new(
            ParserKind::ReportingEvents,
            ParserImplementation::ReportingEvents,
            ParserProvenance::Dedicated,
            ParseQuality::Structured,
            RecordFraming::PhysicalLine,
            DateOrder::MonthFirst,
            None,
        );
        let lines = [
            "{11111111-1111-1111-1111-111111111111}\t2024-01-15 08:00:00:123\t1\tSoftware Update\t3\t{22222222-2222-2222-2222-222222222222}\t0x80240022\tWindows Update Agent\tFailure\tInstallation\tInstallation failed for KB5034123",
        ];

        let (entries, parse_errors) = parse_lines_with_selection(&lines, "ReportingEvents.log", &selection);

        assert_eq!(parse_errors, 0);
        assert_eq!(entries.len(), 1);
        assert_eq!(selection.compatibility_format(), crate::models::log_entry::LogFormat::Timestamped);
        assert_eq!(entries[0].component.as_deref(), Some("Windows Update Agent"));
        assert_eq!(entries[0].severity, crate::models::log_entry::Severity::Error);
    }

    #[test]
    fn test_parse_lines_with_selection_can_use_ime_specialization() {
        let selection = ResolvedParser::new(
            ParserKind::Ccm,
            ParserImplementation::Ccm,
            ParserProvenance::Dedicated,
            ParseQuality::Structured,
            RecordFraming::LogicalRecord,
            DateOrder::MonthFirst,
            Some(ParserSpecialization::Ime),
        );
        let lines = [
            r#"<![LOG[Powershell execution is done, exitCode = 1]LOG]!><time="11:16:37.3093207" date="3-12-2026" component="HealthScripts" context="" type="1" thread="50" file="">"#,
            r#"<![LOG[[HS] err output = Downloaded profile payload is not valid JSON."#,
            r#"At C:\Windows\IMECache\HealthScripts\script.ps1:457 char:9"#,
            r#"]LOG]!><time="11:16:42.3322734" date="3-12-2026" component="HealthScripts" context="" type="1" thread="50" file="">"#,
        ];

        let (entries, parse_errors) = parse_lines_with_selection(&lines, "HealthScripts.log", &selection);

        assert_eq!(parse_errors, 0);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].line_number, 1);
        assert_eq!(entries[1].line_number, 2);
        assert!(entries[1].message.contains("Downloaded profile payload is not valid JSON"));
        assert!(entries[1].message.contains("At C:\\Windows\\IMECache\\HealthScripts\\script.ps1:457 char:9"));
    }

    #[test]
    fn test_parse_content_with_selection_can_use_ime_specialization() {
        let selection = ResolvedParser::new(
            ParserKind::Ccm,
            ParserImplementation::Ccm,
            ParserProvenance::Dedicated,
            ParseQuality::Structured,
            RecordFraming::LogicalRecord,
            DateOrder::MonthFirst,
            Some(ParserSpecialization::Ime),
        );
        let content = concat!(
            "<![LOG[Client Health evaluation starts.]LOG]!><time=\"23:00:10.6893636\" date=\"11-12-2025\" component=\"ClientHealth\" context=\"\" type=\"1\" thread=\"1\" file=\"\">\n",
            "<![LOG[Set MdmDeviceCertificate : 3788C1E384FDCB3F173A3222CB4191883A94224E\n",
            "More detail]LOG]!><time=\"23:00:11.4573058\" date=\"11-12-2025\" component=\"ClientHealth\" context=\"\" type=\"3\" thread=\"1\" file=\"\">"
        );

        let parsed = parse_content_with_selection(content, "ClientHealth.log", &selection);

        assert_eq!(parsed.total_lines, 3);
        assert_eq!(parsed.parse_errors, 0);
        assert_eq!(parsed.entries.len(), 2);
        assert_eq!(parsed.entries[0].format, crate::models::log_entry::LogFormat::Ccm);
        assert_eq!(parsed.entries[1].line_number, 2);
        assert_eq!(parsed.entries[1].severity, crate::models::log_entry::Severity::Error);
        assert!(parsed.entries[1].message.contains("More detail"));
    }

    #[test]
    fn test_parse_content_with_selection_keeps_non_ime_ccm_physical_line_behavior() {
        let selection = ResolvedParser::ccm();
        let content = concat!(
            "<![LOG[Normal CCM record]LOG]!><time=\"08:00:00.000+000\" date=\"01-01-2024\" component=\"Test\" context=\"\" type=\"1\" thread=\"100\" file=\"\">\n",
            "Continuation that should remain a plain fallback line"
        );

        let parsed = parse_content_with_selection(content, "sample.log", &selection);

        assert_eq!(parsed.total_lines, 2);
        assert_eq!(parsed.parse_errors, 1);
        assert_eq!(parsed.entries.len(), 2);
        assert_eq!(parsed.entries[0].format, crate::models::log_entry::LogFormat::Ccm);
        assert_eq!(parsed.entries[1].format, crate::models::log_entry::LogFormat::Plain);
        assert_eq!(parsed.entries[1].line_number, 2);
    }
}
