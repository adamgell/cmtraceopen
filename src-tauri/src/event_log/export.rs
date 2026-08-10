//! Exporting event records to text formats.
//!
//! FullEventLogView offers nine export formats and we offered none, which made every analysis
//! dead-end in the app. This covers the three that carry the data losslessly enough to be worth
//! having: CSV for spreadsheets, JSON for tooling, and raw event XML for anything that wants the
//! provider's own representation.
//!
//! Formatting is deliberately separate from writing files, so the rules below are unit-testable
//! without touching the filesystem.

use serde::{Deserialize, Serialize};

use super::models::EvtxRecord;

/// A supported export format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ExportFormat {
    /// Comma-separated, one row per event, with a header line.
    Csv,
    /// Tab-separated, one row per event, with a header line.
    Tsv,
    /// A JSON array of the full records.
    Json,
    /// The provider's own event XML, concatenated under a single root.
    Xml,
}

impl ExportFormat {
    /// The conventional file extension.
    pub fn extension(&self) -> &'static str {
        match self {
            Self::Csv => "csv",
            Self::Tsv => "tsv",
            Self::Json => "json",
            Self::Xml => "xml",
        }
    }

    fn delimiter(&self) -> char {
        match self {
            Self::Tsv => '\t',
            _ => ',',
        }
    }
}

const COLUMNS: [&str; 13] = [
    "Event Time",
    "Record ID",
    "Event ID",
    "Level",
    "Provider",
    "Channel",
    "Computer",
    "Task",
    "Opcode",
    "Process ID",
    "Thread ID",
    "Keywords",
    "Description",
];

/// Neutralizes a value that a spreadsheet would otherwise execute as a formula.
///
/// Excel and LibreOffice treat a leading `=`, `+`, `-` or `@` as the start of a formula. Event
/// descriptions and command lines routinely begin with those characters, and an attacker who can
/// influence event content can otherwise get code to run when an analyst opens the export. A
/// leading apostrophe forces the cell to be read as text.
fn neutralize_formula(value: &str) -> String {
    match value.chars().next() {
        Some('=') | Some('+') | Some('-') | Some('@') => format!("'{value}"),
        // Tab and carriage return are also treated as formula leads by some spreadsheet readers.
        Some('\t') | Some('\r') => format!("'{value}"),
        _ => value.to_string(),
    }
}

/// Quotes a field for delimiter-separated output.
///
/// Always quoting would be simpler, but unquoted values keep exports diffable, so quoting is
/// applied only where the value would otherwise break the row.
fn escape_delimited(value: &str, delimiter: char) -> String {
    let value = neutralize_formula(value);
    let needs_quotes = value.contains(delimiter)
        || value.contains('"')
        || value.contains('\n')
        || value.contains('\r');
    if needs_quotes {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value
    }
}

fn optional(value: Option<impl ToString>) -> String {
    value.map(|v| v.to_string()).unwrap_or_default()
}

fn row_of(record: &EvtxRecord) -> [String; 13] {
    [
        record.timestamp.clone(),
        record.event_record_id.to_string(),
        record.event_id.to_string(),
        format!("{:?}", record.level),
        record.provider.clone(),
        record.channel.clone(),
        record.computer.clone(),
        optional(record.task),
        optional(record.opcode),
        optional(record.process_id),
        optional(record.thread_id),
        record.keywords.clone().unwrap_or_default(),
        record.message.clone(),
    ]
}

/// Renders records in `format`.
pub fn export_records(records: &[EvtxRecord], format: ExportFormat) -> Result<String, String> {
    match format {
        ExportFormat::Csv | ExportFormat::Tsv => {
            let delimiter = format.delimiter();
            let mut out = String::new();
            out.push_str(
                &COLUMNS
                    .iter()
                    .map(|column| escape_delimited(column, delimiter))
                    .collect::<Vec<_>>()
                    .join(&delimiter.to_string()),
            );
            out.push('\n');
            for record in records {
                let row = row_of(record);
                out.push_str(
                    &row.iter()
                        .map(|value| escape_delimited(value, delimiter))
                        .collect::<Vec<_>>()
                        .join(&delimiter.to_string()),
                );
                out.push('\n');
            }
            Ok(out)
        }
        ExportFormat::Json => {
            serde_json::to_string_pretty(records).map_err(|error| error.to_string())
        }
        ExportFormat::Xml => {
            let mut out = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Events>\n");
            for record in records {
                // The provider's own XML is passed through untouched. Re-encoding it would risk
                // changing what the source actually said, which matters when an export is evidence.
                out.push_str(record.raw_xml.trim());
                out.push('\n');
            }
            out.push_str("</Events>\n");
            Ok(out)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_log::models::EvtxLevel;

    fn record(message: &str) -> EvtxRecord {
        EvtxRecord {
            id: 0,
            event_record_id: 42,
            timestamp: "2026-08-09 12:00:00".into(),
            timestamp_epoch: 0,
            provider: "ESENT".into(),
            channel: "Application".into(),
            event_id: 326,
            level: EvtxLevel::Error,
            computer: "TESTHOST-01".into(),
            message: message.into(),
            event_data: Vec::new(),
            raw_xml: "<Event><System /></Event>".into(),
            source_label: "Live".into(),
            task: Some(13312),
            opcode: None,
            process_id: Some(1234),
            thread_id: None,
            user_sid: Some("S-1-5-18".into()),
            keywords: Some("0x80".into()),
            mapped: Vec::new(),
        }
    }

    fn csv_body(message: &str) -> String {
        let out = export_records(&[record(message)], ExportFormat::Csv).expect("exports");
        out.lines().nth(1).expect("data row").to_string()
    }

    #[test]
    fn csv_starts_with_a_header_row() {
        let out = export_records(&[], ExportFormat::Csv).expect("exports");
        assert!(out.starts_with("Event Time,Record ID,Event ID,Level,"));
    }

    #[test]
    fn a_value_containing_the_delimiter_is_quoted() {
        assert!(csv_body("a, b").contains("\"a, b\""));
    }

    #[test]
    fn embedded_quotes_are_doubled() {
        assert!(csv_body("say \"hi\"").contains("\"say \"\"hi\"\"\""));
    }

    #[test]
    fn a_newline_inside_a_value_is_quoted_rather_than_breaking_the_row() {
        let out = export_records(&[record("line1\nline2")], ExportFormat::Csv).expect("exports");
        assert!(out.contains("\"line1\nline2\""));
        // Header plus one logical row; the embedded newline must stay inside the quoted field.
        assert_eq!(out.matches("2026-08-09 12:00:00").count(), 1);
    }

    #[test]
    fn a_leading_equals_cannot_execute_as_a_spreadsheet_formula() {
        // Event content is attacker-influenceable, and an analyst opening the export in Excel
        // would otherwise run it.
        let body = csv_body("=cmd|'/c calc'!A1");
        assert!(body.contains("'=cmd"), "{body}");
        assert!(!body.contains(",=cmd"), "{body}");
    }

    #[test]
    fn the_other_formula_leads_are_neutralized_too() {
        for lead in ['+', '-', '@'] {
            let body = csv_body(&format!("{lead}danger"));
            assert!(body.contains(&format!("'{lead}danger")), "{body}");
        }
    }

    #[test]
    fn an_ordinary_value_is_not_quoted_so_exports_stay_diffable() {
        let body = csv_body("plain text");
        assert!(body.contains(",plain text"), "{body}");
    }

    #[test]
    fn an_absent_optional_renders_empty_rather_than_zero() {
        // Opcode and thread id are None on the fixture; claiming 0 would invent provider data.
        let body = csv_body("x");
        let fields: Vec<&str> = body.split(',').collect();
        assert_eq!(fields[7], "13312", "task present");
        assert_eq!(fields[8], "", "opcode absent");
        assert_eq!(fields[10], "", "thread id absent");
    }

    #[test]
    fn tsv_uses_tabs_and_quotes_values_containing_them() {
        let out = export_records(&[record("a\tb")], ExportFormat::Tsv).expect("exports");
        assert!(out.starts_with("Event Time\tRecord ID"));
        assert!(out.contains("\"a\tb\""));
    }

    #[test]
    fn json_round_trips_back_into_records() {
        let out = export_records(&[record("hello")], ExportFormat::Json).expect("exports");
        let restored: Vec<EvtxRecord> = serde_json::from_str(&out).expect("valid JSON");
        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].event_record_id, 42);
        assert_eq!(restored[0].task, Some(13312));
        assert_eq!(restored[0].opcode, None);
    }

    #[test]
    fn xml_passes_the_provider_representation_through_untouched() {
        let out = export_records(&[record("x")], ExportFormat::Xml).expect("exports");
        assert!(out.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
        assert!(out.contains("<Events>"));
        assert!(out.contains("<Event><System /></Event>"));
        assert!(out.trim_end().ends_with("</Events>"));
    }

    #[test]
    fn an_empty_export_is_still_well_formed() {
        assert!(export_records(&[], ExportFormat::Json).expect("exports") == "[]");
        let xml = export_records(&[], ExportFormat::Xml).expect("exports");
        assert!(xml.contains("<Events>") && xml.contains("</Events>"));
    }

    #[test]
    fn extensions_match_the_format() {
        assert_eq!(ExportFormat::Csv.extension(), "csv");
        assert_eq!(ExportFormat::Tsv.extension(), "tsv");
        assert_eq!(ExportFormat::Json.extension(), "json");
        assert_eq!(ExportFormat::Xml.extension(), "xml");
    }
}
