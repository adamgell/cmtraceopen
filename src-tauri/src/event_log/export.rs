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

/// Columns every delimited export carries, in order.
///
/// `User SID` is here because it is a primary pivot for event triage; leaving it out meant an
/// analyst who exported the grid got fewer columns than the grid had shown them.
const COLUMNS: [&str; 14] = [
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
    "User SID",
    "Keywords",
    "Description",
];

/// Map-derived column names present across `records`, in first-seen order.
///
/// Appended after the fixed columns so a delimited export carries the same map values the grid
/// renders. Discovered from the records rather than declared, because which properties exist
/// depends on which maps matched.
fn mapped_columns(records: &[EvtxRecord]) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for record in records {
        for column in &record.mapped {
            if !names.iter().any(|existing| existing == &column.property) {
                names.push(column.property.clone());
            }
        }
    }
    names
}

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

/// Removes a leading `<?xml ... ?>` declaration.
///
/// Returns the input unchanged when there is none, and leaves everything after the declaration
/// exactly as the source wrote it.
fn strip_xml_declaration(xml: &str) -> &str {
    let trimmed = xml.trim_start();
    let Some(rest) = trimmed.strip_prefix("<?xml") else {
        return xml;
    };
    match rest.find("?>") {
        Some(end) => rest[end + 2..].trim_start(),
        // A declaration that never closes is not something to silently repair.
        None => xml,
    }
}

fn optional(value: Option<impl ToString>) -> String {
    value.map(|v| v.to_string()).unwrap_or_default()
}

fn row_of(record: &EvtxRecord, mapped: &[String]) -> Vec<String> {
    let mut row: Vec<String> = vec![
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
        record.user_sid.clone().unwrap_or_default(),
        record.keywords.clone().unwrap_or_default(),
        record.message.clone(),
    ];
    for property in mapped {
        // An incomplete mapping renders empty here for the same reason it does in the grid: a
        // half-substituted template would put a literal %3 into an exported cell.
        let value = record
            .mapped
            .iter()
            .find(|column| &column.property == property)
            .filter(|column| column.complete)
            .map(|column| column.text.clone())
            .unwrap_or_default();
        row.push(value);
    }
    row
}

/// Renders records in `format`.
pub fn export_records(records: &[EvtxRecord], format: ExportFormat) -> Result<String, String> {
    match format {
        ExportFormat::Csv | ExportFormat::Tsv => {
            let delimiter = format.delimiter();
            let mapped = mapped_columns(records);

            // Written straight into the output. Collecting each row into a Vec and joining it
            // allocated a vector and a fresh separator String per record, on an export that can
            // run to a hundred thousand of them.
            let mut out = String::new();
            let write_row = |out: &mut String, cells: &mut dyn Iterator<Item = &str>| {
                let mut first = true;
                for cell in cells {
                    if !first {
                        out.push(delimiter);
                    }
                    first = false;
                    out.push_str(&escape_delimited(cell, delimiter));
                }
                out.push('\n');
            };

            write_row(
                &mut out,
                &mut COLUMNS
                    .iter()
                    .copied()
                    .chain(mapped.iter().map(String::as_str)),
            );
            for record in records {
                let row = row_of(record, &mapped);
                write_row(&mut out, &mut row.iter().map(String::as_str));
            }
            Ok(out)
        }
        ExportFormat::Json => {
            serde_json::to_string_pretty(records).map_err(|error| error.to_string())
        }
        ExportFormat::Xml => {
            let mut out = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Events>\n");
            for record in records {
                // The provider's own XML is passed through otherwise untouched: re-encoding it
                // would risk changing what the source actually said, which matters when an export
                // is evidence. Only the per-record declaration is removed, because the evtx reader
                // prefixes every record with one and a declaration is legal only at the very start
                // of a document. Concatenating them produced a file no XML parser would open.
                out.push_str(strip_xml_declaration(record.raw_xml.trim()));
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
    fn the_user_sid_reaches_the_export() {
        // A primary pivot for triage. Leaving it out gave an analyst fewer columns than the grid
        // had shown them.
        let out = export_records(&[record("x")], ExportFormat::Csv).expect("exports");
        assert!(out.lines().next().expect("header").contains("User SID"));
        assert!(out.lines().nth(1).expect("row").contains("S-1-5-18"));
    }

    #[test]
    fn map_derived_columns_are_appended_after_the_fixed_ones() {
        let mut mapped = record("x");
        mapped.mapped = vec![crate::event_log::maps::MappedColumn {
            property: "PayloadData1".into(),
            text: "cmd.exe".into(),
            complete: true,
        }];

        let out = export_records(&[mapped], ExportFormat::Csv).expect("exports");
        let header = out.lines().next().expect("header");
        assert!(header.ends_with("PayloadData1"), "{header}");
        assert!(out.lines().nth(1).expect("row").ends_with("cmd.exe"));
    }

    #[test]
    fn a_record_without_a_mapped_value_leaves_the_cell_empty() {
        // The union of properties is the header, so a record the map did not match still has to
        // line up with it.
        let mut mapped = record("has one");
        mapped.mapped = vec![crate::event_log::maps::MappedColumn {
            property: "PayloadData1".into(),
            text: "cmd.exe".into(),
            complete: true,
        }];
        let plain = record("has none");

        let out = export_records(&[mapped, plain], ExportFormat::Csv).expect("exports");
        let rows: Vec<&str> = out.lines().collect();
        let columns = |line: &str| line.split(',').count();
        assert_eq!(columns(rows[0]), columns(rows[1]));
        assert_eq!(columns(rows[0]), columns(rows[2]));
        assert!(
            rows[2].ends_with(','),
            "the unmatched cell is empty: {}",
            rows[2]
        );
    }

    #[test]
    fn an_incomplete_mapping_exports_empty_rather_than_a_raw_template() {
        let mut mapped = record("x");
        mapped.mapped = vec![crate::event_log::maps::MappedColumn {
            property: "PayloadData1".into(),
            text: "ran %3 as adam".into(),
            complete: false,
        }];

        let out = export_records(&[mapped], ExportFormat::Csv).expect("exports");
        assert!(!out.contains("%3"), "{out}");
    }

    #[test]
    fn tsv_uses_tabs_and_quotes_values_containing_them() {
        let out = export_records(&[record("a\tb")], ExportFormat::Tsv).expect("exports");
        assert!(out.starts_with("Event Time\tRecord ID"));
        assert!(out.contains("\"a\tb\""));
    }

    #[test]
    fn json_carries_the_metadata_fields_with_the_wire_names_the_frontend_reads() {
        // The TypeScript EvtxRecord declares these in camelCase. Nothing on either side compares
        // the two, so a rename or a missed serde attribute would surface only as undefined in the
        // detail pane.
        let mut r = record("x");
        r.mapped = vec![crate::event_log::maps::MappedColumn {
            property: "PayloadData1".into(),
            text: "cmd.exe".into(),
            complete: true,
        }];
        let json: serde_json::Value =
            serde_json::from_str(&export_records(&[r], ExportFormat::Json).expect("exports"))
                .expect("valid JSON");
        let first = &json[0];

        // Presence, not value: the fixture leaves some of these unset on purpose, and an absent
        // optional legitimately serializes as null. What matters is that the key is there and
        // spelled the way the frontend reads it.
        for key in [
            "eventRecordId",
            "timestampEpoch",
            "sourceLabel",
            "processId",
            "threadId",
            "userSid",
            "eventData",
            "rawXml",
            "mapped",
        ] {
            assert!(first.get(key).is_some(), "{key} missing: {first}");
        }
        assert_eq!(first["eventRecordId"], 42);
        assert_eq!(first["processId"], 1234);
        assert_eq!(first["userSid"], "S-1-5-18");
        assert_eq!(first["mapped"][0]["property"], "PayloadData1");
        for snake in [
            "event_record_id",
            "timestamp_epoch",
            "source_label",
            "user_sid",
        ] {
            assert!(first.get(snake).is_none(), "{snake} leaked in snake_case");
        }
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
    fn per_record_xml_declarations_are_stripped_from_the_concatenation() {
        // The evtx reader prefixes every record with a declaration, and a declaration is legal
        // only at the very start of a document. Concatenating them produced a file no XML parser
        // would open.
        let mut record = record("x");
        record.raw_xml =
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<Event><System /></Event>".into();
        let out = export_records(&[record.clone(), record], ExportFormat::Xml).expect("exports");

        assert_eq!(
            out.matches("<?xml").count(),
            1,
            "only the document's own declaration may remain: {out}"
        );
        assert!(out.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
        assert_eq!(out.matches("<Event>").count(), 2, "both records survive");
    }

    #[test]
    fn a_record_without_a_declaration_is_untouched() {
        let out = export_records(&[record("x")], ExportFormat::Xml).expect("exports");
        assert!(out.contains("<Event><System /></Event>"));
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
