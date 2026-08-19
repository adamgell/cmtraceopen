//! Exporting event records to text formats.
//!
//! FullEventLogView offers nine export formats and we offered none, which made every analysis
//! dead-end in the app. This covers the three that carry the data losslessly enough to be worth
//! having: CSV for spreadsheets, JSON for tooling, and raw event XML for anything that wants the
//! provider's own representation.
//!
//! Formatting is deliberately separate from writing files, so the rules below are unit-testable
//! without touching the filesystem.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use cmtraceopen_parser::intune::apps::windows::common::redact_text;


const MAX_RAW_XML_BYTES: usize = 256 * 1024;
use super::models::EvtxRecord;

/// A supported export format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ExportFormat {
    /// Comma-separated, one row per event, with a header line.
    Csv,
    /// Tab-separated, one row per event, with a header line.
    Tsv,
    /// A JSON array of the redacted normalized records.
    Json,
    /// Redacted provider event XML concatenated under a single root.
    Xml,
    /// An escaped HTML table of the redacted normalized fields.
    Html,
    /// Redacted provider event XML without an added document root.
    RawXml,
}

impl ExportFormat {
    /// The conventional file extension.
    pub fn extension(&self) -> &'static str {
        match self {
            Self::Csv => "csv",
            Self::Tsv => "tsv",
            Self::Json => "json",
            Self::Xml | Self::RawXml => "xml",
            Self::Html => "html",
        }
    }
    pub(crate) fn delimiter(&self) -> char {
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
pub(crate) const COLUMNS: [&str; 15] = [
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
    "Source Label",
];

/// Map-derived column names present across `records`, in first-seen order.
///
/// Appended after the fixed columns so a delimited export carries the same map values the grid
/// renders. Discovered from the records rather than declared, because which properties exist
/// depends on which maps matched.
pub(crate) fn mapped_columns(records: &[EvtxRecord]) -> Vec<String> {
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
pub(crate) fn neutralize_formula(value: &str) -> String {
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
pub(crate) fn escape_delimited(value: &str, delimiter: char) -> String {
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
pub(crate) fn strip_xml_declaration(xml: &str) -> &str {
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

pub(crate) fn row_of(record: &EvtxRecord, mapped: &[String]) -> Vec<String> {
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
        record.source_label.clone(),
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
/// Produces the default-safe projection used by every export format.
///
/// Redaction is performed immediately before serialization so the interactive
/// record remains useful in memory while neither normalized fields nor provider
/// XML can bypass the export boundary.
pub(crate) fn redact_record(record: &EvtxRecord) -> EvtxRecord {
    let mut redacted = record.clone();
    redacted.timestamp = redact_text(&record.timestamp);
    redacted.provider = redact_text(&record.provider);
    redacted.channel = redact_text(&record.channel);
    redacted.message = redact_text(&record.message);
    redacted.computer = redact_labeled_value("ComputerName", &record.computer);
    redacted.raw_xml = redact_raw_xml(&record.raw_xml);
    redacted.source_label = redact_text(&record.source_label);
    redacted.event_data = record
        .event_data
        .iter()
        .map(|field| super::models::EvtxField {
            name: field.name.clone(),
            value: redact_labeled_value(&field.name, &field.value),
        })
        .collect();
    redacted.user_sid = record.user_sid.as_deref().map(redact_text);
    redacted.mapped = record
        .mapped
        .iter()
        .map(|column| super::maps::MappedColumn {
            property: column.property.clone(),
            text: redact_labeled_value(&column.property, &column.text),
            complete: column.complete,
        })
        .collect();
    redacted
}
fn redact_labeled_value(label: &str, value: &str) -> String {
    let prefix = format!("{label}=");
    let redacted = redact_text(&format!("{prefix}{value}"));
    redacted
        .strip_prefix(&prefix)
        .unwrap_or(&redacted)
        .to_owned()
}

fn redact_xml_value(label: &str, value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return value.to_owned();
    }
    let start = value.find(trimmed).expect("trimmed value is present");
    let end = start + trimmed.len();
    format!(
        "{}{}{}",
        &value[..start],
        redact_labeled_value(label, trimmed),
        &value[end..]
    )
}

fn event_data_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(
            r#"(?is)(?P<open><(?:[\w.-]+:)?Data\b[^>]*\bName\s*=\s*["'](?P<label>[^"']+)["'][^>]*>)(?P<value>[^<]*)(?P<close></(?:[\w.-]+:)?Data\s*>)"#,
        )
        .expect("event data redaction pattern must compile")
    })
}

fn cdata_event_data_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(
            r#"(?is)(?P<open><(?:[\w.-]+:)?Data\b[^>]*\bName\s*=\s*["'](?P<label>[^"']+)["'][^>]*>)(?P<leading>\s*)<!\[CDATA\[(?P<value>.*?)\]\]>(?P<trailing>\s*)(?P<close></(?:[\w.-]+:)?Data\s*>)"#,
        )
        .expect("CDATA event data redaction pattern must compile")
    })
}

fn labeled_xml_field_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(
            r#"(?is)(?P<open><(?:[\w.-]+:)?(?P<label>Computer|ComputerName|DeviceName|MachineName|HostName|SubjectUserName|SubjectDomainName|RemoteHost|SerialNumber|DeviceId|HardwareHash|DeviceHardwareData|TargetUserName|UserName|RunAsUser|UserId|TenantId|Password|ApiKey|ApiSecret|AccessToken|Token|Secret|ClientSecret|Credential|CredentialData)\b[^>]*>)(?P<value>[^<]*)(?P<close></(?:[\w.-]+:)?(?:Computer|ComputerName|DeviceName|MachineName|HostName|SubjectUserName|SubjectDomainName|RemoteHost|SerialNumber|DeviceId|HardwareHash|DeviceHardwareData|TargetUserName|UserName|RunAsUser|UserId|TenantId|Password|ApiKey|ApiSecret|AccessToken|Token|Secret|ClientSecret|Credential|CredentialData)\s*>)"#,
        )
        .expect("labeled XML field redaction pattern must compile")
    })
}

fn xml_name_attribute(tag: &str) -> Option<String> {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r#"(?i)\bName\s*=\s*["']([^"']+)["']"#)
            .expect("XML Name attribute pattern must compile")
    })
    .captures(tag)
    .map(|captures| captures[1].to_owned())
}

fn redact_xml_tag(tag: &str) -> String {
    let mut output = String::with_capacity(tag.len());
    let mut cursor = 0;
    let context_label = xml_name_attribute(tag).map(|label| {
        if label.eq_ignore_ascii_case("Computer") {
            "ComputerName".to_owned()
        } else {
            label
        }
    });
    let mut pending_label: Option<String> = None;
    while cursor < tag.len() {
        let Some(relative) = tag[cursor..].find(['"', '\''])
        else {
            output.push_str(&tag[cursor..]);
            break;
        };
        let opening = cursor + relative;
        output.push_str(&tag[cursor..=opening]);
        let quote = tag.as_bytes()[opening];
        let Some(relative_end) = tag[opening + 1..].find(quote as char) else {
            output.push_str(&tag[opening + 1..]);
            break;
        };
        let end = opening + 1 + relative_end;
        let before = tag[..opening].trim_end();
        let attr_name = before
            .rfind('=')
            .and_then(|equals| before[..equals].trim_end().rsplit([' ', '\t']).next())
            .unwrap_or("")
            .trim_start_matches(['<', '/']);
        let value = &tag[opening + 1..end];
        let label = if attr_name.eq_ignore_ascii_case("value") {
            pending_label
                .as_deref()
                .or(context_label.as_deref())
                .unwrap_or(attr_name)
        } else if attr_name.eq_ignore_ascii_case("computer") {
            "ComputerName"
        } else {
            attr_name
        };
        if attr_name.eq_ignore_ascii_case("name") {
            pending_label = Some(value.to_owned());
            output.push_str(value);
        } else {
            output.push_str(&redact_xml_value(label, value));
            if attr_name.eq_ignore_ascii_case("value") {
                pending_label = None;
            }
        }
        output.push(quote as char);

        cursor = end + 1;
    }
    output
}
fn redact_xml_text(text: &str) -> String {
    if let Ok(decoded) = quick_xml::escape::unescape(text) {
        let redacted = redact_text(&decoded);
        if redacted != decoded {
            return redacted;
        }
    }
    redact_text(text)
}

fn redact_raw_xml(xml: &str) -> String {
    if xml.len() > MAX_RAW_XML_BYTES {
        return "<Event><Redaction>[redacted: oversized text omitted]</Redaction></Event>".to_owned();
    }
    let labeled = event_data_pattern().replace_all(xml, |captures: &regex::Captures<'_>| {
        let label = if captures["label"].eq_ignore_ascii_case("Computer") {
            "ComputerName"
        } else {
            &captures["label"]
        };
        format!(
            "{}{}{}",
            &captures["open"],
            redact_xml_value(label, &captures["value"]),
            &captures["close"],
        )
    });
    let labeled = labeled_xml_field_pattern().replace_all(&labeled, |captures: &regex::Captures<'_>| {
        let label = if captures["label"].eq_ignore_ascii_case("Computer") {
            "ComputerName"
        } else {
            &captures["label"]
        };
        format!(
            "{}{}{}",
            &captures["open"],
            redact_xml_value(label, &captures["value"]),
            &captures["close"],
        )
    });
    let labeled = cdata_event_data_pattern().replace_all(&labeled, |captures: &regex::Captures<'_>| {
        format!(
            "{}{}<![CDATA[{}]]>{}{}",
            &captures["open"],
            &captures["leading"],
            redact_xml_value(&captures["label"], &captures["value"]),
            &captures["trailing"],
            &captures["close"],
        )
    });
    let mut output = String::with_capacity(labeled.len());
    let mut cursor = 0;
    while cursor < labeled.len() {
        let Some(relative_open) = labeled[cursor..].find('<') else {
            output.push_str(&redact_xml_text(&labeled[cursor..]));
            break;
        };
        let opening = cursor + relative_open;
        output.push_str(&redact_xml_text(&labeled[cursor..opening]));
        let tail = &labeled[opening..];
        if let Some(content) = tail.strip_prefix("<?") {
            if let Some(end) = content.find("?>") {
                output.push_str("<?");
                output.push_str(&redact_xml_text(&content[..end]));
                output.push_str("?>");
                cursor = opening + 2 + end + 2;
                continue;
            }
            output.push_str("<?");
            output.push_str(&redact_xml_text(content));
            break;
        }
        if let Some(content) = tail.strip_prefix("<!--") {
            if let Some(end) = content.find("-->") {
                output.push_str("<!--");
                output.push_str(&redact_xml_text(&content[..end]));
                output.push_str("-->");
                cursor = opening + 4 + end + 3;
                continue;
            }
            output.push_str("<!--");
            output.push_str(&redact_xml_text(content));
            break;
        }
        if let Some(content) = tail.strip_prefix("<![CDATA[") {
            if let Some(end) = content.find("]]>") {
                output.push_str("<![CDATA[");
                output.push_str(&redact_text(&content[..end]));
                output.push_str("]]>");
                cursor = opening + 9 + end + 3;
                continue;
            }
            output.push_str("<![CDATA[");
            output.push_str(&redact_text(content));
            break;
        }
        let mut end = opening + 1;
        let mut quote = None;
        while end < labeled.len() {
            let byte = labeled.as_bytes()[end];
            if let Some(expected) = quote {
                if byte == expected {
                    quote = None;
                }
            } else if byte == b'"' || byte == b'\'' {
                quote = Some(byte);
            } else if byte == b'>' {
                end += 1;
                break;
            }
            end += 1;
        }
        output.push_str(&redact_xml_tag(&labeled[opening..end]));
        cursor = end;
    }
    output
}

/// Renders records in `format`.
pub fn export_records(records: &[EvtxRecord], format: ExportFormat) -> Result<String, String> {
    super::writer::validate_raw_xml(records, format).map_err(|error| error.to_string())?;
    let mut output = Vec::new();
    super::writer::write_record_stream(
        &mut output,
        format,
        records.iter(),
        &mapped_columns(records),
    )
    .map_err(|error| error.to_string())?;
    String::from_utf8(output).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_log::models::EvtxLevel;

    fn record(message: &str) -> EvtxRecord {
        EvtxRecord {
            id: 0,
            event_record_id: 42,
            event_record_id_text: None,
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
            activity_id: None,
            related_activity_id: None,
            session_id: None,
            device_id: None,
            user_id: None,
            process_start_time: None,
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
        assert!(out.contains("Live"));
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
    fn a_delimited_export_works_from_a_payload_without_raw_xml() {
        // The frontend omits rawXml for CSV and TSV because neither reads it and it dominates the
        // IPC payload. Deserializing has to tolerate that, and the output must be unchanged.
        let mut trimmed = record("x");
        trimmed.raw_xml = String::new();

        let with_xml = export_records(&[record("x")], ExportFormat::Csv).expect("exports");
        let without = export_records(&[trimmed], ExportFormat::Csv).expect("exports");
        assert_eq!(with_xml, without);
    }

    #[test]
    fn a_record_missing_raw_xml_still_deserializes() {
        let json = serde_json::json!([{
            "id": 0, "eventRecordId": 1, "timestamp": "", "timestampEpoch": 0,
            "provider": "P", "channel": "C", "eventId": 1, "level": "Error",
            "computer": "TESTHOST-01", "message": "m", "sourceLabel": "Live", "mapped": []
        }]);
        let records: Vec<EvtxRecord> =
            serde_json::from_value(json).expect("a trimmed payload deserializes");
        assert_eq!(records[0].raw_xml, "");
        assert!(records[0].event_data.is_empty());
    }

    #[test]
    fn raw_xml_attributes_and_processing_instructions_are_redacted() {
        let mut event = record("safe");
        event.raw_xml = r#"<Event Computer="DESKTOP-JOHN"><SerialNumber>ABC123456</SerialNumber><TargetUserName>CONTOSO\Jane Doe</TargetUserName><TenantId>99999999-8888-4777-8666-555555555555</TenantId><Password>hunter2</Password><Data Value="REMOTE-HOST" Name="RemoteHost" /><Data Name="Computer" Value="DESKTOP-JOHN" /><Encoded>PASSWORD&#x3D;encoded-secret</Encoded><Message><?provider PASSWORD=hunter2?></Message></Event>"#.into();
        for format in [ExportFormat::Json, ExportFormat::Xml, ExportFormat::RawXml] {
            let output = export_records(&[event.clone()], format).expect("export");
            assert!(!output.contains("DESKTOP-JOHN"));
            assert!(!output.contains("REMOTE-HOST"));
            assert!(!output.contains("ABC123456"));
            assert!(!output.contains("Jane Doe"));
            assert!(!output.contains("99999999-8888"));
            assert!(!output.contains("hunter2"));
            assert!(output.contains("<?provider"));
        }
    }
    #[test]
    fn json_rejects_malformed_raw_xml_before_serializing_it() {
        let mut event = record("safe");
        event.raw_xml = r#"<Event Computer="DESKTOP-JOHN">"#.into();
        let error = export_records(&[event], ExportFormat::Json).expect_err("malformed XML rejected");
        assert!(error.contains("malformed") || error.contains("incomplete"));
    }

    #[test]
    fn every_serialized_field_and_raw_xml_uses_the_shared_redaction_projection() {
        let mut event = record(r#"RunAsUser=CONTOSO\John Doe PASSWORD=hunter2"#);
        event.computer = "DESKTOP-JOHN".into();
        event.event_data = vec![
            crate::event_log::models::EvtxField {
                name: "SerialNumber".into(),
                value: "ABC123456".into(),
            },
            crate::event_log::models::EvtxField {
                name: "TargetUserName".into(),
                value: "CONTOSO\\Jane Doe".into(),
            },
            crate::event_log::models::EvtxField {
                name: "SubjectUserName".into(),
                value: "CONTOSO\\Alice Doe".into(),
            },
            crate::event_log::models::EvtxField {
                name: "SubjectDomainName".into(),
                value: "CONTOSO".into(),
            },
        ];
        event.raw_xml = "<Event><Data>TenantId=99999999-8888-4777-8666-555555555555</Data><Message><![CDATA[PASSWORD=hunter2]]></Message><!-- SubjectUserName=CONTOSO\\Comment User --></Event>".into();
        event.mapped = vec![crate::event_log::maps::MappedColumn {
            property: "RemoteHost".into(),
            text: "REMOTE-HOST".into(),
            complete: true,
        }];

        let json = export_records(&[event.clone()], ExportFormat::Json).expect("JSON export");
        assert!(!json.contains("John Doe"));
        assert!(!json.contains("DESKTOP-JOHN"));
        assert!(!json.contains("Jane Doe"));
        assert!(!json.contains("Alice Doe"));
        assert!(!json.contains("\"value\":\"CONTOSO\""));
        assert!(!json.contains("hunter2"));
        assert!(!json.contains("ABC123456"));
        assert!(!json.contains("REMOTE-HOST"));
        assert!(!json.contains("Comment User"));
        let xml = export_records(&[event.clone()], ExportFormat::Xml).expect("XML export");
        assert!(!xml.contains("John Doe"));
        assert!(!xml.contains("Jane Doe"));
        assert!(!xml.contains("Alice Doe"));
        assert!(!xml.contains("\"value\":\"CONTOSO\""));
        assert!(!xml.contains("hunter2"));
        assert!(!xml.contains("REMOTE-HOST"));
        assert!(!xml.contains("Comment User"));
        assert!(!xml.contains("ABC123456"));
        assert!(!xml.contains("99999999-8888"));

        let raw = export_records(&[event], ExportFormat::RawXml).expect("raw XML export");
        assert!(!raw.contains("Comment User"));
        assert!(!raw.contains("hunter2"));
        assert!(!raw.contains("99999999-8888"));
        assert!(raw.contains("[tenant:") || raw.contains("[sensitive:"));
    }

    #[test]
    fn oversized_raw_xml_is_replaced_before_tag_processing() {
        let mut event = record("safe");
        event.raw_xml = format!("<Event>{}</Event>", "safe ".repeat(60_000));
        let output = export_records(&[event], ExportFormat::RawXml).expect("raw XML export");
        assert_eq!(output, "<Event><Redaction>[redacted: oversized text omitted]</Redaction></Event>\n");
        let mut reader = quick_xml::Reader::from_str(output.trim());
        while !matches!(reader.read_event().expect("valid marker"), quick_xml::events::Event::Eof) {}
    }
    #[test]
    fn oversized_normalized_content_is_explicitly_replaced() {
        let event = record(&"secret-user@example.com ".repeat(20_000));
        let output = export_records(&[event], ExportFormat::Json).expect("JSON export");
        assert!(output.contains("[redacted: oversized text omitted]"));
        assert!(!output.contains("secret-user@example.com"));
    }

    #[test]
    fn extensions_match_the_format() {
        assert_eq!(ExportFormat::Csv.extension(), "csv");
        assert_eq!(ExportFormat::Tsv.extension(), "tsv");
        assert_eq!(ExportFormat::Json.extension(), "json");
        assert_eq!(ExportFormat::Xml.extension(), "xml");
        assert_eq!(ExportFormat::Html.extension(), "html");
        assert_eq!(ExportFormat::RawXml.extension(), "xml");
    }
}
