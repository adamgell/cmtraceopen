//! Exporting event records to text formats.
//!
//! FullEventLogView offers nine export formats and we offered none, which made every analysis
//! dead-end in the app. This covers the three that carry the data losslessly enough to be worth
//! having: CSV for spreadsheets, JSON for tooling, and raw event XML for anything that wants the
//! provider's own representation.
//!
//! Formatting is deliberately separate from writing files, so the rules below are unit-testable
//! without touching the filesystem.

use cmtraceopen_parser::intune::apps::windows::common::redact_text;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::borrow::Borrow;
use std::collections::HashSet;
use std::sync::OnceLock;

use super::models::{canonical_event_record_id_text, EvtxRecord};
use super::writer::{MAX_RAW_XML_BYTES, OVERSIZED_RAW_XML_MARKER};

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

/// Maximum number of map-derived columns retained in one export schema.
///
/// This matches the existing 4,096-item source-manifest bound. A schema larger than this would
/// make header construction and per-row projection unnecessarily expensive, so discovery fails
/// explicitly rather than silently dropping columns.
pub const MAX_MAPPED_COLUMNS: usize = super::parser::MAX_SOURCE_MANIFEST_ENTRIES;
/// Maximum map-derived entries accepted on one record, including duplicate properties.
///
/// The schema budget deduplicates names, but the JSON and redacted projections still carry every
/// entry. Bound the per-record work separately so repeated properties cannot bypass the schema cap.
const MAX_MAPPED_ENTRIES_PER_RECORD: usize = MAX_MAPPED_COLUMNS;
/// Maximum total bytes retained by the unique map-derived export schema.
const MAX_MAPPED_SCHEMA_BYTES: usize = MAX_RAW_XML_BYTES;
const MAX_MAPPED_PROPERTY_BYTES: usize = MAX_RAW_XML_BYTES;

fn validate_mapped_property(property: &str) -> Result<(), String> {
    if property.len() > MAX_MAPPED_PROPERTY_BYTES {
        return Err(format!(
            "mapped-column property exceeds {MAX_MAPPED_PROPERTY_BYTES}-byte limit"
        ));
    }
    Ok(())
}

fn redact_mapped_property(property: &str) -> String {
    let redacted = redact_text(property);
    for (index, delimiter) in redacted.char_indices() {
        if delimiter != '=' && delimiter != ':' {
            continue;
        }
        let key = redacted[..index]
            .rsplit(['=', ':'])
            .next()
            .map(str::trim)
            .unwrap_or_default();
        if let Some(sensitive) = sensitive_xml_label(mapped_property_label(key)) {
            return format!(
                "{}[sensitive:{sensitive}]",
                &redacted[..index + delimiter.len_utf8()]
            );
        }
    }
    redacted
}
fn mapped_property_label(property: &str) -> &str {
    property
        .split(['=', ':'])
        .map(str::trim)
        .find_map(canonical_sensitive_label)
        .or_else(|| {
            property
                .char_indices()
                .find(|(_, delimiter)| *delimiter == '=' || *delimiter == ':')
                .map(|(index, _)| property[..index].trim())
                .filter(|label| !label.is_empty())
        })
        .unwrap_or(property)
}
fn redact_export_text(value: &str) -> String {
    let mut redacted = redact_text(value);
    let mut cursor = 0;
    while cursor < redacted.len() {
        let Some((relative_index, delimiter)) = redacted[cursor..]
            .char_indices()
            .find(|(_, character)| *character == '=' || *character == ':')
        else {
            break;
        };
        let index = cursor + relative_index;
        let key = redacted[..index]
            .rsplit(|character: char| {
                character.is_ascii_whitespace()
                    || matches!(character, '=' | ':' | ',' | ';' | '(' | '[' | '{')
            })
            .next()
            .unwrap_or_default()
            .trim();
        let Some(sensitive) = sensitive_xml_label(mapped_property_label(key)) else {
            cursor = index + delimiter.len_utf8();
            continue;
        };
        let value_start = index + delimiter.len_utf8();
        let Some(value_offset) = redacted[value_start..]
            .char_indices()
            .find(|(_, character)| !character.is_ascii_whitespace())
            .map(|(offset, _)| offset)
        else {
            break;
        };
        let value_start = value_start + value_offset;
        let value_end = redacted[value_start..]
            .char_indices()
            .find(|(_, character)| {
                character.is_ascii_whitespace() || matches!(character, ',' | ';' | ')' | ']' | '}')
            })
            .map(|(offset, _)| value_start + offset)
            .unwrap_or(redacted.len());
        let marker = format!("[sensitive:{sensitive}]");
        redacted.replace_range(value_start..value_end, &marker);
        cursor = value_start + marker.len();
    }
    redacted
}

/// Map-derived column names present across `records`, in first-seen order.
///
/// Appended after the fixed columns so a delimited export carries the same map values the grid
/// renders. Discovered from the records rather than declared, because which properties exist
/// depends on which maps matched. Returns an error rather than truncating when the explicit schema
/// budget is exceeded.
#[derive(Default)]
pub(crate) struct MappedColumnAccumulator {
    names: Vec<String>,
    seen: HashSet<String>,
    schema_bytes: usize,
}

impl MappedColumnAccumulator {
    pub(crate) fn observe(&mut self, record: &EvtxRecord) -> Result<(), String> {
        if record.mapped.len() > MAX_MAPPED_ENTRIES_PER_RECORD {
            return Err(format!(
                "mapped-column entries per record exceed {MAX_MAPPED_ENTRIES_PER_RECORD}"
            ));
        }
        for column in &record.mapped {
            validate_mapped_property(&column.property)?;
            let property = redact_mapped_property(&column.property);
            validate_mapped_property(&property)?;
            if self.seen.contains(&property) {
                continue;
            }
            if self.names.len() >= MAX_MAPPED_COLUMNS {
                return Err(format!(
                    "mapped-column budget of {MAX_MAPPED_COLUMNS} columns exceeded"
                ));
            }
            let next_schema_bytes = self.schema_bytes.saturating_add(property.len());
            if next_schema_bytes > MAX_MAPPED_SCHEMA_BYTES {
                return Err(format!(
                    "mapped-column schema exceeds {MAX_MAPPED_SCHEMA_BYTES}-byte budget"
                ));
            }
            self.schema_bytes = next_schema_bytes;
            self.seen.insert(property.clone());
            self.names.push(property);
        }
        Ok(())
    }

    pub(crate) fn into_columns(self) -> Vec<String> {
        self.names
    }
}

pub fn mapped_columns_iter<I, R>(records: I) -> Result<Vec<String>, String>
where
    I: IntoIterator<Item = R>,
    R: Borrow<EvtxRecord>,
{
    let mut accumulator = MappedColumnAccumulator::default();
    for item in records {
        accumulator.observe(item.borrow())?;
    }
    Ok(accumulator.into_columns())
}

pub fn mapped_columns(records: &[EvtxRecord]) -> Result<Vec<String>, String> {
    mapped_columns_iter(records.iter())
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
    // `xml-stylesheet` is a processing instruction, not an XML declaration.
    if !rest
        .as_bytes()
        .first()
        .is_some_and(|byte| byte.is_ascii_whitespace())
    {
        return xml;
    }
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
        canonical_event_record_id_text(record),
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
    // Construct the projection field-by-field rather than cloning `record` first. In particular,
    // `redact_raw_xml` must see the size cap before an unbounded provider payload is copied.
    EvtxRecord {
        id: record.id,
        event_record_id: record.event_record_id,
        event_record_id_text: Some(canonical_event_record_id_text(record)),
        timestamp: redact_export_text(&record.timestamp),
        timestamp_epoch: record.timestamp_epoch,
        provider: redact_export_text(&record.provider),
        channel: redact_export_text(&record.channel),
        event_id: record.event_id,
        level: record.level,
        computer: redact_labeled_value("ComputerName", &record.computer),
        message: redact_export_text(&record.message),
        event_data: record
            .event_data
            .iter()
            .map(|field| super::models::EvtxField {
                name: redact_mapped_property(&field.name),
                value: redact_labeled_value(mapped_property_label(&field.name), &field.value),
            })
            .collect(),
        raw_xml: redact_raw_xml(&record.raw_xml),
        source_label: redact_export_text(&record.source_label),
        origin_kind: record.origin_kind,
        task: record.task,
        opcode: record.opcode,
        process_id: record.process_id,
        activity_id: record
            .activity_id
            .as_deref()
            .map(|value| redact_labeled_value("ActivityID", value)),
        related_activity_id: record
            .related_activity_id
            .as_deref()
            .map(|value| redact_labeled_value("RelatedActivityID", value)),
        session_id: record
            .session_id
            .as_deref()
            .map(|value| redact_labeled_value("SessionID", value)),
        device_id: record
            .device_id
            .as_deref()
            .map(|value| redact_labeled_value("DeviceId", value)),
        user_id: record
            .user_id
            .as_deref()
            .map(|value| redact_labeled_value("UserId", value)),
        process_start_time: record
            .process_start_time
            .as_deref()
            .map(|value| redact_labeled_value("ProcessStartTime", value)),
        thread_id: record.thread_id,
        user_sid: record.user_sid.as_deref().map(redact_export_text),
        keywords: record.keywords.as_deref().map(redact_export_text),
        mapped: record
            .mapped
            .iter()
            .map(|column| {
                let property = redact_mapped_property(&column.property);
                let labeled =
                    redact_labeled_value(mapped_property_label(&column.property), &column.text);
                let text = if labeled == column.text {
                    redact_export_text(&column.text)
                } else {
                    labeled
                };
                super::maps::MappedColumn {
                    property,
                    text,
                    complete: column.complete,
                }
            })
            .collect(),
    }
}

fn redact_labeled_value(label: &str, value: &str) -> String {
    if let Some(sensitive) = sensitive_xml_label(label) {
        return format!("[sensitive:{sensitive}]");
    }
    let prefix = format!("{label}=");
    let redacted = redact_export_text(&format!("{prefix}{value}"));
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
    let decoded = quick_xml::escape::unescape(trimmed)
        .map(|value| value.into_owned())
        .unwrap_or_else(|_| trimmed.to_owned());
    let redacted = if let Some(sensitive) = sensitive_xml_label(label) {
        format!("[sensitive:{sensitive}]")
    } else if label.eq_ignore_ascii_case("XmlData") {
        "[sensitive:XmlData]".to_owned()
    } else {
        let assignment_redacted = redact_mapped_property(&decoded);
        if assignment_redacted != decoded {
            assignment_redacted
        } else {
            redact_labeled_value(label, &decoded)
        }
    };
    if redacted == decoded {
        return value.to_owned();
    }
    format!(
        "{}{}{}",
        &value[..start],
        quick_xml::escape::escape(redacted).into_owned(),
        &value[end..]
    )
}

fn redact_cdata_value(label: &str, value: &str) -> String {
    if let Some(sensitive) = sensitive_xml_label(label) {
        return redact_sensitive_xml_text(value, sensitive);
    }
    redact_labeled_value(label, value)
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

fn xml_name_attribute(tag: &str) -> Option<String> {
    static CELL: OnceLock<Regex> = OnceLock::new();
    let value = CELL
        .get_or_init(|| {
            Regex::new(r#"(?i)\bName\s*=\s*["']([^"']+)["']"#)
                .expect("XML Name attribute pattern must compile")
        })
        .captures(tag)
        .map(|captures| captures[1].to_owned())?;
    quick_xml::escape::unescape(&value)
        .map(|value| value.into_owned())
        .ok()
        .or(Some(value))
}

fn xml_local_name(name: &str) -> &str {
    name.rsplit(':').next().unwrap_or(name)
}

fn xml_tag_name(tag: &str) -> Option<String> {
    let inner = tag
        .strip_prefix("</")
        .or_else(|| tag.strip_prefix('<'))?
        .trim_start();
    let name = inner
        .split(|character: char| {
            character.is_ascii_whitespace() || character == '>' || character == '/'
        })
        .next()?;
    (!name.is_empty()).then(|| xml_local_name(name).to_owned())
}

const SENSITIVE_XML_LABELS: &[&str] = &[
    "Computer",
    "ComputerName",
    "DeviceName",
    "MachineName",
    "HostName",
    "SubjectUserName",
    "SubjectDomainName",
    "RemoteHost",
    "SerialNumber",
    "Serial",
    "DeviceId",
    "HardwareHash",
    "DeviceHardwareData",
    "TargetUserName",
    "UserName",
    "UserPrincipalName",
    "RunAsUser",
    "UserId",
    "Account",
    "AADTenantId",
    "TenantId",
    "Password",
    "Pwd",
    "Passphrase",
    "ApiKey",
    "ApiSecret",
    "AccessToken",
    "RefreshToken",
    "BearerToken",
    "Token",
    "Secret",
    "SecretKey",
    "PrivateKey",
    "LicenseKey",
    "ProductKey",
    "ClientSecret",
    "Credential",
    "Credentials",
    "CredentialData",
    "Authorization",
];

fn has_sensitive_xml_fragment(name: &str) -> bool {
    const FRAGMENTS: &[&str] = &[
        "credential",
        "key",
        "passphrase",
        "password",
        "secret",
        "token",
        "userprincipal",
        "username",
    ];
    let bytes = name.as_bytes();
    let mut part_start = 0;
    let mut index = 0;
    while index <= bytes.len() {
        let at_end = index == bytes.len();
        let separator = !at_end && matches!(bytes[index], b'_' | b'-' | b'.');
        let case_boundary = !at_end
            && index > part_start
            && bytes[index].is_ascii_uppercase()
            && (bytes[index - 1].is_ascii_lowercase()
                || (bytes[index - 1].is_ascii_uppercase()
                    && bytes
                        .get(index + 1)
                        .is_some_and(|byte| byte.is_ascii_lowercase())));
        if at_end || separator || case_boundary {
            if part_start < index
                && FRAGMENTS
                    .iter()
                    .any(|fragment| name[part_start..index].eq_ignore_ascii_case(fragment))
            {
                return true;
            }
            part_start = if separator { index + 1 } else { index };
        }
        index += 1;
    }
    false
}

fn canonical_sensitive_label(name: &str) -> Option<&'static str> {
    if name.eq_ignore_ascii_case("SensitiveXmlValue") {
        return Some("SensitiveXmlValue");
    }
    SENSITIVE_XML_LABELS
        .iter()
        .copied()
        .find_map(|label| {
            let matches = label.eq_ignore_ascii_case(name)
                || (name.len() > label.len()
                    && name
                        .get(name.len() - label.len()..)
                        .is_some_and(|suffix| suffix.eq_ignore_ascii_case(label)));
            matches.then_some(if label.eq_ignore_ascii_case("Computer") {
                "ComputerName"
            } else if label.eq_ignore_ascii_case("Pwd") {
                "Password"
            } else if label.eq_ignore_ascii_case("Serial") {
                "SerialNumber"
            } else {
                label
            })
        })
        .or_else(|| has_sensitive_xml_fragment(name).then_some("SensitiveXmlValue"))
}

fn sensitive_xml_label(name: &str) -> Option<&'static str> {
    if safe_xml_element(name) {
        None
    } else {
        canonical_sensitive_label(name)
    }
}

fn safe_xml_element(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "event"
            | "events"
            | "system"
            | "provider"
            | "eventid"
            | "version"
            | "level"
            | "task"
            | "opcode"
            | "keywords"
            | "timecreated"
            | "eventrecordid"
            | "channel"
            | "correlation"
            | "execution"
            | "security"
            | "eventdata"
            | "userdata"
            | "binaryeventdata"
            | "data"
            | "message"
            | "renderinginfo"
            | "param"
    )
}

fn xml_element_redaction_label(name: &str, inherited_label: Option<&str>) -> Option<String> {
    if safe_xml_element(name) {
        return None;
    }
    sensitive_xml_label(name)
        .map(str::to_owned)
        .or_else(|| inherited_label.is_none().then(|| "XmlData".to_owned()))
}

fn redact_xml_tag(tag: &str, inherited_label: Option<&str>) -> String {
    let mut output = String::with_capacity(tag.len());
    let mut cursor = 0;
    let context_label = xml_name_attribute(tag).map(|label| {
        sensitive_xml_label(&label)
            .map(str::to_owned)
            .unwrap_or_else(|| {
                if label.eq_ignore_ascii_case("Computer") {
                    "ComputerName".to_owned()
                } else {
                    label
                }
            })
    });
    let own_label =
        xml_tag_name(tag).and_then(|name| xml_element_redaction_label(&name, inherited_label));
    let context_sensitive_label = context_label.as_deref().and_then(sensitive_xml_label);
    let mut pending_label: Option<String> = None;
    while cursor < tag.len() {
        let Some(relative) = tag[cursor..].find(['"', '\'']) else {
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
            .and_then(|equals| before[..equals].split_whitespace().last())
            .unwrap_or("")
            .trim_start_matches(['<', '/']);
        let attr_local_name = xml_local_name(attr_name);
        let value = &tag[opening + 1..end];
        let decoded_name = if attr_local_name.eq_ignore_ascii_case("name") {
            quick_xml::escape::unescape(value)
                .map(|value| value.into_owned())
                .unwrap_or_else(|_| value.to_owned())
        } else {
            String::new()
        };
        let pending_label_for_value = pending_label.clone();
        let label = if attr_local_name.eq_ignore_ascii_case("value") {
            context_sensitive_label
                .or(own_label
                    .as_deref()
                    .filter(|label| !label.eq_ignore_ascii_case("XmlData")))
                .or(inherited_label)
                .or(pending_label_for_value.as_deref())
                .or(context_label.as_deref())
                .or(own_label.as_deref())
                .unwrap_or(attr_local_name)
        } else if attr_local_name.eq_ignore_ascii_case("name") {
            own_label
                .as_deref()
                .filter(|label| !label.eq_ignore_ascii_case("XmlData"))
                .or(inherited_label)
                .unwrap_or("Name")
        } else if attr_local_name.eq_ignore_ascii_case("computer") {
            "ComputerName"
        } else {
            sensitive_xml_label(attr_local_name)
                .or(own_label.as_deref())
                .or(inherited_label)
                .unwrap_or(attr_local_name)
        };
        if attr_local_name.eq_ignore_ascii_case("name") {
            pending_label = Some(decoded_name);
            output.push_str(&redact_xml_value(label, value));
        } else if attr_name.eq_ignore_ascii_case("xmlns")
            || attr_name.to_ascii_lowercase().starts_with("xmlns:")
        {
            // Namespace declarations are structural, but their values are still untrusted text.
            // Preserve ordinary URIs while masking credential-like assignments embedded in one.
            output.push_str(&redact_xml_value(attr_name, value));
        } else {
            output.push_str(&redact_xml_value(label, value));
            if attr_local_name.eq_ignore_ascii_case("value") {
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
        let redacted = redact_export_text(&decoded);
        if redacted != decoded {
            return quick_xml::escape::escape(redacted).into_owned();
        }
    }
    redact_export_text(text)
}

fn redact_sensitive_xml_text(text: &str, label: &str) -> String {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return text.to_owned();
    }
    let start = text.find(trimmed).expect("trimmed value is present");
    let end = start + trimmed.len();
    // Every text node below a sensitive ancestor is sensitive as a whole. The shared free-text
    // redactor intentionally preserves safe suffixes after a credential token, which would leak
    // part of a nested XML value here. Use the explicit subtree marker instead.
    let redacted = format!("[sensitive:{label}]");
    format!("{}{}{}", &text[..start], redacted, &text[end..])
}

fn redact_xml_processing_instruction(content: &str, inherited_label: Option<&str>) -> String {
    let target_end = content
        .find(|character: char| character.is_ascii_whitespace())
        .unwrap_or(content.len());
    let target = &content[..target_end];
    let target = target.rsplit(':').next().unwrap_or(target);
    let label = sensitive_xml_label(target).or(inherited_label);
    let Some(label) = label else {
        return redact_xml_text(content);
    };
    let data = &content[target_end..];
    if data.trim().is_empty() {
        return content.to_owned();
    }
    format!(
        "{}{}",
        &content[..target_end],
        redact_sensitive_xml_text(data, label)
    )
}

fn redact_raw_xml(xml: &str) -> String {
    if xml.len() > MAX_RAW_XML_BYTES {
        return OVERSIZED_RAW_XML_MARKER.to_owned();
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
    let labeled =
        cdata_event_data_pattern().replace_all(&labeled, |captures: &regex::Captures<'_>| {
            format!(
                "{}{}<![CDATA[{}]]>{}{}",
                &captures["open"],
                &captures["leading"],
                redact_cdata_value(&captures["label"], &captures["value"]),
                &captures["trailing"],
                &captures["close"],
            )
        });
    let source = labeled.as_ref();
    let mut output = String::with_capacity(source.len());
    let mut stack: Vec<(String, Option<String>)> = Vec::new();
    let mut cursor = 0;
    while cursor < source.len() {
        let Some(relative_open) = source[cursor..].find('<') else {
            let text = &source[cursor..];
            if let Some((_, Some(label))) = stack.iter().rev().find(|(_, label)| label.is_some()) {
                output.push_str(&redact_sensitive_xml_text(text, label));
            } else {
                output.push_str(&redact_xml_text(text));
            }
            break;
        };
        let opening = cursor + relative_open;
        let text = &source[cursor..opening];
        if let Some((_, Some(label))) = stack.iter().rev().find(|(_, label)| label.is_some()) {
            output.push_str(&redact_sensitive_xml_text(text, label));
        } else {
            output.push_str(&redact_xml_text(text));
        }
        let tail = &source[opening..];
        if let Some(content) = tail.strip_prefix("<?") {
            if let Some(end) = content.find("?>") {
                output.push_str("<?");
                let inherited = stack.iter().rev().find_map(|(_, label)| label.as_deref());
                output.push_str(&redact_xml_processing_instruction(
                    &content[..end],
                    inherited,
                ));
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
                if let Some((_, Some(label))) =
                    stack.iter().rev().find(|(_, label)| label.is_some())
                {
                    output.push_str(&redact_sensitive_xml_text(&content[..end], label));
                } else {
                    output.push_str(&redact_xml_text(&content[..end]));
                }
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
                let text = &content[..end];
                if let Some((_, Some(label))) =
                    stack.iter().rev().find(|(_, label)| label.is_some())
                {
                    output.push_str(&redact_sensitive_xml_text(text, label));
                } else {
                    output.push_str(&redact_export_text(text));
                }
                output.push_str("]]>");
                cursor = opening + 9 + end + 3;
                continue;
            }
            output.push_str("<![CDATA[");
            output.push_str(&redact_export_text(content));
            break;
        }
        let mut end = opening + 1;
        let mut quote = None;
        while end < source.len() {
            let byte = source.as_bytes()[end];
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
        let tag = &source[opening..end];
        let closing = tag.starts_with("</");
        let self_closing = tag.trim_end().ends_with("/>");
        let inherited = stack.iter().rev().find_map(|(_, label)| label.as_deref());
        output.push_str(&redact_xml_tag(tag, inherited));
        if closing {
            stack.pop();
        } else if !self_closing {
            let name = xml_tag_name(tag).unwrap_or_default();
            let own_label = xml_element_redaction_label(&name, inherited).or_else(|| {
                xml_name_attribute(tag)
                    .and_then(|label| sensitive_xml_label(&label).map(str::to_owned))
            });
            stack.push((name, own_label));
        }
        cursor = end;
    }
    if output.len() > MAX_RAW_XML_BYTES {
        OVERSIZED_RAW_XML_MARKER.to_owned()
    } else {
        output
    }
}

/// Renders records in `format`.
pub fn export_records(records: &[EvtxRecord], format: ExportFormat) -> Result<String, String> {
    super::writer::validate_raw_xml(records, format).map_err(|error| error.to_string())?;
    let mapped = mapped_columns(records)?;
    let mut output = Vec::new();
    super::writer::write_record_stream_unchecked(&mut output, format, records.iter(), &mapped)
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
            origin_kind: crate::event_log::models::EvtxOriginKind::Event,
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
    fn mapped_columns_preserve_first_seen_order_and_deduplicate() {
        let mut first = record("first");
        first.mapped = vec![
            crate::event_log::maps::MappedColumn {
                property: "Second".into(),
                text: "2".into(),
                complete: true,
            },
            crate::event_log::maps::MappedColumn {
                property: "First".into(),
                text: "1".into(),
                complete: true,
            },
        ];
        let mut second = record("second");
        second.mapped = vec![
            crate::event_log::maps::MappedColumn {
                property: "First".into(),
                text: "1b".into(),
                complete: true,
            },
            crate::event_log::maps::MappedColumn {
                property: "Third".into(),
                text: "3".into(),
                complete: true,
            },
        ];

        let columns = mapped_columns_iter([first, second]).expect("mapped columns");
        assert_eq!(
            columns,
            vec!["Second".to_owned(), "First".to_owned(), "Third".to_owned()]
        );
    }

    #[test]
    fn mapped_columns_reject_a_union_over_the_explicit_budget() {
        let records = (0..=MAX_MAPPED_COLUMNS)
            .map(|index| {
                let mut event = record("mapped");
                event.mapped = vec![crate::event_log::maps::MappedColumn {
                    property: format!("mapped-{index}"),
                    text: "value".into(),
                    complete: true,
                }];
                event
            })
            .collect::<Vec<_>>();

        let error = mapped_columns_iter(records).expect_err("column budget must be enforced");
        assert!(
            error.contains("mapped-column") && error.contains("budget"),
            "{error}"
        );
    }
    #[test]
    fn mapped_columns_reject_duplicate_entries_on_one_record() {
        let mut event = record("mapped");
        event.mapped = (0..=MAX_MAPPED_ENTRIES_PER_RECORD)
            .map(|_| crate::event_log::maps::MappedColumn {
                property: "Duplicate".into(),
                text: "value".into(),
                complete: true,
            })
            .collect();

        let error = mapped_columns_iter([event]).expect_err("duplicate entry budget");
        assert!(error.contains("entries per record"), "{error}");
    }

    #[test]
    fn mapped_columns_reject_aggregate_schema_bytes() {
        let property_size = MAX_MAPPED_SCHEMA_BYTES / 2 + 1;
        let mut first = record("mapped");
        first.mapped = vec![crate::event_log::maps::MappedColumn {
            property: "a".repeat(property_size),
            text: "value".into(),
            complete: true,
        }];
        let mut second = record("mapped");
        second.mapped = vec![crate::event_log::maps::MappedColumn {
            property: format!("b{}", "b".repeat(property_size - 1)),
            text: "value".into(),
            complete: true,
        }];

        let error = mapped_columns_iter([first, second]).expect_err("schema byte budget");
        assert!(
            error.contains("schema") && error.contains("budget"),
            "{error}"
        );
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
    fn sensitive_event_data_labels_and_flat_fields_are_redacted_in_all_exports() {
        let mut event = record("FooPassword:hunter2 FooPwd:pwdsecret FooSerial:serialsecret");
        event.computer = "DESKTOP-JOHN".into();
        event.event_data = vec![
            crate::event_log::models::EvtxField {
                name: "Password=hunter2".into(),
                value: "ordinary value".into(),
            },
            crate::event_log::models::EvtxField {
                name: "OrdinaryLabel".into(),
                value: "ordinary value".into(),
            },
            crate::event_log::models::EvtxField {
                name: "FooPassword".into(),
                value: "hunter2".into(),
            },
            crate::event_log::models::EvtxField {
                name: "FooPwd".into(),
                value: "pwdsecret".into(),
            },
            crate::event_log::models::EvtxField {
                name: "FooSerial".into(),
                value: "serialsecret".into(),
            },
        ];
        event.raw_xml =
            r#"<Event xmlns:foo="FooPassword=hunter2"><Message>FooPassword:hunter2</Message><Data Name="Password=hunter2">ordinary value</Data><Data Name="FooPassword">hunter2</Data><Data Name="FooPwd">pwdsecret</Data><Data Name="FooSerial">serialsecret</Data><Data Name="OrdinaryLabel">ordinary value</Data></Event>"#.into();

        for format in [
            ExportFormat::Json,
            ExportFormat::Xml,
            ExportFormat::RawXml,
            ExportFormat::Csv,
            ExportFormat::Tsv,
        ] {
            let output = export_records(&[event.clone()], format).expect("export");
            assert!(!output.contains("pwdsecret"), "{format:?}: {output}");
            assert!(!output.contains("serialsecret"), "{format:?}: {output}");
            assert!(!output.contains("Password=hunter2"), "{format:?}: {output}");
            assert!(!output.contains("hunter2"), "{format:?}: {output}");
            assert!(!output.contains("DESKTOP-JOHN"), "{format:?}: {output}");
            if !matches!(format, ExportFormat::Csv | ExportFormat::Tsv) {
                assert!(output.contains("OrdinaryLabel"), "{format:?}: {output}");
            }
        }

        let raw = export_records(&[event], ExportFormat::RawXml).expect("raw XML export");
        let mut reader = quick_xml::Reader::from_str(raw.trim());
        while !matches!(
            reader
                .read_event()
                .expect("label redaction keeps XML well-formed"),
            quick_xml::events::Event::Eof
        ) {}
    }
    #[test]
    fn compound_pwd_and_serial_aliases_redact_mapped_json_and_xml_data() {
        let mut event = record("safe");
        event.event_data = vec![
            crate::event_log::models::EvtxField {
                name: "FooPwd".into(),
                value: "event-pwd-secret".into(),
            },
            crate::event_log::models::EvtxField {
                name: "FooSerial".into(),
                value: "event-serial-secret".into(),
            },
            crate::event_log::models::EvtxField {
                name: "SerialPort".into(),
                value: "ordinary serial value".into(),
            },
        ];
        event.mapped = vec![
            crate::event_log::maps::MappedColumn {
                property: "FooPwd".into(),
                text: "mapped-pwd-secret".into(),
                complete: true,
            },
            crate::event_log::maps::MappedColumn {
                property: "FooSerial".into(),
                text: "mapped-serial-secret".into(),
                complete: true,
            },
            crate::event_log::maps::MappedColumn {
                property: "SerialPort".into(),
                text: "ordinary serial value".into(),
                complete: true,
            },
        ];
        event.raw_xml = r#"<Event><Data Name="FooPwd">xml-data-pwd-secret</Data><Data Name="FooSerial">xml-data-serial-secret</Data><FooPwd>xml-element-pwd-secret</FooPwd><FooSerial>xml-element-serial-secret</FooSerial><SerialPort>ordinary serial value</SerialPort></Event>"#.into();

        assert_eq!(sensitive_xml_label("fOoPwD"), Some("Password"));
        assert_eq!(sensitive_xml_label("fOoSeRiAl"), Some("SerialNumber"));
        assert_eq!(sensitive_xml_label("SerialPort"), None);

        for format in [
            ExportFormat::Json,
            ExportFormat::Xml,
            ExportFormat::RawXml,
            ExportFormat::Html,
            ExportFormat::Csv,
            ExportFormat::Tsv,
        ] {
            let output = export_records(&[event.clone()], format).expect("export");
            for secret in [
                "event-pwd-secret",
                "event-serial-secret",
                "mapped-pwd-secret",
                "mapped-serial-secret",
                "xml-data-pwd-secret",
                "xml-data-serial-secret",
                "xml-element-pwd-secret",
                "xml-element-serial-secret",
            ] {
                assert!(!output.contains(secret), "{format:?}: {output}");
            }
            assert!(
                output.contains("[sensitive:Password]"),
                "{format:?}: {output}"
            );
            assert!(
                output.contains("[sensitive:SerialNumber]"),
                "{format:?}: {output}"
            );
            if !matches!(format, ExportFormat::Xml | ExportFormat::RawXml) {
                assert!(
                    output.contains("ordinary serial value"),
                    "{format:?}: non-sensitive label changed: {output}"
                );
            }
            if matches!(
                format,
                ExportFormat::Json | ExportFormat::Html | ExportFormat::Csv | ExportFormat::Tsv
            ) {
                assert!(output.contains("FooPwd"), "{format:?}: {output}");
                assert!(output.contains("FooSerial"), "{format:?}: {output}");
            }
        }
    }

    #[test]
    fn generic_key_fragment_does_not_redact_keyboard_layout() {
        assert_eq!(sensitive_xml_label("KeyboardLayout"), None);
        assert_eq!(
            canonical_sensitive_label("EncryptionKey"),
            Some("SensitiveXmlValue")
        );
        assert_eq!(sensitive_xml_label("AuthenticationPackageName"), None);
        assert_eq!(sensitive_xml_label("AccountStatus"), None);
        assert_eq!(
            canonical_sensitive_label("MyTokenBlob"),
            Some("SensitiveXmlValue")
        );
        assert_eq!(canonical_sensitive_label("Monkey"), None);
        assert_eq!(
            canonical_sensitive_label("My_Key_Blob"),
            Some("SensitiveXmlValue")
        );
        assert_eq!(
            sensitive_xml_label("SensitiveXmlValue"),
            Some("SensitiveXmlValue")
        );
        assert_eq!(
            redact_xml_value("MyTokenBlob", "secret"),
            "[sensitive:SensitiveXmlValue]"
        );
        assert_eq!(canonical_sensitive_label("éFoo"), None);

        let mut event = record("safe");
        event.event_data = vec![crate::event_log::models::EvtxField {
            name: "KeyboardLayout".into(),
            value: "us".into(),
        }];
        event.raw_xml = "<Event><Message>us</Message></Event>".into();

        let output = export_records(&[event], ExportFormat::Json).expect("export");
        assert!(output.contains("\"value\":\"us\""));
    }

    #[test]
    fn mapped_column_properties_are_redacted_and_oversized_schema_is_rejected() {
        let mut sensitive = record("mapped");
        sensitive.mapped = vec![crate::event_log::maps::MappedColumn {
            property: "Password=hunter2".into(),
            text: "hunter2".into(),
            complete: true,
        }];
        sensitive.mapped.push(crate::event_log::maps::MappedColumn {
            property: "Foo=FooPassword=hunter2".into(),
            text: "hunter2".into(),
            complete: true,
        });
        sensitive.mapped.push(crate::event_log::maps::MappedColumn {
            property: "FooPassword:hunter2".into(),
            text: "hunter2".into(),
            complete: true,
        });
        sensitive.mapped.push(crate::event_log::maps::MappedColumn {
            property: "FooPwd:pwdsecret".into(),
            text: "pwdsecret".into(),
            complete: true,
        });
        sensitive.mapped.push(crate::event_log::maps::MappedColumn {
            property: "FooSerial:serialsecret".into(),
            text: "serialsecret".into(),
            complete: true,
        });

        for format in [
            ExportFormat::Json,
            ExportFormat::Xml,
            ExportFormat::RawXml,
            ExportFormat::Html,
            ExportFormat::Csv,
            ExportFormat::Tsv,
        ] {
            let output = export_records(&[sensitive.clone()], format).expect("export");
            assert!(!output.contains("Password=hunter2"), "{format:?}: {output}");
            assert!(!output.contains("hunter2"), "{format:?}: {output}");
            assert!(!output.contains("pwdsecret"), "{format:?}: {output}");
            assert!(!output.contains("serialsecret"), "{format:?}: {output}");
        }

        let mut oversized = record("mapped");
        oversized.mapped = vec![crate::event_log::maps::MappedColumn {
            property: "x".repeat(MAX_MAPPED_PROPERTY_BYTES + 1),
            text: "ordinary value".into(),
            complete: true,
        }];
        for format in [
            ExportFormat::Json,
            ExportFormat::Xml,
            ExportFormat::RawXml,
            ExportFormat::Html,
            ExportFormat::Csv,
            ExportFormat::Tsv,
        ] {
            let error = export_records(&[oversized.clone()], format).expect_err("oversized schema");
            assert!(
                error.contains("mapped-column property"),
                "{format:?}: unexpected error: {error}"
            );
        }
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
        event.raw_xml = r#"<Event Computer="DESKTOP-JOHN"><SerialNumber>ABC123456</SerialNumber><TargetUserName>CONTOSO\Jane Doe</TargetUserName><TenantId>99999999-8888-4777-8666-555555555555</TenantId><Password>hunter2</Password><Password value="attribute-secret" Name="name-secret" /><Secret Name="ordinary" Value="element-secret" /><ns:Password ns:value="namespace-secret" ns:Name="namespace-name-secret" /><Data Value="REMOTE-HOST" Name="RemoteHost" /><Data Name="Computer" Value="DESKTOP-JOHN" /><Encoded>PASSWORD&#x3D;encoded-secret</Encoded><Message><?provider PASSWORD=hunter2?></Message></Event>"#.into();
        for format in [ExportFormat::Json, ExportFormat::Xml, ExportFormat::RawXml] {
            let output = export_records(&[event.clone()], format).expect("export");
            assert!(!output.contains("DESKTOP-JOHN"));
            assert!(!output.contains("REMOTE-HOST"));
            assert!(!output.contains("ABC123456"));
            assert!(!output.contains("Jane Doe"));
            assert!(!output.contains("99999999-8888"));
            assert!(!output.contains("hunter2"));
            assert!(!output.contains("attribute-secret"));
            assert!(!output.contains("name-secret"));
            assert!(!output.contains("element-secret"));
            assert!(!output.contains("namespace-secret"));
            assert!(!output.contains("namespace-name-secret"));
            assert!(output.contains("<?provider"));
        }
    }

    #[test]
    fn safe_keywords_xml_element_is_not_redacted_by_sensitive_fallback() {
        let mut event = record("safe");
        event.raw_xml = "<Event><Keywords>0x8020000000000000</Keywords></Event>".into();

        let output = export_records(&[event], ExportFormat::RawXml).expect("raw XML export");

        assert!(output.contains("<Keywords>0x8020000000000000</Keywords>"));
    }
    #[test]
    fn unknown_provider_xml_fields_are_redacted_by_default() {
        let mut event = record("safe");
        event.raw_xml = r#"<Event><Passphrase>passphrase-secret</Passphrase><ns:ProviderPassword>provider-secret</ns:ProviderPassword><Foo>unlabeled-secret</Foo><Message>safe message</Message></Event>"#.into();

        let output = export_records(&[event], ExportFormat::RawXml).expect("raw XML export");

        assert!(!output.contains("passphrase-secret"));
        assert!(!output.contains("provider-secret"));
        assert!(!output.contains("unlabeled-secret"));
        assert!(output.contains("safe message"));
    }
    #[test]
    fn unknown_xml_value_uses_sensitive_name_context() {
        let mut event = record("safe");
        event.raw_xml =
            r#"<Event><Foo Name="Password" Value="secret" /><Foo Name="Ordinary" Value="safe" /></Event>"#
                .into();

        let output = export_records(&[event], ExportFormat::RawXml).expect("raw XML export");

        assert!(!output.contains("secret"), "{output}");
        assert!(
            output.contains(r#"Value="[sensitive:Password]""#),
            "{output}"
        );
        assert!(output.contains(r#"Value="safe""#), "{output}");
    }
    #[test]
    fn sensitive_labeled_values_redact_the_complete_value() {
        let mut event = record("safe");
        event.computer = "HOST-UNIQUE-SENSITIVE-SUFFIX".into();
        event.event_data = vec![crate::event_log::models::EvtxField {
            name: "Password".into(),
            value: "secret prefix UNIQUE-SENSITIVE-SUFFIX".into(),
        }];
        event.mapped = vec![crate::event_log::maps::MappedColumn {
            property: "RunAsUser".into(),
            text: "CONTOSO\\Alice UNIQUE-SENSITIVE-SUFFIX".into(),
            complete: true,
        }];

        for format in [
            ExportFormat::Json,
            ExportFormat::Xml,
            ExportFormat::RawXml,
            ExportFormat::Csv,
            ExportFormat::Tsv,
        ] {
            let output = export_records(&[event.clone()], format).expect("export");
            assert!(
                !output.contains("UNIQUE-SENSITIVE-SUFFIX"),
                "{format:?}: {output}"
            );
        }
    }

    #[test]
    fn unknown_xml_attributes_are_redacted_by_default() {
        let mut event = record("safe");
        event.raw_xml = r#"<Event><Foo Value="UNKNOWN-ATTRIBUTE-SECRET" /></Event>"#.into();

        for format in [ExportFormat::Json, ExportFormat::Xml, ExportFormat::RawXml] {
            let output = export_records(&[event.clone()], format).expect("export");
            assert!(
                !output.contains("UNKNOWN-ATTRIBUTE-SECRET"),
                "{format:?}: {output}"
            );
        }
    }

    #[test]
    fn sensitive_processing_instruction_targets_redact_their_data() {
        let mut event = record("safe");
        event.raw_xml = r#"<Event><?Password hunter2?></Event>"#.into();

        for format in [ExportFormat::Json, ExportFormat::Xml, ExportFormat::RawXml] {
            let output = export_records(&[event.clone()], format).expect("export");
            assert!(!output.contains("hunter2"), "{format:?}: {output}");
            assert!(output.contains("<?Password"), "{format:?}: {output}");
            assert!(
                output.contains("[sensitive:Password]"),
                "{format:?}: {output}"
            );
        }
    }

    #[test]
    fn redacted_xml_text_reescapes_surviving_entities() {
        let mut event = record("safe");
        event.raw_xml = r#"<Event><Message>hello &amp; PASSWORD=hunter2</Message></Event>"#.into();

        let output = export_records(&[event], ExportFormat::RawXml).expect("raw XML export");
        assert!(output.contains("hello &amp;"));
        assert!(!output.contains("hunter2"));

        let mut reader = quick_xml::Reader::from_str(output.trim());
        while !matches!(
            reader
                .read_event()
                .expect("redacted XML remains well-formed"),
            quick_xml::events::Event::Eof
        ) {}
    }
    #[test]
    fn json_rejects_malformed_raw_xml_before_serializing_it() {
        let mut event = record("safe");
        event.raw_xml = r#"<Event Computer="DESKTOP-JOHN">"#.into();
        let error = export_records(&[event], ExportFormat::Json).expect_err("malformed XML");
        assert!(
            error.contains("incomplete") || error.contains("malformed"),
            "unexpected error: {error}"
        );
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
        assert_eq!(
            output,
            "<Event><Redaction>[redacted: oversized text omitted]</Redaction></Event>\n"
        );
        let mut reader = quick_xml::Reader::from_str(output.trim());
        while !matches!(
            reader.read_event().expect("valid marker"),
            quick_xml::events::Event::Eof
        ) {}
    }

    #[test]
    fn oversized_normalized_content_is_explicitly_replaced() {
        let event = record(&"secret-user@example.com ".repeat(20_000));
        let output = export_records(&[event], ExportFormat::Json).expect("JSON export");
        assert!(output.contains("[redacted: oversized text omitted]"));
        assert!(!output.contains("secret-user@example.com"));
    }
    #[test]
    fn oversized_raw_xml_is_omitted_from_every_xml_bearing_export() {
        let mut event = record("safe");
        event.raw_xml = format!("<Event><Message>{}</Message></Event>", "x".repeat(300_000));

        for format in [ExportFormat::Json, ExportFormat::Xml, ExportFormat::RawXml] {
            let output = export_records(&[event.clone()], format).expect("export");
            assert!(
                output.len() < 1_024,
                "oversized raw XML must be replaced by a bounded marker: {format:?}"
            );
            assert!(output.contains("[redacted: oversized text omitted]"));
            assert!(!output.contains(&"x".repeat(1_000)));
        }
    }

    #[test]
    fn nested_sensitive_descendants_and_credential_data_are_redacted() {
        let mut event = record("safe");
        event.raw_xml = r#"<Event><CredentialData><Secret>nested-secret</Secret><Value>nested-value</Value></CredentialData><CredentialData>flat-secret</CredentialData></Event>"#.into();

        let output = export_records(&[event], ExportFormat::RawXml).expect("raw XML export");

        assert!(!output.contains("nested-secret"));
        assert!(!output.contains("nested-value"));
        assert!(!output.contains("flat-secret"));
        assert!(output.contains("[secret:") || output.contains("[sensitive:"));
    }

    #[test]
    fn nested_sensitive_context_uses_nearest_label_for_all_node_text() {
        let mut event = record("safe");
        event.raw_xml = r#"<Event><CredentialData><Password>prefix<?provider secret?><!-- comment secret --><![CDATA[cdata-secret]]><Value/>suffix</Password></CredentialData></Event>"#.into();

        let output = export_records(&[event], ExportFormat::RawXml).expect("raw XML export");

        assert!(!output.contains("prefix"));
        assert!(!output.contains(" secret?"));
        assert!(!output.contains("comment secret"));
        assert!(!output.contains("cdata-secret"));
        assert!(!output.contains("suffix"));
        assert!(output.matches("[sensitive:Password]").count() >= 5);
    }

    #[test]
    fn entity_encoded_and_newline_separated_data_attributes_are_redacted() {
        let mut event = record("safe");
        event.raw_xml = r#"<Event><Data
            Name="Credential&#x44;ata"
            Value="credential-secret"
        /></Event>"#
            .into();

        let output = export_records(&[event], ExportFormat::RawXml).expect("raw XML export");

        assert!(!output.contains("credential-secret"));
        assert!(output.contains("Name=\"Credential&#x44;ata\""));
    }

    #[test]
    fn named_sensitive_data_masks_nested_text_and_xml_nodes() {
        let mut event = record("safe");
        event.raw_xml = r#"<Event><Data Name="Password"><Value>password-prefix PASSWORD=hunter2 suffix</Value><![CDATA[cdata-prefix PASSWORD=secret suffix]]><!-- comment-prefix PASSWORD=comment-secret suffix --><?provider PASSWORD=pi-secret suffix?></Data></Event>"#.into();

        let output = export_records(&[event], ExportFormat::RawXml).expect("raw XML export");

        assert!(!output.contains("hunter2"));
        assert!(!output.contains("comment-secret"));
        assert!(!output.contains("pi-secret"));
        assert!(!output.contains("password-prefix"));
        assert!(output.matches("[sensitive:Password]").count() >= 4);
    }

    #[test]
    fn invalid_event_record_id_text_falls_back_to_the_trusted_numeric_id() {
        for invalid in [
            "PASSWORD=hunter2",
            r#"<script>alert(1)</script>"#,
            "42x",
            "42&amp;",
            "18446744073709551616",
        ] {
            let mut event = record("safe");
            event.event_record_id_text = Some(invalid.into());

            let output = export_records(&[event], ExportFormat::Json).expect("JSON export");
            let value: serde_json::Value = serde_json::from_str(&output).expect("valid JSON");

            assert_eq!(value[0]["eventRecordId"], 42);
            assert_eq!(value[0]["eventRecordIdText"], "42");
            assert!(!output.contains(invalid));
        }
    }

    #[test]
    fn conflicting_safe_event_record_id_text_falls_back_to_numeric_identity() {
        let mut event = record("safe");
        event.event_record_id_text = Some("43".into());

        let output = export_records(&[event], ExportFormat::Json).expect("JSON export");
        let value: serde_json::Value = serde_json::from_str(&output).expect("valid JSON");

        assert_eq!(value[0]["eventRecordId"], 42);
        assert_eq!(value[0]["eventRecordIdText"], "42");
    }

    #[test]
    fn exact_decimal_event_record_id_text_is_preserved_for_lossless_ids() {
        let mut event = record("safe");
        event.event_record_id = 9_007_199_254_740_992;
        event.event_record_id_text = Some("9007199254740993".into());

        let output = export_records(&[event], ExportFormat::Json).expect("JSON export");
        let value: serde_json::Value = serde_json::from_str(&output).expect("valid JSON");

        assert_eq!(value[0]["eventRecordId"], 9_007_199_254_740_992u64);
        assert_eq!(value[0]["eventRecordIdText"], "9007199254740993");
    }

    #[test]
    fn leading_whitespace_before_an_utf8_xml_declaration_is_accepted() {
        let mut event = record("safe");
        event.raw_xml = " \n\t<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Event />".into();

        let output = export_records(&[event], ExportFormat::RawXml).expect("raw XML export");

        assert!(output.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
        assert!(output.contains("<Event />"));
    }

    #[test]
    fn processing_instructions_survive_redaction_unchanged() {
        let mut event = record("safe");
        event.raw_xml =
            r#"<Event><?trace source="unit"?><?provider PASSWORD=hunter2?></Event>"#.into();

        let output = export_records(&[event], ExportFormat::RawXml).expect("raw XML export");

        assert!(output.contains(r#"<?trace source="unit"?>"#));
        assert!(output.contains("<?provider"));
        assert!(!output.contains("hunter2"));
    }

    #[test]
    fn canonical_decimal_event_record_id_text_is_used_when_missing() {
        let output = export_records(&[record("safe")], ExportFormat::Json).expect("JSON export");
        let value: serde_json::Value = serde_json::from_str(&output).expect("valid JSON");

        assert_eq!(value[0]["eventRecordIdText"], "42");
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
