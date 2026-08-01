//! Record grammar and logical framing for direct macOS Company Portal app logs.
//!
//! # The grammar
//!
//! A record begins with a header line:
//!
//! ```text
//! 2026-03-12 09:14:22:301 | CompanyPortal | I | 8412 | SSOExtension | message text
//! ```
//!
//! Reading left to right: an ISO-style local date and time with a fractional
//! second and an optional UTC offset, then pipe-delimited `process`, `severity`,
//! `thread`, and `subsystem` fields, then the message.
//!
//! Advanced logging inserts labeled attribute fields between the subsystem and
//! the message:
//!
//! ```text
//! 2026-03-12 09:14:22:301-0700 | CompanyPortal | E | 8412 | Network | category=Http | activity=0x1a2b3c | message text
//! ```
//!
//! Attributes are labeled rather than positional on purpose. A message routinely
//! contains `|`, so a positional seventh field would be ambiguous with a message
//! that happens to contain two pipes. Matching a *closed* set of attribute keys
//! (`ATTRIBUTE_KEYS`) against `key=value` with no interior whitespace removes the
//! ambiguity: a message fragment would have to be exactly one of those keys
//! followed by `=` and a whitespace-free value to be misread.
//!
//! # Framing
//!
//! Any line that is not a header continues the record above it. Exception traces
//! and JSON payloads therefore stay attached to the record that emitted them,
//! and the joined text is preserved byte-for-byte in
//! [`crate::intune::portal::macos::company_portal::logs::CompanyPortalLogRecord::raw`].
//!
//! A continuation with no preceding header, or a header this build cannot
//! decompose, becomes an `Unrecognized` record: still emitted, still complete,
//! and counted as a parse error so coverage reflects it.

use std::sync::OnceLock;

use regex::Regex;

/// Attribute keys advanced logging is known to emit.
///
/// Closed by design; see the ambiguity note in the module docs. An unknown
/// `key=value` field is left in the message rather than silently consumed,
/// because consuming it would delete text from a lossless record.
pub const ATTRIBUTE_KEYS: &[&str] = &["category", "activity", "version", "session", "correlation"];

/// The minimum number of pipe-delimited fields a decomposable header carries:
/// process, severity, thread, subsystem, message.
const MINIMUM_FIELDS: usize = 5;

/// Header line: timestamp, then at least one pipe.
///
/// The fractional second separator is `:` in the shape the macOS Intune agent
/// family writes and `.` in the shape some builds emit; both are accepted and
/// the original text is preserved either way.
fn header_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(concat!(
            r"^(?P<date>\d{4}-\d{2}-\d{2})[ T]",
            r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})",
            r"[.:](?P<fraction>\d{1,9})",
            r"(?P<offset>Z|[+-]\d{2}:?\d{2})?",
            r"\s*\|(?P<rest>.*)$",
        ))
        .expect("Company Portal header pattern must compile")
    })
}

/// `key=value` with no interior whitespace, anchored to the whole field.
fn attribute_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"^\s*(?P<key>[A-Za-z][A-Za-z0-9_]*)=(?P<value>[^\s|]*)\s*$")
            .expect("Company Portal attribute pattern must compile")
    })
}

/// Apple `log show` export row: a microsecond timestamp with an offset, then a
/// hex thread id and a message type.
///
/// Used only to *reject* unified-log exports here. The unified-log parser is a
/// separate leaf; this is a guard, not a second implementation.
fn unified_log_row_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(
            r"^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{6}[+-]\d{4}\s+0x[0-9A-Fa-f]+\s+\S+\s+0x",
        )
        .expect("unified log row pattern must compile")
    })
}

/// Apple `log show` column header.
fn unified_log_header_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"(?i)^Timestamp\s+Thread\s+Type\s+Activity\s+PID")
            .expect("unified log header pattern must compile")
    })
}

/// Is this line the start of a new logical record?
pub fn is_header_line(line: &str) -> bool {
    header_re().is_match(line.trim_start_matches('\u{feff}'))
}

/// Does this line look like a row of an Apple unified-log export?
pub fn is_unified_log_line(line: &str) -> bool {
    let trimmed = line.trim_start_matches('\u{feff}').trim_start();
    unified_log_header_re().is_match(trimmed) || unified_log_row_re().is_match(trimmed)
}

/// A timestamp as the record wrote it, before any normalization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderTimestamp {
    /// The exact timestamp substring from the source line.
    pub raw_text: String,
    pub year: i32,
    pub month: u32,
    pub day: u32,
    pub hour: u32,
    pub minute: u32,
    pub second: u32,
    /// Fractional second scaled to milliseconds.
    pub millisecond: u32,
    /// `+HHMM`, `-HH:MM`, or `Z`, exactly as written.
    pub offset_text: Option<String>,
    /// The offset in minutes east of UTC, when one was stated.
    pub offset_minutes: Option<i32>,
}

/// A decomposed header line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderFields {
    pub timestamp: HeaderTimestamp,
    pub process: String,
    pub severity_token: String,
    pub thread_token: String,
    pub subsystem: String,
    /// Labeled attributes in source order.
    pub attributes: Vec<(String, String)>,
    pub message: String,
}

/// Decompose a header line into fields.
///
/// Returns `None` for a line that starts like a header but carries too few
/// fields to decompose — a record truncated by a crash or a rotation boundary.
/// The caller keeps such a line whole rather than inventing the missing fields.
pub fn parse_header(line: &str) -> Option<HeaderFields> {
    let line = line.trim_start_matches('\u{feff}');
    let captures = header_re().captures(line)?;

    let timestamp = timestamp_from_captures(line, &captures)?;
    let rest = captures.name("rest")?.as_str();

    // The message is the remainder after the modeled fields, so split with a
    // limit rather than collecting: a message containing `|` must survive whole.
    let mut fields = rest.splitn(MINIMUM_FIELDS, '|');
    let process = fields.next()?.trim().to_string();
    let severity_token = fields.next()?.trim().to_string();
    let thread_token = fields.next()?.trim().to_string();
    let subsystem = fields.next()?.trim().to_string();
    let mut remainder = fields.next()?.to_string();

    if process.is_empty() || severity_token.is_empty() || subsystem.is_empty() {
        return None;
    }

    // Consume labeled attributes from the front of the remainder, one pipe
    // segment at a time, stopping at the first segment that is not one.
    let mut attributes = Vec::new();
    loop {
        let Some((candidate, tail)) = remainder.split_once('|') else {
            break;
        };
        let Some(captures) = attribute_re().captures(candidate) else {
            break;
        };
        let key = captures.name("key")?.as_str().to_ascii_lowercase();
        if !ATTRIBUTE_KEYS.contains(&key.as_str()) {
            break;
        }
        attributes.push((key, captures.name("value")?.as_str().to_string()));
        remainder = tail.to_string();
    }

    Some(HeaderFields {
        timestamp,
        process,
        severity_token,
        thread_token,
        subsystem,
        attributes,
        message: remainder.trim().to_string(),
    })
}

fn timestamp_from_captures(line: &str, captures: &regex::Captures<'_>) -> Option<HeaderTimestamp> {
    let date = captures.name("date")?;
    let fraction = captures.name("fraction")?;
    let offset = captures.name("offset");

    // The raw text runs from the start of the date to the end of whichever of
    // the fraction or the offset came last, so the exact source spelling of the
    // timestamp survives even when this build normalizes it differently.
    let end = offset.map_or(fraction.end(), |m| m.end());
    let raw_text = line.get(date.start()..end)?.to_string();

    let date_text = date.as_str();
    let year = date_text.get(0..4)?.parse().ok()?;
    let month = date_text.get(5..7)?.parse().ok()?;
    let day = date_text.get(8..10)?.parse().ok()?;

    let offset_text = offset.map(|m| m.as_str().to_string());
    let offset_minutes = offset_text.as_deref().and_then(offset_to_minutes);

    Some(HeaderTimestamp {
        raw_text,
        year,
        month,
        day,
        hour: captures.name("hour")?.as_str().parse().ok()?,
        minute: captures.name("minute")?.as_str().parse().ok()?,
        second: captures.name("second")?.as_str().parse().ok()?,
        millisecond: fraction_to_milliseconds(fraction.as_str()),
        offset_text,
        offset_minutes,
    })
}

/// Scale a fractional-second string of any precision to whole milliseconds.
fn fraction_to_milliseconds(fraction: &str) -> u32 {
    let mut digits = fraction.chars().filter(|c| c.is_ascii_digit());
    let mut value = 0u32;
    for _ in 0..3 {
        value = value * 10 + digits.next().and_then(|c| c.to_digit(10)).unwrap_or(0);
    }
    value
}

/// Convert `Z`, `+HHMM`, or `-HH:MM` to minutes east of UTC.
fn offset_to_minutes(text: &str) -> Option<i32> {
    if text.eq_ignore_ascii_case("Z") {
        return Some(0);
    }
    let sign = match text.as_bytes().first()? {
        b'+' => 1,
        b'-' => -1,
        _ => return None,
    };
    let digits: String = text[1..].chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() != 4 {
        return None;
    }
    let hours: i32 = digits.get(0..2)?.parse().ok()?;
    let minutes: i32 = digits.get(2..4)?.parse().ok()?;
    if hours > 23 || minutes > 59 {
        return None;
    }
    Some(sign * (hours * 60 + minutes))
}

/// One logical record before any interpretation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FramedRecord {
    /// 1-based line number of the header line within the artifact.
    pub line_number: u64,
    /// Decomposed header fields, absent for a record this build cannot read.
    pub fields: Option<HeaderFields>,
    /// Header and continuations joined with `\n`, exactly as written.
    pub raw: String,
    pub continuation_lines: u32,
    /// Did this record start without a header line above it?
    pub orphaned: bool,
}

impl FramedRecord {
    /// Is this record one this build fully understood?
    pub fn is_recognized(&self) -> bool {
        self.fields.is_some()
    }

    /// The message, including every continuation line, losslessly.
    pub fn message(&self) -> String {
        let Some(fields) = &self.fields else {
            return self.raw.clone();
        };
        if self.continuation_lines == 0 {
            return fields.message.clone();
        }
        // Continuations follow the header line in `raw`; re-attach them to the
        // header's message rather than to the whole raw text, so the message
        // does not grow a duplicate copy of its own header.
        let tail = self
            .raw
            .split_once('\n')
            .map(|(_, tail)| tail)
            .unwrap_or_default();
        if fields.message.is_empty() {
            tail.to_string()
        } else {
            format!("{}\n{}", fields.message, tail)
        }
    }
}

/// Split artifact text into logical records.
///
/// Blank lines between records are dropped; a blank line *inside* a record is a
/// continuation and is kept, because an exception trace routinely contains one
/// and removing it would corrupt the payload.
pub fn frame_records(content: &str) -> Vec<FramedRecord> {
    let mut records: Vec<FramedRecord> = Vec::new();

    for (index, line) in content.lines().enumerate() {
        let line_number = index as u64 + 1;
        let normalized = line.strip_prefix('\u{feff}').unwrap_or(line);

        if is_header_line(normalized) {
            records.push(FramedRecord {
                line_number,
                fields: parse_header(normalized),
                raw: normalized.to_string(),
                continuation_lines: 0,
                orphaned: false,
            });
            continue;
        }

        match records.last_mut() {
            Some(record) => {
                record.raw.push('\n');
                record.raw.push_str(normalized);
                record.continuation_lines += 1;
            }
            None => {
                if normalized.trim().is_empty() {
                    // Leading blank lines belong to no record and carry nothing.
                    continue;
                }
                records.push(FramedRecord {
                    line_number,
                    fields: None,
                    raw: normalized.to_string(),
                    continuation_lines: 0,
                    orphaned: true,
                });
            }
        }
    }

    // Drop blank continuations at the *end* of a record: they are the separator
    // before the next header, or the file's final newline, not payload the
    // record emitted. A blank line with non-blank continuations after it is
    // interior to a payload and is left alone by the `ends_with` guard.
    for record in &mut records {
        while record.continuation_lines > 0 && record.raw.ends_with('\n') {
            record.raw.pop();
            record.continuation_lines -= 1;
        }
    }

    records
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_basic_header_decomposes_into_five_fields() {
        let fields = parse_header(
            "2026-03-12 09:14:22:301 | CompanyPortal | I | 8412 | SSOExtension | signing in",
        )
        .expect("basic header must decompose");
        assert_eq!(fields.process, "CompanyPortal");
        assert_eq!(fields.severity_token, "I");
        assert_eq!(fields.thread_token, "8412");
        assert_eq!(fields.subsystem, "SSOExtension");
        assert_eq!(fields.message, "signing in");
        assert!(fields.attributes.is_empty());
        assert_eq!(fields.timestamp.raw_text, "2026-03-12 09:14:22:301");
        assert_eq!(fields.timestamp.millisecond, 301);
        assert_eq!(fields.timestamp.offset_minutes, None);
    }

    #[test]
    fn labeled_attributes_are_consumed_and_the_message_survives() {
        let fields = parse_header(
            "2026-03-12 09:14:22.301-0700 | CompanyPortal | E | 8412 | Network | category=Http | activity=0x1a2b | request failed",
        )
        .expect("advanced header must decompose");
        assert_eq!(
            fields.attributes,
            vec![
                ("category".to_owned(), "Http".to_owned()),
                ("activity".to_owned(), "0x1a2b".to_owned()),
            ]
        );
        assert_eq!(fields.message, "request failed");
        assert_eq!(fields.timestamp.offset_minutes, Some(-420));
        assert_eq!(fields.timestamp.offset_text.as_deref(), Some("-0700"));
    }

    #[test]
    fn a_message_containing_pipes_is_not_mistaken_for_attributes() {
        // The whole reason attributes are labeled: a positional field count
        // would swallow the first two message fragments here.
        let fields = parse_header(
            "2026-03-12 09:14:22:301 | CompanyPortal | I | 8412 | Catalog | app A | app B | app C",
        )
        .expect("header must decompose");
        assert!(fields.attributes.is_empty());
        assert_eq!(fields.message, "app A | app B | app C");
    }

    #[test]
    fn an_unknown_attribute_key_stays_in_the_message() {
        let fields = parse_header(
            "2026-03-12 09:14:22:301 | CompanyPortal | I | 8412 | Catalog | tenant=x | done",
        )
        .expect("header must decompose");
        assert!(fields.attributes.is_empty());
        assert_eq!(fields.message, "tenant=x | done");
    }

    #[test]
    fn a_truncated_header_does_not_decompose() {
        assert!(parse_header("2026-03-12 09:14:22:301 | CompanyPortal | I").is_none());
        // It still reads as a header line, so it is framed and reported rather
        // than being silently attached to the record above it.
        assert!(is_header_line("2026-03-12 09:14:22:301 | CompanyPortal | I"));
    }

    #[test]
    fn continuations_attach_to_the_record_above() {
        let content = concat!(
            "2026-03-12 09:14:22:301 | CompanyPortal | E | 8412 | Catalog | install failed\n",
            "  Domain=CPError Code=42\n",
            "  {\n",
            "    \"detail\": \"unreachable\"\n",
            "  }\n",
            "2026-03-12 09:14:23:000 | CompanyPortal | I | 8412 | Catalog | retrying\n",
        );
        let records = frame_records(content);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].continuation_lines, 4);
        assert!(records[0].message().contains("\"detail\": \"unreachable\""));
        assert!(records[0].message().starts_with("install failed\n"));
        assert_eq!(records[1].continuation_lines, 0);
    }

    #[test]
    fn a_blank_line_inside_a_record_is_kept() {
        let content = concat!(
            "2026-03-12 09:14:22:301 | CompanyPortal | E | 8412 | Catalog | trace\n",
            "frame one\n",
            "\n",
            "frame two\n",
        );
        let records = frame_records(content);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].continuation_lines, 3);
        assert!(records[0].raw.contains("frame one\n\nframe two"));
    }

    #[test]
    fn a_continuation_with_no_header_above_it_becomes_an_orphan_record() {
        let records = frame_records("mid-record text from a rotation boundary\n");
        assert_eq!(records.len(), 1);
        assert!(records[0].orphaned);
        assert!(!records[0].is_recognized());
        assert_eq!(records[0].message(), "mid-record text from a rotation boundary");
    }

    #[test]
    fn a_byte_order_mark_does_not_hide_the_first_record() {
        let records = frame_records(
            "\u{feff}2026-03-12 09:14:22:301 | CompanyPortal | I | 8412 | Catalog | start\n",
        );
        assert_eq!(records.len(), 1);
        assert!(records[0].is_recognized());
    }

    #[test]
    fn fractional_seconds_of_any_precision_scale_to_milliseconds() {
        assert_eq!(fraction_to_milliseconds("3"), 300);
        assert_eq!(fraction_to_milliseconds("30"), 300);
        assert_eq!(fraction_to_milliseconds("301"), 301);
        assert_eq!(fraction_to_milliseconds("301474"), 301);
    }

    #[test]
    fn offsets_parse_in_every_spelling_and_reject_nonsense() {
        assert_eq!(offset_to_minutes("Z"), Some(0));
        assert_eq!(offset_to_minutes("+0530"), Some(330));
        assert_eq!(offset_to_minutes("-07:00"), Some(-420));
        assert_eq!(offset_to_minutes("+9900"), None);
    }

    #[test]
    fn unified_log_rows_are_recognized_as_foreign() {
        assert!(is_unified_log_line(
            "Timestamp                       Thread     Type        Activity             PID"
        ));
        assert!(is_unified_log_line(
            "2026-03-12 09:14:22.301474-0700 0x1a2b3c   Default     0x0                  412"
        ));
        assert!(!is_unified_log_line(
            "2026-03-12 09:14:22:301 | CompanyPortal | I | 8412 | Catalog | start"
        ));
    }
}
