//! Record grammar, byte decoding, and structural field extraction.
//!
//! The grammar is the Microsoft macOS house format shared with
//! [`crate::parser::intune_macos`]:
//!
//! ```text
//! YYYY-MM-DD HH:MM:SS:mmm | Process | S | ThreadID | Component | Message
//! ```
//!
//! It is re-expressed here (rather than imported) because this module needs the
//! individual captures, which the generic parser does not expose. The
//! `grammar_matches_the_generic_intune_macos_parser` test in
//! `tests/company_portal_macos_logs.rs` pins the two definitions together.

use std::sync::OnceLock;

use regex::Regex;

use super::models::{
    PortalDecodedText, PortalEncoding, PortalVersionSupport, COMPANY_PORTAL_PROCESS_TOKENS,
    VALIDATED_APP_VERSION_FAMILIES,
};
use crate::models::log_entry::Severity;

/// Full record grammar. Groups: y, mo, d, h, mi, s, ms, process, severity,
/// thread, component, message.
fn record_head_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(concat!(
            r"^(\d{4})-(\d{2})-(\d{2})\s+(\d{2}):(\d{2}):(\d{2}):(\d{3})",
            r"\s*\|\s*([^|]+?)\s*", // process
            r"\|\s*([A-Z])\s*",     // severity letter
            r"\|\s*(\d+)\s*",       // thread id
            r"\|\s*([^|]+?)\s*",    // component
            r"\|\s*(.*)",           // message (rest of line)
        ))
        .expect("Company Portal macOS record grammar must compile")
    })
}

/// Probe for "this line intends to start a record", used to separate malformed
/// record starts from genuine continuation lines.
fn record_start_probe_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}")
            .expect("Company Portal record-start probe must compile")
    })
}

/// Version banner, anchored at the start of a structural message field.
fn version_banner_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"^Company Portal version ([0-9][0-9A-Za-z.\-+]*)")
            .expect("Company Portal version banner pattern must compile")
    })
}

/// Activity correlation id, anchored at the start of a structural message field.
fn activity_id_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"^\[activityId=([0-9A-Za-z._:-]{1,128})\]")
            .expect("Company Portal activity-id pattern must compile")
    })
}

/// Structural fields of one record head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PortalRecordHead {
    pub raw_timestamp: String,
    pub timestamp_millis: Option<i64>,
    pub timestamp_display: String,
    pub process: String,
    pub severity_letter: String,
    pub thread_id: Option<u32>,
    pub component: String,
    pub message: String,
}

/// Parse a physical line as a record head. Returns `None` when the line does not
/// satisfy the full grammar.
pub(crate) fn parse_record_head(line: &str) -> Option<PortalRecordHead> {
    let caps = record_head_re().captures(line.trim_end())?;

    let num = |i: usize| -> u32 {
        caps.get(i)
            .and_then(|m| m.as_str().parse().ok())
            .unwrap_or(0)
    };
    let year: i32 = caps
        .get(1)
        .and_then(|m| m.as_str().parse().ok())
        .unwrap_or(0);
    let (month, day, hour, minute, second, millis) =
        (num(2), num(3), num(4), num(5), num(6), num(7));

    let timestamp_millis = chrono::NaiveDate::from_ymd_opt(year, month, day)
        .and_then(|d| d.and_hms_milli_opt(hour, minute, second, millis))
        .map(|dt| dt.and_utc().timestamp_millis());

    Some(PortalRecordHead {
        raw_timestamp: format!(
            "{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}:{millis:03}"
        ),
        timestamp_millis,
        timestamp_display: format!(
            "{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}.{millis:03}"
        ),
        process: caps
            .get(8)
            .map(|m| m.as_str().trim())
            .unwrap_or("")
            .to_string(),
        severity_letter: caps.get(9).map(|m| m.as_str()).unwrap_or("I").to_string(),
        thread_id: caps.get(10).and_then(|m| m.as_str().parse().ok()),
        component: caps
            .get(11)
            .map(|m| m.as_str().trim())
            .unwrap_or("")
            .to_string(),
        message: caps
            .get(12)
            .map(|m| m.as_str().trim_end())
            .unwrap_or("")
            .to_string(),
    })
}

/// True when a line looks like a record start, whether or not it is well formed.
pub(crate) fn looks_like_record_start(line: &str) -> bool {
    record_start_probe_re().is_match(line)
}

/// True when a line satisfies the full record grammar.
pub fn is_record_line(line: &str) -> bool {
    record_head_re().is_match(line.trim_end())
}

/// True when a structural process field identifies Company Portal.
///
/// Matching is exact and case-sensitive against
/// [`COMPANY_PORTAL_PROCESS_TOKENS`]; free message text is never consulted.
pub fn is_company_portal_process(process: &str) -> bool {
    COMPANY_PORTAL_PROCESS_TOKENS.contains(&process)
}

/// Map the structural severity letter to a [`Severity`].
///
/// Unknown letters fall back to `Info`, matching the generic macOS Intune
/// parser. Message text is never sniffed.
pub fn severity_from_letter(letter: &str) -> Severity {
    match letter {
        "E" | "F" => Severity::Error,
        "W" => Severity::Warning,
        _ => Severity::Info,
    }
}

/// Extract a version banner from a structural message field.
pub fn version_banner(message: &str) -> Option<String> {
    version_banner_re()
        .captures(message)
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str().to_string())
}

/// Extract an activity id from an anchored `[activityId=...]` message prefix.
///
/// The prefix stays in the message text; the id is additive metadata.
pub fn activity_id(message: &str) -> Option<String> {
    activity_id_re()
        .captures(message)
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str().to_string())
}

/// Whether a declared app version belongs to a fixture-validated family.
pub fn app_version_support(raw_version: &str) -> PortalVersionSupport {
    if VALIDATED_APP_VERSION_FAMILIES
        .iter()
        .any(|family| raw_version.starts_with(family))
    {
        PortalVersionSupport::Validated
    } else {
        PortalVersionSupport::Unknown
    }
}

/// Split decoded text into physical lines, tolerating CRLF and a trailing
/// newline. Line content is returned verbatim apart from the line terminator.
pub(crate) fn split_physical_lines(text: &str) -> Vec<&str> {
    if text.is_empty() {
        return Vec::new();
    }
    let mut lines: Vec<&str> = text
        .split('\n')
        .map(|l| l.strip_suffix('\r').unwrap_or(l))
        .collect();
    if text.ends_with('\n') {
        lines.pop();
    }
    lines
}

/// Decode raw artifact bytes.
///
/// BOM-marked UTF-8/UTF-16 is honoured, otherwise UTF-8 is attempted and
/// Windows-1252 is the fallback (the repo-wide convention).
pub fn decode_log_bytes(bytes: &[u8]) -> PortalDecodedText {
    if let Some((encoding, bom_len)) = encoding_rs::Encoding::for_bom(bytes) {
        let kind = match encoding.name() {
            "UTF-8" => Some(PortalEncoding::Utf8Bom),
            "UTF-16LE" => Some(PortalEncoding::Utf16Le),
            "UTF-16BE" => Some(PortalEncoding::Utf16Be),
            _ => None,
        };
        if let Some(kind) = kind {
            let (text, had_replacement_chars) =
                encoding.decode_without_bom_handling(&bytes[bom_len..]);
            return PortalDecodedText {
                text: text.into_owned(),
                encoding: kind,
                had_bom: true,
                had_replacement_chars,
            };
        }
    }

    match core::str::from_utf8(bytes) {
        Ok(text) => PortalDecodedText {
            text: text.to_string(),
            encoding: PortalEncoding::Utf8,
            had_bom: false,
            had_replacement_chars: false,
        },
        Err(_) => {
            let (text, had_replacement_chars) =
                encoding_rs::WINDOWS_1252.decode_without_bom_handling(bytes);
            PortalDecodedText {
                text: text.into_owned(),
                encoding: PortalEncoding::Windows1252Fallback,
                had_bom: false,
                had_replacement_chars,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str =
        "2026-05-12 08:14:20:104 | CompanyPortal | I | 261481 | AppDelegate | started";

    #[test]
    fn parses_structural_fields() {
        let head = parse_record_head(SAMPLE).expect("sample must parse");
        assert_eq!(head.process, "CompanyPortal");
        assert_eq!(head.severity_letter, "I");
        assert_eq!(head.thread_id, Some(261481));
        assert_eq!(head.component, "AppDelegate");
        assert_eq!(head.message, "started");
        assert_eq!(head.raw_timestamp, "2026-05-12 08:14:20:104");
    }

    #[test]
    fn truncated_line_is_a_record_start_but_not_a_record() {
        let truncated = "2026-05-12 08:16:01:4 | CompanyPortal | I | 26149";
        assert!(looks_like_record_start(truncated));
        assert!(parse_record_head(truncated).is_none());
    }

    #[test]
    fn continuation_line_is_not_a_record_start() {
        assert!(!looks_like_record_start("  UserInfo={"));
    }

    #[test]
    fn severity_comes_from_the_letter_only() {
        assert_eq!(severity_from_letter("E"), Severity::Error);
        assert_eq!(severity_from_letter("W"), Severity::Warning);
        assert_eq!(severity_from_letter("I"), Severity::Info);
        assert_eq!(severity_from_letter("X"), Severity::Info);
    }

    #[test]
    fn version_and_activity_are_anchored() {
        assert_eq!(
            version_banner("Company Portal version 5.2504.0 (build 2504.12)").as_deref(),
            Some("5.2504.0")
        );
        assert!(version_banner("mentions Company Portal version 5.2504.0").is_none());
        assert_eq!(
            activity_id("[activityId=abc-123] doing work").as_deref(),
            Some("abc-123")
        );
        assert!(activity_id("doing work [activityId=abc-123]").is_none());
    }

    #[test]
    fn decodes_utf8_bom_and_windows_1252_fallback() {
        let mut utf8_bom = vec![0xEF, 0xBB, 0xBF];
        utf8_bom.extend_from_slice(b"line");
        let decoded = decode_log_bytes(&utf8_bom);
        assert_eq!(decoded.encoding, PortalEncoding::Utf8Bom);
        assert_eq!(decoded.text, "line");
        assert!(decoded.had_bom);

        let latin1 = [b'c', b'a', b'f', 0xE9];
        let decoded = decode_log_bytes(&latin1);
        assert_eq!(decoded.encoding, PortalEncoding::Windows1252Fallback);
        assert_eq!(decoded.text, "café");
    }

    #[test]
    fn splits_lines_without_inventing_a_trailing_line() {
        assert_eq!(split_physical_lines("a\nb\n"), vec!["a", "b"]);
        assert_eq!(split_physical_lines("a\r\nb"), vec!["a", "b"]);
        assert!(split_physical_lines("").is_empty());
    }
}
