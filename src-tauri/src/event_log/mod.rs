pub mod archive;
pub mod capture;
pub mod commands;
pub mod event_node;
pub mod export;
pub mod fetch;
pub mod maps;
pub mod models;
pub mod parser;
pub mod provider_db;
pub mod rendered;
pub mod timeline;
pub mod writer;

pub mod live;

/// Strip control characters from a string, preserving newlines and tabs.
///
/// EVTX event data often contains trailing `\r`, `\0`, or other non-printable
/// characters that render as unexpected glyphs in the UI. This strips all
/// C0 control characters (U+0000–U+001F) except `\t` (U+0009) and `\n` (U+000A),
/// plus the DEL character (U+007F), then trims leading/trailing whitespace.
pub(crate) fn sanitize_control_chars(s: &str) -> String {
    s.chars()
        .filter(|&c| c == '\t' || c == '\n' || !(c.is_control() || c == '\u{7f}'))
        .collect::<String>()
        .trim()
        .to_string()
}

/// Parse an event timestamp to epoch milliseconds.
///
/// Shared by the live and file paths so that a record sorts to the same place regardless of how it
/// was opened. Windows usually writes a full RFC 3339 stamp, but some providers omit the zone, in
/// which case it is read as UTC: the alternative is dropping the event to the epoch, which would
/// silently reorder the timeline rather than being off by a zone offset.
pub(crate) fn parse_timestamp_to_epoch_ms(timestamp: &str) -> i64 {
    chrono::DateTime::parse_from_rfc3339(timestamp)
        .or_else(|_| {
            chrono::NaiveDateTime::parse_from_str(timestamp, "%Y-%m-%dT%H:%M:%S%.f")
                .map(|naive| naive.and_utc().fixed_offset())
        })
        .map(|dt| dt.timestamp_millis())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::{parse_timestamp_to_epoch_ms, sanitize_control_chars};

    #[test]
    fn reads_a_full_rfc3339_stamp() {
        assert_eq!(
            parse_timestamp_to_epoch_ms("2026-08-09T12:00:00.000Z"),
            1_786_276_800_000
        );
    }

    #[test]
    fn a_stamp_without_a_zone_is_read_as_utc_rather_than_dropped() {
        // Dropping it to zero would sort the event to 1970 and silently reorder the timeline.
        assert_eq!(
            parse_timestamp_to_epoch_ms("2026-08-09T12:00:00.000"),
            parse_timestamp_to_epoch_ms("2026-08-09T12:00:00.000Z")
        );
    }

    #[test]
    fn an_unreadable_stamp_yields_zero() {
        assert_eq!(parse_timestamp_to_epoch_ms("not a time"), 0);
        assert_eq!(parse_timestamp_to_epoch_ms(""), 0);
    }

    #[test]
    fn strips_trailing_carriage_return() {
        assert_eq!(sanitize_control_chars("hello world\r"), "hello world");
    }

    #[test]
    fn strips_null_bytes() {
        assert_eq!(sanitize_control_chars("hello\0world\0"), "helloworld");
        // Trailing null only
        assert_eq!(sanitize_control_chars("hello\0"), "hello");
    }

    #[test]
    fn strips_mixed_control_chars() {
        assert_eq!(
            sanitize_control_chars("line1\r\nline2\r\n\0"),
            "line1\nline2"
        );
    }

    #[test]
    fn preserves_tabs_and_newlines() {
        assert_eq!(
            sanitize_control_chars("col1\tcol2\nrow2"),
            "col1\tcol2\nrow2"
        );
    }

    #[test]
    fn trims_whitespace() {
        assert_eq!(sanitize_control_chars("  hello  "), "hello");
    }

    #[test]
    fn handles_empty_string() {
        assert_eq!(sanitize_control_chars(""), "");
    }

    #[test]
    fn strips_del_character() {
        assert_eq!(sanitize_control_chars("hello\x7f"), "hello");
    }

    #[test]
    fn clean_string_unchanged() {
        assert_eq!(sanitize_control_chars("normal text"), "normal text");
    }
}
