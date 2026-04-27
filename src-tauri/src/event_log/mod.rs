pub mod commands;
pub mod models;
pub mod parser;

#[cfg(target_os = "windows")]
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

#[cfg(test)]
mod tests {
    use super::sanitize_control_chars;

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
        assert_eq!(sanitize_control_chars("col1\tcol2\nrow2"), "col1\tcol2\nrow2");
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
