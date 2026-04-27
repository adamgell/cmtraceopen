pub mod evtx_parser;
pub mod models;

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
