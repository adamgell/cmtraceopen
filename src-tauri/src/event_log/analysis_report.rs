//! The Markdown report of an event-log analysis session (spec 8.17, #851).
//!
//! The report is rendered by the backend from what the analysis session holds, so no record text
//! crosses IPC and reaches the file unredacted. Three rules shape this module:
//!
//! - **One writer, one gate.** [`safe::Doc`] only accepts [`safe::Safe`] values. A `Safe` is minted
//!   from a raw string by exactly one function, [`safe::Redactor::text`], which redacts, substitutes
//!   known machine names, flattens, cuts and only then escapes Markdown. Everything else that
//!   reaches the document is a `'static` literal, a number, an enum word or a machine token. A raw
//!   `&str` from the session cannot be printed because it does not type-check.
//! - **Evidence first.** Every sentence is a count the report holds or a statement of what was not
//!   loaded, scoped, read or capped. Nothing says one entry caused another.
//! - **Fail closed.** A report that exceeds [`MAX_REPORT_BYTES`], or that names a relation the
//!   session does not hold, is an error, never a silently shortened file.
//!
//! The session is the scope. It is built from the visible records, so the report describes what the
//! operator was looking at, identified by session id and revision.

// The renderer is wired to the Tauri command by a later commit of the same lane.
#![allow(dead_code)]

/// The most bytes a rendered report may have. Over this the export fails.
pub(crate) const MAX_REPORT_BYTES: usize = 2 * 1024 * 1024;
/// Rows in the events table. The rest is counted, not listed.
pub(crate) const REPORT_EVENT_ROW_CAP: usize = 500;
/// Characters of a message cell, counted after redaction.
pub(crate) const REPORT_MESSAGE_CHARS: usize = 240;

mod safe {
    //! The only code that can write text into the report.

    use std::collections::HashMap;

    use cmtraceopen_parser::intune::apps::windows::common::redact_field_value;

    use crate::event_log::export::redact_export_text;

    /// Machine names shorter than this are not searched for in free text: a two-letter name would
    /// corrupt ordinary words. They are counted and the report says so.
    pub(super) const MIN_SUBSTITUTED_MACHINE_CHARS: usize = 3;

    /// Text that is safe to write into the report.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(super) struct Safe(String);

    impl Safe {
        /// Static text written by this module's authors.
        pub(super) fn literal(text: &'static str) -> Self {
            Self(text.to_owned())
        }

        pub(super) fn count(value: u64) -> Self {
            Self(value.to_string())
        }

        /// A UTC time, ISO 8601 with milliseconds and `Z`. A value no calendar can hold is
        /// reported as unavailable; it is never shown as 1970.
        pub(super) fn utc(epoch_ms: i64) -> Self {
            match chrono::DateTime::from_timestamp_millis(epoch_ms) {
                Some(time) => Self(time.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()),
                None => Self("time unavailable".to_owned()),
            }
        }

        /// A stable replacement token for a typed value (`[host:0123456789abcdef]`).
        pub(super) fn token(kind: &'static str, value: &str) -> Self {
            Self(escape(&redact_field_value(kind, value)))
        }

        pub(super) fn as_str(&self) -> &str {
            &self.0
        }
    }

    /// The document being written. It accepts literals, numbers and [`Safe`] values only.
    pub(super) struct Doc {
        out: String,
    }

    impl Doc {
        pub(super) fn new() -> Self {
            Self { out: String::new() }
        }

        pub(super) fn lit(&mut self, text: &'static str) -> &mut Self {
            self.out.push_str(text);
            self
        }

        pub(super) fn safe(&mut self, text: &Safe) -> &mut Self {
            self.out.push_str(&text.0);
            self
        }

        pub(super) fn count(&mut self, value: u64) -> &mut Self {
            self.out.push_str(&value.to_string());
            self
        }

        pub(super) fn nl(&mut self) -> &mut Self {
            self.out.push('\n');
            self
        }

        /// The finished text, or an error when it is over `limit` bytes.
        pub(super) fn finish(self, limit: usize) -> Result<String, String> {
            if self.out.len() > limit {
                return Err(format!(
                    "the report is {} bytes, over the {limit}-byte limit, so it was not written",
                    self.out.len()
                ));
            }
            Ok(self.out)
        }
    }

    /// Redacts free text from the analysis session and mints [`Safe`] values from it.
    pub(super) struct Redactor {
        /// Lowercased machine name to its token.
        machines: HashMap<String, String>,
        /// The distinct byte lengths of the machine names, longest first.
        lengths: Vec<usize>,
        skipped_short: usize,
    }

    impl Redactor {
        /// `names` are the machine names the session's origins carry.
        pub(super) fn new<'a>(names: impl IntoIterator<Item = &'a String>) -> Self {
            let mut machines = HashMap::new();
            let mut skipped_short = 0;
            for name in names {
                let name = name.trim();
                if name.chars().count() < MIN_SUBSTITUTED_MACHINE_CHARS {
                    skipped_short += 1;
                    continue;
                }
                machines
                    .entry(name.to_ascii_lowercase())
                    .or_insert_with(|| redact_field_value("host", name));
            }
            let mut lengths: Vec<usize> = machines.keys().map(String::len).collect();
            lengths.sort_unstable_by(|left, right| right.cmp(left));
            lengths.dedup();
            Self {
                machines,
                lengths,
                skipped_short,
            }
        }

        /// How many machine names were too short to substitute in free text.
        pub(super) fn skipped_short(&self) -> usize {
            self.skipped_short
        }

        /// A machine name as its token. This is the same token the diagnosis projection writes.
        pub(super) fn machine(&self, name: &str) -> Safe {
            Safe::token("host", name.trim())
        }

        /// Free text from the session, safe to print. The order is the point:
        /// redact the whole field, substitute the machine names the session knows, flatten
        /// whitespace, cut to `max_chars`, and only then escape Markdown. Escaping first would
        /// change the text the redaction patterns read; cutting first could split a value the
        /// patterns would have caught.
        pub(super) fn text(&self, raw: &str, max_chars: usize) -> Safe {
            let redacted = redact_export_text(raw);
            let substituted = self.substitute(&redacted);
            let flat = flatten(&substituted);
            Safe(escape(&cut_chars(&flat, max_chars)))
        }

        /// Replaces every known machine name with its token. A name matches only at name
        /// boundaries (a longer identifier that merely contains it is left alone), without regard
        /// to ASCII case, longest first, and never inside an existing replacement token.
        fn substitute(&self, text: &str) -> String {
            if self.machines.is_empty() {
                return text.to_owned();
            }
            let mut out = String::with_capacity(text.len());
            let mut index = 0;
            let mut previous: Option<char> = None;
            while index < text.len() {
                if let Some(length) = token_len_at(text, index) {
                    out.push_str(&text[index..index + length]);
                    index += length;
                    previous = Some(']');
                    continue;
                }
                if !previous.is_some_and(is_name_char) {
                    if let Some((length, token)) = self.match_at(text, index) {
                        out.push_str(token);
                        index += length;
                        previous = Some(']');
                        continue;
                    }
                }
                let Some(character) = text[index..].chars().next() else {
                    break;
                };
                out.push(character);
                index += character.len_utf8();
                previous = Some(character);
            }
            out
        }

        /// The longest known machine name that starts at `index` and ends at a name boundary.
        fn match_at(&self, text: &str, index: usize) -> Option<(usize, &str)> {
            for &length in &self.lengths {
                let Some(candidate) = text.get(index..index + length) else {
                    continue;
                };
                let Some(token) = self.machines.get(&candidate.to_ascii_lowercase()) else {
                    continue;
                };
                if text[index + length..]
                    .chars()
                    .next()
                    .is_some_and(is_name_char)
                {
                    continue;
                }
                return Some((length, token));
            }
            None
        }
    }

    /// A character that continues a machine name or identifier.
    fn is_name_char(character: char) -> bool {
        character.is_alphanumeric() || character == '_' || character == '-'
    }

    /// The length of the `[kind:16 hex digits]` token that starts at byte `start`, if one does.
    pub(super) fn token_len_at(text: &str, start: usize) -> Option<usize> {
        let bytes = text.as_bytes();
        if bytes.get(start) != Some(&b'[') {
            return None;
        }
        let kind_start = start + 1;
        let mut index = kind_start;
        while bytes.get(index).is_some_and(u8::is_ascii_lowercase) {
            index += 1;
        }
        if index == kind_start || bytes.get(index) != Some(&b':') {
            return None;
        }
        index += 1;
        let digits = bytes.get(index..index + 16)?;
        if !digits.iter().all(u8::is_ascii_hexdigit) {
            return None;
        }
        index += 16;
        (bytes.get(index) == Some(&b']')).then_some(index + 1 - start)
    }

    /// Strips format and control characters, and collapses every run of whitespace to one space.
    pub(super) fn flatten(text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        let mut pending_space = false;
        for character in text.chars() {
            if is_invisible(character) {
                continue;
            }
            if character.is_whitespace() || character.is_control() {
                pending_space = !out.is_empty();
                continue;
            }
            if pending_space {
                out.push(' ');
                pending_space = false;
            }
            out.push(character);
        }
        out
    }

    /// Zero-width and bidirectional format characters. They can reorder or hide text when a
    /// reader opens the file, so they are removed rather than shown.
    fn is_invisible(character: char) -> bool {
        matches!(
            character,
            '\u{61c}'
                | '\u{200b}'..='\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{2069}'
                | '\u{feff}'
        )
    }

    /// At most `max_chars` characters, with `...` when text was cut. A cut never lands inside a
    /// replacement token.
    pub(super) fn cut_chars(text: &str, max_chars: usize) -> String {
        let Some((mut end, _)) = text.char_indices().nth(max_chars) else {
            return text.to_owned();
        };
        // A token that straddles the cut is dropped whole: half a token names nothing.
        let mut search_from = end.saturating_sub(MAX_TOKEN_LOOKBACK_BYTES);
        while !text.is_char_boundary(search_from) {
            search_from -= 1;
        }
        if let Some(open) = text[search_from..end].rfind('[') {
            let open = search_from + open;
            if token_len_at(text, open).is_some_and(|length| open + length > end) {
                end = open;
            }
        }
        format!("{}...", text[..end].trim_end())
    }

    /// The longest `[kind:16 hex digits]` token this module reads, in bytes, bounds the search for
    /// a token that a cut would split. A kind is a short lowercase word.
    const MAX_TOKEN_LOOKBACK_BYTES: usize = 64;

    /// Backslash-escapes the characters that carry Markdown or HTML meaning. Replacement tokens
    /// pass through so they stay greppable across the app's surfaces.
    pub(super) fn escape(text: &str) -> String {
        let mut out = String::with_capacity(text.len() + text.len() / 8);
        let mut index = 0;
        while index < text.len() {
            if let Some(length) = token_len_at(text, index) {
                out.push_str(&text[index..index + length]);
                index += length;
                continue;
            }
            let Some(character) = text[index..].chars().next() else {
                break;
            };
            if matches!(
                character,
                '\\' | '`'
                    | '*'
                    | '_'
                    | '['
                    | ']'
                    | '('
                    | ')'
                    | '<'
                    | '>'
                    | '|'
                    | '&'
                    | '#'
                    | '!'
                    | '~'
            ) {
                out.push('\\');
            }
            out.push(character);
            index += character.len_utf8();
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::safe::{cut_chars, escape, flatten, token_len_at, Doc, Redactor, Safe};
    use super::MAX_REPORT_BYTES;
    use cmtraceopen_parser::intune::apps::windows::common::redact_field_value;

    fn redactor(names: &[&str]) -> Redactor {
        let names: Vec<String> = names.iter().map(|name| (*name).to_owned()).collect();
        Redactor::new(&names)
    }

    fn host(name: &str) -> String {
        redact_field_value("host", name)
    }

    #[test]
    fn escape_neutralizes_markdown_and_html_syntax() {
        assert_eq!(
            escape(r"a | b <i> [x](y) `c` *d* _e_ & #f !g ~h"),
            r"a \| b \<i\> \[x\]\(y\) \`c\` \*d\* \_e\_ \& \#f \!g \~h"
        );
        assert_eq!(escape(r"C:\dir"), r"C:\\dir");
    }

    #[test]
    fn a_replacement_token_passes_through_escape_and_a_lookalike_does_not() {
        assert_eq!(escape("[host:0123456789abcdef]"), "[host:0123456789abcdef]");
        // 15 hex digits: not a token.
        assert_eq!(
            escape("[host:0123456789abcde]"),
            r"\[host:0123456789abcde\]"
        );
        // A token followed by a link target must not become a link.
        assert_eq!(
            escape("[host:0123456789abcdef](http://x)"),
            r"[host:0123456789abcdef]\(http://x\)"
        );
        assert_eq!(token_len_at("x[user:00ff00ff00ff00ff]", 1), Some(23));
        assert_eq!(token_len_at("[Host:0123456789abcdef]", 0), None);
        assert_eq!(token_len_at("[host:0123456789abcdeg]", 0), None);
    }

    #[test]
    fn text_is_redacted_before_it_is_escaped() {
        // Escaping first turns `user_0001@...` into `user\_0001@...`, and the UPN pattern then
        // matches only from the underscore on, leaving `user` in the output.
        let out = redactor(&[]).text("contact user_0001@example.invalid today", 240);
        assert!(out.as_str().contains("[upn:"), "{}", out.as_str());
        assert!(!out.as_str().contains("user"), "{}", out.as_str());
        assert!(
            !out.as_str().contains("example.invalid"),
            "{}",
            out.as_str()
        );
    }

    #[test]
    fn text_is_cut_after_it_is_redacted() {
        // The UPN straddles character 240 and the cut falls before its first dot. Cut first, the
        // pattern sees `user0001@subdomain-with-long` (no top-level label) and leaves it; redact
        // first, the whole UPN is one 22-character token that fits before the cut.
        let raw = format!(
            "{} user0001@subdomain-with-long-name.example.invalid tail",
            "x".repeat(211)
        );
        let out = redactor(&[]).text(&raw, 240);
        assert!(out.as_str().contains("[upn:"), "{}", out.as_str());
        assert!(!out.as_str().contains("user0001"), "{}", out.as_str());
    }

    #[test]
    fn a_cut_never_lands_inside_a_token() {
        let raw = format!("{}[host:0123456789abcdef] after", "a".repeat(236));
        let cut = cut_chars(&raw, 240);
        assert_eq!(cut, format!("{}...", "a".repeat(236)));
        assert_eq!(cut_chars("short", 240), "short");
        // Characters are counted, not bytes, and the look-back for a token never splits one.
        assert_eq!(
            cut_chars("\u{e9}\u{e9}\u{e9}\u{e9}", 3),
            "\u{e9}\u{e9}\u{e9}..."
        );
        let wide = "\u{4e2d}".repeat(100);
        assert_eq!(
            cut_chars(&wide, 80),
            format!("{}...", "\u{4e2d}".repeat(80))
        );
    }

    #[test]
    fn flatten_collapses_whitespace_and_strips_format_characters() {
        assert_eq!(flatten("a\r\n\tb\u{202e}c\u{200b}d\u{0}e  f"), "a bcd e f");
        assert_eq!(flatten("  lead and trail  "), "lead and trail");
    }

    #[test]
    fn known_machines_are_replaced_longest_first_at_name_boundaries() {
        let r = redactor(&["HOST-0001", "HOST-0001.example.invalid"]);
        // Longest first: the full name is one token, not a token plus a domain tail.
        let out = r.text("see host-0001.example.invalid now", 240);
        assert_eq!(
            out.as_str(),
            format!("see {} now", host("HOST-0001.example.invalid"))
        );
        // Name boundaries: a longer identifier that contains the name is left alone.
        let out = r.text("XHOST-0001Y HOST-00012 HOST-0001", 240);
        assert_eq!(
            out.as_str(),
            format!("XHOST-0001Y HOST-00012 {}", host("HOST-0001"))
        );
    }

    #[test]
    fn machine_matching_ignores_ascii_case_and_leaves_tokens_alone() {
        let r = redactor(&["Host-0007", "host"]);
        let out = r.text("HOST-0007 and [host:0123456789abcdef] and host", 240);
        assert_eq!(
            out.as_str(),
            format!(
                "{} and [host:0123456789abcdef] and {}",
                host("Host-0007"),
                host("host")
            )
        );
    }

    #[test]
    fn short_machine_names_are_skipped_counted_and_still_tokenized_in_the_header() {
        let r = redactor(&["ab", "HOST-0001"]);
        assert_eq!(r.skipped_short(), 1);
        assert_eq!(
            r.text("ab HOST-0001", 240).as_str(),
            format!("ab {}", host("HOST-0001"))
        );
        assert_eq!(r.machine("ab").as_str(), host("ab"));
    }

    #[test]
    fn the_machine_token_is_the_diagnosis_token() {
        let r = redactor(&["HOST-0001"]);
        let token = r.machine("HOST-0001");
        assert!(token.as_str().starts_with("[host:"));
        assert_eq!(token.as_str(), host("HOST-0001"));
    }

    #[test]
    fn utc_has_milliseconds_and_a_zulu_suffix_and_marks_what_no_calendar_holds() {
        assert_eq!(
            Safe::utc(1_791_282_047_123).as_str(),
            "2026-10-06T10:20:47.123Z"
        );
        assert_eq!(Safe::utc(i64::MAX).as_str(), "time unavailable");
        assert_eq!(Safe::utc(i64::MIN).as_str(), "time unavailable");
    }

    #[test]
    fn the_document_refuses_to_exceed_its_cap() {
        let mut doc = Doc::new();
        doc.lit("0123456789").nl();
        assert_eq!(doc.finish(11).unwrap(), "0123456789\n");
        let mut doc = Doc::new();
        doc.lit("0123456789").nl();
        assert!(doc.finish(10).is_err());
        assert_eq!(MAX_REPORT_BYTES, 2 * 1024 * 1024);
    }
}
