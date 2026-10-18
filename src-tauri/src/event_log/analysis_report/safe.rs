//! The only code that can write text into the report.

use std::collections::HashMap;

use cmtraceopen_parser::diagnosis::{redacted_display_projection, DiagnosisSummary};
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

    /// Concatenation of values that are already safe is safe.
    pub(super) fn join(parts: &[Safe]) -> Self {
        Self(parts.iter().map(|part| part.0.as_str()).collect())
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

/// A diagnosis summary after `redacted_display_projection`. The report reads findings and
/// evidence only through one of these, so it cannot print a summary that was not projected.
pub(super) struct Projected(DiagnosisSummary);

impl Projected {
    pub(super) fn new(summary: DiagnosisSummary) -> Self {
        Self(redacted_display_projection(summary))
    }

    pub(super) fn summary(&self) -> &DiagnosisSummary {
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
        self.finish(&redact_export_text(raw), max_chars)
    }

    /// Text read from a projected summary. The projection is the diagnosis' own redaction, so
    /// the export pass is not run over it again: that pass rewrites the tokens the projection
    /// wrote (`[account:..]` would become `[account:[sensitive:Account]]`).
    pub(super) fn projected(&self, _from: &Projected, text: &str, max_chars: usize) -> Safe {
        self.finish(text, max_chars)
    }

    /// Substitute known machines, flatten, cut, escape.
    fn finish(&self, redacted: &str, max_chars: usize) -> Safe {
        let substituted = self.substitute(redacted);
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
        // A `(` can only start a link target straight after a `]`, and every `]` this function
        // writes is either escaped or the end of a token, so `(` is escaped there and only there.
        if matches!(
            character,
            '\\' | '`' | '*' | '_' | '[' | ']' | '<' | '>' | '|' | '&' | '#' | '!' | '~'
        ) || (character == '(' && out.ends_with(']'))
        {
            out.push('\\');
        }
        out.push(character);
        index += character.len_utf8();
    }
    out
}
