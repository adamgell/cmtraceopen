//! The only code that can write text into the report.

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::LazyLock;

use cmtraceopen_parser::diagnosis::{redacted_display_projection, DiagnosisSummary};
use cmtraceopen_parser::intune::apps::windows::common::redact_field_value;
use regex::Regex;

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

/// A diagnosis summary after `redacted_display_projection`, projected from a copy whose strings
/// had their invisible characters removed first. The report reads findings and evidence only
/// through one of these, so it cannot print a summary that was not projected.
pub(super) struct Projected(DiagnosisSummary);

impl Projected {
    /// Fails only when the summary cannot be walked as JSON, which no summary the engine builds
    /// should do. The error names nothing from the summary.
    pub(super) fn new(summary: DiagnosisSummary) -> Result<Self, String> {
        Ok(Self(redacted_display_projection(strip_summary(&summary)?)))
    }

    pub(super) fn summary(&self) -> &DiagnosisSummary {
        &self.0
    }

    /// The summary itself, as the starting point for reading text out of it.
    pub(super) fn root(&self) -> Within<'_, DiagnosisSummary> {
        Within(&self.0)
    }
}

/// A borrow of something inside a [`Projected`] summary. It is the only way to get a
/// [`ProjectedText`]: every way of reaching a string takes a closure that is higher-ranked over
/// the borrow, so it can return text borrowed from the item it is given (or a `'static` literal)
/// and cannot return a string that came from anywhere else.
pub(super) struct Within<'a, T>(&'a T);

impl<T> Clone for Within<'_, T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for Within<'_, T> {}

impl<'a, T> Within<'a, T> {
    /// The item, for the counts, enums and structure the report reads from it.
    pub(super) fn get(self) -> &'a T {
        self.0
    }

    pub(super) fn text(self, pick: impl for<'s> FnOnce(&'s T) -> &'s str) -> ProjectedText<'a> {
        ProjectedText(pick(self.0))
    }

    pub(super) fn maybe_text(
        self,
        pick: impl for<'s> FnOnce(&'s T) -> Option<&'s str>,
    ) -> Option<ProjectedText<'a>> {
        pick(self.0).map(ProjectedText)
    }

    pub(super) fn each<U: 'a>(
        self,
        pick: impl for<'s> FnOnce(&'s T) -> &'s [U],
    ) -> impl Iterator<Item = Within<'a, U>> {
        pick(self.0).iter().map(Within)
    }

    pub(super) fn variant<U: 'a>(
        self,
        pick: impl for<'s> FnOnce(&'s T) -> Option<&'s U>,
    ) -> Option<Within<'a, U>> {
        pick(self.0).map(Within)
    }
}

/// A string read out of a [`Projected`] summary. [`Redactor::projected`] accepts nothing else, so
/// text that did not come from a projected summary cannot be written through it.
#[derive(Debug, Clone, Copy)]
pub(super) struct ProjectedText<'a>(&'a str);

impl<'a> ProjectedText<'a> {
    pub(super) fn as_str(self) -> &'a str {
        self.0
    }

    /// The last path segment.
    pub(super) fn file_name(self) -> Self {
        Self(file_name(self.0))
    }

    /// The first `count` characters.
    pub(super) fn first_chars(self, count: usize) -> Self {
        match self.0.char_indices().nth(count) {
            Some((end, _)) => Self(&self.0[..end]),
            None => self,
        }
    }
}

/// A path reduced to its last segment, so a folder name above a file never reaches the report.
pub(super) fn file_name(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
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
            // A name is known by what it reads as, so an invisible character inside it does not
            // keep it from matching the same name in text.
            let name = strip_invisible(name);
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

    /// A machine name as its token. This is the same token the diagnosis projection writes for
    /// the name as it reads, without its invisible characters.
    pub(super) fn machine(&self, name: &str) -> Safe {
        Safe::token("host", strip_invisible(name).trim())
    }

    /// Free text from the session, safe to print. The order is the point:
    /// delete the invisible characters, redact the whole field, substitute the machine names
    /// the session knows, flatten whitespace, cut to `max_chars`, and only then escape Markdown.
    /// An invisible character inside an identifier keeps every pattern from matching it, so it
    /// goes first. Escaping first would change the text the redaction patterns read; cutting
    /// first could split a value the patterns would have caught.
    pub(super) fn text(&self, raw: &str, max_chars: usize) -> Safe {
        self.finish(&redact_export_text(&strip_invisible(raw)), max_chars)
    }

    /// Text read from a projected summary. The projection is the diagnosis' own redaction, so
    /// the export pass is not run over it again: that pass rewrites the tokens the projection
    /// wrote (`[account:..]` would become `[account:[sensitive:Account]]`).
    pub(super) fn projected(&self, text: ProjectedText<'_>, max_chars: usize) -> Safe {
        self.finish(text.as_str(), max_chars)
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

/// A character that continues a machine name. Only letters and digits do: a dash or an underscore
/// beside a name is punctuation, and collector file names and evtx basenames carry the machine
/// that way (`collector-...-HOST-0002-4242.log`, `HOST-0002_System.evtx`).
fn is_name_char(character: char) -> bool {
    character.is_alphanumeric()
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

/// Strips the invisible characters (again, as a guard) and the control characters, and collapses
/// every run of whitespace to one space.
pub(super) fn flatten(text: &str) -> String {
    let text = strip_invisible(text);
    let mut out = String::with_capacity(text.len());
    let mut pending_space = false;
    for character in text.chars() {
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

/// The invisible set, in one place. Characters that draw nothing, or that reorder what is drawn,
/// and so can sit inside an identifier without changing how it reads:
///
/// - Unicode general category Cf (zero width space, joiners, word joiner, byte order mark, soft
///   hyphen, the bidirectional controls, tag characters);
/// - the combining grapheme joiner U+034F;
/// - the Hangul fillers U+115F, U+1160, U+3164 and U+FFA0;
/// - the variation selectors U+FE00 to U+FE0F and U+E0100 to U+E01EF.
///
/// Homoglyphs and fullwidth forms are not normalized.
static INVISIBLE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"[\p{Cf}\x{34F}\x{115F}\x{1160}\x{3164}\x{FFA0}",
        r"\x{FE00}-\x{FE0F}\x{E0100}-\x{E01EF}]"
    ))
    .expect("the invisible character class must compile")
});

/// `text` without its invisible characters. This is the one definition of them: the redaction
/// paths strip first, and [`flatten`] strips again as a guard.
pub(super) fn strip_invisible(text: &str) -> Cow<'_, str> {
    INVISIBLE.replace_all(text, "")
}

/// A copy of `summary` with every string stripped of its invisible characters. The summary is
/// walked as JSON, so a string field added to it later is covered without anyone listing it.
pub(super) fn strip_summary(summary: &DiagnosisSummary) -> Result<DiagnosisSummary, String> {
    const UNPREPARED: &str = "the diagnosis summary could not be prepared for the report";
    let mut value = serde_json::to_value(summary).map_err(|_| UNPREPARED.to_owned())?;
    strip_strings(&mut value);
    serde_json::from_value(value).map_err(|_| UNPREPARED.to_owned())
}

fn strip_strings(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(text) => {
            if let Cow::Owned(stripped) = strip_invisible(text) {
                *text = stripped;
            }
        }
        serde_json::Value::Array(items) => items.iter_mut().for_each(strip_strings),
        serde_json::Value::Object(fields) => fields.values_mut().for_each(strip_strings),
        _ => {}
    }
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
