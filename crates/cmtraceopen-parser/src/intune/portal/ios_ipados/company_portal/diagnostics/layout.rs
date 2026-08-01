//! Console export layout resolution and timestamp normalization.
//!
//! Console renders column labels, the timestamp grammar, and message-type labels
//! according to the Mac's locale. Sniffing them independently lets a German
//! `12.03.2026` be read as an American month-first date, so they are resolved as
//! one unit: a layout is the tuple of all three, and a record grammar is only
//! ever applied once its layout is known.

use std::sync::OnceLock;

use chrono::{FixedOffset, NaiveDate, SecondsFormat, TimeZone};
use regex::Regex;

use super::models::{
    ConsoleColumn, ConsoleLayout, ConsoleLayoutConfidence, ConsoleLayoutRefusal, ConsoleMessageType,
};
use crate::intune::evidence::{IntuneTimestamp, IntuneTimestampKind};

/// Columns a layout must declare before this leaf will frame records from it.
///
/// Without a timestamp there is no record boundary, and without a message there
/// is nothing to classify. Everything else is optional: Console lets the operator
/// hide columns, and a capture missing `Subsystem` is still usable evidence.
const REQUIRED_COLUMNS: [ConsoleColumn; 2] = [ConsoleColumn::Timestamp, ConsoleColumn::Message];

/// The column order Console writes when the operator has not rearranged them.
///
/// Used only to recover a headerless copy, where the labels were left behind.
const CANONICAL_COLUMNS: [ConsoleColumn; 9] = [
    ConsoleColumn::Timestamp,
    ConsoleColumn::MessageType,
    ConsoleColumn::Process,
    ConsoleColumn::ProcessId,
    ConsoleColumn::ThreadId,
    ConsoleColumn::Activity,
    ConsoleColumn::Subsystem,
    ConsoleColumn::Category,
    ConsoleColumn::Message,
];

/// Header labels per layout, lowercased.
///
/// Matching is by label, not position, so an operator who reorders Console's
/// columns still produces a resolvable export.
fn header_vocabulary(layout: ConsoleLayout) -> &'static [(&'static str, ConsoleColumn)] {
    match layout {
        ConsoleLayout::TabularEnUs => &[
            ("timestamp", ConsoleColumn::Timestamp),
            ("time", ConsoleColumn::Timestamp),
            ("type", ConsoleColumn::MessageType),
            ("process", ConsoleColumn::Process),
            ("pid", ConsoleColumn::ProcessId),
            ("tid", ConsoleColumn::ThreadId),
            ("thread", ConsoleColumn::ThreadId),
            ("activity", ConsoleColumn::Activity),
            ("subsystem", ConsoleColumn::Subsystem),
            ("category", ConsoleColumn::Category),
            ("message", ConsoleColumn::Message),
        ],
        ConsoleLayout::TabularDeDe => &[
            ("zeitpunkt", ConsoleColumn::Timestamp),
            ("zeit", ConsoleColumn::Timestamp),
            ("typ", ConsoleColumn::MessageType),
            ("prozess", ConsoleColumn::Process),
            ("pid", ConsoleColumn::ProcessId),
            ("tid", ConsoleColumn::ThreadId),
            ("aktivität", ConsoleColumn::Activity),
            ("teilsystem", ConsoleColumn::Subsystem),
            ("kategorie", ConsoleColumn::Category),
            ("nachricht", ConsoleColumn::Message),
        ],
        ConsoleLayout::Unresolved => &[],
    }
}

/// Message-type labels per layout, lowercased.
///
/// An unrecognized label becomes [`ConsoleMessageType::Unknown`] and round-trips
/// verbatim rather than being forced into the nearest known severity.
fn message_type_vocabulary(layout: ConsoleLayout) -> &'static [(&'static str, ConsoleMessageType)] {
    match layout {
        ConsoleLayout::TabularEnUs => &[
            ("default", ConsoleMessageType::Default),
            ("info", ConsoleMessageType::Info),
            ("debug", ConsoleMessageType::Debug),
            ("error", ConsoleMessageType::Error),
            ("fault", ConsoleMessageType::Fault),
            ("activity", ConsoleMessageType::Activity),
            ("signpost", ConsoleMessageType::Signpost),
        ],
        ConsoleLayout::TabularDeDe => &[
            ("standard", ConsoleMessageType::Default),
            ("info", ConsoleMessageType::Info),
            ("fehlersuche", ConsoleMessageType::Debug),
            ("fehler", ConsoleMessageType::Error),
            ("systemfehler", ConsoleMessageType::Fault),
            ("aktivität", ConsoleMessageType::Activity),
        ],
        ConsoleLayout::Unresolved => &[],
    }
}

/// Layouts tried, in order, when resolving a header.
const KNOWN_LAYOUTS: [ConsoleLayout; 2] = [ConsoleLayout::TabularEnUs, ConsoleLayout::TabularDeDe];

/// `2026-03-12 10:15:22.481293-0700`, with the fraction and offset both optional.
fn en_us_timestamp() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?x)
            ^(?P<year>\d{4})-(?P<month>\d{2})-(?P<day>\d{2})
            [\ T]
            (?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})
            (?:\.(?P<fraction>\d{1,9}))?
            (?P<offset>Z|[+-]\d{2}:?\d{2})?$",
        )
        .expect("en-US Console timestamp pattern is valid")
    })
}

/// `12.03.2026 10:15:22,481293+0100`, with the fraction and offset both optional.
fn de_de_timestamp() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?x)
            ^(?P<day>\d{2})\.(?P<month>\d{2})\.(?P<year>\d{4})
            [\ ,]\ ?
            (?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})
            (?:,(?P<fraction>\d{1,9}))?
            (?P<offset>Z|[+-]\d{2}:?\d{2})?$",
        )
        .expect("de-DE Console timestamp pattern is valid")
    })
}

/// Anything that opens with a date-shaped run of digits.
///
/// This is what separates "a record row whose timestamp is corrupt" from "a
/// continuation line of the previous message". Getting that wrong silently folds
/// broken rows into the message above them, which is exactly how a malformed
/// capture comes to look clean.
fn timestamp_shape() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^\s*(?:\d{4}-\d{1,2}-\d{1,2}|\d{1,2}\.\d{1,2}\.\d{4}|\d{1,2}/\d{1,2}/\d{2,4})")
            .expect("timestamp shape pattern is valid")
    })
}

/// The resolved reading frame for one export.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ResolvedLayout {
    pub layout: ConsoleLayout,
    pub confidence: ConsoleLayoutConfidence,
    pub refusal: Option<ConsoleLayoutRefusal>,
    pub columns: Vec<ConsoleColumn>,
    /// Zero-based index of the header row, when one was found.
    pub header_line_index: Option<usize>,
    /// Zero-based index of the first line that may frame a record.
    pub body_start_index: usize,
    /// Lines before the body that framed no record.
    pub preamble_line_count: u32,
}

impl ResolvedLayout {
    fn refused(refusal: ConsoleLayoutRefusal) -> Self {
        Self {
            layout: ConsoleLayout::Unresolved,
            confidence: ConsoleLayoutConfidence::None,
            refusal: Some(refusal),
            columns: Vec::new(),
            header_line_index: None,
            body_start_index: 0,
            preamble_line_count: 0,
        }
    }

    /// Index of a column in the resolved order, if the export declared it.
    pub fn index_of(&self, column: &ConsoleColumn) -> Option<usize> {
        self.columns.iter().position(|candidate| candidate == column)
    }
}

/// Resolve the layout of an export from its lines.
///
/// A header row wins outright. Without one, the canonical column order is
/// inferred only when several rows agree on it, so a stray tab in an unrelated
/// text file cannot promote itself to a Console export.
pub(super) fn resolve_layout(lines: &[&str]) -> ResolvedLayout {
    // A header must appear before any record; scanning the whole file would let
    // a message body containing the word "Subsystem" masquerade as one.
    const HEADER_SEARCH_LIMIT: usize = 16;

    let mut saw_tabular_non_record = false;

    for (index, line) in lines.iter().enumerate().take(HEADER_SEARCH_LIMIT) {
        let trimmed = line.trim_end_matches('\r');
        if trimmed.trim().is_empty() {
            continue;
        }
        if timestamp_shape().is_match(trimmed) {
            // A record already: there is no header to find.
            break;
        }
        let fields = split_fields(trimmed);
        if fields.len() < 3 {
            continue;
        }
        saw_tabular_non_record = true;

        if let Some(resolved) = header_from_fields(&fields, index) {
            return resolved;
        }
    }

    if let Some(resolved) = infer_headerless_layout(lines) {
        return resolved;
    }

    ResolvedLayout::refused(if saw_tabular_non_record {
        ConsoleLayoutRefusal::UnknownHeaderVocabulary
    } else {
        ConsoleLayoutRefusal::NotAConsoleExport
    })
}

/// Resolve a header row against every known locale vocabulary.
fn header_from_fields(fields: &[&str], index: usize) -> Option<ResolvedLayout> {
    let mut best: Option<(usize, ConsoleLayout, Vec<ConsoleColumn>)> = None;

    for layout in KNOWN_LAYOUTS {
        let vocabulary = header_vocabulary(layout);
        let mut columns = Vec::with_capacity(fields.len());
        let mut matched = 0usize;
        for field in fields {
            let label = field.trim().to_lowercase();
            match vocabulary
                .iter()
                .find(|(candidate, _)| *candidate == label)
                .map(|(_, column)| column.clone())
            {
                Some(column) => {
                    matched += 1;
                    columns.push(column);
                }
                // Preserved verbatim: a column this build does not model still
                // occupies a position, and its values are carried unmodeled
                // rather than shifting every column to its right.
                None => columns.push(ConsoleColumn::Unknown(field.trim().to_owned())),
            }
        }
        if best.as_ref().is_none_or(|(best_matched, _, _)| matched > *best_matched) {
            best = Some((matched, layout, columns));
        }
    }

    let (matched, layout, columns) = best?;
    // Two labels is the floor: one lucky collision ("Type", "PID") is not a
    // Console header, and demanding all of them would reject a copy made with
    // some columns hidden.
    //
    // Below the floor this row is simply not a header, so `None` lets the caller
    // keep looking. Refusing outright here would let one tab-containing preamble
    // line above the real header sink the whole export.
    if matched < 2 {
        return None;
    }

    let resolved = ResolvedLayout {
        layout,
        confidence: ConsoleLayoutConfidence::HeaderDeclared,
        refusal: None,
        columns,
        header_line_index: Some(index),
        body_start_index: index + 1,
        preamble_line_count: u32::try_from(index).unwrap_or(u32::MAX),
    };

    if REQUIRED_COLUMNS
        .iter()
        .any(|required| resolved.index_of(required).is_none())
    {
        return Some(ResolvedLayout::refused(
            ConsoleLayoutRefusal::IncompleteHeader,
        ));
    }

    Some(resolved)
}

/// Recover a header-less copy from consistently shaped rows.
///
/// Requires several rows agreeing on the full canonical column count and on one
/// timestamp grammar. Anything less stays unresolved: guessing here would give a
/// tab-containing text file a process and a subsystem it never had.
fn infer_headerless_layout(lines: &[&str]) -> Option<ResolvedLayout> {
    const MIN_AGREEING_ROWS: usize = 2;
    const SAMPLE_LIMIT: usize = 64;

    for layout in KNOWN_LAYOUTS {
        let mut agreeing = 0usize;
        let mut first_index = None;
        for (index, line) in lines.iter().enumerate().take(SAMPLE_LIMIT) {
            let trimmed = line.trim_end_matches('\r');
            if trimmed.trim().is_empty() {
                continue;
            }
            let fields = split_fields(trimmed);
            if fields.len() < CANONICAL_COLUMNS.len() {
                continue;
            }
            if parse_timestamp(layout, fields[0]).kind == IntuneTimestampKind::Invalid {
                continue;
            }
            agreeing += 1;
            first_index.get_or_insert(index);
        }
        if agreeing >= MIN_AGREEING_ROWS {
            let body_start_index = first_index.unwrap_or(0);
            return Some(ResolvedLayout {
                layout,
                confidence: ConsoleLayoutConfidence::Inferred,
                refusal: None,
                columns: CANONICAL_COLUMNS.to_vec(),
                header_line_index: None,
                body_start_index,
                preamble_line_count: u32::try_from(body_start_index).unwrap_or(u32::MAX),
            });
        }
    }
    None
}

/// Split a Console row into columns.
///
/// Console's plain-text copy is tab-delimited. A row is never split on runs of
/// spaces: message bodies contain them, and doing so shreds every multi-word
/// message into phantom columns.
pub(super) fn split_fields(line: &str) -> Vec<&str> {
    line.split('\t').collect()
}

/// Whether a line opens with something date-shaped.
pub(super) fn looks_like_record_start(field: &str) -> bool {
    timestamp_shape().is_match(field)
}

/// Map a message-type label to Apple's vocabulary for the resolved layout.
pub(super) fn parse_message_type(layout: ConsoleLayout, raw: &str) -> Option<ConsoleMessageType> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let lowered = trimmed.to_lowercase();
    Some(
        message_type_vocabulary(layout)
            .iter()
            .find(|(label, _)| *label == lowered)
            .map(|(_, kind)| kind.clone())
            .unwrap_or_else(|| ConsoleMessageType::Unknown(trimmed.to_owned())),
    )
}

/// Normalize a Console timestamp without inventing a timezone.
///
/// A Console export shows the Mac's local wall clock, and the offset column is
/// frequently absent from a copied selection. When it is,
/// [`IntuneTimestampKind::Local`] is reported and `normalized_utc` stays `None`:
/// stamping such a record as UTC would silently shift it by hours and make the
/// error invisible to whoever later compares it against a service-side log.
pub(super) fn parse_timestamp(layout: ConsoleLayout, raw: &str) -> IntuneTimestamp {
    let text = raw.trim();
    let invalid = || IntuneTimestamp {
        raw_text: text.to_owned(),
        original_offset: None,
        normalized_utc: None,
        kind: IntuneTimestampKind::Invalid,
    };

    let pattern = match layout {
        ConsoleLayout::TabularEnUs => en_us_timestamp(),
        ConsoleLayout::TabularDeDe => de_de_timestamp(),
        ConsoleLayout::Unresolved => return invalid(),
    };

    let Some(captures) = pattern.captures(text) else {
        return invalid();
    };

    let field = |name: &str| captures.name(name).map(|m| m.as_str());
    let number = |name: &str| field(name).and_then(|value| value.parse::<u32>().ok());

    let (Some(year), Some(month), Some(day), Some(hour), Some(minute), Some(second)) = (
        number("year"),
        number("month"),
        number("day"),
        number("hour"),
        number("minute"),
        number("second"),
    ) else {
        return invalid();
    };

    let Ok(year) = i32::try_from(year) else {
        return invalid();
    };
    let Some(date) = NaiveDate::from_ymd_opt(year, month, day) else {
        return invalid();
    };
    let nanoseconds = field("fraction").map_or(0, |digits| {
        let mut padded = digits.to_owned();
        padded.truncate(9);
        while padded.len() < 9 {
            padded.push('0');
        }
        padded.parse::<u32>().unwrap_or(0)
    });
    let Some(naive) = date.and_hms_nano_opt(hour, minute, second, nanoseconds) else {
        return invalid();
    };

    let has_fraction = field("fraction").is_some();
    let Some(offset_text) = field("offset") else {
        // No offset in the capture: local wall clock, deliberately not normalized.
        return IntuneTimestamp {
            raw_text: text.to_owned(),
            original_offset: None,
            normalized_utc: None,
            kind: IntuneTimestampKind::Local,
        };
    };

    let Some(offset_seconds) = offset_seconds(offset_text) else {
        return invalid();
    };
    let Some(offset) = FixedOffset::east_opt(offset_seconds) else {
        return invalid();
    };
    let Some(fixed) = offset.from_local_datetime(&naive).single() else {
        return invalid();
    };

    let precision = if has_fraction {
        SecondsFormat::Micros
    } else {
        SecondsFormat::Secs
    };

    IntuneTimestamp {
        raw_text: text.to_owned(),
        original_offset: Some(offset_text.to_owned()),
        normalized_utc: Some(
            fixed
                .with_timezone(&chrono::Utc)
                .to_rfc3339_opts(precision, true),
        ),
        kind: if offset_seconds == 0 && offset_text.eq_ignore_ascii_case("Z") {
            IntuneTimestampKind::Utc
        } else {
            IntuneTimestampKind::Offset
        },
    }
}

/// `Z`, `+0100`, or `-07:00` as a signed second count.
fn offset_seconds(text: &str) -> Option<i32> {
    if text.eq_ignore_ascii_case("Z") {
        return Some(0);
    }
    let sign = match text.as_bytes().first()? {
        b'+' => 1,
        b'-' => -1,
        _ => return None,
    };
    let digits = text[1..].replace(':', "");
    if digits.len() != 4 || !digits.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let hours: i32 = digits[..2].parse().ok()?;
    let minutes: i32 = digits[2..].parse().ok()?;
    if minutes >= 60 || hours > 18 {
        return None;
    }
    Some(sign * (hours * 3600 + minutes * 60))
}

#[cfg(test)]
mod tests {
    use super::*;

    const EN_HEADER: &str = "Timestamp\tType\tProcess\tPID\tTID\tActivity\tSubsystem\tCategory\tMessage";

    #[test]
    fn english_header_resolves_the_en_us_layout() {
        let resolved = resolve_layout(&[EN_HEADER]);
        assert_eq!(resolved.layout, ConsoleLayout::TabularEnUs);
        assert_eq!(resolved.confidence, ConsoleLayoutConfidence::HeaderDeclared);
        assert_eq!(resolved.index_of(&ConsoleColumn::Message), Some(8));
    }

    #[test]
    fn german_header_resolves_the_de_de_layout() {
        let header = "Zeitpunkt\tTyp\tProzess\tPID\tTID\tAktivität\tTeilsystem\tKategorie\tNachricht";
        let resolved = resolve_layout(&[header]);
        assert_eq!(resolved.layout, ConsoleLayout::TabularDeDe);
        assert_eq!(resolved.index_of(&ConsoleColumn::Subsystem), Some(6));
    }

    #[test]
    fn a_reordered_header_is_matched_by_label_not_position() {
        let resolved = resolve_layout(&["Process\tTimestamp\tMessage"]);
        assert_eq!(resolved.index_of(&ConsoleColumn::Timestamp), Some(1));
        assert_eq!(resolved.index_of(&ConsoleColumn::Message), Some(2));
    }

    #[test]
    fn an_unmodeled_column_keeps_its_label_and_its_position() {
        let resolved = resolve_layout(&["Timestamp\tBacktrace\tMessage"]);
        assert_eq!(
            resolved.columns[1],
            ConsoleColumn::Unknown("Backtrace".to_owned())
        );
        assert_eq!(resolved.index_of(&ConsoleColumn::Message), Some(2));
    }

    #[test]
    fn a_header_without_a_message_column_is_refused() {
        let resolved = resolve_layout(&["Timestamp\tType\tProcess"]);
        assert_eq!(resolved.layout, ConsoleLayout::Unresolved);
        assert_eq!(resolved.refusal, Some(ConsoleLayoutRefusal::IncompleteHeader));
    }

    #[test]
    fn an_unknown_header_vocabulary_is_refused_rather_than_guessed() {
        let resolved = resolve_layout(&["Colonne1\tColonne2\tColonne3\tColonne4"]);
        assert_eq!(resolved.layout, ConsoleLayout::Unresolved);
        assert_eq!(
            resolved.refusal,
            Some(ConsoleLayoutRefusal::UnknownHeaderVocabulary)
        );
    }

    #[test]
    fn a_tab_containing_preamble_line_does_not_hide_the_real_header() {
        // Refusing on the first unrecognized tabular line let one note pasted
        // above the header sink an otherwise sound export.
        let resolved = resolve_layout(&["note\tabout\tthis\tcapture", EN_HEADER]);
        assert_eq!(resolved.layout, ConsoleLayout::TabularEnUs);
        assert_eq!(resolved.header_line_index, Some(1));
        assert_eq!(resolved.body_start_index, 2);
    }

    #[test]
    fn arbitrary_prose_is_not_a_console_export() {
        let resolved = resolve_layout(&["hello there", "this is a note", ""]);
        assert_eq!(
            resolved.refusal,
            Some(ConsoleLayoutRefusal::NotAConsoleExport)
        );
    }

    #[test]
    fn a_headerless_copy_is_inferred_only_from_agreeing_rows() {
        let row = |seconds: &str| {
            format!(
                "2026-03-12 10:15:{seconds}.100000-0700\tDefault\tCompanyPortal\t418\t0x1\t0\tcom.microsoft.CompanyPortal\tGeneral\thello"
            )
        };
        let first = row("22");
        let second = row("23");
        let resolved = resolve_layout(&[first.as_str(), second.as_str()]);
        assert_eq!(resolved.layout, ConsoleLayout::TabularEnUs);
        assert_eq!(resolved.confidence, ConsoleLayoutConfidence::Inferred);
    }

    #[test]
    fn one_tab_containing_line_does_not_infer_a_layout() {
        let single =
            "2026-03-12 10:15:22.100000-0700\tDefault\tCompanyPortal\t418\t0x1\t0\tsub\tcat\thello";
        let resolved = resolve_layout(&[single]);
        assert_eq!(resolved.layout, ConsoleLayout::Unresolved);
    }

    #[test]
    fn an_offset_timestamp_normalizes_to_utc() {
        let stamp = parse_timestamp(ConsoleLayout::TabularEnUs, "2026-03-12 10:15:22.481293-0700");
        assert_eq!(stamp.kind, IntuneTimestampKind::Offset);
        assert_eq!(stamp.original_offset.as_deref(), Some("-0700"));
        assert_eq!(
            stamp.normalized_utc.as_deref(),
            Some("2026-03-12T17:15:22.481293Z")
        );
    }

    #[test]
    fn a_zulu_timestamp_is_reported_as_utc() {
        let stamp = parse_timestamp(ConsoleLayout::TabularEnUs, "2026-03-12 10:15:22Z");
        assert_eq!(stamp.kind, IntuneTimestampKind::Utc);
        assert_eq!(stamp.normalized_utc.as_deref(), Some("2026-03-12T10:15:22Z"));
    }

    #[test]
    fn an_offsetless_timestamp_stays_local_and_is_never_normalized() {
        // The whole reason IntuneTimestamp keeps a kind: assuming UTC here shifts
        // the record by hours and leaves no trace that a guess was made.
        let stamp = parse_timestamp(ConsoleLayout::TabularEnUs, "2026-03-12 10:15:22.481293");
        assert_eq!(stamp.kind, IntuneTimestampKind::Local);
        assert_eq!(stamp.normalized_utc, None);
        assert_eq!(stamp.raw_text, "2026-03-12 10:15:22.481293");
    }

    #[test]
    fn german_day_first_dates_are_not_read_as_month_first() {
        let stamp = parse_timestamp(ConsoleLayout::TabularDeDe, "12.03.2026 10:15:22,481293+0100");
        assert_eq!(
            stamp.normalized_utc.as_deref(),
            Some("2026-03-12T09:15:22.481293Z")
        );
    }

    #[test]
    fn an_impossible_calendar_date_is_invalid_and_keeps_its_raw_text() {
        let stamp = parse_timestamp(ConsoleLayout::TabularEnUs, "2026-02-30 10:15:22-0700");
        assert_eq!(stamp.kind, IntuneTimestampKind::Invalid);
        assert_eq!(stamp.raw_text, "2026-02-30 10:15:22-0700");
    }

    #[test]
    fn an_out_of_range_offset_is_invalid() {
        let stamp = parse_timestamp(ConsoleLayout::TabularEnUs, "2026-03-12 10:15:22+9900");
        assert_eq!(stamp.kind, IntuneTimestampKind::Invalid);
    }

    #[test]
    fn localized_message_type_labels_map_to_apples_vocabulary() {
        assert_eq!(
            parse_message_type(ConsoleLayout::TabularDeDe, "Fehler"),
            Some(ConsoleMessageType::Error)
        );
        assert_eq!(
            parse_message_type(ConsoleLayout::TabularEnUs, "Fault"),
            Some(ConsoleMessageType::Fault)
        );
    }

    #[test]
    fn an_unknown_message_type_round_trips_verbatim() {
        assert_eq!(
            parse_message_type(ConsoleLayout::TabularEnUs, "Notice"),
            Some(ConsoleMessageType::Unknown("Notice".to_owned()))
        );
    }
}
