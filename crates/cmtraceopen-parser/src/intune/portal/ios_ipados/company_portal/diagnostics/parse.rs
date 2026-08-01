//! Record framing for one Console export.
//!
//! Console's plain-text copy is line-oriented but not line-per-record: a message
//! containing an exception, a stack, or a JSON payload spans as many lines as it
//! needs, and only the first of them carries a timestamp. Framing therefore
//! works forward from record starts, and every line that is not one belongs to
//! the record above it.
//!
//! Two failure shapes get explicit treatment rather than being folded into the
//! previous message:
//!
//! * a row whose leading field is date-shaped but unparsable is a *malformed
//!   record*, not continuation text. Treating it as continuation is how a
//!   corrupt capture comes to look clean;
//! * continuation text arriving before any record has started is a *leading
//!   fragment*: the operator's selection began mid-record. It is kept, flagged,
//!   and never attributed to a process it cannot be shown to belong to.

use super::classify::{classify_semantic, classify_source};
use super::layout::{
    looks_like_record_start, parse_message_type, parse_timestamp, split_fields, ResolvedLayout,
};
use super::models::{
    ConsoleColumn, ConsoleLayout, ConsoleRecord, ConsoleRecordDefect, ConsoleSourceClass,
};
use super::redaction::classify_sensitivity;
use crate::intune::evidence::{
    IntuneAccessState, IntuneEvidenceRef, IntuneNamedValue, IntuneObservationContext,
    IntuneParseState, IntuneProvenance, IntuneSourceKind, IntuneTimestamp, IntuneTimestampKind,
};

/// Everything framing needs that is not in the text itself.
#[derive(Debug, Clone)]
pub(super) struct ParseContext<'a> {
    pub artifact_id: &'a str,
    pub file_path: Option<&'a str>,
    pub observed_at_utc: &'a str,
    pub access_state: IntuneAccessState,
    pub max_records: usize,
}

/// The framed result for one export.
#[derive(Debug, Clone, Default)]
pub(super) struct ParseOutcome {
    pub records: Vec<ConsoleRecord>,
    pub truncated_leading_fragment: bool,
    pub truncated_trailing_record: bool,
    pub record_cap_reached: bool,
}

/// A record under construction.
struct PendingRecord {
    line_number: u64,
    fields: Vec<String>,
    continuation: Vec<String>,
    defects: Vec<ConsoleRecordDefect>,
    /// A leading fragment has no columns at all, only text.
    fragment: bool,
}

/// Frame every record in `text` under an already-resolved layout.
pub(super) fn parse_export(
    text: &str,
    resolved: &ResolvedLayout,
    context: &ParseContext<'_>,
) -> ParseOutcome {
    let mut outcome = ParseOutcome::default();
    if resolved.layout == ConsoleLayout::Unresolved {
        return outcome;
    }

    let lines: Vec<&str> = text.lines().collect();
    let mut pending: Option<PendingRecord> = None;
    let mut record_number: u64 = 0;

    for (index, raw_line) in lines.iter().enumerate().skip(resolved.body_start_index) {
        let line = raw_line.trim_end_matches('\r');
        // Blank lines separate nothing and belong to nothing. Folding them into
        // the message above would make two captures of the same session differ
        // only in whitespace.
        if line.trim().is_empty() {
            continue;
        }

        let fields = split_fields(line);
        let leading = fields.first().copied().unwrap_or_default();

        if looks_like_record_start(leading) {
            if let Some(finished) = pending.take() {
                push_record(&mut outcome, &mut record_number, finished, resolved, context);
            }
            if outcome.records.len() >= context.max_records {
                outcome.record_cap_reached = true;
                return outcome;
            }

            let mut defects = Vec::new();
            if fields.len() < resolved.columns.len() {
                defects.push(ConsoleRecordDefect::MissingColumns);
            }
            if parse_timestamp(resolved.layout, leading).kind == IntuneTimestampKind::Invalid {
                defects.push(ConsoleRecordDefect::UnparsableTimestamp);
            }

            pending = Some(PendingRecord {
                line_number: line_number(index),
                fields: fields.iter().map(|field| (*field).to_owned()).collect(),
                continuation: Vec::new(),
                defects,
                fragment: false,
            });
            continue;
        }

        match pending.as_mut() {
            Some(open) => open.continuation.push(line.to_owned()),
            None => {
                outcome.truncated_leading_fragment = true;
                pending = Some(PendingRecord {
                    line_number: line_number(index),
                    fields: Vec::new(),
                    continuation: vec![line.to_owned()],
                    defects: vec![ConsoleRecordDefect::OrphanedContinuation],
                    fragment: true,
                });
            }
        }
    }

    if let Some(finished) = pending.take() {
        if outcome.records.len() >= context.max_records {
            outcome.record_cap_reached = true;
            return outcome;
        }
        push_record(&mut outcome, &mut record_number, finished, resolved, context);
    }

    // A capture that does not end with a newline ended mid-line: the operator's
    // selection stopped inside the final record, whose message is incomplete.
    if !text.is_empty() && !text.ends_with('\n') {
        outcome.truncated_trailing_record = true;
        if let Some(last) = outcome.records.last_mut() {
            last.truncated = true;
        }
    }

    outcome
}

fn line_number(index: usize) -> u64 {
    u64::try_from(index).unwrap_or(u64::MAX).saturating_add(1)
}

fn push_record(
    outcome: &mut ParseOutcome,
    record_number: &mut u64,
    pending: PendingRecord,
    resolved: &ResolvedLayout,
    context: &ParseContext<'_>,
) {
    *record_number += 1;
    outcome
        .records
        .push(build_record(pending, resolved, context, *record_number));
}

/// Value of one declared column, trimmed, with empties reported as absent.
fn column_value(fields: &[String], resolved: &ResolvedLayout, column: ConsoleColumn) -> Option<String> {
    let index = resolved.index_of(&column)?;
    let value = fields.get(index)?.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_owned())
    }
}

/// The message column, rejoined when it is the final column.
///
/// A message legitimately contains tabs, and Console does not escape them, so
/// everything from the message column onward is the message whenever the message
/// is last. When the operator has moved the column, only its own field is taken:
/// swallowing the columns to its right would fabricate message text.
fn message_value(fields: &[String], resolved: &ResolvedLayout) -> String {
    let Some(index) = resolved.index_of(&ConsoleColumn::Message) else {
        return String::new();
    };
    if index + 1 == resolved.columns.len() {
        fields
            .get(index..)
            .map(|rest| rest.join("\t"))
            .unwrap_or_default()
    } else {
        fields.get(index).cloned().unwrap_or_default()
    }
}

/// Columns the export declared that this build does not model.
fn unmodeled_columns(fields: &[String], resolved: &ResolvedLayout) -> Vec<IntuneNamedValue> {
    resolved
        .columns
        .iter()
        .enumerate()
        .filter_map(|(index, column)| {
            let ConsoleColumn::Unknown(label) = column else {
                return None;
            };
            let value = fields.get(index)?.trim();
            if value.is_empty() {
                return None;
            }
            Some(IntuneNamedValue {
                name: label.clone(),
                value: value.to_owned(),
            })
        })
        .collect()
}

/// Console writes `0` or `0x0` for "no activity"; both mean absent.
fn activity_value(raw: Option<String>) -> Option<String> {
    raw.filter(|value| !matches!(value.as_str(), "0" | "0x0" | "0X0"))
}

fn build_record(
    pending: PendingRecord,
    resolved: &ResolvedLayout,
    context: &ParseContext<'_>,
    record_number: u64,
) -> ConsoleRecord {
    let PendingRecord {
        line_number,
        fields,
        continuation,
        defects,
        fragment,
    } = pending;

    let mut message = if fragment {
        String::new()
    } else {
        message_value(&fields, resolved)
    };
    let mut message_line_count = 1u32;
    for line in &continuation {
        if !message.is_empty() || !fragment {
            message.push('\n');
        }
        message.push_str(line);
        message_line_count = message_line_count.saturating_add(1);
    }
    if fragment {
        // The fragment's own "record line" is the first continuation line, so it
        // was already counted once.
        message_line_count = message_line_count.saturating_sub(1).max(1);
    }

    // A fragment carries no timestamp at all. `Unspecified` records that fact
    // without claiming the record has no time, which `None` would imply.
    let source_timestamp = if fragment {
        IntuneTimestamp {
            raw_text: String::new(),
            original_offset: None,
            normalized_utc: None,
            kind: IntuneTimestampKind::Unspecified,
        }
    } else {
        parse_timestamp(
            resolved.layout,
            fields.first().map(String::as_str).unwrap_or_default(),
        )
    };

    let process = column_value(&fields, resolved, ConsoleColumn::Process);
    let subsystem = column_value(&fields, resolved, ConsoleColumn::Subsystem);
    let category = column_value(&fields, resolved, ConsoleColumn::Category);

    let (source_class, source_signals) = if fragment {
        (ConsoleSourceClass::Indeterminate, Vec::new())
    } else {
        classify_source(process.as_deref(), subsystem.as_deref())
    };

    let (semantic, semantic_source) = if source_class == ConsoleSourceClass::CompanyPortal {
        match classify_semantic(category.as_deref(), &message) {
            Some((kind, source)) => (Some(kind), Some(source)),
            None => (None, None),
        }
    } else {
        (None, None)
    };

    let parse_state = if defects.contains(&ConsoleRecordDefect::MissingColumns)
        || defects.contains(&ConsoleRecordDefect::UnparsableTimestamp)
    {
        IntuneParseState::Malformed
    } else if fragment {
        // Framed and preserved, but not understood as a record: `Raw` is exactly
        // that state, and it keeps the fragment out of the malformed count.
        IntuneParseState::Raw
    } else {
        IntuneParseState::Parsed
    };

    ConsoleRecord {
        context: IntuneObservationContext {
            evidence_ref: IntuneEvidenceRef {
                evidence_id: format!("{}:r{record_number}", context.artifact_id),
                source_artifact_id: context.artifact_id.to_owned(),
            },
            provenance: IntuneProvenance {
                source_kind: IntuneSourceKind::PlainTextLog,
                source_artifact_id: context.artifact_id.to_owned(),
                file_path: context.file_path.map(str::to_owned),
                line_number: Some(line_number),
                record_number: Some(record_number),
                registry: None,
                event: None,
            },
            source_timestamp: Some(source_timestamp),
            observed_at_utc: context.observed_at_utc.to_owned(),
            sensitivity: classify_sensitivity(&message),
            parse_state,
            access_state: context.access_state.clone(),
        },
        layout: resolved.layout,
        message_type: column_value(&fields, resolved, ConsoleColumn::MessageType)
            .and_then(|raw| parse_message_type(resolved.layout, &raw)),
        process,
        process_id: column_value(&fields, resolved, ConsoleColumn::ProcessId)
            .and_then(|raw| parse_process_id(&raw)),
        thread_id: column_value(&fields, resolved, ConsoleColumn::ThreadId),
        activity_id: activity_value(column_value(&fields, resolved, ConsoleColumn::Activity)),
        subsystem,
        category,
        message,
        message_line_count,
        source_class,
        source_signals,
        semantic,
        semantic_source,
        defects,
        truncated: false,
        unmodeled_columns: unmodeled_columns(&fields, resolved),
    }
}

/// `418` or `[418]` or `418:0x1f4a`, all of which Console has written.
fn parse_process_id(raw: &str) -> Option<u32> {
    let digits: String = raw
        .trim_matches(|c: char| !c.is_ascii_digit())
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    digits.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::layout::resolve_layout;

    const HEADER: &str =
        "Timestamp\tType\tProcess\tPID\tTID\tActivity\tSubsystem\tCategory\tMessage";

    fn context() -> ParseContext<'static> {
        ParseContext {
            artifact_id: "console",
            file_path: None,
            observed_at_utc: "2026-07-31T00:00:00Z",
            access_state: IntuneAccessState::Available,
            max_records: 1_000,
        }
    }

    fn parse(text: &str) -> ParseOutcome {
        let lines: Vec<&str> = text.lines().collect();
        let resolved = resolve_layout(&lines);
        parse_export(text, &resolved, &context())
    }

    fn record_row(seconds: &str, process: &str, message: &str) -> String {
        format!(
            "2026-03-12 10:15:{seconds}.100000-0700\tDefault\t{process}\t418\t0x1f4a\t0\tcom.microsoft.CompanyPortal\tGeneral\t{message}"
        )
    }

    #[test]
    fn a_single_record_is_framed_with_its_line_and_record_numbers() {
        let text = format!("{HEADER}\n{}\n", record_row("22", "CompanyPortal", "hello"));
        let outcome = parse(&text);
        assert_eq!(outcome.records.len(), 1);
        let record = &outcome.records[0];
        assert_eq!(record.context.provenance.line_number, Some(2));
        assert_eq!(record.context.provenance.record_number, Some(1));
        assert_eq!(record.message, "hello");
        assert_eq!(record.process.as_deref(), Some("CompanyPortal"));
        assert_eq!(record.process_id, Some(418));
        assert_eq!(record.activity_id, None);
        assert_eq!(record.source_class, ConsoleSourceClass::CompanyPortal);
    }

    #[test]
    fn continuation_lines_join_the_record_above_them() {
        let text = format!(
            "{HEADER}\n{}\n    at Frame 1\n    at Frame 2\n",
            record_row("22", "CompanyPortal", "Unhandled exception")
        );
        let outcome = parse(&text);
        assert_eq!(outcome.records.len(), 1);
        assert_eq!(
            outcome.records[0].message,
            "Unhandled exception\n    at Frame 1\n    at Frame 2"
        );
        assert_eq!(outcome.records[0].message_line_count, 3);
    }

    #[test]
    fn a_tab_inside_the_message_does_not_split_it() {
        let text = format!(
            "{HEADER}\n{}\n",
            record_row("22", "CompanyPortal", "key\tvalue")
        );
        let outcome = parse(&text);
        assert_eq!(outcome.records[0].message, "key\tvalue");
    }

    #[test]
    fn a_row_with_a_broken_timestamp_is_malformed_not_continuation() {
        let broken =
            "2026-13-45 99:99:99-0700\tDefault\tCompanyPortal\t418\t0x1\t0\tsub\tcat\tbroken";
        let text = format!("{HEADER}\n{}\n{broken}\n", record_row("22", "CompanyPortal", "ok"));
        let outcome = parse(&text);
        assert_eq!(outcome.records.len(), 2);
        assert!(outcome.records[1]
            .defects
            .contains(&ConsoleRecordDefect::UnparsableTimestamp));
        assert_eq!(
            outcome.records[1].context.parse_state,
            IntuneParseState::Malformed
        );
        assert_eq!(
            outcome.records[1]
                .context
                .source_timestamp
                .as_ref()
                .map(|stamp| stamp.kind.clone()),
            Some(IntuneTimestampKind::Invalid)
        );
    }

    #[test]
    fn a_short_row_is_malformed_and_keeps_what_it_had() {
        let short = "2026-03-12 10:15:24.100000-0700\tError\tCompanyPortal";
        let text = format!("{HEADER}\n{}\n{short}\n", record_row("22", "CompanyPortal", "ok"));
        let outcome = parse(&text);
        assert_eq!(outcome.records.len(), 2);
        assert!(outcome.records[1]
            .defects
            .contains(&ConsoleRecordDefect::MissingColumns));
        assert_eq!(outcome.records[1].process.as_deref(), Some("CompanyPortal"));
    }

    #[test]
    fn text_before_the_first_record_is_a_leading_fragment() {
        let text = format!(
            "{HEADER}\n    trailing half of an earlier message\n{}\n",
            record_row("22", "CompanyPortal", "ok")
        );
        let outcome = parse(&text);
        assert!(outcome.truncated_leading_fragment);
        assert_eq!(outcome.records.len(), 2);
        let fragment = &outcome.records[0];
        assert_eq!(fragment.source_class, ConsoleSourceClass::Indeterminate);
        assert_eq!(fragment.context.parse_state, IntuneParseState::Raw);
        assert_eq!(fragment.message, "    trailing half of an earlier message");
    }

    #[test]
    fn a_capture_ending_mid_line_flags_its_last_record() {
        let text = format!("{HEADER}\n{}", record_row("22", "CompanyPortal", "cut off"));
        let outcome = parse(&text);
        assert!(outcome.truncated_trailing_record);
        assert!(outcome.records.last().expect("a record").truncated);
    }

    #[test]
    fn a_complete_capture_is_not_reported_as_truncated() {
        let text = format!("{HEADER}\n{}\n", record_row("22", "CompanyPortal", "complete"));
        let outcome = parse(&text);
        assert!(!outcome.truncated_trailing_record);
        assert!(!outcome.truncated_leading_fragment);
    }

    #[test]
    fn framing_stops_at_the_record_cap_and_says_so() {
        let mut text = String::from(HEADER);
        for index in 0..10 {
            text.push('\n');
            text.push_str(&record_row(&format!("{:02}", 20 + index), "CompanyPortal", "x"));
        }
        text.push('\n');
        let lines: Vec<&str> = text.lines().collect();
        let resolved = resolve_layout(&lines);
        let mut context = context();
        context.max_records = 3;
        let outcome = parse_export(&text, &resolved, &context);
        assert_eq!(outcome.records.len(), 3);
        assert!(outcome.record_cap_reached);
    }

    #[test]
    fn unrelated_processes_are_framed_but_not_claimed() {
        let text = format!(
            "{HEADER}\n2026-03-12 10:15:22.100000-0700\tDefault\tSpringBoard\t60\t0x2\t0\tcom.apple.springboard\tDefault\tmentions Intune in passing\n"
        );
        let outcome = parse(&text);
        assert_eq!(outcome.records.len(), 1);
        assert_eq!(outcome.records[0].source_class, ConsoleSourceClass::Unrelated);
        assert!(outcome.records[0].semantic.is_none());
    }

    #[test]
    fn an_unmodeled_column_is_carried_rather_than_dropped() {
        let header = "Timestamp\tProcess\tBacktrace\tMessage";
        let text = format!(
            "{header}\n2026-03-12 10:15:22-0700\tCompanyPortal\t0x104ab\thello\n"
        );
        let outcome = parse(&text);
        assert_eq!(
            outcome.records[0].unmodeled_columns,
            vec![IntuneNamedValue {
                name: "Backtrace".to_owned(),
                value: "0x104ab".to_owned()
            }]
        );
    }

    #[test]
    fn an_unresolved_layout_frames_nothing() {
        let outcome = parse("just some prose\nand more prose\n");
        assert!(outcome.records.is_empty());
    }
}
