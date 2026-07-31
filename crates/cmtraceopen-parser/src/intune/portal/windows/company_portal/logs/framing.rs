//! Record framing shared by the `LogEntry` projection and the evidence
//! document, so both agree on exactly where a record starts and ends.
//!
//! # The continuation rule
//!
//! Whether Company Portal ever writes a payload across several lines is not
//! established by any published evidence. `V1` therefore uses the reading that
//! is lossless either way: a line that does not open a record belongs to the
//! record above it.
//!
//! A line that *does* look like a record start but fails validation is not a
//! continuation — it closes the previous record and is reported as a malformed
//! record, so a corrupted header can never be silently absorbed into the
//! message of a healthy record.

use super::grammar::{looks_like_record_start, parse_record_fields, CompanyPortalRecordFields};

/// Why a framed record exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum FramedRecordKind {
    /// The head line validated against the grammar.
    Record(Box<CompanyPortalRecordFields>),
    /// The head line opened a record but failed validation.
    Malformed,
    /// Text that arrived before any record started — a truncated leading
    /// fragment of a rotated file.
    Orphaned,
}

/// One record: a head line plus every line that followed it before the next
/// record started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct FramedRecord<'a> {
    pub kind: FramedRecordKind,
    /// 1-based line number of the head line.
    pub line_number: u32,
    /// The head line with trailing whitespace removed.
    pub head: &'a str,
    /// Continuation lines with trailing whitespace removed; leading
    /// indentation is kept because it is part of a stack trace's meaning.
    pub continuations: Vec<&'a str>,
}

impl FramedRecord<'_> {
    /// The record's original text, head plus continuations.
    pub(super) fn raw_text(&self) -> String {
        join_lines(self.head, &self.continuations)
    }

    /// `true` when the record could not be read as a well-formed record.
    pub(super) fn is_parse_error(&self) -> bool {
        !matches!(self.kind, FramedRecordKind::Record(_))
    }
}

/// Group physical lines into records.
pub(super) fn frame_records<'a>(lines: &[&'a str]) -> Vec<FramedRecord<'a>> {
    let mut records: Vec<FramedRecord<'a>> = Vec::new();

    for (index, line) in lines.iter().enumerate() {
        // Only trailing whitespace is stripped before the record test: a record
        // starts in column 0, so an indented line is a continuation even if it
        // would otherwise look like a header.
        let trimmed = line.trim_end();

        if let Some(fields) = parse_record_fields(trimmed) {
            records.push(FramedRecord {
                kind: FramedRecordKind::Record(Box::new(fields)),
                line_number: (index + 1) as u32,
                head: trimmed,
                continuations: Vec::new(),
            });
            continue;
        }

        if looks_like_record_start(trimmed) {
            records.push(FramedRecord {
                kind: FramedRecordKind::Malformed,
                line_number: (index + 1) as u32,
                head: trimmed,
                continuations: Vec::new(),
            });
            continue;
        }

        if trimmed.is_empty() {
            continue;
        }

        match records.last_mut() {
            Some(pending) => pending.continuations.push(trimmed),
            None => records.push(FramedRecord {
                kind: FramedRecordKind::Orphaned,
                line_number: (index + 1) as u32,
                head: trimmed,
                continuations: Vec::new(),
            }),
        }
    }

    records
}

/// Join a head line with its continuations using `\n`.
pub(super) fn join_lines(head: &str, continuations: &[&str]) -> String {
    if continuations.is_empty() {
        return head.to_string();
    }
    let mut joined = String::with_capacity(
        head.len()
            + continuations
                .iter()
                .map(|line| line.len() + 1)
                .sum::<usize>(),
    );
    joined.push_str(head);
    for line in continuations {
        joined.push('\n');
        joined.push_str(line);
    }
    joined
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEAD: &str = "2024-11-15T16:50:07.2850341Z  INFO  Event  None  0  1487dc30-3bb0-46bf-98ee-76771bd9953e  12-0-0  install failed";

    #[test]
    fn continuation_lines_attach_to_the_record_above() {
        let lines = vec![
            HEAD,
            "System.Net.Http.HttpRequestException: response status 403",
            "   at Microsoft.Management.Services.PortalClient.SendAsync()",
        ];
        let records = frame_records(&lines);

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].continuations.len(), 2);
        assert_eq!(
            records[0].raw_text(),
            format!(
                "{HEAD}\nSystem.Net.Http.HttpRequestException: response status 403\n   at Microsoft.Management.Services.PortalClient.SendAsync()"
            )
        );
    }

    #[test]
    fn a_malformed_head_closes_the_previous_record() {
        let lines = vec![
            HEAD,
            "2024-13-45T99:99:99.0000000Z  INFO  Event  None  0  1487dc30-3bb0-46bf-98ee-76771bd9953e  12-0-0  impossible",
            "   trailing detail",
        ];
        let records = frame_records(&lines);

        assert_eq!(records.len(), 2);
        assert!(!records[0].is_parse_error());
        assert_eq!(records[1].kind, FramedRecordKind::Malformed);
        // The malformed record still gathers its own continuations, so a stack
        // trace under a corrupt header is not scattered across entries.
        assert_eq!(records[1].continuations, vec!["   trailing detail"]);
    }

    #[test]
    fn text_before_any_record_is_orphaned_not_dropped() {
        let lines = vec!["ry all instances of CCM_Application)", HEAD];
        let records = frame_records(&lines);

        assert_eq!(records.len(), 2);
        assert_eq!(records[0].kind, FramedRecordKind::Orphaned);
        assert_eq!(records[0].head, "ry all instances of CCM_Application)");
        assert_eq!(records[0].line_number, 1);
        assert_eq!(records[1].line_number, 2);
    }

    #[test]
    fn blank_lines_do_not_open_records() {
        let lines = vec!["", HEAD, "   ", ""];
        let records = frame_records(&lines);

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].line_number, 2);
        assert!(records[0].continuations.is_empty());
    }
}
