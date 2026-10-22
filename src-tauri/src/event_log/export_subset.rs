//! EVTX subset export (spec 8.17, Phase 18b).
//!
//! `evtx_export_subset` copies a chosen set of events, by `EventRecordID`, out of live channels and
//! `.evtx` files into new `.evtx` files with `EvtExportLog`, then calls `EvtArchiveExportedLog` so
//! the localized messages travel with each file. The files are raw copies: the shared redaction
//! module cannot apply, which is why the UI puts an explicit confirmation in front of this command.
//!
//! The Windows-only part is deliberately tiny (`windows_backend`): two API calls behind the
//! `SubsetBackend` trait. Everything that can be decided without the Event Log service (request
//! validation, file naming, range coalescing, query building, the existing-file policy, per-source
//! failure isolation, result assembly) lives in `engine`, which compiles and is tested on every
//! platform.
//!
//! Output policy:
//! - One output file per source log, named `{label}-subset.evtx` inside the chosen folder. The
//!   label is sanitized so a channel path or file name can never leave that folder.
//!   Spec 8.17 writes `{source-label}`; for an `.evtx` source this is read as the file stem (not
//!   the path), and two sources that sanitize to the same name are numbered in request order
//!   (`{label}-2-subset.evtx`). Both readings are deliberate and are recorded in the PR.
//! - Nothing is overwritten. The whole request is refused before any API call if a target name is
//!   already taken, and `EvtExportLogOverwrite` is never passed, so the service refuses too. A
//!   file whose name already has an entry in `LocaleMetaData` is exported but not archived, with
//!   its own warning, because `EvtArchiveExportedLog` would overwrite that entry.
//!   The request is also refused as a whole when the output folder is unusable, when no source is
//!   given, or when one source is listed twice: those are problems with the request itself.
//! - A problem with one source (a file that disappeared, a selection too fragmented to express,
//!   Security without elevation, a channel that no longer exists) does not abort the others. That
//!   source reports `Failed` with its reason, in request order, and the rest are exported.
//! - Every exported file is read back and compared with the request by EventRecordID, Computer
//!   and source Channel (the event's own `System/Channel`): events that were requested but are
//!   missing, and events that are present but were not requested, are reported separately. A bare
//!   count would hide a file that holds the wrong events. When the verification cannot run, the
//!   difference is `None` (unknown), never zero.
//! - An event is identified by that same triple everywhere: the planner groups by it, the query
//!   names it and the read-back compares by it (`EventOrigin`).

use serde::{Deserialize, Serialize};

/// What an exported source is: a registered channel, or an `.evtx` file on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EvtxSubsetSourceKind {
    Channel,
    File,
}

/// The events of one source that share a computer and a source channel.
///
/// `EventRecordID` is only unique per log on the machine that wrote it. A log that collects events
/// (ForwardedEvents) can hold the same ID from two machines, and from two logs of one machine, so
/// an event is identified by its computer, its source channel and its ID together. The same
/// identity decides how the planner groups, what the query names and how the file is read back.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvtxSubsetRecordGroup {
    /// `System/Computer` of these events. `None` when the events carry none, in which case the
    /// query does not name a computer and the group selects any machine's events.
    #[serde(default)]
    pub computer: Option<String>,
    /// The events' own `System/Channel`: the log they were written to, which for a collector such
    /// as ForwardedEvents is not the log being exported from. `None` when they carry none, in which
    /// case the query does not name a channel and the group selects events of any channel.
    #[serde(default)]
    pub channel: Option<String>,
    /// `EventRecordID`s as decimal strings, so a value outside JavaScript's safe-integer range is
    /// never rounded on its way here. The frontend sends the lossless text field.
    pub record_ids: Vec<String>,
}

/// One source log and the events to keep from it.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvtxSubsetSource {
    pub kind: EvtxSubsetSourceKind,
    /// The channel name (`Microsoft-Windows-AAD/Operational`) or the absolute `.evtx` path.
    pub path: String,
    pub record_groups: Vec<EvtxSubsetRecordGroup>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum EvtxSubsetFileStatus {
    Exported,
    Failed,
}

/// Events on one side of the comparison between the request and the written file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvtxSubsetIdDifference {
    pub count: u64,
    /// The first few, as `EventRecordID 101 on HOST-A in System` (the machine and the log only
    /// when the event names them), so the operator can find them. Capped; `count` is the whole.
    pub sample: Vec<String>,
}

/// What happened to one source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvtxSubsetFileResult {
    pub kind: EvtxSubsetSourceKind,
    pub source_path: String,
    pub file_name: String,
    pub output_path: String,
    /// Distinct events (computer, source channel and `EventRecordID`) that were asked for.
    pub requested_records: u64,
    pub status: EvtxSubsetFileStatus,
    /// Records found in the written file by reading it back. `None` is "could not be verified",
    /// never zero: a file that was written but could not be read back still exists.
    pub exported_records: Option<u64>,
    /// Requested events the file does not hold. `None` when the file could not be read back.
    pub missing: Option<EvtxSubsetIdDifference>,
    /// Events the file holds that were not requested. `None` when the file could not be read back.
    pub unrequested: Option<EvtxSubsetIdDifference>,
    /// True only when `EvtArchiveExportedLog` succeeded, so the file renders without the provider.
    pub messages_archived: bool,
    pub error: Option<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvtxSubsetResult {
    pub folder: String,
    pub files: Vec<EvtxSubsetFileResult>,
}

#[cfg(not(target_os = "windows"))]
const UNSUPPORTED_MESSAGE: &str = "EVTX subset export is only available on Windows.";

#[tauri::command]
pub async fn evtx_export_subset(
    folder: String,
    sources: Vec<EvtxSubsetSource>,
) -> Result<EvtxSubsetResult, String> {
    // EvtExportLog is synchronous and can take a long time on a large log, so it must not run on
    // the async runtime's worker threads.
    tokio::task::spawn_blocking(move || export_subset(&folder, &sources))
        .await
        .map_err(|error| format!("Task join error: {error}"))?
}

#[cfg(target_os = "windows")]
pub fn export_subset(
    folder: &str,
    sources: &[EvtxSubsetSource],
) -> Result<EvtxSubsetResult, String> {
    let plan = engine::plan_subset_export(folder, sources)?;
    log::info!("event=evtx_export_subset sources={}", plan.entries.len());
    Ok(engine::run_plan(&plan, &windows_backend::WindowsBackend))
}

#[cfg(not(target_os = "windows"))]
pub fn export_subset(
    _folder: &str,
    _sources: &[EvtxSubsetSource],
) -> Result<EvtxSubsetResult, String> {
    Err(UNSUPPORTED_MESSAGE.to_string())
}

#[cfg(any(target_os = "windows", test))]
mod engine {
    use std::collections::HashSet;
    use std::fs;
    use std::path::{Path, PathBuf};

    use super::super::event_node::{extract_system_fields, parse_event_xml};
    use super::super::models::MAX_SAFE_EVENT_RECORD_ID;
    use super::{
        EvtxSubsetFileResult, EvtxSubsetFileStatus, EvtxSubsetIdDifference, EvtxSubsetResult,
        EvtxSubsetSource, EvtxSubsetSourceKind,
    };

    /// Spec 8.17: XPath is limited to about 20 expressions, so a query that needs more becomes a
    /// structured XML query. Counted as comparisons: one per single ID, two per range.
    pub(super) const XPATH_EXPRESSION_LIMIT: usize = 20;
    /// A ceiling on the disjoint ranges one source may need. A filtered view of a large log can
    /// fragment into thousands of ranges; the query text grows with them and the service's limit
    /// on a structured query is not documented, so the request is refused with a message rather
    /// than sent. Unverified: tune on the Windows lab.
    pub(super) const MAX_RANGES_PER_SOURCE: usize = 10_000;
    pub(super) const LABEL_MAX_CHARS: usize = 100;
    /// The folder `EvtArchiveExportedLog` fills with the localized strings, next to the export.
    pub(super) const LOCALE_METADATA_DIR: &str = "LocaleMetaData";
    const FALLBACK_LABEL: &str = "events";

    // ---- record IDs -------------------------------------------------------------------------

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) struct RecordIdRange {
        pub(super) start: u64,
        pub(super) end: u64,
    }

    /// Parses decimal `EventRecordID` text. Strict on purpose: a sign, a space, a hex prefix or a
    /// fraction is a malformed request, not something to guess at.
    pub(super) fn parse_record_ids(source: &str, ids: &[String]) -> Result<Vec<u64>, String> {
        if ids.is_empty() {
            return Err(format!("{source}: no record IDs were given"));
        }
        let mut parsed = Vec::with_capacity(ids.len());
        for text in ids {
            if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(format!("{source}: {text:?} is not a decimal EventRecordID"));
            }
            let id: u64 = text
                .parse()
                .map_err(|_| format!("{source}: EventRecordID {text} does not fit in 64 bits"))?;
            // Zero is the "no EventRecordID" default, not an identity; the service never writes it.
            if id == 0 {
                return Err(format!(
                    "{source}: EventRecordID 0 is not an identity (the event carried none)"
                ));
            }
            // XPath numbers are IEEE doubles, so above 2^53 - 1 the service compares a rounded
            // value and could export the wrong event. Refuse rather than export a different set.
            if id > MAX_SAFE_EVENT_RECORD_ID {
                return Err(format!(
                    "{source}: EventRecordID {id} is above {MAX_SAFE_EVENT_RECORD_ID}, which the \
                     Event Log query language cannot match exactly"
                ));
            }
            parsed.push(id);
        }
        Ok(parsed)
    }

    /// Sorts, removes duplicates and merges adjacent IDs into inclusive ranges.
    pub(super) fn coalesce_record_ids(ids: &[u64]) -> Vec<RecordIdRange> {
        let mut sorted = ids.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        let mut ranges: Vec<RecordIdRange> = Vec::new();
        for id in sorted {
            match ranges.last_mut() {
                // `checked_add` so a range ending at u64::MAX cannot wrap into a false merge.
                Some(last) if last.end.checked_add(1) == Some(id) => last.end = id,
                _ => ranges.push(RecordIdRange { start: id, end: id }),
            }
        }
        ranges
    }

    pub(super) fn distinct_record_count(ranges: &[RecordIdRange]) -> u64 {
        ranges.iter().map(|range| range.end - range.start + 1).sum()
    }

    /// Where an event was logged, the two parts of its identity beside the `EventRecordID`.
    ///
    /// One definition serves the three places that must agree on what "the same event" means: the
    /// planner's groups, the names the query carries and the comparison with the written file. A
    /// part that is `None` is not named: in a group the query leaves it out and the group selects
    /// any value, in a record it is an event whose XML carried none.
    #[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
    pub(super) struct EventOrigin {
        pub(super) computer: Option<String>,
        pub(super) channel: Option<String>,
    }

    impl EventOrigin {
        /// True when a group with this origin selects an event logged at `found`: every part the
        /// group names must be the event's, exactly as written.
        fn selects(&self, found: &EventOrigin) -> bool {
            let part_selects = |wanted: &Option<String>, actual: &Option<String>| {
                wanted.is_none() || wanted == actual
            };
            part_selects(&self.computer, &found.computer)
                && part_selects(&self.channel, &found.channel)
        }

        /// True when one event could be selected by both groups, so the file could not say which
        /// of the two it was requested for.
        fn overlaps(&self, other: &EventOrigin) -> bool {
            let parts_overlap =
                |a: &Option<String>, b: &Option<String>| a.is_none() || b.is_none() || a == b;
            parts_overlap(&self.computer, &other.computer)
                && parts_overlap(&self.channel, &other.channel)
        }

        /// `EventRecordID 101 on HOST-A in System`: the machine and the log only when named.
        pub(super) fn describe(&self, id: u64) -> String {
            let mut text = format!("EventRecordID {id}");
            if let Some(computer) = &self.computer {
                text.push_str(&format!(" on {computer}"));
            }
            if let Some(channel) = &self.channel {
                text.push_str(&format!(" in {channel}"));
            }
            text
        }
    }

    /// The events of one origin, as ranges: the unit a query is built from and the unit the
    /// written file is compared against.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(super) struct EventGroup {
        pub(super) origin: EventOrigin,
        pub(super) ranges: Vec<RecordIdRange>,
    }

    impl EventGroup {
        fn distinct_records(&self) -> u64 {
            distinct_record_count(&self.ranges)
        }

        fn contains(&self, found: &EventOrigin, id: u64) -> bool {
            self.origin.selects(found)
                && self
                    .ranges
                    .binary_search_by(|range| {
                        if id < range.start {
                            std::cmp::Ordering::Greater
                        } else if id > range.end {
                            std::cmp::Ordering::Less
                        } else {
                            std::cmp::Ordering::Equal
                        }
                    })
                    .is_ok()
        }
    }

    // ---- query building ---------------------------------------------------------------------

    /// The text passed as `EvtExportLog`'s `Query`.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(super) struct SubsetQuery {
        pub(super) text: String,
        /// True for a `<QueryList>` document, false for a bare XPath.
        pub(super) structured: bool,
    }

    fn range_cost(range: &RecordIdRange) -> usize {
        if range.start == range.end {
            1
        } else {
            2
        }
    }

    fn range_term(range: &RecordIdRange) -> String {
        if range.start == range.end {
            format!("EventRecordID={}", range.start)
        } else {
            format!(
                "(EventRecordID>={} and EventRecordID<={})",
                range.start, range.end
            )
        }
    }

    /// A computer name as an XPath string literal, or `None` when no quoting can hold it. XPath 1.0
    /// has no escape inside a literal, so a name holding both quote characters cannot be written.
    fn xpath_literal(name: &str) -> Option<String> {
        if name.chars().any(char::is_control) {
            return None;
        }
        match (name.contains('\''), name.contains('"')) {
            (false, _) => Some(format!("'{name}'")),
            (true, false) => Some(format!("\"{name}\"")),
            (true, true) => None,
        }
    }

    /// Whether a group's channel is named in the query. The log being queried holds only events of
    /// its own channel, so naming it adds nothing there (Windows compares channel names without
    /// regard to case). Any other channel means the log collects events, and the term is what keeps
    /// one source log's event from selecting another's. A file has no log name of its own, so it
    /// always names the channel.
    ///
    /// Assumes a collector log never holds events that name the collector as their channel; lab
    /// item (g) is where that is confirmed.
    fn names_channel_in_query(kind: EvtxSubsetSourceKind, path: &str, channel: &str) -> bool {
        match kind {
            EvtxSubsetSourceKind::Channel => !channel.eq_ignore_ascii_case(path),
            EvtxSubsetSourceKind::File => true,
        }
    }

    /// The XPath literals a group's query names beside its record ids. Each one is a comparison
    /// that counts toward the limit in every `<Select>` that carries it.
    struct GroupTerms {
        computer: Option<String>,
        channel: Option<String>,
    }

    impl GroupTerms {
        fn cost(&self) -> usize {
            usize::from(self.computer.is_some()) + usize::from(self.channel.is_some())
        }
    }

    fn group_terms(
        kind: EvtxSubsetSourceKind,
        path: &str,
        origin: &EventOrigin,
    ) -> Result<GroupTerms, String> {
        let literal = |what: &str, name: &str| {
            xpath_literal(name).ok_or_else(|| {
                format!("{path}: the {what} name {name:?} cannot be written in a query")
            })
        };
        Ok(GroupTerms {
            computer: origin
                .computer
                .as_deref()
                .map(|name| literal("computer", name))
                .transpose()?,
            channel: origin
                .channel
                .as_deref()
                .filter(|name| names_channel_in_query(kind, path, name))
                .map(|name| literal("channel", name))
                .transpose()?,
        })
    }

    /// The predicate for one origin's ranges. With a computer and a channel it is
    /// `Computer='X' and Channel='Y' and (EventRecordID=1 or ...)`, so another machine's event, or
    /// another log's, that happens to carry the same EventRecordID is never selected.
    ///
    /// Decision (routed at verification 1; kept by Main pending the maintainer's sign-off,
    /// conditioned on lab item (a)): the computer is named whenever it is known, not only when one
    /// source's visible events span several machines. A view filtered to one machine over a log
    /// that also holds another's (ForwardedEvents) would otherwise still select, and write
    /// unredacted, the other machine's event with the same EventRecordID; the read-back would
    /// report it only after the write. The price is that the Computer term is a dependency of every
    /// export. It is unverified against the service and covered by the Windows lab tests:
    /// `Computer='X'` and `Computer="X"` inside `System[...]`, for a channel and for a file.
    /// Under-matching shows as missing events and over-matching as unrequested ones, never
    /// silently. The Channel term follows the same rule (see `names_channel_in_query`) and adds
    /// lab items (g) and (h).
    fn unit_predicate(terms: &GroupTerms, ranges: &[RecordIdRange]) -> String {
        let ids: Vec<String> = ranges.iter().map(range_term).collect();
        let mut conditions: Vec<String> = Vec::new();
        if let Some(literal) = &terms.computer {
            conditions.push(format!("Computer={literal}"));
        }
        if let Some(literal) = &terms.channel {
            conditions.push(format!("Channel={literal}"));
        }
        if conditions.is_empty() {
            return ids.join(" or ");
        }
        let prefix = conditions.join(" and ");
        // One term needs no further parentheses: a range already has its own.
        match ids.as_slice() {
            [only] => format!("{prefix} and {only}"),
            many => format!("{prefix} and ({})", many.join(" or ")),
        }
    }

    fn xpath_of(units: &[String]) -> String {
        match units {
            [only] => format!("*[System[{only}]]"),
            many => {
                let joined: Vec<String> = many.iter().map(|unit| format!("({unit})")).collect();
                format!("*[System[{}]]", joined.join(" or "))
            }
        }
    }

    fn escape_xml(text: &str, attribute: bool) -> String {
        let mut out = String::with_capacity(text.len());
        for ch in text.chars() {
            match ch {
                '&' => out.push_str("&amp;"),
                '<' => out.push_str("&lt;"),
                '>' => out.push_str("&gt;"),
                '"' if attribute => out.push_str("&quot;"),
                '\'' if attribute => out.push_str("&apos;"),
                other => out.push(other),
            }
        }
        out
    }

    /// The `Path` of a structured query's `<Select>`. Unverified for files: a log file is written
    /// as a `file://` URI in structured queries; confirm on the Windows lab (report item).
    fn select_path(kind: EvtxSubsetSourceKind, path: &str) -> String {
        match kind {
            EvtxSubsetSourceKind::Channel => path.to_string(),
            EvtxSubsetSourceKind::File => format!("file://{path}"),
        }
    }

    /// Builds the query that keeps exactly the events in `groups`.
    ///
    /// Up to [`XPATH_EXPRESSION_LIMIT`] comparisons it is one XPath. Beyond that it is a structured
    /// XML query with several `<Select>` elements on the same path, each holding at most that many
    /// comparisons (a single `<Select>` XPath is itself limited), which the service unions. A
    /// group's computer and channel names each cost one comparison in every `<Select>` that carries
    /// them.
    pub(super) fn build_subset_query(
        kind: EvtxSubsetSourceKind,
        path: &str,
        groups: &[EventGroup],
    ) -> Result<SubsetQuery, String> {
        if groups.is_empty() || groups.iter().any(|group| group.ranges.is_empty()) {
            return Err(format!("{path}: no record ranges to export"));
        }
        let total_ranges: usize = groups.iter().map(|group| group.ranges.len()).sum();
        if total_ranges > MAX_RANGES_PER_SOURCE {
            return Err(format!(
                "{path}: the selected events fall in {total_ranges} separate runs of record IDs, \
                 more than the {MAX_RANGES_PER_SOURCE} one export can express. Narrow the filter \
                 and try again."
            ));
        }
        let terms: Vec<GroupTerms> = groups
            .iter()
            .map(|group| group_terms(kind, path, &group.origin))
            .collect::<Result<_, _>>()?;

        let total_cost: usize = groups
            .iter()
            .zip(&terms)
            .map(|(group, terms)| terms.cost() + group.ranges.iter().map(range_cost).sum::<usize>())
            .sum();
        if total_cost <= XPATH_EXPRESSION_LIMIT {
            let units: Vec<String> = groups
                .iter()
                .zip(&terms)
                .map(|(group, terms)| unit_predicate(terms, &group.ranges))
                .collect();
            return Ok(SubsetQuery {
                text: xpath_of(&units),
                structured: false,
            });
        }

        let path_attribute = escape_xml(&select_path(kind, path), true);
        let mut text = String::from("<QueryList><Query Id=\"0\">");
        for (group, terms) in groups.iter().zip(&terms) {
            let budget = XPATH_EXPRESSION_LIMIT - terms.cost();
            let mut start = 0usize;
            let mut cost = 0usize;
            let mut chunks: Vec<&[RecordIdRange]> = Vec::new();
            for (index, range) in group.ranges.iter().enumerate() {
                let next = range_cost(range);
                if cost + next > budget {
                    chunks.push(&group.ranges[start..index]);
                    start = index;
                    cost = 0;
                }
                cost += next;
            }
            chunks.push(&group.ranges[start..]);
            for chunk in chunks {
                let xpath = xpath_of(&[unit_predicate(terms, chunk)]);
                text.push_str(&format!(
                    "<Select Path=\"{path_attribute}\">{}</Select>",
                    escape_xml(&xpath, false)
                ));
            }
        }
        text.push_str("</Query></QueryList>");
        Ok(SubsetQuery {
            text,
            structured: true,
        })
    }

    // ---- file naming ------------------------------------------------------------------------

    fn is_invisible_format_char(ch: char) -> bool {
        matches!(
            ch,
            '\u{200B}'..='\u{200F}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{2069}'
                | '\u{FEFF}'
        )
    }

    fn is_reserved_device_name(label: &str) -> bool {
        // Windows treats `NUL.anything` as the NUL device, so the part before the first dot decides.
        let head = label.split('.').next().unwrap_or("").trim_end();
        let upper = head.to_ascii_uppercase();
        matches!(
            upper.as_str(),
            "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
        ) || ((upper.starts_with("COM") || upper.starts_with("LPT"))
            && upper.len() == 4
            && upper.as_bytes()[3].is_ascii_digit())
    }

    /// Turns a channel name or file stem into a single safe path component fragment.
    ///
    /// Characters Windows forbids in a file name, control characters, directional overrides and
    /// every path separator become `-`; runs of them collapse to one. A source name therefore
    /// cannot carry the file out of the chosen folder, whatever it contains.
    pub(super) fn sanitize_label(label: &str) -> String {
        let mut out = String::with_capacity(label.len());
        let mut after_replacement = false;
        let mut after_dot = false;
        for ch in label.chars() {
            let forbidden = ch.is_control()
                || is_invisible_format_char(ch)
                || matches!(ch, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*');
            if forbidden {
                if !after_replacement {
                    out.push('-');
                    after_replacement = true;
                }
                after_dot = false;
            } else if ch == '.' {
                // A run of dots becomes one, so `..` never survives inside a name.
                if !after_dot {
                    out.push('.');
                }
                after_dot = true;
                after_replacement = false;
            } else {
                out.push(ch);
                after_replacement = false;
                after_dot = false;
            }
        }
        // Windows silently drops trailing dots and spaces, so two different names would collide.
        // Leading and trailing `-` are only ever the residue of a replaced separator.
        let trim = |text: &str| -> String {
            text.trim_matches(|c: char| c == '.' || c == '-' || c.is_whitespace())
                .to_string()
        };
        let mut label: String = trim(&out).chars().take(LABEL_MAX_CHARS).collect();
        label = trim(&label);
        if label.is_empty() {
            return FALLBACK_LABEL.to_string();
        }
        if is_reserved_device_name(&label) {
            label.insert(0, '_');
        }
        label
    }

    /// The label a source contributes to its output name. For a file this is the file stem, not
    /// the path; the spec's `{source-label}` is read as the name an operator would recognize.
    pub(super) fn source_label(kind: EvtxSubsetSourceKind, path: &str) -> String {
        match kind {
            EvtxSubsetSourceKind::Channel => sanitize_label(path),
            EvtxSubsetSourceKind::File => {
                // Split on both separators so the result does not depend on the host OS.
                let name = path.rsplit(['/', '\\']).next().unwrap_or("");
                let stem = match name.len().checked_sub(5) {
                    Some(cut)
                        if name.is_char_boundary(cut)
                            && name[cut..].eq_ignore_ascii_case(".evtx") =>
                    {
                        &name[..cut]
                    }
                    _ => name,
                };
                sanitize_label(stem)
            }
        }
    }

    pub(super) fn output_file_name(label: &str, ordinal: usize) -> String {
        if ordinal <= 1 {
            format!("{label}-subset.evtx")
        } else {
            format!("{label}-{ordinal}-subset.evtx")
        }
    }

    /// Two sources can sanitize to the same name (two `Application.evtx` from different folders;
    /// `A/B` and `A-B`). The file system is case-insensitive on Windows, so compare lowercased and
    /// number the later ones in request order.
    pub(super) fn assign_unique_file_names(labels: &[String]) -> Vec<String> {
        let mut taken: HashSet<String> = HashSet::new();
        labels
            .iter()
            .map(|label| {
                let mut ordinal = 1usize;
                loop {
                    let candidate = output_file_name(label, ordinal);
                    if taken.insert(candidate.to_lowercase()) {
                        return candidate;
                    }
                    ordinal += 1;
                }
            })
            .collect()
    }

    // ---- planning ---------------------------------------------------------------------------

    pub(super) fn validate_output_folder(folder: &str) -> Result<PathBuf, String> {
        if folder.trim().is_empty() {
            return Err("Choose a folder for the exported files.".to_string());
        }
        if folder.chars().any(char::is_control) {
            return Err("The output folder path contains control characters.".to_string());
        }
        let path = PathBuf::from(folder);
        if !path.is_absolute() {
            return Err(format!(
                "The output folder must be an absolute path: {folder}"
            ));
        }
        match fs::metadata(&path) {
            Ok(metadata) if metadata.is_dir() => Ok(path),
            Ok(_) => Err(format!("The output path is not a folder: {folder}")),
            Err(error) => Err(format!("Cannot use the output folder {folder}: {error}")),
        }
    }

    fn validate_source(source: &EvtxSubsetSource) -> Result<(), String> {
        let path = source.path.as_str();
        if path.trim().is_empty() || path.chars().any(char::is_control) {
            return Err("A source has an empty or invalid name.".to_string());
        }
        if source.kind == EvtxSubsetSourceKind::File {
            let candidate = Path::new(path);
            if !candidate.is_absolute() {
                return Err(format!("{path}: an .evtx source must be an absolute path"));
            }
            if !path.to_ascii_lowercase().ends_with(".evtx") {
                return Err(format!("{path}: only .evtx files can be exported"));
            }
            match fs::metadata(candidate) {
                Ok(metadata) if metadata.is_file() => {}
                Ok(_) => return Err(format!("{path}: not a file")),
                Err(error) => return Err(format!("{path}: cannot read the source file: {error}")),
            }
        }
        Ok(())
    }

    #[derive(Debug, Clone)]
    pub(super) struct PlannedExport {
        pub(super) kind: EvtxSubsetSourceKind,
        pub(super) source_path: String,
        pub(super) file_name: String,
        pub(super) target: PathBuf,
        /// Distinct events (computer, source channel and ID) asked for.
        pub(super) requested: u64,
        pub(super) query: SubsetQuery,
        /// What the written file is compared against.
        pub(super) groups: Vec<EventGroup>,
    }

    /// A source that could not be planned. It still gets a row in the result, so the operator sees
    /// which source was left out and why, and the others are exported.
    #[derive(Debug, Clone)]
    pub(super) struct FailedSource {
        pub(super) kind: EvtxSubsetSourceKind,
        pub(super) source_path: String,
        pub(super) file_name: String,
        pub(super) target: PathBuf,
        pub(super) requested: u64,
        pub(super) error: String,
    }

    #[derive(Debug, Clone)]
    pub(super) enum PlanEntry {
        Ready(PlannedExport),
        Failed(FailedSource),
    }

    #[derive(Debug, Clone)]
    pub(super) struct SubsetPlan {
        pub(super) folder: PathBuf,
        /// One entry per requested source, in request order.
        pub(super) entries: Vec<PlanEntry>,
        /// Set when archiving must be skipped for the whole request, with the reason.
        pub(super) archive_blocked: Option<String>,
    }

    /// True when `path` names anything at all, including a directory or a dangling link: none of
    /// those may be replaced.
    fn path_is_taken(path: &Path) -> bool {
        fs::symlink_metadata(path).is_ok()
    }

    /// `EvtArchiveExportedLog` writes into a `LocaleMetaData` folder next to the export, and the
    /// `wevtutil al` documentation warns that it overwrites files there and that the location must
    /// not hold untrusted links. A link in that spot could redirect those writes, so archiving is
    /// skipped (and reported) rather than followed.
    fn locale_metadata_block_reason(folder: &Path) -> Option<String> {
        let locale_dir = folder.join(LOCALE_METADATA_DIR);
        match fs::symlink_metadata(&locale_dir) {
            Ok(metadata) if metadata.file_type().is_symlink() => Some(format!(
                "{} is a link, so the localized messages were not archived into it",
                locale_dir.display()
            )),
            Ok(metadata) if !metadata.is_dir() => Some(format!(
                "{} exists and is not a folder, so the localized messages were not archived",
                locale_dir.display()
            )),
            _ => None,
        }
    }

    /// `EvtArchiveExportedLog` overwrites what it finds in `LocaleMetaData`, so a file whose name
    /// already has an entry there (left by an earlier export whose `.evtx` was moved or deleted) is
    /// not archived: "existing files are never overwritten" holds for the folder as well. The
    /// documentation does not name the entry the service writes; in practice it is
    /// `{log name}_{locale id}.MTA`, so an entry counts when it begins with the target's stem and
    /// `_` or `.`, in any case. Lab item (i) checks that rule against what the service writes. A
    /// folder that cannot be listed is no proof that nothing would be overwritten, so it skips too.
    pub(super) fn locale_entry_block_reason(folder: &Path, file_name: &str) -> Option<String> {
        let locale_dir = folder.join(LOCALE_METADATA_DIR);
        let unreadable = |error: std::io::Error| {
            Some(format!(
                "{} could not be read to check for entries that archiving would overwrite \
                 ({error}), so the localized messages were not archived",
                locale_dir.display()
            ))
        };
        let entries = match fs::read_dir(&locale_dir) {
            Ok(entries) => entries,
            // Nothing has been archived here yet.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
            Err(error) => return unreadable(error),
        };
        let stem = file_name
            .strip_suffix(".evtx")
            .unwrap_or(file_name)
            .to_lowercase();
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => return unreadable(error),
            };
            let name = entry.file_name().to_string_lossy().into_owned();
            let lower = name.to_lowercase();
            if lower.starts_with(&format!("{stem}_")) || lower.starts_with(&format!("{stem}.")) {
                return Some(format!(
                    "{} already holds an entry for {file_name} ({name}), so the localized \
                     messages were not archived rather than overwrite it",
                    locale_dir.display()
                ));
            }
        }
        None
    }

    struct PreparedSource {
        groups: Vec<EventGroup>,
        requested: u64,
        query: SubsetQuery,
    }

    /// A computer or channel name as the request gave it. Whitespace alone is no name.
    fn clean_name(source: &str, what: &str, name: Option<&str>) -> Result<Option<String>, String> {
        let Some(name) = name.filter(|name| !name.trim().is_empty()) else {
            return Ok(None);
        };
        if name.chars().any(char::is_control) {
            return Err(format!(
                "{source}: a {what} name contains control characters"
            ));
        }
        Ok(Some(name.to_string()))
    }

    /// Turns one requested source into ranges and a query, or says why that source cannot be
    /// exported. Never consults the request as a whole, so one bad source cannot block the rest.
    fn prepare_source(source: &EvtxSubsetSource) -> Result<PreparedSource, String> {
        validate_source(source)?;
        if source.record_groups.is_empty() {
            return Err(format!("{}: no events were given", source.path));
        }
        let mut merged: Vec<(EventOrigin, Vec<u64>)> = Vec::new();
        for group in &source.record_groups {
            let origin = EventOrigin {
                computer: clean_name(&source.path, "computer", group.computer.as_deref())?,
                channel: clean_name(&source.path, "channel", group.channel.as_deref())?,
            };
            let ids = parse_record_ids(&source.path, &group.record_ids)?;
            match merged.iter_mut().find(|(existing, _)| *existing == origin) {
                Some((_, known)) => known.extend(ids),
                None => merged.push((origin, ids)),
            }
        }
        // Two groups that could select the same event cannot be told apart by the query, and the
        // file could not say which of them an event was requested for.
        let blurred = merged.iter().enumerate().any(|(index, (origin, _))| {
            merged[index + 1..]
                .iter()
                .any(|(other, _)| origin.overlaps(other))
        });
        if blurred {
            return Err(format!(
                "{}: some events carry no computer or channel name, so they cannot be told apart \
                 from other events with the same ID in the same log; export a view that holds one \
                 machine and one channel",
                source.path
            ));
        }
        let groups: Vec<EventGroup> = merged
            .into_iter()
            .map(|(origin, ids)| EventGroup {
                origin,
                ranges: coalesce_record_ids(&ids),
            })
            .collect();
        let requested = groups.iter().map(EventGroup::distinct_records).sum();
        let query = build_subset_query(source.kind, &source.path, &groups)?;
        Ok(PreparedSource {
            groups,
            requested,
            query,
        })
    }

    /// How many distinct, well-formed events a source asked for, for the row of a source that
    /// could not be planned. Best effort: a malformed ID is not counted.
    fn best_effort_requested(source: &EvtxSubsetSource) -> u64 {
        let mut seen: HashSet<(Option<&str>, Option<&str>, u64)> = HashSet::new();
        for group in &source.record_groups {
            for text in &group.record_ids {
                if text.bytes().all(|byte| byte.is_ascii_digit()) {
                    if let Ok(id) = text.parse::<u64>() {
                        if id > 0 && id <= MAX_SAFE_EVENT_RECORD_ID {
                            seen.insert((group.computer.as_deref(), group.channel.as_deref(), id));
                        }
                    }
                }
            }
        }
        seen.len() as u64
    }

    pub(super) fn plan_subset_export(
        folder: &str,
        sources: &[EvtxSubsetSource],
    ) -> Result<SubsetPlan, String> {
        // Problems with the request itself refuse it whole: nothing has been touched yet, and
        // they are the same for every source.
        let folder = validate_output_folder(folder)?;
        if sources.is_empty() {
            return Err("There are no events to export.".to_string());
        }
        let mut seen: HashSet<(EvtxSubsetSourceKind, String)> = HashSet::new();
        for source in sources {
            if !seen.insert((source.kind, source.path.to_lowercase())) {
                return Err(format!("{}: listed more than once", source.path));
            }
        }

        let labels: Vec<String> = sources
            .iter()
            .map(|source| source_label(source.kind, &source.path))
            .collect();
        let names = assign_unique_file_names(&labels);
        let mut entries = Vec::with_capacity(sources.len());
        for (source, file_name) in sources.iter().zip(names) {
            let target = folder.join(&file_name);
            // The name has no separator and cannot be `.` or `..`, so this holds by construction;
            // asserted anyway because a failure here would be a path escape.
            if target.parent() != Some(folder.as_path()) {
                return Err(format!(
                    "{}: the output name is not a plain file name",
                    source.path
                ));
            }
            // A problem with one source is that source's result, not the request's.
            entries.push(match prepare_source(source) {
                Ok(prepared) => PlanEntry::Ready(PlannedExport {
                    kind: source.kind,
                    source_path: source.path.clone(),
                    file_name,
                    target,
                    requested: prepared.requested,
                    query: prepared.query,
                    groups: prepared.groups,
                }),
                Err(error) => PlanEntry::Failed(FailedSource {
                    kind: source.kind,
                    source_path: source.path.clone(),
                    file_name,
                    target,
                    requested: best_effort_requested(source),
                    error,
                }),
            });
        }

        // Only files that would actually be written can collide with something that exists.
        let conflicts: Vec<&str> = entries
            .iter()
            .filter_map(|entry| match entry {
                PlanEntry::Ready(export) if path_is_taken(&export.target) => {
                    Some(export.file_name.as_str())
                }
                _ => None,
            })
            .collect();
        if !conflicts.is_empty() {
            return Err(format!(
                "These files already exist in {} and are never overwritten: {}. Choose another \
                 folder, or move or rename them.",
                folder.display(),
                conflicts.join(", ")
            ));
        }

        let archive_blocked = locale_metadata_block_reason(&folder);
        Ok(SubsetPlan {
            folder,
            entries,
            archive_blocked,
        })
    }

    // ---- execution --------------------------------------------------------------------------

    pub(super) struct ExportLogError {
        pub(super) message: String,
        /// The service refused because the target already existed. Such a file is not ours.
        pub(super) already_exists: bool,
    }

    /// One event found in a written file.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(super) struct ReadBackRecord {
        pub(super) id: u64,
        pub(super) origin: EventOrigin,
    }

    /// The part that needs the Event Log service. Windows implements it; tests fake it.
    pub(super) trait SubsetBackend {
        fn export_log(&self, export: &PlannedExport) -> Result<(), ExportLogError>;
        fn archive_log(&self, target: &Path) -> Result<(), String>;
        /// Every event in the written file, by `EventRecordID`, `Computer` and `Channel`.
        fn read_back(&self, target: &Path) -> Result<Vec<ReadBackRecord>, String>;
    }

    /// Win32 codes that `EvtExportLog` and `EvtArchiveExportedLog` return in practice, with what
    /// each means to an operator. Anything else is reported by its system message alone.
    pub(super) fn win32_hint(code: u32) -> Option<&'static str> {
        match code {
            2 | 3 => Some("the source log or the output folder was not found"),
            5 => Some("access denied; reading this log may need the application to run elevated"),
            32 => Some("the log file is in use by another process"),
            80 | 183 => Some("the target file already exists"),
            112 => Some("the output disk is full"),
            15000 | 15007 => Some("the channel was not found"),
            15001 => Some("the Event Log service rejected the query"),
            15008 => Some("the structured query was not well-formed XML"),
            _ => None,
        }
    }

    pub(super) fn win32_already_exists(code: u32) -> bool {
        matches!(code, 80 | 183)
    }

    /// Reads the written file back: every event's `System/EventRecordID`, `System/Computer` and
    /// `System/Channel`. An unreadable record makes the answer unknown rather than short, so it is
    /// an error, not a smaller list.
    pub(super) fn read_back_evtx(path: &Path) -> Result<Vec<ReadBackRecord>, String> {
        let mut parser = evtx::EvtxParser::from_path(path)
            .map_err(|error| format!("cannot open the exported file: {error}"))?;
        let mut records = Vec::new();
        let mut unreadable = 0u64;
        for record in parser.records() {
            let Ok(record) = record else {
                unreadable += 1;
                continue;
            };
            let header_id = record.event_record_id;
            match parse_event_xml(&record.data) {
                Ok(root) => {
                    let system = extract_system_fields(&root);
                    records.push(ReadBackRecord {
                        // The XML is what the query matched against; the record header is only the
                        // fallback for an event whose XML carries no EventRecordID.
                        id: system.event_record_id.unwrap_or(header_id),
                        origin: EventOrigin {
                            computer: system.computer,
                            channel: system.channel,
                        },
                    });
                }
                Err(_) => unreadable += 1,
            }
        }
        if unreadable > 0 {
            return Err(format!(
                "{unreadable} records in the exported file could not be read back ({} could)",
                records.len()
            ));
        }
        Ok(records)
    }

    /// How many ids a difference lists by name; the count is always the whole number.
    pub(super) const ID_SAMPLE_LIMIT: usize = 20;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(super) struct ReadBackComparison {
        pub(super) exported: u64,
        pub(super) missing: EvtxSubsetIdDifference,
        pub(super) unrequested: EvtxSubsetIdDifference,
        /// How many of each requested group's events are missing, in the order of the groups, so a
        /// group that came back empty can be told from one that came back short.
        pub(super) missing_by_group: Vec<u64>,
    }

    /// Compares what the file holds with what was asked for, event by event (computer, source
    /// channel and ID).
    ///
    /// A count alone cannot tell a short file from one that also holds events nobody asked for, and
    /// a file whose count matches can still hold different events. Both directions are reported on
    /// their own.
    pub(super) fn compare_read_back(
        expected: &[EventGroup],
        actual: &[ReadBackRecord],
    ) -> ReadBackComparison {
        let mut present: Vec<HashSet<u64>> = vec![HashSet::new(); expected.len()];
        let mut unrequested: Vec<(&EventOrigin, u64)> = Vec::new();
        for record in actual {
            match expected
                .iter()
                .position(|group| group.contains(&record.origin, record.id))
            {
                // A second copy of an event is an event nobody asked for, too.
                Some(index) => {
                    if !present[index].insert(record.id) {
                        unrequested.push((&record.origin, record.id));
                    }
                }
                None => unrequested.push((&record.origin, record.id)),
            }
        }

        let mut missing_count = 0u64;
        let mut missing_sample = Vec::new();
        let mut missing_by_group = Vec::with_capacity(expected.len());
        for (group, seen) in expected.iter().zip(&present) {
            let before = missing_count;
            for range in &group.ranges {
                for id in range.start..=range.end {
                    if !seen.contains(&id) {
                        missing_count += 1;
                        if missing_sample.len() < ID_SAMPLE_LIMIT {
                            missing_sample.push(group.origin.describe(id));
                        }
                    }
                }
            }
            missing_by_group.push(missing_count - before);
        }

        unrequested.sort();
        let unrequested_sample = unrequested
            .iter()
            .take(ID_SAMPLE_LIMIT)
            .map(|(origin, id)| origin.describe(*id))
            .collect();
        ReadBackComparison {
            exported: actual.len() as u64,
            missing: EvtxSubsetIdDifference {
                count: missing_count,
                sample: missing_sample,
            },
            unrequested: EvtxSubsetIdDifference {
                count: unrequested.len() as u64,
                sample: unrequested_sample,
            },
            missing_by_group,
        }
    }

    fn event_noun(count: u64) -> &'static str {
        if count == 1 {
            "event"
        } else {
            "events"
        }
    }

    fn sample_text(difference: &EvtxSubsetIdDifference) -> String {
        let listed = difference.sample.join(", ");
        let more = difference
            .count
            .saturating_sub(difference.sample.len() as u64);
        if more > 0 {
            format!("{listed}, and {more} more")
        } else {
            listed
        }
    }

    /// The other way the query may have gone wrong for a group that came back empty: it names a
    /// computer or a channel, and the name it used may not be the one the events carry. `None` for
    /// a group the query names nothing for, which has no such cause.
    fn unmatched_group_clause(export: &PlannedExport, group: &EventGroup) -> Option<String> {
        let computer = group.origin.computer.as_deref();
        let channel = group
            .origin
            .channel
            .as_deref()
            .filter(|name| names_channel_in_query(export.kind, &export.source_path, name));
        let (who, which) = match (computer, channel) {
            (None, None) => return None,
            (Some(computer), None) => (format!("from {computer}"), "computer"),
            (None, Some(channel)) => (format!("in {channel}"), "channel"),
            (Some(computer), Some(channel)) => (
                format!("from {computer} in {channel}"),
                "computer or channel",
            ),
        };
        Some(format!(
            "no event {who} matched, so the {which} name in the query may differ from the one \
             stored in the events"
        ))
    }

    /// Why requested events are not in the file, worded for what is known.
    ///
    /// The shortfall itself is explained by what the source is: a live log can wrap or be cleared
    /// after the events were loaded, a file can only have been changed. A file that holds none of
    /// the requested events says the query selected none. Then each group that came back wholly
    /// empty says so on its own, because a query that names a computer or a channel can also match
    /// nothing for one group when that name is not the one stored in the events, while another group
    /// of the same query matched.
    fn missing_warning(export: &PlannedExport, comparison: &ReadBackComparison) -> String {
        let missing = &comparison.missing;
        let listed = sample_text(missing);
        let noun = event_noun(missing.count);
        let cause = match export.kind {
            EvtxSubsetSourceKind::Channel => {
                "the log may have wrapped or been cleared since they were loaded"
            }
            EvtxSubsetSourceKind::File => "the file may have changed since it was loaded",
        };
        let mut warning = if missing.count < export.requested {
            format!(
                "{} requested {noun} not in the file ({listed}); {cause}",
                missing.count
            )
        } else {
            format!(
                "the query matched none of the {} requested {noun} ({listed}); {cause}",
                missing.count
            )
        };
        for (group, &group_missing) in export.groups.iter().zip(&comparison.missing_by_group) {
            if group_missing == group.distinct_records() {
                if let Some(clause) = unmatched_group_clause(export, group) {
                    warning.push_str("; ");
                    warning.push_str(&clause);
                }
            }
        }
        warning
    }

    fn remove_partial_output(export: &PlannedExport) -> Option<String> {
        if !path_is_taken(&export.target) {
            return None;
        }
        match fs::remove_file(&export.target) {
            Ok(()) => None,
            Err(error) => Some(format!(
                "a partial file may remain at {}: {error}",
                export.target.display()
            )),
        }
    }

    pub(super) fn run_plan(plan: &SubsetPlan, backend: &dyn SubsetBackend) -> EvtxSubsetResult {
        let files = plan
            .entries
            .iter()
            .map(|entry| match entry {
                PlanEntry::Ready(export) => run_one(plan, export, backend),
                PlanEntry::Failed(failed) => failed_result(failed),
            })
            .collect();
        EvtxSubsetResult {
            folder: plan.folder.to_string_lossy().into_owned(),
            files,
        }
    }

    fn base_result(
        kind: EvtxSubsetSourceKind,
        source_path: &str,
        file_name: &str,
        target: &Path,
        requested: u64,
    ) -> EvtxSubsetFileResult {
        EvtxSubsetFileResult {
            kind,
            source_path: source_path.to_string(),
            file_name: file_name.to_string(),
            output_path: target.to_string_lossy().into_owned(),
            requested_records: requested,
            status: EvtxSubsetFileStatus::Failed,
            exported_records: None,
            missing: None,
            unrequested: None,
            messages_archived: false,
            error: None,
            warnings: Vec::new(),
        }
    }

    fn failed_result(failed: &FailedSource) -> EvtxSubsetFileResult {
        let mut result = base_result(
            failed.kind,
            &failed.source_path,
            &failed.file_name,
            &failed.target,
            failed.requested,
        );
        result.error = Some(failed.error.clone());
        result
    }

    fn run_one(
        plan: &SubsetPlan,
        export: &PlannedExport,
        backend: &dyn SubsetBackend,
    ) -> EvtxSubsetFileResult {
        let mut result = base_result(
            export.kind,
            &export.source_path,
            &export.file_name,
            &export.target,
            export.requested,
        );

        // Checked again immediately before the call: the plan was made earlier, and a file may
        // have appeared since. The service refuses to overwrite as well; this keeps the message
        // clear and guarantees the cleanup below only ever removes a file this call created.
        if path_is_taken(&export.target) {
            result.error = Some(format!(
                "{} already exists and is never overwritten",
                export.file_name
            ));
            return result;
        }

        log::info!(
            "event=evtx_export_subset_file kind={:?} requested={} structured_query={}",
            export.kind,
            export.requested,
            export.query.structured
        );
        if let Err(error) = backend.export_log(export) {
            let mut message = error.message;
            if !error.already_exists {
                if let Some(note) = remove_partial_output(export) {
                    message = format!("{message} ({note})");
                }
            }
            result.error = Some(message);
            return result;
        }
        result.status = EvtxSubsetFileStatus::Exported;

        // The folder is looked at here, immediately before the call, not when the plan was made: an
        // earlier export of this request or another process may have written there since.
        let archive_skipped = plan
            .archive_blocked
            .clone()
            .or_else(|| locale_entry_block_reason(&plan.folder, &export.file_name));
        match archive_skipped {
            Some(reason) => result.warnings.push(reason),
            None => match backend.archive_log(&export.target) {
                Ok(()) => result.messages_archived = true,
                Err(error) => result.warnings.push(format!(
                    "the localized messages were not archived, so events from providers that are \
                     not installed on the machine that opens this file may show no message text \
                     ({error})"
                )),
            },
        }

        match backend.read_back(&export.target) {
            Ok(actual) => {
                let comparison = compare_read_back(&export.groups, &actual);
                result.exported_records = Some(comparison.exported);
                if comparison.missing.count > 0 {
                    result.warnings.push(missing_warning(export, &comparison));
                }
                if comparison.unrequested.count > 0 {
                    result.warnings.push(format!(
                        "the file also holds {} {} that {} not requested ({}); the file is not \
                         redacted, so check {} before sharing it",
                        comparison.unrequested.count,
                        event_noun(comparison.unrequested.count),
                        if comparison.unrequested.count == 1 {
                            "was"
                        } else {
                            "were"
                        },
                        sample_text(&comparison.unrequested),
                        if comparison.unrequested.count == 1 {
                            "it"
                        } else {
                            "them"
                        },
                    ));
                }
                result.missing = Some(comparison.missing);
                result.unrequested = Some(comparison.unrequested);
            }
            Err(error) => result.warnings.push(format!(
                "which events the file holds could not be verified ({error})"
            )),
        }
        result
    }
}

#[cfg(target_os = "windows")]
mod windows_backend {
    use std::path::Path;

    use windows::core::{Error, HSTRING};
    use windows::Win32::System::EventLog::{
        EvtArchiveExportedLog, EvtExportLog, EvtExportLogChannelPath, EvtExportLogFilePath,
    };

    use super::engine::{
        read_back_evtx, win32_already_exists, win32_hint, ExportLogError, PlannedExport,
        ReadBackRecord, SubsetBackend,
    };
    use super::EvtxSubsetSourceKind;

    pub(super) struct WindowsBackend;

    fn win32_code(error: &Error) -> u32 {
        (error.code().0 & 0xFFFF) as u32
    }

    fn describe(context: &str, error: &Error) -> String {
        let message = error.message();
        let message = message.trim();
        let base = if message.is_empty() {
            format!("{context}: Windows error 0x{:08x}", error.code().0 as u32)
        } else {
            format!("{context}: {message}")
        };
        match win32_hint(win32_code(error)) {
            Some(hint) => format!("{base} ({hint})"),
            None => base,
        }
    }

    impl SubsetBackend for WindowsBackend {
        fn export_log(&self, export: &PlannedExport) -> Result<(), ExportLogError> {
            let flags = match export.kind {
                EvtxSubsetSourceKind::Channel => EvtExportLogChannelPath,
                EvtxSubsetSourceKind::File => EvtExportLogFilePath,
            };
            let source = HSTRING::from(export.source_path.as_str());
            let query = HSTRING::from(export.query.text.as_str());
            let target = HSTRING::from(export.target.as_path());
            // SAFETY: every argument is a valid, NUL-terminated wide string that outlives the
            // call. A local session (`None`) is used, and no overwrite flag is passed, so the
            // service itself refuses an existing target.
            unsafe { EvtExportLog(None, &source, &query, &target, flags.0) }.map_err(|error| {
                ExportLogError {
                    message: describe("EvtExportLog", &error),
                    already_exists: win32_already_exists(win32_code(&error)),
                }
            })
        }

        fn archive_log(&self, target: &Path) -> Result<(), String> {
            let target = HSTRING::from(target);
            // SAFETY: `target` is a valid wide string for the duration of the call. Locale 0 uses
            // the calling thread's locale and the flags are reserved and must be zero.
            unsafe { EvtArchiveExportedLog(None, &target, 0, 0) }
                .map_err(|error| describe("EvtArchiveExportedLog", &error))
        }

        fn read_back(&self, target: &Path) -> Result<Vec<ReadBackRecord>, String> {
            read_back_evtx(target)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::fs;
    use std::path::Path;

    use super::engine::*;
    use super::*;

    fn ids(values: &[u64]) -> Vec<String> {
        values.iter().map(u64::to_string).collect()
    }

    fn range(start: u64, end: u64) -> RecordIdRange {
        RecordIdRange { start, end }
    }

    // ---- coalescing -------------------------------------------------------------------------

    #[test]
    fn coalesce_sorts_dedups_and_merges_only_adjacent_ids() {
        let got = coalesce_record_ids(&[9, 3, 4, 5, 3, 7, 10, 1]);
        assert_eq!(
            got,
            vec![range(1, 1), range(3, 5), range(7, 7), range(9, 10)]
        );
    }

    #[test]
    fn coalesce_does_not_wrap_at_the_top_of_u64() {
        let got = coalesce_record_ids(&[u64::MAX, 0, u64::MAX - 1]);
        assert_eq!(got, vec![range(0, 0), range(u64::MAX - 1, u64::MAX)]);
        assert_eq!(coalesce_record_ids(&[]), Vec::<RecordIdRange>::new());
    }

    #[test]
    fn distinct_count_counts_ids_not_ranges() {
        let ranges = coalesce_record_ids(&[1, 2, 3, 3, 3, 10]);
        assert_eq!(distinct_record_count(&ranges), 4);
    }

    #[test]
    fn record_id_text_is_strict() {
        assert_eq!(
            parse_record_ids("S", &["1".into(), "42".into(), "007".into()]).unwrap(),
            vec![1, 42, 7]
        );
        for bad in ["", " 5", "5 ", "+5", "-1", "1.5", "0x10", "abc", "1e3"] {
            assert!(
                parse_record_ids("S", &[bad.to_string()]).is_err(),
                "{bad:?} must be rejected"
            );
        }
        assert!(parse_record_ids("S", &[]).is_err());
        assert!(parse_record_ids("S", &["99999999999999999999999".into()]).is_err());
    }

    #[test]
    fn zero_is_no_identity_in_any_spelling() {
        for zero in ["0", "00", "000000"] {
            let error = parse_record_ids("S", &[zero.to_string()]).unwrap_err();
            assert!(error.contains("not an identity"), "{zero}: {error}");
        }
        // One zero among real ids still refuses the group rather than quietly dropping it.
        assert!(parse_record_ids("S", &["5".into(), "0".into()]).is_err());
    }

    #[test]
    fn ids_the_query_language_cannot_match_exactly_are_refused() {
        let safe = MAX_SAFE_EVENT_RECORD_ID_FOR_TEST;
        assert!(parse_record_ids("S", &[safe.to_string()]).is_ok());
        let error = parse_record_ids("S", &[(safe + 1).to_string()]).unwrap_err();
        assert!(error.contains("cannot match exactly"), "{error}");
    }
    const MAX_SAFE_EVENT_RECORD_ID_FOR_TEST: u64 = 9_007_199_254_740_991;

    // ---- queries ----------------------------------------------------------------------------

    /// Splits `expr` at `separator` where it is not inside parentheses or a quoted literal.
    fn split_top_level<'a>(expr: &'a str, separator: &str) -> Vec<&'a str> {
        let bytes = expr.as_bytes();
        let mut parts = Vec::new();
        let (mut depth, mut start, mut index) = (0i32, 0usize, 0usize);
        let mut quote: Option<u8> = None;
        while index < bytes.len() {
            let byte = bytes[index];
            match quote {
                Some(open) => {
                    if byte == open {
                        quote = None;
                    }
                }
                None => match byte {
                    b'\'' | b'"' => quote = Some(byte),
                    b'(' => depth += 1,
                    b')' => depth -= 1,
                    _ if depth == 0
                        && expr.is_char_boundary(index)
                        && expr[index..].starts_with(separator) =>
                    {
                        parts.push(&expr[start..index]);
                        index += separator.len();
                        start = index;
                        continue;
                    }
                    _ => {}
                },
            }
            index += 1;
        }
        parts.push(&expr[start..]);
        parts
    }

    fn eval(expr: &str, found: &EventOrigin, id: u64) -> bool {
        let expr = expr.trim();
        let ors = split_top_level(expr, " or ");
        if ors.len() > 1 {
            return ors.iter().any(|part| eval(part, found, id));
        }
        let ands = split_top_level(expr, " and ");
        if ands.len() > 1 {
            return ands.iter().all(|part| eval(part, found, id));
        }
        if let Some(inner) = expr
            .strip_prefix('(')
            .and_then(|rest| rest.strip_suffix(')'))
        {
            return eval(inner, found, id);
        }
        if let Some(value) = expr.strip_prefix("EventRecordID>=") {
            return id >= value.parse::<u64>().unwrap();
        }
        if let Some(value) = expr.strip_prefix("EventRecordID<=") {
            return id <= value.parse::<u64>().unwrap();
        }
        if let Some(value) = expr.strip_prefix("EventRecordID=") {
            return id == value.parse::<u64>().unwrap();
        }
        if let Some(literal) = expr.strip_prefix("Computer=") {
            return found.computer.as_deref() == Some(&literal[1..literal.len() - 1]);
        }
        if let Some(literal) = expr.strip_prefix("Channel=") {
            return found.channel.as_deref() == Some(&literal[1..literal.len() - 1]);
        }
        panic!("unexpected XPath term {expr:?}");
    }

    /// Evaluates the XPath shapes this module emits against one event. Written independently of
    /// the builder so a wrong operator, a dropped term or a missing computer test shows up as a
    /// mismatch.
    fn matches_event(xpath: &str, found: &EventOrigin, id: u64) -> bool {
        let inner = xpath
            .strip_prefix("*[System[")
            .and_then(|rest| rest.strip_suffix("]]"))
            .expect("shape *[System[...]]");
        eval(inner, found, id)
    }

    fn unescape(text: &str) -> String {
        text.replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&apos;", "'")
            .replace("&amp;", "&")
    }

    fn select_texts(query: &str) -> Vec<String> {
        query
            .split("</Select>")
            .filter_map(|part| part.split_once('>').map(|(_, rest)| rest))
            .filter_map(|part| part.rsplit_once('>').map(|(_, rest)| rest).or(Some(part)))
            .map(str::to_string)
            .collect()
    }

    fn selects(query: &str) -> Vec<(String, String)> {
        let mut out = Vec::new();
        let mut rest = query;
        while let Some(start) = rest.find("<Select Path=\"") {
            rest = &rest[start + "<Select Path=\"".len()..];
            let (path, after) = rest.split_once("\">").unwrap();
            let (text, after) = after.split_once("</Select>").unwrap();
            out.push((unescape(path), unescape(text)));
            rest = after;
        }
        out
    }

    fn origin(computer: Option<&str>, channel: Option<&str>) -> EventOrigin {
        EventOrigin {
            computer: computer.map(str::to_string),
            channel: channel.map(str::to_string),
        }
    }

    /// One group with no computer and no channel, which is how an anonymous source is queried.
    fn one(ranges: Vec<RecordIdRange>) -> Vec<EventGroup> {
        vec![EventGroup {
            origin: EventOrigin::default(),
            ranges,
        }]
    }

    fn on(computer: &str, ranges: Vec<RecordIdRange>) -> EventGroup {
        EventGroup {
            origin: origin(Some(computer), None),
            ranges,
        }
    }

    fn in_log(computer: &str, channel: &str, ranges: Vec<RecordIdRange>) -> EventGroup {
        EventGroup {
            origin: origin(Some(computer), Some(channel)),
            ranges,
        }
    }

    /// Every comparison a `<Select>` carries: record id tests, computer tests and channel tests.
    fn comparisons(xpath: &str) -> usize {
        xpath.matches("EventRecordID").count()
            + xpath.matches("Computer=").count()
            + xpath.matches("Channel=").count()
    }

    #[test]
    fn a_short_selection_is_one_xpath_with_ranges_and_single_ids() {
        let ranges = coalesce_record_ids(&[5, 6, 7, 8, 9, 12]);
        let query =
            build_subset_query(EvtxSubsetSourceKind::Channel, "System", &one(ranges)).unwrap();
        assert!(!query.structured);
        assert_eq!(
            query.text,
            "*[System[(EventRecordID>=5 and EventRecordID<=9) or EventRecordID=12]]"
        );
    }

    #[test]
    fn the_xpath_limit_counts_comparisons_so_a_range_costs_two() {
        let build = |ranges: Vec<RecordIdRange>| {
            build_subset_query(EvtxSubsetSourceKind::Channel, "S", &one(ranges)).unwrap()
        };
        // 20 singles is 20 comparisons: still one XPath.
        let singles: Vec<u64> = (0..20).map(|n| n * 2).collect();
        assert!(!build(coalesce_record_ids(&singles)).structured);
        // 21 singles is over.
        let over: Vec<u64> = (0..21).map(|n| n * 2).collect();
        assert!(build(coalesce_record_ids(&over)).structured);
        // 10 ranges is 20 comparisons; 11 ranges is 22.
        let ten: Vec<RecordIdRange> = (0..10).map(|n| range(n * 10, n * 10 + 3)).collect();
        assert!(!build(ten).structured);
        let eleven: Vec<RecordIdRange> = (0..11).map(|n| range(n * 10, n * 10 + 3)).collect();
        assert!(build(eleven).structured);
    }

    #[test]
    fn a_structured_query_splits_into_selects_within_the_limit_and_keeps_every_id() {
        // Disjoint ids with a few runs, 200 ranges, so the query needs many Select elements.
        let mut values = Vec::new();
        for n in 0..200u64 {
            values.push(n * 10);
            if n % 3 == 0 {
                values.push(n * 10 + 1);
            }
        }
        let query = build_subset_query(
            EvtxSubsetSourceKind::Channel,
            "Application",
            &one(coalesce_record_ids(&values)),
        )
        .unwrap();
        assert!(query.structured);
        let parsed = selects(&query.text);
        assert!(parsed.len() > 1);
        for (path, xpath) in &parsed {
            assert_eq!(path, "Application");
            let count = comparisons(xpath);
            assert!(count <= XPATH_EXPRESSION_LIMIT, "{count}: {xpath}");
        }
        // Semantics: an id is kept by the query exactly when it was asked for.
        let wanted: std::collections::HashSet<u64> = values.iter().copied().collect();
        for id in 0..2_010u64 {
            let kept = parsed
                .iter()
                .any(|(_, xpath)| matches_event(xpath, &EventOrigin::default(), id));
            assert_eq!(kept, wanted.contains(&id), "id {id}");
        }
    }

    #[test]
    fn the_structured_text_is_escaped_and_well_formed() {
        let ranges: Vec<RecordIdRange> = (0..30).map(|n| range(n * 10, n * 10 + 4)).collect();
        let query =
            build_subset_query(EvtxSubsetSourceKind::Channel, "A&B'\"<C>", &one(ranges)).unwrap();
        assert!(query.structured);
        // Inside element text the comparison operators are entities, never raw.
        for text in select_texts(&query.text) {
            assert!(!text.contains("<="), "{text}");
        }
        assert!(query.text.contains("&gt;="));
        assert!(query.text.contains("&lt;="));
        // The attribute carries the channel name with every XML-special character escaped.
        assert!(query.text.contains("Path=\"A&amp;B&apos;&quot;&lt;C&gt;\""));
        // A real XML parser accepts it end to end.
        let mut reader = quick_xml::Reader::from_str(&query.text);
        loop {
            match reader.read_event() {
                Ok(quick_xml::events::Event::Eof) => break,
                Ok(_) => {}
                Err(error) => panic!("not well-formed: {error}"),
            }
        }
        // And the round trip gives back the original name.
        assert_eq!(selects(&query.text)[0].0, "A&B'\"<C>");
    }

    #[test]
    fn a_file_source_is_addressed_by_file_uri_in_a_structured_query_only() {
        let ranges: Vec<RecordIdRange> = (0..30).map(|n| range(n * 10, n * 10 + 4)).collect();
        let structured = build_subset_query(
            EvtxSubsetSourceKind::File,
            "C:\\logs\\System.evtx",
            &one(ranges),
        )
        .unwrap();
        assert_eq!(
            selects(&structured.text)[0].0,
            "file://C:\\logs\\System.evtx"
        );
        let plain = build_subset_query(
            EvtxSubsetSourceKind::File,
            "C:\\logs\\System.evtx",
            &one(vec![range(1, 5)]),
        )
        .unwrap();
        assert!(!plain.structured);
        assert!(!plain.text.contains("file://"));
    }

    #[test]
    fn an_empty_or_over_fragmented_selection_is_refused_not_truncated() {
        assert!(build_subset_query(EvtxSubsetSourceKind::Channel, "S", &[]).is_err());
        assert!(build_subset_query(EvtxSubsetSourceKind::Channel, "S", &one(vec![])).is_err());
        let fragmented: Vec<RecordIdRange> = (0..=MAX_RANGES_PER_SOURCE as u64)
            .map(|n| range(n * 2, n * 2))
            .collect();
        let error = build_subset_query(EvtxSubsetSourceKind::Channel, "System", &one(fragmented))
            .unwrap_err();
        assert!(error.contains("Narrow the filter"), "{error}");
        let at_cap: Vec<RecordIdRange> = (0..MAX_RANGES_PER_SOURCE as u64)
            .map(|n| range(n * 2, n * 2))
            .collect();
        assert!(build_subset_query(EvtxSubsetSourceKind::Channel, "System", &one(at_cap)).is_ok());
        // The cap is over the whole source, so several machines cannot each stay under it and
        // together exceed it.
        let half = MAX_RANGES_PER_SOURCE as u64 / 2 + 1;
        let groups = vec![
            on("A", (0..half).map(|n| range(n * 2, n * 2)).collect()),
            on("B", (0..half).map(|n| range(n * 2, n * 2)).collect()),
        ];
        assert!(build_subset_query(EvtxSubsetSourceKind::Channel, "System", &groups).is_err());
    }

    #[test]
    fn a_computer_is_named_in_the_query_so_another_machines_event_is_never_selected() {
        // The same EventRecordID on two machines, as a log that collects events can hold.
        let groups = vec![
            on("HOST-A", vec![range(100, 101)]),
            on("HOST-B", vec![range(100, 100)]),
        ];
        let query =
            build_subset_query(EvtxSubsetSourceKind::Channel, "ForwardedEvents", &groups).unwrap();
        assert!(!query.structured);
        assert_eq!(
            query.text,
            "*[System[(Computer='HOST-A' and (EventRecordID>=100 and EventRecordID<=101)) or \
             (Computer='HOST-B' and EventRecordID=100)]]"
        );
        let hit = |computer: Option<&str>, id: u64| {
            matches_event(&query.text, &origin(computer, None), id)
        };
        assert!(hit(Some("HOST-A"), 100) && hit(Some("HOST-A"), 101) && hit(Some("HOST-B"), 100));
        // What was not asked for is not selected, whichever machine it came from.
        assert!(!hit(Some("HOST-B"), 101));
        assert!(!hit(Some("HOST-C"), 100));
        assert!(!hit(None, 100));
        assert!(!hit(Some("host-a"), 100), "the comparison is exact");
    }

    #[test]
    fn a_single_named_machine_is_also_pinned_to_its_computer() {
        let query = build_subset_query(
            EvtxSubsetSourceKind::Channel,
            "ForwardedEvents",
            &[on("HOST-A", vec![range(5, 5), range(9, 12)])],
        )
        .unwrap();
        assert_eq!(
            query.text,
            "*[System[Computer='HOST-A' and (EventRecordID=5 or (EventRecordID>=9 and EventRecordID<=12))]]"
        );
        assert!(!matches_event(
            &query.text,
            &origin(Some("HOST-B"), None),
            5
        ));
    }

    #[test]
    fn two_source_logs_of_one_machine_are_two_events_in_the_query() {
        // A collector log can hold the same machine's EventRecordID 100 from two of its logs.
        let groups = vec![
            in_log("HOST-A", "System", vec![range(100, 100)]),
            in_log("HOST-A", "Security", vec![range(100, 100)]),
        ];
        let query =
            build_subset_query(EvtxSubsetSourceKind::Channel, "ForwardedEvents", &groups).unwrap();
        assert!(!query.structured);
        assert_eq!(
            query.text,
            "*[System[(Computer='HOST-A' and Channel='System' and EventRecordID=100) or \
             (Computer='HOST-A' and Channel='Security' and EventRecordID=100)]]"
        );
        let hit = |channel: Option<&str>| {
            matches_event(&query.text, &origin(Some("HOST-A"), channel), 100)
        };
        assert!(hit(Some("System")) && hit(Some("Security")));
        assert!(!hit(Some("Application")));
        assert!(!hit(None));
    }

    #[test]
    fn the_query_for_one_source_log_cannot_select_its_twin_from_another() {
        // A filter hid the Security twin, so only the System event was asked for.
        let query = build_subset_query(
            EvtxSubsetSourceKind::Channel,
            "ForwardedEvents",
            &[in_log("HOST-A", "System", vec![range(100, 100)])],
        )
        .unwrap();
        assert!(matches_event(
            &query.text,
            &origin(Some("HOST-A"), Some("System")),
            100
        ));
        assert!(
            !matches_event(&query.text, &origin(Some("HOST-A"), Some("Security")), 100),
            "{}",
            query.text
        );
    }

    #[test]
    fn the_channel_is_named_unless_it_is_the_log_being_queried() {
        let one_event = |kind, path: &str, group: EventGroup| {
            build_subset_query(kind, path, &[group]).unwrap().text
        };
        let single = |computer: Option<&str>, channel: &str| EventGroup {
            origin: origin(computer, Some(channel)),
            ranges: vec![range(1, 1)],
        };
        // Naming the log being queried says nothing the query does not already say, whatever case
        // the event spells it in.
        assert_eq!(
            one_event(
                EvtxSubsetSourceKind::Channel,
                "System",
                single(Some("HOST-A"), "system")
            ),
            "*[System[Computer='HOST-A' and EventRecordID=1]]"
        );
        // Any other channel is named: this is a collector holding another log's events.
        assert_eq!(
            one_event(
                EvtxSubsetSourceKind::Channel,
                "System",
                single(Some("HOST-A"), "Security")
            ),
            "*[System[Computer='HOST-A' and Channel='Security' and EventRecordID=1]]"
        );
        assert_eq!(
            one_event(
                EvtxSubsetSourceKind::Channel,
                "ForwardedEvents",
                single(None, "Security")
            ),
            "*[System[Channel='Security' and EventRecordID=1]]"
        );
        // A file has no log name of its own to be redundant with, so the channel is always named.
        assert_eq!(
            one_event(
                EvtxSubsetSourceKind::File,
                "C:\\logs\\System.evtx",
                single(Some("HOST-A"), "System")
            ),
            "*[System[Computer='HOST-A' and Channel='System' and EventRecordID=1]]"
        );
    }

    #[test]
    fn the_channel_test_counts_toward_the_limit_in_every_select() {
        let singles = |count: u64| -> Vec<RecordIdRange> {
            (0..count).map(|n| range(n * 2, n * 2)).collect()
        };
        // 18 singles plus the computer and the channel is exactly 20 comparisons.
        let at_limit = build_subset_query(
            EvtxSubsetSourceKind::Channel,
            "ForwardedEvents",
            &[in_log("HOST-A", "Security", singles(18))],
        )
        .unwrap();
        assert!(!at_limit.structured);
        assert_eq!(comparisons(&at_limit.text), 20);
        // One more id is 21: structured, and every Select names both and stays within the limit.
        let over = build_subset_query(
            EvtxSubsetSourceKind::Channel,
            "ForwardedEvents",
            &[in_log("HOST-A", "Security", singles(45))],
        )
        .unwrap();
        assert!(over.structured);
        let parsed = selects(&over.text);
        assert!(parsed.len() > 1);
        for (_, xpath) in &parsed {
            assert!(xpath.contains("Computer='HOST-A'"), "{xpath}");
            assert!(xpath.contains("Channel='Security'"), "{xpath}");
            assert!(comparisons(xpath) <= XPATH_EXPRESSION_LIMIT, "{xpath}");
        }
        // And the union still keeps exactly the ids that were asked for, for that origin only.
        let found = origin(Some("HOST-A"), Some("Security"));
        let other = origin(Some("HOST-A"), Some("System"));
        for id in 0..100u64 {
            let kept = |who: &EventOrigin| {
                parsed
                    .iter()
                    .any(|(_, xpath)| matches_event(xpath, who, id))
            };
            assert_eq!(kept(&found), id % 2 == 0 && id < 90, "id {id}");
            assert!(!kept(&other), "id {id}");
        }
    }

    #[test]
    fn a_channel_name_is_quoted_safely_or_refused() {
        let build = |name: &str| {
            build_subset_query(
                EvtxSubsetSourceKind::Channel,
                "ForwardedEvents",
                &[in_log("HOST-A", name, vec![range(1, 1)])],
            )
        };
        assert!(build("O'Brien/Operational")
            .unwrap()
            .text
            .contains("Channel=\"O'Brien/Operational\""));
        let error = build("a'b\"c").unwrap_err();
        assert!(error.contains("the channel name"), "{error}");
        assert!(error.contains("cannot be written in a query"), "{error}");
    }

    #[test]
    fn the_computer_test_counts_toward_the_limit_in_every_select() {
        let singles = |count: u64| -> Vec<RecordIdRange> {
            (0..count).map(|n| range(n * 2, n * 2)).collect()
        };
        // 19 singles plus the computer is exactly 20 comparisons: one XPath.
        let at_limit = build_subset_query(
            EvtxSubsetSourceKind::Channel,
            "S",
            &[on("HOST-A", singles(19))],
        )
        .unwrap();
        assert!(!at_limit.structured);
        assert_eq!(comparisons(&at_limit.text), 20);
        // 20 singles plus the computer is 21: structured, and every Select still names the
        // computer and stays within the limit.
        let over = build_subset_query(
            EvtxSubsetSourceKind::Channel,
            "S",
            &[on("HOST-A", singles(45))],
        )
        .unwrap();
        assert!(over.structured);
        let parsed = selects(&over.text);
        assert!(parsed.len() > 1);
        for (_, xpath) in &parsed {
            assert!(xpath.contains("Computer='HOST-A'"), "{xpath}");
            assert!(comparisons(xpath) <= XPATH_EXPRESSION_LIMIT, "{xpath}");
        }
    }

    #[test]
    fn several_machines_in_a_structured_query_keep_exactly_their_own_events() {
        // Three machines, the same 25 ids each, plus ids only some of them were asked for.
        let machines = ["HOST-A", "HOST-B", "HOST-C"];
        let groups: Vec<EventGroup> = machines
            .iter()
            .enumerate()
            .map(|(index, name)| {
                on(
                    name,
                    (0..25u64)
                        .map(|n| range(n * 3 + index as u64, n * 3 + index as u64))
                        .collect(),
                )
            })
            .collect();
        let query =
            build_subset_query(EvtxSubsetSourceKind::Channel, "ForwardedEvents", &groups).unwrap();
        assert!(query.structured);
        let parsed = selects(&query.text);
        for (_, xpath) in &parsed {
            assert!(comparisons(xpath) <= XPATH_EXPRESSION_LIMIT, "{xpath}");
        }
        for (index, name) in machines.iter().enumerate() {
            let wanted: std::collections::HashSet<u64> =
                (0..25u64).map(|n| n * 3 + index as u64).collect();
            for id in 0..80u64 {
                let kept = parsed
                    .iter()
                    .any(|(_, xpath)| matches_event(xpath, &origin(Some(name), None), id));
                assert_eq!(kept, wanted.contains(&id), "{name} {id}");
            }
        }
    }

    #[test]
    fn computer_names_are_quoted_safely_or_refused() {
        let build = |name: &str| {
            build_subset_query(
                EvtxSubsetSourceKind::Channel,
                "S",
                &[on(name, vec![range(1, 1)])],
            )
        };
        assert_eq!(
            build("O'Brien-PC").unwrap().text,
            "*[System[Computer=\"O'Brien-PC\" and EventRecordID=1]]"
        );
        assert!(build("HOST.contoso.com")
            .unwrap()
            .text
            .contains("'HOST.contoso.com'"));
        // XPath 1.0 has no escape inside a literal, so a name with both quotes cannot be written.
        let error = build("a'b\"c").unwrap_err();
        assert!(error.contains("cannot be written in a query"), "{error}");
        assert!(build("a\nb").is_err());
        // In a structured query the XML-special characters of a name are escaped in the text.
        let many: Vec<RecordIdRange> = (0..30).map(|n| range(n * 2, n * 2)).collect();
        let structured =
            build_subset_query(EvtxSubsetSourceKind::Channel, "S", &[on("A&B<C>", many)]).unwrap();
        assert!(structured.text.contains("Computer='A&amp;B&lt;C&gt;'"));
        assert!(selects(&structured.text)[0].1.contains("Computer='A&B<C>'"));
    }

    // ---- naming -----------------------------------------------------------------------------

    fn assert_single_component(name: &str) {
        let path = Path::new(name);
        assert_eq!(path.components().count(), 1, "{name}");
        assert!(!name.contains('/') && !name.contains('\\'), "{name}");
        assert_ne!(name, ".");
        assert_ne!(name, "..");
        assert!(!name.chars().any(char::is_control), "{name:?}");
    }

    #[test]
    fn sanitized_labels_cannot_leave_the_folder() {
        for hostile in [
            "../../evil",
            "..\\..\\evil",
            "/etc/passwd",
            "C:\\Windows\\System32\\config",
            "\\\\server\\share\\x",
            "a/b:c*d?e\"f<g>h|i",
            "..",
            ".",
            "",
            "   ",
            "evil\u{202e}gpj.exe",
            "tab\tand\nnewline\0nul",
        ] {
            let label = sanitize_label(hostile);
            let name = output_file_name(&label, 1);
            assert_single_component(&name);
            assert!(name.ends_with("-subset.evtx"), "{name}");
            assert!(!label.contains(".."), "{hostile:?} -> {label:?}");
        }
    }

    #[test]
    fn labels_follow_the_spec_for_ordinary_names() {
        assert_eq!(
            sanitize_label("Microsoft-Windows-AAD/Operational"),
            "Microsoft-Windows-AAD-Operational"
        );
        assert_eq!(sanitize_label("Application"), "Application");
        assert_eq!(
            output_file_name(&sanitize_label("Application"), 1),
            "Application-subset.evtx"
        );
    }

    #[test]
    fn trailing_dots_spaces_and_reserved_device_names_are_handled() {
        assert_eq!(sanitize_label("name. . "), "name");
        assert_eq!(sanitize_label("NUL"), "_NUL");
        assert_eq!(sanitize_label("nul.x"), "_nul.x");
        assert_eq!(sanitize_label("COM1"), "_COM1");
        assert_eq!(sanitize_label("lpt9"), "_lpt9");
        assert_eq!(sanitize_label("COM10"), "COM10");
        assert_eq!(sanitize_label("CONSOLE"), "CONSOLE");
        assert_eq!(sanitize_label("\u{FEFF}"), "events");
    }

    #[test]
    fn long_labels_are_capped() {
        let label = sanitize_label(&"x".repeat(500));
        assert_eq!(label.chars().count(), LABEL_MAX_CHARS);
        let wide = sanitize_label(&"\u{4e2d}".repeat(500));
        assert_eq!(wide.chars().count(), LABEL_MAX_CHARS);
    }

    #[test]
    fn a_file_source_is_named_by_its_stem_whatever_the_host_separator() {
        use EvtxSubsetSourceKind::File;
        assert_eq!(source_label(File, "C:\\logs\\System.evtx"), "System");
        assert_eq!(source_label(File, "/var/log/System.EVTX"), "System");
        assert_eq!(source_label(File, "D:\\x\\my.log.evtx"), "my.log");
        assert_eq!(source_label(File, "D:\\x\\noext"), "noext");
        assert_eq!(source_label(File, "D:\\x\\.evtx"), "events");
        assert_eq!(
            source_label(
                EvtxSubsetSourceKind::Channel,
                "Microsoft-Windows-AAD/Operational"
            ),
            "Microsoft-Windows-AAD-Operational"
        );
    }

    #[test]
    fn names_that_collide_are_numbered_in_request_order_case_insensitively() {
        let labels: Vec<String> = ["Application", "application", "System", "Application"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(
            assign_unique_file_names(&labels),
            vec![
                "Application-subset.evtx",
                "application-2-subset.evtx",
                "System-subset.evtx",
                "Application-3-subset.evtx",
            ]
        );
    }

    // ---- folder and plan --------------------------------------------------------------------

    fn group_of(
        computer: Option<&str>,
        channel: Option<&str>,
        record_ids: &[u64],
    ) -> EvtxSubsetRecordGroup {
        EvtxSubsetRecordGroup {
            computer: computer.map(str::to_string),
            channel: channel.map(str::to_string),
            record_ids: ids(record_ids),
        }
    }

    fn group(computer: Option<&str>, record_ids: &[u64]) -> EvtxSubsetRecordGroup {
        group_of(computer, None, record_ids)
    }

    fn group_in(computer: &str, channel: &str, record_ids: &[u64]) -> EvtxSubsetRecordGroup {
        group_of(Some(computer), Some(channel), record_ids)
    }

    fn channel(name: &str, record_ids: &[u64]) -> EvtxSubsetSource {
        EvtxSubsetSource {
            kind: EvtxSubsetSourceKind::Channel,
            path: name.to_string(),
            record_groups: vec![group(None, record_ids)],
        }
    }

    fn channel_with(name: &str, record_groups: Vec<EvtxSubsetRecordGroup>) -> EvtxSubsetSource {
        EvtxSubsetSource {
            kind: EvtxSubsetSourceKind::Channel,
            path: name.to_string(),
            record_groups,
        }
    }

    fn file_source(path: &Path, record_ids: &[u64]) -> EvtxSubsetSource {
        EvtxSubsetSource {
            kind: EvtxSubsetSourceKind::File,
            path: path.to_string_lossy().into_owned(),
            record_groups: vec![group(None, record_ids)],
        }
    }

    /// The sources a plan will export, in request order.
    fn ready(plan: &SubsetPlan) -> Vec<&PlannedExport> {
        plan.entries
            .iter()
            .filter_map(|entry| match entry {
                PlanEntry::Ready(export) => Some(export),
                PlanEntry::Failed(_) => None,
            })
            .collect()
    }

    fn failure(plan: &SubsetPlan, index: usize) -> &FailedSource {
        match &plan.entries[index] {
            PlanEntry::Failed(failed) => failed,
            PlanEntry::Ready(_) => panic!("entry {index} was planned, expected a failure"),
        }
    }

    fn folder_str(dir: &tempfile::TempDir) -> String {
        dir.path().to_string_lossy().into_owned()
    }

    #[test]
    fn the_output_folder_must_be_an_existing_absolute_directory() {
        let dir = tempfile::tempdir().unwrap();
        assert!(validate_output_folder(&folder_str(&dir)).is_ok());
        assert!(validate_output_folder("").is_err());
        assert!(validate_output_folder("   ").is_err());
        assert!(validate_output_folder("relative/dir").is_err());
        assert!(validate_output_folder(&format!("{}/missing", folder_str(&dir))).is_err());
        let file = dir.path().join("a.txt");
        fs::write(&file, b"x").unwrap();
        let error = validate_output_folder(&file.to_string_lossy()).unwrap_err();
        assert!(error.contains("not a folder"), "{error}");
        assert!(validate_output_folder(&format!("{}\n", folder_str(&dir))).is_err());
    }

    #[test]
    fn a_plan_names_one_file_per_source_inside_the_folder() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("src").join("Setup.evtx");
        fs::create_dir_all(log.parent().unwrap()).unwrap();
        fs::write(&log, b"evtx").unwrap();
        let out = tempfile::tempdir().unwrap();
        let plan = plan_subset_export(
            &folder_str(&out),
            &[
                channel("Microsoft-Windows-AAD/Operational", &[3, 4, 5, 9]),
                file_source(&log, &[1, 2]),
            ],
        )
        .unwrap();
        let exports = ready(&plan);
        let names: Vec<&str> = exports.iter().map(|e| e.file_name.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "Microsoft-Windows-AAD-Operational-subset.evtx",
                "Setup-subset.evtx"
            ]
        );
        for export in &exports {
            assert_eq!(export.target.parent(), Some(out.path()));
        }
        assert_eq!(exports[0].requested, 4);
        assert_eq!(exports[1].requested, 2);
        assert!(plan.archive_blocked.is_none());
    }

    #[test]
    fn a_request_is_refused_before_any_work_when_a_target_name_is_taken() {
        let out = tempfile::tempdir().unwrap();
        fs::write(out.path().join("System-subset.evtx"), b"previous export").unwrap();
        let error = plan_subset_export(
            &folder_str(&out),
            &[channel("Application", &[1]), channel("System", &[1])],
        )
        .unwrap_err();
        assert!(error.contains("System-subset.evtx"), "{error}");
        assert!(error.contains("never overwritten"), "{error}");
        assert!(!error.contains("Application-subset.evtx"), "{error}");
        // The existing file is untouched.
        assert_eq!(
            fs::read(out.path().join("System-subset.evtx")).unwrap(),
            b"previous export"
        );
    }

    #[test]
    fn a_folder_or_link_at_a_target_name_also_counts_as_taken() {
        let out = tempfile::tempdir().unwrap();
        fs::create_dir(out.path().join("System-subset.evtx")).unwrap();
        assert!(plan_subset_export(&folder_str(&out), &[channel("System", &[1])]).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn a_dangling_link_at_a_target_name_counts_as_taken() {
        let out = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(
            out.path().join("does-not-exist"),
            out.path().join("System-subset.evtx"),
        )
        .unwrap();
        assert!(plan_subset_export(&folder_str(&out), &[channel("System", &[1])]).is_err());
    }

    #[test]
    fn an_output_can_never_be_the_source_it_was_made_from() {
        let out = tempfile::tempdir().unwrap();
        // Re-exporting a previous subset names the new file after the old one's full stem, so it
        // lands beside it rather than on it.
        let previous = out.path().join("System-subset.evtx");
        fs::write(&previous, b"evtx").unwrap();
        let plan = plan_subset_export(&folder_str(&out), &[file_source(&previous, &[1])]).unwrap();
        assert_eq!(ready(&plan)[0].file_name, "System-subset-subset.evtx");
        assert_ne!(ready(&plan)[0].target, previous);

        // A source that already holds the name a collision would give the second export
        // (`System-2-subset.evtx`) is refused as an existing target, not overwritten.
        let other = tempfile::tempdir().unwrap();
        let first = other.path().join("System.evtx");
        fs::write(&first, b"evtx").unwrap();
        let second = out.path().join("System.evtx");
        fs::write(&second, b"evtx").unwrap();
        let colliding = out.path().join("System-2-subset.evtx");
        fs::write(&colliding, b"evtx").unwrap();
        let error = plan_subset_export(
            &folder_str(&out),
            &[file_source(&first, &[1]), file_source(&second, &[1])],
        )
        .unwrap_err();
        assert!(error.contains("System-2-subset.evtx"), "{error}");
        assert_eq!(fs::read(&colliding).unwrap(), b"evtx");
    }

    #[test]
    fn problems_with_the_request_itself_refuse_it_whole_before_anything_is_written() {
        let out = tempfile::tempdir().unwrap();
        let folder = folder_str(&out);
        // No sources at all.
        assert!(plan_subset_export(&folder, &[]).is_err());
        // The same source twice, whatever its case.
        let error =
            plan_subset_export(&folder, &[channel("System", &[1]), channel("SYSTEM", &[2])])
                .unwrap_err();
        assert!(error.contains("listed more than once"), "{error}");
        // An unusable output folder.
        assert!(plan_subset_export("relative/dir", &[channel("System", &[1])]).is_err());
        assert!(
            plan_subset_export(&format!("{folder}/missing"), &[channel("System", &[1])]).is_err()
        );
        assert_eq!(fs::read_dir(out.path()).unwrap().count(), 0);
    }

    #[test]
    fn a_problem_with_one_source_fails_that_source_and_plans_the_rest() {
        let out = tempfile::tempdir().unwrap();
        let folder = folder_str(&out);
        let sources_dir = tempfile::tempdir().unwrap();
        let wrong_extension = sources_dir.path().join("notes.txt");
        fs::write(&wrong_extension, b"x").unwrap();
        let missing = sources_dir.path().join("Unplugged.evtx");
        let mut bad_id = channel("BadId", &[1]);
        bad_id.record_groups[0]
            .record_ids
            .push("not a number".into());
        let mut zero_id = channel("ZeroId", &[1]);
        zero_id.record_groups[0].record_ids.push("0".into());
        let fragmented = channel(
            "Fragmented",
            &(0..=MAX_RANGES_PER_SOURCE as u64)
                .map(|n| n * 2 + 1)
                .collect::<Vec<_>>(),
        );
        let sources = vec![
            channel("System", &[1, 2]),
            file_source(&missing, &[1]),
            file_source(&wrong_extension, &[1]),
            EvtxSubsetSource {
                kind: EvtxSubsetSourceKind::File,
                path: "Relative.evtx".into(),
                record_groups: vec![group(None, &[1])],
            },
            bad_id,
            zero_id,
            channel_with("NoIds", vec![group(None, &[])]),
            channel_with("NoGroups", vec![]),
            channel("", &[1]),
            channel("Sys\0tem", &[1]),
            fragmented,
            channel_with("BadName", vec![group(Some("a'b\"c"), &[1])]),
            channel_with("Controls", vec![group(Some("a\nb"), &[1])]),
            channel_with(
                "Mixed",
                vec![group(Some("HOST-A"), &[1]), group(None, &[2])],
            ),
            channel("Application", &[7]),
        ];
        let plan = plan_subset_export(&folder, &sources).unwrap();

        assert_eq!(
            plan.entries.len(),
            sources.len(),
            "one entry per source, in order"
        );
        let expectations = [
            (1, "cannot read the source file"),
            (2, "only .evtx files"),
            (3, "must be an absolute path"),
            (4, "is not a decimal EventRecordID"),
            (5, "not an identity"),
            (6, "no record IDs"),
            (7, "no events were given"),
            (8, "empty or invalid name"),
            (9, "empty or invalid name"),
            (10, "Narrow the filter"),
            (11, "cannot be written in a query"),
            (12, "control characters"),
            (13, "carry no computer or channel name"),
        ];
        for (index, expected) in expectations {
            let failed = failure(&plan, index);
            assert!(
                failed.error.contains(expected),
                "entry {index}: {}",
                failed.error
            );
            assert_eq!(failed.source_path, sources[index].path);
        }
        // The good sources are still planned, with their own names.
        let exports = ready(&plan);
        assert_eq!(
            exports
                .iter()
                .map(|e| e.file_name.as_str())
                .collect::<Vec<_>>(),
            vec!["System-subset.evtx", "Application-subset.evtx"]
        );
        // The row of a failed source still says how many well-formed events it asked for.
        assert_eq!(failure(&plan, 1).requested, 1);
        assert_eq!(failure(&plan, 4).requested, 1);
        assert_eq!(failure(&plan, 5).requested, 1);
        // Planning wrote nothing.
        assert_eq!(fs::read_dir(out.path()).unwrap().count(), 0);
    }

    #[test]
    fn only_the_files_that_would_be_written_can_collide_with_an_existing_one() {
        let out = tempfile::tempdir().unwrap();
        // The name a failed source would have had is taken, which does not matter: it is not
        // written.
        fs::write(out.path().join("Gone-subset.evtx"), b"older").unwrap();
        let plan = plan_subset_export(
            &folder_str(&out),
            &[
                file_source(&out.path().join("Gone.evtx"), &[1]),
                channel("System", &[1]),
            ],
        )
        .unwrap();
        assert!(matches!(plan.entries[0], PlanEntry::Failed(_)));
        assert!(matches!(plan.entries[1], PlanEntry::Ready(_)));
    }

    #[test]
    fn events_are_counted_by_computer_and_id_and_a_computer_listed_twice_is_merged() {
        let out = tempfile::tempdir().unwrap();
        let plan = plan_subset_export(
            &folder_str(&out),
            &[channel_with(
                "ForwardedEvents",
                vec![
                    group(Some("HOST-A"), &[100, 101]),
                    group(Some("HOST-B"), &[100]),
                    // Listed again: merged with the first, and 101 is not counted twice.
                    group(Some("HOST-A"), &[101, 102]),
                ],
            )],
        )
        .unwrap();
        let export = ready(&plan)[0];
        // A: 100..=102, B: 100, so four distinct events although two machines share ID 100.
        assert_eq!(export.requested, 4);
        assert_eq!(export.groups.len(), 2);
        assert_eq!(export.groups[0].origin.computer.as_deref(), Some("HOST-A"));
        assert_eq!(export.groups[0].ranges, vec![range(100, 102)]);
        assert!(export.query.text.contains("Computer='HOST-B'"));

        let blank = plan_subset_export(
            &folder_str(&out),
            &[channel_with("System", vec![group(Some("   "), &[1])])],
        )
        .unwrap();
        assert_eq!(ready(&blank)[0].groups[0].origin.computer, None);
        assert!(!ready(&blank)[0].query.text.contains("Computer"));
    }

    #[test]
    fn two_source_logs_of_one_machine_are_two_requested_events() {
        let out = tempfile::tempdir().unwrap();
        let plan = plan_subset_export(
            &folder_str(&out),
            &[channel_with(
                "ForwardedEvents",
                vec![
                    group_in("HOST-A", "System", &[100]),
                    group_in("HOST-A", "Security", &[100]),
                    // Listed again: merged with the first group, 100 is not counted twice.
                    group_in("HOST-A", "System", &[101, 100]),
                    // No channel to speak of is no channel, not a channel named by blanks.
                    group_of(Some("HOST-B"), Some("   "), &[7]),
                ],
            )],
        )
        .unwrap();
        let export = ready(&plan)[0];
        // System 100 and 101, Security 100, and HOST-B 7.
        assert_eq!(export.requested, 4);
        assert_eq!(export.groups.len(), 3);
        assert_eq!(
            export.groups[0].origin,
            origin(Some("HOST-A"), Some("System"))
        );
        assert_eq!(export.groups[0].ranges, vec![range(100, 101)]);
        assert_eq!(
            export.groups[1].origin,
            origin(Some("HOST-A"), Some("Security"))
        );
        assert_eq!(export.groups[2].origin, origin(Some("HOST-B"), None));
        let wanted = |channel: &str, id| {
            matches_event(
                &export.query.text,
                &origin(Some("HOST-A"), Some(channel)),
                id,
            )
        };
        assert!(wanted("System", 101) && wanted("Security", 100));
        assert!(!wanted("Security", 101), "{}", export.query.text);
    }

    #[test]
    fn a_filter_that_hid_one_twin_requests_only_the_visible_one() {
        let out = tempfile::tempdir().unwrap();
        let plan = plan_subset_export(
            &folder_str(&out),
            &[channel_with(
                "ForwardedEvents",
                vec![group_in("HOST-A", "System", &[100])],
            )],
        )
        .unwrap();
        let export = ready(&plan)[0];
        assert_eq!(export.requested, 1);
        let hidden = origin(Some("HOST-A"), Some("Security"));
        assert!(!matches_event(&export.query.text, &hidden, 100));
    }

    #[test]
    fn events_that_cannot_be_told_apart_refuse_the_source_and_those_that_can_do_not() {
        let out = tempfile::tempdir().unwrap();
        let refused = |groups: Vec<EvtxSubsetRecordGroup>| {
            let plan = plan_subset_export(&folder_str(&out), &[channel_with("Forwarded", groups)])
                .unwrap();
            match &plan.entries[0] {
                PlanEntry::Failed(failed) => {
                    assert!(failed.error.contains("told apart"), "{}", failed.error);
                    true
                }
                PlanEntry::Ready(_) => false,
            }
        };
        // A group that names no computer also matches the named machine's events in that log.
        assert!(refused(vec![
            group_of(None, Some("System"), &[1]),
            group_in("HOST-A", "System", &[1]),
        ]));
        // The same for a group that names no channel.
        assert!(refused(vec![
            group_of(Some("HOST-A"), None, &[1]),
            group_in("HOST-A", "System", &[1]),
        ]));
        // Groups that differ where both name a value are told apart by the query.
        assert!(!refused(vec![
            group_of(None, Some("System"), &[1]),
            group_of(None, Some("Security"), &[1]),
        ]));
        assert!(!refused(vec![
            group_of(Some("HOST-A"), None, &[1]),
            group_of(Some("HOST-B"), None, &[1]),
        ]));
        assert!(!refused(vec![
            group_in("HOST-A", "System", &[1]),
            group_in("HOST-B", "Security", &[1]),
        ]));
    }

    #[test]
    fn a_failed_source_still_counts_the_events_of_each_log() {
        let out = tempfile::tempdir().unwrap();
        let mut bad = group_of(Some("HOST-B"), None, &[]);
        bad.record_ids.push("not a number".into());
        let plan = plan_subset_export(
            &folder_str(&out),
            &[channel_with(
                "ForwardedEvents",
                vec![
                    group_in("HOST-A", "System", &[100]),
                    group_in("HOST-A", "Security", &[100]),
                    bad,
                ],
            )],
        )
        .unwrap();
        assert_eq!(failure(&plan, 0).requested, 2);
    }

    #[test]
    fn a_group_deserializes_from_the_shape_the_frontend_sends() {
        let group: EvtxSubsetRecordGroup = serde_json::from_str(
            r#"{"computer":"HOST-A","channel":"System","recordIds":["1","2"]}"#,
        )
        .unwrap();
        assert_eq!(group.computer.as_deref(), Some("HOST-A"));
        assert_eq!(group.channel.as_deref(), Some("System"));
        assert_eq!(group.record_ids, vec!["1", "2"]);
        let named_nothing: EvtxSubsetRecordGroup =
            serde_json::from_str(r#"{"computer":null,"channel":null,"recordIds":["3"]}"#).unwrap();
        assert_eq!(
            (named_nothing.computer, named_nothing.channel),
            (None, None)
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_linked_locale_folder_blocks_archiving_instead_of_following_it() {
        let out = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(elsewhere.path(), out.path().join(LOCALE_METADATA_DIR)).unwrap();
        let plan = plan_subset_export(&folder_str(&out), &[channel("System", &[1])]).unwrap();
        let reason = plan.archive_blocked.expect("archiving is blocked");
        assert!(reason.contains("is a link"), "{reason}");
    }

    #[test]
    fn a_real_locale_folder_does_not_block_archiving() {
        let out = tempfile::tempdir().unwrap();
        fs::create_dir(out.path().join(LOCALE_METADATA_DIR)).unwrap();
        let plan = plan_subset_export(&folder_str(&out), &[channel("System", &[1])]).unwrap();
        assert!(plan.archive_blocked.is_none());
    }

    // ---- execution with a fake backend ------------------------------------------------------

    #[derive(Default)]
    struct FakeBackend {
        /// Source path -> outcome of `export_log`: Ok writes a file, Err returns the message.
        export_failures: HashMap<String, (String, bool)>,
        /// Partial file written before a failure.
        write_partial_on_failure: bool,
        archive_error: Option<String>,
        /// Output file name -> what reading that file back finds.
        reads: HashMap<String, Result<Vec<ReadBackRecord>, String>>,
        calls: RefCell<Vec<String>>,
    }

    impl SubsetBackend for FakeBackend {
        fn export_log(&self, export: &PlannedExport) -> Result<(), ExportLogError> {
            self.calls
                .borrow_mut()
                .push(format!("export:{}", export.file_name));
            if let Some((message, already_exists)) = self.export_failures.get(&export.source_path) {
                if self.write_partial_on_failure {
                    fs::write(&export.target, b"partial").unwrap();
                }
                return Err(ExportLogError {
                    message: message.clone(),
                    already_exists: *already_exists,
                });
            }
            fs::write(&export.target, b"evtx").unwrap();
            Ok(())
        }

        fn archive_log(&self, target: &Path) -> Result<(), String> {
            self.calls.borrow_mut().push(format!(
                "archive:{}",
                target.file_name().unwrap().to_string_lossy()
            ));
            match &self.archive_error {
                Some(error) => Err(error.clone()),
                None => Ok(()),
            }
        }

        fn read_back(&self, target: &Path) -> Result<Vec<ReadBackRecord>, String> {
            let key = target.file_name().unwrap().to_string_lossy().into_owned();
            self.reads.get(&key).cloned().unwrap_or(Ok(Vec::new()))
        }
    }

    fn plan_for(out: &tempfile::TempDir, sources: &[EvtxSubsetSource]) -> SubsetPlan {
        plan_subset_export(&folder_str(out), sources).unwrap()
    }

    /// Events with no computer and no channel, as an anonymous file would hold them.
    fn found(ids: &[u64]) -> Result<Vec<ReadBackRecord>, String> {
        Ok(ids
            .iter()
            .map(|&id| ReadBackRecord {
                id,
                origin: EventOrigin::default(),
            })
            .collect())
    }

    fn found_on(computer: &str, ids: &[u64]) -> Vec<ReadBackRecord> {
        ids.iter()
            .map(|&id| ReadBackRecord {
                id,
                origin: origin(Some(computer), None),
            })
            .collect()
    }

    fn found_in(computer: &str, channel: &str, ids: &[u64]) -> Vec<ReadBackRecord> {
        ids.iter()
            .map(|&id| ReadBackRecord {
                id,
                origin: origin(Some(computer), Some(channel)),
            })
            .collect()
    }

    fn reads(
        pairs: Vec<(&str, Result<Vec<ReadBackRecord>, String>)>,
    ) -> HashMap<String, Result<Vec<ReadBackRecord>, String>> {
        pairs
            .into_iter()
            .map(|(name, read)| (name.to_string(), read))
            .collect()
    }

    fn none_missing() -> Option<EvtxSubsetIdDifference> {
        Some(EvtxSubsetIdDifference {
            count: 0,
            sample: vec![],
        })
    }

    #[test]
    fn a_clean_export_reports_the_verified_events_and_archives_the_messages() {
        let out = tempfile::tempdir().unwrap();
        let plan = plan_for(
            &out,
            &[channel("System", &[1, 2, 3]), channel("Application", &[7])],
        );
        let backend = FakeBackend {
            reads: reads(vec![
                ("System-subset.evtx", found(&[1, 2, 3])),
                ("Application-subset.evtx", found(&[7])),
            ]),
            ..Default::default()
        };
        let result = run_plan(&plan, &backend);
        assert_eq!(result.files.len(), 2);
        for file in &result.files {
            assert_eq!(file.status, EvtxSubsetFileStatus::Exported);
            assert_eq!(file.exported_records, Some(file.requested_records));
            assert_eq!(file.missing, none_missing());
            assert_eq!(file.unrequested, none_missing());
            assert!(file.messages_archived);
            assert!(file.error.is_none());
            assert!(file.warnings.is_empty(), "{:?}", file.warnings);
            assert!(Path::new(&file.output_path).exists());
        }
        // The files were archived after being exported, one at a time.
        assert_eq!(
            *backend.calls.borrow(),
            vec![
                "export:System-subset.evtx",
                "archive:System-subset.evtx",
                "export:Application-subset.evtx",
                "archive:Application-subset.evtx",
            ]
        );
    }

    #[test]
    fn one_source_failing_does_not_stop_the_others_and_leaves_no_partial_file() {
        let out = tempfile::tempdir().unwrap();
        let plan = plan_for(
            &out,
            &[channel("Security", &[1]), channel("System", &[1, 2])],
        );
        let mut backend = FakeBackend {
            write_partial_on_failure: true,
            reads: reads(vec![("System-subset.evtx", found(&[1, 2]))]),
            ..Default::default()
        };
        backend.export_failures.insert(
            "Security".into(),
            (
                "EvtExportLog: access denied (needs elevation)".into(),
                false,
            ),
        );
        let result = run_plan(&plan, &backend);
        assert_eq!(result.files[0].status, EvtxSubsetFileStatus::Failed);
        assert!(result.files[0]
            .error
            .as_deref()
            .unwrap()
            .contains("access denied"));
        assert_eq!(result.files[0].exported_records, None);
        assert!(!out.path().join("Security-subset.evtx").exists());
        assert_eq!(result.files[1].status, EvtxSubsetFileStatus::Exported);
        assert!(out.path().join("System-subset.evtx").exists());
    }

    #[test]
    fn a_source_that_cannot_be_planned_is_a_failed_row_and_the_others_are_still_exported() {
        // The USB drive holding Setup.evtx was unplugged after the list was filtered.
        let out = tempfile::tempdir().unwrap();
        let unplugged = out.path().join("not-plugged-in").join("Setup.evtx");
        let sources = vec![
            channel("System", &[1, 2]),
            file_source(&unplugged, &[5]),
            channel("Application", &[7]),
        ];
        let plan = plan_for(&out, &sources);
        let backend = FakeBackend {
            reads: reads(vec![
                ("System-subset.evtx", found(&[1, 2])),
                ("Application-subset.evtx", found(&[7])),
            ]),
            ..Default::default()
        };
        let result = run_plan(&plan, &backend);

        // One row per source, in request order, with the kind and path the request gave.
        assert_eq!(result.files.len(), 3);
        for (file, source) in result.files.iter().zip(&sources) {
            assert_eq!(file.source_path, source.path);
            assert_eq!(file.kind, source.kind);
        }
        assert_eq!(result.files[0].status, EvtxSubsetFileStatus::Exported);
        assert_eq!(result.files[2].status, EvtxSubsetFileStatus::Exported);
        let failed = &result.files[1];
        assert_eq!(failed.status, EvtxSubsetFileStatus::Failed);
        assert!(failed
            .error
            .as_deref()
            .unwrap()
            .contains("cannot read the source file"));
        assert_eq!(failed.requested_records, 1);
        assert_eq!(failed.exported_records, None);
        assert!(!Path::new(&failed.output_path).exists());
        // The service was never asked to export the source that could not be planned.
        assert_eq!(
            *backend.calls.borrow(),
            vec![
                "export:System-subset.evtx",
                "archive:System-subset.evtx",
                "export:Application-subset.evtx",
                "archive:Application-subset.evtx",
            ]
        );
    }

    #[test]
    fn a_file_that_appeared_after_planning_is_never_replaced_or_deleted() {
        let out = tempfile::tempdir().unwrap();
        let plan = plan_for(&out, &[channel("System", &[1])]);
        fs::write(out.path().join("System-subset.evtx"), b"someone else's").unwrap();
        let backend = FakeBackend::default();
        let result = run_plan(&plan, &backend);
        assert_eq!(result.files[0].status, EvtxSubsetFileStatus::Failed);
        assert!(result.files[0]
            .error
            .as_deref()
            .unwrap()
            .contains("never overwritten"));
        assert!(
            backend.calls.borrow().is_empty(),
            "the API must not be called"
        );
        assert_eq!(
            fs::read(out.path().join("System-subset.evtx")).unwrap(),
            b"someone else's"
        );
    }

    #[test]
    fn when_the_service_reports_the_target_exists_the_existing_file_is_kept() {
        let out = tempfile::tempdir().unwrap();
        let plan = plan_for(&out, &[channel("System", &[1])]);
        let mut backend = FakeBackend::default();
        backend
            .export_failures
            .insert("System".into(), ("EvtExportLog: exists".into(), true));
        // The file appears between the in-process check and the service call.
        struct Racing(FakeBackend);
        impl SubsetBackend for Racing {
            fn export_log(&self, export: &PlannedExport) -> Result<(), ExportLogError> {
                fs::write(&export.target, b"raced in").unwrap();
                self.0.export_log(export)
            }
            fn archive_log(&self, target: &Path) -> Result<(), String> {
                self.0.archive_log(target)
            }
            fn read_back(&self, target: &Path) -> Result<Vec<ReadBackRecord>, String> {
                self.0.read_back(target)
            }
        }
        let result = run_plan(&plan, &Racing(backend));
        assert_eq!(result.files[0].status, EvtxSubsetFileStatus::Failed);
        assert_eq!(
            fs::read(out.path().join("System-subset.evtx")).unwrap(),
            b"raced in",
            "a file the service said already existed is not ours to delete"
        );
    }

    #[test]
    fn an_archive_failure_keeps_the_file_and_says_the_messages_are_missing() {
        let out = tempfile::tempdir().unwrap();
        let plan = plan_for(&out, &[channel("System", &[1, 2])]);
        let backend = FakeBackend {
            archive_error: Some("EvtArchiveExportedLog: not found".into()),
            reads: reads(vec![("System-subset.evtx", found(&[1, 2]))]),
            ..Default::default()
        };
        let file = &run_plan(&plan, &backend).files[0];
        assert_eq!(file.status, EvtxSubsetFileStatus::Exported);
        assert!(!file.messages_archived);
        assert_eq!(file.exported_records, Some(2));
        assert!(file.warnings.iter().any(|w| w.contains("not archived")));
        assert!(out.path().join("System-subset.evtx").exists());
    }

    #[cfg(unix)]
    #[test]
    fn a_blocked_locale_folder_skips_the_archive_call_and_says_so() {
        let out = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(elsewhere.path(), out.path().join(LOCALE_METADATA_DIR)).unwrap();
        let plan = plan_for(&out, &[channel("System", &[1])]);
        let backend = FakeBackend {
            reads: reads(vec![("System-subset.evtx", found(&[1]))]),
            ..Default::default()
        };
        let file = &run_plan(&plan, &backend).files[0];
        assert_eq!(file.status, EvtxSubsetFileStatus::Exported);
        assert!(!file.messages_archived);
        assert!(file.warnings.iter().any(|w| w.contains("is a link")));
        assert!(backend
            .calls
            .borrow()
            .iter()
            .all(|call| !call.starts_with("archive")));
    }

    #[test]
    fn archiving_is_skipped_for_a_file_whose_name_already_has_an_entry_in_locale_metadata() {
        let out = tempfile::tempdir().unwrap();
        let locale = out.path().join(LOCALE_METADATA_DIR);
        fs::create_dir(&locale).unwrap();
        // What an earlier export of a file with this name left behind, in any case.
        let earlier = locale.join("SYSTEM-subset_1033.MTA");
        fs::write(&earlier, b"earlier archive").unwrap();
        let plan = plan_for(
            &out,
            &[channel("System", &[1]), channel("Application", &[7])],
        );
        let backend = FakeBackend {
            reads: reads(vec![
                ("System-subset.evtx", found(&[1])),
                ("Application-subset.evtx", found(&[7])),
            ]),
            ..Default::default()
        };
        let result = run_plan(&plan, &backend);

        let system = &result.files[0];
        assert_eq!(system.status, EvtxSubsetFileStatus::Exported);
        assert_eq!(system.exported_records, Some(1));
        assert!(!system.messages_archived);
        let warning = system.warnings.join(" | ");
        assert!(
            warning.contains("already holds an entry for System-subset.evtx"),
            "{warning}"
        );
        assert!(warning.contains("not archived"), "{warning}");
        // The other file in the same request is archived as usual.
        assert!(result.files[1].messages_archived);
        assert!(result.files[1].warnings.is_empty());
        assert_eq!(
            *backend.calls.borrow(),
            vec![
                "export:System-subset.evtx",
                "export:Application-subset.evtx",
                "archive:Application-subset.evtx",
            ]
        );
        // Nothing that was there was overwritten.
        assert_eq!(fs::read(&earlier).unwrap(), b"earlier archive");
    }

    #[test]
    fn an_entry_for_another_name_does_not_block_archiving() {
        let out = tempfile::tempdir().unwrap();
        let locale = out.path().join(LOCALE_METADATA_DIR);
        fs::create_dir(&locale).unwrap();
        // The archive of `System-subset-subset.evtx` starts with this file's stem but is not its
        // entry, and neither is an unrelated name.
        fs::write(locale.join("System-subset-subset_1033.MTA"), b"other").unwrap();
        fs::write(locale.join("Application_1033.MTA"), b"other").unwrap();
        let plan = plan_for(&out, &[channel("System", &[1])]);
        let backend = FakeBackend {
            reads: reads(vec![("System-subset.evtx", found(&[1]))]),
            ..Default::default()
        };
        let file = &run_plan(&plan, &backend).files[0];
        assert!(file.messages_archived, "{:?}", file.warnings);
        assert!(file.warnings.is_empty(), "{:?}", file.warnings);
    }

    #[test]
    fn a_locale_folder_that_cannot_be_read_skips_archiving_instead_of_guessing() {
        let out = tempfile::tempdir().unwrap();
        // A file where the folder should be cannot be listed. (The plan blocks that case as a
        // whole; this is the check on its own.)
        fs::write(out.path().join(LOCALE_METADATA_DIR), b"not a folder").unwrap();
        let reason = locale_entry_block_reason(out.path(), "System-subset.evtx")
            .expect("an unreadable folder is not proof that nothing would be overwritten");
        assert!(reason.contains("could not be read"), "{reason}");
        // No folder yet is a different thing: nothing has been archived here.
        let empty = tempfile::tempdir().unwrap();
        assert_eq!(
            locale_entry_block_reason(empty.path(), "System-subset.evtx"),
            None
        );
    }

    // ---- what the written file holds, compared with what was asked for -----------------------

    fn exported_file(
        sources: &[EvtxSubsetSource],
        read: Result<Vec<ReadBackRecord>, String>,
    ) -> EvtxSubsetFileResult {
        let out = tempfile::tempdir().unwrap();
        let plan = plan_for(&out, sources);
        let name = ready(&plan)[0].file_name.clone();
        let backend = FakeBackend {
            reads: reads(vec![(name.as_str(), read)]),
            ..Default::default()
        };
        run_plan(&plan, &backend).files.remove(0)
    }

    #[test]
    fn a_short_file_says_which_requested_events_are_missing_and_that_nothing_extra_is_there() {
        let file = exported_file(&[channel("System", &[1, 2, 3])], found(&[1, 3]));
        assert_eq!(file.exported_records, Some(2));
        assert_eq!(file.requested_records, 3);
        assert_eq!(
            file.missing,
            Some(EvtxSubsetIdDifference {
                count: 1,
                sample: vec!["EventRecordID 2".into()]
            })
        );
        assert_eq!(file.unrequested, none_missing());
        let warning = file.warnings.join(" | ");
        assert!(
            warning.contains("1 requested event not in the file (EventRecordID 2)"),
            "{warning}"
        );
        assert!(warning.contains("wrapped or been cleared"), "{warning}");
    }

    #[test]
    fn a_file_holding_none_of_the_requested_events_says_the_query_matched_none_of_them() {
        // With a computer in the query, a mismatch on the name is a possible cause.
        let named = exported_file(
            &[channel_with(
                "System",
                vec![group(Some("HOST-A"), &[1, 2, 3])],
            )],
            found(&[]),
        );
        let warning = named.warnings.join(" | ");
        assert!(
            warning.contains("the query matched none of the 3 requested events"),
            "{warning}"
        );
        assert!(warning.contains("wrapped or been cleared"), "{warning}");
        assert!(
            warning.contains(
                "no event from HOST-A matched, so the computer name in the query may differ from \
                 the one stored in the events"
            ),
            "{warning}"
        );
        assert_eq!(named.missing.as_ref().unwrap().count, 3);

        // Without a computer there is no such cause to name.
        let unnamed = exported_file(&[channel("System", &[1, 2, 3])], found(&[]));
        let warning = unnamed.warnings.join(" | ");
        assert!(
            warning.contains("the query matched none of the 3"),
            "{warning}"
        );
        assert!(!warning.contains("computer"), "{warning}");

        // A file that holds some of them is short, which is a different account.
        let short = exported_file(
            &[channel_with(
                "System",
                vec![group(Some("HOST-A"), &[1, 2, 3])],
            )],
            Ok(found_on("HOST-A", &[1, 3])),
        );
        let warning = short.warnings.join(" | ");
        assert!(!warning.contains("matched none"), "{warning}");
        assert!(!warning.contains("computer name"), "{warning}");
        assert!(warning.contains("wrapped or been cleared"), "{warning}");
    }

    #[test]
    fn a_machine_none_of_whose_events_matched_is_named_beside_the_one_that_did() {
        // HOST-A came back whole and HOST-B not at all, from the same log in the same query. That
        // points at the name the query used for HOST-B, not at HOST-A, which is not blamed.
        let file = exported_file(
            &[channel_with(
                "ForwardedEvents",
                vec![
                    group(Some("HOST-A"), &[1, 2]),
                    group(Some("HOST-B"), &[7, 8]),
                ],
            )],
            Ok(found_on("HOST-A", &[1, 2])),
        );
        let warning = file.warnings.join(" | ");
        assert!(
            warning.contains(
                "2 requested events not in the file (EventRecordID 7 on HOST-B, \
                 EventRecordID 8 on HOST-B)"
            ),
            "{warning}"
        );
        assert!(
            warning.contains(
                "no event from HOST-B matched, so the computer name in the query may differ from \
                 the one stored in the events"
            ),
            "{warning}"
        );
        assert!(!warning.contains("no event from HOST-A"), "{warning}");
        // The log may still have wrapped, so the shortfall explanation stays.
        assert!(warning.contains("wrapped or been cleared"), "{warning}");
        assert!(!warning.contains("matched none"), "{warning}");
    }

    #[test]
    fn a_machine_that_lost_only_some_events_is_not_blamed_on_its_name() {
        let file = exported_file(
            &[channel_with(
                "ForwardedEvents",
                vec![
                    group(Some("HOST-A"), &[1, 2, 3]),
                    group(Some("HOST-B"), &[7, 8]),
                ],
            )],
            Ok([found_on("HOST-A", &[1, 3]), found_on("HOST-B", &[7, 8])].concat()),
        );
        let warning = file.warnings.join(" | ");
        assert!(
            warning.contains("1 requested event not in the file"),
            "{warning}"
        );
        assert!(!warning.contains("no event from"), "{warning}");
        assert!(!warning.contains("computer name"), "{warning}");
    }

    #[test]
    fn a_group_that_names_a_channel_in_the_query_can_blame_the_channel_name() {
        // Naming the channel is a second way for a query to match nothing, so the warning does not
        // pin it all on the computer.
        let collector = exported_file(
            &[channel_with(
                "ForwardedEvents",
                vec![group_in("HOST-A", "Security", &[1, 2])],
            )],
            found(&[]),
        );
        let warning = collector.warnings.join(" | ");
        assert!(
            warning.contains(
                "no event from HOST-A in Security matched, so the computer or channel name in \
                 the query may differ from the one stored in the events"
            ),
            "{warning}"
        );
        let channel_only = exported_file(
            &[channel_with(
                "ForwardedEvents",
                vec![group_of(None, Some("Security"), &[1])],
            )],
            found(&[]),
        );
        let warning = channel_only.warnings.join(" | ");
        assert!(
            warning.contains(
                "no event in Security matched, so the channel name in the query may differ"
            ),
            "{warning}"
        );
        assert!(!warning.contains("computer"), "{warning}");
        // The log being queried is not named in its own query, so its name cannot be the cause.
        let own_log = exported_file(
            &[channel_with(
                "System",
                vec![group_in("HOST-A", "System", &[1])],
            )],
            found(&[]),
        );
        let warning = own_log.warnings.join(" | ");
        assert!(
            warning.contains("no event from HOST-A matched"),
            "{warning}"
        );
        assert!(!warning.contains("channel name"), "{warning}");
    }

    #[test]
    fn a_shortfall_is_explained_by_what_the_source_is() {
        let channel = exported_file(&[channel("System", &[1, 2, 3])], found(&[1, 3]));
        let warning = channel.warnings.join(" | ");
        assert!(
            warning.contains("the log may have wrapped or been cleared since they were loaded"),
            "{warning}"
        );
        // A file does not wrap or get cleared; it may have been replaced or edited.
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("Setup.evtx");
        fs::write(&log, b"evtx").unwrap();
        let file = exported_file(&[file_source(&log, &[1, 2, 3])], found(&[1, 3]));
        let warning = file.warnings.join(" | ");
        assert!(
            warning.contains("the file may have changed since it was loaded"),
            "{warning}"
        );
        assert!(!warning.contains("wrapped"), "{warning}");
        assert!(!warning.contains("cleared"), "{warning}");
        let none = exported_file(&[file_source(&log, &[1, 2])], found(&[]));
        let warning = none.warnings.join(" | ");
        assert!(
            warning.contains("the query matched none of the 2 requested events"),
            "{warning}"
        );
        assert!(
            warning.contains("the file may have changed since it was loaded"),
            "{warning}"
        );
        assert!(!warning.contains("wrapped"), "{warning}");
    }

    #[test]
    fn a_single_requested_event_that_is_absent_is_also_a_query_that_matched_none() {
        let file = exported_file(&[channel("System", &[7])], found(&[]));
        let warning = file.warnings.join(" | ");
        assert!(
            warning.contains("the query matched none of the 1 requested event (EventRecordID 7)"),
            "{warning}"
        );
    }

    #[test]
    fn extra_events_are_reported_on_their_own_and_not_blamed_on_wrap_around() {
        let file = exported_file(&[channel("System", &[1])], found(&[1, 99]));
        assert_eq!(file.exported_records, Some(2));
        assert_eq!(file.missing, none_missing());
        assert_eq!(
            file.unrequested,
            Some(EvtxSubsetIdDifference {
                count: 1,
                sample: vec!["EventRecordID 99".into()]
            })
        );
        let warning = file.warnings.join(" | ");
        assert!(
            warning.contains("also holds 1 event that was not requested (EventRecordID 99)"),
            "{warning}"
        );
        assert!(warning.contains("not redacted"), "{warning}");
        // A shortfall explanation does not apply to a file with more than was asked for.
        assert!(!warning.contains("wrapped"), "{warning}");
        assert!(!warning.contains("cleared"), "{warning}");
    }

    #[test]
    fn a_file_with_the_right_count_but_other_events_is_not_reported_as_clean() {
        let file = exported_file(&[channel("System", &[1, 2])], found(&[1, 3]));
        assert_eq!(file.exported_records, Some(file.requested_records));
        assert_eq!(
            file.missing.as_ref().unwrap().sample,
            vec!["EventRecordID 2".to_string()]
        );
        assert_eq!(
            file.unrequested.as_ref().unwrap().sample,
            vec!["EventRecordID 3".to_string()]
        );
        assert_eq!(file.warnings.len(), 2, "{:?}", file.warnings);
    }

    #[test]
    fn the_same_id_on_two_machines_is_two_events() {
        let sources = [channel_with(
            "ForwardedEvents",
            vec![group(Some("HOST-A"), &[100]), group(Some("HOST-B"), &[100])],
        )];
        let mut both = found_on("HOST-A", &[100]);
        both.extend(found_on("HOST-B", &[100]));
        let clean = exported_file(&sources, Ok(both));
        assert_eq!(clean.requested_records, 2);
        assert_eq!(clean.exported_records, Some(2));
        assert_eq!(clean.missing, none_missing());
        assert_eq!(clean.unrequested, none_missing());

        // HOST-B's event is absent and another machine's event with that ID took its place.
        let mut wrong = found_on("HOST-A", &[100]);
        wrong.extend(found_on("HOST-C", &[100]));
        let file = exported_file(&sources, Ok(wrong));
        assert_eq!(file.exported_records, Some(2));
        assert_eq!(
            file.missing.as_ref().unwrap().sample,
            vec!["EventRecordID 100 on HOST-B".to_string()]
        );
        assert_eq!(
            file.unrequested.as_ref().unwrap().sample,
            vec!["EventRecordID 100 on HOST-C".to_string()]
        );
    }

    #[test]
    fn the_same_id_in_two_source_logs_is_two_events() {
        let sources = [channel_with(
            "ForwardedEvents",
            vec![
                group_in("HOST-A", "System", &[100]),
                group_in("HOST-A", "Security", &[100]),
            ],
        )];
        let mut both = found_in("HOST-A", "System", &[100]);
        both.extend(found_in("HOST-A", "Security", &[100]));
        let clean = exported_file(&sources, Ok(both));
        assert_eq!(clean.requested_records, 2);
        assert_eq!(clean.exported_records, Some(2));
        assert_eq!(clean.missing, none_missing());
        assert_eq!(clean.unrequested, none_missing());
        assert!(clean.warnings.is_empty(), "{:?}", clean.warnings);
    }

    #[test]
    fn an_event_with_the_right_machine_and_id_from_another_log_is_not_the_requested_one() {
        // The System event was asked for. The file holds the Security event with the same machine
        // and ID instead, so a comparison that ignored the channel would call this file clean.
        let file = exported_file(
            &[channel_with(
                "ForwardedEvents",
                vec![group_in("HOST-A", "System", &[100])],
            )],
            Ok(found_in("HOST-A", "Security", &[100])),
        );
        assert_eq!(file.exported_records, Some(1));
        let missing = file.missing.expect("verified");
        assert_eq!(missing.count, 1);
        assert_eq!(
            missing.sample,
            vec!["EventRecordID 100 on HOST-A in System".to_string()]
        );
        let unrequested = file.unrequested.expect("verified");
        assert_eq!(unrequested.count, 1);
        assert_eq!(
            unrequested.sample,
            vec!["EventRecordID 100 on HOST-A in Security".to_string()]
        );
    }

    #[test]
    fn a_sample_says_which_machine_and_log_an_event_is_from() {
        let sample =
            |computer: Option<&str>, channel: Option<&str>| origin(computer, channel).describe(101);
        assert_eq!(sample(None, None), "EventRecordID 101");
        assert_eq!(sample(Some("HOST-A"), None), "EventRecordID 101 on HOST-A");
        assert_eq!(sample(None, Some("System")), "EventRecordID 101 in System");
        assert_eq!(
            sample(Some("HOST-A"), Some("System")),
            "EventRecordID 101 on HOST-A in System"
        );
    }

    #[test]
    fn events_without_a_computer_group_are_matched_on_the_id_alone() {
        let file = exported_file(&[channel("System", &[5])], Ok(found_on("ANY-HOST", &[5])));
        assert_eq!(file.missing, none_missing());
        assert_eq!(file.unrequested, none_missing());
        assert!(file.warnings.is_empty());
    }

    #[test]
    fn a_second_copy_of_a_requested_event_is_an_event_nobody_asked_for() {
        let file = exported_file(&[channel("System", &[1])], found(&[1, 1]));
        assert_eq!(file.exported_records, Some(2));
        assert_eq!(file.missing, none_missing());
        assert_eq!(file.unrequested.as_ref().unwrap().count, 1);
    }

    #[test]
    fn long_differences_give_the_whole_count_and_a_capped_sample() {
        // 31 asked for and the file holds only the last: 30 are missing, which is a shortfall.
        let wanted: Vec<u64> = (1..=31).collect();
        let file = exported_file(&[channel("System", &wanted)], found(&[31]));
        let missing = file.missing.unwrap();
        assert_eq!(missing.count, 30);
        assert_eq!(missing.sample.len(), ID_SAMPLE_LIMIT);
        assert_eq!(missing.sample[0], "EventRecordID 1");
        let warning = file.warnings.join(" | ");
        assert!(
            warning.contains("30 requested events not in the file"),
            "{warning}"
        );
        assert!(warning.contains("and 10 more"), "{warning}");
    }

    #[test]
    fn a_file_that_cannot_be_read_back_is_unknown_not_clean() {
        let file = exported_file(&[channel("System", &[1])], Err("cannot open".into()));
        assert_eq!(file.status, EvtxSubsetFileStatus::Exported);
        assert_eq!(file.exported_records, None);
        assert_eq!(file.missing, None);
        assert_eq!(file.unrequested, None);
        assert!(file
            .warnings
            .iter()
            .any(|w| w.contains("could not be verified")));
    }

    #[test]
    fn the_comparison_itself_orders_and_samples_deterministically() {
        let groups = one(vec![range(1, 3)]);
        let actual = found(&[9, 2, 7]).unwrap();
        let comparison = compare_read_back(&groups, &actual);
        assert_eq!(comparison.exported, 3);
        assert_eq!(
            comparison.missing.sample,
            vec!["EventRecordID 1".to_string(), "EventRecordID 3".to_string()]
        );
        assert_eq!(
            comparison.unrequested.sample,
            vec!["EventRecordID 7".to_string(), "EventRecordID 9".to_string()]
        );
    }

    // ---- error mapping and platform ---------------------------------------------------------

    #[test]
    fn the_win32_hints_name_elevation_and_existing_targets() {
        assert!(win32_hint(5).unwrap().contains("elevated"));
        assert!(win32_hint(15007).unwrap().contains("channel"));
        assert!(win32_hint(15001).is_some());
        assert!(win32_hint(1).is_none());
        assert!(win32_already_exists(80) && win32_already_exists(183));
        assert!(!win32_already_exists(5));
    }

    #[test]
    fn an_unreadable_exported_file_is_an_error_not_an_empty_list() {
        let dir = tempfile::tempdir().unwrap();
        let bogus = dir.path().join("bogus-subset.evtx");
        fs::write(&bogus, b"not an evtx file").unwrap();
        assert!(read_back_evtx(&bogus).is_err());
        assert!(read_back_evtx(&dir.path().join("missing.evtx")).is_err());
    }

    /// Needs a real capture, which carries real machine data and stays out of the repo. Set
    /// `CMTRACE_EVTX_FIXTURE` to an .evtx file and `CMTRACE_EVTX_FIXTURE_RECORDS` to the number of
    /// events it is known to hold (for example from Event Viewer's log properties); both are
    /// required, and the test runs only with `--ignored`.
    #[test]
    #[ignore = "requires a real .evtx via CMTRACE_EVTX_FIXTURE"]
    fn the_read_back_lists_the_events_of_a_real_log() {
        let raw = std::env::var_os("CMTRACE_EVTX_FIXTURE")
            .expect("set CMTRACE_EVTX_FIXTURE to an .evtx file to run this test");
        let records = read_back_evtx(Path::new(&raw))
            .expect("the fixture reads back without unreadable records");
        assert!(!records.is_empty(), "the fixture holds no events");
        assert!(records.iter().all(|record| record.id > 0));
        // The identity is read from the same System block as the id: a real log names a channel on
        // every event, so a read-back that lost it would compare every event as unrequested.
        assert!(records.iter().all(|record| record.origin.channel.is_some()));
        // Required, like the fixture itself: a comparison that can be skipped can pass without
        // having compared anything.
        let known: usize = std::env::var("CMTRACE_EVTX_FIXTURE_RECORDS")
            .expect("set CMTRACE_EVTX_FIXTURE_RECORDS to the number of events the fixture holds")
            .trim()
            .parse()
            .expect("CMTRACE_EVTX_FIXTURE_RECORDS must be a whole number");
        assert_eq!(records.len(), known);
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn off_windows_the_command_body_reports_that_the_feature_is_unsupported() {
        let out = tempfile::tempdir().unwrap();
        let error = export_subset(&folder_str(&out), &[channel("System", &[1])]).unwrap_err();
        assert!(error.contains("only available on Windows"), "{error}");
        assert_eq!(fs::read_dir(out.path()).unwrap().count(), 0);
    }
}

/// Lab tests for `WindowsBackend` against the real Event Log service. They need a Windows host with
/// a System log holding at least 60 events from the last week, and are run by hand:
///
///     cargo test --features event-log windows_lab -- --ignored
///
/// The fake-backend tests above cover everything around the two API calls; these cover the calls
/// themselves, and only what they run: the flags; a plain XPath with `Computer='X'` for a live
/// channel and with `Computer='X' and Channel='Y'` for a file; structured queries of one group,
/// including the `file://` Select path; the 20-comparison boundary for both kinds; two groups in
/// one plain XPath, the second naming a machine no event carries (once as `Computer='X'`, once as
/// `Computer="X"` for a name with an apostrophe); the archive step and the rule that recognises an
/// entry in `LocaleMetaData` (lab item (i)); and the code the service returns for an existing
/// target. A structured query of several groups is covered by the fake-backend tests only. Every
/// request carries the computer and the channel the way production sends them, taken from the
/// events themselves.
///
/// Two more need a collector that holds events in ForwardedEvents (lab items (g) and (h)); they say
/// what is missing when it does not.
#[cfg(all(test, target_os = "windows"))]
mod windows_lab_tests {
    use std::collections::BTreeSet;
    use std::fs;
    use std::path::{Path, PathBuf};

    use super::engine::*;
    use super::windows_backend::WindowsBackend;
    use super::*;

    /// Long enough that any machine in use has well over 60 System events inside it.
    const PROBE_QUERY: &str = "*[System[TimeCreated[timediff(@SystemTime) <= 604800000]]]";
    const NEEDED_EVENTS: usize = 60;
    /// A machine name no event carries, and one that needs the double-quoted XPath literal.
    const NO_SUCH_COMPUTER: &str = "NO-SUCH-COMPUTER-CMTRACE-LAB";
    const NO_SUCH_COMPUTER_WITH_APOSTROPHE: &str = "NO-SUCH-O'BRIEN-PC";

    fn planned(
        kind: EvtxSubsetSourceKind,
        source_path: &str,
        target: &Path,
        query: &str,
    ) -> PlannedExport {
        PlannedExport {
            kind,
            source_path: source_path.to_string(),
            file_name: target.file_name().unwrap().to_string_lossy().into_owned(),
            target: target.to_path_buf(),
            requested: 0,
            query: SubsetQuery {
                text: query.to_string(),
                structured: false,
            },
            groups: Vec::new(),
        }
    }

    /// What the probe found: the file, the machine and the channel its events name, and the
    /// EventRecordIDs of that machine's events in that channel, ascending.
    struct Probe {
        file: PathBuf,
        computer: String,
        channel: String,
        ids: Vec<u64>,
    }

    /// Exports the last week of System to `probe.evtx` in `dir`, and reads it back.
    fn probe(dir: &Path) -> Probe {
        let target = dir.join("probe.evtx");
        let export = planned(
            EvtxSubsetSourceKind::Channel,
            "System",
            &target,
            PROBE_QUERY,
        );
        if let Err(error) = WindowsBackend.export_log(&export) {
            panic!("the probe export of System failed: {}", error.message);
        }
        let records = read_back_evtx(&target).expect("the probe file reads back");
        // The local System log is written by this machine alone. Take its name from the events, as
        // the dialog does, so the request carries exactly what production would send.
        let computer = records
            .iter()
            .find_map(|record| record.origin.computer.clone())
            .expect("the System events must carry a Computer for this test");
        let channel = records
            .iter()
            .find_map(|record| record.origin.channel.clone())
            .expect("the System events must carry a Channel for this test");
        let ids: BTreeSet<u64> = records
            .iter()
            .filter(|record| {
                record.origin.computer.as_deref() == Some(computer.as_str())
                    && record.origin.channel.as_deref() == Some(channel.as_str())
            })
            .map(|record| record.id)
            .collect();
        assert!(
            ids.len() >= NEEDED_EVENTS,
            "this test needs {NEEDED_EVENTS} System events from the last week, found {}",
            ids.len()
        );
        Probe {
            file: target,
            computer,
            channel,
            ids: ids.into_iter().collect(),
        }
    }

    fn group(computer: &str, channel: &str, ids: &[u64]) -> EvtxSubsetRecordGroup {
        EvtxSubsetRecordGroup {
            computer: Some(computer.to_string()),
            channel: Some(channel.to_string()),
            record_ids: ids.iter().map(u64::to_string).collect(),
        }
    }

    fn source(
        kind: EvtxSubsetSourceKind,
        path: &str,
        groups: Vec<EvtxSubsetRecordGroup>,
    ) -> EvtxSubsetSource {
        EvtxSubsetSource {
            kind,
            path: path.to_string(),
            record_groups: groups,
        }
    }

    /// The source a test exports from: the live System channel, or the probe file.
    fn from_kind(kind: EvtxSubsetSourceKind, probe: &Probe) -> (EvtxSubsetSourceKind, String) {
        match kind {
            EvtxSubsetSourceKind::Channel => (kind, "System".to_string()),
            EvtxSubsetSourceKind::File => (kind, probe.file.to_string_lossy().into_owned()),
        }
    }

    fn run_one_source(out: &Path, source: EvtxSubsetSource) -> EvtxSubsetFileResult {
        let result = export_subset(&out.to_string_lossy(), &[source]).expect("request accepted");
        result.files.into_iter().next().expect("one file")
    }

    fn query_of(out: &Path, source: &EvtxSubsetSource) -> SubsetQuery {
        let plan = plan_subset_export(&out.to_string_lossy(), std::slice::from_ref(source))
            .expect("request planned");
        match &plan.entries[0] {
            PlanEntry::Ready(export) => export.query.clone(),
            PlanEntry::Failed(failed) => panic!("not planned: {}", failed.error),
        }
    }

    fn ids_in(path: &str) -> BTreeSet<u64> {
        read_back_evtx(Path::new(path))
            .expect("the exported file reads back")
            .into_iter()
            .map(|record| record.id)
            .collect()
    }

    fn assert_exported_exactly(file: &EvtxSubsetFileResult, wanted: &[u64]) {
        assert_eq!(
            file.status,
            EvtxSubsetFileStatus::Exported,
            "{:?}",
            file.error
        );
        assert_eq!(file.requested_records, wanted.len() as u64);
        assert_eq!(
            file.exported_records,
            Some(wanted.len() as u64),
            "{:?}",
            file.warnings
        );
        assert_eq!(
            file.missing.as_ref().map(|d| d.count),
            Some(0),
            "{:?}",
            file.missing
        );
        assert_eq!(
            file.unrequested.as_ref().map(|d| d.count),
            Some(0),
            "{:?}",
            file.unrequested
        );
        // The IDs read back from the written file, not just their number.
        assert_eq!(
            ids_in(&file.output_path),
            wanted.iter().copied().collect::<BTreeSet<u64>>()
        );
    }

    /// The spec 8.17 behavior that the file renders without the provider: the archive step ran and
    /// nothing was left to warn about.
    fn assert_archived_cleanly(file: &EvtxSubsetFileResult) {
        assert!(
            file.messages_archived,
            "EvtArchiveExportedLog did not succeed: {:?}",
            file.warnings
        );
        assert!(file.warnings.is_empty(), "{:?}", file.warnings);
    }

    fn short_range(ids: &[u64]) -> Vec<u64> {
        ids[10..13].to_vec()
    }

    /// Alternate IDs, so none are adjacent and each costs a comparison of its own.
    fn alternate(ids: &[u64], count: usize) -> Vec<u64> {
        ids.iter().copied().step_by(2).take(count).collect()
    }

    const BOTH_KINDS: [EvtxSubsetSourceKind; 2] =
        [EvtxSubsetSourceKind::Channel, EvtxSubsetSourceKind::File];

    #[test]
    #[ignore = "requires a Windows Event Log service"]
    fn a_short_range_with_its_computer_is_exported_from_a_live_channel() {
        let work = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        let probe = probe(work.path());
        let wanted = short_range(&probe.ids);
        let request = source(
            EvtxSubsetSourceKind::Channel,
            "System",
            vec![group(&probe.computer, &probe.channel, &wanted)],
        );
        let query = query_of(out.path(), &request);
        assert!(!query.structured);
        assert!(query.text.contains("Computer="), "{}", query.text);
        // The queried log is the event's own channel, so the Channel term is left out.
        assert!(!query.text.contains("Channel="), "{}", query.text);
        let file = run_one_source(out.path(), request);
        assert_exported_exactly(&file, &wanted);
        assert_archived_cleanly(&file);
        // Lab item (i): the guard against overwriting an earlier archive recognises the entry the
        // service has just written for this file, so its naming rule is the service's.
        assert!(
            locale_entry_block_reason(out.path(), &file.file_name).is_some(),
            "no entry in LocaleMetaData matches the guard's rule for {}",
            file.file_name
        );
    }

    #[test]
    #[ignore = "requires a Windows Event Log service"]
    fn a_short_range_with_its_computer_is_exported_from_an_evtx_file() {
        let work = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        let probe = probe(work.path());
        let wanted = short_range(&probe.ids);
        let request = source(
            EvtxSubsetSourceKind::File,
            &probe.file.to_string_lossy(),
            vec![group(&probe.computer, &probe.channel, &wanted)],
        );
        let query = query_of(out.path(), &request);
        assert!(!query.structured);
        // A file always names the channel.
        assert!(query.text.contains("Channel="), "{}", query.text);
        assert_exported_exactly(&run_one_source(out.path(), request), &wanted);
    }

    #[test]
    #[ignore = "requires a Windows Event Log service"]
    fn more_than_twenty_comparisons_with_the_computer_use_a_structured_query() {
        // 25 non-adjacent single ids plus the computer is 26 comparisons: over what an XPath may
        // hold, so every Select carries its own copy of the Computer term. For a file source this
        // is also the case that needs the `file://` Select path to be what the service expects.
        for kind in BOTH_KINDS {
            let work = tempfile::tempdir().unwrap();
            let out = tempfile::tempdir().unwrap();
            let probe = probe(work.path());
            let wanted = alternate(&probe.ids, 25);
            let (kind, path) = from_kind(kind, &probe);
            let request = source(
                kind,
                &path,
                vec![group(&probe.computer, &probe.channel, &wanted)],
            );
            let query = query_of(out.path(), &request);
            assert!(query.structured, "{kind:?}: {}", query.text);
            assert!(query.text.contains("Computer="), "{kind:?}: {}", query.text);
            assert_exported_exactly(&run_one_source(out.path(), request), &wanted);
        }
    }

    #[test]
    #[ignore = "requires a Windows Event Log service"]
    fn the_names_count_toward_the_limit_exactly_at_the_boundary() {
        // A channel source names the computer (one comparison) and a file source also names the
        // channel (two). Ids up to 20 minus those are one XPath, one more is structured. The
        // service must accept both forms, and the limit is the one assumed.
        for kind in BOTH_KINDS {
            let at_limit = match kind {
                EvtxSubsetSourceKind::Channel => 19usize,
                EvtxSubsetSourceKind::File => 18usize,
            };
            for (count, structured) in [(at_limit, false), (at_limit + 1, true)] {
                let work = tempfile::tempdir().unwrap();
                let out = tempfile::tempdir().unwrap();
                let probe = probe(work.path());
                let wanted = alternate(&probe.ids, count);
                let (kind, path) = from_kind(kind, &probe);
                let request = source(
                    kind,
                    &path,
                    vec![group(&probe.computer, &probe.channel, &wanted)],
                );
                let query = query_of(out.path(), &request);
                assert_eq!(
                    query.structured, structured,
                    "{kind:?} {count}: {}",
                    query.text
                );
                assert_exported_exactly(&run_one_source(out.path(), request), &wanted);
            }
        }
    }

    #[test]
    #[ignore = "requires a Windows Event Log service"]
    fn a_second_computer_that_matches_nothing_comes_back_missing_and_adds_nothing() {
        // Two groups: the real machine, and a name no event carries (once plain, once with an
        // apostrophe so that the double-quoted literal form is used). The second group asks for
        // other ids than the first. If the query ignored the Computer term it would select those
        // events under the real machine's name, and they would come back as unrequested.
        for kind in BOTH_KINDS {
            for fake in [NO_SUCH_COMPUTER, NO_SUCH_COMPUTER_WITH_APOSTROPHE] {
                let work = tempfile::tempdir().unwrap();
                let out = tempfile::tempdir().unwrap();
                let probe = probe(work.path());
                let real = short_range(&probe.ids);
                let other: Vec<u64> = probe.ids[20..24].to_vec();
                let (kind, path) = from_kind(kind, &probe);
                let request = source(
                    kind,
                    &path,
                    vec![
                        group(&probe.computer, &probe.channel, &real),
                        group(fake, &probe.channel, &other),
                    ],
                );
                let file = run_one_source(out.path(), request);
                assert_eq!(
                    file.status,
                    EvtxSubsetFileStatus::Exported,
                    "{kind:?} {fake}: {:?}",
                    file.error
                );
                // Only the real machine's events are in the file.
                assert_eq!(
                    ids_in(&file.output_path),
                    real.iter().copied().collect::<BTreeSet<u64>>(),
                    "{kind:?} {fake}"
                );
                assert_eq!(file.exported_records, Some(real.len() as u64));
                // The fake machine's events were asked for and are reported missing, by name.
                let missing = file.missing.expect("verified");
                assert_eq!(missing.count, other.len() as u64, "{kind:?} {fake}");
                assert!(
                    missing
                        .sample
                        .iter()
                        .all(|entry| entry.contains(&format!(" on {fake}"))),
                    "{:?}",
                    missing.sample
                );
                // And nothing the request did not name was exported alongside.
                assert_eq!(
                    file.unrequested.expect("verified").count,
                    0,
                    "{kind:?} {fake}"
                );
            }
        }
    }

    #[test]
    #[ignore = "requires a Windows Event Log service"]
    fn an_existing_target_is_refused_and_left_alone() {
        let work = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        let probe = probe(work.path());
        let taken = out.path().join("System-subset.evtx");
        fs::write(&taken, b"someone else's file").unwrap();

        // Through the command: the whole request is refused before the service is called.
        let error = export_subset(
            &out.path().to_string_lossy(),
            &[source(
                EvtxSubsetSourceKind::Channel,
                "System",
                vec![group(
                    &probe.computer,
                    &probe.channel,
                    &short_range(&probe.ids),
                )],
            )],
        )
        .unwrap_err();
        assert!(error.contains("never overwritten"), "{error}");

        // Straight at the service, bypassing our own check: it refuses too, and with a code that
        // `win32_already_exists` recognises, which is what keeps the cleanup from deleting a file
        // that is not ours.
        let export = planned(
            EvtxSubsetSourceKind::Channel,
            "System",
            &taken,
            "*[System[EventRecordID>=1]]",
        );
        let refusal = WindowsBackend
            .export_log(&export)
            .expect_err("the service must not overwrite an existing file");
        assert!(
            refusal.already_exists,
            "the service reported an existing target with a code not recognised as one: {}",
            refusal.message
        );
        assert_eq!(fs::read(&taken).unwrap(), b"someone else's file");
    }

    /// Every event in ForwardedEvents, exported whole and read back. What matters is what each
    /// event says about itself: its machine, its own channel and its EventRecordID.
    fn forwarded_events(dir: &Path) -> Vec<ReadBackRecord> {
        let target = dir.join("forwarded-probe.evtx");
        let export = planned(
            EvtxSubsetSourceKind::Channel,
            "ForwardedEvents",
            &target,
            "*",
        );
        if let Err(error) = WindowsBackend.export_log(&export) {
            panic!(
                "the probe export of ForwardedEvents failed; this test needs a collector that \
                 holds events: {}",
                error.message
            );
        }
        read_back_evtx(&target).expect("the probe file reads back")
    }

    /// An event of ForwardedEvents that names its own machine and a channel other than the
    /// collector's, as an event forwarded from another log does.
    fn names_its_source_log(record: &ReadBackRecord) -> bool {
        record.origin.computer.is_some()
            && record
                .origin
                .channel
                .as_deref()
                .is_some_and(|channel| !channel.eq_ignore_ascii_case("ForwardedEvents"))
    }

    /// Requests one event from ForwardedEvents by its own machine, channel and ID, and checks that
    /// the file holds only events with that identity.
    fn export_forwarded_event_alone(chosen: &ReadBackRecord) {
        let out = tempfile::tempdir().unwrap();
        let computer = chosen.origin.computer.clone().expect("a machine");
        let channel = chosen.origin.channel.clone().expect("a channel");
        let request = source(
            EvtxSubsetSourceKind::Channel,
            "ForwardedEvents",
            vec![group(&computer, &channel, &[chosen.id])],
        );
        let query = query_of(out.path(), &request);
        assert!(query.text.contains("Channel="), "{}", query.text);
        let file = run_one_source(out.path(), request);
        assert_eq!(
            file.status,
            EvtxSubsetFileStatus::Exported,
            "{:?}",
            file.error
        );
        assert_eq!(
            file.missing.as_ref().map(|d| d.count),
            Some(0),
            "{:?}",
            file.missing
        );
        let held =
            read_back_evtx(Path::new(&file.output_path)).expect("the exported file reads back");
        assert!(
            !held.is_empty(),
            "the query selected nothing: {}",
            query.text
        );
        for record in &held {
            assert_eq!(record.id, chosen.id, "{record:?}");
            assert_eq!(record.origin, chosen.origin, "{record:?}");
        }
    }

    #[test]
    #[ignore = "requires a Windows Event Log collector that holds events in ForwardedEvents"]
    fn a_forwarded_event_keeps_its_source_log_and_is_selected_by_it() {
        // Lab item (g): a forwarded event keeps its source log's EventRecordID and System/Channel,
        // and an XPath Channel and EventRecordID test on ForwardedEvents matches them.
        let work = tempfile::tempdir().unwrap();
        let records = forwarded_events(work.path());
        let chosen = records
            .iter()
            .find(|record| names_its_source_log(record))
            .expect(
                "no event in ForwardedEvents names a channel other than ForwardedEvents, which is \
                 what lab item (g) says a forwarded event does",
            );
        export_forwarded_event_alone(chosen);
    }

    #[test]
    #[ignore = "requires a collector that receives two channels from one machine with a shared ID"]
    fn two_channels_of_one_machine_with_the_same_id_are_told_apart() {
        // Lab item (h): one machine forwarding two channels yields duplicate (Computer,
        // EventRecordID) pairs, so the channel is what tells the events apart.
        let work = tempfile::tempdir().unwrap();
        let records = forwarded_events(work.path());
        let twin = records
            .iter()
            .filter(|record| names_its_source_log(record))
            .find(|record| {
                records.iter().any(|other| {
                    names_its_source_log(other)
                        && other.id == record.id
                        && other.origin.computer == record.origin.computer
                        && other.origin.channel != record.origin.channel
                })
            })
            .expect(
                "no machine in ForwardedEvents forwarded two channels with the same EventRecordID, \
                 so lab item (h) cannot be settled on this collector",
            );
        export_forwarded_event_alone(twin);
    }
}
