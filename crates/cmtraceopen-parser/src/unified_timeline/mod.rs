//! Merging Windows events and parsed text logs into one chronological view.
//!
//! Every event viewer surveyed for issue #539 is events-only, and every log viewer is text-only.
//! Nobody puts them side by side, which is the one thing that actually explains a failure: the
//! `DeviceManagement-Enterprise-Diagnostics-Provider` event says enrollment failed with an HRESULT,
//! and the `IntuneManagementExtension.log` line thirty seconds earlier says why.
//!
//! This module owns the merge. It is pure and holds no knowledge of where items came from, so the
//! event side can live in the host layer while the log side comes straight from
//! [`LogEntry`](crate::models::log_entry::LogEntry).
//!
//! The hard part is not sorting. It is refusing to place things that cannot honestly be placed:
//! an entry with no timestamp has no position on a timeline, and putting it at the epoch or at the
//! previous entry's time would invent a sequence the evidence does not support.

use serde::{Deserialize, Serialize};

use crate::models::log_entry::{LogEntry, Severity};

/// Severity normalized across both sides of the merge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub enum TimelineSeverity {
    /// Diagnostic detail, from a verbose event. Text logs have no equivalent.
    Verbose,
    /// Ordinary progress. The default, since a line carrying no severity is not a problem.
    #[default]
    Info,
    /// Something the source flagged as worth noticing but did not treat as a failure.
    Warning,
    /// A failure the source reported. The highest a text log reaches.
    Error,
    /// Only events carry this; text logs top out at error.
    Critical,
}

impl TimelineSeverity {
    /// Maps a text log severity.
    ///
    /// `Success` maps to `Info` rather than gaining a level of its own: on a merged timeline it is
    /// an ordinary informational line, and a separate rank would sort it away from the events it
    /// sits between.
    pub fn from_log(severity: Severity) -> Self {
        match severity {
            Severity::Error => Self::Error,
            Severity::Warning => Self::Warning,
            Severity::Info | Severity::Success => Self::Info,
        }
    }

    /// Maps a Windows event level value as written in `System/Level`.
    ///
    /// Level 0 means "not set", which providers use for events that are not classified. It maps to
    /// `Info` because treating an unclassified event as critical would flood a severity filter.
    pub fn from_event_level(level: u8) -> Self {
        match level {
            1 => Self::Critical,
            2 => Self::Error,
            3 => Self::Warning,
            5 => Self::Verbose,
            _ => Self::Info,
        }
    }
}

/// Where a timeline item came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
// Growable: a third kind of source, such as a registry export or an ETW trace read directly, is a
// plausible addition. Marking it now keeps that a minor change.
#[non_exhaustive]
// rename_all covers the variant names; rename_all_fields is what camel-cases the fields inside a
// struct variant. Without the second one, event_id went over the wire as "event_id" while the
// timeline view reads origin.eventId, so every event row rendered undefined.
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum TimelineOrigin {
    /// A line from a parsed text log.
    Log {
        /// File the line came from, as the parser recorded it.
        file: String,
        /// Emitting component, when the format carries one.
        component: Option<String>,
        /// 1-based line number, so the item can be traced back to the source.
        line: u32,
        /// Stable source label. This is the source file when one is available.
        source: String,
        /// Machine that emitted the line, when the source records one.
        machine: Option<String>,
        /// Containing evidence bundle, when the source path identifies one.
        bundle: Option<String>,
        /// Stable parser record identity.
        record_id: u64,
    },
    /// A Windows event.
    Event {
        /// Stable identity composed from source identity, channel, and EventRecordID.
        ///
        /// `EvtxRecord.id` is a mutable UI index and must not be used here: live appends can
        /// reorder records and renumber it.
        stable_id: String,
        source: String,
        /// Machine that emitted the event, when the source records one.
        machine: Option<String>,
        /// Containing evidence bundle, when known.
        bundle: Option<String>,
        /// Channel the event was read from, for example `Microsoft-Windows-DNSServer/Audit`.
        channel: String,
        /// Publisher that raised it, as the event's own `System` block names it.
        provider: String,
        /// Emitting process, when the event declares one.
        process_id: Option<u32>,
        /// Correlation ActivityID, when the event declares one.
        activity_id: Option<String>,
        /// Event ID, which identifies the event only in combination with the provider.
        event_id: u32,
        /// Record identifier within its channel.
        record_id: u64,
    },
}

/// One placed item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TimelineItem {
    /// Milliseconds since the Unix epoch.
    pub timestamp_ms: i64,
    /// How serious the source said this was, normalized across event levels and log levels.
    pub severity: TimelineSeverity,
    /// The rendered text, already whatever the source's own formatting produced.
    pub message: String,
    /// Which file or channel this came from, so a row on a merged timeline stays attributable.
    pub origin: TimelineOrigin,
}

/// Something that could not be placed, and why.
///
/// Surfaced rather than dropped: a timeline that silently omits a third of a log file looks
/// complete and is not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnplacedItem {
    /// Where it came from, so an operator can go and look.
    pub origin: TimelineOrigin,
    /// Why it has no position.
    pub reason: UnplacedReason,
}

/// Why an item has no position on the timeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
// Growable: this build does not know every variant a newer schema will define.
// Marking it now keeps adding one a minor change; after the first release that
// exposes the type, adding the attribute is itself breaking.
#[non_exhaustive]
pub enum UnplacedReason {
    /// The source carried no timestamp, or one the parser could not read.
    ///
    /// Common in continuation lines and in text logs whose first line is a header.
    MissingTimestamp,
}

/// A merged timeline plus everything that could not be placed on it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnifiedTimeline {
    /// Items in chronological order.
    pub items: Vec<TimelineItem>,
    /// Items with no honest position, in input order.
    pub unplaced: Vec<UnplacedItem>,
}

impl UnifiedTimeline {
    /// True when everything supplied was placed.
    pub fn is_complete(&self) -> bool {
        self.unplaced.is_empty()
    }

    /// Inclusive time span covered, or `None` when nothing was placed.
    pub fn span_ms(&self) -> Option<(i64, i64)> {
        let mut stamps = self.items.iter().map(|item| item.timestamp_ms);
        let first = stamps.next()?;
        Some(stamps.fold((first, first), |(low, high), stamp| {
            (low.min(stamp), high.max(stamp))
        }))
    }
}

fn bundle_from_source(source: &str) -> Option<String> {
    let first = source.split(['/', '\\']).next()?;
    if first.is_empty() || first.ends_with(':') || !source.contains(['/', '\\']) {
        None
    } else {
        Some(first.to_string())
    }
}

/// Converts a parsed log entry, or reports why it cannot be placed.
pub fn from_log_entry(entry: &LogEntry) -> Result<TimelineItem, UnplacedItem> {
    let file = entry.file_path.clone();
    let source = entry
        .source_file
        .clone()
        .unwrap_or_else(|| file.clone());
    let origin = TimelineOrigin::Log {
        file,
        component: entry.component.clone(),
        line: entry.line_number,
        bundle: bundle_from_source(&source),
        // LogEntry::host_name is DHCP client payload, not the machine that emitted the log.
        machine: None,
        record_id: entry.id,
        source,
    };

    match entry.timestamp {
        Some(timestamp_ms) => Ok(TimelineItem {
            timestamp_ms,
            severity: TimelineSeverity::from_log(entry.severity),
            message: entry.message.clone(),
            origin,
        }),
        None => Err(UnplacedItem {
            origin,
            reason: UnplacedReason::MissingTimestamp,
        }),
    }
}

/// Appends parsed log entries without losing existing placed or unplaced records.
pub fn append(timeline: &mut UnifiedTimeline, entries: &[LogEntry]) {
    let mut placed = std::mem::take(&mut timeline.items);
    let mut unplaced = std::mem::take(&mut timeline.unplaced);
    for entry in entries {
        match from_log_entry(entry) {
            Ok(item) => placed.push(item),
            Err(item) => unplaced.push(item),
        }
    }
    *timeline = merge(placed, unplaced);
}
/// Builds a collision-resistant textual key for deterministic provenance ordering.
fn key_part(value: &str) -> String {
    format!("{}:{value}", value.len())
}

fn origin_sort_key(origin: &TimelineOrigin) -> String {
    match origin {
        TimelineOrigin::Log {
            source,
            file,
            line,
            component,
            record_id,
            ..
        } => format!(
            "log|{}|{}|{line:010}|{record_id:020}|{}",
            key_part(source),
            key_part(file),
            key_part(component.as_deref().unwrap_or_default())
        ),
        TimelineOrigin::Event { stable_id, .. } => format!("event|{}", key_part(stable_id)),
    }
}

/// Merges already-converted items into one chronological timeline.
///
/// Equal timestamps use deterministic source identity ordering, so channel completion order and
/// append history cannot change the merged result.
pub fn merge(
    placed: impl IntoIterator<Item = TimelineItem>,
    unplaced: impl IntoIterator<Item = UnplacedItem>,
) -> UnifiedTimeline {
    let mut items: Vec<TimelineItem> = placed.into_iter().collect();
    items.sort_by_cached_key(|item| (item.timestamp_ms, origin_sort_key(&item.origin)));
    let mut unplaced: Vec<UnplacedItem> = unplaced.into_iter().collect();
    unplaced.sort_by_cached_key(|item| origin_sort_key(&item.origin));
    UnifiedTimeline { items, unplaced }
}

/// Converts and merges a slice of log entries, collecting the ones that cannot be placed.
pub fn from_log_entries(entries: &[LogEntry]) -> UnifiedTimeline {
    let mut timeline = UnifiedTimeline::default();
    append(&mut timeline, entries);
    timeline
}

#[cfg(test)]
mod tests {
    use super::*;

    fn log_entry(timestamp: Option<i64>, message: &str, severity: Severity) -> LogEntry {
        LogEntry {
            id: 0,
            line_number: 7,
            message: message.to_string(),
            component: Some("IME".to_string()),
            timestamp,
            severity,
            file_path: "C:/logs/IntuneManagementExtension.log".to_string(),
            ..LogEntry::default()
        }
    }

    fn event(timestamp_ms: i64, message: &str, severity: TimelineSeverity) -> TimelineItem {
        TimelineItem {
            timestamp_ms,
            severity,
            message: message.to_string(),
            origin: TimelineOrigin::Event {
                stable_id: "Live/Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin#1"
                    .to_string(),
                source: "Live".to_string(),
                machine: Some("TESTHOST".to_string()),
                bundle: None,
                channel: "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin"
                    .to_string(),
                provider: "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider"
                    .to_string(),
                process_id: None,
                activity_id: None,
                event_id: 76,
                record_id: 1,
            },
        }
    }

    #[test]
    fn events_and_log_lines_interleave_by_time() {
        // The whole point: the event says enrollment failed, the log line before it says why.
        let logs = [
            log_entry(Some(1_000), "Checking enrollment", Severity::Info),
            log_entry(Some(3_000), "Token request rejected", Severity::Error),
        ];
        let timeline = merge(
            logs.iter()
                .filter_map(|entry| from_log_entry(entry).ok())
                .chain([event(2_000, "MDM enroll failed", TimelineSeverity::Error)]),
            [],
        );

        let messages: Vec<&str> = timeline.items.iter().map(|i| i.message.as_str()).collect();
        assert_eq!(
            messages,
            vec![
                "Checking enrollment",
                "MDM enroll failed",
                "Token request rejected"
            ]
        );
    }

    #[test]
    fn an_entry_without_a_timestamp_is_reported_rather_than_placed() {
        let entries = [
            log_entry(Some(1_000), "placed", Severity::Info),
            log_entry(None, "continuation line", Severity::Info),
        ];
        let timeline = from_log_entries(&entries);

        assert_eq!(timeline.items.len(), 1);
        assert_eq!(timeline.unplaced.len(), 1);
        assert_eq!(timeline.unplaced[0].reason, UnplacedReason::MissingTimestamp);
        assert!(!timeline.is_complete());
    }

    #[test]
    fn an_unplaced_item_still_says_where_it_came_from() {
        let timeline = from_log_entries(&[log_entry(None, "orphan", Severity::Error)]);
        match &timeline.unplaced[0].origin {
            TimelineOrigin::Log { file, line, component, .. } => {
                assert!(file.ends_with("IntuneManagementExtension.log"));
                assert_eq!(*line, 7);
                assert_eq!(component.as_deref(), Some("IME"));
            }
            other => panic!("expected a log origin, got {other:?}"),
        }
    }

    #[test]
    fn items_sharing_a_timestamp_keep_their_input_order() {
        // A log line and an event in the same millisecond have no discoverable ordering, so the
        // merge must not invent one by sorting on severity or source.
        let timeline = merge(
            [
                event(5_000, "first supplied", TimelineSeverity::Error),
                event(5_000, "second supplied", TimelineSeverity::Verbose),
                event(5_000, "third supplied", TimelineSeverity::Critical),
            ],
            [],
        );
        let messages: Vec<&str> = timeline.items.iter().map(|i| i.message.as_str()).collect();
        assert_eq!(
            messages,
            vec!["first supplied", "second supplied", "third supplied"]
        );
    }

    #[test]
    fn negative_timestamps_sort_before_the_epoch_rather_than_wrapping() {
        let timeline = merge(
            [
                event(10, "after", TimelineSeverity::Info),
                event(-10, "before", TimelineSeverity::Info),
            ],
            [],
        );
        assert_eq!(timeline.items[0].message, "before");
    }

    #[test]
    fn the_span_covers_first_to_last() {
        let timeline = merge(
            [
                event(3_000, "c", TimelineSeverity::Info),
                event(1_000, "a", TimelineSeverity::Info),
            ],
            [],
        );
        assert_eq!(timeline.span_ms(), Some((1_000, 3_000)));
    }

    #[test]
    fn an_empty_timeline_has_no_span_rather_than_a_zero_one() {
        let timeline = UnifiedTimeline::default();
        assert_eq!(timeline.span_ms(), None);
        assert!(timeline.is_complete());
    }

    #[test]
    fn log_success_is_informational_not_a_rank_of_its_own() {
        // A separate rank would sort Success away from the events it sits between.
        assert_eq!(
            TimelineSeverity::from_log(Severity::Success),
            TimelineSeverity::Info
        );
        assert_eq!(
            TimelineSeverity::from_log(Severity::Error),
            TimelineSeverity::Error
        );
    }

    #[test]
    fn event_level_zero_is_informational_not_critical() {
        // Level 0 means "not set". Ranking it critical would flood a severity filter.
        assert_eq!(
            TimelineSeverity::from_event_level(0),
            TimelineSeverity::Info
        );
        assert_eq!(
            TimelineSeverity::from_event_level(1),
            TimelineSeverity::Critical
        );
        assert_eq!(
            TimelineSeverity::from_event_level(5),
            TimelineSeverity::Verbose
        );
        // An undeclared level must not panic or invent a rank.
        assert_eq!(
            TimelineSeverity::from_event_level(9),
            TimelineSeverity::Info
        );
    }

    #[test]
    fn severity_orders_from_verbose_to_critical() {
        assert!(TimelineSeverity::Verbose < TimelineSeverity::Info);
        assert!(TimelineSeverity::Error < TimelineSeverity::Critical);
    }

    #[test]
    fn a_log_entry_falls_back_to_its_file_path_when_no_source_file_is_recorded() {
        let timeline = from_log_entries(&[log_entry(Some(1), "x", Severity::Info)]);
        match &timeline.items[0].origin {
            TimelineOrigin::Log { file, .. } => assert!(file.contains("IntuneManagementExtension")),
            other => panic!("expected a log origin, got {other:?}"),
        }
    }

    #[test]
    fn an_event_origin_preserves_all_cross_source_provenance() {
        let origin = TimelineOrigin::Event {
            stable_id: "capture.evtx/Application#42".into(),
            source: "capture.evtx".into(),
            machine: Some("HOST-A".into()),
            bundle: Some("bundle-123".into()),
            channel: "Application".into(),
            provider: "ESENT".into(),
            process_id: Some(4321),
            activity_id: Some("{activity}".into()),
            event_id: 326,
            record_id: 42,
        };
        let json = serde_json::to_value(&origin).expect("serializes");

        assert_eq!(json["kind"], "event");
        assert_eq!(json["source"], "capture.evtx");
        assert_eq!(json["machine"], "HOST-A");
        assert_eq!(json["bundle"], "bundle-123");
        assert_eq!(json["channel"], "Application");
        assert_eq!(json["provider"], "ESENT");
        assert_eq!(json["processId"], 4321);
        assert_eq!(json["activityId"], "{activity}");
        assert_eq!(json["eventId"], 326);
        assert_eq!(json["stableId"], "capture.evtx/Application#42");
        assert_eq!(json["recordId"], 42);
    }

    #[test]
    fn appending_records_reconciles_into_the_same_deterministic_order() {
        let mut timeline = merge([event(3_000, "last", TimelineSeverity::Info)], []);
        append(&mut timeline, &[log_entry(Some(1_000), "first", Severity::Info)]);

        let messages: Vec<&str> = timeline.items.iter().map(|item| item.message.as_str()).collect();
        assert_eq!(messages, vec!["first", "last"]);
        assert!(timeline.is_complete());
    }

    #[test]
    fn equal_timestamps_order_cross_source_identity_not_input_history() {
        let log = from_log_entries(&[log_entry(Some(5_000), "text", Severity::Info)])
            .items
            .pop()
            .expect("log item");
        let event_item = event(5_000, "event", TimelineSeverity::Info);
        let one = merge([log.clone(), event_item.clone()], []);
        let two = merge([event_item, log], []);
        let messages_one: Vec<_> = one.items.iter().map(|item| item.message.as_str()).collect();
        let messages_two: Vec<_> = two.items.iter().map(|item| item.message.as_str()).collect();
        assert_eq!(messages_one, messages_two);
        assert_eq!(messages_one, vec!["event", "text"]);
    }

    #[test]
    fn append_keeps_missing_timestamps_visible_and_counts_them() {
        let mut timeline = merge([event(1_000, "placed", TimelineSeverity::Info)], []);
        append(&mut timeline, &[log_entry(None, "unplaced", Severity::Info)]);

        assert_eq!(timeline.items.len(), 1);
        assert_eq!(timeline.unplaced.len(), 1);
        assert_eq!(
            timeline.unplaced[0].reason,
            UnplacedReason::MissingTimestamp
        );
        assert!(!timeline.is_complete());
    }

    #[test]
    fn equal_timestamps_keep_supplied_order_for_live_reconciliation() {
        let mut timeline = UnifiedTimeline::default();
        append(&mut timeline, &[log_entry(Some(5_000), "first", Severity::Info)]);
        append(&mut timeline, &[log_entry(Some(5_000), "second", Severity::Info)]);

        let messages: Vec<&str> = timeline.items.iter().map(|item| item.message.as_str()).collect();
        assert_eq!(messages, vec!["first", "second"]);
    }

    #[test]
    fn log_origin_does_not_treat_dhcp_client_name_as_machine_provenance() {
        let mut entry = log_entry(Some(1_000), "line", Severity::Info);
        entry.id = 99;
        entry.host_name = Some("LEASED-CLIENT".into());
        entry.source_file = Some("bundle/evidence/dhcp.log".into());
        let timeline = from_log_entries(&[entry]);

        match &timeline.items[0].origin {
            TimelineOrigin::Log {
                source,
                machine,
                bundle,
                record_id,
                ..
            } => {
                assert_eq!(source, "bundle/evidence/dhcp.log");
                assert_eq!(machine, &None);
                assert_eq!(bundle.as_deref(), Some("bundle"));
                assert_eq!(*record_id, 99);
            }
            other => panic!("expected a log origin, got {other:?}"),
        }
    }

    #[test]
    fn log_origin_keeps_physical_file_separate_from_parser_source_token() {
        let mut entry = log_entry(Some(1_000), "line", Severity::Info);
        entry.source_file = Some("store.cs:1".into());
        entry.file_path = "/logs/ccm.log".into();
        let timeline = from_log_entries(&[entry]);

        match &timeline.items[0].origin {
            TimelineOrigin::Log { file, source, .. } => {
                assert_eq!(file, "/logs/ccm.log");
                assert_eq!(source, "store.cs:1");
            }
            other => panic!("expected a log origin, got {other:?}"),
        }
    }

    #[test]
    fn a_log_origin_keeps_its_wire_keys() {
        let origin = TimelineOrigin::Log {
            file: "cmt.log".into(),
            component: Some("Agent".into()),
            line: 7,
            source: "cmt.log".into(),
            machine: None,
            bundle: None,
            record_id: 7,
        };
        let json = serde_json::to_value(&origin).expect("serializes");
        assert_eq!(json["kind"], "log");
        assert_eq!(json["file"], "cmt.log");
        assert_eq!(json["line"], 7);
        assert_eq!(json["source"], "cmt.log");
        assert_eq!(json["recordId"], 7);
    }
}
