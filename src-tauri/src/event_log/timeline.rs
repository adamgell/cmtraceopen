//! Placing Windows events onto the unified timeline.
//!
//! The merge itself lives in `cmtraceopen_parser::unified_timeline`, which is pure and knows
//! nothing about where items came from. This is the event-side adapter: it converts an
//! [`EvtxRecord`] into a timeline item, or reports why it cannot be placed.
//!
//! The log side needs no adapter because `LogEntry` already lives in the parser crate.

use cmtraceopen_parser::models::log_entry::LogEntry;
use cmtraceopen_parser::unified_timeline::{
    from_log_entry, merge, TimelineItem, TimelineOrigin, TimelineSeverity, UnifiedTimeline,
    UnplacedItem, UnplacedReason,
};

use super::event_node::parse_event_xml;
use super::models::{EvtxLevel, EvtxRecord};

/// Maps the record's level back to a timeline severity.
///
/// `EvtxRecord` stores a decoded level rather than the raw `System/Level` value, so this maps the
/// decoded form. Information is the resting state, matching how the decoder treats a level it does
/// not recognise.
fn severity_of(level: EvtxLevel) -> TimelineSeverity {
    match level {
        EvtxLevel::Critical => TimelineSeverity::Critical,
        EvtxLevel::Error => TimelineSeverity::Error,
        EvtxLevel::Warning => TimelineSeverity::Warning,
        EvtxLevel::Verbose => TimelineSeverity::Verbose,
        EvtxLevel::Information => TimelineSeverity::Info,
    }
}
fn origin_of(record: &EvtxRecord) -> TimelineOrigin {
    TimelineOrigin::Event {
        stable_id: record.id,
        source: record.source_label.clone(),
        machine: machine_of(&record.computer),
        bundle: bundle_from_source(&record.source_label),
        channel: record.channel.clone(),
        provider: record.provider.clone(),
        process_id: record.process_id,
        activity_id: extract_activity_id(&record.raw_xml),
        event_id: record.event_id,
        record_id: record.event_record_id,
    }
}

fn machine_of(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty() && !value.eq_ignore_ascii_case("unknown")).then(|| value.to_string())
}

fn bundle_from_source(source: &str) -> Option<String> {
    let first = source.split(['/', '\\']).next()?;
    if first.is_empty() || first.ends_with(':') || !source.contains(['/', '\\']) {
        None
    } else {
        Some(first.to_string())
    }
}

/// Extracts only the provider-declared correlation ActivityID; absence remains explicit.
///
/// The correlation element is scoped to the event's `System` block. Looking for the attribute by
/// substring would accept unrelated provider data (or `RelatedActivityID`) as a causal identity.
fn extract_activity_id(xml: &str) -> Option<String> {
    let root = parse_event_xml(xml).ok()?;
    let system = root.children.iter().find(|child| child.name == "System")?;
    let correlation = system
        .children
        .iter()
        .find(|child| child.name == "Correlation")?;
    let value = correlation.attribute("ActivityID")?.trim();
    (!value.is_empty()).then(|| value.to_string())
}

/// Converts one event, or reports why it has no position.
///
/// A record whose timestamp did not parse carries `timestamp_epoch == 0`, which is 1970 and not a
/// time any Windows event was written. Treating it as a real position would drop the event at the
/// far left of every timeline and imply it happened first.
pub fn from_event(record: &EvtxRecord) -> Result<TimelineItem, UnplacedItem> {
    if record.timestamp_epoch == 0 {
        return Err(UnplacedItem {
            origin: origin_of(record),
            reason: UnplacedReason::MissingTimestamp,
        });
    }

    Ok(TimelineItem {
        timestamp_ms: record.timestamp_epoch,
        severity: severity_of(record.level),
        message: record.message.clone(),
        origin: origin_of(record),
    })
}

/// Builds one timeline from parsed log entries and events.
pub fn build(entries: &[LogEntry], records: &[EvtxRecord]) -> UnifiedTimeline {
    let mut placed = Vec::with_capacity(entries.len() + records.len());
    let mut unplaced = Vec::new();

    for entry in entries {
        match from_log_entry(entry) {
            Ok(item) => placed.push(item),
            Err(reason) => unplaced.push(reason),
        }
    }
    for record in records {
        match from_event(record) {
            Ok(item) => placed.push(item),
            Err(reason) => unplaced.push(reason),
        }
    }

    merge(placed, unplaced)
}

/// Appends new log and event records while preserving existing placed and unplaced items.
pub fn append(timeline: &mut UnifiedTimeline, entries: &[LogEntry], records: &[EvtxRecord]) {
    let mut placed = std::mem::take(&mut timeline.items);
    let mut unplaced = std::mem::take(&mut timeline.unplaced);
    for entry in entries {
        match from_log_entry(entry) {
            Ok(item) => placed.push(item),
            Err(item) => unplaced.push(item),
        }
    }
    for record in records {
        match from_event(record) {
            Ok(item) => placed.push(item),
            Err(item) => unplaced.push(item),
        }
    }
    *timeline = merge(placed, unplaced);
}

#[cfg(test)]
mod tests {
    use super::*;
    fn record(timestamp_epoch: i64, message: &str, level: EvtxLevel) -> EvtxRecord {
        EvtxRecord {
            id: 0,
            // Distinct from event_id below, so a test cannot pass while reading the wrong one.
            event_record_id: 1234,
            timestamp: String::new(),
            timestamp_epoch,
            provider: "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider"
                .to_string(),
            channel: "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin"
                .to_string(),
            event_id: 76,
            level,
            computer: "TESTHOST-01".to_string(),
            message: message.to_string(),
            event_data: Vec::new(),
            raw_xml: String::new(),
            source_label: "Live".to_string(),
            task: None,
            opcode: None,
            process_id: None,
            thread_id: None,
            user_sid: None,
            keywords: None,
            mapped: Vec::new(),
        }
    }

    fn entry(timestamp: Option<i64>, message: &str) -> LogEntry {
        LogEntry {
            line_number: 12,
            message: message.to_string(),
            component: Some("IME".to_string()),
            timestamp,
            file_path: "C:/logs/IntuneManagementExtension.log".to_string(),
            ..LogEntry::default()
        }
    }

    #[test]
    fn an_event_and_the_log_lines_around_it_interleave() {
        // The case the whole feature exists for.
        let timeline = build(
            &[
                entry(Some(1_000), "Checking enrollment"),
                entry(Some(3_000), "Token request rejected"),
            ],
            &[record(2_000, "MDM enroll failed", EvtxLevel::Error)],
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
        assert!(timeline.is_complete());
    }

    #[test]
    fn an_event_with_no_parsed_timestamp_is_unplaced_rather_than_dated_to_1970() {
        // Epoch zero would put it at the far left of every timeline and imply it happened first.
        let timeline = build(&[], &[record(0, "undated", EvtxLevel::Error)]);
        assert!(timeline.items.is_empty());
        assert_eq!(timeline.unplaced.len(), 1);
        assert_eq!(
            timeline.unplaced[0].reason,
            UnplacedReason::MissingTimestamp
        );
    }

    #[test]
    fn an_unplaced_event_still_identifies_itself() {
        let timeline = build(&[], &[record(0, "undated", EvtxLevel::Error)]);
        match &timeline.unplaced[0].origin {
            TimelineOrigin::Event {
                channel,
                event_id,
                record_id,
                ..
            } => {
                assert!(channel.contains("DeviceManagement"));
                // Distinct values, so mapping event_id to record_id or the reverse fails here.
                assert_eq!(*event_id, 76);
                assert_eq!(*record_id, 1234);
            }
            other => panic!("expected an event origin, got {other:?}"),
        }
    }

    #[test]
    fn unplaced_items_from_both_sides_are_collected_together() {
        let timeline = build(
            &[entry(None, "continuation line")],
            &[record(0, "undated event", EvtxLevel::Information)],
        );
        assert_eq!(timeline.unplaced.len(), 2);
        assert!(!timeline.is_complete());
    }

    #[test]
    fn every_level_maps_without_panicking() {
        // Every arm asserted, not just the two ends. The loop previously only checked the
        // timestamp, which is independent of the level, so a wrong arm for Warning, Error or
        // Information passed.
        for (level, expected) in [
            (EvtxLevel::Critical, TimelineSeverity::Critical),
            (EvtxLevel::Error, TimelineSeverity::Error),
            (EvtxLevel::Warning, TimelineSeverity::Warning),
            (EvtxLevel::Information, TimelineSeverity::Info),
            (EvtxLevel::Verbose, TimelineSeverity::Verbose),
        ] {
            let item = from_event(&record(1, "x", level)).expect("placed");
            assert_eq!(item.timestamp_ms, 1);
            assert_eq!(
                item.severity, expected,
                "{level:?} must map to {expected:?}"
            );
            assert_eq!(severity_of(level), expected);
        }
    }

    #[test]
    fn an_empty_build_is_complete_and_empty() {
        let timeline = build(&[], &[]);
        assert!(timeline.items.is_empty());
        assert!(timeline.is_complete());
        assert_eq!(timeline.span_ms(), None);
    }
    #[test]
    fn event_origin_preserves_source_machine_process_and_activity() {
        let mut source = record(1, "x", EvtxLevel::Information);
        source.source_label = "bundle/evidence/events.evtx".to_string();
        source.computer = "HOST-A".to_string();
        source.process_id = Some(4321);
        source.raw_xml =
            r#"<Event><System><Correlation ActivityID="{1234}" RelatedActivityID="{5678}"/></System></Event>"#
                .to_string();

        match &from_event(&source).expect("placed").origin {
            TimelineOrigin::Event {
                source,
                machine,
                bundle,
                process_id,
                activity_id,
                ..
            } => {
                assert_eq!(source, "bundle/evidence/events.evtx");
                assert_eq!(machine.as_deref(), Some("HOST-A"));
                assert_eq!(bundle.as_deref(), Some("bundle"));
                assert_eq!(*process_id, Some(4321));
                assert_eq!(activity_id.as_deref(), Some("{1234}"));
            }
            other => panic!("expected event origin, got {other:?}"),
        }
    }

    #[test]
    fn same_basename_sources_with_reused_event_record_ids_keep_distinct_keys() {
        let mut first = record(1_000, "first source", EvtxLevel::Information);
        first.id = 101;
        first.source_label = "C:\\evidence\\folder-a\\capture.evtx".to_string();
        first.computer = "HOST-A".to_string();

        let mut second = record(1_000, "second source", EvtxLevel::Information);
        second.id = 202;
        second.source_label = "D:\\evidence\\folder-b\\capture.evtx".to_string();
        second.computer = "HOST-B".to_string();

        let timeline = build(&[], &[first, second]);
        let origins: Vec<_> = timeline
            .items
            .iter()
            .map(|item| match &item.origin {
                TimelineOrigin::Event {
                    stable_id,
                    source,
                    machine,
                    record_id,
                    ..
                } => (*stable_id, source.clone(), machine.clone(), *record_id),
                other => panic!("expected event origin, got {other:?}"),
            })
            .collect();

        assert_eq!(
            origins,
            vec![
                (
                    101,
                    "C:\\evidence\\folder-a\\capture.evtx".to_string(),
                    Some("HOST-A".to_string()),
                    1234,
                ),
                (
                    202,
                    "D:\\evidence\\folder-b\\capture.evtx".to_string(),
                    Some("HOST-B".to_string()),
                    1234,
                ),
            ]
        );
    }

    #[test]
    fn related_activity_does_not_masquerade_as_activity() {
        let mut source = record(1, "x", EvtxLevel::Information);
        source.raw_xml =
            r#"<Event><System><Correlation RelatedActivityID="{5678}"/></System></Event>"#
                .to_string();
        let item = from_event(&source).expect("placed");
        match item.origin {
            TimelineOrigin::Event { activity_id, .. } => assert_eq!(activity_id, None),
            other => panic!("expected event origin, got {other:?}"),
        }
    }

    #[test]
    fn activity_id_requires_the_system_correlation_element() {
        let mut source = record(1, "x", EvtxLevel::Information);
        source.raw_xml = r#"<Event><System><Provider ActivityID="{wrong}"/></System><Correlation ActivityID="{outside}"/></Event>"#.to_string();
        let item = from_event(&source).expect("placed");
        match item.origin {
            TimelineOrigin::Event { activity_id, .. } => assert_eq!(activity_id, None),
            other => panic!("expected event origin, got {other:?}"),
        }
    }

    #[test]
    fn unknown_computer_is_rendered_as_absent_machine_provenance() {
        let mut source = record(1, "x", EvtxLevel::Information);
        source.computer = "Unknown".to_string();
        let item = from_event(&source).expect("placed");
        match item.origin {
            TimelineOrigin::Event { machine, .. } => assert_eq!(machine, None),
            other => panic!("expected event origin, got {other:?}"),
        }
    }

    #[test]
    fn equal_timestamp_event_append_keeps_input_order() {
        let mut timeline = build(
            &[],
            &[record(5_000, "existing", EvtxLevel::Information)],
        );
        let mut appended = record(5_000, "appended", EvtxLevel::Information);
        appended.id = 99;
        append(&mut timeline, &[], &[appended]);
        let messages: Vec<_> = timeline.items.iter().map(|item| item.message.as_str()).collect();
        assert_eq!(messages, vec!["existing", "appended"]);
    }
    #[test]
    fn append_reconciles_new_events_without_dropping_unplaced_records() {
        let mut timeline = build(&[], &[record(2_000, "second", EvtxLevel::Information)]);
        append(
            &mut timeline,
            &[],
            &[record(1_000, "first", EvtxLevel::Information), record(0, "undated", EvtxLevel::Warning)],
        );

        let messages: Vec<&str> = timeline.items.iter().map(|item| item.message.as_str()).collect();
        assert_eq!(messages, vec!["first", "second"]);
        assert_eq!(timeline.unplaced.len(), 1);
        assert!(!timeline.is_complete());
    }
}
