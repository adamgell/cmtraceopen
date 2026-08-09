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
        channel: record.channel.clone(),
        provider: record.provider.clone(),
        event_id: record.event_id,
        record_id: record.event_record_id,
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn record(timestamp_epoch: i64, message: &str, level: EvtxLevel) -> EvtxRecord {
        EvtxRecord {
            id: 0,
            event_record_id: 76,
            timestamp: String::new(),
            timestamp_epoch,
            provider: "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider"
                .to_string(),
            channel: "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin"
                .to_string(),
            event_id: 76,
            level,
            computer: "RING0IVY24-01".to_string(),
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
                assert_eq!(*event_id, 76);
                assert_eq!(*record_id, 76);
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
        for level in [
            EvtxLevel::Critical,
            EvtxLevel::Error,
            EvtxLevel::Warning,
            EvtxLevel::Information,
            EvtxLevel::Verbose,
        ] {
            let item = from_event(&record(1, "x", level)).expect("placed");
            assert_eq!(item.timestamp_ms, 1);
        }
        assert_eq!(severity_of(EvtxLevel::Critical), TimelineSeverity::Critical);
        assert_eq!(severity_of(EvtxLevel::Verbose), TimelineSeverity::Verbose);
    }

    #[test]
    fn an_empty_build_is_complete_and_empty() {
        let timeline = build(&[], &[]);
        assert!(timeline.items.is_empty());
        assert!(timeline.is_complete());
        assert_eq!(timeline.span_ms(), None);
    }
}
