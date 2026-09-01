//! Placing Windows events onto the unified timeline.
//!
//! The merge itself lives in `cmtraceopen_parser::unified_timeline`, which is pure and knows
//! nothing about where items came from. This is the event-side adapter: it converts an
//! [`EvtxRecord`] into a timeline item, or reports why it cannot be placed.
//!
//! The log side needs no adapter because `LogEntry` already lives in the parser crate.

use cmtraceopen_parser::models::log_entry::LogEntry;
use cmtraceopen_parser::unified_timeline::{
    bundle_from_source, correlate_timeline, from_log_entry, merge, timeline_sort_key, TimelineItem,
    TimelineOrigin, TimelineSeverity, UnifiedTimeline, UnplacedItem, UnplacedReason,
};

use super::event_node::extract_event_identity;
use super::models::{EvtxLevel, EvtxOriginKind, EvtxRecord};
///
/// `EvtxRecord` stores a decoded level rather than the raw `System/Level` value, so this maps the
/// decoded form. Information is the resting state, matching how the decoder treats a level it does
/// not recognise.
///
fn severity_of(level: EvtxLevel) -> TimelineSeverity {
    match level {
        EvtxLevel::Critical => TimelineSeverity::Critical,
        EvtxLevel::Error => TimelineSeverity::Error,
        EvtxLevel::Warning => TimelineSeverity::Warning,
        EvtxLevel::Verbose => TimelineSeverity::Verbose,
        EvtxLevel::Information => TimelineSeverity::Info,
    }
}
fn missing_record_digest(record: &EvtxRecord) -> String {
    let mut first = 2_166_136_261_u32;
    let mut second = first ^ 0x9e37_79b9;
    let mut feed = |bytes: &[u8]| {
        for &byte in bytes {
            first = (first ^ u32::from(byte)).wrapping_mul(16_777_619);
            second = (second ^ u32::from(byte ^ 0xa5)).wrapping_mul(16_777_619);
        }
    };
    feed(record.timestamp_epoch.to_string().as_bytes());
    feed(b"|");
    feed(record.event_id.to_string().as_bytes());
    feed(b"|");
    feed(record.provider.as_bytes());
    feed(b"|");
    feed(record.message.as_bytes());
    feed(b"|");
    feed(record.raw_xml.as_bytes());
    format!("{first:08x}{second:08x}")
}

fn record_id_text(record: &EvtxRecord) -> Option<String> {
    let value = record.event_record_id_text.as_deref()?.trim();
    (!value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| value.to_string())
}

fn usable_record_id_text(record: &EvtxRecord) -> Option<String> {
    record_id_text(record).filter(|value| value.bytes().any(|byte| byte != b'0'))
}

fn record_id(record: &EvtxRecord) -> Option<u64> {
    record
        .event_record_id_text
        .as_deref()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value != 0)
        .or_else(|| (record.event_record_id != 0).then_some(record.event_record_id))
}

fn stable_event_id(record: &EvtxRecord) -> String {
    let source = format!(
        "source{}:{}",
        record.source_label.len(),
        record.source_label
    );
    let channel = format!("channel{}:{}", record.channel.len(), record.channel);
    let machine = record.computer.trim();
    let machine = format!("machine{}:{}", machine.len(), machine);
    let identity = format!("{source}|{machine}|{channel}");
    if let Some(event_record_id) = usable_record_id_text(record) {
        return format!("{identity}|record{event_record_id}");
    }
    if let Some(event_record_id) = record_id(record) {
        return format!("{identity}|record{event_record_id}");
    }
    format!("{identity}|missing{}", missing_record_digest(record))
}

fn stable_event_id_with_occurrence(record: &EvtxRecord, occurrence: usize) -> String {
    let base = stable_event_id(record);
    if usable_record_id_text(record).is_some() || record_id(record).is_some() {
        return base;
    }
    format!("{base}-{occurrence}")
}
fn stable_event_base_from_id(stable_id: &str) -> &str {
    if stable_id.contains("|missing") {
        stable_id
            .rsplit_once('-')
            .map(|(base, _)| base)
            .unwrap_or(stable_id)
    } else {
        stable_id
    }
}
fn normalized_identity(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn identity_conflicts_for(record: &EvtxRecord) -> Vec<String> {
    let identity = extract_event_identity(&record.event_data);
    let mut conflicts = identity.conflicts;
    for (label, normalized_value, data_value) in [
        (
            "activityId",
            normalized_identity(record.activity_id.as_deref()),
            identity.activity_id.as_deref(),
        ),
        (
            "relatedActivityId",
            normalized_identity(record.related_activity_id.as_deref()),
            identity.related_activity_id.as_deref(),
        ),
    ] {
        if let (Some(normalized_value), Some(data_value)) = (normalized_value, data_value) {
            if !normalized_value.eq_ignore_ascii_case(data_value.trim())
                && !conflicts.iter().any(|existing| existing == label)
            {
                conflicts.push(label.to_string());
            }
        }
    }
    conflicts
}

fn normalized_provenance(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty()
        || matches!(
            trimmed.to_ascii_lowercase().as_str(),
            "unknown" | "n/a" | "na" | "none" | "null" | "not available" | "not_applicable"
        )
    {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn machine_of(value: &str) -> Option<String> {
    normalized_provenance(value)
}

fn component_of(provider: &str) -> Option<String> {
    normalized_provenance(provider)
}

fn origin_of(record: &EvtxRecord, occurrence: usize) -> TimelineOrigin {
    if record.origin_kind == EvtxOriginKind::Log {
        return TimelineOrigin::Log {
            file: record.source_label.clone(),
            component: component_of(&record.provider),
            line: u32::try_from(record.event_record_id).unwrap_or(u32::MAX),
            source: record.source_label.clone(),
            machine: machine_of(&record.computer),
            bundle: bundle_from_source(&record.source_label),
            record_id: record.event_record_id,
        };
    }

    TimelineOrigin::Event {
        stable_id: stable_event_id_with_occurrence(record, occurrence),
        source: record.source_label.clone(),
        machine: machine_of(&record.computer),
        bundle: bundle_from_source(&record.source_label),
        channel: record.channel.clone(),
        provider: record.provider.clone(),
        process_id: record.process_id,
        activity_id: normalized_identity(record.activity_id.as_deref()),
        related_activity_id: normalized_identity(record.related_activity_id.as_deref()),
        session_id: record.session_id.clone(),
        device_id: record.device_id.clone(),
        user_id: record.user_id.clone().or_else(|| record.user_sid.clone()),
        process_start_time: record.process_start_time.clone(),
        identity_conflicts: identity_conflicts_for(record),
        event_id: record.event_id,
        record_id: record.event_record_id,
        record_id_text: record_id_text(record),
    }
}

fn parsed_timestamp_epoch(record: &EvtxRecord) -> Option<i64> {
    if record.timestamp_epoch != 0 {
        return Some(record.timestamp_epoch);
    }
    let timestamp = record.timestamp.trim();
    if timestamp.is_empty() {
        return None;
    }
    chrono::DateTime::parse_from_rfc3339(timestamp)
        .map(|parsed| parsed.timestamp_millis())
        .or_else(|_| {
            chrono::NaiveDateTime::parse_from_str(timestamp, "%Y-%m-%dT%H:%M:%S%.f")
                .map(|parsed| parsed.and_utc().timestamp_millis())
        })
        .ok()
}

fn timestamp_is_present(record: &EvtxRecord) -> bool {
    parsed_timestamp_epoch(record).is_some()
}

/// Converts one event, or reports why it has no position.
pub fn from_event(record: &EvtxRecord) -> Result<TimelineItem, Box<UnplacedItem>> {
    from_event_with_occurrence(record, 0)
}

fn from_event_with_occurrence(
    record: &EvtxRecord,
    occurrence: usize,
) -> Result<TimelineItem, Box<UnplacedItem>> {
    from_event_with_origin(record, origin_of(record, occurrence))
}

fn from_event_with_origin(
    record: &EvtxRecord,
    origin: TimelineOrigin,
) -> Result<TimelineItem, Box<UnplacedItem>> {
    if !timestamp_is_present(record) {
        return Err(Box::new(UnplacedItem {
            origin,
            reason: UnplacedReason::MissingTimestamp,
        }));
    }

    Ok(TimelineItem {
        timestamp_ms: parsed_timestamp_epoch(record).unwrap_or(0),
        severity: severity_of(record.level),
        message: record.message.clone(),
        origin,
    })
}

fn origin_with_occurrence(
    mut origin: TimelineOrigin,
    record: &EvtxRecord,
    occurrence: usize,
) -> TimelineOrigin {
    if usable_record_id_text(record).is_none() && record_id(record).is_none() {
        if let TimelineOrigin::Event { stable_id, .. } = &mut origin {
            *stable_id = format!("{}-{occurrence}", stable_event_id(record));
        }
    }
    origin
}

struct OrderedRecord<'a> {
    record: &'a EvtxRecord,
    origin: TimelineOrigin,
    occurrence: usize,
}

fn ordered_records(records: &[EvtxRecord]) -> Vec<OrderedRecord<'_>> {
    let mut ordered: Vec<_> = records
        .iter()
        .map(|record| {
            let origin = origin_of(record, 0);
            let sort_key = timeline_sort_key(
                parsed_timestamp_epoch(record).unwrap_or(0),
                severity_of(record.level),
                &record.message,
                &origin,
            );
            (record, origin, sort_key)
        })
        .collect();
    ordered.sort_by(|left, right| left.2.cmp(&right.2));
    let mut occurrence_by_key = std::collections::HashMap::new();
    ordered
        .into_iter()
        .map(|(record, origin, _)| {
            let key = stable_event_id(record);
            let occurrence = occurrence_by_key.entry(key).or_insert(0);
            let current = *occurrence;
            *occurrence += 1;
            OrderedRecord {
                record,
                origin: origin_with_occurrence(origin, record, current),
                occurrence: current,
            }
        })
        .collect()
}

/// Recomputes correlation from stable origin fields after each merge or append.
fn refresh_correlations(timeline: &mut UnifiedTimeline) {
    let (edges, gaps) = correlate_timeline(&timeline.items, &timeline.unplaced);
    timeline.edges = edges;
    timeline.coverage_gaps = gaps;
}

/// Builds one timeline from parsed log entries and events.
pub fn build(entries: &[LogEntry], records: &[EvtxRecord]) -> UnifiedTimeline {
    let mut placed = Vec::with_capacity(entries.len() + records.len());
    let mut unplaced = Vec::new();

    for entry in entries {
        match from_log_entry(entry) {
            Ok(item) => placed.push(item),
            Err(reason) => unplaced.push(*reason),
        }
    }
    for OrderedRecord { record, origin, .. } in ordered_records(records) {
        match from_event_with_origin(record, origin) {
            Ok(item) => placed.push(item),
            Err(item) => unplaced.push(*item),
        }
    }

    let mut timeline = merge(placed, unplaced);
    refresh_correlations(&mut timeline);
    timeline
}

/// Appends new log and event records while preserving existing placed and unplaced items.
pub fn append(timeline: &mut UnifiedTimeline, entries: &[LogEntry], records: &[EvtxRecord]) {
    let mut placed = std::mem::take(&mut timeline.items);
    let mut unplaced = std::mem::take(&mut timeline.unplaced);
    for entry in entries {
        match from_log_entry(entry) {
            Ok(item) => placed.push(item),
            Err(item) => unplaced.push(*item),
        }
    }
    let mut existing_occurrences = std::collections::HashMap::new();
    for origin in placed
        .iter()
        .map(|item| &item.origin)
        .chain(unplaced.iter().map(|item| &item.origin))
    {
        if let TimelineOrigin::Event { stable_id, .. } = origin {
            let base = stable_event_base_from_id(stable_id);
            *existing_occurrences
                .entry(base.to_string())
                .or_insert(0usize) += 1;
        }
    }
    for OrderedRecord {
        record,
        origin,
        occurrence,
    } in ordered_records(records)
    {
        let base = stable_event_id(record);
        let offset = existing_occurrences.get(&base).copied().unwrap_or_default();
        let origin = origin_with_occurrence(origin, record, occurrence + offset);
        match from_event_with_origin(record, origin) {
            Ok(item) => placed.push(item),
            Err(item) => unplaced.push(*item),
        }
    }
    *timeline = merge(placed, unplaced);
    refresh_correlations(timeline);
}

#[cfg(test)]
mod tests {
    use super::*;
    fn record(timestamp_epoch: i64, message: &str, level: EvtxLevel) -> EvtxRecord {
        EvtxRecord {
            id: 0,
            // Distinct from event_id below, so a test cannot pass while reading the wrong one.
            event_record_id: 1234,
            event_record_id_text: None,
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
            origin_kind: EvtxOriginKind::Event,
            task: None,
            opcode: None,
            process_id: None,
            activity_id: None,
            related_activity_id: None,
            session_id: None,
            device_id: None,
            user_id: None,
            process_start_time: None,
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
    fn log_origin_normalizes_placeholder_components() {
        for (provider, expected) in [
            ("", None),
            ("   ", None),
            ("UNKNOWN", None),
            ("unknown", None),
            ("N/A", None),
            ("not available", None),
            ("NOT_APPLICABLE", None),
            ("  ImeCore  ", Some("ImeCore")),
        ] {
            let mut source = record(1, "log", EvtxLevel::Information);
            source.origin_kind = EvtxOriginKind::Log;
            source.provider = provider.to_string();

            match origin_of(&source, 0) {
                TimelineOrigin::Log { component, .. } => {
                    assert_eq!(component.as_deref(), expected, "provider={provider:?}");
                }
                other => panic!("expected log origin, got {other:?}"),
            }
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
    fn epoch_zero_with_valid_timestamp_is_placed() {
        let mut event = record(0, "epoch", EvtxLevel::Information);
        event.timestamp = "1970-01-01T00:00:00.000Z".to_string();
        let timeline = build(&[], &[event]);
        assert_eq!(timeline.items.len(), 1);
        assert!(timeline.unplaced.is_empty());
        assert_eq!(timeline.items[0].timestamp_ms, 0);
    }

    #[test]
    fn epoch_zero_uses_non_epoch_text_timestamp_for_placement_and_order() {
        let mut text_timestamp = record(0, "text timestamp", EvtxLevel::Information);
        text_timestamp.timestamp = "2026-08-09T12:00:00.000Z".to_string();
        let earlier = record(2_000, "earlier", EvtxLevel::Information);

        let timeline = build(&[], &[text_timestamp, earlier]);

        assert_eq!(
            timeline
                .items
                .iter()
                .map(|item| item.message.as_str())
                .collect::<Vec<_>>(),
            vec!["earlier", "text timestamp"]
        );
        assert_eq!(timeline.items[1].timestamp_ms, 1_786_276_800_000);
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
        source.source_label = "/ProgramData/CmtraceOpen/Evidence/CMTRACE-20260822-120000-HOST-fedcba9876543210fedcba9876543210/evidence/event-logs/Application.evtx".to_string();
        source.computer = "HOST-A".to_string();
        source.process_id = Some(4321);
        source.activity_id = Some(" {1234} ".to_string());
        source.related_activity_id = Some("{5678}".to_string());
        source.raw_xml = "<malformed".to_string();

        match &from_event(&source).expect("placed").origin {
            TimelineOrigin::Event {
                source,
                machine,
                bundle,
                process_id,
                activity_id,
                related_activity_id,
                ..
            } => {
                assert_eq!(source, "/ProgramData/CmtraceOpen/Evidence/CMTRACE-20260822-120000-HOST-fedcba9876543210fedcba9876543210/evidence/event-logs/Application.evtx");
                assert_eq!(machine.as_deref(), Some("HOST-A"));
                assert_eq!(
                    bundle.as_deref(),
                    Some("CMTRACE-20260822-120000-HOST-fedcba9876543210fedcba9876543210")
                );
                assert_eq!(*process_id, Some(4321));
                assert_eq!(activity_id.as_deref(), Some("{1234}"));
                assert_eq!(related_activity_id.as_deref(), Some("{5678}"));
            }
            other => panic!("expected event origin, got {other:?}"),
        }
    }

    #[test]
    fn remote_source_label_and_machine_are_preserved_in_timeline_origin() {
        let mut source = record(1, "remote event", EvtxLevel::Information);
        source.source_label = "Remote: HOST-B".to_string();
        source.computer = "HOST-B".to_string();
        let expected_stable = format!(
            "source14:Remote: HOST-B|machine6:HOST-B|channel{}:{}|record1234",
            source.channel.len(),
            source.channel
        );
        match &from_event(&source).expect("placed").origin {
            TimelineOrigin::Event {
                source,
                machine: _,
                stable_id,
                ..
            } => {
                assert_eq!(source, "Remote: HOST-B");
                assert_eq!(stable_id, &expected_stable);
            }
            other => panic!("expected event origin, got {other:?}"),
        }
    }

    #[test]
    fn missing_record_ids_and_delimiter_like_sources_keep_distinct_stable_keys() {
        let mut first = record(1, "secret-token", EvtxLevel::Information);
        first.event_record_id = 0;
        first.source_label = "a/b#c".to_string();
        first.channel = "d/e#f".to_string();
        first.message = "secret-token".repeat(100);
        first.raw_xml =
            "<Event><System><EventRecordID>0</EventRecordID></System></Event>".repeat(100);

        let mut second = first.clone();
        second.message = "other-secret".repeat(100);
        second.raw_xml =
            "<Event><System><EventRecordID>0</EventRecordID><Level>2</Level></System></Event>"
                .repeat(100);

        let timeline = build(&[], &[first, second]);
        let ids: Vec<_> = timeline
            .items
            .iter()
            .map(|item| match &item.origin {
                TimelineOrigin::Event { stable_id, .. } => stable_id.clone(),
                other => panic!("expected event origin, got {other:?}"),
            })
            .collect();

        assert_eq!(ids.len(), 2);
        assert_ne!(ids[0], ids[1]);
        assert!(ids[0].starts_with("source5:a/b#c|machine11:TESTHOST-01|channel5:d/e#f|missing"));
        assert!(ids.iter().all(|id| id.len() < 128));
        assert!(ids.iter().all(|id| !id.contains("secret")));
    }

    #[test]
    fn identical_missing_ids_get_deterministic_occurrence_suffixes() {
        let mut event = record(1_000, "same", EvtxLevel::Information);
        event.event_record_id = 0;
        let timeline = build(&[], &[event.clone(), event]);
        let ids: Vec<_> = timeline
            .items
            .iter()
            .map(|item| match &item.origin {
                TimelineOrigin::Event { stable_id, .. } => stable_id.clone(),
                other => panic!("expected event origin, got {other:?}"),
            })
            .collect();
        assert_eq!(ids.len(), 2);
        assert_ne!(ids[0], ids[1]);
        assert!(ids[0].ends_with("-0") || ids[0].ends_with("-1"));
        assert!(ids[1].ends_with("-0") || ids[1].ends_with("-1"));
    }

    #[test]
    fn appending_identical_missing_id_keeps_occurrence_identity_distinct() {
        let mut event = record(1_000, "same", EvtxLevel::Information);
        event.event_record_id = 0;
        let mut timeline = build(&[], &[event.clone()]);
        append(&mut timeline, &[], &[event]);
        let ids: Vec<_> = timeline
            .items
            .iter()
            .map(|item| match &item.origin {
                TimelineOrigin::Event { stable_id, .. } => stable_id.clone(),
                other => panic!("expected event origin, got {other:?}"),
            })
            .collect();
        assert_eq!(ids.len(), 2);
        assert_ne!(ids[0], ids[1]);
        assert!(ids.iter().any(|id| id.ends_with("-0")));
        assert!(ids.iter().any(|id| id.ends_with("-1")));
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
                } => (
                    stable_id.to_string(),
                    source.clone(),
                    machine.clone(),
                    *record_id,
                ),
                other => panic!("expected event origin, got {other:?}"),
            })
            .collect();

        assert_eq!(
            origins,
            vec![
                (
                    r"source33:C:\evidence\folder-a\capture.evtx|machine6:HOST-A|channel72:Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin|record1234".to_string(),
                    r"C:\evidence\folder-a\capture.evtx".to_string(),
                    Some("HOST-A".to_string()),
                    1234,
                ),
                (
                    r"source33:D:\evidence\folder-b\capture.evtx|machine6:HOST-B|channel72:Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin|record1234".to_string(),
                    r"D:\evidence\folder-b\capture.evtx".to_string(),
                    Some("HOST-B".to_string()),
                    1234,
                ),
            ]
        );
    }

    #[test]
    fn lossless_event_record_id_text_controls_stable_identity() {
        let mut event = record(1_000, "exact", EvtxLevel::Information);
        event.event_record_id = 9_007_199_254_740_992;
        event.event_record_id_text = Some("9007199254740993".to_string());

        let timeline = build(&[], &[event]);
        let stable_id = match &timeline.items[0].origin {
            TimelineOrigin::Event { stable_id, .. } => stable_id,
            other => panic!("expected event origin, got {other:?}"),
        };
        assert!(stable_id.ends_with("|record9007199254740993"));
    }

    #[test]
    fn equal_timestamp_events_have_deterministic_order_across_input_permutations() {
        let mut first = record(1_000, "first", EvtxLevel::Information);
        first.event_record_id = 20;
        let mut second = record(1_000, "second", EvtxLevel::Information);
        second.event_record_id = 10;

        let one = build(&[], &[first.clone(), second.clone()]);
        let two = build(&[], &[second, first]);
        let messages_one: Vec<_> = one.items.iter().map(|item| item.message.as_str()).collect();
        let messages_two: Vec<_> = two.items.iter().map(|item| item.message.as_str()).collect();
        assert_eq!(messages_one, vec!["second", "first"]);
        assert_eq!(messages_one, messages_two);
    }

    #[test]
    fn appending_an_earlier_event_keeps_existing_source_record_identity() {
        let mut existing = record(2_000, "existing", EvtxLevel::Information);
        existing.id = 0;
        existing.source_label = "Live".to_string();
        existing.channel = "Security".to_string();

        let mut earlier = record(1_000, "earlier", EvtxLevel::Information);
        earlier.id = 99;
        earlier.event_record_id = 5678;
        earlier.source_label = "Live".to_string();
        earlier.channel = "Security".to_string();

        let mut timeline = build(&[], &[existing]);
        append(&mut timeline, &[], &[earlier]);
        let ids: Vec<_> = timeline
            .items
            .iter()
            .map(|item| match &item.origin {
                TimelineOrigin::Event { stable_id, .. } => stable_id.clone(),
                other => panic!("expected event origin, got {other:?}"),
            })
            .collect();

        assert_eq!(
            ids,
            vec![
                "source4:Live|machine11:TESTHOST-01|channel8:Security|record5678".to_string(),
                "source4:Live|machine11:TESTHOST-01|channel8:Security|record1234".to_string(),
            ]
        );
    }

    #[test]
    fn related_activity_does_not_masquerade_as_activity() {
        let mut source = record(1, "x", EvtxLevel::Information);
        source.related_activity_id = Some("{5678}".to_string());
        let item = from_event(&source).expect("placed");
        match item.origin {
            TimelineOrigin::Event {
                activity_id,
                related_activity_id,
                ..
            } => {
                assert_eq!(activity_id, None);
                assert_eq!(related_activity_id.as_deref(), Some("{5678}"));
            }
            other => panic!("expected event origin, got {other:?}"),
        }
    }
    #[test]
    fn blank_normalized_activity_id_does_not_reparse_raw_xml() {
        let mut source = record(1, "x", EvtxLevel::Information);
        source.activity_id = Some("  ".to_string());
        source.raw_xml =
            r#"<Event><System><Correlation ActivityID="{from-xml}"/></System></Event>"#.to_string();
        let item = from_event(&source).expect("placed");
        match item.origin {
            TimelineOrigin::Event { activity_id, .. } => assert_eq!(activity_id, None),
            other => panic!("expected event origin, got {other:?}"),
        }
    }

    #[test]
    fn normalized_system_identity_reports_event_data_conflicts() {
        let mut source = record(1, "x", EvtxLevel::Information);
        source.activity_id = Some("{system}".to_string());
        source.event_data.push(super::super::models::EvtxField {
            name: "ActivityID".to_string(),
            value: "{payload}".to_string(),
        });
        source.raw_xml = "<malformed".to_string();

        match from_event(&source).expect("placed").origin {
            TimelineOrigin::Event {
                activity_id,
                identity_conflicts,
                ..
            } => {
                assert_eq!(activity_id.as_deref(), Some("{system}"));
                assert_eq!(identity_conflicts, vec!["activityId"]);
            }
            other => panic!("expected event origin, got {other:?}"),
        }
    }
    #[test]
    fn backend_activity_ids_are_trimmed_before_timeline_correlation() {
        let mut source = record(1, "x", EvtxLevel::Information);
        source.activity_id = Some("  {from-backend}  ".to_string());
        let item = from_event(&source).expect("placed");
        match item.origin {
            TimelineOrigin::Event { activity_id, .. } => {
                assert_eq!(activity_id.as_deref(), Some("{from-backend}"));
            }
            other => panic!("expected event origin, got {other:?}"),
        }
    }

    #[test]
    fn build_populates_exact_activity_edge_and_coverage_state() {
        let mut first = record(1_000, "first", EvtxLevel::Information);
        first.event_record_id = 1;
        first.event_record_id_text = Some("1".into());
        first.activity_id = Some("{activity}".into());
        let mut second = record(2_000, "second", EvtxLevel::Error);
        second.event_record_id = 2;
        second.event_record_id_text = Some("2".into());
        second.activity_id = Some("{activity}".into());

        let timeline = build(&[], &[first, second]);
        assert_eq!(timeline.edges.len(), 1);
        assert_eq!(
            timeline.edges[0].key.kind,
            cmtraceopen_parser::unified_timeline::TimelineCorrelationKeyKind::ActivityId
        );
        assert_eq!(
            timeline.edges[0].strength,
            cmtraceopen_parser::unified_timeline::TimelineCorrelationStrength::Exact
        );
        assert_eq!(
            timeline.edges[0].coverage.state,
            cmtraceopen_parser::unified_timeline::TimelineCorrelationCoverageState::Covered
        );
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
    fn equal_identity_events_match_full_build_and_append_history() {
        let existing = record(5_000, "existing", EvtxLevel::Information);
        let appended = record(5_000, "appended", EvtxLevel::Information);
        let full = build(&[], &[existing.clone(), appended.clone()]);

        let mut split = build(&[], &[existing]);
        append(&mut split, &[], &[appended]);

        assert_eq!(split, full);
        let messages: Vec<_> = split
            .items
            .iter()
            .map(|item| item.message.as_str())
            .collect();
        assert_eq!(messages, vec!["appended", "existing"]);
    }

    #[test]
    fn cross_source_equal_time_order_matches_full_build_and_append_history() {
        let event = record(5_000, "event", EvtxLevel::Information);
        let log = entry(Some(5_000), "log");
        let full = build(std::slice::from_ref(&log), std::slice::from_ref(&event));

        let mut appended = build(&[], &[]);
        append(&mut appended, &[log], &[]);
        append(&mut appended, &[], &[event]);

        let full_messages: Vec<_> = full
            .items
            .iter()
            .map(|item| item.message.as_str())
            .collect();
        let appended_messages: Vec<_> = appended
            .items
            .iter()
            .map(|item| item.message.as_str())
            .collect();
        assert_eq!(full_messages, appended_messages);
        assert_eq!(full_messages, vec!["event", "log"]);
    }
    #[test]
    fn append_reconciles_new_events_without_dropping_unplaced_records() {
        let mut timeline = build(&[], &[record(2_000, "second", EvtxLevel::Information)]);
        append(
            &mut timeline,
            &[],
            &[
                record(1_000, "first", EvtxLevel::Information),
                record(0, "undated", EvtxLevel::Warning),
            ],
        );

        let messages: Vec<&str> = timeline
            .items
            .iter()
            .map(|item| item.message.as_str())
            .collect();
        assert_eq!(messages, vec!["first", "second"]);
        assert_eq!(timeline.unplaced.len(), 1);
        assert!(!timeline.is_complete());
    }
}
