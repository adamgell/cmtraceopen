use app_lib::sysmon::evtx_parser::build_summary;
use app_lib::sysmon::models::{SysmonEvent, SysmonEventType, SysmonSeverity};

fn make_event(id: u64, timestamp: &str, timestamp_ms: Option<i64>, event_id: u32) -> SysmonEvent {
    SysmonEvent {
        id,
        record_id: id,
        timestamp: timestamp.to_string(),
        timestamp_ms,
        event_id,
        event_type: SysmonEventType::from_event_id(event_id),
        event_type_display: SysmonEventType::from_event_id(event_id)
            .display_name()
            .to_string(),
        severity: SysmonSeverity::Info,
        message: String::new(),
        computer: Some("DESKTOP-TEST".to_string()),
        utc_time: None,
        user: None,
        process_guid: Some("{00000000-0000-0000-0000-000000000001}".to_string()),
        process_id: None,
        image: None,
        command_line: None,
        parent_image: None,
        parent_command_line: None,
        parent_process_id: None,
        target_filename: None,
        target_object: None,
        details: None,
        hashes: None,
        protocol: None,
        source_ip: None,
        source_port: None,
        destination_ip: None,
        destination_port: None,
        destination_hostname: None,
        query_name: None,
        query_results: None,
        source_image: None,
        target_image: None,
        granted_access: None,
        source_file: "Sysmon.evtx".to_string(),
        rule_name: None,
    }
}

#[test]
fn build_summary_empty_events() {
    let summary = build_summary(&[], vec![], 0);
    assert_eq!(summary.total_events, 0);
    assert_eq!(summary.unique_processes, 0);
    assert!(summary.earliest_timestamp.is_none());
    assert!(summary.latest_timestamp.is_none());
}

#[test]
fn build_summary_counts_event_types() {
    let events = vec![
        make_event(0, "2024-04-28T10:00:00Z", Some(1714298400000), 1),
        make_event(1, "2024-04-28T10:00:01Z", Some(1714298401000), 1),
        make_event(2, "2024-04-28T10:00:02Z", Some(1714298402000), 3),
    ];
    let summary = build_summary(&events, vec!["test.evtx".to_string()], 0);
    assert_eq!(summary.total_events, 3);
    assert_eq!(summary.unique_computers, 1);

    // Two ProcessCreate (id=1) events and one NetworkConnect (id=3)
    let process_create_count = summary
        .event_type_counts
        .iter()
        .find(|c| c.event_id == 1)
        .map(|c| c.count)
        .unwrap_or(0);
    assert_eq!(process_create_count, 2);
}

#[test]
fn build_summary_tracks_earliest_latest_with_numeric_timestamps() {
    let events = vec![
        make_event(0, "2024-04-28T10:00:00Z", Some(1714298400000), 1),
        make_event(1, "2024-04-28T09:00:00Z", Some(1714294800000), 1),
        make_event(2, "2024-04-28T11:00:00Z", Some(1714302000000), 1),
    ];
    let summary = build_summary(&events, vec![], 0);
    assert_eq!(
        summary.earliest_timestamp.as_deref(),
        Some("2024-04-28T09:00:00Z")
    );
    assert_eq!(
        summary.latest_timestamp.as_deref(),
        Some("2024-04-28T11:00:00Z")
    );
}

#[test]
fn build_summary_string_only_events_still_tracked_after_numeric() {
    // Issue 10: string-only events must still update earliest/latest
    // even when numeric timestamps have been seen
    let events = vec![
        make_event(0, "2024-04-28T10:00:00Z", Some(1714298400000), 1),
        make_event(1, "2024-04-28T08:00:00Z", None, 1), // earlier, but no ms
        make_event(2, "2024-04-28T12:00:00Z", None, 1), // later, but no ms
    ];
    let summary = build_summary(&events, vec![], 0);
    // The string-only event at 08:00 should be tracked as earliest
    assert_eq!(
        summary.earliest_timestamp.as_deref(),
        Some("2024-04-28T08:00:00Z")
    );
    // The string-only event at 12:00 should be tracked as latest
    assert_eq!(
        summary.latest_timestamp.as_deref(),
        Some("2024-04-28T12:00:00Z")
    );
}

#[test]
fn build_summary_parse_errors_propagated() {
    let summary = build_summary(&[], vec!["a.evtx".to_string()], 42);
    assert_eq!(summary.parse_errors, 42);
    assert_eq!(summary.source_files.len(), 1);
}
