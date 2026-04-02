use app_lib::sysmon::evtx_parser::{build_dashboard_data, build_summary, extract_config};
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

#[test]
fn dashboard_data_empty_events() {
    let data = build_dashboard_data(&[]);
    assert!(data.timeline_minute.is_empty());
    assert!(data.timeline_hourly.is_empty());
    assert!(data.timeline_daily.is_empty());
    assert!(data.top_processes.is_empty());
    assert!(data.top_destinations.is_empty());
    assert!(data.top_ports.is_empty());
    assert!(data.top_dns_queries.is_empty());
    assert!(data.top_target_files.is_empty());
    assert!(data.top_registry_keys.is_empty());
    assert_eq!(data.security_events.total_warnings, 0);
    assert_eq!(data.security_events.total_errors, 0);
}

#[test]
fn dashboard_data_timeline_bucketing() {
    let events = vec![
        make_event(0, "2024-04-28T10:00:00Z", Some(1714298400000), 1),
        make_event(1, "2024-04-28T10:00:30Z", Some(1714298430000), 1),
        make_event(2, "2024-04-28T11:00:00Z", Some(1714302000000), 1),
    ];
    let data = build_dashboard_data(&events);
    assert_eq!(data.timeline_minute.len(), 2);
    assert_eq!(data.timeline_minute[0].count, 2);
    assert_eq!(data.timeline_minute[1].count, 1);
    assert_eq!(data.timeline_hourly.len(), 2);
    assert_eq!(data.timeline_daily.len(), 1);
    assert_eq!(data.timeline_daily[0].count, 3);
}

#[test]
fn dashboard_data_top_processes() {
    let mut e1 = make_event(0, "2024-04-28T10:00:00Z", Some(1714298400000), 1);
    e1.image = Some("C:\\Windows\\svchost.exe".to_string());
    let mut e2 = make_event(1, "2024-04-28T10:00:01Z", Some(1714298401000), 1);
    e2.image = Some("C:\\Windows\\svchost.exe".to_string());
    let mut e3 = make_event(2, "2024-04-28T10:00:02Z", Some(1714298402000), 1);
    e3.image = Some("C:\\Windows\\explorer.exe".to_string());

    let data = build_dashboard_data(&[e1, e2, e3]);
    assert_eq!(data.top_processes.len(), 2);
    assert_eq!(data.top_processes[0].name, "C:\\Windows\\svchost.exe");
    assert_eq!(data.top_processes[0].count, 2);
    assert_eq!(data.top_processes[1].name, "C:\\Windows\\explorer.exe");
    assert_eq!(data.top_processes[1].count, 1);
}

#[test]
fn dashboard_data_network_and_dns() {
    let mut net1 = make_event(0, "2024-04-28T10:00:00Z", Some(1714298400000), 3);
    net1.destination_ip = Some("10.0.0.1".to_string());
    net1.destination_port = Some(443);
    net1.destination_hostname = Some("example.com".to_string());

    let mut net2 = make_event(1, "2024-04-28T10:00:01Z", Some(1714298401000), 3);
    net2.destination_ip = Some("10.0.0.1".to_string());
    net2.destination_port = Some(80);

    let mut dns1 = make_event(2, "2024-04-28T10:00:02Z", Some(1714298402000), 22);
    dns1.query_name = Some("google.com".to_string());

    let mut dns2 = make_event(3, "2024-04-28T10:00:03Z", Some(1714298403000), 22);
    dns2.query_name = Some("google.com".to_string());

    let data = build_dashboard_data(&[net1, net2, dns1, dns2]);
    assert_eq!(data.top_destinations.len(), 2);
    assert_eq!(data.top_destinations[0].count, 1);
    assert_eq!(data.top_ports.len(), 2);
    assert_eq!(data.top_dns_queries.len(), 1);
    assert_eq!(data.top_dns_queries[0].name, "google.com");
    assert_eq!(data.top_dns_queries[0].count, 2);
}

#[test]
fn dashboard_data_security_events() {
    let mut e1 = make_event(0, "2024-04-28T10:00:00Z", Some(1714298400000), 8);
    e1.severity = SysmonSeverity::Warning;
    let mut e2 = make_event(1, "2024-04-28T10:00:01Z", Some(1714298401000), 255);
    e2.severity = SysmonSeverity::Error;
    let e3 = make_event(2, "2024-04-28T10:00:02Z", Some(1714298402000), 1);

    let data = build_dashboard_data(&[e1, e2, e3]);
    assert_eq!(data.security_events.total_warnings, 1);
    assert_eq!(data.security_events.total_errors, 1);
    assert_eq!(data.security_events.events_by_type.len(), 2);
}

#[test]
fn extract_config_empty_events_returns_default() {
    let summary = build_summary(&[], vec![], 0);
    let config = extract_config(&[], &summary);
    assert!(!config.found);
    assert!(config.schema_version.is_none());
    assert!(config.hash_algorithms.is_none());
    assert!(config.last_config_change.is_none());
    assert!(config.sysmon_version.is_none());
    assert!(config.configuration_xml.is_none());
    assert!(config.active_event_types.is_empty());
}

#[test]
fn extract_config_with_service_state_change() {
    let mut e1 = make_event(0, "2024-04-28T10:00:00Z", Some(1714298400000), 4);
    e1.details = Some("Sysmon version 15.0".to_string());

    let events = vec![e1];
    let summary = build_summary(&events, vec![], 0);
    let config = extract_config(&events, &summary);

    assert!(config.found);
    assert_eq!(config.sysmon_version.as_deref(), Some("Sysmon version 15.0"));
}

#[test]
fn extract_config_hash_algorithm_inference() {
    let mut e1 = make_event(0, "2024-04-28T10:00:00Z", Some(1714298400000), 1);
    e1.hashes = Some("SHA256=abc123,MD5=def456".to_string());

    let events = vec![e1];
    let summary = build_summary(&events, vec![], 0);
    let config = extract_config(&events, &summary);

    assert!(config.found);
    assert_eq!(config.hash_algorithms.as_deref(), Some("SHA256,MD5"));
}

#[test]
fn extract_config_config_change_tracks_timestamp() {
    let e1 = make_event(0, "2024-04-28T10:00:00Z", Some(1714298400000), 16);
    let e2 = make_event(1, "2024-04-28T12:00:00Z", Some(1714305600000), 16);

    let events = vec![e1, e2];
    let summary = build_summary(&events, vec![], 0);
    let config = extract_config(&events, &summary);

    assert!(config.found);
    assert_eq!(
        config.last_config_change.as_deref(),
        Some("2024-04-28T12:00:00Z")
    );
}
