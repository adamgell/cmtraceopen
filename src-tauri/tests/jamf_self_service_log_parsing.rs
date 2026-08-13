#![cfg(feature = "macos-diag")]

use std::path::Path;

use app_lib::jamf::self_service::parse_self_service_log_impl;

const FIXTURE: &str = "tests/fixtures/jamf_self_service_basic.log";

#[test]
fn parses_real_selfservice_log_shapes() {
    let events = parse_self_service_log_impl(Path::new(FIXTURE)).expect("parse");
    // Every timestamped line becomes an event; only the line with no
    // `[ts]` prefix is dropped.
    assert_eq!(events.len(), 12);

    assert_eq!(events[0].action, "launch");
    assert_eq!(events[1].action, "info");
    assert_eq!(
        events[1].item_name.as_deref(),
        Some("Self Service Core initialized")
    );

    // Connectivity state lands in `result` so a reader can scan for the
    // negotiating → active transition.
    assert_eq!(events[2].action, "connectivity");
    assert_eq!(events[2].result.as_deref(), Some("negotiating"));
    assert_eq!(events[3].result.as_deref(), Some("active"));

    // API chatter is one action with the endpoint as the item.
    assert_eq!(events[4].action, "request");
    assert_eq!(
        events[4].item_name.as_deref(),
        Some("updateDevicePushToken")
    );

    assert_eq!(events[7].action, "warning");
    assert!(events[7]
        .item_name
        .as_deref()
        .is_some_and(|m| m.starts_with("A customized icon")));

    // Binary requests are the user-side operations.
    let triggers: Vec<&_> = events
        .iter()
        .filter(|e| e.action == "triggerPolicy")
        .collect();
    assert_eq!(triggers.len(), 2);
    assert_eq!(events.iter().filter(|e| e.action == "doRecon").count(), 1);
}

#[test]
fn timestamps_are_ordered() {
    let events = parse_self_service_log_impl(Path::new(FIXTURE)).expect("parse");
    for pair in events.windows(2) {
        assert!(pair[0].timestamp <= pair[1].timestamp);
    }
}

#[test]
fn missing_file_is_empty_not_error() {
    let events =
        parse_self_service_log_impl(Path::new("/nonexistent/self-service.log")).expect("ok");
    assert!(events.is_empty());
}
