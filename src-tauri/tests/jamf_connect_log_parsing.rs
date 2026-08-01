#![cfg(feature = "macos-diag")]

use std::path::Path;

use app_lib::jamf::connect::parse_connect_log_impl;

const FIXTURE: &str = "tests/fixtures/jamf_connect_basic.log";

#[test]
fn parses_login_and_sync_events() {
    let events = parse_connect_log_impl(Path::new(FIXTURE)).expect("parse");
    assert_eq!(events.len(), 4);
    assert_eq!(events[0].event_type, "Login");
    assert_eq!(events[0].user.as_deref(), Some("adam@example.com"));
    assert_eq!(events[0].idp.as_deref(), Some("Microsoft"));
    assert_eq!(events[2].event_type, "Sync");
    assert_eq!(events[3].event_type, "Login");
}

#[test]
fn missing_file_is_empty_not_error() {
    let v = parse_connect_log_impl(Path::new("/nonexistent/JAMFConnect.log")).expect("ok");
    assert!(v.is_empty());
}
