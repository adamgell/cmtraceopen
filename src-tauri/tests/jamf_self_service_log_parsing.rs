#![cfg(feature = "macos-diag")]

use std::path::Path;

use app_lib::jamf::self_service::parse_self_service_log_impl;

const FIXTURE: &str = "tests/fixtures/jamf_self_service_basic.log";

#[test]
fn parses_install_browse_cancel() {
    let events = parse_self_service_log_impl(Path::new(FIXTURE)).expect("parse");
    assert_eq!(events.len(), 5);
    let actions: Vec<&str> = events.iter().map(|e| e.action.as_str()).collect();
    assert_eq!(actions, vec!["Browse", "Install", "Install", "Cancel", "Install"]);
    assert_eq!(events[0].item_name.as_deref(), Some("Google Chrome Installer"));
    assert_eq!(events[2].result.as_deref(), Some("success"));
    assert_eq!(events[4].result.as_deref(), Some("failure"));
}

#[test]
fn missing_file_is_empty_not_error() {
    let events = parse_self_service_log_impl(Path::new("/nonexistent/self-service.log")).expect("ok");
    assert!(events.is_empty());
}
