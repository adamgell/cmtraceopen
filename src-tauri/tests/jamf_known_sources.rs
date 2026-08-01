use app_lib::commands::known_sources::build_known_log_sources;
// Only the macOS assertions name this type; importing it unconditionally trips
// `-D warnings` on every other target.
#[cfg(target_os = "macos")]
use app_lib::commands::known_sources::KnownSourceMetadata;

#[cfg(target_os = "macos")]
fn jamf_sources(all: &[KnownSourceMetadata]) -> Vec<&KnownSourceMetadata> {
    all.iter()
        .filter(|s| {
            s.grouping
                .as_ref()
                .map(|g| g.family_id == "macos-jamf" || g.family_id == "macos-jamf-connect")
                .unwrap_or(false)
        })
        .collect()
}

#[cfg(target_os = "macos")]
#[test]
fn jamf_known_sources_present() {
    let all = build_known_log_sources();
    let jamf = jamf_sources(&all);
    let ids: Vec<&str> = jamf.iter().map(|s| s.id.as_str()).collect();
    assert!(ids.contains(&"macos-jamf-log"), "missing macos-jamf-log: {ids:?}");
    assert!(ids.contains(&"macos-jamf-app-support-logs"));
    assert!(ids.contains(&"macos-jamf-receipts"));
    assert!(ids.contains(&"macos-jamf-self-service-log"));
    assert!(ids.contains(&"macos-jamf-user-logs"));
    assert!(ids.contains(&"macos-jamf-connect-log"));
    assert!(ids.contains(&"macos-jamf-connect-user-logs"));
    assert_eq!(jamf.len(), 7); // 5 macos-jamf + 2 macos-jamf-connect
}

#[cfg(target_os = "macos")]
#[test]
fn jamf_log_default_file_is_jamf_log() {
    let all = build_known_log_sources();
    let entry = all
        .iter()
        .find(|s| s.id == "macos-jamf-log")
        .expect("macos-jamf-log should exist");
    let intent = entry.default_file_intent.as_ref().expect("should have default file intent");
    assert!(intent
        .preferred_file_names
        .iter()
        .any(|n| n == "jamf.log"));
}

#[cfg(not(target_os = "macos"))]
#[test]
fn jamf_known_sources_only_on_macos() {
    let all = build_known_log_sources();
    let jamf_count = all
        .iter()
        .filter(|s| {
            s.grouping
                .as_ref()
                .map(|g| g.family_id.starts_with("macos-jamf"))
                .unwrap_or(false)
        })
        .count();
    assert_eq!(jamf_count, 0);
}
