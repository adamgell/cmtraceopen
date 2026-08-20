use std::fs;
use std::process::Command;

fn manifest(directory: &tempfile::TempDir, raw_xml: &str, message: &str) -> std::path::PathBuf {
    let path = directory.path().join("manifest.json");
    let payload = serde_json::json!({
        "records": [{
            "id": 1,
            "eventRecordId": 42,
            "timestamp": "2026-08-09T12:00:00Z",
            "timestampEpoch": 0,
            "provider": "Provider",
            "channel": "Application",
            "eventId": 326,
            "level": "Error",
            "computer": "DESKTOP-JOHN",
            "message": message,
            "eventData": [],
            "rawXml": raw_xml,
            "sourceLabel": "events.evtx",
            "mapped": []
        }],
        "totalRecords": 1,
        "parseErrors": 1,
        "errorMessages": ["damaged.evtx: truncated"]
    });
    fs::write(&path, payload.to_string()).expect("manifest");
    path
}

#[test]
fn binary_exports_stdout_and_reports_coverage_to_stderr() {
    let directory = tempfile::tempdir().expect("temp directory");
    let manifest = manifest(
        &directory,
        "<Event><System><Computer>DESKTOP-JOHN</Computer></System></Event>",
        "PASSWORD=hunter2",
    );
    let output = Command::new(env!("CARGO_BIN_EXE_event-log-export"))
        .args([
            "--manifest",
            manifest.to_str().expect("manifest path"),
            "--format",
            "json",
        ])
        .output()
        .expect("run event-log-export");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout");
    let stderr = String::from_utf8(output.stderr).expect("stderr");
    assert!(stdout.starts_with('['));
    assert!(!stdout.contains("hunter2"));
    assert!(!stdout.contains("DESKTOP-JOHN"));
    assert!(stderr.contains("coverage: sourceRecords=1 exportedRecords=1 parseErrors=1 gaps=1"));
    assert!(stderr.contains("coverage-gap: damaged.evtx: truncated"));
}

#[test]
fn binary_exports_to_a_file_without_mixing_bytes_into_stdout() {
    let directory = tempfile::tempdir().expect("temp directory");
    let manifest = manifest(&directory, "<Event />", "safe");
    let destination = directory.path().join("events.csv");
    let output = Command::new(env!("CARGO_BIN_EXE_event-log-export"))
        .args([
            "--manifest",
            manifest.to_str().expect("manifest path"),
            "--format",
            "csv",
            "--output",
            destination.to_str().expect("destination path"),
        ])
        .output()
        .expect("run event-log-export");
    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8(output.stderr)
        .expect("stderr")
        .contains("exportedRecords=1"));
    assert!(fs::read_to_string(destination)
        .expect("CSV output")
        .contains("Event Time"));
}

#[test]
fn binary_returns_nonzero_and_surfaces_writer_errors() {
    let directory = tempfile::tempdir().expect("temp directory");
    let manifest = manifest(&directory, "", "safe");
    let output = Command::new(env!("CARGO_BIN_EXE_event-log-export"))
        .args([
            "--manifest",
            manifest.to_str().expect("manifest path"),
            "--format",
            "xml",
        ])
        .output()
        .expect("run event-log-export");
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).expect("stderr");
    assert!(
        stderr.contains("coverage: sourceRecords=1 exportedRecords=unknown parseErrors=1 gaps=1")
    );
    assert!(stderr.contains("coverage-gap: damaged.evtx: truncated"));
    assert!(stderr.contains("export failed"));
    assert!(stderr.contains("record is missing raw XML"));
    let destination = directory.path().join("events.xml");
    fs::write(&destination, "sentinel").expect("seed destination");
    let file_output = Command::new(env!("CARGO_BIN_EXE_event-log-export"))
        .args([
            "--manifest",
            manifest.to_str().expect("manifest path"),
            "--format",
            "xml",
            "--output",
            destination.to_str().expect("destination path"),
        ])
        .output()
        .expect("run event-log-export");
    assert!(!file_output.status.success());
    assert_eq!(
        fs::read_to_string(destination).expect("destination"),
        "sentinel"
    );
}

#[test]
fn binary_rejects_malformed_raw_xml_without_creating_an_artifact() {
    let directory = tempfile::tempdir().expect("temp directory");
    let manifest = manifest(&directory, "<Event><Message></Event>", "safe");
    let destination = directory.path().join("malformed.xml");
    let output = Command::new(env!("CARGO_BIN_EXE_event-log-export"))
        .args([
            "--manifest",
            manifest.to_str().expect("manifest path"),
            "--format",
            "xml",
            "--output",
            destination.to_str().expect("destination path"),
        ])
        .output()
        .expect("run event-log-export");
    assert!(!output.status.success());
    assert!(!destination.exists());
    let stderr = String::from_utf8(output.stderr).expect("stderr");
    assert!(stderr.contains("raw XML is malformed"));
    assert!(stderr.contains("coverage: sourceRecords=1 exportedRecords=unknown"));
}

#[test]
fn binary_rejects_malformed_raw_xml_for_json_without_creating_an_artifact() {
    let directory = tempfile::tempdir().expect("temp directory");
    let manifest = manifest(&directory, "<Event><Message></Event>", "safe");
    let destination = directory.path().join("malformed.json");
    let output = Command::new(env!("CARGO_BIN_EXE_event-log-export"))
        .args([
            "--manifest",
            manifest.to_str().expect("manifest path"),
            "--format",
            "json",
            "--output",
            destination.to_str().expect("destination path"),
        ])
        .output()
        .expect("run event-log-export");
    assert!(!output.status.success());
    assert!(!destination.exists());
    let stderr = String::from_utf8(output.stderr).expect("stderr");
    assert!(stderr.contains("raw XML is malformed"));
    assert!(stderr.contains("coverage: sourceRecords=1 exportedRecords=unknown"));
}
