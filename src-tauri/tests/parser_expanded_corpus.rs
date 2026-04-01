mod common;

use common::{detect_fixture, parse_fixture};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// Helper: create a temp file for detection/parsing tests
// ---------------------------------------------------------------------------

struct TempLogFixture {
    dir: PathBuf,
    path: PathBuf,
}

impl TempLogFixture {
    fn new(file_name: &str, content: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("cmtrace-open-expanded-{unique}"));
        fs::create_dir_all(&dir).expect("create temp dir");
        let path = dir.join(file_name);
        fs::write(&path, content).expect("write fixture");
        Self { dir, path }
    }

    fn detect(&self) -> common::SelectionSnapshot {
        let content = fs::read_to_string(&self.path).expect("read fixture");
        let selection =
            app_lib::parser::detect::detect_parser(&self.path.to_string_lossy(), &content);
        snapshot(&selection)
    }

    fn parse(&self) -> common::ParsedFixture {
        let file_size = fs::metadata(&self.path).expect("metadata").len();
        let path_str = self.path.to_string_lossy().to_string();
        let (result, selection) =
            app_lib::parser::parse_file(&path_str).expect("should parse");

        common::ParsedFixture {
            selection: snapshot(&selection),
            compatibility_format: format!("{:?}", result.format_detected),
            total_lines: result.total_lines,
            parse_errors: result.parse_errors,
            file_size,
            byte_offset: result.byte_offset,
            entries: result
                .entries
                .into_iter()
                .map(|e| common::EntrySnapshot {
                    id: e.id,
                    line_number: e.line_number,
                    message: e.message,
                    component: e.component,
                    timestamp_display: e.timestamp_display,
                    severity: format!("{:?}", e.severity),
                    format: format!("{:?}", e.format),
                })
                .collect(),
        }
    }
}

impl Drop for TempLogFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn snapshot(s: &app_lib::parser::ResolvedParser) -> common::SelectionSnapshot {
    common::SelectionSnapshot {
        parser: format!("{:?}", s.parser),
        implementation: format!("{:?}", s.implementation),
        provenance: format!("{:?}", s.provenance),
        parse_quality: format!("{:?}", s.parse_quality),
        record_framing: format!("{:?}", s.record_framing),
        specialization: s.specialization.map(|v| format!("{:?}", v)),
    }
}

// ===========================================================================
// CCM Format Tests
// ===========================================================================

#[test]
fn ccm_clean_fixture_detects_and_parses() {
    let detected = detect_fixture("ccm/clean/basic.log");
    assert_eq!(detected.parser, "Ccm");
    assert_eq!(detected.implementation, "Ccm");
    assert_eq!(detected.provenance, "Dedicated");

    let parsed = parse_fixture("ccm/clean/basic.log");
    assert_eq!(parsed.entries.len(), 3);
    assert_eq!(parsed.parse_errors, 0);
    assert_eq!(parsed.entries[0].component.as_deref(), Some("CcmExec"));
    assert_eq!(parsed.entries[1].component.as_deref(), Some("PolicyAgent"));
    assert_eq!(parsed.entries[2].severity, "Error");
    assert!(parsed.entries[2].message.contains("Failed to connect"));
}

#[test]
fn ccm_malformed_truncated_recovers_gracefully() {
    let parsed = parse_fixture("ccm/malformed/truncated.log");
    // Should parse what it can and not panic
    assert!(parsed.entries.len() >= 2, "should recover at least 2 entries");
    assert_eq!(parsed.entries[0].message, "Complete record here");
    // The last entry should be the one after the truncated record
    let last = parsed.entries.last().unwrap();
    assert_eq!(last.message, "Another complete record");
}

#[test]
fn ccm_malformed_broken_timestamp_still_parses() {
    let parsed = parse_fixture("ccm/malformed/broken_timestamp.log");
    // Should still parse all 4 lines even with bad timestamps
    assert!(parsed.entries.len() >= 2, "should parse despite bad timestamps");
    // First and last entries should have valid data
    assert_eq!(parsed.entries[0].message, "Good timestamp");
    let last = parsed.entries.last().unwrap();
    assert_eq!(last.message, "Good after bad");
}

// ===========================================================================
// Simple Format Tests
// ===========================================================================

#[test]
fn simple_clean_fixture_detects_and_parses() {
    let detected = detect_fixture("simple/clean/basic.log");
    assert_eq!(detected.parser, "Simple");
    assert_eq!(detected.implementation, "Simple");

    let parsed = parse_fixture("simple/clean/basic.log");
    assert!(parsed.entries.len() >= 1, "should parse at least 1 entry, got {}", parsed.entries.len());
    assert_eq!(parsed.entries[0].component.as_deref(), Some("CcmExec"));
}

// ===========================================================================
// MSI Format Tests
// ===========================================================================

#[test]
fn msi_clean_fixture_detects_and_parses() {
    let detected = detect_fixture("msi/clean/basic.log");
    assert_eq!(detected.parser, "Msi");
    assert_eq!(detected.implementation, "Msi");

    let parsed = parse_fixture("msi/clean/basic.log");
    assert!(parsed.entries.len() >= 4, "should parse MSI log entries");
    assert_eq!(parsed.parse_errors, 0);
}

// ===========================================================================
// Plain Text Fallback Tests
// ===========================================================================

#[test]
fn plain_text_fallback_for_unstructured_content() {
    let detected = detect_fixture("plain/unstructured.txt");
    assert_eq!(detected.parser, "Plain");
    assert_eq!(detected.implementation, "PlainText");
    assert_eq!(detected.provenance, "Fallback");
    assert_eq!(detected.parse_quality, "TextFallback");

    let parsed = parse_fixture("plain/unstructured.txt");
    assert_eq!(parsed.entries.len(), 4);
    assert_eq!(parsed.parse_errors, 0);
    assert_eq!(parsed.entries[0].message, "This is a plain text log file with no structured format.");
    assert_eq!(parsed.entries[3].message, "Final line of the file.");
}

// ===========================================================================
// Detection Edge Cases
// ===========================================================================

#[test]
fn empty_file_falls_back_to_plain() {
    let fixture = TempLogFixture::new("empty.log", "");
    let detected = fixture.detect();
    assert_eq!(detected.parser, "Plain");
    assert_eq!(detected.provenance, "Fallback");
}

#[test]
fn single_line_file_parses_as_plain() {
    let fixture = TempLogFixture::new("single.log", "Just one line of text");
    let parsed = fixture.parse();
    assert_eq!(parsed.entries.len(), 1);
    assert_eq!(parsed.entries[0].message, "Just one line of text");
}

#[test]
fn ccm_format_detected_by_content_not_just_extension() {
    // CCM content in a .txt file — should still detect as CCM
    let fixture = TempLogFixture::new(
        "data.txt",
        "<![LOG[Test message]LOG]!><time=\"08:00:00.0000000\" date=\"3-15-2026\" component=\"Test\" context=\"\" type=\"1\" thread=\"1\" file=\"\">\n",
    );
    let detected = fixture.detect();
    assert_eq!(detected.parser, "Ccm");
}

#[test]
fn simple_format_detected_by_content() {
    let fixture = TempLogFixture::new(
        "data.txt",
        "$$<Component><03-15-2026 08:00:00.000+000><thread=100 (0x64)>Test message\n",
    );
    let detected = fixture.detect();
    assert_eq!(detected.parser, "Simple");
}

// ===========================================================================
// Error Database Tests
// ===========================================================================

#[test]
fn error_db_detects_hex_error_codes_in_message() {
    let spans = app_lib::error_db::lookup::detect_error_code_spans(
        "Installation failed with error 0x80070005 access denied",
    );
    assert!(!spans.is_empty(), "should detect 0x80070005");
    assert_eq!(spans[0].code_hex, "0x80070005");
}

#[test]
fn error_db_detects_multiple_error_codes() {
    let spans = app_lib::error_db::lookup::detect_error_code_spans(
        "First error 0x80070002 then second error 0x80004005",
    );
    assert_eq!(spans.len(), 2);
}

#[test]
fn error_db_no_false_positives_on_plain_text() {
    let spans =
        app_lib::error_db::lookup::detect_error_code_spans("No error codes in this message");
    assert!(spans.is_empty());
}

#[test]
fn error_db_lookup_known_code() {
    let result = app_lib::error_db::lookup::lookup_error_code("0x80070005");
    assert!(result.found);
    // ACCESS_DENIED is a well-known error
    let desc = result.description.to_lowercase();
    assert!(
        desc.contains("access") || desc.contains("denied"),
        "expected access denied description, got: {}",
        desc
    );
}

#[test]
fn error_db_lookup_unknown_code_returns_not_found() {
    let result = app_lib::error_db::lookup::lookup_error_code("0xDEADBEEF");
    assert!(!result.found);
}

#[test]
fn error_db_search_returns_results_for_broad_query() {
    let results = app_lib::error_db::lookup::search_error_codes("access");
    assert!(!results.is_empty(), "should find codes related to 'access'");
}

#[test]
fn error_db_search_empty_query_returns_empty() {
    let results = app_lib::error_db::lookup::search_error_codes("");
    assert!(results.is_empty());
}

// ===========================================================================
// Large Synthetic File Test
// ===========================================================================

#[test]
fn large_ccm_file_parses_without_panic() {
    let fixture = common::build_ccm_bench_file(5000);
    let path_str = fixture.path_string();
    let (result, _selection) =
        app_lib::parser::parse_file(&path_str).expect("large file should parse");
    assert_eq!(result.entries.len(), 5000);
    assert_eq!(result.parse_errors, 0);
}

// ===========================================================================
// Encoding Tests
// ===========================================================================

#[test]
fn utf8_bom_file_parses_correctly() {
    let content = "\u{FEFF}<![LOG[BOM test]LOG]!><time=\"08:00:00.0000000\" date=\"3-15-2026\" component=\"Test\" context=\"\" type=\"1\" thread=\"1\" file=\"\">\n";
    let fixture = TempLogFixture::new("bom.log", content);
    let parsed = fixture.parse();
    assert_eq!(parsed.entries.len(), 1);
    assert_eq!(parsed.entries[0].message, "BOM test");
}
