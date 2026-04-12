mod common;

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use common::{detect_fixture, parse_fixture, ParsedFixture, SelectionSnapshot};

struct TempLogFixture {
    dir: PathBuf,
    path: PathBuf,
}

impl TempLogFixture {
    fn new(file_name: &str, content: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("cmtrace-open-parser-regression-{unique}"));
        fs::create_dir_all(&dir).expect("create temp fixture dir");

        let path = dir.join(file_name);
        fs::write(&path, content).expect("write temp fixture");

        Self { dir, path }
    }

    fn detect(&self) -> SelectionSnapshot {
        let content = fs::read_to_string(&self.path).expect("fixture should be readable as UTF-8");
        let selection =
            app_lib::parser::detect::detect_parser(&self.path.to_string_lossy(), &content);
        selection_snapshot(&selection)
    }

    fn parse(&self) -> ParsedFixture {
        let file_size = fs::metadata(&self.path)
            .expect("fixture metadata should be readable")
            .len();
        let path_str = self.path.to_string_lossy().to_string();
        let (result, selection) =
            app_lib::parser::parse_file(&path_str).expect("fixture should parse successfully");

        ParsedFixture {
            selection: selection_snapshot(&selection),
            compatibility_format: format!("{:?}", result.format_detected),
            total_lines: result.total_lines,
            parse_errors: result.parse_errors,
            file_size,
            byte_offset: result.byte_offset,
            entries: result
                .entries
                .into_iter()
                .map(|entry| common::EntrySnapshot {
                    id: entry.id,
                    line_number: entry.line_number,
                    message: entry.message,
                    component: entry.component,
                    timestamp_display: entry.timestamp_display,
                    severity: format!("{:?}", entry.severity),
                    format: format!("{:?}", entry.format),
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

fn selection_snapshot(selection: &app_lib::parser::ResolvedParser) -> SelectionSnapshot {
    SelectionSnapshot {
        parser: format!("{:?}", selection.parser),
        implementation: format!("{:?}", selection.implementation),
        provenance: format!("{:?}", selection.provenance),
        parse_quality: format!("{:?}", selection.parse_quality),
        record_framing: format!("{:?}", selection.record_framing),
        specialization: selection.specialization.map(|value| format!("{:?}", value)),
    }
}

fn assert_selection(
    selection: &SelectionSnapshot,
    parser: &str,
    implementation: &str,
    provenance: &str,
    parse_quality: &str,
    record_framing: &str,
) {
    assert_eq!(selection.parser, parser);
    assert_eq!(selection.implementation, implementation);
    assert_eq!(selection.provenance, provenance);
    assert_eq!(selection.parse_quality, parse_quality);
    assert_eq!(selection.record_framing, record_framing);
}

fn assert_specialization(selection: &SelectionSnapshot, specialization: Option<&str>) {
    assert_eq!(selection.specialization.as_deref(), specialization);
}

fn assert_parsed_selection(
    parsed: &ParsedFixture,
    parser: &str,
    implementation: &str,
    provenance: &str,
    parse_quality: &str,
    record_framing: &str,
    compatibility_format: &str,
) {
    assert_selection(
        &parsed.selection,
        parser,
        implementation,
        provenance,
        parse_quality,
        record_framing,
    );
    assert_eq!(parsed.compatibility_format, compatibility_format);
    assert_eq!(parsed.byte_offset, parsed.file_size);
}

#[test]
fn panther_clean_fixture_detects_and_parses_multiline_records() {
    let detected = detect_fixture("panther/clean/setupact.log");
    assert_selection(
        &detected,
        "Panther",
        "GenericTimestamped",
        "Dedicated",
        "SemiStructured",
        "LogicalRecord",
    );

    let parsed = parse_fixture("panther/clean/setupact.log");
    assert_parsed_selection(
        &parsed,
        "Panther",
        "GenericTimestamped",
        "Dedicated",
        "SemiStructured",
        "LogicalRecord",
        "Timestamped",
    );
    assert_eq!(parsed.total_lines, 4);
    assert_eq!(parsed.parse_errors, 0);
    assert_eq!(parsed.entries.len(), 2);
    assert_eq!(parsed.entries[0].line_number, 1);
    assert_eq!(parsed.entries[0].component.as_deref(), Some("MIG"));
    assert_eq!(
        parsed.entries[0].message,
        "[0x080489] Gather started\nAdditional migration detail\n    indented continuation"
    );
    assert_eq!(parsed.entries[1].severity, "Warning");
    assert_eq!(parsed.entries[1].message, "Retry required");
}

#[test]
fn panther_mixed_fixture_preserves_fallback_segments() {
    let detected = detect_fixture("panther/mixed/setuperr.log");
    assert_selection(
        &detected,
        "Panther",
        "GenericTimestamped",
        "Dedicated",
        "SemiStructured",
        "LogicalRecord",
    );

    let parsed = parse_fixture("panther/mixed/setuperr.log");
    assert_parsed_selection(
        &parsed,
        "Panther",
        "GenericTimestamped",
        "Dedicated",
        "SemiStructured",
        "LogicalRecord",
        "Timestamped",
    );
    assert_eq!(parsed.total_lines, 5);
    assert_eq!(parsed.parse_errors, 1);
    assert_eq!(parsed.entries.len(), 4);
    assert_eq!(parsed.entries[0].message, "orphan preamble");
    assert_eq!(parsed.entries[1].message, "Setup started\ncontinuation detail");
    assert_eq!(parsed.entries[2].message, "malformed header");
    assert_eq!(parsed.entries[2].component.as_deref(), Some("SP"));
    assert_eq!(parsed.entries[3].component.as_deref(), Some("SP"));
    assert_eq!(parsed.entries[3].severity, "Error");
}

#[test]
fn cbs_clean_fixture_detects_and_parses_multiline_records() {
    let detected = detect_fixture("cbs/clean/CBS.log");
    assert_selection(
        &detected,
        "Cbs",
        "GenericTimestamped",
        "Dedicated",
        "SemiStructured",
        "LogicalRecord",
    );

    let parsed = parse_fixture("cbs/clean/CBS.log");
    assert_parsed_selection(
        &parsed,
        "Cbs",
        "GenericTimestamped",
        "Dedicated",
        "SemiStructured",
        "LogicalRecord",
        "Timestamped",
    );
    assert_eq!(parsed.total_lines, 4);
    assert_eq!(parsed.parse_errors, 0);
    assert_eq!(parsed.entries.len(), 2);
    assert_eq!(parsed.entries[0].component.as_deref(), Some("CBS"));
    assert_eq!(
        parsed.entries[0].message,
        "Exec: Processing package\nContinuation detail\n    indented continuation"
    );
    assert_eq!(parsed.entries[1].component.as_deref(), Some("CSI"));
    assert_eq!(parsed.entries[1].severity, "Error");
}

#[test]
fn cbs_mixed_fixture_preserves_fallback_segments() {
    let detected = detect_fixture("cbs/mixed/CBS.log");
    assert_selection(
        &detected,
        "Cbs",
        "GenericTimestamped",
        "Dedicated",
        "SemiStructured",
        "LogicalRecord",
    );

    let parsed = parse_fixture("cbs/mixed/CBS.log");
    assert_parsed_selection(
        &parsed,
        "Cbs",
        "GenericTimestamped",
        "Dedicated",
        "SemiStructured",
        "LogicalRecord",
        "Timestamped",
    );
    assert_eq!(parsed.total_lines, 5);
    assert_eq!(parsed.parse_errors, 1);
    assert_eq!(parsed.entries.len(), 4);
    assert_eq!(parsed.entries[0].message, "orphan preamble");
    assert_eq!(parsed.entries[1].message, "Exec: Processing package\nContinuation detail");
    assert_eq!(parsed.entries[2].message, "malformed header");
    assert_eq!(parsed.entries[2].component.as_deref(), Some("CBS"));
    assert_eq!(parsed.entries[3].component.as_deref(), Some("CSI"));
    assert_eq!(parsed.entries[3].severity, "Warning");
}

#[test]
fn dism_clean_fixture_detects_and_parses_multiline_records() {
    let detected = detect_fixture("dism/clean/dism.log");
    assert_selection(
        &detected,
        "Dism",
        "GenericTimestamped",
        "Dedicated",
        "SemiStructured",
        "LogicalRecord",
    );

    let parsed = parse_fixture("dism/clean/dism.log");
    assert_parsed_selection(
        &parsed,
        "Dism",
        "GenericTimestamped",
        "Dedicated",
        "SemiStructured",
        "LogicalRecord",
        "Timestamped",
    );
    assert_eq!(parsed.total_lines, 3);
    assert_eq!(parsed.parse_errors, 0);
    assert_eq!(parsed.entries.len(), 2);
    assert_eq!(parsed.entries[0].component.as_deref(), Some("DISM"));
    assert_eq!(
        parsed.entries[0].message,
        "DISM Provider Store: PID=100 TID=200 loaded provider\nContinuation detail"
    );
    assert_eq!(parsed.entries[1].severity, "Warning");
}

#[test]
fn dism_mixed_fixture_preserves_fallback_segments() {
    let detected = detect_fixture("dism/mixed/dism.log");
    assert_selection(
        &detected,
        "Dism",
        "GenericTimestamped",
        "Dedicated",
        "SemiStructured",
        "LogicalRecord",
    );

    let parsed = parse_fixture("dism/mixed/dism.log");
    assert_parsed_selection(
        &parsed,
        "Dism",
        "GenericTimestamped",
        "Dedicated",
        "SemiStructured",
        "LogicalRecord",
        "Timestamped",
    );
    assert_eq!(parsed.total_lines, 5);
    assert_eq!(parsed.parse_errors, 1);
    assert_eq!(parsed.entries.len(), 4);
    assert_eq!(parsed.entries[0].message, "orphan preamble");
    assert_eq!(
        parsed.entries[1].message,
        "DISM Package Manager: Processing package\nContinuation detail"
    );
    assert_eq!(parsed.entries[2].message, "malformed header");
    assert_eq!(parsed.entries[2].component.as_deref(), Some("DISM"));
    assert_eq!(parsed.entries[3].component.as_deref(), Some("DISM"));
    assert_eq!(parsed.entries[3].severity, "Error");
}

#[test]
fn reporting_events_clean_fixture_detects_and_parses_rows() {
    let detected = detect_fixture("reporting_events/clean/ReportingEvents.log");
    assert_selection(
        &detected,
        "ReportingEvents",
        "ReportingEvents",
        "Dedicated",
        "Structured",
        "PhysicalLine",
    );

    let parsed = parse_fixture("reporting_events/clean/ReportingEvents.log");
    assert_parsed_selection(
        &parsed,
        "ReportingEvents",
        "ReportingEvents",
        "Dedicated",
        "Structured",
        "PhysicalLine",
        "Timestamped",
    );
    assert_eq!(parsed.total_lines, 2);
    assert_eq!(parsed.parse_errors, 0);
    assert_eq!(parsed.entries.len(), 2);
    assert_eq!(parsed.entries[0].component.as_deref(), Some("Windows Update Agent"));
    assert_eq!(
        parsed.entries[0].timestamp_display.as_deref(),
        Some("2024-01-15 08:00:00.123")
    );
    assert!(parsed.entries[0].message.contains("Success | Installation"));
    assert_eq!(parsed.entries[1].severity, "Error");
    assert!(parsed.entries[1].message.contains("HRESULT 0x80240022"));
}

#[test]
fn reporting_events_mixed_fixture_preserves_fallback_rows() {
    let detected = detect_fixture("reporting_events/mixed/ReportingEvents.log");
    assert_selection(
        &detected,
        "ReportingEvents",
        "ReportingEvents",
        "Dedicated",
        "Structured",
        "PhysicalLine",
    );

    let parsed = parse_fixture("reporting_events/mixed/ReportingEvents.log");
    assert_parsed_selection(
        &parsed,
        "ReportingEvents",
        "ReportingEvents",
        "Dedicated",
        "Structured",
        "PhysicalLine",
        "Timestamped",
    );
    assert_eq!(parsed.total_lines, 4);
    assert_eq!(parsed.parse_errors, 2);
    assert_eq!(parsed.entries.len(), 4);
    assert_eq!(
        parsed.entries[1].message,
        "{33333333-3333-3333-3333-333333333333}\tnot-a-timestamp\t2\tSoftware Update\t3\t{44444444-4444-4444-4444-444444444444}\t0x80240022\tWindows Update Agent\tFailure\tInstallation\tInstallation failed for KB5034441"
    );
    assert_eq!(parsed.entries[2].message, "orphan raw line");
    assert_eq!(parsed.entries[3].severity, "Warning");
    assert_eq!(parsed.entries[3].line_number, 4);
}

#[test]
fn ime_multiline_fixture_detects_and_parses_logical_records() {
    let detected = detect_fixture("ime/multiline/HealthScripts.log");
    assert_selection(
        &detected,
        "Ccm",
        "Ccm",
        "Dedicated",
        "Structured",
        "LogicalRecord",
    );
    assert_specialization(&detected, Some("Ime"));

    let parsed = parse_fixture("ime/multiline/HealthScripts.log");
    assert_parsed_selection(
        &parsed,
        "Ccm",
        "Ccm",
        "Dedicated",
        "Structured",
        "LogicalRecord",
        "Ccm",
    );
    assert_specialization(&parsed.selection, Some("Ime"));
    assert_eq!(parsed.total_lines, 17);
    assert_eq!(parsed.parse_errors, 0);
    assert_eq!(parsed.entries.len(), 2);
    assert_eq!(parsed.entries[0].line_number, 1);
    assert_eq!(parsed.entries[1].line_number, 2);
    assert_eq!(parsed.entries[0].format, "Ccm");
    assert_eq!(parsed.entries[1].component.as_deref(), Some("HealthScripts"));
    assert_eq!(
        parsed.entries[1].timestamp_display.as_deref(),
        Some("03-12-2026 11:16:42.332")
    );
    assert!(parsed.entries[1]
        .message
        .contains("Downloaded profile payload is not valid JSON"));
    assert!(parsed.entries[1].message.contains("FullyQualifiedErrorId"));
}

#[test]
fn ime_sparse_fixture_preserves_truncated_tail_as_plain_entry() {
    let detected = detect_fixture("ime/sparse/ClientHealth.log");
    assert_selection(
        &detected,
        "Ccm",
        "Ccm",
        "Dedicated",
        "Structured",
        "LogicalRecord",
    );
    assert_specialization(&detected, Some("Ime"));

    let parsed = parse_fixture("ime/sparse/ClientHealth.log");
    assert_parsed_selection(
        &parsed,
        "Ccm",
        "Ccm",
        "Dedicated",
        "Structured",
        "LogicalRecord",
        "Ccm",
    );
    assert_specialization(&parsed.selection, Some("Ime"));
    assert_eq!(parsed.total_lines, 4);
    assert_eq!(parsed.parse_errors, 1);
    assert_eq!(parsed.entries.len(), 3);
    assert_eq!(parsed.entries[0].line_number, 1);
    assert_eq!(parsed.entries[1].line_number, 3);
    assert_eq!(parsed.entries[2].line_number, 4);
    assert_eq!(parsed.entries[2].format, "Plain");
    assert!(parsed.entries[2].message.contains("Set MdmDeviceCertificate"));
}

#[test]
fn ime_primary_log_temp_fixture_detects_and_parses_logical_records() {
    let fixture = TempLogFixture::new(
        "IntuneManagementExtension.log",
        concat!(
            "<![LOG[[Win32App][V3Processor] Processing subgraph 1.]LOG]!><time=\"08:00:00.0000000\" date=\"1-15-2024\" component=\"IntuneManagementExtension\" context=\"\" type=\"1\" thread=\"7\" file=\"\">\n",
            "<![LOG[Adding new state transition - From: Install In Progress\n",
            "To: Download In Progress With Event: Download Started.]LOG]!><time=\"08:00:01.0000000\" date=\"1-15-2024\" component=\"IntuneManagementExtension\" context=\"\" type=\"1\" thread=\"7\" file=\"\">"
        ),
    );

    let detected = fixture.detect();
    assert_selection(
        &detected,
        "Ccm",
        "Ccm",
        "Dedicated",
        "Structured",
        "LogicalRecord",
    );
    assert_specialization(&detected, Some("Ime"));

    let parsed = fixture.parse();
    assert_parsed_selection(
        &parsed,
        "Ccm",
        "Ccm",
        "Dedicated",
        "Structured",
        "LogicalRecord",
        "Ccm",
    );
    assert_specialization(&parsed.selection, Some("Ime"));
    assert_eq!(parsed.total_lines, 3);
    assert_eq!(parsed.parse_errors, 0);
    assert_eq!(parsed.entries.len(), 2);
    assert_eq!(parsed.entries[0].line_number, 1);
    assert_eq!(parsed.entries[1].line_number, 2);
    assert_eq!(
        parsed.entries[1].component.as_deref(),
        Some("IntuneManagementExtension")
    );
    assert!(parsed.entries[1]
        .message
        .contains("To: Download In Progress With Event: Download Started."));
}

#[test]
fn ime_appworkload_temp_fixture_detects_and_parses_logical_records() {
    let fixture = TempLogFixture::new(
        "AppWorkload.log",
        concat!(
            "<![LOG[Starting content download RequestPayload: {\\\"AppId\\\":\\\"a1b2c3d4-e5f6-7890-abcd-ef1234567890\\\",\n",
            "\\\"ApplicationName\\\":\\\"Contoso App\\\"}]LOG]!><time=\"08:00:00.0000000\" date=\"1-15-2024\" component=\"AppWorkload\" context=\"\" type=\"1\" thread=\"9\" file=\"\">\n",
            "<![LOG[Download completed successfully. Content size: 5242880 bytes, speed: 1048576 Bps, Delivery Optimization: 75.5%]LOG]!><time=\"08:00:05.0000000\" date=\"1-15-2024\" component=\"AppWorkload\" context=\"\" type=\"1\" thread=\"9\" file=\"\">"
        ),
    );

    let detected = fixture.detect();
    assert_selection(
        &detected,
        "Ccm",
        "Ccm",
        "Dedicated",
        "Structured",
        "LogicalRecord",
    );
    assert_specialization(&detected, Some("Ime"));

    let parsed = fixture.parse();
    assert_parsed_selection(
        &parsed,
        "Ccm",
        "Ccm",
        "Dedicated",
        "Structured",
        "LogicalRecord",
        "Ccm",
    );
    assert_specialization(&parsed.selection, Some("Ime"));
    assert_eq!(parsed.total_lines, 3);
    assert_eq!(parsed.parse_errors, 0);
    assert_eq!(parsed.entries.len(), 2);
    assert_eq!(parsed.entries[0].line_number, 1);
    assert_eq!(parsed.entries[1].line_number, 3);
    assert_eq!(parsed.entries[0].component.as_deref(), Some("AppWorkload"));
    assert!(parsed.entries[0].message.contains("ApplicationName\\\":\\\"Contoso App"));
    assert!(parsed.entries[1]
        .message
        .contains("Download completed successfully."));
}

#[test]
fn test_dns_debug_basic_fixture_detection() {
    let fixture = TempLogFixture::new(
        "DNSServer_debug.log",
        &std::fs::read_to_string(
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/corpus/dns_debug/clean/basic.log")
        ).expect("read fixture"),
    );
    let snapshot = fixture.detect();
    assert_eq!(snapshot.parser, "DnsDebug");
    assert_eq!(snapshot.record_framing, "LogicalRecord");
}

#[test]
fn test_dns_debug_basic_fixture_parse() {
    let fixture = TempLogFixture::new(
        "DNSServer_debug.log",
        &std::fs::read_to_string(
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/corpus/dns_debug/clean/basic.log")
        ).expect("read fixture"),
    );
    let parsed = fixture.parse();
    assert_eq!(parsed.selection.parser, "DnsDebug");
    assert_eq!(parsed.parse_errors, 0);
    assert_eq!(parsed.entries.len(), 4);
    assert_eq!(parsed.entries[0].severity, "Info");
}

#[test]
fn test_dns_debug_rcodes_fixture_severity() {
    let fixture = TempLogFixture::new(
        "dns.log",
        &std::fs::read_to_string(
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/corpus/dns_debug/mixed/rcodes.log")
        ).expect("read fixture"),
    );
    let parsed = fixture.parse();
    assert_eq!(parsed.entries.len(), 4);
    assert_eq!(parsed.entries[0].severity, "Info");     // NOERROR query
    assert_eq!(parsed.entries[1].severity, "Info");     // NOERROR response
    assert_eq!(parsed.entries[2].severity, "Warning");  // NXDOMAIN
    assert_eq!(parsed.entries[3].severity, "Error");    // SERVFAIL
}