mod common;

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

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
        let dir = std::env::temp_dir().join(format!("cmtrace-open-cmtlog-test-{unique}"));
        fs::create_dir_all(&dir).expect("create temp fixture dir");

        let path = dir.join(file_name);
        fs::write(&path, content).expect("write temp fixture");

        Self { dir, path }
    }

    fn detect(&self) -> app_lib::parser::ResolvedParser {
        let content = fs::read_to_string(&self.path).expect("fixture should be readable as UTF-8");
        app_lib::parser::detect::detect_parser(&self.path.to_string_lossy(), &content)
    }
}

impl Drop for TempLogFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn fixture_content() -> &'static str {
    concat!(
        "<![LOG[Script started: Detect-WDAC.ps1 v2.1.0]LOG]!><time=\"10:30:00.000+000\" date=\"04-13-2026\" component=\"__HEADER__\" context=\"\" type=\"1\" thread=\"0\" file=\"\" script=\"Detect-WDAC.ps1\" version=\"2.1.0\" runid=\"a3f8c9e1\" mode=\"Normal\" ps_version=\"7.4.2\">\n",
        "<![LOG[Detection Phase]LOG]!><time=\"10:32:01.000+000\" date=\"04-13-2026\" component=\"__SECTION__\" context=\"\" type=\"1\" thread=\"0\" file=\"\" color=\"#5b9aff\">\n",
        "<![LOG[Scanning policy files]LOG]!><time=\"10:32:01.123+000\" date=\"04-13-2026\" component=\"Detect-WDAC\" context=\"CONTOSO\\admin\" type=\"1\" thread=\"1234\" file=\"\" section=\"detection\" tag=\"phase:scan\">\n",
        "<![LOG[Policy validation failed]LOG]!><time=\"10:32:01.456+000\" date=\"04-13-2026\" component=\"Detect-WDAC\" context=\"CONTOSO\\admin\" type=\"3\" thread=\"1234\" file=\"\" section=\"detection\">\n",
        "<![LOG[Loop Iteration 1/3 - WDAC policies]LOG]!><time=\"10:32:02.000+000\" date=\"04-13-2026\" component=\"__ITERATION__\" context=\"\" type=\"1\" thread=\"0\" file=\"\" iteration=\"1/3\" color=\"#a78bfa\">\n",
        "<![LOG[Processing policy contoso.xml]LOG]!><time=\"10:32:02.100+000\" date=\"04-13-2026\" component=\"Detect-WDAC\" context=\"CONTOSO\\admin\" type=\"1\" thread=\"1234\" file=\"\" section=\"detection\" iteration=\"1/3\">\n",
        "<![LOG[Would apply policy contoso.xml]LOG]!><time=\"10:32:02.200+000\" date=\"04-13-2026\" component=\"Detect-WDAC\" context=\"CONTOSO\\admin\" type=\"1\" thread=\"1234\" file=\"\" section=\"detection\" whatif=\"1\">\n",
    )
}

/// Helper: parse the fixture and return entries + parse_errors via `parse_file`.
fn parse_fixture(file_name: &str, content: &str) -> TempLogFixtureResult {
    let fixture = TempLogFixture::new(file_name, content);
    let path_str = fixture.path.to_string_lossy().to_string();
    let (result, selection) =
        app_lib::parser::parse_file(&path_str).expect("fixture should parse successfully");

    // Snapshot entries into owned structs so we don't depend on private type names.
    let entries: Vec<EntrySnapshot> = result
        .entries
        .iter()
        .map(|e| EntrySnapshot {
            message: e.message.clone(),
            component: e.component.clone(),
            entry_kind: format!("{:?}", e.entry_kind),
            format: format!("{:?}", e.format),
            severity: format!("{:?}", e.severity),
            section_name: e.section_name.clone(),
            section_color: e.section_color.clone(),
            iteration: e.iteration.clone(),
            whatif: e.whatif,
            tags: e.tags.clone(),
        })
        .collect();

    TempLogFixtureResult {
        entry_count: result.entries.len(),
        parse_errors: result.parse_errors,
        entries,
        selection_parser: format!("{:?}", selection.parser),
        selection_implementation: format!("{:?}", selection.implementation),
        selection_provenance: format!("{:?}", selection.provenance),
        selection_parse_quality: format!("{:?}", selection.parse_quality),
        selection_record_framing: format!("{:?}", selection.record_framing),
        _fixture: fixture,
    }
}

#[allow(dead_code)]
struct EntrySnapshot {
    message: String,
    component: Option<String>,
    entry_kind: String,
    format: String,
    severity: String,
    section_name: Option<String>,
    section_color: Option<String>,
    iteration: Option<String>,
    whatif: Option<bool>,
    tags: Option<Vec<String>>,
}

#[allow(dead_code)]
struct TempLogFixtureResult {
    entry_count: usize,
    parse_errors: u32,
    entries: Vec<EntrySnapshot>,
    selection_parser: String,
    selection_implementation: String,
    selection_provenance: String,
    selection_parse_quality: String,
    selection_record_framing: String,
    // Hold fixture alive so temp files aren't cleaned up before assertions.
    _fixture: TempLogFixture,
}

// Test 1: .cmtlog extension triggers CmtLog parser detection
#[test]
fn cmtlog_extension_triggers_cmtlog_parser() {
    let fixture = TempLogFixture::new("test.cmtlog", fixture_content());
    let selection = fixture.detect();

    assert_eq!(format!("{:?}", selection.parser), "CmtLog");
    assert_eq!(format!("{:?}", selection.implementation), "CmtLog");
    assert_eq!(format!("{:?}", selection.provenance), "Dedicated");
    assert_eq!(format!("{:?}", selection.parse_quality), "Structured");
    assert_eq!(format!("{:?}", selection.record_framing), "PhysicalLine");
}

// Test 2: Header entry parsed with EntryKind::Header
#[test]
fn header_entry_parsed_correctly() {
    let result = parse_fixture("test.cmtlog", fixture_content());

    assert_eq!(result.entries[0].entry_kind, "Some(Header)");
    assert_eq!(result.entries[0].format, "CmtLog");
    assert_eq!(
        result.entries[0].message,
        "Script started: Detect-WDAC.ps1 v2.1.0"
    );
    assert_eq!(result.entries[0].component.as_deref(), Some("__HEADER__"));
}

// Test 3: Section entry parsed with EntryKind::Section and correct color
#[test]
fn section_entry_parsed_with_color() {
    let result = parse_fixture("test.cmtlog", fixture_content());

    assert_eq!(result.entries[1].entry_kind, "Some(Section)");
    assert_eq!(
        result.entries[1].section_name.as_deref(),
        Some("Detection Phase")
    );
    assert_eq!(
        result.entries[1].section_color.as_deref(),
        Some("#5b9aff")
    );
}

// Test 4: Iteration entry parsed with EntryKind::Iteration and iteration string
#[test]
fn iteration_entry_parsed_correctly() {
    let result = parse_fixture("test.cmtlog", fixture_content());

    assert_eq!(result.entries[4].entry_kind, "Some(Iteration)");
    assert_eq!(result.entries[4].iteration.as_deref(), Some("1/3"));
    // Iteration has its own explicit color
    assert_eq!(
        result.entries[4].section_color.as_deref(),
        Some("#a78bfa")
    );
}

// Test 5: Regular entries have EntryKind::Log with section_name propagated
#[test]
fn regular_entries_have_section_propagated() {
    let result = parse_fixture("test.cmtlog", fixture_content());

    // Entry 2 (index 2): "Scanning policy files" — has explicit section="detection"
    assert_eq!(result.entries[2].entry_kind, "Some(Log)");
    assert_eq!(
        result.entries[2].section_name.as_deref(),
        Some("detection")
    );
    // Section color is inherited from the current section
    assert_eq!(
        result.entries[2].section_color.as_deref(),
        Some("#5b9aff")
    );

    // Entry 5 (index 5): "Processing policy contoso.xml" — has explicit section="detection"
    assert_eq!(result.entries[5].entry_kind, "Some(Log)");
    assert_eq!(
        result.entries[5].section_name.as_deref(),
        Some("detection")
    );
    assert_eq!(result.entries[5].iteration.as_deref(), Some("1/3"));
}

// Test 6: WhatIf flag parsed correctly
#[test]
fn whatif_flag_parsed() {
    let result = parse_fixture("test.cmtlog", fixture_content());

    // Entry 6 (index 6): "Would apply policy contoso.xml" — whatif="1"
    assert_eq!(result.entries[6].whatif, Some(true));
    // Entry 2 (index 2): "Scanning policy files" — no whatif attr
    assert_eq!(result.entries[2].whatif, None);
}

// Test 7: Severity mapped correctly (type="3" -> Error)
#[test]
fn severity_mapped_correctly() {
    let result = parse_fixture("test.cmtlog", fixture_content());

    // Entry 3 (index 3): "Policy validation failed" — type="3"
    assert_eq!(result.entries[3].severity, "Error");
    // Entry 0 (index 0): Header — type="1"
    assert_eq!(result.entries[0].severity, "Info");
}

// Test 8: Total entry count = 7
#[test]
fn total_entry_count() {
    let result = parse_fixture("test.cmtlog", fixture_content());

    assert_eq!(result.entry_count, 7);
    assert_eq!(result.parse_errors, 0);
}

// Test 9: Content fallback detection (.log file with __SECTION__ component -> CmtLog)
#[test]
fn content_fallback_detection() {
    let fixture = TempLogFixture::new("script-output.log", fixture_content());
    let selection = fixture.detect();

    assert_eq!(format!("{:?}", selection.parser), "CmtLog");
    assert_eq!(format!("{:?}", selection.implementation), "CmtLog");
    assert_eq!(format!("{:?}", selection.provenance), "Heuristic");
    assert_eq!(format!("{:?}", selection.parse_quality), "Structured");
}
