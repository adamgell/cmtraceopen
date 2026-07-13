//! Regression test for issue #211: CCM `type="0"` must be classified as
//! `Severity::Success`, not `Info`.
//!
//! Fixture is a real PSAppDeployToolkit 4.2.0 install log (UTF-8 BOM, CRLF,
//! multi-line CCM records) with the reporter's username, machine name, and
//! home path scrubbed. The single `type="0"` line is the "install completed
//! … exit code [0]" line that OneTrace renders with a green tick.

use app_lib::models::log_entry::Severity;

const FIXTURE_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/ccm/psadt_install.log"
);

#[test]
fn ccm_type0_is_success_in_real_psadt_log() {
    let (result, selection) =
        app_lib::parser::parse_file(FIXTURE_PATH).expect("fixture should parse");

    // Detected as CCM and parsed without errors.
    assert_eq!(format!("{:?}", selection.parser), "Ccm");
    assert_eq!(format!("{:?}", result.format_detected), "Ccm");
    assert_eq!(result.parse_errors, 0, "should have zero parse errors");

    let count = |sev: Severity| result.entries.iter().filter(|e| e.severity == sev).count();
    let success = count(Severity::Success);
    let warning = count(Severity::Warning);
    let error = count(Severity::Error);
    let info = count(Severity::Info);

    // The one type="0" record maps to Success.
    assert_eq!(success, 1, "expected exactly one Success entry (the type=\"0\" line)");

    // No false positives: the fix must not coerce neutral type="1" (or empty)
    // lines into Success/Warning/Error. Every non-success line here is Info.
    assert_eq!(warning, 0, "no warnings expected in this log");
    assert_eq!(error, 0, "no errors expected in this log");
    assert_eq!(
        info,
        result.entries.len() - 1,
        "every non-success record should be Info"
    );

    // The Success record is the finalization line reported in #211.
    let s = result
        .entries
        .iter()
        .find(|e| e.severity == Severity::Success)
        .unwrap();
    assert!(
        s.message.contains("install completed") && s.message.contains("exit code [0]"),
        "unexpected success message: {}",
        s.message
    );
}
