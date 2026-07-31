//! Focused tests for `intune::portal::macos::company_portal::logs`.
//!
//! Every test is driven by a committed synthetic fixture under
//! `tests/fixtures/intune/portal/macos/logs/<version>/<scenario>/`. The test
//! names map one-to-one onto the required fixture matrix in issue #368.

use std::collections::BTreeSet;

use cmtraceopen_parser::intune::portal::macos::company_portal::logs::*;
use cmtraceopen_parser::models::log_entry::{LogFormat, Severity};
use cmtraceopen_parser::parser::intune_macos::matches_intune_macos;

const FIXTURE_ROOT: &str = "tests/fixtures/intune/portal/macos/logs";

const BASIC: &str =
    include_str!("fixtures/intune/portal/macos/logs/5.2504.0/basic-records/CompanyPortal.log");
const ADVANCED: &str =
    include_str!("fixtures/intune/portal/macos/logs/5.2504.0/advanced-logging/CompanyPortal.log");
const MULTILINE: &str = include_str!(
    "fixtures/intune/portal/macos/logs/5.2504.0/multiline-exception/CompanyPortal.log"
);
const ROTATION_CURRENT: &str =
    include_str!("fixtures/intune/portal/macos/logs/5.2504.0/rotation/CompanyPortal.log");
const ROTATION_PREVIOUS: &str =
    include_str!("fixtures/intune/portal/macos/logs/5.2504.0/rotation/CompanyPortal-1.log");
const SAME_TIME: &str = include_str!(
    "fixtures/intune/portal/macos/logs/5.2504.0/same-time-activities/CompanyPortal.log"
);
const TRUNCATED: &str =
    include_str!("fixtures/intune/portal/macos/logs/5.2504.0/truncated-record/CompanyPortal.log");
const UTF8_BOM: &[u8] = include_bytes!(
    "fixtures/intune/portal/macos/logs/5.2504.0/encoding-utf8-bom/CompanyPortal.log"
);
const UTF16LE_BOM: &[u8] = include_bytes!(
    "fixtures/intune/portal/macos/logs/5.2504.0/encoding-utf16le-bom/CompanyPortal.log"
);
const UNKNOWN_VERSION: &str = include_str!(
    "fixtures/intune/portal/macos/logs/unknown-version/version-banner/CompanyPortal.log"
);
const DIAGNOSTIC_REPORT: &str = include_str!(
    "fixtures/intune/portal/macos/logs/negative/diagnostic-report/DiagnosticReportSummary.txt"
);
const UNIFIED_LOG: &str = include_str!(
    "fixtures/intune/portal/macos/logs/negative/unified-log-export/unified-log.ndjson"
);
const OTHER_PROCESS: &str =
    include_str!("fixtures/intune/portal/macos/logs/negative/other-process/IntuneMdmAgent.log");

fn log_path(scenario: &str, file_name: &str) -> String {
    format!("/Users/adele/Library/Logs/CompanyPortal/{scenario}/{file_name}")
}

fn parse_scenario(text: &str, scenario: &str, file_name: &str) -> PortalLogParse {
    parse_company_portal_macos_log(text, &PortalLogSource::new(log_path(scenario, file_name)))
}

fn parsed_records(parse: &PortalLogParse) -> Vec<&PortalLogRecord> {
    parse
        .records
        .iter()
        .filter(|record| record.state == PortalRecordState::Parsed)
        .collect()
}

fn has_note(parse: &PortalLogParse, kind: PortalCoverageKind) -> bool {
    parse.coverage.notes.iter().any(|note| note.kind == kind)
}

/// Coverage never loses a line: records plus unattached blanks equal the file.
fn assert_full_line_coverage(parse: &PortalLogParse) {
    assert_eq!(
        parse.coverage.covered_lines, parse.coverage.total_lines,
        "coverage must account for every physical line"
    );
    let spanned: u32 = parse.records.iter().map(|record| record.line_span).sum();
    assert_eq!(
        spanned + parse.coverage.blank_lines,
        parse.coverage.total_lines
    );
}

/// Every physical line of the source text must survive verbatim in some record.
fn assert_lossless(parse: &PortalLogParse, text: &str) {
    let preserved: String = parse
        .records
        .iter()
        .map(|record| record.raw_text.value.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        assert!(
            preserved.contains(line),
            "line was not preserved losslessly: {line}"
        );
    }
}

// -- matrix item 1: basic information/warning/error records ------------------

#[test]
fn basic_information_warning_and_error_records_parse() {
    let parse = parse_scenario(BASIC, "basic-records", "CompanyPortal.log");

    assert_eq!(
        parse.detection.source_kind,
        PortalSourceKind::CompanyPortalMacosAppLog
    );
    assert_eq!(
        parse.detection.confidence,
        PortalDetectionConfidence::Confirmed
    );
    assert_eq!(parse.app_version.raw_text.as_deref(), Some("5.2504.0"));
    assert_eq!(parse.app_version.support, PortalVersionSupport::Validated);
    assert_eq!(parse.records.len(), 6);
    assert_eq!(parse.coverage.parsed_record_count, 6);
    assert_full_line_coverage(&parse);
    assert_lossless(&parse, BASIC);

    let records = parsed_records(&parse);
    let severities: Vec<Severity> = records.iter().map(|record| record.severity).collect();
    assert_eq!(
        severities,
        vec![
            Severity::Info,
            Severity::Info,
            Severity::Warning,
            Severity::Error,
            Severity::Info,
            Severity::Info,
        ]
    );
    assert_eq!(records[2].severity_letter.as_deref(), Some("W"));
    assert_eq!(records[3].component.as_deref(), Some("EnrollmentManager"));
    assert_eq!(records[3].process.as_deref(), Some("CompanyPortal"));
    assert_eq!(records[3].thread_id, Some(261488));
    assert_eq!(
        records[3].timestamp.as_ref().map(|ts| ts.kind),
        Some(PortalTimestampKind::Local)
    );
    assert_eq!(
        records[3].timestamp.as_ref().map(|ts| ts.raw_text.as_str()),
        Some("2026-05-12 08:14:22:007")
    );

    // Severity is structural only: an `I` record whose text says "failure" and
    // "error" is still Info.
    let benign = records[5];
    assert!(benign.message.value.contains("failure"));
    assert!(benign.message.value.contains("error"));
    assert_eq!(benign.severity, Severity::Info);
    assert_eq!(benign.severity_letter.as_deref(), Some("I"));

    let entries = to_log_entries(&parse);
    assert_eq!(entries.len(), 6);
    assert_eq!(entries[3].format, LogFormat::Timestamped);
    assert_eq!(entries[3].severity, Severity::Error);
    assert_eq!(entries[3].component.as_deref(), Some("CompanyPortal"));
    assert_eq!(entries[3].source_file.as_deref(), Some("EnrollmentManager"));
    assert_eq!(entries[3].line_number, 4);
    assert!(entries[3].timestamp.is_some());
}

// -- matrix item 2: advanced-logging certificate/network record + redaction ---

#[test]
fn advanced_logging_certificate_and_network_records_are_redacted() {
    let parse = parse_scenario(ADVANCED, "advanced-logging", "CompanyPortal.log");
    assert_eq!(parse.coverage.parsed_record_count, 11);
    assert_full_line_coverage(&parse);

    let categories: BTreeSet<PortalEvidenceCategory> =
        parse.records.iter().map(|record| record.category).collect();
    assert!(categories.contains(&PortalEvidenceCategory::NetworkServiceResponse));
    assert!(categories.contains(&PortalEvidenceCategory::SignInAuthentication));
    assert!(categories.contains(&PortalEvidenceCategory::DiagnosticReportAction));
    assert!(categories.contains(&PortalEvidenceCategory::DeviceAction));

    let export = redacted_export_projection(&parse);
    let json = serde_json::to_string(&export).expect("export must serialize");
    for secret in [
        "adele.vance@contoso.example",
        "4b2f9d61-1c53-4c58-8f1a-b0d3e1b5aa77",
        "1d9f6b0e-6d1f-4a2b-9f74-2c0a51a9e310",
        "SC_Online_Issuing",
        "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678",
        "C02XK1TDJGH5",
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9",
        "manage.contoso.example",
        "/Users/adele",
        "tenantId",
        // Network addresses: advanced logging records network-response detail,
        // so IPv4, IPv6, and MAC must not survive the export either.
        "203.0.113.47",
        "198.51.100.9",
        "3c:22:fb:a1:9d:4e",
        "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
    ] {
        assert!(
            !json.contains(secret),
            "redacted export still contains {secret}"
        );
    }

    // Grammar survives redaction: structural fields are untouched.
    assert!(json.contains("NetworkService"));
    assert!(json.contains("CompanyPortal"));
    let kinds: BTreeSet<PortalRedactionKind> = export
        .placeholders
        .iter()
        .map(|placeholder| placeholder.kind)
        .collect();
    for kind in [
        PortalRedactionKind::Email,
        PortalRedactionKind::Url,
        PortalRedactionKind::Certificate,
        PortalRedactionKind::Serial,
        PortalRedactionKind::Token,
        PortalRedactionKind::UserName,
        PortalRedactionKind::Path,
        PortalRedactionKind::Ip,
        PortalRedactionKind::Mac,
    ] {
        assert!(kinds.contains(&kind), "no placeholder issued for {kind:?}");
    }
}

/// A version banner, a timestamp, and a GUID all look address-shaped to a lazy
/// matcher. Redacting them as network addresses would corrupt evidence the
/// module promises to preserve losslessly.
#[test]
fn network_redaction_does_not_swallow_versions_timestamps_or_guids() {
    let parse = parse_scenario(ADVANCED, "advanced-logging", "CompanyPortal.log");
    let export = redacted_export_projection(&parse);
    let json = serde_json::to_string(&export).expect("export must serialize");

    // Dotted version strings have an octet above 255 and must survive.
    assert!(json.contains("5.2504.0"));
    assert!(json.contains("15.4.1"));
    // Structural timestamps are colon-separated but only four groups.
    assert!(json.contains("08:18:00"));
    // The model identifier is not an address.
    assert!(json.contains("MacBookPro18,3"));
}

// -- matrix item 3: multiline exception/payload ------------------------------

#[test]
fn multiline_payload_frames_as_one_logical_record() {
    let parse = parse_scenario(MULTILINE, "multiline-exception", "CompanyPortal.log");

    assert_eq!(parse.records.len(), 2);
    assert_eq!(parse.coverage.continuation_line_count, 5);
    assert_full_line_coverage(&parse);
    assert_lossless(&parse, MULTILINE);

    let first = &parse.records[0];
    assert_eq!(first.line_number, 1);
    assert_eq!(first.line_span, 6);
    assert_eq!(first.severity, Severity::Error);
    assert!(first
        .message
        .value
        .starts_with("Unhandled error while loading catalog\n"));
    assert!(first.message.value.contains("NSLocalizedDescription"));
    assert!(first.raw_text.value.contains("  UserInfo={"));

    assert_eq!(parse.records[1].line_number, 7);
    assert_eq!(parse.records[1].line_span, 1);

    // The projection keeps the multiline payload on one entry.
    let entries = to_log_entries(&parse);
    assert_eq!(entries.len(), 2);
    assert!(entries[0].message.contains('\n'));
}

// -- matrix item 4: rotation ordering ---------------------------------------

#[test]
fn rotation_members_are_ordered_oldest_first() {
    let current = parse_company_portal_macos_log(
        ROTATION_CURRENT,
        &PortalLogSource::new(log_path("rotation", "CompanyPortal.log")),
    );
    let previous = parse_company_portal_macos_log(
        ROTATION_PREVIOUS,
        &PortalLogSource::new(log_path("rotation", "CompanyPortal-1.log")),
    );

    assert_eq!(current.rotation.rotation_index, Some(0));
    assert!(current.rotation.is_current);
    assert_eq!(previous.rotation.rotation_index, Some(1));
    assert!(!previous.rotation.is_current);

    // Deliberately pass the newest member first.
    let merged = merge_rotated_log_entries(&[current.clone(), previous.clone()]);
    assert_eq!(merged.len(), 6);

    let timestamps: Vec<i64> = merged
        .iter()
        .map(|entry| entry.timestamp.expect("record timestamps are parsed"))
        .collect();
    assert!(
        timestamps.windows(2).all(|pair| pair[0] <= pair[1]),
        "merged rotation members must be chronological: {timestamps:?}"
    );
    assert_eq!(
        merged[0].timestamp_display.as_deref(),
        Some("2026-05-11 22:04:11.010")
    );
    let ids: Vec<u64> = merged.iter().map(|entry| entry.id).collect();
    assert_eq!(ids, (0..6).collect::<Vec<u64>>());
}

// -- matrix item 5: same-time distinct activity ids --------------------------

#[test]
fn same_timestamp_records_keep_distinct_activity_ids() {
    let parse = parse_scenario(SAME_TIME, "same-time-activities", "CompanyPortal.log");
    let records = parsed_records(&parse);
    assert_eq!(records.len(), 3);

    let raw_timestamps: BTreeSet<&str> = records
        .iter()
        .filter_map(|record| record.timestamp.as_ref())
        .map(|timestamp| timestamp.raw_text.as_str())
        .collect();
    assert_eq!(
        raw_timestamps.len(),
        1,
        "fixture pins one wall-clock instant"
    );

    let activities: Vec<&str> = records
        .iter()
        .map(|record| {
            record
                .activity_id
                .as_ref()
                .map(|activity| activity.value.as_str())
                .expect("every fixture record declares an activity id")
        })
        .collect();
    assert_eq!(activities[0], activities[2], "same activity correlates");
    assert_ne!(
        activities[0], activities[1],
        "distinct activities stay distinct"
    );

    // Record order is stable and follows line order, not timestamp collisions.
    let lines: Vec<u32> = records.iter().map(|record| record.line_number).collect();
    assert_eq!(lines, vec![1, 2, 3]);

    // Distinctness survives redaction: each activity id gets its own token.
    let export = redacted_export_projection(&parse);
    let redacted: Vec<&str> = export
        .records
        .iter()
        .map(|record| record.activity_id.as_deref().unwrap_or_default())
        .collect();
    assert_eq!(redacted[0], redacted[2]);
    assert_ne!(redacted[0], redacted[1]);
    assert!(redacted[0].starts_with("[redacted:guid:"));
}

// -- matrix item 6: invalid/truncated record --------------------------------

#[test]
fn truncated_records_stay_visible_as_coverage() {
    let parse = parse_scenario(TRUNCATED, "truncated-record", "CompanyPortal.log");

    assert_eq!(parse.coverage.total_lines, 5);
    assert_eq!(parse.records.len(), 5);
    assert_eq!(parse.coverage.parsed_record_count, 2);
    assert_eq!(parse.coverage.malformed_record_count, 2);
    assert_eq!(parse.coverage.unframed_record_count, 1);
    assert_full_line_coverage(&parse);
    assert_lossless(&parse, TRUNCATED);

    assert!(has_note(&parse, PortalCoverageKind::MalformedRecord));
    assert!(has_note(&parse, PortalCoverageKind::UnframedLeadingText));
    assert!(has_note(&parse, PortalCoverageKind::LowConfidenceStructure));
    assert_eq!(parse.detection.confidence, PortalDetectionConfidence::Low);
    assert_eq!(
        parse.detection.source_kind,
        PortalSourceKind::CompanyPortalMacosAppLog
    );

    // Malformed records carry no invented structure and no sniffed severity.
    let malformed = &parse.records[2];
    assert_eq!(malformed.state, PortalRecordState::Malformed);
    assert!(malformed.timestamp.is_none());
    assert!(malformed.severity_letter.is_none());
    assert_eq!(malformed.severity, Severity::Info);
    assert_eq!(malformed.category, PortalEvidenceCategory::Generic);
    assert_eq!(
        malformed.raw_text.value,
        "2026-05-12 08:16:01:4 | CompanyPortal | I | 26149"
    );

    let entries = to_log_entries(&parse);
    assert_eq!(entries.len(), 5);
    assert_eq!(entries[0].format, LogFormat::Plain);
    assert_eq!(entries[2].format, LogFormat::Plain);
    assert_eq!(entries[1].format, LogFormat::Timestamped);
}

// -- matrix item 7: encoding/BOM variants -----------------------------------

#[test]
fn bom_encoding_variants_decode_to_the_same_records() {
    let utf8 = parse_company_portal_macos_log_bytes(
        UTF8_BOM,
        &PortalLogSource::new(log_path("encoding-utf8-bom", "CompanyPortal.log")),
    );
    let utf16 = parse_company_portal_macos_log_bytes(
        UTF16LE_BOM,
        &PortalLogSource::new(log_path("encoding-utf16le-bom", "CompanyPortal.log")),
    );

    assert_eq!(utf8.encoding, PortalEncoding::Utf8Bom);
    assert_eq!(utf16.encoding, PortalEncoding::Utf16Le);
    assert_eq!(
        utf8.detection.source_kind,
        PortalSourceKind::CompanyPortalMacosAppLog
    );
    assert_eq!(
        utf16.detection.source_kind,
        PortalSourceKind::CompanyPortalMacosAppLog
    );
    assert_eq!(utf8.coverage.parsed_record_count, 3);
    assert_eq!(utf16.coverage.parsed_record_count, 3);
    assert_full_line_coverage(&utf8);
    assert_full_line_coverage(&utf16);

    // The BOM must not leak into the first record.
    assert_eq!(utf8.records[0].line_number, 1);
    assert_eq!(utf8.records[0].process.as_deref(), Some("CompanyPortal"));
    assert!(!utf8.records[0].raw_text.value.starts_with('\u{feff}'));

    // Non-ASCII payload survives both decodes identically.
    let utf8_messages: Vec<&str> = utf8
        .records
        .iter()
        .map(|record| record.message.value.as_str())
        .collect();
    let utf16_messages: Vec<&str> = utf16
        .records
        .iter()
        .map(|record| record.message.value.as_str())
        .collect();
    assert_eq!(utf8_messages, utf16_messages);
    assert!(utf8_messages[2].contains('\u{201c}'));

    // A UTF-8 artifact without a BOM is reported as plain UTF-8.
    let plain = parse_company_portal_macos_log_bytes(
        BASIC.as_bytes(),
        &PortalLogSource::new(log_path("basic-records", "CompanyPortal.log")),
    );
    assert_eq!(plain.encoding, PortalEncoding::Utf8);
}

// -- matrix item 8: unknown app version -------------------------------------

#[test]
fn unknown_app_version_downgrades_confidence_without_losing_records() {
    let parse = parse_scenario(UNKNOWN_VERSION, "version-banner", "CompanyPortal.log");

    assert_eq!(
        parse.detection.source_kind,
        PortalSourceKind::CompanyPortalMacosAppLog
    );
    assert_eq!(
        parse.detection.confidence,
        PortalDetectionConfidence::Probable,
        "an unvalidated version family must never yield a confident answer"
    );
    assert_eq!(parse.app_version.raw_text.as_deref(), Some("9.9-preview.1"));
    assert_eq!(parse.app_version.support, PortalVersionSupport::Unknown);
    assert_eq!(parse.app_version.source_line, Some(1));
    assert!(has_note(&parse, PortalCoverageKind::UnknownAppVersion));

    // Records are still parsed losslessly, and unknown components stay generic.
    assert_eq!(parse.coverage.parsed_record_count, 3);
    assert_full_line_coverage(&parse);
    assert_lossless(&parse, UNKNOWN_VERSION);
    assert_eq!(
        parse.records[2].component.as_deref(),
        Some("FutureFeatureManager")
    );
    assert_eq!(parse.records[2].category, PortalEvidenceCategory::Generic);
    assert_eq!(
        parse.records[1].category,
        PortalEvidenceCategory::SignInAuthentication
    );
}

// -- matrix item 9: direct app log vs saved diagnostic report ----------------

#[test]
fn saved_diagnostic_report_is_a_different_source_kind() {
    let parse = parse_company_portal_macos_log(
        DIAGNOSTIC_REPORT,
        &PortalLogSource::new(log_path("diagnostic-report", "DiagnosticReportSummary.txt")),
    );

    assert_eq!(
        parse.detection.source_kind,
        PortalSourceKind::CompanyPortalDiagnosticReport
    );
    assert_eq!(
        parse.detection.confidence,
        PortalDetectionConfidence::Rejected
    );
    assert!(parse.records.is_empty(), "no records may be invented");
    assert!(has_note(&parse, PortalCoverageKind::UnsupportedSourceKind));
    assert_eq!(parse.coverage.total_lines, 15);
    assert_eq!(parse.coverage.covered_lines, 0);

    // The word "CompanyPortal" is all over this file and still proves nothing.
    assert!(DIAGNOSTIC_REPORT.contains("CompanyPortal"));
    assert_eq!(parse.detection.company_portal_record_lines, 0);
    assert!(parse
        .detection
        .signatures
        .contains(&PortalSignature::DiagnosticReportHeader));
    assert!(!parse
        .detection
        .signatures
        .contains(&PortalSignature::CompanyPortalProcessToken));
}

// -- matrix item 10: direct app log vs unified-log export --------------------

#[test]
fn unified_log_export_is_a_different_source_kind() {
    let parse = parse_company_portal_macos_log(
        UNIFIED_LOG,
        &PortalLogSource::new(log_path("unified-log-export", "unified-log.ndjson")),
    );

    assert_eq!(
        parse.detection.source_kind,
        PortalSourceKind::MacosUnifiedLogExport
    );
    assert_eq!(
        parse.detection.confidence,
        PortalDetectionConfidence::Rejected
    );
    assert!(parse.records.is_empty());
    assert!(has_note(&parse, PortalCoverageKind::UnsupportedSourceKind));
    assert!(parse
        .detection
        .signatures
        .contains(&PortalSignature::UnifiedLogNdjsonShape));

    // The export names the CompanyPortal process; structure still rules.
    assert!(UNIFIED_LOG.contains("\"processImagePath\""));
    assert!(UNIFIED_LOG.contains("CompanyPortal"));
    assert_eq!(parse.detection.company_portal_record_lines, 0);
}

#[test]
fn other_intune_macos_processes_are_not_company_portal() {
    let parse = parse_company_portal_macos_log(
        OTHER_PROCESS,
        &PortalLogSource::new(log_path("other-process", "IntuneMdmAgent.log")),
    );

    assert_eq!(
        parse.detection.source_kind,
        PortalSourceKind::IntuneMacosOtherProcessLog
    );
    assert_eq!(
        parse.detection.confidence,
        PortalDetectionConfidence::Rejected
    );
    assert!(parse.records.is_empty());
    assert_eq!(parse.detection.record_head_lines, 3);
    assert_eq!(parse.detection.company_portal_record_lines, 0);

    // This is exactly the case the generic macOS Intune parser cannot separate:
    // it matches both artifacts identically, which is why this module exists.
    for line in OTHER_PROCESS.lines().chain(BASIC.lines()) {
        assert!(matches_intune_macos(line));
    }
}

// -- matrix item 11: deterministic privacy export ---------------------------

#[test]
fn redacted_export_is_deterministic() {
    let first = parse_scenario(ADVANCED, "advanced-logging", "CompanyPortal.log");
    let second = parse_scenario(ADVANCED, "advanced-logging", "CompanyPortal.log");

    let first_json = serde_json::to_string_pretty(&redacted_export_projection(&first))
        .expect("export must serialize");
    let second_json = serde_json::to_string_pretty(&redacted_export_projection(&second))
        .expect("export must serialize");
    assert_eq!(
        first_json, second_json,
        "redacted export must be byte-stable"
    );

    let export = redacted_export_projection(&first);

    // Placeholder index is stably ordered and leaks no original values.
    let ordered: Vec<(PortalRedactionKind, String)> = export
        .placeholders
        .iter()
        .map(|placeholder| (placeholder.kind, placeholder.token.clone()))
        .collect();
    let mut sorted = ordered.clone();
    sorted.sort();
    assert_eq!(ordered, sorted);
    for placeholder in &export.placeholders {
        assert!(placeholder.token.starts_with("[redacted:"));
        assert!(placeholder.occurrences >= 1);
    }

    // The same original value always maps to the same token: the fixture uses
    // one address twice, so exactly one email placeholder is issued.
    let email_placeholders: Vec<&PortalPlaceholder> = export
        .placeholders
        .iter()
        .filter(|placeholder| placeholder.kind == PortalRedactionKind::Email)
        .collect();
    assert_eq!(email_placeholders.len(), 1);
    assert!(email_placeholders[0].occurrences >= 2);

    // Structure, coverage, and record identity survive the projection.
    assert_eq!(export.records.len(), first.records.len());
    assert_eq!(export.coverage, first.coverage);
    assert_eq!(export.detection, first.detection);
    assert_eq!(export.app_version, first.app_version);
    assert_eq!(export.records[0].evidence_id, "cp-macos-log-r000000");
    assert!(export.file_path.starts_with("/Users/[redacted:user:"));
}

// -- cross-cutting contract tests -------------------------------------------

#[test]
fn grammar_matches_the_generic_intune_macos_parser() {
    for line in BASIC.lines().chain(ADVANCED.lines()) {
        assert_eq!(
            is_record_line(line),
            matches_intune_macos(line),
            "record grammar drifted from crate::parser::intune_macos for: {line}"
        );
    }
}

#[test]
fn path_hint_never_decides_the_source_kind() {
    // Correct folder, wrong content.
    let wrong_content = parse_company_portal_macos_log(
        UNIFIED_LOG,
        &PortalLogSource::new("/Users/adele/Library/Logs/CompanyPortal/CompanyPortal.log"),
    );
    assert!(wrong_content.detection.path_hint_matched);
    assert_eq!(
        wrong_content.detection.source_kind,
        PortalSourceKind::MacosUnifiedLogExport
    );

    // Wrong folder, correct content.
    let wrong_folder = parse_company_portal_macos_log(
        BASIC,
        &PortalLogSource::new("/tmp/copied-from-a-ticket.log"),
    );
    assert!(!wrong_folder.detection.path_hint_matched);
    assert_eq!(
        wrong_folder.detection.source_kind,
        PortalSourceKind::CompanyPortalMacosAppLog
    );
    assert_eq!(
        wrong_folder.detection.confidence,
        PortalDetectionConfidence::Confirmed
    );
}

#[test]
fn every_classified_component_is_proven_by_a_fixture() {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for text in [
        BASIC,
        ADVANCED,
        MULTILINE,
        ROTATION_CURRENT,
        ROTATION_PREVIOUS,
        SAME_TIME,
        TRUNCATED,
        UNKNOWN_VERSION,
    ] {
        let parse = parse_scenario(text, "component-scan", "CompanyPortal.log");
        for record in &parse.records {
            if let Some(component) = &record.component {
                seen.insert(component.clone());
            }
        }
    }

    for token in classified_component_tokens() {
        assert!(
            seen.contains(token),
            "classified component {token} has no fixture proving it"
        );
    }
}

#[test]
fn empty_and_blank_input_is_reported_not_guessed() {
    let empty = parse_company_portal_macos_log(
        "",
        &PortalLogSource::new(log_path("basic-records", "CompanyPortal.log")),
    );
    assert_eq!(empty.coverage.total_lines, 0);
    assert!(empty.records.is_empty());
    assert!(has_note(&empty, PortalCoverageKind::EmptyInput));
    assert_eq!(empty.detection.source_kind, PortalSourceKind::Unrecognized);

    // A rejected artifact accumulates coverage notes rather than replacing them:
    // the empty-input note recorded before detection survives alongside the
    // rejection note. Consumers must not assume exactly one note.
    assert!(has_note(&empty, PortalCoverageKind::UnsupportedSourceKind));
    assert!(
        empty.coverage.notes.len() >= 2,
        "expected both EmptyInput and UnsupportedSourceKind, got {:?}",
        empty.coverage.notes
    );
}

/// A caller that decodes a BOM-marked file itself and uses the text API must get
/// the same records as the bytes API. Left in place, the BOM breaks the record
/// grammar on line 1 and the first record degrades to Unframed.
#[test]
fn text_api_tolerates_a_leading_bom_like_the_bytes_api() {
    let source = PortalLogSource::new(log_path("basic-records", "CompanyPortal.log"));

    let plain = parse_company_portal_macos_log(BASIC, &source);
    let bommed = parse_company_portal_macos_log(&format!("\u{feff}{BASIC}"), &source);

    assert_eq!(
        bommed.coverage.parsed_record_count,
        plain.coverage.parsed_record_count
    );
    assert_eq!(bommed.coverage.unframed_record_count, 0);
    assert_eq!(bommed.records.len(), plain.records.len());
    assert_eq!(bommed.records[0].message, plain.records[0].message);
    assert!(!bommed.records[0].raw_text.value.starts_with('\u{feff}'));

    // And the bytes API keeps agreeing with it.
    let via_bytes = parse_company_portal_macos_log_bytes(
        &[b"\xef\xbb\xbf".to_vec(), BASIC.as_bytes().to_vec()].concat(),
        &source,
    );
    assert_eq!(
        via_bytes.coverage.parsed_record_count,
        plain.coverage.parsed_record_count
    );
}

/// `Confirmed` does not mean "a version banner was validated". Rotated members
/// carry no banner and must not be demoted for it.
#[test]
fn confirmed_confidence_does_not_require_a_version_banner() {
    let no_banner = "2026-05-12 08:14:20:104 | CompanyPortal | I | 261510 | SignInViewModel | Sign-in state refreshed\n\
                     2026-05-12 08:14:21:200 | CompanyPortal | W | 261510 | NetworkService | Retrying request\n";
    let parse = parse_company_portal_macos_log(
        no_banner,
        &PortalLogSource::new(log_path("rotation", "CompanyPortal-3.log")),
    );

    assert_eq!(
        parse.detection.confidence,
        PortalDetectionConfidence::Confirmed
    );
    // The absence of a banner is reported separately, so a consumer that needs a
    // declared version can still tell.
    assert_eq!(parse.app_version.support, PortalVersionSupport::NotDeclared);
    assert!(parse.app_version.raw_text.is_none());
}

/// `F` is the one severity letter where this module deliberately diverges from
/// `parser::intune_macos`, which has no `F` arm and would fall back to `Info`.
/// Rendering a fatal record as `Info` hides the most important line in the file,
/// so the divergence is intentional. Pinned here so it is not "corrected" back.
#[test]
fn fatal_severity_letter_maps_to_error() {
    let fatal = "2026-05-12 08:14:20:104 | CompanyPortal | F | 261510 | AppDelegate | Unrecoverable state, terminating\n";
    let parse = parse_company_portal_macos_log(
        fatal,
        &PortalLogSource::new(log_path("basic-records", "CompanyPortal.log")),
    );

    assert_eq!(parse.coverage.parsed_record_count, 1);
    assert_eq!(parse.records[0].severity, Severity::Error);

    // E and W still match the generic parser exactly.
    for (letter, expected) in [("E", Severity::Error), ("W", Severity::Warning)] {
        let line = format!(
            "2026-05-12 08:14:20:104 | CompanyPortal | {letter} | 261510 | AppDelegate | probe\n"
        );
        let probe = parse_company_portal_macos_log(
            &line,
            &PortalLogSource::new(log_path("basic-records", "CompanyPortal.log")),
        );
        assert_eq!(probe.records[0].severity, expected);
    }
}

/// The rotation digit group is unbounded, so an absurd index overflows `u32`.
/// Deriving `is_current` from the parsed value marked such a member as the live
/// file and sorted the oldest member newest.
#[test]
fn unparsable_rotation_index_is_not_treated_as_the_current_log() {
    let huge = rotation_member_from_file_name("CompanyPortal-99999999999.log");
    assert!(
        !huge.is_current,
        "a member with a digit group is never the live file"
    );
    assert_eq!(huge.rotation_index, Some(u32::MAX));

    let current = rotation_member_from_file_name("CompanyPortal.log");
    assert!(current.is_current);
    assert_eq!(current.rotation_index, Some(0));

    // The saturated member is the oldest, so it sorts first, not last.
    let ordered = order_rotation_members_oldest_first(&[
        rotation_member_from_file_name("CompanyPortal.log"),
        rotation_member_from_file_name("CompanyPortal-99999999999.log"),
        rotation_member_from_file_name("CompanyPortal-1.log"),
    ]);
    let names: Vec<&str> = ordered
        .iter()
        .map(|m| m.file_name.as_deref().unwrap_or(""))
        .collect();
    assert_eq!(
        names,
        vec![
            "CompanyPortal-99999999999.log",
            "CompanyPortal-1.log",
            "CompanyPortal.log"
        ]
    );
}

/// Rotation cuts at a byte boundary, so a member can open with a long run of
/// continuation lines. Sampling only the first `DETECTION_SAMPLE_LINES` physical
/// lines classified such a file as `Unrecognized` and dropped every record.
#[test]
fn rotated_member_with_long_leading_continuation_run_is_still_recognized() {
    let mut text = String::new();
    for i in 0..250 {
        text.push_str(&format!("    continuation payload line {i}\n"));
    }
    text.push_str(
        "2026-05-12 08:14:20:104 | CompanyPortal | I | 261510 | SignInViewModel | Sign-in state refreshed\n",
    );

    let parse = parse_company_portal_macos_log(
        &text,
        &PortalLogSource::new(log_path("rotation", "CompanyPortal-1.log")),
    );

    assert_eq!(
        parse.detection.source_kind,
        PortalSourceKind::CompanyPortalMacosAppLog
    );
    assert_eq!(parse.coverage.parsed_record_count, 1);
    assert_full_line_coverage(&parse);

    // An artifact with no record start anywhere is still rejected.
    let never = parse_company_portal_macos_log(
        &"    just continuation text\n".repeat(250),
        &PortalLogSource::new(log_path("rotation", "CompanyPortal-1.log")),
    );
    assert_ne!(
        never.detection.source_kind,
        PortalSourceKind::CompanyPortalMacosAppLog
    );
}

/// `PortalTimestamp::raw_text` must be the source text. The grammar tolerates
/// multiple spaces and tabs, which a reconstructed value silently rewrote.
#[test]
fn raw_timestamp_preserves_the_source_spacing() {
    let spaced =
        "2026-05-12  08:14:20:104 | CompanyPortal | I | 261510 | SignInViewModel | Spaced\n";
    let parse = parse_company_portal_macos_log(
        spaced,
        &PortalLogSource::new(log_path("basic-records", "CompanyPortal.log")),
    );

    assert_eq!(parse.coverage.parsed_record_count, 1);
    let timestamp = parse.records[0]
        .timestamp
        .as_ref()
        .expect("a well-formed record carries a timestamp");
    assert_eq!(
        timestamp.raw_text, "2026-05-12  08:14:20:104",
        "raw_text must keep the original spacing, not a re-rendering"
    );
    // The grammar carries no timezone, so the record stays Local and is never
    // normalized to UTC. Preserving the raw spacing must not change that.
    assert_eq!(timestamp.kind, PortalTimestampKind::Local);
    assert!(timestamp.normalized_utc.is_none());

    // The irregular spacing still resolves to the same instant downstream.
    let entries = to_log_entries(&parse);
    assert_eq!(entries.len(), 1);
    assert!(entries[0].timestamp.is_some());
    assert_eq!(
        entries[0].timestamp_display.as_deref(),
        Some("2026-05-12 08:14:20.104")
    );
}

/// An ASCII-only email class does not truncate a non-ASCII address, it misses it
/// entirely, because the leading word boundary never anchors.
#[test]
fn non_ascii_identities_are_redacted() {
    let text = "2026-05-12 08:14:20:104 | CompanyPortal | I | 261510 | SignInViewModel | Signed in as \u{e9}lodie.dupont@contoso.example\n";
    let parse = parse_company_portal_macos_log(
        text,
        &PortalLogSource::new(log_path("basic-records", "CompanyPortal.log")),
    );
    let export = redacted_export_projection(&parse);
    let json = serde_json::to_string(&export).expect("export must serialize");

    assert!(
        !json.contains("lodie.dupont"),
        "non-ASCII identity leaked: {json}"
    );
    assert!(!json.contains("contoso.example"));
    assert!(json.contains("[redacted:email:"));
}

#[test]
fn fixture_root_layout_is_versioned_by_scenario() {
    // Documents the on-disk contract the include_* macros above depend on.
    assert_eq!(FIXTURE_ROOT, "tests/fixtures/intune/portal/macos/logs");
    assert!(BASIC.starts_with("2026-05-12 08:14:20:104 | CompanyPortal |"));
}
