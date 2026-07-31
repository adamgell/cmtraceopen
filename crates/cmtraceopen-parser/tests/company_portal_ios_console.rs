//! Company Portal for iOS / iPadOS: imported macOS Console plain-text diagnostics.
//!
//! Each test names the fixture-matrix item from issue #372 that it proves.

use cmtraceopen_parser::intune::portal::ios_ipados::company_portal::diagnostics::*;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const SUPPORTED_BASELINE: &str = include_str!(
    "fixtures/intune/portal/ios_ipados/console/console-plaintext-v1/supported-baseline/export.log"
);
const SEVERITY_COVERAGE: &str = include_str!(
    "fixtures/intune/portal/ios_ipados/console/console-plaintext-v1/severity-coverage/export.log"
);
const UNRELATED_PROCESS_NOISE: &str = include_str!(
    "fixtures/intune/portal/ios_ipados/console/console-plaintext-v1/unrelated-process-noise/export.log"
);
const SAME_TIMESTAMP: &str = include_str!(
    "fixtures/intune/portal/ios_ipados/console/console-plaintext-v1/same-timestamp-multiple-processes/export.log"
);
const MULTILINE_PAYLOAD: &str = include_str!(
    "fixtures/intune/portal/ios_ipados/console/console-plaintext-v1/multiline-payload/export.log"
);
const TRUNCATED_BOUNDARIES: &str = include_str!(
    "fixtures/intune/portal/ios_ipados/console/console-plaintext-v1/truncated-boundaries/export.log"
);
const MALFORMED_RECORDS: &str = include_str!(
    "fixtures/intune/portal/ios_ipados/console/console-plaintext-v1/malformed-records/export.log"
);
const MISSING_TIMEZONE: &str = include_str!(
    "fixtures/intune/portal/ios_ipados/console/console-plaintext-v1/missing-timezone/export.log"
);
const KNOWN_APP_VERSION: &str = include_str!(
    "fixtures/intune/portal/ios_ipados/console/console-plaintext-v1/known-app-version/export.log"
);
const UNKNOWN_APP_VERSION: &str = include_str!(
    "fixtures/intune/portal/ios_ipados/console/console-plaintext-v1/unknown-app-version/export.log"
);
const PRIVACY_PAYLOAD: &str = include_str!(
    "fixtures/intune/portal/ios_ipados/console/console-plaintext-v1/privacy-payload/export.log"
);
const LOCALE_VARIANT: &str = include_str!(
    "fixtures/intune/portal/ios_ipados/console/console-plaintext-v1-de/locale-variant/export.log"
);
const SUBSYSTEM_COLUMNS: &str = include_str!(
    "fixtures/intune/portal/ios_ipados/console/console-plaintext-v2-subsystem-columns/explicit-subsystem-columns/export.log"
);
const ARBITRARY_PLAIN_LOG: &str = include_str!(
    "fixtures/intune/portal/ios_ipados/console/unknown/arbitrary-plain-log/export.log"
);
const UNREGISTERED_HEADER: &str = include_str!(
    "fixtures/intune/portal/ios_ipados/console/unknown/unregistered-header/export.log"
);
const UNREGISTERED_SEQUENCE: &str = include_str!(
    "fixtures/intune/portal/ios_ipados/console/unknown/unregistered-header/export-known-titles.log"
);
const HEADERLESS_RECORDS: &str =
    include_str!("fixtures/intune/portal/ios_ipados/console/unknown/headerless-records/export.log");

const ALL_FIXTURES: &[(&str, &str)] = &[
    ("supported-baseline", SUPPORTED_BASELINE),
    ("severity-coverage", SEVERITY_COVERAGE),
    ("unrelated-process-noise", UNRELATED_PROCESS_NOISE),
    ("same-timestamp-multiple-processes", SAME_TIMESTAMP),
    ("multiline-payload", MULTILINE_PAYLOAD),
    ("truncated-boundaries", TRUNCATED_BOUNDARIES),
    ("malformed-records", MALFORMED_RECORDS),
    ("missing-timezone", MISSING_TIMEZONE),
    ("known-app-version", KNOWN_APP_VERSION),
    ("unknown-app-version", UNKNOWN_APP_VERSION),
    ("privacy-payload", PRIVACY_PAYLOAD),
    ("locale-variant", LOCALE_VARIANT),
    ("explicit-subsystem-columns", SUBSYSTEM_COLUMNS),
    ("arbitrary-plain-log", ARBITRARY_PLAIN_LOG),
    ("unregistered-header", UNREGISTERED_HEADER),
    ("unregistered-sequence", UNREGISTERED_SEQUENCE),
    ("headerless-records", HEADERLESS_RECORDS),
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn message_of(record: &PortalConsoleRecord) -> &str {
    record.message.value.as_str()
}

fn record_at(capture: &PortalConsoleCapture, index: usize) -> &PortalConsoleRecord {
    capture
        .records
        .get(index)
        .unwrap_or_else(|| panic!("record {index} must exist"))
}

// ---------------------------------------------------------------------------
// Item 1 - supported Console plain-text export
// ---------------------------------------------------------------------------

#[test]
fn item01_supported_export_is_detected_and_fully_parsed() {
    let capture = parse_console_export(SUPPORTED_BASELINE);

    assert_eq!(
        capture.detection.outcome,
        PortalConsoleDetectionOutcome::Supported
    );
    assert_eq!(capture.schema_version, PORTAL_IOS_CONSOLE_SCHEMA_VERSION);

    let layout = capture.layout.as_ref().expect("layout must be resolved");
    assert_eq!(layout.layout_id, "console-plaintext-v1");
    assert_eq!(layout.locale_hint, None);
    assert_eq!(layout.decimal_separator, PortalConsoleDecimalSeparator::Dot);
    assert_eq!(
        layout.columns,
        vec![
            PortalConsoleColumn::Timestamp,
            PortalConsoleColumn::Thread,
            PortalConsoleColumn::Type,
            PortalConsoleColumn::Activity,
            PortalConsoleColumn::Pid,
            PortalConsoleColumn::Ttl,
        ]
    );

    assert_eq!(capture.totals.total_records, 5);
    assert!(capture
        .records
        .iter()
        .all(|record| record.parse_state == PortalConsoleParseState::Parsed));

    let first = record_at(&capture, 0);
    assert_eq!(first.thread_id.as_deref(), Some("0x1a2b3"));
    assert_eq!(first.activity_id.as_deref(), Some("0x0"));
    assert_eq!(first.pid, Some(312));
    assert_eq!(first.ttl, Some(0));
    assert_eq!(first.level.raw, "Default");
    assert_eq!(first.level.normalized, PortalConsoleSeverity::Default);
    assert_eq!(first.source.process.as_deref(), Some("CompanyPortal"));
    assert_eq!(first.source.library.as_deref(), Some("Enrollment"));
    assert_eq!(
        first.source.subsystem.as_deref(),
        Some("com.microsoft.CompanyPortal")
    );
    assert_eq!(first.source.category.as_deref(), Some("Enrollment"));
    assert_eq!(message_of(first), "Beginning device enrollment flow");
}

#[test]
fn item01_every_record_carries_an_exact_source_reference() {
    let capture = parse_console_export(SUPPORTED_BASELINE);

    for (index, record) in capture.records.iter().enumerate() {
        assert_eq!(record.reference.record_index, index);
        // Line 1 is the header, so records start on line 2.
        assert_eq!(record.reference.first_line_number, index + 2);
        assert_eq!(record.reference.last_line_number, index + 2);
        assert_eq!(
            record.reference.evidence_ref.evidence_id,
            format!("ios-console-record-{index:06}")
        );
        assert_eq!(
            record.reference.evidence_ref.source_artifact_id,
            DEFAULT_SOURCE_ARTIFACT_ID
        );
    }
}

#[test]
fn item01_source_artifact_id_flows_into_every_evidence_ref() {
    let capture = parse_console_export_with_artifact_id(SUPPORTED_BASELINE, "case-4711");

    assert_eq!(capture.source_artifact_id, "case-4711");
    assert!(capture
        .records
        .iter()
        .all(|record| record.reference.evidence_ref.source_artifact_id == "case-4711"));
}

// ---------------------------------------------------------------------------
// Item 2 - Company Portal info / debug / warning / error records
// ---------------------------------------------------------------------------

#[test]
fn item02_console_message_types_are_normalized_and_preserved() {
    let capture = parse_console_export(SEVERITY_COVERAGE);

    let observed: Vec<(&str, &PortalConsoleSeverity)> = capture
        .records
        .iter()
        .map(|record| (record.level.raw.as_str(), &record.level.normalized))
        .collect();

    assert_eq!(
        observed,
        vec![
            ("Debug", &PortalConsoleSeverity::Debug),
            ("Info", &PortalConsoleSeverity::Info),
            ("Default", &PortalConsoleSeverity::Default),
            ("Error", &PortalConsoleSeverity::Error),
            ("Fault", &PortalConsoleSeverity::Fault),
        ]
    );

    // Every one of them is Company Portal evidence.
    assert_eq!(capture.company_portal_records().len(), 5);
}

#[test]
fn item02_unrecognized_type_token_preserves_raw_without_guessing() {
    let export = "\
Timestamp                       Thread     Type        Activity             PID    TTL
2024-03-15 10:00:00.000001-0700 0x1a2b3    Notice      0x0                  312    0    CompanyPortal: (Sync) [com.microsoft.CompanyPortal:Sync] Message
";
    let capture = parse_console_export(export);
    let record = record_at(&capture, 0);

    assert_eq!(record.level.raw, "Notice");
    assert_eq!(record.level.normalized, PortalConsoleSeverity::Unknown);
    assert_eq!(record.parse_state, PortalConsoleParseState::Parsed);
}

// ---------------------------------------------------------------------------
// Item 3 - unrelated-process noise, and the structural filter
// ---------------------------------------------------------------------------

#[test]
fn item03_filtering_is_structural_not_textual() {
    let capture = parse_console_export(UNRELATED_PROCESS_NOISE);

    // Every raw record is preserved.
    assert_eq!(capture.totals.total_records, 5);
    assert_eq!(capture.totals.company_portal_records, 1);
    assert_eq!(capture.totals.other_process_records, 4);

    // The four unrelated records all mention Intune or CompanyPortal in free text, and are
    // still not Company Portal evidence. That is the whole point of the contract.
    for record in capture.other_process_records() {
        let text = message_of(record);
        assert!(
            text.contains("Intune") || text.contains("CompanyPortal"),
            "noise fixture record must mention Intune/CompanyPortal in text: {text}"
        );
        assert_eq!(record.source.class, PortalConsoleSourceClass::OtherProcess);
        assert_eq!(record.source.signature, PortalConsoleSourceSignature::None);
    }

    let company_portal = capture.company_portal_records();
    assert_eq!(company_portal.len(), 1);
    assert_eq!(
        company_portal[0].source.signature,
        PortalConsoleSourceSignature::ProcessName
    );
    assert_eq!(
        company_portal[0].source.process.as_deref(),
        Some("CompanyPortal")
    );
}

#[test]
fn item03_subsystem_namespace_is_matched_exactly() {
    // A look-alike namespace must not be attributed to Company Portal.
    let export = "\
Timestamp                       Thread     Type        Activity             PID    TTL
2024-03-15 10:00:00.000001-0700 0x1a2b3    Default     0x0                  900    0    thirdparty: (Kit) [com.microsoft.CompanyPortalium:Sync] Look-alike subsystem
2024-03-15 10:00:00.000002-0700 0x1a2b4    Default     0x0                  901    0    helper: (Kit) [com.microsoft.CompanyPortal.Extension:Sync] Genuine child namespace
";
    let capture = parse_console_export(export);

    assert_eq!(
        record_at(&capture, 0).source.class,
        PortalConsoleSourceClass::OtherProcess
    );
    assert_eq!(
        record_at(&capture, 1).source.class,
        PortalConsoleSourceClass::CompanyPortal
    );
    assert_eq!(
        record_at(&capture, 1).source.signature,
        PortalConsoleSourceSignature::SubsystemNamespace
    );
}

// ---------------------------------------------------------------------------
// Item 4 - same time, different processes and activities
// ---------------------------------------------------------------------------

#[test]
fn item04_identical_timestamps_stay_distinct_records_in_source_order() {
    let capture = parse_console_export(SAME_TIMESTAMP);

    assert_eq!(capture.totals.total_records, 4);

    let instants: Vec<Option<&str>> = capture
        .records
        .iter()
        .map(|record| record.timestamp.normalized_utc.as_deref())
        .collect();
    assert!(
        instants
            .iter()
            .all(|instant| *instant == Some("2024-03-15T19:00:00.500000Z")),
        "fixture shares one instant across processes: {instants:?}"
    );

    let pids: Vec<Option<u32>> = capture.records.iter().map(|record| record.pid).collect();
    assert_eq!(pids, vec![Some(312), Some(98), Some(312), Some(55)]);

    let activities: Vec<Option<&str>> = capture
        .records
        .iter()
        .map(|record| record.activity_id.as_deref())
        .collect();
    assert_eq!(
        activities,
        vec![Some("0x0"), Some("0x7f1"), Some("0x7f2"), Some("0x7f3")]
    );

    // Source order, not timestamp order, disambiguates a tie.
    let classes: Vec<&PortalConsoleSourceClass> = capture
        .records
        .iter()
        .map(|record| &record.source.class)
        .collect();
    assert_eq!(
        classes,
        vec![
            &PortalConsoleSourceClass::CompanyPortal,
            &PortalConsoleSourceClass::OtherProcess,
            &PortalConsoleSourceClass::CompanyPortal,
            &PortalConsoleSourceClass::OtherProcess,
        ]
    );
}

// ---------------------------------------------------------------------------
// Item 5 - multiline exception / payload
// ---------------------------------------------------------------------------

#[test]
fn item05_continuation_lines_fold_into_the_owning_record() {
    let capture = parse_console_export(MULTILINE_PAYLOAD);

    assert_eq!(capture.totals.total_records, 4);

    let backtrace = record_at(&capture, 1);
    assert_eq!(backtrace.continuation_line_count, 4);
    assert_eq!(backtrace.reference.first_line_number, 3);
    assert_eq!(backtrace.reference.last_line_number, 7);
    assert!(message_of(backtrace).starts_with("Enrollment failed with an unhandled error\n"));
    assert!(message_of(backtrace).contains("CompanyPortalKit.EnrollmentError.profileRejected"));
    assert!(message_of(backtrace).contains("_dispatch_call_block_and_release + 32"));
    assert_eq!(backtrace.level.normalized, PortalConsoleSeverity::Error);
    assert_eq!(
        backtrace.source.class,
        PortalConsoleSourceClass::CompanyPortal
    );

    let payload = record_at(&capture, 2);
    assert_eq!(payload.continuation_line_count, 5);
    assert!(message_of(payload).contains("\"reason\": \"profileRejected\""));

    // The raw text of a folded record is lossless.
    assert_eq!(payload.raw_text.lines().count(), 6);

    // The record after a multi-line payload is framed independently.
    let after = record_at(&capture, 3);
    assert_eq!(after.continuation_line_count, 0);
    assert_eq!(after.source.class, PortalConsoleSourceClass::OtherProcess);
}

#[test]
fn item05_blank_lines_do_not_split_a_payload() {
    let export = "\
Timestamp                       Thread     Type        Activity             PID    TTL
2024-03-15 10:00:00.000001-0700 0x1a2b3    Error       0x0                  312    0    CompanyPortal: (Sync) [com.microsoft.CompanyPortal:Sync] Payload follows
\tfirst payload line

\tsecond payload line after a blank
";
    let capture = parse_console_export(export);

    assert_eq!(capture.totals.total_records, 1);
    let record = record_at(&capture, 0);
    assert_eq!(record.continuation_line_count, 2);
    assert!(message_of(record).contains("second payload line after a blank"));
}

// ---------------------------------------------------------------------------
// Item 6 - truncated first / last record
// ---------------------------------------------------------------------------

#[test]
fn item06_copy_boundaries_become_visible_coverage() {
    let capture = parse_console_export(TRUNCATED_BOUNDARIES);

    let leading: Vec<&PortalConsoleCoverage> = capture
        .coverage
        .iter()
        .filter(|entry| entry.kind == PortalConsoleCoverageKind::TruncatedLeading)
        .collect();
    assert_eq!(leading.len(), 1);
    assert_eq!(leading[0].first_line_number, 2);
    assert_eq!(leading[0].last_line_number, 3);
    assert!(leading[0]
        .raw_text
        .contains("_dispatch_call_block_and_release"));

    let trailing: Vec<&PortalConsoleCoverage> = capture
        .coverage
        .iter()
        .filter(|entry| entry.kind == PortalConsoleCoverageKind::TruncatedTrailing)
        .collect();
    assert_eq!(trailing.len(), 1);
    assert_eq!(trailing[0].raw_text.trim(), "2024-03-15 17:00:02.0");

    assert_eq!(capture.totals.truncated_records, 1);
    assert_eq!(capture.totals.malformed_records, 0);

    // The two intact records in between still parse and classify.
    assert_eq!(capture.totals.company_portal_records, 2);

    // A truncated record is never attributed to Company Portal.
    let truncated = capture
        .records
        .iter()
        .find(|record| record.parse_state == PortalConsoleParseState::Truncated)
        .expect("truncated record must exist");
    assert_eq!(
        truncated.source.class,
        PortalConsoleSourceClass::Unattributed
    );
}

// ---------------------------------------------------------------------------
// Item 7 - malformed timestamp / column
// ---------------------------------------------------------------------------

#[test]
fn item07_malformed_records_are_preserved_and_never_attributed() {
    let capture = parse_console_export(MALFORMED_RECORDS);

    assert_eq!(capture.totals.total_records, 4);
    assert_eq!(capture.totals.malformed_records, 2);
    assert_eq!(capture.totals.company_portal_records, 2);
    assert_eq!(capture.totals.unattributed_records, 2);

    let bad_timestamp = record_at(&capture, 1);
    assert_eq!(
        bad_timestamp.parse_state,
        PortalConsoleParseState::Malformed
    );
    assert_eq!(bad_timestamp.timestamp.kind, PortalTimestampKind::Invalid);
    assert_eq!(bad_timestamp.timestamp.normalized_utc, None);
    assert!(bad_timestamp.raw_text.contains("2024-13-45 99:99:99"));

    let bad_column = record_at(&capture, 2);
    assert_eq!(bad_column.parse_state, PortalConsoleParseState::Malformed);
    assert!(bad_column.raw_text.contains("non-numeric PID column"));

    // Both malformed lines are also reported as coverage, so nothing is silently dropped.
    let malformed_coverage = capture
        .coverage
        .iter()
        .filter(|entry| entry.kind == PortalConsoleCoverageKind::MalformedRecord)
        .count();
    assert_eq!(malformed_coverage, 2);

    // The good records around them are unaffected.
    assert_eq!(
        record_at(&capture, 0).parse_state,
        PortalConsoleParseState::Parsed
    );
    assert_eq!(
        record_at(&capture, 3).parse_state,
        PortalConsoleParseState::Parsed
    );
}

// ---------------------------------------------------------------------------
// Item 8 - locale / layout variants
// ---------------------------------------------------------------------------

#[test]
fn item08_localized_header_and_comma_decimals_resolve_to_the_v1_layout() {
    let capture = parse_console_export(LOCALE_VARIANT);

    assert_eq!(
        capture.detection.outcome,
        PortalConsoleDetectionOutcome::Supported
    );
    let layout = capture.layout.as_ref().expect("layout must be resolved");
    assert_eq!(layout.layout_id, "console-plaintext-v1");
    assert_eq!(layout.locale_hint.as_deref(), Some("de"));
    assert_eq!(
        layout.decimal_separator,
        PortalConsoleDecimalSeparator::Comma
    );

    assert_eq!(capture.totals.total_records, 3);
    assert_eq!(capture.totals.company_portal_records, 2);

    let first = record_at(&capture, 0);
    assert_eq!(first.timestamp.kind, PortalTimestampKind::Offset);
    assert_eq!(first.timestamp.original_offset.as_deref(), Some("+0100"));
    // 12:00:00,123456 +0100 is 11:00:00.123456 UTC.
    assert_eq!(
        first.timestamp.normalized_utc.as_deref(),
        Some("2024-03-15T11:00:00.123456Z")
    );
    assert!(capture.is_cross_source_comparable());
}

#[test]
fn item08_explicit_subsystem_columns_resolve_to_the_v2_layout() {
    let capture = parse_console_export(SUBSYSTEM_COLUMNS);

    assert_eq!(
        capture.detection.outcome,
        PortalConsoleDetectionOutcome::Supported
    );
    let layout = capture.layout.as_ref().expect("layout must be resolved");
    assert_eq!(layout.layout_id, "console-plaintext-v2-subsystem-columns");
    assert_eq!(layout.columns.len(), 8);

    assert_eq!(capture.totals.total_records, 3);
    assert_eq!(capture.totals.company_portal_records, 2);

    let first = record_at(&capture, 0);
    assert_eq!(
        first.source.subsystem.as_deref(),
        Some("com.microsoft.CompanyPortal")
    );
    assert_eq!(first.source.category.as_deref(), Some("Enrollment"));
    assert_eq!(first.source.process.as_deref(), Some("CompanyPortal"));
    assert_eq!(first.source.library.as_deref(), Some("Enrollment"));
    assert_eq!(message_of(first), "Profile installation requested");

    let noise = record_at(&capture, 2);
    assert_eq!(noise.source.class, PortalConsoleSourceClass::OtherProcess);
    assert_eq!(
        noise.source.subsystem.as_deref(),
        Some("com.apple.ManagedConfiguration")
    );
}

// ---------------------------------------------------------------------------
// Item 9 - missing timezone
// ---------------------------------------------------------------------------

#[test]
fn item09_missing_timezone_is_a_state_not_an_error_and_never_defaults_to_utc() {
    let capture = parse_console_export(MISSING_TIMEZONE);

    assert_eq!(
        capture.detection.outcome,
        PortalConsoleDetectionOutcome::Supported
    );
    assert_eq!(capture.totals.total_records, 3);
    assert_eq!(capture.totals.malformed_records, 0);

    for record in &capture.records {
        assert_eq!(record.parse_state, PortalConsoleParseState::Parsed);
        assert_eq!(record.timestamp.kind, PortalTimestampKind::Local);
        assert_eq!(record.timestamp.original_offset, None);
        assert_eq!(
            record.timestamp.normalized_utc, None,
            "a zoneless instant must never be manufactured into UTC"
        );
        assert!(!record.timestamp.raw_text.is_empty());
    }

    // Classification still works; only cross-source ordering is withheld.
    assert_eq!(capture.totals.company_portal_records, 2);
    assert_eq!(
        capture.ordering.confidence,
        PortalOrderingConfidence::CaptureLocalOnly
    );
    assert_eq!(capture.ordering.records_without_offset, 3);
    assert!(!capture.is_cross_source_comparable());
}

#[test]
fn item09_fully_offset_capture_is_cross_source_comparable() {
    let capture = parse_console_export(SUPPORTED_BASELINE);

    assert_eq!(
        capture.ordering.confidence,
        PortalOrderingConfidence::CrossSourceComparable
    );
    assert_eq!(capture.ordering.records_without_offset, 0);
    assert!(capture.is_cross_source_comparable());

    let first = record_at(&capture, 0);
    assert_eq!(first.timestamp.kind, PortalTimestampKind::Offset);
    assert_eq!(
        first.timestamp.normalized_utc.as_deref(),
        Some("2024-03-15T17:00:00.123456Z")
    );
}

#[test]
fn item09_a_single_zoneless_record_downgrades_the_whole_capture() {
    let export = "\
Timestamp                       Thread     Type        Activity             PID    TTL
2024-03-15 10:00:00.000001-0700 0x1a2b3    Default     0x0                  312    0    CompanyPortal: (Sync) [com.microsoft.CompanyPortal:Sync] With offset
2024-03-15 10:00:01.000002 0x1a2b3    Default     0x0                  312    0    CompanyPortal: (Sync) [com.microsoft.CompanyPortal:Sync] Without offset
";
    let capture = parse_console_export(export);

    assert_eq!(
        capture.ordering.confidence,
        PortalOrderingConfidence::CaptureLocalOnly
    );
    assert_eq!(capture.ordering.records_without_offset, 1);
}

#[test]
fn item09_zero_offset_is_reported_as_utc() {
    let export = "\
Timestamp                       Thread     Type        Activity             PID    TTL
2024-03-15 10:00:00.000001+0000 0x1a2b3    Default     0x0                  312    0    CompanyPortal: (Sync) [com.microsoft.CompanyPortal:Sync] Zero offset
";
    let capture = parse_console_export(export);
    let record = record_at(&capture, 0);

    assert_eq!(record.timestamp.kind, PortalTimestampKind::Utc);
    assert_eq!(
        record.timestamp.normalized_utc.as_deref(),
        Some("2024-03-15T10:00:00.000001Z")
    );
}

// ---------------------------------------------------------------------------
// Item 10 - unknown app / OS version
// ---------------------------------------------------------------------------

#[test]
fn item10_version_banner_is_recovered_and_lifts_semantic_confidence() {
    let capture = parse_console_export(KNOWN_APP_VERSION);

    assert_eq!(capture.versions.state, PortalConsoleVersionState::Known);
    assert_eq!(
        capture.versions.company_portal_version.as_deref(),
        Some("5.2403.1")
    );
    assert_eq!(capture.versions.os_version.as_deref(), Some("iOS 17.4"));
    assert_eq!(
        capture
            .versions
            .evidence
            .as_ref()
            .expect("version evidence must be recorded")
            .evidence_id,
        "ios-console-record-000000"
    );

    let enrollment = record_at(&capture, 1);
    let semantic = enrollment
        .semantic
        .as_ref()
        .expect("enrollment record must carry semantic evidence");
    assert_eq!(semantic.confidence, PortalConsoleConfidence::High);
}

#[test]
fn item10_unknown_version_degrades_to_low_confidence_without_inventing_one() {
    let capture = parse_console_export(UNKNOWN_APP_VERSION);

    assert_eq!(capture.versions.state, PortalConsoleVersionState::Unknown);
    assert_eq!(capture.versions.company_portal_version, None);
    assert_eq!(capture.versions.os_version, None);
    assert_eq!(capture.versions.evidence, None);

    // The records still parse and still classify.
    assert_eq!(capture.totals.company_portal_records, 3);

    let enrollment = record_at(&capture, 1);
    let semantic = enrollment
        .semantic
        .as_ref()
        .expect("enrollment record must carry semantic evidence");
    assert_eq!(
        semantic.category,
        PortalConsoleSemanticCategory::EnrollmentProfile
    );
    assert_eq!(semantic.confidence, PortalConsoleConfidence::Low);
}

#[test]
fn item10_version_banner_requires_the_company_portal_diagnostics_anchor() {
    // The same banner text emitted by an unrelated process proves nothing.
    let export = "\
Timestamp                       Thread     Type        Activity             PID    TTL
2024-03-15 10:00:00.000001-0700 0x2001     Default     0x0                  60     0    dasd: (Sched) [com.apple.duetactivityscheduler:Diagnostics] Company Portal 5.2403.1 (2403001) starting on iOS 17.4
";
    let capture = parse_console_export(export);

    assert_eq!(capture.versions.state, PortalConsoleVersionState::Unknown);
}

// ---------------------------------------------------------------------------
// Item 11 - negatives and conservative degradation
// ---------------------------------------------------------------------------

#[test]
fn item11_arbitrary_plain_log_is_rejected() {
    let detection = detect_console_export(ARBITRARY_PLAIN_LOG);
    assert_eq!(
        detection.outcome,
        PortalConsoleDetectionOutcome::NotConsoleExport
    );
    assert_eq!(detection.layout, None);

    let capture = parse_console_export(ARBITRARY_PLAIN_LOG);
    assert_eq!(capture.totals.total_records, 0);
    assert_eq!(capture.totals.company_portal_records, 0);
    assert_eq!(
        capture.ordering.confidence,
        PortalOrderingConfidence::Unordered
    );
}

#[test]
fn item11_empty_and_whitespace_input_is_rejected() {
    for input in ["", "\n\n   \n"] {
        let capture = parse_console_export(input);
        assert_eq!(
            capture.detection.outcome,
            PortalConsoleDetectionOutcome::NotConsoleExport,
            "input {input:?} must not be claimed"
        );
        assert!(capture.records.is_empty());
    }
}

#[test]
fn item11_header_with_no_records_is_rejected() {
    let export =
        "Timestamp                       Thread     Type        Activity             PID    TTL\n";
    let detection = detect_console_export(export);
    assert_eq!(
        detection.outcome,
        PortalConsoleDetectionOutcome::NotConsoleExport
    );
}

#[test]
fn item11_unregistered_header_fails_conservatively_without_guessing_columns() {
    let capture = parse_console_export(UNREGISTERED_HEADER);

    assert_eq!(
        capture.detection.outcome,
        PortalConsoleDetectionOutcome::UnsupportedLayout
    );
    assert!(capture.detection.reason.contains("Fabricated"));
    assert_eq!(capture.layout, None);

    // Records are still framed and preserved, but no column is interpreted and nothing is
    // claimed as Company Portal evidence.
    assert_eq!(capture.totals.total_records, 2);
    assert_eq!(capture.totals.company_portal_records, 0);
    assert_eq!(capture.totals.unattributed_records, 2);
    for record in &capture.records {
        assert_eq!(record.parse_state, PortalConsoleParseState::Unsupported);
        assert_eq!(record.source.process, None);
        assert_eq!(record.source.subsystem, None);
        assert!(record.raw_text.contains("CompanyPortal"));
    }

    assert!(capture
        .coverage
        .iter()
        .any(|entry| entry.kind == PortalConsoleCoverageKind::UnsupportedLayout));
    assert!(!capture
        .coverage
        .iter()
        .any(|entry| entry.kind == PortalConsoleCoverageKind::HeaderMissing));
}

#[test]
fn item11_known_titles_in_an_unregistered_order_are_also_refused() {
    let capture = parse_console_export(UNREGISTERED_SEQUENCE);

    assert_eq!(
        capture.detection.outcome,
        PortalConsoleDetectionOutcome::UnsupportedLayout
    );
    assert!(capture.detection.reason.contains("not a registered layout"));
    assert_eq!(capture.totals.company_portal_records, 0);
}

#[test]
fn item11_headerless_console_records_degrade_to_generic_records() {
    let capture = parse_console_export(HEADERLESS_RECORDS);

    // Console-shaped, so not rejected outright, but never reported as a confirmed layout.
    assert_eq!(
        capture.detection.outcome,
        PortalConsoleDetectionOutcome::UnsupportedLayout
    );
    assert!(capture
        .coverage
        .iter()
        .any(|entry| entry.kind == PortalConsoleCoverageKind::HeaderMissing));

    assert_eq!(capture.totals.total_records, 3);
    assert_eq!(capture.totals.company_portal_records, 2);
    assert_eq!(
        capture
            .layout
            .as_ref()
            .map(|layout| layout.layout_id.as_str()),
        Some("console-plaintext-v1")
    );
}

// ---------------------------------------------------------------------------
// Item 12 - privacy
// ---------------------------------------------------------------------------

#[test]
fn item12_redaction_covers_every_sensitive_class() {
    let capture = parse_console_export(PRIVACY_PAYLOAD);
    assert_eq!(capture.totals.company_portal_records, 7);

    let redacted = redacted_export_projection(&capture);
    let all_text: String = redacted
        .records
        .iter()
        .map(|record| format!("{}\n{}\n", record.message.value, record.raw_text))
        .collect();

    // Nothing sensitive survives.
    for leaked in [
        "alex.taylor@contoso.example",
        "8f3c2a10-4b5d-4e6f-9a70-1c2d3e4f5a6b",
        "1a2b3c4d-5e6f-4071-8293-a4b5c6d7e8f9",
        "99887766-5544-4332-9110-aabbccddeeff",
        "https://manage.example.test",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
        "AA:BB:CC:DD:EE:FF",
        "MIIBsyntheticCertificateBodyForFixtureUseOnly",
        "com.contoso.expenses",
        "com.contoso.fieldservice",
    ] {
        assert!(
            !all_text.contains(leaked),
            "redacted export still contains {leaked}"
        );
    }

    // Each class produced its own stable token.
    for token in [
        REDACTED_EMAIL,
        REDACTED_URL,
        REDACTED_TOKEN,
        REDACTED_CERTIFICATE,
        REDACTED_TENANT_ID,
        REDACTED_DEVICE_ID,
        REDACTED_GUID,
        REDACTED_APP_ID,
    ] {
        assert!(
            all_text.contains(token),
            "redacted export never produced {token}"
        );
    }
}

#[test]
fn item12_structural_attribution_survives_redaction() {
    let capture = parse_console_export(PRIVACY_PAYLOAD);
    let redacted = redacted_export_projection(&capture);

    // The filtering decision must stay auditable after export.
    assert_eq!(
        redacted.totals.company_portal_records,
        capture.totals.company_portal_records
    );
    for (before, after) in capture.records.iter().zip(redacted.records.iter()) {
        assert_eq!(before.source.class, after.source.class);
        assert_eq!(before.source.signature, after.source.signature);
        assert_eq!(before.source.process, after.source.process);
        assert_eq!(before.source.subsystem, after.source.subsystem);
        assert_eq!(before.source.category, after.source.category);
        assert_eq!(before.reference, after.reference);
        assert_eq!(before.timestamp, after.timestamp);
    }

    // Company Portal's own namespace is deliberately preserved; it is the signature.
    assert!(redacted
        .records
        .iter()
        .any(|record| record.raw_text.contains("com.microsoft.CompanyPortal")));
}

#[test]
fn item12_redaction_is_idempotent() {
    let capture = parse_console_export(PRIVACY_PAYLOAD);
    let once = redacted_export_projection(&capture);
    let twice = redacted_export_projection(&once);

    assert_eq!(once, twice, "redaction must be a fixed point");
}

// ---------------------------------------------------------------------------
// Item 13 - deterministic filtering and export
// ---------------------------------------------------------------------------

#[test]
fn item13_parsing_and_redaction_are_deterministic_across_every_fixture() {
    for (name, content) in ALL_FIXTURES {
        let first = parse_console_export(content);
        let second = parse_console_export(content);
        assert_eq!(first, second, "parse of {name} is not deterministic");

        let first_json =
            serde_json::to_string(&redacted_export_projection(&first)).expect("serializable");
        let second_json =
            serde_json::to_string(&redacted_export_projection(&second)).expect("serializable");
        assert_eq!(
            first_json, second_json,
            "redacted export of {name} is not byte-stable"
        );
    }
}

#[test]
fn item13_filtering_is_stable_and_order_preserving() {
    let capture = parse_console_export(UNRELATED_PROCESS_NOISE);

    let first: Vec<usize> = capture
        .company_portal_records()
        .iter()
        .map(|record| record.reference.record_index)
        .collect();
    let second: Vec<usize> = capture
        .company_portal_records()
        .iter()
        .map(|record| record.reference.record_index)
        .collect();

    assert_eq!(first, second);
    assert_eq!(first, vec![4]);

    // The two subsets partition the parsed records exactly.
    assert_eq!(
        capture.company_portal_records().len() + capture.other_process_records().len(),
        capture.totals.total_records
    );

    let others: Vec<usize> = capture
        .other_process_records()
        .iter()
        .map(|record| record.reference.record_index)
        .collect();
    assert_eq!(others, vec![0, 1, 2, 3]);
}

#[test]
fn item13_capture_round_trips_through_json() {
    for (name, content) in ALL_FIXTURES {
        let capture = parse_console_export(content);
        let encoded = serde_json::to_string(&capture).expect("capture must serialize");
        let decoded: PortalConsoleCapture =
            serde_json::from_str(&encoded).expect("capture must deserialize");
        assert_eq!(capture, decoded, "{name} did not round-trip");
    }
}

#[test]
fn item13_no_input_line_is_ever_silently_dropped() {
    for (name, content) in ALL_FIXTURES {
        let capture = parse_console_export(content);
        if capture.detection.outcome == PortalConsoleDetectionOutcome::NotConsoleExport {
            continue;
        }

        let accounted: usize = capture
            .records
            .iter()
            .map(|record| record.raw_text.lines().count())
            .sum::<usize>()
            + capture
                .coverage
                .iter()
                .filter(|entry| entry.kind == PortalConsoleCoverageKind::TruncatedLeading)
                .map(|entry| entry.raw_text.lines().count())
                .sum::<usize>();

        let non_empty_body = content
            .lines()
            .filter(|line| !line.trim().is_empty())
            .count()
            - usize::from(
                capture
                    .layout
                    .as_ref()
                    .is_some_and(|layout| !layout.header_raw.is_empty())
                    || capture.detection.outcome
                        == PortalConsoleDetectionOutcome::UnsupportedLayout
                        && capture.layout.is_none(),
            );

        assert_eq!(
            accounted, non_empty_body,
            "{name}: {accounted} accounted lines vs {non_empty_body} body lines"
        );
    }
}

// ---------------------------------------------------------------------------
// Semantic evidence: only fixture-proven categories
// ---------------------------------------------------------------------------

#[test]
fn semantic_evidence_covers_only_proven_categories() {
    let capture = parse_console_export(SEVERITY_COVERAGE);

    let categories: Vec<Option<PortalConsoleSemanticCategory>> = capture
        .records
        .iter()
        .map(|record| record.semantic.as_ref().map(|evidence| evidence.category))
        .collect();

    assert_eq!(
        categories,
        vec![
            Some(PortalConsoleSemanticCategory::NetworkService),
            Some(PortalConsoleSemanticCategory::NetworkService),
            Some(PortalConsoleSemanticCategory::SyncCompliance),
            Some(PortalConsoleSemanticCategory::SyncCompliance),
            Some(PortalConsoleSemanticCategory::AppDeviceAction),
        ]
    );
}

#[test]
fn semantic_evidence_is_withheld_for_unmapped_categories() {
    let export = "\
Timestamp                       Thread     Type        Activity             PID    TTL
2024-03-15 10:00:00.000001-0700 0x1a2b3    Default     0x0                  312    0    CompanyPortal: (Kit) [com.microsoft.CompanyPortal:SomethingNew] An unmapped category stays ordinary
";
    let capture = parse_console_export(export);
    let record = record_at(&capture, 0);

    assert_eq!(record.source.class, PortalConsoleSourceClass::CompanyPortal);
    assert_eq!(record.source.category.as_deref(), Some("SomethingNew"));
    assert_eq!(record.semantic, None);
}

#[test]
fn semantic_evidence_is_never_derived_for_unrelated_processes() {
    let capture = parse_console_export(UNRELATED_PROCESS_NOISE);

    for record in capture.other_process_records() {
        assert_eq!(
            record.semantic, None,
            "non-Company-Portal record must stay ordinary"
        );
    }
}

#[test]
fn semantic_evidence_records_the_token_that_proved_it() {
    let capture = parse_console_export(KNOWN_APP_VERSION);
    let auth = record_at(&capture, 2);

    let semantic = auth.semantic.as_ref().expect("semantic evidence expected");
    assert_eq!(semantic.category, PortalConsoleSemanticCategory::SignInAuth);
    assert_eq!(semantic.matched_category_token, "Authentication");
}
