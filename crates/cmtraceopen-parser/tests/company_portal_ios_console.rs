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

const CONSOLE_HEADER: &str =
    "Timestamp                       Thread     Type        Activity             PID    TTL";
const CONSOLE_RECORD_PREFIX: &str = "0x1a2b3    Default     0x0                  312    0    \
     CompanyPortal: (Diagnostics) [com.microsoft.CompanyPortal:Diagnostics] ";

/// Build a supported Console export carrying one Company Portal record per entry of
/// `messages`, then return the concatenated *redacted* message and raw text.
///
/// One message per record matters for the secret rules, whose value deliberately runs to the
/// end of its line: putting two labels on one line would let the first swallow the second and
/// hide whether the second rule works at all.
fn redacted_console_text(messages: &[&str]) -> String {
    let mut export = String::from(CONSOLE_HEADER);
    export.push('\n');
    for (index, message) in messages.iter().enumerate() {
        export.push_str(&format!(
            "2024-03-15 10:00:{index:02}.000001-0700 {CONSOLE_RECORD_PREFIX}{message}\n"
        ));
    }

    let capture = parse_console_export(&export);
    assert_eq!(
        capture.detection.outcome,
        PortalConsoleDetectionOutcome::Supported,
        "helper fixture must parse as a supported export"
    );
    assert_eq!(
        capture.totals.company_portal_records,
        messages.len(),
        "helper fixture must yield one Company Portal record per message"
    );

    let redacted = redacted_export_projection(&capture);
    redacted
        .records
        .iter()
        .map(|record| format!("{}\n{}\n", record.message.value, record.raw_text))
        .collect()
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
            .all(|instant| *instant == Some("2024-03-15T19:00:00.500000000Z")),
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
    // Three, not two: the blank line is itself folded into the record, so the count has to
    // include it. `continuation_line_count` reports the lines folded into `raw_text`, and a
    // count that skipped the blank would disagree with the text and the span that carry it.
    assert_eq!(record.continuation_line_count, 3);
    assert!(message_of(record).contains("second payload line after a blank"));
    assert!(
        message_of(record).contains("first payload line\n\n\tsecond payload line"),
        "the blank line inside the payload was not preserved: {:?}",
        message_of(record)
    );
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

#[test]
fn item07_a_timestamp_column_that_was_never_examined_reports_unknown_not_invalid() {
    // `Invalid` is a verdict: the timestamp column was read and rejected. It must not be
    // reported for a record abandoned before the column was ever looked at, and
    // `PortalTimestamp::raw_text` must never carry a whole record line.

    // (1) Unsupported layout: columns are not interpreted at all.
    let unsupported = parse_console_export(UNREGISTERED_HEADER);
    assert!(!unsupported.records.is_empty());
    for record in &unsupported.records {
        assert_eq!(record.parse_state, PortalConsoleParseState::Unsupported);
        assert_eq!(
            record.timestamp.kind,
            PortalTimestampKind::Unknown,
            "no column was interpreted, so the timestamp was never examined"
        );
        assert_eq!(
            record.timestamp.raw_text, "",
            "timestamp raw_text must not hold the whole record line: {:?}",
            record.timestamp.raw_text
        );
        assert_eq!(record.timestamp.normalized_utc, None);
        // The untouched line is still preserved on the record itself.
        assert!(record.raw_text.contains("CompanyPortal"));
    }

    // (2) Column extraction failed before the timestamp was validated.
    let malformed = parse_console_export(MALFORMED_RECORDS);
    let bad_column = record_at(&malformed, 2);
    assert_eq!(bad_column.parse_state, PortalConsoleParseState::Malformed);
    assert!(bad_column.raw_text.contains("non-numeric PID column"));
    assert_eq!(
        bad_column.timestamp.kind,
        PortalTimestampKind::Unknown,
        "extraction failed on the PID column, so the timestamp verdict is unknown"
    );
    assert_eq!(
        bad_column.timestamp.raw_text, "",
        "timestamp raw_text must not hold the whole record line: {:?}",
        bad_column.timestamp.raw_text
    );

    // (3) Contrast: the column *was* examined and rejected, so `Invalid` stays, and
    // `raw_text` carries the offending timestamp text and nothing else.
    let bad_timestamp = record_at(&malformed, 1);
    assert_eq!(bad_timestamp.timestamp.kind, PortalTimestampKind::Invalid);
    assert_eq!(
        bad_timestamp.timestamp.raw_text,
        "2024-13-45 99:99:99.000002-0700"
    );
    assert_eq!(bad_timestamp.timestamp.normalized_utc, None);
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
        Some("2024-03-15T11:00:00.123456000Z")
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

/// The shipped v2 fixture row, and the same row with exactly one attribution cell blanked.
/// Every other byte and column offset is identical, so these differ from a good row only in
/// the way a real empty cell would.
const V2_HEADER: &str = "Timestamp                       Thread     Type        Activity             PID    TTL  Subsystem                    Category";
const V2_EMPTY_SUBSYSTEM: &str = "2024-03-15 13:00:00.000001-0700 0x4001     Default     0x0                  312    0                                 Enrollment  CompanyPortal: (Enrollment) Profile installation requested";
const V2_EMPTY_CATEGORY: &str = "2024-03-15 13:00:00.000001-0700 0x4001     Default     0x0                  312    0    com.microsoft.CompanyPortal              CompanyPortal: (Enrollment) Profile installation requested";

#[test]
fn item08_an_empty_v2_attribution_cell_fails_closed_instead_of_shifting_columns() {
    // Console pads these cells with spaces, so to a `^\S+` tokenizer an empty cell is
    // indistinguishable from padding and the column silently takes the *next* column's value.
    // The record then carried another column's data in a named field and was still reported
    // as `Parsed`. An empty Subsystem also moved a Company Portal record to `OtherProcess`,
    // an attribution error in the very field that structural filtering depends on.
    //
    // The parser cannot delimit these cells (see the overflow test below for why fixed-width
    // slicing is not available), so the honest outcome is a visible parse failure.
    for (name, row) in [
        ("empty subsystem", V2_EMPTY_SUBSYSTEM),
        ("empty category", V2_EMPTY_CATEGORY),
    ] {
        let export = format!("{V2_HEADER}\n{row}\n");
        let capture = parse_console_export(&export);
        let record = record_at(&capture, 0);

        assert_eq!(
            record.parse_state,
            PortalConsoleParseState::Malformed,
            "{name}: an undelimitable cell must fail closed, not parse to shifted values"
        );
        // Nothing is guessed and nothing is attributed.
        assert_eq!(record.source.subsystem, None, "{name}");
        assert_eq!(record.source.category, None, "{name}");
        assert_eq!(
            record.source.class,
            PortalConsoleSourceClass::Unattributed,
            "{name}"
        );
        assert_eq!(capture.totals.company_portal_records, 0, "{name}");

        // The input survives verbatim and is accounted for rather than dropped.
        assert_eq!(record.raw_text, row, "{name}");
        assert!(
            capture
                .coverage
                .iter()
                .any(|entry| entry.kind == PortalConsoleCoverageKind::MalformedRecord),
            "{name}: the malformed record must be visible in coverage"
        );
    }
}

#[test]
fn item08_a_subsystem_that_overflows_its_cell_still_parses() {
    // The shipped fixture's third row carries a 30-character subsystem in a 29-character
    // cell, so Console lets it overflow and every later column shifts right. That is why the
    // columns cannot be sliced at header-derived fixed-width boundaries, and it is the case
    // the empty-cell guard must not cost anything.
    let capture = parse_console_export(SUBSYSTEM_COLUMNS);

    assert!(
        capture
            .records
            .iter()
            .all(|record| record.parse_state == PortalConsoleParseState::Parsed),
        "the shipped v2 fixture must still parse cleanly"
    );
    let overflowing = record_at(&capture, 2);
    assert_eq!(
        overflowing.source.subsystem.as_deref(),
        Some("com.apple.ManagedConfiguration")
    );
    assert_eq!(overflowing.source.category.as_deref(), Some("profiled"));
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
        Some("2024-03-15T17:00:00.123456000Z")
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
        Some("2024-03-15T10:00:00.000001000Z")
    );
}

#[test]
fn item09_sub_microsecond_precision_is_not_rounded_away_by_normalization() {
    // Console can emit up to nanosecond precision and the timestamp grammar accepts it, so
    // `normalized_utc` must denote the same instant as `raw_text` rather than a rounded one.
    let export = "\
Timestamp                       Thread     Type        Activity             PID    TTL
2024-03-15 10:00:00.123456789-0700 0x1a2b3    Default     0x0                  312    0    CompanyPortal: (Sync) [com.microsoft.CompanyPortal:Sync] Nanosecond precision
2024-03-15 10:00:01.1234567-0700 0x1a2b3    Default     0x0                  312    0    CompanyPortal: (Sync) [com.microsoft.CompanyPortal:Sync] Seven fractional digits
";
    let capture = parse_console_export(export);

    let nanos = record_at(&capture, 0);
    assert_eq!(nanos.parse_state, PortalConsoleParseState::Parsed);
    assert_eq!(nanos.timestamp.kind, PortalTimestampKind::Offset);
    assert_eq!(
        nanos.timestamp.raw_text,
        "2024-03-15 10:00:00.123456789-0700"
    );
    assert_eq!(
        nanos.timestamp.normalized_utc.as_deref(),
        Some("2024-03-15T17:00:00.123456789Z"),
        "the .789 nanoseconds present in raw_text must survive UTC normalization"
    );

    // A 7-digit fraction is likewise carried whole, padded to the fixed nanosecond width.
    let seven = record_at(&capture, 1);
    assert_eq!(seven.parse_state, PortalConsoleParseState::Parsed);
    assert_eq!(
        seven.timestamp.normalized_utc.as_deref(),
        Some("2024-03-15T17:00:01.123456700Z")
    );

    // Fixed-width rendering keeps byte order agreeing with instant order.
    let mut rendered: Vec<&str> = capture
        .records
        .iter()
        .filter_map(|record| record.timestamp.normalized_utc.as_deref())
        .collect();
    let source_order = rendered.clone();
    rendered.sort_unstable();
    assert_eq!(rendered, source_order);
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
fn item11_a_header_whose_first_column_is_not_a_timestamp_is_not_a_console_export() {
    // `Process` resolves to a real column role, so the first title alone does not reject the
    // line. The unknown second title then short-circuited to `Unregistered` before the
    // Timestamp-first rule was ever reached, so an ordinary process table was reported as a
    // Console export with an unsupported layout instead of as unrelated text.
    let content = "\
Process        Owner          Path
launchd        root           /sbin/launchd
loginwindow    adam           /System/Library/CoreServices/loginwindow.app
";

    let detection = detect_console_export(content);
    assert_eq!(
        detection.outcome,
        PortalConsoleDetectionOutcome::NotConsoleExport,
        "unrelated text must not be diagnosed as an unsupported Console layout; reason was {:?}",
        detection.reason
    );
    assert_eq!(detection.layout, None);
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
fn item11_unregistered_header_row_survives_in_its_coverage_entry() {
    // With no registered layout, `detection.layout` and `capture.layout` are both `None`, so
    // the `UnsupportedLayout` coverage entry is the only place the header row can survive.
    // Coverage is meant to be a visible, non-silent account of input; an empty `raw_text`
    // discards the one line that explains why the layout is unsupported.
    for (name, content) in [
        ("unregistered-header", UNREGISTERED_HEADER),
        ("unregistered-sequence", UNREGISTERED_SEQUENCE),
    ] {
        let capture = parse_console_export(content);
        assert_eq!(capture.layout, None, "{name}: layout must stay unresolved");

        let header = content
            .lines()
            .find(|line| !line.trim().is_empty())
            .expect("fixture has a header row");
        let entry = capture
            .coverage
            .iter()
            .find(|entry| entry.kind == PortalConsoleCoverageKind::UnsupportedLayout)
            .unwrap_or_else(|| panic!("{name}: expected an UnsupportedLayout coverage entry"));

        assert_eq!(
            entry.raw_text, header,
            "{name}: the unregistered header row was discarded"
        );

        // And it is redacted on export like any other raw text.
        let redacted = redacted_export_projection(&capture);
        let redacted_entry = redacted
            .coverage
            .iter()
            .find(|entry| entry.kind == PortalConsoleCoverageKind::UnsupportedLayout)
            .expect("coverage entry survives the redacted projection");
        assert!(
            !redacted_entry.raw_text.is_empty(),
            "{name}: redaction must not empty the preserved header"
        );
    }
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
fn item12_json_shaped_labels_are_redacted() {
    // A Console payload routinely carries a serialized JSON body verbatim, so the label
    // arrives as `"password":"hunter2"`. A rule that allows only whitespace between the label
    // and the separator stops at the closing quote and nothing else catches the bare secret.
    let text = redacted_console_text(&[
        r#"Auth state {"password":"hunter2"}"#,
        r#"Auth state {"access_token":"plainSecretValue123"}"#,
        "Auth state client_secret=abcDEF123",
        r#"Enrolled {"tenantId":"8f3c2a10-4b5d-4e6f-9a70-1c2d3e4f5a6b"}"#,
        r#"Enrolled {"deviceId":"1a2b3c4d-5e6f-4071-8293-a4b5c6d7e8f9"}"#,
    ]);

    for leaked in [
        "hunter2",
        "plainSecretValue123",
        "abcDEF123",
        "8f3c2a10-4b5d-4e6f-9a70-1c2d3e4f5a6b",
        "1a2b3c4d-5e6f-4071-8293-a4b5c6d7e8f9",
    ] {
        assert!(
            !text.contains(leaked),
            "JSON-shaped secret {leaked} survived redaction:\n{text}"
        );
    }

    assert!(
        text.contains(REDACTED_TOKEN),
        "no token placeholder:\n{text}"
    );
    assert!(
        text.contains(REDACTED_TENANT_ID),
        "no tenant placeholder:\n{text}"
    );
    assert!(
        text.contains(REDACTED_DEVICE_ID),
        "no device placeholder:\n{text}"
    );
}

#[test]
fn item12_keyed_secret_values_run_to_the_end_of_the_line() {
    // A whitespace-bounded value class redacts `my` and exports the rest of the passphrase.
    // For high-signal secret labels the value deliberately runs to end of line.
    let text = redacted_console_text(&[
        "Recovered password=my secret pass phrase from the keychain",
        "Recovered api_key=first second third",
    ]);

    for leaked in [
        "my secret pass phrase",
        "pass phrase",
        "from the keychain",
        "second third",
    ] {
        assert!(
            !text.contains(leaked),
            "keyed secret tail {leaked:?} survived redaction:\n{text}"
        );
    }
    assert!(
        text.contains(REDACTED_TOKEN),
        "no token placeholder:\n{text}"
    );
}

#[test]
fn item12_non_ascii_identities_are_redacted() {
    // An ASCII-only class does not truncate a non-ASCII identity, it misses it entirely:
    // with an accented leading character there is no word boundary for a leading `\b` to
    // anchor on, and `Zoe`-with-diaeresis leaks the given name ahead of the matched tail.
    let text = redacted_console_text(&[
        "Signing in as m\u{fc}ller@contoso.example",
        "Signing in as Zo\u{eb}.Chen@contoso.example",
    ]);

    for leaked in [
        "m\u{fc}ller",
        "Zo\u{eb}",
        ".Chen",
        "@contoso.example",
        "contoso.example",
    ] {
        assert!(
            !text.contains(leaked),
            "non-ASCII identity fragment {leaked:?} survived redaction:\n{text}"
        );
    }
    assert!(
        text.contains(REDACTED_EMAIL),
        "no email placeholder:\n{text}"
    );
}

#[test]
fn item12_network_addresses_are_redacted() {
    let text = redacted_console_text(&[
        "Reached service at 10.20.30.40 after retry",
        "Interface hardware address AA:BB:CC:DD:EE:FF is up",
        "Reached service at 2001:0db8:85a3:0000:0000:8a2e:0370:7334 after retry",
        "Reached service at fe80::1c2d:3e4f:5a6b after retry",
    ]);

    for leaked in [
        "10.20.30.40",
        "AA:BB:CC:DD:EE:FF",
        "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        "0370:7334",
        "fe80::1c2d:3e4f:5a6b",
        "1c2d:3e4f:5a6b",
    ] {
        assert!(
            !text.contains(leaked),
            "network address {leaked} survived redaction:\n{text}"
        );
    }
    assert!(
        text.contains(REDACTED_ADDRESS),
        "no address placeholder:\n{text}"
    );
}

#[test]
fn item12_compressed_ipv6_addresses_are_redacted() {
    // A `\b` anchor needs a word character on one side, and every `::`-compressed form either
    // begins or ends with a colon, so the rule that exists to stop an address leak was the
    // rule that leaked. Bracketed, port-suffixed and IPv4-mapped forms are all real Console
    // shapes.
    let text = redacted_console_text(&[
        "Bound loopback ::1 for the retry probe",
        "Bound loopback [::1] for the retry probe",
        "Link-local prefix fe80:: is configured",
        "Unspecified address :: is configured",
        "peer ::1 connected",
        "Dialing [fe80::1]:8080 for the retry probe",
        "Mapped ::ffff:192.0.2.1 for the retry probe",
    ]);

    for leaked in [
        "::1",
        "[::1]",
        "fe80::",
        "::ffff",
        "192.0.2.1",
        "address :: is",
    ] {
        assert!(
            !text.contains(leaked),
            "compressed IPv6 form {leaked:?} survived redaction:\n{text}"
        );
    }
    assert!(
        text.contains(REDACTED_ADDRESS),
        "no address placeholder:\n{text}"
    );

    // The surrounding text is evidence and must survive intact, including the delimiters that
    // bounded the address.
    for preserved in ["peer ", " connected", "for the retry probe", ":8080"] {
        assert!(
            text.contains(preserved),
            "text around the address {preserved:?} was consumed:\n{text}"
        );
    }
}

#[test]
fn item12_colon_separated_text_is_not_mistaken_for_an_ipv6_address() {
    // The inverse failure of the `\b` anchoring: a word boundary *does* exist between an
    // identifier character and a colon, so C++ scope resolution matched the rule that real
    // addresses missed. Backtraces are the main reason a Console capture is collected, so
    // eating their symbol names would destroy the evidence.
    let text = redacted_console_text(&[
        "Frame std::__1::basic_string in the backtrace",
        "Symbol std::cout resolved during startup",
        "Retry budget 3:2 with key:value pairs",
        "Elapsed 10:00:00 since the first attempt",
    ]);

    for preserved in [
        "std::__1::basic_string",
        "std::cout",
        "3:2",
        "key:value",
        "10:00:00",
    ] {
        assert!(
            text.contains(preserved),
            "ordinary colon-separated text {preserved:?} was redacted as an address:\n{text}"
        );
    }
    assert!(
        !text.contains(REDACTED_ADDRESS),
        "ordinary colon-separated text was reported as an address:\n{text}"
    );
}

#[test]
fn item12_dotted_version_strings_are_not_mistaken_for_addresses() {
    // Console payloads are full of dotted version numbers. Bounding each IPv4 octet to 0-255
    // is what keeps a four-part build number out of the address matcher; an unbounded
    // dotted-quad would redact the very evidence the capture exists to carry.
    let text = redacted_console_text(&[
        "Company Portal 5.2504.0.1234 starting on iOS 17.4 build 21E236",
        "Library versions 1.900.3.7 and 2.1000.0.0 loaded",
    ]);

    for preserved in ["5.2504.0.1234", "17.4", "21E236", "1.900.3.7", "2.1000.0.0"] {
        assert!(
            text.contains(preserved),
            "version string {preserved} was swallowed by an address matcher:\n{text}"
        );
    }
    assert!(
        !text.contains(REDACTED_ADDRESS),
        "a version string was reported as an address:\n{text}"
    );
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
fn item13_raw_text_reproduces_every_source_line_the_record_spans() {
    // `PortalConsoleRecord::raw_text` is documented as the record's source text verbatim, and
    // the record's span claims every line from `first_line_number` to `last_line_number`. A
    // blank line inside a folded payload was dropped from `raw_text` while the span still
    // covered it, so the two fields disagreed about the same source region and a JSON body or
    // backtrace containing an empty line could not be reconstructed from the field that
    // promises to carry it.
    let export = format!(
        "{CONSOLE_HEADER}\n\
         2024-03-15 10:00:00.000001-0700 {CONSOLE_RECORD_PREFIX}Response body follows\n\
         \t{{\n\
         \n\
         \t  \"status\": \"failed\"\n\
         \t}}\n"
    );

    let capture = parse_console_export(&export);
    let lines: Vec<&str> = export.lines().collect();
    assert_eq!(capture.records.len(), 1, "fixture must yield one record");

    for record in &capture.records {
        let first = record.reference.first_line_number;
        let last = record.reference.last_line_number;
        assert_eq!(
            record.raw_text,
            lines[first - 1..last].join("\n"),
            "raw_text must reproduce source lines {first}..={last} verbatim"
        );
    }

    assert!(
        capture.records[0].raw_text.contains("\n\n"),
        "the blank line inside the folded payload was dropped: {:?}",
        capture.records[0].raw_text
    );
    assert!(
        capture.records[0].message.value.contains("\n\n"),
        "the blank line is missing from the folded message: {:?}",
        capture.records[0].message.value
    );
}

#[test]
fn item13_trailing_blank_lines_are_not_folded_into_the_last_record() {
    // A blank line is payload only when payload follows it. Padding at the end of the copy
    // must not extend the last record's span or its continuation count.
    let export = format!(
        "{CONSOLE_HEADER}\n\
         2024-03-15 10:00:00.000001-0700 {CONSOLE_RECORD_PREFIX}Single line record\n\
         \n\
         \n"
    );

    let capture = parse_console_export(&export);
    let record = record_at(&capture, 0);

    assert_eq!(record.continuation_line_count, 0);
    assert_eq!(record.reference.first_line_number, 2);
    assert_eq!(record.reference.last_line_number, 2);
    assert!(
        !record.raw_text.ends_with('\n'),
        "trailing padding was folded into the record: {:?}",
        record.raw_text
    );
}

#[test]
fn item13_no_input_line_is_ever_silently_dropped() {
    for (name, content) in ALL_FIXTURES {
        let capture = parse_console_export(content);
        if capture.detection.outcome == PortalConsoleDetectionOutcome::NotConsoleExport {
            continue;
        }

        // The header row is not a record, but it is input, so it has to be *found* somewhere
        // rather than excused: verbatim in the resolved layout when the layout is registered,
        // and verbatim in the `UnsupportedLayout` coverage entry when it is not. Coverage of
        // any other kind is deliberately excluded because it restates a record's own text.
        let header_text: String = match &capture.layout {
            Some(layout) => layout.header_raw.clone(),
            None => capture
                .coverage
                .iter()
                .filter(|entry| entry.kind == PortalConsoleCoverageKind::UnsupportedLayout)
                .map(|entry| entry.raw_text.as_str())
                .collect(),
        };

        if let Some(header) = content.lines().find(|line| !line.trim().is_empty()) {
            if capture.layout.is_none() {
                assert_eq!(
                    header_text, header,
                    "{name}: the unregistered header row was discarded instead of preserved"
                );
            }
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
                .sum::<usize>()
            + header_text.lines().count();

        let non_empty_body = content
            .lines()
            .filter(|line| !line.trim().is_empty())
            .count();

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
