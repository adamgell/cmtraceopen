//! Focused contract tests for `intune::portal::macos::company_portal::unified_log`.
//!
//! Every fixture under
//! `tests/fixtures/intune/portal/macos/unified_log/<schema>/<scenario>/` is
//! synthetic. No real device, tenant, user, host, or capture data appears here.
//!
//! The tests are ordered to follow the required fixture matrix of issue #370.

use std::collections::BTreeSet;

use cmtraceopen_parser::intune::portal::macos::company_portal::unified_log::*;
use serde_json::Value;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const SUPPORTED_NDJSON: &str =
    include_str!("fixtures/intune/portal/macos/unified_log/v1/supported-records/capture.ndjson");
const SUPPORTED_JSON: &str =
    include_str!("fixtures/intune/portal/macos/unified_log/v1/supported-records/capture.json");
const LEVELS: &str =
    include_str!("fixtures/intune/portal/macos/unified_log/v1/levels/capture.ndjson");
const ACTIVITY: &str =
    include_str!("fixtures/intune/portal/macos/unified_log/v1/activity-signpost/capture.ndjson");
const SENSITIVE: &str =
    include_str!("fixtures/intune/portal/macos/unified_log/v1/privacy-sensitive/capture.ndjson");
const METADATA_KNOWN: &str = include_str!(
    "fixtures/intune/portal/macos/unified_log/v1/capture-metadata/known-preset.ndjson"
);
const METADATA_CUSTOM: &str = include_str!(
    "fixtures/intune/portal/macos/unified_log/v1/capture-metadata/custom-predicate.ndjson"
);
const DUPLICATES: &str =
    include_str!("fixtures/intune/portal/macos/unified_log/v1/duplicate-sequence/capture.ndjson");
const DEGRADED_TIME: &str =
    include_str!("fixtures/intune/portal/macos/unified_log/v1/degraded-time/capture.ndjson");
const MALFORMED: &str =
    include_str!("fixtures/intune/portal/macos/unified_log/v1/malformed-json-line/capture.ndjson");
const FUTURE_VERSION: &str = include_str!(
    "fixtures/intune/portal/macos/unified_log/v2/unknown-schema-version/capture.ndjson"
);
const ALIEN_SCHEMA: &str = include_str!(
    "fixtures/intune/portal/macos/unified_log/unknown/unknown-schema-id/capture.ndjson"
);
const MISSING_HEADER: &str =
    include_str!("fixtures/intune/portal/macos/unified_log/unknown/missing-header/capture.ndjson");
const NEGATIVES: &str =
    include_str!("fixtures/intune/portal/macos/unified_log/v1/unrelated-source/capture.ndjson");
const MATCH_KEYS: &str =
    include_str!("fixtures/intune/portal/macos/unified_log/v1/direct-log-match-key/capture.ndjson");
const SAME_TIME: &str =
    include_str!("fixtures/intune/portal/macos/unified_log/v1/same-time-no-merge/capture.ndjson");
const CAPTURE_COVERAGE: &str =
    include_str!("fixtures/intune/portal/macos/unified_log/v1/capture-coverage/capture.ndjson");
const REDACTED_EXPORT: &str =
    include_str!("fixtures/intune/portal/macos/unified_log/v1/redacted-export/capture.ndjson");
const GOLDEN_CAPTURE: &str =
    include_str!("fixtures/intune/portal/macos/unified_log/v1/schema-golden/capture.ndjson");
const GOLDEN_EXPECTED: &str = include_str!(
    "fixtures/intune/portal/macos/unified_log/v1/schema-golden/expected-capture-set.json"
);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn coverage_with(
    reduction: &PortalUnifiedLogReduction,
    status: PortalCoverageStatus,
) -> Vec<&PortalCoverageEntry> {
    reduction
        .coverage
        .iter()
        .filter(|entry| entry.status == status)
        .collect()
}

fn set_coverage_with(
    capture_set: &PortalUnifiedLogCaptureSet,
    status: PortalCoverageStatus,
) -> Vec<&PortalCoverageEntry> {
    capture_set
        .coverage
        .iter()
        .filter(|entry| entry.status == status)
        .collect()
}

fn anchor(anchor_id: &str) -> PortalDirectLogAnchor {
    PortalDirectLogAnchor {
        anchor_id: anchor_id.to_string(),
        timestamp: PortalTimestamp::unspecified(),
        activity_id: None,
        signpost_id: None,
        request_id: None,
        correlation_id: None,
        documented_relationship_id: None,
    }
}

// ---------------------------------------------------------------------------
// 1. Supported normalized JSON/NDJSON records
// ---------------------------------------------------------------------------

#[test]
fn supported_records_parse_identically_from_ndjson_and_json() {
    let from_ndjson = parse_capture(SUPPORTED_NDJSON);
    let from_json = parse_capture(SUPPORTED_JSON);

    assert!(from_ndjson.supported);
    assert!(from_json.supported);
    assert_eq!(
        from_ndjson, from_json,
        "the two wire encodings of one capture must reduce to the same value"
    );

    assert_eq!(from_ndjson.records.len(), 3);
    assert_eq!(from_ndjson.stats.stream_lines, 3);
    assert_eq!(from_ndjson.stats.records_parsed, 3);
    assert_eq!(from_ndjson.stats.records_malformed, 0);

    let processes: Vec<&str> = from_ndjson
        .records
        .iter()
        .map(|r| r.process.as_str())
        .collect();
    assert_eq!(
        processes,
        ["CompanyPortal", "IntuneMdmAgent", "IntuneMdmDaemon"]
    );
    assert_eq!(
        from_ndjson.records[0].record_id, "ul-000000",
        "record ids are derived from stream position, so they are stable"
    );

    // The explicit encoding-specific entry points agree with auto-detection.
    assert_eq!(parse_capture_ndjson(SUPPORTED_NDJSON), from_ndjson);
    assert_eq!(parse_capture_json(SUPPORTED_JSON), from_json);

    let reduction = reduce_capture_set(from_ndjson);
    assert_eq!(reduction.evidence.len(), 3);
    assert_eq!(reduction.stats.records_selected, 3);
    assert!(
        coverage_with(&reduction, PortalCoverageStatus::NotSelected).is_empty(),
        "every verified record should be selected"
    );

    let kinds: Vec<&PortalUnifiedLogEvidenceKind> =
        reduction.evidence.iter().map(|e| &e.kind).collect();
    assert_eq!(
        kinds,
        [
            &PortalUnifiedLogEvidenceKind::ProcessStartup,
            &PortalUnifiedLogEvidenceKind::SyncCompliance,
            &PortalUnifiedLogEvidenceKind::EnrollmentProfile,
        ]
    );
    assert!(reduction
        .evidence
        .iter()
        .all(|e| e.confidence == PortalEvidenceConfidence::Exact));
}

// ---------------------------------------------------------------------------
// 2. Information / warning / error / debug levels
// ---------------------------------------------------------------------------

#[test]
fn levels_are_normalized_and_raw_message_type_is_preserved() {
    let reduction = reduce_capture_text(LEVELS);
    assert_eq!(reduction.evidence.len(), 7);

    let levels: Vec<&PortalUnifiedLogLevel> = reduction.evidence.iter().map(|e| &e.level).collect();
    assert_eq!(
        levels,
        [
            &PortalUnifiedLogLevel::Debug,
            &PortalUnifiedLogLevel::Info,
            &PortalUnifiedLogLevel::Default,
            &PortalUnifiedLogLevel::Warning,
            &PortalUnifiedLogLevel::Error,
            &PortalUnifiedLogLevel::Fault,
            &PortalUnifiedLogLevel::Unknown,
        ]
    );

    let capture_set = parse_capture(LEVELS);
    let raws: Vec<&str> = capture_set
        .records
        .iter()
        .map(|r| r.message_type.raw.as_str())
        .collect();
    assert_eq!(
        raws,
        [
            "Debug",
            "Info",
            "Default",
            "Warning",
            "Error",
            "Fault",
            "Emergency"
        ],
        "an unrecognised level normalizes to Unknown but its text is never lost"
    );

    assert_eq!(normalize_level("ERROR"), PortalUnifiedLogLevel::Error);
    assert_eq!(normalize_level("warn"), PortalUnifiedLogLevel::Warning);
    assert_eq!(normalize_level(""), PortalUnifiedLogLevel::Unknown);
}

// ---------------------------------------------------------------------------
// 3. Activity / signpost relationship
// ---------------------------------------------------------------------------

#[test]
fn activity_and_signpost_relationships_are_preserved() {
    let reduction = reduce_capture_text(ACTIVITY);

    assert_eq!(reduction.activities.len(), 2);
    let enrollment = &reduction.activities[0];
    assert_eq!(enrollment.activity_id, "0x1a2b");
    assert_eq!(enrollment.parent_activity_id.as_deref(), Some("0x0011"));
    assert_eq!(
        enrollment.record_ids,
        ["ul-000000", "ul-000001", "ul-000002", "ul-000003"],
        "activity members stay in exact source sequence"
    );
    assert_eq!(enrollment.signpost_ids, ["0x9f01"]);
    assert_eq!(enrollment.first_stream_index, 0);
    assert_eq!(enrollment.last_stream_index, 3);

    let sync = &reduction.activities[1];
    assert_eq!(sync.activity_id, "0x3c4d");
    assert_eq!(sync.record_ids, ["ul-000004"]);

    // Signpost begin/event/end ordering survives reduction.
    let capture_set = parse_capture(ACTIVITY);
    let signpost_types: Vec<Option<&str>> = capture_set
        .records
        .iter()
        .map(|r| r.activity.signpost_type.as_deref())
        .collect();
    assert_eq!(
        signpost_types,
        [
            Some("begin"),
            Some("event"),
            None,
            Some("end"),
            Some("begin")
        ]
    );

    // The helper record has an unverified subsystem; only the explicit shared
    // activity identifier brings it in, and that is recorded as the reason.
    let linked = &reduction.evidence[2];
    assert_eq!(linked.record_id, "ul-000002");
    assert_eq!(
        linked.selection.reason,
        PortalSelectionReason::ActivityLinkedToSelected
    );
    assert!(linked.selection.selected);
    assert_eq!(linked.confidence, PortalEvidenceConfidence::Strong);
    assert_eq!(
        linked.selection.predicate_version,
        PORTAL_UNIFIED_LOG_SELECTION_PREDICATE_VERSION
    );
}

// ---------------------------------------------------------------------------
// 4. Record with privacy-sensitive formatted values
// ---------------------------------------------------------------------------

#[test]
fn privacy_sensitive_values_are_classified_then_redacted() {
    let capture_set = parse_capture(SENSITIVE);
    let record = &capture_set.records[0];

    assert_eq!(
        record.event_message.sensitivity,
        PortalSensitivity::Sensitive
    );
    assert_eq!(
        record
            .process_image_path
            .as_ref()
            .map(|p| &p.sensitivity)
            .unwrap(),
        &PortalSensitivity::Sensitive
    );
    assert!(
        record.unknown_fields.contains_key("upn"),
        "fields the schema does not name are preserved losslessly"
    );

    let redacted = redacted_capture_projection(&capture_set);
    let message = &redacted.records[0].event_message.value;

    for secret in [
        "kai.rivera@contoso.example.com",
        "8f14e45f-ceea-467a-9f19-7a1b2c3d4e5f",
        "C02SYNTH0001",
        "eyJhbGciOiJIUzI1NiJ9",
        "login.microsoftonline.example",
        "AA:BB:CC:DD:EE:FF",
        "kai.rivera",
    ] {
        assert!(
            !message.contains(secret),
            "redacted message still leaks {secret}: {message}"
        );
    }

    for token in [
        "[redacted:identity]",
        "[redacted:guid]",
        "[redacted:serial]",
        "[redacted:token]",
        "[redacted:url]",
        "[redacted:certificate]",
        "[redacted:path]",
    ] {
        assert!(
            message.contains(token),
            "redacted message is missing the stable token {token}: {message}"
        );
    }

    assert_eq!(
        redacted.records[0]
            .process_image_path
            .as_ref()
            .unwrap()
            .value,
        "[redacted:path]"
    );
    assert_eq!(
        redacted.records[0].unknown_fields.get("upn"),
        Some(&Value::String("[redacted:identity]".to_string())),
        "a sensitive member name redacts its value even when the text carries no label"
    );
    assert!(!redacted.records[1]
        .event_message
        .value
        .contains("2d7f8a91-3b4c-4d5e-8f90-a1b2c3d4e5f6"));
}

// ---------------------------------------------------------------------------
// 5. Capture window / predicate metadata
// ---------------------------------------------------------------------------

#[test]
fn capture_predicate_and_window_are_provenance() {
    let known = parse_capture(METADATA_KNOWN);
    let capture = known.capture.as_ref().expect("capture metadata");

    assert_eq!(capture.schema_id, PORTAL_UNIFIED_LOG_SCHEMA_ID);
    assert_eq!(capture.schema_version, PORTAL_UNIFIED_LOG_SCHEMA_VERSION);
    assert_eq!(
        capture.predicate.predicate_id.as_deref(),
        Some(PORTAL_UNIFIED_LOG_CAPTURE_PREDICATE_ID)
    );
    assert_eq!(
        capture.predicate.predicate_text, PORTAL_UNIFIED_LOG_CAPTURE_PREDICATE,
        "the predicate is stored verbatim so a reduction is reproducible"
    );
    assert!(capture.predicate.matches_known_preset);
    assert_eq!(
        capture.selection_predicate_version,
        PORTAL_UNIFIED_LOG_SELECTION_PREDICATE_VERSION
    );

    let window = &capture.window;
    assert_eq!(
        window.start.as_ref().unwrap().normalized_utc.as_deref(),
        Some("2026-07-15T12:00:00.000000Z")
    );
    assert_eq!(
        window.end.as_ref().unwrap().original_offset.as_deref(),
        Some("-05:00")
    );
    assert_eq!(window.timezone_name.as_deref(), Some("America/Chicago"));
    assert_eq!(capture.host.os_build.as_deref(), Some("24F74"));
    assert_eq!(
        capture.host.company_portal_version.as_deref(),
        Some("5.2506.0")
    );
    assert_eq!(
        capture.collector.name.as_deref(),
        Some("cmtraceopen-macos-diag")
    );
    assert_eq!(
        capture.collected_at_utc.as_deref(),
        Some("2026-07-15T12:05:10Z")
    );

    // A capture taken with a different predicate is still reduced, but it is
    // never silently claimed to be the known preset.
    let custom = parse_capture(METADATA_CUSTOM);
    let custom_capture = custom.capture.as_ref().unwrap();
    assert!(!custom_capture.predicate.matches_known_preset);
    assert_eq!(
        custom_capture.predicate.predicate_text,
        r#"process == "CompanyPortal""#
    );
    assert_eq!(custom_capture.window.last.as_deref(), Some("1h"));
    assert!(custom_capture.window.start.is_none());
}

// ---------------------------------------------------------------------------
// 6. Duplicate / sequence ordering
// ---------------------------------------------------------------------------

#[test]
fn duplicate_sequences_are_coverage_and_source_order_is_exact() {
    let reduction = reduce_capture_text(DUPLICATES);

    let messages: Vec<&str> = reduction
        .evidence
        .iter()
        .map(|e| e.summary.value.as_str())
        .collect();
    assert_eq!(
        messages,
        [
            "third emitted, seq 2",
            "first emitted, seq 0",
            "second emitted, seq 0 again",
            "fourth emitted, seq 1",
        ],
        "records keep the order they arrived in; declared sequence never re-sorts them"
    );

    let capture_set = parse_capture(DUPLICATES);
    let declared: Vec<Option<u64>> = capture_set
        .records
        .iter()
        .map(|r| r.declared_sequence)
        .collect();
    assert_eq!(declared, [Some(2), Some(0), Some(0), Some(1)]);
    let stream: Vec<u64> = capture_set.records.iter().map(|r| r.stream_index).collect();
    assert_eq!(stream, [0, 1, 2, 3]);

    let duplicates = coverage_with(&reduction, PortalCoverageStatus::DuplicateSequence);
    assert_eq!(duplicates.len(), 1);
    assert_eq!(duplicates[0].stream_index, Some(2));
    assert!(duplicates[0].detail.contains("sequence 0"));
    assert_eq!(
        reduction.evidence.len(),
        4,
        "a duplicated sequence number is reported, never used to drop a record"
    );
}

// ---------------------------------------------------------------------------
// 7. Missing timezone or boot-relative-only time
// ---------------------------------------------------------------------------

#[test]
fn missing_timezone_and_boot_relative_time_stay_visible() {
    let capture_set = parse_capture(DEGRADED_TIME);
    let kinds: Vec<&PortalTimestampKind> = capture_set
        .records
        .iter()
        .map(|r| &r.timestamp.kind)
        .collect();
    assert_eq!(
        kinds,
        [
            &PortalTimestampKind::Local,
            &PortalTimestampKind::BootRelative,
            &PortalTimestampKind::Invalid,
            &PortalTimestampKind::Utc,
        ]
    );

    let local = &capture_set.records[0];
    assert_eq!(local.timestamp.raw_text, "2026-07-15 07:05:00.123456");
    assert!(
        local.timestamp.normalized_utc.is_none(),
        "wall-clock text with no offset is never promoted to UTC"
    );
    assert!(!local.timestamp.is_absolute());
    assert_eq!(local.timezone_name.as_deref(), Some("America/Chicago"));

    let boot = &capture_set.records[1];
    let boot_relative = boot.boot_relative.as_ref().expect("boot-relative metadata");
    assert_eq!(
        boot_relative.boot_uuid.as_deref(),
        Some("0f1e2d3c-4b5a-4968-8776-655443322110")
    );
    assert_eq!(boot_relative.mach_timestamp, Some(184_467_440_737));
    assert_eq!(boot_relative.time_since_boot_ns, Some(76_543_210_987));
    assert!(boot.timestamp.raw_text.is_empty());

    let invalid = &capture_set.records[2];
    assert_eq!(invalid.timestamp.raw_text, "not-a-timestamp");

    let absolute = &capture_set.records[3];
    assert!(absolute.timestamp.is_absolute());
    assert_eq!(absolute.timestamp.original_offset.as_deref(), Some("Z"));

    let degraded = set_coverage_with(&capture_set, PortalCoverageStatus::DegradedTimestamp);
    assert_eq!(degraded.len(), 3);
    let flagged: Vec<Option<u64>> = degraded.iter().map(|c| c.stream_index).collect();
    assert_eq!(flagged, [Some(0), Some(1), Some(2)]);

    assert_eq!(
        normalize_timestamp("   ").kind,
        PortalTimestampKind::Unspecified
    );
}

// ---------------------------------------------------------------------------
// 8. Malformed JSON line
// ---------------------------------------------------------------------------

#[test]
fn malformed_lines_become_coverage_and_are_preserved() {
    let capture_set = parse_capture(MALFORMED);

    assert!(capture_set.supported);
    assert_eq!(capture_set.records.len(), 2);
    assert_eq!(capture_set.stats.stream_lines, 4);
    assert_eq!(capture_set.stats.records_malformed, 2);

    let malformed = set_coverage_with(&capture_set, PortalCoverageStatus::MalformedRecord);
    assert_eq!(malformed.len(), 2);
    assert!(malformed[0].detail.contains("not valid JSON"));
    assert!(malformed[1].detail.contains("not an object"));

    let excerpt = malformed[0].raw_excerpt.as_ref().expect("verbatim excerpt");
    assert_eq!(excerpt.sensitivity, PortalSensitivity::Sensitive);
    assert!(excerpt.value.contains("truncated by a collector crash"));

    assert_eq!(
        capture_set.records[0].event_message.value,
        "Before the malformed lines"
    );
    assert_eq!(
        capture_set.records[1].event_message.value, "After the malformed lines",
        "a bad line never desynchronises the records around it"
    );
    assert_eq!(
        capture_set.records[1].stream_index, 1,
        "stream index counts records, so the surviving records stay contiguous"
    );
}

// ---------------------------------------------------------------------------
// 9. Unknown schema / version
// ---------------------------------------------------------------------------

#[test]
fn unknown_schema_versions_are_refused_without_losing_content() {
    let future = parse_capture(FUTURE_VERSION);
    assert!(!future.supported);
    assert_eq!(future.schema_version, Some(2));
    assert!(future.records.is_empty());
    assert_eq!(
        future.raw_unsupported.len(),
        2,
        "records from an unsupported version are preserved losslessly"
    );
    let refusal = set_coverage_with(&future, PortalCoverageStatus::UnsupportedSchemaVersion);
    assert_eq!(refusal.len(), 1);
    assert!(refusal[0].detail.contains("version 2"));

    let reduction = reduce_capture_set(future);
    assert!(!reduction.supported);
    assert!(
        reduction.evidence.is_empty(),
        "an unsupported version yields no confident answer, only coverage"
    );
    assert_eq!(reduction.coverage.len(), 1);

    let alien = parse_capture(ALIEN_SCHEMA);
    assert!(!alien.supported);
    assert_eq!(
        alien.schema_id.as_deref(),
        Some("com.example.someOtherCaptureSchema")
    );
    let unknown = set_coverage_with(&alien, PortalCoverageStatus::UnknownSchema);
    assert_eq!(unknown.len(), 1);
    assert!(unknown[0].detail.contains("unknown capture schema"));
    assert_eq!(alien.raw_unsupported.len(), 2);

    let headerless = parse_capture(MISSING_HEADER);
    assert!(!headerless.supported);
    assert!(headerless.schema_id.is_none());
    let missing = set_coverage_with(&headerless, PortalCoverageStatus::UnknownSchema);
    assert_eq!(missing.len(), 1);
    assert!(missing[0].detail.contains("capture header is missing"));
    assert_eq!(headerless.raw_unsupported.len(), 2);

    assert!(is_supported_schema_version(
        PORTAL_UNIFIED_LOG_SCHEMA_VERSION
    ));
    assert!(!is_supported_schema_version(
        PORTAL_UNIFIED_LOG_SCHEMA_VERSION + 1
    ));
}

// ---------------------------------------------------------------------------
// 10. Unrelated process / subsystem negative
// ---------------------------------------------------------------------------

#[test]
fn unrelated_sources_and_process_only_matches_are_not_selected() {
    let reduction = reduce_capture_text(NEGATIVES);

    assert_eq!(
        reduction.evidence.len(),
        1,
        "only the verified process/subsystem pair is Company Portal evidence"
    );
    assert_eq!(reduction.evidence[0].record_id, "ul-000000");
    assert_eq!(
        reduction.evidence[0].selection.reason,
        PortalSelectionReason::VerifiedProcessAndSubsystem
    );
    assert_eq!(
        reduction.evidence[0].selection.matched_subsystem.as_deref(),
        Some("com.microsoft.CompanyPortalMac")
    );

    let rejected = coverage_with(&reduction, PortalCoverageStatus::NotSelected);
    assert_eq!(rejected.len(), 4);
    let flagged: Vec<Option<u64>> = rejected.iter().map(|c| c.stream_index).collect();
    assert_eq!(flagged, [Some(1), Some(2), Some(3), Some(4)]);

    let capture_set = parse_capture(NEGATIVES);
    let reasons: Vec<PortalSelectionReason> = capture_set
        .records
        .iter()
        .map(|r| classify_record(r).reason)
        .collect();
    assert_eq!(
        reasons,
        [
            PortalSelectionReason::VerifiedProcessAndSubsystem,
            PortalSelectionReason::UnrelatedSource,
            PortalSelectionReason::MessageMentionOnlyIgnored,
            PortalSelectionReason::ProcessOnlyInsufficient,
            PortalSelectionReason::ProcessOnlyInsufficient,
        ]
    );

    assert!(
        rejected[1]
            .detail
            .contains("free text is never a selection signal"),
        "a message body naming Company Portal must never select: {}",
        rejected[1].detail
    );
    assert!(
        rejected[2]
            .detail
            .contains("a process name alone is not sufficient"),
        "a bare process match must never select: {}",
        rejected[2].detail
    );

    // The predicate tables themselves encode the rule.
    assert!(is_capture_process("CompanyPortal"));
    assert!(verified_source("CompanyPortal", "com.example.spoofed").is_none());
    assert!(verified_source("CompanyPortal", "com.microsoft.CompanyPortalMac").is_some());
    assert!(
        verified_source("CompanyPortal", "COM.MICROSOFT.COMPANYPORTALMAC").is_some(),
        "reverse-DNS subsystems are not case-significant"
    );
    assert_eq!(PORTAL_VERIFIED_SOURCES.len(), 3);
}

// ---------------------------------------------------------------------------
// 11. Direct-log / unified-log matching key
// ---------------------------------------------------------------------------

#[test]
fn explicit_identifiers_merge_direct_and_unified_evidence() {
    let reduction = reduce_capture_text(MATCH_KEYS);
    assert_eq!(reduction.evidence.len(), 3);

    let by_activity = PortalDirectLogAnchor {
        activity_id: Some("0x5150".to_string()),
        ..anchor("direct-activity")
    };
    let by_request = PortalDirectLogAnchor {
        request_id: Some("req-77e1".to_string()),
        ..anchor("direct-request")
    };
    let by_correlation = PortalDirectLogAnchor {
        correlation_id: Some("corr-9931".to_string()),
        ..anchor("direct-correlation")
    };
    let by_documented = PortalDirectLogAnchor {
        documented_relationship_id: Some("trace-4410".to_string()),
        ..anchor("direct-documented")
    };

    let result = correlate_with_direct_logs(
        &reduction,
        &[by_activity, by_request, by_correlation, by_documented],
    );

    assert!(
        result.rejections.is_empty(),
        "no anchor shares a timestamp with these records"
    );
    assert_eq!(result.links.len(), 6);
    assert!(result.links.iter().all(|link| link.merged));

    let summary: Vec<(&str, &str, &PortalMergeBasis)> = result
        .links
        .iter()
        .map(|l| (l.anchor_id.as_str(), l.record_id.as_str(), &l.basis))
        .collect();
    assert_eq!(
        summary,
        [
            (
                "direct-activity",
                "ul-000000",
                &PortalMergeBasis::ActivityId
            ),
            (
                "direct-activity",
                "ul-000001",
                &PortalMergeBasis::ActivityId
            ),
            ("direct-request", "ul-000000", &PortalMergeBasis::RequestId),
            ("direct-request", "ul-000001", &PortalMergeBasis::RequestId),
            (
                "direct-correlation",
                "ul-000001",
                &PortalMergeBasis::CorrelationId
            ),
            (
                "direct-documented",
                "ul-000000",
                &PortalMergeBasis::DocumentedRelationship
            ),
        ],
        "the unrelated agent record ul-000002 must never attach to these anchors"
    );

    assert!(result
        .links
        .iter()
        .filter(|l| l.basis != PortalMergeBasis::DocumentedRelationship)
        .all(|l| l.confidence == PortalEvidenceConfidence::Exact));
    assert_eq!(
        result.links[5].confidence,
        PortalEvidenceConfidence::Strong,
        "a documented relationship is strong, not exact"
    );
    assert_eq!(result.links[0].matched_value.value, "0x5150");
}

// ---------------------------------------------------------------------------
// 12. Same-time unrelated activity proving no time-only merge
// ---------------------------------------------------------------------------

#[test]
fn same_timestamp_unrelated_activities_never_merge() {
    let reduction = reduce_capture_text(SAME_TIME);
    assert_eq!(reduction.evidence.len(), 2);
    assert_eq!(
        reduction.evidence[0].timestamp.normalized_utc,
        reduction.evidence[1].timestamp.normalized_utc,
        "the fixture must actually place both records at the same instant"
    );
    assert_ne!(
        reduction.evidence[0].activity.activity_id,
        reduction.evidence[1].activity.activity_id
    );

    // An anchor that shares only the instant merges with nothing.
    let time_only = PortalDirectLogAnchor {
        timestamp: normalize_timestamp("2026-07-15 07:10:00.000000-0500"),
        ..anchor("direct-time-only")
    };
    let result = correlate_with_direct_logs(&reduction, std::slice::from_ref(&time_only));
    assert!(
        result.links.is_empty(),
        "a time-only coincidence must never produce a merge"
    );
    assert_eq!(result.rejections.len(), 2);
    assert!(result.rejections.iter().all(|r| !r.merged));
    assert!(result
        .rejections
        .iter()
        .all(|r| r.basis == PortalMergeBasis::TimeOnly));
    assert!(result
        .rejections
        .iter()
        .all(|r| r.confidence == PortalEvidenceConfidence::Low));
    assert!(result.rejections[0].detail.contains("never merges"));

    // An anchor that shares the instant AND one activity id merges with that
    // record only; the co-timed unrelated activity is still refused.
    let one_activity = PortalDirectLogAnchor {
        timestamp: normalize_timestamp("2026-07-15 07:10:00.000000-0500"),
        activity_id: Some("0x7001".to_string()),
        ..anchor("direct-one-activity")
    };
    let result = correlate_with_direct_logs(&reduction, &[one_activity]);
    assert_eq!(result.links.len(), 1);
    assert_eq!(result.links[0].record_id, "ul-000000");
    assert_eq!(result.rejections.len(), 1);
    assert_eq!(result.rejections[0].record_id, "ul-000001");

    assert!(!merge_is_permitted(&PortalMergeBasis::TimeOnly));
    for basis in [
        PortalMergeBasis::ActivityId,
        PortalMergeBasis::SignpostId,
        PortalMergeBasis::RequestId,
        PortalMergeBasis::CorrelationId,
        PortalMergeBasis::DocumentedRelationship,
    ] {
        assert!(merge_is_permitted(&basis));
    }
}

// ---------------------------------------------------------------------------
// 13. Capped / skipped / permission-denied capture coverage
// ---------------------------------------------------------------------------

#[test]
fn capped_skipped_and_permission_denied_capture_is_explicit_coverage() {
    let reduction = reduce_capture_text(CAPTURE_COVERAGE);

    assert!(reduction.supported);
    assert_eq!(reduction.evidence.len(), 2);
    assert!(reduction.stats.capped);
    assert_eq!(reduction.stats.total_matched, Some(12_000));
    assert_eq!(reduction.stats.result_cap, Some(2));
    assert_eq!(reduction.stats.records_parsed, 2);

    let capped = coverage_with(&reduction, PortalCoverageStatus::Capped);
    assert_eq!(capped.len(), 1);
    assert_eq!(capped[0].scope, PortalCoverageScope::Capture);
    assert!(capped[0].detail.contains("12000"));

    let denied = coverage_with(&reduction, PortalCoverageStatus::PermissionDenied);
    assert_eq!(denied.len(), 1);
    assert!(denied[0].detail.contains("private data was withheld"));

    let skipped = coverage_with(&reduction, PortalCoverageStatus::Skipped);
    assert_eq!(skipped.len(), 1);
    assert!(skipped[0].detail.contains("boot session changed"));

    let unknown = coverage_with(&reduction, PortalCoverageStatus::UnknownSchema);
    assert_eq!(
        unknown.len(),
        1,
        "a coverage status this build does not know is itself coverage"
    );
    assert!(unknown[0].detail.contains("unheardOf"));

    let ids: Vec<&str> = reduction
        .coverage
        .iter()
        .map(|c| c.coverage_id.as_str())
        .collect();
    let unique: BTreeSet<&&str> = ids.iter().collect();
    assert_eq!(unique.len(), ids.len(), "coverage ids must be unique");
    assert_eq!(ids[0], "coverage-0000");
}

// ---------------------------------------------------------------------------
// 14. Deterministic redacted export
// ---------------------------------------------------------------------------

#[test]
fn redacted_export_is_deterministic_and_uses_stable_tokens() {
    let reduction = reduce_capture_text(REDACTED_EXPORT);
    let first = redacted_export_projection(&reduction);
    let second = redacted_export_projection(&reduction);

    assert_eq!(first, second, "redaction must be a pure function");
    assert_eq!(
        serde_json::to_string(&first).unwrap(),
        serde_json::to_string(&second).unwrap(),
        "serialized export must be byte-identical across runs"
    );
    assert_eq!(
        redacted_export_projection(&first),
        first,
        "redaction must be idempotent"
    );

    let capture = first.capture.as_ref().expect("capture provenance survives");
    assert!(capture.redaction.applied);
    assert_eq!(
        capture.redaction.policy_id.as_deref(),
        Some(PORTAL_UNIFIED_LOG_REDACTION_POLICY_ID)
    );
    assert_eq!(
        capture.redaction.placeholder_style.as_deref(),
        Some(PORTAL_UNIFIED_LOG_REDACTION_PLACEHOLDER_STYLE)
    );
    assert_eq!(
        capture.host.host_name.as_ref().unwrap().value,
        "[redacted:host]",
        "the host name is an identifier and does not survive export"
    );
    assert!(
        capture.predicate.matches_known_preset
            && capture.predicate.predicate_text == PORTAL_UNIFIED_LOG_CAPTURE_PREDICATE,
        "provenance survives redaction, otherwise the export is not reproducible"
    );

    let serialized = serde_json::to_string(&first).unwrap();
    for secret in [
        "rin.okafor",
        "8f14e45f-ceea-467a-9f19-7a1b2c3d4e5f",
        "2d7f8a91-3b4c-4d5e-8f90-a1b2c3d4e5f6",
        "eyJhbGciOiJIUzI1NiJ9",
        "login.microsoftonline.example",
        "Synthetic Intune Device CA",
        "synthetic-mac.contoso.example.com",
    ] {
        assert!(
            !serialized.contains(secret),
            "redacted export still leaks {secret}"
        );
    }

    // Operation handles are deliberately preserved: they are the join keys and
    // they name no person, tenant, or device.
    assert_eq!(
        first.evidence[0].activity.activity_id.as_deref(),
        Some("0x5150")
    );
    assert_eq!(
        first.evidence[0].activity.request_id.as_deref(),
        Some("req-77e1")
    );
    assert_eq!(first.activities.len(), 1);
    assert_eq!(first.activities[0].record_ids, ["ul-000000", "ul-000001"]);

    // Record-level projection covers fields that reduction does not carry.
    let capture_set = parse_capture(REDACTED_EXPORT);
    let redacted_records = redacted_capture_projection(&capture_set);
    let record = &redacted_records.records[0];
    assert_eq!(
        record.process_image_path.as_ref().unwrap().value,
        "[redacted:path]"
    );
    assert!(record.redaction.applied);
    assert_eq!(
        record.redaction.policy_id.as_deref(),
        Some(PORTAL_UNIFIED_LOG_REDACTION_POLICY_ID)
    );
    assert_eq!(
        record.redaction.redacted_fields,
        ["eventMessage", "processImagePath", "senderImagePath"],
        "redacted field names are sorted, so the export is stable"
    );
    let vendor = record.unknown_fields.get("vendorDetail").unwrap();
    assert_eq!(
        vendor.get("serialNumber"),
        Some(&Value::String("[redacted:serial]".to_string()))
    );
    assert_eq!(
        vendor.get("reportUrl"),
        Some(&Value::String("[redacted:url]".to_string()))
    );

    // Coverage is emitted in a stable, sorted order.
    let coverage_ids: Vec<&str> = first
        .coverage
        .iter()
        .map(|c| c.coverage_id.as_str())
        .collect();
    let mut sorted = coverage_ids.clone();
    sorted.sort_unstable();
    assert_eq!(coverage_ids, sorted);

    assert_eq!(redact_text("no secrets here"), "no secrets here");
}

// ---------------------------------------------------------------------------
// Acceptance criteria
// ---------------------------------------------------------------------------

#[test]
fn normalized_capture_schema_serialization_is_golden() {
    let actual = serde_json::to_value(parse_capture(GOLDEN_CAPTURE)).unwrap();
    let expected: Value = serde_json::from_str(GOLDEN_EXPECTED).unwrap();
    assert_eq!(
        actual, expected,
        "the versioned capture schema changed; review the contract before updating the golden file"
    );

    // The golden file is also a round-trip contract.
    let round_tripped: PortalUnifiedLogCaptureSet = serde_json::from_str(GOLDEN_EXPECTED).unwrap();
    assert_eq!(round_tripped, parse_capture(GOLDEN_CAPTURE));

    assert_eq!(
        expected.get("schemaVersion").and_then(Value::as_u64),
        Some(u64::from(PORTAL_UNIFIED_LOG_SCHEMA_VERSION))
    );
    assert_eq!(
        expected.get("schemaId").and_then(Value::as_str),
        Some(PORTAL_UNIFIED_LOG_SCHEMA_ID)
    );
}

#[test]
fn pure_module_cannot_collect_and_stays_wasm_clean() {
    let module_dir = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/intune/portal/macos/company_portal"
    );

    let mut sources = Vec::new();
    let mut stack = vec![std::path::PathBuf::from(module_dir)];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("module directory is readable") {
            let path = entry.expect("directory entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                sources.push((
                    path.clone(),
                    std::fs::read_to_string(&path).expect("source file is readable"),
                ));
            }
        }
    }
    assert!(sources.len() >= 8, "expected the full module tree");

    // Doc comments legitimately mention `log show`; executable code must not.
    for (path, text) in &sources {
        for (number, line) in text.lines().enumerate() {
            let code = line.trim_start();
            if code.starts_with("//") || code.starts_with("///") || code.starts_with("//!") {
                continue;
            }
            for forbidden in [
                "std::process",
                "Command::new",
                "std::fs",
                "std::net",
                "SystemTime",
                "thread::spawn",
                "log show",
            ] {
                assert!(
                    !code.contains(forbidden),
                    "{}:{} uses `{forbidden}`; the pure crate must not collect and must stay \
                     wasm-compatible",
                    path.display(),
                    number + 1
                );
            }
        }
    }
}

#[test]
fn selection_and_category_tables_are_conservative() {
    assert_eq!(
        classify_category(Some("Enrollment")),
        Some(PortalUnifiedLogEvidenceKind::EnrollmentProfile)
    );
    assert_eq!(
        classify_category(Some("authentication")),
        Some(PortalUnifiedLogEvidenceKind::Authentication)
    );
    assert_eq!(classify_category(Some("SomethingElse")), None);
    assert_eq!(classify_category(None), None);

    assert!(is_known_capture_predicate(
        PORTAL_UNIFIED_LOG_CAPTURE_PREDICATE
    ));
    assert!(!is_known_capture_predicate(r#"process == "CompanyPortal""#));
    assert_eq!(selection_predicate_version(), 1);
    assert_eq!(
        PORTAL_CAPTURE_PROCESSES,
        ["CompanyPortal", "IntuneMdmAgent", "IntuneMdmDaemon"]
    );
}

// ---------------------------------------------------------------------------
// Redaction and ingest hardening (PR #390 review)
// ---------------------------------------------------------------------------

/// An ASCII-only email class does not truncate a non-ASCII identity, it misses
/// it entirely: with an accented leading character the leading word boundary
/// never anchors, so the whole address survives into the export.
#[test]
fn non_ascii_identities_are_redacted() {
    let redacted = redact_text("signed in as jos\u{e9}.garc\u{ed}a@contoso.example");
    assert!(
        !redacted.contains("garc"),
        "non-ASCII identity leaked: {redacted}"
    );
    assert!(!redacted.contains("contoso.example"));
}

/// A malformed NDJSON line is kept verbatim as a coverage excerpt and redacted
/// by the label-scoped patterns alone. In JSON the label arrives quoted, so a
/// separator that did not tolerate the quote never matched the input that most
/// needs it.
#[test]
fn json_shaped_labels_are_redacted() {
    let json = r#"{"process":"CompanyPortal","serialNumber":"C02XG2QQMD6M","access_token":"opaqueSessionValue123","tenantId":"4b2f9d61-1c53-4c58-8f1a-b0d3e1b5aa77"}"#;
    let redacted = redact_text(json);

    assert!(
        !redacted.contains("C02XG2QQMD6M"),
        "serial leaked: {redacted}"
    );
    assert!(
        !redacted.contains("opaqueSessionValue123"),
        "token leaked: {redacted}"
    );
    assert!(
        !redacted.contains("4b2f9d61-1c53-4c58-8f1a-b0d3e1b5aa77"),
        "tenant id leaked: {redacted}"
    );
    // The structural key names are evidence and must survive.
    assert!(redacted.contains("serialNumber"));
    assert!(redacted.contains("CompanyPortal"));
}

/// The generic labelled rule stops its value at the first space, so on
/// `Authorization: Bearer <opaque>` it redacted the scheme word and left the
/// credential. A JWT is caught by shape; an opaque bearer or Basic blob is not.
#[test]
fn opaque_authorization_credentials_are_redacted() {
    for header in [
        "Authorization: Bearer abcOpaqueSessionToken1234567890",
        "Authorization: Basic dXNlcjpwYXNzd29yZA==",
        "authorization: Negotiate YIIZgAYGKwYBBQUCoIIZ",
    ] {
        let redacted = redact_text(header);
        assert!(
            !redacted.contains("abcOpaqueSessionToken1234567890")
                && !redacted.contains("dXNlcjpwYXNzd29yZA==")
                && !redacted.contains("YIIZgAYGKwYBBQUCoIIZ"),
            "credential leaked from {header:?}: {redacted}"
        );
    }
}

/// Removes `[redacted:...]` spans so a hextet is only ever matched against text
/// that actually survived. Placeholder tokens carry characters of their own.
fn strip_placeholder_tokens(redacted: &str) -> String {
    let mut out = String::with_capacity(redacted.len());
    let mut rest = redacted;
    while let Some(start) = rest.find("[redacted:") {
        out.push_str(&rest[..start]);
        let Some(end) = rest[start..].find(']') else {
            return out;
        };
        rest = &rest[start + end + 1..];
    }
    out.push_str(rest);
    out
}

/// Asserts every meaningful hextet of an address is gone.
///
/// `!redacted.contains(address)` alone is too weak: a partial redaction leaving
/// `fd12:3456:[redacted:host]` satisfies it while still exporting a stable
/// network prefix, which is the identifying part.
fn assert_no_ipv6_component_survives(address: &str, redacted: &str) {
    let remaining = strip_placeholder_tokens(redacted);
    for hextet in address.split(':').filter(|part| !part.is_empty()) {
        assert!(
            !remaining.contains(hextet),
            "hextet `{hextet}` of {address} survived: {redacted}"
        );
    }
    assert!(
        !redacted.contains(address),
        "{address} survived redaction: {redacted}"
    );
}

/// `\b` is a word-boundary assertion and `:` is not a word character, so it
/// cannot anchor an address that begins or ends with a colon. Every
/// `::`-compressed form does one or both, and the address exports verbatim.
#[test]
fn compressed_ipv6_forms_are_fully_redacted() {
    for address in [
        "2001:db8:85a3::",
        "fd12:3456:789a::",
        "fe80::",
        "::1",
        "2001:db8::8a2e:370:7334",
    ] {
        let redacted = redact_text(&format!("peer {address} connected"));
        assert_no_ipv6_component_survives(address, &redacted);
        assert!(
            redacted.starts_with("peer ") && redacted.ends_with(" connected"),
            "delimiters must survive: {redacted}"
        );
    }
}

/// Two addresses separated by a single delimiter must both be redacted. A guard
/// that consumes the delimiter on both sides would leave the second address
/// without one to anchor against.
#[test]
fn adjacent_ipv6_addresses_are_both_redacted() {
    let redacted = redact_text("peers fd12:3456:789a:: fd12:3456:789b:: done");
    assert_no_ipv6_component_survives("fd12:3456:789a::", &redacted);
    assert_no_ipv6_component_survives("fd12:3456:789b::", &redacted);

    let redacted = redact_text("::1,::2");
    assert_no_ipv6_component_survives("::1", &redacted);
    assert_no_ipv6_component_survives("::2", &redacted);
}

/// The IPv6 matcher must not claim text that merely contains hex and colons.
#[test]
fn ipv6_redaction_does_not_claim_timestamps_macs_or_prose() {
    let redacted = redact_text("collected at 08:18:00:104 local");
    assert!(
        redacted.contains("08:18:00:104"),
        "a timestamp is not an address: {redacted}"
    );

    // A bare `::` identifies nothing and appears in ordinary prose.
    let redacted = redact_text("called std::process::exit");
    assert_eq!(redacted, "called std::process::exit");

    // An address embedded in a word is not an address, and must not be
    // half-matched into a partial redaction that hides the leak. The lead-in
    // word avoids `token`, `secret` and friends, which the labelled-secret rule
    // legitimately claims along with whatever follows them.
    let redacted = redact_text("opaque x2001:db8::y");
    assert_eq!(redacted, "opaque x2001:db8::y");
}

/// Unified-log evidence carries a `NetworkRequest` kind, so bare addresses are
/// plausible in `eventMessage`. The ESP redactor already enforces this.
#[test]
fn network_addresses_are_redacted() {
    let redacted = redact_text(
        "endpoint 203.0.113.47 via proxy 198.51.100.9:8080, nic 3c:22:fb:a1:9d:4e, v6 2001:0db8:85a3:0000:0000:8a2e:0370:7334",
    );
    for secret in [
        "203.0.113.47",
        "198.51.100.9",
        "3c:22:fb:a1:9d:4e",
        "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
    ] {
        assert!(!redacted.contains(secret), "{secret} leaked: {redacted}");
    }
}

/// Address matchers must not eat evidence that merely looks address-shaped.
#[test]
fn network_redaction_does_not_swallow_versions() {
    let redacted = redact_text("Company Portal 5.2504.0 on macOS 15.4.1 build 2504.12");
    assert!(redacted.contains("5.2504.0"));
    assert!(redacted.contains("15.4.1"));
}

/// `as u32` wraps: a declared `schemaVersion` of 4294967297 truncates to 1 and
/// would be parsed as if it were the supported schema.
#[test]
fn out_of_range_schema_version_is_unsupported_not_wrapped() {
    // Build the header from the real constant. Hand-typing the schema id makes
    // the capture fail on the *id* branch before the version check ever runs,
    // so the test would still pass with the wrapping cast restored.
    let header =
        format!(r#"{{"schemaId":"{PORTAL_UNIFIED_LOG_SCHEMA_ID}","schemaVersion":4294967297}}"#);
    let capture = parse_capture_ndjson(&format!("{header}\n"));

    assert!(
        !capture.supported,
        "an out-of-range schema version must not be accepted as v1"
    );

    // It must be refused for the right reason: the version, not the id.
    let statuses: Vec<PortalCoverageStatus> = capture
        .coverage
        .iter()
        .map(|entry| entry.status.clone())
        .collect();
    assert!(
        statuses.contains(&PortalCoverageStatus::UnsupportedSchemaVersion),
        "expected UnsupportedSchemaVersion, got {statuses:?}"
    );
    assert!(
        !statuses.contains(&PortalCoverageStatus::UnknownSchema),
        "the schema id is valid, so this must not be an unknown-schema refusal"
    );

    // The detail must say the version was out of range, not that none was
    // declared: the header plainly declares one, and telling a support engineer
    // otherwise sends them looking for the wrong thing.
    let detail = capture
        .coverage
        .iter()
        .find(|e| e.status == PortalCoverageStatus::UnsupportedSchemaVersion)
        .map(|e| e.detail.clone())
        .expect("an unsupported-version coverage entry");
    assert!(
        detail.contains("4294967297"),
        "the declared value must be reported: {detail}"
    );
    assert!(
        !detail.contains("does not declare"),
        "the header does declare a version: {detail}"
    );

    // The guard does not over-reject: the declared version is still readable.
    let supported_header = format!(
        r#"{{"schemaId":"{PORTAL_UNIFIED_LOG_SCHEMA_ID}","schemaVersion":{PORTAL_UNIFIED_LOG_SCHEMA_VERSION}}}"#
    );
    let ok = parse_capture_ndjson(&format!("{supported_header}\n"));
    assert_eq!(ok.schema_version, Some(PORTAL_UNIFIED_LOG_SCHEMA_VERSION));
    assert!(parse_capture_ndjson(SUPPORTED_NDJSON).supported);
}

/// macOS paths contain spaces. Stopping at the first space redacted only the
/// head of the path and left the tail in the exported text.
#[test]
fn user_paths_containing_spaces_are_fully_redacted() {
    let redacted = redact_text(
        "wrote report to /Users/alice/Applications/Company Portal.app/Contents/log.txt and exited",
    );
    assert!(!redacted.contains("alice"), "leaked: {redacted}");
    assert!(!redacted.contains("Portal.app"), "leaked tail: {redacted}");
    assert!(!redacted.contains("log.txt"), "leaked tail: {redacted}");
    // Prose after the path is evidence and must survive.
    assert!(redacted.contains("and exited"), "over-captured: {redacted}");
    assert!(redacted.contains("wrote report to"));
}

/// A plain path with no spaces still redacts, and prose after it survives.
#[test]
fn user_path_redaction_stops_at_the_end_of_the_path() {
    let redacted = redact_text("opened /Users/bob/Library/Logs/x.log then continued");
    assert!(!redacted.contains("bob"));
    assert!(!redacted.contains("x.log"));
    assert!(
        redacted.contains("then continued"),
        "over-captured: {redacted}"
    );
}

/// Rule 2 links a record to a selected one through an *explicit* identifier, not
/// a coincidence. Flattening every identifier field into one untyped set let a
/// candidate's `traceId` match an anchor's `activityIdentifier` and be selected
/// as activity-linked although they share no relationship in any one namespace.
/// The committed fixtures already reuse the `0x...` shape across both fields.
#[test]
fn cross_namespace_identifier_collisions_do_not_link_records() {
    let header = format!(
        r#"{{"captureId":"c","collectedAtUtc":"2026-07-15T12:05:10Z","schemaId":"{PORTAL_UNIFIED_LOG_SCHEMA_ID}","schemaVersion":{PORTAL_UNIFIED_LOG_SCHEMA_VERSION}}}"#
    );
    // Anchor: verified subsystem, so selected on its own merits, activity 0x1a2b.
    let anchor_record = r#"{"activityIdentifier":"0x1a2b","category":"Enrollment","eventMessage":"anchor","messageType":"Default","process":"CompanyPortal","sourceSequence":0,"subsystem":"com.microsoft.CompanyPortalMac","timestamp":"2026-07-15 07:02:00.000000-0500"}"#;
    // Candidate: capture process only, unverified subsystem, and its *trace* id
    // happens to equal the anchor's *activity* id.
    let collide = r#"{"traceId":"0x1a2b","category":"Misc","eventMessage":"unrelated","messageType":"Default","process":"CompanyPortal","sourceSequence":1,"subsystem":"com.example.unrelated","timestamp":"2026-07-15 07:02:01.000000-0500"}"#;
    // Control: same namespace, so this one legitimately links.
    let same_kind = r#"{"activityIdentifier":"0x1a2b","category":"Misc","eventMessage":"linked","messageType":"Default","process":"CompanyPortal","sourceSequence":2,"subsystem":"com.example.unrelated","timestamp":"2026-07-15 07:02:02.000000-0500"}"#;

    let reduction = reduce_capture_text(&format!(
        "{header}\n{anchor_record}\n{collide}\n{same_kind}\n"
    ));
    let selected: Vec<&str> = reduction
        .evidence
        .iter()
        .map(|e| e.summary.value.as_str())
        .collect();

    assert!(selected.contains(&"anchor"));
    assert!(
        selected.contains(&"linked"),
        "a shared activity id in the same namespace must still link: {selected:?}"
    );
    assert!(
        !selected.contains(&"unrelated"),
        "a traceId must not match an anchor's activityIdentifier: {selected:?}"
    );
}

/// The header is the leading object and must look like one. A record carrying a
/// stray `schemaId` among its unknown fields used to be lifted out of the stream
/// and treated as capture metadata, changing both the record set and the stats.
#[test]
fn a_record_mentioning_schema_id_is_not_mistaken_for_the_header() {
    let header = format!(
        r#"{{"captureId":"c","schemaId":"{PORTAL_UNIFIED_LOG_SCHEMA_ID}","schemaVersion":{PORTAL_UNIFIED_LOG_SCHEMA_VERSION}}}"#
    );
    let sneaky = r#"{"schemaId":"attacker-supplied","category":"Enrollment","eventMessage":"still a record","messageType":"Default","process":"CompanyPortal","sourceSequence":1,"subsystem":"com.microsoft.CompanyPortalMac","timestamp":"2026-07-15 07:02:01.000000-0500"}"#;
    let plain = r#"{"category":"Enrollment","eventMessage":"plain record","messageType":"Default","process":"CompanyPortal","sourceSequence":2,"subsystem":"com.microsoft.CompanyPortalMac","timestamp":"2026-07-15 07:02:02.000000-0500"}"#;

    let capture = parse_capture_ndjson(&format!("{header}\n{sneaky}\n{plain}\n"));

    assert!(capture.supported);
    assert_eq!(
        capture.schema_id.as_deref(),
        Some(PORTAL_UNIFIED_LOG_SCHEMA_ID)
    );
    assert_eq!(
        capture.stats.stream_lines, 2,
        "both records must stay in the stream"
    );
    assert_eq!(capture.records.len(), 2);

    // With no real header at all, a record that merely mentions schemaId is
    // still a record, not a header.
    let headerless = parse_capture_ndjson(&format!("{sneaky}\n"));
    assert!(!headerless.supported);
    assert_eq!(
        headerless.stats.stream_lines, 1,
        "the record must not be consumed as capture metadata"
    );
}

// ---------------------------------------------------------------------------
// Capture-scope defects are not record-scope defects
// ---------------------------------------------------------------------------

/// A defect in the capture header's own `coverage` array is a defect in the
/// capture description, not in a record.
///
/// `records_malformed` is read against `stream_lines` and `records_parsed` to
/// answer "how much of the record stream survived". Charging a header defect to
/// that counter makes the three disagree and points a reader at a record that
/// does not exist.
#[test]
fn a_malformed_capture_coverage_entry_is_not_a_malformed_record() {
    let header = format!(
        r#"{{"captureId":"c","collectedAtUtc":"2026-07-15T12:05:10Z","coverage":["not-an-object"],"schemaId":"{PORTAL_UNIFIED_LOG_SCHEMA_ID}","schemaVersion":{PORTAL_UNIFIED_LOG_SCHEMA_VERSION}}}"#
    );
    let record = r#"{"category":"Enrollment","eventMessage":"only record","messageType":"Default","process":"CompanyPortal","sourceSequence":0,"subsystem":"com.microsoft.CompanyPortalMac","timestamp":"2026-07-15 07:02:00.000000-0500"}"#;

    let capture = parse_capture_ndjson(&format!("{header}\n{record}\n"));

    assert!(capture.supported);
    assert_eq!(
        capture.stats.records_malformed, 0,
        "the defect is in the capture header, not in a record"
    );
    assert_eq!(capture.stats.stream_lines, 1);
    assert_eq!(capture.stats.records_parsed, 1);

    let entry = capture
        .coverage
        .iter()
        .find(|c| {
            c.detail
                .contains("capture coverage entry is not a JSON object")
        })
        .expect("the unusable coverage entry is still reported, never dropped");
    assert_eq!(
        entry.scope,
        PortalCoverageScope::Capture,
        "a header defect is capture scope"
    );
    assert_eq!(entry.status, PortalCoverageStatus::UnknownSchema);
    assert!(
        entry.stream_index.is_none(),
        "no stream line produced this defect"
    );
    assert_eq!(
        entry
            .raw_excerpt
            .as_ref()
            .map(|excerpt| excerpt.value.as_str()),
        Some("\"not-an-object\""),
        "the offending value is preserved verbatim"
    );
}

/// Sibling of the case above, found by auditing every `push_malformed` call
/// site: a `records` key that is not an array is a defect in the capture
/// envelope. There is no record to be malformed, and no stream line was read.
#[test]
fn a_non_array_records_field_is_not_a_malformed_record() {
    let payload = format!(
        r#"{{"captureId":"c","collectedAtUtc":"2026-07-15T12:05:10Z","records":5,"schemaId":"{PORTAL_UNIFIED_LOG_SCHEMA_ID}","schemaVersion":{PORTAL_UNIFIED_LOG_SCHEMA_VERSION}}}"#
    );

    let capture = parse_capture(&payload);

    assert_eq!(
        capture.stats.records_malformed, 0,
        "the capture envelope is malformed, not a record"
    );
    assert_eq!(capture.stats.stream_lines, 0);
    assert_eq!(capture.stats.records_parsed, 0);

    let entry = capture
        .coverage
        .iter()
        .find(|c| c.detail.contains("`records` is not an array"))
        .expect("the unusable `records` value is still reported");
    assert_eq!(entry.scope, PortalCoverageScope::Capture);
    assert_eq!(entry.status, PortalCoverageStatus::UnknownSchema);
    assert!(entry.stream_index.is_none());
    assert_eq!(
        entry
            .raw_excerpt
            .as_ref()
            .map(|excerpt| excerpt.value.as_str()),
        Some("5"),
        "the offending value is preserved verbatim"
    );
}

// ---------------------------------------------------------------------------
// One coverage-id scheme, one formatter
// ---------------------------------------------------------------------------

/// Ingest and reduction both append to one coverage array, and a consumer reads
/// it as a single sequence. Pinning the ids against the one public formatter
/// fails as soon as either producer invents its own format or its own seed.
#[test]
fn coverage_ids_are_one_dense_sequence_across_ingest_and_reduction() {
    // A header whose declared coverage makes ingest emit entries, plus a record
    // from an unrelated source that makes reduction emit one. Both land in the
    // same array, so both producers are exercised in one sequence.
    let header = format!(
        r#"{{"captureId":"c","collectedAtUtc":"2026-07-15T12:05:10Z","coverage":[{{"detail":"capped","status":"capped"}},{{"detail":"denied","status":"permissionDenied"}}],"schemaId":"{PORTAL_UNIFIED_LOG_SCHEMA_ID}","schemaVersion":{PORTAL_UNIFIED_LOG_SCHEMA_VERSION}}}"#
    );
    let unrelated = r#"{"category":"Misc","eventMessage":"not evidence","messageType":"Default","process":"Finder","sourceSequence":0,"subsystem":"com.example.unrelated","timestamp":"2026-07-15 07:02:00.000000-0500"}"#;

    let reduction = reduce_capture_text(&format!("{header}\n{unrelated}\n"));

    assert!(
        reduction
            .coverage
            .iter()
            .any(|entry| entry.status == PortalCoverageStatus::Capped),
        "the ingest-side producer must have run"
    );
    assert!(
        reduction
            .coverage
            .iter()
            .any(|entry| entry.status == PortalCoverageStatus::NotSelected),
        "the reduction-side producer must have run"
    );
    assert!(
        reduction.coverage.len() >= 3,
        "expected entries from both producers, got {:?}",
        reduction.coverage.len()
    );

    for (index, entry) in reduction.coverage.iter().enumerate() {
        assert_eq!(
            entry.coverage_id,
            coverage_id(index),
            "coverage ids must be one dense sequence; entry {index} broke it"
        );
    }

    let unique: BTreeSet<&str> = reduction
        .coverage
        .iter()
        .map(|entry| entry.coverage_id.as_str())
        .collect();
    assert_eq!(
        unique.len(),
        reduction.coverage.len(),
        "coverage ids must be unique"
    );
}

// ---------------------------------------------------------------------------
// Unknown members that no text pattern can catch
// ---------------------------------------------------------------------------

/// A value the record redactor replaces wholesale, because no text pattern can
/// recognise it, must also be recognised by name inside `unknownFields`.
///
/// A bare host name has no `@`, no scheme, and no dotted quad, which is exactly
/// why `capture.host.hostName` is replaced whole rather than pattern-matched.
/// The same value arriving as an unknown member had no such protection. Image
/// paths are the same shape of problem: only paths under `/Users` match a
/// pattern, so `/Applications/Company Portal.app/...` exported verbatim.
#[test]
fn unknown_members_naming_a_host_or_image_path_are_redacted() {
    let header = format!(
        r#"{{"captureId":"c","schemaId":"{PORTAL_UNIFIED_LOG_SCHEMA_ID}","schemaVersion":{PORTAL_UNIFIED_LOG_SCHEMA_VERSION}}}"#
    );
    let record = r#"{"category":"Enrollment","eventMessage":"enrolled","messageType":"Default","process":"CompanyPortal","sourceSequence":0,"subsystem":"com.microsoft.CompanyPortalMac","timestamp":"2026-07-15 07:02:00.000000-0500","hostName":"synthetic-mac-0001","computerName":"synthetic-mac-0001","deviceName":"rin-macbook","nested":{"machineName":"synthetic-mac-0002","processImagePath":"/Applications/Company Portal.app/Contents/MacOS/CompanyPortal"}}"#;

    let capture = parse_capture(&format!("{header}\n{record}\n"));
    let projection = redacted_capture_projection(&capture);
    let serialized = serde_json::to_string(&projection).unwrap();

    for secret in [
        "synthetic-mac-0001",
        "synthetic-mac-0002",
        "rin-macbook",
        "/Applications/Company Portal.app",
    ] {
        assert!(
            !serialized.contains(secret),
            "{secret} leaked through unknownFields: {serialized}"
        );
    }
}

// ---------------------------------------------------------------------------
// An empty identifier is not an identifier
// ---------------------------------------------------------------------------

/// Ingest normalises a blank identifier to `None`, but a record can also reach
/// the reducer by deserialization or direct construction carrying `Some("")`.
///
/// An empty identifier names nothing. Treating it as a value makes every record
/// carrying one share an identifier with every other, which links records that
/// have no relationship and collapses them into one empty-keyed activity group.
#[test]
fn empty_identifiers_never_link_group_or_merge_records() {
    let header = format!(
        r#"{{"captureId":"c","schemaId":"{PORTAL_UNIFIED_LOG_SCHEMA_ID}","schemaVersion":{PORTAL_UNIFIED_LOG_SCHEMA_VERSION}}}"#
    );
    // Verified subsystem, so selected on its own merits and used as an anchor.
    let anchor_line = r#"{"category":"Enrollment","eventMessage":"anchor","messageType":"Default","process":"CompanyPortal","sourceSequence":0,"subsystem":"com.microsoft.CompanyPortalMac","timestamp":"2026-07-15 07:02:00.000000-0500"}"#;
    // Capture process only, unverified subsystem: reachable only through rule 2.
    let candidate = r#"{"category":"Misc","eventMessage":"unrelated","messageType":"Default","process":"CompanyPortal","sourceSequence":1,"subsystem":"com.example.unrelated","timestamp":"2026-07-15 07:02:01.000000-0500"}"#;

    let mut capture = parse_capture(&format!("{header}\n{anchor_line}\n{candidate}\n"));
    assert_eq!(capture.records.len(), 2);
    for record in &mut capture.records {
        record.activity.activity_id = Some(String::new());
        record.activity.parent_activity_id = Some("   ".to_string());
        record.activity.signpost_id = Some(String::new());
        record.activity.correlation_id = Some("  ".to_string());
    }

    let reduction = reduce_capture_set(capture);
    let selected: Vec<&str> = reduction
        .evidence
        .iter()
        .map(|item| item.summary.value.as_str())
        .collect();

    assert!(selected.contains(&"anchor"));
    assert!(
        !selected.contains(&"unrelated"),
        "two blank identifiers are not a shared identifier: {selected:?}"
    );
    assert!(
        reduction.activities.is_empty(),
        "a blank activity id must not open a group: {:?}",
        reduction.activities
    );

    // The same rule on the correlation side: a blank anchor key merges nothing.
    let blank = PortalDirectLogAnchor {
        activity_id: Some(String::new()),
        correlation_id: Some("   ".to_string()),
        ..anchor("direct-blank")
    };
    let result = correlate_with_direct_logs(&reduction, &[blank]);
    assert!(
        result.links.is_empty(),
        "a blank identifier must never justify a merge: {:?}",
        result.links
    );
}

// ---------------------------------------------------------------------------
// Encoding detection
// ---------------------------------------------------------------------------

/// A whole-payload JSON object that declares a capture header is the JSON
/// encoding, whether or not it carries a `records` key.
///
/// `parse_capture_json_object` already treats an absent `records` key as an
/// empty capture. Routing on `records` alone sent a pretty-printed capture with
/// no records down the NDJSON path, where every physical line of the pretty
/// printing failed to parse and became a `MalformedRecord`. A well-formed empty
/// capture was reported as a stream of broken records.
#[test]
fn a_records_free_json_capture_is_not_a_stream_of_malformed_lines() {
    let payload = format!(
        "{{\n  \"captureId\": \"c\",\n  \"collectedAtUtc\": \"2026-07-15T12:05:10Z\",\n  \
         \"schemaId\": \"{PORTAL_UNIFIED_LOG_SCHEMA_ID}\",\n  \
         \"schemaVersion\": {PORTAL_UNIFIED_LOG_SCHEMA_VERSION}\n}}"
    );

    let capture = parse_capture(&payload);

    assert!(
        capture.supported,
        "the capture is well formed and simply empty: {:?}",
        capture.coverage
    );
    assert!(capture.records.is_empty());
    assert_eq!(
        capture.stats.records_malformed, 0,
        "a capture with no records has no malformed records"
    );
    assert_eq!(capture.stats.stream_lines, 0);
    assert_eq!(
        capture,
        parse_capture_json(&payload),
        "auto-detection must agree with the explicit JSON entry point"
    );
}

// ---------------------------------------------------------------------------
// Fixture provenance
// ---------------------------------------------------------------------------

/// Every fixture header must describe a capture that could have produced that
/// fixture's own records.
///
/// A bounded `log show --start/--end` collection cannot return a record outside
/// the window it declares, and a collector cannot stamp `collectedAtUtc` before
/// the last record it collected. A fixture that breaks either models provenance
/// no real capture produces, so it is not evidence of what this code does with a
/// real one. This walks the whole fixture tree, so a fixture added later
/// inherits the check instead of repeating the mistake.
#[test]
fn fixture_capture_headers_cover_their_own_records() {
    let fixtures = capture_fixture_files();
    assert!(
        fixtures.len() >= 19,
        "expected the full fixture tree, found {}",
        fixtures.len()
    );

    let mut offenders = Vec::new();
    for (path, text) in &fixtures {
        let (header, records) = split_fixture(text);
        let Some(header) = header else {
            continue;
        };
        let window = header.get("window").and_then(Value::as_object);
        let start = window
            .and_then(|w| w.get("start"))
            .and_then(Value::as_str)
            .and_then(fixture_utc);
        let end = window
            .and_then(|w| w.get("end"))
            .and_then(Value::as_str)
            .and_then(fixture_utc);
        let collected = header
            .get("collectedAtUtc")
            .and_then(Value::as_str)
            .and_then(fixture_utc);

        for record in &records {
            let Some(stamp) = record
                .get("timestamp")
                .and_then(Value::as_str)
                .and_then(fixture_utc)
            else {
                // Local-only, boot-relative, and uninterpretable stamps are a
                // separate documented case and carry no absolute position.
                continue;
            };
            if let Some(start) = &start {
                if stamp < *start {
                    offenders.push(format!(
                        "{path}: record {stamp} precedes window.start {start}"
                    ));
                }
            }
            if let Some(end) = &end {
                if stamp > *end {
                    offenders.push(format!("{path}: record {stamp} follows window.end {end}"));
                }
            }
            if let Some(collected) = &collected {
                if stamp > *collected {
                    offenders.push(format!(
                        "{path}: record {stamp} follows collectedAtUtc {collected}"
                    ));
                }
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "fixture headers contradict their own records:\n{}",
        offenders.join("\n")
    );
}

/// Reads every capture fixture as `(relative path, text)`.
fn capture_fixture_files() -> Vec<(String, String)> {
    let root = std::path::PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/intune/portal/macos/unified_log"
    ));

    let mut fixtures = Vec::new();
    let mut stack = vec![root.clone()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("fixture directory is readable") {
            let path = entry.expect("directory entry").path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let is_capture = path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("capture") || name.ends_with(".ndjson"));
            if !is_capture {
                continue;
            }
            let relative = path
                .strip_prefix(&root)
                .unwrap_or(&path)
                .display()
                .to_string();
            fixtures.push((
                relative,
                std::fs::read_to_string(&path).expect("fixture is readable"),
            ));
        }
    }
    fixtures.sort();
    fixtures
}

/// Splits fixture text into its capture header and its record objects, using the
/// same header rule the parser uses. Lines that are not JSON objects are a
/// deliberate part of some fixtures and are skipped.
fn split_fixture(text: &str) -> (Option<Value>, Vec<Value>) {
    if let Ok(Value::Object(root)) = serde_json::from_str::<Value>(text) {
        if let Some(Value::Array(records)) = root.get("records") {
            let records = records.clone();
            return (Some(Value::Object(root)), records);
        }
    }

    let mut header = None;
    let mut records = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Ok(Value::Object(obj)) = serde_json::from_str::<Value>(trimmed) else {
            continue;
        };
        let looks_like_header = obj.contains_key("schemaId") && obj.contains_key("schemaVersion");
        if header.is_none() && records.is_empty() && looks_like_header {
            header = Some(Value::Object(obj));
        } else {
            records.push(Value::Object(obj));
        }
    }
    (header, records)
}

/// Normalized UTC text for a timestamp that carries an absolute position, using
/// the crate's own normalizer so every value compares in one format.
fn fixture_utc(raw: &str) -> Option<String> {
    normalize_timestamp(raw).normalized_utc
}
