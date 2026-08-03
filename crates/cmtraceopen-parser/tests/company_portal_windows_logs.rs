//! Company Portal Windows LocalState log contracts — issue #366.
//!
//! Fixtures under `tests/fixtures/intune/portal/windows/logs/<version>/<scenario>/`
//! are entirely synthetic. Every UPN, tenant id, serial, token, GUID, and host
//! name in them was authored for this suite; no user-submitted diagnostic is
//! committed to this repository.
//!
//! The version directory is load-bearing. `v12-0-0` is the only Company Portal
//! app version with a published verbatim record, so it holds the scenarios the
//! grammar was derived from; `v13-4-2` exercises the downgrade path for a
//! version the grammar was *not* derived from.
//!
//! Encoding fixtures are byte-sensitive (UTF-8 BOM, CRLF, UTF-16LE) and are
//! loaded with `include_bytes!` so the crate's own decoding boundary is what is
//! under test.

use cmtraceopen_parser::intune::portal::windows::company_portal::logs::*;
use cmtraceopen_parser::models::log_entry::{
    LogFormat, ParseQuality, ParserImplementation, ParserKind, ParserProvenance, RecordFraming,
    Severity,
};
use cmtraceopen_parser::parser::{decode_bytes, detect_encoding, parse_content, FileEncoding};

/// `%LOCALAPPDATA%\Packages\Microsoft.CompanyPortal_8wekyb3d8bbwe\LocalState`.
const LOCAL_STATE: &str =
    "C:/Users/adele.vance/AppData/Local/Packages/Microsoft.CompanyPortal_8wekyb3d8bbwe/LocalState";

fn local_state_path(file_name: &str) -> String {
    format!("{LOCAL_STATE}/{file_name}")
}

/// Run a fixture through the full public pipeline: detection, then parsing.
fn parse_fixture(
    file_name: &str,
    content: &str,
) -> (
    cmtraceopen_parser::models::log_entry::ParseResult,
    cmtraceopen_parser::parser::ResolvedParser,
) {
    let path = local_state_path(file_name);
    parse_content(content, &path, content.len() as u64)
}

fn document(file_name: &str, content: &str) -> CompanyPortalLogDocument {
    parse_log_document(&local_state_path(file_name), content)
}

// ---------------------------------------------------------------------------
// 1. information / warning / error records
// ---------------------------------------------------------------------------

const SEVERITY_LEVELS: &str =
    include_str!("fixtures/intune/portal/windows/logs/v12-0-0/severity-levels/Log_1.log");

#[test]
fn portal_logs_severity_fixture_covers_every_documented_level() {
    let (result, _) = parse_fixture("Log_1.log", SEVERITY_LEVELS);
    assert_eq!(result.entries.len(), 6, "severity fixture rows");
    assert_eq!(result.parse_errors, 0);

    let severities: Vec<Severity> = result.entries.iter().map(|entry| entry.severity).collect();
    assert_eq!(
        severities,
        vec![
            Severity::Info,    // INFO
            Severity::Warning, // WARNING
            Severity::Error,   // ERROR
            Severity::Info,    // VERBOSE
            Severity::Info,    // INFO whose message says "failed"
            Severity::Error,   // NOTICE — unknown token, inferred from "error"
        ]
    );
}

#[test]
fn portal_logs_dedicated_severity_beats_keyword_inference() {
    let (result, _) = parse_fixture("Log_1.log", SEVERITY_LEVELS);

    let entry = &result.entries[4];
    assert!(entry.message.contains("failed"));
    assert_eq!(
        entry.severity,
        Severity::Info,
        "the record's own severity field must win over the word 'failed'"
    );
}

#[test]
fn portal_logs_unknown_severity_token_is_preserved_in_the_document() {
    let document = document("Log_1.log", SEVERITY_LEVELS);
    let severity = document.records[5]
        .severity
        .as_ref()
        .expect("record must carry its severity field");

    assert_eq!(severity.raw_text, "NOTICE");
    assert_eq!(severity.level, CompanyPortalSeverityLevel::Unknown);
}

// ---------------------------------------------------------------------------
// 2. multiline continuation
// ---------------------------------------------------------------------------

const MULTILINE: &str =
    include_str!("fixtures/intune/portal/windows/logs/v12-0-0/multiline-continuation/Log_1.log");

#[test]
fn portal_logs_continuation_lines_join_the_record_above() {
    let (result, selection) = parse_fixture("Log_1.log", MULTILINE);

    assert_eq!(selection.record_framing, RecordFraming::LogicalRecord);
    assert_eq!(result.entries.len(), 3, "three records, six physical lines");
    assert_eq!(result.parse_errors, 0);

    let failure = &result.entries[1];
    assert_eq!(failure.line_number, 2, "record keeps its first line number");
    assert!(failure.message.contains("HttpRequestException"));
    assert!(failure
        .message
        .contains("   at Contoso.Sample.PortalClient.CatalogClient.GetAppsAsync()"));
    assert_eq!(result.entries[2].line_number, 6);
}

#[test]
fn portal_logs_continuation_text_is_byte_identical_to_the_source() {
    let document = document("Log_1.log", MULTILINE);
    let record = &document.records[1];

    for line in MULTILINE.lines().skip(2).take(3) {
        assert!(
            record.raw_text.contains(line.trim_end()),
            "continuation line must survive verbatim: {line}"
        );
    }
}

// ---------------------------------------------------------------------------
// 3. current plus rotated files
// ---------------------------------------------------------------------------

const ROTATION_CURRENT: &str =
    include_str!("fixtures/intune/portal/windows/logs/v12-0-0/rotation/Log_1.log");
const ROTATION_ROLLED: &str =
    include_str!("fixtures/intune/portal/windows/logs/v12-0-0/rotation/Log_2.log");

#[test]
fn portal_logs_rotation_members_keep_distinct_identities() {
    let current = document("Log_1.log", ROTATION_CURRENT);
    let rolled = document("Log_2.log", ROTATION_ROLLED);

    assert_eq!(current.file.kind, CompanyPortalLogFileKind::App);
    assert_eq!(current.file.rotation_index, Some(1));
    assert_eq!(rolled.file.rotation_index, Some(2));
    assert_ne!(current.records[0].record_id, rolled.records[0].record_id);
}

#[test]
fn portal_logs_repeated_record_across_rotation_is_not_deduplicated() {
    let current = document("Log_1.log", ROTATION_CURRENT);
    let rolled = document("Log_2.log", ROTATION_ROLLED);

    let boundary = "[Sync] rollover boundary record";
    assert!(current
        .records
        .iter()
        .any(|record| record.message.contains(boundary)));
    assert!(rolled
        .records
        .iter()
        .any(|record| record.message.contains(boundary)));
    assert_eq!(current.records.len(), 2);
    assert_eq!(rolled.records.len(), 2);
}

#[test]
fn portal_logs_bridge_file_identity_is_preserved() {
    let bridge = document("Log.ConfigurationManagerBridge_1.log", ROTATION_CURRENT);

    assert_eq!(bridge.file.kind, CompanyPortalLogFileKind::Bridge);
    assert_eq!(
        bridge.file.bridge_name.as_deref(),
        Some("ConfigurationManagerBridge")
    );
}

// ---------------------------------------------------------------------------
// 4. same timestamp, distinct activity ids
// ---------------------------------------------------------------------------

const SAME_TIMESTAMP: &str = include_str!(
    "fixtures/intune/portal/windows/logs/v12-0-0/same-timestamp-distinct-activity/Log_1.log"
);

#[test]
fn portal_logs_identical_timestamps_stay_separate_activities() {
    let document = document("Log_1.log", SAME_TIMESTAMP);
    assert_eq!(document.records.len(), 2);

    let first = &document.records[0];
    let second = &document.records[1];

    assert_eq!(
        first.timestamp.as_ref().map(|ts| ts.raw_text.as_str()),
        second.timestamp.as_ref().map(|ts| ts.raw_text.as_str())
    );
    assert_ne!(first.activity_id, second.activity_id);
    assert_ne!(first.record_id, second.record_id);
    assert_eq!(first.scenario.as_deref(), Some("SignIn"));
    assert_eq!(second.scenario.as_deref(), Some("DeviceSync"));
}

// ---------------------------------------------------------------------------
// 5. known and unknown code tokens
// ---------------------------------------------------------------------------

const CODE_TOKENS: &str =
    include_str!("fixtures/intune/portal/windows/logs/v12-0-0/code-tokens/Log_1.log");

#[test]
fn portal_logs_known_and_unknown_code_tokens_are_both_preserved() {
    let (result, _) = parse_fixture("Log_1.log", CODE_TOKENS);
    assert_eq!(result.entries.len(), 2);

    assert!(result.entries[0].message.contains("0x80070005"));
    assert!(result.entries[1].message.contains("0x0ABCDEF1"));

    // A known code gains a lookup span; an unknown code is left as text rather
    // than being resolved to a guess.
    assert_eq!(result.entries[0].error_code_spans.len(), 1);
    assert_eq!(result.entries[0].error_code_spans[0].code_hex, "0x80070005");
    assert!(result.entries[1].error_code_spans.is_empty());
}

// ---------------------------------------------------------------------------
// 6. invalid timestamp
// ---------------------------------------------------------------------------

const INVALID_TIMESTAMP: &str =
    include_str!("fixtures/intune/portal/windows/logs/v12-0-0/invalid-timestamp/Log_1.log");

#[test]
fn portal_logs_invalid_timestamp_is_preserved_as_a_parse_error() {
    let (result, _) = parse_fixture("Log_1.log", INVALID_TIMESTAMP);

    assert_eq!(result.entries.len(), 3);
    assert_eq!(result.parse_errors, 1);

    let broken = &result.entries[1];
    assert_eq!(broken.message, INVALID_TIMESTAMP.lines().nth(1).unwrap());
    assert_eq!(broken.format, LogFormat::Plain);
    assert!(broken.timestamp.is_none());
    assert!(broken.timestamp_display.is_none());

    // The records either side of it still parse.
    assert!(result.entries[0].timestamp.is_some());
    assert!(result.entries[2].timestamp.is_some());
}

#[test]
fn portal_logs_invalid_timestamp_becomes_coverage_not_absence() {
    let document = document("Log_1.log", INVALID_TIMESTAMP);

    assert_eq!(
        document.records[1].parse_state,
        CompanyPortalParseState::Malformed
    );
    assert_eq!(
        document.coverage[0].status,
        CompanyPortalCoverageStatus::ParseFailed
    );
    assert_eq!(
        document.coverage[0].artifact_id,
        "companyPortal.windows.logs"
    );
}

#[test]
fn portal_logs_empty_input_is_not_available_coverage() {
    let document = document("Log_1.log", "");

    assert!(document.records.is_empty());
    assert_eq!(
        document.coverage[0].status,
        CompanyPortalCoverageStatus::ParseFailed,
        "zero parsed records must never be reported as available coverage"
    );
}

// ---------------------------------------------------------------------------
// 7. truncated first and last records
// ---------------------------------------------------------------------------

const TRUNCATED: &str =
    include_str!("fixtures/intune/portal/windows/logs/v12-0-0/truncated-boundaries/Log_1.log");

#[test]
fn portal_logs_truncated_boundaries_are_preserved_losslessly() {
    let document = document("Log_1.log", TRUNCATED);
    assert_eq!(document.records.len(), 3);

    // Leading fragment of a rotated file — no record ever started it.
    assert_eq!(
        document.records[0].parse_state,
        CompanyPortalParseState::Orphaned
    );
    assert_eq!(
        document.records[0].raw_text,
        "alog client because the previous file reached its size limit)"
    );

    assert_eq!(
        document.records[1].parse_state,
        CompanyPortalParseState::Parsed
    );

    // Trailing record cut off mid-activity-id.
    assert_eq!(
        document.records[2].parse_state,
        CompanyPortalParseState::Malformed
    );
    assert_eq!(
        document.records[2].raw_text,
        TRUNCATED.lines().nth(2).unwrap()
    );
}

#[test]
fn portal_logs_truncated_boundaries_report_two_parse_errors() {
    let (result, _) = parse_fixture("Log_1.log", TRUNCATED);
    assert_eq!(result.parse_errors, 2);
    assert_eq!(result.entries.len(), 3);
}

// ---------------------------------------------------------------------------
// 8. malformed structural token
// ---------------------------------------------------------------------------

const MALFORMED_TOKEN: &str = include_str!(
    "fixtures/intune/portal/windows/logs/v12-0-0/malformed-structural-token/Log_1.log"
);

#[test]
fn portal_logs_malformed_structural_tokens_do_not_produce_derived_fields() {
    let document = document("Log_1.log", MALFORMED_TOKEN);
    assert_eq!(document.records.len(), 3);

    // A 35-character activity id and a dotted version are both structural
    // failures; neither may yield a half-parsed record.
    for index in [1usize, 2usize] {
        let record = &document.records[index];
        assert_eq!(
            record.parse_state,
            CompanyPortalParseState::Malformed,
            "record {index}"
        );
        assert!(record.activity_id.is_none(), "record {index}");
        assert!(record.app_version.is_none(), "record {index}");
        assert!(record.severity.is_none(), "record {index}");
        assert_eq!(
            record.raw_text,
            MALFORMED_TOKEN.lines().nth(index).unwrap(),
            "record {index}"
        );
    }
}

// ---------------------------------------------------------------------------
// 9. encodings: UTF-8 BOM, UTF-8 no BOM, UTF-16LE
// ---------------------------------------------------------------------------

const UTF8_BOM: &[u8] =
    include_bytes!("fixtures/intune/portal/windows/logs/v12-0-0/encoding-utf8-bom/Log_1.log");
const UTF8_NO_BOM: &[u8] =
    include_bytes!("fixtures/intune/portal/windows/logs/v12-0-0/encoding-utf8-nobom/Log_1.log");
const UTF16_LE: &[u8] =
    include_bytes!("fixtures/intune/portal/windows/logs/v12-0-0/encoding-utf16le/Log_1.log");

fn decode(bytes: &[u8]) -> String {
    let encoding = detect_encoding(bytes);
    decode_bytes(bytes, encoding).expect("fixture must decode")
}

#[test]
fn portal_logs_encoding_fixtures_carry_the_bytes_they_claim() {
    assert_eq!(&UTF8_BOM[..3], &[0xEF, 0xBB, 0xBF]);
    assert_ne!(&UTF8_NO_BOM[..3], &[0xEF, 0xBB, 0xBF]);
    assert_eq!(&UTF16_LE[..2], &[0xFF, 0xFE]);
    assert_eq!(detect_encoding(UTF8_BOM), FileEncoding::Utf8);
    assert_eq!(detect_encoding(UTF8_NO_BOM), FileEncoding::Utf8);
    assert_eq!(detect_encoding(UTF16_LE), FileEncoding::Utf16Le);
}

#[test]
fn portal_logs_are_detected_and_parsed_identically_across_encodings() {
    for (label, bytes) in [
        ("utf-8 with BOM", UTF8_BOM),
        ("utf-8 without BOM", UTF8_NO_BOM),
        ("utf-16le", UTF16_LE),
    ] {
        let content = decode(bytes);
        let (result, selection) = parse_fixture("Log_1.log", &content);

        assert_eq!(selection.parser, ParserKind::CompanyPortal, "{label}");
        assert_eq!(result.parse_errors, 0, "{label}");
        assert_eq!(result.entries.len(), 2, "{label}");
        assert!(
            result.entries[0].message.contains("resumé"),
            "non-ASCII text must survive: {label}"
        );
        assert_eq!(
            result.entries[0].timestamp_display.as_deref(),
            Some("2026-05-04 15:00:00.100"),
            "{label}"
        );
    }
}

// ---------------------------------------------------------------------------
// 10 & 11. negatives — detection must not claim every Log_<n>.log
// ---------------------------------------------------------------------------

const NEGATIVE_UWP: &str =
    include_str!("fixtures/intune/portal/windows/logs/v12-0-0/negative-unrelated-uwp/Log_1.log");
const NEGATIVE_GENERIC: &str = include_str!(
    "fixtures/intune/portal/windows/logs/v12-0-0/negative-generic-timestamped/Log_1.log"
);

#[test]
fn portal_logs_unrelated_uwp_log_file_does_not_false_positive() {
    // Same file name, same package layout, aligned columns and ISO instants —
    // refused because field 6 is not a GUID and field 7 is not a version triple.
    let path = "C:/Users/adele.vance/AppData/Local/Packages/Contoso.SampleApp_1a2b3c4d5e6f7/LocalState/Log_1.log";
    let (_, selection) = parse_content(NEGATIVE_UWP, path, NEGATIVE_UWP.len() as u64);

    assert_eq!(selection.parser, ParserKind::Timestamped);
    assert_eq!(
        selection.implementation,
        ParserImplementation::GenericTimestamped
    );
}

#[test]
fn portal_logs_unrelated_uwp_log_is_refused_even_inside_the_company_portal_folder() {
    // The strongest form of the guarantee: the exact package path plus the
    // exact file name still is not enough without confirming record structure.
    let (_, selection) = parse_fixture("Log_1.log", NEGATIVE_UWP);
    assert_eq!(selection.parser, ParserKind::Timestamped);
}

#[test]
fn portal_logs_generic_timestamped_log_does_not_false_positive() {
    let (_, selection) = parse_fixture("Log_1.log", NEGATIVE_GENERIC);
    assert_eq!(selection.parser, ParserKind::Timestamped);
}

#[test]
fn portal_logs_negative_fixtures_contain_no_confirmed_record() {
    for content in [NEGATIVE_UWP, NEGATIVE_GENERIC] {
        for line in content.lines() {
            assert!(
                !matches_company_portal_log_record(line.trim_end()),
                "negative fixture line must not match: {line}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 12. redaction of synthetic UPN / tenant / device / token values
// ---------------------------------------------------------------------------

const REDACTION: &str =
    include_str!("fixtures/intune/portal/windows/logs/v12-0-0/redaction/Log_1.log");

/// Synthetic sensitive values planted in the redaction fixture.
const SENSITIVE_VALUES: [&str; 6] = [
    "adele.vance@contoso.onmicrosoft.com",
    "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.SYNTHETIC.SIGNATURE",
    "SYNTHETIC-SERIAL-0F1E2D",
    "adele.vance",
    "203.0.113.10",
];

#[test]
fn portal_logs_document_is_redacted_by_default() {
    let document = document("Log_1.log", REDACTION);
    assert!(document.redacted);

    let json = serde_json::to_string(&document).expect("document must serialize");
    for value in SENSITIVE_VALUES {
        assert!(
            !json.contains(value),
            "redacted document still contains {value}"
        );
    }
}

#[test]
fn portal_logs_untrusted_severity_text_is_redacted_from_default_evidence() {
    const SENSITIVE_SEVERITY: &str = "adele.vance@contoso.onmicrosoft.com";
    let content = format!(
        "2026-05-04T16:00:00.1000000Z  {SENSITIVE_SEVERITY}  Event  None  0  \
         1a2b3c4d-0001-4000-8000-000000000001  12-0-0  safe message\n"
    );

    let local =
        parse_log_document_preserving_local_values(&local_state_path("Log_1.log"), &content);
    let local_severity = local.records[0]
        .severity
        .as_ref()
        .expect("record must preserve its dedicated severity field");
    assert_eq!(local_severity.raw_text, SENSITIVE_SEVERITY);
    assert_eq!(local_severity.level, CompanyPortalSeverityLevel::Unknown);

    let safe = parse_log_document(&local_state_path("Log_1.log"), &content);
    let safe_json = serde_json::to_string(&safe).expect("document must serialize");

    assert!(safe.redacted);
    assert!(!safe_json.contains(SENSITIVE_SEVERITY));
    assert_eq!(
        safe.records[0]
            .severity
            .as_ref()
            .expect("redaction must retain the typed severity field")
            .level,
        CompanyPortalSeverityLevel::Unknown
    );
}

#[test]
fn portal_logs_local_projection_is_the_explicit_opt_out() {
    let local =
        parse_log_document_preserving_local_values(&local_state_path("Log_1.log"), REDACTION);
    assert!(!local.redacted);

    let original_json = serde_json::to_string(&local).expect("document must serialize");
    assert!(original_json.contains("adele.vance@contoso.onmicrosoft.com"));

    // And the redacting projection over the same input drops everything.
    let safe = redacted_export_projection(&local);
    let safe_json = serde_json::to_string(&safe).expect("document must serialize");
    for value in SENSITIVE_VALUES {
        assert!(!safe_json.contains(value), "{value}");
    }
    assert!(!local.redacted, "projection must not mutate its input");
    assert_eq!(
        serde_json::to_string(&local).expect("local document still serializes"),
        original_json,
        "redacted export must not mutate any local document content"
    );
}

#[test]
fn portal_logs_redaction_keeps_records_correlatable() {
    let document = document("Log_1.log", REDACTION);

    assert_eq!(document.records.len(), 4);
    assert_eq!(
        document.records[0].activity_id.as_deref(),
        Some("1a2b3c4d-0001-4000-8000-000000000001")
    );
    assert_eq!(document.records[0].component.as_deref(), Some("SignIn"));
    assert_eq!(
        document.records[0]
            .timestamp
            .as_ref()
            .map(|ts| ts.raw_text.as_str()),
        Some("2026-05-04T16:00:00.1000000Z")
    );
}

#[test]
fn portal_logs_viewer_entries_are_not_redacted() {
    // The viewer must show the file the user opened; redaction belongs to the
    // evidence/export projection, not to local rendering.
    let (result, _) = parse_fixture("Log_1.log", REDACTION);
    assert!(result.entries[0]
        .message
        .contains("adele.vance@contoso.onmicrosoft.com"));
}

// ---------------------------------------------------------------------------
// 13. unknown app-version downgrade
// ---------------------------------------------------------------------------

const UNKNOWN_VERSION: &str =
    include_str!("fixtures/intune/portal/windows/logs/v13-4-2/unknown-app-version/Log_1.log");

#[test]
fn portal_logs_unknown_app_version_downgrades_instead_of_guessing() {
    let (result, selection) = parse_fixture("Log_1.log", UNKNOWN_VERSION);

    // Still claimed and still parsed with the only grammar there is …
    assert_eq!(selection.parser, ParserKind::CompanyPortal);
    assert_eq!(
        selection.implementation,
        ParserImplementation::CompanyPortal
    );
    assert_eq!(result.parse_errors, 0);
    assert_eq!(result.entries.len(), 2);
    // … but the selection is heuristic rather than a validated read.
    assert_eq!(selection.provenance, ParserProvenance::Heuristic);
}

#[test]
fn portal_logs_unknown_app_version_is_named_in_the_document_and_its_coverage() {
    let document = document("Log_1.log", UNKNOWN_VERSION);

    assert_eq!(
        document.grammar_support,
        CompanyPortalGrammarSupport::Experimental
    );
    assert_eq!(document.confidence, CompanyPortalConfidence::Low);
    assert_eq!(document.grammar_version, CompanyPortalGrammarVersion::V1);

    let app_version = document.records[0]
        .app_version
        .as_ref()
        .expect("record must carry its app version");
    assert_eq!(app_version.raw_text, "13-4-2");
    assert_eq!(app_version.triple.major, 13);
    assert_eq!(
        app_version.support,
        CompanyPortalGrammarSupport::Experimental
    );

    let gap = document
        .coverage
        .iter()
        .find(|row| row.artifact_id == "companyPortal.windows.logs.grammar")
        .expect("an unvalidated app version must be named in coverage");
    assert_eq!(gap.status, CompanyPortalCoverageStatus::Unsupported);
}

#[test]
fn portal_logs_validated_app_version_is_medium_confidence_never_high() {
    let document = document("Log_1.log", SEVERITY_LEVELS);

    assert_eq!(
        document.grammar_support,
        CompanyPortalGrammarSupport::Validated
    );
    // One published app version is not enough for `High`.
    assert_eq!(document.confidence, CompanyPortalConfidence::Medium);
    assert!(document
        .coverage
        .iter()
        .all(|row| row.artifact_id != "companyPortal.windows.logs.grammar"));
}

// ---------------------------------------------------------------------------
// Cross-cutting contracts
// ---------------------------------------------------------------------------

#[test]
fn portal_logs_selection_contract_is_stable() {
    let (result, selection) = parse_fixture("Log_1.log", SEVERITY_LEVELS);
    let info = selection.to_info();

    assert_eq!(selection.parser, ParserKind::CompanyPortal);
    assert_eq!(
        selection.implementation,
        ParserImplementation::CompanyPortal
    );
    assert_eq!(selection.provenance, ParserProvenance::Dedicated);
    assert_eq!(selection.parse_quality, ParseQuality::Structured);
    assert_eq!(selection.record_framing, RecordFraming::LogicalRecord);
    assert_eq!(selection.specialization, None);
    assert_eq!(info.date_order, None);
    assert_eq!(result.format_detected, LogFormat::Timestamped);
}

#[test]
fn portal_logs_document_schema_version_is_pinned() {
    let document = document("Log_1.log", SEVERITY_LEVELS);
    let value = serde_json::to_value(&document).expect("document must serialize");

    assert_eq!(value["schemaVersion"], 1);
    assert_eq!(COMPANY_PORTAL_WINDOWS_LOGS_SCHEMA_VERSION, 1);
    assert_eq!(value["grammarVersion"], "v1");
    assert_eq!(value["records"][0]["parseState"], "parsed");
    assert_eq!(value["file"]["kind"], "app");
}

#[test]
fn portal_logs_nested_configmgr_trace_text_is_never_reinterpreted() {
    // The published record's message embeds a legacy ConfigMgr trace line whose
    // date is day-first. It stays message text: the record timestamp is field 1
    // and the inner date is not touched.
    let published = "2024-11-15T16:50:07.2850341Z  INFO  Event        None                      0  1487dc30-3bb0-46bf-98ee-76771bd9953e  12-0-0  [Configuration Manager Trace Listener] 15/11/2024 16:50:07: SCClient Information: 1: Getting all instances of CCM_Application    (Microsoft.SoftwareCenter.Client.Data.Shared.WmiDataConnectorShared at GetAllApplicationsWithType)";
    let document = document("Log_1.log", published);
    let record = &document.records[0];

    assert_eq!(
        record.timestamp.as_ref().map(|ts| ts.raw_text.as_str()),
        Some("2024-11-15T16:50:07.2850341Z")
    );
    assert!(record.message.contains("15/11/2024 16:50:07:"));
    assert!(record.message.contains("SCClient Information: 1:"));
    assert!(record.message.contains(
        "CCM_Application    (Microsoft.SoftwareCenter.Client.Data.Shared.WmiDataConnectorShared at GetAllApplicationsWithType)"
    ));
    assert!(published.ends_with(&record.message));
    assert_eq!(
        record.component.as_deref(),
        Some("Configuration Manager Trace Listener")
    );
}

#[test]
fn portal_logs_every_fixture_line_survives_into_a_record() {
    // Lossless-by-construction check across the whole matrix: no non-empty
    // source line may be dropped.
    for (label, content) in [
        ("severity-levels", SEVERITY_LEVELS),
        ("multiline-continuation", MULTILINE),
        ("rotation/Log_1", ROTATION_CURRENT),
        ("rotation/Log_2", ROTATION_ROLLED),
        ("same-timestamp", SAME_TIMESTAMP),
        ("code-tokens", CODE_TOKENS),
        ("invalid-timestamp", INVALID_TIMESTAMP),
        ("truncated-boundaries", TRUNCATED),
        ("malformed-structural-token", MALFORMED_TOKEN),
        ("redaction", REDACTION),
        ("unknown-app-version", UNKNOWN_VERSION),
    ] {
        let local =
            parse_log_document_preserving_local_values(&local_state_path("Log_1.log"), content);
        let joined = local
            .records
            .iter()
            .map(|record| record.raw_text.as_str())
            .collect::<Vec<_>>()
            .join("\n");

        for line in content.lines().filter(|line| !line.trim().is_empty()) {
            assert!(
                joined.contains(line.trim_end()),
                "{label}: line was lost: {line}"
            );
        }
    }
}
