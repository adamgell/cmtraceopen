use cmtraceopen_parser::models::log_entry::{LogFormat, ParserKind};
use cmtraceopen_parser::parser::detect::detect_parser;
use cmtraceopen_parser::sccm::{
    classify_artifact_name, declared_source_catalog, extract_signals, normalize_ccm_artifact,
    SccmArtifact, SccmArtifactFamily, SccmCoverageState, SccmFindingClass, SccmRole, SccmRotation,
    SccmSignalKind, SccmTimeOrderingState, SccmUnknownRotation, SCCM_DIAGNOSTICS_SCHEMA_VERSION,
};

fn client_policy_artifact() -> SccmArtifact {
    SccmArtifact {
        artifact_id: "client-policy-agent".into(),
        display_name: "PolicyAgent.log".into(),
        original_path: Some(r"C:\Windows\CCM\Logs\PolicyAgent.log".into()),
        host: Some("LAB-CLIENT-01".into()),
        role: SccmRole::Client,
        configmgr_version: Some("5.00.9128.1007".into()),
        collected_at_utc: Some("2026-07-30T15:00:00Z".into()),
        rotation: SccmRotation::Current,
        coverage: SccmCoverageState::Captured,
        encoding: Some("utf-8".into()),
    }
}

fn json_value_contains_sensitive(value: &serde_json::Value, sensitive: &str) -> bool {
    match value {
        serde_json::Value::String(value) => value.contains(sensitive),
        serde_json::Value::Array(values) => values
            .iter()
            .any(|value| json_value_contains_sensitive(value, sensitive)),
        serde_json::Value::Object(values) => values
            .values()
            .any(|value| json_value_contains_sensitive(value, sensitive)),
        _ => false,
    }
}

fn public_json_contains_sensitive(json: &str, sensitive: &str) -> bool {
    let decoded: serde_json::Value = serde_json::from_str(json).unwrap();
    let encoded = serde_json::to_string(sensitive).unwrap();
    let escaped = &encoded[1..encoded.len() - 1];

    json_value_contains_sensitive(&decoded, sensitive) || json.contains(escaped)
}

fn assert_public_json_omits(json: &str, sensitive: &str) {
    assert!(
        !public_json_contains_sensitive(json, sensitive),
        "{sensitive} leaked in decoded or escaped public JSON"
    );
}

#[test]
fn sccm_contract_is_public_and_versioned() {
    assert_eq!(SCCM_DIAGNOSTICS_SCHEMA_VERSION, 1);
    let artifact = SccmArtifact::missing(
        "client-policy-agent",
        "PolicyAgent.log",
        SccmRole::Client,
        SccmCoverageState::Absent,
    );
    assert_eq!(artifact.coverage, SccmCoverageState::Absent);
    assert_eq!(
        SccmFindingClass::InsufficientEvidence.as_str(),
        "insufficientEvidence"
    );
}

#[test]
fn public_ccm_multiline_projection_stays_compatible() {
    let text = include_str!("fixtures/sccm/spine/multiline-policy.log");
    let (entries, errors) =
        cmtraceopen_parser::parser::ccm::parse_content(text, "PolicyAgent.log", None);
    assert_eq!(errors, 0);
    assert_eq!(
        entries.len(),
        1,
        "ordinary public CCM output stays unchanged"
    );
    assert_eq!(entries[0].line_number, 1);
    assert_eq!(entries[0].format, LogFormat::Ccm);
    assert_eq!(entries[0].timezone_offset, Some(-240));
    assert!(entries[0]
        .message
        .contains("{11111111-1111-1111-1111-111111111111}"));

    let public_json = serde_json::to_value(&entries[0]).unwrap();
    assert!(public_json.get("context").is_none());
    assert!(!serde_json::to_string(&public_json)
        .unwrap()
        .contains(r"NT AUTHORITY\\SYSTEM"));
}

#[test]
fn public_ccm_single_line_projection_matches_line_parser() {
    let text = r#"<![LOG[Synthetic policy record]LOG]!><time="10:00:00.000-240" date="07-30-2026" component="PolicyAgent" context="LAB\SyntheticUser" type="1" thread="42" file="policyagent.cpp">"#;
    let (content_entries, content_errors) =
        cmtraceopen_parser::parser::ccm::parse_content(text, "PolicyAgent.log", None);
    let (line_entries, line_errors) =
        cmtraceopen_parser::parser::ccm::parse_lines(&[text], "PolicyAgent.log");

    assert_eq!(content_errors, line_errors);
    assert_eq!(
        serde_json::to_vec(&content_entries).unwrap(),
        serde_json::to_vec(&line_entries).unwrap()
    );
}

#[test]
fn signal_extractor_preserves_known_hresult_and_error_db_metadata() {
    let signals = extract_signals("Download failed with hr=0x80070005");

    assert_eq!(signals.len(), 1);
    assert_eq!(signals[0].kind, SccmSignalKind::HResult);
    assert_eq!(signals[0].raw, "0x80070005");
    assert_eq!(signals[0].numeric, Some(0x80070005));
    assert!(signals[0].error_description.is_some());
    assert!(signals[0].error_category.is_some());
}

#[test]
fn signal_extractor_preserves_unknown_exit_and_gle_values() {
    let signals = extract_signals("exit code 1603; [gle=0xDEADBEEF]; status=71");

    assert_eq!(
        signals
            .iter()
            .map(|signal| (&signal.kind, signal.raw.as_str()))
            .collect::<Vec<_>>(),
        vec![
            (&SccmSignalKind::ExitCode, "1603"),
            (&SccmSignalKind::Gle, "0xDEADBEEF"),
            (&SccmSignalKind::Status, "71"),
        ]
    );
    assert!(signals
        .iter()
        .all(|signal| signal.error_description.is_none() || !signal.raw.is_empty()));
    assert_eq!(signals[1].numeric, Some(0xDEADBEEF));
    assert_eq!(signals[1].error_description, None);
    assert_eq!(signals[1].error_category, None);
}

#[test]
fn signal_extractor_supports_only_the_declared_structured_forms() {
    let signals = extract_signals(
        "HRESULT 0x80004005; exitCode = 1618; return code 3010; \
         unstructured 0x80070005; id={80070005-1111-2222-3333-444444444444}",
    );

    assert_eq!(
        signals
            .iter()
            .map(|signal| (&signal.kind, signal.raw.as_str()))
            .collect::<Vec<_>>(),
        vec![
            (&SccmSignalKind::HResult, "0x80004005"),
            (&SccmSignalKind::ExitCode, "1618"),
            (&SccmSignalKind::ReturnCode, "3010"),
        ]
    );
}

#[test]
fn signal_extractor_uses_utf16_spans_and_preserves_repeated_tokens() {
    let message = "😀 hr=0x80070005 then hr=0x80070005";
    let signals = extract_signals(message);

    assert_eq!(signals.len(), 2);
    assert_eq!(signals[0].raw, signals[1].raw);
    assert_ne!(
        (signals[0].start, signals[0].end),
        (signals[1].start, signals[1].end)
    );
    assert_eq!((signals[0].start, signals[0].end), (6, 16));
    assert_eq!(
        message
            .encode_utf16()
            .skip(signals[0].start)
            .take(signals[0].end - signals[0].start)
            .collect::<Vec<_>>(),
        "0x80070005".encode_utf16().collect::<Vec<_>>()
    );
}

#[test]
fn signal_extractor_is_deterministic_and_serializes_camel_case() {
    let message = "HRESULT 0x80004005; status=4294967296";
    let first = extract_signals(message);
    let second = extract_signals(message);

    assert_eq!(first, second);
    assert_eq!(first[1].raw, "4294967296");
    assert_eq!(first[1].numeric, None);
    assert_eq!(first[1].error_description, None);

    let json = serde_json::to_value(&first).unwrap();
    assert_eq!(json[0]["kind"], "hResult");
    assert_eq!(json[0]["raw"], "0x80004005");
    assert!(json[0]["errorDescription"].is_string());
    assert!(json[0]["errorCategory"].is_string());
    assert!(json[0]["start"].is_number());
    assert!(json[0]["end"].is_number());
}

#[test]
fn public_ccm_malformed_continuation_stays_plain() {
    let text = "<![LOG[unfinished record\ncontinuation without attributes";
    let (entries, errors) =
        cmtraceopen_parser::parser::ccm::parse_content(text, "PolicyAgent.log", None);

    assert_eq!(errors, 2);
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].format, LogFormat::Plain);
    assert_eq!(entries[0].line_number, 1);
    assert_eq!(entries[1].format, LogFormat::Plain);
    assert_eq!(entries[1].line_number, 2);
}

#[test]
fn public_ccm_digit_only_timestamp_tails_match_pre_spine_baseline() {
    // Commit 463133d's public regex greedily assigned all but the final digit
    // to milliseconds and the final digit to timezoneOffset. Preserve that
    // observable LogEntry behavior while SCCM provenance interprets the same
    // captured tail independently.
    let cases = [
        (
            "000",
            "07-30-2026 10:00:00.000",
            0,
            0,
            "07-30-2026 10:00:00.000",
            None,
            SccmTimeOrderingState::OffsetMissing,
        ),
        (
            "123",
            "07-30-2026 10:00:00.012",
            12,
            3,
            "07-30-2026 10:00:00.123",
            None,
            SccmTimeOrderingState::OffsetMissing,
        ),
        (
            "000240",
            "07-30-2026 10:00:00.000",
            0,
            0,
            "07-30-2026 10:00:00.000",
            Some(240),
            SccmTimeOrderingState::NormalizedUtc,
        ),
        (
            "1234567",
            "07-30-2026 10:00:00.123",
            123,
            7,
            "07-30-2026 10:00:00.1234567",
            None,
            SccmTimeOrderingState::OffsetMissing,
        ),
    ];

    for (
        time_tail,
        public_display,
        public_millis,
        public_offset,
        evidence_display,
        evidence_offset,
        evidence_state,
    ) in cases
    {
        let text = format!(
            r#"<![LOG[Tail {time_tail}]LOG]!><time="10:00:00.{time_tail}" date="07-30-2026" component="PolicyAgent" context="" type="1" thread="42" file="policyagent.cpp">"#
        );
        let (entries, errors) =
            cmtraceopen_parser::parser::ccm::parse_content(&text, "PolicyAgent.log", None);
        let evidence = normalize_ccm_artifact(client_policy_artifact(), &text);
        let expected_public_timestamp = chrono::NaiveDate::from_ymd_opt(2026, 7, 30)
            .unwrap()
            .and_hms_milli_opt(10, 0, 0, public_millis)
            .unwrap()
            .and_utc()
            .timestamp_millis()
            - i64::from(public_offset) * 60_000;

        assert_eq!(errors, 0, "{time_tail}");
        assert_eq!(entries.len(), 1, "{time_tail}");
        assert_eq!(entries[0].format, LogFormat::Ccm, "{time_tail}");
        assert_eq!(
            entries[0].timestamp_display.as_deref(),
            Some(public_display),
            "{time_tail}"
        );
        assert_eq!(
            entries[0].timezone_offset,
            Some(public_offset),
            "{time_tail}"
        );
        assert_eq!(
            entries[0].timestamp,
            Some(expected_public_timestamp),
            "{time_tail}"
        );
        assert_eq!(evidence.len(), 1, "{time_tail}");
        assert_eq!(
            evidence[0].timestamp.original_display.as_deref(),
            Some(evidence_display),
            "{time_tail}"
        );
        assert_eq!(
            evidence[0].timestamp.offset_minutes, evidence_offset,
            "{time_tail}"
        );
        assert_eq!(
            evidence[0].timestamp.ordering_state, evidence_state,
            "{time_tail}"
        );
    }
}

#[test]
fn signless_ccm_offset_is_enriched_only_in_sccm_provenance() {
    // CMTrace's documented `%03u%d` grammar permits the decimal offset to
    // omit a sign: three millisecond digits followed by the offset. The
    // public LogEntry keeps its pre-spine projection; only the additive SCCM
    // timestamp provenance receives the corrected interpretation.
    let text = r#"<![LOG[Signless source offset]LOG]!><time="10:00:00.000240" date="07-30-2026" component="PolicyAgent" context="" type="1" thread="42" file="policyagent.cpp">"#;
    let (entries, errors) =
        cmtraceopen_parser::parser::ccm::parse_content(text, "PolicyAgent.log", None);
    let evidence = normalize_ccm_artifact(client_policy_artifact(), text);

    assert_eq!(errors, 0);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].format, LogFormat::Ccm);
    assert_eq!(entries[0].timezone_offset, Some(0));
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].timestamp.offset_minutes, Some(240));
    assert_eq!(
        evidence[0].timestamp.ordering_state,
        SccmTimeOrderingState::NormalizedUtc
    );
    assert!(evidence[0].timestamp.utc_millis.is_some());
}

#[test]
fn evidence_uses_one_logical_record_and_normalized_utc_ordering() {
    let text = include_str!("fixtures/sccm/spine/multiline-policy.log");
    let evidence = normalize_ccm_artifact(client_policy_artifact(), text);

    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].evidence_id, "client-policy-agent:1-2");
    assert_eq!(evidence[0].reference.entry_id, "client-policy-agent:1-2");
    assert_eq!(evidence[0].reference.artifact_id, "client-policy-agent");
    assert_eq!(evidence[0].reference.line_start, Some(1));
    assert_eq!(evidence[0].reference.line_end, Some(2));
    assert_eq!(
        evidence[0].ccm_source_file.as_deref(),
        Some("policyagent.cpp")
    );
    assert_eq!(
        evidence[0].timestamp.original_display.as_deref(),
        Some("07-30-2026 10:00:00.000")
    );
    assert_eq!(evidence[0].timestamp.offset_minutes, Some(-240));
    assert_eq!(
        evidence[0].timestamp.ordering_state,
        SccmTimeOrderingState::NormalizedUtc
    );
    assert!(evidence[0].timestamp.utc_millis.is_some());
}

#[test]
fn evidence_missing_or_invalid_time_provenance_is_not_comparable() {
    let cases = [
        (
            r#"<![LOG[No source offset]LOG]!><time="10:00:00.1234567" date="07-30-2026" component="PolicyAgent" context="" type="1" thread="42" file="policyagent.cpp">"#,
            SccmTimeOrderingState::OffsetMissing,
            None,
        ),
        (
            r#"<![LOG[Invalid source offset]LOG]!><time="10:00:00.000+99999" date="07-30-2026" component="PolicyAgent" context="" type="1" thread="42" file="policyagent.cpp">"#,
            SccmTimeOrderingState::OffsetInvalid,
            Some(99999),
        ),
        (
            r#"<![LOG[Invalid local date]LOG]!><time="10:00:00.000-240" date="13-40-2026" component="PolicyAgent" context="" type="1" thread="42" file="policyagent.cpp">"#,
            SccmTimeOrderingState::TimestampMissing,
            Some(-240),
        ),
    ];

    for (text, expected_state, expected_offset) in cases {
        let evidence = normalize_ccm_artifact(client_policy_artifact(), text);
        assert_eq!(evidence.len(), 1, "{expected_state:?}");
        assert_eq!(
            evidence[0].timestamp.ordering_state, expected_state,
            "{text}"
        );
        assert_eq!(evidence[0].timestamp.offset_minutes, expected_offset);
        assert_eq!(evidence[0].timestamp.utc_millis, None);
    }
}

#[test]
fn evidence_export_is_deterministic_redacted_and_non_mutating() {
    let text = include_str!("fixtures/sccm/spine/multiline-policy.log");
    let first = normalize_ccm_artifact(client_policy_artifact(), text);
    let before_export = first.clone();
    let first_json = serde_json::to_string(&first).unwrap();
    let second = normalize_ccm_artifact(client_policy_artifact(), text);

    assert_eq!(first, before_export);
    assert_eq!(first, second);
    assert_public_json_omits(&first_json, r"NT AUTHORITY\SYSTEM");
    assert_public_json_omits(&first_json, r"C:\Windows\CCM\Logs");
    assert_eq!(
        first[0].execution_context, None,
        "public export omits unkeyed context handles by default"
    );

    let alternate = r#"<![LOG[Synthetic user context]LOG]!><time="10:00:00.000-240" date="07-30-2026" component="PolicyAgent" context="LAB\SyntheticUser" type="1" thread="42" file="policyagent.cpp">"#;
    let alternate_evidence = normalize_ccm_artifact(client_policy_artifact(), alternate);
    let alternate_json = serde_json::to_string(&alternate_evidence).unwrap();
    assert_public_json_omits(&alternate_json, r"LAB\SyntheticUser");
    assert_eq!(alternate_evidence[0].execution_context, None);
}

#[test]
fn public_json_sensitive_assertion_detects_serde_escaped_backslashes() {
    let leaked = serde_json::json!([{"message": r"LAB\SyntheticUser"}]);
    let json = serde_json::to_string(&leaked).unwrap();

    assert!(json.contains(r"LAB\\SyntheticUser"));
    assert!(public_json_contains_sensitive(&json, r"LAB\SyntheticUser"));
}

#[test]
fn evidence_public_message_projection_redacts_sensitive_markers_and_preserves_safe_tokens() {
    let assignment_id = "{ABCDEFAB-0000-0000-0000-000000000001}";
    let text = format!(
        r#"<![LOG[Policy id={assignment_id} failed hr=0x80070005 user=LAB\SyntheticUser credential="synthetic credential with spaces" token=synthetic-secret]LOG]!><time="10:00:00.000-240" date="07-30-2026" component="PolicyAgent" context="" type="1" thread="42" file="policyagent.cpp">"#
    );

    let first = normalize_ccm_artifact(client_policy_artifact(), &text);
    let second = normalize_ccm_artifact(client_policy_artifact(), &text);
    let message = &first[0].message;
    let json = serde_json::to_string(&first).unwrap();

    assert_eq!(first, second);
    assert!(message.starts_with("[sccm-public-message-v1] "));
    assert!(message.contains(assignment_id));
    assert!(message.contains("hr=0x80070005"));
    for sensitive in [
        r"LAB\SyntheticUser",
        "synthetic credential with spaces",
        "synthetic-secret",
    ] {
        assert!(
            !message.contains(sensitive),
            "{sensitive} leaked in message"
        );
        assert_public_json_omits(&json, sensitive);
    }
    assert!(message.contains("[redacted:sccm-public-message-v1]"));
}

#[test]
fn evidence_public_message_projection_fails_closed_without_path_or_code_false_positives() {
    let assignment_id = "{ABCDEFAB-0000-0000-0000-000000000001}";
    let text = format!(
        r#"<![LOG[Caller LAB\SyntheticUser; Authorization: Bearer synthetic-bearer; client_secret="synthetic; leaked-credential-fragment"; sig=synthetic-signature; clientToken=synthetic-client-token; Path C:\Windows\CCM\Logs\PolicyAgent.log Policy id={assignment_id} status=71]LOG]!><time="10:00:00.000-240" date="07-30-2026" component="PolicyAgent" context="" type="1" thread="42" file="policyagent.cpp">"#
    );

    let evidence = normalize_ccm_artifact(client_policy_artifact(), &text);
    let message = &evidence[0].message;

    assert!(message.starts_with("[sccm-public-message-v1] "));
    assert!(message.contains(r"C:\Windows\CCM\Logs\PolicyAgent.log"));
    assert!(message.contains(assignment_id));
    assert!(message.contains("status=71"));
    for sensitive in [
        r"LAB\SyntheticUser",
        "synthetic-bearer",
        "leaked-credential-fragment",
        "synthetic-signature",
        "synthetic-client-token",
    ] {
        assert!(!message.contains(sensitive), "{sensitive} leaked");
    }
}

#[test]
fn evidence_public_message_projection_redacts_unterminated_sensitive_values_to_end() {
    let assignment_id = "{ABCDEFAB-0000-0000-0000-000000000001}";
    let text = format!(
        r#"<![LOG[Policy id={assignment_id} hr=0x80070005 client_secret="synthetic; leaked-unterminated-tail]LOG]!><time="10:00:00.000-240" date="07-30-2026" component="PolicyAgent" context="" type="1" thread="42" file="policyagent.cpp">"#
    );

    let evidence = normalize_ccm_artifact(client_policy_artifact(), &text);
    let message = &evidence[0].message;

    assert!(message.starts_with("[sccm-public-message-v1] "));
    assert!(message.contains(assignment_id));
    assert!(message.contains("hr=0x80070005"));
    assert!(message.ends_with("[redacted:sccm-public-message-v1]"));
    assert!(!message.contains("leaked-unterminated-tail"));
}

#[test]
fn evidence_public_message_projection_redacts_whitespace_delimited_credentials() {
    let cases = [
        (
            "Authorization Bearer synthetic-auth-token",
            "synthetic-auth-token",
        ),
        (
            r#"Authorization Bearer "synthetic quoted auth token""#,
            "synthetic quoted auth token",
        ),
        (
            "Bearer synthetic-standalone-token",
            "synthetic-standalone-token",
        ),
        (
            "Bearer 'synthetic quoted bearer token'",
            "synthetic quoted bearer token",
        ),
        (
            "client_secret synthetic-client-secret",
            "synthetic-client-secret",
        ),
        (
            r#"client_secret "synthetic quoted client secret""#,
            "synthetic quoted client secret",
        ),
        ("sig synthetic-signature", "synthetic-signature"),
        (
            "clientToken synthetic-client-token",
            "synthetic-client-token",
        ),
        ("credential synthetic-credential", "synthetic-credential"),
        (
            "credential 'synthetic quoted credential'",
            "synthetic quoted credential",
        ),
    ];

    for (raw_message, sensitive) in cases {
        let text = format!(
            r#"<![LOG[{raw_message}]LOG]!><time="10:00:00.000-240" date="07-30-2026" component="PolicyAgent" context="" type="1" thread="42" file="policyagent.cpp">"#
        );
        let evidence = normalize_ccm_artifact(client_policy_artifact(), &text);
        let message = &evidence[0].message;
        let json = serde_json::to_string(&evidence).unwrap();

        assert!(
            !message.contains(sensitive),
            "{sensitive} leaked in projected message for {raw_message}"
        );
        assert_public_json_omits(&json, sensitive);
        assert!(
            message.contains("[redacted:sccm-public-message-v1]"),
            "{raw_message} was not classified as sensitive"
        );
    }
}

#[test]
fn evidence_public_message_projection_redacts_quoted_structured_keys() {
    let cases = [
        (
            r#"payload={"token":"synthetic-json-token","user":"SyntheticJsonUser"} status=71"#,
            ["synthetic-json-token", "SyntheticJsonUser"],
            "status=71",
        ),
        (
            "payload={'password':'synthetic-json-password','user':'SyntheticSingleUser'} hr=0x80070005",
            ["synthetic-json-password", "SyntheticSingleUser"],
            "hr=0x80070005",
        ),
    ];

    for (raw_message, sensitive_values, safe) in cases {
        let text = format!(
            r#"<![LOG[{raw_message}]LOG]!><time="10:00:00.000-240" date="07-30-2026" component="PolicyAgent" context="" type="1" thread="42" file="policyagent.cpp">"#
        );
        let evidence = normalize_ccm_artifact(client_policy_artifact(), &text);
        let message = &evidence[0].message;
        let json = serde_json::to_string(&evidence).unwrap();

        assert!(message.contains(safe), "{safe} was swallowed");
        for sensitive in sensitive_values {
            assert!(!message.contains(sensitive), "{sensitive} leaked");
            assert_public_json_omits(&json, sensitive);
        }
    }
}

#[test]
fn evidence_public_message_projection_bounds_query_values_at_ampersand() {
    let text = r#"<![LOG[url=https://example.invalid/?token=synthetic-query-token&status=71]LOG]!><time="10:00:00.000-240" date="07-30-2026" component="PolicyAgent" context="" type="1" thread="42" file="policyagent.cpp">"#;

    let evidence = normalize_ccm_artifact(client_policy_artifact(), text);
    let message = &evidence[0].message;
    let json = serde_json::to_string(&evidence).unwrap();

    assert!(!message.contains("synthetic-query-token"));
    assert_public_json_omits(&json, "synthetic-query-token");
    assert!(message.contains("&status=71"));
}

#[test]
fn evidence_public_message_projection_fails_closed_for_unterminated_whitespace_values() {
    let cases = [
        (
            r#"Authorization Bearer "synthetic-unterminated-auth"#,
            "synthetic-unterminated-auth",
        ),
        (
            "Bearer 'synthetic-unterminated-bearer",
            "synthetic-unterminated-bearer",
        ),
        (
            r#"client_secret "synthetic-unterminated-client-secret"#,
            "synthetic-unterminated-client-secret",
        ),
        (
            "credential 'synthetic-unterminated-credential",
            "synthetic-unterminated-credential",
        ),
    ];

    for (raw_message, sensitive) in cases {
        let text = format!(
            r#"<![LOG[Policy hr=0x80070005 {raw_message}]LOG]!><time="10:00:00.000-240" date="07-30-2026" component="PolicyAgent" context="" type="1" thread="42" file="policyagent.cpp">"#
        );
        let evidence = normalize_ccm_artifact(client_policy_artifact(), &text);
        let message = &evidence[0].message;

        assert!(message.contains("hr=0x80070005"), "{raw_message}");
        assert!(
            message.ends_with("[redacted:sccm-public-message-v1]"),
            "{raw_message}"
        );
        assert!(!message.contains(sensitive), "{sensitive} leaked");
    }
}

#[test]
fn evidence_public_message_projection_bounds_unquoted_values_before_safe_evidence() {
    let assignment_id = "{ABCDEFAB-0000-0000-0000-000000000001}";
    let text = format!(
        r#"<![LOG[client_secret=synthetic-client-secret hr=0x80070005 sig synthetic-signature Policy id={assignment_id} clientToken:synthetic-client-token Path C:\Windows\CCM\Logs\PolicyAgent.log credential synthetic-credential status=71]LOG]!><time="10:00:00.000-240" date="07-30-2026" component="PolicyAgent" context="" type="1" thread="42" file="policyagent.cpp">"#
    );

    let evidence = normalize_ccm_artifact(client_policy_artifact(), &text);
    let message = &evidence[0].message;

    for sensitive in [
        "synthetic-client-secret",
        "synthetic-signature",
        "synthetic-client-token",
        "synthetic-credential",
    ] {
        assert!(!message.contains(sensitive), "{sensitive} leaked");
    }
    for safe in [
        "hr=0x80070005",
        assignment_id,
        r"C:\Windows\CCM\Logs\PolicyAgent.log",
        "status=71",
    ] {
        assert!(message.contains(safe), "{safe} was swallowed");
    }
}

#[test]
fn evidence_public_message_projection_redacts_local_and_upn_identities_without_path_noise() {
    let text = r#"<![LOG[Caller .\LocalUser; UPN Synthetic.User@contoso.example; package package@1.2.3; Path C:\Windows\CCM\Logs\PolicyAgent.log; Relative .\Cache\Policy.bin; UNC \\LAB-CM01\SMS_CCM\Logs\MP.log]LOG]!><time="10:00:00.000-240" date="07-30-2026" component="PolicyAgent" context="" type="1" thread="42" file="policyagent.cpp">"#;

    let evidence = normalize_ccm_artifact(client_policy_artifact(), text);
    let message = &evidence[0].message;

    for sensitive in [r".\LocalUser", "Synthetic.User@contoso.example"] {
        assert!(!message.contains(sensitive), "{sensitive} leaked");
    }
    for safe in [
        "package@1.2.3",
        r"C:\Windows\CCM\Logs\PolicyAgent.log",
        r".\Cache\Policy.bin",
        r"\\LAB-CM01\SMS_CCM\Logs\MP.log",
    ] {
        assert!(message.contains(safe), "{safe} was falsely redacted");
    }
}

#[test]
fn evidence_public_message_projection_redacts_colon_delimited_windows_identities() {
    for sensitive in [r"LAB\SyntheticUser", r".\LocalUser"] {
        let raw_message = format!(
            r#"Caller:{sensitive}; Path C:\Windows\CCM\Logs\PolicyAgent.log; Relative .\Cache\Policy.bin; UNC \\LAB-CM01\SMS_CCM\Logs\MP.log; status=71"#
        );
        let text = format!(
            r#"<![LOG[{raw_message}]LOG]!><time="10:00:00.000-240" date="07-30-2026" component="PolicyAgent" context="" type="1" thread="42" file="policyagent.cpp">"#
        );

        let evidence = normalize_ccm_artifact(client_policy_artifact(), &text);
        let message = &evidence[0].message;
        let json = serde_json::to_string(&evidence).unwrap();

        assert!(!message.contains(sensitive), "{sensitive} leaked");
        assert_public_json_omits(&json, sensitive);
        for safe in [
            r"C:\Windows\CCM\Logs\PolicyAgent.log",
            r".\Cache\Policy.bin",
            r"\\LAB-CM01\SMS_CCM\Logs\MP.log",
            "status=71",
        ] {
            assert!(message.contains(safe), "{safe} was falsely redacted");
        }
    }
}

#[test]
fn serde_roles_are_string_backed_and_future_tolerant() {
    assert_eq!(
        serde_json::to_string(&SccmRole::ManagementPoint).unwrap(),
        r#""managementPoint""#
    );
    assert_eq!(
        serde_json::to_string(&SccmRole::Unknown("futureEdgeRole".into())).unwrap(),
        r#""futureEdgeRole""#
    );
    assert_eq!(
        serde_json::from_str::<SccmRole>(r#""futureEdgeRole""#).unwrap(),
        SccmRole::Unknown("futureEdgeRole".into())
    );

    let admin_service = serde_json::from_str::<SccmRole>(r#""adminService""#).unwrap();
    assert_eq!(
        serde_json::to_string(&admin_service).unwrap(),
        r#""adminService""#
    );
}

#[test]
fn serde_families_are_string_backed_and_future_tolerant() {
    assert_eq!(
        serde_json::to_string(&SccmArtifactFamily::ClientPolicy).unwrap(),
        r#""clientPolicy""#
    );
    assert_eq!(
        serde_json::to_string(&SccmArtifactFamily::Unknown("futureFamily".into())).unwrap(),
        r#""futureFamily""#
    );
    assert_eq!(
        serde_json::from_str::<SccmArtifactFamily>(r#""futureFamily""#).unwrap(),
        SccmArtifactFamily::Unknown("futureFamily".into())
    );
}

#[test]
fn serde_rotations_have_exact_tags_and_preserve_future_values() {
    let known = [
        (SccmRotation::Current, r#"{"kind":"current"}"#),
        (SccmRotation::LoUnderscore, r#"{"kind":"loUnderscore"}"#),
        (
            SccmRotation::Numbered(3),
            r#"{"kind":"numbered","value":3}"#,
        ),
        (
            SccmRotation::Timestamped("20260730-150000".into()),
            r#"{"kind":"timestamped","value":"20260730-150000"}"#,
        ),
    ];

    for (rotation, expected) in known {
        assert_eq!(serde_json::to_string(&rotation).unwrap(), expected);
        assert_eq!(
            serde_json::from_str::<SccmRotation>(expected).unwrap(),
            rotation
        );
    }

    let future = r#"{"kind":"vendorArchive","value":{"lineage":"A7","sequence":4}}"#;
    let rotation = serde_json::from_str::<SccmRotation>(future).unwrap();
    let unknown: &SccmUnknownRotation = match &rotation {
        SccmRotation::Unknown(unknown) => unknown,
        other => panic!("future rotation did not remain unknown: {other:?}"),
    };
    assert_eq!(unknown.kind, "vendorArchive");
    assert_eq!(
        unknown.value,
        Some(serde_json::json!({"lineage": "A7", "sequence": 4}))
    );
    assert_eq!(serde_json::to_string(&rotation).unwrap(), future);

    let valueless_future = r#"{"kind":"vendorArchiveWithoutValue"}"#;
    let rotation = serde_json::from_str::<SccmRotation>(valueless_future).unwrap();
    assert_eq!(serde_json::to_string(&rotation).unwrap(), valueless_future);
}

#[test]
fn serde_known_rotation_tags_reject_malformed_shapes() {
    for malformed in [
        r#"{"kind":"current","value":null}"#,
        r#"{"kind":"loUnderscore","value":"unexpected"}"#,
        r#"{"kind":"numbered"}"#,
        r#"{"kind":"numbered","value":-1}"#,
        r#"{"kind":"numbered","value":4294967296}"#,
        r#"{"kind":"timestamped"}"#,
        r#"{"kind":"timestamped","value":3}"#,
        r#"{"kind":"current","unexpected":true}"#,
    ] {
        assert!(
            serde_json::from_str::<SccmRotation>(malformed).is_err(),
            "accepted malformed known rotation: {malformed}"
        );
    }
}

#[test]
fn serde_known_rotation_values_reject_noncanonical_values() {
    for noncanonical in [
        r#"{"kind":"numbered","value":0}"#,
        r#"{"kind":"timestamped","value":""}"#,
        r#"{"kind":"timestamped","value":"20260730-15000"}"#,
        r#"{"kind":"timestamped","value":"20260730-1500000"}"#,
        r#"{"kind":"timestamped","value":"2026073A-150000"}"#,
        r#"{"kind":"timestamped","value":"20260730_150000"}"#,
        r#"{"kind":"timestamped","value":"20260229-150000"}"#,
        r#"{"kind":"timestamped","value":"20260730-240000"}"#,
        r#"{"kind":"timestamped","value":"20260730-156000"}"#,
        r#"{"kind":"timestamped","value":"20260730-150060"}"#,
        r#"{"kind":"timestamped","value":"20260730-150000Z"}"#,
    ] {
        assert!(
            serde_json::from_str::<SccmRotation>(noncanonical).is_err(),
            "accepted noncanonical known rotation: {noncanonical}"
        );
    }
}

#[test]
fn serde_known_rotation_values_fail_closed_on_serialize() {
    for rotation in [
        SccmRotation::Numbered(0),
        SccmRotation::Timestamped("20260730_150000".into()),
        SccmRotation::Timestamped("20260229-150000".into()),
        SccmRotation::Timestamped("20260730-150060".into()),
    ] {
        assert!(
            serde_json::to_string(&rotation).is_err(),
            "serialized noncanonical known rotation: {rotation:?}"
        );
    }
}

#[test]
fn serde_canonical_rotation_values_round_trip() {
    for rotation in [
        SccmRotation::Numbered(1),
        SccmRotation::Numbered(u32::MAX),
        SccmRotation::Timestamped("20240229-000000".into()),
        SccmRotation::Timestamped("20261231-235959".into()),
    ] {
        let json = serde_json::to_string(&rotation).unwrap();
        assert_eq!(
            serde_json::from_str::<SccmRotation>(&json).unwrap(),
            rotation
        );
    }
}

#[test]
fn artifact_round_trip_preserves_capture_and_rotation_provenance() {
    let artifact = SccmArtifact {
        artifact_id: "client-content-transfer".into(),
        display_name: "ContentTransferManager.log.2".into(),
        original_path: Some(r"C:\Windows\CCM\Logs\ContentTransferManager.log.2".into()),
        host: Some("LAB-CLIENT-01".into()),
        role: SccmRole::Client,
        configmgr_version: Some("5.00.9128.1007".into()),
        collected_at_utc: Some("2026-07-30T15:00:00Z".into()),
        rotation: SccmRotation::Numbered(2),
        coverage: SccmCoverageState::Captured,
        encoding: Some("utf-8".into()),
    };

    let json = serde_json::to_value(&artifact).unwrap();
    assert_eq!(json["rotation"]["kind"], "numbered");
    assert_eq!(json["rotation"]["value"], 2);
    assert_eq!(json["coverage"], "captured");
    assert_eq!(
        serde_json::from_value::<SccmArtifact>(json).unwrap(),
        artifact
    );
}

#[test]
fn coverage_json_names_are_exact_and_never_collapse_to_captured() {
    for (state, expected) in [
        (SccmCoverageState::Captured, r#""captured""#),
        (SccmCoverageState::Absent, r#""absent""#),
        (SccmCoverageState::AccessDenied, r#""accessDenied""#),
        (SccmCoverageState::Capped, r#""capped""#),
        (SccmCoverageState::Skipped, r#""skipped""#),
        (SccmCoverageState::Unsupported, r#""unsupported""#),
        (SccmCoverageState::ParseFailed, r#""parseFailed""#),
    ] {
        assert_eq!(serde_json::to_string(&state).unwrap(), expected);
        let round_trip = serde_json::from_str::<SccmCoverageState>(expected).unwrap();
        assert_eq!(round_trip, state);
        if expected != r#""captured""# {
            assert_ne!(round_trip, SccmCoverageState::Captured);
        }
    }
}

#[test]
fn artifact_manifest_fixture_preserves_each_coverage_state() {
    let artifacts: Vec<SccmArtifact> =
        serde_json::from_str(include_str!("fixtures/sccm/spine/artifact-manifest.json")).unwrap();

    assert_eq!(artifacts.len(), 4);
    assert_eq!(artifacts[0].rotation, SccmRotation::Current);
    assert_eq!(artifacts[1].rotation, SccmRotation::Numbered(2));
    assert_eq!(
        artifacts
            .iter()
            .map(|artifact| artifact.coverage.clone())
            .collect::<Vec<_>>(),
        vec![
            SccmCoverageState::Captured,
            SccmCoverageState::Captured,
            SccmCoverageState::Absent,
            SccmCoverageState::AccessDenied,
        ]
    );
    assert_eq!(
        artifacts[0].original_path.as_deref(),
        Some(r"C:\Windows\CCM\Logs\PolicyAgent.log")
    );
    assert_eq!(artifacts[3].encoding, None);
}

#[test]
fn catalog_classifies_client_policy_without_changing_ccm_parser_kind() {
    let class = classify_artifact_name("PolicyAgent.log", SccmRole::Client);
    assert_eq!(class.family, SccmArtifactFamily::ClientPolicy);
    assert_eq!(class.logical_name, "policyAgent");
    assert!(class.uses_ccm_records);

    let ccm = r#"<![LOG[Synthetic policy record]LOG]!><time="10:00:00.000-240" date="07-30-2026" component="PolicyAgent" context="" type="1" thread="42" file="policyagent.cpp">"#;
    assert_eq!(
        detect_parser("PolicyAgent.log", ccm).parser,
        ParserKind::Ccm
    );
}

#[test]
fn catalog_recognizes_rotated_client_log_by_base_name() {
    let class = classify_artifact_name("AppEnforce.log.3", SccmRole::Client);
    assert_eq!(class.family, SccmArtifactFamily::ClientApplication);
    assert_eq!(class.rotation, SccmRotation::Numbered(3));
}

#[test]
fn catalog_recognizes_standard_lo_rollback_name_by_canonical_log_basename() {
    let class = classify_artifact_name("CcmExec.lo_", SccmRole::Client);

    assert_eq!(class.basename, "CcmExec.log");
    assert_eq!(class.logical_name, "ccmExec");
    assert_eq!(class.family, SccmArtifactFamily::ClientHealth);
    assert_eq!(class.rotation, SccmRotation::LoUnderscore);
    assert!(class.uses_ccm_records);
    assert!(class.supported_for_diagnosis);
}

#[test]
fn catalog_leaves_unrecognized_sources_explicitly_unknown() {
    let class = classify_artifact_name("CustomVendorHook.log", SccmRole::Client);
    assert_eq!(
        class.family,
        SccmArtifactFamily::Unknown("customVendorHook".into())
    );
    assert!(!class.supported_for_diagnosis);
}

#[test]
fn catalog_exact_declared_tuples_match_the_public_classifier() {
    let expected = expected_catalog_tuples();
    let declared = declared_source_catalog();
    assert_eq!(declared.len(), expected.len());

    for (entry, expected) in declared.iter().zip(expected.iter()) {
        assert_eq!(entry.basename, expected.0);
        assert_eq!(entry.role, expected.1);
        assert_eq!(entry.logical_name, expected.2);
        assert_eq!(entry.family, expected.3);
        assert_eq!(entry.uses_ccm_records, expected.4);
        assert_eq!(entry.supported_for_diagnosis, expected.5);
        assert_eq!(entry.rotation, SccmRotation::Current);

        let classified = classify_artifact_name(expected.0, expected.1.clone());
        assert_eq!(classified, *entry);
    }
}

#[test]
fn catalog_declared_basename_role_tuples_are_unique() {
    let mut keys = std::collections::BTreeSet::new();
    for entry in declared_source_catalog() {
        let role = serde_json::to_string(&entry.role).unwrap();
        assert!(
            keys.insert((entry.basename.to_ascii_lowercase(), role)),
            "duplicate catalog tuple: {} / {:?}",
            entry.basename,
            entry.role
        );
    }
}

#[test]
fn catalog_rejects_every_role_not_declared_by_the_exact_table() {
    let expected = expected_catalog_tuples();
    let basenames = expected
        .iter()
        .map(|entry| entry.0)
        .collect::<std::collections::BTreeSet<_>>();

    for basename in basenames {
        let allowed_roles = expected
            .iter()
            .filter(|entry| entry.0 == basename)
            .map(|entry| &entry.1)
            .collect::<Vec<_>>();
        for role in known_roles() {
            if allowed_roles.contains(&&role) {
                continue;
            }

            let class = classify_artifact_name(basename, role.clone());
            assert_eq!(class.role, role, "{basename}");
            assert!(
                matches!(class.family, SccmArtifactFamily::Unknown(_)),
                "{basename} accepted undeclared role {:?}",
                class.role
            );
            assert!(!class.supported_for_diagnosis, "{basename}");
        }
    }
}

#[test]
fn catalog_rotation_grammar_accepts_only_canonical_suffixes() {
    let canonical = [
        ("AppEnforce.log", SccmRotation::Current),
        ("AppEnforce.lo_", SccmRotation::LoUnderscore),
        ("AppEnforce.LO_", SccmRotation::LoUnderscore),
        ("AppEnforce.log.3", SccmRotation::Numbered(3)),
        (
            "AppEnforce.log.20260730-150000",
            SccmRotation::Timestamped("20260730-150000".into()),
        ),
    ];
    for (name, expected_rotation) in canonical {
        let class = classify_artifact_name(name, SccmRole::Client);
        assert_eq!(
            class.family,
            SccmArtifactFamily::ClientApplication,
            "{name}"
        );
        assert_eq!(class.rotation, expected_rotation, "{name}");
        assert!(class.uses_ccm_records, "{name}");
        assert!(class.supported_for_diagnosis, "{name}");
    }

    let rejected = [
        ("AppEnforce.log.lo_", ".lo_"),
        ("AppEnforce.LOG.LO_", ".LO_"),
        ("AppEnforce.log.0", ".0"),
        ("AppEnforce.log.03", ".03"),
        ("AppEnforce.log.4294967296", ".4294967296"),
        ("AppEnforce.log.backup", ".backup"),
        ("AppEnforce.log.20260730_150000", ".20260730_150000"),
        ("AppEnforce.log.20260229-150000", ".20260229-150000"),
        ("AppEnforce.log.20260730-240000", ".20260730-240000"),
        ("AppEnforce.log.20260730-150000Z", ".20260730-150000Z"),
        ("AppEnforce.log.20261340-996099", ".20261340-996099"),
    ];
    for (name, raw_suffix) in rejected {
        let class = classify_artifact_name(name, SccmRole::Client);
        assert_eq!(
            class.family,
            SccmArtifactFamily::ClientApplication,
            "{name}"
        );
        assert_eq!(class.logical_name, "appEnforce", "{name}");
        assert_eq!(
            serde_json::to_value(&class.rotation).unwrap(),
            serde_json::json!({"kind": "filenameSuffix", "value": raw_suffix}),
            "{name}"
        );
        assert!(class.uses_ccm_records, "{name}");
        assert!(!class.supported_for_diagnosis, "{name}");
    }
}

#[test]
fn catalog_rotation_grammar_preserves_unknown_suffix_and_initialism() {
    let class = classify_artifact_name("SMSVendorHook.log.archive", SccmRole::Client);
    assert_eq!(class.logical_name, "smsVendorHook");
    assert_eq!(
        class.family,
        SccmArtifactFamily::Unknown("smsVendorHook".into())
    );
    assert_eq!(
        serde_json::to_value(&class.rotation).unwrap(),
        serde_json::json!({"kind": "filenameSuffix", "value": ".archive"})
    );
    assert!(!class.uses_ccm_records);
    assert!(!class.supported_for_diagnosis);
}

#[test]
fn catalog_requires_exact_producer_roles_for_server_workflow_sources() {
    let cases = [
        (
            "distmgr.log",
            SccmRole::SiteServer,
            SccmArtifactFamily::DistributionPoint,
        ),
        (
            "PkgXferMgr.log",
            SccmRole::SiteServer,
            SccmArtifactFamily::DistributionPoint,
        ),
        (
            "SMSDPProv.log",
            SccmRole::DistributionPoint,
            SccmArtifactFamily::DistributionPoint,
        ),
        (
            "PullDP.log",
            SccmRole::DistributionPoint,
            SccmArtifactFamily::DistributionPoint,
        ),
        (
            "WCM.log",
            SccmRole::SiteServer,
            SccmArtifactFamily::SoftwareUpdatePoint,
        ),
        (
            "wsyncmgr.log",
            SccmRole::SiteServer,
            SccmArtifactFamily::SoftwareUpdatePoint,
        ),
        (
            "WSUSCtrl.log",
            SccmRole::SoftwareUpdatePoint,
            SccmArtifactFamily::SoftwareUpdatePoint,
        ),
        (
            "SUPSetup.log",
            SccmRole::SoftwareUpdatePoint,
            SccmArtifactFamily::SoftwareUpdatePoint,
        ),
        (
            "AdminService.log",
            SccmRole::Provider,
            SccmArtifactFamily::AdminService,
        ),
    ];

    for (source, producer_role, family) in cases {
        let class = classify_artifact_name(source, producer_role.clone());
        assert_eq!(class.role, producer_role, "{source}");
        assert_eq!(class.family, family, "{source}");
        assert!(class.uses_ccm_records, "{source}");
        assert!(class.supported_for_diagnosis, "{source}");

        for role in &known_roles() {
            if *role == producer_role {
                continue;
            }

            let class = classify_artifact_name(source, role.clone());
            assert_eq!(class.role, *role, "{source}");
            assert!(
                matches!(class.family, SccmArtifactFamily::Unknown(_)),
                "{source} accepted non-producer role {role:?}"
            );
            assert!(!class.uses_ccm_records, "{source} / {role:?}");
            assert!(!class.supported_for_diagnosis, "{source} / {role:?}");
        }
    }
}

fn known_roles() -> [SccmRole; 8] {
    [
        SccmRole::Client,
        SccmRole::SiteServer,
        SccmRole::ManagementPoint,
        SccmRole::DistributionPoint,
        SccmRole::SoftwareUpdatePoint,
        SccmRole::WsUs,
        SccmRole::Provider,
        SccmRole::AdminService,
    ]
}

type ExpectedCatalogTuple = (
    &'static str,
    SccmRole,
    &'static str,
    SccmArtifactFamily,
    bool,
    bool,
);

fn expected_catalog_tuples() -> Vec<ExpectedCatalogTuple> {
    vec![
        (
            "CCMSetup.log",
            SccmRole::Client,
            "ccmSetup",
            SccmArtifactFamily::ClientSetup,
            true,
            true,
        ),
        (
            "CcmEval.log",
            SccmRole::Client,
            "ccmEval",
            SccmArtifactFamily::ClientHealth,
            true,
            true,
        ),
        (
            "CcmExec.log",
            SccmRole::Client,
            "ccmExec",
            SccmArtifactFamily::ClientHealth,
            true,
            true,
        ),
        (
            "CcmRestart.log",
            SccmRole::Client,
            "ccmRestart",
            SccmArtifactFamily::ClientHealth,
            true,
            true,
        ),
        (
            "ClientIDManagerStartup.log",
            SccmRole::Client,
            "clientIdManagerStartup",
            SccmArtifactFamily::ClientIdentity,
            true,
            true,
        ),
        (
            "ClientLocation.log",
            SccmRole::Client,
            "clientLocation",
            SccmArtifactFamily::ClientLocation,
            true,
            true,
        ),
        (
            "LocationServices.log",
            SccmRole::Client,
            "locationServices",
            SccmArtifactFamily::ClientLocation,
            true,
            true,
        ),
        (
            "CcmMessaging.log",
            SccmRole::Client,
            "ccmMessaging",
            SccmArtifactFamily::ClientLocation,
            true,
            true,
        ),
        (
            "PolicyAgent.log",
            SccmRole::Client,
            "policyAgent",
            SccmArtifactFamily::ClientPolicy,
            true,
            true,
        ),
        (
            "PolicyAgentProvider.log",
            SccmRole::Client,
            "policyAgentProvider",
            SccmArtifactFamily::ClientPolicy,
            true,
            true,
        ),
        (
            "PolicyEvaluator.log",
            SccmRole::Client,
            "policyEvaluator",
            SccmArtifactFamily::ClientPolicy,
            true,
            true,
        ),
        (
            "Scheduler.log",
            SccmRole::Client,
            "scheduler",
            SccmArtifactFamily::ClientPolicy,
            true,
            true,
        ),
        (
            "CAS.log",
            SccmRole::Client,
            "cas",
            SccmArtifactFamily::ClientContent,
            true,
            true,
        ),
        (
            "ContentTransferManager.log",
            SccmRole::Client,
            "contentTransferManager",
            SccmArtifactFamily::ClientContent,
            true,
            true,
        ),
        (
            "DataTransferService.log",
            SccmRole::Client,
            "dataTransferService",
            SccmArtifactFamily::ClientContent,
            true,
            true,
        ),
        (
            "AppIntentEval.log",
            SccmRole::Client,
            "appIntentEval",
            SccmArtifactFamily::ClientApplication,
            true,
            true,
        ),
        (
            "AppDiscovery.log",
            SccmRole::Client,
            "appDiscovery",
            SccmArtifactFamily::ClientApplication,
            true,
            true,
        ),
        (
            "AppEnforce.log",
            SccmRole::Client,
            "appEnforce",
            SccmArtifactFamily::ClientApplication,
            true,
            true,
        ),
        (
            "ScanAgent.log",
            SccmRole::Client,
            "scanAgent",
            SccmArtifactFamily::ClientUpdates,
            true,
            true,
        ),
        (
            "WUAHandler.log",
            SccmRole::Client,
            "wuaHandler",
            SccmArtifactFamily::ClientUpdates,
            true,
            true,
        ),
        (
            "UpdatesDeployment.log",
            SccmRole::Client,
            "updatesDeployment",
            SccmArtifactFamily::ClientUpdates,
            true,
            true,
        ),
        (
            "UpdatesHandler.log",
            SccmRole::Client,
            "updatesHandler",
            SccmArtifactFamily::ClientUpdates,
            true,
            true,
        ),
        (
            "UpdatesStore.log",
            SccmRole::Client,
            "updatesStore",
            SccmArtifactFamily::ClientUpdates,
            true,
            true,
        ),
        (
            "smsts.log",
            SccmRole::Client,
            "smsts",
            SccmArtifactFamily::ClientTaskSequence,
            true,
            true,
        ),
        (
            "sitecomp.log",
            SccmRole::SiteServer,
            "sitecomp",
            SccmArtifactFamily::SiteComponent,
            true,
            true,
        ),
        (
            "hman.log",
            SccmRole::SiteServer,
            "hman",
            SccmArtifactFamily::SiteComponent,
            true,
            true,
        ),
        (
            "statmgr.log",
            SccmRole::SiteServer,
            "statmgr",
            SccmArtifactFamily::SiteStatus,
            true,
            true,
        ),
        (
            "statesys.log",
            SccmRole::SiteServer,
            "statesys",
            SccmArtifactFamily::SiteStatus,
            true,
            true,
        ),
        (
            "MP_CliReg.log",
            SccmRole::ManagementPoint,
            "mpCliReg",
            SccmArtifactFamily::ManagementPoint,
            true,
            true,
        ),
        (
            "MP_GetAuth.log",
            SccmRole::ManagementPoint,
            "mpGetAuth",
            SccmArtifactFamily::ManagementPoint,
            true,
            true,
        ),
        (
            "MP_GetPolicy.log",
            SccmRole::ManagementPoint,
            "mpGetPolicy",
            SccmArtifactFamily::ManagementPoint,
            true,
            true,
        ),
        (
            "MP_Location.log",
            SccmRole::ManagementPoint,
            "mpLocation",
            SccmArtifactFamily::ManagementPoint,
            true,
            true,
        ),
        (
            "MP_RegistrationManager.log",
            SccmRole::ManagementPoint,
            "mpRegistrationManager",
            SccmArtifactFamily::ManagementPoint,
            true,
            true,
        ),
        (
            "mpcontrol.log",
            SccmRole::ManagementPoint,
            "mpcontrol",
            SccmArtifactFamily::ManagementPoint,
            true,
            true,
        ),
        (
            "distmgr.log",
            SccmRole::SiteServer,
            "distmgr",
            SccmArtifactFamily::DistributionPoint,
            true,
            true,
        ),
        (
            "PkgXferMgr.log",
            SccmRole::SiteServer,
            "pkgXferMgr",
            SccmArtifactFamily::DistributionPoint,
            true,
            true,
        ),
        (
            "SMSDPProv.log",
            SccmRole::DistributionPoint,
            "smsDpProv",
            SccmArtifactFamily::DistributionPoint,
            true,
            true,
        ),
        (
            "PullDP.log",
            SccmRole::DistributionPoint,
            "pullDp",
            SccmArtifactFamily::DistributionPoint,
            true,
            true,
        ),
        (
            "WCM.log",
            SccmRole::SiteServer,
            "wcm",
            SccmArtifactFamily::SoftwareUpdatePoint,
            true,
            true,
        ),
        (
            "WSUSCtrl.log",
            SccmRole::SoftwareUpdatePoint,
            "wsusCtrl",
            SccmArtifactFamily::SoftwareUpdatePoint,
            true,
            true,
        ),
        (
            "wsyncmgr.log",
            SccmRole::SiteServer,
            "wsyncmgr",
            SccmArtifactFamily::SoftwareUpdatePoint,
            true,
            true,
        ),
        (
            "SUPSetup.log",
            SccmRole::SoftwareUpdatePoint,
            "supSetup",
            SccmArtifactFamily::SoftwareUpdatePoint,
            true,
            true,
        ),
        (
            "replmgr.log",
            SccmRole::SiteServer,
            "replmgr",
            SccmArtifactFamily::Hierarchy,
            true,
            true,
        ),
        (
            "rcmctrl.log",
            SccmRole::SiteServer,
            "rcmctrl",
            SccmArtifactFamily::Hierarchy,
            true,
            true,
        ),
        (
            "sender.log",
            SccmRole::SiteServer,
            "sender",
            SccmArtifactFamily::Hierarchy,
            true,
            true,
        ),
        (
            "despool.log",
            SccmRole::SiteServer,
            "despool",
            SccmArtifactFamily::Hierarchy,
            true,
            true,
        ),
        (
            "Smsprov.log",
            SccmRole::Provider,
            "smsprov",
            SccmArtifactFamily::Provider,
            true,
            true,
        ),
        (
            "AdminService.log",
            SccmRole::Provider,
            "adminService",
            SccmArtifactFamily::AdminService,
            true,
            true,
        ),
    ]
}
