use cmtraceopen_parser::diagnosis::{
    adapt_esp_finding, adapt_event_entry, adapt_event_entry_with_data,
    adapt_event_entry_with_data_and_raw_xml, adapt_intune_finding, adapt_log_entry,
    enrich_error_tokens, finding_for_coverage, redacted_display_projection, summarize_cross_source,
    CorrelationBasis, CorrelationEdge, CorrelationStatus, CoverageState, EventEvidenceRef,
    EvidenceRef, FindingClass, TextLogEvidenceRef,
};
use cmtraceopen_parser::esp::{
    EspDiagnosticFinding, EspEvidenceRef, EspFindingConfidence, EspFindingSeverity,
};
use cmtraceopen_parser::intune::evidence::IntuneEvidenceRef;
use cmtraceopen_parser::intune::evidence::{
    IntuneFinding, IntuneFindingConfidence, IntuneFindingSeverity,
};
use cmtraceopen_parser::intune::models::{EventLogChannel, EventLogEntry, EventLogSeverity};
use cmtraceopen_parser::models::log_entry::{LogEntry, Severity};
use cmtraceopen_parser::sccm::SccmEvidenceRef;

fn event_entry(message: &str) -> EventLogEntry {
    EventLogEntry {
        id: 12,
        channel: EventLogChannel::DeviceManagementOperational,
        channel_display: "Microsoft-Windows-DeviceManagement/Operational".into(),
        provider: "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider".into(),
        event_id: 75,
        severity: EventLogSeverity::Error,
        timestamp: "2026-08-18T12:00:00Z".into(),
        computer: Some("WIN-TEST".into()),
        message: message.into(),
        correlation_activity_id: Some("activity-1".into()),
        source_file: "MDM.evtx".into(),
    }
}

#[test]
fn evidence_identity_round_trips_without_flattening_native_refs() {
    let intune = IntuneEvidenceRef {
        evidence_id: "ime-line-1".into(),
        source_artifact_id: "IntuneManagementExtension.log".into(),
    };
    let esp = EspEvidenceRef {
        evidence_id: "esp-event-1".into(),
        source_artifact_id: "esp.evtx".into(),
    };
    let sccm = SccmEvidenceRef {
        artifact_id: "PolicyAgent.log".into(),
        entry_id: "entry-1".into(),
        line_start: Some(10),
        line_end: Some(12),
    };
    let refs = vec![
        EvidenceRef::from_intune(intune.clone()),
        EvidenceRef::from_esp(esp.clone()),
        EvidenceRef::from_sccm(sccm.clone()),
        EvidenceRef::from_dsreg_raw("Client ErrorCode: 0x80070005"),
        EvidenceRef::from_text_log(TextLogEvidenceRef {
            source: "PolicyAgent.log".into(),
            file_path: "C:/evidence/PolicyAgent.log".into(),
            line_number: 42,
            entry_id: 7,
        }),
        EvidenceRef::from_event("MDM.evtx", "Microsoft-Windows-DeviceManagement", 75, 12),
    ];
    let wire = serde_json::to_string(&refs).expect("serialize refs");
    let decoded: Vec<EvidenceRef> = serde_json::from_str(&wire).expect("deserialize refs");
    assert_eq!(refs, decoded);
    assert!(refs
        .iter()
        .all(|reference| !reference.stable_id().is_empty()));
    assert!(refs
        .iter()
        .any(|reference| reference.source_reference().contains("PolicyAgent.log")));
}

#[test]
fn event_identity_uses_channel_and_lossless_record_text() {
    let reference = EvidenceRef::Event(EventEvidenceRef {
        source: "Application.evtx".into(),
        provider: "Provider".into(),
        event_id: 100,
        record_id: 9_007_199_254_740_992,
        record_id_text: Some("9007199254740993".into()),
        fallback_identity: None,
        machine: Some("WIN-TEST".into()),
        channel: Some("Application".into()),
        activity_id: None,
    });
    let stable_id = reference.stable_id();
    assert!(stable_id.contains("Application"));
    assert!(stable_id.contains("9007199254740993"));
    assert!(!stable_id.contains("9007199254740992"));
}

#[test]
fn coverage_states_are_non_assertive_findings() {
    for state in [
        CoverageState::Unknown,
        CoverageState::Absent,
        CoverageState::AccessDenied,
        CoverageState::Capped,
        CoverageState::Skipped,
        CoverageState::Unsupported,
        CoverageState::Malformed,
    ] {
        let finding = finding_for_coverage(
            "autopilot",
            state,
            "required event source unavailable".into(),
        );
        assert_eq!(finding.class, FindingClass::CoverageGap);
        assert!(finding.evidence.is_empty());
        assert!(!finding.coverage_gaps.is_empty());
        assert!(!matches!(finding.class, FindingClass::ConfirmedFailure));
    }
}

#[test]
fn source_adapters_preserve_unknown_coverage_without_claiming_failure() {
    let intune = adapt_intune_finding(&IntuneFinding {
        finding_id: "intune-finding".into(),
        severity: IntuneFindingSeverity::Error,
        confidence: IntuneFindingConfidence::High,
        title: "IME failure".into(),
        summary: "The source is incomplete.".into(),
        recommended_checks: vec!["Collect IME".into()],
        evidence: Vec::new(),
        coverage_gap_ids: vec!["ime-gap".into()],
    });
    let esp = adapt_esp_finding(&EspDiagnosticFinding {
        finding_id: "esp-finding".into(),
        severity: EspFindingSeverity::Warning,
        confidence: EspFindingConfidence::Medium,
        title: "ESP warning".into(),
        summary: "The source is incomplete.".into(),
        recommended_checks: vec!["Collect ESP".into()],
        evidence: Vec::new(),
        coverage_gap_ids: vec!["esp-gap".into()],
    });
    for finding in [intune, esp] {
        assert_eq!(finding.class, FindingClass::LikelyContributor);
        assert_eq!(finding.coverage_gaps[0].state, CoverageState::Unknown);
    }
}

#[test]
fn event_adapter_keeps_evidence_and_classifies_explicit_failure() {
    let event = adapt_event_entry(event_entry("Enrollment failed with 0x80070005"));
    assert!(!event.evidence.is_empty());
    assert!(!event.findings.is_empty());
    assert!(event
        .findings
        .iter()
        .all(|finding| { !finding.evidence.is_empty() || !finding.coverage_gaps.is_empty() }));
    assert!(event
        .findings
        .iter()
        .any(|finding| finding.class == FindingClass::ConfirmedFailure));
}

#[test]
fn success_status_and_zero_error_code_are_not_failures() {
    let mut entry = event_entry("Enrollment completed");
    entry.severity = EventLogSeverity::Information;
    let diagnosis = adapt_event_entry_with_data(
        entry,
        &[
            "Status=Completed".into(),
            "ErrorCode=0".into(),
            "ErrorDescription=No error".into(),
        ],
    );
    assert!(diagnosis.findings.is_empty());
}

#[test]
fn missing_record_ids_include_raw_xml_in_content_identity() {
    let mut first = event_entry("same event");
    first.id = 0;
    let second = first.clone();
    let first_id = adapt_event_entry_with_data_and_raw_xml(
        first,
        &[],
        r#"<Event><Provider Name="first"/></Event>"#,
    )
    .evidence[0]
        .stable_id();
    let second_id = adapt_event_entry_with_data_and_raw_xml(
        second,
        &[],
        r#"<Event><Provider Name="second"/></Event>"#,
    )
    .evidence[0]
        .stable_id();
    assert_ne!(first_id, second_id);
}

#[test]
fn text_log_adapter_preserves_source_line_identity() {
    let entry = LogEntry {
        id: 7,
        line_number: 12,
        message: "Install failed with 0x80070005".into(),
        severity: Severity::Error,
        source_file: Some("IntuneManagementExtension.log".into()),
        file_path: "IntuneManagementExtension.log".into(),
        ..LogEntry::default()
    };
    let finding = adapt_log_entry(entry).expect("error log should produce a finding");
    assert_eq!(finding.class, FindingClass::ConfirmedFailure);
    assert!(finding.evidence[0]
        .source_reference()
        .contains("IntuneManagementExtension.log:12"));
}

#[test]
fn event_family_rules_cover_autopilot_esp_mdm_and_configmgr() {
    let families = [
        (
            EventLogChannel::Autopilot,
            "Autopilot",
            "Autopilot deployment failed",
        ),
        (
            EventLogChannel::ProvisioningDiagnosticsAdmin,
            "ESP",
            "ESP workload failed",
        ),
        (
            EventLogChannel::DeviceManagementOperational,
            "MDM",
            "MDM enrollment failed",
        ),
        (
            EventLogChannel::Other("ConfigMgr".into()),
            "ConfigMgr",
            "ConfigMgr client failed",
        ),
    ];
    for (channel, family, message) in families {
        let mut entry = event_entry(message);

        entry.channel = channel;
        entry.channel_display = family.into();
        entry.provider = family.into();
        let diagnosis = adapt_event_entry(entry);
        assert!(format!("{:?}", diagnosis.family)
            .to_ascii_lowercase()
            .contains(&family.to_ascii_lowercase()));
        assert!(diagnosis
            .findings
            .iter()
            .all(|finding| { !finding.evidence.is_empty() || !finding.coverage_gaps.is_empty() }));
    }
}
#[test]
fn response_text_does_not_misclassify_mdm_as_esp() {
    let mut entry = event_entry("Enrollment response received");
    entry.severity = EventLogSeverity::Information;
    let diagnosis = adapt_event_entry(entry);
    assert_eq!(
        diagnosis.family,
        cmtraceopen_parser::diagnosis::EventFamily::MdmEnrollment
    );
}
#[test]
fn contradictory_event_is_not_reduced_to_success_or_failure() {
    let event = adapt_event_entry(event_entry("Enrollment succeeded but final status failed"));
    assert!(event
        .findings
        .iter()
        .any(|finding| finding.class == FindingClass::ContradictoryEvidence));
}

#[test]
fn error_tokens_are_lossless_for_known_unknown_malformed_signed_and_hex_inputs() {
    let tokens = enrich_error_tokens(
        "known 0x80070005 unknown 0xDEADBEEF malformed 0xZZZZ signed -2147024891",
    );
    assert!(tokens
        .iter()
        .any(|token| token.raw == "0x80070005" && token.hex.is_some()));
    assert!(tokens
        .iter()
        .any(|token| token.raw == "0xDEADBEEF" && token.hex.is_some()));
    assert!(tokens
        .iter()
        .any(|token| token.raw == "0xZZZZ" && token.malformed));
    assert!(tokens
        .iter()
        .any(|token| token.raw == "-2147024891" && token.decimal == Some(-2147024891)));
}

#[test]
fn bare_numeric_tokens_require_local_error_context() {
    let tokens =
        enrich_error_tokens("No error was reported. Policy version 20260818 applied deadbeef");
    assert!(!tokens.iter().any(|token| token.raw == "20260818"));
    assert!(!tokens.iter().any(|token| token.raw == "deadbeef"));
    let contextual = enrich_error_tokens("Error status 20260818");
    assert!(contextual.iter().any(|token| token.raw == "20260818"));
}

#[test]
fn cross_source_summary_preserves_refs_gaps_and_timestamp_ambiguity() {
    let event = adapt_event_entry(event_entry("Enrollment failed with 0x80070005"));
    let text_finding = adapt_log_entry(LogEntry {
        id: 7,
        line_number: 42,
        message: "Install failed".into(),
        severity: Severity::Error,
        source_file: Some("IntuneManagementExtension.log".into()),
        file_path: "IntuneManagementExtension.log".into(),
        ..LogEntry::default()
    })
    .expect("text finding");
    let summary = summarize_cross_source(
        vec![event],
        vec![
            text_finding,
            finding_for_coverage(
                "intune",
                CoverageState::Absent,
                "IME log was not captured".into(),
            ),
        ],
        vec![CorrelationEdge {
            left: "event:1".into(),
            right: Some("ime:2".into()),
            basis: CorrelationBasis::TimestampOnly,
            status: CorrelationStatus::Ambiguous,
            candidate_ids: Vec::new(),
            evidence: Vec::new(),
        }],
    );
    assert!(!summary.findings.is_empty());
    assert!(summary
        .coverage_gaps
        .iter()
        .any(|item| item.source == "intune" && item.state == CoverageState::Absent));
    assert!(summary
        .correlations
        .iter()
        .all(|edge| edge.basis != CorrelationBasis::TimestampOnly
            || edge.status != CorrelationStatus::Exact));
    assert!(!summary.evidence.is_empty());
}

#[test]
fn autopilot_failure_rule_requires_explicit_profile_status() {
    let mut entry = event_entry("Autopilot profile operation failed");
    entry.channel = EventLogChannel::Autopilot;
    entry.channel_display =
        "Microsoft-Windows-ModernDeployment-Diagnostics-Provider/Autopilot".into();
    entry.provider = "Microsoft-Windows-ModernDeployment-Diagnostics-Provider".into();
    entry.event_id = 153;
    entry.severity = EventLogSeverity::Error;
    let diagnosis = adapt_event_entry_with_data(
        entry,
        &[
            "ProfileName=Windows 11".into(),
            "ProfileStatus=Failed".into(),
            "ErrorCode=0x80070005".into(),
        ],
    );
    let finding = diagnosis
        .findings
        .iter()
        .find(|finding| finding.finding_id.contains("autopilot-profile"))
        .expect("autopilot profile rule finding");
    assert_eq!(finding.class, FindingClass::ConfirmedFailure);
    assert_eq!(
        finding.confidence,
        cmtraceopen_parser::diagnosis::FindingConfidence::High
    );
    assert!(finding.summary.contains("ProfileStatus=Failed"));
}

#[test]
fn autopilot_without_terminal_status_reports_a_coverage_gap() {
    let mut entry = event_entry("Autopilot profile operation started");
    entry.channel = EventLogChannel::Autopilot;
    entry.channel_display =
        "Microsoft-Windows-ModernDeployment-Diagnostics-Provider/Autopilot".into();
    entry.provider = "Microsoft-Windows-ModernDeployment-Diagnostics-Provider".into();
    entry.event_id = 153;
    entry.severity = EventLogSeverity::Information;
    let diagnosis = adapt_event_entry_with_data(entry, &["ProfileName=Windows 11".into()]);
    assert!(diagnosis.findings.iter().any(|finding| {
        finding.finding_id.contains("autopilot-profile")
            && finding.class == FindingClass::CoverageGap
    }));
    assert!(diagnosis
        .findings
        .iter()
        .all(|finding| { finding.class != FindingClass::ConfirmedFailure }));
}

#[test]
fn esp_malformed_status_is_visible_without_a_failure_claim() {
    let mut entry = event_entry("ESP phase status received");
    entry.channel = EventLogChannel::ProvisioningDiagnosticsAdmin;
    entry.channel_display = "Microsoft-Windows-Provisioning-Diagnostics-Provider/Admin".into();
    entry.provider = "Microsoft-Windows-Provisioning-Diagnostics-Provider".into();
    entry.event_id = 300;
    entry.severity = EventLogSeverity::Information;
    let diagnosis = adapt_event_entry_with_data(entry, &["Status=maybe".into()]);
    let finding = diagnosis
        .findings
        .iter()
        .find(|finding| finding.finding_id.contains("esp-status"))
        .expect("ESP status coverage finding");
    assert_eq!(finding.class, FindingClass::CoverageGap);
    assert!(finding
        .coverage_gaps
        .iter()
        .any(|gap| gap.state == CoverageState::Malformed));
    assert!(diagnosis
        .findings
        .iter()
        .all(|finding| finding.class != FindingClass::ConfirmedFailure));
}

#[test]
fn mdm_success_with_nonzero_error_code_is_contradictory() {
    let mut entry = event_entry("MDM enrollment completed");
    entry.channel = EventLogChannel::DeviceManagementOperational;
    entry.channel_display =
        "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Operational".into();
    entry.provider = "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider".into();
    entry.event_id = 75;
    entry.severity = EventLogSeverity::Information;
    let diagnosis = adapt_event_entry_with_data(
        entry,
        &["Status=Completed".into(), "ErrorCode=0x80070005".into()],
    );
    assert!(diagnosis
        .findings
        .iter()
        .any(|finding| finding.class == FindingClass::ContradictoryEvidence));
}

#[test]
fn mdm_missing_status_is_visible_as_a_coverage_gap() {
    let mut entry = event_entry("MDM enrollment event received");
    entry.severity = EventLogSeverity::Information;
    let diagnosis = adapt_event_entry_with_data(entry, &["EnrollmentId=abc".into()]);
    assert!(diagnosis.findings.iter().any(|finding| {
        finding.finding_id.contains("mdm-enrollment-status")
            && finding.class == FindingClass::CoverageGap
    }));
    assert!(diagnosis
        .findings
        .iter()
        .all(|finding| finding.class != FindingClass::ConfirmedFailure));
}

#[test]
fn configmgr_missing_component_result_is_visible_as_a_coverage_gap() {
    let mut entry = event_entry("Configuration Manager component operation started");
    entry.channel = EventLogChannel::Other("Application".into());
    entry.channel_display = "Application".into();
    entry.provider = "Microsoft.ConfigurationManagement".into();
    entry.severity = EventLogSeverity::Information;
    let diagnosis = adapt_event_entry_with_data(entry, &["Component=LocationServices".into()]);
    assert!(diagnosis.findings.iter().any(|finding| {
        finding.finding_id.contains("configmgr-component-status")
            && finding.class == FindingClass::CoverageGap
    }));
    assert!(diagnosis
        .findings
        .iter()
        .all(|finding| finding.class != FindingClass::ConfirmedFailure));
}

#[test]
fn configmgr_component_failure_has_operational_rule_identity() {
    let mut entry = event_entry("Configuration Manager component reported failure");
    entry.channel = EventLogChannel::Other("Application".into());
    entry.channel_display = "Application".into();
    entry.provider = "Microsoft.ConfigurationManagement".into();
    entry.event_id = 1001;
    entry.severity = EventLogSeverity::Error;
    let diagnosis = adapt_event_entry_with_data(
        entry,
        &[
            "Component=LocationServices".into(),
            "Result=Failed".into(),
            "ErrorCode=0x80072EE7".into(),
        ],
    );
    assert!(diagnosis
        .findings
        .iter()
        .any(|finding| finding.finding_id.contains("configmgr-component")));
}

#[test]
fn cross_source_summary_exposes_non_causal_overview() {
    let event = adapt_event_entry(event_entry("Enrollment failed with 0x80070005"));
    let summary = summarize_cross_source(vec![event], Vec::new(), Vec::new());
    assert_eq!(summary.overview.outcome, "confirmedFailure");
    assert_eq!(summary.overview.finding_count, 1);
    assert_eq!(summary.overview.coverage_gap_count, 0);
    assert!(summary.overview.headline.contains("confirmed"));
}

#[test]
fn typed_mdm_channel_wins_over_misleading_autopilot_message() {
    let diagnosis = adapt_event_entry(event_entry("Autopilot profile operation failed"));
    assert_eq!(
        diagnosis.family,
        cmtraceopen_parser::diagnosis::EventFamily::MdmEnrollment
    );
}

#[test]
fn negated_success_language_does_not_create_a_contradiction() {
    let diagnosis = adapt_event_entry_with_data(
        event_entry("Enrollment was unsuccessful"),
        &["Status=Failed".into()],
    );
    assert!(diagnosis
        .findings
        .iter()
        .any(|finding| finding.class == FindingClass::ConfirmedFailure));
    assert!(diagnosis
        .findings
        .iter()
        .all(|finding| finding.class != FindingClass::ContradictoryEvidence));
}

#[test]
fn failed_status_and_success_language_are_contradictory() {
    let diagnosis = adapt_event_entry_with_data(
        event_entry("Enrollment completed but the status failed"),
        &["Status=Failed".into()],
    );
    assert!(diagnosis
        .findings
        .iter()
        .any(|finding| finding.class == FindingClass::ContradictoryEvidence));
}

#[test]
fn successful_message_without_mdm_status_remains_a_coverage_gap() {
    let mut entry = event_entry("Enrollment completed");
    entry.severity = EventLogSeverity::Information;
    let diagnosis = adapt_event_entry_with_data(entry, &["ErrorCode=0".into()]);
    assert!(diagnosis.findings.iter().any(|finding| {
        finding.finding_id.contains("mdm-enrollment-status")
            && finding.class == FindingClass::CoverageGap
    }));
}

#[test]
fn unsupported_event_family_is_a_coverage_gap_not_a_failure() {
    let mut entry = event_entry("Unknown provider operation failed");
    entry.channel = EventLogChannel::Other("Application".into());
    entry.channel_display = "Application".into();
    entry.provider = "Unknown provider".into();
    let diagnosis = adapt_event_entry(entry);
    assert_eq!(
        diagnosis.family,
        cmtraceopen_parser::diagnosis::EventFamily::Other
    );
    assert!(diagnosis
        .findings
        .iter()
        .any(|finding| finding.class == FindingClass::CoverageGap));
    assert!(diagnosis
        .findings
        .iter()
        .all(|finding| finding.class != FindingClass::ConfirmedFailure));
}

#[test]
fn diagnosis_projection_masks_code_shaped_secrets_from_event_data_and_xml() {
    let mut entry = event_entry("Enrollment completed");
    entry.severity = EventLogSeverity::Information;
    let event = adapt_event_entry_with_data_and_raw_xml(
        entry,
        &[
            "Status=Completed".into(),
            "Password=0xDEADBEEF".into(),
            "ErrorCode=0x80070005".into(),
        ],
        r#"<Event><Password>0xCAFEBABE</Password><Password value="0xBADC0DE"/><Data Name="Token">0xBADCAFE1</Data></Event>"#,
    );
    let summary =
        redacted_display_projection(summarize_cross_source(vec![event], Vec::new(), Vec::new()));
    let serialized = serde_json::to_string(&summary).expect("diagnosis serializes");
    assert!(!serialized.contains("0xDEADBEEF"), "{serialized}");
    assert!(!serialized.contains("0xCAFEBABE"), "{serialized}");
    assert!(!serialized.contains("0xBADC0DE"), "{serialized}");
    assert!(!serialized.contains("0xBADCAFE1"), "{serialized}");
    assert!(serialized.contains("0x80070005"), "{serialized}");
}
