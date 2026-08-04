use cmtraceopen_parser::models::log_entry::{LogFormat, ParserKind, Severity};
use cmtraceopen_parser::parser::detect::detect_parser;
use cmtraceopen_parser::sccm::{
    classify_artifact_name, declared_source_catalog, extract_keys, extract_signals,
    normalize_ccm_artifact, normalize_key, SccmArtifact, SccmArtifactFamily, SccmArtifactRequest,
    SccmConfidence, SccmCorrelationKey, SccmCorrelationKeyKind, SccmCoverageState, SccmEvidence,
    SccmEvidenceRef, SccmExtractionGapKind, SccmExtractionProfile, SccmExtractionProfileMaturity,
    SccmFinding, SccmFindingBuilder, SccmFindingClass, SccmFindingCoverageGap,
    SccmFindingValidationError, SccmKeyConfidence, SccmKeyExtractionResult, SccmPhase, SccmRole,
    SccmRotation, SccmSignal, SccmSignalKind, SccmTerminalEvidence, SccmTerminalEvidenceKind,
    SccmTimeOrderingState, SccmTimestamp, SccmUnknownRotation,
    MAX_SCCM_ARTIFACT_REQUEST_REASON_CHARS, MAX_SCCM_NEXT_ARTIFACT_REQUESTS,
    SCCM_DIAGNOSTICS_SCHEMA_VERSION,
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

fn evidence_with_message(message: &str) -> SccmEvidence {
    SccmEvidence {
        evidence_id: "client-policy-agent:1-1".into(),
        reference: SccmEvidenceRef {
            artifact_id: "client-policy-agent".into(),
            entry_id: "client-policy-agent:1-1".into(),
            line_start: Some(1),
            line_end: Some(1),
        },
        role: SccmRole::Client,
        component: Some("PolicyAgent".into()),
        ccm_source_file: Some("policyagent.cpp".into()),
        message: message.into(),
        timestamp: SccmTimestamp {
            original_display: None,
            offset_minutes: None,
            utc_millis: None,
            ordering_state: SccmTimeOrderingState::TimestampMissing,
        },
        execution_context: None,
    }
}

fn finding_evidence_ref(artifact_id: &str, entry_id: &str) -> SccmEvidenceRef {
    SccmEvidenceRef {
        artifact_id: artifact_id.into(),
        entry_id: entry_id.into(),
        line_start: Some(1),
        line_end: Some(1),
    }
}

fn finding_key(
    kind: SccmCorrelationKeyKind,
    raw: &str,
    normalized: &str,
    confidence: SccmKeyConfidence,
    extraction_profile_id: Option<&str>,
    evidence: SccmEvidenceRef,
) -> SccmCorrelationKey {
    SccmCorrelationKey {
        kind,
        raw: raw.into(),
        normalized: normalized.into(),
        confidence,
        extraction_profile_id: extraction_profile_id.map(str::to_owned),
        evidence: Some(evidence),
        start: None,
        end: None,
    }
}

/// Evidence-reference payloads that `validate_evidence_reference` rejects.
///
/// Every door that admits a reference, standalone or nested, must reject all
/// of them. Shared so a nested door cannot be tested against a weaker list
/// than the standalone door.
fn noncanonical_evidence_ref_payloads() -> Vec<(&'static str, serde_json::Value)> {
    let canonical = serde_json::to_value(finding_evidence_ref("artifact-a", "entry-a")).unwrap();
    let mut payloads: Vec<(&'static str, serde_json::Value)> = Vec::new();

    for (label, field, value) in [
        ("a 5000-char artifact ID", "artifactId", "a".repeat(5000)),
        ("an empty artifact ID", "artifactId", String::new()),
        ("an untrimmed entry ID", "entryId", " entry-a ".to_owned()),
        ("an empty entry ID", "entryId", String::new()),
    ] {
        let mut json = canonical.clone();
        json[field] = serde_json::json!(value);
        payloads.push((label, json));
    }

    for (label, start, end) in [
        (
            "an inverted line range",
            serde_json::json!(9),
            serde_json::json!(2),
        ),
        (
            "a half-set line range",
            serde_json::json!(7),
            serde_json::Value::Null,
        ),
        (
            "a zero line start",
            serde_json::json!(0),
            serde_json::json!(1),
        ),
    ] {
        let mut json = canonical.clone();
        json["lineStart"] = start;
        json["lineEnd"] = end;
        payloads.push((label, json));
    }

    payloads
}

fn finding_client_gap(artifact_id: &str, coverage: SccmCoverageState) -> SccmFindingCoverageGap {
    SccmFindingCoverageGap {
        artifact_id: artifact_id.into(),
        role: SccmRole::Client,
        coverage,
    }
}

fn finding_request(logical_id: &str, role: SccmRole, reason: &str) -> SccmArtifactRequest {
    SccmArtifactRequest {
        logical_id: logical_id.into(),
        role,
        reason: reason.into(),
    }
}

fn finding_with_gap_and_request(finding_id: &str) -> SccmFinding {
    SccmFindingBuilder::new(finding_id)
        .class(SccmFindingClass::Symptom)
        .phase(SccmPhase::Policy)
        .role(SccmRole::Client)
        .severity(Severity::Warning)
        .confidence(SccmConfidence::Low)
        .evidence(vec![finding_evidence_ref("artifact-a", "entry-a")])
        .coverage_gap(finding_client_gap(
            "client-policy-agent",
            SccmCoverageState::AccessDenied,
        ))
        .next_artifact(finding_request(
            "policyAgent",
            SccmRole::Client,
            "Confirm the bounded policy request outcome.",
        ))
        .build()
        .unwrap()
}

const ROOTED_ARTIFACT_REQUEST_REASONS: [&str; 7] = [
    r"Collect C:\ for related evidence.",
    r"Collect C:\Windows\CCM\Logs\PolicyAgent.log.",
    r"Collect C:/Windows/CCM/Logs/PolicyAgent.log.",
    "Collect / for related evidence.",
    "Collect /var/log/sccm/PolicyAgent.log.",
    r"Collect \\server\share\PolicyAgent.log.",
    "Collect //server/share/PolicyAgent.log.",
];

const COMPACT_UNBOUNDED_ARTIFACT_REQUEST_REASONS: [&str; 5] = [
    "Collect allfiles.",
    "Collect everydirectory.",
    "Scan entiredisk.",
    "Search wholefilesystem.",
    "Collect every log on the system.",
];

const ORDER_INDEPENDENT_UNBOUNDED_ARTIFACT_REQUEST_REASONS: [&str; 12] = [
    "Every log on the system must be collected.",
    "Request all files on the system.",
    "Obtain every directory from the machine.",
    "Copy the entire filesystem for review.",
    "Enumerate all folders under the client.",
    "Download all logs from the device.",
    "Archive the whole disk.",
    "All files from every directory are required.",
    "Collect all of the files.",
    "Scan every single directory.",
    "Collect PolicyAgent.log plus logs at root.",
    "Collect PolicyAgent.log plus systemwide collection scope.",
];

const BOUNDED_NARRATIVE_ARTIFACT_REQUESTS: [(&str, &str); 5] = [
    ("smsts", "Collect the full disk imaging Task Sequence log."),
    (
        "policyAgent",
        "Confirm the whole-disk encryption status recorded in PolicyAgent.log.",
    ),
    (
        "policyAgent",
        "Confirm the system-wide assignment recorded in PolicyAgent.log.",
    ),
    (
        "policyAgent",
        "Confirm recursive retry behavior recorded in PolicyAgent.log.",
    ),
    (
        "policyAgent",
        "Confirm all files were downloaded, as recorded in PolicyAgent.log.",
    ),
];

const REVIEW_UNBOUNDED_ARTIFACT_REQUEST_REASONS: [&str; 19] = [
    "System-wide logs are required.",
    "Systemwide logs are required.",
    "Drive-wide files are requested.",
    "Logs from the filesystem root are required.",
    "The filesystem root must be archived.",
    "Recursive collection of system logs is required.",
    "Recursive traversal of the filesystem is required.",
    "All files were downloaded; collect them, as recorded in PolicyAgent.log.",
    "Archive the whole disk; encryption is recorded in PolicyAgent.log.",
    "Collect the full disk; imaging is recorded in Smsts.log.",
    "Collect the full disk imaging Task Sequence log recursively across directories.",
    "Collect the full disk imaging Task Sequence log and include recursive directory traversal.",
    "Collect the full disk imaging Task Sequence log; include folders recursively.",
    "Collect the full disk imaging Task Sequence log using recursion across folders.",
    "Confirm all files were downloaded, as recorded in PolicyAgent.log, with recursive directory inclusion.",
    "Confirm all files were downloaded, as recorded in PolicyAgent.log; recursive traversal across directories is also required.",
    "Collect the full disk imaging Task Sequence log plus system-wide logs.",
    "Collect the full disk imaging Task Sequence log plus systemwide logs.",
    "Confirm all files were downloaded, as recorded in PolicyAgent.log, plus logs from the filesystem root.",
];

const REVIEW_BOUNDED_NAMED_ARTIFACT_REQUESTS: [(&str, &str); 14] = [
    ("policyAgent", "Collect the complete PolicyAgent.log file."),
    ("policyAgent", "Collect every cited PolicyAgent.log entry."),
    (
        "policyAgent",
        "Confirm all assignment IDs in the cited PolicyAgent.log record.",
    ),
    (
        "dataTransferService",
        "Confirm complete file download status in DataTransferService.log.",
    ),
    ("policyAgent", "Collect all rotations of PolicyAgent.log."),
    (
        "policyAgent",
        "Confirm every retry in PolicyAgent.log for assignment A.",
    ),
    (
        "policyAgent",
        "Collect the whole PolicyAgent.log record cited by entry A.",
    ),
    (
        "policyAgent",
        "Confirm the full client policy in PolicyAgent.log.",
    ),
    ("smsts", "Collect the complete Task Sequence log."),
    (
        "dataTransferService",
        "Confirm all content files were downloaded, as recorded in DataTransferService.log.",
    ),
    (
        "dataTransferService",
        "Confirm all of the files were downloaded, as recorded in DataTransferService.log.",
    ),
    (
        "dataTransferService",
        "Confirm every file was downloaded, as recorded in DataTransferService.log.",
    ),
    ("smsts", "Confirm the full disk-image status in Smsts.log."),
    (
        "smsts",
        "Collect the complete disk imaging Task Sequence log.",
    ),
];

const REVIEW_EXPANDED_UNBOUNDED_ARTIFACT_REQUEST_REASONS: [&str; 49] = [
    "Recursively; collect PolicyAgent.log.",
    "Collect PolicyAgent.log. Recursively.",
    "Collect PolicyAgent.log! Recursively.",
    "Collect PolicyAgent.log; this request also applies recursively.",
    "Collect PolicyAgent.log; use recursion.",
    "Use recursion; collect PolicyAgent.log.",
    "Collect PolicyAgent.log; recurse.",
    "Recurse; collect PolicyAgent.log.",
    "Collect PolicyAgent.log; scan the filesystem.",
    "Scan the filesystem; collect PolicyAgent.log.",
    "Collect PolicyAgent.log; traverse directories.",
    "Collect PolicyAgent.log; enumerate the filesystem.",
    "Collect PolicyAgent.log; archive the filesystem.",
    "Collect PolicyAgent.log; search system logs.",
    "Collect PolicyAgent.log; gather device logs.",
    "Collect PolicyAgent.log; capture machine files.",
    "Collect PolicyAgent.log; logs from the machine.",
    "Collect PolicyAgent.log; across the filesystem.",
    "Collect PolicyAgent.log; throughout the system.",
    "Collect PolicyAgent.log; from root.",
    "At root; collect PolicyAgent.log.",
    "Collect PolicyAgent.log; device root.",
    "Collect PolicyAgent.log; systemwide.",
    "System-wide; collect PolicyAgent.log.",
    "Collect PolicyAgent.log; sitewide.",
    "Collect PolicyAgent.log; across all systems.",
    "Collect PolicyAgent.log; from every machine.",
    "Collect PolicyAgent.log; the entire system.",
    "Collect PolicyAgent.log; all data.",
    "Collect PolicyAgent.log; all records on the system.",
    "Collect PolicyAgent.log; everything from the system.",
    "Collect PolicyAgent.log; capture everything.",
    "Collect PolicyAgent.log; download all data.",
    "Collect PolicyAgent.log; collect related files.",
    "Collect all disks, status is recorded in PolicyAgent.log.",
    "Collect every drive, encryption status is recorded in PolicyAgent.log.",
    "Collect all files, download status is recorded in PolicyAgent.log.",
    "Collect the whole filesystem status from PolicyAgent.log.",
    "Collect complete machine status files recorded in PolicyAgent.log.",
    "Collect C:.",
    "Collect D: for evidence.",
    "Collect %SYSTEMROOT%.",
    "Collect %WINDIR%.",
    "Collect %SystemDrive%.",
    "Collect $env:SystemRoot.",
    "Collect ../PolicyAgent.log.",
    r"Collect ..\PolicyAgent.log.",
    "Collect Logs/../PolicyAgent.log.",
    "Collect PolicyAgent.log; recursively.",
];

const REVIEW_LOOKALIKE_ARTIFACT_REQUEST_REASONS: [&str; 4] = [
    "Collect every PolicyAgent-backup.log file.",
    "Collect every PolicyAgent.log.backup file.",
    "Collect every PolicyAgent—backup.log file.",
    "Collect every PolicyAgent backup file.",
];

const REVIEW_UNQUALIFIED_COLLECTION_ACTION_REASONS: [&str; 15] = [
    "Archive diagnostics.zip.",
    "Capture the registry.",
    "Collect unrelated.log.",
    "Copy database.db.",
    "Download package.bin.",
    "Enumerate registry keys.",
    "Export credentials.json.",
    "Gather diagnostics.",
    "Inspect arbitrary.txt.",
    "Obtain secrets.txt.",
    "Read config.ini.",
    "Scan unrelated.log.",
    "Search temp files.",
    "Traverse cache.",
    "Walk the directory tree.",
];

const REVIEW_COORDINATED_UNQUALIFIED_ACTION_REASONS: [&str; 3] = [
    "Collect PolicyAgent.log and archive.",
    "Collect PolicyAgent.log then scan.",
    "Collect PolicyAgent.log plus export.",
];

const REVIEW_UNBOUND_COLLECTION_TARGET_REASONS: [&str; 10] = [
    "Collect secrets.txt because PolicyAgent.log reported an error.",
    "Collect PolicyAgent.log and retrieve secrets.txt.",
    "Collect credentials.json since PolicyAgent.log recorded a failure.",
    "Collect evidence.zip after PolicyAgent.log reported a failure.",
    "Collect credentials because PolicyAgent.log reported an error.",
    "Collect PolicyAgent.log then retrieve credentials.json.",
    "Collect PolicyAgent.log plus fetch credentials.json.",
    "Collect PolicyAgent.log and preserve secrets.txt.",
    "Collect PolicyAgent.log, retrieve secrets.txt.",
    "Collect PolicyAgent.log and retrieve credentials.",
];

const REVIEW_SAFE_COLLECTION_NARRATIVE_REASONS: [&str; 4] = [
    "Collect PolicyAgent.log because the policy evaluation reported an error.",
    "Collect PolicyAgent.log for review of the reported assignment error.",
    "Collect PolicyAgent.log after the reported policy error.",
    "Policy evidence was not captured.",
];

const REVIEW_NON_AUTHORIZING_COLLECTION_LANGUAGE_REASONS: [&str; 6] = [
    "Collect PolicyAgent.log; retrieve secrets.txt.",
    "Collect PolicyAgent.log. Fetch credentials.",
    "Collect PolicyAgent.log; preserve secrets.txt.",
    "Collect PolicyAgent.log for collection of credentials.",
    "Collect PolicyAgent.log because secrets must be copied.",
    "Collect PolicyAgent.log after credentials were archived.",
];

const REVIEW_SAFE_STRONG_PUNCTUATION_NARRATIVE_REASONS: [&str; 3] = [
    "Collect PolicyAgent.log; policy evidence was not captured.",
    "Collect PolicyAgent.log. The policy evaluation reported an error.",
    "Collect PolicyAgent.log; the assignment error was reported.",
];

const REVIEW_EVIDENCE_SUBJECT_UNBOUND_PASSIVE_REASONS: [&str; 3] = [
    "Collect PolicyAgent.log; policy evidence must include credentials.",
    "Collect PolicyAgent.log; policy evidence needs credentials.",
    "Collect PolicyAgent.log. Policy evidence needs to include secrets.",
];

const REVIEW_STANDALONE_AND_INFLECTED_COLLECTION_REASONS: [&str; 6] = [
    "Retrieve secrets.txt.",
    "Fetch credentials.json.",
    "Preserve secrets.txt.",
    "Acquire credentials.json.",
    "Collect PolicyAgent.log for fetching credentials.",
    "Collect PolicyAgent.log after retrieving credentials.",
];

const REVIEW_UNRECOGNIZED_CONFIRMATION_REQUEST_REASONS: [&str; 10] = [
    "Confirm retrieve secrets.txt.",
    "Confirm acquire credentials.json.",
    "Confirm fetch credentials.json.",
    "Confirm preserve secrets.txt.",
    "Confirm retrieving credentials.",
    "Confirm fetching secrets.",
    "Confirm preservation of secrets.txt.",
    "Confirm collection of credentials.json.",
    "Confirm PolicyAgent.log after retrieving credentials.",
    "Confirm PolicyAgent.log for fetching credentials.",
];

const REVIEW_PASSIVE_UNBOUNDED_CONFIRMATION_REASONS: [&str; 36] = [
    "Confirm all files are required for status in PolicyAgent.log.",
    "Confirm every file must be provided for download status in PolicyAgent.log.",
    "Confirm the whole disk is required for imaging status in Smsts.log.",
    "Confirm the full disk must be provided for imaging status in Smsts.log.",
    "Confirm PolicyAgent.log status must include all files.",
    "Confirm Smsts.log imaging status must provide the full disk.",
    "Confirm PolicyAgent.log status must have all files provided.",
    "Confirm Smsts.log imaging status must have the full disk provided.",
    "Confirm PolicyAgent.log status has all files provided.",
    "Confirm PolicyAgent.log status has every file provided.",
    "Confirm all files have provided status in PolicyAgent.log.",
    "Confirm Smsts.log imaging status has the full disk provided.",
    "Confirm PolicyAgent.log status had every file.",
    "Confirm PolicyAgent.log status has all files.",
    "Confirm PolicyAgent.log status have every file.",
    "Confirm PolicyAgent.log status are all files.",
    "Confirm PolicyAgent.log status be all files.",
    "Confirm PolicyAgent.log status been all files.",
    "Confirm PolicyAgent.log status being all files.",
    "Confirm Smsts.log imaging status is the full disk.",
    "Confirm Smsts.log imaging status was the full disk.",
    "Confirm Smsts.log imaging status were the full disk.",
    "Confirm Smsts.log imaging status has the full disk.",
    "Confirm every file had status in PolicyAgent.log.",
    "Confirm every file has status in PolicyAgent.log.",
    "Confirm all files have status in PolicyAgent.log.",
    "Confirm all files are in PolicyAgent.log status.",
    "Confirm all files be in PolicyAgent.log status.",
    "Confirm all files have been in PolicyAgent.log status.",
    "Confirm all files are being in PolicyAgent.log status.",
    "Confirm the full disk is in Smsts.log imaging status.",
    "Confirm the full disk was in Smsts.log imaging status.",
    "Confirm the full disk were in Smsts.log imaging status.",
    "Confirm the full disk has imaging status in Smsts.log.",
    "Confirm all files, have status in PolicyAgent.log.",
    "Confirm the full disk, has imaging status in Smsts.log.",
];

const REVIEW_BOUNDED_AUXILIARY_CONFIRMATION_REASONS: [(&str, &str); 10] = [
    (
        "policyAgent",
        "Confirm PolicyAgent.log status had evidence.",
    ),
    (
        "policyAgent",
        "Confirm PolicyAgent.log status has evidence.",
    ),
    ("policyAgent", "Confirm PolicyAgent.log files have status."),
    (
        "policyAgent",
        "Confirm PolicyAgent.log files are downloaded.",
    ),
    (
        "policyAgent",
        "Confirm PolicyAgent.log status should be available.",
    ),
    (
        "policyAgent",
        "Confirm PolicyAgent.log status has been available.",
    ),
    (
        "policyAgent",
        "Confirm PolicyAgent.log status is being reported.",
    ),
    (
        "policyAgent",
        "Confirm PolicyAgent.log status is available.",
    ),
    (
        "policyAgent",
        "Confirm PolicyAgent.log status was available.",
    ),
    (
        "policyAgent",
        "Confirm PolicyAgent.log files were downloaded.",
    ),
];

const REVIEW_EXACT_MP_ARTIFACT_REQUESTS: [(&str, &str); 5] = [
    ("mpCliReg", "Collect the complete MP_CliReg.log file."),
    ("mpGetAuth", "Collect the complete MP_GetAuth.log file."),
    ("mpGetPolicy", "Collect the complete MP_GetPolicy.log file."),
    ("mpLocation", "Collect the complete MP_Location.log file."),
    (
        "mpRegistrationManager",
        "Collect the complete MP_RegistrationManager.log file.",
    ),
];

#[derive(Clone, Copy, Debug)]
enum FindingEvidenceAliasSurface {
    TopLevel,
    Terminal,
    CorrelationKey,
}

fn finding_with_evidence_alias(
    finding_id: &str,
    alias_surface: Option<FindingEvidenceAliasSurface>,
) -> Result<SccmFinding, SccmFindingValidationError> {
    let mut top_level = finding_evidence_ref("artifact-a", "entry-a");
    let mut terminal = top_level.clone();
    let mut key = top_level.clone();
    match alias_surface {
        Some(FindingEvidenceAliasSurface::TopLevel) => {
            top_level.artifact_id = " artifact-a ".into();
            top_level.entry_id = " entry-a ".into();
        }
        Some(FindingEvidenceAliasSurface::Terminal) => {
            terminal.artifact_id = " artifact-a ".into();
            terminal.entry_id = " entry-a ".into();
        }
        Some(FindingEvidenceAliasSurface::CorrelationKey) => {
            key.artifact_id = " artifact-a ".into();
            key.entry_id = " entry-a ".into();
        }
        None => {}
    }

    SccmFindingBuilder::new(finding_id)
        .class(SccmFindingClass::ConfirmedFailure)
        .phase(SccmPhase::Policy)
        .role(SccmRole::Client)
        .severity(Severity::Error)
        .confidence(SccmConfidence::High)
        .evidence(vec![top_level])
        .terminal_evidence(vec![SccmTerminalEvidence::observed_failure(terminal)])
        .correlation_keys(vec![finding_key(
            SccmCorrelationKeyKind::AssignmentId,
            "{ABCDEFAB-0000-0000-0000-000000000001}",
            "abcdefab-0000-0000-0000-000000000001",
            SccmKeyConfidence::Low,
            Some("sccm-keys-experimental-v1"),
            key,
        )])
        .build()
}

fn apply_evidence_alias(finding: &mut SccmFinding, surface: FindingEvidenceAliasSurface) {
    match surface {
        FindingEvidenceAliasSurface::TopLevel => {
            finding.evidence[0].artifact_id = " artifact-a ".into();
            finding.evidence[0].entry_id = " entry-a ".into();
        }
        FindingEvidenceAliasSurface::Terminal => {
            finding.terminal_evidence[0].reference.artifact_id = " artifact-a ".into();
            finding.terminal_evidence[0].reference.entry_id = " entry-a ".into();
        }
        FindingEvidenceAliasSurface::CorrelationKey => {
            let reference = finding.correlation_keys[0].evidence.as_mut().unwrap();
            reference.artifact_id = " artifact-a ".into();
            reference.entry_id = " entry-a ".into();
        }
    }
}

fn apply_evidence_alias_json(
    finding: &mut serde_json::Value,
    surface: FindingEvidenceAliasSurface,
) {
    match surface {
        FindingEvidenceAliasSurface::TopLevel => {
            finding["evidence"][0]["artifactId"] = serde_json::json!(" artifact-a ");
            finding["evidence"][0]["entryId"] = serde_json::json!(" entry-a ");
        }
        FindingEvidenceAliasSurface::Terminal => {
            finding["terminalEvidence"][0]["reference"]["artifactId"] =
                serde_json::json!(" artifact-a ");
            finding["terminalEvidence"][0]["reference"]["entryId"] = serde_json::json!(" entry-a ");
        }
        FindingEvidenceAliasSurface::CorrelationKey => {
            finding["correlationKeys"][0]["evidence"]["artifactId"] =
                serde_json::json!(" artifact-a ");
            finding["correlationKeys"][0]["evidence"]["entryId"] = serde_json::json!(" entry-a ");
        }
    }
}

fn assert_evidence_alias_is_rejected(surface: FindingEvidenceAliasSurface) {
    let mut mismatches = Vec::new();

    if finding_with_evidence_alias("builder-evidence-alias", Some(surface)).err()
        != Some(SccmFindingValidationError::InvalidEvidenceReference)
    {
        mismatches.push("builder did not return InvalidEvidenceReference");
    }

    let mut direct = finding_with_evidence_alias("direct-evidence-alias", None).unwrap();
    apply_evidence_alias(&mut direct, surface);
    if direct.validate().err() != Some(SccmFindingValidationError::InvalidEvidenceReference) {
        mismatches.push("direct validate did not return InvalidEvidenceReference");
    }
    if serde_json::to_value(&direct).is_ok() {
        mismatches.push("validating serializer accepted the alias");
    }

    let canonical = finding_with_evidence_alias("deserialized-evidence-alias", None).unwrap();
    let mut json = serde_json::to_value(canonical).unwrap();
    apply_evidence_alias_json(&mut json, surface);
    if serde_json::from_value::<SccmFinding>(json).is_ok() {
        mismatches.push("deserializer accepted the alias");
    }

    assert!(mismatches.is_empty(), "{surface:?}: {mismatches:?}");
}

#[test]
fn finding_confirmed_failure_requires_terminal_evidence() {
    let result = SccmFindingBuilder::new("app-enforcement-failed")
        .class(SccmFindingClass::ConfirmedFailure)
        .phase(SccmPhase::Enforcement)
        .role(SccmRole::Client)
        .severity(Severity::Error)
        .confidence(SccmConfidence::High)
        .evidence(vec![finding_evidence_ref(
            "client-app-enforce",
            "client-app-enforce:1-1",
        )])
        .build();

    assert_eq!(
        result.unwrap_err(),
        SccmFindingValidationError::MissingTerminalEvidence
    );
}

#[test]
fn finding_insufficient_evidence_requires_next_artifact_request() {
    let result = SccmFindingBuilder::new("missing-policy-log")
        .class(SccmFindingClass::InsufficientEvidence)
        .phase(SccmPhase::Policy)
        .role(SccmRole::Client)
        .severity(Severity::Warning)
        .confidence(SccmConfidence::Low)
        .coverage_gap(finding_client_gap(
            "client-policy-agent",
            SccmCoverageState::Absent,
        ))
        .build();

    assert_eq!(
        result.unwrap_err(),
        SccmFindingValidationError::MissingNextArtifactRequest
    );
}

#[test]
fn finding_high_confirmed_failure_accepts_a_cited_terminal_failure() {
    let evidence = finding_evidence_ref("client-app-enforce", "client-app-enforce:9-9");
    let finding = SccmFindingBuilder::new("app-enforcement-failed")
        .class(SccmFindingClass::ConfirmedFailure)
        .phase(SccmPhase::Enforcement)
        .role(SccmRole::Client)
        .severity(Severity::Error)
        .confidence(SccmConfidence::High)
        .evidence(vec![evidence.clone()])
        .terminal_evidence(vec![SccmTerminalEvidence::observed_failure(
            evidence.clone(),
        )])
        .build()
        .unwrap();

    assert_eq!(finding.evidence, vec![evidence.clone()]);
    assert_eq!(finding.terminal_evidence[0].reference, evidence);
    assert_eq!(
        finding.terminal_evidence[0].kind,
        SccmTerminalEvidenceKind::ObservedFailure
    );
}

#[test]
fn finding_rejects_unknown_phase_values_that_shadow_declared_names() {
    for phase in ["policy", "content", "enforcement"] {
        let result = SccmFindingBuilder::new(format!("shadowed-{phase}"))
            .class(SccmFindingClass::Symptom)
            .phase(SccmPhase::Unknown(phase.into()))
            .role(SccmRole::Client)
            .severity(Severity::Warning)
            .confidence(SccmConfidence::Low)
            .evidence(vec![finding_evidence_ref(
                "client-policy-agent",
                "policy:1-1",
            )])
            .build();

        assert_eq!(
            result.unwrap_err(),
            SccmFindingValidationError::MissingRequiredField,
            "{phase}"
        );
    }
}

#[test]
fn finding_forged_unregistered_profile_is_rejected() {
    let first = finding_evidence_ref("client-policy-agent", "policy:10-10");
    let second = finding_evidence_ref("mp-get-policy", "mp-policy:20-20");
    let result = SccmFindingBuilder::new("policy-request-failed")
        .class(SccmFindingClass::ConfirmedFailure)
        .phase(SccmPhase::Policy)
        .role(SccmRole::Client)
        .severity(Severity::Error)
        .confidence(SccmConfidence::High)
        .evidence(vec![second.clone(), first.clone()])
        .correlation_keys(vec![
            finding_key(
                SccmCorrelationKeyKind::AssignmentId,
                "{ABCDEFAB-0000-0000-0000-000000000001}",
                "abcdefab-0000-0000-0000-000000000001",
                SccmKeyConfidence::Exact,
                Some("sccm-keys-stable-v1"),
                first,
            ),
            finding_key(
                SccmCorrelationKeyKind::AssignmentId,
                "abcdefab-0000-0000-0000-000000000001",
                "abcdefab-0000-0000-0000-000000000001",
                SccmKeyConfidence::Strong,
                Some("sccm-keys-stable-v1"),
                second,
            ),
        ])
        .build();

    assert_eq!(
        result.unwrap_err(),
        SccmFindingValidationError::InvalidCorrelationKey
    );
}

#[test]
fn finding_review_invalid_profiled_keys_fail_at_every_public_boundary() {
    let evidence = finding_evidence_ref("artifact-a", "entry-a");
    let mut malformed = finding_key(
        SccmCorrelationKeyKind::PackageId,
        "",
        "",
        SccmKeyConfidence::Exact,
        Some("sccm-keys-stable-v1"),
        evidence.clone(),
    );
    malformed.start = Some(9);
    malformed.end = Some(3);
    let cases = [
        (
            "exact-without-profile",
            finding_key(
                SccmCorrelationKeyKind::AssignmentId,
                "{ABCDEFAB-0000-0000-0000-000000000001}",
                "abcdefab-0000-0000-0000-000000000001",
                SccmKeyConfidence::Exact,
                None,
                evidence.clone(),
            ),
        ),
        (
            "strong-with-unknown-profile",
            finding_key(
                SccmCorrelationKeyKind::ContentId,
                "ContentABC",
                "contentabc",
                SccmKeyConfidence::Strong,
                Some("sccm-keys-unknown-v1"),
                evidence.clone(),
            ),
        ),
        ("malformed-values-and-spans", malformed),
    ];
    let canonical = finding_with_gap_and_request("review-invalid-key-parity");
    let mut accepted = Vec::new();

    for (label, key) in cases {
        let builder = SccmFindingBuilder::new(format!("review-invalid-key-{label}"))
            .class(SccmFindingClass::Symptom)
            .phase(SccmPhase::Policy)
            .role(SccmRole::Client)
            .severity(Severity::Warning)
            .confidence(SccmConfidence::Low)
            .evidence(vec![evidence.clone()])
            .correlation_keys(vec![key.clone()])
            .build();
        if builder.err() != Some(SccmFindingValidationError::InvalidCorrelationKey) {
            accepted.push(format!(
                "builder did not return InvalidCorrelationKey: {label}"
            ));
        }

        let mut direct = canonical.clone();
        direct.correlation_keys = vec![key.clone()];
        if direct.validate().err() != Some(SccmFindingValidationError::InvalidCorrelationKey) {
            accepted.push(format!(
                "direct validate did not return InvalidCorrelationKey: {label}"
            ));
        }
        if serde_json::to_value(&direct).is_ok() {
            accepted.push(format!("serializer: {label}"));
        }

        let key_json = serde_json::json!({
            "kind": &key.kind,
            "raw": &key.raw,
            "normalized": &key.normalized,
            "confidence": &key.confidence,
            "extractionProfileId": &key.extraction_profile_id,
            "evidence": &key.evidence,
            "start": key.start,
            "end": key.end,
        });
        let mut json = serde_json::to_value(&canonical).unwrap();
        json["correlationKeys"] = serde_json::json!([key_json]);
        if serde_json::from_value::<SccmFinding>(json).is_ok() {
            accepted.push(format!("deserializer: {label}"));
        }
    }

    assert!(
        accepted.is_empty(),
        "accepted invalid profiled keys: {accepted:#?}"
    );
}

#[test]
fn finding_unregistered_exact_duplicate_keys_are_rejected() {
    let evidence = finding_evidence_ref("client-policy-agent", "policy:10-10");
    let key = finding_key(
        SccmCorrelationKeyKind::AssignmentId,
        "{ABCDEFAB-0000-0000-0000-000000000001}",
        "abcdefab-0000-0000-0000-000000000001",
        SccmKeyConfidence::Exact,
        Some("sccm-keys-stable-v1"),
        evidence.clone(),
    );
    let result = SccmFindingBuilder::new("duplicated-corroboration")
        .class(SccmFindingClass::ConfirmedFailure)
        .phase(SccmPhase::Policy)
        .role(SccmRole::Client)
        .severity(Severity::Error)
        .confidence(SccmConfidence::High)
        .evidence(vec![evidence])
        .correlation_keys(vec![key.clone(), key])
        .build();

    assert_eq!(
        result.unwrap_err(),
        SccmFindingValidationError::InvalidCorrelationKey
    );
}

#[test]
fn finding_same_minute_keyless_evidence_never_counts_as_high_confidence() {
    let result = SccmFindingBuilder::new("same-minute-is-not-causation")
        .class(SccmFindingClass::ConfirmedFailure)
        .phase(SccmPhase::Content)
        .role(SccmRole::Client)
        .severity(Severity::Error)
        .confidence(SccmConfidence::High)
        .evidence(vec![
            finding_evidence_ref("client-content", "client-content:12:00"),
            finding_evidence_ref("server-content", "server-content:12:00"),
        ])
        .build();

    assert_eq!(
        result.unwrap_err(),
        SccmFindingValidationError::MissingTerminalEvidence
    );
}

#[test]
fn finding_unregistered_strong_or_exact_key_profiles_are_rejected() {
    let first = finding_evidence_ref("client-content", "client-content:1-1");
    let second = finding_evidence_ref("server-content", "server-content:1-1");
    let cases = [
        (
            "mismatched-normalized-keys",
            finding_key(
                SccmCorrelationKeyKind::ContentId,
                "ContentABC",
                "contentabc",
                SccmKeyConfidence::Strong,
                Some("sccm-keys-stable-v1"),
                first.clone(),
            ),
            finding_key(
                SccmCorrelationKeyKind::ContentId,
                "ContentXYZ",
                "contentxyz",
                SccmKeyConfidence::Strong,
                Some("sccm-keys-stable-v1"),
                second.clone(),
            ),
        ),
        (
            "mismatched-key-profiles",
            finding_key(
                SccmCorrelationKeyKind::ContentId,
                "ContentABC",
                "contentabc",
                SccmKeyConfidence::Strong,
                Some("sccm-keys-stable-v1"),
                first.clone(),
            ),
            finding_key(
                SccmCorrelationKeyKind::ContentId,
                "contentabc",
                "contentabc",
                SccmKeyConfidence::Exact,
                Some("sccm-keys-stable-v2"),
                second.clone(),
            ),
        ),
    ];

    for (finding_id, first_key, second_key) in cases {
        let result = SccmFindingBuilder::new(finding_id)
            .class(SccmFindingClass::ConfirmedFailure)
            .phase(SccmPhase::Content)
            .role(SccmRole::Client)
            .severity(Severity::Error)
            .confidence(SccmConfidence::High)
            .evidence(vec![first.clone(), second.clone()])
            .correlation_keys(vec![first_key, second_key])
            .build();

        assert_eq!(
            result.unwrap_err(),
            SccmFindingValidationError::InvalidCorrelationKey,
            "{finding_id}"
        );
    }
}

#[test]
fn finding_rejects_key_or_terminal_refs_that_are_not_cited() {
    let cited = finding_evidence_ref("client-policy-agent", "policy:1-1");
    // `finding_evidence_ref` pins every span to line 1, so this reference used
    // to claim line 1 while calling itself `policy:2-2`. Two entry ids over one
    // physical line is the shape this suite now rejects outright, and it would
    // mask the uncited-reference rule under test. The span is spelled out to
    // match the entry id it advertises.
    let missing = SccmEvidenceRef {
        line_start: Some(2),
        line_end: Some(2),
        ..finding_evidence_ref("client-policy-agent", "policy:2-2")
    };

    let key_result = SccmFindingBuilder::new("uncited-key")
        .class(SccmFindingClass::Symptom)
        .phase(SccmPhase::Policy)
        .role(SccmRole::Client)
        .severity(Severity::Warning)
        .confidence(SccmConfidence::Low)
        .evidence(vec![cited.clone()])
        .correlation_keys(vec![finding_key(
            SccmCorrelationKeyKind::AssignmentId,
            "{ABCDEFAB-0000-0000-0000-000000000001}",
            "abcdefab-0000-0000-0000-000000000001",
            SccmKeyConfidence::Low,
            Some("sccm-keys-experimental-v1"),
            missing.clone(),
        )])
        .build();
    assert_eq!(
        key_result.unwrap_err(),
        SccmFindingValidationError::CorrelationKeyEvidenceNotCited
    );

    let terminal_result = SccmFindingBuilder::new("uncited-terminal")
        .class(SccmFindingClass::ConfirmedFailure)
        .phase(SccmPhase::Policy)
        .role(SccmRole::Client)
        .severity(Severity::Error)
        .confidence(SccmConfidence::High)
        .evidence(vec![cited])
        .terminal_evidence(vec![SccmTerminalEvidence::observed_failure(missing)])
        .build();
    assert_eq!(
        terminal_result.unwrap_err(),
        SccmFindingValidationError::TerminalEvidenceNotCited
    );
}

#[test]
fn finding_nested_references_use_shared_identity_validation() {
    let cited = finding_evidence_ref("client-policy-agent", "policy:1-1");
    let invalid = SccmEvidenceRef {
        artifact_id: " ".into(),
        entry_id: "policy:2-2".into(),
        line_start: Some(2),
        line_end: Some(2),
    };

    let terminal_result = SccmFindingBuilder::new("invalid-terminal-reference")
        .class(SccmFindingClass::Symptom)
        .phase(SccmPhase::Policy)
        .role(SccmRole::Client)
        .severity(Severity::Warning)
        .confidence(SccmConfidence::Low)
        .evidence(vec![cited.clone()])
        .terminal_evidence(vec![SccmTerminalEvidence::observed_failure(
            invalid.clone(),
        )])
        .build();
    assert_eq!(
        terminal_result.unwrap_err(),
        SccmFindingValidationError::InvalidEvidenceReference
    );

    let key_result = SccmFindingBuilder::new("invalid-key-reference")
        .class(SccmFindingClass::Symptom)
        .phase(SccmPhase::Policy)
        .role(SccmRole::Client)
        .severity(Severity::Warning)
        .confidence(SccmConfidence::Low)
        .evidence(vec![cited])
        .correlation_keys(vec![finding_key(
            SccmCorrelationKeyKind::AssignmentId,
            "{ABCDEFAB-0000-0000-0000-000000000001}",
            "abcdefab-0000-0000-0000-000000000001",
            SccmKeyConfidence::Low,
            Some("sccm-keys-experimental-v1"),
            invalid,
        )])
        .build();
    assert_eq!(
        key_result.unwrap_err(),
        SccmFindingValidationError::InvalidEvidenceReference
    );
}

#[test]
fn finding_evidence_reference_line_ranges_are_integral() {
    let cases = [
        ("missing-end", Some(1), None),
        ("missing-start", None, Some(1)),
        ("zero-start", Some(0), Some(1)),
        ("reversed", Some(2), Some(1)),
    ];

    for (label, line_start, line_end) in cases {
        let result = SccmFindingBuilder::new(format!("invalid-range-{label}"))
            .class(SccmFindingClass::Symptom)
            .phase(SccmPhase::Policy)
            .role(SccmRole::Client)
            .severity(Severity::Warning)
            .confidence(SccmConfidence::Low)
            .evidence(vec![SccmEvidenceRef {
                artifact_id: "client-policy-agent".into(),
                entry_id: "policy:1-1".into(),
                line_start,
                line_end,
            }])
            .build();

        assert_eq!(
            result.unwrap_err(),
            SccmFindingValidationError::InvalidEvidenceReference,
            "{label}"
        );
    }
}

#[test]
fn finding_evidence_reference_allows_an_unavailable_line_range() {
    let finding = SccmFindingBuilder::new("line-range-unavailable")
        .class(SccmFindingClass::Symptom)
        .phase(SccmPhase::Policy)
        .role(SccmRole::Client)
        .severity(Severity::Warning)
        .confidence(SccmConfidence::Low)
        .evidence(vec![SccmEvidenceRef {
            artifact_id: "client-policy-agent".into(),
            entry_id: "policy:logical-record".into(),
            line_start: None,
            line_end: None,
        }])
        .build()
        .unwrap();

    serde_json::to_value(finding).unwrap();
}

#[test]
fn finding_serialization_canonicalizes_public_collection_mutation() {
    let first = finding_evidence_ref("artifact-a", "entry-a");
    let second = finding_evidence_ref("artifact-b", "entry-b");
    let mut finding = SccmFindingBuilder::new("mutated-order")
        .class(SccmFindingClass::Symptom)
        .phase(SccmPhase::Policy)
        .role(SccmRole::Client)
        .severity(Severity::Warning)
        .confidence(SccmConfidence::Low)
        .evidence(vec![first.clone(), second.clone()])
        .terminal_evidence(vec![
            SccmTerminalEvidence::observed_failure(first.clone()),
            SccmTerminalEvidence::observed_failure(second.clone()),
        ])
        .coverage_gaps(vec![
            finding_client_gap("artifact-gap-a", SccmCoverageState::AccessDenied),
            finding_client_gap("artifact-gap-b", SccmCoverageState::Capped),
        ])
        .correlation_keys(vec![
            finding_key(
                SccmCorrelationKeyKind::AssignmentId,
                "{ABCDEFAB-0000-0000-0000-000000000001}",
                "abcdefab-0000-0000-0000-000000000001",
                SccmKeyConfidence::Low,
                Some("sccm-keys-experimental-v1"),
                first,
            ),
            finding_key(
                SccmCorrelationKeyKind::PackageId,
                "LAB00001",
                "LAB00001",
                SccmKeyConfidence::Low,
                Some("sccm-keys-experimental-v1"),
                second,
            ),
        ])
        .next_artifacts(vec![
            finding_request(
                "policyAgent",
                SccmRole::Client,
                "Confirm the bounded policy request outcome.",
            ),
            finding_request(
                "policyEvaluator",
                SccmRole::Client,
                "Confirm the bounded policy evaluation outcome.",
            ),
        ])
        .build()
        .unwrap();

    let expected = serde_json::to_value(&finding).unwrap();
    fn scramble<T: Clone>(values: &mut Vec<T>) {
        values.reverse();
        values.push(values[0].clone());
    }
    scramble(&mut finding.evidence);
    scramble(&mut finding.terminal_evidence);
    scramble(&mut finding.coverage_gaps);
    scramble(&mut finding.correlation_keys);
    scramble(&mut finding.next_artifacts);

    assert_eq!(serde_json::to_value(finding).unwrap(), expected);
}

#[test]
fn finding_rejects_conflicting_ranges_for_one_logical_evidence_identity() {
    let first = SccmEvidenceRef {
        artifact_id: "artifact-a".into(),
        entry_id: "entry-a".into(),
        line_start: Some(1),
        line_end: Some(1),
    };
    let conflicting = SccmEvidenceRef {
        line_start: Some(2),
        line_end: Some(2),
        ..first.clone()
    };
    let top_level = SccmFindingBuilder::new("conflicting-top-level-ranges")
        .class(SccmFindingClass::Symptom)
        .phase(SccmPhase::Policy)
        .role(SccmRole::Client)
        .severity(Severity::Warning)
        .confidence(SccmConfidence::Low)
        .evidence(vec![first.clone(), conflicting.clone()])
        .build();
    let terminal = SccmFindingBuilder::new("conflicting-terminal-range")
        .class(SccmFindingClass::Symptom)
        .phase(SccmPhase::Policy)
        .role(SccmRole::Client)
        .severity(Severity::Warning)
        .confidence(SccmConfidence::Low)
        .evidence(vec![first.clone()])
        .terminal_evidence(vec![SccmTerminalEvidence::observed_failure(
            conflicting.clone(),
        )])
        .build();
    let key = SccmFindingBuilder::new("conflicting-key-range")
        .class(SccmFindingClass::Symptom)
        .phase(SccmPhase::Policy)
        .role(SccmRole::Client)
        .severity(Severity::Warning)
        .confidence(SccmConfidence::Low)
        .evidence(vec![first])
        .correlation_keys(vec![finding_key(
            SccmCorrelationKeyKind::AssignmentId,
            "{ABCDEFAB-0000-0000-0000-000000000001}",
            "abcdefab-0000-0000-0000-000000000001",
            SccmKeyConfidence::Low,
            Some("sccm-keys-experimental-v1"),
            conflicting,
        )])
        .build();

    for (label, result) in [
        ("top-level", top_level),
        ("terminal", terminal),
        ("correlation-key", key),
    ] {
        assert_eq!(
            result.unwrap_err(),
            SccmFindingValidationError::ConflictingEvidenceReference,
            "{label}"
        );
    }

    let mut mutated = SccmFindingBuilder::new("mutated-conflicting-range")
        .class(SccmFindingClass::Symptom)
        .phase(SccmPhase::Policy)
        .role(SccmRole::Client)
        .severity(Severity::Warning)
        .confidence(SccmConfidence::Low)
        .evidence(vec![SccmEvidenceRef {
            artifact_id: "artifact-a".into(),
            entry_id: "entry-a".into(),
            line_start: Some(1),
            line_end: Some(1),
        }])
        .build()
        .unwrap();
    mutated.evidence.push(SccmEvidenceRef {
        artifact_id: " artifact-a ".into(),
        entry_id: " entry-a ".into(),
        line_start: Some(2),
        line_end: Some(2),
    });
    assert_eq!(
        mutated.validate().unwrap_err(),
        SccmFindingValidationError::InvalidEvidenceReference
    );
}

#[test]
fn finding_deserialization_prioritizes_conflicting_evidence_identity_ranges() {
    let evidence = finding_evidence_ref("artifact-a", "entry-a");
    let finding = SccmFindingBuilder::new("conflicting-deserialized-range")
        .class(SccmFindingClass::ConfirmedFailure)
        .phase(SccmPhase::Enforcement)
        .role(SccmRole::Client)
        .severity(Severity::Error)
        .confidence(SccmConfidence::High)
        .evidence(vec![evidence.clone()])
        .terminal_evidence(vec![SccmTerminalEvidence::observed_failure(evidence)])
        .build()
        .unwrap();
    let mut json = serde_json::to_value(finding).unwrap();
    json["terminalEvidence"][0]["reference"]["lineStart"] = serde_json::json!(2);
    json["terminalEvidence"][0]["reference"]["lineEnd"] = serde_json::json!(2);

    let error = serde_json::from_value::<SccmFinding>(json)
        .unwrap_err()
        .to_string();
    assert!(error.contains("ConflictingEvidenceReference"), "{error}");
}

#[test]
fn finding_serialization_prioritizes_conflicting_evidence_identity_ranges() {
    let evidence = finding_evidence_ref("artifact-a", "entry-a");
    let mut finding = SccmFindingBuilder::new("conflicting-serialized-range")
        .class(SccmFindingClass::Symptom)
        .phase(SccmPhase::Policy)
        .role(SccmRole::Client)
        .severity(Severity::Warning)
        .confidence(SccmConfidence::Low)
        .evidence(vec![evidence.clone()])
        .correlation_keys(vec![finding_key(
            SccmCorrelationKeyKind::AssignmentId,
            "{ABCDEFAB-0000-0000-0000-000000000001}",
            "abcdefab-0000-0000-0000-000000000001",
            SccmKeyConfidence::Low,
            Some("sccm-keys-experimental-v1"),
            evidence,
        )])
        .build()
        .unwrap();
    let key_reference = finding.correlation_keys[0].evidence.as_mut().unwrap();
    key_reference.line_start = Some(2);
    key_reference.line_end = Some(2);

    let error = serde_json::to_string(&finding).unwrap_err().to_string();
    assert!(error.contains("ConflictingEvidenceReference"), "{error}");
}

/// Builds one finding per citation surface, carrying `second` on that surface
/// only, so a validator that scans a single surface cannot pass by accident.
fn evidence_surface_findings(
    label: &str,
    first: &SccmEvidenceRef,
    second: &SccmEvidenceRef,
) -> Vec<(String, Result<SccmFinding, SccmFindingValidationError>)> {
    fn scaffold(finding_id: String) -> SccmFindingBuilder {
        SccmFindingBuilder::new(finding_id)
            .class(SccmFindingClass::Symptom)
            .phase(SccmPhase::Policy)
            .role(SccmRole::Client)
            .severity(Severity::Warning)
            .confidence(SccmConfidence::Low)
    }

    vec![
        (
            format!("{label}/top-level"),
            scaffold(format!("{label}-top-level"))
                .evidence(vec![first.clone(), second.clone()])
                .build(),
        ),
        (
            format!("{label}/terminal"),
            scaffold(format!("{label}-terminal"))
                .evidence(vec![first.clone()])
                .terminal_evidence(vec![SccmTerminalEvidence::observed_failure(second.clone())])
                .build(),
        ),
        (
            format!("{label}/correlation-key"),
            scaffold(format!("{label}-correlation-key"))
                .evidence(vec![first.clone()])
                .correlation_keys(vec![finding_key(
                    SccmCorrelationKeyKind::AssignmentId,
                    "{ABCDEFAB-0000-0000-0000-000000000001}",
                    "abcdefab-0000-0000-0000-000000000001",
                    SccmKeyConfidence::Low,
                    Some("sccm-keys-experimental-v1"),
                    second.clone(),
                )])
                .build(),
        ),
    ]
}

#[test]
fn finding_rejects_overlapping_ranges_across_distinct_evidence_identities() {
    let first = SccmEvidenceRef {
        artifact_id: "artifact-a".into(),
        entry_id: "entry-a".into(),
        line_start: Some(4),
        line_end: Some(6),
    };
    // Every case claims at least one physical line of `first` under a second
    // entry id, so the two references cannot both be the record they claim.
    let cases = [
        ("identical-span", Some(4), Some(6)),
        ("shared-start-line", Some(1), Some(4)),
        ("shared-end-line", Some(6), Some(9)),
        ("contained-span", Some(5), Some(5)),
        ("containing-span", Some(1), Some(9)),
        ("straddling-span", Some(5), Some(9)),
    ];

    for (label, line_start, line_end) in cases {
        let second = SccmEvidenceRef {
            entry_id: "entry-b".into(),
            line_start,
            line_end,
            ..first.clone()
        };
        for (surface, result) in evidence_surface_findings(label, &first, &second) {
            assert_eq!(
                result.unwrap_err(),
                SccmFindingValidationError::OverlappingEvidenceReference,
                "{surface}"
            );
        }
    }
}

#[test]
fn finding_overlap_rejection_survives_evidence_serde_round_trips() {
    let first = SccmEvidenceRef {
        artifact_id: "artifact-a".into(),
        entry_id: "entry-a".into(),
        line_start: Some(4),
        line_end: Some(6),
    };
    let mut finding = SccmFindingBuilder::new("overlapping-serde-ranges")
        .class(SccmFindingClass::Symptom)
        .phase(SccmPhase::Policy)
        .role(SccmRole::Client)
        .severity(Severity::Warning)
        .confidence(SccmConfidence::Low)
        .evidence(vec![
            first.clone(),
            SccmEvidenceRef {
                entry_id: "entry-b".into(),
                line_start: Some(7),
                line_end: Some(9),
                ..first
            },
        ])
        .build()
        .unwrap();

    let mut json = serde_json::to_value(&finding).unwrap();
    json["evidence"][1]["lineStart"] = serde_json::json!(6);
    let error = serde_json::from_value::<SccmFinding>(json)
        .unwrap_err()
        .to_string();
    assert!(error.contains("OverlappingEvidenceReference"), "{error}");

    finding.evidence[1].line_start = Some(6);
    assert_eq!(
        finding.validate().unwrap_err(),
        SccmFindingValidationError::OverlappingEvidenceReference
    );
    let error = serde_json::to_string(&finding).unwrap_err().to_string();
    assert!(error.contains("OverlappingEvidenceReference"), "{error}");
}

#[test]
fn finding_accepts_disjoint_and_unbounded_evidence_ranges() {
    let anchor = SccmEvidenceRef {
        artifact_id: "artifact-a".into(),
        entry_id: "entry-a".into(),
        line_start: Some(4),
        line_end: Some(6),
    };
    // Overlap is a claim about physical extent within one artifact. Adjacent
    // spans, other artifacts, and references that assert no extent at all are
    // all citations nine lanes already emit, and must keep validating.
    let cases = [
        (
            "adjacent-below",
            SccmEvidenceRef {
                entry_id: "entry-b".into(),
                line_start: Some(1),
                line_end: Some(3),
                ..anchor.clone()
            },
        ),
        (
            "adjacent-above",
            SccmEvidenceRef {
                entry_id: "entry-b".into(),
                line_start: Some(7),
                line_end: Some(9),
                ..anchor.clone()
            },
        ),
        (
            "same-span-other-artifact",
            SccmEvidenceRef {
                artifact_id: "artifact-b".into(),
                entry_id: "entry-b".into(),
                ..anchor.clone()
            },
        ),
        (
            "unbounded-second",
            SccmEvidenceRef {
                entry_id: "entry-b".into(),
                line_start: None,
                line_end: None,
                ..anchor.clone()
            },
        ),
    ];

    for (label, second) in cases {
        let finding = SccmFindingBuilder::new(format!("disjoint-{label}"))
            .class(SccmFindingClass::Symptom)
            .phase(SccmPhase::Policy)
            .role(SccmRole::Client)
            .severity(Severity::Warning)
            .confidence(SccmConfidence::Low)
            .evidence(vec![anchor.clone(), second])
            .build()
            .unwrap_or_else(|error| panic!("{label}: {error:?}"));
        let json = serde_json::to_value(&finding).unwrap();
        assert_eq!(
            serde_json::from_value::<SccmFinding>(json).unwrap(),
            finding,
            "{label}"
        );
    }

    // Two references that both assert no extent stay indistinguishable by span
    // and must not be treated as claiming the same lines.
    let unbounded = SccmEvidenceRef {
        artifact_id: "artifact-a".into(),
        entry_id: "entry-a".into(),
        line_start: None,
        line_end: None,
    };
    SccmFindingBuilder::new("disjoint-both-unbounded")
        .class(SccmFindingClass::Symptom)
        .phase(SccmPhase::Policy)
        .role(SccmRole::Client)
        .severity(Severity::Warning)
        .confidence(SccmConfidence::Low)
        .evidence(vec![
            unbounded.clone(),
            SccmEvidenceRef {
                entry_id: "entry-b".into(),
                ..unbounded
            },
        ])
        .build()
        .expect("unbounded references assert no physical extent");
}

#[test]
fn finding_rejects_top_level_evidence_identity_whitespace_aliases() {
    assert_evidence_alias_is_rejected(FindingEvidenceAliasSurface::TopLevel);
}

#[test]
fn finding_rejects_terminal_evidence_identity_whitespace_aliases() {
    assert_evidence_alias_is_rejected(FindingEvidenceAliasSurface::Terminal);
}

#[test]
fn finding_rejects_correlation_key_evidence_identity_whitespace_aliases() {
    assert_evidence_alias_is_rejected(FindingEvidenceAliasSurface::CorrelationKey);
}

#[test]
fn finding_rejects_noncanonical_opaque_ids_across_public_boundaries() {
    let mut mismatches = Vec::new();

    if finding_with_evidence_alias(" finding-id ", None).err()
        != Some(SccmFindingValidationError::MissingRequiredField)
    {
        mismatches.push("builder accepted a noncanonical finding ID");
    }
    let mut finding_id = finding_with_evidence_alias("finding-id", None).unwrap();
    finding_id.finding_id = " finding-id ".into();
    if finding_id.validate().err() != Some(SccmFindingValidationError::MissingRequiredField) {
        mismatches.push("direct validate accepted a noncanonical finding ID");
    }
    if serde_json::to_value(&finding_id).is_ok() {
        mismatches.push("serializer accepted a noncanonical finding ID");
    }
    let mut finding_id_json =
        serde_json::to_value(finding_with_evidence_alias("finding-id-json", None).unwrap())
            .unwrap();
    finding_id_json["findingId"] = serde_json::json!(" finding-id-json ");
    if serde_json::from_value::<SccmFinding>(finding_id_json).is_ok() {
        mismatches.push("deserializer accepted a noncanonical finding ID");
    }

    let gap_builder = SccmFindingBuilder::new("noncanonical-gap-id")
        .class(SccmFindingClass::Symptom)
        .phase(SccmPhase::Policy)
        .role(SccmRole::Client)
        .severity(Severity::Warning)
        .confidence(SccmConfidence::Low)
        .evidence(vec![finding_evidence_ref("artifact-a", "entry-a")])
        .coverage_gap(finding_client_gap(
            " client-policy-agent ",
            SccmCoverageState::AccessDenied,
        ))
        .build();
    if gap_builder.err() != Some(SccmFindingValidationError::InvalidCoverageGap) {
        mismatches.push("builder accepted a noncanonical coverage-gap artifact ID");
    }
    let mut gap = finding_with_gap_and_request("noncanonical-gap-direct");
    gap.coverage_gaps[0].artifact_id = " client-policy-agent ".into();
    if gap.validate().err() != Some(SccmFindingValidationError::InvalidCoverageGap) {
        mismatches.push("direct validate accepted a noncanonical coverage-gap artifact ID");
    }
    if serde_json::to_value(&gap).is_ok() {
        mismatches.push("serializer accepted a noncanonical coverage-gap artifact ID");
    }
    let mut gap_json =
        serde_json::to_value(finding_with_gap_and_request("noncanonical-gap-json")).unwrap();
    gap_json["coverageGaps"][0]["artifactId"] = serde_json::json!(" client-policy-agent ");
    if serde_json::from_value::<SccmFinding>(gap_json).is_ok() {
        mismatches.push("deserializer accepted a noncanonical coverage-gap artifact ID");
    }

    let request_builder = SccmFindingBuilder::new("noncanonical-request-id")
        .class(SccmFindingClass::Symptom)
        .phase(SccmPhase::Policy)
        .role(SccmRole::Client)
        .severity(Severity::Warning)
        .confidence(SccmConfidence::Low)
        .evidence(vec![finding_evidence_ref("artifact-a", "entry-a")])
        .next_artifact(finding_request(
            " policyAgent ",
            SccmRole::Client,
            " Confirm the bounded policy request outcome. ",
        ))
        .build();
    if request_builder.err() != Some(SccmFindingValidationError::UndeclaredArtifactRequest) {
        mismatches.push("builder accepted a noncanonical request logical ID");
    }
    let mut request = finding_with_gap_and_request("noncanonical-request-direct");
    request.next_artifacts[0].logical_id = " policyAgent ".into();
    request.next_artifacts[0].reason = " Confirm the bounded policy request outcome. ".into();
    if request.validate().err() != Some(SccmFindingValidationError::UndeclaredArtifactRequest) {
        mismatches.push("direct validate did not reject a noncanonical request logical ID");
    }
    if serde_json::to_value(&request).is_ok() {
        mismatches.push("serializer accepted a noncanonical request logical ID");
    }
    let mut request_json =
        serde_json::to_value(finding_with_gap_and_request("noncanonical-request-json")).unwrap();
    request_json["nextArtifacts"][0]["logicalId"] = serde_json::json!(" policyAgent ");
    request_json["nextArtifacts"][0]["reason"] =
        serde_json::json!(" Confirm the bounded policy request outcome. ");
    if serde_json::from_value::<SccmFinding>(request_json).is_ok() {
        mismatches.push("deserializer accepted a noncanonical request logical ID");
    }

    assert!(mismatches.is_empty(), "{mismatches:#?}");
}

fn bounded_finding_with_id(finding_id: &str) -> Result<SccmFinding, SccmFindingValidationError> {
    SccmFindingBuilder::new(finding_id)
        .class(SccmFindingClass::Symptom)
        .phase(SccmPhase::Policy)
        .role(SccmRole::Client)
        .severity(Severity::Warning)
        .confidence(SccmConfidence::Low)
        .evidence(vec![finding_evidence_ref("artifact-a", "entry-a")])
        .build()
}

#[test]
fn finding_rejects_overlong_opaque_ids_across_public_boundaries() {
    let mut mismatches: Vec<String> = Vec::new();
    let overlong_id = "a".repeat(257);
    let bounded_id = "a".repeat(256);

    if bounded_finding_with_id(&overlong_id).err()
        != Some(SccmFindingValidationError::MissingRequiredField)
    {
        mismatches.push("builder accepted an overlong finding ID".into());
    }

    for (label, artifact_id, entry_id) in [
        ("artifact ID", overlong_id.as_str(), "entry-a"),
        ("entry ID", "artifact-a", overlong_id.as_str()),
    ] {
        let result = SccmFindingBuilder::new("overlong-evidence-id")
            .class(SccmFindingClass::Symptom)
            .phase(SccmPhase::Policy)
            .role(SccmRole::Client)
            .severity(Severity::Warning)
            .confidence(SccmConfidence::Low)
            .evidence(vec![finding_evidence_ref(artifact_id, entry_id)])
            .build();
        if result.err() != Some(SccmFindingValidationError::InvalidEvidenceReference) {
            mismatches.push(format!("builder accepted an overlong evidence {label}"));
        }
    }

    let gap_result = SccmFindingBuilder::new("overlong-gap-artifact-id")
        .class(SccmFindingClass::Symptom)
        .phase(SccmPhase::Policy)
        .role(SccmRole::Client)
        .severity(Severity::Warning)
        .confidence(SccmConfidence::Low)
        .evidence(vec![finding_evidence_ref("artifact-a", "entry-a")])
        .coverage_gap(finding_client_gap(
            &overlong_id,
            SccmCoverageState::AccessDenied,
        ))
        .build();
    if gap_result.err() != Some(SccmFindingValidationError::InvalidCoverageGap) {
        mismatches.push("builder accepted an overlong coverage-gap artifact ID".into());
    }

    let key_evidence = finding_evidence_ref("artifact-a", "entry-a");
    let key_result = SccmFindingBuilder::new("overlong-key-profile-id")
        .class(SccmFindingClass::Symptom)
        .phase(SccmPhase::Policy)
        .role(SccmRole::Client)
        .severity(Severity::Warning)
        .confidence(SccmConfidence::Low)
        .evidence(vec![key_evidence.clone()])
        .correlation_keys(vec![finding_key(
            SccmCorrelationKeyKind::AssignmentId,
            "{ABCDEFAB-0000-0000-0000-000000000001}",
            "abcdefab-0000-0000-0000-000000000001",
            SccmKeyConfidence::Low,
            Some(overlong_id.as_str()),
            key_evidence,
        )])
        .build();
    if key_result.err() != Some(SccmFindingValidationError::InvalidCorrelationKey) {
        mismatches.push("builder accepted an overlong correlation-key profile ID".into());
    }

    let mut direct = bounded_finding_with_id("overlong-direct").unwrap();
    direct.finding_id = overlong_id.clone();
    if direct.validate().err() != Some(SccmFindingValidationError::MissingRequiredField) {
        mismatches.push("direct validate accepted an overlong finding ID".into());
    }
    if serde_json::to_value(&direct).is_ok() {
        mismatches.push("serializer accepted an overlong finding ID".into());
    }

    let canonical_json =
        serde_json::to_value(bounded_finding_with_id("overlong-json").unwrap()).unwrap();
    let mut finding_id_json = canonical_json.clone();
    finding_id_json["findingId"] = serde_json::json!(overlong_id);
    if serde_json::from_value::<SccmFinding>(finding_id_json).is_ok() {
        mismatches.push("deserializer accepted an overlong finding ID".into());
    }
    for field in ["artifactId", "entryId"] {
        let mut evidence_json = canonical_json.clone();
        evidence_json["evidence"][0][field] = serde_json::json!(overlong_id);
        if serde_json::from_value::<SccmFinding>(evidence_json).is_ok() {
            mismatches.push(format!(
                "deserializer accepted an overlong evidence {field}"
            ));
        }
    }

    let bounded = SccmFindingBuilder::new(bounded_id.as_str())
        .class(SccmFindingClass::Symptom)
        .phase(SccmPhase::Policy)
        .role(SccmRole::Client)
        .severity(Severity::Warning)
        .confidence(SccmConfidence::Low)
        .evidence(vec![finding_evidence_ref(&bounded_id, &bounded_id)])
        .build();
    match bounded {
        Ok(bounded) => {
            let json = serde_json::to_value(&bounded).unwrap();
            if serde_json::from_value::<SccmFinding>(json).ok().as_ref() != Some(&bounded) {
                mismatches.push("bound-length opaque IDs did not round trip".into());
            }
        }
        Err(error) => {
            mismatches.push(format!(
                "builder rejected bound-length opaque IDs: {error:?}"
            ));
        }
    }

    assert!(mismatches.is_empty(), "{mismatches:#?}");
}

#[test]
fn finding_rejects_overlong_display_text_across_public_boundaries() {
    let mut mismatches: Vec<String> = Vec::new();
    let overlong_title = "t".repeat(513);
    let overlong_summary = "s".repeat(2049);

    for (label, title, summary) in [
        ("title", overlong_title.as_str(), "bounded summary"),
        ("summary", "bounded title", overlong_summary.as_str()),
    ] {
        let result = SccmFindingBuilder::new("overlong-display-text")
            .class(SccmFindingClass::Symptom)
            .phase(SccmPhase::Policy)
            .role(SccmRole::Client)
            .severity(Severity::Warning)
            .confidence(SccmConfidence::Low)
            .title(title)
            .summary(summary)
            .evidence(vec![finding_evidence_ref("artifact-a", "entry-a")])
            .build();
        if result.err() != Some(SccmFindingValidationError::MissingRequiredField) {
            mismatches.push(format!("builder accepted an overlong {label}"));
        }
    }

    let mut direct = bounded_finding_with_id("overlong-title-direct").unwrap();
    direct.title = overlong_title.clone();
    if direct.validate().err() != Some(SccmFindingValidationError::MissingRequiredField) {
        mismatches.push("direct validate accepted an overlong title".into());
    }
    if serde_json::to_value(&direct).is_ok() {
        mismatches.push("serializer accepted an overlong title".into());
    }
    let mut direct = bounded_finding_with_id("overlong-summary-direct").unwrap();
    direct.summary = overlong_summary.clone();
    if direct.validate().err() != Some(SccmFindingValidationError::MissingRequiredField) {
        mismatches.push("direct validate accepted an overlong summary".into());
    }
    if serde_json::to_value(&direct).is_ok() {
        mismatches.push("serializer accepted an overlong summary".into());
    }

    let canonical_json =
        serde_json::to_value(bounded_finding_with_id("overlong-text-json").unwrap()).unwrap();
    for (field, value) in [("title", &overlong_title), ("summary", &overlong_summary)] {
        let mut json = canonical_json.clone();
        json[field] = serde_json::json!(value);
        if serde_json::from_value::<SccmFinding>(json).is_ok() {
            mismatches.push(format!("deserializer accepted an overlong {field}"));
        }
    }

    let bounded = SccmFindingBuilder::new("bound-length-display-text")
        .class(SccmFindingClass::Symptom)
        .phase(SccmPhase::Policy)
        .role(SccmRole::Client)
        .severity(Severity::Warning)
        .confidence(SccmConfidence::Low)
        .title("t".repeat(512))
        .summary("s".repeat(2048))
        .evidence(vec![finding_evidence_ref("artifact-a", "entry-a")])
        .build();
    match bounded {
        Ok(bounded) => {
            let json = serde_json::to_value(&bounded).unwrap();
            if serde_json::from_value::<SccmFinding>(json).ok().as_ref() != Some(&bounded) {
                mismatches.push("bound-length display text did not round trip".into());
            }
        }
        Err(error) => {
            mismatches.push(format!(
                "builder rejected bound-length display text: {error:?}"
            ));
        }
    }

    assert!(mismatches.is_empty(), "{mismatches:#?}");
}

#[test]
fn finding_rejects_display_text_whose_stored_form_exceeds_the_bound() {
    let mut accepted = Vec::new();

    for (label, title, summary) in [
        (
            "title",
            format!("{}bounded title", " ".repeat(512)),
            "bounded summary".to_owned(),
        ),
        (
            "summary",
            "bounded title".to_owned(),
            format!("{}bounded summary", " ".repeat(2048)),
        ),
    ] {
        let builder = SccmFindingBuilder::new("padded-display-text")
            .class(SccmFindingClass::Symptom)
            .phase(SccmPhase::Policy)
            .role(SccmRole::Client)
            .severity(Severity::Warning)
            .confidence(SccmConfidence::Low)
            .title(&title)
            .summary(&summary)
            .evidence(vec![finding_evidence_ref("artifact-a", "entry-a")])
            .build();
        if builder.err() != Some(SccmFindingValidationError::MissingRequiredField) {
            accepted.push(format!("builder accepted padded {label}"));
        }

        let mut direct = bounded_finding_with_id("padded-display-direct").unwrap();
        direct.title = title.clone();
        direct.summary = summary.clone();
        if direct.validate().err() != Some(SccmFindingValidationError::MissingRequiredField) {
            accepted.push(format!("direct validation accepted padded {label}"));
        }
        if serde_json::to_value(&direct).is_ok() {
            accepted.push(format!("serialization accepted padded {label}"));
        }

        let mut json =
            serde_json::to_value(bounded_finding_with_id("padded-display-json").unwrap()).unwrap();
        json["title"] = serde_json::json!(title);
        json["summary"] = serde_json::json!(summary);
        if serde_json::from_value::<SccmFinding>(json).is_ok() {
            accepted.push(format!("deserialization accepted padded {label}"));
        }
    }

    assert!(
        accepted.is_empty(),
        "accepted display text with an oversized stored form: {accepted:#?}"
    );
}

fn finding_with_ci_key_value(
    finding_id: &str,
    digits: &str,
) -> Result<SccmFinding, SccmFindingValidationError> {
    let key_evidence = finding_evidence_ref("artifact-a", "entry-a");
    SccmFindingBuilder::new(finding_id)
        .class(SccmFindingClass::Symptom)
        .phase(SccmPhase::Policy)
        .role(SccmRole::Client)
        .severity(Severity::Warning)
        .confidence(SccmConfidence::Low)
        .evidence(vec![key_evidence.clone()])
        .correlation_keys(vec![finding_key(
            SccmCorrelationKeyKind::CiId,
            digits,
            digits,
            SccmKeyConfidence::Low,
            Some("sccm-keys-experimental-v1"),
            key_evidence,
        )])
        .build()
}

#[test]
fn finding_rejects_overlong_correlation_key_values() {
    let mut mismatches: Vec<String> = Vec::new();
    let overlong_digits = "1".repeat(257);
    let bounded_digits = "1".repeat(256);

    if finding_with_ci_key_value("overlong-key-value", &overlong_digits).err()
        != Some(SccmFindingValidationError::InvalidCorrelationKey)
    {
        mismatches.push("builder accepted an overlong correlation-key value".into());
    }

    for field in ["raw", "normalized"] {
        let mut direct = finding_with_ci_key_value("overlong-key-value-direct", "71").unwrap();
        match field {
            "raw" => direct.correlation_keys[0].raw = overlong_digits.clone(),
            "normalized" => direct.correlation_keys[0].normalized = overlong_digits.clone(),
            _ => unreachable!(),
        }
        if direct.validate().err() != Some(SccmFindingValidationError::InvalidCorrelationKey) {
            mismatches.push(format!(
                "direct validate accepted an overlong {field} value"
            ));
        }
        if serde_json::to_value(&direct).is_ok() {
            mismatches.push(format!("serializer accepted an overlong {field} value"));
        }

        let mut json = serde_json::to_value(
            finding_with_ci_key_value("overlong-key-value-json", "71").unwrap(),
        )
        .unwrap();
        json["correlationKeys"][0][field] = serde_json::json!(overlong_digits);
        if serde_json::from_value::<SccmFinding>(json).is_ok() {
            mismatches.push(format!("deserializer accepted an overlong {field} value"));
        }
    }

    match finding_with_ci_key_value("bound-length-key-value", &bounded_digits) {
        Ok(bounded) => {
            let json = serde_json::to_value(&bounded).unwrap();
            if serde_json::from_value::<SccmFinding>(json).ok().as_ref() != Some(&bounded) {
                mismatches.push("bound-length correlation-key value did not round trip".into());
            }
        }
        Err(error) => {
            mismatches.push(format!(
                "builder rejected a bound-length correlation-key value: {error:?}"
            ));
        }
    }

    assert!(mismatches.is_empty(), "{mismatches:#?}");
}

#[test]
fn coverage_gap_deserializes_through_the_same_wire_contract_as_a_finding() {
    let mut mismatches: Vec<String> = Vec::new();

    let gap = finding_client_gap("client-policy-agent", SccmCoverageState::AccessDenied);
    let canonical = serde_json::to_value(&gap).unwrap();
    if serde_json::from_value::<SccmFindingCoverageGap>(canonical.clone())
        .ok()
        .as_ref()
        != Some(&gap)
    {
        mismatches.push("a canonical coverage gap did not round trip".into());
    }

    let mut unknown_field = canonical.clone();
    unknown_field["unexpectedField"] = serde_json::json!("surplus");
    if serde_json::from_value::<SccmFindingCoverageGap>(unknown_field).is_ok() {
        mismatches.push("coverage gap deserializer accepted an unknown field".into());
    }

    let mut captured = canonical.clone();
    captured["coverage"] = serde_json::json!("captured");
    if serde_json::from_value::<SccmFindingCoverageGap>(captured).is_ok() {
        mismatches.push("coverage gap deserializer accepted captured coverage".into());
    }

    for (label, artifact_id) in [
        ("an empty artifact ID", String::new()),
        (
            "an untrimmed artifact ID",
            " client-policy-agent ".to_owned(),
        ),
        ("an overlong artifact ID", "a".repeat(257)),
    ] {
        let mut json = canonical.clone();
        json["artifactId"] = serde_json::json!(artifact_id);
        if serde_json::from_value::<SccmFindingCoverageGap>(json).is_ok() {
            mismatches.push(format!("coverage gap deserializer accepted {label}"));
        }
    }

    let mut untrimmed_role = canonical.clone();
    untrimmed_role["role"] = serde_json::json!(" client ");
    if serde_json::from_value::<SccmFindingCoverageGap>(untrimmed_role).is_ok() {
        mismatches.push("coverage gap deserializer accepted a nested untrimmed role".into());
    }

    assert!(mismatches.is_empty(), "{mismatches:#?}");
}

#[test]
fn coverage_gap_serialization_enforces_the_full_standalone_contract() {
    let mut empty_artifact =
        finding_client_gap("client-policy-agent", SccmCoverageState::AccessDenied);
    empty_artifact.artifact_id.clear();
    let mut overlong_artifact =
        finding_client_gap("client-policy-agent", SccmCoverageState::AccessDenied);
    overlong_artifact.artifact_id = "a".repeat(257);
    let captured = finding_client_gap("client-policy-agent", SccmCoverageState::Captured);
    let mut mismatches = Vec::new();

    for (label, gap) in [
        ("an empty artifact ID", empty_artifact),
        ("an overlong artifact ID", overlong_artifact),
        ("captured coverage", captured),
    ] {
        match serde_json::to_value(gap) {
            Ok(_) => mismatches.push(format!("serializer accepted {label}")),
            Err(error) if !error.to_string().contains("InvalidCoverageGap") => {
                mismatches.push(format!(
                    "serializer rejected {label} with the wrong contract error: {error}"
                ));
            }
            Err(_) => {}
        }
    }

    assert!(mismatches.is_empty(), "{mismatches:#?}");
}

#[test]
fn artifact_request_deserializes_through_the_same_wire_contract_as_a_finding() {
    let mut mismatches: Vec<String> = Vec::new();

    let request = finding_request(
        "policyAgent",
        SccmRole::Client,
        "Confirm the bounded policy request outcome.",
    );
    let canonical = serde_json::to_value(&request).unwrap();
    if serde_json::from_value::<SccmArtifactRequest>(canonical.clone())
        .ok()
        .as_ref()
        != Some(&request)
    {
        mismatches.push("a canonical artifact request did not round trip".into());
    }

    let mut unknown_field = canonical.clone();
    unknown_field["unexpectedField"] = serde_json::json!("surplus");
    if serde_json::from_value::<SccmArtifactRequest>(unknown_field).is_ok() {
        mismatches.push("artifact request deserializer accepted an unknown field".into());
    }

    for (label, logical_id) in [
        ("an empty logical ID", String::new()),
        ("an untrimmed logical ID", " policyAgent ".to_owned()),
        ("an overlong logical ID", "a".repeat(257)),
        (
            "an undeclared logical ID",
            "not-a-declared-source".to_owned(),
        ),
    ] {
        let mut json = canonical.clone();
        json["logicalId"] = serde_json::json!(logical_id);
        if serde_json::from_value::<SccmArtifactRequest>(json).is_ok() {
            mismatches.push(format!("artifact request deserializer accepted {label}"));
        }
    }

    for (label, reason) in [
        ("an empty reason", String::new()),
        (
            "a rooted-path reason",
            ROOTED_ARTIFACT_REQUEST_REASONS[1].to_owned(),
        ),
        (
            "an overlong reason",
            "a".repeat(MAX_SCCM_ARTIFACT_REQUEST_REASON_CHARS + 1),
        ),
    ] {
        let mut json = canonical.clone();
        json["reason"] = serde_json::json!(reason);
        if serde_json::from_value::<SccmArtifactRequest>(json).is_ok() {
            mismatches.push(format!("artifact request deserializer accepted {label}"));
        }
    }

    for (label, role) in [
        ("a nested untrimmed role", " client "),
        ("a nested mismatched role", "distributionPoint"),
    ] {
        let mut json = canonical.clone();
        json["role"] = serde_json::json!(role);
        if serde_json::from_value::<SccmArtifactRequest>(json).is_ok() {
            mismatches.push(format!("artifact request deserializer accepted {label}"));
        }
    }

    assert!(mismatches.is_empty(), "{mismatches:#?}");
}

#[test]
fn artifact_request_serialization_enforces_the_full_standalone_contract() {
    let cases = [
        (
            "an undeclared logical ID",
            finding_request(
                "not-a-declared-source",
                SccmRole::Client,
                "Confirm the not-a-declared-source request outcome.",
            ),
            "UndeclaredArtifactRequest",
        ),
        (
            "a role mismatch",
            finding_request(
                "policyAgent",
                SccmRole::DistributionPoint,
                "Confirm the bounded policy request outcome.",
            ),
            "ArtifactRequestRoleMismatch",
        ),
        (
            "a rooted-path reason",
            finding_request(
                "policyAgent",
                SccmRole::Client,
                ROOTED_ARTIFACT_REQUEST_REASONS[1],
            ),
            "InvalidArtifactRequestReason",
        ),
        (
            "an out-of-scope reason",
            finding_request(
                "policyAgent",
                SccmRole::Client,
                "Collect the complete CAS.log file.",
            ),
            "InvalidArtifactRequestReason",
        ),
    ];
    let mut mismatches = Vec::new();

    for (label, request, expected_error) in cases {
        match serde_json::to_value(request) {
            Ok(_) => mismatches.push(format!("serializer accepted {label}")),
            Err(error) if !error.to_string().contains(expected_error) => mismatches.push(format!(
                "serializer rejected {label} with the wrong contract error: {error}"
            )),
            Err(_) => {}
        }
    }

    assert!(mismatches.is_empty(), "{mismatches:#?}");
}

#[test]
fn artifact_request_deserialization_returns_a_canonical_reason() {
    let mut json = serde_json::to_value(finding_request(
        "policyAgent",
        SccmRole::Client,
        "Confirm the bounded policy request outcome.",
    ))
    .unwrap();
    json["reason"] = serde_json::json!(" Confirm the bounded policy request outcome. ");

    let request = serde_json::from_value::<SccmArtifactRequest>(json).unwrap();

    assert_eq!(
        request.reason,
        "Confirm the bounded policy request outcome."
    );

    let serialized = serde_json::to_value(finding_request(
        "policyAgent",
        SccmRole::Client,
        " Confirm the bounded policy request outcome. ",
    ))
    .unwrap();
    assert_eq!(
        serialized["reason"],
        "Confirm the bounded policy request outcome."
    );
}

#[test]
fn artifact_request_rejects_padding_that_exceeds_the_reason_bound() {
    let reason = format!(
        "{}Confirm the bounded policy request outcome.",
        " ".repeat(MAX_SCCM_ARTIFACT_REQUEST_REASON_CHARS)
    );
    let mut accepted = Vec::new();

    let builder = SccmFindingBuilder::new("padded-request-builder")
        .class(SccmFindingClass::Symptom)
        .phase(SccmPhase::Policy)
        .role(SccmRole::Client)
        .severity(Severity::Warning)
        .confidence(SccmConfidence::Low)
        .evidence(vec![finding_evidence_ref("artifact-a", "entry-a")])
        .next_artifact(finding_request("policyAgent", SccmRole::Client, &reason))
        .build();
    if builder.err() != Some(SccmFindingValidationError::InvalidArtifactRequestReason) {
        accepted.push("builder".to_owned());
    }

    let mut direct = finding_with_gap_and_request("padded-request-direct");
    direct.next_artifacts[0].reason = reason.clone();
    if direct.validate().err() != Some(SccmFindingValidationError::InvalidArtifactRequestReason) {
        accepted.push("direct validation".to_owned());
    }
    if serde_json::to_value(&direct).is_ok() {
        accepted.push("serialization".to_owned());
    }

    let mut finding_json =
        serde_json::to_value(finding_with_gap_and_request("padded-request-json")).unwrap();
    finding_json["nextArtifacts"][0]["reason"] = serde_json::json!(&reason);
    if serde_json::from_value::<SccmFinding>(finding_json).is_ok() {
        accepted.push("finding deserialization".to_owned());
    }

    let mut request_json = serde_json::to_value(finding_request(
        "policyAgent",
        SccmRole::Client,
        "Confirm the bounded policy request outcome.",
    ))
    .unwrap();
    request_json["reason"] = serde_json::json!(reason);
    if serde_json::from_value::<SccmArtifactRequest>(request_json).is_ok() {
        accepted.push("standalone request deserialization".to_owned());
    }
    if serde_json::to_value(finding_request("policyAgent", SccmRole::Client, &reason)).is_ok() {
        accepted.push("standalone request serialization".to_owned());
    }

    assert!(
        accepted.is_empty(),
        "accepted an artifact request whose stored reason exceeds the bound: {accepted:#?}"
    );
}

#[test]
fn evidence_ref_deserializes_through_the_same_wire_contract_as_a_finding() {
    let mut mismatches: Vec<String> = Vec::new();

    let reference = finding_evidence_ref("artifact-a", "entry-a");
    let canonical = serde_json::to_value(&reference).unwrap();
    if serde_json::from_value::<SccmEvidenceRef>(canonical.clone())
        .ok()
        .as_ref()
        != Some(&reference)
    {
        mismatches.push("a canonical evidence ref did not round trip".into());
    }

    let mut unknown_field = canonical.clone();
    unknown_field["unexpectedField"] = serde_json::json!("surplus");
    if serde_json::from_value::<SccmEvidenceRef>(unknown_field).is_ok() {
        mismatches.push("evidence ref deserializer accepted an unknown field".into());
    }

    for (label, json) in noncanonical_evidence_ref_payloads() {
        if serde_json::from_value::<SccmEvidenceRef>(json).is_ok() {
            mismatches.push(format!("evidence ref deserializer accepted {label}"));
        }
    }

    assert!(mismatches.is_empty(), "{mismatches:#?}");
}

#[test]
fn evidence_ref_serialization_enforces_the_full_standalone_contract() {
    let canonical = finding_evidence_ref("artifact-a", "entry-a");
    let mut empty_artifact = canonical.clone();
    empty_artifact.artifact_id.clear();
    let mut overlong_entry = canonical.clone();
    overlong_entry.entry_id = "e".repeat(257);
    let mut half_set_range = canonical.clone();
    half_set_range.line_end = None;
    let mut zero_start = canonical.clone();
    zero_start.line_start = Some(0);
    let mut inverted_range = canonical;
    inverted_range.line_start = Some(9);
    inverted_range.line_end = Some(2);

    let mut mismatches = Vec::new();
    for (label, reference) in [
        ("an empty artifact ID", empty_artifact),
        ("an overlong entry ID", overlong_entry),
        ("a half-set line range", half_set_range),
        ("a zero line start", zero_start),
        ("an inverted line range", inverted_range),
    ] {
        match serde_json::to_value(reference) {
            Ok(_) => mismatches.push(format!("serializer accepted {label}")),
            Err(error) if !error.to_string().contains("InvalidEvidenceReference") => {
                mismatches.push(format!(
                    "serializer rejected {label} with the wrong contract error: {error}"
                ));
            }
            Err(_) => {}
        }
    }

    assert!(mismatches.is_empty(), "{mismatches:#?}");
}

#[test]
fn terminal_evidence_deserializes_through_the_same_wire_contract_as_a_finding() {
    let mut mismatches: Vec<String> = Vec::new();

    let terminal =
        SccmTerminalEvidence::observed_failure(finding_evidence_ref("artifact-a", "entry-a"));
    let canonical = serde_json::to_value(&terminal).unwrap();
    if serde_json::from_value::<SccmTerminalEvidence>(canonical.clone())
        .ok()
        .as_ref()
        != Some(&terminal)
    {
        mismatches.push("a canonical terminal evidence did not round trip".into());
    }

    let mut unknown_field = canonical.clone();
    unknown_field["unexpectedField"] = serde_json::json!("surplus");
    if serde_json::from_value::<SccmTerminalEvidence>(unknown_field).is_ok() {
        mismatches.push("terminal evidence deserializer accepted an unknown field".into());
    }

    let mut nested_unknown = canonical.clone();
    nested_unknown["reference"]["unexpectedField"] = serde_json::json!("surplus");
    if serde_json::from_value::<SccmTerminalEvidence>(nested_unknown).is_ok() {
        mismatches.push("terminal evidence deserializer accepted a nested unknown field".into());
    }

    for (label, reference) in noncanonical_evidence_ref_payloads() {
        let mut json = canonical.clone();
        json["reference"] = reference;
        if serde_json::from_value::<SccmTerminalEvidence>(json).is_ok() {
            mismatches.push(format!(
                "terminal evidence deserializer accepted nested {label}"
            ));
        }
    }

    let mut non_terminal_kind = canonical.clone();
    non_terminal_kind["kind"] = serde_json::json!("observedRecovery");
    if serde_json::from_value::<SccmTerminalEvidence>(non_terminal_kind).is_ok() {
        mismatches.push("terminal evidence deserializer accepted a non-failure kind".into());
    }

    assert!(mismatches.is_empty(), "{mismatches:#?}");
}

#[test]
fn terminal_evidence_serialization_enforces_the_full_standalone_contract() {
    let mut invalid_reference =
        SccmTerminalEvidence::observed_failure(finding_evidence_ref("artifact-a", "entry-a"));
    invalid_reference.reference.artifact_id.clear();
    let non_terminal_kind = SccmTerminalEvidence {
        reference: finding_evidence_ref("artifact-a", "entry-a"),
        kind: SccmTerminalEvidenceKind::Unknown("observedRecovery".to_owned()),
    };
    let mut mismatches = Vec::new();

    for (label, terminal, expected_error) in [
        (
            "an invalid nested reference",
            invalid_reference,
            "InvalidEvidenceReference",
        ),
        (
            "a non-failure terminal kind",
            non_terminal_kind,
            "InvalidTerminalEvidence",
        ),
    ] {
        match serde_json::to_value(terminal) {
            Ok(_) => mismatches.push(format!("serializer accepted {label}")),
            Err(error) if !error.to_string().contains(expected_error) => mismatches.push(format!(
                "serializer rejected {label} with the wrong contract error: {error}"
            )),
            Err(_) => {}
        }
    }

    assert!(mismatches.is_empty(), "{mismatches:#?}");
}

#[test]
fn correlation_key_deserializes_through_the_same_wire_contract_as_a_finding() {
    let mut mismatches: Vec<String> = Vec::new();

    let key = finding_key(
        SccmCorrelationKeyKind::CiId,
        "71",
        "71",
        SccmKeyConfidence::Low,
        Some("sccm-keys-experimental-v1"),
        finding_evidence_ref("artifact-a", "entry-a"),
    );
    let canonical = serde_json::to_value(&key).unwrap();
    if serde_json::from_value::<SccmCorrelationKey>(canonical.clone())
        .ok()
        .as_ref()
        != Some(&key)
    {
        mismatches.push("a canonical correlation key did not round trip".into());
    }

    let mut unknown_field = canonical.clone();
    unknown_field["unexpectedField"] = serde_json::json!("surplus");
    if serde_json::from_value::<SccmCorrelationKey>(unknown_field).is_ok() {
        mismatches.push("correlation key deserializer accepted an unknown field".into());
    }

    // The trust-signal bypass. REGISTERED_STABLE_CORRELATION_PROFILE_IDS is
    // deliberately empty, so validate_correlation_key_evidence holds every key
    // at Low; standalone deserialization must not let a payload forge a
    // stronger confidence than any registered profile can authorize.
    for forged in ["exact", "strong"] {
        let mut json = canonical.clone();
        json["confidence"] = serde_json::json!(forged);
        if serde_json::from_value::<SccmCorrelationKey>(json).is_ok() {
            mismatches.push(format!(
                "correlation key deserializer accepted forged {forged} confidence"
            ));
        }
    }

    for (label, field, value) in [
        ("a 5000-char raw value", "raw", "1".repeat(5000)),
        (
            "a 5000-char normalized value",
            "normalized",
            "1".repeat(5000),
        ),
        ("an empty raw value", "raw", String::new()),
    ] {
        let mut json = canonical.clone();
        json[field] = serde_json::json!(value);
        if serde_json::from_value::<SccmCorrelationKey>(json).is_ok() {
            mismatches.push(format!("correlation key deserializer accepted {label}"));
        }
    }

    let mut incoherent_span = canonical.clone();
    incoherent_span["start"] = serde_json::json!(99999);
    incoherent_span["end"] = serde_json::json!(1);
    if serde_json::from_value::<SccmCorrelationKey>(incoherent_span).is_ok() {
        mismatches.push("correlation key deserializer accepted an incoherent span".into());
    }

    let mut overlong_profile = canonical.clone();
    overlong_profile["extractionProfileId"] = serde_json::json!("p".repeat(257));
    if serde_json::from_value::<SccmCorrelationKey>(overlong_profile).is_ok() {
        mismatches.push("correlation key deserializer accepted an overlong profile ID".into());
    }

    let mut no_evidence = canonical.clone();
    no_evidence["evidence"] = serde_json::Value::Null;
    if serde_json::from_value::<SccmCorrelationKey>(no_evidence).is_ok() {
        mismatches.push("correlation key deserializer accepted a key with no evidence".into());
    }

    // The key's own evidence reference is the citation set the contract checks
    // it against, so `evidence.contains(reference)` is self-satisfying here. It
    // proves nothing about the reference itself, which must still clear the
    // same bar a standalone SccmEvidenceRef clears.
    let mut nested_unknown = canonical.clone();
    nested_unknown["evidence"]["unexpectedField"] = serde_json::json!("surplus");
    if serde_json::from_value::<SccmCorrelationKey>(nested_unknown).is_ok() {
        mismatches.push("correlation key deserializer accepted a nested unknown field".into());
    }

    for (label, evidence) in noncanonical_evidence_ref_payloads() {
        let mut json = canonical.clone();
        json["evidence"] = evidence;
        if serde_json::from_value::<SccmCorrelationKey>(json).is_ok() {
            mismatches.push(format!(
                "correlation key deserializer accepted nested {label}"
            ));
        }
    }

    assert!(mismatches.is_empty(), "{mismatches:#?}");
}

#[test]
fn correlation_key_serialization_enforces_the_full_standalone_contract() {
    let canonical = finding_key(
        SccmCorrelationKeyKind::CiId,
        "71",
        "71",
        SccmKeyConfidence::Low,
        Some("sccm-keys-experimental-v1"),
        finding_evidence_ref("artifact-a", "entry-a"),
    );
    let mut overlong_raw = canonical.clone();
    overlong_raw.raw = "1".repeat(257);
    let mut overlong_normalized = canonical.clone();
    overlong_normalized.normalized = "1".repeat(257);
    let mut forged_confidence = canonical.clone();
    forged_confidence.confidence = SccmKeyConfidence::Strong;
    let mut invalid_evidence = canonical.clone();
    invalid_evidence
        .evidence
        .as_mut()
        .unwrap()
        .artifact_id
        .clear();
    let mut missing_evidence = canonical.clone();
    missing_evidence.evidence = None;
    let mut incoherent_span = canonical;
    incoherent_span.start = Some(8);
    incoherent_span.end = Some(9);

    let mut mismatches = Vec::new();
    for (label, key, expected_error) in [
        (
            "an overlong raw value",
            overlong_raw,
            "InvalidCorrelationKey",
        ),
        (
            "an overlong normalized value",
            overlong_normalized,
            "InvalidCorrelationKey",
        ),
        (
            "forged strong confidence",
            forged_confidence,
            "InvalidCorrelationKey",
        ),
        (
            "an invalid evidence reference",
            invalid_evidence,
            "InvalidEvidenceReference",
        ),
        (
            "a missing evidence reference",
            missing_evidence,
            "CorrelationKeyMissingEvidence",
        ),
        (
            "an incoherent UTF-16 span",
            incoherent_span,
            "InvalidCorrelationKey",
        ),
    ] {
        match serde_json::to_value(key) {
            Ok(_) => mismatches.push(format!("serializer accepted {label}")),
            Err(error) if !error.to_string().contains(expected_error) => mismatches.push(format!(
                "serializer rejected {label} with the wrong contract error: {error}"
            )),
            Err(_) => {}
        }
    }

    assert!(mismatches.is_empty(), "{mismatches:#?}");
}

#[test]
fn key_extraction_result_deserializes_keys_through_the_same_wire_contract() {
    let mut mismatches: Vec<String> = Vec::new();

    let result = SccmKeyExtractionResult {
        profile_id: "sccm-keys-experimental-v1".into(),
        keys: vec![finding_key(
            SccmCorrelationKeyKind::CiId,
            "71",
            "71",
            SccmKeyConfidence::Low,
            Some("sccm-keys-experimental-v1"),
            finding_evidence_ref("artifact-a", "entry-a"),
        )],
        gaps: Vec::new(),
    };
    let canonical = serde_json::to_value(&result).unwrap();
    if serde_json::from_value::<SccmKeyExtractionResult>(canonical.clone())
        .ok()
        .as_ref()
        != Some(&result)
    {
        mismatches.push("a canonical key extraction result did not round trip".into());
    }

    for (label, evidence) in noncanonical_evidence_ref_payloads() {
        let mut json = canonical.clone();
        json["keys"][0]["evidence"] = evidence;
        if serde_json::from_value::<SccmKeyExtractionResult>(json).is_ok() {
            mismatches.push(format!(
                "key extraction result deserializer accepted nested {label}"
            ));
        }
    }

    assert!(mismatches.is_empty(), "{mismatches:#?}");
}

#[test]
fn finding_rejects_whitespace_wrapped_declared_phase_shadow() {
    let result = SccmFindingBuilder::new("wrapped-phase-shadow")
        .class(SccmFindingClass::Symptom)
        .phase(SccmPhase::Unknown(" policy ".into()))
        .role(SccmRole::Client)
        .severity(Severity::Warning)
        .confidence(SccmConfidence::Low)
        .evidence(vec![finding_evidence_ref("artifact-a", "entry-a")])
        .build();

    assert_eq!(
        result.unwrap_err(),
        SccmFindingValidationError::MissingRequiredField
    );

    let mut mutated = SccmFindingBuilder::new("direct-wrapped-phase-shadow")
        .class(SccmFindingClass::Symptom)
        .phase(SccmPhase::Policy)
        .role(SccmRole::Client)
        .severity(Severity::Warning)
        .confidence(SccmConfidence::Low)
        .evidence(vec![finding_evidence_ref("artifact-a", "entry-a")])
        .build()
        .unwrap();
    mutated.phase = SccmPhase::Unknown(" policy ".into());
    assert_eq!(
        mutated.validate().unwrap_err(),
        SccmFindingValidationError::MissingRequiredField
    );
}

#[test]
fn finding_deserialization_rejects_whitespace_wrapped_declared_phase_shadow() {
    let finding = SccmFindingBuilder::new("deserialized-wrapped-phase-shadow")
        .class(SccmFindingClass::Symptom)
        .phase(SccmPhase::Policy)
        .role(SccmRole::Client)
        .severity(Severity::Warning)
        .confidence(SccmConfidence::Low)
        .evidence(vec![finding_evidence_ref("artifact-a", "entry-a")])
        .build()
        .unwrap();
    let mut json = serde_json::to_value(finding).unwrap();
    json["phase"] = serde_json::json!(" policy ");

    assert!(serde_json::from_value::<SccmFinding>(json).is_err());
}

#[test]
fn finding_serialization_rejects_whitespace_wrapped_declared_phase_shadow() {
    let mut finding = SccmFindingBuilder::new("serialized-wrapped-phase-shadow")
        .class(SccmFindingClass::Symptom)
        .phase(SccmPhase::Policy)
        .role(SccmRole::Client)
        .severity(Severity::Warning)
        .confidence(SccmConfidence::Low)
        .evidence(vec![finding_evidence_ref("artifact-a", "entry-a")])
        .build()
        .unwrap();
    finding.phase = SccmPhase::Unknown(" policy ".into());

    assert!(serde_json::to_value(finding).is_err());
}

#[test]
fn finding_rejects_noncanonical_future_phase_whitespace() {
    let result = SccmFindingBuilder::new("noncanonical-future-phase")
        .class(SccmFindingClass::Symptom)
        .phase(SccmPhase::Unknown(" futurePhase ".into()))
        .role(SccmRole::Client)
        .severity(Severity::Warning)
        .confidence(SccmConfidence::Low)
        .evidence(vec![finding_evidence_ref("artifact-a", "entry-a")])
        .build();

    assert_eq!(
        result.unwrap_err(),
        SccmFindingValidationError::MissingRequiredField
    );

    let mut mutated = SccmFindingBuilder::new("direct-noncanonical-future-phase")
        .class(SccmFindingClass::Symptom)
        .phase(SccmPhase::Unknown("futurePhase".into()))
        .role(SccmRole::Client)
        .severity(Severity::Warning)
        .confidence(SccmConfidence::Low)
        .evidence(vec![finding_evidence_ref("artifact-a", "entry-a")])
        .build()
        .unwrap();
    mutated.phase = SccmPhase::Unknown(" futurePhase ".into());
    assert_eq!(
        mutated.validate().unwrap_err(),
        SccmFindingValidationError::MissingRequiredField
    );
    assert!(serde_json::to_value(&mutated).is_err());

    let mut json = serde_json::to_value(
        SccmFindingBuilder::new("deserialized-noncanonical-future-phase")
            .class(SccmFindingClass::Symptom)
            .phase(SccmPhase::Unknown("futurePhase".into()))
            .role(SccmRole::Client)
            .severity(Severity::Warning)
            .confidence(SccmConfidence::Low)
            .evidence(vec![finding_evidence_ref("artifact-a", "entry-a")])
            .build()
            .unwrap(),
    )
    .unwrap();
    json["phase"] = serde_json::json!(" futurePhase ");
    assert!(serde_json::from_value::<SccmFinding>(json).is_err());
}

#[test]
fn finding_phase_unknown_values_require_canonical_standalone_serde() {
    for value in ["", " ", " policy ", " futurePhase "] {
        assert!(
            serde_json::to_string(&SccmPhase::Unknown(value.into())).is_err(),
            "serialized {value:?}"
        );
        let wire = serde_json::to_string(value).unwrap();
        assert!(
            serde_json::from_str::<SccmPhase>(&wire).is_err(),
            "deserialized {value:?}"
        );
    }
    for value in ["policy", "content", "enforcement"] {
        assert!(
            serde_json::to_string(&SccmPhase::Unknown(value.into())).is_err(),
            "shadowed {value:?}"
        );
    }

    let phase = SccmPhase::Unknown("futurePhase".into());
    let wire = serde_json::to_string(&phase).unwrap();
    assert_eq!(serde_json::from_str::<SccmPhase>(&wire).unwrap(), phase);

    let finding = SccmFindingBuilder::new("canonical-future-phase")
        .class(SccmFindingClass::Symptom)
        .phase(phase)
        .role(SccmRole::Client)
        .severity(Severity::Warning)
        .confidence(SccmConfidence::Low)
        .evidence(vec![finding_evidence_ref("artifact-a", "entry-a")])
        .build()
        .unwrap();
    assert_eq!(
        serde_json::to_value(finding).unwrap()["phase"],
        "futurePhase"
    );
}

#[test]
fn finding_terminal_evidence_kind_unknown_values_require_canonical_standalone_serde() {
    for value in ["", " ", " futureTerminalKind "] {
        assert!(
            serde_json::to_string(&SccmTerminalEvidenceKind::Unknown(value.into())).is_err(),
            "serialized {value:?}"
        );
        let wire = serde_json::to_string(value).unwrap();
        assert!(
            serde_json::from_str::<SccmTerminalEvidenceKind>(&wire).is_err(),
            "deserialized {value:?}"
        );
    }
    assert!(
        serde_json::to_string(&SccmTerminalEvidenceKind::Unknown("observedFailure".into()))
            .is_err()
    );

    let future = SccmTerminalEvidenceKind::Unknown("futureTerminalKind".into());
    let wire = serde_json::to_string(&future).unwrap();
    assert_eq!(
        serde_json::from_str::<SccmTerminalEvidenceKind>(&wire).unwrap(),
        future
    );
}

#[test]
fn finding_role_unknown_values_cannot_shadow_declared_roles() {
    for value in ["", " ", " futureRole "] {
        assert!(
            serde_json::to_string(&SccmRole::Unknown(value.into())).is_err(),
            "{value:?}"
        );
        let wire = serde_json::to_string(value).unwrap();
        assert!(
            serde_json::from_str::<SccmRole>(&wire).is_err(),
            "{value:?}"
        );
    }

    for value in [
        "client",
        "siteServer",
        "managementPoint",
        "distributionPoint",
        "softwareUpdatePoint",
        "wsUs",
        "provider",
        "adminService",
    ] {
        assert!(
            serde_json::to_string(&SccmRole::Unknown(value.into())).is_err(),
            "{value:?}"
        );
    }

    let future = SccmRole::Unknown("futureRole".into());
    let wire = serde_json::to_string(&future).unwrap();
    assert_eq!(serde_json::from_str::<SccmRole>(&wire).unwrap(), future);
}

#[test]
fn finding_validates_finding_gap_and_request_roles_before_other_rules() {
    let top_level = SccmFindingBuilder::new("invalid-top-level-role")
        .class(SccmFindingClass::Symptom)
        .phase(SccmPhase::Policy)
        .role(SccmRole::Unknown("client".into()))
        .severity(Severity::Warning)
        .confidence(SccmConfidence::Low)
        .evidence(vec![finding_evidence_ref("artifact-a", "entry-a")])
        .build();
    let gap = SccmFindingBuilder::new("invalid-gap-role")
        .class(SccmFindingClass::Symptom)
        .phase(SccmPhase::Policy)
        .role(SccmRole::Client)
        .severity(Severity::Warning)
        .confidence(SccmConfidence::Low)
        .evidence(vec![finding_evidence_ref("artifact-a", "entry-a")])
        .coverage_gap(SccmFindingCoverageGap {
            artifact_id: "client-policy-agent".into(),
            role: SccmRole::Unknown("client".into()),
            coverage: SccmCoverageState::AccessDenied,
        })
        .build();
    let request = SccmFindingBuilder::new("invalid-request-role")
        .class(SccmFindingClass::Symptom)
        .phase(SccmPhase::Policy)
        .role(SccmRole::Client)
        .severity(Severity::Warning)
        .confidence(SccmConfidence::Low)
        .evidence(vec![finding_evidence_ref("artifact-a", "entry-a")])
        .next_artifact(finding_request(
            "policyAgent",
            SccmRole::Unknown("client".into()),
            "Confirm the bounded policy request outcome.",
        ))
        .build();

    for (label, result) in [
        ("finding", top_level),
        ("coverage-gap", gap),
        ("artifact-request", request),
    ] {
        assert_eq!(
            result.unwrap_err(),
            SccmFindingValidationError::InvalidRole,
            "{label}"
        );
    }
}

#[test]
fn finding_deserialization_validates_finding_gap_and_request_roles() {
    let json =
        serde_json::to_value(finding_with_gap_and_request("invalid-deserialized-role")).unwrap();
    let mut cases = Vec::new();

    let mut top_level = json.clone();
    top_level["role"] = serde_json::json!(" client ");
    cases.push(("finding", top_level));

    let mut gap = json.clone();
    gap["coverageGaps"][0]["role"] = serde_json::json!(" client ");
    cases.push(("coverage-gap", gap));

    let mut request = json;
    request["nextArtifacts"][0]["role"] = serde_json::json!(" client ");
    cases.push(("artifact-request", request));

    for (label, case) in cases {
        let error = serde_json::from_value::<SccmFinding>(case)
            .unwrap_err()
            .to_string();
        assert!(error.contains("InvalidRole"), "{label}: {error}");
    }
}

#[test]
fn finding_serialization_validates_finding_gap_and_request_roles() {
    let finding = finding_with_gap_and_request("invalid-serialized-role");
    let mut cases = Vec::new();

    let mut top_level = finding.clone();
    top_level.role = SccmRole::Unknown("client".into());
    cases.push(("finding", top_level));

    let mut gap = finding.clone();
    gap.coverage_gaps[0].role = SccmRole::Unknown("client".into());
    cases.push(("coverage-gap", gap));

    let mut request = finding;
    request.next_artifacts[0].role = SccmRole::Unknown("client".into());
    cases.push(("artifact-request", request));

    for (label, case) in cases {
        let error = serde_json::to_string(&case).unwrap_err().to_string();
        assert!(error.contains("InvalidRole"), "{label}: {error}");
    }
}

#[test]
fn finding_artifact_requests_reject_structurally_unbounded_reasons() {
    let reasons = [
        "Collect every file on the system.",
        "Scan the full disk for related evidence.",
        "Collect the complete C: drive.",
        "Walk all directories under C:.",
        "Collect drive-wide logs.",
        "Collect drive wide logs.",
        "Collect drivewide logs.",
        "Collect sitewide logs.",
        "Recursively collect PolicyAgent.log.",
        "Collect from the filesystem root.",
        "Use a glob for matching log files.",
        r"Collect C:\Windows\CCM\Logs\*.log.",
    ];
    let mut accepted = Vec::new();

    for reason in reasons
        .into_iter()
        .chain(ROOTED_ARTIFACT_REQUEST_REASONS)
        .chain(COMPACT_UNBOUNDED_ARTIFACT_REQUEST_REASONS)
        .chain(ORDER_INDEPENDENT_UNBOUNDED_ARTIFACT_REQUEST_REASONS)
    {
        let result = SccmFindingBuilder::new("unbounded-structural-request")
            .class(SccmFindingClass::Symptom)
            .phase(SccmPhase::Policy)
            .role(SccmRole::Client)
            .severity(Severity::Warning)
            .confidence(SccmConfidence::Low)
            .evidence(vec![finding_evidence_ref("artifact-a", "entry-a")])
            .next_artifact(finding_request("policyAgent", SccmRole::Client, reason))
            .build();

        if result.err() != Some(SccmFindingValidationError::InvalidArtifactRequestReason) {
            accepted.push(reason);
        }
    }

    assert!(
        accepted.is_empty(),
        "accepted unbounded reasons: {accepted:#?}"
    );
}

#[test]
fn finding_artifact_requests_accept_specific_bounded_reasons() {
    let existing = [
        ("policyAgent", "Confirm the bounded policy request outcome."),
        (
            "policyAgent",
            "Collect the PolicyAgent record cited by assignment A.",
        ),
        (
            "policyAgent",
            "Confirm the root cause recorded by PolicyAgent.",
        ),
        (
            "policyAgent",
            "Confirm the disk status code recorded in PolicyAgent.log.",
        ),
        ("smsts", "Collect the disk imaging Task Sequence log."),
        (
            "policyAgent",
            "Collect Logs/PolicyAgent.log from the bounded bundle.",
        ),
        (
            "policyAgent",
            r"Collect Logs\PolicyAgent.log from the bounded bundle.",
        ),
    ];
    let canonical = finding_with_gap_and_request("bounded-reason-parity");
    let mut rejected = Vec::new();

    for (logical_id, reason) in existing
        .into_iter()
        .chain(BOUNDED_NARRATIVE_ARTIFACT_REQUESTS)
    {
        if SccmFindingBuilder::new("bounded-structural-request")
            .class(SccmFindingClass::Symptom)
            .phase(SccmPhase::Policy)
            .role(SccmRole::Client)
            .severity(Severity::Warning)
            .confidence(SccmConfidence::Low)
            .evidence(vec![finding_evidence_ref("artifact-a", "entry-a")])
            .next_artifact(finding_request(logical_id, SccmRole::Client, reason))
            .build()
            .is_err()
        {
            rejected.push(format!("builder: {reason}"));
        }

        let mut direct = canonical.clone();
        direct.next_artifacts[0] = finding_request(logical_id, SccmRole::Client, reason);
        if direct.validate().is_err() {
            rejected.push(format!("direct validate: {reason}"));
        }
        if serde_json::to_value(&direct).is_err() {
            rejected.push(format!("serializer: {reason}"));
        }

        let mut json = serde_json::to_value(&canonical).unwrap();
        json["nextArtifacts"][0] =
            serde_json::to_value(finding_request(logical_id, SccmRole::Client, reason)).unwrap();
        if serde_json::from_value::<SccmFinding>(json).is_err() {
            rejected.push(format!("deserializer: {reason}"));
        }
    }

    assert!(
        rejected.is_empty(),
        "rejected bounded reasons: {rejected:#?}"
    );
}

#[test]
fn finding_artifact_request_bounds_apply_to_deserialization_and_serialization() {
    let finding = finding_with_gap_and_request("request-boundary-parity");
    let mut accepted = Vec::new();
    for reason in ROOTED_ARTIFACT_REQUEST_REASONS
        .into_iter()
        .chain([
            "Collect every file on the system.",
            "Scan the full disk for related evidence.",
        ])
        .chain(COMPACT_UNBOUNDED_ARTIFACT_REQUEST_REASONS)
        .chain(ORDER_INDEPENDENT_UNBOUNDED_ARTIFACT_REQUEST_REASONS)
    {
        let mut direct = finding.clone();
        direct.next_artifacts[0].reason = reason.into();
        if direct.validate().err() != Some(SccmFindingValidationError::InvalidArtifactRequestReason)
        {
            accepted.push(format!("direct validate: {reason}"));
        }

        let mut json = serde_json::to_value(&finding).unwrap();
        json["nextArtifacts"][0]["reason"] = serde_json::json!(reason);
        if serde_json::from_value::<SccmFinding>(json).is_ok() {
            accepted.push(format!("deserializer: {reason}"));
        }

        let mut mutated = finding.clone();
        mutated.next_artifacts[0].reason = reason.into();
        if serde_json::to_string(&mutated).is_ok() {
            accepted.push(format!("serializer: {reason}"));
        }
    }

    assert!(
        accepted.is_empty(),
        "accepted unbounded request boundaries: {accepted:#?}"
    );
}

#[test]
fn finding_review_unbounded_scope_matrix_fails_at_every_public_boundary() {
    let canonical = finding_with_gap_and_request("review-unbounded-scope-parity");
    let mut accepted = Vec::new();

    for reason in REVIEW_UNBOUNDED_ARTIFACT_REQUEST_REASONS {
        let builder = SccmFindingBuilder::new("review-unbounded-scope-builder")
            .class(SccmFindingClass::Symptom)
            .phase(SccmPhase::Policy)
            .role(SccmRole::Client)
            .severity(Severity::Warning)
            .confidence(SccmConfidence::Low)
            .evidence(vec![finding_evidence_ref("artifact-a", "entry-a")])
            .next_artifact(finding_request("policyAgent", SccmRole::Client, reason))
            .build();
        if builder.err() != Some(SccmFindingValidationError::InvalidArtifactRequestReason) {
            accepted.push(format!("builder: {reason}"));
        }

        let mut direct = canonical.clone();
        direct.next_artifacts[0].reason = reason.into();
        if direct.validate().err() != Some(SccmFindingValidationError::InvalidArtifactRequestReason)
        {
            accepted.push(format!("direct validate: {reason}"));
        }
        if serde_json::to_value(&direct).is_ok() {
            accepted.push(format!("serializer: {reason}"));
        }

        let mut json = serde_json::to_value(&canonical).unwrap();
        json["nextArtifacts"][0]["reason"] = serde_json::json!(reason);
        if serde_json::from_value::<SccmFinding>(json).is_ok() {
            accepted.push(format!("deserializer: {reason}"));
        }
    }

    assert!(
        accepted.is_empty(),
        "accepted reviewed unbounded request boundaries: {accepted:#?}"
    );
}

#[test]
fn finding_review_bounded_named_artifact_matrix_passes_every_public_boundary() {
    let canonical = finding_with_gap_and_request("review-bounded-scope-parity");
    let mut rejected = Vec::new();

    for (logical_id, reason) in REVIEW_BOUNDED_NAMED_ARTIFACT_REQUESTS {
        let builder = SccmFindingBuilder::new("review-bounded-scope-builder")
            .class(SccmFindingClass::Symptom)
            .phase(SccmPhase::Policy)
            .role(SccmRole::Client)
            .severity(Severity::Warning)
            .confidence(SccmConfidence::Low)
            .evidence(vec![finding_evidence_ref("artifact-a", "entry-a")])
            .next_artifact(finding_request(logical_id, SccmRole::Client, reason))
            .build();
        if builder.is_err() {
            rejected.push(format!("builder: {logical_id}: {reason}"));
        }

        let mut direct = canonical.clone();
        direct.next_artifacts[0] = finding_request(logical_id, SccmRole::Client, reason);
        if direct.validate().is_err() {
            rejected.push(format!("direct validate: {logical_id}: {reason}"));
        }
        if serde_json::to_value(&direct).is_err() {
            rejected.push(format!("serializer: {logical_id}: {reason}"));
        }

        let mut json = serde_json::to_value(&canonical).unwrap();
        json["nextArtifacts"][0] =
            serde_json::to_value(finding_request(logical_id, SccmRole::Client, reason)).unwrap();
        if serde_json::from_value::<SccmFinding>(json).is_err() {
            rejected.push(format!("deserializer: {logical_id}: {reason}"));
        }
    }

    assert!(
        rejected.is_empty(),
        "rejected reviewed bounded request boundaries: {rejected:#?}"
    );
}

#[test]
fn finding_review_expanded_unbounded_scope_fails_at_every_public_boundary() {
    let canonical = finding_with_gap_and_request("review-expanded-unbounded-scope-parity");
    let mut accepted = Vec::new();

    for reason in REVIEW_EXPANDED_UNBOUNDED_ARTIFACT_REQUEST_REASONS {
        let builder = SccmFindingBuilder::new("review-expanded-unbounded-scope-builder")
            .class(SccmFindingClass::Symptom)
            .phase(SccmPhase::Policy)
            .role(SccmRole::Client)
            .severity(Severity::Warning)
            .confidence(SccmConfidence::Low)
            .evidence(vec![finding_evidence_ref("artifact-a", "entry-a")])
            .next_artifact(finding_request("policyAgent", SccmRole::Client, reason))
            .build();
        if builder.err() != Some(SccmFindingValidationError::InvalidArtifactRequestReason) {
            accepted.push(format!("builder: {reason}"));
        }

        let mut direct = canonical.clone();
        direct.next_artifacts[0].reason = reason.into();
        if direct.validate().err() != Some(SccmFindingValidationError::InvalidArtifactRequestReason)
        {
            accepted.push(format!("direct validate: {reason}"));
        }
        if serde_json::to_value(&direct).is_ok() {
            accepted.push(format!("serializer: {reason}"));
        }

        let mut json = serde_json::to_value(&canonical).unwrap();
        json["nextArtifacts"][0]["reason"] = serde_json::json!(reason);
        if serde_json::from_value::<SccmFinding>(json).is_ok() {
            accepted.push(format!("deserializer: {reason}"));
        }
    }

    assert!(
        accepted.is_empty(),
        "accepted expanded unbounded request boundaries: {accepted:#?}"
    );
}

#[test]
fn finding_review_lookalike_identity_fails_at_every_public_boundary() {
    let canonical = finding_with_gap_and_request("review-lookalike-identity-parity");
    let mut accepted = Vec::new();

    for reason in REVIEW_LOOKALIKE_ARTIFACT_REQUEST_REASONS {
        let builder = SccmFindingBuilder::new("review-lookalike-identity-builder")
            .class(SccmFindingClass::Symptom)
            .phase(SccmPhase::Policy)
            .role(SccmRole::Client)
            .severity(Severity::Warning)
            .confidence(SccmConfidence::Low)
            .evidence(vec![finding_evidence_ref("artifact-a", "entry-a")])
            .next_artifact(finding_request("policyAgent", SccmRole::Client, reason))
            .build();
        if builder.err() != Some(SccmFindingValidationError::InvalidArtifactRequestReason) {
            accepted.push(format!("builder: {reason}"));
        }

        let mut direct = canonical.clone();
        direct.next_artifacts[0].reason = reason.into();
        if direct.validate().err() != Some(SccmFindingValidationError::InvalidArtifactRequestReason)
        {
            accepted.push(format!("direct validate: {reason}"));
        }
        if serde_json::to_value(&direct).is_ok() {
            accepted.push(format!("serializer: {reason}"));
        }

        let mut json = serde_json::to_value(&canonical).unwrap();
        json["nextArtifacts"][0]["reason"] = serde_json::json!(reason);
        if serde_json::from_value::<SccmFinding>(json).is_ok() {
            accepted.push(format!("deserializer: {reason}"));
        }
    }

    assert!(
        accepted.is_empty(),
        "accepted lookalike artifact request boundaries: {accepted:#?}"
    );
}

#[test]
fn finding_review_unqualified_collection_actions_fail_at_every_public_boundary() {
    let canonical = finding_with_gap_and_request("review-unqualified-action-parity");
    let mut accepted = Vec::new();

    for reason in REVIEW_UNQUALIFIED_COLLECTION_ACTION_REASONS {
        let builder = SccmFindingBuilder::new("review-unqualified-action-builder")
            .class(SccmFindingClass::Symptom)
            .phase(SccmPhase::Policy)
            .role(SccmRole::Client)
            .severity(Severity::Warning)
            .confidence(SccmConfidence::Low)
            .evidence(vec![finding_evidence_ref("artifact-a", "entry-a")])
            .next_artifact(finding_request("policyAgent", SccmRole::Client, reason))
            .build();
        if builder.err() != Some(SccmFindingValidationError::InvalidArtifactRequestReason) {
            accepted.push(format!("builder: {reason}"));
        }

        let mut direct = canonical.clone();
        direct.next_artifacts[0].reason = reason.into();
        if direct.validate().err() != Some(SccmFindingValidationError::InvalidArtifactRequestReason)
        {
            accepted.push(format!("direct validate: {reason}"));
        }
        if serde_json::to_value(&direct).is_ok() {
            accepted.push(format!("serializer: {reason}"));
        }

        let mut json = serde_json::to_value(&canonical).unwrap();
        json["nextArtifacts"][0]["reason"] = serde_json::json!(reason);
        if serde_json::from_value::<SccmFinding>(json).is_ok() {
            accepted.push(format!("deserializer: {reason}"));
        }
    }

    assert!(
        accepted.is_empty(),
        "accepted unqualified collection action boundaries: {accepted:#?}"
    );
}

#[test]
fn finding_review_coordinated_unqualified_actions_fail_at_every_public_boundary() {
    let canonical = finding_with_gap_and_request("review-coordinated-action-parity");
    let mut accepted = Vec::new();

    for reason in REVIEW_COORDINATED_UNQUALIFIED_ACTION_REASONS {
        let builder = SccmFindingBuilder::new("review-coordinated-action-builder")
            .class(SccmFindingClass::Symptom)
            .phase(SccmPhase::Policy)
            .role(SccmRole::Client)
            .severity(Severity::Warning)
            .confidence(SccmConfidence::Low)
            .evidence(vec![finding_evidence_ref("artifact-a", "entry-a")])
            .next_artifact(finding_request("policyAgent", SccmRole::Client, reason))
            .build();
        if builder.err() != Some(SccmFindingValidationError::InvalidArtifactRequestReason) {
            accepted.push(format!("builder: {reason}"));
        }

        let mut direct = canonical.clone();
        direct.next_artifacts[0].reason = reason.into();
        if direct.validate().err() != Some(SccmFindingValidationError::InvalidArtifactRequestReason)
        {
            accepted.push(format!("direct validate: {reason}"));
        }
        if serde_json::to_value(&direct).is_ok() {
            accepted.push(format!("serializer: {reason}"));
        }

        let mut json = serde_json::to_value(&canonical).unwrap();
        json["nextArtifacts"][0]["reason"] = serde_json::json!(reason);
        if serde_json::from_value::<SccmFinding>(json).is_ok() {
            accepted.push(format!("deserializer: {reason}"));
        }
    }

    assert!(
        accepted.is_empty(),
        "accepted coordinated unqualified action boundaries: {accepted:#?}"
    );
}

#[test]
fn finding_review_unbound_collection_targets_fail_at_every_public_boundary() {
    let canonical = finding_with_gap_and_request("review-unbound-target-parity");
    let mut accepted = Vec::new();

    for reason in REVIEW_UNBOUND_COLLECTION_TARGET_REASONS {
        let builder = SccmFindingBuilder::new("review-unbound-target-builder")
            .class(SccmFindingClass::Symptom)
            .phase(SccmPhase::Policy)
            .role(SccmRole::Client)
            .severity(Severity::Warning)
            .confidence(SccmConfidence::Low)
            .evidence(vec![finding_evidence_ref("artifact-a", "entry-a")])
            .next_artifact(finding_request("policyAgent", SccmRole::Client, reason))
            .build();
        if builder.err() != Some(SccmFindingValidationError::InvalidArtifactRequestReason) {
            accepted.push(format!("builder: {reason}"));
        }

        let mut direct = canonical.clone();
        direct.next_artifacts[0].reason = reason.into();
        if direct.validate().err() != Some(SccmFindingValidationError::InvalidArtifactRequestReason)
        {
            accepted.push(format!("direct validate: {reason}"));
        }
        if serde_json::to_value(&direct).is_ok() {
            accepted.push(format!("serializer: {reason}"));
        }

        let mut json = serde_json::to_value(&canonical).unwrap();
        json["nextArtifacts"][0]["reason"] = serde_json::json!(reason);
        if serde_json::from_value::<SccmFinding>(json).is_ok() {
            accepted.push(format!("deserializer: {reason}"));
        }
    }

    assert!(
        accepted.is_empty(),
        "accepted unbound collection target boundaries: {accepted:#?}"
    );
}

#[test]
fn finding_review_safe_collection_narratives_pass_at_every_public_boundary() {
    let canonical = finding_with_gap_and_request("review-safe-narrative-parity");
    let mut rejected = Vec::new();

    for reason in REVIEW_SAFE_COLLECTION_NARRATIVE_REASONS {
        let builder = SccmFindingBuilder::new("review-safe-narrative-builder")
            .class(SccmFindingClass::Symptom)
            .phase(SccmPhase::Policy)
            .role(SccmRole::Client)
            .severity(Severity::Warning)
            .confidence(SccmConfidence::Low)
            .evidence(vec![finding_evidence_ref("artifact-a", "entry-a")])
            .next_artifact(finding_request("policyAgent", SccmRole::Client, reason))
            .build();
        if let Err(error) = builder {
            rejected.push(format!("builder ({error:?}): {reason}"));
        }

        let mut direct = canonical.clone();
        direct.next_artifacts[0].reason = reason.into();
        if let Err(error) = direct.validate() {
            rejected.push(format!("direct validate ({error:?}): {reason}"));
        }
        if serde_json::to_value(&direct).is_err() {
            rejected.push(format!("serializer: {reason}"));
        }

        let mut json = serde_json::to_value(&canonical).unwrap();
        json["nextArtifacts"][0]["reason"] = serde_json::json!(reason);
        if serde_json::from_value::<SccmFinding>(json).is_err() {
            rejected.push(format!("deserializer: {reason}"));
        }
    }

    assert!(
        rejected.is_empty(),
        "rejected safe collection narratives: {rejected:#?}"
    );
}

#[test]
fn finding_review_non_authorizing_collection_language_fails_at_every_public_boundary() {
    let canonical = finding_with_gap_and_request("review-non-authorizing-language-parity");
    let mut accepted = Vec::new();

    for reason in REVIEW_NON_AUTHORIZING_COLLECTION_LANGUAGE_REASONS {
        let builder = SccmFindingBuilder::new("review-non-authorizing-language-builder")
            .class(SccmFindingClass::Symptom)
            .phase(SccmPhase::Policy)
            .role(SccmRole::Client)
            .severity(Severity::Warning)
            .confidence(SccmConfidence::Low)
            .evidence(vec![finding_evidence_ref("artifact-a", "entry-a")])
            .next_artifact(finding_request("policyAgent", SccmRole::Client, reason))
            .build();
        if builder.err() != Some(SccmFindingValidationError::InvalidArtifactRequestReason) {
            accepted.push(format!("builder: {reason}"));
        }

        let mut direct = canonical.clone();
        direct.next_artifacts[0].reason = reason.into();
        if direct.validate().err() != Some(SccmFindingValidationError::InvalidArtifactRequestReason)
        {
            accepted.push(format!("direct validate: {reason}"));
        }
        if serde_json::to_value(&direct).is_ok() {
            accepted.push(format!("serializer: {reason}"));
        }

        let mut json = serde_json::to_value(&canonical).unwrap();
        json["nextArtifacts"][0]["reason"] = serde_json::json!(reason);
        if serde_json::from_value::<SccmFinding>(json).is_ok() {
            accepted.push(format!("deserializer: {reason}"));
        }
    }

    assert!(
        accepted.is_empty(),
        "accepted non-authorizing collection language: {accepted:#?}"
    );
}

#[test]
fn finding_review_safe_strong_punctuation_narratives_pass_at_every_public_boundary() {
    let canonical = finding_with_gap_and_request("review-safe-strong-narrative-parity");
    let mut rejected = Vec::new();

    for reason in REVIEW_SAFE_STRONG_PUNCTUATION_NARRATIVE_REASONS {
        let builder = SccmFindingBuilder::new("review-safe-strong-narrative-builder")
            .class(SccmFindingClass::Symptom)
            .phase(SccmPhase::Policy)
            .role(SccmRole::Client)
            .severity(Severity::Warning)
            .confidence(SccmConfidence::Low)
            .evidence(vec![finding_evidence_ref("artifact-a", "entry-a")])
            .next_artifact(finding_request("policyAgent", SccmRole::Client, reason))
            .build();
        if let Err(error) = builder {
            rejected.push(format!("builder ({error:?}): {reason}"));
        }

        let mut direct = canonical.clone();
        direct.next_artifacts[0].reason = reason.into();
        if let Err(error) = direct.validate() {
            rejected.push(format!("direct validate ({error:?}): {reason}"));
        }
        if serde_json::to_value(&direct).is_err() {
            rejected.push(format!("serializer: {reason}"));
        }

        let mut json = serde_json::to_value(&canonical).unwrap();
        json["nextArtifacts"][0]["reason"] = serde_json::json!(reason);
        if serde_json::from_value::<SccmFinding>(json).is_err() {
            rejected.push(format!("deserializer: {reason}"));
        }
    }

    assert!(
        rejected.is_empty(),
        "rejected safe strong-punctuation narratives: {rejected:#?}"
    );
}

#[test]
fn finding_review_evidence_subject_cannot_authorize_passive_target_at_any_public_boundary() {
    let canonical = finding_with_gap_and_request("review-evidence-passive-target-parity");
    let mut accepted = Vec::new();

    for reason in REVIEW_EVIDENCE_SUBJECT_UNBOUND_PASSIVE_REASONS {
        let builder = SccmFindingBuilder::new("review-evidence-passive-target-builder")
            .class(SccmFindingClass::Symptom)
            .phase(SccmPhase::Policy)
            .role(SccmRole::Client)
            .severity(Severity::Warning)
            .confidence(SccmConfidence::Low)
            .evidence(vec![finding_evidence_ref("artifact-a", "entry-a")])
            .next_artifact(finding_request("policyAgent", SccmRole::Client, reason))
            .build();
        if builder.err() != Some(SccmFindingValidationError::InvalidArtifactRequestReason) {
            accepted.push(format!("builder: {reason}"));
        }

        let mut direct = canonical.clone();
        direct.next_artifacts[0].reason = reason.into();
        if direct.validate().err() != Some(SccmFindingValidationError::InvalidArtifactRequestReason)
        {
            accepted.push(format!("direct validate: {reason}"));
        }
        if serde_json::to_value(&direct).is_ok() {
            accepted.push(format!("serializer: {reason}"));
        }

        let mut json = serde_json::to_value(&canonical).unwrap();
        json["nextArtifacts"][0]["reason"] = serde_json::json!(reason);
        if serde_json::from_value::<SccmFinding>(json).is_ok() {
            accepted.push(format!("deserializer: {reason}"));
        }
    }

    assert!(
        accepted.is_empty(),
        "accepted evidence-subject passive targets: {accepted:#?}"
    );
}

#[test]
fn finding_review_standalone_and_inflected_collection_requests_fail_at_every_public_boundary() {
    let canonical = finding_with_gap_and_request("review-standalone-inflected-parity");
    let mut accepted = Vec::new();

    for reason in REVIEW_STANDALONE_AND_INFLECTED_COLLECTION_REASONS {
        let builder = SccmFindingBuilder::new("review-standalone-inflected-builder")
            .class(SccmFindingClass::Symptom)
            .phase(SccmPhase::Policy)
            .role(SccmRole::Client)
            .severity(Severity::Warning)
            .confidence(SccmConfidence::Low)
            .evidence(vec![finding_evidence_ref("artifact-a", "entry-a")])
            .next_artifact(finding_request("policyAgent", SccmRole::Client, reason))
            .build();
        if builder.err() != Some(SccmFindingValidationError::InvalidArtifactRequestReason) {
            accepted.push(format!("builder: {reason}"));
        }

        let mut direct = canonical.clone();
        direct.next_artifacts[0].reason = reason.into();
        if direct.validate().err() != Some(SccmFindingValidationError::InvalidArtifactRequestReason)
        {
            accepted.push(format!("direct validate: {reason}"));
        }
        if serde_json::to_value(&direct).is_ok() {
            accepted.push(format!("serializer: {reason}"));
        }

        let mut json = serde_json::to_value(&canonical).unwrap();
        json["nextArtifacts"][0]["reason"] = serde_json::json!(reason);
        if serde_json::from_value::<SccmFinding>(json).is_ok() {
            accepted.push(format!("deserializer: {reason}"));
        }
    }

    assert!(
        accepted.is_empty(),
        "accepted standalone or inflected collection requests: {accepted:#?}"
    );
}

#[test]
fn finding_review_unrecognized_confirmation_requests_fail_at_every_public_boundary() {
    let canonical = finding_with_gap_and_request("review-confirmation-request-parity");
    let mut accepted = Vec::new();

    for reason in REVIEW_UNRECOGNIZED_CONFIRMATION_REQUEST_REASONS {
        let builder = SccmFindingBuilder::new("review-confirmation-request-builder")
            .class(SccmFindingClass::Symptom)
            .phase(SccmPhase::Policy)
            .role(SccmRole::Client)
            .severity(Severity::Warning)
            .confidence(SccmConfidence::Low)
            .evidence(vec![finding_evidence_ref("artifact-a", "entry-a")])
            .next_artifact(finding_request("policyAgent", SccmRole::Client, reason))
            .build();
        if builder.err() != Some(SccmFindingValidationError::InvalidArtifactRequestReason) {
            accepted.push(format!("builder: {reason}"));
        }

        let mut direct = canonical.clone();
        direct.next_artifacts[0].reason = reason.into();
        if direct.validate().err() != Some(SccmFindingValidationError::InvalidArtifactRequestReason)
        {
            accepted.push(format!("direct validate: {reason}"));
        }
        if serde_json::to_value(&direct).is_ok() {
            accepted.push(format!("serializer: {reason}"));
        }

        let mut json = serde_json::to_value(&canonical).unwrap();
        json["nextArtifacts"][0]["reason"] = serde_json::json!(reason);
        if serde_json::from_value::<SccmFinding>(json).is_ok() {
            accepted.push(format!("deserializer: {reason}"));
        }
    }

    assert!(
        accepted.is_empty(),
        "accepted unrecognized confirmation requests: {accepted:#?}"
    );
}

#[test]
fn finding_review_passive_unbounded_confirmation_requests_fail_at_every_public_boundary() {
    let canonical = finding_with_gap_and_request("review-passive-confirmation-parity");
    let mut accepted = Vec::new();

    for reason in REVIEW_PASSIVE_UNBOUNDED_CONFIRMATION_REASONS {
        let logical_id = if reason.contains("Smsts.log") {
            "smsts"
        } else {
            "policyAgent"
        };
        let builder = SccmFindingBuilder::new("review-passive-confirmation-builder")
            .class(SccmFindingClass::Symptom)
            .phase(SccmPhase::Policy)
            .role(SccmRole::Client)
            .severity(Severity::Warning)
            .confidence(SccmConfidence::Low)
            .evidence(vec![finding_evidence_ref("artifact-a", "entry-a")])
            .next_artifact(finding_request(logical_id, SccmRole::Client, reason))
            .build();
        if builder.err() != Some(SccmFindingValidationError::InvalidArtifactRequestReason) {
            accepted.push(format!("builder: {reason}"));
        }

        let mut direct = canonical.clone();
        direct.next_artifacts[0] = finding_request(logical_id, SccmRole::Client, reason);
        if direct.validate().err() != Some(SccmFindingValidationError::InvalidArtifactRequestReason)
        {
            accepted.push(format!("direct validate: {reason}"));
        }
        if serde_json::to_value(&direct).is_ok() {
            accepted.push(format!("serializer: {reason}"));
        }

        let mut json = serde_json::to_value(&canonical).unwrap();
        json["nextArtifacts"][0] = serde_json::json!({
            "logicalId": logical_id,
            "role": "client",
            "reason": reason,
        });
        if serde_json::from_value::<SccmFinding>(json).is_ok() {
            accepted.push(format!("deserializer: {reason}"));
        }
    }

    assert!(
        accepted.is_empty(),
        "accepted passive unbounded confirmation requests: {accepted:#?}"
    );
}

#[test]
fn finding_review_bounded_auxiliary_confirmations_pass_at_every_public_boundary() {
    let canonical = finding_with_gap_and_request("review-bounded-auxiliary-parity");
    let mut rejected = Vec::new();

    for (logical_id, reason) in REVIEW_BOUNDED_AUXILIARY_CONFIRMATION_REASONS {
        let builder = SccmFindingBuilder::new("review-bounded-auxiliary-builder")
            .class(SccmFindingClass::Symptom)
            .phase(SccmPhase::Policy)
            .role(SccmRole::Client)
            .severity(Severity::Warning)
            .confidence(SccmConfidence::Low)
            .evidence(vec![finding_evidence_ref("artifact-a", "entry-a")])
            .next_artifact(finding_request(logical_id, SccmRole::Client, reason))
            .build();
        if builder.is_err() {
            rejected.push(format!("builder: {reason}"));
        }

        let mut direct = canonical.clone();
        direct.next_artifacts[0] = finding_request(logical_id, SccmRole::Client, reason);
        if direct.validate().is_err() {
            rejected.push(format!("direct validate: {reason}"));
        }
        if serde_json::to_value(&direct).is_err() {
            rejected.push(format!("serializer: {reason}"));
        }

        let mut json = serde_json::to_value(&canonical).unwrap();
        json["nextArtifacts"][0] =
            serde_json::to_value(finding_request(logical_id, SccmRole::Client, reason)).unwrap();
        if serde_json::from_value::<SccmFinding>(json).is_err() {
            rejected.push(format!("deserializer: {reason}"));
        }
    }

    assert!(
        rejected.is_empty(),
        "rejected bounded auxiliary confirmations: {rejected:#?}"
    );
}

#[test]
fn finding_review_exact_mp_identity_passes_every_public_boundary() {
    let canonical = finding_with_gap_and_request("review-exact-mp-identity-parity");
    let mut rejected = Vec::new();

    for (logical_id, reason) in REVIEW_EXACT_MP_ARTIFACT_REQUESTS {
        let builder = SccmFindingBuilder::new("review-exact-mp-identity-builder")
            .class(SccmFindingClass::Symptom)
            .phase(SccmPhase::Policy)
            .role(SccmRole::ManagementPoint)
            .severity(Severity::Warning)
            .confidence(SccmConfidence::Low)
            .evidence(vec![finding_evidence_ref("artifact-a", "entry-a")])
            .next_artifact(finding_request(
                logical_id,
                SccmRole::ManagementPoint,
                reason,
            ))
            .build();
        if let Err(error) = builder {
            rejected.push(format!("builder ({error:?}): {logical_id}: {reason}"));
        }

        let mut direct = canonical.clone();
        direct.next_artifacts[0] = finding_request(logical_id, SccmRole::ManagementPoint, reason);
        if let Err(error) = direct.validate() {
            rejected.push(format!(
                "direct validate ({error:?}): {logical_id}: {reason}"
            ));
        }
        if serde_json::to_value(&direct).is_err() {
            rejected.push(format!("serializer: {logical_id}: {reason}"));
        }

        let mut json = serde_json::to_value(&canonical).unwrap();
        json["nextArtifacts"][0] = serde_json::to_value(finding_request(
            logical_id,
            SccmRole::ManagementPoint,
            reason,
        ))
        .unwrap();
        if serde_json::from_value::<SccmFinding>(json).is_err() {
            rejected.push(format!("deserializer: {logical_id}: {reason}"));
        }
    }

    assert!(
        rejected.is_empty(),
        "rejected exact MP artifact request boundaries: {rejected:#?}"
    );
}

#[test]
fn finding_review_every_exact_catalog_identity_passes_at_every_public_boundary() {
    let canonical = finding_with_gap_and_request("review-exact-catalog-identity-parity");
    let mut rejected = Vec::new();

    for source in declared_source_catalog() {
        let reasons = [
            format!("Collect the complete {} file.", source.basename),
            format!("Collect the complete {}.log file.", source.logical_name),
        ];

        for reason in reasons {
            let request = finding_request(&source.logical_name, source.role.clone(), &reason);
            let builder = SccmFindingBuilder::new("review-exact-catalog-identity-builder")
                .class(SccmFindingClass::Symptom)
                .phase(SccmPhase::Policy)
                .role(source.role.clone())
                .severity(Severity::Warning)
                .confidence(SccmConfidence::Low)
                .evidence(vec![finding_evidence_ref("artifact-a", "entry-a")])
                .next_artifact(request.clone())
                .build();
            if let Err(error) = builder {
                rejected.push(format!(
                    "builder ({error:?}): {}: {reason}",
                    source.logical_name
                ));
            }

            let mut direct = canonical.clone();
            direct.next_artifacts[0] = request.clone();
            if let Err(error) = direct.validate() {
                rejected.push(format!(
                    "direct validate ({error:?}): {}: {reason}",
                    source.logical_name
                ));
            }
            if serde_json::to_value(&direct).is_err() {
                rejected.push(format!("serializer: {}: {reason}", source.logical_name));
            }

            let mut json = serde_json::to_value(&canonical).unwrap();
            json["nextArtifacts"][0] = serde_json::to_value(request).unwrap();
            if serde_json::from_value::<SccmFinding>(json).is_err() {
                rejected.push(format!("deserializer: {}: {reason}", source.logical_name));
            }
        }
    }

    assert!(
        rejected.is_empty(),
        "rejected exact catalog artifact request boundaries: {rejected:#?}"
    );
}

#[test]
fn finding_request_accepts_exact_multi_dot_catalog_basename_at_every_public_boundary() {
    let reason = "Collect the complete client.msi.log file.";
    let request = finding_request("clientMsi", SccmRole::Client, reason);
    let canonical = finding_with_gap_and_request("exact-multi-dot-catalog-identity-parity");
    let mut rejected = Vec::new();

    let builder = SccmFindingBuilder::new("exact-multi-dot-catalog-identity-builder")
        .class(SccmFindingClass::Symptom)
        .phase(SccmPhase::Policy)
        .role(SccmRole::Client)
        .severity(Severity::Warning)
        .confidence(SccmConfidence::Low)
        .evidence(vec![finding_evidence_ref("artifact-a", "entry-a")])
        .next_artifact(request.clone())
        .build();
    if let Err(error) = builder {
        rejected.push(format!("builder ({error:?})"));
    }

    let mut direct = canonical.clone();
    direct.next_artifacts[0] = request.clone();
    if let Err(error) = direct.validate() {
        rejected.push(format!("direct validate ({error:?})"));
    }
    if let Err(error) = serde_json::to_value(&direct) {
        rejected.push(format!("serializer ({error})"));
    }

    let mut json = serde_json::to_value(&canonical).unwrap();
    json["nextArtifacts"][0] = serde_json::to_value(request).unwrap();
    if let Err(error) = serde_json::from_value::<SccmFinding>(json) {
        rejected.push(format!("deserializer ({error})"));
    }

    assert!(
        rejected.is_empty(),
        "rejected exact multi-dot catalog identity: {rejected:#?}"
    );
}

#[test]
fn finding_request_rejects_multi_dot_scope_without_exact_catalog_authorization() {
    let canonical = finding_with_gap_and_request("invalid-multi-dot-catalog-identity-parity");
    let cases = [
        (
            "unknown multi-dot basename",
            finding_request(
                "clientMsi",
                SccmRole::Client,
                "Collect the complete client.unknown.log file.",
            ),
            SccmFindingValidationError::InvalidArtifactRequestReason,
        ),
        (
            "bare component of the multi-dot basename",
            finding_request(
                "clientMsi",
                SccmRole::Client,
                "Collect the complete client.log file.",
            ),
            SccmFindingValidationError::InvalidArtifactRequestReason,
        ),
        (
            "mismatched logical id",
            finding_request(
                "policyAgent",
                SccmRole::Client,
                "Collect the complete client.msi.log file.",
            ),
            SccmFindingValidationError::InvalidArtifactRequestReason,
        ),
        (
            "mismatched role",
            finding_request(
                "clientMsi",
                SccmRole::ManagementPoint,
                "Collect the complete client.msi.log file.",
            ),
            SccmFindingValidationError::ArtifactRequestRoleMismatch,
        ),
        (
            "glob",
            finding_request(
                "clientMsi",
                SccmRole::Client,
                "Collect client.msi*.log from the bundle.",
            ),
            SccmFindingValidationError::InvalidArtifactRequestReason,
        ),
        (
            "unbounded language",
            finding_request(
                "clientMsi",
                SccmRole::Client,
                "Collect client.msi.log and every file on the system.",
            ),
            SccmFindingValidationError::InvalidArtifactRequestReason,
        ),
    ];
    let mut incorrectly_accepted = Vec::new();

    for (label, request, expected_error) in cases {
        let builder = SccmFindingBuilder::new("invalid-multi-dot-catalog-identity-builder")
            .class(SccmFindingClass::Symptom)
            .phase(SccmPhase::Policy)
            .role(SccmRole::Client)
            .severity(Severity::Warning)
            .confidence(SccmConfidence::Low)
            .evidence(vec![finding_evidence_ref("artifact-a", "entry-a")])
            .next_artifact(request.clone())
            .build();
        if builder.err() != Some(expected_error) {
            incorrectly_accepted.push(format!("builder: {label}"));
        }

        let mut direct = canonical.clone();
        direct.next_artifacts[0] = request.clone();
        if direct.validate().err() != Some(expected_error) {
            incorrectly_accepted.push(format!("direct validate: {label}"));
        }
        if serde_json::to_value(&direct).is_ok() {
            incorrectly_accepted.push(format!("serializer: {label}"));
        }

        let mut json = serde_json::to_value(&canonical).unwrap();
        json["nextArtifacts"][0] = serde_json::json!({
            "logicalId": &request.logical_id,
            "role": &request.role,
            "reason": &request.reason,
        });
        let deserialized = serde_json::from_value::<SccmFinding>(json);
        let expected_message = format!("invalid SCCM finding contract: {expected_error:?}");
        let matches_expected = deserialized
            .err()
            .is_some_and(|error| error.to_string() == expected_message);
        if !matches_expected {
            incorrectly_accepted.push(format!("deserializer: {label}"));
        }
    }

    assert!(
        incorrectly_accepted.is_empty(),
        "accepted or misclassified unauthorized multi-dot requests: {incorrectly_accepted:#?}"
    );
}

#[test]
fn finding_review_percentages_are_not_environment_paths_at_every_public_boundary() {
    let reason = "Collect PolicyAgent.log after 50% and before 60% completion.";
    let canonical = finding_with_gap_and_request("review-percentage-path-parity");
    let mut rejected = Vec::new();

    let builder = SccmFindingBuilder::new("review-percentage-path-builder")
        .class(SccmFindingClass::Symptom)
        .phase(SccmPhase::Policy)
        .role(SccmRole::Client)
        .severity(Severity::Warning)
        .confidence(SccmConfidence::Low)
        .evidence(vec![finding_evidence_ref("artifact-a", "entry-a")])
        .next_artifact(finding_request("policyAgent", SccmRole::Client, reason))
        .build();
    if let Err(error) = builder {
        rejected.push(format!("builder ({error:?})"));
    }

    let mut direct = canonical.clone();
    direct.next_artifacts[0].reason = reason.into();
    if let Err(error) = direct.validate() {
        rejected.push(format!("direct validate ({error:?})"));
    }
    if serde_json::to_value(&direct).is_err() {
        rejected.push("serializer".into());
    }

    let mut json = serde_json::to_value(&canonical).unwrap();
    json["nextArtifacts"][0]["reason"] = serde_json::json!(reason);
    if serde_json::from_value::<SccmFinding>(json).is_err() {
        rejected.push("deserializer".into());
    }

    assert!(
        rejected.is_empty(),
        "rejected non-environment percentages: {rejected:#?}"
    );
}

#[test]
fn finding_rejects_a_correlation_key_without_an_evidence_ref() {
    let cited = finding_evidence_ref("client-policy-agent", "policy:1-1");
    let mut key = finding_key(
        SccmCorrelationKeyKind::AssignmentId,
        "{ABCDEFAB-0000-0000-0000-000000000001}",
        "abcdefab-0000-0000-0000-000000000001",
        SccmKeyConfidence::Low,
        Some("sccm-keys-experimental-v1"),
        cited.clone(),
    );
    key.evidence = None;

    let result = SccmFindingBuilder::new("missing-key-evidence")
        .class(SccmFindingClass::Symptom)
        .phase(SccmPhase::Policy)
        .role(SccmRole::Client)
        .severity(Severity::Warning)
        .confidence(SccmConfidence::Low)
        .evidence(vec![cited])
        .correlation_keys(vec![key])
        .build();

    assert_eq!(
        result.unwrap_err(),
        SccmFindingValidationError::CorrelationKeyMissingEvidence
    );
}

#[test]
fn finding_low_profiled_or_unprofiled_keys_never_corroborate_high_confidence() {
    let first = finding_evidence_ref("client-content", "client-content:1-1");
    let second = finding_evidence_ref("server-content", "server-content:1-1");
    let cases = [
        (
            "low-profiled-keys",
            Some("sccm-keys-experimental-v1"),
            SccmKeyConfidence::Low,
        ),
        ("low-unprofiled-keys", None, SccmKeyConfidence::Low),
    ];

    for (finding_id, profile, confidence) in cases {
        let result = SccmFindingBuilder::new(finding_id)
            .class(SccmFindingClass::ConfirmedFailure)
            .phase(SccmPhase::Content)
            .role(SccmRole::Client)
            .severity(Severity::Error)
            .confidence(SccmConfidence::High)
            .evidence(vec![first.clone(), second.clone()])
            .correlation_keys(vec![
                finding_key(
                    SccmCorrelationKeyKind::ContentId,
                    "ContentABC",
                    "contentabc",
                    confidence.clone(),
                    profile,
                    first.clone(),
                ),
                finding_key(
                    SccmCorrelationKeyKind::ContentId,
                    "contentabc",
                    "contentabc",
                    confidence.clone(),
                    profile,
                    second.clone(),
                ),
            ])
            .build();

        assert_eq!(
            result.unwrap_err(),
            SccmFindingValidationError::MissingTerminalEvidence,
            "{finding_id}"
        );
    }
}

#[test]
fn finding_rejects_forged_terminal_markers() {
    let evidence = finding_evidence_ref("client-app-enforce", "client-app-enforce:1-1");
    let result = SccmFindingBuilder::new("forged-terminal")
        .class(SccmFindingClass::ConfirmedFailure)
        .phase(SccmPhase::Enforcement)
        .role(SccmRole::Client)
        .severity(Severity::Error)
        .confidence(SccmConfidence::High)
        .evidence(vec![evidence.clone()])
        .terminal_evidence(vec![SccmTerminalEvidence {
            reference: evidence,
            kind: SccmTerminalEvidenceKind::Unknown("observedFailure".into()),
        }])
        .build();

    assert_eq!(
        result.unwrap_err(),
        SccmFindingValidationError::InvalidTerminalEvidence
    );
}

#[test]
fn finding_likely_contributor_is_capped_without_terminal_corroboration() {
    let evidence = finding_evidence_ref("client-policy-agent", "policy:1-1");
    let high = SccmFindingBuilder::new("likely-contributor-high")
        .class(SccmFindingClass::LikelyContributor)
        .phase(SccmPhase::Policy)
        .role(SccmRole::Client)
        .severity(Severity::Warning)
        .confidence(SccmConfidence::High)
        .evidence(vec![evidence.clone()])
        .build();
    assert_eq!(
        high.unwrap_err(),
        SccmFindingValidationError::LikelyContributorConfidenceTooHigh
    );

    let moderate = SccmFindingBuilder::new("likely-contributor-moderate")
        .class(SccmFindingClass::LikelyContributor)
        .phase(SccmPhase::Policy)
        .role(SccmRole::Client)
        .severity(Severity::Warning)
        .confidence(SccmConfidence::Moderate)
        .evidence(vec![evidence.clone()])
        .build()
        .unwrap();
    assert_eq!(moderate.confidence, SccmConfidence::Moderate);

    let terminal = SccmFindingBuilder::new("likely-contributor-terminal")
        .class(SccmFindingClass::LikelyContributor)
        .phase(SccmPhase::Policy)
        .role(SccmRole::Client)
        .severity(Severity::Error)
        .confidence(SccmConfidence::High)
        .evidence(vec![evidence.clone()])
        .terminal_evidence(vec![SccmTerminalEvidence::observed_failure(evidence)])
        .build()
        .unwrap();
    assert_eq!(terminal.confidence, SccmConfidence::High);
}

#[test]
fn finding_evidence_less_claims_are_rejected() {
    let result = SccmFindingBuilder::new("unsupported-success-claim")
        .class(SccmFindingClass::Symptom)
        .phase(SccmPhase::Policy)
        .role(SccmRole::Client)
        .severity(Severity::Success)
        .confidence(SccmConfidence::High)
        .build();

    assert_eq!(
        result.unwrap_err(),
        SccmFindingValidationError::MissingEvidenceOrCoverageGap
    );
}

#[test]
fn finding_access_denied_coverage_only_cannot_substantiate_an_outcome_class() {
    let canonical = SccmFindingBuilder::new("access-denied-insufficient-evidence")
        .class(SccmFindingClass::InsufficientEvidence)
        .phase(SccmPhase::Policy)
        .role(SccmRole::Client)
        .severity(Severity::Warning)
        .confidence(SccmConfidence::Low)
        .coverage_gap(finding_client_gap(
            "client-policy-agent",
            SccmCoverageState::AccessDenied,
        ))
        .next_artifact(finding_request(
            "policyAgent",
            SccmRole::Client,
            "Policy evidence was not captured.",
        ))
        .build()
        .unwrap();
    let cases = [
        (SccmFindingClass::Symptom, SccmConfidence::High, "symptom"),
        (
            SccmFindingClass::LikelyContributor,
            SccmConfidence::Moderate,
            "likelyContributor",
        ),
        (
            SccmFindingClass::ConfirmedFailure,
            SccmConfidence::Moderate,
            "confirmedFailure",
        ),
        (
            SccmFindingClass::Recovered,
            SccmConfidence::High,
            "recovered",
        ),
        (
            SccmFindingClass::ContradictoryEvidence,
            SccmConfidence::Low,
            "contradictoryEvidence",
        ),
        (
            SccmFindingClass::BlockedOrDeferred,
            SccmConfidence::Low,
            "blockedOrDeferred",
        ),
    ];
    let mut accepted = Vec::new();

    for (class, confidence, label) in cases {
        let builder = SccmFindingBuilder::new(format!("access-denied-builder-{label}"))
            .class(class.clone())
            .phase(SccmPhase::Policy)
            .role(SccmRole::Client)
            .severity(Severity::Warning)
            .confidence(confidence)
            .coverage_gap(finding_client_gap(
                "client-policy-agent",
                SccmCoverageState::AccessDenied,
            ))
            .next_artifact(finding_request(
                "policyAgent",
                SccmRole::Client,
                "Policy evidence was not captured.",
            ))
            .build();
        if builder.err() != Some(SccmFindingValidationError::MissingEvidenceOrCoverageGap) {
            accepted.push(format!("builder: {label}"));
        }

        let mut direct = canonical.clone();
        direct.class = class;
        direct.confidence = confidence;
        if direct.validate().err() != Some(SccmFindingValidationError::MissingEvidenceOrCoverageGap)
        {
            accepted.push(format!("direct validate: {label}"));
        }
        if serde_json::to_value(&direct).is_ok() {
            accepted.push(format!("serializer: {label}"));
        }

        let mut json = serde_json::to_value(&canonical).unwrap();
        json["class"] = serde_json::json!(label);
        json["confidence"] = serde_json::to_value(direct.confidence).unwrap();
        if serde_json::from_value::<SccmFinding>(json).is_ok() {
            accepted.push(format!("deserializer: {label}"));
        }
    }

    assert!(
        accepted.is_empty(),
        "coverage-only access denial substantiated outcome classes: {accepted:#?}"
    );
}

#[test]
fn finding_insufficient_evidence_requires_an_explicit_noncaptured_gap() {
    let request = finding_request(
        "policyAgent",
        SccmRole::Client,
        "Policy evidence was not captured.",
    );
    let missing_gap = SccmFindingBuilder::new("missing-gap")
        .class(SccmFindingClass::InsufficientEvidence)
        .phase(SccmPhase::Policy)
        .role(SccmRole::Client)
        .severity(Severity::Warning)
        .confidence(SccmConfidence::Low)
        .next_artifact(request.clone())
        .build();
    assert_eq!(
        missing_gap.unwrap_err(),
        SccmFindingValidationError::MissingCoverageGap
    );

    let captured_is_not_a_gap = SccmFindingBuilder::new("captured-is-not-gap")
        .class(SccmFindingClass::InsufficientEvidence)
        .phase(SccmPhase::Policy)
        .role(SccmRole::Client)
        .severity(Severity::Warning)
        .confidence(SccmConfidence::Low)
        .coverage_gap(finding_client_gap(
            "client-policy-agent",
            SccmCoverageState::Captured,
        ))
        .next_artifact(request)
        .build();
    assert_eq!(
        captured_is_not_a_gap.unwrap_err(),
        SccmFindingValidationError::InvalidCoverageGap
    );
}

#[test]
fn finding_rejects_conflicting_coverage_for_one_artifact_identity() {
    let first = finding_client_gap("client-policy-agent", SccmCoverageState::Absent);
    let conflicts = [
        (
            "state",
            vec![
                first.clone(),
                finding_client_gap("client-policy-agent", SccmCoverageState::AccessDenied),
            ],
        ),
        (
            "role",
            vec![
                first.clone(),
                SccmFindingCoverageGap {
                    artifact_id: "client-policy-agent".into(),
                    role: SccmRole::ManagementPoint,
                    coverage: SccmCoverageState::Absent,
                },
            ],
        ),
    ];
    let mut accepted = Vec::new();

    for (label, gaps) in conflicts {
        let builder = SccmFindingBuilder::new(format!("conflicting-coverage-builder-{label}"))
            .class(SccmFindingClass::Symptom)
            .phase(SccmPhase::Policy)
            .role(SccmRole::Client)
            .severity(Severity::Warning)
            .confidence(SccmConfidence::Low)
            .evidence(vec![finding_evidence_ref("artifact-a", "entry-a")])
            .coverage_gaps(gaps.clone())
            .build();
        if builder.err() != Some(SccmFindingValidationError::InvalidCoverageGap) {
            accepted.push(format!("builder: {label}"));
        }

        let mut direct =
            finding_with_gap_and_request(&format!("conflicting-coverage-direct-{label}"));
        direct.coverage_gaps = gaps.clone();
        if direct.validate().err() != Some(SccmFindingValidationError::InvalidCoverageGap) {
            accepted.push(format!("direct validate: {label}"));
        }
        if serde_json::to_value(&direct).is_ok() {
            accepted.push(format!("serializer: {label}"));
        }

        let mut json = serde_json::to_value(finding_with_gap_and_request(&format!(
            "conflicting-coverage-json-{label}"
        )))
        .unwrap();
        json["coverageGaps"] = serde_json::to_value(gaps).unwrap();
        if serde_json::from_value::<SccmFinding>(json).is_ok() {
            accepted.push(format!("deserializer: {label}"));
        }
    }

    assert!(
        accepted.is_empty(),
        "accepted conflicting coverage: {accepted:#?}"
    );

    let duplicate = finding_client_gap("client-policy-agent", SccmCoverageState::AccessDenied);
    let built = SccmFindingBuilder::new("duplicate-coverage-builder")
        .class(SccmFindingClass::Symptom)
        .phase(SccmPhase::Policy)
        .role(SccmRole::Client)
        .severity(Severity::Warning)
        .confidence(SccmConfidence::Low)
        .evidence(vec![finding_evidence_ref("artifact-a", "entry-a")])
        .coverage_gaps(vec![duplicate.clone(), duplicate.clone()])
        .build()
        .unwrap();
    assert_eq!(built.coverage_gaps, vec![duplicate.clone()]);

    let mut direct = built.clone();
    direct.coverage_gaps = vec![duplicate.clone(), duplicate];
    direct.validate().unwrap();
    let serialized = serde_json::to_value(&direct).unwrap();
    assert_eq!(serialized["coverageGaps"].as_array().unwrap().len(), 1);
    let deserialized = serde_json::from_value::<SccmFinding>(serialized).unwrap();
    assert_eq!(deserialized.coverage_gaps.len(), 1);
}

#[test]
fn finding_artifact_requests_require_declared_logical_id_and_role() {
    for invalid_id in [
        "client-policy-agent",
        r"C:\",
        "D:/",
        "/",
        "*",
        "**/*.log",
        "whole disk",
        "PolicyAgent.log",
    ] {
        let result = SccmFindingBuilder::new("invalid-request-id")
            .class(SccmFindingClass::InsufficientEvidence)
            .phase(SccmPhase::Policy)
            .role(SccmRole::Client)
            .severity(Severity::Warning)
            .confidence(SccmConfidence::Low)
            .coverage_gap(finding_client_gap(
                "client-policy-agent",
                SccmCoverageState::Absent,
            ))
            .next_artifact(finding_request(
                invalid_id,
                SccmRole::Client,
                "Policy evidence was not captured.",
            ))
            .build();
        assert_eq!(
            result.unwrap_err(),
            SccmFindingValidationError::UndeclaredArtifactRequest,
            "{invalid_id}"
        );
    }

    let role_mismatch = SccmFindingBuilder::new("invalid-request-role")
        .class(SccmFindingClass::InsufficientEvidence)
        .phase(SccmPhase::Policy)
        .role(SccmRole::Client)
        .severity(Severity::Warning)
        .confidence(SccmConfidence::Low)
        .coverage_gap(finding_client_gap(
            "client-policy-agent",
            SccmCoverageState::Absent,
        ))
        .next_artifact(finding_request(
            "policyAgent",
            SccmRole::ManagementPoint,
            "Policy evidence was not captured.",
        ))
        .build();
    assert_eq!(
        role_mismatch.unwrap_err(),
        SccmFindingValidationError::ArtifactRequestRoleMismatch
    );
}

#[test]
fn finding_artifact_requests_require_nonempty_bounded_reasons_and_count() {
    for reason in ["", "   ", ".", ";", "!?"] {
        let result = SccmFindingBuilder::new("empty-request-reason")
            .class(SccmFindingClass::InsufficientEvidence)
            .phase(SccmPhase::Policy)
            .role(SccmRole::Client)
            .severity(Severity::Warning)
            .confidence(SccmConfidence::Low)
            .coverage_gap(finding_client_gap(
                "client-policy-agent",
                SccmCoverageState::Absent,
            ))
            .next_artifact(finding_request("policyAgent", SccmRole::Client, reason))
            .build();
        assert_eq!(
            result.unwrap_err(),
            SccmFindingValidationError::InvalidArtifactRequestReason
        );
    }

    let overlong_reason = "x".repeat(MAX_SCCM_ARTIFACT_REQUEST_REASON_CHARS + 1);
    let overlong = SccmFindingBuilder::new("overlong-request-reason")
        .class(SccmFindingClass::InsufficientEvidence)
        .phase(SccmPhase::Policy)
        .role(SccmRole::Client)
        .severity(Severity::Warning)
        .confidence(SccmConfidence::Low)
        .coverage_gap(finding_client_gap(
            "client-policy-agent",
            SccmCoverageState::Absent,
        ))
        .next_artifact(finding_request(
            "policyAgent",
            SccmRole::Client,
            &overlong_reason,
        ))
        .build();
    assert_eq!(
        overlong.unwrap_err(),
        SccmFindingValidationError::InvalidArtifactRequestReason
    );

    let requests = (0..=MAX_SCCM_NEXT_ARTIFACT_REQUESTS)
        .map(|index| {
            finding_request(
                "policyAgent",
                SccmRole::Client,
                &format!("Bounded request {index}"),
            )
        })
        .collect();
    let too_many = SccmFindingBuilder::new("too-many-requests")
        .class(SccmFindingClass::InsufficientEvidence)
        .phase(SccmPhase::Policy)
        .role(SccmRole::Client)
        .severity(Severity::Warning)
        .confidence(SccmConfidence::Low)
        .coverage_gap(finding_client_gap(
            "client-policy-agent",
            SccmCoverageState::Absent,
        ))
        .next_artifacts(requests)
        .build();
    assert_eq!(
        too_many.unwrap_err(),
        SccmFindingValidationError::TooManyArtifactRequests
    );
}

#[test]
fn finding_artifact_request_raw_cardinality_precedes_exact_deduplication() {
    let canonical = finding_with_gap_and_request("duplicate-request-cardinality");
    let request = canonical.next_artifacts[0].clone();
    let duplicated = vec![request; MAX_SCCM_NEXT_ARTIFACT_REQUESTS + 1];

    let builder = SccmFindingBuilder::new("duplicate-request-builder")
        .class(SccmFindingClass::InsufficientEvidence)
        .phase(SccmPhase::Policy)
        .role(SccmRole::Client)
        .severity(Severity::Warning)
        .confidence(SccmConfidence::Low)
        .coverage_gap(finding_client_gap(
            "client-policy-agent",
            SccmCoverageState::AccessDenied,
        ))
        .next_artifacts(duplicated.clone())
        .build();
    assert_eq!(
        builder.unwrap_err(),
        SccmFindingValidationError::TooManyArtifactRequests
    );

    let mut direct = canonical.clone();
    direct.next_artifacts = duplicated;
    assert_eq!(
        direct.validate().unwrap_err(),
        SccmFindingValidationError::TooManyArtifactRequests
    );

    let mut json = serde_json::to_value(canonical).unwrap();
    let request_json = json["nextArtifacts"][0].clone();
    json["nextArtifacts"] =
        serde_json::Value::Array(vec![request_json; MAX_SCCM_NEXT_ARTIFACT_REQUESTS + 1]);
    assert!(serde_json::from_value::<SccmFinding>(json).is_err());

    let error = serde_json::to_string(&direct).unwrap_err().to_string();
    assert!(error.contains("TooManyArtifactRequests"), "{error}");
}

#[test]
fn finding_artifact_requests_reject_unbounded_reason_language_and_globs() {
    for reason in [
        "Collect the entire drive.",
        "Search the whole disk for related evidence.",
        "Collect all files recursively.",
        "Recursively scan the client logs.",
        "Collect C:\\**\\*.log.",
    ] {
        let result = SccmFindingBuilder::new("unbounded-request-reason")
            .class(SccmFindingClass::InsufficientEvidence)
            .phase(SccmPhase::Policy)
            .role(SccmRole::Client)
            .severity(Severity::Warning)
            .confidence(SccmConfidence::Low)
            .coverage_gap(finding_client_gap(
                "client-policy-agent",
                SccmCoverageState::Absent,
            ))
            .next_artifact(finding_request("policyAgent", SccmRole::Client, reason))
            .build();

        assert_eq!(
            result.unwrap_err(),
            SccmFindingValidationError::InvalidArtifactRequestReason,
            "{reason}"
        );
    }
}

#[test]
fn finding_deserialization_rejects_unsound_high_and_forged_terminal_state() {
    let evidence = finding_evidence_ref("client-app-enforce", "client-app-enforce:1-1");
    let sound = SccmFindingBuilder::new("sound-terminal")
        .class(SccmFindingClass::ConfirmedFailure)
        .phase(SccmPhase::Enforcement)
        .role(SccmRole::Client)
        .severity(Severity::Error)
        .confidence(SccmConfidence::High)
        .evidence(vec![evidence.clone()])
        .terminal_evidence(vec![SccmTerminalEvidence::observed_failure(evidence)])
        .build()
        .unwrap();

    let mut keyless_high = serde_json::to_value(&sound).unwrap();
    keyless_high["terminalEvidence"] = serde_json::json!([]);
    assert!(serde_json::from_value::<SccmFinding>(keyless_high).is_err());

    let mut forged_terminal = serde_json::to_value(&sound).unwrap();
    forged_terminal["terminalEvidence"][0]["kind"] = serde_json::json!("forgedFailure");
    assert!(serde_json::from_value::<SccmFinding>(forged_terminal).is_err());
}

#[test]
fn finding_builder_rejects_blank_self_attesting_terminal_identity() {
    let invalid = SccmEvidenceRef {
        artifact_id: String::new(),
        entry_id: "   ".into(),
        line_start: None,
        line_end: None,
    };
    let result = SccmFindingBuilder::new("blank-terminal-builder")
        .class(SccmFindingClass::ConfirmedFailure)
        .phase(SccmPhase::Enforcement)
        .role(SccmRole::Client)
        .severity(Severity::Error)
        .confidence(SccmConfidence::High)
        .evidence(vec![invalid.clone()])
        .terminal_evidence(vec![SccmTerminalEvidence::observed_failure(invalid)])
        .build();

    assert_eq!(
        result.unwrap_err(),
        SccmFindingValidationError::InvalidEvidenceReference
    );
}

#[test]
fn finding_deserialization_rejects_blank_self_attesting_terminal_identity() {
    let evidence = finding_evidence_ref("client-app-enforce", "client-app-enforce:1-1");
    let finding = SccmFindingBuilder::new("blank-terminal-deserialize")
        .class(SccmFindingClass::ConfirmedFailure)
        .phase(SccmPhase::Enforcement)
        .role(SccmRole::Client)
        .severity(Severity::Error)
        .confidence(SccmConfidence::High)
        .evidence(vec![evidence.clone()])
        .terminal_evidence(vec![SccmTerminalEvidence::observed_failure(evidence)])
        .build()
        .unwrap();
    let mut json = serde_json::to_value(finding).unwrap();
    json["evidence"][0]["artifactId"] = serde_json::json!(" ");
    json["evidence"][0]["entryId"] = serde_json::json!("");
    json["terminalEvidence"][0]["reference"]["artifactId"] = serde_json::json!(" ");
    json["terminalEvidence"][0]["reference"]["entryId"] = serde_json::json!("");

    assert!(serde_json::from_value::<SccmFinding>(json).is_err());
}

#[test]
fn finding_serialization_rejects_blank_self_attesting_terminal_identity() {
    let evidence = finding_evidence_ref("client-app-enforce", "client-app-enforce:1-1");
    let mut finding = SccmFindingBuilder::new("blank-terminal-serialize")
        .class(SccmFindingClass::ConfirmedFailure)
        .phase(SccmPhase::Enforcement)
        .role(SccmRole::Client)
        .severity(Severity::Error)
        .confidence(SccmConfidence::High)
        .evidence(vec![evidence.clone()])
        .terminal_evidence(vec![SccmTerminalEvidence::observed_failure(evidence)])
        .build()
        .unwrap();
    finding.evidence[0].artifact_id = " ".into();
    finding.evidence[0].entry_id.clear();
    finding.terminal_evidence[0].reference.artifact_id = " ".into();
    finding.terminal_evidence[0].reference.entry_id.clear();

    assert!(serde_json::to_value(finding).is_err());
}

#[test]
fn finding_serialization_rejects_post_build_invalid_mutation() {
    let evidence = finding_evidence_ref("client-app-enforce", "client-app-enforce:1-1");
    let mut finding = SccmFindingBuilder::new("mutated-confirmed-failure")
        .class(SccmFindingClass::ConfirmedFailure)
        .phase(SccmPhase::Enforcement)
        .role(SccmRole::Client)
        .severity(Severity::Error)
        .confidence(SccmConfidence::High)
        .evidence(vec![evidence.clone()])
        .terminal_evidence(vec![SccmTerminalEvidence::observed_failure(evidence)])
        .build()
        .unwrap();
    finding.terminal_evidence.clear();

    assert!(serde_json::to_value(finding).is_err());
}

#[test]
fn finding_deserialization_sorts_and_deduplicates_terminal_evidence() {
    let first = finding_evidence_ref("artifact-a", "entry-a");
    let second = finding_evidence_ref("artifact-b", "entry-b");
    let finding = SccmFindingBuilder::new("terminal-ordering")
        .class(SccmFindingClass::ConfirmedFailure)
        .phase(SccmPhase::Enforcement)
        .role(SccmRole::Client)
        .severity(Severity::Error)
        .confidence(SccmConfidence::High)
        .evidence(vec![first.clone(), second.clone()])
        .terminal_evidence(vec![SccmTerminalEvidence::observed_failure(first.clone())])
        .build()
        .unwrap();
    let first_terminal =
        serde_json::to_value(SccmTerminalEvidence::observed_failure(first)).unwrap();
    let second_terminal =
        serde_json::to_value(SccmTerminalEvidence::observed_failure(second)).unwrap();
    let mut json = serde_json::to_value(finding).unwrap();
    json["terminalEvidence"] =
        serde_json::json!([second_terminal, first_terminal.clone(), first_terminal]);

    let normalized: SccmFinding = serde_json::from_value(json).unwrap();
    assert_eq!(normalized.terminal_evidence.len(), 2);
    assert_eq!(
        normalized.terminal_evidence[0].reference.artifact_id,
        "artifact-a"
    );
    assert_eq!(
        normalized.terminal_evidence[1].reference.artifact_id,
        "artifact-b"
    );
}

#[test]
fn finding_deserialization_rejects_raw_execution_context_fields() {
    let evidence = finding_evidence_ref("client-policy-agent", "policy:1-1");
    let finding = SccmFindingBuilder::new("no-raw-context")
        .class(SccmFindingClass::Symptom)
        .phase(SccmPhase::Policy)
        .role(SccmRole::Client)
        .severity(Severity::Warning)
        .confidence(SccmConfidence::Low)
        .evidence(vec![evidence])
        .build()
        .unwrap();
    let mut json = serde_json::to_value(finding).unwrap();
    json["executionContext"] = serde_json::json!(r"LAB\SyntheticUser");

    assert!(serde_json::from_value::<SccmFinding>(json).is_err());
}

#[test]
fn finding_deserialization_rejects_unknown_fields_recursively() {
    let evidence = finding_evidence_ref("client-policy-agent", "policy:1-1");
    let finding = SccmFindingBuilder::new("strict-finding-wire")
        .class(SccmFindingClass::Symptom)
        .phase(SccmPhase::Policy)
        .role(SccmRole::Client)
        .severity(Severity::Warning)
        .confidence(SccmConfidence::Low)
        .evidence(vec![evidence.clone()])
        .terminal_evidence(vec![SccmTerminalEvidence::observed_failure(
            evidence.clone(),
        )])
        .coverage_gap(finding_client_gap(
            "client-policy-agent",
            SccmCoverageState::AccessDenied,
        ))
        .correlation_keys(vec![finding_key(
            SccmCorrelationKeyKind::AssignmentId,
            "{ABCDEFAB-0000-0000-0000-000000000001}",
            "abcdefab-0000-0000-0000-000000000001",
            SccmKeyConfidence::Low,
            Some("sccm-keys-experimental-v1"),
            evidence,
        )])
        .next_artifact(finding_request(
            "policyAgent",
            SccmRole::Client,
            "Confirm the bounded policy request outcome.",
        ))
        .build()
        .unwrap();
    let json = serde_json::to_value(finding).unwrap();

    let mut cases = Vec::new();

    let mut nested_evidence = json.clone();
    nested_evidence["evidence"][0]["executionContext"] = serde_json::json!(r"LAB\SyntheticUser");
    cases.push(("evidence", nested_evidence));

    let mut terminal_evidence = json.clone();
    terminal_evidence["terminalEvidence"][0]["executionContext"] =
        serde_json::json!(r"LAB\SyntheticUser");
    cases.push(("terminal evidence", terminal_evidence));

    let mut terminal_reference = json.clone();
    terminal_reference["terminalEvidence"][0]["reference"]["executionContext"] =
        serde_json::json!(r"LAB\SyntheticUser");
    cases.push(("terminal reference", terminal_reference));

    let mut coverage_gap = json.clone();
    coverage_gap["coverageGaps"][0]["executionContext"] = serde_json::json!(r"LAB\SyntheticUser");
    cases.push(("coverage gap", coverage_gap));

    let mut correlation_key = json.clone();
    correlation_key["correlationKeys"][0]["executionContext"] =
        serde_json::json!(r"LAB\SyntheticUser");
    cases.push(("correlation key", correlation_key));

    let mut correlation_key_reference = json.clone();
    correlation_key_reference["correlationKeys"][0]["evidence"]["executionContext"] =
        serde_json::json!(r"LAB\SyntheticUser");
    cases.push(("correlation key reference", correlation_key_reference));

    let mut artifact_request = json;
    artifact_request["nextArtifacts"][0]["executionContext"] =
        serde_json::json!(r"LAB\SyntheticUser");
    cases.push(("artifact request", artifact_request));

    for (label, case) in cases {
        assert!(
            serde_json::from_value::<SccmFinding>(case).is_err(),
            "{label} accepted an undeclared nested field"
        );
    }
}

#[test]
fn finding_output_is_sorted_deduplicated_camel_case_and_round_trippable() {
    let first = finding_evidence_ref("artifact-a", "entry-a");
    let second = finding_evidence_ref("artifact-b", "entry-b");
    let package_key = finding_key(
        SccmCorrelationKeyKind::PackageId,
        "LAB00001",
        "LAB00001",
        SccmKeyConfidence::Low,
        Some("sccm-keys-experimental-v1"),
        second.clone(),
    );
    let assignment_key = finding_key(
        SccmCorrelationKeyKind::AssignmentId,
        "{ABCDEFAB-0000-0000-0000-000000000001}",
        "abcdefab-0000-0000-0000-000000000001",
        SccmKeyConfidence::Low,
        Some("sccm-keys-experimental-v1"),
        first.clone(),
    );

    let finding = SccmFindingBuilder::new("blocked-policy")
        .class(SccmFindingClass::BlockedOrDeferred)
        .phase(SccmPhase::Unknown("futurePhase".into()))
        .role(SccmRole::Client)
        .severity(Severity::Warning)
        .confidence(SccmConfidence::Moderate)
        .title("Policy processing is blocked")
        .summary("Synthetic evidence does not expose execution context.")
        .evidence(vec![second.clone(), first.clone(), second.clone()])
        .correlation_keys(vec![
            package_key.clone(),
            assignment_key.clone(),
            package_key,
        ])
        .coverage_gaps(vec![
            finding_client_gap("artifact-z", SccmCoverageState::Capped),
            finding_client_gap("artifact-c", SccmCoverageState::AccessDenied),
            finding_client_gap("artifact-z", SccmCoverageState::Capped),
        ])
        .next_artifacts(vec![
            finding_request(
                "policyEvaluator",
                SccmRole::Client,
                "Confirm the bounded policy evaluation outcome.",
            ),
            finding_request(
                "policyAgent",
                SccmRole::Client,
                "Confirm the bounded policy request outcome.",
            ),
            finding_request(
                "policyEvaluator",
                SccmRole::Client,
                "Confirm the bounded policy evaluation outcome.",
            ),
        ])
        .build()
        .unwrap();

    assert_eq!(finding.evidence, vec![first, second]);
    assert_eq!(
        finding
            .correlation_keys
            .iter()
            .map(|key| key.kind.clone())
            .collect::<Vec<_>>(),
        vec![
            SccmCorrelationKeyKind::AssignmentId,
            SccmCorrelationKeyKind::PackageId,
        ]
    );
    assert_eq!(
        finding
            .coverage_gaps
            .iter()
            .map(|gap| gap.artifact_id.as_str())
            .collect::<Vec<_>>(),
        vec!["artifact-c", "artifact-z"]
    );
    assert_eq!(
        finding
            .next_artifacts
            .iter()
            .map(|request| request.logical_id.as_str())
            .collect::<Vec<_>>(),
        vec!["policyAgent", "policyEvaluator"]
    );

    let json = serde_json::to_value(&finding).unwrap();
    assert_eq!(json["findingId"], "blocked-policy");
    assert_eq!(json["class"], "blockedOrDeferred");
    assert_eq!(json["phase"], "futurePhase");
    assert!(json.get("coverageGaps").is_some());
    assert!(json.get("correlationKeys").is_some());
    assert!(json.get("nextArtifacts").is_some());
    assert!(json.get("executionContext").is_none());
    assert!(!serde_json::to_string(&json)
        .unwrap()
        .contains("SyntheticUser"));

    let round_trip: SccmFinding = serde_json::from_value(json).unwrap();
    assert_eq!(round_trip, finding);
    round_trip.validate().unwrap();
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
    assert!(signals[0].error_description.is_some());
    assert_eq!(signals[1].numeric, Some(0xDEADBEEF));
    assert_eq!(signals[1].error_description, None);
    assert_eq!(signals[1].error_category, None);
}

#[test]
fn signal_extractor_does_not_enrich_decimal_values_as_unprefixed_hex() {
    let signals = extract_signals("status=80004005");

    assert_eq!(signals.len(), 1);
    assert_eq!(signals[0].kind, SccmSignalKind::Status);
    assert_eq!(signals[0].raw, "80004005");
    assert_eq!(signals[0].numeric, Some(80_004_005));
    assert_eq!(signals[0].error_description, None);
    assert_eq!(signals[0].error_category, None);
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
    assert_eq!(
        json,
        serde_json::json!([
            {
                "kind": "hResult",
                "raw": "0x80004005",
                "numeric": 2_147_500_037_u32,
                "start": 8,
                "end": 18,
                "errorDescription": "E_FAIL - Unspecified failure",
                "errorCategory": "Windows"
            },
            {
                "kind": "status",
                "raw": "4294967296",
                "numeric": null,
                "start": 27,
                "end": 37,
                "errorDescription": null,
                "errorCategory": null
            }
        ])
    );

    let decoded: Vec<SccmSignal> = serde_json::from_value(json.clone()).unwrap();
    assert_eq!(decoded, first);
    assert_eq!(serde_json::to_value(&decoded).unwrap(), json);

    let kind_json = serde_json::to_string(&SccmSignalKind::Gle).unwrap();
    assert_eq!(kind_json, r#""gle""#);
    let decoded_kind: SccmSignalKind = serde_json::from_str(&kind_json).unwrap();
    assert_eq!(decoded_kind, SccmSignalKind::Gle);
}

#[test]
fn key_normalization_is_stable_across_case_and_brace_variants() {
    let left = normalize_key(
        SccmCorrelationKeyKind::AssignmentId,
        "{ABCDEFAB-0000-0000-0000-000000000001}",
    );
    let right = normalize_key(
        SccmCorrelationKeyKind::AssignmentId,
        "abcdefab-0000-0000-0000-000000000001",
    );

    assert_eq!(left.normalized, right.normalized);
    assert_eq!(left.confidence, SccmKeyConfidence::Exact);
}

#[test]
fn key_normalization_covers_each_declared_lexical_kind() {
    let cases = [
        (
            SccmCorrelationKeyKind::AssignmentId,
            "{ABCDEFAB-0000-0000-0000-000000000001}",
            "abcdefab-0000-0000-0000-000000000001",
        ),
        (
            SccmCorrelationKeyKind::ClientGuid,
            "GUID:{ABCDEFAB-0000-0000-0000-000000000002}",
            "abcdefab-0000-0000-0000-000000000002",
        ),
        (SccmCorrelationKeyKind::PackageId, "lab00001", "LAB00001"),
        (
            SccmCorrelationKeyKind::ContentId,
            "Content_ABC-123",
            "content_abc-123",
        ),
        (SccmCorrelationKeyKind::SiteCode, "lab", "LAB"),
        (
            SccmCorrelationKeyKind::ServerHost,
            "MP01.LAB.LOCAL.",
            "mp01.lab.local",
        ),
        (SccmCorrelationKeyKind::CiId, "00042", "42"),
        (
            SccmCorrelationKeyKind::UpdateId,
            "{ABCDEFAB-0000-0000-0000-000000000003}",
            "abcdefab-0000-0000-0000-000000000003",
        ),
        (SccmCorrelationKeyKind::KbId, "kb5034441", "KB5034441"),
        (
            SccmCorrelationKeyKind::BitsJobId,
            "{ABCDEFAB-0000-0000-0000-000000000004}",
            "abcdefab-0000-0000-0000-000000000004",
        ),
        (
            SccmCorrelationKeyKind::TaskSequenceExecutionId,
            "{ABCDEFAB-0000-0000-0000-000000000005}",
            "abcdefab-0000-0000-0000-000000000005",
        ),
        (
            SccmCorrelationKeyKind::RequestId,
            "{ABCDEFAB-0000-0000-0000-000000000006}",
            "abcdefab-0000-0000-0000-000000000006",
        ),
        (
            SccmCorrelationKeyKind::TopicId,
            "{ABCDEFAB-0000-0000-0000-000000000007}",
            "abcdefab-0000-0000-0000-000000000007",
        ),
        (SccmCorrelationKeyKind::StateMessageId, "00071", "71"),
    ];

    for (kind, raw, expected) in cases {
        let key = normalize_key(kind, raw);
        assert_eq!(key.normalized, expected, "{raw}");
        assert_eq!(key.confidence, SccmKeyConfidence::Exact, "{raw}");
    }
}

#[test]
fn key_normalization_malformed_values_are_low_confidence_only() {
    for (kind, raw) in [
        (SccmCorrelationKeyKind::AssignmentId, "{not-a-guid}"),
        (SccmCorrelationKeyKind::PackageId, "LAB001"),
        (SccmCorrelationKeyKind::ServerHost, "bad..host"),
        (SccmCorrelationKeyKind::KbId, "KB-not-numeric"),
    ] {
        assert_eq!(
            normalize_key(kind, raw).confidence,
            SccmKeyConfidence::Low,
            "{raw}"
        );
    }
}

#[test]
fn key_extraction_unvalidated_version_cannot_emit_exact_extracted_key() {
    let result = extract_keys(
        &evidence_with_message("Policy id={ABCDEFAB-0000-0000-0000-000000000001}"),
        &SccmExtractionProfile::for_version(Some("unobserved-version")),
    );

    assert!(result.keys.is_empty());
    assert_eq!(
        result.gaps[0].kind,
        SccmExtractionGapKind::UnvalidatedVersion
    );
    assert_eq!(
        result.gaps[0].candidate_raw.as_deref(),
        Some("{ABCDEFAB-0000-0000-0000-000000000001}")
    );
}

#[test]
fn key_extraction_missing_version_is_an_explicit_gap_not_a_key() {
    let result = extract_keys(
        &evidence_with_message("package id=LAB00001"),
        &SccmExtractionProfile::for_version(None),
    );

    assert!(result.keys.is_empty());
    assert_eq!(result.gaps[0].kind, SccmExtractionGapKind::MissingVersion);
    assert_eq!(result.gaps[0].candidate_raw.as_deref(), Some("LAB00001"));
}

#[test]
fn key_extraction_unvalidated_and_missing_versions_preserve_every_candidate_gap() {
    let evidence = evidence_with_message(
        "package id=LAB00001; site code=LAB; \
         assignment id={ABCDEFAB-0000-0000-0000-000000000001}",
    );

    for (profile, expected_gap_kind) in [
        (
            SccmExtractionProfile::for_version(Some("unobserved-version")),
            SccmExtractionGapKind::UnvalidatedVersion,
        ),
        (
            SccmExtractionProfile::for_version(None),
            SccmExtractionGapKind::MissingVersion,
        ),
    ] {
        let first = extract_keys(&evidence, &profile);
        let second = extract_keys(&evidence, &profile);

        assert_eq!(first, second);
        assert!(first.keys.is_empty());
        assert_eq!(first.gaps.len(), 3);
        assert!(first.gaps.iter().all(|gap| gap.kind == expected_gap_kind));
        assert_eq!(
            first
                .gaps
                .iter()
                .map(|gap| (gap.candidate_kind.clone(), gap.candidate_raw.as_deref()))
                .collect::<Vec<_>>(),
            vec![
                (Some(SccmCorrelationKeyKind::PackageId), Some("LAB00001")),
                (Some(SccmCorrelationKeyKind::SiteCode), Some("LAB")),
                (
                    Some(SccmCorrelationKeyKind::AssignmentId),
                    Some("{ABCDEFAB-0000-0000-0000-000000000001}")
                ),
            ]
        );
        assert!(first
            .gaps
            .iter()
            .all(|gap| gap.evidence == evidence.reference));
    }
}

#[test]
fn key_extraction_rejects_truncated_prefixes_from_invalid_structured_values() {
    let overlong_content_id = "a".repeat(129);
    let invalid_guid = "{ABCDEFAB-0000-0000-0000-000000000001}extra";
    let invalid_host = "mp01.lab.local_suffix";
    let evidence = evidence_with_message(&format!(
        "assignment id={invalid_guid}; content id={overlong_content_id}; \
         server host={invalid_host}"
    ));

    let result = extract_keys(
        &evidence,
        &SccmExtractionProfile::for_version(Some("5.00.9128.1007")),
    );

    assert!(result.keys.is_empty());
    assert_eq!(
        result
            .gaps
            .iter()
            .filter(|gap| gap.kind == SccmExtractionGapKind::MalformedCandidate)
            .map(|gap| gap.candidate_raw.as_deref())
            .collect::<Vec<_>>(),
        vec![
            Some(invalid_guid),
            Some(overlong_content_id.as_str()),
            Some(invalid_host),
        ]
    );
}

#[test]
fn key_extraction_requires_a_full_token_boundary_for_every_declared_kind() {
    let cases = [
        (
            SccmCorrelationKeyKind::AssignmentId,
            "assignment id={ABCDEFAB-0000-0000-0000-000000000001}}",
            "{ABCDEFAB-0000-0000-0000-000000000001}}",
        ),
        (
            SccmCorrelationKeyKind::ClientGuid,
            "client guid=GUID:{ABCDEFAB-0000-0000-0000-000000000002}/continued",
            "GUID:{ABCDEFAB-0000-0000-0000-000000000002}/continued",
        ),
        (
            SccmCorrelationKeyKind::PackageId,
            "package id=LAB00001é",
            "LAB00001é",
        ),
        (
            SccmCorrelationKeyKind::ContentId,
            "content id=ContentABC/continued",
            "ContentABC/continued",
        ),
        (
            SccmCorrelationKeyKind::SiteCode,
            "site code=LAB:continued",
            "LAB:continued",
        ),
        (
            SccmCorrelationKeyKind::ServerHost,
            "server host=mp01.lab.localé",
            "mp01.lab.localé",
        ),
        (
            SccmCorrelationKeyKind::CiId,
            "ci id=42+continued",
            "42+continued",
        ),
        (
            SccmCorrelationKeyKind::UpdateId,
            "update id={ABCDEFAB-0000-0000-0000-000000000003}:continued",
            "{ABCDEFAB-0000-0000-0000-000000000003}:continued",
        ),
        (
            SccmCorrelationKeyKind::KbId,
            "kb id=KB5034441/continued",
            "KB5034441/continued",
        ),
        (
            SccmCorrelationKeyKind::BitsJobId,
            "bits job id={ABCDEFAB-0000-0000-0000-000000000004}+continued",
            "{ABCDEFAB-0000-0000-0000-000000000004}+continued",
        ),
        (
            SccmCorrelationKeyKind::TaskSequenceExecutionId,
            "task sequence execution id={ABCDEFAB-0000-0000-0000-000000000005}}",
            "{ABCDEFAB-0000-0000-0000-000000000005}}",
        ),
        (
            SccmCorrelationKeyKind::RequestId,
            "request id={ABCDEFAB-0000-0000-0000-000000000006}/continued",
            "{ABCDEFAB-0000-0000-0000-000000000006}/continued",
        ),
        (
            SccmCorrelationKeyKind::TopicId,
            "topic id={ABCDEFAB-0000-0000-0000-000000000007}:continued",
            "{ABCDEFAB-0000-0000-0000-000000000007}:continued",
        ),
        (
            SccmCorrelationKeyKind::StateMessageId,
            "state message id=71é",
            "71é",
        ),
    ];
    let profile = SccmExtractionProfile::for_version(Some("5.00.9128.1007"));
    let mut violations = Vec::new();

    for (expected_kind, message, expected_raw) in cases {
        let evidence = evidence_with_message(message);
        let first = extract_keys(&evidence, &profile);
        let second = extract_keys(&evidence, &profile);

        assert_eq!(first, second, "{message}");
        let malformed = first
            .gaps
            .iter()
            .filter(|gap| gap.kind == SccmExtractionGapKind::MalformedCandidate)
            .map(|gap| (gap.candidate_kind.clone(), gap.candidate_raw.as_deref()))
            .collect::<Vec<_>>();
        if !first.keys.is_empty() || malformed != vec![(Some(expected_kind), Some(expected_raw))] {
            violations.push(format!("{message}: {first:?}"));
        }
    }

    assert!(
        violations.is_empty(),
        "truncated key prefixes were admitted:\n{}",
        violations.join("\n")
    );
}

#[test]
fn key_extraction_rejects_every_label_inside_a_preceding_malformed_token() {
    let second_labels = [
        (
            SccmCorrelationKeyKind::AssignmentId,
            "assignment id={ABCDEFAB-0000-0000-0000-000000000001}",
        ),
        (
            SccmCorrelationKeyKind::ClientGuid,
            "client guid=GUID:{ABCDEFAB-0000-0000-0000-000000000002}",
        ),
        (SccmCorrelationKeyKind::PackageId, "package id=LAB00002"),
        (SccmCorrelationKeyKind::ContentId, "content id=ContentABC"),
        (SccmCorrelationKeyKind::SiteCode, "site code=LAB"),
        (
            SccmCorrelationKeyKind::ServerHost,
            "server host=mp01.lab.local",
        ),
        (SccmCorrelationKeyKind::CiId, "ci id=42"),
        (
            SccmCorrelationKeyKind::UpdateId,
            "update id={ABCDEFAB-0000-0000-0000-000000000003}",
        ),
        (SccmCorrelationKeyKind::KbId, "kb id=KB5034441"),
        (
            SccmCorrelationKeyKind::BitsJobId,
            "bits job id={ABCDEFAB-0000-0000-0000-000000000004}",
        ),
        (
            SccmCorrelationKeyKind::TaskSequenceExecutionId,
            "task sequence execution id={ABCDEFAB-0000-0000-0000-000000000005}",
        ),
        (
            SccmCorrelationKeyKind::RequestId,
            "request id={ABCDEFAB-0000-0000-0000-000000000006}",
        ),
        (
            SccmCorrelationKeyKind::TopicId,
            "topic id={ABCDEFAB-0000-0000-0000-000000000007}",
        ),
        (
            SccmCorrelationKeyKind::StateMessageId,
            "state message id=71",
        ),
    ];
    let forbidden_delimiters = ["/", ":", "+"];
    let profile = SccmExtractionProfile::for_version(Some("5.00.9128.1007"));
    let mut violations = Vec::new();

    for (index, (second_kind, second_label)) in second_labels.into_iter().enumerate() {
        let delimiter = forbidden_delimiters[index % forbidden_delimiters.len()];
        let message = format!("package id=LAB00001{delimiter}{second_label}");
        let malformed_raw = format!(
            "LAB00001{delimiter}{}",
            second_label.split_whitespace().next().unwrap()
        );
        let evidence = evidence_with_message(&message);
        let first = extract_keys(&evidence, &profile);
        let second = extract_keys(&evidence, &profile);
        let malformed = first
            .gaps
            .iter()
            .filter(|gap| gap.kind == SccmExtractionGapKind::MalformedCandidate)
            .map(|gap| {
                (
                    gap.candidate_kind.clone(),
                    gap.candidate_raw.as_deref(),
                    gap.evidence.clone(),
                )
            })
            .collect::<Vec<_>>();
        let expected_malformed = vec![(
            Some(SccmCorrelationKeyKind::PackageId),
            Some(malformed_raw.as_str()),
            evidence.reference.clone(),
        )];

        if first != second || !first.keys.is_empty() || malformed != expected_malformed {
            violations.push(format!("{second_kind:?}: {message}: {first:?}"));
        }
    }

    for (message, malformed_kind, malformed_raw) in [
        (
            "assignment id={ABCDEFAB-0000-0000-0000-000000000001}}content id=ContentABC",
            SccmCorrelationKeyKind::AssignmentId,
            "{ABCDEFAB-0000-0000-0000-000000000001}}content",
        ),
        (
            "package id=LAB00001écontent id=ContentABC",
            SccmCorrelationKeyKind::PackageId,
            "LAB00001écontent",
        ),
    ] {
        let result = extract_keys(&evidence_with_message(message), &profile);
        let malformed = result
            .gaps
            .iter()
            .find(|gap| gap.kind == SccmExtractionGapKind::MalformedCandidate);
        if !result.keys.is_empty()
            || malformed.and_then(|gap| gap.candidate_kind.clone()) != Some(malformed_kind)
            || malformed.and_then(|gap| gap.candidate_raw.as_deref()) != Some(malformed_raw)
        {
            violations.push(format!("{message}: {result:?}"));
        }
    }

    let unvalidated_evidence = evidence_with_message("package id=LAB00001/content id=ContentABC");
    let unvalidated = extract_keys(
        &unvalidated_evidence,
        &SccmExtractionProfile::for_version(Some("unobserved-version")),
    );
    if !unvalidated.keys.is_empty()
        || unvalidated.gaps.len() != 1
        || unvalidated.gaps[0].kind != SccmExtractionGapKind::UnvalidatedVersion
        || unvalidated.gaps[0].candidate_kind != Some(SccmCorrelationKeyKind::PackageId)
        || unvalidated.gaps[0].candidate_raw.as_deref() != Some("LAB00001/content")
        || unvalidated.gaps[0].evidence != unvalidated_evidence.reference
    {
        violations.push(format!("unvalidated profile: {unvalidated:?}"));
    }

    assert!(
        violations.is_empty(),
        "labels escaped from malformed tokens:\n{}",
        violations.join("\n")
    );
}

#[test]
fn key_extraction_accepts_the_declared_full_token_boundaries() {
    let profile = SccmExtractionProfile::for_version(Some("5.00.9128.1007"));

    for separator in [" ", "\n", "\t", ",", ";", "&"] {
        let message = format!("😀 package id=LAB00001{separator}content id=ContentABC");
        let result = extract_keys(&evidence_with_message(&message), &profile);

        assert_eq!(result.keys.len(), 2, "{message:?}");
        assert_eq!(result.keys[0].kind, SccmCorrelationKeyKind::PackageId);
        assert_eq!(result.keys[0].raw, "LAB00001", "{message:?}");
        assert_eq!(result.keys[1].kind, SccmCorrelationKeyKind::ContentId);
        assert_eq!(result.keys[1].raw, "ContentABC", "{message:?}");
        assert!(result
            .keys
            .iter()
            .all(|key| key.confidence == SccmKeyConfidence::Low));
        for key in &result.keys {
            let byte_start = message.find(&key.raw).unwrap();
            let expected_start = message[..byte_start].encode_utf16().count();
            assert_eq!(key.start, Some(expected_start), "{message:?}");
            assert_eq!(
                key.end,
                Some(expected_start + key.raw.encode_utf16().count()),
                "{message:?}"
            );
        }
        assert!(result
            .gaps
            .iter()
            .all(|gap| gap.kind != SccmExtractionGapKind::MalformedCandidate));
    }
}

#[test]
fn key_profile_single_observed_version_stays_experimental_and_low_confidence() {
    let profile = SccmExtractionProfile::for_version(Some("5.00.9128.1007"));
    let evidence = evidence_with_message(
        "Policy id={ABCDEFAB-0000-0000-0000-000000000001}; \
         package id=LAB00001; site code=LAB",
    );
    let result = extract_keys(&evidence, &profile);

    assert_eq!(
        profile.maturity,
        SccmExtractionProfileMaturity::Experimental
    );
    assert_eq!(profile.configmgr_version_prefixes, vec!["5.00.9128."]);
    assert!(profile.validated_artifact_families.is_empty());
    assert_eq!(result.keys.len(), 3);
    assert!(result
        .keys
        .iter()
        .all(|key| key.confidence == SccmKeyConfidence::Low));
    assert!(result.keys.iter().all(|key| {
        !matches!(
            key.confidence,
            SccmKeyConfidence::Strong | SccmKeyConfidence::Exact
        )
    }));
    assert_eq!(
        result.gaps[0].kind,
        SccmExtractionGapKind::ExperimentalProfile
    );
    assert_eq!(
        SccmExtractionProfile::for_version(Some("5.00.9135.1000")).maturity,
        SccmExtractionProfileMaturity::Unvalidated
    );
}

#[test]
fn key_profile_version_selection_rejects_malformed_or_prefix_collision_versions() {
    for version in ["5.00.9128.not-observed", "5.00.91280.1007", "5.00.9128"] {
        assert_eq!(
            SccmExtractionProfile::for_version(Some(version)).maturity,
            SccmExtractionProfileMaturity::Unvalidated,
            "{version}"
        );
    }
}

#[test]
fn key_extraction_covers_declared_labels_in_message_order() {
    let evidence = evidence_with_message(
        "assignment id={ABCDEFAB-0000-0000-0000-000000000001}; \
         client guid=GUID:{ABCDEFAB-0000-0000-0000-000000000002}; \
         package id=LAB00001; content id=Content_ABC-123; site code=lab; \
         server host=MP01.LAB.LOCAL.; ci id=00042; \
         update id={ABCDEFAB-0000-0000-0000-000000000003}; kb id=KB5034441; \
         bits job id={ABCDEFAB-0000-0000-0000-000000000004}; \
         task sequence execution id={ABCDEFAB-0000-0000-0000-000000000005}; \
         request id={ABCDEFAB-0000-0000-0000-000000000006}; \
         topic id={ABCDEFAB-0000-0000-0000-000000000007}; state message id=00071",
    );
    let result = extract_keys(
        &evidence,
        &SccmExtractionProfile::for_version(Some("5.00.9128.1007")),
    );

    assert_eq!(
        result
            .keys
            .iter()
            .map(|key| key.kind.clone())
            .collect::<Vec<_>>(),
        vec![
            SccmCorrelationKeyKind::AssignmentId,
            SccmCorrelationKeyKind::ClientGuid,
            SccmCorrelationKeyKind::PackageId,
            SccmCorrelationKeyKind::ContentId,
            SccmCorrelationKeyKind::SiteCode,
            SccmCorrelationKeyKind::ServerHost,
            SccmCorrelationKeyKind::CiId,
            SccmCorrelationKeyKind::UpdateId,
            SccmCorrelationKeyKind::KbId,
            SccmCorrelationKeyKind::BitsJobId,
            SccmCorrelationKeyKind::TaskSequenceExecutionId,
            SccmCorrelationKeyKind::RequestId,
            SccmCorrelationKeyKind::TopicId,
            SccmCorrelationKeyKind::StateMessageId,
        ]
    );
}

#[test]
fn key_profile_forged_stable_profile_cannot_emit_strong_or_exact_keys() {
    let mut profile = SccmExtractionProfile::for_version(Some("5.00.9128.1007"));
    profile.maturity = SccmExtractionProfileMaturity::Stable;

    let result = extract_keys(&evidence_with_message("package id=LAB00001"), &profile);

    assert!(result.keys.is_empty());
    assert_eq!(
        result.gaps[0].kind,
        SccmExtractionGapKind::UnvalidatedProfile
    );
}

#[test]
fn key_profile_and_extraction_result_have_deterministic_json_round_trips() {
    let profile = SccmExtractionProfile::for_version(Some("5.00.9128.1007"));
    let evidence = evidence_with_message("Policy id={ABCDEFAB-0000-0000-0000-000000000001}");
    let first = extract_keys(&evidence, &profile);
    let second = extract_keys(&evidence, &profile);

    assert_eq!(first, second);
    assert_eq!(
        serde_json::to_value(&profile).unwrap(),
        serde_json::json!({
            "profileId": "sccm-keys-5.00.9128-experimental-v1",
            "configmgrVersionPrefixes": ["5.00.9128."],
            "validatedArtifactFamilies": [],
            "selectedConfigmgrVersion": "5.00.9128.1007",
            "maturity": "experimental"
        })
    );

    let profile_json = serde_json::to_string(&profile).unwrap();
    assert_eq!(
        serde_json::from_str::<SccmExtractionProfile>(&profile_json).unwrap(),
        profile
    );

    let result_json = serde_json::to_string(&first).unwrap();
    assert_eq!(
        serde_json::from_str::<SccmKeyExtractionResult>(&result_json).unwrap(),
        first
    );
}

#[test]
fn key_extraction_never_emits_a_key_its_own_contract_rejects() {
    let mut mismatches: Vec<String> = Vec::new();
    let profile = SccmExtractionProfile::for_version(Some("5.00.9128.1010"));

    // Both raws are inside the regexes' token grammar but outside the
    // correlation-key value bound. The KB case is bounded as a raw and only
    // crosses the bound once normalization prepends "KB", so the producer has
    // to weigh the normalized value too.
    for (label, message, raw) in [
        (
            "an overlong CI ID",
            format!("CI ID={} status=71", "1".repeat(300)),
            "1".repeat(300),
        ),
        (
            "a KB ID that normalizes past the bound",
            format!("KB ID={}", "9".repeat(255)),
            "9".repeat(255),
        ),
    ] {
        let evidence = evidence_with_message(&message);
        let result = extract_keys(&evidence, &profile);

        for key in &result.keys {
            let key_json = serde_json::to_value(key).unwrap();
            if serde_json::from_value::<SccmCorrelationKey>(key_json)
                .ok()
                .as_ref()
                != Some(key)
            {
                mismatches.push(format!(
                    "extract_keys emitted a key its own validator rejects for {label}"
                ));
            }
        }

        let result_json = serde_json::to_value(&result).unwrap();
        if serde_json::from_value::<SccmKeyExtractionResult>(result_json)
            .ok()
            .as_ref()
            != Some(&result)
        {
            mismatches.push(format!(
                "extract_keys emitted a result that does not round trip for {label}"
            ));
        }

        // An out-of-bound candidate must stay visible as a gap rather than
        // disappear, exactly as a candidate that fails to normalize does.
        if !result.gaps.iter().any(|gap| {
            gap.kind == SccmExtractionGapKind::MalformedCandidate
                && gap.candidate_raw.as_deref() == Some(raw.as_str())
        }) {
            mismatches.push(format!(
                "extract_keys dropped the out-of-bound candidate for {label}"
            ));
        }
    }

    assert!(mismatches.is_empty(), "{mismatches:#?}");
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
fn microsecond_precision_tail_is_not_read_as_a_source_offset() {
    // A six-digit unsigned tail is ambiguous: `%03u%d` would read it as three
    // millisecond digits plus a positive offset, and .NET microsecond
    // precision writes six fractional digits. 456 is not a real UTC offset
    // (it is neither within UTC-14..UTC+14 as a quarter-hour value nor a
    // shape `%d` emits), so the tail stays fractional and the record is not
    // promoted to UTC-normalized ordering.
    let text = r#"<![LOG[Microsecond precision]LOG]!><time="10:00:00.123456" date="07-30-2026" component="PolicyAgent" context="" type="1" thread="42" file="policyagent.cpp">"#;
    let (entries, errors) =
        cmtraceopen_parser::parser::ccm::parse_content(text, "PolicyAgent.log", None);
    let evidence = normalize_ccm_artifact(client_policy_artifact(), text);

    assert_eq!(errors, 0);
    assert_eq!(evidence.len(), 1);
    assert_eq!(
        evidence[0].timestamp.original_display.as_deref(),
        Some("07-30-2026 10:00:00.123456")
    );
    assert_eq!(evidence[0].timestamp.offset_minutes, None);
    assert_eq!(
        evidence[0].timestamp.ordering_state,
        SccmTimeOrderingState::OffsetMissing
    );
    assert_eq!(evidence[0].timestamp.utc_millis, None);

    // The public LogEntry still carries the pre-spine greedy projection,
    // which assigns the final digit to the offset. That divergence is
    // deliberate compatibility, not a second reading of the grammar.
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].timezone_offset, Some(6));
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
fn evidence_public_message_projection_redacts_provider_handles_in_all_positions() {
    let cases = [
        (
            "QueryHandle=SELECT * FROM SMS_R_System; status=71",
            "SELECT * FROM SMS_R_System",
            Some("status=71"),
        ),
        (
            "phase=receive; QueryHandle:/AdminService/v1.0/device; status=72",
            "/AdminService/v1.0/device",
            Some("status=72"),
        ),
        (
            r#"phase=receive; status=73; "QueryHandle"="opaque private query""#,
            "opaque private query",
            None,
        ),
        (
            "CallerHandle=opaque-private-caller; status=74",
            "opaque-private-caller",
            Some("status=74"),
        ),
        (
            r#"phase=receive; CallerHandle:"opaque private caller"; status=75"#,
            "opaque private caller",
            Some("status=75"),
        ),
        (
            r#"phase=receive; status=76; "CallerHandle"="private-caller-tail""#,
            "private-caller-tail",
            None,
        ),
        (
            "Authorization=Bearer private-auth-start; status=77",
            "private-auth-start",
            Some("status=77"),
        ),
        (
            "phase=receive; Authorization: Custom private-auth-middle; status=78",
            "private-auth-middle",
            Some("status=78"),
        ),
        (
            r#"phase=receive; status=79; "Authorization"="private-auth-tail""#,
            "private-auth-tail",
            None,
        ),
        (
            "AuthorizationHeader=Custom private-credential-value; status=81",
            "private-credential-value",
            Some("status=81"),
        ),
        (
            "AuthorizationToken=private-auth-token-value; status=82",
            "private-auth-token-value",
            Some("status=82"),
        ),
        (
            "QueryHandle=SELECT 1; DROP TABLE private_object; status=80",
            "DROP TABLE private_object",
            Some("status=80"),
        ),
    ];

    for (raw_message, sensitive, safe_tail) in cases {
        let text = format!(
            r#"<![LOG[{raw_message}]LOG]!><time="10:00:00.000-240" date="07-30-2026" component="PolicyAgent" context="" type="1" thread="42" file="policyagent.cpp">"#
        );
        let evidence = normalize_ccm_artifact(client_policy_artifact(), &text);
        let message = &evidence[0].message;
        let json = serde_json::to_string(&evidence).unwrap();

        assert!(
            !message.contains(sensitive),
            "{sensitive} leaked from {raw_message}"
        );
        assert_public_json_omits(&json, sensitive);
        assert!(
            message.contains("[redacted:sccm-public-message-v1]"),
            "{raw_message} was not classified as sensitive"
        );
        if let Some(safe_tail) = safe_tail {
            assert!(
                message.contains(safe_tail),
                "{safe_tail} was swallowed for {raw_message}"
            );
        }
    }
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
fn evidence_public_message_projection_redacts_path_adjacent_windows_identities() {
    let cases: [(&str, &[&str]); 3] = [
        (
            r"Caller LAB\SyntheticUser\subdirectory",
            &["Caller", "subdirectory"],
        ),
        (
            r"Profile C:\Users\LAB\SyntheticUser\profile.dat",
            &[r"C:\Users\", "profile.dat"],
        ),
        (
            r"Home \\server\users\LAB\SyntheticUser\cache",
            &[r"\\server\users\", "cache"],
        ),
    ];
    let mut violations = Vec::new();

    for (raw_message, safe_fragments) in cases {
        let text = format!(
            r#"<![LOG[{raw_message}]LOG]!><time="10:00:00.000-240" date="07-30-2026" component="PolicyAgent" context="" type="1" thread="42" file="policyagent.cpp">"#
        );
        let first = normalize_ccm_artifact(client_policy_artifact(), &text);
        let second = normalize_ccm_artifact(client_policy_artifact(), &text);
        let message = &first[0].message;
        let json = serde_json::to_string(&first).unwrap();

        assert_eq!(first, second, "{raw_message}");
        if message.contains(r"LAB\SyntheticUser")
            || public_json_contains_sensitive(&json, r"LAB\SyntheticUser")
        {
            violations.push(format!("identity leaked: {raw_message}"));
        }
        if !message.contains("[redacted:sccm-public-message-v1]") {
            violations.push(format!("identity was not classified: {raw_message}"));
        }
        for safe in safe_fragments {
            if !message.contains(safe) {
                violations.push(format!("{safe} was swallowed: {raw_message}"));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "path-adjacent identity projection violations: {violations:#?}"
    );
}

#[test]
fn evidence_public_projection_redacts_identity_on_every_string_surface() {
    let raw_message = r#"Profile C:\Profiles\LAB\SyntheticUser\profile.dat; Home \\server\home\LAB\SyntheticHomeUser\cache; Local C:\Profiles\.\LocalUser\profile.dat; account={"domain":"LAB","accountName":"SyntheticJsonUser"}; sam={"domain":"LAB","samAccountName":"SyntheticSamUser"}; localUser=LocalStructuredUser; status=71"#;
    let text = format!(
        r#"<![LOG[{raw_message}]LOG]!><time="10:00:00.000-240" date="07-30-2026" component="LAB\ComponentUser" context="" type="1" thread="42" file="LAB\FileUser">"#
    );
    let first = normalize_ccm_artifact(client_policy_artifact(), &text);
    let second = normalize_ccm_artifact(client_policy_artifact(), &text);
    let json = serde_json::to_string(&first).unwrap();
    let evidence = &first[0];

    assert_eq!(first, second);
    for sensitive in [
        "SyntheticUser",
        "SyntheticHomeUser",
        "LocalUser",
        "SyntheticJsonUser",
        "SyntheticSamUser",
        "LocalStructuredUser",
        "ComponentUser",
        "FileUser",
    ] {
        assert_public_json_omits(&json, sensitive);
    }
    assert!(evidence.message.contains("status=71"));
    assert!(evidence
        .message
        .contains("[redacted:sccm-public-message-v1]"));
    assert!(
        evidence
            .component
            .as_deref()
            .is_some_and(|value| value.contains("[redacted:sccm-public-message-v1]")),
        "component identity was not classified"
    );
    assert!(
        evidence
            .ccm_source_file
            .as_deref()
            .is_some_and(|value| value.contains("[redacted:sccm-public-message-v1]")),
        "CCM source-file identity was not classified"
    );
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
            "SMSdpmon.log",
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
            SccmRole::AdminService,
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
            "ccmsetup.log",
            SccmRole::Client,
            "ccmSetup",
            SccmArtifactFamily::ClientSetup,
            true,
            true,
        ),
        (
            "client.msi.log",
            SccmRole::Client,
            "clientMsi",
            SccmArtifactFamily::ClientSetup,
            false,
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
            "CIAgent.log",
            SccmRole::Client,
            "ciAgent",
            SccmArtifactFamily::ClientPolicy,
            true,
            true,
        ),
        (
            "CIDownloader.log",
            SccmRole::Client,
            "ciDownloader",
            SccmArtifactFamily::ClientPolicy,
            true,
            true,
        ),
        (
            "StateMessage.log",
            SccmRole::Client,
            "stateMessage",
            SccmArtifactFamily::ClientPolicy,
            true,
            true,
        ),
        (
            "StatusAgent.log",
            SccmRole::Client,
            "statusAgent",
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
            "ExecMgr.log",
            SccmRole::Client,
            "execMgr",
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
            "ServiceWindowManager.log",
            SccmRole::Client,
            "serviceWindowManager",
            SccmArtifactFamily::ClientUpdates,
            true,
            true,
        ),
        (
            "RebootCoordinator.log",
            SccmRole::Client,
            "rebootCoordinator",
            SccmArtifactFamily::ClientUpdates,
            true,
            true,
        ),
        (
            "CBS.log",
            SccmRole::Client,
            "componentBasedServicing",
            SccmArtifactFamily::ClientUpdates,
            false,
            true,
        ),
        (
            "ReportingEvents.log",
            SccmRole::Client,
            "reportingEvents",
            SccmArtifactFamily::ClientUpdates,
            false,
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
            "InventoryAgent.log",
            SccmRole::Client,
            "inventoryAgent",
            SccmArtifactFamily::ClientInventory,
            true,
            true,
        ),
        (
            "InventoryProvider.log",
            SccmRole::Client,
            "inventoryProvider",
            SccmArtifactFamily::ClientInventory,
            true,
            true,
        ),
        (
            "InventoryAgentProvider.log",
            SccmRole::Client,
            "inventoryAgentProvider",
            SccmArtifactFamily::ClientInventory,
            true,
            true,
        ),
        (
            "CITaskMgr.log",
            SccmRole::Client,
            "ciTaskMgr",
            SccmArtifactFamily::ClientCompliance,
            true,
            true,
        ),
        (
            "DCMAgent.log",
            SccmRole::Client,
            "dcmAgent",
            SccmArtifactFamily::ClientCompliance,
            true,
            true,
        ),
        (
            "DCMReporting.log",
            SccmRole::Client,
            "dcmReporting",
            SccmArtifactFamily::ClientCompliance,
            true,
            true,
        ),
        (
            "SWMTRReportGen.log",
            SccmRole::Client,
            "swmtrReportGen",
            SccmArtifactFamily::ClientMetering,
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
            SccmRole::SiteServer,
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
            "SMSdpmon.log",
            SccmRole::DistributionPoint,
            "smsDpmon",
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
            SccmRole::AdminService,
            "adminService",
            SccmArtifactFamily::AdminService,
            true,
            true,
        ),
    ]
}
