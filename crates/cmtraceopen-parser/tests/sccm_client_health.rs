use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use cmtraceopen_parser::sccm::{
    analyze_client_health, normalize_ccm_artifact, SccmArtifact, SccmConfidence, SccmCoverageState,
    SccmFindingClass, SccmHealthPhase, SccmNormalizedBundle, SccmRole, SccmRotation,
    SccmTimeOrderingState,
};
use serde::Deserialize;
use serde_json::{json, Value};

const FIXTURE_ROOT: &str = "tests/fixtures/sccm/client/health";
const SCENARIOS: &[&str] = &[
    "success",
    "setup-failure",
    "identity-failure",
    "no-site-or-mp",
    "transport-failure",
    "contradictory",
    "rotation-boundary",
    "malformed",
    "incomplete",
];

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FixtureManifest {
    artifacts: Vec<FixtureArtifact>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FixtureArtifact {
    artifact_id: String,
    role: String,
    capture_state: String,
    encoding: Option<String>,
    original_basename: String,
    sanitized_source_path: Option<String>,
    rotation: FixtureRotation,
    source_version: Option<String>,
    captured_utc: Option<String>,
    relative_path: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FixtureRotation {
    kind: String,
    value: Option<Value>,
}

fn fixture_directory(scenario: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(FIXTURE_ROOT)
        .join(scenario)
}

fn load_json(path: &Path) -> Value {
    serde_json::from_str(&fs::read_to_string(path).expect("fixture JSON must be readable"))
        .expect("fixture JSON must be valid")
}

fn coverage_state(value: &str) -> SccmCoverageState {
    match value {
        "captured" => SccmCoverageState::Captured,
        "partial" => SccmCoverageState::Partial,
        "absent" => SccmCoverageState::Absent,
        "accessDenied" => SccmCoverageState::AccessDenied,
        "capped" => SccmCoverageState::Capped,
        "skipped" => SccmCoverageState::Skipped,
        "unsupported" => SccmCoverageState::Unsupported,
        "parseFailed" => SccmCoverageState::ParseFailed,
        other => panic!("unsupported fixture coverage state {other}"),
    }
}

fn rotation(value: &FixtureRotation) -> SccmRotation {
    match value.kind.as_str() {
        "current" => SccmRotation::Current,
        "lo" | "loUnderscore" => SccmRotation::LoUnderscore,
        "numbered" => SccmRotation::Numbered(
            value
                .value
                .as_ref()
                .and_then(Value::as_u64)
                .and_then(|number| u32::try_from(number).ok())
                .expect("numbered rotation must contain a u32"),
        ),
        "timestamped" => SccmRotation::Timestamped(
            value
                .value
                .as_ref()
                .and_then(Value::as_str)
                .expect("timestamped rotation must contain a string")
                .to_owned(),
        ),
        other => panic!("unsupported fixture rotation {other}"),
    }
}

fn load_bundle(scenario: &str) -> SccmNormalizedBundle {
    let directory = fixture_directory(scenario);
    let manifest: FixtureManifest =
        serde_json::from_value(load_json(&directory.join("manifest.json")))
            .expect("fixture manifest must match its declared contract");

    let mut artifacts = Vec::new();
    let mut evidence = Vec::new();
    for source in manifest.artifacts {
        assert_eq!(source.role, "client", "health fixtures must be client-only");
        let artifact = SccmArtifact {
            artifact_id: source.artifact_id,
            display_name: source.original_basename,
            original_path: source.sanitized_source_path,
            host: None,
            role: SccmRole::Client,
            configmgr_version: source.source_version,
            collected_at_utc: source.captured_utc,
            rotation: rotation(&source.rotation),
            coverage: coverage_state(&source.capture_state),
            encoding: source.encoding,
        };

        if let Some(relative_path) = source.relative_path {
            let content = fs::read_to_string(directory.join(relative_path))
                .expect("captured health evidence must be readable UTF-8");
            evidence.extend(normalize_ccm_artifact(artifact.clone(), &content));
        }
        artifacts.push(artifact);
    }

    artifacts.sort_by(|left, right| left.artifact_id.cmp(&right.artifact_id));
    evidence.sort_by(|left, right| left.evidence_id.cmp(&right.evidence_id));
    SccmNormalizedBundle {
        artifacts,
        evidence,
    }
}

fn expected_finding_projection(expected: &Value) -> Vec<Value> {
    expected["findings"]
        .as_array()
        .expect("expected findings")
        .iter()
        .map(|finding| {
            json!({
                "findingId": finding["findingId"],
                "healthPhase": finding["phase"],
                "class": finding["class"],
                "confidence": finding["confidence"],
                "coverageGapArtifactIds": finding["coverageGapArtifactIds"],
                "nextArtifactLogicalId": finding["nextArtifacts"]
                    .as_array()
                    .and_then(|requests| requests.first())
                    .map(|request| request["logicalArtifactId"].clone())
                    .unwrap_or(Value::Null),
            })
        })
        .collect()
}

fn source_group_for_request(logical_id: &str) -> Option<&'static str> {
    match logical_id {
        "ccmSetup" => Some("client-ccmsetup"),
        "ccmEval" | "ccmExec" | "ccmRestart" => Some("client-evaluation"),
        "clientIdManagerStartup" => Some("client-identity"),
        "clientLocation" | "locationServices" | "ccmMessaging" => Some("client-location"),
        _ => None,
    }
}

fn actual_finding_projection(analysis: &Value) -> Vec<Value> {
    analysis["findings"]
        .as_array()
        .expect("analysis findings")
        .iter()
        .map(|finding| {
            let next_group = finding["nextArtifacts"]
                .as_array()
                .and_then(|requests| requests.first())
                .and_then(|request| request["logicalId"].as_str())
                .and_then(source_group_for_request);
            let mut gap_ids = finding["coverageGaps"]
                .as_array()
                .expect("coverage gaps")
                .iter()
                .map(|gap| gap["artifactId"].clone())
                .collect::<Vec<_>>();
            gap_ids.sort_by_key(Value::to_string);
            json!({
                "findingId": finding["findingId"],
                "healthPhase": finding["healthPhase"],
                "class": finding["class"],
                "confidence": finding["confidence"],
                "coverageGapArtifactIds": gap_ids,
                "nextArtifactLogicalId": next_group,
            })
        })
        .collect()
}

fn reference_is_within_expected_ranges(reference: &Value, expected_ranges: &[Value]) -> bool {
    let Some(artifact_id) = reference["artifactId"].as_str() else {
        return false;
    };
    let Some(line_start) = reference["lineStart"].as_u64() else {
        return false;
    };
    let Some(line_end) = reference["lineEnd"].as_u64() else {
        return false;
    };

    expected_ranges.iter().any(|expected_reference| {
        expected_reference["artifactId"].as_str() == Some(artifact_id)
            && expected_reference["lineStart"]
                .as_u64()
                .is_some_and(|start| start <= line_start)
            && expected_reference["lineEnd"]
                .as_u64()
                .is_some_and(|end| line_end <= end)
    })
}

fn assert_finding_evidence_matches_contract(scenario: &str, analysis: &Value, expected: &Value) {
    let expected_by_id = expected["findings"]
        .as_array()
        .expect("expected findings")
        .iter()
        .map(|finding| {
            (
                finding["findingId"].as_str().expect("expected finding ID"),
                finding,
            )
        })
        .collect::<BTreeMap<_, _>>();

    for finding in analysis["findings"].as_array().expect("analysis findings") {
        let finding_id = finding["findingId"].as_str().expect("finding ID");
        let expected_finding = expected_by_id
            .get(finding_id)
            .unwrap_or_else(|| panic!("{scenario}: unexpected finding {finding_id}"));
        let expected_ranges = expected_finding["fixtureEvidence"]
            .as_array()
            .expect("expected evidence");
        let evidence = finding["evidence"].as_array().expect("finding evidence");
        assert!(
            evidence
                .iter()
                .all(|reference| reference_is_within_expected_ranges(reference, expected_ranges)),
            "{scenario}: {finding_id} emitted uncited evidence"
        );
        for expected_reference in expected_ranges {
            assert!(
                evidence.iter().any(|reference| {
                    reference["artifactId"] == expected_reference["artifactId"]
                }),
                "{scenario}: {finding_id} omitted expected evidence"
            );
        }

        let terminal = finding["terminalEvidence"]
            .as_array()
            .expect("terminal evidence");
        if finding["class"] == "confirmedFailure" && finding["confidence"] == "high" {
            assert!(
                !terminal.is_empty(),
                "{scenario}: high failure needs terminal evidence"
            );
        }
        for terminal_reference in terminal {
            assert!(
                evidence.contains(&terminal_reference["reference"]),
                "{scenario}: terminal evidence must also be cited"
            );
        }
    }
}

#[test]
fn health_reducer_matches_the_frozen_phase_and_coverage_contracts() {
    for scenario in SCENARIOS {
        let expected = load_json(&fixture_directory(scenario).join("expected.json"));
        let analysis = serde_json::to_value(analyze_client_health(&load_bundle(scenario)))
            .expect("health analysis must serialize");

        assert_eq!(analysis["schemaVersion"], 1, "{scenario}");
        assert_eq!(analysis["workflow"], "health", "{scenario}");
        assert_eq!(
            analysis["lastSuccessfulPhase"], expected["lastSuccessfulPhase"],
            "{scenario}"
        );
        assert_eq!(
            actual_finding_projection(&analysis),
            expected_finding_projection(&expected),
            "{scenario}"
        );
        assert_finding_evidence_matches_contract(scenario, &analysis, &expected);

        let serialized = serde_json::to_string(&analysis).expect("analysis JSON");
        for prohibited in [
            "SYNTHETIC FIXTURE",
            "synthetic.cc",
            "SYNTHETIC://",
            "executionContext",
            "root cause",
            "server-side failure",
        ] {
            assert!(
                !serialized.contains(prohibited),
                "{scenario}: public analysis leaked or claimed {prohibited}"
            );
        }
    }
}

#[test]
fn health_analysis_is_deterministic_under_bundle_reordering() {
    for scenario in SCENARIOS {
        let bundle = load_bundle(scenario);
        let expected =
            serde_json::to_string(&analyze_client_health(&bundle)).expect("analysis JSON");

        let mut reordered = bundle.clone();
        reordered.artifacts.reverse();
        reordered.evidence.reverse();
        let actual =
            serde_json::to_string(&analyze_client_health(&reordered)).expect("analysis JSON");
        assert_eq!(actual, expected, "{scenario}");
    }
}

fn has_high_confirmed_failure(bundle: &SccmNormalizedBundle) -> bool {
    analyze_client_health(bundle)
        .findings
        .iter()
        .any(|finding| {
            finding.finding.class == SccmFindingClass::ConfirmedFailure
                && finding.finding.confidence == SccmConfidence::High
        })
}

fn replace_first_message(bundle: &mut SccmNormalizedBundle, from: &str, to: &str) {
    let evidence = bundle
        .evidence
        .iter_mut()
        .find(|evidence| evidence.message.contains(from))
        .unwrap_or_else(|| panic!("fixture must contain {from}"));
    evidence.message = evidence.message.replacen(from, to, 1);
}

#[test]
fn health_adversarial_inputs_cannot_create_terminal_or_success_outcomes() {
    let mut accepted = Vec::new();

    let mut zero_setup_error = load_bundle("setup-failure");
    replace_first_message(
        &mut zero_setup_error,
        "error=0x80070005",
        "error=0x00000000",
    );
    if has_high_confirmed_failure(&zero_setup_error) {
        accepted.push("zero setup error accepted as terminal");
    }

    let mut zero_transport_status = load_bundle("success");
    replace_first_message(&mut zero_transport_status, "status=200", "status=0");
    if analyze_client_health(&zero_transport_status).last_successful_phase
        == Some(SccmHealthPhase::Transport)
    {
        accepted.push("zero transport status accepted as success");
    }

    let mut mismatched_client = load_bundle("success");
    replace_first_message(
        &mut mismatched_client,
        "Client service evaluation succeeded clientGuid=11111111-1111-1111-1111-111111111111",
        "Client service evaluation succeeded clientGuid=99999999-9999-9999-9999-999999999999",
    );
    if analyze_client_health(&mismatched_client).last_successful_phase
        != Some(SccmHealthPhase::Setup)
    {
        accepted.push("mismatched client GUID advanced the phase chain");
    }

    let mut unsafe_host = load_bundle("success");
    for evidence in &mut unsafe_host.evidence {
        evidence.message = evidence
            .message
            .replace("mp-lab.contoso.invalid", "user@real.example");
    }
    if analyze_client_health(&unsafe_host).last_successful_phase
        >= Some(SccmHealthPhase::ManagementPoint)
    {
        accepted.push("unsafe raw host advanced management-point evidence");
    }

    let mut wrong_source = load_bundle("success");
    let evaluation_artifact = wrong_source
        .artifacts
        .iter_mut()
        .find(|artifact| artifact.display_name.eq_ignore_ascii_case("CcmEval.log"))
        .expect("success fixture evaluation artifact");
    evaluation_artifact.display_name = "LocationServices.log".to_owned();
    if analyze_client_health(&wrong_source).last_successful_phase != Some(SccmHealthPhase::Setup) {
        accepted.push("source-phase mismatch advanced service evidence");
    }

    let mut unknown_profile = load_bundle("identity-failure");
    for artifact in &mut unknown_profile.artifacts {
        artifact.configmgr_version = Some("5.00.UNKNOWN.0000".to_owned());
    }
    if has_high_confirmed_failure(&unknown_profile) {
        accepted.push("unknown extraction profile created high failure");
    }

    let mut missing_profile = load_bundle("identity-failure");
    for artifact in &mut missing_profile.artifacts {
        artifact.configmgr_version = None;
    }
    if has_high_confirmed_failure(&missing_profile) {
        accepted.push("missing extraction profile created high failure");
    }

    let mut access_denied_identity = load_bundle("identity-failure");
    let identity_id = access_denied_identity
        .artifacts
        .iter_mut()
        .find(|artifact| {
            artifact
                .display_name
                .eq_ignore_ascii_case("ClientIDManagerStartup.log")
        })
        .map(|artifact| {
            artifact.coverage = SccmCoverageState::AccessDenied;
            artifact.artifact_id.clone()
        })
        .expect("identity artifact");
    access_denied_identity
        .evidence
        .retain(|evidence| evidence.reference.artifact_id != identity_id);
    if has_high_confirmed_failure(&access_denied_identity) {
        accepted.push("access-denied source created high failure");
    }

    let mut capped_success = load_bundle("success");
    for artifact in &mut capped_success.artifacts {
        artifact.coverage = SccmCoverageState::Capped;
    }
    if analyze_client_health(&capped_success)
        .last_successful_phase
        .is_some()
    {
        accepted.push("capped sources created a successful phase");
    }

    for coverage in [
        SccmCoverageState::Partial,
        SccmCoverageState::Skipped,
        SccmCoverageState::Unsupported,
        SccmCoverageState::ParseFailed,
    ] {
        let mut incomplete_coverage = load_bundle("success");
        for artifact in &mut incomplete_coverage.artifacts {
            artifact.coverage = coverage.clone();
        }
        if analyze_client_health(&incomplete_coverage)
            .last_successful_phase
            .is_some()
        {
            accepted.push("non-captured coverage created a successful phase");
        }
    }

    let mut mismatched_request = load_bundle("success");
    replace_first_message(
        &mut mismatched_request,
        "Transport response completed requestId=REQ-TEST-001",
        "Transport response completed requestId=REQ-TEST-OTHER",
    );
    if analyze_client_health(&mismatched_request).last_successful_phase
        == Some(SccmHealthPhase::Transport)
    {
        accepted.push("mismatched request key created transport success");
    }

    let mut unsafe_request = load_bundle("success");
    for evidence in &mut unsafe_request.evidence {
        evidence.message = evidence.message.replace("REQ-TEST-001", "REQ-REAL-001");
    }
    if analyze_client_health(&unsafe_request).last_successful_phase
        == Some(SccmHealthPhase::Transport)
    {
        accepted.push("out-of-profile request key created transport success");
    }

    assert!(
        accepted.is_empty(),
        "health reducer accepted adversarial outcomes: {accepted:#?}"
    );
}

#[test]
fn health_terminal_chronology_and_recovery_are_source_local_and_ordered() {
    let mut accepted = Vec::new();

    let mut time_inverted_identity = load_bundle("identity-failure");
    for evidence in &mut time_inverted_identity.evidence {
        evidence.timestamp.ordering_state = SccmTimeOrderingState::NormalizedUtc;
        evidence.timestamp.utc_millis = Some(
            if evidence.reference.artifact_id.contains("identity-current") {
                1
            } else if evidence
                .reference
                .artifact_id
                .contains("evaluation-current")
            {
                20
            } else {
                10
            },
        );
    }
    if has_high_confirmed_failure(&time_inverted_identity) {
        accepted.push("cross-artifact time inversion retained high identity failure");
    }

    let mut invalid_offset_identity = load_bundle("identity-failure");
    for evidence in &mut invalid_offset_identity.evidence {
        if evidence.reference.artifact_id.contains("identity-current") {
            evidence.timestamp.ordering_state = SccmTimeOrderingState::OffsetInvalid;
            evidence.timestamp.utc_millis = None;
        }
    }
    if has_high_confirmed_failure(&invalid_offset_identity) {
        accepted.push("invalid timestamp offset retained high identity failure");
    }

    let mut failure_before_start = load_bundle("transport-failure");
    let location_id = failure_before_start
        .artifacts
        .iter()
        .find(|artifact| artifact.display_name == "LocationServices.log")
        .expect("location artifact")
        .artifact_id
        .clone();
    for evidence in &mut failure_before_start.evidence {
        if evidence.reference.artifact_id == location_id
            && evidence.message.contains("Transport terminal failure")
        {
            evidence.reference.line_start = Some(2);
            evidence.reference.line_end = Some(2);
            evidence.reference.entry_id = "terminal-before-start".to_owned();
        }
    }
    if has_high_confirmed_failure(&failure_before_start) {
        accepted.push("terminal transport evidence before request start retained high failure");
    }

    let mut later_failure = load_bundle("transport-failure");
    let failure_index = later_failure
        .evidence
        .iter()
        .position(|evidence| evidence.message.contains("Transport terminal failure"))
        .expect("transport failure evidence");
    later_failure.evidence[failure_index].reference.line_start = Some(5);
    later_failure.evidence[failure_index].reference.line_end = Some(5);
    later_failure.evidence[failure_index].reference.entry_id = "later-terminal".to_owned();
    let mut earlier_response = later_failure.evidence[failure_index].clone();
    earlier_response.message = earlier_response
        .message
        .replace("Transport terminal failure", "Transport response completed")
        .replace("error=0x80072EFD", "status=200");
    earlier_response.reference.line_start = Some(4);
    earlier_response.reference.line_end = Some(4);
    earlier_response.reference.entry_id = "earlier-success".to_owned();
    later_failure.evidence.push(earlier_response);
    let later_failure_analysis = analyze_client_health(&later_failure);
    if later_failure_analysis.last_successful_phase == Some(SccmHealthPhase::Transport)
        || !has_high_confirmed_failure(&later_failure)
    {
        accepted.push("earlier response suppressed later same-key terminal failure");
    }

    let mut later_recovery = load_bundle("transport-failure");
    let recovery_index = later_recovery
        .evidence
        .iter()
        .position(|evidence| evidence.message.contains("Transport terminal failure"))
        .expect("transport failure evidence");
    let mut response = later_recovery.evidence[recovery_index].clone();
    response.message = response
        .message
        .replace("Transport terminal failure", "Transport response completed")
        .replace("error=0x80072EFD", "status=200");
    response.reference.line_start = Some(5);
    response.reference.line_end = Some(5);
    response.reference.entry_id = "later-recovery".to_owned();
    later_recovery.evidence.push(response);
    let recovery_analysis = analyze_client_health(&later_recovery);
    if recovery_analysis.last_successful_phase != Some(SccmHealthPhase::Transport)
        || has_high_confirmed_failure(&later_recovery)
    {
        accepted.push("later same-key transport response did not prove source-local recovery");
    }

    assert!(
        accepted.is_empty(),
        "health chronology accepted adversarial outcomes: {accepted:#?}"
    );
}

#[test]
fn health_same_key_setup_recovery_does_not_cross_bootstrap_identity() {
    let mut recovered = load_bundle("setup-failure");
    let mut recovery = recovered
        .evidence
        .first()
        .expect("setup failure evidence")
        .clone();
    recovery.message = "[sccm-public-message-v1] Bootstrap completed bootstrapId=BOOT-TEST-010 clientGuid=AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA".to_owned();
    recovery.reference.line_start = Some(2);
    recovery.reference.line_end = Some(2);
    recovery.reference.entry_id = "same-bootstrap-recovery".to_owned();
    recovered.evidence.push(recovery);
    let recovered_analysis = analyze_client_health(&recovered);
    assert_eq!(
        recovered_analysis.last_successful_phase,
        Some(SccmHealthPhase::Setup)
    );
    assert!(!has_high_confirmed_failure(&recovered));

    let mut different_bootstrap = load_bundle("setup-failure");
    let mut unrelated_success = different_bootstrap
        .evidence
        .first()
        .expect("setup failure evidence")
        .clone();
    unrelated_success.message = "[sccm-public-message-v1] Bootstrap completed bootstrapId=BOOT-TEST-OTHER clientGuid=AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA".to_owned();
    unrelated_success.reference.line_start = Some(2);
    unrelated_success.reference.line_end = Some(2);
    unrelated_success.reference.entry_id = "different-bootstrap-success".to_owned();
    different_bootstrap.evidence.push(unrelated_success);
    let unrelated_analysis = analyze_client_health(&different_bootstrap);
    assert_eq!(unrelated_analysis.last_successful_phase, None);
    assert_eq!(
        unrelated_analysis.findings[0].finding.finding_id,
        "health-setup-contradictory"
    );
}

#[test]
fn health_public_output_rejects_unsafe_artifact_provenance() {
    let mut bundle = load_bundle("setup-failure");
    let unsafe_id = r"C:\Users\Person\ccmsetup.log";
    bundle.artifacts[0].artifact_id = unsafe_id.to_owned();
    bundle.artifacts[0].original_path = Some(r"C:\Users\Person\ccmsetup.log".to_owned());
    bundle.artifacts[0].host = Some("private-host.example".to_owned());
    bundle.evidence[0].reference.artifact_id = unsafe_id.to_owned();
    bundle.evidence[0].reference.entry_id = "unsafe-provenance".to_owned();

    let serialized =
        serde_json::to_string(&analyze_client_health(&bundle)).expect("health analysis JSON");
    for prohibited in [
        "Users",
        "Person",
        "private-host.example",
        "ccmsetup.log",
        "BOOT-TEST-010",
        "0x80070005",
    ] {
        assert!(
            !serialized.contains(prohibited),
            "public health analysis leaked {prohibited}: {serialized}"
        );
    }

    let success_serialized = serde_json::to_string(&analyze_client_health(&load_bundle("success")))
        .expect("success analysis JSON");
    for prohibited in [
        "mp-lab.contoso.invalid",
        "REQ-TEST-001",
        "11111111-1111-1111-1111-111111111111",
        "Bootstrap completed",
        "Transport response completed",
    ] {
        assert!(
            !success_serialized.contains(prohibited),
            "public success analysis leaked {prohibited}: {success_serialized}"
        );
    }
}
