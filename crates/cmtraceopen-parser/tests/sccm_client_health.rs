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
            let mut gap_ids = finding["coverageGapArtifactIds"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            gap_ids.sort_by_key(Value::to_string);
            json!({
                "findingId": finding["findingId"],
                "healthPhase": finding["phase"],
                "class": finding["class"],
                "confidence": finding["confidence"],
                "coverageGapArtifactIds": gap_ids,
                "nextArtifactLogicalId": finding["nextArtifacts"]
                    .as_array()
                    .and_then(|requests| requests.first())
                    .map(|request| request["logicalArtifactId"].clone())
                    .unwrap_or(Value::Null),
            })
        })
        .collect()
}

fn source_group_for_request(logical_id: &str) -> &'static str {
    match logical_id {
        "ccmSetup" => "client-ccmsetup",
        "ccmEval" | "ccmExec" | "ccmRestart" => "client-evaluation",
        "clientIdManagerStartup" => "client-identity",
        "clientLocation" | "locationServices" | "ccmMessaging" => "client-location",
        other => panic!("unmapped health request logical ID {other}"),
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
                .map(source_group_for_request);
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
                        && reference_is_within_expected_ranges(
                            reference,
                            std::slice::from_ref(expected_reference),
                        )
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
fn health_duplicate_artifact_ids_fail_closed_without_order_authority() {
    let mut forward = load_bundle("success");
    let mut duplicate = forward
        .artifacts
        .iter()
        .find(|artifact| artifact.display_name.eq_ignore_ascii_case("CcmEval.log"))
        .expect("success fixture evaluation artifact")
        .clone();
    duplicate.coverage = SccmCoverageState::AccessDenied;
    forward.artifacts.push(duplicate);

    let mut reverse = forward.clone();
    reverse.artifacts.reverse();

    let forward_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        analyze_client_health(&forward)
    }));
    let reverse_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        analyze_client_health(&reverse)
    }));
    assert!(
        forward_result.is_ok() && reverse_result.is_ok(),
        "duplicate public artifact identities must fail closed without panicking"
    );

    let forward_analysis = forward_result.expect("forward duplicate analysis");
    let reverse_analysis = reverse_result.expect("reverse duplicate analysis");
    assert_eq!(forward_analysis.last_successful_phase, None);
    assert_eq!(forward_analysis.findings.len(), 1);
    assert_eq!(
        forward_analysis.findings[0].finding.finding_id,
        "health-artifact-identity-collision"
    );
    assert_eq!(
        forward_analysis.findings[0].finding.class,
        SccmFindingClass::InsufficientEvidence
    );
    assert_eq!(
        serde_json::to_string(&forward_analysis).expect("forward duplicate JSON"),
        serde_json::to_string(&reverse_analysis).expect("reverse duplicate JSON"),
        "artifact vector order must not select an authority for a duplicate identity"
    );
}

#[test]
fn health_server_role_identity_collisions_do_not_change_client_analysis() {
    let baseline = load_bundle("success");
    let expected = serde_json::to_string(&analyze_client_health(&baseline))
        .expect("baseline client analysis JSON");
    let mut bundle = baseline.clone();

    let mut server_artifact = baseline
        .artifacts
        .first()
        .expect("success fixture artifact")
        .clone();
    server_artifact.artifact_id = "server-role-collision".to_owned();
    server_artifact.display_name = "MP_GetPolicy.log".to_owned();
    server_artifact.role = SccmRole::ManagementPoint;
    bundle.artifacts.push(server_artifact.clone());
    bundle.artifacts.push(server_artifact);

    let mut server_evidence = baseline
        .evidence
        .first()
        .expect("success fixture evidence")
        .clone();
    server_evidence.evidence_id = "evidence:server-role-collision".to_owned();
    server_evidence.reference.artifact_id = "server-role-collision".to_owned();
    server_evidence.reference.entry_id = "server-role-collision-entry".to_owned();
    server_evidence.role = SccmRole::ManagementPoint;
    bundle.evidence.push(server_evidence.clone());
    bundle.evidence.push(server_evidence);

    assert_eq!(
        serde_json::to_string(&analyze_client_health(&bundle))
            .expect("client analysis with unrelated server collisions"),
        expected,
        "server-role identity collisions are outside the client-health authority boundary"
    );
}

#[test]
fn health_cross_role_shared_artifact_id_cannot_select_an_order_authority() {
    let baseline = load_bundle("success");
    let expected = serde_json::to_string(&analyze_client_health(&baseline))
        .expect("baseline client analysis JSON");

    let mut forward = baseline.clone();
    let mut server_artifact = baseline
        .artifacts
        .iter()
        .find(|artifact| artifact.artifact_id == "health-success-ccmsetup-current")
        .expect("success fixture ccmsetup artifact")
        .clone();
    server_artifact.display_name = "MP_GetPolicy.log".to_owned();
    server_artifact.role = SccmRole::ManagementPoint;
    forward.artifacts.push(server_artifact);

    let mut reversed = forward.clone();
    reversed.artifacts.reverse();
    reversed.evidence.reverse();

    let forward_json = serde_json::to_string(&analyze_client_health(&forward))
        .expect("forward cross-role collision analysis JSON");
    let reversed_json = serde_json::to_string(&analyze_client_health(&reversed))
        .expect("reversed cross-role collision analysis JSON");
    assert_eq!(
        forward_json, reversed_json,
        "artifact vector order must not select an authority for a duplicate identity"
    );
    assert_eq!(
        forward_json, expected,
        "server-role artifacts reusing a client artifact id must stay invisible to admission"
    );
}

#[test]
fn health_equal_time_opposing_transport_outcomes_are_contradictory() {
    fn with_failure_artifact_id(artifact_id: &str) -> SccmNormalizedBundle {
        let mut bundle = load_bundle("success");
        let mut failure_artifact = bundle
            .artifacts
            .iter()
            .find(|artifact| artifact.display_name == "LocationServices.log")
            .expect("success fixture location artifact")
            .clone();
        failure_artifact.artifact_id = artifact_id.to_owned();
        failure_artifact.display_name = "CcmMessaging.log".to_owned();
        bundle.artifacts.push(failure_artifact);

        let mut failure = bundle
            .evidence
            .iter()
            .find(|evidence| evidence.message.contains("Transport response completed"))
            .expect("success fixture transport response")
            .clone();
        failure.evidence_id = format!("evidence:{artifact_id}:equal-time-failure");
        failure.reference.artifact_id = artifact_id.to_owned();
        failure.reference.entry_id = "equal-time-failure".to_owned();
        failure.reference.line_start = Some(1);
        failure.reference.line_end = Some(1);
        failure.message = failure
            .message
            .replace("Transport response completed", "Transport terminal failure")
            .replace("status=200", "error=0x80072EFD");
        bundle.evidence.push(failure);
        bundle
    }

    let failure_sorts_first = with_failure_artifact_id("aaa-health-equal-time-messaging");
    let failure_sorts_last = with_failure_artifact_id("zzz-health-equal-time-messaging");

    for bundle in [&failure_sorts_first, &failure_sorts_last] {
        let analysis = analyze_client_health(bundle);
        assert_eq!(
            analysis.last_successful_phase,
            Some(SccmHealthPhase::ManagementPoint)
        );
        assert_eq!(analysis.findings.len(), 1);
        assert_eq!(
            analysis.findings[0].finding.finding_id,
            "health-transport-contradictory"
        );
        assert_eq!(analysis.findings[0].finding.confidence, SccmConfidence::Low);
        assert!(!has_high_confirmed_failure(bundle));
    }
}

#[test]
fn health_guid_matching_is_case_insensitive() {
    let mut bundle = load_bundle("success");
    let original = "11111111-1111-1111-1111-111111111111";
    let lowercase = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    let uppercase = "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA";
    let original_occurrences = bundle
        .evidence
        .iter()
        .filter(|evidence| evidence.message.contains(original))
        .count();
    assert!(
        original_occurrences > 0,
        "success fixture must contain the original client GUID"
    );
    for evidence in &mut bundle.evidence {
        evidence.message = evidence.message.replace(original, lowercase);
    }
    assert!(
        bundle
            .evidence
            .iter()
            .all(|evidence| !evidence.message.contains(original)),
        "every original client GUID occurrence must be mutated"
    );
    let setup = bundle
        .evidence
        .iter_mut()
        .find(|evidence| evidence.message.contains("Bootstrap completed"))
        .expect("success fixture setup evidence");
    assert!(
        setup.message.contains(lowercase),
        "setup evidence must carry the lowercase mutation before case splitting"
    );
    setup.message = setup.message.replace(lowercase, uppercase);
    assert!(
        setup.message.contains(uppercase) && !setup.message.contains(lowercase),
        "setup evidence must carry only the uppercase client GUID mutation"
    );

    assert_eq!(
        analyze_client_health(&bundle).last_successful_phase,
        Some(SccmHealthPhase::Transport),
        "hex case must not split one validated client GUID"
    );
}

#[test]
fn health_same_guid_identity_success_recovers_prior_failure() {
    let mut bundle = load_bundle("identity-failure");
    let mut recovery = bundle
        .evidence
        .iter()
        .find(|evidence| evidence.message.contains("terminal failure clientGuid="))
        .expect("identity failure evidence")
        .clone();
    recovery.evidence_id = "evidence:health-identity-recovery".to_owned();
    recovery.reference.entry_id = "identity-recovery".to_owned();
    recovery.reference.line_start = Some(2);
    recovery.reference.line_end = Some(2);
    recovery.message = recovery
        .message
        .replace(
            "[redacted:sccm-public-message-v1] terminal failure",
            "[redacted:sccm-public-message-v1] succeeded",
        )
        .replace(" error=0x80004005", "");
    bundle.evidence.push(recovery);

    let analysis = analyze_client_health(&bundle);
    assert_eq!(
        analysis.last_successful_phase,
        Some(SccmHealthPhase::Identity)
    );
    assert!(!has_high_confirmed_failure(&bundle));
    assert!(analysis
        .findings
        .iter()
        .all(|finding| finding.finding.finding_id != "health-identity-terminal"));

    let mut different_guid = load_bundle("identity-failure");
    let mut unrelated_success = different_guid
        .evidence
        .iter()
        .find(|evidence| evidence.message.contains("terminal failure clientGuid="))
        .expect("identity failure evidence")
        .clone();
    unrelated_success.evidence_id = "evidence:health-unrelated-identity-success".to_owned();
    unrelated_success.reference.entry_id = "unrelated-identity-success".to_owned();
    unrelated_success.reference.line_start = Some(2);
    unrelated_success.reference.line_end = Some(2);
    unrelated_success.message = unrelated_success
        .message
        .replace(
            "[redacted:sccm-public-message-v1] terminal failure",
            "[redacted:sccm-public-message-v1] succeeded",
        )
        .replace(
            "22222222-2222-2222-2222-222222222222",
            "33333333-3333-3333-3333-333333333333",
        )
        .replace(" error=0x80004005", "");
    different_guid.evidence.push(unrelated_success);

    let unrelated_analysis = analyze_client_health(&different_guid);
    assert_eq!(
        unrelated_analysis.last_successful_phase,
        Some(SccmHealthPhase::Service)
    );
    assert!(has_high_confirmed_failure(&different_guid));
    assert_eq!(
        unrelated_analysis.findings.len(),
        1,
        "an unrelated identity GUID must preserve exactly one identity failure finding"
    );
    assert_eq!(
        unrelated_analysis.findings[0].finding.finding_id,
        "health-identity-terminal"
    );
}

#[test]
fn health_quoted_terminal_marker_cannot_create_a_high_failure() {
    let mut bundle = load_bundle("transport-failure");
    assert!(
        has_high_confirmed_failure(&bundle),
        "the unmodified terminal fixture must prove the mutation is meaningful"
    );
    replace_first_message(
        &mut bundle,
        "Transport terminal failure",
        "Narrative quotes Transport terminal failure",
    );

    let analysis = analyze_client_health(&bundle);
    assert!(!has_high_confirmed_failure(&bundle));
    assert_eq!(
        analysis.last_successful_phase,
        Some(SccmHealthPhase::ManagementPoint)
    );
    assert_eq!(analysis.findings.len(), 1);
    assert_eq!(
        analysis.findings[0].finding.finding_id,
        "health-transport-insufficient"
    );
}

#[test]
fn health_later_normalized_utc_identity_success_recovers_across_canonical_rotation() {
    let mut bundle = load_bundle("identity-failure");
    let original_identity_id = bundle
        .artifacts
        .iter()
        .find(|artifact| {
            artifact
                .display_name
                .eq_ignore_ascii_case("ClientIDManagerStartup.log")
        })
        .expect("identity failure current artifact")
        .artifact_id
        .clone();
    let rotated_identity_id = "health-identity-failure-identity-lo";
    let current_identity_id = "health-identity-recovery-identity-current";

    let rotated_artifact = bundle
        .artifacts
        .iter_mut()
        .find(|artifact| artifact.artifact_id == original_identity_id)
        .expect("identity failure artifact");
    rotated_artifact.artifact_id = rotated_identity_id.to_owned();
    rotated_artifact.display_name = "ClientIDManagerStartup.lo_".to_owned();
    rotated_artifact.rotation = SccmRotation::LoUnderscore;
    let mut current_artifact = rotated_artifact.clone();
    current_artifact.artifact_id = current_identity_id.to_owned();
    current_artifact.display_name = "ClientIDManagerStartup.log".to_owned();
    current_artifact.rotation = SccmRotation::Current;
    bundle.artifacts.push(current_artifact);

    let identity_record_count = bundle
        .evidence
        .iter()
        .filter(|evidence| evidence.reference.artifact_id == original_identity_id)
        .count();
    assert_eq!(
        identity_record_count, 1,
        "this rotation test assumes one identity evidence record"
    );
    for evidence in &mut bundle.evidence {
        evidence.timestamp.ordering_state = SccmTimeOrderingState::NormalizedUtc;
        evidence.timestamp.utc_millis = Some(if evidence.message.contains("Bootstrap completed") {
            10
        } else if evidence
            .message
            .contains("Client service evaluation succeeded")
        {
            20
        } else {
            30
        });
        if evidence.reference.artifact_id == original_identity_id {
            evidence.evidence_id = "evidence:health-identity-failure-rotation".to_owned();
            evidence.reference.artifact_id = rotated_identity_id.to_owned();
            evidence.reference.entry_id = "identity-failure-rotation".to_owned();
        }
    }
    assert!(
        has_high_confirmed_failure(&bundle),
        "the canonical rotation failure must remain terminal before recovery is added"
    );

    let mut recovery = bundle
        .evidence
        .iter()
        .find(|evidence| evidence.reference.artifact_id == rotated_identity_id)
        .expect("rotated identity failure evidence")
        .clone();
    recovery.evidence_id = "evidence:health-identity-recovery-current".to_owned();
    recovery.reference.artifact_id = current_identity_id.to_owned();
    recovery.reference.entry_id = "identity-recovery-current".to_owned();
    recovery.timestamp.utc_millis = Some(40);
    recovery.message = recovery
        .message
        .replace(
            "[redacted:sccm-public-message-v1] terminal failure",
            "[redacted:sccm-public-message-v1] succeeded",
        )
        .replace(" error=0x80004005", "");
    assert!(
        recovery
            .message
            .contains("[redacted:sccm-public-message-v1] succeeded clientGuid="),
        "recovery mutation must create the exact supported success marker"
    );
    bundle.evidence.push(recovery);

    let analysis = analyze_client_health(&bundle);
    assert_eq!(
        analysis.last_successful_phase,
        Some(SccmHealthPhase::Identity)
    );
    assert!(!has_high_confirmed_failure(&bundle));
    assert!(analysis
        .findings
        .iter()
        .all(|finding| finding.finding.finding_id != "health-identity-terminal"));

    let mut reversed = bundle.clone();
    reversed.artifacts.reverse();
    reversed.evidence.reverse();
    assert_eq!(
        serde_json::to_string(&analyze_client_health(&reversed)).expect("reversed analysis JSON"),
        serde_json::to_string(&analysis).expect("forward analysis JSON"),
        "canonical rotation recovery must not depend on vector order"
    );
}

#[test]
fn health_embedded_error_field_is_not_an_exact_terminal_token() {
    let mut bundle = load_bundle("transport-failure");
    replace_first_message(&mut bundle, "error=0x80072EFD", "httperror=0x80072EFD");

    let analysis = analyze_client_health(&bundle);
    assert!(!has_high_confirmed_failure(&bundle));
    assert_eq!(
        analysis.last_successful_phase,
        Some(SccmHealthPhase::ManagementPoint)
    );
    assert_eq!(analysis.findings.len(), 1);
    assert_eq!(
        analysis.findings[0].finding.finding_id,
        "health-transport-insufficient"
    );
}

#[test]
fn health_fixture_validator_requires_every_expected_line_range() {
    let analysis = json!({
        "findings": [{
            "findingId": "health-test-finding",
            "class": "symptom",
            "confidence": "low",
            "evidence": [{
                "artifactId": "health-test-artifact",
                "entryId": "entry-000001",
                "lineStart": 1,
                "lineEnd": 1
            }],
            "terminalEvidence": []
        }]
    });
    let expected = json!({
        "findings": [{
            "findingId": "health-test-finding",
            "fixtureEvidence": [
                {
                    "artifactId": "health-test-artifact",
                    "entryId": "entry-000001",
                    "lineStart": 1,
                    "lineEnd": 1
                },
                {
                    "artifactId": "health-test-artifact",
                    "entryId": "entry-000002",
                    "lineStart": 2,
                    "lineEnd": 2
                }
            ]
        }]
    });

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        assert_finding_evidence_matches_contract("validator-probe", &analysis, &expected);
    }));
    assert!(
        result.is_err(),
        "one actual reference must not satisfy two expected ranges in one artifact"
    );
}

#[test]
fn health_adversarial_inputs_cannot_create_terminal_or_success_outcomes() {
    let mut accepted = Vec::<String>::new();

    let mut zero_setup_error = load_bundle("setup-failure");
    replace_first_message(
        &mut zero_setup_error,
        "error=0x80070005",
        "error=0x00000000",
    );
    if has_high_confirmed_failure(&zero_setup_error) {
        accepted.push("zero setup error accepted as terminal".to_owned());
    }

    let mut zero_transport_status = load_bundle("success");
    replace_first_message(&mut zero_transport_status, "status=200", "status=0");
    if analyze_client_health(&zero_transport_status).last_successful_phase
        == Some(SccmHealthPhase::Transport)
    {
        accepted.push("zero transport status accepted as success".to_owned());
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
        accepted.push("mismatched client GUID advanced the phase chain".to_owned());
    }

    let mut unsafe_host = load_bundle("success");
    for evidence in &mut unsafe_host.evidence {
        evidence.message = evidence
            .message
            .replace("mp-lab.contoso.invalid", "user@real.example");
    }
    if matches!(
        analyze_client_health(&unsafe_host).last_successful_phase,
        Some(SccmHealthPhase::ManagementPoint | SccmHealthPhase::Transport)
    ) {
        accepted.push("unsafe raw host advanced management-point evidence".to_owned());
    }

    let mut wrong_source = load_bundle("success");
    let evaluation_artifact = wrong_source
        .artifacts
        .iter_mut()
        .find(|artifact| artifact.display_name.eq_ignore_ascii_case("CcmEval.log"))
        .expect("success fixture evaluation artifact");
    evaluation_artifact.display_name = "LocationServices.log".to_owned();
    if analyze_client_health(&wrong_source).last_successful_phase != Some(SccmHealthPhase::Setup) {
        accepted.push("source-phase mismatch advanced service evidence".to_owned());
    }

    let mut unknown_profile = load_bundle("identity-failure");
    for artifact in &mut unknown_profile.artifacts {
        artifact.configmgr_version = Some("5.00.UNKNOWN.0000".to_owned());
    }
    if has_high_confirmed_failure(&unknown_profile) {
        accepted.push("unknown extraction profile created high failure".to_owned());
    }

    let mut missing_profile = load_bundle("identity-failure");
    for artifact in &mut missing_profile.artifacts {
        artifact.configmgr_version = None;
    }
    if has_high_confirmed_failure(&missing_profile) {
        accepted.push("missing extraction profile created high failure".to_owned());
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
        accepted.push("access-denied source created high failure".to_owned());
    }

    let mut capped_success = load_bundle("success");
    for artifact in &mut capped_success.artifacts {
        artifact.coverage = SccmCoverageState::Capped;
    }
    if analyze_client_health(&capped_success)
        .last_successful_phase
        .is_some()
    {
        accepted.push("capped sources created a successful phase".to_owned());
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
            accepted.push(format!(
                "non-captured coverage {coverage:?} created a successful phase"
            ));
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
        accepted.push("mismatched request key created transport success".to_owned());
    }

    let mut unsafe_request = load_bundle("success");
    for evidence in &mut unsafe_request.evidence {
        evidence.message = evidence.message.replace("REQ-TEST-001", "REQ-REAL-001");
    }
    if analyze_client_health(&unsafe_request).last_successful_phase
        == Some(SccmHealthPhase::Transport)
    {
        accepted.push("out-of-profile request key created transport success".to_owned());
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
    earlier_response.evidence_id = "evidence:health-earlier-success".to_owned();
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
    response.evidence_id = "evidence:health-later-recovery".to_owned();
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
    recovery.evidence_id = "evidence:health-same-bootstrap-recovery".to_owned();
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
    unrelated_success.evidence_id = "evidence:health-different-bootstrap-success".to_owned();
    different_bootstrap.evidence.push(unrelated_success);
    let unrelated_analysis = analyze_client_health(&different_bootstrap);
    assert_eq!(unrelated_analysis.last_successful_phase, None);
    assert_eq!(
        unrelated_analysis.findings.len(),
        1,
        "different bootstrap IDs must yield exactly one setup finding"
    );
    assert_eq!(
        unrelated_analysis.findings[0].finding.finding_id,
        "health-setup-contradictory"
    );
}

#[test]
fn health_public_output_rejects_unsafe_artifact_provenance() {
    let mut bundle = load_bundle("setup-failure");
    let unsafe_id = r"C:\Users\Person\ccmsetup.log";
    let setup_artifact = bundle
        .artifacts
        .iter_mut()
        .find(|artifact| artifact.display_name.eq_ignore_ascii_case("ccmsetup.log"))
        .expect("setup failure ccmsetup artifact");
    let original_artifact_id = setup_artifact.artifact_id.clone();
    setup_artifact.artifact_id = unsafe_id.to_owned();
    setup_artifact.original_path = Some(r"C:\Users\Person\ccmsetup.log".to_owned());
    setup_artifact.host = Some("private-host.example".to_owned());
    let setup_evidence = bundle
        .evidence
        .iter_mut()
        .find(|evidence| evidence.reference.artifact_id == original_artifact_id)
        .expect("setup failure evidence");
    setup_evidence.reference.artifact_id = unsafe_id.to_owned();
    setup_evidence.reference.entry_id = "unsafe-provenance".to_owned();

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

#[test]
fn health_terminal_error_field_requires_a_whitespace_delimiter() {
    for prefixed_field in ["http-error=0x80072EFD", "http_error=0x80072EFD"] {
        let mut bundle = load_bundle("transport-failure");
        assert!(
            has_high_confirmed_failure(&bundle),
            "the unmodified fixture must prove terminal admission is exercised"
        );
        replace_first_message(&mut bundle, "error=0x80072EFD", prefixed_field);

        let analysis = analyze_client_health(&bundle);
        assert!(
            !has_high_confirmed_failure(&bundle),
            "{prefixed_field} is not the whitespace-delimited error field"
        );
        assert_eq!(
            analysis.last_successful_phase,
            Some(SccmHealthPhase::ManagementPoint),
            "a punctuation-prefixed field cannot advance or fail transport"
        );
        assert_eq!(analysis.findings.len(), 1);
        assert_eq!(
            analysis.findings[0].finding.finding_id,
            "health-transport-insufficient"
        );
    }
}

#[test]
fn health_same_bootstrap_setup_recovers_across_canonical_rotation() {
    let mut bundle = load_bundle("setup-failure");
    let rotated_artifact_id = "health-setup-failure-ccmsetup-lo";
    let current_artifact_id = "health-setup-recovery-ccmsetup-current";

    let rotated_artifact = bundle
        .artifacts
        .iter_mut()
        .find(|artifact| artifact.display_name.eq_ignore_ascii_case("ccmsetup.log"))
        .expect("setup failure ccmsetup artifact");
    let original_artifact_id = rotated_artifact.artifact_id.clone();
    rotated_artifact.artifact_id = rotated_artifact_id.to_owned();
    rotated_artifact.display_name = "ccmsetup.lo_".to_owned();
    rotated_artifact.rotation = SccmRotation::LoUnderscore;
    let mut current_artifact = rotated_artifact.clone();
    current_artifact.artifact_id = current_artifact_id.to_owned();
    current_artifact.display_name = "ccmsetup.log".to_owned();
    current_artifact.rotation = SccmRotation::Current;
    bundle.artifacts.push(current_artifact);

    let failure = bundle
        .evidence
        .iter_mut()
        .find(|evidence| evidence.reference.artifact_id == original_artifact_id)
        .expect("setup terminal evidence");
    failure.evidence_id = "evidence:health-setup-failure-rotation".to_owned();
    failure.reference.artifact_id = rotated_artifact_id.to_owned();
    failure.reference.entry_id = "setup-failure-rotation".to_owned();
    failure.timestamp.ordering_state = SccmTimeOrderingState::NormalizedUtc;
    failure.timestamp.utc_millis = Some(10);

    let mut recovery = failure.clone();
    recovery.evidence_id = "evidence:health-setup-recovery-current".to_owned();
    recovery.reference.artifact_id = current_artifact_id.to_owned();
    recovery.reference.entry_id = "setup-recovery-current".to_owned();
    recovery.timestamp.utc_millis = Some(20);
    recovery.message = recovery
        .message
        .replace("Bootstrap terminal failure", "Bootstrap completed")
        .replace(
            " error=0x80070005",
            " clientGuid=AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA",
        );
    assert!(
        recovery.message.contains(
            "Bootstrap completed bootstrapId=BOOT-TEST-010 clientGuid=AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA"
        ),
        "recovery must carry the exact supported same-bootstrap success marker"
    );
    bundle.evidence.push(recovery);

    let analysis = analyze_client_health(&bundle);
    assert_eq!(analysis.last_successful_phase, Some(SccmHealthPhase::Setup));
    assert!(!has_high_confirmed_failure(&bundle));
    assert!(analysis.findings.iter().all(|finding| {
        !matches!(
            finding.finding.finding_id.as_str(),
            "health-setup-terminal" | "health-setup-contradictory"
        )
    }));

    let mut reversed = bundle.clone();
    reversed.artifacts.reverse();
    reversed.evidence.reverse();
    assert_eq!(
        serde_json::to_string(&analyze_client_health(&reversed)).expect("reversed analysis JSON"),
        serde_json::to_string(&analysis).expect("forward analysis JSON"),
        "canonical setup recovery cannot depend on vector order"
    );

    let mut incompatible_rotation = bundle;
    let current = incompatible_rotation
        .artifacts
        .iter_mut()
        .find(|artifact| artifact.artifact_id == current_artifact_id)
        .expect("current recovery artifact");
    current.rotation = SccmRotation::LoUnderscore;
    assert_ne!(
        analyze_client_health(&incompatible_rotation).last_successful_phase,
        Some(SccmHealthPhase::Setup),
        "a display-name/rotation mismatch cannot prove cross-rotation recovery"
    );
}

#[test]
fn health_conflicting_evidence_id_or_reference_collisions_fail_closed() {
    fn assert_collision(bundle: &SccmNormalizedBundle, case: &str) {
        let analysis = analyze_client_health(bundle);
        assert_eq!(analysis.last_successful_phase, None, "{case}");
        assert_eq!(analysis.findings.len(), 1, "{case}");
        assert_eq!(
            analysis.findings[0].finding.finding_id, "health-evidence-identity-collision",
            "{case}"
        );
        assert_eq!(
            analysis.findings[0].finding.class,
            SccmFindingClass::InsufficientEvidence,
            "{case}"
        );
        assert_eq!(
            analysis.findings[0].finding.confidence,
            SccmConfidence::Low,
            "{case}"
        );
        assert!(!has_high_confirmed_failure(bundle), "{case}");
    }

    let baseline = load_bundle("identity-failure");
    let failure = baseline
        .evidence
        .iter()
        .find(|evidence| evidence.message.contains("terminal failure clientGuid="))
        .expect("identity failure evidence")
        .clone();

    let mut same_id_and_reference = baseline.clone();
    let mut conflicting = failure.clone();
    conflicting.message = conflicting
        .message
        .replace(
            "[redacted:sccm-public-message-v1] terminal failure",
            "[redacted:sccm-public-message-v1] succeeded",
        )
        .replace(" error=0x80004005", "");
    same_id_and_reference.evidence.push(conflicting.clone());
    assert_collision(
        &same_id_and_reference,
        "one identity cannot attest conflicting messages",
    );

    let mut duplicate_id = baseline.clone();
    conflicting.reference.entry_id = "duplicate-id-distinct-reference".to_owned();
    conflicting.reference.line_start = Some(2);
    conflicting.reference.line_end = Some(2);
    duplicate_id.evidence.push(conflicting.clone());
    assert_collision(&duplicate_id, "duplicate evidence ID");

    let mut duplicate_reference = baseline;
    conflicting.evidence_id = "evidence:health-distinct-id-duplicate-reference".to_owned();
    conflicting.reference = failure.reference.clone();
    duplicate_reference.evidence.push(conflicting);
    assert_collision(&duplicate_reference, "duplicate evidence reference");
}

#[test]
fn health_invalid_cross_artifact_chronology_cannot_prove_complete_transport() {
    let mut bundle = load_bundle("success");
    for evidence in &mut bundle.evidence {
        evidence.timestamp.ordering_state = SccmTimeOrderingState::OffsetInvalid;
        evidence.timestamp.utc_millis = None;
    }

    let analysis = analyze_client_health(&bundle);
    assert_eq!(
        analysis.last_successful_phase,
        Some(SccmHealthPhase::ManagementPoint)
    );
    assert_eq!(analysis.findings.len(), 1);
    let finding = &analysis.findings[0];
    assert_eq!(
        finding.finding.finding_id,
        "health-transport-chronology-uncertain"
    );
    assert_eq!(finding.finding.class, SccmFindingClass::Symptom);
    assert_eq!(finding.finding.confidence, SccmConfidence::Low);
    assert_eq!(
        finding.finding.evidence.len(),
        7,
        "the chronology finding must cite the complete client-side chain"
    );
    assert_eq!(analysis.artifact_requests.len(), 1);

    let mut reversed = bundle.clone();
    reversed.artifacts.reverse();
    reversed.evidence.reverse();
    assert_eq!(
        serde_json::to_string(&analyze_client_health(&reversed)).expect("reversed analysis JSON"),
        serde_json::to_string(&analysis).expect("forward analysis JSON"),
        "incomparable chronology must fail closed deterministically"
    );
}
