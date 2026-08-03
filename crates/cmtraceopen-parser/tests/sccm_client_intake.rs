use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use cmtraceopen_parser::sccm::{
    assess_client_intake, classify_artifact_name, declared_client_source_groups, SccmArtifact,
    SccmClientIntakeArtifact, SccmClientIntakeAssessment, SccmClientIntakeBundle,
    SccmClientIntakeCaptureGap, SccmClientIntakeCoverageGap, SccmClientIntakeError,
    SccmClientIntakeFragment, SccmClientUnsupportedArtifact, SccmCoverageState, SccmRole,
    SccmRotation, SccmUnknownRotation, MAX_SCCM_CLIENT_INTAKE_ARTIFACTS,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

const FIXTURE_ROOT: &str = "tests/fixtures/sccm/client/intake";

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
    path_fingerprint: Option<String>,
    rotation: FixtureRotation,
    source_version: Option<String>,
    captured_utc: Option<String>,
    relative_path: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FixtureRotation {
    kind: String,
    number: Option<u32>,
    timestamp: Option<String>,
    lineage_id: Option<String>,
    fragment_complete: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExpectedIntakeContract {
    contract_state: ExpectedContractState,
    scenario: String,
    pure_assessment: ExpectedPureAssessment,
    native_design_pending: ExpectedNativeDesign,
    downstream_design_pending: ExpectedDownstreamDesign,
}

#[derive(Debug, PartialEq, Deserialize)]
enum ExpectedContractState {
    #[serde(rename = "pureIntakeImplementedNativePending")]
    PureIntakeImplementedNativePending,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExpectedPureAssessment {
    schema_version: u32,
    groups: Vec<ExpectedPureGroup>,
    fragments: Vec<ExpectedPureFragment>,
    physical_artifact_ids: Vec<String>,
    unsupported_artifacts: Vec<ExpectedUnsupportedArtifact>,
    coverage_gaps: Vec<ExpectedCoverageGap>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExpectedPureGroup {
    logical_artifact_id: String,
    coverage: SccmCoverageState,
    fragment_artifact_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExpectedPureFragment {
    artifact_id: String,
    basename: String,
    rotation: SccmRotation,
    coverage: SccmCoverageState,
    path_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rotation_lineage: Option<String>,
    relative_path: Option<String>,
    fragment_complete: Option<bool>,
    configmgr_version: Option<String>,
    collected_at_utc: Option<String>,
    encoding: Option<String>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExpectedUnsupportedArtifact {
    artifact_id: String,
    basename: String,
    declared_coverage: SccmCoverageState,
    classification: SccmCoverageState,
    rotation: SccmRotation,
    path_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rotation_lineage: Option<String>,
    relative_path: Option<String>,
    fragment_complete: Option<bool>,
    configmgr_version: Option<String>,
    collected_at_utc: Option<String>,
    encoding: Option<String>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExpectedCoverageGap {
    logical_artifact_id: String,
    artifact_id: Option<String>,
    role: SccmRole,
    coverage: SccmCoverageState,
    reason: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExpectedNativeDesign {
    artifact_provenance: Vec<ExpectedNativeArtifactProvenance>,
    #[serde(default)]
    capture_assertions: Option<ExpectedCaptureAssertions>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExpectedNativeArtifactProvenance {
    artifact_id: String,
    byte_limit: u64,
    limit_applied: bool,
    bytes_copied: u64,
    #[serde(default)]
    sha256: Option<String>,
}

#[derive(Debug, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExpectedCaptureAssertions {
    truncated: bool,
    raw_byte_counted_before_decoding: bool,
    exact_source_prefix: bool,
    collector_injected_marker: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExpectedDownstreamDesign {
    workflow_diagnosis_expected: bool,
    requests: Vec<ExpectedRequestDesign>,
    prohibited_claims: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum ExpectedRequestDesign {
    SourceGroup(ExpectedSourceGroupRequest),
    IntakeCoverage(ExpectedIntakeCoverageRequest),
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExpectedSourceGroupRequest {
    logical_artifact_id: String,
    reason: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExpectedIntakeCoverageRequest {
    kind: ExpectedRequestKind,
    reason: String,
}

#[derive(Debug, PartialEq, Deserialize)]
enum ExpectedRequestKind {
    #[serde(rename = "intakeCoverage")]
    IntakeCoverage,
}

fn fixture_directory(scenario: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(FIXTURE_ROOT)
        .join(scenario)
}

fn load_bundle(scenario: &str) -> SccmClientIntakeBundle {
    let path = fixture_directory(scenario).join("manifest.json");
    let manifest: FixtureManifest =
        serde_json::from_str(&fs::read_to_string(path).expect("fixture manifest is readable"))
            .expect("fixture manifest is valid");

    SccmClientIntakeBundle {
        artifacts: manifest
            .artifacts
            .into_iter()
            .map(|fixture| {
                assert_eq!(fixture.role, "client");
                SccmClientIntakeArtifact {
                    artifact: SccmArtifact {
                        artifact_id: fixture.artifact_id,
                        display_name: fixture.original_basename,
                        original_path: None,
                        host: None,
                        role: SccmRole::Client,
                        configmgr_version: fixture.source_version,
                        collected_at_utc: fixture.captured_utc,
                        rotation: rotation(&fixture.rotation),
                        coverage: coverage(&fixture.capture_state),
                        encoding: fixture.encoding,
                    },
                    path_fingerprint: fixture.path_fingerprint,
                    rotation_lineage: fixture.rotation.lineage_id,
                    relative_path: fixture.relative_path,
                    fragment_complete: fixture.rotation.fragment_complete,
                }
            })
            .collect(),
        capture_gaps: Vec::new(),
    }
}

fn load_fixture_json(scenario: &str, file_name: &str) -> Value {
    let path = fixture_directory(scenario).join(file_name);
    serde_json::from_str(&fs::read_to_string(path).expect("fixture JSON is readable"))
        .expect("fixture JSON is valid")
}

fn rotation(fixture: &FixtureRotation) -> SccmRotation {
    match fixture.kind.as_str() {
        "current" => SccmRotation::Current,
        "lo" | "loUnderscore" => SccmRotation::LoUnderscore,
        "numbered" => SccmRotation::Numbered(fixture.number.expect("numbered rotation")),
        "timestamped" => {
            SccmRotation::Timestamped(fixture.timestamp.clone().expect("timestamped rotation"))
        }
        other => panic!("unsupported fixture rotation {other}"),
    }
}

fn coverage(value: &str) -> SccmCoverageState {
    match value {
        "captured" => SccmCoverageState::Captured,
        "absent" => SccmCoverageState::Absent,
        "accessDenied" => SccmCoverageState::AccessDenied,
        "capped" => SccmCoverageState::Capped,
        "skipped" => SccmCoverageState::Skipped,
        "unsupported" => SccmCoverageState::Unsupported,
        "parseFailed" => SccmCoverageState::ParseFailed,
        other => panic!("unsupported fixture coverage {other}"),
    }
}

fn assessment(scenario: &str) -> cmtraceopen_parser::sccm::SccmClientIntakeAssessment {
    assess_client_intake(&load_bundle(scenario)).expect("fixture intake is valid")
}

fn lowercase_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

impl From<&SccmClientIntakeFragment> for ExpectedPureFragment {
    fn from(fragment: &SccmClientIntakeFragment) -> Self {
        Self {
            artifact_id: fragment.artifact_id.clone(),
            basename: fragment.basename.clone(),
            rotation: fragment.rotation.clone(),
            coverage: fragment.coverage.clone(),
            path_fingerprint: fragment.path_fingerprint.clone(),
            rotation_lineage: fragment.rotation_lineage.clone(),
            relative_path: fragment.relative_path.clone(),
            fragment_complete: fragment.fragment_complete,
            configmgr_version: fragment.configmgr_version.clone(),
            collected_at_utc: fragment.collected_at_utc.clone(),
            encoding: fragment.encoding.clone(),
        }
    }
}

impl From<&SccmClientUnsupportedArtifact> for ExpectedUnsupportedArtifact {
    fn from(artifact: &SccmClientUnsupportedArtifact) -> Self {
        Self {
            artifact_id: artifact.artifact_id.clone(),
            basename: artifact.basename.clone(),
            declared_coverage: artifact.declared_coverage.clone(),
            classification: artifact.classification.clone(),
            rotation: artifact.rotation.clone(),
            path_fingerprint: artifact.path_fingerprint.clone(),
            rotation_lineage: artifact.rotation_lineage.clone(),
            relative_path: artifact.relative_path.clone(),
            fragment_complete: artifact.fragment_complete,
            configmgr_version: artifact.configmgr_version.clone(),
            collected_at_utc: artifact.collected_at_utc.clone(),
            encoding: artifact.encoding.clone(),
        }
    }
}

impl From<&SccmClientIntakeCoverageGap> for ExpectedCoverageGap {
    fn from(gap: &SccmClientIntakeCoverageGap) -> Self {
        Self {
            logical_artifact_id: gap.logical_artifact_id.clone(),
            artifact_id: gap.artifact_id.clone(),
            role: gap.role.clone(),
            coverage: gap.coverage.clone(),
            reason: gap.reason.clone(),
        }
    }
}

fn normalize_pure_assessment(assessment: &SccmClientIntakeAssessment) -> ExpectedPureAssessment {
    let mut fragments = BTreeMap::new();
    let groups = assessment
        .groups
        .iter()
        .map(|group| {
            let fragment_artifact_ids = group
                .fragments
                .iter()
                .map(|fragment| {
                    let normalized = ExpectedPureFragment::from(fragment);
                    if let Some(existing) =
                        fragments.insert(fragment.artifact_id.clone(), normalized.clone())
                    {
                        assert_eq!(
                            existing, normalized,
                            "one artifact ID must retain identical provenance across group memberships"
                        );
                    }
                    fragment.artifact_id.clone()
                })
                .collect();

            ExpectedPureGroup {
                logical_artifact_id: group.logical_artifact_id.clone(),
                coverage: group.coverage.clone(),
                fragment_artifact_ids,
            }
        })
        .collect();

    let mut physical_ids = BTreeSet::new();
    let physical_artifact_ids = assessment
        .physical_artifacts
        .iter()
        .map(|fragment| {
            assert!(
                physical_ids.insert(fragment.artifact_id.as_str()),
                "physical artifact IDs must be unique"
            );
            let expected_fragment = ExpectedPureFragment::from(fragment);
            assert_eq!(
                fragments.get(&fragment.artifact_id),
                Some(&expected_fragment),
                "physical artifact provenance must equal its canonical group fragment"
            );
            fragment.artifact_id.clone()
        })
        .collect();

    ExpectedPureAssessment {
        schema_version: assessment.schema_version,
        groups,
        fragments: fragments.into_values().collect(),
        physical_artifact_ids,
        unsupported_artifacts: assessment
            .unsupported_artifacts
            .iter()
            .map(Into::into)
            .collect(),
        coverage_gaps: assessment.coverage_gaps.iter().map(Into::into).collect(),
    }
}

fn synthetic_artifact(artifact_id: &str, display_name: &str) -> SccmClientIntakeArtifact {
    let source_group = match display_name {
        "AppEnforce.log" => "client-app-enforce",
        "CIAgent.log" => "client-policy-state",
        "PolicyAgent.log" => "client-policy-agent",
        _ => "unknown",
    };
    let relative_path = if source_group == "unknown" {
        format!("evidence/{source_group}/{display_name}")
    } else {
        format!("evidence/{source_group}/current/{display_name}")
    };
    SccmClientIntakeArtifact {
        artifact: SccmArtifact {
            artifact_id: format!("fixture-{artifact_id}"),
            display_name: display_name.to_owned(),
            original_path: None,
            host: None,
            role: SccmRole::Client,
            configmgr_version: Some("5.00.TEST.0000".to_owned()),
            collected_at_utc: Some("2026-07-30T00:00:00Z".to_owned()),
            rotation: SccmRotation::Current,
            coverage: SccmCoverageState::Captured,
            encoding: Some("utf-8".to_owned()),
        },
        path_fingerprint: Some(format!("synthetic-{artifact_id}")),
        rotation_lineage: None,
        relative_path: Some(relative_path),
        fragment_complete: Some(true),
    }
}

fn synthetic_marker(
    artifact_id: &str,
    display_name: &str,
    coverage: SccmCoverageState,
) -> SccmClientIntakeArtifact {
    let mut artifact = synthetic_artifact(artifact_id, display_name);
    artifact.artifact.coverage = coverage;
    artifact.path_fingerprint = None;
    artifact.relative_path = None;
    artifact.fragment_complete = Some(false);
    artifact
}

fn opaque_numbered_artifact(number: usize) -> SccmClientIntakeArtifact {
    let rotation_number = u32::try_from(number).expect("test artifact number fits u32");
    SccmClientIntakeArtifact {
        artifact: SccmArtifact {
            artifact_id: format!("sccm-artifact:v1:sha256:{number:064x}"),
            display_name: format!("PolicyAgent.log.{number}"),
            original_path: None,
            host: None,
            role: SccmRole::Client,
            configmgr_version: Some("5.00.TEST.0000".to_owned()),
            collected_at_utc: Some("2026-07-30T00:00:00Z".to_owned()),
            rotation: SccmRotation::Numbered(rotation_number),
            coverage: SccmCoverageState::Captured,
            encoding: Some("utf-8".to_owned()),
        },
        path_fingerprint: Some(format!("sha256:{number:064x}")),
        rotation_lineage: None,
        relative_path: Some(format!(
            "evidence/client-policy-agent/numbered-{number}/PolicyAgent.log.{number}"
        )),
        fragment_complete: Some(true),
    }
}

#[test]
fn intake_rejects_more_than_the_v1_artifact_limit_before_validation_indexes() {
    // Keep the input otherwise invalid (all declarations collide) so this
    // asserts that the public limit runs before the per-artifact indexes.
    let duplicate = synthetic_artifact("limit", "PolicyAgent.log");
    let artifacts = vec![duplicate; MAX_SCCM_CLIENT_INTAKE_ARTIFACTS + 1];

    let error = assess_client_intake(&SccmClientIntakeBundle {
        artifacts,
        capture_gaps: Vec::new(),
    })
    .expect_err("the v1 client intake artifact ceiling must fail closed");

    assert_eq!(
        error.to_string(),
        "client intake artifact count exceeds the supported limit"
    );
}

#[test]
fn intake_wire_rejects_more_than_the_v1_artifact_limit_while_deserializing() {
    let boundary_artifacts = (1..=MAX_SCCM_CLIENT_INTAKE_ARTIFACTS)
        .map(opaque_numbered_artifact)
        .collect::<Vec<_>>();
    let boundary = serde_json::json!({
        "artifacts": boundary_artifacts,
    });
    let decoded: SccmClientIntakeBundle =
        serde_json::from_value(boundary).expect("the declared v1 boundary is accepted");
    assert_eq!(decoded.artifacts.len(), MAX_SCCM_CLIENT_INTAKE_ARTIFACTS);

    let artifact = serde_json::to_value(synthetic_artifact("wire-limit", "PolicyAgent.log"))
        .expect("synthetic intake artifact serializes");
    let oversized = serde_json::json!({
        "artifacts": vec![artifact; MAX_SCCM_CLIENT_INTAKE_ARTIFACTS + 1],
    });
    let error = serde_json::from_value::<SccmClientIntakeBundle>(oversized)
        .expect_err("the wire must reject an oversized artifact sequence");
    assert!(
        error.to_string().contains("artifact count exceeds"),
        "the wire must report the bounded-contract violation: {error}"
    );
}

#[test]
fn intake_wire_rejects_more_than_the_v1_artifact_limit_from_json_text() {
    let artifact = synthetic_artifact("wire-limit-text", "PolicyAgent.log");
    let oversized = serde_json::json!({
        "artifacts": vec![artifact; MAX_SCCM_CLIENT_INTAKE_ARTIFACTS + 1],
    });
    let text = oversized.to_string();

    let error = serde_json::from_str::<SccmClientIntakeBundle>(&text)
        .expect_err("streaming JSON must reject an oversized artifact sequence");
    assert!(
        error.to_string().contains("artifact count exceeds"),
        "the streaming fallback must report the bounded-contract violation: {error}"
    );
}

#[test]
fn capped_omitted_rotation_degrades_group_coverage_without_relabeling_current_capture() {
    let current = synthetic_artifact("current", "PolicyAgent.log");
    let omitted_rotation = SccmClientIntakeCaptureGap {
        artifact_id: "fixture-capped-rotation".to_owned(),
        basename: "PolicyAgent.log.1".to_owned(),
        rotation: SccmRotation::Numbered(1),
        coverage: SccmCoverageState::Capped,
        path_fingerprint: "synthetic-capped-rotation".to_owned(),
        rotation_lineage: "synthetic:capped-rotation".to_owned(),
    };

    let assessment = assess_client_intake(&SccmClientIntakeBundle {
        artifacts: vec![current],
        capture_gaps: vec![omitted_rotation],
    })
    .expect("a coverage-only omitted rotation is a valid client intake declaration");

    let group = assessment
        .group("client-policy-agent")
        .expect("policy agent group");
    assert_eq!(group.coverage, SccmCoverageState::Capped);
    assert_eq!(group.fragments.len(), 1);
    assert_eq!(group.fragments[0].coverage, SccmCoverageState::Captured);
    assert_eq!(assessment.physical_artifacts.len(), 1);
    assert_eq!(
        assessment.physical_artifacts[0].coverage,
        SccmCoverageState::Captured
    );
    assert_eq!(assessment.capture_gaps.len(), 1);
    assert_eq!(
        assessment.capture_gaps[0].artifact_id,
        "fixture-capped-rotation"
    );
    assert!(assessment.coverage_gaps.iter().any(|gap| {
        gap.logical_artifact_id == "client-policy-agent"
            && gap.artifact_id.as_deref() == Some("fixture-capped-rotation")
            && gap.coverage == SccmCoverageState::Capped
    }));

    let serialized = serde_json::to_value(&assessment).expect("assessment serializes");
    let gap = &serialized["captureGaps"][0];
    assert!(gap.get("relativePath").is_none());
    assert!(gap.get("bytesCopied").is_none());
    assert!(gap.get("bytesRetained").is_none());
}

#[test]
fn intake_wire_rejects_a_combined_artifact_and_capture_gap_count_above_the_v1_limit() {
    let artifact = serde_json::to_value(synthetic_artifact("wire-current", "PolicyAgent.log"))
        .expect("synthetic intake artifact serializes");
    let capture_gap = serde_json::to_value(SccmClientIntakeCaptureGap {
        artifact_id: "fixture-capped-rotation".to_owned(),
        basename: "PolicyAgent.log.1".to_owned(),
        rotation: SccmRotation::Numbered(1),
        coverage: SccmCoverageState::Capped,
        path_fingerprint: "synthetic-capped-rotation".to_owned(),
        rotation_lineage: "synthetic:capped-rotation".to_owned(),
    })
    .expect("synthetic capture gap serializes");
    let oversized_values = [
        serde_json::json!({
            "artifacts": [artifact.clone()],
            "captureGaps": vec![capture_gap.clone(); MAX_SCCM_CLIENT_INTAKE_ARTIFACTS],
        }),
        serde_json::json!({
            "artifacts": vec![artifact; MAX_SCCM_CLIENT_INTAKE_ARTIFACTS],
            "captureGaps": [capture_gap],
        }),
    ];

    for oversized in oversized_values {
        let error = serde_json::from_value::<SccmClientIntakeBundle>(oversized)
            .expect_err("the shared v1 declaration ceiling must reject a combined oversized wire");
        assert!(
            error.to_string().contains("artifact count exceeds"),
            "the wire must report the shared declaration bound: {error}"
        );
    }
}

#[test]
fn intake_accepts_the_shared_v1_boundary_across_physical_and_coverage_only_declarations() {
    let artifacts = (1..MAX_SCCM_CLIENT_INTAKE_ARTIFACTS)
        .map(opaque_numbered_artifact)
        .collect();
    let capture_gap = SccmClientIntakeCaptureGap {
        artifact_id: format!("sccm-artifact:v1:sha256:{MAX_SCCM_CLIENT_INTAKE_ARTIFACTS:064x}"),
        basename: format!("PolicyAgent.log.{MAX_SCCM_CLIENT_INTAKE_ARTIFACTS}"),
        rotation: SccmRotation::Numbered(MAX_SCCM_CLIENT_INTAKE_ARTIFACTS as u32),
        coverage: SccmCoverageState::Capped,
        path_fingerprint: format!("sha256:{MAX_SCCM_CLIENT_INTAKE_ARTIFACTS:064x}"),
        rotation_lineage: format!(
            "cmtraceopen.lineage.sha256.v1:{MAX_SCCM_CLIENT_INTAKE_ARTIFACTS:064x}"
        ),
    };

    let assessment = assess_client_intake(&SccmClientIntakeBundle {
        artifacts,
        capture_gaps: vec![capture_gap],
    })
    .expect("the shared v1 declaration boundary is accepted exactly");
    assert_eq!(
        assessment.physical_artifacts.len(),
        MAX_SCCM_CLIENT_INTAKE_ARTIFACTS - 1
    );
    assert_eq!(assessment.capture_gaps.len(), 1);

    let wire = serde_json::to_value(&assessment)
        .expect("the canonical shared boundary assessment serializes");
    let decoded = serde_json::from_value::<SccmClientIntakeAssessment>(wire)
        .expect("the canonical shared boundary assessment deserializes");
    assert_eq!(decoded, assessment);
}

#[test]
fn legacy_bundle_wire_omits_the_additive_empty_capture_gap_field() {
    let artifact = serde_json::to_value(synthetic_artifact("policy-current", "PolicyAgent.log"))
        .expect("synthetic intake artifact serializes");
    let legacy_wire = serde_json::json!({ "artifacts": [artifact] });

    let decoded: SccmClientIntakeBundle =
        serde_json::from_value(legacy_wire).expect("pre-gap bundle wire remains accepted");
    assert!(decoded.capture_gaps.is_empty());
    let reserialized = serde_json::to_value(decoded).expect("bundle reserializes");
    assert!(
        reserialized.get("captureGaps").is_none(),
        "an empty additive field must preserve the existing wire shape"
    );
}

#[test]
fn intake_rejects_malformed_coverage_only_capture_gap() {
    let malformed = SccmClientIntakeCaptureGap {
        artifact_id: "fixture-captured-rotation".to_owned(),
        basename: "PolicyAgent.log.1".to_owned(),
        rotation: SccmRotation::Numbered(1),
        coverage: SccmCoverageState::Captured,
        path_fingerprint: "synthetic-captured-rotation".to_owned(),
        rotation_lineage: "synthetic:captured-rotation".to_owned(),
    };

    assert_eq!(
        assess_client_intake(&SccmClientIntakeBundle {
            artifacts: Vec::new(),
            capture_gaps: vec![malformed],
        }),
        Err(SccmClientIntakeError::InvalidCaptureGap),
        "coverage-only gaps must not be able to claim captured physical evidence"
    );
}

#[test]
fn capture_gap_wire_rejects_physical_path_or_byte_claims() {
    let capture_gap = serde_json::to_value(SccmClientIntakeCaptureGap {
        artifact_id: "fixture-capped-rotation".to_owned(),
        basename: "PolicyAgent.log.1".to_owned(),
        rotation: SccmRotation::Numbered(1),
        coverage: SccmCoverageState::Capped,
        path_fingerprint: "synthetic-capped-rotation".to_owned(),
        rotation_lineage: "synthetic:capped-rotation".to_owned(),
    })
    .expect("synthetic capture gap serializes");
    let mut with_path = capture_gap.clone();
    with_path["relativePath"] =
        serde_json::json!("evidence/client-policy-agent/numbered-1/PolicyAgent.log.1");
    let mut with_bytes = capture_gap;
    with_bytes["bytesCopied"] = serde_json::json!(1);

    for malformed_gap in [with_path, with_bytes] {
        assert!(
            serde_json::from_value::<SccmClientIntakeBundle>(serde_json::json!({
                "artifacts": [],
                "captureGaps": [malformed_gap],
            }))
            .is_err(),
            "a coverage-only gap must reject physical evidence fields"
        );
    }
}

fn capture_gap_wire_value(gap: &SccmClientIntakeCaptureGap) -> Value {
    serde_json::json!({
        "artifactId": gap.artifact_id,
        "basename": gap.basename,
        "rotation": gap.rotation,
        "coverage": gap.coverage,
        "pathFingerprint": gap.path_fingerprint,
        "rotationLineage": gap.rotation_lineage,
    })
}

#[test]
fn standalone_capture_gap_serde_and_direct_assessment_reject_unsafe_public_state() {
    let valid = SccmClientIntakeCaptureGap {
        artifact_id: "fixture-capped-rotation".to_owned(),
        basename: "PolicyAgent.log.1".to_owned(),
        rotation: SccmRotation::Numbered(1),
        coverage: SccmCoverageState::Capped,
        path_fingerprint: "synthetic-capped-rotation".to_owned(),
        rotation_lineage: "synthetic:capped-rotation".to_owned(),
    };
    let mut captured = valid.clone();
    captured.coverage = SccmCoverageState::Captured;
    let mut unsafe_id = valid.clone();
    unsafe_id.artifact_id = r"C:\Users\RealUser\PolicyAgent.log.1".to_owned();
    let mut raw_fingerprint = valid.clone();
    raw_fingerprint.path_fingerprint = r"C:\Users\RealUser".to_owned();
    let mut unversioned_lineage = valid.clone();
    unversioned_lineage.rotation_lineage = "lineage-1".to_owned();

    for invalid in [captured, unsafe_id, raw_fingerprint, unversioned_lineage] {
        assert_eq!(
            assess_client_intake(&SccmClientIntakeBundle {
                artifacts: Vec::new(),
                capture_gaps: vec![invalid.clone()],
            }),
            Err(SccmClientIntakeError::InvalidCaptureGap),
            "direct assessment must reject the unsafe capture-gap shape"
        );
        assert!(
            serde_json::to_value(&invalid).is_err(),
            "standalone serialization must validate post-construction mutation"
        );

        let wire = capture_gap_wire_value(&invalid);
        assert!(
            serde_json::from_value::<SccmClientIntakeCaptureGap>(wire.clone()).is_err(),
            "from_value must validate standalone capture-gap input"
        );
        assert!(
            serde_json::from_str::<SccmClientIntakeCaptureGap>(&wire.to_string()).is_err(),
            "from_str must validate standalone capture-gap input"
        );
    }
}

#[test]
fn standalone_capture_gap_serde_preserves_parse_failed_as_coverage_only() {
    let gap = SccmClientIntakeCaptureGap {
        artifact_id: "fixture-capped-rotation".to_owned(),
        basename: "PolicyAgent.log.1".to_owned(),
        rotation: SccmRotation::Numbered(1),
        coverage: SccmCoverageState::ParseFailed,
        path_fingerprint: "synthetic-capped-rotation".to_owned(),
        rotation_lineage: "synthetic:capped-rotation".to_owned(),
    };

    let wire = serde_json::to_value(&gap).expect("ParseFailed remains a valid unretained gap");
    assert_eq!(
        serde_json::from_value::<SccmClientIntakeCaptureGap>(wire.clone())
            .expect("from_value accepts the reviewed ParseFailed state"),
        gap
    );
    assert_eq!(
        serde_json::from_str::<SccmClientIntakeCaptureGap>(&wire.to_string())
            .expect("from_str accepts the reviewed ParseFailed state"),
        gap
    );
}

#[test]
fn bundle_serialization_rejects_colliding_standalone_valid_capture_gaps() {
    let first = SccmClientIntakeCaptureGap {
        artifact_id: "fixture-capped-rotation-numbered-1".to_owned(),
        basename: "PolicyAgent.log.1".to_owned(),
        rotation: SccmRotation::Numbered(1),
        coverage: SccmCoverageState::Capped,
        path_fingerprint: "synthetic-capped-rotation".to_owned(),
        rotation_lineage: "synthetic:capped-rotation".to_owned(),
    };
    let mut second = first.clone();
    second.artifact_id = "fixture-capped-rotation-numbered-2".to_owned();
    assert!(serde_json::to_value(&first).is_ok());
    assert!(serde_json::to_value(&second).is_ok());
    let bundle = SccmClientIntakeBundle {
        artifacts: Vec::new(),
        capture_gaps: vec![first, second],
    };

    assert_eq!(
        assess_client_intake(&bundle),
        Err(SccmClientIntakeError::CollidingPhysicalIdentity)
    );
    assert!(
        serde_json::to_value(&bundle).is_err(),
        "bundle serialization must validate cross-declaration collisions"
    );
}

fn assert_bundle_wire_rejected_at_both_json_boundaries(label: &str, wire: Value) {
    let value_rejected = serde_json::from_value::<SccmClientIntakeBundle>(wire.clone()).is_err();
    let text_rejected = serde_json::from_str::<SccmClientIntakeBundle>(&wire.to_string()).is_err();
    assert!(
        value_rejected && text_rejected,
        "invalid bundle declaration was accepted: {label}; \
         from_value rejected={value_rejected}, from_str rejected={text_rejected}"
    );
}

#[test]
fn bundle_deserialization_revalidates_unsafe_collision_and_capture_gap_inputs() {
    let artifact = serde_json::to_value(synthetic_artifact("policy-current", "PolicyAgent.log"))
        .expect("valid artifact serializes");

    let mut unsafe_identity = serde_json::json!({ "artifacts": [artifact.clone()] });
    unsafe_identity["artifacts"][0]["artifact"]["artifactId"] =
        serde_json::json!(r"C:\Users\RealUser\PolicyAgent.log");

    let duplicate_artifact = serde_json::json!({
        "artifacts": [artifact.clone(), artifact.clone()],
    });

    let first_gap = SccmClientIntakeCaptureGap {
        artifact_id: "fixture-capped-rotation-numbered-1".to_owned(),
        basename: "PolicyAgent.log.1".to_owned(),
        rotation: SccmRotation::Numbered(1),
        coverage: SccmCoverageState::Capped,
        path_fingerprint: "synthetic-capped-rotation".to_owned(),
        rotation_lineage: "synthetic:capped-rotation".to_owned(),
    };
    let mut second_gap = first_gap.clone();
    second_gap.artifact_id = "fixture-capped-rotation-numbered-2".to_owned();
    let colliding_gaps = serde_json::json!({
        "artifacts": [],
        "captureGaps": [
            capture_gap_wire_value(&first_gap),
            capture_gap_wire_value(&second_gap),
        ],
    });

    let mut invalid_gap = first_gap.clone();
    invalid_gap.coverage = SccmCoverageState::Captured;
    let invalid_gap_shape = serde_json::json!({
        "artifacts": [],
        "captureGaps": [capture_gap_wire_value(&invalid_gap)],
    });

    let mut duplicate_across_declaration_kinds = first_gap;
    duplicate_across_declaration_kinds.artifact_id = "fixture-policy-current".to_owned();
    let duplicate_artifact_and_gap = serde_json::json!({
        "artifacts": [artifact],
        "captureGaps": [capture_gap_wire_value(&duplicate_across_declaration_kinds)],
    });

    for (label, wire) in [
        ("unsafe artifact identity", unsafe_identity),
        ("duplicate artifact identity", duplicate_artifact),
        ("colliding capture gaps", colliding_gaps),
        ("invalid capture-gap shape", invalid_gap_shape),
        (
            "duplicate artifact and capture-gap identity",
            duplicate_artifact_and_gap,
        ),
    ] {
        assert_bundle_wire_rejected_at_both_json_boundaries(label, wire);
    }
}

#[test]
fn shared_decode_quota_wins_before_malformed_second_field_in_both_wire_orders() {
    let artifact =
        serde_json::to_value(synthetic_artifact("boundary-candidate", "PolicyAgent.log"))
            .expect("synthetic intake artifact serializes");
    let capture_gap = capture_gap_wire_value(&SccmClientIntakeCaptureGap {
        artifact_id: "fixture-capped-rotation".to_owned(),
        basename: "PolicyAgent.log.1".to_owned(),
        rotation: SccmRotation::Numbered(1),
        coverage: SccmCoverageState::Capped,
        path_fingerprint: "synthetic-capped-rotation".to_owned(),
        rotation_lineage: "synthetic:capped-rotation".to_owned(),
    });
    let artifacts = serde_json::to_string(&vec![artifact; MAX_SCCM_CLIENT_INTAKE_ARTIFACTS])
        .expect("artifact boundary wire serializes");
    let capture_gaps = serde_json::to_string(&vec![capture_gap; MAX_SCCM_CLIENT_INTAKE_ARTIFACTS])
        .expect("capture-gap boundary wire serializes");
    let artifacts_first =
        format!(r#"{{"artifacts":{artifacts},"captureGaps":[{{"coverage":"captured"}}]}}"#);
    let capture_gaps_first =
        format!(r#"{{"captureGaps":{capture_gaps},"artifacts":[{{"artifact":null}}]}}"#);

    for wire in [artifacts_first, capture_gaps_first] {
        let error = serde_json::from_str::<SccmClientIntakeBundle>(&wire)
            .expect_err("the first field exhausts the shared declaration quota");
        assert!(
            error
                .to_string()
                .starts_with(&SccmClientIntakeError::ArtifactLimitExceeded.to_string()),
            "an element beyond the shared quota must not be semantically decoded: {error}"
        );
    }
}

#[test]
fn intake_rejects_capture_gap_that_conflicts_with_physical_lineage() {
    let mut current = synthetic_artifact("current", "PolicyAgent.log");
    current.path_fingerprint = Some("synthetic-current-rotation".to_owned());
    current.rotation_lineage = Some("synthetic:current-rotation".to_owned());
    let colliding_gap = SccmClientIntakeCaptureGap {
        artifact_id: "fixture-capped-rotation".to_owned(),
        basename: "PolicyAgent.log.1".to_owned(),
        rotation: SccmRotation::Numbered(1),
        coverage: SccmCoverageState::Capped,
        path_fingerprint: "synthetic-current-rotation".to_owned(),
        rotation_lineage: "synthetic:capped-rotation".to_owned(),
    };

    assert_eq!(
        assess_client_intake(&SccmClientIntakeBundle {
            artifacts: vec![current],
            capture_gaps: vec![colliding_gap],
        }),
        Err(SccmClientIntakeError::CollidingPhysicalIdentity),
        "a coverage-only rotation must remain bound to the same collision and lineage rules"
    );
}

#[test]
fn capture_gap_projection_is_deterministic_and_round_trips() {
    let current = synthetic_artifact("current", "PolicyAgent.log");
    let first = SccmClientIntakeCaptureGap {
        artifact_id: "fixture-capped-rotation-numbered-1".to_owned(),
        basename: "PolicyAgent.log.1".to_owned(),
        rotation: SccmRotation::Numbered(1),
        coverage: SccmCoverageState::Capped,
        path_fingerprint: "synthetic-capped-rotation".to_owned(),
        rotation_lineage: "synthetic:capped-rotation".to_owned(),
    };
    let second = SccmClientIntakeCaptureGap {
        artifact_id: "fixture-capped-rotation-numbered-2".to_owned(),
        basename: "PolicyAgent.log.2".to_owned(),
        rotation: SccmRotation::Numbered(2),
        coverage: SccmCoverageState::Capped,
        path_fingerprint: "synthetic-capped-rotation".to_owned(),
        rotation_lineage: "synthetic:capped-rotation".to_owned(),
    };

    let ordered = assess_client_intake(&SccmClientIntakeBundle {
        artifacts: vec![current.clone()],
        capture_gaps: vec![first.clone(), second.clone()],
    })
    .expect("ordered capture gaps are valid");
    let reversed = assess_client_intake(&SccmClientIntakeBundle {
        artifacts: vec![current],
        capture_gaps: vec![second, first],
    })
    .expect("reversed capture gaps are equally valid");

    assert_eq!(ordered, reversed);
    assert_eq!(
        ordered
            .capture_gaps
            .iter()
            .map(|gap| gap.artifact_id.as_str())
            .collect::<Vec<_>>(),
        vec![
            "fixture-capped-rotation-numbered-1",
            "fixture-capped-rotation-numbered-2",
        ]
    );
    let serialized = serde_json::to_value(&ordered).expect("assessment serializes");
    let decoded: SccmClientIntakeAssessment =
        serde_json::from_value(serialized).expect("canonical capture gaps round trip");
    assert_eq!(decoded, ordered);
}

/// Every assertion that a serialized projection did not leak an identity must
/// casefold its input and route through this helper. A bare substring check
/// against the original-case JSON has twice missed a form this covers: the
/// JSON-escaped backslash root, and the forward-slash normalized root that
/// carries no `RealUser` sentinel. Positive assertions may keep their exact
/// case, since they pin what the projection must reproduce verbatim.
fn serialized_json_contains_windows_user_root(serialized_casefolded: &str) -> bool {
    debug_assert_eq!(
        serialized_casefolded,
        serialized_casefolded.to_ascii_lowercase(),
        "caller must casefold before probing for a Windows user root"
    );
    serialized_casefolded.contains(r"c:\\users") || serialized_casefolded.contains("c:/users")
}

#[test]
fn serialized_privacy_probe_detects_json_escaped_windows_user_path() {
    let leaked_json = serde_json::to_string(&serde_json::json!({
        "originalPath": r"C:\Users\RealUser\PolicyAgent.log"
    }))
    .expect("leak probe serializes")
    .to_ascii_lowercase();

    assert!(
        serialized_json_contains_windows_user_root(&leaked_json),
        "privacy probe must detect a Windows user path after JSON escaping: {leaked_json}"
    );
}

#[test]
fn serialized_privacy_probe_detects_forward_slash_normalized_windows_user_path() {
    let leaked_json = serde_json::to_string(&serde_json::json!({
        "relativePath": "C:/Users/RealUser/PolicyAgent.log"
    }))
    .expect("leak probe serializes")
    .to_ascii_lowercase();

    assert!(
        serialized_json_contains_windows_user_root(&leaked_json),
        "privacy probe must detect a forward-slash normalized Windows user path \
         even without the RealUser sentinel: {leaked_json}"
    );
}

#[test]
fn public_assessment_deserialization_rejects_forged_coverage_and_identity() {
    let mut forged_coverage =
        serde_json::to_value(assessment("missing-root")).expect("assessment serializes");
    forged_coverage["groups"][0]["coverage"] = serde_json::json!("captured");
    assert!(
        serde_json::from_value::<SccmClientIntakeAssessment>(forged_coverage).is_err(),
        "a standalone assessment must not deserialize coverage that contradicts its fragments"
    );

    let mut leaked_identity =
        serde_json::to_value(assessment("complete")).expect("assessment serializes");
    let original_artifact_id = leaked_identity["physicalArtifacts"][0]["artifactId"]
        .as_str()
        .expect("physical artifact ID")
        .to_owned();
    leaked_identity["physicalArtifacts"][0]["artifactId"] =
        serde_json::json!(r"C:\Users\RealUser\PolicyAgent.log");
    leaked_identity["physicalArtifacts"][0]["pathFingerprint"] =
        serde_json::json!("synthetic:realuser");
    leaked_identity["physicalArtifacts"][0]["relativePath"] =
        serde_json::json!(r"C:\Users\RealUser\PolicyAgent.log");
    for group in leaked_identity["groups"]
        .as_array_mut()
        .expect("assessment groups")
    {
        for fragment in group["fragments"].as_array_mut().expect("group fragments") {
            if fragment["artifactId"] == original_artifact_id {
                fragment["artifactId"] = serde_json::json!(r"C:\Users\RealUser\PolicyAgent.log");
                fragment["pathFingerprint"] = serde_json::json!("synthetic:realuser");
                fragment["relativePath"] = serde_json::json!(r"C:\Users\RealUser\PolicyAgent.log");
            }
        }
    }
    assert!(
        serde_json::from_value::<SccmClientIntakeAssessment>(leaked_identity).is_err(),
        "a standalone assessment must not deserialize raw identity-bearing provenance"
    );
}

#[test]
fn public_assessment_capture_gaps_are_bounded_before_projection_validation() {
    let mut wire =
        serde_json::to_value(assessment("missing-root")).expect("canonical assessment serializes");
    let gap = capture_gap_wire_value(&SccmClientIntakeCaptureGap {
        artifact_id: "fixture-capped-rotation".to_owned(),
        basename: "PolicyAgent.log.1".to_owned(),
        rotation: SccmRotation::Numbered(1),
        coverage: SccmCoverageState::Capped,
        path_fingerprint: "synthetic-capped-rotation".to_owned(),
        rotation_lineage: "synthetic:capped-rotation".to_owned(),
    });
    wire["captureGaps"] = serde_json::json!(vec![gap; MAX_SCCM_CLIENT_INTAKE_ARTIFACTS + 1]);

    let value_error = serde_json::from_value::<SccmClientIntakeAssessment>(wire.clone())
        .expect_err("from_value must reject capture gap 4097 before projection validation");
    let text = wire.to_string();
    let text_error = serde_json::from_str::<SccmClientIntakeAssessment>(&text)
        .expect_err("from_str must reject capture gap 4097 before projection validation");
    let limit_error = SccmClientIntakeError::ArtifactLimitExceeded.to_string();
    let value_stopped_early = value_error.to_string().starts_with(&limit_error);
    let text_stopped_early = text_error.to_string().starts_with(&limit_error);
    assert!(
        value_stopped_early && text_stopped_early,
        "oversized assessment capture gaps reached canonical projection validation; \
         from_value early={value_stopped_early} ({value_error}); \
         from_str early={text_stopped_early} ({text_error})"
    );
}

#[test]
fn public_assessment_serialization_rejects_post_build_invalid_mutation() {
    let mut forged_coverage = assessment("missing-root");
    forged_coverage.groups[0].coverage = SccmCoverageState::Captured;
    assert!(
        serde_json::to_string(&forged_coverage).is_err(),
        "post-build coverage mutation must not cross the public wire boundary"
    );

    let mut leaked_identity = assessment("complete");
    let original_artifact_id = leaked_identity.physical_artifacts[0].artifact_id.clone();
    leaked_identity.physical_artifacts[0].artifact_id =
        r"C:\Users\RealUser\PolicyAgent.log".to_owned();
    leaked_identity.physical_artifacts[0].path_fingerprint = Some("synthetic:realuser".to_owned());
    leaked_identity.physical_artifacts[0].relative_path =
        Some(r"C:\Users\RealUser\PolicyAgent.log".to_owned());
    for group in &mut leaked_identity.groups {
        for fragment in &mut group.fragments {
            if fragment.artifact_id == original_artifact_id {
                fragment.artifact_id = r"C:\Users\RealUser\PolicyAgent.log".to_owned();
                fragment.path_fingerprint = Some("synthetic:realuser".to_owned());
                fragment.relative_path = Some(r"C:\Users\RealUser\PolicyAgent.log".to_owned());
            }
        }
    }
    assert!(
        serde_json::to_string(&leaked_identity).is_err(),
        "post-build identity mutation must not cross the public wire boundary"
    );
}

#[test]
fn collection_timestamp_is_projected_as_canonical_utc() {
    let mut artifact = synthetic_artifact("offset", "PolicyAgent.log");
    artifact.artifact.collected_at_utc = Some("2026-07-30T05:00:00+05:00".to_owned());

    let intake = assess_client_intake(&SccmClientIntakeBundle {
        artifacts: vec![artifact],
        capture_gaps: Vec::new(),
    })
    .expect("a valid RFC 3339 collection instant remains representable");
    assert_eq!(
        intake
            .group("client-policy-agent")
            .expect("policy group")
            .fragments[0]
            .collected_at_utc
            .as_deref(),
        Some("2026-07-30T00:00:00Z"),
        "collectedAtUtc must have one deterministic UTC spelling"
    );

    let serialized = serde_json::to_value(&intake).expect("assessment serializes");
    assert!(
        serde_json::from_value::<SccmClientIntakeAssessment>(serialized).is_ok(),
        "canonical assessment output must retain a valid standalone wire round trip"
    );
}

#[test]
fn group_level_coverage_gaps_serialize_an_explicit_null_artifact_id() {
    let serialized =
        serde_json::to_value(assessment("rotations")).expect("client intake assessment serializes");
    let gaps = serialized["coverageGaps"]
        .as_array()
        .expect("coverage gaps serialize as an array");

    assert!(
        !gaps.is_empty(),
        "the rotations fixture has group-level gaps"
    );
    assert!(
        gaps.iter().all(|gap| {
            gap.as_object()
                .is_some_and(|object| object.get("artifactId").is_some_and(Value::is_null))
        }),
        "group-level gaps must serialize artifactId explicitly as null"
    );
}

#[test]
fn every_declared_client_basename_is_supported_by_the_authoritative_catalog() {
    for group in declared_client_source_groups() {
        for basename in group.accepted_basenames {
            let classified = classify_artifact_name(&basename, SccmRole::Client);
            assert!(
                classified.supported_for_diagnosis,
                "{basename} in {} bypasses the shared SCCM catalog",
                group.logical_artifact_id
            );
            assert_eq!(
                classified.basename, basename,
                "{basename} in {} must use the shared catalog's exact canonical basename",
                group.logical_artifact_id
            );
            assert_eq!(
                classified.uses_ccm_records,
                !matches!(basename.as_str(), "client.msi.log" | "ReportingEvents.log"),
                "the shared catalog must not route a non-CCM supplement through raw CCM"
            );
        }
    }
}

#[test]
fn expected_pure_assessments_are_complete_exact_and_deterministic() {
    for scenario in [
        "complete",
        "rotations",
        "missing-root",
        "access-denied",
        "capped",
        "collision",
    ] {
        let expected: ExpectedIntakeContract = serde_json::from_str(
            &fs::read_to_string(fixture_directory(scenario).join("expected.json"))
                .expect("expected fixture is readable"),
        )
        .expect("expected fixture has the exact typed pure contract");

        assert_eq!(
            expected.contract_state,
            ExpectedContractState::PureIntakeImplementedNativePending
        );
        assert_eq!(expected.scenario, scenario);
        assert_eq!(
            expected.pure_assessment,
            normalize_pure_assessment(&assessment(scenario)),
            "{scenario}: expected pure assessment must cover the entire deterministic output"
        );
    }
}

fn expected_contract_matches(value: Value, scenario: &str) -> bool {
    serde_json::from_value::<ExpectedIntakeContract>(value).is_ok_and(|expected| {
        expected.contract_state == ExpectedContractState::PureIntakeImplementedNativePending
            && expected.scenario == scenario
            && expected.pure_assessment == normalize_pure_assessment(&assessment(scenario))
    })
}

#[test]
fn exact_pure_oracle_rejects_unknown_omitted_reordered_and_forged_output() {
    let complete = load_fixture_json("complete", "expected.json");

    let mut unknown_root = complete.clone();
    unknown_root["unexpected"] = serde_json::json!(true);
    assert!(!expected_contract_matches(unknown_root, "complete"));

    let mut unknown_fragment = complete.clone();
    unknown_fragment["pureAssessment"]["fragments"][0]["unexpected"] = serde_json::json!(true);
    assert!(!expected_contract_matches(unknown_fragment, "complete"));

    let mut omitted_group = complete.clone();
    omitted_group["pureAssessment"]["groups"]
        .as_array_mut()
        .expect("expected groups")
        .pop();
    assert!(!expected_contract_matches(omitted_group, "complete"));

    let mut reordered_groups = complete.clone();
    reordered_groups["pureAssessment"]["groups"]
        .as_array_mut()
        .expect("expected groups")
        .swap(0, 1);
    assert!(!expected_contract_matches(reordered_groups, "complete"));

    let mut forged_fragment = complete.clone();
    forged_fragment["pureAssessment"]["fragments"][0]["relativePath"] =
        serde_json::json!("evidence/client-app-enforce/current/forged.log");
    assert!(!expected_contract_matches(forged_fragment, "complete"));

    let mut reordered_physical = complete;
    reordered_physical["pureAssessment"]["physicalArtifactIds"]
        .as_array_mut()
        .expect("physical artifact IDs")
        .swap(0, 1);
    assert!(!expected_contract_matches(reordered_physical, "complete"));

    let mut omitted_gap = load_fixture_json("rotations", "expected.json");
    omitted_gap["pureAssessment"]["coverageGaps"]
        .as_array_mut()
        .expect("coverage gaps")
        .pop();
    assert!(!expected_contract_matches(omitted_gap, "rotations"));
}

#[test]
fn pending_request_schema_rejects_missing_ambiguous_and_unknown_discriminators() {
    let missing_root = load_fixture_json("missing-root", "expected.json");
    assert!(serde_json::from_value::<ExpectedIntakeContract>(missing_root.clone()).is_ok());

    let mut missing_discriminator = missing_root.clone();
    missing_discriminator["downstreamDesignPending"]["requests"][0]
        .as_object_mut()
        .expect("pending request")
        .remove("kind");
    assert!(
        serde_json::from_value::<ExpectedIntakeContract>(missing_discriminator).is_err(),
        "a pending request without kind or logicalArtifactId must fail closed"
    );

    let mut ambiguous = missing_root.clone();
    ambiguous["downstreamDesignPending"]["requests"][0]["logicalArtifactId"] =
        serde_json::json!("client-policy-agent");
    assert!(
        serde_json::from_value::<ExpectedIntakeContract>(ambiguous).is_err(),
        "a pending request cannot select both request variants"
    );

    let mut unknown = missing_root;
    unknown["downstreamDesignPending"]["requests"][0]["unexpected"] = serde_json::json!(true);
    assert!(
        serde_json::from_value::<ExpectedIntakeContract>(unknown).is_err(),
        "pending request variants must reject unknown fields"
    );
}

#[test]
fn pending_native_design_is_typed_bounded_and_fixture_backed() {
    let declared_groups = declared_client_source_groups()
        .into_iter()
        .map(|group| group.logical_artifact_id)
        .collect::<BTreeSet<_>>();

    for scenario in [
        "complete",
        "rotations",
        "missing-root",
        "access-denied",
        "capped",
        "collision",
    ] {
        let expected: ExpectedIntakeContract = serde_json::from_str(
            &fs::read_to_string(fixture_directory(scenario).join("expected.json"))
                .expect("expected fixture is readable"),
        )
        .expect("expected fixture has the exact typed contract");
        let manifest = load_fixture_json(scenario, "manifest.json");
        let intake = assessment(scenario);
        let provenance = &expected.native_design_pending.artifact_provenance;

        assert!(
            provenance
                .windows(2)
                .all(|pair| pair[0].artifact_id < pair[1].artifact_id),
            "{scenario}: pending native provenance must be stable-sorted and unique"
        );
        assert_eq!(
            provenance
                .iter()
                .map(|artifact| artifact.artifact_id.as_str())
                .collect::<BTreeSet<_>>(),
            intake
                .physical_artifacts
                .iter()
                .map(|artifact| artifact.artifact_id.as_str())
                .collect::<BTreeSet<_>>(),
            "{scenario}: pending native provenance must cover every physical artifact exactly"
        );

        for artifact in provenance {
            let manifest_artifact = manifest["artifacts"]
                .as_array()
                .expect("manifest artifacts")
                .iter()
                .find(|candidate| candidate["artifactId"] == artifact.artifact_id)
                .expect("pending provenance refers to a manifest artifact");
            let manifest_byte_limit = manifest_artifact["collectionLimit"]["byteLimit"]
                .as_u64()
                .expect("physical manifest byteLimit is an unsigned integer");
            let manifest_limit_applied = manifest_artifact["collectionLimit"]["limitApplied"]
                .as_bool()
                .expect("physical manifest limitApplied is a boolean");
            let manifest_bytes_copied = manifest_artifact["bytesCopied"]
                .as_u64()
                .expect("physical manifest bytesCopied is an unsigned integer");

            assert_eq!(artifact.byte_limit, manifest_byte_limit);
            assert_eq!(artifact.limit_applied, manifest_limit_applied);
            assert_eq!(artifact.bytes_copied, manifest_bytes_copied);
            assert!(artifact.byte_limit > 0, "capture limits must be bounded");
            if artifact.limit_applied {
                assert_eq!(artifact.bytes_copied, artifact.byte_limit);
                assert!(artifact.bytes_copied > 0);
                assert!(
                    artifact.sha256.is_some(),
                    "capped evidence must pin the exact retained prefix"
                );
            } else {
                assert!(artifact.bytes_copied <= artifact.byte_limit);
            }

            let relative_path = manifest_artifact["relativePath"]
                .as_str()
                .expect("physical manifest artifact has a relative path");
            let bytes = fs::read(fixture_directory(scenario).join(relative_path))
                .expect("physical fixture evidence is readable");
            assert_eq!(bytes.len() as u64, artifact.bytes_copied);
            if let Some(expected_sha256) = artifact.sha256.as_deref() {
                assert_eq!(
                    lowercase_hex(Sha256::digest(&bytes).as_ref()),
                    expected_sha256
                );
            }
        }

        let expected_capture_assertions = if scenario == "capped" {
            Some(ExpectedCaptureAssertions {
                truncated: true,
                raw_byte_counted_before_decoding: true,
                exact_source_prefix: true,
                collector_injected_marker: false,
            })
        } else {
            None
        };
        assert_eq!(
            expected.native_design_pending.capture_assertions, expected_capture_assertions,
            "{scenario}: only the capped fixture carries pending native prefix assertions"
        );
        if let Some(assertions) = expected_capture_assertions {
            let capped_artifact = manifest["artifacts"]
                .as_array()
                .expect("manifest artifacts")
                .iter()
                .find(|artifact| artifact["captureState"] == "capped")
                .expect("capped scenario declares a capped artifact");
            assert_eq!(
                capped_artifact["truncated"].as_bool(),
                Some(assertions.truncated),
                "capped native design must bind the manifest truncation marker"
            );
        }

        let downstream = expected.downstream_design_pending;
        assert!(
            !downstream.workflow_diagnosis_expected,
            "{scenario}: intake alone must not claim a workflow diagnosis"
        );
        for request in downstream.requests {
            let reason = match request {
                ExpectedRequestDesign::SourceGroup(request) => {
                    assert!(
                        declared_groups.contains(&request.logical_artifact_id),
                        "{scenario}: request uses an undeclared client source group"
                    );
                    request.reason
                }
                ExpectedRequestDesign::IntakeCoverage(request) => {
                    assert_eq!(request.kind, ExpectedRequestKind::IntakeCoverage);
                    request.reason
                }
            };
            assert!(
                !reason.trim().is_empty(),
                "{scenario}: request reason is empty"
            );
        }
        assert_eq!(
            downstream
                .prohibited_claims
                .iter()
                .collect::<BTreeSet<_>>()
                .len(),
            downstream.prohibited_claims.len(),
            "{scenario}: prohibited claims must be unique"
        );
        assert!(
            downstream
                .prohibited_claims
                .iter()
                .all(|claim| !claim.trim().is_empty()),
            "{scenario}: prohibited claims must not be empty"
        );
    }
}

#[test]
fn complete_client_intake_covers_every_declared_group_without_a_diagnosis() {
    let declared = declared_client_source_groups();
    let intake = assessment("complete");

    assert_eq!(declared.len(), 11);
    assert_eq!(intake.groups.len(), declared.len());
    assert!(intake
        .groups
        .iter()
        .all(|group| group.coverage == SccmCoverageState::Captured));
    assert!(intake.coverage_gaps.is_empty());
    assert!(intake.unsupported_artifacts.is_empty());

    let location = intake.group("client-location").expect("location group");
    let content = intake.group("client-content").expect("content group");
    let location_services_id = "fixture-complete-location-services-root-a-current";
    assert!(location
        .fragments
        .iter()
        .any(|fragment| fragment.artifact_id == location_services_id));
    assert!(content
        .fragments
        .iter()
        .any(|fragment| fragment.artifact_id == location_services_id));
    assert_eq!(
        intake
            .physical_artifacts
            .iter()
            .filter(|fragment| fragment.artifact_id == location_services_id)
            .count(),
        1,
        "LocationServices is captured once and shared by group projections"
    );
}

#[test]
fn rotations_are_one_group_with_stable_physical_order_and_reordering_is_deterministic() {
    let bundle = load_bundle("rotations");
    let intake = assess_client_intake(&bundle).expect("rotation intake");
    let group = intake
        .group("client-app-enforce")
        .expect("app enforcement group");

    assert_eq!(group.coverage, SccmCoverageState::Captured);
    assert_eq!(group.fragments.len(), 3);
    assert_eq!(group.fragments[0].rotation, SccmRotation::Current);
    assert_eq!(group.fragments[1].rotation, SccmRotation::LoUnderscore);
    assert_eq!(group.fragments[2].rotation, SccmRotation::Numbered(2));
    assert_eq!(
        group
            .fragments
            .iter()
            .filter_map(|fragment| fragment.path_fingerprint.as_deref())
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        1,
        "one configured source fingerprint is retained across its rotations"
    );
    assert_eq!(
        group
            .fragments
            .iter()
            .filter_map(|fragment| fragment.rotation_lineage.as_deref())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["synthetic:app-enforce-root-a"]),
        "every rotation retains the immutable source lineage"
    );

    let mut reordered = bundle;
    reordered.artifacts.reverse();
    let reordered = assess_client_intake(&reordered).expect("reordered intake");
    assert_eq!(
        serde_json::to_string(&reordered).expect("reordered JSON"),
        serde_json::to_string(&intake).expect("intake JSON")
    );

    let mut duplicate_bundle = load_bundle("rotations");
    let mut duplicate = duplicate_bundle.artifacts[1].clone();
    duplicate.artifact.artifact_id = "fixture-rotations-app-enforce-root-a-lo-two".to_owned();
    duplicate.relative_path =
        Some("evidence/client-app-enforce/root-a/lo/AppEnforce.lo_".to_owned());
    duplicate_bundle.artifacts.push(duplicate);
    assert_eq!(
        assess_client_intake(&duplicate_bundle),
        Err(SccmClientIntakeError::CollidingPhysicalIdentity),
        "one lineage cannot declare the same physical rotation twice"
    );

    let mut conflicting_root_bundle = load_bundle("rotations");
    let mut conflicting_root = conflicting_root_bundle.artifacts[1].clone();
    conflicting_root.artifact.artifact_id = "fixture-rotations-app-enforce-root-b-lo".to_owned();
    conflicting_root.path_fingerprint = Some("synthetic-root-b".to_owned());
    conflicting_root.relative_path =
        Some("evidence/client-app-enforce/root-b/lo/AppEnforce.lo_".to_owned());
    conflicting_root_bundle.artifacts.push(conflicting_root);
    assert_eq!(
        assess_client_intake(&conflicting_root_bundle),
        Err(SccmClientIntakeError::CollidingPhysicalIdentity),
        "one lineage and rotation cannot be relabeled as a second configured root"
    );
}

#[test]
fn rotation_lineage_cannot_cross_path_fingerprints_across_distinct_rotations() {
    let mut bundle = load_bundle("rotations");
    bundle.artifacts[1].path_fingerprint = Some("synthetic-root-b".to_owned());
    bundle.artifacts[1].relative_path =
        Some("evidence/client-app-enforce/root-b/lo/AppEnforce.lo_".to_owned());

    assert_eq!(
        assess_client_intake(&bundle),
        Err(SccmClientIntakeError::CollidingPhysicalIdentity),
        "one immutable lineage cannot combine rotations from distinct configured roots"
    );
}

#[test]
fn fragment_order_is_source_identity_then_rotation_rank() {
    let fixture = load_bundle("rotations");
    let mut root_a_current = fixture.artifacts[0].clone();
    root_a_current.relative_path =
        Some("evidence/client-app-enforce/root-a/current/AppEnforce.log".to_owned());
    let mut root_a_lo = fixture.artifacts[1].clone();
    root_a_lo.relative_path =
        Some("evidence/client-app-enforce/root-a/lo/AppEnforce.lo_".to_owned());

    let mut root_b_current = root_a_current.clone();
    root_b_current.artifact.artifact_id = "fixture-rotations-app-enforce-root-b-current".to_owned();
    root_b_current.path_fingerprint = Some("synthetic-root-b".to_owned());
    root_b_current.rotation_lineage = Some("synthetic:app-enforce-root-b".to_owned());
    root_b_current.relative_path =
        Some("evidence/client-app-enforce/root-b/current/AppEnforce.log".to_owned());

    let mut root_b_lo = root_a_lo.clone();
    root_b_lo.artifact.artifact_id = "fixture-rotations-app-enforce-root-b-lo".to_owned();
    root_b_lo.path_fingerprint = Some("synthetic-root-b".to_owned());
    root_b_lo.rotation_lineage = Some("synthetic:app-enforce-root-b".to_owned());
    root_b_lo.relative_path =
        Some("evidence/client-app-enforce/root-b/lo/AppEnforce.lo_".to_owned());

    let bundle = SccmClientIntakeBundle {
        artifacts: vec![root_b_lo, root_a_current, root_b_current, root_a_lo],
        capture_gaps: Vec::new(),
    };
    let assessment = assess_client_intake(&bundle).expect("two source lineages are valid");
    let ordered_ids = assessment
        .group("client-app-enforce")
        .expect("app enforcement group")
        .fragments
        .iter()
        .map(|fragment| fragment.artifact_id.as_str())
        .collect::<Vec<_>>();

    assert_eq!(
        ordered_ids,
        [
            "fixture-rotations-app-enforce-root-a-current",
            "fixture-rotations-app-enforce-root-a-lo",
            "fixture-rotations-app-enforce-root-b-current",
            "fixture-rotations-app-enforce-root-b-lo",
        ],
        "stable source/path identity must precede rotation rank"
    );

    let mut reordered = bundle;
    reordered.artifacts.reverse();
    assert_eq!(
        serde_json::to_string(&assess_client_intake(&reordered).expect("reordered intake"))
            .expect("reordered JSON"),
        serde_json::to_string(&assessment).expect("assessment JSON"),
        "source-first ordering must remain independent of declaration order"
    );
}

#[test]
fn missing_access_denied_and_capped_sources_remain_exact_coverage_states() {
    let missing = assessment("missing-root");
    assert!(missing
        .groups
        .iter()
        .all(|group| group.coverage == SccmCoverageState::Absent));
    assert_eq!(
        missing.coverage_gaps.len(),
        12,
        "the shared LocationServices declaration contributes one gap to each consumer group"
    );
    assert_eq!(
        missing
            .coverage_gaps
            .iter()
            .filter_map(|gap| gap.artifact_id.as_deref())
            .collect::<BTreeSet<_>>()
            .len(),
        11,
        "every missing source declaration remains identifiable"
    );
    assert!(serde_json::to_string(&missing)
        .expect("missing JSON")
        .contains("\"coverage\":\"absent\""));

    let denied = assessment("access-denied");
    assert_eq!(
        denied
            .group("client-policy-agent")
            .expect("policy-agent group")
            .coverage,
        SccmCoverageState::AccessDenied
    );
    assert_eq!(
        denied
            .group("client-policy-state")
            .expect("policy-state group")
            .coverage,
        SccmCoverageState::Captured
    );
    assert!(denied.coverage_gaps.iter().any(|gap| {
        gap.logical_artifact_id == "client-policy-agent"
            && gap.coverage == SccmCoverageState::AccessDenied
    }));

    let capped = assessment("capped");
    let content = capped.group("client-content").expect("content group");
    assert_eq!(content.coverage, SccmCoverageState::Capped);
    assert_eq!(content.fragments.len(), 1);
    assert_eq!(content.fragments[0].fragment_complete, Some(false));
    assert!(capped.coverage_gaps.iter().any(|gap| {
        gap.logical_artifact_id == "client-content" && gap.coverage == SccmCoverageState::Capped
    }));
}

#[test]
fn capped_cas_fragment_cannot_claim_complete() {
    let contradictory = SccmClientIntakeArtifact {
        artifact: SccmArtifact {
            artifact_id: "fixture-content-capped".to_owned(),
            display_name: "CAS.log".to_owned(),
            original_path: None,
            host: None,
            role: SccmRole::Client,
            configmgr_version: Some("5.00.TEST.0000".to_owned()),
            collected_at_utc: Some("2026-07-30T00:03:00Z".to_owned()),
            rotation: SccmRotation::Current,
            coverage: SccmCoverageState::Capped,
            encoding: Some("utf-8".to_owned()),
        },
        path_fingerprint: Some("synthetic:content-capped".to_owned()),
        rotation_lineage: None,
        relative_path: Some("evidence/client-content/current/CAS.log".to_owned()),
        fragment_complete: Some(true),
    };

    assert_eq!(
        assess_client_intake(&SccmClientIntakeBundle {
            artifacts: vec![contradictory],
            capture_gaps: Vec::new(),
        }),
        Err(SccmClientIntakeError::InvalidFragmentCompleteness),
        "a capped physical fragment cannot claim complete public provenance"
    );
}

#[test]
fn captured_incomplete_fragment_retains_a_boundary_without_becoming_capped() {
    let mut boundary = synthetic_artifact("content-a", "CAS.log");
    boundary.relative_path = Some("evidence/client-content/current/CAS.log".to_owned());
    boundary.fragment_complete = Some(false);

    let intake = assess_client_intake(&SccmClientIntakeBundle {
        artifacts: vec![boundary],
        capture_gaps: Vec::new(),
    })
    .expect("a fully copied rotation may still end on an incomplete logical record");
    let content = intake.group("client-content").expect("content group");

    assert_eq!(content.coverage, SccmCoverageState::Captured);
    assert_eq!(content.fragments[0].coverage, SccmCoverageState::Captured);
    assert_eq!(content.fragments[0].fragment_complete, Some(false));
    assert!(intake.coverage_gaps.iter().any(|gap| {
        gap.logical_artifact_id == "client-content"
            && gap.artifact_id.as_deref() == Some("fixture-content-a")
            && gap.coverage == SccmCoverageState::Captured
            && gap.reason
                == "Client source CAS.log was captured with an incomplete logical-record boundary."
    }));
}

#[test]
fn parse_failed_fragment_completeness_is_intentionally_two_valued() {
    // ParseFailed is the one physical state where both completeness values
    // carry meaning: `true` records a fully copied source that could not be
    // normalized, `false` records a truncated copy that also failed to
    // parse. Both must stay representable so neither situation is forced to
    // misdeclare itself as the other.
    for (fragment_complete, artifact_id) in [(true, "complete"), (false, "incomplete")] {
        let mut unparseable = synthetic_artifact(artifact_id, "PolicyAgent.log");
        unparseable.artifact.coverage = SccmCoverageState::ParseFailed;
        unparseable.fragment_complete = Some(fragment_complete);

        let intake = assess_client_intake(&SccmClientIntakeBundle {
            artifacts: vec![unparseable],
            capture_gaps: Vec::new(),
        })
        .unwrap_or_else(|error| {
            panic!("parse-failed completeness {fragment_complete} was rejected: {error}")
        });

        let group = intake.group("client-policy-agent").expect("policy group");
        assert_eq!(group.coverage, SccmCoverageState::ParseFailed);
        assert_eq!(group.fragments.len(), 1);
        assert_eq!(
            group.fragments[0].fragment_complete,
            Some(fragment_complete),
            "declared parse-failed completeness must project unchanged"
        );
        let expected_artifact_id = format!("fixture-{artifact_id}");
        let parse_gap = intake
            .coverage_gaps
            .iter()
            .find(|gap| gap.artifact_id.as_deref() == Some(expected_artifact_id.as_str()))
            .expect("parse-failed source retains its own coverage gap");
        assert_eq!(
            parse_gap.reason,
            "Client source PolicyAgent.log could not be normalized as CCM evidence.",
            "parse failure wording must remain independent of fragment-boundary completeness"
        );
    }
}

#[test]
fn mixed_captured_and_absent_group_preserves_partial_coverage_and_names_the_absent_source() {
    let mut captured = synthetic_artifact("content-a", "CAS.log");
    captured.relative_path = Some("evidence/client-content/current/CAS.log".to_owned());
    let absent = synthetic_marker(
        "content-transfer-absent",
        "ContentTransferManager.log",
        SccmCoverageState::Absent,
    );

    let intake = assess_client_intake(&SccmClientIntakeBundle {
        artifacts: vec![captured, absent],
        capture_gaps: Vec::new(),
    })
    .expect("a mixed captured and absent client-content group is representable");

    let group = intake.group("client-content").expect("content group");
    assert_eq!(
        group.coverage,
        SccmCoverageState::Absent,
        "partial source coverage must remain visible at the group boundary"
    );
    assert_eq!(group.fragments.len(), 2);
    assert_eq!(
        intake.physical_artifacts.len(),
        1,
        "a non-physical marker must not be published as a physical artifact"
    );

    let gaps: Vec<_> = intake
        .coverage_gaps
        .iter()
        .filter(|gap| gap.logical_artifact_id == "client-content")
        .collect();
    assert_eq!(gaps.len(), 1, "one per-source gap for the absent sibling");
    assert_eq!(gaps[0].coverage, SccmCoverageState::Absent);
    assert_eq!(
        gaps[0].artifact_id.as_deref(),
        Some("fixture-content-transfer-absent")
    );
    assert_eq!(
        gaps[0].reason,
        "No artifact for client source ContentTransferManager.log was supplied."
    );
    assert!(
        gaps.iter()
            .all(|gap| gap.reason
                != "No artifact for this bounded client source group was supplied."),
        "the gap must name the absent source instead of claiming the whole group was unsupplied"
    );
}

#[test]
fn mixed_captured_and_access_denied_group_preserves_partial_coverage_and_names_the_denied_source() {
    let mut captured = synthetic_artifact("content-a", "CAS.log");
    captured.relative_path = Some("evidence/client-content/current/CAS.log".to_owned());
    let mut denied = synthetic_marker(
        "content-denied",
        "DataTransferService.log",
        SccmCoverageState::AccessDenied,
    );
    denied.path_fingerprint = Some("synthetic:content-denied".to_owned());

    let intake = assess_client_intake(&SccmClientIntakeBundle {
        artifacts: vec![captured, denied],
        capture_gaps: Vec::new(),
    })
    .expect("a mixed captured and access-denied client-content group is representable");

    let group = intake.group("client-content").expect("content group");
    assert_eq!(
        group.coverage,
        SccmCoverageState::AccessDenied,
        "captured evidence must not erase an access-denied sibling source"
    );
    assert_eq!(group.fragments.len(), 2);
    assert_eq!(intake.physical_artifacts.len(), 1);

    let gaps: Vec<_> = intake
        .coverage_gaps
        .iter()
        .filter(|gap| gap.logical_artifact_id == "client-content")
        .collect();
    assert_eq!(gaps.len(), 1, "one per-source gap for the denied sibling");
    assert_eq!(gaps[0].coverage, SccmCoverageState::AccessDenied);
    assert_eq!(
        gaps[0].artifact_id.as_deref(),
        Some("fixture-content-denied")
    );
    assert_eq!(
        gaps[0].reason,
        "Access was denied for client source DataTransferService.log."
    );
}

#[test]
fn mixed_capped_and_absent_group_keeps_the_capped_capture_and_names_the_absent_source() {
    let mut capped = synthetic_artifact("content-capped", "DataTransferService.log");
    capped.artifact.coverage = SccmCoverageState::Capped;
    capped.path_fingerprint = Some("synthetic:content-capped".to_owned());
    capped.relative_path =
        Some("evidence/client-content/current/DataTransferService.log".to_owned());
    capped.fragment_complete = Some(false);
    let absent = synthetic_marker("content-absent", "CAS.log", SccmCoverageState::Absent);

    let intake = assess_client_intake(&SccmClientIntakeBundle {
        artifacts: vec![capped, absent],
        capture_gaps: Vec::new(),
    })
    .expect("a mixed capped and absent client-content group is representable");

    let group = intake.group("client-content").expect("content group");
    assert_eq!(
        group.coverage,
        SccmCoverageState::Capped,
        "Capped outranks Absent in the group coverage severity order"
    );
    assert_eq!(group.fragments.len(), 2);

    let gaps: Vec<_> = intake
        .coverage_gaps
        .iter()
        .filter(|gap| gap.logical_artifact_id == "client-content")
        .collect();
    assert_eq!(
        gaps.len(),
        2,
        "the capped and absent sources both retain explicit gaps"
    );
    let capped_gap = gaps
        .iter()
        .find(|gap| gap.artifact_id.as_deref() == Some("fixture-content-capped"))
        .expect("capped source gap");
    assert_eq!(capped_gap.coverage, SccmCoverageState::Capped);
    assert_eq!(
        capped_gap.reason,
        "Client source DataTransferService.log reached its capture limit."
    );
    let absent_gap = gaps
        .iter()
        .find(|gap| gap.artifact_id.as_deref() == Some("fixture-content-absent"))
        .expect("absent source gap");
    assert_eq!(absent_gap.coverage, SccmCoverageState::Absent);
    assert_eq!(
        absent_gap.reason,
        "No artifact for client source CAS.log was supplied."
    );
}

#[test]
fn duplicate_nonphysical_markers_for_the_same_source_fail_closed() {
    assert_eq!(
        SccmClientIntakeError::DuplicateArtifactId.to_string(),
        "client intake contains a duplicate artifact ID or source declaration"
    );

    let first = synthetic_marker("missing-one", "PolicyAgent.log", SccmCoverageState::Absent);
    let second = synthetic_marker("missing-two", "PolicyAgent.log", SccmCoverageState::Absent);
    assert_eq!(
        assess_client_intake(&SccmClientIntakeBundle {
            artifacts: vec![first, second],
            capture_gaps: Vec::new(),
        }),
        Err(SccmClientIntakeError::DuplicateArtifactId),
        "the same missing source must not be double-declared under differing caller labels"
    );

    let absent = synthetic_marker("missing-one", "PolicyAgent.log", SccmCoverageState::Absent);
    let denied = synthetic_marker(
        "denied-one",
        "PolicyAgent.log",
        SccmCoverageState::AccessDenied,
    );
    assert_eq!(
        assess_client_intake(&SccmClientIntakeBundle {
            artifacts: vec![absent, denied],
            capture_gaps: Vec::new(),
        }),
        Err(SccmClientIntakeError::DuplicateArtifactId),
        "contradictory marker states for the same source must not both project as fragments"
    );
}

#[test]
fn absent_markers_with_distinct_path_fingerprints_remain_distinct_sources() {
    let mut root_a = synthetic_marker(
        "missing-root-a",
        "PolicyAgent.log",
        SccmCoverageState::Absent,
    );
    root_a.path_fingerprint = Some("synthetic:policy-root-a".to_owned());
    let mut root_b = synthetic_marker(
        "missing-root-b",
        "PolicyAgent.log",
        SccmCoverageState::Absent,
    );
    root_b.path_fingerprint = Some("synthetic:policy-root-b".to_owned());

    let intake = assess_client_intake(&SccmClientIntakeBundle {
        artifacts: vec![root_a, root_b],
        capture_gaps: Vec::new(),
    })
    .expect("markers distinguished by explicit path fingerprints stay representable");

    let group = intake.group("client-policy-agent").expect("policy group");
    assert_eq!(group.coverage, SccmCoverageState::Absent);
    assert_eq!(
        group.fragments.len(),
        2,
        "per-root absence claims with distinct fingerprints are distinct sources"
    );
    let gap_artifacts = intake
        .coverage_gaps
        .iter()
        .filter(|gap| gap.logical_artifact_id == "client-policy-agent")
        .filter_map(|gap| gap.artifact_id.as_deref())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        gap_artifacts,
        BTreeSet::from(["fixture-missing-root-a", "fixture-missing-root-b"]),
        "every configured root must retain its own explicit coverage gap"
    );
}

#[test]
fn unpinned_marker_for_a_physically_declared_source_fails_closed() {
    // Round-6 review repro: one captured PolicyAgent.log plus one absent
    // marker for the same source (current rotation, no path fingerprint)
    // previously produced an assessment claiming no artifact for the source
    // was supplied while serializing the captured PolicyAgent.log fragment.
    // The marker's canonical identity must intersect the physical
    // declaration for the source and fail closed instead.
    let captured = synthetic_artifact("policy", "PolicyAgent.log");
    let absent = synthetic_marker("missing-one", "PolicyAgent.log", SccmCoverageState::Absent);

    assert_eq!(
        assess_client_intake(&SccmClientIntakeBundle {
            artifacts: vec![captured.clone(), absent.clone()],
            capture_gaps: Vec::new(),
        }),
        Err(SccmClientIntakeError::CollidingPhysicalIdentity),
        "an unpinned absent marker for a captured source is a self-contradiction"
    );
    assert_eq!(
        assess_client_intake(&SccmClientIntakeBundle {
            artifacts: vec![absent, captured],
            capture_gaps: Vec::new(),
        }),
        Err(SccmClientIntakeError::CollidingPhysicalIdentity),
        "declaration order must not reopen the marker-versus-physical collision"
    );
}

#[test]
fn pinned_markers_for_distinct_roots_coexist_with_physical_evidence() {
    // The basename and rotation are not a complete source identity when
    // both declarations carry distinct configured-root fingerprints.
    for marker_coverage in [
        SccmCoverageState::Absent,
        SccmCoverageState::AccessDenied,
        SccmCoverageState::Skipped,
    ] {
        let captured = synthetic_artifact("policy", "PolicyAgent.log");
        let mut pinned =
            synthetic_marker("missing-one", "PolicyAgent.log", marker_coverage.clone());
        pinned.path_fingerprint = Some("synthetic:policy-root-b".to_owned());

        let intake = assess_client_intake(&SccmClientIntakeBundle {
            artifacts: vec![captured.clone(), pinned.clone()],
            capture_gaps: Vec::new(),
        })
        .expect("distinct configured roots remain distinct sources");
        assert_eq!(intake.physical_artifacts.len(), 1);
        assert_eq!(
            intake
                .group("client-policy-agent")
                .expect("policy group")
                .coverage,
            marker_coverage
        );

        assess_client_intake(&SccmClientIntakeBundle {
            artifacts: vec![pinned, captured],
            capture_gaps: Vec::new(),
        })
        .expect("declaration order must not collapse distinct roots");
    }

    let mut capped = synthetic_artifact("capped-one", "PolicyAgent.log");
    capped.artifact.coverage = SccmCoverageState::Capped;
    capped.fragment_complete = Some(false);
    let mut pinned = synthetic_marker("missing-one", "PolicyAgent.log", SccmCoverageState::Absent);
    pinned.path_fingerprint = Some("synthetic:policy-root-b".to_owned());
    let intake = assess_client_intake(&SccmClientIntakeBundle {
        artifacts: vec![capped, pinned],
        capture_gaps: Vec::new(),
    })
    .expect("a capped root and absent sibling root are both preserved");
    assert_eq!(
        intake
            .group("client-policy-agent")
            .expect("policy group")
            .coverage,
        SccmCoverageState::Capped
    );
}

#[test]
fn a_marker_cannot_reuse_the_physical_source_fingerprint() {
    let captured = synthetic_artifact("policy", "PolicyAgent.log");
    let mut marker = synthetic_marker("missing-one", "PolicyAgent.log", SccmCoverageState::Absent);
    marker.path_fingerprint = captured.path_fingerprint.clone();

    assert_eq!(
        assess_client_intake(&SccmClientIntakeBundle {
            artifacts: vec![captured, marker],
            capture_gaps: Vec::new(),
        }),
        Err(SccmClientIntakeError::CollidingPhysicalIdentity)
    );
}

#[test]
fn unpinned_and_pinned_markers_for_the_same_source_fail_closed() {
    // A fingerprint-less marker claims the whole declared source, so it
    // must collide with any other declaration for that source identity,
    // including a marker pinned to one configured root. The sibling server
    // intake removes this ambiguity by making the path fingerprint
    // mandatory on every declaration; the client contract keeps optional
    // marker fingerprints for the committed all-absent fixture bundles, so
    // identity intersection is the fail-closed equivalent here. Documented
    // #319 native-manifest follow-up: reassess whether legacy marker mapping
    // can converge the client contract on mandatory fingerprints and remove
    // the remaining client/server asymmetry.
    let unpinned = synthetic_marker("missing-one", "PolicyAgent.log", SccmCoverageState::Absent);
    let mut pinned = synthetic_marker("missing-two", "PolicyAgent.log", SccmCoverageState::Absent);
    pinned.path_fingerprint = Some("synthetic:policy-root-a".to_owned());

    assert_eq!(
        assess_client_intake(&SccmClientIntakeBundle {
            artifacts: vec![unpinned.clone(), pinned.clone()],
            capture_gaps: Vec::new(),
        }),
        Err(SccmClientIntakeError::DuplicateArtifactId),
        "an unpinned and a pinned marker must not double-declare one source"
    );
    assert_eq!(
        assess_client_intake(&SccmClientIntakeBundle {
            artifacts: vec![pinned, unpinned],
            capture_gaps: Vec::new(),
        }),
        Err(SccmClientIntakeError::DuplicateArtifactId),
        "declaration order must not reopen the marker double-declaration"
    );
}

#[test]
fn markers_for_distinct_rotations_of_a_captured_source_remain_representable() {
    // The collision is scoped to one source identity: a marker for a
    // genuinely distinct source (here the numbered rotation of the same
    // basename) still coexists with the captured current rotation and
    // surfaces as a per-source gap that the fragments array corroborates.
    let captured = synthetic_artifact("policy", "PolicyAgent.log");
    let mut rotated_absent = synthetic_marker(
        "missing-one",
        "PolicyAgent.log.2",
        SccmCoverageState::Absent,
    );
    rotated_absent.artifact.rotation = SccmRotation::Numbered(2);

    let intake = assess_client_intake(&SccmClientIntakeBundle {
        artifacts: vec![captured, rotated_absent],
        capture_gaps: Vec::new(),
    })
    .expect("a marker for a distinct rotation of a captured source stays representable");

    let group = intake.group("client-policy-agent").expect("policy group");
    assert_eq!(group.coverage, SccmCoverageState::Absent);
    assert_eq!(group.fragments.len(), 2);

    let gaps: Vec<_> = intake
        .coverage_gaps
        .iter()
        .filter(|gap| gap.logical_artifact_id == "client-policy-agent")
        .collect();
    assert_eq!(gaps.len(), 1, "one per-source gap for the absent rotation");
    assert_eq!(gaps[0].coverage, SccmCoverageState::Absent);
    assert_eq!(gaps[0].artifact_id.as_deref(), Some("fixture-missing-one"));
    assert_eq!(
        gaps[0].reason,
        "No artifact for client source PolicyAgent.log.2 was supplied."
    );
}

#[test]
fn basename_collisions_preserve_distinct_artifacts_and_bundle_paths() {
    let intake = assessment("collision");
    let group = intake
        .group("client-app-enforce")
        .expect("app enforcement group");
    assert_eq!(group.fragments.len(), 2);
    assert_eq!(
        group
            .fragments
            .iter()
            .map(|fragment| fragment.artifact_id.as_str())
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        2
    );
    assert_eq!(
        group
            .fragments
            .iter()
            .filter_map(|fragment| fragment.relative_path.as_deref())
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        2
    );
}

#[test]
fn unknown_and_lookalike_names_are_retained_as_unsupported_not_reclassified() {
    let bundle = SccmClientIntakeBundle {
        artifacts: vec![
            synthetic_artifact("custom", "CustomVendorHook.log"),
            synthetic_artifact("lookalike", "PolicyAgent.log.backup"),
            synthetic_artifact("unknown-lo", "CustomVendorHook.lo_"),
        ],
        capture_gaps: Vec::new(),
    };
    let intake = assess_client_intake(&bundle).expect("unknown intake");

    assert_eq!(intake.unsupported_artifacts.len(), 3);
    assert!(intake
        .unsupported_artifacts
        .iter()
        .all(|unknown| unknown.classification == SccmCoverageState::Unsupported));
    assert!(intake
        .group("client-policy-agent")
        .expect("policy group")
        .fragments
        .is_empty());
}

#[test]
fn malformed_rotation_and_public_provenance_values_fail_closed() {
    // The relative path is consistent with the declared rotation so the
    // malformed timestamp grammar is the only contract this input violates.
    let mut invalid_rotation = synthetic_artifact("invalid-rotation", "AppEnforce.log.2026-bad");
    invalid_rotation.artifact.rotation = SccmRotation::Timestamped("2026-bad".to_owned());
    invalid_rotation.relative_path =
        Some("evidence/client-app-enforce/timestamped-2026-bad/AppEnforce.log.2026-bad".to_owned());
    assert_eq!(
        assess_client_intake(&SccmClientIntakeBundle {
            artifacts: vec![invalid_rotation],
            capture_gaps: Vec::new(),
        }),
        Err(SccmClientIntakeError::InvalidRotation),
        "a malformed rotation timestamp must fail on the rotation contract"
    );

    let mut unsafe_basename =
        synthetic_artifact("unsafe-basename", r"C:\Users\RealUser\PolicyAgent.log");
    unsafe_basename.relative_path =
        Some("evidence/unknown/unsafe-basename/PolicyAgent.log".to_owned());
    assert_eq!(
        assess_client_intake(&SccmClientIntakeBundle {
            artifacts: vec![unsafe_basename],
            capture_gaps: Vec::new(),
        }),
        Err(SccmClientIntakeError::InvalidBasename),
        "a path-bearing basename must fail on the basename contract"
    );

    let mut invalid_time = synthetic_artifact("invalid-time", "PolicyAgent.log");
    invalid_time.artifact.collected_at_utc = Some(r"C:\Users\RealUser".to_owned());
    invalid_time.relative_path = Some("evidence/client-policy-agent/PolicyAgent.log".to_owned());
    assert_eq!(
        assess_client_intake(&SccmClientIntakeBundle {
            artifacts: vec![invalid_time],
            capture_gaps: Vec::new(),
        }),
        Err(SccmClientIntakeError::InvalidCollectedAt),
        "a non-RFC-3339 collection timestamp must fail on the timestamp contract"
    );

    let mut invalid_version = synthetic_artifact("invalid-version", "PolicyAgent.log");
    invalid_version.artifact.configmgr_version = Some("5.00.TEST/C:\\RealUser".to_owned());
    invalid_version.relative_path = Some("evidence/client-policy-agent/PolicyAgent.log".to_owned());
    assert_eq!(
        assess_client_intake(&SccmClientIntakeBundle {
            artifacts: vec![invalid_version],
            capture_gaps: Vec::new(),
        }),
        Err(SccmClientIntakeError::InvalidConfigMgrVersion),
        "an unsafe ConfigMgr version must fail on the version contract"
    );
}

#[test]
fn configmgr_version_and_encoding_use_bounded_public_grammars() {
    for version in ["5.00.9128.1007", "5.00.TEST.0000", "5.00.UNKNOWN.0000"] {
        let mut artifact = synthetic_artifact("valid-version", "PolicyAgent.log");
        artifact.artifact.configmgr_version = Some(version.to_owned());
        assert!(
            assess_client_intake(&SccmClientIntakeBundle {
                artifacts: vec![artifact],
                capture_gaps: Vec::new(),
            })
            .is_ok(),
            "documented ConfigMgr version {version} should remain representable"
        );
    }

    for version in [
        "realuser",
        "corp-example-test",
        "domain-example-test",
        r"5.00.C:\Users\RealUser",
        "5.00.TEST.\0",
    ] {
        let mut artifact = synthetic_artifact("invalid-version", "PolicyAgent.log");
        artifact.artifact.configmgr_version = Some(version.to_owned());
        assert_eq!(
            assess_client_intake(&SccmClientIntakeBundle {
                artifacts: vec![artifact],
                capture_gaps: Vec::new(),
            }),
            Err(SccmClientIntakeError::InvalidConfigMgrVersion),
            "unsafe ConfigMgr version {version:?} must fail closed"
        );
    }

    for encoding in ["utf-8", "utf-16le", "utf-16be", "windows-1252"] {
        let mut artifact = synthetic_artifact("valid-version", "PolicyAgent.log");
        artifact.artifact.encoding = Some(encoding.to_owned());
        assert!(
            assess_client_intake(&SccmClientIntakeBundle {
                artifacts: vec![artifact],
                capture_gaps: Vec::new(),
            })
            .is_ok(),
            "supported encoding {encoding} should remain representable"
        );
    }

    for encoding in [
        "realuser",
        "corp-example-test",
        "domain-example-test",
        r"C:\Users\RealUser",
        "utf-8\0realuser",
    ] {
        let mut artifact = synthetic_artifact("invalid-version", "PolicyAgent.log");
        artifact.artifact.encoding = Some(encoding.to_owned());
        assert_eq!(
            assess_client_intake(&SccmClientIntakeBundle {
                artifacts: vec![artifact],
                capture_gaps: Vec::new(),
            }),
            Err(SccmClientIntakeError::InvalidEncoding),
            "unsafe encoding {encoding:?} must fail closed"
        );
    }
}

#[test]
fn unknown_rotation_public_metadata_is_versioned_and_opaque() {
    let opaque_handle = format!("sha256:{}", "a".repeat(64));
    for kind in [
        "realuser".to_owned(),
        "corp-example-test".to_owned(),
        "realuser.example.com".to_owned(),
        r"C:\Users\RealUser".to_owned(),
        "cmtraceopen.rotation.opaque.v1\0".to_owned(),
        "x".repeat(129),
    ] {
        let mut artifact = synthetic_artifact("invalid-rotation", "PolicyAgent.log");
        artifact.artifact.rotation = SccmRotation::Unknown(SccmUnknownRotation {
            kind,
            value: Some(serde_json::json!("opaque-v1")),
        });
        artifact.relative_path = Some("evidence/unknown/PolicyAgent.log".to_owned());
        assert_eq!(
            assess_client_intake(&SccmClientIntakeBundle {
                artifacts: vec![artifact],
                capture_gaps: Vec::new(),
            }),
            Err(SccmClientIntakeError::InvalidRotation)
        );
    }

    for value in [
        serde_json::json!("realuser"),
        serde_json::json!("corp-example-test"),
        serde_json::json!("realuser.example.com"),
        serde_json::json!(r"C:\Users\RealUser"),
        serde_json::json!("opaque\0realuser"),
        serde_json::json!("x".repeat(129)),
        serde_json::json!(123456789),
        serde_json::json!({"opaque": "realuser"}),
    ] {
        let mut artifact = synthetic_artifact("invalid-rotation", "PolicyAgent.log");
        artifact.artifact.rotation = SccmRotation::Unknown(SccmUnknownRotation {
            kind: "cmtraceopen.rotation.opaque.v1".to_owned(),
            value: Some(value),
        });
        artifact.relative_path = Some("evidence/unknown/PolicyAgent.log".to_owned());
        assert_eq!(
            assess_client_intake(&SccmClientIntakeBundle {
                artifacts: vec![artifact],
                capture_gaps: Vec::new(),
            }),
            Err(SccmClientIntakeError::InvalidRotation)
        );
    }

    let mut future = synthetic_artifact("custom", "PolicyAgent.log");
    future.artifact.rotation = SccmRotation::Unknown(SccmUnknownRotation {
        kind: "cmtraceopen.rotation.opaque.v1".to_owned(),
        value: Some(serde_json::json!(opaque_handle)),
    });
    future.relative_path = Some("evidence/unknown/PolicyAgent.log".to_owned());
    let assessed = assess_client_intake(&SccmClientIntakeBundle {
        artifacts: vec![future],
        capture_gaps: Vec::new(),
    })
    .expect("versioned opaque future rotation remains representable");
    assert_eq!(assessed.unsupported_artifacts.len(), 1);
}

#[test]
fn distinct_opaque_unknown_rotations_do_not_collapse_to_one_source_identity() {
    let mut captured = synthetic_artifact("unknown-a", "PolicyAgent.log");
    captured.artifact.rotation = SccmRotation::Unknown(SccmUnknownRotation {
        kind: "cmtraceopen.rotation.opaque.v1".to_owned(),
        value: Some(serde_json::json!(format!("sha256:{}", "a".repeat(64)))),
    });
    captured.relative_path = Some("evidence/unknown/PolicyAgent.log".to_owned());

    let mut unavailable = synthetic_marker(
        "unknown-b",
        "PolicyAgent.log",
        SccmCoverageState::AccessDenied,
    );
    unavailable.artifact.rotation = SccmRotation::Unknown(SccmUnknownRotation {
        kind: "cmtraceopen.rotation.opaque.v1".to_owned(),
        value: Some(serde_json::json!(format!("sha256:{}", "b".repeat(64)))),
    });

    let intake = assess_client_intake(&SccmClientIntakeBundle {
        artifacts: vec![captured, unavailable],
        capture_gaps: Vec::new(),
    })
    .expect("distinct opaque rotations remain distinct declarations");

    assert_eq!(intake.unsupported_artifacts.len(), 2);
    assert_ne!(
        intake.unsupported_artifacts[0].rotation,
        intake.unsupported_artifacts[1].rotation
    );
}

#[test]
fn caller_controlled_public_identity_channels_fail_closed() {
    for artifact_id in [
        "client-realuser",
        "client-corp-example-test",
        "realuser",
        "fixture-123-45-6789",
    ] {
        let mut artifact = synthetic_artifact("invalid-artifact", "PolicyAgent.log");
        artifact.artifact.artifact_id = artifact_id.to_owned();
        artifact.path_fingerprint = Some("synthetic:policy-current".to_owned());
        assert_eq!(
            assess_client_intake(&SccmClientIntakeBundle {
                artifacts: vec![artifact],
                capture_gaps: Vec::new(),
            }),
            Err(SccmClientIntakeError::InvalidArtifactId),
            "identity-bearing artifact ID {artifact_id:?} reached public output"
        );
    }

    for basename in [
        "RealUser.log",
        "corp-example-test.log",
        "realuser.example.test.log",
    ] {
        let mut artifact = synthetic_artifact("custom", basename);
        artifact.relative_path = Some(format!("evidence/unknown/current/{basename}"));
        assert_eq!(
            assess_client_intake(&SccmClientIntakeBundle {
                artifacts: vec![artifact],
                capture_gaps: Vec::new(),
            }),
            Err(SccmClientIntakeError::InvalidBasename),
            "identity-bearing unsupported basename {basename:?} reached public output"
        );
    }

    for relative_path in [
        "evidence/client-policy-agent/current/RealUser.log",
        "evidence/client-policy-agent/current/corp-example-test.log",
        "evidence/client-content/current/PolicyAgent.log",
        "evidence/client-policy-agent/lo/PolicyAgent.log",
    ] {
        let mut artifact = synthetic_artifact("invalid-relative", "PolicyAgent.log");
        artifact.relative_path = Some(relative_path.to_owned());
        assert_eq!(
            assess_client_intake(&SccmClientIntakeBundle {
                artifacts: vec![artifact],
                capture_gaps: Vec::new(),
            }),
            Err(SccmClientIntakeError::InvalidRelativePath),
            "relative path was not bound to its canonical source: {relative_path:?}"
        );
    }

    let mut mixed_case = synthetic_artifact("invalid-basename", "policyagent.log");
    mixed_case.relative_path =
        Some("evidence/client-policy-agent/current/policyagent.log".to_owned());
    assert_eq!(
        assess_client_intake(&SccmClientIntakeBundle {
            artifacts: vec![mixed_case],
            capture_gaps: Vec::new(),
        }),
        Err(SccmClientIntakeError::InvalidBasename),
        "supported source names must use their exact canonical spelling"
    );
}

#[test]
fn public_identity_contract_retains_only_reviewed_synthetic_and_opaque_forms() {
    let mut native = synthetic_artifact("valid-version", "PolicyAgent.log");
    native.artifact.artifact_id = format!("sccm-artifact:v1:sha256:{}", "a".repeat(64));
    assert!(assess_client_intake(&SccmClientIntakeBundle {
        artifacts: vec![native],
        capture_gaps: Vec::new(),
    })
    .is_ok());

    let opaque_basename = format!("sccm-unknown-v1-sha256-{}.log", "b".repeat(64));
    let mut unknown = synthetic_artifact("custom", &opaque_basename);
    unknown.relative_path = Some(format!("evidence/unknown/current/{opaque_basename}"));
    let unknown = assess_client_intake(&SccmClientIntakeBundle {
        artifacts: vec![unknown],
        capture_gaps: Vec::new(),
    })
    .expect("opaque unsupported source remains representable");
    assert_eq!(unknown.unsupported_artifacts.len(), 1);

    let mut raw_context = synthetic_artifact("valid-version", "PolicyAgent.log");
    raw_context.artifact.original_path = Some(r"C:\Users\RealUser\PolicyAgent.log".to_owned());
    raw_context.artifact.host = Some("host-only-sentinel.corp.example.test".to_owned());
    let serialized = serde_json::to_string(
        &assess_client_intake(&SccmClientIntakeBundle {
            artifacts: vec![raw_context],
            capture_gaps: Vec::new(),
        })
        .expect("raw native context is intentionally not projected"),
    )
    .expect("assessment serializes");
    let serialized_casefolded = serialized.to_ascii_lowercase();
    assert!(!serialized_casefolded.contains("realuser"));
    assert!(!serialized_casefolded.contains("host-only-sentinel"));
    assert!(!serialized_json_contains_windows_user_root(
        &serialized_casefolded
    ));

    let mut oversized_timestamp = synthetic_artifact("invalid-time", "PolicyAgent.log");
    oversized_timestamp.artifact.collected_at_utc =
        Some(format!("2026-07-30T00:00:00.{}Z", "1".repeat(256)));
    assert_eq!(
        assess_client_intake(&SccmClientIntakeBundle {
            artifacts: vec![oversized_timestamp],
            capture_gaps: Vec::new(),
        }),
        Err(SccmClientIntakeError::InvalidCollectedAt)
    );
}

#[test]
fn fragment_completeness_and_every_path_fingerprint_are_explicit_and_unambiguous() {
    let mut missing_completeness = synthetic_artifact("missing-completeness", "PolicyAgent.log");
    missing_completeness.relative_path =
        Some("evidence/client-policy-agent/PolicyAgent.log".to_owned());
    missing_completeness.fragment_complete = None;
    assert_eq!(
        assess_client_intake(&SccmClientIntakeBundle {
            artifacts: vec![missing_completeness],
            capture_gaps: Vec::new(),
        }),
        Err(SccmClientIntakeError::MissingFragmentCompleteness),
        "fragment completeness must be an explicit declaration"
    );

    // A non-physical marker keeping fragmentComplete=true invents a physical
    // capture it does not have; markers carry no bytes that could be
    // complete, so the completeness contract is the check that fails.
    let mut invented_physical_state = synthetic_artifact("denied", "PolicyAgent.log");
    invented_physical_state.artifact.coverage = SccmCoverageState::AccessDenied;
    invented_physical_state.relative_path = None;
    assert_eq!(
        assess_client_intake(&SccmClientIntakeBundle {
            artifacts: vec![invented_physical_state],
            capture_gaps: Vec::new(),
        }),
        Err(SccmClientIntakeError::InvalidFragmentCompleteness),
        "a marker claiming a complete fragment invents a physical capture"
    );

    // The mirror image: a physical capture stripped of its collision-safe
    // bundle path must fail on the provenance contract.
    let mut missing_provenance = synthetic_artifact("missing-path", "PolicyAgent.log");
    missing_provenance.relative_path = None;
    assert_eq!(
        assess_client_intake(&SccmClientIntakeBundle {
            artifacts: vec![missing_provenance],
            capture_gaps: Vec::new(),
        }),
        Err(SccmClientIntakeError::MissingPhysicalProvenance),
        "a physical capture without its bundle path lacks required provenance"
    );

    let mut first = synthetic_artifact("denied-one", "PolicyAgent.log");
    first.artifact.coverage = SccmCoverageState::AccessDenied;
    first.relative_path = None;
    first.fragment_complete = Some(false);
    let mut second = synthetic_artifact("denied-two", "CIAgent.log");
    second.artifact.coverage = SccmCoverageState::AccessDenied;
    second.relative_path = None;
    second.fragment_complete = Some(false);
    second.path_fingerprint = first.path_fingerprint.clone();
    assert_eq!(
        assess_client_intake(&SccmClientIntakeBundle {
            artifacts: vec![first, second],
            capture_gaps: Vec::new(),
        }),
        Err(SccmClientIntakeError::CollidingPhysicalIdentity),
        "two markers must not share one path fingerprint"
    );
}

#[test]
fn unsupported_physical_artifacts_retain_safe_provenance_without_raw_host_or_path() {
    let mut artifact = synthetic_artifact("custom", "CustomVendorHook.log");
    artifact.artifact.original_path = Some(r"C:\Users\RealUser\CustomVendorHook.log".to_owned());
    artifact.artifact.host = Some("real-user-host.example".to_owned());
    let intake = assess_client_intake(&SccmClientIntakeBundle {
        artifacts: vec![artifact],
        capture_gaps: Vec::new(),
    })
    .expect("unknown physical artifact remains representable");
    let serialized = serde_json::to_string(&intake).expect("intake JSON");
    let serialized_casefolded = serialized.to_ascii_lowercase();

    // The positive assertions deliberately keep the original case: the
    // projection must reproduce the declared basename exactly. Every leak
    // assertion below is casefolded instead, so a projection that
    // normalized case could not smuggle an identity past this site.
    assert!(serialized.contains("synthetic-custom"));
    assert!(serialized.contains("evidence/unknown/CustomVendorHook.log"));
    assert!(!serialized_casefolded.contains("realuser"));
    assert!(!serialized_casefolded.contains("real-user-host"));
    assert!(!serialized_json_contains_windows_user_root(
        &serialized_casefolded
    ));
}

#[test]
fn ambiguous_identity_or_nonclient_role_fails_closed() {
    // The collision fixture declares one basename under two configured roots,
    // so each artifact stays individually well formed and only the identity
    // channel under test collides.
    let mut duplicate = load_bundle("collision");
    duplicate.artifacts[1].artifact.artifact_id =
        duplicate.artifacts[0].artifact.artifact_id.clone();
    assert_eq!(
        assess_client_intake(&duplicate),
        Err(SccmClientIntakeError::DuplicateArtifactId),
        "two artifacts must not share one caller identity"
    );

    let mut duplicate_path = load_bundle("collision");
    duplicate_path.artifacts[1].relative_path = duplicate_path.artifacts[0].relative_path.clone();
    assert_eq!(
        assess_client_intake(&duplicate_path),
        Err(SccmClientIntakeError::CollidingPhysicalIdentity),
        "two captures must not share one bundle-relative evidence path"
    );

    let mut wrong_role = load_bundle("complete");
    wrong_role.artifacts[0].artifact.role = SccmRole::ManagementPoint;
    assert_eq!(
        assess_client_intake(&wrong_role),
        Err(SccmClientIntakeError::RoleMismatch),
        "client intake must reject a non-client role outright"
    );
}

#[test]
fn identity_bearing_relative_paths_fail_before_public_projection() {
    let unsafe_relative_paths = [
        (
            "PolicyAgent.log",
            SccmRotation::Current,
            "evidence/client-RealUser/PolicyAgent.log",
        ),
        (
            "PolicyAgent.log",
            SccmRotation::Current,
            "evidence/client-corp-example-test/PolicyAgent.log",
        ),
        (
            "AppEnforce.log",
            SccmRotation::Current,
            "evidence/client-app-enforce/root-realuser/current/AppEnforce.log",
        ),
        (
            "AppEnforce.log",
            SccmRotation::Current,
            "evidence/client-app-enforce/root-corp-example-test/current/AppEnforce.log",
        ),
        (
            "PolicyAgent.log",
            SccmRotation::Current,
            "evidence/client-policy-agent/RealUser@example.test/PolicyAgent.log",
        ),
        (
            "PolicyAgent.log",
            SccmRotation::Current,
            "evidence/client-policy-agent/Users/RealUser/PolicyAgent.log",
        ),
        (
            "PolicyAgent.log",
            SccmRotation::Current,
            "evidence/client-policy-agent/home/real-user/PolicyAgent.log",
        ),
        (
            "PolicyAgent.log",
            SccmRotation::Current,
            "evidence/client-policy-agent/corp.example.test/PolicyAgent.log",
        ),
        (
            "PolicyAgent.log",
            SccmRotation::Current,
            "evidence/client-policy-agent/profile=RealUser/PolicyAgent.log",
        ),
        (
            "PolicyAgent.log",
            SccmRotation::Current,
            "evidence/client-policy-agent/LAB%5CRealUser/PolicyAgent.log",
        ),
        (
            "PolicyAgent.log",
            SccmRotation::Current,
            "evidence/client-policy-agent/Real User/PolicyAgent.log",
        ),
        (
            "PolicyAgent.log",
            SccmRotation::Current,
            "evidence/client-policy-agent/résumé-real-user/PolicyAgent.log",
        ),
        (
            "PolicyAgent.log",
            SccmRotation::Current,
            "evidence/client-policy-agent/\0/PolicyAgent.log",
        ),
        (
            "PolicyAgent.log",
            SccmRotation::Current,
            "evidence/client-policy-agent/../PolicyAgent.log",
        ),
        (
            "PolicyAgent.log",
            SccmRotation::Current,
            "evidence/client-policy-agent/..",
        ),
        (
            "PolicyAgent.log",
            SccmRotation::Current,
            "evidence/client-policy-agent/.",
        ),
        (
            "PolicyAgent.log",
            SccmRotation::Current,
            "/evidence/client-policy-agent/current/PolicyAgent.log",
        ),
        (
            "PolicyAgent.log",
            SccmRotation::Current,
            "evidence/client-policy-agent/C:/Users/RealUser/PolicyAgent.log",
        ),
        (
            "PolicyAgent.log",
            SccmRotation::Current,
            "evidence/client-policy-agent/LAB\\RealUser/PolicyAgent.log",
        ),
    ];

    for (display_name, rotation, relative_path) in unsafe_relative_paths {
        let mut artifact = synthetic_artifact("unsafe-relative", display_name);
        artifact.artifact.rotation = rotation;
        artifact.path_fingerprint = Some("synthetic:policy-current".to_owned());
        artifact.relative_path = Some(relative_path.to_owned());

        let result = assess_client_intake(&SccmClientIntakeBundle {
            artifacts: vec![artifact],
            capture_gaps: Vec::new(),
        });
        assert!(
            matches!(result, Err(SccmClientIntakeError::InvalidRelativePath)),
            "identity-bearing path reached the public assessment: {relative_path:?} => {result:?}"
        );
    }

    let mut malformed_timestamp =
        synthetic_artifact("unsafe-relative", "AppEnforce.log.20241340-296199");
    malformed_timestamp.artifact.rotation = SccmRotation::Timestamped("20241340-296199".to_owned());
    malformed_timestamp.path_fingerprint = Some("synthetic:app-enforce-current".to_owned());
    malformed_timestamp.relative_path = Some(
        "evidence/client-app-enforce/timestamped-20241340-296199/AppEnforce.log.20241340-296199"
            .to_owned(),
    );
    assert_eq!(
        assess_client_intake(&SccmClientIntakeBundle {
            artifacts: vec![malformed_timestamp],
            capture_gaps: Vec::new(),
        }),
        Err(SccmClientIntakeError::InvalidRotation),
        "malformed timestamp rotation must fail on its own metadata contract"
    );
}

#[test]
fn rotation_lineage_is_versioned_privacy_safe_and_bound_to_one_source() {
    let digest = "a".repeat(64);
    let mut opaque = synthetic_artifact("policy-a", "PolicyAgent.log");
    opaque.rotation_lineage = Some(format!("cmtraceopen.lineage.sha256.v1:{digest}"));
    assess_client_intake(&SccmClientIntakeBundle {
        artifacts: vec![opaque],
        capture_gaps: Vec::new(),
    })
    .expect("the versioned opaque lineage form is accepted");

    for lineage in [
        "",
        "synthetic:free-form-user-value",
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "cmtraceopen.lineage.sha256.v1:short",
        "cmtraceopen.lineage.sha256.v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        r"C:\Users\RealUser\CCM\Logs",
    ] {
        let mut artifact = synthetic_artifact("policy-a", "PolicyAgent.log");
        artifact.rotation_lineage = Some(lineage.to_owned());
        assert_eq!(
            assess_client_intake(&SccmClientIntakeBundle {
                artifacts: vec![artifact],
                capture_gaps: Vec::new(),
            }),
            Err(SccmClientIntakeError::InvalidRotationLineage),
            "unsafe lineage reached the public projection: {lineage:?}"
        );
    }

    let mut policy = synthetic_artifact("policy-a", "PolicyAgent.log");
    policy.rotation_lineage = Some("synthetic:policy-root-a".to_owned());
    let mut state = synthetic_artifact("state-b", "CIAgent.log");
    state.rotation_lineage = Some("synthetic:policy-root-a".to_owned());
    assert_eq!(
        assess_client_intake(&SccmClientIntakeBundle {
            artifacts: vec![policy, state],
            capture_gaps: Vec::new(),
        }),
        Err(SccmClientIntakeError::CollidingPhysicalIdentity),
        "one immutable lineage cannot be rebound to a different catalog source"
    );
}

#[test]
fn shared_location_services_path_binding_preserves_every_canonical_rotation() {
    let rotations = [
        ("LocationServices.log", SccmRotation::Current, "current"),
        ("LocationServices.lo_", SccmRotation::LoUnderscore, "lo"),
        (
            "LocationServices.log.2",
            SccmRotation::Numbered(2),
            "numbered-2",
        ),
        (
            "LocationServices.log.20260730-030405",
            SccmRotation::Timestamped("20260730-030405".to_owned()),
            "timestamped-20260730-030405",
        ),
    ];

    for (display_name, rotation, rotation_segment) in rotations {
        let mut artifact = synthetic_artifact("valid-location", display_name);
        artifact.artifact.rotation = rotation;
        artifact.path_fingerprint = Some("synthetic:location-services-current".to_owned());
        artifact.relative_path = Some(format!(
            "evidence/client-location-services-shared/{rotation_segment}/{display_name}"
        ));

        let assessment = assess_client_intake(&SccmClientIntakeBundle {
            artifacts: vec![artifact],
            capture_gaps: Vec::new(),
        })
        .unwrap_or_else(|error| {
            panic!(
                "canonical shared LocationServices rotation was rejected: {display_name}: {error}"
            )
        });

        assert_eq!(assessment.physical_artifacts.len(), 1);
        assert_eq!(
            assessment
                .group("client-content")
                .expect("content group")
                .fragments
                .len(),
            1
        );
        assert_eq!(
            assessment
                .group("client-location")
                .expect("location group")
                .fragments
                .len(),
            1
        );
    }
}

#[test]
fn unsafe_path_fingerprints_fail_before_public_projection() {
    let unsafe_fingerprints = [
        "realuser",
        "corp-example-test",
        "domain-example-test",
        "md5:0123456789abcdef",
        "sha256:not-a-hex-handle",
        "synthetic:realuser",
        "synthetic:RealUser",
        "synthetic:corp-example-test",
        "synthetic-RealUser",
        "synthetic:123:45:6789",
        "synthetic-123-45-6789",
        "synthetic\0raw-user",
        "synthetic\u{7f}raw-user",
        "synthetic-résumé-user",
        "synthetic=raw-user",
        "synthetic%5craw-user",
        "synthetic/raw-user",
        "synthetic\\raw-user",
        "synthetic@raw-user",
        "synthetic raw-user",
    ];

    for fingerprint in unsafe_fingerprints {
        let mut artifact = synthetic_artifact("unsafe-fingerprint", "PolicyAgent.log");
        artifact.relative_path =
            Some("evidence/client-policy-agent/current/PolicyAgent.log".to_owned());
        artifact.path_fingerprint = Some(fingerprint.to_owned());

        let result = assess_client_intake(&SccmClientIntakeBundle {
            artifacts: vec![artifact],
            capture_gaps: Vec::new(),
        });
        assert!(
            matches!(result, Err(SccmClientIntakeError::InvalidPathFingerprint)),
            "unsafe fingerprint reached the public assessment: {fingerprint:?} => {result:?}"
        );
    }
}

#[test]
fn sha256_path_fingerprints_require_exactly_64_lowercase_hex_characters() {
    for digest in [
        "a".repeat(16),
        "a".repeat(63),
        "a".repeat(65),
        "A".repeat(64),
        "g".repeat(64),
    ] {
        let mut artifact = synthetic_artifact("unsafe-fingerprint", "PolicyAgent.log");
        artifact.path_fingerprint = Some(format!("sha256:{digest}"));

        assert_eq!(
            assess_client_intake(&SccmClientIntakeBundle {
                artifacts: vec![artifact],
                capture_gaps: Vec::new(),
            }),
            Err(SccmClientIntakeError::InvalidPathFingerprint),
            "invalid SHA-256 digest was accepted: {digest:?}"
        );
    }

    let mut artifact = synthetic_artifact("approved-fingerprint", "PolicyAgent.log");
    artifact.path_fingerprint = Some(format!("sha256:{}", "a".repeat(64)));
    assert!(assess_client_intake(&SccmClientIntakeBundle {
        artifacts: vec![artifact],
        capture_gaps: Vec::new(),
    })
    .is_ok());
}

#[test]
fn numbered_synthetic_path_fingerprints_accept_only_a_short_numeric_suffix() {
    let mut numbered = synthetic_artifact("approved-fingerprint", "AppEnforce.log.3");
    numbered.artifact.rotation = SccmRotation::Numbered(3);
    numbered.path_fingerprint = Some("synthetic:app-enforce-numbered-3".to_owned());
    numbered.relative_path =
        Some("evidence/client-app-enforce/numbered-3/AppEnforce.log.3".to_owned());
    assert!(assess_client_intake(&SccmClientIntakeBundle {
        artifacts: vec![numbered],
        capture_gaps: Vec::new(),
    })
    .is_ok());

    let mut oversized = synthetic_artifact("unsafe-fingerprint", "AppEnforce.log");
    oversized.path_fingerprint = Some("synthetic:app-enforce-numbered-123".to_owned());
    assert_eq!(
        assess_client_intake(&SccmClientIntakeBundle {
            artifacts: vec![oversized],
            capture_gaps: Vec::new(),
        }),
        Err(SccmClientIntakeError::InvalidPathFingerprint)
    );
}

#[test]
fn approved_namespaced_path_fingerprints_remain_accepted() {
    let approved_fingerprints = [
        "synthetic-root-a-current",
        "synthetic:policy-current",
        "synthetic:path:client-root-a",
        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    ];

    for fingerprint in approved_fingerprints {
        let mut artifact = synthetic_artifact("approved-fingerprint", "PolicyAgent.log");
        artifact.relative_path =
            Some("evidence/client-policy-agent/current/PolicyAgent.log".to_owned());
        artifact.path_fingerprint = Some(fingerprint.to_owned());

        assess_client_intake(&SccmClientIntakeBundle {
            artifacts: vec![artifact],
            capture_gaps: Vec::new(),
        })
        .unwrap_or_else(|error| panic!("approved fingerprint {fingerprint:?} failed: {error}"));
    }
}

#[test]
fn approved_collision_safe_relative_layouts_remain_accepted() {
    let approved_relative_paths = [
        (
            "PolicyAgent.log",
            SccmRotation::Current,
            "evidence/client-policy-agent/PolicyAgent.log",
        ),
        (
            "PolicyAgent.log",
            SccmRotation::Current,
            "evidence/client-policy-agent/current/PolicyAgent.log",
        ),
        (
            "LocationServices.log",
            SccmRotation::Current,
            "evidence/client-location-services-shared/current/LocationServices.log",
        ),
        (
            "AppEnforce.log",
            SccmRotation::Current,
            "evidence/client-app-enforce/root-a/current/AppEnforce.log",
        ),
        (
            "AppEnforce.log",
            SccmRotation::Current,
            "evidence/client-app-enforce/root-0123456789abcdef/current/AppEnforce.log",
        ),
        (
            "AppEnforce.log.2",
            SccmRotation::Numbered(2),
            "evidence/client-app-enforce/numbered-2/AppEnforce.log.2",
        ),
        (
            "AppEnforce.log.20260730-030405",
            SccmRotation::Timestamped("20260730-030405".to_owned()),
            "evidence/client-app-enforce/timestamped-20260730-030405/AppEnforce.log.20260730-030405",
        ),
        (
            "AppEnforce.log",
            SccmRotation::Current,
            "evidence/sccm/client/client-app-enforce/current/AppEnforce.log",
        ),
        (
            "CustomVendorHook.log",
            SccmRotation::Current,
            "evidence/unknown/CustomVendorHook.log",
        ),
    ];

    for (display_name, rotation, relative_path) in approved_relative_paths {
        let mut artifact = synthetic_artifact("approved-relative", display_name);
        artifact.artifact.rotation = rotation;
        artifact.path_fingerprint = Some("synthetic:policy-current".to_owned());
        artifact.relative_path = Some(relative_path.to_owned());

        assess_client_intake(&SccmClientIntakeBundle {
            artifacts: vec![artifact],
            capture_gaps: Vec::new(),
        })
        .unwrap_or_else(|error| panic!("approved path {relative_path:?} failed: {error}"));
    }
}
