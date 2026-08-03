use cmtraceopen_parser::sccm::{
    assess_client_health_coverage, SccmArtifact, SccmClientIntakeArtifact, SccmClientIntakeBundle,
    SccmClientIntakeCaptureGap, SccmClientIntakeError, SccmCoverageState, SccmRole, SccmRotation,
};
use serde::Deserialize;
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};

fn captured_health_artifact(id: &str, basename: &str) -> SccmClientIntakeArtifact {
    let group = match basename {
        "ccmsetup.log" => "client-ccmsetup",
        "CcmEval.log" => "client-evaluation",
        "ClientIDManagerStartup.log" => "client-identity",
        "LocationServices.log" => "client-location-services-shared",
        _ => panic!("unsupported health fixture source {basename}"),
    };

    SccmClientIntakeArtifact {
        artifact: SccmArtifact {
            artifact_id: format!("fixture-{id}"),
            display_name: basename.to_owned(),
            original_path: None,
            host: None,
            role: SccmRole::Client,
            configmgr_version: Some("5.00.TEST.0000".to_owned()),
            collected_at_utc: Some("2026-08-03T00:00:00Z".to_owned()),
            rotation: SccmRotation::Current,
            coverage: SccmCoverageState::Captured,
            encoding: Some("utf-8".to_owned()),
        },
        path_fingerprint: Some(format!("synthetic:health-{id}")),
        rotation_lineage: None,
        relative_path: Some(format!("evidence/{group}/current/{basename}")),
        fragment_complete: Some(true),
        declared_byte_length: None,
        content_sha256: None,
    }
}

fn captured_health_bundle() -> SccmClientIntakeBundle {
    SccmClientIntakeBundle {
        artifacts: vec![
            captured_health_artifact("health-setup", "ccmsetup.log"),
            captured_health_artifact("health-evaluation", "CcmEval.log"),
            captured_health_artifact("health-identity", "ClientIDManagerStartup.log"),
            captured_health_artifact("health-location", "LocationServices.log"),
        ],
        capture_gaps: Vec::new(),
    }
}

fn with_source_coverage(
    mut bundle: SccmClientIntakeBundle,
    source_index: usize,
    coverage: SccmCoverageState,
) -> SccmClientIntakeBundle {
    let source = &mut bundle.artifacts[source_index];
    source.artifact.coverage = coverage.clone();
    match coverage {
        SccmCoverageState::Captured => source.fragment_complete = Some(true),
        SccmCoverageState::Capped => source.fragment_complete = Some(false),
        SccmCoverageState::ParseFailed => source.fragment_complete = Some(true),
        SccmCoverageState::Absent
        | SccmCoverageState::AccessDenied
        | SccmCoverageState::Skipped
        | SccmCoverageState::Unsupported => {
            source.artifact.encoding = None;
            source.relative_path = None;
            source.fragment_complete = Some(false);
        }
    }
    bundle
}

#[test]
fn all_captured_health_coverage_is_complete_without_a_health_verdict() {
    let bundle = captured_health_bundle();

    let readiness = assess_client_health_coverage(&bundle)
        .expect("four captured health sources form a valid intake bundle");

    assert_eq!(
        serde_json::to_value(readiness).expect("coverage readiness serializes"),
        json!({
            "workflow": "health",
            "sourceGroups": [
                {"logicalArtifactId": "client-ccmsetup", "coverage": "captured"},
                {"logicalArtifactId": "client-evaluation", "coverage": "captured"},
                {"logicalArtifactId": "client-identity", "coverage": "captured"},
                {"logicalArtifactId": "client-location", "coverage": "captured"}
            ],
            "coverageGaps": [],
            "coverageComplete": true,
            "nextRequiredSourceGroup": null
        }),
        "complete coverage must only report the fixed health coverage contract"
    );
}

#[test]
fn health_coverage_preserves_every_non_captured_source_state() {
    let cases = [
        (SccmCoverageState::Absent, "absent"),
        (SccmCoverageState::AccessDenied, "accessDenied"),
        (SccmCoverageState::Capped, "capped"),
        (SccmCoverageState::Skipped, "skipped"),
        (SccmCoverageState::Unsupported, "unsupported"),
        (SccmCoverageState::ParseFailed, "parseFailed"),
    ];

    for (coverage, serialized_coverage) in cases {
        let readiness = assess_client_health_coverage(&with_source_coverage(
            captured_health_bundle(),
            0,
            coverage,
        ))
        .expect("each intake coverage state is a valid coverage-only health input");
        let value = serde_json::to_value(readiness).expect("coverage readiness serializes");

        assert_eq!(
            value["sourceGroups"][0],
            json!({"logicalArtifactId": "client-ccmsetup", "coverage": serialized_coverage}),
            "the health adapter must retain {serialized_coverage} instead of synthesizing a verdict"
        );
        assert_eq!(value["coverageComplete"], false);
        assert_eq!(
            value["nextRequiredSourceGroup"], "client-ccmsetup",
            "the first uncovered group is setup for every noncaptured setup state"
        );
        assert!(
            value["coverageGaps"]
                .as_array()
                .is_some_and(|gaps| gaps.iter().any(|gap| {
                    gap["logicalArtifactId"] == "client-ccmsetup"
                        && gap["coverage"] == serialized_coverage
                })),
            "the already-projected gap must retain the source state"
        );
    }
}

#[test]
fn health_coverage_selects_the_first_uncovered_group_in_phase_order() {
    for (source_index, expected_group) in [
        (0, "client-ccmsetup"),
        (1, "client-evaluation"),
        (2, "client-identity"),
        (3, "client-location"),
    ] {
        let readiness = assess_client_health_coverage(&with_source_coverage(
            captured_health_bundle(),
            source_index,
            SccmCoverageState::Absent,
        ))
        .expect("one missing health source remains valid intake");

        assert_eq!(
            serde_json::to_value(readiness).expect("coverage readiness serializes")
                ["nextRequiredSourceGroup"],
            expected_group,
            "setup, service, identity, and location must be considered in fixed phase order"
        );
    }
}

#[test]
fn health_coverage_is_deterministic_under_artifact_gap_reordering_and_versions() {
    let mut original = captured_health_bundle();
    original.capture_gaps = vec![
        SccmClientIntakeCaptureGap {
            artifact_id: "fixture-capped-rotation-numbered-1".to_owned(),
            basename: "PolicyAgent.log.1".to_owned(),
            rotation: SccmRotation::Numbered(1),
            coverage: SccmCoverageState::Capped,
            path_fingerprint: "synthetic-capped-rotation".to_owned(),
            rotation_lineage: "synthetic:capped-rotation".to_owned(),
        },
        SccmClientIntakeCaptureGap {
            artifact_id: "fixture-capped-rotation-numbered-2".to_owned(),
            basename: "PolicyAgent.log.2".to_owned(),
            rotation: SccmRotation::Numbered(2),
            coverage: SccmCoverageState::Capped,
            path_fingerprint: "synthetic-capped-rotation".to_owned(),
            rotation_lineage: "synthetic:capped-rotation".to_owned(),
        },
    ];
    let original_json = serde_json::to_value(
        assess_client_health_coverage(&original).expect("health gaps are valid intake metadata"),
    )
    .expect("coverage readiness serializes");

    let mut reordered = original.clone();
    reordered.artifacts.reverse();
    reordered.capture_gaps.reverse();
    let reordered_json = serde_json::to_value(
        assess_client_health_coverage(&reordered).expect("reordered intake remains valid"),
    )
    .expect("coverage readiness serializes");
    assert_eq!(reordered_json, original_json);

    let mut changed_versions = reordered;
    for artifact in &mut changed_versions.artifacts {
        artifact.artifact.configmgr_version = Some("5.00.1234.5678".to_owned());
    }
    let changed_version_json = serde_json::to_value(
        assess_client_health_coverage(&changed_versions)
            .expect("an arbitrary valid ConfigMgr version remains coverage-only"),
    )
    .expect("coverage readiness serializes");
    assert_eq!(changed_version_json, original_json);
}

#[test]
fn health_coverage_returns_the_original_intake_error_for_invalid_bundles() {
    let mut invalid = captured_health_bundle();
    invalid.artifacts[0].artifact.role = SccmRole::SiteServer;

    assert_eq!(
        assess_client_health_coverage(&invalid),
        Err(SccmClientIntakeError::RoleMismatch),
        "the adapter must validate through intake rather than accepting a caller-forged projection"
    );
}

const FIXTURE_ROOT: &str = "tests/fixtures/sccm/client/health";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct HealthFixtureManifest {
    artifacts: Vec<HealthFixtureArtifact>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct HealthFixtureArtifact {
    artifact_id: String,
    role: String,
    capture_state: String,
    encoding: Option<String>,
    original_basename: String,
    path_fingerprint: Option<String>,
    rotation: HealthFixtureRotation,
    source_version: Option<String>,
    captured_utc: Option<String>,
    relative_path: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct HealthFixtureRotation {
    kind: String,
    fragment_complete: Option<bool>,
}

fn fixture_directory(scenario: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(FIXTURE_ROOT)
        .join(scenario)
}

fn fixture_rotation(rotation: &HealthFixtureRotation) -> SccmRotation {
    match rotation.kind.as_str() {
        "current" => SccmRotation::Current,
        "lo" => SccmRotation::LoUnderscore,
        other => panic!("unsupported health fixture rotation {other}"),
    }
}

fn fixture_coverage(capture_state: &str) -> SccmCoverageState {
    match capture_state {
        "captured" => SccmCoverageState::Captured,
        "absent" => SccmCoverageState::Absent,
        "accessDenied" => SccmCoverageState::AccessDenied,
        "capped" => SccmCoverageState::Capped,
        "skipped" => SccmCoverageState::Skipped,
        "unsupported" => SccmCoverageState::Unsupported,
        "parseFailed" => SccmCoverageState::ParseFailed,
        other => panic!("unsupported health fixture coverage {other}"),
    }
}

fn load_fixture_bundle(scenario: &str) -> SccmClientIntakeBundle {
    let manifest_path = fixture_directory(scenario).join("manifest.json");
    let manifest: HealthFixtureManifest = serde_json::from_str(
        &fs::read_to_string(manifest_path).expect("health fixture manifest is readable"),
    )
    .expect("health fixture manifest is valid");

    SccmClientIntakeBundle {
        artifacts: manifest
            .artifacts
            .into_iter()
            .map(|fixture| {
                assert_eq!(fixture.role, "client");
                SccmClientIntakeArtifact {
                    artifact: SccmArtifact {
                        artifact_id: format!("fixture-{}", fixture.artifact_id),
                        display_name: fixture.original_basename,
                        original_path: None,
                        host: None,
                        role: SccmRole::Client,
                        configmgr_version: fixture.source_version,
                        collected_at_utc: fixture.captured_utc,
                        rotation: fixture_rotation(&fixture.rotation),
                        coverage: fixture_coverage(&fixture.capture_state),
                        encoding: fixture.encoding,
                    },
                    path_fingerprint: fixture.path_fingerprint,
                    rotation_lineage: None,
                    relative_path: fixture.relative_path,
                    fragment_complete: if matches!(
                        fixture_coverage(&fixture.capture_state),
                        SccmCoverageState::Captured
                            | SccmCoverageState::Capped
                            | SccmCoverageState::ParseFailed
                    ) {
                        fixture.rotation.fragment_complete
                    } else {
                        Some(false)
                    },
                    declared_byte_length: None,
                    content_sha256: None,
                }
            })
            .collect(),
        capture_gaps: Vec::new(),
    }
}

#[test]
fn health_fixture_manifests_project_the_coverage_matrix_without_reading_evidence_bytes() {
    let cases = [
        (
            "contradictory",
            ["captured", "absent", "absent", "absent"],
            false,
            Some("client-evaluation"),
        ),
        (
            "identity-failure",
            ["captured", "captured", "captured", "absent"],
            false,
            Some("client-location"),
        ),
        (
            "incomplete",
            ["captured", "captured", "accessDenied", "absent"],
            false,
            Some("client-identity"),
        ),
        (
            "malformed",
            ["captured", "captured", "absent", "absent"],
            false,
            Some("client-identity"),
        ),
        (
            "no-site-or-mp",
            ["captured", "captured", "captured", "captured"],
            true,
            None,
        ),
        (
            "rotation-boundary",
            ["captured", "absent", "absent", "absent"],
            false,
            Some("client-evaluation"),
        ),
        (
            "setup-failure",
            ["captured", "absent", "absent", "absent"],
            false,
            Some("client-evaluation"),
        ),
        (
            "success",
            ["captured", "captured", "captured", "captured"],
            true,
            None,
        ),
        (
            "transport-failure",
            ["captured", "captured", "captured", "captured"],
            true,
            None,
        ),
    ];

    for (scenario, expected_coverage, coverage_complete, next_required_source_group) in cases {
        let readiness = assess_client_health_coverage(&load_fixture_bundle(scenario))
            .expect("fixture manifest supplies valid health intake metadata");
        let value = serde_json::to_value(readiness).expect("coverage readiness serializes");

        assert_eq!(
            value["sourceGroups"]
                .as_array()
                .expect("source groups are an array")
                .iter()
                .map(|group| group["coverage"].as_str().expect("coverage is serialized"))
                .collect::<Vec<_>>(),
            expected_coverage,
            "{scenario}: manifest metadata projects the expected coverage matrix"
        );
        assert_eq!(value["coverageComplete"], coverage_complete, "{scenario}");
        assert_eq!(
            value["nextRequiredSourceGroup"],
            next_required_source_group.map_or(serde_json::Value::Null, |group| json!(group)),
            "{scenario}"
        );
    }
}
