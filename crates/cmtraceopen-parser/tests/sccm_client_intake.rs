use std::fs;
use std::path::{Path, PathBuf};

use cmtraceopen_parser::sccm::{
    assess_client_intake, declared_client_source_groups, SccmArtifact, SccmClientIntakeArtifact,
    SccmClientIntakeBundle, SccmCoverageState, SccmRole, SccmRotation,
};
use serde::Deserialize;

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
    fragment_complete: Option<bool>,
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
                    relative_path: fixture.relative_path,
                    fragment_complete: fixture.rotation.fragment_complete,
                }
            })
            .collect(),
    }
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
        3
    );

    let mut reordered = bundle;
    reordered.artifacts.reverse();
    let reordered = assess_client_intake(&reordered).expect("reordered intake");
    assert_eq!(
        serde_json::to_string(&reordered).expect("reordered JSON"),
        serde_json::to_string(&intake).expect("intake JSON")
    );
}

#[test]
fn missing_access_denied_and_capped_sources_remain_exact_coverage_states() {
    let missing = assessment("missing-root");
    assert!(missing
        .groups
        .iter()
        .all(|group| group.coverage == SccmCoverageState::Absent));
    assert_eq!(missing.coverage_gaps.len(), 11);
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
    let artifact = |artifact_id: &str, display_name: &str| SccmClientIntakeArtifact {
        artifact: SccmArtifact {
            artifact_id: artifact_id.to_owned(),
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
        relative_path: Some(format!("evidence/unknown/{display_name}")),
        fragment_complete: Some(true),
    };
    let bundle = SccmClientIntakeBundle {
        artifacts: vec![
            artifact("custom", "CustomVendorHook.log"),
            artifact("lookalike", "PolicyAgent.log.backup"),
            artifact("unknown-lo", "CustomVendorHook.lo_"),
        ],
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
fn ambiguous_identity_or_nonclient_role_fails_closed() {
    let mut duplicate = load_bundle("collision");
    duplicate.artifacts[1].artifact.artifact_id =
        duplicate.artifacts[0].artifact.artifact_id.clone();
    assert!(assess_client_intake(&duplicate).is_err());

    let mut duplicate_path = load_bundle("collision");
    duplicate_path.artifacts[1].relative_path = duplicate_path.artifacts[0].relative_path.clone();
    assert!(assess_client_intake(&duplicate_path).is_err());

    let mut wrong_role = load_bundle("complete");
    wrong_role.artifacts[0].artifact.role = SccmRole::ManagementPoint;
    assert!(assess_client_intake(&wrong_role).is_err());
}
