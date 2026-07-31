use std::fs;
use std::path::{Path, PathBuf};

use cmtraceopen_parser::sccm::{
    assess_client_intake, declared_client_source_groups, SccmArtifact, SccmClientIntakeArtifact,
    SccmClientIntakeBundle, SccmClientIntakeError, SccmCoverageState, SccmRole, SccmRotation,
    SccmUnknownRotation,
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
        relative_path: Some(relative_path),
        fragment_complete: Some(true),
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
        relative_path: Some("evidence/client-content/current/CAS.log".to_owned()),
        fragment_complete: Some(true),
    };

    assert_eq!(
        assess_client_intake(&SccmClientIntakeBundle {
            artifacts: vec![contradictory],
        }),
        Err(SccmClientIntakeError::InvalidFragmentCompleteness),
        "a capped physical fragment cannot claim complete public provenance"
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
    let mut invalid_rotation = synthetic_artifact("invalid-rotation", "AppEnforce.log.2026-bad");
    invalid_rotation.artifact.rotation = SccmRotation::Timestamped("2026-bad".to_owned());
    assert!(assess_client_intake(&SccmClientIntakeBundle {
        artifacts: vec![invalid_rotation],
    })
    .is_err());

    let mut unsafe_basename =
        synthetic_artifact("unsafe-basename", r"C:\Users\RealUser\PolicyAgent.log");
    unsafe_basename.relative_path =
        Some("evidence/unknown/unsafe-basename/PolicyAgent.log".to_owned());
    assert!(assess_client_intake(&SccmClientIntakeBundle {
        artifacts: vec![unsafe_basename],
    })
    .is_err());

    let mut invalid_time = synthetic_artifact("invalid-time", "PolicyAgent.log");
    invalid_time.artifact.collected_at_utc = Some(r"C:\Users\RealUser".to_owned());
    invalid_time.relative_path = Some("evidence/client-policy-agent/PolicyAgent.log".to_owned());
    assert!(assess_client_intake(&SccmClientIntakeBundle {
        artifacts: vec![invalid_time],
    })
    .is_err());

    let mut invalid_version = synthetic_artifact("invalid-version", "PolicyAgent.log");
    invalid_version.artifact.configmgr_version = Some("5.00.TEST/C:\\RealUser".to_owned());
    invalid_version.relative_path = Some("evidence/client-policy-agent/PolicyAgent.log".to_owned());
    assert!(assess_client_intake(&SccmClientIntakeBundle {
        artifacts: vec![invalid_version],
    })
    .is_err());
}

#[test]
fn configmgr_version_and_encoding_use_bounded_public_grammars() {
    for version in ["5.00.9128.1007", "5.00.TEST.0000", "5.00.UNKNOWN.0000"] {
        let mut artifact = synthetic_artifact("valid-version", "PolicyAgent.log");
        artifact.artifact.configmgr_version = Some(version.to_owned());
        assert!(
            assess_client_intake(&SccmClientIntakeBundle {
                artifacts: vec![artifact],
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
        assert_eq!(
            assess_client_intake(&SccmClientIntakeBundle {
                artifacts: vec![artifact],
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
        assert_eq!(
            assess_client_intake(&SccmClientIntakeBundle {
                artifacts: vec![artifact],
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
    })
    .expect("versioned opaque future rotation remains representable");
    assert_eq!(assessed.unsupported_artifacts.len(), 1);
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
    })
    .is_ok());

    let opaque_basename = format!("sccm-unknown-v1-sha256-{}.log", "b".repeat(64));
    let mut unknown = synthetic_artifact("custom", &opaque_basename);
    unknown.relative_path = Some(format!("evidence/unknown/current/{opaque_basename}"));
    let unknown = assess_client_intake(&SccmClientIntakeBundle {
        artifacts: vec![unknown],
    })
    .expect("opaque unsupported source remains representable");
    assert_eq!(unknown.unsupported_artifacts.len(), 1);

    let mut raw_context = synthetic_artifact("valid-version", "PolicyAgent.log");
    raw_context.artifact.original_path = Some(r"C:\Users\RealUser\PolicyAgent.log".to_owned());
    raw_context.artifact.host = Some("realuser.corp.example.test".to_owned());
    let serialized = serde_json::to_string(
        &assess_client_intake(&SccmClientIntakeBundle {
            artifacts: vec![raw_context],
        })
        .expect("raw native context is intentionally not projected"),
    )
    .expect("assessment serializes");
    let serialized_casefolded = serialized.to_ascii_lowercase();
    assert!(!serialized_casefolded.contains("realuser"));
    assert!(!serialized_casefolded.contains("realuser.corp"));
    assert!(!serialized_casefolded.contains(r"c:\users"));

    let mut oversized_timestamp = synthetic_artifact("invalid-time", "PolicyAgent.log");
    oversized_timestamp.artifact.collected_at_utc =
        Some(format!("2026-07-30T00:00:00.{}Z", "1".repeat(256)));
    assert_eq!(
        assess_client_intake(&SccmClientIntakeBundle {
            artifacts: vec![oversized_timestamp],
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
    assert!(assess_client_intake(&SccmClientIntakeBundle {
        artifacts: vec![missing_completeness],
    })
    .is_err());

    let mut invented_physical_state = synthetic_artifact("denied", "PolicyAgent.log");
    invented_physical_state.artifact.coverage = SccmCoverageState::AccessDenied;
    invented_physical_state.relative_path = None;
    assert!(assess_client_intake(&SccmClientIntakeBundle {
        artifacts: vec![invented_physical_state],
    })
    .is_err());

    let mut first = synthetic_artifact("denied-one", "PolicyAgent.log");
    first.artifact.coverage = SccmCoverageState::AccessDenied;
    first.relative_path = None;
    first.fragment_complete = Some(false);
    let mut second = synthetic_artifact("denied-two", "CIAgent.log");
    second.artifact.coverage = SccmCoverageState::AccessDenied;
    second.relative_path = None;
    second.fragment_complete = Some(false);
    second.path_fingerprint = first.path_fingerprint.clone();
    assert!(assess_client_intake(&SccmClientIntakeBundle {
        artifacts: vec![first, second],
    })
    .is_err());
}

#[test]
fn unsupported_physical_artifacts_retain_safe_provenance_without_raw_host_or_path() {
    let mut artifact = synthetic_artifact("custom", "CustomVendorHook.log");
    artifact.artifact.original_path = Some(r"C:\Users\RealUser\CustomVendorHook.log".to_owned());
    artifact.artifact.host = Some("real-user-host.example".to_owned());
    let intake = assess_client_intake(&SccmClientIntakeBundle {
        artifacts: vec![artifact],
    })
    .expect("unknown physical artifact remains representable");
    let serialized = serde_json::to_string(&intake).expect("intake JSON");

    assert!(serialized.contains("synthetic-custom"));
    assert!(serialized.contains("evidence/unknown/CustomVendorHook.log"));
    assert!(!serialized.contains("RealUser"));
    assert!(!serialized.contains("real-user-host"));
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
        }),
        Err(SccmClientIntakeError::InvalidRotation),
        "malformed timestamp rotation must fail on its own metadata contract"
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
        });
        assert!(
            matches!(result, Err(SccmClientIntakeError::InvalidPathFingerprint)),
            "unsafe fingerprint reached the public assessment: {fingerprint:?} => {result:?}"
        );
    }
}

#[test]
fn sha256_path_fingerprints_require_exactly_64_lowercase_hex_characters() {
    for digest in ["a".repeat(16), "a".repeat(63), "a".repeat(65)] {
        let mut artifact = synthetic_artifact("unsafe-fingerprint", "PolicyAgent.log");
        artifact.path_fingerprint = Some(format!("sha256:{digest}"));

        assert_eq!(
            assess_client_intake(&SccmClientIntakeBundle {
                artifacts: vec![artifact],
            }),
            Err(SccmClientIntakeError::InvalidPathFingerprint),
            "non-SHA-256 digest length was accepted: {}",
            digest.len()
        );
    }

    let mut artifact = synthetic_artifact("approved-fingerprint", "PolicyAgent.log");
    artifact.path_fingerprint = Some(format!("sha256:{}", "a".repeat(64)));
    assert!(assess_client_intake(&SccmClientIntakeBundle {
        artifacts: vec![artifact],
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
    })
    .is_ok());

    let mut oversized = synthetic_artifact("unsafe-fingerprint", "AppEnforce.log");
    oversized.path_fingerprint = Some("synthetic:app-enforce-numbered-123".to_owned());
    assert_eq!(
        assess_client_intake(&SccmClientIntakeBundle {
            artifacts: vec![oversized],
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
        })
        .unwrap_or_else(|error| panic!("approved path {relative_path:?} failed: {error}"));
    }
}
