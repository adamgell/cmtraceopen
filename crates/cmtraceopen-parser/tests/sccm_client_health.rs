use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use cmtraceopen_parser::sccm::client::{
    admit_client_evidence, analyze_client_health, assess_client_intake, SccmClientAdmittedEvidence,
    SccmClientCapturedPayload, SccmClientHealthAnalysis, SccmClientHealthHopState,
    SccmClientHealthPhase, SccmClientIntakeArtifact, SccmClientIntakeBundle,
};
use cmtraceopen_parser::sccm::{
    SccmArtifact, SccmCoverageState, SccmFindingClass, SccmRole, SccmRotation,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

const FIXTURE_ROOT: &str = "tests/fixtures/sccm/client/health";
const SCENARIOS: &[&str] = &[
    "authentication-failure",
    "boundary-location-failure",
    "contradictory",
    "identity-failure",
    "incomplete",
    "malformed",
    "no-site-or-mp",
    "rotation-boundary",
    "setup-failure",
    "success",
    "transport-failure",
];

struct FixtureAdmission {
    admitted: SccmClientAdmittedEvidence,
    artifact_ids: BTreeMap<String, String>,
}

fn fixture_directory(scenario: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(FIXTURE_ROOT)
        .join(scenario)
}

fn load_json(path: &Path) -> Value {
    serde_json::from_slice(
        &fs::read(path).unwrap_or_else(|error| panic!("{} is readable: {error}", path.display())),
    )
    .unwrap_or_else(|error| panic!("{} is valid JSON: {error}", path.display()))
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
        other => panic!("unsupported health fixture coverage {other}"),
    }
}

fn rotation(value: &str) -> SccmRotation {
    match value {
        "current" => SccmRotation::Current,
        "lo" => SccmRotation::LoUnderscore,
        other => panic!("unsupported health fixture rotation {other}"),
    }
}

fn admit_fixture(scenario: &str) -> Result<FixtureAdmission, String> {
    admit_fixture_after(scenario, |_, _| {})
}

fn admit_fixture_after(
    scenario: &str,
    mut mutate_payload: impl FnMut(&str, &mut Vec<u8>),
) -> Result<FixtureAdmission, String> {
    let root = fixture_directory(scenario);
    let manifest = load_json(&root.join("manifest.json"));
    assert_eq!(
        manifest
            .as_object()
            .expect("health manifest object")
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "artifacts",
            "sccmManifestVersion",
            "scenario",
            "syntheticFixture",
        ]),
        "{scenario}: production fixture manifest schema"
    );
    assert_eq!(manifest["sccmManifestVersion"], 1);
    assert_eq!(manifest["syntheticFixture"], true);
    assert_eq!(manifest["scenario"], scenario);
    let declared = manifest["artifacts"]
        .as_array()
        .ok_or_else(|| "manifest artifacts missing".to_owned())?;
    let mut artifacts = Vec::new();
    let mut payloads = Vec::new();
    let mut artifact_ids = BTreeMap::new();

    for (index, item) in declared.iter().enumerate() {
        assert_eq!(
            item.as_object()
                .expect("health manifest artifact object")
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                "artifactId",
                "bytesCopied",
                "captureState",
                "capturedUtc",
                "encoding",
                "originalBasename",
                "pathFingerprint",
                "relativePath",
                "role",
                "rotation",
                "sourceVersion",
            ]),
            "{scenario}: production fixture artifact schema"
        );
        assert_eq!(
            item["rotation"]
                .as_object()
                .expect("health manifest rotation object")
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["fragmentComplete", "kind"]),
            "{scenario}: production fixture rotation schema"
        );
        assert_eq!(item["role"], "client", "{scenario}: exact client role");
        let preparation_id = item["artifactId"]
            .as_str()
            .ok_or_else(|| "artifactId missing".to_owned())?;
        let artifact_id = format!("fixture-health-numbered-{:02}", index + 1);
        artifact_ids.insert(preparation_id.to_owned(), artifact_id.clone());
        let source_coverage = coverage(
            item["captureState"]
                .as_str()
                .ok_or_else(|| "captureState missing".to_owned())?,
        );
        let fragment_complete = item["rotation"]["fragmentComplete"]
            .as_bool()
            .unwrap_or(false);
        let committed_bytes = item["relativePath"]
            .as_str()
            .map(|relative| fs::read(root.join(relative)).map_err(|error| error.to_string()))
            .transpose()?;
        assert_eq!(
            item["bytesCopied"].as_u64(),
            Some(
                committed_bytes
                    .as_ref()
                    .map_or(0, |bytes| bytes.len() as u64)
            ),
            "{scenario}: exact committed fixture byte count"
        );
        let mut payload_bytes = (source_coverage == SccmCoverageState::Captured
            && fragment_complete)
            .then(|| {
                committed_bytes
                    .clone()
                    .ok_or_else(|| "complete capture has no relativePath".to_owned())
            })
            .transpose()?;
        if let Some(bytes) = &mut payload_bytes {
            mutate_payload(preparation_id, bytes);
        }
        artifacts.push(SccmClientIntakeArtifact {
            artifact: SccmArtifact {
                artifact_id: artifact_id.clone(),
                display_name: item["originalBasename"]
                    .as_str()
                    .ok_or_else(|| "originalBasename missing".to_owned())?
                    .to_owned(),
                original_path: None,
                host: None,
                role: SccmRole::Client,
                configmgr_version: item["sourceVersion"].as_str().map(str::to_owned),
                collected_at_utc: item["capturedUtc"].as_str().map(str::to_owned),
                rotation: rotation(
                    item["rotation"]["kind"]
                        .as_str()
                        .ok_or_else(|| "rotation kind missing".to_owned())?,
                ),
                coverage: source_coverage,
                encoding: item["encoding"].as_str().map(str::to_owned),
            },
            path_fingerprint: item["pathFingerprint"].as_str().map(str::to_owned),
            rotation_lineage: None,
            relative_path: item["relativePath"].as_str().map(str::to_owned),
            fragment_complete: Some(fragment_complete),
            declared_byte_length: payload_bytes.as_ref().map(|bytes| bytes.len() as u64),
            content_sha256: payload_bytes.as_ref().map(|bytes| digest(bytes)),
        });
        if let Some(bytes) = payload_bytes {
            payloads.push(
                SccmClientCapturedPayload::new(artifact_id, bytes)
                    .map_err(|error| error.to_string())?,
            );
        }
    }

    let bundle = SccmClientIntakeBundle {
        artifacts,
        capture_gaps: Vec::new(),
    };
    let assessment = assess_client_intake(&bundle).map_err(|error| error.to_string())?;
    let admitted = admit_client_evidence(&bundle, &assessment, &payloads)
        .map_err(|error| error.to_string())?;
    Ok(FixtureAdmission {
        admitted,
        artifact_ids,
    })
}

fn analyze_fixture(scenario: &str) -> SccmClientHealthAnalysis {
    let fixture = admit_fixture(scenario)
        .unwrap_or_else(|error| panic!("{scenario}: fixture admission failed: {error}"));
    analyze_client_health(&fixture.admitted)
        .unwrap_or_else(|error| panic!("{scenario}: health analysis failed: {error}"))
}

fn analyze_success_regression(name: &str) -> (SccmClientHealthAnalysis, BTreeMap<String, String>) {
    let fixture = admit_fixture_after("success", |artifact_id, bytes| {
        let content = std::str::from_utf8(bytes).expect("health fixture is UTF-8");
        let mutated = match (name, artifact_id) {
            ("service-before-install", "health-success-evaluation-current") => {
                content.replace("01:00:01.000+000", "00:59:59.000+000")
            }
            ("cross-client-management-point", "health-success-location-services-current") => {
                content.replace(
                    "Phase=managementPointLocation Disposition=succeeded Terminal=true SiteCode=LAB",
                    "Phase=managementPointLocation Disposition=succeeded Terminal=true ClientGuid=22222222-2222-2222-2222-222222222222 SiteCode=LAB",
                )
            }
            _ => return,
        };
        *bytes = mutated.into_bytes();
    })
    .unwrap_or_else(|error| panic!("{name}: sealed fixture admission failed: {error}"));
    let analysis = analyze_client_health(&fixture.admitted)
        .unwrap_or_else(|error| panic!("{name}: health analysis failed: {error}"));
    (analysis, fixture.artifact_ids)
}

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn translate_artifact_ids(value: &mut Value, artifact_ids: &BTreeMap<String, String>) {
    match value {
        Value::String(text) => {
            let mut translations = artifact_ids.iter().collect::<Vec<_>>();
            translations.sort_by_key(|(_, admitted)| std::cmp::Reverse(admitted.len()));
            for (fixture, admitted) in translations {
                *text = text.replace(admitted, fixture);
            }
        }
        Value::Array(values) => {
            for value in values {
                translate_artifact_ids(value, artifact_ids);
            }
        }
        Value::Object(fields) => {
            for value in fields.values_mut() {
                translate_artifact_ids(value, artifact_ids);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn normalized_output(
    analysis: &SccmClientHealthAnalysis,
    artifact_ids: &BTreeMap<String, String>,
) -> Value {
    let mut normalized = serde_json::to_value(analysis).expect("health analysis serializes");
    translate_artifact_ids(&mut normalized, artifact_ids);
    normalized
}

fn admitted_record(phase: &str) -> SccmClientAdmittedEvidence {
    let artifact_id = "fixture-policy-agent";
    let message = format!(
        "Family=health Phase={phase} Disposition=succeeded Terminal=true ClientGuid=11111111-1111-1111-1111-111111111111"
    );
    let bytes = format!(
        "<![LOG[{message}]LOG]!><time=\"01:00:00.000+000\" date=\"07-30-2026\" component=\"ccmsetup\" context=\"\" type=\"1\" thread=\"1\" file=\"ccmsetup.cc:1\">\n"
    )
    .into_bytes();
    let bundle = SccmClientIntakeBundle {
        artifacts: vec![
            SccmClientIntakeArtifact {
                artifact: SccmArtifact {
                    artifact_id: artifact_id.to_owned(),
                    display_name: "ccmsetup.log".to_owned(),
                    original_path: None,
                    host: None,
                    role: SccmRole::Client,
                    configmgr_version: Some("5.00.9128.1000".to_owned()),
                    collected_at_utc: Some("2026-07-30T00:00:00Z".to_owned()),
                    rotation: SccmRotation::Current,
                    coverage: SccmCoverageState::Captured,
                    encoding: Some("utf-8".to_owned()),
                },
                path_fingerprint: Some("synthetic-policy-agent".to_owned()),
                rotation_lineage: None,
                relative_path: Some("evidence/client-ccmsetup/current/ccmsetup.log".to_owned()),
                fragment_complete: Some(true),
                declared_byte_length: Some(bytes.len() as u64),
                content_sha256: Some(digest(&bytes)),
            },
            SccmClientIntakeArtifact {
                artifact: SccmArtifact {
                    artifact_id: "fixture-health-numbered-02".to_owned(),
                    display_name: "CcmEval.log".to_owned(),
                    original_path: None,
                    host: None,
                    role: SccmRole::Client,
                    configmgr_version: Some("5.00.9128.1000".to_owned()),
                    collected_at_utc: Some("2026-07-30T00:00:01Z".to_owned()),
                    rotation: SccmRotation::Current,
                    coverage: SccmCoverageState::Absent,
                    encoding: None,
                },
                path_fingerprint: Some(
                    "synthetic-candidate-health-success-evaluation-absent".to_owned(),
                ),
                rotation_lineage: None,
                relative_path: None,
                fragment_complete: Some(false),
                declared_byte_length: None,
                content_sha256: None,
            },
        ],
        capture_gaps: Vec::new(),
    };
    let assessment = assess_client_intake(&bundle).expect("operation bundle intake");
    admit_client_evidence(
        &bundle,
        &assessment,
        &[SccmClientCapturedPayload::new(artifact_id, bytes).expect("operation payload")],
    )
    .expect("operation evidence admission")
}

#[test]
fn lifecycle_operations_are_classified_from_sealed_profiled_records() {
    for (name, expected) in [
        ("install", SccmClientHealthPhase::Install),
        ("upgrade", SccmClientHealthPhase::Upgrade),
        ("repair", SccmClientHealthPhase::Repair),
        ("removal", SccmClientHealthPhase::Removal),
    ] {
        let analysis = analyze_client_health(&admitted_record(name)).expect("health analysis");
        assert_eq!(analysis.lifecycle_phase, Some(expected));
        assert_eq!(analysis.last_confirmed_successful_phase, Some(expected));
        assert_eq!(analysis.hops[0].phase, expected);
        assert_eq!(analysis.hops[0].state, SccmClientHealthHopState::Succeeded);
    }
}

#[test]
fn success_fixture_confirms_every_post_install_hop() {
    let analysis = analyze_fixture("success");
    assert!(
        analysis.findings.is_empty(),
        "{}",
        serde_json::to_string_pretty(&analysis).expect("debug analysis")
    );
    assert_eq!(
        analysis.lifecycle_phase,
        Some(SccmClientHealthPhase::Install)
    );
    assert_eq!(
        analysis.last_confirmed_successful_phase,
        Some(SccmClientHealthPhase::Transport)
    );
    assert_eq!(
        analysis
            .hops
            .iter()
            .map(|hop| hop.phase)
            .collect::<Vec<_>>(),
        [
            SccmClientHealthPhase::Install,
            SccmClientHealthPhase::Service,
            SccmClientHealthPhase::ClientHealth,
            SccmClientHealthPhase::Reboot,
            SccmClientHealthPhase::Identity,
            SccmClientHealthPhase::Authentication,
            SccmClientHealthPhase::Assignment,
            SccmClientHealthPhase::Boundary,
            SccmClientHealthPhase::ManagementPointLocation,
            SccmClientHealthPhase::Transport,
        ]
    );
}

#[test]
fn post_lifecycle_phases_require_strict_monotonic_time() {
    let (analysis, _) = analyze_success_regression("service-before-install");
    assert_eq!(
        analysis
            .hops
            .iter()
            .map(|hop| hop.phase)
            .collect::<Vec<_>>(),
        vec![SccmClientHealthPhase::Install]
    );
    assert_eq!(
        analysis.last_confirmed_successful_phase,
        Some(SccmClientHealthPhase::Install)
    );
    assert_eq!(analysis.findings.len(), 1);
    assert_eq!(
        analysis.findings[0].health_phase,
        SccmClientHealthPhase::Service
    );
}

#[test]
fn management_point_identity_cannot_cross_clients_on_a_shared_site() {
    let (analysis, _) = analyze_success_regression("cross-client-management-point");
    assert_eq!(
        analysis.last_confirmed_successful_phase,
        Some(SccmClientHealthPhase::Boundary)
    );
    assert_eq!(analysis.findings.len(), 1);
    assert_eq!(
        analysis.findings[0].health_phase,
        SccmClientHealthPhase::ManagementPointLocation
    );
    assert!(analysis
        .hops
        .iter()
        .all(|hop| hop.phase != SccmClientHealthPhase::ManagementPointLocation));
}

#[test]
fn sealed_admission_regressions_match_exact_full_output_oracles() {
    let oracle_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/sccm/client/health-regression-oracles");
    for name in ["service-before-install", "cross-client-management-point"] {
        let (analysis, artifact_ids) = analyze_success_regression(name);
        let actual = normalized_output(&analysis, &artifact_ids);
        let path = oracle_root.join(format!("{name}.json"));
        assert_eq!(actual, load_json(&path), "{name}: exact full output");
    }
}

#[test]
fn terminal_and_incomplete_stops_are_conservative_and_request_one_exact_artifact() {
    for (scenario, phase, class, last_success, logical_id) in [
        (
            "setup-failure",
            SccmClientHealthPhase::Install,
            SccmFindingClass::ConfirmedFailure,
            None,
            "ccmSetup",
        ),
        (
            "identity-failure",
            SccmClientHealthPhase::Identity,
            SccmFindingClass::ConfirmedFailure,
            Some(SccmClientHealthPhase::Reboot),
            "clientIdManagerStartup",
        ),
        (
            "authentication-failure",
            SccmClientHealthPhase::Authentication,
            SccmFindingClass::ConfirmedFailure,
            Some(SccmClientHealthPhase::Identity),
            "clientIdManagerStartup",
        ),
        (
            "boundary-location-failure",
            SccmClientHealthPhase::Boundary,
            SccmFindingClass::ConfirmedFailure,
            Some(SccmClientHealthPhase::Assignment),
            "locationServices",
        ),
        (
            "transport-failure",
            SccmClientHealthPhase::Transport,
            SccmFindingClass::ConfirmedFailure,
            Some(SccmClientHealthPhase::ManagementPointLocation),
            "locationServices",
        ),
        (
            "incomplete",
            SccmClientHealthPhase::Identity,
            SccmFindingClass::InsufficientEvidence,
            Some(SccmClientHealthPhase::Reboot),
            "clientIdManagerStartup",
        ),
        (
            "malformed",
            SccmClientHealthPhase::Service,
            SccmFindingClass::InsufficientEvidence,
            Some(SccmClientHealthPhase::Install),
            "ccmEval",
        ),
        (
            "rotation-boundary",
            SccmClientHealthPhase::Install,
            SccmFindingClass::InsufficientEvidence,
            None,
            "ccmSetup",
        ),
    ] {
        let analysis = analyze_fixture(scenario);
        assert_eq!(analysis.findings.len(), 1, "{scenario}");
        let finding = &analysis.findings[0];
        assert_eq!(finding.health_phase, phase, "{scenario}");
        assert_eq!(finding.class, class, "{scenario}");
        assert_eq!(finding.last_confirmed_successful_phase, last_success);
        assert_eq!(finding.next_artifacts.len(), 1);
        assert_eq!(finding.next_artifacts[0].logical_id, logical_id);
        if class == SccmFindingClass::ConfirmedFailure {
            assert!(!finding.terminal_evidence.is_empty());
        }
    }
}

#[test]
fn contradictory_lifecycle_evidence_is_not_promoted_to_a_confirmed_failure() {
    let analysis = analyze_fixture("contradictory");
    assert_eq!(analysis.last_confirmed_successful_phase, None);
    assert_eq!(analysis.hops.len(), 1);
    assert_eq!(
        analysis.hops[0].state,
        SccmClientHealthHopState::Contradictory
    );
    assert_eq!(analysis.findings[0].class, SccmFindingClass::Symptom);
    assert!(analysis.findings[0].terminal_evidence.is_empty());
}

#[test]
fn isolated_network_error_does_not_become_a_terminal_failure() {
    let analysis = analyze_fixture("no-site-or-mp");
    let finding = &analysis.findings[0];
    assert_eq!(finding.health_phase, SccmClientHealthPhase::Assignment);
    assert_eq!(finding.class, SccmFindingClass::Symptom);
    assert!(finding.terminal_evidence.is_empty());
    assert_eq!(
        analysis.last_confirmed_successful_phase,
        Some(SccmClientHealthPhase::Authentication)
    );
}

#[test]
fn production_output_omits_raw_messages_hosts_paths_and_correlation_values() {
    for scenario in SCENARIOS
        .iter()
        .copied()
        .filter(|name| *name != "malformed")
    {
        let serialized = serde_json::to_string(&analyze_fixture(scenario)).expect("analysis JSON");
        for prohibited in [
            "message",
            "component",
            "executionContext",
            "mp-lab.contoso.invalid",
            "11111111-1111-1111-1111-111111111111",
            "SYNTHETIC://",
        ] {
            assert!(
                !serialized.contains(prohibited),
                "{scenario}: leaked {prohibited}: {serialized}"
            );
        }
    }
}

#[test]
fn committed_multifile_corpus_matches_exact_full_output_or_error_oracles() {
    let actual_directories = fs::read_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join(FIXTURE_ROOT))
        .expect("health fixture root")
        .filter_map(|entry| {
            let entry = entry.ok()?;
            entry
                .file_type()
                .ok()?
                .is_dir()
                .then(|| entry.file_name().to_string_lossy().into_owned())
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        actual_directories,
        SCENARIOS.iter().map(|name| (*name).to_owned()).collect()
    );

    let mut outputs = BTreeSet::new();
    for scenario in SCENARIOS {
        let expected_path = fixture_directory(scenario).join("expected.json");
        let (production_output, admission_error) = match admit_fixture(scenario) {
            Ok(fixture) => {
                let analysis = analyze_client_health(&fixture.admitted)
                    .unwrap_or_else(|error| panic!("{scenario}: analyzer failed: {error}"));
                let repeated = analyze_client_health(&fixture.admitted)
                    .unwrap_or_else(|error| panic!("{scenario}: repeat analyzer failed: {error}"));
                assert_eq!(
                    serde_json::to_value(&analysis).unwrap(),
                    serde_json::to_value(&repeated).unwrap(),
                    "{scenario}: deterministic full output"
                );
                (
                    Some(normalized_output(&analysis, &fixture.artifact_ids)),
                    None,
                )
            }
            Err(error) => (None, Some(error)),
        };

        let expected = load_json(&expected_path);
        let fields = expected
            .as_object()
            .expect("expected contract is an object")
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            fields,
            BTreeSet::from(["productionAdmissionError", "productionOutput", "scenario"]),
            "{scenario}: exact oracle schema"
        );
        assert_eq!(expected["scenario"], *scenario);
        assert_eq!(
            expected["productionOutput"],
            production_output.clone().unwrap_or(Value::Null),
            "{scenario}: exact normalized production output"
        );
        assert_eq!(
            expected["productionAdmissionError"],
            admission_error
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
            "{scenario}: exact admission error"
        );
        if let Some(output) = production_output {
            let bytes = serde_json::to_vec(&output).expect("normalized health JSON");
            assert!(
                outputs.insert(digest(&bytes)),
                "{scenario}: unique full output"
            );
        }
    }
}
