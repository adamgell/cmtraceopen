use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use cmtraceopen_parser::models::log_entry::Severity;
use cmtraceopen_parser::sccm::server::windows::{
    analyze_hierarchy_replication, assess_server_intake, declared_server_source_catalog,
    SccmHierarchyDirection, SccmHierarchyProfileSelectionState, SccmHierarchyRemoteCausality,
    SccmHierarchyState, SccmHierarchyTimestampOrdering, SccmServerArtifactPayload,
    SccmServerIntakeAssessment, SCCM_HIERARCHY_PROFILE_ID, SCCM_HIERARCHY_SOURCE_VERSION,
};
use cmtraceopen_parser::sccm::{
    SccmConfidence, SccmCorrelationKeyKind, SccmFindingClass, SccmKeyConfidence, SccmRole,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const SCENARIOS: &[&str] = &[
    "absent-remote-source",
    "backlog-retry",
    "clock-offset-unknown",
    "generic-site-token",
    "healthy-link",
    "incomplete",
    "receiver-processing-failure",
    "recovery",
    "rotation-boundary",
    "sender-failure",
    "topology-mismatch",
];

const FULL_OUTPUT_SHA256: &[(&str, &str)] = &[
    (
        "absent-remote-source",
        "d433de24f68f9675b97afb3a65b6fe664f389dd3dafb780d5eaae1284f423153",
    ),
    (
        "backlog-retry",
        "e63b67202b6e5a0aa9179000ad72d3215cae3d5b8bfc894fea2f8c9c7bde36a9",
    ),
    (
        "clock-offset-unknown",
        "da02ddec04085e5c729365212b2c741d92fc1ec025bfe7bb01ed481e93f6fa71",
    ),
    (
        "generic-site-token",
        "03b82f7f80db1f0fe6a6a3738cef962545584d280002558468d03c67e290dcb5",
    ),
    (
        "healthy-link",
        "cd3a558339e006cbd8003bc35c81dc94b6db90391302863772debe7e17cff39f",
    ),
    (
        "incomplete",
        "43f1a50ac2818110176cb8e4db007e1cbbf3ef920665c956bf8452f80263d9a9",
    ),
    (
        "receiver-processing-failure",
        "5785052b51919023838db1bb0d282e234002f9eb05609dbf8d74e188e0f04fd7",
    ),
    (
        "recovery",
        "d2d7035ae31dc35ed07b517bc8ba1f08159460316fba38d8267932067b7969d9",
    ),
    (
        "rotation-boundary",
        "452c1efab5b79c76fb496e75d4ffa8716ed1f41afe47c13709872f4448eb5d42",
    ),
    (
        "sender-failure",
        "87934ae0c81f5bde7d075fc11f75d982f2f81c02dd045df52ff8c24b51bc88c3",
    ),
    (
        "topology-mismatch",
        "6747a6b9e63c88ff544be788bf0ce1c51dfa2dfb04dedf45cc67dcb76efc6304",
    ),
];

fn corpus_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/sccm/server/hierarchy_and_replication")
}

fn fixture_parts(scenario: &str) -> (Value, Vec<SccmServerArtifactPayload>, Value) {
    let root = corpus_root().join(scenario);
    let source: Value = serde_json::from_str(
        &std::fs::read_to_string(root.join("manifest.json")).expect("manifest is readable"),
    )
    .expect("manifest is valid JSON");
    let expected: Value = serde_json::from_str(
        &std::fs::read_to_string(root.join("expected.json")).expect("expected is readable"),
    )
    .expect("expected is valid JSON");

    let topology = &source["topology"];
    let mut links = vec![json!({
        "originSiteCode": required_str(topology, "originSiteCode"),
        "targetSiteCode": required_str(topology, "targetSiteCode"),
        "originHostHandle": canonical_host(required_str(topology, "originHostHandle")),
        "targetHostHandle": canonical_host(required_str(topology, "targetHostHandle")),
    })];
    links.extend(
        topology["additionalTargets"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|target| {
                json!({
                    "originSiteCode": required_str(topology, "originSiteCode"),
                    "targetSiteCode": required_str(target, "siteCode"),
                    "originHostHandle": canonical_host(required_str(topology, "originHostHandle")),
                    "targetHostHandle": canonical_host(required_str(target, "hostHandle")),
                })
            }),
    );

    let mut payloads = Vec::new();
    let artifacts = source["artifacts"]
        .as_array()
        .expect("artifacts are an array")
        .iter()
        .map(|artifact| {
            let artifact_id = required_str(artifact, "artifactId");
            let source_id = required_str(artifact, "sourceId");
            let basename = required_str(artifact, "originalBasename");
            let rotation = match required_str(&artifact["rotation"], "kind") {
                "current" => "current",
                "loUnderscore" => "lo_",
                value => panic!("unsupported hierarchy rotation {value}"),
            };
            let physical = matches!(
                required_str(artifact, "captureState"),
                "captured" | "capped" | "parseFailed"
            );
            let mut normalized = json!({
                "artifactId": artifact_id,
                "producerRole": "siteServer",
                "producerHostHandle": canonical_host(required_str(artifact, "producerHostHandle")),
                "sourceId": source_id,
                "sourceKind": "ccmLog",
                "sourceVersion": SCCM_HIERARCHY_SOURCE_VERSION,
                "originalPath": "REDACTED_HIERARCHY",
                "originalBasename": basename,
                "configuredPathProvenance": {
                    "state": "configured",
                    "pathFingerprint": required_str(artifact, "pathFingerprint"),
                },
                "rotation": {
                    "kind": rotation,
                    "lineageId": required_str(&artifact["rotation"], "lineageId"),
                },
                "captureState": artifact["captureState"],
                "collectedUtc": artifact["collectedUtc"],
                "bytesCopied": 0,
            });
            if physical {
                let old_relative_path = required_str(artifact, "relativePath");
                let bytes = std::fs::read(root.join(old_relative_path))
                    .expect("hierarchy payload is readable");
                normalized["encoding"] = json!("utf-8");
                normalized["collectionLimit"] = artifact["collectionLimit"].clone();
                normalized["bytesCopied"] = json!(bytes.len());
                normalized["relativePath"] = json!(format!(
                    "evidence/sccm/server/site-server/{source_id}/{rotation}/{basename}"
                ));
                if artifact["captureState"] == "capped" {
                    normalized["truncated"] = json!(true);
                    normalized["fragmentComplete"] = json!(false);
                }
                payloads.push(SccmServerArtifactPayload {
                    manifest_artifact_id: artifact_id.to_owned(),
                    bytes,
                });
            }
            normalized
        })
        .collect::<Vec<_>>();

    (
        json!({
            "sccmManifestVersion": 1,
            "syntheticFixture": true,
            "proposalOnly": true,
            "privacy": {"synthetic": true, "rawPaths": "redacted"},
            "bundleRole": "server",
            "topology": {
                "captureHost": "LAB-CM01",
                "siteCode": "LAB",
                "rolesObserved": ["siteServer"],
                "hierarchyLinks": links,
            },
            "artifacts": artifacts,
        }),
        payloads,
        expected,
    )
}

fn assess(manifest: &Value, payloads: &[SccmServerArtifactPayload]) -> SccmServerIntakeAssessment {
    assess_server_intake(
        &serde_json::to_string(manifest).expect("manifest serializes"),
        payloads,
    )
    .expect("canonical hierarchy intake is admitted")
}

fn load_assessment(scenario: &str) -> (SccmServerIntakeAssessment, Value) {
    let (manifest, payloads, expected) = fixture_parts(scenario);
    (assess(&manifest, &payloads), expected)
}

fn payload_mut<'a>(
    payloads: &'a mut [SccmServerArtifactPayload],
    artifact_id: &str,
) -> &'a mut Vec<u8> {
    &mut payloads
        .iter_mut()
        .find(|payload| payload.manifest_artifact_id == artifact_id)
        .expect("payload exists")
        .bytes
}

fn sync_payload_length(manifest: &mut Value, payloads: &[SccmServerArtifactPayload]) {
    for artifact in manifest["artifacts"]
        .as_array_mut()
        .expect("artifacts are mutable")
    {
        if let Some(payload) = payloads
            .iter()
            .find(|payload| payload.manifest_artifact_id == artifact["artifactId"])
        {
            artifact["bytesCopied"] = json!(payload.bytes.len());
        }
    }
}

fn required_str<'a>(value: &'a Value, field: &str) -> &'a str {
    value[field]
        .as_str()
        .unwrap_or_else(|| panic!("{field} is a string"))
}

fn canonical_host(value: &str) -> &'static str {
    match value {
        "safe:server:lab-pri-01" => "synthetic:host:site-01",
        "safe:server:lab-chd-01" => "synthetic:host:site-02",
        "safe:server:lab-sec-01" => "synthetic:host:site-03",
        value => panic!("unregistered hierarchy fixture host {value}"),
    }
}

#[test]
fn every_corpus_scenario_runs_through_canonical_intake_and_the_exported_analyzer() {
    for scenario in SCENARIOS {
        let (intake, expected) = load_assessment(scenario);
        let analysis = analyze_hierarchy_replication(&intake).expect("sealed intake is trusted");
        assert_eq!(analysis.workflow, "hierarchyAndReplication", "{scenario}");
        assert_eq!(analysis.state_chain.len(), 7, "{scenario}");
        assert_eq!(
            analysis.extraction_profile.selection_state,
            SccmHierarchyProfileSelectionState::SelectedSynthetic,
            "{scenario}"
        );
        assert_eq!(
            analysis.extraction_profile.profile_id.as_deref(),
            Some(SCCM_HIERARCHY_PROFILE_ID),
            "{scenario}"
        );
        assert!(
            analysis.extraction_profile.synthetic_fixture_only,
            "{scenario}"
        );
        assert!(!analysis.native_validation_performed, "{scenario}");
        assert!(analysis.cross_side_causal_claims.is_empty(), "{scenario}");
        assert_eq!(
            coverage_projection(&analysis),
            coverage_expectation(&expected, scenario),
            "{scenario}"
        );
        assert_eq!(
            transaction_projection(&analysis),
            transaction_expectation(&expected),
            "{scenario}"
        );
        assert_eq!(
            source_local_projection(&analysis),
            source_local_expectation(&expected),
            "{scenario}"
        );
        assert_eq!(
            request_projection(&analysis),
            expected["artifactRequests"],
            "{scenario}"
        );
        assert!(analysis
            .findings
            .iter()
            .all(|finding| finding.validate().is_ok()));

        let mut ids = BTreeSet::new();
        for observation in analysis
            .transactions
            .iter()
            .flat_map(|transaction| transaction.observations.iter())
        {
            assert!(ids.insert(observation.observation_id.clone()), "{scenario}");
            let reference = &observation.evidence[0];
            assert!(observation.observation_id.contains(&reference.artifact_id));
            assert!(observation
                .observation_id
                .contains(&reference.line_start.expect("line").to_string()));
        }

        let (mut reversed_manifest, mut reversed_payloads, _) = fixture_parts(scenario);
        reversed_manifest["artifacts"]
            .as_array_mut()
            .expect("artifacts")
            .reverse();
        reversed_payloads.reverse();
        let reversed =
            analyze_hierarchy_replication(&assess(&reversed_manifest, &reversed_payloads))
                .expect("reordered intake is trusted");
        assert_eq!(
            serde_json::to_value(&analysis).expect("analysis serializes"),
            serde_json::to_value(reversed).expect("reversed analysis serializes"),
            "input order changed full output for {scenario}"
        );

        if let Some((_, expected_digest)) =
            FULL_OUTPUT_SHA256.iter().find(|(name, _)| name == scenario)
        {
            assert_eq!(
                full_output_digest(&analysis),
                *expected_digest,
                "{scenario}"
            );
        } else {
            eprintln!("{scenario} {}", full_output_digest(&analysis));
        }
    }
    assert_eq!(FULL_OUTPUT_SHA256.len(), SCENARIOS.len());
}

#[test]
fn hierarchy_authority_is_private_canonical_intake_and_all_provenance_is_sealed() {
    let (intake, _) = load_assessment("healthy-link");
    for mutate in [
        |assessment: &mut SccmServerIntakeAssessment| {
            assessment.evidence[0].message.push_str(" mutated")
        },
        |assessment: &mut SccmServerIntakeAssessment| {
            assessment.artifacts[0].content_sha256 = Some("0".repeat(64))
        },
        |assessment: &mut SccmServerIntakeAssessment| {
            assessment.artifacts[0].source_version = Some("5.00.9128.1007".to_owned())
        },
        |assessment: &mut SccmServerIntakeAssessment| {
            assessment.artifacts[0].collected_at_utc = "2026-07-30T20:00:00Z".to_owned()
        },
        |assessment: &mut SccmServerIntakeAssessment| {
            assessment.artifacts[0]
                .capture_provenance
                .as_mut()
                .expect("provenance")
                .encoding = "windows-1252".to_owned()
        },
        |assessment: &mut SccmServerIntakeAssessment| {
            assessment.artifacts[0].producer_host_handle = Some("synthetic:host:site-03".to_owned())
        },
    ] {
        let mut changed = intake.clone();
        mutate(&mut changed);
        assert_eq!(
            analyze_hierarchy_replication(&changed),
            Err(cmtraceopen_parser::sccm::server::windows::SccmHierarchyError::UntrustedIntake)
        );
    }

    let (mut manifest, mut payloads, _) = fixture_parts("healthy-link");
    let arbitrary = String::from_utf8(payload_mut(&mut payloads, "healthy-01-replmgr").clone())
        .expect("utf8")
        .replace("msg-healthy-01", "msg-unreviewed-01");
    *payload_mut(&mut payloads, "healthy-01-replmgr") = arbitrary.into_bytes();
    sync_payload_length(&mut manifest, &payloads);
    let arbitrary = analyze_hierarchy_replication(&assess(&manifest, &payloads))
        .expect("canonical intake remains well formed");
    assert_eq!(
        arbitrary.extraction_profile.selection_state,
        SccmHierarchyProfileSelectionState::Unavailable
    );
    assert!(arbitrary.transactions.is_empty());
}

#[test]
fn registered_hierarchy_profile_bounds_failures_without_required_target_sources() {
    let (intake, _) = load_assessment("sender-failure");
    let analysis = analyze_hierarchy_replication(&intake).expect("sealed intake");
    assert_eq!(analysis.transactions.len(), 2);
    for transaction in &analysis.transactions {
        assert!(transaction.correlation_keys.iter().any(|key| {
            key.kind == SccmCorrelationKeyKind::HierarchyMessageId
                && key.confidence == SccmKeyConfidence::Exact
                && key.extraction_profile_id.as_deref() == Some(SCCM_HIERARCHY_PROFILE_ID)
        }));
        assert!(transaction.correlation_keys.iter().any(|key| {
            key.kind == SccmCorrelationKeyKind::HierarchyLinkId
                && key.confidence == SccmKeyConfidence::Exact
        }));
        assert_eq!(transaction.state, SccmHierarchyState::Incomplete);
        assert_eq!(transaction.confidence, SccmConfidence::Low);
        assert_eq!(
            transaction.remote_causality,
            SccmHierarchyRemoteCausality::NotEstablished
        );
        assert_eq!(transaction.next_artifacts.len(), 2);
    }
    assert_eq!(analysis.findings.len(), 2);
    assert!(analysis.findings.iter().all(|finding| {
        finding.class == SccmFindingClass::Symptom
            && finding.severity == Severity::Warning
            && finding.terminal_evidence.is_empty()
            && finding.validate().is_ok()
    }));
}

#[test]
fn equal_time_ordering_uses_physical_lines_and_cross_artifact_ties_fail_closed() {
    let (mut manifest, mut payloads, _) = fixture_parts("healthy-link");
    let replmgr = String::from_utf8(payload_mut(&mut payloads, "healthy-01-replmgr").clone())
        .expect("utf8")
        .replace("15:03:01.000+000", "15:03:00.000+000");
    *payload_mut(&mut payloads, "healthy-01-replmgr") = replmgr.clone().into_bytes();
    sync_payload_length(&mut manifest, &payloads);
    let analysis = analyze_hierarchy_replication(&assess(&manifest, &payloads)).expect("sealed");
    assert_eq!(
        analysis.transactions[0].timestamp_ordering,
        SccmHierarchyTimestampOrdering::Usable
    );

    let physically_reversed = replmgr
        .replace("Phase=initiate", "Phase=TEMP")
        .replace("Phase=queueOrSerialize", "Phase=initiate")
        .replace("Phase=TEMP", "Phase=queueOrSerialize");
    *payload_mut(&mut payloads, "healthy-01-replmgr") = physically_reversed.into_bytes();
    sync_payload_length(&mut manifest, &payloads);
    let analysis = analyze_hierarchy_replication(&assess(&manifest, &payloads)).expect("sealed");
    assert_eq!(
        analysis.transactions[0].timestamp_ordering,
        SccmHierarchyTimestampOrdering::Contradictory
    );

    let (mut manifest, mut payloads, _) = fixture_parts("healthy-link");
    let sender = String::from_utf8(payload_mut(&mut payloads, "healthy-02-sender").clone())
        .expect("utf8")
        .replace("15:03:02.000+000", "15:03:01.000+000");
    *payload_mut(&mut payloads, "healthy-02-sender") = sender.into_bytes();
    sync_payload_length(&mut manifest, &payloads);
    let analysis = analyze_hierarchy_replication(&assess(&manifest, &payloads)).expect("sealed");
    assert_eq!(
        analysis.transactions[0].timestamp_ordering,
        SccmHierarchyTimestampOrdering::Contradictory
    );
    assert_eq!(
        analysis.transactions[0].state,
        SccmHierarchyState::Contradictory
    );
}

#[test]
fn rotation_split_requires_the_exact_current_lo_lineage_and_topology_pair() {
    let (mut manifest, payloads, _) = fixture_parts("rotation-boundary");
    let analysis = analyze_hierarchy_replication(&assess(&manifest, &payloads)).expect("sealed");
    assert_eq!(
        analysis.source_local_observations.len(),
        1,
        "{:?}",
        analysis.source_local_observations
    );
    assert_eq!(
        analysis.source_local_observations[0].reason_code,
        "rotationSplit"
    );
    assert_eq!(analysis.artifact_requests[0].transaction_id, None);
    assert_eq!(analysis.artifact_requests[0].origin_site_code, "LAB");
    assert_eq!(analysis.artifact_requests[0].target_site_code, "CHD");

    manifest["artifacts"][1]["rotation"]["lineageId"] = json!("healthy-sender");
    let analysis = analyze_hierarchy_replication(&assess(&manifest, &payloads)).expect("sealed");
    assert!(analysis
        .source_local_observations
        .iter()
        .all(|observation| observation.reason_code != "rotationSplit"));
}

#[test]
fn gaps_and_requests_are_transaction_and_exact_topology_scoped() {
    let (intake, _) = load_assessment("absent-remote-source");
    let analysis = analyze_hierarchy_replication(&intake).expect("sealed");
    assert_eq!(analysis.transactions.len(), 1);
    assert_eq!(
        analysis.transactions[0].coverage_gap_artifact_ids,
        ["absent-02-despool"]
    );
    assert!(analysis.transactions[0]
        .next_artifacts
        .iter()
        .all(|request| {
            request.transaction_id.as_deref()
                == Some(analysis.transactions[0].transaction_id.as_str())
                && request.origin_site_code == "LAB"
                && request.target_site_code == "CHD"
        }));
    assert!(analysis.artifact_requests.iter().all(|request| {
        request.transaction_id.as_deref() == Some(analysis.transactions[0].transaction_id.as_str())
            && request.origin_site_code == "LAB"
            && request.target_site_code == "CHD"
    }));
}

fn assert_missing_target_sources(missing: &[(&str, &str)]) {
    let (mut manifest, mut payloads, _) = fixture_parts("healthy-link");
    remove_target_sources(&mut manifest, &mut payloads, missing);

    let analysis = analyze_hierarchy_replication(&assess(&manifest, &payloads)).expect("sealed");
    assert_missing_target_gate(&analysis, missing);
}

fn remove_target_sources(
    manifest: &mut Value,
    payloads: &mut Vec<SccmServerArtifactPayload>,
    missing: &[(&str, &str)],
) {
    let missing_basenames = missing
        .iter()
        .map(|(_, basename)| *basename)
        .collect::<BTreeSet<_>>();
    let target_ids = manifest["artifacts"]
        .as_array()
        .expect("artifacts")
        .iter()
        .filter(|artifact| missing_basenames.contains(required_str(artifact, "originalBasename")))
        .map(|artifact| required_str(artifact, "artifactId").to_owned())
        .collect::<BTreeSet<_>>();
    manifest["artifacts"]
        .as_array_mut()
        .expect("artifacts")
        .retain(|artifact| !target_ids.contains(required_str(artifact, "artifactId")));
    payloads.retain(|payload| !target_ids.contains(&payload.manifest_artifact_id));
}

fn declare_target_source_state(
    manifest: &mut Value,
    payloads: &mut Vec<SccmServerArtifactPayload>,
    basename: &str,
    state: &str,
) {
    let artifact = manifest["artifacts"]
        .as_array_mut()
        .expect("artifacts")
        .iter_mut()
        .find(|artifact| required_str(artifact, "originalBasename") == basename)
        .expect("target artifact");
    let artifact_id = required_str(artifact, "artifactId").to_owned();
    artifact["captureState"] = json!(state);

    match state {
        "capped" => {
            let payload_len = payloads
                .iter()
                .find(|payload| payload.manifest_artifact_id == artifact_id)
                .expect("capped payload")
                .bytes
                .len();
            artifact["collectionLimit"]["byteLimit"] = json!(payload_len);
            artifact["collectionLimit"]["limitApplied"] = json!(true);
            artifact["bytesCopied"] = json!(payload_len);
            artifact["truncated"] = json!(true);
            artifact["fragmentComplete"] = json!(false);
        }
        "parseFailed" => {}
        "absent" | "accessDenied" | "skipped" | "unsupported" => {
            let object = artifact.as_object_mut().expect("artifact object");
            for field in [
                "encoding",
                "collectionLimit",
                "relativePath",
                "truncated",
                "fragmentComplete",
            ] {
                object.remove(field);
            }
            artifact["bytesCopied"] = json!(0);
            payloads.retain(|payload| payload.manifest_artifact_id != artifact_id);
        }
        value => panic!("unsupported test coverage state {value}"),
    }
}

fn tied_healthy_fixture() -> (Value, Vec<SccmServerArtifactPayload>) {
    let (mut manifest, mut payloads, _) = fixture_parts("healthy-link");
    let sender = String::from_utf8(payload_mut(&mut payloads, "healthy-02-sender").clone())
        .expect("utf8")
        .replace("15:03:02.000+000", "15:03:01.000+000");
    *payload_mut(&mut payloads, "healthy-02-sender") = sender.into_bytes();
    sync_payload_length(&mut manifest, &payloads);
    (manifest, payloads)
}

fn add_target_sources_from_healthy(
    manifest: &mut Value,
    payloads: &mut Vec<SccmServerArtifactPayload>,
    basenames: &[&str],
) {
    let (healthy_manifest, healthy_payloads, _) = fixture_parts("healthy-link");
    for basename in basenames {
        let artifact = healthy_manifest["artifacts"]
            .as_array()
            .expect("healthy artifacts")
            .iter()
            .find(|artifact| required_str(artifact, "originalBasename") == *basename)
            .expect("registered healthy target artifact")
            .clone();
        let artifact_id = required_str(&artifact, "artifactId").to_owned();
        manifest["artifacts"]
            .as_array_mut()
            .expect("artifacts")
            .push(artifact);
        payloads.push(
            healthy_payloads
                .iter()
                .find(|payload| payload.manifest_artifact_id == artifact_id)
                .expect("registered healthy target payload")
                .clone(),
        );
    }
}

fn assert_missing_target_gate(
    analysis: &cmtraceopen_parser::sccm::server::windows::SccmHierarchyAnalysis,
    missing: &[(&str, &str)],
) {
    assert_eq!(analysis.transactions.len(), 1);
    let transaction = &analysis.transactions[0];
    assert_eq!(transaction.state, SccmHierarchyState::Incomplete);
    assert_eq!(transaction.confidence, SccmConfidence::Low);
    assert_eq!(
        transaction.remote_causality,
        SccmHierarchyRemoteCausality::NotEstablished
    );

    assert_eq!(transaction.next_artifacts.len(), missing.len());
    assert!(transaction.next_artifacts.iter().all(|request| {
        request.transaction_id.as_deref() == Some(transaction.transaction_id.as_str())
            && request.direction == SccmHierarchyDirection::Target
            && request.origin_site_code == "LAB"
            && request.target_site_code == "CHD"
            && request.reason_code == "missingTargetReceiveProcessApply"
    }));
    let requested_sources = transaction
        .next_artifacts
        .iter()
        .map(|request| {
            assert_eq!(request.basenames.len(), 1);
            (request.source_id.as_str(), request.basenames[0].as_str())
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(requested_sources, missing.iter().copied().collect());
    assert_eq!(analysis.artifact_requests, transaction.next_artifacts);
}

#[test]
fn omitted_target_despool_emits_only_transfer_request() {
    assert_missing_target_sources(&[("server-hierarchy-transfer", "despool.log")]);
}

#[test]
fn omitted_target_rcmctrl_emits_only_control_request() {
    assert_missing_target_sources(&[("server-hierarchy-control", "rcmctrl.log")]);
}

#[test]
fn omitted_both_target_sources_emit_both_requests() {
    assert_missing_target_sources(&[
        ("server-hierarchy-transfer", "despool.log"),
        ("server-hierarchy-control", "rcmctrl.log"),
    ]);
}

#[test]
fn missing_target_gate_precedes_cross_artifact_contradiction_and_terminal_success() {
    let (manifest, payloads) = tied_healthy_fixture();

    let both_present =
        analyze_hierarchy_replication(&assess(&manifest, &payloads)).expect("sealed control");
    assert_eq!(both_present.transactions.len(), 1);
    assert_eq!(
        both_present.transactions[0].timestamp_ordering,
        SccmHierarchyTimestampOrdering::Contradictory
    );
    assert_eq!(
        both_present.transactions[0].state,
        SccmHierarchyState::Contradictory
    );
    assert!(both_present.transactions[0].terminal_evidence);

    for missing in [
        [("server-hierarchy-transfer", "despool.log")],
        [("server-hierarchy-control", "rcmctrl.log")],
    ] {
        let mut missing_manifest = manifest.clone();
        let mut missing_payloads = payloads.clone();
        remove_target_sources(&mut missing_manifest, &mut missing_payloads, &missing);
        let analysis = analyze_hierarchy_replication(&assess(&missing_manifest, &missing_payloads))
            .expect("sealed missing-target case");
        assert_eq!(
            analysis.transactions[0].timestamp_ordering,
            SccmHierarchyTimestampOrdering::Contradictory
        );
        assert_missing_target_gate(&analysis, &missing);
    }
}

#[test]
fn declared_absent_target_sources_gate_equal_time_contradiction() {
    for (source_id, basename) in [
        ("server-hierarchy-transfer", "despool.log"),
        ("server-hierarchy-control", "rcmctrl.log"),
    ] {
        let (mut manifest, mut payloads) = tied_healthy_fixture();
        declare_target_source_state(&mut manifest, &mut payloads, basename, "absent");
        let analysis = analyze_hierarchy_replication(&assess(&manifest, &payloads))
            .expect("sealed declared-absent case");
        assert_eq!(
            analysis.transactions[0].timestamp_ordering,
            SccmHierarchyTimestampOrdering::Contradictory
        );
        assert_missing_target_gate(&analysis, &[(source_id, basename)]);
    }
}

#[test]
fn every_other_non_usable_target_state_gates_equal_time_contradiction() {
    for state in [
        "accessDenied",
        "capped",
        "skipped",
        "unsupported",
        "parseFailed",
    ] {
        for (source_id, basename) in [
            ("server-hierarchy-transfer", "despool.log"),
            ("server-hierarchy-control", "rcmctrl.log"),
        ] {
            let (mut manifest, mut payloads) = tied_healthy_fixture();
            declare_target_source_state(&mut manifest, &mut payloads, basename, state);
            let analysis = analyze_hierarchy_replication(&assess(&manifest, &payloads))
                .unwrap_or_else(|error| panic!("sealed {state} case: {error:?}"));
            assert_eq!(
                analysis.transactions[0].timestamp_ordering,
                SccmHierarchyTimestampOrdering::Contradictory,
                "{state}/{basename}"
            );
            assert_missing_target_gate(&analysis, &[(source_id, basename)]);
        }
    }
}

#[test]
fn both_target_sources_preserve_terminal_retry_and_recovery_selection() {
    for (scenario, message_id, added, expected) in [
        (
            "backlog-retry",
            "msg-backlog-01",
            &["despool.log", "rcmctrl.log"][..],
            SccmHierarchyState::Deferred,
        ),
        (
            "sender-failure",
            "msg-send-chd",
            &["despool.log", "rcmctrl.log"][..],
            SccmHierarchyState::Failed,
        ),
        (
            "receiver-processing-failure",
            "msg-receiver-01",
            &["rcmctrl.log"][..],
            SccmHierarchyState::Failed,
        ),
        (
            "recovery",
            "msg-recovery-01",
            &["rcmctrl.log"][..],
            SccmHierarchyState::Recovered,
        ),
    ] {
        let (mut manifest, mut payloads, _) = fixture_parts(scenario);
        add_target_sources_from_healthy(&mut manifest, &mut payloads, added);
        let analysis = analyze_hierarchy_replication(&assess(&manifest, &payloads))
            .expect("sealed both-present control");
        let transaction = analysis
            .transactions
            .iter()
            .find(|transaction| transaction.key.message_id == message_id)
            .expect("control transaction");
        assert_eq!(transaction.state, expected, "{scenario}");
        assert!(transaction
            .next_artifacts
            .iter()
            .all(|request| { request.reason_code != "missingTargetReceiveProcessApply" }));
    }

    let (intake, _) = load_assessment("healthy-link");
    let healthy = analyze_hierarchy_replication(&intake).expect("sealed success control");
    assert_eq!(healthy.transactions[0].state, SccmHierarchyState::Succeeded);
}

#[test]
fn malformed_grammar_is_retained_source_locally_without_promoting_keys() {
    let (mut manifest, mut payloads, _) = fixture_parts("sender-failure");
    let malformed = String::from_utf8(payload_mut(&mut payloads, "sender-failure-01-chd").clone())
        .expect("utf8")
        .replace("MessageId=msg-send-chd", "MessageId=content-send-chd");
    *payload_mut(&mut payloads, "sender-failure-01-chd") = malformed.into_bytes();
    sync_payload_length(&mut manifest, &payloads);
    let analysis = analyze_hierarchy_replication(&assess(&manifest, &payloads)).expect("sealed");
    assert_eq!(analysis.transactions.len(), 1);
    assert!(analysis
        .source_local_observations
        .iter()
        .any(|observation| {
            observation.reason_code == "topologyOrGrammarMismatch"
                && observation.observation_id.contains(":1-1:")
        }));
}

#[test]
fn hierarchy_sources_live_in_the_canonical_server_windows_catalog() {
    let hierarchy = declared_server_source_catalog()
        .iter()
        .filter(|spec| spec.source_id.starts_with("server-hierarchy-"))
        .collect::<Vec<_>>();
    assert_eq!(hierarchy.len(), 2);
    assert!(hierarchy.iter().all(|spec| {
        spec.producer_role == SccmRole::SiteServer
            && spec.workflow_subject_role.is_none()
            && !spec.supplemental
    }));
    assert_eq!(hierarchy[0].logical_names, ["replmgr", "rcmctrl"]);
    assert_eq!(hierarchy[1].logical_names, ["sender", "despool"]);
}

fn full_output_digest(
    analysis: &cmtraceopen_parser::sccm::server::windows::SccmHierarchyAnalysis,
) -> String {
    let bytes = serde_json::to_vec(analysis).expect("analysis serializes");
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn coverage_projection(
    analysis: &cmtraceopen_parser::sccm::server::windows::SccmHierarchyAnalysis,
) -> Value {
    Value::Array(
        analysis
            .coverage
            .iter()
            .map(|coverage| {
                json!({
                    "artifactId": coverage.artifact_id,
                    "state": serde_json::to_value(coverage.state.clone()).expect("state serializes"),
                })
            })
            .collect(),
    )
}

fn coverage_expectation(expected: &Value, scenario: &str) -> Value {
    let mut coverage = expected["coverage"].clone();
    if scenario == "rotation-boundary" {
        for item in coverage.as_array_mut().expect("coverage array") {
            item["state"] = json!("parseFailed");
        }
    }
    coverage
}

fn transaction_projection(
    analysis: &cmtraceopen_parser::sccm::server::windows::SccmHierarchyAnalysis,
) -> Value {
    Value::Array(
        analysis
            .transactions
            .iter()
            .map(|transaction| {
                json!({
                    "transactionId": transaction.transaction_id,
                    "key": {
                        "messageId": transaction.key.message_id,
                        "linkId": transaction.key.link_id,
                        "originSiteCode": transaction.key.origin_site_code,
                        "targetSiteCode": transaction.key.target_site_code,
                        "confidence": "exact",
                        "extractionProfileId": "hierarchy-server-5.00.test-v1",
                    },
                    "topologyCompatibility": transaction.topology_compatibility,
                    "timestampOrdering": transaction.timestamp_ordering,
                    "terminalEvidence": transaction.terminal_evidence,
                    "state": transaction.state,
                    "classification": classification(transaction),
                    "confidence": confidence_name(transaction.confidence),
                    "confidenceCeiling": confidence_name(transaction.confidence_ceiling),
                    "coverageGapArtifactIds": transaction.coverage_gap_artifact_ids,
                    "observations": transaction.observations.iter().map(|observation| json!({
                        "phase": observation.phase,
                        "disposition": observation.disposition,
                        "terminal": observation.terminal,
                        "evidence": observation.evidence.iter().map(|reference| json!({
                            "artifactId": reference.artifact_id,
                            "startLine": reference.line_start,
                            "endLine": reference.line_end,
                        })).collect::<Vec<_>>(),
                    })).collect::<Vec<_>>(),
                })
            })
            .collect(),
    )
}

fn transaction_expectation(expected: &Value) -> Value {
    Value::Array(
        expected["transactions"]
            .as_array()
            .expect("transactions are an array")
            .iter()
            .map(|transaction| {
                json!({
                    "transactionId": transaction["transactionId"],
                    "key": transaction["key"],
                    "topologyCompatibility": transaction["topologyCompatibility"],
                    "timestampOrdering": transaction["timestampOrdering"],
                    "terminalEvidence": transaction["terminalEvidence"],
                    "state": transaction["state"],
                    "classification": transaction["classification"],
                    "confidence": transaction["confidence"],
                    "confidenceCeiling": transaction["confidenceCeiling"],
                    "coverageGapArtifactIds": transaction["coverageGapArtifactIds"],
                    "observations": transaction["observations"].as_array().expect("observations").iter().map(|observation| json!({
                        "phase": observation["phase"],
                        "disposition": observation["disposition"],
                        "terminal": observation["terminal"],
                        "evidence": observation["evidence"],
                    })).collect::<Vec<_>>(),
                })
            })
            .collect(),
    )
}

fn classification(
    transaction: &cmtraceopen_parser::sccm::server::windows::SccmHierarchyTransaction,
) -> &'static str {
    match transaction.state {
        SccmHierarchyState::Succeeded | SccmHierarchyState::Recovered => "success",
        SccmHierarchyState::Failed => "confirmedFailure",
        SccmHierarchyState::Deferred => "blockedOrDeferred",
        SccmHierarchyState::Incomplete => "insufficientEvidence",
        SccmHierarchyState::Contradictory => "contradictoryEvidence",
    }
}

fn confidence_name(confidence: SccmConfidence) -> &'static str {
    match confidence {
        SccmConfidence::None => "none",
        SccmConfidence::Low => "low",
        SccmConfidence::Moderate => "medium",
        SccmConfidence::High => "high",
    }
}

fn source_local_projection(
    analysis: &cmtraceopen_parser::sccm::server::windows::SccmHierarchyAnalysis,
) -> Value {
    Value::Array(
        analysis
            .source_local_observations
            .iter()
            .map(|observation| {
                json!({
                    "classification": match observation.reason_code.as_str() {
                        "rotationSplit" => "rotationSplit",
                        "topologyOrGrammarMismatch" | "unlinkedTopologyCandidate" | "topologyMismatch" => "topologyMismatch",
                        _ => "coverageOnly",
                    },
                    "confidence": confidence_name(observation.confidence),
                    "correlationEligible": observation.correlation_eligible,
                    "artifactIds": observation.artifact_ids,
                    "evidence": observation.evidence.iter().map(|reference| json!({
                        "artifactId": reference.artifact_id,
                        "startLine": reference.line_start,
                        "endLine": reference.line_end,
                    })).collect::<Vec<_>>(),
                })
            })
            .collect(),
    )
}

fn source_local_expectation(expected: &Value) -> Value {
    Value::Array(
        expected["sourceLocalObservations"]
            .as_array()
            .expect("source-local observations are an array")
            .iter()
            .map(|observation| {
                json!({
                    "classification": observation["classification"],
                    "confidence": observation["confidence"],
                    "correlationEligible": observation["correlationEligible"],
                    "artifactIds": observation["artifactIds"],
                    "evidence": observation["evidence"],
                })
            })
            .collect(),
    )
}

fn request_projection(
    analysis: &cmtraceopen_parser::sccm::server::windows::SccmHierarchyAnalysis,
) -> Value {
    Value::Array(
        analysis
            .artifact_requests
            .iter()
            .map(|request| {
                json!({
                    "sourceId": request.source_id,
                    "producerRole": request.producer_role,
                    "direction": request.direction,
                    "targetSiteCode": request.target_site_code,
                    "basenames": request.basenames,
                    "reasonCode": request.reason_code,
                })
            })
            .collect(),
    )
}
