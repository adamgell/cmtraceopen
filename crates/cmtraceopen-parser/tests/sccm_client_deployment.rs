//! Behavior contract for the issue #322 client deployment/content reducer.
//!
//! Every expectation is read from the merged issue #322 fixture corpus under
//! `tests/fixtures/sccm/client/deployment`. The corpus is the specification:
//! this file only translates its declared manifests into a normalized bundle
//! and compares the reducer output against the declared expectations.

use std::path::{Path, PathBuf};

use cmtraceopen_parser::sccm::{
    analyze_client_deployment, normalize_ccm_artifact, SccmArtifact, SccmCoverageState,
    SccmDeploymentClassification, SccmDeploymentConfidence, SccmDeploymentKeyConfidence,
    SccmDeploymentKeyProfileKind, SccmDeploymentPhase, SccmDeploymentState, SccmEvidence,
    SccmNormalizedBundle, SccmRole, SccmRotation, SCCM_DEPLOYMENT_TEST_PROFILE_ID,
};
use serde_json::Value;

const SCENARIOS: [&str; 12] = [
    "bits-transfer-failure",
    "cache-failure",
    "dependency-failure",
    "detection-false-negative",
    "dp-content-missing",
    "enforcement-exit",
    "incomplete",
    "location-missing",
    "not-targeted",
    "requirements-failure",
    "rotation-boundary",
    "success",
];

fn deployment_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sccm/client/deployment")
}

fn load_json(path: &Path) -> Value {
    let contents = std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("{} is readable: {error}", path.display()));
    serde_json::from_str(&contents)
        .unwrap_or_else(|error| panic!("{} contains valid JSON: {error}", path.display()))
}

fn expected(scenario: &str) -> Value {
    load_json(&deployment_root().join(scenario).join("expected.json"))
}

/// Translate one declared manifest artifact into the shared spine artifact.
///
/// `captureState` plus `rotation.fragmentComplete` collapse into a single
/// coverage state: captured bytes that do not form a complete logical record
/// are `Partial`, never `Captured`.
fn artifact_from_manifest(entry: &Value) -> SccmArtifact {
    let capture_state = entry["captureState"]
        .as_str()
        .expect("captureState is a string");
    let fragment_complete = entry["rotation"]["fragmentComplete"]
        .as_bool()
        .expect("fragmentComplete is a bool");
    let coverage = match capture_state {
        "captured" if fragment_complete => SccmCoverageState::Captured,
        "captured" => SccmCoverageState::Partial,
        "capped" => SccmCoverageState::Capped,
        "absent" => SccmCoverageState::Absent,
        "accessDenied" => SccmCoverageState::AccessDenied,
        "skipped" => SccmCoverageState::Skipped,
        "unsupported" => SccmCoverageState::Unsupported,
        other => panic!("unsupported captureState {other}"),
    };
    let rotation = match entry["rotation"]["kind"].as_str() {
        Some("current") => SccmRotation::Current,
        Some("lo") => SccmRotation::LoUnderscore,
        other => panic!("unsupported rotation kind {other:?}"),
    };

    SccmArtifact {
        artifact_id: entry["artifactId"]
            .as_str()
            .expect("artifactId is a string")
            .to_owned(),
        display_name: entry["originalBasename"]
            .as_str()
            .expect("originalBasename is a string")
            .to_owned(),
        original_path: None,
        host: None,
        role: SccmRole::Client,
        configmgr_version: entry["sourceVersion"].as_str().map(str::to_owned),
        collected_at_utc: entry["capturedUtc"].as_str().map(str::to_owned),
        rotation,
        coverage,
        encoding: entry["encoding"].as_str().map(str::to_owned),
    }
}

fn load_bundle(scenario: &str) -> SccmNormalizedBundle {
    let scenario_root = deployment_root().join(scenario);
    let manifest = load_json(&scenario_root.join("manifest.json"));
    let mut artifacts = Vec::new();
    let mut evidence: Vec<SccmEvidence> = Vec::new();

    for entry in manifest["artifacts"]
        .as_array()
        .expect("manifest artifacts are an array")
    {
        let artifact = artifact_from_manifest(entry);
        if let Some(relative_path) = entry["relativePath"].as_str() {
            let content = std::fs::read_to_string(scenario_root.join(relative_path))
                .expect("declared evidence is readable UTF-8");
            evidence.extend(normalize_ccm_artifact(artifact.clone(), &content));
        }
        artifacts.push(artifact);
    }

    SccmNormalizedBundle {
        artifacts,
        evidence,
    }
}

fn phase_name(phase: SccmDeploymentPhase) -> &'static str {
    match phase {
        SccmDeploymentPhase::Intent => "intent",
        SccmDeploymentPhase::Requirements => "requirements",
        SccmDeploymentPhase::LocateContent => "locateContent",
        SccmDeploymentPhase::Transfer => "transfer",
        SccmDeploymentPhase::Cache => "cache",
        SccmDeploymentPhase::Enforce => "enforce",
        SccmDeploymentPhase::Detect => "detect",
        SccmDeploymentPhase::Report => "report",
    }
}

fn state_name(state: SccmDeploymentState) -> &'static str {
    match state {
        SccmDeploymentState::NotTargeted => "notTargeted",
        SccmDeploymentState::InsufficientEvidence => "insufficientEvidence",
        SccmDeploymentState::Failed => "failed",
        SccmDeploymentState::DetectionMismatch => "detectionMismatch",
        SccmDeploymentState::Succeeded => "succeeded",
    }
}

fn classification_name(classification: SccmDeploymentClassification) -> &'static str {
    match classification {
        SccmDeploymentClassification::NotTargeted => "notTargeted",
        SccmDeploymentClassification::InsufficientEvidence => "insufficientEvidence",
        SccmDeploymentClassification::Symptom => "symptom",
        SccmDeploymentClassification::ConfirmedFailure => "confirmedFailure",
        SccmDeploymentClassification::Success => "success",
    }
}

fn confidence_name(confidence: SccmDeploymentConfidence) -> &'static str {
    match confidence {
        SccmDeploymentConfidence::Low => "low",
        SccmDeploymentConfidence::Medium => "medium",
        SccmDeploymentConfidence::High => "high",
    }
}

fn key_profile_name(kind: SccmDeploymentKeyProfileKind) -> &'static str {
    match kind {
        SccmDeploymentKeyProfileKind::AssignmentCi => "assignmentCi",
        SccmDeploymentKeyProfileKind::AssignmentCiContentTopology => "assignmentCiContentTopology",
    }
}

fn key_confidence_name(confidence: SccmDeploymentKeyConfidence) -> &'static str {
    match confidence {
        SccmDeploymentKeyConfidence::Candidate => "candidate",
        SccmDeploymentKeyConfidence::Exact => "exact",
    }
}

#[test]
fn declared_transaction_outcomes_are_reproduced_for_every_scenario() {
    for scenario in SCENARIOS {
        let analysis = analyze_client_deployment(&load_bundle(scenario));
        let expected = expected(scenario);
        let declared = expected["transactions"]
            .as_array()
            .expect("declared transactions are an array");

        assert_eq!(
            analysis.transactions.len(),
            declared.len(),
            "{scenario}: transaction count"
        );

        for (produced, declared) in analysis.transactions.iter().zip(declared) {
            let label = format!("{scenario}/{}", produced.transaction_id);
            assert_eq!(
                produced.transaction_id, declared["transactionId"],
                "{label}: transaction id"
            );
            assert_eq!(
                phase_name(produced.phase),
                declared["phase"].as_str().expect("declared phase"),
                "{label}: phase"
            );
            assert_eq!(
                state_name(produced.state),
                declared["state"].as_str().expect("declared state"),
                "{label}: state"
            );
            assert_eq!(
                produced.last_successful_phase.map(phase_name),
                declared["lastSuccessfulPhase"].as_str(),
                "{label}: last successful phase"
            );
            assert_eq!(
                classification_name(produced.classification),
                declared["classification"]
                    .as_str()
                    .expect("declared classification"),
                "{label}: classification"
            );
            assert_eq!(
                confidence_name(produced.confidence),
                declared["confidence"].as_str().expect("declared confidence"),
                "{label}: confidence"
            );
            assert_eq!(
                confidence_name(produced.confidence_ceiling),
                declared["confidenceCeiling"]
                    .as_str()
                    .expect("declared confidence ceiling"),
                "{label}: confidence ceiling"
            );
        }
    }
}

#[test]
fn declared_transaction_keys_are_bound_to_the_selected_version_profile() {
    for scenario in SCENARIOS {
        let analysis = analyze_client_deployment(&load_bundle(scenario));
        let expected = expected(scenario);
        let declared = expected["transactions"]
            .as_array()
            .expect("declared transactions are an array");

        for (produced, declared) in analysis.transactions.iter().zip(declared) {
            let label = format!("{scenario}/{}", produced.transaction_id);
            let key = &produced.key;
            let declared_key = &declared["key"];

            assert_eq!(
                key_profile_name(key.key_profile_kind),
                declared_key["keyProfileKind"]
                    .as_str()
                    .expect("declared key profile kind"),
                "{label}: key profile kind"
            );
            assert_eq!(
                key_confidence_name(key.confidence),
                declared_key["confidence"]
                    .as_str()
                    .expect("declared key confidence"),
                "{label}: key confidence"
            );
            assert_eq!(
                key.extraction_profile_id, SCCM_DEPLOYMENT_TEST_PROFILE_ID,
                "{label}: extraction profile"
            );
            assert_eq!(
                declared_key["extractionProfileId"], SCCM_DEPLOYMENT_TEST_PROFILE_ID,
                "{label}: declared extraction profile"
            );

            assert_eq!(
                Some(key.assignment_id.as_str()),
                declared_key["assignmentId"].as_str(),
                "{label}: assignmentId"
            );
            assert_eq!(
                Some(key.ci_id.as_str()),
                declared_key["ciId"].as_str(),
                "{label}: ciId"
            );
            assert_eq!(
                key.package_id.as_deref(),
                declared_key["packageId"].as_str(),
                "{label}: packageId"
            );
            assert_eq!(
                key.content_id.as_deref(),
                declared_key["contentId"].as_str(),
                "{label}: contentId"
            );
            assert_eq!(
                key.content_version.map(u64::from),
                declared_key["contentVersion"].as_u64(),
                "{label}: contentVersion"
            );
            assert_eq!(
                key.distribution_point_host_handle.as_deref(),
                declared_key["distributionPointHostHandle"].as_str(),
                "{label}: distributionPointHostHandle"
            );
            assert_eq!(
                key.request_id.as_deref(),
                declared_key["requestId"].as_str(),
                "{label}: requestId"
            );
            assert_eq!(
                key.bits_job_id.as_deref(),
                declared_key["bitsJobId"].as_str(),
                "{label}: bitsJobId"
            );
            assert_eq!(
                key.product_code.as_deref(),
                declared_key["productCode"].as_str(),
                "{label}: productCode"
            );
            assert_eq!(
                key.exit_code.as_deref(),
                declared_key["exitCode"].as_str(),
                "{label}: exitCode"
            );
        }
    }
}

#[test]
fn declared_transaction_evidence_spans_are_reproduced_exactly() {
    for scenario in SCENARIOS {
        let analysis = analyze_client_deployment(&load_bundle(scenario));
        let expected = expected(scenario);
        let declared = expected["transactions"]
            .as_array()
            .expect("declared transactions are an array");

        for (produced, declared) in analysis.transactions.iter().zip(declared) {
            let label = format!("{scenario}/{}", produced.transaction_id);
            let produced_spans = produced
                .evidence
                .iter()
                .map(|reference| {
                    (
                        reference.artifact_id.clone(),
                        reference.line_start,
                        reference.line_end,
                    )
                })
                .collect::<Vec<_>>();
            let declared_spans = declared["evidence"]
                .as_array()
                .expect("declared evidence is an array")
                .iter()
                .map(|reference| {
                    (
                        reference["artifactId"]
                            .as_str()
                            .expect("declared artifactId")
                            .to_owned(),
                        reference["startLine"].as_u64().map(|line| line as u32),
                        reference["endLine"].as_u64().map(|line| line as u32),
                    )
                })
                .collect::<Vec<_>>();
            assert_eq!(produced_spans, declared_spans, "{label}: evidence spans");
        }
    }
}

#[test]
fn counterpart_ready_facts_match_the_declared_content_request_boundary() {
    for scenario in SCENARIOS {
        let analysis = analyze_client_deployment(&load_bundle(scenario));
        let expected = expected(scenario);
        let declared = expected["transactions"]
            .as_array()
            .expect("declared transactions are an array");

        for (produced, declared) in analysis.transactions.iter().zip(declared) {
            let label = format!("{scenario}/{}", produced.transaction_id);
            let declared_fact = &declared["counterpartReadyFact"];
            let Some(fact) = produced.counterpart_ready_fact.as_ref() else {
                assert!(
                    declared_fact.is_null(),
                    "{label}: missing declared counterpart-ready fact"
                );
                continue;
            };
            assert!(
                !declared_fact.is_null(),
                "{label}: unexpected counterpart-ready fact"
            );

            assert_eq!(
                phase_name(fact.phase),
                declared_fact["phase"].as_str().expect("declared fact phase"),
                "{label}: counterpart phase"
            );
            assert_eq!(
                fact.extraction_profile_id, SCCM_DEPLOYMENT_TEST_PROFILE_ID,
                "{label}: counterpart profile"
            );
            assert_eq!(
                Some(fact.package_id.as_str()),
                declared_fact["packageId"].as_str(),
                "{label}: counterpart packageId"
            );
            assert_eq!(
                Some(fact.content_id.as_str()),
                declared_fact["contentId"].as_str(),
                "{label}: counterpart contentId"
            );
            assert_eq!(
                Some(u64::from(fact.content_version)),
                declared_fact["contentVersion"].as_u64(),
                "{label}: counterpart contentVersion"
            );
            assert_eq!(
                Some(fact.distribution_point_host_handle.as_str()),
                declared_fact["distributionPointHostHandle"].as_str(),
                "{label}: counterpart distributionPointHostHandle"
            );
            assert_eq!(
                Some(fact.request_id.as_str()),
                declared_fact["requestId"].as_str(),
                "{label}: counterpart requestId"
            );
            assert_eq!(
                Some(fact.timestamp_provenance.normalized_utc.as_str()),
                declared_fact["timestampProvenance"]["normalizedUtc"].as_str(),
                "{label}: counterpart normalized UTC"
            );
            assert_eq!(
                Some(i64::from(fact.timestamp_provenance.offset_minutes)),
                declared_fact["timestampProvenance"]["offsetMinutes"].as_i64(),
                "{label}: counterpart offset"
            );
            assert_eq!(
                Some(fact.evidence.artifact_id.as_str()),
                declared_fact["evidence"]["artifactId"].as_str(),
                "{label}: counterpart evidence artifact"
            );
            assert_eq!(
                fact.evidence.line_start.map(u64::from),
                declared_fact["evidence"]["startLine"].as_u64(),
                "{label}: counterpart evidence start"
            );
            assert_eq!(
                fact.evidence.line_end.map(u64::from),
                declared_fact["evidence"]["endLine"].as_u64(),
                "{label}: counterpart evidence end"
            );
        }
    }
}

#[test]
fn no_scenario_claims_a_distribution_point_or_server_cause() {
    for scenario in SCENARIOS {
        let analysis = analyze_client_deployment(&load_bundle(scenario));
        let handoff = &analysis.correlation_handoff;
        assert!(!handoff.performed, "{scenario}: #333 is not performed here");
        assert!(
            !handoff.time_only_eligible,
            "{scenario}: time alone cannot correlate"
        );
        assert!(
            !handoff.topology_compatibility_evaluated,
            "{scenario}: topology belongs to #333"
        );
        assert!(
            !handoff.server_cause_claimed,
            "{scenario}: no DP or server cause"
        );
        assert_eq!(
            handoff.emitted_counterpart_ready_fact,
            analysis
                .transactions
                .iter()
                .any(|transaction| transaction.counterpart_ready_fact.is_some()),
            "{scenario}: counterpart handoff flag"
        );
    }
}
