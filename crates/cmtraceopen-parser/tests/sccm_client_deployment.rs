//! Behavior contract for the issue #322 client deployment/content reducer.
//!
//! Every expectation is read from the merged issue #322 fixture corpus under
//! `tests/fixtures/sccm/client/deployment`. The corpus is the specification:
//! this file only translates its declared manifests into a normalized bundle
//! and compares the reducer output against the declared expectations.

use std::path::{Path, PathBuf};

use cmtraceopen_parser::sccm::{
    analyze_client_deployment, declared_source_catalog, normalize_ccm_artifact,
    normalize_physical_lines, SccmArtifact, SccmConfidence, SccmCoverageState,
    SccmDeploymentClassification, SccmDeploymentConfidence, SccmDeploymentKeyConfidence,
    SccmDeploymentKeyProfileKind, SccmDeploymentObservationKeyConfidence, SccmDeploymentPhase,
    SccmDeploymentState, SccmEvidence, SccmFindingClass, SccmNormalizedBundle, SccmRole,
    SccmRotation, SCCM_DEPLOYMENT_TEST_PROFILE_ID,
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
            // Complete logical records first, then the physical-line residue an
            // intake must still surface so a fragment is visible without ever
            // becoming a fact.
            evidence.extend(normalize_ccm_artifact(artifact.clone(), &content));
            evidence.extend(normalize_physical_lines(&artifact, &content));
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
                declared["confidence"]
                    .as_str()
                    .expect("declared confidence"),
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
                declared_fact["phase"]
                    .as_str()
                    .expect("declared fact phase"),
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

fn coverage_state_name(state: &SccmCoverageState) -> &'static str {
    match state {
        SccmCoverageState::Captured => "captured",
        SccmCoverageState::Partial => "partial",
        SccmCoverageState::Absent => "absent",
        SccmCoverageState::AccessDenied => "accessDenied",
        SccmCoverageState::Capped => "capped",
        SccmCoverageState::Skipped => "skipped",
        SccmCoverageState::Unsupported => "unsupported",
        SccmCoverageState::ParseFailed => "parseFailed",
    }
}

fn finding_class_name(class: &SccmFindingClass) -> &'static str {
    match class {
        SccmFindingClass::Symptom => "symptom",
        SccmFindingClass::ConfirmedFailure => "confirmedFailure",
        SccmFindingClass::BlockedOrDeferred => "blockedOrDeferred",
        SccmFindingClass::LikelyContributor => "likelyContributor",
        SccmFindingClass::InsufficientEvidence => "insufficientEvidence",
    }
}

fn shared_confidence_name(confidence: &SccmConfidence) -> &'static str {
    match confidence {
        SccmConfidence::None => "none",
        SccmConfidence::Low => "low",
        SccmConfidence::Moderate => "moderate",
        SccmConfidence::High => "high",
    }
}

fn observation_key_confidence_name(
    confidence: SccmDeploymentObservationKeyConfidence,
) -> &'static str {
    match confidence {
        SccmDeploymentObservationKeyConfidence::None => "none",
        SccmDeploymentObservationKeyConfidence::Candidate => "candidate",
    }
}

fn declared_evidence_spans(value: &Value) -> Vec<(String, Option<u32>, Option<u32>)> {
    value
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
        .collect()
}

#[test]
fn declared_group_coverage_is_reproduced_for_every_scenario() {
    for scenario in SCENARIOS {
        let analysis = analyze_client_deployment(&load_bundle(scenario));
        let expected = expected(scenario);
        let declared = expected["coverage"]
            .as_array()
            .expect("declared coverage is an array");

        let produced = analysis
            .coverage
            .iter()
            .map(|row| {
                (
                    row.logical_artifact_id.clone(),
                    coverage_state_name(&row.state),
                )
            })
            .collect::<Vec<_>>();
        let declared_rows = declared
            .iter()
            .map(|row| {
                (
                    row["logicalArtifactId"]
                        .as_str()
                        .expect("declared logicalArtifactId")
                        .to_owned(),
                    row["state"].as_str().expect("declared coverage state"),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(produced, declared_rows, "{scenario}: coverage rows");

        for row in declared {
            let Some(declared_ids) = row["artifactIds"].as_array() else {
                continue;
            };
            let logical_artifact_id = row["logicalArtifactId"]
                .as_str()
                .expect("declared logicalArtifactId");
            let produced_ids = analysis
                .coverage
                .iter()
                .find(|produced| produced.logical_artifact_id == logical_artifact_id)
                .map(|produced| produced.artifact_ids.clone())
                .expect("coverage row exists");
            let declared_ids = declared_ids
                .iter()
                .map(|id| id.as_str().expect("declared artifact id").to_owned())
                .collect::<Vec<_>>();
            assert_eq!(
                produced_ids, declared_ids,
                "{scenario}/{logical_artifact_id}: partial coverage artifact ids"
            );
        }
    }
}

#[test]
fn declared_next_artifacts_and_coverage_gaps_are_reproduced() {
    for scenario in SCENARIOS {
        let analysis = analyze_client_deployment(&load_bundle(scenario));
        let expected = expected(scenario);
        let declared = expected["transactions"]
            .as_array()
            .expect("declared transactions are an array");

        for (produced, declared) in analysis.transactions.iter().zip(declared) {
            let label = format!("{scenario}/{}", produced.transaction_id);
            let declared_ids = declared["coverageGapArtifactIds"]
                .as_array()
                .expect("declared coverage gap ids")
                .iter()
                .map(|id| id.as_str().expect("declared gap id").to_owned())
                .collect::<Vec<_>>();
            assert_eq!(
                produced.coverage_gap_artifact_ids, declared_ids,
                "{label}: coverage gap artifact ids"
            );

            match produced.next_artifact.as_ref() {
                Some(request) => {
                    assert_eq!(
                        Some(request.logical_artifact_id.as_str()),
                        declared["nextArtifact"]["logicalArtifactId"].as_str(),
                        "{label}: next artifact group"
                    );
                    assert_eq!(
                        Some(request.reason.as_str()),
                        declared["nextArtifact"]["reason"].as_str(),
                        "{label}: next artifact reason"
                    );
                }
                None => assert!(
                    declared["nextArtifact"].is_null(),
                    "{label}: unexpected next artifact"
                ),
            }
        }
    }
}

#[test]
fn declared_source_local_observations_stay_low_and_uncorrelatable() {
    for scenario in SCENARIOS {
        let analysis = analyze_client_deployment(&load_bundle(scenario));
        let expected = expected(scenario);
        let declared = expected["sourceLocalObservations"]
            .as_array()
            .expect("declared observations are an array");

        assert_eq!(
            analysis.source_local_observations.len(),
            declared.len(),
            "{scenario}: source-local observation count"
        );

        for declared in declared {
            let artifact_id = declared["artifactId"]
                .as_str()
                .expect("declared observation artifact");
            let produced = analysis
                .source_local_observations
                .iter()
                .find(|observation| observation.artifact_id == artifact_id)
                .unwrap_or_else(|| panic!("{scenario}: no observation for {artifact_id}"));
            let label = format!("{scenario}/{artifact_id}");

            assert_eq!(
                produced.complete_logical_record,
                declared["completeLogicalRecord"]
                    .as_bool()
                    .expect("declared completeLogicalRecord"),
                "{label}: complete logical record"
            );
            assert_eq!(
                observation_key_confidence_name(produced.key_confidence),
                declared["keyConfidence"]
                    .as_str()
                    .expect("declared keyConfidence"),
                "{label}: key confidence"
            );
            assert_eq!(
                confidence_name(produced.confidence_ceiling),
                declared["confidenceCeiling"]
                    .as_str()
                    .expect("declared confidenceCeiling"),
                "{label}: confidence ceiling"
            );
            assert_eq!(
                produced.correlation_eligible,
                declared["correlationEligible"]
                    .as_bool()
                    .expect("declared correlationEligible"),
                "{label}: correlation eligibility"
            );
            assert_eq!(
                (
                    produced.evidence.artifact_id.clone(),
                    produced.evidence.line_start,
                    produced.evidence.line_end,
                ),
                (
                    declared["evidence"]["artifactId"]
                        .as_str()
                        .expect("declared observation evidence artifact")
                        .to_owned(),
                    declared["evidence"]["startLine"]
                        .as_u64()
                        .map(|line| line as u32),
                    declared["evidence"]["endLine"]
                        .as_u64()
                        .map(|line| line as u32),
                ),
                "{label}: observation evidence"
            );
        }
    }
}

#[test]
fn declared_findings_are_produced_and_respect_their_prohibited_claims() {
    for scenario in SCENARIOS {
        let analysis = analyze_client_deployment(&load_bundle(scenario));
        let expected = expected(scenario);

        for declared in expected["findings"]
            .as_array()
            .expect("declared findings are an array")
        {
            let finding_id = declared["findingId"].as_str().expect("declared findingId");
            let produced = analysis
                .findings
                .iter()
                .find(|finding| finding.finding.finding_id == finding_id)
                .unwrap_or_else(|| panic!("{scenario}: no finding {finding_id}"));
            let label = format!("{scenario}/{finding_id}");

            assert_eq!(
                finding_class_name(&produced.finding.class),
                declared["class"].as_str().expect("declared class"),
                "{label}: class"
            );
            assert_eq!(
                phase_name(produced.deployment_phase),
                declared["phase"].as_str().expect("declared phase"),
                "{label}: phase"
            );
            assert_eq!(produced.finding.role, SccmRole::Client, "{label}: role");
            assert_eq!(
                declared["role"].as_str(),
                Some("client"),
                "{label}: declared role"
            );
            assert_eq!(
                shared_confidence_name(&produced.finding.confidence),
                declared["confidence"]
                    .as_str()
                    .expect("declared confidence"),
                "{label}: confidence"
            );

            let produced_spans = produced
                .finding
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
            assert_eq!(
                produced_spans,
                declared_evidence_spans(&declared["evidence"]),
                "{label}: finding evidence"
            );

            let produced_gaps = produced
                .finding
                .coverage_gaps
                .iter()
                .map(|gap| gap.artifact_id.clone())
                .collect::<Vec<_>>();
            let declared_gaps = declared["coverageGapArtifactIds"]
                .as_array()
                .expect("declared finding coverage gaps")
                .iter()
                .map(|id| id.as_str().expect("declared gap id").to_owned())
                .collect::<Vec<_>>();
            assert_eq!(
                produced_gaps, declared_gaps,
                "{label}: finding coverage gaps"
            );

            let claim_text = format!(
                "{} {}",
                produced.finding.title.to_ascii_lowercase(),
                produced.finding.summary.to_ascii_lowercase()
            );
            for prohibited in declared["mustNotClaim"]
                .as_array()
                .expect("declared prohibited claims")
            {
                let prohibited = prohibited
                    .as_str()
                    .expect("declared prohibited claim")
                    .to_ascii_lowercase();
                assert!(
                    !claim_text.contains(&prohibited),
                    "{label}: finding claims {prohibited}"
                );
            }
        }
    }
}

#[test]
fn every_finding_satisfies_the_shared_finding_contract() {
    for scenario in SCENARIOS {
        let analysis = analyze_client_deployment(&load_bundle(scenario));
        let catalog = declared_source_catalog();

        for finding in &analysis.findings {
            finding.finding.validate().unwrap_or_else(|error| {
                panic!(
                    "{scenario}/{}: shared finding contract: {error:?}",
                    finding.finding.finding_id
                )
            });
            for request in &finding.finding.next_artifacts {
                assert!(
                    catalog
                        .iter()
                        .any(|entry| entry.logical_name == request.logical_id
                            && entry.role == request.role),
                    "{scenario}/{}: undeclared next artifact {}",
                    finding.finding.finding_id,
                    request.logical_id
                );
            }
        }

        for request in analysis
            .findings
            .iter()
            .flat_map(|finding| finding.finding.next_artifacts.iter().cloned())
        {
            assert!(
                analysis.artifact_requests.contains(&request),
                "{scenario}: aggregated artifact requests omit {}",
                request.logical_id
            );
        }
        for gap in analysis
            .findings
            .iter()
            .flat_map(|finding| finding.finding.coverage_gaps.iter().cloned())
        {
            assert!(
                analysis.coverage_gaps.contains(&gap),
                "{scenario}: aggregated coverage gaps omit {}",
                gap.artifact_id
            );
        }
    }
}

#[test]
fn reordering_the_bundle_never_changes_the_analysis() {
    for scenario in SCENARIOS {
        let bundle = load_bundle(scenario);
        let forward = analyze_client_deployment(&bundle);

        let reversed = SccmNormalizedBundle {
            artifacts: bundle.artifacts.iter().rev().cloned().collect(),
            evidence: bundle.evidence.iter().rev().cloned().collect(),
        };
        assert_eq!(
            analyze_client_deployment(&reversed),
            forward,
            "{scenario}: reordered input changed the analysis"
        );
    }
}
