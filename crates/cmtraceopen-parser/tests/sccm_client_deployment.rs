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
    SccmDeploymentProfileSelectionState, SccmDeploymentState, SccmEvidence, SccmFindingClass,
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

// ---------------------------------------------------------------------------
// Synthetic adversarial contracts
//
// These cases cannot exist in the merged corpus but are exactly the ways a
// deployment reducer overstates evidence in the field.
// ---------------------------------------------------------------------------

const ASSIGNMENT: &str = "10000000-0000-0000-0000-0000000000a1";
const CI: &str = "20000000-0000-0000-0000-0000000000a2";
const CONTENT: &str = "30000000-0000-0000-0000-0000000000a3";
const REQUEST: &str = "40000000-0000-0000-0000-0000000000a4";
const BITS_JOB: &str = "50000000-0000-0000-0000-0000000000a5";
const PRODUCT: &str = "60000000-0000-0000-0000-0000000000a6";
const OTHER_CI: &str = "20000000-0000-0000-0000-0000000000b2";

fn client_artifact(artifact_id: &str, basename: &str) -> SccmArtifact {
    SccmArtifact {
        artifact_id: artifact_id.to_owned(),
        display_name: basename.to_owned(),
        original_path: None,
        host: None,
        role: SccmRole::Client,
        configmgr_version: Some("5.00.TEST.0000".to_owned()),
        collected_at_utc: None,
        rotation: SccmRotation::Current,
        coverage: SccmCoverageState::Captured,
        encoding: Some("utf-8".to_owned()),
    }
}

fn record(message: &str, time: &str, component: &str) -> String {
    format!(
        "<![LOG[{message}]LOG]!><time=\"{time}\" date=\"07-30-2026\" component=\"{component}\" context=\"\" type=\"1\" thread=\"1\" file=\"synthetic.cc:1\">\n"
    )
}

fn bundle_from(sources: Vec<(SccmArtifact, String)>) -> SccmNormalizedBundle {
    let mut artifacts = Vec::new();
    let mut evidence = Vec::new();
    for (artifact, content) in sources {
        evidence.extend(normalize_ccm_artifact(artifact.clone(), &content));
        evidence.extend(normalize_physical_lines(&artifact, &content));
        artifacts.push(artifact);
    }
    SccmNormalizedBundle {
        artifacts,
        evidence,
    }
}

fn intent_content() -> String {
    format!(
        "{}{}",
        record(
            &format!(
                "SYNTHETIC FIXTURE deployment targeted assignmentId={ASSIGNMENT} ciId={CI} state=targeted"
            ),
            "05:00:00.000+000",
            "AppIntentEval",
        ),
        record(
            &format!("Requirements satisfied assignmentId={ASSIGNMENT} ciId={CI}"),
            "05:00:01.000+000",
            "AppIntentEval",
        ),
    )
}

fn content_content() -> String {
    format!(
        "{}{}",
        record(
            &format!(
                "SYNTHETIC FIXTURE deployment content located assignmentId={ASSIGNMENT} ciId={CI} packageId=LAB00021 contentId={CONTENT} contentVersion=21 distributionPointHostHandle=safe:dp:lab-dp-02 requestId={REQUEST} siteCode=LAB"
            ),
            "05:00:02.000+000",
            "CAS",
        ),
        record(
            &format!(
                "Cache commit completed assignmentId={ASSIGNMENT} ciId={CI} contentId={CONTENT} contentVersion=21"
            ),
            "05:00:05.000+000",
            "CAS",
        ),
    )
}

fn transfer_content(started_time: &str, completed_time: &str) -> String {
    format!(
        "{}{}",
        record(
            &format!(
                "SYNTHETIC FIXTURE deployment transfer started assignmentId={ASSIGNMENT} contentId={CONTENT} contentVersion=21 requestId={REQUEST} bitsJobId={BITS_JOB}"
            ),
            started_time,
            "DataTransferService",
        ),
        record(
            &format!("Transfer completed assignmentId={ASSIGNMENT} contentId={CONTENT} bitsJobId={BITS_JOB}"),
            completed_time,
            "DataTransferService",
        ),
    )
}

fn only_transaction(
    analysis: &cmtraceopen_parser::sccm::SccmDeploymentAnalysis,
) -> &cmtraceopen_parser::sccm::SccmDeploymentTransaction {
    assert_eq!(analysis.transactions.len(), 1, "expected one transaction");
    &analysis.transactions[0]
}

#[test]
fn a_duplicate_client_artifact_identity_reports_coverage_only() {
    let artifact = client_artifact("synthetic-intent", "AppIntentEval.log");
    let mut bundle = bundle_from(vec![(artifact.clone(), intent_content())]);
    assert_eq!(
        analyze_client_deployment(&bundle).transactions.len(),
        1,
        "the same bundle without a collision must produce a transaction"
    );

    bundle.artifacts.push(artifact);
    let analysis = analyze_client_deployment(&bundle);
    assert!(
        analysis.transactions.is_empty(),
        "an ambiguous artifact identity cannot elect a source"
    );
    assert!(analysis.findings.is_empty());
    assert!(
        !analysis.coverage.is_empty(),
        "coverage still reports what was collected"
    );
}

#[test]
fn a_duplicate_evidence_identity_reports_coverage_only() {
    let artifact = client_artifact("synthetic-intent", "AppIntentEval.log");
    let mut bundle = bundle_from(vec![(artifact, intent_content())]);
    bundle.evidence.extend(bundle.evidence.clone());

    let analysis = analyze_client_deployment(&bundle);
    assert!(
        analysis.transactions.is_empty(),
        "a duplicated logical record cannot be an authority"
    );
    assert!(analysis.findings.is_empty());
}

#[test]
fn an_artifact_from_another_role_never_decides_a_client_source() {
    let client = client_artifact("shared-identity", "AppIntentEval.log");
    let mut management_point = client.clone();
    management_point.role = SccmRole::ManagementPoint;
    management_point.display_name = "mpcontrol.log".to_owned();

    let mut forward = bundle_from(vec![(client.clone(), intent_content())]);
    let mut reversed = forward.clone();
    forward.artifacts.push(management_point.clone());
    reversed.artifacts.insert(0, management_point);

    for (label, bundle) in [("client first", forward), ("client last", reversed)] {
        let analysis = analyze_client_deployment(&bundle);
        let transaction = only_transaction(&analysis);
        assert_eq!(
            transaction.key.assignment_id, ASSIGNMENT,
            "{label}: client source was displaced by another role"
        );
        assert_eq!(
            phase_name(transaction.phase),
            "locateContent",
            "{label}: phase"
        );
    }
}

#[test]
fn an_unorderable_terminal_record_downgrades_to_a_low_confidence_symptom() {
    let failing_transfer = format!(
        "{}{}",
        record(
            &format!(
                "SYNTHETIC FIXTURE deployment transfer started assignmentId={ASSIGNMENT} contentId={CONTENT} contentVersion=21 requestId={REQUEST} bitsJobId={BITS_JOB}"
            ),
            "05:00:03.000",
            "DataTransferService",
        ),
        record(
            &format!(
                "Transfer terminal failure assignmentId={ASSIGNMENT} contentId={CONTENT} bitsJobId={BITS_JOB} errorCode=0x80070020 terminal=true"
            ),
            "05:00:04.000",
            "DataTransferService",
        ),
    );
    let bundle = bundle_from(vec![
        (
            client_artifact("synthetic-intent", "AppIntentEval.log"),
            intent_content(),
        ),
        (
            client_artifact("synthetic-content", "CAS.log"),
            content_content(),
        ),
        (
            client_artifact("synthetic-transfer", "DataTransferService.log"),
            failing_transfer,
        ),
    ]);

    let analysis = analyze_client_deployment(&bundle);
    let transaction = only_transaction(&analysis);
    assert_eq!(phase_name(transaction.phase), "transfer");
    assert_eq!(state_name(transaction.state), "insufficientEvidence");
    assert_eq!(classification_name(transaction.classification), "symptom");
    assert_eq!(confidence_name(transaction.confidence), "low");
    assert!(
        analysis.findings.iter().any(|finding| finding
            .finding
            .finding_id
            .starts_with("deployment-chronology-uncertain")),
        "an unorderable chain must name the missing ordering evidence"
    );
}

#[test]
fn a_transfer_pair_is_elected_together_across_two_attempts() {
    // A rotated transfer source keeps the completion of an attempt whose start
    // has already scrolled out, so the earliest completion in canonical
    // reference order belongs to a different attempt than the earliest start.
    let orphan_completion = record(
        &format!(
            "Transfer completed assignmentId={ASSIGNMENT} contentId={CONTENT} bitsJobId={BITS_JOB}"
        ),
        "05:00:03.000+000",
        "ContentTransferManager",
    );
    let bundle = bundle_from(vec![
        (
            client_artifact("synthetic-intent", "AppIntentEval.log"),
            intent_content(),
        ),
        (
            client_artifact("synthetic-content", "CAS.log"),
            content_content(),
        ),
        (
            client_artifact("synthetic-transfer-a", "ContentTransferManager.log"),
            orphan_completion,
        ),
        (
            client_artifact("synthetic-transfer-b", "DataTransferService.log"),
            transfer_content("05:00:03.500+000", "05:00:04.000+000"),
        ),
        (
            client_artifact("synthetic-enforce", "AppEnforce.log"),
            record(
                &format!(
                    "SYNTHETIC FIXTURE deployment enforcement terminal failure assignmentId={ASSIGNMENT} ciId={CI} productCode={PRODUCT} exitCode=1603 terminal=true"
                ),
                "05:00:06.000+000",
                "AppEnforce",
            ),
        ),
    ]);

    let analysis = analyze_client_deployment(&bundle);
    let transaction = only_transaction(&analysis);
    assert_eq!(
        transaction.last_successful_phase.map(phase_name),
        Some("cache"),
        "one attempt is fully ordered, so the transfer phase must be admitted"
    );
    assert_eq!(phase_name(transaction.phase), "enforce");
    assert_eq!(
        state_name(transaction.state),
        "failed",
        "a terminal enforcement record stays terminal when the chain is orderable"
    );
    assert_eq!(
        classification_name(transaction.classification),
        "confirmedFailure"
    );
    assert!(
        !analysis.findings.iter().any(|finding| finding
            .finding
            .finding_id
            .starts_with("deployment-chronology-uncertain")),
        "an orderable start and completion must not be reported as unorderable"
    );
}

#[test]
fn a_label_embedded_in_a_longer_phrase_is_not_a_requirements_outcome() {
    let embedded = format!(
        "{}{}",
        record(
            &format!(
                "SYNTHETIC FIXTURE deployment targeted assignmentId={ASSIGNMENT} ciId={CI} state=targeted"
            ),
            "05:00:00.000+000",
            "AppIntentEval",
        ),
        record(
            &format!("Base requirements satisfied assignmentId={ASSIGNMENT} ciId={CI}"),
            "05:00:01.000+000",
            "AppIntentEval",
        ),
    );
    let bundle = bundle_from(vec![(
        client_artifact("synthetic-intent", "AppIntentEval.log"),
        embedded,
    )]);

    let analysis = analyze_client_deployment(&bundle);
    let transaction = only_transaction(&analysis);
    assert_eq!(phase_name(transaction.phase), "requirements");
    assert_eq!(state_name(transaction.state), "insufficientEvidence");
    assert_eq!(
        transaction.last_successful_phase.map(phase_name),
        Some("intent")
    );
}

#[test]
fn a_duplicated_key_label_fails_closed_for_the_whole_record() {
    let duplicated = record(
        &format!(
            "SYNTHETIC FIXTURE deployment targeted assignmentId={ASSIGNMENT} assignmentId={ASSIGNMENT} ciId={CI} state=targeted"
        ),
        "05:00:00.000+000",
        "AppIntentEval",
    );
    let bundle = bundle_from(vec![(
        client_artifact("synthetic-intent", "AppIntentEval.log"),
        duplicated,
    )]);

    let analysis = analyze_client_deployment(&bundle);
    assert!(
        analysis.transactions.is_empty(),
        "a duplicated exact-token label cannot pick a value"
    );
}

#[test]
fn two_configuration_items_under_one_assignment_never_form_a_transaction() {
    let ambiguous = format!(
        "{}{}",
        record(
            &format!(
                "SYNTHETIC FIXTURE deployment targeted assignmentId={ASSIGNMENT} ciId={CI} state=targeted"
            ),
            "05:00:00.000+000",
            "AppIntentEval",
        ),
        record(
            &format!(
                "SYNTHETIC FIXTURE deployment targeted assignmentId={ASSIGNMENT} ciId={OTHER_CI} state=targeted"
            ),
            "05:00:01.000+000",
            "AppIntentEval",
        ),
    );
    let bundle = bundle_from(vec![(
        client_artifact("synthetic-intent", "AppIntentEval.log"),
        ambiguous,
    )]);

    let analysis = analyze_client_deployment(&bundle);
    assert!(
        analysis.transactions.is_empty(),
        "two configuration items cannot share one exact transaction key"
    );
}

#[test]
fn an_unprofiled_source_version_stays_a_source_local_observation() {
    let mut artifact = client_artifact("synthetic-intent", "AppIntentEval.log");
    artifact.configmgr_version = Some("5.00.PROD.9128".to_owned());
    let bundle = bundle_from(vec![(artifact, intent_content())]);

    let analysis = analyze_client_deployment(&bundle);
    assert!(
        analysis.transactions.is_empty(),
        "an unprofiled version cannot produce facts"
    );
    assert_eq!(analysis.source_local_observations.len(), 1);
    let observation = &analysis.source_local_observations[0];
    assert!(observation.complete_logical_record);
    assert!(!observation.correlation_eligible);
    assert_eq!(
        confidence_name(observation.confidence_ceiling),
        "low",
        "an unprofiled record stays capped at low confidence"
    );
    assert!(
        analysis
            .extraction_profile
            .validated_artifact_families
            .is_empty(),
        "a captured source the profile could not read is not a validated family"
    );
}

#[test]
fn a_nonzero_exit_code_without_a_terminal_record_is_not_a_confirmed_failure() {
    let enforcement = record(
        &format!(
            "SYNTHETIC FIXTURE deployment enforcement terminal failure assignmentId={ASSIGNMENT} ciId={CI} productCode={PRODUCT} exitCode=1603"
        ),
        "05:00:06.000+000",
        "AppEnforce",
    );
    let bundle = bundle_from(vec![
        (
            client_artifact("synthetic-intent", "AppIntentEval.log"),
            intent_content(),
        ),
        (
            client_artifact("synthetic-content", "CAS.log"),
            content_content(),
        ),
        (
            client_artifact("synthetic-transfer", "DataTransferService.log"),
            transfer_content("05:00:03.000+000", "05:00:04.000+000"),
        ),
        (
            client_artifact("synthetic-enforce", "AppEnforce.log"),
            enforcement,
        ),
    ]);

    let analysis = analyze_client_deployment(&bundle);
    let transaction = only_transaction(&analysis);
    assert_eq!(phase_name(transaction.phase), "enforce");
    assert_ne!(
        classification_name(transaction.classification),
        "confirmedFailure",
        "a bare AppEnforce exit code is not a root cause"
    );
    assert_eq!(state_name(transaction.state), "insufficientEvidence");
    assert_eq!(
        transaction.last_successful_phase.map(phase_name),
        Some("cache")
    );
    assert_eq!(
        transaction
            .next_artifact
            .as_ref()
            .map(|request| request.logical_artifact_id.as_str()),
        Some("client-app-enforce")
    );
    assert!(transaction.key.exit_code.is_none(), "no admitted exit code");
}

#[test]
fn the_public_projection_is_camel_case_and_carries_no_private_material() {
    for scenario in SCENARIOS {
        let analysis = analyze_client_deployment(&load_bundle(scenario));
        let json = serde_json::to_value(&analysis)
            .unwrap_or_else(|error| panic!("{scenario}: analysis serializes: {error}"));

        for field in [
            "schemaVersion",
            "workflow",
            "extractionProfile",
            "coverage",
            "transactions",
            "sourceLocalObservations",
            "findings",
            "coverageGaps",
            "artifactRequests",
            "correlationHandoff",
        ] {
            assert!(
                json.get(field).is_some(),
                "{scenario}: public field {field} is missing"
            );
        }

        let mut keys = Vec::new();
        collect_object_keys(&json, &mut keys);
        for key in keys {
            assert!(
                !key.contains('_') && key.chars().next().is_some_and(char::is_lowercase),
                "{scenario}: public field {key} is not camelCase"
            );
        }

        let text = serde_json::to_string(&analysis).expect("analysis serializes");
        for forbidden in [
            "CONTOSO",
            "C:\\\\Users\\\\",
            "S-1-",
            "Bearer ",
            "client_secret",
        ] {
            assert!(
                !text.contains(forbidden),
                "{scenario}: public projection contains {forbidden}"
            );
        }
    }
}

fn collect_object_keys(value: &Value, keys: &mut Vec<String>) {
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                keys.push(key.clone());
                collect_object_keys(child, keys);
            }
        }
        Value::Array(array) => {
            for child in array {
                collect_object_keys(child, keys);
            }
        }
        _ => {}
    }
}

/// Scenarios whose declared `extractionProfile` states what the bundle
/// actually produced rather than the profile's full capability list.
const OBSERVED_KEY_KIND_SCENARIOS: [&str; 8] = [
    "bits-transfer-failure",
    "cache-failure",
    "detection-false-negative",
    "dp-content-missing",
    "enforcement-exit",
    "incomplete",
    "rotation-boundary",
    "success",
];

/// `rotation-boundary` additionally declares `client-content` as a validated
/// family even though none of its rotation fragments ever formed a record, so
/// its family list is not observation derived.
const OBSERVED_FAMILY_SCENARIOS: [&str; 7] = [
    "bits-transfer-failure",
    "cache-failure",
    "detection-false-negative",
    "dp-content-missing",
    "enforcement-exit",
    "incomplete",
    "success",
];

#[test]
fn the_selected_extraction_profile_reports_what_the_bundle_validated() {
    for scenario in SCENARIOS {
        let analysis = analyze_client_deployment(&load_bundle(scenario));
        let expected = expected(scenario);
        let declared = &expected["extractionProfile"];
        let profile = &analysis.extraction_profile;

        assert_eq!(
            Some(profile.profile_id.as_str()),
            declared["profileId"].as_str(),
            "{scenario}: profile id"
        );
        assert_eq!(
            Some(profile.source_version_prefix.as_str()),
            declared["sourceVersionPrefix"].as_str(),
            "{scenario}: source version prefix"
        );
        assert_eq!(
            Some(profile.content_version_required),
            declared["contentVersionRequired"].as_bool(),
            "{scenario}: content version requirement"
        );

        if OBSERVED_KEY_KIND_SCENARIOS.contains(&scenario) {
            let declared_kinds = declared["keyKinds"]
                .as_array()
                .expect("declared key kinds")
                .iter()
                .map(|kind| kind.as_str().expect("declared key kind").to_owned())
                .collect::<Vec<_>>();
            assert_eq!(profile.key_kinds, declared_kinds, "{scenario}: key kinds");
        }

        if OBSERVED_FAMILY_SCENARIOS.contains(&scenario) {
            let declared_families = declared["validatedArtifactFamilies"]
                .as_array()
                .expect("declared validated families")
                .iter()
                .map(|family| family.as_str().expect("declared family").to_owned())
                .collect::<Vec<_>>();
            assert_eq!(
                profile.validated_artifact_families, declared_families,
                "{scenario}: validated artifact families"
            );
        }

        for family in &profile.validated_artifact_families {
            assert!(
                analysis
                    .coverage
                    .iter()
                    .any(|row| &row.logical_artifact_id == family),
                "{scenario}: validated family {family} has no coverage row"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Review defects: a fragment is not a record, ambiguity is not a choice, a
// boundary miss is not a discard, and a group representative may not speak for
// evidence it does not represent.
// ---------------------------------------------------------------------------

const OTHER_ASSIGNMENT: &str = "10000000-0000-0000-0000-0000000000c1";
const OTHER_CONTENT: &str = "30000000-0000-0000-0000-0000000000c3";
const OTHER_REQUEST: &str = "40000000-0000-0000-0000-0000000000c4";

fn rotated_artifact(artifact_id: &str, basename: &str, rotation: SccmRotation) -> SccmArtifact {
    let mut artifact = client_artifact(artifact_id, basename);
    artifact.rotation = rotation;
    artifact
}

fn intent_record() -> String {
    record(
        &format!(
            "SYNTHETIC FIXTURE deployment targeted assignmentId={ASSIGNMENT} ciId={CI} state=targeted"
        ),
        "05:00:00.000+000",
        "AppIntentEval",
    )
}

#[test]
fn a_physical_fragment_inside_a_captured_artifact_never_becomes_a_fact() {
    let content = format!(
        "{}Requirements satisfied assignmentId={ASSIGNMENT} ciId={CI}\n",
        intent_record()
    );
    let bundle = bundle_from(vec![(
        client_artifact("synthetic-intent", "AppIntentEval.log"),
        content,
    )]);

    let analysis = analyze_client_deployment(&bundle);
    let transaction = only_transaction(&analysis);
    assert_eq!(
        phase_name(transaction.phase),
        "requirements",
        "an unframed line cannot satisfy requirements"
    );
    assert_eq!(
        transaction.last_successful_phase.map(phase_name),
        Some("intent"),
        "a fragment cannot promote the last successful phase"
    );
    assert!(
        analysis
            .source_local_observations
            .iter()
            .any(|observation| observation.artifact_id == "synthetic-intent"
                && !observation.complete_logical_record),
        "the fragment must still be visible as a source-local observation"
    );
}

#[test]
fn a_physical_fragment_never_confirms_a_terminal_failure() {
    let content = format!(
        "{}Requirements terminal failure assignmentId={ASSIGNMENT} ciId={CI} requirementId=REQ-TEST-901 terminal=true\n",
        intent_record()
    );
    let bundle = bundle_from(vec![(
        client_artifact("synthetic-intent", "AppIntentEval.log"),
        content,
    )]);

    let analysis = analyze_client_deployment(&bundle);
    let transaction = only_transaction(&analysis);
    assert_ne!(
        classification_name(transaction.classification),
        "confirmedFailure",
        "an unframed line cannot confirm a terminal failure"
    );
    assert_ne!(confidence_name(transaction.confidence), "high");
}

#[test]
fn an_ambiguous_content_request_is_never_published_cross_side() {
    let located = |content_id: &str, request_id: &str, package: &str| {
        record(
            &format!(
                "SYNTHETIC FIXTURE deployment content located assignmentId={ASSIGNMENT} ciId={CI} packageId={package} contentId={content_id} contentVersion=21 distributionPointHostHandle=safe:dp:lab-dp-02 requestId={request_id} siteCode=LAB"
            ),
            "05:00:02.000+000",
            "CAS",
        )
    };

    for (label, first_id, second_id) in [
        ("alphabetical", "synthetic-content-a", "synthetic-content-b"),
        ("renamed", "synthetic-content-z", "synthetic-content-y"),
    ] {
        let bundle = bundle_from(vec![
            (
                client_artifact("synthetic-intent", "AppIntentEval.log"),
                intent_content(),
            ),
            (
                client_artifact(first_id, "CAS.log"),
                located(CONTENT, REQUEST, "LAB00021"),
            ),
            (
                rotated_artifact(second_id, "CAS.log.1", SccmRotation::Numbered(1)),
                located(OTHER_CONTENT, OTHER_REQUEST, "LAB00022"),
            ),
        ]);

        let analysis = analyze_client_deployment(&bundle);
        let transaction = only_transaction(&analysis);
        assert_eq!(
            key_profile_name(transaction.key.key_profile_kind),
            "assignmentCi",
            "{label}: an ambiguous topology cannot key a transaction"
        );
        assert!(transaction.key.content_id.is_none(), "{label}: content id");
        assert!(
            transaction.counterpart_ready_fact.is_none(),
            "{label}: an ambiguous content request must never be published cross-side"
        );
        assert!(
            !analysis.correlation_handoff.emitted_counterpart_ready_fact,
            "{label}: correlation handoff flag"
        );
    }
}

#[test]
fn a_punctuation_adjacent_duplicate_label_is_ambiguity_not_a_first_win() {
    let cases = [
        (
            "terminal",
            format!(
                "SYNTHETIC FIXTURE deployment enforcement terminal failure assignmentId={ASSIGNMENT} ciId={CI} productCode={PRODUCT} exitCode=1603 terminal=true (terminal=false)"
            ),
        ),
        (
            "exit code",
            format!(
                "SYNTHETIC FIXTURE deployment enforcement terminal failure assignmentId={ASSIGNMENT} ciId={CI} productCode={PRODUCT} exitCode=1603 (exitCode=0) terminal=true"
            ),
        ),
    ];

    for (label, message) in cases {
        let bundle = bundle_from(vec![
            (
                client_artifact("synthetic-intent", "AppIntentEval.log"),
                intent_content(),
            ),
            (
                client_artifact("synthetic-content", "CAS.log"),
                content_content(),
            ),
            (
                client_artifact("synthetic-transfer", "DataTransferService.log"),
                transfer_content("05:00:03.000+000", "05:00:04.000+000"),
            ),
            (
                client_artifact("synthetic-enforce", "AppEnforce.log"),
                record(&message, "05:00:06.000+000", "AppEnforce"),
            ),
        ]);

        let analysis = analyze_client_deployment(&bundle);
        let transaction = only_transaction(&analysis);
        assert_ne!(
            classification_name(transaction.classification),
            "confirmedFailure",
            "{label}: a conflicting duplicate label cannot confirm a failure"
        );
        assert_ne!(
            confidence_name(transaction.confidence),
            "high",
            "{label}: confidence"
        );
    }
}

#[test]
fn a_chronology_finding_never_speaks_for_another_phase() {
    let unorderable_requirements = record(
        &format!(
            "Requirements terminal failure assignmentId={OTHER_ASSIGNMENT} ciId={CI} requirementId=REQ-TEST-902 terminal=true"
        ),
        "05:00:01.000",
        "AppIntentEval",
    );
    let other_intent = record(
        &format!(
            "SYNTHETIC FIXTURE deployment targeted assignmentId={OTHER_ASSIGNMENT} ciId={CI} state=targeted"
        ),
        "05:00:00.000+000",
        "AppIntentEval",
    );
    let unorderable_enforce = record(
        &format!(
            "SYNTHETIC FIXTURE deployment enforcement terminal failure assignmentId={ASSIGNMENT} ciId={CI} productCode={PRODUCT} exitCode=1603 terminal=true"
        ),
        "05:00:06.000",
        "AppEnforce",
    );

    let bundle = bundle_from(vec![
        (
            client_artifact("synthetic-intent", "AppIntentEval.log"),
            format!("{}{other_intent}", intent_content()),
        ),
        (
            rotated_artifact(
                "synthetic-intent-rotated",
                "AppIntentEval.log.1",
                SccmRotation::Numbered(1),
            ),
            unorderable_requirements,
        ),
        (
            client_artifact("synthetic-content", "CAS.log"),
            content_content(),
        ),
        (
            client_artifact("synthetic-transfer", "DataTransferService.log"),
            transfer_content("05:00:03.000+000", "05:00:04.000+000"),
        ),
        (
            client_artifact("synthetic-enforce", "AppEnforce.log"),
            unorderable_enforce,
        ),
    ]);

    let analysis = analyze_client_deployment(&bundle);
    assert_eq!(analysis.transactions.len(), 2, "two keyed transactions");

    let mut identifiers = analysis
        .findings
        .iter()
        .map(|finding| finding.finding.finding_id.clone())
        .collect::<Vec<_>>();
    let total = identifiers.len();
    identifiers.sort();
    identifiers.dedup();
    assert_eq!(
        identifiers.len(),
        total,
        "finding identities must be unique"
    );

    let mut chronology = analysis
        .findings
        .iter()
        .filter(|finding| {
            finding
                .finding
                .finding_id
                .starts_with("deployment-chronology-uncertain")
        })
        .map(|finding| {
            (
                phase_name(finding.deployment_phase),
                finding
                    .finding
                    .next_artifacts
                    .first()
                    .map(|request| request.logical_id.as_str())
                    .unwrap_or("none"),
            )
        })
        .collect::<Vec<_>>();
    chronology.sort();
    assert_eq!(
        chronology,
        vec![("enforce", "appEnforce"), ("requirements", "appIntentEval")],
        "each unorderable phase must request its own artifact"
    );

    for finding in &analysis.findings {
        let phase = finding.deployment_phase;
        for reference in &finding.finding.evidence {
            let cited_by_this_phase = analysis.transactions.iter().any(|transaction| {
                transaction.phase == phase
                    && transaction
                        .evidence
                        .iter()
                        .any(|cited| cited.artifact_id == reference.artifact_id)
            });
            assert!(
                cited_by_this_phase,
                "{}: cites {} from a transaction at another phase",
                finding.finding.finding_id, reference.artifact_id
            );
        }
    }
}

#[test]
fn every_equally_terminal_record_is_cited_rather_than_one_elected() {
    let enforcement = |exit_code: &str, time: &str| {
        record(
            &format!(
                "SYNTHETIC FIXTURE deployment enforcement terminal failure assignmentId={ASSIGNMENT} ciId={CI} productCode={PRODUCT} exitCode={exit_code} terminal=true"
            ),
            time,
            "AppEnforce",
        )
    };

    for (label, first_id, second_id) in [
        ("alphabetical", "synthetic-enforce-a", "synthetic-enforce-b"),
        ("renamed", "synthetic-enforce-z", "synthetic-enforce-y"),
    ] {
        let bundle = bundle_from(vec![
            (
                client_artifact("synthetic-intent", "AppIntentEval.log"),
                intent_content(),
            ),
            (
                client_artifact("synthetic-content", "CAS.log"),
                content_content(),
            ),
            (
                client_artifact("synthetic-transfer", "DataTransferService.log"),
                transfer_content("05:00:03.000+000", "05:00:04.000+000"),
            ),
            (
                client_artifact(first_id, "AppEnforce.log"),
                enforcement("1603", "05:00:06.000+000"),
            ),
            (
                rotated_artifact(second_id, "AppEnforce.log.1", SccmRotation::Numbered(1)),
                enforcement("1618", "05:00:07.000+000"),
            ),
        ]);

        let analysis = analyze_client_deployment(&bundle);
        let finding = analysis
            .findings
            .iter()
            .find(|finding| finding.finding.finding_id == "deployment-enforce-terminal")
            .unwrap_or_else(|| panic!("{label}: expected an enforcement terminal finding"));

        let mut cited = finding
            .finding
            .terminal_evidence
            .iter()
            .map(|terminal| terminal.reference.artifact_id.clone())
            .collect::<Vec<_>>();
        cited.sort();
        let mut expected = vec![first_id.to_owned(), second_id.to_owned()];
        expected.sort();
        assert_eq!(
            cited, expected,
            "{label}: every equally terminal record must be cited"
        );

        let transaction = only_transaction(&analysis);
        assert!(
            transaction.key.exit_code.is_none(),
            "{label}: two conflicting exit codes cannot key the transaction"
        );
    }
}

fn selection_state_name(state: SccmDeploymentProfileSelectionState) -> &'static str {
    match state {
        SccmDeploymentProfileSelectionState::Selected => "selected",
        SccmDeploymentProfileSelectionState::Unselected => "unselected",
    }
}

#[test]
fn the_extraction_profile_reports_its_selection_state() {
    for scenario in SCENARIOS {
        let analysis = analyze_client_deployment(&load_bundle(scenario));
        let expected = expected(scenario);
        assert_eq!(
            selection_state_name(analysis.extraction_profile.selection_state),
            expected["extractionProfile"]["selectionState"]
                .as_str()
                .expect("declared selection state"),
            "{scenario}: extraction profile selection state"
        );
    }

    let mut unprofiled = client_artifact("synthetic-intent", "AppIntentEval.log");
    unprofiled.configmgr_version = Some("5.00.PROD.9128".to_owned());
    let analysis = analyze_client_deployment(&bundle_from(vec![(unprofiled, intent_content())]));
    assert_eq!(
        selection_state_name(analysis.extraction_profile.selection_state),
        "unselected",
        "no client source declares the profiled version"
    );
}

#[test]
fn a_repeated_identical_content_request_publishes_the_earliest_record_only() {
    let located = |time: &str| {
        record(
            &format!(
                "SYNTHETIC FIXTURE deployment content located assignmentId={ASSIGNMENT} ciId={CI} packageId=LAB00021 contentId={CONTENT} contentVersion=21 distributionPointHostHandle=safe:dp:lab-dp-02 requestId={REQUEST} siteCode=LAB"
            ),
            time,
            "CAS",
        )
    };

    // The two records carry the same exact key, so the transaction key is not
    // ambiguous. Only the citation is in question, and it must follow the
    // records rather than the artifact names.
    for (label, early_id, late_id) in [
        (
            "early sorts first",
            "synthetic-content-a",
            "synthetic-content-b",
        ),
        (
            "early sorts last",
            "synthetic-content-z",
            "synthetic-content-a",
        ),
    ] {
        let bundle = bundle_from(vec![
            (
                client_artifact("synthetic-intent", "AppIntentEval.log"),
                intent_content(),
            ),
            (
                client_artifact(early_id, "CAS.log"),
                located("05:00:02.000+000"),
            ),
            (
                rotated_artifact(late_id, "CAS.log.1", SccmRotation::Numbered(1)),
                located("05:00:09.000+000"),
            ),
        ]);

        let analysis = analyze_client_deployment(&bundle);
        let transaction = only_transaction(&analysis);
        let fact = transaction
            .counterpart_ready_fact
            .as_ref()
            .unwrap_or_else(|| panic!("{label}: an unambiguous repeated request is publishable"));
        assert_eq!(
            fact.evidence.artifact_id, early_id,
            "{label}: the citation must follow chronology, not the artifact name"
        );
        assert_eq!(
            fact.timestamp_provenance.normalized_utc, "2026-07-30T05:00:02Z",
            "{label}: published instant"
        );
    }
}

#[test]
fn an_unorderable_repeated_content_request_is_never_published() {
    let located = |time: &str| {
        record(
            &format!(
                "SYNTHETIC FIXTURE deployment content located assignmentId={ASSIGNMENT} ciId={CI} packageId=LAB00021 contentId={CONTENT} contentVersion=21 distributionPointHostHandle=safe:dp:lab-dp-02 requestId={REQUEST} siteCode=LAB"
            ),
            time,
            "CAS",
        )
    };
    let bundle = bundle_from(vec![
        (
            client_artifact("synthetic-intent", "AppIntentEval.log"),
            intent_content(),
        ),
        (
            client_artifact("synthetic-content-a", "CAS.log"),
            located("05:00:02.000+000"),
        ),
        (
            rotated_artifact(
                "synthetic-content-b",
                "CAS.log.1",
                SccmRotation::Numbered(1),
            ),
            located("05:00:09.000"),
        ),
    ]);

    let analysis = analyze_client_deployment(&bundle);
    let transaction = only_transaction(&analysis);
    assert!(
        transaction.counterpart_ready_fact.is_none(),
        "two incomparable records cannot decide which instant is published"
    );
}
