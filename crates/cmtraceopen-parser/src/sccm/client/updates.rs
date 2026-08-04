//! Conservative SCCM client software-update transaction analysis.
//!
//! The analyzer accepts only evidence produced by the sealed client admission
//! boundary. It never reads files, consumes another reducer, or infers a
//! server-side SUP cause.

use std::collections::BTreeMap;

use chrono::{DateTime, SecondsFormat, Utc};
use serde::Serialize;

use crate::sccm::{
    SccmConfidence, SccmCoverageState, SccmEvidence, SccmEvidenceRef, SccmFindingClass,
    SccmKeyConfidence, SccmTimeOrderingState, SccmTimestamp, SCCM_EXPERIMENTAL_KEY_PROFILE_ID,
};

use super::{SccmClientAdmittedEvidence, SccmClientEvidenceAdmissionError};

pub const SCCM_CLIENT_UPDATES_ANALYSIS_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmClientUpdatePhase {
    Scan,
    Evaluate,
    LocateSup,
    Download,
    MaintenanceWindow,
    Install,
    Reboot,
    Report,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmClientUpdateState {
    Succeeded,
    Failed,
    BlockedOrDeferred,
    Incomplete,
    Contradictory,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmClientUpdateClassification {
    Success,
    ConfirmedFailure,
    BlockedOrDeferred,
    InsufficientEvidence,
    Symptom,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmClientUpdateKey {
    pub update_id: String,
    pub ci_id: String,
    pub content_id: Option<String>,
    pub update_job_id: Option<String>,
    pub client_handle: Option<String>,
    pub site_code: Option<String>,
    pub sup_host_handle: Option<String>,
    pub confidence: SccmKeyConfidence,
    pub extraction_profile_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmClientUpdateArtifactRequest {
    pub logical_artifact_id: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmClientUpdateTransaction {
    pub transaction_id: String,
    pub key: SccmClientUpdateKey,
    pub phase: SccmClientUpdatePhase,
    pub state: SccmClientUpdateState,
    pub last_successful_phase: Option<SccmClientUpdatePhase>,
    pub classification: SccmClientUpdateClassification,
    pub confidence: SccmConfidence,
    pub confidence_ceiling: SccmConfidence,
    pub coverage_gap_artifact_ids: Vec<String>,
    pub next_artifact: Option<SccmClientUpdateArtifactRequest>,
    pub evidence: Vec<SccmEvidenceRef>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmClientUpdateFinding {
    pub finding_id: String,
    pub subject_id: String,
    pub class: SccmFindingClass,
    pub phase: Option<SccmClientUpdatePhase>,
    pub last_successful_phase: Option<SccmClientUpdatePhase>,
    pub confidence: SccmConfidence,
    pub confidence_ceiling: SccmConfidence,
    pub next_artifact: Option<SccmClientUpdateArtifactRequest>,
    pub evidence: Vec<SccmEvidenceRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmClientUpdateObservation {
    pub observation_id: String,
    pub reason: String,
    pub evidence: Vec<SccmEvidenceRef>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmClientUpdateCoverage {
    pub logical_artifact_id: String,
    pub state: SccmCoverageState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmClientUpdateExtractionProfile {
    pub selection_state: String,
    pub profile_id: String,
    pub key_confidence_ceiling: SccmKeyConfidence,
    pub validated_artifact_families: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmClientUpdateCorrelationHandoff {
    pub issue: String,
    pub server_prerequisite_issue: String,
    pub performed: bool,
    pub time_only_eligible: bool,
    pub topology_compatibility_evaluated: bool,
    pub server_cause_claimed: bool,
    pub native_acceptance_claimed: bool,
    pub bundle_capture_host_used_as_sup_evidence: bool,
    pub counterpart_ready_key_kinds: Vec<String>,
    pub emitted_counterpart_ready_fact: bool,
    pub counterpart_ready_facts: Vec<SccmClientUpdateCounterpartReadyFact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmClientUpdateCounterpartEvidence {
    pub artifact_id: String,
    pub start_line: u32,
    pub end_line: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmClientUpdateTimestampProvenance {
    pub normalized_utc: String,
    pub utc_millis: i64,
    pub offset_minutes: i32,
    pub ordering_state: SccmTimeOrderingState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmClientUpdateCounterpartReadyFact {
    pub update_id: String,
    pub ci_id: String,
    pub content_id: String,
    pub update_job_id: String,
    pub client_handle: String,
    pub site_code: String,
    pub sup_host_handle: String,
    pub key_confidence: SccmKeyConfidence,
    pub correlation_eligible: bool,
    pub time_only_eligible: bool,
    pub phase: SccmClientUpdatePhase,
    pub extraction_profile_id: String,
    pub timestamp_provenance: SccmClientUpdateTimestampProvenance,
    pub evidence: SccmClientUpdateCounterpartEvidence,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmClientUpdatesAnalysis {
    pub schema_version: u32,
    pub transactions: Vec<SccmClientUpdateTransaction>,
    pub observations: Vec<SccmClientUpdateObservation>,
    pub findings: Vec<SccmClientUpdateFinding>,
    pub coverage: Vec<SccmClientUpdateCoverage>,
    pub extraction_profile: SccmClientUpdateExtractionProfile,
    pub correlation_handoff: SccmClientUpdateCorrelationHandoff,
    pub prohibited_claims: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PhaseDisposition {
    Succeeded,
    Failed,
    Deferred,
    Contradictory,
}

#[derive(Debug, Clone)]
struct UpdateFact {
    key: SccmClientUpdateKey,
    phase: SccmClientUpdatePhase,
    disposition: PhaseDisposition,
    evidence: SccmEvidenceRef,
    timestamp: SccmTimestamp,
    location_services_source: bool,
}

/// Reduces sealed, intake-bound client evidence into update transactions.
pub fn analyze_client_updates(
    admitted: &SccmClientAdmittedEvidence,
) -> Result<SccmClientUpdatesAnalysis, SccmClientEvidenceAdmissionError> {
    let declared_gap_phases = declared_gap_phases(admitted)?;
    let mut facts_by_key = BTreeMap::<(String, String), Vec<UpdateFact>>::new();
    let mut observations = Vec::new();
    for evidence in admitted.evidence()? {
        if let Some(fact) = update_fact(evidence) {
            facts_by_key
                .entry((fact.key.update_id.clone(), fact.key.ci_id.clone()))
                .or_default()
                .push(fact);
        } else if is_update_source(evidence.component.as_deref()) {
            observations.push(SccmClientUpdateObservation {
                observation_id: format!("updates:source-local:{}", evidence.evidence_id),
                reason: "Update-related source evidence was retained locally but did not satisfy an exact phase/key grammar.".to_owned(),
                evidence: vec![evidence.reference.clone()],
            });
        }
    }
    let supplemental_present =
        ["CBS.log", "ReportingEvents.log"]
            .into_iter()
            .try_fold(false, |present, basename| {
                admitted
                    .source_coverage_for_basename(basename)
                    .map(|coverage| {
                        present
                            || coverage
                                .is_some_and(|coverage| *coverage == SccmCoverageState::Captured)
                    })
            })?;
    if supplemental_present {
        observations.push(SccmClientUpdateObservation {
            observation_id: "updates:source-local:windows-update-supplemental".to_owned(),
            reason: "Windows servicing supplemental evidence remains source-local and cannot override the SCCM update transaction.".to_owned(),
            evidence: Vec::new(),
        });
    }
    observations.sort_by(|left, right| left.observation_id.cmp(&right.observation_id));
    let client_updates_unavailable = match admitted.require_captured_source("client-updates") {
        Ok(()) => false,
        Err(
            SccmClientEvidenceAdmissionError::SourceCoverageUnavailable
            | SccmClientEvidenceAdmissionError::UnknownSourceGroup,
        ) => true,
        Err(error) => return Err(error),
    };
    if client_updates_unavailable && observations.is_empty() {
        observations.push(SccmClientUpdateObservation {
            observation_id: "updates:source-local:coverage".to_owned(),
            reason: "The client update source group was declared but was not admitted as complete captured evidence.".to_owned(),
            evidence: Vec::new(),
        });
    }

    let mut transactions = Vec::new();
    let mut findings = Vec::new();
    let mut counterpart_ready_facts = Vec::new();
    for (_, mut facts) in facts_by_key {
        facts.sort_by(|left, right| {
            left.phase
                .cmp(&right.phase)
                .then_with(|| left.timestamp.utc_millis.cmp(&right.timestamp.utc_millis))
                .then_with(|| left.evidence.artifact_id.cmp(&right.evidence.artifact_id))
                .then_with(|| left.evidence.line_start.cmp(&right.evidence.line_start))
        });
        let mut effective_by_phase = BTreeMap::new();
        for fact in &facts {
            effective_by_phase.insert(fact.phase, fact);
        }
        let Some(last) = effective_by_phase.values().next_back().copied() else {
            continue;
        };
        if let Some(counterpart) = facts.iter().find_map(counterpart_ready_fact) {
            counterpart_ready_facts.push(counterpart);
        }
        let failed = effective_by_phase
            .values()
            .copied()
            .filter(|fact| fact.disposition == PhaseDisposition::Failed)
            .min_by_key(|fact| fact.phase);
        let deferred = effective_by_phase
            .values()
            .copied()
            .filter(|fact| fact.disposition == PhaseDisposition::Deferred)
            .max_by_key(|fact| fact.phase);
        let contradictory = effective_by_phase
            .values()
            .copied()
            .filter(|fact| fact.disposition == PhaseDisposition::Contradictory)
            .min_by_key(|fact| fact.phase);
        let decisive = failed.or(deferred).or(contradictory).unwrap_or(last);
        let incomplete_phase = (failed.is_none() && deferred.is_none() && contradictory.is_none())
            .then(|| {
                declared_gap_phases
                    .iter()
                    .copied()
                    .find(|phase| *phase > last.phase)
            })
            .flatten();
        let output_phase = incomplete_phase.unwrap_or(decisive.phase);
        let state = if failed.is_some() {
            SccmClientUpdateState::Failed
        } else if deferred.is_some() {
            SccmClientUpdateState::BlockedOrDeferred
        } else if contradictory.is_some() {
            SccmClientUpdateState::Contradictory
        } else if incomplete_phase.is_some() {
            SccmClientUpdateState::Incomplete
        } else {
            SccmClientUpdateState::Succeeded
        };
        let classification = if failed.is_some() {
            SccmClientUpdateClassification::Symptom
        } else if deferred.is_some() {
            SccmClientUpdateClassification::BlockedOrDeferred
        } else if contradictory.is_some() || incomplete_phase.is_some() {
            SccmClientUpdateClassification::InsufficientEvidence
        } else {
            SccmClientUpdateClassification::Success
        };
        let decisive_is_success = failed.is_none() && deferred.is_none() && contradictory.is_none();
        let last_successful_phase = effective_by_phase
            .values()
            .copied()
            .filter(|fact| {
                fact.disposition == PhaseDisposition::Succeeded
                    && (fact.phase < decisive.phase
                        || (decisive_is_success && fact.phase == decisive.phase))
            })
            .map(|fact| fact.phase)
            .max();
        let mut evidence = facts
            .iter()
            .filter(|fact| fact.phase <= decisive.phase)
            .map(|fact| fact.evidence.clone())
            .collect::<Vec<_>>();
        evidence.sort_by(|left, right| {
            left.artifact_id
                .cmp(&right.artifact_id)
                .then_with(|| left.line_start.cmp(&right.line_start))
                .then_with(|| left.line_end.cmp(&right.line_end))
        });
        evidence.dedup();
        let next_artifact =
            if deferred.is_some() || contradictory.is_some() || incomplete_phase.is_some() {
                Some(request_for(output_phase))
            } else {
                None
            };
        let coverage_gap_artifact_ids = next_artifact
            .as_ref()
            .map(|request| vec![request.logical_artifact_id.clone()])
            .unwrap_or_default();
        let transaction_id = format!("updates:update:{}", decisive.key.update_id);
        let transaction = SccmClientUpdateTransaction {
            transaction_id: transaction_id.clone(),
            key: decisive.key.clone(),
            phase: output_phase,
            state,
            last_successful_phase,
            classification,
            confidence: SccmConfidence::Low,
            confidence_ceiling: SccmConfidence::Low,
            coverage_gap_artifact_ids,
            next_artifact: next_artifact.clone(),
            evidence: evidence.clone(),
        };
        if failed.is_some()
            || deferred.is_some()
            || contradictory.is_some()
            || incomplete_phase.is_some()
        {
            findings.push(SccmClientUpdateFinding {
                finding_id: format!(
                    "finding:updates:{}:{}-{}",
                    decisive.key.update_id,
                    phase_name(output_phase),
                    if failed.is_some() {
                        "failure"
                    } else if deferred.is_some() {
                        "deferred"
                    } else if contradictory.is_some() {
                        "contradictory"
                    } else {
                        "incomplete"
                    }
                ),
                subject_id: transaction_id,
                class: if failed.is_some() {
                    SccmFindingClass::Symptom
                } else if deferred.is_some() {
                    SccmFindingClass::BlockedOrDeferred
                } else {
                    SccmFindingClass::InsufficientEvidence
                },
                phase: Some(output_phase),
                last_successful_phase,
                confidence: SccmConfidence::Low,
                confidence_ceiling: SccmConfidence::Low,
                next_artifact,
                evidence,
            });
        }
        transactions.push(transaction);
    }

    if transactions.is_empty() && (!observations.is_empty() || client_updates_unavailable) {
        let evidence = observations
            .iter()
            .flat_map(|observation| observation.evidence.clone())
            .collect::<Vec<_>>();
        findings.push(SccmClientUpdateFinding {
            finding_id: "finding:updates:source-local".to_owned(),
            subject_id: "updates:source-local".to_owned(),
            class: SccmFindingClass::InsufficientEvidence,
            phase: None,
            last_successful_phase: None,
            confidence: SccmConfidence::Low,
            confidence_ceiling: SccmConfidence::Low,
            next_artifact: Some(request_for(SccmClientUpdatePhase::Install)),
            evidence,
        });
    }
    if supplemental_present {
        findings.push(SccmClientUpdateFinding {
            finding_id: "finding:updates:supplemental-source-local".to_owned(),
            subject_id: "updates:source-local:windows-update-supplemental".to_owned(),
            class: SccmFindingClass::Symptom,
            phase: transactions.first().map(|transaction| transaction.phase),
            last_successful_phase: None,
            confidence: SccmConfidence::Low,
            confidence_ceiling: SccmConfidence::Low,
            next_artifact: Some(SccmClientUpdateArtifactRequest {
                logical_artifact_id: "client-windows-update-supplemental".to_owned(),
                reason: "Collect the smallest bounded client-windows-update-supplemental continuation for this exact update subject.".to_owned(),
            }),
            evidence: Vec::new(),
        });
    }

    counterpart_ready_facts.sort_by(|left, right| {
        left.update_id
            .cmp(&right.update_id)
            .then_with(|| left.ci_id.cmp(&right.ci_id))
            .then_with(|| left.evidence.artifact_id.cmp(&right.evidence.artifact_id))
            .then_with(|| left.evidence.start_line.cmp(&right.evidence.start_line))
    });
    counterpart_ready_facts.dedup();
    let emitted_counterpart_ready_fact = !counterpart_ready_facts.is_empty();
    let coverage = update_coverage(admitted)?;

    Ok(SccmClientUpdatesAnalysis {
        schema_version: SCCM_CLIENT_UPDATES_ANALYSIS_SCHEMA_VERSION,
        transactions,
        observations,
        findings,
        coverage,
        extraction_profile: SccmClientUpdateExtractionProfile {
            selection_state: "experimental".to_owned(),
            profile_id: SCCM_EXPERIMENTAL_KEY_PROFILE_ID.to_owned(),
            key_confidence_ceiling: SccmKeyConfidence::Low,
            validated_artifact_families: Vec::new(),
        },
        correlation_handoff: SccmClientUpdateCorrelationHandoff {
            issue: "#333".to_owned(),
            server_prerequisite_issue: "#330".to_owned(),
            performed: false,
            time_only_eligible: false,
            topology_compatibility_evaluated: false,
            server_cause_claimed: false,
            native_acceptance_claimed: false,
            bundle_capture_host_used_as_sup_evidence: false,
            counterpart_ready_key_kinds: vec![
                "updateId".to_owned(),
                "ciId".to_owned(),
                "contentId".to_owned(),
                "updateJobId".to_owned(),
                "clientSafeHandle".to_owned(),
                "siteCode".to_owned(),
                "supHostHandle".to_owned(),
            ],
            emitted_counterpart_ready_fact,
            counterpart_ready_facts,
        },
        prohibited_claims: vec![
            "SUP or server root cause".to_owned(),
            "time-only cross-artifact causality".to_owned(),
            "policy reducer dependency".to_owned(),
            "native Windows acceptance".to_owned(),
        ],
    })
}

fn update_coverage(
    admitted: &SccmClientAdmittedEvidence,
) -> Result<Vec<SccmClientUpdateCoverage>, SccmClientEvidenceAdmissionError> {
    let groups: [(&str, &[&str]); 7] = [
        (
            "client-content",
            &["DataTransferService.log", "ContentTransferManager.log"],
        ),
        ("client-location-services-shared", &["LocationServices.log"]),
        ("client-maintenance-window", &["ServiceWindowManager.log"]),
        ("client-policy-state", &["StateMessage.log"]),
        ("client-reboot", &["RebootCoordinator.log"]),
        (
            "client-updates",
            &[
                "ScanAgent.log",
                "WUAHandler.log",
                "UpdatesDeployment.log",
                "UpdatesHandler.log",
                "UpdatesStore.log",
            ],
        ),
        (
            "client-windows-update-supplemental",
            &["CBS.log", "ReportingEvents.log"],
        ),
    ];
    let mut coverage = Vec::new();
    for (logical_artifact_id, basenames) in groups {
        let mut declared = false;
        for basename in basenames {
            declared |= admitted.source_coverage_for_basename(basename)?.is_some();
        }
        if declared {
            if let Some(state) = admitted.source_coverage(logical_artifact_id)? {
                coverage.push(SccmClientUpdateCoverage {
                    logical_artifact_id: logical_artifact_id.to_owned(),
                    state: state.clone(),
                });
            }
        }
    }
    Ok(coverage)
}

fn is_update_source(component: Option<&str>) -> bool {
    component.is_some_and(|component| {
        source_is(
            component,
            &[
                "ScanAgent",
                "WUAHandler",
                "LocationServices",
                "DataTransferService",
                "ContentTransferManager",
                "ServiceWindowManager",
                "UpdatesDeployment",
                "UpdatesHandler",
                "UpdatesStore",
                "RebootCoordinator",
                "StateMessage",
                "CBS",
            ],
        )
    })
}

fn declared_gap_phases(
    admitted: &SccmClientAdmittedEvidence,
) -> Result<Vec<SccmClientUpdatePhase>, SccmClientEvidenceAdmissionError> {
    let mut phases = Vec::new();
    for (basename, phase) in [
        ("ScanAgent.log", SccmClientUpdatePhase::Scan),
        ("WUAHandler.log", SccmClientUpdatePhase::Evaluate),
        ("LocationServices.log", SccmClientUpdatePhase::LocateSup),
        ("DataTransferService.log", SccmClientUpdatePhase::Download),
        (
            "ContentTransferManager.log",
            SccmClientUpdatePhase::Download,
        ),
        (
            "ServiceWindowManager.log",
            SccmClientUpdatePhase::MaintenanceWindow,
        ),
        ("UpdatesHandler.log", SccmClientUpdatePhase::Install),
        ("RebootCoordinator.log", SccmClientUpdatePhase::Reboot),
        ("StateMessage.log", SccmClientUpdatePhase::Report),
    ] {
        if admitted
            .source_coverage_for_basename(basename)?
            .is_some_and(|coverage| *coverage != SccmCoverageState::Captured)
            && !phases.contains(&phase)
        {
            phases.push(phase);
        }
    }
    Ok(phases)
}

fn update_fact(evidence: &SccmEvidence) -> Option<UpdateFact> {
    let update_id = normalize_update_id(message_field(&evidence.message, "UpdateId")?)?;
    let ci_id = safe_value(message_field(&evidence.message, "CIId")?)?;
    let (phase, disposition) = phase_disposition(evidence)?;
    Some(UpdateFact {
        key: SccmClientUpdateKey {
            update_id,
            ci_id,
            content_id: optional_safe_field(&evidence.message, "ContentId"),
            update_job_id: optional_safe_field(&evidence.message, "UpdateJobId"),
            client_handle: optional_safe_handle(&evidence.message, "ClientHandle"),
            site_code: optional_safe_field(&evidence.message, "SiteCode"),
            sup_host_handle: optional_safe_handle(&evidence.message, "SupHostHandle"),
            confidence: SccmKeyConfidence::Low,
            extraction_profile_id: SCCM_EXPERIMENTAL_KEY_PROFILE_ID.to_owned(),
        },
        phase,
        disposition,
        evidence: evidence.reference.clone(),
        timestamp: evidence.timestamp.clone(),
        location_services_source: evidence
            .component
            .as_deref()
            .is_some_and(|component| component.eq_ignore_ascii_case("LocationServices")),
    })
}

fn counterpart_ready_fact(fact: &UpdateFact) -> Option<SccmClientUpdateCounterpartReadyFact> {
    if !fact.location_services_source
        || fact.phase != SccmClientUpdatePhase::LocateSup
        || fact.disposition != PhaseDisposition::Succeeded
        || fact.timestamp.ordering_state != SccmTimeOrderingState::NormalizedUtc
    {
        return None;
    }
    let utc_millis = fact.timestamp.utc_millis?;
    let offset_minutes = fact.timestamp.offset_minutes?;
    let normalized_utc = DateTime::<Utc>::from_timestamp_millis(utc_millis)?
        .to_rfc3339_opts(SecondsFormat::Millis, true);
    Some(SccmClientUpdateCounterpartReadyFact {
        update_id: fact.key.update_id.clone(),
        ci_id: fact.key.ci_id.clone(),
        content_id: fact.key.content_id.clone()?,
        update_job_id: fact.key.update_job_id.clone()?,
        client_handle: fact.key.client_handle.clone()?,
        site_code: fact.key.site_code.clone()?,
        sup_host_handle: fact.key.sup_host_handle.clone()?,
        key_confidence: fact.key.confidence.clone(),
        correlation_eligible: false,
        time_only_eligible: false,
        phase: SccmClientUpdatePhase::LocateSup,
        extraction_profile_id: fact.key.extraction_profile_id.clone(),
        timestamp_provenance: SccmClientUpdateTimestampProvenance {
            normalized_utc,
            utc_millis,
            offset_minutes,
            ordering_state: SccmTimeOrderingState::NormalizedUtc,
        },
        evidence: SccmClientUpdateCounterpartEvidence {
            artifact_id: fact.evidence.artifact_id.clone(),
            start_line: fact.evidence.line_start?,
            end_line: fact.evidence.line_end?,
        },
    })
}

fn phase_disposition(evidence: &SccmEvidence) -> Option<(SccmClientUpdatePhase, PhaseDisposition)> {
    let component = evidence.component.as_deref()?;
    let message = evidence.message.to_ascii_lowercase();
    let fact = if source_is(component, &["ScanAgent"])
        && (message.contains("scanresult=failed")
            || message.contains("scan terminal failure")
            || message.contains("scan failed"))
    {
        (SccmClientUpdatePhase::Scan, PhaseDisposition::Failed)
    } else if source_is(component, &["ScanAgent"])
        && (message.contains("scanresult=success") || message.contains("scan succeeded"))
    {
        (SccmClientUpdatePhase::Scan, PhaseDisposition::Succeeded)
    } else if source_is(
        component,
        &[
            "ScanAgent",
            "WUAHandler",
            "UpdatesDeployment",
            "UpdatesStore",
        ],
    ) && message.contains("evaluate terminal-looking")
    {
        (
            SccmClientUpdatePhase::Evaluate,
            PhaseDisposition::Contradictory,
        )
    } else if source_is(
        component,
        &[
            "ScanAgent",
            "WUAHandler",
            "UpdatesDeployment",
            "UpdatesStore",
        ],
    ) && message.contains("evaluate terminal failure")
    {
        (SccmClientUpdatePhase::Evaluate, PhaseDisposition::Failed)
    } else if source_is(
        component,
        &[
            "ScanAgent",
            "WUAHandler",
            "UpdatesDeployment",
            "UpdatesStore",
        ],
    ) && (message.contains("evaluate applicable")
        || message.contains("evaluate succeeded"))
    {
        (SccmClientUpdatePhase::Evaluate, PhaseDisposition::Succeeded)
    } else if source_is(component, &["LocationServices", "UpdatesDeployment"])
        && message.contains("locatesup selected")
    {
        (
            SccmClientUpdatePhase::LocateSup,
            PhaseDisposition::Succeeded,
        )
    } else if source_is(
        component,
        &[
            "DataTransferService",
            "ContentTransferManager",
            "UpdatesDeployment",
        ],
    ) && message.contains("download terminal failure")
    {
        (SccmClientUpdatePhase::Download, PhaseDisposition::Failed)
    } else if source_is(
        component,
        &[
            "DataTransferService",
            "ContentTransferManager",
            "UpdatesDeployment",
        ],
    ) && message.contains("download succeeded")
    {
        (SccmClientUpdatePhase::Download, PhaseDisposition::Succeeded)
    } else if source_is(
        component,
        &[
            "ServiceWindowManager",
            "UpdatesDeployment",
            "UpdatesHandler",
            "UpdatesStore",
        ],
    ) && message.contains("maintenancewindow deferred")
    {
        (
            SccmClientUpdatePhase::MaintenanceWindow,
            PhaseDisposition::Deferred,
        )
    } else if source_is(
        component,
        &[
            "ServiceWindowManager",
            "UpdatesDeployment",
            "UpdatesHandler",
            "UpdatesStore",
        ],
    ) && message.contains("maintenancewindow open")
    {
        (
            SccmClientUpdatePhase::MaintenanceWindow,
            PhaseDisposition::Succeeded,
        )
    } else if source_is(component, &["UpdatesHandler", "UpdatesDeployment"])
        && message.contains("install terminal failure")
    {
        (SccmClientUpdatePhase::Install, PhaseDisposition::Failed)
    } else if source_is(component, &["UpdatesHandler", "UpdatesDeployment"])
        && message.contains("install succeeded")
    {
        (SccmClientUpdatePhase::Install, PhaseDisposition::Succeeded)
    } else if source_is(component, &["RebootCoordinator", "UpdatesDeployment"])
        && message.contains("reboot pending")
    {
        (SccmClientUpdatePhase::Reboot, PhaseDisposition::Deferred)
    } else if source_is(component, &["RebootCoordinator", "UpdatesDeployment"])
        && message.contains("reboot complete")
    {
        (SccmClientUpdatePhase::Reboot, PhaseDisposition::Succeeded)
    } else if source_is(component, &["StateMessage", "UpdatesHandler"])
        && message.contains("report terminal failure")
    {
        (SccmClientUpdatePhase::Report, PhaseDisposition::Failed)
    } else if source_is(component, &["StateMessage", "UpdatesHandler"])
        && message.contains("report succeeded")
    {
        (SccmClientUpdatePhase::Report, PhaseDisposition::Succeeded)
    } else {
        return None;
    };
    Some(fact)
}

fn source_is(component: &str, accepted: &[&str]) -> bool {
    accepted
        .iter()
        .any(|candidate| component.eq_ignore_ascii_case(candidate))
}

fn message_field<'a>(message: &'a str, label: &str) -> Option<&'a str> {
    message.split_ascii_whitespace().find_map(|token| {
        let (candidate_label, value) = token.split_once('=')?;
        candidate_label.eq_ignore_ascii_case(label).then_some(value)
    })
}

fn optional_safe_field(message: &str, label: &str) -> Option<String> {
    safe_value(message_field(message, label)?)
}

fn optional_safe_handle(message: &str, label: &str) -> Option<String> {
    safe_value(message_field(message, label)?).filter(|value| value.starts_with("safe:"))
}

fn safe_value(value: &str) -> Option<String> {
    let value = value.trim_matches(|character| matches!(character, '{' | '}' | ',' | ';'));
    (!value.is_empty()
        && value.len() <= 160
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')))
    .then(|| value.to_owned())
}

fn normalize_update_id(value: &str) -> Option<String> {
    let normalized = safe_value(value)?.to_ascii_lowercase();
    let bytes = normalized.as_bytes();
    if bytes.len() != 36
        || ![8, 13, 18, 23]
            .into_iter()
            .all(|index| bytes.get(index) == Some(&b'-'))
        || bytes
            .iter()
            .enumerate()
            .any(|(index, byte)| ![8, 13, 18, 23].contains(&index) && !byte.is_ascii_hexdigit())
    {
        return None;
    }
    Some(normalized)
}

fn phase_name(phase: SccmClientUpdatePhase) -> &'static str {
    match phase {
        SccmClientUpdatePhase::Scan => "scan",
        SccmClientUpdatePhase::Evaluate => "evaluate",
        SccmClientUpdatePhase::LocateSup => "locate-sup",
        SccmClientUpdatePhase::Download => "download",
        SccmClientUpdatePhase::MaintenanceWindow => "maintenance-window",
        SccmClientUpdatePhase::Install => "install",
        SccmClientUpdatePhase::Reboot => "reboot",
        SccmClientUpdatePhase::Report => "report",
    }
}

fn request_for(phase: SccmClientUpdatePhase) -> SccmClientUpdateArtifactRequest {
    let logical_artifact_id = match phase {
        SccmClientUpdatePhase::Scan | SccmClientUpdatePhase::Evaluate => "client-updates",
        SccmClientUpdatePhase::LocateSup => "client-location-services-shared",
        SccmClientUpdatePhase::Download => "client-content",
        SccmClientUpdatePhase::MaintenanceWindow => "client-maintenance-window",
        SccmClientUpdatePhase::Install => "client-updates",
        SccmClientUpdatePhase::Reboot => "client-reboot",
        SccmClientUpdatePhase::Report => "client-policy-state",
    };
    SccmClientUpdateArtifactRequest {
        logical_artifact_id: logical_artifact_id.to_owned(),
        reason: format!(
            "Collect the smallest bounded {logical_artifact_id} continuation for this exact update subject."
        ),
    }
}
