use std::{borrow::Cow, collections::BTreeMap};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::models::log_entry::Severity;

use super::super::{
    normalize_key, SccmCorrelationKey, SccmCorrelationKeyKind, SccmCoverageState, SccmEvidence,
    SccmEvidenceRef, SccmFindingClass, SccmKeyConfidence, SccmRole, SccmRotation,
    SccmTimeOrderingState, SCCM_EXPERIMENTAL_KEY_PROFILE_ID,
};
use super::admission::SccmClientAdmittedSourceArtifact;
use super::{SccmClientAdmittedEvidence, SccmClientEvidenceAdmissionError};

pub const SCCM_CLIENT_EXTENDED_ANALYSIS_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmClientExtendedWorkflow {
    Inventory,
    Compliance,
    Metering,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmClientExtendedPhase {
    Collect,
    Provider,
    Serialize,
    Queue,
    Evaluate,
    Remediate,
    Aggregate,
    Report,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmClientExtendedState {
    InProgress,
    Succeeded,
    Failed,
    Recovered,
    Contradictory,
    EvaluatedCompliant,
    EvaluatedNonCompliant,
    Remediated,
    BlockedOrDeferred,
    InsufficientEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmClientExtendedTransaction {
    pub transaction_id: String,
    pub workflow: SccmClientExtendedWorkflow,
    pub profile_id: String,
    pub phase: SccmClientExtendedPhase,
    pub source_basename: String,
    pub state: SccmClientExtendedState,
    pub last_successful_phase: Option<SccmClientExtendedPhase>,
    pub keys: Vec<SccmCorrelationKey>,
    pub evidence: Vec<SccmEvidenceRef>,
    pub coverage_gap_artifact_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmClientExtendedSourceCitation {
    pub artifact_id: String,
    pub source_basename: String,
    pub rotation: SccmRotation,
    pub coverage: SccmCoverageState,
    pub fragment_complete: bool,
    pub physical: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmClientExtendedCoverage {
    pub workflow: SccmClientExtendedWorkflow,
    pub logical_artifact_id: String,
    pub source: SccmClientExtendedSourceCitation,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmClientExtendedObservation {
    pub workflow: SccmClientExtendedWorkflow,
    pub reason: String,
    pub sources: Vec<SccmClientExtendedSourceCitation>,
    pub evidence: Vec<SccmEvidenceRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmClientExtendedArtifactRequest {
    pub logical_artifact_id: String,
    pub source_basename: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmClientExtendedFinding {
    pub finding_id: String,
    pub subject_id: String,
    pub workflow: SccmClientExtendedWorkflow,
    pub role: SccmRole,
    pub class: SccmFindingClass,
    pub severity: Severity,
    pub state: SccmClientExtendedState,
    pub phase: SccmClientExtendedPhase,
    pub confidence: SccmKeyConfidence,
    pub keys: Vec<SccmCorrelationKey>,
    pub next_artifact: Option<SccmClientExtendedArtifactRequest>,
    pub evidence: Vec<SccmEvidenceRef>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmClientExtendedAnalysis {
    pub schema_version: u32,
    pub transactions: Vec<SccmClientExtendedTransaction>,
    pub coverage: Vec<SccmClientExtendedCoverage>,
    pub source_local_observations: Vec<SccmClientExtendedObservation>,
    pub findings: Vec<SccmClientExtendedFinding>,
    pub prohibited_claims: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct TransactionKey {
    workflow: SccmClientExtendedWorkflow,
    tuple: String,
}

#[derive(Debug, Clone)]
struct Fact {
    workflow: SccmClientExtendedWorkflow,
    phase: SccmClientExtendedPhase,
    disposition: Disposition,
    terminal: bool,
    evidence: SccmEvidence,
    keys: Vec<SccmCorrelationKey>,
    tuple: String,
    profile_id: String,
    result_type_evaluation: bool,
    disposition_compliant: bool,
    source_basename: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Disposition {
    Succeeded,
    Failed,
    NonCompliant,
    Deferred,
    Other,
}

/// Analyze inventory, compliance, and metering only through sealed client
/// evidence. The reducer never accepts caller-assembled artifacts or records.
pub fn analyze_client_extended(
    admitted: &SccmClientAdmittedEvidence,
) -> Result<SccmClientExtendedAnalysis, SccmClientEvidenceAdmissionError> {
    let coverage = extended_coverage(admitted)?;
    let mut observations = Vec::new();
    let mut facts = BTreeMap::<TransactionKey, Vec<Fact>>::new();

    for (artifact_id, source) in admitted.source_artifacts()? {
        let Some(workflow) = workflow_for_basename(&source.basename) else {
            continue;
        };
        if source.coverage == SccmCoverageState::Captured && source.fragment_complete == Some(true)
        {
            continue;
        }
        observations.push(SccmClientExtendedObservation {
            workflow,
            reason: if source.coverage == SccmCoverageState::Captured {
                "An incomplete rotation fragment remains source-local coverage and cannot establish a workflow outcome."
            } else {
                "An unavailable or malformed source artifact remains coverage and cannot establish a workflow outcome."
            }
            .to_owned(),
            sources: vec![source_citation(artifact_id, source)],
            evidence: Vec::new(),
        });
    }

    for evidence in admitted.evidence()? {
        let Some(context) = evidence_context(admitted, evidence)? else {
            continue;
        };
        let profile_id = profile_id(context.workflow);
        let Some(fact) = parse_fact(&context, profile_id, evidence, &mut observations) else {
            continue;
        };
        facts
            .entry(TransactionKey {
                workflow: fact.workflow,
                tuple: fact.tuple.clone(),
            })
            .or_default()
            .push(fact);
    }

    observations.sort_by(|left, right| {
        left.workflow
            .cmp(&right.workflow)
            .then_with(|| {
                left.sources
                    .iter()
                    .map(|source| source.artifact_id.as_str())
                    .cmp(
                        right
                            .sources
                            .iter()
                            .map(|source| source.artifact_id.as_str()),
                    )
            })
            .then_with(|| {
                left.evidence
                    .first()
                    .map(|reference| {
                        (
                            reference.artifact_id.as_str(),
                            reference.line_start,
                            reference.line_end,
                            reference.entry_id.as_str(),
                        )
                    })
                    .cmp(&right.evidence.first().map(|reference| {
                        (
                            reference.artifact_id.as_str(),
                            reference.line_start,
                            reference.line_end,
                            reference.entry_id.as_str(),
                        )
                    }))
            })
            .then_with(|| left.reason.cmp(&right.reason))
    });

    let mut transactions = facts
        .into_values()
        .map(|mut group| reduce_group(&mut group))
        .collect::<Vec<_>>();
    for transaction in &mut transactions {
        transaction.coverage_gap_artifact_ids = coverage
            .iter()
            .filter(|gap| {
                transaction
                    .evidence
                    .iter()
                    .any(|reference| reference.artifact_id == gap.source.artifact_id)
                    && !source_is_complete(&gap.source)
            })
            .map(|gap| gap.source.artifact_id.clone())
            .collect();
        if !transaction.coverage_gap_artifact_ids.is_empty() {
            transaction.state = SccmClientExtendedState::InsufficientEvidence;
        }
    }
    let findings = transactions
        .iter()
        .filter_map(finding_for)
        .collect::<Vec<_>>();

    Ok(SccmClientExtendedAnalysis {
        schema_version: SCCM_CLIENT_EXTENDED_ANALYSIS_SCHEMA_VERSION,
        transactions,
        coverage,
        source_local_observations: observations,
        findings,
        prohibited_claims: vec![
            "server root cause".to_owned(),
            "time-only cross-artifact causality".to_owned(),
            "native Windows acceptance".to_owned(),
        ],
    })
}

#[derive(Debug, Clone)]
struct ArtifactContext {
    workflow: SccmClientExtendedWorkflow,
    source_basename: &'static str,
    source: SccmClientExtendedSourceCitation,
}

fn extended_coverage(
    admitted: &SccmClientAdmittedEvidence,
) -> Result<Vec<SccmClientExtendedCoverage>, SccmClientEvidenceAdmissionError> {
    let mut coverage = Vec::new();
    for (artifact_id, source) in admitted.source_artifacts()? {
        let Some(workflow) = workflow_for_basename(&source.basename) else {
            continue;
        };
        let citation = source_citation(artifact_id, source);
        coverage.push(SccmClientExtendedCoverage {
            workflow,
            logical_artifact_id: logical_artifact_for_basename(&source.basename).to_owned(),
            reason: if source_is_complete(&citation) {
                "This exact physical source was captured completely; transaction claims still require exact record evidence."
            } else {
                "This exact source was not captured completely; its coverage state cannot become a workflow outcome."
            }
            .to_owned(),
            source: citation,
        });
    }
    Ok(coverage)
}

fn source_citation(
    artifact_id: &str,
    source: &SccmClientAdmittedSourceArtifact,
) -> SccmClientExtendedSourceCitation {
    SccmClientExtendedSourceCitation {
        artifact_id: artifact_id.to_owned(),
        source_basename: source.basename.clone(),
        rotation: source.rotation.clone(),
        coverage: source.coverage.clone(),
        fragment_complete: source.fragment_complete == Some(true),
        physical: source.physical,
    }
}

fn source_is_complete(source: &SccmClientExtendedSourceCitation) -> bool {
    source.coverage == SccmCoverageState::Captured && source.fragment_complete && source.physical
}

fn evidence_context(
    admitted: &SccmClientAdmittedEvidence,
    evidence: &SccmEvidence,
) -> Result<Option<ArtifactContext>, SccmClientEvidenceAdmissionError> {
    let Some(component) = evidence.component.as_deref() else {
        return Ok(None);
    };
    let (workflow, source_basename) = match component.to_ascii_lowercase().as_str() {
        "inventoryagent" => (SccmClientExtendedWorkflow::Inventory, "InventoryAgent.log"),
        "inventoryprovider" => (
            SccmClientExtendedWorkflow::Inventory,
            "InventoryProvider.log",
        ),
        "inventoryagentprovider" => (
            SccmClientExtendedWorkflow::Inventory,
            "InventoryAgentProvider.log",
        ),
        "ciagent" => (SccmClientExtendedWorkflow::Compliance, "CIAgent.log"),
        "citaskmgr" => (SccmClientExtendedWorkflow::Compliance, "CITaskMgr.log"),
        "dcmagent" => (SccmClientExtendedWorkflow::Compliance, "DCMAgent.log"),
        "dcmreporting" => (SccmClientExtendedWorkflow::Compliance, "DCMReporting.log"),
        "statemessage" => (SccmClientExtendedWorkflow::Compliance, "StateMessage.log"),
        "swmtrreportgen" => (SccmClientExtendedWorkflow::Metering, "SWMTRReportGen.log"),
        _ => return Ok(None),
    };
    let Some(source) = admitted
        .source_artifacts()?
        .get(&evidence.reference.artifact_id)
    else {
        return Ok(None);
    };
    if source.basename != source_basename {
        return Ok(None);
    }

    Ok(Some(ArtifactContext {
        workflow,
        source_basename,
        source: source_citation(&evidence.reference.artifact_id, source),
    }))
}

fn workflow_for_basename(basename: &str) -> Option<SccmClientExtendedWorkflow> {
    match canonical_family_basename(basename).as_ref() {
        "InventoryAgent.log" | "InventoryProvider.log" | "InventoryAgentProvider.log" => {
            Some(SccmClientExtendedWorkflow::Inventory)
        }
        "CIAgent.log" | "CITaskMgr.log" | "DCMAgent.log" | "DCMReporting.log"
        | "StateMessage.log" => Some(SccmClientExtendedWorkflow::Compliance),
        "SWMTRReportGen.log" => Some(SccmClientExtendedWorkflow::Metering),
        _ => None,
    }
}

fn parse_fact(
    context: &ArtifactContext,
    profile_id: &str,
    evidence: &SccmEvidence,
    observations: &mut Vec<SccmClientExtendedObservation>,
) -> Option<Fact> {
    let fields = match parse_unique_fields(&evidence.message) {
        Ok(fields) => fields,
        Err(()) => {
            observe(
                observations,
                context,
                evidence,
                "The record repeats a field label, so its semantics are ambiguous.",
            );
            return None;
        }
    };
    let phase = fields
        .get("phase")
        .and_then(|value| parse_phase(context.workflow, value));
    let disposition = fields
        .get("disposition")
        .map_or(Disposition::Other, |value| parse_disposition(value));
    let terminal = fields
        .get("terminal")
        .is_some_and(|value| value.eq_ignore_ascii_case("true"));
    let Some(phase) = phase else {
        observe(
            observations,
            context,
            evidence,
            "The record has no admitted phase for this workflow.",
        );
        return None;
    };
    if !source_allows_phase(context.source_basename, phase) {
        observe(
            observations,
            context,
            evidence,
            "The source family cannot establish this phase.",
        );
        return None;
    }
    if fields
        .get("family")
        .is_some_and(|value| !value.eq_ignore_ascii_case(workflow_name(context.workflow)))
    {
        observe(
            observations,
            context,
            evidence,
            "The record explicitly names a different workflow family.",
        );
        return None;
    }

    let required = required_fields(context.workflow);
    let Some(values) = required
        .iter()
        .map(|label| fields.get(&label.to_ascii_lowercase()).cloned())
        .collect::<Option<Vec<_>>>()
    else {
        observe(
            observations,
            context,
            evidence,
            "The record lacks the complete exact workflow key tuple.",
        );
        return None;
    };
    let Some(keys) = make_keys(context.workflow, &values, profile_id, evidence) else {
        observe(
            observations,
            context,
            evidence,
            "The workflow key tuple contains an invalid or unbounded value.",
        );
        return None;
    };
    if context.workflow == SccmClientExtendedWorkflow::Compliance
        && disposition == Disposition::NonCompliant
        && !fields
            .get("resulttype")
            .is_some_and(|value| value.eq_ignore_ascii_case("Evaluation"))
    {
        observe(
            observations,
            context,
            evidence,
            "A noncompliant result is promotable only from an explicit evaluation record.",
        );
        return None;
    }
    let tuple = values.join("|");

    Some(Fact {
        workflow: context.workflow,
        phase,
        disposition,
        terminal,
        evidence: evidence.clone(),
        keys,
        tuple,
        profile_id: profile_id.to_owned(),
        result_type_evaluation: fields
            .get("resulttype")
            .is_some_and(|value| value.eq_ignore_ascii_case("Evaluation")),
        disposition_compliant: fields
            .get("disposition")
            .is_some_and(|value| value.eq_ignore_ascii_case("Compliant")),
        source_basename: context.source_basename.to_owned(),
    })
}

fn required_fields(workflow: SccmClientExtendedWorkflow) -> &'static [&'static str] {
    match workflow {
        SccmClientExtendedWorkflow::Inventory => {
            &["InventoryCycleId", "ResourceHandle", "ReportId"]
        }
        SccmClientExtendedWorkflow::Compliance => {
            &["CiId", "BaselineId", "StateId", "ResourceHandle"]
        }
        SccmClientExtendedWorkflow::Metering => {
            &["MeteringCycleId", "RuleId", "ReportId", "ResourceHandle"]
        }
    }
}

fn make_keys(
    workflow: SccmClientExtendedWorkflow,
    values: &[String],
    profile_id: &str,
    evidence: &SccmEvidence,
) -> Option<Vec<SccmCorrelationKey>> {
    let kinds = match workflow {
        SccmClientExtendedWorkflow::Inventory => vec![
            SccmCorrelationKeyKind::InventoryCycleId,
            SccmCorrelationKeyKind::ResourceHandle,
            SccmCorrelationKeyKind::ReportId,
        ],
        SccmClientExtendedWorkflow::Compliance => vec![
            SccmCorrelationKeyKind::ComplianceCiId,
            SccmCorrelationKeyKind::BaselineId,
            SccmCorrelationKeyKind::ComplianceStateId,
            SccmCorrelationKeyKind::ResourceHandle,
        ],
        SccmClientExtendedWorkflow::Metering => vec![
            SccmCorrelationKeyKind::MeteringCycleId,
            SccmCorrelationKeyKind::RuleId,
            SccmCorrelationKeyKind::ReportId,
            SccmCorrelationKeyKind::ResourceHandle,
        ],
    };
    values
        .iter()
        .zip(kinds)
        .map(|(value, kind)| {
            let mut key = normalize_key(kind, value);
            (key.confidence == super::super::SccmKeyConfidence::Exact).then(|| {
                key.confidence = SccmKeyConfidence::Low;
                key.extraction_profile_id = Some(profile_id.to_owned());
                key.evidence = Some(evidence.reference.clone());
                key
            })
        })
        .collect()
}

fn reduce_group(group: &mut [Fact]) -> SccmClientExtendedTransaction {
    group.sort_by(|left, right| {
        (
            left.evidence.timestamp.utc_millis,
            &left.evidence.evidence_id,
        )
            .cmp(&(
                right.evidence.timestamp.utc_millis,
                &right.evidence.evidence_id,
            ))
    });
    let first = &group[0];
    let terminal = group
        .iter()
        .filter(|fact| fact.terminal)
        .collect::<Vec<_>>();
    let successes = terminal
        .iter()
        .filter(|fact| fact.disposition == Disposition::Succeeded)
        .copied()
        .collect::<Vec<_>>();
    let failures = terminal
        .iter()
        .filter(|fact| fact.disposition == Disposition::Failed)
        .copied()
        .collect::<Vec<_>>();
    let noncompliant = terminal
        .iter()
        .filter(|fact| fact.disposition == Disposition::NonCompliant)
        .copied()
        .collect::<Vec<_>>();
    let deferred = group
        .iter()
        .filter(|fact| fact.disposition == Disposition::Deferred)
        .collect::<Vec<_>>();
    let compliant = terminal
        .iter()
        .any(|fact| fact.disposition_compliant && fact.result_type_evaluation);
    let remediated = first.workflow == SccmClientExtendedWorkflow::Compliance
        && group.iter().any(|fact| {
            fact.phase == SccmClientExtendedPhase::Remediate
                && fact.disposition == Disposition::Succeeded
        })
        && !successes.is_empty();

    let state = if !failures.is_empty() && !successes.is_empty() {
        if ordered_recovery(&failures, &successes) {
            SccmClientExtendedState::Recovered
        } else {
            SccmClientExtendedState::Contradictory
        }
    } else if !failures.is_empty() {
        SccmClientExtendedState::Failed
    } else if !noncompliant.is_empty() && compliant {
        SccmClientExtendedState::Contradictory
    } else if !noncompliant.is_empty() {
        SccmClientExtendedState::EvaluatedNonCompliant
    } else if !deferred.is_empty() {
        SccmClientExtendedState::BlockedOrDeferred
    } else if remediated {
        SccmClientExtendedState::Remediated
    } else if compliant {
        SccmClientExtendedState::EvaluatedCompliant
    } else if !successes.is_empty() {
        SccmClientExtendedState::Succeeded
    } else {
        SccmClientExtendedState::InProgress
    };

    let last_successful_phase = group
        .iter()
        .filter(|fact| {
            fact.disposition == Disposition::Succeeded
                || (fact.workflow == SccmClientExtendedWorkflow::Compliance
                    && fact.disposition == Disposition::NonCompliant)
        })
        .map(|fact| fact.phase)
        .max();
    let evidence = if terminal.is_empty() {
        group
            .iter()
            .map(|fact| fact.evidence.reference.clone())
            .collect()
    } else {
        terminal
            .iter()
            .map(|fact| fact.evidence.reference.clone())
            .collect()
    };
    let decisive = terminal
        .iter()
        .copied()
        .max_by_key(|fact| fact.phase)
        .unwrap_or_else(|| group.iter().max_by_key(|fact| fact.phase).unwrap_or(first));
    let phase = decisive.phase;
    let transaction_id = format!(
        "client-extended:{}:{}",
        workflow_name(first.workflow),
        tuple_discriminator(first.workflow, &first.tuple)
    );
    SccmClientExtendedTransaction {
        transaction_id,
        workflow: first.workflow,
        profile_id: first.profile_id.clone(),
        phase,
        source_basename: decisive.source_basename.clone(),
        state,
        last_successful_phase,
        keys: first.keys.clone(),
        evidence,
        coverage_gap_artifact_ids: Vec::new(),
    }
}

fn finding_for(transaction: &SccmClientExtendedTransaction) -> Option<SccmClientExtendedFinding> {
    let class = match transaction.state {
        SccmClientExtendedState::Failed | SccmClientExtendedState::EvaluatedNonCompliant => {
            SccmFindingClass::Symptom
        }
        SccmClientExtendedState::BlockedOrDeferred => SccmFindingClass::BlockedOrDeferred,
        SccmClientExtendedState::Contradictory | SccmClientExtendedState::InsufficientEvidence => {
            SccmFindingClass::InsufficientEvidence
        }
        SccmClientExtendedState::InProgress
        | SccmClientExtendedState::Succeeded
        | SccmClientExtendedState::EvaluatedCompliant
        | SccmClientExtendedState::Remediated
        | SccmClientExtendedState::Recovered => return None,
    };
    let source_basename = transaction.source_basename.as_str();
    let next_artifact = Some(SccmClientExtendedArtifactRequest {
        logical_artifact_id: workflow_artifact_id(transaction.workflow).to_owned(),
        source_basename: source_basename.to_owned(),
        reason: format!(
            "Inspect the same exact {} key in this admitted {} source.",
            workflow_name(transaction.workflow),
            workflow_name(transaction.workflow)
        ),
    });
    Some(SccmClientExtendedFinding {
        finding_id: format!("finding:client-extended:{}", transaction.transaction_id),
        subject_id: transaction.transaction_id.clone(),
        workflow: transaction.workflow,
        role: SccmRole::Client,
        class,
        severity: match transaction.state {
            SccmClientExtendedState::Failed => Severity::Error,
            SccmClientExtendedState::EvaluatedNonCompliant
            | SccmClientExtendedState::BlockedOrDeferred
            | SccmClientExtendedState::Contradictory
            | SccmClientExtendedState::InsufficientEvidence => Severity::Warning,
            SccmClientExtendedState::InProgress
            | SccmClientExtendedState::Succeeded
            | SccmClientExtendedState::EvaluatedCompliant
            | SccmClientExtendedState::Remediated
            | SccmClientExtendedState::Recovered => Severity::Info,
        },
        state: transaction.state,
        phase: transaction.phase,
        confidence: SccmKeyConfidence::Low,
        keys: transaction.keys.clone(),
        next_artifact,
        evidence: transaction.evidence.clone(),
    })
}

fn tuple_discriminator(workflow: SccmClientExtendedWorkflow, tuple: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(workflow_name(workflow).as_bytes());
    hasher.update([0]);
    hasher.update(tuple.as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn logical_artifact_for_basename(source_basename: &str) -> &'static str {
    match canonical_family_basename(source_basename).as_ref() {
        "InventoryAgent.log" | "InventoryProvider.log" | "InventoryAgentProvider.log" => {
            "client-inventory"
        }
        "CIAgent.log" | "StateMessage.log" => "client-policy-state",
        "CITaskMgr.log" | "DCMAgent.log" | "DCMReporting.log" => "client-compliance",
        "SWMTRReportGen.log" => "client-metering",
        _ => unreachable!("extended analysis only calls this for admitted source families"),
    }
}

fn canonical_family_basename(basename: &str) -> Cow<'_, str> {
    basename.strip_suffix(".lo_").map_or_else(
        || Cow::Borrowed(basename),
        |stem| Cow::Owned(format!("{stem}.log")),
    )
}

fn workflow_artifact_id(workflow: SccmClientExtendedWorkflow) -> &'static str {
    match workflow {
        SccmClientExtendedWorkflow::Inventory => "client-inventory",
        SccmClientExtendedWorkflow::Compliance => "client-compliance",
        SccmClientExtendedWorkflow::Metering => "client-metering",
    }
}

fn ordered_recovery(failures: &[&Fact], successes: &[&Fact]) -> bool {
    let Some(failure) = failures.last() else {
        return false;
    };
    let Some(success) = successes.first() else {
        return false;
    };
    failure.phase == success.phase
        && failure.evidence.timestamp.ordering_state == SccmTimeOrderingState::NormalizedUtc
        && success.evidence.timestamp.ordering_state == SccmTimeOrderingState::NormalizedUtc
        && failure.evidence.timestamp.utc_millis.is_some()
        && success.evidence.timestamp.utc_millis.is_some()
        && failure.evidence.timestamp.utc_millis < success.evidence.timestamp.utc_millis
}

fn parse_phase(
    workflow: SccmClientExtendedWorkflow,
    value: &str,
) -> Option<SccmClientExtendedPhase> {
    let phase = match value.to_ascii_lowercase().as_str() {
        "collect" => SccmClientExtendedPhase::Collect,
        "provider" => SccmClientExtendedPhase::Provider,
        "serialize" => SccmClientExtendedPhase::Serialize,
        "queue" => SccmClientExtendedPhase::Queue,
        "evaluate" => SccmClientExtendedPhase::Evaluate,
        "remediate" => SccmClientExtendedPhase::Remediate,
        "aggregate" => SccmClientExtendedPhase::Aggregate,
        "report" => SccmClientExtendedPhase::Report,
        _ => return None,
    };
    let valid = match workflow {
        SccmClientExtendedWorkflow::Inventory => matches!(
            phase,
            SccmClientExtendedPhase::Collect
                | SccmClientExtendedPhase::Provider
                | SccmClientExtendedPhase::Serialize
                | SccmClientExtendedPhase::Queue
                | SccmClientExtendedPhase::Report
        ),
        SccmClientExtendedWorkflow::Compliance => {
            matches!(
                phase,
                SccmClientExtendedPhase::Evaluate
                    | SccmClientExtendedPhase::Remediate
                    | SccmClientExtendedPhase::Report
            )
        }
        SccmClientExtendedWorkflow::Metering => {
            matches!(
                phase,
                SccmClientExtendedPhase::Collect
                    | SccmClientExtendedPhase::Aggregate
                    | SccmClientExtendedPhase::Report
            )
        }
    };
    valid.then_some(phase)
}

fn source_allows_phase(source: &str, phase: SccmClientExtendedPhase) -> bool {
    match source {
        "InventoryAgent.log" => phase == SccmClientExtendedPhase::Collect,
        "InventoryProvider.log" => matches!(
            phase,
            SccmClientExtendedPhase::Provider | SccmClientExtendedPhase::Serialize
        ),
        "InventoryAgentProvider.log" => matches!(
            phase,
            SccmClientExtendedPhase::Queue | SccmClientExtendedPhase::Report
        ),
        "CIAgent.log" => phase == SccmClientExtendedPhase::Evaluate,
        "CITaskMgr.log" => matches!(
            phase,
            SccmClientExtendedPhase::Evaluate | SccmClientExtendedPhase::Remediate
        ),
        "DCMAgent.log" => phase == SccmClientExtendedPhase::Remediate,
        "DCMReporting.log" => matches!(
            phase,
            SccmClientExtendedPhase::Evaluate | SccmClientExtendedPhase::Report
        ),
        "StateMessage.log" => phase == SccmClientExtendedPhase::Report,
        "SWMTRReportGen.log" => matches!(
            phase,
            SccmClientExtendedPhase::Collect
                | SccmClientExtendedPhase::Aggregate
                | SccmClientExtendedPhase::Report
        ),
        _ => false,
    }
}

fn parse_disposition(value: &str) -> Disposition {
    match value.to_ascii_lowercase().as_str() {
        "succeeded" | "compliant" => Disposition::Succeeded,
        "failed" => Disposition::Failed,
        "noncompliant" => Disposition::NonCompliant,
        "deferred" | "pending" => Disposition::Deferred,
        _ => Disposition::Other,
    }
}

fn parse_unique_fields(message: &str) -> Result<BTreeMap<String, String>, ()> {
    let mut fields = BTreeMap::new();
    for token in message.split_whitespace() {
        let Some((key, value)) = token.split_once('=') else {
            continue;
        };
        let key = key.to_ascii_lowercase();
        if fields.insert(key, value.to_owned()).is_some() {
            return Err(());
        }
    }
    Ok(fields)
}

fn profile_id(_workflow: SccmClientExtendedWorkflow) -> &'static str {
    SCCM_EXPERIMENTAL_KEY_PROFILE_ID
}

fn workflow_name(workflow: SccmClientExtendedWorkflow) -> &'static str {
    match workflow {
        SccmClientExtendedWorkflow::Inventory => "inventory",
        SccmClientExtendedWorkflow::Compliance => "compliance",
        SccmClientExtendedWorkflow::Metering => "metering",
    }
}

fn observe(
    observations: &mut Vec<SccmClientExtendedObservation>,
    context: &ArtifactContext,
    evidence: &SccmEvidence,
    reason: &str,
) {
    observations.push(SccmClientExtendedObservation {
        workflow: context.workflow,
        reason: reason.to_owned(),
        sources: vec![context.source.clone()],
        evidence: vec![evidence.reference.clone()],
    });
}
