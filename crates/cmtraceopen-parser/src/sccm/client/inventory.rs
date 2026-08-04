use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::models::log_entry::Severity;

use super::super::{
    normalize_key, SccmCorrelationKey, SccmCorrelationKeyKind, SccmCoverageState, SccmEvidence,
    SccmEvidenceRef, SccmFindingClass, SccmKeyConfidence, SccmRole, SccmTimeOrderingState,
    SCCM_EXPERIMENTAL_KEY_PROFILE_ID,
};
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
    pub state: SccmClientExtendedState,
    pub last_successful_phase: Option<SccmClientExtendedPhase>,
    pub keys: Vec<SccmCorrelationKey>,
    pub evidence: Vec<SccmEvidenceRef>,
    pub coverage_gap_artifact_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmClientExtendedCoverageGap {
    pub workflow: SccmClientExtendedWorkflow,
    pub logical_artifact_id: String,
    pub state: SccmCoverageState,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmClientExtendedObservation {
    pub workflow: SccmClientExtendedWorkflow,
    pub reason: String,
    pub artifact_ids: Vec<String>,
    pub evidence: Vec<SccmEvidenceRef>,
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
    pub next_artifact_id: Option<String>,
    pub evidence: Vec<SccmEvidenceRef>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmClientExtendedAnalysis {
    pub schema_version: u32,
    pub transactions: Vec<SccmClientExtendedTransaction>,
    pub coverage: Vec<SccmClientExtendedCoverageGap>,
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
            artifact_ids: vec![artifact_id.clone()],
            evidence: Vec::new(),
        });
    }

    for evidence in admitted.evidence()? {
        let Some(context) = evidence_context(admitted, evidence)? else {
            continue;
        };
        let profile_id = profile_id(context.workflow);
        let Some(fact) = parse_fact(context, profile_id, evidence, &mut observations) else {
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
            .then_with(|| left.artifact_ids.cmp(&right.artifact_ids))
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
                gap.workflow == transaction.workflow && gap.state != SccmCoverageState::Captured
            })
            .map(|gap| gap.logical_artifact_id.clone())
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

#[derive(Debug, Clone, Copy)]
struct ArtifactContext {
    workflow: SccmClientExtendedWorkflow,
    source_basename: &'static str,
}

fn extended_coverage(
    admitted: &SccmClientAdmittedEvidence,
) -> Result<Vec<SccmClientExtendedCoverageGap>, SccmClientEvidenceAdmissionError> {
    let mut coverage = Vec::new();
    for (workflow, logical_artifact_id) in [
        (SccmClientExtendedWorkflow::Inventory, "client-inventory"),
        (SccmClientExtendedWorkflow::Compliance, "client-compliance"),
        (
            SccmClientExtendedWorkflow::Compliance,
            "client-policy-state",
        ),
        (SccmClientExtendedWorkflow::Metering, "client-metering"),
    ] {
        let state = admitted
            .source_coverage(logical_artifact_id)?
            .cloned()
            .unwrap_or(SccmCoverageState::Absent);
        coverage.push(SccmClientExtendedCoverageGap {
            workflow,
            logical_artifact_id: logical_artifact_id.to_owned(),
            reason: if state == SccmCoverageState::Captured {
                "The bounded workflow source group was captured; transaction claims still require exact record evidence."
            } else {
                "The bounded workflow source group is incomplete; coverage cannot become a workflow outcome."
            }
            .to_owned(),
            state,
        });
    }
    Ok(coverage)
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
    if admitted.source_basename_for_artifact(&evidence.reference.artifact_id)?
        != Some(source_basename)
    {
        return Ok(None);
    }

    Ok(Some(ArtifactContext {
        workflow,
        source_basename,
    }))
}

fn workflow_for_basename(basename: &str) -> Option<SccmClientExtendedWorkflow> {
    match basename {
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
    context: ArtifactContext,
    profile_id: &str,
    evidence: &SccmEvidence,
    observations: &mut Vec<SccmClientExtendedObservation>,
) -> Option<Fact> {
    let phase =
        field(&evidence.message, "Phase").and_then(|value| parse_phase(context.workflow, &value));
    let disposition = field(&evidence.message, "Disposition")
        .map_or(Disposition::Other, |value| parse_disposition(&value));
    let terminal = field(&evidence.message, "Terminal")
        .is_some_and(|value| value.eq_ignore_ascii_case("true"));
    let Some(phase) = phase else {
        observe(
            observations,
            context.workflow,
            evidence,
            "The record has no admitted phase for this workflow.",
        );
        return None;
    };
    if !source_allows_phase(context.source_basename, phase) {
        observe(
            observations,
            context.workflow,
            evidence,
            "The source family cannot establish this phase.",
        );
        return None;
    }
    if field(&evidence.message, "Family")
        .is_some_and(|value| !value.eq_ignore_ascii_case(workflow_name(context.workflow)))
    {
        observe(
            observations,
            context.workflow,
            evidence,
            "The record explicitly names a different workflow family.",
        );
        return None;
    }

    let required = required_fields(context.workflow);
    let Some(values) = required
        .iter()
        .map(|label| field(&evidence.message, label))
        .collect::<Option<Vec<_>>>()
    else {
        observe(
            observations,
            context.workflow,
            evidence,
            "The record lacks the complete exact workflow key tuple.",
        );
        return None;
    };
    let Some(keys) = make_keys(context.workflow, &values, profile_id, evidence) else {
        observe(
            observations,
            context.workflow,
            evidence,
            "The workflow key tuple contains an invalid or unbounded value.",
        );
        return None;
    };
    if context.workflow == SccmClientExtendedWorkflow::Compliance
        && disposition == Disposition::NonCompliant
        && !field(&evidence.message, "ResultType")
            .is_some_and(|value| value.eq_ignore_ascii_case("Evaluation"))
    {
        observe(
            observations,
            context.workflow,
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
    let compliant = terminal.iter().any(|fact| {
        fact.disposition == Disposition::Succeeded
            && field(&fact.evidence.message, "ResultType")
                .is_some_and(|value| value.eq_ignore_ascii_case("Evaluation"))
            && field(&fact.evidence.message, "Disposition")
                .is_some_and(|value| value.eq_ignore_ascii_case("Compliant"))
    });
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
    let phase = terminal
        .iter()
        .map(|fact| fact.phase)
        .max()
        .unwrap_or(first.phase);
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
        | SccmClientExtendedState::Remediated
        | SccmClientExtendedState::Recovered => return None,
    };
    let next_artifact_id = transaction
        .coverage_gap_artifact_ids
        .first()
        .cloned()
        .or_else(|| {
            matches!(
                transaction.state,
                SccmClientExtendedState::BlockedOrDeferred
                    | SccmClientExtendedState::Contradictory
                    | SccmClientExtendedState::InsufficientEvidence
            )
            .then(|| workflow_artifact_id(transaction.workflow).to_owned())
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
            | SccmClientExtendedState::Remediated
            | SccmClientExtendedState::Recovered => Severity::Info,
        },
        state: transaction.state,
        phase: transaction.phase,
        confidence: SccmKeyConfidence::Low,
        keys: transaction.keys.clone(),
        next_artifact_id,
        evidence: transaction.evidence.clone(),
    })
}

fn tuple_discriminator(workflow: SccmClientExtendedWorkflow, tuple: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(workflow_name(workflow).as_bytes());
    hasher.update([0]);
    hasher.update(tuple.as_bytes());
    hasher.finalize()[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
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

fn field(message: &str, label: &str) -> Option<String> {
    message.split_whitespace().find_map(|token| {
        let (key, value) = token.split_once('=')?;
        key.eq_ignore_ascii_case(label).then(|| value.to_owned())
    })
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
    workflow: SccmClientExtendedWorkflow,
    evidence: &SccmEvidence,
    reason: &str,
) {
    observations.push(SccmClientExtendedObservation {
        workflow,
        reason: reason.to_owned(),
        artifact_ids: vec![evidence.reference.artifact_id.clone()],
        evidence: vec![evidence.reference.clone()],
    });
}
