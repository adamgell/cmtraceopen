use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::super::{
    classify_artifact_name, normalize_key, SccmArtifact, SccmArtifactFamily, SccmCorrelationKey,
    SccmCorrelationKeyKind, SccmCoverageState, SccmEvidence, SccmEvidenceRef,
    SccmTimeOrderingState,
};

const OBSERVED_VERSION_PREFIX: &str = "5.00.TEST.";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmWorkflow {
    Inventory,
    Compliance,
    Metering,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmPhase {
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
pub enum SccmTransactionState {
    InProgress,
    Succeeded,
    Failed,
    Recovered,
    Contradictory,
    EvaluatedNonCompliant,
    InsufficientEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmTransaction {
    pub transaction_id: String,
    pub workflow: SccmWorkflow,
    pub profile_id: String,
    pub configmgr_version: String,
    pub phase: SccmPhase,
    pub state: SccmTransactionState,
    pub last_successful_phase: Option<SccmPhase>,
    pub keys: Vec<SccmCorrelationKey>,
    pub evidence: Vec<SccmEvidenceRef>,
    pub coverage_gap_artifact_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmCoverageGap {
    pub workflow: SccmWorkflow,
    pub artifact_id: String,
    pub source_basename: String,
    pub state: SccmCoverageState,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmSourceObservation {
    pub workflow: SccmWorkflow,
    pub artifact_id: String,
    pub evidence_id: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmClientAnalysis {
    pub transactions: Vec<SccmTransaction>,
    pub coverage: Vec<SccmCoverageGap>,
    pub source_local_observations: Vec<SccmSourceObservation>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct TransactionKey {
    workflow: SccmWorkflow,
    tuple: String,
}

#[derive(Debug, Clone)]
struct Fact {
    workflow: SccmWorkflow,
    phase: SccmPhase,
    disposition: Disposition,
    terminal: bool,
    evidence: SccmEvidence,
    keys: Vec<SccmCorrelationKey>,
    tuple: String,
    profile_id: String,
    configmgr_version: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Disposition {
    Succeeded,
    Failed,
    NonCompliant,
    Deferred,
    Other,
}

/// Analyze only the three client-extended workflows represented by the observed
/// #325 source catalog. The function accepts normalized evidence and metadata;
/// it never reads files, infers paths, or reparses CCM records.
pub fn analyze_client_extended(
    artifacts: &[SccmArtifact],
    evidence: &[SccmEvidence],
) -> SccmClientAnalysis {
    let mut coverage = Vec::new();
    let mut observations = Vec::new();
    let mut facts = BTreeMap::<TransactionKey, Vec<Fact>>::new();

    for artifact in artifacts {
        let Some(context) = artifact_context(artifact) else {
            continue;
        };

        if artifact.coverage != SccmCoverageState::Captured {
            coverage.push(SccmCoverageGap {
                workflow: context.workflow,
                artifact_id: artifact.artifact_id.clone(),
                source_basename: context.source_basename.to_owned(),
                state: artifact.coverage.clone(),
                reason: "The admitted source was not captured; this is a coverage gap, not a workflow outcome.".to_owned(),
            });
            continue;
        }

        let Some(version) = artifact.configmgr_version.as_deref() else {
            coverage.push(version_gap(context, artifact));
            continue;
        };
        if !version.starts_with(OBSERVED_VERSION_PREFIX) {
            coverage.push(version_gap(context, artifact));
            continue;
        }

        let profile_id = profile_id(context.workflow);
        for item in evidence
            .iter()
            .filter(|item| item.reference.artifact_id == artifact.artifact_id)
        {
            let Some(fact) = parse_fact(
                context,
                profile_id,
                version,
                artifact,
                item,
                &mut observations,
            ) else {
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
    }

    coverage.sort_by(|left, right| {
        (
            left.workflow,
            &left.artifact_id,
            &left.source_basename,
            &left.reason,
        )
            .cmp(&(
                right.workflow,
                &right.artifact_id,
                &right.source_basename,
                &right.reason,
            ))
    });
    observations.sort_by(|left, right| {
        (
            left.workflow,
            &left.artifact_id,
            &left.evidence_id,
            &left.reason,
        )
            .cmp(&(
                right.workflow,
                &right.artifact_id,
                &right.evidence_id,
                &right.reason,
            ))
    });

    let transactions = facts
        .into_values()
        .map(|mut group| reduce_group(&mut group))
        .collect();

    SccmClientAnalysis {
        transactions,
        coverage,
        source_local_observations: observations,
    }
}

#[derive(Debug, Clone, Copy)]
struct ArtifactContext {
    workflow: SccmWorkflow,
    source_basename: &'static str,
}

fn artifact_context(artifact: &SccmArtifact) -> Option<ArtifactContext> {
    let catalog = classify_artifact_name(&artifact.display_name, artifact.role.clone());
    let (workflow, source_basename) = match &catalog.family {
        SccmArtifactFamily::ClientInventory => (SccmWorkflow::Inventory, catalog.logical_name),
        SccmArtifactFamily::ClientCompliance => (SccmWorkflow::Compliance, catalog.logical_name),
        SccmArtifactFamily::ClientMetering => (SccmWorkflow::Metering, catalog.logical_name),
        _ => return None,
    };

    let source_basename = match workflow {
        SccmWorkflow::Inventory => match source_basename.as_str() {
            "inventoryAgent" => "InventoryAgent.log",
            "inventoryProvider" => "InventoryProvider.log",
            "inventoryAgentProvider" => "InventoryAgentProvider.log",
            _ => return None,
        },
        SccmWorkflow::Compliance => match source_basename.as_str() {
            "ciAgent" => "CIAgent.log",
            "ciTaskMgr" => "CITaskMgr.log",
            "dcmAgent" => "DCMAgent.log",
            "dcmReporting" => "DCMReporting.log",
            "stateMessage" => "StateMessage.log",
            _ => return None,
        },
        SccmWorkflow::Metering => "SWMTRReportGen.log",
    };

    Some(ArtifactContext {
        workflow,
        source_basename,
    })
}

fn version_gap(context: ArtifactContext, artifact: &SccmArtifact) -> SccmCoverageGap {
    SccmCoverageGap {
        workflow: context.workflow,
        artifact_id: artifact.artifact_id.clone(),
        source_basename: context.source_basename.to_owned(),
        state: artifact.coverage.clone(),
        reason: "The source version is absent or outside the observed profile; no state claim was promoted.".to_owned(),
    }
}

fn parse_fact(
    context: ArtifactContext,
    profile_id: &str,
    version: &str,
    artifact: &SccmArtifact,
    evidence: &SccmEvidence,
    observations: &mut Vec<SccmSourceObservation>,
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
            artifact,
            evidence,
            "The record has no admitted phase for this workflow.",
        );
        return None;
    };
    if !source_allows_phase(context.source_basename, phase) {
        observe(
            observations,
            context.workflow,
            artifact,
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
            artifact,
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
            artifact,
            evidence,
            "The record lacks the complete exact workflow key tuple.",
        );
        return None;
    };
    let Some(keys) = make_keys(context.workflow, &values, profile_id, evidence) else {
        observe(
            observations,
            context.workflow,
            artifact,
            evidence,
            "The workflow key tuple contains an invalid or unbounded value.",
        );
        return None;
    };
    if context.workflow == SccmWorkflow::Compliance
        && disposition == Disposition::NonCompliant
        && !field(&evidence.message, "ResultType")
            .is_some_and(|value| value.eq_ignore_ascii_case("Evaluation"))
    {
        observe(
            observations,
            context.workflow,
            artifact,
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
        configmgr_version: version.to_owned(),
    })
}

fn required_fields(workflow: SccmWorkflow) -> &'static [&'static str] {
    match workflow {
        SccmWorkflow::Inventory => &["InventoryCycleId", "ResourceHandle", "ReportId"],
        SccmWorkflow::Compliance => &["CiId", "BaselineId", "StateId", "ResourceHandle"],
        SccmWorkflow::Metering => &["MeteringCycleId", "RuleId", "ReportId", "ResourceHandle"],
    }
}

fn make_keys(
    workflow: SccmWorkflow,
    values: &[String],
    profile_id: &str,
    evidence: &SccmEvidence,
) -> Option<Vec<SccmCorrelationKey>> {
    let kinds = match workflow {
        SccmWorkflow::Inventory => vec![
            SccmCorrelationKeyKind::InventoryCycleId,
            SccmCorrelationKeyKind::ResourceHandle,
            SccmCorrelationKeyKind::ReportId,
        ],
        SccmWorkflow::Compliance => vec![
            SccmCorrelationKeyKind::ComplianceCiId,
            SccmCorrelationKeyKind::BaselineId,
            SccmCorrelationKeyKind::ComplianceStateId,
            SccmCorrelationKeyKind::ResourceHandle,
        ],
        SccmWorkflow::Metering => vec![
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
                key.extraction_profile_id = Some(profile_id.to_owned());
                key.evidence = Some(evidence.reference.clone());
                key
            })
        })
        .collect()
}

fn reduce_group(group: &mut [Fact]) -> SccmTransaction {
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
    let compliant = terminal.iter().any(|fact| {
        fact.disposition == Disposition::Succeeded
            && field(&fact.evidence.message, "ResultType")
                .is_some_and(|value| value.eq_ignore_ascii_case("Evaluation"))
            && field(&fact.evidence.message, "Disposition")
                .is_some_and(|value| value.eq_ignore_ascii_case("Compliant"))
    });

    let state = if !failures.is_empty() && !successes.is_empty() {
        if ordered_recovery(&failures, &successes) {
            SccmTransactionState::Recovered
        } else {
            SccmTransactionState::Contradictory
        }
    } else if !failures.is_empty() {
        SccmTransactionState::Failed
    } else if !noncompliant.is_empty() && compliant {
        SccmTransactionState::Contradictory
    } else if !noncompliant.is_empty() {
        SccmTransactionState::EvaluatedNonCompliant
    } else if !successes.is_empty() {
        SccmTransactionState::Succeeded
    } else {
        SccmTransactionState::InProgress
    };

    let last_successful_phase = group
        .iter()
        .filter(|fact| {
            fact.disposition == Disposition::Succeeded
                || (fact.workflow == SccmWorkflow::Compliance
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
        "{}:{}",
        workflow_name(first.workflow),
        first.tuple.to_ascii_lowercase()
    );
    SccmTransaction {
        transaction_id,
        workflow: first.workflow,
        profile_id: first.profile_id.clone(),
        configmgr_version: first.configmgr_version.clone(),
        phase,
        state,
        last_successful_phase,
        keys: first.keys.clone(),
        evidence,
        coverage_gap_artifact_ids: Vec::new(),
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

fn parse_phase(workflow: SccmWorkflow, value: &str) -> Option<SccmPhase> {
    let phase = match value.to_ascii_lowercase().as_str() {
        "collect" => SccmPhase::Collect,
        "provider" => SccmPhase::Provider,
        "serialize" => SccmPhase::Serialize,
        "queue" => SccmPhase::Queue,
        "evaluate" => SccmPhase::Evaluate,
        "remediate" => SccmPhase::Remediate,
        "aggregate" => SccmPhase::Aggregate,
        "report" => SccmPhase::Report,
        _ => return None,
    };
    let valid = match workflow {
        SccmWorkflow::Inventory => matches!(
            phase,
            SccmPhase::Collect
                | SccmPhase::Provider
                | SccmPhase::Serialize
                | SccmPhase::Queue
                | SccmPhase::Report
        ),
        SccmWorkflow::Compliance => {
            matches!(
                phase,
                SccmPhase::Evaluate | SccmPhase::Remediate | SccmPhase::Report
            )
        }
        SccmWorkflow::Metering => {
            matches!(
                phase,
                SccmPhase::Collect | SccmPhase::Aggregate | SccmPhase::Report
            )
        }
    };
    valid.then_some(phase)
}

fn source_allows_phase(source: &str, phase: SccmPhase) -> bool {
    match source {
        "InventoryAgent.log" => phase == SccmPhase::Collect,
        "InventoryProvider.log" => matches!(phase, SccmPhase::Provider | SccmPhase::Serialize),
        "InventoryAgentProvider.log" => matches!(phase, SccmPhase::Queue | SccmPhase::Report),
        "CIAgent.log" => phase == SccmPhase::Evaluate,
        "CITaskMgr.log" => matches!(phase, SccmPhase::Evaluate | SccmPhase::Remediate),
        "DCMAgent.log" => phase == SccmPhase::Remediate,
        "DCMReporting.log" | "StateMessage.log" => phase == SccmPhase::Report,
        "SWMTRReportGen.log" => matches!(
            phase,
            SccmPhase::Collect | SccmPhase::Aggregate | SccmPhase::Report
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

fn profile_id(workflow: SccmWorkflow) -> &'static str {
    match workflow {
        SccmWorkflow::Inventory => "sccm-client-inventory-5.00.test-v1",
        SccmWorkflow::Compliance => "sccm-client-compliance-5.00.test-v1",
        SccmWorkflow::Metering => "sccm-client-metering-5.00.test-v1",
    }
}

fn workflow_name(workflow: SccmWorkflow) -> &'static str {
    match workflow {
        SccmWorkflow::Inventory => "inventory",
        SccmWorkflow::Compliance => "compliance",
        SccmWorkflow::Metering => "metering",
    }
}

fn observe(
    observations: &mut Vec<SccmSourceObservation>,
    workflow: SccmWorkflow,
    artifact: &SccmArtifact,
    evidence: &SccmEvidence,
    reason: &str,
) {
    observations.push(SccmSourceObservation {
        workflow,
        artifact_id: artifact.artifact_id.clone(),
        evidence_id: evidence.evidence_id.clone(),
        reason: reason.to_owned(),
    });
}
