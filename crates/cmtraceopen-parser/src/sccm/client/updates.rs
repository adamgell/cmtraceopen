//! Conservative SCCM client software-update transaction analysis.
//!
//! The analyzer accepts only evidence produced by the sealed client admission
//! boundary. It never reads files, consumes another reducer, or infers a
//! server-side SUP cause.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::sccm::{
    SccmConfidence, SccmEvidence, SccmEvidenceRef, SccmFindingClass, SccmKeyConfidence,
    SCCM_EXPERIMENTAL_KEY_PROFILE_ID,
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
    InsufficientEvidence,
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
    pub phase: SccmClientUpdatePhase,
    pub last_successful_phase: Option<SccmClientUpdatePhase>,
    pub confidence: SccmConfidence,
    pub confidence_ceiling: SccmConfidence,
    pub next_artifact: Option<SccmClientUpdateArtifactRequest>,
    pub evidence: Vec<SccmEvidenceRef>,
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
    pub emitted_counterpart_ready_fact: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmClientUpdatesAnalysis {
    pub schema_version: u32,
    pub transactions: Vec<SccmClientUpdateTransaction>,
    pub findings: Vec<SccmClientUpdateFinding>,
    pub correlation_handoff: SccmClientUpdateCorrelationHandoff,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PhaseDisposition {
    Succeeded,
    Failed,
    Deferred,
}

#[derive(Debug, Clone)]
struct UpdateFact {
    key: SccmClientUpdateKey,
    phase: SccmClientUpdatePhase,
    disposition: PhaseDisposition,
    evidence: SccmEvidenceRef,
}

/// Reduces sealed, intake-bound client evidence into update transactions.
pub fn analyze_client_updates(
    admitted: &SccmClientAdmittedEvidence,
) -> Result<SccmClientUpdatesAnalysis, SccmClientEvidenceAdmissionError> {
    let mut facts_by_key = BTreeMap::<(String, String), Vec<UpdateFact>>::new();
    for evidence in admitted.evidence()? {
        if let Some(fact) = update_fact(evidence) {
            facts_by_key
                .entry((fact.key.update_id.clone(), fact.key.ci_id.clone()))
                .or_default()
                .push(fact);
        }
    }

    let mut transactions = Vec::new();
    let mut findings = Vec::new();
    for (_, mut facts) in facts_by_key {
        facts.sort_by(|left, right| {
            left.phase
                .cmp(&right.phase)
                .then_with(|| left.evidence.artifact_id.cmp(&right.evidence.artifact_id))
                .then_with(|| left.evidence.line_start.cmp(&right.evidence.line_start))
        });
        let Some(last) = facts.last() else {
            continue;
        };
        let failed = facts
            .iter()
            .filter(|fact| fact.disposition == PhaseDisposition::Failed)
            .min_by_key(|fact| fact.phase);
        let deferred = facts
            .iter()
            .filter(|fact| fact.disposition == PhaseDisposition::Deferred)
            .max_by_key(|fact| fact.phase);
        let decisive = failed.or(deferred).unwrap_or(last);
        let state = if failed.is_some() {
            SccmClientUpdateState::Failed
        } else if deferred.is_some() {
            SccmClientUpdateState::BlockedOrDeferred
        } else {
            SccmClientUpdateState::Succeeded
        };
        let classification = if failed.is_some() {
            SccmClientUpdateClassification::ConfirmedFailure
        } else if deferred.is_some() {
            SccmClientUpdateClassification::BlockedOrDeferred
        } else {
            SccmClientUpdateClassification::Success
        };
        let last_successful_phase = facts
            .iter()
            .filter(|fact| {
                fact.disposition == PhaseDisposition::Succeeded && fact.phase <= decisive.phase
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
        let transaction_id = format!("updates:update:{}", decisive.key.update_id);
        let transaction = SccmClientUpdateTransaction {
            transaction_id: transaction_id.clone(),
            key: decisive.key.clone(),
            phase: decisive.phase,
            state,
            last_successful_phase,
            classification,
            confidence: SccmConfidence::Low,
            confidence_ceiling: SccmConfidence::Low,
            coverage_gap_artifact_ids: Vec::new(),
            next_artifact: None,
            evidence: evidence.clone(),
        };
        if failed.is_some() || deferred.is_some() {
            findings.push(SccmClientUpdateFinding {
                finding_id: format!(
                    "finding:updates:{}-{}",
                    phase_name(decisive.phase),
                    if failed.is_some() {
                        "failure"
                    } else {
                        "deferred"
                    }
                ),
                subject_id: transaction_id,
                class: if failed.is_some() {
                    SccmFindingClass::ConfirmedFailure
                } else {
                    SccmFindingClass::BlockedOrDeferred
                },
                phase: decisive.phase,
                last_successful_phase,
                confidence: SccmConfidence::Low,
                confidence_ceiling: SccmConfidence::Low,
                next_artifact: None,
                evidence,
            });
        }
        transactions.push(transaction);
    }

    Ok(SccmClientUpdatesAnalysis {
        schema_version: SCCM_CLIENT_UPDATES_ANALYSIS_SCHEMA_VERSION,
        transactions,
        findings,
        correlation_handoff: SccmClientUpdateCorrelationHandoff {
            issue: "#333".to_owned(),
            server_prerequisite_issue: "#330".to_owned(),
            performed: false,
            time_only_eligible: false,
            topology_compatibility_evaluated: false,
            server_cause_claimed: false,
            emitted_counterpart_ready_fact: false,
        },
    })
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
            client_handle: optional_safe_field(&evidence.message, "ClientHandle"),
            site_code: optional_safe_field(&evidence.message, "SiteCode"),
            sup_host_handle: optional_safe_field(&evidence.message, "SupHostHandle"),
            confidence: SccmKeyConfidence::Exact,
            extraction_profile_id: SCCM_EXPERIMENTAL_KEY_PROFILE_ID.to_owned(),
        },
        phase,
        disposition,
        evidence: evidence.reference.clone(),
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
