use std::collections::{BTreeMap, BTreeSet};
use std::ops::Deref;

use serde::Serialize;
use thiserror::Error;

use crate::models::log_entry::Severity;
use crate::sccm::{
    SccmArtifactFamily, SccmArtifactRequest, SccmConfidence, SccmCorrelationKey,
    SccmCorrelationKeyKind, SccmCoverageState, SccmEvidence, SccmEvidenceRef, SccmFinding,
    SccmFindingBuilder, SccmFindingClass, SccmFindingCoverageGap, SccmFindingValidationError,
    SccmPhase, SccmRole, SccmRotation, SccmTerminalEvidence,
};

use super::admission::SccmClientAdmittedSourceArtifact;
use super::{SccmClientAdmittedEvidence, SccmClientEvidenceAdmissionError};

pub const SCCM_CLIENT_HEALTH_ANALYSIS_SCHEMA_VERSION: u32 = 1;

type EvidenceIdentity = (String, String, Option<u32>, Option<u32>);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmClientHealthPhase {
    Install,
    Upgrade,
    Repair,
    Removal,
    Service,
    ClientHealth,
    Reboot,
    Identity,
    Authentication,
    Assignment,
    Boundary,
    ManagementPointLocation,
    Transport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmClientHealthHopState {
    Succeeded,
    Failed,
    Pending,
    Contradictory,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmClientHealthHop {
    pub phase: SccmClientHealthPhase,
    pub state: SccmClientHealthHopState,
    pub evidence: Vec<SccmEvidenceRef>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmClientHealthSourceCoverage {
    pub artifact_id: String,
    pub logical_artifact_id: String,
    pub coverage: SccmCoverageState,
    pub rotation: SccmRotation,
    pub fragment_complete: bool,
    pub physical: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmClientHealthFinding {
    #[serde(flatten)]
    pub finding: SccmFinding,
    pub health_phase: SccmClientHealthPhase,
    pub last_confirmed_successful_phase: Option<SccmClientHealthPhase>,
}

impl Deref for SccmClientHealthFinding {
    type Target = SccmFinding;

    fn deref(&self) -> &Self::Target {
        &self.finding
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmClientHealthAnalysis {
    pub schema_version: u32,
    pub lifecycle_phase: Option<SccmClientHealthPhase>,
    pub last_confirmed_successful_phase: Option<SccmClientHealthPhase>,
    pub hops: Vec<SccmClientHealthHop>,
    pub findings: Vec<SccmClientHealthFinding>,
    pub source_coverage: Vec<SccmClientHealthSourceCoverage>,
    pub prohibited_claims: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SccmClientHealthAnalysisError {
    #[error(transparent)]
    EvidenceAdmission(#[from] SccmClientEvidenceAdmissionError),
    #[error("client health reducer produced an invalid canonical finding: {0:?}")]
    FindingContract(SccmFindingValidationError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Disposition {
    Started,
    Succeeded,
    Failed,
    Pending,
}

#[derive(Debug, Clone, Default)]
struct FactKeys {
    client_guid: Option<String>,
    site_code: Option<String>,
    management_point_host: Option<String>,
    request_id: Option<String>,
}

#[derive(Debug, Clone)]
struct HealthFact {
    phase: SccmClientHealthPhase,
    disposition: Disposition,
    terminal: bool,
    keys: FactKeys,
    reference: SccmEvidenceRef,
    utc_millis: i64,
}

#[derive(Debug, Clone, Default)]
struct ChainKeys {
    client_guid: Option<String>,
    site_code: Option<String>,
    management_point_host: Option<String>,
    last_utc_millis: Option<i64>,
}

#[derive(Debug)]
enum Resolution<'a> {
    Succeeded(&'a HealthFact),
    Failed(&'a HealthFact),
    Pending(Vec<&'a HealthFact>),
    Contradictory(Vec<&'a HealthFact>),
    Missing,
}

pub fn analyze_client_health(
    admitted: &SccmClientAdmittedEvidence,
) -> Result<SccmClientHealthAnalysis, SccmClientHealthAnalysisError> {
    let evidence = admitted.evidence()?;
    let sources = admitted.source_artifacts()?;
    let source_coverage = health_source_coverage(sources);
    let keys_by_reference = admitted_health_keys(admitted, evidence, sources)?;
    let mut facts = evidence
        .iter()
        .filter_map(|evidence| {
            let source = sources.get(&evidence.reference.artifact_id)?;
            let keys = keys_by_reference
                .get(&reference_identity(&evidence.reference))
                .cloned()
                .unwrap_or_default();
            parse_fact(evidence, source, keys)
        })
        .collect::<Vec<_>>();
    facts.sort_by(|left, right| {
        (left.utc_millis, reference_identity(&left.reference))
            .cmp(&(right.utc_millis, reference_identity(&right.reference)))
    });

    let mut hops = Vec::new();
    let mut chain = ChainKeys::default();
    let mut last_success = None;
    let lifecycle = lifecycle_resolution(&facts);
    let lifecycle_phase = lifecycle_phase(&lifecycle);

    match lifecycle {
        Resolution::Succeeded(fact) => {
            advance_chain(&mut chain, fact);
            last_success = Some(fact.phase);
            hops.push(hop(fact.phase, SccmClientHealthHopState::Succeeded, [fact]));
        }
        stop => {
            return finish_at_stop(
                lifecycle_phase.unwrap_or(SccmClientHealthPhase::Install),
                stop,
                last_success,
                hops,
                source_coverage,
                evidence,
                sources,
            );
        }
    }

    for phase in ordered_post_lifecycle_phases() {
        let resolution = resolve_phase(&facts, phase, &chain);
        match resolution {
            Resolution::Succeeded(fact) => {
                advance_chain(&mut chain, fact);
                last_success = Some(phase);
                hops.push(hop(phase, SccmClientHealthHopState::Succeeded, [fact]));
            }
            stop => {
                return finish_at_stop(
                    phase,
                    stop,
                    last_success,
                    hops,
                    source_coverage,
                    evidence,
                    sources,
                );
            }
        }
    }

    Ok(SccmClientHealthAnalysis {
        schema_version: SCCM_CLIENT_HEALTH_ANALYSIS_SCHEMA_VERSION,
        lifecycle_phase,
        last_confirmed_successful_phase: last_success,
        hops,
        findings: Vec::new(),
        source_coverage,
        prohibited_claims: prohibited_claims(),
    })
}

fn finish_at_stop(
    phase: SccmClientHealthPhase,
    resolution: Resolution<'_>,
    last_success: Option<SccmClientHealthPhase>,
    mut hops: Vec<SccmClientHealthHop>,
    source_coverage: Vec<SccmClientHealthSourceCoverage>,
    evidence: &[SccmEvidence],
    sources: &BTreeMap<String, SccmClientAdmittedSourceArtifact>,
) -> Result<SccmClientHealthAnalysis, SccmClientHealthAnalysisError> {
    let (state, facts) = match resolution {
        Resolution::Failed(fact) => (SccmClientHealthHopState::Failed, vec![fact]),
        Resolution::Pending(facts) => (SccmClientHealthHopState::Pending, facts),
        Resolution::Contradictory(facts) => (SccmClientHealthHopState::Contradictory, facts),
        Resolution::Missing => (SccmClientHealthHopState::Pending, Vec::new()),
        Resolution::Succeeded(_) => unreachable!("successful phases do not stop the chain"),
    };
    if !facts.is_empty() {
        hops.push(hop(phase, state, facts.iter().copied()));
    }
    let finding = finding_for_stop(phase, state, &facts, last_success, evidence, sources)?;

    Ok(SccmClientHealthAnalysis {
        schema_version: SCCM_CLIENT_HEALTH_ANALYSIS_SCHEMA_VERSION,
        lifecycle_phase: hops
            .first()
            .map(|hop| hop.phase)
            .filter(|phase| phase.is_lifecycle()),
        last_confirmed_successful_phase: last_success,
        hops,
        findings: vec![finding],
        source_coverage,
        prohibited_claims: prohibited_claims(),
    })
}

fn finding_for_stop(
    phase: SccmClientHealthPhase,
    state: SccmClientHealthHopState,
    facts: &[&HealthFact],
    last_success: Option<SccmClientHealthPhase>,
    evidence: &[SccmEvidence],
    sources: &BTreeMap<String, SccmClientAdmittedSourceArtifact>,
) -> Result<SccmClientHealthFinding, SccmClientHealthAnalysisError> {
    let logical_id = logical_artifact_for_phase(phase);
    let coverage_gaps = sources
        .iter()
        .filter(|(_, source)| {
            logical_artifact_for_basename(&source.basename) == Some(logical_id)
                && !source_is_complete(source)
        })
        .map(|(artifact_id, source)| SccmFindingCoverageGap {
            artifact_id: artifact_id.clone(),
            role: SccmRole::Client,
            coverage: if source.coverage == SccmCoverageState::Captured {
                SccmCoverageState::Capped
            } else {
                source.coverage.clone()
            },
        })
        .collect::<Vec<_>>();
    let mut cited = facts
        .iter()
        .map(|fact| fact.reference.clone())
        .collect::<Vec<_>>();
    if cited.is_empty() && coverage_gaps.is_empty() {
        cited = evidence
            .iter()
            .filter(|evidence| {
                sources
                    .get(&evidence.reference.artifact_id)
                    .is_some_and(|source| {
                        logical_artifact_for_basename(&source.basename) == Some(logical_id)
                    })
            })
            .map(|evidence| evidence.reference.clone())
            .collect();
    }
    cited.sort_by_key(reference_identity);
    cited.dedup();

    let (class, severity, confidence, title, summary) = if state == SccmClientHealthHopState::Failed
    {
        (
            SccmFindingClass::ConfirmedFailure,
            Severity::Error,
            SccmConfidence::High,
            format!(
                "Client health {} recorded a terminal failure",
                phase.display_name()
            ),
            format!(
                "Admitted client evidence recorded a terminal failure at the {} phase.",
                phase.display_name()
            ),
        )
    } else if !coverage_gaps.is_empty() {
        (
            SccmFindingClass::InsufficientEvidence,
            Severity::Warning,
            SccmConfidence::Low,
            format!(
                "Client health {} evidence is incomplete",
                phase.display_name()
            ),
            format!(
                "The {} phase cannot be evaluated because its exact source coverage is incomplete.",
                phase.display_name()
            ),
        )
    } else {
        (
            SccmFindingClass::Symptom,
            Severity::Warning,
            SccmConfidence::Low,
            format!("Client health {} outcome is not confirmed", phase.display_name()),
            format!(
                "The admitted {} source does not contain one unambiguous terminal outcome for the exact chain key.",
                phase.display_name()
            ),
        )
    };

    let terminal_evidence = if state == SccmClientHealthHopState::Failed {
        facts
            .iter()
            .map(|fact| SccmTerminalEvidence::observed_failure(fact.reference.clone()))
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let finding =
        SccmFindingBuilder::new(format!("client-health-{}-stop", phase.serialized_name()))
            .class(class)
            .phase(SccmPhase::Unknown(phase.serialized_name().to_owned()))
            .role(SccmRole::Client)
            .severity(severity)
            .confidence(confidence)
            .title(title)
            .summary(summary)
            .evidence(cited)
            .terminal_evidence(terminal_evidence)
            .coverage_gaps(coverage_gaps)
            .next_artifact(request_for_phase(phase))
            .build()
            .map_err(SccmClientHealthAnalysisError::FindingContract)?;

    Ok(SccmClientHealthFinding {
        finding,
        health_phase: phase,
        last_confirmed_successful_phase: last_success,
    })
}

fn admitted_health_keys(
    admitted: &SccmClientAdmittedEvidence,
    evidence: &[SccmEvidence],
    sources: &BTreeMap<String, SccmClientAdmittedSourceArtifact>,
) -> Result<BTreeMap<EvidenceIdentity, FactKeys>, SccmClientHealthAnalysisError> {
    let evidence_ids = evidence
        .iter()
        .map(|item| reference_identity(&item.reference))
        .collect::<BTreeSet<_>>();
    let mut by_reference = BTreeMap::<_, FactKeys>::new();
    for (artifact_id, source) in sources {
        if !source_is_complete(source) || logical_artifact_for_basename(&source.basename).is_none()
        {
            continue;
        }
        let extraction = admitted.extract_keys_for_artifact(artifact_id)?;
        if extraction.artifact_id() != artifact_id {
            return Err(SccmClientEvidenceAdmissionError::IntegrityViolation.into());
        }
        if artifact_family_for_basename(&source.basename)
            .is_none_or(|family| extraction.artifact_family() != &family)
        {
            return Err(SccmClientEvidenceAdmissionError::IntegrityViolation.into());
        }
        for result in extraction.results() {
            for key in &result.keys {
                let Some(reference) = key.evidence.as_ref() else {
                    continue;
                };
                let identity = reference_identity(reference);
                if !evidence_ids.contains(&identity) {
                    return Err(SccmClientEvidenceAdmissionError::IntegrityViolation.into());
                }
                apply_key(by_reference.entry(identity).or_default(), key);
            }
        }
    }
    Ok(by_reference)
}

fn apply_key(keys: &mut FactKeys, key: &SccmCorrelationKey) {
    let target = match key.kind {
        SccmCorrelationKeyKind::ClientGuid => &mut keys.client_guid,
        SccmCorrelationKeyKind::SiteCode => &mut keys.site_code,
        SccmCorrelationKeyKind::ServerHost => &mut keys.management_point_host,
        SccmCorrelationKeyKind::RequestId => &mut keys.request_id,
        _ => return,
    };
    if target.is_none() {
        *target = Some(key.normalized.clone());
    }
}

fn parse_fact(
    evidence: &SccmEvidence,
    source: &SccmClientAdmittedSourceArtifact,
    keys: FactKeys,
) -> Option<HealthFact> {
    if !source_is_complete(source) {
        return None;
    }
    let fields = parse_unique_fields(&evidence.message)?;
    if !fields
        .get("family")
        .is_some_and(|value| value.eq_ignore_ascii_case("health"))
    {
        return None;
    }
    let phase = fields.get("phase").and_then(|value| parse_phase(value))?;
    if !source_allows_phase(&source.basename, phase) || !required_keys_present(phase, &keys) {
        return None;
    }
    let disposition = fields
        .get("disposition")
        .and_then(|value| parse_disposition(value))?;
    let terminal = fields
        .get("terminal")
        .is_some_and(|value| value.eq_ignore_ascii_case("true"));
    if matches!(disposition, Disposition::Succeeded | Disposition::Failed) != terminal {
        return None;
    }
    Some(HealthFact {
        phase,
        disposition,
        terminal,
        keys,
        reference: evidence.reference.clone(),
        utc_millis: evidence.timestamp.utc_millis?,
    })
}

fn parse_unique_fields(message: &str) -> Option<BTreeMap<String, String>> {
    let mut fields = BTreeMap::new();
    for token in message.split_whitespace() {
        let Some((label, value)) = token.split_once('=') else {
            continue;
        };
        if value.is_empty()
            || fields
                .insert(label.to_ascii_lowercase(), value.to_owned())
                .is_some()
        {
            return None;
        }
    }
    Some(fields)
}

fn lifecycle_resolution(facts: &[HealthFact]) -> Resolution<'_> {
    let lifecycle = facts
        .iter()
        .filter(|fact| fact.phase.is_lifecycle())
        .collect::<Vec<_>>();
    resolve_candidates(lifecycle, None, false)
}

fn lifecycle_phase(resolution: &Resolution<'_>) -> Option<SccmClientHealthPhase> {
    match resolution {
        Resolution::Succeeded(fact) | Resolution::Failed(fact) => Some(fact.phase),
        Resolution::Pending(facts) | Resolution::Contradictory(facts) => {
            facts.first().map(|fact| fact.phase)
        }
        Resolution::Missing => None,
    }
}

fn resolve_phase<'a>(
    facts: &'a [HealthFact],
    phase: SccmClientHealthPhase,
    chain: &ChainKeys,
) -> Resolution<'a> {
    let candidates = facts
        .iter()
        .filter(|fact| fact.phase == phase && fact_matches_chain(fact, chain))
        .collect::<Vec<_>>();
    resolve_candidates(
        candidates,
        Some(phase),
        phase == SccmClientHealthPhase::Transport,
    )
}

fn resolve_candidates<'a>(
    candidates: Vec<&'a HealthFact>,
    phase: Option<SccmClientHealthPhase>,
    transport: bool,
) -> Resolution<'a> {
    if candidates.is_empty() {
        return Resolution::Missing;
    }
    if phase.is_none()
        && candidates
            .iter()
            .filter_map(|fact| fact.keys.client_guid.as_deref())
            .collect::<BTreeSet<_>>()
            .len()
            != 1
    {
        return Resolution::Contradictory(candidates);
    }
    let newest_utc_millis = candidates
        .iter()
        .map(|fact| fact.utc_millis)
        .max()
        .expect("candidate set is nonempty");
    let newest = candidates
        .iter()
        .copied()
        .filter(|fact| fact.utc_millis == newest_utc_millis)
        .collect::<Vec<_>>();
    if phase.is_none()
        && newest
            .iter()
            .map(|fact| fact.phase)
            .collect::<BTreeSet<_>>()
            .len()
            != 1
    {
        return Resolution::Contradictory(newest);
    }
    let newest_phase = phase.unwrap_or(newest[0].phase);
    if newest
        .iter()
        .any(|fact| !same_phase_correlation_tuple(newest[0], fact, newest_phase))
    {
        return Resolution::Contradictory(newest);
    }
    let newest_disposition = newest[0].disposition;
    if newest
        .iter()
        .any(|fact| fact.disposition != newest_disposition)
    {
        return Resolution::Contradictory(newest);
    }
    let last = *newest
        .iter()
        .max_by_key(|fact| reference_identity(&fact.reference))
        .expect("newest candidate set is nonempty");
    if !last.terminal {
        return Resolution::Pending(newest);
    }
    if transport {
        let started = candidates.iter().any(|fact| {
            fact.disposition == Disposition::Started
                && fact.utc_millis < last.utc_millis
                && fact.keys.request_id == last.keys.request_id
                && fact.keys.management_point_host == last.keys.management_point_host
        });
        if !started {
            return Resolution::Pending(candidates);
        }
    }
    match last.disposition {
        Disposition::Succeeded => Resolution::Succeeded(last),
        Disposition::Failed => Resolution::Failed(last),
        Disposition::Started | Disposition::Pending => Resolution::Pending(candidates),
    }
}

fn same_phase_correlation_tuple(
    left: &HealthFact,
    right: &HealthFact,
    phase: SccmClientHealthPhase,
) -> bool {
    match phase {
        phase if phase.is_lifecycle() => left.keys.client_guid == right.keys.client_guid,
        SccmClientHealthPhase::Service
        | SccmClientHealthPhase::ClientHealth
        | SccmClientHealthPhase::Reboot
        | SccmClientHealthPhase::Identity
        | SccmClientHealthPhase::Authentication => left.keys.client_guid == right.keys.client_guid,
        SccmClientHealthPhase::Assignment | SccmClientHealthPhase::Boundary => {
            left.keys.client_guid == right.keys.client_guid
                && left.keys.site_code == right.keys.site_code
        }
        SccmClientHealthPhase::ManagementPointLocation => {
            left.keys.site_code == right.keys.site_code
                && left.keys.management_point_host == right.keys.management_point_host
        }
        SccmClientHealthPhase::Transport => {
            left.keys.management_point_host == right.keys.management_point_host
                && left.keys.request_id == right.keys.request_id
        }
        _ => false,
    }
}

fn fact_matches_chain(fact: &HealthFact, chain: &ChainKeys) -> bool {
    if chain
        .last_utc_millis
        .is_some_and(|last_utc_millis| fact.utc_millis <= last_utc_millis)
    {
        return false;
    }
    match fact.phase {
        SccmClientHealthPhase::Service
        | SccmClientHealthPhase::ClientHealth
        | SccmClientHealthPhase::Reboot
        | SccmClientHealthPhase::Identity
        | SccmClientHealthPhase::Authentication
        | SccmClientHealthPhase::Assignment
        | SccmClientHealthPhase::Boundary => fact.keys.client_guid == chain.client_guid,
        SccmClientHealthPhase::ManagementPointLocation => {
            fact.keys.site_code == chain.site_code && optional_client_matches(fact, chain)
        }
        SccmClientHealthPhase::Transport => {
            fact.keys.management_point_host == chain.management_point_host
                && optional_client_matches(fact, chain)
        }
        phase if phase.is_lifecycle() => true,
        _ => false,
    }
}

fn optional_client_matches(fact: &HealthFact, chain: &ChainKeys) -> bool {
    fact.keys
        .client_guid
        .as_ref()
        .is_none_or(|client_guid| Some(client_guid) == chain.client_guid.as_ref())
}

fn advance_chain(chain: &mut ChainKeys, fact: &HealthFact) {
    if fact.keys.client_guid.is_some() {
        chain.client_guid = fact.keys.client_guid.clone();
    }
    if fact.keys.site_code.is_some() {
        chain.site_code = fact.keys.site_code.clone();
    }
    if fact.keys.management_point_host.is_some() {
        chain.management_point_host = fact.keys.management_point_host.clone();
    }
    chain.last_utc_millis = Some(fact.utc_millis);
}

fn required_keys_present(phase: SccmClientHealthPhase, keys: &FactKeys) -> bool {
    match phase {
        phase if phase.is_lifecycle() => keys.client_guid.is_some(),
        SccmClientHealthPhase::Service
        | SccmClientHealthPhase::ClientHealth
        | SccmClientHealthPhase::Reboot
        | SccmClientHealthPhase::Identity
        | SccmClientHealthPhase::Authentication => keys.client_guid.is_some(),
        SccmClientHealthPhase::Assignment | SccmClientHealthPhase::Boundary => {
            keys.client_guid.is_some() && keys.site_code.is_some()
        }
        SccmClientHealthPhase::ManagementPointLocation => {
            keys.site_code.is_some() && keys.management_point_host.is_some()
        }
        SccmClientHealthPhase::Transport => {
            keys.management_point_host.is_some() && keys.request_id.is_some()
        }
        _ => false,
    }
}

fn health_source_coverage(
    sources: &BTreeMap<String, SccmClientAdmittedSourceArtifact>,
) -> Vec<SccmClientHealthSourceCoverage> {
    sources
        .iter()
        .filter_map(|(artifact_id, source)| {
            Some(SccmClientHealthSourceCoverage {
                artifact_id: artifact_id.clone(),
                logical_artifact_id: logical_artifact_for_basename(&source.basename)?.to_owned(),
                coverage: source.coverage.clone(),
                rotation: source.rotation.clone(),
                fragment_complete: source.fragment_complete == Some(true),
                physical: source.physical,
            })
        })
        .collect()
}

fn source_is_complete(source: &SccmClientAdmittedSourceArtifact) -> bool {
    source.coverage == SccmCoverageState::Captured
        && source.fragment_complete == Some(true)
        && source.physical
}

fn source_allows_phase(basename: &str, phase: SccmClientHealthPhase) -> bool {
    match canonical_basename(basename) {
        "ccmsetup.log" | "client.msi.log" => phase.is_lifecycle(),
        "CcmEval.log" | "CcmExec.log" => matches!(
            phase,
            SccmClientHealthPhase::Service
                | SccmClientHealthPhase::ClientHealth
                | SccmClientHealthPhase::Reboot
        ),
        "CcmRestart.log" => phase == SccmClientHealthPhase::Reboot,
        "ClientIDManagerStartup.log" => matches!(
            phase,
            SccmClientHealthPhase::Identity | SccmClientHealthPhase::Authentication
        ),
        "LocationServices.log" | "ClientLocation.log" => matches!(
            phase,
            SccmClientHealthPhase::Assignment
                | SccmClientHealthPhase::Boundary
                | SccmClientHealthPhase::ManagementPointLocation
                | SccmClientHealthPhase::Transport
        ),
        "CcmMessaging.log" => phase == SccmClientHealthPhase::Transport,
        _ => false,
    }
}

fn logical_artifact_for_basename(basename: &str) -> Option<&'static str> {
    match canonical_basename(basename) {
        "ccmsetup.log" | "client.msi.log" => Some("client-ccmsetup"),
        "CcmEval.log" | "CcmExec.log" | "CcmRestart.log" => Some("client-evaluation"),
        "ClientIDManagerStartup.log" => Some("client-identity"),
        "LocationServices.log" | "ClientLocation.log" | "CcmMessaging.log" => {
            Some("client-location")
        }
        _ => None,
    }
}

fn artifact_family_for_basename(basename: &str) -> Option<SccmArtifactFamily> {
    match canonical_basename(basename) {
        "ccmsetup.log" | "client.msi.log" => Some(SccmArtifactFamily::ClientSetup),
        "CcmEval.log" | "CcmExec.log" | "CcmRestart.log" => Some(SccmArtifactFamily::ClientHealth),
        "ClientIDManagerStartup.log" => Some(SccmArtifactFamily::ClientIdentity),
        "LocationServices.log" | "ClientLocation.log" | "CcmMessaging.log" => {
            Some(SccmArtifactFamily::ClientLocation)
        }
        _ => None,
    }
}

fn canonical_basename(basename: &str) -> &str {
    match basename {
        "ccmsetup.lo_" => "ccmsetup.log",
        "client.msi.lo_" => "client.msi.log",
        "CcmEval.lo_" => "CcmEval.log",
        "CcmExec.lo_" => "CcmExec.log",
        "CcmRestart.lo_" => "CcmRestart.log",
        "ClientIDManagerStartup.lo_" => "ClientIDManagerStartup.log",
        "LocationServices.lo_" => "LocationServices.log",
        "ClientLocation.lo_" => "ClientLocation.log",
        "CcmMessaging.lo_" => "CcmMessaging.log",
        other => other,
    }
}

fn logical_artifact_for_phase(phase: SccmClientHealthPhase) -> &'static str {
    match phase {
        phase if phase.is_lifecycle() => "client-ccmsetup",
        SccmClientHealthPhase::Service
        | SccmClientHealthPhase::ClientHealth
        | SccmClientHealthPhase::Reboot => "client-evaluation",
        SccmClientHealthPhase::Identity | SccmClientHealthPhase::Authentication => {
            "client-identity"
        }
        SccmClientHealthPhase::Assignment
        | SccmClientHealthPhase::Boundary
        | SccmClientHealthPhase::ManagementPointLocation
        | SccmClientHealthPhase::Transport => "client-location",
        _ => unreachable!("all health phases are mapped"),
    }
}

fn request_for_phase(phase: SccmClientHealthPhase) -> SccmArtifactRequest {
    let (logical_id, basename) = match logical_artifact_for_phase(phase) {
        "client-ccmsetup" => ("ccmSetup", "ccmsetup"),
        "client-evaluation" => ("ccmEval", "CcmEval"),
        "client-identity" => ("clientIdManagerStartup", "ClientIDManagerStartup"),
        "client-location" => ("locationServices", "LocationServices"),
        _ => unreachable!("health request mapping is closed"),
    };
    SccmArtifactRequest {
        logical_id: logical_id.to_owned(),
        role: SccmRole::Client,
        reason: format!("Confirm the root cause recorded by {basename}."),
    }
}

fn hop<'a>(
    phase: SccmClientHealthPhase,
    state: SccmClientHealthHopState,
    facts: impl IntoIterator<Item = &'a HealthFact>,
) -> SccmClientHealthHop {
    let mut evidence = facts
        .into_iter()
        .map(|fact| fact.reference.clone())
        .collect::<Vec<_>>();
    evidence.sort_by_key(reference_identity);
    evidence.dedup();
    SccmClientHealthHop {
        phase,
        state,
        evidence,
    }
}

fn reference_identity(reference: &SccmEvidenceRef) -> EvidenceIdentity {
    (
        reference.artifact_id.clone(),
        reference.entry_id.clone(),
        reference.line_start,
        reference.line_end,
    )
}

fn parse_phase(value: &str) -> Option<SccmClientHealthPhase> {
    match value.to_ascii_lowercase().as_str() {
        "install" => Some(SccmClientHealthPhase::Install),
        "upgrade" => Some(SccmClientHealthPhase::Upgrade),
        "repair" => Some(SccmClientHealthPhase::Repair),
        "removal" => Some(SccmClientHealthPhase::Removal),
        "service" => Some(SccmClientHealthPhase::Service),
        "clienthealth" => Some(SccmClientHealthPhase::ClientHealth),
        "reboot" => Some(SccmClientHealthPhase::Reboot),
        "identityregistration" => Some(SccmClientHealthPhase::Identity),
        "authentication" => Some(SccmClientHealthPhase::Authentication),
        "assignment" => Some(SccmClientHealthPhase::Assignment),
        "boundary" => Some(SccmClientHealthPhase::Boundary),
        "managementpointlocation" => Some(SccmClientHealthPhase::ManagementPointLocation),
        "transport" => Some(SccmClientHealthPhase::Transport),
        _ => None,
    }
}

fn parse_disposition(value: &str) -> Option<Disposition> {
    match value.to_ascii_lowercase().as_str() {
        "started" => Some(Disposition::Started),
        "succeeded" => Some(Disposition::Succeeded),
        "failed" => Some(Disposition::Failed),
        "pending" | "deferred" => Some(Disposition::Pending),
        _ => None,
    }
}

fn ordered_post_lifecycle_phases() -> [SccmClientHealthPhase; 9] {
    [
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
}

impl SccmClientHealthPhase {
    fn is_lifecycle(self) -> bool {
        matches!(
            self,
            Self::Install | Self::Upgrade | Self::Repair | Self::Removal
        )
    }

    fn serialized_name(self) -> &'static str {
        match self {
            Self::Install => "install",
            Self::Upgrade => "upgrade",
            Self::Repair => "repair",
            Self::Removal => "removal",
            Self::Service => "service",
            Self::ClientHealth => "clientHealth",
            Self::Reboot => "reboot",
            Self::Identity => "identityRegistration",
            Self::Authentication => "authentication",
            Self::Assignment => "assignment",
            Self::Boundary => "boundary",
            Self::ManagementPointLocation => "managementPointLocation",
            Self::Transport => "transport",
        }
    }

    fn display_name(self) -> &'static str {
        match self {
            Self::Install => "install",
            Self::Upgrade => "upgrade",
            Self::Repair => "repair",
            Self::Removal => "removal",
            Self::Service => "service",
            Self::ClientHealth => "client health",
            Self::Reboot => "reboot",
            Self::Identity => "identity registration",
            Self::Authentication => "authentication",
            Self::Assignment => "assignment",
            Self::Boundary => "boundary",
            Self::ManagementPointLocation => "management point location",
            Self::Transport => "transport",
        }
    }
}

fn prohibited_claims() -> Vec<String> {
    vec![
        "server root cause".to_owned(),
        "isolated error proves terminal failure".to_owned(),
        "missing source proves workflow failure".to_owned(),
        "host path or raw sensitive text export".to_owned(),
    ]
}
