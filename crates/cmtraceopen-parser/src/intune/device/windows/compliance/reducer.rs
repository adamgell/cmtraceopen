//! Reduce classified compliance observations into an immutable snapshot.
//!
//! The reduction runs strictly phase by phase and never lets a later phase
//! rewrite an earlier one:
//!
//! 1. **local** — merge setting observations by grouping token;
//! 2. **aggregate** — fold the local settings into one device result;
//! 3. **reporting** — record submission state and compare service records
//!    against the *timestamp* of the local evaluation, not against its verdict;
//! 4. **access** — attach downstream decisions, correlated only on explicit
//!    identity plus explicit time provenance.
//!
//! Findings are derived last, from the finished snapshot, so no rule can see a
//! half-built state.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};

use super::models::*;
use super::rules::derive_findings;
use super::sources::{
    classify_event, classify_setting_report, decode_bundle, ComplianceSignal,
    ComplianceSourceInput, SettingObservation,
};
use crate::intune::evidence::{IntuneEvidenceRef, IntuneTimestamp, IntuneTimestampKind};

/// Decode a supplied evidence bundle and reduce it in one call.
pub fn analyze_compliance_bundle(
    sources: &[ComplianceSourceInput],
    generated_at_utc: &str,
) -> ComplianceSnapshot {
    analyze_compliance(&decode_bundle(sources, generated_at_utc))
}

/// Reduce already-decoded compliance facts into a snapshot.
pub fn analyze_compliance(input: &ComplianceInput) -> ComplianceSnapshot {
    let generated_at = parse_rfc3339(&input.generated_at_utc);

    let device_context = reduce_device_context(input);
    let local = reduce_local(input, generated_at);
    let aggregate = reduce_aggregate(&local);
    let reporting = reduce_reporting(input, &local, &aggregate, generated_at);
    let access_impact = reduce_access(input, &reporting);

    let mut snapshot = ComplianceSnapshot {
        schema_version: INTUNE_COMPLIANCE_SCHEMA_VERSION,
        generated_at_utc: input.generated_at_utc.clone(),
        device_context,
        local_evaluation: local,
        aggregate,
        reporting,
        access_impact,
        coverage: input.coverage.clone(),
        findings: Vec::new(),
    };
    snapshot.findings = derive_findings(&snapshot);
    snapshot
}

// ── Device context ──────────────────────────────────────────────────────────

fn reduce_device_context(input: &ComplianceInput) -> ComplianceDeviceContextView {
    let Some(fact) = input.device_context.as_ref() else {
        return ComplianceDeviceContextView::default();
    };

    // A user key alone does not prove a user session was available for
    // evaluation; only the explicit flag does. Inferring presence from the key
    // would make an unevaluated user-scoped setting look like a failure.
    let user_evaluation_context = match fact.user_session_present {
        Some(true) => ComplianceUserContext::UserPresent,
        Some(false) => ComplianceUserContext::NoUserSession,
        None => ComplianceUserContext::Unknown,
    };

    ComplianceDeviceContextView {
        device_key: fact.device_key.clone(),
        tenant_key: fact.tenant_key.clone(),
        enrollment_id: fact.enrollment_id.clone(),
        windows_build: fact.windows_build.clone(),
        active_user_key: fact.active_user_key.clone(),
        user_evaluation_context,
        evidence: vec![fact.context.evidence_ref.clone()],
    }
}

// ── Phase 1: local evaluation ───────────────────────────────────────────────

fn reduce_local(
    input: &ComplianceInput,
    generated_at: Option<DateTime<Utc>>,
) -> ComplianceLocalPhase {
    let mut phase = ComplianceLocalPhase::default();
    let mut grouped: BTreeMap<String, Vec<SettingObservation>> = BTreeMap::new();
    let mut policies: BTreeMap<String, CompliancePolicyObservation> = BTreeMap::new();
    let mut prerequisites: BTreeMap<String, CompliancePrerequisite> = BTreeMap::new();
    let mut evidence = Vec::new();

    for event in &input.events {
        evidence.push(event.context.evidence_ref.clone());
        let reference = event.context.evidence_ref.clone();
        match classify_event(event) {
            Some(ComplianceSignal::SettingEvaluation(observation)) => {
                grouped
                    .entry(observation.grouping_token.clone())
                    .or_default()
                    .push(*observation);
            }
            Some(ComplianceSignal::Prerequisite {
                name,
                state,
                detail,
            }) => {
                let entry =
                    prerequisites
                        .entry(name.clone())
                        .or_insert_with(|| CompliancePrerequisite {
                            name,
                            state,
                            detail: detail.clone(),
                            evidence: Vec::new(),
                        });
                // An unmet prerequisite outranks a met one: the device saying
                // "blocked" at any point is the fact worth surfacing.
                if state == CompliancePrerequisiteState::Unmet {
                    entry.state = state;
                    entry.detail = detail;
                }
                entry.evidence.push(reference);
            }
            Some(ComplianceSignal::PolicyState {
                policy_id,
                state,
                scope,
            }) => {
                let entry = policies.entry(policy_id.clone()).or_insert_with(|| {
                    CompliancePolicyObservation {
                        policy_id,
                        state,
                        scope,
                        evidence: Vec::new(),
                    }
                });
                entry.evidence.push(reference);
            }
            // Reporting signals belong to phase 3.
            Some(ComplianceSignal::ReportSubmission { .. }) => {}
            // The record was supplied as compliance evidence but names no
            // setting, policy, prerequisite, or report status. It is recorded as
            // unattributed coverage rather than dropped, so a bundle that
            // produced no result can be told apart from one that was never read.
            None => phase.unkeyed_observations.push(reference),
        }
    }

    for report in &input.setting_reports {
        evidence.push(report.context.evidence_ref.clone());
        match classify_setting_report(report) {
            Some(observation) => grouped
                .entry(observation.grouping_token.clone())
                .or_default()
                .push(observation),
            None => phase
                .unkeyed_observations
                .push(report.context.evidence_ref.clone()),
        }
    }

    phase.settings = grouped
        .into_iter()
        .map(|(token, observations)| merge_setting(token, observations, generated_at))
        .collect();
    phase.policies = policies.into_values().collect();
    phase.prerequisites = prerequisites.into_values().collect();
    for policy in &mut phase.policies {
        normalize_evidence(&mut policy.evidence);
    }
    for prerequisite in &mut phase.prerequisites {
        normalize_evidence(&mut prerequisite.evidence);
    }

    phase.custom_compliance = input
        .custom_compliance
        .iter()
        .map(|fact| {
            evidence.push(fact.context.evidence_ref.clone());
            ComplianceCustomEvaluation {
                policy_id: fact.policy_id.clone(),
                run_id: fact.run_id.clone(),
                setting_name: fact.setting_name.clone(),
                state: fact.outcome,
                error: fact.error.clone(),
                raw_output: fact.raw_output.clone(),
                evidence: vec![fact.context.evidence_ref.clone()],
                named_data: fact.named_data.clone(),
            }
        })
        .collect();

    phase.latest_evaluation_at_utc = latest_evaluation(&phase.settings).map(format_utc);
    normalize_evidence(&mut phase.unkeyed_observations);
    normalize_evidence(&mut evidence);
    phase.evidence = evidence;
    phase
}

/// Fold every observation that shares a grouping token into one evaluation.
///
/// Two *definite* states that disagree produce
/// [`ComplianceSettingState::Contradictory`] rather than an arbitrary winner.
/// Preferring the newest would silently pick a side in exactly the case where
/// the evidence does not support picking one.
fn merge_setting(
    grouping_token: String,
    observations: Vec<SettingObservation>,
    generated_at: Option<DateTime<Utc>>,
) -> ComplianceSettingEvaluation {
    let mut key = ComplianceSettingKey::default();
    let mut scope = ComplianceScope::Unknown;
    let mut display_name = None;
    let mut error = None;
    let mut evaluated_at: Option<IntuneTimestamp> = None;
    let mut evidence = Vec::new();
    let mut named_data = Vec::new();
    let mut definite = Vec::new();
    let mut indefinite = Vec::new();
    let mut time_contradiction = false;
    let mut identity_contradiction = false;

    for observation in observations {
        identity_contradiction |= conflicts(&key.policy_id, &observation.key.policy_id)
            || conflicts(&key.setting_id, &observation.key.setting_id)
            || conflicts(&key.setting_uri, &observation.key.setting_uri);
        key.policy_id = key.policy_id.or(observation.key.policy_id);
        key.setting_id = key.setting_id.or(observation.key.setting_id);
        key.setting_uri = key.setting_uri.or(observation.key.setting_uri);
        if scope == ComplianceScope::Unknown {
            scope = observation.scope;
        }
        display_name = display_name.or(observation.display_name);
        error = error.or(observation.error);

        if observation.state.is_definite() {
            definite.push(observation.state);
        } else {
            indefinite.push(observation.state);
        }

        if let Some(timestamp) = observation.evaluated_at {
            if let (Some(candidate), Some(generated_at)) =
                (normalized_timestamp(&timestamp), generated_at)
            {
                if candidate > generated_at {
                    time_contradiction = true;
                }
            }
            evaluated_at = Some(match evaluated_at {
                Some(existing) if is_newer(&existing, &timestamp) => existing,
                _ => timestamp,
            });
        }

        evidence.push(observation.context.evidence_ref);
        named_data.extend(observation.named_data);
    }

    definite.sort();
    definite.dedup();
    let state = match definite.len() {
        1 => definite[0],
        0 => most_informative_indefinite(&indefinite),
        _ => ComplianceSettingState::Contradictory,
    };

    normalize_evidence(&mut evidence);
    named_data.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| left.value.cmp(&right.value))
    });
    named_data.dedup();

    ComplianceSettingEvaluation {
        key,
        grouping_token,
        scope,
        state,
        display_name,
        error,
        evaluated_at,
        observed_states: definite,
        time_contradiction,
        identity_contradiction,
        evidence,
        named_data,
    }
}

/// Whether two sources declare different non-empty values for one identifier.
fn conflicts(existing: &Option<String>, candidate: &Option<String>) -> bool {
    let usable = |value: &Option<String>| {
        value
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_ascii_lowercase)
    };
    match (usable(existing), usable(candidate)) {
        (Some(existing), Some(candidate)) => existing != candidate,
        _ => false,
    }
}

/// Rank the non-definite states so a merge keeps the most informative one.
fn most_informative_indefinite(states: &[ComplianceSettingState]) -> ComplianceSettingState {
    let rank = |state: &ComplianceSettingState| match state {
        ComplianceSettingState::PrerequisiteUnmet => 4,
        ComplianceSettingState::Contradictory => 3,
        ComplianceSettingState::NotEvaluated => 2,
        ComplianceSettingState::InsufficientEvidence => 1,
        _ => 0,
    };
    states
        .iter()
        .max_by_key(|state| rank(state))
        .copied()
        .unwrap_or(ComplianceSettingState::InsufficientEvidence)
}

fn is_newer(left: &IntuneTimestamp, right: &IntuneTimestamp) -> bool {
    match (normalized_timestamp(left), normalized_timestamp(right)) {
        (Some(left), Some(right)) => left > right,
        (Some(_), None) => true,
        _ => false,
    }
}

fn latest_evaluation(settings: &[ComplianceSettingEvaluation]) -> Option<DateTime<Utc>> {
    settings
        .iter()
        .filter_map(|setting| setting.evaluated_at.as_ref())
        .filter_map(normalized_timestamp)
        .max()
}

// ── Phase 2: aggregate ──────────────────────────────────────────────────────

/// Fold local settings and custom-compliance results into one device result.
///
/// Precedence is by severity of claim, and a custom-compliance *script failure*
/// is folded in as an error, never as a noncompliance: a script that did not run
/// produced no verdict to aggregate.
fn reduce_aggregate(local: &ComplianceLocalPhase) -> ComplianceAggregatePhase {
    let mut phase = ComplianceAggregatePhase::default();

    for setting in &local.settings {
        match setting.state {
            ComplianceSettingState::Compliant => phase.compliant_count += 1,
            ComplianceSettingState::Noncompliant => phase.noncompliant_count += 1,
            ComplianceSettingState::EvaluationError => phase.error_count += 1,
            ComplianceSettingState::NotApplicable => phase.not_applicable_count += 1,
            ComplianceSettingState::NotEvaluated
            | ComplianceSettingState::PrerequisiteUnmet
            | ComplianceSettingState::InsufficientEvidence => phase.not_evaluated_count += 1,
            ComplianceSettingState::Contradictory => phase.contradictory_count += 1,
        }
    }

    let custom_noncompliant = local
        .custom_compliance
        .iter()
        .filter(|custom| custom.state == ComplianceCustomState::DiscoveryNoncompliant)
        .collect::<Vec<_>>();
    let custom_failed = local
        .custom_compliance
        .iter()
        .filter(|custom| {
            matches!(
                custom.state,
                ComplianceCustomState::ScriptFailed | ComplianceCustomState::OutputInvalid
            )
        })
        .collect::<Vec<_>>();

    let has_local_source = !local.settings.is_empty() || !local.custom_compliance.is_empty();

    let (state, rationale, evidence) = if phase.noncompliant_count > 0 {
        (
            ComplianceAggregateState::Noncompliant,
            ComplianceAggregateRationale::LocalSettingNoncompliant,
            evidence_for(local, ComplianceSettingState::Noncompliant),
        )
    } else if !custom_noncompliant.is_empty() {
        (
            ComplianceAggregateState::Noncompliant,
            ComplianceAggregateRationale::CustomComplianceDiscoveryNoncompliant,
            collect_evidence(custom_noncompliant.iter().flat_map(|c| c.evidence.iter())),
        )
    } else if phase.error_count > 0 {
        (
            ComplianceAggregateState::EvaluationError,
            ComplianceAggregateRationale::LocalEvaluationError,
            evidence_for(local, ComplianceSettingState::EvaluationError),
        )
    } else if !custom_failed.is_empty() {
        (
            ComplianceAggregateState::EvaluationError,
            ComplianceAggregateRationale::CustomComplianceScriptFailed,
            collect_evidence(custom_failed.iter().flat_map(|c| c.evidence.iter())),
        )
    } else if phase.contradictory_count > 0 {
        (
            ComplianceAggregateState::InsufficientEvidence,
            ComplianceAggregateRationale::ContradictoryLocalEvidence,
            evidence_for(local, ComplianceSettingState::Contradictory),
        )
    } else if phase.compliant_count > 0 {
        (
            ComplianceAggregateState::Compliant,
            ComplianceAggregateRationale::AllEvaluatedSettingsCompliant,
            evidence_for(local, ComplianceSettingState::Compliant),
        )
    } else if has_local_source {
        (
            ComplianceAggregateState::NotEvaluated,
            ComplianceAggregateRationale::NoSettingEvaluated,
            collect_evidence(local.settings.iter().flat_map(|s| s.evidence.iter())),
        )
    } else {
        (
            ComplianceAggregateState::InsufficientEvidence,
            ComplianceAggregateRationale::NoLocalSourceAvailable,
            Vec::new(),
        )
    };

    phase.state = state;
    phase.rationale = rationale;
    phase.evidence = evidence;
    phase
}

fn evidence_for(
    local: &ComplianceLocalPhase,
    state: ComplianceSettingState,
) -> Vec<IntuneEvidenceRef> {
    collect_evidence(
        local
            .settings
            .iter()
            .filter(|setting| setting.state == state)
            .flat_map(|setting| setting.evidence.iter()),
    )
}

// ── Phase 3: reporting and service state ────────────────────────────────────

fn reduce_reporting(
    input: &ComplianceInput,
    local: &ComplianceLocalPhase,
    aggregate: &ComplianceAggregatePhase,
    generated_at: Option<DateTime<Utc>>,
) -> ComplianceReportingPhase {
    let mut phase = ComplianceReportingPhase::default();
    let mut evidence = Vec::new();
    let latest_local = local
        .latest_evaluation_at_utc
        .as_deref()
        .and_then(parse_rfc3339);

    for event in &input.events {
        let Some(ComplianceSignal::ReportSubmission {
            state,
            report_id,
            error,
            submitted_at,
        }) = classify_event(event)
        else {
            continue;
        };
        evidence.push(event.context.evidence_ref.clone());
        // A submission is the terminal outcome: once the bundle shows the report
        // went out, a later queued or failed row cannot take that back. A failure
        // still outranks queued, because a later "queued" does not undo an
        // observed submission failure.
        match state {
            ComplianceReportState::Submitted => phase.state = state,
            ComplianceReportState::Failed => {
                if phase.state != ComplianceReportState::Submitted {
                    phase.state = state;
                }
            }
            _ => {
                if !matches!(
                    phase.state,
                    ComplianceReportState::Submitted | ComplianceReportState::Failed
                ) {
                    phase.state = state;
                }
            }
        }
        phase.report_id = phase.report_id.or(report_id);
        phase.error = phase.error.or(error);
        if state == ComplianceReportState::Submitted {
            phase.last_submission_at = submitted_at;
        }
    }

    // A submission that predates the most recent local evaluation cannot carry
    // that evaluation's result, whatever the submission itself reported.
    if phase.state == ComplianceReportState::Submitted {
        if let (Some(submitted), Some(latest_local)) = (
            phase
                .last_submission_at
                .as_ref()
                .and_then(normalized_timestamp),
            latest_local,
        ) {
            if submitted < latest_local {
                phase.state = ComplianceReportState::Stale;
            }
        }
    }

    phase.service_results = input
        .service_results
        .iter()
        .map(|fact| {
            evidence.push(fact.context.evidence_ref.clone());
            let reported = fact.reported_at.as_ref().and_then(normalized_timestamp);
            let freshness = match (reported, latest_local) {
                (Some(reported), Some(local)) if reported >= local => {
                    ComplianceServiceFreshness::Fresh
                }
                (Some(_), Some(_)) => ComplianceServiceFreshness::Stale,
                _ => ComplianceServiceFreshness::Unknown,
            };
            ComplianceServiceResult {
                policy_id: fact.policy_id.clone(),
                setting_id: fact.setting_id.clone(),
                state: fact.state.clone(),
                reported_at: fact.reported_at.clone(),
                freshness,
                device_key: fact.device_key.clone(),
                user_key: fact.user_key.clone(),
                evidence: vec![fact.context.evidence_ref.clone()],
            }
        })
        .collect();

    phase.service_freshness = fold_freshness(&phase.service_results);
    phase.service_disagrees_with_local = phase
        .service_results
        .iter()
        .any(|result| disagrees(&result.state, aggregate.state));

    // A service record stamped after the snapshot was generated is a provenance
    // contradiction, not a fresher truth; surface it as unknown freshness.
    if let Some(generated_at) = generated_at {
        let future = phase.service_results.iter().any(|result| {
            result
                .reported_at
                .as_ref()
                .and_then(normalized_timestamp)
                .is_some_and(|reported| reported > generated_at)
        });
        if future {
            phase.service_freshness = ComplianceServiceFreshness::Unknown;
        }
    }

    normalize_evidence(&mut evidence);
    phase.evidence = evidence;
    phase
}

fn fold_freshness(results: &[ComplianceServiceResult]) -> ComplianceServiceFreshness {
    if results.is_empty() {
        return ComplianceServiceFreshness::Unknown;
    }
    if results
        .iter()
        .any(|result| result.freshness == ComplianceServiceFreshness::Stale)
    {
        return ComplianceServiceFreshness::Stale;
    }
    if results
        .iter()
        .all(|result| result.freshness == ComplianceServiceFreshness::Fresh)
    {
        return ComplianceServiceFreshness::Fresh;
    }
    ComplianceServiceFreshness::Unknown
}

/// Whether a service-held state contradicts the locally derived aggregate.
///
/// Only the two unambiguous pairings count. An unrecognized service token, a
/// grace period, or an error state is not a disagreement, because we cannot say
/// what it disagrees with.
fn disagrees(service: &ComplianceServiceState, aggregate: ComplianceAggregateState) -> bool {
    matches!(
        (service, aggregate),
        (
            ComplianceServiceState::Noncompliant,
            ComplianceAggregateState::Compliant
        ) | (
            ComplianceServiceState::Compliant,
            ComplianceAggregateState::Noncompliant
        )
    )
}

// ── Phase 4: downstream access ──────────────────────────────────────────────

/// Attach access decisions as downstream impact.
///
/// A decision reaches [`ComplianceAccessLinkage::MatchedComplianceState`] only
/// when a device or user key matches a compliance record *and* both sides carry
/// a normalized timestamp with the compliance record preceding the decision.
/// Everything weaker is explicitly uncorrelated; the rules then refuse to make a
/// causal claim from it.
fn reduce_access(
    input: &ComplianceInput,
    reporting: &ComplianceReportingPhase,
) -> ComplianceAccessPhase {
    let mut phase = ComplianceAccessPhase::default();
    let mut evidence = Vec::new();

    for fact in &input.access_decisions {
        evidence.push(fact.context.evidence_ref.clone());
        let occurred = fact.occurred_at.as_ref().and_then(normalized_timestamp);

        let matched = reporting
            .service_results
            .iter()
            .filter(|result| keys_match(fact, result))
            .filter(|result| {
                match (
                    result.reported_at.as_ref().and_then(normalized_timestamp),
                    occurred,
                ) {
                    (Some(reported), Some(occurred)) => reported <= occurred,
                    // Time-only proximity, or no time at all, cannot correlate.
                    _ => false,
                }
            })
            .collect::<Vec<_>>();

        let identity_declared = fact.device_key.is_some() || fact.user_key.is_some();
        let candidates_exist = !reporting.service_results.is_empty();

        let linkage = if !matched.is_empty() {
            ComplianceAccessLinkage::MatchedComplianceState
        } else if !candidates_exist {
            ComplianceAccessLinkage::NoMatchingComplianceEvidence
        } else if !identity_declared || occurred.is_none() {
            ComplianceAccessLinkage::InsufficientProvenance
        } else if reporting
            .service_results
            .iter()
            .any(|result| keys_match(fact, result))
        {
            // Identity lines up but the times do not; provenance is incomplete.
            ComplianceAccessLinkage::InsufficientProvenance
        } else {
            ComplianceAccessLinkage::IdentityMismatch
        };

        phase.decisions.push(ComplianceAccessObservation {
            decision: fact.decision,
            linkage,
            failure_code: fact.failure_code.clone(),
            occurred_at: fact.occurred_at.clone(),
            device_key: fact.device_key.clone(),
            user_key: fact.user_key.clone(),
            resource: fact.resource.clone(),
            matched_evidence: collect_evidence(matched.iter().flat_map(|r| r.evidence.iter())),
            evidence: vec![fact.context.evidence_ref.clone()],
        });
    }

    normalize_evidence(&mut evidence);
    phase.evidence = evidence;
    phase
}

/// Whether one access decision and one service record name the same subject.
///
/// Every identity the decision declares must match. A decision that names both a
/// device and a user is only about the service record that names both the same
/// way; accepting either half alone would correlate a denial for one user with
/// another user's compliance state on the same device. A decision that declares
/// no identity at all cannot be correlated with anything.
fn keys_match(fact: &ComplianceAccessFact, result: &ComplianceServiceResult) -> bool {
    let same = |left: &Option<String>, right: &Option<String>| match (left, right) {
        (Some(left), Some(right)) => left.eq_ignore_ascii_case(right),
        _ => false,
    };

    match (fact.device_key.is_some(), fact.user_key.is_some()) {
        (true, true) => {
            same(&fact.device_key, &result.device_key) && same(&fact.user_key, &result.user_key)
        }
        (true, false) => same(&fact.device_key, &result.device_key),
        (false, true) => same(&fact.user_key, &result.user_key),
        (false, false) => false,
    }
}

// ── Time helpers ────────────────────────────────────────────────────────────

/// Only a timestamp whose kind is trustworthy for ordering may be used.
///
/// A local or unspecified-zone timestamp has no known offset, so its normalized
/// form is a guess; using it to order a submission against an evaluation, or a
/// service record against an access decision, would manufacture a correlation
/// out of an unknown. Such timestamps are declined here and surface as missing
/// provenance instead.
pub(super) fn normalized_timestamp(timestamp: &IntuneTimestamp) -> Option<DateTime<Utc>> {
    match timestamp.kind {
        IntuneTimestampKind::Utc | IntuneTimestampKind::Offset => {
            timestamp.normalized_utc.as_deref().and_then(parse_rfc3339)
        }
        _ => None,
    }
}

pub(super) fn parse_rfc3339(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|value| value.with_timezone(&Utc))
}

fn format_utc(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intune::evidence::{
        IntuneAccessState, IntuneEvidenceRef, IntuneObservationContext, IntuneParseState,
        IntuneProvenance, IntuneSensitivity, IntuneSourceKind, IntuneTimestampKind,
    };
    use crate::intune::normalized::{NormalizedEventLevel, NormalizedWindowsEvent};

    fn context(evidence_id: &str, artifact: &str) -> IntuneObservationContext {
        IntuneObservationContext {
            evidence_ref: IntuneEvidenceRef {
                evidence_id: evidence_id.to_owned(),
                source_artifact_id: artifact.to_owned(),
            },
            provenance: IntuneProvenance {
                source_kind: IntuneSourceKind::EventLog,
                source_artifact_id: artifact.to_owned(),
                file_path: None,
                line_number: None,
                record_number: None,
                registry: None,
                event: None,
            },
            source_timestamp: None,
            observed_at_utc: "2026-07-31T00:00:00Z".to_owned(),
            sensitivity: IntuneSensitivity::Public,
            parse_state: IntuneParseState::Parsed,
            access_state: IntuneAccessState::Available,
        }
    }

    fn timestamp(value: &str) -> IntuneTimestamp {
        IntuneTimestamp {
            raw_text: value.to_owned(),
            original_offset: None,
            normalized_utc: Some(value.to_owned()),
            kind: IntuneTimestampKind::Utc,
        }
    }

    fn setting_event(
        evidence_id: &str,
        uri: &str,
        result: &str,
        at: &str,
    ) -> NormalizedWindowsEvent {
        NormalizedWindowsEvent {
            context: IntuneObservationContext {
                source_timestamp: Some(timestamp(at)),
                ..context(evidence_id, "events")
            },
            channel: "channel".to_owned(),
            provider: "provider".to_owned(),
            event_id: 100,
            level: NormalizedEventLevel::Information,
            task: None,
            keywords: None,
            record_id: None,
            activity_id: None,
            named_data: vec![
                crate::intune::evidence::IntuneNamedValue {
                    name: "SettingUri".to_owned(),
                    value: uri.to_owned(),
                },
                crate::intune::evidence::IntuneNamedValue {
                    name: "EvaluationResult".to_owned(),
                    value: result.to_owned(),
                },
            ],
            message: None,
        }
    }

    #[test]
    fn two_disagreeing_definite_sources_produce_a_contradiction() {
        let input = ComplianceInput {
            generated_at_utc: "2026-07-31T12:00:00Z".to_owned(),
            events: vec![
                setting_event("e1", "./Device/X", "compliant", "2026-07-31T10:00:00Z"),
                setting_event("e2", "./Device/X", "noncompliant", "2026-07-31T10:05:00Z"),
            ],
            ..ComplianceInput::default()
        };
        let snapshot = analyze_compliance(&input);
        assert_eq!(snapshot.local_evaluation.settings.len(), 1);
        assert_eq!(
            snapshot.local_evaluation.settings[0].state,
            ComplianceSettingState::Contradictory
        );
        assert_eq!(
            snapshot.aggregate.state,
            ComplianceAggregateState::InsufficientEvidence
        );
    }

    #[test]
    fn a_stale_service_record_never_changes_the_local_state() {
        let input = ComplianceInput {
            generated_at_utc: "2026-07-31T12:00:00Z".to_owned(),
            events: vec![setting_event(
                "e1",
                "./Device/X",
                "compliant",
                "2026-07-31T10:00:00Z",
            )],
            service_results: vec![ComplianceServiceFact {
                context: context("s1", "service"),
                policy_id: None,
                setting_id: None,
                state: ComplianceServiceState::Noncompliant,
                reported_at: Some(timestamp("2026-07-30T09:00:00Z")),
                device_key: Some("device-1".to_owned()),
                user_key: None,
                named_data: Vec::new(),
            }],
            ..ComplianceInput::default()
        };
        let snapshot = analyze_compliance(&input);
        assert_eq!(
            snapshot.aggregate.state,
            ComplianceAggregateState::Compliant
        );
        assert_eq!(
            snapshot.reporting.service_freshness,
            ComplianceServiceFreshness::Stale
        );
        assert!(snapshot.reporting.service_disagrees_with_local);
        assert!(
            snapshot
                .local_evaluation
                .settings
                .iter()
                .all(|setting| setting.state == ComplianceSettingState::Compliant),
            "a service record must never rewrite a local setting state"
        );
    }

    #[test]
    fn an_access_denial_alone_correlates_to_nothing() {
        let input = ComplianceInput {
            generated_at_utc: "2026-07-31T12:00:00Z".to_owned(),
            access_decisions: vec![ComplianceAccessFact {
                context: context("a1", "access"),
                decision: ComplianceAccessDecision::Denied,
                failure_code: None,
                occurred_at: Some(timestamp("2026-07-31T11:00:00Z")),
                device_key: Some("device-1".to_owned()),
                user_key: None,
                resource: None,
                named_data: Vec::new(),
            }],
            ..ComplianceInput::default()
        };
        let snapshot = analyze_compliance(&input);
        assert_eq!(
            snapshot.access_impact.decisions[0].linkage,
            ComplianceAccessLinkage::NoMatchingComplianceEvidence
        );
        assert_eq!(
            snapshot.aggregate.state,
            ComplianceAggregateState::InsufficientEvidence,
            "an access denial must not produce a local compliance verdict"
        );
    }

    #[test]
    fn a_custom_script_failure_is_an_error_not_a_noncompliance() {
        let input = ComplianceInput {
            generated_at_utc: "2026-07-31T12:00:00Z".to_owned(),
            custom_compliance: vec![ComplianceCustomFact {
                context: context("c1", "custom"),
                policy_id: Some("policy-1".to_owned()),
                run_id: Some("run-1".to_owned()),
                setting_name: Some("DiskEncryption".to_owned()),
                outcome: ComplianceCustomState::ScriptFailed,
                error: None,
                raw_output: None,
                named_data: Vec::new(),
            }],
            ..ComplianceInput::default()
        };
        let snapshot = analyze_compliance(&input);
        assert_eq!(
            snapshot.aggregate.state,
            ComplianceAggregateState::EvaluationError
        );
        assert_eq!(
            snapshot.aggregate.rationale,
            ComplianceAggregateRationale::CustomComplianceScriptFailed
        );
    }

    #[test]
    fn a_submission_predating_the_latest_evaluation_is_stale() {
        let mut submitted = setting_event("e2", "./Device/Y", "compliant", "2026-07-31T09:00:00Z");
        submitted.named_data = vec![crate::intune::evidence::IntuneNamedValue {
            name: "ReportStatus".to_owned(),
            value: "submitted".to_owned(),
        }];
        let input = ComplianceInput {
            generated_at_utc: "2026-07-31T12:00:00Z".to_owned(),
            events: vec![
                setting_event("e1", "./Device/X", "compliant", "2026-07-31T10:00:00Z"),
                submitted,
            ],
            ..ComplianceInput::default()
        };
        let snapshot = analyze_compliance(&input);
        assert_eq!(snapshot.reporting.state, ComplianceReportState::Stale);
    }

    fn report_event(evidence_id: &str, status: &str, at: &str) -> NormalizedWindowsEvent {
        let mut event = setting_event(evidence_id, "./Device/X", "compliant", at);
        event.named_data = vec![crate::intune::evidence::IntuneNamedValue {
            name: "ReportStatus".to_owned(),
            value: status.to_owned(),
        }];
        event
    }

    #[test]
    fn a_submission_after_a_failure_is_reported_as_submitted() {
        let input = ComplianceInput {
            generated_at_utc: "2026-07-31T12:00:00Z".to_owned(),
            events: vec![
                report_event("r1", "failed", "2026-07-31T10:00:00Z"),
                report_event("r2", "submitted", "2026-07-31T11:00:00Z"),
            ],
            ..ComplianceInput::default()
        };
        let snapshot = analyze_compliance(&input);
        assert_eq!(
            snapshot.reporting.state,
            ComplianceReportState::Submitted,
            "a later successful submission must not stay hidden behind an earlier failure"
        );
    }

    #[test]
    fn a_queued_row_after_a_failure_does_not_undo_the_failure() {
        let input = ComplianceInput {
            generated_at_utc: "2026-07-31T12:00:00Z".to_owned(),
            events: vec![
                report_event("r1", "failed", "2026-07-31T10:00:00Z"),
                report_event("r2", "queued", "2026-07-31T11:00:00Z"),
            ],
            ..ComplianceInput::default()
        };
        let snapshot = analyze_compliance(&input);
        assert_eq!(snapshot.reporting.state, ComplianceReportState::Failed);
    }

    #[test]
    fn a_denial_naming_a_different_user_on_the_same_device_is_not_correlated() {
        let input = ComplianceInput {
            generated_at_utc: "2026-07-31T12:00:00Z".to_owned(),
            events: vec![setting_event(
                "e1",
                "./Device/X",
                "compliant",
                "2026-07-31T09:00:00Z",
            )],
            service_results: vec![ComplianceServiceFact {
                context: context("s1", "service"),
                policy_id: None,
                setting_id: None,
                state: ComplianceServiceState::Noncompliant,
                reported_at: Some(timestamp("2026-07-31T10:00:00Z")),
                device_key: Some("device-1".to_owned()),
                user_key: Some("user-1".to_owned()),
                named_data: Vec::new(),
            }],
            access_decisions: vec![ComplianceAccessFact {
                context: context("a1", "access"),
                decision: ComplianceAccessDecision::Denied,
                failure_code: None,
                occurred_at: Some(timestamp("2026-07-31T11:00:00Z")),
                device_key: Some("device-1".to_owned()),
                user_key: Some("user-2".to_owned()),
                resource: None,
                named_data: Vec::new(),
            }],
            ..ComplianceInput::default()
        };
        let snapshot = analyze_compliance(&input);
        assert_eq!(
            snapshot.access_impact.decisions[0].linkage,
            ComplianceAccessLinkage::IdentityMismatch,
            "a denial that names a different user must not borrow another user's state"
        );
    }

    #[test]
    fn a_timestamp_with_no_known_zone_cannot_order_anything() {
        let unusable = IntuneTimestamp {
            raw_text: "2026-07-31T10:00:00".to_owned(),
            original_offset: None,
            normalized_utc: Some("2026-07-31T10:00:00Z".to_owned()),
            kind: IntuneTimestampKind::Unspecified,
        };
        assert_eq!(
            normalized_timestamp(&unusable),
            None,
            "a zone-less timestamp must not be treated as an ordered UTC instant"
        );
    }
}
