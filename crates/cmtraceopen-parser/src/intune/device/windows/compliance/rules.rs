//! Findings derived from a finished compliance snapshot.
//!
//! Every rule is a private `push_*` function driven from [`derive_findings`], and
//! every rule obeys three constraints:
//!
//! * a finding cites evidence or a coverage gap, never neither;
//! * a finding that claims a **local setting failed** cites local evaluation
//!   evidence — never a service record and never a sign-in result;
//! * a finding built only from access evidence is capped at
//!   [`IntuneFindingConfidence::Low`] and [`IntuneFindingSeverity::Info`],
//!   because a Conditional Access denial is a downstream symptom whose cause
//!   this module does not analyze.

use super::models::*;
use crate::intune::evidence::{
    IntuneArtifactStatus, IntuneEvidenceRef, IntuneFinding, IntuneFindingConfidence,
    IntuneFindingSeverity,
};

/// Derive stable, read-only findings from an immutable snapshot.
pub fn derive_findings(snapshot: &ComplianceSnapshot) -> Vec<IntuneFinding> {
    let mut findings = Vec::new();

    push_local_setting_noncompliant(snapshot, &mut findings);
    push_local_evaluation_error(snapshot, &mut findings);
    push_prerequisite_unmet(snapshot, &mut findings);
    push_setting_not_applicable(snapshot, &mut findings);
    push_user_scoped_not_evaluated(snapshot, &mut findings);
    push_custom_discovery_noncompliant(snapshot, &mut findings);
    push_custom_script_failed(snapshot, &mut findings);
    push_contradictory_local_evidence(snapshot, &mut findings);
    push_report_submission_failed(snapshot, &mut findings);
    push_service_state_stale(snapshot, &mut findings);
    push_access_denied_correlated(snapshot, &mut findings);
    push_access_denied_uncorrelated(snapshot, &mut findings);
    push_unkeyed_observations(snapshot, &mut findings);
    push_source_unusable(snapshot, &mut findings);
    push_device_compliant(snapshot, &mut findings);

    findings
}

// ── Phase 1: local evaluation ───────────────────────────────────────────────

fn push_local_setting_noncompliant(
    snapshot: &ComplianceSnapshot,
    findings: &mut Vec<IntuneFinding>,
) {
    let settings = settings_in(snapshot, ComplianceSettingState::Noncompliant);
    if settings.is_empty() {
        return;
    }
    push(
        findings,
        finding(
            "compliance-local-setting-noncompliant",
            IntuneFindingSeverity::Error,
            IntuneFindingConfidence::High,
            "A device-local compliance setting evaluated as noncompliant",
            &format!(
                "{} evaluated as noncompliant on the device itself: {}.",
                count_label(settings.len(), "setting", "settings"),
                setting_labels(&settings)
            ),
            "Inspect the cited local evaluation records for the named setting and confirm the required configuration on the device.",
            collect_evidence(settings.iter().flat_map(|setting| setting.evidence.iter())),
            Vec::new(),
        ),
    );
}

fn push_local_evaluation_error(snapshot: &ComplianceSnapshot, findings: &mut Vec<IntuneFinding>) {
    let settings = settings_in(snapshot, ComplianceSettingState::EvaluationError);
    if settings.is_empty() {
        return;
    }
    push(
        findings,
        finding(
            "compliance-local-evaluation-error",
            IntuneFindingSeverity::Error,
            IntuneFindingConfidence::High,
            "A compliance setting could not be evaluated",
            &format!(
                "{} reported an evaluation error rather than a verdict: {}. An evaluation error is not the same as a noncompliant device.",
                count_label(settings.len(), "setting", "settings"),
                setting_labels(&settings)
            ),
            "Inspect the cited evaluation records for the reported error code and the CSP the setting resolves to.",
            collect_evidence(settings.iter().flat_map(|setting| setting.evidence.iter())),
            Vec::new(),
        ),
    );
}

fn push_prerequisite_unmet(snapshot: &ComplianceSnapshot, findings: &mut Vec<IntuneFinding>) {
    let unmet = snapshot
        .local_evaluation
        .prerequisites
        .iter()
        .filter(|prerequisite| prerequisite.state == CompliancePrerequisiteState::Unmet)
        .collect::<Vec<_>>();
    if unmet.is_empty() {
        return;
    }
    push(
        findings,
        finding(
            "compliance-prerequisite-unmet",
            IntuneFindingSeverity::Warning,
            IntuneFindingConfidence::High,
            "A local prerequisite for compliance evaluation was not met",
            &format!(
                "The device reported an unmet prerequisite: {}. Settings gated on it were not evaluated, which is not the same as failing them.",
                unmet
                    .iter()
                    .map(|prerequisite| prerequisite.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            "Resolve the cited prerequisite, then re-run compliance evaluation and re-collect the evidence.",
            collect_evidence(unmet.iter().flat_map(|prerequisite| prerequisite.evidence.iter())),
            Vec::new(),
        ),
    );
}

fn push_setting_not_applicable(snapshot: &ComplianceSnapshot, findings: &mut Vec<IntuneFinding>) {
    let settings = settings_in(snapshot, ComplianceSettingState::NotApplicable);
    if settings.is_empty() {
        return;
    }
    push(
        findings,
        finding(
            "compliance-setting-not-applicable",
            IntuneFindingSeverity::Info,
            IntuneFindingConfidence::High,
            "A compliance setting does not apply to this device",
            &format!(
                "{} reported as not applicable: {}. A not-applicable setting is excluded from the aggregate result rather than counted as a pass or a failure.",
                count_label(settings.len(), "setting", "settings"),
                setting_labels(&settings)
            ),
            "Confirm the cited setting's applicability rules against this device's edition and hardware.",
            collect_evidence(settings.iter().flat_map(|setting| setting.evidence.iter())),
            Vec::new(),
        ),
    );
}

/// A user-targeted setting that no user context evaluated.
///
/// This is the finding that keeps "nobody was signed in" from being read as "the
/// device failed the setting". It is `Info`, never an error, and its summary
/// says so explicitly.
fn push_user_scoped_not_evaluated(
    snapshot: &ComplianceSnapshot,
    findings: &mut Vec<IntuneFinding>,
) {
    let settings = snapshot
        .local_evaluation
        .settings
        .iter()
        .filter(|setting| {
            setting.scope == ComplianceScope::User
                && matches!(
                    setting.state,
                    ComplianceSettingState::NotEvaluated
                        | ComplianceSettingState::InsufficientEvidence
                )
        })
        .collect::<Vec<_>>();
    if settings.is_empty() {
        return;
    }

    let context_note = match snapshot.device_context.user_evaluation_context {
        ComplianceUserContext::NoUserSession => {
            "The collector reported that no user session was present."
        }
        ComplianceUserContext::UserPresent => {
            "A user session was reported as present, so the absence of a result is unexplained."
        }
        ComplianceUserContext::Unknown => {
            "The collector did not report whether a user session was present."
        }
    };

    push(
        findings,
        finding(
            "compliance-user-scoped-not-evaluated",
            IntuneFindingSeverity::Info,
            IntuneFindingConfidence::Medium,
            "A user-targeted compliance setting was not evaluated in this context",
            &format!(
                "{} targeted at a user produced no local verdict: {}. {context_note} This is missing evaluation coverage, not a failed setting.",
                count_label(settings.len(), "setting", "settings"),
                setting_labels(&settings)
            ),
            "Re-collect evidence with the affected user signed in, then compare the cited settings' results.",
            collect_evidence(settings.iter().flat_map(|setting| setting.evidence.iter())),
            Vec::new(),
        ),
    );
}

fn push_custom_discovery_noncompliant(
    snapshot: &ComplianceSnapshot,
    findings: &mut Vec<IntuneFinding>,
) {
    let results = custom_in(snapshot, &[ComplianceCustomState::DiscoveryNoncompliant]);
    if results.is_empty() {
        return;
    }
    push(
        findings,
        finding(
            "compliance-custom-discovery-noncompliant",
            IntuneFindingSeverity::Error,
            IntuneFindingConfidence::High,
            "A custom compliance discovery script returned a noncompliant result",
            &format!(
                "{} produced a noncompliant discovery result. The script ran to completion and reported this verdict, so it is a local result rather than an execution problem.",
                count_label(results.len(), "custom compliance setting", "custom compliance settings")
            ),
            "Inspect the cited custom compliance run's discovered values against the policy's JSON rules.",
            collect_evidence(results.iter().flat_map(|result| result.evidence.iter())),
            Vec::new(),
        ),
    );
}

/// A custom-compliance script that did not complete.
///
/// Deliberately distinct from the rule above: a crashed script produced no
/// verdict, and reporting it as a noncompliant device would invent one.
fn push_custom_script_failed(snapshot: &ComplianceSnapshot, findings: &mut Vec<IntuneFinding>) {
    let results = custom_in(
        snapshot,
        &[
            ComplianceCustomState::ScriptFailed,
            ComplianceCustomState::OutputInvalid,
        ],
    );
    if results.is_empty() {
        return;
    }
    push(
        findings,
        finding(
            "compliance-custom-script-failed",
            IntuneFindingSeverity::Error,
            IntuneFindingConfidence::High,
            "A custom compliance script failed to produce a usable result",
            &format!(
                "{} failed to execute or returned output that could not be interpreted. No compliance verdict was produced, so this is an evaluation failure and not evidence that the device is noncompliant.",
                count_label(results.len(), "custom compliance run", "custom compliance runs")
            ),
            "Inspect the cited run's exit code and output shape against the policy's expected discovery JSON.",
            collect_evidence(results.iter().flat_map(|result| result.evidence.iter())),
            Vec::new(),
        ),
    );
}

fn push_contradictory_local_evidence(
    snapshot: &ComplianceSnapshot,
    findings: &mut Vec<IntuneFinding>,
) {
    let contradictory = settings_in(snapshot, ComplianceSettingState::Contradictory);
    let out_of_order = snapshot
        .local_evaluation
        .settings
        .iter()
        .filter(|setting| setting.time_contradiction)
        .collect::<Vec<_>>();
    let mismatched_ids = snapshot
        .local_evaluation
        .settings
        .iter()
        .filter(|setting| setting.identity_contradiction)
        .collect::<Vec<_>>();
    if contradictory.is_empty() && out_of_order.is_empty() && mismatched_ids.is_empty() {
        return;
    }

    let mut evidence = collect_evidence(
        contradictory
            .iter()
            .chain(out_of_order.iter())
            .chain(mismatched_ids.iter())
            .flat_map(|setting| setting.evidence.iter()),
    );
    normalize_evidence(&mut evidence);

    push(
        findings,
        finding(
            "compliance-contradictory-evidence",
            IntuneFindingSeverity::Warning,
            IntuneFindingConfidence::Medium,
            "Local compliance sources contradict each other",
            &format!(
                "{} setting(s) carry disagreeing verdicts, {} claim an evaluation time after this evidence was collected, and {} were described with conflicting identifiers. Any setting whose sources disagreed was left at its observed state or insufficiently evidenced rather than resolved to a single verdict.",
                contradictory.len(),
                out_of_order.len(),
                mismatched_ids.len()
            ),
            "Compare the cited records' identifiers and timestamps; re-collect with a single consistent capture if the sources came from different runs.",
            evidence,
            Vec::new(),
        ),
    );
}

// ── Phase 3: reporting ──────────────────────────────────────────────────────

fn push_report_submission_failed(snapshot: &ComplianceSnapshot, findings: &mut Vec<IntuneFinding>) {
    if snapshot.reporting.state != ComplianceReportState::Failed {
        return;
    }
    let code = snapshot
        .reporting
        .error
        .as_ref()
        .map(|error| format!(" Reported code: {}.", error.raw))
        .unwrap_or_default();
    push(
        findings,
        finding(
            "compliance-report-submission-failed",
            IntuneFindingSeverity::Error,
            IntuneFindingConfidence::High,
            "The device failed to submit its compliance report",
            &format!(
                "A compliance report submission failed.{code} The service therefore holds no result from this evaluation, which is a reporting problem and says nothing about whether the local settings pass."
            ),
            "Check device connectivity to the Intune service and the cited submission record's error code.",
            snapshot.reporting.evidence.clone(),
            Vec::new(),
        ),
    );
}

/// The service holds a state that predates the most recent local evaluation.
///
/// The summary states the local aggregate explicitly, so a reader cannot come
/// away thinking the stale service record is a local failure.
fn push_service_state_stale(snapshot: &ComplianceSnapshot, findings: &mut Vec<IntuneFinding>) {
    if snapshot.reporting.service_freshness != ComplianceServiceFreshness::Stale {
        return;
    }
    let stale = snapshot
        .reporting
        .service_results
        .iter()
        .filter(|result| result.freshness == ComplianceServiceFreshness::Stale)
        .collect::<Vec<_>>();
    if stale.is_empty() {
        return;
    }

    let disagreement = if snapshot.reporting.service_disagrees_with_local {
        " The stale service state also disagrees with the local result."
    } else {
        ""
    };

    push(
        findings,
        finding(
            "compliance-service-state-stale",
            IntuneFindingSeverity::Warning,
            IntuneFindingConfidence::High,
            "The service-held compliance state predates the local evaluation",
            &format!(
                "{} service-held record(s) were reported before the most recent local evaluation, so they cannot describe it. The device's own aggregate result is {}.{disagreement} This is a reporting-freshness problem, not a local setting failure.",
                stale.len(),
                aggregate_label(snapshot.aggregate.state)
            ),
            "Force a compliance check-in, wait for the report to submit, and re-read the service state before drawing conclusions from it.",
            collect_evidence(stale.iter().flat_map(|result| result.evidence.iter())),
            Vec::new(),
        ),
    );
}

// ── Phase 4: downstream access ──────────────────────────────────────────────

/// A denial that lines up with a compliance record on identity **and** time.
///
/// Confidence is capped at Medium and the wording is coincidence, not cause:
/// this module does not analyze Conditional Access policy, so it cannot know
/// that compliance is why the sign-in was blocked.
fn push_access_denied_correlated(snapshot: &ComplianceSnapshot, findings: &mut Vec<IntuneFinding>) {
    let denials = snapshot
        .access_impact
        .decisions
        .iter()
        .filter(|decision| {
            decision.decision == ComplianceAccessDecision::Denied
                && decision.linkage == ComplianceAccessLinkage::MatchedComplianceState
        })
        .collect::<Vec<_>>();
    if denials.is_empty() {
        return;
    }

    let mut evidence = collect_evidence(denials.iter().flat_map(|decision| {
        decision
            .evidence
            .iter()
            .chain(decision.matched_evidence.iter())
    }));
    normalize_evidence(&mut evidence);

    push(
        findings,
        finding(
            "compliance-access-denied-correlated",
            IntuneFindingSeverity::Warning,
            IntuneFindingConfidence::Medium,
            "An access denial coincides with a matching compliance record",
            &format!(
                "{} access denial(s) match a compliance record on device or user identity and occurred after it was reported. The local aggregate result is {}. This is downstream impact; the Conditional Access policy itself is not analyzed here, so no cause is claimed.",
                denials.len(),
                aggregate_label(snapshot.aggregate.state)
            ),
            "Confirm in the sign-in log which Conditional Access policy applied, then compare its device-compliance requirement against the cited compliance record.",
            evidence,
            Vec::new(),
        ),
    );
}

/// A denial with nothing to match against.
///
/// Info + Low, always. This is the rule that would otherwise turn a sign-in
/// error into a compliance diagnosis.
fn push_access_denied_uncorrelated(
    snapshot: &ComplianceSnapshot,
    findings: &mut Vec<IntuneFinding>,
) {
    let denials = snapshot
        .access_impact
        .decisions
        .iter()
        .filter(|decision| {
            decision.decision == ComplianceAccessDecision::Denied
                && decision.linkage != ComplianceAccessLinkage::MatchedComplianceState
        })
        .collect::<Vec<_>>();
    if denials.is_empty() {
        return;
    }
    push(
        findings,
        finding(
            "compliance-access-denied-uncorrelated",
            IntuneFindingSeverity::Info,
            IntuneFindingConfidence::Low,
            "An access denial was observed with no matching compliance evidence",
            &format!(
                "{} access denial(s) could not be tied to a compliance record by identity and time. No causal claim is made: this evidence does not show that device compliance was the reason for the denial, and it is not evidence that any local setting failed.",
                denials.len()
            ),
            "Collect the sign-in record's full failure reason and the device compliance state captured at the same time, then re-run the analysis.",
            collect_evidence(denials.iter().flat_map(|decision| decision.evidence.iter())),
            Vec::new(),
        ),
    );
}

// ── Coverage ────────────────────────────────────────────────────────────────

fn push_unkeyed_observations(snapshot: &ComplianceSnapshot, findings: &mut Vec<IntuneFinding>) {
    let unkeyed = &snapshot.local_evaluation.unkeyed_observations;
    if unkeyed.is_empty() {
        return;
    }
    push(
        findings,
        finding(
            "compliance-unkeyed-observations",
            IntuneFindingSeverity::Info,
            IntuneFindingConfidence::Medium,
            "Compliance records carried no setting identifier",
            &format!(
                "{} record(s) referenced compliance evaluation without naming a policy, setting, or CSP URI. They were not merged into any setting result, because an unidentified record cannot be correlated.",
                unkeyed.len()
            ),
            "Re-collect with the source that supplies setting identifiers, or confirm the adapter is projecting them into named data.",
            unkeyed.clone(),
            Vec::new(),
        ),
    );
}

/// Expected sources that were missing, capped, denied, skipped, unsupported, or
/// unreadable.
///
/// Split into two findings so a genuinely absent source and a source that was
/// collected but could not be interpreted are never conflated.
fn push_source_unusable(snapshot: &ComplianceSnapshot, findings: &mut Vec<IntuneFinding>) {
    let gaps = |statuses: &[IntuneArtifactStatus]| {
        let mut ids = snapshot
            .coverage
            .iter()
            .filter(|entry| statuses.contains(&entry.status))
            .map(|entry| entry.artifact_id.clone())
            .collect::<Vec<_>>();
        ids.sort();
        ids.dedup();
        ids
    };

    let uncollected = gaps(&[
        IntuneArtifactStatus::Missing,
        IntuneArtifactStatus::PermissionDenied,
        IntuneArtifactStatus::Skipped,
        IntuneArtifactStatus::Capped,
    ]);
    if !uncollected.is_empty() {
        push(
            findings,
            finding(
                "compliance-source-missing",
                IntuneFindingSeverity::Warning,
                IntuneFindingConfidence::High,
                "Expected compliance evidence was not collected",
                &format!(
                    "{} expected source(s) were absent, inaccessible, skipped, or truncated. Any conclusion drawn from the remaining evidence is incomplete, and the absence of a signal in this bundle proves nothing.",
                    uncollected.len()
                ),
                "Re-collect the cited sources with sufficient privileges and without truncation, then re-run the analysis.",
                Vec::new(),
                uncollected,
            ),
        );
    }

    let unusable = gaps(&[
        IntuneArtifactStatus::ParseFailed,
        IntuneArtifactStatus::Unsupported,
    ]);
    if !unusable.is_empty() {
        push(
            findings,
            finding(
                "compliance-source-malformed",
                IntuneFindingSeverity::Warning,
                IntuneFindingConfidence::High,
                "Compliance evidence was collected but could not be interpreted",
                &format!(
                    "{} source(s) were malformed or declared a schema this build does not support. Their contents contributed nothing to the result and were not guessed at.",
                    unusable.len()
                ),
                "Check the cited sources' format and schema version against the collector that produced them.",
                Vec::new(),
                unusable,
            ),
        );
    }
}

fn push_device_compliant(snapshot: &ComplianceSnapshot, findings: &mut Vec<IntuneFinding>) {
    if snapshot.aggregate.state != ComplianceAggregateState::Compliant {
        return;
    }
    // A clean result asserted over incomplete evidence is not a clean result,
    // and an empty coverage list is the least complete evidence there is: an
    // unqualified `all` over it would vacuously report high confidence.
    let complete = !snapshot.coverage.is_empty()
        && snapshot
            .coverage
            .iter()
            .all(|entry| entry.status == IntuneArtifactStatus::Available);
    let confidence = if complete {
        IntuneFindingConfidence::High
    } else {
        IntuneFindingConfidence::Medium
    };
    push(
        findings,
        finding(
            "compliance-device-compliant",
            IntuneFindingSeverity::Info,
            confidence,
            "Every locally evaluated compliance setting passed",
            &format!(
                "{} setting(s) evaluated compliant on the device and none evaluated noncompliant or errored.",
                snapshot.aggregate.compliant_count
            ),
            "Compare the cited local results against the service-held state to confirm the two agree.",
            snapshot.aggregate.evidence.clone(),
            Vec::new(),
        ),
    );
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn settings_in(
    snapshot: &ComplianceSnapshot,
    state: ComplianceSettingState,
) -> Vec<&ComplianceSettingEvaluation> {
    snapshot
        .local_evaluation
        .settings
        .iter()
        .filter(|setting| setting.state == state)
        .collect()
}

fn custom_in<'a>(
    snapshot: &'a ComplianceSnapshot,
    states: &[ComplianceCustomState],
) -> Vec<&'a ComplianceCustomEvaluation> {
    snapshot
        .local_evaluation
        .custom_compliance
        .iter()
        .filter(|custom| states.contains(&custom.state))
        .collect()
}

/// A short, de-duplicated label list for the cited settings.
///
/// Prefers the display name, falls back to the grouping token, and caps the
/// list so a summary stays readable when a policy has many settings.
fn setting_labels(settings: &[&ComplianceSettingEvaluation]) -> String {
    const MAX_LABELS: usize = 6;
    let mut labels: Vec<String> = Vec::new();
    for setting in settings {
        let label = setting
            .display_name
            .clone()
            .unwrap_or_else(|| setting.grouping_token.clone());
        if !labels.contains(&label) {
            labels.push(label);
        }
    }
    let extra = labels.len().saturating_sub(MAX_LABELS);
    labels.truncate(MAX_LABELS);
    let mut joined = labels.join(", ");
    if extra > 0 {
        joined.push_str(&format!(" (+{extra} more)"));
    }
    joined
}

fn count_label(count: usize, singular: &str, plural: &str) -> String {
    if count == 1 {
        format!("One {singular}")
    } else {
        format!("{count} {plural}")
    }
}

fn aggregate_label(state: ComplianceAggregateState) -> &'static str {
    match state {
        ComplianceAggregateState::Compliant => "compliant",
        ComplianceAggregateState::Noncompliant => "noncompliant",
        ComplianceAggregateState::EvaluationError => "an evaluation error",
        ComplianceAggregateState::NotEvaluated => "not evaluated",
        ComplianceAggregateState::InsufficientEvidence => "insufficient evidence",
    }
}

#[allow(clippy::too_many_arguments)]
fn finding(
    id: &str,
    severity: IntuneFindingSeverity,
    confidence: IntuneFindingConfidence,
    title: &str,
    summary: &str,
    check: &str,
    evidence: Vec<IntuneEvidenceRef>,
    coverage_gap_ids: Vec<String>,
) -> Option<IntuneFinding> {
    // The invariant from `intune::evidence`: a finding backed by neither
    // evidence nor a coverage gap is an assertion, so it is never emitted. The
    // verdict is asked of the owning predicate rather than restated here, so
    // this lane cannot drift from the definition it cites.
    let candidate = IntuneFinding {
        finding_id: id.to_owned(),
        severity,
        confidence,
        title: title.to_owned(),
        summary: summary.to_owned(),
        recommended_checks: vec![check.to_owned()],
        evidence,
        coverage_gap_ids,
    };
    candidate.is_evidence_backed().then_some(candidate)
}

fn push(findings: &mut Vec<IntuneFinding>, finding: Option<IntuneFinding>) {
    if let Some(finding) = finding {
        findings.push(finding);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence_ref(id: &str, artifact: &str) -> IntuneEvidenceRef {
        IntuneEvidenceRef {
            evidence_id: id.to_owned(),
            source_artifact_id: artifact.to_owned(),
        }
    }

    fn snapshot_with_denial(linkage: ComplianceAccessLinkage) -> ComplianceSnapshot {
        ComplianceSnapshot {
            access_impact: ComplianceAccessPhase {
                decisions: vec![ComplianceAccessObservation {
                    decision: ComplianceAccessDecision::Denied,
                    linkage,
                    failure_code: None,
                    occurred_at: None,
                    device_key: None,
                    user_key: None,
                    resource: None,
                    matched_evidence: Vec::new(),
                    evidence: vec![evidence_ref("a1", "access")],
                }],
                evidence: vec![evidence_ref("a1", "access")],
            },
            ..ComplianceSnapshot::default()
        }
    }

    #[test]
    fn an_uncorrelated_denial_is_never_high_confidence() {
        let snapshot = snapshot_with_denial(ComplianceAccessLinkage::NoMatchingComplianceEvidence);
        let findings = derive_findings(&snapshot);
        let denial = findings
            .iter()
            .find(|finding| finding.finding_id == "compliance-access-denied-uncorrelated")
            .expect("uncorrelated denial finding");
        assert_eq!(denial.confidence, IntuneFindingConfidence::Low);
        assert_eq!(denial.severity, IntuneFindingSeverity::Info);
        assert!(denial.summary.contains("No causal claim is made"));
    }

    #[test]
    fn an_access_denial_never_produces_a_local_failure_finding() {
        let snapshot = snapshot_with_denial(ComplianceAccessLinkage::NoMatchingComplianceEvidence);
        let findings = derive_findings(&snapshot);
        assert!(
            !findings
                .iter()
                .any(|finding| finding.finding_id == "compliance-local-setting-noncompliant"),
            "a sign-in denial must not create a local-noncompliance finding"
        );
    }

    #[test]
    fn every_derived_finding_is_evidence_backed() {
        let snapshot = snapshot_with_denial(ComplianceAccessLinkage::IdentityMismatch);
        for finding in derive_findings(&snapshot) {
            assert!(
                finding.is_evidence_backed(),
                "{} cites neither evidence nor a coverage gap",
                finding.finding_id
            );
        }
    }

    #[test]
    fn an_empty_snapshot_produces_no_findings() {
        assert!(derive_findings(&ComplianceSnapshot::default()).is_empty());
    }

    fn build(
        evidence: Vec<IntuneEvidenceRef>,
        coverage_gap_ids: Vec<String>,
    ) -> Option<IntuneFinding> {
        finding(
            "compliance-pin",
            IntuneFindingSeverity::Warning,
            IntuneFindingConfidence::Low,
            "title",
            "summary",
            "check",
            evidence,
            coverage_gap_ids,
        )
    }

    /// Pins the whole input space of the citation guard: two emptiness bits, and
    /// nothing else. The constructor reads no snapshot, access state, parse state,
    /// severity or confidence, so these four cells are exhaustive.
    ///
    /// Suppression must agree exactly with the negation of the shared invariant
    /// [`IntuneFinding::is_evidence_backed`], which is what this constructor
    /// claims to enforce.
    #[test]
    fn the_citation_guard_agrees_with_the_shared_invariant_on_every_input() {
        for (evidence, gaps, expected_backed) in [
            (Vec::new(), Vec::new(), false),
            (Vec::new(), vec!["gap".to_owned()], true),
            (vec![evidence_ref("e1", "compliance")], Vec::new(), true),
            (
                vec![evidence_ref("e1", "compliance")],
                vec!["gap".to_owned()],
                true,
            ),
        ] {
            let built = build(evidence.clone(), gaps.clone());
            assert_eq!(
                built.is_some(),
                expected_backed,
                "evidence={evidence:?} gaps={gaps:?}"
            );
            if let Some(built) = built {
                assert!(
                    built.is_evidence_backed(),
                    "an emitted finding must satisfy the invariant it was gated on"
                );
            }
        }
    }

    /// Unlike Autopilot, this constructor does not sort or de-duplicate; each
    /// rule owns the order of its own citations and consumers sort before
    /// comparing. Pinned so a future consistency pass cannot quietly adopt the
    /// other lane's normalization while claiming to touch only the guard. See
    /// `docs/architecture/shared-vs-workload-invariants.md`.
    #[test]
    fn the_constructor_preserves_citation_order_and_duplicates_verbatim() {
        let evidence = vec![
            evidence_ref("e2", "compliance"),
            evidence_ref("e1", "compliance"),
            evidence_ref("e2", "compliance"),
        ];
        let gaps = vec!["b".to_owned(), "a".to_owned(), "b".to_owned()];
        let built = build(evidence.clone(), gaps.clone()).expect("cited finding");
        assert_eq!(built.evidence, evidence);
        assert_eq!(built.coverage_gap_ids, gaps);
    }

    /// The single recommended check is wrapped into the shared vector field; the
    /// Autopilot constructor takes a slice instead. The arity difference is the
    /// reason the two constructors are not one function.
    #[test]
    fn the_constructor_wraps_its_single_recommended_check() {
        let built =
            build(vec![evidence_ref("e1", "compliance")], Vec::new()).expect("cited finding");
        assert_eq!(built.recommended_checks, vec!["check".to_owned()]);
    }
}
