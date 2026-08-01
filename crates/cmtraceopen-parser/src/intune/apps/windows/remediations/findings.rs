//! Conservative findings derived from an immutable remediation snapshot.
//!
//! One private `push_*` per rule, each emitting only when its triggering
//! evidence is present, so every returned finding cites at least one evidence
//! reference or one coverage gap. Nothing here re-reads a record or re-decides
//! an outcome: the reducer already did that, and a rule that disagreed with it
//! would be a second, invisible reducer.

use std::collections::BTreeSet;

use crate::intune::evidence::{
    IntuneArtifactStatus, IntuneEvidenceRef, IntuneFinding, IntuneFindingConfidence,
    IntuneFindingSeverity, IntuneParseState,
};

use super::models::{
    DetectionOutcome, PostRemediationState, RemediationEvent, RemediationOutcome, RemediationRun,
    RemediationSnapshot, ReportingState,
};

/// Derive stable, read-only findings from a snapshot.
pub fn derive_findings(snapshot: &RemediationSnapshot) -> Vec<IntuneFinding> {
    let mut findings = Vec::new();

    push_missing_expected_source(snapshot, &mut findings);
    push_detection_failed(snapshot, &mut findings);
    push_remediation_failed(snapshot, &mut findings);
    push_remediation_ineffective(snapshot, &mut findings);
    push_reporting_failed(snapshot, &mut findings);
    push_reporting_never_observed(snapshot, &mut findings);
    push_unattributed_execution(snapshot, &mut findings);
    push_malformed_payload(snapshot, &mut findings);
    push_split_record(snapshot, &mut findings);
    push_retry_observed(snapshot, &mut findings);
    push_incomplete_run(snapshot, &mut findings);
    push_remediation_succeeded(snapshot, &mut findings);
    push_already_compliant(snapshot, &mut findings);

    findings.sort_by(|left, right| left.finding_id.cmp(&right.finding_id));
    findings
}

/// Build a finding, dropping it when it would cite nothing.
///
/// This is the single place the "a finding is evidence-backed or it does not
/// exist" invariant is enforced, so no rule can forget it.
#[allow(clippy::too_many_arguments)]
fn push_finding(
    findings: &mut Vec<IntuneFinding>,
    finding_id: &str,
    severity: IntuneFindingSeverity,
    confidence: IntuneFindingConfidence,
    title: &str,
    summary: String,
    recommended_checks: Vec<String>,
    evidence: Vec<IntuneEvidenceRef>,
    coverage_gap_ids: Vec<String>,
) {
    let finding = IntuneFinding {
        finding_id: finding_id.to_owned(),
        severity,
        confidence,
        title: title.to_owned(),
        summary,
        recommended_checks,
        evidence: dedupe(evidence),
        coverage_gap_ids: dedupe_ids(coverage_gap_ids),
    };
    if finding.is_evidence_backed() {
        findings.push(finding);
    }
}

fn dedupe(refs: Vec<IntuneEvidenceRef>) -> Vec<IntuneEvidenceRef> {
    refs.into_iter().collect::<BTreeSet<_>>().into_iter().collect()
}

fn dedupe_ids(ids: Vec<String>) -> Vec<String> {
    ids.into_iter().collect::<BTreeSet<_>>().into_iter().collect()
}

/// A run's identity, for a human-readable summary.
fn label(run: &RemediationRun) -> String {
    match &run.key.run_id {
        Some(run_id) => format!("policy {} run {run_id}", run.key.policy_id),
        None => format!("policy {} (no run identifier)", run.key.policy_id),
    }
}

fn labels(runs: &[&RemediationRun]) -> String {
    runs.iter().map(|run| label(run)).collect::<Vec<_>>().join(", ")
}

/// The weakest confidence across the runs a finding cites.
fn confidence_of(runs: &[&RemediationRun]) -> IntuneFindingConfidence {
    runs.iter().fold(IntuneFindingConfidence::High, |acc, run| {
        super::models::lower_confidence(acc, run.confidence.clone())
    })
}

fn select(
    snapshot: &RemediationSnapshot,
    predicate: impl Fn(&RemediationRun) -> bool,
) -> Vec<&RemediationRun> {
    snapshot.runs.iter().filter(|run| predicate(run)).collect()
}

/// Flatten one evidence list per run into a single citation list.
fn evidence_of(
    runs: &[&RemediationRun],
    pick: impl Fn(&RemediationRun) -> &Vec<IntuneEvidenceRef>,
) -> Vec<IntuneEvidenceRef> {
    runs.iter()
        .flat_map(|run| pick(run).iter().cloned())
        .collect()
}

// ── Rules ───────────────────────────────────────────────────────────────────

/// An expected source that was not usable. Reported first because every other
/// rule's silence has to be read in the light of it.
fn push_missing_expected_source(snapshot: &RemediationSnapshot, findings: &mut Vec<IntuneFinding>) {
    let gaps = snapshot
        .coverage
        .iter()
        .filter(|entry| {
            matches!(entry.family.as_str(), "healthScripts" | "agentExecutor")
                && entry.status != IntuneArtifactStatus::Available
        })
        .collect::<Vec<_>>();
    if gaps.is_empty() {
        return;
    }

    let names = gaps
        .iter()
        .map(|entry| entry.artifact_id.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    push_finding(
        findings,
        "remediation-source-not-collected",
        IntuneFindingSeverity::Info,
        IntuneFindingConfidence::High,
        "An expected remediation source was not collected",
        format!(
            "{names} could not be read, so the absence of a detection or remediation signal in this bundle proves nothing."
        ),
        vec![
            "Collect HealthScripts.log and AgentExecutor.log from the Intune Management Extension log directory and re-run the analysis".to_owned(),
        ],
        Vec::new(),
        gaps.iter().map(|entry| entry.artifact_id.clone()).collect(),
    );
}

fn push_detection_failed(snapshot: &RemediationSnapshot, findings: &mut Vec<IntuneFinding>) {
    let failed = select(snapshot, |run| {
        matches!(
            run.detection.outcome,
            DetectionOutcome::Failed | DetectionOutcome::TimedOut
        )
    });
    if failed.is_empty() {
        return;
    }
    let timed_out = failed
        .iter()
        .any(|run| run.detection.outcome == DetectionOutcome::TimedOut);
    push_finding(
        findings,
        "remediation-detection-failed",
        IntuneFindingSeverity::Error,
        confidence_of(&failed),
        "The detection script did not produce a compliance result",
        format!(
            "Detection {} for {}. Until detection produces a compliance result the agent cannot decide whether remediation is required.",
            if timed_out { "timed out or failed" } else { "failed" },
            labels(&failed)
        ),
        vec![
            "Read the cited detection records for the exit code or launch error".to_owned(),
            "Confirm the detection script runs to completion inside the agent's execution timeout".to_owned(),
        ],
        evidence_of(&failed, |run| &run.detection.evidence),
        Vec::new(),
    );
}

fn push_remediation_failed(snapshot: &RemediationSnapshot, findings: &mut Vec<IntuneFinding>) {
    let failed = select(snapshot, |run| {
        matches!(
            run.remediation.outcome,
            RemediationOutcome::ExitedNonZero
                | RemediationOutcome::FailedToLaunch
                | RemediationOutcome::TimedOut
        )
    });
    if failed.is_empty() {
        return;
    }
    let codes = failed
        .iter()
        .filter_map(|run| run.remediation.exit_code.as_ref())
        .map(|code| code.raw.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let code_text = if codes.is_empty() {
        String::new()
    } else {
        format!(" Exit code(s): {}.", codes.join(", "))
    };

    push_finding(
        findings,
        "remediation-script-failed",
        IntuneFindingSeverity::Error,
        confidence_of(&failed),
        "The remediation script did not complete successfully",
        format!(
            "Remediation did not succeed for {}.{code_text} The device stays in the state detection reported.",
            labels(&failed)
        ),
        vec![
            "Read the cited remediation records for the exit code, launch error, or timeout".to_owned(),
            "Collect the retained remediation output artifact for the cited run".to_owned(),
        ],
        evidence_of(&failed, |run| &run.remediation.evidence),
        Vec::new(),
    );
}

fn push_remediation_ineffective(snapshot: &RemediationSnapshot, findings: &mut Vec<IntuneFinding>) {
    let ineffective = select(snapshot, |run| {
        run.remediation.outcome == RemediationOutcome::Succeeded
            && run.post_remediation.state == PostRemediationState::NonCompliant
    });
    if ineffective.is_empty() {
        return;
    }
    push_finding(
        findings,
        "remediation-did-not-change-state",
        IntuneFindingSeverity::Warning,
        confidence_of(&ineffective),
        "Remediation succeeded but the device is still non-compliant",
        format!(
            "The remediation script exited successfully for {} and the post-remediation detection still reported non-compliant. A successful exit code is not proof the condition was fixed.",
            labels(&ineffective)
        ),
        vec![
            "Compare the cited remediation and post-remediation records".to_owned(),
            "Confirm the remediation script changes the exact condition the detection script tests".to_owned(),
        ],
        ineffective
            .iter()
            .flat_map(|run| {
                run.remediation
                    .evidence
                    .iter()
                    .chain(run.post_remediation.evidence.iter())
                    .cloned()
            })
            .collect(),
        Vec::new(),
    );
}

fn push_reporting_failed(snapshot: &RemediationSnapshot, findings: &mut Vec<IntuneFinding>) {
    let unreported = select(snapshot, |run| {
        matches!(
            run.reporting.state,
            ReportingState::Failed | ReportingState::RetryDeferred
        )
    });
    if unreported.is_empty() {
        return;
    }
    push_finding(
        findings,
        "remediation-result-not-reported",
        IntuneFindingSeverity::Warning,
        confidence_of(&unreported),
        "The run finished locally but its result did not reach Intune",
        format!(
            "Execution completed on the device for {} and the result upload failed or was deferred. The portal will keep showing the previous result until an upload succeeds; this says nothing about whether the scripts themselves worked.",
            labels(&unreported)
        ),
        vec![
            "Read the cited reporting records for the upload error code".to_owned(),
            "Confirm the device can reach the Intune service endpoints".to_owned(),
        ],
        evidence_of(&unreported, |run| &run.reporting.evidence),
        Vec::new(),
    );
}

fn push_reporting_never_observed(snapshot: &RemediationSnapshot, findings: &mut Vec<IntuneFinding>) {
    let silent = select(snapshot, |run| {
        run.is_locally_resolved()
            && matches!(
                run.reporting.state,
                ReportingState::NotStarted | ReportingState::InsufficientEvidence
            )
    });
    if silent.is_empty() {
        return;
    }
    push_finding(
        findings,
        "remediation-reporting-not-observed",
        IntuneFindingSeverity::Info,
        IntuneFindingConfidence::Medium,
        "No reporting record was supplied for a finished run",
        format!(
            "{} finished locally and the supplied evidence contains no upload record. Absence of a reporting record is not evidence that reporting failed.",
            labels(&silent)
        ),
        silent
            .iter()
            .filter_map(|run| run.next_evidence_request.clone())
            .collect(),
        silent
            .iter()
            .flat_map(|run| run.evidence.iter().cloned())
            .collect(),
        Vec::new(),
    );
}

/// Execution records that could not be attributed to a stage or to a run.
fn push_unattributed_execution(snapshot: &RemediationSnapshot, findings: &mut Vec<IntuneFinding>) {
    let unattributed = snapshot
        .observations
        .iter()
        .filter(|observation| {
            matches!(
                observation.event,
                RemediationEvent::Completed | RemediationEvent::TimedOut
            ) && (observation.stage.is_none() || observation.policy_id.is_none())
        })
        .collect::<Vec<_>>();
    if unattributed.is_empty() {
        return;
    }
    push_finding(
        findings,
        "remediation-execution-not-attributable",
        IntuneFindingSeverity::Info,
        IntuneFindingConfidence::Low,
        "An execution record could not be attributed to a stage",
        format!(
            "{} execution record(s) state an outcome without naming the policy, run, or stage they belong to. The same exit code means \"remediation required\" after detection and \"the script failed\" after remediation, so these records were not used to decide any outcome.",
            unattributed.len()
        ),
        vec![
            "Supply the AgentExecutor.log rotation that contains the script path record for the cited execution".to_owned(),
        ],
        unattributed
            .iter()
            .map(|observation| observation.context.evidence_ref.clone())
            .collect(),
        Vec::new(),
    );
}

fn push_malformed_payload(snapshot: &RemediationSnapshot, findings: &mut Vec<IntuneFinding>) {
    let malformed = snapshot
        .observations
        .iter()
        .filter(|observation| observation.context.parse_state == IntuneParseState::Malformed)
        .collect::<Vec<_>>();
    if malformed.is_empty() {
        return;
    }
    push_finding(
        findings,
        "remediation-payload-malformed",
        IntuneFindingSeverity::Warning,
        IntuneFindingConfidence::Low,
        "An embedded result payload could not be parsed",
        format!(
            "{} record(s) carry a structured payload this build could not parse. Nothing was read from them: no policy, no stage, and no outcome, so a run they belonged to may be reported as less complete than it was.",
            malformed.len()
        ),
        vec![
            "Read the cited record verbatim to see the payload the agent wrote".to_owned(),
        ],
        malformed
            .iter()
            .map(|observation| observation.context.evidence_ref.clone())
            .collect(),
        Vec::new(),
    );
}

/// Lines the CCM framer could not turn into a record, which is what a record
/// split across a rotation boundary looks like from inside one file.
fn push_split_record(snapshot: &RemediationSnapshot, findings: &mut Vec<IntuneFinding>) {
    let split = snapshot
        .artifacts
        .iter()
        .filter(|artifact| artifact.unframed_records > 0)
        .collect::<Vec<_>>();
    if split.is_empty() {
        return;
    }
    let total: u32 = split.iter().map(|artifact| artifact.unframed_records).sum();
    push_finding(
        findings,
        "remediation-record-split-across-rotation",
        IntuneFindingSeverity::Info,
        IntuneFindingConfidence::High,
        "A log record was cut off at a rotation boundary",
        format!(
            "{total} line(s) across {} artifact(s) could not be framed into a complete record. Fragments are never joined across files, so whatever those lines said was not used.",
            split.len()
        ),
        vec![
            "Supply the adjacent rotation of the same log so the split record can be read whole".to_owned(),
        ],
        Vec::new(),
        split
            .iter()
            .map(|artifact| artifact.artifact_id.clone())
            .collect(),
    );
}

fn push_retry_observed(snapshot: &RemediationSnapshot, findings: &mut Vec<IntuneFinding>) {
    let retried = select(snapshot, |run| {
        run.detection.attempts > 1 || run.remediation.attempts > 1
    });
    if retried.is_empty() {
        return;
    }
    push_finding(
        findings,
        "remediation-retried",
        IntuneFindingSeverity::Info,
        confidence_of(&retried),
        "A stage ran more than once in the same run",
        format!(
            "More than one attempt was recorded for {}. The reported outcome is the most recent attempt, not the first.",
            labels(&retried)
        ),
        vec!["Read the cited records in order to see what changed between attempts".to_owned()],
        retried
            .iter()
            .flat_map(|run| {
                run.detection
                    .evidence
                    .iter()
                    .chain(run.remediation.evidence.iter())
                    .cloned()
            })
            .collect(),
        Vec::new(),
    );
}

/// A run whose lifecycle simply stops in the supplied evidence.
fn push_incomplete_run(snapshot: &RemediationSnapshot, findings: &mut Vec<IntuneFinding>) {
    let incomplete = select(snapshot, |run| !run.is_locally_resolved());
    if incomplete.is_empty() {
        return;
    }
    push_finding(
        findings,
        "remediation-run-incomplete",
        IntuneFindingSeverity::Info,
        IntuneFindingConfidence::Medium,
        "A run stops before a local outcome",
        format!(
            "{} has no terminal local outcome in the supplied evidence. This is a gap in what was collected, not a failure.",
            labels(&incomplete)
        ),
        incomplete
            .iter()
            .filter_map(|run| run.next_evidence_request.clone())
            .collect(),
        incomplete
            .iter()
            .flat_map(|run| run.evidence.iter().cloned())
            .collect(),
        Vec::new(),
    );
}

fn push_remediation_succeeded(snapshot: &RemediationSnapshot, findings: &mut Vec<IntuneFinding>) {
    let succeeded = select(snapshot, |run| {
        run.detection.outcome == DetectionOutcome::NonCompliant
            && run.remediation.outcome == RemediationOutcome::Succeeded
            && run.post_remediation.state != PostRemediationState::NonCompliant
    });
    if succeeded.is_empty() {
        return;
    }
    let confirmed = succeeded
        .iter()
        .filter(|run| run.post_remediation.state == PostRemediationState::Compliant)
        .count();
    push_finding(
        findings,
        "remediation-succeeded",
        IntuneFindingSeverity::Info,
        confidence_of(&succeeded),
        "Remediation ran and exited successfully",
        format!(
            "Detection reported non-compliant and remediation exited successfully for {}. {} of {} run(s) also have a post-remediation detection confirming the new state.",
            labels(&succeeded),
            confirmed,
            succeeded.len()
        ),
        vec![
            "Confirm the post-remediation detection result, or collect it if it was not supplied".to_owned(),
        ],
        evidence_of(&succeeded, |run| &run.remediation.evidence),
        Vec::new(),
    );
}

fn push_already_compliant(snapshot: &RemediationSnapshot, findings: &mut Vec<IntuneFinding>) {
    let compliant = select(snapshot, |run| {
        run.detection.outcome == DetectionOutcome::Compliant
            && matches!(
                run.remediation.outcome,
                RemediationOutcome::Skipped | RemediationOutcome::NotStarted
            )
    });
    if compliant.is_empty() {
        return;
    }
    push_finding(
        findings,
        "remediation-not-required",
        IntuneFindingSeverity::Info,
        confidence_of(&compliant),
        "Detection reported compliant and remediation was not run",
        format!(
            "Detection reported the desired state for {}, so the remediation script was correctly not executed.",
            labels(&compliant)
        ),
        Vec::new(),
        evidence_of(&compliant, |run| &run.detection.evidence),
        Vec::new(),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intune::apps::windows::remediations::{
        analyze_remediation_bundle, RemediationSourceInput,
    };

    const POLICY: &str = "11111111-2222-3333-4444-555555555555";
    const RUN: &str = "66666666-7777-8888-9999-000000000000";

    fn record(message: &str, time: &str) -> String {
        format!(
            "<![LOG[{message}]LOG]!><time=\"{time}+000\" date=\"03-12-2026\" \
             component=\"HealthScripts\" context=\"\" type=\"1\" thread=\"7\" file=\"\">\n"
        )
    }

    fn analyze(messages: &[(&str, &str)]) -> RemediationSnapshot {
        let content: String = messages
            .iter()
            .map(|(message, time)| record(message, time))
            .collect();
        analyze_remediation_bundle(&[RemediationSourceInput::captured(
            "hs",
            "HealthScripts.log",
            content,
        )])
    }

    fn ids(snapshot: &RemediationSnapshot) -> Vec<String> {
        snapshot
            .findings
            .iter()
            .map(|finding| finding.finding_id.clone())
            .collect()
    }

    #[test]
    fn every_finding_cites_evidence_or_a_coverage_gap() {
        let snapshot = analyze(&[
            (
                &format!("Processing health script policy with id = {POLICY}, RunId = {RUN}"),
                "10:00:00.000",
            ),
            (
                "Detection script completed, exit code = 1, compliance result = NonCompliant",
                "10:00:02.000",
            ),
            ("Start to execute the remediation script", "10:00:03.000"),
            ("Remediation script completed, exit code = 5", "10:00:07.000"),
        ]);
        assert!(!snapshot.findings.is_empty());
        for finding in &snapshot.findings {
            assert!(
                finding.is_evidence_backed(),
                "{} cites nothing",
                finding.finding_id
            );
        }
    }

    #[test]
    fn a_failed_remediation_is_reported_as_an_error() {
        let snapshot = analyze(&[
            (
                &format!("Processing health script policy with id = {POLICY}, RunId = {RUN}"),
                "10:00:00.000",
            ),
            (
                "Detection script completed, exit code = 1, compliance result = NonCompliant",
                "10:00:02.000",
            ),
            ("Remediation script completed, exit code = 5", "10:00:07.000"),
        ]);
        assert!(ids(&snapshot).contains(&"remediation-script-failed".to_owned()));
    }

    #[test]
    fn a_successful_remediation_that_did_not_change_the_state_is_surfaced() {
        let snapshot = analyze(&[
            (
                &format!("Processing health script policy with id = {POLICY}, RunId = {RUN}"),
                "10:00:00.000",
            ),
            (
                "Detection script completed, exit code = 1, compliance result = NonCompliant",
                "10:00:02.000",
            ),
            ("Remediation script completed, exit code = 0", "10:00:07.000"),
            (
                "Post-remediation detection script completed, exit code = 1, compliance result = NonCompliant",
                "10:00:09.000",
            ),
        ]);
        assert!(ids(&snapshot).contains(&"remediation-did-not-change-state".to_owned()));
        assert!(!ids(&snapshot).contains(&"remediation-succeeded".to_owned()));
    }

    #[test]
    fn local_success_and_reporting_failure_are_separate_findings() {
        let snapshot = analyze(&[
            (
                &format!("Processing health script policy with id = {POLICY}, RunId = {RUN}"),
                "10:00:00.000",
            ),
            (
                "Detection script completed, exit code = 1, compliance result = NonCompliant",
                "10:00:02.000",
            ),
            ("Remediation script completed, exit code = 0", "10:00:07.000"),
            (
                "Failed to send the health script result to service, error = 0x80072EE2",
                "10:00:10.000",
            ),
        ]);
        let ids = ids(&snapshot);
        assert!(ids.contains(&"remediation-succeeded".to_owned()));
        assert!(ids.contains(&"remediation-result-not-reported".to_owned()));
    }

    #[test]
    fn findings_are_ordered_deterministically() {
        let snapshot = analyze(&[
            (
                &format!("Processing health script policy with id = {POLICY}, RunId = {RUN}"),
                "10:00:00.000",
            ),
            (
                "Detection script completed, exit code = 0, compliance result = Compliant",
                "10:00:02.000",
            ),
            ("Detection reported compliant, remediation is not required", "10:00:03.000"),
        ]);
        let mut sorted = ids(&snapshot);
        sorted.sort();
        assert_eq!(ids(&snapshot), sorted);
    }
}
