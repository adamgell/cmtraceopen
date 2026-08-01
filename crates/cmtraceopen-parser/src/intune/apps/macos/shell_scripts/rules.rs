//! Diagnostic rules over a reduced shell-script snapshot.
//!
//! One private `push_*` per rule, each emitting only when its triggering
//! evidence is present, so every finding satisfies
//! [`IntuneFinding::is_evidence_backed`].
//!
//! These rules are separate from the package rules for the same reason the
//! reducers are: "timed out" and "could not launch" have no package analogue,
//! and "detection did not confirm the payload" has no script analogue.

use super::models::{
    ShellOutputPresence, ShellReportingState, ShellScriptOutcome, ShellScriptRun,
    ShellScriptSnapshot,
};
use crate::intune::evidence::{
    IntuneEvidenceRef, IntuneFinding, IntuneFindingConfidence, IntuneFindingSeverity,
};

/// Derive stable, read-only findings from an immutable snapshot.
pub fn derive_findings(snapshot: &ShellScriptSnapshot) -> Vec<IntuneFinding> {
    let mut findings = Vec::new();

    push_launch_failure(snapshot, &mut findings);
    push_timeout(snapshot, &mut findings);
    push_nonzero_exit(snapshot, &mut findings);
    push_retry_pending(snapshot, &mut findings);
    push_reporting_failure(snapshot, &mut findings);
    push_output_not_observed(snapshot, &mut findings);
    push_insufficient_evidence(snapshot, &mut findings);
    push_coverage_gap(snapshot, &mut findings);
    push_malformed_records(snapshot, &mut findings);
    push_unknown_grammar(snapshot, &mut findings);
    push_successful_run(snapshot, &mut findings);

    findings
}

/// Build a finding, or refuse to.
///
/// Returning `None` when a finding would cite neither evidence nor a coverage
/// gap makes [`IntuneFinding::is_evidence_backed`] structurally unbreakable
/// rather than a convention each rule has to remember. It is reachable: a
/// bundle with no artifacts at all has an unrecognized grammar and no coverage
/// entries to cite, so the grammar rule would otherwise emit an assertion.
///
/// The argument count mirrors `esp::rules::finding`, the established shape for
/// this constructor across the crate.
#[allow(clippy::too_many_arguments)]
fn finding(
    snapshot: &ShellScriptSnapshot,
    finding_id: &str,
    severity: IntuneFindingSeverity,
    confidence: IntuneFindingConfidence,
    title: &str,
    summary: String,
    recommended_checks: &[&str],
    evidence: Vec<IntuneEvidenceRef>,
    coverage_gap_ids: Vec<String>,
) -> Option<IntuneFinding> {
    if evidence.is_empty() && coverage_gap_ids.is_empty() {
        return None;
    }

    let confidence = if snapshot.grammar_recognized {
        confidence
    } else {
        match confidence {
            IntuneFindingConfidence::High => IntuneFindingConfidence::Medium,
            other => other,
        }
    };

    Some(IntuneFinding {
        finding_id: finding_id.to_owned(),
        severity,
        confidence,
        title: title.to_owned(),
        summary,
        recommended_checks: recommended_checks.iter().map(|s| (*s).to_owned()).collect(),
        evidence,
        coverage_gap_ids,
    })
}

fn evidence_of(runs: &[&ShellScriptRun]) -> Vec<IntuneEvidenceRef> {
    let mut refs = Vec::new();
    for run in runs {
        for reference in &run.evidence {
            if !refs.contains(reference) {
                refs.push(reference.clone());
            }
        }
    }
    refs
}

/// A stable, non-identifying label for a run.
///
/// Run ids are synthetic GUIDs and safe to show. The script display name is
/// tenant configuration and is deliberately never interpolated into a summary,
/// because summaries are exported by default.
fn labels(runs: &[&ShellScriptRun]) -> String {
    let mut ids = runs
        .iter()
        .map(|run| run.key.run_id.clone())
        .collect::<Vec<_>>();
    ids.sort();
    ids.dedup();
    ids.join(", ")
}

fn with_outcome(
    snapshot: &ShellScriptSnapshot,
    outcome: ShellScriptOutcome,
) -> Vec<&ShellScriptRun> {
    snapshot
        .runs
        .iter()
        .filter(|run| run.outcome == outcome)
        .collect()
}

fn push_launch_failure(snapshot: &ShellScriptSnapshot, findings: &mut Vec<IntuneFinding>) {
    let matched = with_outcome(snapshot, ShellScriptOutcome::LaunchFailed);
    if matched.is_empty() {
        return;
    }
    findings.extend(finding(
        snapshot,
        "macos-shell-script-launch-failed",
        IntuneFindingSeverity::Error,
        IntuneFindingConfidence::High,
        "A shell script could not be started",
        format!(
            "The agent failed to launch the script for run(s) {}, so the script never executed. \
             This is distinct from a script that ran and failed.",
            labels(&matched)
        ),
        &[
            "Confirm the script begins with a valid shebang line",
            "Check the script file's permissions and that the interpreter exists on the device",
        ],
        evidence_of(&matched),
        Vec::new(),
    ));
}

fn push_timeout(snapshot: &ShellScriptSnapshot, findings: &mut Vec<IntuneFinding>) {
    let matched = with_outcome(snapshot, ShellScriptOutcome::TimedOut);
    if matched.is_empty() {
        return;
    }
    findings.extend(finding(
        snapshot,
        "macos-shell-script-timed-out",
        IntuneFindingSeverity::Error,
        IntuneFindingConfidence::High,
        "A shell script was stopped before it completed",
        format!(
            "The agent stopped run(s) {} at the configured limit, so any exit status the script \
             would have returned is unknown.",
            labels(&matched)
        ),
        &[
            "Check whether the script waits on user input or a network call that can hang",
            "Compare the script's expected runtime with the configured limit",
        ],
        evidence_of(&matched),
        Vec::new(),
    ));
}

fn push_nonzero_exit(snapshot: &ShellScriptSnapshot, findings: &mut Vec<IntuneFinding>) {
    let matched = with_outcome(snapshot, ShellScriptOutcome::NonZeroExit);
    if matched.is_empty() {
        return;
    }
    findings.extend(finding(
        snapshot,
        "macos-shell-script-nonzero-exit",
        IntuneFindingSeverity::Error,
        IntuneFindingConfidence::High,
        "A shell script ran and exited nonzero",
        format!(
            "Run(s) {} completed with a nonzero exit status. A nonzero exit is an execution \
             outcome, not a root cause.",
            labels(&matched)
        ),
        &[
            "Inspect the cited record for the exact exit status",
            "Collect the script's captured output if the tenant permits it",
        ],
        evidence_of(&matched),
        Vec::new(),
    ));
}

fn push_retry_pending(snapshot: &ShellScriptSnapshot, findings: &mut Vec<IntuneFinding>) {
    let matched = with_outcome(snapshot, ShellScriptOutcome::RetryScheduled);
    if matched.is_empty() {
        return;
    }
    findings.extend(finding(
        snapshot,
        "macos-shell-script-retry-pending",
        IntuneFindingSeverity::Info,
        IntuneFindingConfidence::High,
        "A failed script run has a retry scheduled",
        format!(
            "A failure was followed by a scheduled retry for run(s) {}, so the run is not yet terminal.",
            labels(&matched)
        ),
        &["Collect a later log rotation to see whether the retry succeeded"],
        evidence_of(&matched),
        Vec::new(),
    ));
}

fn push_reporting_failure(snapshot: &ShellScriptSnapshot, findings: &mut Vec<IntuneFinding>) {
    let matched = snapshot
        .runs
        .iter()
        .filter(|run| run.reporting == ShellReportingState::Failed)
        .collect::<Vec<_>>();
    if matched.is_empty() {
        return;
    }
    findings.extend(finding(
        snapshot,
        "macos-shell-script-report-failed",
        IntuneFindingSeverity::Warning,
        IntuneFindingConfidence::High,
        "The device could not report a script result to Intune",
        format!(
            "The agent failed to send the result for run(s) {}. The local outcome is unaffected, \
             but the Intune console may show a stale state.",
            labels(&matched)
        ),
        &[
            "Check device connectivity to the Intune service endpoints",
            "Compare the local outcome with what the console currently reports",
        ],
        evidence_of(&matched),
        Vec::new(),
    ));
}

/// A completed run whose output presence was never established.
///
/// Emitted only for runs that actually completed: for a script that never
/// launched, absent output is expected rather than a gap.
fn push_output_not_observed(snapshot: &ShellScriptSnapshot, findings: &mut Vec<IntuneFinding>) {
    let matched = snapshot
        .runs
        .iter()
        .filter(|run| {
            run.output == ShellOutputPresence::NotObserved
                && matches!(
                    run.outcome,
                    ShellScriptOutcome::Succeeded | ShellScriptOutcome::NonZeroExit
                )
        })
        .collect::<Vec<_>>();
    if matched.is_empty() {
        return;
    }
    findings.extend(finding(
        snapshot,
        "macos-shell-script-output-not-observed",
        IntuneFindingSeverity::Info,
        IntuneFindingConfidence::High,
        "A completed run's output was never established",
        format!(
            "Run(s) {} completed but nothing stated whether output was produced. This is not \
             evidence that the script was silent.",
            labels(&matched)
        ),
        &["Collect the script's retained output artifact if the tenant permits it"],
        evidence_of(&matched),
        snapshot.coverage_gap_ids(),
    ));
}

fn push_insufficient_evidence(snapshot: &ShellScriptSnapshot, findings: &mut Vec<IntuneFinding>) {
    let matched = with_outcome(snapshot, ShellScriptOutcome::InsufficientEvidence);
    if matched.is_empty() {
        return;
    }
    findings.extend(finding(
        snapshot,
        "macos-shell-script-insufficient-evidence",
        IntuneFindingSeverity::Info,
        IntuneFindingConfidence::Medium,
        "A script run was seen but no record decided its outcome",
        format!(
            "Records name run(s) {} but none stated a completion, timeout, or launch failure, \
             so the outcome is unknown rather than failed.",
            labels(&matched)
        ),
        &["Collect the adjacent log rotations covering this execution window"],
        evidence_of(&matched),
        snapshot.coverage_gap_ids(),
    ));
}

fn push_coverage_gap(snapshot: &ShellScriptSnapshot, findings: &mut Vec<IntuneFinding>) {
    let gaps = snapshot.coverage_gap_ids();
    if gaps.is_empty() {
        return;
    }
    findings.extend(finding(
        snapshot,
        "macos-shell-script-coverage-gap",
        IntuneFindingSeverity::Info,
        IntuneFindingConfidence::High,
        "Expected shell-script evidence was not fully collected",
        format!(
            "{} expected artifact(s) were missing, capped, skipped, or unreadable, so the \
             absence of a record in this bundle proves nothing.",
            gaps.len()
        ),
        &["Re-collect the named artifacts and re-run the analysis"],
        Vec::new(),
        gaps,
    ));
}

fn push_malformed_records(snapshot: &ShellScriptSnapshot, findings: &mut Vec<IntuneFinding>) {
    if snapshot.malformed_records == 0 {
        return;
    }
    findings.extend(finding(
        snapshot,
        "macos-shell-script-malformed-records",
        IntuneFindingSeverity::Info,
        IntuneFindingConfidence::High,
        "Some lines did not match the agent record grammar",
        format!(
            "{} line(s) could not be framed. They are retained as malformed rather than \
             discarded, but any signal they carried was not read.",
            snapshot.malformed_records
        ),
        &["Confirm the artifact was captured whole and decoded with the right encoding"],
        Vec::new(),
        snapshot
            .coverage
            .iter()
            .map(|entry| entry.artifact_id.clone())
            .collect(),
    ));
}

fn push_unknown_grammar(snapshot: &ShellScriptSnapshot, findings: &mut Vec<IntuneFinding>) {
    if snapshot.grammar_recognized {
        return;
    }
    let summary = match snapshot.grammar_version.as_deref() {
        Some(version) => format!(
            "The agent declared grammar revision {version}, which this build does not recognize. \
             Message wording may have changed, so every conclusion here is confidence-capped."
        ),
        None => "No agent version banner was present, so the record grammar could not be \
             version-checked and every conclusion here is confidence-capped."
            .to_owned(),
    };
    findings.extend(finding(
        snapshot,
        "macos-shell-script-unknown-agent-grammar",
        IntuneFindingSeverity::Info,
        IntuneFindingConfidence::Medium,
        "The agent log grammar revision is unrecognized",
        summary,
        &["Confirm whether the Intune macOS agent was updated on this device"],
        Vec::new(),
        snapshot
            .coverage
            .iter()
            .map(|entry| entry.artifact_id.clone())
            .collect(),
    ));
}

fn push_successful_run(snapshot: &ShellScriptSnapshot, findings: &mut Vec<IntuneFinding>) {
    let matched = with_outcome(snapshot, ShellScriptOutcome::Succeeded);
    if matched.is_empty() {
        return;
    }
    findings.extend(finding(
        snapshot,
        "macos-shell-script-succeeded",
        IntuneFindingSeverity::Info,
        IntuneFindingConfidence::High,
        "A shell script ran to completion with exit status zero",
        format!("Run(s) {} completed successfully.", labels(&matched)),
        &[],
        evidence_of(&matched),
        Vec::new(),
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intune::apps::macos::pkg::shared::agent_log::{
        MacAgentArtifactInput, MacAgentCaptureState,
    };
    use crate::intune::apps::macos::shell_scripts::reducer::analyze_shell_script_bundle;

    const POLICY: &str = "11111111-1111-4111-8111-111111111111";
    const RUN: &str = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaa1";

    fn snapshot_from(lines: &[String], capture_state: MacAgentCaptureState) -> ShellScriptSnapshot {
        let mut content = String::from(
            "2026-07-29 09:00:00:000 | IntuneMDM-Daemon | I | 1 | Startup | Intune MDM Agent version 2026.07.1 starting\n",
        );
        for entry in lines {
            content.push_str(entry);
            content.push('\n');
        }
        analyze_shell_script_bundle(
            &[MacAgentArtifactInput {
                artifact_id: "daemon-current".to_owned(),
                family: "intuneMdmDaemon".to_owned(),
                file_name: "IntuneMDMDaemon.log".to_owned(),
                sanitized_source_path: None,
                capture_state,
                content: Some(content),
                detail: None,
            }],
            "2026-07-31T00:00:00Z",
        )
    }

    fn line(message: &str) -> String {
        format!(
            "2026-07-29 09:10:00:000 | IntuneMDM-Daemon | I | 10 | ShellScriptManager | {message}"
        )
    }

    #[test]
    fn every_finding_is_evidence_backed() {
        let snapshot = snapshot_from(
            &[
                line(&format!("Failed to launch shell script PolicyId={POLICY} RunId={RUN} Error=-13")),
                "a line that cannot be framed".to_owned(),
            ],
            MacAgentCaptureState::Capped,
        );
        assert!(!snapshot.findings.is_empty());
        for found in &snapshot.findings {
            assert!(
                found.is_evidence_backed(),
                "{} cites neither evidence nor a coverage gap",
                found.finding_id
            );
        }
    }

    #[test]
    fn an_empty_bundle_emits_no_finding_at_all() {
        // The grammar of an empty bundle is unrecognized and there is no
        // coverage entry to cite, so the grammar rule would otherwise emit a
        // finding backed by nothing.
        let snapshot = analyze_shell_script_bundle(&[], "2026-07-31T00:00:00Z");
        assert!(snapshot.findings.is_empty());
        assert!(!snapshot.grammar_recognized);
    }

    #[test]
    fn a_launch_failure_and_a_nonzero_exit_are_distinct_findings() {
        let launch = snapshot_from(
            &[line(&format!(
                "Failed to launch shell script PolicyId={POLICY} RunId={RUN} Error=-13"
            ))],
            MacAgentCaptureState::Captured,
        );
        assert!(launch
            .findings
            .iter()
            .any(|f| f.finding_id == "macos-shell-script-launch-failed"));
        assert!(!launch
            .findings
            .iter()
            .any(|f| f.finding_id == "macos-shell-script-nonzero-exit"));
    }

    #[test]
    fn a_launch_failure_does_not_also_complain_about_missing_output() {
        // The script never ran, so absent output is expected rather than a gap.
        let snapshot = snapshot_from(
            &[line(&format!(
                "Failed to launch shell script PolicyId={POLICY} RunId={RUN} Error=-13"
            ))],
            MacAgentCaptureState::Captured,
        );
        assert!(!snapshot
            .findings
            .iter()
            .any(|f| f.finding_id == "macos-shell-script-output-not-observed"));
    }

    #[test]
    fn an_unrecognized_grammar_caps_confidence_at_medium() {
        let mut content = String::from(
            "2026-07-29 09:00:00:000 | IntuneMDM-Daemon | I | 1 | Startup | Intune MDM Agent version 2031.01.9 starting\n",
        );
        content.push_str(&line(&format!(
            "Shell script finished PolicyId={POLICY} RunId={RUN} ExitCode=3"
        )));
        content.push('\n');
        let snapshot = analyze_shell_script_bundle(
            &[MacAgentArtifactInput {
                artifact_id: "daemon-current".to_owned(),
                family: "intuneMdmDaemon".to_owned(),
                file_name: "IntuneMDMDaemon.log".to_owned(),
                sanitized_source_path: None,
                capture_state: MacAgentCaptureState::Captured,
                content: Some(content),
                detail: None,
            }],
            "2026-07-31T00:00:00Z",
        );
        assert!(snapshot
            .findings
            .iter()
            .all(|f| f.confidence != IntuneFindingConfidence::High));
    }
}
