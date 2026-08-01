//! Reduce classified shell-script signals into an immutable snapshot.
//!
//! Structurally parallel to the package reducer but deliberately a separate
//! state machine: the phases differ, the terminal set differs, and a script has
//! an execution context and an output-presence question that a package does not.

use std::collections::BTreeMap;

use super::models::{
    ShellExecutionContext, ShellOutputPresence, ShellReportingState, ShellScriptOutcome,
    ShellScriptPhase, ShellScriptPhaseEvent, ShellScriptRun, ShellScriptRunKey, ShellScriptSnapshot,
};
use super::rules::derive_findings;
use super::signals::{classify_record, ShellSignal, ShellSignalKind};
use crate::intune::apps::macos::pkg::shared::agent_log::{
    bundle_grammar, ordered_records, parse_bundle, MacAgentArtifactInput, MacAgentLog,
    MACOS_AGENT_SCHEMA_VERSION,
};
use crate::intune::evidence::{IntuneArtifactCoverage, IntuneEvidenceRef, IntuneNamedValue};

/// Analyze one bundle of supplied macOS agent artifacts for script activity.
///
/// `observed_at_utc` is supplied by the caller: the parser crate is
/// `wasm32`-clean and owns no notion of "now".
pub fn analyze_shell_script_bundle(
    inputs: &[MacAgentArtifactInput],
    observed_at_utc: &str,
) -> ShellScriptSnapshot {
    let logs = parse_bundle(inputs);
    let records = ordered_records(&logs);

    let path_by_artifact = logs
        .iter()
        .map(|log| {
            (
                log.artifact_id.as_str(),
                log.sanitized_source_path.as_deref(),
            )
        })
        .collect::<BTreeMap<_, _>>();

    let signals = records
        .iter()
        .filter_map(|record| {
            classify_record(
                record,
                path_by_artifact
                    .get(record.artifact_id.as_str())
                    .copied()
                    .flatten(),
                observed_at_utc,
            )
        })
        .collect::<Vec<_>>();

    let grammar = bundle_grammar(&logs);
    let mut snapshot = ShellScriptSnapshot {
        schema_version: MACOS_AGENT_SCHEMA_VERSION,
        observed_at_utc: observed_at_utc.to_owned(),
        grammar_version: grammar.declared_version.clone(),
        grammar_recognized: grammar.recognized,
        runs: reduce_runs(&signals),
        coverage: build_coverage(&logs, &signals, observed_at_utc),
        findings: Vec::new(),
        malformed_records: logs.iter().map(|log| log.malformed_records).sum(),
    };

    snapshot.findings = derive_findings(&snapshot);
    snapshot
}

/// Group signals by the full run key, then reduce each group in order.
///
/// The key is `(policy_id, run_id)`. Grouping on policy alone would merge two
/// runs of the same script, which is precisely the same-minute case issue #361
/// calls out.
fn reduce_runs(signals: &[ShellSignal]) -> Vec<ShellScriptRun> {
    let mut grouped: BTreeMap<ShellScriptRunKey, Vec<&ShellSignal>> = BTreeMap::new();
    for signal in signals {
        grouped.entry(signal.key.clone()).or_default().push(signal);
    }

    grouped
        .into_iter()
        .map(|(key, group)| reduce_run(key, &group))
        .collect()
}

fn reduce_run(key: ShellScriptRunKey, signals: &[&ShellSignal]) -> ShellScriptRun {
    let mut phases: Vec<ShellScriptPhaseEvent> = Vec::new();
    let mut outcome = ShellScriptOutcome::InsufficientEvidence;
    let mut reporting = ShellReportingState::NotObserved;
    let mut output = ShellOutputPresence::NotObserved;
    let mut exit_code = None;
    let mut error_code = None;
    let mut timeout_seconds = None;
    let mut retry_count = 0u32;

    let mut display_name = None;
    let mut execution_context: Option<ShellExecutionContext> = None;
    let mut attributes: Vec<IntuneNamedValue> = Vec::new();
    let mut evidence: Vec<IntuneEvidenceRef> = Vec::new();

    for signal in signals {
        display_name = display_name.or_else(|| signal.display_name.clone());
        if execution_context.is_none() {
            execution_context = signal.execution_context.clone();
        }
        timeout_seconds = timeout_seconds.or(signal.timeout_seconds);

        for attribute in &signal.attributes {
            if !attributes
                .iter()
                .any(|existing| existing.name == attribute.name)
            {
                attributes.push(attribute.clone());
            }
        }
        let reference = signal.context.evidence_ref.clone();
        if !evidence.contains(&reference) {
            evidence.push(reference.clone());
        }

        phases.push(ShellScriptPhaseEvent {
            phase: phase_of(signal.kind),
            timestamp: signal.context.source_timestamp.clone(),
            evidence: reference,
        });

        match signal.kind {
            ShellSignalKind::LaunchFailed => {
                outcome = ShellScriptOutcome::LaunchFailed;
                error_code = signal.error_code.clone();
            }
            ShellSignalKind::TimedOut => {
                outcome = ShellScriptOutcome::TimedOut;
                error_code = signal.error_code.clone();
            }
            ShellSignalKind::Completed => {
                // A completion record is the only thing that can state an exit
                // status, and the status alone decides success or failure.
                exit_code = signal.exit_code.clone();
                outcome = if signal
                    .exit_code
                    .as_ref()
                    .is_some_and(|code| code.decimal == Some(0))
                {
                    ShellScriptOutcome::Succeeded
                } else {
                    ShellScriptOutcome::NonZeroExit
                };
            }
            ShellSignalKind::OutputCaptured => output = ShellOutputPresence::Captured,
            ShellSignalKind::OutputEmpty => output = ShellOutputPresence::ExplicitlyEmpty,
            ShellSignalKind::Reported => reporting = ShellReportingState::Reported,
            ShellSignalKind::ReportFailed => reporting = ShellReportingState::Failed,
            ShellSignalKind::RetryScheduled => {
                retry_count += 1;
                if outcome.is_failure() {
                    outcome = ShellScriptOutcome::RetryScheduled;
                }
            }
            ShellSignalKind::PolicyReceived
            | ShellSignalKind::Scheduled
            | ShellSignalKind::Launched => {}
        }
    }

    let last_confirmed_phase = phases.iter().map(|event| event.phase).max();

    ShellScriptRun {
        key,
        display_name,
        execution_context,
        phases,
        last_confirmed_phase,
        outcome,
        reporting,
        output,
        exit_code,
        error_code,
        timeout_seconds,
        retry_count,
        attributes,
        evidence,
    }
}

fn phase_of(kind: ShellSignalKind) -> ShellScriptPhase {
    match kind {
        ShellSignalKind::PolicyReceived => ShellScriptPhase::PolicyReceived,
        ShellSignalKind::Scheduled | ShellSignalKind::RetryScheduled => ShellScriptPhase::Scheduled,
        ShellSignalKind::Launched | ShellSignalKind::LaunchFailed => ShellScriptPhase::Launched,
        ShellSignalKind::OutputCaptured | ShellSignalKind::OutputEmpty => {
            ShellScriptPhase::OutputCaptured
        }
        ShellSignalKind::Completed | ShellSignalKind::TimedOut => ShellScriptPhase::Completed,
        ShellSignalKind::Reported | ShellSignalKind::ReportFailed => ShellScriptPhase::Reported,
    }
}

fn build_coverage(
    logs: &[MacAgentLog],
    signals: &[ShellSignal],
    observed_at_utc: &str,
) -> Vec<IntuneArtifactCoverage> {
    logs.iter()
        .map(|log| IntuneArtifactCoverage {
            artifact_id: log.artifact_id.clone(),
            family: log.family.clone(),
            status: log.capture_state.artifact_status(),
            detail: log.detail.clone(),
            observed_at_utc: observed_at_utc.to_owned(),
            evidence: signals
                .iter()
                .filter(|signal| {
                    signal.context.evidence_ref.source_artifact_id == log.artifact_id
                })
                .map(|signal| signal.context.evidence_ref.clone())
                .collect(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intune::apps::macos::pkg::shared::agent_log::MacAgentCaptureState;

    const POLICY: &str = "11111111-1111-4111-8111-111111111111";
    const RUN_A: &str = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaa1";
    const RUN_B: &str = "bbbbbbbb-2222-4222-8222-bbbbbbbbbbb2";

    fn line(process: &str, time: &str, message: &str) -> String {
        format!("2026-07-29 {time} | {process} | I | 10 | ShellScriptManager | {message}")
    }

    fn analyze(process: &str, lines: &[String]) -> ShellScriptSnapshot {
        let mut content = format!(
            "2026-07-29 09:00:00:000 | {process} | I | 1 | Startup | Intune MDM Agent version 2026.07.1 starting\n"
        );
        for entry in lines {
            content.push_str(entry);
            content.push('\n');
        }
        analyze_shell_script_bundle(
            &[MacAgentArtifactInput {
                artifact_id: "agent-current".to_owned(),
                family: "intuneMdmAgent".to_owned(),
                file_name: if process == "IntuneMDM-Agent" {
                    "IntuneMDMAgent.log".to_owned()
                } else {
                    "IntuneMDMDaemon.log".to_owned()
                },
                sanitized_source_path: None,
                capture_state: MacAgentCaptureState::Captured,
                content: Some(content),
                detail: None,
            }],
            "2026-07-31T00:00:00Z",
        )
    }

    #[test]
    fn a_successful_system_run_reduces_to_succeeded() {
        let snapshot = analyze(
            "IntuneMDM-Daemon",
            &[
                line("IntuneMDM-Daemon", "09:10:00:000", &format!("Received shell script policy PolicyId={POLICY} RunId={RUN_A} Name=Set Wallpaper")),
                line("IntuneMDM-Daemon", "09:10:01:000", &format!("Launching shell script PolicyId={POLICY} RunId={RUN_A} Context=system")),
                line("IntuneMDM-Daemon", "09:10:05:000", &format!("Captured stdout for PolicyId={POLICY} RunId={RUN_A} Bytes=42")),
                line("IntuneMDM-Daemon", "09:10:06:000", &format!("Shell script finished PolicyId={POLICY} RunId={RUN_A} ExitCode=0")),
                line("IntuneMDM-Daemon", "09:10:07:000", &format!("Reported shell script result PolicyId={POLICY} RunId={RUN_A} Status=success")),
            ],
        );
        assert_eq!(snapshot.runs.len(), 1);
        let run = &snapshot.runs[0];
        assert_eq!(run.outcome, ShellScriptOutcome::Succeeded);
        assert_eq!(
            run.execution_context,
            Some(ShellExecutionContext::System)
        );
        assert_eq!(run.output, ShellOutputPresence::Captured);
        assert_eq!(run.reporting, ShellReportingState::Reported);
    }

    #[test]
    fn a_user_run_is_distinguished_by_its_context() {
        let snapshot = analyze(
            "IntuneMDM-Agent",
            &[line(
                "IntuneMDM-Agent",
                "09:10:01:000",
                &format!("Launching shell script PolicyId={POLICY} RunId={RUN_A} Context=user"),
            )],
        );
        assert_eq!(
            snapshot.runs[0].execution_context,
            Some(ShellExecutionContext::User)
        );
    }

    #[test]
    fn a_nonzero_exit_is_an_outcome_and_keeps_its_status() {
        let snapshot = analyze(
            "IntuneMDM-Daemon",
            &[line(
                "IntuneMDM-Daemon",
                "09:10:06:000",
                &format!("Shell script finished PolicyId={POLICY} RunId={RUN_A} ExitCode=3"),
            )],
        );
        assert_eq!(snapshot.runs[0].outcome, ShellScriptOutcome::NonZeroExit);
        assert_eq!(
            snapshot.runs[0].exit_code.as_ref().expect("code").decimal,
            Some(3)
        );
    }

    #[test]
    fn a_launch_failure_never_reports_an_exit_status() {
        let snapshot = analyze(
            "IntuneMDM-Daemon",
            &[line(
                "IntuneMDM-Daemon",
                "09:10:01:000",
                &format!("Failed to launch shell script PolicyId={POLICY} RunId={RUN_A} Error=-13"),
            )],
        );
        assert_eq!(snapshot.runs[0].outcome, ShellScriptOutcome::LaunchFailed);
        assert_eq!(snapshot.runs[0].exit_code, None);
    }

    #[test]
    fn a_timeout_is_distinct_from_a_nonzero_exit() {
        let snapshot = analyze(
            "IntuneMDM-Daemon",
            &[line(
                "IntuneMDM-Daemon",
                "09:20:00:000",
                &format!("Shell script timed out PolicyId={POLICY} RunId={RUN_A} TimeoutSeconds=600"),
            )],
        );
        assert_eq!(snapshot.runs[0].outcome, ShellScriptOutcome::TimedOut);
        assert_eq!(snapshot.runs[0].timeout_seconds, Some(600));
    }

    #[test]
    fn a_retry_after_a_failure_is_superseded_by_a_later_success() {
        let snapshot = analyze(
            "IntuneMDM-Daemon",
            &[
                line("IntuneMDM-Daemon", "09:10:06:000", &format!("Shell script finished PolicyId={POLICY} RunId={RUN_A} ExitCode=3")),
                line("IntuneMDM-Daemon", "09:10:07:000", &format!("Scheduling retry for PolicyId={POLICY} RunId={RUN_A} Attempt=2")),
                line("IntuneMDM-Daemon", "09:15:06:000", &format!("Shell script finished PolicyId={POLICY} RunId={RUN_A} ExitCode=0")),
            ],
        );
        assert_eq!(snapshot.runs[0].outcome, ShellScriptOutcome::Succeeded);
        assert_eq!(snapshot.runs[0].retry_count, 1);
    }

    #[test]
    fn two_runs_of_the_same_policy_in_the_same_minute_stay_separate() {
        // They share a policy, a component, a thread, and a timestamp. Only the
        // run id tells them apart, which is exactly why it is in the key.
        let snapshot = analyze(
            "IntuneMDM-Daemon",
            &[
                line("IntuneMDM-Daemon", "09:10:06:000", &format!("Shell script finished PolicyId={POLICY} RunId={RUN_A} ExitCode=0")),
                line("IntuneMDM-Daemon", "09:10:06:000", &format!("Shell script finished PolicyId={POLICY} RunId={RUN_B} ExitCode=7")),
            ],
        );
        assert_eq!(snapshot.runs.len(), 2);
        let outcomes = snapshot
            .runs
            .iter()
            .map(|run| (run.key.run_id.as_str(), run.outcome))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(outcomes[RUN_A], ShellScriptOutcome::Succeeded);
        assert_eq!(outcomes[RUN_B], ShellScriptOutcome::NonZeroExit);
    }

    #[test]
    fn a_missing_output_record_is_not_read_as_proof_of_silence() {
        let snapshot = analyze(
            "IntuneMDM-Daemon",
            &[line(
                "IntuneMDM-Daemon",
                "09:10:06:000",
                &format!("Shell script finished PolicyId={POLICY} RunId={RUN_A} ExitCode=0"),
            )],
        );
        assert_eq!(snapshot.runs[0].output, ShellOutputPresence::NotObserved);
    }

    #[test]
    fn reporting_failure_does_not_turn_a_successful_run_into_a_failure() {
        let snapshot = analyze(
            "IntuneMDM-Daemon",
            &[
                line("IntuneMDM-Daemon", "09:10:06:000", &format!("Shell script finished PolicyId={POLICY} RunId={RUN_A} ExitCode=0")),
                line("IntuneMDM-Daemon", "09:10:07:000", &format!("Failed to report shell script result PolicyId={POLICY} RunId={RUN_A} Error=-1005")),
            ],
        );
        assert_eq!(snapshot.runs[0].outcome, ShellScriptOutcome::Succeeded);
        assert_eq!(snapshot.runs[0].reporting, ShellReportingState::Failed);
    }

    #[test]
    fn a_package_record_never_becomes_a_script_run() {
        let snapshot = analyze(
            "IntuneMDM-Daemon",
            &[format!(
                "2026-07-29 09:10:06:000 | IntuneMDM-Daemon | I | 10 | AppInstaller | Installer finished for AppId={RUN_A} ExitCode=0"
            )],
        );
        assert!(snapshot.runs.is_empty());
    }
}
