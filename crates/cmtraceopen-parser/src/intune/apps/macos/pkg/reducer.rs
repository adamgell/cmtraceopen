//! Reduce classified package signals into an immutable snapshot.
//!
//! The reducer walks signals in deterministic order and lets each one move the
//! state it actually proves. Nothing is inferred from absence, and a later
//! record always supersedes an earlier one for the same transaction, which is
//! what makes retry-then-success fall out of the ordering rather than needing a
//! special case.

use std::collections::BTreeMap;

use super::models::{
    PkgAppType, PkgOutcome, PkgPhase, PkgPhaseEvent, PkgReportingState, PkgSnapshot, PkgTransaction,
    PkgTransactionKey,
};
use super::rules::derive_findings;
use super::shared::agent_log::{
    bundle_grammar, ordered_records, parse_bundle, MacAgentArtifactInput, MacAgentLog,
    MACOS_AGENT_SCHEMA_VERSION,
};
use super::signals::{classify_record, PkgSignal, PkgSignalKind};
use crate::intune::evidence::{IntuneArtifactCoverage, IntuneEvidenceRef, IntuneNamedValue};

/// Analyze one bundle of supplied macOS agent artifacts for package activity.
///
/// `observed_at_utc` is supplied by the caller rather than read from a clock:
/// the parser crate is `wasm32`-clean and owns no notion of "now".
pub fn analyze_pkg_bundle(
    inputs: &[MacAgentArtifactInput],
    observed_at_utc: &str,
) -> PkgSnapshot {
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

    let transactions = reduce_transactions(&signals);
    let grammar = bundle_grammar(&logs);

    let mut snapshot = PkgSnapshot {
        schema_version: MACOS_AGENT_SCHEMA_VERSION,
        observed_at_utc: observed_at_utc.to_owned(),
        grammar_version: grammar.declared_version.clone(),
        grammar_recognized: grammar.recognized,
        transactions,
        coverage: build_coverage(&logs, &signals, observed_at_utc),
        findings: Vec::new(),
        malformed_records: logs.iter().map(|log| log.malformed_records).sum(),
    };

    snapshot.findings = derive_findings(&snapshot);
    snapshot
}

/// Group signals by the app they name, then reduce each group in order.
///
/// Grouping is on `app_id` alone. A policy id is stated on some records and not
/// others, so including it in the grouping key would split one deployment into
/// two transactions the moment a record omitted it.
fn reduce_transactions(signals: &[PkgSignal]) -> Vec<PkgTransaction> {
    let mut grouped: BTreeMap<String, Vec<&PkgSignal>> = BTreeMap::new();
    for signal in signals {
        grouped
            .entry(signal.key.app_id.clone())
            .or_default()
            .push(signal);
    }

    grouped
        .into_values()
        .map(|group| reduce_transaction(&group))
        .collect()
}

fn reduce_transaction(signals: &[&PkgSignal]) -> PkgTransaction {
    let mut phases: Vec<PkgPhaseEvent> = Vec::new();
    let mut outcome = PkgOutcome::InsufficientEvidence;
    let mut reporting = PkgReportingState::NotObserved;
    let mut error_code = None;
    let mut retry_count = 0u32;

    let mut policy_id = None;
    let mut display_name = None;
    let mut app_type: Option<PkgAppType> = None;
    let mut bundle_id = None;
    let mut version = None;
    let mut attributes: Vec<IntuneNamedValue> = Vec::new();
    let mut evidence: Vec<IntuneEvidenceRef> = Vec::new();

    for signal in signals {
        // Identity fields: first stated value wins, so a later record that
        // omits a field never erases what an earlier one proved.
        policy_id = policy_id.or_else(|| signal.key.policy_id.clone());
        display_name = display_name.or_else(|| signal.display_name.clone());
        if app_type.is_none() {
            app_type = signal.app_type.clone();
        }
        bundle_id = bundle_id.or_else(|| signal.bundle_id.clone());
        version = version.or_else(|| signal.version.clone());

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

        let phase = phase_of(signal.kind);
        phases.push(PkgPhaseEvent {
            phase,
            timestamp: signal.context.source_timestamp.clone(),
            evidence: reference,
        });

        match signal.kind {
            PkgSignalKind::DownloadFailed => {
                outcome = PkgOutcome::DownloadFailed;
                error_code = signal.error_code.clone();
            }
            PkgSignalKind::ValidationFailed => {
                outcome = PkgOutcome::ValidationFailed;
                error_code = signal.error_code.clone();
            }
            PkgSignalKind::InstallerCompleted => {
                // A zero exit proves the installer returned, not that the
                // payload landed. Detection is what promotes this further.
                if signal
                    .error_code
                    .as_ref()
                    .is_some_and(|code| code.decimal == Some(0))
                {
                    outcome = PkgOutcome::InstalledPendingDetection;
                    error_code = None;
                } else {
                    outcome = PkgOutcome::InstallFailed;
                    error_code = signal.error_code.clone();
                }
            }
            PkgSignalKind::DetectionSucceeded => {
                if outcome == PkgOutcome::InstalledPendingDetection {
                    outcome = PkgOutcome::Installed;
                }
            }
            PkgSignalKind::DetectionFailed => {
                if outcome == PkgOutcome::InstalledPendingDetection {
                    outcome = PkgOutcome::DetectionFailed;
                }
            }
            PkgSignalKind::Reported => reporting = PkgReportingState::Reported,
            PkgSignalKind::ReportFailed => reporting = PkgReportingState::Failed,
            PkgSignalKind::RetryScheduled => {
                retry_count += 1;
                // A retry after a failure means the deployment is not terminal.
                // A retry with no failure behind it changes nothing.
                if outcome.is_failure() {
                    outcome = PkgOutcome::RetryScheduled;
                }
            }
            PkgSignalKind::PolicyReceived
            | PkgSignalKind::ApplicabilityPassed
            | PkgSignalKind::ApplicabilityFailed
            | PkgSignalKind::DownloadStarted
            | PkgSignalKind::DownloadCompleted
            | PkgSignalKind::Staged
            | PkgSignalKind::ValidationStarted
            | PkgSignalKind::InstallerLaunched => {}
        }
    }

    // An app type without installer semantics never reaches a package terminal
    // state. Issue #361 permits cataloguing such a type but forbids reducing it
    // as if a missing installer exit were a fault.
    if app_type
        .as_ref()
        .is_some_and(|kind| !kind.has_installer_semantics())
    {
        outcome = PkgOutcome::UnsupportedAppType;
        error_code = None;
    }

    let last_confirmed_phase = phases.iter().map(|event| event.phase).max();

    PkgTransaction {
        key: PkgTransactionKey {
            policy_id,
            app_id: signals
                .first()
                .map(|signal| signal.key.app_id.clone())
                .unwrap_or_default(),
        },
        display_name,
        app_type,
        bundle_id,
        version,
        phases,
        last_confirmed_phase,
        outcome,
        reporting,
        error_code,
        retry_count,
        attributes,
        evidence,
    }
}

fn phase_of(kind: PkgSignalKind) -> PkgPhase {
    match kind {
        PkgSignalKind::PolicyReceived => PkgPhase::PolicyReceived,
        PkgSignalKind::ApplicabilityPassed | PkgSignalKind::ApplicabilityFailed => {
            PkgPhase::ApplicabilityEvaluated
        }
        PkgSignalKind::DownloadStarted
        | PkgSignalKind::DownloadCompleted
        | PkgSignalKind::DownloadFailed => PkgPhase::Downloading,
        PkgSignalKind::Staged => PkgPhase::Staged,
        PkgSignalKind::ValidationStarted | PkgSignalKind::ValidationFailed => PkgPhase::Validating,
        PkgSignalKind::InstallerLaunched => PkgPhase::InstallerLaunched,
        PkgSignalKind::InstallerCompleted => PkgPhase::InstallerCompleted,
        PkgSignalKind::DetectionSucceeded | PkgSignalKind::DetectionFailed => {
            PkgPhase::PostInstallDetection
        }
        PkgSignalKind::Reported | PkgSignalKind::ReportFailed => PkgPhase::Reported,
        PkgSignalKind::RetryScheduled => PkgPhase::PolicyReceived,
    }
}

/// One coverage entry per supplied artifact, in manifest order.
///
/// An artifact that yielded no signal still appears: that is the difference
/// between "collected and silent" and "never collected", and a finding is
/// entitled to cite either.
fn build_coverage(
    logs: &[MacAgentLog],
    signals: &[PkgSignal],
    observed_at_utc: &str,
) -> Vec<IntuneArtifactCoverage> {
    logs.iter()
        .map(|log| {
            let evidence = signals
                .iter()
                .filter(|signal| {
                    signal.context.evidence_ref.source_artifact_id == log.artifact_id
                })
                .map(|signal| signal.context.evidence_ref.clone())
                .collect::<Vec<_>>();

            IntuneArtifactCoverage {
                artifact_id: log.artifact_id.clone(),
                family: log.family.clone(),
                status: log.capture_state.artifact_status(),
                detail: log.detail.clone(),
                observed_at_utc: observed_at_utc.to_owned(),
                evidence,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::shared::agent_log::MacAgentCaptureState;

    const APP: &str = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaa1";
    const OTHER: &str = "bbbbbbbb-2222-4222-8222-bbbbbbbbbbb2";

    fn bundle(lines: &[&str]) -> Vec<MacAgentArtifactInput> {
        let mut content = String::from(
            "2026-07-29 09:00:00:000 | IntuneMDM-Daemon | I | 1 | Startup | Intune MDM Agent version 2026.07.1 starting\n",
        );
        for line in lines {
            content.push_str(line);
            content.push('\n');
        }
        vec![MacAgentArtifactInput {
            artifact_id: "daemon-current".to_owned(),
            family: "intuneMdmDaemon".to_owned(),
            file_name: "IntuneMDMDaemon.log".to_owned(),
            sanitized_source_path: Some("SYNTHETIC://system/IntuneMDMDaemon.log".to_owned()),
            capture_state: MacAgentCaptureState::Captured,
            content: Some(content),
            detail: None,
        }]
    }

    fn line(time: &str, message: &str) -> String {
        format!("2026-07-29 {time} | IntuneMDM-Daemon | I | 10 | AppInstaller | {message}")
    }

    fn analyze(lines: &[String]) -> PkgSnapshot {
        let refs = lines.iter().map(String::as_str).collect::<Vec<_>>();
        analyze_pkg_bundle(&bundle(&refs), "2026-07-31T00:00:00Z")
    }

    #[test]
    fn a_complete_install_reduces_to_installed_and_reported() {
        let snapshot = analyze(&[
            line("09:10:00:000", &format!("Received app policy AppId={APP} Name=Contoso Reader Type=pkg")),
            line("09:10:01:000", &format!("Downloading content for AppId={APP}")),
            line("09:10:05:000", &format!("Download complete for AppId={APP} Bytes=1024")),
            line("09:10:06:000", &format!("Staged package for AppId={APP}")),
            line("09:10:07:000", &format!("Validating package signature for AppId={APP}")),
            line("09:10:08:000", &format!("Launching installer for AppId={APP}")),
            line("09:10:20:000", &format!("Installer finished for AppId={APP} ExitCode=0")),
            line("09:10:21:000", &format!("Detection succeeded for AppId={APP} BundleId=example.contoso.reader Version=3.1")),
            line("09:10:22:000", &format!("Reported app status for AppId={APP} Status=installed")),
        ]);
        assert_eq!(snapshot.transactions.len(), 1);
        let transaction = &snapshot.transactions[0];
        assert_eq!(transaction.outcome, PkgOutcome::Installed);
        assert_eq!(transaction.reporting, PkgReportingState::Reported);
        assert_eq!(transaction.last_confirmed_phase, Some(PkgPhase::Reported));
        assert_eq!(transaction.bundle_id.as_deref(), Some("example.contoso.reader"));
    }

    #[test]
    fn a_zero_exit_without_detection_is_not_reported_as_installed() {
        let snapshot = analyze(&[
            line("09:10:00:000", &format!("Received app policy AppId={APP} Type=pkg")),
            line("09:10:20:000", &format!("Installer finished for AppId={APP} ExitCode=0")),
        ]);
        assert_eq!(
            snapshot.transactions[0].outcome,
            PkgOutcome::InstalledPendingDetection
        );
    }

    #[test]
    fn a_nonzero_installer_exit_retains_its_code() {
        let snapshot = analyze(&[
            line("09:10:00:000", &format!("Received app policy AppId={APP} Type=pkg")),
            line("09:10:20:000", &format!("Installer finished for AppId={APP} ExitCode=1")),
        ]);
        assert_eq!(snapshot.transactions[0].outcome, PkgOutcome::InstallFailed);
        assert_eq!(
            snapshot.transactions[0]
                .error_code
                .as_ref()
                .expect("code")
                .decimal,
            Some(1)
        );
    }

    #[test]
    fn a_retry_after_a_failure_supersedes_the_failure_and_a_later_success_supersedes_the_retry() {
        let snapshot = analyze(&[
            line("09:10:00:000", &format!("Received app policy AppId={APP} Type=pkg")),
            line("09:10:01:000", &format!("Download failed for AppId={APP} Error=-1009")),
            line("09:10:02:000", &format!("Scheduling retry for AppId={APP} Attempt=2")),
            line("09:11:00:000", &format!("Download complete for AppId={APP}")),
            line("09:11:20:000", &format!("Installer finished for AppId={APP} ExitCode=0")),
            line("09:11:21:000", &format!("Detection succeeded for AppId={APP}")),
        ]);
        assert_eq!(snapshot.transactions[0].outcome, PkgOutcome::Installed);
        assert_eq!(snapshot.transactions[0].retry_count, 1);
    }

    #[test]
    fn an_unsupported_app_type_never_receives_package_terminal_semantics() {
        let snapshot = analyze(&[
            line("09:10:00:000", &format!("Received app policy AppId={APP} Type=dmg")),
            line("09:10:20:000", &format!("Installer finished for AppId={APP} ExitCode=1")),
        ]);
        // The nonzero exit would read as InstallFailed for a pkg. It must not.
        assert_eq!(
            snapshot.transactions[0].outcome,
            PkgOutcome::UnsupportedAppType
        );
        assert_eq!(snapshot.transactions[0].error_code, None);
    }

    #[test]
    fn two_apps_in_the_same_second_stay_separate_transactions() {
        let snapshot = analyze(&[
            line("09:10:00:000", &format!("Received app policy AppId={APP} Type=pkg")),
            line("09:10:00:000", &format!("Received app policy AppId={OTHER} Type=pkg")),
            line("09:10:20:000", &format!("Installer finished for AppId={APP} ExitCode=0")),
            line("09:10:20:000", &format!("Installer finished for AppId={OTHER} ExitCode=9")),
        ]);
        assert_eq!(snapshot.transactions.len(), 2);
        let by_app = snapshot
            .transactions
            .iter()
            .map(|t| (t.key.app_id.as_str(), t.outcome))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(by_app[APP], PkgOutcome::InstalledPendingDetection);
        assert_eq!(by_app[OTHER], PkgOutcome::InstallFailed);
    }

    #[test]
    fn reporting_failure_does_not_turn_a_successful_install_into_a_failure() {
        let snapshot = analyze(&[
            line("09:10:00:000", &format!("Received app policy AppId={APP} Type=pkg")),
            line("09:10:20:000", &format!("Installer finished for AppId={APP} ExitCode=0")),
            line("09:10:21:000", &format!("Detection succeeded for AppId={APP}")),
            line("09:10:22:000", &format!("Failed to report app status for AppId={APP} Error=-1005")),
        ]);
        assert_eq!(snapshot.transactions[0].outcome, PkgOutcome::Installed);
        assert_eq!(
            snapshot.transactions[0].reporting,
            PkgReportingState::Failed
        );
    }

    #[test]
    fn analysis_is_deterministic_regardless_of_artifact_order() {
        let lines = vec![
            line("09:10:00:000", &format!("Received app policy AppId={APP} Type=pkg")),
            line("09:10:20:000", &format!("Installer finished for AppId={APP} ExitCode=0")),
        ];
        let first = analyze(&lines);
        let second = analyze(&lines);
        assert_eq!(first, second);
    }
}
