//! Diagnostic rules over a reduced package snapshot.
//!
//! One private `push_*` per rule, each emitting only when its triggering
//! evidence is present. Every finding therefore carries at least one evidence
//! reference or an explicit coverage-gap identifier, which
//! [`IntuneFinding::is_evidence_backed`] asserts.
//!
//! Confidence is capped at [`IntuneFindingConfidence::Medium`] whenever the
//! bundle's agent grammar is unrecognized: the reducer keys on message wording,
//! and an unknown revision may have reworded the record that would have changed
//! the conclusion.

use super::models::{PkgOutcome, PkgReportingState, PkgSnapshot, PkgTransaction};
use crate::intune::evidence::{
    IntuneEvidenceRef, IntuneFinding, IntuneFindingConfidence, IntuneFindingSeverity,
};

/// Derive stable, read-only findings from an immutable snapshot.
pub fn derive_findings(snapshot: &PkgSnapshot) -> Vec<IntuneFinding> {
    let mut findings = Vec::new();

    push_download_failure(snapshot, &mut findings);
    push_validation_failure(snapshot, &mut findings);
    push_installer_failure(snapshot, &mut findings);
    push_detection_missing(snapshot, &mut findings);
    push_detection_failure(snapshot, &mut findings);
    push_reporting_failure(snapshot, &mut findings);
    push_retry_pending(snapshot, &mut findings);
    push_unsupported_app_type(snapshot, &mut findings);
    push_insufficient_evidence(snapshot, &mut findings);
    push_coverage_gap(snapshot, &mut findings);
    push_malformed_records(snapshot, &mut findings);
    push_unknown_grammar(snapshot, &mut findings);
    push_successful_install(snapshot, &mut findings);

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
    snapshot: &PkgSnapshot,
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

/// A transaction's own evidence, which is what any per-transaction rule cites.
fn evidence_of(transactions: &[&PkgTransaction]) -> Vec<IntuneEvidenceRef> {
    let mut refs = Vec::new();
    for transaction in transactions {
        for reference in &transaction.evidence {
            if !refs.contains(reference) {
                refs.push(reference.clone());
            }
        }
    }
    refs
}

/// A stable, non-identifying label for a transaction.
///
/// The app id is a synthetic GUID and safe to show; the display name is tenant
/// catalog data and is deliberately not interpolated into a finding summary,
/// because summaries are exported by default.
fn labels(transactions: &[&PkgTransaction]) -> String {
    let mut ids = transactions
        .iter()
        .map(|transaction| transaction.key.app_id.clone())
        .collect::<Vec<_>>();
    ids.sort();
    ids.dedup();
    ids.join(", ")
}

fn with_outcome(snapshot: &PkgSnapshot, outcome: PkgOutcome) -> Vec<&PkgTransaction> {
    snapshot
        .transactions
        .iter()
        .filter(|transaction| transaction.outcome == outcome)
        .collect()
}

fn push_download_failure(snapshot: &PkgSnapshot, findings: &mut Vec<IntuneFinding>) {
    let matched = with_outcome(snapshot, PkgOutcome::DownloadFailed);
    if matched.is_empty() {
        return;
    }
    findings.extend(finding(
        snapshot,
        "macos-pkg-download-failed",
        IntuneFindingSeverity::Error,
        IntuneFindingConfidence::High,
        "Package content could not be downloaded",
        format!(
            "Content download failed and no later record superseded it for: {}.",
            labels(&matched)
        ),
        &[
            "Check network egress and proxy rules for the content delivery endpoint",
            "Confirm the app's content version is still published in Intune",
        ],
        evidence_of(&matched),
        Vec::new(),
    ));
}

fn push_validation_failure(snapshot: &PkgSnapshot, findings: &mut Vec<IntuneFinding>) {
    let matched = with_outcome(snapshot, PkgOutcome::ValidationFailed);
    if matched.is_empty() {
        return;
    }
    findings.extend(finding(
        snapshot,
        "macos-pkg-validation-failed",
        IntuneFindingSeverity::Error,
        IntuneFindingConfidence::High,
        "Package signature or integrity validation failed",
        format!(
            "The staged package failed validation before the installer ran for: {}.",
            labels(&matched)
        ),
        &[
            "Confirm the uploaded package is signed by a Developer ID installer certificate",
            "Re-upload the package if the stored content may be truncated",
        ],
        evidence_of(&matched),
        Vec::new(),
    ));
}

fn push_installer_failure(snapshot: &PkgSnapshot, findings: &mut Vec<IntuneFinding>) {
    let matched = with_outcome(snapshot, PkgOutcome::InstallFailed);
    if matched.is_empty() {
        return;
    }
    findings.extend(finding(
        snapshot,
        "macos-pkg-installer-nonzero-exit",
        IntuneFindingSeverity::Error,
        IntuneFindingConfidence::High,
        "The installer exited with a nonzero status",
        format!(
            "The macOS installer ran and returned a nonzero status for: {}. \
             A nonzero exit is an execution outcome, not a root cause.",
            labels(&matched)
        ),
        &[
            "Inspect the cited record for the exact exit status",
            "Review the package's preinstall and postinstall scripts",
        ],
        evidence_of(&matched),
        Vec::new(),
    ));
}

fn push_detection_missing(snapshot: &PkgSnapshot, findings: &mut Vec<IntuneFinding>) {
    let matched = with_outcome(snapshot, PkgOutcome::InstalledPendingDetection);
    if matched.is_empty() {
        return;
    }
    findings.extend(finding(
        snapshot,
        "macos-pkg-detection-not-observed",
        IntuneFindingSeverity::Warning,
        IntuneFindingConfidence::High,
        "The installer succeeded but nothing confirmed the app is present",
        format!(
            "The installer exited zero for {} and no post-install detection record followed. \
             A zero exit proves the installer returned, not that the payload landed.",
            labels(&matched)
        ),
        &[
            "Collect a later log rotation in case detection ran after this capture",
            "Verify the app's detection rule matches the installed bundle id and version",
        ],
        evidence_of(&matched),
        snapshot.coverage_gap_ids(),
    ));
}

fn push_detection_failure(snapshot: &PkgSnapshot, findings: &mut Vec<IntuneFinding>) {
    let matched = with_outcome(snapshot, PkgOutcome::DetectionFailed);
    if matched.is_empty() {
        return;
    }
    findings.extend(finding(
        snapshot,
        "macos-pkg-detection-failed",
        IntuneFindingSeverity::Error,
        IntuneFindingConfidence::High,
        "Post-install detection did not find the app",
        format!(
            "The installer exited zero but detection explicitly failed for: {}.",
            labels(&matched)
        ),
        &["Compare the detection rule with the bundle actually installed"],
        evidence_of(&matched),
        Vec::new(),
    ));
}

fn push_reporting_failure(snapshot: &PkgSnapshot, findings: &mut Vec<IntuneFinding>) {
    let matched = snapshot
        .transactions
        .iter()
        .filter(|transaction| transaction.reporting == PkgReportingState::Failed)
        .collect::<Vec<_>>();
    if matched.is_empty() {
        return;
    }
    findings.extend(finding(
        snapshot,
        "macos-pkg-report-failed",
        IntuneFindingSeverity::Warning,
        IntuneFindingConfidence::High,
        "The device could not report the app result to Intune",
        format!(
            "The agent failed to send the app status for {}. The local outcome is unaffected, \
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

fn push_retry_pending(snapshot: &PkgSnapshot, findings: &mut Vec<IntuneFinding>) {
    let matched = with_outcome(snapshot, PkgOutcome::RetryScheduled);
    if matched.is_empty() {
        return;
    }
    findings.extend(finding(
        snapshot,
        "macos-pkg-retry-pending",
        IntuneFindingSeverity::Info,
        IntuneFindingConfidence::High,
        "A failed deployment has a retry scheduled",
        format!(
            "A failure was followed by a scheduled retry for {}, so the deployment is not yet terminal.",
            labels(&matched)
        ),
        &["Collect a later log rotation to see whether the retry succeeded"],
        evidence_of(&matched),
        Vec::new(),
    ));
}

fn push_unsupported_app_type(snapshot: &PkgSnapshot, findings: &mut Vec<IntuneFinding>) {
    let matched = with_outcome(snapshot, PkgOutcome::UnsupportedAppType);
    if matched.is_empty() {
        return;
    }
    findings.extend(finding(
        snapshot,
        "macos-pkg-unsupported-app-type",
        IntuneFindingSeverity::Info,
        IntuneFindingConfidence::High,
        "The policy names an app type this analyzer does not model",
        format!(
            "The app type declared for {} is not a package install, so package terminal \
             semantics were deliberately not applied to it.",
            labels(&matched)
        ),
        &["Evaluate this deployment with the workflow that owns its app type"],
        evidence_of(&matched),
        Vec::new(),
    ));
}

fn push_insufficient_evidence(snapshot: &PkgSnapshot, findings: &mut Vec<IntuneFinding>) {
    let matched = with_outcome(snapshot, PkgOutcome::InsufficientEvidence);
    if matched.is_empty() {
        return;
    }
    findings.extend(finding(
        snapshot,
        "macos-pkg-insufficient-evidence",
        IntuneFindingSeverity::Info,
        IntuneFindingConfidence::Medium,
        "A deployment was seen but no record decided its outcome",
        format!(
            "Records name {} but none stated an installer result, so the outcome is unknown \
             rather than failed.",
            labels(&matched)
        ),
        &["Collect the adjacent log rotations covering this deployment window"],
        evidence_of(&matched),
        snapshot.coverage_gap_ids(),
    ));
}

fn push_coverage_gap(snapshot: &PkgSnapshot, findings: &mut Vec<IntuneFinding>) {
    let gaps = snapshot.coverage_gap_ids();
    if gaps.is_empty() {
        return;
    }
    findings.extend(finding(
        snapshot,
        "macos-pkg-coverage-gap",
        IntuneFindingSeverity::Info,
        IntuneFindingConfidence::High,
        "Expected package evidence was not fully collected",
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

fn push_malformed_records(snapshot: &PkgSnapshot, findings: &mut Vec<IntuneFinding>) {
    if snapshot.malformed_records == 0 {
        return;
    }
    findings.extend(finding(
        snapshot,
        "macos-pkg-malformed-records",
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

fn push_unknown_grammar(snapshot: &PkgSnapshot, findings: &mut Vec<IntuneFinding>) {
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
        "macos-pkg-unknown-agent-grammar",
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

fn push_successful_install(snapshot: &PkgSnapshot, findings: &mut Vec<IntuneFinding>) {
    let matched = with_outcome(snapshot, PkgOutcome::Installed);
    if matched.is_empty() {
        return;
    }
    findings.extend(finding(
        snapshot,
        "macos-pkg-installed",
        IntuneFindingSeverity::Info,
        IntuneFindingConfidence::High,
        "A package installed and was confirmed present",
        format!(
            "The installer exited zero and post-install detection confirmed: {}.",
            labels(&matched)
        ),
        &[],
        evidence_of(&matched),
        Vec::new(),
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intune::apps::macos::pkg::reducer::analyze_pkg_bundle;
    use crate::intune::apps::macos::pkg::shared::agent_log::{
        MacAgentArtifactInput, MacAgentCaptureState,
    };

    const APP: &str = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaa1";

    fn snapshot_from(body: &str, capture_state: MacAgentCaptureState) -> PkgSnapshot {
        analyze_pkg_bundle(
            &[MacAgentArtifactInput {
                artifact_id: "daemon-current".to_owned(),
                family: "intuneMdmDaemon".to_owned(),
                file_name: "IntuneMDMDaemon.log".to_owned(),
                sanitized_source_path: None,
                capture_state,
                content: Some(body.to_owned()),
                detail: None,
            }],
            "2026-07-31T00:00:00Z",
        )
    }

    fn known_grammar_body(lines: &[String]) -> String {
        let mut body = String::from(
            "2026-07-29 09:00:00:000 | IntuneMDM-Daemon | I | 1 | Startup | Intune MDM Agent version 2026.07.1 starting\n",
        );
        for line in lines {
            body.push_str(line);
            body.push('\n');
        }
        body
    }

    fn line(message: &str) -> String {
        format!("2026-07-29 09:10:00:000 | IntuneMDM-Daemon | I | 10 | AppInstaller | {message}")
    }

    #[test]
    fn every_finding_is_evidence_backed() {
        let snapshot = snapshot_from(
            &known_grammar_body(&[
                line(&format!("Received app policy AppId={APP} Type=pkg")),
                line(&format!("Download failed for AppId={APP} Error=-1009")),
                "a line that cannot be framed".to_owned(),
            ]),
            MacAgentCaptureState::Captured,
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
    fn an_unrecognized_grammar_caps_confidence_at_medium() {
        let body = format!(
            "2026-07-29 09:00:00:000 | IntuneMDM-Daemon | I | 1 | Startup | Intune MDM Agent version 2031.01.9 starting\n{}\n{}\n",
            line(&format!("Received app policy AppId={APP} Type=pkg")),
            line(&format!("Download failed for AppId={APP} Error=-1009")),
        );
        let snapshot = snapshot_from(&body, MacAgentCaptureState::Captured);
        assert!(!snapshot.grammar_recognized);
        assert!(snapshot
            .findings
            .iter()
            .all(|found| found.confidence != IntuneFindingConfidence::High));
        assert!(snapshot
            .findings
            .iter()
            .any(|found| found.finding_id == "macos-pkg-unknown-agent-grammar"));
    }

    #[test]
    fn a_clean_install_emits_no_failure_finding() {
        let snapshot = snapshot_from(
            &known_grammar_body(&[
                line(&format!("Received app policy AppId={APP} Type=pkg")),
                line(&format!("Installer finished for AppId={APP} ExitCode=0")),
                line(&format!("Detection succeeded for AppId={APP}")),
                line(&format!("Reported app status for AppId={APP} Status=installed")),
            ]),
            MacAgentCaptureState::Captured,
        );
        let ids = snapshot
            .findings
            .iter()
            .map(|found| found.finding_id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(ids, vec!["macos-pkg-installed"]);
    }

    #[test]
    fn an_empty_bundle_emits_no_finding_at_all() {
        // The grammar of an empty bundle is unrecognized and there is no
        // coverage entry to cite, so the grammar rule would otherwise emit a
        // finding backed by nothing.
        let snapshot = analyze_pkg_bundle(&[], "2026-07-31T00:00:00Z");
        assert!(snapshot.findings.is_empty());
        assert!(!snapshot.grammar_recognized);
    }

    #[test]
    fn a_capped_artifact_produces_a_coverage_gap_finding() {
        let snapshot = snapshot_from(
            &known_grammar_body(&[line(&format!(
                "Received app policy AppId={APP} Type=pkg"
            ))]),
            MacAgentCaptureState::Capped,
        );
        assert!(snapshot
            .findings
            .iter()
            .any(|found| found.finding_id == "macos-pkg-coverage-gap"));
    }
}
