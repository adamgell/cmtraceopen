//! Findings derived from an immutable [`Win32Analysis`] snapshot.
//!
//! Each rule is one private `push_*` function that reads the snapshot and emits
//! nothing unless its triggering evidence is present. Every finding therefore
//! cites at least one [`IntuneEvidenceRef`] or at least one coverage-gap id;
//! [`IntuneFinding::is_evidence_backed`] is the invariant, and the contract test
//! asserts it over the whole corpus.
//!
//! Severity, confidence, and cause classification are deliberately independent.
//! An unmapped installer return code is a high-severity failure reported at
//! medium confidence, because the deployment definitely failed and the *reason*
//! is not in the evidence. Collapsing the two would make an honest "it failed,
//! and I cannot tell you why" impossible to express.

use crate::intune::evidence::{
    IntuneArtifactStatus, IntuneEvidenceRef, IntuneFinding, IntuneFindingConfidence,
    IntuneFindingSeverity,
};

use super::models::{
    Win32Analysis, Win32Outcome, Win32Phase, Win32ReturnCodeKind, Win32Signal, Win32Transaction,
};

/// Derive stable, read-only diagnostic findings from a reduced snapshot.
pub fn derive_findings(snapshot: &Win32Analysis) -> Vec<IntuneFinding> {
    let mut findings = Vec::new();

    push_missing_artifacts(snapshot, &mut findings);
    push_unusable_artifacts(snapshot, &mut findings);
    push_unknown_vocabulary(snapshot, &mut findings);
    push_fragmented_records(snapshot, &mut findings);
    push_unkeyed_signals(snapshot, &mut findings);
    push_unlinked_installer_artifacts(snapshot, &mut findings);

    for transaction in &snapshot.transactions {
        push_not_targeted(transaction, &mut findings);
        push_not_applicable(transaction, &mut findings);
        push_requirement_not_met(transaction, &mut findings);
        push_dependency_unresolved(transaction, &mut findings);
        push_already_detected(transaction, &mut findings);
        push_content_failure(transaction, &mut findings);
        push_enforcement_command_failed(transaction, &mut findings);
        push_installer_reported_failure(transaction, &mut findings);
        push_unmapped_return_code(transaction, &mut findings);
        push_installer_failed_but_detected(snapshot, transaction, &mut findings);
        push_installed_not_detected(transaction, &mut findings);
        push_reporting_failed(transaction, &mut findings);
        push_deferred(transaction, &mut findings);
        push_unresolved(transaction, &mut findings);
        push_conflicting(transaction, &mut findings);
        push_superseded_failures(transaction, &mut findings);
        push_succeeded(transaction, &mut findings);
    }

    findings
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// A stable, human-readable label for a transaction.
///
/// The caller-supplied display name is used when present; otherwise the app id.
/// Nothing is ever inferred from log text, which is where real app names would
/// arrive alongside real tenant data.
fn label(transaction: &Win32Transaction) -> String {
    transaction
        .display_name
        .clone()
        .unwrap_or_else(|| transaction.key.app_id.clone())
}

fn finding_id(rule: &str, transaction: &Win32Transaction) -> String {
    format!(
        "win32-{rule}:{}:{}",
        transaction.key.app_id,
        transaction
            .key
            .deployment_type_id
            .as_deref()
            .unwrap_or("unknown")
    )
}

fn phase_label(phase: Option<Win32Phase>) -> String {
    match phase {
        Some(phase) => format!("{phase:?}"),
        None => "no phase confirmed".to_owned(),
    }
}

/// The sentence every transaction-scoped finding ends with.
///
/// Epic #356 requires a finding to identify the last confirmed phase *and* the
/// next requested artifact; building it in one place is what stops a rule
/// forgetting half of it.
fn provenance_sentence(transaction: &Win32Transaction) -> String {
    let phase = phase_label(transaction.last_confirmed_phase);
    match &transaction.next_evidence_request {
        Some(request) => {
            format!(" Last confirmed phase: {phase}. Next evidence requested: {request}.")
        }
        None => format!(" Last confirmed phase: {phase}."),
    }
}

#[allow(clippy::too_many_arguments)]
fn finding(
    finding_id: String,
    severity: IntuneFindingSeverity,
    confidence: IntuneFindingConfidence,
    title: &str,
    summary: String,
    recommended_checks: Vec<String>,
    evidence: Vec<IntuneEvidenceRef>,
    coverage_gap_ids: Vec<String>,
) -> IntuneFinding {
    IntuneFinding {
        finding_id,
        severity,
        confidence,
        title: title.to_owned(),
        summary,
        recommended_checks,
        evidence,
        coverage_gap_ids,
    }
}

/// Push a finding only when it actually cites something.
///
/// The guard is the last line of defence for the epic-wide rule that a finding
/// backed by neither evidence nor a coverage gap is an assertion, not a
/// diagnosis. A rule whose evidence collection came back empty is a bug, and
/// dropping the finding is strictly better than exporting an uncited claim.
fn push(findings: &mut Vec<IntuneFinding>, candidate: IntuneFinding) {
    if candidate.is_evidence_backed() {
        findings.push(candidate);
    }
}

/// Evidence refs for the records in a transaction that carried a given signal.
fn evidence_for_signal(
    snapshot: &Win32Analysis,
    transaction: &Win32Transaction,
    predicate: impl Fn(Win32Signal) -> bool,
) -> Vec<IntuneEvidenceRef> {
    snapshot
        .observations
        .iter()
        .filter(|observation| {
            transaction
                .observations
                .contains(&observation.observation_id)
                && predicate(observation.signal)
        })
        .map(|observation| observation.context.evidence_ref.clone())
        .collect()
}

/// The transaction's own evidence, which is always non-empty by construction.
fn all_evidence(transaction: &Win32Transaction) -> Vec<IntuneEvidenceRef> {
    transaction.evidence.clone()
}

// ── Coverage rules ──────────────────────────────────────────────────────────

fn push_missing_artifacts(snapshot: &Win32Analysis, findings: &mut Vec<IntuneFinding>) {
    let gaps: Vec<String> = snapshot
        .coverage
        .artifacts
        .iter()
        .filter(|entry| entry.status == IntuneArtifactStatus::Missing)
        .map(|entry| entry.artifact_id.clone())
        .collect();
    if gaps.is_empty() {
        return;
    }
    push(
        findings,
        finding(
            "win32-coverage-missing-artifact".to_owned(),
            IntuneFindingSeverity::Info,
            IntuneFindingConfidence::High,
            "Expected Win32 app evidence was not collected",
            format!(
                "{} expected artifact(s) were absent from the bundle, so any phase they alone \
                 record cannot be evaluated.",
                gaps.len()
            ),
            vec![
                "Collect the named artifacts from the IME log directory and re-run the analysis"
                    .to_owned(),
            ],
            Vec::new(),
            gaps,
        ),
    );
}

fn push_unusable_artifacts(snapshot: &Win32Analysis, findings: &mut Vec<IntuneFinding>) {
    let gaps: Vec<String> = snapshot
        .coverage
        .artifacts
        .iter()
        .filter(|entry| {
            matches!(
                entry.status,
                IntuneArtifactStatus::PermissionDenied
                    | IntuneArtifactStatus::Capped
                    | IntuneArtifactStatus::ParseFailed
                    | IntuneArtifactStatus::Skipped
                    | IntuneArtifactStatus::Unsupported
            )
        })
        .map(|entry| entry.artifact_id.clone())
        .collect();
    if gaps.is_empty() {
        return;
    }
    push(
        findings,
        finding(
            "win32-coverage-unusable-artifact".to_owned(),
            IntuneFindingSeverity::Warning,
            IntuneFindingConfidence::High,
            "Some Win32 app evidence was collected but could not be used",
            format!(
                "{} artifact(s) were truncated, denied, skipped, or could not be parsed. The \
                 absence of a signal in them proves nothing.",
                gaps.len()
            ),
            vec![
                "Re-collect the named artifacts from an elevated context and without truncation"
                    .to_owned(),
            ],
            Vec::new(),
            gaps,
        ),
    );
}

fn push_unknown_vocabulary(snapshot: &Win32Analysis, findings: &mut Vec<IntuneFinding>) {
    if !snapshot.coverage.unknown_vocabulary_observed {
        return;
    }
    let evidence = snapshot
        .observations
        .iter()
        .filter(|observation| {
            observation.signal == Win32Signal::Unclassified
                || (observation.signal == Win32Signal::InstallerCompleted
                    && observation.error_code.is_none())
        })
        .map(|observation| observation.context.evidence_ref.clone())
        .collect::<Vec<_>>();
    push(
        findings,
        finding(
            "win32-unknown-enforcement-vocabulary".to_owned(),
            IntuneFindingSeverity::Warning,
            IntuneFindingConfidence::Medium,
            "An enforcement record did not match any known IME phrasing",
            "At least one record looked like Win32 enforcement but matched no rule, which is how \
             an unrecognised IME version presents. Affected deployments are reported at low \
             confidence rather than guessed."
                .to_owned(),
            vec!["Check the IME agent version against the supported log grammar".to_owned()],
            evidence,
            Vec::new(),
        ),
    );
}

fn push_fragmented_records(snapshot: &Win32Analysis, findings: &mut Vec<IntuneFinding>) {
    if snapshot.coverage.fragment_records == 0 {
        return;
    }
    let evidence = snapshot
        .observations
        .iter()
        .filter(|observation| {
            observation.context.parse_state == crate::intune::evidence::IntuneParseState::Malformed
        })
        .map(|observation| observation.context.evidence_ref.clone())
        .collect::<Vec<_>>();
    push(
        findings,
        finding(
            "win32-rotation-fragment".to_owned(),
            IntuneFindingSeverity::Info,
            IntuneFindingConfidence::High,
            "A logical record was split across a rotation boundary",
            format!(
                "{} physical-line fragment(s) could not be framed into a complete record and were \
                 therefore excluded from every transaction.",
                snapshot.coverage.fragment_records
            ),
            vec![
                "Supply the adjacent IME log rotation so the split record can be framed".to_owned(),
            ],
            evidence,
            Vec::new(),
        ),
    );
}

fn push_unkeyed_signals(snapshot: &Win32Analysis, findings: &mut Vec<IntuneFinding>) {
    if snapshot.unkeyed_observations.is_empty() {
        return;
    }
    let evidence = snapshot
        .observations
        .iter()
        .filter(|observation| {
            snapshot
                .unkeyed_observations
                .contains(&observation.observation_id)
        })
        .map(|observation| observation.context.evidence_ref.clone())
        .collect::<Vec<_>>();
    push(
        findings,
        finding(
            "win32-unkeyed-signal".to_owned(),
            IntuneFindingSeverity::Info,
            IntuneFindingConfidence::High,
            "Some records carried a signal but named no app",
            format!(
                "{} record(s) could not be keyed to an app. They are reported here rather than \
                 attached to the nearest deployment in time.",
                snapshot.unkeyed_observations.len()
            ),
            vec!["Supply the adjacent IME log rotation so these records can be keyed".to_owned()],
            evidence,
            Vec::new(),
        ),
    );
}

fn push_unlinked_installer_artifacts(snapshot: &Win32Analysis, findings: &mut Vec<IntuneFinding>) {
    if snapshot.coverage.unlinked_installer_artifacts.is_empty() {
        return;
    }
    push(
        findings,
        finding(
            "win32-unlinked-installer-artifact".to_owned(),
            IntuneFindingSeverity::Info,
            IntuneFindingConfidence::High,
            "A supplemental installer artifact could not be keyed to a deployment",
            "No keyed record named these artifacts, and a supplemental artifact is never joined \
             to a deployment by timestamp alone."
                .to_owned(),
            vec![
                "Supply the AppWorkload.log records that name the installer output file".to_owned(),
            ],
            Vec::new(),
            snapshot.coverage.unlinked_installer_artifacts.clone(),
        ),
    );
}

// ── Transaction rules ───────────────────────────────────────────────────────

fn push_not_targeted(transaction: &Win32Transaction, findings: &mut Vec<IntuneFinding>) {
    if transaction.outcome != Win32Outcome::NotTargeted {
        return;
    }
    push(
        findings,
        finding(
            finding_id("not-targeted", transaction),
            IntuneFindingSeverity::Info,
            transaction.confidence.clone(),
            "The app is no longer targeted at this device",
            format!(
                "{} was removed from targeting, so no enforcement was attempted.{}",
                label(transaction),
                provenance_sentence(transaction)
            ),
            vec!["Confirm the assignment in the Intune portal".to_owned()],
            all_evidence(transaction),
            Vec::new(),
        ),
    );
}

fn push_not_applicable(transaction: &Win32Transaction, findings: &mut Vec<IntuneFinding>) {
    if transaction.outcome != Win32Outcome::NotApplicable {
        return;
    }
    push(
        findings,
        finding(
            finding_id("not-applicable", transaction),
            IntuneFindingSeverity::Info,
            transaction.confidence.clone(),
            "The app was evaluated as not applicable",
            format!(
                "{} did not pass applicability, so no content was acquired and no installer ran.{}",
                label(transaction),
                provenance_sentence(transaction)
            ),
            vec![
                "Compare the deployment type's applicability criteria with the device's platform \
                 and architecture"
                    .to_owned(),
            ],
            all_evidence(transaction),
            Vec::new(),
        ),
    );
}

fn push_requirement_not_met(transaction: &Win32Transaction, findings: &mut Vec<IntuneFinding>) {
    if transaction.outcome != Win32Outcome::RequirementNotMet {
        return;
    }
    let rules = if transaction.failed_requirements.is_empty() {
        "an unnamed requirement rule".to_owned()
    } else {
        transaction.failed_requirements.join(", ")
    };
    push(
        findings,
        finding(
            finding_id("requirement-not-met", transaction),
            IntuneFindingSeverity::Warning,
            transaction.confidence.clone(),
            "A requirement rule blocked the deployment",
            format!(
                "{} stopped at requirement evaluation: {rules}.{}",
                label(transaction),
                provenance_sentence(transaction)
            ),
            vec!["Re-evaluate the named requirement rule against this device".to_owned()],
            all_evidence(transaction),
            Vec::new(),
        ),
    );
}

fn push_dependency_unresolved(transaction: &Win32Transaction, findings: &mut Vec<IntuneFinding>) {
    if transaction.outcome != Win32Outcome::DependencyUnresolved {
        return;
    }
    let dependencies = if transaction.unresolved_dependencies.is_empty() {
        "an unnamed dependency".to_owned()
    } else {
        transaction.unresolved_dependencies.join(", ")
    };
    push(
        findings,
        finding(
            finding_id("dependency-unresolved", transaction),
            IntuneFindingSeverity::Error,
            transaction.confidence.clone(),
            "A dependency blocked the deployment",
            format!(
                "{} is waiting on {dependencies}.{}",
                label(transaction),
                provenance_sentence(transaction)
            ),
            vec![
                "Analyse the dependency app's own deployment before re-testing this one".to_owned(),
            ],
            all_evidence(transaction),
            Vec::new(),
        ),
    );
}

fn push_already_detected(transaction: &Win32Transaction, findings: &mut Vec<IntuneFinding>) {
    if transaction.outcome != Win32Outcome::DetectedBeforeEnforcement {
        return;
    }
    push(
        findings,
        finding(
            finding_id("already-detected", transaction),
            IntuneFindingSeverity::Info,
            transaction.confidence.clone(),
            "Detection was already satisfied, so no installer ran",
            format!(
                "{} was detected before enforcement, which is a successful no-op rather than a \
                 skipped install.{}",
                label(transaction),
                provenance_sentence(transaction)
            ),
            vec![
                "Confirm the detection rule matches the intended version, not merely any version"
                    .to_owned(),
            ],
            all_evidence(transaction),
            Vec::new(),
        ),
    );
}

fn push_content_failure(transaction: &Win32Transaction, findings: &mut Vec<IntuneFinding>) {
    let (rule, title, summary) = match transaction.outcome {
        Win32Outcome::ContentUnavailable => (
            "content-unavailable",
            "No usable content was available for this app",
            "the service reported no usable content for the requested version",
        ),
        Win32Outcome::ContentDeliveryFailed => (
            "content-delivery-failed",
            "Content download, hash validation, or staging failed",
            "content acquisition failed before any installer could run",
        ),
        _ => return,
    };
    push(
        findings,
        finding(
            finding_id(rule, transaction),
            IntuneFindingSeverity::Error,
            transaction.confidence.clone(),
            title,
            format!(
                "{}: {summary}.{}",
                label(transaction),
                provenance_sentence(transaction)
            ),
            vec![
                "Check Delivery Optimization and the content version referenced by the assignment"
                    .to_owned(),
            ],
            all_evidence(transaction),
            Vec::new(),
        ),
    );
}

fn push_enforcement_command_failed(
    transaction: &Win32Transaction,
    findings: &mut Vec<IntuneFinding>,
) {
    if transaction.outcome != Win32Outcome::EnforcementCommandFailed {
        return;
    }
    push(
        findings,
        finding(
            finding_id("enforcement-command-failed", transaction),
            IntuneFindingSeverity::Error,
            transaction.confidence.clone(),
            "The install command could not be launched",
            format!(
                "{} never reached the installer: the enforcement command itself failed to start, \
                 so there is no return code to interpret.{}",
                label(transaction),
                provenance_sentence(transaction)
            ),
            vec![
                "Verify the install command line, its working directory, and the execution context"
                    .to_owned(),
            ],
            all_evidence(transaction),
            Vec::new(),
        ),
    );
}

fn push_installer_reported_failure(
    transaction: &Win32Transaction,
    findings: &mut Vec<IntuneFinding>,
) {
    if transaction.outcome != Win32Outcome::InstallerReportedFailure {
        return;
    }
    let token = transaction
        .return_code
        .as_ref()
        .map(|code| code.raw.clone())
        .unwrap_or_else(|| "an unreported code".to_owned());
    push(
        findings,
        finding(
            finding_id("installer-reported-failure", transaction),
            IntuneFindingSeverity::Error,
            transaction.confidence.clone(),
            "The installer ran and reported a failure",
            format!(
                "{} reached enforcement and the installer returned {token}. The return code is an \
                 execution outcome, not a root cause.{}",
                label(transaction),
                provenance_sentence(transaction)
            ),
            vec![
                "Read the installer-native log for this run before acting on the return code"
                    .to_owned(),
            ],
            all_evidence(transaction),
            Vec::new(),
        ),
    );
}

/// A code outside the supplied return-code table.
///
/// Reported separately and at medium confidence: the failure itself is
/// well-evidenced, but the analyzer refuses to assign the token a meaning that
/// is not in the evidence or in the app's configured table.
fn push_unmapped_return_code(transaction: &Win32Transaction, findings: &mut Vec<IntuneFinding>) {
    if transaction.return_code_kind != Some(Win32ReturnCodeKind::Unmapped) {
        return;
    }
    let Some(code) = &transaction.return_code else {
        return;
    };
    let hex = code
        .hex
        .as_ref()
        .map(|hex| format!(" ({hex})"))
        .unwrap_or_default();
    push(
        findings,
        finding(
            finding_id("unmapped-return-code", transaction),
            IntuneFindingSeverity::Warning,
            IntuneFindingConfidence::Medium,
            "The installer's return code is not in the app's return-code table",
            format!(
                "{} returned {}{hex}, which neither the supplied table nor Intune's documented \
                 defaults classify. No meaning is asserted for it here.{}",
                label(transaction),
                code.raw,
                provenance_sentence(transaction)
            ),
            vec![
                "Add the observed code to the deployment type's return-code table if it is \
                 expected"
                    .to_owned(),
            ],
            all_evidence(transaction),
            Vec::new(),
        ),
    );
}

/// The installer reported failure and detection then found the app present.
///
/// The reducer deliberately keeps the return code as the stronger claim rather
/// than silently upgrading the deployment to success; this rule makes the
/// contradiction visible instead of hiding it.
fn push_installer_failed_but_detected(
    snapshot: &Win32Analysis,
    transaction: &Win32Transaction,
    findings: &mut Vec<IntuneFinding>,
) {
    if transaction.outcome != Win32Outcome::InstallerReportedFailure {
        return;
    }
    let evidence = evidence_for_signal(snapshot, transaction, |signal| {
        signal == Win32Signal::DetectionSatisfied
    });
    if evidence.is_empty() {
        return;
    }
    push(
        findings,
        finding(
            finding_id("installer-failed-but-detected", transaction),
            IntuneFindingSeverity::Warning,
            IntuneFindingConfidence::Medium,
            "The installer reported failure but detection found the app present",
            format!(
                "{} has contradictory evidence: a failing return code and a satisfied detection \
                 rule. Neither is discarded here.{}",
                label(transaction),
                provenance_sentence(transaction)
            ),
            vec![
                "Confirm whether the detection rule is broad enough to match a partial install"
                    .to_owned(),
            ],
            evidence,
            Vec::new(),
        ),
    );
}

fn push_installed_not_detected(transaction: &Win32Transaction, findings: &mut Vec<IntuneFinding>) {
    if transaction.outcome != Win32Outcome::InstalledNotDetected {
        return;
    }
    push(
        findings,
        finding(
            finding_id("installed-not-detected", transaction),
            IntuneFindingSeverity::Error,
            transaction.confidence.clone(),
            "The installer succeeded but detection still fails",
            format!(
                "{} enforced successfully and post-enforcement detection remained unsatisfied. \
                 The device will keep retrying and the app will keep reporting as failed.{}",
                label(transaction),
                provenance_sentence(transaction)
            ),
            vec![
                "Compare the detection rule with what the installer actually wrote to disk or the \
                 registry"
                    .to_owned(),
            ],
            all_evidence(transaction),
            Vec::new(),
        ),
    );
}

fn push_reporting_failed(transaction: &Win32Transaction, findings: &mut Vec<IntuneFinding>) {
    if transaction.outcome != Win32Outcome::ReportingFailed {
        return;
    }
    let local = match transaction.local_outcome {
        Some(outcome) => format!("The local outcome was {outcome:?}"),
        None => "No local outcome was evidenced before the upload attempt".to_owned(),
    };
    push(
        findings,
        finding(
            finding_id("reporting-failed", transaction),
            IntuneFindingSeverity::Warning,
            transaction.confidence.clone(),
            "The local outcome could not be reported to the service",
            format!(
                "{} finished locally and the status upload failed, so the portal will disagree \
                 with the device. {local}.{}",
                label(transaction),
                provenance_sentence(transaction)
            ),
            vec!["Check device connectivity and proxy configuration for the IME".to_owned()],
            all_evidence(transaction),
            Vec::new(),
        ),
    );
}

fn push_deferred(transaction: &Win32Transaction, findings: &mut Vec<IntuneFinding>) {
    if transaction.outcome != Win32Outcome::Deferred {
        return;
    }
    push(
        findings,
        finding(
            finding_id("deferred", transaction),
            IntuneFindingSeverity::Info,
            IntuneFindingConfidence::Low,
            "The deployment was deferred and has no terminal outcome yet",
            format!(
                "{} scheduled a retry and the supplied evidence contains no result after it. This \
                 is an unresolved state, not a failure.{}",
                label(transaction),
                provenance_sentence(transaction)
            ),
            vec!["Collect the IME log rotation covering the next retry window".to_owned()],
            all_evidence(transaction),
            Vec::new(),
        ),
    );
}

fn push_unresolved(transaction: &Win32Transaction, findings: &mut Vec<IntuneFinding>) {
    if !matches!(
        transaction.outcome,
        Win32Outcome::InsufficientEvidence | Win32Outcome::Assigned | Win32Outcome::Enforcing
    ) {
        return;
    }
    push(
        findings,
        finding(
            finding_id("unresolved", transaction),
            IntuneFindingSeverity::Info,
            IntuneFindingConfidence::Low,
            "The deployment has no terminal outcome in the supplied evidence",
            format!(
                "{} is reported as {:?}. No conclusion is drawn about whether it succeeded.{}",
                label(transaction),
                transaction.outcome,
                provenance_sentence(transaction)
            ),
            vec!["Collect the artifact named in the next-evidence request".to_owned()],
            all_evidence(transaction),
            Vec::new(),
        ),
    );
}

/// Two equal-authority terminal statements that nothing in the evidence orders.
///
/// Per ADR-003 the reduction refuses to pick a winner; this finding is where
/// the refusal becomes visible instead of a silent `InsufficientEvidence`.
fn push_conflicting(transaction: &Win32Transaction, findings: &mut Vec<IntuneFinding>) {
    if transaction.outcome != Win32Outcome::Conflicting {
        return;
    }
    push(
        findings,
        finding(
            finding_id("conflicting-terminal-outcomes", transaction),
            IntuneFindingSeverity::Warning,
            IntuneFindingConfidence::Low,
            "The evidence states contradictory terminal outcomes that cannot be ordered",
            format!(
                "{} has records of equal authority claiming different terminal outcomes, and no \
                 shared record order or trusted timestamps prove which came later. No winner is \
                 asserted.{}",
                label(transaction),
                provenance_sentence(transaction)
            ),
            vec![
                "Collect every rotation of the artifact in one capture so a single source orders \
                 the check-ins"
                    .to_owned(),
            ],
            all_evidence(transaction),
            Vec::new(),
        ),
    );
}

/// A proven failure that a later, explicitly linked record superseded.
///
/// Retry semantics per ADR-003: the linked later outcome is the transaction's
/// answer, but the failed enforcement cycle really happened and stays visible.
fn push_superseded_failures(transaction: &Win32Transaction, findings: &mut Vec<IntuneFinding>) {
    if transaction.superseded_failures.is_empty() {
        return;
    }
    let outcomes = transaction
        .superseded_failures
        .iter()
        .map(|entry| match &entry.return_code {
            Some(code) => format!("{:?} ({})", entry.outcome, code.raw),
            None => format!("{:?}", entry.outcome),
        })
        .collect::<Vec<_>>()
        .join(", ");
    let evidence = transaction
        .superseded_failures
        .iter()
        .flat_map(|entry| entry.evidence.iter().cloned())
        .collect::<Vec<_>>();
    push(
        findings,
        finding(
            finding_id("superseded-failure", transaction),
            IntuneFindingSeverity::Warning,
            transaction.confidence.clone(),
            "An earlier enforcement cycle failed before the current outcome",
            format!(
                "{} reached its current outcome after at least one proven failure that a later, \
                 explicitly ordered record superseded: {outcomes}. The failure is retained as \
                 evidence of a real failed cycle, not erased by the retry.{}",
                label(transaction),
                provenance_sentence(transaction)
            ),
            vec![
                "Check whether the earlier failure recurs across devices before treating the \
                 retry success as the steady state"
                    .to_owned(),
            ],
            evidence,
            Vec::new(),
        ),
    );
}

fn push_succeeded(transaction: &Win32Transaction, findings: &mut Vec<IntuneFinding>) {
    if transaction.outcome != Win32Outcome::Succeeded {
        return;
    }
    let reboot = if transaction.reboot_required {
        " A restart is pending, so the app is installed but not yet fully applied."
    } else {
        ""
    };
    push(
        findings,
        finding(
            finding_id("succeeded", transaction),
            IntuneFindingSeverity::Info,
            transaction.confidence.clone(),
            "The deployment completed successfully",
            format!(
                "{} reached a successful outcome.{reboot}{}",
                label(transaction),
                provenance_sentence(transaction)
            ),
            Vec::new(),
            all_evidence(transaction),
            Vec::new(),
        ),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intune::apps::windows::win32::{analyze_win32_bundle, Win32SourceInput};

    const APP: &str = "11111111-2222-4333-8444-555555555555";
    const DT: &str = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";

    fn record(message: &str) -> String {
        format!(
            "<![LOG[{message}]LOG]!><time=\"10:00:00.000+000\" date=\"7-31-2026\" \
             component=\"Win32App\" context=\"\" type=\"1\" thread=\"5\" file=\"\">\n"
        )
    }

    fn analyze(messages: &[String]) -> Win32Analysis {
        analyze_win32_bundle(&[Win32SourceInput::captured(
            "aw",
            "AppWorkload.log",
            messages.concat(),
        )])
    }

    #[test]
    fn every_finding_cites_evidence_or_a_coverage_gap() {
        let snapshot = analyze(&[
            record(&format!(
                "[Win32App] Processing app policy for app with id: {APP}, deployment type id: {DT}"
            )),
            record(&format!(
                "[Win32App] Installation is done for app with id: {APP}, exit code: 0x80070643"
            )),
        ]);
        let findings = derive_findings(&snapshot);
        assert!(!findings.is_empty());
        for candidate in &findings {
            assert!(
                candidate.is_evidence_backed(),
                "{} cites nothing",
                candidate.finding_id
            );
        }
    }

    #[test]
    fn an_unmapped_code_produces_a_failure_and_a_separate_unmapped_finding() {
        let snapshot = analyze(&[
            record(&format!(
                "[Win32App] Processing app policy for app with id: {APP}, deployment type id: {DT}"
            )),
            record(&format!(
                "[Win32App] Installation is done for app with id: {APP}, exit code: 0x80070643"
            )),
        ]);
        let ids: Vec<String> = derive_findings(&snapshot)
            .into_iter()
            .map(|candidate| candidate.finding_id)
            .collect();
        assert!(ids.contains(&format!("win32-installer-reported-failure:{APP}:{DT}")));
        assert!(ids.contains(&format!("win32-unmapped-return-code:{APP}:{DT}")));
    }

    #[test]
    fn a_successful_deployment_still_names_its_last_confirmed_phase() {
        let snapshot = analyze(&[
            record(&format!(
                "[Win32App] Processing app policy for app with id: {APP}, deployment type id: {DT}"
            )),
            record(&format!(
                "[Win32App] Installation is done for app with id: {APP}, exit code: 0"
            )),
        ]);
        let findings = derive_findings(&snapshot);
        let success = findings
            .iter()
            .find(|candidate| candidate.finding_id == format!("win32-succeeded:{APP}:{DT}"))
            .expect("a successful deployment must be reported");
        assert!(success
            .summary
            .contains("Last confirmed phase: Enforcement"));
    }

    #[test]
    fn findings_are_deterministic_across_repeated_derivations() {
        let snapshot = analyze(&[record(&format!(
            "[Win32App] Processing app policy for app with id: {APP}"
        ))]);
        assert_eq!(derive_findings(&snapshot), derive_findings(&snapshot));
    }
}
