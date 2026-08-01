//! Conservative findings derived from an immutable Store analysis snapshot.
//!
//! Structure follows `crate::esp::rules`: one public entry point composed of one
//! private `push_*` per rule, each of which emits only when its triggering
//! evidence is actually present. Every finding therefore satisfies
//! [`IntuneFinding::is_evidence_backed`].
//!
//! The rule this module exists to enforce is the attribution rule from the
//! source contract: a device-side Store or AppX failure is never reported as an
//! Intune failure unless Intune intent evidence and a matching package
//! identifier are both present. When one side is missing the finding says so and
//! cites the coverage gap, rather than picking whichever story the available
//! artifact happened to tell.

use std::collections::BTreeMap;

use crate::intune::evidence::{
    IntuneArtifactStatus, IntuneEvidenceRef, IntuneFinding, IntuneFindingConfidence,
    IntuneFindingSeverity,
};

use super::models::{
    StoreAnalysis, StoreFamilyBasis, StoreInstallerFamily, StoreTransaction, StoreTransactionState,
};
use super::reducer::family_is_material;

/// Derive every finding the snapshot supports.
pub fn derive_findings(snapshot: &StoreAnalysis) -> Vec<IntuneFinding> {
    let mut findings = Vec::new();

    push_license_failure(snapshot, &mut findings);
    push_download_failure(snapshot, &mut findings);
    push_registration_failure(snapshot, &mut findings);
    push_provisioning_failure(snapshot, &mut findings);
    push_uninstall_failure(snapshot, &mut findings);
    push_no_interactive_user(snapshot, &mut findings);
    push_unresolved_win32_handoff(snapshot, &mut findings);
    push_unknown_installer_family(snapshot, &mut findings);
    push_intent_without_device_evidence(snapshot, &mut findings);
    push_device_failure_without_intune_intent(snapshot, &mut findings);
    push_ambiguous_display_name(snapshot, &mut findings);
    push_unknown_event_version(snapshot, &mut findings);
    push_malformed_source(snapshot, &mut findings);
    push_evidence_coverage_gap(snapshot, &mut findings);
    push_install_completed(snapshot, &mut findings);
    push_uninstall_completed(snapshot, &mut findings);

    findings
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// A human label for a transaction that never leans on the display name alone.
///
/// The package family name is the identity; the display name is a convenience
/// and is appended only when one exists.
fn label(transaction: &StoreTransaction) -> String {
    let identity = &transaction.identity;
    let key = identity
        .package_family_name
        .clone()
        .or_else(|| identity.package_full_name.clone())
        .or_else(|| identity.store_product_id.clone())
        .or_else(|| transaction.app_id.clone())
        .unwrap_or_else(|| transaction.transaction_id.clone());
    match &identity.display_name {
        Some(name) => format!("{name} ({key})"),
        None => key,
    }
}

fn labels(transactions: &[&StoreTransaction]) -> String {
    const MAX: usize = 6;
    let mut names: Vec<String> = Vec::new();
    for transaction in transactions {
        let label = label(transaction);
        if !names.contains(&label) {
            names.push(label);
        }
    }
    let extra = names.len().saturating_sub(MAX);
    names.truncate(MAX);
    let mut joined = names.join(", ");
    if extra > 0 {
        joined.push_str(&format!(" (+{extra} more)"));
    }
    joined
}

fn evidence_of(transactions: &[&StoreTransaction]) -> Vec<IntuneEvidenceRef> {
    let mut refs: Vec<IntuneEvidenceRef> = Vec::new();
    for transaction in transactions {
        for reference in &transaction.evidence {
            if !refs.contains(reference) {
                refs.push(reference.clone());
            }
        }
    }
    refs.sort();
    refs
}

/// Error codes observed on the given transactions, de-duplicated and ordered.
fn error_suffix(transactions: &[&StoreTransaction]) -> String {
    let mut codes: Vec<String> = Vec::new();
    for transaction in transactions {
        if let Some(error) = &transaction.error {
            let rendered = error.hex.clone().unwrap_or_else(|| error.raw.clone());
            if !codes.contains(&rendered) {
                codes.push(rendered);
            }
        }
    }
    if codes.is_empty() {
        String::new()
    } else {
        format!(" Reported code(s): {}.", codes.join(", "))
    }
}

fn transactions_in_state(
    snapshot: &StoreAnalysis,
    state: StoreTransactionState,
) -> Vec<&StoreTransaction> {
    snapshot
        .transactions
        .iter()
        .filter(|transaction| transaction.state == state)
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn push_finding(
    findings: &mut Vec<IntuneFinding>,
    finding_id: &str,
    severity: IntuneFindingSeverity,
    confidence: IntuneFindingConfidence,
    title: &str,
    summary: String,
    recommended_checks: &[&str],
    evidence: Vec<IntuneEvidenceRef>,
    coverage_gap_ids: Vec<String>,
) {
    let finding = IntuneFinding {
        finding_id: finding_id.to_owned(),
        severity,
        confidence,
        title: title.to_owned(),
        summary,
        recommended_checks: recommended_checks
            .iter()
            .map(|check| (*check).to_owned())
            .collect(),
        evidence,
        coverage_gap_ids,
    };
    // The invariant the whole family upholds: an uncited finding is an
    // assertion, not a diagnosis, so it is never emitted.
    if finding.is_evidence_backed() {
        findings.push(finding);
    }
}

fn coverage_gap_ids(snapshot: &StoreAnalysis) -> Vec<String> {
    snapshot
        .coverage_gaps()
        .map(|entry| entry.artifact_id.clone())
        .collect()
}

// ── Failure rules ───────────────────────────────────────────────────────────

fn push_license_failure(snapshot: &StoreAnalysis, findings: &mut Vec<IntuneFinding>) {
    let affected = transactions_in_state(snapshot, StoreTransactionState::LicenseFailure);
    if affected.is_empty() {
        return;
    }
    push_finding(
        findings,
        "store-license-acquisition-failed",
        IntuneFindingSeverity::Error,
        IntuneFindingConfidence::High,
        "Store license or acquisition failed",
        format!(
            "The Store could not acquire a license or entitlement for {}.{}",
            labels(&affected),
            error_suffix(&affected)
        ),
        &[
            "Confirm the app is still assigned and the tenant still has an entitlement for it",
            "Check Store and Delivery Optimization network access from the device",
        ],
        evidence_of(&affected),
        Vec::new(),
    );
}

fn push_download_failure(snapshot: &StoreAnalysis, findings: &mut Vec<IntuneFinding>) {
    let affected = transactions_in_state(snapshot, StoreTransactionState::DownloadFailure);
    if affected.is_empty() {
        return;
    }
    push_finding(
        findings,
        "store-download-staging-failed",
        IntuneFindingSeverity::Error,
        IntuneFindingConfidence::High,
        "Package download or staging failed",
        format!(
            "The package payload for {} was never staged on disk, so no registration was attempted.{}",
            labels(&affected),
            error_suffix(&affected)
        ),
        &[
            "Check free disk space and the WindowsApps staging location",
            "Check Delivery Optimization and proxy access to Store content endpoints",
        ],
        evidence_of(&affected),
        Vec::new(),
    );
}

fn push_registration_failure(snapshot: &StoreAnalysis, findings: &mut Vec<IntuneFinding>) {
    let affected = transactions_in_state(snapshot, StoreTransactionState::RegistrationFailure);
    if affected.is_empty() {
        return;
    }
    let win32 = affected
        .iter()
        .any(|transaction| transaction.installer_family == StoreInstallerFamily::StoreWin32);
    push_finding(
        findings,
        "store-registration-failed",
        IntuneFindingSeverity::Error,
        IntuneFindingConfidence::High,
        if win32 {
            "Store-delivered installer reported failure"
        } else {
            "Package deployment registration failed"
        },
        format!(
            "{} reached the install stage and failed there.{}",
            labels(&affected),
            error_suffix(&affected)
        ),
        &[
            "Compare the cited deployment record with the package's dependency and framework versions",
            "Confirm the installer family before applying AppX-specific remediation",
        ],
        evidence_of(&affected),
        Vec::new(),
    );
}

fn push_provisioning_failure(snapshot: &StoreAnalysis, findings: &mut Vec<IntuneFinding>) {
    let affected = transactions_in_state(snapshot, StoreTransactionState::ProvisioningFailure);
    if affected.is_empty() {
        return;
    }
    push_finding(
        findings,
        "store-provisioning-failed",
        IntuneFindingSeverity::Error,
        IntuneFindingConfidence::High,
        "Device provisioning of the package failed",
        format!(
            "{} failed while being provisioned for all users on the device. This is a machine-wide operation and does not imply any per-user registration failed.{}",
            labels(&affected),
            error_suffix(&affected)
        ),
        &[
            "Check whether a newer version of the same package family is already registered for a user",
            "Confirm the provisioning operation ran in a system context",
        ],
        evidence_of(&affected),
        Vec::new(),
    );
}

fn push_uninstall_failure(snapshot: &StoreAnalysis, findings: &mut Vec<IntuneFinding>) {
    let affected = transactions_in_state(snapshot, StoreTransactionState::UninstallFailure);
    if affected.is_empty() {
        return;
    }
    push_finding(
        findings,
        "store-uninstall-failed",
        IntuneFindingSeverity::Error,
        IntuneFindingConfidence::High,
        "Package removal failed",
        format!(
            "Removal of {} did not complete.{}",
            labels(&affected),
            error_suffix(&affected)
        ),
        &[
            "Check whether the package is still provisioned for the device after the per-user removal",
        ],
        evidence_of(&affected),
        Vec::new(),
    );
}

fn push_no_interactive_user(snapshot: &StoreAnalysis, findings: &mut Vec<IntuneFinding>) {
    let affected = transactions_in_state(snapshot, StoreTransactionState::NoInteractiveUser);
    if affected.is_empty() {
        return;
    }
    push_finding(
        findings,
        "store-no-interactive-user",
        IntuneFindingSeverity::Warning,
        IntuneFindingConfidence::High,
        "A user-context package had no user to install for",
        format!(
            "{} requires a user context and no interactive user was signed in when it was evaluated. This is a scheduling condition, not an installation failure.",
            labels(&affected)
        ),
        &[
            "Re-evaluate after a user signs in, or retarget the app as a device-provisioned assignment",
        ],
        evidence_of(&affected),
        Vec::new(),
    );
}

fn push_unresolved_win32_handoff(snapshot: &StoreAnalysis, findings: &mut Vec<IntuneFinding>) {
    let affected = transactions_in_state(snapshot, StoreTransactionState::StoreWin32Handoff);
    if affected.is_empty() {
        return;
    }
    push_finding(
        findings,
        "store-win32-handoff-unresolved",
        IntuneFindingSeverity::Warning,
        IntuneFindingConfidence::Medium,
        "A Store-delivered Win32 package was handed off with no outcome",
        format!(
            "{} is a Store-delivered Win32 package. The handoff is recorded but no installer outcome was supplied, so AppX deployment evidence cannot settle it.",
            labels(&affected)
        ),
        &["Collect the installer's own log for the handed-off package"],
        evidence_of(&affected),
        coverage_gap_ids(snapshot),
    );
}

fn push_unknown_installer_family(snapshot: &StoreAnalysis, findings: &mut Vec<IntuneFinding>) {
    let affected = snapshot
        .transactions
        .iter()
        .filter(|transaction| {
            transaction.installer_family == StoreInstallerFamily::Unknown
                && transaction.family_basis == StoreFamilyBasis::Unvalidated
                // With no device evidence at all, the missing family is already
                // covered by `store-intent-without-device-evidence`; saying it
                // twice adds noise, not information.
                && transaction.has_device_evidence
                && family_is_material(transaction.state)
        })
        .collect::<Vec<_>>();
    if affected.is_empty() {
        return;
    }
    push_finding(
        findings,
        "store-installer-family-unknown",
        IntuneFindingSeverity::Warning,
        IntuneFindingConfidence::Medium,
        "The installer family could not be established",
        format!(
            "Nothing in the supplied evidence stated whether {} is a per-user UWP/MSIX registration, a device-provisioned package, or a Store-delivered Win32 package. No family-specific remediation applies until that is known.",
            labels(&affected)
        ),
        &[
            "Collect the AppX deployment scope from Microsoft-Windows-AppXDeploymentServer/Operational",
            "Collect the device's provisioned-package inventory",
        ],
        evidence_of(&affected),
        Vec::new(),
    );
}

// ── Attribution rules ───────────────────────────────────────────────────────

fn push_intent_without_device_evidence(
    snapshot: &StoreAnalysis,
    findings: &mut Vec<IntuneFinding>,
) {
    let affected = snapshot
        .transactions
        .iter()
        .filter(|transaction| transaction.has_intune_intent && !transaction.has_device_evidence)
        .collect::<Vec<_>>();
    if affected.is_empty() {
        return;
    }
    push_finding(
        findings,
        "store-intent-without-device-evidence",
        IntuneFindingSeverity::Warning,
        IntuneFindingConfidence::Medium,
        "Intune intent is recorded but the device never reported back",
        format!(
            "Intune targeted {} and no matching OS deployment or Store event was supplied. Whether the device acted on the assignment is unknown; this is not evidence of a failure.",
            labels(&affected)
        ),
        &[
            "Collect Microsoft-Windows-AppXDeploymentServer/Operational and Microsoft-Windows-StoreAgent for the same time window",
        ],
        evidence_of(&affected),
        coverage_gap_ids(snapshot),
    );
}

fn push_device_failure_without_intune_intent(
    snapshot: &StoreAnalysis,
    findings: &mut Vec<IntuneFinding>,
) {
    let affected = snapshot
        .transactions
        .iter()
        .filter(|transaction| {
            transaction.state.is_failure()
                && transaction.has_device_evidence
                && !transaction.has_intune_intent
        })
        .collect::<Vec<_>>();
    if affected.is_empty() {
        return;
    }
    push_finding(
        findings,
        "store-device-failure-without-intune-intent",
        IntuneFindingSeverity::Warning,
        IntuneFindingConfidence::Medium,
        "An OS Store or AppX failure has no matching Intune intent",
        format!(
            "The device reported a Store or AppX failure for {}, and no Intune assignment or IME handoff naming the same package was supplied. This failure must not be attributed to Intune on the evidence available.{}",
            labels(&affected),
            error_suffix(&affected)
        ),
        &[
            "Collect IntuneManagementExtension.log or the app assignment for the same package identifier before treating this as an Intune deployment failure",
        ],
        evidence_of(&affected),
        coverage_gap_ids(snapshot),
    );
}

/// Two transactions sharing a display name but not a package family.
///
/// A human reading a report that names the same app twice will assume a
/// duplicate. It is not: they are different packages, and merging them on the
/// name is precisely the join this analyzer refuses to make.
fn push_ambiguous_display_name(snapshot: &StoreAnalysis, findings: &mut Vec<IntuneFinding>) {
    let mut by_name: BTreeMap<&str, Vec<&StoreTransaction>> = BTreeMap::new();
    for transaction in &snapshot.transactions {
        if let Some(name) = &transaction.identity.display_name {
            by_name.entry(name.as_str()).or_default().push(transaction);
        }
    }

    let affected = by_name
        .into_iter()
        .filter(|(_, group)| {
            if group.len() < 2 {
                return false;
            }
            let mut families = group
                .iter()
                .map(|transaction| transaction.identity.effective_package_family_name())
                .collect::<Vec<_>>();
            families.sort();
            families.dedup();
            families.len() > 1
        })
        .flat_map(|(_, group)| group)
        .collect::<Vec<_>>();
    if affected.is_empty() {
        return;
    }

    push_finding(
        findings,
        "store-ambiguous-display-name",
        IntuneFindingSeverity::Info,
        IntuneFindingConfidence::High,
        "One display name covers more than one package",
        format!(
            "{} share a display name but have different package family identifiers, so they are separate deployments and were not merged.",
            labels(&affected)
        ),
        &["Use the package family name, not the display name, when comparing these deployments"],
        evidence_of(&affected),
        Vec::new(),
    );
}

// ── Coverage rules ──────────────────────────────────────────────────────────

fn push_unknown_event_version(snapshot: &StoreAnalysis, findings: &mut Vec<IntuneFinding>) {
    let evidence = snapshot
        .observations
        .iter()
        .filter(|observation| observation.unknown_version)
        .map(|observation| observation.context.evidence_ref.clone())
        .collect::<Vec<_>>();
    if evidence.is_empty() {
        return;
    }
    push_finding(
        findings,
        "store-unknown-event-version",
        IntuneFindingSeverity::Info,
        IntuneFindingConfidence::High,
        "A recognized provider emitted records this build has no rule for",
        format!(
            "{} record(s) came from a known AppX or Store provider with an unrecognized event id or payload version. Their outcome was not guessed, and any transaction they touch is reported at reduced confidence.",
            evidence.len()
        ),
        &["Re-run with a build that recognizes the provider version, or supply the rendered event text"],
        evidence,
        Vec::new(),
    );
}

fn push_malformed_source(snapshot: &StoreAnalysis, findings: &mut Vec<IntuneFinding>) {
    let gaps = snapshot
        .coverage
        .iter()
        .filter(|entry| entry.status == IntuneArtifactStatus::ParseFailed)
        .map(|entry| entry.artifact_id.clone())
        .collect::<Vec<_>>();
    if gaps.is_empty() {
        return;
    }
    push_finding(
        findings,
        "store-malformed-source",
        IntuneFindingSeverity::Warning,
        IntuneFindingConfidence::High,
        "A supplied artifact could not be interpreted",
        format!(
            "{} artifact(s) were collected but could not be read as Store evidence. Nothing inside them contributed to any transaction.",
            gaps.len()
        ),
        &["Re-collect the artifact; check for truncation and for a text encoding the collector did not declare"],
        Vec::new(),
        gaps,
    );
}

fn push_evidence_coverage_gap(snapshot: &StoreAnalysis, findings: &mut Vec<IntuneFinding>) {
    let gaps = snapshot
        .coverage
        .iter()
        .filter(|entry| {
            !matches!(
                entry.status,
                IntuneArtifactStatus::Available | IntuneArtifactStatus::ParseFailed
            )
        })
        .map(|entry| entry.artifact_id.clone())
        .collect::<Vec<_>>();
    if gaps.is_empty() {
        return;
    }
    push_finding(
        findings,
        "store-evidence-coverage-gap",
        IntuneFindingSeverity::Info,
        IntuneFindingConfidence::High,
        "Expected Store evidence was not collected",
        format!(
            "{} expected artifact(s) were missing, denied, capped, skipped, or unsupported. The absence of a Store or AppX signal in this bundle therefore proves nothing.",
            gaps.len()
        ),
        &["Re-collect the named artifacts before concluding that no deployment was attempted"],
        Vec::new(),
        gaps,
    );
}

// ── Success rules ───────────────────────────────────────────────────────────

fn push_install_completed(snapshot: &StoreAnalysis, findings: &mut Vec<IntuneFinding>) {
    let affected = transactions_in_state(snapshot, StoreTransactionState::InstallCompleted);
    if affected.is_empty() {
        return;
    }
    push_finding(
        findings,
        "store-install-completed",
        IntuneFindingSeverity::Info,
        IntuneFindingConfidence::High,
        "A Store app install completed",
        format!("{} completed installation.", labels(&affected)),
        &[],
        evidence_of(&affected),
        Vec::new(),
    );
}

fn push_uninstall_completed(snapshot: &StoreAnalysis, findings: &mut Vec<IntuneFinding>) {
    let affected = transactions_in_state(snapshot, StoreTransactionState::UninstallCompleted);
    if affected.is_empty() {
        return;
    }
    push_finding(
        findings,
        "store-uninstall-completed",
        IntuneFindingSeverity::Info,
        IntuneFindingConfidence::High,
        "A Store app uninstall completed",
        format!("{} was removed.", labels(&affected)),
        &[],
        evidence_of(&affected),
        Vec::new(),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intune::apps::windows::microsoft_store::models::{
        StoreAssignmentIntent, StoreDeploymentAction, StoreExecutionContext, StorePackageIdentity,
    };

    fn transaction(state: StoreTransactionState) -> StoreTransaction {
        StoreTransaction {
            transaction_id: "store-01".to_owned(),
            app_id: None,
            identity: StorePackageIdentity {
                package_family_name: Some("Contoso.SynthApp_9abcdef01234h".to_owned()),
                ..StorePackageIdentity::default()
            },
            installer_family: StoreInstallerFamily::UwpUserContext,
            family_basis: StoreFamilyBasis::Declared,
            execution_context: StoreExecutionContext::User,
            action: StoreDeploymentAction::Install,
            intent: StoreAssignmentIntent::Required,
            last_confirmed_phase: None,
            state,
            error: None,
            confidence: IntuneFindingConfidence::High,
            has_intune_intent: true,
            has_device_evidence: true,
            unknown_version_observed: false,
            observations: vec!["appx:1".to_owned()],
            evidence: vec![IntuneEvidenceRef {
                evidence_id: "appx:1".to_owned(),
                source_artifact_id: "appx".to_owned(),
            }],
            next_evidence_request: None,
        }
    }

    #[test]
    fn every_derived_finding_cites_evidence_or_a_gap() {
        let snapshot = StoreAnalysis {
            transactions: vec![
                transaction(StoreTransactionState::RegistrationFailure),
                transaction(StoreTransactionState::InstallCompleted),
            ],
            ..StoreAnalysis::default()
        };
        let findings = derive_findings(&snapshot);
        assert!(!findings.is_empty());
        for finding in &findings {
            assert!(
                finding.is_evidence_backed(),
                "{} cites nothing",
                finding.finding_id
            );
        }
    }

    #[test]
    fn finding_ids_are_unique() {
        let snapshot = StoreAnalysis {
            transactions: vec![
                transaction(StoreTransactionState::RegistrationFailure),
                transaction(StoreTransactionState::RegistrationFailure),
            ],
            ..StoreAnalysis::default()
        };
        let findings = derive_findings(&snapshot);
        let mut ids = findings
            .iter()
            .map(|finding| finding.finding_id.clone())
            .collect::<Vec<_>>();
        ids.sort();
        let count = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), count, "duplicate finding ids: {ids:?}");
    }

    #[test]
    fn an_os_failure_without_intune_intent_is_not_blamed_on_intune() {
        let mut orphan = transaction(StoreTransactionState::RegistrationFailure);
        orphan.has_intune_intent = false;
        let snapshot = StoreAnalysis {
            transactions: vec![orphan],
            ..StoreAnalysis::default()
        };
        let findings = derive_findings(&snapshot);
        let attribution = findings
            .iter()
            .find(|finding| finding.finding_id == "store-device-failure-without-intune-intent")
            .expect("attribution finding must be emitted");
        assert!(attribution.summary.contains("must not be attributed to Intune"));
    }
}
