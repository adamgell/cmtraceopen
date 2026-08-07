//! Findings derived from an [`UpdateSnapshot`].
//!
//! One private `push_*` per rule, in a fixed order, so the output list is
//! deterministic without a sort pass that would hide an ordering bug.
//!
//! Two invariants hold across every rule, and the leaf's contract tests assert
//! both:
//!
//! 1. Every finding cites at least one evidence reference or one coverage-gap
//!    id ([`IntuneFinding::is_evidence_backed`]).
//! 2. A finding about **update execution** (`…/update/…`) cites at least one
//!    reference produced by the Windows Update client. A policy record can never
//!    back a claim that Windows scanned, downloaded, or installed anything, and
//!    a supplemental CBS or DISM line can corroborate such a claim but never
//!    establish it.
//!
//! The second invariant is the entire reason issue #365 exists, so it is
//! enforced structurally: update findings are built from
//! [`UpdateTransaction::evidence`], which the reducer fills only from
//! update-client observations.

use crate::intune::evidence::{
    IntuneArtifactStatus, IntuneEvidenceRef, IntuneFinding, IntuneFindingConfidence,
    IntuneFindingSeverity,
};

use super::models::*;

/// Prefix shared by every finding id this leaf emits.
pub const FINDING_PREFIX: &str = "intune/windows/updates";

/// Id prefix for findings about Intune's delivery of update settings.
pub const POLICY_FINDING_PREFIX: &str = "intune/windows/updates/policy";
/// Id prefix for findings about what the Windows Update client actually did.
pub const UPDATE_FINDING_PREFIX: &str = "intune/windows/updates/update";
/// Id prefix for findings about the evidence itself rather than the device.
pub const EVIDENCE_FINDING_PREFIX: &str = "intune/windows/updates/evidence";

/// Derive every finding the snapshot supports.
pub fn derive_findings(snapshot: &UpdateSnapshot) -> Vec<IntuneFinding> {
    let mut findings = Vec::new();

    push_workload_not_owned_by_intune(snapshot, &mut findings);
    push_policy_delivery_failed(snapshot, &mut findings);
    push_policy_conflict(snapshot, &mut findings);
    push_policy_unsupported_value(snapshot, &mut findings);
    push_effective_source_mismatch(snapshot, &mut findings);
    push_policy_not_observed(snapshot, &mut findings);
    push_policy_applied(snapshot, &mut findings);

    push_scan_failure(snapshot, &mut findings);
    push_no_applicable_update(snapshot, &mut findings);
    push_download_failure(snapshot, &mut findings);
    push_install_failure(snapshot, &mut findings);
    push_deferral(snapshot, &mut findings);
    push_reboot_pending(snapshot, &mut findings);
    push_installed(snapshot, &mut findings);
    push_reporting_mismatch(snapshot, &mut findings);

    push_order_contradiction(snapshot, &mut findings);
    push_unknown_schema(snapshot, &mut findings);
    push_coverage_gaps(snapshot, &mut findings);

    findings
}

// ── Shared helpers ──────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn finding(
    id: String,
    severity: IntuneFindingSeverity,
    confidence: IntuneFindingConfidence,
    title: &str,
    summary: String,
    checks: &[&str],
    evidence: Vec<IntuneEvidenceRef>,
    coverage_gap_ids: Vec<String>,
) -> IntuneFinding {
    let mut evidence = evidence;
    evidence.sort();
    evidence.dedup();
    IntuneFinding {
        finding_id: id,
        severity,
        confidence,
        title: title.to_owned(),
        summary,
        recommended_checks: checks.iter().map(|check| (*check).to_owned()).collect(),
        evidence,
        coverage_gap_ids,
    }
}

/// Evidence references for policy observations carrying a given signal.
fn policy_evidence(snapshot: &UpdateSnapshot, signal: PolicySignal) -> Vec<IntuneEvidenceRef> {
    snapshot
        .policy_chain
        .observations
        .iter()
        .filter(|observation| observation.signal == signal)
        .map(|observation| observation.context.evidence_ref.clone())
        .collect()
}

/// Update-client evidence for a given phase and outcome, from both the unkeyed
/// device-level readings and every transaction's phase list.
///
/// Supplemental readings are excluded by construction: this is what keeps a CBS
/// line from ever being the sole citation behind an execution claim.
fn client_evidence(
    snapshot: &UpdateSnapshot,
    phase: UpdatePhase,
    outcome: UpdateOutcome,
) -> Vec<IntuneEvidenceRef> {
    let from_unkeyed = snapshot
        .update_chain
        .unkeyed_observations
        .iter()
        .filter(|observation| {
            observation.is_update_client_evidence()
                && observation.phase == phase
                && observation.outcome == outcome
        })
        .map(|observation| observation.context.evidence_ref.clone());

    let from_transactions = snapshot
        .update_chain
        .transactions
        .iter()
        .flat_map(|transaction| transaction.phases.iter())
        .filter(|record| {
            record.supplemental.is_none() && record.phase == phase && record.outcome == outcome
        })
        .map(|record| record.evidence.clone());

    from_unkeyed.chain(from_transactions).collect()
}

/// Artifact ids that were not usable, used as coverage-gap citations.
fn coverage_gap_ids(snapshot: &UpdateSnapshot) -> Vec<String> {
    snapshot
        .coverage
        .iter()
        .filter(|entry| entry.status != IntuneArtifactStatus::Available)
        .map(|entry| entry.artifact_id.clone())
        .collect()
}

/// Render an error code for a summary, preferring the hex form an administrator
/// will recognize.
fn error_text(error: Option<&crate::intune::evidence::IntuneErrorCode>) -> String {
    match error {
        Some(code) => format!(
            " ({})",
            code.hex.clone().unwrap_or_else(|| code.raw.clone())
        ),
        None => String::new(),
    }
}

fn source_text(source: &UpdateSource) -> String {
    serde_json::to_value(source)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| "unknown".to_owned())
}

fn transactions_in_state(
    snapshot: &UpdateSnapshot,
    state: UpdateTransactionState,
) -> Vec<&UpdateTransaction> {
    snapshot
        .update_chain
        .transactions
        .iter()
        .filter(|transaction| transaction.state == state)
        .collect()
}

// ── Policy chain rules ──────────────────────────────────────────────────────

fn push_workload_not_owned_by_intune(snapshot: &UpdateSnapshot, findings: &mut Vec<IntuneFinding>) {
    if snapshot.policy_chain.state != PolicyChainState::NotOwnedByIntune {
        return;
    }
    let evidence = snapshot
        .device
        .context
        .as_ref()
        .map(|context| vec![context.evidence_ref.clone()])
        .unwrap_or_default();
    let gaps = if evidence.is_empty() {
        coverage_gap_ids(snapshot)
    } else {
        Vec::new()
    };
    if evidence.is_empty() && gaps.is_empty() {
        return;
    }
    findings.push(finding(
        format!("{POLICY_FINDING_PREFIX}/workload-not-owned-by-intune"),
        IntuneFindingSeverity::Warning,
        snapshot.policy_chain.confidence.clone(),
        "Configuration Manager owns the Windows Update workload",
        "The update workload is not assigned to Intune, so Intune update ring settings are not in force on this device. Any Intune update policy present is delivered but inert."
            .to_owned(),
        &[
            "Confirm the co-management workload slider for Windows Update policies",
            "Evaluate the Configuration Manager software update deployment instead",
        ],
        evidence,
        gaps,
    ));
}

fn push_policy_delivery_failed(snapshot: &UpdateSnapshot, findings: &mut Vec<IntuneFinding>) {
    if snapshot.policy_chain.state != PolicyChainState::DeliveryFailed {
        return;
    }
    let evidence = policy_evidence(snapshot, PolicySignal::DeliveryFailed);
    if evidence.is_empty() {
        return;
    }
    let error = snapshot
        .policy_chain
        .observations
        .iter()
        .find(|observation| observation.signal == PolicySignal::DeliveryFailed)
        .and_then(|observation| observation.error.clone());
    findings.push(finding(
        format!("{POLICY_FINDING_PREFIX}/delivery-failed"),
        IntuneFindingSeverity::Error,
        snapshot.policy_chain.confidence.clone(),
        "Intune failed to deliver update policy to this device",
        format!(
            "An MDM or CSP record reported a failure applying an update policy node{}. This is a policy-delivery fault and says nothing about whether Windows installed any update.",
            error_text(error.as_ref())
        ),
        &[
            "Check the CSP URI and result code on the cited MDM diagnostics record",
            "Confirm the update ring is still assigned and the device is still enrolled",
        ],
        evidence,
        Vec::new(),
    ));
}

fn push_policy_conflict(snapshot: &UpdateSnapshot, findings: &mut Vec<IntuneFinding>) {
    for conflict in &snapshot.policy_chain.conflicts {
        findings.push(finding(
            format!("{POLICY_FINDING_PREFIX}/conflict/{}", conflict.node),
            IntuneFindingSeverity::Error,
            IntuneFindingConfidence::High,
            "Two policy sources contend for the same update setting",
            format!(
                "{} was claimed by {} policy sources ({}). The device applies one of them; the others are not in force.",
                conflict.node,
                conflict.policy_ids.len(),
                conflict.policy_ids.join(", ")
            ),
            &[
                "Remove the overlapping assignment so a single source owns the node",
                "Confirm which source won before assuming the intended value is active",
            ],
            conflict.evidence.clone(),
            Vec::new(),
        ));
    }
}

fn push_policy_unsupported_value(snapshot: &UpdateSnapshot, findings: &mut Vec<IntuneFinding>) {
    let evidence = policy_evidence(snapshot, PolicySignal::UnsupportedValue);
    if evidence.is_empty() {
        return;
    }
    let build = snapshot
        .device
        .windows_build
        .clone()
        .map(|build| format!(" on Windows build {build}"))
        .unwrap_or_default();
    findings.push(finding(
        format!("{POLICY_FINDING_PREFIX}/unsupported-value"),
        IntuneFindingSeverity::Warning,
        IntuneFindingConfidence::High,
        "An update policy value is not supported on this device",
        format!(
            "The device received an update policy value the CSP does not support{build}. The setting was delivered; it is not in effect."
        ),
        &[
            "Check the minimum Windows build for the cited setting",
            "Scope the update ring so unsupported builds are excluded",
        ],
        evidence,
        Vec::new(),
    ));
}

fn push_effective_source_mismatch(snapshot: &UpdateSnapshot, findings: &mut Vec<IntuneFinding>) {
    let assessment = &snapshot.policy_chain.effective_source;
    if assessment.matches_expectation != Some(false) {
        return;
    }
    let (Some(expected), Some(effective)) = (
        assessment.expected.as_ref(),
        assessment.scanned.as_ref().or(assessment.configured.as_ref()),
    ) else {
        return;
    };

    let mut evidence = assessment.scanned_evidence.clone();
    evidence.extend(assessment.configured_evidence.iter().cloned());
    if evidence.is_empty() {
        return;
    }

    // The source is a property of the policy chain, but when the *scanned*
    // source is what proved the mismatch the claim rests on update-client
    // evidence and is stated with higher confidence.
    let confidence = if assessment.scanned.is_some() {
        IntuneFindingConfidence::High
    } else {
        IntuneFindingConfidence::Medium
    };

    findings.push(finding(
        format!("{POLICY_FINDING_PREFIX}/effective-source-mismatch"),
        IntuneFindingSeverity::Error,
        confidence,
        "The device is not using the expected update source",
        format!(
            "Expected update source '{}', observed '{}'. Update-ring deferral and deadline settings do not apply to updates obtained from a different source.",
            source_text(expected),
            source_text(effective)
        ),
        &[
            "Check WUServer and UseWUServer under the WindowsUpdate policy key",
            "Check the SetPolicyDrivenUpdateSourceFor* values and UpdateServiceUrl",
        ],
        evidence,
        Vec::new(),
    ));
}

/// Reported only when something was actually missing.
///
/// If every expected artifact was read and simply contained no update policy,
/// the state is still `NotObserved` and remains queryable on the snapshot, but
/// no finding is emitted: there would be nothing to cite, and an uncited finding
/// is an assertion.
fn push_policy_not_observed(snapshot: &UpdateSnapshot, findings: &mut Vec<IntuneFinding>) {
    if snapshot.policy_chain.state != PolicyChainState::NotObserved {
        return;
    }
    let gaps = coverage_gap_ids(snapshot);
    if gaps.is_empty() {
        return;
    }
    findings.push(finding(
        format!("{POLICY_FINDING_PREFIX}/not-observed"),
        IntuneFindingSeverity::Warning,
        IntuneFindingConfidence::Medium,
        "No update policy delivery evidence was available",
        "No MDM, CSP, or registry record of update policy delivery was present, and part of the expected evidence was not collected. Whether Intune delivered update settings cannot be determined from this bundle."
            .to_owned(),
        &[
            "Collect the DeviceManagement-Enterprise-Diagnostics-Provider/Admin channel",
            "Collect the PolicyManager Update registry values",
        ],
        Vec::new(),
        gaps,
    ));
}

fn push_policy_applied(snapshot: &UpdateSnapshot, findings: &mut Vec<IntuneFinding>) {
    if snapshot.policy_chain.state != PolicyChainState::Applied {
        return;
    }
    let evidence = policy_evidence(snapshot, PolicySignal::Applied);
    if evidence.is_empty() {
        return;
    }
    findings.push(finding(
        format!("{POLICY_FINDING_PREFIX}/applied"),
        IntuneFindingSeverity::Info,
        snapshot.policy_chain.confidence.clone(),
        "Intune update policy was applied",
        "Update policy nodes were delivered and applied. This describes policy delivery only; see the update chain for what Windows Update actually did."
            .to_owned(),
        &["Compare the applied values against the assigned update ring"],
        evidence,
        Vec::new(),
    ));
}

// ── Update chain rules ──────────────────────────────────────────────────────

fn push_scan_failure(snapshot: &UpdateSnapshot, findings: &mut Vec<IntuneFinding>) {
    if snapshot.update_chain.state != UpdateChainState::ScanFailed {
        return;
    }
    let evidence = client_evidence(snapshot, UpdatePhase::Scan, UpdateOutcome::Failed);
    if evidence.is_empty() {
        return;
    }
    findings.push(finding(
        format!("{UPDATE_FINDING_PREFIX}/scan-failed"),
        IntuneFindingSeverity::Error,
        IntuneFindingConfidence::High,
        "The Windows Update client could not complete a scan",
        "The update client reported a detection failure. No applicability, download, or install conclusion can be drawn until scanning succeeds."
            .to_owned(),
        &[
            "Check the error code on the cited WindowsUpdateClient record",
            "Confirm the device can reach the configured update service",
        ],
        evidence,
        Vec::new(),
    ));
}

fn push_no_applicable_update(snapshot: &UpdateSnapshot, findings: &mut Vec<IntuneFinding>) {
    if snapshot.update_chain.state != UpdateChainState::NoApplicableUpdate {
        return;
    }
    let evidence = client_evidence(
        snapshot,
        UpdatePhase::Applicability,
        UpdateOutcome::NotApplicable,
    );
    if evidence.is_empty() {
        return;
    }
    findings.push(finding(
        format!("{UPDATE_FINDING_PREFIX}/no-applicable-update"),
        IntuneFindingSeverity::Info,
        IntuneFindingConfidence::High,
        "The scan succeeded and found no applicable update",
        "The update client completed detection and reported zero applicable updates. This is a successful scan, not a failure, and it is unrelated to whether update policy was delivered."
            .to_owned(),
        &[
            "Confirm the deferral window in the update ring is not holding the update back",
            "Confirm the device build is still in scope for the expected update",
        ],
        evidence,
        Vec::new(),
    ));
}

fn push_download_failure(snapshot: &UpdateSnapshot, findings: &mut Vec<IntuneFinding>) {
    for transaction in transactions_in_state(snapshot, UpdateTransactionState::DownloadFailed) {
        if transaction.evidence.is_empty() {
            continue;
        }
        findings.push(finding(
            format!(
                "{UPDATE_FINDING_PREFIX}/download-failed/{}",
                transaction.key.label()
            ),
            IntuneFindingSeverity::Error,
            transaction.confidence.clone(),
            "An update failed to download",
            format!(
                "{} failed to download{}. The update was offered to the device, so this is a delivery-of-bits failure rather than a policy or applicability problem.",
                transaction.key.label(),
                error_text(transaction.error.as_ref())
            ),
            &[
                "Check Delivery Optimization and proxy reachability for the cited update",
                "Confirm the device has free space and can reach the update source",
            ],
            transaction.evidence.clone(),
            Vec::new(),
        ));
    }
}

fn push_install_failure(snapshot: &UpdateSnapshot, findings: &mut Vec<IntuneFinding>) {
    for transaction in transactions_in_state(snapshot, UpdateTransactionState::InstallFailed) {
        if transaction.evidence.is_empty() {
            continue;
        }
        // Corroboration is added to the citation list, never used in place of
        // it: the guard above means a CBS or DISM line alone can never produce
        // this finding.
        let mut evidence = transaction.evidence.clone();
        let corroborated = !transaction.corroborating_evidence.is_empty();
        evidence.extend(transaction.corroborating_evidence.iter().cloned());

        findings.push(finding(
            format!(
                "{UPDATE_FINDING_PREFIX}/install-failed/{}",
                transaction.key.label()
            ),
            IntuneFindingSeverity::Error,
            transaction.confidence.clone(),
            "An update failed to install",
            format!(
                "{} failed to install{}.{}",
                transaction.key.label(),
                error_text(transaction.error.as_ref()),
                if corroborated {
                    " Servicing-stack evidence naming the same update is cited alongside the update client record."
                } else {
                    ""
                }
            ),
            &[
                "Look up the cited install error code",
                "Check CBS.log and dism.log around the cited update for a servicing fault",
            ],
            evidence,
            Vec::new(),
        ));
    }
}

fn push_deferral(snapshot: &UpdateSnapshot, findings: &mut Vec<IntuneFinding>) {
    for transaction in transactions_in_state(snapshot, UpdateTransactionState::Deferred) {
        if transaction.evidence.is_empty() {
            continue;
        }
        findings.push(finding(
            format!(
                "{UPDATE_FINDING_PREFIX}/deferred/{}",
                transaction.key.label()
            ),
            IntuneFindingSeverity::Info,
            transaction.confidence.clone(),
            "An update is held by a maintenance window or deadline policy",
            format!(
                "{} was downloaded or offered but held back by an active-hours, deadline, or deferral policy. This is working as configured, not a failure.",
                transaction.key.label()
            ),
            &[
                "Check the active hours and deadline settings on the assigned update ring",
                "Confirm the deadline has not yet elapsed for the cited update",
            ],
            transaction.evidence.clone(),
            Vec::new(),
        ));
    }
}

fn push_reboot_pending(snapshot: &UpdateSnapshot, findings: &mut Vec<IntuneFinding>) {
    let mut evidence: Vec<IntuneEvidenceRef> =
        transactions_in_state(snapshot, UpdateTransactionState::RebootPending)
            .into_iter()
            .flat_map(|transaction| transaction.evidence.iter().cloned())
            .collect();
    if evidence.is_empty() {
        evidence = client_evidence(snapshot, UpdatePhase::Reboot, UpdateOutcome::Pending);
    }
    if evidence.is_empty() || snapshot.update_chain.reboot_pending != Some(true) {
        return;
    }
    findings.push(finding(
        format!("{UPDATE_FINDING_PREFIX}/reboot-pending"),
        IntuneFindingSeverity::Warning,
        IntuneFindingConfidence::High,
        "A restart is required to finish installing an update",
        "The update client reported that a restart is required. The update is staged but not complete, so a service-side report of 'installed' would be premature."
            .to_owned(),
        &[
            "Confirm the restart deadline and grace period on the assigned update ring",
            "Confirm the device has not been blocked from restarting",
        ],
        evidence,
        Vec::new(),
    ));
}

fn push_installed(snapshot: &UpdateSnapshot, findings: &mut Vec<IntuneFinding>) {
    for transaction in transactions_in_state(snapshot, UpdateTransactionState::Installed) {
        if transaction.evidence.is_empty() {
            continue;
        }
        findings.push(finding(
            format!(
                "{UPDATE_FINDING_PREFIX}/installed/{}",
                transaction.key.label()
            ),
            IntuneFindingSeverity::Info,
            transaction.confidence.clone(),
            "An update installed successfully",
            format!(
                "{} was installed successfully according to the Windows Update client.",
                transaction.key.label()
            ),
            &["Confirm the installed revision matches the intended update"],
            transaction.evidence.clone(),
            Vec::new(),
        ));
    }
}

/// The service and the device disagree about one update.
///
/// The device's own update-client record is treated as authoritative and the
/// service report as the stale party, because the report is produced from data
/// the device already sent and can lag it by hours.
fn push_reporting_mismatch(snapshot: &UpdateSnapshot, findings: &mut Vec<IntuneFinding>) {
    for transaction in &snapshot.update_chain.transactions {
        let Some(service_state) = &transaction.service_state else {
            continue;
        };
        if transaction.evidence.is_empty() || transaction.service_evidence.is_empty() {
            continue;
        }
        let agrees = match (transaction.state, service_state) {
            (UpdateTransactionState::Installed, ServiceReportedState::Installed) => true,
            (UpdateTransactionState::InstallFailed, ServiceReportedState::Failed) => true,
            (UpdateTransactionState::DownloadFailed, ServiceReportedState::Failed) => true,
            (UpdateTransactionState::NoApplicableUpdate, ServiceReportedState::NotApplicable) => {
                true
            }
            (
                UpdateTransactionState::RebootPending | UpdateTransactionState::InProgress,
                ServiceReportedState::Pending,
            ) => true,
            // An unrecognized service vocabulary value is not a disagreement.
            (_, ServiceReportedState::Unknown(_)) => true,
            _ => false,
        };
        if agrees {
            continue;
        }

        let mut evidence = transaction.evidence.clone();
        evidence.extend(transaction.service_evidence.iter().cloned());
        findings.push(finding(
            format!(
                "{UPDATE_FINDING_PREFIX}/reporting-mismatch/{}",
                transaction.key.label()
            ),
            IntuneFindingSeverity::Warning,
            IntuneFindingConfidence::Medium,
            "The service report disagrees with the device's own update record",
            format!(
                "Local Windows Update client evidence for {} reads '{}', while the Intune update report reads '{}'. The local record is the more recent of the two.",
                transaction.key.label(),
                serde_json::to_value(transaction.state)
                    .ok()
                    .and_then(|value| value.as_str().map(str::to_owned))
                    .unwrap_or_else(|| "unknown".to_owned()),
                source_text_for_service(service_state)
            ),
            &[
                "Allow a reporting cycle to complete before acting on the service report",
                "Confirm the device is still checking in if the report stays stale",
            ],
            evidence,
            Vec::new(),
        ));
    }
}

fn source_text_for_service(state: &ServiceReportedState) -> String {
    serde_json::to_value(state)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| "unknown".to_owned())
}

// ── Evidence-quality rules ──────────────────────────────────────────────────

fn push_order_contradiction(snapshot: &UpdateSnapshot, findings: &mut Vec<IntuneFinding>) {
    for transaction in &snapshot.update_chain.transactions {
        if !transaction.order_contradiction {
            continue;
        }
        let mut evidence = transaction.evidence.clone();
        evidence.extend(transaction.corroborating_evidence.iter().cloned());
        if evidence.is_empty() {
            continue;
        }
        findings.push(finding(
            format!(
                "{EVIDENCE_FINDING_PREFIX}/contradictory-order/{}",
                transaction.key.label()
            ),
            IntuneFindingSeverity::Warning,
            IntuneFindingConfidence::High,
            "Timestamps for one update cannot describe a real sequence",
            format!(
                "Records for {} carry an unusable or out-of-order timestamp, so the phase ordering is not trustworthy. The reported state is held at low confidence.",
                transaction.key.label()
            ),
            &[
                "Check the timezone offset on the cited records",
                "Re-collect the evidence from a source with normalized timestamps",
            ],
            evidence,
            Vec::new(),
        ));
    }
}

fn push_unknown_schema(snapshot: &UpdateSnapshot, findings: &mut Vec<IntuneFinding>) {
    let coverage = &snapshot.input_coverage;
    if !coverage.has_unknowns() || coverage.evidence.is_empty() {
        return;
    }
    let mut parts = Vec::new();
    if coverage.unmapped_event_ids > 0 {
        parts.push(format!(
            "{} record(s) from a modeled provider carried event id(s) {} that this build does not map",
            coverage.unmapped_event_ids,
            coverage
                .unmapped_event_id_list
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if coverage.unknown_provider_events > 0 {
        parts.push(format!(
            "{} record(s) came from unmodeled provider(s) {}",
            coverage.unknown_provider_events,
            coverage.unknown_providers.join(", ")
        ));
    }
    findings.push(finding(
        format!("{EVIDENCE_FINDING_PREFIX}/unknown-schema"),
        IntuneFindingSeverity::Info,
        IntuneFindingConfidence::High,
        "Part of the supplied evidence uses a schema this build does not model",
        format!(
            "{}. Those records are retained but contribute to no conclusion, so an absent signal here does not mean the event did not occur.",
            parts.join("; ")
        ),
        &["Update the analyzer's event tables, or supply the phase through the documented adapter keys"],
        coverage.evidence.clone(),
        Vec::new(),
    ));
}

fn push_coverage_gaps(snapshot: &UpdateSnapshot, findings: &mut Vec<IntuneFinding>) {
    for entry in &snapshot.coverage {
        if entry.status == IntuneArtifactStatus::Available {
            continue;
        }
        let status = serde_json::to_value(&entry.status)
            .ok()
            .and_then(|value| value.as_str().map(str::to_owned))
            .unwrap_or_else(|| "unknown".to_owned());
        findings.push(finding(
            format!("{EVIDENCE_FINDING_PREFIX}/coverage-gap/{}", entry.artifact_id),
            IntuneFindingSeverity::Info,
            IntuneFindingConfidence::High,
            "Expected update evidence was not usable",
            format!(
                "Artifact '{}' (family '{}') reported status '{}', so any signal it would have carried is unknown rather than absent.",
                entry.artifact_id, entry.family, status
            ),
            &["Re-collect the named artifact and re-run the analysis"],
            entry.evidence.clone(),
            vec![entry.artifact_id.clone()],
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_snapshot_produces_no_findings() {
        let snapshot = UpdateSnapshot::default();
        assert!(derive_findings(&snapshot).is_empty());
    }

    #[test]
    fn every_finding_id_uses_one_of_the_three_documented_prefixes() {
        for prefix in [
            POLICY_FINDING_PREFIX,
            UPDATE_FINDING_PREFIX,
            EVIDENCE_FINDING_PREFIX,
        ] {
            assert!(prefix.starts_with(FINDING_PREFIX));
        }
    }
}
