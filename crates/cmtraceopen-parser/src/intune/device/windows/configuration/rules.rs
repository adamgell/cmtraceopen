//! Conservative findings derived from an immutable configuration snapshot.
//!
//! Every rule is one private `push_*` and emits at most one aggregated finding,
//! so the finding identifiers are a fixed vocabulary rather than a function of
//! how many settings a device happens to have.
//!
//! Two invariants hold for all of them:
//!
//! 1. A finding cites at least one [`IntuneEvidenceRef`] or at least one coverage
//!    gap identifier. Callers can assert this with
//!    [`IntuneFinding::is_evidence_backed`].
//! 2. Conflict and supersedence are only *claimed* when the competing source was
//!    actually observed. When the device says "conflict" and the other side of
//!    the argument is nowhere in the bundle, the finding says exactly that and
//!    asks for the next artifact instead.

use std::collections::{BTreeMap, BTreeSet};

use crate::intune::evidence::{
    IntuneArtifactStatus, IntuneErrorCode, IntuneEvidenceRef, IntuneFinding,
    IntuneFindingConfidence, IntuneFindingSeverity,
};

use super::identity::ConfigurationScope;
use super::models::{
    ConfigurationDisposition, ConfigurationEvidenceSide, ConfigurationLocalState,
    ConfigurationObservation, ConfigurationReceiptState, ConfigurationResolution,
    ConfigurationServiceState, ConfigurationSetting, ConfigurationSnapshot,
};
use super::sources::{normalize_source_id, same_source_id};

/// Maximum number of setting labels quoted in a summary before it is truncated.
const MAX_LABELS: usize = 6;

/// Derive every finding this build knows how to state.
///
/// The order is fixed so a golden fixture can assert the whole vector.
pub fn derive_findings(snapshot: &ConfigurationSnapshot) -> Vec<IntuneFinding> {
    let mut findings = Vec::new();

    push_local_rejection(snapshot, &mut findings);
    push_local_service_contradiction(snapshot, &mut findings);
    push_contested_device_evidence(snapshot, &mut findings);
    push_unassessable_failure(snapshot, &mut findings);
    push_substantiated_conflict(snapshot, &mut findings);
    push_unsubstantiated_conflict(snapshot, &mut findings);
    push_substantiated_supersedence(snapshot, &mut findings);
    push_unsubstantiated_supersedence(snapshot, &mut findings);
    push_removal(snapshot, &mut findings);
    push_not_applicable(snapshot, &mut findings);
    push_scope_split(snapshot, &mut findings);
    push_duplicate_display_name(snapshot, &mut findings);
    push_service_only_evidence(snapshot, &mut findings);
    push_device_only_evidence(snapshot, &mut findings);
    push_uninterpretable_evidence(snapshot, &mut findings);
    push_unusable_ordering(snapshot, &mut findings);
    push_unattributed_records(snapshot, &mut findings);
    push_uncollected_artifacts(snapshot, &mut findings);
    push_truncated_artifacts(snapshot, &mut findings);
    push_unreadable_artifacts(snapshot, &mut findings);
    push_artifacts_without_usable_records(snapshot, &mut findings);
    push_applied(snapshot, &mut findings);

    findings
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// The most specific human-readable name for a setting.
fn label(setting: &ConfigurationSetting) -> String {
    setting
        .identity
        .canonical_uri
        .clone()
        .or_else(|| setting.identity.setting_id.clone())
        .or_else(|| setting.identity.display_name.clone())
        .unwrap_or_else(|| setting.identity.key.clone())
}

/// Comma-joined, de-duplicated, capped setting labels.
fn join_labels(settings: &[&ConfigurationSetting]) -> String {
    let mut labels: Vec<String> = Vec::new();
    for setting in settings {
        let value = label(setting);
        if !labels.contains(&value) {
            labels.push(value);
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

/// Sorted, de-duplicated evidence references.
fn collect_evidence<'a>(
    refs: impl IntoIterator<Item = &'a IntuneEvidenceRef>,
) -> Vec<IntuneEvidenceRef> {
    refs.into_iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// Evidence for every observation of `settings` matching `keep`.
fn evidence_where(
    settings: &[&ConfigurationSetting],
    keep: impl Fn(&ConfigurationObservation) -> bool + Copy,
) -> Vec<IntuneEvidenceRef> {
    collect_evidence(
        settings
            .iter()
            .flat_map(|setting| setting.observations.iter())
            .filter(|observation| keep(observation))
            .map(|observation| &observation.evidence_ref),
    )
}

#[allow(clippy::too_many_arguments)]
fn finding(
    finding_id: &str,
    severity: IntuneFindingSeverity,
    confidence: IntuneFindingConfidence,
    title: &str,
    summary: String,
    recommended_checks: Vec<String>,
    evidence: Vec<IntuneEvidenceRef>,
    coverage_gap_ids: Vec<String>,
) -> IntuneFinding {
    IntuneFinding {
        finding_id: finding_id.to_owned(),
        severity,
        confidence,
        title: title.to_owned(),
        summary,
        recommended_checks,
        evidence,
        coverage_gap_ids,
    }
}

/// Append `candidate` only when it cites something.
///
/// This is the single choke point that upholds the evidence-backed invariant; a
/// rule that computed an empty citation set silently emits nothing rather than an
/// unsupported claim.
fn push_finding(findings: &mut Vec<IntuneFinding>, candidate: IntuneFinding) {
    if candidate.is_evidence_backed() {
        findings.push(candidate);
    }
}

fn select(
    snapshot: &ConfigurationSnapshot,
    keep: impl Fn(&ConfigurationSetting) -> bool,
) -> Vec<&ConfigurationSetting> {
    snapshot.settings.iter().filter(|s| keep(s)).collect()
}

// ── Device outcome rules ────────────────────────────────────────────────────

fn push_local_rejection(snapshot: &ConfigurationSnapshot, findings: &mut Vec<IntuneFinding>) {
    let settings = select(snapshot, |setting| {
        setting.local == ConfigurationLocalState::Rejected
    });
    if settings.is_empty() {
        return;
    }
    let codes = settings
        .iter()
        .filter_map(|setting| setting.local_error.as_ref())
        .map(|code| code.hex.clone().unwrap_or_else(|| code.raw.clone()))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let codes = if codes.is_empty() {
        "no readable status".to_owned()
    } else {
        codes.join(", ")
    };
    push_finding(
        findings,
        finding(
            "configuration-local-rejection",
            IntuneFindingSeverity::Error,
            IntuneFindingConfidence::High,
            "A CSP rejected a configuration setting on the device",
            format!(
                "The configuration service provider returned a terminal error for {}. Reported status: {codes}.",
                join_labels(&settings)
            ),
            vec![
                "Look up the cited status code for the named CSP node.".to_owned(),
                "Confirm the device meets the edition, build, and licensing prerequisites for that node.".to_owned(),
            ],
            evidence_where(&settings, |observation| {
                observation.side == ConfigurationEvidenceSide::Device
                    && observation.disposition == ConfigurationDisposition::Rejected
            }),
            Vec::new(),
        ),
    );
}

fn push_local_service_contradiction(
    snapshot: &ConfigurationSnapshot,
    findings: &mut Vec<IntuneFinding>,
) {
    let settings = select(snapshot, |setting| {
        setting.resolution == ConfigurationResolution::Contradicted
            && setting.local != ConfigurationLocalState::Contested
            && setting.service != ConfigurationServiceState::NoEvidence
    });
    if settings.is_empty() {
        return;
    }
    let recency = if settings.iter().all(|setting| setting.recency_is_usable()) {
        "Both sides carry usable time provenance, but neither is authoritative over the other."
    } else {
        "At least one side has unusable time provenance, so the newer statement cannot be preferred."
    };
    // `service_error` was populated and cited by no rule at all, so the code
    // Intune reported never reached a reader. It belongs here: the whole point of
    // the finding is to put the two statements side by side.
    let codes = |pick: fn(&ConfigurationSetting) -> Option<&IntuneErrorCode>| {
        settings
            .iter()
            .filter_map(|setting| pick(setting))
            .map(|code| code.hex.clone().unwrap_or_else(|| code.raw.clone()))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
    };
    let reported = |label: &str, codes: Vec<String>| {
        if codes.is_empty() {
            String::new()
        } else {
            format!(" {label} status: {}.", codes.join(", "))
        }
    };
    let statuses = format!(
        "{}{}",
        reported(
            "Device-reported",
            codes(|setting| setting.local_error.as_ref())
        ),
        reported(
            "Service-reported",
            codes(|setting| setting.service_error.as_ref())
        ),
    );
    push_finding(
        findings,
        finding(
            "configuration-local-service-contradiction",
            IntuneFindingSeverity::Error,
            IntuneFindingConfidence::High,
            "Device evidence and Intune reporting disagree",
            format!(
                "The device and the imported Intune report state incompatible outcomes for {}.{statuses} {recency} The device statement describes what the CSP did; the service statement describes what Intune was told.",
                join_labels(&settings)
            ),
            vec![
                "Compare the cited device record and service row side by side before trusting either.".to_owned(),
                "Re-collect both after a forced sync so the two describe the same policy version.".to_owned(),
            ],
            evidence_where(&settings, |observation| {
                observation.disposition.is_terminal()
            }),
            Vec::new(),
        ),
    );
}

fn push_contested_device_evidence(
    snapshot: &ConfigurationSnapshot,
    findings: &mut Vec<IntuneFinding>,
) {
    // A setting contested only because a failure record could not be read is
    // reported by `push_unassessable_failure`, which can name the actual shape.
    // Saying "records state a different terminal outcome" about it would be wrong:
    // one of them states no outcome at all.
    let settings = select(snapshot, |setting| {
        setting.local == ConfigurationLocalState::Contested && !setting.has_unassessable_failure
    });
    if settings.is_empty() {
        return;
    }
    push_finding(
        findings,
        finding(
            "configuration-contested-device-evidence",
            IntuneFindingSeverity::Error,
            IntuneFindingConfidence::Medium,
            "Device records disagree about the same setting",
            format!(
                "More than one device-side record states a different terminal outcome for {}. No outcome is claimed.",
                join_labels(&settings)
            ),
            vec![
                "Order the cited records by their channel record numbers rather than by timestamp.".to_owned(),
                "Check whether the records belong to different enrollments or configuration sources.".to_owned(),
            ],
            evidence_where(&settings, |observation| {
                observation.side == ConfigurationEvidenceSide::Device
                    && observation.disposition.is_terminal()
            }),
            Vec::new(),
        ),
    );
}

/// A device record that reports a failure nobody can read the reason for.
fn push_unassessable_failure(snapshot: &ConfigurationSnapshot, findings: &mut Vec<IntuneFinding>) {
    let settings = select(snapshot, |setting| setting.has_unassessable_failure);
    if settings.is_empty() {
        return;
    }
    push_finding(
        findings,
        finding(
            "configuration-unassessable-failure",
            IntuneFindingSeverity::Warning,
            IntuneFindingConfidence::High,
            "A reported command failure could not be read",
            format!(
                "A device record reports a CSP command failure for {}, but its status could not be interpreted or the record was not fully read. The direction is still evidence: no success is claimed for these settings, even where another record says the value was written.",
                join_labels(&settings)
            ),
            vec![
                "Re-collect the event channel with the event XML preserved so the status reaches the analyzer.".to_owned(),
                "Compare the cited failure record with any success record for the same node before acting on either.".to_owned(),
            ],
            evidence_where(&settings, |observation| {
                observation.side == ConfigurationEvidenceSide::Device
                    && !observation.disposition.is_terminal()
            }),
            Vec::new(),
        ),
    );
}

/// A conflict where the competing source is actually present in the bundle.
fn push_substantiated_conflict(
    snapshot: &ConfigurationSnapshot,
    findings: &mut Vec<IntuneFinding>,
) {
    let settings = select(snapshot, |setting| {
        is_conflicted(setting) && competing_sources_are_observed(setting)
    });
    if settings.is_empty() {
        return;
    }
    push_finding(
        findings,
        finding(
            "configuration-conflict",
            IntuneFindingSeverity::Warning,
            IntuneFindingConfidence::High,
            "Two configuration sources target the same setting",
            format!(
                "{} is claimed by more than one configuration source, and the competing statements are cited below.",
                join_labels(&settings)
            ),
            vec![
                "Compare the cited configuration source identifiers against the policies assigned to this device.".to_owned(),
                "Remove the setting from all but one policy, or align their values.".to_owned(),
            ],
            evidence_where(&settings, |_| true),
            Vec::new(),
        ),
    );
}

/// A reported conflict whose other side is missing from the bundle.
fn push_unsubstantiated_conflict(
    snapshot: &ConfigurationSnapshot,
    findings: &mut Vec<IntuneFinding>,
) {
    let settings = select(snapshot, |setting| {
        is_conflicted(setting) && !competing_sources_are_observed(setting)
    });
    if settings.is_empty() {
        return;
    }
    push_finding(
        findings,
        finding(
            "configuration-conflict-unsubstantiated",
            IntuneFindingSeverity::Warning,
            IntuneFindingConfidence::Low,
            "A conflict was reported but the competing source was not collected",
            format!(
                "A record reports a conflict for {}, but no second configuration source for that node appears in this bundle, so the competing policy is not identified here.",
                join_labels(&settings)
            ),
            vec![
                "Collect the full MDM diagnostic report so every configuration source for the node is present.".to_owned(),
                "Export the device's policy assignments and compare them with the cited node.".to_owned(),
            ],
            evidence_where(&settings, |observation| {
                observation.disposition == ConfigurationDisposition::Conflict
            }),
            Vec::new(),
        ),
    );
}

fn is_conflicted(setting: &ConfigurationSetting) -> bool {
    setting.local == ConfigurationLocalState::Conflicted
        || setting.service == ConfigurationServiceState::ReportedConflict
}

/// Every distinct configuration source that stated something about this node.
///
/// Normalized, because one policy GUID written braced by the event provider and
/// bare by the report is one source, and comparing the bytes made it two
/// competing ones — enough on its own to raise a conflict finding.
fn observed_source_ids(setting: &ConfigurationSetting) -> BTreeSet<String> {
    setting
        .sources
        .iter()
        .filter_map(|statement| statement.source_id.as_deref())
        .map(normalize_source_id)
        .collect()
}

/// Whether the bundle actually contains the second side of the argument.
///
/// Either two distinct configuration sources stated something about the node, or
/// a record named a winner *that is itself in the bundle*. Merely naming someone
/// is not observing them: a single row carrying `WinningProvider: GPO` used to
/// substantiate a conflict at Warning/High with one source present and the
/// alleged winner nowhere in the evidence. Such a row now reaches the
/// unsubstantiated variant, which asks for the missing artifact instead.
fn competing_sources_are_observed(setting: &ConfigurationSetting) -> bool {
    let observed = observed_source_ids(setting);
    if observed.len() >= 2 {
        return true;
    }
    setting.observations.iter().any(|observation| {
        observation
            .winning_source_id
            .as_deref()
            .is_some_and(|winner| {
                let names_another = observation
                    .source_id
                    .as_deref()
                    .is_none_or(|source| !same_source_id(source, winner));
                names_another && observed.contains(&normalize_source_id(winner))
            })
    })
}

fn push_substantiated_supersedence(
    snapshot: &ConfigurationSnapshot,
    findings: &mut Vec<IntuneFinding>,
) {
    let settings = select(snapshot, |setting| {
        is_superseded(setting) && superseding_source_is_observed(setting)
    });
    if settings.is_empty() {
        return;
    }
    push_finding(
        findings,
        finding(
            "configuration-superseded",
            IntuneFindingSeverity::Info,
            IntuneFindingConfidence::High,
            "A setting was replaced by another configuration source",
            format!(
                "{} was superseded, and the replacing configuration source is cited below.",
                join_labels(&settings)
            ),
            vec![
                "Confirm the replacing configuration source carries the value you intended."
                    .to_owned(),
            ],
            evidence_where(&settings, |_| true),
            Vec::new(),
        ),
    );
}

fn push_unsubstantiated_supersedence(
    snapshot: &ConfigurationSnapshot,
    findings: &mut Vec<IntuneFinding>,
) {
    let settings = select(snapshot, |setting| {
        is_superseded(setting) && !superseding_source_is_observed(setting)
    });
    if settings.is_empty() {
        return;
    }
    push_finding(
        findings,
        finding(
            "configuration-superseded-unsubstantiated",
            IntuneFindingSeverity::Warning,
            IntuneFindingConfidence::Low,
            "A setting was reported superseded but the replacement was not collected",
            format!(
                "A record reports {} as superseded without naming a replacing source that also appears in this bundle.",
                join_labels(&settings)
            ),
            vec![
                "Collect the full MDM diagnostic report so the replacing configuration source is present.".to_owned(),
            ],
            evidence_where(&settings, |observation| {
                observation.disposition == ConfigurationDisposition::Superseded
            }),
            Vec::new(),
        ),
    );
}

fn is_superseded(setting: &ConfigurationSetting) -> bool {
    setting.local == ConfigurationLocalState::Superseded
        || setting.service == ConfigurationServiceState::ReportedSuperseded
}

/// Whether the replacing source named by a superseded record is in the bundle.
///
/// The self-reference guard mirrors the conflict rule's: a row naming *itself* as
/// its own replacement matched the bundle trivially and produced
/// `configuration-superseded` at High confidence with one source present.
fn superseding_source_is_observed(setting: &ConfigurationSetting) -> bool {
    let observed = observed_source_ids(setting);
    setting.observations.iter().any(|observation| {
        observation
            .superseded_by_source_id
            .as_deref()
            .is_some_and(|replacement| {
                let names_another = observation
                    .source_id
                    .as_deref()
                    .is_none_or(|source| !same_source_id(source, replacement));
                names_another && observed.contains(&normalize_source_id(replacement))
            })
    })
}

fn push_removal(snapshot: &ConfigurationSnapshot, findings: &mut Vec<IntuneFinding>) {
    let settings = select(snapshot, |setting| {
        setting.resolution == ConfigurationResolution::Removed
    });
    if settings.is_empty() {
        return;
    }
    push_finding(
        findings,
        finding(
            "configuration-removed",
            IntuneFindingSeverity::Info,
            IntuneFindingConfidence::High,
            "A setting was removed from the device",
            format!(
                "The CSP deleted {}. A removal is the expected result of unassigning a policy; it is only a problem if the policy is still assigned.",
                join_labels(&settings)
            ),
            vec![
                "Confirm the policy carrying the cited node is still assigned to this device.".to_owned(),
            ],
            evidence_where(&settings, |observation| {
                observation.disposition == ConfigurationDisposition::Removed
            }),
            Vec::new(),
        ),
    );
}

fn push_not_applicable(snapshot: &ConfigurationSnapshot, findings: &mut Vec<IntuneFinding>) {
    let settings = select(snapshot, |setting| {
        setting.resolution == ConfigurationResolution::NotApplicable
    });
    if settings.is_empty() {
        return;
    }
    push_finding(
        findings,
        finding(
            "configuration-not-applicable",
            IntuneFindingSeverity::Info,
            IntuneFindingConfidence::High,
            "A setting does not apply to this device",
            format!(
                "{} was reported as not applicable, so no value was written. This build does not infer why; the CSP decides applicability from edition, build, and hardware.",
                join_labels(&settings)
            ),
            vec![
                "Check the Windows edition and build requirements documented for the cited CSP node.".to_owned(),
            ],
            evidence_where(&settings, |observation| {
                observation.disposition == ConfigurationDisposition::NotApplicable
            }),
            Vec::new(),
        ),
    );
}

// ── Identity rules ──────────────────────────────────────────────────────────

/// The same CSP node observed under both device and user scope.
fn push_scope_split(snapshot: &ConfigurationSnapshot, findings: &mut Vec<IntuneFinding>) {
    let mut by_resource: BTreeMap<String, Vec<&ConfigurationSetting>> = BTreeMap::new();
    for setting in &snapshot.settings {
        if matches!(setting.identity.scope, ConfigurationScope::Unspecified) {
            continue;
        }
        let Some(resource) = setting.identity.resource_path.as_deref() else {
            continue;
        };
        // Lowercased for the same reason the dedupe key is: CSP node names are
        // documented with specific casing but are not case-sensitive, and grouping
        // on the exact bytes meant a device `Start/…` and a user `start/…` were
        // two separate transactions that never met, so the scope split they
        // represent went unreported.
        by_resource
            .entry(resource.to_ascii_lowercase())
            .or_default()
            .push(setting);
    }

    let split: Vec<&ConfigurationSetting> = by_resource
        .into_values()
        .filter(|settings| {
            settings
                .iter()
                .map(|setting| setting.identity.scope)
                .collect::<BTreeSet<_>>()
                .len()
                > 1
        })
        .flatten()
        .collect();
    if split.is_empty() {
        return;
    }

    push_finding(
        findings,
        finding(
            "configuration-scope-split",
            IntuneFindingSeverity::Warning,
            IntuneFindingConfidence::High,
            "The same CSP node was targeted in both device and user scope",
            format!(
                "{} appears under both ./Device and ./User. These are separate settings with separate outcomes; a value written in one scope does not satisfy the other.",
                join_labels(&split)
            ),
            vec![
                "Confirm which scope the policy intended, and compare it with the cited records.".to_owned(),
                "For a user-scoped node, confirm a user was signed in when the CSP ran.".to_owned(),
            ],
            evidence_where(&split, |_| true),
            Vec::new(),
        ),
    );
}

/// One friendly name shared by two different CSP paths.
fn push_duplicate_display_name(
    snapshot: &ConfigurationSnapshot,
    findings: &mut Vec<IntuneFinding>,
) {
    let mut by_name: BTreeMap<String, Vec<&ConfigurationSetting>> = BTreeMap::new();
    for setting in &snapshot.settings {
        let Some(name) = setting.identity.display_name.as_deref() else {
            continue;
        };
        by_name
            .entry(name.to_ascii_lowercase())
            .or_default()
            .push(setting);
    }

    let duplicates: Vec<&ConfigurationSetting> = by_name
        .into_values()
        .filter(|settings| {
            settings
                .iter()
                .map(|setting| setting.identity.key.as_str())
                .collect::<BTreeSet<_>>()
                .len()
                > 1
        })
        .flatten()
        .collect();
    if duplicates.is_empty() {
        return;
    }

    push_finding(
        findings,
        finding(
            "configuration-duplicate-display-name",
            IntuneFindingSeverity::Info,
            IntuneFindingConfidence::High,
            "One display name covers more than one CSP node",
            format!(
                "{} share a display name but resolve to different CSP identities and are reported separately here. A portal view that groups by name will look inconsistent with this output.",
                join_labels(&duplicates)
            ),
            vec![
                "Match the cited OMA-URIs, not the display names, when comparing with the portal.".to_owned(),
            ],
            evidence_where(&duplicates, |_| true),
            Vec::new(),
        ),
    );
}

// ── Coverage rules ──────────────────────────────────────────────────────────

fn push_service_only_evidence(snapshot: &ConfigurationSnapshot, findings: &mut Vec<IntuneFinding>) {
    let settings = select(snapshot, |setting| {
        setting.receipt == ConfigurationReceiptState::Intended
            && setting.service != ConfigurationServiceState::NoEvidence
    });
    if settings.is_empty() {
        return;
    }
    push_finding(
        findings,
        finding(
            "configuration-service-only-evidence",
            IntuneFindingSeverity::Warning,
            IntuneFindingConfidence::Medium,
            "Only Intune reporting describes these settings",
            format!(
                "{} is described solely by imported Intune data. A portal status reports what the service was told and does not prove the CSP applied anything on this device.",
                join_labels(&settings)
            ),
            vec![
                "Collect the DeviceManagement-Enterprise-Diagnostics-Provider/Admin channel from the device.".to_owned(),
                "Collect an MDM diagnostic report so the local CSP state is present.".to_owned(),
            ],
            evidence_where(&settings, |_| true),
            Vec::new(),
        ),
    );
}

fn push_device_only_evidence(snapshot: &ConfigurationSnapshot, findings: &mut Vec<IntuneFinding>) {
    // Only settings whose local state actually says something. A device record
    // that could not be interpreted is reported by the uninterpretable-evidence
    // rule; calling it "device evidence" here would overstate what was read.
    let settings = select(snapshot, |setting| {
        setting.service == ConfigurationServiceState::NoEvidence
            && !matches!(
                setting.local,
                ConfigurationLocalState::NoEvidence | ConfigurationLocalState::Indeterminate
            )
    });
    if settings.is_empty() {
        return;
    }
    push_finding(
        findings,
        finding(
            "configuration-device-only-evidence",
            IntuneFindingSeverity::Info,
            IntuneFindingConfidence::High,
            "No Intune reporting was imported for these settings",
            format!(
                "{} is described only by device evidence. That is sufficient to state what the CSP did, but it cannot show whether Intune received the same answer.",
                join_labels(&settings)
            ),
            vec![
                "Import the Intune per-setting report if you need to compare device state with service reporting.".to_owned(),
            ],
            evidence_where(&settings, |_| true),
            Vec::new(),
        ),
    );
}

fn push_uninterpretable_evidence(
    snapshot: &ConfigurationSnapshot,
    findings: &mut Vec<IntuneFinding>,
) {
    let settings = select(snapshot, |setting| setting.has_uninterpretable_evidence);
    let unattributed_uninterpretable = snapshot
        .unattributed
        .iter()
        .filter(|observation| observation.is_uninterpretable)
        .map(|observation| &observation.evidence_ref);

    let mut evidence = evidence_where(&settings, |observation| observation.is_uninterpretable);
    evidence.extend(unattributed_uninterpretable.cloned());
    let evidence = collect_evidence(evidence.iter());
    if evidence.is_empty() {
        return;
    }

    push_finding(
        findings,
        finding(
            "configuration-uninterpretable-evidence",
            IntuneFindingSeverity::Warning,
            IntuneFindingConfidence::High,
            "Some configuration records could not be interpreted",
            format!(
                "{} record(s) were malformed or used a schema this build does not recognize. They are retained as evidence but contribute no outcome, so absence of a result for the settings they mention proves nothing.",
                evidence.len()
            ),
            vec![
                "Re-export the MDM diagnostic report; a truncated export is the usual cause.".to_owned(),
                "Check whether the report or event schema is newer than this build supports.".to_owned(),
            ],
            evidence,
            Vec::new(),
        ),
    );
}

fn push_unusable_ordering(snapshot: &ConfigurationSnapshot, findings: &mut Vec<IntuneFinding>) {
    let settings = select(snapshot, |setting| !setting.recency_is_usable());
    if settings.is_empty() {
        return;
    }
    push_finding(
        findings,
        finding(
            "configuration-unusable-ordering",
            IntuneFindingSeverity::Warning,
            IntuneFindingConfidence::High,
            "Record ordering cannot be trusted for these settings",
            format!(
                "For {}, a contributing record carries an invalid or ambiguous timestamp, or the channel record numbers contradict the timestamps. No outcome in this report was chosen by preferring the newer record.",
                join_labels(&settings)
            ),
            vec![
                "Re-collect the event channel; a clock change during capture produces this shape.".to_owned(),
                "Order the cited records by their channel record numbers instead of their timestamps.".to_owned(),
            ],
            evidence_where(&settings, |_| true),
            Vec::new(),
        ),
    );
}

fn push_unattributed_records(snapshot: &ConfigurationSnapshot, findings: &mut Vec<IntuneFinding>) {
    if snapshot.unattributed.is_empty() {
        return;
    }
    push_finding(
        findings,
        finding(
            "configuration-unattributed-records",
            IntuneFindingSeverity::Warning,
            IntuneFindingConfidence::Medium,
            "Some records name no identifiable setting",
            format!(
                "{} record(s) describe a configuration outcome without an OMA-URI or setting identifier. They are kept separate and never merged with an identified setting, because a name alone cannot establish which node they are about.",
                snapshot.unattributed.len()
            ),
            vec![
                "Re-collect with the event XML preserved so the node URI reaches the analyzer.".to_owned(),
            ],
            collect_evidence(
                snapshot
                    .unattributed
                    .iter()
                    .map(|observation| &observation.evidence_ref),
            ),
            Vec::new(),
        ),
    );
}

fn artifacts_with_status(
    snapshot: &ConfigurationSnapshot,
    statuses: &[IntuneArtifactStatus],
) -> Vec<String> {
    snapshot
        .coverage
        .iter()
        .filter(|entry| statuses.contains(&entry.status))
        .map(|entry| entry.artifact_id.clone())
        .collect()
}

fn push_uncollected_artifacts(snapshot: &ConfigurationSnapshot, findings: &mut Vec<IntuneFinding>) {
    let gaps = artifacts_with_status(
        snapshot,
        &[
            IntuneArtifactStatus::Missing,
            IntuneArtifactStatus::PermissionDenied,
            IntuneArtifactStatus::Skipped,
        ],
    );
    if gaps.is_empty() {
        return;
    }
    push_finding(
        findings,
        finding(
            "configuration-uncollected-artifacts",
            IntuneFindingSeverity::Warning,
            IntuneFindingConfidence::High,
            "Expected configuration evidence was not collected",
            format!(
                "{} expected artifact(s) were missing, inaccessible, or skipped. Any setting they would have described is unresolved rather than absent.",
                gaps.len()
            ),
            vec![
                "Re-run collection elevated so protected event channels and the MDM report can be read.".to_owned(),
                "Collect the named artifacts and re-run the analysis.".to_owned(),
            ],
            Vec::new(),
            gaps,
        ),
    );
}

fn push_truncated_artifacts(snapshot: &ConfigurationSnapshot, findings: &mut Vec<IntuneFinding>) {
    let gaps = artifacts_with_status(snapshot, &[IntuneArtifactStatus::Capped]);
    if gaps.is_empty() {
        return;
    }
    push_finding(
        findings,
        finding(
            "configuration-truncated-artifacts",
            IntuneFindingSeverity::Warning,
            IntuneFindingConfidence::High,
            "Configuration evidence was truncated during collection",
            format!(
                "{} artifact(s) hit a collection cap. Records past the cap were never read, so the absence of a setting in this bundle is not evidence the device lacks it.",
                gaps.len()
            ),
            vec![
                "Re-collect with a larger cap, or narrow the collection window.".to_owned(),
            ],
            Vec::new(),
            gaps,
        ),
    );
}

fn push_unreadable_artifacts(snapshot: &ConfigurationSnapshot, findings: &mut Vec<IntuneFinding>) {
    let gaps = artifacts_with_status(
        snapshot,
        &[
            IntuneArtifactStatus::ParseFailed,
            IntuneArtifactStatus::Unsupported,
        ],
    );
    if gaps.is_empty() {
        return;
    }
    push_finding(
        findings,
        finding(
            "configuration-unreadable-artifacts",
            IntuneFindingSeverity::Warning,
            IntuneFindingConfidence::High,
            "Configuration evidence was collected but could not be read",
            format!(
                "{} artifact(s) were collected and then failed to parse or used an unsupported format. The bytes exist; this build cannot interpret them.",
                gaps.len()
            ),
            vec![
                "Re-export the MDM diagnostic report and confirm the export completed.".to_owned(),
                "Check whether the artifact's schema version is newer than this build supports.".to_owned(),
            ],
            Vec::new(),
            gaps,
        ),
    );
}

/// Every artifact this bundle expected but did not fully read.
fn coverage_gaps(snapshot: &ConfigurationSnapshot) -> Vec<String> {
    artifacts_with_status(
        snapshot,
        &[
            IntuneArtifactStatus::Missing,
            IntuneArtifactStatus::PermissionDenied,
            IntuneArtifactStatus::Skipped,
            IntuneArtifactStatus::Capped,
            IntuneArtifactStatus::ParseFailed,
            IntuneArtifactStatus::Unsupported,
        ],
    )
}

/// An artifact the collector read in full that nevertheless settled nothing.
///
/// `available` is easy to read as "we looked and there was nothing wrong". When
/// every record an artifact contributed is unrecognized, unsupported, or states no
/// outcome, the honest statement is that this artifact answered no question — the
/// same class of admission as a coverage gap, reached from the other direction.
fn push_artifacts_without_usable_records(
    snapshot: &ConfigurationSnapshot,
    findings: &mut Vec<IntuneFinding>,
) {
    let productive = snapshot
        .settings
        .iter()
        .flat_map(|setting| setting.observations.iter())
        .chain(snapshot.unattributed.iter())
        .filter(|observation| !observation.is_uninterpretable)
        .filter(|observation| observation.disposition.is_terminal())
        .map(|observation| observation.evidence_ref.source_artifact_id.as_str())
        .collect::<BTreeSet<_>>();

    let barren = snapshot
        .coverage
        .iter()
        .filter(|entry| entry.status == IntuneArtifactStatus::Available)
        .filter(|entry| !productive.contains(entry.artifact_id.as_str()))
        .map(|entry| entry.artifact_id.clone())
        .collect::<Vec<_>>();
    if barren.is_empty() {
        return;
    }

    push_finding(
        findings,
        finding(
            "configuration-artifact-without-usable-records",
            IntuneFindingSeverity::Info,
            IntuneFindingConfidence::High,
            "An artifact was read in full but settled nothing",
            format!(
                "{} artifact(s) were collected successfully and produced no record this build could turn into an outcome. Their `available` status describes the collection, not the analysis: no setting is resolved by them, so their silence is not evidence that nothing happened.",
                barren.len()
            ),
            vec![
                "Check whether the artifact's record schema or event ids are newer than this build supports.".to_owned(),
                "Collect the companion artifact for the same workload before concluding a setting was never delivered.".to_owned(),
            ],
            Vec::new(),
            barren,
        ),
    );
}

fn push_applied(snapshot: &ConfigurationSnapshot, findings: &mut Vec<IntuneFinding>) {
    // A setting carrying an uninterpretable record is not a clean success: the
    // unread record may be the one that mattered, and ADR-001 forbids a terminal
    // success claim built on non-assessable evidence.
    let settings = select(snapshot, |setting| {
        setting.resolution == ConfigurationResolution::Applied
            && setting.local == ConfigurationLocalState::Applied
            && !setting.has_uninterpretable_evidence
            && !setting.has_unassessable_failure
    });
    if settings.is_empty() {
        return;
    }

    // ADR-001: coverage gaps cannot raise confidence. Success is the claim a gap
    // actually undermines — it rests partly on *not* having seen a failure, and a
    // capped or unreadable artifact is exactly where an unseen failure would be.
    // A rejection, by contrast, is directly evidenced and keeps its confidence.
    let gaps = coverage_gaps(snapshot);
    let (confidence, caveat) = if gaps.is_empty() {
        (IntuneFindingConfidence::High, String::new())
    } else {
        (
            IntuneFindingConfidence::Medium,
            format!(
                " {} expected artifact(s) were not fully read, so this bundle cannot show whether a later record changed any of them.",
                gaps.len()
            ),
        )
    };

    push_finding(
        findings,
        finding(
            "configuration-applied",
            IntuneFindingSeverity::Info,
            confidence,
            "Settings were applied by their CSP",
            format!(
                "The device's own records show {} written by the responsible configuration service provider.{caveat}",
                join_labels(&settings)
            ),
            Vec::new(),
            evidence_where(&settings, |observation| {
                observation.side == ConfigurationEvidenceSide::Device
                    && observation.disposition == ConfigurationDisposition::Applied
            }),
            gaps,
        ),
    );
}
