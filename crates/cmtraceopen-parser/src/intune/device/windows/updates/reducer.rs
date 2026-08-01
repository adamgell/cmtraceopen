//! Reduction of classified observations into one immutable [`UpdateSnapshot`].
//!
//! The reducer builds the two chains independently and only afterwards asks
//! whether anything defensible connects them. That order is deliberate: a
//! reducer that built one combined timeline would have to *un*-merge policy and
//! update facts to answer "did Intune deliver the setting?" separately from "did
//! Windows install the update?", and un-merging is where the conflation bug of
//! issue #365 would reappear.
//!
//! Nothing here reads a clock, a file, or a registry. Every input arrives in the
//! bundle.

use std::collections::{BTreeSet, HashSet};

use chrono::{DateTime, Utc};

use crate::intune::evidence::{
    IntuneArtifactCoverage, IntuneEvidenceRef, IntuneFindingConfidence, IntuneTimestampKind,
};

use super::models::*;
use super::rules::derive_findings;
use super::sources::{
    classify_event, classify_registry_fact, classify_setting_report, read_supplemental,
    workload_owner_from, EventClassification, USE_WU_SERVER_VALUE, WSUS_SERVER_VALUE,
};

/// Reduce one evidence bundle into a snapshot, findings included.
pub fn reduce_bundle(bundle: &UpdateEvidenceBundle) -> UpdateSnapshot {
    let mut input_coverage = UpdateInputCoverage::default();
    let mut policy_observations = Vec::new();
    let mut update_observations = Vec::new();
    let mut unknown_providers = BTreeSet::new();
    let mut unmapped_ids = BTreeSet::new();

    for event in &bundle.events {
        match classify_event(event) {
            EventClassification::Policy(observation) => policy_observations.push(*observation),
            EventClassification::Update(observation) => update_observations.push(*observation),
            EventClassification::UnmappedEventId(event_id) => {
                input_coverage.unmapped_event_ids += 1;
                unmapped_ids.insert(event_id);
                input_coverage
                    .evidence
                    .push(event.context.evidence_ref.clone());
            }
            EventClassification::UnknownProvider(provider) => {
                input_coverage.unknown_provider_events += 1;
                unknown_providers.insert(provider);
                input_coverage
                    .evidence
                    .push(event.context.evidence_ref.clone());
            }
            EventClassification::OutOfScope => {}
        }
    }

    for report in &bundle.setting_reports {
        if let Some(observation) = classify_setting_report(report) {
            policy_observations.push(observation);
        }
    }
    for fact in &bundle.registry_facts {
        if let Some(observation) = classify_registry_fact(fact) {
            policy_observations.push(observation);
        }
    }
    for log in &bundle.supplemental_logs {
        let reading = read_supplemental(log);
        input_coverage.supplemental_parse_errors += reading.parse_errors;
        update_observations.extend(reading.observations);
    }

    input_coverage.unmapped_event_id_list = unmapped_ids.into_iter().collect();
    input_coverage.unknown_providers = unknown_providers.into_iter().collect();
    sort_evidence(&mut input_coverage.evidence);

    // The policy chain needs the update client's own scanned service id to
    // complete its source assessment, and nothing else. Passing only the
    // client-backed observations keeps a supplemental CBS or DISM line from
    // ever influencing a policy conclusion.
    let client_observations: Vec<UpdateObservation> = update_observations
        .iter()
        .filter(|observation| observation.is_update_client_evidence())
        .cloned()
        .collect();

    let policy_chain = build_policy_chain(bundle, &policy_observations, &client_observations);
    let update_chain = build_update_chain(bundle, update_observations);
    let linkage = link_chains(&policy_chain);

    let mut snapshot = UpdateSnapshot {
        schema_version: INTUNE_WINDOWS_UPDATES_SCHEMA_VERSION,
        generated_at_utc: bundle.generated_at_utc.clone(),
        device: bundle.device.clone(),
        policy_chain,
        update_chain,
        linkage,
        input_coverage,
        coverage: sorted_coverage(&bundle.coverage),
        findings: Vec::new(),
    };
    snapshot.findings = derive_findings(&snapshot);
    snapshot
}

fn sorted_coverage(coverage: &[IntuneArtifactCoverage]) -> Vec<IntuneArtifactCoverage> {
    let mut sorted = coverage.to_vec();
    sorted.sort_by(|left, right| left.artifact_id.cmp(&right.artifact_id));
    sorted
}

/// Sort and deduplicate evidence so a snapshot never depends on input order.
fn sort_evidence(evidence: &mut Vec<IntuneEvidenceRef>) {
    evidence.sort();
    evidence.dedup();
}

// ── Policy chain ────────────────────────────────────────────────────────────

fn build_policy_chain(
    bundle: &UpdateEvidenceBundle,
    observations: &[PolicyObservation],
    client_observations: &[UpdateObservation],
) -> PolicyChain {
    let workload_owner = bundle
        .device
        .update_workload_owner
        .clone()
        .or_else(|| workload_owner_from(&bundle.device.named_data))
        .unwrap_or_default();

    let conflicts = collect_conflicts(observations);
    let effective_source = assess_effective_source(bundle, observations, client_observations);

    let mut evidence: Vec<IntuneEvidenceRef> = observations
        .iter()
        .map(|observation| observation.context.evidence_ref.clone())
        .collect();
    sort_evidence(&mut evidence);

    let state = policy_state(&workload_owner, observations, &conflicts);
    let confidence = match state {
        PolicyChainState::NotObserved | PolicyChainState::InsufficientEvidence => {
            IntuneFindingConfidence::Low
        }
        PolicyChainState::NotOwnedByIntune => {
            if bundle.device.update_workload_owner.is_some() {
                IntuneFindingConfidence::High
            } else {
                IntuneFindingConfidence::Medium
            }
        }
        _ => IntuneFindingConfidence::High,
    };

    PolicyChain {
        state,
        workload_owner,
        effective_source,
        observations: observations.to_vec(),
        conflicts,
        evidence,
        confidence,
    }
}

/// Terminal reading of the policy chain.
///
/// Ownership outranks everything: if Configuration Manager owns the update
/// workload, an Intune update ring is not in force regardless of how cleanly it
/// was delivered, and reporting "applied" would be actively misleading.
fn policy_state(
    owner: &UpdateWorkloadOwner,
    observations: &[PolicyObservation],
    conflicts: &[PolicyConflict],
) -> PolicyChainState {
    if owner == &UpdateWorkloadOwner::ConfigurationManager {
        return PolicyChainState::NotOwnedByIntune;
    }
    if observations.is_empty() {
        return PolicyChainState::NotObserved;
    }
    let has = |signal: PolicySignal| {
        observations
            .iter()
            .any(|observation| observation.signal == signal)
    };

    if has(PolicySignal::DeliveryFailed) {
        PolicyChainState::DeliveryFailed
    } else if !conflicts.is_empty() {
        PolicyChainState::Conflicted
    } else if has(PolicySignal::UnsupportedValue) {
        PolicyChainState::UnsupportedValue
    } else if has(PolicySignal::Applied) {
        PolicyChainState::Applied
    } else {
        PolicyChainState::InsufficientEvidence
    }
}

/// A conflict needs two *named* sources for one node.
///
/// A conflict row that names only one policy id is retained as an observation
/// but does not become a `PolicyConflict`: naming a single contender as a
/// conflict gives an administrator nothing to reconcile.
fn collect_conflicts(observations: &[PolicyObservation]) -> Vec<PolicyConflict> {
    let mut nodes: Vec<(String, Vec<String>, Vec<IntuneEvidenceRef>)> = Vec::new();

    for observation in observations {
        if observation.signal != PolicySignal::Conflict {
            continue;
        }
        let Some(node) = observation
            .setting_uri
            .clone()
            .or_else(|| observation.setting_id.clone())
        else {
            continue;
        };

        let mut ids = Vec::new();
        if let Some(policy_id) = &observation.policy_id {
            ids.push(policy_id.clone());
        }
        if let Some(winner) = super::sources::named(
            &observation.named_data,
            super::sources::NAMED_WINNING_POLICY_ID,
        ) {
            ids.push(winner);
        }

        match nodes.iter_mut().find(|(existing, _, _)| existing == &node) {
            Some((_, existing_ids, evidence)) => {
                existing_ids.extend(ids);
                evidence.push(observation.context.evidence_ref.clone());
            }
            None => nodes.push((
                node,
                ids,
                vec![observation.context.evidence_ref.clone()],
            )),
        }
    }

    let mut conflicts: Vec<PolicyConflict> = nodes
        .into_iter()
        .filter_map(|(node, mut policy_ids, mut evidence)| {
            policy_ids.sort();
            policy_ids.dedup();
            if policy_ids.len() < 2 {
                return None;
            }
            sort_evidence(&mut evidence);
            Some(PolicyConflict {
                node,
                policy_ids,
                evidence,
            })
        })
        .collect();
    conflicts.sort_by(|left, right| left.node.cmp(&right.node));
    conflicts
}

/// Decide what source the device is *configured* for, and what it actually
/// scanned.
///
/// The configured decision follows the real precedence on a Windows device: a
/// WSUS server value only takes effect when `UseWUServer` turns it on, so
/// `UseWUServer=0` alongside a populated `WUServer` means the WSUS entry is
/// inert. Collapsing that to "WSUS is configured" would send an administrator
/// after a redirection that is not happening.
fn assess_effective_source(
    bundle: &UpdateEvidenceBundle,
    policy_observations: &[PolicyObservation],
    update_observations: &[UpdateObservation],
) -> EffectiveSourceAssessment {
    let mut configured_evidence = Vec::new();
    let mut use_wu_server: Option<bool> = None;
    let mut wsus_server_configured = false;
    let mut policy_driven: Option<UpdateSource> = None;

    for observation in policy_observations {
        let Some(source) = &observation.source else {
            continue;
        };
        let setting = observation.setting_id.clone().unwrap_or_default();
        if setting.eq_ignore_ascii_case(USE_WU_SERVER_VALUE) {
            use_wu_server = Some(source == &UpdateSource::Wsus);
        } else if setting.eq_ignore_ascii_case(WSUS_SERVER_VALUE) {
            wsus_server_configured = true;
        } else if policy_driven.is_none() {
            policy_driven = Some(source.clone());
        }
        configured_evidence.push(observation.context.evidence_ref.clone());
    }
    sort_evidence(&mut configured_evidence);

    let configured = match (use_wu_server, wsus_server_configured) {
        (Some(true), true) => Some(UpdateSource::Wsus),
        (Some(true), false) => Some(UpdateSource::Wsus),
        (Some(false), _) => Some(
            policy_driven
                .clone()
                .unwrap_or(UpdateSource::WindowsUpdateForBusiness),
        ),
        (None, true) => Some(UpdateSource::Wsus),
        (None, false) => policy_driven.clone(),
    };

    let mut scanned_evidence = Vec::new();
    let mut scanned: Option<UpdateSource> = None;
    for observation in update_observations {
        let Some(source) = &observation.source else {
            continue;
        };
        if scanned.is_none() {
            scanned = Some(source.clone());
        }
        scanned_evidence.push(observation.context.evidence_ref.clone());
    }
    sort_evidence(&mut scanned_evidence);

    let expected = bundle.device.expected_update_source.clone();
    // The scanned source is what the device really used, so it wins over the
    // configured one when the two are both known and disagree.
    let effective = scanned.clone().or_else(|| configured.clone());
    let matches_expectation = match (&expected, &effective) {
        (Some(expected), Some(effective)) => Some(sources_agree(expected, effective)),
        _ => None,
    };

    EffectiveSourceAssessment {
        expected,
        configured,
        scanned,
        matches_expectation,
        configured_evidence,
        scanned_evidence,
    }
}

/// Windows Update and Windows Update for Business scan the same service, so an
/// expectation of one is satisfied by the other. Every other pair must match
/// exactly.
fn sources_agree(expected: &UpdateSource, effective: &UpdateSource) -> bool {
    let public_wu = |source: &UpdateSource| {
        matches!(
            source,
            UpdateSource::WindowsUpdate | UpdateSource::WindowsUpdateForBusiness
        )
    };
    expected == effective || (public_wu(expected) && public_wu(effective))
}

// ── Update chain ────────────────────────────────────────────────────────────

fn build_update_chain(
    bundle: &UpdateEvidenceBundle,
    observations: Vec<UpdateObservation>,
) -> UpdateChain {
    let mut buckets: Vec<(UpdateKey, Vec<UpdateObservation>)> = Vec::new();
    let mut unkeyed = Vec::new();

    for observation in observations {
        if !observation.key.is_identified() {
            unkeyed.push(observation);
            continue;
        }
        match buckets
            .iter_mut()
            .find(|(key, _)| key.joins(&observation.key))
        {
            Some((key, group)) => {
                key.absorb(&observation.key);
                group.push(observation);
            }
            None => buckets.push((observation.key.clone(), vec![observation])),
        }
    }

    let mut transactions: Vec<UpdateTransaction> = buckets
        .into_iter()
        .map(|(key, group)| build_transaction(key, &group, &bundle.service_reports))
        .collect();
    transactions.sort_by(|left, right| left.key.label().cmp(&right.key.label()));

    let device_signals = device_level_signals(&unkeyed);
    let state = chain_state(&transactions, &device_signals);

    let reboot_pending = reboot_pending_flag(&transactions, &device_signals);

    let mut evidence: Vec<IntuneEvidenceRef> = transactions
        .iter()
        .flat_map(|transaction| transaction.evidence.iter().cloned())
        .chain(
            unkeyed
                .iter()
                .map(|observation| observation.context.evidence_ref.clone()),
        )
        .collect();
    sort_evidence(&mut evidence);

    UpdateChain {
        state,
        transactions,
        unkeyed_observations: unkeyed,
        reboot_pending,
        evidence,
    }
}

/// Device-wide readings that carry no update identity.
///
/// A scan failure or a pending restart is a statement about the device, not
/// about a particular update, so it legitimately has no key. Attaching it to
/// whichever update happened to be in flight would be the time-only correlation
/// the issue forbids.
struct DeviceSignals {
    scan_failed: Option<IntuneEvidenceRef>,
    no_applicable_update: Option<IntuneEvidenceRef>,
    reboot_pending: Option<IntuneEvidenceRef>,
    client_evidence_present: bool,
}

fn device_level_signals(unkeyed: &[UpdateObservation]) -> DeviceSignals {
    let mut signals = DeviceSignals {
        scan_failed: None,
        no_applicable_update: None,
        reboot_pending: None,
        client_evidence_present: false,
    };
    for observation in unkeyed {
        if !observation.is_update_client_evidence() {
            continue;
        }
        signals.client_evidence_present = true;
        let reference = observation.context.evidence_ref.clone();
        match (observation.phase, observation.outcome) {
            (UpdatePhase::Scan, UpdateOutcome::Failed) => {
                signals.scan_failed.get_or_insert(reference);
            }
            (UpdatePhase::Applicability, UpdateOutcome::NotApplicable)
            | (UpdatePhase::Scan, UpdateOutcome::NotApplicable) => {
                signals.no_applicable_update.get_or_insert(reference);
            }
            (UpdatePhase::Reboot, UpdateOutcome::Pending) => {
                signals.reboot_pending.get_or_insert(reference);
            }
            _ => {}
        }
    }
    signals
}

fn build_transaction(
    key: UpdateKey,
    observations: &[UpdateObservation],
    service_reports: &[UpdateServiceReport],
) -> UpdateTransaction {
    let phases: Vec<UpdatePhaseRecord> = observations
        .iter()
        .map(|observation| UpdatePhaseRecord {
            phase: observation.phase,
            outcome: observation.outcome,
            evidence: observation.context.evidence_ref.clone(),
            supplemental: observation.supplemental.clone(),
        })
        .collect();

    let mut evidence = Vec::new();
    let mut corroborating = Vec::new();
    for observation in observations {
        if observation.is_update_client_evidence() {
            evidence.push(observation.context.evidence_ref.clone());
        } else {
            corroborating.push(observation.context.evidence_ref.clone());
        }
    }
    sort_evidence(&mut evidence);
    sort_evidence(&mut corroborating);

    let state = transaction_state(observations);
    let error = terminal_error(observations, state);
    let title = observations
        .iter()
        .find_map(|observation| observation.title.clone());
    let order_contradiction = has_order_contradiction(observations);

    let mut service_state = None;
    let mut service_evidence = Vec::new();
    for report in service_reports {
        if key.joins(&report.key) {
            if service_state.is_none() {
                service_state = Some(report.state.clone());
            }
            service_evidence.push(report.context.evidence_ref.clone());
        }
    }
    sort_evidence(&mut service_evidence);

    let confidence = if order_contradiction || evidence.is_empty() {
        IntuneFindingConfidence::Low
    } else if key.update_id.is_some() {
        IntuneFindingConfidence::High
    } else {
        IntuneFindingConfidence::Medium
    };

    UpdateTransaction {
        key,
        state,
        phases,
        error,
        title,
        evidence,
        corroborating_evidence: corroborating,
        service_state,
        service_evidence,
        confidence,
        order_contradiction,
    }
}

/// The terminal state is the *last* decisive update-client reading.
///
/// Last rather than worst, because an update that failed to download and then
/// downloaded and installed on retry did install, and reporting the earlier
/// failure as the outcome would send an administrator after a resolved problem.
///
/// Supplemental readings are skipped entirely here. CBS and DISM corroborate a
/// state; they never establish one, which is what keeps them from becoming
/// hidden requirements.
fn transaction_state(observations: &[UpdateObservation]) -> UpdateTransactionState {
    let mut state = UpdateTransactionState::InsufficientEvidence;
    for observation in observations {
        if !observation.is_update_client_evidence() {
            continue;
        }
        state = match (observation.phase, observation.outcome) {
            (_, UpdateOutcome::Deferred) => UpdateTransactionState::Deferred,
            (UpdatePhase::Scan, UpdateOutcome::Failed) => UpdateTransactionState::ScanFailed,
            (UpdatePhase::Applicability, UpdateOutcome::NotApplicable) => {
                UpdateTransactionState::NoApplicableUpdate
            }
            (UpdatePhase::Download, UpdateOutcome::Failed) => UpdateTransactionState::DownloadFailed,
            (UpdatePhase::Install, UpdateOutcome::Failed) => UpdateTransactionState::InstallFailed,
            (UpdatePhase::Install, UpdateOutcome::Succeeded) => UpdateTransactionState::Installed,
            (UpdatePhase::Reboot, UpdateOutcome::Pending) => UpdateTransactionState::RebootPending,
            (UpdatePhase::Reboot, UpdateOutcome::Succeeded) => UpdateTransactionState::Installed,
            (UpdatePhase::Download, UpdateOutcome::Succeeded)
            | (_, UpdateOutcome::Started)
            | (_, UpdateOutcome::Pending) => UpdateTransactionState::InProgress,
            _ => state,
        };
    }
    state
}

/// The error belonging to the terminal state, not merely the last error seen.
fn terminal_error(
    observations: &[UpdateObservation],
    state: UpdateTransactionState,
) -> Option<crate::intune::evidence::IntuneErrorCode> {
    let wanted_phase = match state {
        UpdateTransactionState::ScanFailed => UpdatePhase::Scan,
        UpdateTransactionState::DownloadFailed => UpdatePhase::Download,
        UpdateTransactionState::InstallFailed => UpdatePhase::Install,
        _ => return None,
    };
    observations
        .iter()
        .rfind(|observation| {
            observation.is_update_client_evidence()
                && observation.phase == wanted_phase
                && observation.outcome == UpdateOutcome::Failed
        })
        .and_then(|observation| observation.error.clone())
}

/// Phase ordering used only to detect impossible sequences.
fn phase_rank(phase: UpdatePhase) -> u8 {
    match phase {
        UpdatePhase::Scan => 0,
        UpdatePhase::Applicability => 1,
        UpdatePhase::Download => 2,
        UpdatePhase::Install => 3,
        UpdatePhase::Reboot => 4,
        UpdatePhase::Reporting => 5,
    }
}

/// True when the timestamps cannot describe a real sequence.
///
/// Two shapes count: a timestamp the adapter could not normalize at all
/// (`IntuneTimestampKind::Invalid`), and a later phase stamped earlier than an
/// earlier phase of the same update. Both mean the ordering evidence is unusable,
/// which caps the transaction's confidence rather than being silently ignored.
fn has_order_contradiction(observations: &[UpdateObservation]) -> bool {
    let mut stamped: Vec<(u8, DateTime<Utc>)> = Vec::new();

    for observation in observations {
        let Some(timestamp) = &observation.context.source_timestamp else {
            continue;
        };
        if timestamp.kind == IntuneTimestampKind::Invalid {
            return true;
        }
        let Some(normalized) = timestamp.normalized_utc.as_deref() else {
            continue;
        };
        let Ok(parsed) = DateTime::parse_from_rfc3339(normalized) else {
            // A `normalized_utc` that is not RFC 3339 is itself contradictory:
            // the adapter claimed a normalization it did not perform.
            return true;
        };
        stamped.push((
            phase_rank(observation.phase),
            parsed.with_timezone(&Utc),
        ));
    }

    stamped.iter().enumerate().any(|(index, (rank, at))| {
        stamped
            .iter()
            .skip(index + 1)
            .any(|(later_rank, later_at)| later_rank > rank && later_at < at)
    })
}

/// Aggregate the per-update states plus the device-level signals.
///
/// Worst-first here, unlike within a transaction: across several updates there
/// is no "latest" to prefer, and the most actionable outcome is the one an
/// administrator needs to see.
fn chain_state(
    transactions: &[UpdateTransaction],
    signals: &DeviceSignals,
) -> UpdateChainState {
    if signals.scan_failed.is_some() {
        return UpdateChainState::ScanFailed;
    }

    let states: HashSet<UpdateTransactionState> = transactions
        .iter()
        .map(|transaction| transaction.state)
        .collect();

    for (candidate, chain) in [
        (UpdateTransactionState::ScanFailed, UpdateChainState::ScanFailed),
        (
            UpdateTransactionState::InstallFailed,
            UpdateChainState::InstallFailed,
        ),
        (
            UpdateTransactionState::DownloadFailed,
            UpdateChainState::DownloadFailed,
        ),
        (UpdateTransactionState::Deferred, UpdateChainState::Deferred),
        (
            UpdateTransactionState::RebootPending,
            UpdateChainState::RebootPending,
        ),
        (UpdateTransactionState::InProgress, UpdateChainState::InProgress),
        (UpdateTransactionState::Installed, UpdateChainState::Installed),
        (
            UpdateTransactionState::NoApplicableUpdate,
            UpdateChainState::NoApplicableUpdate,
        ),
    ] {
        if states.contains(&candidate) {
            return chain;
        }
    }

    if signals.reboot_pending.is_some() {
        return UpdateChainState::RebootPending;
    }
    if signals.no_applicable_update.is_some() {
        return UpdateChainState::NoApplicableUpdate;
    }
    if signals.client_evidence_present || !transactions.is_empty() {
        return UpdateChainState::InsufficientEvidence;
    }
    UpdateChainState::NotObserved
}

fn reboot_pending_flag(
    transactions: &[UpdateTransaction],
    signals: &DeviceSignals,
) -> Option<bool> {
    if signals.reboot_pending.is_some()
        || transactions
            .iter()
            .any(|transaction| transaction.state == UpdateTransactionState::RebootPending)
    {
        return Some(true);
    }
    if transactions.is_empty() && !signals.client_evidence_present {
        return None;
    }
    Some(false)
}

// ── Linkage ─────────────────────────────────────────────────────────────────

/// Connect the chains only through the one identifier they genuinely share.
///
/// The update service id is that identifier: policy and registry evidence say
/// which service the device should use, and the update client's own
/// `serviceGuid` says which it did use. Nothing else in the two chains refers to
/// the same thing, so nothing else may create a link.
fn link_chains(policy: &PolicyChain) -> ChainLinkage {
    let (Some(configured), Some(scanned)) = (
        policy.effective_source.configured.as_ref(),
        policy.effective_source.scanned.as_ref(),
    ) else {
        return ChainLinkage::default();
    };

    let mut evidence = policy.effective_source.configured_evidence.clone();
    evidence.extend(policy.effective_source.scanned_evidence.iter().cloned());
    sort_evidence(&mut evidence);

    let agree = sources_agree(configured, scanned);
    ChainLinkage {
        state: if agree {
            ChainLinkState::SharedUpdateSource
        } else {
            ChainLinkState::SourceDisagreement
        },
        confidence: IntuneFindingConfidence::High,
        basis: if agree {
            "Policy-configured update source and the update client's scanned service id name the same service.".to_owned()
        } else {
            "Policy-configured update source and the update client's scanned service id name different services.".to_owned()
        },
        evidence,
    }
}
