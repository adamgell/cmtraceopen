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

use std::cmp::Ordering;
use std::collections::{BTreeSet, HashSet};

use chrono::{DateTime, Utc};

use crate::intune::evidence::{
    IntuneAccessState, IntuneArtifactCoverage, IntuneArtifactStatus, IntuneEvidenceRef,
    IntuneFindingConfidence, IntuneObservationContext, IntuneParseState, IntuneTimestampKind,
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
        if !record_can_be_read(&event.context) {
            exclude_unreadable(&mut input_coverage, &event.context);
            continue;
        }
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
        if !record_can_be_read(&report.context) {
            exclude_unreadable(&mut input_coverage, &report.context);
            continue;
        }
        if let Some(observation) = classify_setting_report(report) {
            policy_observations.push(observation);
        }
    }
    for fact in &bundle.registry_facts {
        if !record_can_be_read(&fact.context) {
            exclude_unreadable(&mut input_coverage, &fact.context);
            continue;
        }
        if let Some(observation) = classify_registry_fact(fact) {
            policy_observations.push(observation);
        }
    }
    for log in &bundle.supplemental_logs {
        if !record_can_be_read(&log.context) {
            exclude_unreadable(&mut input_coverage, &log.context);
            continue;
        }
        let reading = read_supplemental(log);
        input_coverage.supplemental_parse_errors += reading.parse_errors;
        update_observations.extend(reading.observations);
    }

    for report in &bundle.service_reports {
        // Read by `build_transaction`, which skips these; counting them here is
        // what keeps the exclusion visible in the snapshot.
        if !record_can_be_read(&report.context) {
            exclude_unreadable(&mut input_coverage, &report.context);
        }
    }

    // Device facts arrive in one record. If that record could not be read, the
    // facts it carries are not evidence -- including the workload owner, which
    // decides whether an Intune update ring is in force at all.
    let device = match bundle.device.context.as_ref() {
        Some(context) if !record_can_be_read(context) => {
            exclude_unreadable(&mut input_coverage, context);
            UpdateDeviceFacts::default()
        }
        _ => bundle.device.clone(),
    };

    input_coverage.unmapped_event_id_list = unmapped_ids.into_iter().collect();
    input_coverage.unknown_providers = unknown_providers.into_iter().collect();
    input_coverage.extraction_profile = bundle.extraction_profile.clone();
    input_coverage.extraction_profile_unsupported = bundle
        .extraction_profile
        .as_deref()
        .is_some_and(|profile| !profile.eq_ignore_ascii_case(UPDATES_EXTRACTION_PROFILE));
    sort_evidence(&mut input_coverage.evidence);

    // Both chains read their readings in canonical order, never in the order
    // the caller happened to list the artifacts in.
    sort_policy_readings(&mut policy_observations);
    sort_readings(&mut update_observations);

    // The policy chain needs the update client's own scanned service id to
    // complete its source assessment, and nothing else. Passing only the
    // client-backed observations keeps a supplemental CBS or DISM line from
    // ever influencing a policy conclusion.
    let client_observations: Vec<UpdateObservation> = update_observations
        .iter()
        .filter(|observation| observation.is_update_client_evidence())
        .cloned()
        .collect();

    let policy_chain = build_policy_chain(&device, &policy_observations, &client_observations);
    let update_chain = build_update_chain(bundle, update_observations);
    let linkage = link_chains(&policy_chain);

    let mut snapshot = UpdateSnapshot {
        schema_version: INTUNE_WINDOWS_UPDATES_SCHEMA_VERSION,
        generated_at_utc: bundle.generated_at_utc.clone(),
        device,
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

/// Whether a captured record may become evidence.
///
/// A record the adapter could not parse, or could not read at all, is a coverage
/// state rather than a reading. Classifying it anyway is what let a malformed,
/// access-denied install establish an `Installed` transaction at High confidence
/// in an earlier revision of this leaf.
///
/// `Capped` stays readable: the records a truncated capture did contain are real
/// readings, and the truncation is on the artifact's own coverage entry where a
/// conclusion that depends on completeness can see it.
fn record_can_be_read(context: &IntuneObservationContext) -> bool {
    context.parse_state == IntuneParseState::Parsed
        && matches!(
            context.access_state,
            IntuneAccessState::Available | IntuneAccessState::Capped
        )
}

/// Count an excluded record and keep its reference, so the exclusion shows up
/// in the snapshot rather than looking like evidence that was never captured.
fn exclude_unreadable(coverage: &mut UpdateInputCoverage, context: &IntuneObservationContext) {
    coverage.unusable_records += 1;
    coverage
        .unusable_evidence
        .push(context.evidence_ref.clone());
}

/// Sort and deduplicate evidence so a snapshot never depends on input order.
fn sort_evidence(evidence: &mut Vec<IntuneEvidenceRef>) {
    evidence.sort();
    evidence.dedup();
}

/// Put the readings of one pass in their canonical order.
///
/// The terminal state is the *last* decisive reading, so "last" has to mean
/// last in time. Ordering by the record's own timestamp, instead of trusting
/// the order a caller listed artifacts in, is what makes a snapshot a function
/// of the evidence rather than of the collection order.
///
/// A reading with no usable timestamp sorts first. That is not cosmetic: an
/// unplaceable reading must not become the terminal one merely because it was
/// handed over last, and an earlier revision of this leaf did exactly that --
/// reversing one bundle changed a transaction's state and which scan source was
/// selected.
fn sort_readings(readings: &mut [UpdateObservation]) {
    readings.sort_by(|left, right| {
        compare_contexts(&left.context, &right.context)
            .then_with(|| left.phase.cmp(&right.phase))
            .then_with(|| left.outcome.cmp(&right.outcome))
    });
}

/// Canonical order for policy readings; see [`sort_readings`].
///
/// The source assessment reads the last `UseWUServer` statement and the first
/// policy that names a source, so an unsorted vector let the caller's listing
/// order decide which source the device is assessed as being configured for.
fn sort_policy_readings(readings: &mut [PolicyObservation]) {
    readings.sort_by(|left, right| {
        compare_contexts(&left.context, &right.context)
            .then_with(|| left.signal.cmp(&right.signal))
            .then_with(|| left.setting_uri.cmp(&right.setting_uri))
            .then_with(|| left.setting_id.cmp(&right.setting_id))
            .then_with(|| left.policy_id.cmp(&right.policy_id))
            .then_with(|| left.event_id.cmp(&right.event_id))
    });
}

/// Order two readings by the record they came from.
///
/// One rule for both chains, so "which record comes first" has a single
/// definition. Ties break on the evidence pointer, then the line, then the
/// record number, so two runs over the same bytes agree even when two records
/// share an instant.
fn compare_contexts(left: &IntuneObservationContext, right: &IntuneObservationContext) -> Ordering {
    context_instant(left)
        .cmp(&context_instant(right))
        .then_with(|| left.evidence_ref.cmp(&right.evidence_ref))
        .then_with(|| {
            left.provenance
                .line_number
                .cmp(&right.provenance.line_number)
        })
        .then_with(|| {
            left.provenance
                .record_number
                .cmp(&right.provenance.record_number)
        })
}

/// The instant a reading places itself at, or `None` when it cannot be placed.
///
/// A timestamp the adapter marked invalid counts as unplaceable, which is the
/// same reading `has_order_contradiction` takes of it.
///
/// `pub(super)` so the findings pass can ask the same question about a reading
/// rather than inventing a second answer to it.
pub(super) fn context_instant(context: &IntuneObservationContext) -> Option<DateTime<Utc>> {
    let timestamp = context.source_timestamp.as_ref()?;
    if timestamp.kind == IntuneTimestampKind::Invalid {
        return None;
    }
    DateTime::parse_from_rfc3339(timestamp.normalized_utc.as_deref()?)
        .ok()
        .map(|parsed| parsed.with_timezone(&Utc))
}

// ── Policy chain ────────────────────────────────────────────────────────────

fn build_policy_chain(
    device: &UpdateDeviceFacts,
    observations: &[PolicyObservation],
    client_observations: &[UpdateObservation],
) -> PolicyChain {
    let workload_owner = device
        .update_workload_owner
        .clone()
        .or_else(|| workload_owner_from(&device.named_data))
        .unwrap_or_default();

    let conflicts = collect_conflicts(observations);
    let effective_source = assess_effective_source(device, observations, client_observations);

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
            if device.update_workload_owner.is_some() {
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
            None => nodes.push((node, ids, vec![observation.context.evidence_ref.clone()])),
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
    device: &UpdateDeviceFacts,
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
        // Readings arrive in canonical order with unplaceable ones first, so the
        // last assignment is the latest *placed* reading. Taking the first made
        // an untimestamped reading win every time, and made an older source win
        // when all of them were placed -- a device that moved from WSUS to WUfB
        // stayed assessed as WSUS, which drives `matches_expectation`, the linked
        // chains and the effective-source-mismatch finding.
        scanned = Some(source.clone());
        scanned_evidence.push(observation.context.evidence_ref.clone());
    }
    sort_evidence(&mut scanned_evidence);

    let expected = device.expected_update_source.clone();
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
    transactions.sort_by_key(|transaction| transaction.key.label());

    let device_signals = device_level_signals(&unkeyed);
    let state = chain_state(&transactions, &device_signals);

    let reboot_pending = reboot_pending_flag(&transactions, &device_signals, &bundle.coverage);

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
            // Last rather than worst, the rule the transaction design already
            // uses: event 25 is unkeyed and often transient, and a later
            // successful scan is the device's scan health, so it clears an
            // earlier failure instead of leaving the chain at `ScanFailed`
            // beside a finding that cites a successful install.
            (UpdatePhase::Scan, UpdateOutcome::Failed) => {
                signals.scan_failed = Some(reference);
            }
            (UpdatePhase::Scan, UpdateOutcome::Succeeded) => {
                signals.scan_failed = None;
                // A scan that found updates answers the earlier one, the rule the
                // failure above already states: an event 26 reporting
                // `updateCount=0` followed by one that found updates left the
                // device reading as `NoApplicableUpdate`, beside a finding that
                // cited the earlier scan.
                signals.no_applicable_update = None;
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
    let readings_are_placed = observations
        .iter()
        .filter(|observation| observation.is_update_client_evidence())
        .all(|observation| context_instant(&observation.context).is_some());
    let title = observations
        .iter()
        .find_map(|observation| observation.title.clone());
    let order_contradiction = has_order_contradiction(observations);

    let mut service_state = None;
    let mut service_evidence = Vec::new();
    for report in service_reports {
        if !record_can_be_read(&report.context) {
            continue;
        }
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
        readings_are_placed,
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
            (UpdatePhase::Download, UpdateOutcome::Failed) => {
                UpdateTransactionState::DownloadFailed
            }
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
///
/// The pair check is symmetric by construction: every ordered pair is compared,
/// so the answer cannot depend on which of the two records the caller listed
/// first. Comparing only *later* vector positions was the bug -- it detected
/// `install@01:00` after `download@02:00` but not the same two records in the
/// other order, so a bundle's ordering evidence was decided by its listing.
fn has_order_contradiction(observations: &[UpdateObservation]) -> bool {
    let mut stamped: Vec<(u8, DateTime<Utc>)> = Vec::new();

    for observation in observations {
        // A supplemental format corroborates the client's reading; it never
        // establishes a state of its own, so its timestamps cannot contradict the
        // client's ordering and drop a client-backed verdict to low confidence.
        // `build_transaction` draws the same line between `evidence` and
        // `corroborating`.
        if observation.supplemental.is_some() {
            continue;
        }
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
        stamped.push((phase_rank(observation.phase), parsed.with_timezone(&Utc)));
    }

    stamped.iter().any(|(rank, at)| {
        stamped
            .iter()
            .any(|(other_rank, other_at)| other_rank > rank && other_at < at)
    })
}

/// Aggregate the per-update states plus the device-level signals.
///
/// Worst-first here, unlike within a transaction: across several updates there
/// is no "latest" to prefer, and the most actionable outcome is the one an
/// administrator needs to see.
fn chain_state(transactions: &[UpdateTransaction], signals: &DeviceSignals) -> UpdateChainState {
    if signals.scan_failed.is_some() {
        return UpdateChainState::ScanFailed;
    }

    let states: HashSet<UpdateTransactionState> = transactions
        .iter()
        .map(|transaction| transaction.state)
        .collect();

    for (candidate, chain) in [
        (
            UpdateTransactionState::ScanFailed,
            UpdateChainState::ScanFailed,
        ),
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
        (
            UpdateTransactionState::InProgress,
            UpdateChainState::InProgress,
        ),
        (
            UpdateTransactionState::Installed,
            UpdateChainState::Installed,
        ),
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

/// The artifact family that carries the update client's own readings.
///
/// Only this family can establish a pending restart. Supplemental readings --
/// the update-agent log and the servicing logs -- corroborate and never
/// establish one, so a truncated or unparseable supplemental artifact cannot
/// invalidate a claim the client channel itself supports.
const CLIENT_FAMILY: &str = "windowsUpdateClient";

/// Whether the capture described the client channel well enough to trust what is
/// missing from it.
///
/// Two ways to lose that trust: an entry that reports the client artifact as
/// something other than available, and no entry at all. A bundle that never
/// describes the channel cannot support "no restart is pending" any more than one
/// that describes it as truncated -- "not captured cleanly" and "not described"
/// both leave the absence unexplained.
fn client_capture_is_incomplete(coverage: &[IntuneArtifactCoverage]) -> bool {
    let client_entries: Vec<&IntuneArtifactCoverage> = coverage
        .iter()
        .filter(|entry| entry.family.eq_ignore_ascii_case(CLIENT_FAMILY))
        .collect();
    client_entries.is_empty()
        || client_entries
            .iter()
            .any(|entry| entry.status != IntuneArtifactStatus::Available)
}

fn reboot_pending_flag(
    transactions: &[UpdateTransaction],
    signals: &DeviceSignals,
    coverage: &[IntuneArtifactCoverage],
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
    if client_capture_is_incomplete(coverage) {
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

#[cfg(test)]
mod sources_agree_tests {
    use super::*;

    #[test]
    fn windows_update_and_wufb_are_treated_as_the_same_service() {
        // They scan the same backend service, so an expectation of one is
        // satisfied by the other. The exact values stay visible on
        // EffectiveSourceAssessment, so this is not hidden.
        assert!(sources_agree(
            &UpdateSource::WindowsUpdateForBusiness,
            &UpdateSource::WindowsUpdate
        ));
        assert!(sources_agree(
            &UpdateSource::WindowsUpdate,
            &UpdateSource::WindowsUpdateForBusiness
        ));
    }

    #[test]
    fn distinct_sources_do_not_agree() {
        assert!(!sources_agree(
            &UpdateSource::WindowsUpdateForBusiness,
            &UpdateSource::Wsus
        ));
        assert!(!sources_agree(
            &UpdateSource::WindowsUpdate,
            &UpdateSource::MicrosoftStore
        ));
        assert!(sources_agree(&UpdateSource::Wsus, &UpdateSource::Wsus));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A supplemental format corroborates; it cannot contradict the client.
    ///
    /// A CBS or DISM line arrives with its own timestamps and used to take part
    /// in the ordering check, so a supplement could drop a client-backed
    /// transaction to low confidence without saying anything about the client.
    #[test]
    fn a_supplemental_reading_cannot_contradict_the_client_ordering() {
        let install = reading_at("install", "succeeded", "wu-2", "2026-01-01T01:00:00Z");
        let mut download = reading_at("download", "started", "wu-1", "2026-01-01T02:00:00Z");

        assert!(
            has_order_contradiction(&[download.clone(), install.clone()]),
            "the client's own records contradict each other here"
        );

        download.supplemental = Some(SupplementalLogKind::Cbs);

        assert!(
            !has_order_contradiction(&[download, install]),
            "a supplemental line is not a contradiction with the client's ordering"
        );
    }

    /// An unplaceable reading never becomes the terminal one.
    ///
    /// `sort_readings` puts readings with no usable timestamp first precisely so
    /// this cannot happen, and nothing in the fixture corpus exercises it: every
    /// scenario reports a usable instant. A device whose newest install report
    /// carries an unreadable time must still be read from its placed records.
    #[test]
    fn an_unplaceable_reading_does_not_become_the_terminal_state() {
        let mut unreadable = reading_at("install", "succeeded", "wu-30", "2026-01-01T03:00:00Z");
        if let Some(timestamp) = unreadable.context.source_timestamp.as_mut() {
            timestamp.kind = IntuneTimestampKind::Invalid;
            timestamp.normalized_utc = None;
        }
        let placed = reading_at("download", "failed", "wu-31", "2026-01-01T02:00:00Z");

        // Canonical order: the unplaceable reading sorts first.
        let state = transaction_state(&[unreadable, placed]);

        assert_eq!(
            state,
            UpdateTransactionState::DownloadFailed,
            "the placed record states the terminal outcome"
        );
    }

    /// The scanned source is the latest reading, not the first.
    ///
    /// A device that moved from WSUS to WUfB kept being assessed as WSUS while
    /// the first reading won, and that value drives `matches_expectation`, the
    /// linked chains and the effective-source-mismatch finding.
    #[test]
    fn the_scanned_source_is_the_latest_reading() {
        let mut older = reading_at("applicability", "succeeded", "wu-1", "2026-01-01T01:00:00Z");
        older.source = Some(UpdateSource::Wsus);
        let mut newer = reading_at("applicability", "succeeded", "wu-2", "2026-01-01T02:00:00Z");
        newer.source = Some(UpdateSource::WindowsUpdateForBusiness);

        // Readings reach this function in canonical order, which is the contract
        // its own comment states.
        let assessment =
            assess_effective_source(&UpdateDeviceFacts::default(), &[], &[older, newer]);

        assert_eq!(
            assessment.scanned,
            Some(UpdateSource::WindowsUpdateForBusiness),
            "the latest placed reading is the scanned source"
        );
    }

    /// One unkeyed device reading, built from the context a fixture carries.
    ///
    /// The shape is copied from the corpus rather than invented, so a change to
    /// the observation context shows up here as a deserialization failure.
    const CONTEXT: &str = r#"{"evidenceRef":{"evidenceId":"{evidence_id}","sourceArtifactId":"wu-client-events"},"provenance":{"sourceKind":"eventLog","sourceArtifactId":"wu-client-events","filePath":null,"lineNumber":null,"recordNumber":201,"registry":null,"event":{"channel":"Microsoft-Windows-WindowsUpdateClient/Operational","provider":"Microsoft-Windows-WindowsUpdateClient","eventId":25,"recordId":201}},"sourceTimestamp":{"rawText":"2026-07-31T01:00:00Z","originalOffset":null,"normalizedUtc":"2026-07-31T01:00:00Z","kind":"utc"},"observedAtUtc":"2026-07-31T03:00:00Z","sensitivity":"public","parseState":"parsed","accessState":"available"}"#;

    fn reading(phase: &str, outcome: &str, evidence_id: &str) -> UpdateObservation {
        reading_at(phase, outcome, evidence_id, "2026-01-01T01:00:00Z")
    }

    /// The same reading, at a stated instant.
    fn reading_at(phase: &str, outcome: &str, evidence_id: &str, at: &str) -> UpdateObservation {
        let mut context: IntuneObservationContext =
            serde_json::from_str(&CONTEXT.replace("{evidence_id}", evidence_id))
                .expect("the corpus context deserializes");
        if let Some(timestamp) = context.source_timestamp.as_mut() {
            timestamp.normalized_utc = Some(at.to_owned());
        }
        UpdateObservation {
            context,
            phase: match phase {
                "scan" => UpdatePhase::Scan,
                "applicability" => UpdatePhase::Applicability,
                "download" => UpdatePhase::Download,
                "install" => UpdatePhase::Install,
                other => panic!("unknown phase {other}"),
            },
            outcome: match outcome {
                "failed" => UpdateOutcome::Failed,
                "succeeded" => UpdateOutcome::Succeeded,
                "started" => UpdateOutcome::Started,
                other => panic!("unknown outcome {other}"),
            },
            key: UpdateKey::default(),
            error: None,
            activity_id: None,
            event_id: None,
            source: None,
            title: None,
            supplemental: None,
            named_data: Vec::new(),
        }
    }

    /// A later successful scan also clears an earlier "nothing applies" verdict.
    ///
    /// The same rule as the failure below, which this branch applied to
    /// `scan_failed` only: an event 26 reporting `updateCount=0` left the device
    /// reading as `NoApplicableUpdate` after a later scan found updates, beside a
    /// finding that cited the earlier scan.
    #[test]
    fn a_later_successful_scan_clears_an_earlier_no_applicable_verdict() {
        let mut empty = reading_at("scan", "succeeded", "wu-40", "2026-01-01T01:00:00Z");
        empty.outcome = UpdateOutcome::NotApplicable;
        let later = reading_at("scan", "succeeded", "wu-41", "2026-01-01T02:00:00Z");

        let signals = device_level_signals(&[empty, later]);

        assert!(
            signals.no_applicable_update.is_none(),
            "the later scan reported updates, so the earlier verdict does not stand"
        );
    }

    /// A later successful scan clears an earlier failure.
    ///
    /// Event 25 is unkeyed and often transient, and the transaction design reads
    /// last rather than worst, so a device-level reading has to do the same: the
    /// readings are already in canonical time order. Keeping the first failure
    /// left the chain at `ScanFailed` beside a finding that cited a successful
    /// install.
    #[test]
    fn a_later_successful_scan_clears_an_earlier_failure() {
        let signals = device_level_signals(&[
            reading("scan", "failed", "wu-25"),
            reading("scan", "succeeded", "wu-26"),
        ]);

        assert_eq!(
            signals.scan_failed, None,
            "the later success is the device's scan health"
        );
    }

    /// A failure after a success is still a failure.
    #[test]
    fn a_failure_after_a_success_is_still_a_failure() {
        let signals = device_level_signals(&[
            reading("scan", "succeeded", "wu-26"),
            reading("scan", "failed", "wu-25"),
        ]);

        assert!(
            signals.scan_failed.is_some(),
            "the last reading is the device's scan health"
        );
    }
}
