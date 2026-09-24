//! Combine observations into one immutable per-setting snapshot.
//!
//! The reducer never picks a winner between disagreeing evidence. When device
//! records disagree with one another the local state is `Contested`; when device
//! and service disagree the resolution is `Contradicted`. Both keep every
//! contributing observation so a rule can cite the competing evidence rather than
//! assert an outcome.

use std::collections::btree_map::Entry;
use std::collections::BTreeMap;

use chrono::{DateTime, Utc};

use crate::intune::evidence::{IntuneErrorCode, IntuneEvidenceRef};

use super::identity::ConfigurationSettingIdentity;
use super::models::{
    ConfigurationDisposition, ConfigurationEvidenceSide, ConfigurationInput,
    ConfigurationLocalState, ConfigurationObservation, ConfigurationReceiptState,
    ConfigurationResolution, ConfigurationServiceState, ConfigurationSetting,
    ConfigurationSnapshot, ConfigurationSourceStatement, INTUNE_CONFIGURATION_SCHEMA_VERSION,
};
use super::redaction::analysis_scope_digest;
use super::sources::{
    is_device_side, is_service_side, is_unassessable_failure, observation_from_event,
    observation_from_report, same_source_id,
};

/// Project every input record and fold it into per-setting transactions.
///
/// The returned snapshot carries no findings; [`super::derive_findings`] produces
/// those from it, and [`super::analyze_configuration`] does both.
pub fn reduce_configuration(input: &ConfigurationInput) -> ConfigurationSnapshot {
    let mut observations = Vec::new();
    for event in &input.events {
        if let Some(observation) = observation_from_event(event) {
            observations.push(observation);
        }
    }
    for report in &input.reports {
        observations.push(observation_from_report(report));
    }

    let mut grouped: BTreeMap<String, Vec<ConfigurationObservation>> = BTreeMap::new();
    let mut unattributed = Vec::new();
    for observation in observations {
        if observation.identity.is_unidentified {
            unattributed.push(observation);
            continue;
        }
        grouped
            .entry(observation.identity.key.clone())
            .or_default()
            .push(observation);
    }

    let settings = grouped.into_values().map(reduce_setting).collect();
    // ADR-003: the caller's vector order is an acquisition detail, not chronology.
    // Sorting the unattributed records by their evidence reference means the
    // export never carries it.
    unattributed.sort_by(|left, right| left.evidence_ref.cmp(&right.evidence_ref));

    ConfigurationSnapshot {
        schema_version: INTUNE_CONFIGURATION_SCHEMA_VERSION,
        generated_at_utc: input.generated_at_utc.clone(),
        // Resolved once, here, so every projection of this snapshot — including a
        // redaction of a redaction — mints tokens in the same scope. The caller's
        // own scope value is reduced to a digest and does not travel further.
        analysis_scope: analysis_scope_digest(
            input.analysis_scope.as_deref(),
            &input.generated_at_utc,
        ),
        settings,
        unattributed,
        coverage: input.coverage.clone(),
        findings: Vec::new(),
        redacted: false,
    }
}

fn reduce_setting(mut observations: Vec<ConfigurationObservation>) -> ConfigurationSetting {
    // Canonical order first, so nothing downstream — nor the exported vector —
    // can depend on how the caller happened to hand the records over. ADR-003
    // permits caller order as chronology only where the source contract defines
    // it, and no configuration source defines it. Where real order exists it is
    // read from record ordinals, not from this vector.
    observations.sort_by(|left, right| left.evidence_ref.cmp(&right.evidence_ref));

    let identity = merge_identity(&observations);

    let receipt = receipt_state(&observations);
    let local = local_state(&observations);
    let service = service_state(&observations);
    let resolution = resolve(local, service);

    let local_error = terminal_error(&observations, is_device_side);
    let service_error = terminal_error(&observations, is_service_side);

    let applied_value = agreed_applied_value(&observations);

    let time_is_reliable = observations
        .iter()
        .all(|observation| observation.time_is_reliable);
    let ordering_is_contradictory = ordering_is_contradictory(&observations);
    let has_uninterpretable_evidence = observations
        .iter()
        .any(|observation| observation.is_uninterpretable);
    let has_unassessable_failure = observations.iter().any(is_unassessable_failure);

    let evidence = observations
        .iter()
        .map(|observation| observation.evidence_ref.clone())
        .collect::<Vec<_>>();

    ConfigurationSetting {
        identity,
        receipt,
        local,
        service,
        resolution,
        sources: source_statements(&observations),
        local_error,
        service_error,
        applied_value,
        time_is_reliable,
        ordering_is_contradictory,
        has_uninterpretable_evidence,
        has_unassessable_failure,
        observations,
        evidence,
    }
}

/// The value the device reported writing, when its records agree on one.
///
/// Two sources applying *different* values to one node do not entitle the export
/// to name whichever arrived first — that made the exported value a function of
/// the caller's vector. A disagreement is reported as no stated value; the
/// conflict rules already name the sources that are arguing.
fn agreed_applied_value(observations: &[ConfigurationObservation]) -> Option<String> {
    let mut agreed: Option<&str> = None;
    for value in observations
        .iter()
        .filter(|observation| is_device_side(observation))
        .filter(|observation| observation.disposition == ConfigurationDisposition::Applied)
        .filter_map(|observation| observation.value.as_deref())
    {
        match agreed {
            None => agreed = Some(value),
            Some(existing) if existing == value => {}
            Some(_) => return None,
        }
    }
    agreed.map(str::to_owned)
}

/// Fill in the identity fields that only some records carried.
///
/// Every observation in the group already shares a key, so this widens the
/// description without changing which transaction it is. Where records offer
/// different values for one field, the smallest is taken rather than the first:
/// "first" meant the serializer's order, and it could flip
/// `configuration-duplicate-display-name` on and off between two runs over the
/// same evidence.
fn merge_identity(observations: &[ConfigurationObservation]) -> ConfigurationSettingIdentity {
    let base = &observations
        .first()
        .expect("a group always has at least one observation")
        .identity;

    // The three URI views are derived from one string and must move as a unit; a
    // canonical URI from one record beside a raw URI from another would describe
    // no record at all.
    let uri_source = observations
        .iter()
        .map(|observation| &observation.identity)
        .filter(|identity| identity.canonical_uri.is_some())
        .min_by(|left, right| left.canonical_uri.cmp(&right.canonical_uri));

    ConfigurationSettingIdentity {
        // Shared by construction: it is the grouping key.
        key: base.key.clone(),
        canonical_uri: uri_source.and_then(|identity| identity.canonical_uri.clone()),
        raw_uri: uri_source.and_then(|identity| identity.raw_uri.clone()),
        resource_path: uri_source.and_then(|identity| identity.resource_path.clone()),
        setting_id: smallest_stated(observations, |identity| identity.setting_id.as_ref()),
        policy_id: smallest_stated(observations, |identity| identity.policy_id.as_ref()),
        display_name: smallest_stated(observations, |identity| identity.display_name.as_ref()),
        scope: base.scope,
        csp: smallest_stated(observations, |identity| identity.csp.as_ref()),
        is_unidentified: base.is_unidentified,
    }
}

fn smallest_stated(
    observations: &[ConfigurationObservation],
    pick: fn(&ConfigurationSettingIdentity) -> Option<&String>,
) -> Option<String> {
    observations
        .iter()
        .filter_map(|observation| pick(&observation.identity))
        .min()
        .cloned()
}

fn receipt_state(observations: &[ConfigurationObservation]) -> ConfigurationReceiptState {
    let device: Vec<&ConfigurationObservation> = observations
        .iter()
        .filter(|observation| is_device_side(observation))
        .collect();

    if device
        .iter()
        .any(|observation| observation.disposition.is_terminal())
    {
        return ConfigurationReceiptState::CspProcessed;
    }
    if !device.is_empty() {
        return ConfigurationReceiptState::CommandReceived;
    }
    if observations.iter().any(is_service_side) {
        return ConfigurationReceiptState::Intended;
    }
    ConfigurationReceiptState::NoEvidence
}

/// Distinct terminal dispositions stated by one side, preserving observation order.
fn terminal_dispositions(
    observations: &[ConfigurationObservation],
    side: fn(&ConfigurationObservation) -> bool,
) -> Vec<ConfigurationDisposition> {
    let mut seen = Vec::new();
    for disposition in observations
        .iter()
        .filter(|observation| side(observation))
        .map(|observation| observation.disposition)
        .filter(|disposition| disposition.is_terminal())
    {
        if !seen.contains(&disposition) {
            seen.push(disposition);
        }
    }
    seen
}

fn local_state(observations: &[ConfigurationObservation]) -> ConfigurationLocalState {
    let state = terminal_local_state(observations);

    // ADR-001: non-assessable evidence cannot produce a terminal conclusion. A
    // command-failure record whose status could not be read still establishes the
    // *direction*, so a clean success alongside it is a disagreement, not a
    // success with a footnote. Failure-shaped states are left alone: the node is
    // already reported as trouble and the unreadable record is reported by its own
    // rule.
    let blocks_success = matches!(
        state,
        ConfigurationLocalState::Applied | ConfigurationLocalState::Removed
    ) && observations.iter().any(is_unassessable_failure);
    if blocks_success {
        return ConfigurationLocalState::Contested;
    }
    state
}

fn terminal_local_state(observations: &[ConfigurationObservation]) -> ConfigurationLocalState {
    let terminal = terminal_dispositions(observations, is_device_side);
    match terminal.as_slice() {
        [] => {
            // A device record that named the setting but could not be
            // interpreted is not the same as no device record at all: the first
            // is a parse problem worth reporting, the second is a coverage gap.
            let indeterminate = observations
                .iter()
                .filter(|observation| is_device_side(observation))
                .any(|observation| {
                    observation.disposition == ConfigurationDisposition::Indeterminate
                });
            if indeterminate {
                ConfigurationLocalState::Indeterminate
            } else {
                ConfigurationLocalState::NoEvidence
            }
        }
        [only] => match only {
            ConfigurationDisposition::Applied => ConfigurationLocalState::Applied,
            ConfigurationDisposition::Rejected => ConfigurationLocalState::Rejected,
            ConfigurationDisposition::Conflict => ConfigurationLocalState::Conflicted,
            ConfigurationDisposition::Superseded => ConfigurationLocalState::Superseded,
            ConfigurationDisposition::NotApplicable => ConfigurationLocalState::NotApplicable,
            ConfigurationDisposition::Removed => ConfigurationLocalState::Removed,
            ConfigurationDisposition::Received
            | ConfigurationDisposition::Pending
            | ConfigurationDisposition::Indeterminate => ConfigurationLocalState::Indeterminate,
        },
        many => reconcile_multiple_local(many, observations),
    }
}

/// Several device-side terminal dispositions for one setting.
///
/// Two mechanisms settle this, in order, and neither is caller order.
///
/// 1. **Explicit linkage.** A row that reports a conflict or a supersedence and
///    *names the source that beat it*, with that source present in the same
///    bundle, has stated the relationship outright. ADR-002 calls an explicit
///    shared key strong correlation, and this is the shape real MDM report
///    snapshots actually emit: the losing row carries `WinningPolicyId` or
///    `SupersededBy` and the winning row is simply `Applied`. Requiring the
///    *loser* to also emit an `Applied` row — which reports do not do — was what
///    made both headline scenarios unreachable.
/// 2. **Last terminal disposition.** Failing an explicit link, a lifecycle is
///    read from a comparable record order, and the current fact is the *last*
///    disposition in it. `[Applied, Removed, Applied]` is a re-application, not a
///    removal, and `[Removed, Applied]` (unassign, then re-assign) is not a
///    disagreement.
///
/// Only the lifecycle dispositions participate in step 2. A `Rejected` or
/// `NotApplicable` mixed with anything else is a genuine disagreement about what
/// the CSP did, and ADR-003 forbids letting a later-looking success quietly
/// replace a failure without explicit retry linkage. Those stay `Contested` so a
/// rule must cite both sides.
fn reconcile_multiple_local(
    terminal: &[ConfigurationDisposition],
    observations: &[ConfigurationObservation],
) -> ConfigurationLocalState {
    if let Some(state) = explicitly_linked_state(terminal, observations) {
        return state;
    }
    if !terminal.iter().copied().all(is_lifecycle_disposition) {
        return ConfigurationLocalState::Contested;
    }
    let Some(ordered) = ordered_terminal_dispositions(observations) else {
        return ConfigurationLocalState::Contested;
    };
    match ordered.last() {
        Some(ConfigurationDisposition::Applied) => ConfigurationLocalState::Applied,
        Some(ConfigurationDisposition::Removed) => ConfigurationLocalState::Removed,
        Some(ConfigurationDisposition::Superseded) => ConfigurationLocalState::Superseded,
        Some(ConfigurationDisposition::Conflict) => ConfigurationLocalState::Conflicted,
        _ => ConfigurationLocalState::Contested,
    }
}

/// Whether a disposition describes a stage of one setting's life rather than a
/// verdict that contradicts another verdict.
fn is_lifecycle_disposition(disposition: ConfigurationDisposition) -> bool {
    matches!(
        disposition,
        ConfigurationDisposition::Applied
            | ConfigurationDisposition::Removed
            | ConfigurationDisposition::Superseded
            | ConfigurationDisposition::Conflict
    )
}

/// The state implied by a losing row that names its winner, when the winner is
/// also in the bundle.
///
/// Returns `None` when no such link exists, when the terminal set contains
/// something the link cannot explain, or when the only "link" is a row naming
/// itself.
fn explicitly_linked_state(
    terminal: &[ConfigurationDisposition],
    observations: &[ConfigurationObservation],
) -> Option<ConfigurationLocalState> {
    let explainable = terminal.iter().all(|disposition| {
        matches!(
            disposition,
            ConfigurationDisposition::Applied
                | ConfigurationDisposition::Conflict
                | ConfigurationDisposition::Superseded
        )
    });
    if !explainable {
        return None;
    }

    if linked_source_is_observed(
        observations,
        ConfigurationDisposition::Conflict,
        |observation| observation.winning_source_id.as_deref(),
    ) {
        return Some(ConfigurationLocalState::Conflicted);
    }
    if linked_source_is_observed(
        observations,
        ConfigurationDisposition::Superseded,
        |observation| observation.superseded_by_source_id.as_deref(),
    ) {
        return Some(ConfigurationLocalState::Superseded);
    }
    None
}

/// Whether some record with `disposition` names another source that the bundle
/// actually contains.
fn linked_source_is_observed(
    observations: &[ConfigurationObservation],
    disposition: ConfigurationDisposition,
    named: fn(&ConfigurationObservation) -> Option<&str>,
) -> bool {
    observations
        .iter()
        .filter(|observation| is_device_side(observation) && observation.disposition == disposition)
        .filter_map(|observation| named(observation).map(|link| (observation, link)))
        .any(|(observation, link)| {
            // A row naming itself as its own winner substantiates nothing.
            let names_another = observation
                .source_id
                .as_deref()
                .is_none_or(|own| !same_source_id(own, link));
            names_another
                && observations.iter().any(|candidate| {
                    candidate
                        .source_id
                        .as_deref()
                        .is_some_and(|source| same_source_id(source, link))
                })
        })
}

/// Return terminal dispositions in their evidence order, when that order is
/// comparable.
///
/// Records are deduplicated by artifact and record ordinal *before* the
/// comparability guard runs. Re-collecting the same channel, or collecting it
/// twice under two artifact ids, previously made this refuse and degraded a clean
/// `configuration-removed` into a contested-evidence error: duplication was
/// making the diagnosis worse. Two artifacts are accepted only when they yield
/// the identical sequence, which is what a duplicate collection looks like; two
/// artifacts telling different stories stay incomparable.
fn ordered_terminal_dispositions(
    observations: &[ConfigurationObservation],
) -> Option<Vec<ConfigurationDisposition>> {
    let terminal = observations
        .iter()
        .filter(|observation| is_device_side(observation) && observation.disposition.is_terminal())
        .collect::<Vec<_>>();
    if terminal.len() < 2 || ordering_is_contradictory(observations) {
        return None;
    }

    let mut by_artifact: BTreeMap<&str, BTreeMap<u64, ConfigurationDisposition>> = BTreeMap::new();
    for observation in &terminal {
        let (Some(record_id), Some(_)) =
            (observation.record_id, observation.occurred_at_utc.as_ref())
        else {
            return None;
        };
        if !observation.time_is_reliable {
            return None;
        }
        match by_artifact
            .entry(observation.evidence_ref.source_artifact_id.as_str())
            .or_default()
            .entry(record_id)
        {
            Entry::Vacant(slot) => {
                slot.insert(observation.disposition);
            }
            // One ordinal in one artifact cannot have said two different things;
            // that is a broken collection, not a lifecycle.
            Entry::Occupied(slot) if *slot.get() != observation.disposition => return None,
            Entry::Occupied(_) => {}
        }
    }

    let mut sequences = by_artifact
        .into_values()
        .map(|records| records.into_values().collect::<Vec<_>>());
    let first = sequences.next()?;
    if sequences.any(|sequence| sequence != first) || first.len() < 2 {
        return None;
    }
    Some(first)
}

fn service_state(observations: &[ConfigurationObservation]) -> ConfigurationServiceState {
    let service: Vec<&ConfigurationObservation> = observations
        .iter()
        .filter(|observation| is_service_side(observation))
        .collect();
    if service.is_empty() {
        return ConfigurationServiceState::NoEvidence;
    }

    let terminal = terminal_dispositions(observations, is_service_side);
    match terminal.as_slice() {
        [] => {
            if service
                .iter()
                .any(|observation| observation.disposition == ConfigurationDisposition::Pending)
            {
                ConfigurationServiceState::ReportedPending
            } else {
                ConfigurationServiceState::Assigned
            }
        }
        [only] => match only {
            ConfigurationDisposition::Applied => ConfigurationServiceState::ReportedSuccess,
            ConfigurationDisposition::Rejected => ConfigurationServiceState::ReportedFailure,
            ConfigurationDisposition::Conflict => ConfigurationServiceState::ReportedConflict,
            ConfigurationDisposition::Superseded => ConfigurationServiceState::ReportedSuperseded,
            ConfigurationDisposition::NotApplicable => {
                ConfigurationServiceState::ReportedNotApplicable
            }
            // The service has no "removed" vocabulary; a delete reported as
            // success is still just a success from its point of view.
            ConfigurationDisposition::Removed => ConfigurationServiceState::ReportedSuccess,
            ConfigurationDisposition::Received
            | ConfigurationDisposition::Pending
            | ConfigurationDisposition::Indeterminate => ConfigurationServiceState::Assigned,
        },
        _ => ConfigurationServiceState::Contested,
    }
}

/// Decide the single conclusion, or refuse to.
///
/// Service evidence never overrides device evidence and never fills in for it.
/// A portal success with a local rejection is a contradiction, not a success,
/// and a portal success with no local evidence at all remains insufficient:
/// Intune reports what it was told, which is not the same as what the CSP did.
fn resolve(
    local: ConfigurationLocalState,
    service: ConfigurationServiceState,
) -> ConfigurationResolution {
    let local_conclusion = match local {
        ConfigurationLocalState::Applied => Some(ConfigurationResolution::Applied),
        ConfigurationLocalState::Rejected => Some(ConfigurationResolution::Rejected),
        ConfigurationLocalState::Conflicted => Some(ConfigurationResolution::Conflicted),
        ConfigurationLocalState::Superseded => Some(ConfigurationResolution::Superseded),
        ConfigurationLocalState::NotApplicable => Some(ConfigurationResolution::NotApplicable),
        ConfigurationLocalState::Removed => Some(ConfigurationResolution::Removed),
        ConfigurationLocalState::Contested => Some(ConfigurationResolution::Contradicted),
        ConfigurationLocalState::NoEvidence | ConfigurationLocalState::Indeterminate => None,
    };

    let service_conclusion = match service {
        ConfigurationServiceState::ReportedSuccess => Some(ConfigurationResolution::Applied),
        ConfigurationServiceState::ReportedFailure => Some(ConfigurationResolution::Rejected),
        ConfigurationServiceState::ReportedConflict => Some(ConfigurationResolution::Conflicted),
        ConfigurationServiceState::ReportedSuperseded => Some(ConfigurationResolution::Superseded),
        ConfigurationServiceState::ReportedNotApplicable => {
            Some(ConfigurationResolution::NotApplicable)
        }
        ConfigurationServiceState::Contested => Some(ConfigurationResolution::Contradicted),
        ConfigurationServiceState::NoEvidence
        | ConfigurationServiceState::Assigned
        | ConfigurationServiceState::ReportedPending => None,
    };

    // A device removal beside a service success used to resolve to `Removed`, on
    // the assumption that Intune reports a completed delete as a success. No
    // documented contract says so, and ADR-003 is explicit that an unresolved
    // authoritative contradiction becomes conflicting rather than an arbitrary
    // winner. It is now treated like any other disagreement: both statements are
    // kept and cited, and the reader decides. If Intune's reporting vocabulary is
    // ever written down, this is the one line that changes.
    match (local_conclusion, service_conclusion) {
        (Some(local), Some(service)) if local != service => ConfigurationResolution::Contradicted,
        (Some(local), _) => local,
        // Service-only evidence is supplemental. It cannot establish that the
        // CSP applied anything, so it does not become a resolution on its own.
        (None, _) => ConfigurationResolution::InsufficientEvidence,
    }
}

/// The terminal status one side reported.
///
/// When two records of one side report *different* codes, the smallest by
/// canonical ordering is named rather than whichever arrived first: two 404s used
/// to flip which HRESULT the rejection finding quoted depending on the caller's
/// vector order. Both records stay cited either way, so nothing is hidden — only
/// the choice of which code to lead with is made stable.
fn terminal_error(
    observations: &[ConfigurationObservation],
    side: fn(&ConfigurationObservation) -> bool,
) -> Option<IntuneErrorCode> {
    observations
        .iter()
        .filter(|observation| side(observation))
        .filter(|observation| observation.disposition == ConfigurationDisposition::Rejected)
        .filter_map(|observation| observation.error.as_ref())
        .min_by(|left, right| {
            (&left.decimal, &left.hex, &left.raw).cmp(&(&right.decimal, &right.hex, &right.raw))
        })
        .cloned()
}

/// One entry per distinct configuration source that stated something.
fn source_statements(
    observations: &[ConfigurationObservation],
) -> Vec<ConfigurationSourceStatement> {
    let mut grouped: BTreeMap<
        (
            Option<String>,
            ConfigurationEvidenceSide,
            ConfigurationDisposition,
        ),
        Vec<IntuneEvidenceRef>,
    > = BTreeMap::new();

    for observation in observations {
        grouped
            .entry((
                observation.source_id.clone(),
                observation.side,
                observation.disposition,
            ))
            .or_default()
            .push(observation.evidence_ref.clone());
    }

    grouped
        .into_iter()
        .map(
            |((source_id, side, disposition), evidence)| ConfigurationSourceStatement {
                source_id,
                side,
                disposition,
                evidence,
            },
        )
        .collect()
}

/// True when device record order and device timestamp order disagree.
///
/// Compared only within one artifact: record numbers are per-channel ordinals and
/// comparing them across two files would manufacture a contradiction that the
/// evidence does not contain.
fn ordering_is_contradictory(observations: &[ConfigurationObservation]) -> bool {
    let mut by_artifact: BTreeMap<&str, Vec<(u64, DateTime<Utc>)>> = BTreeMap::new();
    for observation in observations.iter().filter(|obs| is_device_side(obs)) {
        let (Some(record_id), Some(instant)) = (
            observation.record_id,
            observation.occurred_at_utc.as_deref(),
        ) else {
            continue;
        };
        if !observation.time_is_reliable {
            continue;
        }
        let Ok(instant) = DateTime::parse_from_rfc3339(instant) else {
            continue;
        };
        by_artifact
            .entry(observation.evidence_ref.source_artifact_id.as_str())
            .or_default()
            .push((record_id, instant.with_timezone(&Utc)));
    }

    by_artifact.into_values().any(|mut records| {
        records.sort_by_key(|(record_id, _)| *record_id);
        records.windows(2).any(|pair| pair[0].1 > pair[1].1)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intune::evidence::{
        IntuneEvidenceRef, IntuneNamedValue, IntuneSensitivity, IntuneSourceKind,
    };

    fn observation(
        evidence_id: &str,
        disposition: ConfigurationDisposition,
        record_id: Option<u64>,
        occurred_at_utc: Option<&str>,
    ) -> ConfigurationObservation {
        let identity =
            super::super::identity::resolve_identity(&super::super::identity::IdentityHints {
                uri: Some("./Device/Vendor/MSFT/Policy/Config/Test"),
                evidence_id,
                ..Default::default()
            });
        ConfigurationObservation {
            evidence_ref: IntuneEvidenceRef {
                evidence_id: evidence_id.to_owned(),
                source_artifact_id: "test-artifact".to_owned(),
            },
            side: ConfigurationEvidenceSide::Device,
            source_kind: IntuneSourceKind::PlainTextLog,
            sensitivity: IntuneSensitivity::Public,
            identity,
            disposition,
            event_kind: None,
            event_id: None,
            source_id: None,
            enrollment_id: None,
            command_type: None,
            value: None,
            error: None,
            winning_source_id: None,
            superseded_by_source_id: None,
            occurred_at_utc: occurred_at_utc.map(str::to_owned),
            time_is_reliable: occurred_at_utc.is_some(),
            record_id,
            is_uninterpretable: false,
            named_data: Vec::<IntuneNamedValue>::new(),
        }
    }

    #[test]
    fn apply_then_remove_is_removed_but_reverse_observation_is_ordered_by_metadata() {
        let apply = observation(
            "apply",
            ConfigurationDisposition::Applied,
            Some(1),
            Some("2026-07-31T09:00:00Z"),
        );
        let remove = observation(
            "remove",
            ConfigurationDisposition::Removed,
            Some(2),
            Some("2026-07-31T10:00:00Z"),
        );
        assert_eq!(
            local_state(&[apply.clone(), remove.clone()]),
            ConfigurationLocalState::Removed
        );
        assert_eq!(
            local_state(&[remove, apply]),
            ConfigurationLocalState::Removed
        );
    }

    #[test]
    fn contradictory_or_unavailable_order_stays_contested() {
        let observations = vec![
            observation(
                "apply",
                ConfigurationDisposition::Applied,
                Some(1),
                Some("2026-07-31T10:00:00Z"),
            ),
            observation(
                "remove",
                ConfigurationDisposition::Removed,
                Some(2),
                Some("2026-07-31T09:00:00Z"),
            ),
        ];
        assert_eq!(
            local_state(&observations),
            ConfigurationLocalState::Contested
        );

        let unavailable = vec![
            observation("apply", ConfigurationDisposition::Applied, None, None),
            observation("remove", ConfigurationDisposition::Removed, None, None),
        ];
        assert_eq!(
            local_state(&unavailable),
            ConfigurationLocalState::Contested
        );
    }

    #[test]
    fn removed_local_and_reported_success_stay_a_contradiction() {
        // Previously hard-coded to `Removed` on the assumption that Intune reports
        // a completed delete as a success. Nothing documents that, and ADR-003
        // requires an unresolved authoritative contradiction to stay conservative.
        assert_eq!(
            resolve(
                ConfigurationLocalState::Removed,
                ConfigurationServiceState::ReportedSuccess,
            ),
            ConfigurationResolution::Contradicted
        );
    }

    /// `[Applied, Removed, Applied]` is a re-application. Reading the *first*
    /// index of each disposition reported `Removed`, which is the opposite of
    /// what the last record says happened.
    #[test]
    fn a_re_application_after_a_removal_is_applied() {
        let observations = vec![
            observation(
                "apply",
                ConfigurationDisposition::Applied,
                Some(1),
                Some("2026-07-31T09:00:00Z"),
            ),
            observation(
                "remove",
                ConfigurationDisposition::Removed,
                Some(2),
                Some("2026-07-31T10:00:00Z"),
            ),
            observation(
                "reapply",
                ConfigurationDisposition::Applied,
                Some(3),
                Some("2026-07-31T11:00:00Z"),
            ),
        ];
        assert_eq!(local_state(&observations), ConfigurationLocalState::Applied);
    }

    /// Unassign, then re-assign. The old first-index comparison failed the guard
    /// here and reported a disagreement at Error severity.
    #[test]
    fn a_removal_followed_by_an_application_is_applied_not_contested() {
        let observations = vec![
            observation(
                "remove",
                ConfigurationDisposition::Removed,
                Some(1),
                Some("2026-07-31T09:00:00Z"),
            ),
            observation(
                "apply",
                ConfigurationDisposition::Applied,
                Some(2),
                Some("2026-07-31T10:00:00Z"),
            ),
        ];
        assert_eq!(local_state(&observations), ConfigurationLocalState::Applied);
    }

    #[test]
    fn a_rejection_alongside_an_application_is_never_resolved_by_order() {
        // ADR-003: a later-looking success may not replace a failure without
        // explicit retry linkage, which no configuration source supplies.
        let observations = vec![
            observation(
                "reject",
                ConfigurationDisposition::Rejected,
                Some(1),
                Some("2026-07-31T09:00:00Z"),
            ),
            observation(
                "apply",
                ConfigurationDisposition::Applied,
                Some(2),
                Some("2026-07-31T10:00:00Z"),
            ),
        ];
        assert_eq!(
            local_state(&observations),
            ConfigurationLocalState::Contested
        );
    }

    #[test]
    fn re_collecting_the_same_record_does_not_escalate_a_clean_lifecycle() {
        let apply = observation(
            "apply",
            ConfigurationDisposition::Applied,
            Some(1),
            Some("2026-07-31T09:00:00Z"),
        );
        let remove = observation(
            "remove",
            ConfigurationDisposition::Removed,
            Some(2),
            Some("2026-07-31T10:00:00Z"),
        );
        let mut duplicate = remove.clone();
        duplicate.evidence_ref.evidence_id = "remove-again".to_owned();
        assert_eq!(
            local_state(&[apply, remove, duplicate]),
            ConfigurationLocalState::Removed,
            "a duplicated record must not turn a removal into a disagreement"
        );
    }

    #[test]
    fn collecting_one_channel_under_two_artifact_ids_is_a_duplicate_not_a_disagreement() {
        let apply = observation(
            "apply",
            ConfigurationDisposition::Applied,
            Some(1),
            Some("2026-07-31T09:00:00Z"),
        );
        let remove = observation(
            "remove",
            ConfigurationDisposition::Removed,
            Some(2),
            Some("2026-07-31T10:00:00Z"),
        );
        let second_copy = |observation: &ConfigurationObservation, id: &str| {
            let mut copy = observation.clone();
            copy.evidence_ref.evidence_id = id.to_owned();
            copy.evidence_ref.source_artifact_id = "second-capture".to_owned();
            copy
        };
        let observations = vec![
            apply.clone(),
            remove.clone(),
            second_copy(&apply, "apply-again"),
            second_copy(&remove, "remove-again"),
        ];
        assert_eq!(local_state(&observations), ConfigurationLocalState::Removed);
    }

    #[test]
    fn two_artifacts_telling_different_stories_stay_incomparable() {
        let apply = observation(
            "apply",
            ConfigurationDisposition::Applied,
            Some(1),
            Some("2026-07-31T09:00:00Z"),
        );
        let mut elsewhere = observation(
            "remove",
            ConfigurationDisposition::Removed,
            Some(1),
            Some("2026-07-31T10:00:00Z"),
        );
        elsewhere.evidence_ref.source_artifact_id = "other-artifact".to_owned();
        assert_eq!(
            local_state(&[apply, elsewhere]),
            ConfigurationLocalState::Contested
        );
    }

    /// The shape a real MDM report emits: the losing row names the winner and the
    /// winner is simply `Applied`. No losing `Applied` row exists, and the record
    /// numbers say nothing about which policy won.
    #[test]
    fn an_explicitly_named_winner_makes_the_node_conflicted_whatever_the_record_order() {
        let winner = "22222222-2222-4222-8222-222222222222";
        let build = |loser_record: u64, winner_record: u64| {
            let mut loser = observation(
                "loser",
                ConfigurationDisposition::Conflict,
                Some(loser_record),
                Some("2026-07-31T09:00:00Z"),
            );
            loser.source_id = Some("11111111-1111-4111-8111-111111111111".to_owned());
            loser.winning_source_id = Some(winner.to_ascii_uppercase());
            let mut applied = observation(
                "winner",
                ConfigurationDisposition::Applied,
                Some(winner_record),
                Some("2026-07-31T09:00:00Z"),
            );
            applied.source_id = Some(format!("{{{winner}}}"));
            vec![loser, applied]
        };
        assert_eq!(
            local_state(&build(1, 2)),
            ConfigurationLocalState::Conflicted
        );
        assert_eq!(
            local_state(&build(2, 1)),
            ConfigurationLocalState::Conflicted,
            "swapping the record numbers must not change the diagnosis"
        );
    }

    #[test]
    fn an_explicitly_named_replacement_makes_the_node_superseded() {
        let replacement = "22222222-2222-4222-8222-222222222222";
        let mut superseded = observation(
            "superseded",
            ConfigurationDisposition::Superseded,
            Some(1),
            Some("2026-07-31T09:00:00Z"),
        );
        superseded.source_id = Some("11111111-1111-4111-8111-111111111111".to_owned());
        superseded.superseded_by_source_id = Some(replacement.to_owned());
        let mut applied = observation(
            "replacement",
            ConfigurationDisposition::Applied,
            Some(2),
            Some("2026-07-31T09:00:00Z"),
        );
        applied.source_id = Some(replacement.to_owned());
        assert_eq!(
            local_state(&[superseded, applied]),
            ConfigurationLocalState::Superseded
        );
    }

    #[test]
    fn a_row_naming_itself_as_the_winner_links_nothing() {
        let own = "11111111-1111-4111-8111-111111111111";
        let mut loser = observation(
            "self-referential",
            ConfigurationDisposition::Conflict,
            Some(1),
            Some("2026-07-31T09:00:00Z"),
        );
        loser.source_id = Some(own.to_owned());
        loser.winning_source_id = Some(own.to_ascii_uppercase());
        let mut applied = observation(
            "applied",
            ConfigurationDisposition::Applied,
            Some(2),
            Some("2026-07-31T09:00:00Z"),
        );
        applied.source_id = Some(own.to_owned());
        // Falls through to the ordered path, where the last record is the fact.
        assert_eq!(
            local_state(&[loser, applied]),
            ConfigurationLocalState::Applied
        );
    }
}
