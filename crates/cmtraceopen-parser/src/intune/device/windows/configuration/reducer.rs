//! Combine observations into one immutable per-setting snapshot.
//!
//! The reducer never picks a winner between disagreeing evidence. When device
//! records disagree with one another the local state is `Contested`; when device
//! and service disagree the resolution is `Contradicted`. Both keep every
//! contributing observation so a rule can cite the competing evidence rather than
//! assert an outcome.

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
use super::sources::{
    is_device_side, is_service_side, observation_from_event, observation_from_report,
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

    ConfigurationSnapshot {
        schema_version: INTUNE_CONFIGURATION_SCHEMA_VERSION,
        generated_at_utc: input.generated_at_utc.clone(),
        settings,
        unattributed,
        coverage: input.coverage.clone(),
        findings: Vec::new(),
        redacted: false,
    }
}

fn reduce_setting(observations: Vec<ConfigurationObservation>) -> ConfigurationSetting {
    let identity = merge_identity(&observations);

    let receipt = receipt_state(&observations);
    let local = local_state(&observations);
    let service = service_state(&observations);
    let resolution = resolve(local, service);

    let local_error = terminal_error(&observations, is_device_side);
    let service_error = terminal_error(&observations, is_service_side);

    let applied_value = observations
        .iter()
        .filter(|observation| is_device_side(observation))
        .filter(|observation| observation.disposition == ConfigurationDisposition::Applied)
        .find_map(|observation| observation.value.clone());

    let time_is_reliable = observations
        .iter()
        .all(|observation| observation.time_is_reliable);
    let ordering_is_contradictory = ordering_is_contradictory(&observations);
    let has_uninterpretable_evidence = observations
        .iter()
        .any(|observation| observation.is_uninterpretable);

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
        observations,
        evidence,
    }
}

/// Fill in the identity fields that only some records carried.
///
/// Every observation in the group already shares a key, so this widens the
/// description without changing which transaction it is. The first non-empty
/// value wins, and observations arrive in input order, so the result is
/// deterministic.
fn merge_identity(observations: &[ConfigurationObservation]) -> ConfigurationSettingIdentity {
    let mut identity = observations
        .first()
        .expect("a group always has at least one observation")
        .identity
        .clone();

    for observation in observations.iter().skip(1) {
        let other = &observation.identity;
        if identity.canonical_uri.is_none() {
            identity.canonical_uri.clone_from(&other.canonical_uri);
            identity.raw_uri.clone_from(&other.raw_uri);
            identity.resource_path.clone_from(&other.resource_path);
        }
        if identity.setting_id.is_none() {
            identity.setting_id.clone_from(&other.setting_id);
        }
        if identity.policy_id.is_none() {
            identity.policy_id.clone_from(&other.policy_id);
        }
        if identity.display_name.is_none() {
            identity.display_name.clone_from(&other.display_name);
        }
        if identity.csp.is_none() {
            identity.csp.clone_from(&other.csp);
        }
    }

    identity
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
/// A removal following an application is a lifecycle, not a disagreement: the
/// setting was applied and then deleted, and `Removed` is the current fact.
/// The same holds for a conflict or supersedence recorded alongside an
/// application, where the losing write genuinely did happen first. Anything else
/// is a real disagreement and stays `Contested` so a rule must cite both sides.
fn reconcile_multiple_local(
    terminal: &[ConfigurationDisposition],
    observations: &[ConfigurationObservation],
) -> ConfigurationLocalState {
    let Some(ordered) = ordered_terminal_dispositions(observations) else {
        return ConfigurationLocalState::Contested;
    };
    let has = |disposition: ConfigurationDisposition| terminal.contains(&disposition);
    let applied_precedes = |disposition: ConfigurationDisposition| {
        ordered
            .iter()
            .position(|candidate| *candidate == ConfigurationDisposition::Applied)
            .zip(
                ordered
                    .iter()
                    .position(|candidate| *candidate == disposition),
            )
            .is_some_and(|(applied, terminal)| applied < terminal)
    };

    if has(ConfigurationDisposition::Removed)
        && terminal.iter().all(|d| {
            matches!(
                d,
                ConfigurationDisposition::Removed | ConfigurationDisposition::Applied
            )
        })
        && applied_precedes(ConfigurationDisposition::Removed)
    {
        return ConfigurationLocalState::Removed;
    }
    if has(ConfigurationDisposition::Superseded)
        && terminal.iter().all(|d| {
            matches!(
                d,
                ConfigurationDisposition::Superseded | ConfigurationDisposition::Applied
            )
        })
        && applied_precedes(ConfigurationDisposition::Superseded)
    {
        return ConfigurationLocalState::Superseded;
    }
    if has(ConfigurationDisposition::Conflict)
        && terminal.iter().all(|d| {
            matches!(
                d,
                ConfigurationDisposition::Conflict | ConfigurationDisposition::Applied
            )
        })
        && applied_precedes(ConfigurationDisposition::Conflict)
    {
        return ConfigurationLocalState::Conflicted;
    }
    ConfigurationLocalState::Contested
}

/// Return terminal dispositions in their evidence order, when that order is
/// comparable. Record ordinals and reliable timestamps must describe one artifact;
/// otherwise a lifecycle conclusion would be inferred from an unordered set.
fn ordered_terminal_dispositions(
    observations: &[ConfigurationObservation],
) -> Option<Vec<ConfigurationDisposition>> {
    let mut terminal = observations
        .iter()
        .filter(|observation| is_device_side(observation) && observation.disposition.is_terminal())
        .collect::<Vec<_>>();
    if terminal.len() < 2 || ordering_is_contradictory(observations) {
        return None;
    }
    let artifact = terminal.first()?.evidence_ref.source_artifact_id.as_str();
    if terminal
        .iter()
        .any(|observation| observation.evidence_ref.source_artifact_id != artifact)
    {
        return None;
    }
    if terminal.iter().any(|observation| {
        observation.record_id.is_none()
            || !observation.time_is_reliable
            || observation.occurred_at_utc.is_none()
    }) {
        return None;
    }
    terminal.sort_by_key(|observation| observation.record_id);
    if terminal
        .windows(2)
        .any(|pair| pair[0].record_id == pair[1].record_id)
    {
        return None;
    }
    Some(
        terminal
            .iter()
            .map(|observation| observation.disposition)
            .collect(),
    )
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

    match (local_conclusion, service_conclusion) {
        // A service-side removal is represented as reported success. When the
        // device also says Removed, those statements agree on the lifecycle
        // outcome rather than contradicting one another.
        (Some(ConfigurationResolution::Removed), Some(ConfigurationResolution::Applied)) => {
            ConfigurationResolution::Removed
        }
        (Some(local), Some(service)) if local != service => ConfigurationResolution::Contradicted,
        (Some(local), _) => local,
        // Service-only evidence is supplemental. It cannot establish that the
        // CSP applied anything, so it does not become a resolution on its own.
        (None, _) => ConfigurationResolution::InsufficientEvidence,
    }
}

fn terminal_error(
    observations: &[ConfigurationObservation],
    side: fn(&ConfigurationObservation) -> bool,
) -> Option<IntuneErrorCode> {
    observations
        .iter()
        .filter(|observation| side(observation))
        .filter(|observation| observation.disposition == ConfigurationDisposition::Rejected)
        .find_map(|observation| observation.error.clone())
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
    fn removed_local_and_reported_success_agree_on_removed_resolution() {
        assert_eq!(
            resolve(
                ConfigurationLocalState::Removed,
                ConfigurationServiceState::ReportedSuccess,
            ),
            ConfigurationResolution::Removed
        );
    }
}
