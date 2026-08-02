//! Read-only normalization of already-observed SCCM client source candidates.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

#[cfg(test)]
use std::cell::Cell;

use cmtraceopen_parser::sccm::SccmRotation;
use sha2::{Digest, Sha256};

use super::contract::{
    canonical_client_source, catalog_entry_id, expected_marker_artifact_id,
    expected_physical_artifact_id, logical_artifact_ids_for_basename, root_handle_digest,
    rotation_order, rotation_segment, source_identity_digest, SccmManifestSourceState,
};

pub const MAX_SCCM_CLIENT_DISCOVERY_DECLARATIONS: usize = 4_096;
/// Defensive bound for supplied observations. Native enumeration must report
/// its own truncation as SCCM coverage; this pure normalizer does not silently
/// discard observations beyond the contract.
pub const MAX_SCCM_CLIENT_DISCOVERY_OBSERVATIONS: usize =
    MAX_SCCM_CLIENT_DISCOVERY_DECLARATIONS + 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SccmClientDiscoveryObservationState {
    Found,
    AccessDenied,
    NotFound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SccmClientDiscoveryState {
    Discovered,
    AccessDenied,
    NotFound,
    Capped,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SccmClientDiscoveryObservation {
    /// A privacy-classified root handle, never a native path.
    pub root_handle: String,
    pub basename: String,
    pub rotation: SccmRotation,
    pub state: SccmClientDiscoveryObservationState,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SccmClientDiscoveryInput {
    /// Physical found-fragment cap for one root/source lineage.
    pub max_found_fragments_per_source: usize,
    pub observations: Vec<SccmClientDiscoveryObservation>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SccmClientDiscoveryDeclaration {
    pub catalog_entry_id: String,
    pub logical_artifact_ids: Vec<String>,
    pub artifact_id: String,
    pub evidence_identity: String,
    pub path_fingerprint: String,
    pub root_handle: String,
    pub basename: String,
    pub rotation: SccmRotation,
    pub state: SccmClientDiscoveryState,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct SccmClientDiscoveryResult {
    pub declarations: Vec<SccmClientDiscoveryDeclaration>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SccmClientDiscoveryError {
    ConflictingObservation,
    ObservationLimitExceeded,
}

impl fmt::Display for SccmClientDiscoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConflictingObservation => {
                formatter.write_str("conflicting SCCM client discovery observations")
            }
            Self::ObservationLimitExceeded => {
                formatter.write_str("SCCM client discovery observation limit exceeded")
            }
        }
    }
}

impl std::error::Error for SccmClientDiscoveryError {}

struct Candidate {
    observation: SccmClientDiscoveryObservation,
    catalog_entry_id: String,
    logical_artifact_ids: Vec<String>,
    source_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct PhysicalObservationKey {
    root_handle: String,
    canonical_basename: String,
    rotation: String,
}

struct NormalizedObservation<'a> {
    observation: &'a SccmClientDiscoveryObservation,
    canonical_basename: String,
}

#[cfg(test)]
thread_local! {
    static CANDIDATE_CONSTRUCTIONS: Cell<usize> = const { Cell::new(0) };
    static DECLARATION_CONSTRUCTIONS: Cell<usize> = const { Cell::new(0) };
    static NORMALIZATION_OPERATIONS: Cell<usize> = const { Cell::new(0) };
}

pub fn discover_client_sources(
    input: &SccmClientDiscoveryInput,
) -> Result<SccmClientDiscoveryResult, SccmClientDiscoveryError> {
    if input.observations.len() > MAX_SCCM_CLIENT_DISCOVERY_OBSERVATIONS {
        return Err(SccmClientDiscoveryError::ObservationLimitExceeded);
    }

    let observations = normalize_observations(input)?;
    let mut found_per_source = BTreeMap::<(String, String), usize>::new();
    let mut capped_sources = BTreeSet::<(String, String)>::new();
    let mut declarations = Vec::with_capacity(MAX_SCCM_CLIENT_DISCOVERY_DECLARATIONS);
    let mut first_omitted: Option<(NormalizedObservation<'_>, SccmClientDiscoveryState)> = None;

    for observation in observations {
        let Some(state) = selection_state(
            &observation,
            input.max_found_fragments_per_source,
            &mut found_per_source,
            &mut capped_sources,
        ) else {
            continue;
        };

        if declarations.len() < MAX_SCCM_CLIENT_DISCOVERY_DECLARATIONS - 1 {
            declarations.push(declaration_from_candidate(
                candidate_from_observation(&observation).expect("prevalidated observation"),
                state,
            ));
        } else if let Some((first_omitted, _)) = first_omitted {
            declarations.push(declaration_from_candidate(
                candidate_from_observation(&first_omitted).expect("prevalidated observation"),
                SccmClientDiscoveryState::Capped,
            ));
            return Ok(SccmClientDiscoveryResult { declarations });
        } else {
            first_omitted = Some((observation, state));
        }
    }

    if let Some((last, state)) = first_omitted {
        declarations.push(declaration_from_candidate(
            candidate_from_observation(&last).expect("prevalidated observation"),
            state,
        ));
    }

    Ok(SccmClientDiscoveryResult { declarations })
}

fn normalize_observations(
    input: &SccmClientDiscoveryInput,
) -> Result<Vec<NormalizedObservation<'_>>, SccmClientDiscoveryError> {
    let mut observations = BTreeMap::<PhysicalObservationKey, NormalizedObservation<'_>>::new();
    for observation in &input.observations {
        let Some(normalized) = normalize_observation(observation) else {
            continue;
        };
        let key = PhysicalObservationKey {
            root_handle: observation.root_handle.clone(),
            canonical_basename: normalized.canonical_basename.clone(),
            rotation: rotation_segment(&observation.rotation),
        };
        match observations.entry(key) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(normalized);
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                if entry.get().observation.state != observation.state {
                    return Err(SccmClientDiscoveryError::ConflictingObservation);
                }
                if compare_observation_order(&normalized, entry.get()) == Ordering::Less {
                    entry.insert(normalized);
                }
            }
        }
    }
    let mut observations = observations.into_values().collect::<Vec<_>>();
    observations.sort_by(compare_observation_order);
    Ok(observations)
}

fn normalize_observation(
    observation: &SccmClientDiscoveryObservation,
) -> Option<NormalizedObservation<'_>> {
    #[cfg(test)]
    NORMALIZATION_OPERATIONS.with(|count| count.set(count.get() + 1));
    root_handle_digest(&observation.root_handle)?;
    let canonical_basename = canonical_client_source(&observation.basename, &observation.rotation)?;
    Some(NormalizedObservation {
        observation,
        canonical_basename,
    })
}

fn selection_state(
    observation: &NormalizedObservation<'_>,
    max_found_fragments_per_source: usize,
    found_per_source: &mut BTreeMap<(String, String), usize>,
    capped_sources: &mut BTreeSet<(String, String)>,
) -> Option<SccmClientDiscoveryState> {
    let source_key = (
        observation.observation.root_handle.clone(),
        observation.canonical_basename.clone(),
    );
    Some(match observation.observation.state {
        SccmClientDiscoveryObservationState::Found => {
            let count = found_per_source.entry(source_key.clone()).or_default();
            if *count < max_found_fragments_per_source {
                *count += 1;
                SccmClientDiscoveryState::Discovered
            } else if capped_sources.insert(source_key) {
                SccmClientDiscoveryState::Capped
            } else {
                return None;
            }
        }
        SccmClientDiscoveryObservationState::AccessDenied => SccmClientDiscoveryState::AccessDenied,
        SccmClientDiscoveryObservationState::NotFound => SccmClientDiscoveryState::NotFound,
    })
}

fn candidate_from_observation(observation: &NormalizedObservation<'_>) -> Option<Candidate> {
    #[cfg(test)]
    CANDIDATE_CONSTRUCTIONS.with(|count| count.set(count.get() + 1));
    let source_digest = source_identity_digest(
        &observation.observation.root_handle,
        &observation.canonical_basename,
    )?;

    Some(Candidate {
        observation: observation.observation.clone(),
        catalog_entry_id: catalog_entry_id(&observation.canonical_basename),
        logical_artifact_ids: logical_artifact_ids_for_basename(&observation.canonical_basename),
        source_digest,
    })
}

fn declaration_from_candidate(
    candidate: Candidate,
    state: SccmClientDiscoveryState,
) -> SccmClientDiscoveryDeclaration {
    #[cfg(test)]
    DECLARATION_CONSTRUCTIONS.with(|count| count.set(count.get() + 1));

    let path_fingerprint = format!("sha256:{}", candidate.source_digest);
    let artifact_id = match state {
        SccmClientDiscoveryState::Discovered => expected_physical_artifact_id(
            &path_fingerprint,
            &candidate.observation.rotation,
            &candidate.observation.basename,
        ),
        SccmClientDiscoveryState::AccessDenied => marker_id(
            &candidate.catalog_entry_id,
            SccmManifestSourceState::AccessDenied,
            &candidate.observation.rotation,
            &candidate.observation.basename,
            &path_fingerprint,
        ),
        SccmClientDiscoveryState::NotFound => marker_id(
            &candidate.catalog_entry_id,
            SccmManifestSourceState::Absent,
            &candidate.observation.rotation,
            &candidate.observation.basename,
            &path_fingerprint,
        ),
        SccmClientDiscoveryState::Capped => marker_id(
            &candidate.catalog_entry_id,
            SccmManifestSourceState::Capped,
            &candidate.observation.rotation,
            &candidate.observation.basename,
            &path_fingerprint,
        ),
    };
    SccmClientDiscoveryDeclaration {
        evidence_identity: evidence_id(
            &candidate.catalog_entry_id,
            &candidate.source_digest,
            &candidate.observation.rotation,
            &candidate.observation.basename,
        ),
        catalog_entry_id: candidate.catalog_entry_id,
        logical_artifact_ids: candidate.logical_artifact_ids,
        artifact_id,
        path_fingerprint,
        root_handle: candidate.observation.root_handle,
        basename: candidate.observation.basename,
        rotation: candidate.observation.rotation,
        state,
    }
}

fn marker_id(
    catalog_entry_id: &str,
    state: SccmManifestSourceState,
    rotation: &SccmRotation,
    basename: &str,
    path_fingerprint: &str,
) -> String {
    expected_marker_artifact_id(
        catalog_entry_id,
        state,
        rotation,
        basename,
        Some(path_fingerprint),
    )
}

fn evidence_id(
    catalog_entry_id: &str,
    source_digest: &str,
    rotation: &SccmRotation,
    basename: &str,
) -> String {
    let value = format!(
        "cmtraceopen.sccm.evidence.v1\0{catalog_entry_id}\0{source_digest}\0{}\0{basename}",
        rotation_segment(rotation)
    );
    let digest = Sha256::digest(value.as_bytes());
    format!(
        "sccm-evidence:v1:sha256:{}",
        digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

fn compare_observation_order(
    left: &NormalizedObservation<'_>,
    right: &NormalizedObservation<'_>,
) -> Ordering {
    logical_artifact_ids_for_basename(&left.canonical_basename)
        .cmp(&logical_artifact_ids_for_basename(
            &right.canonical_basename,
        ))
        .then_with(|| {
            left.observation
                .root_handle
                .cmp(&right.observation.root_handle)
        })
        .then_with(|| rotation_order(&left.observation.rotation, &right.observation.rotation))
        .then_with(|| left.observation.basename.cmp(&right.observation.basename))
        .then_with(|| state_rank(left.observation.state).cmp(&state_rank(right.observation.state)))
}

fn state_rank(state: SccmClientDiscoveryObservationState) -> u8 {
    match state {
        SccmClientDiscoveryObservationState::Found => 0,
        SccmClientDiscoveryObservationState::AccessDenied => 1,
        SccmClientDiscoveryObservationState::NotFound => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT_A: &str = "root-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const ROOT_B: &str = "root-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn observation(
        root_handle: &str,
        basename: String,
        rotation: SccmRotation,
    ) -> SccmClientDiscoveryObservation {
        SccmClientDiscoveryObservation {
            root_handle: root_handle.to_owned(),
            basename,
            rotation,
            state: SccmClientDiscoveryObservationState::Found,
        }
    }

    fn construction_counts() -> (usize, usize) {
        (
            CANDIDATE_CONSTRUCTIONS.with(Cell::get),
            DECLARATION_CONSTRUCTIONS.with(Cell::get),
        )
    }

    fn reset_construction_counts() {
        CANDIDATE_CONSTRUCTIONS.with(|count| count.set(0));
        DECLARATION_CONSTRUCTIONS.with(|count| count.set(0));
    }

    fn normalization_count() -> usize {
        NORMALIZATION_OPERATIONS.with(Cell::get)
    }

    fn reset_normalization_count() {
        NORMALIZATION_OPERATIONS.with(|count| count.set(0));
    }

    #[test]
    fn defensive_observation_limit_rejects_before_any_normalization_or_construction() {
        let observations = (1..=MAX_SCCM_CLIENT_DISCOVERY_OBSERVATIONS + 1)
            .map(|number| {
                observation(
                    ROOT_A,
                    format!("AppEnforce.log.{number}"),
                    SccmRotation::Numbered(number as u32),
                )
            })
            .collect();
        let input = SccmClientDiscoveryInput {
            max_found_fragments_per_source: MAX_SCCM_CLIENT_DISCOVERY_DECLARATIONS,
            observations,
        };

        reset_construction_counts();
        reset_normalization_count();
        assert_eq!(
            discover_client_sources(&input),
            Err(SccmClientDiscoveryError::ObservationLimitExceeded),
            "input beyond the defensive discovery contract must fail conservatively"
        );
        assert_eq!(
            normalization_count(),
            0,
            "the defensive limit rejects before any observation is normalized"
        );
        assert_eq!(
            construction_counts(),
            (0, 0),
            "the defensive limit rejects before candidates or declarations are built"
        );
    }

    #[test]
    fn defensive_observation_bound_normalizes_each_all_found_or_mixed_state_input_once() {
        let all_found = (1..=MAX_SCCM_CLIENT_DISCOVERY_OBSERVATIONS)
            .map(|number| {
                observation(
                    ROOT_A,
                    format!("AppEnforce.log.{number}"),
                    SccmRotation::Numbered(number as u32),
                )
            })
            .collect::<Vec<_>>();
        let mixed_states = (1..=MAX_SCCM_CLIENT_DISCOVERY_OBSERVATIONS)
            .map(|number| SccmClientDiscoveryObservation {
                root_handle: if number % 2 == 0 { ROOT_A } else { ROOT_B }.to_owned(),
                basename: format!("PolicyAgent.log.{number}"),
                rotation: SccmRotation::Numbered(number as u32),
                state: match number % 3 {
                    0 => SccmClientDiscoveryObservationState::Found,
                    1 => SccmClientDiscoveryObservationState::AccessDenied,
                    _ => SccmClientDiscoveryObservationState::NotFound,
                },
            })
            .collect::<Vec<_>>();

        for observations in [all_found, mixed_states] {
            reset_construction_counts();
            reset_normalization_count();
            let result = discover_client_sources(&SccmClientDiscoveryInput {
                max_found_fragments_per_source: MAX_SCCM_CLIENT_DISCOVERY_DECLARATIONS,
                observations,
            })
            .expect("the defensive boundary itself remains processable");

            assert_eq!(
                normalization_count(),
                MAX_SCCM_CLIENT_DISCOVERY_OBSERVATIONS,
                "each accepted observation is normalized exactly once"
            );
            assert!(
                result.declarations.len() <= MAX_SCCM_CLIENT_DISCOVERY_DECLARATIONS,
                "the declaration output remains globally bounded"
            );
        }
    }

    #[test]
    fn oversized_discovery_is_rejected_without_constructing_candidates_or_declarations() {
        let mut observations = Vec::new();
        for number in 1..=6_000 {
            observations.push(observation(
                ROOT_A,
                format!("AppEnforce.log.{number}"),
                SccmRotation::Numbered(number),
            ));
            observations.push(observation(
                ROOT_B,
                format!("PolicyAgent.log.{number}"),
                SccmRotation::Numbered(number),
            ));
        }
        let input = SccmClientDiscoveryInput {
            max_found_fragments_per_source: MAX_SCCM_CLIENT_DISCOVERY_DECLARATIONS,
            observations,
        };

        reset_construction_counts();
        reset_normalization_count();
        let error = discover_client_sources(&input)
            .expect_err("inputs outside the defensive contract must be rejected");
        let counts = construction_counts();

        let mut reversed = input.clone();
        reversed.observations.reverse();
        reset_construction_counts();
        reset_normalization_count();
        let reversed_error = discover_client_sources(&reversed)
            .expect_err("input order does not weaken the defensive limit");
        let reversed_counts = construction_counts();

        assert_eq!(
            error, reversed_error,
            "input order must not change conservative overflow behavior"
        );
        for (candidate_constructions, declaration_constructions) in [counts, reversed_counts] {
            assert_eq!(
                (candidate_constructions, declaration_constructions),
                (0, 0),
                "the defensive limit rejects before candidates or declarations are built"
            );
        }
    }

    #[test]
    fn per_source_cap_does_not_let_an_early_noisy_source_starve_later_sources() {
        let mut observations = (1..=MAX_SCCM_CLIENT_DISCOVERY_OBSERVATIONS - 4)
            .map(|number| {
                observation(
                    ROOT_A,
                    format!("AppEnforce.log.{number}"),
                    SccmRotation::Numbered(number as u32),
                )
            })
            .collect::<Vec<_>>();
        observations.splice(
            0..0,
            [
                observation(ROOT_A, "AppEnforce.log".to_owned(), SccmRotation::Current),
                observation(
                    ROOT_A,
                    "AppEnforce.lo_".to_owned(),
                    SccmRotation::LoUnderscore,
                ),
            ],
        );
        observations.push(observation(
            ROOT_B,
            "PolicyAgent.log".to_owned(),
            SccmRotation::Current,
        ));
        observations.push(observation(
            ROOT_B,
            "PolicyAgent.lo_".to_owned(),
            SccmRotation::LoUnderscore,
        ));

        reset_construction_counts();
        let result = discover_client_sources(&SccmClientDiscoveryInput {
            max_found_fragments_per_source: 2,
            observations,
        })
        .expect("valid observations");
        let (candidate_constructions, declaration_constructions) = construction_counts();

        assert_eq!(
            result
                .declarations
                .iter()
                .filter(|declaration| declaration.root_handle == ROOT_A)
                .map(|declaration| (&declaration.rotation, declaration.state))
                .collect::<Vec<_>>(),
            vec![
                (&SccmRotation::Current, SccmClientDiscoveryState::Discovered),
                (
                    &SccmRotation::LoUnderscore,
                    SccmClientDiscoveryState::Discovered
                ),
                (&SccmRotation::Numbered(1), SccmClientDiscoveryState::Capped),
            ]
        );
        assert!(result.declarations.iter().any(|declaration| {
            declaration.root_handle == ROOT_B
                && declaration.rotation == SccmRotation::Current
                && declaration.state == SccmClientDiscoveryState::Discovered
        }));
        assert!(
            result.declarations.len() <= MAX_SCCM_CLIENT_DISCOVERY_DECLARATIONS
                && candidate_constructions <= MAX_SCCM_CLIENT_DISCOVERY_DECLARATIONS
                && declaration_constructions <= MAX_SCCM_CLIENT_DISCOVERY_DECLARATIONS
        );
    }
}
