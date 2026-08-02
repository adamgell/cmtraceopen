//! Read-only normalization of already-observed SCCM client source candidates.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

#[cfg(test)]
use std::cell::Cell;

use cmtraceopen_parser::sccm::SccmRotation;
use sha2::{Digest, Sha256};

use super::contract::{
    canonical_client_source, catalog_entry_id, expected_marker_artifact_id,
    expected_physical_artifact_id, logical_artifact_ids_for_basename, rotation_order,
    rotation_segment, source_identity_digest, SccmManifestSourceState,
};

pub const MAX_SCCM_CLIENT_DISCOVERY_DECLARATIONS: usize = 4_096;

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

struct Candidate {
    observation: SccmClientDiscoveryObservation,
    catalog_entry_id: String,
    logical_artifact_ids: Vec<String>,
    source_digest: String,
}

#[cfg(test)]
thread_local! {
    static CANDIDATE_CONSTRUCTIONS: Cell<usize> = const { Cell::new(0) };
    static DECLARATION_CONSTRUCTIONS: Cell<usize> = const { Cell::new(0) };
}

pub fn discover_client_sources(input: &SccmClientDiscoveryInput) -> SccmClientDiscoveryResult {
    let mut candidates = input
        .observations
        .iter()
        .filter_map(candidate_from_observation)
        .collect::<Vec<_>>();
    candidates.sort_by(compare_candidates);

    let mut found_per_source = BTreeMap::<String, usize>::new();
    let mut capped_sources = BTreeSet::<String>::new();
    let mut declarations = Vec::new();
    for candidate in candidates {
        let source_key = format!(
            "{}:{}",
            candidate.observation.root_handle, candidate.source_digest
        );
        let state = match candidate.observation.state {
            SccmClientDiscoveryObservationState::Found => {
                let count = found_per_source.entry(source_key.clone()).or_default();
                if *count < input.max_found_fragments_per_source {
                    *count += 1;
                    SccmClientDiscoveryState::Discovered
                } else if capped_sources.insert(source_key) {
                    SccmClientDiscoveryState::Capped
                } else {
                    continue;
                }
            }
            SccmClientDiscoveryObservationState::AccessDenied => {
                SccmClientDiscoveryState::AccessDenied
            }
            SccmClientDiscoveryObservationState::NotFound => SccmClientDiscoveryState::NotFound,
        };
        declarations.push(declaration_from_candidate(candidate, state));
    }

    if declarations.len() > MAX_SCCM_CLIENT_DISCOVERY_DECLARATIONS {
        let first_omitted = declarations[MAX_SCCM_CLIENT_DISCOVERY_DECLARATIONS - 1].clone();
        declarations.truncate(MAX_SCCM_CLIENT_DISCOVERY_DECLARATIONS - 1);
        declarations.push(SccmClientDiscoveryDeclaration {
            state: SccmClientDiscoveryState::Capped,
            artifact_id: marker_id(
                &first_omitted.catalog_entry_id,
                SccmManifestSourceState::Capped,
                &first_omitted.rotation,
                &first_omitted.basename,
                &first_omitted.path_fingerprint,
            ),
            ..first_omitted
        });
    }
    SccmClientDiscoveryResult { declarations }
}

fn candidate_from_observation(observation: &SccmClientDiscoveryObservation) -> Option<Candidate> {
    let canonical = canonical_client_source(&observation.basename, &observation.rotation)?;
    #[cfg(test)]
    CANDIDATE_CONSTRUCTIONS.with(|count| count.set(count.get() + 1));
    let source_digest = source_identity_digest(&observation.root_handle, &canonical)?;

    Some(Candidate {
        observation: observation.clone(),
        catalog_entry_id: catalog_entry_id(&canonical),
        logical_artifact_ids: logical_artifact_ids_for_basename(&canonical),
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

fn compare_candidates(left: &Candidate, right: &Candidate) -> Ordering {
    left.logical_artifact_ids
        .cmp(&right.logical_artifact_ids)
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

    #[test]
    fn oversized_discovery_constructs_only_the_bounded_retained_candidates_and_declarations() {
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
        let result = discover_client_sources(&input).expect("valid observations");
        let counts = construction_counts();

        let mut reversed = input.clone();
        reversed.observations.reverse();
        reset_construction_counts();
        let reversed_result = discover_client_sources(&reversed).expect("valid observations");
        let reversed_counts = construction_counts();

        assert_eq!(
            result, reversed_result,
            "input order must not change the result"
        );
        assert!(
            result.declarations.len() <= MAX_SCCM_CLIENT_DISCOVERY_DECLARATIONS,
            "the global result remains bounded"
        );
        for (candidate_constructions, declaration_constructions) in [counts, reversed_counts] {
            assert!(
                candidate_constructions <= MAX_SCCM_CLIENT_DISCOVERY_DECLARATIONS,
                "candidate construction must stop at the retained global budget"
            );
            assert!(
                declaration_constructions <= MAX_SCCM_CLIENT_DISCOVERY_DECLARATIONS,
                "declaration and identity construction must stop at the retained global budget"
            );
        }
    }

    #[test]
    fn per_source_cap_does_not_let_an_early_noisy_source_starve_later_sources() {
        let mut observations = (1..=6_000)
            .map(|number| {
                observation(
                    ROOT_A,
                    format!("AppEnforce.log.{number}"),
                    SccmRotation::Numbered(number),
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
