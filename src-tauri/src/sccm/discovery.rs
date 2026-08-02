//! Read-only normalization of already-observed SCCM client source candidates.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::num::NonZeroU16;

#[cfg(test)]
use std::cell::Cell;

use super::contract::{
    canonical_client_source, catalog_entry_id, expected_marker_artifact_id,
    expected_physical_artifact_id, logical_artifact_ids_for_basename, root_handle_digest,
    rotation_order, rotation_segment, sha256_bytes, source_identity_digest,
    SccmManifestSourceState,
};
use cmtraceopen_parser::sccm::SccmRotation;

pub const MAX_SCCM_CLIENT_DISCOVERY_DECLARATIONS: usize = 4_096;
/// Defensive bound for supplied observations. Native enumeration must report
/// its own truncation as SCCM coverage; this pure normalizer does not silently
/// discard observations beyond the contract.
pub const MAX_SCCM_CLIENT_DISCOVERY_OBSERVATIONS: usize =
    MAX_SCCM_CLIENT_DISCOVERY_DECLARATIONS + 1;
/// Coverage issues are derived only from admitted observations. They remain
/// separately bounded without sharing the declaration budget, so a capture
/// frontier cannot hide coverage loss.
pub const MAX_SCCM_CLIENT_DISCOVERY_COVERAGE_ISSUES: usize = MAX_SCCM_CLIENT_DISCOVERY_OBSERVATIONS;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SccmClientDiscoveryObservationState {
    Found,
    AccessDenied,
    NotFound,
    /// An additive caller-observed state; exhaustive matches must handle it.
    /// Discovery never infers this state from a rejected observation.
    Skipped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SccmClientDiscoveryState {
    Discovered,
    AccessDenied,
    NotFound,
    Capped,
    Skipped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SccmClientDiscoveryCoverageIssueState {
    InvalidProvenance,
    Unsupported,
    /// The bounded declaration output omitted one or more otherwise eligible
    /// observations. This is a capacity fact, not a source-observation state.
    DeclarationLimitExceeded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SccmClientDiscoveryRotationCategory {
    Current,
    LoUnderscore,
    Numbered,
    Timestamped,
    Unknown,
}

/// Coverage-only metadata intentionally kept out of declarations. These
/// issues cannot be captured or interpreted as workflow evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SccmClientDiscoveryCoverageIssue {
    pub artifact_id: String,
    /// A validated catalog identity or the fixed `none` category. It never
    /// derives from an unvalidated basename or root handle.
    pub catalog_entry_id: String,
    /// Rejected observations never assert workflow membership, even when a
    /// privacy-safe catalog identity can still be retained.
    pub logical_artifact_ids: Vec<String>,
    pub rotation_category: SccmClientDiscoveryRotationCategory,
    pub state: SccmClientDiscoveryCoverageIssueState,
    /// Actual declaration state omitted only by the global output bound. This
    /// preserves per-source `Capped` separately from raw input `Found`.
    /// Other issue kinds leave this unset.
    pub omitted_declaration_state: Option<SccmClientDiscoveryState>,
    /// Number of supplied observations represented by this privacy-safe issue
    /// category. The category identity intentionally remains count-independent.
    pub occurrence_count: NonZeroU16,
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
    /// Additive discovery-only diagnostics. Result struct literals must
    /// initialize this field; coverage issues never become capture declarations.
    pub coverage_issues: Vec<SccmClientDiscoveryCoverageIssue>,
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

struct NormalizedObservation<'a> {
    observation: &'a SccmClientDiscoveryObservation,
    canonical_basename: String,
    logical_artifact_ids: Vec<String>,
}

struct NormalizedDiscovery<'a> {
    observations: Vec<NormalizedObservation<'a>>,
    coverage_issue_counts: BTreeMap<CoverageIssueKey, u16>,
}

#[derive(Debug)]
struct RawPhysicalIdentity<'a> {
    /// Raw metadata is borrowed only while the bounded consistency map exists.
    /// Rotation and classification never change this exact physical identity.
    root_handle: &'a str,
    raw_basename: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ObservationDisposition {
    Accepted,
    Rejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ObservationFacts {
    state: SccmClientDiscoveryObservationState,
    disposition: ObservationDisposition,
}

#[derive(Debug)]
struct CanonicalPhysicalIdentity<'a> {
    root_handle: &'a str,
    canonical_basename: String,
    rotation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct CoverageIssueKey {
    catalog_entry_id: String,
    logical_artifact_ids: Vec<String>,
    rotation_category: SccmClientDiscoveryRotationCategory,
    state: SccmClientDiscoveryCoverageIssueState,
    omitted_declaration_state: Option<SccmClientDiscoveryState>,
}

#[cfg(test)]
thread_local! {
    static CANDIDATE_CONSTRUCTIONS: Cell<usize> = const { Cell::new(0) };
    static DECLARATION_CONSTRUCTIONS: Cell<usize> = const { Cell::new(0) };
    static NORMALIZATION_OPERATIONS: Cell<usize> = const { Cell::new(0) };
    static LOGICAL_ARTIFACT_ID_LOOKUPS: Cell<usize> = const { Cell::new(0) };
    static CONSISTENCY_KEY_CONSTRUCTIONS: Cell<usize> = const { Cell::new(0) };
    static CLASSIFIER_INVOCATIONS: Cell<usize> = const { Cell::new(0) };
    static CONSISTENCY_COMPARISONS: Cell<usize> = const { Cell::new(0) };
}

pub fn discover_client_sources(
    input: &SccmClientDiscoveryInput,
) -> Result<SccmClientDiscoveryResult, SccmClientDiscoveryError> {
    if input.observations.len() > MAX_SCCM_CLIENT_DISCOVERY_OBSERVATIONS {
        return Err(SccmClientDiscoveryError::ObservationLimitExceeded);
    }

    let NormalizedDiscovery {
        observations,
        mut coverage_issue_counts,
    } = normalize_observations(input)?;
    let mut found_per_source = BTreeMap::<(String, String), usize>::new();
    let mut capped_sources = BTreeSet::<(String, String)>::new();
    let mut selected = Vec::with_capacity(
        input
            .observations
            .len()
            .min(MAX_SCCM_CLIENT_DISCOVERY_OBSERVATIONS),
    );

    for observation in observations {
        let Some(state) = selection_state(
            &observation,
            input.max_found_fragments_per_source,
            &mut found_per_source,
            &mut capped_sources,
        ) else {
            continue;
        };
        selected.push((observation, state));
    }

    if selected.len() > MAX_SCCM_CLIENT_DISCOVERY_DECLARATIONS {
        let terminal = selected
            .pop()
            .expect("an over-cap selection has a terminal observation");
        for (_, omitted_state) in &selected[MAX_SCCM_CLIENT_DISCOVERY_DECLARATIONS - 1..] {
            add_coverage_issue_count(
                &mut coverage_issue_counts,
                declaration_limit_issue_key(*omitted_state),
                1,
            );
        }
        selected.truncate(MAX_SCCM_CLIENT_DISCOVERY_DECLARATIONS - 1);
        selected.push(terminal);
    }

    let declarations = selected
        .into_iter()
        .map(|(observation, state)| {
            declaration_from_candidate(
                candidate_from_observation(&observation).expect("prevalidated observation"),
                state,
            )
        })
        .collect();
    debug_assert!(coverage_issue_counts.len() <= MAX_SCCM_CLIENT_DISCOVERY_COVERAGE_ISSUES);
    Ok(SccmClientDiscoveryResult {
        declarations,
        coverage_issues: coverage_issue_counts
            .into_iter()
            .map(|(issue, count)| coverage_issue_from_key(issue, count))
            .collect(),
    })
}

impl PartialEq for RawPhysicalIdentity<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for RawPhysicalIdentity<'_> {}

impl PartialOrd for RawPhysicalIdentity<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RawPhysicalIdentity<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        record_consistency_comparison();
        self.root_handle
            .cmp(other.root_handle)
            .then_with(|| self.raw_basename.cmp(other.raw_basename))
    }
}

impl PartialEq for CanonicalPhysicalIdentity<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for CanonicalPhysicalIdentity<'_> {}

impl PartialOrd for CanonicalPhysicalIdentity<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CanonicalPhysicalIdentity<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        record_consistency_comparison();
        self.root_handle
            .cmp(other.root_handle)
            .then_with(|| self.canonical_basename.cmp(&other.canonical_basename))
            .then_with(|| self.rotation.cmp(&other.rotation))
    }
}

fn record_consistency_comparison() {
    #[cfg(test)]
    CONSISTENCY_COMPARISONS.with(|count| count.set(count.get() + 1));
}

fn normalize_observations(
    input: &SccmClientDiscoveryInput,
) -> Result<NormalizedDiscovery<'_>, SccmClientDiscoveryError> {
    let mut physical_facts = BTreeMap::<RawPhysicalIdentity<'_>, ObservationFacts>::new();
    let mut observations =
        BTreeMap::<CanonicalPhysicalIdentity<'_>, NormalizedObservation<'_>>::new();
    let mut coverage_issue_counts = BTreeMap::<CoverageIssueKey, u16>::new();
    for observation in &input.observations {
        #[cfg(test)]
        NORMALIZATION_OPERATIONS.with(|count| count.set(count.get() + 1));
        let root_is_valid = root_handle_digest(&observation.root_handle).is_some();
        let canonical_basename =
            classify_observation_source(&observation.basename, &observation.rotation);
        #[cfg(test)]
        CONSISTENCY_KEY_CONSTRUCTIONS.with(|count| count.set(count.get() + 1));

        let disposition = if root_is_valid && canonical_basename.is_some() {
            ObservationDisposition::Accepted
        } else {
            ObservationDisposition::Rejected
        };
        let facts = ObservationFacts {
            state: observation.state,
            disposition,
        };
        let raw_identity = RawPhysicalIdentity {
            root_handle: &observation.root_handle,
            raw_basename: &observation.basename,
        };
        match physical_facts.entry(raw_identity) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(facts);
            }
            std::collections::btree_map::Entry::Occupied(entry) => {
                if *entry.get() != facts {
                    return Err(SccmClientDiscoveryError::ConflictingObservation);
                }
            }
        }

        match (root_is_valid, canonical_basename) {
            (true, Some(canonical_basename)) => {
                let key = CanonicalPhysicalIdentity {
                    root_handle: &observation.root_handle,
                    canonical_basename: canonical_basename.clone(),
                    rotation: rotation_segment(&observation.rotation),
                };
                let normalized = NormalizedObservation {
                    observation,
                    logical_artifact_ids: logical_artifact_ids(&canonical_basename),
                    canonical_basename,
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
            (root_is_valid, catalog_basename) => {
                let coverage_issue = coverage_issue_key(root_is_valid, catalog_basename.as_deref());
                add_coverage_issue_count(&mut coverage_issue_counts, coverage_issue, 1);
            }
        }
    }
    let mut observations = observations.into_values().collect::<Vec<_>>();
    observations.sort_by(compare_observation_order);
    debug_assert!(coverage_issue_counts.len() <= MAX_SCCM_CLIENT_DISCOVERY_COVERAGE_ISSUES);
    Ok(NormalizedDiscovery {
        observations,
        coverage_issue_counts,
    })
}

fn coverage_issue_key(root_is_valid: bool, catalog_basename: Option<&str>) -> CoverageIssueKey {
    let state = if root_is_valid {
        SccmClientDiscoveryCoverageIssueState::Unsupported
    } else {
        SccmClientDiscoveryCoverageIssueState::InvalidProvenance
    };
    let catalog_entry_id = catalog_basename
        .map(catalog_entry_id)
        .unwrap_or_else(|| "sccm-client-source:v1:none".to_owned());
    CoverageIssueKey {
        catalog_entry_id,
        logical_artifact_ids: Vec::new(),
        rotation_category: SccmClientDiscoveryRotationCategory::Unknown,
        state,
        omitted_declaration_state: None,
    }
}

fn declaration_limit_issue_key(
    omitted_declaration_state: SccmClientDiscoveryState,
) -> CoverageIssueKey {
    CoverageIssueKey {
        catalog_entry_id: "sccm-client-source:v1:none".to_owned(),
        logical_artifact_ids: Vec::new(),
        rotation_category: SccmClientDiscoveryRotationCategory::Unknown,
        state: SccmClientDiscoveryCoverageIssueState::DeclarationLimitExceeded,
        omitted_declaration_state: Some(omitted_declaration_state),
    }
}

fn add_coverage_issue_count(
    counts: &mut BTreeMap<CoverageIssueKey, u16>,
    key: CoverageIssueKey,
    additional_count: usize,
) {
    let additional_count =
        u16::try_from(additional_count).expect("admitted discovery issue count fits in u16");
    let count = counts.entry(key).or_insert(0_u16);
    *count = count
        .checked_add(additional_count)
        .expect("aggregated discovery issue count fits in u16");
}

fn coverage_issue_from_key(
    key: CoverageIssueKey,
    occurrence_count: u16,
) -> SccmClientDiscoveryCoverageIssue {
    let CoverageIssueKey {
        catalog_entry_id,
        logical_artifact_ids,
        rotation_category,
        state,
        omitted_declaration_state,
    } = key;
    let artifact_id = coverage_issue_id(
        &catalog_entry_id,
        rotation_category,
        state,
        omitted_declaration_state,
    );
    SccmClientDiscoveryCoverageIssue {
        artifact_id,
        catalog_entry_id,
        logical_artifact_ids,
        rotation_category,
        state,
        omitted_declaration_state,
        occurrence_count: NonZeroU16::new(occurrence_count)
            .expect("every coverage issue represents an admitted observation"),
    }
}

fn classify_observation_source(basename: &str, rotation: &SccmRotation) -> Option<String> {
    #[cfg(test)]
    CLASSIFIER_INVOCATIONS.with(|count| count.set(count.get() + 1));
    canonical_client_source(basename, rotation)
}

fn coverage_issue_id(
    catalog_entry_id: &str,
    rotation_category: SccmClientDiscoveryRotationCategory,
    state: SccmClientDiscoveryCoverageIssueState,
    omitted_declaration_state: Option<SccmClientDiscoveryState>,
) -> String {
    let rotation = match rotation_category {
        SccmClientDiscoveryRotationCategory::Current => "current",
        SccmClientDiscoveryRotationCategory::LoUnderscore => "lo",
        SccmClientDiscoveryRotationCategory::Numbered => "numbered",
        SccmClientDiscoveryRotationCategory::Timestamped => "timestamped",
        SccmClientDiscoveryRotationCategory::Unknown => "unknown",
    };
    let state = match state {
        SccmClientDiscoveryCoverageIssueState::InvalidProvenance => "invalid-provenance",
        SccmClientDiscoveryCoverageIssueState::Unsupported => "unsupported",
        SccmClientDiscoveryCoverageIssueState::DeclarationLimitExceeded => {
            "declaration-limit-exceeded"
        }
    };
    let omitted_state = omitted_declaration_state.map(|state| match state {
        SccmClientDiscoveryState::Discovered => "discovered",
        SccmClientDiscoveryState::AccessDenied => "access-denied",
        SccmClientDiscoveryState::NotFound => "not-found",
        SccmClientDiscoveryState::Capped => "capped",
        SccmClientDiscoveryState::Skipped => "skipped",
    });
    let value = match omitted_state {
        Some(omitted_state) => format!(
            "cmtraceopen.sccm.discovery.coverage.v1\\0{catalog_entry_id}\\0{rotation}\\0{state}\\0{omitted_state}"
        ),
        None => format!(
            "cmtraceopen.sccm.discovery.coverage.v1\\0{catalog_entry_id}\\0{rotation}\\0{state}"
        ),
    };
    format!(
        "sccm-discovery-coverage:v1:sha256:{}",
        sha256_bytes(value.as_bytes())
    )
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
        SccmClientDiscoveryObservationState::Skipped => SccmClientDiscoveryState::Skipped,
    })
}

fn candidate_from_observation(observation: &NormalizedObservation<'_>) -> Option<Candidate> {
    #[cfg(test)]
    CANDIDATE_CONSTRUCTIONS.with(|count| count.set(count.get() + 1));
    let source_digest = source_identity_digest(
        &observation.observation.root_handle,
        &observation.canonical_basename,
    )?;

    let mut physical_observation = observation.observation.clone();
    physical_observation.basename = physical_basename(
        &observation.canonical_basename,
        &physical_observation.rotation,
    );
    Some(Candidate {
        observation: physical_observation,
        catalog_entry_id: catalog_entry_id(&observation.canonical_basename),
        logical_artifact_ids: observation.logical_artifact_ids.clone(),
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
        SccmClientDiscoveryState::Skipped => marker_id(
            &candidate.catalog_entry_id,
            SccmManifestSourceState::Skipped,
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
    format!("sccm-evidence:v1:sha256:{}", sha256_bytes(value.as_bytes()))
}

fn compare_observation_order(
    left: &NormalizedObservation<'_>,
    right: &NormalizedObservation<'_>,
) -> Ordering {
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

fn logical_artifact_ids(canonical_basename: &str) -> Vec<String> {
    #[cfg(test)]
    LOGICAL_ARTIFACT_ID_LOOKUPS.with(|count| count.set(count.get() + 1));
    logical_artifact_ids_for_basename(canonical_basename)
}

fn physical_basename(canonical_basename: &str, rotation: &SccmRotation) -> String {
    match rotation {
        SccmRotation::Current => canonical_basename.to_owned(),
        SccmRotation::LoUnderscore => {
            let stem = canonical_basename
                .strip_suffix(".log")
                .expect("prevalidated lo_ rotation has a canonical log basename");
            format!("{stem}.lo_")
        }
        SccmRotation::Numbered(number) => format!("{canonical_basename}.{number}"),
        SccmRotation::Timestamped(timestamp) => format!("{canonical_basename}.{timestamp}"),
        SccmRotation::Unknown(_) => unreachable!("supported observation has a known rotation"),
    }
}

fn state_rank(state: SccmClientDiscoveryObservationState) -> u8 {
    match state {
        SccmClientDiscoveryObservationState::Found => 0,
        SccmClientDiscoveryObservationState::AccessDenied => 1,
        SccmClientDiscoveryObservationState::NotFound => 2,
        SccmClientDiscoveryObservationState::Skipped => 3,
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

    fn logical_artifact_id_lookup_count() -> usize {
        LOGICAL_ARTIFACT_ID_LOOKUPS.with(Cell::get)
    }

    fn reset_logical_artifact_id_lookup_count() {
        LOGICAL_ARTIFACT_ID_LOOKUPS.with(|count| count.set(0));
    }

    fn consistency_key_count() -> usize {
        CONSISTENCY_KEY_CONSTRUCTIONS.with(Cell::get)
    }

    fn reset_consistency_key_count() {
        CONSISTENCY_KEY_CONSTRUCTIONS.with(|count| count.set(0));
    }

    fn classifier_invocation_count() -> usize {
        CLASSIFIER_INVOCATIONS.with(Cell::get)
    }

    fn consistency_comparison_count() -> usize {
        CONSISTENCY_COMPARISONS.with(Cell::get)
    }

    fn reset_classification_work_counts() {
        CLASSIFIER_INVOCATIONS.with(|count| count.set(0));
        CONSISTENCY_COMPARISONS.with(|count| count.set(0));
    }

    fn comparison_budget(observation_count: usize) -> usize {
        let log_bound =
            usize::BITS as usize - observation_count.saturating_sub(1).leading_zeros() as usize;
        observation_count
            .saturating_mul(log_bound.saturating_add(2))
            .saturating_mul(4)
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
        reset_consistency_key_count();
        reset_classification_work_counts();
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
        assert_eq!(
            consistency_key_count(),
            0,
            "the defensive limit rejects before ephemeral consistency keys are built"
        );
        assert_eq!(classifier_invocation_count(), 0);
        assert_eq!(consistency_comparison_count(), 0);
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
            reset_consistency_key_count();
            reset_classification_work_counts();
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
            assert_eq!(
                consistency_key_count(),
                MAX_SCCM_CLIENT_DISCOVERY_OBSERVATIONS,
                "the bounded consistency pass builds exactly one borrowed key per observation"
            );
            assert_eq!(
                classifier_invocation_count(),
                MAX_SCCM_CLIENT_DISCOVERY_OBSERVATIONS,
                "every admitted observation is classified at most once"
            );
            assert!(
                consistency_comparison_count()
                    <= comparison_budget(MAX_SCCM_CLIENT_DISCOVERY_OBSERVATIONS),
                "consistency work must remain O(n log n): {} comparisons exceeded {}",
                consistency_comparison_count(),
                comparison_budget(MAX_SCCM_CLIENT_DISCOVERY_OBSERVATIONS),
            );
            assert!(
                result.declarations.len() <= MAX_SCCM_CLIENT_DISCOVERY_DECLARATIONS,
                "the declaration output remains globally bounded"
            );
        }
    }

    #[test]
    fn normalization_caches_logical_artifact_ids_once_per_observation_despite_sorting() {
        let observations = (1..=64)
            .map(|number| {
                observation(
                    ROOT_A,
                    format!("AppEnforce.log.{number}"),
                    SccmRotation::Numbered(number),
                )
            })
            .collect::<Vec<_>>();

        reset_logical_artifact_id_lookup_count();
        discover_client_sources(&SccmClientDiscoveryInput {
            max_found_fragments_per_source: 64,
            observations,
        })
        .expect("accepted observations normalize deterministically");

        assert_eq!(
            logical_artifact_id_lookup_count(),
            64,
            "sorting and declaration construction must reuse each normalized observation's cached logical IDs"
        );
    }

    #[test]
    fn rejected_duplicate_boundary_has_bounded_classification_and_consistency_work() {
        let observations = (0..MAX_SCCM_CLIENT_DISCOVERY_OBSERVATIONS)
            .map(|_| SccmClientDiscoveryObservation {
                root_handle: "unvalidated-root".to_owned(),
                basename: "Unrelated.log.backup".to_owned(),
                rotation: SccmRotation::Unknown(cmtraceopen_parser::sccm::SccmUnknownRotation {
                    kind: "filenameSuffix".to_owned(),
                    value: Some(serde_json::Value::String(".backup".to_owned())),
                }),
                state: SccmClientDiscoveryObservationState::Found,
            })
            .collect();

        reset_classification_work_counts();
        let result = discover_client_sources(&SccmClientDiscoveryInput {
            max_found_fragments_per_source: MAX_SCCM_CLIENT_DISCOVERY_DECLARATIONS,
            observations,
        })
        .expect("same-state rejected duplicates remain countable at the admission boundary");

        assert!(result.declarations.is_empty());
        assert_eq!(result.coverage_issues.len(), 1);
        assert_eq!(
            result.coverage_issues[0].occurrence_count.get() as usize,
            MAX_SCCM_CLIENT_DISCOVERY_OBSERVATIONS
        );
        assert!(
            consistency_comparison_count()
                <= comparison_budget(MAX_SCCM_CLIENT_DISCOVERY_OBSERVATIONS),
            "rejected consistency work must remain O(n log n): {} comparisons exceeded {}",
            consistency_comparison_count(),
            comparison_budget(MAX_SCCM_CLIENT_DISCOVERY_OBSERVATIONS),
        );
        assert_eq!(
            classifier_invocation_count(),
            MAX_SCCM_CLIENT_DISCOVERY_OBSERVATIONS,
            "every rejected observation is classified at most once"
        );
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
