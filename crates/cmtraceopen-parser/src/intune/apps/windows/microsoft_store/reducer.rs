//! Reduction of classified Store observations into keyed transactions.
//!
//! Two observations join a transaction only when all three of the following
//! hold:
//!
//! 1. their package identities share a normalized correlation token
//!    (package family name, package full name, or Store product id);
//! 2. their execution contexts are compatible;
//! 3. their installer families are compatible.
//!
//! Display name, timestamp proximity, and "it was the only other Store record in
//! the bundle" are explicitly not joins. Rule 3 is what keeps a Store-delivered
//! Win32 package from inheriting AppX terminal semantics, and rule 2 is what
//! keeps a per-user registration from being closed out by a machine-wide
//! provisioning event.
//!
//! A shared Intune app id alone is an Intune-level association, not a package
//! join (ADR-002): it may group observations only while neither side claims a
//! package identity, so an identity-free record can never be merged into a
//! package-identified transaction or drive a package-specific terminal outcome.
//!
//! An observation carrying no correlation token stays unkeyed. It remains
//! visible in [`StoreAnalysis::unkeyed_observations`] and can never terminate
//! somebody else's transaction.

use crate::intune::evidence::{
    IntuneAccessState, IntuneArtifactCoverage, IntuneArtifactStatus, IntuneErrorCode,
    IntuneEvidenceRef, IntuneFindingConfidence, IntuneNamedValue, IntuneObservationContext,
    IntuneParseState, IntuneProvenance, IntuneSensitivity, IntuneTimestamp, IntuneTimestampKind,
};
use crate::intune::ime_parser::{parse_ime_content, ImeLine};

use super::findings::derive_findings;
use super::models::{
    StoreAnalysis, StoreArtifactPayload, StoreAssignment, StoreAssignmentIntent,
    StoreDeploymentAction, StoreEvidenceOrigin, StoreExecutionContext, StoreFamilyBasis,
    StoreInstallerFamily, StoreInstallerOutcome, StoreObservation, StorePackageFact,
    StorePackageIdentity, StorePhase, StoreSignal, StoreSourceArtifact, StoreTransaction,
    StoreTransactionState, MICROSOFT_STORE_SCHEMA_VERSION,
};
use super::rules::{classify_event, classify_ime_record, StoreClassification};
use super::sources::{classify_text_artifact, StoreTextSource};

/// Reduce a supplied Store app bundle into transactions, coverage, and findings.
///
/// The bundle is pure input: the caller has already read, decoded, and
/// normalized every artifact. Artifacts that could not be collected are still
/// declared, and become coverage rather than silence.
pub fn analyze_store_bundle(artifacts: &[StoreSourceArtifact]) -> StoreAnalysis {
    let mut observations: Vec<StoreObservation> = Vec::new();

    for artifact in artifacts {
        collect_from_artifact(artifact, &mut observations);
    }

    let groups = group_observations(&observations);
    let transactions = groups
        .iter()
        .enumerate()
        .map(|(index, group)| reduce_group(index, group, &observations))
        .collect::<Vec<_>>();

    let keyed: Vec<bool> = {
        let mut keyed = vec![false; observations.len()];
        for group in &groups {
            for &index in group {
                keyed[index] = true;
            }
        }
        keyed
    };
    let unkeyed_observations = observations
        .iter()
        .zip(&keyed)
        .filter(|(observation, keyed)| !**keyed && observation.signal != StoreSignal::Unclassified)
        .map(|(observation, _)| observation.observation_id.clone())
        .collect();

    let coverage = build_coverage(artifacts, &observations);

    let mut analysis = StoreAnalysis {
        schema_version: MICROSOFT_STORE_SCHEMA_VERSION,
        transactions,
        observations,
        unkeyed_observations,
        coverage,
        findings: Vec::new(),
    };
    analysis.findings = derive_findings(&analysis);
    analysis
}

// ── Observation extraction ──────────────────────────────────────────────────

fn access_state_for(status: &IntuneArtifactStatus) -> IntuneAccessState {
    match status {
        IntuneArtifactStatus::Available => IntuneAccessState::Available,
        IntuneArtifactStatus::Missing => IntuneAccessState::Missing,
        IntuneArtifactStatus::PermissionDenied => IntuneAccessState::PermissionDenied,
        IntuneArtifactStatus::Capped => IntuneAccessState::Capped,
        IntuneArtifactStatus::Skipped => IntuneAccessState::Skipped,
        IntuneArtifactStatus::ParseFailed => IntuneAccessState::Failed,
        IntuneArtifactStatus::Unsupported => IntuneAccessState::Unsupported,
    }
}

fn collect_from_artifact(artifact: &StoreSourceArtifact, observations: &mut Vec<StoreObservation>) {
    let Some(payload) = &artifact.payload else {
        return;
    };
    match payload {
        StoreArtifactPayload::ImeText { text } => {
            collect_from_ime_text(artifact, text, observations)
        }
        StoreArtifactPayload::WindowsEvents { events } => {
            for event in events {
                let classification = classify_event(event);
                if !classification.recognized {
                    // Not a Store or AppX source. Letting it through would
                    // manufacture a transaction out of an unrelated provider
                    // that happened to name a package.
                    continue;
                }
                push_observation(
                    observations,
                    event.context.clone(),
                    StoreEvidenceOrigin::WindowsEvent,
                    classification,
                    event.message.clone(),
                    event.named_data.clone(),
                );
            }
        }
        StoreArtifactPayload::PackageFacts { facts } => {
            for fact in facts {
                collect_from_fact(fact, observations);
            }
        }
        StoreArtifactPayload::Assignments { assignments } => {
            for assignment in assignments {
                collect_from_assignment(assignment, observations);
            }
        }
        StoreArtifactPayload::InstallerOutcomes { outcomes } => {
            for outcome in outcomes {
                collect_from_installer_outcome(outcome, observations);
            }
        }
    }
}

/// Build an observation context for a CCM record read out of a text artifact.
fn ime_context(
    artifact: &StoreSourceArtifact,
    record: &ImeLine,
    record_number: u64,
    parse_state: IntuneParseState,
) -> IntuneObservationContext {
    IntuneObservationContext {
        evidence_ref: IntuneEvidenceRef {
            evidence_id: format!("{}:{record_number}", artifact.artifact_id),
            source_artifact_id: artifact.artifact_id.clone(),
        },
        provenance: IntuneProvenance {
            source_kind: artifact.source_kind.clone(),
            source_artifact_id: artifact.artifact_id.clone(),
            file_path: artifact.file_path.clone(),
            line_number: Some(u64::from(record.line_number)),
            record_number: Some(record_number),
            registry: None,
            event: None,
        },
        source_timestamp: record.timestamp.as_ref().map(|raw| IntuneTimestamp {
            raw_text: raw.clone(),
            original_offset: record.timezone_offset.map(format_offset),
            // Only an offset the record stated itself can produce a
            // source-accurate UTC value. Without one, `timestamp_utc` is derived
            // from the parsing machine's timezone and is not evidence.
            normalized_utc: record
                .timezone_offset
                .and_then(|_| record.timestamp_utc.clone()),
            kind: match record.timezone_offset {
                Some(_) => IntuneTimestampKind::Offset,
                None => IntuneTimestampKind::Unspecified,
            },
        }),
        observed_at_utc: artifact.observed_at_utc.clone(),
        // IME records quote package paths and app display names.
        sensitivity: IntuneSensitivity::Sensitive,
        parse_state,
        access_state: access_state_for(&artifact.status),
    }
}

fn format_offset(minutes: i32) -> String {
    let sign = if minutes < 0 { '-' } else { '+' };
    let absolute = minutes.unsigned_abs();
    format!("{sign}{:02}:{:02}", absolute / 60, absolute % 60)
}

fn collect_from_ime_text(
    artifact: &StoreSourceArtifact,
    text: &str,
    observations: &mut Vec<StoreObservation>,
) {
    let records = parse_ime_content(text);
    let source = classify_text_artifact(artifact.file_name.as_deref(), &records);
    if source == StoreTextSource::Unknown {
        // Unconfirmed: the artifact stays in coverage, but nothing inside it is
        // allowed to become evidence.
        return;
    }

    for (index, record) in records.iter().enumerate() {
        let classification = classify_ime_record(&record.message);
        if classification.signal == StoreSignal::Unclassified && classification.identity.is_empty()
        {
            continue;
        }
        let record_number = index as u64 + 1;
        let parse_state = if classification.signal == StoreSignal::Unclassified {
            IntuneParseState::Raw
        } else {
            IntuneParseState::Parsed
        };
        let context = ime_context(artifact, record, record_number, parse_state);
        push_observation(
            observations,
            context,
            StoreEvidenceOrigin::IntuneManagementExtension,
            classification,
            Some(record.message.clone()),
            Vec::new(),
        );
    }
}

fn collect_from_fact(fact: &StorePackageFact, observations: &mut Vec<StoreObservation>) {
    let classification = StoreClassification {
        signal: if fact.installed {
            StoreSignal::PackageInstalledFact
        } else {
            StoreSignal::PackageAbsentFact
        },
        identity: fact.identity.clone(),
        app_id: None,
        execution_context: fact.execution_context,
        action: StoreDeploymentAction::Unknown,
        installer_family: fact.installer_family,
        family_declared: fact.installer_family != StoreInstallerFamily::Unknown,
        typed_intent: None,
        error: None,
        unknown_version: false,
        recognized: true,
    };
    push_observation(
        observations,
        fact.context.clone(),
        StoreEvidenceOrigin::PackageInventory,
        classification,
        None,
        fact.named_data.clone(),
    );
}

fn collect_from_assignment(assignment: &StoreAssignment, observations: &mut Vec<StoreObservation>) {
    let classification = StoreClassification {
        signal: match assignment.intent {
            StoreAssignmentIntent::NotTargeted => StoreSignal::Unclassified,
            _ => StoreSignal::TargetedByIntune,
        },
        identity: assignment.identity.clone(),
        app_id: assignment.app_id.clone(),
        execution_context: assignment.target_context,
        action: match assignment.intent {
            StoreAssignmentIntent::Uninstall => StoreDeploymentAction::Uninstall,
            StoreAssignmentIntent::Required | StoreAssignmentIntent::Available => {
                StoreDeploymentAction::Install
            }
            _ => StoreDeploymentAction::Unknown,
        },
        installer_family: StoreInstallerFamily::Unknown,
        family_declared: false,
        // The typed field is the only authority for intent. Caller-supplied
        // named_data on this or any other observation stays visible as raw
        // metadata but can never state or override an intent (ADR-001).
        typed_intent: Some(assignment.intent),
        error: None,
        unknown_version: false,
        recognized: true,
    };
    push_observation(
        observations,
        assignment.context.clone(),
        StoreEvidenceOrigin::IntuneAssignment,
        classification,
        None,
        assignment.named_data.clone(),
    );
}

fn collect_from_installer_outcome(
    outcome: &StoreInstallerOutcome,
    observations: &mut Vec<StoreObservation>,
) {
    let signal = match outcome.succeeded {
        Some(true) => StoreSignal::Win32InstallerCompleted,
        Some(false) => StoreSignal::Win32InstallerFailed,
        None => StoreSignal::Unclassified,
    };
    let classification = StoreClassification {
        signal,
        identity: outcome.identity.clone(),
        app_id: outcome.app_id.clone(),
        execution_context: StoreExecutionContext::Unknown,
        action: outcome.action,
        // Installer-native evidence exists only for a Store-delivered Win32
        // package; that is what makes it installer-native.
        installer_family: StoreInstallerFamily::StoreWin32,
        family_declared: true,
        typed_intent: None,
        error: outcome.exit_code.clone(),
        unknown_version: false,
        recognized: true,
    };
    push_observation(
        observations,
        outcome.context.clone(),
        StoreEvidenceOrigin::InstallerNative,
        classification,
        None,
        outcome.named_data.clone(),
    );
}

/// The observation id, which is the evidence id it was built from.
///
/// Giving an observation its own numbering scheme meant one record answered to
/// two different ids, which is a needless trap for anyone cross-referencing a
/// finding against a log. A caller that supplies a duplicate evidence id gets a
/// disambiguating suffix rather than a silently dropped observation.
fn unique_observation_id(observations: &[StoreObservation], evidence_id: &str) -> String {
    let taken = |candidate: &str| {
        observations
            .iter()
            .any(|existing| existing.observation_id == candidate)
    };
    if !taken(evidence_id) {
        return evidence_id.to_owned();
    }
    let mut suffix = 2u32;
    loop {
        let candidate = format!("{evidence_id}#{suffix}");
        if !taken(&candidate) {
            return candidate;
        }
        suffix += 1;
    }
}

fn push_observation(
    observations: &mut Vec<StoreObservation>,
    context: IntuneObservationContext,
    origin: StoreEvidenceOrigin,
    classification: StoreClassification,
    message: Option<String>,
    named_data: Vec<IntuneNamedValue>,
) {
    let observation_id = unique_observation_id(observations, &context.evidence_ref.evidence_id);
    observations.push(StoreObservation {
        observation_id,
        context,
        origin,
        signal: classification.signal,
        installer_family: classification.installer_family,
        family_basis: if classification.family_declared {
            StoreFamilyBasis::Declared
        } else {
            StoreFamilyBasis::Unvalidated
        },
        identity: classification.identity,
        app_id: classification.app_id,
        execution_context: classification.execution_context,
        action: classification.action,
        typed_intent: classification.typed_intent,
        error: classification.error,
        unknown_version: classification.unknown_version,
        named_data,
        message,
    });
}

// ── Grouping ────────────────────────────────────────────────────────────────

/// A transaction under construction.
struct Group {
    tokens: Vec<String>,
    app_ids: Vec<String>,
    execution_context: StoreExecutionContext,
    installer_family: StoreInstallerFamily,
    members: Vec<usize>,
}

/// The `kind:` prefix of a normalized correlation token.
fn token_kind(token: &str) -> &str {
    token.split_once(':').map_or(token, |(kind, _)| kind)
}

/// Whether two identities state the same kind of identifier with different values.
///
/// This is what stops an Intune app id from joining two demonstrably different
/// packages: sharing an app id is an Intune-level correlation, and it can never
/// override the package identifiers actually disagreeing.
fn identities_conflict(left: &[String], right: &[String]) -> bool {
    left.iter().any(|token| {
        right
            .iter()
            .any(|other| token_kind(token) == token_kind(other) && token != other)
    })
}

/// Whether an observation may join a group.
///
/// A shared package correlation token is a join. A shared Intune app id alone
/// is not: per ADR-002 it is an Intune-level association, at most weak or
/// moderate, so it may only group observations while *neither* side claims a
/// package identity. An identity-free record must never be merged into a
/// package-identified transaction (where its terminal signal would become a
/// package-specific conclusion), and a package-identified record must never
/// donate its identity to a group built from identity-free evidence.
fn joinable(group: &Group, tokens: &[String], app_id: Option<&String>) -> bool {
    if identities_conflict(tokens, &group.tokens) {
        return false;
    }
    if tokens.iter().any(|token| group.tokens.contains(token)) {
        return true;
    }
    app_id.is_some_and(|app| group.app_ids.contains(app))
        && tokens.is_empty()
        && group.tokens.is_empty()
}

/// Partition observations into transaction groups.
///
/// Runs in two passes. Observations that *declare* an installer family are
/// placed first, so the groups exist before the ambiguous records are assigned;
/// without that, whether an IME intent record landed on the per-user or the
/// provisioned transaction depended on which artifact the caller happened to
/// supply first. Members and groups are then returned in source order, so
/// transaction ids and cited evidence do not depend on the pass an observation
/// was placed in.
fn group_observations(observations: &[StoreObservation]) -> Vec<Vec<usize>> {
    let mut groups: Vec<Group> = Vec::new();

    for declared_pass in [true, false] {
        for (index, observation) in observations.iter().enumerate() {
            let declares_family = observation.installer_family != StoreInstallerFamily::Unknown;
            if declares_family != declared_pass {
                continue;
            }

            let tokens = observation.identity.correlation_tokens();
            let app_id = observation
                .app_id
                .as_ref()
                .map(|app| app.to_ascii_lowercase());
            if tokens.is_empty() && app_id.is_none() {
                continue;
            }

            let matched = groups.iter_mut().find(|group| {
                joinable(group, &tokens, app_id.as_ref())
                    && group
                        .execution_context
                        .is_compatible_with(observation.execution_context)
                    && group
                        .installer_family
                        .is_compatible_with(observation.installer_family)
            });

            match matched {
                Some(group) => {
                    for token in tokens {
                        if !group.tokens.contains(&token) {
                            group.tokens.push(token);
                        }
                    }
                    if let Some(app) = app_id {
                        if !group.app_ids.contains(&app) {
                            group.app_ids.push(app);
                        }
                    }
                    if group.execution_context == StoreExecutionContext::Unknown {
                        group.execution_context = observation.execution_context;
                    }
                    if group.installer_family == StoreInstallerFamily::Unknown {
                        group.installer_family = observation.installer_family;
                    }
                    group.members.push(index);
                }
                None => groups.push(Group {
                    tokens,
                    app_ids: app_id.into_iter().collect(),
                    execution_context: observation.execution_context,
                    installer_family: observation.installer_family,
                    members: vec![index],
                }),
            }
        }
    }

    let mut members = groups
        .into_iter()
        .map(|group| {
            let mut members = group.members;
            members.sort_unstable();
            members
        })
        .collect::<Vec<_>>();
    members.sort_by_key(|group| group.first().copied().unwrap_or(usize::MAX));
    members
}

// ── Reduction ───────────────────────────────────────────────────────────────

fn phase_for(signal: StoreSignal) -> Option<StorePhase> {
    match signal {
        StoreSignal::TargetedByIntune => Some(StorePhase::Targeted),
        StoreSignal::NotApplicable => Some(StorePhase::Applicability),
        StoreSignal::AcquisitionRequested
        | StoreSignal::LicenseAcquired
        | StoreSignal::LicenseFailed => Some(StorePhase::Acquisition),
        StoreSignal::Win32HandoffStarted => Some(StorePhase::HandedOff),
        StoreSignal::Win32InstallerCompleted | StoreSignal::Win32InstallerFailed => {
            Some(StorePhase::Reported)
        }
        StoreSignal::DeploymentStarted => Some(StorePhase::Download),
        StoreSignal::StagingCompleted | StoreSignal::StagingFailed => Some(StorePhase::Staging),
        StoreSignal::RegistrationCompleted
        | StoreSignal::RegistrationFailed
        | StoreSignal::RemovalCompleted
        | StoreSignal::RemovalFailed
        | StoreSignal::NoInteractiveUser => Some(StorePhase::Registration),
        StoreSignal::ProvisioningCompleted | StoreSignal::ProvisioningFailed => {
            Some(StorePhase::Provisioning)
        }
        StoreSignal::PackageInstalledFact | StoreSignal::PackageAbsentFact => {
            Some(StorePhase::Reported)
        }
        StoreSignal::RetryScheduled | StoreSignal::Unclassified => None,
    }
}

fn state_for(signal: StoreSignal) -> Option<StoreTransactionState> {
    match signal {
        StoreSignal::TargetedByIntune | StoreSignal::DeploymentStarted => None,
        StoreSignal::NotApplicable => Some(StoreTransactionState::NotApplicable),
        StoreSignal::AcquisitionRequested | StoreSignal::LicenseAcquired => {
            Some(StoreTransactionState::AcquisitionRequested)
        }
        StoreSignal::LicenseFailed => Some(StoreTransactionState::LicenseFailure),
        StoreSignal::StagingCompleted => None,
        StoreSignal::StagingFailed => Some(StoreTransactionState::DownloadFailure),
        StoreSignal::RegistrationCompleted => Some(StoreTransactionState::InstallCompleted),
        StoreSignal::RegistrationFailed => Some(StoreTransactionState::RegistrationFailure),
        StoreSignal::ProvisioningCompleted => Some(StoreTransactionState::InstallCompleted),
        StoreSignal::ProvisioningFailed => Some(StoreTransactionState::ProvisioningFailure),
        StoreSignal::RemovalCompleted => Some(StoreTransactionState::UninstallCompleted),
        StoreSignal::RemovalFailed => Some(StoreTransactionState::UninstallFailure),
        StoreSignal::NoInteractiveUser => Some(StoreTransactionState::NoInteractiveUser),
        StoreSignal::Win32HandoffStarted => Some(StoreTransactionState::StoreWin32Handoff),
        StoreSignal::Win32InstallerCompleted => Some(StoreTransactionState::InstallCompleted),
        StoreSignal::Win32InstallerFailed => Some(StoreTransactionState::InstallerFailure),
        StoreSignal::RetryScheduled => Some(StoreTransactionState::PendingRetry),
        StoreSignal::PackageInstalledFact => Some(StoreTransactionState::InstallCompleted),
        StoreSignal::PackageAbsentFact | StoreSignal::Unclassified => None,
    }
}

/// Lifecycle rank. A higher-ranked state replaces a lower one. Equal ranks are
/// resolved by [`resolve_state`], never by the order the caller supplied the
/// observations in (ADR-003).
fn state_rank(state: StoreTransactionState) -> u8 {
    match state {
        StoreTransactionState::InsufficientEvidence => 0,
        StoreTransactionState::NotTargeted | StoreTransactionState::NotApplicable => 1,
        StoreTransactionState::AcquisitionRequested => 2,
        StoreTransactionState::PendingRetry => 3,
        StoreTransactionState::StoreWin32Handoff => 4,
        StoreTransactionState::NoInteractiveUser => 5,
        StoreTransactionState::LicenseFailure
        | StoreTransactionState::DownloadFailure
        | StoreTransactionState::RegistrationFailure
        | StoreTransactionState::ProvisioningFailure
        | StoreTransactionState::InstallerFailure
        | StoreTransactionState::UninstallFailure
        | StoreTransactionState::InstallCompleted
        | StoreTransactionState::UninstallCompleted => 6,
    }
}

/// One observation's statement about the transaction state, with the provenance
/// needed to order it against other statements.
struct StateCandidate<'a> {
    state: StoreTransactionState,
    error: Option<&'a IntuneErrorCode>,
    source_artifact_id: &'a str,
    record_number: Option<u64>,
    /// True when the observation came from a source whose own record numbering
    /// is a monotonic write order (an event log's record ids, a CCM log's
    /// records). Supplied facts carry a caller-chosen record number that states
    /// nothing about time, so they are never sequenced against anything.
    sequenced: bool,
}

/// Whether `later` supersedes `earlier` by the source's own ordering.
///
/// Only records from the *same* sequenced source artifact are comparable:
/// record numbers from two different artifacts, or from supplied facts, share
/// no clock and no counter. Incomparable records stay ambiguous (ADR-003).
fn supersedes(later: &StateCandidate<'_>, earlier: &StateCandidate<'_>) -> bool {
    later.sequenced
        && earlier.sequenced
        && later.source_artifact_id == earlier.source_artifact_id
        && matches!(
            (later.record_number, earlier.record_number),
            (Some(later), Some(earlier)) if later > earlier
        )
}

/// Resolve the transaction state from every state-bearing observation at once.
///
/// Caller vector order is an acquisition detail, not chronology, so this
/// resolution must give the same answer for any permutation of the same
/// observations (ADR-003):
///
/// 1. the highest lifecycle rank wins, as before;
/// 2. within that rank, a record superseded by a later record from the same
///    sequenced source artifact is dropped — this is what lets an explicitly
///    ordered retry land on its final outcome instead of its first failure;
/// 3. if the surviving records still state more than one distinct state, the
///    evidence is an unresolved authoritative contradiction and the reduction
///    stays conservative: `InsufficientEvidence` for a single terminal
///    conclusion, with every contributing observation left visible, rather
///    than whichever record the caller happened to list last.
fn resolve_state(
    candidates: &[StateCandidate<'_>],
) -> (StoreTransactionState, Option<IntuneErrorCode>) {
    let Some(top_rank) = candidates
        .iter()
        .map(|candidate| state_rank(candidate.state))
        .max()
    else {
        return (StoreTransactionState::InsufficientEvidence, None);
    };
    let top: Vec<&StateCandidate<'_>> = candidates
        .iter()
        .filter(|candidate| state_rank(candidate.state) == top_rank)
        .collect();
    let mut surviving: Vec<&StateCandidate<'_>> = top
        .iter()
        .filter(|candidate| !top.iter().any(|other| supersedes(other, candidate)))
        .copied()
        .collect();
    // Canonical evidence order, independent of the caller's input order.
    surviving.sort_by_key(|candidate| (candidate.source_artifact_id, candidate.record_number));

    let state = surviving[0].state;
    if surviving
        .iter()
        .any(|candidate| candidate.state != state)
    {
        return (StoreTransactionState::InsufficientEvidence, None);
    }
    let error = surviving
        .iter()
        .find_map(|candidate| candidate.error.cloned());
    (state, error)
}

fn reduce_group(
    index: usize,
    members: &[usize],
    observations: &[StoreObservation],
) -> StoreTransaction {
    let mut identity = StorePackageIdentity::default();
    let mut app_id: Option<String> = None;
    let mut execution_context = StoreExecutionContext::Unknown;
    let mut installer_family = StoreInstallerFamily::Unknown;
    let mut family_basis = StoreFamilyBasis::Unvalidated;
    let mut action = StoreDeploymentAction::Unknown;
    let mut intent = StoreAssignmentIntent::Unknown;
    let mut intent_conflict = false;
    let mut last_confirmed_phase: Option<StorePhase> = None;
    let mut state_candidates: Vec<StateCandidate<'_>> = Vec::new();
    let mut has_intune_intent = false;
    let mut has_device_evidence = false;
    let mut unknown_version_observed = false;
    let mut malformed_contributor = false;
    let mut observation_ids = Vec::with_capacity(members.len());
    let mut evidence = Vec::with_capacity(members.len());

    for &member in members {
        let observation = &observations[member];
        observation_ids.push(observation.observation_id.clone());
        evidence.push(observation.context.evidence_ref.clone());

        identity.absorb(&observation.identity);
        if app_id.is_none() {
            app_id.clone_from(&observation.app_id);
        }
        if execution_context == StoreExecutionContext::Unknown {
            execution_context = observation.execution_context;
        }
        if installer_family == StoreInstallerFamily::Unknown
            && observation.installer_family != StoreInstallerFamily::Unknown
        {
            installer_family = observation.installer_family;
            family_basis = observation.family_basis;
        }
        if action == StoreDeploymentAction::Unknown {
            action = observation.action;
        }
        // Typed assignment intent is authoritative (ADR-001). It is read only
        // from the typed field a real assignment carried; a caller-writable
        // `named_data` pair on a package or installer observation is raw
        // metadata and can never state or override an intent. Two typed
        // assignments stating different intents are an unresolved contradiction
        // and stay `Unknown` rather than letting input order pick a winner.
        if let Some(typed) = observation.typed_intent {
            if typed != StoreAssignmentIntent::Unknown {
                if intent == StoreAssignmentIntent::Unknown && !intent_conflict {
                    intent = typed;
                } else if intent != typed {
                    intent = StoreAssignmentIntent::Unknown;
                    intent_conflict = true;
                }
            }
        }

        has_intune_intent |= observation.origin.is_intune_intent();
        has_device_evidence |= observation.origin.is_device_evidence();
        unknown_version_observed |= observation.unknown_version;
        malformed_contributor |= observation.context.parse_state == IntuneParseState::Malformed
            || observation.context.access_state != IntuneAccessState::Available;

        if let Some(phase) = phase_for(observation.signal) {
            last_confirmed_phase = Some(match last_confirmed_phase {
                Some(current) if current > phase => current,
                _ => phase,
            });
        }

        if let Some(candidate) = state_for(observation.signal) {
            state_candidates.push(StateCandidate {
                state: candidate,
                error: observation.error.as_ref(),
                source_artifact_id: &observation.context.evidence_ref.source_artifact_id,
                record_number: observation.context.provenance.record_number,
                sequenced: matches!(
                    observation.origin,
                    StoreEvidenceOrigin::WindowsEvent
                        | StoreEvidenceOrigin::IntuneManagementExtension
                ),
            });
        }
    }

    let (mut state, mut error) = resolve_state(&state_candidates);

    if intent == StoreAssignmentIntent::NotTargeted {
        state = StoreTransactionState::NotTargeted;
    }
    if intent == StoreAssignmentIntent::Uninstall && action == StoreDeploymentAction::Unknown {
        action = StoreDeploymentAction::Uninstall;
    }
    // A code carried by the record that produced a *successful* state is an
    // installer's return value, not an error. It stays on the observation,
    // where it is unambiguous, rather than being surfaced as the transaction's
    // error and read as a failure that did not happen.
    if !state.is_failure() {
        error = None;
    }

    let confidence = confidence_for(
        installer_family,
        state,
        last_confirmed_phase,
        has_intune_intent,
        has_device_evidence,
        unknown_version_observed || malformed_contributor,
    );

    StoreTransaction {
        transaction_id: format!("store-{:02}", index + 1),
        app_id,
        identity,
        installer_family,
        family_basis,
        execution_context,
        action,
        intent,
        last_confirmed_phase,
        state,
        error,
        confidence,
        has_intune_intent,
        has_device_evidence,
        unknown_version_observed,
        next_evidence_request: next_evidence_request(
            installer_family,
            state,
            has_intune_intent,
            has_device_evidence,
        ),
        observations: observation_ids,
        evidence,
    }
}

/// Whether the installer family is material to this transaction's diagnosis.
///
/// Licensing and acquisition happen before any payload is staged, so there is no
/// installer family to establish yet. Treating its absence as a gap there would
/// report noise, and letting it lower confidence would understate a direct,
/// error-coded acquisition failure.
pub(super) fn family_is_material(state: StoreTransactionState) -> bool {
    !matches!(
        state,
        StoreTransactionState::NotTargeted
            | StoreTransactionState::NotApplicable
            | StoreTransactionState::AcquisitionRequested
            | StoreTransactionState::LicenseFailure
    )
}

fn confidence_for(
    installer_family: StoreInstallerFamily,
    state: StoreTransactionState,
    last_confirmed_phase: Option<StorePhase>,
    has_intune_intent: bool,
    has_device_evidence: bool,
    degraded: bool,
) -> IntuneFindingConfidence {
    let family_missing =
        installer_family == StoreInstallerFamily::Unknown && family_is_material(state);
    if state == StoreTransactionState::InsufficientEvidence
        || last_confirmed_phase.is_none()
        || family_missing
        || degraded
    {
        return IntuneFindingConfidence::Low;
    }
    if has_intune_intent && has_device_evidence {
        IntuneFindingConfidence::High
    } else {
        IntuneFindingConfidence::Medium
    }
}

/// The smallest artifact that would advance this diagnosis.
fn next_evidence_request(
    installer_family: StoreInstallerFamily,
    state: StoreTransactionState,
    has_intune_intent: bool,
    has_device_evidence: bool,
) -> Option<String> {
    if state == StoreTransactionState::StoreWin32Handoff {
        return Some("Collect the Win32 app installer log for the handed-off package".to_owned());
    }
    if !has_device_evidence {
        return Some(
            "Collect Microsoft-Windows-AppXDeploymentServer/Operational and Microsoft-Windows-StoreAgent events for this package".to_owned(),
        );
    }
    if !has_intune_intent {
        return Some(
            "Collect IntuneManagementExtension.log or the app assignment for this package"
                .to_owned(),
        );
    }
    if installer_family == StoreInstallerFamily::Unknown && family_is_material(state) {
        return Some(
            "Collect the AppX deployment scope or package provisioning state to establish the installer family".to_owned(),
        );
    }
    None
}

// ── Coverage ────────────────────────────────────────────────────────────────

fn build_coverage(
    artifacts: &[StoreSourceArtifact],
    observations: &[StoreObservation],
) -> Vec<IntuneArtifactCoverage> {
    artifacts
        .iter()
        .map(|artifact| IntuneArtifactCoverage {
            artifact_id: artifact.artifact_id.clone(),
            family: artifact.family.clone(),
            status: artifact.status.clone(),
            detail: artifact.detail.clone(),
            observed_at_utc: artifact.observed_at_utc.clone(),
            evidence: observations
                .iter()
                .filter(|observation| {
                    observation.context.evidence_ref.source_artifact_id == artifact.artifact_id
                })
                .map(|observation| observation.context.evidence_ref.clone())
                .collect(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intune::evidence::IntuneSourceKind;
    use crate::intune::normalized::{NormalizedEventLevel, NormalizedWindowsEvent};

    fn context(artifact: &str, record: u64, kind: IntuneSourceKind) -> IntuneObservationContext {
        IntuneObservationContext {
            evidence_ref: IntuneEvidenceRef {
                evidence_id: format!("{artifact}:{record}"),
                source_artifact_id: artifact.to_owned(),
            },
            provenance: IntuneProvenance {
                source_kind: kind,
                source_artifact_id: artifact.to_owned(),
                file_path: None,
                line_number: None,
                record_number: Some(record),
                registry: None,
                event: None,
            },
            source_timestamp: None,
            observed_at_utc: "2026-07-31T00:00:00Z".to_owned(),
            sensitivity: IntuneSensitivity::Public,
            parse_state: IntuneParseState::Parsed,
            access_state: IntuneAccessState::Available,
        }
    }

    fn appx_event(
        artifact: &str,
        record: u64,
        event_id: u32,
        named_data: &[(&str, &str)],
    ) -> NormalizedWindowsEvent {
        NormalizedWindowsEvent {
            context: context(artifact, record, IntuneSourceKind::EventLog),
            channel: "Microsoft-Windows-AppXDeploymentServer/Operational".to_owned(),
            provider: "Microsoft-Windows-AppXDeployment-Server".to_owned(),
            event_id,
            level: NormalizedEventLevel::Information,
            task: None,
            keywords: None,
            record_id: Some(record),
            activity_id: None,
            event_version: None,
            named_data: named_data
                .iter()
                .map(|(name, value)| IntuneNamedValue {
                    name: (*name).to_owned(),
                    value: (*value).to_owned(),
                })
                .collect(),
            message: None,
        }
    }

    fn event_artifact(id: &str, events: Vec<NormalizedWindowsEvent>) -> StoreSourceArtifact {
        StoreSourceArtifact {
            artifact_id: id.to_owned(),
            family: "appxDeployment".to_owned(),
            source_kind: IntuneSourceKind::EventLog,
            status: IntuneArtifactStatus::Available,
            detail: None,
            observed_at_utc: "2026-07-31T00:00:00Z".to_owned(),
            file_name: None,
            file_path: None,
            payload: Some(StoreArtifactPayload::WindowsEvents { events }),
        }
    }

    #[test]
    fn a_user_context_registration_and_a_provisioning_event_do_not_merge() {
        // Same package, two installer families. Merging them would let a
        // machine-wide provisioning failure close out a per-user registration.
        let analysis = analyze_store_bundle(&[event_artifact(
            "appx",
            vec![
                appx_event(
                    "appx",
                    1,
                    603,
                    &[
                        ("DeploymentOperation", "Register"),
                        ("DeploymentScope", "User"),
                        ("PackageFamilyName", "Contoso.SynthApp_9abcdef01234h"),
                    ],
                ),
                appx_event(
                    "appx",
                    2,
                    404,
                    &[
                        ("DeploymentOperation", "Provision"),
                        ("PackageFamilyName", "Contoso.SynthApp_9abcdef01234h"),
                        ("ErrorCode", "0x80073CF9"),
                    ],
                ),
            ],
        )]);

        assert_eq!(analysis.transactions.len(), 2);
        assert_eq!(
            analysis.transactions[0].installer_family,
            StoreInstallerFamily::UwpUserContext
        );
        assert_eq!(
            analysis.transactions[0].state,
            StoreTransactionState::InstallCompleted
        );
        assert_eq!(
            analysis.transactions[1].installer_family,
            StoreInstallerFamily::UwpProvisioned
        );
        assert_eq!(
            analysis.transactions[1].state,
            StoreTransactionState::ProvisioningFailure
        );
    }

    #[test]
    fn a_full_name_event_joins_a_family_name_event() {
        let analysis = analyze_store_bundle(&[event_artifact(
            "appx",
            vec![
                appx_event(
                    "appx",
                    1,
                    400,
                    &[
                        ("DeploymentOperation", "Stage"),
                        ("DeploymentScope", "User"),
                        (
                            "PackageFullName",
                            "Contoso.SynthApp_1.2.3.0_x64__9abcdef01234h",
                        ),
                    ],
                ),
                appx_event(
                    "appx",
                    2,
                    603,
                    &[
                        ("DeploymentOperation", "Register"),
                        ("DeploymentScope", "User"),
                        ("PackageFamilyName", "Contoso.SynthApp_9abcdef01234h"),
                    ],
                ),
            ],
        )]);
        assert_eq!(analysis.transactions.len(), 1);
        assert_eq!(analysis.transactions[0].observations.len(), 2);
    }

    #[test]
    fn an_observation_without_any_identifier_stays_unkeyed() {
        let analysis = analyze_store_bundle(&[event_artifact(
            "appx",
            vec![appx_event(
                "appx",
                1,
                404,
                &[("DeploymentOperation", "Register")],
            )],
        )]);
        assert!(analysis.transactions.is_empty());
        assert_eq!(analysis.unkeyed_observations, vec!["appx:1".to_owned()]);
    }

    #[test]
    fn coverage_is_emitted_for_every_declared_artifact_including_absent_ones() {
        let mut absent = event_artifact("appx", Vec::new());
        absent.artifact_id = "appx-absent".to_owned();
        absent.status = IntuneArtifactStatus::Missing;
        absent.payload = None;

        let analysis = analyze_store_bundle(&[absent]);
        assert_eq!(analysis.coverage.len(), 1);
        assert_eq!(analysis.coverage[0].status, IntuneArtifactStatus::Missing);
        assert!(analysis.coverage[0].evidence.is_empty());
    }
}
