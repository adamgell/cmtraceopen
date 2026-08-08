//! Reduction of supplied Autopilot evidence into an immutable snapshot.
//!
//! The shape follows the ESP sibling in `crate::esp`: typed observations that
//! each carry an [`IntuneObservationContext`], then a single pass that folds
//! them into a snapshot, then `derive_findings` over that snapshot. Nothing
//! here performs I/O, and nothing mutates the snapshot after it is returned.
//!
//! Three rules constrain every inference below:
//!
//! 1. A conclusion needs an explicit record. Absence of a signal is a
//!    conclusion only when the artifact that would have carried it was fully
//!    captured; see [`AutopilotCaptureState::supports_negative_conclusion`].
//! 2. Cross-sibling linkage needs an explicit shared key. Overlapping time
//!    ranges can only ever produce a low-confidence candidate.
//! 3. An unknown Windows build, Autopilot schema, or document version refuses
//!    terminal semantics outright rather than reasoning from a guess.

use std::collections::{BTreeMap, BTreeSet};

use crate::intune::evidence::{
    IntuneAccessState, IntuneArtifactCoverage, IntuneArtifactStatus, IntuneErrorCode,
    IntuneEvidenceRef, IntuneFindingConfidence, IntuneNamedValue, IntuneObservationContext,
    IntuneParseState, IntuneProvenance, IntuneSensitivity, IntuneSourceKind, IntuneTimestampKind,
};
use crate::intune::normalized::NormalizedWindowsEvent;

use super::models::*;
use super::normalize::{
    classify_event, extract_error_code, extract_oobe_setting, extract_policy_pair,
    extract_profile_state,
};
use super::rules::derive_findings;
use super::sources::{
    capture_is_validated, classify_timezone, detect_document, AutopilotBundleInput,
    AutopilotCaptureState, AutopilotDocumentDetection, AutopilotDocumentKind,
    AutopilotEspSessionDocument, AutopilotEventsDocument, AutopilotReportDocument,
    AutopilotReportSection, AutopilotSourceInput, AUTOPILOT_EVENT_CHANNEL,
};

/// Named-data and report-value keys the reducer lifts into typed identity
/// fields. Anything not listed stays in `named_data`, untouched.
const IDENTITY_KEYS: [&str; 9] = [
    "serialNumber",
    "hardwareHash",
    "productKeyId",
    "ztdRegistrationId",
    "entraDeviceId",
    "managedDeviceId",
    "tenantId",
    "tenantDomain",
    "deviceName",
];

/// Reduce one supplied Autopilot bundle into an immutable snapshot.
///
/// Total: every input shape produces a snapshot. A bundle the reducer cannot
/// interpret yields [`AutopilotOutcome::InsufficientEvidence`] or
/// [`AutopilotOutcome::UnknownSchema`] plus coverage explaining why, never an
/// error and never a silent empty result.
pub fn reduce_autopilot_bundle(bundle: &AutopilotBundleInput) -> AutopilotSnapshot {
    let timezone_state = classify_timezone(bundle.capture.timezone.as_deref());

    let mut ingest = Ingest {
        observed_at_utc: bundle.generated_at_utc.clone(),
        ..Ingest::default()
    };
    for source in &bundle.sources {
        ingest.absorb_source(source);
    }
    for (index, event) in bundle.events.iter().enumerate() {
        ingest.absorb_native_event(index, event);
    }

    let mut observations = ingest.observations;
    let time_basis = time_basis(timezone_state, &observations);
    sort_observations(&mut observations, time_basis);

    let identity = reduce_identity(&observations, &ingest.sections);
    let profile = reduce_profile(&observations, &ingest.sections);
    let oobe = reduce_oobe(&observations);
    let handoff = reduce_handoff(&observations, &ingest.sections);
    let conflicts = detect_conflicts(&observations, &ingest.sections, &ingest.esp_sessions);
    let esp_linkage = reduce_esp_linkage(
        &observations,
        &ingest.esp_sessions,
        &handoff,
        &conflicts,
        time_basis,
    );

    let coverage = ingest.coverage;
    // A malformed document is deliberately *not* part of this gate. Unreadable
    // bytes are a coverage gap, reported as `parseFailed` coverage and its own
    // finding; they say nothing about whether this build understands the
    // device's Autopilot schema, which is what refusing terminal semantics is
    // supposed to express.
    let capture_validated = capture_is_validated(&bundle.capture) && !ingest.unsupported_documents;

    let phase = reduce_phase(&identity, &profile, &handoff);
    let outcome = reduce_outcome(
        capture_validated,
        &conflicts,
        &identity,
        &profile,
        &handoff,
        &esp_linkage,
        &observations,
        &ingest.sections,
    );
    let confidence = reduce_confidence(outcome, capture_validated, time_basis, &coverage);
    let next_evidence_requests = next_evidence_requests(
        outcome,
        &esp_linkage,
        !ingest.esp_sessions.is_empty(),
        &coverage,
    );

    let unclassified_observation_ids = observations
        .iter()
        .filter(|observation| observation.signal == AutopilotSignal::Unclassified)
        .map(|observation| observation.observation_id.clone())
        .collect();

    let mut snapshot = AutopilotSnapshot {
        schema_version: AUTOPILOT_SNAPSHOT_SCHEMA_VERSION,
        generated_at_utc: bundle.generated_at_utc.clone(),
        capture: bundle.capture.clone(),
        timezone_state,
        time_basis,
        identity,
        profile,
        oobe,
        handoff,
        esp_linkage,
        phase,
        outcome,
        confidence,
        next_evidence_requests,
        observations,
        unclassified_observation_ids,
        documents: ingest.documents,
        conflicts,
        coverage,
        findings: Vec::new(),
    };
    snapshot.findings = derive_findings(&snapshot);
    snapshot
}

// ── Ingest ──────────────────────────────────────────────────────────────────

#[derive(Default)]
struct Ingest {
    observed_at_utc: String,
    observations: Vec<AutopilotObservation>,
    sections: Vec<AutopilotReportSection>,
    esp_sessions: Vec<AutopilotEspSessionFact>,
    documents: Vec<AutopilotDocumentReport>,
    coverage: Vec<IntuneArtifactCoverage>,
    /// Artifacts whose document declared that the channel it carries is
    /// truncated. Their coverage is forced to `Capped`, because a partial
    /// channel cannot support "this signal never appeared".
    incomplete_artifacts: BTreeSet<String>,
    unsupported_documents: bool,
}

impl Ingest {
    fn absorb_source(&mut self, source: &AutopilotSourceInput) {
        let declared_status = source.capture_state.declared_status();
        let Some(content) = source.content.as_deref() else {
            self.push_coverage(source, declared_status, None);
            return;
        };

        match detect_document(content) {
            AutopilotDocumentDetection::Supported { kind, version } => {
                match self.absorb_payload(source, &kind, content) {
                    Ok(observation_ids) => {
                        self.documents.push(AutopilotDocumentReport {
                            artifact_id: source.artifact_id.clone(),
                            declared_kind: Some(kind_wire(&kind)),
                            declared_version: Some(version),
                            parse_state: IntuneParseState::Parsed,
                            detail: None,
                            observation_ids,
                        });
                        if self.incomplete_artifacts.contains(&source.artifact_id)
                            && declared_status == IntuneArtifactStatus::Available
                        {
                            self.push_coverage(
                                source,
                                IntuneArtifactStatus::Capped,
                                Some(
                                    "The document declares the event channel incomplete, so the \
                                     absence of a signal in it proves nothing."
                                        .to_owned(),
                                ),
                            );
                        } else {
                            self.push_coverage(source, declared_status, None);
                        }
                    }
                    // The envelope was valid but the payload was not. That is a
                    // malformed document, not a supported one with no records:
                    // collapsing the two would let corrupt content masquerade
                    // as proof that nothing happened.
                    Err(detail) => {
                        self.documents.push(AutopilotDocumentReport {
                            artifact_id: source.artifact_id.clone(),
                            declared_kind: Some(kind_wire(&kind)),
                            declared_version: Some(version),
                            parse_state: IntuneParseState::Malformed,
                            detail: Some(detail.clone()),
                            observation_ids: Vec::new(),
                        });
                        self.push_coverage(
                            source,
                            escalate(declared_status, IntuneParseState::Malformed),
                            Some(detail),
                        );
                    }
                }
            }
            AutopilotDocumentDetection::Unsupported {
                declared_kind,
                declared_version,
                detail,
            } => {
                self.unsupported_documents = true;
                self.documents.push(AutopilotDocumentReport {
                    artifact_id: source.artifact_id.clone(),
                    declared_kind,
                    declared_version,
                    parse_state: IntuneParseState::Unsupported,
                    detail: Some(detail.clone()),
                    observation_ids: Vec::new(),
                });
                self.push_coverage(
                    source,
                    escalate(declared_status, IntuneParseState::Unsupported),
                    Some(detail),
                );
            }
            AutopilotDocumentDetection::Malformed { detail } => {
                self.documents.push(AutopilotDocumentReport {
                    artifact_id: source.artifact_id.clone(),
                    declared_kind: None,
                    declared_version: None,
                    parse_state: IntuneParseState::Malformed,
                    detail: Some(detail.clone()),
                    observation_ids: Vec::new(),
                });
                self.push_coverage(
                    source,
                    escalate(declared_status, IntuneParseState::Malformed),
                    Some(detail),
                );
            }
        }
    }

    /// Parse a detected document's payload.
    ///
    /// `Err` carries why the payload could not be read, so the caller can
    /// record a malformed document instead of an empty supported one. The
    /// detail is a stable reducer-authored sentence and deliberately excludes
    /// `serde_json`'s error text: that text flows into golden-asserted finding
    /// summaries, and serde_json does not guarantee its `Display` output
    /// across releases.
    fn absorb_payload(
        &mut self,
        source: &AutopilotSourceInput,
        kind: &AutopilotDocumentKind,
        content: &str,
    ) -> Result<Vec<String>, String> {
        let mut ids = Vec::new();
        match kind {
            AutopilotDocumentKind::Events => {
                let document = serde_json::from_str::<AutopilotEventsDocument>(content)
                    .map_err(|_| "events payload could not be read".to_owned())?;
                if document.channel_complete == Some(false) {
                    self.incomplete_artifacts.insert(source.artifact_id.clone());
                }
                for (index, event) in document.events.iter().enumerate() {
                    if let Some(observation) =
                        observation_from_event(&source.artifact_id, index, event)
                    {
                        ids.push(observation.observation_id.clone());
                        self.observations.push(observation);
                    }
                }
            }
            AutopilotDocumentKind::DiagnosticsReport | AutopilotDocumentKind::IdentityFacts => {
                let document = serde_json::from_str::<AutopilotReportDocument>(content)
                    .map_err(|_| "report payload could not be read".to_owned())?;
                for section in &document.sections {
                    let observation = observation_from_section(section);
                    ids.push(observation.observation_id.clone());
                    self.observations.push(observation);
                    self.sections.push(section.clone());
                }
            }
            AutopilotDocumentKind::EspSession => {
                let document = serde_json::from_str::<AutopilotEspSessionDocument>(content)
                    .map_err(|_| "ESP session payload could not be read".to_owned())?;
                for session in &document.sessions {
                    let observation = observation_from_esp_session(session);
                    ids.push(observation.observation_id.clone());
                    self.observations.push(observation);
                    self.esp_sessions.push(session.clone());
                }
            }
            // Detection never yields `Supported` for an unknown kind.
            AutopilotDocumentKind::Unknown(_) => {}
        }
        Ok(ids)
    }

    fn absorb_native_event(&mut self, index: usize, event: &NormalizedWindowsEvent) {
        let artifact_id = event.context.provenance.source_artifact_id.clone();
        if let Some(observation) = observation_from_event(&artifact_id, index, event) {
            self.observations.push(observation);
        }
    }

    fn push_coverage(
        &mut self,
        source: &AutopilotSourceInput,
        status: IntuneArtifactStatus,
        detail: Option<String>,
    ) {
        let evidence = self
            .observations
            .iter()
            .filter(|observation| {
                observation.context.evidence_ref.source_artifact_id == source.artifact_id
            })
            .map(AutopilotObservation::evidence_ref)
            .collect::<Vec<_>>();
        self.coverage.push(IntuneArtifactCoverage {
            artifact_id: source.artifact_id.clone(),
            family: source.family.clone(),
            status,
            detail: detail.or_else(|| coverage_detail(source)),
            observed_at_utc: self.observed_at_utc.clone(),
            evidence,
        });
    }
}

fn coverage_detail(source: &AutopilotSourceInput) -> Option<String> {
    match source.capture_state {
        AutopilotCaptureState::Capped => Some(
            "The artifact was truncated, so the absence of a signal in it proves nothing."
                .to_owned(),
        ),
        AutopilotCaptureState::Absent => source
            .original_basename
            .as_ref()
            .map(|name| format!("{name} was not present on the device.")),
        AutopilotCaptureState::AccessDenied => Some(
            "The collector was not permitted to read this artifact; re-collect elevated."
                .to_owned(),
        ),
        AutopilotCaptureState::Skipped => {
            Some("The collector was told not to read this artifact.".to_owned())
        }
        _ => None,
    }
}

/// Worsen a declared coverage status with what the reducer found in the bytes.
///
/// A collector that reports success over content the reducer cannot read must
/// not be able to launder that into coverage, so parse outcomes only ever move
/// the status in the pessimistic direction.
///
/// Statuses that are already a positive statement by the collector are left
/// alone. `Missing`, `PermissionDenied`, and `Skipped` had no bytes, so they
/// cannot also be malformed; `ParseFailed` already says exactly this; and
/// `Unsupported` means the collector recognized the source and declined it,
/// which stays true whatever its bytes turn out to contain.
fn escalate(declared: IntuneArtifactStatus, parse_state: IntuneParseState) -> IntuneArtifactStatus {
    if matches!(
        declared,
        IntuneArtifactStatus::Missing
            | IntuneArtifactStatus::PermissionDenied
            | IntuneArtifactStatus::Skipped
            | IntuneArtifactStatus::ParseFailed
            | IntuneArtifactStatus::Unsupported
    ) {
        return declared;
    }
    match parse_state {
        IntuneParseState::Malformed => IntuneArtifactStatus::ParseFailed,
        IntuneParseState::Unsupported => IntuneArtifactStatus::Unsupported,
        IntuneParseState::Parsed | IntuneParseState::Raw => declared,
    }
}

fn kind_wire(kind: &AutopilotDocumentKind) -> String {
    serde_json::to_value(kind)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default()
}

// ── Observation construction ────────────────────────────────────────────────

fn observation_from_event(
    artifact_id: &str,
    index: usize,
    event: &NormalizedWindowsEvent,
) -> Option<AutopilotObservation> {
    let signal = classify_event(event)?;
    // Prefer the evidence id the collector already assigned: it stays stable if
    // the events are ever re-ordered, which a positional id would not.
    let observation_id = if event.context.evidence_ref.evidence_id.trim().is_empty() {
        format!("{artifact_id}:{index}")
    } else {
        event.context.evidence_ref.evidence_id.clone()
    };
    let mut named_data = event.named_data.clone();
    if let Some(pair) = extract_policy_pair(event.message.as_deref()) {
        if !named_data
            .iter()
            .any(|value| value.name.eq_ignore_ascii_case(&pair.name))
        {
            named_data.push(pair);
        }
    }
    Some(AutopilotObservation {
        observation_id,
        context: event.context.clone(),
        signal,
        channel: Some(event.channel.clone()),
        provider: Some(event.provider.clone()),
        event_id: Some(event.event_id),
        event_version: event.event_version,
        activity_id: event.activity_id.clone(),
        section_kind: None,
        section_outcome: None,
        error: extract_error_code(event.message.as_deref()),
        named_data,
        message: event.message.clone(),
    })
}

fn observation_from_section(section: &AutopilotReportSection) -> AutopilotObservation {
    AutopilotObservation {
        observation_id: section.context.evidence_ref.evidence_id.clone(),
        context: section.context.clone(),
        signal: AutopilotSignal::ReportSection,
        channel: None,
        provider: None,
        event_id: None,
        event_version: None,
        activity_id: section
            .values
            .iter()
            .find(|value| value.name.eq_ignore_ascii_case("activityId"))
            .map(|value| value.value.clone()),
        section_kind: Some(section.kind.clone()),
        section_outcome: Some(section.outcome.clone()),
        error: section.error.clone(),
        named_data: section.values.clone(),
        message: section.message.clone(),
    }
}

fn observation_from_esp_session(session: &AutopilotEspSessionFact) -> AutopilotObservation {
    let mut named_data = vec![IntuneNamedValue {
        name: "espSessionId".to_owned(),
        value: session.session_id.clone(),
    }];
    for (name, value) in [
        ("enrollmentId", session.enrollment_id.as_ref()),
        ("correlationId", session.correlation_id.as_ref()),
        ("activityId", session.activity_id.as_ref()),
        ("entraDeviceId", session.entra_device_id.as_ref()),
        ("managedDeviceId", session.managed_device_id.as_ref()),
        ("espPhase", session.phase.as_ref()),
    ] {
        if let Some(value) = value {
            named_data.push(IntuneNamedValue {
                name: name.to_owned(),
                value: value.clone(),
            });
        }
    }
    AutopilotObservation {
        observation_id: session.evidence.evidence_id.clone(),
        context: IntuneObservationContext {
            evidence_ref: session.evidence.clone(),
            provenance: IntuneProvenance {
                source_kind: IntuneSourceKind::SuppliedFact,
                source_artifact_id: session.evidence.source_artifact_id.clone(),
                file_path: None,
                line_number: None,
                record_number: None,
                registry: None,
                event: None,
            },
            source_timestamp: None,
            observed_at_utc: session.started_at_utc.clone().unwrap_or_default(),
            sensitivity: IntuneSensitivity::Sensitive,
            parse_state: IntuneParseState::Parsed,
            access_state: IntuneAccessState::Available,
        },
        signal: AutopilotSignal::EspSessionFact,
        channel: None,
        provider: None,
        event_id: None,
        event_version: None,
        activity_id: session.activity_id.clone(),
        section_kind: None,
        section_outcome: None,
        error: None,
        named_data,
        message: None,
    }
}

// ── Time ────────────────────────────────────────────────────────────────────

/// Decide whether wall-clock time may be used for anything.
///
/// Both conditions must hold: the collection declared a timezone whose shape is
/// recognizable, and every timestamp that exists was normalized from an
/// explicit UTC or offset form. A bare local timestamp with no declared zone
/// would otherwise silently inherit whatever zone the reducing machine happens
/// to sit in, which is exactly the wrong-timezone inference that cannot be
/// audited afterwards.
fn time_basis(
    timezone_state: AutopilotTimezoneState,
    observations: &[AutopilotObservation],
) -> AutopilotTimeBasis {
    if timezone_state != AutopilotTimezoneState::Declared {
        return AutopilotTimeBasis::Unreliable;
    }
    let all_normalized = observations.iter().all(|observation| {
        observation
            .context
            .source_timestamp
            .as_ref()
            .is_none_or(|timestamp| {
                timestamp.normalized_utc.is_some()
                    && matches!(
                        timestamp.kind,
                        IntuneTimestampKind::Utc | IntuneTimestampKind::Offset
                    )
            })
    });
    if all_normalized {
        AutopilotTimeBasis::Utc
    } else {
        AutopilotTimeBasis::Unreliable
    }
}

/// Order observations deterministically.
///
/// When the time basis is unreliable the sort deliberately ignores timestamps
/// entirely and falls back to record id then observation id, so the ordering is
/// reproducible without implying a chronology the evidence does not support.
fn sort_observations(observations: &mut [AutopilotObservation], basis: AutopilotTimeBasis) {
    observations.sort_by(|left, right| {
        let left_time = sort_time(left, basis);
        let right_time = sort_time(right, basis);
        left_time
            .cmp(&right_time)
            .then_with(|| {
                left.context
                    .provenance
                    .record_number
                    .cmp(&right.context.provenance.record_number)
            })
            .then_with(|| left.observation_id.cmp(&right.observation_id))
    });
}

fn sort_time(observation: &AutopilotObservation, basis: AutopilotTimeBasis) -> Option<&str> {
    if basis != AutopilotTimeBasis::Utc {
        return None;
    }
    observation
        .context
        .source_timestamp
        .as_ref()
        .and_then(|timestamp| timestamp.normalized_utc.as_deref())
}

// ── Field reduction ─────────────────────────────────────────────────────────

/// An observation is assessable only when its record was fully available and
/// parsed. Malformed or access-denied records carry no semantic signal.
///
/// Every reduction path that turns a record into state, evidence, a phase, a
/// correlation key, or a time bound must pass through this gate (ADR-001:
/// non-assessable evidence cannot produce a terminal conclusion). The one
/// deliberate exception is [`time_basis`], where an *unfiltered* scan is the
/// conservative direction: a non-assessable record with an unnormalized
/// timestamp downgrades the basis, and gating it would upgrade it.
fn is_assessable(observation: &AutopilotObservation) -> bool {
    observation.context.access_state == IntuneAccessState::Available
        && observation.context.parse_state == IntuneParseState::Parsed
}

/// A report section is assessable under the same rule as an observation: its
/// own declared context must be fully available and parsed. Sections arrive
/// inside a parsed document, but each one still carries a caller-declared
/// context, and a section declared unreadable proves nothing.
fn is_assessable_section(section: &AutopilotReportSection) -> bool {
    section.context.access_state == IntuneAccessState::Available
        && section.context.parse_state == IntuneParseState::Parsed
}

fn signal_observations(
    observations: &[AutopilotObservation],
    signal: AutopilotSignal,
) -> impl Iterator<Item = &AutopilotObservation> {
    observations
        .iter()
        .filter(move |observation| is_assessable(observation) && observation.signal == signal)
}

fn has_signal(observations: &[AutopilotObservation], signal: AutopilotSignal) -> bool {
    signal_observations(observations, signal).next().is_some()
}

/// Iterate the assessable sections of one kind. The gate lives here so no
/// individual caller can forget it.
///
/// This gate is deliberately direction-aware in combination with
/// [`recorded_non_assessable_failure_sections`]: everything reached through
/// *this* iterator may prove progress, success, or a terminal cause, so it
/// admits assessable sections only. A non-assessable section that explicitly
/// recorded a failure is not silently discarded with it -- see the companion
/// iterator below.
fn sections_of<'a>(
    sections: &'a [AutopilotReportSection],
    kind: &AutopilotSectionKind,
) -> impl Iterator<Item = &'a AutopilotReportSection> {
    let kind = kind.clone();
    sections
        .iter()
        .filter(|section| is_assessable_section(section))
        .filter(move |section| section.kind == kind)
}

/// Iterate the *non-assessable* sections that explicitly recorded a failure or
/// mismatch.
///
/// ADR-001 cuts both ways. A capped or unparsed section cannot PROVE anything:
/// not progress, not success, and not a terminal failure either -- which is why
/// [`sections_of`] excludes it and why the reducer never turns one of these
/// into `ProfileRetrievalFailure`/`ProfileApplicationFailure`. But `Capped`
/// means "absence proves nothing", not "presence proves nothing": a failure
/// that IS on the record must still BLOCK a success conclusion, or sibling
/// assessable evidence would complete the enrollment at high confidence over a
/// recorded failure. Consumers of this iterator may only move the result in
/// the conservative direction.
///
/// `Failed` and `Mismatch` are the explicit negative recordings. `NotFound`
/// and `Retrying` stay out on purpose: those are statements of absence or of a
/// transient state, and an absence statement from a partially captured view
/// proves nothing in either direction.
fn recorded_non_assessable_failure_sections(
    sections: &[AutopilotReportSection],
) -> impl Iterator<Item = &AutopilotReportSection> {
    sections
        .iter()
        .filter(|section| !is_assessable_section(section))
        .filter(|section| {
            matches!(
                section.outcome,
                AutopilotSectionOutcome::Failed | AutopilotSectionOutcome::Mismatch
            )
        })
}

/// Iterate the *non-assessable* observations that explicitly recorded a
/// documented failure signal.
///
/// The event-side companion of
/// [`recorded_non_assessable_failure_sections`], with the same direction-aware
/// contract: a capped or unparsed event cannot PROVE the failure -- which is
/// why [`signal_observations`] and every other consumer stay gated on
/// [`is_assessable`], and why none of these observations ever produce a
/// terminal failure outcome -- but a failure that IS on the record must still
/// BLOCK a success conclusion. Consumers may only move the result in the
/// conservative direction.
///
/// The class is [`AutopilotSignal::is_terminal_failure`]: exactly the signals
/// that would produce a terminal failure outcome if they were assessable
/// (171, 172, 807, 809, 815, 908). That symmetry is the rule -- any record
/// strong enough to fail the enrollment when readable is strong enough to
/// block its success when unreadable. `ProfilePolicyNotFound` (100) stays out
/// for the same reason the section iterator excludes `NotFound`/`Retrying`:
/// it is documented as transient, not a recorded failure.
fn recorded_non_assessable_failure_observations(
    observations: &[AutopilotObservation],
) -> impl Iterator<Item = &AutopilotObservation> {
    observations
        .iter()
        .filter(|observation| !is_assessable(observation))
        .filter(|observation| observation.signal.is_terminal_failure())
}

/// Collect the distinct values a named key takes across every source.
///
/// Returned sorted and deduplicated so that "more than one value" is a
/// reproducible fact rather than an artifact of iteration order.
///
/// Distinctness is case-insensitive: the identifiers this feeds -- serials,
/// GUIDs, tenant domains, device names -- are case-insensitive identities on
/// Windows, and the redacted export masks the trimmed, lowercased value
/// (see the redaction module contract). Treating two casings as two values
/// produced a conflict whose export said "2 distinct values" over two
/// identical tokens, changing the conclusion under redaction (ADR-004). Each
/// group is keyed by a deterministic representative casing -- the
/// lexicographically smallest sighting -- so permuting the input cannot change
/// the result (ADR-003).
fn distinct_values(
    observations: &[AutopilotObservation],
    key: &str,
) -> BTreeMap<String, Vec<IntuneEvidenceRef>> {
    let mut groups: BTreeMap<String, (String, Vec<IntuneEvidenceRef>)> = BTreeMap::new();
    for observation in observations.iter().filter(|obs| is_assessable(obs)) {
        let Some(value) = observation.named(key) else {
            continue;
        };
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        let group = groups
            .entry(value.to_ascii_lowercase())
            .or_insert_with(|| (value.to_owned(), Vec::new()));
        if value < group.0.as_str() {
            group.0 = value.to_owned();
        }
        group.1.push(observation.evidence_ref());
    }
    groups.into_values().collect()
}

fn single_value(observations: &[AutopilotObservation], key: &str) -> Option<String> {
    let values = distinct_values(observations, key);
    let mut keys = values.into_keys();
    let first = keys.next()?;
    // More than one distinct value never picks a winner. Only `profileId`,
    // `serialNumber`, and `entraDeviceId` disagreements are additionally
    // reported as conflicts by `detect_conflicts`; the remaining keys
    // (`deviceName` legitimately changes mid-provisioning, and the rest lack a
    // validated single-value contract) just collapse to `None` here.
    if keys.next().is_some() {
        return None;
    }
    Some(first)
}

fn reduce_identity(
    observations: &[AutopilotObservation],
    sections: &[AutopilotReportSection],
) -> AutopilotDeviceIdentity {
    let mut identity = AutopilotDeviceIdentity {
        serial_number: single_value(observations, "serialNumber"),
        hardware_hash: single_value(observations, "hardwareHash"),
        product_key_id: single_value(observations, "productKeyId"),
        ztd_registration_id: single_value(observations, "ztdRegistrationId"),
        entra_device_id: single_value(observations, "entraDeviceId"),
        managed_device_id: single_value(observations, "managedDeviceId"),
        tenant_id: single_value(observations, "tenantId"),
        tenant_domain: single_value(observations, "tenantDomain"),
        device_name: single_value(observations, "deviceName"),
        registration_state: AutopilotRegistrationState::Unknown,
        evidence: Vec::new(),
    };

    let mut evidence = Vec::new();
    let mut state = AutopilotRegistrationState::Unknown;

    for section in sections_of(sections, &AutopilotSectionKind::DeviceIdentity) {
        evidence.push(section.context.evidence_ref.clone());
        state = merge_registration_state(
            state,
            match section.outcome {
                AutopilotSectionOutcome::Succeeded | AutopilotSectionOutcome::Observed => {
                    AutopilotRegistrationState::Registered
                }
                AutopilotSectionOutcome::NotFound => AutopilotRegistrationState::NotRegistered,
                AutopilotSectionOutcome::Mismatch => AutopilotRegistrationState::Mismatch,
                _ => AutopilotRegistrationState::Unknown,
            },
        );
    }
    for observation in signal_observations(observations, AutopilotSignal::DeviceNotRegistered) {
        evidence.push(observation.evidence_ref());
        state = merge_registration_state(state, AutopilotRegistrationState::NotRegistered);
    }
    for observation in signal_observations(observations, AutopilotSignal::IdentityMismatch) {
        evidence.push(observation.evidence_ref());
        state = merge_registration_state(state, AutopilotRegistrationState::Mismatch);
    }
    for observation in observations.iter().filter(|observation| {
        is_assessable(observation)
            && IDENTITY_KEYS
                .iter()
                .any(|key| observation.named(key).is_some())
    }) {
        evidence.push(observation.evidence_ref());
    }

    identity.registration_state = state;
    identity.evidence = normalized_evidence(evidence);
    identity
}

/// Combine two registration observations.
///
/// A mismatch outranks everything: a device can be both registered and
/// mismatched, and the mismatch is the fact that matters. `NotRegistered`
/// outranks `Registered` for the same reason a failure outranks a success --
/// the negative statement is the one that blocks provisioning.
fn merge_registration_state(
    current: AutopilotRegistrationState,
    incoming: AutopilotRegistrationState,
) -> AutopilotRegistrationState {
    fn rank(state: AutopilotRegistrationState) -> u8 {
        match state {
            AutopilotRegistrationState::Unknown => 0,
            AutopilotRegistrationState::Registered => 1,
            AutopilotRegistrationState::NotRegistered => 2,
            AutopilotRegistrationState::Mismatch => 3,
        }
    }
    if rank(incoming) > rank(current) {
        incoming
    } else {
        current
    }
}

fn reduce_profile(
    observations: &[AutopilotObservation],
    sections: &[AutopilotReportSection],
) -> AutopilotProfileState {
    let mut evidence = Vec::new();
    let mut candidate = AutopilotProfileCandidateState::Unknown;
    let mut retrieved = false;
    let mut applied = false;
    let mut error: Option<IntuneErrorCode> = None;
    let mut last_state_token = None;

    for observation in observations.iter().filter(|obs| is_assessable(obs)) {
        match observation.signal {
            AutopilotSignal::ProfileAcquisitionStarted
            | AutopilotSignal::ProfilePolicyNotFound
            | AutopilotSignal::NetworkAvailableForDownload => {
                evidence.push(observation.evidence_ref());
                candidate = raise_candidate(candidate, AutopilotProfileCandidateState::Pending);
            }
            AutopilotSignal::ProfileRetrieveSucceeded
            | AutopilotSignal::ProfileSettingsRetrieved => {
                evidence.push(observation.evidence_ref());
                retrieved = true;
                candidate = raise_candidate(candidate, AutopilotProfileCandidateState::Available);
            }
            AutopilotSignal::ProfileStateChanged => {
                evidence.push(observation.evidence_ref());
                let token = extract_profile_state(observation.message.as_deref());
                // `ProfileState_Available` deliberately counts as application
                // evidence, not merely retrieval. Event 172 -- the documented
                // failure sibling of this transition -- reads "failed to set
                // Autopilot profile as available": setting the profile
                // available IS the application step, so the transition into
                // `Available` is its explicit success record.
                if matches!(
                    token,
                    Some(AutopilotProfileStateToken::Available)
                        | Some(AutopilotProfileStateToken::Provisioned)
                ) {
                    applied = true;
                    candidate =
                        raise_candidate(candidate, AutopilotProfileCandidateState::Available);
                }
                if token.is_some() {
                    last_state_token = token;
                }
            }
            AutopilotSignal::DeviceAlreadyProvisioned => {
                evidence.push(observation.evidence_ref());
                applied = true;
                candidate = raise_candidate(candidate, AutopilotProfileCandidateState::Available);
            }
            AutopilotSignal::NoAssignedProfile => {
                evidence.push(observation.evidence_ref());
                candidate = AutopilotProfileCandidateState::NoneAssigned;
            }
            AutopilotSignal::AssignedProfileMissing => {
                evidence.push(observation.evidence_ref());
                candidate = AutopilotProfileCandidateState::AssignedButMissing;
            }
            AutopilotSignal::ProfileApplicationFailed => {
                evidence.push(observation.evidence_ref());
                error = error.or_else(|| observation.error.clone());
            }
            _ => {}
        }
    }

    for section in sections_of(sections, &AutopilotSectionKind::ProfileRetrieval) {
        evidence.push(section.context.evidence_ref.clone());
        match section.outcome {
            AutopilotSectionOutcome::Succeeded => {
                retrieved = true;
                candidate = raise_candidate(candidate, AutopilotProfileCandidateState::Available);
            }
            AutopilotSectionOutcome::NotFound => {
                candidate = AutopilotProfileCandidateState::NoneAssigned;
            }
            AutopilotSectionOutcome::Retrying => {
                candidate = raise_candidate(candidate, AutopilotProfileCandidateState::Pending);
            }
            _ => {}
        }
        error = error.or_else(|| section.error.clone());
    }
    for section in sections_of(sections, &AutopilotSectionKind::ProfileApplication) {
        evidence.push(section.context.evidence_ref.clone());
        if section.outcome == AutopilotSectionOutcome::Succeeded {
            applied = true;
        }
        error = error.or_else(|| section.error.clone());
    }

    AutopilotProfileState {
        profile_id: single_value(observations, "profileId"),
        profile_name: single_value(observations, "profileName"),
        deployment_profile_type: single_value(observations, "deploymentProfileType")
            .map(|value| deployment_profile_type(&value)),
        candidate_state: candidate,
        last_state_token,
        retrieved,
        applied,
        error,
        evidence: normalized_evidence(evidence),
    }
}

/// Raise a candidate state, never lowering one that was explicitly proven.
///
/// `NoneAssigned` and `AssignedButMissing` are assigned directly rather than
/// through this function: those are explicit service statements and must be
/// able to overwrite an earlier optimistic `Pending`.
fn raise_candidate(
    current: AutopilotProfileCandidateState,
    incoming: AutopilotProfileCandidateState,
) -> AutopilotProfileCandidateState {
    fn rank(state: AutopilotProfileCandidateState) -> u8 {
        match state {
            AutopilotProfileCandidateState::Unknown => 0,
            AutopilotProfileCandidateState::Pending => 1,
            AutopilotProfileCandidateState::NoneAssigned => 2,
            AutopilotProfileCandidateState::AssignedButMissing => 2,
            AutopilotProfileCandidateState::Available => 3,
        }
    }
    if rank(incoming) > rank(current) {
        incoming
    } else {
        current
    }
}

fn deployment_profile_type(raw: &str) -> AutopilotDeploymentProfileType {
    serde_json::from_value(serde_json::Value::String(raw.to_owned()))
        .unwrap_or_else(|_| AutopilotDeploymentProfileType::Unknown(raw.to_owned()))
}

fn reduce_oobe(observations: &[AutopilotObservation]) -> AutopilotOobeState {
    let mut settings = Vec::new();
    let mut evidence = Vec::new();
    let mut already_provisioned = false;

    for observation in signal_observations(observations, AutopilotSignal::OobeSettingObserved) {
        evidence.push(observation.evidence_ref());
        if let Some((setting, state)) = extract_oobe_setting(observation.message.as_deref()) {
            settings.push(AutopilotOobeSettingObservation {
                setting,
                state: Some(state),
                evidence: observation.evidence_ref(),
            });
        }
    }
    for observation in signal_observations(observations, AutopilotSignal::DeviceAlreadyProvisioned)
    {
        evidence.push(observation.evidence_ref());
        already_provisioned = true;
    }

    AutopilotOobeState {
        settings,
        already_provisioned,
        evidence: normalized_evidence(evidence),
    }
}

fn reduce_handoff(
    observations: &[AutopilotObservation],
    sections: &[AutopilotReportSection],
) -> AutopilotHandoff {
    let mut handoff = AutopilotHandoff::default();
    let mut evidence = Vec::new();

    for section in sections_of(sections, &AutopilotSectionKind::EnrollmentHandoff) {
        if matches!(
            section.outcome,
            AutopilotSectionOutcome::Succeeded | AutopilotSectionOutcome::Observed
        ) {
            handoff.enrollment_observed = true;
            evidence.push(section.context.evidence_ref.clone());
        }
    }
    for section in sections_of(sections, &AutopilotSectionKind::EspHandoff) {
        if matches!(
            section.outcome,
            AutopilotSectionOutcome::Succeeded | AutopilotSectionOutcome::Observed
        ) {
            handoff.esp_observed = true;
            evidence.push(section.context.evidence_ref.clone());
        }
    }

    handoff.enrollment_id = single_value(observations, "enrollmentId");
    handoff.correlation_id = single_value(observations, "correlationId");
    handoff.evidence = normalized_evidence(evidence);
    handoff
}

// ── Conflicts ───────────────────────────────────────────────────────────────

fn detect_conflicts(
    observations: &[AutopilotObservation],
    sections: &[AutopilotReportSection],
    esp_sessions: &[AutopilotEspSessionFact],
) -> Vec<AutopilotConflict> {
    let mut conflicts = Vec::new();

    for (key, kind, conflict_id) in [
        (
            "profileId",
            AutopilotConflictKind::ProfileIdentifier,
            "conflicting-profile-id",
        ),
        (
            "serialNumber",
            AutopilotConflictKind::DeviceIdentity,
            "conflicting-serial-number",
        ),
        (
            "entraDeviceId",
            AutopilotConflictKind::DeviceIdentity,
            "conflicting-entra-device-id",
        ),
    ] {
        let values = distinct_values(observations, key);
        if values.len() < 2 {
            continue;
        }
        let evidence = values.values().flatten().cloned().collect::<Vec<_>>();
        conflicts.push(AutopilotConflict {
            conflict_id: conflict_id.to_owned(),
            kind,
            detail: format!(
                "{} distinct {key} values were observed across the supplied sources.",
                values.len()
            ),
            values: values.into_keys().collect(),
            evidence: normalized_evidence(evidence),
        });
    }

    // One correlation key resolving to more than one ESP session means the
    // bundle cannot say which session it handed off to.
    let mut by_key: BTreeMap<AutopilotCorrelationKey, BTreeSet<String>> = BTreeMap::new();
    for session in esp_sessions {
        for key in session_keys(session) {
            by_key
                .entry(key)
                .or_default()
                .insert(session.session_id.clone());
        }
    }
    let ambiguous = by_key
        .iter()
        .filter(|(_, sessions)| sessions.len() > 1)
        .collect::<Vec<_>>();
    if !ambiguous.is_empty() {
        let mut sessions = BTreeSet::new();
        for (_, ids) in &ambiguous {
            sessions.extend(ids.iter().cloned());
        }
        let evidence = esp_sessions
            .iter()
            .filter(|session| sessions.contains(&session.session_id))
            .map(|session| session.evidence.clone())
            .collect::<Vec<_>>();
        conflicts.push(AutopilotConflict {
            conflict_id: "conflicting-esp-session-id".to_owned(),
            kind: AutopilotConflictKind::EspSessionIdentifier,
            detail: "A single correlation key resolves to more than one ESP session.".to_owned(),
            values: sessions.into_iter().collect(),
            evidence: normalized_evidence(evidence),
        });
    }

    // A report section that explicitly reports a mismatch is a conflict the
    // collector already detected; carrying it here keeps the two paths uniform.
    // Gated like every other path: an unreadable section cannot assert a
    // mismatch any more than it can assert a success.
    for section in sections
        .iter()
        .filter(|section| is_assessable_section(section))
        .filter(|section| section.outcome == AutopilotSectionOutcome::Mismatch)
    {
        conflicts.push(AutopilotConflict {
            conflict_id: format!("reported-mismatch-{}", section.section_id),
            kind: AutopilotConflictKind::DeviceIdentity,
            detail: section
                .message
                .clone()
                .unwrap_or_else(|| "A report section reported an identity mismatch.".to_owned()),
            values: section
                .values
                .iter()
                .map(|value| format!("{}={}", value.name, value.value))
                .collect(),
            evidence: vec![section.context.evidence_ref.clone()],
        });
    }

    conflicts.sort_by(|left, right| left.conflict_id.cmp(&right.conflict_id));
    conflicts
}

fn session_keys(session: &AutopilotEspSessionFact) -> Vec<AutopilotCorrelationKey> {
    [
        (
            AutopilotCorrelationKeyKind::EnrollmentId,
            session.enrollment_id.as_ref(),
        ),
        (
            AutopilotCorrelationKeyKind::CorrelationId,
            session.correlation_id.as_ref(),
        ),
        (
            AutopilotCorrelationKeyKind::ActivityId,
            session.activity_id.as_ref(),
        ),
        (
            AutopilotCorrelationKeyKind::EntraDeviceId,
            session.entra_device_id.as_ref(),
        ),
        (
            AutopilotCorrelationKeyKind::ManagedDeviceId,
            session.managed_device_id.as_ref(),
        ),
    ]
    .into_iter()
    .filter_map(|(kind, value)| {
        let value = value?.trim();
        (!value.is_empty()).then(|| AutopilotCorrelationKey {
            kind,
            value: value.to_ascii_lowercase(),
        })
    })
    .collect()
}

/// Which observations may contribute correlation keys.
///
/// The distinction is ADR-001's direction-aware gate applied to session
/// identity. Keys are the one input where *more* evidence is *more*
/// conservative: every additional key can only ever widen the set of ESP
/// sessions the bundle is entangled with, and a wider set means Conflicting,
/// never a stronger Linked. So conflict DETECTION reads every observation,
/// while PROOF of a link (the confident `Linked` state, and the `Completed`
/// outcome behind it) stays restricted to assessable records.
#[derive(Clone, Copy, PartialEq, Eq)]
enum AutopilotKeyGate {
    /// Assessable observations only: these keys may prove a link.
    Proving,
    /// Every observation, assessable or not: these keys may only detect
    /// conflicts and can never upgrade a linkage on their own.
    Detecting,
}

/// The explicit keys the Autopilot side of the bundle can offer.
///
/// Deliberately skips [`AutopilotSignal::EspSessionFact`] observations: an ESP
/// fact matching its own key would be a tautology, not a correlation.
fn autopilot_keys(
    observations: &[AutopilotObservation],
    gate: AutopilotKeyGate,
) -> BTreeSet<AutopilotCorrelationKey> {
    const NAMED_KEYS: [(&str, AutopilotCorrelationKeyKind); 5] = [
        ("enrollmentId", AutopilotCorrelationKeyKind::EnrollmentId),
        ("correlationId", AutopilotCorrelationKeyKind::CorrelationId),
        ("activityId", AutopilotCorrelationKeyKind::ActivityId),
        ("entraDeviceId", AutopilotCorrelationKeyKind::EntraDeviceId),
        (
            "managedDeviceId",
            AutopilotCorrelationKeyKind::ManagedDeviceId,
        ),
    ];

    let mut keys = BTreeSet::new();
    for observation in observations.iter().filter(|observation| {
        (gate == AutopilotKeyGate::Detecting || is_assessable(observation))
            && observation.signal != AutopilotSignal::EspSessionFact
    }) {
        for (name, kind) in NAMED_KEYS {
            let Some(value) = observation.named(name).map(str::trim) else {
                continue;
            };
            if !value.is_empty() {
                keys.insert(AutopilotCorrelationKey {
                    kind,
                    value: value.to_ascii_lowercase(),
                });
            }
        }
        if let Some(activity_id) = observation
            .activity_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            keys.insert(AutopilotCorrelationKey {
                kind: AutopilotCorrelationKeyKind::ActivityId,
                value: activity_id.to_ascii_lowercase(),
            });
        }
    }
    keys
}

fn reduce_esp_linkage(
    observations: &[AutopilotObservation],
    esp_sessions: &[AutopilotEspSessionFact],
    handoff: &AutopilotHandoff,
    conflicts: &[AutopilotConflict],
    time_basis: AutopilotTimeBasis,
) -> AutopilotEspLinkage {
    if esp_sessions.is_empty() {
        return AutopilotEspLinkage {
            state: if handoff.esp_observed {
                AutopilotEspLinkState::EvidenceMissing
            } else {
                AutopilotEspLinkState::NotObserved
            },
            confidence: if handoff.esp_observed {
                IntuneFindingConfidence::High
            } else {
                IntuneFindingConfidence::Low
            },
            matched_keys: Vec::new(),
            esp_session_ids: Vec::new(),
            evidence: normalized_evidence(handoff.evidence.clone()),
        };
    }

    if conflicts
        .iter()
        .any(|conflict| conflict.kind == AutopilotConflictKind::EspSessionIdentifier)
    {
        return AutopilotEspLinkage {
            state: AutopilotEspLinkState::Conflicting,
            confidence: IntuneFindingConfidence::High,
            matched_keys: Vec::new(),
            esp_session_ids: sorted_unique(
                esp_sessions
                    .iter()
                    .map(|session| session.session_id.clone()),
            ),
            evidence: normalized_evidence(
                esp_sessions
                    .iter()
                    .map(|session| session.evidence.clone())
                    .collect(),
            ),
        };
    }

    let proving_keys = autopilot_keys(observations, AutopilotKeyGate::Proving);
    let detecting_keys = autopilot_keys(observations, AutopilotKeyGate::Detecting);

    // Two match passes over the same sessions. `detected_*` uses every key the
    // bundle carries, assessable or not, because each extra key can only widen
    // the entangled-session set (the conservative direction). `matched_*` is
    // the assessable subset, the only one allowed to prove a link.
    let mut matched_keys = BTreeSet::new();
    let mut matched_sessions = BTreeSet::new();
    let mut evidence = Vec::new();
    let mut detected_keys = BTreeSet::new();
    let mut detected_sessions = BTreeSet::new();
    let mut detection_evidence = Vec::new();
    for session in esp_sessions {
        for key in session_keys(session) {
            if detecting_keys.contains(&key) {
                detected_sessions.insert(session.session_id.clone());
                detection_evidence.push(session.evidence.clone());
                if proving_keys.contains(&key) {
                    matched_keys.insert(key.clone());
                    matched_sessions.insert(session.session_id.clone());
                    evidence.push(session.evidence.clone());
                }
                detected_keys.insert(key);
            }
        }
    }

    // A single Autopilot phase can only have produced one ESP session, so keys
    // resolving to more than one session mean the identity space is ambiguous:
    // Conflicting, never a silent merge. This check runs on the *detecting*
    // set on purpose. A key carried only by a capped observation cannot prove
    // a link, but dropping it here would shrink the session set and collapse
    // Conflicting into Linked into Completed -- a non-assessable record
    // silently upgrading the conclusion, which is exactly what ADR-001
    // forbids.
    if detected_sessions.len() > 1 {
        for observation in observations
            .iter()
            .filter(|observation| observation.signal != AutopilotSignal::EspSessionFact)
        {
            // Non-assessable carriers are cited too: a capped record is the
            // very evidence of the entanglement this state reports. Citing is
            // not proving; the state it supports is the conservative one.
            if session_key_values(&detected_keys)
                .any(|value| observation_mentions(observation, value))
            {
                detection_evidence.push(observation.evidence_ref());
            }
        }
        return AutopilotEspLinkage {
            state: AutopilotEspLinkState::Conflicting,
            confidence: IntuneFindingConfidence::High,
            matched_keys: detected_keys.into_iter().collect(),
            esp_session_ids: detected_sessions.into_iter().collect(),
            evidence: normalized_evidence(detection_evidence),
        };
    }

    if matched_keys.is_empty() {
        // ESP facts exist but nothing binds them via an explicit key.
        // Only emit TimeOnlyCandidate when the collection's time basis is UTC
        // (timezone was declared and recognized) AND there is an actual
        // overlap between Autopilot observation timestamps and ESP session
        // start times. An unreliable time basis or a non-overlapping window
        // cannot support even a low-confidence proximity claim.
        let state = if time_basis == AutopilotTimeBasis::Utc
            && has_time_overlap(observations, esp_sessions)
        {
            AutopilotEspLinkState::TimeOnlyCandidate
        } else {
            AutopilotEspLinkState::NotObserved
        };
        return AutopilotEspLinkage {
            state,
            confidence: IntuneFindingConfidence::Low,
            matched_keys: Vec::new(),
            esp_session_ids: if state == AutopilotEspLinkState::TimeOnlyCandidate {
                sorted_unique(esp_sessions.iter().map(|s| s.session_id.clone()))
            } else {
                Vec::new()
            },
            evidence: if state == AutopilotEspLinkState::TimeOnlyCandidate {
                normalized_evidence(esp_sessions.iter().map(|s| s.evidence.clone()).collect())
            } else {
                Vec::new()
            },
        };
    }

    for observation in observations.iter().filter(|observation| {
        is_assessable(observation) && observation.signal != AutopilotSignal::EspSessionFact
    }) {
        if session_key_values(&matched_keys).any(|value| observation_mentions(observation, value)) {
            evidence.push(observation.evidence_ref());
        }
    }

    // `matched_sessions` is a subset of `detected_sessions`, and the multi-
    // session case already returned Conflicting above, so exactly one session
    // remains here and it was matched by an assessable key.
    AutopilotEspLinkage {
        state: AutopilotEspLinkState::Linked,
        confidence: IntuneFindingConfidence::High,
        matched_keys: matched_keys.into_iter().collect(),
        esp_session_ids: matched_sessions.into_iter().collect(),
        evidence: normalized_evidence(evidence),
    }
}

fn session_key_values(keys: &BTreeSet<AutopilotCorrelationKey>) -> impl Iterator<Item = &str> {
    keys.iter().map(|key| key.value.as_str())
}

/// Whether Autopilot observation timestamps and ESP session timestamps overlap.
/// Uses UTC string comparison on ISO-8601 timestamps; imprecise but sufficient
/// for a low-confidence time-only candidate gate (not for a hard conclusion).
fn has_time_overlap(
    observations: &[AutopilotObservation],
    esp_sessions: &[AutopilotEspSessionFact],
) -> bool {
    let ap_times: Vec<&str> = observations
        .iter()
        .filter(|obs| is_assessable(obs))
        .filter_map(|obs| {
            obs.context
                .source_timestamp
                .as_ref()
                .and_then(|ts| ts.normalized_utc.as_deref())
                .filter(|ts| !ts.is_empty())
        })
        .collect();
    let esp_times: Vec<&str> = esp_sessions
        .iter()
        .filter_map(|session| {
            session
                .started_at_utc
                .as_deref()
                .filter(|ts| !ts.is_empty())
        })
        .collect();
    if ap_times.is_empty() || esp_times.is_empty() {
        return false;
    }
    // Find the min/max of Autopilot times and check if any ESP time falls within.
    let ap_min = ap_times.iter().min().copied().unwrap_or("");
    let ap_max = ap_times.iter().max().copied().unwrap_or("");
    esp_times
        .iter()
        .any(|esp_t| *esp_t >= ap_min && *esp_t <= ap_max)
}

fn observation_mentions(observation: &AutopilotObservation, value: &str) -> bool {
    observation
        .named_data
        .iter()
        .any(|named| named.value.trim().eq_ignore_ascii_case(value))
        || observation
            .activity_id
            .as_deref()
            .is_some_and(|activity| activity.trim().eq_ignore_ascii_case(value))
}

// ── Phase, outcome, confidence ──────────────────────────────────────────────

fn reduce_phase(
    identity: &AutopilotDeviceIdentity,
    profile: &AutopilotProfileState,
    handoff: &AutopilotHandoff,
) -> AutopilotPhase {
    let mut phase = AutopilotPhase::NoEvidence;
    if identity.registration_state != AutopilotRegistrationState::Unknown
        || !identity.evidence.is_empty()
    {
        phase = phase.max(AutopilotPhase::IdentityObserved);
    }
    if profile.candidate_state != AutopilotProfileCandidateState::Unknown {
        phase = phase.max(AutopilotPhase::ProfileDiscovery);
    }
    if profile.retrieved {
        phase = phase.max(AutopilotPhase::ProfileRetrieved);
    }
    if profile.applied {
        phase = phase.max(AutopilotPhase::ProfileApplied);
    }
    if handoff.enrollment_observed {
        phase = phase.max(AutopilotPhase::EnrollmentHandoff);
    }
    if handoff.esp_observed {
        phase = phase.max(AutopilotPhase::EspHandoff);
    }
    phase
}

#[allow(clippy::too_many_arguments)]
fn reduce_outcome(
    capture_validated: bool,
    conflicts: &[AutopilotConflict],
    identity: &AutopilotDeviceIdentity,
    profile: &AutopilotProfileState,
    handoff: &AutopilotHandoff,
    esp_linkage: &AutopilotEspLinkage,
    observations: &[AutopilotObservation],
    sections: &[AutopilotReportSection],
) -> AutopilotOutcome {
    // An unvalidated build, schema, or document version refuses every terminal
    // conclusion. The evidence is still retained; only its meaning is withheld.
    if !capture_validated {
        return AutopilotOutcome::UnknownSchema;
    }
    if !conflicts.is_empty() {
        return AutopilotOutcome::ContradictoryEvidence;
    }
    if identity.registration_state == AutopilotRegistrationState::Mismatch
        || has_signal(observations, AutopilotSignal::TpmIdentityFailed)
    {
        return AutopilotOutcome::IdentityRegistrationMismatch;
    }
    if identity.registration_state == AutopilotRegistrationState::NotRegistered {
        return AutopilotOutcome::MissingRegistrationEvidence;
    }
    if matches!(
        profile.candidate_state,
        AutopilotProfileCandidateState::NoneAssigned
            | AutopilotProfileCandidateState::AssignedButMissing
    ) {
        return AutopilotOutcome::NoProfileCandidate;
    }
    if sections_of(sections, &AutopilotSectionKind::ProfileRetrieval)
        .any(|section| section.outcome == AutopilotSectionOutcome::Failed)
    {
        return AutopilotOutcome::ProfileRetrievalFailure;
    }
    if has_signal(observations, AutopilotSignal::ProfileApplicationFailed)
        || sections_of(sections, &AutopilotSectionKind::ProfileApplication)
            .any(|section| section.outcome == AutopilotSectionOutcome::Failed)
    {
        return AutopilotOutcome::ProfileApplicationFailure;
    }
    if profile.applied && handoff.esp_observed {
        // Direction-aware assessability gate (ADR-001). A non-assessable
        // section that explicitly recorded a failure or mismatch can prove
        // nothing -- including the failure itself, so the terminal failure
        // outcomes above stay reserved for assessable records -- but it must
        // still block a success claim. `InsufficientEvidence` is the honest
        // reduction: the bundle cannot support success while a failure is on
        // record, and cannot prove the failure while its record is
        // non-assessable. The recorded failure is surfaced by its own finding
        // rather than silently swallowed. The gate is symmetric across both
        // record shapes: a report section that recorded Failed/Mismatch, and
        // an event carrying a documented failure signal.
        if recorded_non_assessable_failure_sections(sections)
            .next()
            .is_some()
            || recorded_non_assessable_failure_observations(observations)
                .next()
                .is_some()
        {
            return AutopilotOutcome::InsufficientEvidence;
        }
        return match esp_linkage.state {
            AutopilotEspLinkState::EvidenceMissing => {
                AutopilotOutcome::HandoffReachedEspEvidenceMissing
            }
            // Matched explicitly rather than through `conflicts`: the
            // multiple-matched-sessions path records no `AutopilotConflict`,
            // so relying on the conflicts gate above would let an ambiguous
            // session identity fall through to `Completed` (ADR-003:
            // unresolved authoritative contradictions stay conservative).
            AutopilotEspLinkState::Conflicting => AutopilotOutcome::ContradictoryEvidence,
            _ => AutopilotOutcome::Completed,
        };
    }
    // A network or service symptom is only reported once every proven cause
    // above has been ruled out; that is what "without proven cause" means.
    if sections_of(sections, &AutopilotSectionKind::NetworkService)
        .any(|section| matches!(section.outcome, AutopilotSectionOutcome::Failed))
    {
        return AutopilotOutcome::NetworkOrServiceSymptom;
    }
    if sections_of(sections, &AutopilotSectionKind::ProfileRetrieval)
        .any(|section| section.outcome == AutopilotSectionOutcome::Retrying)
        || (has_signal(observations, AutopilotSignal::ProfilePolicyNotFound) && !profile.retrieved)
    {
        return AutopilotOutcome::RetryDeferred;
    }
    AutopilotOutcome::InsufficientEvidence
}

fn reduce_confidence(
    outcome: AutopilotOutcome,
    capture_validated: bool,
    time_basis: AutopilotTimeBasis,
    coverage: &[IntuneArtifactCoverage],
) -> IntuneFindingConfidence {
    if matches!(
        outcome,
        AutopilotOutcome::UnknownSchema
            | AutopilotOutcome::InsufficientEvidence
            | AutopilotOutcome::NetworkOrServiceSymptom
    ) {
        return IntuneFindingConfidence::Low;
    }
    let coverage_is_complete = coverage
        .iter()
        .all(|entry| entry.status == IntuneArtifactStatus::Available);
    if !capture_validated || time_basis != AutopilotTimeBasis::Utc || !coverage_is_complete {
        return IntuneFindingConfidence::Medium;
    }
    IntuneFindingConfidence::High
}

/// Name the smallest artifacts that would advance the diagnosis.
///
/// Ordered most-specific first, so a human collects one file rather than a
/// whole bundle when one file would settle it.
fn next_evidence_requests(
    outcome: AutopilotOutcome,
    esp_linkage: &AutopilotEspLinkage,
    esp_sessions_supplied: bool,
    coverage: &[IntuneArtifactCoverage],
) -> Vec<String> {
    let mut requests: Vec<String> = match outcome {
        AutopilotOutcome::NoProfileCandidate => vec![
            "The device's Autopilot registration and assigned deployment profile in Intune".to_owned(),
            format!("{AUTOPILOT_EVENT_CHANNEL} events 809 and 815"),
        ],
        AutopilotOutcome::ProfileRetrievalFailure => vec![
            format!("{AUTOPILOT_EVENT_CHANNEL} events 160, 100, and 161"),
            "The Autopilot section of an MdmDiagnosticsTool export (-area Autopilot)".to_owned(),
        ],
        AutopilotOutcome::ProfileApplicationFailure => vec![
            format!("{AUTOPILOT_EVENT_CHANNEL} events 172 and 153"),
            "TpmHliInfo_Output.txt from the same diagnostics bundle".to_owned(),
        ],
        AutopilotOutcome::IdentityRegistrationMismatch => vec![
            "The registered serial number and hardware hash for this device in Intune".to_owned(),
            format!("{AUTOPILOT_EVENT_CHANNEL} events 908 and 171"),
        ],
        AutopilotOutcome::MissingRegistrationEvidence => vec![
            format!("{AUTOPILOT_EVENT_CHANNEL} event 807"),
            "MdmDiagReport_RegistryDump.reg from the same diagnostics bundle".to_owned(),
        ],
        AutopilotOutcome::NetworkOrServiceSymptom => vec![
            "A network trace or proxy log covering the Autopilot service endpoints".to_owned(),
            format!("{AUTOPILOT_EVENT_CHANNEL} event 164"),
        ],
        AutopilotOutcome::RetryDeferred => vec![format!(
            "A later capture of {AUTOPILOT_EVENT_CHANNEL} once acquisition settles"
        )],
        AutopilotOutcome::HandoffReachedEspEvidenceMissing => {
            vec!["The ESP diagnostics bundle for the correlated enrollment".to_owned()]
        }
        AutopilotOutcome::ContradictoryEvidence => {
            vec!["A fresh single-pass collection, so the sources share one point in time".to_owned()]
        }
        AutopilotOutcome::UnknownSchema => vec![
            "A diagnostics export from a Windows build this build has validated rules for"
                .to_owned(),
        ],
        AutopilotOutcome::InsufficientEvidence => vec![
            format!("{AUTOPILOT_EVENT_CHANNEL} (microsoft-windows-moderndeployment-diagnostics-provider-autopilot.evtx)"),
            "An MdmDiagnosticsTool export covering the Autopilot area".to_owned(),
        ],
        AutopilotOutcome::Completed => Vec::new(),
    };

    // ESP facts were supplied but no explicit key bound them. The request for
    // a shared identifier is keyed on that situation, not on the linkage state
    // alone: the time gate can narrow the overlap window and turn
    // `TimeOnlyCandidate` into `NotObserved`, and the guidance -- go find the
    // identifier the two sides share -- must survive that downgrade rather
    // than vanish with it.
    if esp_sessions_supplied
        && matches!(
            esp_linkage.state,
            AutopilotEspLinkState::TimeOnlyCandidate | AutopilotEspLinkState::NotObserved
        )
    {
        requests.push(
            "An enrollment, correlation, or device identifier shared by the Autopilot and ESP evidence"
                .to_owned(),
        );
    }
    for entry in coverage
        .iter()
        .filter(|entry| entry.status != IntuneArtifactStatus::Available)
    {
        requests.push(format!(
            "Re-collect {} ({})",
            entry.artifact_id,
            status_wire(&entry.status)
        ));
    }
    requests.dedup();
    requests
}

fn status_wire(status: &IntuneArtifactStatus) -> String {
    serde_json::to_value(status)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default()
}

// ── Shared helpers ──────────────────────────────────────────────────────────

/// Sort and de-duplicate evidence so a snapshot is byte-identical across runs.
pub(super) fn normalized_evidence(mut evidence: Vec<IntuneEvidenceRef>) -> Vec<IntuneEvidenceRef> {
    evidence.sort();
    evidence.dedup();
    evidence
}

fn sorted_unique(values: impl IntoIterator<Item = String>) -> Vec<String> {
    values
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}
