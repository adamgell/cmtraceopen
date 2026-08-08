//! Findings derived from an immutable Autopilot snapshot.
//!
//! Shaped exactly like `crate::esp::rules`: one public entry point, one private
//! `push_*` per rule, and a shared constructor that **refuses to build a finding
//! citing neither evidence nor a coverage gap**. That refusal is the enforcement
//! point for the conservative-findings rule; a rule that finds nothing simply
//! returns nothing rather than asserting something unsupported.
//!
//! Every finding names the next smallest artifact that would settle it. "Collect
//! the whole MDM bundle" is not an answer when one event ID would do.

use crate::intune::evidence::{
    IntuneAccessState, IntuneArtifactStatus, IntuneEvidenceRef, IntuneFinding,
    IntuneFindingConfidence, IntuneFindingSeverity, IntuneParseState,
};

use super::models::*;
use super::reducer::normalized_evidence;
use super::sources::{
    is_validated_schema_version, is_validated_windows_build, AUTOPILOT_EVENT_CHANNEL,
};

/// Derive stable, read-only findings from a snapshot.
///
/// Deterministic: the rules run in a fixed order and each one sorts its own
/// evidence, so two runs over the same snapshot produce byte-identical output.
pub fn derive_findings(snapshot: &AutopilotSnapshot) -> Vec<IntuneFinding> {
    let mut findings = Vec::new();

    push_unknown_schema(snapshot, &mut findings);
    push_malformed_document(snapshot, &mut findings);
    push_contradictory_evidence(snapshot, &mut findings);
    push_identity_mismatch(snapshot, &mut findings);
    push_missing_registration(snapshot, &mut findings);
    push_no_profile_candidate(snapshot, &mut findings);
    push_profile_retrieval_failure(snapshot, &mut findings);
    push_profile_application_failure(snapshot, &mut findings);
    push_network_or_service_symptom(snapshot, &mut findings);
    push_retry_deferred(snapshot, &mut findings);
    push_esp_evidence_missing(snapshot, &mut findings);
    push_esp_time_only_candidate(snapshot, &mut findings);
    push_esp_link_conflicting(snapshot, &mut findings);
    push_esp_linked(snapshot, &mut findings);
    push_unreliable_timestamps(snapshot, &mut findings);
    push_coverage_gaps(snapshot, &mut findings);
    push_non_assessable_failure_recorded(snapshot, &mut findings);
    push_unclassified_records(snapshot, &mut findings);
    push_completed(snapshot, &mut findings);

    findings
}

// ── Schema and integrity ────────────────────────────────────────────────────

fn push_unknown_schema(snapshot: &AutopilotSnapshot, findings: &mut Vec<IntuneFinding>) {
    let unsupported = snapshot
        .documents
        .iter()
        .filter(|document| document.parse_state == IntuneParseState::Unsupported)
        .collect::<Vec<_>>();
    // Either declared capture value can be the one that failed validation.
    // Gating on `windows_build` alone left a capture that declared only an
    // unvalidated `autopilotSchemaVersion` with an unexplained `UnknownSchema`
    // outcome: every terminal rule was suppressed and no finding said why.
    let capture_unvalidated = snapshot.outcome == AutopilotOutcome::UnknownSchema
        && unsupported.is_empty()
        && (snapshot.capture.windows_build.is_some()
            || snapshot.capture.autopilot_schema_version.is_some());
    if unsupported.is_empty() && !capture_unvalidated {
        return;
    }

    let mut summary = if unsupported.is_empty() {
        let mut offenders = Vec::new();
        if !is_validated_windows_build(snapshot.capture.windows_build.as_deref()) {
            offenders.push(format!(
                "Windows build {}",
                snapshot
                    .capture
                    .windows_build
                    .as_deref()
                    .unwrap_or("unknown")
            ));
        }
        if !is_validated_schema_version(snapshot.capture.autopilot_schema_version.as_deref()) {
            offenders.push(format!(
                "Autopilot schema version {}",
                snapshot
                    .capture
                    .autopilot_schema_version
                    .as_deref()
                    .unwrap_or("unknown")
            ));
        }
        format!(
            "This build has no validated Autopilot rules for {}, so terminal semantics are \
             withheld and the evidence is retained raw.",
            offenders.join(" or ")
        )
    } else {
        format!(
            "{} supplied document(s) declare a kind or version this build has no validated \
             rules for. Their bytes are retained as raw evidence; their meaning is not.",
            unsupported.len()
        )
    };
    if let Some(detail) = unsupported
        .first()
        .and_then(|document| document.detail.clone())
    {
        summary.push(' ');
        summary.push_str(&detail);
    }

    push(
        findings,
        finding(
            "autopilot-unknown-schema",
            IntuneFindingSeverity::Warning,
            IntuneFindingConfidence::High,
            "Autopilot evidence uses a schema or build this release cannot interpret",
            &summary,
            &[
                "Confirm the Windows build and Autopilot diagnostics schema of the source device."
                    .to_owned(),
                "Re-collect on a build with validated rules, or upgrade CMTrace Open.".to_owned(),
            ],
            snapshot
                .coverage
                .iter()
                .filter(|entry| entry.status == IntuneArtifactStatus::Unsupported)
                .flat_map(|entry| entry.evidence.iter().cloned())
                .collect(),
            unsupported
                .iter()
                .map(|document| document.artifact_id.clone())
                .chain(
                    capture_unvalidated
                        .then(|| {
                            snapshot
                                .coverage
                                .iter()
                                .map(|entry| entry.artifact_id.clone())
                        })
                        .into_iter()
                        .flatten(),
                )
                .collect(),
        ),
    );
}

fn push_malformed_document(snapshot: &AutopilotSnapshot, findings: &mut Vec<IntuneFinding>) {
    let malformed = snapshot
        .documents
        .iter()
        .filter(|document| document.parse_state == IntuneParseState::Malformed)
        .collect::<Vec<_>>();
    if malformed.is_empty() {
        return;
    }
    let detail = malformed
        .iter()
        .filter_map(|document| document.detail.clone())
        .next()
        .unwrap_or_else(|| "The content is not a tagged Autopilot document.".to_owned());
    push(
        findings,
        finding(
            "autopilot-report-section-malformed",
            IntuneFindingSeverity::Warning,
            IntuneFindingConfidence::High,
            "An Autopilot report section could not be parsed",
            &format!(
                "{} supplied document(s) could not be interpreted, so any signal they carried is \
                 absent from this analysis rather than proven absent. {detail}",
                malformed.len()
            ),
            &[
                "Re-export the Autopilot section of the MDM diagnostics report.".to_owned(),
                "Confirm the export was not truncated in transit.".to_owned(),
            ],
            Vec::new(),
            malformed
                .iter()
                .map(|document| document.artifact_id.clone())
                .collect(),
        ),
    );
}

fn push_contradictory_evidence(snapshot: &AutopilotSnapshot, findings: &mut Vec<IntuneFinding>) {
    if snapshot.conflicts.is_empty() {
        return;
    }
    let summary = snapshot
        .conflicts
        .iter()
        .map(|conflict| conflict.detail.clone())
        .collect::<Vec<_>>()
        .join(" ");
    push(
        findings,
        finding(
            "autopilot-contradictory-sources",
            IntuneFindingSeverity::Error,
            IntuneFindingConfidence::High,
            "Supplied Autopilot sources contradict each other",
            &format!(
                "{summary} No single Autopilot outcome can be asserted while the sources disagree."
            ),
            &[
                "Re-collect the Autopilot evidence in one pass so every source describes the same \
                 point in time."
                    .to_owned(),
                "Confirm the bundle was not assembled from two devices or two provisioning \
                 attempts."
                    .to_owned(),
            ],
            snapshot
                .conflicts
                .iter()
                .flat_map(|conflict| conflict.evidence.iter().cloned())
                .collect(),
            Vec::new(),
        ),
    );
}

// ── Identity and registration ───────────────────────────────────────────────

fn push_identity_mismatch(snapshot: &AutopilotSnapshot, findings: &mut Vec<IntuneFinding>) {
    if terminal_semantics_withheld(snapshot) {
        return;
    }
    let tpm_failures = signal_evidence(snapshot, AutopilotSignal::TpmIdentityFailed);
    if snapshot.identity.registration_state != AutopilotRegistrationState::Mismatch
        && tpm_failures.is_empty()
    {
        return;
    }
    let mut evidence = snapshot.identity.evidence.clone();
    evidence.extend(tpm_failures);
    push(
        findings,
        finding(
            "autopilot-identity-registration-mismatch",
            IntuneFindingSeverity::Blocker,
            IntuneFindingConfidence::High,
            "The device's hardware identity does not match its Autopilot registration",
            "A cited record reports a serial number, product key, or TPM identity that disagrees \
             with the identity registered for this device. Provisioning cannot proceed until the \
             registration matches the hardware.",
            &[
                "Compare the registered serial number and hardware hash in Intune with the \
                 device's own values."
                    .to_owned(),
                format!("Read {AUTOPILOT_EVENT_CHANNEL} events 908 and 171 for the exact token."),
                "Deregister and re-register the device if the hardware was replaced.".to_owned(),
            ],
            normalized_evidence(evidence),
            Vec::new(),
        ),
    );
}

fn push_missing_registration(snapshot: &AutopilotSnapshot, findings: &mut Vec<IntuneFinding>) {
    if terminal_semantics_withheld(snapshot)
        || snapshot.identity.registration_state != AutopilotRegistrationState::NotRegistered
    {
        return;
    }
    let mut evidence = signal_evidence(snapshot, AutopilotSignal::DeviceNotRegistered);
    evidence.extend(snapshot.identity.evidence.iter().cloned());
    push(
        findings,
        finding(
            "autopilot-device-not-registered",
            IntuneFindingSeverity::Blocker,
            IntuneFindingConfidence::High,
            "The device is not registered for Windows Autopilot",
            "A cited record reports the device as not registered (ZtdDeviceIsNotRegistered), so \
             no deployment profile can be assigned to it.",
            &[
                "Confirm the device's hardware hash was imported into Intune.".to_owned(),
                "MdmDiagReport_RegistryDump.reg from the same bundle shows the registration state \
                 the client actually saw."
                    .to_owned(),
            ],
            normalized_evidence(evidence),
            Vec::new(),
        ),
    );
}

// ── Profile ─────────────────────────────────────────────────────────────────

fn push_no_profile_candidate(snapshot: &AutopilotSnapshot, findings: &mut Vec<IntuneFinding>) {
    if terminal_semantics_withheld(snapshot) {
        return;
    }
    let (title, summary) = match snapshot.profile.candidate_state {
        AutopilotProfileCandidateState::NoneAssigned => (
            "No Autopilot deployment profile is assigned to this device",
            "A cited record reports that no profile is assigned to the device and that the tenant \
             has no default profile, so there is nothing for Autopilot to apply.",
        ),
        AutopilotProfileCandidateState::AssignedButMissing => (
            "The assigned Autopilot deployment profile no longer exists",
            "A cited record reports that the profile assigned to this device has been deleted \
             without being unassigned first.",
        ),
        _ => return,
    };
    let mut evidence = signal_evidence(snapshot, AutopilotSignal::NoAssignedProfile);
    evidence.extend(signal_evidence(
        snapshot,
        AutopilotSignal::AssignedProfileMissing,
    ));
    evidence.extend(snapshot.profile.evidence.iter().cloned());
    push(
        findings,
        finding(
            "autopilot-no-profile-candidate",
            IntuneFindingSeverity::Blocker,
            IntuneFindingConfidence::High,
            title,
            summary,
            &[
                "Check the device's Autopilot device record and its group/profile assignment."
                    .to_owned(),
                format!("Read {AUTOPILOT_EVENT_CHANNEL} events 809 and 815."),
            ],
            normalized_evidence(evidence),
            Vec::new(),
        ),
    );
}

fn push_profile_retrieval_failure(snapshot: &AutopilotSnapshot, findings: &mut Vec<IntuneFinding>) {
    if snapshot.outcome != AutopilotOutcome::ProfileRetrievalFailure {
        return;
    }
    let mut summary = "A cited record reports that profile retrieval failed after acquisition \
                       began, so the device never received a profile to apply."
        .to_owned();
    if let Some(error) = &snapshot.profile.error {
        summary.push_str(&format!(" The reported code was {}.", error.raw));
    }
    push(
        findings,
        finding(
            "autopilot-profile-retrieval-failed",
            IntuneFindingSeverity::Blocker,
            IntuneFindingConfidence::High,
            "The Autopilot deployment profile could not be retrieved",
            &summary,
            &[
                format!(
                    "Read {AUTOPILOT_EVENT_CHANNEL} events 160, 100, and 161 in order to see how \
                     far acquisition got."
                ),
                "Confirm the Autopilot service endpoints are reachable from the provisioning \
                 network."
                    .to_owned(),
            ],
            normalized_evidence(snapshot.profile.evidence.clone()),
            Vec::new(),
        ),
    );
}

fn push_profile_application_failure(
    snapshot: &AutopilotSnapshot,
    findings: &mut Vec<IntuneFinding>,
) {
    if snapshot.outcome != AutopilotOutcome::ProfileApplicationFailure {
        return;
    }
    let mut summary = "A cited record reports that the retrieved profile could not be made \
                       available to the device, so its OOBE settings were never applied."
        .to_owned();
    if let Some(error) = &snapshot.profile.error {
        summary.push_str(&format!(" The reported code was {}.", error.raw));
    }
    let mut evidence = signal_evidence(snapshot, AutopilotSignal::ProfileApplicationFailed);
    evidence.extend(snapshot.profile.evidence.iter().cloned());
    push(
        findings,
        finding(
            "autopilot-profile-application-failed",
            IntuneFindingSeverity::Blocker,
            IntuneFindingConfidence::High,
            "The Autopilot deployment profile could not be applied",
            &summary,
            &[
                format!("Read {AUTOPILOT_EVENT_CHANNEL} events 172 and 153 for the HRESULT."),
                "TpmHliInfo_Output.txt from the same bundle shows whether TPM attestation is the \
                 underlying constraint."
                    .to_owned(),
            ],
            normalized_evidence(evidence),
            Vec::new(),
        ),
    );
}

fn push_network_or_service_symptom(
    snapshot: &AutopilotSnapshot,
    findings: &mut Vec<IntuneFinding>,
) {
    if snapshot.outcome != AutopilotOutcome::NetworkOrServiceSymptom {
        return;
    }
    push(
        findings,
        finding(
            "autopilot-network-symptom-without-cause",
            IntuneFindingSeverity::Warning,
            // Deliberately low: a connectivity symptom with every proven cause
            // ruled out is a lead, not a diagnosis.
            IntuneFindingConfidence::Low,
            "A network or service symptom was reported with no proven cause",
            "A cited record reports a network or service problem, but nothing in the bundle shows \
             which request failed or why. This is a lead to follow, not a root cause.",
            &[
                "Capture a network trace or proxy log covering the Autopilot service endpoints."
                    .to_owned(),
                format!(
                    "Confirm whether {AUTOPILOT_EVENT_CHANNEL} event 164 was ever logged for this \
                     attempt."
                ),
            ],
            normalized_evidence(
                snapshot
                    .observations
                    .iter()
                    .filter(|observation| {
                        observation.section_kind.as_ref()
                            == Some(&AutopilotSectionKind::NetworkService)
                    })
                    .map(AutopilotObservation::evidence_ref)
                    .collect(),
            ),
            Vec::new(),
        ),
    );
}

fn push_retry_deferred(snapshot: &AutopilotSnapshot, findings: &mut Vec<IntuneFinding>) {
    if snapshot.outcome != AutopilotOutcome::RetryDeferred {
        return;
    }
    push(
        findings,
        finding(
            "autopilot-acquisition-deferred",
            IntuneFindingSeverity::Info,
            IntuneFindingConfidence::Medium,
            "Autopilot profile acquisition is still retrying",
            "Acquisition began and the profile was reported as not yet found. Microsoft documents \
             this state as usually transient, so it is not treated as a failure here.",
            &[format!(
                "Re-collect {AUTOPILOT_EVENT_CHANNEL} once the device settles, and compare event \
                 100 against a later event 161."
            )],
            normalized_evidence(
                signal_evidence(snapshot, AutopilotSignal::ProfilePolicyNotFound)
                    .into_iter()
                    .chain(signal_evidence(
                        snapshot,
                        AutopilotSignal::ProfileAcquisitionStarted,
                    ))
                    .collect(),
            ),
            Vec::new(),
        ),
    );
}

// ── ESP sibling linkage ─────────────────────────────────────────────────────

fn push_esp_evidence_missing(snapshot: &AutopilotSnapshot, findings: &mut Vec<IntuneFinding>) {
    if snapshot.esp_linkage.state != AutopilotEspLinkState::EvidenceMissing {
        return;
    }
    push(
        findings,
        finding(
            "autopilot-esp-evidence-missing",
            IntuneFindingSeverity::Warning,
            IntuneFindingConfidence::High,
            "Autopilot handed off to ESP but no ESP evidence was supplied",
            "The local Autopilot phase reached the Enrollment Status Page handoff. What happened \
             after that point is owned by the ESP reducer, and this bundle contains none of its \
             evidence, so the deployment cannot be called complete or failed.",
            &[
                "Collect the ESP diagnostics bundle for the same enrollment and analyze it with \
                 the ESP workspace."
                    .to_owned(),
                "Carry the enrollment or correlation identifier across so the two analyses bind \
                 explicitly."
                    .to_owned(),
            ],
            normalized_evidence(snapshot.esp_linkage.evidence.clone()),
            Vec::new(),
        ),
    );
}

fn push_esp_time_only_candidate(snapshot: &AutopilotSnapshot, findings: &mut Vec<IntuneFinding>) {
    if snapshot.esp_linkage.state != AutopilotEspLinkState::TimeOnlyCandidate {
        return;
    }
    push(
        findings,
        finding(
            "autopilot-esp-link-time-only",
            IntuneFindingSeverity::Warning,
            // Never above low: this is the rule that stops a time-only join
            // from being presented as a correlation.
            IntuneFindingConfidence::Low,
            "ESP evidence exists but shares no identifier with the Autopilot evidence",
            "The supplied ESP session facts carry no enrollment, correlation, activity, or device \
             identifier in common with the Autopilot evidence. They may describe the same \
             provisioning attempt or a different one; proximity in time is not proof.",
            &[
                "Re-collect both sides in one pass so they share an enrollment or correlation \
                 identifier."
                    .to_owned(),
                "Compare the Entra device id recorded by each side.".to_owned(),
            ],
            normalized_evidence(snapshot.esp_linkage.evidence.clone()),
            Vec::new(),
        ),
    );
}

/// Explain a `Conflicting` ESP linkage that no recorded conflict covers.
///
/// The linkage turns `Conflicting` on two paths. When a single correlation key
/// resolves to more than one session, `detect_conflicts` records an
/// [`AutopilotConflictKind::EspSessionIdentifier`] conflict and
/// `push_contradictory_evidence` already explains it. When *distinct* keys
/// each resolve cleanly but to *different* sessions, no conflict is recorded;
/// this rule is what keeps that outcome from being silent.
fn push_esp_link_conflicting(snapshot: &AutopilotSnapshot, findings: &mut Vec<IntuneFinding>) {
    if snapshot.esp_linkage.state != AutopilotEspLinkState::Conflicting
        || snapshot
            .conflicts
            .iter()
            .any(|conflict| conflict.kind == AutopilotConflictKind::EspSessionIdentifier)
    {
        return;
    }
    push(
        findings,
        finding(
            "autopilot-esp-link-conflicting",
            IntuneFindingSeverity::Error,
            IntuneFindingConfidence::High,
            "The Autopilot evidence matches more than one ESP session",
            &format!(
                "Explicit correlation keys bind this Autopilot evidence to {} different ESP \
                 sessions ({}). A single Autopilot phase produces one session, so no completed \
                 handoff can be asserted. Two real sessions can exist legitimately -- a reimaged, \
                 reset, or re-enrolled device provisions more than once -- but this bundle does \
                 not say which session belongs to this attempt.",
                snapshot.esp_linkage.esp_session_ids.len(),
                snapshot.esp_linkage.esp_session_ids.join(", ")
            ),
            &[
                "If the device was reimaged or re-enrolled, both sessions may be real: identify \
                 the attempt under investigation and analyze its session on its own in the ESP \
                 workspace."
                    .to_owned(),
                "Otherwise re-collect both sides in one pass so the bundle describes a single \
                 provisioning attempt."
                    .to_owned(),
            ],
            normalized_evidence(snapshot.esp_linkage.evidence.clone()),
            Vec::new(),
        ),
    );
}

fn push_esp_linked(snapshot: &AutopilotSnapshot, findings: &mut Vec<IntuneFinding>) {
    if snapshot.esp_linkage.state != AutopilotEspLinkState::Linked {
        return;
    }
    push(
        findings,
        finding(
            "autopilot-esp-session-linked",
            IntuneFindingSeverity::Info,
            IntuneFindingConfidence::High,
            "Autopilot evidence is bound to an ESP session by an explicit key",
            &format!(
                "{} explicit correlation key(s) bind this Autopilot evidence to ESP session(s) {}. \
                 ESP remains the owner of everything after the handoff.",
                snapshot.esp_linkage.matched_keys.len(),
                snapshot.esp_linkage.esp_session_ids.join(", ")
            ),
            &["Continue the investigation in the ESP workspace for the cited session.".to_owned()],
            normalized_evidence(snapshot.esp_linkage.evidence.clone()),
            Vec::new(),
        ),
    );
}

// ── Coverage and time ───────────────────────────────────────────────────────

fn push_unreliable_timestamps(snapshot: &AutopilotSnapshot, findings: &mut Vec<IntuneFinding>) {
    if snapshot.time_basis == AutopilotTimeBasis::Utc {
        return;
    }
    let (title, why) = match snapshot.timezone_state {
        AutopilotTimezoneState::Missing => (
            "The capture declared no timezone",
            "no timezone was declared for the collection",
        ),
        AutopilotTimezoneState::Invalid => (
            "The capture declared an unrecognizable timezone",
            "the declared timezone is not a recognizable UTC offset or region identifier",
        ),
        AutopilotTimezoneState::Declared => (
            "Some Autopilot timestamps could not be normalized",
            "at least one record carried a wall-clock time with no explicit offset",
        ),
    };
    push(
        findings,
        finding(
            "autopilot-timestamps-unreliable",
            IntuneFindingSeverity::Warning,
            IntuneFindingConfidence::High,
            title,
            &format!(
                "Ordering fell back to record identity because {why}. No conclusion in this \
                 analysis relies on wall-clock time, and time-proximity correlation with an ESP \
                 session is refused outright."
            ),
            &[
                "Re-collect with the device's timezone recorded alongside the evidence.".to_owned(),
                "Prefer sources that emit an explicit UTC offset per record.".to_owned(),
            ],
            Vec::new(),
            // The gap is the capture itself, not any one artifact, so every
            // artifact in the bundle is named rather than singling one out.
            snapshot
                .coverage
                .iter()
                .map(|entry| entry.artifact_id.clone())
                .collect(),
        ),
    );
}

fn push_coverage_gaps(snapshot: &AutopilotSnapshot, findings: &mut Vec<IntuneFinding>) {
    let gaps = snapshot
        .coverage
        .iter()
        .filter(|entry| {
            matches!(
                entry.status,
                IntuneArtifactStatus::Missing
                    | IntuneArtifactStatus::PermissionDenied
                    | IntuneArtifactStatus::Capped
                    | IntuneArtifactStatus::Skipped
            )
        })
        .collect::<Vec<_>>();
    if gaps.is_empty() {
        return;
    }
    let detail = gaps
        .iter()
        .filter_map(|entry| entry.detail.clone())
        .collect::<Vec<_>>()
        .join(" ");
    push(
        findings,
        finding(
            "autopilot-evidence-coverage-gap",
            IntuneFindingSeverity::Warning,
            IntuneFindingConfidence::High,
            "Expected Autopilot evidence was incomplete",
            &format!(
                "{} expected artifact(s) were missing, truncated, skipped, or unreadable. The \
                 absence of a signal in them proves nothing. {detail}",
                gaps.len()
            ),
            &[
                "Re-collect the cited artifacts, elevated, before ruling anything out.".to_owned(),
                format!(
                    "microsoft-windows-moderndeployment-diagnostics-provider-autopilot.evtx carries \
                     {AUTOPILOT_EVENT_CHANNEL} in full."
                ),
            ],
            gaps.iter()
                .flat_map(|entry| entry.evidence.iter().cloned())
                .collect(),
            gaps.iter()
                .map(|entry| entry.artifact_id.clone())
                .collect(),
        ),
    );
}

/// Surface a failure that is on the record but not assessable.
///
/// ADR-001's direction-aware gate: a capped or unparsed record can prove
/// nothing -- so the reducer neither completes the enrollment over it nor
/// turns it into a terminal failure outcome -- but a recorded failure must
/// never be *silent*. This rule is the surface for that middle state: it names
/// the record, says why the failure cannot be trusted yet, and asks for the
/// one artifact that would settle it. Both record shapes are covered: a
/// report section whose outcome is `Failed`/`Mismatch`, and an event carrying
/// a documented failure signal ([`AutopilotSignal::is_terminal_failure`]) --
/// the same two classes whose recorded failure blocks the success branch in
/// the reducer. Deliberately not gated by `terminal_semantics_withheld`: like
/// coverage gaps, this describes the bundle, not a cause.
fn push_non_assessable_failure_recorded(
    snapshot: &AutopilotSnapshot,
    findings: &mut Vec<IntuneFinding>,
) {
    let recorded = snapshot
        .observations
        .iter()
        .filter(|observation| {
            observation.context.access_state != IntuneAccessState::Available
                || observation.context.parse_state != IntuneParseState::Parsed
        })
        .filter(|observation| {
            let failed_section = observation.signal == AutopilotSignal::ReportSection
                && matches!(
                    observation.section_outcome,
                    Some(AutopilotSectionOutcome::Failed) | Some(AutopilotSectionOutcome::Mismatch)
                );
            failed_section || observation.signal.is_terminal_failure()
        })
        .collect::<Vec<_>>();
    if recorded.is_empty() {
        return;
    }
    push(
        findings,
        finding(
            "autopilot-non-assessable-failure-recorded",
            IntuneFindingSeverity::Warning,
            // Low on purpose: non-assessable evidence cannot support a
            // confident conclusion in either direction (ADR-001). The finding
            // exists so the recorded failure blocks success visibly instead of
            // silently.
            IntuneFindingConfidence::Low,
            "A record that could not be fully read recorded a failure",
            &format!(
                "{} record(s) whose own capture or parse state is not assessable explicitly \
                 recorded a failure -- a failed or mismatched report section, or an event \
                 carrying a documented failure signal. That record cannot prove the failure, but \
                 it blocks any success conclusion until it is re-collected in a readable form.",
                recorded.len()
            ),
            &[
                "Re-collect the cited record(s), complete and readable, before trusting any \
                 success signal from this bundle."
                    .to_owned(),
                "Compare the re-collected record's outcome against the sibling assessable \
                 evidence."
                    .to_owned(),
            ],
            normalized_evidence(
                recorded
                    .iter()
                    .map(|observation| observation.evidence_ref())
                    .collect(),
            ),
            Vec::new(),
        ),
    );
}

fn push_unclassified_records(snapshot: &AutopilotSnapshot, findings: &mut Vec<IntuneFinding>) {
    if snapshot.unclassified_observation_ids.is_empty() {
        return;
    }
    let evidence = snapshot
        .unclassified_observation_ids
        .iter()
        .filter_map(|id| snapshot.observation(id))
        .map(AutopilotObservation::evidence_ref)
        .collect::<Vec<_>>();
    push(
        findings,
        finding(
            "autopilot-undocumented-events-retained",
            IntuneFindingSeverity::Info,
            IntuneFindingConfidence::High,
            "Autopilot records with no documented meaning were retained",
            &format!(
                "{} record(s) came from the Autopilot channel with an event ID this build has no \
                 documented meaning for. They are kept as raw evidence and deliberately given no \
                 terminal semantics.",
                snapshot.unclassified_observation_ids.len()
            ),
            &[
                "Read the cited records directly; their message text may still be informative."
                    .to_owned(),
            ],
            normalized_evidence(evidence),
            Vec::new(),
        ),
    );
}

fn push_completed(snapshot: &AutopilotSnapshot, findings: &mut Vec<IntuneFinding>) {
    if snapshot.outcome != AutopilotOutcome::Completed {
        return;
    }
    let mut evidence = snapshot.profile.evidence.clone();
    evidence.extend(snapshot.handoff.evidence.iter().cloned());
    push(
        findings,
        finding(
            "autopilot-phase-completed",
            IntuneFindingSeverity::Info,
            IntuneFindingConfidence::High,
            "The local Autopilot phase completed and handed off",
            "A profile was retrieved and applied, and the handoff into enrollment and the \
             Enrollment Status Page was observed. Everything after this point belongs to the ESP \
             analysis, not to Autopilot.",
            &["Review the correlated ESP session for what happened after the handoff.".to_owned()],
            normalized_evidence(evidence),
            Vec::new(),
        ),
    );
}

// ── Construction ────────────────────────────────────────────────────────────

/// Whether this snapshot may assert a terminal cause at all.
///
/// When the Windows build, Autopilot schema, or a supplied document version is
/// one this release has no validated rules for, the reducer reports
/// [`AutopilotOutcome::UnknownSchema`]. Rules that key on a *state* rather than
/// on the outcome must consult this, or a blocking finding sails past the very
/// refusal the outcome exists to express. Rules that already key on
/// `snapshot.outcome` are gated by construction.
///
/// Evidence-level rules -- coverage gaps, malformed documents, unreliable
/// timestamps, ESP linkage -- are deliberately *not* gated: those describe the
/// bundle, not a cause, and stay true whatever the schema turns out to mean.
fn terminal_semantics_withheld(snapshot: &AutopilotSnapshot) -> bool {
    snapshot.outcome == AutopilotOutcome::UnknownSchema
}

fn signal_evidence(
    snapshot: &AutopilotSnapshot,
    signal: AutopilotSignal,
) -> Vec<IntuneEvidenceRef> {
    snapshot
        .observations
        .iter()
        .filter(|observation| observation.signal == signal)
        .map(AutopilotObservation::evidence_ref)
        .collect()
}

/// Build a finding, or nothing when it would cite neither evidence nor a gap.
///
/// This is the single enforcement point for the invariant
/// [`IntuneFinding::is_evidence_backed`] describes. Keeping it here means no
/// individual rule can forget it.
#[allow(clippy::too_many_arguments)]
fn finding(
    id: &str,
    severity: IntuneFindingSeverity,
    confidence: IntuneFindingConfidence,
    title: &str,
    summary: &str,
    recommended_checks: &[String],
    evidence: Vec<IntuneEvidenceRef>,
    coverage_gap_ids: Vec<String>,
) -> Option<IntuneFinding> {
    let evidence = normalized_evidence(evidence);
    let mut coverage_gap_ids = coverage_gap_ids;
    coverage_gap_ids.sort();
    coverage_gap_ids.dedup();
    if evidence.is_empty() && coverage_gap_ids.is_empty() {
        return None;
    }
    Some(IntuneFinding {
        finding_id: id.to_owned(),
        severity,
        confidence,
        title: title.to_owned(),
        summary: summary.to_owned(),
        recommended_checks: recommended_checks.to_vec(),
        evidence,
        coverage_gap_ids,
    })
}

fn push(findings: &mut Vec<IntuneFinding>, finding: Option<IntuneFinding>) {
    if let Some(finding) = finding {
        findings.push(finding);
    }
}
