//! Public types for Windows Autopilot identity, profile, and OOBE evidence.
//!
//! These describe *what the evidence showed*, never what the reducer guessed.
//! Every state that implies an outcome is reachable only from an explicit,
//! citable record; everything else lands in
//! [`AutopilotOutcome::InsufficientEvidence`] alongside a named next artifact.
//!
//! The Autopilot contract is a **sibling** of `crate::esp`, not a superset of
//! it. Autopilot owns device identity/registration, profile discovery,
//! retrieval and application, OOBE facts, and the handoff into enrollment and
//! ESP. ESP continues to own app/profile progress and blocking status *after*
//! that handoff. The only thing the two share is an explicit correlation key;
//! see [`AutopilotEspLinkage`].

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::intune::evidence::{
    intune_raw_preserving_string_enum, IntuneArtifactCoverage, IntuneErrorCode, IntuneEvidenceRef,
    IntuneFinding, IntuneFindingConfidence, IntuneNamedValue, IntuneObservationContext,
    IntuneParseState,
};

/// Schema version of the Autopilot snapshot contract.
///
/// Bump only on a breaking change. Adding an optional field, or a variant to
/// one of the raw-preserving enums below, is additive.
pub const AUTOPILOT_SNAPSHOT_SCHEMA_VERSION: u32 = 1;

intune_raw_preserving_string_enum! {
    /// The deployment mode a profile declared.
    ///
    /// Raw-preserving: Microsoft adds modes without warning, and an
    /// unrecognized mode must survive export verbatim rather than becoming a
    /// mode this build happens to know.
    pub enum AutopilotDeploymentProfileType {
        UserDriven => "userDriven",
        SelfDeploying => "selfDeploying",
        PreProvisioning => "preProvisioning",
        HybridJoin => "hybridJoin",
        ExistingDevice => "existingDevice",
    }
}

intune_raw_preserving_string_enum! {
    /// An OOBE setting override token, as the Autopilot provider wrote it.
    ///
    /// Values such as `AUTOPILOT_OOBE_SETTINGS_AAD_JOIN_ONLY` come straight
    /// from event 109 and are not a closed set.
    pub enum AutopilotOobeSetting {
        AadJoinOnly => "AUTOPILOT_OOBE_SETTINGS_AAD_JOIN_ONLY",
        SkipKeyboard => "AUTOPILOT_OOBE_SETTINGS_SKIP_KEYBOARD",
        SkipEula => "AUTOPILOT_OOBE_SETTINGS_SKIP_EULA",
    }
}

intune_raw_preserving_string_enum! {
    /// A `ProfileState_*` token from event 153's state transition message.
    ///
    /// `ProfileUnknown` is Windows' own `ProfileState_Unknown` token, which is
    /// a real observed state and quite distinct from the macro-generated
    /// `Unknown(String)` catch-all for a token this build does not recognize.
    pub enum AutopilotProfileStateToken {
        ProfileUnknown => "ProfileState_Unknown",
        Available => "ProfileState_Available",
        Unavailable => "ProfileState_Unavailable",
        Provisioned => "ProfileState_Provisioned",
    }
}

/// A record-level signal, classified from a validated source contract.
///
/// Event-derived variants carry the Microsoft-documented event ID they are
/// keyed on. Every event ID outside that documented table classifies as
/// [`AutopilotSignal::Unclassified`] and is retained as raw evidence: an
/// undocumented event may not carry terminal semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AutopilotSignal {
    /// Event 160: `AutopilotRetrieveSettings beginning acquisition.`
    ProfileAcquisitionStarted,
    /// Event 164: internet available to attempt policy download.
    NetworkAvailableForDownload,
    /// Event 100: `Autopilot policy [name] not found.` Documented as typically
    /// transient, so this is explicitly **not** a terminal failure.
    ProfilePolicyNotFound,
    /// Event 161: `AutopilotManager retrieve settings succeeded.`
    ProfileRetrieveSucceeded,
    /// Event 153: `AutopilotManager reported the state changed from X to Y.`
    ProfileStateChanged,
    /// Event 111: `AutopilotRetrieveSettings succeeded.`
    ProfileSettingsRetrieved,
    /// Events 101, 103, 109: an OOBE setting was retrieved and processed.
    OobeSettingObserved,
    /// Event 163: download not required, the device is already provisioned.
    DeviceAlreadyProvisioned,
    /// Event 171: failed to set TPM identity confirmed.
    TpmIdentityFailed,
    /// Event 172: failed to set the Autopilot profile as available.
    ProfileApplicationFailed,
    /// Event 807: `ZtdDeviceIsNotRegistered`.
    DeviceNotRegistered,
    /// Event 809: the assigned profile no longer exists.
    AssignedProfileMissing,
    /// Event 815: no profile assigned and no tenant default.
    NoAssignedProfile,
    /// Event 908: serial number or product key mismatch.
    IdentityMismatch,
    /// A diagnostics-report or supplied-fact section, classified by its own
    /// declared section kind rather than by an event ID.
    ReportSection,
    /// A normalized ESP session fact supplied by the sibling reducer.
    EspSessionFact,
    /// A record from a validated channel carrying no documented meaning.
    Unclassified,
}

impl AutopilotSignal {
    /// Whether this signal by itself proves a terminal Autopilot failure.
    pub fn is_terminal_failure(self) -> bool {
        matches!(
            self,
            Self::TpmIdentityFailed
                | Self::ProfileApplicationFailed
                | Self::DeviceNotRegistered
                | Self::AssignedProfileMissing
                | Self::NoAssignedProfile
                | Self::IdentityMismatch
        )
    }
}

intune_raw_preserving_string_enum! {
    /// What a diagnostics-report section describes.
    pub enum AutopilotSectionKind {
        DeviceIdentity => "deviceIdentity",
        ProfileRetrieval => "profileRetrieval",
        ProfileApplication => "profileApplication",
        OobeMode => "oobeMode",
        EnrollmentHandoff => "enrollmentHandoff",
        EspHandoff => "espHandoff",
        NetworkService => "networkService",
        DiagnosticsPage => "diagnosticsPage",
    }
}

intune_raw_preserving_string_enum! {
    /// What a diagnostics-report section reported.
    ///
    /// `NotFound` and `Failed` are separate on purpose: "the service had
    /// nothing for this device" and "the attempt errored" lead to different
    /// next steps and different findings.
    pub enum AutopilotSectionOutcome {
        Succeeded => "succeeded",
        Failed => "failed",
        NotFound => "notFound",
        Retrying => "retrying",
        Mismatch => "mismatch",
        Observed => "observed",
    }
}

/// Whether the collection's declared timezone can be trusted.
///
/// The pure crate carries no timezone database, so this classifies the
/// declared value's *shape* only: a fixed UTC offset, `UTC`/`Z`, or an
/// `Area/City` identifier. Anything else is [`AutopilotTimezoneState::Invalid`],
/// which is a coverage fact, not a parse failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AutopilotTimezoneState {
    Declared,
    Missing,
    Invalid,
}

/// Whether observation ordering may rely on wall-clock time.
///
/// `Unreliable` forbids every time-based inference in the reducer, including
/// time-proximity correlation with an ESP session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AutopilotTimeBasis {
    Utc,
    Unreliable,
}

/// Collection-side metadata supplied with a bundle.
///
/// None of this can be discovered by the pure crate; a native collector states
/// it, and the reducer refuses terminal semantics when the declared Windows
/// build or Autopilot schema is one this build has no validated rules for.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AutopilotCaptureMetadata {
    pub collected_at_utc: Option<String>,
    pub windows_build: Option<String>,
    pub autopilot_schema_version: Option<String>,
    pub timezone: Option<String>,
}

/// One document the reducer was handed, and what became of it.
///
/// This is the reducer's own judgment about the bytes, kept separate from the
/// collector's declared capture state so a collector that reports success over
/// unreadable content cannot launder it into coverage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AutopilotDocumentReport {
    pub artifact_id: String,
    pub declared_kind: Option<String>,
    pub declared_version: Option<u32>,
    pub parse_state: IntuneParseState,
    pub detail: Option<String>,
    pub observation_ids: Vec<String>,
}

/// A classified Autopilot record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AutopilotObservation {
    pub observation_id: String,
    pub context: IntuneObservationContext,
    pub signal: AutopilotSignal,
    pub channel: Option<String>,
    pub provider: Option<String>,
    pub event_id: Option<u32>,
    pub event_version: Option<u32>,
    pub activity_id: Option<String>,
    pub section_kind: Option<AutopilotSectionKind>,
    pub section_outcome: Option<AutopilotSectionOutcome>,
    pub error: Option<IntuneErrorCode>,
    pub named_data: Vec<IntuneNamedValue>,
    /// Verbatim record text. Sensitive: Autopilot messages quote tenant names,
    /// serial numbers, and UPNs.
    pub message: Option<String>,
}

impl AutopilotObservation {
    /// The evidence pointer this observation is cited by.
    pub fn evidence_ref(&self) -> IntuneEvidenceRef {
        self.context.evidence_ref.clone()
    }

    /// Look up one named-data value, case-insensitively.
    pub fn named(&self, name: &str) -> Option<&str> {
        self.named_data
            .iter()
            .find(|value| value.name.eq_ignore_ascii_case(name))
            .map(|value| value.value.as_str())
    }
}

/// Identity and registration evidence for the device being provisioned.
///
/// Every field is `Option` because absence is itself a diagnostic fact:
/// a bundle with no serial number cannot be used to prove a serial mismatch.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AutopilotDeviceIdentity {
    pub serial_number: Option<String>,
    pub hardware_hash: Option<String>,
    pub product_key_id: Option<String>,
    pub ztd_registration_id: Option<String>,
    pub entra_device_id: Option<String>,
    pub managed_device_id: Option<String>,
    pub tenant_id: Option<String>,
    pub tenant_domain: Option<String>,
    pub device_name: Option<String>,
    pub registration_state: AutopilotRegistrationState,
    pub evidence: Vec<IntuneEvidenceRef>,
}

/// Whether the device's Autopilot registration was proven.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AutopilotRegistrationState {
    /// No registration evidence was present either way.
    #[default]
    Unknown,
    Registered,
    /// The service explicitly reported the device as not registered.
    NotRegistered,
    /// Registered identity and observed hardware identity disagree.
    Mismatch,
}

/// Profile discovery, retrieval, and application evidence.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AutopilotProfileState {
    pub profile_id: Option<String>,
    pub profile_name: Option<String>,
    pub deployment_profile_type: Option<AutopilotDeploymentProfileType>,
    pub candidate_state: AutopilotProfileCandidateState,
    pub last_state_token: Option<AutopilotProfileStateToken>,
    pub retrieved: bool,
    pub applied: bool,
    pub error: Option<IntuneErrorCode>,
    pub evidence: Vec<IntuneEvidenceRef>,
}

/// Whether a profile candidate was ever proven to exist for this device.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AutopilotProfileCandidateState {
    #[default]
    Unknown,
    /// A profile was assigned and made available to the device.
    Available,
    /// The service explicitly reported no assigned profile and no default.
    NoneAssigned,
    /// A profile was assigned but the referenced profile no longer exists.
    AssignedButMissing,
    /// Acquisition started and is still pending; documented as transient.
    Pending,
}

/// OOBE facts observed for this deployment.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AutopilotOobeState {
    pub settings: Vec<AutopilotOobeSettingObservation>,
    pub already_provisioned: bool,
    pub evidence: Vec<IntuneEvidenceRef>,
}

/// One OOBE setting override and the state it was reported in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AutopilotOobeSettingObservation {
    pub setting: AutopilotOobeSetting,
    pub state: Option<String>,
    pub evidence: IntuneEvidenceRef,
}

/// The handoff out of the local Autopilot phase.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AutopilotHandoff {
    pub enrollment_observed: bool,
    pub esp_observed: bool,
    pub enrollment_id: Option<String>,
    pub correlation_id: Option<String>,
    pub evidence: Vec<IntuneEvidenceRef>,
}

/// How an Autopilot bundle relates to an ESP session.
///
/// Linkage is a claim about identity, not about time. `Linked` requires an
/// explicit shared enrollment, correlation, activity, or device key. Overlapping
/// timestamps alone can only ever produce [`AutopilotEspLinkState::TimeOnlyCandidate`]
/// at low confidence, and are refused outright when the time basis is unreliable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AutopilotEspLinkage {
    pub state: AutopilotEspLinkState,
    pub confidence: IntuneFindingConfidence,
    /// The keys that actually matched, empty for every non-`Linked` state.
    pub matched_keys: Vec<AutopilotCorrelationKey>,
    pub esp_session_ids: Vec<String>,
    pub evidence: Vec<IntuneEvidenceRef>,
}

impl Default for AutopilotEspLinkage {
    fn default() -> Self {
        Self {
            state: AutopilotEspLinkState::NotObserved,
            confidence: IntuneFindingConfidence::Low,
            matched_keys: Vec::new(),
            esp_session_ids: Vec::new(),
            evidence: Vec::new(),
        }
    }
}

/// The relationship between Autopilot evidence and ESP evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AutopilotEspLinkState {
    /// No ESP facts were supplied and no handoff was observed.
    NotObserved,
    /// A shared explicit key bound the two.
    Linked,
    /// ESP facts exist but share no key; only the time ranges overlap.
    TimeOnlyCandidate,
    /// A handoff into ESP was observed but no ESP facts were supplied.
    EvidenceMissing,
    /// The same key resolves to more than one ESP session.
    Conflicting,
}

/// One explicit key that bound Autopilot evidence to ESP evidence.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AutopilotCorrelationKey {
    pub kind: AutopilotCorrelationKeyKind,
    pub value: String,
}

/// Which identity a correlation key expresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AutopilotCorrelationKeyKind {
    EnrollmentId,
    CorrelationId,
    ActivityId,
    EntraDeviceId,
    ManagedDeviceId,
}

/// A supplied, already-normalized ESP session fact.
///
/// This is a read-only projection of the sibling reducer's output. Nothing here
/// re-derives ESP state; the Autopilot reducer only checks whether an explicit
/// key binds the two.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AutopilotEspSessionFact {
    pub session_id: String,
    pub enrollment_id: Option<String>,
    pub correlation_id: Option<String>,
    pub activity_id: Option<String>,
    pub entra_device_id: Option<String>,
    pub managed_device_id: Option<String>,
    pub started_at_utc: Option<String>,
    pub phase: Option<String>,
    pub evidence: IntuneEvidenceRef,
}

/// Two sources that cannot both be true.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AutopilotConflict {
    pub conflict_id: String,
    pub kind: AutopilotConflictKind,
    pub detail: String,
    /// The distinct values observed, sorted, so the conflict is reproducible.
    pub values: Vec<String>,
    pub evidence: Vec<IntuneEvidenceRef>,
}

/// What kind of contradiction was observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AutopilotConflictKind {
    ProfileIdentifier,
    EspSessionIdentifier,
    DeviceIdentity,
}

/// The furthest local Autopilot phase with direct evidence.
///
/// This is the furthest phase *proven*, never the furthest phase assumed. The
/// ordering is deliberate: `PartialOrd` is what lets the reducer take a maximum
/// rather than track a state machine that could regress on out-of-order input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AutopilotPhase {
    /// Nothing was proven.
    NoEvidence,
    /// Device identity or registration evidence exists.
    IdentityObserved,
    /// Profile acquisition began.
    ProfileDiscovery,
    /// A profile was retrieved.
    ProfileRetrieved,
    /// A profile's OOBE settings were applied.
    ProfileApplied,
    /// The handoff into MDM enrollment was observed.
    EnrollmentHandoff,
    /// The handoff into ESP / Device Preparation was observed.
    EspHandoff,
}

/// The reduced diagnosis for the local Autopilot phase.
///
/// Exactly one outcome is reported. The reducer's precedence puts identity and
/// profile-availability failures ahead of downstream symptoms, because a device
/// that is not registered cannot meaningfully be described as having a network
/// problem.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AutopilotOutcome {
    /// The local Autopilot phase completed and handed off.
    Completed,
    /// Handoff into ESP was observed but no ESP evidence was supplied.
    HandoffReachedEspEvidenceMissing,
    /// No profile was assigned to this device.
    NoProfileCandidate,
    /// A profile exists but could not be retrieved.
    ProfileRetrievalFailure,
    /// A profile was retrieved but could not be applied.
    ProfileApplicationFailure,
    /// Registered identity and observed hardware identity disagree.
    IdentityRegistrationMismatch,
    /// The device is not registered, or registration evidence is absent.
    MissingRegistrationEvidence,
    /// A network or service symptom with no proven cause.
    NetworkOrServiceSymptom,
    /// Acquisition is pending or explicitly retrying; documented as transient.
    RetryDeferred,
    /// Sources contradict each other.
    ContradictoryEvidence,
    /// A document, Windows build, or Autopilot schema this build has no
    /// validated rules for. Terminal semantics are refused.
    UnknownSchema,
    /// Nothing in the bundle supports any conclusion.
    InsufficientEvidence,
}

/// The immutable public result of reducing an Autopilot bundle.
///
/// Every field is derived; nothing here is mutated after
/// [`crate::intune::enrollment::windows::autopilot::reduce_autopilot_bundle`]
/// returns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AutopilotSnapshot {
    pub schema_version: u32,
    pub generated_at_utc: String,
    pub capture: AutopilotCaptureMetadata,
    pub timezone_state: AutopilotTimezoneState,
    pub time_basis: AutopilotTimeBasis,
    pub identity: AutopilotDeviceIdentity,
    pub profile: AutopilotProfileState,
    pub oobe: AutopilotOobeState,
    pub handoff: AutopilotHandoff,
    pub esp_linkage: AutopilotEspLinkage,
    pub phase: AutopilotPhase,
    pub outcome: AutopilotOutcome,
    pub confidence: IntuneFindingConfidence,
    /// The smallest artifacts that would advance this diagnosis, in the order a
    /// human should collect them.
    pub next_evidence_requests: Vec<String>,
    pub observations: Vec<AutopilotObservation>,
    /// Records from a validated channel that carried no documented meaning.
    /// Retained so an undocumented event stays visible instead of vanishing.
    pub unclassified_observation_ids: Vec<String>,
    pub documents: Vec<AutopilotDocumentReport>,
    pub conflicts: Vec<AutopilotConflict>,
    pub coverage: Vec<IntuneArtifactCoverage>,
    pub findings: Vec<IntuneFinding>,
}

impl AutopilotSnapshot {
    /// Look up one observation by id.
    pub fn observation(&self, observation_id: &str) -> Option<&AutopilotObservation> {
        self.observations
            .iter()
            .find(|observation| observation.observation_id == observation_id)
    }

    /// Whether every finding cites evidence or a coverage gap.
    ///
    /// The reducer already refuses to emit an uncited finding; this exists so a
    /// consumer can assert the invariant rather than trust it.
    pub fn findings_are_evidence_backed(&self) -> bool {
        self.findings.iter().all(IntuneFinding::is_evidence_backed)
    }
}
