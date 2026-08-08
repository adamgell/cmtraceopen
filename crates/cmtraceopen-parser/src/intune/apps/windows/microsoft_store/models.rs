//! Public types for Intune-managed Microsoft Store app evidence.
//!
//! The organising decision in this module is that there is no single "Store app"
//! installer grammar. A UWP/MSIX package registered for one user, the same
//! payload provisioned for every user on the device, and a Store-delivered Win32
//! package reach terminal states through different mechanisms, report different
//! errors, and are fixed by different actions. Collapsing them behind one
//! `installed / failed` enum would make the analyzer confidently wrong, so
//! [`StoreInstallerFamily`] is a required field on every transaction and
//! [`StoreInstallerFamily::Unknown`] is a real answer rather than a placeholder.
//!
//! Everything shared with the rest of the Intune parser family — provenance,
//! coverage, findings, timestamps, error codes — comes from
//! [`crate::intune::evidence`]. This module deliberately defines no parallel
//! sensitivity, evidence-reference, or coverage type.

use serde::{Deserialize, Serialize};

use crate::intune::evidence::{
    IntuneArtifactCoverage, IntuneArtifactStatus, IntuneErrorCode, IntuneEvidenceRef,
    IntuneFinding, IntuneFindingConfidence, IntuneNamedValue, IntuneObservationContext,
    IntuneSourceKind,
};
use crate::intune::normalized::NormalizedWindowsEvent;

/// Schema version of the serialized shapes in this module.
pub const MICROSOFT_STORE_SCHEMA_VERSION: u32 = 1;

// ── Classification vocabulary ───────────────────────────────────────────────

/// Which installer grammar a transaction is executed with.
///
/// `Unknown` is not a failure state and not a default to be quietly ignored: it
/// records that no observation established the family, which means no
/// family-specific terminal semantics may be applied to the transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum StoreInstallerFamily {
    /// UWP/AppX/MSIX registered into a single user's context.
    UwpUserContext,
    /// UWP/AppX/MSIX staged and provisioned for the device.
    UwpProvisioned,
    /// A Store-delivered Win32 package; the Store only brokers acquisition and
    /// the installer itself is an ordinary Windows installer.
    StoreWin32,
    /// No observation established the family, or the ones that did disagreed.
    Unknown,
}

impl StoreInstallerFamily {
    /// Whether two observed families may belong to the same transaction.
    ///
    /// `Unknown` is compatible with anything because it asserts nothing. Two
    /// different concrete families are never merged: that is exactly the
    /// collapse this module exists to prevent.
    pub fn is_compatible_with(self, other: Self) -> bool {
        self == other || self == Self::Unknown || other == Self::Unknown
    }

    /// Whether AppX/MSIX terminal semantics apply.
    pub fn is_appx(self) -> bool {
        matches!(self, Self::UwpUserContext | Self::UwpProvisioned)
    }
}

/// How the installer family was established.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum StoreFamilyBasis {
    /// An observation stated the deployment scope, provisioning operation, or
    /// Win32 handoff outright.
    Declared,
    /// Nothing in the evidence established it. Pairs with
    /// [`StoreInstallerFamily::Unknown`] and is itself a coverage statement.
    Unvalidated,
}

/// The account context a deployment ran in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum StoreExecutionContext {
    System,
    User,
    Unknown,
}

impl StoreExecutionContext {
    /// Whether two observed contexts may belong to the same transaction.
    pub fn is_compatible_with(self, other: Self) -> bool {
        self == other || self == Self::Unknown || other == Self::Unknown
    }
}

/// What the deployment was trying to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum StoreDeploymentAction {
    Install,
    Uninstall,
    Unknown,
}

/// Intune's stated intent for an assignment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum StoreAssignmentIntent {
    Required,
    Available,
    Uninstall,
    NotTargeted,
    Unknown,
}

/// Lifecycle phases in order. `last_confirmed_phase` is the furthest phase an
/// observation proved, never the furthest phase assumed to have been reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum StorePhase {
    Targeted,
    Applicability,
    Acquisition,
    HandedOff,
    Download,
    Staging,
    Registration,
    Provisioning,
    Reported,
}

/// What one record proved on its own.
///
/// A signal is a statement about a record, never about an outcome. Turning a
/// sequence of signals into a state is the reducer's job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum StoreSignal {
    TargetedByIntune,
    NotApplicable,
    AcquisitionRequested,
    LicenseAcquired,
    LicenseFailed,
    DeploymentStarted,
    StagingCompleted,
    StagingFailed,
    RegistrationCompleted,
    RegistrationFailed,
    ProvisioningCompleted,
    ProvisioningFailed,
    RemovalCompleted,
    RemovalFailed,
    NoInteractiveUser,
    Win32HandoffStarted,
    Win32InstallerCompleted,
    Win32InstallerFailed,
    RetryScheduled,
    PackageInstalledFact,
    PackageAbsentFact,
    /// Parsed, but it proved nothing about a Store deployment.
    Unclassified,
}

/// The reduced state of one transaction.
///
/// Every failure variant names the stage that failed, because "the Store app
/// failed" is not an actionable statement: a license failure, a staging failure,
/// and a per-user registration failure have nothing in common operationally.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum StoreTransactionState {
    NotTargeted,
    NotApplicable,
    AcquisitionRequested,
    LicenseFailure,
    DownloadFailure,
    RegistrationFailure,
    ProvisioningFailure,
    NoInteractiveUser,
    StoreWin32Handoff,
    /// A Store-delivered Win32 package's own installer reported failure.
    ///
    /// Deliberately not folded into [`Self::RegistrationFailure`]: registration
    /// is an AppX concept, and a Win32 installer that returns nonzero has not
    /// "failed to register" anything. Sharing one state would be the exact
    /// cross-grammar collapse this module exists to prevent.
    InstallerFailure,
    InstallCompleted,
    UninstallCompleted,
    UninstallFailure,
    PendingRetry,
    InsufficientEvidence,
}

impl StoreTransactionState {
    /// Whether this state reports a device-side failure.
    pub fn is_failure(self) -> bool {
        matches!(
            self,
            Self::LicenseFailure
                | Self::DownloadFailure
                | Self::RegistrationFailure
                | Self::ProvisioningFailure
                | Self::InstallerFailure
                | Self::UninstallFailure
        )
    }
}

// ── Package identity ────────────────────────────────────────────────────────

/// The identifiers a Store transaction can be correlated on.
///
/// `display_name` is carried for presentation and is explicitly **not** a
/// correlation key. Two distinct packages routinely ship under one product
/// name, and joining on it would merge unrelated deployments.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StorePackageIdentity {
    pub store_product_id: Option<String>,
    pub package_family_name: Option<String>,
    pub package_full_name: Option<String>,
    pub display_name: Option<String>,
}

impl StorePackageIdentity {
    /// Whether any correlatable identifier is present.
    pub fn is_empty(&self) -> bool {
        self.correlation_tokens().is_empty()
    }

    /// The package family name, deriving it from a package full name when only
    /// the latter is present.
    ///
    /// A full name is `Name_Version_Architecture__PublisherId`, so the family
    /// name is recoverable by construction rather than by guesswork. Recovering
    /// it is what lets a staging event that only logged a full name join the
    /// registration event that only logged a family name.
    pub fn effective_package_family_name(&self) -> Option<String> {
        if let Some(family) = &self.package_family_name {
            return Some(family.to_ascii_lowercase());
        }
        derive_family_from_full_name(self.package_full_name.as_deref()?)
    }

    /// Normalized correlation tokens, sorted and de-duplicated.
    ///
    /// Two observations join only when these sets intersect.
    pub fn correlation_tokens(&self) -> Vec<String> {
        let mut tokens = Vec::new();
        if let Some(family) = self.effective_package_family_name() {
            tokens.push(format!("pfn:{family}"));
        }
        if let Some(full) = &self.package_full_name {
            tokens.push(format!("pfullname:{}", full.to_ascii_lowercase()));
        }
        if let Some(product) = &self.store_product_id {
            tokens.push(format!("product:{}", product.to_ascii_uppercase()));
        }
        tokens.sort();
        tokens.dedup();
        tokens
    }

    /// Widen this identity with anything `other` knows and this one does not.
    pub fn absorb(&mut self, other: &StorePackageIdentity) {
        absorb_option(&mut self.store_product_id, &other.store_product_id);
        absorb_option(&mut self.package_family_name, &other.package_family_name);
        absorb_option(&mut self.package_full_name, &other.package_full_name);
        absorb_option(&mut self.display_name, &other.display_name);
    }
}

fn absorb_option(target: &mut Option<String>, source: &Option<String>) {
    if target.is_none() {
        if let Some(value) = source {
            *target = Some(value.clone());
        }
    }
}

/// `Name_Version_Architecture__PublisherId` → `name_publisherid`.
pub(crate) fn derive_family_from_full_name(full_name: &str) -> Option<String> {
    let (name, rest) = full_name.split_once('_')?;
    let publisher = rest.rsplit_once("__").map(|(_, publisher)| publisher)?;
    if name.is_empty() || publisher.is_empty() {
        return None;
    }
    Some(format!(
        "{}_{}",
        name.to_ascii_lowercase(),
        publisher.to_ascii_lowercase()
    ))
}

// ── Supplied inputs ─────────────────────────────────────────────────────────

/// An Intune assignment or app metadata fact supplied by the caller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoreAssignment {
    pub context: IntuneObservationContext,
    pub app_id: Option<String>,
    pub identity: StorePackageIdentity,
    pub intent: StoreAssignmentIntent,
    pub target_context: StoreExecutionContext,
    #[serde(default)]
    pub named_data: Vec<IntuneNamedValue>,
}

/// An inventory or provisioning fact about a package already on the device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StorePackageFact {
    pub context: IntuneObservationContext,
    pub identity: StorePackageIdentity,
    pub installer_family: StoreInstallerFamily,
    pub execution_context: StoreExecutionContext,
    pub installed: bool,
    pub provisioned: Option<bool>,
    #[serde(default)]
    pub named_data: Vec<IntuneNamedValue>,
}

/// Installer-native evidence for a Store-delivered Win32 package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoreInstallerOutcome {
    pub context: IntuneObservationContext,
    pub app_id: Option<String>,
    pub identity: StorePackageIdentity,
    pub action: StoreDeploymentAction,
    pub exit_code: Option<IntuneErrorCode>,
    pub succeeded: Option<bool>,
    #[serde(default)]
    pub named_data: Vec<IntuneNamedValue>,
}

/// The decoded contents of one supplied artifact.
///
/// The pure crate never opens a file, decodes an EVTX record, or queries a
/// package. Callers do that and hand the results over in these shapes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum StoreArtifactPayload {
    /// Raw CCM-framed IME log text. Framed by [`crate::intune::ime_parser`].
    ImeText {
        text: String,
    },
    /// Normalized Windows event records from an AppX, packaging, or Store channel.
    WindowsEvents {
        events: Vec<NormalizedWindowsEvent>,
    },
    PackageFacts {
        facts: Vec<StorePackageFact>,
    },
    Assignments {
        assignments: Vec<StoreAssignment>,
    },
    InstallerOutcomes {
        outcomes: Vec<StoreInstallerOutcome>,
    },
}

/// One artifact the caller attempted to collect, whether or not it succeeded.
///
/// An artifact that was missing, denied, capped, or unparseable is still
/// declared, because the absence of a signal only means something when the
/// source it would have come from was actually readable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoreSourceArtifact {
    pub artifact_id: String,
    /// Free-text grouping, e.g. `ime`, `appxDeployment`, `store`, `inventory`.
    pub family: String,
    pub source_kind: IntuneSourceKind,
    pub status: IntuneArtifactStatus,
    pub detail: Option<String>,
    pub observed_at_utc: String,
    pub file_name: Option<String>,
    /// Sanitized source path. Privacy-sensitive: profile paths land here.
    pub file_path: Option<String>,
    pub payload: Option<StoreArtifactPayload>,
}

// ── Reduced output ──────────────────────────────────────────────────────────

/// Which side of the story an observation came from.
///
/// The distinction is load-bearing rather than decorative: a finding may only
/// blame Intune when Intune evidence exists, and may only report a device-side
/// outcome when device-side evidence exists. Deriving that from the source kind
/// alone does not work, because an assignment fact and a package inventory fact
/// are both `suppliedFact` yet sit on opposite sides.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum StoreEvidenceOrigin {
    /// Intune stated an intent: an assignment, or an IME log record.
    IntuneAssignment,
    IntuneManagementExtension,
    /// The OS reported what it did.
    WindowsEvent,
    PackageInventory,
    InstallerNative,
}

impl StoreEvidenceOrigin {
    /// Whether this origin establishes that Intune targeted the package.
    pub fn is_intune_intent(self) -> bool {
        matches!(
            self,
            Self::IntuneAssignment | Self::IntuneManagementExtension
        )
    }

    /// Whether this origin establishes what the device actually did.
    pub fn is_device_evidence(self) -> bool {
        matches!(
            self,
            Self::WindowsEvent | Self::PackageInventory | Self::InstallerNative
        )
    }
}

/// One classified record, event, or supplied fact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoreObservation {
    pub observation_id: String,
    pub context: IntuneObservationContext,
    pub origin: StoreEvidenceOrigin,
    pub signal: StoreSignal,
    pub installer_family: StoreInstallerFamily,
    pub family_basis: StoreFamilyBasis,
    pub identity: StorePackageIdentity,
    pub app_id: Option<String>,
    pub execution_context: StoreExecutionContext,
    pub action: StoreDeploymentAction,
    /// The source's own operation-correlation token — for a Windows event, the
    /// ETW activity id. This is the only linkage that can tie a success record
    /// to an earlier failure as one operation: record order alone proves
    /// chronology, not linkage (ADR-003), so the reducer requires a shared
    /// activity id before a later success may supersede a failure. Absent for
    /// sources whose grammar carries no such token (IME text, supplied facts).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activity_id: Option<String>,
    /// Intune's typed assignment intent, present only when this observation is
    /// a typed assignment. This is the authoritative statement of intent: the
    /// reducer reads intent from here and never from caller-writable
    /// `named_data` (ADR-001).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub typed_intent: Option<StoreAssignmentIntent>,
    pub error: Option<IntuneErrorCode>,
    /// True when the record came from a recognized provider but an event id or
    /// schema version this build has no rule for.
    pub unknown_version: bool,
    /// True when a *known* event's level contradicts the outcome its event id
    /// states (a failure id logged at Information level). Deliberately a
    /// separate flag from [`Self::unknown_version`]: an unrecognized dialect
    /// and a self-contradictory known record degrade confidence for distinct
    /// reasons, and conflating them would hide which one happened.
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub level_mismatch: bool,
    #[serde(default)]
    pub named_data: Vec<IntuneNamedValue>,
    /// Verbatim record or rendered event text. Redacted by the export
    /// projection when the observation context marks it sensitive.
    pub message: Option<String>,
}

/// A reduced Store app transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoreTransaction {
    pub transaction_id: String,
    pub app_id: Option<String>,
    pub identity: StorePackageIdentity,
    /// Always present. `Unknown` means no observation established the family.
    pub installer_family: StoreInstallerFamily,
    pub family_basis: StoreFamilyBasis,
    pub execution_context: StoreExecutionContext,
    pub action: StoreDeploymentAction,
    pub intent: StoreAssignmentIntent,
    pub last_confirmed_phase: Option<StorePhase>,
    pub state: StoreTransactionState,
    pub error: Option<IntuneErrorCode>,
    pub confidence: IntuneFindingConfidence,
    /// True when Intune assignment or IME handoff evidence is present.
    pub has_intune_intent: bool,
    /// True when device-side OS evidence (event, inventory fact, installer) is present.
    pub has_device_evidence: bool,
    pub unknown_version_observed: bool,
    pub observations: Vec<String>,
    pub evidence: Vec<IntuneEvidenceRef>,
    /// The smallest artifact that would advance this diagnosis.
    pub next_evidence_request: Option<String>,
}

/// The public result of reducing a Store app bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoreAnalysis {
    pub schema_version: u32,
    pub transactions: Vec<StoreTransaction>,
    pub observations: Vec<StoreObservation>,
    /// Observations that carried no correlatable package identifier. They stay
    /// visible and can never terminate a transaction.
    pub unkeyed_observations: Vec<String>,
    pub coverage: Vec<IntuneArtifactCoverage>,
    pub findings: Vec<IntuneFinding>,
}

impl Default for StoreAnalysis {
    fn default() -> Self {
        Self {
            schema_version: MICROSOFT_STORE_SCHEMA_VERSION,
            transactions: Vec::new(),
            observations: Vec::new(),
            unkeyed_observations: Vec::new(),
            coverage: Vec::new(),
            findings: Vec::new(),
        }
    }
}

impl StoreAnalysis {
    /// Coverage entries whose artifact was not fully readable.
    pub fn coverage_gaps(&self) -> impl Iterator<Item = &IntuneArtifactCoverage> {
        self.coverage
            .iter()
            .filter(|entry| entry.status != IntuneArtifactStatus::Available)
    }

    /// Look up one observation by id.
    pub fn observation(&self, observation_id: &str) -> Option<&StoreObservation> {
        self.observations
            .iter()
            .find(|observation| observation.observation_id == observation_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn family_name_is_recovered_from_a_full_name() {
        assert_eq!(
            derive_family_from_full_name("Contoso.SynthApp_1.2.3.0_x64__9abcdef01234h"),
            Some("contoso.synthapp_9abcdef01234h".to_owned())
        );
    }

    #[test]
    fn a_full_name_without_a_publisher_segment_yields_nothing() {
        assert_eq!(
            derive_family_from_full_name("Contoso.SynthApp_1.2.3.0"),
            None
        );
        assert_eq!(derive_family_from_full_name("no-underscores"), None);
    }

    #[test]
    fn display_name_alone_is_not_a_correlation_token() {
        let identity = StorePackageIdentity {
            display_name: Some("Synthetic Store App".to_owned()),
            ..StorePackageIdentity::default()
        };
        assert!(identity.is_empty());
        assert!(identity.correlation_tokens().is_empty());
    }

    #[test]
    fn a_full_name_and_a_family_name_correlate_to_the_same_token() {
        let from_full = StorePackageIdentity {
            package_full_name: Some("Contoso.SynthApp_1.2.3.0_x64__9abcdef01234h".to_owned()),
            ..StorePackageIdentity::default()
        };
        let from_family = StorePackageIdentity {
            package_family_name: Some("Contoso.SynthApp_9abcdef01234h".to_owned()),
            ..StorePackageIdentity::default()
        };
        assert!(from_full
            .correlation_tokens()
            .iter()
            .any(|token| from_family.correlation_tokens().contains(token)));
    }

    #[test]
    fn two_concrete_installer_families_never_merge() {
        assert!(!StoreInstallerFamily::UwpUserContext
            .is_compatible_with(StoreInstallerFamily::UwpProvisioned));
        assert!(!StoreInstallerFamily::StoreWin32
            .is_compatible_with(StoreInstallerFamily::UwpProvisioned));
        assert!(
            StoreInstallerFamily::Unknown.is_compatible_with(StoreInstallerFamily::UwpUserContext)
        );
    }

    #[test]
    fn wire_values_are_camel_case() {
        assert_eq!(
            serde_json::to_string(&StoreInstallerFamily::UwpUserContext).unwrap(),
            "\"uwpUserContext\""
        );
        assert_eq!(
            serde_json::to_string(&StoreTransactionState::InsufficientEvidence).unwrap(),
            "\"insufficientEvidence\""
        );
    }
}
