//! Public types for Intune Win32 app deployment transactions.
//!
//! These types describe *what the evidence showed*, not what the analyzer
//! guessed. Every outcome that implies a diagnosis is only reachable from an
//! explicit record; everything else lands in
//! [`Win32Outcome::InsufficientEvidence`] plus a coverage request naming the
//! smallest artifact that would resolve it.
//!
//! Envelopes, provenance, coverage, error tokens, and findings all come from
//! [`crate::intune::evidence`]. This module deliberately defines no parallel
//! sensitivity, evidence-reference, or coverage type: a Win32 finding has to be
//! comparable with an enrollment finding or a compliance finding without a
//! translation layer.

use serde::{Deserialize, Serialize};

use crate::intune::evidence::{
    IntuneArtifactCoverage, IntuneErrorCode, IntuneEvidenceRef, IntuneNamedValue,
    IntuneObservationContext,
};

/// Schema version for the Win32 transaction surface.
///
/// Bump only on a breaking change. Adding an optional field or a new enum
/// variant at the end is additive and does not bump it.
pub const WIN32_SCHEMA_VERSION: u32 = 1;

/// Which supplied artifact a record came from.
///
/// A file name only ever selects a *candidate*; see
/// [`super::sources::classify_artifact`] for why the records inside have to
/// confirm it before the kind is trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Win32SourceKind {
    /// `IntuneManagementExtension.log`: check-in, policy receipt, dispatch, reporting.
    IntuneManagementExtension,
    /// `AppWorkload.log`: the app lifecycle from assignment to reporting.
    AppWorkload,
    /// `AppActionProcessor.log`: applicability, action, and detection decisions.
    AppActionProcessor,
    /// `AgentExecutor.log`: a PowerShell installer or prerequisite invocation.
    AgentExecutor,
    /// An installer-native artifact (MSI, PSADT, Burn, or captured EXE output).
    ///
    /// Supplemental only. Its contents are never parsed for signals; its
    /// *identity* is the evidence, and it may only corroborate a transaction it
    /// can be keyed to.
    InstallerOutput,
    /// A recognised name whose records did not confirm it, or a name we do not
    /// recognise at all. Kept visible in coverage rather than fed to the reducer.
    Unknown,
}

/// The context an app deployment ran in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Win32ExecutionContext {
    System,
    User,
    Unknown,
}

/// The intent an assignment expressed, when a record states it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Win32Intent {
    Required,
    Available,
    Uninstall,
    Unknown,
}

/// Lifecycle phases of a Win32 deployment, in the order IME performs them.
///
/// Detection runs *before* content is acquired: IME asks whether the app is
/// already present before it spends bandwidth, so `PreEnforcementDetection`
/// precedes `Content`.
///
/// [`Win32Transaction::last_confirmed_phase`] is the furthest phase the evidence
/// proves *completed successfully*, not the furthest phase we assume was
/// reached. A phase that was entered and failed does not advance it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Win32Phase {
    Assignment,
    Applicability,
    Requirements,
    Dependencies,
    PreEnforcementDetection,
    Content,
    Enforcement,
    PostEnforcementDetection,
    Reporting,
}

/// One record-level signal.
///
/// A signal answers "what did this record *say*". It never decides an outcome;
/// that is the reducer's job, working only from what these signals could prove.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Win32Signal {
    /// An app policy for this app arrived in a check-in.
    AppPolicyReceived,
    /// The service no longer targets this app at this device or user.
    NotTargeted,
    ApplicabilityPassed,
    ApplicabilityFailed,
    RequirementPassed,
    RequirementFailed,
    DependencyResolved,
    DependencyUnresolved,
    /// A detection rule evaluation that found the app present.
    ///
    /// Whether this is pre- or post-enforcement is decided by the reducer from
    /// record order, never by the record itself.
    DetectionSatisfied,
    DetectionNotSatisfied,
    /// The service has no usable content for the requested version.
    ContentUnavailable,
    DownloadStarted,
    DownloadCompleted,
    DownloadFailed,
    /// The download stalled, timed out, or exhausted its retries without a
    /// completion or failure statement. Recognized through the shared
    /// content-download vocabulary owned by [`crate::intune::download_stats`];
    /// deliberately not a terminal statement, because a stall is trouble in
    /// flight, not a proven outcome.
    DownloadStalled,
    HashValidationFailed,
    StagingFailed,
    EnforcementStarted,
    /// The install command could not be launched at all.
    EnforcementCommandFailed,
    /// The installer ran to completion and reported a code.
    InstallerCompleted,
    RetryScheduled,
    ReportSubmitted,
    ReportFailed,
    Unclassified,
}

/// How the supplied return-code table classifies an installer code.
///
/// The default table is Intune's own documented Win32 app return codes, which is
/// a product contract rather than an interpretation invented here. A code the
/// table does not contain stays [`Win32ReturnCodeKind::Unmapped`]: the analyzer
/// reports the token and refuses to assign it a meaning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Win32ReturnCodeKind {
    Success,
    SoftReboot,
    HardReboot,
    Retry,
    Failed,
    Unmapped,
}

/// One entry of a caller-supplied return-code table.
///
/// Intune lets an administrator remap return codes per deployment type, so a
/// code that means failure on one app can mean success on another. Callers pass
/// the app's configured table; without one the documented defaults apply.
///
/// `deployment_type_id` scopes an entry to one deployment type of the app, the
/// same granularity Intune configures the table at. An entry without one
/// applies to every deployment type of the app; an exact deployment-type match
/// always wins over an app-wide entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Win32ReturnCodeMapping {
    pub app_id: String,
    #[serde(default)]
    pub deployment_type_id: Option<String>,
    pub code: i64,
    pub kind: Win32ReturnCodeKind,
}

/// Caller-supplied, privacy-safe display metadata for one app.
///
/// The analyzer never invents a display name. When no metadata is supplied a
/// transaction is identified by its synthetic ids alone, which is safe to export.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Win32AppMetadata {
    pub app_id: String,
    pub display_name: Option<String>,
    pub deployment_type_id: Option<String>,
    pub deployment_type_name: Option<String>,
    pub content_version: Option<String>,
}

/// One classified record, with the shared observation envelope attached.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Win32Observation {
    pub observation_id: String,
    pub context: IntuneObservationContext,
    pub source_kind: Win32SourceKind,
    pub signal: Win32Signal,
    /// The app id this record resolved to, whether stated or inherited from its
    /// own execution block. `None` means the record could not be keyed at all.
    pub app_id: Option<String>,
    pub deployment_type_id: Option<String>,
    pub content_version: Option<String>,
    /// The dependency app a dependency signal named.
    pub dependency_app_id: Option<String>,
    /// The requirement rule a requirement signal named.
    pub requirement_name: Option<String>,
    pub execution_context: Win32ExecutionContext,
    pub intent: Win32Intent,
    /// A return/exit/error token exactly as the record wrote it.
    pub error_code: Option<IntuneErrorCode>,
    /// True when the record looked like Win32 enforcement but matched no rule,
    /// or matched a completion whose code could not be read. These are the
    /// records the unknown-vocabulary coverage flag is built from, carried per
    /// observation so a finding can cite exactly them.
    #[serde(default)]
    pub enforcement_shaped_but_unmatched: bool,
    /// Fields retained without interpretation, so typing one later is a widening
    /// change rather than a re-parse.
    pub attributes: Vec<IntuneNamedValue>,
    /// Verbatim record text. Sensitive: Win32 records quote command lines, UPNs,
    /// and profile paths.
    pub message: String,
}

/// The identity a transaction is keyed on.
///
/// Two records merge only when this key matches. Timestamp proximity, display
/// name, and a shared `Win32App` component are explicitly not part of it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Win32TransactionKey {
    pub app_id: String,
    pub deployment_type_id: Option<String>,
    pub execution_context: Win32ExecutionContext,
}

/// Terminal outcome or explicit unresolved state of one deployment.
///
/// The non-terminal variants are as load-bearing as the terminal ones: a
/// deployment that is still enforcing, or deferred, or simply not evidenced, is
/// a different answer from one that failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Win32Outcome {
    /// Nothing in the supplied evidence pins this deployment to a phase.
    InsufficientEvidence,
    /// A policy arrived and nothing further was evidenced.
    Assigned,
    NotTargeted,
    NotApplicable,
    RequirementNotMet,
    DependencyUnresolved,
    /// Detection was already satisfied before any enforcement ran.
    DetectedBeforeEnforcement,
    /// The service had no usable content for the requested version.
    ContentUnavailable,
    /// Download, hash validation, or staging failed.
    ContentDeliveryFailed,
    /// Enforcement started and no result was evidenced.
    Enforcing,
    /// The install command could not be launched.
    EnforcementCommandFailed,
    /// The installer ran and reported a code the return-code table treats as a
    /// failure, or does not map at all.
    InstallerReportedFailure,
    /// The installer reported success and post-enforcement detection stayed false.
    InstalledNotDetected,
    /// A retry or deferral was scheduled and no terminal outcome followed.
    Deferred,
    /// A local outcome was reached and reporting it to the service failed.
    ReportingFailed,
    Succeeded,
    /// Two records of equal authority stated contradictory terminal outcomes
    /// and nothing in the evidence orders one after the other.
    ///
    /// Per ADR-003 an unresolved authoritative contradiction stays conservative
    /// rather than letting whichever record the caller supplied last win. This
    /// is an unresolved state, not a terminal one: the missing artifact is the
    /// one that would prove which statement came later.
    Conflicting,
}

impl Win32Outcome {
    /// Whether this outcome is a settled answer rather than an in-flight state.
    ///
    /// Used by the reducer so a scheduled retry cannot erase a failure that was
    /// already proven, and by the confidence rule so an in-flight deployment can
    /// never be reported at high confidence.
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::NotTargeted
                | Self::NotApplicable
                | Self::RequirementNotMet
                | Self::DependencyUnresolved
                | Self::DetectedBeforeEnforcement
                | Self::ContentUnavailable
                | Self::ContentDeliveryFailed
                | Self::EnforcementCommandFailed
                | Self::InstallerReportedFailure
                | Self::InstalledNotDetected
                | Self::ReportingFailed
                | Self::Succeeded
        )
    }

    /// Whether this outcome describes a deployment that did not land.
    pub fn is_failure(self) -> bool {
        matches!(
            self,
            Self::RequirementNotMet
                | Self::DependencyUnresolved
                | Self::ContentUnavailable
                | Self::ContentDeliveryFailed
                | Self::EnforcementCommandFailed
                | Self::InstallerReportedFailure
                | Self::InstalledNotDetected
                | Self::ReportingFailed
        )
    }
}

/// How strongly the evidence supports the reduced outcome.
///
/// Reuses the shared finding-confidence scale so a transaction and the findings
/// derived from it are directly comparable.
pub type Win32Confidence = crate::intune::evidence::IntuneFindingConfidence;

/// A proven terminal failure that a later, explicitly linked record superseded.
///
/// Retry semantics per ADR-003: a linked later success may replace an earlier
/// failure as the transaction outcome, but the failure is evidence of a real
/// failed enforcement cycle and must stay visible rather than be erased.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Win32SupersededFailure {
    pub outcome: Win32Outcome,
    /// The failing return/error token, when the superseded record carried one.
    pub return_code: Option<IntuneErrorCode>,
    pub evidence: Vec<IntuneEvidenceRef>,
}

/// One reduced Win32 app deployment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Win32Transaction {
    pub key: Win32TransactionKey,
    /// Caller-supplied display name, never inferred from a log.
    pub display_name: Option<String>,
    pub content_version: Option<String>,
    pub intent: Win32Intent,
    /// Observation ids in reduction order.
    pub observations: Vec<String>,
    /// The furthest phase the evidence proves completed successfully.
    pub last_confirmed_phase: Option<Win32Phase>,
    pub outcome: Win32Outcome,
    /// The outcome reached locally, when reporting later failed on top of it.
    ///
    /// Without this a reporting failure would hide whether the install itself
    /// succeeded, which is the first thing an operator needs to know.
    pub local_outcome: Option<Win32Outcome>,
    /// The installer's return token, exactly as written.
    pub return_code: Option<IntuneErrorCode>,
    pub return_code_kind: Option<Win32ReturnCodeKind>,
    /// True only when a return code the table maps to a reboot was observed.
    pub reboot_required: bool,
    /// Dependency apps this deployment was proven to be blocked on.
    pub unresolved_dependencies: Vec<String>,
    /// Requirement rules this deployment was proven to have failed.
    pub failed_requirements: Vec<String>,
    /// Proven terminal failures that a later, explicitly linked record
    /// superseded. Never empty silently: each entry keeps the failing outcome,
    /// its token, and the records that proved it (ADR-003 retry semantics).
    #[serde(default)]
    pub superseded_failures: Vec<Win32SupersededFailure>,
    /// Supplemental installer artifacts keyed to this transaction.
    pub corroborating_artifacts: Vec<String>,
    pub confidence: Win32Confidence,
    pub evidence: Vec<IntuneEvidenceRef>,
    /// The smallest artifact that would advance this diagnosis.
    pub next_evidence_request: Option<String>,
}

/// What the supplied bundle did and did not cover.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Win32Coverage {
    /// One entry per expected artifact, including the ones that were not read.
    pub artifacts: Vec<IntuneArtifactCoverage>,
    /// In-scope records that parsed but carried no Win32 signal.
    pub unclassified_records: u32,
    /// Physical-line fragments and unmatched rotation tails.
    ///
    /// These can never create a transaction event, so they are counted rather
    /// than classified.
    pub fragment_records: u32,
    /// True when a record looked like Win32 enforcement but matched no rule,
    /// which is how an unrecognised IME version shows up.
    pub unknown_vocabulary_observed: bool,
    /// Supplemental installer artifacts that could not be keyed to any
    /// transaction. They are never merged on timestamp, so they stay here.
    pub unlinked_installer_artifacts: Vec<String>,
}

/// The public result of reducing a Win32 app bundle.
///
/// This is an immutable snapshot: [`super::derive_findings`] reads it and
/// returns findings, and never mutates it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Win32Analysis {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    pub transactions: Vec<Win32Transaction>,
    pub observations: Vec<Win32Observation>,
    /// Signals that could not be keyed to an app. These can never terminate a
    /// transaction; they are surfaced so the gap stays visible.
    pub unkeyed_observations: Vec<String>,
    pub coverage: Win32Coverage,
}

fn default_schema_version() -> u32 {
    WIN32_SCHEMA_VERSION
}

impl Default for Win32Analysis {
    /// An empty analysis still carries the current schema version: a
    /// `Default`-built value with `schema_version: 0` would deserialize-round-
    /// trip as an invalid, never-emitted version.
    fn default() -> Self {
        Self {
            schema_version: WIN32_SCHEMA_VERSION,
            transactions: Vec::new(),
            observations: Vec::new(),
            unkeyed_observations: Vec::new(),
            coverage: Win32Coverage::default(),
        }
    }
}

impl Win32Analysis {
    /// The transaction for an app id, when exactly one exists.
    pub fn transaction_for_app(&self, app_id: &str) -> Option<&Win32Transaction> {
        let mut matches = self
            .transactions
            .iter()
            .filter(|transaction| transaction.key.app_id == app_id);
        let first = matches.next()?;
        matches.next().is_none().then_some(first)
    }
}
