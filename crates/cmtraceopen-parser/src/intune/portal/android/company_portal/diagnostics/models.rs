//! Input and output types for imported Android Company Portal diagnostics.
//!
//! The input side models an archive that **someone else already extracted**.
//! Issue #371 places archive acquisition, extraction, and import safety outside
//! the parser, so this crate never sees a `.zip`: it receives named entries, the
//! bytes the importer decoded, and whatever the importer noticed while
//! extracting. It re-derives every safety property it can from the names alone,
//! because a host that forgets to report a traversal entry must not thereby
//! make one invisible.
//!
//! The output side is deliberately thin. Until
//! [`super::contract::VERIFIED_CONTRACTS`] has an entry, no record grammar is
//! known, so [`AndroidDiagnosticsSnapshot::records`] is always empty and every
//! member is reported as unsupported rather than as understood.

use serde::{Deserialize, Serialize};

use crate::intune::evidence::{
    IntuneAccessState, IntuneArtifactCoverage, IntuneArtifactStatus, IntuneFinding,
    IntuneNamedValue, IntuneObservationContext, IntuneTimestamp,
};

use super::contract::{
    AndroidCollectionFlow, AndroidDiagnosticApp, AndroidManagementMode, AndroidUploadOutcome,
    AndroidVerboseLoggingState,
};

// ── Input ───────────────────────────────────────────────────────────────────

/// Envelope facts the importer asserts about a bundle.
///
/// Every field here is a *claim by the caller*, not a reading of the artifact.
/// They are recorded with `IntuneSourceKind::SuppliedFact` provenance and are
/// never upgraded to content-derived evidence.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AndroidSuppliedCollectionFacts {
    pub app: Option<AndroidDiagnosticApp>,
    pub app_version: Option<String>,
    pub management_mode: Option<AndroidManagementMode>,
    pub collection_flow: Option<AndroidCollectionFlow>,
    pub verbose_logging: Option<AndroidVerboseLoggingState>,
    /// The incident ID a submission flow pre-populated into a mail draft.
    ///
    /// A correlation identifier, and privacy-sensitive. Its presence says a
    /// submission was started; it never says one succeeded.
    pub incident_id: Option<String>,
    pub upload_outcome: Option<AndroidUploadOutcome>,
    /// Collection time exactly as the importer wrote it, in any form.
    pub collected_at_text: Option<String>,
    /// Device time zone name, when the importer knows one.
    ///
    /// This crate carries no tz database, so a named zone is recorded and
    /// reported as un-normalized rather than resolved to an offset.
    pub device_time_zone: Option<String>,
    /// A schema or version token the artifact declared, if it declared one.
    pub declared_schema_token: Option<String>,
    /// How the members reached this crate, e.g. `extractedDirectory`.
    pub container_kind: Option<String>,
    /// Anything else the importer wants preserved, kept uninterpreted.
    #[serde(default)]
    pub extra: Vec<IntuneNamedValue>,
}

/// Something the importer, or this module's own name check, found wrong with a
/// member.
///
/// A flagged member is enumerated and reported but never treated as evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AndroidMemberSafetyFlag {
    /// Two members share one entry name.
    DuplicateEntryName,
    /// The entry name contains a `..` component.
    PathTraversal,
    /// The entry name is absolute, or begins with a drive or root.
    AbsoluteEntryPath,
    /// The member exceeds the caller's per-member byte limit.
    OversizedEntry,
    /// The importer reported the member as cut short.
    TruncatedEntry,
    /// The entry is a link rather than a regular file.
    SymlinkEntry,
    /// The bytes did not decode to text.
    UndecodableBytes,
}

impl AndroidMemberSafetyFlag {
    /// Stable wire token, used to build deterministic finding identifiers.
    pub fn wire(self) -> &'static str {
        match self {
            Self::DuplicateEntryName => "duplicateEntryName",
            Self::PathTraversal => "pathTraversal",
            Self::AbsoluteEntryPath => "absoluteEntryPath",
            Self::OversizedEntry => "oversizedEntry",
            Self::TruncatedEntry => "truncatedEntry",
            Self::SymlinkEntry => "symlinkEntry",
            Self::UndecodableBytes => "undecodableBytes",
        }
    }
}

/// Byte limits the caller wants enforced against supplied members.
///
/// The parser cannot stop a decompression bomb, because it never decompresses.
/// It can refuse to treat an implausibly large member as evidence, and say so.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AndroidImportLimits {
    pub max_member_bytes: Option<u64>,
}

/// One already-extracted archive member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AndroidDiagnosticMemberInput {
    pub artifact_id: String,
    /// The member's name inside the container, as the importer read it.
    pub entry_name: String,
    /// A sanitized on-disk path, when the importer has one. Privacy-sensitive.
    pub sanitized_entry_path: Option<String>,
    /// What became of this member during import.
    pub status: IntuneArtifactStatus,
    pub declared_bytes: u64,
    pub encoding: Option<String>,
    /// Rotation label the importer derived, kept verbatim.
    pub rotation: Option<String>,
    /// Decoded text, when the member was collected and decoded.
    pub text: Option<String>,
    /// Safety problems the importer observed. Merged with what this module
    /// derives from the entry names.
    #[serde(default)]
    pub safety_flags: Vec<AndroidMemberSafetyFlag>,
}

/// One imported bundle, ready to analyze.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AndroidDiagnosticBundleInput {
    pub bundle_id: String,
    /// The caller's clock reading, supplied rather than sampled so the crate
    /// stays pure and results stay reproducible.
    pub observed_at_utc: String,
    pub supplied: AndroidSuppliedCollectionFacts,
    pub members: Vec<AndroidDiagnosticMemberInput>,
    #[serde(default)]
    pub limits: AndroidImportLimits,
}

// ── Output ──────────────────────────────────────────────────────────────────

/// What this build is willing to say the bundle *is*.
///
/// The ladder only descends from a caller's claim. A hint may nominate a
/// candidate; content may refuse one; nothing short of a verified contract may
/// promote one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AndroidBundleClassification {
    /// A layout in [`super::contract::VERIFIED_CONTRACTS`] matched. Unreachable
    /// while that registry is empty.
    VerifiedContract,
    /// The importer nominated this as Android Company Portal diagnostics and
    /// nothing contradicted it, but no verified layout matched. No record is
    /// claimed and every member is reported unsupported.
    CandidateUnverifiedContract,
    /// The bundle is something else: a bare `logcat` capture, an unrelated
    /// archive, or a bundle whose every member is a recognized foreign format.
    NotCompanyPortalDiagnostics,
    /// No members were supplied at all.
    EmptyBundle,
}

/// What this build is willing to say one member *is*.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AndroidMemberClassification {
    /// Present and named, contents not interpreted.
    Enumerated,
    /// Recognized as an Android `logcat` capture. Recognized in order to be
    /// refused: issue #371 explicitly scopes a general logcat parser out.
    RecognizedForeignLogcat,
    /// Enumerated but excluded from evidence because it carries a safety flag.
    RejectedUnsafe,
    /// Nothing was collected for this member.
    NotCollected,
}

/// One enumerated member of an imported bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AndroidDiagnosticMember {
    pub artifact_id: String,
    pub entry_name: String,
    /// Privacy-sensitive; masked by [`super::redacted_export_projection`].
    pub sanitized_entry_path: Option<String>,
    pub classification: AndroidMemberClassification,
    pub status: IntuneArtifactStatus,
    pub declared_bytes: u64,
    pub encoding: Option<String>,
    pub rotation: Option<String>,
    pub safety_flags: Vec<AndroidMemberSafetyFlag>,
    pub context: IntuneObservationContext,
}

/// One parsed diagnostic record.
///
/// The output slot a verified contract would populate. It is empty in every
/// result this build can produce, and [`AndroidDiagnosticsSnapshot::records`]
/// documents why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AndroidDiagnosticRecord {
    pub record_id: String,
    pub context: IntuneObservationContext,
    pub level: Option<String>,
    pub component: Option<String>,
    /// Verbatim record text. Privacy-sensitive.
    pub message: String,
    pub fields: Vec<IntuneNamedValue>,
}

/// Report-level metadata for one imported bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AndroidDiagnosticReportMetadata {
    pub bundle_id: String,
    pub schema_version: u32,
    pub generated_at_utc: String,
    pub classification: AndroidBundleClassification,
    /// Set only when a verified contract matched.
    pub verified_contract_id: Option<String>,
    pub app: Option<AndroidDiagnosticApp>,
    pub app_version: Option<String>,
    pub management_mode: Option<AndroidManagementMode>,
    pub collection_flow: Option<AndroidCollectionFlow>,
    pub verbose_logging: AndroidVerboseLoggingState,
    pub upload_outcome: AndroidUploadOutcome,
    /// Privacy-sensitive; masked by [`super::redacted_export_projection`].
    pub incident_id: Option<String>,
    pub collected_at: Option<IntuneTimestamp>,
    pub declared_schema_token: Option<String>,
    pub container_kind: Option<String>,
    /// Uninterpreted importer-supplied extras, preserved verbatim.
    pub supplied_extra: Vec<IntuneNamedValue>,
    /// The envelope under which every supplied fact above was recorded.
    ///
    /// Findings about supplied facts cite this rather than an artifact, so the
    /// difference between "the artifact said so" and "the importer said so"
    /// survives into the finding.
    pub supplied_context: IntuneObservationContext,
}

/// The public result of analyzing one imported bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AndroidDiagnosticsSnapshot {
    pub metadata: AndroidDiagnosticReportMetadata,
    pub members: Vec<AndroidDiagnosticMember>,
    /// Always empty in this build.
    ///
    /// Populating it requires a verified entry in
    /// [`super::contract::VERIFIED_CONTRACTS`]; until one exists, claiming a
    /// record would mean inventing the grammar it was read with.
    pub records: Vec<AndroidDiagnosticRecord>,
    pub coverage: Vec<IntuneArtifactCoverage>,
    pub findings: Vec<IntuneFinding>,
}

impl AndroidDiagnosticsSnapshot {
    /// Coverage entries whose artifact could not be read or understood.
    ///
    /// These are the identifiers a finding cites when it reasons from a gap.
    pub fn coverage_gap_ids(&self) -> Vec<String> {
        self.coverage
            .iter()
            .filter(|entry| entry.status != IntuneArtifactStatus::Available)
            .map(|entry| entry.artifact_id.clone())
            .collect()
    }

    /// Whether every finding cites evidence or a coverage gap.
    pub fn findings_are_evidence_backed(&self) -> bool {
        self.findings
            .iter()
            .all(IntuneFinding::is_evidence_backed)
    }
}

/// Map an import outcome onto the shared access vocabulary.
///
/// `ParseFailed` becomes [`IntuneAccessState::Failed`]: the member was reached,
/// so calling it missing would turn a decode failure into a false claim that
/// nothing was collected.
pub fn access_state_for(status: &IntuneArtifactStatus) -> IntuneAccessState {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_artifact_status_maps_to_a_distinct_access_state() {
        let pairs = [
            (IntuneArtifactStatus::Available, IntuneAccessState::Available),
            (IntuneArtifactStatus::Missing, IntuneAccessState::Missing),
            (
                IntuneArtifactStatus::PermissionDenied,
                IntuneAccessState::PermissionDenied,
            ),
            (IntuneArtifactStatus::Capped, IntuneAccessState::Capped),
            (IntuneArtifactStatus::Skipped, IntuneAccessState::Skipped),
            (IntuneArtifactStatus::ParseFailed, IntuneAccessState::Failed),
            (
                IntuneArtifactStatus::Unsupported,
                IntuneAccessState::Unsupported,
            ),
        ];
        for (status, expected) in pairs {
            assert_eq!(access_state_for(&status), expected);
        }
    }

    #[test]
    fn safety_flag_wire_tokens_are_unique() {
        let flags = [
            AndroidMemberSafetyFlag::DuplicateEntryName,
            AndroidMemberSafetyFlag::PathTraversal,
            AndroidMemberSafetyFlag::AbsoluteEntryPath,
            AndroidMemberSafetyFlag::OversizedEntry,
            AndroidMemberSafetyFlag::TruncatedEntry,
            AndroidMemberSafetyFlag::SymlinkEntry,
            AndroidMemberSafetyFlag::UndecodableBytes,
        ];
        let mut wires = flags.iter().map(|flag| flag.wire()).collect::<Vec<_>>();
        wires.sort_unstable();
        let unique = wires.len();
        wires.dedup();
        assert_eq!(wires.len(), unique);
    }
}
