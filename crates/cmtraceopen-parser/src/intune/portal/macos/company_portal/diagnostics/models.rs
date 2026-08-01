//! Input and output shapes for macOS Company Portal saved diagnostic reports.
//!
//! Two schemas live here and they are deliberately not the same thing:
//!
//! 1. The **import envelope** ([`DiagnosticReportImport`]). This crate owns it,
//!    it is fully specified, and it is versioned by
//!    [`COMPANY_PORTAL_MACOS_DIAGNOSTICS_SCHEMA_VERSION`]. A native import
//!    boundary opens the container, enforces the archive limits, decodes member
//!    bytes to text, and hands the result here.
//! 2. The **report schema** — the member names, layout, and field vocabulary
//!    that Company Portal itself writes inside the saved report. Microsoft does
//!    not document it, and no sanitized real report is fixture-backed in this
//!    repository. See [`report_schema_support_state`].
//!
//! Because (2) is unknown, nothing in this module names a Company Portal member
//! file, and no member is promoted to a semantic role on the strength of its
//! path. What the parser asserts is limited to what it can actually observe:
//! container-level facts the importer declared, member path safety, decoded
//! content *structure*, and coverage for everything it could not read.

// `Serializer` and `Deserializer` look unused: they are named by the expansion
// of `intune_raw_preserving_string_enum!`, which refers to them unqualified.
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::intune::evidence::{
    intune_raw_preserving_string_enum, IntuneArtifactCoverage, IntuneFinding, IntuneNamedValue,
    IntuneObservationContext,
};

/// Wire version of the import envelope this build understands.
///
/// A higher version is not an error: the envelope is retained, no member facts
/// are claimed, and the analysis reports an unsupported envelope with full
/// coverage gaps. See [`super::analyze_diagnostic_report`].
pub const COMPANY_PORTAL_MACOS_DIAGNOSTICS_SCHEMA_VERSION: u32 = 1;

/// Coverage family every artifact this module emits belongs to.
pub const COMPANY_PORTAL_MACOS_DIAGNOSTICS_FAMILY: &str = "companyPortalMacosDiagnostics";

/// Module path a structurally confirmed direct log member is delegated to.
///
/// Direct Company Portal log records are parsed by issue #368, not here. This
/// module only proves that a member *is* a log and hands it on; duplicating the
/// record grammar would create two places for it to drift.
pub const DIRECT_LOG_DELEGATION_TARGET: &str =
    "cmtraceopen_parser::intune::portal::macos::company_portal::logs";

/// How far along the public-support ladder a schema is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DiagnosticsSupportState {
    /// The format has not been obtained; no stable parser is exposed for it.
    SourceContract,
    /// Fixture-backed but still subject to change.
    Experimental,
    /// Fixture-backed and covered by the public schema guarantee.
    Stable,
}

/// Support state of the **report** schema, as opposed to the import envelope.
///
/// This is [`DiagnosticsSupportState::SourceContract`] and stays there until a
/// sanitized real saved report is committed to the corpus. Issue #369's
/// acceptance criteria are explicit that stable support begins only after an
/// actual report schema is fixture-backed, so the analysis advertises the state
/// rather than letting a caller infer stability from the module simply existing.
pub const fn report_schema_support_state() -> DiagnosticsSupportState {
    DiagnosticsSupportState::SourceContract
}

intune_raw_preserving_string_enum! {
    /// Container the importer opened.
    pub enum ReportContainerKind {
        Zip => "zip",
        Directory => "directory",
        UnknownContainer => "unknownContainer",
    }
}

intune_raw_preserving_string_enum! {
    /// Product the importer says produced the container.
    ///
    /// The importer knows this because the operator chose the file; the parser
    /// cannot confirm it from content while the report schema is undocumented.
    pub enum DeclaredProduct {
        CompanyPortalMacos => "companyPortalMacos",
        Other => "other",
    }
}

intune_raw_preserving_string_enum! {
    /// How completely the importer managed to read the container.
    pub enum ExtractionOutcome {
        Complete => "complete",
        Truncated => "truncated",
        Capped => "capped",
        Failed => "failed",
    }
}

intune_raw_preserving_string_enum! {
    /// Role a member plays, per issue #369's classification requirement.
    ///
    /// Every variant except [`ReportMemberRole::DirectLog`] can only ever be a
    /// *declared* role on this build: confirming "this member is MSAL evidence"
    /// or "this member is a configuration fact" needs the report schema, which
    /// is not fixture-backed. A direct log is confirmable because log framing is
    /// observable in the bytes themselves.
    pub enum ReportMemberRole {
        DirectLog => "directLog",
        AuthEvidence => "authEvidence",
        ConfigurationFact => "configurationFact",
        SystemFact => "systemFact",
        UnsupportedSupplemental => "unsupportedSupplemental",
        Unclassified => "unclassified",
    }
}

intune_raw_preserving_string_enum! {
    /// What the import boundary managed to do with one member.
    ///
    /// The parser may only ever *downgrade* this. An importer that claims
    /// [`MemberImportState::Decoded`] for a member with a traversal path or
    /// undecodable content does not get to keep that claim.
    ///
    /// `Rejected` and `NotClaimed` are both parser-assigned and deliberately
    /// distinct: `Rejected` means this member's own container path was refused,
    /// while `NotClaimed` means the *container* was refused (undeclared product
    /// or unreadable envelope) and no member of it is interpreted. Collapsing
    /// them would make "this archive holds a traversal member" read the same as
    /// "this archive is not a Company Portal report".
    pub enum MemberImportState {
        Decoded => "decoded",
        Capped => "capped",
        Oversized => "oversized",
        Absent => "absent",
        Skipped => "skipped",
        Encrypted => "encrypted",
        UnknownCompression => "unknownCompression",
        Undecodable => "undecodable",
        Rejected => "rejected",
        NotClaimed => "notClaimed",
    }
}

intune_raw_preserving_string_enum! {
    /// Structure the decoded member text actually has.
    pub enum MemberContentKind {
        PlainTextLog => "plainTextLog",
        Json => "json",
        PropertyList => "propertyList",
        PlainText => "plainText",
        Binary => "binary",
        Empty => "empty",
        Undecoded => "undecoded",
    }
}

intune_raw_preserving_string_enum! {
    /// Relationship between the declared role and what the content shows.
    pub enum RoleConfirmation {
        ContentConfirmed => "contentConfirmed",
        DeclaredUnconfirmed => "declaredUnconfirmed",
        Contradicted => "contradicted",
        NotDeclared => "notDeclared",
    }
}

intune_raw_preserving_string_enum! {
    /// Why the parser refused a member outright.
    ///
    /// These are import-security concerns. The native boundary is expected to
    /// reject them first; this is the second line, because a parser that trusts
    /// its caller's path hygiene is one bad importer away from writing outside
    /// the extraction directory.
    pub enum MemberPathRejection {
        EmptyPath => "emptyPath",
        AbsolutePath => "absolutePath",
        ParentTraversal => "parentTraversal",
        CurrentDirectorySegment => "currentDirectorySegment",
        BackslashSeparator => "backslashSeparator",
        DriveQualifiedPath => "driveQualifiedPath",
        ControlCharacter => "controlCharacter",
        DuplicatePath => "duplicatePath",
    }
}

intune_raw_preserving_string_enum! {
    /// Whether the container is treated as a Company Portal diagnostic report.
    pub enum ReportDetection {
        DeclaredUnconfirmed => "declaredUnconfirmed",
        DeclaredContradicted => "declaredContradicted",
        Refused => "refused",
    }
}

intune_raw_preserving_string_enum! {
    /// Whether the import envelope version is one this build reads.
    pub enum EnvelopeState {
        Supported => "supported",
        UnsupportedSchemaVersion => "unsupportedSchemaVersion",
    }
}

// ── Input ───────────────────────────────────────────────────────────────────

/// Container-level metadata supplied by the import boundary.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticReportEnvelope {
    /// Stable identifier for this container, used as the report coverage id.
    pub report_id: String,
    pub declared_product: Option<DeclaredProduct>,
    pub container_kind: ReportContainerKind,
    /// Version string the report declared for itself, if any.
    pub declared_report_schema: Option<String>,
    pub declared_app_version: Option<String>,
    pub collected_at: Option<String>,
    pub extraction: ExtractionOutcome,
    pub extraction_detail: Option<String>,
    /// Already-sanitized path the container came from. Never a live user path.
    pub sanitized_source_path: Option<String>,
    /// Observation time, supplied rather than read from a clock.
    ///
    /// The parser has no I/O and no clock, so this is what makes two runs over
    /// the same input byte-identical.
    pub observed_at_utc: String,
}

/// One already-extracted, already-decoded member handed to the parser.
///
/// `content` is text because decompression, encoding detection, and transcoding
/// all belong to the import boundary. Keeping bytes out of this crate is what
/// lets it stay `wasm32`-clean and free of an archive dependency.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SuppliedReportMember {
    pub member_id: String,
    /// Path exactly as recorded in the container, before any normalization.
    pub member_path: String,
    pub declared_role: Option<ReportMemberRole>,
    /// Size the container header claimed, which may disagree with what arrived.
    pub declared_bytes: u64,
    pub declared_encoding: Option<String>,
    /// Encoding the importer transcoded from, when it did.
    pub transcoded_from: Option<String>,
    pub import_state: MemberImportState,
    pub import_detail: Option<String>,
    pub content: Option<String>,
}

/// A whole saved report as the pure parser receives it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticReportImport {
    pub schema_version: u32,
    pub report: DiagnosticReportEnvelope,
    pub members: Vec<SuppliedReportMember>,
}

// ── Output ──────────────────────────────────────────────────────────────────

/// Where a structurally confirmed direct log member is handed on to.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MemberDelegation {
    pub target: String,
    pub reason: String,
}

/// One member after path checking, classification, and coverage assignment.
///
/// Deliberately carries no member content. The export projection would have to
/// strip it anyway, and a field that must always be redacted is a field better
/// not stored. The single exception is [`ClassifiedMember::failure_excerpt`],
/// which exists because a malformed member is useless to a reviewer without a
/// glimpse of why it failed, and which the export projection always redacts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ClassifiedMember {
    pub member_id: String,
    /// Normalized member path, or the raw path when normalization refused it.
    pub member_path: String,
    pub context: IntuneObservationContext,
    pub import_state: MemberImportState,
    pub content_kind: MemberContentKind,
    pub declared_role: Option<ReportMemberRole>,
    pub confirmed_role: ReportMemberRole,
    pub role_confirmation: RoleConfirmation,
    pub delegation: Option<MemberDelegation>,
    pub declared_bytes: u64,
    pub decoded_bytes: u64,
    pub line_count: u64,
    pub declared_encoding: Option<String>,
    pub transcoded_from: Option<String>,
    pub rejection: Option<MemberPathRejection>,
    pub detail: Option<String>,
    pub failure_excerpt: Option<String>,
}

/// A normalized fact, with the observation envelope that justifies it.
///
/// Only container-level metadata the importer declared becomes a fact on this
/// build. Deriving a fact from a member field would mean asserting a report
/// schema that no fixture backs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticFact {
    pub fact: IntuneNamedValue,
    pub context: IntuneObservationContext,
}

/// The immutable reduction findings are derived from.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticReportSnapshot {
    pub schema_version: u32,
    pub envelope_state: EnvelopeState,
    pub support_state: DiagnosticsSupportState,
    pub detection: ReportDetection,
    pub report: DiagnosticReportEnvelope,
    /// Members sorted by normalized path, then member id.
    pub members: Vec<ClassifiedMember>,
    pub facts: Vec<DiagnosticFact>,
    /// Container-level coverage. Its `artifact_id` is the report id, which is
    /// why it is kept out of [`DiagnosticReportSnapshot::coverage`].
    pub report_coverage: IntuneArtifactCoverage,
    /// Per-member coverage, one entry per supplied member, sorted by member id.
    pub coverage: Vec<IntuneArtifactCoverage>,
    pub findings: Vec<IntuneFinding>,
}

impl DiagnosticReportSnapshot {
    /// Coverage entries a finding may cite, container entry included.
    pub fn coverage_entries(&self) -> impl Iterator<Item = &IntuneArtifactCoverage> {
        std::iter::once(&self.report_coverage).chain(self.coverage.iter())
    }

    /// Members whose content structure confirmed them as direct logs.
    pub fn delegated_direct_logs(&self) -> impl Iterator<Item = &ClassifiedMember> {
        self.members
            .iter()
            .filter(|member| member.delegation.is_some())
    }
}
