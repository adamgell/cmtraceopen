//! Public model types for the macOS Company Portal application-log parser.

use serde::{Deserialize, Serialize};

use crate::models::log_entry::Severity;

/// Schema version of the Company Portal macOS log projection.
pub const COMPANY_PORTAL_MACOS_LOG_SCHEMA_VERSION: u32 = 1;

/// Structural process tokens that confirm a direct Company Portal app log.
///
/// This is the value of the second grammar field, not free message text. The
/// macOS process name has no space (see the native unified-log predicate
/// `process == "CompanyPortal"`).
pub const COMPANY_PORTAL_PROCESS_TOKENS: &[&str] = &["CompanyPortal"];

/// Directory hint used by native known-source discovery. A *hint only*: it never
/// confirms the source kind on its own.
pub const COMPANY_PORTAL_LOG_DIRECTORY_HINT: &str = "Library/Logs/CompanyPortal";

/// App-version families whose record grammar is covered by committed fixtures.
///
/// A version banner outside these families is not an error: the records still
/// parse, but detection reports [`PortalDetectionConfidence::Probable`] with an
/// explicit [`PortalCoverageKind::UnknownAppVersion`] note instead of
/// [`PortalDetectionConfidence::Confirmed`].
///
/// It is specifically *not* [`PortalDetectionConfidence::Low`], which this
/// module reserves for a record structure that is mostly unusable. An
/// unrecognised version says nothing about whether the records parsed.
pub const VALIDATED_APP_VERSION_FAMILIES: &[&str] = &["5.2504."];

/// Which macOS artifact a candidate text actually is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PortalSourceKind {
    /// Direct Company Portal application log (this module's source kind).
    CompanyPortalMacosAppLog,
    /// Same Microsoft macOS house grammar, but a different process
    /// (`IntuneMdmAgent`, `IntuneMDM-Daemon`, ...).
    IntuneMacosOtherProcessLog,
    /// `log show --style ndjson` export. Handled elsewhere; rejected here.
    MacosUnifiedLogExport,
    /// Saved Company Portal diagnostic report summary/manifest. Rejected here.
    CompanyPortalDiagnosticReport,
    /// Nothing recognizable.
    Unrecognized,
}

/// How strongly the content confirms [`PortalSourceKind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PortalDetectionConfidence {
    /// Structure and process signature both confirmed, and no version banner
    /// contradicted them.
    ///
    /// A banner is not required: rotated members routinely carry no banner at
    /// all, and demoting them would punish evidence for being a continuation
    /// file. Check [`PortalAppVersion::support`] when you need to know whether a
    /// version was actually declared.
    Confirmed,
    /// Structure and process signature confirmed, but a version banner was
    /// present and named a family no committed fixture covers.
    Probable,
    /// Signature present but the record structure is mostly unusable.
    Low,
    /// Not this source kind.
    Rejected,
}

/// An individual signal that contributed to detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PortalSignature {
    /// At least one line satisfied the full record grammar.
    RecordGrammar,
    /// A structurally valid record carried a Company Portal process token.
    CompanyPortalProcessToken,
    /// A structurally valid record carried a Company Portal version banner.
    VersionBanner,
    /// The supplied path matched the known-source directory hint.
    PathHint,
    /// Lines shaped like `log show --style ndjson` output.
    UnifiedLogNdjsonShape,
    /// Header shaped like a saved diagnostic-report summary.
    DiagnosticReportHeader,
}

/// Interpretation of a source timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PortalTimestampKind {
    Utc,
    Local,
    Unknown,
}

/// A source timestamp with its original text preserved.
///
/// Company Portal writes wall-clock local time with no offset, so
/// `original_offset` and `normalized_utc` stay `None` and `kind` is
/// [`PortalTimestampKind::Local`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortalTimestamp {
    pub raw_text: String,
    pub original_offset: Option<String>,
    pub normalized_utc: Option<String>,
    pub kind: PortalTimestampKind,
}

/// Privacy classification of a string value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PortalSensitivity {
    Public,
    Sensitive,
}

/// A string carrying its privacy classification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortalClassifiedString {
    pub value: String,
    pub sensitivity: PortalSensitivity,
}

impl PortalClassifiedString {
    pub fn sensitive(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            sensitivity: PortalSensitivity::Sensitive,
        }
    }

    pub fn public(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            sensitivity: PortalSensitivity::Public,
        }
    }
}

/// Stable reference from a record back to the artifact it came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortalEvidenceRef {
    pub evidence_id: String,
    pub source_artifact_id: String,
}

/// Parse state of a single logical record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PortalRecordState {
    /// Full record grammar satisfied.
    Parsed,
    /// Looked like a record start but failed the grammar (truncated/corrupt).
    Malformed,
    /// Continuation text with no preceding record head in this file.
    Unframed,
}

/// Normalized evidence category.
///
/// Only categories proven by a committed fixture are ever assigned; anything
/// else stays [`PortalEvidenceCategory::Generic`]. Under-claiming is deliberate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PortalEvidenceCategory {
    SignInAuthentication,
    EnrollmentProfile,
    SyncCompliance,
    AppCatalogAction,
    DeviceAction,
    NetworkServiceResponse,
    DiagnosticReportAction,
    Generic,
}

/// Text encoding of the decoded artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PortalEncoding {
    Utf8,
    Utf8Bom,
    Utf16Le,
    Utf16Be,
    /// UTF-8 decode failed; decoded as Windows-1252 (repo-wide fallback).
    Windows1252Fallback,
}

/// Result of decoding raw artifact bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortalDecodedText {
    pub text: String,
    pub encoding: PortalEncoding,
    pub had_bom: bool,
    pub had_replacement_chars: bool,
}

/// Whether the declared app version is covered by committed fixtures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PortalVersionSupport {
    /// Banner found and inside [`VALIDATED_APP_VERSION_FAMILIES`].
    Validated,
    /// Banner found but the version family has no fixture coverage.
    Unknown,
    /// No version banner in the artifact (normal for rotated members).
    NotDeclared,
}

/// The Company Portal application version declared by the artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortalAppVersion {
    pub raw_text: Option<String>,
    pub support: PortalVersionSupport,
    pub source_line: Option<u32>,
}

/// Rotation position of an artifact within its log set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortalRotationMember {
    pub file_name: Option<String>,
    /// Higher is older. `None` = not a recognized member. An index too large for
    /// `u32` saturates to [`u32::MAX`], which sorts oldest.
    ///
    /// A `0` here does **not** mean the live file: `CompanyPortal-0.log` is a
    /// recognized rotated member whose declared index is `0`. Read
    /// [`Self::is_current`] for that, which is derived from the *absence* of a
    /// declared index rather than from its value.
    pub rotation_index: Option<u32>,
    /// True only for the undecorated `CompanyPortal.log`.
    pub is_current: bool,
}

/// Why a line or artifact needed coverage reporting rather than a clean parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PortalCoverageKind {
    MalformedRecord,
    UnframedLeadingText,
    UnknownAppVersion,
    MissingVersionBanner,
    UnsupportedSourceKind,
    LowConfidenceStructure,
    EncodingFallback,
    EmptyInput,
}

/// A single coverage observation. Unsupported input stays visible here; it is
/// never silently dropped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortalCoverageNote {
    pub kind: PortalCoverageKind,
    pub line_number: Option<u32>,
    pub detail: String,
}

/// Per-artifact coverage accounting.
///
/// `covered_lines == total_lines` holds when
/// `detection.source_kind == PortalSourceKind::CompanyPortalMacosAppLog`: every
/// physical line is then either inside a record or counted as blank. For any
/// other detected kind the artifact is rejected before framing, so
/// `covered_lines` is `0` while `total_lines` still reports the real physical
/// line count, and the file is represented by an `UnsupportedSourceKind` note
/// rather than per-line accounting. Framing text this module does not own would
/// be a worse answer than declining it. A rejected artifact may carry further
/// notes recorded before detection ran, such as `EmptyInput` or
/// `EncodingFallback`, so consumers should not assume a single note.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortalCoverage {
    pub total_lines: u32,
    pub blank_lines: u32,
    pub covered_lines: u32,
    pub record_count: u32,
    pub parsed_record_count: u32,
    pub malformed_record_count: u32,
    pub unframed_record_count: u32,
    pub continuation_line_count: u32,
    pub notes: Vec<PortalCoverageNote>,
}

/// One logical Company Portal record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortalLogRecord {
    pub record_index: u64,
    /// 1-based physical line of the record head.
    pub line_number: u32,
    /// Number of physical lines the record spans (head plus continuations).
    pub line_span: u32,
    pub state: PortalRecordState,
    pub timestamp: Option<PortalTimestamp>,
    /// Structural severity letter exactly as written, when present.
    pub severity_letter: Option<String>,
    pub severity: Severity,
    pub process: Option<String>,
    pub component: Option<String>,
    pub thread_id: Option<u32>,
    /// Activity correlation id from an anchored `[activityId=...]` message prefix.
    pub activity_id: Option<PortalClassifiedString>,
    /// Full message text including continuation lines. Lossless.
    pub message: PortalClassifiedString,
    /// Exact original physical lines of this record, joined with `\n`. Lossless.
    pub raw_text: PortalClassifiedString,
    pub category: PortalEvidenceCategory,
    pub evidence_ref: PortalEvidenceRef,
}

/// Detection outcome for a candidate artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortalDetection {
    pub source_kind: PortalSourceKind,
    pub confidence: PortalDetectionConfidence,
    /// True only when the caller supplied a path under the known-source folder.
    pub path_hint_matched: bool,
    pub signatures: Vec<PortalSignature>,
    pub rejections: Vec<String>,
    pub sampled_lines: u32,
    /// Lines that look like a record start (valid or malformed).
    pub record_start_lines: u32,
    /// Lines that satisfied the full record grammar.
    pub record_head_lines: u32,
    /// Valid record heads whose process field is a Company Portal token.
    pub company_portal_record_lines: u32,
}

/// Where an artifact came from. Supplied by the caller; the crate performs no
/// filesystem access of its own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortalLogSource {
    pub file_path: String,
    pub source_artifact_id: String,
    pub encoding: PortalEncoding,
}

/// Full parse of one Company Portal macOS log artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortalLogParse {
    pub schema_version: u32,
    pub source_artifact_id: String,
    pub file_path: String,
    pub encoding: PortalEncoding,
    pub rotation: PortalRotationMember,
    pub detection: PortalDetection,
    pub app_version: PortalAppVersion,
    pub records: Vec<PortalLogRecord>,
    pub coverage: PortalCoverage,
}

/// Redaction kind of a placeholder token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PortalRedactionKind {
    Email,
    Guid,
    Serial,
    Token,
    Url,
    Certificate,
    Path,
    UserName,
    Ip,
    Mac,
}

impl PortalRedactionKind {
    pub(crate) fn tag(self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::Guid => "guid",
            Self::Serial => "serial",
            Self::Token => "token",
            Self::Url => "url",
            Self::Certificate => "cert",
            Self::Path => "path",
            Self::UserName => "user",
            Self::Ip => "ip",
            Self::Mac => "mac",
        }
    }
}

/// A placeholder token that was issued during redaction. The original value is
/// deliberately absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortalPlaceholder {
    pub token: String,
    pub kind: PortalRedactionKind,
    pub occurrences: u32,
}

/// A record as it appears in a redacted export.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortalRedactedRecord {
    pub record_index: u64,
    pub line_number: u32,
    pub line_span: u32,
    pub state: PortalRecordState,
    pub timestamp: Option<PortalTimestamp>,
    pub severity_letter: Option<String>,
    pub severity: Severity,
    pub process: Option<String>,
    pub component: Option<String>,
    pub thread_id: Option<u32>,
    pub activity_id: Option<String>,
    pub category: PortalEvidenceCategory,
    pub message: String,
    pub raw_text: String,
    pub evidence_id: String,
}

/// Deterministic, redacted projection of a [`PortalLogParse`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortalRedactedExport {
    pub schema_version: u32,
    pub source_artifact_id: String,
    pub file_path: String,
    pub encoding: PortalEncoding,
    pub rotation: PortalRotationMember,
    pub detection: PortalDetection,
    pub app_version: PortalAppVersion,
    pub coverage: PortalCoverage,
    pub records: Vec<PortalRedactedRecord>,
    /// Issued placeholders, ordered by kind then token for stable output.
    pub placeholders: Vec<PortalPlaceholder>,
}
