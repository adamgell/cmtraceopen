//! Output contract for imported macOS Console plain-text exports captured against an
//! iOS / iPadOS device that is reproducing a Company Portal problem.
//!
//! Everything here is a value type. The crate performs no filesystem access, no device
//! access, and no Console control; the caller supplies the already-imported text.

use serde::{Deserialize, Serialize};

/// Schema version of [`PortalConsoleCapture`]. Bump on any breaking shape change.
pub const PORTAL_IOS_CONSOLE_SCHEMA_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// Shared primitives (mirrors the ESP evidence style, deliberately not reused)
// ---------------------------------------------------------------------------

/// How much is known about a record timestamp's placement on an absolute timeline.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum PortalTimestampKind {
    /// Explicit zero offset (`+0000`); already UTC.
    Utc,
    /// Explicit non-zero numeric offset (`-0700`); normalizable to UTC without guessing.
    Offset,
    /// Wall-clock text with no offset at all. The instant is device-local and the zone is
    /// unknown, so this value must never be silently treated as UTC.
    Local,
    /// The timestamp was never examined. Either the record carried no timestamp text at
    /// all, or it was abandoned before the timestamp column was interpreted (unsupported
    /// layout, or column extraction that failed on an earlier column). This is the absence
    /// of a verdict, not a negative one.
    Unknown,
    /// The timestamp column was examined and rejected: text was present but is not a valid
    /// instant. Never used for text that was simply not interpreted.
    Invalid,
}

/// A source timestamp plus everything known about its offset.
///
/// `normalized_utc` is populated only for [`PortalTimestampKind::Utc`] and
/// [`PortalTimestampKind::Offset`]. A missing timezone is a *state*, not an error, and is
/// never defaulted to UTC.
///
/// `raw_text` carries the source text of the timestamp column and nothing else; it is
/// empty whenever `kind` is [`PortalTimestampKind::Unknown`], because no column text was
/// ever interpreted. The verbatim record line lives on `PortalConsoleRecord::raw_text`.
///
/// When `normalized_utc` is present it is rendered at fixed nanosecond width, so comparing
/// two of these strings byte-wise agrees with comparing the instants they denote.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PortalTimestamp {
    pub raw_text: String,
    pub original_offset: Option<String>,
    pub normalized_utc: Option<String>,
    pub kind: PortalTimestampKind,
}

/// Privacy classification attached to a carried string value.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum PortalSensitivity {
    Public,
    Sensitive,
}

/// A string value carried together with its privacy classification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PortalClassifiedString {
    pub value: String,
    pub sensitivity: PortalSensitivity,
}

/// Stable pointer from a derived fact back to the artifact it came from.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PortalEvidenceRef {
    pub evidence_id: String,
    pub source_artifact_id: String,
}

/// Confidence attached to a derived (non-verbatim) claim.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum PortalConsoleConfidence {
    High,
    Low,
}

// ---------------------------------------------------------------------------
// Layout
// ---------------------------------------------------------------------------

/// A column role in a Console plain-text export.
///
/// Console lets the operator choose which columns are visible before copying, and localizes
/// the header titles. Roles are resolved from the header row through an alias table so a
/// different visible column set or a localized header is *detected* rather than mis-parsed.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum PortalConsoleColumn {
    Timestamp,
    Thread,
    Type,
    Activity,
    Pid,
    Ttl,
    Subsystem,
    Category,
    Process,
    Library,
    Message,
}

/// Decimal separator used by the fractional-seconds part of the timestamp column.
///
/// Detected from record data rather than from the header, because the header does not
/// carry it.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum PortalConsoleDecimalSeparator {
    Dot,
    Comma,
}

/// A resolved, registered Console export layout.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PortalConsoleLayout {
    /// Stable identifier of the registered layout, e.g. `console-plaintext-v1`.
    pub layout_id: String,
    /// The header row exactly as it appeared in the source.
    pub header_raw: String,
    /// Column roles in source order.
    pub columns: Vec<PortalConsoleColumn>,
    pub decimal_separator: PortalConsoleDecimalSeparator,
    /// Locale tag when the header was resolved through non-English aliases.
    pub locale_hint: Option<String>,
}

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------

/// Result of testing whether some text is a Console plain-text export we can parse.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum PortalConsoleDetectionOutcome {
    /// Recognized header, registered layout. Full parse.
    Supported,
    /// Console-shaped content whose layout is not registered, or whose header is missing.
    /// Parsed conservatively or degraded to generic preserved records; never a confident
    /// wrong parse.
    UnsupportedLayout,
    /// Not a Console plain-text export.
    NotConsoleExport,
}

/// Detection verdict plus the reason, so a caller can explain a refusal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PortalConsoleDetection {
    pub outcome: PortalConsoleDetectionOutcome,
    pub layout: Option<PortalConsoleLayout>,
    pub reason: String,
}

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------

/// Per-record parse state. Nothing is ever dropped; unparsed input stays visible.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum PortalConsoleParseState {
    /// Every column required by the layout was extracted and validated.
    Parsed,
    /// The line anchored as a record start but a column or the timestamp failed validation.
    Malformed,
    /// The record was cut off by the copy/paste boundary at the start or end of the capture.
    Truncated,
    /// The layout is not registered, so columns were deliberately not interpreted.
    Unsupported,
}

/// Normalized Console message type.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum PortalConsoleSeverity {
    Debug,
    Info,
    Default,
    Error,
    Fault,
    Activity,
    Unknown,
}

/// The `Type` column, preserved verbatim alongside its normalization.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PortalConsoleLevel {
    pub raw: String,
    pub normalized: PortalConsoleSeverity,
}

/// Which structural rule attributed a record to Company Portal.
///
/// Free message text is never a signature: the documented workflow copies *all* Console
/// records, so unrelated processes routinely mention `Intune` or `CompanyPortal`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum PortalConsoleSourceSignature {
    /// The emitting process is a known Company Portal process.
    ProcessName,
    /// The record's subsystem sits in the Company Portal subsystem namespace.
    SubsystemNamespace,
    /// No structural signature matched.
    None,
}

/// Company Portal attribution for a record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum PortalConsoleSourceClass {
    /// Structurally attributed to Company Portal.
    CompanyPortal,
    /// A record from some other process, retained verbatim as capture context.
    OtherProcess,
    /// Attribution impossible because the record did not parse.
    Unattributed,
}

/// The structural source fields a record was attributed from.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PortalConsoleSource {
    pub process: Option<String>,
    pub library: Option<String>,
    pub subsystem: Option<String>,
    pub category: Option<String>,
    pub class: PortalConsoleSourceClass,
    pub signature: PortalConsoleSourceSignature,
}

/// Semantic buckets that fixtures actually prove. Anything else stays an ordinary record.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum PortalConsoleSemanticCategory {
    SignInAuth,
    EnrollmentProfile,
    SyncCompliance,
    AppDeviceAction,
    NetworkService,
    DiagnosticActivity,
}

/// Optional semantic classification, derived only from the structural category token.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PortalConsoleSemanticEvidence {
    pub category: PortalConsoleSemanticCategory,
    /// The verbatim structural category value that proved the classification.
    pub matched_category_token: String,
    pub confidence: PortalConsoleConfidence,
}

/// Exact reference from a record back to its position in the source text.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PortalConsoleRecordRef {
    /// Zero-based index of the record within the capture, in source order.
    pub record_index: usize,
    /// One-based physical line number where the record starts.
    pub first_line_number: usize,
    /// One-based physical line number where the record ends (inclusive of continuations).
    pub last_line_number: usize,
    pub evidence_ref: PortalEvidenceRef,
}

/// One normalized Console record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PortalConsoleRecord {
    pub reference: PortalConsoleRecordRef,
    pub timestamp: PortalTimestamp,
    pub thread_id: Option<String>,
    pub activity_id: Option<String>,
    pub pid: Option<u32>,
    pub ttl: Option<u32>,
    pub level: PortalConsoleLevel,
    pub source: PortalConsoleSource,
    pub message: PortalClassifiedString,
    /// Number of continuation lines folded into this record.
    pub continuation_line_count: usize,
    pub parse_state: PortalConsoleParseState,
    pub semantic: Option<PortalConsoleSemanticEvidence>,
    /// The record's source text, verbatim, including any continuation lines.
    pub raw_text: String,
}

// ---------------------------------------------------------------------------
// Coverage
// ---------------------------------------------------------------------------

/// Why a region of the source is not represented as a fully parsed record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum PortalConsoleCoverageKind {
    /// The copy began part-way through a record.
    TruncatedLeading,
    /// The copy ended part-way through a record.
    TruncatedTrailing,
    /// A line anchored as a record but failed column or timestamp validation.
    MalformedRecord,
    /// The header row was present but its layout is not registered.
    UnsupportedLayout,
    /// No recognizable Console header row was found.
    HeaderMissing,
}

/// A visible, non-silent account of input that did not become a clean record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PortalConsoleCoverage {
    pub kind: PortalConsoleCoverageKind,
    pub first_line_number: usize,
    pub last_line_number: usize,
    pub detail: String,
    pub raw_text: String,
}

// ---------------------------------------------------------------------------
// Capture-level facts
// ---------------------------------------------------------------------------

/// Whether capture records may be ordered against server / cloud timelines.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum PortalOrderingConfidence {
    /// Every parsed record carries an explicit UTC offset.
    CrossSourceComparable,
    /// At least one parsed record has no timezone. Relative order inside the capture is
    /// still source order, but records must not be ordered against server / cloud sources.
    CaptureLocalOnly,
    /// No parsed record carries a usable instant.
    Unordered,
}

/// Ordering verdict for the capture as a whole.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PortalConsoleOrdering {
    pub confidence: PortalOrderingConfidence,
    pub records_without_offset: usize,
    pub detail: String,
}

/// Whether the capture identified the Company Portal / OS versions it came from.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum PortalConsoleVersionState {
    Known,
    Unknown,
}

/// Versions, recovered only from a strictly anchored Company Portal version banner.
///
/// Console exports carry no version column, so absence is the common case and downgrades
/// semantic evidence to [`PortalConsoleConfidence::Low`] rather than inventing a version.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PortalConsoleCaptureVersions {
    pub state: PortalConsoleVersionState,
    pub company_portal_version: Option<String>,
    pub os_version: Option<String>,
    pub evidence: Option<PortalEvidenceRef>,
}

/// Counts, so a caller can show coverage without walking every record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PortalConsoleTotals {
    pub source_lines: usize,
    pub total_records: usize,
    pub company_portal_records: usize,
    pub other_process_records: usize,
    pub unattributed_records: usize,
    pub malformed_records: usize,
    pub truncated_records: usize,
}

/// The parse result for one imported Console plain-text export.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PortalConsoleCapture {
    pub schema_version: u32,
    pub source_artifact_id: String,
    pub detection: PortalConsoleDetection,
    pub layout: Option<PortalConsoleLayout>,
    pub ordering: PortalConsoleOrdering,
    pub versions: PortalConsoleCaptureVersions,
    /// Every record, in source order. Company Portal and unrelated records alike.
    pub records: Vec<PortalConsoleRecord>,
    pub coverage: Vec<PortalConsoleCoverage>,
    pub totals: PortalConsoleTotals,
}

impl PortalConsoleCapture {
    /// The Company Portal subset, in source order.
    ///
    /// Filtering is structural: it reads [`PortalConsoleSource::class`], which is set only
    /// from a verified process name or subsystem namespace.
    pub fn company_portal_records(&self) -> Vec<&PortalConsoleRecord> {
        self.records
            .iter()
            .filter(|record| record.source.class == PortalConsoleSourceClass::CompanyPortal)
            .collect()
    }

    /// Records from every other process, in source order. Retained as capture context.
    pub fn other_process_records(&self) -> Vec<&PortalConsoleRecord> {
        self.records
            .iter()
            .filter(|record| record.source.class == PortalConsoleSourceClass::OtherProcess)
            .collect()
    }

    /// Whether the capture may be placed on an absolute timeline next to server evidence.
    pub fn is_cross_source_comparable(&self) -> bool {
        self.ordering.confidence == PortalOrderingConfidence::CrossSourceComparable
    }
}
