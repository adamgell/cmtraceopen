//! Types of the versioned normalized Apple unified-log capture schema.
//!
//! Every public type mirrors the crate's evidence house style: derives
//! `Debug, Clone, PartialEq, Serialize, Deserialize` and serializes
//! `camelCase`. Sensitive values are wrapped in [`PortalClassifiedString`] so
//! the redacted projection can act on classification rather than on guesswork
//! at export time.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Primitives
// ---------------------------------------------------------------------------

/// How much is known about the wall-clock meaning of a timestamp.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PortalTimestampKind {
    /// Explicit UTC (`Z` offset).
    Utc,
    /// Explicit non-zero UTC offset.
    Offset,
    /// Wall-clock text with no offset; the true instant is unknown.
    Local,
    /// Only boot-relative / mach-continuous time is available.
    BootRelative,
    /// No timestamp supplied at all.
    Unspecified,
    /// Text was present but could not be interpreted; kept verbatim.
    Invalid,
}

/// A timestamp that always preserves its original text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortalTimestamp {
    pub raw_text: String,
    pub original_offset: Option<String>,
    pub normalized_utc: Option<String>,
    pub kind: PortalTimestampKind,
}

impl PortalTimestamp {
    /// A timestamp placeholder for records that supplied no time text.
    pub fn unspecified() -> Self {
        Self {
            raw_text: String::new(),
            original_offset: None,
            normalized_utc: None,
            kind: PortalTimestampKind::Unspecified,
        }
    }

    /// True when the record can be placed on an absolute timeline.
    pub fn is_absolute(&self) -> bool {
        matches!(
            self.kind,
            PortalTimestampKind::Utc | PortalTimestampKind::Offset
        ) && self.normalized_utc.is_some()
    }
}

/// Boot-relative timing metadata, preserved even when wall clock is absent.
///
/// Present only when the collector supplied at least one boot-relative field.
/// Timezone lives on the record instead, because a timezone name describes the
/// wall clock rather than the boot reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortalBootRelativeTime {
    pub boot_uuid: Option<String>,
    pub mach_timestamp: Option<u64>,
    pub time_since_boot_ns: Option<u64>,
}

impl PortalBootRelativeTime {
    /// True when no boot-relative field carried a value.
    pub fn is_empty(&self) -> bool {
        self.boot_uuid.is_none()
            && self.mach_timestamp.is_none()
            && self.time_since_boot_ns.is_none()
    }
}

/// Privacy classification of a captured string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    pub fn public(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            sensitivity: PortalSensitivity::Public,
        }
    }

    pub fn sensitive(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            sensitivity: PortalSensitivity::Sensitive,
        }
    }
}

/// Pointer from a derived object back to the record it came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortalEvidenceRef {
    pub evidence_id: String,
    pub source_artifact_id: String,
}

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------

/// Normalized severity. The raw `messageType` text is always kept alongside.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PortalUnifiedLogLevel {
    Debug,
    Info,
    Default,
    Notice,
    Warning,
    Error,
    Fault,
    Unknown,
}

/// A unified-log `messageType`, lossless plus normalized.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortalMessageType {
    pub raw: String,
    pub level: PortalUnifiedLogLevel,
}

/// Activity, signpost, and request identifiers.
///
/// These are the *only* keys allowed to justify a merge with a direct Company
/// Portal log; see [`super::correlation`].
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortalActivityIds {
    pub activity_id: Option<String>,
    pub parent_activity_id: Option<String>,
    pub signpost_id: Option<String>,
    pub signpost_name: Option<String>,
    pub signpost_type: Option<String>,
    pub trace_id: Option<String>,
    pub request_id: Option<String>,
    pub correlation_id: Option<String>,
}

impl PortalActivityIds {
    /// True when at least one explicit identifier is present.
    pub fn has_any(&self) -> bool {
        self.activity_id.is_some()
            || self.parent_activity_id.is_some()
            || self.signpost_id.is_some()
            || self.trace_id.is_some()
            || self.request_id.is_some()
            || self.correlation_id.is_some()
    }
}

/// Redaction the *native collector* already applied before handing records over.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortalRecordRedaction {
    pub applied: bool,
    pub redacted_fields: Vec<String>,
    pub policy_id: Option<String>,
}

/// One normalized unified-log record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortalUnifiedLogRecord {
    /// Deterministic id derived from stream position: `ul-<streamIndex:06>`.
    pub record_id: String,
    /// Zero-based position in the supplied stream. This is the exact source
    /// order and is never re-sorted.
    pub stream_index: u64,
    /// Sequence number declared by the collector. May duplicate or disagree
    /// with `stream_index`; both are preserved.
    pub declared_sequence: Option<u64>,
    pub timestamp: PortalTimestamp,
    /// IANA timezone the wall clock was rendered in, when the collector knew it.
    pub timezone_name: Option<String>,
    pub boot_relative: Option<PortalBootRelativeTime>,
    pub process: String,
    pub process_image_path: Option<PortalClassifiedString>,
    pub sender_image_path: Option<PortalClassifiedString>,
    pub subsystem: Option<String>,
    pub category: Option<String>,
    pub message_type: PortalMessageType,
    pub event_message: PortalClassifiedString,
    pub process_id: Option<u32>,
    pub thread_id: Option<u64>,
    pub activity: PortalActivityIds,
    pub redaction: PortalRecordRedaction,
    /// Fields the schema did not name, preserved losslessly and in stable order.
    pub unknown_fields: BTreeMap<String, serde_json::Value>,
}

// ---------------------------------------------------------------------------
// Capture metadata
// ---------------------------------------------------------------------------

/// The `log show` predicate a capture was taken with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortalCapturePredicate {
    pub predicate_id: Option<String>,
    pub predicate_text: String,
    pub predicate_version: Option<u32>,
    /// True when `predicate_text` is the known `intune-agent` preset verbatim.
    pub matches_known_preset: bool,
}

/// The time window a capture covers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortalCaptureWindow {
    pub start: Option<PortalTimestamp>,
    pub end: Option<PortalTimestamp>,
    /// Relative window (`--last 1h`) when no explicit start/end was used.
    pub last: Option<String>,
    pub timezone_name: Option<String>,
}

/// Host and app versions at collection time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortalCaptureHost {
    pub host_name: Option<PortalClassifiedString>,
    pub os_version: Option<String>,
    pub os_build: Option<String>,
    pub company_portal_version: Option<String>,
    pub intune_agent_version: Option<String>,
}

/// Identity of the native collector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortalCollectorInfo {
    pub name: Option<String>,
    pub version: Option<String>,
}

/// Redaction metadata declared at capture scope.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortalCaptureRedaction {
    pub applied: bool,
    pub policy_id: Option<String>,
    pub placeholder_style: Option<String>,
}

/// Provenance of a capture: what was asked for, of what, by whom, when.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortalUnifiedLogCapture {
    pub schema_id: String,
    pub schema_version: u32,
    pub capture_id: String,
    pub predicate: PortalCapturePredicate,
    /// Version of the in-crate selection rules used to reduce this capture.
    pub selection_predicate_version: u32,
    pub window: PortalCaptureWindow,
    pub host: PortalCaptureHost,
    pub collector: PortalCollectorInfo,
    pub collected_at_utc: Option<String>,
    pub redaction: PortalCaptureRedaction,
}

// ---------------------------------------------------------------------------
// Coverage
// ---------------------------------------------------------------------------

/// Why part of a capture is missing, degraded, or excluded.
///
/// Nothing is ever dropped silently: every skipped line, refused schema, capped
/// query, or unselected record produces one of these.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PortalCoverageStatus {
    /// The capture was collected in full.
    Available,
    /// The collector hit its result cap; later matches were not emitted.
    Capped,
    /// The collector deliberately skipped a source or window.
    Skipped,
    /// Collection was refused by the OS (TCC / Full Disk Access / entitlement).
    PermissionDenied,
    /// A stream line was not valid JSON, or was not a JSON object.
    MalformedRecord,
    /// Schema id recognised, version outside the supported range.
    UnsupportedSchemaVersion,
    /// Capture metadata this build does not recognise.
    ///
    /// Raised when the header declares no `schemaId` or an unrecognised one, and
    /// also when a capture declares its own coverage entry with a status this
    /// build has no variant for (see `absorb_declared_coverage`). Both mean the
    /// same thing to a consumer: something in the capture's own description was
    /// not understood, so the detail string carries the specifics. A version
    /// that is recognised but out of range is
    /// [`Self::UnsupportedSchemaVersion`] instead.
    UnknownSchema,
    /// Record parsed fine but is not Company Portal evidence.
    NotSelected,
    /// Record retained, but its time is local-only or boot-relative-only.
    DegradedTimestamp,
    /// Two records declared the same sequence number; both retained.
    DuplicateSequence,
}

/// Whether a coverage entry describes the whole capture or one record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PortalCoverageScope {
    Capture,
    Record,
}

/// One explicit gap, degradation, or exclusion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortalCoverageEntry {
    pub coverage_id: String,
    pub status: PortalCoverageStatus,
    pub scope: PortalCoverageScope,
    pub detail: String,
    pub stream_index: Option<u64>,
    /// Verbatim input for malformed or unsupported content, so nothing is lost.
    pub raw_excerpt: Option<PortalClassifiedString>,
    pub evidence: Vec<PortalEvidenceRef>,
}

/// The usable identifier in `value`, or `None`.
///
/// An empty or whitespace-only identifier names nothing. Treating it as a value
/// makes every record carrying one "share" an identifier with every other,
/// which links records that have no relationship, collapses them into a single
/// empty-keyed activity group, and justifies merges against a direct log.
///
/// Ingest already normalises blank fields to `None`, so this cannot arise from
/// parsing a capture. It arises when a record reaches selection, reduction, or
/// correlation by deserialization or direct construction, which the public API
/// allows. This is the one place the rule lives; every identifier comparison in
/// this module goes through it.
pub fn usable_identifier(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|id| !id.is_empty())
}

/// Mints the `coverage_id` for the entry at `index` in a capture's coverage.
///
/// Coverage entries come from two producers, ingest and reduction, and land in
/// one array that a consumer reads as a single sequence. This is the only place
/// the id scheme exists, so the two producers cannot drift apart: the index is
/// the entry's own position in that array, which is what makes reduction able to
/// continue the numbering ingest started simply by appending.
pub fn coverage_id(index: usize) -> String {
    format!("coverage-{index:04}")
}

/// Counts describing what the capture contained.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortalCaptureStats {
    pub stream_lines: u64,
    pub records_parsed: u64,
    pub records_malformed: u64,
    pub records_selected: u64,
    /// Total matches the collector saw, which may exceed `records_parsed`.
    pub total_matched: Option<u64>,
    pub capped: bool,
    pub result_cap: Option<u64>,
}

// ---------------------------------------------------------------------------
// Ingest result
// ---------------------------------------------------------------------------

/// Everything a supplied capture yielded: provenance, records, coverage.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortalUnifiedLogCaptureSet {
    pub schema_id: Option<String>,
    pub schema_version: Option<u32>,
    /// False when the schema is unknown/unsupported or the header is missing.
    /// Records are then left unreduced and preserved in `raw_unsupported`.
    pub supported: bool,
    pub capture: Option<PortalUnifiedLogCapture>,
    pub records: Vec<PortalUnifiedLogRecord>,
    pub coverage: Vec<PortalCoverageEntry>,
    pub stats: PortalCaptureStats,
    /// Lossless payload retained when `supported` is false.
    pub raw_unsupported: Vec<serde_json::Value>,
}

// ---------------------------------------------------------------------------
// Selection
// ---------------------------------------------------------------------------

/// Why a record was, or was not, treated as Company Portal evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PortalSelectionReason {
    /// Process and subsystem both matched a verified pair.
    VerifiedProcessAndSubsystem,
    /// Subsystem was unverified, but the record shares an explicit activity or
    /// signpost identifier with a record selected on its own merits.
    ActivityLinkedToSelected,
    /// Process is in the capture predicate but the subsystem is missing or
    /// unverified. A process name alone is not sufficient.
    ProcessOnlyInsufficient,
    /// The only Company Portal signal was free text inside the message body.
    MessageMentionOnlyIgnored,
    /// Neither process nor subsystem relates to Company Portal.
    UnrelatedSource,
}

/// The selection verdict recorded on every evidence item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortalSelection {
    pub selected: bool,
    pub reason: PortalSelectionReason,
    pub predicate_version: u32,
    pub matched_process: Option<String>,
    pub matched_subsystem: Option<String>,
}

// ---------------------------------------------------------------------------
// Evidence
// ---------------------------------------------------------------------------

/// Proven Company Portal activity classes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PortalUnifiedLogEvidenceKind {
    ProcessStartup,
    Authentication,
    EnrollmentProfile,
    SyncCompliance,
    AppAction,
    DeviceAction,
    NetworkRequest,
    Diagnostics,
    /// Selected source, but the category is not one we can prove a meaning for.
    Unclassified,
}

/// How much the evidence classification can be trusted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PortalEvidenceConfidence {
    /// Verified source and a known category.
    Exact,
    /// Verified source, or an explicit activity link, with a weaker category.
    Strong,
    /// Retained but not relied on.
    Low,
}

/// One reduced Company Portal observation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortalUnifiedLogEvidence {
    pub evidence_id: String,
    pub record_id: String,
    pub stream_index: u64,
    pub kind: PortalUnifiedLogEvidenceKind,
    pub confidence: PortalEvidenceConfidence,
    pub level: PortalUnifiedLogLevel,
    pub timestamp: PortalTimestamp,
    pub summary: PortalClassifiedString,
    pub activity: PortalActivityIds,
    pub selection: PortalSelection,
    pub evidence: Vec<PortalEvidenceRef>,
}

/// Records grouped by activity identifier, in exact source order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortalActivityGroup {
    pub activity_id: String,
    pub parent_activity_id: Option<String>,
    pub record_ids: Vec<String>,
    pub signpost_ids: Vec<String>,
    pub first_stream_index: u64,
    pub last_stream_index: u64,
}

/// The reduced view a consumer works with.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortalUnifiedLogReduction {
    pub schema_id: Option<String>,
    pub schema_version: Option<u32>,
    pub supported: bool,
    pub capture: Option<PortalUnifiedLogCapture>,
    pub evidence: Vec<PortalUnifiedLogEvidence>,
    pub activities: Vec<PortalActivityGroup>,
    pub coverage: Vec<PortalCoverageEntry>,
    pub stats: PortalCaptureStats,
}

// ---------------------------------------------------------------------------
// Correlation with direct Company Portal logs
// ---------------------------------------------------------------------------

/// A key from a direct Company Portal log that unified-log evidence may attach to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortalDirectLogAnchor {
    pub anchor_id: String,
    pub timestamp: PortalTimestamp,
    pub activity_id: Option<String>,
    pub signpost_id: Option<String>,
    pub request_id: Option<String>,
    pub correlation_id: Option<String>,
    /// Set only when a reviewed, documented relationship justifies the join.
    pub documented_relationship_id: Option<String>,
}

/// What justified (or failed to justify) attaching evidence to an anchor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PortalMergeBasis {
    ActivityId,
    SignpostId,
    RequestId,
    CorrelationId,
    DocumentedRelationship,
    /// Timestamps coincide and nothing else does. Never merges.
    TimeOnly,
}

/// An accepted link between a direct-log anchor and a unified-log record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortalCorrelationLink {
    pub anchor_id: String,
    pub record_id: String,
    pub basis: PortalMergeBasis,
    pub matched_value: PortalClassifiedString,
    pub confidence: PortalEvidenceConfidence,
    pub merged: bool,
}

/// A refused link, kept so the near-miss stays visible.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortalCorrelationRejection {
    pub anchor_id: String,
    pub record_id: String,
    pub basis: PortalMergeBasis,
    pub confidence: PortalEvidenceConfidence,
    pub merged: bool,
    pub detail: String,
}

/// Result of correlating unified-log evidence against direct-log anchors.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortalCorrelationResult {
    pub links: Vec<PortalCorrelationLink>,
    pub rejections: Vec<PortalCorrelationRejection>,
}
