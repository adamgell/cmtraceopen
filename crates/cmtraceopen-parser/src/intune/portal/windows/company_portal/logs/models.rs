//! Wire types for the Company Portal Windows `Log_<n>.log` evidence document.
//!
//! Serde recipe follows the ESP module: `rename_all = "camelCase"`, no
//! `skip_serializing_if`, determinism from declaration order. Every type that
//! can fail to parse keeps its source text, so a record the grammar cannot read
//! is still reported rather than dropped. See [`super::framing`] for the two
//! documented exceptions to byte-for-byte fidelity (trailing whitespace and
//! blank lines).

use serde::{Deserialize, Serialize};

/// Wire schema version of [`CompanyPortalLogDocument`].
///
/// Bump only for a breaking change to the document shape. The *grammar* the
/// records were parsed with is tracked separately by
/// [`CompanyPortalGrammarVersion`], because a new app-version grammar does not
/// have to change the document shape.
pub const COMPANY_PORTAL_WINDOWS_LOGS_SCHEMA_VERSION: u32 = 1;

/// Version of the record field grammar used to read a file.
///
/// Versioned from the start: only one Company Portal app version has ever had
/// a verbatim record published, so a second observed layout must be able to
/// arrive as `V2` rather than silently reinterpreting `V1` records.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum CompanyPortalGrammarVersion {
    /// Field layout observed in app version `12-0-0`.
    V1,
}

/// Whether the grammar was applied to an app version it was actually derived
/// from.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum CompanyPortalGrammarSupport {
    /// The record's app-version field is one the grammar was derived from.
    Validated,
    /// The record layout matched but the app version is outside the validated
    /// set. The grammar is applied unchanged and the result is downgraded
    /// rather than guessed at.
    Experimental,
}

/// Confidence in the derived record fields.
///
/// Deliberately capped at [`CompanyPortalConfidence::Medium`]: raising it to
/// `High` requires a second Company Portal app version captured from a real
/// device, which does not exist yet.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum CompanyPortalConfidence {
    Low,
    Medium,
    High,
}

/// Severity level mapped from the record's dedicated severity field.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum CompanyPortalSeverityLevel {
    Verbose,
    Information,
    Warning,
    Error,
    Critical,
    /// The field was present but its token is not in the known vocabulary. The
    /// token itself is kept in [`CompanyPortalSeverity::raw_text`].
    Unknown,
}

/// The record's dedicated severity field, kept losslessly.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CompanyPortalSeverity {
    pub raw_text: String,
    pub level: CompanyPortalSeverityLevel,
}

/// How far a record timestamp could be resolved.
///
/// Only resolved timestamps are represented. A field that has the right shape
/// but is not a real instant (`2026-13-45T99:99:99.0000000Z`) does not produce
/// a timestamp at all: `parse_utc_instant` rejects it, the record is framed as
/// [`FramedRecordKind::Malformed`], and it reaches the document with
/// `timestamp: None` plus a coverage row. There is deliberately no "invalid
/// instant" variant, because a half-resolved timestamp would be a claim the
/// evidence does not support.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum CompanyPortalTimestampKind {
    /// Resolved to an absolute UTC instant.
    Utc,
}

/// A record timestamp. `raw_text` is always the field exactly as written.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CompanyPortalTimestamp {
    pub raw_text: String,
    pub normalized_utc: Option<String>,
    pub kind: CompanyPortalTimestampKind,
}

/// A dash-separated Company Portal app version triple, e.g. `12-0-0`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CompanyPortalVersionTriple {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

/// The record's app-version field plus whether the grammar was derived from it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CompanyPortalAppVersion {
    pub raw_text: String,
    pub triple: CompanyPortalVersionTriple,
    pub support: CompanyPortalGrammarSupport,
}

/// Which LocalState log a file is.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum CompanyPortalLogFileKind {
    /// `Log_<n>.log` — the main Company Portal app log.
    App,
    /// `Log.<BridgeName>_<n>.log` — a bridge log written by the same logger.
    Bridge,
    /// The name does not follow either LocalState pattern.
    Unrecognized,
}

/// Identity of the file a document was built from.
///
/// Only the file name is retained. The full path contains the user profile
/// directory, which is privacy-sensitive, and the LocalState folder is already
/// implied by the artifact family.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CompanyPortalLogFileIdentity {
    pub file_name: String,
    pub kind: CompanyPortalLogFileKind,
    /// Bridge name for [`CompanyPortalLogFileKind::Bridge`], e.g.
    /// `ConfigurationManagerBridge`.
    pub bridge_name: Option<String>,
    /// The `<n>` in `Log_<n>.log`. Preserved so rotated members stay distinct;
    /// whether `1` is the newest or the oldest member is not established by any
    /// published evidence, so members are never reordered or deduplicated.
    pub rotation_index: Option<u32>,
}

/// Per-record parse outcome.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum CompanyPortalParseState {
    /// Fields 1-7 validated against the grammar.
    Parsed,
    /// The line began a record but failed validation. Its text is preserved
    /// verbatim in [`CompanyPortalLogRecord::raw_text`].
    Malformed,
    /// Text that belongs to no record — a truncated leading fragment.
    Orphaned,
}

/// Coverage status for an artifact the document tried to account for.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum CompanyPortalCoverageStatus {
    Available,
    ParseFailed,
    Unsupported,
}

/// A named gap, so that "we did not read this" is never mistaken for "this did
/// not happen".
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CompanyPortalCoverage {
    pub artifact_id: String,
    pub family: String,
    pub status: CompanyPortalCoverageStatus,
    pub detail: Option<String>,
}

/// One Company Portal log record.
///
/// A record is one header line plus any continuation lines that followed it.
/// Everything the grammar did not claim stays in `message`, and `raw_text`
/// always holds the record's original text.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CompanyPortalLogRecord {
    /// Stable id: `companyPortalLog|<fileName>|<lineNumber>`.
    pub record_id: String,
    /// 1-based line number of the record's first physical line.
    pub line_number: u32,
    pub parse_state: CompanyPortalParseState,
    pub timestamp: Option<CompanyPortalTimestamp>,
    pub severity: Option<CompanyPortalSeverity>,
    /// Field 3 — record category/kind token.
    pub category: Option<String>,
    /// Field 4 — scenario/context name. The literal `None` is how .NET renders
    /// a null scenario; it is kept as the string it is, not turned into an
    /// absent field.
    pub scenario: Option<String>,
    /// Field 5 — unsigned integer whose semantics are unproven. It is *not*
    /// asserted to be monotonic, and it is not proven to be a thread id, so it
    /// is never mapped onto a thread column.
    pub sequence: Option<u64>,
    /// Field 6 — correlation/activity identifier.
    pub activity_id: Option<String>,
    pub app_version: Option<CompanyPortalAppVersion>,
    /// Leading `[Component Name]` of the message, when the message opens with a
    /// balanced bracket. The bracket is *not* removed from `message`.
    pub component: Option<String>,
    /// Field 8 onward, verbatim, including any nested legacy ConfigMgr trace
    /// text and its own day-first date.
    pub message: String,
    /// The record's source text, head plus any continuation lines, joined with
    /// `\n`. Trailing whitespace is stripped from each line before framing (a
    /// record starts in column 0, so that test has to run on the trimmed line),
    /// and blank lines are not carried. Nothing else is altered: the nested
    /// legacy ConfigMgr trace text and its day-first date survive verbatim.
    pub raw_text: String,
}

/// A parsed Company Portal log file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CompanyPortalLogDocument {
    pub schema_version: u32,
    pub grammar_version: CompanyPortalGrammarVersion,
    pub grammar_support: CompanyPortalGrammarSupport,
    pub confidence: CompanyPortalConfidence,
    /// `true` when sensitive values were redacted out of this document.
    pub redacted: bool,
    pub file: CompanyPortalLogFileIdentity,
    pub records: Vec<CompanyPortalLogRecord>,
    pub coverage: Vec<CompanyPortalCoverage>,
}
