//! Types for imported macOS Console plain-text captures of an iOS/iPadOS device.
//!
//! Nothing here interprets a device: every value is something a Console export
//! literally contained, plus the classification this crate derived from it.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::intune::evidence::{
    intune_raw_preserving_string_enum, IntuneAccessState, IntuneArtifactCoverage,
    IntuneArtifactStatus, IntuneFinding, IntuneNamedValue, IntuneObservationContext,
    IntuneParseState,
};

/// Schema version of the snapshot this module produces.
pub const COMPANY_PORTAL_IOS_CONSOLE_SCHEMA_VERSION: u32 = 1;

/// Coverage family every artifact of this leaf reports under.
pub const COMPANY_PORTAL_IOS_CONSOLE_FAMILY: &str = "companyPortalIosConsole";

intune_raw_preserving_string_enum! {
    /// Apple's `log` message type, as Console renders it in the Type column.
    ///
    /// The vocabulary is Apple's and has grown before (`Fault`, `Signpost`), so an
    /// unrecognized label round-trips verbatim rather than collapsing to a guess.
    pub enum ConsoleMessageType {
        Default => "default",
        Info => "info",
        Debug => "debug",
        Error => "error",
        Fault => "fault",
        Activity => "activity",
        Signpost => "signpost",
    }
}

impl ConsoleMessageType {
    /// Whether this type is one Apple treats as a failure signal.
    pub fn is_failure(&self) -> bool {
        matches!(self, Self::Error | Self::Fault)
    }
}

intune_raw_preserving_string_enum! {
    /// A column of a Console export, identified independently of its header label.
    ///
    /// Console's header labels are localized, so the label is the wire form only
    /// for columns this build does not model; a recognized column serializes under
    /// its canonical name and an unrecognized one keeps the label it was written
    /// with.
    pub enum ConsoleColumn {
        Timestamp => "timestamp",
        MessageType => "type",
        Process => "process",
        ProcessId => "processId",
        ThreadId => "threadId",
        Activity => "activity",
        Subsystem => "subsystem",
        Category => "category",
        Message => "message",
    }
}

/// A recognized Console plain-text export layout.
///
/// A layout binds a header vocabulary, a timestamp grammar, and a message-type
/// vocabulary together. Console renders all three per locale, so they are
/// resolved as a unit rather than sniffed independently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ConsoleLayout {
    /// Tab-delimited export with English column labels and ISO-style timestamps.
    TabularEnUs,
    /// Tab-delimited export with German column labels and `DD.MM.YYYY` timestamps.
    TabularDeDe,
    /// No layout could be resolved; no records were framed.
    Unresolved,
}

/// How confidently a layout was resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ConsoleLayoutConfidence {
    /// A header row named the columns.
    HeaderDeclared,
    /// No header row survived the copy, and the canonical column order was
    /// inferred from consistently shaped records.
    Inferred,
    /// Nothing was resolved.
    None,
}

/// Why a layout could not be resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ConsoleLayoutRefusal {
    /// The text carries no header and no consistently shaped tabular records.
    NotAConsoleExport,
    /// A header row is present but its labels match no known locale vocabulary.
    UnknownHeaderVocabulary,
    /// A header row is present but omits a column this leaf requires.
    IncompleteHeader,
}

/// Whether a record is Company Portal evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ConsoleSourceClass {
    /// A verified process name or subsystem identified the Company Portal app.
    CompanyPortal,
    /// Source columns were present and named something else.
    Unrelated,
    /// No usable source column, so the record can be neither claimed nor excluded.
    Indeterminate,
}

/// Which column verified a Company Portal record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ConsoleSourceSignal {
    Process,
    Subsystem,
}

/// A fixture-proven activity a Company Portal message belongs to.
///
/// Absent from a record means "not recognized", never "not that activity".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ConsoleSemanticKind {
    SignInAuth,
    EnrollmentProfile,
    SyncCompliance,
    AppDeviceAction,
    NetworkService,
    Diagnostic,
}

/// What supported a semantic classification.
///
/// A category match is structural; a message match is a keyword heuristic. They
/// are distinguished so a reviewer can tell which conclusions rest on which.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ConsoleSemanticSource {
    Category,
    Message,
}

/// Why a record could not be fully parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ConsoleRecordDefect {
    /// The leading field looked like a timestamp and did not parse.
    UnparsableTimestamp,
    /// The row carried fewer columns than the resolved layout declares.
    MissingColumns,
    /// Continuation text arrived before any record had started.
    OrphanedContinuation,
}

/// A class of value masked by the export projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ConsoleRedactionKind {
    Upn,
    Secret,
    Guid,
    DeviceIdentifier,
    Url,
    FilePath,
    Certificate,
}

/// How many values of one class a redaction pass masked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsoleRedaction {
    pub kind: ConsoleRedactionKind,
    pub count: u32,
}

/// One normalized Console record.
///
/// `message` is retained as captured: the operator reading their own device log
/// is entitled to it. [`super::redacted_export_projection`] is what masks
/// identity and secret material on the way out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsoleRecord {
    pub context: IntuneObservationContext,
    pub layout: ConsoleLayout,
    pub message_type: Option<ConsoleMessageType>,
    pub process: Option<String>,
    pub process_id: Option<u32>,
    pub thread_id: Option<String>,
    pub activity_id: Option<String>,
    pub subsystem: Option<String>,
    pub category: Option<String>,
    pub message: String,
    /// Physical lines the message spans, including the record's own line.
    pub message_line_count: u32,
    pub source_class: ConsoleSourceClass,
    pub source_signals: Vec<ConsoleSourceSignal>,
    pub semantic: Option<ConsoleSemanticKind>,
    pub semantic_source: Option<ConsoleSemanticSource>,
    pub defects: Vec<ConsoleRecordDefect>,
    /// The record was the last in a capture that ended mid-line.
    pub truncated: bool,
    /// Columns the resolved layout declared but this build does not model.
    pub unmodeled_columns: Vec<IntuneNamedValue>,
}

impl ConsoleRecord {
    /// Whether this record is verified Company Portal evidence.
    pub fn is_company_portal(&self) -> bool {
        self.source_class == ConsoleSourceClass::CompanyPortal
    }

    /// Whether this record reports a failure from the Company Portal app.
    ///
    /// A malformed row is excluded even when its Type column reads `Error`. Its
    /// columns did not line up, so which value landed in which field is exactly
    /// what is in doubt; such a row is reported as malformed rather than
    /// promoted to a failure the operator would act on.
    pub fn is_company_portal_failure(&self) -> bool {
        self.is_company_portal()
            && self.context.parse_state == IntuneParseState::Parsed
            && self
                .message_type
                .as_ref()
                .is_some_and(ConsoleMessageType::is_failure)
    }
}

/// One supplied Console export file and what the parser made of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsoleArtifact {
    pub artifact_id: String,
    pub file_name: String,
    pub file_path: Option<String>,
    pub layout: ConsoleLayout,
    pub layout_confidence: ConsoleLayoutConfidence,
    pub layout_refusal: Option<ConsoleLayoutRefusal>,
    pub status: IntuneArtifactStatus,
    /// Columns in the order the export declared them.
    pub columns: Vec<ConsoleColumn>,
    /// Lines before the header row that framed no record.
    pub preamble_line_count: u32,
    pub record_count: u32,
    pub company_portal_record_count: u32,
    pub unrelated_record_count: u32,
    pub malformed_record_count: u32,
    /// The capture began mid-record, so its first message is incomplete.
    pub truncated_leading_fragment: bool,
    /// The capture ended mid-record, so its last message is incomplete.
    pub truncated_trailing_record: bool,
    /// The record cap was reached and the remainder of the file was not framed.
    pub record_cap_reached: bool,
    pub reported_app_version: Option<String>,
    pub reported_os_version: Option<String>,
}

/// Totals across every artifact in one analysis.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsoleTotals {
    pub artifact_count: u32,
    pub record_count: u32,
    pub company_portal_record_count: u32,
    pub malformed_record_count: u32,
    /// Records whose wall-clock time carried no offset, so they cannot be ordered
    /// against a server-side source with any confidence.
    pub offsetless_record_count: u32,
}

/// The immutable result of analyzing a bundle of Console exports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsoleDiagnosticsSnapshot {
    pub schema_version: u32,
    pub observed_at_utc: String,
    pub artifacts: Vec<ConsoleArtifact>,
    pub records: Vec<ConsoleRecord>,
    pub coverage: Vec<IntuneArtifactCoverage>,
    pub findings: Vec<IntuneFinding>,
    pub totals: ConsoleTotals,
}

impl ConsoleDiagnosticsSnapshot {
    /// Records verified as Company Portal evidence, in capture order.
    pub fn company_portal_records(&self) -> impl Iterator<Item = &ConsoleRecord> {
        self.records.iter().filter(|record| record.is_company_portal())
    }

    /// The artifact a record was read from.
    pub fn artifact_of(&self, record: &ConsoleRecord) -> Option<&ConsoleArtifact> {
        let id = &record.context.provenance.source_artifact_id;
        self.artifacts.iter().find(|artifact| &artifact.artifact_id == id)
    }
}

/// One Console export handed to the analyzer.
///
/// The crate performs no I/O: a caller reads and decodes the file, then supplies
/// the text. `content` is `None` exactly when there is nothing to supply, which
/// is why `acquisition` carries the reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsoleExportInput {
    pub artifact_id: String,
    pub file_name: String,
    /// A sanitized path. Real capture paths are privacy-sensitive; the caller
    /// decides what, if anything, is safe to attribute.
    pub file_path: Option<String>,
    pub content: Option<String>,
    /// What the collector knows about acquisition.
    ///
    /// Only [`IntuneAccessState::Available`] and [`IntuneAccessState::Capped`]
    /// carry content. [`IntuneArtifactStatus::Unsupported`] and
    /// [`IntuneArtifactStatus::ParseFailed`] are *outcomes* this module derives
    /// from the content; a caller does not assert them.
    pub acquisition: IntuneAccessState,
    /// Free-text detail for a non-available acquisition, surfaced in coverage.
    pub detail: Option<String>,
}

impl ConsoleExportInput {
    /// A captured export with content.
    pub fn captured(artifact_id: impl Into<String>, file_name: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            artifact_id: artifact_id.into(),
            file_name: file_name.into(),
            file_path: None,
            content: Some(content.into()),
            acquisition: IntuneAccessState::Available,
            detail: None,
        }
    }
}

/// Deterministic knobs for one analysis.
///
/// `observed_at_utc` is supplied rather than read from the clock: this crate is
/// wasm-clean and its output is a golden-comparable artifact, so nothing in it
/// may depend on when it ran.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsoleAnalysisOptions {
    pub observed_at_utc: String,
    /// Records framed per artifact before the remainder is left unread.
    pub max_records_per_artifact: usize,
}

impl Default for ConsoleAnalysisOptions {
    fn default() -> Self {
        Self {
            observed_at_utc: "1970-01-01T00:00:00Z".to_owned(),
            max_records_per_artifact: 250_000,
        }
    }
}

impl ConsoleAnalysisOptions {
    /// Options stamped with a caller-supplied observation time.
    pub fn observed_at(observed_at_utc: impl Into<String>) -> Self {
        Self {
            observed_at_utc: observed_at_utc.into(),
            ..Self::default()
        }
    }
}
