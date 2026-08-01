//! Types for direct macOS Company Portal application logs.
//!
//! Everything here is a projection of what a record actually said. Fields the
//! grammar does not model land in [`CompanyPortalLogRecord::attributes`] and the
//! verbatim source text always survives in [`CompanyPortalLogRecord::raw`], so a
//! later typed field is a widening change rather than a re-parse.

// `Deserializer` and `Serializer` look unused here: they are named by the
// expansion of `intune_raw_preserving_string_enum!` below, which is written in
// the shared evidence module and resolves those paths at the invocation site.
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::intune::evidence::{
    intune_raw_preserving_string_enum, IntuneAccessState, IntuneArtifactStatus, IntuneNamedValue,
    IntuneObservationContext, IntuneSensitivity,
};

/// Schema version for every type in this module.
pub const COMPANY_PORTAL_LOG_SCHEMA_VERSION: u32 = 1;

/// App-version major numbers this build claims to understand.
///
/// A record from outside this set still parses and is preserved in full; it is
/// reported through [`CompanyPortalLogSnapshot::unknown_app_versions`] and
/// demotes confidence rather than being dropped.
pub const SUPPORTED_APP_VERSION_MAJORS: &[u32] = &[5];

intune_raw_preserving_string_enum! {
    /// Severity exactly as the record's structural severity field expressed it.
    ///
    /// Microsoft extends this vocabulary without notice, so an unrecognized token
    /// round-trips verbatim instead of collapsing into `info`. The raw token is
    /// often the only evidence that a build wrote something this reader does not
    /// yet model.
    pub enum CompanyPortalSeverity {
        Verbose => "verbose",
        Debug => "debug",
        Info => "info",
        Warning => "warning",
        Error => "error",
        Fatal => "fatal",
    }
}

impl CompanyPortalSeverity {
    /// Map a structural severity token to a severity.
    ///
    /// Returns `None` when the token is not one this build recognizes; the caller
    /// keeps the raw token and records the gap rather than guessing from the
    /// message text, which would silently contradict the source.
    pub fn from_token(token: &str) -> Option<Self> {
        let normalized = token.trim().to_ascii_uppercase();
        Some(match normalized.as_str() {
            "V" | "VERBOSE" | "TRACE" => Self::Verbose,
            "D" | "DEBUG" => Self::Debug,
            "I" | "INFO" | "INFORMATION" => Self::Info,
            "W" | "WARN" | "WARNING" => Self::Warning,
            "E" | "ERR" | "ERROR" => Self::Error,
            "A" | "F" | "FATAL" | "CRITICAL" | "ASSERT" => Self::Fatal,
            _ => return None,
        })
    }

    /// Does this severity denote a failure the operator should look at?
    pub fn is_failure(&self) -> bool {
        matches!(self, Self::Error | Self::Fatal)
    }
}

/// Which field shape a record used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CompanyPortalRecordProfile {
    /// `timestamp | process | severity | thread | subsystem | message`.
    Basic,
    /// Basic plus one or more `key=value` attribute fields before the message.
    ///
    /// Deliberately not called "advanced": a record carrying only `version=` is
    /// attributed but says nothing about the advanced-logging preference. See
    /// [`CompanyPortalLogRecord::is_advanced`] for that distinction.
    Attributed,
    /// A header-shaped line this build could not decompose into fields.
    Unrecognized,
}

/// A string carrying its privacy classification.
///
/// The classification exists to be acted on by
/// [`super::redaction::redacted_company_portal_log_export`]. Masking on presence
/// alone would destroy the diagnostic value an export exists for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompanyPortalClassifiedString {
    pub value: String,
    pub sensitivity: IntuneSensitivity,
}

impl CompanyPortalClassifiedString {
    pub fn public(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            sensitivity: IntuneSensitivity::Public,
        }
    }

    pub fn sensitive(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            sensitivity: IntuneSensitivity::Sensitive,
        }
    }
}

/// What became of an artifact the native adapter tried to collect.
///
/// The vocabulary matches the fixture manifest's `captureState` and maps onto the
/// shared [`IntuneArtifactStatus`] and [`IntuneAccessState`] one-to-one, so a
/// corpus cannot declare one thing in its manifest and another in its expected
/// coverage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CompanyPortalCaptureState {
    Captured,
    Capped,
    Absent,
    AccessDenied,
    Skipped,
    Unsupported,
    ParseFailed,
}

impl CompanyPortalCaptureState {
    /// Parse the wire token used by capture manifests.
    pub fn from_wire(token: &str) -> Option<Self> {
        Some(match token {
            "captured" => Self::Captured,
            "capped" => Self::Capped,
            "absent" => Self::Absent,
            "accessDenied" => Self::AccessDenied,
            "skipped" => Self::Skipped,
            "unsupported" => Self::Unsupported,
            "parseFailed" => Self::ParseFailed,
            _ => return None,
        })
    }

    /// The coverage status this capture state requires.
    pub fn artifact_status(&self) -> IntuneArtifactStatus {
        match self {
            Self::Captured => IntuneArtifactStatus::Available,
            Self::Capped => IntuneArtifactStatus::Capped,
            Self::Absent => IntuneArtifactStatus::Missing,
            Self::AccessDenied => IntuneArtifactStatus::PermissionDenied,
            Self::Skipped => IntuneArtifactStatus::Skipped,
            Self::Unsupported => IntuneArtifactStatus::Unsupported,
            Self::ParseFailed => IntuneArtifactStatus::ParseFailed,
        }
    }

    /// The observation access state this capture state implies.
    pub fn access_state(&self) -> IntuneAccessState {
        match self {
            Self::Captured => IntuneAccessState::Available,
            Self::Capped => IntuneAccessState::Capped,
            Self::Absent => IntuneAccessState::Missing,
            Self::AccessDenied => IntuneAccessState::PermissionDenied,
            Self::Skipped => IntuneAccessState::Skipped,
            Self::Unsupported => IntuneAccessState::Unsupported,
            Self::ParseFailed => IntuneAccessState::Failed,
        }
    }

    /// Did this state produce bytes a parser could read?
    pub fn has_content(&self) -> bool {
        matches!(self, Self::Captured | Self::Capped | Self::ParseFailed)
    }

    /// Is the absence of a signal in this artifact meaningful?
    ///
    /// Only a complete capture proves a negative. A capped, skipped, denied, or
    /// missing artifact proves nothing, which is why coverage is reported rather
    /// than collapsed into "no data".
    pub fn proves_absence(&self) -> bool {
        matches!(self, Self::Captured)
    }
}

/// Which rotation member of the log directory an artifact is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CompanyPortalRotationKind {
    /// The live file the app is currently appending to.
    Current,
    /// An explicitly numbered rotation, `Name-1.log`.
    Numbered,
    /// A datestamped rotation, `Name-20260312.log`.
    Datestamped,
    /// A file whose name carries no rotation signal.
    Unknown,
}

/// Rotation identity derived from an artifact's file name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompanyPortalRotation {
    pub kind: CompanyPortalRotationKind,
    /// `0` is the live file and higher numbers are progressively older.
    ///
    /// `None` for a datestamped or unrecognized member: reporting a fabricated
    /// ordinal would make it indistinguishable from an explicit one and mislead
    /// the chronological ordering the reducer performs.
    pub ordinal: Option<u32>,
    /// The datestamp text, when the name carried one.
    pub datestamp: Option<String>,
}

impl CompanyPortalRotation {
    /// Sort key placing the oldest rotation first.
    ///
    /// Higher ordinals are older, so the key is inverted. A member with no
    /// ordinal sorts before every numbered one but after nothing, keeping the
    /// ordering total and stable regardless of input order.
    pub fn chronological_key(&self) -> (u8, std::cmp::Reverse<u32>, Option<String>) {
        match self.ordinal {
            Some(ordinal) => (1, std::cmp::Reverse(ordinal), self.datestamp.clone()),
            None => (0, std::cmp::Reverse(0), self.datestamp.clone()),
        }
    }
}

/// Why an artifact was not accepted as a direct Company Portal app log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CompanyPortalLogRejection {
    /// No line matched the direct app-log record grammar.
    NoRecords,
    /// Records matched but named a process that is not Company Portal.
    ForeignProcess,
    /// The content is a saved Company Portal diagnostic report.
    ///
    /// Reports are a distinct source kind owned by a separate leaf; recognizing
    /// one here is a guard, not a parser.
    DiagnosticReport,
    /// The content is an Apple unified-log (`log show`) export.
    UnifiedLogExport,
    /// Records matched, but too few to confirm without a path hint.
    InsufficientEvidence,
    /// The artifact carried no content to inspect.
    NoContent,
}

/// Result of deciding whether an artifact is a direct Company Portal app log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompanyPortalLogDetection {
    pub confirmed: bool,
    pub rejection: Option<CompanyPortalLogRejection>,
    /// Records in the sample window whose header matched the grammar.
    pub matched_records: u32,
    /// Records in the sample window naming a Company Portal process.
    pub company_portal_records: u32,
    /// Did the sanitized path or file name suggest the Company Portal log
    /// directory? A hint alone never confirms.
    pub path_hint: bool,
}

/// One logical record, header plus any continuation lines.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompanyPortalLogRecord {
    pub context: IntuneObservationContext,
    /// Zero-based position within its artifact.
    pub record_index: u32,
    pub profile: CompanyPortalRecordProfile,
    pub process: Option<String>,
    pub severity: Option<CompanyPortalSeverity>,
    /// The severity field exactly as written, kept even when recognized.
    pub severity_token: Option<String>,
    pub thread: Option<u32>,
    pub subsystem: Option<String>,
    pub category: Option<String>,
    pub activity_id: Option<String>,
    pub app_version: Option<String>,
    /// Every labeled attribute in source order, including modeled ones.
    pub attributes: Vec<IntuneNamedValue>,
    pub message: CompanyPortalClassifiedString,
    /// The record's exact source text, header and continuations, newline joined.
    pub raw: CompanyPortalClassifiedString,
    pub continuation_lines: u32,
}

impl CompanyPortalLogRecord {
    /// Does this record carry advanced-logging detail?
    ///
    /// Advanced logging widens what Company Portal writes to include certificate
    /// and network-response material, which is why its presence is surfaced: the
    /// privacy posture of the artifact changes.
    ///
    /// Keyed on the diagnostic-grouping attributes rather than on the profile.
    /// A record that carries only `version=` is [`CompanyPortalRecordProfile::Attributed`]
    /// but reveals nothing extra, and treating it as advanced would raise a
    /// privacy warning about a log that has none of the material the warning is
    /// about.
    pub fn is_advanced(&self) -> bool {
        self.category.is_some() || self.activity_id.is_some()
    }
}

/// One artifact and what parsing it produced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompanyPortalLogArtifact {
    pub artifact_id: String,
    pub file_name: String,
    pub file_path: Option<CompanyPortalClassifiedString>,
    pub capture_state: CompanyPortalCaptureState,
    pub rotation: CompanyPortalRotation,
    pub detection: CompanyPortalLogDetection,
    pub encoding: Option<String>,
    pub record_count: u32,
    pub malformed_record_count: u32,
    pub captured_at_utc: String,
}

/// Records counted by the severity their structural field declared.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompanyPortalSeverityCounts {
    pub verbose: u32,
    pub debug: u32,
    pub info: u32,
    pub warning: u32,
    pub error: u32,
    pub fatal: u32,
    /// Records whose severity token this build does not recognize.
    pub unrecognized: u32,
    /// Records with no severity field at all.
    pub absent: u32,
}

impl CompanyPortalSeverityCounts {
    fn record(&mut self, severity: Option<&CompanyPortalSeverity>) {
        match severity {
            Some(CompanyPortalSeverity::Verbose) => self.verbose += 1,
            Some(CompanyPortalSeverity::Debug) => self.debug += 1,
            Some(CompanyPortalSeverity::Info) => self.info += 1,
            Some(CompanyPortalSeverity::Warning) => self.warning += 1,
            Some(CompanyPortalSeverity::Error) => self.error += 1,
            Some(CompanyPortalSeverity::Fatal) => self.fatal += 1,
            Some(CompanyPortalSeverity::Unknown(_)) => self.unrecognized += 1,
            None => self.absent += 1,
        }
    }

    /// Fold every record in `records` into a fresh count.
    pub fn from_records<'a>(
        records: impl IntoIterator<Item = &'a CompanyPortalLogRecord>,
    ) -> Self {
        let mut counts = Self::default();
        for record in records {
            counts.record(record.severity.as_ref());
        }
        counts
    }
}

/// Aggregate parse statistics across every artifact in a snapshot.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompanyPortalLogStats {
    pub total_records: u32,
    pub parsed_records: u32,
    pub malformed_records: u32,
    pub continuation_lines: u32,
    pub advanced_records: u32,
    pub severity_counts: CompanyPortalSeverityCounts,
}

/// Everything one reduction produced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompanyPortalLogSnapshot {
    pub schema_version: u32,
    pub artifacts: Vec<CompanyPortalLogArtifact>,
    /// Every record from every artifact, in chronological rotation order.
    pub records: Vec<CompanyPortalLogRecord>,
    pub coverage: Vec<crate::intune::evidence::IntuneArtifactCoverage>,
    pub stats: CompanyPortalLogStats,
    /// Distinct app versions observed that this build does not claim to support.
    pub unknown_app_versions: Vec<String>,
    pub advanced_logging_observed: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_tokens_map_from_letters_and_words() {
        assert_eq!(
            CompanyPortalSeverity::from_token("E"),
            Some(CompanyPortalSeverity::Error)
        );
        assert_eq!(
            CompanyPortalSeverity::from_token("warning"),
            Some(CompanyPortalSeverity::Warning)
        );
        assert_eq!(CompanyPortalSeverity::from_token("Q"), None);
    }

    #[test]
    fn unrecognized_severity_round_trips_verbatim() {
        let decoded: CompanyPortalSeverity = serde_json::from_str("\"notice\"").unwrap();
        assert_eq!(decoded, CompanyPortalSeverity::Unknown("notice".to_owned()));
        assert_eq!(serde_json::to_string(&decoded).unwrap(), "\"notice\"");
    }

    #[test]
    fn every_capture_state_binds_to_one_coverage_status() {
        for (wire, status) in [
            ("captured", IntuneArtifactStatus::Available),
            ("capped", IntuneArtifactStatus::Capped),
            ("absent", IntuneArtifactStatus::Missing),
            ("accessDenied", IntuneArtifactStatus::PermissionDenied),
            ("skipped", IntuneArtifactStatus::Skipped),
            ("unsupported", IntuneArtifactStatus::Unsupported),
            ("parseFailed", IntuneArtifactStatus::ParseFailed),
        ] {
            let state = CompanyPortalCaptureState::from_wire(wire).expect("known capture state");
            assert_eq!(state.artifact_status(), status, "capture state {wire}");
        }
        assert_eq!(CompanyPortalCaptureState::from_wire("probably"), None);
    }

    #[test]
    fn only_a_complete_capture_proves_an_absence() {
        assert!(CompanyPortalCaptureState::Captured.proves_absence());
        for state in [
            CompanyPortalCaptureState::Capped,
            CompanyPortalCaptureState::Absent,
            CompanyPortalCaptureState::AccessDenied,
            CompanyPortalCaptureState::Skipped,
            CompanyPortalCaptureState::Unsupported,
            CompanyPortalCaptureState::ParseFailed,
        ] {
            assert!(!state.proves_absence(), "{state:?} must not prove absence");
        }
    }

    #[test]
    fn rotation_ordering_puts_the_oldest_member_first() {
        let mut members = [
            CompanyPortalRotation {
                kind: CompanyPortalRotationKind::Current,
                ordinal: Some(0),
                datestamp: None,
            },
            CompanyPortalRotation {
                kind: CompanyPortalRotationKind::Numbered,
                ordinal: Some(2),
                datestamp: None,
            },
            CompanyPortalRotation {
                kind: CompanyPortalRotationKind::Numbered,
                ordinal: Some(1),
                datestamp: None,
            },
        ];
        members.sort_by_key(CompanyPortalRotation::chronological_key);
        assert_eq!(
            members.iter().map(|m| m.ordinal).collect::<Vec<_>>(),
            vec![Some(2), Some(1), Some(0)]
        );
    }
}
