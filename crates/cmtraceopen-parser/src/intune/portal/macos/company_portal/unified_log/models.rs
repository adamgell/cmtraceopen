//! Output contract for reduced Company Portal unified-log evidence.
//!
//! These types describe *what the capture showed*. Every field that implies a
//! Company Portal activity is reachable only from a record that passed the
//! selection rule in [`super::predicate`]; nothing here is inferred from
//! timestamps alone.

use serde::{Deserialize, Serialize};

use crate::intune::evidence::{
    IntuneArtifactCoverage, IntuneErrorCode, IntuneFinding, IntuneNamedValue,
    IntuneObservationContext,
};

use super::predicate::{UnifiedLogPredicateDescriptor, UnifiedLogRelevance};
use super::schema::{
    UnifiedLogCaptureCoverage, UnifiedLogCaptureWindow, UnifiedLogEventType,
    UnifiedLogMessageType, UnifiedLogRedactionMetadata, UnifiedLogRejectedLine,
    UnifiedLogSignpostType,
};

/// Version of the reduced output contract in this module.
pub const UNIFIED_LOG_ANALYSIS_SCHEMA_VERSION: u32 = 1;

/// Collection state of one supplied artifact.
///
/// The wire values match the fixture-manifest vocabulary exactly, so a corpus
/// cannot declare one state and drive the analyzer with another.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum UnifiedLogCaptureState {
    Captured,
    Capped,
    Absent,
    AccessDenied,
    Skipped,
    Unsupported,
    ParseFailed,
}

/// One supplied capture artifact.
///
/// `content` is `None` for every state that produced no bytes. It is *not* an
/// error for a state that normally has bytes to arrive without them; that
/// contradiction is reported as coverage rather than dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnifiedLogSourceInput {
    pub artifact_id: String,
    pub file_name: String,
    pub capture_state: UnifiedLogCaptureState,
    pub content: Option<String>,
}

/// Severity of a record, derived from Apple's message type.
///
/// Separate from [`UnifiedLogMessageType`] because the message type is an open
/// vocabulary and this is the closed ranking the rules reason over. An
/// unrecognized message type maps to `Unknown`, never to a level it might not be.
///
/// Declaration order is the severity order, so `max()` over a group yields its
/// worst level. `Unknown` sorts *below* `Debug` deliberately: an unrecognized
/// message type must never win a "highest level seen" comparison against a real
/// error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum UnifiedLogLevel {
    Unknown,
    Debug,
    Info,
    Default,
    Error,
    Fault,
}

impl UnifiedLogLevel {
    /// Map Apple's message type onto the ranked level.
    pub fn from_message_type(message_type: Option<&UnifiedLogMessageType>) -> Self {
        match message_type {
            Some(UnifiedLogMessageType::Debug) => Self::Debug,
            Some(UnifiedLogMessageType::Info) => Self::Info,
            Some(UnifiedLogMessageType::Default) => Self::Default,
            Some(UnifiedLogMessageType::Error) => Self::Error,
            Some(UnifiedLogMessageType::Fault) => Self::Fault,
            Some(UnifiedLogMessageType::Unknown(_)) | None => Self::Unknown,
        }
    }

    /// Whether this level is a failure signal the rules may act on.
    pub fn is_failure(self) -> bool {
        matches!(self, Self::Error | Self::Fault)
    }
}

/// The Company Portal workflow a record belongs to.
///
/// Assigned from the record's `category` — a field the emitting binary controls
/// — and only for records that already passed the selection rule. It is never
/// assigned from free-text message content, which any process can write.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum UnifiedLogActivityKind {
    ProcessStartup,
    Authentication,
    EnrollmentProfile,
    SyncCompliance,
    AppAction,
    DeviceAction,
    NetworkRequest,
    Diagnostics,
    /// Relevant evidence whose category this build has no rule for.
    Unclassified,
}

/// The kind of identifier two records may be joined on.
///
/// Every variant is an *explicit* identifier the source stated. There is no
/// timestamp variant, and adding one would defeat the rule this type exists to
/// enforce: unified-log evidence may corroborate a direct Company Portal log
/// only on a shared identifier, never on proximity in time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum UnifiedLogCorrelationKind {
    Activity,
    ParentActivity,
    Signpost,
    ClientRequestId,
    CorrelationId,
    SessionId,
}

/// One join key a record carries.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnifiedLogCorrelationKey {
    pub kind: UnifiedLogCorrelationKind,
    pub value: String,
}

/// One reduced unified-log record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnifiedLogObservation {
    pub observation_id: String,
    pub context: IntuneObservationContext,
    /// The collector's source ordinal, preserved exactly.
    pub sequence: u64,
    /// Position within the artifact as emitted, independent of `sequence`.
    /// This is the ordering the analyzer trusts when sequences disagree.
    pub source_position: u64,
    pub relevance: UnifiedLogRelevance,
    pub activity_kind: UnifiedLogActivityKind,
    pub level: UnifiedLogLevel,
    pub message_type: Option<UnifiedLogMessageType>,
    pub event_type: Option<UnifiedLogEventType>,
    pub process: Option<String>,
    pub process_id: Option<u32>,
    pub thread_id: Option<u64>,
    pub subsystem: Option<String>,
    pub category: Option<String>,
    /// Sensitive: unified-log messages quote UPNs, device serials, URLs, and
    /// home-directory paths. Masked by the export projection.
    pub message: Option<String>,
    /// Sensitive for the same reason: an image path names the user's volume.
    pub sender_image_path: Option<String>,
    pub activity_identifier: Option<u64>,
    pub parent_activity_identifier: Option<u64>,
    pub signpost_id: Option<u64>,
    pub signpost_name: Option<String>,
    pub signpost_type: Option<UnifiedLogSignpostType>,
    pub correlation_keys: Vec<UnifiedLogCorrelationKey>,
    pub error: Option<IntuneErrorCode>,
    /// Values Apple's privacy filter had already masked when the record was
    /// written. A high count means the record is weak evidence.
    pub apple_redacted_values: u32,
    /// True when the record stated no usable wall-clock time: either no
    /// timestamp at all, or only a boot-relative mach value.
    pub boot_relative_only: bool,
    pub named_data: Vec<IntuneNamedValue>,
}

/// A group of records sharing one activity identifier.
///
/// Membership is by identifier only. Two records that merely occurred at the
/// same instant are never grouped, which is what the same-time fixture proves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnifiedLogActivity {
    pub activity_identifier: u64,
    pub parent_activity_identifier: Option<u64>,
    pub kind: UnifiedLogActivityKind,
    /// Observation ids in source order.
    pub observation_ids: Vec<String>,
    /// Signpost identifiers seen inside this activity, ordered.
    pub signpost_ids: Vec<u64>,
    pub highest_level: UnifiedLogLevel,
}

/// A disagreement between the collector's stated sequence and the emitted order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum UnifiedLogSequenceAnomalyKind {
    /// Two records in one artifact declared the same sequence.
    Duplicate,
    /// A record declared a sequence lower than its predecessor's.
    OutOfOrder,
}

/// One sequence disagreement, with the records it involves.
///
/// Neither record is dropped. A duplicate sequence is a collector fault, and
/// discarding one of the two would silently delete evidence that exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnifiedLogSequenceAnomaly {
    pub kind: UnifiedLogSequenceAnomalyKind,
    pub artifact_id: String,
    pub sequence: u64,
    pub observation_ids: Vec<String>,
}

/// Reproducibility metadata for one capture artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnifiedLogCaptureSummary {
    pub artifact_id: String,
    pub file_name: String,
    pub capture_state: UnifiedLogCaptureState,
    pub capture_id: Option<String>,
    /// The predicate the capture declares it ran.
    pub declared_predicate: Option<UnifiedLogPredicateDescriptor>,
    /// The predicate this build implements, for comparison.
    pub analyzer_predicate: UnifiedLogPredicateDescriptor,
    /// True when the capture ran a selection rule this build does not implement,
    /// which caps how much its absence of a signal can prove.
    pub predicate_mismatch: bool,
    pub window: Option<UnifiedLogCaptureWindow>,
    pub collected_at_utc: Option<String>,
    pub host_os_version: Option<String>,
    pub company_portal_version: Option<String>,
    pub time_zone: Option<String>,
    pub boot_uuid: Option<String>,
    pub coverage: Option<UnifiedLogCaptureCoverage>,
    pub redaction: Option<UnifiedLogRedactionMetadata>,
    /// Records read from this artifact, before relevance filtering.
    pub records_read: u64,
    /// Records that passed the selection rule.
    pub records_relevant: u64,
    pub rejected: Vec<UnifiedLogRejectedLine>,
}

/// The public result of reducing a Company Portal unified-log bundle.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnifiedLogAnalysis {
    pub schema_version: u32,
    pub captures: Vec<UnifiedLogCaptureSummary>,
    /// Every record read, relevant or not, in source order. Unrelated records
    /// are retained so that "this capture proved nothing" and "this capture was
    /// never filtered" stay distinguishable.
    pub observations: Vec<UnifiedLogObservation>,
    pub activities: Vec<UnifiedLogActivity>,
    pub sequence_anomalies: Vec<UnifiedLogSequenceAnomaly>,
    pub coverage: Vec<IntuneArtifactCoverage>,
    pub findings: Vec<IntuneFinding>,
}

impl UnifiedLogAnalysis {
    /// Observations that passed the selection rule.
    pub fn relevant_observations(&self) -> impl Iterator<Item = &UnifiedLogObservation> {
        self.observations
            .iter()
            .filter(|observation| observation.relevance.is_relevant())
    }

    /// Observations sharing an explicit identifier with a direct Company Portal
    /// log record.
    ///
    /// This is the only sanctioned join between this leaf's evidence and a
    /// direct-log record. There is no timestamp overload, by design: a
    /// time-proximate record is not the same operation, and the corpus contains
    /// a fixture that fails if this ever changes.
    pub fn observations_matching_key(
        &self,
        key: &UnifiedLogCorrelationKey,
    ) -> Vec<&UnifiedLogObservation> {
        self.observations
            .iter()
            .filter(|observation| {
                observation.relevance.is_relevant() && observation.correlation_keys.contains(key)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unrecognized_message_type_maps_to_unknown_not_to_a_level() {
        let level = UnifiedLogLevel::from_message_type(Some(&UnifiedLogMessageType::Unknown(
            "notice".to_owned(),
        )));
        assert_eq!(level, UnifiedLogLevel::Unknown);
        assert!(!level.is_failure());
    }

    #[test]
    fn fault_and_error_are_the_only_failure_levels() {
        assert!(UnifiedLogLevel::Fault.is_failure());
        assert!(UnifiedLogLevel::Error.is_failure());
        for level in [
            UnifiedLogLevel::Debug,
            UnifiedLogLevel::Info,
            UnifiedLogLevel::Default,
            UnifiedLogLevel::Unknown,
        ] {
            assert!(!level.is_failure(), "{level:?} must not be a failure signal");
        }
    }

    #[test]
    fn capture_state_wire_values_match_the_manifest_vocabulary() {
        for (state, wire) in [
            (UnifiedLogCaptureState::Captured, "\"captured\""),
            (UnifiedLogCaptureState::Capped, "\"capped\""),
            (UnifiedLogCaptureState::Absent, "\"absent\""),
            (UnifiedLogCaptureState::AccessDenied, "\"accessDenied\""),
            (UnifiedLogCaptureState::Skipped, "\"skipped\""),
            (UnifiedLogCaptureState::Unsupported, "\"unsupported\""),
            (UnifiedLogCaptureState::ParseFailed, "\"parseFailed\""),
        ] {
            assert_eq!(serde_json::to_string(&state).unwrap(), wire);
        }
    }

    #[test]
    fn correlation_kinds_have_no_timestamp_variant() {
        // A compile-time reminder rather than a runtime check: if someone adds a
        // time-based join kind, this exhaustive match stops compiling and the
        // reviewer is forced to read the doc comment on the enum.
        for kind in [
            UnifiedLogCorrelationKind::Activity,
            UnifiedLogCorrelationKind::ParentActivity,
            UnifiedLogCorrelationKind::Signpost,
            UnifiedLogCorrelationKind::ClientRequestId,
            UnifiedLogCorrelationKind::CorrelationId,
            UnifiedLogCorrelationKind::SessionId,
        ] {
            let named = match kind {
                UnifiedLogCorrelationKind::Activity => "activity",
                UnifiedLogCorrelationKind::ParentActivity => "parentActivity",
                UnifiedLogCorrelationKind::Signpost => "signpost",
                UnifiedLogCorrelationKind::ClientRequestId => "clientRequestId",
                UnifiedLogCorrelationKind::CorrelationId => "correlationId",
                UnifiedLogCorrelationKind::SessionId => "sessionId",
            };
            assert_eq!(serde_json::to_string(&kind).unwrap(), format!("\"{named}\""));
        }
    }
}
