//! Shared evidence, provenance, coverage, and finding contracts for the Intune
//! parser family (epic #356).
//!
//! Every workload leaf under `intune::{apps, enrollment, device, portal}` emits
//! observations that carry an [`IntuneObservationContext`]. That envelope is what
//! lets a result distinguish *absent*, *inaccessible*, *capped*, *skipped*,
//! *unsupported*, and *malformed* evidence from a successful workload, instead of
//! silently collapsing all six into "no data".
//!
//! The shape deliberately mirrors `crate::esp` so that the two trees stay legible
//! side by side, but the types are separate: ESP's schema is stable and versioned
//! on its own cadence, and coupling the families would make either one hard to
//! evolve.
//!
//! This module is owned by the parser-family skeleton. Workload leaves consume it
//! and must not need to modify it; see the note on additive extension at the
//! bottom of this file.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Schema version for every type in this module.
///
/// Bump only on a breaking change. Adding an optional field, or a variant to a
/// [`intune_raw_preserving_string_enum`] enum, is additive and does not bump it.
pub const INTUNE_EVIDENCE_SCHEMA_VERSION: u32 = 1;

/// Define an enum whose wire form round-trips values it does not recognize.
///
/// Microsoft's vocabularies grow without warning. An unrecognized status must
/// survive a decode/encode cycle verbatim rather than becoming `Unknown` and
/// losing the original token, because the raw token is often the only evidence a
/// human has to work from.
macro_rules! intune_raw_preserving_string_enum {
    (
        $(#[$meta:meta])*
        pub enum $name:ident {
            $($variant:ident => $wire_value:literal),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub enum $name {
            $($variant,)+
            /// A wire value this build does not recognize, preserved verbatim.
            Unknown(String),
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                let value = match self {
                    $(Self::$variant => $wire_value,)+
                    Self::Unknown(raw) => raw.as_str(),
                };

                serializer.serialize_str(value)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let raw = String::deserialize(deserializer)?;
                Ok(match raw.as_str() {
                    $($wire_value => Self::$variant,)+
                    _ => Self::Unknown(raw),
                })
            }
        }
    };
}

// Re-exported for the workload leaves of epic #356, which parse Microsoft
// vocabularies that grow over time and need the same round-tripping behavior.
// It has no in-crate consumer besides `IntuneSourceKind` below until the first
// leaf lands, and an unused re-export is a hard error under `-D warnings`.
#[allow(unused_imports)]
pub(crate) use intune_raw_preserving_string_enum;

intune_raw_preserving_string_enum! {
    /// The kind of artifact an observation was read from.
    ///
    /// Unrecognized kinds round-trip so a leaf can introduce a source without
    /// editing this shared enum.
    pub enum IntuneSourceKind {
        ImeLog => "imeLog",
        CcmLog => "ccmLog",
        AgentLog => "agentLog",
        PlainTextLog => "plainTextLog",
        Registry => "registry",
        EventLog => "eventLog",
        Json => "json",
        UnifiedLog => "unifiedLog",
        DiagnosticReport => "diagnosticReport",
        SuppliedFact => "suppliedFact",
        Graph => "graph",
        Coverage => "coverage",
    }
}

/// How a source timestamp was expressed before normalization.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum IntuneTimestampKind {
    Utc,
    Offset,
    Local,
    Unspecified,
    Invalid,
}

/// A timestamp that keeps its original text alongside the normalized value.
///
/// The raw text is retained because Intune logs mix local time, explicit offsets,
/// and bare wall-clock strings; discarding the original makes a wrong timezone
/// inference impossible to audit after the fact.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct IntuneTimestamp {
    pub raw_text: String,
    pub original_offset: Option<String>,
    pub normalized_utc: Option<String>,
    pub kind: IntuneTimestampKind,
}

/// A stable pointer to one observation, used by findings and coverage entries.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub struct IntuneEvidenceRef {
    pub evidence_id: String,
    pub source_artifact_id: String,
}

/// Registry location an observation came from, when the source is a registry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct IntuneRegistryProvenance {
    pub hive: String,
    pub key: String,
    pub value_name: Option<String>,
}

/// Event-log coordinates an observation came from, when the source is an event log.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct IntuneEventProvenance {
    pub channel: String,
    pub provider: String,
    pub event_id: u32,
    pub record_id: Option<u64>,
}

/// Where an observation physically came from.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct IntuneProvenance {
    pub source_kind: IntuneSourceKind,
    pub source_artifact_id: String,
    pub file_path: Option<String>,
    pub line_number: Option<u64>,
    pub record_number: Option<u64>,
    pub registry: Option<IntuneRegistryProvenance>,
    pub event: Option<IntuneEventProvenance>,
}

/// Privacy classification governing whether a value may appear in an export.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum IntuneSensitivity {
    Public,
    Sensitive,
    Restricted,
}

/// Whether the record was understood, and if not, how it failed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum IntuneParseState {
    Parsed,
    Raw,
    Malformed,
    Unsupported,
}

/// Whether the underlying artifact could be read at all.
///
/// `Capped` and `Skipped` are distinct from `Missing` on purpose: a truncated or
/// deliberately skipped source means the absence of a signal proves nothing,
/// whereas a genuinely missing artifact is itself a diagnostic fact.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum IntuneAccessState {
    Available,
    Missing,
    PermissionDenied,
    Capped,
    Skipped,
    Failed,
    Unsupported,
}

/// The uniform envelope every workload observation carries.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct IntuneObservationContext {
    pub evidence_ref: IntuneEvidenceRef,
    pub provenance: IntuneProvenance,
    pub source_timestamp: Option<IntuneTimestamp>,
    pub observed_at_utc: String,
    pub sensitivity: IntuneSensitivity,
    pub parse_state: IntuneParseState,
    pub access_state: IntuneAccessState,
}

/// A name/value pair carried without interpretation.
///
/// Leaves use this to retain fields they do not model yet, so that adding a typed
/// field later is a widening change rather than a re-parse.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct IntuneNamedValue {
    pub name: String,
    pub value: String,
}

/// A return/exit/error token, kept in every form it was observed in.
///
/// Intune surfaces the same failure as a signed decimal, an unsigned decimal, and
/// a hex HRESULT depending on the artifact. Storing the raw token plus both
/// derived forms avoids assigning a meaning the evidence does not carry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct IntuneErrorCode {
    pub raw: String,
    pub decimal: Option<i64>,
    pub hex: Option<String>,
}

/// Whether an expected artifact was usable.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum IntuneArtifactStatus {
    Available,
    Missing,
    PermissionDenied,
    Capped,
    Skipped,
    ParseFailed,
    Unsupported,
}

/// One expected artifact and what became of it.
///
/// Coverage is emitted for artifacts that were *not* read as well as those that
/// were; a finding may then cite a coverage gap instead of overclaiming.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct IntuneArtifactCoverage {
    pub artifact_id: String,
    pub family: String,
    pub status: IntuneArtifactStatus,
    pub detail: Option<String>,
    pub observed_at_utc: String,
    pub evidence: Vec<IntuneEvidenceRef>,
}

/// How serious a finding is.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum IntuneFindingSeverity {
    Info,
    Warning,
    Error,
    Blocker,
}

/// How strongly the evidence supports a finding.
///
/// Kept separate from severity because a catastrophic outcome inferred from thin
/// evidence and a minor one confirmed outright are different claims.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum IntuneFindingConfidence {
    Low,
    Medium,
    High,
}

/// A conservative, evidence-backed conclusion.
///
/// Invariant every leaf must uphold: a finding carries at least one entry in
/// `evidence` or at least one entry in `coverage_gap_ids`. A finding backed by
/// neither is an assertion, not a diagnosis.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct IntuneFinding {
    pub finding_id: String,
    pub severity: IntuneFindingSeverity,
    pub confidence: IntuneFindingConfidence,
    pub title: String,
    pub summary: String,
    pub recommended_checks: Vec<String>,
    pub evidence: Vec<IntuneEvidenceRef>,
    pub coverage_gap_ids: Vec<String>,
}

impl IntuneFinding {
    /// Whether this finding cites anything at all.
    ///
    /// Leaves should assert this in their own contract tests rather than relying
    /// on review to catch an uncited finding.
    pub fn is_evidence_backed(&self) -> bool {
        !self.evidence.is_empty() || !self.coverage_gap_ids.is_empty()
    }
}

// Extending this module from a workload leaf:
//
// Prefer `IntuneSourceKind::Unknown("...")` and `IntuneNamedValue` over new
// shared types; both round-trip and neither requires touching this file. If a
// genuinely shared concept is missing, append a variant at the end of the
// relevant enum or an `Option<T>` field at the end of the relevant struct. Both
// are additive, keep the schema version at 1, and produce a two-line merge rather
// than a conflict if two branches do it at once.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_kind_round_trips_known_values() {
        let encoded = serde_json::to_string(&IntuneSourceKind::ImeLog).unwrap();
        assert_eq!(encoded, "\"imeLog\"");
        let decoded: IntuneSourceKind = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, IntuneSourceKind::ImeLog);
    }

    #[test]
    fn source_kind_preserves_unknown_values_verbatim() {
        let decoded: IntuneSourceKind = serde_json::from_str("\"someFutureSource\"").unwrap();
        assert_eq!(
            decoded,
            IntuneSourceKind::Unknown("someFutureSource".to_owned())
        );
        assert_eq!(
            serde_json::to_string(&decoded).unwrap(),
            "\"someFutureSource\""
        );
    }

    #[test]
    fn access_state_distinguishes_capped_and_skipped_from_missing() {
        for (state, wire) in [
            (IntuneAccessState::Missing, "\"missing\""),
            (IntuneAccessState::Capped, "\"capped\""),
            (IntuneAccessState::Skipped, "\"skipped\""),
        ] {
            assert_eq!(serde_json::to_string(&state).unwrap(), wire);
        }
    }

    #[test]
    fn finding_without_evidence_or_coverage_gap_is_not_evidence_backed() {
        let mut finding = IntuneFinding {
            finding_id: "f1".to_owned(),
            severity: IntuneFindingSeverity::Error,
            confidence: IntuneFindingConfidence::Low,
            title: "t".to_owned(),
            summary: "s".to_owned(),
            recommended_checks: Vec::new(),
            evidence: Vec::new(),
            coverage_gap_ids: Vec::new(),
        };
        assert!(!finding.is_evidence_backed());

        finding.coverage_gap_ids.push("gap".to_owned());
        assert!(finding.is_evidence_backed());
    }
}
