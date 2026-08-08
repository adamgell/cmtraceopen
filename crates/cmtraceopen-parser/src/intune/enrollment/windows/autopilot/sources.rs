//! The input contract: what a native collector hands the pure reducer.
//!
//! EVTX decoding, registry reads, diagnostics-export generation, and live OOBE
//! interaction are all native concerns and stay outside this crate. What
//! crosses the boundary is a set of *documents*: serializable, versioned, and
//! self-identifying.
//!
//! # Explicit schema detection
//!
//! A document is only interpreted when it says what it is. Every supported
//! document declares `autopilotDocument` (its kind) and `documentVersion`.
//! Content that omits the tag is [`IntuneParseState::Malformed`]; content that
//! declares a kind or version this build has no rules for is
//! [`IntuneParseState::Unsupported`] and is retained as raw evidence without
//! terminal semantics. Nothing is sniffed, and identifiers are never scraped
//! out of unrelated MDM report text.

use std::sync::OnceLock;

use regex::Regex;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::intune::evidence::{
    intune_raw_preserving_string_enum, IntuneAccessState, IntuneArtifactStatus, IntuneErrorCode,
    IntuneNamedValue, IntuneObservationContext,
};
use crate::intune::normalized::NormalizedWindowsEvent;

use super::models::{
    AutopilotCaptureMetadata, AutopilotEspSessionFact, AutopilotSectionKind,
    AutopilotSectionOutcome, AutopilotTimezoneState,
};

/// The only document version this build has validated rules for.
pub const AUTOPILOT_DOCUMENT_VERSION: u32 = 1;

/// The Autopilot diagnostics channel, per Microsoft's troubleshooting guidance.
pub const AUTOPILOT_EVENT_CHANNEL: &str =
    "Microsoft-Windows-ModernDeployment-Diagnostics-Provider/Autopilot";

/// The provider that owns [`AUTOPILOT_EVENT_CHANNEL`].
pub const AUTOPILOT_EVENT_PROVIDER: &str =
    "Microsoft-Windows-ModernDeployment-Diagnostics-Provider";

intune_raw_preserving_string_enum! {
    /// What a supplied document contains.
    pub enum AutopilotDocumentKind {
        Events => "autopilot.events",
        DiagnosticsReport => "autopilot.mdmDiagnosticsReport",
        IdentityFacts => "autopilot.identityFacts",
        EspSession => "autopilot.espSession",
    }
}

/// What the collector says happened to an artifact.
///
/// This mirrors [`IntuneAccessState`] because only the collector can know it:
/// the pure crate cannot distinguish "the file was not there" from "we were not
/// allowed to read it" from bytes it never received.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AutopilotCaptureState {
    Captured,
    Capped,
    Absent,
    AccessDenied,
    Skipped,
    Unsupported,
    ParseFailed,
}

impl AutopilotCaptureState {
    /// The coverage status this capture state implies before the reducer has
    /// looked at any bytes.
    pub fn declared_status(self) -> IntuneArtifactStatus {
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

    /// The observation-level access state records from this artifact carry.
    pub fn access_state(self) -> IntuneAccessState {
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

    /// Whether the absence of a signal in this artifact proves anything.
    ///
    /// A capped or partially collected channel cannot support a negative
    /// conclusion, which is the whole reason `Capped` is not folded into
    /// `Available`.
    pub fn supports_negative_conclusion(self) -> bool {
        self == Self::Captured
    }
}

/// One artifact the collector attempted, and its bytes when it got any.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutopilotSourceInput {
    pub artifact_id: String,
    /// Coarse grouping used by coverage, e.g. `autopilotEvents` or `mdmReport`.
    pub family: String,
    pub capture_state: AutopilotCaptureState,
    pub original_basename: Option<String>,
    /// Already sanitized by the collector; never a live host path.
    pub sanitized_source_path: Option<String>,
    pub content: Option<String>,
    /// Coarse artifact kind tag for rotation/fragment accounting.
    pub source_kind_tag: Option<String>,
    /// Rotation index when a channel was split across multiple files.
    pub rotation_index: Option<u32>,
    /// Fragment index within a rotation, for further sub-splits.
    pub fragment_index: Option<u32>,
}

impl Default for AutopilotSourceInput {
    fn default() -> Self {
        Self {
            artifact_id: String::new(),
            family: String::new(),
            capture_state: AutopilotCaptureState::Absent,
            original_basename: None,
            sanitized_source_path: None,
            content: None,
            source_kind_tag: None,
            rotation_index: None,
            fragment_index: None,
        }
    }
}

/// Everything the reducer is given for one device.
#[derive(Debug, Clone, Default)]
pub struct AutopilotBundleInput {
    /// The pure crate has no clock; the caller states when this ran.
    pub generated_at_utc: String,
    pub capture: AutopilotCaptureMetadata,
    pub sources: Vec<AutopilotSourceInput>,
    /// Events a native adapter already normalized, in addition to any carried
    /// by an `autopilot.events` document in `sources`.
    pub events: Vec<NormalizedWindowsEvent>,
}

// ── Document envelope ───────────────────────────────────────────────────────

/// What detection concluded about one document's bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AutopilotDocumentDetection {
    /// A kind and version this build has rules for.
    Supported {
        kind: AutopilotDocumentKind,
        version: u32,
    },
    /// Well-formed JSON declaring a kind or version this build cannot
    /// interpret. The bytes remain valid evidence; their meaning does not.
    Unsupported {
        declared_kind: Option<String>,
        declared_version: Option<u32>,
        detail: String,
    },
    /// Not parseable as a tagged Autopilot document at all.
    Malformed { detail: String },
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DocumentEnvelope {
    autopilot_document: Option<String>,
    document_version: Option<u32>,
}

/// Classify a document's bytes without interpreting its payload.
///
/// Detection is deliberately separate from parsing so that an unknown-version
/// document produces a precise coverage fact rather than a parse error that
/// looks like corruption.
pub fn detect_document(content: &str) -> AutopilotDocumentDetection {
    // The detail stays a stable reducer-authored sentence: it flows into
    // golden-asserted finding summaries, and serde_json does not guarantee its
    // error `Display` output across releases.
    let envelope: DocumentEnvelope = match serde_json::from_str(content) {
        Ok(envelope) => envelope,
        Err(_) => {
            return AutopilotDocumentDetection::Malformed {
                detail: "content is not a JSON object".to_owned(),
            }
        }
    };

    let Some(declared_kind) = envelope.autopilot_document else {
        return AutopilotDocumentDetection::Malformed {
            detail: "document does not declare autopilotDocument".to_owned(),
        };
    };
    let Some(declared_version) = envelope.document_version else {
        return AutopilotDocumentDetection::Unsupported {
            declared_kind: Some(declared_kind),
            declared_version: None,
            detail: "document does not declare documentVersion".to_owned(),
        };
    };

    let kind: AutopilotDocumentKind =
        match serde_json::from_value(serde_json::Value::String(declared_kind.clone())) {
            Ok(kind) => kind,
            // The raw-preserving enum never fails to decode a string, so this arm
            // is unreachable in practice; treating it as unsupported rather than
            // panicking keeps the reducer total.
            Err(error) => {
                return AutopilotDocumentDetection::Unsupported {
                    declared_kind: Some(declared_kind),
                    declared_version: Some(declared_version),
                    detail: format!("document kind could not be decoded: {error}"),
                }
            }
        };

    if let AutopilotDocumentKind::Unknown(raw) = &kind {
        return AutopilotDocumentDetection::Unsupported {
            declared_kind: Some(raw.clone()),
            declared_version: Some(declared_version),
            detail: format!("no validated rules for document kind {raw}"),
        };
    }
    if declared_version != AUTOPILOT_DOCUMENT_VERSION {
        return AutopilotDocumentDetection::Unsupported {
            detail: format!(
                "no validated rules for {declared_kind} version {declared_version}; \
                 this build understands version {AUTOPILOT_DOCUMENT_VERSION}"
            ),
            declared_kind: Some(declared_kind),
            declared_version: Some(declared_version),
        };
    }

    AutopilotDocumentDetection::Supported {
        kind,
        version: declared_version,
    }
}

// ── Document payloads ───────────────────────────────────────────────────────

/// An `autopilot.events` payload: normalized Windows event records.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AutopilotEventsDocument {
    #[serde(default)]
    pub events: Vec<NormalizedWindowsEvent>,
    /// True when the collector knows the channel was truncated at either end.
    /// A truncated channel cannot support "this never happened".
    #[serde(default)]
    pub channel_complete: Option<bool>,
}

/// One section of an MDM diagnostics report or diagnostics-page export.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AutopilotReportSection {
    pub context: IntuneObservationContext,
    pub section_id: String,
    pub kind: AutopilotSectionKind,
    pub outcome: AutopilotSectionOutcome,
    #[serde(default)]
    pub error: Option<IntuneErrorCode>,
    #[serde(default)]
    pub values: Vec<IntuneNamedValue>,
    #[serde(default)]
    pub message: Option<String>,
}

/// An `autopilot.mdmDiagnosticsReport` or `autopilot.identityFacts` payload.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AutopilotReportDocument {
    #[serde(default)]
    pub sections: Vec<AutopilotReportSection>,
}

/// An `autopilot.espSession` payload: facts from the sibling ESP reducer.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AutopilotEspSessionDocument {
    #[serde(default)]
    pub sessions: Vec<AutopilotEspSessionFact>,
}

// ── Capture metadata validation ─────────────────────────────────────────────

/// Windows builds this build has validated Autopilot rules for.
///
/// The documented event vocabulary is stable across supported Windows 10 and
/// 11 servicing, so the gate is the *major* build line rather than an exact
/// build. A build outside this set is not an error; it means terminal
/// semantics are refused and the evidence is kept raw.
const VALIDATED_BUILD_PREFIXES: [&str; 6] =
    ["10.0.19", "10.0.22", "10.0.25", "10.0.26", "19", "22"];

/// Whether the declared Windows build is one with validated rules.
///
/// An undeclared build is *not* treated as unvalidated: many collectors cannot
/// read it, and refusing every conclusion on that basis would make the reducer
/// useless. An explicitly declared but unrecognized build is what triggers
/// refusal, because that is a positive statement the reducer disagrees with.
pub fn is_validated_windows_build(build: Option<&str>) -> bool {
    let Some(build) = build.map(str::trim).filter(|build| !build.is_empty()) else {
        return true;
    };
    VALIDATED_BUILD_PREFIXES
        .iter()
        .any(|prefix| build.starts_with(prefix))
}

/// Whether the declared Autopilot schema version is one with validated rules.
pub fn is_validated_schema_version(version: Option<&str>) -> bool {
    let Some(version) = version.map(str::trim).filter(|value| !value.is_empty()) else {
        return true;
    };
    version == "1" || version == "1.0"
}

fn utc_offset_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"^(?i)(?:UTC|Z|GMT)?(?:[+-](?:[01]\d|2[0-3]):?[0-5]\d)?$")
            .expect("utc offset regex must compile")
    })
}

fn iana_zone_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"^[A-Za-z][A-Za-z_+-]*(?:/[A-Za-z0-9][A-Za-z0-9_+-]*){1,2}$")
            .expect("iana zone regex must compile")
    })
}

/// A Windows time zone identifier such as `Pacific Standard Time`.
///
/// Windows collectors report this form, not an IANA name, so omitting it made
/// the single most common real input classify as invalid and needlessly
/// downgraded the time basis. Every Windows time zone identifier ends in
/// `Time` (`W. Europe Standard Time`, `Coordinated Universal Time`); anchoring
/// on that suffix is what rejects collector placeholders such as `unknown` or
/// `not recorded`, which would otherwise pass as a declared timezone and let
/// `reduce_esp_linkage` offer a time-only candidate the module contract
/// forbids. `UTC` and offset forms are covered by `utc_offset_re`. Punctuation
/// beyond spaces, hyphens, and periods stays excluded, which still rejects an
/// annotated value like `Pacific Standard Time (device local)`.
fn windows_zone_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"^[A-Za-z][A-Za-z .\-]* Time$").expect("windows zone regex must compile")
    })
}

/// Classify the declared collection timezone.
///
/// The pure crate carries no timezone database, so this checks *shape* only: a
/// fixed UTC offset, a bare `UTC`/`Z`/`GMT`, an `Area/City` identifier, or a
/// Windows time zone name. Claiming more than that would be inventing a
/// validation the crate cannot perform, so `Declared` means "this looks like a
/// timezone", never "this timezone exists".
pub fn classify_timezone(timezone: Option<&str>) -> AutopilotTimezoneState {
    let Some(timezone) = timezone.map(str::trim) else {
        return AutopilotTimezoneState::Missing;
    };
    if timezone.is_empty() {
        return AutopilotTimezoneState::Missing;
    }
    let looks_like_offset = utc_offset_re().is_match(timezone)
        && timezone
            .chars()
            .any(|character| character.is_ascii_alphanumeric());
    if looks_like_offset
        || iana_zone_re().is_match(timezone)
        || windows_zone_re().is_match(timezone)
    {
        AutopilotTimezoneState::Declared
    } else {
        AutopilotTimezoneState::Invalid
    }
}

/// Whether the whole capture declares a context this build can reason about.
pub fn capture_is_validated(capture: &AutopilotCaptureMetadata) -> bool {
    is_validated_windows_build(capture.windows_build.as_deref())
        && is_validated_schema_version(capture.autopilot_schema_version.as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tagged_current_version_document_is_supported() {
        let detection = detect_document(
            r#"{"autopilotDocument":"autopilot.events","documentVersion":1,"events":[]}"#,
        );
        assert_eq!(
            detection,
            AutopilotDocumentDetection::Supported {
                kind: AutopilotDocumentKind::Events,
                version: 1,
            }
        );
    }

    #[test]
    fn an_untagged_document_is_malformed_not_unsupported() {
        // The distinction matters: unsupported means "we know what this is and
        // refuse to interpret it", malformed means "this is not our document".
        let detection = detect_document(r#"{"events":[]}"#);
        assert!(matches!(
            detection,
            AutopilotDocumentDetection::Malformed { .. }
        ));
    }

    #[test]
    fn a_future_version_is_unsupported_and_keeps_the_declared_values() {
        let detection = detect_document(
            r#"{"autopilotDocument":"autopilot.events","documentVersion":9,"events":[]}"#,
        );
        match detection {
            AutopilotDocumentDetection::Unsupported {
                declared_kind,
                declared_version,
                ..
            } => {
                assert_eq!(declared_kind.as_deref(), Some("autopilot.events"));
                assert_eq!(declared_version, Some(9));
            }
            other => panic!("expected unsupported, got {other:?}"),
        }
    }

    #[test]
    fn an_unknown_kind_is_unsupported_and_preserves_the_raw_token() {
        let detection = detect_document(
            r#"{"autopilotDocument":"autopilot.somethingNew","documentVersion":1}"#,
        );
        match detection {
            AutopilotDocumentDetection::Unsupported { declared_kind, .. } => {
                assert_eq!(declared_kind.as_deref(), Some("autopilot.somethingNew"));
            }
            other => panic!("expected unsupported, got {other:?}"),
        }
    }

    #[test]
    fn non_json_content_is_malformed() {
        assert!(matches!(
            detect_document("<html><body>not a document</body></html>"),
            AutopilotDocumentDetection::Malformed { .. }
        ));
    }

    #[test]
    fn timezone_shapes_are_classified_without_a_timezone_database() {
        assert_eq!(
            classify_timezone(Some("UTC")),
            AutopilotTimezoneState::Declared
        );
        assert_eq!(
            classify_timezone(Some("UTC-05:00")),
            AutopilotTimezoneState::Declared
        );
        assert_eq!(
            classify_timezone(Some("America/New_York")),
            AutopilotTimezoneState::Declared
        );
        assert_eq!(classify_timezone(None), AutopilotTimezoneState::Missing);
        assert_eq!(
            classify_timezone(Some("   ")),
            AutopilotTimezoneState::Missing
        );
    }

    #[test]
    fn a_windows_time_zone_name_is_accepted_but_an_annotated_one_is_not() {
        // Windows collectors report this form, so rejecting it downgraded the
        // time basis on the most common real input there is.
        assert_eq!(
            classify_timezone(Some("Pacific Standard Time")),
            AutopilotTimezoneState::Declared
        );
        assert_eq!(
            classify_timezone(Some("W. Europe Standard Time")),
            AutopilotTimezoneState::Declared
        );
        for junk in [
            "Pacific Standard Time (device local)",
            "Pacific Standard Time?",
            "??",
            // Collector placeholders: a plausible-looking word is not a
            // declared timezone, and treating it as one raised confidence and
            // enabled the time-only ESP candidate the contract forbids.
            "unknown",
            "not recorded",
            "Unavailable",
        ] {
            assert_eq!(
                classify_timezone(Some(junk)),
                AutopilotTimezoneState::Invalid,
                "{junk:?} must not pass as a timezone"
            );
        }
    }

    #[test]
    fn an_undeclared_build_is_not_treated_as_unvalidated() {
        // Refusing every conclusion when the collector simply could not read
        // the build would make the reducer useless on the majority of bundles.
        assert!(is_validated_windows_build(None));
        assert!(is_validated_windows_build(Some("10.0.22631.4317")));
        assert!(!is_validated_windows_build(Some("10.0.99999.1")));
    }

    #[test]
    fn capture_states_bind_to_coverage_and_access_states() {
        assert_eq!(
            AutopilotCaptureState::Capped.declared_status(),
            IntuneArtifactStatus::Capped
        );
        assert_eq!(
            AutopilotCaptureState::Capped.access_state(),
            IntuneAccessState::Capped
        );
        assert!(!AutopilotCaptureState::Capped.supports_negative_conclusion());
        assert!(AutopilotCaptureState::Captured.supports_negative_conclusion());
    }
}
