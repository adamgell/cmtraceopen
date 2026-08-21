//! Evidence-backed operational diagnosis for normalized Windows events and existing source findings.
//!
//! This module is deliberately pure: it accepts already parsed records and findings and returns
//! serializable projections. It does not read files, call Windows APIs, or infer causality from
//! timestamps. Native source references remain tagged so an operator can navigate back to the
//! source-specific evidence that produced a conclusion.

use crate::error_db::lookup::{detect_error_code_spans, lookup_error_code, ErrorLookupResult};
use crate::esp::{EspDiagnosticFinding, EspEvidenceRef, EspFindingConfidence, EspFindingSeverity};
use crate::intune::apps::windows::common::redact_text;
use crate::intune::evidence::{
    IntuneEvidenceRef, IntuneFinding, IntuneFindingConfidence, IntuneFindingSeverity,
};
use crate::intune::models::{EventLogChannel, EventLogEntry, EventLogSeverity};
use crate::models::log_entry::{LogEntry, Severity};
use crate::sccm::{SccmConfidence, SccmEvidenceRef, SccmFinding, SccmFindingClass};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::LazyLock;

fn redact_labeled_value(label: &str, value: &str) -> String {
    let prefix = format!("{label}=");
    let redacted = redact_text(&format!("{prefix}{value}"));
    redacted
        .strip_prefix(&prefix)
        .unwrap_or(&redacted)
        .to_owned()
}

/// A source reference retained without flattening the source-specific evidence contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "camelCase")]
#[non_exhaustive]
pub enum EvidenceRef {
    Intune(IntuneEvidenceRef),
    Esp(EspEvidenceRef),
    Sccm(SccmEvidenceRef),
    DsregcmdRaw(String),
    TextLog(TextLogEvidenceRef),
    Event(EventEvidenceRef),
}

impl EvidenceRef {
    /// Wraps an Intune-native evidence reference.
    pub fn from_intune(value: IntuneEvidenceRef) -> Self {
        Self::Intune(value)
    }

    /// Wraps an ESP-native evidence reference.
    pub fn from_esp(value: EspEvidenceRef) -> Self {
        Self::Esp(value)
    }

    /// Wraps an SCCM-native evidence reference.
    pub fn from_sccm(value: SccmEvidenceRef) -> Self {
        Self::Sccm(value)
    }

    /// Wraps a raw dsregcmd evidence reference.
    pub fn from_dsreg_raw(value: impl Into<String>) -> Self {
        Self::DsregcmdRaw(value.into())
    }
    /// Wraps a normalized text-log evidence reference.
    pub fn from_text_log(value: TextLogEvidenceRef) -> Self {
        Self::TextLog(value)
    }

    /// Creates an event evidence reference from its stable source coordinates.
    pub fn from_event(
        source: impl Into<String>,
        provider: impl Into<String>,
        event_id: u32,
        record_id: u64,
    ) -> Self {
        Self::Event(EventEvidenceRef {
            source: source.into(),
            provider: provider.into(),
            event_id,
            record_id,
            record_id_text: None,
            fallback_identity: None,
            machine: None,
            channel: None,
            activity_id: None,
        })
    }

    /// A deterministic ID used for deduplication and UI navigation.
    pub fn stable_id(&self) -> String {
        match self {
            Self::Intune(value) => {
                format!("intune:{}:{}", value.source_artifact_id, value.evidence_id)
            }
            Self::Esp(value) => format!("esp:{}:{}", value.source_artifact_id, value.evidence_id),
            Self::Sccm(value) => format!("sccm:{}:{}", value.artifact_id, value.entry_id),
            Self::DsregcmdRaw(value) => format!("dsregcmd:{value}"),
            Self::TextLog(value) => value.stable_id(),
            Self::Event(value) => value.stable_id(),
        }
    }

    /// Returns the source-native pointer or raw identifier for display and export.
    pub fn source_reference(&self) -> String {
        match self {
            Self::Intune(value) => format!("{}#{}", value.source_artifact_id, value.evidence_id),
            Self::Esp(value) => format!("{}#{}", value.source_artifact_id, value.evidence_id),
            Self::Sccm(value) => {
                let line = match (value.line_start, value.line_end) {
                    (Some(start), Some(end)) => format!(":{start}-{end}"),
                    (Some(start), None) => format!(":{start}"),
                    _ => String::new(),
                };
                format!("{}#{}{}", value.artifact_id, value.entry_id, line)
            }
            Self::DsregcmdRaw(value) => value.clone(),
            Self::TextLog(value) => value.source_reference(),
            Self::Event(value) => value.stable_id(),
        }
    }
}
/// Coordinates for a normalized text-log entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TextLogEvidenceRef {
    pub source: String,
    pub file_path: String,
    pub line_number: u32,
    pub entry_id: u64,
}

impl TextLogEvidenceRef {
    fn stable_id(&self) -> String {
        format!(
            "text:{}:{}:{}",
            self.file_path, self.line_number, self.entry_id
        )
    }

    fn source_reference(&self) -> String {
        format!("{}:{}", self.file_path, self.line_number)
    }
}

/// Coordinates for a normalized event record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventEvidenceRef {
    pub source: String,
    pub provider: String,
    pub event_id: u32,
    pub record_id: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_id_text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback_identity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activity_id: Option<String>,
}

impl EventEvidenceRef {
    /// Returns the deterministic ID used for deduplication and UI navigation.
    pub fn stable_id(&self) -> String {
        let fallback_record_id = self.record_id.to_string();
        let record_id = self
            .record_id_text
            .as_deref()
            .filter(|value| {
                let trimmed = value.trim();
                !trimmed.is_empty() && trimmed.chars().any(|character| character != '0')
            })
            .or(self.fallback_identity.as_deref())
            .unwrap_or(&fallback_record_id);
        let machine = self.machine.as_deref().unwrap_or_default();
        let channel = self.channel.as_deref().unwrap_or_default();
        format!(
            "event:{}:{}:{}:{}:{}:{}",
            self.source, machine, channel, self.provider, self.event_id, record_id
        )
    }
}

/// Coverage is separate from an assertion about a source's health.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum CoverageState {
    Covered,
    Unknown,
    Absent,
    AccessDenied,
    Capped,
    Skipped,
    Unsupported,
    Malformed,
    ParseFailed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CoverageGap {
    pub id: String,
    pub source: String,
    pub state: CoverageState,
    pub detail: String,
    #[serde(default)]
    pub evidence: Vec<EvidenceRef>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum FindingClass {
    ConfirmedFailure,
    LikelyContributor,
    Symptom,
    Recovered,
    ContradictoryEvidence,
    CoverageGap,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum FindingSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum FindingConfidence {
    Unknown,
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosisFinding {
    pub finding_id: String,
    pub class: FindingClass,
    pub severity: FindingSeverity,
    pub confidence: FindingConfidence,
    pub title: String,
    pub summary: String,
    #[serde(default)]
    pub evidence: Vec<EvidenceRef>,
    #[serde(default)]
    pub coverage_gaps: Vec<CoverageGap>,
    #[serde(default)]
    pub recommended_checks: Vec<String>,
}

/// Builds a non-assertive finding for an unavailable source.
pub fn finding_for_coverage(
    source: impl Into<String>,
    state: CoverageState,
    detail: String,
) -> DiagnosisFinding {
    let source = source.into();
    let gap_id = format!("coverage:{source}:{state:?}:{detail}");
    let gap = CoverageGap {
        id: gap_id.clone(),
        source: source.clone(),
        state,
        detail: detail.clone(),
        evidence: Vec::new(),
    };
    DiagnosisFinding {
        finding_id: format!("coverage-gap:{source}:{detail}"),
        class: FindingClass::CoverageGap,
        severity: FindingSeverity::Info,
        confidence: FindingConfidence::Unknown,
        title: format!("{source} evidence coverage is incomplete"),
        summary: detail,
        evidence: Vec::new(),
        coverage_gaps: vec![gap],
        recommended_checks: vec![format!(
            "Collect or grant access to the {source} evidence source."
        )],
    }
}

/// A token enriched using the existing error database without losing the original spelling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorToken {
    pub raw: String,
    pub decimal: Option<i64>,
    pub hex: Option<String>,
    pub malformed: bool,
    pub found: bool,
    pub description: Option<String>,
    pub category: Option<String>,
}

impl ErrorToken {
    /// Parses a raw token through the shared error database.
    pub fn from_raw(raw: impl Into<String>) -> Self {
        let raw = raw.into();
        let lookup = lookup_error_code(&raw);
        Self::from_lookup(raw, lookup)
    }

    fn from_lookup(raw: String, lookup: ErrorLookupResult) -> Self {
        let malformed = lookup.code_hex.is_empty();
        Self {
            raw,
            decimal: lookup.code_decimal.parse::<i64>().ok(),
            hex: (!lookup.code_hex.is_empty()).then_some(lookup.code_hex),
            malformed,
            found: lookup.found,
            description: (!lookup.description.is_empty()
                && lookup.description != "Unknown error code"
                && lookup.description != "Invalid error code format")
                .then_some(lookup.description),
            category: (!lookup.category.is_empty()).then_some(lookup.category),
        }
    }
}

fn error_token_re() -> &'static Regex {
    static CELL: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?:0[xX][0-9A-Za-z]+|[-+]?[0-9]{4,}|\b[0-9A-Fa-f]{8}\b)")
            .expect("error token regex")
    });
    &CELL
}

fn utf16_slice(value: &str, start: usize, end: usize) -> Option<&str> {
    if start >= end {
        return None;
    }
    let mut units = 0usize;
    let mut start_byte = None;
    for (byte, character) in value.char_indices() {
        if units == start {
            start_byte = Some(byte);
        }
        units += character.len_utf16();
        if units == end {
            return start_byte.map(|begin| &value[begin..byte + character.len_utf8()]);
        }
    }
    None
}
fn has_error_context(message: &str, start: usize, end: usize) -> bool {
    let context_start = message[..start]
        .rfind(['.', ';', '\n'])
        .map(|index| index + 1)
        .unwrap_or(0);
    let context_end = message[end..]
        .find(['.', ';', '\n'])
        .map(|index| end + index)
        .unwrap_or(message.len());
    let context = message
        .get(context_start..context_end)
        .unwrap_or_default()
        .to_ascii_lowercase();
    ["error", "hresult", "code", "status", "failed", "failure"]
        .iter()
        .any(|marker| context.contains(marker))
}

/// Enrich every plausible error token in a message. Known spans are consulted first through the
/// shared detector; the wider token scan then keeps unknown and malformed forms lossless too.
pub fn enrich_error_tokens(message: &str) -> Vec<ErrorToken> {
    let mut candidates = detect_error_code_spans(message)
        .into_iter()
        .filter_map(|span| {
            utf16_slice(message, span.start, span.end).map(|raw| (span.start, raw.to_string()))
        })
        .collect::<Vec<_>>();
    candidates.extend(error_token_re().find_iter(message).filter_map(|matched| {
        let raw = matched.as_str();
        let explicit = raw.starts_with("0x")
            || raw.starts_with("0X")
            || raw.starts_with('+')
            || raw.starts_with('-');
        (explicit || has_error_context(message, matched.start(), matched.end()))
            .then(|| (matched.start(), raw.to_string()))
    }));
    candidates.sort_by_key(|(start, _)| *start);

    let mut tokens = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for (_, raw) in candidates {
        if seen.insert(raw.clone()) {
            tokens.push(ErrorToken::from_raw(raw));
        }
    }
    tokens
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum EventFamily {
    Autopilot,
    Esp,
    MdmEnrollment,
    ConfigMgrClient,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventDiagnosis {
    pub evidence: Vec<EvidenceRef>,
    pub family: EventFamily,
    #[serde(default)]
    pub findings: Vec<DiagnosisFinding>,
    #[serde(default)]
    pub error_tokens: Vec<ErrorToken>,
}

fn family_from_text(value: &str) -> Option<EventFamily> {
    let lower = value.to_ascii_lowercase();
    if lower.contains("configmgr")
        || lower.contains("configuration manager")
        || lower.contains("configurationmanagement")
        || lower.contains("sccm")
        || lower.contains("ccm")
    {
        Some(EventFamily::ConfigMgrClient)
    } else if lower.contains("autopilot") {
        Some(EventFamily::Autopilot)
    } else if lower.contains("enrollment status")
        || lower
            .split(|character: char| !character.is_ascii_alphanumeric())
            .any(|token| token == "esp")
        || lower.contains("provisioning")
    {
        Some(EventFamily::Esp)
    } else if lower.contains("devicemanagement") || lower.contains("mdm") {
        Some(EventFamily::MdmEnrollment)
    } else {
        None
    }
}

fn event_family(entry: &EventLogEntry) -> EventFamily {
    match &entry.channel {
        crate::intune::models::EventLogChannel::Autopilot => EventFamily::Autopilot,
        crate::intune::models::EventLogChannel::ProvisioningDiagnosticsAdmin => EventFamily::Esp,
        crate::intune::models::EventLogChannel::DeviceManagementAdmin
        | crate::intune::models::EventLogChannel::DeviceManagementOperational => {
            EventFamily::MdmEnrollment
        }
        _ => {
            let source = format!("{} {}", entry.channel_display, entry.provider);
            family_from_text(&source)
                .or_else(|| family_from_text(&entry.message))
                .unwrap_or(EventFamily::Other)
        }
    }
}

fn family_label(family: EventFamily) -> &'static str {
    match family {
        EventFamily::Autopilot => "Autopilot",
        EventFamily::Esp => "ESP",
        EventFamily::MdmEnrollment => "MDM enrollment",
        EventFamily::ConfigMgrClient => "ConfigMgr client",
        EventFamily::Other => "event",
    }
}

fn event_severity(severity: EventLogSeverity) -> FindingSeverity {
    match severity {
        EventLogSeverity::Critical => FindingSeverity::Critical,
        EventLogSeverity::Error => FindingSeverity::Error,
        EventLogSeverity::Warning => FindingSeverity::Warning,
        EventLogSeverity::Information | EventLogSeverity::Verbose | EventLogSeverity::Unknown => {
            FindingSeverity::Info
        }
    }
}

fn explicit_failure(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.split(['.', ',', ';', '\n']).any(|clause| {
        [
            "failed",
            "failure",
            "error",
            "denied",
            "blocked",
            "timeout",
            "timed out",
        ]
        .iter()
        .any(|marker| {
            let negations: &[&str] = match *marker {
                "failed" => &[
                    "not failed",
                    "did not fail",
                    "no failure",
                    "without failure",
                ],
                "failure" => &["no failure", "without failure", "failure-free"],
                "error" => &[
                    "not an error",
                    "no error",
                    "without error",
                    "error-free",
                    "errorcode=0",
                    "errorcode=0x0",
                    "errorcode:0",
                    "error code = 0",
                    "error code: 0",
                ],
                "denied" => &["not denied", "no denial", "without denial"],
                "blocked" => &["not blocked", "no block", "without block"],
                "timeout" | "timed out" => &["no timeout", "without timeout", "not timed out"],
                _ => &[],
            };
            clause.contains(marker) && !negations.iter().any(|value| clause.contains(value))
        })
    })
}

fn explicit_success(message: &str) -> bool {
    message
        .to_ascii_lowercase()
        .split(['.', ',', ';', '\n'])
        .any(|clause| {
            let words = clause
                .split(|character: char| !character.is_ascii_alphanumeric())
                .filter(|word| !word.is_empty())
                .collect::<Vec<_>>();
            words.iter().enumerate().any(|(index, word)| {
                if !matches!(
                    *word,
                    "succeed"
                        | "succeeded"
                        | "success"
                        | "successful"
                        | "successfully"
                        | "complete"
                        | "completed"
                        | "installed"
                        | "enrolled"
                ) {
                    return false;
                }
                !matches!(
                    index
                        .checked_sub(1)
                        .and_then(|previous| words.get(previous))
                        .copied(),
                    Some("not" | "no" | "without")
                )
            })
        })
}

const MAX_FALLBACK_IDENTITY_COMPONENT_BYTES: usize = 256 * 1024;
const MAX_FALLBACK_IDENTITY_FIELDS: usize = 1024;

fn update_fallback_identity_text(digest: &mut Sha256, label: &str, value: &str) {
    let bytes = value.as_bytes();
    digest.update(label.as_bytes());
    digest.update((bytes.len() as u64).to_le_bytes());
    if bytes.len() <= MAX_FALLBACK_IDENTITY_COMPONENT_BYTES {
        digest.update(bytes);
        return;
    }
    digest.update(b"[hashed]");
    let mut component_digest = Sha256::new();
    component_digest.update(bytes);
    digest.update(component_digest.finalize());
}

fn event_fallback_identity(entry: &EventLogEntry, event_data: &[String], raw_xml: &str) -> String {
    let mut digest = Sha256::new();
    update_fallback_identity_text(&mut digest, "channel", entry.channel.display_name());
    if let EventLogChannel::Other(name) = &entry.channel {
        update_fallback_identity_text(&mut digest, "channelOther", name);
    }
    update_fallback_identity_text(&mut digest, "channelDisplay", &entry.channel_display);
    update_fallback_identity_text(&mut digest, "provider", &entry.provider);
    digest.update(b"eventId");
    digest.update(entry.event_id.to_le_bytes());
    let severity = match entry.severity {
        EventLogSeverity::Critical => "Critical",
        EventLogSeverity::Error => "Error",
        EventLogSeverity::Warning => "Warning",
        EventLogSeverity::Information => "Information",
        EventLogSeverity::Verbose => "Verbose",
        EventLogSeverity::Unknown => "Unknown",
    };
    update_fallback_identity_text(&mut digest, "severity", severity);
    update_fallback_identity_text(&mut digest, "source", &entry.source_file);
    update_fallback_identity_text(&mut digest, "timestamp", &entry.timestamp);
    digest.update(b"eventDataCount");
    digest.update((event_data.len() as u64).to_le_bytes());
    for (index, value) in event_data
        .iter()
        .take(MAX_FALLBACK_IDENTITY_FIELDS)
        .enumerate()
    {
        digest.update(b"eventDataIndex");
        digest.update((index as u64).to_le_bytes());
        update_fallback_identity_text(&mut digest, "eventData", value);
    }
    update_fallback_identity_text(
        &mut digest,
        "activityId",
        entry.correlation_activity_id.as_deref().unwrap_or_default(),
    );
    update_fallback_identity_text(&mut digest, "rawXml", raw_xml);
    digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
fn event_data_pairs(event_data: &[String], raw_xml: &str) -> Vec<(String, String)> {
    let mut pairs = event_data
        .iter()
        .filter_map(|field| {
            let field = field.trim();
            let (name, value) = field.split_once('=').or_else(|| field.split_once(':'))?;
            let name = name.trim();
            let value = value.trim();
            (!name.is_empty()).then(|| (name.to_string(), value.to_string()))
        })
        .collect::<Vec<_>>();
    if pairs.iter().any(|(name, _)| status_field(name)) || raw_xml.is_empty() {
        return pairs;
    }
    static XML_STATUS_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r#"(?is)<(?:data|field)\s+[^>]*name\s*=\s*["'](status|result|state|profilestatus|enrollmentstatus)["'][^>]*>\s*([^<]*)"#,
        )
        .expect("event status XML regex")
    });
    if let Some(captures) = XML_STATUS_RE.captures(raw_xml) {
        if let (Some(name), Some(value)) = (captures.get(1), captures.get(2)) {
            pairs.push((name.as_str().to_string(), value.as_str().trim().to_string()));
        }
    }
    pairs
}

fn status_field(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "status" | "result" | "state" | "profilestatus" | "enrollmentstatus" | "operationstatus"
    )
}

fn event_status(pairs: &[(String, String)]) -> Option<(String, String)> {
    pairs.iter().find(|(name, _)| status_field(name)).cloned()
}

fn status_matches(value: &str, markers: &[&str]) -> bool {
    let lower = value.trim().to_ascii_lowercase();
    markers.iter().any(|marker| {
        lower == *marker
            || lower.starts_with(&format!("{marker}:"))
            || lower.starts_with(&format!("{marker} "))
            || lower.contains(&format!(" {marker} "))
    })
}

fn failure_status(value: &str) -> bool {
    status_matches(
        value,
        &[
            "failed",
            "failure",
            "error",
            "denied",
            "blocked",
            "timeout",
            "timed out",
        ],
    )
}

fn success_status(value: &str) -> bool {
    status_matches(
        value,
        &[
            "success",
            "succeeded",
            "completed",
            "complete",
            "enrolled",
            "installed",
        ],
    )
}

fn pending_status(value: &str) -> bool {
    status_matches(
        value,
        &[
            "pending",
            "started",
            "running",
            "retry",
            "queued",
            "waiting",
            "in progress",
            "in-progress",
        ],
    )
}

fn nonzero_error_token(tokens: &[ErrorToken]) -> bool {
    tokens.iter().any(|token| {
        if token.malformed {
            return false;
        }
        token
            .decimal
            .map(|value| value != 0)
            .or_else(|| {
                token.hex.as_deref().and_then(|value| {
                    let digits = value
                        .strip_prefix("0x")
                        .or_else(|| value.strip_prefix("0X"))
                        .unwrap_or(value);
                    u128::from_str_radix(digits, 16)
                        .ok()
                        .map(|number| number != 0)
                })
            })
            .unwrap_or(false)
    })
}

fn event_data_detail(pairs: &[(String, String)]) -> String {
    pairs
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join(", ")
}

#[allow(clippy::too_many_arguments)]
fn rule_finding(
    evidence: &EvidenceRef,
    suffix: &str,
    class: FindingClass,
    severity: FindingSeverity,
    confidence: FindingConfidence,
    title: String,
    summary: String,
    recommended_checks: Vec<String>,
) -> DiagnosisFinding {
    DiagnosisFinding {
        finding_id: format!("{}:{suffix}", evidence.stable_id()),
        class,
        severity,
        confidence,
        title,
        summary,
        evidence: vec![evidence.clone()],
        coverage_gaps: Vec::new(),
        recommended_checks,
    }
}

fn rule_coverage_finding(
    evidence: &EvidenceRef,
    family: &str,
    suffix: &str,
    state: CoverageState,
    detail: String,
    recommended_check: String,
) -> DiagnosisFinding {
    let gap = CoverageGap {
        id: format!("{}:{suffix}", evidence.stable_id()),
        source: family.to_string(),
        state,
        detail: detail.clone(),
        evidence: vec![evidence.clone()],
    };
    DiagnosisFinding {
        finding_id: format!("{}:{suffix}", evidence.stable_id()),
        class: FindingClass::CoverageGap,
        severity: FindingSeverity::Info,
        confidence: FindingConfidence::Unknown,
        title: format!("{family} event evidence is incomplete"),
        summary: detail,
        evidence: vec![evidence.clone()],
        coverage_gaps: vec![gap],
        recommended_checks: vec![recommended_check],
    }
}

fn operational_event_finding(
    family: EventFamily,
    entry: &EventLogEntry,
    evidence: &EvidenceRef,
    pairs: &[(String, String)],
    errors: &[ErrorToken],
    explicit_failure_signal: bool,
    explicit_success_signal: bool,
) -> Option<DiagnosisFinding> {
    let status = event_status(pairs);
    let status_value = status.as_ref().map(|(_, value)| value.as_str());
    let status_failure = status_value.is_some_and(failure_status);
    let status_success = status_value.is_some_and(success_status);
    let status_pending = status_value.is_some_and(pending_status);
    let status_unknown = status_value.is_some_and(|value| {
        !failure_status(value) && !success_status(value) && !pending_status(value)
    });
    let nonzero_error = nonzero_error_token(errors);
    let detail = event_data_detail(pairs);
    let message = if detail.is_empty() {
        entry.message.clone()
    } else {
        format!("{} ({detail})", entry.message)
    };
    let label = family_label(family);
    if status_failure && explicit_success_signal {
        return Some(rule_finding(
            evidence,
            "status-contradiction",
            FindingClass::ContradictoryEvidence,
            event_severity(entry.severity),
            FindingConfidence::Medium,
            format!("{label} status is contradictory"),
            message.clone(),
            vec!["Inspect the provider XML for the authoritative terminal status.".to_string()],
        ));
    }
    if status.is_none() && explicit_failure_signal && explicit_success_signal {
        return Some(rule_finding(
            evidence,
            "status-contradiction",
            FindingClass::ContradictoryEvidence,
            event_severity(entry.severity),
            FindingConfidence::Medium,
            format!("{label} status is contradictory"),
            message.clone(),
            vec!["Inspect the provider XML for the authoritative terminal status.".to_string()],
        ));
    }
    match family {
        EventFamily::Autopilot => {
            if status_failure
                || (status.is_none() && explicit_failure_signal && !explicit_success_signal)
            {
                return Some(rule_finding(
                    evidence,
                    "autopilot-profile-failure",
                    FindingClass::ConfirmedFailure,
                    event_severity(entry.severity),
                    if status_failure {
                        FindingConfidence::High
                    } else {
                        FindingConfidence::Medium
                    },
                    "Autopilot profile operation failed".to_string(),
                    message,
                    vec![
                        "Inspect the Autopilot profile assignment and the associated error code."
                            .to_string(),
                        "Compare adjacent Autopilot and ESP records for the same activity."
                            .to_string(),
                    ],
                ));
            }
            if status_success && (nonzero_error || explicit_failure_signal) {
                return Some(rule_finding(
                    evidence,
                    "autopilot-profile-contradiction",
                    FindingClass::ContradictoryEvidence,
                    event_severity(entry.severity),
                    FindingConfidence::Medium,
                    "Autopilot profile status is contradictory".to_string(),
                    message,
                    vec![
                        "Inspect the provider XML for the authoritative terminal status."
                            .to_string(),
                    ],
                ));
            }
            if status_pending {
                return Some(rule_finding(
                    evidence,
                    "autopilot-profile-pending",
                    FindingClass::Symptom,
                    FindingSeverity::Info,
                    FindingConfidence::Medium,
                    "Autopilot profile operation is still in progress".to_string(),
                    message,
                    vec![
                        "Collect the later terminal Autopilot event before concluding success."
                            .to_string(),
                    ],
                ));
            }
            if status.is_none() || status_unknown {
                return Some(rule_coverage_finding(
                    evidence,
                    label,
                    "autopilot-profile-status",
                    if status_unknown {
                        CoverageState::Malformed
                    } else {
                        CoverageState::Absent
                    },
                    if status_unknown {
                        format!(
                            "Autopilot status `{}` is not a recognized terminal or pending value.",
                            status_value.unwrap_or_default()
                        )
                    } else {
                        "Autopilot event did not include a profile status.".to_string()
                    },
                    "Collect the provider EventData or a later terminal Autopilot record."
                        .to_string(),
                ));
            }
        }
        EventFamily::Esp => {
            if status_failure
                || (status.is_none() && explicit_failure_signal && !explicit_success_signal)
            {
                return Some(rule_finding(
                    evidence,
                    "esp-status-failure",
                    FindingClass::ConfirmedFailure,
                    event_severity(entry.severity),
                    if status_failure {
                        FindingConfidence::High
                    } else {
                        FindingConfidence::Medium
                    },
                    "ESP provisioning status reports failure".to_string(),
                    message,
                    vec![
                        "Inspect the ESP phase and workload named by EventData.".to_string(),
                        "Compare the matching MDM enrollment and IME records.".to_string(),
                    ],
                ));
            }
            if status_success && (nonzero_error || explicit_failure_signal) {
                return Some(rule_finding(
                    evidence,
                    "esp-status-contradiction",
                    FindingClass::ContradictoryEvidence,
                    event_severity(entry.severity),
                    FindingConfidence::Medium,
                    "ESP status is contradictory".to_string(),
                    message,
                    vec!["Inspect the ESP provider XML and adjacent phase records.".to_string()],
                ));
            }
            if status_pending {
                return Some(rule_finding(
                    evidence,
                    "esp-status-pending",
                    FindingClass::Symptom,
                    FindingSeverity::Info,
                    FindingConfidence::Medium,
                    "ESP provisioning remains pending".to_string(),
                    message,
                    vec![
                        "Collect the terminal ESP event before concluding the phase outcome."
                            .to_string(),
                    ],
                ));
            }
            if status.is_none() || status_unknown {
                return Some(rule_coverage_finding(
                    evidence,
                    label,
                    "esp-status",
                    if status_unknown {
                        CoverageState::Malformed
                    } else {
                        CoverageState::Absent
                    },
                    if status_unknown {
                        format!(
                            "ESP status `{}` is not a recognized terminal or pending value.",
                            status_value.unwrap_or_default()
                        )
                    } else {
                        "ESP event did not include a phase status.".to_string()
                    },
                    "Collect the ESP provider EventData and the matching phase records."
                        .to_string(),
                ));
            }
        }
        EventFamily::MdmEnrollment => {
            if status_failure
                || (status.is_none() && explicit_failure_signal && !explicit_success_signal)
            {
                return Some(rule_finding(
                    evidence,
                    "mdm-enrollment-failure",
                    FindingClass::ConfirmedFailure,
                    event_severity(entry.severity),
                    if status_failure {
                        FindingConfidence::High
                    } else {
                        FindingConfidence::Medium
                    },
                    "MDM enrollment status reports failure".to_string(),
                    message,
                    vec![
                        "Inspect the enrollment provider error fields and HRESULT.".to_string(),
                        "Compare the enrollment record with the corresponding IME and ESP evidence."
                            .to_string(),
                    ],
                ));
            }
            if status_success && (nonzero_error || explicit_failure_signal) {
                return Some(rule_finding(
                    evidence,
                    "mdm-enrollment-contradiction",
                    FindingClass::ContradictoryEvidence,
                    event_severity(entry.severity),
                    FindingConfidence::Medium,
                    "MDM enrollment status is contradictory".to_string(),
                    message,
                    vec![
                        "Inspect the provider XML for the authoritative enrollment result."
                            .to_string(),
                    ],
                ));
            }
            if status_pending {
                return Some(rule_finding(
                    evidence,
                    "mdm-enrollment-pending",
                    FindingClass::Symptom,
                    FindingSeverity::Info,
                    FindingConfidence::Medium,
                    "MDM enrollment remains pending".to_string(),
                    message,
                    vec!["Collect a later enrollment terminal event.".to_string()],
                ));
            }
            if status.is_none() {
                return Some(rule_coverage_finding(
                    evidence,
                    label,
                    "mdm-enrollment-status",
                    CoverageState::Absent,
                    "MDM enrollment event did not include a status.".to_string(),
                    "Collect the provider EventData or a later terminal enrollment record."
                        .to_string(),
                ));
            }
            if status_unknown {
                return Some(rule_coverage_finding(
                    evidence,
                    label,
                    "mdm-enrollment-status",
                    CoverageState::Malformed,
                    format!(
                        "MDM enrollment status `{}` is not recognized.",
                        status_value.unwrap_or_default()
                    ),
                    "Inspect the provider template and preserve the raw status value.".to_string(),
                ));
            }
        }
        EventFamily::ConfigMgrClient => {
            if status_failure
                || (status.is_none() && explicit_failure_signal && !explicit_success_signal)
            {
                return Some(rule_finding(
                    evidence,
                    "configmgr-component-failure",
                    FindingClass::ConfirmedFailure,
                    event_severity(entry.severity),
                    if status_failure {
                        FindingConfidence::High
                    } else {
                        FindingConfidence::Medium
                    },
                    "ConfigMgr client component reports failure".to_string(),
                    message,
                    vec![
                        "Inspect the named ConfigMgr component and its client log.".to_string(),
                        "Check whether the same component later reports recovery.".to_string(),
                    ],
                ));
            }
            if status_success && (nonzero_error || explicit_failure_signal) {
                return Some(rule_finding(
                    evidence,
                    "configmgr-component-contradiction",
                    FindingClass::ContradictoryEvidence,
                    event_severity(entry.severity),
                    FindingConfidence::Medium,
                    "ConfigMgr client component status is contradictory".to_string(),
                    message,
                    vec![
                        "Inspect the component event XML and adjacent client records.".to_string(),
                    ],
                ));
            }
            if status_pending {
                return Some(rule_finding(
                    evidence,
                    "configmgr-component-pending",
                    FindingClass::Symptom,
                    FindingSeverity::Info,
                    FindingConfidence::Medium,
                    "ConfigMgr client component remains pending".to_string(),
                    message,
                    vec![
                        "Collect a terminal component result before concluding health.".to_string(),
                    ],
                ));
            }
            if status.is_none() {
                return Some(rule_coverage_finding(
                    evidence,
                    label,
                    "configmgr-component-status",
                    CoverageState::Absent,
                    "ConfigMgr client event did not include a component result.".to_string(),
                    "Collect the component result field or a later terminal client record."
                        .to_string(),
                ));
            }
            if status_unknown {
                return Some(rule_coverage_finding(
                    evidence,
                    label,
                    "configmgr-component-status",
                    CoverageState::Malformed,
                    format!(
                        "ConfigMgr component status `{}` is not recognized.",
                        status_value.unwrap_or_default()
                    ),
                    "Inspect the provider template and preserve the raw result value.".to_string(),
                ));
            }
        }
        EventFamily::Other => {}
    }
    None
}

/// Adapts the parser's normalized event model and applies the four operational event-family rules.
pub fn adapt_event_entry(entry: EventLogEntry) -> EventDiagnosis {
    adapt_event_entry_with_data_and_raw_xml(entry, &[], "")
}

/// Adapts a normalized event while retaining provider EventData values for token enrichment.
pub fn adapt_event_entry_with_data(entry: EventLogEntry, event_data: &[String]) -> EventDiagnosis {
    adapt_event_entry_with_data_and_raw_xml(entry, event_data, "")
}

fn redact_diagnostic_xml(value: &str) -> String {
    const SENSITIVE_FIELDS: &str = concat!(
        "Password|Pwd|Passphrase|LicenseKey|License_Key|ProductKey|Product_Key|",
        "SerialKey|Serial|ApiKey|Api_Key|ApiSecret|Api_Secret|AccessToken|",
        "Access_Token|Token|Secret|ClientSecret|Client_Secret|Credential|",
        "Credentials|CredentialData|Authorization|AADTenantId|TenantId|DeviceId|",
        "HardwareHash|UserName|UserId|UserPrincipalName|RunAsUser|RunAsAccount|",
        "ComputerName|MachineName|HostName|DeviceName|RemoteHost"
    );
    static SENSITIVE_ELEMENT_SELF_CLOSING_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(&format!(
            r#"(?is)<(?P<tag>(?:{SENSITIVE_FIELDS}))\b[^>]*/>"#
        ))
        .expect("diagnosis self-closing sensitive XML element regex")
    });
    static SENSITIVE_ELEMENT_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(&format!(
            r#"(?is)(<(?:{SENSITIVE_FIELDS})\b[^>]*>).*?(</[^>]+>)"#
        ))
        .expect("diagnosis sensitive XML element regex")
    });
    static SENSITIVE_ELEMENT_OPEN_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(&format!(r#"(?is)<(?P<tag>(?:{SENSITIVE_FIELDS}))\b[^>]*>"#))
            .expect("diagnosis sensitive XML opening element regex")
    });
    static SENSITIVE_NAMED_ELEMENT_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(&format!(
            r#"(?is)(<[^>]+\b(?:name|key|id)\s*=\s*["'](?:{SENSITIVE_FIELDS})["'][^>]*>).*?(</[^>]+>)"#
        ))
        .expect("diagnosis named XML element regex")
    });
    static SENSITIVE_NAMED_ELEMENT_OPEN_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(&format!(
            r#"(?is)<(?P<tag>[A-Za-z_][A-Za-z0-9_.:-]*)\b[^>]*\b(?:name|key|id)\s*=\s*["'](?:{SENSITIVE_FIELDS})["'][^>]*>"#
        ))
        .expect("diagnosis named sensitive XML opening element regex")
    });
    static SENSITIVE_ATTRIBUTE_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(&format!(
            r#"(?is)<(?P<tag>[A-Za-z_][A-Za-z0-9_.:-]*)\b[^>]*\b(?:name|key|id)\s*=\s*["'](?:{SENSITIVE_FIELDS})["'][^>]*/>"#
        ))
        .expect("diagnosis sensitive XML attribute regex")
    });
    let masked = SENSITIVE_ELEMENT_SELF_CLOSING_RE
        .replace_all(value, "<${tag}>[redacted]</${tag}>")
        .into_owned();
    let masked = SENSITIVE_ATTRIBUTE_RE
        .replace_all(&masked, "<${tag}>[redacted]</${tag}>")
        .into_owned();
    let masked = SENSITIVE_ELEMENT_RE
        .replace_all(&masked, "$1[redacted]$2")
        .into_owned();
    let masked = SENSITIVE_ELEMENT_OPEN_RE
        .replace_all(&masked, "<${tag}>")
        .into_owned();
    let masked = SENSITIVE_NAMED_ELEMENT_RE
        .replace_all(&masked, "$1[redacted]$2")
        .into_owned();
    let masked = SENSITIVE_NAMED_ELEMENT_OPEN_RE
        .replace_all(&masked, "<${tag}>")
        .into_owned();
    redact_text(&masked)
}

/// Adapts an event while scanning both normalized fields and the provider's raw XML for error
/// tokens. Raw XML is used only for lossless token enrichment; failure classification remains based
/// on the normalized message and EventData values.
pub fn adapt_event_entry_with_data_and_raw_xml(
    entry: EventLogEntry,
    event_data: &[String],
    raw_xml: &str,
) -> EventDiagnosis {
    let family = event_family(&entry);
    let evidence = EvidenceRef::Event(EventEvidenceRef {
        source: entry.source_file.clone(),
        provider: entry.provider.clone(),
        event_id: entry.event_id,
        record_id: entry.id,
        record_id_text: (entry.id != 0).then(|| entry.id.to_string()),
        fallback_identity: (entry.id == 0)
            .then(|| event_fallback_identity(&entry, event_data, raw_xml)),
        machine: entry.computer.clone(),
        channel: Some(entry.channel_display.clone()),
        activity_id: entry.correlation_activity_id.clone(),
    });
    let evidence_id = evidence.stable_id();
    let mut diagnostic_text = entry.message.clone();
    for value in event_data {
        diagnostic_text.push(' ');
        diagnostic_text.push_str(value);
    }
    let mut token_text = redact_text(&diagnostic_text);
    if !raw_xml.is_empty() {
        token_text.push(' ');
        token_text.push_str(&redact_diagnostic_xml(raw_xml));
    }
    let errors = enrich_error_tokens(&token_text);
    let pairs = event_data_pairs(event_data, raw_xml);
    let explicit_failure_signal = explicit_failure(&diagnostic_text);
    let explicit_success_signal = explicit_success(&diagnostic_text);
    let status_success = event_status(&pairs)
        .as_ref()
        .is_some_and(|(_, value)| success_status(value));
    let failure = explicit_failure_signal
        || (matches!(
            entry.severity,
            EventLogSeverity::Critical | EventLogSeverity::Error
        ) && !status_success);
    let contradictory = failure && explicit_success_signal;
    let mut findings = Vec::new();
    let operational = operational_event_finding(
        family,
        &entry,
        &evidence,
        &pairs,
        &errors,
        explicit_failure_signal,
        explicit_success_signal,
    );
    if let Some(finding) = operational {
        findings.push(finding);
    } else if matches!(family, EventFamily::Other) {
        findings.push(rule_coverage_finding(
            &evidence,
            "event",
            "unsupported-event-family",
            CoverageState::Unsupported,
            "Event source is outside the supported device-management diagnosis families."
                .to_string(),
            "Inspect a supported Autopilot, ESP, MDM, or ConfigMgr source for an operational rule."
                .to_string(),
        ));
    } else if contradictory {
        findings.push(DiagnosisFinding {
            finding_id: format!("{evidence_id}:contradictory"),
            class: FindingClass::ContradictoryEvidence,
            severity: event_severity(entry.severity),
            confidence: FindingConfidence::Medium,
            title: format!("{} event contains contradictory status signals", family_label(family)),
            summary: "The same event contains both success and failure language; no terminal outcome is asserted.".to_string(),
            evidence: vec![evidence.clone()],
            coverage_gaps: Vec::new(),
            recommended_checks: vec!["Inspect the provider XML and adjacent records for the authoritative terminal state.".to_string()],
        });
    } else if failure && !status_success {
        let confidence = if explicit_failure_signal {
            FindingConfidence::High
        } else {
            FindingConfidence::Medium
        };
        findings.push(DiagnosisFinding {
            finding_id: format!("{evidence_id}:failure"),
            class: FindingClass::ConfirmedFailure,
            severity: event_severity(entry.severity),
            confidence,
            title: format!("{} event reports a failure", family_label(family)),
            summary: entry.message.clone(),
            evidence: vec![evidence.clone()],
            coverage_gaps: Vec::new(),
            recommended_checks: vec![format!(
                "Inspect the {} source record and its provider-specific error details.",
                family_label(family)
            )],
        });
    } else if matches!(entry.severity, EventLogSeverity::Warning) {
        findings.push(DiagnosisFinding {
            finding_id: format!("{evidence_id}:symptom"),
            class: FindingClass::Symptom,
            severity: FindingSeverity::Warning,
            confidence: FindingConfidence::Medium,
            title: format!("{} event is a warning", family_label(family)),
            summary: entry.message.clone(),
            evidence: vec![evidence.clone()],
            coverage_gaps: Vec::new(),
            recommended_checks: vec![
                "Compare this warning with the surrounding timeline and source coverage."
                    .to_string(),
            ],
        });
    }
    EventDiagnosis {
        evidence: vec![evidence],
        family,
        findings,
        error_tokens: errors,
    }
}
/// Adapts an existing normalized text-log entry without asserting that neutral lines are failures.
pub fn adapt_log_entry(entry: LogEntry) -> Option<DiagnosisFinding> {
    let evidence = EvidenceRef::from_text_log(TextLogEvidenceRef {
        source: entry
            .source_file
            .clone()
            .unwrap_or_else(|| entry.file_path.clone()),
        file_path: entry.file_path.clone(),
        line_number: entry.line_number,
        entry_id: entry.id,
    });
    let mut diagnostic_text = entry.message.clone();
    for value in [entry.result_code.as_deref(), entry.gle_code.as_deref()]
        .into_iter()
        .flatten()
    {
        diagnostic_text.push(' ');
        diagnostic_text.push_str(value);
    }
    let explicit = explicit_failure(&diagnostic_text);
    let failure = explicit || matches!(entry.severity, Severity::Error);
    let warning = matches!(entry.severity, Severity::Warning);
    if !failure && !warning {
        return None;
    }
    let class = if failure {
        FindingClass::ConfirmedFailure
    } else {
        FindingClass::Symptom
    };
    let severity = match entry.severity {
        Severity::Error => FindingSeverity::Error,
        Severity::Warning => FindingSeverity::Warning,
        Severity::Success | Severity::Info if explicit => FindingSeverity::Error,
        Severity::Success | Severity::Info => FindingSeverity::Info,
    };
    Some(DiagnosisFinding {
        finding_id: format!("{}:{class:?}", evidence.stable_id()),
        class,
        severity,
        confidence: if explicit {
            FindingConfidence::High
        } else {
            FindingConfidence::Medium
        },
        title: if failure {
            "Text log reports a failure".to_string()
        } else {
            "Text log contains a warning".to_string()
        },
        summary: entry.message,
        evidence: vec![evidence],
        coverage_gaps: Vec::new(),
        recommended_checks: vec![
            "Inspect the source log entry and adjacent records for the terminal operation state."
                .to_string(),
        ],
    })
}

fn map_intune_severity(value: IntuneFindingSeverity) -> FindingSeverity {
    match value {
        IntuneFindingSeverity::Info => FindingSeverity::Info,
        IntuneFindingSeverity::Warning => FindingSeverity::Warning,
        IntuneFindingSeverity::Error => FindingSeverity::Error,
        IntuneFindingSeverity::Blocker => FindingSeverity::Critical,
    }
}

fn map_intune_confidence(value: IntuneFindingConfidence) -> FindingConfidence {
    match value {
        IntuneFindingConfidence::Low => FindingConfidence::Low,
        IntuneFindingConfidence::Medium => FindingConfidence::Medium,
        IntuneFindingConfidence::High => FindingConfidence::High,
    }
}

/// Adapts an Intune finding as a `LikelyContributor`; it preserves source assertions without adding new semantics.
pub fn adapt_intune_finding(value: &IntuneFinding) -> DiagnosisFinding {
    DiagnosisFinding {
        finding_id: value.finding_id.clone(),
        class: FindingClass::LikelyContributor,
        severity: map_intune_severity(value.severity.clone()),
        confidence: map_intune_confidence(value.confidence.clone()),
        title: value.title.clone(),
        summary: value.summary.clone(),
        evidence: value
            .evidence
            .iter()
            .cloned()
            .map(EvidenceRef::Intune)
            .collect(),
        coverage_gaps: value
            .coverage_gap_ids
            .iter()
            .map(|id| CoverageGap {
                id: id.clone(),
                source: "intune".to_string(),
                state: CoverageState::Unknown,
                detail:
                    "Intune finding cites an incomplete artifact; capture state was not supplied."
                        .to_string(),
                evidence: Vec::new(),
            })
            .collect(),
        recommended_checks: value.recommended_checks.clone(),
    }
}

fn map_esp_severity(value: EspFindingSeverity) -> FindingSeverity {
    match value {
        EspFindingSeverity::Info => FindingSeverity::Info,
        EspFindingSeverity::Warning => FindingSeverity::Warning,
        EspFindingSeverity::Error => FindingSeverity::Error,
        EspFindingSeverity::Blocker => FindingSeverity::Critical,
    }
}

fn map_esp_confidence(value: EspFindingConfidence) -> FindingConfidence {
    match value {
        EspFindingConfidence::Low => FindingConfidence::Low,
        EspFindingConfidence::Medium => FindingConfidence::Medium,
        EspFindingConfidence::High => FindingConfidence::High,
    }
}

/// Adapts an ESP finding as a `LikelyContributor`; it preserves source assertions without adding new semantics.
pub fn adapt_esp_finding(value: &EspDiagnosticFinding) -> DiagnosisFinding {
    DiagnosisFinding {
        finding_id: value.finding_id.clone(),
        class: FindingClass::LikelyContributor,
        severity: map_esp_severity(value.severity.clone()),
        confidence: map_esp_confidence(value.confidence.clone()),
        title: value.title.clone(),
        summary: value.summary.clone(),
        evidence: value
            .evidence
            .iter()
            .cloned()
            .map(EvidenceRef::Esp)
            .collect(),
        coverage_gaps: value
            .coverage_gap_ids
            .iter()
            .map(|id| CoverageGap {
                id: id.clone(),
                source: "esp".to_string(),
                state: CoverageState::Unknown,
                detail: "ESP finding cites an incomplete artifact; capture state was not supplied."
                    .to_string(),
                evidence: Vec::new(),
            })
            .collect(),
        recommended_checks: value.recommended_checks.clone(),
    }
}

fn map_sccm_class(value: SccmFindingClass) -> FindingClass {
    match value {
        SccmFindingClass::ConfirmedFailure => FindingClass::ConfirmedFailure,
        SccmFindingClass::LikelyContributor => FindingClass::LikelyContributor,
        SccmFindingClass::Symptom => FindingClass::Symptom,
        SccmFindingClass::ContradictoryEvidence => FindingClass::ContradictoryEvidence,
        SccmFindingClass::BlockedOrDeferred | SccmFindingClass::InsufficientEvidence => {
            FindingClass::CoverageGap
        }
        SccmFindingClass::Recovered => FindingClass::Recovered,
    }
}

fn map_sccm_severity(value: Severity) -> FindingSeverity {
    match value {
        Severity::Success | Severity::Info => FindingSeverity::Info,
        Severity::Warning => FindingSeverity::Warning,
        Severity::Error => FindingSeverity::Error,
    }
}

fn map_sccm_confidence(value: SccmConfidence) -> FindingConfidence {
    match value {
        SccmConfidence::None => FindingConfidence::Unknown,
        SccmConfidence::Low => FindingConfidence::Low,
        SccmConfidence::Moderate => FindingConfidence::Medium,
        SccmConfidence::High => FindingConfidence::High,
    }
}

/// Adapts an SCCM finding while preserving its source classification without adding new semantics.
pub fn adapt_sccm_finding(value: &SccmFinding) -> DiagnosisFinding {
    let mut evidence: Vec<EvidenceRef> = value
        .evidence
        .iter()
        .cloned()
        .map(EvidenceRef::Sccm)
        .collect();
    evidence.extend(
        value
            .terminal_evidence
            .iter()
            .map(|terminal| EvidenceRef::Sccm(terminal.reference.clone())),
    );
    DiagnosisFinding {
        finding_id: value.finding_id.clone(),
        class: map_sccm_class(value.class.clone()),
        severity: map_sccm_severity(value.severity),
        confidence: map_sccm_confidence(value.confidence),
        title: value.title.clone(),
        summary: value.summary.clone(),
        evidence,
        coverage_gaps: value
            .coverage_gaps
            .iter()
            .map(|gap| CoverageGap {
                id: gap.artifact_id.clone(),
                source: gap.artifact_id.clone(),
                state: match gap.coverage {
                    crate::sccm::SccmCoverageState::Captured => CoverageState::Covered,
                    crate::sccm::SccmCoverageState::Absent => CoverageState::Absent,
                    crate::sccm::SccmCoverageState::AccessDenied => CoverageState::AccessDenied,
                    crate::sccm::SccmCoverageState::Capped => CoverageState::Capped,
                    crate::sccm::SccmCoverageState::Skipped => CoverageState::Skipped,
                    crate::sccm::SccmCoverageState::Unsupported => CoverageState::Unsupported,
                    crate::sccm::SccmCoverageState::ParseFailed => CoverageState::ParseFailed,
                },
                detail: "SCCM source coverage is incomplete.".to_string(),
                evidence: Vec::new(),
            })
            .collect(),
        recommended_checks: value
            .next_artifacts
            .iter()
            .map(|request| request.reason.clone())
            .collect(),
    }
}

/// Adapts a dsregcmd insight as a `LikelyContributor`; it preserves the insight without adding new semantics.
pub fn adapt_dsregcmd_insight(
    value: &crate::dsregcmd::DsregcmdDiagnosticInsight,
) -> DiagnosisFinding {
    DiagnosisFinding {
        finding_id: value.id.clone(),
        class: FindingClass::LikelyContributor,
        severity: match value.severity.clone() {
            crate::intune::models::IntuneDiagnosticSeverity::Info => FindingSeverity::Info,
            crate::intune::models::IntuneDiagnosticSeverity::Warning => FindingSeverity::Warning,
            crate::intune::models::IntuneDiagnosticSeverity::Error => FindingSeverity::Error,
        },
        confidence: FindingConfidence::Medium,
        title: value.title.clone(),
        summary: value.summary.clone(),
        evidence: value
            .evidence
            .iter()
            .cloned()
            .map(EvidenceRef::DsregcmdRaw)
            .collect(),
        coverage_gaps: Vec::new(),
        recommended_checks: value.next_checks.clone(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum CorrelationBasis {
    ExactIdentifier,
    CandidateIdentifier,
    TimestampOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum CorrelationStatus {
    Exact,
    Candidate,
    Ambiguous,
    CoverageBlocked,
    NotCausal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CorrelationEvidence {
    pub origin_id: String,
    pub field: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CorrelationEdge {
    pub left: String,
    pub right: Option<String>,
    pub basis: CorrelationBasis,
    pub status: CorrelationStatus,
    #[serde(default)]
    pub candidate_ids: Vec<String>,
    #[serde(default)]
    pub evidence: Vec<CorrelationEvidence>,
}

/// Converts the unified timeline's exact-first edge into the diagnosis edge contract.
pub fn adapt_timeline_edge(
    value: &crate::unified_timeline::TimelineCorrelationEdge,
) -> CorrelationEdge {
    let basis = match &value.key.kind {
        crate::unified_timeline::TimelineCorrelationKeyKind::Secondary => {
            CorrelationBasis::CandidateIdentifier
        }
        _ => CorrelationBasis::ExactIdentifier,
    };
    let status = match value.strength {
        crate::unified_timeline::TimelineCorrelationStrength::Exact => CorrelationStatus::Exact,
        crate::unified_timeline::TimelineCorrelationStrength::Candidate => {
            CorrelationStatus::Candidate
        }
        crate::unified_timeline::TimelineCorrelationStrength::Ambiguous => {
            CorrelationStatus::Ambiguous
        }
    };
    CorrelationEdge {
        left: value.from_id.clone(),
        right: value.to_id.clone(),
        basis,
        status: if matches!(
            &value.coverage.state,
            crate::unified_timeline::TimelineCorrelationCoverageState::Gap
        ) {
            CorrelationStatus::CoverageBlocked
        } else {
            status
        },
        candidate_ids: value.candidate_ids.clone(),
        evidence: value
            .evidence
            .iter()
            .map(|item| CorrelationEvidence {
                origin_id: item.origin_id.clone(),
                field: item.field.clone(),
                value: item.value.clone(),
            })
            .collect(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosisOverview {
    /// Stable, non-causal outcome selected from finding precedence.
    pub outcome: String,
    pub headline: String,
    pub finding_count: usize,
    pub coverage_gap_count: usize,
    pub evidence_count: usize,
    pub correlation_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosisSummary {
    pub findings: Vec<DiagnosisFinding>,
    pub evidence: Vec<EvidenceRef>,
    pub coverage_gaps: Vec<CoverageGap>,
    pub correlations: Vec<CorrelationEdge>,
    pub events: Vec<EventDiagnosis>,
    pub overview: DiagnosisOverview,
}

fn redact_identifier(value: &str, machines: &BTreeMap<String, String>) -> String {
    let mut redacted = redact_diagnostic_xml(value);
    let mut ordered = machines.iter().collect::<Vec<_>>();
    ordered.sort_by(|left, right| {
        right
            .0
            .len()
            .cmp(&left.0.len())
            .then_with(|| left.0.cmp(right.0))
    });
    for (machine, replacement) in ordered {
        redacted = redacted.replace(machine, replacement);
    }
    redacted
}

fn redact_evidence(reference: &mut EvidenceRef, machines: &BTreeMap<String, String>) {
    match reference {
        EvidenceRef::Intune(value) => {
            value.source_artifact_id = redact_identifier(&value.source_artifact_id, machines);
            value.evidence_id = redact_identifier(&value.evidence_id, machines);
        }
        EvidenceRef::Esp(value) => {
            value.source_artifact_id = redact_identifier(&value.source_artifact_id, machines);
            value.evidence_id = redact_identifier(&value.evidence_id, machines);
        }
        EvidenceRef::Sccm(value) => {
            value.artifact_id = redact_identifier(&value.artifact_id, machines);
            value.entry_id = redact_identifier(&value.entry_id, machines);
        }
        EvidenceRef::DsregcmdRaw(value) => *value = redact_identifier(value, machines),
        EvidenceRef::TextLog(value) => {
            value.source = redact_identifier(&value.source, machines);
            value.file_path = redact_identifier(&value.file_path, machines);
        }
        EvidenceRef::Event(value) => {
            value.source = redact_identifier(&value.source, machines);
            value.provider = redact_identifier(&value.provider, machines);
            value.record_id_text = value
                .record_id_text
                .as_deref()
                .map(|value| redact_identifier(value, machines));
            value.fallback_identity = value
                .fallback_identity
                .as_deref()
                .map(|value| redact_identifier(value, machines));
            value.machine = value.machine.as_deref().map(|machine| {
                machines
                    .get(machine)
                    .cloned()
                    .unwrap_or_else(|| redact_labeled_value("ComputerName", machine))
            });
            value.channel = value
                .channel
                .as_deref()
                .map(|value| redact_identifier(value, machines));
            value.activity_id = value
                .activity_id
                .as_deref()
                .map(|value| redact_identifier(value, machines));
        }
    }
}

fn collect_machines_from_evidence(
    reference: &EvidenceRef,
    machines: &mut BTreeMap<String, String>,
) {
    if let EvidenceRef::Event(value) = reference {
        if let Some(machine) = value.machine.as_deref() {
            let (label, value) = machine.split_once('=').unwrap_or(("ComputerName", machine));
            let replacement = redact_labeled_value(label, value);
            machines
                .entry(machine.to_owned())
                .or_insert_with(|| replacement.clone());
            if machine.contains('=') && !value.is_empty() {
                let prefix = format!("{label}=");
                let value_replacement = replacement
                    .strip_prefix(&prefix)
                    .unwrap_or(&replacement)
                    .to_owned();
                machines
                    .entry(value.to_owned())
                    .or_insert(value_replacement);
            }
        }
    }
}

fn collect_machines_from_gap(gap: &CoverageGap, machines: &mut BTreeMap<String, String>) {
    for evidence in &gap.evidence {
        collect_machines_from_evidence(evidence, machines);
    }
}

fn collect_machines_from_finding(
    finding: &DiagnosisFinding,
    machines: &mut BTreeMap<String, String>,
) {
    for evidence in &finding.evidence {
        collect_machines_from_evidence(evidence, machines);
    }
    for gap in &finding.coverage_gaps {
        collect_machines_from_gap(gap, machines);
    }
}

fn redact_coverage_gap(gap: &mut CoverageGap, machines: &BTreeMap<String, String>) {
    gap.id = redact_identifier(&gap.id, machines);
    gap.source = redact_identifier(&gap.source, machines);
    gap.detail = redact_identifier(&gap.detail, machines);
    for evidence in &mut gap.evidence {
        redact_evidence(evidence, machines);
    }
}

fn redact_finding(finding: &mut DiagnosisFinding, machines: &BTreeMap<String, String>) {
    finding.finding_id = redact_identifier(&finding.finding_id, machines);
    finding.title = redact_identifier(&finding.title, machines);
    finding.summary = redact_identifier(&finding.summary, machines);
    finding.recommended_checks = finding
        .recommended_checks
        .iter()
        .map(|check| redact_identifier(check, machines))
        .collect();
    for evidence in &mut finding.evidence {
        redact_evidence(evidence, machines);
    }
    for gap in &mut finding.coverage_gaps {
        redact_coverage_gap(gap, machines);
    }
}

fn redact_error_token(token: &mut ErrorToken, machines: &BTreeMap<String, String>) {
    token.raw = redact_identifier(&token.raw, machines);
    token.hex = token
        .hex
        .as_deref()
        .map(|value| redact_identifier(value, machines));
    token.description = token
        .description
        .as_deref()
        .map(|value| redact_identifier(value, machines));
    token.category = token
        .category
        .as_deref()
        .map(|value| redact_identifier(value, machines));
}

fn redact_correlation(edge: &mut CorrelationEdge, machines: &BTreeMap<String, String>) {
    edge.left = redact_identifier(&edge.left, machines);
    edge.right = edge
        .right
        .as_deref()
        .map(|value| redact_identifier(value, machines));
    edge.candidate_ids = edge
        .candidate_ids
        .iter()
        .map(|candidate| redact_identifier(candidate, machines))
        .collect();
    for evidence in &mut edge.evidence {
        evidence.origin_id = redact_identifier(&evidence.origin_id, machines);
        evidence.field = redact_identifier(&evidence.field, machines);
        let field_label = match evidence.field.to_ascii_lowercase().as_str() {
            "deviceid" => Some("DeviceId"),
            "userid" => Some("UserId"),
            "sessionid" => Some("SessionId"),
            "activityid" => Some("ActivityId"),
            "relatedactivityid" => Some("RelatedActivityId"),
            "computer" | "computername" | "machine" | "machinename" => Some("ComputerName"),
            "username" => Some("UserName"),
            "userprincipalname" => Some("UserPrincipalName"),
            _ => None,
        };
        let value = redact_identifier(&evidence.value, machines);
        evidence.value = field_label
            .map(|label| redact_labeled_value(label, &value))
            .unwrap_or(value);
    }
}

/// Projects diagnosis into a safe display/IPC representation.
///
/// Rule evaluation receives the original bounded records so error tokens and
/// identity conclusions remain lossless. Only strings in the returned
/// presentation graph are redacted, including derived identifiers, so source
/// paths and identity-bearing text cannot bypass the UI boundary.
pub fn redacted_display_projection(mut summary: DiagnosisSummary) -> DiagnosisSummary {
    let mut machines = BTreeMap::new();
    for evidence in &summary.evidence {
        collect_machines_from_evidence(evidence, &mut machines);
    }
    for gap in &summary.coverage_gaps {
        collect_machines_from_gap(gap, &mut machines);
    }
    for finding in &summary.findings {
        collect_machines_from_finding(finding, &mut machines);
    }
    for event in &summary.events {
        for evidence in &event.evidence {
            collect_machines_from_evidence(evidence, &mut machines);
        }
        for finding in &event.findings {
            collect_machines_from_finding(finding, &mut machines);
        }
    }

    for finding in &mut summary.findings {
        redact_finding(finding, &machines);
    }
    for evidence in &mut summary.evidence {
        redact_evidence(evidence, &machines);
    }
    for gap in &mut summary.coverage_gaps {
        redact_coverage_gap(gap, &machines);
    }
    for edge in &mut summary.correlations {
        redact_correlation(edge, &machines);
    }
    for event in &mut summary.events {
        for evidence in &mut event.evidence {
            redact_evidence(evidence, &machines);
        }
        for finding in &mut event.findings {
            redact_finding(finding, &machines);
        }
        for token in &mut event.error_tokens {
            redact_error_token(token, &machines);
        }
    }
    summary.overview.outcome = redact_identifier(&summary.overview.outcome, &machines);
    summary.overview.headline = redact_identifier(&summary.overview.headline, &machines);
    summary
}

fn normalize_correlation(mut edge: CorrelationEdge) -> CorrelationEdge {
    if matches!(edge.basis, CorrelationBasis::TimestampOnly)
        && matches!(edge.status, CorrelationStatus::Exact)
    {
        edge.status = CorrelationStatus::Ambiguous;
    }
    if matches!(edge.basis, CorrelationBasis::CandidateIdentifier)
        && matches!(edge.status, CorrelationStatus::Exact)
    {
        edge.status = CorrelationStatus::Candidate;
    }

    edge
}
/// Merges event and text findings without discarding source references or coverage gaps.
/// Timestamp-only relationships are always retained as ambiguous candidates, never causal edges.
pub fn summarize_cross_source(
    events: Vec<EventDiagnosis>,
    text_findings: Vec<DiagnosisFinding>,
    correlations: Vec<CorrelationEdge>,
) -> DiagnosisSummary {
    let mut findings = Vec::new();
    let mut coverage_gaps = Vec::new();
    let mut evidence = BTreeMap::<String, EvidenceRef>::new();
    for event in &events {
        for reference in &event.evidence {
            evidence.insert(reference.stable_id(), reference.clone());
        }
        findings.extend(event.findings.clone());
    }
    findings.extend(text_findings);
    for finding in &findings {
        for reference in &finding.evidence {
            evidence.insert(reference.stable_id(), reference.clone());
        }
        for gap in &finding.coverage_gaps {
            for reference in &gap.evidence {
                evidence.insert(reference.stable_id(), reference.clone());
            }
            coverage_gaps.push(gap.clone());
        }
    }
    coverage_gaps.sort_by(|left, right| left.id.cmp(&right.id));
    coverage_gaps.dedup_by(|left, right| left.id == right.id);
    let correlations = correlations
        .into_iter()
        .map(normalize_correlation)
        .collect::<Vec<_>>();
    let outcome = if findings
        .iter()
        .any(|finding| finding.class == FindingClass::ContradictoryEvidence)
    {
        (
            "contradictoryEvidence",
            "Evidence contains contradictory outcomes; no terminal conclusion is asserted.",
        )
    } else if findings
        .iter()
        .any(|finding| finding.class == FindingClass::ConfirmedFailure)
    {
        (
            "confirmedFailure",
            "Evidence contains confirmed operational failure(s).",
        )
    } else if findings.iter().any(|finding| {
        matches!(
            finding.class,
            FindingClass::LikelyContributor | FindingClass::Symptom | FindingClass::Recovered
        )
    }) {
        (
            "symptomsOnly",
            "Evidence contains symptoms or contributing signals but no confirmed failure.",
        )
    } else if !coverage_gaps.is_empty() {
        (
            "insufficientEvidence",
            "Evidence is insufficient to conclude an operational outcome.",
        )
    } else {
        ("noFindings", "No actionable diagnosis was produced.")
    };
    let overview = DiagnosisOverview {
        outcome: outcome.0.to_string(),
        headline: outcome.1.to_string(),
        finding_count: findings.len(),
        coverage_gap_count: coverage_gaps.len(),
        evidence_count: evidence.len(),
        correlation_count: correlations.len(),
    };
    DiagnosisSummary {
        findings,
        evidence: evidence.into_values().collect(),
        coverage_gaps,
        correlations,
        events,
        overview,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        adapt_event_entry_with_data_and_raw_xml, enrich_error_tokens, CoverageState,
        EventLogChannel, EventLogEntry, EventLogSeverity, FindingClass,
    };
    use std::collections::BTreeMap;

    #[test]
    fn malformed_token_is_visible_without_normalized_value() {
        let token = enrich_error_tokens("0xZZZZ").pop().expect("token");
        assert!(token.malformed);
        assert_eq!(token.hex, None);
        assert_eq!(token.decimal, None);
    }

    #[test]
    fn nonzero_error_token_accepts_uppercase_and_wide_hex() {
        let token = super::ErrorToken {
            raw: "0X8000000000000000".into(),
            decimal: None,
            hex: Some("0X8000000000000000".into()),
            malformed: false,
            found: false,
            description: None,
            category: None,
        };
        assert!(super::nonzero_error_token(&[token]));

        let token = super::ErrorToken {
            raw: "0x10000000000000000000000000000000".into(),
            decimal: None,
            hex: Some("0x10000000000000000000000000000000".into()),
            malformed: false,
            found: false,
            description: None,
            category: None,
        };
        assert!(super::nonzero_error_token(&[token]));
    }

    #[test]
    fn machine_redaction_prefers_longer_overlapping_names() {
        let mut machines = BTreeMap::new();
        machines.insert("HOST".to_string(), "<redacted>".to_string());
        machines.insert("HOST-01".to_string(), "<redacted>".to_string());

        assert_eq!(super::redact_identifier("HOST-01", &machines), "<redacted>");
    }

    #[test]
    fn coverage_state_only_marks_gap() {
        let finding =
            super::finding_for_coverage("mdm", CoverageState::Skipped, "not collected".into());
        assert_eq!(finding.class, FindingClass::CoverageGap);
        assert_eq!(finding.confidence, super::FindingConfidence::Unknown);
    }

    #[test]
    fn display_projection_masks_sensitive_strings_without_changing_findings() {
        let source = r"C:\Users\Jane Doe\AppData\Local\event.evtx".to_string();
        let evidence = super::EvidenceRef::Event(super::EventEvidenceRef {
            source: source.clone(),
            provider: "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider".into(),
            event_id: 404,
            record_id: 17,
            record_id_text: None,
            fallback_identity: Some("jane.doe@example.invalid".into()),
            machine: Some("ComputerName=DESKTOP-JANE".into()),
            channel: Some("DeviceManagement-Enterprise-Diagnostics-Provider/Admin".into()),
            activity_id: None,
        });
        let finding = super::DiagnosisFinding {
            finding_id: format!("event:{source}:failure"),
            class: super::FindingClass::ConfirmedFailure,
            severity: super::FindingSeverity::Error,
            confidence: super::FindingConfidence::High,
            title: "Enrollment failed".into(),
            summary: "jane.doe@example.invalid failed with PASSWORD=hunter2 <Password>xml-secret</Password>".into(),
            evidence: vec![evidence.clone()],
            coverage_gaps: vec![super::CoverageGap {
                id: format!("coverage:{source}"),
                source: source.clone(),
                state: super::CoverageState::Covered,
                detail: "Retry for jane.doe@example.invalid on DESKTOP-JANE".into(),
                evidence: vec![evidence.clone()],
            }],
            recommended_checks: vec![r"Inspect C:\Users\Jane Doe\AppData\Local\event.evtx".into()],
        };
        let summary = super::DiagnosisSummary {
            findings: vec![finding],
            evidence: vec![evidence],
            ..Default::default()
        };

        let redacted = super::redacted_display_projection(summary);
        let serialized = serde_json::to_string(&redacted).expect("diagnosis serializes");

        assert!(!serialized.contains("Jane Doe"), "{serialized}");
        assert!(
            !serialized.contains("jane.doe@example.invalid"),
            "{serialized}"
        );
        assert!(!serialized.contains("xml-secret"), "{serialized}");
        assert!(!serialized.contains("DESKTOP-JANE"), "{serialized}");
        assert!(serialized.contains("Enrollment failed"), "{serialized}");
        assert_eq!(redacted.overview, super::DiagnosisOverview::default());
    }
    #[test]
    fn display_projection_redacts_field_labeled_correlation_values() {
        let summary = super::DiagnosisSummary {
            correlations: vec![super::CorrelationEdge {
                left: "event:left".into(),
                right: Some("event:right".into()),
                basis: super::CorrelationBasis::ExactIdentifier,
                status: super::CorrelationStatus::Exact,
                candidate_ids: Vec::new(),
                evidence: vec![super::CorrelationEvidence {
                    origin_id: "event:left".into(),
                    field: "deviceId".into(),
                    value: "device-secret-guid".into(),
                }],
            }],
            ..Default::default()
        };

        let redacted = super::redacted_display_projection(summary);
        let serialized = serde_json::to_string(&redacted).expect("diagnosis serializes");
        assert!(!serialized.contains("device-secret-guid"), "{serialized}");
    }

    #[test]
    fn diagnostic_xml_redacts_sensitive_attributes_and_preserves_safe_elements() {
        let raw_xml = concat!(
            "<EventData>",
            r#"<Password value="0xDEADBEEF"/>"#,
            r#"<Data Name="Password" value="0xBADCAFE"/>"#,
            r#"<Status value="0xCAFEBABE"/>"#,
            "</EventData>",
        );
        let masked = super::redact_diagnostic_xml(raw_xml);
        assert!(!masked.contains("DEADBEEF"), "{masked}");
        assert!(!masked.contains("BADCAFE"), "{masked}");
        assert!(
            masked.contains("<Password>[redacted]</Password>"),
            "{masked}"
        );
        assert!(masked.contains("<Data>[redacted]</Data>"), "{masked}");
        assert!(
            masked.contains(r#"<Status value="0xCAFEBABE"/>"#),
            "{masked}"
        );

        let diagnosis = adapt_event_entry_with_data_and_raw_xml(
            EventLogEntry {
                id: 1,
                channel: EventLogChannel::DeviceManagementAdmin,
                channel_display: "DeviceManagement-Enterprise-Diagnostics-Provider/Admin".into(),
                provider: "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider"
                    .into(),
                event_id: 404,
                severity: EventLogSeverity::Error,
                timestamp: "2025-01-01T00:00:00Z".into(),
                computer: None,
                message: "operation failed".into(),
                correlation_activity_id: None,
                source_file: "event.evtx".into(),
            },
            &[],
            raw_xml,
        );
        let serialized = serde_json::to_string(&diagnosis).expect("diagnosis serializes");
        assert!(!serialized.contains("DEADBEEF"), "{serialized}");
        assert!(!serialized.contains("BADCAFE"), "{serialized}");
    }

    #[test]
    fn missing_id_events_with_distinct_raw_xml_have_distinct_fallback_identity() {
        let entry = || EventLogEntry {
            id: 0,
            channel: EventLogChannel::DeviceManagementAdmin,
            channel_display: "DeviceManagement-Enterprise-Diagnostics-Provider/Admin".into(),
            provider: "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider".into(),
            event_id: 404,
            severity: EventLogSeverity::Error,
            timestamp: "2025-01-01T00:00:00Z".into(),
            computer: None,
            message: "operation failed".into(),
            correlation_activity_id: None,
            source_file: "event.evtx".into(),
        };
        let left = adapt_event_entry_with_data_and_raw_xml(
            entry(),
            &[],
            r#"<EventData><Data Name="Status">Error</Data><Data Name="Payload">one</Data></EventData>"#,
        );
        let right = adapt_event_entry_with_data_and_raw_xml(
            entry(),
            &[],
            r#"<EventData><Data Name="Status">Error</Data><Data Name="Payload">two</Data></EventData>"#,
        );
        let left_id = left.evidence[0].stable_id();
        let right_id = right.evidence[0].stable_id();
        assert_ne!(left_id, right_id);
        assert_ne!(left.findings[0].finding_id, right.findings[0].finding_id);
    }
}
