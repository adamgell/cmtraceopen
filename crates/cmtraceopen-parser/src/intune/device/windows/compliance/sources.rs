//! Source classification for compliance evidence.
//!
//! Two jobs, both pure:
//!
//! 1. decode a supplied evidence bundle into a [`ComplianceInput`], turning any
//!    decode problem into explicit coverage rather than a silent empty result;
//! 2. classify one normalized Windows event or setting-report row into a typed
//!    compliance signal, or decline to classify it.
//!
//! Declining matters as much as classifying. A record that names a setting but
//! states no result yields [`ComplianceSettingState::InsufficientEvidence`], and
//! a record that names no setting at all yields nothing — epic #356 forbids
//! creating a correlation from an unknown identifier.
//!
//! # Named-data vocabulary
//!
//! The native adapter projects platform records into
//! [`NormalizedWindowsEvent`], carrying the payload in `named_data`. This module
//! reads the following names, case-insensitively, with the listed aliases:
//!
//! | Meaning | Names |
//! |---|---|
//! | setting URI | `SettingUri`, `NodeUri`, `Uri` |
//! | setting id | `SettingId` |
//! | policy id | `PolicyId`, `CompliancePolicyId` |
//! | scope | `Scope`, `TargetScope` |
//! | evaluation result | `EvaluationResult`, `ComplianceResult`, `Result` |
//! | error code | `ErrorCode`, `ResultCode`, `Hresult` |
//! | prerequisite | `Prerequisite` (+ `PrerequisiteName`, `PrerequisiteDetail`) |
//! | report status | `ReportStatus`, `ComplianceReportStatus` |
//! | report id | `ReportId` |
//! | policy state | `PolicyState` |
//! | evaluation time | `EvaluatedAt`, `EvaluationTime` |
//! | display name | `DisplayName`, `SettingDisplayName` |
//!
//! Anything else is carried through untouched.

use std::sync::OnceLock;

use regex::Regex;
use serde::Deserialize;
use serde_json::Value;

use super::models::*;
use crate::intune::evidence::{
    IntuneAccessState, IntuneArtifactCoverage, IntuneArtifactStatus, IntuneErrorCode,
    IntuneNamedValue, IntuneObservationContext, IntuneParseState, IntuneTimestamp,
};
use crate::intune::normalized::{
    NormalizedEventLevel, NormalizedSettingOutcome, NormalizedSettingReport, NormalizedWindowsEvent,
};

/// Envelope version this build understands.
pub const COMPLIANCE_INPUT_ENVELOPE_VERSION: u32 = 1;

/// One artifact handed to the analyzer, with what the collector managed to do.
///
/// `content` is `None` whenever the artifact was not read. The analyzer never
/// opens a file: `crate::intune` is wasm32-clean and does no I/O.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComplianceSourceInput {
    pub artifact_id: String,
    /// Grouping label reported in coverage, e.g. `mdmEvents`, `mdmReport`.
    pub family: String,
    /// What the collector reported. A decode failure can only downgrade this.
    pub status: IntuneArtifactStatus,
    pub captured_at_utc: String,
    pub content: Option<String>,
}

/// The record kinds a bundle artifact may carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EnvelopeKind {
    WindowsEvents,
    SettingReports,
    CustomCompliance,
    ServiceResults,
    AccessDecisions,
    DeviceContext,
}

impl EnvelopeKind {
    fn parse(raw: &str) -> Option<Self> {
        match raw {
            "windowsEvents" => Some(Self::WindowsEvents),
            "settingReports" => Some(Self::SettingReports),
            "customCompliance" => Some(Self::CustomCompliance),
            "serviceResults" => Some(Self::ServiceResults),
            "accessDecisions" => Some(Self::AccessDecisions),
            "deviceContext" => Some(Self::DeviceContext),
            _ => None,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ComplianceEnvelope {
    #[serde(default)]
    compliance_input_version: u32,
    #[serde(default)]
    kind: String,
    #[serde(default)]
    records: Vec<Value>,
}

/// Why an artifact could not contribute records.
struct DecodeProblem {
    status: IntuneArtifactStatus,
    detail: String,
}

/// Decode a supplied bundle into the reducer's input, with coverage for every
/// artifact including the ones that produced nothing.
pub fn decode_bundle(sources: &[ComplianceSourceInput], generated_at_utc: &str) -> ComplianceInput {
    let mut input = ComplianceInput {
        generated_at_utc: generated_at_utc.to_owned(),
        ..ComplianceInput::default()
    };

    for source in sources {
        let problem = match source.content.as_deref() {
            Some(text) => absorb_envelope(text, &mut input),
            None => None,
        };

        let (status, detail) = match problem {
            // A decode failure overrides whatever the collector claimed: bytes
            // that cannot be interpreted are not available evidence.
            Some(problem) => (problem.status, Some(problem.detail)),
            None => (source.status.clone(), None),
        };

        input.coverage.push(IntuneArtifactCoverage {
            artifact_id: source.artifact_id.clone(),
            family: source.family.clone(),
            status,
            detail,
            observed_at_utc: source.captured_at_utc.clone(),
            evidence: Vec::new(),
        });
    }

    input.coverage.sort_by(|left, right| {
        left.artifact_id
            .cmp(&right.artifact_id)
            .then_with(|| left.family.cmp(&right.family))
    });
    input
}

/// Parse one artifact's text and append its records, returning a problem when
/// the text cannot be used.
fn absorb_envelope(text: &str, input: &mut ComplianceInput) -> Option<DecodeProblem> {
    let envelope: ComplianceEnvelope = match serde_json::from_str(text) {
        Ok(envelope) => envelope,
        Err(error) => {
            return Some(DecodeProblem {
                status: IntuneArtifactStatus::ParseFailed,
                detail: format!("evidence is not a compliance input envelope: {error}"),
            })
        }
    };

    if envelope.compliance_input_version != COMPLIANCE_INPUT_ENVELOPE_VERSION {
        return Some(DecodeProblem {
            status: IntuneArtifactStatus::Unsupported,
            detail: format!(
                "complianceInputVersion {} is not supported by this build (expected {COMPLIANCE_INPUT_ENVELOPE_VERSION})",
                envelope.compliance_input_version
            ),
        });
    }

    let Some(kind) = EnvelopeKind::parse(&envelope.kind) else {
        return Some(DecodeProblem {
            status: IntuneArtifactStatus::Unsupported,
            detail: format!("record kind {:?} is not recognized", envelope.kind),
        });
    };

    // Decode every record before touching `input`: an envelope contributes all
    // of its records or none of them, so a failure halfway through cannot leave
    // a partially absorbed artifact behind while its coverage says `ParseFailed`.
    let mut staged = StagedRecords::default();
    for record in envelope.records {
        if let Err(error) = stage_record(kind, record, &mut staged) {
            return Some(DecodeProblem {
                status: IntuneArtifactStatus::ParseFailed,
                detail: format!("a {} record failed to decode: {error}", envelope.kind),
            });
        }
    }
    staged.apply(input);

    None
}

/// Records decoded from one envelope, held until the whole envelope succeeds.
#[derive(Default)]
struct StagedRecords {
    events: Vec<NormalizedWindowsEvent>,
    setting_reports: Vec<NormalizedSettingReport>,
    custom_compliance: Vec<ComplianceCustomFact>,
    service_results: Vec<ComplianceServiceFact>,
    access_decisions: Vec<ComplianceAccessFact>,
    device_context: Option<ComplianceDeviceContextFact>,
}

impl StagedRecords {
    fn apply(self, input: &mut ComplianceInput) {
        input.events.extend(self.events);
        input.setting_reports.extend(self.setting_reports);
        input.custom_compliance.extend(self.custom_compliance);
        input.service_results.extend(self.service_results);
        input.access_decisions.extend(self.access_decisions);
        // Last one wins; a bundle is expected to declare device context once.
        if let Some(context) = self.device_context {
            input.device_context = Some(context);
        }
    }
}

fn stage_record(
    kind: EnvelopeKind,
    record: Value,
    staged: &mut StagedRecords,
) -> Result<(), serde_json::Error> {
    match kind {
        EnvelopeKind::WindowsEvents => staged.events.push(serde_json::from_value(record)?),
        EnvelopeKind::SettingReports => {
            staged.setting_reports.push(serde_json::from_value(record)?)
        }
        EnvelopeKind::CustomCompliance => staged
            .custom_compliance
            .push(serde_json::from_value(record)?),
        EnvelopeKind::ServiceResults => {
            staged.service_results.push(serde_json::from_value(record)?)
        }
        EnvelopeKind::AccessDecisions => staged
            .access_decisions
            .push(serde_json::from_value(record)?),
        EnvelopeKind::DeviceContext => {
            staged.device_context = Some(serde_json::from_value(record)?)
        }
    }
    Ok(())
}

// ── Named-data access ───────────────────────────────────────────────────────

/// First value whose name matches any of `names`, case-insensitively.
pub(super) fn named_any<'a>(values: &'a [IntuneNamedValue], names: &[&str]) -> Option<&'a str> {
    values
        .iter()
        .find(|value| {
            names
                .iter()
                .any(|name| value.name.eq_ignore_ascii_case(name))
        })
        .map(|value| value.value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

/// Lowercase a token and drop everything that is not alphanumeric, so
/// `Not Compliant`, `not_compliant`, and `NotCompliant` compare equal.
fn canonical(value: &str) -> String {
    value
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

const SETTING_URI_NAMES: [&str; 3] = ["SettingUri", "NodeUri", "Uri"];
const SETTING_ID_NAMES: [&str; 1] = ["SettingId"];
const POLICY_ID_NAMES: [&str; 2] = ["PolicyId", "CompliancePolicyId"];
const SCOPE_NAMES: [&str; 2] = ["Scope", "TargetScope"];
const RESULT_NAMES: [&str; 3] = ["EvaluationResult", "ComplianceResult", "Result"];
const ERROR_NAMES: [&str; 3] = ["ErrorCode", "ResultCode", "Hresult"];
const REPORT_STATUS_NAMES: [&str; 2] = ["ReportStatus", "ComplianceReportStatus"];
const REPORT_ID_NAMES: [&str; 1] = ["ReportId"];
const POLICY_STATE_NAMES: [&str; 1] = ["PolicyState"];
const EVALUATED_AT_NAMES: [&str; 2] = ["EvaluatedAt", "EvaluationTime"];
const DISPLAY_NAME_NAMES: [&str; 2] = ["DisplayName", "SettingDisplayName"];
const PREREQUISITE_NAMES: [&str; 1] = ["Prerequisite"];

/// Parse a compliance verdict token into a local setting state.
pub(super) fn parse_setting_result(raw: &str) -> Option<ComplianceSettingState> {
    match canonical(raw).as_str() {
        "compliant" | "pass" | "passed" | "true" | "0" => Some(ComplianceSettingState::Compliant),
        "noncompliant" | "notcompliant" | "fail" | "failed" | "false" => {
            Some(ComplianceSettingState::Noncompliant)
        }
        "error" | "evaluationerror" => Some(ComplianceSettingState::EvaluationError),
        "notapplicable" | "na" | "unsupported" => Some(ComplianceSettingState::NotApplicable),
        "notevaluated" | "skipped" | "pending" => Some(ComplianceSettingState::NotEvaluated),
        "prerequisiteunmet" => Some(ComplianceSettingState::PrerequisiteUnmet),
        _ => None,
    }
}

fn parse_scope(raw: Option<&str>) -> ComplianceScope {
    match raw.map(canonical).as_deref() {
        Some("device") | Some("machine") | Some("system") => ComplianceScope::Device,
        Some("user") => ComplianceScope::User,
        _ => ComplianceScope::Unknown,
    }
}

fn parse_report_status(raw: &str) -> Option<ComplianceReportState> {
    match canonical(raw).as_str() {
        "queued" | "pending" => Some(ComplianceReportState::Queued),
        "submitted" | "sent" | "success" | "succeeded" => Some(ComplianceReportState::Submitted),
        "failed" | "failure" | "error" => Some(ComplianceReportState::Failed),
        "stale" => Some(ComplianceReportState::Stale),
        _ => None,
    }
}

fn parse_policy_state(raw: &str) -> Option<CompliancePolicyState> {
    match canonical(raw).as_str() {
        "received" | "known" | "present" | "applied" => Some(CompliancePolicyState::Received),
        "notreceived" | "missing" | "absent" => Some(CompliancePolicyState::NotReceived),
        _ => None,
    }
}

fn parse_prerequisite_state(raw: &str) -> CompliancePrerequisiteState {
    match canonical(raw).as_str() {
        "met" | "satisfied" | "true" => CompliancePrerequisiteState::Met,
        "unmet" | "notmet" | "unsatisfied" | "false" => CompliancePrerequisiteState::Unmet,
        _ => CompliancePrerequisiteState::Unknown,
    }
}

// ── Error codes ─────────────────────────────────────────────────────────────

/// A hexadecimal HRESULT/Win32 token.
fn hex_code_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"(?i)\b0x[0-9a-f]{1,16}\b").expect("hex error-code regex must compile")
    })
}

/// A signed decimal token that is the whole value, not part of an identifier.
fn decimal_code_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| Regex::new(r"^-?\d{1,19}$").expect("decimal error-code regex must compile"))
}

/// Build an [`IntuneErrorCode`] from a raw token, keeping the token verbatim.
///
/// Both derived forms are best-effort. Intune writes the same failure as a
/// signed decimal, an unsigned decimal, and a hex HRESULT depending on the
/// artifact, so neither form is authoritative and the raw token is always kept.
pub(super) fn parse_error_code(raw: &str) -> Option<IntuneErrorCode> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }

    if let Some(hex_match) = hex_code_re().find(raw) {
        let hex = hex_match.as_str();
        let digits = &hex[2..];
        let decimal = u64::from_str_radix(digits, 16)
            .ok()
            .map(|value| value as i64);
        // Render the digits that were actually written rather than a 32-bit
        // truncation of the derived decimal: a 64-bit token such as
        // `0xFFFFFFFF80070002` must not silently become `0x80070002`.
        let upper = digits.to_ascii_uppercase();
        let normalized_hex = if upper.len() <= 8 {
            format!("0x{upper:0>8}")
        } else {
            format!("0x{upper}")
        };
        return Some(IntuneErrorCode {
            raw: raw.to_owned(),
            decimal,
            hex: Some(normalized_hex),
        });
    }

    if decimal_code_re().is_match(raw) {
        let decimal = raw.parse::<i64>().ok();
        return Some(IntuneErrorCode {
            raw: raw.to_owned(),
            decimal,
            hex: decimal.map(|value| format!("0x{:08X}", value as u32)),
        });
    }

    // Unrecognized shape: keep it rather than discard it. A token we cannot
    // interpret is still the only thing a human has to search for.
    Some(IntuneErrorCode {
        raw: raw.to_owned(),
        decimal: None,
        hex: None,
    })
}

// ── Classification ──────────────────────────────────────────────────────────

/// A typed signal extracted from one local observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ComplianceSignal {
    SettingEvaluation(Box<SettingObservation>),
    Prerequisite {
        name: String,
        state: CompliancePrerequisiteState,
        detail: Option<String>,
    },
    PolicyState {
        policy_id: String,
        state: CompliancePolicyState,
        scope: ComplianceScope,
    },
    ReportSubmission {
        state: ComplianceReportState,
        report_id: Option<String>,
        error: Option<IntuneErrorCode>,
        submitted_at: Option<IntuneTimestamp>,
    },
}

/// One local claim about one setting, before merging.
///
/// `grouping_token` is non-optional by construction: an observation is only
/// built once its key yields a token, so the reducer has no unidentified case to
/// handle and cannot merge on an unknown identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SettingObservation {
    pub key: ComplianceSettingKey,
    pub grouping_token: String,
    pub scope: ComplianceScope,
    pub state: ComplianceSettingState,
    pub display_name: Option<String>,
    pub error: Option<IntuneErrorCode>,
    pub evaluated_at: Option<IntuneTimestamp>,
    pub named_data: Vec<IntuneNamedValue>,
    pub context: IntuneObservationContext,
}

/// Whether an observation is eligible to produce a compliance signal.
///
/// A record that failed to parse, or that the collector could not read, states
/// nothing about the device. Reading its fields would turn a collection gap into
/// a fabricated verdict, so such records are declined and left to coverage.
fn is_usable(context: &IntuneObservationContext) -> bool {
    context.parse_state == IntuneParseState::Parsed
        && context.access_state == IntuneAccessState::Available
}

/// Classify one normalized Windows event.
///
/// Returns `None` when the event carries no compliance signal this module can
/// use. A caller that needs to know an event was seen and not understood should
/// consult the unkeyed-observation count on the reduced phase instead.
pub(super) fn classify_event(event: &NormalizedWindowsEvent) -> Option<ComplianceSignal> {
    if !is_usable(&event.context) {
        return None;
    }

    let data = &event.named_data;

    if let Some(raw) = named_any(data, &REPORT_STATUS_NAMES) {
        let state = parse_report_status(raw).unwrap_or(ComplianceReportState::Unknown);
        return Some(ComplianceSignal::ReportSubmission {
            state,
            report_id: named_any(data, &REPORT_ID_NAMES).map(str::to_owned),
            error: named_any(data, &ERROR_NAMES).and_then(parse_error_code),
            submitted_at: event.context.source_timestamp.clone(),
        });
    }

    if let Some(raw) = named_any(data, &PREREQUISITE_NAMES) {
        return Some(ComplianceSignal::Prerequisite {
            name: named_any(data, &["PrerequisiteName"])
                .unwrap_or("prerequisite")
                .to_owned(),
            state: parse_prerequisite_state(raw),
            detail: named_any(data, &["PrerequisiteDetail"]).map(str::to_owned),
        });
    }

    let key = event_setting_key(event);

    // A policy-level statement is only meaningful with a policy id, and only
    // when the event is not already describing a specific setting.
    if let (Some(raw), Some(policy_id)) = (
        named_any(data, &POLICY_STATE_NAMES),
        key.policy_id.as_deref(),
    ) {
        if key.setting_id.is_none() && key.setting_uri.is_none() {
            return Some(ComplianceSignal::PolicyState {
                policy_id: policy_id.to_owned(),
                state: parse_policy_state(raw).unwrap_or(CompliancePolicyState::Unknown),
                scope: parse_scope(named_any(data, &SCOPE_NAMES)),
            });
        }
    }

    let grouping_token = key.grouping_token()?;

    let state = match named_any(data, &RESULT_NAMES).and_then(parse_setting_result) {
        Some(state) => state,
        // No stated verdict. An error-level event about an identified setting is
        // an evaluation error; anything else is a mention, not a result.
        None if event.level == NormalizedEventLevel::Error
            || event.level == NormalizedEventLevel::Critical =>
        {
            ComplianceSettingState::EvaluationError
        }
        None => ComplianceSettingState::InsufficientEvidence,
    };

    Some(ComplianceSignal::SettingEvaluation(Box::new(
        SettingObservation {
            key,
            grouping_token,
            scope: parse_scope(named_any(data, &SCOPE_NAMES)),
            state,
            display_name: named_any(data, &DISPLAY_NAME_NAMES).map(str::to_owned),
            error: named_any(data, &ERROR_NAMES).and_then(parse_error_code),
            evaluated_at: named_any(data, &EVALUATED_AT_NAMES)
                .map(synthetic_timestamp)
                .or_else(|| event.context.source_timestamp.clone()),
            named_data: data.clone(),
            context: event.context.clone(),
        },
    )))
}

fn event_setting_key(event: &NormalizedWindowsEvent) -> ComplianceSettingKey {
    let data = &event.named_data;
    ComplianceSettingKey {
        policy_id: named_any(data, &POLICY_ID_NAMES).map(str::to_owned),
        setting_id: named_any(data, &SETTING_ID_NAMES).map(str::to_owned),
        setting_uri: named_any(data, &SETTING_URI_NAMES).map(str::to_owned),
    }
}

/// Classify one exported report row.
///
/// The outcome mapping is deliberately conservative:
/// [`NormalizedSettingOutcome::Failed`] becomes
/// [`ComplianceSettingState::EvaluationError`], **not** `Noncompliant`. A report
/// row that says the setting failed says the device could not complete it; that
/// is not the same claim as "the device does not meet the requirement", and
/// merging the two is exactly the conflation this module refuses to make. An
/// explicit `EvaluationResult` named value overrides the mapping.
pub(super) fn classify_setting_report(
    report: &NormalizedSettingReport,
) -> Option<SettingObservation> {
    if !is_usable(&report.context) {
        return None;
    }

    let key = ComplianceSettingKey {
        policy_id: report.policy_id.clone(),
        setting_id: report.setting_id.clone(),
        setting_uri: report.setting_uri.clone(),
    };
    let grouping_token = key.grouping_token()?;

    let state = named_any(&report.named_data, &RESULT_NAMES)
        .and_then(parse_setting_result)
        .unwrap_or(match report.outcome {
            NormalizedSettingOutcome::Applied => ComplianceSettingState::Compliant,
            NormalizedSettingOutcome::Failed => ComplianceSettingState::EvaluationError,
            NormalizedSettingOutcome::Pending => ComplianceSettingState::NotEvaluated,
            NormalizedSettingOutcome::Conflict => ComplianceSettingState::Contradictory,
            NormalizedSettingOutcome::Superseded => ComplianceSettingState::NotEvaluated,
            NormalizedSettingOutcome::NotApplicable => ComplianceSettingState::NotApplicable,
            NormalizedSettingOutcome::Unknown => ComplianceSettingState::InsufficientEvidence,
        });

    Some(SettingObservation {
        key,
        grouping_token,
        scope: parse_scope(named_any(&report.named_data, &SCOPE_NAMES)),
        state,
        display_name: report.display_name.clone(),
        error: report.error.clone(),
        evaluated_at: named_any(&report.named_data, &EVALUATED_AT_NAMES)
            .map(synthetic_timestamp)
            .or_else(|| report.context.source_timestamp.clone()),
        named_data: report.named_data.clone(),
        context: report.context.clone(),
    })
}

/// Wrap a timestamp string carried in named data, keeping the raw text.
///
/// The kind reflects what the text actually stated: a trailing `Z` is UTC, any
/// other RFC 3339 offset is [`IntuneTimestampKind::Offset`]. Labelling an
/// offset-bearing string as UTC would claim a precision the source never gave.
fn synthetic_timestamp(raw: &str) -> IntuneTimestamp {
    use crate::intune::evidence::IntuneTimestampKind;

    let trimmed = raw.trim();
    let (kind, normalized) = match chrono::DateTime::parse_from_rfc3339(trimmed) {
        Ok(value) => {
            let kind = if trimmed.ends_with('Z') || trimmed.ends_with('z') {
                IntuneTimestampKind::Utc
            } else {
                IntuneTimestampKind::Offset
            };
            (
                kind,
                Some(
                    value
                        .with_timezone(&chrono::Utc)
                        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                ),
            )
        }
        Err(_) => (IntuneTimestampKind::Invalid, None),
    };

    IntuneTimestamp {
        raw_text: raw.to_owned(),
        original_offset: None,
        kind,
        normalized_utc: normalized,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intune::evidence::{
        IntuneAccessState, IntuneEvidenceRef, IntuneParseState, IntuneProvenance,
        IntuneSensitivity, IntuneSourceKind,
    };

    fn context(evidence_id: &str) -> IntuneObservationContext {
        IntuneObservationContext {
            evidence_ref: IntuneEvidenceRef {
                evidence_id: evidence_id.to_owned(),
                source_artifact_id: "artifact".to_owned(),
            },
            provenance: IntuneProvenance {
                source_kind: IntuneSourceKind::EventLog,
                source_artifact_id: "artifact".to_owned(),
                file_path: None,
                line_number: None,
                record_number: None,
                registry: None,
                event: None,
            },
            source_timestamp: None,
            observed_at_utc: "2026-07-31T00:00:00Z".to_owned(),
            sensitivity: IntuneSensitivity::Public,
            parse_state: IntuneParseState::Parsed,
            access_state: IntuneAccessState::Available,
        }
    }

    fn event(level: NormalizedEventLevel, data: &[(&str, &str)]) -> NormalizedWindowsEvent {
        NormalizedWindowsEvent {
            context: context("e1"),
            channel: "channel".to_owned(),
            provider: "provider".to_owned(),
            event_id: 1,
            level,
            task: None,
            keywords: None,
            record_id: None,
            activity_id: None,
            named_data: data
                .iter()
                .map(|(name, value)| IntuneNamedValue {
                    name: (*name).to_owned(),
                    value: (*value).to_owned(),
                })
                .collect(),
            message: None,
        }
    }

    #[test]
    fn an_event_with_no_setting_identity_is_not_classified() {
        assert_eq!(
            classify_event(&event(
                NormalizedEventLevel::Error,
                &[("EvaluationResult", "noncompliant")]
            )),
            None,
            "a verdict with no setting identity must not become a setting evaluation"
        );
    }

    #[test]
    fn an_identified_error_event_without_a_verdict_is_an_evaluation_error() {
        let signal = classify_event(&event(
            NormalizedEventLevel::Error,
            &[("SettingUri", "./Device/X")],
        ))
        .expect("classified");
        match signal {
            ComplianceSignal::SettingEvaluation(observation) => {
                assert_eq!(observation.state, ComplianceSettingState::EvaluationError);
            }
            other => panic!("unexpected signal {other:?}"),
        }
    }

    #[test]
    fn an_identified_informational_event_without_a_verdict_is_insufficient() {
        let signal = classify_event(&event(
            NormalizedEventLevel::Information,
            &[("SettingUri", "./Device/X")],
        ))
        .expect("classified");
        match signal {
            ComplianceSignal::SettingEvaluation(observation) => {
                assert_eq!(
                    observation.state,
                    ComplianceSettingState::InsufficientEvidence
                );
            }
            other => panic!("unexpected signal {other:?}"),
        }
    }

    #[test]
    fn a_failed_report_row_is_an_evaluation_error_not_a_noncompliance() {
        let report = NormalizedSettingReport {
            context: context("r1"),
            setting_uri: Some("./Device/X".to_owned()),
            setting_id: None,
            policy_id: None,
            display_name: None,
            outcome: NormalizedSettingOutcome::Failed,
            value: None,
            error: None,
            named_data: Vec::new(),
        };
        let observation = classify_setting_report(&report).expect("classified");
        assert_eq!(observation.state, ComplianceSettingState::EvaluationError);
    }

    #[test]
    fn result_tokens_are_matched_case_and_punctuation_insensitively() {
        for raw in ["Not Compliant", "not_compliant", "NONCOMPLIANT"] {
            assert_eq!(
                parse_setting_result(raw),
                Some(ComplianceSettingState::Noncompliant),
                "{raw} must parse as noncompliant"
            );
        }
    }

    #[test]
    fn a_hex_error_token_keeps_its_raw_form() {
        let code = parse_error_code("0x87D1FDE8").expect("parsed");
        assert_eq!(code.raw, "0x87D1FDE8");
        assert_eq!(code.hex.as_deref(), Some("0x87D1FDE8"));
    }

    #[test]
    fn a_sixty_four_bit_hex_token_is_not_truncated_to_thirty_two_bits() {
        let code = parse_error_code("0xFFFFFFFF80070002").expect("parsed");
        assert_eq!(code.hex.as_deref(), Some("0xFFFFFFFF80070002"));
    }

    #[test]
    fn an_offset_bearing_evaluation_time_is_not_labelled_utc() {
        let signal = classify_event(&event(
            NormalizedEventLevel::Information,
            &[
                ("SettingUri", "./Device/X"),
                ("EvaluationResult", "compliant"),
                ("EvaluatedAt", "2026-07-31T12:00:00+05:00"),
            ],
        ))
        .expect("classified");
        match signal {
            ComplianceSignal::SettingEvaluation(observation) => {
                let stamp = observation.evaluated_at.expect("evaluated at");
                assert_eq!(
                    stamp.kind,
                    crate::intune::evidence::IntuneTimestampKind::Offset
                );
                assert_eq!(
                    stamp.normalized_utc.as_deref(),
                    Some("2026-07-31T07:00:00Z")
                );
            }
            other => panic!("unexpected signal {other:?}"),
        }
    }

    #[test]
    fn an_unparsed_record_states_nothing_about_a_setting() {
        let mut unusable = event(
            NormalizedEventLevel::Information,
            &[
                ("SettingUri", "./Device/X"),
                ("EvaluationResult", "noncompliant"),
            ],
        );
        unusable.context.parse_state = IntuneParseState::Malformed;
        assert_eq!(classify_event(&unusable), None);

        let mut unreadable = event(
            NormalizedEventLevel::Information,
            &[
                ("SettingUri", "./Device/X"),
                ("EvaluationResult", "noncompliant"),
            ],
        );
        unreadable.context.access_state = IntuneAccessState::PermissionDenied;
        assert_eq!(classify_event(&unreadable), None);
    }

    #[test]
    fn a_record_that_fails_halfway_absorbs_nothing() {
        let text = format!(
            r#"{{"complianceInputVersion":{COMPLIANCE_INPUT_ENVELOPE_VERSION},"kind":"windowsEvents","records":[{{"channel":"c"}},7]}}"#
        );
        let input = decode_bundle(
            &[ComplianceSourceInput {
                artifact_id: "a".to_owned(),
                family: "mdmEvents".to_owned(),
                status: IntuneArtifactStatus::Available,
                captured_at_utc: "2026-07-31T00:00:00Z".to_owned(),
                content: Some(text),
            }],
            "2026-07-31T00:00:00Z",
        );
        assert_eq!(input.coverage[0].status, IntuneArtifactStatus::ParseFailed);
        assert!(
            input.events.is_empty(),
            "an envelope that failed to decode must contribute no records"
        );
    }

    #[test]
    fn an_unrecognized_error_token_is_preserved_rather_than_dropped() {
        let code = parse_error_code("E_SOMETHING").expect("parsed");
        assert_eq!(code.raw, "E_SOMETHING");
        assert_eq!(code.decimal, None);
    }

    #[test]
    fn malformed_evidence_becomes_parse_failed_coverage() {
        let input = decode_bundle(
            &[ComplianceSourceInput {
                artifact_id: "a".to_owned(),
                family: "mdmEvents".to_owned(),
                status: IntuneArtifactStatus::Available,
                captured_at_utc: "2026-07-31T00:00:00Z".to_owned(),
                content: Some("{not json".to_owned()),
            }],
            "2026-07-31T00:00:00Z",
        );
        assert_eq!(input.coverage[0].status, IntuneArtifactStatus::ParseFailed);
        assert!(input.events.is_empty());
    }

    #[test]
    fn an_unknown_envelope_version_becomes_unsupported_coverage() {
        let input = decode_bundle(
            &[ComplianceSourceInput {
                artifact_id: "a".to_owned(),
                family: "mdmEvents".to_owned(),
                status: IntuneArtifactStatus::Available,
                captured_at_utc: "2026-07-31T00:00:00Z".to_owned(),
                content: Some(r#"{"complianceInputVersion":99,"kind":"windowsEvents"}"#.to_owned()),
            }],
            "2026-07-31T00:00:00Z",
        );
        assert_eq!(input.coverage[0].status, IntuneArtifactStatus::Unsupported);
    }

    #[test]
    fn an_uncollected_artifact_keeps_the_collector_reported_status() {
        let input = decode_bundle(
            &[ComplianceSourceInput {
                artifact_id: "a".to_owned(),
                family: "mdmReport".to_owned(),
                status: IntuneArtifactStatus::PermissionDenied,
                captured_at_utc: "2026-07-31T00:00:00Z".to_owned(),
                content: None,
            }],
            "2026-07-31T00:00:00Z",
        );
        assert_eq!(
            input.coverage[0].status,
            IntuneArtifactStatus::PermissionDenied
        );
    }
}
