//! Record-level classification for remediation evidence.
//!
//! Every rule here answers one question about one record: what did this line
//! *say*? Nothing in this module decides a run's outcome, merges records, or
//! infers a value that is not written down.
//!
//! The one rule that matters more than the rest: a stage is only ever read from
//! a record that named it, either in the script path it launched, in an
//! explicit phrase, or in a structured payload field. `exitCode = 1` means
//! "remediation required" after detection and "the remediation script failed"
//! after remediation, so an exit code with no stage is kept as an execution
//! observation and never promoted to a stage outcome.

use std::sync::OnceLock;

use regex::Regex;
use serde_json::{Map, Value};

use crate::intune::evidence::{IntuneErrorCode, IntuneNamedValue};

use super::models::{RemediationEvent, RemediationInvocation, RemediationSourceKind, RemediationStage};

const GUID: &str = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}";

fn re(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).expect("remediation regex must compile"))
}

/// `...\IMECache\HealthScripts\{policyId}_{runId}\detect.ps1` -- the strongest
/// identity in the executor log: it names the policy, the run, and the stage in
/// one token.
fn script_path_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        &format!(
            r"(?i)[\\/]HealthScripts[\\/](?P<policy>{GUID})_(?P<run>{GUID})[\\/](?P<script>detect|remediate)\.ps1"
        ),
    )
}

fn policy_id_field_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(&CELL, &format!(r"(?i)\bPolicyId\s*[:=]\s*(?P<policy>{GUID})"))
}

fn policy_id_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        &format!(r"(?i)\bpolicy\s*(?:with\s+)?id\s*[:=]\s*(?P<policy>{GUID})"),
    )
}

fn policy_bare_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(&CELL, &format!(r"(?i)\bpolicy\s+(?P<policy>{GUID})\b"))
}

fn run_id_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        &format!(r"(?i)\b(?:run\s*id|execution\s*id)\s*[:=]\s*(?P<run>{GUID})"),
    )
}

fn invocation_field_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        r"(?i)\b(?:invocation|trigger|triggertype|schedule)\s*[:=]\s*(?P<invocation>scheduled|ondemand|on-demand|recurring)\b",
    )
}

fn on_demand_phrase_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(&CELL, r"(?i)\bon[\s-]?demand\b")
}

fn exit_code_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        r"(?i)\bexit\s*code\b(?:\s+of\s+the\s+script)?[^-\dxA-F]{0,12}(?P<code>-?(?:0x[0-9a-fA-F]+|\d+))",
    )
}

fn error_code_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        r"(?i)\berror(?:\s*code)?\s*[:=]\s*(?P<code>-?(?:0x[0-9a-fA-F]+|\d+))",
    )
}

fn attempt_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        r"(?i)\b(?:attempt|retry)\s*(?:#|number\s*)?(?P<attempt>\d+)\b",
    )
}

fn compliance_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        r"(?i)\bcompliance\s*(?:result|state)\s*[:=]\s*(?P<state>non-?compliant|compliant)\b",
    )
}

// ── Stage vocabulary ────────────────────────────────────────────────────────

fn post_detection_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        r"(?i)\bpost[\s-]?remediation\s+detection\b|\bpost[\s-]?detect(?:ion)?\b",
    )
}

fn detection_stage_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        r"(?i)\bdetection\s+script\b|\bpre[\s-]?detect(?:ion)?\b|\bdetect\.ps1\b",
    )
}

fn remediation_stage_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        r"(?i)\bremediation\s+script\b|\bremediate\.ps1\b|\bremediation\s+(?:is\s+)?(?:required|not\s+required|needed)\b",
    )
}

// ── Event vocabulary ────────────────────────────────────────────────────────

fn timeout_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        r"(?i)\btimeout\s+to\s+execute\b|\btimed\s*out\b|\bexceeded\s+the\s+(?:execution\s+)?timeout\b",
    )
}

fn launch_failed_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        r"(?i)\bfail(?:ed|ure)\s+to\s+(?:create|start|launch|spawn)\b",
    )
}

fn completed_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        r"(?i)\bexecution\s+is\s+done\b|\bscript\s+(?:execution\s+)?(?:completed|finished)\b|\b(?:detection|remediation)\s+script\s+(?:completed|finished|returned)\b|\bexit\s*code\s*(?:of\s+the\s+script\s*)?[:=]",
    )
}

fn launch_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        r"(?i)\bstart(?:ing|ed|s)?\s+(?:to\s+)?(?:execute|run|launch)\b|\bstarting\s+powershell\s+execution\b|\blaunch(?:ing)?\s+the\b",
    )
}

fn not_required_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        r"(?i)\bremediation\s+is\s+not\s+(?:required|needed)\b|\bno\s+remediation\s+(?:is\s+)?(?:required|needed)\b|\bskipping\s+(?:the\s+)?remediation\b",
    )
}

fn report_failed_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        r"(?i)\bfail(?:ed|ure)\s+to\s+(?:send|upload|report)\b|\bresult\s+send\s+failed\b",
    )
}

fn report_deferred_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        r"(?i)\bwill\s+retry\s+sending\b|\bresult\s+send\s+(?:is\s+)?deferred\b|\bdeferred\s+until\s+the\s+next\s+check[\s-]?in\b",
    )
}

fn report_submitted_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        r"(?i)\bresult\s+(?:has\s+been\s+)?sent\s+to\s+(?:the\s+)?service\s+successfully\b|\bresult\s+(?:was\s+)?(?:uploaded|reported)\s+successfully\b",
    )
}

fn report_sending_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        r"(?i)\bsend(?:ing)?\s+(?:the\s+)?(?:health\s+script\s+)?result\s+to\s+(?:the\s+)?service\b",
    )
}

fn retry_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        r"(?i)\bwill\s+retry\b|\bretrying\b|\bschedul(?:e|ing)\s+a\s+retry\b",
    )
}

fn scheduled_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        r"(?i)\bschedul(?:e|ed|ing)\s+(?:the\s+)?(?:health\s+script\s+)?(?:policy|run)\b|\bnext\s+run\s+time\b",
    )
}

fn policy_received_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        r"(?i)\bprocessing\s+(?:the\s+)?(?:health\s+script\s+)?policy\b|\bget\s+(?:health\s+script\s+)?policies\b|\breceived\s+polic(?:y|ies)\b",
    )
}

fn output_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        r"(?i)\b(?:stdout|stderr|script\s+output|output\s+file)\b",
    )
}

/// Outcome vocabulary for the unknown-version heuristic, matched on word
/// boundaries so that an ordinary `-ExecutionPolicy Bypass` argument is not
/// mistaken for an unrecognised execution outcome.
fn unknown_outcome_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        r"(?i)\b(?:exit|exits|exited|complete|completed|fail|fails|failed|failure|finish|finished|done|terminated|termination)\b",
    )
}

fn lifecycle_word_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        r"(?i)\b(?:powershell|detection|remediation|health\s*script)\b",
    )
}

/// An object-open immediately followed by a quoted key: the shape of an
/// embedded payload, and the only shape worth attempting to parse.
fn json_open_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(&CELL, r#"\{\s*""#)
}

/// The `[Subsystem]` prefix the shared IME log writes in front of a record that
/// belongs to a specific workload.
fn health_scripts_prefix_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(&CELL, r"(?i)^\s*\[health\s*scripts?\]")
}

/// Parse an exit/error token into every form it was observed in.
pub(crate) fn parse_error_code(raw: &str) -> IntuneErrorCode {
    let trimmed = raw.trim();
    let (negative, digits) = match trimmed.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, trimmed),
    };

    let (decimal, hex) = if let Some(hex) = digits
        .strip_prefix("0x")
        .or_else(|| digits.strip_prefix("0X"))
    {
        let value = i64::from_str_radix(hex, 16).ok();
        (
            value.map(|v| if negative { -v } else { v }),
            Some(format!("0x{}", hex.to_ascii_uppercase())),
        )
    } else {
        let value = digits.parse::<i64>().ok();
        let signed = value.map(|v| if negative { -v } else { v });
        // Only render the unsigned 32-bit view when the value actually fits it.
        // Truncating would print a different number than the log recorded.
        let hex = signed
            .and_then(|v| {
                u32::try_from(v)
                    .ok()
                    .or_else(|| i32::try_from(v).ok().map(|v| v as u32))
            })
            .map(|v| format!("0x{v:08X}"));
        (signed, hex)
    };

    IntuneErrorCode {
        raw: trimmed.to_string(),
        decimal,
        hex,
    }
}

/// Everything one record could prove.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordClassification {
    pub event: RemediationEvent,
    pub stage: Option<RemediationStage>,
    pub policy_id: Option<String>,
    pub run_id: Option<String>,
    pub invocation: RemediationInvocation,
    pub attempt: Option<u32>,
    pub exit_code: Option<IntuneErrorCode>,
    /// An explicit `compliance result = ...` statement, when the record made one.
    pub stated_compliance: Option<bool>,
    /// Payload fields this build does not model, preserved verbatim.
    pub retained_fields: Vec<IntuneNamedValue>,
    /// True when an embedded payload was present and could not be parsed.
    /// Such a record contributes no key, no stage, and no outcome.
    pub payload_malformed: bool,
    /// True when a parsed payload named a stage *and* that stage's result. A
    /// structured result payload is a completion record even when the prose
    /// around it says nothing this build recognises.
    pub payload_result: bool,
    /// True when the record looks like remediation execution but matched no
    /// event rule. The reducer turns this into lowered confidence, never a state.
    pub lifecycle_shaped_but_unmatched: bool,
    /// False when the record belongs to another workload sharing the same log.
    pub in_scope: bool,
}

impl RecordClassification {
    fn empty() -> Self {
        Self {
            event: RemediationEvent::Unclassified,
            stage: None,
            policy_id: None,
            run_id: None,
            invocation: RemediationInvocation::Unknown,
            attempt: None,
            exit_code: None,
            stated_compliance: None,
            retained_fields: Vec::new(),
            payload_malformed: false,
            payload_result: false,
            lifecycle_shaped_but_unmatched: false,
            in_scope: false,
        }
    }

    /// Does this record name a policy, and therefore anchor a run?
    pub fn is_key_bearing(&self) -> bool {
        self.policy_id.is_some()
    }
}

/// Whether a record's component puts it inside the remediation workload.
///
/// The shared IME log carries every workload's records, so a record there is in
/// scope only when it says it is: either the component is `HealthScripts` or
/// the message carries the `[HealthScripts]` subsystem prefix.
fn component_is_in_scope(
    source_kind: RemediationSourceKind,
    component: Option<&str>,
    message: &str,
) -> bool {
    let component_matches = |expected: &[&str]| {
        component.is_some_and(|component| {
            expected
                .iter()
                .any(|candidate| candidate.eq_ignore_ascii_case(component))
        })
    };

    match source_kind {
        RemediationSourceKind::HealthScripts => component_matches(&["HealthScripts"]),
        RemediationSourceKind::AgentExecutor => component_matches(&["AgentExecutor"]),
        RemediationSourceKind::IntuneManagementExtension => {
            component_matches(&["HealthScripts"])
                || (component_matches(&["IntuneManagementExtension"])
                    && health_scripts_prefix_re().is_match(message))
        }
        _ => false,
    }
}

/// The JSON span of a message, when it contains one.
///
/// An object that opens and never closes is still a payload -- a truncated one.
/// Returning the unterminated span makes the parse fail, which is the correct
/// reading: the record carried structured data this build could not read, and
/// the missing half belongs to whatever record actually contains it.
fn json_span(message: &str) -> Option<&str> {
    if !json_open_re().is_match(message) {
        return None;
    }
    let start = message.find('{')?;
    match message.rfind('}') {
        Some(end) if end > start => Some(&message[start..=end]),
        _ => Some(&message[start..]),
    }
}

/// What became of an embedded payload.
enum Payload {
    None,
    Malformed,
    Parsed(Map<String, Value>),
}

/// Parse an embedded payload without ever looking outside this record.
///
/// Fragments are never joined: a record holding only half an object is
/// malformed on its own terms, and the other half belongs to whatever record
/// actually contains it.
fn parse_payload(message: &str) -> Payload {
    let Some(span) = json_span(message) else {
        return Payload::None;
    };
    match serde_json::from_str::<Value>(span) {
        Ok(Value::Object(map)) => Payload::Parsed(map),
        // A well-formed non-object (an array, a bare string) is not the payload
        // shape this analyzer understands and is not treated as corruption.
        Ok(_) => Payload::None,
        Err(_) => Payload::Malformed,
    }
}

/// Render a payload value for retention without interpreting it.
fn render_value(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

fn stage_from_token(token: &str) -> Option<RemediationStage> {
    let normalized = token.trim().to_ascii_lowercase().replace(['-', '_', ' '], "");
    match normalized.as_str() {
        "detection" | "detect" | "predetection" | "predetect" => Some(RemediationStage::Detection),
        "remediation" | "remediate" => Some(RemediationStage::Remediation),
        "postremediationdetection" | "postremediation" | "postdetection" | "postdetect" => {
            Some(RemediationStage::PostRemediationDetection)
        }
        _ => None,
    }
}

fn invocation_from_token(token: &str) -> RemediationInvocation {
    match token
        .trim()
        .to_ascii_lowercase()
        .replace(['-', '_', ' '], "")
        .as_str()
    {
        "scheduled" | "recurring" | "schedule" => RemediationInvocation::Scheduled,
        "ondemand" | "manual" => RemediationInvocation::OnDemand,
        _ => RemediationInvocation::Unknown,
    }
}

/// Read the fields this build models out of a payload, retaining the rest.
fn apply_payload(map: &Map<String, Value>, result: &mut RecordClassification) {
    let mut retained = Vec::new();

    for (name, value) in map {
        let known = match name.to_ascii_lowercase().as_str() {
            "policyid" => {
                if let Value::String(text) = value {
                    result.policy_id = Some(text.to_ascii_lowercase());
                }
                true
            }
            "runid" | "executionid" => {
                if let Value::String(text) = value {
                    result.run_id = Some(text.to_ascii_lowercase());
                }
                true
            }
            "stage" | "scripttype" => {
                if let Value::String(text) = value {
                    if let Some(stage) = stage_from_token(text) {
                        result.stage = Some(stage);
                    }
                }
                true
            }
            "exitcode" => {
                match value {
                    Value::Number(number) => {
                        result.exit_code = Some(parse_error_code(&number.to_string()));
                    }
                    Value::String(text) => result.exit_code = Some(parse_error_code(text)),
                    _ => {}
                }
                true
            }
            "compliancestate" | "detectionstate" => {
                if let Value::String(text) = value {
                    match text.to_ascii_lowercase().replace('-', "").as_str() {
                        "compliant" => result.stated_compliance = Some(true),
                        "noncompliant" => result.stated_compliance = Some(false),
                        _ => {}
                    }
                }
                true
            }
            "invocation" | "triggertype" => {
                if let Value::String(text) = value {
                    let invocation = invocation_from_token(text);
                    if invocation != RemediationInvocation::Unknown {
                        result.invocation = invocation;
                    }
                }
                true
            }
            _ => false,
        };

        if !known {
            retained.push(IntuneNamedValue {
                name: name.clone(),
                value: render_value(value),
            });
        }
    }

    // `serde_json::Map` preserves insertion order unless the `preserve_order`
    // feature is off; sorting makes the output deterministic either way.
    retained.sort_by(|left, right| left.name.cmp(&right.name));
    result.retained_fields = retained;

    // A payload naming a stage and that stage's result is a completion record,
    // whatever the prose around it says. A payload naming only one of the two is
    // not: a stage without a result decides nothing, and a result without a
    // stage is exactly the unattributable exit code this module refuses to use.
    result.payload_result =
        result.stage.is_some() && (result.exit_code.is_some() || result.stated_compliance.is_some());
}

/// The stage a record named, from its script path or its own words.
fn extract_stage(message: &str) -> Option<RemediationStage> {
    if let Some(caps) = script_path_re().captures(message) {
        return match caps.name("script").map(|m| m.as_str().to_ascii_lowercase()) {
            Some(script) if script == "detect" => Some(RemediationStage::Detection),
            Some(script) if script == "remediate" => Some(RemediationStage::Remediation),
            _ => None,
        };
    }
    // Checked first: "post-remediation detection script" also matches the plain
    // detection vocabulary, and the specific reading is the correct one.
    if post_detection_re().is_match(message) {
        return Some(RemediationStage::PostRemediationDetection);
    }
    if detection_stage_re().is_match(message) {
        return Some(RemediationStage::Detection);
    }
    if remediation_stage_re().is_match(message) {
        return Some(RemediationStage::Remediation);
    }
    None
}

fn extract_ids(message: &str) -> (Option<String>, Option<String>) {
    if let Some(caps) = script_path_re().captures(message) {
        return (
            caps.name("policy").map(|m| m.as_str().to_ascii_lowercase()),
            caps.name("run").map(|m| m.as_str().to_ascii_lowercase()),
        );
    }
    let policy = policy_id_field_re()
        .captures(message)
        .or_else(|| policy_id_re().captures(message))
        .or_else(|| policy_bare_re().captures(message))
        .and_then(|caps| caps.name("policy").map(|m| m.as_str().to_ascii_lowercase()));
    let run = run_id_re()
        .captures(message)
        .and_then(|caps| caps.name("run").map(|m| m.as_str().to_ascii_lowercase()));
    (policy, run)
}

fn extract_invocation(message: &str) -> RemediationInvocation {
    if let Some(caps) = invocation_field_re().captures(message) {
        if let Some(token) = caps.name("invocation") {
            let invocation = invocation_from_token(token.as_str());
            if invocation != RemediationInvocation::Unknown {
                return invocation;
            }
        }
    }
    if on_demand_phrase_re().is_match(message) {
        return RemediationInvocation::OnDemand;
    }
    RemediationInvocation::Unknown
}

fn extract_compliance(message: &str) -> Option<bool> {
    compliance_re().captures(message).and_then(|caps| {
        caps.name("state").map(|state| {
            !state
                .as_str()
                .to_ascii_lowercase()
                .replace('-', "")
                .starts_with("noncompliant")
        })
    })
}

/// Classify one already-framed logical record.
pub fn classify_record(
    source_kind: RemediationSourceKind,
    component: Option<&str>,
    message: &str,
) -> RecordClassification {
    let mut result = RecordClassification::empty();

    // Identifiers are only read from a confirmed remediation source. Without
    // this gate a file that merely happens to be named `HealthScripts.log`, and
    // which source classification correctly refused to confirm, could still
    // mint a run from any line containing a GUID.
    if !component_is_in_scope(source_kind, component, message) {
        return result;
    }
    result.in_scope = true;

    match parse_payload(message) {
        Payload::Malformed => {
            // Conservative rejection: a record whose structured half we could
            // not read contributes nothing but the fact that it was malformed.
            result.event = RemediationEvent::MalformedPayload;
            result.payload_malformed = true;
            return result;
        }
        Payload::Parsed(map) => apply_payload(&map, &mut result),
        Payload::None => {}
    }

    let (policy_id, run_id) = extract_ids(message);
    result.policy_id = result.policy_id.or(policy_id);
    result.run_id = result.run_id.or(run_id);
    if result.stage.is_none() {
        result.stage = extract_stage(message);
    }
    if result.invocation == RemediationInvocation::Unknown {
        result.invocation = extract_invocation(message);
    }
    if result.stated_compliance.is_none() {
        result.stated_compliance = extract_compliance(message);
    }
    result.attempt = attempt_re()
        .captures(message)
        .and_then(|caps| caps.name("attempt"))
        .and_then(|value| value.as_str().parse::<u32>().ok());

    result.event = classify_event(message, &mut result);
    if result.event == RemediationEvent::Unclassified && result.payload_result {
        result.event = RemediationEvent::Completed;
    }

    if result.event == RemediationEvent::Unclassified
        && lifecycle_word_re().is_match(message)
        && unknown_outcome_re().is_match(message)
    {
        result.lifecycle_shaped_but_unmatched = true;
    }

    result
}

/// Decide what a record said, most specific reading first.
fn classify_event(message: &str, result: &mut RecordClassification) -> RemediationEvent {
    if timeout_re().is_match(message) {
        return RemediationEvent::TimedOut;
    }
    if launch_failed_re().is_match(message) {
        return RemediationEvent::LaunchFailed;
    }
    if report_failed_re().is_match(message) {
        if result.exit_code.is_none() {
            if let Some(code) = error_code_re()
                .captures(message)
                .and_then(|caps| caps.name("code"))
            {
                result.exit_code = Some(parse_error_code(code.as_str()));
            }
        }
        return RemediationEvent::ReportFailed;
    }
    if report_deferred_re().is_match(message) {
        return RemediationEvent::ReportRetryDeferred;
    }
    if report_submitted_re().is_match(message) {
        return RemediationEvent::ReportSubmitted;
    }
    if not_required_re().is_match(message) {
        return RemediationEvent::RemediationNotRequired;
    }
    if completed_re().is_match(message) {
        if result.exit_code.is_none() {
            if let Some(code) = exit_code_re()
                .captures(message)
                .and_then(|caps| caps.name("code"))
            {
                result.exit_code = Some(parse_error_code(code.as_str()));
            }
        }
        return RemediationEvent::Completed;
    }
    if retry_re().is_match(message) {
        return RemediationEvent::RetryScheduled;
    }
    if launch_re().is_match(message) {
        return RemediationEvent::Launched;
    }
    if scheduled_re().is_match(message) {
        return RemediationEvent::Scheduled;
    }
    if result.invocation == RemediationInvocation::OnDemand && on_demand_phrase_re().is_match(message)
    {
        return RemediationEvent::OnDemandRequested;
    }
    if policy_received_re().is_match(message) {
        return RemediationEvent::PolicyReceived;
    }
    if output_re().is_match(message) {
        return RemediationEvent::OutputCaptured;
    }
    // "Sending the health script result to service" is the attempt, not the
    // outcome, and must never be read as a submission.
    if report_sending_re().is_match(message) {
        return RemediationEvent::Unclassified;
    }
    RemediationEvent::Unclassified
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY: &str = "11111111-2222-3333-4444-555555555555";
    const RUN: &str = "66666666-7777-8888-9999-000000000000";

    fn health(message: &str) -> RecordClassification {
        classify_record(
            RemediationSourceKind::HealthScripts,
            Some("HealthScripts"),
            message,
        )
    }

    fn agent(message: &str) -> RecordClassification {
        classify_record(
            RemediationSourceKind::AgentExecutor,
            Some("AgentExecutor"),
            message,
        )
    }

    #[test]
    fn a_script_path_proves_policy_run_and_stage_at_once() {
        let result = agent(&format!(
            r"Powershell script is: C:\Windows\IMECache\HealthScripts\{POLICY}_{RUN}\detect.ps1"
        ));
        assert_eq!(result.policy_id.as_deref(), Some(POLICY));
        assert_eq!(result.run_id.as_deref(), Some(RUN));
        assert_eq!(result.stage, Some(RemediationStage::Detection));
    }

    #[test]
    fn a_remediation_script_path_reads_as_the_remediation_stage() {
        let result = agent(&format!(
            r"Powershell script is: C:\Windows\IMECache\HealthScripts\{POLICY}_{RUN}\remediate.ps1"
        ));
        assert_eq!(result.stage, Some(RemediationStage::Remediation));
    }

    #[test]
    fn an_exit_code_without_a_stage_carries_no_stage() {
        // The single most important rule in this module: the same code means
        // opposite things in the two stages.
        let result = agent("Powershell execution is done, exitCode = 1");
        assert_eq!(result.event, RemediationEvent::Completed);
        assert_eq!(result.stage, None);
        assert_eq!(result.exit_code.unwrap().decimal, Some(1));
    }

    #[test]
    fn post_remediation_detection_is_its_own_stage() {
        let result =
            health("Post-remediation detection script completed, exit code = 0, compliance result = Compliant");
        assert_eq!(result.stage, Some(RemediationStage::PostRemediationDetection));
        assert_eq!(result.stated_compliance, Some(true));
    }

    #[test]
    fn detection_and_remediation_phrases_do_not_bleed_into_each_other() {
        assert_eq!(
            health("Start to execute the detection script").stage,
            Some(RemediationStage::Detection)
        );
        assert_eq!(
            health("Start to execute the remediation script").stage,
            Some(RemediationStage::Remediation)
        );
    }

    #[test]
    fn timeout_outranks_a_trailing_exit_code() {
        let result = health("Timeout to execute the remediation script, exit code = 1");
        assert_eq!(result.event, RemediationEvent::TimedOut);
        assert_eq!(result.stage, Some(RemediationStage::Remediation));
    }

    #[test]
    fn launch_failure_is_distinct_from_a_nonzero_exit() {
        let result = health("Failed to create the process for the detection script");
        assert_eq!(result.event, RemediationEvent::LaunchFailed);
        assert!(result.exit_code.is_none());
    }

    #[test]
    fn a_compliance_statement_is_read_when_present() {
        let result = health("Detection script completed, exit code = 1, compliance result = NonCompliant, remediation is required");
        assert_eq!(result.stated_compliance, Some(false));
        assert_eq!(result.exit_code.unwrap().decimal, Some(1));
    }

    #[test]
    fn an_explicit_skip_is_its_own_event() {
        let result = health(&format!(
            "Detection reported compliant for policy {POLICY}, remediation is not required"
        ));
        assert_eq!(result.event, RemediationEvent::RemediationNotRequired);
        assert_eq!(result.policy_id.as_deref(), Some(POLICY));
    }

    #[test]
    fn reporting_success_failure_and_deferral_are_separate_events() {
        assert_eq!(
            health("Health script result has been sent to service successfully").event,
            RemediationEvent::ReportSubmitted
        );
        assert_eq!(
            health("Failed to send the health script result to service, error = 0x80072EE2").event,
            RemediationEvent::ReportFailed
        );
        assert_eq!(
            health("Result send is deferred, will retry sending at the next check-in").event,
            RemediationEvent::ReportRetryDeferred
        );
    }

    #[test]
    fn a_reporting_failure_keeps_its_error_code() {
        let result = health("Failed to send the health script result to service, error = 0x80072EE2");
        let code = result.exit_code.expect("error code");
        assert_eq!(code.raw, "0x80072EE2");
        assert_eq!(code.hex.as_deref(), Some("0x80072EE2"));
    }

    #[test]
    fn sending_a_result_is_not_the_same_as_having_sent_it() {
        assert_eq!(
            health(&format!(
                "Sending the health script result to service, PolicyId = {POLICY}"
            ))
            .event,
            RemediationEvent::Unclassified
        );
    }

    #[test]
    fn invocation_is_read_from_an_explicit_field_or_phrase() {
        assert_eq!(
            health(&format!(
                "Processing health script policy with id = {POLICY}, Invocation = Scheduled"
            ))
            .invocation,
            RemediationInvocation::Scheduled
        );
        assert_eq!(
            health(&format!(
                "On demand health script run requested for policy {POLICY}"
            ))
            .invocation,
            RemediationInvocation::OnDemand
        );
    }

    #[test]
    fn an_embedded_payload_is_read_losslessly() {
        let result = health(&format!(
            r#"Health script result payload: {{"PolicyId":"{POLICY}","RunId":"{RUN}","Stage":"Remediation","ExitCode":0,"ComplianceState":"Compliant","FutureField":"keep-me","Nested":{{"a":1}}}}"#
        ));
        assert_eq!(result.policy_id.as_deref(), Some(POLICY));
        assert_eq!(result.run_id.as_deref(), Some(RUN));
        assert_eq!(result.stage, Some(RemediationStage::Remediation));
        assert_eq!(result.exit_code.unwrap().decimal, Some(0));
        assert_eq!(result.stated_compliance, Some(true));
        assert_eq!(
            result.retained_fields,
            vec![
                IntuneNamedValue {
                    name: "FutureField".to_owned(),
                    value: "keep-me".to_owned()
                },
                IntuneNamedValue {
                    name: "Nested".to_owned(),
                    value: r#"{"a":1}"#.to_owned()
                },
            ]
        );
    }

    #[test]
    fn a_payload_naming_a_stage_and_its_result_is_a_completion_record() {
        let result = health(&format!(
            r#"Health script result payload: {{"PolicyId":"{POLICY}","RunId":"{RUN}","Stage":"PostRemediationDetection","ExitCode":0}}"#
        ));
        assert_eq!(result.event, RemediationEvent::Completed);
        assert_eq!(result.stage, Some(RemediationStage::PostRemediationDetection));
    }

    #[test]
    fn a_payload_naming_a_result_without_a_stage_is_not_a_completion() {
        // This is the unattributable exit code, arriving as structured data.
        let result = health(&format!(
            r#"Health script telemetry: {{"PolicyId":"{POLICY}","RunId":"{RUN}","ExitCode":1}}"#
        ));
        assert!(!result.payload_result);
        assert_eq!(result.event, RemediationEvent::Unclassified);
        assert_eq!(result.stage, None);
    }

    #[test]
    fn a_malformed_payload_yields_no_key_no_stage_and_no_outcome() {
        let result = health(&format!(
            r#"Health script result payload: {{"PolicyId":"{POLICY}","Stage":"Remediation","ExitCode":}}"#
        ));
        assert!(result.payload_malformed);
        assert_eq!(result.event, RemediationEvent::MalformedPayload);
        assert_eq!(result.policy_id, None);
        assert_eq!(result.stage, None);
        assert_eq!(result.exit_code, None);
    }

    #[test]
    fn payload_fragments_are_never_joined_across_records() {
        // Two records each holding half an object. Neither may be completed by
        // the other, and neither may key a run.
        let first = health(&format!(
            r#"Result payload: {{"PolicyId":"{POLICY}","Stage":"Remediation","#
        ));
        let second = health(r#""ExitCode":0}"#);
        assert!(first.payload_malformed);
        assert_eq!(first.policy_id, None);
        // The tail alone is not an object-open, so it is simply unclassified.
        assert!(!second.is_key_bearing());
    }

    #[test]
    fn a_record_outside_the_workload_is_out_of_scope() {
        let result = classify_record(
            RemediationSourceKind::IntuneManagementExtension,
            Some("Win32App"),
            &format!("Get policies for policy {POLICY}"),
        );
        assert!(!result.in_scope);
        assert_eq!(result.policy_id, None);
        assert_eq!(result.event, RemediationEvent::Unclassified);
    }

    #[test]
    fn the_shared_ime_log_is_in_scope_only_for_health_script_records() {
        let tagged = classify_record(
            RemediationSourceKind::IntuneManagementExtension,
            Some("IntuneManagementExtension"),
            &format!("[HealthScripts] Processing health script policy with id = {POLICY}"),
        );
        assert!(tagged.in_scope);
        assert_eq!(tagged.policy_id.as_deref(), Some(POLICY));

        let untagged = classify_record(
            RemediationSourceKind::IntuneManagementExtension,
            Some("IntuneManagementExtension"),
            &format!("Checking in with the service for policy {POLICY}"),
        );
        assert!(!untagged.in_scope);
    }

    #[test]
    fn an_unconfirmed_artifact_yields_no_identifiers_at_all() {
        let result = classify_record(
            RemediationSourceKind::Unknown,
            Some("HealthScripts"),
            &format!(r"Powershell script is: C:\IMECache\HealthScripts\{POLICY}_{RUN}\detect.ps1"),
        );
        assert_eq!(result.policy_id, None);
        assert_eq!(result.stage, None);
    }

    #[test]
    fn unrecognised_execution_wording_is_flagged_for_coverage_not_guessed() {
        let result = agent("Powershell runspace terminated in an unexpected condition");
        assert_eq!(result.event, RemediationEvent::Unclassified);
        assert!(result.lifecycle_shaped_but_unmatched);
    }

    #[test]
    fn an_execution_policy_argument_is_not_an_unknown_version_signal() {
        let result = agent(r"Launching: powershell.exe -ExecutionPolicy Bypass -File detect.ps1");
        assert!(!result.lifecycle_shaped_but_unmatched);
    }

    #[test]
    fn out_of_range_exit_codes_get_no_truncated_hex_view() {
        let code = parse_error_code("4294967297");
        assert_eq!(code.decimal, Some(4_294_967_297));
        assert_eq!(code.hex, None);
        assert_eq!(code.raw, "4294967297");
    }

    #[test]
    fn negative_and_hex_exit_codes_survive_round_trip() {
        assert_eq!(parse_error_code("-1").decimal, Some(-1));
        let hex = parse_error_code("0x80070005");
        assert_eq!(hex.decimal, Some(0x8007_0005));
        assert_eq!(hex.hex.as_deref(), Some("0x80070005"));
    }

    #[test]
    fn attempt_numbers_are_read_when_stated() {
        assert_eq!(
            health("Remediation script failed, will retry, attempt 2").attempt,
            Some(2)
        );
    }

    #[test]
    fn guids_are_normalised_to_lower_case() {
        let upper = POLICY.to_ascii_uppercase();
        assert_eq!(
            health(&format!("Processing health script policy with id = {upper}"))
                .policy_id
                .as_deref(),
            Some(POLICY)
        );
    }
}
