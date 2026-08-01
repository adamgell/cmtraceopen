//! Record-level classification for remediation evidence.
//!
//! Every rule answers one question about one record. Nothing here decides an
//! outcome or merges records.
//!
//! The stage rules carry the weight. `exitCode = 0` means "compliant" from a
//! detection script and "succeeded" from a remediation script, so a record that
//! does not name its stage yields no exit token at all rather than a token the
//! reducer might attribute to the wrong half.

use std::sync::OnceLock;

use regex::Regex;

use super::models::{
    RemediationExitToken, RemediationInvocation, RemediationSignal, RemediationSourceKind,
    RemediationStage,
};

const GUID: &str = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}";

fn re(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).expect("remediation regex must compile"))
}

/// Components whose records belong to the remediation workload.
///
/// The primary IME log is shared by every workload, so a bare `Win32App` record
/// there must not speak for remediations.
const HEALTH_SCRIPTS_COMPONENTS: &[&str] = &["HealthScripts"];
const AGENT_EXECUTOR_COMPONENTS: &[&str] = &["AgentExecutor"];
/// Components that let a record in the shared primary IME log speak for the
/// remediation workload.
///
/// `PowerShell` is deliberately absent. In the primary IME log that component
/// marks *platform-script* records, which `intune::apps::windows::scripts`
/// owns. Accepting it here would let one workload's reporting records become
/// the other's -- the same cross-workload contamination that gate exists to
/// prevent. Remediation orchestration is logged under `HealthScripts`.
///
/// Named for record scope; `sources.rs` has its own, wider list for confirming
/// that a *file* is the IME log at all.
const IME_RECORD_SCOPE_COMPONENTS: &[&str] = &["IntuneManagementExtension", "HealthScripts"];

fn component_is_in_scope(source_kind: RemediationSourceKind, component: Option<&str>) -> bool {
    let expected: &[&str] = match source_kind {
        RemediationSourceKind::HealthScripts => HEALTH_SCRIPTS_COMPONENTS,
        RemediationSourceKind::AgentExecutor => AGENT_EXECUTOR_COMPONENTS,
        RemediationSourceKind::IntuneManagementExtension => IME_RECORD_SCOPE_COMPONENTS,
        _ => return false,
    };
    component.is_some_and(|component| {
        expected
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(component))
    })
}

fn policy_id_field_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        &format!(r"(?i)\b(?:PolicyId|PackageId)\s*[:=]\s*(?P<policy>{GUID})"),
    )
}

fn policy_id_phrase_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        &format!(r"(?i)\bpolicy\s+(?:with\s+)?(?:id\s*[:=]\s*)?(?P<policy>{GUID})"),
    )
}

fn run_id_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        &format!(r"(?i)\b(?:run\s*id|executionId)\s*[:=]\s*(?P<run>{GUID})"),
    )
}

/// The script path form used for remediation content.
fn script_path_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        &format!(
            r"(?i)[\\/]HealthScripts[\\/](?P<policy>{GUID})_(?P<run>{GUID})[\\/]?(?P<stage>detect|remediate)?"
        ),
    )
}

fn detection_stage_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(&CELL, r"(?i)\bdetect(?:ion)?\s+script\b|\bdetection\b")
}

fn remediation_stage_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        r"(?i)\bremediat(?:ion|e)\s+script\b|\bremediation\b|\bremediating\b",
    )
}

fn post_detection_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        r"(?i)\bpost[-\s]?remediation\s+detection\b|\bre[-\s]?detection\b|\bdetection\s+after\s+remediation\b",
    )
}

fn on_demand_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(&CELL, r"(?i)\bon[-\s]?demand\b|\bmanually\s+triggered\b")
}

fn scheduled_invocation_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(&CELL, r"(?i)\bscheduled\s+run\b|\bon\s+schedule\b")
}

fn exit_code_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        r"(?i)\b(?:exit\s*code|exitCode)\b[^-\dxA-F]{0,12}(?P<code>-?(?:0x[0-9a-fA-F]+|\d+))",
    )
}

fn attempt_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        r"(?i)\b(?:attempt|retry)\s*(?:#|number\s*)?(?P<attempt>\d+)\b",
    )
}

fn launched_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        r"(?i)\b(?:start(?:ing)?|launch(?:ing)?|executing|running)\b",
    )
}

fn completed_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(&CELL, r"(?i)\b(?:completed?|finished|is\s+done|returned)\b")
}

fn launch_failed_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        r"(?i)\bfail(?:ed|ure)\s+to\s+(?:create|start|launch|spawn)\b|\bcould\s+not\s+start\b",
    )
}

fn timed_out_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        r"(?i)\btimeout\s+to\s+execute\b|\btimed\s+out\b|\bkill(?:ed|ing)?\s+the\s+process\b",
    )
}

fn policy_received_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        r"(?i)\bprocessing\s+(?:health\s+)?(?:script|policy)\b|\breceived\s+policy\b|\bget\s+policies\b",
    )
}

fn scheduled_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        r"(?i)\bschedul(?:e|ed|ing)\s+(?:the\s+)?(?:policy|script|run)\b|\bnext\s+run\s+time\b",
    )
}

fn retry_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        r"(?i)\bwill\s+retry\b|\bretrying\b|\bscheduling\s+a\s+retry\b",
    )
}

fn report_sent_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        r"(?i)\bresult\s+(?:has\s+been\s+)?sent\s+to\s+(?:the\s+)?service\s+successfully\b",
    )
}

fn report_failed_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        r"(?i)\bfail(?:ed|ure)\s+to\s+send\s+(?:the\s+)?(?:result|report)\b",
    )
}

fn output_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        r"(?i)\b(?:output|stdout|stderr|error)\s+file\b|\bscript\s+output\b",
    )
}

/// Everything one record could prove.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordClassification {
    pub signal: RemediationSignal,
    pub stage: Option<RemediationStage>,
    pub policy_id: Option<String>,
    pub run_id: Option<String>,
    pub invocation: RemediationInvocation,
    pub attempt: Option<u32>,
    pub exit_token: Option<RemediationExitToken>,
    /// Braces that looked like a JSON payload, with whether they parsed.
    pub payload: Option<(String, bool)>,
    /// The record named a stage outcome in wording we have no rule for.
    pub stage_shaped_but_unmatched: bool,
    /// False when the record belongs to another workload sharing the same log.
    pub in_scope: bool,
}

impl RecordClassification {
    fn empty() -> Self {
        Self {
            signal: RemediationSignal::Unclassified,
            stage: None,
            policy_id: None,
            run_id: None,
            invocation: RemediationInvocation::Unknown,
            attempt: None,
            exit_token: None,
            payload: None,
            stage_shaped_but_unmatched: false,
            in_scope: false,
        }
    }

    pub fn is_key_bearing(&self) -> bool {
        self.policy_id.is_some()
    }
}

fn parse_exit_token(stage: RemediationStage, raw: &str) -> RemediationExitToken {
    let trimmed = raw.trim();
    let (negative, digits) = match trimmed.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, trimmed),
    };

    // Parse first, then render. Deriving `hex_text` from the source text made
    // the same code render two ways (`0x1` vs `0x00000001`), dropped the sign
    // (`-0x1` rendered as `0x1` while `-1` rendered as `0xFFFFFFFF`), and could
    // leave a hex form present when the value was unreadable.
    let decimal = if let Some(hex) = digits
        .strip_prefix("0x")
        .or_else(|| digits.strip_prefix("0X"))
    {
        i64::from_str_radix(hex, 16).ok()
    } else {
        digits.parse::<i64>().ok()
    }
    .map(|value| if negative { -value } else { value });

    // A value outside the unsigned 32-bit view gets no hex form rather than a
    // truncated one that would print a different number.
    let hex_text = decimal
        .and_then(|value| {
            u32::try_from(value)
                .ok()
                .or_else(|| i32::try_from(value).ok().map(|value| value as u32))
        })
        .map(|value| format!("0x{value:08X}"));

    RemediationExitToken {
        stage,
        raw_text: trimmed.to_string(),
        decimal,
        hex_text,
    }
}

/// Which stage a record speaks for, or `None` when it does not say.
///
/// Post-detection is checked first because "post-remediation detection"
/// contains both other vocabularies and would otherwise match the wrong one.
fn extract_stage(message: &str) -> Option<RemediationStage> {
    if post_detection_re().is_match(message) {
        return Some(RemediationStage::PostDetection);
    }
    let detection = detection_stage_re().is_match(message);
    let remediation = remediation_stage_re().is_match(message);
    match (detection, remediation) {
        (true, false) => Some(RemediationStage::Detection),
        (false, true) => Some(RemediationStage::Remediation),
        // Naming both, or neither, is not naming one.
        _ => None,
    }
}

fn extract_invocation(message: &str) -> RemediationInvocation {
    if on_demand_re().is_match(message) {
        RemediationInvocation::OnDemand
    } else if scheduled_invocation_re().is_match(message) {
        RemediationInvocation::Scheduled
    } else {
        RemediationInvocation::Unknown
    }
}

/// The stage named by a script path, e.g. `...\{policy}_{run}\detect.ps1`.
///
/// The path states the stage as plainly as the prose does, and `detect.ps1`
/// matches none of the prose rules -- they require the word `script` to follow.
fn stage_from_script_path(message: &str) -> Option<RemediationStage> {
    let caps = script_path_re().captures(message)?;
    match caps.name("stage")?.as_str().to_ascii_lowercase().as_str() {
        "detect" => Some(RemediationStage::Detection),
        "remediate" => Some(RemediationStage::Remediation),
        _ => None,
    }
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
        .or_else(|| policy_id_phrase_re().captures(message))
        .and_then(|caps| caps.name("policy").map(|m| m.as_str().to_ascii_lowercase()));
    let run = run_id_re()
        .captures(message)
        .and_then(|caps| caps.name("run").map(|m| m.as_str().to_ascii_lowercase()));
    (policy, run)
}

/// Extract a balanced top-level `{...}` span and report whether it parsed.
///
/// Fragments are never concatenated across records: only a span that both opens
/// and closes inside this one message is considered.
fn extract_payload(message: &str) -> Option<(String, bool)> {
    let start = message.find('{')?;
    let bytes = message.as_bytes();
    let mut depth = 0i32;
    let mut end = None;
    // Braces inside a JSON string are data, not structure. Detection scripts
    // emit arbitrary text into these fields, so a `}` inside a string value is
    // ordinary; counting it would truncate the payload and then report the
    // truncation as malformed.
    let mut in_string = false;
    let mut escaped = false;
    for (index, byte) in bytes.iter().enumerate().skip(start) {
        if escaped {
            escaped = false;
            continue;
        }
        match byte {
            b'\\' if in_string => escaped = true,
            b'"' => in_string = !in_string,
            b'{' if !in_string => depth += 1,
            b'}' if !in_string => {
                depth -= 1;
                if depth == 0 {
                    end = Some(index + 1);
                    break;
                }
            }
            _ => {}
        }
    }
    let end = end?;
    let raw = &message[start..end];
    let parsed = serde_json::from_str::<serde_json::Value>(raw).is_ok();
    Some((raw.to_string(), parsed))
}

/// Classify one already-framed logical record.
pub fn classify_record(
    source_kind: RemediationSourceKind,
    component: Option<&str>,
    message: &str,
) -> RecordClassification {
    let mut result = RecordClassification::empty();

    if !component_is_in_scope(source_kind, component) {
        return result;
    }
    result.in_scope = true;

    let (policy_id, run_id) = extract_ids(message);
    result.policy_id = policy_id;
    result.run_id = run_id;
    result.stage = extract_stage(message).or_else(|| stage_from_script_path(message));
    result.invocation = extract_invocation(message);
    result.attempt = attempt_re()
        .captures(message)
        .and_then(|caps| caps.name("attempt"))
        .and_then(|m| m.as_str().parse::<u32>().ok());
    result.payload = extract_payload(message);

    result.signal = classify_signal(message, &mut result);

    if result.signal == RemediationSignal::Unclassified && looks_like_stage_outcome(message) {
        result.stage_shaped_but_unmatched = true;
    }

    result
}

/// Mentions a stage plus an outcome word, but matched no rule -- how an
/// unrecognised agent version usually shows up.
fn looks_like_stage_outcome(message: &str) -> bool {
    let mentions_stage =
        detection_stage_re().is_match(message) || remediation_stage_re().is_match(message);
    mentions_stage && exit_code_re().is_match(message)
}

fn classify_signal(message: &str, result: &mut RecordClassification) -> RemediationSignal {
    if report_failed_re().is_match(message) {
        return RemediationSignal::ReportFailed;
    }
    if report_sent_re().is_match(message) {
        return RemediationSignal::ReportSubmitted;
    }
    if timed_out_re().is_match(message) {
        return RemediationSignal::StageTimedOut;
    }
    if launch_failed_re().is_match(message) {
        return RemediationSignal::StageLaunchFailed;
    }

    if completed_re().is_match(message) {
        // The exit token is only produced when the record named its stage.
        // Without one, `0` is ambiguous between "compliant" and "succeeded".
        if let (Some(stage), Some(code)) = (
            result.stage,
            exit_code_re()
                .captures(message)
                .and_then(|caps| caps.name("code")),
        ) {
            result.exit_token = Some(parse_exit_token(stage, code.as_str()));
        }
        return RemediationSignal::StageCompleted;
    }

    if output_re().is_match(message) {
        return RemediationSignal::OutputCaptured;
    }
    if retry_re().is_match(message) {
        return RemediationSignal::RetryScheduled;
    }
    if scheduled_re().is_match(message) {
        return RemediationSignal::Scheduled;
    }
    if policy_received_re().is_match(message) {
        return RemediationSignal::PolicyReceived;
    }
    if launched_re().is_match(message) && result.stage.is_some() {
        return RemediationSignal::StageLaunched;
    }
    RemediationSignal::Unclassified
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY: &str = "11111111-1111-4111-8111-111111111111";
    const RUN: &str = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaa1";

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
    fn detection_and_remediation_stages_are_distinguished() {
        assert_eq!(
            health("Detection script completed, exitCode = 0").stage,
            Some(RemediationStage::Detection)
        );
        assert_eq!(
            health("Remediation script completed, exitCode = 0").stage,
            Some(RemediationStage::Remediation)
        );
    }

    #[test]
    fn post_remediation_detection_is_its_own_stage() {
        // The phrase contains both other vocabularies; it must not be mistaken
        // for a plain detection or a remediation.
        assert_eq!(
            health("Post-remediation detection completed, exitCode = 0").stage,
            Some(RemediationStage::PostDetection)
        );
    }

    #[test]
    fn a_record_naming_both_stages_names_neither() {
        assert_eq!(
            health("Comparing detection and remediation results").stage,
            None
        );
    }

    #[test]
    fn an_exit_code_without_a_stage_yields_no_token() {
        // This is the core safety property: `0` means "compliant" for
        // detection and "succeeded" for remediation. Guessing inverts the
        // diagnosis, so an unstaged code produces nothing.
        let result = agent("Powershell execution is done, exitCode = 0");
        assert_eq!(result.stage, None);
        assert!(result.exit_token.is_none());
    }

    #[test]
    fn a_staged_exit_code_is_attributed_to_that_stage() {
        let token = health("Detection script completed, exitCode = 1")
            .exit_token
            .unwrap();
        assert_eq!(token.stage, RemediationStage::Detection);
        assert_eq!(token.decimal, Some(1));
    }

    #[test]
    fn out_of_range_exit_codes_get_no_truncated_hex_view() {
        let token = health("Remediation script completed, exitCode = 4294967297")
            .exit_token
            .unwrap();
        assert_eq!(token.decimal, Some(4_294_967_297));
        assert_eq!(token.hex_text, None);
    }

    #[test]
    fn script_path_yields_both_key_halves() {
        let result = health(&format!(
            r"Running C:\Windows\IMECache\HealthScripts\{POLICY}_{RUN}\detect.ps1"
        ));
        assert_eq!(result.policy_id.as_deref(), Some(POLICY));
        assert_eq!(result.run_id.as_deref(), Some(RUN));
    }

    #[test]
    fn on_demand_and_scheduled_invocations_are_read_from_the_record() {
        assert_eq!(
            health("Starting on-demand remediation script").invocation,
            RemediationInvocation::OnDemand
        );
        assert_eq!(
            health("Starting scheduled run of detection script").invocation,
            RemediationInvocation::Scheduled
        );
        assert_eq!(
            health("Starting detection script").invocation,
            RemediationInvocation::Unknown
        );
    }

    #[test]
    fn timeout_outranks_a_trailing_exit_code() {
        assert_eq!(
            health("Detection script timed out, exitCode = 1").signal,
            RemediationSignal::StageTimedOut
        );
    }

    #[test]
    fn launch_failure_is_distinct_from_a_nonzero_exit() {
        let result = health("Failed to create process for the remediation script");
        assert_eq!(result.signal, RemediationSignal::StageLaunchFailed);
        assert!(result.exit_token.is_none());
    }

    #[test]
    fn a_well_formed_embedded_payload_is_preserved_and_marked_parsed() {
        let result =
            health(r#"Detection script completed with result {"Compliant":false,"Detail":"x"}"#);
        let (raw, parsed) = result.payload.unwrap();
        assert!(parsed);
        assert!(raw.contains("\"Compliant\":false"));
    }

    #[test]
    fn a_malformed_payload_is_reported_not_repaired() {
        let result = health(r#"Detection script completed with result {"Compliant":}"#);
        let (raw, parsed) = result.payload.unwrap();
        assert!(!parsed);
        assert_eq!(raw, r#"{"Compliant":}"#);
    }

    #[test]
    fn a_brace_inside_a_json_string_does_not_close_the_payload() {
        let result = health(
            r#"Detection script completed with result {"Detail":"a } b","Compliant":false}"#,
        );
        let (raw, parsed) = result.payload.unwrap();
        assert!(parsed, "got {raw}");
        assert!(raw.ends_with(r#""Compliant":false}"#), "got {raw}");
    }

    #[test]
    fn an_escaped_quote_inside_a_json_string_is_handled() {
        let result =
            health(r#"Detection script completed with result {"Detail":"say \" }","Ok":true}"#);
        let (raw, parsed) = result.payload.unwrap();
        assert!(parsed, "got {raw}");
    }

    #[test]
    fn a_script_path_names_its_own_stage() {
        let result = health(&format!(
            r"Running C:\Windows\IMECache\HealthScripts\{POLICY}_{RUN}\detect.ps1"
        ));
        assert_eq!(result.stage, Some(RemediationStage::Detection));
        let result = health(&format!(
            r"Running C:\Windows\IMECache\HealthScripts\{POLICY}_{RUN}\remediate.ps1"
        ));
        assert_eq!(result.stage, Some(RemediationStage::Remediation));
    }

    #[test]
    fn hex_and_decimal_exit_codes_render_the_same_way() {
        let from_hex = health("Detection script completed, exitCode = 0x1")
            .exit_token
            .unwrap();
        let from_decimal = health("Detection script completed, exitCode = 1")
            .exit_token
            .unwrap();
        assert_eq!(from_hex.decimal, from_decimal.decimal);
        assert_eq!(from_hex.hex_text, from_decimal.hex_text);
        assert_eq!(from_hex.hex_text.as_deref(), Some("0x00000001"));
    }

    #[test]
    fn a_negative_hex_exit_code_keeps_its_sign() {
        let token = health("Detection script completed, exitCode = -0x1")
            .exit_token
            .unwrap();
        assert_eq!(token.decimal, Some(-1));
        assert_eq!(token.hex_text.as_deref(), Some("0xFFFFFFFF"));
    }

    #[test]
    fn an_unreadable_exit_code_carries_no_hex_form() {
        let token = health("Detection script completed, exitCode = 0xFFFFFFFFFFFFFFFFF")
            .exit_token
            .unwrap();
        assert_eq!(token.decimal, None);
        assert_eq!(token.hex_text, None);
    }

    #[test]
    fn an_unterminated_payload_is_not_captured() {
        // Never concatenate across records to close a brace.
        let result = health(r#"Detection script emitting {"Compliant":false"#);
        assert!(result.payload.is_none());
    }

    #[test]
    fn other_workload_components_are_out_of_scope() {
        let result = classify_record(
            RemediationSourceKind::IntuneManagementExtension,
            Some("Win32App"),
            &format!("Processing policy {POLICY}"),
        );
        assert!(!result.in_scope);
        assert_eq!(result.policy_id, None);
    }

    #[test]
    fn unrecognised_stage_wording_is_flagged_for_coverage_not_guessed() {
        let result = health("Detection script reached an unrecognised condition, exitCode = 7");
        assert_eq!(result.signal, RemediationSignal::Unclassified);
        assert!(result.stage_shaped_but_unmatched);
    }

    #[test]
    fn a_powershell_component_record_cannot_report_for_remediations() {
        // In the primary IME log `PowerShell` marks platform-script records,
        // which `intune::apps::windows::scripts` owns. Accepting it here would
        // make one workload's reporting record become the other's.
        let result = classify_record(
            RemediationSourceKind::IntuneManagementExtension,
            Some("PowerShell"),
            "Result has been sent to service successfully",
        );
        assert!(!result.in_scope);
        assert_eq!(result.signal, RemediationSignal::Unclassified);
    }

    #[test]
    fn health_scripts_component_can_report_in_the_primary_ime_log() {
        let result = classify_record(
            RemediationSourceKind::IntuneManagementExtension,
            Some("HealthScripts"),
            "Result has been sent to service successfully",
        );
        assert!(result.in_scope);
        assert_eq!(result.signal, RemediationSignal::ReportSubmitted);
    }

    #[test]
    fn a_completion_that_does_not_state_its_stage_yields_no_token() {
        // Deliberate: a stage may be inherited for routing but never for
        // interpreting a code. See the module docs.
        let result = health("Script completed, exitCode = 0");
        assert_eq!(result.signal, RemediationSignal::StageCompleted);
        assert_eq!(result.stage, None);
        assert!(result.exit_token.is_none());
    }

    #[test]
    fn report_success_and_failure_are_separate_signals() {
        assert_eq!(
            health("Result has been sent to service successfully").signal,
            RemediationSignal::ReportSubmitted
        );
        assert_eq!(
            health("Failed to send result to service").signal,
            RemediationSignal::ReportFailed
        );
    }
}
