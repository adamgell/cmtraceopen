//! Record-level classification for platform-script evidence.
//!
//! Every rule here answers one question about one record: what did this line
//! *say*? Nothing in this module decides an outcome, merges records, or infers
//! a value that is not written down. That is the reducer's job, and it only
//! gets to work from what these rules could actually prove.

use std::sync::OnceLock;

use regex::Regex;

use super::models::{
    ScriptExecutionContext, ScriptExitToken, ScriptInterpreterBitness, ScriptSignal,
    ScriptSourceKind,
};

const GUID: &str = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}";

fn re(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).expect("platform-script regex must compile"))
}

/// `...\Policies\Scripts\{policyId}_{runId}.ps1` -- the strongest identity in
/// the AgentExecutor log, because it names both halves of the key at once.
fn script_path_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        &format!(r"(?i)[\\/]Scripts[\\/](?P<policy>{GUID})_(?P<run>{GUID})\.ps1"),
    )
}

/// Result artifacts use the same `{policyId}_{runId}` stem.
fn result_path_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        &format!(r"(?i)[\\/]Results[\\/](?P<policy>{GUID})_(?P<run>{GUID})\.(?:output|error)"),
    )
}

fn policy_id_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        &format!(r"(?i)policy\s*(?:with\s+)?id\s*[:=]\s*(?P<policy>{GUID})"),
    )
}

fn policy_id_field_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        &format!(r"(?i)\bPolicyId\s*[:=]\s*(?P<policy>{GUID})"),
    )
}

/// `Schedule policy <guid> for execution` -- the IME log names a policy this
/// way too, without an `id =` label.
fn policy_bare_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(&CELL, &format!(r"(?i)\bpolicy\s+(?P<policy>{GUID})\b"))
}

fn run_id_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        &format!(r"(?i)\b(?:run\s*id|executionId)\s*[:=]\s*(?P<run>{GUID})"),
    )
}

fn context_field_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        r"(?i)\b(?:ExecutionContext|RunAsAccount|context)\s*[:=]\s*(?P<context>system|user)\b",
    )
}

fn context_phrase_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(&CELL, r"(?i)\bin\s+(?P<context>system|user)\s+context\b")
}

fn bitness_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(&CELL, r"(?i)\b(?P<bits>32|64)[\s-]?bit\b")
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

fn launch_start_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        r"(?i)\bstart(?:ing)?\s+(?:the\s+)?powershell\s+(?:execution|host|process)\b",
    )
}

fn launch_failed_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        r"(?i)\bfail(?:ed|ure)\s+to\s+(?:create|start|launch|spawn)\s+(?:the\s+)?(?:process|powershell|script)\b",
    )
}

fn execution_done_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        r"(?i)\bpowershell\s+execution\s+is\s+done\b|\bprocess\s+exit\s+code\s+is\b",
    )
}

fn timeout_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        r"(?i)\btimeout\s+to\s+execute\s+the\s+script\b|\bscript\s+(?:execution\s+)?timed\s+out\b",
    )
}

fn retry_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        r"(?i)\bwill\s+retry\b|\bretrying\b|\bscheduling\s+a\s+retry\b",
    )
}

fn policy_received_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        r"(?i)\bprocessing\s+policy\s+with\s+id\b|\breceived\s+policy\b|\bget\s+policies\b",
    )
}

fn scheduled_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        r"(?i)\bschedul(?:e|ed|ing)\s+(?:the\s+)?(?:policy|script)\b|\bnext\s+run\s+time\b",
    )
}

fn report_sent_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        r"(?i)\bresult\s+(?:has\s+been\s+)?sent\s+to\s+(?:the\s+)?service\s+successfully\b|\breport(?:ed|ing)?\s+result\s+succe(?:ss|ssfully|eded)\b",
    )
}

fn report_failed_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        r"(?i)\bfail(?:ed|ure)\s+to\s+send\s+(?:the\s+)?(?:result|report)\b|\bresult\s+send\s+failed\b",
    )
}

fn report_sending_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        r"(?i)\bsend(?:ing)?\s+(?:the\s+)?result\s+to\s+(?:the\s+)?service\b",
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
    pub signal: ScriptSignal,
    pub policy_id: Option<String>,
    pub run_id: Option<String>,
    pub context: ScriptExecutionContext,
    pub bitness: ScriptInterpreterBitness,
    pub attempt: Option<u32>,
    pub exit_token: Option<ScriptExitToken>,
    /// True when the record looks like platform-script execution but matched no
    /// signal rule. The reducer turns this into a coverage flag, never a state.
    pub execution_shaped_but_unmatched: bool,
}

impl RecordClassification {
    fn empty() -> Self {
        Self {
            signal: ScriptSignal::Unclassified,
            policy_id: None,
            run_id: None,
            context: ScriptExecutionContext::Unknown,
            bitness: ScriptInterpreterBitness::Unknown,
            attempt: None,
            exit_token: None,
            execution_shaped_but_unmatched: false,
        }
    }

    /// Does this record name a policy, and therefore anchor a transaction?
    pub fn is_key_bearing(&self) -> bool {
        self.policy_id.is_some()
    }
}

fn parse_exit_token(raw: &str) -> ScriptExitToken {
    let trimmed = raw.trim();
    let (negative, digits) = match trimmed.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, trimmed),
    };

    let (decimal, hex_text) = if let Some(hex) = digits
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
        // Render the hex form for the unsigned 32-bit view operators expect.
        let hex_text = signed.map(|v| format!("0x{:08X}", v as u32));
        (signed, hex_text)
    };

    ScriptExitToken {
        raw_text: trimmed.to_string(),
        decimal,
        hex_text,
    }
}

fn extract_context(message: &str) -> ScriptExecutionContext {
    let captured = context_field_re()
        .captures(message)
        .or_else(|| context_phrase_re().captures(message));

    match captured
        .and_then(|caps| {
            caps.name("context")
                .map(|m| m.as_str().to_ascii_lowercase())
        })
        .as_deref()
    {
        Some("system") => ScriptExecutionContext::System,
        Some("user") => ScriptExecutionContext::User,
        _ => ScriptExecutionContext::Unknown,
    }
}

fn extract_bitness(message: &str) -> ScriptInterpreterBitness {
    match bitness_re()
        .captures(message)
        .and_then(|caps| caps.name("bits").map(|m| m.as_str()))
    {
        Some("32") => ScriptInterpreterBitness::Bit32,
        Some("64") => ScriptInterpreterBitness::Bit64,
        _ => ScriptInterpreterBitness::Unknown,
    }
}

/// Pull the policy/run pair out of a record, preferring the script path because
/// it proves both halves in one token.
fn extract_ids(message: &str) -> (Option<String>, Option<String>) {
    for pattern in [script_path_re(), result_path_re()] {
        if let Some(caps) = pattern.captures(message) {
            return (
                caps.name("policy").map(|m| m.as_str().to_ascii_lowercase()),
                caps.name("run").map(|m| m.as_str().to_ascii_lowercase()),
            );
        }
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

/// Classify one already-framed logical record.
///
/// `source_kind` gates which vocabulary applies: an `AgentExecutor` phrase in
/// the primary IME log is not treated as an execution record, because the two
/// files describe different halves of the lifecycle.
pub fn classify_record(source_kind: ScriptSourceKind, message: &str) -> RecordClassification {
    let mut result = RecordClassification::empty();

    // Identifiers are only extracted from a *confirmed* platform-script source.
    //
    // Without this gate, an artifact that merely happens to be named
    // `AgentExecutor.log` -- and which `classify_artifact` correctly refused to
    // confirm -- could still mint a transaction from any line that happened to
    // contain a policy GUID. HealthScripts is excluded for the same reason from
    // the other direction: it is remediation evidence, and until #360 defines
    // the handoff, letting it carry a key would attach remediation records to a
    // platform-script transaction.
    if !matches!(
        source_kind,
        ScriptSourceKind::AgentExecutor | ScriptSourceKind::IntuneManagementExtension
    ) {
        return result;
    }

    let (policy_id, run_id) = extract_ids(message);
    result.policy_id = policy_id;
    result.run_id = run_id;
    result.context = extract_context(message);
    result.bitness = extract_bitness(message);
    result.attempt = attempt_re()
        .captures(message)
        .and_then(|caps| caps.name("attempt"))
        .and_then(|m| m.as_str().parse::<u32>().ok());

    result.signal = match source_kind {
        ScriptSourceKind::AgentExecutor => classify_agent_executor(message, &mut result),
        ScriptSourceKind::IntuneManagementExtension => classify_ime(message),
        // HealthScripts records are remediation evidence. They are only carried
        // as supplemental context and never classified into a script signal
        // here; issue #360 owns that lifecycle.
        _ => ScriptSignal::Unclassified,
    };

    if source_kind == ScriptSourceKind::AgentExecutor
        && result.signal == ScriptSignal::Unclassified
        && looks_like_execution(message)
    {
        result.execution_shaped_but_unmatched = true;
    }

    result
}

/// Outcome vocabulary for the unknown-version heuristic.
///
/// Matched on word boundaries rather than as substrings. A substring test
/// treats the perfectly ordinary `-ExecutionPolicy Bypass` as an unrecognised
/// execution outcome, which would flag a healthy bundle as an unknown agent
/// version and drop every transaction in it to low confidence.
fn unknown_outcome_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        r"(?i)\b(?:exit|exits|exited|completed?|fail|fails|failed|failure|finish|finished|done|terminated|termination)\b",
    )
}

/// Execution-shaped but unmatched: mentions powershell plus an outcome word,
/// which is how an unrecognised agent version usually shows up.
///
/// The vocabulary is deliberately narrow. It must not match the key-bearing
/// `Powershell script is: ...` record, which is unclassified by design and
/// present in every healthy bundle.
fn looks_like_execution(message: &str) -> bool {
    message.to_ascii_lowercase().contains("powershell") && unknown_outcome_re().is_match(message)
}

fn classify_agent_executor(message: &str, result: &mut RecordClassification) -> ScriptSignal {
    if timeout_re().is_match(message) {
        return ScriptSignal::ExecutionTimedOut;
    }
    if launch_failed_re().is_match(message) {
        return ScriptSignal::LaunchFailed;
    }
    if execution_done_re().is_match(message) {
        if let Some(code) = exit_code_re()
            .captures(message)
            .and_then(|caps| caps.name("code"))
        {
            result.exit_token = Some(parse_exit_token(code.as_str()));
        }
        return ScriptSignal::ExecutionCompleted;
    }
    if launch_start_re().is_match(message) {
        return ScriptSignal::LaunchAttempted;
    }
    if output_re().is_match(message) {
        return ScriptSignal::OutputCaptured;
    }
    ScriptSignal::Unclassified
}

fn classify_ime(message: &str) -> ScriptSignal {
    if report_failed_re().is_match(message) {
        return ScriptSignal::ReportFailed;
    }
    if report_sent_re().is_match(message) {
        return ScriptSignal::ReportSubmitted;
    }
    if retry_re().is_match(message) {
        return ScriptSignal::RetryScheduled;
    }
    if scheduled_re().is_match(message) {
        return ScriptSignal::Scheduled;
    }
    if policy_received_re().is_match(message) {
        return ScriptSignal::PolicyReceived;
    }
    // "Send result to service, PolicyId = ..." is the attempt, not the success.
    if report_sending_re().is_match(message) {
        return ScriptSignal::Unclassified;
    }
    ScriptSignal::Unclassified
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY: &str = "11111111-2222-3333-4444-555555555555";
    const RUN: &str = "66666666-7777-8888-9999-000000000000";

    fn agent(message: &str) -> RecordClassification {
        classify_record(ScriptSourceKind::AgentExecutor, message)
    }

    fn ime(message: &str) -> RecordClassification {
        classify_record(ScriptSourceKind::IntuneManagementExtension, message)
    }

    #[test]
    fn script_path_yields_both_key_halves() {
        let result = agent(&format!(
            r"Powershell script is: C:\Program Files (x86)\Microsoft Intune Management Extension\Policies\Scripts\{POLICY}_{RUN}.ps1"
        ));
        assert_eq!(result.policy_id.as_deref(), Some(POLICY));
        assert_eq!(result.run_id.as_deref(), Some(RUN));
        assert!(result.is_key_bearing());
    }

    #[test]
    fn execution_done_captures_a_zero_exit() {
        let result = agent("Powershell execution is done, exitCode = 0");
        assert_eq!(result.signal, ScriptSignal::ExecutionCompleted);
        let token = result.exit_token.unwrap();
        assert_eq!(token.decimal, Some(0));
        assert_eq!(token.raw_text, "0");
    }

    #[test]
    fn execution_done_captures_an_unknown_decimal_exit() {
        let result = agent("Powershell execution is done, exitCode = 3221225477");
        let token = result.exit_token.unwrap();
        assert_eq!(token.decimal, Some(3_221_225_477));
        assert_eq!(token.hex_text.as_deref(), Some("0xC0000005"));
    }

    #[test]
    fn execution_done_captures_a_hex_exit_verbatim() {
        let result = agent("Powershell execution is done, exitCode = 0x80070005");
        let token = result.exit_token.unwrap();
        assert_eq!(token.raw_text, "0x80070005");
        assert_eq!(token.hex_text.as_deref(), Some("0x80070005"));
        assert_eq!(token.decimal, Some(0x8007_0005));
    }

    #[test]
    fn negative_exit_codes_survive_round_trip() {
        let result = agent("Powershell execution is done, exitCode = -1");
        let token = result.exit_token.unwrap();
        assert_eq!(token.decimal, Some(-1));
        assert_eq!(token.raw_text, "-1");
    }

    #[test]
    fn timeout_outranks_a_trailing_exit_code() {
        // A killed process still logs a code; the timeout is the real story.
        let result = agent("Timeout to execute the script, kill the process. exitCode = 1");
        assert_eq!(result.signal, ScriptSignal::ExecutionTimedOut);
    }

    #[test]
    fn launch_failure_is_distinct_from_a_nonzero_exit() {
        let result = agent("Failed to create process for the script");
        assert_eq!(result.signal, ScriptSignal::LaunchFailed);
        assert!(result.exit_token.is_none());
    }

    #[test]
    fn launch_start_is_recognised() {
        assert_eq!(
            agent("Starting Powershell Execution").signal,
            ScriptSignal::LaunchAttempted
        );
    }

    #[test]
    fn execution_context_is_read_from_an_explicit_field() {
        let result = ime(&format!(
            "[PowerShell] Send result to service, PolicyId = {POLICY}, ExecutionContext = System"
        ));
        assert_eq!(result.context, ScriptExecutionContext::System);
        assert_eq!(result.policy_id.as_deref(), Some(POLICY));
    }

    #[test]
    fn user_context_phrase_is_read() {
        let result = agent("Executing the script in user context");
        assert_eq!(result.context, ScriptExecutionContext::User);
    }

    #[test]
    fn bitness_is_retained_when_stated() {
        assert_eq!(
            agent("Starting Powershell Execution using 64-bit host").bitness,
            ScriptInterpreterBitness::Bit64
        );
        assert_eq!(
            agent("Starting Powershell Execution").bitness,
            ScriptInterpreterBitness::Unknown
        );
    }

    #[test]
    fn report_success_and_failure_are_separate_signals() {
        assert_eq!(
            ime("[PowerShell] Policy result has been sent to service successfully").signal,
            ScriptSignal::ReportSubmitted
        );
        assert_eq!(
            ime("[PowerShell] Failed to send result to service").signal,
            ScriptSignal::ReportFailed
        );
    }

    #[test]
    fn sending_a_result_is_not_the_same_as_having_sent_it() {
        let result = ime(&format!(
            "[PowerShell] Send result to service, PolicyId = {POLICY}"
        ));
        assert_eq!(result.signal, ScriptSignal::Unclassified);
    }

    #[test]
    fn policy_receipt_is_recognised_with_its_id() {
        let result = ime(&format!(
            "[PowerShell] Processing policy with id = {POLICY}"
        ));
        assert_eq!(result.signal, ScriptSignal::PolicyReceived);
        assert_eq!(result.policy_id.as_deref(), Some(POLICY));
    }

    #[test]
    fn agent_executor_vocabulary_does_not_apply_to_the_primary_ime_log() {
        // The same sentence in the wrong file must not become an execution.
        assert_eq!(
            ime("Powershell execution is done, exitCode = 0").signal,
            ScriptSignal::Unclassified
        );
    }

    #[test]
    fn health_scripts_records_never_classify_as_a_script_signal() {
        let result = classify_record(
            ScriptSourceKind::HealthScripts,
            "Powershell execution is done, exitCode = 1",
        );
        assert_eq!(result.signal, ScriptSignal::Unclassified);
    }

    #[test]
    fn unrecognised_execution_wording_is_flagged_for_coverage_not_guessed() {
        let result = agent("Powershell runspace finished with an unexpected condition");
        assert_eq!(result.signal, ScriptSignal::Unclassified);
        assert!(result.execution_shaped_but_unmatched);
    }

    #[test]
    fn unrelated_text_is_not_flagged_as_unknown_version() {
        let result = agent("Cleaning up temporary folder");
        assert!(!result.execution_shaped_but_unmatched);
    }

    #[test]
    fn execution_policy_argument_is_not_an_unknown_version_signal() {
        // `-ExecutionPolicy` contains "execut" as a substring; a healthy bundle
        // must not be demoted to low confidence because of it.
        let result = agent(r"Launching: powershell.exe -ExecutionPolicy Bypass -File script.ps1");
        assert!(!result.execution_shaped_but_unmatched);
    }

    #[test]
    fn an_unconfirmed_artifact_yields_no_identifiers_at_all() {
        // `classify_artifact` refused to confirm this source. If identifiers
        // were still extracted, an unrelated file that merely mentions a policy
        // GUID could mint a transaction.
        let result = classify_record(
            ScriptSourceKind::Unknown,
            &format!(r"Powershell script is: C:\\Policies\\Scripts\\{POLICY}_{RUN}.ps1"),
        );
        assert_eq!(result.policy_id, None);
        assert_eq!(result.run_id, None);
        assert!(!result.is_key_bearing());
    }

    #[test]
    fn health_scripts_records_carry_no_key_into_a_script_transaction() {
        let result = classify_record(
            ScriptSourceKind::HealthScripts,
            &format!("Remediation for PolicyId = {POLICY}"),
        );
        assert_eq!(result.policy_id, None);
    }

    #[test]
    fn attempt_number_is_extracted_when_present() {
        assert_eq!(agent("Retry attempt 3 for the script").attempt, Some(3));
    }

    #[test]
    fn guid_matching_is_case_insensitive_and_normalises() {
        let upper = POLICY.to_ascii_uppercase();
        let result = ime(&format!("[PowerShell] Processing policy with id = {upper}"));
        assert_eq!(result.policy_id.as_deref(), Some(POLICY));
    }
}
