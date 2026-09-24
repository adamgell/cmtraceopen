//! Record-level classification for Win32 app deployment evidence.
//!
//! Every rule here answers one question about one record: what did this line
//! *say*? Nothing in this module decides an outcome, merges records, or infers a
//! value that is not written down. That is the reducer's job, and it only gets
//! to work from what these rules could actually prove.
//!
//! Two deliberate exclusions:
//!
//! * `AgentExecutor` records are never classified into a Win32 signal. That log
//!   is the platform-script analyzer's primary source; a PowerShell installer
//!   invoked for a Win32 app corroborates a transaction that was already keyed
//!   from IME evidence, and may not mint one on its own.
//! * A record whose component does not belong to the Win32 app workload yields
//!   no identifiers at all, so another workload sharing the primary IME log can
//!   never contribute an app id.

use std::sync::OnceLock;

use regex::Regex;

// One grammar owns each shared vocabulary: the GUID shape belongs to
// `guid_registry`, and the content-download phrases (started / completed /
// failed / stalled) belong to `download_stats`. This module composes those
// primitives instead of keeping parallel copies that can drift (issue #357's
// one-behavior-owner requirement).
use crate::intune::download_stats::{
    download_complete_re, download_failed_re, download_re as download_vocabulary_re,
    download_stall_re, is_download_start, is_state_transition_template,
};
use crate::intune::evidence::{IntuneErrorCode, IntuneNamedValue};
use crate::intune::guid_registry::GUID_PATTERN;

use super::models::{Win32ExecutionContext, Win32Intent, Win32Signal, Win32SourceKind};

const GUID: &str = GUID_PATTERN;

fn re(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).expect("win32 regex must compile"))
}

macro_rules! win32_regex {
    ($name:ident, $pattern:expr) => {
        fn $name() -> &'static Regex {
            static CELL: OnceLock<Regex> = OnceLock::new();
            re(&CELL, $pattern)
        }
    };
    ($name:ident, fmt $pattern:expr) => {
        fn $name() -> &'static Regex {
            static CELL: OnceLock<Regex> = OnceLock::new();
            re(&CELL, &format!($pattern, guid = GUID))
        }
    };
}

// ── Identifier extraction ───────────────────────────────────────────────────

win32_regex!(
    app_id_re,
    fmt r"(?i)\b(?:win32\s*)?app(?:lication)?\s*(?:with\s+)?id\s*[:=]\s*\{{?(?P<app>{guid})\}}?"
);
win32_regex!(
    app_id_field_re,
    fmt r"(?i)\bAppId\s*[:=]\s*\{{?(?P<app>{guid})\}}?"
);
win32_regex!(
    app_bare_re,
    fmt r"(?i)\b(?:win32\s+)?app\s+\{{?(?P<app>{guid})\}}?"
);
win32_regex!(
    deployment_type_re,
    fmt r"(?i)\b(?:deployment\s*type|DeploymentType)\s*(?:with\s+)?id\s*[:=]\s*\{{?(?P<dt>{guid})\}}?"
);
win32_regex!(
    dependency_re,
    fmt r"(?i)\bdependency\s+(?:app\s+)?(?:with\s+)?(?:id\s*[:=]\s*)?\{{?(?P<dep>{guid})\}}?"
);
win32_regex!(
    content_version_re,
    r"(?i)\bcontent\s*version\s*[:=]\s*(?P<version>[0-9]+)"
);
win32_regex!(
    requirement_name_re,
    r"(?i)\brequirement\s+rule\s+'(?P<name>[^']+)'"
);
win32_regex!(
    context_field_re,
    r"(?i)\b(?:ExecutionContext|RunAsAccount|RunAsUser|TargetType|context)\s*[:=]\s*(?P<context>system|user|device)\b"
);
win32_regex!(
    context_phrase_re,
    r"(?i)\bin\s+(?P<context>system|user|device)\s+context\b"
);
win32_regex!(
    intent_re,
    r"(?i)\bintent\s*[:=]\s*(?P<intent>required|available|uninstall|availableWithoutEnrollment)\b"
);

// ── Signal vocabulary ───────────────────────────────────────────────────────

win32_regex!(
    policy_received_re,
    r"(?i)\b(?:processing|processed|received)\s+(?:the\s+)?app\s+policy\b|\bapp\s+policy\s+received\b|\bget\s+app\s+policies\b"
);
win32_regex!(
    not_targeted_re,
    r"(?i)\bno\s+longer\s+(?:targeted|assigned)\b|\bnot\s+targeted\b|\bremoved\s+from\s+targeting\b"
);
// IME writes the subject id *between* the field name and its value
// (`Applicability state for app with id: X = Applicable`), so the bounded lazy
// gap is what lets one rule cover both that shape and the compact one. It is
// bounded rather than open-ended so a long record cannot make the value of one
// field bind to the name of another.
win32_regex!(
    applicability_failed_re,
    r"(?i)\bapplicability\s+(?:state|result)\b[^\r\n]{0,160}?\bnot\s*applicable\b|\bis\s+not\s+applicable\b"
);
win32_regex!(
    applicability_passed_re,
    r"(?i)\bapplicability\s+(?:state|result)\b[^\r\n]{0,160}?[:=]\s*applicable\b|\bis\s+applicable\b"
);
win32_regex!(
    requirement_failed_re,
    r"(?i)\brequirement\s+rules?\s+(?:check\s+)?(?:failed|not\s+met|not\s+satisfied)\b|\brequirement\s+rule\s+'[^']*'\s+(?:check\s+)?failed\b"
);
win32_regex!(
    requirement_passed_re,
    r"(?i)\brequirement\s+rules?\s+(?:check\s+)?(?:passed|met|satisfied)\b"
);
// Same bounded-gap shape as the applicability rules: a dependency record names
// the dependency id, then the parent app id, and only then its verdict. The
// negative rule is evaluated first, so `not installed` never reaches the
// positive one.
win32_regex!(
    dependency_unresolved_re,
    r"(?i)\bdependenc(?:y|ies)\b[^\r\n]{0,160}?\b(?:not\s+(?:resolved|satisfied|met|installed)|unresolved|failed|missing)\b|\bblocked\s+by\s+(?:a\s+)?dependency\b"
);
win32_regex!(
    dependency_resolved_re,
    r"(?i)\bdependenc(?:y|ies)\b[^\r\n]{0,160}?\b(?:resolved|satisfied|met|installed)\b"
);
// The negative rule is always evaluated first; see `classify_signal`. Reversing
// them would report the app as present at exactly the moment the evidence says
// it is absent, because `Not Detected` contains `Detected`.
win32_regex!(
    detection_not_satisfied_re,
    r"(?i)\bdetection\s+(?:state|result)\b[^\r\n]{0,160}?\bnot\s+detected\b|\bapp\s+is\s+not\s+detected\b|\bdetection\s+rules?\s+(?:were\s+|was\s+)?not\s+satisfied\b"
);
win32_regex!(
    detection_satisfied_re,
    r"(?i)\bdetection\s+(?:state|result)\b[^\r\n]{0,160}?[:=]\s*detected\b|\bapp\s+is\s+detected\b|\bdetection\s+rules?\s+(?:were\s+|was\s+)?satisfied\b"
);
win32_regex!(
    content_unavailable_re,
    r"(?i)\bno\s+content\s+(?:is\s+)?available\b|\bcontent\s+(?:is\s+)?not\s+available\b|\bcontent\s+version\s+[^\r\n]*?\bnot\s+found\b"
);
win32_regex!(
    hash_failed_re,
    r"(?i)\bhash\s+(?:validation|check|verification)\s+failed\b|\bhash\s+mismatch\b"
);
win32_regex!(
    staging_failed_re,
    r"(?i)\b(?:staging|extraction|decryption)\s+(?:of\s+[^\r\n]*?)?failed\b|\bfailed\s+to\s+(?:stage|extract|decrypt|unzip)\b"
);
// The download started/completed/failed/stalled phrases are consumed from
// `download_stats` (see the imports at the top). The completion phrase
// `content downloaded successfully` is the one IME wording the shared
// vocabulary does not carry, so it is kept as a local *addition*, not a copy.
win32_regex!(
    download_completed_local_re,
    r"(?i)\bcontent\s+downloaded\s+successfully\b"
);
// `Downloading content` is a progressive form the shared start vocabulary
// (which anchors on starting/queued/resuming verbs) does not carry.
win32_regex!(download_started_local_re, r"(?i)\bdownloading\s+content\b");
win32_regex!(
    enforcement_command_failed_re,
    r"(?i)\bfail(?:ed|ure)\s+to\s+(?:create|start|launch|spawn)\s+(?:the\s+)?(?:process|installer|install\s+command)\b"
);
win32_regex!(
    installer_completed_re,
    r"(?i)\binstall(?:ation)?\s+(?:is\s+)?(?:done|complete|completed|finished)\b|\binstaller\s+exited\b|\bprocess\s+exit\s+code(?:\s+is)?\b"
);
win32_regex!(
    enforcement_started_re,
    r"(?i)\binstall(?:ation)?\s+command\s+line\b|\bstart(?:ing|ed)?\s+(?:the\s+)?install(?:ation)?\b|\blaunch(?:ing|ed)?\s+(?:the\s+)?installer\b|\bexecut(?:ing|ed)\s+(?:the\s+)?install\s+command\b"
);
win32_regex!(
    retry_re,
    r"(?i)\bwill\s+retry\b|\bretrying\b|\bschedul(?:ed|ing)\s+a\s+retry\b|\bdeferr(?:ed|ing)\b|\bnext\s+retry\s+(?:at|in)\b"
);
win32_regex!(
    report_failed_re,
    r"(?i)\bfail(?:ed|ure)\s+to\s+(?:send|report|upload)\s+(?:the\s+)?(?:app\s+)?(?:status|result|report)\b|\b(?:status|result)\s+report\s+failed\b"
);
win32_regex!(
    report_submitted_re,
    r"(?i)\b(?:status|result|app\s+status)\s+(?:report\s+)?(?:was\s+)?sent\s+to\s+(?:the\s+)?service\s+successfully\b|\breported\s+app\s+status\s+successfully\b"
);
win32_regex!(
    report_sending_re,
    r"(?i)\bsend(?:ing)?\s+(?:the\s+)?(?:app\s+)?(?:status|result)\s+to\s+(?:the\s+)?service\b"
);

// Return/exit/result token written next to an explicit label.
win32_regex!(
    return_code_re,
    r"(?i)\b(?:exit\s*code|exitCode|return\s*code|returnCode|result\s*code|resultCode)\b\s*(?:is\s*)?[:=]?\s*(?P<code>-?(?:0x[0-9a-fA-F]+|\d+))"
);
// Error token written next to an explicit label.
win32_regex!(
    error_code_re,
    r"(?i)\b(?:error\s*code|errorCode|hresult|HRESULT|error)\b\s*[:=]?\s*(?P<code>-?(?:0x[0-9a-fA-F]+|\d+))"
);

// Outcome vocabulary used only by the unknown-version heuristic.
//
// Matched on word boundaries. A substring test would treat an ordinary
// `/quiet` command line or an `Installer.exe` file name as an unrecognised
// outcome and demote a healthy bundle to low confidence.
win32_regex!(
    unknown_outcome_re,
    r"(?i)\b(?:exit|exits|exited|complete|completed|fail|fails|failed|failure|finish|finished|done|terminated|abort|aborted)\b"
);

// A supplemental installer artifact named inside a keyed record.
//
// This is the only way an MSI/PSADT/Burn/EXE artifact joins a transaction.
// Matching on timestamp proximity is explicitly not supported.
// The value stops at whitespace unless it is quoted. Running to the end of the
// line instead swallowed the trailing `for app with id: …` clause into the path,
// so the artifact name never matched and the artifact never linked.
win32_regex!(
    output_file_re,
    r#"(?i)\b(?:output|log)\s+file\s*[:=]\s*(?P<path>"[^"\r\n]+"|[^\s,;]+)"#
);

// ── Classification ──────────────────────────────────────────────────────────

/// Everything one record could prove.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordClassification {
    pub signal: Win32Signal,
    pub app_id: Option<String>,
    pub deployment_type_id: Option<String>,
    pub content_version: Option<String>,
    pub dependency_app_id: Option<String>,
    pub requirement_name: Option<String>,
    pub execution_context: Win32ExecutionContext,
    pub intent: Win32Intent,
    pub error_code: Option<IntuneErrorCode>,
    pub attributes: Vec<IntuneNamedValue>,
    /// A supplemental artifact file name this record referenced.
    pub referenced_output_file: Option<String>,
    /// True when the record looks like Win32 enforcement but matched no rule.
    /// The reducer turns this into a coverage flag, never an outcome.
    pub enforcement_shaped_but_unmatched: bool,
    /// False when the record belongs to another workload sharing the same log.
    pub in_scope: bool,
}

impl RecordClassification {
    fn empty() -> Self {
        Self {
            signal: Win32Signal::Unclassified,
            app_id: None,
            deployment_type_id: None,
            content_version: None,
            dependency_app_id: None,
            requirement_name: None,
            execution_context: Win32ExecutionContext::Unknown,
            intent: Win32Intent::Unknown,
            error_code: None,
            attributes: Vec::new(),
            referenced_output_file: None,
            enforcement_shaped_but_unmatched: false,
            in_scope: false,
        }
    }

    /// Does this record name an app, and therefore anchor a transaction?
    pub fn is_key_bearing(&self) -> bool {
        self.app_id.is_some()
    }
}

/// Parse a raw token into every form it was observed in.
///
/// The hex view is only rendered for values that fit the unsigned 32-bit window
/// operators expect. A value outside it gets no hex form: truncating would print
/// a different number than the log recorded.
pub(super) fn parse_code(raw: &str) -> IntuneErrorCode {
    let trimmed = raw.trim();
    let (negative, digits) = match trimmed.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, trimmed),
    };

    let (decimal, hex) = if let Some(hex) = digits
        .strip_prefix("0x")
        .or_else(|| digits.strip_prefix("0X"))
    {
        let value = i64::from_str_radix(hex, 16)
            .ok()
            .map(|v| if negative { -v } else { v });
        // A negative token's hex view must state the same number as the
        // decimal view, so it goes through the same signed-to-u32 rendering
        // as the decimal branch (`-0x5` is `0xFFFFFFFB`, not `0x5`). A
        // positive token echoes the digits it was written with.
        let rendered = if negative {
            value
                .and_then(|v| i32::try_from(v).ok())
                .map(|v| format!("0x{:08X}", v as u32))
        } else {
            Some(format!("0x{}", hex.to_ascii_uppercase()))
        };
        (value, rendered)
    } else {
        let value = digits
            .parse::<i64>()
            .ok()
            .map(|v| if negative { -v } else { v });
        let hex = value
            .and_then(|v| {
                u32::try_from(v)
                    .ok()
                    .or_else(|| i32::try_from(v).ok().map(|v| v as u32))
            })
            .map(|v| format!("0x{v:08X}"));
        (value, hex)
    };

    IntuneErrorCode {
        raw: trimmed.to_owned(),
        decimal,
        hex,
    }
}

/// Components whose records belong to the Win32 app workload.
///
/// The primary IME log is shared by every workload. `PowerShell` records are
/// platform scripts and `HealthScripts` records are remediations; classifying
/// either here would invent a Win32 transaction out of another workload's
/// evidence.
fn component_is_in_scope(source_kind: Win32SourceKind, component: Option<&str>) -> bool {
    let expected: &[&str] = match source_kind {
        Win32SourceKind::IntuneManagementExtension | Win32SourceKind::AppWorkload => {
            &["Win32App", "AppWorkload"]
        }
        Win32SourceKind::AppActionProcessor => &["AppActionProcessor", "Win32App"],
        // AgentExecutor is the platform-script analyzer's primary source and
        // InstallerOutput contents are never parsed at all.
        _ => return false,
    };
    component.is_some_and(|component| {
        expected
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(component))
    })
}

fn capture_lower(caps: Option<regex::Captures<'_>>, group: &str) -> Option<String> {
    caps.and_then(|caps| caps.name(group).map(|m| m.as_str().to_ascii_lowercase()))
}

fn extract_context(message: &str) -> Win32ExecutionContext {
    let captured = context_field_re()
        .captures(message)
        .or_else(|| context_phrase_re().captures(message));
    match capture_lower(captured, "context").as_deref() {
        // Intune writes the machine context as either `system` or `device`
        // depending on the record; both mean the same thing here.
        Some("system") | Some("device") => Win32ExecutionContext::System,
        Some("user") => Win32ExecutionContext::User,
        _ => Win32ExecutionContext::Unknown,
    }
}

fn extract_intent(message: &str) -> Win32Intent {
    match capture_lower(intent_re().captures(message), "intent").as_deref() {
        Some("required") => Win32Intent::Required,
        Some("uninstall") => Win32Intent::Uninstall,
        Some("available") | Some("availablewithoutenrollment") => Win32Intent::Available,
        _ => Win32Intent::Unknown,
    }
}

/// Pull the app id out of a record.
///
/// The dependency span is removed first. `Dependency app with id: X for app with
/// id: Y` otherwise resolves the *dependency* as the app, which would attach the
/// blocked deployment's evidence to the app it is waiting on.
fn extract_app_id(message: &str, dependency_span: Option<(usize, usize)>) -> Option<String> {
    let without_dependency = match dependency_span {
        Some((start, end)) => {
            let mut owned = String::with_capacity(message.len());
            owned.push_str(&message[..start]);
            owned.push(' ');
            owned.push_str(&message[end..]);
            owned
        }
        None => message.to_owned(),
    };

    for pattern in [app_id_field_re(), app_id_re(), app_bare_re()] {
        if let Some(app) = capture_lower(pattern.captures(&without_dependency), "app") {
            return Some(app);
        }
    }
    None
}

/// Classify one already-framed logical record.
pub fn classify_record(
    source_kind: Win32SourceKind,
    component: Option<&str>,
    message: &str,
) -> RecordClassification {
    let mut result = RecordClassification::empty();

    // Identifiers are only extracted from a *confirmed*, in-scope Win32 source.
    // Without this gate a file that merely happens to be named `AppWorkload.log`
    // could mint a transaction from any line containing a GUID.
    if !component_is_in_scope(source_kind, component) {
        return result;
    }
    result.in_scope = true;

    let dependency_match = dependency_re().captures(message);
    let dependency_span = dependency_match
        .as_ref()
        .and_then(|caps| caps.get(0))
        .map(|m| (m.start(), m.end()));
    result.dependency_app_id = dependency_match
        .as_ref()
        .and_then(|caps| caps.name("dep"))
        .map(|m| m.as_str().to_ascii_lowercase());

    result.app_id = extract_app_id(message, dependency_span);
    result.deployment_type_id = capture_lower(deployment_type_re().captures(message), "dt");
    result.content_version = content_version_re()
        .captures(message)
        .and_then(|caps| caps.name("version"))
        .map(|m| m.as_str().to_owned());
    result.requirement_name = requirement_name_re()
        .captures(message)
        .and_then(|caps| caps.name("name"))
        .map(|m| m.as_str().to_owned());
    result.execution_context = extract_context(message);
    result.intent = extract_intent(message);
    result.referenced_output_file = output_file_re()
        .captures(message)
        .and_then(|caps| caps.name("path"))
        .map(|m| file_name_of(m.as_str().trim()));

    result.signal = classify_signal(message, &mut result);

    // A template line is bookkeeping for the unknown-vocabulary heuristic
    // too: its Event: field quotes enforcement wording on every healthy
    // bundle, and flagging it would demote them all to low confidence.
    if result.signal == Win32Signal::Unclassified
        && !is_state_transition_template(message)
        && looks_like_enforcement(message)
    {
        result.enforcement_shaped_but_unmatched = true;
    }

    result
}

/// The trailing path segment of a referenced artifact.
///
/// Only the file name is kept: the directory half is where profile names live,
/// and the name alone is what keys the supplemental artifact.
fn file_name_of(path: &str) -> String {
    path.rsplit(['\\', '/'])
        .next()
        .unwrap_or(path)
        .trim_matches('"')
        .to_owned()
}

/// Order matters here, and every negative rule precedes its positive twin.
///
/// `Detection state = Not Detected` contains `Detected`; checking the positive
/// rule first would report the app as present at exactly the moment the evidence
/// says it is absent.
fn classify_signal(message: &str, result: &mut RecordClassification) -> Win32Signal {
    // The shared transition-template gate runs before EVERY rule, matching
    // download_stats' own composition, where from_message returns None
    // outright for a template line. IME's state-machine bookkeeping quotes
    // the vocabulary of every phase in its To:/Event: fields (`… To: Hash
    // Mismatch With Event: Hash Validation Failed.`, `… To: Install Done
    // With Event: Installation is done.`) without stating any of it, and
    // gating only the download rules let a template line mint hash, staging,
    // installer, and detection signals out of bookkeeping.
    if is_state_transition_template(message) {
        return Win32Signal::Unclassified;
    }
    if not_targeted_re().is_match(message) {
        return Win32Signal::NotTargeted;
    }
    if applicability_failed_re().is_match(message) {
        return Win32Signal::ApplicabilityFailed;
    }
    if requirement_failed_re().is_match(message) {
        return Win32Signal::RequirementFailed;
    }
    if dependency_unresolved_re().is_match(message) {
        return Win32Signal::DependencyUnresolved;
    }
    if hash_failed_re().is_match(message) {
        result.error_code = extract_failure_code(message);
        return Win32Signal::HashValidationFailed;
    }
    if staging_failed_re().is_match(message) {
        result.error_code = extract_failure_code(message);
        return Win32Signal::StagingFailed;
    }
    // Content-unavailable is checked before the shared download-failed
    // vocabulary: the shared alternation includes `content not found`, and the
    // more specific no-usable-content diagnosis must win over the generic
    // delivery failure.
    if content_unavailable_re().is_match(message) {
        result.error_code = extract_failure_code(message);
        return Win32Signal::ContentUnavailable;
    }
    // Template lines already returned above, so the download-shape gate is
    // purely about vocabulary here.
    let download_statement = download_vocabulary_re().is_match(message);
    // The shared failure vocabulary carries bare words (`cancelled`,
    // `aborted`) that are only download statements on a download-shaped line,
    // so it is gated by the shared download vocabulary — the same composition
    // `download_stats` itself uses.
    if download_statement && download_failed_re().is_match(message) {
        result.error_code = extract_failure_code(message);
        return Win32Signal::DownloadFailed;
    }
    if enforcement_command_failed_re().is_match(message) {
        result.error_code = extract_failure_code(message);
        return Win32Signal::EnforcementCommandFailed;
    }
    if report_failed_re().is_match(message) {
        result.error_code = extract_failure_code(message);
        return Win32Signal::ReportFailed;
    }
    if report_submitted_re().is_match(message) {
        return Win32Signal::ReportSubmitted;
    }
    // "Sending app status to service" is the attempt, not the success.
    if report_sending_re().is_match(message) {
        return Win32Signal::Unclassified;
    }
    if installer_completed_re().is_match(message) {
        result.error_code = return_code_re()
            .captures(message)
            .and_then(|caps| caps.name("code"))
            .map(|m| parse_code(m.as_str()));
        return Win32Signal::InstallerCompleted;
    }
    if detection_not_satisfied_re().is_match(message) {
        return Win32Signal::DetectionNotSatisfied;
    }
    if detection_satisfied_re().is_match(message) {
        return Win32Signal::DetectionSatisfied;
    }
    if applicability_passed_re().is_match(message) {
        return Win32Signal::ApplicabilityPassed;
    }
    if requirement_passed_re().is_match(message) {
        return Win32Signal::RequirementPassed;
    }
    if dependency_resolved_re().is_match(message) {
        return Win32Signal::DependencyResolved;
    }
    if download_statement
        && (download_complete_re().is_match(message)
            || download_completed_local_re().is_match(message))
    {
        return Win32Signal::DownloadCompleted;
    }
    if download_statement && download_stall_re().is_match(message) {
        return Win32Signal::DownloadStalled;
    }
    if download_statement
        && (is_download_start(message) || download_started_local_re().is_match(message))
    {
        return Win32Signal::DownloadStarted;
    }
    if enforcement_started_re().is_match(message) {
        return Win32Signal::EnforcementStarted;
    }
    // `download_stats::appworkload_retry_re` is deliberately NOT reused here:
    // its alternation folds `retry exhausted` and `failed … retry` — statements
    // about a retry *ending* — into the same bucket as a retry being scheduled.
    // For statistics that conflation is harmless; for a transaction outcome,
    // classifying an exhausted retry as `RetryScheduled` would report a
    // deployment as deferred at the exact moment the agent gave up.
    if retry_re().is_match(message) {
        return Win32Signal::RetryScheduled;
    }
    if policy_received_re().is_match(message) {
        result.attributes = policy_attributes(message);
        return Win32Signal::AppPolicyReceived;
    }
    Win32Signal::Unclassified
}

/// Prefer an explicit error label, falling back to a return-code label.
fn extract_failure_code(message: &str) -> Option<IntuneErrorCode> {
    error_code_re()
        .captures(message)
        .or_else(|| return_code_re().captures(message))
        .and_then(|caps| caps.name("code").map(|m| parse_code(m.as_str())))
}

/// Retain policy fields we do not model yet, so typing one later is a widening
/// change rather than a re-parse.
fn policy_attributes(message: &str) -> Vec<IntuneNamedValue> {
    let mut attributes = Vec::new();
    if let Some(version) = content_version_re()
        .captures(message)
        .and_then(|caps| caps.name("version"))
    {
        attributes.push(IntuneNamedValue {
            name: "contentVersion".to_owned(),
            value: version.as_str().to_owned(),
        });
    }
    attributes
}

/// Enforcement-shaped but unmatched: mentions installation plus an outcome word.
///
/// This is how an unrecognised IME version shows up. The vocabulary is
/// deliberately narrow so a healthy bundle is never demoted.
fn looks_like_enforcement(message: &str) -> bool {
    let lowered = message.to_ascii_lowercase();
    (lowered.contains("install") || lowered.contains("enforcement"))
        && unknown_outcome_re().is_match(message)
}

#[cfg(test)]
mod tests {
    use super::*;

    const APP: &str = "11111111-2222-4333-8444-555555555555";
    const DEP: &str = "99999999-8888-4777-8666-555555555555";
    const DT: &str = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";

    fn workload(message: &str) -> RecordClassification {
        classify_record(Win32SourceKind::AppWorkload, Some("Win32App"), message)
    }

    #[test]
    fn app_id_is_extracted_and_normalised() {
        let result = workload(&format!(
            "[Win32App] Processing app policy for app with id: {}",
            APP.to_ascii_uppercase()
        ));
        assert_eq!(result.app_id.as_deref(), Some(APP));
        assert_eq!(result.signal, Win32Signal::AppPolicyReceived);
        assert!(result.is_key_bearing());
    }

    #[test]
    fn a_dependency_guid_never_becomes_the_app_id() {
        // Otherwise the blocked deployment's evidence attaches to the app it is
        // waiting on, which is the wrong app entirely.
        let result = workload(&format!(
            "[Win32App] Dependency app with id: {DEP} for app with id: {APP} is not installed"
        ));
        assert_eq!(result.app_id.as_deref(), Some(APP));
        assert_eq!(result.dependency_app_id.as_deref(), Some(DEP));
        assert_eq!(result.signal, Win32Signal::DependencyUnresolved);
    }

    #[test]
    fn deployment_type_is_a_separate_identifier() {
        let result = workload(&format!(
            "[Win32App] app with id: {APP}, deployment type id: {DT}, content version: 3"
        ));
        assert_eq!(result.deployment_type_id.as_deref(), Some(DT));
        assert_eq!(result.content_version.as_deref(), Some("3"));
    }

    #[test]
    fn not_detected_is_never_read_as_detected() {
        let result = workload(&format!(
            "[Win32App] Detection state for app with id: {APP} = Not Detected"
        ));
        assert_eq!(result.signal, Win32Signal::DetectionNotSatisfied);
    }

    #[test]
    fn detected_is_recognised() {
        let result = workload(&format!(
            "[Win32App] Detection state for app with id: {APP} = Detected"
        ));
        assert_eq!(result.signal, Win32Signal::DetectionSatisfied);
    }

    #[test]
    fn not_applicable_outranks_applicable() {
        let result = workload(&format!(
            "[Win32App] app with id: {APP} is not applicable to this device"
        ));
        assert_eq!(result.signal, Win32Signal::ApplicabilityFailed);
    }

    #[test]
    fn installer_completion_captures_a_zero_code() {
        let result = workload(&format!(
            "[Win32App] Installation is done for app with id: {APP}, exit code: 0"
        ));
        assert_eq!(result.signal, Win32Signal::InstallerCompleted);
        let code = result.error_code.expect("code");
        assert_eq!(code.decimal, Some(0));
        assert_eq!(code.raw, "0");
    }

    #[test]
    fn process_exit_code_is_captured_with_the_is_separator() {
        let result = workload(&format!(
            "[Win32App] Process exit code is 1603 for app with id: {APP}"
        ));
        assert_eq!(result.signal, Win32Signal::InstallerCompleted);
        assert_eq!(result.error_code.expect("code").decimal, Some(1603));
    }

    #[test]
    fn installer_completion_keeps_a_hex_code_verbatim() {
        let result = workload(&format!(
            "[Win32App] Installation completed for app with id: {APP}, exit code: 0x80070643"
        ));
        let code = result.error_code.expect("code");
        assert_eq!(code.raw, "0x80070643");
        assert_eq!(code.hex.as_deref(), Some("0x80070643"));
        assert_eq!(code.decimal, Some(0x8007_0643));
    }

    #[test]
    fn an_out_of_range_code_gets_no_truncated_hex_view() {
        let code = parse_code("4294967297");
        assert_eq!(code.decimal, Some(4_294_967_297));
        assert_eq!(code.hex, None);
    }

    #[test]
    fn a_negative_code_survives_round_trip() {
        let code = parse_code("-2147024891");
        assert_eq!(code.decimal, Some(-2_147_024_891));
        assert_eq!(code.raw, "-2147024891");
    }

    #[test]
    fn a_negative_hex_token_renders_the_same_number_in_both_views() {
        // `-0x5` is -5; rendering the hex view as `0x5` stated a different
        // number than the decimal view. The two branches share the
        // signed-to-u32 rendering, so the hex view is the two's-complement
        // form of the same value.
        let code = parse_code("-0x5");
        assert_eq!(code.decimal, Some(-5));
        assert_eq!(code.hex.as_deref(), Some("0xFFFFFFFB"));

        // Consistency with the decimal branch on the canonical HRESULT shape.
        let hex = parse_code("-0x7FF8FF85");
        let dec = parse_code("-2147024773");
        assert_eq!(hex.decimal, dec.decimal);
        assert_eq!(hex.hex, dec.hex);

        // A negative value outside the i32 window has no honest 32-bit hex
        // form, exactly like the positive out-of-range case.
        let out_of_range = parse_code("-0x100000000");
        assert_eq!(out_of_range.decimal, Some(-4_294_967_296));
        assert_eq!(out_of_range.hex, None);
    }

    #[test]
    fn the_shared_download_vocabulary_is_consumed_not_duplicated() {
        // Stall/timeout phrasing comes straight from download_stats and is now
        // recognized instead of falling into Unclassified (one-behavior-owner,
        // issue #357). It is deliberately not a terminal statement.
        assert_eq!(
            workload(&format!(
                "[Win32App] Content download timed out for app with id: {APP}"
            ))
            .signal,
            Win32Signal::DownloadStalled
        );
        // The shared failure vocabulary's bare words only count on a
        // download-shaped line.
        assert_eq!(
            workload(&format!(
                "[Win32App] Content download cancelled for app with id: {APP}"
            ))
            .signal,
            Win32Signal::DownloadFailed
        );
        assert_eq!(
            workload("[Win32App] User cancelled the completion dialog").signal,
            Win32Signal::Unclassified
        );
        // The more specific no-usable-content diagnosis wins over the generic
        // delivery failure even though the shared alternation matches both.
        assert_eq!(
            workload(&format!(
                "[Win32App] Content version 5 not found while starting the download for app with id: {APP}"
            ))
            .signal,
            Win32Signal::ContentUnavailable
        );
    }

    #[test]
    fn the_state_transition_template_never_mints_a_download_signal() {
        // The exact template line download_stats pins in its own
        // ime_transition_template_is_ignored test. The shared ignore gate is
        // checked before the download vocabulary there, and must be here too:
        // a state-machine transition line quotes the download phrases without
        // being a download statement.
        assert_eq!(
            workload(
                "Adding new state transition - From: Install In Progress To: \
                 Download In Progress With Event: Download Started."
            )
            .signal,
            Win32Signal::Unclassified
        );
        // The failure-event form is the one that minted a terminal
        // ContentDeliveryFailed before the gate was applied here.
        assert_eq!(
            workload(&format!(
                "Adding new state transition - From: Download In Progress To: \
                 Download Failed With Event: Download Failed for app with id: {APP}."
            ))
            .signal,
            Win32Signal::Unclassified
        );
    }

    #[test]
    fn transition_templates_are_bookkeeping_for_every_rule_not_just_downloads() {
        // The template gate must run before ANY content/hash/staging/installer/
        // detection rule, exactly as download_stats composes it (from_message
        // returns None outright for a template line): the state machine's
        // To:/Event: fields quote the vocabulary of every phase, and reading
        // one as evidence minted terminal outcomes out of bookkeeping.
        let templates = [
            // Hash vocabulary in both the To: field and the Event: field.
            format!(
                "Adding new state transition - From: Download In Progress To: \
                 Hash Mismatch With Event: Hash Validation Failed for app with id: {APP}."
            ),
            // Installer-completion vocabulary.
            format!(
                "Adding new state transition - From: Install In Progress To: \
                 Install Done With Event: Installation is done for app with id: {APP}."
            ),
            // Staging vocabulary in the To: field.
            format!(
                "Adding new state transition - From: Download Complete To: \
                 Staging Failed With Event: Staging of content failed for app with id: {APP}."
            ),
            // Detection vocabulary in the To: field.
            "Adding new state transition - From: Detection In Progress To: \
             App Is Not Detected With Event: Detection rules were not satisfied."
                .to_owned(),
        ];
        for template in &templates {
            let result = workload(template);
            assert_eq!(
                result.signal,
                Win32Signal::Unclassified,
                "template line must not classify: {template:?}"
            );
            assert!(
                !result.enforcement_shaped_but_unmatched,
                "template line is bookkeeping, not unknown vocabulary: {template:?}"
            );
            assert!(
                result.error_code.is_none(),
                "template line must not carry a failure code: {template:?}"
            );
        }
    }

    #[test]
    fn every_pre_refactor_download_phrasing_still_classifies() {
        // These phrasings were matched by the win32-local rules before the
        // vocabulary moved to download_stats; the shared regexes now carry
        // them so the consolidation is a widening, not a regression. The
        // phrase table itself lives with the vocabulary's owner
        // (download_stats::test_vocabulary) so the two test suites cannot
        // drift apart.
        use crate::intune::download_stats::test_vocabulary::{
            PRE_CONSOLIDATION_COMPLETE, PRE_CONSOLIDATION_FAILED, PRE_CONSOLIDATION_START,
        };
        for phrase in PRE_CONSOLIDATION_FAILED {
            assert_eq!(
                workload(&format!("[Win32App] {phrase} for app with id: {APP}")).signal,
                Win32Signal::DownloadFailed,
                "{phrase:?} must classify as a download failure"
            );
        }
        for phrase in PRE_CONSOLIDATION_COMPLETE {
            assert_eq!(
                workload(&format!("[Win32App] {phrase} for app with id: {APP}")).signal,
                Win32Signal::DownloadCompleted,
                "{phrase:?} must classify as a download completion"
            );
        }
        for phrase in PRE_CONSOLIDATION_START {
            assert_eq!(
                workload(&format!("[Win32App] {phrase} for app with id: {APP}")).signal,
                Win32Signal::DownloadStarted,
                "{phrase:?} must classify as a download start"
            );
        }
    }

    #[test]
    fn a_failed_download_start_classifies_as_a_failure_not_a_start() {
        // The start vocabulary matches inside "failed to start download", but
        // the line states the opposite of a start; the shared failure
        // vocabulary carries the phrase and must win.
        assert_eq!(
            workload(&format!(
                "[Win32App] Failed to start download for app with id: {APP}"
            ))
            .signal,
            Win32Signal::DownloadFailed
        );
        // Every phrasing the shared negation gate suppresses must classify as
        // a failure here too, or the suppressed line mints no signal at all
        // and the download disappears from the transaction.
        for phrase in crate::intune::download_stats::test_vocabulary::NEGATED_START_FAILED {
            assert_eq!(
                workload(&format!("[Win32App] {phrase} for app with id: {APP}")).signal,
                Win32Signal::DownloadFailed,
                "{phrase:?}"
            );
        }
    }

    #[test]
    fn hash_failure_outranks_a_generic_download_line() {
        let result = workload(&format!(
            "[Win32App] Hash mismatch while downloading content for app with id: {APP}, error code: 0x87D30067"
        ));
        assert_eq!(result.signal, Win32Signal::HashValidationFailed);
        assert_eq!(
            result.error_code.expect("code").hex.as_deref(),
            Some("0x87D30067")
        );
    }

    #[test]
    fn sending_a_report_is_not_the_same_as_having_sent_it() {
        let result = workload(&format!(
            "[Win32App] Sending app status to service for app with id: {APP}"
        ));
        assert_eq!(result.signal, Win32Signal::Unclassified);
    }

    #[test]
    fn report_success_and_failure_are_separate_signals() {
        assert_eq!(
            workload("[Win32App] App status report was sent to service successfully").signal,
            Win32Signal::ReportSubmitted
        );
        assert_eq!(
            workload("[Win32App] Failed to send app status to service, error code: 0x80072ee2")
                .signal,
            Win32Signal::ReportFailed
        );
    }

    #[test]
    fn a_platform_script_record_in_the_shared_ime_log_is_out_of_scope() {
        let result = classify_record(
            Win32SourceKind::IntuneManagementExtension,
            Some("PowerShell"),
            &format!("[PowerShell] Processing app policy for app with id: {APP}"),
        );
        assert!(!result.in_scope);
        assert_eq!(result.app_id, None);
        assert_eq!(result.signal, Win32Signal::Unclassified);
    }

    #[test]
    fn agent_executor_records_never_mint_a_win32_signal() {
        let result = classify_record(
            Win32SourceKind::AgentExecutor,
            Some("AgentExecutor"),
            &format!("Installation is done for app with id: {APP}, exit code: 1603"),
        );
        assert!(!result.in_scope);
        assert_eq!(result.app_id, None);
    }

    #[test]
    fn an_unconfirmed_artifact_yields_no_identifiers_at_all() {
        let result = classify_record(
            Win32SourceKind::Unknown,
            Some("Win32App"),
            &format!("Installation is done for app with id: {APP}, exit code: 0"),
        );
        assert_eq!(result.app_id, None);
        assert!(!result.is_key_bearing());
    }

    #[test]
    fn a_record_without_a_component_cannot_produce_a_signal() {
        let result = classify_record(
            Win32SourceKind::AppWorkload,
            None,
            &format!("Installation is done for app with id: {APP}, exit code: 0"),
        );
        assert_eq!(result.signal, Win32Signal::Unclassified);
        assert_eq!(result.app_id, None);
    }

    #[test]
    fn unrecognised_enforcement_wording_is_flagged_for_coverage_not_guessed() {
        let result = workload(&format!(
            "[Win32App] Install pipeline for app with id: {APP} terminated in an unexpected condition"
        ));
        assert_eq!(result.signal, Win32Signal::Unclassified);
        assert!(result.enforcement_shaped_but_unmatched);
    }

    #[test]
    fn ordinary_records_are_not_flagged_as_unknown_vocabulary() {
        assert!(
            !workload("[Win32App] Cleaning up the staging directory")
                .enforcement_shaped_but_unmatched
        );
        assert!(
            !workload(&format!(
                "[Win32App] Install command line: setup.exe /quiet for app with id: {APP}"
            ))
            .enforcement_shaped_but_unmatched
        );
    }

    #[test]
    fn execution_context_is_read_from_a_field_or_a_phrase() {
        assert_eq!(
            workload("[Win32App] ExecutionContext = System").execution_context,
            Win32ExecutionContext::System
        );
        assert_eq!(
            workload("[Win32App] Enforcing the app in user context").execution_context,
            Win32ExecutionContext::User
        );
        assert_eq!(
            workload("[Win32App] Cleaning up").execution_context,
            Win32ExecutionContext::Unknown
        );
    }

    #[test]
    fn intent_is_retained_when_stated() {
        assert_eq!(
            workload("[Win32App] App policy received, intent = Required").intent,
            Win32Intent::Required
        );
    }

    #[test]
    fn a_referenced_output_file_is_reduced_to_its_name() {
        let result = workload(&format!(
            r"[Win32App] Install output file: C:\Windows\IMECache\{APP}\Contoso-Setup.msi.log"
        ));
        assert_eq!(
            result.referenced_output_file.as_deref(),
            Some("Contoso-Setup.msi.log")
        );
    }

    #[test]
    fn requirement_rule_name_is_captured_with_its_failure() {
        let result = workload(&format!(
            "[Win32App] Requirement rule 'Minimum OS build' check failed for app with id: {APP}"
        ));
        assert_eq!(result.signal, Win32Signal::RequirementFailed);
        assert_eq!(result.requirement_name.as_deref(), Some("Minimum OS build"));
    }

    #[test]
    fn not_targeted_is_distinct_from_not_applicable() {
        let result = workload(&format!(
            "[Win32App] app with id: {APP} is no longer targeted to this device"
        ));
        assert_eq!(result.signal, Win32Signal::NotTargeted);
    }
}
