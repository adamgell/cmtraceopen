use std::collections::{HashMap, HashSet};
use std::path::Path;

use once_cell::sync::Lazy;
use regex::Regex;

use super::guid_registry::{self, GuidRegistry, GUID_RE};
use super::ime_parser::ImeLine;
use super::models::{IntuneEvent, IntuneEventType, IntuneStatus};

static WIN32_APP_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)\[Win32App\].*(?:processing|executing|installing|detected|not detected|evaluating)"#,
    )
    .unwrap()
});
static WIN32_RESULT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)\[Win32App\].*(?:result|completed|success|failed|error)"#).unwrap()
});
static WIN32_GUID_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(?:app|application)\s+(?:id|with\s+id)[:\s]+([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"#).unwrap()
});
static WINGET_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)WinGetApp.*(?:processing|installing|detected|evaluating)"#).unwrap()
});
static WINGET_TOKEN_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)(?:winget|microsoft\.winget)"#).unwrap());
static APPWORKLOAD_DOWNLOAD_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(?:download(?:ing|ed)?|delivery\s+optimization|content\s+download|bytes\s+downloaded|download\s+progress|download\s+session|content\s+retrieval)"#,
    )
    .unwrap()
});
static APPWORKLOAD_STAGING_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(?:staging\s+(?:file|content)|hash\s+validation|content\s+cached|cache\s+location|expanded\s+content|extract(?:ed|ing))"#,
    )
    .unwrap()
});
static APPWORKLOAD_HASH_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)(?:hash\s+validation|hash\s+mismatch|hash\s+check)"#).unwrap());
static APPWORKLOAD_INSTALL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(?:install(?:ing|ation)?|execution|enforcement|installer|launching\s+install|handoff\s+to\s+install|processdetectionrules|detection\s+rule)"#,
    )
    .unwrap()
});
static APPWORKLOAD_RETRY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(?:retry|retrying|reattempt|will\s+retry|attempt\s+\d+\s+of\s+\d+)"#).unwrap()
});
static APPWORKLOAD_STALL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(?:stalled|not\s+progressing|no\s+progress|timed?\s*out|timeout|hung|retry\s+exhausted)"#,
    )
    .unwrap()
});
static APPWORKLOAD_QUEUE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(?:queued|queueing|requesting\s+download|waiting\s+for\s+download|waiting\s+for\s+content|pending\s+download)"#,
    )
    .unwrap()
});
static APPWORKLOAD_FAILURE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(?:download\s+failed|failed\s+to\s+download|hash\s+validation\s+failed|hash\s+mismatch|staging\s+failed|unable\s+to\s+download|content\s+not\s+found|cancelled|aborted|retry\s+exhausted)"#,
    )
    .unwrap()
});
static APPWORKLOAD_SUCCESS_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(?:download\s+completed|download\s+succeeded|staging\s+completed|content\s+cached|hash\s+validation\s+succeeded|install\s+completed|completed\s+successfully)"#,
    )
    .unwrap()
});
static POLICY_EVAL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(?:assignment\s+evaluation|targeted\s+intent|applicability\s*=|\bapplicable\b|not\s+applicable|requirement\s+rule|detection\s+rule|local\s+deadline|grs\s+expired|grs\s+not\s+expired|enforcement\s+classification|will\s+not\s+be\s+enforced)"#,
    )
    .unwrap()
});
static APP_ACTION_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(?:app\s+with\s+id:|application\s+action|managed\s+app)"#).unwrap()
});
static APPLICABILITY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(?:applicability|applicable|not\s+applicable|requirement\s+rule|detection\s+rule|will\s+not\s+be\s+enforced)"#)
        .unwrap()
});
static APPLICABILITY_BLOCK_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(?:not\s+applicable|applicability\s*(?:=|:)\s*false|will\s+not\s+be\s+enforced|requirement\s+rule.*(?:not\s+satisfied|failed|false)|assignment.*(?:not\s+applicable|not\s+targeted)|enforcement\s+classification.*not\s+applicable)"#,
    )
    .unwrap()
});
static APPLICABILITY_SUCCESS_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(?:applicability\s*(?:=|:)\s*true|requirement\s+rule.*(?:passed|satisfied|true)|assignment\s+evaluation\s+completed|applicable\s*=\s*true)"#,
    )
    .unwrap()
});
static POLICY_PENDING_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(?:local\s+deadline|grs\s+not\s+expired|scheduled|queued|pending)"#).unwrap()
});
static SCRIPT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(?:PowerShell\s+script|script\s+execution|running\s+script)"#).unwrap()
});
static SCRIPT_RESULT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)script.*(?:completed|exit\s+code|result|output|failed|success)"#).unwrap()
});
static AGENTEXECUTOR_SCRIPT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(?:powershell\s+script\s+is\s+successfully\s+executed|detection\s+script|remediation\s+script|exit\s+code|script\s+(?:completed|failed|timed?\s*out|execution)|stdout|stderr)"#,
    )
    .unwrap()
});
static DETECTION_SCRIPT_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)\b(?:pre-)?detection\s+script\b|\bpre-detect\b"#).unwrap());
static REMEDIATION_SCRIPT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)\b(?:post-)?remediation\s+script\b|\bpost-detect\b|\bremediation\b"#).unwrap()
});
static SCRIPT_FAILURE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(?:access\s+is\s+denied|unauthorized|permission\s+denied|term\s+'.+'\s+is\s+not\s+recognized|cannot\s+find\s+path|path\s+not\s+found|file\s+not\s+found|module\s+.*\s+not\s+found|parsererror|syntax\s+error|execution\s+policy|digitally\s+signed|failed\s+to\s+execute|exception|stderr)"#,
    )
    .unwrap()
});
static REMEDIATION_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(?:Remediation|HealthScript|proactive\s+remediation)"#).unwrap()
});
static HEALTHSCRIPT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(?:healthscript|health\s+script|detection\s+script|remediation\s+script|pre-detect|post-detect|schedule(?:d|ing)?|compliance\s+result)"#,
    )
    .unwrap()
});
static ESP_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(?:ESP|EspBody|EnrollmentStatusPage|enrollment\s+status)"#).unwrap()
});
static SYNC_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)(?:sync\s+session|check-in|SyncSession)"#).unwrap());
// GUID_RE imported from guid_registry
static ERROR_CODE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(?:error\s*(?:code)?|exit\s*code(?:\s+of\s+the\s+script)?|hresult|hr|result|return\s*code)\s*(?:is|[=:])\s*(0x[0-9a-fA-F]+|-?\d+)"#,
    )
    .unwrap()
});
static EXIT_CODE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)exit\s*code(?:\s+of\s+the\s+script)?\s*(?:is|[=:])\s*(-?\d+)"#).unwrap()
});
static PENDING_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)(?:pending|queued|waiting|scheduled|requesting)"#).unwrap());
static TIMEOUT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(?:timed?\s*out|timeout|stalled|hung|not\s+progressing|no\s+progress)"#)
        .unwrap()
});
static COMPLIANCE_TRUE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)compliance\s+result.*\bis\s+true\b"#).unwrap());
static COMPLIANCE_FALSE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)compliance\s+result.*\bis\s+false\b"#).unwrap());
static CLIENT_HEALTH_RULE_SUMMARY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)summary:\s*rule\s+(.+?)\s+with\s+ID\s+[0-9a-f-]{36},\s*result\s*=\s*(pass|fail),\s*details\s*=\s*(.+)$"#,
    )
    .unwrap()
});
static CLIENT_HEALTH_HEARTBEAT_SUCCESS_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)the client health report was sent successfully\. done\."#).unwrap()
});
static CLIENT_HEALTH_HEARTBEAT_FAILURE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(?:failed to send heartbeat report|exception occurred while sending heartbeat report|clienthealthruleengine\]\(sendheartbeatreport\).*(?:failed|unauthorized|exception)|found webexception in aggregateexception)"#,
    )
    .unwrap()
});
static CLIENT_CERT_LOCAL_MACHINE_COUNT_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)MDM certs found in LocalMachine count:\s*(\d+)"#).unwrap());
static CLIENT_CERT_FAILURE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(?:certificate.*(?:invalid|error|fail)|private key|correct oid|expired|client cert check.*exception|exception.*certificate)"#,
    )
    .unwrap()
});
static DEVICE_HEALTH_APP_CRASH_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)received application event.*?<Data Name="AppName">([^<]+)</Data>.*?<Data Name="ExceptionCode">([^<]+)</Data>"#,
    )
    .unwrap()
});
static SENSOR_MEMORY_FAILURE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(?:error getting physically installed system memory|GetPhysicallyInstalledSystemMemory failed)"#,
    )
    .unwrap()
});
static WIN32_APP_INVENTORY_FULL_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)\[Win32AppInventory\]\s*report type is 1\b"#).unwrap());
static WIN32_APP_INVENTORY_NO_CHANGE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)no change detected in win32 app inventory delta update"#).unwrap()
});
static WIN32_APP_INVENTORY_DELTA_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)computing delta inventory\.\.\.done\.\s*add count\s*=\s*(\d+),\s*modify count\s*=\s*(\d+),\s*delete count\s*=\s*(\d+)"#,
    )
    .unwrap()
});
static SUCCESS_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(?:success|succeeded|completed\s+successfully|installed|detected|compliant|validated|passed)"#,
    )
    .unwrap()
});
static FAILED_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(?:fail|error|not\s+detected|not\s+installed|non-compliant|cancelled|aborted|exception)"#,
    )
    .unwrap()
});

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ImeSourceKind {
    PrimaryIme,
    AppWorkload,
    AppActionProcessor,
    AgentExecutor,
    HealthScripts,
    ClientHealth,
    ClientCertCheck,
    DeviceHealthMonitoring,
    Sensor,
    Win32AppInventory,
    Other,
}

#[derive(Debug, Default, Clone, Copy)]
struct AppWorkloadMatchFlags {
    winget_token: bool,
    winget: bool,
    download: bool,
    staging: bool,
    hash: bool,
    install: bool,
    retry: bool,
    stall: bool,
    failure: bool,
    success: bool,
    queue: bool,
    pending: bool,
    timeout: bool,
}

impl AppWorkloadMatchFlags {
    fn from_message(msg: &str) -> Self {
        Self {
            winget_token: WINGET_TOKEN_RE.is_match(msg),
            winget: WINGET_RE.is_match(msg),
            download: APPWORKLOAD_DOWNLOAD_RE.is_match(msg),
            staging: APPWORKLOAD_STAGING_RE.is_match(msg),
            hash: APPWORKLOAD_HASH_RE.is_match(msg),
            install: APPWORKLOAD_INSTALL_RE.is_match(msg),
            retry: APPWORKLOAD_RETRY_RE.is_match(msg),
            stall: APPWORKLOAD_STALL_RE.is_match(msg),
            failure: APPWORKLOAD_FAILURE_RE.is_match(msg),
            success: APPWORKLOAD_SUCCESS_RE.is_match(msg),
            queue: APPWORKLOAD_QUEUE_RE.is_match(msg),
            pending: PENDING_RE.is_match(msg),
            timeout: TIMEOUT_RE.is_match(msg),
        }
    }

    fn is_candidate(self) -> bool {
        self.download
            || self.staging
            || self.install
            || self.retry
            || self.stall
            || self.winget_token
            || self.winget
    }
}

pub fn extract_events(
    lines: &[ImeLine],
    source_file: &str,
    registry: &GuidRegistry,
) -> Vec<IntuneEvent> {
    let mut events = Vec::new();
    let mut next_id = 0u64;
    let source_kind = classify_source_kind(source_file);

    for line in lines {
        if source_kind == ImeSourceKind::AppWorkload {
            if let Some(event) =
                extract_appworkload_event(line, source_file, next_id, registry)
            {
                events.push(event);
                next_id += 1;
            }
            continue;
        }

        let Some(event_type) = detect_event_type(&line.message, source_kind) else {
            continue;
        };

        // Try primary extract_guid, fall back to guid_registry::extract_app_id
        let guid = extract_guid(&line.message)
            .or_else(|| guid_registry::extract_app_id(&line.message));
        let status = determine_status(&line.message, source_kind);
        let raw_name = build_event_name(&event_type, &guid, &line.message, source_kind);

        // Inline enrichment: resolve GUID suffix immediately if possible
        let name = match guid.as_deref() {
            Some(g) => registry.enrich_event_name(&raw_name, g).unwrap_or(raw_name),
            None => raw_name,
        };

        let detail = line.message.clone();

        events.push(IntuneEvent {
            id: next_id,
            event_type,
            name,
            guid,
            status,
            start_time: line
                .timestamp_utc
                .clone()
                .or_else(|| line.timestamp.clone()),
            end_time: None,
            duration_secs: None,
            error_code: extract_error_code(&line.message),
            detail,
            source_file: source_file.to_string(),
            line_number: line.line_number,
        });
        next_id += 1;
    }

    pair_events(&mut events);
    events
}

fn extract_appworkload_event(
    line: &ImeLine,
    source_file: &str,
    next_id: u64,
    registry: &GuidRegistry,
) -> Option<IntuneEvent> {
    let msg = line.message.as_str();
    if contains_any_ascii_case_insensitive(
        msg,
        &[
            "reportingmanager",
            "reportingcachemanager",
            "reporting state initialized",
            "sending reports",
            "writeabletostorage",
            "cangenerate",
            "isappreportable",
        ],
    ) {
        return None;
    }

    let flags = AppWorkloadMatchFlags::from_message(msg);
    if !flags.is_candidate() {
        return None;
    }

    let event_type = if flags.winget_token || flags.winget {
        IntuneEventType::WinGetApp
    } else if flags.download || flags.staging || flags.retry || flags.stall {
        IntuneEventType::ContentDownload
    } else if flags.install {
        IntuneEventType::Win32App
    } else {
        return None;
    };

    // Try primary extract_guid, fall back to guid_registry::extract_app_id
    let guid = extract_guid(msg).or_else(|| guid_registry::extract_app_id(msg));
    let status = determine_appworkload_status(msg, flags);
    let raw_name = build_appworkload_name(&event_type, &guid, msg, flags);

    // Inline enrichment: resolve GUID suffix immediately if possible
    let name = match guid.as_deref() {
        Some(g) => registry.enrich_event_name(&raw_name, g).unwrap_or(raw_name),
        None => raw_name,
    };

    Some(IntuneEvent {
        id: next_id,
        event_type,
        name,
        guid,
        status,
        start_time: line
            .timestamp_utc
            .clone()
            .or_else(|| line.timestamp.clone()),
        end_time: None,
        duration_secs: None,
        error_code: extract_error_code(msg),
        detail: build_detail(msg),
        source_file: source_file.to_string(),
        line_number: line.line_number,
    })
}

fn determine_appworkload_status(msg: &str, flags: AppWorkloadMatchFlags) -> IntuneStatus {
    if flags.stall || flags.timeout {
        IntuneStatus::Timeout
    } else if flags.retry || flags.failure {
        IntuneStatus::Failed
    } else if flags.success {
        IntuneStatus::Success
    } else if flags.queue || flags.pending || contains_ascii_case_insensitive(msg, "pending") {
        IntuneStatus::Pending
    } else {
        IntuneStatus::InProgress
    }
}

fn build_appworkload_name(
    event_type: &IntuneEventType,
    guid: &Option<String>,
    msg: &str,
    flags: AppWorkloadMatchFlags,
) -> String {
    if *event_type == IntuneEventType::WinGetApp {
        return match guid.as_deref().map(short_guid) {
            Some(short) => format!("AppWorkload WinGet ({short})"),
            None => "AppWorkload WinGet".to_string(),
        };
    }

    let phase = if flags.stall {
        "Download Stall"
    } else if flags.retry {
        "Download Retry"
    } else if flags.hash {
        "Hash Validation"
    } else if flags.staging {
        "Staging"
    } else if flags.install {
        "Install"
    } else if flags.download {
        "Download"
    } else {
        return build_event_name(event_type, guid, msg, ImeSourceKind::AppWorkload);
    };

    match guid.as_deref().map(short_guid) {
        Some(short) => format!("AppWorkload {phase} ({short})"),
        None => format!("AppWorkload {phase}"),
    }
}

fn build_detail(msg: &str) -> String {
    msg.to_string()
}

fn classify_source_kind(source_file: &str) -> ImeSourceKind {
    let file_name = Path::new(source_file)
        .file_name()
        .map(|name| name.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_else(|| source_file.to_ascii_lowercase());

    if file_name.contains("appworkload") {
        ImeSourceKind::AppWorkload
    } else if file_name.contains("appactionprocessor") {
        ImeSourceKind::AppActionProcessor
    } else if file_name.contains("agentexecutor") {
        ImeSourceKind::AgentExecutor
    } else if file_name.contains("healthscripts") {
        ImeSourceKind::HealthScripts
    } else if file_name.contains("clienthealth") {
        ImeSourceKind::ClientHealth
    } else if file_name.contains("clientcertcheck") {
        ImeSourceKind::ClientCertCheck
    } else if file_name.contains("devicehealthmonitoring") {
        ImeSourceKind::DeviceHealthMonitoring
    } else if file_name.contains("sensor") {
        ImeSourceKind::Sensor
    } else if file_name.contains("win32appinventory") {
        ImeSourceKind::Win32AppInventory
    } else if file_name.contains("intunemanagementextension") {
        ImeSourceKind::PrimaryIme
    } else {
        ImeSourceKind::Other
    }
}

fn detect_event_type(msg: &str, source_kind: ImeSourceKind) -> Option<IntuneEventType> {
    match source_kind {
        ImeSourceKind::AppWorkload => {
            if !is_appworkload_event_candidate(msg) {
                return None;
            }
            if WINGET_TOKEN_RE.is_match(msg) || WINGET_RE.is_match(msg) {
                return Some(IntuneEventType::WinGetApp);
            }
            if APPWORKLOAD_DOWNLOAD_RE.is_match(msg)
                || APPWORKLOAD_STAGING_RE.is_match(msg)
                || APPWORKLOAD_RETRY_RE.is_match(msg)
                || APPWORKLOAD_STALL_RE.is_match(msg)
            {
                return Some(IntuneEventType::ContentDownload);
            }
            if APPWORKLOAD_INSTALL_RE.is_match(msg) {
                return Some(IntuneEventType::Win32App);
            }
        }
        ImeSourceKind::AppActionProcessor => {
            if is_app_action_processor_event_candidate(msg)
                && (POLICY_EVAL_RE.is_match(msg)
                    || APP_ACTION_RE.is_match(msg)
                    || APPLICABILITY_RE.is_match(msg))
            {
                return Some(IntuneEventType::PolicyEvaluation);
            }
        }
        ImeSourceKind::AgentExecutor => {
            if !is_agent_executor_event_candidate(msg) {
                return None;
            }
            if REMEDIATION_SCRIPT_RE.is_match(msg) || REMEDIATION_RE.is_match(msg) {
                return Some(IntuneEventType::Remediation);
            }
            if AGENTEXECUTOR_SCRIPT_RE.is_match(msg)
                || SCRIPT_RE.is_match(msg)
                || SCRIPT_RESULT_RE.is_match(msg)
            {
                return Some(IntuneEventType::PowerShellScript);
            }
        }
        ImeSourceKind::HealthScripts => {
            if is_healthscripts_event_candidate(msg)
                && (HEALTHSCRIPT_RE.is_match(msg) || REMEDIATION_RE.is_match(msg))
            {
                return Some(IntuneEventType::Remediation);
            }
        }
        ImeSourceKind::ClientHealth => {
            if is_client_health_event_candidate(msg) {
                return Some(IntuneEventType::Other);
            }
        }
        ImeSourceKind::ClientCertCheck => {
            if is_client_cert_check_event_candidate(msg) {
                return Some(IntuneEventType::Other);
            }
        }
        ImeSourceKind::DeviceHealthMonitoring => {
            if DEVICE_HEALTH_APP_CRASH_RE.is_match(msg) {
                return Some(IntuneEventType::Other);
            }
        }
        ImeSourceKind::Sensor => {
            if SENSOR_MEMORY_FAILURE_RE.is_match(msg) {
                return Some(IntuneEventType::Other);
            }
        }
        ImeSourceKind::Win32AppInventory => {
            if is_win32_app_inventory_event_candidate(msg) {
                return Some(IntuneEventType::Other);
            }
        }
        ImeSourceKind::PrimaryIme | ImeSourceKind::Other => {}
    }

    if WIN32_APP_RE.is_match(msg) || WIN32_RESULT_RE.is_match(msg) {
        Some(IntuneEventType::Win32App)
    } else if WINGET_RE.is_match(msg) {
        Some(IntuneEventType::WinGetApp)
    } else if SCRIPT_RE.is_match(msg) || SCRIPT_RESULT_RE.is_match(msg) {
        Some(IntuneEventType::PowerShellScript)
    } else if REMEDIATION_RE.is_match(msg) {
        Some(IntuneEventType::Remediation)
    } else if ESP_RE.is_match(msg) {
        Some(IntuneEventType::Esp)
    } else if SYNC_RE.is_match(msg) {
        Some(IntuneEventType::SyncSession)
    } else {
        None
    }
}

fn is_agent_executor_event_candidate(msg: &str) -> bool {
    if ends_with_ascii_case_insensitive(msg, ".timeout")
        || ends_with_ascii_case_insensitive(msg, "quotedtimeoutfilepath.txt")
        || contains_any_ascii_case_insensitive(
            msg,
            &[
                "prepare to run powershell script",
                "remediation script option gets invoked",
                "creating command line parser",
                "adding argument",
                "powershell path is",
            ],
        )
    {
        return false;
    }

    contains_any_ascii_case_insensitive(
        msg,
        &[
            "powershell exit code",
            "powershell script is successfully executed",
            "detection script",
            "remediation script",
            "script completed",
            "script failed",
            "script execution",
            "timed out",
            "timeout",
            "stdout",
            "stderr",
            "exit code",
        ],
    )
}

fn is_appworkload_event_candidate(msg: &str) -> bool {
    if contains_any_ascii_case_insensitive(
        msg,
        &[
            "reportingmanager",
            "reportingcachemanager",
            "reporting state initialized",
            "sending reports",
            "writeabletostorage",
            "cangenerate",
            "isappreportable",
        ],
    ) {
        return false;
    }

    APPWORKLOAD_DOWNLOAD_RE.is_match(msg)
        || APPWORKLOAD_STAGING_RE.is_match(msg)
        || APPWORKLOAD_INSTALL_RE.is_match(msg)
        || APPWORKLOAD_RETRY_RE.is_match(msg)
        || APPWORKLOAD_STALL_RE.is_match(msg)
        || WINGET_TOKEN_RE.is_match(msg)
}

fn is_app_action_processor_event_candidate(msg: &str) -> bool {
    !(contains_ascii_case_insensitive(msg, "processor initializing")
        || (contains_ascii_case_insensitive(msg, "found:")
            && contains_ascii_case_insensitive(msg, "apps with intent"))
        || contains_ascii_case_insensitive(
            msg,
            "evaluating install enforcement actions for app with id",
        )
        || contains_ascii_case_insensitive(msg, "no action required for app with id"))
        && contains_any_ascii_case_insensitive(
            msg,
            &[
                "app with id:",
                "assignment evaluation",
                "targeted intent",
                "applicability =",
                "not applicable",
                "local deadline",
                "grs expired",
                "grs not expired",
                "requirement rule",
                "detection rule",
                "will not be enforced",
            ],
        )
}

fn is_healthscripts_event_candidate(msg: &str) -> bool {
    if contains_any_ascii_case_insensitive(
        msg,
        &[
            "inspect hourly schedule",
            "job is queued and will be scheduled",
            "completed user session",
        ],
    ) {
        return false;
    }

    contains_any_ascii_case_insensitive(
        msg,
        &[
            "detection script",
            "remediation script",
            "exit code of the script",
            "compliance result",
            "pre-detect",
            "post-detect",
            "timed out",
            "timeout",
            "failed",
            "schedule",
        ],
    )
}

fn is_client_health_event_candidate(msg: &str) -> bool {
    CLIENT_HEALTH_HEARTBEAT_SUCCESS_RE.is_match(msg)
        || CLIENT_HEALTH_HEARTBEAT_FAILURE_RE.is_match(msg)
        || matches!(
            parse_client_health_summary(msg),
            Some((_, IntuneStatus::Failed, _))
        )
}

fn is_client_cert_check_event_candidate(msg: &str) -> bool {
    parse_client_cert_local_machine_count(msg) == Some(0) || CLIENT_CERT_FAILURE_RE.is_match(msg)
}

fn is_win32_app_inventory_event_candidate(msg: &str) -> bool {
    WIN32_APP_INVENTORY_FULL_RE.is_match(msg)
        || WIN32_APP_INVENTORY_NO_CHANGE_RE.is_match(msg)
        || matches!(parse_win32_app_inventory_delta(msg), Some((add, modify, delete)) if add > 0 || modify > 0 || delete > 0)
}

fn extract_guid(msg: &str) -> Option<String> {
    WIN32_GUID_RE
        .captures(msg)
        .and_then(|cap| cap.get(1))
        .map(|value| value.as_str().to_string())
        .or_else(|| {
            GUID_RE
                .captures(msg)
                .and_then(|cap| cap.get(1))
                .map(|value| value.as_str().to_string())
        })
}

fn extract_error_code(msg: &str) -> Option<String> {
    ERROR_CODE_RE
        .captures(msg)
        .and_then(|cap| cap.get(1))
        .map(|value| value.as_str().to_string())
}

fn determine_status(msg: &str, source_kind: ImeSourceKind) -> IntuneStatus {
    if COMPLIANCE_TRUE_RE.is_match(msg) {
        return IntuneStatus::Success;
    }
    if COMPLIANCE_FALSE_RE.is_match(msg) {
        return IntuneStatus::Failed;
    }
    if let Some(exit_code) = EXIT_CODE_RE
        .captures(msg)
        .and_then(|cap| cap.get(1))
        .and_then(|value| value.as_str().parse::<i32>().ok())
    {
        return if exit_code == 0 {
            IntuneStatus::Success
        } else {
            IntuneStatus::Failed
        };
    }

    match source_kind {
        ImeSourceKind::AppWorkload => {
            if APPWORKLOAD_STALL_RE.is_match(msg) || TIMEOUT_RE.is_match(msg) {
                IntuneStatus::Timeout
            } else if APPWORKLOAD_RETRY_RE.is_match(msg) || APPWORKLOAD_FAILURE_RE.is_match(msg) {
                IntuneStatus::Failed
            } else if APPWORKLOAD_SUCCESS_RE.is_match(msg) {
                IntuneStatus::Success
            } else if APPWORKLOAD_QUEUE_RE.is_match(msg) || PENDING_RE.is_match(msg) {
                IntuneStatus::Pending
            } else {
                IntuneStatus::InProgress
            }
        }
        ImeSourceKind::AppActionProcessor => {
            if APPLICABILITY_BLOCK_RE.is_match(msg) {
                IntuneStatus::Failed
            } else if APPLICABILITY_SUCCESS_RE.is_match(msg) {
                IntuneStatus::Success
            } else if POLICY_PENDING_RE.is_match(msg) {
                IntuneStatus::Pending
            } else {
                IntuneStatus::InProgress
            }
        }
        ImeSourceKind::AgentExecutor | ImeSourceKind::HealthScripts => {
            if TIMEOUT_RE.is_match(msg) {
                IntuneStatus::Timeout
            } else if SCRIPT_FAILURE_RE.is_match(msg) || FAILED_RE.is_match(msg) {
                IntuneStatus::Failed
            } else if SUCCESS_RE.is_match(msg) {
                IntuneStatus::Success
            } else if PENDING_RE.is_match(msg) {
                IntuneStatus::Pending
            } else {
                IntuneStatus::InProgress
            }
        }
        ImeSourceKind::ClientHealth => {
            if let Some((_, status, _)) = parse_client_health_summary(msg) {
                status
            } else if CLIENT_HEALTH_HEARTBEAT_FAILURE_RE.is_match(msg) {
                IntuneStatus::Failed
            } else if CLIENT_HEALTH_HEARTBEAT_SUCCESS_RE.is_match(msg) {
                IntuneStatus::Success
            } else {
                IntuneStatus::Unknown
            }
        }
        ImeSourceKind::ClientCertCheck => {
            if parse_client_cert_local_machine_count(msg) == Some(0)
                || CLIENT_CERT_FAILURE_RE.is_match(msg)
            {
                IntuneStatus::Failed
            } else {
                IntuneStatus::Unknown
            }
        }
        ImeSourceKind::DeviceHealthMonitoring | ImeSourceKind::Sensor => IntuneStatus::Failed,
        ImeSourceKind::Win32AppInventory => IntuneStatus::Success,
        ImeSourceKind::PrimaryIme | ImeSourceKind::Other => {
            if TIMEOUT_RE.is_match(msg) {
                IntuneStatus::Timeout
            } else if FAILED_RE.is_match(msg) {
                IntuneStatus::Failed
            } else if SUCCESS_RE.is_match(msg) {
                IntuneStatus::Success
            } else if PENDING_RE.is_match(msg) {
                IntuneStatus::Pending
            } else {
                IntuneStatus::InProgress
            }
        }
    }
}

fn build_event_name(
    event_type: &IntuneEventType,
    guid: &Option<String>,
    msg: &str,
    source_kind: ImeSourceKind,
) -> String {
    if let Some(name) = build_source_specific_name(event_type, guid, msg, source_kind) {
        return name;
    }

    let label = match event_type {
        IntuneEventType::Win32App => "Win32 App",
        IntuneEventType::WinGetApp => "WinGet App",
        IntuneEventType::PowerShellScript => "PowerShell Script",
        IntuneEventType::Remediation => "Remediation",
        IntuneEventType::Esp => "ESP",
        IntuneEventType::SyncSession => "Sync Session",
        IntuneEventType::PolicyEvaluation => "Policy Evaluation",
        IntuneEventType::ContentDownload => "Content Download",
        IntuneEventType::Other => "Other",
    };

    if let Some(guid) = guid {
        let short = short_guid(guid);
        format!("{label} ({short})")
    } else {
        format!("{label}: {msg}")
    }
}

fn build_source_specific_name(
    event_type: &IntuneEventType,
    guid: &Option<String>,
    msg: &str,
    source_kind: ImeSourceKind,
) -> Option<String> {
    let short_guid = guid.as_deref().map(short_guid);

    match source_kind {
        ImeSourceKind::AppWorkload => {
            let phase = if APPWORKLOAD_STALL_RE.is_match(msg) {
                "Download Stall"
            } else if APPWORKLOAD_RETRY_RE.is_match(msg) {
                "Download Retry"
            } else if APPWORKLOAD_HASH_RE.is_match(msg) {
                "Hash Validation"
            } else if APPWORKLOAD_STAGING_RE.is_match(msg) {
                "Staging"
            } else if APPWORKLOAD_INSTALL_RE.is_match(msg) {
                "Install"
            } else if APPWORKLOAD_DOWNLOAD_RE.is_match(msg) {
                "Download"
            } else {
                return None;
            };
            Some(match short_guid {
                Some(short) => format!("AppWorkload {phase} ({short})"),
                None => format!("AppWorkload {phase}"),
            })
        }
        ImeSourceKind::AppActionProcessor => {
            let area = if APPLICABILITY_BLOCK_RE.is_match(msg) || APPLICABILITY_RE.is_match(msg) {
                "Applicability"
            } else if contains_case_insensitive(msg, "requirement rule") {
                "Requirement Rule"
            } else if contains_case_insensitive(msg, "detection rule") {
                "Detection Rule"
            } else if POLICY_EVAL_RE.is_match(msg) {
                "Policy Evaluation"
            } else {
                return None;
            };
            Some(match short_guid {
                Some(short) => format!("AppActionProcessor {area} ({short})"),
                None => format!("AppActionProcessor {area}"),
            })
        }
        ImeSourceKind::AgentExecutor => {
            let area = if REMEDIATION_SCRIPT_RE.is_match(msg)
                || *event_type == IntuneEventType::Remediation
            {
                "Remediation Script"
            } else if DETECTION_SCRIPT_RE.is_match(msg) {
                "Detection Script"
            } else if TIMEOUT_RE.is_match(msg) {
                "Script Timeout"
            } else {
                "PowerShell Script"
            };
            Some(match short_guid {
                Some(short) => format!("AgentExecutor {area} ({short})"),
                None => format!("AgentExecutor {area}"),
            })
        }
        ImeSourceKind::HealthScripts => {
            let area = if REMEDIATION_SCRIPT_RE.is_match(msg) {
                "Remediation"
            } else if DETECTION_SCRIPT_RE.is_match(msg)
                || contains_case_insensitive(msg, "compliance result")
            {
                "Detection"
            } else {
                "Schedule"
            };
            Some(match short_guid {
                Some(short) => format!("HealthScripts {area} ({short})"),
                None => format!("HealthScripts {area}"),
            })
        }
        ImeSourceKind::ClientHealth => {
            if let Some((rule, status, details)) = parse_client_health_summary(msg) {
                let status_label = match status {
                    IntuneStatus::Success => "Passed",
                    IntuneStatus::Failed => "Failed",
                    IntuneStatus::Pending => "Pending",
                    IntuneStatus::InProgress => "In Progress",
                    IntuneStatus::Timeout => "Timed Out",
                    IntuneStatus::Unknown => "Unknown",
                };
                let suffix = if details.eq_ignore_ascii_case("N/A") {
                    String::new()
                } else {
                    format!(": {}", details.chars().take(40).collect::<String>())
                };
                return Some(format!("ClientHealth Rule {status_label}: {rule}{suffix}"));
            }
            if CLIENT_HEALTH_HEARTBEAT_FAILURE_RE.is_match(msg) {
                Some("ClientHealth Heartbeat Failed".to_string())
            } else if CLIENT_HEALTH_HEARTBEAT_SUCCESS_RE.is_match(msg) {
                Some("ClientHealth Heartbeat Sent".to_string())
            } else {
                None
            }
        }
        ImeSourceKind::ClientCertCheck => {
            if parse_client_cert_local_machine_count(msg) == Some(0) {
                Some("ClientCertCheck Missing MDM Certificate".to_string())
            } else if CLIENT_CERT_FAILURE_RE.is_match(msg) {
                Some("ClientCertCheck Validation Failure".to_string())
            } else {
                None
            }
        }
        ImeSourceKind::DeviceHealthMonitoring => {
            parse_device_health_app_crash(msg).map(|(app_name, exception_code)| {
                format!(
                    "DeviceHealthMonitoring App Crash: {} ({})",
                    app_name, exception_code
                )
            })
        }
        ImeSourceKind::Sensor => {
            if SENSOR_MEMORY_FAILURE_RE.is_match(msg) {
                Some("Sensor Hardware Readiness Memory Failure".to_string())
            } else {
                None
            }
        }
        ImeSourceKind::Win32AppInventory => {
            if WIN32_APP_INVENTORY_FULL_RE.is_match(msg) {
                Some("Win32AppInventory Full Inventory".to_string())
            } else if WIN32_APP_INVENTORY_NO_CHANGE_RE.is_match(msg) {
                Some("Win32AppInventory No Delta".to_string())
            } else if let Some((add, modify, delete)) = parse_win32_app_inventory_delta(msg) {
                Some(format!(
                    "Win32AppInventory Delta (+{add} ~{modify} -{delete})"
                ))
            } else {
                None
            }
        }
        ImeSourceKind::PrimaryIme | ImeSourceKind::Other => None,
    }
}

fn parse_client_health_summary(msg: &str) -> Option<(String, IntuneStatus, String)> {
    let captures = CLIENT_HEALTH_RULE_SUMMARY_RE.captures(msg)?;
    let rule = captures.get(1)?.as_str().trim().to_string();
    let status = match captures.get(2)?.as_str().to_ascii_lowercase().as_str() {
        "pass" => IntuneStatus::Success,
        "fail" => IntuneStatus::Failed,
        _ => IntuneStatus::Unknown,
    };
    let details = captures.get(3)?.as_str().trim().to_string();
    Some((rule, status, details))
}

fn parse_client_cert_local_machine_count(msg: &str) -> Option<u32> {
    CLIENT_CERT_LOCAL_MACHINE_COUNT_RE
        .captures(msg)
        .and_then(|cap| cap.get(1))
        .and_then(|value| value.as_str().parse::<u32>().ok())
}

fn parse_device_health_app_crash(msg: &str) -> Option<(String, String)> {
    let captures = DEVICE_HEALTH_APP_CRASH_RE.captures(msg)?;
    let app_name = captures.get(1)?.as_str().trim().to_string();
    let exception_code = captures.get(2)?.as_str().trim().to_string();
    Some((app_name, exception_code))
}

fn parse_win32_app_inventory_delta(msg: &str) -> Option<(u32, u32, u32)> {
    let captures = WIN32_APP_INVENTORY_DELTA_RE.captures(msg)?;
    let add = captures.get(1)?.as_str().parse::<u32>().ok()?;
    let modify = captures.get(2)?.as_str().parse::<u32>().ok()?;
    let delete = captures.get(3)?.as_str().parse::<u32>().ok()?;
    Some((add, modify, delete))
}

fn short_guid(value: &str) -> &str {
    value
}

fn contains_case_insensitive(value: &str, needle: &str) -> bool {
    contains_ascii_case_insensitive(value, needle)
}

fn contains_any_ascii_case_insensitive(value: &str, needles: &[&str]) -> bool {
    needles
        .iter()
        .copied()
        .any(|needle| contains_ascii_case_insensitive(value, needle))
}

fn contains_ascii_case_insensitive(value: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > value.len() {
        return false;
    }

    value
        .as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle.as_bytes()))
}

fn ends_with_ascii_case_insensitive(value: &str, suffix: &str) -> bool {
    value
        .get(value.len().saturating_sub(suffix.len())..)
        .is_some_and(|tail| tail.eq_ignore_ascii_case(suffix))
}

fn pair_events(events: &mut Vec<IntuneEvent>) {
    let mut consumed_end_indices: HashSet<usize> = HashSet::new();
    let mut open_events: HashMap<String, Vec<usize>> = HashMap::new();

    for index in 0..events.len() {
        let status = events[index].status;
        let Some(identity_key) = event_identity_key(&events[index]) else {
            continue;
        };

        if status == IntuneStatus::InProgress {
            open_events.entry(identity_key).or_default().push(index);
            continue;
        }
        if !(status == IntuneStatus::Success
            || status == IntuneStatus::Failed
            || status == IntuneStatus::Timeout)
        {
            continue;
        }

        let Some(start_index) = open_events
            .get_mut(&identity_key)
            .and_then(|indices| indices.pop())
        else {
            continue;
        };
        if consumed_end_indices.contains(&index) {
            continue;
        }

        events[start_index].end_time = events[index].start_time.clone();
        events[start_index].status = events[index].status;
        events[start_index].error_code = events[index]
            .error_code
            .clone()
            .or_else(|| events[start_index].error_code.clone());

        if let (Some(start), Some(end)) = (
            &events[start_index].start_time,
            &events[start_index].end_time,
        ) {
            events[start_index].duration_secs = estimate_duration(start, end);
        }

        consumed_end_indices.insert(index);
    }

    if consumed_end_indices.is_empty() {
        return;
    }

    let mut index = 0usize;
    events.retain(|_| {
        let keep = !consumed_end_indices.contains(&index);
        index += 1;
        keep
    });
}

fn event_identity_key(event: &IntuneEvent) -> Option<String> {
    if let Some(guid) = &event.guid {
        return Some(format!(
            "{}|{}|{}",
            event.source_file,
            event_type_identity(&event.event_type),
            guid
        ));
    }

    let normalized_name = normalize_identity_fragment(&event.name);
    if normalized_name.is_empty() {
        None
    } else {
        Some(format!(
            "{}|{}|{}",
            event.source_file,
            event_type_identity(&event.event_type),
            normalized_name
        ))
    }
}

fn event_type_identity(event_type: &IntuneEventType) -> &'static str {
    match event_type {
        IntuneEventType::Win32App => "win32",
        IntuneEventType::WinGetApp => "winget",
        IntuneEventType::PowerShellScript => "script",
        IntuneEventType::Remediation => "remediation",
        IntuneEventType::Esp => "esp",
        IntuneEventType::SyncSession => "sync",
        IntuneEventType::PolicyEvaluation => "policy",
        IntuneEventType::ContentDownload => "download",
        IntuneEventType::Other => "other",
    }
}

fn normalize_identity_fragment(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                ' '
            }
        })
        .collect::<String>()
        .split_whitespace()
        .take(6)
        .collect::<Vec<_>>()
        .join(" ")
}

fn estimate_duration(start: &str, end: &str) -> Option<f64> {
    if let (Some(start_dt), Some(end_dt)) =
        (parse_event_timestamp(start), parse_event_timestamp(end))
    {
        return Some((end_dt - start_dt).num_milliseconds().abs() as f64 / 1000.0);
    }

    let parse_seconds = |ts: &str| -> Option<f64> {
        let time_part = ts.split_whitespace().last()?;
        let parts: Vec<&str> = time_part.split(':').collect();
        if parts.len() >= 3 {
            let h: f64 = parts[0].parse().ok()?;
            let m: f64 = parts[1].parse().ok()?;
            let s: f64 = parts[2].parse().ok()?;
            Some(h * 3600.0 + m * 60.0 + s)
        } else {
            None
        }
    };

    let start_secs = parse_seconds(start)?;
    let end_secs = parse_seconds(end)?;
    let diff = end_secs - start_secs;
    if diff >= 0.0 {
        Some(diff)
    } else {
        Some(diff + 86400.0)
    }
}

fn parse_event_timestamp(value: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    if let Ok(parsed) = chrono::DateTime::parse_from_rfc3339(value) {
        return Some(parsed.with_timezone(&chrono::Utc));
    }

    let naive = chrono::NaiveDateTime::parse_from_str(value, "%m-%d-%Y %H:%M:%S%.f").ok()?;
    Some(chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(
        naive,
        chrono::Utc,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_registry() -> GuidRegistry {
        GuidRegistry::new()
    }

    fn line(message: &str, timestamp: &str, line_number: u32) -> ImeLine {
        ImeLine {
            line_number,
            timestamp: Some(timestamp.to_string()),
            timestamp_utc: Some(timestamp.to_string()),
            message: message.to_string(),
            component: None,
        }
    }

    #[test]
    fn extract_events_prefers_utc_normalized_timestamp() {
        let events = extract_events(
            &[ImeLine {
                line_number: 1,
                timestamp: Some("03-12-2026 11:16:42.332".to_string()),
                timestamp_utc: Some("2026-03-12T11:16:42.332Z".to_string()),
                message: "Assignment evaluation failed for app with id: a1b2c3d4-e5f6-7890-abcd-ef1234567890".to_string(),
                component: None,
            }],
            "C:/Logs/AppActionProcessor.log",
            &empty_registry(),
        );

        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].start_time.as_deref(),
            Some("2026-03-12T11:16:42.332Z")
        );
    }

    #[test]
    fn estimate_duration_supports_iso_timestamps() {
        assert_eq!(
            estimate_duration("2026-03-12T11:16:42.332Z", "2026-03-12T11:16:47.332Z"),
            Some(5.0)
        );
    }

    #[test]
    fn appworkload_extracts_stalled_download_events() {
        let events = extract_events(
            &[line(
                "AppWorkload download stalled with no progress for app id: a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                "01-15-2024 10:00:05.000",
                1,
            )],
            "C:/Logs/AppWorkload.log",
            &empty_registry(),
        );

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, IntuneEventType::ContentDownload);
        assert_eq!(events[0].status, IntuneStatus::Timeout);
    }

    #[test]
    fn app_action_processor_marks_not_applicable_as_failed() {
        let events = extract_events(
            &[line(
                "Assignment evaluation found app is not applicable and will not be enforced for app with id: a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                "01-15-2024 10:00:05.000",
                1,
            )],
            "C:/Logs/AppActionProcessor.log",
            &empty_registry(),
        );

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, IntuneEventType::PolicyEvaluation);
        assert_eq!(events[0].status, IntuneStatus::Failed);
    }

    #[test]
    fn agent_executor_extracts_remediation_timeout() {
        let events = extract_events(
            &[line(
                "AgentExecutor remediation script timed out for package a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                "01-15-2024 10:00:05.000",
                1,
            )],
            "C:/Logs/AgentExecutor.log",
            &empty_registry(),
        );

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, IntuneEventType::Remediation);
        assert_eq!(events[0].status, IntuneStatus::Timeout);
    }

    #[test]
    fn agent_executor_skips_argument_parsing_noise() {
        let events = extract_events(
            &[
                line(
                    "Creating command line parser, name delimiter is - and value separator is .",
                    "01-15-2024 10:00:05.000",
                    1,
                ),
                line(
                    "Adding argument remediationScript with value C:\\Windows\\IMECache\\HealthScripts\\abc\\detect.ps1 to the named argument list.",
                    "01-15-2024 10:00:06.000",
                    2,
                ),
            ],
            "C:/Logs/AgentExecutor.log",
            &empty_registry(),
        );

        assert!(events.is_empty());
    }

    #[test]
    fn client_health_extracts_heartbeat_failure() {
        let events = extract_events(
            &[line(
                "Failed to send heartbeat report, exception = System.NullReferenceException: Object reference not set to an instance of an object.",
                "01-15-2024 10:00:05.000",
                1,
            )],
            "C:/Logs/ClientHealth.log",
            &empty_registry(),
        );

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, IntuneEventType::Other);
        assert_eq!(events[0].status, IntuneStatus::Failed);
        assert_eq!(events[0].name, "ClientHealth Heartbeat Failed");
    }

    #[test]
    fn client_health_ignores_passing_rule_summaries() {
        let events = extract_events(
            &[line(
                "Summary: rule Verify Intune Management Extension service exists. with ID b862e7a7-fe34-47f3-a648-edd4803f781a, result = Pass, details = N/A",
                "01-15-2024 10:00:05.000",
                1,
            )],
            "C:/Logs/ClientHealth.log",
            &empty_registry(),
        );

        assert!(events.is_empty());
    }

    #[test]
    fn client_cert_check_detects_missing_local_machine_certificate() {
        let events = extract_events(
            &[line(
                "MDM certs found in LocalMachine count: 0",
                "01-15-2024 10:00:05.000",
                1,
            )],
            "C:/Logs/ClientCertCheck.log",
            &empty_registry(),
        );

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, IntuneEventType::Other);
        assert_eq!(events[0].status, IntuneStatus::Failed);
        assert_eq!(events[0].name, "ClientCertCheck Missing MDM Certificate");
    }

    #[test]
    fn device_health_monitoring_extracts_app_crash_event() {
        let events = extract_events(
            &[line(
                "[datasensor] received application event, RecordId: 19583, 1000 , <![CDATA[<EventData xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">\n  <Data Name=\"AppName\">SenseNdr.exe</Data>\n  <Data Name=\"ExceptionCode\">c0000409</Data>\n</EventData>]]>",
                "01-15-2024 10:00:05.000",
                1,
            )],
            "C:/Logs/DeviceHealthMonitoring.log",
            &empty_registry(),
        );

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, IntuneEventType::Other);
        assert_eq!(events[0].status, IntuneStatus::Failed);
        assert_eq!(
            events[0].name,
            "DeviceHealthMonitoring App Crash: SenseNdr.exe (c0000409)"
        );
    }

    #[test]
    fn sensor_extracts_memory_failure() {
        let events = extract_events(
            &[line(
                "Win32Exception occurred. Error: 0; Message: Call to GetPhysicallyInstalledSystemMemory failed.; Stacktrace:",
                "01-15-2024 10:00:05.000",
                1,
            )],
            "C:/Logs/Sensor.log",
            &empty_registry(),
        );

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, IntuneEventType::Other);
        assert_eq!(events[0].status, IntuneStatus::Failed);
        assert_eq!(events[0].name, "Sensor Hardware Readiness Memory Failure");
    }

    #[test]
    fn win32_app_inventory_extracts_non_zero_delta() {
        let events = extract_events(
            &[line(
                "[Win32AppInventory] Computing delta inventory...Done. Add count = 2, Modify count = 0, Delete count = 2",
                "01-15-2024 10:00:05.000",
                1,
            )],
            "C:/Logs/Win32AppInventory.log",
            &empty_registry(),
        );

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, IntuneEventType::Other);
        assert_eq!(events[0].status, IntuneStatus::Success);
        assert_eq!(events[0].name, "Win32AppInventory Delta (+2 ~0 -2)");
    }

    #[test]
    fn win32_app_inventory_ignores_no_user_skip_noise() {
        let events = extract_events(
            &[line(
                "[Win32AppInventory] OnAppInventoryCollecting There is no any AAD User logged in, skip this round of inventory collection.",
                "01-15-2024 10:00:05.000",
                1,
            )],
            "C:/Logs/Win32AppInventory.log",
            &empty_registry(),
        );

        assert!(events.is_empty());
    }

    #[test]
    fn paired_completion_events_are_collapsed() {
        let events = extract_events(
            &[
                line(
                    "[Win32App] Processing app with id: a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                    "01-15-2024 10:00:00.000",
                    1,
                ),
                line(
                    "[Win32App] Completed successfully for app with id: a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                    "01-15-2024 10:01:00.000",
                    2,
                ),
            ],
            "C:/Logs/IntuneManagementExtension.log",
            &empty_registry(),
        );

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].status, IntuneStatus::Success);
        assert_eq!(events[0].duration_secs, Some(60.0));
    }

    #[test]
    fn appworkload_request_payload_events_are_paired() {
        let events = extract_events(
            &[
                line(
                    r#"Starting content download RequestPayload: {\"AppId\":\"a1b2c3d4-e5f6-7890-abcd-ef1234567890\",\"ApplicationName\":\"Contoso App\"}"#,
                    "01-15-2024 10:00:00.000",
                    1,
                ),
                line(
                    r#"Download completed successfully RequestPayload: {\"AppId\":\"a1b2c3d4-e5f6-7890-abcd-ef1234567890\",\"ApplicationName\":\"Contoso App\"}"#,
                    "01-15-2024 10:00:05.000",
                    2,
                ),
            ],
            "C:/Logs/AppWorkload.log",
            &empty_registry(),
        );

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, IntuneEventType::ContentDownload);
        assert_eq!(events[0].status, IntuneStatus::Success);
        assert_eq!(
            events[0].guid.as_deref(),
            Some("a1b2c3d4-e5f6-7890-abcd-ef1234567890")
        );
        assert_eq!(events[0].duration_secs, Some(5.0));
    }
}
