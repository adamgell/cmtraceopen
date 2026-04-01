use chrono::{DateTime, Local, LocalResult, NaiveDateTime, TimeZone, Utc};
use regex::Regex;

use crate::dsregcmd::models::{
    DsregcmdCaptureConfidence, DsregcmdDerived, DsregcmdDiagnosticInsight,
    DsregcmdDiagnosticPhase, DsregcmdFacts, DsregcmdJoinType,
};
use crate::intune::models::IntuneDiagnosticSeverity;
use std::sync::OnceLock;

pub(super) const NETWORK_ERROR_MARKERS: &[&str] = &[
    "ERROR_WINHTTP_TIMEOUT",
    "ERROR_WINHTTP_NAME_NOT_RESOLVED",
    "ERROR_WINHTTP_CANNOT_CONNECT",
    "ERROR_WINHTTP_CONNECTION_ERROR",
];

fn certificate_timestamp_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
    Regex::new(
        r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?(?: UTC|Z)?|\d{1,2}/\d{1,2}/\d{4} \d{2}:\d{2}:\d{2}(?:\.\d+)?(?: UTC|Z)?",
    )
    .expect("valid certificate timestamp regex")
})
}

pub(super) fn derive_facts(facts: &DsregcmdFacts, raw_input: &str) -> DsregcmdDerived {
    let join_type = derive_join_type(facts);
    let join_type_label = join_type_label(join_type).to_string();
    let mdm_enrolled = if facts.management_details.mdm_url.is_some()
        || facts.management_details.mdm_compliance_url.is_some()
    {
        Some(true)
    } else {
        None
    };
    let missing_mdm = match (
        facts.management_details.mdm_url.is_some(),
        facts.management_details.mdm_compliance_url.is_some(),
    ) {
        (false, true) => Some(true),
        (true, _) => Some(false),
        (false, false) => None,
    };
    let compliance_url_present = if facts.management_details.mdm_compliance_url.is_some() {
        Some(true)
    } else if facts.management_details.mdm_url.is_some() {
        Some(false)
    } else {
        None
    };
    let missing_compliance_url = match (
        facts.management_details.mdm_url.is_some(),
        facts.management_details.mdm_compliance_url.is_some(),
    ) {
        (true, false) => Some(true),
        (true, true) => Some(false),
        (false, _) => None,
    };
    let azure_ad_prt_present = facts.sso_state.azure_ad_prt;
    let prt_reference_time = facts
        .diagnostics
        .client_time
        .as_deref()
        .and_then(parse_dsregcmd_timestamp)
        .or_else(|| Some(Utc::now()));
    let prt_last_update = facts
        .sso_state
        .azure_ad_prt_update_time
        .as_deref()
        .and_then(parse_dsregcmd_timestamp);
    let prt_age_hours = match (prt_reference_time, prt_last_update) {
        (Some(reference_time), Some(last_update)) => {
            let age_hours = reference_time
                .signed_duration_since(last_update)
                .num_minutes() as f64
                / 60.0;
            Some(age_hours.max(0.0))
        }
        _ => None,
    };
    let stale_prt = prt_age_hours.map(|hours| hours > 4.0);
    let tpm_protected = facts.device_details.tpm_protected;
    let (certificate_valid_from, certificate_valid_to) = facts
        .device_details
        .device_certificate_validity
        .as_deref()
        .map(parse_certificate_validity)
        .unwrap_or((None, None));
    let certificate_days_remaining = match (prt_reference_time, certificate_valid_to) {
        (Some(reference_time), Some(valid_to)) => {
            Some(valid_to.signed_duration_since(reference_time).num_days())
        }
        _ => None,
    };
    let certificate_expiring_soon = certificate_days_remaining.map(|days| days < 30);
    let network_error_code = detect_network_error(raw_input);
    let has_network_error = network_error_code.is_some();
    let remote_session_system = match (
        facts.diagnostics.user_context.as_deref(),
        facts.user_state.session_is_not_remote,
    ) {
        (Some(user_context), Some(false)) if user_context.eq_ignore_ascii_case("SYSTEM") => {
            Some(true)
        }
        (Some(_), Some(_)) => Some(false),
        _ => None,
    };
    let dominant_phase = derive_dominant_phase(facts);
    let phase_summary = phase_summary(dominant_phase).to_string();
    let (capture_confidence, capture_confidence_reason) =
        derive_capture_confidence(facts, prt_reference_time, remote_session_system);

    DsregcmdDerived {
        join_type,
        join_type_label,
        dominant_phase,
        phase_summary,
        capture_confidence,
        capture_confidence_reason,
        mdm_enrolled,
        missing_mdm,
        compliance_url_present,
        missing_compliance_url,
        azure_ad_prt_present,
        stale_prt,
        prt_last_update,
        prt_reference_time,
        prt_age_hours,
        tpm_protected,
        certificate_valid_from,
        certificate_valid_to,
        certificate_expiring_soon,
        certificate_days_remaining,
        network_error_code,
        has_network_error,
        remote_session_system,
    }
}

pub(super) fn derive_join_type(facts: &DsregcmdFacts) -> DsregcmdJoinType {
    match (
        facts.join_state.azure_ad_joined,
        facts.join_state.domain_joined,
    ) {
        (Some(true), Some(true)) => DsregcmdJoinType::HybridEntraIdJoined,
        (Some(true), Some(false)) => DsregcmdJoinType::EntraIdJoined,
        (Some(false), _) => DsregcmdJoinType::NotJoined,
        _ => DsregcmdJoinType::Unknown,
    }
}

fn join_type_label(join_type: DsregcmdJoinType) -> &'static str {
    match join_type {
        DsregcmdJoinType::HybridEntraIdJoined => "Hybrid Entra ID Joined",
        DsregcmdJoinType::EntraIdJoined => "Entra ID Joined",
        DsregcmdJoinType::NotJoined => "Not Joined",
        DsregcmdJoinType::Unknown => "Unknown",
    }
}

fn derive_dominant_phase(facts: &DsregcmdFacts) -> DsregcmdDiagnosticPhase {
    if let Some(phase) = facts
        .registration
        .error_phase
        .as_deref()
        .and_then(parse_phase)
    {
        return phase;
    }

    if facts.diagnostics.attempt_status.is_some()
        || facts.diagnostics.previous_prt_attempt.is_some()
        || facts.sso_state.acquire_prt_diagnostics.is_some()
    {
        return DsregcmdDiagnosticPhase::PostJoin;
    }

    if is_failure(&facts.pre_join_tests.ad_connectivity_test) {
        return DsregcmdDiagnosticPhase::Precheck;
    }

    if is_failure(&facts.pre_join_tests.ad_configuration_test)
        || is_failure(&facts.pre_join_tests.drs_discovery_test)
        || is_failure(&facts.pre_join_tests.drs_connectivity_test)
    {
        return DsregcmdDiagnosticPhase::Discover;
    }

    if is_failure(&facts.pre_join_tests.token_acquisition_test)
        || has_any_code(
            facts,
            &[
                "0xcaa90017",
                "0xcaa9002c",
                "0xcaa90023",
                "0xcaa82ee2",
                "0xcaa82efe",
                "0xcaa82f8f",
                "0xcaa82efd",
                "0xcaa20003",
                "0xcaa90014",
                "0xcaa90006",
                "0xcaa1002d",
            ],
        )
    {
        return DsregcmdDiagnosticPhase::Auth;
    }

    if facts.registration.client_error_code.is_some()
        || facts.registration.server_error_code.is_some()
        || facts.registration.server_message.is_some()
    {
        return DsregcmdDiagnosticPhase::Join;
    }

    if facts.sso_state.azure_ad_prt == Some(false) || facts.sso_state.azure_ad_prt_update_time.is_some() {
        return DsregcmdDiagnosticPhase::PostJoin;
    }

    DsregcmdDiagnosticPhase::Unknown
}

fn phase_summary(phase: DsregcmdDiagnosticPhase) -> &'static str {
    match phase {
        DsregcmdDiagnosticPhase::Precheck => {
            "Current evidence points to a precheck failure before discovery could complete."
        }
        DsregcmdDiagnosticPhase::Discover => {
            "Current evidence points to a discover-phase failure while locating or reaching registration services."
        }
        DsregcmdDiagnosticPhase::Auth => {
            "Current evidence points to an authentication-phase failure during federation or token acquisition."
        }
        DsregcmdDiagnosticPhase::Join => {
            "Current evidence points to a join-phase failure while registering the device with Entra."
        }
        DsregcmdDiagnosticPhase::PostJoin => {
            "Current evidence points to a post-join token, session, or refresh problem."
        }
        DsregcmdDiagnosticPhase::Unknown => {
            "Current evidence does not isolate a single failure phase from this capture."
        }
    }
}

fn derive_capture_confidence(
    facts: &DsregcmdFacts,
    reference_time: Option<DateTime<Utc>>,
    remote_session_system: Option<bool>,
) -> (DsregcmdCaptureConfidence, String) {
    if remote_session_system == Some(true) {
        return (
            DsregcmdCaptureConfidence::Low,
            "Capture was taken as SYSTEM in a remote session, so user-scoped token and session evidence may be distorted.".to_string(),
        );
    }

    if let Some(client_time) = facts
        .diagnostics
        .client_time
        .as_deref()
        .and_then(parse_dsregcmd_timestamp)
    {
        let age_minutes = Utc::now().signed_duration_since(client_time).num_minutes().abs();
        if age_minutes <= 15
            && facts.user_state.session_is_not_remote == Some(true)
            && !matches!(facts.diagnostics.user_context.as_deref(), Some(context) if context.eq_ignore_ascii_case("SYSTEM"))
        {
            return (
                DsregcmdCaptureConfidence::High,
                "Capture looks recent and interactive, so user-scoped evidence should be trustworthy.".to_string(),
            );
        }

        if age_minutes <= 24 * 60 {
            return (
                DsregcmdCaptureConfidence::Medium,
                "Capture looks reasonably recent, but it may not exactly match the current device state.".to_string(),
            );
        }

        return (
            DsregcmdCaptureConfidence::Low,
            "Capture looks old relative to the device clock, so conclusions may no longer match the current state.".to_string(),
        );
    }

    if reference_time.is_some() {
        return (
            DsregcmdCaptureConfidence::Medium,
            "Capture included enough timing context to analyze, but it did not provide a clearly recent interactive client timestamp.".to_string(),
        );
    }

    (
        DsregcmdCaptureConfidence::Medium,
        "Capture confidence is moderate because the source lacked enough timing and session context to judge freshness precisely.".to_string(),
    )
}

fn parse_phase(value: &str) -> Option<DsregcmdDiagnosticPhase> {
    match value.trim().to_ascii_lowercase().as_str() {
        "pre-check" | "precheck" => Some(DsregcmdDiagnosticPhase::Precheck),
        "discover" => Some(DsregcmdDiagnosticPhase::Discover),
        "auth" | "authentication" => Some(DsregcmdDiagnosticPhase::Auth),
        "join" => Some(DsregcmdDiagnosticPhase::Join),
        "post_join" | "post-join" | "postjoin" => Some(DsregcmdDiagnosticPhase::PostJoin),
        _ => None,
    }
}

pub(super) fn parse_dsregcmd_timestamp(value: &str) -> Option<DateTime<Utc>> {
    let trimmed = value.trim();
    if let Ok(parsed) = DateTime::parse_from_rfc3339(trimmed) {
        return Some(parsed.with_timezone(&Utc));
    }

    for format in [
        "%Y-%m-%d %H:%M:%S%.f UTC",
        "%Y-%m-%d %H:%M:%S UTC",
        "%m/%d/%Y %H:%M:%S%.f UTC",
        "%m/%d/%Y %H:%M:%S UTC",
    ] {
        if let Ok(parsed) = NaiveDateTime::parse_from_str(trimmed, format) {
            return Some(DateTime::<Utc>::from_naive_utc_and_offset(parsed, Utc));
        }
    }

    for format in [
        "%Y-%m-%d %H:%M:%S%.f",
        "%Y-%m-%d %H:%M:%S",
        "%m/%d/%Y %H:%M:%S%.f",
        "%m/%d/%Y %H:%M:%S",
    ] {
        if let Ok(parsed) = NaiveDateTime::parse_from_str(trimmed, format) {
            return match Local.from_local_datetime(&parsed) {
                LocalResult::Single(local_time) => Some(local_time.with_timezone(&Utc)),
                LocalResult::Ambiguous(local_time, _) => Some(local_time.with_timezone(&Utc)),
                LocalResult::None => None,
            };
        }
    }

    None
}

fn parse_certificate_validity(value: &str) -> (Option<DateTime<Utc>>, Option<DateTime<Utc>>) {
    let timestamps: Vec<DateTime<Utc>> = certificate_timestamp_re()
        .find_iter(value)
        .filter_map(|capture| parse_dsregcmd_timestamp(capture.as_str()))
        .collect();

    match timestamps.as_slice() {
        [valid_from, valid_to, ..] => (Some(*valid_from), Some(*valid_to)),
        [valid_to] => (None, Some(*valid_to)),
        _ => (None, None),
    }
}

fn detect_network_error(raw_input: &str) -> Option<String> {
    let uppercase = raw_input.to_ascii_uppercase();
    NETWORK_ERROR_MARKERS
        .iter()
        .find(|marker| uppercase.contains(**marker))
        .map(|marker| (*marker).to_string())
}

// ── Utility helpers shared across rule modules ──────────────────────────────

pub(super) fn aggregated_error_text(facts: &DsregcmdFacts) -> String {
    [
        facts.registration.client_error_code.as_deref(),
        facts.registration.server_error_code.as_deref(),
        facts.registration.server_message.as_deref(),
        facts.registration.server_error_description.as_deref(),
        facts.diagnostics.attempt_status.as_deref(),
        facts.diagnostics.http_error.as_deref(),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>()
    .join(" ")
    .to_ascii_lowercase()
}

pub(super) fn has_code(facts: &DsregcmdFacts, code: &str) -> bool {
    contains_text(&facts.registration.client_error_code, code)
        || contains_text(&facts.registration.server_error_code, code)
        || contains_text(&facts.registration.server_message, code)
        || contains_text(&facts.registration.server_error_description, code)
        || contains_text(&facts.diagnostics.attempt_status, code)
        || contains_text(&facts.diagnostics.http_error, code)
        || contains_text(&facts.pre_join_tests.token_acquisition_test, code)
        || contains_text(&facts.pre_join_tests.drs_discovery_test, code)
        || contains_text(&facts.pre_join_tests.ad_configuration_test, code)
}

pub(super) fn has_any_code(facts: &DsregcmdFacts, codes: &[&str]) -> bool {
    codes.iter().any(|code| has_code(facts, code))
}

pub(super) fn is_failure(field: &Option<String>) -> bool {
    field
        .as_deref()
        .map(|value| value.to_ascii_uppercase().contains("FAIL"))
        .unwrap_or(false)
}

pub(super) fn is_failure_text(field: &Option<String>) -> bool {
    field
        .as_deref()
        .map(|value| {
            let normalized = value.to_ascii_uppercase();
            normalized.contains("FAIL") || normalized.contains("ERROR")
        })
        .unwrap_or(false)
}

pub(super) fn render_phase_code_evidence(facts: &DsregcmdFacts, code: &str) -> String {
    let sources = [
        ("Client ErrorCode", facts.registration.client_error_code.as_deref()),
        ("Attempt Status", facts.diagnostics.attempt_status.as_deref()),
        ("HTTP Error", facts.diagnostics.http_error.as_deref()),
        (
            "Token Acquisition Test",
            facts.pre_join_tests.token_acquisition_test.as_deref(),
        ),
    ];

    for (label, value) in sources {
        if let Some(value) = value {
            if value.to_ascii_lowercase().contains(&code.to_ascii_lowercase()) {
                return format!("{label}: {value}");
            }
        }
    }

    format!("Code: {code}")
}

pub(super) fn push_test_failure(
    diagnostics: &mut Vec<DsregcmdDiagnosticInsight>,
    id: &str,
    category: &str,
    title: &str,
    field: &Option<String>,
    next_checks: Vec<String>,
    suggested_fixes: Vec<String>,
) {
    let Some(value) = field.as_deref() else {
        return;
    };

    if !value.to_ascii_uppercase().contains("FAIL") {
        return;
    }

    let mut evidence = vec![format!("Result: {value}")];
    if let Some(detail) = extract_bracket_detail(value) {
        evidence.push(format!("Detail: {detail}"));
    }

    diagnostics.push(issue(
        id,
        IntuneDiagnosticSeverity::Error,
        category,
        title,
        &format!("{title}."),
        evidence,
        next_checks,
        suggested_fixes,
    ));
}

fn extract_bracket_detail(value: &str) -> Option<String> {
    let start = value.find('[')?;
    let end = value[start + 1..].find(']')?;
    let detail = &value[start + 1..start + 1 + end];
    (!detail.trim().is_empty()).then(|| detail.trim().to_string())
}

#[expect(
    clippy::too_many_arguments,
    reason = "diagnostic construction keeps explicit backend contract fields together"
)]
pub(super) fn issue(
    id: &str,
    severity: IntuneDiagnosticSeverity,
    category: &str,
    title: &str,
    summary: &str,
    evidence: Vec<String>,
    next_checks: Vec<String>,
    suggested_fixes: Vec<String>,
) -> DsregcmdDiagnosticInsight {
    DsregcmdDiagnosticInsight {
        id: id.to_string(),
        severity,
        category: category.to_string(),
        title: title.to_string(),
        summary: summary.to_string(),
        evidence,
        next_checks,
        suggested_fixes,
    }
}

pub(super) fn render_optional(label: &str, value: &Option<String>) -> String {
    match value {
        Some(value) => format!("{label}: {value}"),
        None => format!("{label}: (missing)"),
    }
}

pub(super) fn render_bool(label: &str, value: Option<bool>) -> String {
    match value {
        Some(true) => format!("{label}: YES"),
        Some(false) => format!("{label}: NO"),
        None => format!("{label}: (unknown)"),
    }
}

pub(super) fn contains_text(field: &Option<String>, needle: &str) -> bool {
    field
        .as_deref()
        .map(|value| {
            value
                .to_ascii_lowercase()
                .contains(&needle.to_ascii_lowercase())
        })
        .unwrap_or(false)
}

pub(super) fn equals_text(field: &Option<String>, expected: &str) -> bool {
    field
        .as_deref()
        .map(|value| value.eq_ignore_ascii_case(expected))
        .unwrap_or(false)
}

pub(super) fn is_missing(field: &Option<String>) -> bool {
    field.is_none()
}
