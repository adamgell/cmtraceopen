use std::sync::OnceLock;

use chrono::{NaiveDateTime, TimeZone, Utc};
use regex::Regex;

use super::models::{
    LogLevel, LogSession, LogSource, SecureBootStage, TimelineEntry, TimelineEventType,
};

// ---------------------------------------------------------------------------
// Compiled regexes (OnceLock pattern matching codebase convention)
// ---------------------------------------------------------------------------

fn log_line_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(
            r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \[(DETECT|REMEDIATE|SYSTEM)\] \[(INFO|WARNING|ERROR|SUCCESS)\] (.+)$",
        )
        .expect("valid log line regex")
    })
}

fn stage_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"(?:NON-COMPLIANT|COMPLIANT)\s*-\s*Stage\s+(\d)")
            .expect("valid stage regex")
    })
}

fn error_code_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"0x[0-9A-Fa-f]{4,8}").expect("valid error code regex")
    })
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn parse_source(s: &str) -> LogSource {
    match s {
        "DETECT" => LogSource::Detect,
        "REMEDIATE" => LogSource::Remediate,
        _ => LogSource::System,
    }
}

fn parse_level(s: &str) -> LogLevel {
    match s {
        "WARNING" => LogLevel::Warning,
        "ERROR" => LogLevel::Error,
        "SUCCESS" => LogLevel::Success,
        _ => LogLevel::Info,
    }
}

fn classify_event(message: &str) -> TimelineEventType {
    if message.starts_with("========== DETECTION STARTED")
        || message.starts_with("========== REMEDIATION STARTED")
    {
        return TimelineEventType::SessionStart;
    }
    if message.starts_with("========== DETECTION COMPLETED")
        || message.starts_with("========== REMEDIATION COMPLETED")
    {
        return TimelineEventType::SessionEnd;
    }
    if message.starts_with("Detection Result:") {
        return TimelineEventType::StageTransition;
    }
    if message.starts_with("Remediation Result:") {
        return TimelineEventType::RemediationResult;
    }
    if message.contains("FALLBACK") || message.contains("Fallback") {
        return TimelineEventType::Fallback;
    }
    if message.starts_with("---------- DIAGNOSTIC DATA") || message.starts_with("--- ") {
        return TimelineEventType::DiagnosticData;
    }
    if message.contains("ERROR") || message.contains("FAILED") {
        return TimelineEventType::Error;
    }
    TimelineEventType::Info
}

fn extract_stage(message: &str) -> Option<SecureBootStage> {
    let cap = stage_re().captures(message)?;
    match cap[1].parse::<u8>().ok()? {
        0 => Some(SecureBootStage::Stage0),
        1 => Some(SecureBootStage::Stage1),
        2 => Some(SecureBootStage::Stage2),
        3 => Some(SecureBootStage::Stage3),
        4 => Some(SecureBootStage::Stage4),
        5 => Some(SecureBootStage::Stage5),
        _ => None,
    }
}

fn extract_error_code(message: &str) -> Option<String> {
    error_code_re()
        .find(message)
        .map(|m| m.as_str().to_owned())
}

/// Parse a single log line into a `TimelineEntry`, returning `None` if the
/// line does not match the expected format.
fn parse_line(line: &str) -> Option<TimelineEntry> {
    let caps = log_line_re().captures(line.trim())?;

    let timestamp_str = &caps[1];
    let source_str = &caps[2];
    let level_str = &caps[3];
    let message = caps[4].to_owned();

    let naive = NaiveDateTime::parse_from_str(timestamp_str, "%Y-%m-%d %H:%M:%S").ok()?;
    let timestamp = Utc.from_utc_datetime(&naive);

    let source = parse_source(source_str);
    let level = parse_level(level_str);
    let event_type = classify_event(&message);
    let stage = extract_stage(&message);
    let error_code = extract_error_code(&message);

    Some(TimelineEntry {
        timestamp,
        source,
        level,
        event_type,
        message,
        stage,
        error_code,
    })
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Parse the full text content of a `SecureBootCertificateUpdate.log` file.
///
/// Returns `(sessions, all_entries)` where `all_entries` is the flat
/// chronological timeline and `sessions` groups entries by
/// STARTED/COMPLETED boundaries.
pub fn parse_log(content: &str) -> (Vec<LogSession>, Vec<TimelineEntry>) {
    let all_entries: Vec<TimelineEntry> = content
        .lines()
        .filter_map(parse_line)
        .collect();

    let sessions = build_sessions(&all_entries);

    (sessions, all_entries)
}

/// Group a flat list of entries into `LogSession`s.
fn build_sessions(entries: &[TimelineEntry]) -> Vec<LogSession> {
    let mut sessions: Vec<LogSession> = Vec::new();
    let mut current: Option<LogSession> = None;

    for entry in entries {
        match entry.event_type {
            TimelineEventType::SessionStart => {
                // Close any unterminated session first.
                if let Some(open) = current.take() {
                    sessions.push(open);
                }
                current = Some(LogSession {
                    source: entry.source,
                    started_at: entry.timestamp,
                    ended_at: None,
                    result_stage: None,
                    result_outcome: None,
                    entries: vec![entry.clone()],
                });
            }

            TimelineEventType::SessionEnd => {
                if let Some(ref mut sess) = current {
                    sess.ended_at = Some(entry.timestamp);
                    sess.entries.push(entry.clone());
                    sessions.push(current.take().unwrap());
                }
                // If there's no open session, discard the orphaned end marker.
            }

            TimelineEventType::StageTransition | TimelineEventType::RemediationResult => {
                let stage = entry.stage;
                let outcome = Some(entry.message.clone());

                if let Some(ref mut sess) = current {
                    if stage.is_some() {
                        sess.result_stage = stage;
                    }
                    sess.result_outcome = outcome;
                    sess.entries.push(entry.clone());
                }
            }

            _ => {
                if let Some(ref mut sess) = current {
                    sess.entries.push(entry.clone());
                }
            }
        }
    }

    // Any session that never received a COMPLETED marker is pushed as-is.
    if let Some(open) = current {
        sessions.push(open);
    }

    sessions
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_LOG: &str = "\
2026-03-01 08:14:22 [DETECT] [INFO] ========== DETECTION STARTED ==========
2026-03-01 08:14:22 [DETECT] [INFO] Script Version: 4.0
2026-03-01 08:14:22 [DETECT] [SUCCESS] Secure Boot is ENABLED
2026-03-01 08:14:22 [DETECT] [SUCCESS] MicrosoftUpdateManagedOptIn is SET to 0x5944 (22852)
2026-03-01 08:14:23 [DETECT] [WARNING] Detection Result: NON-COMPLIANT - Stage 2 (exit 1)
2026-03-01 08:14:23 [DETECT] [INFO] ========== DETECTION COMPLETED ==========
2026-03-15 14:22:01 [DETECT] [INFO] ========== DETECTION STARTED ==========
2026-03-15 14:22:01 [DETECT] [ERROR] 0x80070002 - Missing SecureBootUpdates payload files
2026-03-15 14:22:01 [DETECT] [WARNING] Detection Result: NON-COMPLIANT - Stage 3 (exit 1)
2026-03-15 14:22:01 [DETECT] [INFO] ========== DETECTION COMPLETED ==========
2026-04-01 08:30:12 [DETECT] [INFO] ========== DETECTION STARTED ==========
2026-04-01 08:30:12 [DETECT] [SUCCESS] Detection Result: COMPLIANT - Stage 5 (exit 0)
2026-04-01 08:30:12 [DETECT] [INFO] ========== DETECTION COMPLETED ==========";

    #[test]
    fn parses_sessions() {
        let (sessions, _) = parse_log(SAMPLE_LOG);

        assert_eq!(sessions.len(), 3, "expected 3 sessions");

        // Session 1: NON-COMPLIANT Stage 2
        assert_eq!(sessions[0].result_stage, Some(SecureBootStage::Stage2));

        // Session 2: NON-COMPLIANT Stage 3
        assert_eq!(sessions[1].result_stage, Some(SecureBootStage::Stage3));

        // Session 3: COMPLIANT Stage 5
        assert_eq!(sessions[2].result_stage, Some(SecureBootStage::Stage5));
    }

    #[test]
    fn extracts_error_codes() {
        let (_, entries) = parse_log(SAMPLE_LOG);

        let codes: Vec<&str> = entries
            .iter()
            .filter_map(|e| e.error_code.as_deref())
            .collect();

        assert!(
            codes.contains(&"0x5944"),
            "expected 0x5944 in extracted codes, got: {codes:?}"
        );
        assert!(
            codes.contains(&"0x80070002"),
            "expected 0x80070002 in extracted codes, got: {codes:?}"
        );
    }

    #[test]
    fn classifies_session_boundaries() {
        let (sessions, _) = parse_log(SAMPLE_LOG);

        let first_session = &sessions[0];

        let first_entry = first_session.entries.first().expect("session has entries");
        assert_eq!(
            first_entry.event_type,
            TimelineEventType::SessionStart,
            "first entry of first session should be SessionStart"
        );

        let last_entry = first_session.entries.last().expect("session has entries");
        assert_eq!(
            last_entry.event_type,
            TimelineEventType::SessionEnd,
            "last entry of first session should be SessionEnd"
        );
    }

    #[test]
    fn handles_empty_input() {
        let (sessions, entries) = parse_log("");
        assert!(sessions.is_empty(), "expected no sessions for empty input");
        assert!(entries.is_empty(), "expected no entries for empty input");
    }

    #[test]
    fn handles_malformed_lines() {
        let mixed = "\
this line is not valid at all
2026-03-01 08:14:22 [DETECT] [INFO] ========== DETECTION STARTED ==========
ANOTHER BAD LINE
2026-03-01 08:14:22 [DETECT] [INFO] ========== DETECTION COMPLETED ==========
yet another bad one";

        let (sessions, entries) = parse_log(mixed);

        // Only the two valid lines should have been parsed.
        assert_eq!(entries.len(), 2, "only 2 valid lines should be parsed");
        assert_eq!(sessions.len(), 1, "one complete session from valid lines");
    }
}
