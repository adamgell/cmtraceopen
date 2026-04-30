use std::fs;
use std::io::{BufRead, BufReader, Seek};
use std::path::Path;

use chrono::{DateTime, Datelike, NaiveDate, NaiveDateTime, NaiveTime, TimeZone, Timelike, Utc};
use regex::Regex;

use crate::error::AppError;
use crate::jamf::models::{
    JamfPolicyEvent, JamfPolicyLogResult, JamfPolicyResult, JamfPolicyTrigger,
};

// Line shape (verified from real JAMF Pro 11 host):
//   Wed Apr 29 13:23:04 LT-APLFVFHWEYHQ6L7 jamf[92532]: Executing Policy Google Chrome Installer
//
// Captures: month, day, time(HH:MM:SS), pid, message.
// The year is not present; we infer it from the file's modified time and
// fix Dec→Jan rollover after parsing.
fn line_regex() -> &'static Regex {
    use std::sync::OnceLock;
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"^(?P<dow>\w{3})\s+(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+\S+\s+jamf\[(?P<pid>\d+)\]:\s+(?P<msg>.*)$",
        )
        .expect("static regex must compile")
    })
}

pub fn parse_policy_log_impl(path: &Path) -> Result<JamfPolicyLogResult, AppError> {
    let file = fs::File::open(path).map_err(AppError::Io)?;
    let reference_year = reference_year_for(path);

    let mut reader = BufReader::new(file);
    let mut events: Vec<JamfPolicyEvent> = Vec::new();
    let mut total_lines = 0usize;
    let mut unparsed = 0usize;

    let mut line = String::new();
    loop {
        let offset = reader.stream_position().map_err(AppError::Io)?;
        line.clear();
        let n = reader.read_line(&mut line).map_err(AppError::Io)?;
        if n == 0 {
            break;
        }
        total_lines += 1;
        let trimmed = line.trim_end_matches(['\r', '\n']);

        match parse_line(trimmed, offset, reference_year) {
            Some(ev) => events.push(ev),
            None => unparsed += 1,
        }
    }

    fix_year_wrap(&mut events);

    Ok(JamfPolicyLogResult {
        events,
        total_lines,
        unparsed_lines: unparsed,
        source_path: path.to_string_lossy().into_owned(),
    })
}

fn reference_year_for(path: &Path) -> i32 {
    fs::metadata(path)
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .and_then(|d| Utc.timestamp_opt(d.as_secs() as i64, 0).single())
        .map(|dt| dt.year())
        .unwrap_or_else(|| Utc::now().year())
}

fn parse_line(line: &str, offset: u64, year: i32) -> Option<JamfPolicyEvent> {
    let caps = line_regex().captures(line)?;
    let mon = month_to_num(caps.name("mon")?.as_str())?;
    let day: u32 = caps.name("day")?.as_str().parse().ok()?;
    let time = NaiveTime::parse_from_str(caps.name("time")?.as_str(), "%H:%M:%S").ok()?;
    let date = NaiveDate::from_ymd_opt(year, mon, day)?;
    let dt = NaiveDateTime::new(date, time);
    let ts = Utc.from_utc_datetime(&dt);

    let msg = caps.name("msg")?.as_str();
    let (trigger, policy_id, policy_name, result) = classify(msg);

    Some(JamfPolicyEvent {
        timestamp: ts,
        trigger,
        policy_id,
        policy_name,
        result,
        duration_ms: None,
        raw_line_offset: offset,
        raw_line: line.to_string(),
    })
}

fn month_to_num(s: &str) -> Option<u32> {
    Some(match s {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    })
}

fn classify(
    msg: &str,
) -> (
    JamfPolicyTrigger,
    Option<String>,
    Option<String>,
    JamfPolicyResult,
) {
    if let Some(t) = check_in_trigger(msg) {
        return (t, None, None, JamfPolicyResult::Unknown);
    }
    if let Some(rest) = msg.strip_prefix("Checking for policy ID ") {
        // rest looks like: "332..." (literal "332" followed by trailing ellipsis)
        let id = rest
            .trim_end_matches('.')
            .trim_end_matches("...")
            .split_whitespace()
            .next()
            .unwrap_or("")
            .trim_end_matches('.')
            .to_string();
        if !id.is_empty() {
            return (
                JamfPolicyTrigger::PolicyId(id.clone()),
                Some(id),
                None,
                JamfPolicyResult::Unknown,
            );
        }
    }
    if let Some(name) = msg.strip_prefix("Executing Policy ") {
        return (
            JamfPolicyTrigger::Other("execute".to_string()),
            None,
            Some(name.to_string()),
            JamfPolicyResult::InProgress,
        );
    }
    if let Some(rest) = msg.strip_prefix("Error running ") {
        return (
            JamfPolicyTrigger::Other("error".to_string()),
            None,
            None,
            JamfPolicyResult::Failure(format!("Error running {rest}")),
        );
    }
    if msg.starts_with("No patch policies were found") {
        return (
            JamfPolicyTrigger::Other("patch-check".to_string()),
            None,
            None,
            JamfPolicyResult::Success,
        );
    }
    if msg.starts_with("Checking for patches") {
        return (
            JamfPolicyTrigger::Other("patch-check".to_string()),
            None,
            None,
            JamfPolicyResult::InProgress,
        );
    }

    (
        JamfPolicyTrigger::Other("info".to_string()),
        None,
        None,
        JamfPolicyResult::Unknown,
    )
}

fn check_in_trigger(msg: &str) -> Option<JamfPolicyTrigger> {
    let prefix = "Checking for policies triggered by \"";
    let rest = msg.strip_prefix(prefix)?;
    let close = rest.find('"')?;
    let trigger_label = &rest[..close];
    Some(match trigger_label {
        "recurring check-in" => JamfPolicyTrigger::RecurringCheckIn,
        "startup" => JamfPolicyTrigger::Startup,
        "login" => JamfPolicyTrigger::Login,
        "logout" => JamfPolicyTrigger::Logout,
        "manual" | "Custom" => JamfPolicyTrigger::Manual,
        other => JamfPolicyTrigger::Event(other.to_string()),
    })
}

fn fix_year_wrap(events: &mut [JamfPolicyEvent]) {
    if events.len() < 2 {
        return;
    }
    for i in (0..events.len() - 1).rev() {
        if events[i].timestamp > events[i + 1].timestamp {
            let prior = events[i].timestamp;
            let new_ts: DateTime<Utc> = Utc
                .with_ymd_and_hms(
                    prior.year() - 1,
                    prior.month(),
                    prior.day(),
                    prior.hour(),
                    prior.minute(),
                    prior.second(),
                )
                .single()
                .unwrap_or(prior);
            events[i].timestamp = new_ts;
        }
    }
}
