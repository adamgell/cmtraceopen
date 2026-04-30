use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;

use chrono::{DateTime, Utc};
use regex::Regex;

use crate::error::AppError;
use crate::jamf::models::JamfConnectEvent;

fn line_regex() -> &'static Regex {
    use std::sync::OnceLock;
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+\-Z][\d:]*)\s+\[\w+\]\s+\[(?P<type>\w+)\]\s+(?P<msg>.*)$",
        )
        .expect("static regex must compile")
    })
}

fn user_regex() -> &'static Regex {
    use std::sync::OnceLock;
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)user\s+(?P<user>[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+)")
            .expect("static regex must compile")
    })
}

fn idp_regex() -> &'static Regex {
    use std::sync::OnceLock;
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"provider=(?P<idp>\w+)").expect("static regex must compile")
    })
}

pub fn parse_connect_log_impl(path: &Path) -> Result<Vec<JamfConnectEvent>, AppError> {
    let file = match fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(AppError::Io(e)),
    };
    let mut events = Vec::new();
    for line in BufReader::new(file).lines().map_while(Result::ok) {
        if let Some(ev) = parse_line(&line) {
            events.push(ev);
        }
    }
    Ok(events)
}

fn parse_line(line: &str) -> Option<JamfConnectEvent> {
    let caps = line_regex().captures(line)?;
    let ts_raw = caps.name("ts")?.as_str();
    let event_type = caps.name("type")?.as_str().to_string();
    let msg = caps.name("msg")?.as_str().to_string();

    let timestamp = parse_timestamp(ts_raw)?;
    let user = user_regex()
        .captures(&msg)
        .and_then(|c| c.name("user"))
        .map(|m| m.as_str().to_string());
    let idp = idp_regex()
        .captures(&msg)
        .and_then(|c| c.name("idp"))
        .map(|m| m.as_str().to_string());

    Some(JamfConnectEvent {
        timestamp,
        event_type,
        idp,
        user,
        message: msg,
        raw_line: line.to_string(),
    })
}

fn parse_timestamp(raw: &str) -> Option<DateTime<Utc>> {
    // Accept "2026-04-29T09:12:03+0000" and "2026-04-29T09:12:03Z".
    // If no timezone marker is present, default to UTC.
    let has_tz =
        raw.ends_with('Z') || raw.contains('+') || raw.matches('-').count() >= 3;
    let normalized = if has_tz {
        raw.to_string()
    } else {
        format!("{raw}+0000")
    };
    DateTime::parse_from_str(&normalized, "%Y-%m-%dT%H:%M:%S%z")
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}
