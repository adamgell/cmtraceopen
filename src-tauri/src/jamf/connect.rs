use std::fs;
use std::io::BufReader;
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
    let mut reader = BufReader::new(file);
    crate::jamf::text::for_each_line(&mut reader, |_offset, line| {
        if let Some(ev) = parse_line(line) {
            events.push(ev);
        }
    })?;
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

/// Accepts `2026-04-29T09:12:03+0000`, `...+00:00` and `...Z`.
///
/// chrono's `%z` does not accept the RFC 3339 `Z` designator, so a Zulu
/// timestamp silently failed to parse and the whole line was dropped — the
/// previous code documented `Z` as supported but discarded it. Normalize `Z` to
/// an explicit numeric offset before parsing.
fn parse_timestamp(raw: &str) -> Option<DateTime<Utc>> {
    let normalized = match raw.strip_suffix(['Z', 'z']) {
        Some(head) => format!("{head}+0000"),
        None => raw.to_string(),
    };
    // `%#z` accepts both `+0000` and `+00:00`.
    DateTime::parse_from_str(&normalized, "%Y-%m-%dT%H:%M:%S%#z")
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}
