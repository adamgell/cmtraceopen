use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;

use chrono::{NaiveDateTime, TimeZone, Utc};
use regex::Regex;

use crate::error::AppError;
use crate::jamf::models::JamfSelfServiceEvent;

fn line_regex() -> &'static Regex {
    use std::sync::OnceLock;
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+\[\w+\]\s+(?P<action>Browse|Install|Cancel):\s+(?P<rest>.*)$"#,
        )
        .expect("static regex must compile")
    })
}

fn item_regex() -> &'static Regex {
    use std::sync::OnceLock;
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"item\s+"(?P<item>[^"]+)""#).expect("static regex must compile")
    })
}

fn result_regex() -> &'static Regex {
    use std::sync::OnceLock;
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"result=(?P<result>\w+)"#).expect("static regex must compile")
    })
}

pub fn parse_self_service_log_impl(path: &Path) -> Result<Vec<JamfSelfServiceEvent>, AppError> {
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

fn parse_line(line: &str) -> Option<JamfSelfServiceEvent> {
    let caps = line_regex().captures(line)?;
    let ts_raw = caps.name("ts")?.as_str();
    let action = caps.name("action")?.as_str().to_string();
    let rest = caps.name("rest")?.as_str();

    let ts = NaiveDateTime::parse_from_str(ts_raw, "%Y-%m-%d %H:%M:%S").ok()?;
    let timestamp = Utc.from_utc_datetime(&ts);

    let item_name = item_regex()
        .captures(rest)
        .and_then(|c| c.name("item"))
        .map(|m| m.as_str().to_string());
    let result = result_regex()
        .captures(rest)
        .and_then(|c| c.name("result"))
        .map(|m| m.as_str().to_string());

    Some(JamfSelfServiceEvent {
        timestamp,
        action,
        item_name,
        result,
        raw_line: line.to_string(),
    })
}
