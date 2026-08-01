use std::fs;
use std::io::BufReader;
use std::path::Path;

use chrono::NaiveDateTime;
use regex::Regex;

use crate::error::AppError;
use crate::jamf::models::JamfSelfServiceEvent;
use crate::jamf::time::local_naive_to_utc;

// Line shape (verified from a real Self Service 11 host):
//   [2026-04-29 14:59:40] Application successfully launched
//   [2026-04-29 15:00:02] Binary Request: triggerPolicy
//   [2026-04-29 14:59:42] Request: getPolicies
//   [2026-04-29 15:00:01] WARNING: A customized icon is larger than recommended. ...
//
// An earlier version of this parser expected `<ts> [LEVEL] Browse|Install|Cancel:`
// lines. That format does not exist: run against a real selfservice.log it
// produced zero events. The debug variant (selfservice_debug.log) additionally
// emits continuation lines with no timestamp prefix (request/response bodies);
// those are dropped here — the events they annotate are what the tab reports.
fn line_regex() -> &'static Regex {
    use std::sync::OnceLock;
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^\[(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]\s+(?P<msg>.*)$")
            .expect("static regex must compile")
    })
}

pub fn parse_self_service_log_impl(path: &Path) -> Result<Vec<JamfSelfServiceEvent>, AppError> {
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

fn parse_line(line: &str) -> Option<JamfSelfServiceEvent> {
    let caps = line_regex().captures(line)?;
    let ts_raw = caps.name("ts")?.as_str();
    let msg = caps.name("msg")?.as_str();

    let ts = NaiveDateTime::parse_from_str(ts_raw, "%Y-%m-%d %H:%M:%S").ok()?;
    let timestamp = local_naive_to_utc(ts);

    let (action, item_name, result) = classify(msg);

    Some(JamfSelfServiceEvent {
        timestamp,
        action,
        item_name,
        result,
        raw_line: line.to_string(),
    })
}

/// Maps a log message to `(action, item_name, result)`.
///
/// `Binary Request` lines are the user-side operations (triggerPolicy is a
/// Self Service-initiated install, doRecon an inventory submission), so the
/// operation name becomes the action. Plain `Request` lines are API chatter
/// between the app and the JSS; they are kept — this is a diagnostics view and
/// their absence is itself a signal — but grouped under one `request` action
/// with the endpoint as the item.
fn classify(msg: &str) -> (String, Option<String>, Option<String>) {
    if let Some(name) = msg.strip_prefix("Binary Request: ") {
        return (name.trim().to_string(), None, None);
    }
    if let Some(name) = msg.strip_prefix("Request: ") {
        return ("request".to_string(), Some(name.trim().to_string()), None);
    }
    if let Some(rest) = msg.strip_prefix("WARNING: ") {
        return ("warning".to_string(), Some(rest.trim().to_string()), None);
    }
    if let Some(rest) = msg.strip_prefix("Server Connectivity State change - ") {
        // rest looks like: `state: active, user: nil`
        let state = rest
            .strip_prefix("state: ")
            .and_then(|s| s.split(',').next())
            .map(|s| s.trim().to_string());
        return ("connectivity".to_string(), None, state);
    }
    if msg == "Application successfully launched" {
        return ("launch".to_string(), None, None);
    }
    ("info".to_string(), Some(msg.to_string()), None)
}
