use crate::models::log_entry::LogEntry;
use chrono::{DateTime, NaiveDate, NaiveDateTime};
use serde::{Deserialize, Serialize};

/// The types of filter clause operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FilterOp {
    Equals,
    NotEquals,
    Contains,
    NotContains,
    /// For timestamp: entries before this value
    Before,
    /// For timestamp: entries after this value
    After,
}

/// Which field to apply the filter on.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FilterField {
    Message,
    Component,
    Thread,
    Timestamp,
    Severity,
}

/// A single filter clause.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FilterClause {
    pub field: FilterField,
    pub op: FilterOp,
    pub value: String,
}

/// Apply filter clauses to a list of entries.
/// Returns the IDs of entries that match ALL clauses (AND logic).
#[tauri::command]
pub fn apply_filter(
    entries: Vec<LogEntry>,
    clauses: Vec<FilterClause>,
) -> Result<Vec<u64>, crate::error::AppError> {
    if clauses.is_empty() {
        // No filter — return all IDs
        return Ok(entries.iter().map(|e| e.id).collect());
    }

    let mut matching_ids = Vec::new();

    for entry in &entries {
        let mut matches_all = true;

        for clause in &clauses {
            if !matches_clause(entry, clause)? {
                matches_all = false;
                break;
            }
        }

        if matches_all {
            matching_ids.push(entry.id);
        }
    }

    Ok(matching_ids)
}

fn matches_clause(entry: &LogEntry, clause: &FilterClause) -> Result<bool, crate::error::AppError> {
    let matches = match clause.field {
        FilterField::Message => match_string(&entry.message, &clause.op, &clause.value),
        FilterField::Component => {
            let comp = entry.component.as_deref().unwrap_or("");
            match_string(comp, &clause.op, &clause.value)
        }
        FilterField::Thread => {
            let thread_str = entry.thread.map(|t| t.to_string()).unwrap_or_default();
            match_string(&thread_str, &clause.op, &clause.value)
        }
        FilterField::Timestamp => {
            let ts = entry.timestamp.unwrap_or(0);
            return match_timestamp(ts, &clause.op, &clause.value);
        }
        FilterField::Severity => {
            let sev_str = match &entry.severity {
                crate::models::log_entry::Severity::Error => "Error",
                crate::models::log_entry::Severity::Warning => "Warning",
                crate::models::log_entry::Severity::Info => "Info",
            };
            match_string(sev_str, &clause.op, &clause.value)
        }
    };

    Ok(matches)
}

fn match_string(haystack: &str, op: &FilterOp, needle: &str) -> bool {
    let hay_lower = haystack.to_lowercase();
    let needle_lower = needle.to_lowercase();

    match op {
        FilterOp::Equals => hay_lower == needle_lower,
        FilterOp::NotEquals => hay_lower != needle_lower,
        FilterOp::Contains => hay_lower.contains(&needle_lower),
        FilterOp::NotContains => !hay_lower.contains(&needle_lower),
        // Before/After don't make sense for strings, always true
        FilterOp::Before | FilterOp::After => true,
    }
}

fn match_timestamp(ts: i64, op: &FilterOp, value: &str) -> Result<bool, crate::error::AppError> {
    if matches!(op, FilterOp::Contains | FilterOp::NotContains) {
        return Ok(true);
    }

    let target = parse_filter_timestamp_millis(value)?;

    Ok(match op {
        FilterOp::Before => ts < target,
        FilterOp::After => ts > target,
        FilterOp::Equals => ts == target,
        FilterOp::NotEquals => ts != target,
        FilterOp::Contains | FilterOp::NotContains => true,
    })
}

fn parse_filter_timestamp_millis(value: &str) -> Result<i64, crate::error::AppError> {
    let trimmed = value.trim();

    if trimmed.is_empty() {
        return Err(invalid_timestamp_filter_value(value));
    }

    if let Ok(epoch_millis) = trimmed.parse::<i64>() {
        return Ok(epoch_millis);
    }

    if let Ok(parsed) = DateTime::parse_from_rfc3339(trimmed) {
        return Ok(parsed.timestamp_millis());
    }

    for format in [
        "%Y-%m-%dT%H:%M:%S%.f",
        "%Y-%m-%d %H:%M:%S%.f",
        "%m/%d/%Y %H:%M:%S%.f",
        "%m/%d/%Y %I:%M:%S %p",
    ] {
        if let Ok(parsed) = NaiveDateTime::parse_from_str(trimmed, format) {
            return Ok(parsed.and_utc().timestamp_millis());
        }
    }

    for format in ["%Y-%m-%d", "%m/%d/%Y"] {
        if let Ok(parsed) = NaiveDate::parse_from_str(trimmed, format) {
            let start_of_day = parsed
                .and_hms_opt(0, 0, 0)
                .ok_or_else(|| invalid_timestamp_filter_value(value))?;
            return Ok(start_of_day.and_utc().timestamp_millis());
        }
    }

    Err(invalid_timestamp_filter_value(value))
}

fn invalid_timestamp_filter_value(value: &str) -> crate::error::AppError {
    crate::error::AppError::InvalidInput(format!(
        "Invalid timestamp filter value '{value}'. Use epoch milliseconds, YYYY-MM-DD, MM/DD/YYYY, or an ISO-8601 date/time."
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_filter_accepts_plain_iso_date() {
        let parsed = parse_filter_timestamp_millis("2026-04-01").expect("date should parse");
        let expected = NaiveDate::from_ymd_opt(2026, 4, 1)
            .expect("valid date")
            .and_hms_opt(0, 0, 0)
            .expect("valid time")
            .and_utc()
            .timestamp_millis();

        assert_eq!(parsed, expected);
    }

    #[test]
    fn timestamp_filter_accepts_rfc3339_datetime() {
        let parsed =
            parse_filter_timestamp_millis("2026-04-01T12:30:00Z").expect("datetime should parse");
        let expected = DateTime::parse_from_rfc3339("2026-04-01T12:30:00Z")
            .expect("valid datetime")
            .timestamp_millis();

        assert_eq!(parsed, expected);
    }

    #[test]
    fn timestamp_filter_rejects_invalid_values() {
        let error = match_timestamp(0, &FilterOp::Before, "yesterday")
            .expect_err("invalid value should fail");

        assert!(error.to_string().contains("Invalid timestamp filter value"));
    }

    #[test]
    fn timestamp_before_uses_parsed_date() {
        let target = parse_filter_timestamp_millis("2026-04-01").expect("date should parse");

        assert!(match_timestamp(target - 1, &FilterOp::Before, "2026-04-01").unwrap());
        assert!(!match_timestamp(target, &FilterOp::Before, "2026-04-01").unwrap());
    }
}
