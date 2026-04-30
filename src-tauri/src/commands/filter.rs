use crate::models::log_entry::LogEntry;
use chrono::{DateTime, Local, NaiveDate, NaiveDateTime, TimeZone};
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

/// A clause whose value-side work has been done once up-front so the
/// per-entry hot loop in `apply_filter` does not redo it.
struct CompiledClause<'a> {
    clause: &'a FilterClause,
    /// Pre-parsed target for timestamp ops that need one (Before/After/
    /// Equals/NotEquals). `None` for non-timestamp fields and for the
    /// substring ops, which treat timestamps as a no-op.
    timestamp_target: Option<i64>,
    /// Lower-cased needle for string ops.
    needle_lower: String,
}

fn compile_clauses<'a>(
    clauses: &'a [FilterClause],
) -> Result<Vec<CompiledClause<'a>>, crate::error::AppError> {
    clauses
        .iter()
        .map(|clause| {
            let needs_timestamp_parse = matches!(clause.field, FilterField::Timestamp)
                && !matches!(clause.op, FilterOp::Contains | FilterOp::NotContains);

            let timestamp_target = if needs_timestamp_parse {
                Some(parse_filter_timestamp_millis(&clause.value)?)
            } else {
                None
            };

            Ok(CompiledClause {
                clause,
                timestamp_target,
                needle_lower: clause.value.to_lowercase(),
            })
        })
        .collect()
}

/// Apply filter clauses to a list of entries.
/// Returns the IDs of entries that match ALL clauses (AND logic).
/// Returns `Err(AppError::InvalidInput)` if a timestamp clause has an
/// unparseable value so the caller can surface it to the user.
#[tauri::command]
pub fn apply_filter(
    entries: Vec<LogEntry>,
    clauses: Vec<FilterClause>,
) -> Result<Vec<u64>, crate::error::AppError> {
    if clauses.is_empty() {
        // No filter — return all IDs
        return Ok(entries.iter().map(|e| e.id).collect());
    }

    // Compile once: parse timestamp targets and lowercase needles up-front
    // so the per-entry loop below is pure comparison work.
    let compiled = compile_clauses(&clauses)?;

    let mut matching_ids = Vec::new();

    for entry in &entries {
        if compiled.iter().all(|c| matches_clause(entry, c)) {
            matching_ids.push(entry.id);
        }
    }

    Ok(matching_ids)
}

fn matches_clause(entry: &LogEntry, compiled: &CompiledClause) -> bool {
    let CompiledClause {
        clause,
        timestamp_target,
        needle_lower,
    } = compiled;

    match clause.field {
        FilterField::Message => match_string(&entry.message, &clause.op, needle_lower),
        FilterField::Component => {
            let comp = entry.component.as_deref().unwrap_or("");
            match_string(comp, &clause.op, needle_lower)
        }
        FilterField::Thread => {
            let thread_str = entry.thread.map(|t| t.to_string()).unwrap_or_default();
            match_string(&thread_str, &clause.op, needle_lower)
        }
        FilterField::Timestamp => {
            let ts = entry.timestamp.unwrap_or(0);
            match_timestamp(ts, &clause.op, *timestamp_target)
        }
        FilterField::Severity => {
            let sev_str = match &entry.severity {
                crate::models::log_entry::Severity::Error => "Error",
                crate::models::log_entry::Severity::Warning => "Warning",
                crate::models::log_entry::Severity::Info => "Info",
            };
            match_string(sev_str, &clause.op, needle_lower)
        }
    }
}

/// `needle_lower` must already be lowercased; comparisons are
/// case-insensitive against a lowercased haystack.
fn match_string(haystack: &str, op: &FilterOp, needle_lower: &str) -> bool {
    let hay_lower = haystack.to_lowercase();

    match op {
        FilterOp::Equals => hay_lower == needle_lower,
        FilterOp::NotEquals => hay_lower != needle_lower,
        FilterOp::Contains => hay_lower.contains(needle_lower),
        FilterOp::NotContains => !hay_lower.contains(needle_lower),
        // Before/After don't make sense for strings, always true
        FilterOp::Before | FilterOp::After => true,
    }
}

/// `target` is the pre-parsed timestamp clause value (set by
/// `compile_clauses` for ops that need it). For the substring ops we
/// match every row, mirroring `match_string`'s no-op for Before/After.
fn match_timestamp(ts: i64, op: &FilterOp, target: Option<i64>) -> bool {
    match op {
        FilterOp::Contains | FilterOp::NotContains => true,
        FilterOp::Before => target.is_some_and(|t| ts < t),
        FilterOp::After => target.is_some_and(|t| ts > t),
        FilterOp::Equals => target.is_some_and(|t| ts == t),
        FilterOp::NotEquals => target.is_some_and(|t| ts != t),
    }
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

    // chrono's `%.f` requires a leading dot, so list whole-second variants
    // separately. Order: most-specific first so a millisecond input doesn't
    // get truncated by an earlier whole-second match.
    for format in [
        "%Y-%m-%dT%H:%M:%S%.f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S%.f",
        "%Y-%m-%d %H:%M:%S",
        "%m/%d/%Y %H:%M:%S%.f",
        "%m/%d/%Y %H:%M:%S",
        "%m/%d/%Y %I:%M:%S %p",
    ] {
        if let Ok(parsed) = NaiveDateTime::parse_from_str(trimmed, format) {
            return naive_to_local_millis(parsed)
                .ok_or_else(|| invalid_timestamp_filter_value(value));
        }
    }

    for format in ["%Y-%m-%d", "%m/%d/%Y"] {
        if let Ok(parsed) = NaiveDate::parse_from_str(trimmed, format) {
            let start_of_day = parsed
                .and_hms_opt(0, 0, 0)
                .ok_or_else(|| invalid_timestamp_filter_value(value))?;
            return naive_to_local_millis(start_of_day)
                .ok_or_else(|| invalid_timestamp_filter_value(value));
        }
    }

    Err(invalid_timestamp_filter_value(value))
}

/// Interpret a naive (timezone-less) datetime as local time, then convert to
/// UTC milliseconds. Filter inputs are typed by the user against the
/// log-list display, which the frontend formats in the local timezone.
/// Falls back to the earlier candidate when the wall-clock instant is
/// ambiguous (DST fall-back) and returns `None` for nonexistent times.
fn naive_to_local_millis(naive: NaiveDateTime) -> Option<i64> {
    match Local.from_local_datetime(&naive) {
        chrono::LocalResult::Single(dt) => Some(dt.timestamp_millis()),
        chrono::LocalResult::Ambiguous(earlier, _) => Some(earlier.timestamp_millis()),
        chrono::LocalResult::None => None,
    }
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
        let naive = NaiveDate::from_ymd_opt(2026, 4, 1)
            .expect("valid date")
            .and_hms_opt(0, 0, 0)
            .expect("valid time");
        let expected = naive_to_local_millis(naive).expect("local datetime should resolve");

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
    fn timestamp_filter_accepts_whole_second_datetimes() {
        let naive = NaiveDate::from_ymd_opt(2026, 4, 1)
            .expect("valid date")
            .and_hms_opt(12, 30, 0)
            .expect("valid time");
        let expected = naive_to_local_millis(naive).expect("local datetime should resolve");

        for input in [
            "2026-04-01 12:30:00",
            "2026-04-01T12:30:00",
            "04/01/2026 12:30:00",
        ] {
            let parsed = parse_filter_timestamp_millis(input)
                .unwrap_or_else(|e| panic!("'{input}' should parse: {e}"));
            assert_eq!(parsed, expected, "input={input}");
        }
    }

    #[test]
    fn timestamp_filter_naive_input_is_local_time() {
        // A naive input should match an entry whose UTC millis correspond to
        // that wall-clock instant in the local timezone.
        let naive = NaiveDate::from_ymd_opt(2026, 4, 1)
            .expect("valid date")
            .and_hms_opt(12, 30, 0)
            .expect("valid time");
        let local_millis = Local
            .from_local_datetime(&naive)
            .single()
            .expect("local datetime should resolve unambiguously")
            .timestamp_millis();

        assert_eq!(
            parse_filter_timestamp_millis("2026-04-01 12:30:00").unwrap(),
            local_millis,
        );
    }

    #[test]
    fn timestamp_filter_rejects_invalid_values() {
        let clauses = vec![FilterClause {
            field: FilterField::Timestamp,
            op: FilterOp::Before,
            value: "yesterday".into(),
        }];
        let error = compile_clauses(&clauses)
            .err()
            .expect("invalid value should fail");

        assert!(error.to_string().contains("Invalid timestamp filter value"));
    }

    #[test]
    fn timestamp_before_uses_parsed_date() {
        let target = parse_filter_timestamp_millis("2026-04-01").expect("date should parse");

        assert!(match_timestamp(target - 1, &FilterOp::Before, Some(target)));
        assert!(!match_timestamp(target, &FilterOp::Before, Some(target)));
    }

    #[test]
    fn compile_clauses_parses_each_timestamp_value_once() {
        let clauses = vec![FilterClause {
            field: FilterField::Timestamp,
            op: FilterOp::Before,
            value: "2026-04-01".into(),
        }];
        let compiled = compile_clauses(&clauses).expect("clause should compile");

        assert_eq!(compiled.len(), 1);
        assert!(compiled[0].timestamp_target.is_some());
    }

    #[test]
    fn compile_clauses_skips_parse_for_substring_ops_on_timestamps() {
        let clauses = vec![FilterClause {
            field: FilterField::Timestamp,
            op: FilterOp::Contains,
            value: "not-a-date".into(),
        }];
        let compiled = compile_clauses(&clauses)
            .expect("substring op should not require parseable value");

        assert!(compiled[0].timestamp_target.is_none());
    }
}
