use crate::models::log_entry::LogEntry;
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

    let matching_ids: Vec<u64> = entries
        .iter()
        .filter(|entry| clauses.iter().all(|clause| matches_clause(entry, clause)))
        .map(|entry| entry.id)
        .collect();

    Ok(matching_ids)
}

fn matches_clause(entry: &LogEntry, clause: &FilterClause) -> bool {
    match clause.field {
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
            match_timestamp(ts, &clause.op, &clause.value)
        }
    }
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

fn match_timestamp(ts: i64, op: &FilterOp, value: &str) -> bool {
    // Parse value as millisecond timestamp
    let target: i64 = match value.parse() {
        Ok(v) => v,
        Err(_) => return true, // If can't parse, don't filter
    };

    match op {
        FilterOp::Before => ts < target,
        FilterOp::After => ts > target,
        FilterOp::Equals => ts == target,
        FilterOp::NotEquals => ts != target,
        FilterOp::Contains | FilterOp::NotContains => true,
    }
}
