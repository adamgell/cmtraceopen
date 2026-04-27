use serde::{Deserialize, Serialize};

#[allow(dead_code)]
/// Filter clause types matching CMTrace's string table IDs 16-21.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FilterClauseType {
    IsEqualTo,      // ID=16
    IsNotEqualTo,   // ID=17
    Contains,       // ID=18
    DoesNotContain, // ID=19
    IsBefore,       // ID=20, time dimension only
    IsAfter,        // ID=21, time dimension only
}

#[allow(dead_code)]
/// Which column/dimension the filter applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FilterDimension {
    LogText,
    Component,
    DateTime,
    Thread,
}

#[allow(dead_code)]
/// A single filter rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FilterRule {
    pub dimension: FilterDimension,
    pub clause: FilterClauseType,
    pub value: String,
}

#[allow(dead_code)]
/// Complete filter configuration (can have multiple rules).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct FilterConfig {
    pub rules: Vec<FilterRule>,
    pub active: bool,
}
