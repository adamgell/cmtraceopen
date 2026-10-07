//! Lossless Windows Firewall fields and bounded coverage. No native source state.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FirewallSchemaOrigin {
    Header,
    Canonical,
    Unavailable,
}
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FirewallTimeBasis {
    Local,
    Utc,
    #[default]
    Unknown,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FirewallRecordKind {
    Traffic,
    EventsLost,
    Malformed,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FirewallField {
    pub name: String,
    pub value: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FirewallRecord {
    pub raw_line: String,
    pub declared_fields: Vec<String>,
    pub fields: Vec<FirewallField>,
    pub schema_origin: FirewallSchemaOrigin,
    pub time_basis: FirewallTimeBasis,
    pub record_kind: FirewallRecordKind,
    pub truncated: bool,
}

impl FirewallRecord {
    pub fn field(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|f| f.name.eq_ignore_ascii_case(name))?
            .value
            .as_deref()
    }
}

pub const MAX_FIREWALL_WARNING_SAMPLES: usize = 8;

/// Counts serialize as decimal strings so JavaScript cannot round a large loss count.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FirewallMetric {
    #[serde(with = "decimal_count")]
    pub count: u64,
    pub lines: Vec<u32>,
}
impl FirewallMetric {
    pub fn add(&mut self, count: u64, line: u32) {
        self.count = self.count.saturating_add(count);
        if count > 0
            && self.lines.len() < MAX_FIREWALL_WARNING_SAMPLES
            && !self.lines.contains(&line)
        {
            self.lines.push(line);
        }
    }
    fn merge(&mut self, other: &Self) {
        self.count = self.count.saturating_add(other.count);
        for &line in &other.lines {
            if self.lines.len() < MAX_FIREWALL_WARNING_SAMPLES && !self.lines.contains(&line) {
                self.lines.push(line);
            }
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FirewallCoverage {
    pub padding: FirewallMetric,
    pub malformed: FirewallMetric,
    pub oversized: FirewallMetric,
    pub loss_events: FirewallMetric,
    pub lost_events: FirewallMetric,
    pub unknown_loss_count: FirewallMetric,
    pub unplaced_timestamps: FirewallMetric,
}
impl FirewallCoverage {
    pub fn merge(&mut self, other: &Self) {
        self.padding.merge(&other.padding);
        self.malformed.merge(&other.malformed);
        self.oversized.merge(&other.oversized);
        self.loss_events.merge(&other.loss_events);
        self.lost_events.merge(&other.lost_events);
        self.unknown_loss_count.merge(&other.unknown_loss_count);
        self.unplaced_timestamps.merge(&other.unplaced_timestamps);
    }
    pub fn parse_errors(&self) -> u32 {
        self.malformed
            .count
            .saturating_add(self.oversized.count)
            .min(u32::MAX as u64) as u32
    }
}
mod decimal_count {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}
