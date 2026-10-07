//! Lossless Windows Firewall fields and bounded coverage. No native source state.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// How field positions were established for a record.
pub enum FirewallSchemaOrigin {
    /// An accepted #Fields declaration supplies the order.
    Header,
    /// A strictly validated headerless record supplies the standard order.
    Canonical,
    /// No usable field mapping is available.
    Unavailable,
}
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// Clock provenance; only explicit UTC permits an absolute timestamp.
pub enum FirewallTimeBasis {
    /// Literal local wall-clock time with no inferred offset.
    Local,
    /// The section explicitly declares UTC.
    Utc,
    #[default]
    /// No recognized time directive applies.
    Unknown,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// Whether the row describes traffic, lost evidence, or malformed text.
pub enum FirewallRecordKind {
    /// A mapped traffic observation; ALLOW and DROP remain informational.
    Traffic,
    /// An INFO-EVENTS-LOST notice, represented as a warning.
    EventsLost,
    /// A row that cannot be mapped without reassigning or losing fields.
    Malformed,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// One ordered field, preserving its original spelling and value.
pub struct FirewallField {
    /// Original declared field name.
    pub name: String,
    /// Original token, including literal hyphens; None denotes an absent token.
    pub value: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// Decoded physical-row evidence and its schema and clock provenance.
pub struct FirewallRecord {
    /// Decoded text after framing and leading padding removal; a bounded prefix when truncated.
    pub raw_line: String,
    /// Ordered field names, including a rejected declaration when mapping failed.
    pub declared_fields: Vec<String>,
    /// Mapped fields in declaration order; empty for malformed records.
    pub fields: Vec<FirewallField>,
    /// Origin of the mapping used for this record.
    pub schema_origin: FirewallSchemaOrigin,
    /// Clock provenance retained independently of timestamp validity.
    pub time_basis: FirewallTimeBasis,
    /// Traffic, loss notice, or malformed evidence classification.
    pub record_kind: FirewallRecordKind,
    /// Whether the stream discarded text beyond the decoded line limit.
    pub truncated: bool,
}

impl FirewallRecord {
    /// Find the first case-insensitive field name; missing values remain absent.
    pub fn field(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|f| f.name.eq_ignore_ascii_case(name))?
            .value
            .as_deref()
    }
}

/// Maximum number of unique physical line samples retained per metric.
pub const MAX_FIREWALL_WARNING_SAMPLES: usize = 8;

/// Counts serialize as decimal strings so JavaScript cannot round a large loss count.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FirewallMetric {
    #[serde(with = "decimal_count")]
    /// Saturating count, serialized as a decimal string to avoid JavaScript rounding.
    pub count: u64,
    /// At most eight unique physical line numbers sampled in encounter order.
    pub lines: Vec<u32>,
}
impl FirewallMetric {
    /// Add with saturation and sample the line only when the contribution is positive.
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
/// Cumulative coverage categories with bounded physical-line samples.
pub struct FirewallCoverage {
    /// Leading NUL characters skipped, not raw encoded bytes.
    pub padding: FirewallMetric,
    /// Malformed records, excluding oversized records counted separately.
    pub malformed: FirewallMetric,
    /// Physical records exceeding the decoded line limit.
    pub oversized: FirewallMetric,
    /// INFO-EVENTS-LOST notices encountered.
    pub loss_events: FirewallMetric,
    /// Sum of valid lost-event counts reported by loss notices.
    pub lost_events: FirewallMetric,
    /// Loss notices whose event count could not be interpreted.
    pub unknown_loss_count: FirewallMetric,
    /// Records without a trustworthy absolute timestamp.
    pub unplaced_timestamps: FirewallMetric,
}
impl FirewallCoverage {
    /// Merge independent contributions with saturation and bounded unique samples.
    pub fn merge(&mut self, other: &Self) {
        self.padding.merge(&other.padding);
        self.malformed.merge(&other.malformed);
        self.oversized.merge(&other.oversized);
        self.loss_events.merge(&other.loss_events);
        self.lost_events.merge(&other.lost_events);
        self.unknown_loss_count.merge(&other.unknown_loss_count);
        self.unplaced_timestamps.merge(&other.unplaced_timestamps);
    }
    /// Malformed plus oversized counts, clamped to u32; other coverage is not an error.
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
