//! Merging Windows events and parsed text logs into one chronological view.
//!
//! Every event viewer surveyed for issue #539 is events-only, and every log viewer is text-only.
//! Nobody puts them side by side, which is the one thing that actually explains a failure: the
//! `DeviceManagement-Enterprise-Diagnostics-Provider` event says enrollment failed with an HRESULT,
//! and the `IntuneManagementExtension.log` line thirty seconds earlier says why.
//!
//! This module owns the merge. It is pure and holds no knowledge of where items came from, so the
//! event side can live in the host layer while the log side comes straight from
//! [`LogEntry`](crate::models::log_entry::LogEntry).
//!
//! The hard part is not sorting. It is refusing to place things that cannot honestly be placed:
//! an entry with no timestamp has no position on a timeline, and putting it at the epoch or at the
//! previous entry's time would invent a sequence the evidence does not support.

use serde::{Deserialize, Serialize};

use crate::esp::{process_start_instant, EspTimestamp, EspTimestampKind};
use crate::models::log_entry::{LogEntry, Severity};

/// Severity normalized across both sides of the merge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub enum TimelineSeverity {
    /// Diagnostic detail, from a verbose event. Text logs have no equivalent.
    Verbose,
    /// Ordinary progress. The default, since a line carrying no severity is not a problem.
    #[default]
    Info,
    /// Something the source flagged as worth noticing but did not treat as a failure.
    Warning,
    /// A failure the source reported. The highest a text log reaches.
    Error,
    /// Only events carry this; text logs top out at error.
    Critical,
}

impl TimelineSeverity {
    /// Maps a text log severity.
    ///
    /// `Success` maps to `Info` rather than gaining a level of its own: on a merged timeline it is
    /// an ordinary informational line, and a separate rank would sort it away from the events it
    /// sits between.
    pub fn from_log(severity: Severity) -> Self {
        match severity {
            Severity::Error => Self::Error,
            Severity::Warning => Self::Warning,
            Severity::Info | Severity::Success => Self::Info,
        }
    }

    /// Maps a Windows event level value as written in `System/Level`.
    ///
    /// Level 0 means "not set", which providers use for events that are not classified. It maps to
    /// `Info` because treating an unclassified event as critical would flood a severity filter.
    pub fn from_event_level(level: u8) -> Self {
        match level {
            1 => Self::Critical,
            2 => Self::Error,
            3 => Self::Warning,
            5 => Self::Verbose,
            _ => Self::Info,
        }
    }
}

/// Where a timeline item came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
// Growable: a third kind of source, such as a registry export or an ETW trace read directly, is a
// plausible addition. Marking it now keeps that a minor change.
#[non_exhaustive]
// rename_all covers the variant names; rename_all_fields is what camel-cases the fields inside a
// struct variant. Without the second one, event_id went over the wire as "event_id" while the
// timeline view reads origin.eventId, so every event row rendered undefined.
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
// Keep the flattened wire shape and avoid allocating every event origin behind a Box.
#[allow(clippy::large_enum_variant)]
pub enum TimelineOrigin {
    /// A line from a parsed text log.
    Log {
        /// File the line came from, as the parser recorded it.
        file: String,
        /// Emitting component, when the format carries one.
        component: Option<String>,
        /// 1-based line number, so the item can be traced back to the source.
        line: u32,
        /// Stable source label. This is the source file when one is available.
        source: String,
        /// Machine that emitted the line, when the source records one.
        machine: Option<String>,
        /// Containing evidence bundle, when the source path identifies one.
        bundle: Option<String>,
        /// Stable parser record identity.
        record_id: u64,
    },
    /// A Windows event.
    Event {
        /// Stable identity composed from source identity, channel, and EventRecordID.
        ///
        /// `EvtxRecord.id` is a mutable UI index and must not be used here: live appends can
        /// reorder records and renumber it.
        stable_id: String,
        source: String,
        /// Machine that emitted the event, when the source records one.
        machine: Option<String>,
        /// Containing evidence bundle, when known.
        bundle: Option<String>,
        /// Channel the event was read from, for example `Microsoft-Windows-DNSServer/Audit`.
        channel: String,
        /// Publisher that raised it, as the event's own `System` block names it.
        provider: String,
        /// Emitting process, when the event declares one.
        process_id: Option<u32>,
        /// Correlation ActivityID, when the event declares one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        activity_id: Option<String>,
        /// Related ActivityID, when the event declares one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        related_activity_id: Option<String>,
        /// Session identifier, when the event declares one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session_id: Option<String>,
        /// Device identifier, when the event declares one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        device_id: Option<String>,
        /// User identifier, when the event declares one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        user_id: Option<String>,
        /// Process start evidence paired with `process_id`, when present in event data.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        process_start_time: Option<String>,
        /// Explicit identity aliases that disagreed in the source event.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        identity_conflicts: Vec<String>,
        /// Event ID, which identifies the event only in combination with the provider.
        event_id: u32,
        record_id: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        record_id_text: Option<String>,
    },
}

/// One placed item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TimelineItem {
    /// Milliseconds since the Unix epoch.
    pub timestamp_ms: i64,
    /// How serious the source said this was, normalized across event levels and log levels.
    pub severity: TimelineSeverity,
    /// The rendered text, already whatever the source's own formatting produced.
    pub message: String,
    /// Which file or channel this came from, so a row on a merged timeline stays attributable.
    pub origin: TimelineOrigin,
}

/// Something that could not be placed, and why.
///
/// Surfaced rather than dropped: a timeline that silently omits a third of a log file looks
/// complete and is not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnplacedItem {
    /// Where it came from, so an operator can go and look.
    pub origin: TimelineOrigin,
    /// Why it has no position.
    pub reason: UnplacedReason,
}

/// Why an item has no position on the timeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum UnplacedReason {
    /// The source carried no timestamp, or one the parser could not read.
    MissingTimestamp,
}

/// Identity key that can be used to correlate two timeline origins.
///
/// Exact keys are explicit provider/event identities. `Secondary` is deliberately weaker and can
/// only produce a candidate edge; it is never promoted to causal evidence.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TimelineCorrelationKeyKind {
    ActivityId,
    RelatedActivityId,
    ProviderChannelEventRecord,
    ProcessStart,
    SessionId,
    DeviceId,
    UserId,
    Secondary,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TimelineCorrelationKey {
    pub kind: TimelineCorrelationKeyKind,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TimelineCorrelationObservation {
    pub origin_id: String,
    pub machine: Option<String>,
    pub exact_keys: Vec<TimelineCorrelationKey>,
    #[serde(default)]
    pub secondary_keys: Vec<TimelineCorrelationKey>,
    #[serde(default)]
    pub coverage_gaps: Vec<TimelineCoverageGap>,
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TimelineCorrelationStrength {
    Exact,
    Candidate,
    Ambiguous,
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TimelineCorrelationConfidence {
    High,
    Low,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TimelineCorrelationEvidence {
    pub origin_id: String,
    pub field: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TimelineCoverageGap {
    pub source: String,
    pub reason: String,
}
/// Classification for a timeline coverage gap.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TimelineCoverageState {
    /// Work was intentionally skipped because the available identity was insufficient.
    Skipped,
    /// Required source identity was not available.
    Absent,
    /// A source value was present but could not be interpreted.
    Malformed,
    /// A configured item or relation budget was reached.
    Capped,
    /// The source or correlation mode is not supported.
    Unsupported,
    /// The source was observed but has no stronger classification.
    Unknown,
}
/// Classifies a producer-owned timeline coverage reason without duplicating its
/// wire strings in consumers.
pub fn coverage_state(reason: &str) -> TimelineCoverageState {
    let lower = reason.to_ascii_lowercase();
    let is_correlation_group_limit = (lower.starts_with("exact ")
        && lower.contains(" identity group exceeds the ")
        && lower.ends_with(" correlation limit"))
        || (lower.starts_with("secondary ")
            && lower.contains(" identity group exceeds the ")
            && lower.ends_with(" correlation limit"));

    if lower == "no explicit identity keys were present; timestamp-only correlation is not causal"
        || lower == "only secondary identity was present; correlation remains low confidence"
    {
        TimelineCoverageState::Skipped
    } else if lower == "machine identity unavailable; exact correlation is restricted"
        || lower == "process start identity was unavailable for a nonzero process id"
        || lower == "process start identity requires a nonzero process id"
    {
        TimelineCoverageState::Absent
    } else if lower.starts_with("conflicting explicit identity aliases for ")
        || lower.starts_with("multiple exact identity candidates remain: ")
    {
        TimelineCoverageState::Skipped
    } else if lower.starts_with("duplicate origin identity coalesced from ") {
        TimelineCoverageState::Unknown
    } else if lower.starts_with("process start identity was present but its timestamp was invalid")
    {
        TimelineCoverageState::Malformed
    } else if (lower.starts_with("correlation relation budget") && lower.ends_with(" was reached"))
        || lower.starts_with("coverage gap limit reached;")
        || lower.starts_with("correlation candidate output budget reached;")
        || lower.starts_with("correlation edge output budget reached;")
        || is_correlation_group_limit
    {
        TimelineCoverageState::Capped
    } else {
        TimelineCoverageState::Unsupported
    }
}

#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TimelineCorrelationCoverageState {
    Covered,
    Gap,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TimelineCorrelationCoverage {
    pub state: TimelineCorrelationCoverageState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gap: Option<TimelineCoverageGap>,
}

impl TimelineCorrelationCoverage {
    fn covered() -> Self {
        Self {
            state: TimelineCorrelationCoverageState::Covered,
            gap: None,
        }
    }
    fn gap(gap: TimelineCoverageGap) -> Self {
        Self {
            state: TimelineCorrelationCoverageState::Gap,
            gap: Some(gap),
        }
    }
}

/// An evidence-backed relationship between two stable timeline origins.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TimelineCorrelationEdge {
    pub id: String,
    pub from_id: String,
    pub to_id: Option<String>,
    pub key: TimelineCorrelationKey,
    pub strength: TimelineCorrelationStrength,
    pub confidence: TimelineCorrelationConfidence,
    #[serde(default)]
    pub candidate_ids: Vec<String>,
    #[serde(default)]
    pub evidence: Vec<TimelineCorrelationEvidence>,
    pub coverage: TimelineCorrelationCoverage,
}

/// A merged timeline plus everything that could not be placed on it or assessed for correlation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnifiedTimeline {
    /// Items in chronological order.
    pub items: Vec<TimelineItem>,
    /// Items with no honest position, in input order.
    pub unplaced: Vec<UnplacedItem>,
    /// Evidence-backed relationships between placed or unplaced origins.
    #[serde(default)]
    pub edges: Vec<TimelineCorrelationEdge>,
    /// Missing/unsupported identity coverage that prevents a stronger conclusion.
    #[serde(default)]
    pub coverage_gaps: Vec<TimelineCoverageGap>,
}

impl UnifiedTimeline {
    /// True when everything supplied was placed.
    pub fn is_complete(&self) -> bool {
        self.unplaced.is_empty()
    }

    /// Inclusive time span covered, or `None` when nothing was placed.
    pub fn span_ms(&self) -> Option<(i64, i64)> {
        let mut stamps = self.items.iter().map(|item| item.timestamp_ms);
        let first = stamps.next()?;
        Some(stamps.fold((first, first), |(low, high), stamp| {
            (low.min(stamp), high.max(stamp))
        }))
    }
}

fn identity_value(value: &str) -> Option<&str> {
    let value = value.trim().trim_end_matches('.');
    if value.is_empty()
        || matches!(
            value.to_ascii_lowercase().as_str(),
            "unknown" | "n/a" | "na" | "none" | "null" | "not available" | "not_applicable"
        )
    {
        None
    } else {
        Some(value)
    }
}

fn normalized_identity(value: &str) -> Option<String> {
    identity_value(value).map(str::to_ascii_lowercase)
}

fn source_identity(value: &str) -> Option<String> {
    let value = identity_value(value)?;
    let bytes = value.as_bytes();
    let has_windows_drive = bytes.get(1) == Some(&b':') && bytes[0].is_ascii_alphabetic();
    let is_windows_shaped = has_windows_drive || (!value.starts_with('/') && value.contains('\\'));
    Some(if is_windows_shaped {
        value.to_ascii_lowercase()
    } else {
        value.to_string()
    })
}

fn usable_record_text(value: Option<&str>) -> Option<String> {
    value
        .and_then(normalized_identity)
        .filter(|value| value.bytes().any(|byte| byte != b'0'))
}

/// Normalizes a machine name without ever treating an unknown sentinel as a concrete host.
pub fn normalize_machine_identity(value: Option<&str>) -> Option<String> {
    value.and_then(normalized_identity)
}

fn key_label(kind: &TimelineCorrelationKeyKind) -> &'static str {
    match kind {
        TimelineCorrelationKeyKind::ActivityId => "activityId",
        TimelineCorrelationKeyKind::RelatedActivityId => "relatedActivityId",
        TimelineCorrelationKeyKind::ProviderChannelEventRecord => "providerChannelEventRecord",
        TimelineCorrelationKeyKind::ProcessStart => "processStart",
        TimelineCorrelationKeyKind::SessionId => "sessionId",
        TimelineCorrelationKeyKind::DeviceId => "deviceId",
        TimelineCorrelationKeyKind::UserId => "userId",
        TimelineCorrelationKeyKind::Secondary => "secondary",
    }
}

fn correlation_kind(kind: &TimelineCorrelationKeyKind) -> TimelineCorrelationKeyKind {
    match kind {
        TimelineCorrelationKeyKind::ActivityId | TimelineCorrelationKeyKind::RelatedActivityId => {
            TimelineCorrelationKeyKind::ActivityId
        }
        other => other.clone(),
    }
}

fn keys_match(left: &TimelineCorrelationKey, right: &TimelineCorrelationKey) -> bool {
    correlation_kind(&left.kind) == correlation_kind(&right.kind) && left.value == right.value
}

fn validated_process_start(value: Option<&str>) -> Option<String> {
    let raw = value?.trim();
    if raw.is_empty() {
        return None;
    }
    let kind = if raw.len() == 25 && raw.as_bytes().get(14) == Some(&b'.') {
        EspTimestampKind::Offset
    } else if chrono::DateTime::parse_from_rfc3339(raw).is_ok() {
        if raw.ends_with('Z') || raw.ends_with('z') || raw.ends_with("+00:00") {
            EspTimestampKind::Utc
        } else if !raw.ends_with("-00:00") {
            EspTimestampKind::Offset
        } else {
            return None;
        }
    } else {
        return None;
    };
    let timestamp = EspTimestamp {
        raw_text: raw.to_string(),
        original_offset: None,
        normalized_utc: None,
        kind,
    };
    process_start_instant(&timestamp)
        .map(|instant| instant.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true))
}

fn observation_from_origin(origin: &TimelineOrigin) -> TimelineCorrelationObservation {
    let (origin_id, machine, exact_keys, secondary_keys, coverage_gaps) = match origin {
        TimelineOrigin::Log { .. } => {
            let id = origin_id(origin);
            (id, None, Vec::new(), Vec::new(), Vec::new())
        }
        TimelineOrigin::Event {
            stable_id,
            source,
            machine,
            provider,
            channel,
            process_id,
            activity_id,
            related_activity_id,
            session_id,
            device_id,
            process_start_time,
            identity_conflicts,
            event_id,
            record_id,
            record_id_text,
            ..
        } => {
            let mut exact_keys = Vec::new();
            let mut coverage_gaps = identity_conflicts
                .iter()
                .map(|field| TimelineCoverageGap {
                    source: stable_id.clone(),
                    reason: format!("conflicting explicit identity aliases for {field}"),
                })
                .collect::<Vec<_>>();
            let is_conflicted =
                |field: &str| identity_conflicts.iter().any(|conflict| conflict == field);
            let push_exact = |keys: &mut Vec<TimelineCorrelationKey>,
                              kind: TimelineCorrelationKeyKind,
                              value: Option<&str>,
                              field: &str| {
                if !is_conflicted(field) {
                    if let Some(value) = value.and_then(normalized_identity) {
                        keys.push(TimelineCorrelationKey { kind, value });
                    }
                }
            };
            push_exact(
                &mut exact_keys,
                TimelineCorrelationKeyKind::ActivityId,
                activity_id.as_deref(),
                "activityId",
            );
            push_exact(
                &mut exact_keys,
                TimelineCorrelationKeyKind::RelatedActivityId,
                related_activity_id.as_deref(),
                "relatedActivityId",
            );
            push_exact(
                &mut exact_keys,
                TimelineCorrelationKeyKind::SessionId,
                session_id.as_deref(),
                "sessionId",
            );
            push_exact(
                &mut exact_keys,
                TimelineCorrelationKeyKind::DeviceId,
                device_id.as_deref(),
                "deviceId",
            );
            let record = usable_record_text(record_id_text.as_deref())
                .or_else(|| (*record_id != 0).then(|| record_id.to_string()));
            if let (Some(source), Some(provider), Some(channel), Some(record)) = (
                source_identity(source),
                normalized_identity(provider),
                normalized_identity(channel),
                record,
            ) {
                exact_keys.push(TimelineCorrelationKey {
                    kind: TimelineCorrelationKeyKind::ProviderChannelEventRecord,
                    value: format!(
                        "{}|{}|{}|{}|{}",
                        key_part(&source),
                        key_part(&provider),
                        key_part(&channel),
                        event_id,
                        key_part(&record)
                    ),
                });
            }
            if let Some(process_start_time) = process_start_time.as_deref() {
                if let Some(process_id) = (*process_id).filter(|value| *value != 0) {
                    if !is_conflicted("processStartTime") {
                        if let Some(start) = validated_process_start(Some(process_start_time)) {
                            exact_keys.push(TimelineCorrelationKey {
                                kind: TimelineCorrelationKeyKind::ProcessStart,
                                value: format!("{process_id}|{start}"),
                            });
                        } else {
                            coverage_gaps.push(TimelineCoverageGap {
                                source: stable_id.clone(),
                                reason: "process start identity was present but its timestamp was invalid"
                                    .to_string(),
                            });
                        }
                    }
                } else {
                    coverage_gaps.push(TimelineCoverageGap {
                        source: stable_id.clone(),
                        reason: "process start identity requires a nonzero process id".to_string(),
                    });
                }
            }
            (
                stable_id.clone(),
                normalize_machine_identity(machine.as_deref()),
                exact_keys,
                Vec::new(),
                coverage_gaps,
            )
        }
    };
    TimelineCorrelationObservation {
        origin_id,
        machine,
        exact_keys,
        secondary_keys,
        coverage_gaps,
    }
}

/// Returns the stable ID used by correlation edges for an origin.
pub fn origin_id(origin: &TimelineOrigin) -> String {
    match origin {
        TimelineOrigin::Log {
            source,
            file,
            line,
            record_id,
            ..
        } => format!(
            "log|{}|{}|{line}|{record_id}",
            key_part(source),
            key_part(file)
        ),
        TimelineOrigin::Event { stable_id, .. } => stable_id.clone(),
    }
}

/// Reduces explicit identity observations into deterministic, evidence-backed edges.
///
/// Exact groups are scoped by normalized machine identity and require a unique counterpart. A
/// conflicting set of exact keys remains ambiguous with all candidate IDs. Secondary process-only
/// identity can only produce a low-confidence candidate edge. No timestamp, channel proximity, or
/// message/error text participates in this reducer.
const MAX_CORRELATION_GROUP_MEMBERS: usize = 256;
const MAX_CORRELATION_RELATIONS: usize = 25_000;
const MAX_CORRELATION_GAPS: usize = 4_096;
const CORRELATION_GAP_TRUNCATION_SOURCE: &str = "correlation";
const MAX_CORRELATION_CANDIDATE_BYTES: usize = 1_048_576;
const CORRELATION_CANDIDATE_BUDGET_REASON: &str =
    "correlation candidate output budget reached; candidate IDs omitted";
const MAX_CORRELATION_EDGE_BYTES: usize = 16 * 1024 * 1024;
const CORRELATION_EDGE_BUDGET_REASON: &str =
    "correlation edge output budget reached; additional edges omitted";

fn disambiguate_observation_ids(
    observations: &[TimelineCorrelationObservation],
) -> Vec<TimelineCorrelationObservation> {
    use std::collections::{BTreeMap, BTreeSet};

    // A duplicate origin is already represented by multiple timeline items. Keep its
    // canonical base ID and merge only the identity material used by correlation. Adding
    // an occurrence suffix here would make edges and gaps refer to an ID no timeline
    // origin owns.
    struct Accumulator {
        observation: TimelineCorrelationObservation,
        machines: BTreeSet<String>,
        count: usize,
    }

    let mut grouped = BTreeMap::<String, Accumulator>::new();
    for observation in observations {
        let entry = grouped
            .entry(observation.origin_id.clone())
            .or_insert_with(|| Accumulator {
                observation: TimelineCorrelationObservation {
                    origin_id: observation.origin_id.clone(),
                    machine: None,
                    exact_keys: Vec::new(),
                    secondary_keys: Vec::new(),
                    coverage_gaps: Vec::new(),
                },
                machines: BTreeSet::new(),
                count: 0,
            });
        entry.count += 1;
        if let Some(machine) = normalize_machine_identity(observation.machine.as_deref()) {
            entry.machines.insert(machine);
        }
        entry
            .observation
            .exact_keys
            .extend(observation.exact_keys.iter().cloned());
        entry
            .observation
            .secondary_keys
            .extend(observation.secondary_keys.iter().cloned());
        entry
            .observation
            .coverage_gaps
            .extend(observation.coverage_gaps.iter().cloned());
    }

    grouped
        .into_values()
        .map(|mut entry| {
            if entry.count > 1 {
                let origin_id = entry.observation.origin_id.clone();
                entry.observation.coverage_gaps.push(TimelineCoverageGap {
                    source: origin_id,
                    reason: format!(
                        "duplicate origin identity coalesced from {} observations",
                        entry.count
                    ),
                });
            }
            let observation = &mut entry.observation;
            observation.exact_keys.sort();
            observation.exact_keys.dedup();
            observation.secondary_keys.sort();
            observation.secondary_keys.dedup();
            observation.coverage_gaps.sort_by(|left, right| {
                left.source
                    .cmp(&right.source)
                    .then_with(|| left.reason.cmp(&right.reason))
            });
            observation
                .coverage_gaps
                .dedup_by(|left, right| left.source == right.source && left.reason == right.reason);
            observation.machine = (entry.machines.len() == 1)
                .then(|| entry.machines.into_iter().next().expect("one machine"));
            entry.observation
        })
        .collect()
}

pub fn correlate_observations(
    observations: &[TimelineCorrelationObservation],
) -> (Vec<TimelineCorrelationEdge>, Vec<TimelineCoverageGap>) {
    use std::collections::{BTreeMap, BTreeSet};

    let disambiguated = disambiguate_observation_ids(observations);
    let mut ordered: Vec<_> = disambiguated.iter().collect();
    ordered.sort_by(|left, right| left.origin_id.cmp(&right.origin_id));

    let mut exact_groups: BTreeMap<(String, TimelineCorrelationKeyKind, String), BTreeSet<String>> =
        BTreeMap::new();
    let mut secondary_groups: BTreeMap<(String, String), BTreeSet<String>> = BTreeMap::new();
    let by_id: BTreeMap<_, _> = ordered
        .iter()
        .map(|observation| (observation.origin_id.clone(), *observation))
        .collect();

    for observation in &ordered {
        let Some(machine) = normalize_machine_identity(observation.machine.as_deref()) else {
            continue;
        };
        for key in &observation.exact_keys {
            exact_groups
                .entry((
                    machine.clone(),
                    correlation_kind(&key.kind),
                    key.value.clone(),
                ))
                .or_default()
                .insert(observation.origin_id.clone());
        }
        for key in &observation.secondary_keys {
            secondary_groups
                .entry((machine.clone(), key.value.clone()))
                .or_default()
                .insert(observation.origin_id.clone());
        }
    }

    type Relation = (String, String);
    let mut exact_candidates: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut relation_keys: BTreeMap<Relation, BTreeSet<TimelineCorrelationKey>> = BTreeMap::new();
    let mut fanout_gaps = BTreeSet::new();
    let mut relation_budget = MAX_CORRELATION_RELATIONS;
    for ((_, kind, value), ids) in &exact_groups {
        if ids.len() < 2 {
            continue;
        }
        if ids.len() > MAX_CORRELATION_GROUP_MEMBERS {
            let reason = format!(
                "exact {kind:?} identity group exceeds the {MAX_CORRELATION_GROUP_MEMBERS}-member correlation limit"
            );
            for id in ids {
                fanout_gaps.insert((id.clone(), reason.clone()));
            }
            continue;
        }
        if relation_budget == 0 {
            let reason =
                format!("correlation relation budget of {MAX_CORRELATION_RELATIONS} was reached");
            for id in ids {
                fanout_gaps.insert((id.clone(), reason.clone()));
            }
            continue;
        }
        let pair_count = ids.len().saturating_mul(ids.len().saturating_sub(1)) / 2;
        if pair_count > relation_budget {
            let reason =
                format!("correlation relation budget of {MAX_CORRELATION_RELATIONS} was reached");
            for id in ids {
                fanout_gaps.insert((id.clone(), reason.clone()));
            }
            relation_budget = 0;
            continue;
        }
        let ids: Vec<_> = ids.iter().cloned().collect();
        let mut truncated = false;
        'exact_pairs: for (left_index, left) in ids.iter().enumerate() {
            for right in ids.iter().skip(left_index + 1) {
                if relation_budget == 0 {
                    truncated = true;
                    break 'exact_pairs;
                }
                relation_budget -= 1;
                exact_candidates
                    .entry(left.clone())
                    .or_default()
                    .insert(right.clone());
                exact_candidates
                    .entry(right.clone())
                    .or_default()
                    .insert(left.clone());
                let relation = (left.clone(), right.clone());
                for endpoint in [left, right] {
                    if let Some(observation) = by_id.get(endpoint) {
                        relation_keys.entry(relation.clone()).or_default().extend(
                            observation
                                .exact_keys
                                .iter()
                                .filter(|key| {
                                    correlation_kind(&key.kind) == *kind && key.value == *value
                                })
                                .cloned(),
                        );
                    }
                }
            }
        }
        if truncated {
            let reason =
                format!("correlation relation budget of {MAX_CORRELATION_RELATIONS} was reached");
            for id in ids {
                fanout_gaps.insert((id, reason.clone()));
            }
        }
    }

    let mut candidate_relations: BTreeMap<Relation, BTreeSet<TimelineCorrelationKey>> =
        BTreeMap::new();
    for ((machine, value), ids) in &secondary_groups {
        if ids.len() < 2 {
            continue;
        }
        if ids.len() > MAX_CORRELATION_GROUP_MEMBERS {
            let reason = format!(
                "secondary identity group exceeds the {MAX_CORRELATION_GROUP_MEMBERS}-member correlation limit"
            );
            for id in ids {
                fanout_gaps.insert((id.clone(), reason.clone()));
            }
            continue;
        }
        if relation_budget == 0 {
            let reason =
                format!("correlation relation budget of {MAX_CORRELATION_RELATIONS} was reached");
            for id in ids {
                fanout_gaps.insert((id.clone(), reason.clone()));
            }
            continue;
        }
        let ids: Vec<_> = ids.iter().cloned().collect();
        let mut truncated = false;
        'secondary_pairs: for (left_index, left) in ids.iter().enumerate() {
            if exact_candidates
                .get(left)
                .is_some_and(|candidates| !candidates.is_empty())
            {
                continue;
            }
            for right in ids.iter().skip(left_index + 1) {
                if relation_budget == 0 {
                    truncated = true;
                    break 'secondary_pairs;
                }
                if exact_candidates
                    .get(right)
                    .is_some_and(|candidates| !candidates.is_empty())
                {
                    continue;
                }
                relation_budget -= 1;
                candidate_relations
                    .entry((left.clone(), right.clone()))
                    .or_default()
                    .insert(TimelineCorrelationKey {
                        kind: TimelineCorrelationKeyKind::Secondary,
                        value: format!("{machine}|{value}"),
                    });
            }
        }
        if truncated {
            let reason =
                format!("correlation relation budget of {MAX_CORRELATION_RELATIONS} was reached");
            for id in ids {
                fanout_gaps.insert((id, reason.clone()));
            }
        }
    }

    let mut edges = Vec::new();
    let mut candidate_output_budget = MAX_CORRELATION_CANDIDATE_BYTES;
    let mut edge_output_budget = MAX_CORRELATION_EDGE_BYTES;
    let mut edge_output_truncated = false;
    for (relation, keys) in relation_keys
        .into_iter()
        .map(|(relation, keys)| (relation, (keys, true)))
        .chain(
            candidate_relations
                .into_iter()
                .map(|(relation, keys)| (relation, (keys, false))),
        )
    {
        if edge_output_truncated {
            continue;
        }
        let (left, right) = relation;
        let (keys, exact) = keys;
        let mut candidates = BTreeSet::new();
        if exact {
            candidates.extend(exact_candidates.get(&left).into_iter().flatten().cloned());
            candidates.extend(exact_candidates.get(&right).into_iter().flatten().cloned());
        } else {
            candidates.insert(right.clone());
        }
        let conflicting_candidates: BTreeSet<_> = candidates
            .iter()
            .filter(|candidate| *candidate != &left && *candidate != &right)
            .cloned()
            .collect();
        let ambiguous = exact && !conflicting_candidates.is_empty();
        let strength = if ambiguous {
            TimelineCorrelationStrength::Ambiguous
        } else if exact {
            TimelineCorrelationStrength::Exact
        } else {
            TimelineCorrelationStrength::Candidate
        };
        let confidence = match strength {
            TimelineCorrelationStrength::Exact => TimelineCorrelationConfidence::High,
            TimelineCorrelationStrength::Candidate => TimelineCorrelationConfidence::Low,
            TimelineCorrelationStrength::Ambiguous => TimelineCorrelationConfidence::Unknown,
        };
        let key = keys.into_iter().next().expect("relation has a key");
        let mut evidence = Vec::new();
        for endpoint in [&left, &right] {
            if let Some(observation) = by_id.get(endpoint) {
                let matching = observation
                    .exact_keys
                    .iter()
                    .chain(observation.secondary_keys.iter())
                    .find(|candidate| keys_match(candidate, &key))
                    .cloned()
                    .unwrap_or_else(|| key.clone());
                evidence.push(TimelineCorrelationEvidence {
                    origin_id: endpoint.clone(),
                    field: key_label(&matching.kind).to_string(),
                    value: matching.value,
                });
            }
        }
        let candidate_bytes = if ambiguous {
            candidates
                .iter()
                .filter(|candidate| *candidate != &left)
                .fold(0usize, |total, candidate| {
                    total.saturating_add(candidate.len())
                })
        } else {
            0
        };
        let candidate_output_truncated = ambiguous && candidate_bytes > candidate_output_budget;
        if candidate_output_truncated {
            fanout_gaps.insert((
                CORRELATION_GAP_TRUNCATION_SOURCE.to_string(),
                CORRELATION_CANDIDATE_BUDGET_REASON.to_string(),
            ));
        }
        let candidate_ids: Vec<_> = if ambiguous && !candidate_output_truncated {
            candidate_output_budget = candidate_output_budget.saturating_sub(candidate_bytes);
            candidates
                .iter()
                .filter(|candidate| *candidate != &left)
                .cloned()
                .collect()
        } else {
            Vec::new()
        };
        let id = format!(
            "edge|{}|{}|{}|{}",
            key_part(&left),
            key_part(&right),
            key_label(&key.kind),
            key_part(&key.value)
        );
        let coverage_gap = if candidate_output_truncated {
            Some(TimelineCoverageGap {
                source: left.clone(),
                reason: CORRELATION_CANDIDATE_BUDGET_REASON.to_string(),
            })
        } else {
            [&left, &right]
                .iter()
                .find_map(|endpoint| by_id.get(*endpoint)?.coverage_gaps.first().cloned())
                .or_else(|| {
                    ambiguous.then(|| TimelineCoverageGap {
                        source: left.clone(),
                        reason: format!(
                            "multiple exact identity candidates remain: {}",
                            candidate_ids.join(", ")
                        ),
                    })
                })
        };
        let coverage = coverage_gap
            .map(TimelineCorrelationCoverage::gap)
            .unwrap_or_else(TimelineCorrelationCoverage::covered);
        let evidence_bytes = evidence
            .iter()
            .map(|entry| {
                entry
                    .origin_id
                    .len()
                    .saturating_add(entry.field.len())
                    .saturating_add(entry.value.len())
            })
            .sum::<usize>();
        let coverage_bytes = coverage
            .gap
            .as_ref()
            .map(|gap| gap.source.len().saturating_add(gap.reason.len()))
            .unwrap_or_default();
        let edge_payload_bytes = id
            .len()
            .saturating_add(left.len())
            .saturating_add(right.len())
            .saturating_add(key_label(&key.kind).len())
            .saturating_add(key.value.len())
            .saturating_add(
                candidate_ids
                    .iter()
                    .fold(0usize, |total, value| total.saturating_add(value.len())),
            )
            .saturating_add(evidence_bytes)
            .saturating_add(coverage_bytes)
            .saturating_add(512);
        let estimated_edge_bytes = edge_payload_bytes.saturating_mul(8);
        if estimated_edge_bytes > edge_output_budget {
            edge_output_truncated = true;
            fanout_gaps.insert((
                CORRELATION_GAP_TRUNCATION_SOURCE.to_string(),
                CORRELATION_EDGE_BUDGET_REASON.to_string(),
            ));
            continue;
        }
        edge_output_budget = edge_output_budget.saturating_sub(estimated_edge_bytes);
        edges.push(TimelineCorrelationEdge {
            id,
            from_id: left,
            to_id: Some(right),
            key,
            strength,
            confidence,
            candidate_ids,
            evidence,
            coverage,
        });
    }

    let mut gap_set = fanout_gaps;
    for observation in ordered {
        gap_set.extend(
            observation
                .coverage_gaps
                .iter()
                .cloned()
                .map(|gap| (gap.source, gap.reason)),
        );
        let has_specific_gap = observation
            .coverage_gaps
            .iter()
            .any(|gap| gap.source == observation.origin_id);
        if normalize_machine_identity(observation.machine.as_deref()).is_none() {
            gap_set.insert((
                observation.origin_id.clone(),
                "machine identity unavailable; exact correlation is restricted".to_string(),
            ));
        } else if observation.exact_keys.is_empty()
            && !observation.secondary_keys.is_empty()
            && !has_specific_gap
        {
            gap_set.insert((
                observation.origin_id.clone(),
                "only secondary identity was present; correlation remains low confidence"
                    .to_string(),
            ));
        }
    }
    let truncated = gap_set.len() > MAX_CORRELATION_GAPS;
    let retained_limit = if truncated {
        MAX_CORRELATION_GAPS.saturating_sub(1)
    } else {
        MAX_CORRELATION_GAPS
    };
    let omitted_count = gap_set.len().saturating_sub(retained_limit);
    let mut gaps = gap_set
        .into_iter()
        .take(retained_limit)
        .map(|(source, reason)| TimelineCoverageGap { source, reason })
        .collect::<Vec<_>>();
    if truncated {
        let gap_label = if omitted_count == 1 { "gap" } else { "gaps" };
        gaps.push(TimelineCoverageGap {
            source: CORRELATION_GAP_TRUNCATION_SOURCE.to_string(),
            reason: format!(
                "coverage gap limit reached; {omitted_count} additional {gap_label} omitted"
            ),
        });
    }
    (edges, gaps)
}

/// Correlates all placed and unplaced origins in a timeline.
pub fn correlate_timeline(
    items: &[TimelineItem],
    unplaced: &[UnplacedItem],
) -> (Vec<TimelineCorrelationEdge>, Vec<TimelineCoverageGap>) {
    let observations = items
        .iter()
        .map(|item| observation_from_origin(&item.origin))
        .chain(
            unplaced
                .iter()
                .map(|item| observation_from_origin(&item.origin)),
        )
        .collect::<Vec<_>>();
    correlate_observations(&observations)
}

/// Validates the collector's generated bundle-directory identifier.
fn is_collector_bundle_id(segment: &str) -> bool {
    const PREFIX: &str = "CMTRACE-";
    const NONCE_LENGTH: usize = 32;

    let Some(prefix) = segment.get(..PREFIX.len()) else {
        return false;
    };
    if !prefix.eq_ignore_ascii_case(PREFIX) {
        return false;
    }
    let mut parts = segment[PREFIX.len()..].splitn(3, '-');
    let (Some(date), Some(time), Some(host_and_nonce)) = (parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    let Some((hostname, nonce)) = host_and_nonce.rsplit_once('-') else {
        return false;
    };
    let valid_date = date.len() == 8 && date.bytes().all(|byte| byte.is_ascii_digit()) && {
        let year = date[..4].parse::<i32>().expect("validated year digits");
        let month = date[4..6].parse::<u32>().expect("validated month digits");
        let day = date[6..8].parse::<u32>().expect("validated day digits");
        year >= 1 && chrono::NaiveDate::from_ymd_opt(year, month, day).is_some()
    };
    let valid_time = time.len() == 6 && time.bytes().all(|byte| byte.is_ascii_digit()) && {
        let hour = time[..2].parse::<u32>().expect("validated hour digits");
        let minute = time[2..4].parse::<u32>().expect("validated minute digits");
        let second = time[4..6].parse::<u32>().expect("validated second digits");
        chrono::NaiveTime::from_hms_opt(hour, minute, second).is_some()
    };
    valid_date
        && valid_time
        && !hostname.is_empty()
        && nonce.len() == NONCE_LENGTH
        && nonce.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Returns the bundle identifier from the collector's bundle-id/evidence directory layout.
pub fn bundle_from_source(source: &str) -> Option<String> {
    let segments = source
        .split(['/', '\\'])
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    segments.windows(2).find_map(|pair| {
        let [bundle_id, evidence] = pair else {
            return None;
        };
        (evidence.eq_ignore_ascii_case("evidence") && is_collector_bundle_id(bundle_id))
            .then(|| (*bundle_id).to_string())
    })
}

/// Converts a parsed log entry, or reports why it cannot be placed.
pub fn from_log_entry(entry: &LogEntry) -> Result<TimelineItem, Box<UnplacedItem>> {
    let file = entry.file_path.clone();
    let source = entry.source_file.clone().unwrap_or_else(|| file.clone());
    let bundle = bundle_from_source(&source).or_else(|| bundle_from_source(&file));
    let origin = TimelineOrigin::Log {
        file,
        component: entry.component.clone(),
        line: entry.line_number,
        bundle,
        // LogEntry::host_name is DHCP client payload, not the machine that emitted the log.
        machine: None,
        record_id: entry.id,
        source,
    };

    match entry.timestamp {
        Some(timestamp_ms) => Ok(TimelineItem {
            timestamp_ms,
            severity: TimelineSeverity::from_log(entry.severity),
            message: entry.message.clone(),
            origin,
        }),
        None => Err(Box::new(UnplacedItem {
            origin,
            reason: UnplacedReason::MissingTimestamp,
        })),
    }
}

/// Appends parsed log entries without losing existing placed or unplaced records.
pub fn append(timeline: &mut UnifiedTimeline, entries: &[LogEntry]) {
    let mut placed = std::mem::take(&mut timeline.items);
    let mut unplaced = std::mem::take(&mut timeline.unplaced);
    for entry in entries {
        match from_log_entry(entry) {
            Ok(item) => placed.push(item),
            Err(item) => unplaced.push(*item),
        }
    }
    *timeline = merge(placed, unplaced);
}
/// Builds a collision-resistant textual key for deterministic provenance ordering.
fn key_part(value: &str) -> String {
    format!("{}:{value}", value.len())
}

fn optional_text_key(value: Option<&str>) -> String {
    value.map(key_part).unwrap_or_else(|| "none".to_string())
}

fn optional_number_key<T: std::fmt::Display>(value: Option<T>) -> String {
    value
        .map(|number| format!("some:{number}"))
        .unwrap_or_else(|| "none".to_string())
}

/// Returns the canonical provenance key used for all timeline ordering.
///
/// Every serialized origin field participates, not just the primary identity. This keeps
/// equal-identity records deterministic when a timeline is built in one batch or reconciled from
/// several batches.
pub fn origin_sort_key(origin: &TimelineOrigin) -> String {
    match origin {
        TimelineOrigin::Log {
            source,
            file,
            line,
            component,
            machine,
            bundle,
            record_id,
        } => format!(
            "log|{}|{}|{line:010}|{record_id:020}|{}|{}|{}",
            key_part(source),
            key_part(file),
            optional_text_key(component.as_deref()),
            optional_text_key(machine.as_deref()),
            optional_text_key(bundle.as_deref()),
        ),
        TimelineOrigin::Event {
            stable_id,
            source,
            machine,
            bundle,
            channel,
            provider,
            process_id,
            activity_id,
            related_activity_id,
            session_id,
            device_id,
            user_id,
            process_start_time,
            identity_conflicts,
            event_id,
            record_id,
            record_id_text,
        } => format!(
            "event|{stable}|{source}|{machine}|{bundle}|{channel}|{provider}|{process}|{activity}|{related}|{session}|{device}|{user}|{process_start}|{conflicts}|{event_id:010}|{record_id:020}|{record_text}",
            stable = key_part(stable_id),
            source = key_part(source),
            machine = optional_text_key(machine.as_deref()),
            bundle = optional_text_key(bundle.as_deref()),
            channel = key_part(channel),
            provider = key_part(provider),
            process = optional_number_key(*process_id),
            activity = optional_text_key(activity_id.as_deref()),
            related = optional_text_key(related_activity_id.as_deref()),
            session = optional_text_key(session_id.as_deref()),
            device = optional_text_key(device_id.as_deref()),
            user = optional_text_key(user_id.as_deref()),
            process_start = optional_text_key(process_start_time.as_deref()),
            conflicts = identity_conflicts
                .iter()
                .map(|conflict| key_part(conflict))
                .collect::<Vec<_>>()
                .join(","),
            event_id = event_id,
            record_id = record_id,
            record_text = optional_text_key(record_id_text.as_deref()),
        ),
    }
}

/// Returns the canonical key for a placed timeline item.
///
/// The event adapter uses this same key before occurrence suffixes are assigned, so full builds
/// and append reconciliation cannot disagree when otherwise identical timestamps are split across
/// batches.
pub fn timeline_sort_key(
    timestamp_ms: i64,
    severity: TimelineSeverity,
    message: &str,
    origin: &TimelineOrigin,
) -> (i64, String, String, TimelineSeverity) {
    (
        timestamp_ms,
        origin_sort_key(origin),
        message.to_string(),
        severity,
    )
}

/// Merges already-converted items into one chronological timeline.
///
/// Equal timestamps use deterministic source and row identity ordering, so channel completion
/// order and append history cannot change the merged result.
pub fn merge(
    placed: impl IntoIterator<Item = TimelineItem>,
    unplaced: impl IntoIterator<Item = UnplacedItem>,
) -> UnifiedTimeline {
    let mut items: Vec<TimelineItem> = placed.into_iter().collect();
    items.sort_by_cached_key(|item| {
        timeline_sort_key(
            item.timestamp_ms,
            item.severity,
            &item.message,
            &item.origin,
        )
    });
    let mut unplaced: Vec<UnplacedItem> = unplaced.into_iter().collect();
    unplaced.sort_by_cached_key(|item| origin_sort_key(&item.origin));
    UnifiedTimeline {
        items,
        unplaced,
        edges: Vec::new(),
        coverage_gaps: Vec::new(),
    }
}

/// Converts and merges a slice of log entries, collecting the ones that cannot be placed.
pub fn from_log_entries(entries: &[LogEntry]) -> UnifiedTimeline {
    let mut timeline = UnifiedTimeline::default();
    append(&mut timeline, entries);
    timeline
}

#[cfg(test)]
mod tests {
    use super::*;

    fn log_entry(timestamp: Option<i64>, message: &str, severity: Severity) -> LogEntry {
        LogEntry {
            id: 0,
            line_number: 7,
            message: message.to_string(),
            component: Some("IME".to_string()),
            timestamp,
            severity,
            file_path: "C:/logs/IntuneManagementExtension.log".to_string(),
            ..LogEntry::default()
        }
    }

    fn event(timestamp_ms: i64, message: &str, severity: TimelineSeverity) -> TimelineItem {
        TimelineItem {
            timestamp_ms,
            severity,
            message: message.to_string(),
            origin: TimelineOrigin::Event {
                stable_id: "Live/Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin#1"
                    .to_string(),
                source: "Live".to_string(),
                machine: Some("TESTHOST".to_string()),
                bundle: None,
                channel: "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin"
                    .to_string(),
                provider: "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider"
                    .to_string(),
                process_id: None,
                activity_id: None,
                related_activity_id: None,
                session_id: None,
                device_id: None,
                user_id: None,
                process_start_time: None,
                identity_conflicts: Vec::new(),
                event_id: 76,
                record_id: 1,
                record_id_text: Some("1".to_string()),
            },
        }
    }

    #[test]
    fn events_and_log_lines_interleave_by_time() {
        // The whole point: the event says enrollment failed, the log line before it says why.
        let logs = [
            log_entry(Some(1_000), "Checking enrollment", Severity::Info),
            log_entry(Some(3_000), "Token request rejected", Severity::Error),
        ];
        let timeline = merge(
            logs.iter()
                .filter_map(|entry| from_log_entry(entry).ok())
                .chain([event(2_000, "MDM enroll failed", TimelineSeverity::Error)]),
            [],
        );

        let messages: Vec<&str> = timeline.items.iter().map(|i| i.message.as_str()).collect();
        assert_eq!(
            messages,
            vec![
                "Checking enrollment",
                "MDM enroll failed",
                "Token request rejected"
            ]
        );
    }

    #[test]
    fn an_entry_without_a_timestamp_is_reported_rather_than_placed() {
        let entries = [
            log_entry(Some(1_000), "placed", Severity::Info),
            log_entry(None, "continuation line", Severity::Info),
        ];
        let timeline = from_log_entries(&entries);

        assert_eq!(timeline.items.len(), 1);
        assert_eq!(timeline.unplaced.len(), 1);
        assert_eq!(
            timeline.unplaced[0].reason,
            UnplacedReason::MissingTimestamp
        );
        assert!(!timeline.is_complete());
    }

    #[test]
    fn an_unplaced_item_still_says_where_it_came_from() {
        let timeline = from_log_entries(&[log_entry(None, "orphan", Severity::Error)]);
        match &timeline.unplaced[0].origin {
            TimelineOrigin::Log {
                file,
                line,
                component,
                ..
            } => {
                assert!(file.ends_with("IntuneManagementExtension.log"));
                assert_eq!(*line, 7);
                assert_eq!(component.as_deref(), Some("IME"));
            }
            other => panic!("expected a log origin, got {other:?}"),
        }
    }

    #[test]
    fn items_sharing_a_timestamp_use_canonical_row_order() {
        // Equal timestamps cannot be ordered by time, so the complete row key must govern both
        // one-shot builds and append reconciliation.
        let timeline = merge(
            [
                event(5_000, "third supplied", TimelineSeverity::Error),
                event(5_000, "first supplied", TimelineSeverity::Verbose),
                event(5_000, "second supplied", TimelineSeverity::Critical),
            ],
            [],
        );
        let messages: Vec<&str> = timeline.items.iter().map(|i| i.message.as_str()).collect();
        assert_eq!(
            messages,
            vec!["first supplied", "second supplied", "third supplied"]
        );
    }

    #[test]
    fn negative_timestamps_sort_before_the_epoch_rather_than_wrapping() {
        let timeline = merge(
            [
                event(10, "after", TimelineSeverity::Info),
                event(-10, "before", TimelineSeverity::Info),
            ],
            [],
        );
        assert_eq!(timeline.items[0].message, "before");
    }

    #[test]
    fn the_span_covers_first_to_last() {
        let timeline = merge(
            [
                event(3_000, "c", TimelineSeverity::Info),
                event(1_000, "a", TimelineSeverity::Info),
            ],
            [],
        );
        assert_eq!(timeline.span_ms(), Some((1_000, 3_000)));
    }

    #[test]
    fn an_empty_timeline_has_no_span_rather_than_a_zero_one() {
        let timeline = UnifiedTimeline::default();
        assert_eq!(timeline.span_ms(), None);
        assert!(timeline.is_complete());
    }

    #[test]
    fn log_success_is_informational_not_a_rank_of_its_own() {
        // A separate rank would sort Success away from the events it sits between.
        assert_eq!(
            TimelineSeverity::from_log(Severity::Success),
            TimelineSeverity::Info
        );
        assert_eq!(
            TimelineSeverity::from_log(Severity::Error),
            TimelineSeverity::Error
        );
    }

    #[test]
    fn event_level_zero_is_informational_not_critical() {
        // Level 0 means "not set". Ranking it critical would flood a severity filter.
        assert_eq!(
            TimelineSeverity::from_event_level(0),
            TimelineSeverity::Info
        );
        assert_eq!(
            TimelineSeverity::from_event_level(1),
            TimelineSeverity::Critical
        );
        assert_eq!(
            TimelineSeverity::from_event_level(5),
            TimelineSeverity::Verbose
        );
        // An undeclared level must not panic or invent a rank.
        assert_eq!(
            TimelineSeverity::from_event_level(9),
            TimelineSeverity::Info
        );
    }

    #[test]
    fn severity_orders_from_verbose_to_critical() {
        assert!(TimelineSeverity::Verbose < TimelineSeverity::Info);
        assert!(TimelineSeverity::Error < TimelineSeverity::Critical);
    }

    #[test]
    fn a_log_entry_falls_back_to_its_file_path_when_no_source_file_is_recorded() {
        let timeline = from_log_entries(&[log_entry(Some(1), "x", Severity::Info)]);
        match &timeline.items[0].origin {
            TimelineOrigin::Log { file, .. } => assert!(file.contains("IntuneManagementExtension")),
            other => panic!("expected a log origin, got {other:?}"),
        }
    }

    #[test]
    fn an_event_origin_preserves_all_cross_source_provenance() {
        let origin = TimelineOrigin::Event {
            stable_id: "capture.evtx/Application#42".into(),
            source: "capture.evtx".into(),
            machine: Some("HOST-A".into()),
            bundle: Some("bundle-123".into()),
            channel: "Application".into(),
            provider: "ESENT".into(),
            process_id: Some(4321),
            activity_id: Some("{activity}".into()),
            related_activity_id: None,
            session_id: None,
            device_id: None,
            user_id: None,
            process_start_time: None,
            identity_conflicts: Vec::new(),
            event_id: 326,
            record_id: 42,
            record_id_text: Some("42".into()),
        };
        let json = serde_json::to_value(&origin).expect("serializes");

        assert_eq!(json["kind"], "event");
        assert_eq!(json["source"], "capture.evtx");
        assert_eq!(json["machine"], "HOST-A");
        assert_eq!(json["bundle"], "bundle-123");
        assert_eq!(json["channel"], "Application");
        assert_eq!(json["provider"], "ESENT");
        assert_eq!(json["processId"], 4321);
        assert_eq!(json["activityId"], "{activity}");
        assert_eq!(json["eventId"], 326);
        assert_eq!(json["stableId"], "capture.evtx/Application#42");
        assert_eq!(json["recordId"], 42);
    }

    #[test]
    fn appending_records_reconciles_into_the_same_deterministic_order() {
        let mut timeline = merge([event(3_000, "last", TimelineSeverity::Info)], []);
        append(
            &mut timeline,
            &[log_entry(Some(1_000), "first", Severity::Info)],
        );

        let messages: Vec<&str> = timeline
            .items
            .iter()
            .map(|item| item.message.as_str())
            .collect();
        assert_eq!(messages, vec!["first", "last"]);
        assert!(timeline.is_complete());
    }

    #[test]
    fn equal_timestamps_order_cross_source_identity_not_input_history() {
        let log = from_log_entries(&[log_entry(Some(5_000), "text", Severity::Info)])
            .items
            .pop()
            .expect("log item");
        let event_item = event(5_000, "event", TimelineSeverity::Info);
        let one = merge([log.clone(), event_item.clone()], []);
        let two = merge([event_item, log], []);
        let messages_one: Vec<_> = one.items.iter().map(|item| item.message.as_str()).collect();
        let messages_two: Vec<_> = two.items.iter().map(|item| item.message.as_str()).collect();
        assert_eq!(messages_one, messages_two);
        assert_eq!(messages_one, vec!["event", "text"]);
    }

    #[test]
    fn append_keeps_missing_timestamps_visible_and_counts_them() {
        let mut timeline = merge([event(1_000, "placed", TimelineSeverity::Info)], []);
        append(
            &mut timeline,
            &[log_entry(None, "unplaced", Severity::Info)],
        );

        assert_eq!(timeline.items.len(), 1);
        assert_eq!(timeline.unplaced.len(), 1);
        assert_eq!(
            timeline.unplaced[0].reason,
            UnplacedReason::MissingTimestamp
        );
        assert!(!timeline.is_complete());
    }

    #[test]
    fn equal_timestamps_use_canonical_order_for_live_reconciliation() {
        let mut timeline = UnifiedTimeline::default();
        append(
            &mut timeline,
            &[log_entry(Some(5_000), "second", Severity::Info)],
        );
        append(
            &mut timeline,
            &[log_entry(Some(5_000), "first", Severity::Info)],
        );

        let messages: Vec<&str> = timeline
            .items
            .iter()
            .map(|item| item.message.as_str())
            .collect();
        assert_eq!(messages, vec!["first", "second"]);
    }

    #[test]
    fn log_origin_does_not_treat_dhcp_client_name_as_machine_provenance() {
        let mut entry = log_entry(Some(1_000), "line", Severity::Info);
        entry.id = 99;
        entry.host_name = Some("LEASED-CLIENT".into());
        entry.source_file = Some(
            "/ProgramData/CmtraceOpen/Evidence/CMTRACE-20260822-120000-HOST-0123456789abcdef0123456789abcdef/evidence/dhcp.log"
                .into(),
        );
        let timeline = from_log_entries(&[entry]);

        match &timeline.items[0].origin {
            TimelineOrigin::Log {
                source,
                machine,
                bundle,
                record_id,
                ..
            } => {
                assert_eq!(
                    source,
                    "/ProgramData/CmtraceOpen/Evidence/CMTRACE-20260822-120000-HOST-0123456789abcdef0123456789abcdef/evidence/dhcp.log"
                );
                assert_eq!(machine, &None);
                assert_eq!(
                    bundle.as_deref(),
                    Some("CMTRACE-20260822-120000-HOST-0123456789abcdef0123456789abcdef")
                );
                assert_eq!(*record_id, 99);
            }
            other => panic!("expected a log origin, got {other:?}"),
        }
    }

    #[test]
    fn log_origin_keeps_physical_file_separate_from_parser_source_token() {
        let mut entry = log_entry(Some(1_000), "line", Severity::Info);
        entry.source_file = Some("store.cs:1".into());
        entry.file_path = r"C:\ProgramData\CmtraceOpen\Evidence\CMTRACE-20260822-120000-HOST-abcdef0123456789abcdef0123456789\evidence\ccm.log".into();
        let timeline = from_log_entries(&[entry]);

        match &timeline.items[0].origin {
            TimelineOrigin::Log {
                file,
                source,
                bundle,
                ..
            } => {
                assert_eq!(
                    file,
                    r"C:\ProgramData\CmtraceOpen\Evidence\CMTRACE-20260822-120000-HOST-abcdef0123456789abcdef0123456789\evidence\ccm.log"
                );
                assert_eq!(source, "store.cs:1");
                assert_eq!(
                    bundle.as_deref(),
                    Some("CMTRACE-20260822-120000-HOST-abcdef0123456789abcdef0123456789")
                );
            }
            other => panic!("expected a log origin, got {other:?}"),
        }
    }

    #[test]
    fn bundle_provenance_rejects_paths_that_are_not_collector_output() {
        assert_eq!(
            bundle_from_source("/captures/arbitrary/bundle/evidence/event.evtx"),
            None
        );
        assert_eq!(
            bundle_from_source(
                "/captures/CMTRACE-20260822-120000-HOST-not-a-uuid/evidence/event.evtx"
            ),
            None
        );
        assert_eq!(
            bundle_from_source(
                "/captures/CMTRACE-20261340-120000-HOST-0123456789abcdef0123456789abcdef/evidence/event.evtx"
            ),
            None
        );
        assert_eq!(
            bundle_from_source(
                "/captures/CMTRACE-20260822-250061-HOST-0123456789abcdef0123456789abcdef/evidence/event.evtx"
            ),
            None
        );
        assert_eq!(
            bundle_from_source(
                "/captures/CMTRACE-00000101-120000-HOST-0123456789abcdef0123456789abcdef/evidence/event.evtx"
            ),
            None
        );
        assert_eq!(
            bundle_from_source(
                "/captures/CMTRACE-20260822-235960-HOST-0123456789abcdef0123456789abcdef/evidence/event.evtx"
            ),
            None
        );
    }

    #[test]
    fn non_ccm_log_origin_uses_physical_file_when_no_source_token_exists() {
        let mut entry = log_entry(Some(1_000), "panther line", Severity::Info);
        entry.source_file = None;
        entry.file_path = "/logs/setupact.log".into();
        let timeline = from_log_entries(&[entry]);

        match &timeline.items[0].origin {
            TimelineOrigin::Log {
                file,
                source,
                bundle,
                ..
            } => {
                assert_eq!(file, "/logs/setupact.log");
                assert_eq!(source, "/logs/setupact.log");
                assert_eq!(bundle, &None);
            }
            other => panic!("expected a log origin, got {other:?}"),
        }
    }

    #[test]
    fn a_log_origin_keeps_its_wire_keys() {
        let origin = TimelineOrigin::Log {
            file: "cmt.log".into(),
            component: Some("Agent".into()),
            line: 7,
            source: "cmt.log".into(),
            machine: None,
            bundle: None,
            record_id: 7,
        };
        let json = serde_json::to_value(&origin).expect("serializes");
        assert_eq!(json["kind"], "log");
        assert_eq!(json["file"], "cmt.log");
        assert_eq!(json["line"], 7);
        assert_eq!(json["source"], "cmt.log");
        assert_eq!(json["recordId"], 7);
    }

    #[test]
    fn duplicate_log_origins_keep_a_resolvable_base_gap() {
        let mut first = log_entry(Some(1_000), "first", Severity::Info);
        first.id = 17;
        let mut second = first.clone();
        second.message = "second".to_string();
        let timeline = from_log_entries(&[first, second]);

        let (edges, gaps) = correlate_timeline(&timeline.items, &timeline.unplaced);

        assert!(edges.is_empty());
        assert_eq!(gaps.len(), 2);
        assert!(gaps
            .iter()
            .all(|gap| gap.source == origin_id(&timeline.items[0].origin)));
        assert!(gaps.iter().any(|gap| {
            gap.reason
                .contains("duplicate origin identity coalesced from 2 observations")
        }));
    }

    #[test]
    fn duplicate_observations_merge_keys_without_synthetic_edge_references() {
        let observations = [
            observation(
                "same-origin",
                Some("HOST"),
                &[(TimelineCorrelationKeyKind::ActivityId, "activity")],
                &[],
            ),
            observation(
                "same-origin",
                Some("HOST"),
                &[(TimelineCorrelationKeyKind::SessionId, "session")],
                &[],
            ),
            observation(
                "other-origin",
                Some("HOST"),
                &[(TimelineCorrelationKeyKind::RelatedActivityId, "activity")],
                &[],
            ),
        ];
        let mut reversed = observations.to_vec();
        reversed.reverse();
        assert_eq!(
            correlate_observations(&observations),
            correlate_observations(&reversed)
        );

        let (edges, gaps) = correlate_observations(&observations);

        assert_eq!(edges.len(), 1);
        let edge = &edges[0];
        assert_eq!(edge.from_id, "other-origin");
        assert_eq!(edge.to_id.as_deref(), Some("same-origin"));
        assert!(edge
            .evidence
            .iter()
            .all(|evidence| evidence.origin_id == "other-origin"
                || evidence.origin_id == "same-origin"));
        assert!(!edge.id.contains("#occurrence-"));
        assert!(gaps.iter().any(|gap| {
            gap.source == "same-origin"
                && gap
                    .reason
                    .contains("duplicate origin identity coalesced from 2 observations")
        }));
        assert!(gaps.iter().all(|gap| !gap.source.contains("#occurrence-")));
    }
    fn observation(
        id: &str,
        machine: Option<&str>,
        exact: &[(TimelineCorrelationKeyKind, &str)],
        secondary: &[&str],
    ) -> TimelineCorrelationObservation {
        TimelineCorrelationObservation {
            origin_id: id.into(),
            machine: machine.map(str::to_string),
            exact_keys: exact
                .iter()
                .map(|(kind, value)| TimelineCorrelationKey {
                    kind: kind.clone(),
                    value: (*value).into(),
                })
                .collect(),
            secondary_keys: secondary
                .iter()
                .map(|value| TimelineCorrelationKey {
                    kind: TimelineCorrelationKeyKind::Secondary,
                    value: (*value).into(),
                })
                .collect(),
            coverage_gaps: Vec::new(),
        }
    }
    #[test]
    fn correlation_gap_budget_reports_omitted_gaps() {
        let observations = (0..=MAX_CORRELATION_GAPS)
            .map(|index| observation(&format!("missing-machine-{index}"), None, &[], &[]))
            .collect::<Vec<_>>();

        let (_, gaps) = correlate_observations(&observations);

        assert_eq!(gaps.len(), MAX_CORRELATION_GAPS);
        assert!(gaps.iter().any(|gap| {
            gap.source == "correlation"
                && gap.reason == "coverage gap limit reached; 2 additional gaps omitted"
        }));
    }

    #[test]
    fn relation_budget_gap_precedes_member_limit_for_small_exact_group() {
        let mut observations = (0..224)
            .map(|index| {
                observation(
                    &format!("exact-large-{index}"),
                    Some("HOST"),
                    &[(TimelineCorrelationKeyKind::ActivityId, "a")],
                    &[],
                )
            })
            .collect::<Vec<_>>();
        for group in 0..24 {
            let value = format!("b-{group:02}");
            observations.extend((0..2).map(|index| {
                observation(
                    &format!("exact-pair-{group}-{index}"),
                    Some("HOST"),
                    &[(TimelineCorrelationKeyKind::ActivityId, &value)],
                    &[],
                )
            }));
        }
        observations.extend((0..2).map(|index| {
            observation(
                &format!("exact-small-{index}"),
                Some("HOST"),
                &[(TimelineCorrelationKeyKind::ActivityId, "z")],
                &[],
            )
        }));

        let (_, gaps) = correlate_observations(&observations);

        assert!(gaps.iter().any(|gap| {
            gap.source == "exact-small-0" && gap.reason.contains("relation budget")
        }));
    }

    #[test]
    fn relation_budget_gap_precedes_member_limit_for_small_secondary_group() {
        let mut observations = (0..224)
            .map(|index| {
                observation(
                    &format!("secondary-large-{index}"),
                    Some("HOST"),
                    &[],
                    &["a"],
                )
            })
            .collect::<Vec<_>>();
        for group in 0..24 {
            let value = format!("b-{group:02}");
            observations.extend((0..2).map(|index| {
                observation(
                    &format!("secondary-pair-{group}-{index}"),
                    Some("HOST"),
                    &[],
                    &[&value],
                )
            }));
        }
        observations.extend((0..2).map(|index| {
            observation(
                &format!("secondary-small-{index}"),
                Some("HOST"),
                &[],
                &["z"],
            )
        }));

        let (_, gaps) = correlate_observations(&observations);

        assert!(gaps.iter().any(|gap| {
            gap.source == "secondary-small-0" && gap.reason.contains("relation budget")
        }));
    }

    #[test]
    fn oversized_exact_identity_group_is_reported_without_pair_expansion() {
        let observations = (0..=MAX_CORRELATION_GROUP_MEMBERS)
            .map(|index| {
                observation(
                    &format!("event-{index}"),
                    Some("HOST"),
                    &[(TimelineCorrelationKeyKind::ActivityId, "same-activity")],
                    &[],
                )
            })
            .collect::<Vec<_>>();

        let (edges, gaps) = correlate_observations(&observations);

        assert!(edges.is_empty());
        assert_eq!(gaps.len(), MAX_CORRELATION_GROUP_MEMBERS + 1);
        assert!(gaps
            .iter()
            .all(|gap| gap.reason.contains("correlation limit")));
    }

    #[test]
    fn relation_budget_does_not_emit_partial_exact_group_edges() {
        let mut observations = (0..224)
            .map(|index| {
                observation(
                    &format!("large-{index}"),
                    Some("HOST"),
                    &[(TimelineCorrelationKeyKind::ActivityId, "a")],
                    &[],
                )
            })
            .collect::<Vec<_>>();
        for group in 0..23 {
            let value = format!("b-{group}");
            observations.extend((0..2).map(|index| {
                observation(
                    &format!("pair-{group}-{index}"),
                    Some("HOST"),
                    &[(TimelineCorrelationKeyKind::ActivityId, &value)],
                    &[],
                )
            }));
        }
        observations.extend((0..3).map(|index| {
            observation(
                &format!("truncated-{index}"),
                Some("HOST"),
                &[(TimelineCorrelationKeyKind::ActivityId, "z")],
                &[],
            )
        }));

        let (edges, gaps) = correlate_observations(&observations);

        assert!(edges.iter().all(|edge| {
            !edge.from_id.starts_with("truncated-")
                && !edge
                    .to_id
                    .as_deref()
                    .is_some_and(|id| id.starts_with("truncated-"))
        }));
        assert!(gaps
            .iter()
            .filter(|gap| gap.source.starts_with("truncated-"))
            .all(|gap| gap.reason.contains("relation budget")));
    }
    #[test]
    fn correlation_output_budgets_bound_ambiguous_fanout() {
        let observations = (0..224)
            .map(|index| {
                observation(
                    &format!("origin-{index:03}-{}", "x".repeat(100_000)),
                    Some("HOST"),
                    &[(TimelineCorrelationKeyKind::ActivityId, "activity")],
                    &[],
                )
            })
            .collect::<Vec<_>>();

        let (edges, gaps) = correlate_observations(&observations);
        let candidate_bytes = edges
            .iter()
            .flat_map(|edge| edge.candidate_ids.iter())
            .fold(0usize, |total, value| total.saturating_add(value.len()));
        let serialized = serde_json::to_vec(&edges).expect("edges serialize");

        assert!(candidate_bytes <= MAX_CORRELATION_CANDIDATE_BYTES);
        assert!(serialized.len() <= MAX_CORRELATION_EDGE_BYTES * 2);
        assert!(gaps.iter().any(|gap| {
            gap.source == CORRELATION_GAP_TRUNCATION_SOURCE
                && (gap.reason == CORRELATION_CANDIDATE_BUDGET_REASON
                    || gap.reason == CORRELATION_EDGE_BUDGET_REASON)
        }));
    }

    #[test]
    fn related_activity_identity_matches_an_activity_identity_with_directional_evidence() {
        let observations = [
            observation(
                "producer",
                Some("HOST"),
                &[(TimelineCorrelationKeyKind::ActivityId, "activity-1")],
                &[],
            ),
            observation(
                "child",
                Some("HOST"),
                &[(TimelineCorrelationKeyKind::RelatedActivityId, "activity-1")],
                &[],
            ),
        ];

        let (edges, gaps) = correlate_observations(&observations);

        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].strength, TimelineCorrelationStrength::Exact);
        assert!(gaps.is_empty());
        assert_eq!(
            edges[0]
                .evidence
                .iter()
                .find(|evidence| evidence.origin_id == "child")
                .map(|evidence| evidence.field.as_str()),
            Some("relatedActivityId")
        );
    }

    #[test]
    fn provider_record_identity_is_scoped_to_source() {
        let mut first = event(1_000, "first", TimelineSeverity::Info);
        let mut second = event(2_000, "second", TimelineSeverity::Info);
        for (item, source) in [
            (&mut first, "capture-a.evtx"),
            (&mut second, "capture-b.evtx"),
        ] {
            if let TimelineOrigin::Event {
                stable_id,
                source: origin_source,
                ..
            } = &mut item.origin
            {
                *origin_source = source.to_string();
                *stable_id = format!("{source}/Application#1");
            }
        }

        let observations = [
            observation_from_origin(&first.origin),
            observation_from_origin(&second.origin),
        ];
        let (edges, _) = correlate_observations(&observations);

        assert!(edges.is_empty());
    }

    #[test]
    fn provider_record_identity_case_folds_windows_shaped_sources() {
        for (first_source, second_source) in [
            (r"C:\Captures\Capture.evtx", r"c:\captures\capture.evtx"),
            (
                r"\\Server\Share\Capture.evtx",
                r"\\server\share\capture.evtx",
            ),
            (r"Captures\Capture.evtx", r"captures\capture.evtx"),
        ] {
            let mut first = event(1_000, "first", TimelineSeverity::Info);
            let mut second = event(2_000, "second", TimelineSeverity::Info);
            for (item, source) in [(&mut first, first_source), (&mut second, second_source)] {
                if let TimelineOrigin::Event {
                    stable_id,
                    source: origin_source,
                    ..
                } = &mut item.origin
                {
                    *origin_source = source.to_string();
                    *stable_id = format!("{source}/Application#1");
                }
            }
            let observations = [
                observation_from_origin(&first.origin),
                observation_from_origin(&second.origin),
            ];

            let (edges, _) = correlate_observations(&observations);
            assert_eq!(edges.len(), 1, "{first_source} and {second_source}");
        }
    }

    #[test]
    fn provider_record_identity_preserves_unix_source_case() {
        let mut first = event(1_000, "first", TimelineSeverity::Info);
        let mut second = event(2_000, "second", TimelineSeverity::Info);
        for (item, source) in [
            (&mut first, "/captures/Capture.evtx"),
            (&mut second, "/captures/capture.evtx"),
        ] {
            if let TimelineOrigin::Event {
                stable_id,
                source: origin_source,
                ..
            } = &mut item.origin
            {
                *origin_source = source.to_string();
                *stable_id = format!("{source}/Application#1");
            }
        }
        let observations = [
            observation_from_origin(&first.origin),
            observation_from_origin(&second.origin),
        ];

        let (edges, _) = correlate_observations(&observations);
        assert!(edges.is_empty());
    }

    #[test]
    fn provider_record_identity_preserves_posix_double_slash_source_case() {
        let mut first = event(1_000, "first", TimelineSeverity::Info);
        let mut second = event(2_000, "second", TimelineSeverity::Info);
        for (item, source) in [
            (&mut first, "//captures/Capture.evtx"),
            (&mut second, "//captures/capture.evtx"),
        ] {
            if let TimelineOrigin::Event {
                stable_id,
                source: origin_source,
                ..
            } = &mut item.origin
            {
                *origin_source = source.to_string();
                *stable_id = format!("{source}/Application#1");
            }
        }
        let observations = [
            observation_from_origin(&first.origin),
            observation_from_origin(&second.origin),
        ];

        let (edges, _) = correlate_observations(&observations);
        assert!(edges.is_empty());
    }

    #[test]
    fn provider_record_identity_preserves_backslashes_inside_unix_sources() {
        let mut first = event(1_000, "first", TimelineSeverity::Info);
        let mut second = event(2_000, "second", TimelineSeverity::Info);
        for (item, source) in [
            (&mut first, r"/captures/Folder\Capture.evtx"),
            (&mut second, r"/captures/folder\capture.evtx"),
        ] {
            if let TimelineOrigin::Event {
                stable_id,
                source: origin_source,
                ..
            } = &mut item.origin
            {
                *origin_source = source.to_string();
                *stable_id = format!("{source}/Application#1");
            }
        }
        let observations = [
            observation_from_origin(&first.origin),
            observation_from_origin(&second.origin),
        ];

        let (edges, _) = correlate_observations(&observations);
        assert!(edges.is_empty());
    }

    #[test]
    fn conflicting_identity_aliases_cannot_form_exact_edges() {
        let mut first = event(1_000, "first", TimelineSeverity::Info);
        let mut second = event(2_000, "second", TimelineSeverity::Info);
        for (index, item) in [&mut first, &mut second].into_iter().enumerate() {
            if let TimelineOrigin::Event {
                stable_id,
                activity_id,
                record_id,
                record_id_text,
                identity_conflicts,
                ..
            } = &mut item.origin
            {
                *stable_id = format!("conflicting-activity-{index}");
                *activity_id = Some("same-activity".to_string());
                *identity_conflicts = vec!["activityId".to_string()];
                *record_id = 0;
                *record_id_text = None;
            }
        }
        let observations = [
            observation_from_origin(&first.origin),
            observation_from_origin(&second.origin),
        ];
        let (edges, gaps) = correlate_observations(&observations);

        assert!(edges.is_empty());
        assert!(gaps
            .iter()
            .any(|gap| gap.reason.contains("conflicting explicit identity aliases")));
    }

    #[test]
    fn malformed_process_start_is_rejected_with_a_coverage_gap() {
        let mut first = event(1_000, "first", TimelineSeverity::Info);
        let mut second = event(2_000, "second", TimelineSeverity::Info);
        for (index, item) in [&mut first, &mut second].into_iter().enumerate() {
            if let TimelineOrigin::Event {
                stable_id,
                process_id,
                process_start_time,
                record_id,
                record_id_text,
                ..
            } = &mut item.origin
            {
                *stable_id = format!("process-{index}");
                *process_id = Some(123);
                *process_start_time = Some("not-a-timestamp".to_string());
                *record_id = 0;
                *record_id_text = None;
            }
        }

        let observations = [
            observation_from_origin(&first.origin),
            observation_from_origin(&second.origin),
        ];
        let (edges, gaps) = correlate_observations(&observations);

        assert!(edges
            .iter()
            .all(|edge| edge.strength != TimelineCorrelationStrength::Exact));
        assert!(gaps.iter().any(|gap| gap.reason.contains("process start")));
    }

    #[test]
    fn valid_process_start_is_an_exact_pid_identity() {
        let mut first = event(1_000, "first", TimelineSeverity::Info);
        let mut second = event(2_000, "second", TimelineSeverity::Info);
        for (index, item) in [&mut first, &mut second].into_iter().enumerate() {
            if let TimelineOrigin::Event {
                stable_id,
                process_id,
                process_start_time,
                record_id,
                record_id_text,
                ..
            } = &mut item.origin
            {
                *stable_id = format!("valid-process-{index}");
                *process_id = Some(123);
                *process_start_time = Some(if index == 0 {
                    "2026-08-18T10:00:00Z".to_string()
                } else {
                    "2026-08-18T12:00:00+02:00".to_string()
                });
                *record_id = 0;
                *record_id_text = None;
            }
        }

        let observations = [
            observation_from_origin(&first.origin),
            observation_from_origin(&second.origin),
        ];
        let (edges, gaps) = correlate_observations(&observations);

        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].key.kind, TimelineCorrelationKeyKind::ProcessStart);
        assert_eq!(edges[0].key.value, "123|2026-08-18T10:00:00Z".to_string());
        assert!(gaps.is_empty());
    }

    #[test]
    fn edge_surfaces_endpoint_coverage_gap() {
        let mut first = observation(
            "a",
            Some("HOST"),
            &[(TimelineCorrelationKeyKind::ActivityId, "x")],
            &[],
        );
        first.coverage_gaps.push(TimelineCoverageGap {
            source: "a".to_string(),
            reason: "process start identity unavailable".to_string(),
        });
        let second = observation(
            "b",
            Some("HOST"),
            &[(TimelineCorrelationKeyKind::RelatedActivityId, "x")],
            &[],
        );

        let (edges, _) = correlate_observations(&[first, second]);

        assert_eq!(edges.len(), 1);
        assert_eq!(
            edges[0].coverage.state,
            TimelineCorrelationCoverageState::Gap
        );
        assert_eq!(
            edges[0]
                .coverage
                .gap
                .as_ref()
                .map(|gap| gap.reason.as_str()),
            Some("process start identity unavailable")
        );
    }

    #[test]
    fn process_id_without_process_start_is_neutral() {
        let mut first = event(1_000, "first", TimelineSeverity::Info);
        let mut second = event(2_000, "second", TimelineSeverity::Info);
        for (index, item) in [&mut first, &mut second].into_iter().enumerate() {
            if let TimelineOrigin::Event {
                stable_id,
                process_id,
                process_start_time,
                record_id,
                record_id_text,
                ..
            } = &mut item.origin
            {
                *stable_id = format!("missing-process-{index}");
                *process_id = Some(123);
                *process_start_time = None;
                *record_id = 0;
                *record_id_text = None;
            }
        }
        let observations = [
            observation_from_origin(&first.origin),
            observation_from_origin(&second.origin),
        ];
        let (edges, gaps) = correlate_observations(&observations);
        assert!(edges.is_empty());
        assert!(gaps.is_empty());
    }

    #[test]
    fn exact_activity_identity_requires_same_machine() {
        let observations = [
            observation(
                "a",
                Some("HOST-A"),
                &[(TimelineCorrelationKeyKind::ActivityId, "x")],
                &[],
            ),
            observation(
                "b",
                Some("host-a."),
                &[(TimelineCorrelationKeyKind::ActivityId, "x")],
                &[],
            ),
            observation(
                "c",
                Some("HOST-B"),
                &[(TimelineCorrelationKeyKind::ActivityId, "x")],
                &[],
            ),
        ];
        let (edges, gaps) = correlate_observations(&observations);
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].strength, TimelineCorrelationStrength::Exact);
        assert_eq!(edges[0].confidence, TimelineCorrelationConfidence::High);
        assert!(gaps.is_empty());
    }

    #[test]
    fn process_id_and_start_time_are_one_exact_key() {
        let observations = [
            observation(
                "a",
                Some("HOST"),
                &[(
                    TimelineCorrelationKeyKind::ProcessStart,
                    "123|2026-08-18t10:00:00z",
                )],
                &["process:123"],
            ),
            observation(
                "b",
                Some("HOST"),
                &[(
                    TimelineCorrelationKeyKind::ProcessStart,
                    "123|2026-08-18t10:00:00z",
                )],
                &["process:123"],
            ),
        ];
        let (edges, _) = correlate_observations(&observations);
        assert_eq!(edges[0].key.kind, TimelineCorrelationKeyKind::ProcessStart);
        assert_eq!(edges[0].strength, TimelineCorrelationStrength::Exact);
    }

    #[test]
    fn contradictory_exact_keys_remain_ambiguous_with_candidates() {
        let observations = [
            observation(
                "a",
                Some("HOST"),
                &[
                    (TimelineCorrelationKeyKind::ActivityId, "activity-a"),
                    (TimelineCorrelationKeyKind::SessionId, "session-a"),
                ],
                &[],
            ),
            observation(
                "b",
                Some("HOST"),
                &[(TimelineCorrelationKeyKind::ActivityId, "activity-a")],
                &[],
            ),
            observation(
                "c",
                Some("HOST"),
                &[(TimelineCorrelationKeyKind::SessionId, "session-a")],
                &[],
            ),
        ];
        let (edges, _) = correlate_observations(&observations);
        assert_eq!(edges.len(), 2);
        assert!(edges
            .iter()
            .all(|edge| edge.strength == TimelineCorrelationStrength::Ambiguous));
        assert!(edges
            .iter()
            .all(|edge| edge.candidate_ids.contains(&"b".to_string())
                || edge.candidate_ids.contains(&"c".to_string())));
    }

    #[test]
    fn timestamp_or_secondary_only_never_becomes_exact_causality() {
        let observations = [
            observation("a", Some("HOST"), &[], &["process:123"]),
            observation("b", Some("HOST"), &[], &["process:123"]),
        ];
        let (edges, gaps) = correlate_observations(&observations);
        assert_eq!(edges[0].strength, TimelineCorrelationStrength::Candidate);
        assert_eq!(edges[0].confidence, TimelineCorrelationConfidence::Low);
        assert!(gaps.iter().all(|gap| gap.reason.contains("secondary")));
    }

    #[test]
    fn known_machine_observation_without_identity_keys_is_neutral() {
        let observations = [observation("ordinary-event", Some("HOST"), &[], &[])];

        let (edges, gaps) = correlate_observations(&observations);

        assert!(edges.is_empty());
        assert!(gaps.is_empty());
    }

    #[test]
    fn unknown_machine_is_a_coverage_gap_not_a_match() {
        let observations = [
            observation(
                "a",
                Some("unknown"),
                &[(TimelineCorrelationKeyKind::ActivityId, "x")],
                &[],
            ),
            observation(
                "b",
                None,
                &[(TimelineCorrelationKeyKind::ActivityId, "x")],
                &[],
            ),
        ];
        let (edges, gaps) = correlate_observations(&observations);
        assert!(edges.is_empty());
        assert_eq!(gaps.len(), 2);
    }

    #[test]
    fn correlation_group_budget_reasons_are_capped() {
        assert_eq!(
            super::coverage_state(
                "exact ActivityId identity group exceeds the 64-member correlation limit"
            ),
            super::TimelineCoverageState::Capped
        );
        assert_eq!(
            super::coverage_state(
                "secondary identity group exceeds the 64-member correlation limit"
            ),
            super::TimelineCoverageState::Capped
        );
    }
}
