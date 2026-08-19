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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TimelineCorrelationStrength {
    Exact,
    Candidate,
    Ambiguous,
}

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

fn normalized_identity(value: &str) -> Option<String> {
    let value = value.trim().trim_end_matches('.');
    if value.is_empty()
        || matches!(
            value.to_ascii_lowercase().as_str(),
            "unknown" | "n/a" | "na" | "none" | "null" | "not available" | "not_applicable"
        )
    {
        return None;
    }
    Some(value.to_ascii_lowercase())
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


fn observation_from_origin(origin: &TimelineOrigin) -> TimelineCorrelationObservation {
    let (origin_id, machine, exact_keys, secondary_keys) = match origin {
        TimelineOrigin::Log { .. } => {
            let id = origin_id(origin);
            (id, None, Vec::new(), Vec::new())
        }
        TimelineOrigin::Event {
            stable_id,
            machine,
            provider,
            channel,
            process_id,
            activity_id,
            related_activity_id,
            session_id,
            device_id,
            user_id,
            process_start_time,
            event_id,
            record_id,
            record_id_text,
            ..
        } => {
            let mut exact_keys = Vec::new();
            let mut secondary_keys = Vec::new();
            let push_exact = |keys: &mut Vec<TimelineCorrelationKey>,
                              kind: TimelineCorrelationKeyKind,
                              value: Option<&str>| {
                if let Some(value) = value.and_then(normalized_identity) {
                    keys.push(TimelineCorrelationKey { kind, value });
                }
            };
            push_exact(
                &mut exact_keys,
                TimelineCorrelationKeyKind::ActivityId,
                activity_id.as_deref(),
            );
            push_exact(
                &mut exact_keys,
                TimelineCorrelationKeyKind::RelatedActivityId,
                related_activity_id.as_deref(),
            );
            push_exact(
                &mut exact_keys,
                TimelineCorrelationKeyKind::SessionId,
                session_id.as_deref(),
            );
            push_exact(
                &mut exact_keys,
                TimelineCorrelationKeyKind::DeviceId,
                device_id.as_deref(),
            );
            push_exact(
                &mut exact_keys,
                TimelineCorrelationKeyKind::UserId,
                user_id.as_deref(),
            );
            let record = usable_record_text(record_id_text.as_deref())
                .or_else(|| (*record_id != 0).then(|| record_id.to_string()));
            if let (Some(provider), Some(channel), Some(record)) = (
                normalized_identity(provider),
                normalized_identity(channel),
                record,
            ) {
                exact_keys.push(TimelineCorrelationKey {
                    kind: TimelineCorrelationKeyKind::ProviderChannelEventRecord,
                    value: format!(
                        "{}|{}|{}|{}",
                        key_part(&provider),
                        key_part(&channel),
                        event_id,
                        key_part(&record)
                    ),
                });
            }
            if let (Some(process_id), Some(start)) = (
                *process_id,
                process_start_time.as_deref().and_then(normalized_identity),
            ) {
                if process_id != 0 {
                    exact_keys.push(TimelineCorrelationKey {
                        kind: TimelineCorrelationKeyKind::ProcessStart,
                        value: format!("{process_id}|{start}"),
                    });
                }
            }
            if let Some(process_id) = (*process_id).filter(|value| *value != 0) {
                secondary_keys.push(TimelineCorrelationKey {
                    kind: TimelineCorrelationKeyKind::Secondary,
                    value: format!("process:{process_id}"),
                });
            }
            (
                stable_id.clone(),
                normalize_machine_identity(machine.as_deref()),
                exact_keys,
                secondary_keys,
            )
        }
    };
    TimelineCorrelationObservation {
        origin_id,
        machine,
        exact_keys,
        secondary_keys,
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
pub fn correlate_observations(
    observations: &[TimelineCorrelationObservation],
) -> (Vec<TimelineCorrelationEdge>, Vec<TimelineCoverageGap>) {
    use std::collections::{BTreeMap, BTreeSet};

    let mut ordered: Vec<_> = observations.iter().collect();
    ordered.sort_by(|left, right| left.origin_id.cmp(&right.origin_id));

    let mut exact_groups: BTreeMap<
        (String, TimelineCorrelationKeyKind, String),
        BTreeSet<String>,
    > = BTreeMap::new();
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
                .entry((machine.clone(), key.kind.clone(), key.value.clone()))
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
    for ((_, kind, value), ids) in &exact_groups {
        if ids.len() < 2 {
            continue;
        }
        let ids: Vec<_> = ids.iter().cloned().collect();
        for (left_index, left) in ids.iter().enumerate() {
            for right in ids.iter().skip(left_index + 1) {
                exact_candidates
                    .entry(left.clone())
                    .or_default()
                    .insert(right.clone());
                exact_candidates
                    .entry(right.clone())
                    .or_default()
                    .insert(left.clone());
                relation_keys
                    .entry((left.clone(), right.clone()))
                    .or_default()
                    .insert(TimelineCorrelationKey {
                        kind: kind.clone(),
                        value: value.clone(),
                    });
            }
        }
    }

    let mut candidate_relations: BTreeMap<Relation, BTreeSet<TimelineCorrelationKey>> =
        BTreeMap::new();
    for ((machine, value), ids) in &secondary_groups {
        if ids.len() < 2 {
            continue;
        }
        let ids: Vec<_> = ids.iter().cloned().collect();
        for (left_index, left) in ids.iter().enumerate() {
            if exact_candidates
                .get(left)
                .is_some_and(|candidates| !candidates.is_empty())
            {
                continue;
            }
            for right in ids.iter().skip(left_index + 1) {
                if exact_candidates
                    .get(right)
                    .is_some_and(|candidates| !candidates.is_empty())
                {
                    continue;
                }
                candidate_relations
                    .entry((left.clone(), right.clone()))
                    .or_default()
                    .insert(TimelineCorrelationKey {
                        kind: TimelineCorrelationKeyKind::Secondary,
                        value: format!("{machine}|{value}"),
                    });
            }
        }
    }

    let mut edges = Vec::new();
    for (relation, keys) in relation_keys
        .into_iter()
        .map(|(relation, keys)| (relation, (keys, true)))
        .chain(candidate_relations.into_iter().map(|(relation, keys)| (relation, (keys, false))))
    {
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
                    .find(|candidate| candidate.kind == key.kind && candidate.value == key.value)
                    .cloned()
                    .unwrap_or_else(|| key.clone());
                evidence.push(TimelineCorrelationEvidence {
                    origin_id: endpoint.clone(),
                    field: key_label(&matching.kind).to_string(),
                    value: matching.value,
                });
            }
        }
        let candidate_ids: Vec<_> = if ambiguous {
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
        edges.push(TimelineCorrelationEdge {
            id,
            from_id: left,
            to_id: Some(right),
            key,
            strength,
            confidence,
            candidate_ids,
            evidence,
            coverage: TimelineCorrelationCoverage::covered(),
        });
    }

    let mut gaps = Vec::new();
    for observation in ordered {
        if normalize_machine_identity(observation.machine.as_deref()).is_none() {
            gaps.push(TimelineCoverageGap {
                source: observation.origin_id.clone(),
                reason: "machine identity unavailable; exact correlation is restricted".to_string(),
            });
        } else if observation.exact_keys.is_empty() {
            gaps.push(TimelineCoverageGap {
                source: observation.origin_id.clone(),
                reason: if observation.secondary_keys.is_empty() {
                    "no explicit identity keys were present; timestamp-only correlation is not causal"
                        .to_string()
                } else {
                    "only secondary identity was present; correlation remains low confidence".to_string()
                },
            });
        }
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

fn bundle_from_source(source: &str) -> Option<String> {
    source
        .split(['/', '\\'])
        .find(|part| part.eq_ignore_ascii_case("bundle"))
        .map(str::to_string)
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
            event_id,
            record_id,
            record_id_text,
        } => format!(
            "event|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{event_id:010}|{record_id:020}|{record_text}",
            key_part(stable_id),
            key_part(source),
            optional_text_key(machine.as_deref()),
            optional_text_key(bundle.as_deref()),
            key_part(channel),
            key_part(provider),
            optional_number_key(*process_id),
            optional_text_key(activity_id.as_deref()),
            optional_text_key(related_activity_id.as_deref()),
            optional_text_key(session_id.as_deref()),
            optional_text_key(device_id.as_deref()),
            optional_text_key(user_id.as_deref()),
            optional_text_key(process_start_time.as_deref()),
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
    message: &str,
    origin: &TimelineOrigin,
) -> (i64, String, String) {
    (timestamp_ms, origin_sort_key(origin), message.to_string())
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
        timeline_sort_key(item.timestamp_ms, &item.message, &item.origin)
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
        assert_eq!(timeline.unplaced[0].reason, UnplacedReason::MissingTimestamp);
        assert!(!timeline.is_complete());
    }

    #[test]
    fn an_unplaced_item_still_says_where_it_came_from() {
        let timeline = from_log_entries(&[log_entry(None, "orphan", Severity::Error)]);
        match &timeline.unplaced[0].origin {
            TimelineOrigin::Log { file, line, component, .. } => {
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
        append(&mut timeline, &[log_entry(Some(1_000), "first", Severity::Info)]);

        let messages: Vec<&str> = timeline.items.iter().map(|item| item.message.as_str()).collect();
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
        append(&mut timeline, &[log_entry(None, "unplaced", Severity::Info)]);

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
        append(&mut timeline, &[log_entry(Some(5_000), "second", Severity::Info)]);
        append(&mut timeline, &[log_entry(Some(5_000), "first", Severity::Info)]);

        let messages: Vec<&str> = timeline.items.iter().map(|item| item.message.as_str()).collect();
        assert_eq!(messages, vec!["first", "second"]);
    }

    #[test]
    fn log_origin_does_not_treat_dhcp_client_name_as_machine_provenance() {
        let mut entry = log_entry(Some(1_000), "line", Severity::Info);
        entry.id = 99;
        entry.host_name = Some("LEASED-CLIENT".into());
        entry.source_file = Some("bundle/evidence/dhcp.log".into());
        let timeline = from_log_entries(&[entry]);

        match &timeline.items[0].origin {
            TimelineOrigin::Log {
                source,
                machine,
                bundle,
                record_id,
                ..
            } => {
                assert_eq!(source, "bundle/evidence/dhcp.log");
                assert_eq!(machine, &None);
                assert_eq!(bundle.as_deref(), Some("bundle"));
                assert_eq!(*record_id, 99);
            }
            other => panic!("expected a log origin, got {other:?}"),
        }
    }

    #[test]
    fn log_origin_keeps_physical_file_separate_from_parser_source_token() {
        let mut entry = log_entry(Some(1_000), "line", Severity::Info);
        entry.source_file = Some("store.cs:1".into());
        entry.file_path = "/bundle/evidence/ccm.log".into();
        let timeline = from_log_entries(&[entry]);

        match &timeline.items[0].origin {
            TimelineOrigin::Log { file, source, bundle, .. } => {
                assert_eq!(file, "/bundle/evidence/ccm.log");
                assert_eq!(source, "store.cs:1");
                assert_eq!(bundle.as_deref(), Some("bundle"));
            }
            other => panic!("expected a log origin, got {other:?}"),
        }
    }

    #[test]
    fn non_ccm_log_origin_uses_physical_file_when_no_source_token_exists() {
        let mut entry = log_entry(Some(1_000), "panther line", Severity::Info);
        entry.source_file = None;
        entry.file_path = "/logs/setupact.log".into();
        let timeline = from_log_entries(&[entry]);

        match &timeline.items[0].origin {
            TimelineOrigin::Log { file, source, bundle, .. } => {
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
        }
    }

    #[test]
    fn exact_activity_identity_requires_same_machine() {
        let observations = [
            observation("a", Some("HOST-A"), &[(TimelineCorrelationKeyKind::ActivityId, "x")], &[]),
            observation("b", Some("host-a."), &[(TimelineCorrelationKeyKind::ActivityId, "x")], &[]),
            observation("c", Some("HOST-B"), &[(TimelineCorrelationKeyKind::ActivityId, "x")], &[]),
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
                &[(TimelineCorrelationKeyKind::ProcessStart, "123|2026-08-18t10:00:00z")],
                &["process:123"],
            ),
            observation(
                "b",
                Some("HOST"),
                &[(TimelineCorrelationKeyKind::ProcessStart, "123|2026-08-18t10:00:00z")],
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
    fn unknown_machine_is_a_coverage_gap_not_a_match() {
        let observations = [
            observation("a", Some("unknown"), &[(TimelineCorrelationKeyKind::ActivityId, "x")], &[]),
            observation("b", None, &[(TimelineCorrelationKeyKind::ActivityId, "x")], &[]),
        ];
        let (edges, gaps) = correlate_observations(&observations);
        assert!(edges.is_empty());
        assert_eq!(gaps.len(), 2);
    }
}
