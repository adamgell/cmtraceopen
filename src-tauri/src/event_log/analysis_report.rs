//! The Markdown report of an event-log analysis session (spec 8.17, #851).
//!
//! The report is rendered by the backend from what the analysis session holds, so no record text
//! crosses IPC and reaches the file unredacted. Three rules shape this module:
//!
//! - **One writer, one gate.** [`safe::Doc`] only accepts [`safe::Safe`] values, and a `Safe` is
//!   minted from a string by exactly two functions. [`safe::Redactor::text`] takes text from the
//!   analysis session: it deletes the invisible characters, redacts, substitutes the known machine
//!   names, flattens, cuts and only then escapes Markdown. [`safe::Redactor::projected`] takes a
//!   [`safe::ProjectedText`], which can only be read out of a [`safe::Projected`] summary, one that
//!   had its invisible characters deleted and went through the diagnosis projection: it
//!   substitutes the known machine names, flattens, cuts and escapes. Everything else that reaches
//!   the document is a `'static` literal, a number, an enum word, a UTC time or a token, which is a
//!   hash of a name and never the name. A raw `&str` from the session cannot be printed because it
//!   does not type-check.
//! - **Evidence first.** Every sentence is a count the report holds or a statement of what was not
//!   loaded, scoped, read or capped. Nothing says one entry caused another.
//! - **Fail closed.** A report that exceeds [`MAX_REPORT_BYTES`], or that names a relation the
//!   session does not hold, is an error, never a silently shortened file.
//!
//! The session is the scope. It is built from the visible records, so the report describes what the
//! operator was looking at, identified by session id and revision.

use std::borrow::Cow;
use std::collections::{BTreeSet, HashMap, HashSet};

use cmtraceopen_parser::diagnosis::{
    adapt_timeline_edge, CorrelationEdge, CoverageGap, CoverageState, DiagnosisFinding,
    DiagnosisSummary, EventEvidenceRef, EvidenceRef, FindingClass, FindingConfidence,
    FindingSeverity, TextLogEvidenceRef,
};
use cmtraceopen_parser::unified_timeline::{
    origin_id, TimelineCorrelationCoverageState, TimelineCorrelationEdge,
    TimelineCorrelationKeyKind, TimelineCorrelationStrength, TimelineItem, TimelineOrigin,
    TimelineSeverity, UnifiedTimeline,
};
use serde::Deserialize;

use self::safe::{
    file_name, Doc, Projected, ProjectedText, Redactor, Safe, Within, MIN_SUBSTITUTED_MACHINE_CHARS,
};
use super::analysis_session::{
    EventLogAnalysisSessionStatus, REPORT_SESSION_CHANGED, TIMELINE_GAP_SOURCE_PREFIX,
    TIMELINE_TRANSPORT_PROJECTION_SOURCE,
};
use super::models::{EvtxCoverageGap, EvtxLevel};
use super::timeline::{
    MAX_TIMELINE_MESSAGE_BYTES, TIMELINE_ITEM_PROJECTION_SOURCE, TIMELINE_MESSAGE_PROJECTION_SOURCE,
};

/// The most bytes a rendered report may have. Over this the export fails.
pub(crate) const MAX_REPORT_BYTES: usize = 2 * 1024 * 1024;
/// Rows in the events table. The rest is counted, not listed.
pub(crate) const REPORT_EVENT_ROW_CAP: usize = 500;
/// Characters of a message cell, counted after redaction.
pub(crate) const REPORT_MESSAGE_CHARS: usize = 240;
/// Characters of a channel or provider cell, counted after redaction.
const REPORT_NAME_CHARS: usize = 120;
/// Characters of a finding's title, and of its summary and check texts, after redaction.
const REPORT_FINDING_TITLE_CHARS: usize = 160;
const REPORT_FINDING_TEXT_CHARS: usize = 1_000;
/// Characters of a coverage gap's detail, after redaction.
const REPORT_COVERAGE_DETAIL_CHARS: usize = 240;
/// Evidence references listed under a finding; the rest are counted.
const REPORT_FINDING_EVIDENCE_LABELS: usize = 3;
/// Machine tokens listed in the scope block.
const REPORT_MACHINE_CAP: usize = 10;
/// Channel names listed in the filter summary.
const REPORT_CHANNEL_NAMES_SHOWN: usize = 10;

/// Request bounds. The request carries ids, enums and numbers, so these only stop a malformed
/// caller from asking for an unbounded amount of work.
/// Chains listed, entry lines and evidence lines per chain. The rest are counted, not listed.
pub(crate) const REPORT_CHAIN_ROW_CAP: usize = 100;
const REPORT_CHAIN_MEMBER_LINES: usize = 12;
const REPORT_CHAIN_EVIDENCE_LINES: usize = 8;
const MAX_REPORT_CHAIN_MEMBER_IDS: usize = 50;
/// Pairs per chain row. A spanning set over the 50 members a row can list takes 49, so 64 leaves
/// room for the pairs that carry extra identifiers.
const MAX_REPORT_CHAIN_PAIRS: usize = 64;
const MAX_REPORT_PAIR_KEYS: usize = 16;
const MAX_REPORT_ID_BYTES: usize = 2 * 1024;
const MAX_REPORT_REQUEST_BYTES: usize = 8 * 1024 * 1024;
const MAX_REPORT_CHANNELS: usize = 64;
const MAX_REPORT_CHANNEL_BYTES: usize = 512;
const MAX_REPORT_EVENT_ID_SELECTORS: usize = 64;
const MAX_REPORT_TOP_EVENT_IDS: usize = 50;
const REPORT_LEVEL_COUNT: usize = 5;

/// What the app asks the backend to render. It names the session and carries only numbers, enum
/// words and the coverage gaps the rail was diagnosed with. No search text, quick-filter text,
/// scope title, chain title or record content can be sent: the request type has no field for them
/// and refuses unknown fields.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EventLogAnalysisReportRequest {
    pub session_id: String,
    /// The revision of the session the app was showing. A different revision is refused.
    pub expected_revision: u64,
    /// When the report was asked for. The renderer never reads the wall clock.
    pub generated_at_ms: i64,
    /// The merged coverage gaps the rail was diagnosed with, so the findings match the screen.
    #[serde(default)]
    pub coverage_gaps: Vec<EvtxCoverageGap>,
    pub scope: ReportScope,
    /// The chains the app built from the session's correlation edges, or `null` when it had not
    /// loaded them. Unknown is sent as `null`, never as an empty list.
    pub chains: Option<ReportChains>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ReportSourceMode {
    Files,
    Live,
}

/// What the session was built from, captured by the app when the session was published.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReportScope {
    pub source_mode: ReportSourceMode,
    /// Records the app holds, of every kind.
    pub loaded_record_count: u64,
    /// Event records the session was built from.
    pub event_record_count: u64,
    /// Archive text rows (log-origin records) the session was built from.
    pub archive_text_record_count: u64,
    /// Text-log entries given to the session.
    pub text_log_entry_count: u64,
    /// Counted by the app over the event records above, most severe first.
    pub level_mix: Vec<ReportLevelCount>,
    /// The most frequent event IDs among the event records above.
    pub top_event_ids: Vec<ReportEventIdCount>,
    /// Distinct event IDs among the event records above, when the app counted them.
    pub distinct_event_id_count: Option<u64>,
    pub filters: ReportFilters,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReportLevelCount {
    pub level: EvtxLevel,
    pub count: u64,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReportEventIdCount {
    pub event_id: u32,
    pub count: u64,
}

/// The filters in force when the session was built. Typed fields only: what the operator typed
/// is reported as "active" and never as text.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReportFilters {
    pub levels: Vec<EvtxLevel>,
    pub channels_selected: Vec<String>,
    pub channels_held: u64,
    pub event_id_selectors: Vec<ReportEventIdSelector>,
    pub time_window: ReportTimeWindow,
    pub time_range: Option<ReportTimeRange>,
    pub search_active: bool,
    pub quick_filter_active: bool,
    pub record_scope: Option<ReportRecordScopeKind>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum ReportEventIdSelector {
    Single { id: u32 },
    Range { low: u32, high: u32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum ReportTimeWindow {
    #[serde(rename = "1h")]
    LastHour,
    #[serde(rename = "24h")]
    Last24Hours,
    #[serde(rename = "7d")]
    Last7Days,
    #[serde(rename = "30d")]
    Last30Days,
    #[serde(rename = "all")]
    All,
}

/// A half-open span of event time: `start_ms` is inside it, `end_ms` is not.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReportTimeRange {
    pub start_ms: i64,
    pub end_ms: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ReportRecordScopeKind {
    Finding,
    Chain,
}

/// Chain structure by reference. The app reduces the session's correlation edges to chains; the
/// backend takes only the references (origin ids, and the identifier each relation rests on) and
/// confirms every one against the session's own edges before it prints anything.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReportChains {
    /// Correlation edges the app loaded to build the chains. The session knows how many it has.
    pub loaded_edge_count: u64,
    pub correlation_gaps: ReportCorrelationGaps,
    /// Chains per strength, before the app's row cap.
    pub counts: ReportChainCounts,
    /// The Exact and Candidate chains, in the app's order.
    pub rows: Vec<ReportChainRow>,
}

/// What the engine's correlation coverage gaps say about completeness, as the app classified them.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReportCorrelationGaps {
    /// A limit or truncation left some events uncorrelated.
    pub global: bool,
    /// Not every gap was shown to the app, so which events are affected cannot be told.
    pub preview_cut: bool,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReportChainCounts {
    pub exact: u64,
    pub candidate: u64,
    pub ambiguous: u64,
    pub coverage_blocked: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ReportLinkStrength {
    Exact,
    Candidate,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReportChainRow {
    pub strength: ReportLinkStrength,
    /// Every member of the chain as the app's model counts it, listed or not.
    pub member_count: u64,
    /// Origin ids of the members the app listed, at most [`MAX_REPORT_CHAIN_MEMBER_IDS`]. Each is
    /// printed only if it is the end of one of this row's `pairs`, and each appears once.
    pub member_ids: Vec<String>,
    /// The reduced pairs the chain is made of, at most [`MAX_REPORT_CHAIN_PAIRS`]. A row without
    /// a pair is refused, and so is a listed member that no pair ends at. The app therefore picks
    /// its pairs as a spanning forest over the members it lists first, then any pairs that carry
    /// further identifiers, up to the cap.
    pub pairs: Vec<ReportChainPair>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReportChainPair {
    pub left: String,
    pub right: String,
    pub keys: Vec<ReportKeyRef>,
}

/// The identifier a relation rests on. Used to find the session's edge, never printed from here.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReportKeyRef {
    pub kind: TimelineCorrelationKeyKind,
    pub value: String,
}

impl EventLogAnalysisReportRequest {
    /// Refuses a request that cannot be true. Errors name the field, never its content.
    pub(crate) fn validate(&self) -> Result<(), String> {
        let scope = &self.scope;
        let events = scope.event_record_count;
        if scope.level_mix.len() > REPORT_LEVEL_COUNT {
            return Err("report scope: too many level counts".to_owned());
        }
        for (index, entry) in scope.level_mix.iter().enumerate() {
            if scope.level_mix[..index]
                .iter()
                .any(|earlier| earlier.level == entry.level)
            {
                return Err("report scope: a level is counted twice".to_owned());
            }
        }
        if scope
            .level_mix
            .iter()
            .try_fold(0u64, |sum, entry| {
                sum.checked_add(entry.count)
                    .filter(|total| *total <= events)
            })
            .is_none()
        {
            return Err("report scope: level counts exceed the events in scope".to_owned());
        }
        if scope.top_event_ids.len() > MAX_REPORT_TOP_EVENT_IDS {
            return Err("report scope: too many event ID counts".to_owned());
        }
        for (index, entry) in scope.top_event_ids.iter().enumerate() {
            if scope.top_event_ids[..index]
                .iter()
                .any(|earlier| earlier.event_id == entry.event_id)
            {
                return Err("report scope: an event ID is counted twice".to_owned());
            }
        }
        if scope
            .top_event_ids
            .iter()
            .try_fold(0u64, |sum, entry| {
                sum.checked_add(entry.count)
                    .filter(|total| *total <= events)
            })
            .is_none()
        {
            return Err("report scope: event ID counts exceed the events in scope".to_owned());
        }
        if let Some(distinct) = scope.distinct_event_id_count {
            let listed = u64::try_from(scope.top_event_ids.len()).unwrap_or(u64::MAX);
            if distinct > events || distinct < listed {
                return Err("report scope: the distinct event ID count is impossible".to_owned());
            }
        }
        let filters = &scope.filters;
        if filters.levels.len() > REPORT_LEVEL_COUNT {
            return Err("report filters: too many levels".to_owned());
        }
        if filters.channels_selected.len() > MAX_REPORT_CHANNELS
            || filters
                .channels_selected
                .iter()
                .any(|name| name.len() > MAX_REPORT_CHANNEL_BYTES)
        {
            return Err("report filters: a channel list is too large".to_owned());
        }
        if filters.event_id_selectors.len() > MAX_REPORT_EVENT_ID_SELECTORS
            || filters.event_id_selectors.iter().any(|selector| {
                matches!(selector, ReportEventIdSelector::Range { low, high } if low > high)
            })
        {
            return Err("report filters: the event ID selectors are impossible".to_owned());
        }
        if filters
            .time_range
            .is_some_and(|range| range.start_ms > range.end_ms)
        {
            return Err("report filters: the time range ends before it starts".to_owned());
        }
        if let Some(chains) = &self.chains {
            validate_chains(chains)?;
        }
        Ok(())
    }
}

fn validate_chains(chains: &ReportChains) -> Result<(), String> {
    if chains.rows.len() > REPORT_CHAIN_ROW_CAP {
        return Err("report chains: too many chain rows".to_owned());
    }
    let exact = chains
        .rows
        .iter()
        .filter(|row| row.strength == ReportLinkStrength::Exact)
        .count() as u64;
    let candidate = chains.rows.len() as u64 - exact;
    if exact > chains.counts.exact || candidate > chains.counts.candidate {
        return Err("report chains: more rows than chains counted".to_owned());
    }
    let mut bytes = 0usize;
    let mut measure = |text: &str| -> Result<(), String> {
        if text.len() > MAX_REPORT_ID_BYTES {
            return Err("report chains: an identifier is too long".to_owned());
        }
        bytes = bytes.saturating_add(text.len());
        Ok(())
    };
    for row in &chains.rows {
        if row.member_ids.len() > MAX_REPORT_CHAIN_MEMBER_IDS
            || row.pairs.len() > MAX_REPORT_CHAIN_PAIRS
        {
            return Err("report chains: a chain lists too many references".to_owned());
        }
        if row.member_count < row.member_ids.len() as u64 {
            return Err(MEMBER_COUNT_BELOW_LISTED.to_owned());
        }
        for id in &row.member_ids {
            measure(id)?;
        }
        for pair in &row.pairs {
            if pair.left == pair.right
                || pair.keys.is_empty()
                || pair.keys.len() > MAX_REPORT_PAIR_KEYS
            {
                return Err("report chains: a pair is impossible".to_owned());
            }
            measure(&pair.left)?;
            measure(&pair.right)?;
            for key in &pair.keys {
                measure(&key.value)?;
            }
        }
    }
    if bytes > MAX_REPORT_REQUEST_BYTES {
        return Err("report chains: the references are too large".to_owned());
    }
    Ok(())
}

/// What the backend gathered from the session for one report, under the session lock.
pub(crate) struct ReportSnapshot {
    /// The session's own counts: placed events and text lines, edges, coverage gaps.
    pub status: EventLogAnalysisSessionStatus,
    /// The first [`REPORT_EVENT_ROW_CAP`] placed event items, oldest first.
    pub event_rows: Vec<TimelineItem>,
    /// Events the session could not place because they carry no usable timestamp.
    pub unplaced_events: u64,
    /// Text lines the session could not place for the same reason.
    pub unplaced_text_lines: u64,
    /// First and last placed timestamp of any kind of item.
    pub span_ms: Option<(i64, i64)>,
    /// Every machine name an origin in the session carries.
    pub machines: BTreeSet<String>,
    /// What the engine recorded about shortening what it holds.
    pub engine_notes: EngineNotes,
    /// The entries the chains name, by origin id: members and the origins of evidence rows.
    pub entries: HashMap<String, Entry>,
    /// One per chain row of the request, in the same order.
    pub chains: Vec<ResolvedChain>,
}

/// A timeline entry the report looked up by origin id.
#[derive(Debug, Clone)]
pub(crate) enum Entry {
    Placed(Box<TimelineItem>),
    /// In the session's unplaced list: it carries no usable timestamp.
    Unplaced,
}

/// The session's own edges behind one chain row, each confirmed to exist.
#[derive(Debug, Clone, Default)]
pub(crate) struct ResolvedChain {
    pub edges: Vec<TimelineCorrelationEdge>,
}

const UNKNOWN_RELATION: &str =
    "the report names a correlation relation the analysis session does not hold";
const NOT_A_LINK: &str =
    "a report chain contains a relation the engine labels ambiguous or coverage blocked";
const WEAKER_THAN_EXACT: &str =
    "an Exact report chain rests on a relation the engine does not label Exact";
const MEMBER_COUNT_BELOW_LISTED: &str = "report chains: a chain lists more members than it has";

fn ordered<'a>(left: &'a str, right: &'a str) -> (&'a str, &'a str) {
    if left <= right {
        (left, right)
    } else {
        (right, left)
    }
}

/// Confirms each reference of each chain against the session's edges, and looks up the entries the
/// chains name. A reference the session does not hold is an error: the report never prints a link
/// the engine did not produce, and never prints one the engine calls ambiguous or blocked.
pub(crate) fn collect_chains(
    timeline: &UnifiedTimeline,
    chains: &ReportChains,
) -> Result<(Vec<ResolvedChain>, HashMap<String, Entry>), String> {
    let mut by_pair: HashMap<(&str, &str), Vec<usize>> = HashMap::new();
    for (index, edge) in timeline.edges.iter().enumerate() {
        if let Some(to) = edge.to_id.as_deref() {
            by_pair
                .entry(ordered(&edge.from_id, to))
                .or_default()
                .push(index);
        }
    }
    let mut resolved = Vec::with_capacity(chains.rows.len());
    let mut wanted: HashSet<&str> = HashSet::new();
    for row in &chains.rows {
        let mut picked: Vec<usize> = Vec::new();
        for pair in &row.pairs {
            let candidates = by_pair
                .get(&ordered(&pair.left, &pair.right))
                .map_or(&[][..], Vec::as_slice);
            for key in &pair.keys {
                let index = candidates
                    .iter()
                    .copied()
                    .find(|&index| {
                        let edge = &timeline.edges[index];
                        edge.key.kind == key.kind && edge.key.value == key.value
                    })
                    .ok_or_else(|| UNKNOWN_RELATION.to_owned())?;
                confirm_link(row.strength, &timeline.edges[index])?;
                if !picked.contains(&index) {
                    picked.push(index);
                }
            }
        }
        confirm_members(row)?;
        picked.sort_unstable();
        wanted.extend(row.member_ids.iter().map(String::as_str));
        let mut edges = Vec::with_capacity(picked.len());
        for index in picked {
            let edge = &timeline.edges[index];
            wanted.extend(edge.evidence.iter().map(|row| row.origin_id.as_str()));
            edges.push(edge.clone());
        }
        resolved.push(ResolvedChain { edges });
    }
    Ok((resolved, look_up_entries(timeline, &wanted)))
}

/// A chain prints a member only when its own pairs confirm it: the row must carry a pair, and each
/// member it lists, once, must be the end of one of them. The pairs themselves are confirmed
/// against the session's edges before this runs, so an unknown pair is refused for being unknown.
/// A row that fails this is a builder bug, or a model the session has moved past, so it is
/// refused with the run-again message and names no id.
fn confirm_members(row: &ReportChainRow) -> Result<(), String> {
    if row.pairs.is_empty() {
        return Err(REPORT_SESSION_CHANGED.to_owned());
    }
    let ends: HashSet<&str> = row
        .pairs
        .iter()
        .flat_map(|pair| [pair.left.as_str(), pair.right.as_str()])
        .collect();
    let mut listed: HashSet<&str> = HashSet::with_capacity(row.member_ids.len());
    for id in &row.member_ids {
        if !ends.contains(id.as_str()) || !listed.insert(id.as_str()) {
            return Err(REPORT_SESSION_CHANGED.to_owned());
        }
    }
    Ok(())
}

/// Gathers what one report needs from a finalized session, in one pass over its timeline. Chain
/// references are confirmed against the session's edges first, so a report that names a relation
/// the session does not hold fails before anything is read.
pub(crate) fn collect(
    timeline: &UnifiedTimeline,
    status: EventLogAnalysisSessionStatus,
    request: &EventLogAnalysisReportRequest,
) -> Result<ReportSnapshot, String> {
    let (chains, entries) = match &request.chains {
        Some(chains) => collect_chains(timeline, chains)?,
        None => (Vec::new(), HashMap::new()),
    };
    let mut machines = BTreeSet::new();
    let mut event_rows = Vec::with_capacity(REPORT_EVENT_ROW_CAP.min(timeline.items.len()));
    for item in &timeline.items {
        note_machine(&mut machines, &item.origin);
        if event_rows.len() < REPORT_EVENT_ROW_CAP
            && matches!(item.origin, TimelineOrigin::Event { .. })
        {
            event_rows.push(item.clone());
        }
    }
    let (mut unplaced_events, mut unplaced_text_lines) = (0u64, 0u64);
    for unplaced in &timeline.unplaced {
        note_machine(&mut machines, &unplaced.origin);
        if matches!(unplaced.origin, TimelineOrigin::Event { .. }) {
            unplaced_events += 1;
        } else {
            unplaced_text_lines += 1;
        }
    }
    let has_gap = |source: &str| {
        timeline
            .coverage_gaps
            .iter()
            .any(|gap| gap.source == source)
    };
    Ok(ReportSnapshot {
        status,
        event_rows,
        unplaced_events,
        unplaced_text_lines,
        span_ms: timeline.span_ms(),
        machines,
        engine_notes: EngineNotes {
            messages_shortened: has_gap(TIMELINE_MESSAGE_PROJECTION_SOURCE),
            items_compacted: has_gap(TIMELINE_ITEM_PROJECTION_SOURCE),
            transport_projected: has_gap(TIMELINE_TRANSPORT_PROJECTION_SOURCE),
        },
        entries,
        chains,
    })
}

fn note_machine(machines: &mut BTreeSet<String>, origin: &TimelineOrigin) {
    let machine = match origin {
        TimelineOrigin::Event { machine, .. } | TimelineOrigin::Log { machine, .. } => machine,
        _ => return,
    };
    if let Some(machine) = machine.as_deref().map(str::trim).filter(|m| !m.is_empty()) {
        machines.insert(machine.to_owned());
    }
}

fn confirm_link(
    strength: ReportLinkStrength,
    edge: &TimelineCorrelationEdge,
) -> Result<(), String> {
    let linking = matches!(
        edge.strength,
        TimelineCorrelationStrength::Exact | TimelineCorrelationStrength::Candidate
    ) && matches!(
        edge.coverage.state,
        TimelineCorrelationCoverageState::Covered
    );
    if !linking {
        return Err(NOT_A_LINK.to_owned());
    }
    if strength == ReportLinkStrength::Exact
        && (!matches!(edge.strength, TimelineCorrelationStrength::Exact)
            || edge.key.kind == TimelineCorrelationKeyKind::Secondary)
    {
        return Err(WEAKER_THAN_EXACT.to_owned());
    }
    Ok(())
}

/// The origin id the engine's edges use for this origin, without copying an event's.
fn origin_key(origin: &TimelineOrigin) -> Cow<'_, str> {
    match origin {
        TimelineOrigin::Event { stable_id, .. } => Cow::Borrowed(stable_id),
        other => Cow::Owned(origin_id(other)),
    }
}

fn look_up_entries(timeline: &UnifiedTimeline, wanted: &HashSet<&str>) -> HashMap<String, Entry> {
    let mut entries = HashMap::new();
    if wanted.is_empty() {
        return entries;
    }
    for item in &timeline.items {
        let key = origin_key(&item.origin);
        if wanted.contains(key.as_ref()) {
            entries
                .entry(key.into_owned())
                .or_insert_with(|| Entry::Placed(Box::new(item.clone())));
        }
    }
    for unplaced in &timeline.unplaced {
        let key = origin_key(&unplaced.origin);
        if wanted.contains(key.as_ref()) {
            entries.entry(key.into_owned()).or_insert(Entry::Unplaced);
        }
    }
    entries
}

/// Facts about the timeline's own compaction. The engine records these as timeline coverage gaps
/// whose reasons carry counts only, and the diagnosis leaves them out, so the report states them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct EngineNotes {
    /// Some event messages were shortened to stay inside the message budget.
    pub messages_shortened: bool,
    /// Some timeline items had oversized list-view fields compacted.
    pub items_compacted: bool,
    /// Some rows were reduced in transport before the session read them.
    pub transport_projected: bool,
}

pub(crate) struct ReportInput<'a> {
    pub request: &'a EventLogAnalysisReportRequest,
    pub snapshot: &'a ReportSnapshot,
    /// The session's diagnosis. It may already be projected; the renderer projects it again at its
    /// own boundary, so a caller cannot hand it an unprojected summary by mistake.
    pub summary: &'a DiagnosisSummary,
}

/// Renders the report, or fails: a report over [`MAX_REPORT_BYTES`] is an error, not a shorter file.
pub(crate) fn render_report(input: &ReportInput<'_>) -> Result<String, String> {
    render_report_within(input, MAX_REPORT_BYTES)
}

fn render_report_within(input: &ReportInput<'_>, limit: usize) -> Result<String, String> {
    let request = input.request;
    let snapshot = input.snapshot;
    let redactor = Redactor::new(&snapshot.machines);
    let summary = Projected::new(input.summary.clone())?;
    let mut doc = Doc::new();
    render_title(&mut doc);
    render_scope(&mut doc, &redactor, request, snapshot);
    render_coverage(&mut doc, &redactor, snapshot, &summary);
    render_findings(&mut doc, &redactor, &summary);
    render_chains(&mut doc, &redactor, request, snapshot)?;
    render_nearby(&mut doc);
    render_top_event_ids(&mut doc, &request.scope);
    render_level_mix(&mut doc, &request.scope);
    render_events(&mut doc, &redactor, snapshot);
    doc.finish(limit)
}

fn render_title(doc: &mut Doc) {
    doc.lit("# Event Logs report").nl().nl();
    doc.lit(
        "> Values that match known patterns, and machine names recorded by the events in this \
         report, are replaced by tokens such as [host:0123456789abcdef]. Free text can still \
         contain identifiers that no pattern recognizes, for example a computer name inside a \
         sentence, an account name after a label such as Account Name, a bare tenant ID or a \
         folder name in a path. Review this file before sharing it.",
    )
    .nl()
    .nl();
    doc.lit(
        "All times are UTC (ISO 8601). The app's time zone setting does not change this report.",
    )
    .nl()
    .nl();
}

fn render_scope(
    doc: &mut Doc,
    redactor: &Redactor,
    request: &EventLogAnalysisReportRequest,
    snapshot: &ReportSnapshot,
) {
    let scope = &request.scope;
    let status = &snapshot.status;
    doc.lit("## Scope and coverage").nl().nl();
    doc.lit("- Generated: ")
        .safe(&Safe::utc(request.generated_at_ms))
        .nl();
    match scope.source_mode {
        ReportSourceMode::Files => doc.lit("- Source: opened files").nl(),
        ReportSourceMode::Live => doc
            .lit(
                "- Source: live channels. Events keep arriving, so this report describes the \
                 events in the analysis session when it was made, not later events.",
            )
            .nl(),
    };
    render_machines(doc, redactor, snapshot);
    match snapshot.span_ms {
        Some((first, last)) => doc
            .lit("- Observed span of placed entries: ")
            .safe(&Safe::utc(first))
            .lit(" to ")
            .safe(&Safe::utc(last))
            .nl(),
        None => doc
            .lit(
                "- Observed span of placed entries: no entry in the session has a usable timestamp",
            )
            .nl(),
    };
    doc.lit("- Records loaded in the app: ")
        .count(scope.loaded_record_count)
        .nl();
    doc.lit("- Events in scope (counted by the app): ")
        .count(scope.event_record_count)
        .nl();
    doc.lit("- Events placed on the timeline (counted by the session): ")
        .count(status.event_items)
        .nl();
    doc.lit("- Events in scope without a usable timestamp, not placed and not listed below: ")
        .count(snapshot.unplaced_events)
        .nl();
    let session_events = status.event_items.saturating_add(snapshot.unplaced_events);
    if session_events != scope.event_record_count {
        doc.lit("- The session holds ")
            .count(session_events)
            .lit(" events and the app counted ")
            .count(scope.event_record_count)
            .lit(" in scope. The two counts are shown as each side reported them.")
            .nl();
    }
    doc.lit("- Archive text rows in scope (counted by the app): ")
        .count(scope.archive_text_record_count)
        .nl();
    doc.lit("- Text-log entries given to the session (counted by the app): ")
        .count(scope.text_log_entry_count)
        .nl();
    doc.lit("- Text lines placed on the timeline (counted by the session): ")
        .count(status.log_items)
        .nl();
    doc.lit("- Text lines without a usable timestamp, not placed: ")
        .count(snapshot.unplaced_text_lines)
        .nl();
    let in_scope = scope
        .event_record_count
        .saturating_add(scope.archive_text_record_count);
    if in_scope < scope.loaded_record_count {
        doc.lit(
            "- The session covers fewer records than the app has loaded, so links and strengths \
             are computed over the events in scope only. Events outside the scope can make an \
             Exact link ambiguous.",
        )
        .nl();
        if scope.text_log_entry_count > 0 {
            doc.lit("- Text logs are not scoped.").nl();
        }
    }
    render_filters(doc, redactor, &scope.filters);
    doc.nl();
}

fn render_machines(doc: &mut Doc, redactor: &Redactor, snapshot: &ReportSnapshot) {
    let mut tokens: Vec<Safe> = snapshot
        .machines
        .iter()
        .map(|name| redactor.machine(name))
        .collect();
    tokens.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    tokens.dedup();
    if tokens.is_empty() {
        let entries = snapshot
            .status
            .total_items
            .saturating_add(snapshot.unplaced_events)
            .saturating_add(snapshot.unplaced_text_lines);
        doc.lit(if entries == 0 {
            "- Machines: the session holds no entries"
        } else {
            "- Machines: no entry in the session records a machine name"
        })
        .nl();
    } else {
        doc.lit("- Machines (")
            .count(tokens.len() as u64)
            .lit("): ");
        for (index, token) in tokens.iter().take(REPORT_MACHINE_CAP).enumerate() {
            if index > 0 {
                doc.lit(", ");
            }
            doc.safe(token);
        }
        if tokens.len() > REPORT_MACHINE_CAP {
            doc.lit(" and ")
                .count((tokens.len() - REPORT_MACHINE_CAP) as u64)
                .lit(" more");
        }
        doc.nl();
    }
    if redactor.skipped_short() > 0 {
        doc.lit("- Machine names shorter than ")
            .count(MIN_SUBSTITUTED_MACHINE_CHARS as u64)
            .lit(" characters, not searched for in free text: ")
            .count(redactor.skipped_short() as u64)
            .nl();
    }
}

fn render_filters(doc: &mut Doc, redactor: &Redactor, filters: &ReportFilters) {
    doc.lit("- Filters when the session was built:").nl();
    doc.lit("  - Levels: ");
    if filters.levels.len() == REPORT_LEVEL_COUNT {
        doc.lit("all");
    } else if filters.levels.is_empty() {
        doc.lit("none selected");
    } else {
        for (index, level) in filters.levels.iter().enumerate() {
            if index > 0 {
                doc.lit(", ");
            }
            doc.lit(level_word(*level));
        }
    }
    doc.nl();
    doc.lit("  - Channels: ")
        .count(filters.channels_selected.len() as u64)
        .lit(" of ")
        .count(filters.channels_held)
        .lit(" loaded channels selected");
    if !filters.channels_selected.is_empty() {
        doc.lit(": ");
        for (index, name) in filters
            .channels_selected
            .iter()
            .take(REPORT_CHANNEL_NAMES_SHOWN)
            .enumerate()
        {
            if index > 0 {
                doc.lit(", ");
            }
            doc.safe(&redactor.text(name, REPORT_NAME_CHARS));
        }
        if filters.channels_selected.len() > REPORT_CHANNEL_NAMES_SHOWN {
            doc.lit(" and ")
                .count((filters.channels_selected.len() - REPORT_CHANNEL_NAMES_SHOWN) as u64)
                .lit(" more");
        }
    }
    doc.nl();
    doc.lit("  - Event IDs: ");
    if filters.event_id_selectors.is_empty() {
        doc.lit("not filtered");
    }
    for (index, selector) in filters.event_id_selectors.iter().enumerate() {
        if index > 0 {
            doc.lit(", ");
        }
        match selector {
            ReportEventIdSelector::Single { id } => doc.count(u64::from(*id)),
            ReportEventIdSelector::Range { low, high } => doc
                .count(u64::from(*low))
                .lit(" to ")
                .count(u64::from(*high)),
        };
    }
    doc.nl();
    doc.lit("  - Time window: ")
        .lit(match filters.time_window {
            ReportTimeWindow::LastHour => "last hour",
            ReportTimeWindow::Last24Hours => "last 24 hours",
            ReportTimeWindow::Last7Days => "last 7 days",
            ReportTimeWindow::Last30Days => "last 30 days",
            ReportTimeWindow::All => "all time",
        })
        .nl();
    doc.lit("  - Brushed time range: ");
    match filters.time_range {
        Some(range) => doc
            .safe(&Safe::utc(range.start_ms))
            .lit(" to ")
            .safe(&Safe::utc(range.end_ms))
            .lit(" (start included, end excluded)"),
        None => doc.lit("none"),
    };
    doc.nl();
    doc.lit("  - Text search: ")
        .lit(if filters.search_active {
            "active (its text is not included in this report)"
        } else {
            "not active"
        })
        .nl();
    doc.lit("  - Quick filter: ")
        .lit(if filters.quick_filter_active {
            "active (its text is not included in this report)"
        } else {
            "not active"
        })
        .nl();
    doc.lit("  - Record scope: ")
        .lit(match filters.record_scope {
            Some(ReportRecordScopeKind::Finding) => {
                "limited to the events one finding cites (its title is not included)"
            }
            Some(ReportRecordScopeKind::Chain) => {
                "limited to the events one chain contains (its title is not included)"
            }
            None => "none",
        })
        .nl();
}

fn render_coverage(
    doc: &mut Doc,
    redactor: &Redactor,
    snapshot: &ReportSnapshot,
    projected: &Projected,
) {
    let summary = projected.summary();
    doc.lit("## Coverage and limits").nl().nl();
    let (timeline_gaps, listed): (Vec<Within<CoverageGap>>, Vec<Within<CoverageGap>>) = projected
        .root()
        .each(|summary| &summary.coverage_gaps)
        .partition(|gap| gap.get().source.starts_with(TIMELINE_GAP_SOURCE_PREFIX));
    if listed.is_empty() {
        doc.lit(if timeline_gaps.is_empty() {
            "- The engine listed no coverage gap. A channel that was not loaded or not selected \
             is not a gap and does not appear here."
        } else {
            "- The engine listed no coverage gap other than the timeline gaps below."
        })
        .nl();
    } else {
        doc.lit("- Coverage gaps the engine listed (")
            .count(listed.len() as u64)
            .lit("):")
            .nl();
        // The engine can list the same gap once per event it affects. A gap that repeats is
        // written once with its count, in the order it first appears. Two gaps are the same gap
        // only when their source, state and detail are the same as the engine wrote them, so
        // two files that print alike are still two lines.
        let mut lines: Vec<((&str, &str, &str), Safe, u64)> = Vec::new();
        for gap in &listed {
            let (source, detail) = (gap.text(|g| &g.source), gap.text(|g| &g.detail));
            let state = coverage_state_word(gap.get().state);
            let key = (source.as_str(), state, detail.as_str());
            if let Some((_, _, count)) = lines.iter_mut().find(|(known, _, _)| *known == key) {
                *count += 1;
                continue;
            }
            let line = Safe::join(&[
                Safe::literal(state),
                Safe::literal(": "),
                coverage_source(redactor, source),
                Safe::literal(": "),
                redactor.projected(detail, REPORT_COVERAGE_DETAIL_CHARS),
            ]);
            lines.push((key, line, 1));
        }
        for (_, line, count) in &lines {
            doc.lit("  - ").safe(line);
            if *count > 1 {
                doc.lit(" (").count(*count).lit(" gaps)");
            }
            doc.nl();
        }
    }
    if !timeline_gaps.is_empty() {
        doc.lit("- Correlation and timeline coverage gaps: ")
            .count(timeline_gaps.len() as u64)
            .lit(" (");
        let mut counts: Vec<(&'static str, u64)> = Vec::new();
        for gap in &timeline_gaps {
            let word = coverage_state_word(gap.get().state);
            match counts.iter_mut().find(|(known, _)| *known == word) {
                Some((_, count)) => *count += 1,
                None => counts.push((word, 1)),
            }
        }
        counts.sort_unstable();
        for (index, (word, count)) in counts.iter().enumerate() {
            if index > 0 {
                doc.lit(", ");
            }
            doc.lit(word).lit(" ").count(*count);
        }
        doc.lit(
            "). Their details name individual events, so they are counted here and not listed.",
        )
        .nl();
    }
    let sent = summary.coverage_gaps.len() as u64;
    let counted = summary.overview.coverage_gap_count as u64;
    if counted != sent {
        doc.lit("- The engine counted ")
            .count(counted)
            .lit(" coverage gaps and sent ")
            .count(sent)
            .lit(" of them: its response is bounded.")
            .nl();
    }
    let notes = snapshot.engine_notes;
    if notes.messages_shortened {
        doc.lit("- The engine shortened some event messages to stay inside its message budget.")
            .nl();
    }
    if notes.items_compacted {
        doc.lit(
            "- The engine compacted oversized list-view fields of some timeline items; the full \
             records stay in the event grid.",
        )
        .nl();
    }
    if notes.transport_projected {
        doc.lit(
            "- Some rows were reduced before the session read them, so omitted identity or \
             derived fields may limit correlation.",
        )
        .nl();
    }
    doc.nl();
}

fn render_findings(doc: &mut Doc, redactor: &Redactor, projected: &Projected) {
    let summary = projected.summary();
    doc.lit("## Findings").nl().nl();
    doc.lit("Engine summary: ")
        .safe(&redactor.projected(
            projected.root().text(|summary| &summary.overview.headline),
            REPORT_FINDING_TEXT_CHARS,
        ))
        .nl()
        .nl();
    let mut actionable: Vec<Within<DiagnosisFinding>> = projected
        .root()
        .each(|summary| &summary.findings)
        .filter(|finding| !matches!(finding.get().class, FindingClass::CoverageGap))
        .collect();
    actionable.sort_by(|left, right| {
        let (left, right) = (left.get(), right.get());
        right
            .severity
            .cmp(&left.severity)
            .then_with(|| confidence_rank(right.confidence).cmp(&confidence_rank(left.confidence)))
    });
    let counted = summary.overview.actionable_finding_count as u64;
    let listed = actionable.len() as u64;
    if listed == 0 && counted == 0 {
        doc.lit("The engine reported no actionable findings in the events it read.");
        if !summary.coverage_gaps.is_empty() {
            doc.lit(" Coverage gaps listed above limit what that means.");
        }
        doc.nl().nl();
    } else if listed == counted {
        doc.lit("The engine reported ")
            .count(counted)
            .lit(" actionable findings.")
            .nl()
            .nl();
    } else {
        doc.lit("The engine counted ")
            .count(counted)
            .lit(" actionable findings and sent ")
            .count(listed)
            .lit(" of them: its response is bounded.")
            .nl()
            .nl();
    }
    for finding in actionable {
        render_finding(doc, redactor, finding);
    }
}

fn render_finding(doc: &mut Doc, redactor: &Redactor, projected: Within<DiagnosisFinding>) {
    let finding = projected.get();
    doc.lit("### ")
        .safe(&redactor.projected(projected.text(|f| &f.title), REPORT_FINDING_TITLE_CHARS))
        .nl()
        .nl();
    doc.lit("- Class: ")
        .lit(finding_class_word(finding.class))
        .lit("; severity: ")
        .lit(finding_severity_word(finding.severity))
        .lit("; confidence: ")
        .lit(finding_confidence_word(finding.confidence))
        .nl();
    doc.lit("- Summary: ")
        .safe(&redactor.projected(projected.text(|f| &f.summary), REPORT_FINDING_TEXT_CHARS))
        .nl();
    if !finding.evidence.is_empty() {
        doc.lit("- Evidence: ");
        for (index, evidence) in projected
            .each(|f| &f.evidence)
            .take(REPORT_FINDING_EVIDENCE_LABELS)
            .enumerate()
        {
            if index > 0 {
                doc.lit("; ");
            }
            write_evidence_label(doc, redactor, evidence);
        }
        if finding.evidence.len() > REPORT_FINDING_EVIDENCE_LABELS {
            doc.lit("; and ")
                .count((finding.evidence.len() - REPORT_FINDING_EVIDENCE_LABELS) as u64)
                .lit(" more");
        }
        doc.nl();
    }
    if let Some(first) = projected.maybe_text(|f| f.recommended_checks.first().map(String::as_str))
    {
        doc.lit("- Recommended check: ")
            .safe(&redactor.projected(first, REPORT_FINDING_TEXT_CHARS));
        if finding.recommended_checks.len() > 1 {
            doc.lit("; and ")
                .count((finding.recommended_checks.len() - 1) as u64)
                .lit(" more checks");
        }
        doc.nl();
    }
    doc.nl();
}

/// How an evidence reference names its record, without the source path or the machine.
fn write_evidence_label(doc: &mut Doc, redactor: &Redactor, evidence: Within<EvidenceRef>) {
    if let Some(projected) = evidence.variant(event_variant) {
        let event = projected.get();
        doc.count(u64::from(event.event_id)).lit(" \u{b7} ");
        let place = projected.text(|e| e.channel.as_deref().unwrap_or(&e.provider));
        doc.safe(&redactor.projected(place, REPORT_NAME_CHARS))
            .lit(" \u{b7} ");
        let numbered = projected
            .maybe_text(|e| e.record_id_text.as_deref())
            .filter(|text| text.as_str().chars().any(|digit| digit != '0'));
        if let Some(text) = numbered {
            doc.lit("record ").safe(&redactor.projected(text, 40));
        } else if let Some(fallback) = projected
            .maybe_text(|e| e.fallback_identity.as_deref())
            .filter(|fallback| !fallback.as_str().is_empty())
        {
            doc.lit("ref ")
                .safe(&redactor.projected(fallback.first_chars(8), 16));
        } else if event.record_id != 0 {
            doc.lit("record ").count(event.record_id);
        } else {
            doc.lit("no record ID");
        }
    } else if let Some(projected) = evidence.variant(text_log_variant) {
        doc.safe(&redactor.projected(
            projected.text(|log| &log.file_path).file_name(),
            REPORT_NAME_CHARS,
        ))
        .lit(" \u{b7} line ")
        .count(u64::from(projected.get().line_number));
    } else {
        doc.lit("a source-specific evidence reference");
    }
}

fn event_variant(evidence: &EvidenceRef) -> Option<&EventEvidenceRef> {
    match evidence {
        EvidenceRef::Event(event) => Some(event),
        _ => None,
    }
}

fn text_log_variant(evidence: &EvidenceRef) -> Option<&TextLogEvidenceRef> {
    match evidence {
        EvidenceRef::TextLog(log) => Some(log),
        _ => None,
    }
}

/// Windows' classic logs have no provider part. Behind a remote host they read `host/Security`,
/// and no provider channel ends this way (`Provider/Operational` always has a provider).
const CLASSIC_CHANNELS: [&str; 9] = [
    "application",
    "security",
    "setup",
    "system",
    "forwardedevents",
    "hardwareevents",
    "windows powershell",
    "internet explorer",
    "key management service",
];

/// How a coverage gap names its source, so that two sources that differ never print alike:
///
/// - A file path shows its file name.
/// - A live channel shows its whole name (`Microsoft-Windows-AAD/Operational`): its last segment
///   alone is the same for every provider's Operational channel.
/// - A remote query names its channel behind the host (`HOST/Microsoft-Windows-AAD/Operational`,
///   `HOST/Security`). The host is written as a machine token, never as it was. Where a host and a
///   provider cannot be told apart (`HOST/Custom Channel`), only a host the session knows is
///   replaced, like any machine name in text.
fn coverage_source(redactor: &Redactor, source: ProjectedText<'_>) -> Safe {
    let text = source.as_str();
    if is_file_path(text) {
        return redactor.projected(source.file_name(), REPORT_NAME_CHARS);
    }
    if let Some((host, channel)) = source.split_once('/') {
        let behind_a_host = channel.as_str().contains('/')
            || CLASSIC_CHANNELS.contains(&channel.as_str().to_ascii_lowercase().as_str());
        if behind_a_host {
            return Safe::join(&[
                redactor.machine(host),
                Safe::literal("/"),
                redactor.projected(channel, REPORT_NAME_CHARS),
            ]);
        }
    }
    redactor.projected(source, REPORT_NAME_CHARS)
}

/// A Windows path, a rooted path, or a name whose last segment has a file extension. A channel
/// has none of the three: it uses `/` but never a backslash, is never rooted, and does not end
/// in `.ext`.
fn is_file_path(source: &str) -> bool {
    source.contains('\\') || source.starts_with('/') || has_file_extension(file_name(source))
}

/// A short suffix after the last dot: `System.evtx`, `Sync.log`, `Export.jsonl`.
fn has_file_extension(name: &str) -> bool {
    name.rsplit_once('.')
        .is_some_and(|(_, extension)| (1..=5).contains(&extension.len()))
}

fn confidence_rank(confidence: FindingConfidence) -> u8 {
    match confidence {
        FindingConfidence::High => 3,
        FindingConfidence::Medium => 2,
        FindingConfidence::Low => 1,
        _ => 0,
    }
}

fn finding_class_word(class: FindingClass) -> &'static str {
    match class {
        FindingClass::ConfirmedFailure => "confirmed failure",
        FindingClass::LikelyContributor => "likely contributor",
        FindingClass::Symptom => "symptom",
        FindingClass::Recovered => "recovered",
        FindingClass::ContradictoryEvidence => "contradictory evidence",
        FindingClass::CoverageGap => "coverage gap",
        FindingClass::Unknown => "unknown",
        _ => "unclassified",
    }
}

fn finding_severity_word(severity: FindingSeverity) -> &'static str {
    match severity {
        FindingSeverity::Info => "info",
        FindingSeverity::Warning => "warning",
        FindingSeverity::Error => "error",
        FindingSeverity::Critical => "critical",
        _ => "unclassified",
    }
}

fn finding_confidence_word(confidence: FindingConfidence) -> &'static str {
    match confidence {
        FindingConfidence::Unknown => "unknown",
        FindingConfidence::Low => "low",
        FindingConfidence::Medium => "medium",
        FindingConfidence::High => "high",
        _ => "unclassified",
    }
}

fn coverage_state_word(state: CoverageState) -> &'static str {
    match state {
        CoverageState::Covered => "covered",
        CoverageState::Unknown => "unknown",
        CoverageState::Absent => "absent",
        CoverageState::AccessDenied => "access denied",
        CoverageState::Capped => "capped",
        CoverageState::Skipped => "skipped",
        CoverageState::Unsupported => "unsupported",
        CoverageState::Malformed => "malformed",
        CoverageState::ParseFailed => "parse failed",
        CoverageState::ProviderDescriptionUnavailable => "provider description unavailable",
        _ => "other",
    }
}

fn render_chains(
    doc: &mut Doc,
    redactor: &Redactor,
    request: &EventLogAnalysisReportRequest,
    snapshot: &ReportSnapshot,
) -> Result<(), String> {
    doc.lit("## Correlation chains").nl().nl();
    let Some(chains) = &request.chains else {
        doc.lit(
            "Correlation chains were not loaded when this report was made. Chains may exist; \
             none are listed here, and that says nothing about whether any exist.",
        )
        .nl()
        .nl();
        return Ok(());
    };
    if snapshot.chains.len() != chains.rows.len() {
        return Err("the report's chain references were not resolved".to_owned());
    }
    let total_edges = snapshot.status.total_edges;
    let edges_complete = chains.loaded_edge_count == total_edges;
    let gaps_clear = !(chains.correlation_gaps.global || chains.correlation_gaps.preview_cut);
    let complete = edges_complete && gaps_clear;
    let counts = chains.counts;
    let linking = counts.exact.saturating_add(counts.candidate);

    doc.lit(
        "Chains are built from exact or candidate shared identifiers on one machine. Time \
             alone never links two entries. Exact: every link rests on an exact shared \
             identifier. Candidate: at least one link rests on a weaker identifier.",
    )
    .nl()
    .nl();
    doc.lit("- Chains listed: ")
        .count(chains.rows.len() as u64)
        .lit(" of ")
        .count(linking)
        .lit(" Exact or Candidate chains the app built (Exact ")
        .count(counts.exact)
        .lit(", Candidate ")
        .count(counts.candidate)
        .lit(").");
    if (chains.rows.len() as u64) < linking {
        doc.lit(" The app lists at most ")
            .count(REPORT_CHAIN_ROW_CAP as u64)
            .lit(" chains; ")
            .count(linking - chains.rows.len() as u64)
            .lit(" are not listed.");
    }
    doc.nl();
    if edges_complete {
        doc.lit("- Built from all ")
            .count(total_edges)
            .lit(" correlation edges of the events in scope.")
            .nl();
    } else if chains.loaded_edge_count < total_edges {
        doc.lit("- Built from ")
            .count(chains.loaded_edge_count)
            .lit(" of ")
            .count(total_edges)
            .lit(" correlation edges (")
            .count(total_edges - chains.loaded_edge_count)
            .lit(" not loaded), so more chains may exist.")
            .nl();
    } else {
        doc.lit("- The app reported ")
            .count(chains.loaded_edge_count)
            .lit(" loaded correlation edges and the session holds ")
            .count(total_edges)
            .lit(", so this list cannot be trusted as complete.")
            .nl();
    }
    if !gaps_clear {
        doc.lit(
            "- The engine did not correlate every event (it hit a limit or truncated its \
             output), or not every correlation gap was shown, so a chain may be missing.",
        )
        .nl();
    }
    if linking == 0 {
        if complete {
            doc.lit(
                "- The engine produced no Exact or Candidate link among the events in scope. \
                 Events outside the scope were not considered.",
            )
            .nl();
        } else {
            doc.lit(
                "- No Exact or Candidate chain is listed. The correlation input is incomplete, \
                 so this does not show that none exist.",
            )
            .nl();
        }
    }
    doc.lit(if complete {
        "- Not listed as chains (counts only): "
    } else {
        "- Not listed as chains (counts only, at least): "
    })
    .count(counts.ambiguous)
    .lit(" Ambiguous and ")
    .count(counts.coverage_blocked)
    .lit(" Coverage blocked relations.")
    .nl()
    .nl();

    let adapted: Vec<CorrelationEdge> = snapshot
        .chains
        .iter()
        .flat_map(|chain| chain.edges.iter().map(adapt_timeline_edge))
        .collect();
    let projected = Projected::new(DiagnosisSummary {
        correlations: adapted,
        ..DiagnosisSummary::default()
    })?;
    let edges: Vec<Within<CorrelationEdge>> = projected
        .root()
        .each(|summary| &summary.correlations)
        .collect();
    let mut cursor = 0usize;
    for (index, (row, resolved)) in chains.rows.iter().zip(&snapshot.chains).enumerate() {
        let projected_edges = &edges[cursor..cursor + resolved.edges.len()];
        cursor += resolved.edges.len();
        render_chain(
            doc,
            &ChainContext { redactor, snapshot },
            index as u64 + 1,
            row,
            resolved,
            projected_edges,
        )?;
    }
    Ok(())
}

/// What every chain is rendered with.
struct ChainContext<'a> {
    redactor: &'a Redactor,
    snapshot: &'a ReportSnapshot,
}

fn render_chain(
    doc: &mut Doc,
    context: &ChainContext<'_>,
    number: u64,
    row: &ReportChainRow,
    resolved: &ResolvedChain,
    projected_edges: &[Within<CorrelationEdge>],
) -> Result<(), String> {
    let ChainContext { redactor, snapshot } = *context;
    let mut supplied: Vec<&str> = row.member_ids.iter().map(String::as_str).collect();
    supplied.sort_unstable();
    supplied.dedup();
    let listed = supplied.len() as u64;
    let not_listed = row
        .member_count
        .checked_sub(listed)
        .ok_or_else(|| MEMBER_COUNT_BELOW_LISTED.to_owned())?;
    doc.lit("### Chain ")
        .count(number)
        .lit(": ")
        .lit(match row.strength {
            ReportLinkStrength::Exact => "Exact",
            ReportLinkStrength::Candidate => "Candidate",
        })
        .lit(", ")
        .count(listed)
        .lit(" entries")
        .nl()
        .nl();
    if not_listed > 0 {
        doc.lit("The chain model counts ")
            .count(row.member_count)
            .lit(" entries in all; ")
            .count(not_listed)
            .lit(" are not listed.")
            .nl()
            .nl();
    }
    let mut placed: Vec<&TimelineItem> = Vec::new();
    let (mut unplaced, mut unknown) = (0u64, 0u64);
    for id in &supplied {
        match snapshot.entries.get(*id) {
            Some(Entry::Placed(item)) => placed.push(item.as_ref()),
            Some(Entry::Unplaced) => unplaced += 1,
            None => unknown += 1,
        }
    }
    placed.sort_by_key(|item| item.timestamp_ms);
    doc.lit("- Entries listed: ")
        .count(listed)
        .lit(". Of those, ")
        .count(placed.len() as u64)
        .lit(" are on the placed timeline, ")
        .count(unplaced)
        .lit(" have no usable timestamp and ")
        .count(unknown)
        .lit(" are not in this session.")
        .nl();
    match (placed.first(), placed.last()) {
        (Some(first), Some(last)) => {
            doc.lit("- Span of the listed entries on the timeline: ")
                .safe(&Safe::utc(first.timestamp_ms))
                .lit(" to ")
                .safe(&Safe::utc(last.timestamp_ms))
                .nl();
        }
        _ => {
            doc.lit("- No listed entry has a usable timestamp.").nl();
        }
    }
    let mut kinds: Vec<&'static str> = resolved
        .edges
        .iter()
        .map(|edge| key_word(&edge.key.kind))
        .collect();
    kinds.sort_unstable();
    kinds.dedup();
    doc.lit("- Links rest on: ");
    for (position, kind) in kinds.iter().enumerate() {
        if position > 0 {
            doc.lit(", ");
        }
        doc.lit(kind);
    }
    doc.nl();

    let mut lines: Vec<Safe> = Vec::new();
    for (edge, projected_edge) in resolved.edges.iter().zip(projected_edges) {
        for (raw, safe_row) in edge
            .evidence
            .iter()
            .zip(projected_edge.each(|e| &e.evidence))
        {
            let line = evidence_line(
                redactor,
                snapshot,
                &raw.origin_id,
                &raw.field,
                safe_row.text(|row| &row.value),
            );
            if !lines.contains(&line) {
                lines.push(line);
            }
        }
    }
    if lines.is_empty() {
        doc.lit("- Link evidence: none was available for the references the app listed.")
            .nl();
    } else {
        doc.lit("- Link evidence (")
            .count(lines.len() as u64)
            .lit(" lines):")
            .nl();
        for line in lines.iter().take(REPORT_CHAIN_EVIDENCE_LINES) {
            doc.lit("  - ").safe(line).nl();
        }
        if lines.len() > REPORT_CHAIN_EVIDENCE_LINES {
            doc.lit("  - and ")
                .count((lines.len() - REPORT_CHAIN_EVIDENCE_LINES) as u64)
                .lit(" more evidence lines")
                .nl();
        }
    }
    doc.nl();
    if placed.is_empty() {
        return Ok(());
    }
    doc.lit(ITEM_TABLE_HEADER).nl();
    doc.lit(ITEM_TABLE_RULE).nl();
    for item in placed.iter().take(REPORT_CHAIN_MEMBER_LINES) {
        write_item_row(doc, redactor, item);
    }
    if placed.len() > REPORT_CHAIN_MEMBER_LINES {
        doc.nl()
            .lit("and ")
            .count((placed.len() - REPORT_CHAIN_MEMBER_LINES) as u64)
            .lit(" more listed entries on the timeline, not shown here")
            .nl();
    }
    doc.nl();
    Ok(())
}

/// How the report names an entry: an event by ID, channel and record, a text-log line by its
/// file's last path segment and line. Never by origin id, which names a machine and a path.
fn entry_label(redactor: &Redactor, entry: Option<&Entry>) -> Safe {
    match entry {
        Some(Entry::Placed(item)) => match &item.origin {
            TimelineOrigin::Event {
                event_id,
                channel,
                record_id,
                record_id_text,
                ..
            } => {
                let record = record_id_text
                    .clone()
                    .unwrap_or_else(|| record_id.to_string());
                Safe::join(&[
                    Safe::count(u64::from(*event_id)),
                    Safe::literal(" \u{b7} "),
                    redactor.text(channel, REPORT_NAME_CHARS),
                    Safe::literal(" \u{b7} record "),
                    redactor.text(&record, 40),
                ])
            }
            TimelineOrigin::Log { file, line, .. } => Safe::join(&[
                redactor.text(file_name(file), REPORT_NAME_CHARS),
                Safe::literal(" \u{b7} line "),
                Safe::count(u64::from(*line)),
            ]),
            _ => Safe::literal("an entry of a kind this report does not name"),
        },
        Some(Entry::Unplaced) => Safe::literal("an entry with no usable timestamp"),
        None => Safe::literal("an entry that is not in this session"),
    }
}

/// One line of link evidence. The identifier's value is printed only for the kinds that are
/// correlation ids, as a token for the kinds that identify a person or a device, and never for
/// the kinds whose value holds a source path. A kind this build does not know prints no value.
fn evidence_line(
    redactor: &Redactor,
    snapshot: &ReportSnapshot,
    origin: &str,
    field: &str,
    projected_value: ProjectedText<'_>,
) -> Safe {
    let label = entry_label(redactor, snapshot.entries.get(origin));
    let Some(kind) = field_kind(field) else {
        return Safe::join(&[label, Safe::literal(": an identifier (value not printed)")]);
    };
    let word = Safe::literal(key_word(&kind));
    match value_policy(&kind) {
        ValuePolicy::Print => Safe::join(&[
            label,
            Safe::literal(": "),
            word,
            Safe::literal(" = "),
            redactor.projected(projected_value, REPORT_NAME_CHARS),
        ]),
        ValuePolicy::Token => {
            let shown = projected_value.as_str();
            let value = if safe::token_len_at(shown, 0) == Some(shown.len()) {
                redactor.projected(projected_value, REPORT_NAME_CHARS)
            } else {
                Safe::literal("(masked)")
            };
            Safe::join(&[
                label,
                Safe::literal(": "),
                word,
                Safe::literal(" = "),
                value,
            ])
        }
        ValuePolicy::Withheld => Safe::join(&[
            label,
            Safe::literal(": "),
            word,
            Safe::literal(" (value not printed)"),
        ]),
    }
}

enum ValuePolicy {
    /// A correlation id or a process start: printed after redaction.
    Print,
    /// Identifies a device or a person: printed only if the projection reduced it to a token.
    Token,
    /// Its value holds a source path, or this build does not know the kind.
    Withheld,
}

fn value_policy(kind: &TimelineCorrelationKeyKind) -> ValuePolicy {
    match kind {
        TimelineCorrelationKeyKind::ActivityId
        | TimelineCorrelationKeyKind::RelatedActivityId
        | TimelineCorrelationKeyKind::SessionId
        | TimelineCorrelationKeyKind::ProcessStart => ValuePolicy::Print,
        TimelineCorrelationKeyKind::DeviceId | TimelineCorrelationKeyKind::UserId => {
            ValuePolicy::Token
        }
        _ => ValuePolicy::Withheld,
    }
}

/// An evidence row's `field` is the engine's label for a key kind, which is the kind's own serde
/// name, so the parser's enum is the one list of them.
fn field_kind(field: &str) -> Option<TimelineCorrelationKeyKind> {
    serde_json::from_value(serde_json::Value::String(field.to_owned())).ok()
}

fn key_word(kind: &TimelineCorrelationKeyKind) -> &'static str {
    match kind {
        TimelineCorrelationKeyKind::ActivityId => "ActivityId",
        TimelineCorrelationKeyKind::RelatedActivityId => "RelatedActivityId",
        TimelineCorrelationKeyKind::ProviderChannelEventRecord => "provider, channel and record",
        TimelineCorrelationKeyKind::ProcessStart => "process start",
        TimelineCorrelationKeyKind::SessionId => "SessionId",
        TimelineCorrelationKeyKind::DeviceId => "DeviceId",
        TimelineCorrelationKeyKind::UserId => "UserId",
        TimelineCorrelationKeyKind::Secondary => "secondary identifier",
        _ => "identifier",
    }
}

fn render_nearby(doc: &mut Doc) {
    doc.lit("## Nearby, not linked").nl().nl();
    doc.lit(
        "Nearby context is not produced in this version of the report. This section says \
         nothing about whether nearby events exist, and nothing in this report links two \
         entries by time alone.",
    )
    .nl()
    .nl();
}

fn render_top_event_ids(doc: &mut Doc, scope: &ReportScope) {
    doc.lit("## Top event IDs").nl().nl();
    if scope.event_record_count == 0 {
        doc.lit("No events are in scope.").nl().nl();
        return;
    }
    doc.lit("Counted by the app over the ")
        .count(scope.event_record_count)
        .lit(" events in scope. ");
    match scope.distinct_event_id_count {
        Some(distinct) => doc
            .lit("Top ")
            .count(scope.top_event_ids.len() as u64)
            .lit(" of ")
            .count(distinct)
            .lit(" distinct event IDs."),
        None => doc
            .lit("Top ")
            .count(scope.top_event_ids.len() as u64)
            .lit(" event IDs; the number of distinct IDs was not counted."),
    };
    doc.nl().nl();
    doc.lit("| Event ID | Events |").nl();
    doc.lit("| --- | --- |").nl();
    for entry in &scope.top_event_ids {
        doc.lit("| ")
            .count(u64::from(entry.event_id))
            .lit(" | ")
            .count(entry.count)
            .lit(" |")
            .nl();
    }
    doc.nl();
}

fn render_level_mix(doc: &mut Doc, scope: &ReportScope) {
    doc.lit("## Level mix").nl().nl();
    if scope.event_record_count == 0 {
        doc.lit("No events are in scope.").nl().nl();
        return;
    }
    doc.lit("| Level | Events |").nl();
    doc.lit("| --- | --- |").nl();
    let mut counted = 0u64;
    for entry in &scope.level_mix {
        counted = counted.saturating_add(entry.count);
        doc.lit("| ")
            .lit(level_word(entry.level))
            .lit(" | ")
            .count(entry.count)
            .lit(" |")
            .nl();
    }
    doc.nl();
    if counted != scope.event_record_count {
        doc.lit("The level counts cover ")
            .count(counted)
            .lit(" of the ")
            .count(scope.event_record_count)
            .lit(" events in scope.")
            .nl()
            .nl();
    }
}

fn render_events(doc: &mut Doc, redactor: &Redactor, snapshot: &ReportSnapshot) {
    doc.lit("## Events").nl().nl();
    let placed = snapshot.status.event_items;
    if placed == 0 {
        doc.lit("No event in scope is placed on the timeline.")
            .nl()
            .nl();
        return;
    }
    doc.lit("Events are listed in time order, oldest first, from the session's timeline. Messages are shortened to ")
        .count(REPORT_MESSAGE_CHARS as u64)
        .lit(" characters after redaction, and the engine already shortens messages over ")
        .count((MAX_TIMELINE_MESSAGE_BYTES / 1024) as u64)
        .lit(" KiB.")
        .nl()
        .nl();
    let listed = snapshot.event_rows.len().min(REPORT_EVENT_ROW_CAP);
    let listed_count = listed as u64;
    if listed_count >= placed {
        doc.lit("All ")
            .count(placed)
            .lit(" placed events are listed.");
    } else {
        doc.lit("Showing the first ")
            .count(listed_count)
            .lit(" of ")
            .count(placed)
            .lit(" placed events; ")
            .count(placed - listed_count)
            .lit(" omitted.");
    }
    doc.nl().nl();
    doc.lit(ITEM_TABLE_HEADER).nl();
    doc.lit(ITEM_TABLE_RULE).nl();
    for item in snapshot.event_rows.iter().take(REPORT_EVENT_ROW_CAP) {
        write_item_row(doc, redactor, item);
    }
    doc.nl();
}

const ITEM_TABLE_HEADER: &str = "| Time (UTC) | Level | ID | Channel | Provider | Message |";
const ITEM_TABLE_RULE: &str = "| --- | --- | --- | --- | --- | --- |";

/// One timeline item as a table row: an event by its ID, channel and provider, a text-log line by
/// its file's last path segment and its line number.
fn write_item_row(doc: &mut Doc, redactor: &Redactor, item: &TimelineItem) {
    doc.lit("| ")
        .safe(&Safe::utc(item.timestamp_ms))
        .lit(" | ")
        .lit(severity_word(item.severity))
        .lit(" | ");
    match &item.origin {
        TimelineOrigin::Event {
            event_id,
            channel,
            provider,
            ..
        } => {
            doc.count(u64::from(*event_id))
                .lit(" | ")
                .safe(&redactor.text(channel, REPORT_NAME_CHARS))
                .lit(" | ")
                .safe(&redactor.text(provider, REPORT_NAME_CHARS));
        }
        TimelineOrigin::Log {
            file,
            component,
            line,
            ..
        } => {
            doc.lit("log line ")
                .count(u64::from(*line))
                .lit(" | ")
                .safe(&redactor.text(file_name(file), REPORT_NAME_CHARS))
                .lit(" | ")
                .safe(&redactor.text(component.as_deref().unwrap_or(""), REPORT_NAME_CHARS));
        }
        _ => {
            doc.lit("n/a | n/a | n/a");
        }
    }
    doc.lit(" | ")
        .safe(&redactor.text(&item.message, REPORT_MESSAGE_CHARS))
        .lit(" |")
        .nl();
}

fn level_word(level: EvtxLevel) -> &'static str {
    match level {
        EvtxLevel::Critical => "Critical",
        EvtxLevel::Error => "Error",
        EvtxLevel::Warning => "Warning",
        EvtxLevel::Information => "Information",
        EvtxLevel::Verbose => "Verbose",
    }
}

fn severity_word(severity: TimelineSeverity) -> &'static str {
    match severity {
        TimelineSeverity::Critical => "Critical",
        TimelineSeverity::Error => "Error",
        TimelineSeverity::Warning => "Warning",
        TimelineSeverity::Info => "Information",
        TimelineSeverity::Verbose => "Verbose",
    }
}

mod safe;

#[cfg(test)]
mod tests;
