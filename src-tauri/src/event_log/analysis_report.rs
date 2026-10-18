//! The Markdown report of an event-log analysis session (spec 8.17, #851).
//!
//! The report is rendered by the backend from what the analysis session holds, so no record text
//! crosses IPC and reaches the file unredacted. Three rules shape this module:
//!
//! - **One writer, one gate.** [`safe::Doc`] only accepts [`safe::Safe`] values. A `Safe` is minted
//!   from a raw string by exactly one function, [`safe::Redactor::text`], which redacts, substitutes
//!   known machine names, flattens, cuts and only then escapes Markdown. Everything else that
//!   reaches the document is a `'static` literal, a number, an enum word or a machine token. A raw
//!   `&str` from the session cannot be printed because it does not type-check.
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
    DiagnosisSummary, EvidenceRef, FindingClass, FindingConfidence, FindingSeverity,
};
use cmtraceopen_parser::unified_timeline::{
    origin_id, TimelineCorrelationCoverageState, TimelineCorrelationEdge,
    TimelineCorrelationKeyKind, TimelineCorrelationStrength, TimelineItem, TimelineOrigin,
    TimelineSeverity, UnifiedTimeline,
};
use serde::Deserialize;

use self::safe::{Doc, Projected, Redactor, Safe, MIN_SUBSTITUTED_MACHINE_CHARS};
use super::analysis_session::{
    EventLogAnalysisSessionStatus, TIMELINE_GAP_SOURCE_PREFIX, TIMELINE_TRANSPORT_PROJECTION_SOURCE,
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
const MAX_REPORT_CHAIN_PAIRS: usize = 20;
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
    /// Every member of the chain, resolved or not.
    pub member_count: u64,
    /// Origin ids of the members the app listed, at most [`MAX_REPORT_CHAIN_MEMBER_IDS`].
    pub member_ids: Vec<String>,
    /// The reduced pairs the chain is made of, at most [`MAX_REPORT_CHAIN_PAIRS`].
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
            return Err("report chains: a chain lists more members than it has".to_owned());
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
    let summary = Projected::new(input.summary.clone());
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
        "> Values that match known patterns, and machine names found in the loaded events, are \
         replaced by tokens such as [host:0123456789abcdef]. Free text can still contain \
         identifiers that no pattern recognizes, for example a computer name inside a sentence, \
         an account name after a label such as Account Name, a bare tenant ID or a folder name \
         in a path. Review this file before sharing it.",
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
    let (timeline_gaps, listed): (Vec<&CoverageGap>, Vec<&CoverageGap>) = summary
        .coverage_gaps
        .iter()
        .partition(|gap| gap.source.starts_with(TIMELINE_GAP_SOURCE_PREFIX));
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
        // The engine can list the same gap once per event it affects. Identical lines are
        // written once with their count, in the order they first appear.
        let mut lines: Vec<(Safe, u64)> = Vec::new();
        for gap in &listed {
            let line = Safe::join(&[
                Safe::literal(coverage_state_word(gap.state)),
                Safe::literal(": "),
                redactor.projected(projected, display_source(&gap.source), REPORT_NAME_CHARS),
                Safe::literal(": "),
                redactor.projected(projected, &gap.detail, REPORT_COVERAGE_DETAIL_CHARS),
            ]);
            match lines.iter_mut().find(|(known, _)| *known == line) {
                Some((_, count)) => *count += 1,
                None => lines.push((line, 1)),
            }
        }
        for (line, count) in &lines {
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
            let word = coverage_state_word(gap.state);
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
            projected,
            &summary.overview.headline,
            REPORT_FINDING_TEXT_CHARS,
        ))
        .nl()
        .nl();
    let mut actionable: Vec<&DiagnosisFinding> = summary
        .findings
        .iter()
        .filter(|finding| !matches!(finding.class, FindingClass::CoverageGap))
        .collect();
    actionable.sort_by(|left, right| {
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
        render_finding(doc, redactor, projected, finding);
    }
}

fn render_finding(
    doc: &mut Doc,
    redactor: &Redactor,
    projected: &Projected,
    finding: &DiagnosisFinding,
) {
    doc.lit("### ")
        .safe(&redactor.projected(projected, &finding.title, REPORT_FINDING_TITLE_CHARS))
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
        .safe(&redactor.projected(projected, &finding.summary, REPORT_FINDING_TEXT_CHARS))
        .nl();
    if !finding.evidence.is_empty() {
        doc.lit("- Evidence: ");
        for (index, evidence) in finding
            .evidence
            .iter()
            .take(REPORT_FINDING_EVIDENCE_LABELS)
            .enumerate()
        {
            if index > 0 {
                doc.lit("; ");
            }
            write_evidence_label(doc, redactor, projected, evidence);
        }
        if finding.evidence.len() > REPORT_FINDING_EVIDENCE_LABELS {
            doc.lit("; and ")
                .count((finding.evidence.len() - REPORT_FINDING_EVIDENCE_LABELS) as u64)
                .lit(" more");
        }
        doc.nl();
    }
    if let Some(first) = finding.recommended_checks.first() {
        doc.lit("- Recommended check: ").safe(&redactor.projected(
            projected,
            first,
            REPORT_FINDING_TEXT_CHARS,
        ));
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
fn write_evidence_label(
    doc: &mut Doc,
    redactor: &Redactor,
    projected: &Projected,
    evidence: &EvidenceRef,
) {
    match evidence {
        EvidenceRef::Event(event) => {
            doc.count(u64::from(event.event_id)).lit(" \u{b7} ");
            let place = event.channel.as_deref().unwrap_or(&event.provider);
            doc.safe(&redactor.projected(projected, place, REPORT_NAME_CHARS))
                .lit(" \u{b7} ");
            let numbered = event
                .record_id_text
                .as_deref()
                .filter(|text| text.chars().any(|digit| digit != '0'));
            if let Some(text) = numbered {
                doc.lit("record ")
                    .safe(&redactor.projected(projected, text, 40));
            } else if let Some(fallback) =
                event.fallback_identity.as_deref().filter(|f| !f.is_empty())
            {
                let head: String = fallback.chars().take(8).collect();
                doc.lit("ref ")
                    .safe(&redactor.projected(projected, &head, 16));
            } else if event.record_id != 0 {
                doc.lit("record ").count(event.record_id);
            } else {
                doc.lit("no record ID");
            }
        }
        EvidenceRef::TextLog(log) => {
            doc.safe(&redactor.projected(
                projected,
                display_source(&log.file_path),
                REPORT_NAME_CHARS,
            ))
            .lit(" \u{b7} line ")
            .count(u64::from(log.line_number));
        }
        _ => {
            doc.lit("a source-specific evidence reference");
        }
    }
}

/// A source label for printing: a path is reduced to its last segment, so a folder name above the
/// file never reaches the report.
fn display_source(source: &str) -> &str {
    source.rsplit(['\\', '/']).next().unwrap_or(source)
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
    });
    let mut cursor = 0usize;
    for (index, (row, resolved)) in chains.rows.iter().zip(&snapshot.chains).enumerate() {
        let projected_edges =
            &projected.summary().correlations[cursor..cursor + resolved.edges.len()];
        cursor += resolved.edges.len();
        render_chain(
            doc,
            &ChainContext {
                redactor,
                snapshot,
                projected: &projected,
            },
            index as u64 + 1,
            row,
            resolved,
            projected_edges,
        );
    }
    Ok(())
}

/// What every chain is rendered with.
struct ChainContext<'a> {
    redactor: &'a Redactor,
    snapshot: &'a ReportSnapshot,
    projected: &'a Projected,
}

fn render_chain(
    doc: &mut Doc,
    context: &ChainContext<'_>,
    number: u64,
    row: &ReportChainRow,
    resolved: &ResolvedChain,
    projected_edges: &[CorrelationEdge],
) {
    let ChainContext {
        redactor,
        snapshot,
        projected,
    } = *context;
    doc.lit("### Chain ")
        .count(number)
        .lit(": ")
        .lit(match row.strength {
            ReportLinkStrength::Exact => "Exact",
            ReportLinkStrength::Candidate => "Candidate",
        })
        .lit(", ")
        .count(row.member_count)
        .lit(" entries")
        .nl()
        .nl();

    let mut supplied: Vec<&str> = row.member_ids.iter().map(String::as_str).collect();
    supplied.sort_unstable();
    supplied.dedup();
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
    doc.lit("- Entries: ")
        .count(row.member_count)
        .lit(" in the chain; the app listed ")
        .count(supplied.len() as u64)
        .lit(". Of those listed, ")
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
        for (raw, safe_row) in edge.evidence.iter().zip(&projected_edge.evidence) {
            let line = evidence_line(
                redactor,
                snapshot,
                projected,
                &raw.origin_id,
                &raw.field,
                &safe_row.value,
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
        return;
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
                redactor.text(display_source(file), REPORT_NAME_CHARS),
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
    projected: &Projected,
    origin: &str,
    field: &str,
    projected_value: &str,
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
            redactor.projected(projected, projected_value, REPORT_NAME_CHARS),
        ]),
        ValuePolicy::Token => {
            let value = if safe::token_len_at(projected_value, 0) == Some(projected_value.len()) {
                redactor.projected(projected, projected_value, REPORT_NAME_CHARS)
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
                .safe(&redactor.text(display_source(file), REPORT_NAME_CHARS))
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

mod safe {
    //! The only code that can write text into the report.

    use std::collections::HashMap;

    use cmtraceopen_parser::diagnosis::{redacted_display_projection, DiagnosisSummary};
    use cmtraceopen_parser::intune::apps::windows::common::redact_field_value;

    use crate::event_log::export::redact_export_text;

    /// Machine names shorter than this are not searched for in free text: a two-letter name would
    /// corrupt ordinary words. They are counted and the report says so.
    pub(super) const MIN_SUBSTITUTED_MACHINE_CHARS: usize = 3;

    /// Text that is safe to write into the report.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(super) struct Safe(String);

    impl Safe {
        /// Static text written by this module's authors.
        pub(super) fn literal(text: &'static str) -> Self {
            Self(text.to_owned())
        }

        pub(super) fn count(value: u64) -> Self {
            Self(value.to_string())
        }

        /// Concatenation of values that are already safe is safe.
        pub(super) fn join(parts: &[Safe]) -> Self {
            Self(parts.iter().map(|part| part.0.as_str()).collect())
        }

        /// A UTC time, ISO 8601 with milliseconds and `Z`. A value no calendar can hold is
        /// reported as unavailable; it is never shown as 1970.
        pub(super) fn utc(epoch_ms: i64) -> Self {
            match chrono::DateTime::from_timestamp_millis(epoch_ms) {
                Some(time) => Self(time.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()),
                None => Self("time unavailable".to_owned()),
            }
        }

        /// A stable replacement token for a typed value (`[host:0123456789abcdef]`).
        pub(super) fn token(kind: &'static str, value: &str) -> Self {
            Self(escape(&redact_field_value(kind, value)))
        }

        pub(super) fn as_str(&self) -> &str {
            &self.0
        }
    }

    /// A diagnosis summary after `redacted_display_projection`. The report reads findings and
    /// evidence only through one of these, so it cannot print a summary that was not projected.
    pub(super) struct Projected(DiagnosisSummary);

    impl Projected {
        pub(super) fn new(summary: DiagnosisSummary) -> Self {
            Self(redacted_display_projection(summary))
        }

        pub(super) fn summary(&self) -> &DiagnosisSummary {
            &self.0
        }
    }

    /// The document being written. It accepts literals, numbers and [`Safe`] values only.
    pub(super) struct Doc {
        out: String,
    }

    impl Doc {
        pub(super) fn new() -> Self {
            Self { out: String::new() }
        }

        pub(super) fn lit(&mut self, text: &'static str) -> &mut Self {
            self.out.push_str(text);
            self
        }

        pub(super) fn safe(&mut self, text: &Safe) -> &mut Self {
            self.out.push_str(&text.0);
            self
        }

        pub(super) fn count(&mut self, value: u64) -> &mut Self {
            self.out.push_str(&value.to_string());
            self
        }

        pub(super) fn nl(&mut self) -> &mut Self {
            self.out.push('\n');
            self
        }

        /// The finished text, or an error when it is over `limit` bytes.
        pub(super) fn finish(self, limit: usize) -> Result<String, String> {
            if self.out.len() > limit {
                return Err(format!(
                    "the report is {} bytes, over the {limit}-byte limit, so it was not written",
                    self.out.len()
                ));
            }
            Ok(self.out)
        }
    }

    /// Redacts free text from the analysis session and mints [`Safe`] values from it.
    pub(super) struct Redactor {
        /// Lowercased machine name to its token.
        machines: HashMap<String, String>,
        /// The distinct byte lengths of the machine names, longest first.
        lengths: Vec<usize>,
        skipped_short: usize,
    }

    impl Redactor {
        /// `names` are the machine names the session's origins carry.
        pub(super) fn new<'a>(names: impl IntoIterator<Item = &'a String>) -> Self {
            let mut machines = HashMap::new();
            let mut skipped_short = 0;
            for name in names {
                let name = name.trim();
                if name.chars().count() < MIN_SUBSTITUTED_MACHINE_CHARS {
                    skipped_short += 1;
                    continue;
                }
                machines
                    .entry(name.to_ascii_lowercase())
                    .or_insert_with(|| redact_field_value("host", name));
            }
            let mut lengths: Vec<usize> = machines.keys().map(String::len).collect();
            lengths.sort_unstable_by(|left, right| right.cmp(left));
            lengths.dedup();
            Self {
                machines,
                lengths,
                skipped_short,
            }
        }

        /// How many machine names were too short to substitute in free text.
        pub(super) fn skipped_short(&self) -> usize {
            self.skipped_short
        }

        /// A machine name as its token. This is the same token the diagnosis projection writes.
        pub(super) fn machine(&self, name: &str) -> Safe {
            Safe::token("host", name.trim())
        }

        /// Free text from the session, safe to print. The order is the point:
        /// redact the whole field, substitute the machine names the session knows, flatten
        /// whitespace, cut to `max_chars`, and only then escape Markdown. Escaping first would
        /// change the text the redaction patterns read; cutting first could split a value the
        /// patterns would have caught.
        pub(super) fn text(&self, raw: &str, max_chars: usize) -> Safe {
            self.finish(&redact_export_text(raw), max_chars)
        }

        /// Text read from a projected summary. The projection is the diagnosis' own redaction, so
        /// the export pass is not run over it again: that pass rewrites the tokens the projection
        /// wrote (`[account:..]` would become `[account:[sensitive:Account]]`).
        pub(super) fn projected(&self, _from: &Projected, text: &str, max_chars: usize) -> Safe {
            self.finish(text, max_chars)
        }

        /// Substitute known machines, flatten, cut, escape.
        fn finish(&self, redacted: &str, max_chars: usize) -> Safe {
            let substituted = self.substitute(redacted);
            let flat = flatten(&substituted);
            Safe(escape(&cut_chars(&flat, max_chars)))
        }

        /// Replaces every known machine name with its token. A name matches only at name
        /// boundaries (a longer identifier that merely contains it is left alone), without regard
        /// to ASCII case, longest first, and never inside an existing replacement token.
        fn substitute(&self, text: &str) -> String {
            if self.machines.is_empty() {
                return text.to_owned();
            }
            let mut out = String::with_capacity(text.len());
            let mut index = 0;
            let mut previous: Option<char> = None;
            while index < text.len() {
                if let Some(length) = token_len_at(text, index) {
                    out.push_str(&text[index..index + length]);
                    index += length;
                    previous = Some(']');
                    continue;
                }
                if !previous.is_some_and(is_name_char) {
                    if let Some((length, token)) = self.match_at(text, index) {
                        out.push_str(token);
                        index += length;
                        previous = Some(']');
                        continue;
                    }
                }
                let Some(character) = text[index..].chars().next() else {
                    break;
                };
                out.push(character);
                index += character.len_utf8();
                previous = Some(character);
            }
            out
        }

        /// The longest known machine name that starts at `index` and ends at a name boundary.
        fn match_at(&self, text: &str, index: usize) -> Option<(usize, &str)> {
            for &length in &self.lengths {
                let Some(candidate) = text.get(index..index + length) else {
                    continue;
                };
                let Some(token) = self.machines.get(&candidate.to_ascii_lowercase()) else {
                    continue;
                };
                if text[index + length..]
                    .chars()
                    .next()
                    .is_some_and(is_name_char)
                {
                    continue;
                }
                return Some((length, token));
            }
            None
        }
    }

    /// A character that continues a machine name or identifier.
    fn is_name_char(character: char) -> bool {
        character.is_alphanumeric() || character == '_' || character == '-'
    }

    /// The length of the `[kind:16 hex digits]` token that starts at byte `start`, if one does.
    pub(super) fn token_len_at(text: &str, start: usize) -> Option<usize> {
        let bytes = text.as_bytes();
        if bytes.get(start) != Some(&b'[') {
            return None;
        }
        let kind_start = start + 1;
        let mut index = kind_start;
        while bytes.get(index).is_some_and(u8::is_ascii_lowercase) {
            index += 1;
        }
        if index == kind_start || bytes.get(index) != Some(&b':') {
            return None;
        }
        index += 1;
        let digits = bytes.get(index..index + 16)?;
        if !digits.iter().all(u8::is_ascii_hexdigit) {
            return None;
        }
        index += 16;
        (bytes.get(index) == Some(&b']')).then_some(index + 1 - start)
    }

    /// Strips format and control characters, and collapses every run of whitespace to one space.
    pub(super) fn flatten(text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        let mut pending_space = false;
        for character in text.chars() {
            if is_invisible(character) {
                continue;
            }
            if character.is_whitespace() || character.is_control() {
                pending_space = !out.is_empty();
                continue;
            }
            if pending_space {
                out.push(' ');
                pending_space = false;
            }
            out.push(character);
        }
        out
    }

    /// Zero-width and bidirectional format characters. They can reorder or hide text when a
    /// reader opens the file, so they are removed rather than shown.
    fn is_invisible(character: char) -> bool {
        matches!(
            character,
            '\u{61c}'
                | '\u{200b}'..='\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{2069}'
                | '\u{feff}'
        )
    }

    /// At most `max_chars` characters, with `...` when text was cut. A cut never lands inside a
    /// replacement token.
    pub(super) fn cut_chars(text: &str, max_chars: usize) -> String {
        let Some((mut end, _)) = text.char_indices().nth(max_chars) else {
            return text.to_owned();
        };
        // A token that straddles the cut is dropped whole: half a token names nothing.
        let mut search_from = end.saturating_sub(MAX_TOKEN_LOOKBACK_BYTES);
        while !text.is_char_boundary(search_from) {
            search_from -= 1;
        }
        if let Some(open) = text[search_from..end].rfind('[') {
            let open = search_from + open;
            if token_len_at(text, open).is_some_and(|length| open + length > end) {
                end = open;
            }
        }
        format!("{}...", text[..end].trim_end())
    }

    /// The longest `[kind:16 hex digits]` token this module reads, in bytes, bounds the search for
    /// a token that a cut would split. A kind is a short lowercase word.
    const MAX_TOKEN_LOOKBACK_BYTES: usize = 64;

    /// Backslash-escapes the characters that carry Markdown or HTML meaning. Replacement tokens
    /// pass through so they stay greppable across the app's surfaces.
    pub(super) fn escape(text: &str) -> String {
        let mut out = String::with_capacity(text.len() + text.len() / 8);
        let mut index = 0;
        while index < text.len() {
            if let Some(length) = token_len_at(text, index) {
                out.push_str(&text[index..index + length]);
                index += length;
                continue;
            }
            let Some(character) = text[index..].chars().next() else {
                break;
            };
            // A `(` can only start a link target straight after a `]`, and every `]` this function
            // writes is either escaped or the end of a token, so `(` is escaped there and only there.
            if matches!(
                character,
                '\\' | '`' | '*' | '_' | '[' | ']' | '<' | '>' | '|' | '&' | '#' | '!' | '~'
            ) || (character == '(' && out.ends_with(']'))
            {
                out.push('\\');
            }
            out.push(character);
            index += character.len_utf8();
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::safe::{cut_chars, escape, flatten, token_len_at, Doc, Redactor, Safe};
    use super::{collect, collect_chains, REPORT_CHAIN_ROW_CAP};
    use super::{
        render_report, render_report_within, EngineNotes, EventLogAnalysisReportRequest,
        ReportInput, ReportSnapshot, MAX_REPORT_BYTES, REPORT_EVENT_ROW_CAP,
    };
    use crate::event_log::analysis_session::EventLogAnalysisSessionStatus;
    use cmtraceopen_parser::diagnosis::{
        CoverageGap, CoverageState, DiagnosisFinding, DiagnosisSummary, EventEvidenceRef,
        EvidenceRef, FindingClass, FindingConfidence, FindingSeverity, TextLogEvidenceRef,
    };
    use cmtraceopen_parser::intune::apps::windows::common::redact_field_value;
    use cmtraceopen_parser::unified_timeline::{
        origin_id, TimelineCorrelationConfidence, TimelineCorrelationCoverage,
        TimelineCorrelationCoverageState, TimelineCorrelationEdge, TimelineCorrelationEvidence,
        TimelineCorrelationKey, TimelineCorrelationKeyKind, TimelineCorrelationStrength,
        TimelineCoverageGap, TimelineItem, TimelineOrigin, TimelineSeverity, UnifiedTimeline,
        UnplacedItem, UnplacedReason,
    };
    use serde_json::json;
    use std::collections::{BTreeSet, HashMap};

    fn redactor(names: &[&str]) -> Redactor {
        let names: Vec<String> = names.iter().map(|name| (*name).to_owned()).collect();
        Redactor::new(&names)
    }

    fn host(name: &str) -> String {
        redact_field_value("host", name)
    }

    #[test]
    fn escape_neutralizes_markdown_and_html_syntax() {
        assert_eq!(
            escape(r"a | b <i> [x](y) `c` *d* _e_ & #f !g ~h (k)"),
            r"a \| b \<i\> \[x\]\(y) \`c\` \*d\* \_e\_ \& \#f \!g \~h (k)"
        );
        assert_eq!(escape(r"C:\dir"), r"C:\\dir");
    }

    #[test]
    fn a_replacement_token_passes_through_escape_and_a_lookalike_does_not() {
        assert_eq!(escape("[host:0123456789abcdef]"), "[host:0123456789abcdef]");
        // 15 hex digits: not a token.
        assert_eq!(
            escape("[host:0123456789abcde]"),
            r"\[host:0123456789abcde\]"
        );
        // A token followed by a link target must not become a link.
        assert_eq!(
            escape("[host:0123456789abcdef](http://x)"),
            r"[host:0123456789abcdef]\(http://x)"
        );
        assert_eq!(token_len_at("x[user:00ff00ff00ff00ff]", 1), Some(23));
        assert_eq!(token_len_at("[Host:0123456789abcdef]", 0), None);
        assert_eq!(token_len_at("[host:0123456789abcdeg]", 0), None);
    }

    #[test]
    fn text_is_redacted_before_it_is_escaped() {
        // Escaping first turns `user_0001@...` into `user\_0001@...`, and the UPN pattern then
        // matches only from the underscore on, leaving `user` in the output.
        let out = redactor(&[]).text("contact user_0001@example.invalid today", 240);
        assert!(out.as_str().contains("[upn:"), "{}", out.as_str());
        assert!(!out.as_str().contains("user"), "{}", out.as_str());
        assert!(
            !out.as_str().contains("example.invalid"),
            "{}",
            out.as_str()
        );
    }

    #[test]
    fn text_is_cut_after_it_is_redacted() {
        // The UPN straddles character 240 and the cut falls before its first dot. Cut first, the
        // pattern sees `user0001@subdomain-with-long` (no top-level label) and leaves it; redact
        // first, the whole UPN is one 22-character token that fits before the cut.
        let raw = format!(
            "{} user0001@subdomain-with-long-name.example.invalid tail",
            "x".repeat(211)
        );
        let out = redactor(&[]).text(&raw, 240);
        assert!(out.as_str().contains("[upn:"), "{}", out.as_str());
        assert!(!out.as_str().contains("user0001"), "{}", out.as_str());
    }

    #[test]
    fn a_cut_never_lands_inside_a_token() {
        let raw = format!("{}[host:0123456789abcdef] after", "a".repeat(236));
        let cut = cut_chars(&raw, 240);
        assert_eq!(cut, format!("{}...", "a".repeat(236)));
        assert_eq!(cut_chars("short", 240), "short");
        // Characters are counted, not bytes, and the look-back for a token never splits one.
        assert_eq!(
            cut_chars("\u{e9}\u{e9}\u{e9}\u{e9}", 3),
            "\u{e9}\u{e9}\u{e9}..."
        );
        let wide = "\u{4e2d}".repeat(100);
        assert_eq!(
            cut_chars(&wide, 80),
            format!("{}...", "\u{4e2d}".repeat(80))
        );
    }

    #[test]
    fn flatten_collapses_whitespace_and_strips_format_characters() {
        assert_eq!(flatten("a\r\n\tb\u{202e}c\u{200b}d\u{0}e  f"), "a bcd e f");
        assert_eq!(flatten("  lead and trail  "), "lead and trail");
    }

    #[test]
    fn known_machines_are_replaced_longest_first_at_name_boundaries() {
        let r = redactor(&["HOST-0001", "HOST-0001.example.invalid"]);
        // Longest first: the full name is one token, not a token plus a domain tail.
        let out = r.text("see host-0001.example.invalid now", 240);
        assert_eq!(
            out.as_str(),
            format!("see {} now", host("HOST-0001.example.invalid"))
        );
        // Name boundaries: a longer identifier that contains the name is left alone.
        let out = r.text("XHOST-0001Y HOST-00012 HOST-0001", 240);
        assert_eq!(
            out.as_str(),
            format!("XHOST-0001Y HOST-00012 {}", host("HOST-0001"))
        );
    }

    #[test]
    fn machine_matching_ignores_ascii_case_and_leaves_tokens_alone() {
        let r = redactor(&["Host-0007", "host"]);
        let out = r.text("HOST-0007 and [host:0123456789abcdef] and host", 240);
        assert_eq!(
            out.as_str(),
            format!(
                "{} and [host:0123456789abcdef] and {}",
                host("Host-0007"),
                host("host")
            )
        );
    }

    #[test]
    fn short_machine_names_are_skipped_counted_and_still_tokenized_in_the_header() {
        let r = redactor(&["ab", "HOST-0001"]);
        assert_eq!(r.skipped_short(), 1);
        assert_eq!(
            r.text("ab HOST-0001", 240).as_str(),
            format!("ab {}", host("HOST-0001"))
        );
        assert_eq!(r.machine("ab").as_str(), host("ab"));
    }

    #[test]
    fn the_machine_token_is_the_diagnosis_token() {
        let r = redactor(&["HOST-0001"]);
        let token = r.machine("HOST-0001");
        assert!(token.as_str().starts_with("[host:"));
        assert_eq!(token.as_str(), host("HOST-0001"));
    }

    #[test]
    fn utc_has_milliseconds_and_a_zulu_suffix_and_marks_what_no_calendar_holds() {
        assert_eq!(
            Safe::utc(1_791_282_047_123).as_str(),
            "2026-10-06T10:20:47.123Z"
        );
        assert_eq!(Safe::utc(i64::MAX).as_str(), "time unavailable");
        assert_eq!(Safe::utc(i64::MIN).as_str(), "time unavailable");
    }

    #[test]
    fn the_document_refuses_to_exceed_its_cap() {
        let mut doc = Doc::new();
        doc.lit("0123456789").nl();
        assert_eq!(doc.finish(11).unwrap(), "0123456789\n");
        let mut doc = Doc::new();
        doc.lit("0123456789").nl();
        assert!(doc.finish(10).is_err());
        assert_eq!(MAX_REPORT_BYTES, 2 * 1024 * 1024);
    }

    // ---- the request, the scope block and the events table ------------------------------------

    const FIXTURE_NOW_MS: i64 = 1_791_282_047_123;

    fn request_json() -> serde_json::Value {
        json!({
            "sessionId": "test-session",
            "expectedRevision": 3,
            "generatedAtMs": FIXTURE_NOW_MS,
            "coverageGaps": [],
            "chains": null,
            "scope": {
                "sourceMode": "files",
                "loadedRecordCount": 10,
                "eventRecordCount": 10,
                "archiveTextRecordCount": 0,
                "textLogEntryCount": 0,
                "levelMix": [
                    {"level": "Error", "count": 4},
                    {"level": "Information", "count": 6}
                ],
                "topEventIds": [
                    {"eventId": 100, "count": 6},
                    {"eventId": 7, "count": 4}
                ],
                "distinctEventIdCount": 2,
                "filters": {
                    "levels": ["Critical", "Error", "Warning", "Information", "Verbose"],
                    "channelsSelected": ["Application"],
                    "channelsHeld": 1,
                    "eventIdSelectors": [],
                    "timeWindow": "all",
                    "timeRange": null,
                    "searchActive": false,
                    "quickFilterActive": false,
                    "recordScope": null
                }
            }
        })
    }

    fn request_from(value: serde_json::Value) -> EventLogAnalysisReportRequest {
        serde_json::from_value(value).expect("the request parses")
    }

    fn base_request() -> EventLogAnalysisReportRequest {
        request_from(request_json())
    }

    fn status(event_items: u64, log_items: u64) -> EventLogAnalysisSessionStatus {
        EventLogAnalysisSessionStatus {
            session_id: "test-session".to_owned(),
            revision: 3,
            total_items: event_items + log_items,
            event_items,
            log_items,
            total_unplaced: 0,
            total_edges: 0,
            total_coverage_gaps: 0,
            finalized: true,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn event_item(
        timestamp_ms: i64,
        severity: TimelineSeverity,
        event_id: u32,
        channel: &str,
        provider: &str,
        machine: Option<&str>,
        record: u64,
        message: &str,
    ) -> TimelineItem {
        TimelineItem {
            timestamp_ms,
            severity,
            message: message.to_owned(),
            origin: TimelineOrigin::Event {
                stable_id: format!("source8:test.evtx|machine0:|channel0:|record{record}"),
                source: "test.evtx".to_owned(),
                machine: machine.map(str::to_owned),
                bundle: None,
                channel: channel.to_owned(),
                provider: provider.to_owned(),
                process_id: None,
                activity_id: None,
                related_activity_id: None,
                session_id: None,
                device_id: None,
                user_id: None,
                process_start_time: None,
                identity_conflicts: Vec::new(),
                event_id,
                record_id: record,
                record_id_text: Some(record.to_string()),
            },
        }
    }

    fn plain_item(index: u64) -> TimelineItem {
        event_item(
            FIXTURE_NOW_MS + index as i64 * 1000,
            TimelineSeverity::Info,
            100,
            "Application",
            "Ordinary.Provider",
            Some("HOST-0001"),
            index + 1,
            "An ordinary message.",
        )
    }

    fn snapshot_of(rows: Vec<TimelineItem>, placed: u64) -> ReportSnapshot {
        let mut machines = BTreeSet::new();
        for row in &rows {
            if let TimelineOrigin::Event {
                machine: Some(machine),
                ..
            } = &row.origin
            {
                machines.insert(machine.clone());
            }
        }
        ReportSnapshot {
            status: status(placed, 0),
            event_rows: rows,
            unplaced_events: 0,
            unplaced_text_lines: 0,
            span_ms: Some((FIXTURE_NOW_MS, FIXTURE_NOW_MS + 1000)),
            machines,
            engine_notes: EngineNotes::default(),
            entries: HashMap::new(),
            chains: Vec::new(),
        }
    }

    fn render(request: &EventLogAnalysisReportRequest, snapshot: &ReportSnapshot) -> String {
        render_with(request, snapshot, &DiagnosisSummary::default())
    }

    fn render_with(
        request: &EventLogAnalysisReportRequest,
        snapshot: &ReportSnapshot,
        summary: &DiagnosisSummary,
    ) -> String {
        render_report(&ReportInput {
            request,
            snapshot,
            summary,
        })
        .expect("the report renders")
    }

    /// Whether `needle` is in the report, whether or not Markdown escaping broke it up. A leak
    /// assertion on the escaped text would pass for `user\_0001`, which is the same leak.
    fn leaks(report: &str, needle: &str) -> bool {
        report
            .replace('\\', "")
            .to_lowercase()
            .contains(&needle.to_lowercase())
    }

    fn table_rows(report: &str) -> usize {
        report
            .lines()
            .filter(|line| line.starts_with("| 2026-"))
            .count()
    }

    #[test]
    fn the_request_contract_parses_and_refuses_text_it_has_no_field_for() {
        base_request()
            .validate()
            .expect("the base request is valid");
        for window in ["1h", "24h", "7d", "30d", "all"] {
            let mut value = request_json();
            value["scope"]["filters"]["timeWindow"] = json!(window);
            request_from(value);
        }
        let mut value = request_json();
        value["scope"]["filters"]["eventIdSelectors"] = json!([
            {"kind": "single", "id": 4624},
            {"kind": "range", "low": 4625, "high": 4630}
        ]);
        request_from(value).validate().expect("selectors are valid");

        // No field carries what the operator typed, a title or a record: an attempt to send one
        // is refused at the type, at every level.
        for (path, key) in [
            ("", "searchText"),
            ("scope", "chainTitle"),
            ("scope.filters", "searchText"),
            ("scope.filters", "quickFilterText"),
            ("scope.filters", "recordScopeTitle"),
        ] {
            let mut value = request_json();
            let target = path
                .split('.')
                .filter(|part| !part.is_empty())
                .fold(&mut value, |node, part| &mut node[part]);
            target[key] = json!("fixture text");
            assert!(
                serde_json::from_value::<EventLogAnalysisReportRequest>(value).is_err(),
                "{path}.{key} was accepted"
            );
        }
        let mut value = request_json();
        value["scope"]["filters"]["timeWindow"] = json!("2h");
        assert!(serde_json::from_value::<EventLogAnalysisReportRequest>(value).is_err());
    }

    #[test]
    fn validation_refuses_what_cannot_be_true() {
        type Change = fn(&mut serde_json::Value);
        let cases: [(&str, Change); 9] = [
            ("level counts exceed", |v| {
                v["scope"]["levelMix"][0]["count"] = json!(7);
            }),
            ("a level is counted twice", |v| {
                v["scope"]["levelMix"][1]["level"] = json!("Error");
            }),
            ("event ID counts exceed", |v| {
                v["scope"]["topEventIds"][0]["count"] = json!(9);
            }),
            ("an event ID is counted twice", |v| {
                v["scope"]["topEventIds"][1]["eventId"] = json!(100);
            }),
            ("distinct event ID count is impossible", |v| {
                v["scope"]["distinctEventIdCount"] = json!(1);
            }),
            ("distinct event ID count is impossible", |v| {
                v["scope"]["distinctEventIdCount"] = json!(11);
            }),
            ("selectors are impossible", |v| {
                v["scope"]["filters"]["eventIdSelectors"] =
                    json!([{"kind": "range", "low": 9, "high": 3}]);
            }),
            ("channel list is too large", |v| {
                v["scope"]["filters"]["channelsSelected"] = json!(["c".repeat(513)]);
            }),
            ("ends before it starts", |v| {
                v["scope"]["filters"]["timeRange"] = json!({"startMs": 9, "endMs": 3});
            }),
        ];
        for (expected, change) in cases {
            let mut value = request_json();
            change(&mut value);
            let error = request_from(value).validate().expect_err(expected);
            assert!(error.contains(expected), "{expected}: {error}");
        }
    }

    #[test]
    fn the_events_table_lists_at_most_the_cap_and_counts_the_rest() {
        let request = base_request();
        // (rows the snapshot holds, events the session placed, rows printed, closing sentence)
        let cases: [(u64, u64, usize, &str); 6] = [
            (0, 0, 0, "No event in scope is placed on the timeline."),
            (499, 499, 499, "All 499 placed events are listed."),
            (500, 500, 500, "All 500 placed events are listed."),
            (
                500,
                501,
                500,
                "Showing the first 500 of 501 placed events; 1 omitted.",
            ),
            (
                501,
                501,
                500,
                "Showing the first 500 of 501 placed events; 1 omitted.",
            ),
            (
                600,
                1200,
                500,
                "Showing the first 500 of 1200 placed events; 700 omitted.",
            ),
        ];
        assert_eq!(REPORT_EVENT_ROW_CAP, 500);
        for (held, placed, printed, sentence) in cases {
            let rows = (0..held).map(plain_item).collect();
            let report = render(&request, &snapshot_of(rows, placed));
            assert_eq!(table_rows(&report), printed, "{held} held, {placed} placed");
            assert!(report.contains(sentence), "{sentence}\n{report}");
        }
    }

    #[test]
    fn every_cell_of_the_events_table_is_redacted() {
        let message = concat!(
            "Sign-in by user0001@example.invalid from HOST-0002 ",
            "SID S-1-5-21-1000000001-1000000002-1000000003-1001 ",
            "TenantId=00000000-0000-4000-8000-000000000001 ",
            r"profile C:\Users\user0001\AppData\Local\Temp\a.log"
        );
        let item = event_item(
            FIXTURE_NOW_MS,
            TimelineSeverity::Error,
            1001,
            "Microsoft-Windows-Fixture/Admin for HOST-0002",
            r"Vendor C:\Users\user0001\x",
            Some("HOST-0002"),
            1,
            message,
        );
        let report = render(&base_request(), &snapshot_of(vec![item], 1));
        for leak in [
            "HOST-0002",
            "user0001",
            "example.invalid",
            "S-1-5-21-1000000001",
            "00000000-0000-4000-8000-000000000001",
        ] {
            assert!(!leaks(&report, leak), "{leak} leaked:\n{report}");
        }
        // `TenantId=` is a sensitive label, so the export pass masks its value whole.
        for token in [
            "[host:",
            "[upn:",
            "[sid:",
            r"\[sensitive:TenantId\]",
            "[user:",
        ] {
            assert!(report.contains(token), "{token} missing:\n{report}");
        }
        assert_eq!(table_rows(&report), 1);
    }

    #[test]
    fn a_report_of_five_hundred_long_rows_is_redacted_per_field_not_as_a_document() {
        // Over 256 KiB in all: redacting the assembled document would replace it with the
        // oversize marker, so the redaction has to be per field.
        let message = format!("user_0001@example.invalid {}", "word ".repeat(60));
        let rows: Vec<TimelineItem> = (0..500)
            .map(|index| {
                event_item(
                    FIXTURE_NOW_MS + index,
                    TimelineSeverity::Warning,
                    100,
                    &format!("Microsoft-Windows-{}/Operational", "Channel-".repeat(20)),
                    &format!("Microsoft-Windows-{}", "Provider-".repeat(20)),
                    Some("HOST-0001"),
                    index as u64 + 1,
                    &message,
                )
            })
            .collect();
        let report = render(&base_request(), &snapshot_of(rows, 500));
        assert!(report.len() > 256 * 1024, "{}", report.len());
        assert!(!report.contains("oversized text omitted"));
        assert_eq!(table_rows(&report), 500);
        assert_eq!(report.matches("[upn:").count(), 500);
    }

    #[test]
    fn the_scope_block_counts_what_is_unplaced_and_flags_counts_that_disagree() {
        let request = base_request();
        let mut snapshot = snapshot_of((0..8).map(plain_item).collect(), 8);
        snapshot.unplaced_events = 2;
        snapshot.unplaced_text_lines = 3;
        let report = render(&request, &snapshot);
        assert!(report.contains(
            "- Events in scope without a usable timestamp, not placed and not listed below: 2"
        ));
        assert!(report.contains("- Text lines without a usable timestamp, not placed: 3"));
        assert!(!report.contains("The session holds"), "{report}");

        snapshot.unplaced_events = 1;
        let report = render(&request, &snapshot);
        assert!(report.contains(
            "The session holds 9 events and the app counted 10 in scope. The two counts are \
             shown as each side reported them."
        ));
    }

    #[test]
    fn a_narrowed_scope_is_disclosed_and_an_unnarrowed_one_is_not() {
        let mut value = request_json();
        value["scope"]["loadedRecordCount"] = json!(100);
        value["scope"]["textLogEntryCount"] = json!(4);
        let report = render(&request_from(value), &snapshot_of(Vec::new(), 0));
        assert!(report.contains("computed over the events in scope only"));
        assert!(report.contains("- Text logs are not scoped."));

        let mut value = request_json();
        value["scope"]["loadedRecordCount"] = json!(100);
        let report = render(&request_from(value), &snapshot_of(Vec::new(), 0));
        assert!(report.contains("computed over the events in scope only"));
        assert!(!report.contains("Text logs are not scoped."));

        let report = render(&base_request(), &snapshot_of(Vec::new(), 0));
        assert!(!report.contains("computed over the events in scope only"));
    }

    #[test]
    fn machines_are_listed_as_tokens_and_their_absence_is_said_precisely() {
        let mut rows = vec![plain_item(0)];
        rows.push(event_item(
            FIXTURE_NOW_MS,
            TimelineSeverity::Info,
            1,
            "Application",
            "P",
            Some("HOST-0002"),
            9,
            "m",
        ));
        let report = render(&base_request(), &snapshot_of(rows, 2));
        let expected = {
            let mut tokens = [host("HOST-0001"), host("HOST-0002")];
            tokens.sort();
            format!("- Machines (2): {}, {}", tokens[0], tokens[1])
        };
        assert!(report.contains(&expected), "{report}");
        assert!(!report.contains("HOST-000"), "{report}");

        let mut anonymous = snapshot_of(vec![plain_item(0)], 1);
        anonymous.machines.clear();
        let report = render(&base_request(), &anonymous);
        assert!(report.contains("- Machines: no entry in the session records a machine name"));

        let empty = snapshot_of(Vec::new(), 0);
        let report = render(&base_request(), &empty);
        assert!(report.contains("- Machines: the session holds no entries"));

        let mut short = snapshot_of(vec![plain_item(0)], 1);
        short.machines.insert("ab".to_owned());
        let report = render(&base_request(), &short);
        assert!(report.contains("shorter than 3 characters, not searched for in free text: 1"));
    }

    #[test]
    fn the_aggregates_are_the_apps_counts_and_say_what_they_do_not_cover() {
        let report = render(&base_request(), &snapshot_of(Vec::new(), 0));
        assert!(report.contains("Top 2 of 2 distinct event IDs."));
        assert!(report.contains("| 100 | 6 |"));
        assert!(report.contains("| Error | 4 |"));
        assert!(!report.contains("The level counts cover"));

        let mut value = request_json();
        value["scope"]["distinctEventIdCount"] = json!(null);
        value["scope"]["levelMix"][0]["count"] = json!(3);
        let report = render(&request_from(value), &snapshot_of(Vec::new(), 0));
        assert!(report.contains("the number of distinct IDs was not counted"));
        assert!(report.contains("The level counts cover 9 of the 10 events in scope."));

        let mut value = request_json();
        value["scope"]["eventRecordCount"] = json!(0);
        value["scope"]["levelMix"] = json!([]);
        value["scope"]["topEventIds"] = json!([]);
        value["scope"]["distinctEventIdCount"] = json!(0);
        let report = render(&request_from(value), &snapshot_of(Vec::new(), 0));
        assert_eq!(report.matches("No events are in scope.").count(), 2);
    }

    #[test]
    fn filters_are_typed_and_what_the_operator_typed_is_never_printed() {
        let mut value = request_json();
        value["scope"]["filters"]["searchActive"] = json!(true);
        value["scope"]["filters"]["quickFilterActive"] = json!(true);
        value["scope"]["filters"]["recordScope"] = json!("chain");
        value["scope"]["filters"]["levels"] = json!(["Critical", "Error"]);
        value["scope"]["filters"]["eventIdSelectors"] = json!([
            {"kind": "single", "id": 4624},
            {"kind": "range", "low": 4625, "high": 4630}
        ]);
        value["scope"]["filters"]["timeRange"] =
            json!({"startMs": FIXTURE_NOW_MS, "endMs": FIXTURE_NOW_MS + 60_000});
        value["scope"]["filters"]["timeWindow"] = json!("7d");
        let report = render(&request_from(value), &snapshot_of(Vec::new(), 0));
        assert!(report.contains("  - Levels: Critical, Error"));
        assert!(report.contains("  - Event IDs: 4624, 4625 to 4630"));
        assert!(report.contains("  - Time window: last 7 days"));
        assert!(report.contains(
            "  - Brushed time range: 2026-10-06T10:20:47.123Z to 2026-10-06T10:21:47.123Z \
             (start included, end excluded)"
        ));
        assert!(
            report.contains("  - Text search: active (its text is not included in this report)")
        );
        assert!(
            report.contains("  - Quick filter: active (its text is not included in this report)")
        );
        assert!(report.contains("  - Record scope: limited to the events one chain contains"));
        assert!(report.contains("  - Channels: 1 of 1 loaded channels selected: Application"));
    }

    #[test]
    fn times_are_utc_and_one_no_calendar_holds_is_marked_not_shown_as_1970() {
        let item = event_item(
            i64::MAX,
            TimelineSeverity::Info,
            1,
            "Application",
            "P",
            None,
            1,
            "m",
        );
        let report = render(&base_request(), &snapshot_of(vec![item], 1));
        assert!(
            report.contains("| time unavailable | Information | 1 |"),
            "{report}"
        );
        assert!(!report.contains("1970"));
        assert!(report.contains("- Generated: 2026-10-06T10:20:47.123Z"));
        assert!(report.contains("All times are UTC (ISO 8601)."));
    }

    #[test]
    fn a_report_over_its_cap_is_an_error_and_never_a_shorter_file() {
        let request = base_request();
        let snapshot = snapshot_of((0..50).map(plain_item).collect(), 50);
        let summary = DiagnosisSummary::default();
        let input = ReportInput {
            request: &request,
            snapshot: &snapshot,
            summary: &summary,
        };
        let full = render_report_within(&input, MAX_REPORT_BYTES).expect("within the cap");
        assert!(render_report_within(&input, full.len()).is_ok());
        let error = render_report_within(&input, full.len() - 1).expect_err("one byte over");
        assert!(error.contains("not written"), "{error}");
    }

    #[test]
    fn the_report_is_deterministic_and_does_not_claim_to_be_free_of_identifiers() {
        let request = base_request();
        let snapshot = snapshot_of((0..20).map(plain_item).collect(), 20);
        let first = render(&request, &snapshot);
        assert_eq!(first, render(&request, &snapshot));
        assert!(
            first.contains("Free text can still contain identifiers that no pattern recognizes")
        );
        assert!(first.starts_with("# Event Logs report\n"));
        assert!(!first.to_lowercase().contains("no sensitive"));
    }

    // ---- findings and coverage ----------------------------------------------------------------

    fn finding(
        id: &str,
        class: FindingClass,
        severity: FindingSeverity,
        confidence: FindingConfidence,
        title: &str,
    ) -> DiagnosisFinding {
        DiagnosisFinding {
            finding_id: id.to_owned(),
            class,
            severity,
            confidence,
            title: title.to_owned(),
            summary: format!("{title} summary."),
            evidence: Vec::new(),
            coverage_gaps: Vec::new(),
            recommended_checks: Vec::new(),
        }
    }

    fn event_evidence(
        event_id: u32,
        channel: Option<&str>,
        record_id_text: Option<&str>,
        record_id: u64,
        fallback: Option<&str>,
    ) -> EvidenceRef {
        EvidenceRef::Event(EventEvidenceRef {
            source: r"C:\Cases\CASE-0001\System.evtx".to_owned(),
            provider: "Fixture.Provider".to_owned(),
            event_id,
            record_id,
            record_id_text: record_id_text.map(str::to_owned),
            fallback_identity: fallback.map(str::to_owned),
            machine: Some("HOST-0004".to_owned()),
            channel: channel.map(str::to_owned),
            activity_id: None,
        })
    }

    fn gap(source: &str, state: CoverageState, detail: &str) -> CoverageGap {
        CoverageGap {
            id: format!("coverage:{source}:{detail}"),
            source: source.to_owned(),
            state,
            detail: detail.to_owned(),
            evidence: Vec::new(),
        }
    }

    fn summary_of(findings: Vec<DiagnosisFinding>, gaps: Vec<CoverageGap>) -> DiagnosisSummary {
        let mut summary = DiagnosisSummary {
            findings,
            coverage_gaps: gaps,
            ..DiagnosisSummary::default()
        };
        summary.overview.actionable_finding_count = summary
            .findings
            .iter()
            .filter(|finding| !matches!(finding.class, FindingClass::CoverageGap))
            .count();
        summary.overview.coverage_gap_count = summary.coverage_gaps.len();
        summary.overview.finding_count = summary.findings.len();
        summary
    }

    #[test]
    fn findings_are_listed_by_severity_then_confidence_with_bounded_evidence() {
        let mut first = finding(
            "a",
            FindingClass::LikelyContributor,
            FindingSeverity::Warning,
            FindingConfidence::High,
            "Warning high",
        );
        let mut second = finding(
            "b",
            FindingClass::ConfirmedFailure,
            FindingSeverity::Critical,
            FindingConfidence::Low,
            "Critical low",
        );
        let third = finding(
            "c",
            FindingClass::Symptom,
            FindingSeverity::Warning,
            FindingConfidence::Medium,
            "Warning medium",
        );
        let coverage = finding(
            "d",
            FindingClass::CoverageGap,
            FindingSeverity::Critical,
            FindingConfidence::High,
            "A coverage gap is never an actionable finding",
        );
        first.evidence = vec![
            event_evidence(
                76,
                Some("DeviceManagement/Admin"),
                Some("88456"),
                88456,
                None,
            ),
            event_evidence(77, None, Some("000"), 0, Some("deadbeefcafe")),
            event_evidence(78, Some("System"), None, 12, None),
            event_evidence(79, Some("System"), None, 0, None),
            EvidenceRef::TextLog(TextLogEvidenceRef {
                source: "IntuneManagementExtension.log".to_owned(),
                file_path: r"C:\Cases\CASE-0001\Logs\IntuneManagementExtension.log".to_owned(),
                line_number: 42,
                entry_id: 7,
            }),
        ];
        second.recommended_checks = vec!["Check one.".to_owned(), "Check two.".to_owned()];
        let summary = summary_of(vec![first, second, third, coverage], Vec::new());
        let report = render_with(&base_request(), &snapshot_of(Vec::new(), 0), &summary);

        let position = |needle: &str| report.find(needle).unwrap_or(usize::MAX);
        assert!(position("### Critical low") < position("### Warning high"));
        assert!(position("### Warning high") < position("### Warning medium"));
        assert!(!report.contains("never an actionable finding"));
        assert!(report.contains("The engine reported 3 actionable findings."));
        assert!(report.contains("- Class: confirmed failure; severity: critical; confidence: low"));
        assert!(report.contains("- Summary: Critical low summary."));
        assert!(report.contains(
            "- Evidence: 76 \u{b7} DeviceManagement/Admin \u{b7} record 88456; \
             77 \u{b7} Fixture.Provider \u{b7} ref deadbeef; \
             78 \u{b7} System \u{b7} record 12; and 2 more"
        ));
        assert!(report.contains("- Recommended check: Check one.; and 1 more checks"));
        // Evidence is named by event, channel and record: never by source path or machine.
        assert!(!report.contains("CASE-0001"));
        assert!(!report.contains("HOST-0004"));
    }

    #[test]
    fn evidence_without_a_record_number_says_so_and_a_text_log_is_named_by_its_file() {
        let mut one = finding(
            "a",
            FindingClass::Symptom,
            FindingSeverity::Info,
            FindingConfidence::Unknown,
            "Evidence labels",
        );
        one.evidence = vec![
            event_evidence(79, Some("System"), None, 0, None),
            EvidenceRef::TextLog(TextLogEvidenceRef {
                source: "x".to_owned(),
                file_path: r"C:\Cases\CASE-0001\Logs\IntuneManagementExtension.log".to_owned(),
                line_number: 42,
                entry_id: 7,
            }),
        ];
        let report = render_with(
            &base_request(),
            &snapshot_of(Vec::new(), 0),
            &summary_of(vec![one], Vec::new()),
        );
        assert!(report.contains(
            "- Evidence: 79 \u{b7} System \u{b7} no record ID; \
             IntuneManagementExtension.log \u{b7} line 42"
        ));
        assert!(!report.contains("CASE-0001"));
    }

    #[test]
    fn an_unprojected_summary_is_redacted_by_the_renderer_itself() {
        // Only the diagnosis projection removes an XML element's content and replaces a machine
        // the evidence names. The renderer's own redaction cannot know either, so a renderer that
        // trusted its caller to project would print both.
        let mut one = finding(
            "a",
            FindingClass::ConfirmedFailure,
            FindingSeverity::Error,
            FindingConfidence::High,
            "Enrollment failed",
        );
        one.summary =
            "DESKTOP-JANE rejected <Password>xml-secret-0001</Password> during enrollment"
                .to_owned();
        one.evidence = vec![EvidenceRef::Event(EventEvidenceRef {
            source: "s".to_owned(),
            provider: "p".to_owned(),
            event_id: 1,
            record_id: 1,
            record_id_text: Some("1".to_owned()),
            fallback_identity: None,
            machine: Some("DESKTOP-JANE".to_owned()),
            channel: None,
            activity_id: None,
        })];
        let summary = summary_of(vec![one], Vec::new());
        let report = render_with(&base_request(), &snapshot_of(Vec::new(), 0), &summary);
        assert!(!report.contains("xml-secret-0001"), "{report}");
        assert!(!report.contains("DESKTOP-JANE"), "{report}");
        assert!(report.contains("### Enrollment failed"));
    }

    #[test]
    fn the_engines_headline_is_printed_and_no_issues_is_never_composed() {
        let mut summary = summary_of(
            Vec::new(),
            vec![gap(
                "Security",
                CoverageState::AccessDenied,
                "Access is denied.",
            )],
        );
        summary.overview.outcome = "insufficientEvidence".to_owned();
        summary.overview.headline =
            "Evidence is insufficient to determine whether issues are present.".to_owned();
        let report = render_with(&base_request(), &snapshot_of(Vec::new(), 0), &summary);
        assert!(report.contains(
            "Engine summary: Evidence is insufficient to determine whether issues are present."
        ));
        assert!(report.contains(
            "The engine reported no actionable findings in the events it read. Coverage gaps \
             listed above limit what that means."
        ));
        assert!(!report.contains("No issues detected"));

        // With no gap the engine's own words are printed, as the engine's.
        let report = render(&base_request(), &snapshot_of(Vec::new(), 0));
        assert!(report.contains("Engine summary: No issues detected."));
        assert!(
            report.contains("The engine reported no actionable findings in the events it read.\n")
        );
    }

    #[test]
    fn a_bounded_response_is_stated_with_both_counts() {
        let mut summary = summary_of(
            vec![finding(
                "a",
                FindingClass::Symptom,
                FindingSeverity::Info,
                FindingConfidence::Low,
                "Only one",
            )],
            vec![gap("Security", CoverageState::Capped, "Capped.")],
        );
        summary.overview.actionable_finding_count = 5;
        summary.overview.coverage_gap_count = 9;
        let report = render_with(&base_request(), &snapshot_of(Vec::new(), 0), &summary);
        assert!(report.contains(
            "The engine counted 5 actionable findings and sent 1 of them: its response is bounded."
        ));
        assert!(report.contains(
            "- The engine counted 9 coverage gaps and sent 1 of them: its response is bounded."
        ));
    }

    #[test]
    fn coverage_gaps_are_listed_by_state_and_timeline_gaps_are_counted_and_never_named() {
        let timeline_source =
            "timeline:source9:test.evtx|machine9:HOST-0003|channel11:Application|record5";
        let summary = summary_of(
            Vec::new(),
            vec![
                gap("Security", CoverageState::AccessDenied, "Access is denied."),
                gap(
                    r"C:\Cases\ACME-0001\Archive.evtx",
                    CoverageState::Unsupported,
                    "The file could not be read.",
                ),
                gap(
                    timeline_source,
                    CoverageState::Skipped,
                    "multiple exact identity candidates remain: source9:test.evtx|machine9:HOST-0003",
                ),
                gap(
                    "timeline:correlation",
                    CoverageState::Capped,
                    "correlation edge output budget reached",
                ),
                gap(
                    "timeline:timeline-correlation-projection",
                    CoverageState::Capped,
                    "correlation input limit reached",
                ),
            ],
        );
        let report = render_with(&base_request(), &snapshot_of(Vec::new(), 0), &summary);
        assert!(report.contains("- Coverage gaps the engine listed (2):"));
        assert!(report.contains("  - access denied: Security: Access is denied."));
        assert!(report.contains("  - unsupported: Archive.evtx: The file could not be read."));
        assert!(report.contains(
            "- Correlation and timeline coverage gaps: 3 (capped 2, skipped 1). Their details \
             name individual events, so they are counted here and not listed."
        ));
        for leak in [
            "HOST-0003",
            "ACME-0001",
            "test.evtx",
            "record5",
            "identity candidates",
        ] {
            assert!(!leaks(&report, leak), "{leak} leaked:\n{report}");
        }
    }

    #[test]
    fn what_the_engine_shortened_is_stated_and_a_clean_run_states_nothing_it_did_not_see() {
        let mut snapshot = snapshot_of(Vec::new(), 0);
        let report = render(&base_request(), &snapshot);
        assert!(!report.contains("shortened some event messages"));
        assert!(!report.contains("compacted oversized"));
        assert!(!report.contains("reduced before the session read them"));
        assert!(report.contains(
            "- The engine listed no coverage gap. A channel that was not loaded or not selected \
             is not a gap and does not appear here."
        ));

        snapshot.engine_notes = EngineNotes {
            messages_shortened: true,
            items_compacted: true,
            transport_projected: true,
        };
        let report = render(&base_request(), &snapshot);
        assert!(report.contains("shortened some event messages to stay inside its message budget"));
        assert!(report.contains("compacted oversized list-view fields of some timeline items"));
        assert!(report.contains("reduced before the session read them"));
    }

    #[test]
    fn finding_text_is_redacted_cut_and_single_line() {
        let mut one = finding(
            "a",
            FindingClass::Symptom,
            FindingSeverity::Info,
            FindingConfidence::Low,
            "T",
        );
        one.title = format!(
            "Title\nwith | pipe and user_0001@example.invalid {}",
            "t".repeat(400)
        );
        one.summary = format!("{}\r\nsecond line", "s".repeat(2000));
        let summary = summary_of(vec![one], Vec::new());
        let report = render_with(&base_request(), &snapshot_of(Vec::new(), 0), &summary);
        let heading = report
            .lines()
            .find(|line| line.starts_with("### "))
            .unwrap();
        assert!(heading.contains(r"with \| pipe"), "{heading}");
        assert!(heading.contains("[upn:"));
        assert!(!leaks(heading, "user_0001"));
        assert!(heading.ends_with("..."));
        let summary_line = report
            .lines()
            .find(|line| line.starts_with("- Summary: "))
            .unwrap();
        assert!(
            summary_line.chars().count() < 1_020,
            "{}",
            summary_line.len()
        );
        assert!(!summary_line.contains("second line"));
    }

    // ---- chains and the nearby statement -------------------------------------------------------

    const GUID_A: &str = "00000000-0000-4000-8000-0000000000a1";

    fn stable(record: u64) -> String {
        format!(
            "source30:C:\\Cases\\CASE-0002\\A.evtx|machine9:HOST-0005|channel30:Fixture/Admin|record{record}"
        )
    }

    fn chain_item(record: u64, event_id: u32, offset_s: i64, message: &str) -> TimelineItem {
        let mut item = event_item(
            FIXTURE_NOW_MS + offset_s * 1000,
            TimelineSeverity::Info,
            event_id,
            "Microsoft-Windows-Fixture/Admin",
            "Fixture.Provider",
            Some("HOST-0005"),
            record,
            message,
        );
        if let TimelineOrigin::Event { stable_id, .. } = &mut item.origin {
            *stable_id = stable(record);
        }
        item
    }

    fn edge(
        from: &str,
        to: &str,
        kind: TimelineCorrelationKeyKind,
        field: &str,
        value: &str,
        strength: TimelineCorrelationStrength,
    ) -> TimelineCorrelationEdge {
        TimelineCorrelationEdge {
            id: format!("edge|{from}|{to}|{field}|{value}"),
            from_id: from.to_owned(),
            to_id: Some(to.to_owned()),
            key: TimelineCorrelationKey {
                kind,
                value: value.to_owned(),
            },
            strength,
            confidence: TimelineCorrelationConfidence::High,
            candidate_ids: Vec::new(),
            evidence: vec![
                TimelineCorrelationEvidence {
                    origin_id: from.to_owned(),
                    field: field.to_owned(),
                    value: value.to_owned(),
                },
                TimelineCorrelationEvidence {
                    origin_id: to.to_owned(),
                    field: field.to_owned(),
                    value: value.to_owned(),
                },
            ],
            coverage: TimelineCorrelationCoverage {
                state: TimelineCorrelationCoverageState::Covered,
                gap: None,
            },
        }
    }

    fn exact_edge(from: &str, to: &str, value: &str) -> TimelineCorrelationEdge {
        edge(
            from,
            to,
            TimelineCorrelationKeyKind::ActivityId,
            "activityId",
            value,
            TimelineCorrelationStrength::Exact,
        )
    }

    fn timeline_of(
        items: Vec<TimelineItem>,
        edges: Vec<TimelineCorrelationEdge>,
    ) -> UnifiedTimeline {
        UnifiedTimeline {
            items,
            unplaced: Vec::new(),
            edges,
            coverage_gaps: Vec::new(),
        }
    }

    fn row(strength: &str, members: &[String], pairs: serde_json::Value) -> serde_json::Value {
        json!({
            "strength": strength,
            "memberCount": members.len(),
            "memberIds": members,
            "pairs": pairs,
        })
    }

    fn pair(left: &str, right: &str, keys: &[(&str, &str)]) -> serde_json::Value {
        json!({
            "left": left,
            "right": right,
            "keys": keys
                .iter()
                .map(|(kind, value)| json!({"kind": kind, "value": value}))
                .collect::<Vec<_>>(),
        })
    }

    fn chains_value(
        loaded: u64,
        counts: (u64, u64, u64, u64),
        rows: Vec<serde_json::Value>,
    ) -> serde_json::Value {
        json!({
            "loadedEdgeCount": loaded,
            "correlationGaps": {"global": false, "previewCut": false},
            "counts": {
                "exact": counts.0,
                "candidate": counts.1,
                "ambiguous": counts.2,
                "coverageBlocked": counts.3
            },
            "rows": rows,
        })
    }

    fn chain_report_for(
        timeline: &UnifiedTimeline,
        chains: serde_json::Value,
    ) -> Result<String, String> {
        let mut value = request_json();
        value["chains"] = chains;
        let request = request_from(value);
        request.validate()?;
        let (chains, entries) = collect_chains(timeline, request.chains.as_ref().unwrap())?;
        let mut snapshot = snapshot_of(Vec::new(), 0);
        snapshot.machines.insert("HOST-0005".to_owned());
        snapshot.status.total_edges = timeline.edges.len() as u64;
        snapshot.entries = entries;
        snapshot.chains = chains;
        render_report(&ReportInput {
            request: &request,
            snapshot: &snapshot,
            summary: &DiagnosisSummary::default(),
        })
    }

    fn two_event_timeline() -> (UnifiedTimeline, String, String) {
        let (a, b) = (stable(1), stable(2));
        let timeline = timeline_of(
            vec![
                chain_item(1, 76, 0, "Enrollment started on HOST-0005."),
                chain_item(2, 77, 9, "Enrollment failed."),
            ],
            vec![exact_edge(&a, &b, GUID_A)],
        );
        (timeline, a, b)
    }

    fn section<'a>(report: &'a str, heading: &str) -> &'a str {
        let start = report.find(heading).expect("the section exists");
        let rest = &report[start + heading.len()..];
        &report[start..start + heading.len() + rest.find("\n## ").unwrap_or(rest.len())]
    }

    #[test]
    fn a_chain_is_confirmed_against_the_sessions_edges_and_rendered_from_them() {
        let (timeline, a, b) = two_event_timeline();
        let chains = chains_value(
            1,
            (1, 0, 0, 0),
            vec![row(
                "exact",
                &[a.clone(), b.clone()],
                json!([pair(&a, &b, &[("activityId", GUID_A)])]),
            )],
        );
        let report = chain_report_for(&timeline, chains).expect("the chain renders");
        assert!(report.contains("### Chain 1: Exact, 2 entries"), "{report}");
        assert!(report.contains("- Links rest on: ActivityId"));
        assert!(report.contains("- Link evidence (2 lines):"));
        assert!(report.contains(&format!(
            "  - 76 \u{b7} Microsoft-Windows-Fixture/Admin \u{b7} record 1: ActivityId = {GUID_A}"
        )));
        assert!(report.contains(
            "- Span of the listed entries on the timeline: 2026-10-06T10:20:47.123Z to \
             2026-10-06T10:20:56.123Z"
        ));
        assert_eq!(table_rows(section(&report, "## Correlation chains")), 2);
        // The message names the machine; ids carry the machine and a source path.
        assert!(report.contains(&format!("Enrollment started on {}.", host("HOST-0005"))));
        for leak in ["HOST-0005", "CASE-0002", "A.evtx", "machine9", "record1"] {
            assert!(!leaks(&report, leak), "{leak} leaked:\n{report}");
        }
    }

    #[test]
    fn a_reference_the_session_does_not_hold_is_refused_and_named_nowhere() {
        let (timeline, a, b) = two_event_timeline();
        let members = [a.clone(), b.clone()];
        let wrong_value = chains_value(
            1,
            (1, 0, 0, 0),
            vec![row(
                "exact",
                &members,
                json!([pair(
                    &a,
                    &b,
                    &[("activityId", "00000000-0000-4000-8000-0000000000ff")]
                )]),
            )],
        );
        let wrong_kind = chains_value(
            1,
            (1, 0, 0, 0),
            vec![row(
                "exact",
                &members,
                json!([pair(&a, &b, &[("sessionId", GUID_A)])]),
            )],
        );
        let wrong_pair = chains_value(
            1,
            (1, 0, 0, 0),
            vec![row(
                "exact",
                &members,
                json!([pair(&a, &stable(3), &[("activityId", GUID_A)])]),
            )],
        );
        for chains in [wrong_value, wrong_kind, wrong_pair] {
            let error = chain_report_for(&timeline, chains).expect_err("refused");
            assert!(error.contains("does not hold"), "{error}");
            for name in ["HOST-0005", "CASE-0002", GUID_A, "ff"] {
                assert!(!error.contains(name), "{name} in {error}");
            }
        }
        // The pair may be written either way round.
        let reversed = chains_value(
            1,
            (1, 0, 0, 0),
            vec![row(
                "exact",
                &members,
                json!([pair(&b, &a, &[("activityId", GUID_A)])]),
            )],
        );
        assert!(chain_report_for(&timeline, reversed).is_ok());
    }

    #[test]
    fn a_relation_the_engine_calls_ambiguous_or_blocked_is_never_a_chain_link() {
        let (a, b) = (stable(1), stable(2));
        let items = vec![chain_item(1, 76, 0, "m"), chain_item(2, 77, 9, "m")];
        let mut ambiguous = exact_edge(&a, &b, GUID_A);
        ambiguous.strength = TimelineCorrelationStrength::Ambiguous;
        let mut blocked = exact_edge(&a, &b, GUID_A);
        blocked.coverage.state = TimelineCorrelationCoverageState::Gap;
        for bad in [ambiguous, blocked] {
            let timeline = timeline_of(items.clone(), vec![bad]);
            let chains = chains_value(
                1,
                (0, 1, 0, 0),
                vec![row(
                    "candidate",
                    &[a.clone(), b.clone()],
                    json!([pair(&a, &b, &[("activityId", GUID_A)])]),
                )],
            );
            let error = chain_report_for(&timeline, chains).expect_err("refused");
            assert!(error.contains("ambiguous or coverage blocked"), "{error}");
        }
    }

    #[test]
    fn a_chain_is_never_stronger_than_the_edges_it_rests_on() {
        let (a, b) = (stable(1), stable(2));
        let items = vec![chain_item(1, 76, 0, "m"), chain_item(2, 77, 9, "m")];
        let members = [a.clone(), b.clone()];
        let candidate_edge = edge(
            &a,
            &b,
            TimelineCorrelationKeyKind::ActivityId,
            "activityId",
            GUID_A,
            TimelineCorrelationStrength::Candidate,
        );
        let secondary_edge = edge(
            &a,
            &b,
            TimelineCorrelationKeyKind::Secondary,
            "secondary",
            "pid-1",
            TimelineCorrelationStrength::Exact,
        );
        let weak = [
            (candidate_edge.clone(), ("activityId", GUID_A)),
            (secondary_edge.clone(), ("secondary", "pid-1")),
        ];
        for (weaker, key) in weak {
            let timeline = timeline_of(items.clone(), vec![weaker]);
            let exact = chains_value(
                1,
                (1, 0, 0, 0),
                vec![row("exact", &members, json!([pair(&a, &b, &[key])]))],
            );
            let error = chain_report_for(&timeline, exact).expect_err("refused");
            assert!(error.contains("does not label Exact"), "{error}");
        }
        // The same edges are fine under a Candidate row, which prints as Candidate.
        let timeline = timeline_of(items, vec![candidate_edge, secondary_edge]);
        let candidate = chains_value(
            2,
            (0, 1, 0, 0),
            vec![row(
                "candidate",
                &members,
                json!([pair(
                    &a,
                    &b,
                    &[("activityId", GUID_A), ("secondary", "pid-1")]
                )]),
            )],
        );
        let report = chain_report_for(&timeline, candidate).expect("renders");
        assert!(report.contains("### Chain 1: Candidate, 2 entries"));
        assert!(!report.contains("### Chain 1: Exact"));
        assert!(report.contains("- Links rest on: ActivityId, secondary identifier"));
    }

    #[test]
    fn identifier_values_follow_the_print_policy() {
        let (a, b, c) = (stable(1), stable(2), stable(3));
        let provider_value =
            format!("source30:C:\\Cases\\CASE-0002\\A.evtx|provider|HOST-0005|1|{b}");
        let timeline = timeline_of(
            vec![
                chain_item(1, 76, 0, "m"),
                chain_item(2, 77, 9, "m"),
                chain_item(3, 78, 20, "m"),
            ],
            vec![
                exact_edge(&a, &b, GUID_A),
                edge(
                    &a,
                    &b,
                    TimelineCorrelationKeyKind::DeviceId,
                    "deviceId",
                    "DEVICE-0001",
                    TimelineCorrelationStrength::Exact,
                ),
                edge(
                    &a,
                    &b,
                    TimelineCorrelationKeyKind::UserId,
                    "userId",
                    "user_0001",
                    TimelineCorrelationStrength::Exact,
                ),
                // A device value no redaction pattern recognizes (it starts with a parenthesis):
                // the projection leaves it as written, so only the report's own guard stops it.
                edge(
                    &a,
                    &b,
                    TimelineCorrelationKeyKind::DeviceId,
                    "deviceId",
                    "(unpatterned-device)",
                    TimelineCorrelationStrength::Exact,
                ),
                edge(
                    &b,
                    &c,
                    TimelineCorrelationKeyKind::ProviderChannelEventRecord,
                    "providerChannelEventRecord",
                    &provider_value,
                    TimelineCorrelationStrength::Exact,
                ),
                edge(
                    &b,
                    &c,
                    TimelineCorrelationKeyKind::Secondary,
                    "secondary",
                    "HOST-0005|pid-9",
                    TimelineCorrelationStrength::Candidate,
                ),
            ],
        );
        let chains = chains_value(
            6,
            (1, 1, 0, 0),
            vec![
                row(
                    "exact",
                    &[a.clone(), b.clone()],
                    json!([pair(
                        &a,
                        &b,
                        &[
                            ("activityId", GUID_A),
                            ("deviceId", "DEVICE-0001"),
                            ("userId", "user_0001"),
                            ("deviceId", "(unpatterned-device)")
                        ]
                    )]),
                ),
                row(
                    "candidate",
                    &[b.clone(), c.clone()],
                    json!([pair(
                        &b,
                        &c,
                        &[
                            ("providerChannelEventRecord", provider_value.as_str()),
                            ("secondary", "HOST-0005|pid-9")
                        ]
                    )]),
                ),
            ],
        );
        let report = chain_report_for(&timeline, chains).expect("renders");
        for leak in [
            "DEVICE-0001",
            "user_0001",
            "CASE-0002",
            "HOST-0005",
            "pid-9",
            "unpatterned-device",
        ] {
            assert!(!leaks(&report, leak), "{leak} leaked:\n{report}");
        }
        assert!(report.contains(&format!("ActivityId = {GUID_A}")));
        let values = |word: &str| -> Vec<String> {
            report
                .lines()
                .filter_map(|line| line.split(&format!(": {word} = ")).nth(1))
                .map(str::to_owned)
                .collect()
        };
        let is_token =
            |value: &String| value.starts_with('[') && value.ends_with(']') && value.len() > 18;
        // A person or device identifier is printed only as the token the projection made of it,
        // and a value the projection could not mask is not printed at all.
        let users = values("UserId");
        assert!(users.len() == 2 && users.iter().all(is_token), "{users:?}");
        let devices = values("DeviceId");
        assert!(devices.iter().any(is_token), "{devices:?}");
        assert!(devices.contains(&"(masked)".to_owned()), "{devices:?}");
        assert!(report.contains(": provider, channel and record (value not printed)"));
        assert!(report.contains(": secondary identifier (value not printed)"));
    }

    #[test]
    fn the_ladder_says_what_the_chain_list_can_and_cannot_support() {
        let (timeline, a, b) = two_event_timeline();
        let members = [a.clone(), b.clone()];
        let one_row = || {
            row(
                "exact",
                &members,
                json!([pair(&a, &b, &[("activityId", GUID_A)])]),
            )
        };

        let complete =
            chain_report_for(&timeline, chains_value(1, (1, 0, 2, 3), vec![one_row()])).unwrap();
        assert!(complete.contains(
            "- Chains listed: 1 of 1 Exact or Candidate chains the app built (Exact 1, Candidate 0)."
        ));
        assert!(complete.contains("- Built from all 1 correlation edges of the events in scope."));
        assert!(complete.contains(
            "- Not listed as chains (counts only): 2 Ambiguous and 3 Coverage blocked relations."
        ));
        assert!(!complete.contains("may exist"));

        let empty = timeline_of(Vec::new(), Vec::new());
        let none = chain_report_for(&empty, chains_value(0, (0, 0, 0, 0), Vec::new())).unwrap();
        assert!(none.contains(
            "- The engine produced no Exact or Candidate link among the events in scope. Events \
             outside the scope were not considered."
        ));

        // Edges the app did not load: a shortfall is stated with both numbers, and an empty list
        // is not read as "no chains".
        let three_edges = timeline_of(
            Vec::new(),
            vec![
                exact_edge("x1", "x2", "v1"),
                exact_edge("x3", "x4", "v2"),
                exact_edge("x5", "x6", "v3"),
            ],
        );
        let short =
            chain_report_for(&three_edges, chains_value(1, (0, 0, 0, 0), Vec::new())).unwrap();
        assert!(short.contains(
            "- Built from 1 of 3 correlation edges (2 not loaded), so more chains may exist."
        ));
        assert!(short.contains(
            "- No Exact or Candidate chain is listed. The correlation input is incomplete, so \
             this does not show that none exist."
        ));
        assert!(!short.contains("The engine produced no Exact or Candidate link"));
        assert!(short.contains("(counts only, at least): 0 Ambiguous"));

        // The engine's own gaps make an empty list unprovable even when every edge was loaded.
        for gap in ["global", "previewCut"] {
            let mut chains = chains_value(0, (0, 0, 0, 0), Vec::new());
            chains["correlationGaps"][gap] = json!(true);
            let report = chain_report_for(&empty, chains).unwrap();
            assert!(report.contains("did not correlate every event"), "{gap}");
            assert!(!report.contains("The engine produced no Exact or Candidate link"));
            assert!(report.contains("(counts only, at least)"));
        }

        // The app and the session disagree about the edge count.
        let disagree = chain_report_for(&empty, chains_value(4, (0, 0, 0, 0), Vec::new())).unwrap();
        assert!(disagree.contains(
            "- The app reported 4 loaded correlation edges and the session holds 0, so this list \
             cannot be trusted as complete."
        ));

        // Fewer rows than chains: the rest are counted, and nothing says none exist.
        let capped =
            chain_report_for(&timeline, chains_value(1, (3, 0, 0, 0), vec![one_row()])).unwrap();
        assert!(capped.contains("- Chains listed: 1 of 3 Exact or Candidate chains"));
        assert!(capped.contains("The app lists at most 100 chains; 2 are not listed."));
    }

    #[test]
    fn chains_that_were_not_loaded_are_never_reported_as_none() {
        let report = render(&base_request(), &snapshot_of(Vec::new(), 0));
        let chains = section(&report, "## Correlation chains");
        assert!(chains.contains("Correlation chains were not loaded when this report was made."));
        assert!(chains.contains("that says nothing about whether any exist"));
        for claim in [
            "no Exact or Candidate",
            "Chains listed",
            "0 Exact",
            "Built from",
        ] {
            assert!(!chains.contains(claim), "{claim}");
        }
    }

    #[test]
    fn members_and_evidence_are_capped_and_the_rest_counted() {
        let ids: Vec<String> = (1..=50).map(stable).collect();
        let items: Vec<TimelineItem> = (1..=50)
            .map(|record| chain_item(record, 100 + record as u32, record as i64, "m"))
            .collect();
        let edges: Vec<TimelineCorrelationEdge> = (0..5)
            .map(|index| exact_edge(&ids[index], &ids[index + 1], &format!("guid-{index}")))
            .collect();
        let pairs: Vec<serde_json::Value> = (0..5)
            .map(|index| {
                let value = format!("guid-{index}");
                pair(
                    &ids[index],
                    &ids[index + 1],
                    &[("activityId", value.as_str())],
                )
            })
            .collect();
        let timeline = timeline_of(items, edges);
        let chains = chains_value(5, (1, 0, 0, 0), vec![row("exact", &ids, json!(pairs))]);
        let report = chain_report_for(&timeline, chains).expect("renders");
        assert!(report.contains("### Chain 1: Exact, 50 entries"));
        assert!(report.contains("- Link evidence (10 lines):"));
        assert!(report.contains("  - and 2 more evidence lines"));
        assert_eq!(report.matches("\n  - 10").count(), 8);
        assert_eq!(table_rows(section(&report, "## Correlation chains")), 12);
        assert!(report.contains("and 38 more listed entries on the timeline, not shown here"));
    }

    #[test]
    fn entries_the_session_cannot_place_are_counted_and_never_listed() {
        let (mut timeline, a, b) = two_event_timeline();
        let placeless = stable(7);
        timeline.unplaced.push(UnplacedItem {
            origin: chain_item(7, 99, 0, "m").origin,
            reason: UnplacedReason::MissingTimestamp,
        });
        let missing = stable(8);
        let members = [a.clone(), placeless.clone(), missing.clone()];
        let chains = chains_value(
            1,
            (1, 0, 0, 0),
            vec![row(
                "exact",
                &members,
                json!([pair(&a, &b, &[("activityId", GUID_A)])]),
            )],
        );
        let report = chain_report_for(&timeline, chains).expect("renders");
        assert!(report.contains(
            "- Entries: 3 in the chain; the app listed 3. Of those listed, 1 are on the placed \
             timeline, 1 have no usable timestamp and 1 are not in this session."
        ));
        assert_eq!(table_rows(section(&report, "## Correlation chains")), 1);
    }

    #[test]
    fn a_text_log_member_is_named_by_its_file_and_line_only() {
        let (mut timeline, a, _) = two_event_timeline();
        let log_origin = TimelineOrigin::Log {
            file: r"C:\Cases\CASE-0002\Logs\IntuneManagementExtension.log".to_owned(),
            component: Some("Sync".to_owned()),
            line: 12,
            source: "IntuneManagementExtension.log".to_owned(),
            machine: Some("HOST-0005".to_owned()),
            bundle: None,
            record_id: 12,
        };
        let log_id = origin_id(&log_origin);
        timeline.items.push(TimelineItem {
            timestamp_ms: FIXTURE_NOW_MS + 3000,
            severity: TimelineSeverity::Warning,
            message: "Policy sync retried on HOST-0005.".to_owned(),
            origin: log_origin,
        });
        timeline.edges.push(exact_edge(
            &a,
            &log_id,
            "00000000-0000-4000-8000-0000000000b2",
        ));
        let chains = chains_value(
            2,
            (1, 0, 0, 0),
            vec![row(
                "exact",
                &[a.clone(), log_id.clone()],
                json!([pair(
                    &a,
                    &log_id,
                    &[("activityId", "00000000-0000-4000-8000-0000000000b2")]
                )]),
            )],
        );
        let report = chain_report_for(&timeline, chains).expect("renders");
        assert!(report.contains("| log line 12 | IntuneManagementExtension.log | Sync |"));
        assert!(report.contains("IntuneManagementExtension.log \u{b7} line 12: ActivityId ="));
        for leak in ["CASE-0002", "HOST-0005", "Logs\\"] {
            assert!(!leaks(&report, leak), "{leak} leaked:\n{report}");
        }
    }

    #[test]
    fn nearby_context_is_stated_as_not_produced_and_never_as_none() {
        let report = render(&base_request(), &snapshot_of(Vec::new(), 0));
        let nearby = section(&report, "## Nearby, not linked");
        assert_eq!(
            nearby.trim_end(),
            "## Nearby, not linked\n\nNearby context is not produced in this version of the \
             report. This section says nothing about whether nearby events exist, and nothing in \
             this report links two entries by time alone."
        );
        let lower = nearby.to_lowercase();
        for forbidden in ["none", "no nearby", "empty", "0 "] {
            assert!(!lower.contains(forbidden), "{forbidden}");
        }
    }

    #[test]
    fn chain_references_are_bounded_before_any_work_is_done() {
        let (_, a, b) = two_event_timeline();
        let ok_row = || {
            row(
                "exact",
                &[a.clone(), b.clone()],
                json!([pair(&a, &b, &[("activityId", GUID_A)])]),
            )
        };
        let cases: Vec<(&str, serde_json::Value)> = vec![
            (
                "too many chain rows",
                chains_value(
                    1,
                    (200, 0, 0, 0),
                    (0..=REPORT_CHAIN_ROW_CAP).map(|_| ok_row()).collect(),
                ),
            ),
            (
                "more rows than chains counted",
                chains_value(1, (0, 0, 0, 0), vec![ok_row()]),
            ),
            ("too many references", {
                let ids: Vec<String> = (0..51).map(|index| format!("id-{index}")).collect();
                chains_value(1, (1, 0, 0, 0), vec![row("exact", &ids, json!([]))])
            }),
            ("lists more members than it has", {
                let mut value = ok_row();
                value["memberCount"] = json!(1);
                chains_value(1, (1, 0, 0, 0), vec![value])
            }),
            ("a pair is impossible", {
                chains_value(
                    1,
                    (1, 0, 0, 0),
                    vec![row(
                        "exact",
                        &[a.clone(), b.clone()],
                        json!([pair(&a, &a, &[("activityId", GUID_A)])]),
                    )],
                )
            }),
            ("a pair is impossible", {
                chains_value(
                    1,
                    (1, 0, 0, 0),
                    vec![row(
                        "exact",
                        &[a.clone(), b.clone()],
                        json!([pair(&a, &b, &[])]),
                    )],
                )
            }),
            ("an identifier is too long", {
                let long = "x".repeat(2049);
                chains_value(
                    1,
                    (1, 0, 0, 0),
                    vec![row("exact", &[long.clone(), b.clone()], json!([]))],
                )
            }),
        ];
        for (expected, chains) in cases {
            let mut value = request_json();
            value["chains"] = chains;
            let error = request_from(value).validate().expect_err(expected);
            assert!(error.contains(expected), "{expected}: {error}");
        }
        // A row may not claim a strength the type does not have.
        let mut value = request_json();
        value["chains"] = chains_value(1, (1, 0, 0, 0), vec![row("ambiguous", &[], json!([]))]);
        assert!(serde_json::from_value::<EventLogAnalysisReportRequest>(value).is_err());
    }

    #[test]
    fn tokens_the_projection_wrote_are_not_rewritten_by_the_export_pass() {
        // The export pass reads `[account:` as a key named Account and masks what follows it, so
        // running it over projected text would turn the token into `[account:[sensitive:..]]`.
        let mut one = finding(
            "a",
            FindingClass::Symptom,
            FindingSeverity::Info,
            FindingConfidence::Low,
            "Sign-in",
        );
        one.summary = "UserName=jdoe-0001 was rejected".to_owned();
        let summary = summary_of(vec![one], Vec::new());
        let report = render_with(&base_request(), &snapshot_of(Vec::new(), 0), &summary);
        let line = report
            .lines()
            .find(|line| line.starts_with("- Summary: "))
            .unwrap();
        assert!(!line.contains("jdoe-0001"), "{line}");
        assert!(!line.contains("sensitive"), "{line}");
        // The account rule takes the rest of the line as the value, so the token covers it all.
        assert_eq!(
            *line,
            format!(
                "- Summary: UserName={}",
                redact_field_value("account", "jdoe-0001 was rejected")
            )
        );
    }

    #[test]
    fn a_gap_the_engine_lists_once_per_event_is_written_once_with_its_count() {
        let same = |detail: &str| gap("MDM enrollment", CoverageState::Absent, detail);
        let mut gaps: Vec<CoverageGap> = (0..3)
            .map(|index| {
                let mut one = same("No status.");
                one.id = format!("coverage:{index}");
                one
            })
            .collect();
        gaps.push(same("A different detail."));
        let report = render_with(
            &base_request(),
            &snapshot_of(Vec::new(), 0),
            &summary_of(Vec::new(), gaps),
        );
        assert!(report.contains("- Coverage gaps the engine listed (4):"));
        assert!(report.contains("  - absent: MDM enrollment: No status. (3 gaps)\n"));
        assert!(report.contains("  - absent: MDM enrollment: A different detail.\n"));
    }

    #[test]
    fn collect_gathers_the_rows_machines_unplaced_split_and_the_engines_compaction_notes() {
        let mut timeline = timeline_of(
            (0..600)
                .map(|index| chain_item(index + 1, 100, index as i64, "m"))
                .collect(),
            Vec::new(),
        );
        let log_origin = TimelineOrigin::Log {
            file: "a.log".to_owned(),
            component: None,
            line: 1,
            source: "a.log".to_owned(),
            machine: Some("HOST-0006".to_owned()),
            bundle: None,
            record_id: 1,
        };
        timeline.items.push(TimelineItem {
            timestamp_ms: FIXTURE_NOW_MS,
            severity: TimelineSeverity::Info,
            message: "log line".to_owned(),
            origin: log_origin.clone(),
        });
        for origin in [chain_item(900, 1, 0, "m").origin, log_origin] {
            timeline.unplaced.push(UnplacedItem {
                origin,
                reason: UnplacedReason::MissingTimestamp,
            });
        }
        for source in [
            "timeline-message-projection",
            "timeline-item-projection",
            "timeline-transport-projection",
        ] {
            timeline.coverage_gaps.push(TimelineCoverageGap {
                source: source.to_owned(),
                reason: "counts only".to_owned(),
            });
        }
        let snapshot = collect(&timeline, status(600, 1), &base_request()).expect("collects");
        assert_eq!(snapshot.event_rows.len(), REPORT_EVENT_ROW_CAP);
        assert!(snapshot
            .event_rows
            .iter()
            .all(|item| matches!(item.origin, TimelineOrigin::Event { .. })));
        assert_eq!(snapshot.unplaced_events, 1);
        assert_eq!(snapshot.unplaced_text_lines, 1);
        assert_eq!(
            snapshot
                .machines
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["HOST-0005", "HOST-0006"]
        );
        assert!(snapshot.span_ms.is_some());
        assert_eq!(
            snapshot.engine_notes,
            EngineNotes {
                messages_shortened: true,
                items_compacted: true,
                transport_projected: true,
            }
        );

        timeline.coverage_gaps.clear();
        let clean = collect(&timeline, status(600, 1), &base_request()).expect("collects");
        assert_eq!(clean.engine_notes, EngineNotes::default());
        assert!(clean.entries.is_empty() && clean.chains.is_empty());
    }
}
