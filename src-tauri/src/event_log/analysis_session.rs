//! Backend-owned event-log timeline and diagnosis sessions.
//!
//! A large event selection must not be serialized into one monolithic timeline command and then
//! serialized back again for diagnosis. Sessions accept bounded record chunks, immediately project
//! them into compact timeline and diagnosis models, and expose the finalized timeline by page.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use cmtraceopen_parser::diagnosis::{
    CorrelationEdge, CoverageGap, CoverageState, DiagnosisFinding, DiagnosisSummary,
    EventDiagnosis, EventDiagnosisAccumulator, EventDiagnosisProjection, EvidenceRef, FindingClass,
};
use cmtraceopen_parser::models::log_entry::LogEntry;
use cmtraceopen_parser::unified_timeline::{
    TimelineCorrelationEdge, TimelineCoverageGap, TimelineItem, UnifiedTimeline, UnplacedItem,
};
use serde::{Deserialize, Serialize};

use super::commands::{
    append_diagnosis_cap_finding, diagnosis_event_input, diagnosis_finding_for_gap,
    diagnosis_record_identity, evtx_log_entry, timeline_coverage_state,
    validate_diagnosis_coverage_gaps, validate_diagnosis_log_entry, validate_diagnosis_record,
    DiagnosisRecordIdentity, MAX_DIAGNOSIS_ARCHIVE_TEXT_RECORDS, MAX_DIAGNOSIS_EVENT_RECORDS,
    MAX_DIAGNOSIS_TEXT_ENTRIES, MAX_DIAGNOSIS_TIMELINE_EDGES,
};
use super::models::{EvtxCoverageGap, EvtxOriginKind, EvtxRecord, MAX_SAFE_EVENT_RECORD_ID};
use super::timeline::{
    TimelineBuilder, MAX_SERIALIZED_TIMELINE_ITEM_BYTES, TIMELINE_ITEM_PROJECTION_SOURCE,
    TIMELINE_MESSAGE_PROJECTION_SOURCE,
};
use crate::state::app_state::AppState;

const MAX_ANALYSIS_TIMELINE_PAGE_ITEMS: usize = 1_000;
const MAX_ANALYSIS_TIMELINE_PAGE_BYTES: usize = 8 * 1024 * 1024;
const MAX_ANALYSIS_TIMELINE_PREVIEW_BYTES: usize = 512 * 1024;
const MAX_ANALYSIS_TIMELINE_PREVIEW_ITEMS: usize = 100;
const MAX_DIAGNOSIS_RESPONSE_ROWS: usize = 100;
const MAX_ANALYSIS_SESSION_ID_BYTES: usize = 128;
const DIAGNOSIS_RESPONSE_PROJECTION_SOURCE: &str = "diagnosis-response-projection";
const MAX_DIAGNOSIS_RETAINED_EVENT_BYTES: usize = 16 * 1024 * 1024;
const MAX_DIAGNOSIS_RETAINED_TEXT_FINDING_BYTES: usize = 4 * 1024 * 1024;
const TEXT_DIAGNOSIS_PROJECTION_SOURCE: &str = "text-diagnosis-projection";
const MAX_DIAGNOSIS_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MAX_DIAGNOSIS_DISPLAY_TEXT_BYTES: usize = 4 * 1024;
const MAX_DIAGNOSIS_NESTED_ROWS: usize = 4;
const MAX_ANALYSIS_APPEND_ROWS: usize = 1_000;
const MAX_ANALYSIS_APPEND_BYTES: usize = 8 * 1024 * 1024;
const DIAGNOSIS_INPUT_PROJECTION_SOURCE: &str = "diagnosis-input-projection";
const TIMELINE_TRANSPORT_PROJECTION_SOURCE: &str = "timeline-transport-projection";
const MAX_ANALYSIS_SESSIONS: usize = 16;
const ANALYSIS_SESSION_IDLE_TTL: Duration = Duration::from_secs(60 * 60);

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EventLogAnalysisSessionStatus {
    pub session_id: String,
    pub revision: u64,
    pub total_items: u64,
    pub event_items: u64,
    pub log_items: u64,
    pub total_unplaced: u64,
    pub total_edges: u64,
    pub total_coverage_gaps: u64,
    pub finalized: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EventLogAnalysisTimelinePage {
    pub session_id: String,
    pub revision: u64,
    pub offset: u64,
    pub next_offset: Option<u64>,
    pub total_items: u64,
    pub event_items: u64,
    pub log_items: u64,
    pub total_unplaced: u64,
    pub total_edges: u64,
    pub total_coverage_gaps: u64,
    pub items: Vec<TimelineItem>,
    pub unplaced_preview: Vec<UnplacedItem>,
    pub edges_preview: Vec<TimelineCorrelationEdge>,
    pub coverage_gaps_preview: Vec<TimelineCoverageGap>,
    pub serialized_bytes: u64,
}

/// Timeline items whose `timestampMs` lies in the closed interval `[startMs, endMs]`.
///
/// `items` is the longest byte-bounded prefix of the window, in the same order as
/// `EventLogAnalysisTimelinePage::items`, so it is exactly the slice of the concatenated pages that
/// starts at `offset`. Nothing inside the window is skipped: whatever does not fit is counted in
/// `omittedItems`, and `nextOffset` is the timeline offset of the first omitted item.
///
/// To continue a truncated window, loop: `remaining = omittedItems`, `offset = nextOffset`; while
/// `remaining > 0`, call `page(offset, min(limit, remaining))`, subtract the rows it returned from
/// `remaining` and continue from its `nextOffset`. The byte budget can cut a page short, so this
/// can take more than one call. Never re-window from the last returned timestamp: items tied on
/// that timestamp would be repeated or dropped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EventLogAnalysisTimelineWindow {
    pub session_id: String,
    pub revision: u64,
    pub start_ms: i64,
    pub end_ms: i64,
    /// Timeline offset of the first item at or after `startMs`. When the window holds no items this
    /// is the position where the window would begin, and `items` is empty.
    pub offset: u64,
    /// Timeline offset of the first in-window item that was left out, or `null` when none was.
    pub next_offset: Option<u64>,
    pub total_items: u64,
    /// Every item inside the window, returned or not.
    pub window_items: u64,
    /// In-window items left out by the item limit or the byte budget.
    pub omitted_items: u64,
    pub items: Vec<TimelineItem>,
    pub serialized_bytes: u64,
}

/// A byte-bounded slice of `UnifiedTimeline::edges`.
///
/// The edge order is the order `correlate_origins` produced at finalize: exact and ambiguous
/// relations in ascending relation-key order, then candidate relations in the same order. The list
/// is immutable once the session is finalized, so offsets are stable for a given `revision`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EventLogAnalysisEdgePage {
    pub session_id: String,
    pub revision: u64,
    pub offset: u64,
    pub next_offset: Option<u64>,
    pub total_edges: u64,
    pub edges: Vec<TimelineCorrelationEdge>,
    pub serialized_bytes: u64,
}

pub(crate) type SharedEventLogAnalysisSession = Arc<Mutex<EventLogAnalysisSession>>;

pub(crate) struct EventLogAnalysisSessionEntry {
    session: SharedEventLogAnalysisSession,
    last_access: Instant,
}

pub(crate) type EventLogAnalysisSessionRegistry = HashMap<String, EventLogAnalysisSessionEntry>;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EventLogAnalysisRecordInput {
    pub record: EvtxRecord,
    pub original_serialized_bytes: Option<u64>,
}

impl EventLogAnalysisRecordInput {
    #[cfg(test)]
    fn complete(record: EvtxRecord) -> Self {
        Self {
            record,
            original_serialized_bytes: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EventLogAnalysisLogEntryInput {
    pub entry: LogEntry,
    pub original_serialized_bytes: Option<u64>,
}

impl EventLogAnalysisLogEntryInput {
    #[cfg(test)]
    fn complete(entry: LogEntry) -> Self {
        Self {
            entry,
            original_serialized_bytes: None,
        }
    }
}

pub(crate) struct EventLogAnalysisSession {
    id: String,
    revision: u64,
    builder: Option<TimelineBuilder>,
    timeline: Option<UnifiedTimeline>,
    finalized_timeline_counts: (usize, usize, usize),
    diagnosis_events: EventDiagnosisAccumulator,
    diagnosis_text_findings: Vec<DiagnosisFinding>,
    diagnosis_text_finding_bytes: usize,
    omitted_text_finding_count: usize,
    omitted_text_finding_bytes: usize,
    identity_gap_counts: BTreeMap<String, usize>,
    diagnosis_input_gap_counts: BTreeMap<String, usize>,
    projected_row_count: usize,
    projected_original_bytes: u64,
    projected_retained_bytes: u64,
    admitted_archive_text_records: usize,
    admitted_text_entries: usize,
    omitted_archive_text_records: usize,
    omitted_text_entries: usize,
}

impl EventLogAnalysisSession {
    fn new(id: String) -> Self {
        Self::with_diagnosis_limit(id, MAX_DIAGNOSIS_EVENT_RECORDS)
    }

    fn with_diagnosis_limit(id: String, relevant_event_limit: usize) -> Self {
        Self {
            id,
            revision: 0,
            builder: Some(TimelineBuilder::default()),
            timeline: None,
            finalized_timeline_counts: (0, 0, 0),
            diagnosis_events: EventDiagnosisAccumulator::new(
                relevant_event_limit,
                MAX_DIAGNOSIS_RETAINED_EVENT_BYTES,
            ),
            diagnosis_text_findings: Vec::new(),
            diagnosis_text_finding_bytes: 0,
            omitted_text_finding_count: 0,
            omitted_text_finding_bytes: 0,
            identity_gap_counts: BTreeMap::new(),
            diagnosis_input_gap_counts: BTreeMap::new(),
            projected_row_count: 0,
            projected_original_bytes: 0,
            projected_retained_bytes: 0,
            admitted_archive_text_records: 0,
            admitted_text_entries: 0,
            omitted_archive_text_records: 0,
            omitted_text_entries: 0,
        }
    }

    #[cfg(test)]
    fn append(
        &mut self,
        records: Vec<EvtxRecord>,
        entries: Vec<LogEntry>,
    ) -> Result<EventLogAnalysisSessionStatus, String> {
        self.append_inputs(
            records
                .into_iter()
                .map(EventLogAnalysisRecordInput::complete)
                .collect(),
            entries
                .into_iter()
                .map(EventLogAnalysisLogEntryInput::complete)
                .collect(),
        )
    }

    fn append_inputs(
        &mut self,
        records: Vec<EventLogAnalysisRecordInput>,
        entries: Vec<EventLogAnalysisLogEntryInput>,
    ) -> Result<EventLogAnalysisSessionStatus, String> {
        if self.timeline.is_some() {
            return Err("event-log analysis session is already finalized".to_string());
        }
        validate_analysis_chunk(&records, &entries)?;
        let identities = records
            .iter()
            .map(|input| diagnosis_record_identity(&input.record))
            .collect::<Vec<_>>();
        if self.builder.is_none() {
            return Err("event-log analysis session has no active builder".to_string());
        }

        for (input, identity) in records.into_iter().zip(identities) {
            let EventLogAnalysisRecordInput {
                mut record,
                original_serialized_bytes,
            } = input;
            let relevant_event = matches!(record.origin_kind, EvtxOriginKind::Event)
                && !matches!(
                    cmtraceopen_parser::diagnosis::event_family_from_source(
                        &record.channel,
                        &record.provider,
                        &record.message,
                    ),
                    cmtraceopen_parser::diagnosis::EventFamily::Other
                );
            if let Some(original_serialized_bytes) = original_serialized_bytes {
                let retained_bytes = serde_json::to_vec(&record)
                    .map_err(|error| {
                        format!("projected event record serialization failed: {error}")
                    })?
                    .len();
                self.projected_row_count += 1;
                self.projected_original_bytes = self
                    .projected_original_bytes
                    .saturating_add(original_serialized_bytes);
                self.projected_retained_bytes = self
                    .projected_retained_bytes
                    .saturating_add(usize_to_u64(retained_bytes));
            }
            if matches!(record.origin_kind, EvtxOriginKind::Event) {
                if let DiagnosisRecordIdentity::Malformed { detail } = &identity {
                    *self.identity_gap_counts.entry(detail.clone()).or_default() += 1;
                    sanitize_malformed_timeline_record(&mut record);
                    self.builder
                        .as_mut()
                        .expect("active builder checked above")
                        .push_event_record(&record);
                    continue;
                }
            }
            self.builder
                .as_mut()
                .expect("active builder checked above")
                .push_event_record(&record);

            match record.origin_kind {
                EvtxOriginKind::Event => {
                    if relevant_event {
                        let mut diagnosis_bytes = 0usize;
                        if let Err(detail) =
                            validate_diagnosis_record(&record, &mut diagnosis_bytes)
                        {
                            *self.diagnosis_input_gap_counts.entry(detail).or_default() += 1;
                            continue;
                        }
                    }
                    match diagnosis_event_input(record, &identity) {
                        Ok(input) => {
                            self.diagnosis_events.push_with_record_id_text(
                                input.entry,
                                &input.event_data,
                                &input.raw_xml,
                                input.record_id_text.as_deref(),
                            );
                        }
                        Err(_) => {
                            return Err(
                                "validated event identity was unexpectedly rejected by diagnosis"
                                    .to_string(),
                            )
                        }
                    }
                }
                EvtxOriginKind::Log => {
                    if self.admitted_archive_text_records >= MAX_DIAGNOSIS_ARCHIVE_TEXT_RECORDS {
                        self.omitted_archive_text_records += 1;
                        continue;
                    }
                    self.admitted_archive_text_records += 1;
                    let mut diagnosis_bytes = 0usize;
                    if let Err(detail) = validate_diagnosis_record(&record, &mut diagnosis_bytes) {
                        *self.diagnosis_input_gap_counts.entry(detail).or_default() += 1;
                        continue;
                    }
                    if let Some(finding) =
                        cmtraceopen_parser::diagnosis::adapt_log_entry(evtx_log_entry(record))
                    {
                        self.retain_text_finding(finding)?;
                    }
                }
            }
        }

        for input in entries {
            let EventLogAnalysisLogEntryInput {
                entry,
                original_serialized_bytes,
            } = input;
            if let Some(original_serialized_bytes) = original_serialized_bytes {
                let retained_bytes = serde_json::to_vec(&entry)
                    .map_err(|error| format!("projected log entry serialization failed: {error}"))?
                    .len();
                self.projected_row_count += 1;
                self.projected_original_bytes = self
                    .projected_original_bytes
                    .saturating_add(original_serialized_bytes);
                self.projected_retained_bytes = self
                    .projected_retained_bytes
                    .saturating_add(usize_to_u64(retained_bytes));
            }
            self.builder
                .as_mut()
                .expect("active builder checked above")
                .push_log_entry(&entry);
            if self.admitted_text_entries >= MAX_DIAGNOSIS_TEXT_ENTRIES {
                self.omitted_text_entries += 1;
                continue;
            }
            self.admitted_text_entries += 1;
            let mut diagnosis_bytes = 0usize;
            if let Err(detail) = validate_diagnosis_log_entry(&entry, &mut diagnosis_bytes) {
                *self.diagnosis_input_gap_counts.entry(detail).or_default() += 1;
                continue;
            }
            if let Some(finding) = cmtraceopen_parser::diagnosis::adapt_log_entry(entry) {
                self.retain_text_finding(finding)?;
            }
        }

        self.revision = self.revision.saturating_add(1);
        Ok(self.status())
    }

    fn retain_text_finding(&mut self, finding: DiagnosisFinding) -> Result<(), String> {
        let serialized_bytes = serde_json::to_vec(&finding)
            .map_err(|error| format!("text diagnosis finding serialization failed: {error}"))?
            .len();
        if self
            .diagnosis_text_finding_bytes
            .saturating_add(serialized_bytes)
            > MAX_DIAGNOSIS_RETAINED_TEXT_FINDING_BYTES
        {
            self.omitted_text_finding_count += 1;
            self.omitted_text_finding_bytes = self
                .omitted_text_finding_bytes
                .saturating_add(serialized_bytes);
            return Ok(());
        }
        self.diagnosis_text_finding_bytes = self
            .diagnosis_text_finding_bytes
            .saturating_add(serialized_bytes);
        self.diagnosis_text_findings.push(finding);
        Ok(())
    }

    fn finalize(&mut self) -> Result<EventLogAnalysisSessionStatus, String> {
        if self.timeline.is_none() {
            let builder = self
                .builder
                .take()
                .ok_or_else(|| "event-log analysis session has no active builder".to_string())?;
            self.finalized_timeline_counts = builder.counts();
            let mut timeline = builder.finish();
            if self.projected_row_count > 0 {
                timeline.coverage_gaps.push(TimelineCoverageGap {
                    source: TIMELINE_TRANSPORT_PROJECTION_SOURCE.to_string(),
                    reason: format!(
                        "timeline transport projection affected {} rows totaling {} original serialized bytes and {} retained bytes; omitted identity or derived fields may limit correlation while full records remain in the event grid or log view",
                        self.projected_row_count,
                        self.projected_original_bytes,
                        self.projected_retained_bytes,
                    ),
                });
            }
            timeline
                .coverage_gaps
                .extend(self.identity_gap_counts.iter().map(|(detail, count)| {
                    TimelineCoverageGap {
                        source: "event-record-identity".to_string(),
                        reason: grouped_identity_gap_detail(detail, *count),
                    }
                }));
            self.timeline = Some(timeline);
            self.revision = self.revision.saturating_add(1);
        }
        Ok(self.status())
    }

    fn status(&self) -> EventLogAnalysisSessionStatus {
        let (event_items, log_items, total_unplaced, total_edges, total_coverage_gaps) =
            if let Some(timeline) = self.timeline.as_ref() {
                let (event_items, log_items, total_unplaced) = self.finalized_timeline_counts;
                (
                    event_items,
                    log_items,
                    total_unplaced,
                    timeline.edges.len(),
                    timeline.coverage_gaps.len(),
                )
            } else {
                let (event_items, log_items, total_unplaced) = self
                    .builder
                    .as_ref()
                    .map(TimelineBuilder::counts)
                    .unwrap_or_default();
                (
                    event_items,
                    log_items,
                    total_unplaced,
                    0,
                    self.identity_gap_counts.len(),
                )
            };
        EventLogAnalysisSessionStatus {
            session_id: self.id.clone(),
            revision: self.revision,
            total_items: usize_to_u64(event_items.saturating_add(log_items)),
            event_items: usize_to_u64(event_items),
            log_items: usize_to_u64(log_items),
            total_unplaced: usize_to_u64(total_unplaced),
            total_edges: usize_to_u64(total_edges),
            total_coverage_gaps: usize_to_u64(total_coverage_gaps),
            finalized: self.timeline.is_some(),
        }
    }

    fn page(&self, offset: u64, limit: u32) -> Result<EventLogAnalysisTimelinePage, String> {
        let timeline = self.finalized_timeline()?;
        let limit = validated_timeline_limit(limit, "timeline page")?;
        let start = validated_timeline_offset(offset, "timeline page")?.min(timeline.items.len());
        let requested_end = start.saturating_add(limit).min(timeline.items.len());
        let status = self.status();
        let include_previews = offset == 0;
        let mut preview_bytes = MAX_ANALYSIS_TIMELINE_PREVIEW_BYTES.saturating_sub(4_096);
        let unplaced_preview = if include_previews {
            bounded_preview(timeline.unplaced.iter(), &mut preview_bytes)
        } else {
            Vec::new()
        };
        let edges_preview = if include_previews {
            bounded_preview(timeline.edges.iter(), &mut preview_bytes)
        } else {
            Vec::new()
        };
        let coverage_gaps_preview = if include_previews {
            bounded_preview(timeline.coverage_gaps.iter(), &mut preview_bytes)
        } else {
            Vec::new()
        };
        let mut page = EventLogAnalysisTimelinePage {
            session_id: status.session_id,
            revision: status.revision,
            offset: usize_to_u64(start),
            // Reserve the longest serialized u64 while selecting items. The actual value is set
            // after the variable-size page boundary is known.
            next_offset: Some(u64::MAX),
            total_items: status.total_items,
            event_items: status.event_items,
            log_items: status.log_items,
            total_unplaced: status.total_unplaced,
            total_edges: status.total_edges,
            total_coverage_gaps: status.total_coverage_gaps,
            items: Vec::new(),
            unplaced_preview,
            edges_preview,
            coverage_gaps_preview,
            // Reserve the longest serialized u64 while selecting items. The exact self-inclusive
            // response size is fixed after `nextOffset` is known.
            serialized_bytes: u64::MAX,
        };

        let empty_page_bytes = serialized_len(&page)?;
        let candidates = &timeline.items[start..requested_end];
        let selected = select_bounded_prefix(
            candidates,
            empty_page_bytes,
            MAX_SERIALIZED_TIMELINE_ITEM_BYTES,
            "timeline item",
        )?;
        page.items.extend_from_slice(&candidates[..selected]);

        let end = start.saturating_add(page.items.len());
        page.next_offset = (end < timeline.items.len()).then(|| usize_to_u64(end));
        converge_serialized_bytes(
            &mut page,
            |value| value.serialized_bytes,
            |value, bytes| value.serialized_bytes = bytes,
        )?;
        if usize::try_from(page.serialized_bytes).unwrap_or(usize::MAX)
            > MAX_ANALYSIS_TIMELINE_PAGE_BYTES
        {
            return Err("timeline page projection exceeded its serialized byte budget".to_string());
        }
        Ok(page)
    }

    fn finalized_timeline(&self) -> Result<&UnifiedTimeline, String> {
        self.timeline
            .as_ref()
            .ok_or_else(|| "event-log analysis session is not finalized".to_string())
    }

    /// Items with `start_ms <= timestampMs <= end_ms`, located by binary search.
    ///
    /// `UnifiedTimeline::items` is sorted by `timestampMs` ascending (`merge` in the parser crate,
    /// called from `TimelineBuilder::finish`), so both window edges are partition points and the
    /// window is one contiguous range of the timeline.
    ///
    /// A truncated window continues with a loop over `page(offset, min(limit, remaining))`, starting
    /// at `next_offset` with `remaining = omitted_items` and subtracting each page's row count
    /// (see `EventLogAnalysisTimelineWindow`). Never re-window from the last returned timestamp
    /// (ties would repeat or drop items).
    fn window(
        &self,
        start_ms: i64,
        end_ms: i64,
        limit: u32,
    ) -> Result<EventLogAnalysisTimelineWindow, String> {
        let timeline = self.finalized_timeline()?;
        let limit = validated_timeline_limit(limit, "timeline window")?;
        if start_ms > end_ms {
            return Err("timeline window start must not be after its end".to_string());
        }
        let first = timeline
            .items
            .partition_point(|item| item.timestamp_ms < start_ms);
        let after_last = timeline
            .items
            .partition_point(|item| item.timestamp_ms <= end_ms);
        let requested_end = first.saturating_add(limit).min(after_last);
        let status = self.status();
        let mut window = EventLogAnalysisTimelineWindow {
            session_id: status.session_id,
            revision: status.revision,
            start_ms,
            end_ms,
            offset: usize_to_u64(first),
            // Reserve the widest serialized u64 while selecting items; the real values are set
            // once the boundary is known.
            next_offset: Some(u64::MAX),
            total_items: status.total_items,
            window_items: usize_to_u64(after_last - first),
            omitted_items: u64::MAX,
            items: Vec::new(),
            serialized_bytes: u64::MAX,
        };
        let empty_bytes = serialized_len(&window)?;
        let candidates = &timeline.items[first..requested_end];
        let selected = select_bounded_prefix(
            candidates,
            empty_bytes,
            MAX_SERIALIZED_TIMELINE_ITEM_BYTES,
            "timeline item",
        )?;
        window.items.extend_from_slice(&candidates[..selected]);
        let end = first + selected;
        window.next_offset = (end < after_last).then(|| usize_to_u64(end));
        window.omitted_items = usize_to_u64(after_last - end);
        converge_serialized_bytes(
            &mut window,
            |value| value.serialized_bytes,
            |value, bytes| value.serialized_bytes = bytes,
        )?;
        if usize::try_from(window.serialized_bytes).unwrap_or(usize::MAX)
            > MAX_ANALYSIS_TIMELINE_PAGE_BYTES
        {
            return Err(
                "timeline window projection exceeded its serialized byte budget".to_string(),
            );
        }
        Ok(window)
    }

    /// Edges `[offset, offset + limit)`, trimmed to the shared page byte budget.
    fn edge_page(&self, offset: u64, limit: u32) -> Result<EventLogAnalysisEdgePage, String> {
        let timeline = self.finalized_timeline()?;
        let limit = validated_timeline_limit(limit, "edge page")?;
        let start = validated_timeline_offset(offset, "edge page")?.min(timeline.edges.len());
        let requested_end = start.saturating_add(limit).min(timeline.edges.len());
        let status = self.status();
        let mut page = EventLogAnalysisEdgePage {
            session_id: status.session_id,
            revision: status.revision,
            offset: usize_to_u64(start),
            next_offset: Some(u64::MAX),
            total_edges: status.total_edges,
            edges: Vec::new(),
            serialized_bytes: u64::MAX,
        };
        let empty_bytes = serialized_len(&page)?;
        let candidates = &timeline.edges[start..requested_end];
        let selected = select_bounded_prefix(
            candidates,
            empty_bytes,
            MAX_ANALYSIS_TIMELINE_PAGE_BYTES,
            "correlation edge",
        )?;
        page.edges.extend_from_slice(&candidates[..selected]);
        let end = start + selected;
        page.next_offset = (end < timeline.edges.len()).then(|| usize_to_u64(end));
        converge_serialized_bytes(
            &mut page,
            |value| value.serialized_bytes,
            |value, bytes| value.serialized_bytes = bytes,
        )?;
        if usize::try_from(page.serialized_bytes).unwrap_or(usize::MAX)
            > MAX_ANALYSIS_TIMELINE_PAGE_BYTES
        {
            return Err("edge page projection exceeded its serialized byte budget".to_string());
        }
        Ok(page)
    }

    fn diagnosis_snapshot(&self) -> Result<DiagnosisSnapshot, String> {
        let timeline = self.finalized_timeline()?;
        Ok(DiagnosisSnapshot {
            event_projection: self.diagnosis_events.clone().finish(),
            text_findings: self.diagnosis_text_findings.clone(),
            identity_findings: self
                .identity_gap_counts
                .iter()
                .map(|(detail, count)| {
                    super::commands::diagnosis_identity_finding(grouped_identity_gap_detail(
                        detail, *count,
                    ))
                })
                .collect(),
            diagnosis_input_findings: {
                let mut findings = self
                    .diagnosis_input_gap_counts
                    .iter()
                    .map(|(detail, count)| {
                        cmtraceopen_parser::diagnosis::finding_for_coverage(
                            DIAGNOSIS_INPUT_PROJECTION_SOURCE,
                            CoverageState::Capped,
                            format!(
                                "{count} diagnosis-relevant records were omitted because {detail}."
                            ),
                        )
                    })
                    .collect::<Vec<_>>();
                if self.projected_row_count > 0 {
                    findings.push(cmtraceopen_parser::diagnosis::finding_for_coverage(
                        DIAGNOSIS_INPUT_PROJECTION_SOURCE,
                        CoverageState::Capped,
                        format!(
                            "{} rows totaling {} original serialized bytes were transport-projected to {} bytes; diagnosis used their bounded projected fields and cannot prove omitted fields were neutral.",
                            self.projected_row_count,
                            self.projected_original_bytes,
                            self.projected_retained_bytes,
                        ),
                    ));
                }
                findings
            },
            timeline_edges: timeline
                .edges
                .iter()
                .take(MAX_DIAGNOSIS_TIMELINE_EDGES)
                .cloned()
                .collect(),
            timeline_edge_count: timeline.edges.len(),
            timeline_coverage_gaps: timeline
                .coverage_gaps
                .iter()
                .filter(|gap| {
                    gap.source != "event-record-identity"
                        && gap.source != TIMELINE_ITEM_PROJECTION_SOURCE
                        && gap.source != TIMELINE_MESSAGE_PROJECTION_SOURCE
                        && gap.source != TIMELINE_TRANSPORT_PROJECTION_SOURCE
                })
                .cloned()
                .collect(),
            omitted_archive_text_records: self.omitted_archive_text_records,
            omitted_text_entries: self.omitted_text_entries,
            retained_text_finding_count: self.diagnosis_text_findings.len(),
            retained_text_finding_bytes: self.diagnosis_text_finding_bytes,
            omitted_text_finding_count: self.omitted_text_finding_count,
            omitted_text_finding_bytes: self.omitted_text_finding_bytes,
        })
    }
}

struct DiagnosisSnapshot {
    event_projection: EventDiagnosisProjection,
    text_findings: Vec<DiagnosisFinding>,
    identity_findings: Vec<DiagnosisFinding>,
    diagnosis_input_findings: Vec<DiagnosisFinding>,
    timeline_edges: Vec<TimelineCorrelationEdge>,
    timeline_edge_count: usize,
    timeline_coverage_gaps: Vec<TimelineCoverageGap>,
    omitted_archive_text_records: usize,
    omitted_text_entries: usize,
    retained_text_finding_count: usize,
    retained_text_finding_bytes: usize,
    omitted_text_finding_count: usize,
    omitted_text_finding_bytes: usize,
}

impl DiagnosisSnapshot {
    fn summarize(self, coverage_gaps: Vec<EvtxCoverageGap>) -> DiagnosisSummary {
        let mut findings = self.text_findings;
        findings.extend(coverage_gaps.into_iter().map(diagnosis_finding_for_gap));
        findings.extend(self.identity_findings);
        findings.extend(self.diagnosis_input_findings);
        findings.extend(self.timeline_coverage_gaps.iter().map(|gap| {
            cmtraceopen_parser::diagnosis::finding_for_coverage(
                format!("timeline:{}", gap.source),
                timeline_coverage_state(&gap.reason),
                gap.reason.clone(),
            )
        }));
        append_diagnosis_cap_finding(
            &mut findings,
            "archive-text-records",
            self.omitted_archive_text_records,
            MAX_DIAGNOSIS_ARCHIVE_TEXT_RECORDS,
            "archive text records",
        );
        append_diagnosis_cap_finding(
            &mut findings,
            "text-entries",
            self.omitted_text_entries,
            MAX_DIAGNOSIS_TEXT_ENTRIES,
            "supplied text entries",
        );
        append_diagnosis_cap_finding(
            &mut findings,
            "timeline-correlation-edges",
            self.timeline_edge_count
                .saturating_sub(MAX_DIAGNOSIS_TIMELINE_EDGES),
            MAX_DIAGNOSIS_TIMELINE_EDGES,
            "timeline correlation edges",
        );
        if self.omitted_text_finding_count > 0 {
            findings.push(cmtraceopen_parser::diagnosis::finding_for_coverage(
                TEXT_DIAGNOSIS_PROJECTION_SOURCE,
                CoverageState::Capped,
                format!(
                    "{} text-log diagnosis findings ({} serialized bytes) were omitted after retaining {} findings ({} serialized bytes) within the {}-byte diagnosis budget.",
                    self.omitted_text_finding_count,
                    self.omitted_text_finding_bytes,
                    self.retained_text_finding_count,
                    self.retained_text_finding_bytes,
                    MAX_DIAGNOSIS_RETAINED_TEXT_FINDING_BYTES,
                ),
            ));
        }
        let correlations = self
            .timeline_edges
            .iter()
            .map(cmtraceopen_parser::diagnosis::adapt_timeline_edge)
            .collect();
        let summary = self.event_projection.into_summary(findings, correlations);
        bound_diagnosis_response(summary)
    }
}

fn sanitize_malformed_timeline_record(record: &mut EvtxRecord) {
    record.activity_id = None;
    record.related_activity_id = None;
    record.session_id = None;
    record.device_id = None;
    record.user_id = None;
    record.user_sid = None;
    record.process_id = None;
    record.process_start_time = None;
    record.event_data.clear();
    record.mapped.clear();
    record.raw_xml.clear();
    if record.event_record_id > 0 && record.event_record_id <= MAX_SAFE_EVENT_RECORD_ID {
        record.event_record_id_text = Some(record.event_record_id.to_string());
    } else {
        record.event_record_id = 0;
        record.event_record_id_text = None;
    }
}

fn serialized_array_bytes<'a, T: Serialize + 'a>(
    rows: impl IntoIterator<Item = &'a T>,
) -> Result<usize, String> {
    let mut serialized_bytes = 2usize;
    for (index, row) in rows.into_iter().enumerate() {
        let row_bytes = serde_json::to_vec(row)
            .map_err(|error| format!("event-log analysis row serialization failed: {error}"))?
            .len();
        serialized_bytes = serialized_bytes
            .saturating_add(usize::from(index > 0))
            .saturating_add(row_bytes);
    }
    Ok(serialized_bytes)
}

fn validate_analysis_chunk(
    records: &[EventLogAnalysisRecordInput],
    entries: &[EventLogAnalysisLogEntryInput],
) -> Result<(), String> {
    let row_count = records.len().saturating_add(entries.len());
    if row_count > MAX_ANALYSIS_APPEND_ROWS {
        return Err(format!(
            "event-log analysis chunk contains {row_count} rows; at most {MAX_ANALYSIS_APPEND_ROWS} are allowed"
        ));
    }
    for input in records {
        if let Some(original_serialized_bytes) = input.original_serialized_bytes {
            if original_serialized_bytes == 0
                || original_serialized_bytes > MAX_SAFE_EVENT_RECORD_ID
            {
                return Err(
                    "projected record originalSerializedBytes must be a positive JavaScript-safe integer"
                        .to_string(),
                );
            }
            let retained_bytes = usize_to_u64(
                serde_json::to_vec(&input.record)
                    .map_err(|error| {
                        format!("projected event record serialization failed: {error}")
                    })?
                    .len(),
            );
            if original_serialized_bytes <= retained_bytes {
                return Err(
                    "projected record originalSerializedBytes must exceed the retained record size"
                        .to_string(),
                );
            }
        }
    }
    for input in entries {
        if let Some(original_serialized_bytes) = input.original_serialized_bytes {
            if original_serialized_bytes == 0
                || original_serialized_bytes > MAX_SAFE_EVENT_RECORD_ID
            {
                return Err(
                    "projected log entry originalSerializedBytes must be a positive JavaScript-safe integer"
                        .to_string(),
                );
            }
            let retained_bytes = usize_to_u64(
                serde_json::to_vec(&input.entry)
                    .map_err(|error| format!("projected log entry serialization failed: {error}"))?
                    .len(),
            );
            if original_serialized_bytes <= retained_bytes {
                return Err(
                    "projected log entry originalSerializedBytes must exceed the retained entry size"
                        .to_string(),
                );
            }
        }
    }
    let serialized_bytes = if records.is_empty() {
        serialized_array_bytes(entries)?
    } else if entries.is_empty() {
        serialized_array_bytes(records)?
    } else {
        serialized_array_bytes(records)?.saturating_add(serialized_array_bytes(entries)?)
    };
    if serialized_bytes > MAX_ANALYSIS_APPEND_BYTES {
        return Err(format!(
            "event-log analysis chunk exceeds the {MAX_ANALYSIS_APPEND_BYTES}-byte envelope limit"
        ));
    }
    Ok(())
}

fn grouped_identity_gap_detail(detail: &str, count: usize) -> String {
    let label = if count == 1 {
        "record was"
    } else {
        "records were"
    };
    format!(
        "{count} event {label} excluded from diagnosis because {detail}; timeline rows were retained."
    )
}

#[derive(Default)]
struct DiagnosisDisplayProjectionStats {
    compacted_text_fields: usize,
    omitted_nested_rows: usize,
}

fn display_text_digest(value: &str) -> String {
    let mut digest = 2_166_136_261_u32;
    for &byte in value.as_bytes() {
        digest = (digest ^ u32::from(byte)).wrapping_mul(16_777_619);
    }
    format!("{digest:08x}")
}

fn compact_display_text(value: &mut String, stats: &mut DiagnosisDisplayProjectionStats) {
    if value.len() <= MAX_DIAGNOSIS_DISPLAY_TEXT_BYTES {
        return;
    }
    let suffix = format!(
        "...[{} bytes; digest={}]",
        value.len(),
        display_text_digest(value)
    );
    let mut end = MAX_DIAGNOSIS_DISPLAY_TEXT_BYTES.saturating_sub(suffix.len());
    end = end.min(value.len());
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value.truncate(end);
    value.push_str(&suffix);
    stats.compacted_text_fields += 1;
}

fn compact_optional_display_text(
    value: &mut Option<String>,
    stats: &mut DiagnosisDisplayProjectionStats,
) {
    if let Some(value) = value {
        compact_display_text(value, stats);
    }
}

fn truncate_nested<T>(rows: &mut Vec<T>, stats: &mut DiagnosisDisplayProjectionStats) {
    if rows.len() > MAX_DIAGNOSIS_NESTED_ROWS {
        stats.omitted_nested_rows += rows.len() - MAX_DIAGNOSIS_NESTED_ROWS;
        rows.truncate(MAX_DIAGNOSIS_NESTED_ROWS);
    }
}

fn compact_evidence(reference: &mut EvidenceRef, stats: &mut DiagnosisDisplayProjectionStats) {
    match reference {
        EvidenceRef::Event(value) => {
            compact_display_text(&mut value.source, stats);
            compact_display_text(&mut value.provider, stats);
            compact_optional_display_text(&mut value.record_id_text, stats);
            compact_optional_display_text(&mut value.fallback_identity, stats);
            compact_optional_display_text(&mut value.machine, stats);
            compact_optional_display_text(&mut value.channel, stats);
            compact_optional_display_text(&mut value.activity_id, stats);
        }
        EvidenceRef::TextLog(value) => {
            compact_display_text(&mut value.source, stats);
            compact_display_text(&mut value.file_path, stats);
        }
        _ => {}
    }
}

fn compact_coverage_gap(gap: &mut CoverageGap, stats: &mut DiagnosisDisplayProjectionStats) {
    compact_display_text(&mut gap.id, stats);
    compact_display_text(&mut gap.source, stats);
    compact_display_text(&mut gap.detail, stats);
    truncate_nested(&mut gap.evidence, stats);
    for evidence in &mut gap.evidence {
        compact_evidence(evidence, stats);
    }
}

fn compact_finding(finding: &mut DiagnosisFinding, stats: &mut DiagnosisDisplayProjectionStats) {
    compact_display_text(&mut finding.finding_id, stats);
    compact_display_text(&mut finding.title, stats);
    compact_display_text(&mut finding.summary, stats);
    truncate_nested(&mut finding.recommended_checks, stats);
    for check in &mut finding.recommended_checks {
        compact_display_text(check, stats);
    }
    truncate_nested(&mut finding.evidence, stats);
    for evidence in &mut finding.evidence {
        compact_evidence(evidence, stats);
    }
    truncate_nested(&mut finding.coverage_gaps, stats);
    for gap in &mut finding.coverage_gaps {
        compact_coverage_gap(gap, stats);
    }
}

fn compact_correlation(edge: &mut CorrelationEdge, stats: &mut DiagnosisDisplayProjectionStats) {
    compact_display_text(&mut edge.left, stats);
    compact_optional_display_text(&mut edge.right, stats);
    truncate_nested(&mut edge.candidate_ids, stats);
    for candidate in &mut edge.candidate_ids {
        compact_display_text(candidate, stats);
    }
    truncate_nested(&mut edge.evidence, stats);
    for evidence in &mut edge.evidence {
        compact_display_text(&mut evidence.origin_id, stats);
        compact_display_text(&mut evidence.field, stats);
        compact_display_text(&mut evidence.value, stats);
    }
}

fn compact_event(event: &mut EventDiagnosis, stats: &mut DiagnosisDisplayProjectionStats) {
    truncate_nested(&mut event.evidence, stats);
    for evidence in &mut event.evidence {
        compact_evidence(evidence, stats);
    }
    truncate_nested(&mut event.findings, stats);
    for finding in &mut event.findings {
        compact_finding(finding, stats);
    }
    truncate_nested(&mut event.error_tokens, stats);
    for token in &mut event.error_tokens {
        compact_display_text(&mut token.raw, stats);
        compact_optional_display_text(&mut token.hex, stats);
        compact_optional_display_text(&mut token.description, stats);
        compact_optional_display_text(&mut token.category, stats);
    }
}

fn compact_diagnosis_details(summary: &mut DiagnosisSummary) -> DiagnosisDisplayProjectionStats {
    let mut stats = DiagnosisDisplayProjectionStats::default();
    compact_display_text(&mut summary.overview.outcome, &mut stats);
    compact_display_text(&mut summary.overview.headline, &mut stats);
    for finding in &mut summary.findings {
        compact_finding(finding, &mut stats);
    }
    for evidence in &mut summary.evidence {
        compact_evidence(evidence, &mut stats);
    }
    for gap in &mut summary.coverage_gaps {
        compact_coverage_gap(gap, &mut stats);
    }
    for correlation in &mut summary.correlations {
        compact_correlation(correlation, &mut stats);
    }
    for event in &mut summary.events {
        compact_event(event, &mut stats);
    }
    stats
}

fn projection_detail(
    summary: &DiagnosisSummary,
    totals: [usize; 5],
    stats: &DiagnosisDisplayProjectionStats,
) -> String {
    format!(
        "Bounded diagnosis response omitted {} of {} findings, {} of {} evidence references, {} of {} coverage gaps, {} of {} correlations, and {} of {} diagnosed events; compacted {} oversized text fields and omitted {} nested detail rows. The serialized response is limited to {} bytes.",
        totals[0].saturating_sub(summary.findings.len()),
        totals[0],
        totals[1].saturating_sub(summary.evidence.len()),
        totals[1],
        totals[2].saturating_sub(summary.coverage_gaps.len()),
        totals[2],
        totals[3].saturating_sub(summary.correlations.len()),
        totals[3],
        totals[4].saturating_sub(summary.events.len()),
        totals[4],
        stats.compacted_text_fields,
        stats.omitted_nested_rows,
        MAX_DIAGNOSIS_RESPONSE_BYTES,
    )
}

fn update_projection_detail(
    summary: &mut DiagnosisSummary,
    totals: [usize; 5],
    stats: &DiagnosisDisplayProjectionStats,
) {
    let finding = cmtraceopen_parser::diagnosis::finding_for_coverage(
        DIAGNOSIS_RESPONSE_PROJECTION_SOURCE,
        CoverageState::Capped,
        projection_detail(summary, totals, stats),
    );
    let gap = finding
        .coverage_gaps
        .first()
        .cloned()
        .expect("coverage finding owns one gap");
    summary.findings[0] = finding;
    summary.coverage_gaps[0] = gap;
}

fn pop_largest_detail_row(summary: &mut DiagnosisSummary) -> Option<usize> {
    let mut candidates = Vec::with_capacity(5);
    if summary.findings.len() > 1 {
        candidates.push((
            serde_json::to_vec(summary.findings.last()?).ok()?.len(),
            0usize,
        ));
    }
    if !summary.evidence.is_empty() {
        candidates.push((
            serde_json::to_vec(summary.evidence.last()?).ok()?.len(),
            1usize,
        ));
    }
    if summary.coverage_gaps.len() > 1 {
        candidates.push((
            serde_json::to_vec(summary.coverage_gaps.last()?)
                .ok()?
                .len(),
            2usize,
        ));
    }
    if !summary.correlations.is_empty() {
        candidates.push((
            serde_json::to_vec(summary.correlations.last()?).ok()?.len(),
            3usize,
        ));
    }
    if !summary.events.is_empty() {
        candidates.push((
            serde_json::to_vec(summary.events.last()?).ok()?.len(),
            4usize,
        ));
    }
    let (bytes, section) = candidates.into_iter().max_by_key(|value| value.0)?;
    match section {
        0 => {
            summary.findings.pop();
        }
        1 => {
            summary.evidence.pop();
        }
        2 => {
            summary.coverage_gaps.pop();
        }
        3 => {
            summary.correlations.pop();
        }
        4 => {
            summary.events.pop();
        }
        _ => unreachable!("known diagnosis section"),
    }
    Some(bytes.saturating_add(1))
}

fn bound_diagnosis_response(mut summary: DiagnosisSummary) -> DiagnosisSummary {
    let actionable_finding_count = summary
        .findings
        .iter()
        .filter(|finding| !matches!(finding.class, FindingClass::CoverageGap))
        .count();
    let error_token_event_count = summary
        .events
        .iter()
        .filter(|event| !event.error_tokens.is_empty())
        .count();
    let original_totals = [
        summary.findings.len(),
        summary.evidence.len(),
        summary.coverage_gaps.len(),
        summary.correlations.len(),
        summary.events.len(),
    ];
    summary.findings.truncate(MAX_DIAGNOSIS_RESPONSE_ROWS);
    summary.evidence.truncate(MAX_DIAGNOSIS_RESPONSE_ROWS);
    summary.coverage_gaps.truncate(MAX_DIAGNOSIS_RESPONSE_ROWS);
    summary.correlations.truncate(MAX_DIAGNOSIS_RESPONSE_ROWS);
    summary.events.truncate(MAX_DIAGNOSIS_RESPONSE_ROWS);
    let display_stats = compact_diagnosis_details(&mut summary);
    summary = cmtraceopen_parser::diagnosis::redacted_display_projection(summary);
    let row_projection = original_totals
        .into_iter()
        .any(|count| count > MAX_DIAGNOSIS_RESPONSE_ROWS);
    let needs_projection = row_projection
        || display_stats.compacted_text_fields > 0
        || display_stats.omitted_nested_rows > 0
        || serialized_len(&summary).unwrap_or(usize::MAX) > MAX_DIAGNOSIS_RESPONSE_BYTES;
    let projection_rows = usize::from(needs_projection);
    let totals = [
        original_totals[0].saturating_add(projection_rows),
        original_totals[1],
        original_totals[2].saturating_add(projection_rows),
        original_totals[3],
        original_totals[4],
    ];
    if needs_projection {
        summary
            .findings
            .truncate(MAX_DIAGNOSIS_RESPONSE_ROWS.saturating_sub(1));
        summary
            .coverage_gaps
            .truncate(MAX_DIAGNOSIS_RESPONSE_ROWS.saturating_sub(1));
        let placeholder = cmtraceopen_parser::diagnosis::finding_for_coverage(
            DIAGNOSIS_RESPONSE_PROJECTION_SOURCE,
            CoverageState::Capped,
            String::new(),
        );
        let placeholder_gap = placeholder.coverage_gaps[0].clone();
        summary.findings.insert(0, placeholder);
        summary.coverage_gaps.insert(0, placeholder_gap);
        update_projection_detail(&mut summary, totals, &display_stats);

        let mut estimated_bytes = serialized_len(&summary).unwrap_or(usize::MAX);
        let target_bytes = MAX_DIAGNOSIS_RESPONSE_BYTES.saturating_sub(16 * 1024);
        while estimated_bytes > target_bytes {
            let Some(removed_bytes) = pop_largest_detail_row(&mut summary) else {
                break;
            };
            estimated_bytes = estimated_bytes.saturating_sub(removed_bytes);
        }
        update_projection_detail(&mut summary, totals, &display_stats);
        while serialized_len(&summary).unwrap_or(usize::MAX) > MAX_DIAGNOSIS_RESPONSE_BYTES {
            if pop_largest_detail_row(&mut summary).is_none() {
                break;
            }
            update_projection_detail(&mut summary, totals, &display_stats);
        }
    }

    summary.overview.finding_count = totals[0];
    summary.overview.actionable_finding_count = actionable_finding_count;
    summary.overview.coverage_gap_count = totals[2];
    summary.overview.evidence_count = totals[1];
    summary.overview.correlation_count = totals[3];
    summary.overview.error_token_event_count = error_token_event_count;
    if needs_projection {
        while serialized_len(&summary).unwrap_or(usize::MAX) > MAX_DIAGNOSIS_RESPONSE_BYTES {
            if pop_largest_detail_row(&mut summary).is_none() {
                break;
            }
            update_projection_detail(&mut summary, totals, &display_stats);
        }
    }
    debug_assert!(
        serialized_len(&summary).unwrap_or(usize::MAX) <= MAX_DIAGNOSIS_RESPONSE_BYTES,
        "diagnosis response projection must fit the serialized byte budget"
    );
    summary
}

fn serialized_len<T: Serialize>(value: &T) -> Result<usize, String> {
    serde_json::to_vec(value)
        .map(|encoded| encoded.len())
        .map_err(|error| format!("event-log analysis response serialization failed: {error}"))
}

/// Converts a row offset; `resource` names what is being paged in the error text.
fn validated_timeline_offset(offset: u64, resource: &str) -> Result<usize, String> {
    usize::try_from(offset).map_err(|_| format!("{resource} offset is not representable"))
}

/// Validates a row limit; `resource` names what is being paged in the error text.
fn validated_timeline_limit(limit: u32, resource: &str) -> Result<usize, String> {
    let limit =
        usize::try_from(limit).map_err(|_| format!("{resource} limit is not representable"))?;
    if limit == 0 || limit > MAX_ANALYSIS_TIMELINE_PAGE_ITEMS {
        return Err(format!(
            "{resource} limit must be between 1 and {MAX_ANALYSIS_TIMELINE_PAGE_ITEMS}"
        ));
    }
    Ok(limit)
}

/// Selects the longest prefix of `rows` whose serialized array still fits the page byte budget.
///
/// `empty_envelope_bytes` is the size of the response with no rows (and with every variable-width
/// field already reserved at its widest). Each row is checked against `max_row_bytes` first, so a
/// stored row that breaks its projection invariant is an error rather than a silent skip. At least
/// one row is always selected when `rows` is non-empty, so a caller can always make progress.
/// Rows are never skipped: the selected rows are exactly `rows[..returned]`.
fn select_bounded_prefix<T: Serialize>(
    rows: &[T],
    empty_envelope_bytes: usize,
    max_row_bytes: usize,
    row_label: &str,
) -> Result<usize, String> {
    let mut serialized_row_bytes = 0usize;
    let mut selected = 0usize;
    for row in rows {
        let row_bytes = serde_json::to_vec(row)
            .map_err(|error| format!("{row_label} serialization failed: {error}"))?
            .len();
        if row_bytes > max_row_bytes {
            return Err(format!(
                "stored {row_label} exceeds the {max_row_bytes}-byte projection invariant"
            ));
        }
        let separator_bytes = usize::from(selected > 0);
        let projected_bytes = empty_envelope_bytes
            .saturating_add(serialized_row_bytes)
            .saturating_add(separator_bytes)
            .saturating_add(row_bytes);
        if selected > 0 && projected_bytes > MAX_ANALYSIS_TIMELINE_PAGE_BYTES {
            break;
        }
        serialized_row_bytes = serialized_row_bytes
            .saturating_add(separator_bytes)
            .saturating_add(row_bytes);
        selected += 1;
    }
    Ok(selected)
}

/// Sets `serialized_bytes` to the exact self-inclusive serialized size of the response.
fn converge_serialized_bytes<T: Serialize>(
    response: &mut T,
    get: impl Fn(&T) -> u64,
    set: impl Fn(&mut T, u64),
) -> Result<(), String> {
    for _ in 0..4 {
        let serialized_bytes = usize_to_u64(serialized_len(response)?);
        if get(response) == serialized_bytes {
            return Ok(());
        }
        set(response, serialized_bytes);
    }
    Err("analysis response serialized byte size did not converge".to_string())
}

fn bounded_preview<'a, T: Clone + Serialize + 'a>(
    rows: impl IntoIterator<Item = &'a T>,
    remaining_bytes: &mut usize,
) -> Vec<T> {
    let mut preview = Vec::new();
    for row in rows.into_iter().take(MAX_ANALYSIS_TIMELINE_PREVIEW_ITEMS) {
        let Ok(encoded) = serde_json::to_vec(row) else {
            break;
        };
        let row_bytes = encoded.len().saturating_add(1);
        if row_bytes > *remaining_bytes {
            break;
        }
        preview.push(row.clone());
        *remaining_bytes = remaining_bytes.saturating_sub(row_bytes);
    }
    preview
}

fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn validate_session_id(session_id: &str) -> Result<(), String> {
    if session_id.is_empty()
        || session_id.len() > MAX_ANALYSIS_SESSION_ID_BYTES
        || session_id.chars().any(char::is_control)
    {
        return Err("invalid event-log analysis session ID".to_string());
    }
    Ok(())
}

fn prune_stale_analysis_sessions(sessions: &mut EventLogAnalysisSessionRegistry, now: Instant) {
    sessions.retain(|_, entry| {
        now.saturating_duration_since(entry.last_access) < ANALYSIS_SESSION_IDLE_TTL
    });
}

fn insert_analysis_session(
    sessions: &mut EventLogAnalysisSessionRegistry,
    id: String,
    session: SharedEventLogAnalysisSession,
    now: Instant,
) -> Result<(), String> {
    prune_stale_analysis_sessions(sessions, now);
    if sessions.len() >= MAX_ANALYSIS_SESSIONS {
        return Err(format!(
            "event-log analysis session capacity of {MAX_ANALYSIS_SESSIONS} is in use; close an existing analysis session and retry"
        ));
    }
    sessions.insert(
        id,
        EventLogAnalysisSessionEntry {
            session,
            last_access: now,
        },
    );
    Ok(())
}

fn access_analysis_session(
    sessions: &mut EventLogAnalysisSessionRegistry,
    session_id: &str,
    now: Instant,
) -> Option<SharedEventLogAnalysisSession> {
    let session = sessions.get_mut(session_id).map(|entry| {
        entry.last_access = now;
        entry.session.clone()
    })?;
    prune_stale_analysis_sessions(sessions, now);
    Some(session)
}

/// Looks a session up in the registry it is given.
///
/// Taking the registry rather than the whole app state lets a blocking task own the lookup: the
/// access bookkeeping prunes stale sessions, so the lock can drop a session's buffers before it
/// releases. Every caller that runs on the async executor goes through `spawn_blocking` first.
fn find_session_in(
    sessions: &Mutex<EventLogAnalysisSessionRegistry>,
    session_id: &str,
) -> Result<SharedEventLogAnalysisSession, String> {
    validate_session_id(session_id)?;
    let mut guard = sessions
        .lock()
        .map_err(|_| "event-log analysis session registry lock was poisoned".to_string())?;
    access_analysis_session(&mut guard, session_id, Instant::now())
        .ok_or_else(|| "event-log analysis session was not found".to_string())
}

#[tauri::command]
pub fn evtx_create_analysis_session(
    state: tauri::State<'_, AppState>,
) -> Result<EventLogAnalysisSessionStatus, String> {
    let id = uuid::Uuid::new_v4().to_string();
    let session = EventLogAnalysisSession::new(id.clone());
    let status = session.status();
    let mut sessions = state
        .event_log_analysis_sessions
        .lock()
        .map_err(|_| "event-log analysis session registry lock was poisoned".to_string())?;
    insert_analysis_session(
        &mut sessions,
        id,
        Arc::new(Mutex::new(session)),
        Instant::now(),
    )?;
    Ok(status)
}

#[tauri::command]
pub async fn evtx_append_analysis_chunk(
    session_id: String,
    records: Vec<EventLogAnalysisRecordInput>,
    entries: Vec<EventLogAnalysisLogEntryInput>,
    state: tauri::State<'_, AppState>,
) -> Result<EventLogAnalysisSessionStatus, String> {
    let sessions = Arc::clone(&state.event_log_analysis_sessions);
    tokio::task::spawn_blocking(move || {
        find_session_in(&sessions, &session_id)?
            .lock()
            .map_err(|_| "event-log analysis session lock was poisoned".to_string())?
            .append_inputs(records, entries)
    })
    .await
    .map_err(|error| format!("event-log analysis append task failed: {error}"))?
}

#[tauri::command]
pub async fn evtx_finalize_analysis_session(
    session_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<EventLogAnalysisSessionStatus, String> {
    let sessions = Arc::clone(&state.event_log_analysis_sessions);
    tokio::task::spawn_blocking(move || {
        find_session_in(&sessions, &session_id)?
            .lock()
            .map_err(|_| "event-log analysis session lock was poisoned".to_string())?
            .finalize()
    })
    .await
    .map_err(|error| format!("event-log analysis finalize task failed: {error}"))?
}

#[tauri::command]
pub async fn evtx_query_analysis_timeline(
    session_id: String,
    offset: u64,
    limit: u32,
    state: tauri::State<'_, AppState>,
) -> Result<EventLogAnalysisTimelinePage, String> {
    let sessions = Arc::clone(&state.event_log_analysis_sessions);
    tokio::task::spawn_blocking(move || {
        find_session_in(&sessions, &session_id)?
            .lock()
            .map_err(|_| "event-log analysis session lock was poisoned".to_string())?
            .page(offset, limit)
    })
    .await
    .map_err(|error| format!("event-log analysis page task failed: {error}"))?
}

#[tauri::command]
pub async fn evtx_query_analysis_timeline_window(
    session_id: String,
    start_ms: i64,
    end_ms: i64,
    limit: u32,
    state: tauri::State<'_, AppState>,
) -> Result<EventLogAnalysisTimelineWindow, String> {
    let sessions = Arc::clone(&state.event_log_analysis_sessions);
    tokio::task::spawn_blocking(move || {
        find_session_in(&sessions, &session_id)?
            .lock()
            .map_err(|_| "event-log analysis session lock was poisoned".to_string())?
            .window(start_ms, end_ms, limit)
    })
    .await
    .map_err(|error| format!("event-log analysis window task failed: {error}"))?
}

#[tauri::command]
pub async fn evtx_query_analysis_edges(
    session_id: String,
    offset: u64,
    limit: u32,
    state: tauri::State<'_, AppState>,
) -> Result<EventLogAnalysisEdgePage, String> {
    let sessions = Arc::clone(&state.event_log_analysis_sessions);
    tokio::task::spawn_blocking(move || {
        find_session_in(&sessions, &session_id)?
            .lock()
            .map_err(|_| "event-log analysis session lock was poisoned".to_string())?
            .edge_page(offset, limit)
    })
    .await
    .map_err(|error| format!("event-log analysis edge task failed: {error}"))?
}

#[tauri::command]
pub async fn evtx_diagnose_analysis_session(
    session_id: String,
    coverage_gaps: Option<Vec<EvtxCoverageGap>>,
    state: tauri::State<'_, AppState>,
) -> Result<DiagnosisSummary, String> {
    let coverage_gaps = coverage_gaps.unwrap_or_default();
    validate_diagnosis_coverage_gaps(&coverage_gaps)?;
    // Everything below the handle clone belongs off the async executor: the registry lookup runs the
    // stale-session prune, and the snapshot clones the bounded event projection, the text findings
    // and the identity findings. Only the handles are taken here, before the first await.
    let sessions = Arc::clone(&state.event_log_analysis_sessions);
    tokio::task::spawn_blocking(move || {
        let snapshot = find_session_in(&sessions, &session_id)?
            .lock()
            .map_err(|_| "event-log analysis session lock was poisoned".to_string())?
            .diagnosis_snapshot()?;
        // The session guard was released with the statement above, so the summary runs without it.
        Ok(snapshot.summarize(coverage_gaps))
    })
    .await
    .map_err(|error| format!("event-log analysis diagnosis task failed: {error}"))?
}

#[tauri::command]
pub fn evtx_close_analysis_session(
    session_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    validate_session_id(&session_id)?;
    state
        .event_log_analysis_sessions
        .lock()
        .map_err(|_| "event-log analysis session registry lock was poisoned".to_string())?
        .remove(&session_id);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_log::models::{EvtxField, EvtxLevel, EvtxOriginKind};

    fn record(id: u64, timestamp: i64, message: &str) -> EvtxRecord {
        EvtxRecord {
            id,
            event_record_id: id,
            event_record_id_text: Some(id.to_string()),
            timestamp: format!("2026-08-30T12:00:{:02}.000Z", id % 60),
            timestamp_epoch: timestamp,
            provider: "Ordinary.Application.Provider".to_string(),
            channel: "Application".to_string(),
            event_id: 100,
            level: EvtxLevel::Information,
            computer: "TESTHOST".to_string(),
            message: message.to_string(),
            event_data: Vec::new(),
            raw_xml: String::new(),
            source_label: "Live/Application".to_string(),
            origin_kind: EvtxOriginKind::Event,
            task: None,
            opcode: None,
            process_id: None,
            activity_id: None,
            related_activity_id: None,
            session_id: None,
            device_id: None,
            user_id: None,
            process_start_time: None,
            thread_id: None,
            user_sid: None,
            keywords: None,
            mapped: Vec::new(),
        }
    }

    fn mdm_success_record(id: u64) -> EvtxRecord {
        let mut record = record(id, id as i64, "Enrollment completed.");
        record.channel =
            "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin".into();
        record.provider =
            "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider".into();
        record.event_data = vec![EvtxField {
            name: "Status".into(),
            value: "Success".into(),
        }];
        record
    }

    fn shared_session(id: &str) -> SharedEventLogAnalysisSession {
        Arc::new(Mutex::new(EventLogAnalysisSession::new(id.to_string())))
    }

    #[test]
    fn registry_touches_requested_stale_session_and_prunes_other_stale_sessions() {
        let now = Instant::now();
        let stale = now
            .checked_sub(ANALYSIS_SESSION_IDLE_TTL + Duration::from_secs(1))
            .unwrap();
        let mut sessions = EventLogAnalysisSessionRegistry::new();
        sessions.insert(
            "requested".into(),
            EventLogAnalysisSessionEntry {
                session: shared_session("requested"),
                last_access: stale,
            },
        );
        sessions.insert(
            "other".into(),
            EventLogAnalysisSessionEntry {
                session: shared_session("other"),
                last_access: stale,
            },
        );

        assert!(access_analysis_session(&mut sessions, "requested", now).is_some());
        assert!(sessions.contains_key("requested"));
        assert!(!sessions.contains_key("other"));
        assert_eq!(sessions["requested"].last_access, now);
    }

    #[test]
    fn registry_rejects_capacity_until_a_stale_session_can_be_pruned() {
        let now = Instant::now();
        let mut sessions = EventLogAnalysisSessionRegistry::new();
        for index in 0..MAX_ANALYSIS_SESSIONS {
            let id = format!("session-{index}");
            insert_analysis_session(&mut sessions, id.clone(), shared_session(&id), now).unwrap();
        }
        assert!(insert_analysis_session(
            &mut sessions,
            "overflow".into(),
            shared_session("overflow"),
            now,
        )
        .unwrap_err()
        .contains("capacity"));

        sessions.get_mut("session-0").unwrap().last_access = now
            .checked_sub(ANALYSIS_SESSION_IDLE_TTL + Duration::from_secs(1))
            .unwrap();
        insert_analysis_session(
            &mut sessions,
            "replacement".into(),
            shared_session("replacement"),
            now,
        )
        .unwrap();
        assert_eq!(sessions.len(), MAX_ANALYSIS_SESSIONS);
        assert!(!sessions.contains_key("session-0"));
        assert!(sessions.contains_key("replacement"));
    }

    #[test]
    fn thousands_of_ordinary_events_remain_neutral_and_paged() {
        let mut session = EventLogAnalysisSession::new("test-session".to_string());
        for chunk in 0..5 {
            let records = (0..1_000)
                .map(|index| {
                    let id = chunk * 1_000 + index + 1;
                    record(id, id as i64, "ordinary informational event")
                })
                .collect();
            session.append(records, Vec::new()).unwrap();
        }
        let status = session.finalize().unwrap();
        assert_eq!(status.total_items, 5_000);
        assert_eq!(status.event_items, 5_000);
        assert_eq!(status.log_items, 0);
        assert!(status.finalized);

        let first = session.page(0, 1_000).unwrap();
        let last = session.page(4_000, 1_000).unwrap();
        assert_eq!(first.items.len(), 1_000);
        assert_eq!(last.items.len(), 1_000);
        assert_eq!(first.total_items, 5_000);

        let summary = session.diagnosis_snapshot().unwrap().summarize(Vec::new());
        assert!(summary.findings.is_empty());
        assert!(summary.coverage_gaps.is_empty());
        assert!(summary.events.is_empty());
        assert!(summary.evidence.is_empty());
        assert_eq!(summary.overview.outcome, "noFindings");
    }

    #[test]
    fn relevant_overflow_is_counted_after_neutral_events_are_discarded() {
        let mut session =
            EventLogAnalysisSession::with_diagnosis_limit("test-session".to_string(), 2);
        let mut records = (1..=2_000)
            .map(|id| record(id, id as i64, "ordinary informational event"))
            .collect::<Vec<_>>();
        records.extend((2_001..=2_004).map(mdm_success_record));

        for chunk in records.chunks(MAX_ANALYSIS_APPEND_ROWS) {
            session.append(chunk.to_vec(), Vec::new()).unwrap();
        }
        session.finalize().unwrap();
        let summary = session.diagnosis_snapshot().unwrap().summarize(Vec::new());

        assert_eq!(summary.events.len(), 2);
        assert_eq!(summary.coverage_gaps.len(), 1);
        let gap = &summary.coverage_gaps[0];
        assert_eq!(
            gap.state,
            cmtraceopen_parser::diagnosis::CoverageState::Capped
        );
        assert_eq!(gap.source, "event-diagnosis-projection");
        assert!(gap
            .detail
            .starts_with("2 of 4 diagnostic-family event records ("));
        assert!(gap
            .detail
            .contains("were omitted after retaining 2 records ("));
        assert_eq!(summary.overview.outcome, "insufficientEvidence");
    }

    #[test]
    fn cumulative_input_can_exceed_one_ipc_budget_without_retaining_raw_xml() {
        let mut session = EventLogAnalysisSession::new("test-session".to_string());
        let raw_xml = "x".repeat(250_000);
        for chunk in 0..10 {
            let records = (0..28)
                .map(|index| {
                    let id = chunk * 28 + index + 1;
                    let mut record = record(id, id as i64, "ordinary informational event");
                    record.raw_xml = raw_xml.clone();
                    record
                })
                .collect();
            session.append(records, Vec::new()).unwrap();
        }
        let status = session.finalize().unwrap();
        assert_eq!(status.total_items, 280);
        assert!(280usize.saturating_mul(raw_xml.len()) > 64 * 1024 * 1024);
        let page = session.page(0, 1).unwrap();
        assert_eq!(page.items[0].message, "ordinary informational event");
        let summary = session.diagnosis_snapshot().unwrap().summarize(Vec::new());
        assert!(summary.events.is_empty());
        assert!(summary.evidence.is_empty());
        assert!(summary.coverage_gaps.is_empty());
    }

    #[test]
    fn oversized_ordinary_event_skips_diagnosis_only_validation_neutrally() {
        let mut session = EventLogAnalysisSession::new("test-session".to_string());
        let mut ordinary = record(1, 1, &"ordinary ".repeat(40_000));
        ordinary.raw_xml = "x".repeat(400_000);

        session.append(vec![ordinary], Vec::new()).unwrap();
        let status = session.finalize().unwrap();

        assert_eq!(status.total_items, 1);
        let page = session.page(0, 1).unwrap();
        assert_eq!(page.items.len(), 1);
        assert!(page.items[0].message.len() <= super::super::timeline::MAX_TIMELINE_MESSAGE_BYTES);
        assert!(page
            .coverage_gaps_preview
            .iter()
            .any(|gap| gap.source == TIMELINE_ITEM_PROJECTION_SOURCE));
        let summary = session.diagnosis_snapshot().unwrap().summarize(Vec::new());
        assert!(summary.findings.is_empty());
        assert!(summary.coverage_gaps.is_empty());
        assert!(summary.events.is_empty());
        assert_eq!(summary.overview.outcome, "noFindings");
    }

    #[test]
    fn projected_record_preserves_timeline_and_groups_diagnosis_uncertainty() {
        let mut session = EventLogAnalysisSession::new("test-session".to_string());
        let mut projected = record(1, 1, "ordinary projected event");
        // The original oversized row had a conflicting EventData ActivityID, but transport
        // projection retained only the bounded System identity.
        projected.activity_id = Some("{system-activity}".into());
        let projected_bytes = serde_json::to_vec(&projected).unwrap().len() as u64;
        let original_bytes = 12 * 1024 * 1024_u64;

        session
            .append_inputs(
                vec![EventLogAnalysisRecordInput {
                    record: projected,
                    original_serialized_bytes: Some(original_bytes),
                }],
                Vec::new(),
            )
            .unwrap();
        let status = session.finalize().unwrap();
        assert_eq!(status.total_items, 1);
        assert_eq!(status.total_coverage_gaps, 1);
        let page = session.page(0, 1).unwrap();
        let timeline_gap = page
            .coverage_gaps_preview
            .iter()
            .find(|gap| gap.source == TIMELINE_TRANSPORT_PROJECTION_SOURCE)
            .expect("transport projection must remain visible to timeline correlation");
        assert!(timeline_gap
            .reason
            .contains("omitted identity or derived fields"));
        assert!(timeline_gap.reason.contains(&original_bytes.to_string()));
        assert!(timeline_gap.reason.contains(&projected_bytes.to_string()));

        let summary = session.diagnosis_snapshot().unwrap().summarize(Vec::new());
        assert!(summary.events.is_empty());
        let gap = summary
            .coverage_gaps
            .iter()
            .find(|gap| gap.source == DIAGNOSIS_INPUT_PROJECTION_SOURCE)
            .expect("projected input must be honest about diagnosis uncertainty");
        assert!(gap.detail.contains("1 rows"));
        assert!(gap.detail.contains(&original_bytes.to_string()));
        assert!(gap.detail.contains(&projected_bytes.to_string()));
    }

    #[test]
    fn projected_log_entry_preserves_timeline_and_groups_diagnosis_uncertainty() {
        let mut session = EventLogAnalysisSession::new("test-session".to_string());
        let projected = LogEntry {
            line_number: 7,
            message: "ordinary projected log entry".to_string(),
            timestamp: Some(1_000),
            file_path: "C:/logs/example.log".to_string(),
            ..LogEntry::default()
        };
        let retained_bytes = serde_json::to_vec(&projected).unwrap().len() as u64;
        let original_bytes = retained_bytes + 1_000_000;

        session
            .append_inputs(
                Vec::new(),
                vec![EventLogAnalysisLogEntryInput {
                    entry: projected,
                    original_serialized_bytes: Some(original_bytes),
                }],
            )
            .unwrap();
        let status = session.finalize().unwrap();
        assert_eq!(status.total_items, 1);
        assert_eq!(status.total_coverage_gaps, 1);

        let page = session.page(0, 1).unwrap();
        assert_eq!(page.items.len(), 1);
        let timeline_gap = page
            .coverage_gaps_preview
            .iter()
            .find(|gap| gap.source == TIMELINE_TRANSPORT_PROJECTION_SOURCE)
            .expect("projected log entry must preserve transport uncertainty");
        assert!(timeline_gap.reason.contains("1 rows"));
        assert!(timeline_gap.reason.contains(&original_bytes.to_string()));
        assert!(timeline_gap.reason.contains(&retained_bytes.to_string()));

        let summary = session.diagnosis_snapshot().unwrap().summarize(Vec::new());
        let diagnosis_gap = summary
            .coverage_gaps
            .iter()
            .find(|gap| gap.source == DIAGNOSIS_INPUT_PROJECTION_SOURCE)
            .expect("projected log entry must preserve diagnosis uncertainty");
        assert!(diagnosis_gap.detail.contains("1 rows"));
        assert!(diagnosis_gap.detail.contains(&original_bytes.to_string()));
        assert!(diagnosis_gap.detail.contains(&retained_bytes.to_string()));
    }

    #[test]
    fn provider_description_gap_remains_grouped_without_parse_failure() {
        let mut session = EventLogAnalysisSession::new("test-session".to_string());
        session
            .append(vec![mdm_success_record(1)], Vec::new())
            .unwrap();
        session.finalize().unwrap();
        let provider_gap = super::super::live::provider_message_gap(
            "remote-host/ForwardedEvents",
            "Example.Provider",
            super::super::models::ProviderMessageStage::FormatMessage,
            15_027,
        );

        let summary = session
            .diagnosis_snapshot()
            .unwrap()
            .summarize(vec![provider_gap]);
        let gap = summary
            .coverage_gaps
            .iter()
            .find(|gap| gap.source == "remote-host/ForwardedEvents")
            .expect("provider-description gap remains visible");
        assert_eq!(gap.state, CoverageState::ProviderDescriptionUnavailable);
        assert_ne!(gap.state, CoverageState::ParseFailed);
    }

    #[test]
    fn session_keeps_event_and_archive_text_diagnosis_sources_separate() {
        let mut session = EventLogAnalysisSession::new("test-session".to_string());
        let event = mdm_success_record(1);
        let mut archive = record(2, 2, "Enrollment failed with error 0x80070005");
        archive.origin_kind = EvtxOriginKind::Log;
        archive.source_label = "Application.evtx".into();

        session.append(vec![event, archive], Vec::new()).unwrap();
        session.finalize().unwrap();
        let summary = session.diagnosis_snapshot().unwrap().summarize(Vec::new());

        assert_eq!(summary.events.len(), 1);
        assert!(summary.findings.iter().any(|finding| {
            finding.evidence.iter().any(|evidence| {
                matches!(
                    evidence,
                    EvidenceRef::TextLog(value)
                        if value.source == "Application.evtx" && value.entry_id == 2
                )
            })
        }));
    }

    #[test]
    fn session_response_redacts_sensitive_event_display_strings() {
        let mut session = EventLogAnalysisSession::new("test-session".to_string());
        let mut event = mdm_success_record(1);
        event.message = "Enrollment failed for jane.doe@example.invalid PASSWORD=hunter2".into();
        event.computer = "DESKTOP-JANE".into();
        event.source_label = r"C:\Users\Jane Doe\AppData\Local\event.evtx".into();
        event.event_data = vec![EvtxField {
            name: "Password".into(),
            value: "hunter2".into(),
        }];

        session.append(vec![event], Vec::new()).unwrap();
        session.finalize().unwrap();
        let summary = session.diagnosis_snapshot().unwrap().summarize(Vec::new());
        let serialized = serde_json::to_string(&summary).unwrap();

        assert!(!serialized.contains("jane.doe@example.invalid"));
        assert!(!serialized.contains("Jane Doe"));
        assert!(!serialized.contains("DESKTOP-JANE"));
        assert!(!serialized.contains("hunter2"));
        assert!(serialized.contains("Enrollment failed"));
    }

    #[test]
    fn session_preserves_lossless_event_record_text_identity() {
        let mut session = EventLogAnalysisSession::new("test-session".to_string());
        let mut first = mdm_success_record(9_007_199_254_740_993);
        first.event_record_id_text = Some("9007199254740993".into());
        let mut second = mdm_success_record(9_007_199_254_740_994);
        second.event_record_id_text = Some("9007199254740994".into());
        session.append(vec![first, second], Vec::new()).unwrap();
        session.finalize().unwrap();

        let summary = session.diagnosis_snapshot().unwrap().summarize(Vec::new());
        assert_eq!(summary.events.len(), 2);
        assert!(matches!(
            &summary.events[0].evidence[0],
            EvidenceRef::Event(value)
                if value.record_id_text.as_deref() == Some("9007199254740993")
        ));
        assert!(matches!(
            &summary.events[1].evidence[0],
            EvidenceRef::Event(value)
                if value.record_id_text.as_deref() == Some("9007199254740994")
        ));
        assert_ne!(
            summary.events[0].evidence[0].stable_id(),
            summary.events[1].evidence[0].stable_id()
        );
    }

    #[test]
    fn timeline_pages_and_previews_are_bounded() {
        let mut session = EventLogAnalysisSession::new("test-session".to_string());
        let records = (1..=1_250)
            .map(|id| record(id, id as i64, "ordinary informational event"))
            .collect::<Vec<_>>();
        for chunk in records.chunks(MAX_ANALYSIS_APPEND_ROWS) {
            session.append(chunk.to_vec(), Vec::new()).unwrap();
        }
        session.finalize().unwrap();

        assert!(session.page(0, 1_001).is_err());
        let page = session.page(1_000, 1_000).unwrap();
        assert_eq!(page.items.len(), 250);
        assert!(page.unplaced_preview.is_empty());
        assert!(page.edges_preview.is_empty());
        assert!(page.coverage_gaps_preview.is_empty());
    }

    #[test]
    fn timeline_pages_are_byte_bounded_and_next_offset_never_skips_rows() {
        const RECORD_COUNT: usize = 1_000;
        let mut session = EventLogAnalysisSession::new("test-session".to_string());
        let message = "x".repeat(16 * 1024);
        let records = (1..=RECORD_COUNT)
            .map(|id| record(id as u64, id as i64, &message))
            .collect::<Vec<_>>();
        for chunk in records.chunks(400) {
            session.append(chunk.to_vec(), Vec::new()).unwrap();
        }
        session.finalize().unwrap();

        let mut next_offset = Some(0u64);
        let mut seen_ids = Vec::new();
        let mut page_count = 0;
        while let Some(offset) = next_offset {
            let page = session.page(offset, 1_000).unwrap();
            assert_eq!(page.offset, offset);
            assert!(!page.items.is_empty());
            assert!(
                serialized_len(&page).unwrap() <= MAX_ANALYSIS_TIMELINE_PAGE_BYTES,
                "timeline page exceeded the serialized byte budget"
            );
            assert_eq!(
                page.serialized_bytes,
                usize_to_u64(serialized_len(&page).unwrap())
            );
            seen_ids.extend(page.items.iter().map(|item| match &item.origin {
                cmtraceopen_parser::unified_timeline::TimelineOrigin::Event {
                    record_id, ..
                } => *record_id,
                other => panic!("expected event origin, got {other:?}"),
            }));
            next_offset = page.next_offset;
            page_count += 1;
        }

        assert!(
            page_count > 1,
            "large rows must produce a variable-size page"
        );
        assert_eq!(seen_ids.len(), RECORD_COUNT);
        assert_eq!(seen_ids, (1..=RECORD_COUNT as u64).collect::<Vec<_>>());
    }

    fn finalized_session(records: Vec<EvtxRecord>) -> EventLogAnalysisSession {
        let mut session = EventLogAnalysisSession::new("test-session".to_string());
        // Small chunks keep large-message fixtures inside the per-append envelope budget.
        for chunk in records.chunks(400) {
            session.append(chunk.to_vec(), Vec::new()).unwrap();
        }
        session.finalize().unwrap();
        session
    }

    fn all_page_items(session: &EventLogAnalysisSession) -> Vec<TimelineItem> {
        let mut items = Vec::new();
        let mut next_offset = Some(0u64);
        while let Some(offset) = next_offset {
            let page = session.page(offset, 1_000).unwrap();
            items.extend(page.items);
            next_offset = page.next_offset;
        }
        items
    }

    fn item_record_id(item: &TimelineItem) -> u64 {
        match &item.origin {
            cmtraceopen_parser::unified_timeline::TimelineOrigin::Event { record_id, .. } => {
                *record_id
            }
            other => panic!("expected event origin, got {other:?}"),
        }
    }

    /// Records 1..=count at 10 ms spacing (timestamp = id * 10), appended in a scrambled order so
    /// the finalize sort, not insertion order, is what the window search relies on.
    fn scrambled_session(count: u64) -> EventLogAnalysisSession {
        let mut ids = (1..=count).collect::<Vec<_>>();
        ids.reverse();
        let shift = 7 % ids.len().max(1);
        ids.rotate_left(shift);
        finalized_session(
            ids.into_iter()
                .map(|id| record(id, (id * 10) as i64, "ordinary informational event"))
                .collect(),
        )
    }

    #[test]
    fn timeline_items_are_sorted_by_timestamp_after_finalize() {
        let session = scrambled_session(200);
        let items = all_page_items(&session);
        assert_eq!(items.len(), 200);
        assert!(items
            .windows(2)
            .all(|pair| pair[0].timestamp_ms <= pair[1].timestamp_ms));
    }

    #[test]
    fn window_bounds_are_inclusive_at_both_ends() {
        let session = scrambled_session(100);
        let window = session.window(200, 300, 1_000).unwrap();
        let ids = window.items.iter().map(item_record_id).collect::<Vec<_>>();
        assert_eq!(ids, (20..=30).collect::<Vec<_>>());
        assert_eq!(window.offset, 19);
        assert_eq!(window.window_items, 11);
        assert_eq!(window.omitted_items, 0);
        assert_eq!(window.next_offset, None);

        // A one-point window selects exactly the items stamped at that instant.
        let point = session.window(500, 500, 10).unwrap();
        assert_eq!(
            point.items.iter().map(item_record_id).collect::<Vec<_>>(),
            vec![50]
        );
        // One millisecond inside either end excludes the boundary item.
        let inner = session.window(201, 299, 1_000).unwrap();
        assert_eq!(
            inner.items.iter().map(item_record_id).collect::<Vec<_>>(),
            (21..=29).collect::<Vec<_>>()
        );
    }

    #[test]
    fn window_between_items_before_first_and_after_last_is_empty() {
        let session = scrambled_session(100);

        let between = session.window(201, 209, 10).unwrap();
        assert!(between.items.is_empty());
        assert_eq!(between.offset, 20);
        assert_eq!((between.window_items, between.omitted_items), (0, 0));
        assert_eq!(between.next_offset, None);

        let before = session.window(-1_000, 5, 10).unwrap();
        assert!(before.items.is_empty());
        assert_eq!(before.offset, 0);

        let after = session.window(1_001, 9_999, 10).unwrap();
        assert!(after.items.is_empty());
        assert_eq!(after.offset, 100);
        assert_eq!(after.next_offset, None);
        assert_eq!(after.total_items, 100);
    }

    #[test]
    fn window_rejects_inverted_range_zero_limit_and_oversized_limit() {
        let session = scrambled_session(10);
        assert!(session.window(10, 9, 10).is_err());
        assert!(session.window(0, 100, 0).is_err());
        assert!(session.window(0, 100, 1_001).is_err());
    }

    #[test]
    fn window_requires_a_finalized_session() {
        let mut session = EventLogAnalysisSession::new("test-session".to_string());
        session
            .append(
                vec![record(1, 10, "ordinary informational event")],
                Vec::new(),
            )
            .unwrap();
        assert_eq!(
            session.window(0, 100, 10).unwrap_err(),
            "event-log analysis session is not finalized"
        );
        assert_eq!(
            session.edge_page(0, 10).unwrap_err(),
            "event-log analysis session is not finalized"
        );
    }

    #[test]
    fn window_limit_truncation_reports_the_left_out_count_and_continuation() {
        let session = scrambled_session(100);
        let window = session.window(100, 900, 25).unwrap();
        assert_eq!(window.items.len(), 25);
        assert_eq!(window.window_items, 81);
        assert_eq!(window.omitted_items, 56);
        assert_eq!(window.offset, 9);
        assert_eq!(window.next_offset, Some(34));

        // Continuing from `nextOffset` through `page()` yields the rest of the window with no gap.
        let rest = session.page(34, 1_000).unwrap();
        let rest_in_window = rest
            .items
            .iter()
            .take_while(|item| item.timestamp_ms <= 900)
            .count();
        assert_eq!(rest_in_window as u64, window.omitted_items);
    }

    #[test]
    fn window_is_byte_bounded_with_the_same_budget_and_never_skips_items() {
        const RECORD_COUNT: usize = 1_000;
        let message = "x".repeat(16 * 1024);
        let session = finalized_session(
            (1..=RECORD_COUNT)
                .map(|id| record(id as u64, id as i64, &message))
                .collect(),
        );

        let first = session.window(1, RECORD_COUNT as i64, 1_000).unwrap();
        assert!(!first.items.is_empty());
        assert!(serialized_len(&first).unwrap() <= MAX_ANALYSIS_TIMELINE_PAGE_BYTES);
        assert_eq!(
            first.serialized_bytes,
            usize_to_u64(serialized_len(&first).unwrap())
        );
        assert_eq!(
            first.omitted_items,
            first.window_items - usize_to_u64(first.items.len())
        );
        assert!(
            first.omitted_items > 0,
            "large rows must force a byte-budget truncation"
        );
        let mut seen = first.items.iter().map(item_record_id).collect::<Vec<_>>();

        // Continue the documented way: a loop of pages clipped to the rows still remaining.
        let mut offset = first.next_offset.unwrap();
        let mut remaining = first.omitted_items;
        while remaining > 0 {
            let clip = u32::try_from(remaining.min(1_000)).unwrap();
            let page = session.page(offset, clip).unwrap();
            assert_eq!(page.offset, offset);
            assert!(!page.items.is_empty() && page.items.len() <= clip as usize);
            seen.extend(page.items.iter().map(item_record_id));
            offset += usize_to_u64(page.items.len());
            remaining -= usize_to_u64(page.items.len());
        }
        assert_eq!(seen, (1..=RECORD_COUNT as u64).collect::<Vec<_>>());
    }

    #[test]
    fn window_includes_every_row_tied_on_both_bounds_across_event_and_log_items() {
        let log = |line: u64, timestamp: i64| EventLogAnalysisLogEntryInput {
            entry: LogEntry {
                line_number: line as u32,
                message: format!("tied log row {line}"),
                timestamp: Some(timestamp),
                file_path: "C:/logs/tied.log".to_string(),
                ..LogEntry::default()
            },
            original_serialized_bytes: None,
        };
        let event = |id: u64, timestamp: i64| {
            EventLogAnalysisRecordInput::complete(record(id, timestamp, "tied event row"))
        };
        let mut session = EventLogAnalysisSession::new("test-session".to_string());
        session
            .append_inputs(
                vec![
                    event(1, 500),
                    event(2, 1_000),
                    event(3, 1_000),
                    event(4, 1_000),
                    event(5, 2_000),
                    event(6, 2_000),
                    event(7, 2_500),
                ],
                vec![log(1, 1_000), log(2, 1_000), log(3, 2_000), log(4, 2_500)],
            )
            .unwrap();
        session.finalize().unwrap();

        // 1_000: 3 events + 2 log rows; 2_000: 2 events + 1 log row.
        let full = session.window(1_000, 2_000, 1_000).unwrap();
        assert_eq!(full.offset, 1);
        assert_eq!(full.window_items, 8);
        assert_eq!(full.items.len(), 8);
        assert_eq!(full.omitted_items, 0);
        assert_eq!(full.next_offset, None);
        assert!(full
            .items
            .iter()
            .all(|item| (1_000..=2_000).contains(&item.timestamp_ms)));
        let log_rows = full
            .items
            .iter()
            .filter(|item| {
                matches!(
                    item.origin,
                    cmtraceopen_parser::unified_timeline::TimelineOrigin::Log { .. }
                )
            })
            .count();
        assert_eq!(log_rows, 3);

        // A limit that splits the tie at the end bound reports the rest exactly.
        let cut = session.window(1_000, 2_000, 6).unwrap();
        assert_eq!(cut.items.len(), 6);
        assert_eq!(cut.omitted_items, 2);
        assert_eq!(cut.next_offset, Some(7));
        let rest = session.page(7, 2).unwrap();
        let mut joined = cut.items.clone();
        joined.extend(rest.items);
        assert_eq!(joined, full.items);

        // Windows pinned on a single tied instant return the whole tie.
        assert_eq!(session.window(1_000, 1_000, 10).unwrap().items.len(), 5);
        assert_eq!(session.window(2_000, 2_000, 10).unwrap().items.len(), 3);
    }

    #[test]
    fn limit_and_not_finalized_errors_are_one_text_per_resource() {
        let session = scrambled_session(10);
        for limit in [0u32, 1_001] {
            assert_eq!(
                session.page(0, limit).unwrap_err(),
                "timeline page limit must be between 1 and 1000"
            );
            assert_eq!(
                session.window(0, 100, limit).unwrap_err(),
                "timeline window limit must be between 1 and 1000"
            );
            assert_eq!(
                session.edge_page(0, limit).unwrap_err(),
                "edge page limit must be between 1 and 1000"
            );
        }
        let unfinalized = EventLogAnalysisSession::new("test-session".to_string());
        for error in [
            unfinalized.page(0, 10).unwrap_err(),
            unfinalized.window(0, 1, 10).unwrap_err(),
            unfinalized.edge_page(0, 10).unwrap_err(),
            unfinalized.diagnosis_snapshot().err().unwrap(),
        ] {
            assert_eq!(error, "event-log analysis session is not finalized");
        }
    }

    #[test]
    fn window_equals_the_matching_slice_of_the_concatenated_pages() {
        let session = scrambled_session(1_500);
        let all = all_page_items(&session);
        for (start, end) in [
            (0, 15_000),
            (4_000, 4_990),
            (7_777, 7_777),
            (14_990, 99_999),
        ] {
            let window = session.window(start, end, 1_000).unwrap();
            let first = usize::try_from(window.offset).unwrap();
            let expected = all
                .iter()
                .filter(|item| item.timestamp_ms >= start && item.timestamp_ms <= end)
                .take(window.items.len())
                .cloned()
                .collect::<Vec<_>>();
            assert_eq!(window.items, expected);
            assert_eq!(window.items, all[first..first + window.items.len()]);
            assert_eq!(
                window.window_items,
                all.iter()
                    .filter(|item| item.timestamp_ms >= start && item.timestamp_ms <= end)
                    .count() as u64
            );
        }
    }

    fn correlated_records(count: u64) -> Vec<EvtxRecord> {
        (1..=count)
            .map(|id| {
                let mut record = record(id, id as i64, "ordinary informational event");
                // Pairs of records share an activity id so each pair yields one exact edge.
                record.activity_id =
                    Some(format!("{{{:08X}-0000-0000-0000-000000000000}}", id / 2));
                record
            })
            .collect()
    }

    fn spread_records(count: u64, spacing_ms: i64) -> Vec<EvtxRecord> {
        (1..=count)
            .map(|id| record(id, id as i64 * spacing_ms, "ordinary informational event"))
            .collect()
    }

    #[test]
    fn edge_paging_walks_every_edge_once_and_matches_status() {
        let session = finalized_session(correlated_records(600));
        let total = session.status().total_edges;
        assert!(total > 100, "fixture must produce a meaningful edge list");

        let mut ids = Vec::new();
        let mut next_offset = Some(0u64);
        let mut pages = 0;
        while let Some(offset) = next_offset {
            let page = session.edge_page(offset, 64).unwrap();
            assert_eq!(page.offset, offset);
            assert_eq!(page.total_edges, total);
            assert_eq!(page.revision, session.status().revision);
            assert!(!page.edges.is_empty());
            assert!(page.edges.len() <= 64);
            assert_eq!(
                page.serialized_bytes,
                usize_to_u64(serialized_len(&page).unwrap())
            );
            ids.extend(page.edges.iter().map(|edge| edge.id.clone()));
            next_offset = page.next_offset;
            pages += 1;
        }
        assert!(pages > 1);
        assert_eq!(usize_to_u64(ids.len()), total);
        let expected = session
            .timeline
            .as_ref()
            .unwrap()
            .edges
            .iter()
            .map(|edge| edge.id.clone())
            .collect::<Vec<_>>();
        assert_eq!(ids, expected);

        let past_end = session.edge_page(total + 5, 10).unwrap();
        assert!(past_end.edges.is_empty());
        assert_eq!(past_end.offset, total);
        assert_eq!(past_end.next_offset, None);
        assert!(session.edge_page(0, 0).is_err());
    }

    #[test]
    #[ignore = "latency measurement; run with --ignored --nocapture"]
    fn latency_100k_records_window_and_edge_walk() {
        const RECORDS: u64 = 100_000;
        let build_start = Instant::now();
        let session = finalized_session(correlated_records(RECORDS));
        let build = build_start.elapsed();
        let status = session.status();

        let mut window_micros = Vec::new();
        for center in [1_000i64, 25_000, 50_000, 75_000, 99_000] {
            let started = Instant::now();
            let window = session.window(center - 75, center + 75, 1_000).unwrap();
            window_micros.push(started.elapsed().as_micros());
            assert_eq!(window.items.len(), 151);
        }
        // The spec window: +-75 SECONDS around the selected event.
        // Dense fixture: 1 ms spacing, so the window overflows the 1000-item cap.
        let dense_started = Instant::now();
        let dense = session
            .window(50_000 - 75_000, 50_000 + 75_000, 1_000)
            .unwrap();
        let dense_micros = dense_started.elapsed().as_micros();
        assert_eq!(dense.items.len(), 1_000);
        assert!(dense.omitted_items > 0);
        // Realistic fixture: the same 100k records spread over 24 hours (864 ms apart), so a
        // 150 s window holds about 174 items.
        let spread = finalized_session(spread_records(RECORDS, 86_400_000 / RECORDS as i64));
        let mut spread_micros = Vec::new();
        let mut spread_items = 0usize;
        for center in [3_600_000i64, 21_600_000, 43_200_000, 64_800_000, 82_800_000] {
            let started = Instant::now();
            let window = spread
                .window(center - 75_000, center + 75_000, 1_000)
                .unwrap();
            spread_micros.push(started.elapsed().as_micros());
            assert_eq!(window.omitted_items, 0);
            spread_items = window.items.len();
        }
        let wide_started = Instant::now();
        let wide = session.window(0, i64::MAX, 1_000).unwrap();
        let wide_micros = wide_started.elapsed().as_micros();

        let walk_started = Instant::now();
        let mut walked = 0u64;
        let mut pages = 0u32;
        let mut next_offset = Some(0u64);
        while let Some(offset) = next_offset {
            let page = session.edge_page(offset, 1_000).unwrap();
            walked += usize_to_u64(page.edges.len());
            pages += 1;
            next_offset = page.next_offset;
        }
        let walk = walk_started.elapsed();
        assert_eq!(walked, status.total_edges);

        println!(
            "LATENCY records={RECORDS} items={} edges={} build_and_finalize={build:?}",
            status.total_items, status.total_edges
        );
        println!("LATENCY window(+-75 MILLISECONDS, 151 items) micros per call={window_micros:?}");
        println!(
            "LATENCY window(+-75 SECONDS, dense 1 ms spacing, {} returned, {} omitted) micros={dense_micros}",
            dense.items.len(),
            dense.omitted_items
        );
        println!(
            "LATENCY window(+-75 SECONDS, 24 h spread, {spread_items} items) micros per call={spread_micros:?}"
        );
        println!(
            "LATENCY window(all, limit 1000, {} items returned) micros={wide_micros}",
            wide.items.len()
        );
        println!("LATENCY full edge walk pages={pages} edges={walked} total={walk:?}");
    }

    #[test]
    fn append_enforces_server_side_row_and_envelope_budgets() {
        let too_many = (1..=MAX_ANALYSIS_APPEND_ROWS + 1)
            .map(|id| record(id as u64, id as i64, "ordinary"))
            .collect::<Vec<_>>();
        let too_many = too_many
            .into_iter()
            .map(EventLogAnalysisRecordInput::complete)
            .collect::<Vec<_>>();
        assert!(validate_analysis_chunk(&too_many, &[])
            .unwrap_err()
            .contains("at most 1000"));

        let mut oversized = EventLogAnalysisRecordInput::complete(record(1, 1, "ordinary"));
        oversized.record.raw_xml = "x".repeat(MAX_ANALYSIS_APPEND_BYTES);
        assert!(validate_analysis_chunk(&[oversized], &[])
            .unwrap_err()
            .contains("envelope limit"));

        let mut boundary = EventLogAnalysisRecordInput::complete(record(1, 1, "ordinary"));
        let empty_bytes = serde_json::to_vec(&boundary).unwrap().len();
        boundary.record.raw_xml = "x".repeat(MAX_ANALYSIS_APPEND_BYTES - 2 - empty_bytes);
        assert_eq!(
            serde_json::to_vec(&boundary).unwrap().len() + 2,
            MAX_ANALYSIS_APPEND_BYTES
        );
        validate_analysis_chunk(&[boundary.clone()], &[]).unwrap();
        boundary.record.raw_xml.push('x');
        assert!(validate_analysis_chunk(&[boundary], &[])
            .unwrap_err()
            .contains("envelope limit"));

        let mut false_projection = EventLogAnalysisRecordInput::complete(record(1, 1, "ordinary"));
        false_projection.original_serialized_bytes =
            Some(serde_json::to_vec(&false_projection.record).unwrap().len() as u64);
        assert!(validate_analysis_chunk(&[false_projection], &[])
            .unwrap_err()
            .contains("must exceed the retained record size"));
    }

    #[test]
    fn nested_diagnosis_omissions_are_grouped_in_response_coverage() {
        let mut session = EventLogAnalysisSession::new("test-session".to_string());
        let mut event = mdm_success_record(1);
        event.message = "Enrollment failed with error 0x80070005 despite Success status.".into();
        session.append(vec![event], Vec::new()).unwrap();
        session.finalize().unwrap();
        let mut summary = session.diagnosis_snapshot().unwrap().summarize(Vec::new());
        summary.events[0].findings[0].recommended_checks =
            (0..10).map(|index| format!("check {index}")).collect();

        let bounded = bound_diagnosis_response(summary);

        assert_eq!(
            bounded.events[0].findings[0].recommended_checks.len(),
            MAX_DIAGNOSIS_NESTED_ROWS
        );
        let projection_gap = bounded
            .coverage_gaps
            .iter()
            .find(|gap| gap.source == DIAGNOSIS_RESPONSE_PROJECTION_SOURCE)
            .expect("nested truncation must produce grouped response coverage");
        assert!(projection_gap
            .detail
            .contains("omitted 6 nested detail rows"));
    }

    #[test]
    fn twenty_five_thousand_malformed_identities_are_one_exact_grouped_gap() {
        const RECORD_COUNT: usize = 25_000;
        let mut session = EventLogAnalysisSession::new("test-session".to_string());
        for chunk in 0..25 {
            let records = (0..1_000)
                .map(|index| {
                    let id = chunk * 1_000 + index + 1;
                    let mut record = record(id as u64, id as i64, "malformed identity");
                    record.event_record_id_text = Some("not-decimal".to_string());
                    record
                })
                .collect();
            session.append(records, Vec::new()).unwrap();
        }

        let status = session.finalize().unwrap();
        assert_eq!(status.total_items, RECORD_COUNT as u64);
        assert_eq!(status.total_coverage_gaps, 1);
        let page = session.page(0, 1).unwrap();
        assert_eq!(page.coverage_gaps_preview.len(), 1);
        assert_eq!(
            page.coverage_gaps_preview[0].reason,
            format!(
                "{RECORD_COUNT} event records were excluded from diagnosis because EventRecordID text must be a non-empty decimal value; timeline rows were retained."
            )
        );

        let summary = session.diagnosis_snapshot().unwrap().summarize(Vec::new());
        assert_eq!(summary.findings.len(), 1);
        assert_eq!(summary.coverage_gaps.len(), 1);
        assert_eq!(summary.overview.finding_count, 1);
        assert_eq!(summary.overview.actionable_finding_count, 0);
        assert_eq!(summary.overview.coverage_gap_count, 1);
        assert_eq!(
            summary.coverage_gaps[0].detail,
            format!(
                "{RECORD_COUNT} event records were excluded from diagnosis because EventRecordID text must be a non-empty decimal value; timeline rows were retained."
            )
        );
    }

    #[test]
    fn many_large_relevant_records_are_byte_bounded_with_grouped_coverage() {
        const RECORD_COUNT: usize = 240;
        let mut session = EventLogAnalysisSession::new("test-session".to_string());
        let detail = "diagnostic-detail".repeat(7_000);
        for chunk in 0..6 {
            let records = (0..40)
                .map(|index| {
                    let id = chunk * 40 + index + 1;
                    let mut record = mdm_success_record(id as u64);
                    record.message = format!("Enrollment failed with error 0x80070005. {detail}");
                    record.event_data[0].value = "Failure".to_string();
                    record
                })
                .collect();
            session.append(records, Vec::new()).unwrap();
        }
        session.finalize().unwrap();

        let summary = session.diagnosis_snapshot().unwrap().summarize(Vec::new());

        assert!(summary.overview.actionable_finding_count < RECORD_COUNT);
        assert!(summary.coverage_gaps.iter().any(|gap| {
            gap.source == "event-diagnosis-projection"
                && gap.detail.contains("serialized bytes")
                && gap.detail.contains("were omitted")
        }));
        assert!(serialized_len(&summary).unwrap() <= MAX_DIAGNOSIS_RESPONSE_BYTES);
    }

    #[test]
    fn twenty_five_thousand_relevant_events_return_bounded_exact_previews() {
        const RECORD_COUNT: usize = 25_000;
        const ERROR_EVENT_COUNT: usize = 137;
        let mut session = EventLogAnalysisSession::new("test-session".to_string());
        for chunk in 0..25 {
            let records = (0..1_000)
                .map(|index| {
                    let id = chunk * 1_000 + index + 1;
                    let mut record = mdm_success_record(id as u64);
                    if id <= ERROR_EVENT_COUNT {
                        record.message =
                            "Enrollment failed with error 0x80070005 despite Success status."
                                .to_string();
                    }
                    record
                })
                .collect();
            session.append(records, Vec::new()).unwrap();
        }
        session.finalize().unwrap();

        let summary = session.diagnosis_snapshot().unwrap().summarize(Vec::new());

        assert!(summary.findings.len() <= MAX_DIAGNOSIS_RESPONSE_ROWS);
        assert!(summary.evidence.len() <= MAX_DIAGNOSIS_RESPONSE_ROWS);
        assert!(summary.coverage_gaps.len() <= MAX_DIAGNOSIS_RESPONSE_ROWS);
        assert!(summary.correlations.len() <= MAX_DIAGNOSIS_RESPONSE_ROWS);
        assert!(summary.events.len() <= MAX_DIAGNOSIS_RESPONSE_ROWS);
        assert_eq!(summary.overview.actionable_finding_count, ERROR_EVENT_COUNT);
        assert_eq!(summary.overview.error_token_event_count, ERROR_EVENT_COUNT);
        assert_eq!(summary.overview.finding_count, ERROR_EVENT_COUNT + 1);
        assert_eq!(summary.overview.evidence_count, RECORD_COUNT);
        assert_eq!(summary.overview.coverage_gap_count, 1);
        assert_eq!(summary.overview.correlation_count, 0);
        assert_eq!(summary.overview.outcome, "contradictoryEvidence");
        let projection_gap = summary
            .coverage_gaps
            .iter()
            .find(|gap| gap.source == DIAGNOSIS_RESPONSE_PROJECTION_SOURCE)
            .expect("one grouped response projection gap");
        assert!(projection_gap
            .detail
            .contains("24900 of 25000 evidence references"));
        assert!(projection_gap
            .detail
            .contains("24900 of 25000 diagnosed events"));
        assert!(projection_gap
            .detail
            .contains("The serialized response is limited to 8388608 bytes."));
        let encoded = serde_json::to_vec(&summary).unwrap();
        assert!(
            encoded.len() < 2 * 1024 * 1024,
            "bounded diagnosis response was {} bytes",
            encoded.len()
        );
    }
}
