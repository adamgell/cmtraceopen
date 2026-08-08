use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use cmtraceopen_parser::intune::device::windows::inventory::{
    self, DeviceInventoryLogDialect, FramedLogicalRecord, LogicalRecordSegment,
    MAX_LOGICAL_RECORD_BYTES,
};
use cmtraceopen_parser::intune::portal::windows::company_portal::logs::looks_like_record_start;
use notify::{Config, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use serde::Serialize;

use crate::error_db::lookup::{detect_error_code_spans, ErrorCodeSpan};
use crate::models::log_entry::{
    LogEntry, ParseResult, ParserKind, ParserSpecialization, RecordFraming,
};
use crate::parser::{self, FileEncoding, ResolvedParser};

const IME_RECORD_START: &str = "<![LOG[";
const IME_RECORD_ATTRS_START: &str = "]LOG]!><";
const LOGICAL_RECORD_DEBOUNCE: Duration = Duration::from_millis(250);
const MAX_PENDING_LOGICAL_RECORD_BYTES: usize = 1024 * 1024;

/// Minimal initial-parse state needed to continue the final Company Portal
/// logical record without retaining or rereading the source file.
#[derive(Debug, Clone)]
pub struct InitialLogicalRecord {
    entry_id: u64,
    entry_line_number: u32,
    next_continuation_line: u32,
    message_utf16_len: usize,
}

impl InitialLogicalRecord {
    pub(crate) fn supports_parser(parser_selection: &ResolvedParser) -> bool {
        parser_selection.parser == ParserKind::CompanyPortal
            && parser_selection.record_framing == RecordFraming::LogicalRecord
    }

    /// Capture only the final rendered record's stable identity and offsets.
    /// The original message remains frontend-owned.
    pub fn from_parse_result(
        result: &ParseResult,
        parser_selection: &ResolvedParser,
    ) -> Option<Self> {
        let entry = result.entries.last()?;
        Self::from_entry(entry, result.total_lines, parser_selection)
    }

    pub(crate) fn from_entry(
        entry: &LogEntry,
        total_lines: u32,
        parser_selection: &ResolvedParser,
    ) -> Option<Self> {
        if !Self::supports_parser(parser_selection) {
            return None;
        }

        Some(Self {
            entry_id: entry.id,
            entry_line_number: entry.line_number,
            next_continuation_line: total_lines.saturating_add(1),
            message_utf16_len: entry.message.encode_utf16().count(),
        })
    }

    #[cfg(test)]
    pub(crate) fn entry_id_for_test(&self) -> u64 {
        self.entry_id
    }
}

/// Bounded suffix for a logical entry that was already rendered by the initial
/// whole-file parse.
///
/// The physical range and expected UTF-16 offset make application idempotent:
/// duplicate or stale out-of-order watcher events cannot append the same text
/// twice. Error spans are absolute offsets into the amended message.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TailEntryAmendment {
    pub entry_id: u64,
    pub entry_line_number: u32,
    pub continuation_start_line: u32,
    pub continuation_end_line: u32,
    pub message_utf16_start: usize,
    pub message_suffix: String,
    pub error_code_spans: Vec<ErrorCodeSpan>,
}

/// The result of reading new content from a tailed file.
pub struct TailBatch {
    /// Complete log records parsed since the last read.
    pub entries: Vec<LogEntry>,
    /// Bounded, ordered suffixes for entries emitted during the initial open.
    pub amendments: Vec<TailEntryAmendment>,
    /// Parse errors observed while producing this incremental batch.
    pub parse_errors: u32,
    /// Highest physical source line consumed by this batch, if any.
    pub observed_through_line: Option<u32>,
    /// True when the file was detected as truncated/rotated during this read.
    ///
    /// On truncation the reader rewinds to the start of the file, so `entries`
    /// (when non-empty) represent a fresh read from byte 0 and any entries
    /// previously emitted for this file are now stale. Consumers must replace,
    /// not append, their existing view for this file. A reset can also arrive
    /// with an empty `entries` list (file truncated to empty), which still
    /// means the prior view should be cleared.
    pub reset: bool,
}

impl TailBatch {
    fn empty(reset: bool) -> Self {
        Self {
            entries: Vec::new(),
            amendments: Vec::new(),
            parse_errors: 0,
            observed_through_line: None,
            reset,
        }
    }

    fn append(&mut self, other: Self) {
        self.entries.extend(other.entries);
        self.amendments.extend(other.amendments);
        self.parse_errors = self.parse_errors.saturating_add(other.parse_errors);
        self.observed_through_line = self.observed_through_line.max(other.observed_through_line);
        self.reset |= other.reset;
    }

    /// Whether the batch carries something a consumer must see.
    ///
    /// Parse errors count on their own: a batch that only reports malformed
    /// incremental input or a framing overflow still has to reach the session,
    /// otherwise those failures stay invisible until the tail stops.
    fn is_reportable(&self) -> bool {
        self.reset
            || !self.amendments.is_empty()
            || !self.entries.is_empty()
            || self.parse_errors > 0
            || self.observed_through_line.is_some()
    }
}

struct PendingInitialLogicalRecord {
    entry_id: u64,
    entry_line_number: u32,
    next_continuation_line: u32,
    message_utf16_len: usize,
    retained_suffix_bytes: usize,
    pending_suffix: String,
    pending_start_line: Option<u32>,
    pending_end_line: Option<u32>,
    last_updated: Instant,
    capped: bool,
    cap_reported: bool,
}

impl PendingInitialLogicalRecord {
    fn new(record: InitialLogicalRecord) -> Self {
        Self {
            entry_id: record.entry_id,
            entry_line_number: record.entry_line_number,
            next_continuation_line: record.next_continuation_line,
            message_utf16_len: record.message_utf16_len,
            retained_suffix_bytes: 0,
            pending_suffix: String::new(),
            pending_start_line: None,
            pending_end_line: None,
            last_updated: Instant::now(),
            capped: false,
            cap_reported: false,
        }
    }
}

struct PendingLogicalRecord {
    content: String,
    /// Last time this record saw activity. Only the Company Portal debounce
    /// reads it; inventory framing is chunk invariant and never flushes on
    /// elapsed time.
    last_updated: Instant,
    parser_selection: ResolvedParser,
}

struct LogicalRecordFramingResult {
    completed_records: Vec<FramedLogicalRecord>,
    pending_record: Option<String>,
    overflow_count: u32,
}

struct InitialContinuationResult {
    batch: TailBatch,
    /// Index of the first ordinary header in the supplied lines. `None` means
    /// every supplied line belonged to the initial logical record.
    remaining_start: Option<usize>,
}

/// Manages incremental reading of a log file from a tracked byte offset.
pub struct TailReader {
    path: PathBuf,
    byte_offset: u64,
    parser_selection: ResolvedParser,
    next_id: u64,
    next_line: u32,
    /// Leftover partial record fragment from the previous read.
    pending_fragment: String,
    /// Selection and activity time for an unterminated logical-record line.
    /// The Instant drives the Company Portal continuation debounce; inventory
    /// framing only reads the selection.
    pending_fragment_selection: Option<(ResolvedParser, Instant)>,
    /// True after a bounded prefix of the current physical line was framed.
    inventory_line_continuation: bool,
    /// Newest logical record held for continuation lines.
    pending_logical_record: Option<PendingLogicalRecord>,
    /// Bounded continuation state for the final Company Portal record emitted
    /// during initial open.
    pending_initial_logical_record: Option<PendingInitialLogicalRecord>,
    /// True after an unterminated initial continuation exceeded the cap. Bytes
    /// are discarded until its newline arrives so one physical line cannot be
    /// miscounted as several bounded fragments.
    discarding_capped_initial_line: bool,
    /// File encoding detected from BOM during initial parse.
    encoding: FileEncoding,
    /// Leftover partial byte from a UTF-16 read boundary split.
    pending_byte: Option<u8>,
    /// Incomplete UTF-8 scalar suffix retained across append boundaries.
    pending_utf8_bytes: Vec<u8>,
    /// Parser selection that owns the incomplete UTF-8 scalar suffix.
    pending_utf8_selection: Option<ResolvedParser>,
    #[cfg(test)]
    max_pending_bytes_observed: usize,
}

impl TailReader {
    /// Create a new TailReader starting after the initial parse.
    pub fn new(
        path: PathBuf,
        byte_offset: u64,
        parser_selection: ResolvedParser,
        next_id: u64,
        next_line: u32,
    ) -> Self {
        Self::new_internal(
            path,
            byte_offset,
            parser_selection,
            next_id,
            next_line,
            None,
        )
    }

    pub fn new_with_initial_logical_record(
        path: PathBuf,
        byte_offset: u64,
        parser_selection: ResolvedParser,
        next_id: u64,
        next_line: u32,
        initial_logical_record: InitialLogicalRecord,
    ) -> Self {
        Self::new_internal(
            path,
            byte_offset,
            parser_selection,
            next_id,
            next_line,
            Some(initial_logical_record),
        )
    }

    fn new_internal(
        path: PathBuf,
        byte_offset: u64,
        parser_selection: ResolvedParser,
        next_id: u64,
        next_line: u32,
        initial_logical_record: Option<InitialLogicalRecord>,
    ) -> Self {
        // Encoding is determined by at most the three BOM bytes. The initial
        // source has already been parsed, so tail setup must not read it again.
        let encoding = detect_file_encoding(&path);

        Self {
            path,
            byte_offset,
            parser_selection,
            next_id,
            next_line,
            pending_fragment: String::new(),
            pending_fragment_selection: None,
            inventory_line_continuation: false,
            pending_logical_record: None,
            pending_initial_logical_record: initial_logical_record
                .map(PendingInitialLogicalRecord::new),
            discarding_capped_initial_line: false,
            encoding,
            pending_byte: None,
            pending_utf8_bytes: Vec::new(),
            pending_utf8_selection: None,
            #[cfg(test)]
            max_pending_bytes_observed: 0,
        }
    }

    /// Read new content from the file since last read, parse into entries.
    /// Returns the new entries plus a `reset` flag and updates internal byte_offset.
    pub fn read_new_entries(&mut self) -> Result<TailBatch, crate::error::AppError> {
        let now = Instant::now();
        let mut file = std::fs::File::open(&self.path).map_err(crate::error::AppError::Io)?;
        let metadata = file.metadata().map_err(crate::error::AppError::Io)?;
        let file_size = metadata.len();

        // File was truncated (e.g. log rotation) — rewind to the beginning and
        // signal a reset so the frontend replaces (not appends) its stale view.
        // Line numbers restart at 1 to match the new file generation; ids stay
        // monotonic so they remain unique across the reset.
        let mut batch = TailBatch::empty(false);
        let mut reset = false;
        if file_size < self.byte_offset {
            // Company Portal continuation state belongs to the replaced file
            // generation; discard it instead of publishing stale amendments or
            // stale-numbered records into the fresh view.
            self.pending_initial_logical_record = None;
            self.discarding_capped_initial_line = false;
            let company_portal_owner = self
                .pending_logical_record
                .as_ref()
                .map(|pending| &pending.parser_selection)
                .or_else(|| {
                    self.pending_fragment_selection
                        .as_ref()
                        .map(|(selection, _)| selection)
                })
                .is_some_and(company_portal_logical_framing);
            if company_portal_owner {
                self.pending_logical_record = None;
                self.pending_fragment.clear();
                self.pending_fragment_selection = None;
            }
            batch.append(self.finalize_pending_input());
            self.byte_offset = 0;
            self.pending_fragment.clear();
            self.pending_fragment_selection = None;
            self.inventory_line_continuation = false;
            self.pending_logical_record = None;
            self.pending_byte = None;
            self.pending_utf8_bytes.clear();
            self.pending_utf8_selection = None;
            self.next_line = 1;
            batch.reset = true;
            reset = true;
        }

        if !reset && self.pending_parser_selection_changed() {
            batch.append(self.finalize_pending_input());
            return Ok(batch);
        }

        if !reset && self.company_portal_debounce_elapsed(now) {
            batch.append(self.flush_pending_logical_record());
        }

        // No new data
        if file_size == self.byte_offset {
            return Ok(batch);
        }

        // Seek to our byte offset
        file.seek(SeekFrom::Start(self.byte_offset))
            .map_err(crate::error::AppError::Io)?;

        let bytes_to_read = file_size - self.byte_offset;
        let mut buffer = vec![0u8; bytes_to_read as usize];
        file.read_exact(&mut buffer)
            .map_err(crate::error::AppError::Io)?;

        let new_text = self.decode_tail_bytes(buffer)?;
        let received_text = !new_text.is_empty();

        let inventory_dialect = inventory_logical_dialect(&self.parser_selection);
        if let Some(dialect) = inventory_dialect {
            let selection = self.parser_selection.clone();
            if received_text {
                batch.append(self.process_inventory_text(&new_text, dialect, &selection));
            }
            self.byte_offset = file_size;
            return Ok(batch);
        }

        // Prepend any partial record fragment from the last read.
        let mut full_text = if self.pending_fragment.is_empty() {
            new_text
        } else {
            let combined = format!("{}{}", self.pending_fragment, new_text);
            self.pending_fragment.clear();
            self.pending_fragment_selection = None;
            combined
        };

        if self.discarding_capped_initial_line {
            let Some(newline) = full_text.find('\n') else {
                self.byte_offset = file_size;
                return Ok(batch);
            };
            full_text = full_text[newline + 1..].to_string();
            self.discarding_capped_initial_line = false;
        }

        let lines = match self.parser_selection.record_framing {
            RecordFraming::PhysicalLine => {
                collect_complete_lines(&full_text, &mut self.pending_fragment)
            }
            RecordFraming::LogicalRecord => {
                if matches!(
                    self.parser_selection.specialization,
                    Some(ParserSpecialization::Ime)
                ) {
                    collect_complete_ime_lines(&full_text, &mut self.pending_fragment)
                } else {
                    collect_complete_lines(&full_text, &mut self.pending_fragment)
                }
            }
        };

        if company_portal_logical_framing(&self.parser_selection) {
            let selection = self.parser_selection.clone();
            if !self.pending_fragment.is_empty() {
                self.pending_fragment_selection = Some((selection.clone(), now));
            }

            if received_text {
                if let Some(pending) = self.pending_logical_record.as_mut() {
                    pending.last_updated = now;
                }
            }

            if !lines.is_empty() {
                let remaining_start = if let Some(initial) =
                    self.consume_initial_company_portal_lines(&lines, now)
                {
                    let remaining_start = initial.remaining_start;
                    batch.append(initial.batch);
                    if remaining_start.is_none() {
                        batch.append(self.enforce_initial_fragment_bound(now));
                        self.byte_offset = file_size;
                        return Ok(batch);
                    }
                    remaining_start.unwrap_or_default()
                } else {
                    0
                };

                let prior = self
                    .pending_logical_record
                    .take()
                    .map(|pending| pending.content);
                let framed = frame_company_portal_logical_records(
                    prior,
                    &lines[remaining_start..],
                    MAX_PENDING_LOGICAL_RECORD_BYTES,
                );

                if let Some(content) = framed.pending_record {
                    self.pending_logical_record = Some(PendingLogicalRecord {
                        content,
                        last_updated: now,
                        parser_selection: selection.clone(),
                    });
                }

                batch.append(self.parse_company_portal_records(
                    framed.completed_records,
                    &selection,
                    framed.overflow_count,
                ));
            }

            if self.pending_initial_logical_record.is_some() {
                batch.append(self.enforce_initial_fragment_bound(now));
                self.byte_offset = file_size;
                return Ok(batch);
            }

            batch.append(self.enforce_unterminated_logical_bound(&selection, now));
            self.byte_offset = file_size;
            return Ok(batch);
        }

        if lines.is_empty() {
            self.byte_offset = file_size;
            return Ok(batch);
        }

        // Parse the new complete records through the same dispatch path as initial parsing.
        let path_str = self.path.to_string_lossy().to_string();
        let (mut entries, parse_errors) =
            parser::parse_lines_with_selection(&lines, &path_str, &self.parser_selection);

        let physical_line_count = u32::try_from(lines.len()).unwrap_or(u32::MAX);
        self.assign_physical_entry_identity(&mut entries, physical_line_count);
        batch.append(TailBatch {
            entries,
            amendments: Vec::new(),
            parse_errors,
            observed_through_line: self.next_line.checked_sub(1).filter(|line| *line > 0),
            reset: false,
        });

        // We already keep incomplete text in pending_fragment. Advance to the
        // actual file size so the same bytes are not read and prepended again.
        self.byte_offset = file_size;

        Ok(batch)
    }

    fn decode_tail_bytes(&mut self, buffer: Vec<u8>) -> Result<String, crate::error::AppError> {
        if self.encoding != FileEncoding::Utf8 {
            let decode_buffer = if let Some(previous_byte) = self.pending_byte.take() {
                let mut combined = Vec::with_capacity(buffer.len().saturating_add(1));
                combined.push(previous_byte);
                combined.extend_from_slice(&buffer);
                combined
            } else {
                buffer
            };
            let decode_len = if decode_buffer.len() % 2 == 0 {
                decode_buffer.len()
            } else {
                let split = decode_buffer.len() - 1;
                self.pending_byte = Some(decode_buffer[split]);
                split
            };
            return crate::parser::decode_bytes(&decode_buffer[..decode_len], self.encoding)
                .map_err(|error| {
                    crate::error::AppError::Internal(format!(
                        "Failed to decode tailed bytes: {error}"
                    ))
                });
        }

        let previous_carry = std::mem::take(&mut self.pending_utf8_bytes);
        let previous_carry_selection = self.pending_utf8_selection.take();
        let decoded_start_offset = self.byte_offset.saturating_sub(previous_carry.len() as u64);
        let mut decode_buffer = if previous_carry.is_empty() {
            buffer
        } else {
            let mut combined =
                Vec::with_capacity(previous_carry.len().saturating_add(buffer.len()));
            combined.extend_from_slice(&previous_carry);
            combined.extend_from_slice(&buffer);
            combined
        };

        if decoded_start_offset == 0 && decode_buffer.starts_with(&[0xEF, 0xBB, 0xBF]) {
            decode_buffer.drain(..3);
        }

        match String::from_utf8(decode_buffer) {
            Ok(text) => Ok(text),
            Err(error) => {
                let utf8_error = error.utf8_error();
                if utf8_error.error_len().is_some() {
                    self.pending_utf8_bytes = previous_carry;
                    self.pending_utf8_selection = previous_carry_selection;
                    return Err(crate::error::AppError::Internal(
                        "Failed to decode tailed bytes: invalid UTF-8".to_string(),
                    ));
                }

                let valid_up_to = utf8_error.valid_up_to();
                let mut bytes = error.into_bytes();
                let incomplete = bytes.split_off(valid_up_to);
                if incomplete.len() > 3 {
                    self.pending_utf8_bytes = previous_carry;
                    self.pending_utf8_selection = previous_carry_selection;
                    return Err(crate::error::AppError::Internal(
                        "Failed to decode tailed bytes: invalid UTF-8".to_string(),
                    ));
                }
                self.pending_utf8_bytes = incomplete;
                self.pending_utf8_selection =
                    previous_carry_selection.or_else(|| Some(self.parser_selection.clone()));
                String::from_utf8(bytes).map_err(|_| {
                    crate::error::AppError::Internal(
                        "Failed to decode tailed bytes: invalid UTF-8".to_string(),
                    )
                })
            }
        }
    }

    fn pending_parser_selection_changed(&self) -> bool {
        self.pending_logical_record
            .as_ref()
            .is_some_and(|pending| pending.parser_selection != self.parser_selection)
            || self
                .pending_fragment_selection
                .as_ref()
                .is_some_and(|(selection, _)| selection != &self.parser_selection)
            || self
                .pending_utf8_selection
                .as_ref()
                .is_some_and(|selection| selection != &self.parser_selection)
            || (self.pending_initial_logical_record.is_some()
                && !InitialLogicalRecord::supports_parser(&self.parser_selection))
    }

    /// Whether Company Portal pending state has been idle long enough that the
    /// held continuation text must be flushed to the consumer.
    ///
    /// Only state owned by a Company Portal selection participates: inventory
    /// framing is chunk invariant and never flushes on elapsed time.
    fn company_portal_debounce_elapsed(&self, now: Instant) -> bool {
        let last_updated = self
            .pending_logical_record
            .as_ref()
            .filter(|pending| company_portal_logical_framing(&pending.parser_selection))
            .map(|pending| pending.last_updated)
            .into_iter()
            .chain(
                self.pending_initial_logical_record
                    .as_ref()
                    .filter(|pending| !pending.pending_suffix.is_empty())
                    .map(|pending| pending.last_updated),
            )
            .chain(
                self.pending_fragment_selection
                    .as_ref()
                    .filter(|(selection, _)| company_portal_logical_framing(selection))
                    .map(|(_, updated)| *updated),
            )
            .max();

        last_updated.is_some_and(|updated| {
            now.saturating_duration_since(updated) >= LOGICAL_RECORD_DEBOUNCE
        })
    }

    fn process_inventory_text(
        &mut self,
        text: &str,
        dialect: DeviceInventoryLogDialect,
        selection: &ResolvedParser,
    ) -> TailBatch {
        let mut batch = TailBatch::empty(false);
        for segment in text.split_inclusive('\n') {
            let line_complete = segment.ends_with('\n');
            let content = segment.strip_suffix('\n').unwrap_or(segment);
            batch.append(self.process_inventory_line_segment(
                content,
                line_complete,
                dialect,
                selection,
            ));
        }
        batch
    }

    fn process_inventory_line_segment(
        &mut self,
        raw_content: &str,
        line_complete: bool,
        dialect: DeviceInventoryLogDialect,
        selection: &ResolvedParser,
    ) -> TailBatch {
        let content = if line_complete {
            raw_content.trim_end_matches('\r')
        } else {
            raw_content
        };

        if self.inventory_line_continuation {
            let batch = self.frame_inventory_segments(
                dialect,
                selection,
                &[LogicalRecordSegment::LineContinuation(content)],
            );
            if line_complete {
                self.inventory_line_continuation = false;
                self.pending_fragment_selection = None;
            } else {
                self.pending_fragment_selection = Some((selection.clone(), Instant::now()));
            }
            self.observe_pending_bytes();
            return batch;
        }

        if line_complete && self.pending_fragment.is_empty() {
            let batch = self.frame_inventory_segments(
                dialect,
                selection,
                &[LogicalRecordSegment::LineStart(content)],
            );
            self.pending_fragment_selection = None;
            self.observe_pending_bytes();
            return batch;
        }

        let mut batch = TailBatch::empty(false);
        let mut remaining = content;
        while !remaining.is_empty() {
            let logical_bytes = self
                .pending_logical_record
                .as_ref()
                .map_or(0, |record| record.content.len());
            let separator_bytes = usize::from(self.pending_logical_record.is_some());
            let available = MAX_LOGICAL_RECORD_BYTES
                .saturating_sub(logical_bytes)
                .saturating_sub(separator_bytes)
                .saturating_sub(self.pending_fragment.len());
            let take = utf8_prefix_at_most(remaining, available);
            if take > 0 {
                self.pending_fragment.push_str(&remaining[..take]);
                remaining = &remaining[take..];
                self.pending_fragment_selection = Some((selection.clone(), Instant::now()));
                self.observe_pending_bytes();
            }

            if !remaining.is_empty() {
                let prefix = std::mem::take(&mut self.pending_fragment);
                batch.append(self.frame_inventory_segments(
                    dialect,
                    selection,
                    &[LogicalRecordSegment::LineStart(&prefix)],
                ));
                self.inventory_line_continuation = true;
                batch.append(self.frame_inventory_segments(
                    dialect,
                    selection,
                    &[LogicalRecordSegment::LineContinuation(remaining)],
                ));
                remaining = "";
            }
        }

        if line_complete && !self.inventory_line_continuation {
            let mut line = std::mem::take(&mut self.pending_fragment);
            while line.ends_with('\r') {
                line.pop();
            }
            batch.append(self.frame_inventory_segments(
                dialect,
                selection,
                &[LogicalRecordSegment::LineStart(&line)],
            ));
        }
        if line_complete {
            self.inventory_line_continuation = false;
            self.pending_fragment_selection = None;
        } else if !content.is_empty() {
            self.pending_fragment_selection = Some((selection.clone(), Instant::now()));
        }

        self.observe_pending_bytes();
        batch
    }

    fn frame_inventory_segments(
        &mut self,
        dialect: DeviceInventoryLogDialect,
        selection: &ResolvedParser,
        segments: &[LogicalRecordSegment<'_>],
    ) -> TailBatch {
        let prior = self
            .pending_logical_record
            .take()
            .map(|pending| pending.content);
        let framed = inventory::frame_logical_records(dialect, prior, segments);
        #[cfg(test)]
        {
            self.max_pending_bytes_observed = self
                .max_pending_bytes_observed
                .max(framed.max_pending_bytes_observed);
        }
        if let Some(content) = framed.pending_record {
            self.pending_logical_record = Some(PendingLogicalRecord {
                content,
                last_updated: Instant::now(),
                parser_selection: selection.clone(),
            });
        }
        self.parse_logical_records(framed.completed_records, dialect, framed.overflow_count)
    }

    fn observe_pending_bytes(&mut self) {
        #[cfg(test)]
        {
            let logical_bytes = self
                .pending_logical_record
                .as_ref()
                .map_or(0, |record| record.content.len());
            let fragment_bytes = self.pending_fragment.len().saturating_add(usize::from(
                self.pending_logical_record.is_some() && !self.pending_fragment.is_empty(),
            ));
            self.max_pending_bytes_observed = self
                .max_pending_bytes_observed
                .max(logical_bytes.saturating_add(fragment_bytes));
        }
    }

    fn flush_pending_text(&mut self) -> TailBatch {
        let pending = self.pending_logical_record.take();
        let fragment = std::mem::take(&mut self.pending_fragment);
        let fragment_selection = self.pending_fragment_selection.take();

        let selection = pending
            .as_ref()
            .map(|record| record.parser_selection.clone())
            .or_else(|| fragment_selection.map(|(selection, _)| selection));
        let Some(selection) = selection else {
            return TailBatch::empty(false);
        };
        let Some(dialect) = inventory_logical_dialect(&selection) else {
            return TailBatch::empty(false);
        };

        let mut pending_content = pending.map(|record| record.content);
        let mut completed_records = Vec::new();
        let mut overflow_count = 0u32;
        if !fragment.is_empty() {
            let framed = inventory::frame_logical_records(
                dialect,
                pending_content,
                &[LogicalRecordSegment::LineStart(&fragment)],
            );
            pending_content = framed.pending_record;
            completed_records.extend(framed.completed_records);
            overflow_count = overflow_count.saturating_add(framed.overflow_count);
        }
        let framed =
            inventory::frame_logical_records(dialect, pending_content, &[]).flush_pending();
        completed_records.extend(framed.completed_records);
        overflow_count = overflow_count.saturating_add(framed.overflow_count);
        self.inventory_line_continuation = false;

        // An empty record is kept rather than dropped. It parses to no entries
        // either way, but a blank line is still a physical line, and dropping
        // the record here would drop the line it accounts for and shift every
        // later line number down by one.
        self.parse_logical_records(completed_records, dialect, overflow_count)
    }

    /// Complete all input that can still produce text at a real terminal boundary.
    ///
    /// Pending state belongs to exactly one framing family at a time: Company
    /// Portal logical records flush through their amendment-aware path, and
    /// every other selection flushes through the inventory-aware text flush.
    /// An incomplete UTF-8 suffix is not decoded lossily: once no later bytes
    /// can complete it, consuming it contributes exactly one surfaced parse
    /// error.
    fn finalize_pending_input(&mut self) -> TailBatch {
        let company_portal_owner = self
            .pending_logical_record
            .as_ref()
            .map(|pending| &pending.parser_selection)
            .or_else(|| {
                self.pending_fragment_selection
                    .as_ref()
                    .map(|(selection, _)| selection)
            })
            .is_some_and(company_portal_logical_framing);
        let mut batch = if company_portal_owner || self.pending_initial_logical_record.is_some() {
            self.flush_pending_logical_record()
        } else {
            self.flush_pending_text()
        };
        let incomplete_utf8 = !std::mem::take(&mut self.pending_utf8_bytes).is_empty();
        self.pending_utf8_selection = None;
        if incomplete_utf8 {
            batch.parse_errors = batch.parse_errors.saturating_add(1);
        }
        batch
    }

    fn consume_initial_company_portal_lines(
        &mut self,
        lines: &[&str],
        now: Instant,
    ) -> Option<InitialContinuationResult> {
        self.pending_initial_logical_record.as_ref()?;

        let first_header = lines
            .iter()
            .position(|line| looks_like_record_start(line.trim_end()));

        let continuation_count = first_header.unwrap_or(lines.len());
        let mut batch = TailBatch::empty(false);
        let mut newly_capped = false;

        if let Some(pending) = self.pending_initial_logical_record.as_mut() {
            for line in &lines[..continuation_count] {
                newly_capped |= append_initial_continuation(
                    pending,
                    line.trim_end(),
                    now,
                    MAX_PENDING_LOGICAL_RECORD_BYTES,
                );
            }
            self.next_line = pending.next_continuation_line;
            if continuation_count > 0 {
                batch.observed_through_line = Some(self.next_line.saturating_sub(1));
            }
            if newly_capped && !pending.cap_reported {
                pending.cap_reported = true;
                batch.parse_errors = 1;
            }
        }

        if newly_capped || first_header.is_some() {
            if let Some(amendment) = self.take_initial_amendment() {
                batch.amendments.push(amendment);
            }
        }

        if first_header.is_some() {
            self.pending_initial_logical_record = None;
        }

        Some(InitialContinuationResult {
            batch,
            remaining_start: first_header,
        })
    }

    fn take_initial_amendment(&mut self) -> Option<TailEntryAmendment> {
        let pending = self.pending_initial_logical_record.as_mut()?;
        if pending.pending_suffix.is_empty() {
            return None;
        }

        let continuation_start_line = pending.pending_start_line.take()?;
        let continuation_end_line = pending.pending_end_line.take()?;
        let message_suffix = std::mem::take(&mut pending.pending_suffix);
        let message_utf16_start = pending.message_utf16_len;
        let mut error_code_spans = detect_error_code_spans(&message_suffix);
        for span in &mut error_code_spans {
            span.start = span.start.saturating_add(message_utf16_start);
            span.end = span.end.saturating_add(message_utf16_start);
        }
        pending.message_utf16_len = pending
            .message_utf16_len
            .saturating_add(message_suffix.encode_utf16().count());

        Some(TailEntryAmendment {
            entry_id: pending.entry_id,
            entry_line_number: pending.entry_line_number,
            continuation_start_line,
            continuation_end_line,
            message_utf16_start,
            message_suffix,
            error_code_spans,
        })
    }

    fn enforce_initial_fragment_bound(&mut self, now: Instant) -> TailBatch {
        let retained_suffix_bytes = self
            .pending_initial_logical_record
            .as_ref()
            .map_or(0, |pending| pending.retained_suffix_bytes);
        let pending_bytes = retained_suffix_bytes
            .saturating_add(usize::from(!self.pending_fragment.is_empty()))
            .saturating_add(self.pending_fragment.len());
        if pending_bytes <= MAX_PENDING_LOGICAL_RECORD_BYTES {
            return TailBatch::empty(false);
        }

        let fragment = std::mem::take(&mut self.pending_fragment);
        self.pending_fragment_selection = None;
        let mut batch = TailBatch::empty(false);
        if let Some(pending) = self.pending_initial_logical_record.as_mut() {
            let newly_capped = append_initial_continuation(
                pending,
                &fragment,
                now,
                MAX_PENDING_LOGICAL_RECORD_BYTES,
            );
            self.next_line = pending.next_continuation_line;
            batch.observed_through_line = Some(self.next_line.saturating_sub(1));
            if newly_capped && !pending.cap_reported {
                pending.cap_reported = true;
                batch.parse_errors = 1;
            }
        }
        if let Some(amendment) = self.take_initial_amendment() {
            batch.amendments.push(amendment);
        }
        self.discarding_capped_initial_line = true;
        batch
    }

    fn flush_pending_logical_record(&mut self) -> TailBatch {
        if self.pending_initial_logical_record.is_some()
            && !InitialLogicalRecord::supports_parser(&self.parser_selection)
        {
            self.pending_initial_logical_record = None;
            self.discarding_capped_initial_line = false;
        }

        let mut batch = TailBatch::empty(false);
        let mut fragment = std::mem::take(&mut self.pending_fragment);
        let mut fragment_selection = self.pending_fragment_selection.take();

        if self.pending_initial_logical_record.is_some() {
            if !fragment.is_empty() {
                let fragment_lines = [fragment.as_str()];
                if let Some(initial) =
                    self.consume_initial_company_portal_lines(&fragment_lines, Instant::now())
                {
                    let is_new_header = initial.remaining_start == Some(0);
                    batch.append(initial.batch);
                    if !is_new_header {
                        fragment.clear();
                        fragment_selection = None;
                    }
                }
            }

            if let Some(amendment) = self.take_initial_amendment() {
                batch.amendments.push(amendment);
            }
        }

        let pending = self.pending_logical_record.take();

        let selection = pending
            .as_ref()
            .map(|record| record.parser_selection.clone())
            .or_else(|| fragment_selection.map(|(selection, _)| selection));
        let Some(selection) = selection else {
            return batch;
        };
        if !company_portal_logical_framing(&selection) {
            return batch;
        }

        let mut overflow_count = 0;
        let records = if fragment.is_empty() {
            pending
                .map(|record| vec![FramedLogicalRecord::complete(record.content)])
                .unwrap_or_default()
        } else {
            let fragment_lines = [fragment.as_str()];
            let framed = frame_company_portal_logical_records(
                pending.map(|record| record.content),
                &fragment_lines,
                MAX_PENDING_LOGICAL_RECORD_BYTES,
            );
            overflow_count = framed.overflow_count;
            let mut records = framed.completed_records;
            // The flush ends the record, so the retained pending text owns its
            // last physical line the same way a header-terminated record does.
            records.extend(framed.pending_record.map(FramedLogicalRecord::complete));
            records
        };

        // An empty record is kept rather than dropped. It parses to no entries
        // either way, but a blank line is still a physical line, and dropping
        // the record here would drop the line it accounts for and shift every
        // later line number down by one.
        batch.append(self.parse_company_portal_records(records, &selection, overflow_count));
        batch
    }

    fn enforce_unterminated_logical_bound(
        &mut self,
        selection: &ResolvedParser,
        now: Instant,
    ) -> TailBatch {
        let pending_len = self
            .pending_logical_record
            .as_ref()
            .map_or(0, |record| record.content.len());
        let pending_bytes = pending_len
            .saturating_add(self.pending_fragment.len())
            .saturating_add(usize::from(
                pending_len > 0 && !self.pending_fragment.is_empty(),
            ));
        if pending_bytes <= MAX_PENDING_LOGICAL_RECORD_BYTES {
            return TailBatch::empty(false);
        }

        let pending = self
            .pending_logical_record
            .take()
            .map(|record| record.content);
        let fragment = std::mem::take(&mut self.pending_fragment);
        self.pending_fragment_selection = None;
        let fragment_lines = [fragment.as_str()];
        let framed = frame_company_portal_logical_records(
            pending,
            &fragment_lines,
            MAX_PENDING_LOGICAL_RECORD_BYTES,
        );

        self.pending_fragment = framed.pending_record.unwrap_or_default();
        if !self.pending_fragment.is_empty() {
            self.pending_fragment_selection = Some((selection.clone(), now));
        }

        self.parse_company_portal_records(framed.completed_records, selection, framed.overflow_count)
    }

    fn parse_company_portal_records(
        &mut self,
        records: Vec<FramedLogicalRecord>,
        selection: &ResolvedParser,
        framing_parse_errors: u32,
    ) -> TailBatch {
        let path_str = self.path.to_string_lossy().to_string();
        let mut entries = Vec::new();
        let mut parse_errors = framing_parse_errors;
        let mut consumed_physical_lines = 0u32;

        for record in records {
            consumed_physical_lines = consumed_physical_lines.saturating_add(record.physical_lines);
            let parsed =
                parser::parse_content_with_selection(&record.content, &path_str, selection);
            let mut record_entries = parsed.entries;
            self.assign_framed_entry_identity(&mut record_entries, record.physical_lines);
            entries.extend(record_entries);
            parse_errors = parse_errors.saturating_add(parsed.parse_errors);
        }

        TailBatch {
            entries,
            amendments: Vec::new(),
            parse_errors,
            observed_through_line: (consumed_physical_lines > 0)
                .then(|| self.next_line.saturating_sub(1))
                .filter(|line| *line > 0),
            reset: false,
        }
    }

    fn parse_logical_records(
        &mut self,
        records: Vec<FramedLogicalRecord>,
        dialect: DeviceInventoryLogDialect,
        framing_parse_errors: u32,
    ) -> TailBatch {
        let path_str = self.path.to_string_lossy().to_string();
        let physical_lines = records.iter().fold(0u32, |total, record| {
            total.saturating_add(record.physical_lines)
        });
        let (mut entries, projection_errors) =
            inventory::parse_framed_records(&path_str, &records, dialect);
        parser::annotate_error_code_spans(&mut entries);
        self.assign_framed_entry_identity(&mut entries, physical_lines);

        TailBatch {
            entries,
            amendments: Vec::new(),
            parse_errors: framing_parse_errors.saturating_add(projection_errors),
            observed_through_line: (physical_lines > 0)
                .then(|| self.next_line.saturating_sub(1))
                .filter(|line| *line > 0),
            reset: false,
        }
    }

    /// Number one framed batch's entries, then advance past all of its lines.
    ///
    /// A logical record spans its header plus every continuation beneath it, so
    /// the next record starts at this record's first line plus its physical
    /// line count, not plus its entry count. Advancing per entry would drift
    /// below the real file position on the first multi-line record and keep
    /// drifting, which would make "go to line" disagree between a tailed file
    /// and the same file opened. Entries arrive carrying the line they sit on
    /// within the record, which is what the whole-file parse assigns, so they
    /// rebase onto the record's own start line.
    fn assign_framed_entry_identity(&mut self, entries: &mut [LogEntry], physical_lines: u32) {
        let record_start = self.next_line;
        for entry in entries {
            entry.id = self.next_id;
            entry.line_number = record_start.saturating_add(entry.line_number.saturating_sub(1));
            self.next_id += 1;
        }
        self.next_line = record_start.saturating_add(physical_lines);
    }

    fn assign_physical_entry_identity(&mut self, entries: &mut [LogEntry], physical_lines: u32) {
        let batch_start = self.next_line;
        for entry in entries {
            entry.id = self.next_id;
            entry.line_number = batch_start.saturating_add(entry.line_number.saturating_sub(1));
            self.next_id += 1;
        }
        self.next_line = batch_start.saturating_add(physical_lines);
    }
}

fn inventory_logical_dialect(selection: &ResolvedParser) -> Option<DeviceInventoryLogDialect> {
    if selection.record_framing != RecordFraming::LogicalRecord {
        return None;
    }

    match selection.specialization {
        // Harvester headers usually frame a single line, but the parser still
        // attaches a non-header line to the record above it, so tailing has to
        // frame it the same way the initial parse does.
        Some(ParserSpecialization::IntuneDeviceInventoryHarvester) => {
            Some(DeviceInventoryLogDialect::Harvester)
        }
        Some(ParserSpecialization::IntuneDeviceInventoryAdaptor) => {
            Some(DeviceInventoryLogDialect::InventoryAdaptor)
        }
        Some(ParserSpecialization::IntuneDeviceInventoryRotationFailure) => {
            Some(DeviceInventoryLogDialect::RotationFailure)
        }
        _ => None,
    }
}

fn company_portal_logical_framing(selection: &ResolvedParser) -> bool {
    selection.record_framing == RecordFraming::LogicalRecord
        && selection.specialization.is_none()
        && selection.parser == ParserKind::CompanyPortal
}

/// Retain at most `max_retained_bytes` across every amendment emitted for the
/// initial logical record. Once capped, later continuation content is counted
/// as observed but intentionally not retained; the caller reports that single
/// coverage gap through `parse_errors`.
fn append_initial_continuation(
    pending: &mut PendingInitialLogicalRecord,
    line: &str,
    now: Instant,
    max_retained_bytes: usize,
) -> bool {
    let line_number = pending.next_continuation_line;
    pending.next_continuation_line = pending.next_continuation_line.saturating_add(1);
    pending.last_updated = now;

    if pending.capped {
        return false;
    }

    let required_bytes = 1usize.saturating_add(line.len());
    let remaining = max_retained_bytes.saturating_sub(pending.retained_suffix_bytes);
    let accepted_bytes = required_bytes.min(remaining);

    if accepted_bytes > 0 {
        if pending.pending_start_line.is_none() {
            pending.pending_start_line = Some(line_number);
        }
        pending.pending_end_line = Some(line_number);
        pending.pending_suffix.push('\n');

        let line_capacity = accepted_bytes.saturating_sub(1);
        let split_at = previous_char_boundary(line, line_capacity);
        pending.pending_suffix.push_str(&line[..split_at]);
        pending.retained_suffix_bytes = pending
            .retained_suffix_bytes
            .saturating_add(1)
            .saturating_add(split_at);
    }

    if accepted_bytes < required_bytes {
        pending.capped = true;
        return true;
    }

    false
}

fn frame_company_portal_logical_records(
    mut pending_record: Option<String>,
    new_lines: &[&str],
    max_pending_bytes: usize,
) -> LogicalRecordFramingResult {
    let mut completed_records = Vec::new();
    let mut overflow_count = 0u32;

    for raw_line in new_lines {
        let line = raw_line.trim_end();
        if looks_like_record_start(line) {
            if let Some(record) = pending_record.take() {
                completed_records.push(FramedLogicalRecord::complete(record));
            }
        }

        match pending_record.as_mut() {
            Some(record) => {
                record.push('\n');
                record.push_str(line);
            }
            None => pending_record = Some(line.to_string()),
        }

        while pending_record
            .as_ref()
            .is_some_and(|record| record.len() > max_pending_bytes)
        {
            let mut record = pending_record
                .take()
                .expect("oversized Company Portal record must exist");
            let split_at = previous_char_boundary(&record, max_pending_bytes);
            let remainder = record.split_off(split_at);
            completed_records.push(FramedLogicalRecord {
                physical_lines: u32::try_from(record.matches('\n').count()).unwrap_or(u32::MAX),
                content: record,
            });
            overflow_count = overflow_count.saturating_add(1);
            pending_record = (!remainder.is_empty()).then_some(remainder);
        }
    }

    LogicalRecordFramingResult {
        completed_records,
        pending_record,
        overflow_count,
    }
}

fn previous_char_boundary(text: &str, maximum: usize) -> usize {
    let mut boundary = maximum.min(text.len());
    while !text.is_char_boundary(boundary) {
        boundary -= 1;
    }
    boundary
}

fn detect_file_encoding(path: &Path) -> FileEncoding {
    std::fs::File::open(path).map_or_else(
        |_| crate::parser::detect_encoding(&[]),
        detect_encoding_from_reader,
    )
}

fn detect_encoding_from_reader(reader: impl Read) -> FileEncoding {
    let mut bom = Vec::with_capacity(3);
    match reader.take(3).read_to_end(&mut bom) {
        Ok(_) => crate::parser::detect_encoding(&bom),
        Err(_) => crate::parser::detect_encoding(&[]),
    }
}

fn collect_complete_lines<'a>(text: &'a str, pending_fragment: &mut String) -> Vec<&'a str> {
    let ends_with_newline = text.ends_with('\n') || text.ends_with("\r\n");
    let mut lines: Vec<&str> = text.lines().collect();

    if !ends_with_newline && !lines.is_empty() {
        pending_fragment.push_str(lines.pop().unwrap_or(""));
    }

    lines
}

fn utf8_prefix_at_most(text: &str, maximum: usize) -> usize {
    let mut boundary = maximum.min(text.len());
    while !text.is_char_boundary(boundary) {
        boundary -= 1;
    }
    boundary
}

fn collect_complete_ime_lines<'a>(text: &'a str, pending_fragment: &mut String) -> Vec<&'a str> {
    let cutoff = find_complete_ime_cutoff(text);

    if cutoff < text.len() {
        pending_fragment.push_str(&text[cutoff..]);
    }

    text[..cutoff].lines().collect()
}

fn find_complete_ime_cutoff(text: &str) -> usize {
    let mut cursor = 0usize;

    loop {
        let Some(relative_start) = text[cursor..].find(IME_RECORD_START) else {
            return cursor + complete_unmatched_tail_len(&text[cursor..]);
        };

        let record_start = cursor + relative_start;

        let Some(record_end) = find_complete_ime_record_end(text, record_start) else {
            return record_start;
        };

        cursor = record_end;
    }
}

fn find_complete_ime_record_end(text: &str, record_start: usize) -> Option<usize> {
    let message_start = record_start + IME_RECORD_START.len();
    let attrs_relative_start = text[message_start..].find(IME_RECORD_ATTRS_START)?;
    let attrs_start = message_start + attrs_relative_start + IME_RECORD_ATTRS_START.len();
    let attrs_relative_end = text[attrs_start..].find('>')?;

    Some(attrs_start + attrs_relative_end + 1)
}

fn complete_unmatched_tail_len(text: &str) -> usize {
    if text.is_empty() {
        return 0;
    }

    if text.ends_with('\n') {
        return text.len();
    }

    text.rfind('\n').map(|index| index + 1).unwrap_or(0)
}

fn emit_final_tail_batch<F>(tail_reader: &mut TailReader, on_new_entries: F)
where
    F: FnOnce(TailBatch),
{
    let batch = tail_reader.finalize_pending_input();
    if batch.is_reportable() {
        on_new_entries(batch);
    }
}

/// Represents an active tail-watching session
pub struct TailSession {
    /// Flag to signal the watcher thread to stop
    stop_flag: Arc<AtomicBool>,
    /// Flag to pause emitting events (file is still tracked)
    paused: Arc<AtomicBool>,
}

impl TailSession {
    pub fn set_paused(&self, paused: bool) {
        self.paused.store(paused, Ordering::Relaxed);
    }

    pub fn stop(&self) {
        self.stop_flag.store(true, Ordering::Relaxed);
    }
}

/// Start watching a file for changes.
/// Spawns a background thread that monitors the file and calls `on_new_entries`
/// whenever new log entries appear.
pub fn start_tail_session<F>(
    path: PathBuf,
    byte_offset: u64,
    parser_selection: ResolvedParser,
    next_id: u64,
    next_line: u32,
    initial_logical_record: Option<InitialLogicalRecord>,
    on_new_entries: F,
) -> Result<TailSession, crate::error::AppError>
where
    F: Fn(TailBatch) + Send + 'static,
{
    let stop_flag = Arc::new(AtomicBool::new(false));
    let paused = Arc::new(AtomicBool::new(false));

    let stop_flag_clone = stop_flag.clone();
    let paused_clone = paused.clone();
    let watch_path = path.clone();

    std::thread::spawn(move || {
        let mut tail_reader = match initial_logical_record {
            Some(initial_logical_record) => TailReader::new_with_initial_logical_record(
                path,
                byte_offset,
                parser_selection,
                next_id,
                next_line,
                initial_logical_record,
            ),
            None => TailReader::new(path, byte_offset, parser_selection, next_id, next_line),
        };

        // Create a channel for notify events
        let (tx, rx) = std::sync::mpsc::channel();

        let mut watcher = match RecommendedWatcher::new(tx, Config::default()) {
            Ok(w) => w,
            Err(e) => {
                log::error!("Failed to create file watcher: {}", e);
                return;
            }
        };

        // Watch the parent directory (some systems don't notify on file-level watch
        // when the file is recreated/rotated)
        let watch_dir = watch_path.parent().unwrap_or(Path::new("."));
        if let Err(e) = watcher.watch(watch_dir, RecursiveMode::NonRecursive) {
            log::error!("Failed to start watching {}: {}", watch_dir.display(), e);
            return;
        }

        log::info!("Tail watcher started for {}", watch_path.display());

        // Also do a periodic poll as a fallback (some editors/log writers
        // may not trigger filesystem events reliably)
        let poll_interval = if company_portal_logical_framing(&tail_reader.parser_selection) {
            // The continuation debounce only makes progress when the reader is
            // polled, so a Company Portal tail polls on the debounce cadence.
            LOGICAL_RECORD_DEBOUNCE
        } else {
            Duration::from_millis(500)
        };

        loop {
            if stop_flag_clone.load(Ordering::Relaxed) {
                emit_final_tail_batch(&mut tail_reader, &on_new_entries);
                log::info!("Tail watcher stopped for {}", watch_path.display());
                break;
            }

            // Wait for a notify event or poll timeout
            match rx.recv_timeout(poll_interval) {
                Ok(Ok(event)) => {
                    // Only react to modify/create events for our file
                    match event.kind {
                        EventKind::Modify(_) | EventKind::Create(_)
                            if event.paths.iter().any(|p| p == &watch_path)
                                && !paused_clone.load(Ordering::Relaxed) =>
                        {
                            if let Ok(batch) = tail_reader.read_new_entries() {
                                if batch.is_reportable() {
                                    on_new_entries(batch);
                                }
                            }
                        }
                        _ => {}
                    }
                }
                Ok(Err(e)) => {
                    log::warn!("Watcher error: {}", e);
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    // Periodic poll — check for changes even without FS event
                    if !paused_clone.load(Ordering::Relaxed) {
                        if let Ok(batch) = tail_reader.read_new_entries() {
                            if batch.is_reportable() {
                                on_new_entries(batch);
                            }
                        }
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    emit_final_tail_batch(&mut tail_reader, &on_new_entries);
                    log::info!("Watcher channel disconnected");
                    break;
                }
            }
        }
    });

    Ok(TailSession { stop_flag, paused })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::log_entry::{LogFormat, ParserSpecialization, Severity};
    use crate::parser;
    use crate::parser::detect::ResolvedParser;
    use crate::parser::timestamped::DateOrder;
    use std::fs::{self, OpenOptions};
    use std::io::Write;
    use std::time::{SystemTime, UNIX_EPOCH};

    const PANTHER_CLEAN_FIXTURE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/corpus/panther/clean/setupact.log"
    ));
    const CBS_CLEAN_FIXTURE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/corpus/cbs/clean/CBS.log"
    ));
    const DISM_CLEAN_FIXTURE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/corpus/dism/clean/dism.log"
    ));
    const REPORTING_EVENTS_CLEAN_FIXTURE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/corpus/reporting_events/clean/ReportingEvents.log"
    ));
    fn unique_test_path(name: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("cmtrace-open-{name}-{stamp}.log"))
    }

    fn hinted_test_path(root: &Path, relative: &str) -> PathBuf {
        root.join(relative.replace('/', std::path::MAIN_SEPARATOR_STR))
    }

    fn hinted_test_root(name: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after unix epoch")
            .as_nanos();

        std::env::temp_dir().join(format!("cmtrace-open-{name}-{stamp}"))
    }

    fn split_fixture(fixture: &str, initial_line_count: usize) -> (String, String) {
        let lines: Vec<&str> = fixture.lines().collect();
        let initial = format!("{}\n", lines[..initial_line_count].join("\n"));
        let appended = format!("{}\n", lines[initial_line_count..].join("\n"));
        (initial, appended)
    }

    struct OneByteAtATime<'a>(&'a [u8]);

    impl Read for OneByteAtATime<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            if self.0.is_empty() || buffer.is_empty() {
                return Ok(0);
            }
            buffer[0] = self.0[0];
            self.0 = &self.0[1..];
            Ok(1)
        }
    }

    #[test]
    fn test_encoding_probe_consumes_a_short_reader_through_the_bom() {
        let encoding = detect_encoding_from_reader(OneByteAtATime(&[0xff, 0xfe, b'a']));

        assert_eq!(encoding, FileEncoding::Utf16Le);
    }

    #[test]
    fn test_blank_physical_line_advances_coverage_without_creating_an_entry() {
        let path = unique_test_path("tail-reader-blank-physical-line");
        fs::write(&path, "").expect("should create empty log");
        let mut reader = TailReader::new(path.clone(), 0, ResolvedParser::plain_text(), 0, 1);

        fs::write(&path, "\n").expect("should append one blank physical line");
        let batch = reader.read_new_entries().expect("tail read should succeed");

        assert!(batch.entries.is_empty());
        assert_eq!(batch.observed_through_line, Some(1));
        assert_eq!(reader.next_line, 2);

        fs::remove_file(path).expect("should clean up temp file");
    }

    #[test]
    fn test_empty_logical_batch_does_not_report_line_zero() {
        let path = unique_test_path("tail-reader-empty-logical-batch");
        fs::write(&path, "").expect("should create empty Company Portal log");
        let selection = ResolvedParser::company_portal();
        let mut reader = TailReader::new(path.clone(), 0, selection.clone(), 0, 1);

        let batch = reader.parse_company_portal_records(Vec::new(), &selection, 0);

        assert_eq!(batch.observed_through_line, None);
        assert_eq!(reader.next_line, 1);

        fs::remove_file(path).expect("should clean up temp file");
    }

    fn assert_entries_match(actual: &LogEntry, expected: &LogEntry) {
        assert_eq!(actual.id, expected.id);
        assert_eq!(actual.line_number, expected.line_number);
        assert_eq!(actual.message, expected.message);
        assert_eq!(actual.component, expected.component);
        assert_eq!(actual.timestamp, expected.timestamp);
        assert_eq!(actual.timestamp_display, expected.timestamp_display);
        assert_eq!(actual.severity, expected.severity);
        assert_eq!(actual.format, expected.format);
        assert_eq!(actual.file_path, expected.file_path);
    }

    fn inventory_record_with_size(header: &str, total_bytes: usize, suffix: &str) -> String {
        let fixed_bytes = header.len() + 1 + suffix.len();
        assert!(fixed_bytes <= total_bytes);
        format!(
            "{header}\n{}{suffix}",
            "x".repeat(total_bytes - fixed_bytes)
        )
    }

    fn assert_inventory_tail_matches_initial(
        test_name: &str,
        dialect: DeviceInventoryLogDialect,
        first_record: &str,
        next_header: &str,
    ) {
        let path = unique_test_path(test_name);
        fs::write(&path, "").expect("should create empty Device Inventory log");
        let selection = ResolvedParser::intune_device_inventory(dialect);
        let mut reader = TailReader::new(path.clone(), 0, selection, 0, 1);
        let split_at = first_record
            .find('\n')
            .expect("test record should have a continuation boundary")
            + 1;
        let appends = [
            first_record[..split_at].to_string(),
            first_record[split_at..].to_string(),
            format!("\n{next_header}\n"),
        ];
        let mut tailed_entries = Vec::new();
        let mut tail_errors = 0u32;

        for appended in &appends {
            let mut file = OpenOptions::new()
                .append(true)
                .open(&path)
                .expect("should reopen Device Inventory log");
            write!(file, "{appended}").expect("should append Device Inventory content");
            drop(file);

            let batch = reader
                .read_new_entries()
                .expect("Device Inventory tail read should succeed");
            tailed_entries.extend(batch.entries);
            tail_errors = tail_errors.saturating_add(batch.parse_errors);

            let retained_bytes = reader
                .pending_logical_record
                .as_ref()
                .map_or(0, |record| record.content.len())
                .saturating_add(reader.pending_fragment.len())
                .saturating_add(usize::from(
                    reader.pending_logical_record.is_some() && !reader.pending_fragment.is_empty(),
                ));
            assert!(retained_bytes <= MAX_LOGICAL_RECORD_BYTES);
        }

        let flushed = reader.finalize_pending_input();
        tailed_entries.extend(flushed.entries);
        tail_errors = tail_errors.saturating_add(flushed.parse_errors);

        let content = format!("{first_record}\n{next_header}\n");
        let (opened_entries, opened_errors) =
            inventory::parse_content(&path.to_string_lossy(), &content, dialect);
        let projection = |entries: &[LogEntry]| {
            entries
                .iter()
                .map(|entry| (entry.line_number, entry.severity, entry.message.clone()))
                .collect::<Vec<_>>()
        };

        assert_eq!(
            tail_errors, opened_errors,
            "tail/open parse-error parity failed for {test_name}"
        );
        assert_eq!(projection(&tailed_entries), projection(&opened_entries));
        assert!(tailed_entries
            .iter()
            .all(|entry| entry.message.len() <= MAX_LOGICAL_RECORD_BYTES));

        fs::remove_file(path).expect("should clean up temp file");
    }

    fn inventory_projection(entries: &[LogEntry]) -> Vec<(u32, Severity, String)> {
        entries
            .iter()
            .map(|entry| (entry.line_number, entry.severity, entry.message.clone()))
            .collect()
    }

    fn append_bytes(path: &Path, bytes: &[u8]) {
        let mut file = OpenOptions::new()
            .append(true)
            .open(path)
            .expect("should reopen tail fixture");
        file.write_all(bytes)
            .expect("should append raw fixture bytes");
    }

    fn reader_with_terminal_utf8_prefix(name: &str, prefix: &[u8]) -> (PathBuf, TailReader) {
        let path = unique_test_path(name);
        fs::write(&path, []).expect("should create terminal UTF-8 fixture");
        let mut reader = TailReader::new(
            path.clone(),
            0,
            ResolvedParser::intune_device_inventory(DeviceInventoryLogDialect::Harvester),
            0,
            1,
        );
        append_bytes(
            &path,
            b"7/30/2026 6:00:54 AM [Information] TERMINAL-CONTENT",
        );
        append_bytes(&path, prefix);
        let batch = reader
            .read_new_entries()
            .expect("an incomplete terminal scalar should remain pending");
        assert!(batch.entries.is_empty());
        assert_eq!(batch.parse_errors, 0);
        assert_eq!(reader.pending_utf8_bytes, prefix);
        (path, reader)
    }

    #[test]
    fn test_delayed_inventory_continuations_match_initial_parse_for_every_dialect() {
        let cases = [
            (
                DeviceInventoryLogDialect::Harvester,
                "7/30/2026 6:00:54 AM [Information] DELAYED-START",
                "DELAYED-HARVESTER-CONTINUATION",
                "7/30/2026 6:00:55 AM [Warning] DELAYED-NEXT",
            ),
            (
                DeviceInventoryLogDialect::InventoryAdaptor,
                "[Thu Jul 30 13:05:01 2026][8604] - DELAYED-START",
                "DELAYED-ADAPTOR-CONTINUATION",
                "[Thu Jul 30 13:05:02 2026][8604] - DELAYED-NEXT",
            ),
            (
                DeviceInventoryLogDialect::RotationFailure,
                "2026-07-30T13:05:01.1234567-04:00 Failed to rotate DELAYED-START",
                "System.IO.IOException: DELAYED-ROTATION-CONTINUATION",
                "2026-07-30T13:05:02.1234567-04:00 DELAYED-NEXT",
            ),
        ];

        for (dialect, header, continuation, next_header) in cases {
            let path = unique_test_path(&format!("inventory-delayed-{dialect:?}"));
            fs::write(&path, "").expect("should create delayed fixture");
            let mut reader = TailReader::new(
                path.clone(),
                0,
                ResolvedParser::intune_device_inventory(dialect),
                0,
                1,
            );
            append_bytes(&path, format!("{header}\n").as_bytes());
            assert!(reader
                .read_new_entries()
                .expect("header read should succeed")
                .entries
                .is_empty());

            std::thread::sleep(Duration::from_millis(275));
            append_bytes(&path, format!("{continuation}\n{next_header}\n").as_bytes());
            let mut tailed = reader
                .read_new_entries()
                .expect("delayed continuation read should succeed");
            tailed.append(reader.finalize_pending_input());

            let content = format!("{header}\n{continuation}\n{next_header}\n");
            let (opened, opened_errors) =
                inventory::parse_content(&path.to_string_lossy(), &content, dialect);
            assert_eq!(tailed.parse_errors, opened_errors);
            assert_eq!(
                inventory_projection(&tailed.entries),
                inventory_projection(&opened)
            );
            assert!(tailed.entries[0].message.contains(continuation));

            fs::remove_file(path).expect("should clean up delayed fixture");
        }
    }

    #[test]
    fn test_utf8_scalars_split_across_tail_reads_match_initial_parse() {
        for scalar in ["¢", "€", "🧪"] {
            for split in 1..scalar.len() {
                let path = unique_test_path(&format!("inventory-utf8-{}-{split}", scalar.len()));
                fs::write(&path, "").expect("should create UTF-8 fixture");
                let dialect = DeviceInventoryLogDialect::InventoryAdaptor;
                let mut reader = TailReader::new(
                    path.clone(),
                    0,
                    ResolvedParser::intune_device_inventory(dialect),
                    0,
                    1,
                );
                let prefix = "[Thu Jul 30 13:05:01 2026][8604] - UTF8-";
                append_bytes(&path, prefix.as_bytes());
                append_bytes(&path, &scalar.as_bytes()[..split]);
                assert!(reader
                    .read_new_entries()
                    .expect("incomplete scalar should remain pending")
                    .entries
                    .is_empty());
                assert!(reader.pending_utf8_bytes.len() <= 3);

                let suffix = "-TAIL\n[Thu Jul 30 13:05:02 2026][8604] - NEXT\n";
                append_bytes(&path, &scalar.as_bytes()[split..]);
                append_bytes(&path, suffix.as_bytes());
                let mut tailed = reader
                    .read_new_entries()
                    .expect("completed scalar read should succeed");
                tailed.append(reader.finalize_pending_input());

                let content = format!("{prefix}{scalar}{suffix}");
                let (opened, opened_errors) =
                    inventory::parse_content(&path.to_string_lossy(), &content, dialect);
                assert_eq!(tailed.parse_errors, opened_errors);
                assert_eq!(
                    inventory_projection(&tailed.entries),
                    inventory_projection(&opened)
                );
                assert!(tailed
                    .entries
                    .iter()
                    .all(|entry| !entry.message.contains('�')));

                fs::remove_file(path).expect("should clean up UTF-8 fixture");
            }
        }
    }

    #[test]
    fn test_utf8_bom_split_across_tail_reads_is_still_removed() {
        let path = unique_test_path("inventory-split-utf8-bom");
        fs::write(&path, []).expect("should create BOM fixture");
        let dialect = DeviceInventoryLogDialect::Harvester;
        let mut reader = TailReader::new(
            path.clone(),
            0,
            ResolvedParser::intune_device_inventory(dialect),
            0,
            1,
        );

        for byte in [0xEF, 0xBB] {
            append_bytes(&path, &[byte]);
            assert!(reader
                .read_new_entries()
                .expect("partial BOM should remain pending")
                .entries
                .is_empty());
        }
        let content = "7/30/2026 6:00:54 AM [Information] BOM-SPLIT\n";
        append_bytes(&path, &[0xBF]);
        append_bytes(&path, content.as_bytes());
        let mut tailed = reader
            .read_new_entries()
            .expect("completed BOM should decode");
        tailed.append(reader.finalize_pending_input());

        let (opened, opened_errors) =
            inventory::parse_content(&path.to_string_lossy(), content, dialect);
        assert_eq!(tailed.parse_errors, opened_errors);
        assert_eq!(
            inventory_projection(&tailed.entries),
            inventory_projection(&opened)
        );

        fs::remove_file(path).expect("should clean up BOM fixture");
    }

    #[test]
    fn test_terminal_utf8_prefixes_fail_closed_exactly_once() {
        for (label, prefix) in [
            ("two-byte", &[0xC2][..]),
            ("three-byte", &[0xE2, 0x82][..]),
            ("four-byte", &[0xF0, 0x9F, 0xA7][..]),
        ] {
            let (path, mut reader) =
                reader_with_terminal_utf8_prefix(&format!("terminal-{label}"), prefix);

            let finalized = reader.finalize_pending_input();
            assert_eq!(finalized.parse_errors, 1, "{label}");
            assert_eq!(finalized.entries.len(), 1, "{label}");
            assert_eq!(finalized.entries[0].message, "TERMINAL-CONTENT", "{label}");
            assert!(!finalized.entries[0].message.contains('�'), "{label}");
            assert!(reader.pending_utf8_bytes.is_empty(), "{label}");

            let repeated = reader.finalize_pending_input();
            assert_eq!(repeated.parse_errors, 0, "{label}");
            assert!(repeated.entries.is_empty(), "{label}");

            fs::remove_file(path).expect("should clean up terminal UTF-8 fixture");
        }
    }

    #[test]
    fn test_terminal_partial_utf8_bom_fails_closed() {
        let path = unique_test_path("terminal-partial-bom");
        fs::write(&path, []).expect("should create terminal BOM fixture");
        let mut reader = TailReader::new(
            path.clone(),
            0,
            ResolvedParser::intune_device_inventory(DeviceInventoryLogDialect::Harvester),
            0,
            1,
        );
        append_bytes(&path, &[0xEF, 0xBB]);
        reader
            .read_new_entries()
            .expect("a partial BOM should remain pending");

        let finalized = reader.finalize_pending_input();
        assert_eq!(finalized.parse_errors, 1);
        assert!(finalized.entries.is_empty());
        assert!(reader.pending_utf8_bytes.is_empty());

        fs::remove_file(path).expect("should clean up terminal BOM fixture");
    }

    #[test]
    fn test_terminal_utf8_prefix_fails_closed_on_parser_change() {
        let (path, mut reader) =
            reader_with_terminal_utf8_prefix("terminal-parser-change", &[0xE2, 0x82]);
        reader.parser_selection = ResolvedParser::plain_text();

        let finalized = reader
            .read_new_entries()
            .expect("parser change should finalize old decoder state");
        assert_eq!(finalized.parse_errors, 1);
        assert_eq!(finalized.entries.len(), 1);
        assert_eq!(finalized.entries[0].message, "TERMINAL-CONTENT");
        assert!(reader.pending_utf8_bytes.is_empty());

        fs::remove_file(path).expect("should clean up parser-change fixture");
    }

    #[test]
    fn test_parser_change_finalizes_utf8_carry_without_pending_text() {
        let path = unique_test_path("terminal-carry-only-parser-change");
        fs::write(&path, []).expect("should create carry-only fixture");
        let mut reader = TailReader::new(path.clone(), 0, ResolvedParser::plain_text(), 0, 1);
        append_bytes(&path, b"valid content\n");
        let valid = reader
            .read_new_entries()
            .expect("valid content should parse before the terminal prefix");
        assert_eq!(valid.entries.len(), 1);

        append_bytes(&path, &[0xE2, 0x82]);
        reader
            .read_new_entries()
            .expect("incomplete scalar should remain pending");
        assert!(reader.pending_fragment.is_empty());
        reader.parser_selection = ResolvedParser::generic_timestamped(DateOrder::MonthFirst);

        let finalized = reader
            .read_new_entries()
            .expect("parser change should finalize carry-only decoder state");
        assert_eq!(finalized.parse_errors, 1);
        assert!(finalized.entries.is_empty());
        assert!(reader.pending_utf8_bytes.is_empty());

        fs::remove_file(path).expect("should clean up carry-only fixture");
    }

    #[test]
    fn test_terminal_utf8_prefix_fails_closed_on_truncation() {
        for (label, prefix) in [
            ("two-byte", &[0xC2][..]),
            ("three-byte", &[0xE2, 0x82][..]),
            ("four-byte", &[0xF0, 0x9F, 0xA7][..]),
            ("partial-bom", &[0xEF, 0xBB][..]),
        ] {
            let (path, mut reader) =
                reader_with_terminal_utf8_prefix(&format!("terminal-truncation-{label}"), prefix);
            fs::write(&path, []).expect("should truncate terminal UTF-8 fixture");

            let finalized = reader
                .read_new_entries()
                .expect("truncation should finalize old decoder state");
            assert!(finalized.reset, "{label}");
            assert_eq!(finalized.parse_errors, 1, "{label}");
            assert_eq!(finalized.entries.len(), 1, "{label}");
            assert_eq!(finalized.entries[0].message, "TERMINAL-CONTENT", "{label}");
            assert!(!finalized.entries[0].message.contains('�'), "{label}");
            assert!(reader.pending_utf8_bytes.is_empty(), "{label}");
            assert!(reader.pending_fragment.is_empty(), "{label}");
            assert!(reader.pending_logical_record.is_none(), "{label}");
            assert_eq!(reader.next_id, 1, "{label}");

            let repeated_read = reader
                .read_new_entries()
                .expect("empty replacement file should stay empty");
            assert!(!repeated_read.reset, "{label}");
            assert_eq!(repeated_read.parse_errors, 0, "{label}");
            assert!(repeated_read.entries.is_empty(), "{label}");

            let repeated_finalization = reader.finalize_pending_input();
            assert_eq!(repeated_finalization.parse_errors, 0, "{label}");
            assert!(repeated_finalization.entries.is_empty(), "{label}");

            fs::remove_file(path).expect("should clean up truncation fixture");
        }
    }

    #[test]
    fn test_watcher_terminal_emission_surfaces_incomplete_utf8() {
        let (path, mut reader) = reader_with_terminal_utf8_prefix("terminal-watcher-exit", &[0xC2]);
        let mut emitted = None;

        emit_final_tail_batch(&mut reader, |batch| emitted = Some(batch));

        let emitted = emitted.expect("terminal parse error must reach the watcher callback");
        assert_eq!(emitted.parse_errors, 1);
        assert_eq!(emitted.entries.len(), 1);
        assert_eq!(emitted.entries[0].message, "TERMINAL-CONTENT");
        assert!(reader.pending_utf8_bytes.is_empty());

        fs::remove_file(path).expect("should clean up watcher-exit fixture");
    }

    #[test]
    fn test_invalid_utf8_tail_read_fails_closed_without_state_changes() {
        let path = unique_test_path("inventory-invalid-utf8");
        fs::write(&path, "").expect("should create invalid UTF-8 fixture");
        let mut reader = TailReader::new(
            path.clone(),
            0,
            ResolvedParser::intune_device_inventory(DeviceInventoryLogDialect::Harvester),
            0,
            1,
        );
        append_bytes(
            &path,
            b"7/30/2026 6:00:54 AM [Information] INVALID-UTF8-\xff\n",
        );

        let error = match reader.read_new_entries() {
            Err(error) => error,
            Ok(_) => panic!("invalid UTF-8 must fail closed"),
        };
        assert!(error.to_string().contains("invalid UTF-8"));
        assert_eq!(reader.byte_offset, 0);
        assert!(reader.pending_utf8_bytes.is_empty());
        assert!(reader.pending_fragment.is_empty());
        assert!(reader.pending_logical_record.is_none());
        assert_eq!(reader.next_id, 0);
        assert_eq!(reader.next_line, 1);

        fs::remove_file(path).expect("should clean up invalid UTF-8 fixture");

        let path = unique_test_path("inventory-invalid-utf8-after-carry");
        fs::write(&path, []).expect("should create split-invalid UTF-8 fixture");
        let mut reader = TailReader::new(
            path.clone(),
            0,
            ResolvedParser::intune_device_inventory(DeviceInventoryLogDialect::Harvester),
            0,
            1,
        );
        append_bytes(&path, &[0xE2]);
        reader
            .read_new_entries()
            .expect("an incomplete scalar is not invalid input");
        append_bytes(&path, b"(");

        let error = match reader.read_new_entries() {
            Err(error) => error,
            Ok(_) => panic!("an invalid continuation byte must fail closed"),
        };
        assert!(error.to_string().contains("invalid UTF-8"));
        assert_eq!(reader.byte_offset, 1);
        assert_eq!(reader.pending_utf8_bytes, vec![0xE2]);
        assert!(reader
            .pending_utf8_selection
            .as_ref()
            .is_some_and(|selection| selection == &reader.parser_selection));
        assert!(reader.pending_fragment.is_empty());
        assert!(reader.pending_logical_record.is_none());
        assert_eq!(reader.next_id, 0);
        assert_eq!(reader.next_line, 1);

        fs::remove_file(path).expect("should clean up split-invalid UTF-8 fixture");
    }

    #[test]
    fn test_huge_terminated_and_unterminated_inventory_lines_never_exceed_pending_peak() {
        let path = unique_test_path("inventory-pending-peak");
        fs::write(&path, "").expect("should create peak fixture");
        let dialect = DeviceInventoryLogDialect::InventoryAdaptor;
        let mut reader = TailReader::new(
            path.clone(),
            0,
            ResolvedParser::intune_device_inventory(dialect),
            0,
            1,
        );
        let header = "[Thu Jul 30 13:05:01 2026][8604] - PEAK-START\n";
        let huge = format!("{}🧪-PEAK-TAIL", "x".repeat(MAX_LOGICAL_RECORD_BYTES * 3));
        append_bytes(&path, header.as_bytes());
        append_bytes(&path, huge.as_bytes());
        let first = reader
            .read_new_entries()
            .expect("unterminated huge line should parse incrementally");
        assert!(first.parse_errors >= 2);
        assert!(reader.max_pending_bytes_observed <= MAX_LOGICAL_RECORD_BYTES);
        assert!(reader.pending_fragment.len() <= MAX_LOGICAL_RECORD_BYTES);

        append_bytes(&path, b"\n[Thu Jul 30 13:05:02 2026][8604] - PEAK-NEXT\n");
        let second = reader
            .read_new_entries()
            .expect("terminated huge line should finish");
        assert!(reader.max_pending_bytes_observed <= MAX_LOGICAL_RECORD_BYTES);
        assert!(second
            .entries
            .iter()
            .all(|entry| entry.message.len() <= MAX_LOGICAL_RECORD_BYTES));

        fs::remove_file(path).expect("should clean up peak fixture");
    }

    #[test]
    fn test_tail_reader_reuses_backend_parser_selection() {
        let path = unique_test_path("tail-reader-selection");
        let initial = "15/01/2024 08:00:00 Initial entry\n";
        fs::write(&path, initial).expect("should write initial file");

        let byte_offset = fs::metadata(&path).expect("metadata should exist").len();

        let selection = ResolvedParser::generic_timestamped(DateOrder::DayFirst);
        let mut reader = TailReader::new(path.clone(), byte_offset, selection, 1, 2);

        let mut file = OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("should reopen temp file");
        writeln!(file, "16/01/2024 09:30:00 Follow-up entry").expect("should append log line");
        drop(file);

        let entries = reader
            .read_new_entries()
            .expect("tail read should succeed")
            .entries;

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].format, LogFormat::Timestamped);
        assert_eq!(entries[0].id, 1);
        assert_eq!(entries[0].line_number, 2);
        assert_eq!(
            entries[0].timestamp_display.as_deref(),
            Some("2024-01-16 09:30:00.000")
        );

        fs::remove_file(path).expect("should clean up temp file");
    }

    #[test]
    fn test_tail_reader_does_not_duplicate_buffered_partial_line() {
        let path = unique_test_path("tail-reader-partial-line");
        fs::write(&path, "initial\n").expect("should write initial file");

        let byte_offset = fs::metadata(&path).expect("metadata should exist").len();

        let mut reader = TailReader::new(
            path.clone(),
            byte_offset,
            ResolvedParser::plain_text(),
            1,
            2,
        );

        let mut file = OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("should reopen temp file");
        write!(file, "complete\npartial").expect("should append complete and partial lines");
        drop(file);

        let first_entries = reader
            .read_new_entries()
            .expect("first tail read should succeed")
            .entries;
        assert_eq!(first_entries.len(), 1);
        assert_eq!(first_entries[0].message, "complete");

        let mut file = OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("should reopen temp file");
        writeln!(file, " done").expect("should complete buffered partial line");
        drop(file);

        let second_entries = reader
            .read_new_entries()
            .expect("second tail read should succeed")
            .entries;
        assert_eq!(second_entries.len(), 1);
        assert_eq!(second_entries[0].message, "partial done");

        fs::remove_file(path).expect("should clean up temp file");
    }

    #[test]
    fn test_tail_reader_matches_open_parse_for_regression_corpus_cases() {
        struct TailParityCase<'a> {
            name: &'a str,
            hinted_relative_path: &'a str,
            fixture: &'a str,
            initial_line_count: usize,
        }

        let cases = [
            TailParityCase {
                name: "panther-parity",
                hinted_relative_path: "Windows/Panther/setupact.log",
                fixture: PANTHER_CLEAN_FIXTURE,
                initial_line_count: 3,
            },
            TailParityCase {
                name: "cbs-parity",
                hinted_relative_path: "Windows/Logs/CBS/CBS.log",
                fixture: CBS_CLEAN_FIXTURE,
                initial_line_count: 3,
            },
            TailParityCase {
                name: "dism-parity",
                hinted_relative_path: "Windows/Logs/DISM/dism.log",
                fixture: DISM_CLEAN_FIXTURE,
                initial_line_count: 2,
            },
            TailParityCase {
                name: "reporting-events-parity",
                hinted_relative_path: "Windows/SoftwareDistribution/ReportingEvents.log",
                fixture: REPORTING_EVENTS_CLEAN_FIXTURE,
                initial_line_count: 1,
            },
        ];

        for case in cases {
            let root = hinted_test_root(case.name);
            let path = hinted_test_path(&root, case.hinted_relative_path);
            let parent = path.parent().expect("fixture path should have a parent");
            fs::create_dir_all(parent).expect("should create temporary parser hint directories");

            let (initial, appended) = split_fixture(case.fixture, case.initial_line_count);
            fs::write(&path, &initial).expect("should write initial fixture chunk");

            let path_str = path.to_string_lossy().to_string();
            let (initial_result, selection) =
                parser::parse_file(&path_str).expect("initial fixture should parse");

            let mut reader = TailReader::new(
                path.clone(),
                initial_result.byte_offset,
                selection,
                initial_result.entries.len() as u64,
                initial_result.total_lines + 1,
            );

            let mut file = OpenOptions::new()
                .append(true)
                .open(&path)
                .expect("should reopen temp file");
            write!(file, "{}", appended).expect("should append trailing fixture chunk");
            drop(file);

            let tail_entries = reader
                .read_new_entries()
                .expect("tail read should succeed")
                .entries;
            let (full_result, _) =
                parser::parse_file(&path_str).expect("full fixture should parse");
            let expected_entries = &full_result.entries[initial_result.entries.len()..];

            assert_eq!(
                tail_entries.len(),
                expected_entries.len(),
                "case={}",
                case.name
            );

            for (actual, expected) in tail_entries.iter().zip(expected_entries.iter()) {
                assert_entries_match(actual, expected);
            }

            fs::remove_dir_all(root).expect("should clean up temp parity fixture");
        }
    }

    #[test]
    fn test_tail_reader_buffers_incomplete_ime_record_until_complete() {
        let root = hinted_test_root("ime-tail-boundary");
        let path = hinted_test_path(
            &root,
            "ProgramData/Microsoft/IntuneManagementExtension/Logs/HealthScripts.log",
        );
        let parent = path.parent().expect("fixture path should have a parent");
        fs::create_dir_all(parent).expect("should create temporary parser hint directories");

        let initial = "<![LOG[Powershell execution is done, exitCode = 1]LOG]!><time=\"11:16:37.3093207\" date=\"3-12-2026\" component=\"HealthScripts\" context=\"\" type=\"1\" thread=\"50\" file=\"\">\n";
        fs::write(&path, initial).expect("should write initial fixture chunk");

        let path_str = path.to_string_lossy().to_string();
        let (initial_result, selection) =
            parser::parse_file(&path_str).expect("initial fixture should parse");

        assert_eq!(selection.specialization, Some(ParserSpecialization::Ime));

        let mut reader = TailReader::new(
            path.clone(),
            initial_result.byte_offset,
            selection,
            initial_result.entries.len() as u64,
            initial_result.total_lines + 1,
        );

        let partial_append = concat!(
            "<![LOG[[HS] err output = Downloaded profile payload is not valid JSON.\n",
            "At C:\\Windows\\IMECache\\HealthScripts\\script.ps1:457 char:9\n"
        );

        let mut file = OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("should reopen temp file");
        write!(file, "{}", partial_append).expect("should append partial IME record");
        drop(file);

        let partial_entries = reader
            .read_new_entries()
            .expect("partial IME tail read should succeed")
            .entries;

        assert!(partial_entries.is_empty());

        let mut file = OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("should reopen temp file");
        writeln!(
            file,
            "]LOG]!><time=\"11:16:42.3322734\" date=\"3-12-2026\" component=\"HealthScripts\" context=\"\" type=\"3\" thread=\"50\" file=\"\">"
        )
        .expect("should append IME record terminator");
        drop(file);

        let tail_entries = reader
            .read_new_entries()
            .expect("complete IME tail read should succeed")
            .entries;
        let (full_result, _) = parser::parse_file(&path_str).expect("full fixture should parse");

        assert_eq!(tail_entries.len(), 1);
        assert_entries_match(&tail_entries[0], &full_result.entries[1]);

        let repeat_entries = reader
            .read_new_entries()
            .expect("subsequent IME tail read should succeed")
            .entries;
        assert!(repeat_entries.is_empty());

        fs::remove_dir_all(root).expect("should clean up temp IME fixture");
    }

    #[test]
    fn test_tail_reader_preserves_company_portal_continuations_across_writes() {
        let path = unique_test_path("company-portal-split-logical-record");
        fs::write(&path, "").expect("should create empty Company Portal log");

        let mut reader = TailReader::new(path.clone(), 0, ResolvedParser::company_portal(), 0, 1);
        let first_header = concat!(
            "2024-11-15T16:50:07.2850341Z  INFO  Event  None  0  ",
            "1487dc30-3bb0-46bf-98ee-76771bd9953e  12-0-0  [Sync] started\n"
        );

        let mut file = OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("should reopen temp file");
        write!(file, "{first_header}").expect("should append Company Portal header");
        drop(file);

        let header_batch = reader
            .read_new_entries()
            .expect("header tail read should succeed");
        assert!(
            header_batch.entries.is_empty(),
            "a Company Portal header must remain pending until continuation boundaries are known"
        );

        let mut file = OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("should reopen temp file");
        write!(
            file,
            concat!(
                "System.Net.Http.HttpRequestException: response status 403\n",
                "2024-11-15T16:50:08.2850341Z  INFO  Event  None  1  ",
                "1487dc30-3bb0-46bf-98ee-76771bd9953e  12-0-0  [Sync] finished\n"
            )
        )
        .expect("should append continuation and next Company Portal header");
        drop(file);

        let continuation_batch = reader
            .read_new_entries()
            .expect("continuation tail read should succeed");
        assert_eq!(continuation_batch.parse_errors, 0);
        assert_eq!(continuation_batch.entries.len(), 1);
        assert_eq!(continuation_batch.entries[0].line_number, 1);
        assert_eq!(
            continuation_batch.entries[0].message,
            "[Sync] started\nSystem.Net.Http.HttpRequestException: response status 403"
        );

        fs::remove_file(path).expect("should clean up temp file");
    }

    #[test]
    fn test_tail_reader_amends_initial_company_portal_record_after_late_continuation() {
        let root = hinted_test_root("company-portal-initial-logical-record");
        let path = hinted_test_path(
            &root,
            "Users/Adele/AppData/Local/Packages/Microsoft.CompanyPortal_8wekyb3d8bbwe/LocalState/Log_1.log",
        );
        let parent = path.parent().expect("fixture path should have a parent");
        fs::create_dir_all(parent).expect("should create Company Portal fixture directory");
        let first_header = concat!(
            "2024-11-15T16:50:07.2850341Z  INFO  Event  None  0  ",
            "1487dc30-3bb0-46bf-98ee-76771bd9953e  12-0-0  [Sync] started\n"
        );
        fs::write(&path, first_header).expect("should write initial Company Portal header");

        let path_str = path.to_string_lossy().to_string();
        let (initial_result, selection) =
            parser::parse_file(&path_str).expect("initial fixture should parse");
        assert_eq!(
            selection.parser,
            cmtraceopen_parser::models::log_entry::ParserKind::CompanyPortal
        );
        assert_eq!(initial_result.entries.len(), 1);
        assert_eq!(initial_result.entries[0].id, 0);
        assert_eq!(initial_result.entries[0].line_number, 1);
        assert_eq!(initial_result.entries[0].message, "[Sync] started");

        let initial_record = InitialLogicalRecord::from_parse_result(&initial_result, &selection)
            .expect("initial Company Portal parse should provide a bounded tail seed");
        let mut reader = TailReader::new_with_initial_logical_record(
            path.clone(),
            initial_result.byte_offset,
            selection,
            initial_result.entries.len() as u64,
            initial_result.total_lines + 1,
            initial_record,
        );

        let mut file = OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("should reopen temp file");
        write!(
            file,
            concat!(
                "System.Net.Http.HttpRequestException: response status 403\n",
                "2024-11-15T16:50:08.2850341Z  INFO  Event  None  1  ",
                "1487dc30-3bb0-46bf-98ee-76771bd9953e  12-0-0  [Sync] finished\n"
            )
        )
        .expect("should append continuation and next Company Portal header");
        drop(file);

        let batch = reader.read_new_entries().expect("tail read should succeed");
        assert!(!batch.reset);
        assert_eq!(batch.parse_errors, 0);
        assert!(batch.entries.is_empty());
        let amendment = batch
            .amendments
            .first()
            .expect("late continuation must amend the initial rendered record");
        assert_eq!(amendment.entry_id, 0);
        assert_eq!(amendment.entry_line_number, 1);
        assert_eq!(amendment.continuation_start_line, 2);
        assert_eq!(amendment.continuation_end_line, 2);
        assert_eq!(amendment.message_utf16_start, 14);
        assert_eq!(
            amendment.message_suffix,
            "\nSystem.Net.Http.HttpRequestException: response status 403"
        );

        let flushed = reader.flush_pending_logical_record();
        assert_eq!(flushed.parse_errors, 0);
        assert_eq!(flushed.entries.len(), 1);
        assert_eq!(flushed.entries[0].id, 1);
        assert_eq!(flushed.entries[0].line_number, 3);
        assert_eq!(flushed.entries[0].message, "[Sync] finished");

        fs::remove_dir_all(root).expect("should clean up temp fixture directory");
    }

    #[test]
    fn test_initial_company_portal_continuations_emit_one_amendment_at_next_header() {
        let root = hinted_test_root("company-portal-initial-multi-batch");
        let path = hinted_test_path(
            &root,
            "Users/Adele/AppData/Local/Packages/Microsoft.CompanyPortal_8wekyb3d8bbwe/LocalState/Log_1.log",
        );
        let parent = path.parent().expect("fixture path should have a parent");
        fs::create_dir_all(parent).expect("should create Company Portal fixture directory");
        fs::write(
            &path,
            concat!(
                "2024-11-15T16:50:07.2850341Z  INFO  Event  None  0  ",
                "1487dc30-3bb0-46bf-98ee-76771bd9953e  12-0-0  [Sync] started\n"
            ),
        )
        .expect("should write initial Company Portal header");

        let path_str = path.to_string_lossy().to_string();
        let (initial_result, selection) =
            parser::parse_file(&path_str).expect("initial fixture should parse");
        let initial_record = InitialLogicalRecord::from_parse_result(&initial_result, &selection)
            .expect("initial Company Portal parse should provide a bounded tail seed");
        let mut reader = TailReader::new_with_initial_logical_record(
            path.clone(),
            initial_result.byte_offset,
            selection,
            initial_result.entries.len() as u64,
            initial_result.total_lines + 1,
            initial_record,
        );

        let mut file = OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("should reopen temp file");
        writeln!(file, "first continuation").expect("should append first continuation");
        drop(file);

        let first_batch = reader
            .read_new_entries()
            .expect("first continuation read should succeed");
        assert_eq!(first_batch.parse_errors, 0);
        assert_eq!(first_batch.observed_through_line, Some(2));
        assert!(first_batch.entries.is_empty());
        assert!(
            first_batch.amendments.is_empty(),
            "the initial record should be amended once at a real record boundary"
        );

        let mut file = OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("should reopen temp file");
        write!(
            file,
            concat!(
                "second continuation\n",
                "2024-11-15T16:50:08.2850341Z  INFO  Event  None  1  ",
                "1487dc30-3bb0-46bf-98ee-76771bd9953e  12-0-0  [Sync] finished\n"
            )
        )
        .expect("should append second continuation and next header");
        drop(file);

        let boundary_batch = reader
            .read_new_entries()
            .expect("boundary read should succeed");
        assert_eq!(boundary_batch.parse_errors, 0);
        assert_eq!(boundary_batch.observed_through_line, Some(3));
        assert!(boundary_batch.entries.is_empty());
        let amendment = boundary_batch
            .amendments
            .first()
            .expect("the next header should complete one initial-record amendment");
        assert_eq!(boundary_batch.amendments.len(), 1);
        assert_eq!(amendment.entry_id, 0);
        assert_eq!(amendment.entry_line_number, 1);
        assert_eq!(amendment.continuation_start_line, 2);
        assert_eq!(amendment.continuation_end_line, 3);
        assert_eq!(
            amendment.message_suffix,
            "\nfirst continuation\nsecond continuation"
        );

        let flushed = reader.flush_pending_logical_record();
        assert_eq!(flushed.entries.len(), 1);
        assert_eq!(flushed.entries[0].id, 1);
        assert_eq!(flushed.entries[0].line_number, 4);

        fs::remove_dir_all(root).expect("should clean up temp fixture directory");
    }

    #[test]
    fn test_parser_change_discards_incompatible_initial_company_portal_seed() {
        let root = hinted_test_root("company-portal-initial-parser-change");
        let path = hinted_test_path(
            &root,
            "Users/Adele/AppData/Local/Packages/Microsoft.CompanyPortal_8wekyb3d8bbwe/LocalState/Log_1.log",
        );
        let parent = path.parent().expect("fixture path should have a parent");
        fs::create_dir_all(parent).expect("should create Company Portal fixture directory");
        fs::write(
            &path,
            concat!(
                "2024-11-15T16:50:07.2850341Z  INFO  Event  None  0  ",
                "1487dc30-3bb0-46bf-98ee-76771bd9953e  12-0-0  [Sync] started\n"
            ),
        )
        .expect("should write initial Company Portal header");

        let path_str = path.to_string_lossy().to_string();
        let (initial_result, selection) =
            parser::parse_file(&path_str).expect("initial fixture should parse");
        let initial_record = InitialLogicalRecord::from_parse_result(&initial_result, &selection)
            .expect("initial Company Portal parse should provide a bounded tail seed");
        let mut reader = TailReader::new_with_initial_logical_record(
            path.clone(),
            initial_result.byte_offset,
            selection,
            initial_result.entries.len() as u64,
            initial_result.total_lines + 1,
            initial_record,
        );

        let mut file = OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("should reopen temp file");
        write!(file, "unterminated continuation").expect("should append a partial continuation");
        drop(file);
        assert!(reader
            .read_new_entries()
            .expect("partial continuation read should succeed")
            .amendments
            .is_empty());

        reader.parser_selection = ResolvedParser::plain_text();
        let flushed = reader
            .read_new_entries()
            .expect("parser change should flush pending text");

        assert!(
            flushed.amendments.is_empty(),
            "a parser change must not amend a record owned by the old Company Portal selection"
        );
        assert!(reader.pending_initial_logical_record.is_none());

        fs::remove_dir_all(root).expect("should clean up temp fixture directory");
    }

    #[test]
    fn test_initial_company_portal_tail_does_not_reread_previously_parsed_bytes() {
        let root = hinted_test_root("company-portal-initial-no-reread");
        let path = hinted_test_path(
            &root,
            "Users/Adele/AppData/Local/Packages/Microsoft.CompanyPortal_8wekyb3d8bbwe/LocalState/Log_1.log",
        );
        let parent = path.parent().expect("fixture path should have a parent");
        fs::create_dir_all(parent).expect("should create Company Portal fixture directory");
        let initial = concat!(
            "2024-11-15T16:50:07.2850341Z  INFO  Event  None  0  ",
            "1487dc30-3bb0-46bf-98ee-76771bd9953e  12-0-0  [Sync] started\n"
        );
        fs::write(&path, initial).expect("should write initial Company Portal header");

        let path_str = path.to_string_lossy().to_string();
        let (initial_result, selection) =
            parser::parse_file(&path_str).expect("initial fixture should parse");
        let initial_record = InitialLogicalRecord::from_parse_result(&initial_result, &selection)
            .expect("initial Company Portal parse should provide a bounded tail seed");
        let mut reader = TailReader::new_with_initial_logical_record(
            path.clone(),
            initial_result.byte_offset,
            selection,
            initial_result.entries.len() as u64,
            initial_result.total_lines + 1,
            initial_record,
        );

        let changed_prior_bytes = initial.replace("started", "BROKEN!");
        assert_eq!(changed_prior_bytes.len(), initial.len());
        fs::write(&path, changed_prior_bytes).expect("should mutate only prior bytes in place");
        let mut file = OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("should reopen temp file");
        write!(
            file,
            concat!(
                "continuation from the append-only boundary\n",
                "2024-11-15T16:50:08.2850341Z  INFO  Event  None  1  ",
                "1487dc30-3bb0-46bf-98ee-76771bd9953e  12-0-0  [Sync] finished\n"
            )
        )
        .expect("should append continuation and next header");
        drop(file);

        let batch = reader
            .read_new_entries()
            .expect("tail boundary read should succeed");
        let amendment = batch
            .amendments
            .first()
            .expect("tail boundary should amend the entry parsed during initial open");
        assert_eq!(
            amendment.message_suffix,
            "\ncontinuation from the append-only boundary"
        );

        fs::remove_dir_all(root).expect("should clean up temp fixture directory");
    }

    #[test]
    fn test_initial_company_portal_continuation_overflow_reports_the_cap() {
        let root = hinted_test_root("company-portal-initial-overflow");
        let path = hinted_test_path(
            &root,
            "Users/Adele/AppData/Local/Packages/Microsoft.CompanyPortal_8wekyb3d8bbwe/LocalState/Log_1.log",
        );
        let parent = path.parent().expect("fixture path should have a parent");
        fs::create_dir_all(parent).expect("should create Company Portal fixture directory");
        fs::write(
            &path,
            concat!(
                "2024-11-15T16:50:07.2850341Z  INFO  Event  None  0  ",
                "1487dc30-3bb0-46bf-98ee-76771bd9953e  12-0-0  [Sync] started\n"
            ),
        )
        .expect("should write initial Company Portal header");

        let path_str = path.to_string_lossy().to_string();
        let (initial_result, selection) =
            parser::parse_file(&path_str).expect("initial fixture should parse");
        let initial_record = InitialLogicalRecord::from_parse_result(&initial_result, &selection)
            .expect("initial Company Portal parse should provide a bounded tail seed");
        let mut reader = TailReader::new_with_initial_logical_record(
            path.clone(),
            initial_result.byte_offset,
            selection,
            initial_result.entries.len() as u64,
            initial_result.total_lines + 1,
            initial_record,
        );

        let continuation = "x".repeat(MAX_PENDING_LOGICAL_RECORD_BYTES + 1);
        let mut file = OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("should reopen temp file");
        writeln!(file, "{continuation}").expect("should append oversized continuation");
        drop(file);

        let batch = reader
            .read_new_entries()
            .expect("oversized continuation read should succeed");
        assert_eq!(batch.parse_errors, 1);
        assert_eq!(batch.amendments.len(), 1);
        assert!(
            batch.amendments[0].message_suffix.len() <= MAX_PENDING_LOGICAL_RECORD_BYTES,
            "a single watcher payload must stay inside the logical-record cap"
        );

        let mut file = OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("should reopen temp file");
        writeln!(file, "more content after the cap").expect("should append after cap");
        drop(file);

        let after_cap = reader
            .read_new_entries()
            .expect("post-cap continuation read should succeed");
        assert_eq!(after_cap.parse_errors, 0, "the same cap is reported once");
        assert!(after_cap.amendments.is_empty());

        fs::remove_dir_all(root).expect("should clean up temp fixture directory");
    }

    #[test]
    fn test_initial_company_portal_cap_is_cumulative_across_flushes() {
        let root = hinted_test_root("company-portal-initial-cumulative-cap");
        let path = hinted_test_path(
            &root,
            "Users/Adele/AppData/Local/Packages/Microsoft.CompanyPortal_8wekyb3d8bbwe/LocalState/Log_1.log",
        );
        let parent = path.parent().expect("fixture path should have a parent");
        fs::create_dir_all(parent).expect("should create Company Portal fixture directory");
        fs::write(
            &path,
            concat!(
                "2024-11-15T16:50:07.2850341Z  INFO  Event  None  0  ",
                "1487dc30-3bb0-46bf-98ee-76771bd9953e  12-0-0  [Sync] started\n"
            ),
        )
        .expect("should write initial Company Portal header");

        let path_str = path.to_string_lossy().to_string();
        let (initial_result, selection) =
            parser::parse_file(&path_str).expect("initial fixture should parse");
        let initial_record = InitialLogicalRecord::from_parse_result(&initial_result, &selection)
            .expect("initial Company Portal parse should provide a bounded tail seed");
        let mut reader = TailReader::new_with_initial_logical_record(
            path.clone(),
            initial_result.byte_offset,
            selection,
            initial_result.entries.len() as u64,
            initial_result.total_lines + 1,
            initial_record,
        );

        let first_continuation = "a".repeat(MAX_PENDING_LOGICAL_RECORD_BYTES / 2);
        let mut file = OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("should reopen temp file");
        writeln!(file, "{first_continuation}").expect("should append first continuation");
        drop(file);
        assert!(reader
            .read_new_entries()
            .expect("first continuation read should succeed")
            .amendments
            .is_empty());
        let first_amendment = reader.flush_pending_logical_record();
        assert_eq!(first_amendment.amendments.len(), 1);

        let second_continuation = "b".repeat(MAX_PENDING_LOGICAL_RECORD_BYTES);
        let mut file = OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("should reopen temp file");
        writeln!(file, "{second_continuation}").expect("should append second continuation");
        drop(file);
        let capped = reader
            .read_new_entries()
            .expect("second continuation read should succeed");
        assert_eq!(capped.parse_errors, 1);
        assert_eq!(capped.amendments.len(), 1);
        assert_eq!(
            first_amendment.amendments[0].message_suffix.len()
                + capped.amendments[0].message_suffix.len(),
            MAX_PENDING_LOGICAL_RECORD_BYTES,
            "retained and emitted suffix bytes share one cumulative cap"
        );

        fs::remove_dir_all(root).expect("should clean up temp fixture directory");
    }

    #[test]
    fn test_initial_company_portal_unterminated_overflow_discards_until_newline() {
        let root = hinted_test_root("company-portal-initial-unterminated-cap");
        let path = hinted_test_path(
            &root,
            "Users/Adele/AppData/Local/Packages/Microsoft.CompanyPortal_8wekyb3d8bbwe/LocalState/Log_1.log",
        );
        let parent = path.parent().expect("fixture path should have a parent");
        fs::create_dir_all(parent).expect("should create Company Portal fixture directory");
        fs::write(
            &path,
            concat!(
                "2024-11-15T16:50:07.2850341Z  INFO  Event  None  0  ",
                "1487dc30-3bb0-46bf-98ee-76771bd9953e  12-0-0  [Sync] started\n"
            ),
        )
        .expect("should write initial Company Portal header");

        let path_str = path.to_string_lossy().to_string();
        let (initial_result, selection) =
            parser::parse_file(&path_str).expect("initial fixture should parse");
        let initial_record = InitialLogicalRecord::from_parse_result(&initial_result, &selection)
            .expect("initial Company Portal parse should provide a bounded tail seed");
        let mut reader = TailReader::new_with_initial_logical_record(
            path.clone(),
            initial_result.byte_offset,
            selection,
            initial_result.entries.len() as u64,
            initial_result.total_lines + 1,
            initial_record,
        );

        let mut file = OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("should reopen temp file");
        write!(file, "{}", "x".repeat(MAX_PENDING_LOGICAL_RECORD_BYTES + 1))
            .expect("should append oversized unterminated continuation");
        drop(file);

        let capped = reader
            .read_new_entries()
            .expect("unterminated continuation read should succeed");
        assert_eq!(capped.parse_errors, 1);
        assert_eq!(capped.amendments.len(), 1);
        assert!(capped.amendments[0].message_suffix.len() <= MAX_PENDING_LOGICAL_RECORD_BYTES);

        let mut file = OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("should reopen temp file");
        write!(
            file,
            concat!(
                "discarded tail of the same line\n",
                "2024-11-15T16:50:08.2850341Z  INFO  Event  None  1  ",
                "1487dc30-3bb0-46bf-98ee-76771bd9953e  12-0-0  [Sync] finished\n"
            )
        )
        .expect("should terminate the capped line and append a header");
        drop(file);

        let boundary = reader
            .read_new_entries()
            .expect("post-cap boundary read should succeed");
        assert_eq!(boundary.parse_errors, 0);
        assert!(boundary.amendments.is_empty());
        let flushed = reader.flush_pending_logical_record();
        assert_eq!(flushed.entries.len(), 1);
        assert_eq!(flushed.entries[0].line_number, 3);
        assert_eq!(flushed.entries[0].message, "[Sync] finished");

        fs::remove_dir_all(root).expect("should clean up temp fixture directory");
    }

    #[test]
    fn test_initial_company_portal_flush_emits_one_bounded_amendment_with_absolute_spans() {
        let root = hinted_test_root("company-portal-initial-flush-span");
        let path = hinted_test_path(
            &root,
            "Users/Adele/AppData/Local/Packages/Microsoft.CompanyPortal_8wekyb3d8bbwe/LocalState/Log_1.log",
        );
        let parent = path.parent().expect("fixture path should have a parent");
        fs::create_dir_all(parent).expect("should create Company Portal fixture directory");
        fs::write(
            &path,
            concat!(
                "2024-11-15T16:50:07.2850341Z  INFO  Event  None  0  ",
                "1487dc30-3bb0-46bf-98ee-76771bd9953e  12-0-0  [Sync] started\n"
            ),
        )
        .expect("should write initial Company Portal header");

        let path_str = path.to_string_lossy().to_string();
        let (initial_result, selection) =
            parser::parse_file(&path_str).expect("initial fixture should parse");
        let initial_record = InitialLogicalRecord::from_parse_result(&initial_result, &selection)
            .expect("initial Company Portal parse should provide a bounded tail seed");
        let mut reader = TailReader::new_with_initial_logical_record(
            path.clone(),
            initial_result.byte_offset,
            selection,
            initial_result.entries.len() as u64,
            initial_result.total_lines + 1,
            initial_record,
        );

        let mut file = OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("should reopen temp file");
        writeln!(file, "emoji 🙂 failed with 0x80070005")
            .expect("should append continuation with an error code");
        drop(file);

        let pending = reader
            .read_new_entries()
            .expect("continuation read should succeed");
        assert!(pending.amendments.is_empty());

        let flushed = reader.flush_pending_logical_record();
        assert_eq!(flushed.parse_errors, 0);
        assert_eq!(flushed.amendments.len(), 1);
        let amendment = &flushed.amendments[0];
        assert_eq!(
            amendment.message_suffix,
            "\nemoji 🙂 failed with 0x80070005"
        );
        assert_eq!(amendment.message_utf16_start, 14);
        assert_eq!(amendment.error_code_spans.len(), 1);
        assert_eq!(amendment.error_code_spans[0].start, 36);
        assert_eq!(amendment.error_code_spans[0].end, 46);

        let duplicate_flush = reader.flush_pending_logical_record();
        assert!(duplicate_flush.amendments.is_empty());

        fs::remove_dir_all(root).expect("should clean up temp fixture directory");
    }

    #[test]
    fn test_initial_company_portal_truncation_discards_unpublished_continuation() {
        let root = hinted_test_root("company-portal-initial-reset");
        let path = hinted_test_path(
            &root,
            "Users/Adele/AppData/Local/Packages/Microsoft.CompanyPortal_8wekyb3d8bbwe/LocalState/Log_1.log",
        );
        let parent = path.parent().expect("fixture path should have a parent");
        fs::create_dir_all(parent).expect("should create Company Portal fixture directory");
        fs::write(
            &path,
            concat!(
                "2024-11-15T16:50:07.2850341Z  INFO  Event  None  0  ",
                "1487dc30-3bb0-46bf-98ee-76771bd9953e  12-0-0  [Sync] started\n"
            ),
        )
        .expect("should write initial Company Portal header");

        let path_str = path.to_string_lossy().to_string();
        let (initial_result, selection) =
            parser::parse_file(&path_str).expect("initial fixture should parse");
        let initial_record = InitialLogicalRecord::from_parse_result(&initial_result, &selection)
            .expect("initial Company Portal parse should provide a bounded tail seed");
        let mut reader = TailReader::new_with_initial_logical_record(
            path.clone(),
            initial_result.byte_offset,
            selection,
            initial_result.entries.len() as u64,
            initial_result.total_lines + 1,
            initial_record,
        );

        let mut file = OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("should reopen temp file");
        writeln!(file, "continuation that must be discarded").expect("should append continuation");
        drop(file);
        assert!(reader
            .read_new_entries()
            .expect("continuation read should succeed")
            .amendments
            .is_empty());

        fs::write(&path, "").expect("should truncate the file");
        let reset = reader
            .read_new_entries()
            .expect("reset read should succeed");
        assert!(reset.reset);
        assert!(reset.amendments.is_empty());
        assert!(reader.flush_pending_logical_record().amendments.is_empty());

        fs::remove_dir_all(root).expect("should clean up temp fixture directory");
    }

    #[test]
    fn test_tail_reader_preserves_split_inventory_adaptor_json_record() {
        let path = unique_test_path("inventory-adaptor-split");
        fs::write(&path, "").expect("should create empty adaptor log");

        let selection = ResolvedParser::intune_device_inventory(
            cmtraceopen_parser::intune::device::windows::inventory::DeviceInventoryLogDialect::InventoryAdaptor,
        );
        let mut reader = TailReader::new(path.clone(), 0, selection, 0, 1);

        let mut file = OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("should reopen temp file");
        writeln!(file, "[Thu Jul 30 13:05:02 2026][8604] - Adapter result:")
            .expect("should append adaptor header");
        drop(file);

        let header_batch = reader
            .read_new_entries()
            .expect("header tail read should succeed");
        assert!(
            header_batch.entries.is_empty(),
            "the newest logical header must remain pending until a real boundary"
        );

        let mut file = OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("should reopen temp file");
        writeln!(
            file,
            r#"{{"Status":200,"HResult":"0x00000000","Data":{{"Example":"value"}}}}"#
        )
        .expect("should append adaptor JSON");
        drop(file);

        let continuation_batch = reader
            .read_new_entries()
            .expect("continuation tail read should succeed");
        assert!(
            continuation_batch.entries.is_empty(),
            "a continuation must extend the pending record"
        );

        let flushed = reader.finalize_pending_input();

        assert_eq!(flushed.entries.len(), 1);
        assert_eq!(
            flushed.entries[0].message,
            concat!(
                "Adapter result:\n",
                r#"{"Status":200,"HResult":"0x00000000","Data":{"Example":"value"}}"#
            )
        );
        assert_eq!(flushed.entries[0].thread, Some(8604));

        fs::remove_file(path).expect("should clean up temp file");
    }

    #[test]
    fn test_tail_reader_preserves_split_inventory_rotation_failure_stack() {
        let path = unique_test_path("inventory-rotation-split");
        fs::write(&path, "").expect("should create empty rotation log");

        let selection = ResolvedParser::intune_device_inventory(
            cmtraceopen_parser::intune::device::windows::inventory::DeviceInventoryLogDialect::RotationFailure,
        );
        let mut reader = TailReader::new(path.clone(), 0, selection, 0, 1);

        let mut file = OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("should reopen temp file");
        writeln!(
            file,
            "2026-07-30T13:05:01.1234567-04:00 Failed to rotate Device Inventory log."
        )
        .expect("should append rotation header");
        drop(file);

        let header_batch = reader
            .read_new_entries()
            .expect("header tail read should succeed");
        assert!(header_batch.entries.is_empty());

        let mut file = OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("should reopen temp file");
        write!(
            file,
            "System.IO.IOException: The process cannot access the file.\n   at Synthetic.Inventory.Rotate()\n"
        )
        .expect("should append exception stack");
        drop(file);

        let continuation_batch = reader
            .read_new_entries()
            .expect("continuation tail read should succeed");
        assert!(continuation_batch.entries.is_empty());

        let flushed = reader.finalize_pending_input();

        assert_eq!(flushed.entries.len(), 1);
        assert_eq!(
            flushed.entries[0].message,
            concat!(
                "Failed to rotate Device Inventory log.\n",
                "System.IO.IOException: The process cannot access the file.\n",
                "   at Synthetic.Inventory.Rotate()"
            )
        );
        assert_eq!(
            flushed.entries[0].severity,
            crate::models::log_entry::Severity::Error
        );

        fs::remove_file(path).expect("should clean up temp file");
    }

    #[test]
    fn test_tail_reader_flushes_inventory_record_on_new_header() {
        let path = unique_test_path("inventory-new-header");
        fs::write(&path, "").expect("should create empty adaptor log");

        let selection = ResolvedParser::intune_device_inventory(
            cmtraceopen_parser::intune::device::windows::inventory::DeviceInventoryLogDialect::InventoryAdaptor,
        );
        let mut reader = TailReader::new(path.clone(), 0, selection, 0, 1);

        let mut file = OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("should reopen temp file");
        writeln!(file, "[Thu Jul 30 13:05:02 2026][8604] - First action.")
            .expect("should append first header");
        drop(file);
        assert!(reader
            .read_new_entries()
            .expect("first tail read should succeed")
            .entries
            .is_empty());

        let mut file = OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("should reopen temp file");
        writeln!(file, "[Thu Jul 30 13:05:03 2026][8604] - Second action.")
            .expect("should append second header");
        drop(file);

        let batch = reader
            .read_new_entries()
            .expect("new-header tail read should succeed");
        assert_eq!(batch.entries.len(), 1);
        assert_eq!(batch.entries[0].message, "First action.");
        assert_eq!(batch.parse_errors, 0);

        fs::remove_file(path).expect("should clean up temp file");
    }

    #[test]
    fn test_tail_reader_counts_a_flushed_blank_line_as_a_physical_line() {
        // A blank first line is framed as a record of its own and parses to no
        // entries. It is still a physical line, so the record that follows it
        // sits on line 2. Discarding the empty record would discard the line it
        // accounts for and shift every later line number down by one.
        let path = unique_test_path("inventory-blank-first-line");
        fs::write(&path, "").expect("should create empty harvester log");

        let dialect = cmtraceopen_parser::intune::device::windows::inventory::DeviceInventoryLogDialect::Harvester;
        let selection = ResolvedParser::intune_device_inventory(dialect);
        let mut reader = TailReader::new(path.clone(), 0, selection, 0, 1);

        let mut file = OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("should reopen temp file");
        writeln!(file).expect("should append a blank first line");
        drop(file);

        let blank = reader
            .read_new_entries()
            .expect("blank-line tail read should succeed");
        assert!(blank.entries.is_empty(), "a blank line yields no entry");

        let flushed = reader.finalize_pending_input();
        assert!(flushed.entries.is_empty());

        let mut file = OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("should reopen temp file");
        writeln!(file, "7/30/2026 6:00:54 AM [Information] After the blank.")
            .expect("should append a harvester header");
        drop(file);

        let pending = reader
            .read_new_entries()
            .expect("header tail read should succeed");
        assert!(
            pending.entries.is_empty(),
            "the newest record stays pending until a real boundary"
        );

        let after = reader.finalize_pending_input();
        assert_eq!(after.entries.len(), 1);
        assert_eq!(
            after.entries[0].line_number, 2,
            "the record after a blank first line sits on physical line 2"
        );

        fs::remove_file(path).expect("should clean up temp file");
    }

    #[test]
    fn test_tail_reader_numbers_logical_records_by_physical_span() {
        // A Device Inventory logical record spans its header plus every
        // continuation beneath it. Numbering one line per entry drifts below
        // the real file position as soon as a record is multi-line, so the
        // frontend would point "go to line" at the wrong place for a tailed
        // file while pointing at the right one for the same file opened.
        let path = unique_test_path("inventory-physical-line-span");
        let content = concat!(
            "7/30/2026 6:00:54 AM [Information] First record.\n", // physical line 1
            "first continuation\n",                               // physical line 2
            "7/30/2026 6:00:55 AM [Warning] Second record.\n",    // physical line 3
            "second continuation\n",                              // physical line 4
            "7/30/2026 6:00:56 AM [Error] Third record.\n",       // physical line 5
        );
        fs::write(&path, "").expect("should create empty harvester log");

        let dialect = cmtraceopen_parser::intune::device::windows::inventory::DeviceInventoryLogDialect::Harvester;
        let selection = ResolvedParser::intune_device_inventory(dialect);
        let mut reader = TailReader::new(path.clone(), 0, selection, 0, 1);

        let mut file = OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("should reopen temp file");
        write!(file, "{content}").expect("should append harvester records");
        drop(file);

        let batch = reader.read_new_entries().expect("tail read should succeed");
        assert_eq!(
            batch.entries.len(),
            2,
            "the newest record stays pending until a real boundary"
        );

        let flushed = reader.finalize_pending_input();
        assert_eq!(flushed.entries.len(), 1);

        let tailed_lines: Vec<u32> = batch
            .entries
            .iter()
            .chain(flushed.entries.iter())
            .map(|entry| entry.line_number)
            .collect();
        assert_eq!(
            tailed_lines,
            vec![1, 3, 5],
            "each record must be numbered at its own physical header line"
        );

        // The same reading the file gets when it is opened rather than tailed.
        let (opened, _) = cmtraceopen_parser::intune::device::windows::inventory::parse_content(
            &path.to_string_lossy(),
            content,
            dialect,
        );
        let opened_lines: Vec<u32> = opened.iter().map(|entry| entry.line_number).collect();
        assert_eq!(
            tailed_lines, opened_lines,
            "tailing and opening must agree on line numbers"
        );

        fs::remove_file(path).expect("should clean up temp file");
    }

    #[test]
    fn test_device_inventory_initial_and_tail_parity_at_exact_and_overflow_limits() {
        let cases = [
            (
                DeviceInventoryLogDialect::Harvester,
                "7/30/2026 6:00:54 AM [Error] HARVESTER-START",
                "7/30/2026 6:00:55 AM [Warning] HARVESTER-NEXT",
                "-HARVESTER-TAIL-SENTINEL",
            ),
            (
                DeviceInventoryLogDialect::InventoryAdaptor,
                "[Thu Jul 30 13:05:01 2026][8604] - ADAPTOR-START",
                "[Thu Jul 30 13:05:02 2026][8604] - ADAPTOR-NEXT",
                "-ADAPTOR-TAIL-SENTINEL",
            ),
            (
                DeviceInventoryLogDialect::RotationFailure,
                "2026-07-30T13:05:01.1234567-04:00 Failed to rotate ROTATION-START",
                "2026-07-30T13:05:02.1234567-04:00 ROTATION-NEXT",
                "-ROTATION-TAIL-SENTINEL",
            ),
        ];

        for (dialect, header, next_header, sentinel) in cases {
            for (label, total_bytes) in [
                ("exact", MAX_LOGICAL_RECORD_BYTES),
                ("overflow", MAX_LOGICAL_RECORD_BYTES + 1),
            ] {
                let first_record = inventory_record_with_size(header, total_bytes, sentinel);
                assert_inventory_tail_matches_initial(
                    &format!("inventory-{dialect:?}-{label}"),
                    dialect,
                    &first_record,
                    next_header,
                );
            }
        }
    }

    #[test]
    fn test_device_inventory_initial_and_tail_parity_at_utf8_split_boundary() {
        let header = "[Thu Jul 30 13:05:01 2026][8604] - UTF8-START";
        let fixed_prefix_bytes = header.len() + 1;
        let first_record = format!(
            "{header}\n{}🧪-UTF8-TAIL-SENTINEL",
            "x".repeat(MAX_LOGICAL_RECORD_BYTES - fixed_prefix_bytes - 1)
        );
        assert_eq!(
            first_record[..MAX_LOGICAL_RECORD_BYTES - 1].len(),
            MAX_LOGICAL_RECORD_BYTES - 1
        );

        assert_inventory_tail_matches_initial(
            "inventory-utf8-boundary",
            DeviceInventoryLogDialect::InventoryAdaptor,
            &first_record,
            "[Thu Jul 30 13:05:02 2026][8604] - UTF8-NEXT",
        );
    }

    #[test]
    fn test_tail_reader_attaches_split_harvester_continuation() {
        // The harvester dialect reports LogicalRecord framing because the
        // initial parse attaches a non-header line to the record above it.
        // Tailing must reach the same reading when the continuation lands in a
        // later append instead of emitting a detached record.
        let path = unique_test_path("inventory-harvester-continuation");
        fs::write(&path, "").expect("should create empty harvester log");

        let selection = ResolvedParser::intune_device_inventory(
            cmtraceopen_parser::intune::device::windows::inventory::DeviceInventoryLogDialect::Harvester,
        );
        let mut reader = TailReader::new(path.clone(), 0, selection, 0, 1);

        let mut file = OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("should reopen temp file");
        writeln!(
            file,
            "7/30/2026 6:00:54 AM [Information] First recognized record."
        )
        .expect("should append harvester header");
        drop(file);

        let header_batch = reader
            .read_new_entries()
            .expect("header tail read should succeed");
        assert!(
            header_batch.entries.is_empty(),
            "the newest harvester record must stay pending until a real boundary"
        );

        let mut file = OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("should reopen temp file");
        writeln!(file, "trailing continuation").expect("should append continuation");
        writeln!(file, "7/30/2026 6:00:55 AM [Warning] Second record.")
            .expect("should append the next harvester header");
        drop(file);

        let continuation_batch = reader
            .read_new_entries()
            .expect("continuation tail read should succeed");
        assert_eq!(continuation_batch.entries.len(), 1);
        assert_eq!(
            continuation_batch.entries[0].message,
            "First recognized record.\ntrailing continuation"
        );
        assert_eq!(continuation_batch.entries[0].severity, Severity::Info);

        let flushed = reader.finalize_pending_input();
        assert_eq!(flushed.entries.len(), 1);
        assert_eq!(flushed.entries[0].message, "Second record.");
        assert_eq!(flushed.entries[0].severity, Severity::Warning);

        fs::remove_file(path).expect("should clean up temp file");
    }

    #[test]
    fn test_tail_batch_reports_parse_errors_even_without_entries() {
        // Every emission site in the watcher loop shares this predicate, so a
        // batch that only carries parse errors still reaches the session
        // instead of being dropped until the tail stops.
        assert!(!TailBatch::empty(false).is_reportable());
        assert!(TailBatch::empty(true).is_reportable());

        let parse_errors_only = TailBatch {
            entries: Vec::new(),
            amendments: Vec::new(),
            parse_errors: 1,
            observed_through_line: None,
            reset: false,
        };
        assert!(parse_errors_only.is_reportable());
    }

    #[test]
    fn test_tail_reader_flushes_inventory_record_explicitly() {
        let path = unique_test_path("inventory-explicit-flush");
        fs::write(&path, "").expect("should create empty adaptor log");

        let selection = ResolvedParser::intune_device_inventory(
            cmtraceopen_parser::intune::device::windows::inventory::DeviceInventoryLogDialect::InventoryAdaptor,
        );
        let mut reader = TailReader::new(path.clone(), 0, selection, 0, 1);

        let mut file = OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("should reopen temp file");
        write!(file, "[Thu Jul 30 13:05:02 2026][8604] - Final action.")
            .expect("should append unterminated final header");
        drop(file);
        assert!(reader
            .read_new_entries()
            .expect("tail read should succeed")
            .entries
            .is_empty());

        let flushed = reader.finalize_pending_input();
        assert_eq!(flushed.entries.len(), 1);
        assert_eq!(flushed.entries[0].message, "Final action.");
        assert_eq!(flushed.parse_errors, 0);

        fs::remove_file(path).expect("should clean up temp file");
    }

    #[test]
    fn test_tail_reader_flushes_inventory_record_before_parser_change() {
        let path = unique_test_path("inventory-parser-change");
        fs::write(&path, "").expect("should create empty adaptor log");

        let selection = ResolvedParser::intune_device_inventory(
            cmtraceopen_parser::intune::device::windows::inventory::DeviceInventoryLogDialect::InventoryAdaptor,
        );
        let mut reader = TailReader::new(path.clone(), 0, selection, 0, 1);

        let mut file = OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("should reopen temp file");
        writeln!(
            file,
            "[Thu Jul 30 13:05:02 2026][8604] - Pending before parser change."
        )
        .expect("should append adaptor header");
        drop(file);
        assert!(reader
            .read_new_entries()
            .expect("tail read should succeed")
            .entries
            .is_empty());

        reader.parser_selection = ResolvedParser::plain_text();
        let flushed = reader
            .read_new_entries()
            .expect("parser change should flush pending record");
        assert_eq!(flushed.entries.len(), 1);
        assert_eq!(flushed.entries[0].message, "Pending before parser change.");

        fs::remove_file(path).expect("should clean up temp file");
    }

    #[test]
    fn test_tail_reader_bounds_inventory_overflow_and_counts_parse_error() {
        let path = unique_test_path("inventory-overflow");
        fs::write(&path, "").expect("should create empty adaptor log");

        let selection = ResolvedParser::intune_device_inventory(
            cmtraceopen_parser::intune::device::windows::inventory::DeviceInventoryLogDialect::InventoryAdaptor,
        );
        let mut reader = TailReader::new(path.clone(), 0, selection, 0, 1);
        let continuation = "x".repeat(MAX_LOGICAL_RECORD_BYTES);

        let mut file = OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("should reopen temp file");
        writeln!(
            file,
            "[Thu Jul 30 13:05:02 2026][8604] - Oversized action.\n{continuation}"
        )
        .expect("should append oversized logical record");
        drop(file);

        let overflow = reader
            .read_new_entries()
            .expect("overflow tail read should succeed");
        assert_eq!(overflow.entries.len(), 1);
        assert_eq!(overflow.parse_errors, 1);
        assert!(
            overflow.entries[0].message.len() < MAX_LOGICAL_RECORD_BYTES,
            "emitted overflow record must honor the pending byte bound"
        );

        fs::remove_file(path).expect("should clean up temp file");
    }

    #[test]
    fn test_tail_reader_bounds_unterminated_inventory_continuation() {
        let path = unique_test_path("inventory-unterminated-overflow");
        fs::write(&path, "").expect("should create empty adaptor log");

        let selection = ResolvedParser::intune_device_inventory(
            cmtraceopen_parser::intune::device::windows::inventory::DeviceInventoryLogDialect::InventoryAdaptor,
        );
        let mut reader = TailReader::new(path.clone(), 0, selection, 0, 1);

        let mut file = OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("should reopen temp file");
        writeln!(
            file,
            "[Thu Jul 30 13:05:02 2026][8604] - Oversized partial action."
        )
        .expect("should append adaptor header");
        drop(file);
        assert!(reader
            .read_new_entries()
            .expect("header tail read should succeed")
            .entries
            .is_empty());

        let continuation = "x".repeat(MAX_LOGICAL_RECORD_BYTES);
        let mut file = OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("should reopen temp file");
        write!(file, "{continuation}").expect("should append unterminated continuation");
        drop(file);

        let overflow = reader
            .read_new_entries()
            .expect("unterminated overflow tail read should succeed");
        assert_eq!(overflow.entries.len(), 1);
        assert_eq!(overflow.parse_errors, 1);

        let pending_bytes = reader
            .pending_logical_record
            .as_ref()
            .map_or(0, |record| record.content.len())
            + reader.pending_fragment.len();
        assert!(pending_bytes <= MAX_LOGICAL_RECORD_BYTES);

        fs::remove_file(path).expect("should clean up temp file");
    }

    #[test]
    fn test_tail_reader_signals_reset_and_rewinds_on_truncation() {
        let path = unique_test_path("tail-reader-truncation");
        fs::write(
            &path,
            "15/01/2024 08:00:00 First entry\n15/01/2024 08:00:01 Second entry\n",
        )
        .expect("should write initial file");

        let byte_offset = fs::metadata(&path).expect("metadata should exist").len();
        let selection = ResolvedParser::generic_timestamped(DateOrder::DayFirst);
        let mut reader = TailReader::new(path.clone(), byte_offset, selection, 2, 3);

        // Normal append — should NOT signal a reset.
        let mut file = OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("should reopen temp file");
        writeln!(file, "15/01/2024 08:00:02 Third entry").expect("should append log line");
        drop(file);

        let batch = reader
            .read_new_entries()
            .expect("append tail read should succeed");
        assert!(!batch.reset, "appending must not signal a reset");
        assert_eq!(batch.entries.len(), 1);
        assert_eq!(batch.entries[0].id, 2);
        assert_eq!(batch.entries[0].line_number, 3);

        // Truncate to a smaller size (log rotation) and write fresh content.
        fs::write(&path, "16/01/2024 09:00:00 Rotated entry\n").expect("should truncate file");

        let batch = reader
            .read_new_entries()
            .expect("truncated tail read should succeed");
        assert!(
            batch.reset,
            "truncation must signal a reset so the UI can drop stale entries"
        );
        assert_eq!(batch.entries.len(), 1);
        assert!(batch.entries[0].message.contains("Rotated entry"));
        // Line numbers restart at 1 for the new file generation; ids stay monotonic.
        assert_eq!(batch.entries[0].line_number, 1);
        assert_eq!(batch.entries[0].id, 3);

        fs::remove_file(path).expect("should clean up temp file");
    }
}
