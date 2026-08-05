use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use cmtraceopen_parser::intune::device::windows::inventory::{
    self, DeviceInventoryLogDialect, FramedLogicalRecord, LogicalRecordSegment,
    MAX_LOGICAL_RECORD_BYTES,
};
use notify::{Config, EventKind, RecommendedWatcher, RecursiveMode, Watcher};

use crate::models::log_entry::{LogEntry, ParserSpecialization, RecordFraming};
use crate::parser::{self, FileEncoding, ResolvedParser};

const IME_RECORD_START: &str = "<![LOG[";
const IME_RECORD_ATTRS_START: &str = "]LOG]!><";

/// The result of reading new content from a tailed file.
pub struct TailBatch {
    /// Complete log records parsed since the last read.
    pub entries: Vec<LogEntry>,
    /// Parse errors observed while producing this incremental batch.
    pub parse_errors: u32,
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
            parse_errors: 0,
            reset,
        }
    }

    fn append(&mut self, other: Self) {
        self.entries.extend(other.entries);
        self.parse_errors = self.parse_errors.saturating_add(other.parse_errors);
        self.reset |= other.reset;
    }

    /// Whether the batch carries something a consumer must see.
    ///
    /// Parse errors count on their own: a batch that only reports malformed
    /// incremental input or a framing overflow still has to reach the session,
    /// otherwise those failures stay invisible until the tail stops.
    fn is_reportable(&self) -> bool {
        self.reset || !self.entries.is_empty() || self.parse_errors > 0
    }
}

struct PendingLogicalRecord {
    content: String,
    parser_selection: ResolvedParser,
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
    /// Selection that owns an unterminated Device Inventory line prefix.
    pending_fragment_selection: Option<ResolvedParser>,
    /// True after a bounded prefix of the current physical line was framed.
    inventory_line_continuation: bool,
    /// Newest Device Inventory logical record held for continuation lines.
    pending_logical_record: Option<PendingLogicalRecord>,
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
        // Detect encoding from the file's BOM
        let encoding = std::fs::read(&path)
            .map(|bytes| crate::parser::detect_encoding(&bytes))
            .unwrap_or(FileEncoding::Utf8);

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
            let finalized = self.finalize_pending_input();
            batch.parse_errors = finalized.parse_errors;
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
        let full_text = if self.pending_fragment.is_empty() {
            new_text
        } else {
            let combined = format!("{}{}", self.pending_fragment, new_text);
            self.pending_fragment.clear();
            self.pending_fragment_selection = None;
            combined
        };

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

        if lines.is_empty() {
            self.byte_offset = file_size;
            return Ok(batch);
        }

        // Parse the new complete records through the same dispatch path as initial parsing.
        let path_str = self.path.to_string_lossy().to_string();
        let (mut entries, parse_errors) =
            parser::parse_lines_with_selection(&lines, &path_str, &self.parser_selection);

        self.assign_entry_identity(&mut entries);
        batch.append(TailBatch {
            entries,
            parse_errors,
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
                .is_some_and(|selection| selection != &self.parser_selection)
            || self
                .pending_utf8_selection
                .as_ref()
                .is_some_and(|selection| selection != &self.parser_selection)
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
                self.pending_fragment_selection = Some(selection.clone());
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
                self.pending_fragment_selection = Some(selection.clone());
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
            self.pending_fragment_selection = Some(selection.clone());
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
            .or(fragment_selection);
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
    /// An incomplete UTF-8 suffix is not decoded lossily: once no later bytes can
    /// complete it, consuming it contributes exactly one surfaced parse error.
    fn finalize_pending_input(&mut self) -> TailBatch {
        let mut batch = self.flush_pending_text();
        let incomplete_utf8 = !std::mem::take(&mut self.pending_utf8_bytes).is_empty();
        self.pending_utf8_selection = None;
        if incomplete_utf8 {
            batch.parse_errors = batch.parse_errors.saturating_add(1);
        }
        batch
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
            parse_errors: framing_parse_errors.saturating_add(projection_errors),
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

    fn assign_entry_identity(&mut self, entries: &mut [LogEntry]) {
        for entry in entries {
            entry.id = self.next_id;
            entry.line_number = self.next_line;
            self.next_id += 1;
            self.next_line += 1;
        }
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
        let mut tail_reader =
            TailReader::new(path, byte_offset, parser_selection, next_id, next_line);

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
        let poll_interval = Duration::from_millis(500);

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
        let (path, mut reader) =
            reader_with_terminal_utf8_prefix("terminal-truncation", &[0xF0, 0x9F, 0xA7]);
        fs::write(&path, []).expect("should truncate terminal UTF-8 fixture");

        let finalized = reader
            .read_new_entries()
            .expect("truncation should finalize old decoder state");
        assert!(finalized.reset);
        assert_eq!(finalized.parse_errors, 1);
        assert!(finalized.entries.is_empty());
        assert!(reader.pending_utf8_bytes.is_empty());
        assert!(reader.pending_fragment.is_empty());
        assert!(reader.pending_logical_record.is_none());

        fs::remove_file(path).expect("should clean up truncation fixture");
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
            parse_errors: 1,
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
