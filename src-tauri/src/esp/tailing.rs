//! ESP-owned bounded multi-file tailing.
//!
//! The ESP diagnostics session owns this state directly. It does not reuse the
//! Log Explorer tail-session map, accepts only discovered sources, keeps at
//! most sixteen active current/process logs, and never reads more than the
//! final eight MiB for an attachment or a single poll.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, Metadata, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use crate::esp::discovery::{
    metadata_is_reparse_point, DiscoveredLogSource, DiscoveryPathFailureKind,
    DiscoverySourceOrigin, MAX_ACTIVE_TAILS, MAX_INITIAL_READ_BYTES,
};
use crate::models::log_entry::{LogEntry, ParserSpecialization, RecordFraming};
use crate::parser::{self, ResolvedParser};

const IME_RECORD_START: &str = "<![LOG[";
const IME_RECORD_ATTRS_START: &str = "]LOG]!><";

pub const WINDOWS_SHARED_READ_WRITE_DELETE: u32 = 0x1 | 0x2 | 0x4;
pub const MAX_SESSION_TAIL_SOURCES: usize = 512;
pub const MAX_DORMANT_TAIL_CURSORS: usize = MAX_ACTIVE_TAILS;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EspTailResetReason {
    Truncated,
    Rotated,
    Reattached,
}

#[derive(Debug, Clone)]
pub struct EspTailAttachment {
    pub source: DiscoveredLogSource,
    pub start_offset: u64,
    pub end_offset: u64,
    pub entries: Vec<LogEntry>,
    pub reset_reason: Option<EspTailResetReason>,
}

#[derive(Debug, Clone)]
pub struct EspTailUpdate {
    pub path: PathBuf,
    pub source_id: String,
    pub family: String,
    pub entries: Vec<LogEntry>,
    pub reset_reason: Option<EspTailResetReason>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EspTailFailure {
    pub path: PathBuf,
    pub kind: DiscoveryPathFailureKind,
    pub detail: String,
}

#[derive(Debug, Default)]
pub struct EspTailReconcileResult {
    pub attachments: Vec<EspTailAttachment>,
    pub failures: Vec<EspTailFailure>,
    pub evicted_sources: Vec<DiscoveredLogSource>,
    pub source_limit_reached: bool,
}

#[derive(Debug, Default)]
pub struct EspTailPollResult {
    pub updates: Vec<EspTailUpdate>,
    pub failures: Vec<EspTailFailure>,
}

#[derive(Debug, Default)]
pub struct EspTailSet {
    tails: BTreeMap<String, ActiveTail>,
    selected_tail_keys: BTreeSet<String>,
    attached_sources: BTreeMap<String, AttachedSourceState>,
    stopped: bool,
}

#[derive(Debug, Clone)]
struct AttachedSourceState {
    source: DiscoveredLogSource,
    next_id: u64,
}

impl EspTailSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn reconcile(&mut self, sources: &[DiscoveredLogSource]) -> EspTailReconcileResult {
        if self.stopped {
            return EspTailReconcileResult::default();
        }

        let selected_tails = select_tail_sources(sources);
        let selected_keys = selected_tails
            .iter()
            .map(|source| path_identity(&source.path))
            .collect::<BTreeSet<_>>();
        self.selected_tail_keys = selected_keys.clone();

        let mut result = EspTailReconcileResult::default();
        let attachment_sources = select_attachment_sources(sources, &selected_keys);
        result.source_limit_reached = attachment_sources.len() > MAX_SESSION_TAIL_SOURCES;
        for source in attachment_sources
            .into_iter()
            .take(MAX_SESSION_TAIL_SOURCES)
        {
            let key = path_identity(&source.path);
            if selected_keys.contains(&key) {
                if let Some(existing) = self.tails.get_mut(&key) {
                    existing.source = source.clone();
                    if let Some(attached) = self.attached_sources.get_mut(&key) {
                        attached.source = source;
                        attached.next_id = attached.next_id.max(existing.next_id);
                    }
                    continue;
                }

                if let Some(attached) = self.attached_sources.get(&key) {
                    let next_id = attached.next_id;
                    match ActiveTail::reattach(source.clone(), next_id) {
                        Ok((tail, attachment)) => {
                            let next_id = tail.next_id;
                            self.tails.insert(key.clone(), tail);
                            if let Some(attached) = self.attached_sources.get_mut(&key) {
                                attached.source = source;
                                attached.next_id = next_id;
                            }
                            result.attachments.push(attachment);
                        }
                        Err(failure) => result.failures.push(failure),
                    }
                    continue;
                }

                let eviction_key = if self.attached_sources.len() >= MAX_SESSION_TAIL_SOURCES {
                    result.source_limit_reached = true;
                    let Some(eviction_key) = self.attachment_eviction_candidate(&selected_keys)
                    else {
                        continue;
                    };
                    Some(eviction_key)
                } else {
                    None
                };
                match ActiveTail::attach(source.clone()) {
                    Ok((tail, attachment)) => {
                        if let Some(eviction_key) = eviction_key {
                            if let Some(evicted) = self.attached_sources.remove(&eviction_key) {
                                self.tails.remove(&eviction_key);
                                result.evicted_sources.push(evicted.source);
                            }
                        }
                        let next_id = tail.next_id;
                        self.tails.insert(key, tail);
                        self.attached_sources.insert(
                            path_identity(&source.path),
                            AttachedSourceState { source, next_id },
                        );
                        result.attachments.push(attachment);
                    }
                    Err(failure) => result.failures.push(failure),
                }
                continue;
            }

            if let Some(attached) = self.attached_sources.get_mut(&key) {
                attached.source = source;
                continue;
            }
            if self.attached_sources.len() >= MAX_SESSION_TAIL_SOURCES {
                result.source_limit_reached = true;
                continue;
            }
            match read_initial(&source.path) {
                Ok(initial) => {
                    let next_id = next_entry_id(&initial.entries);
                    let attachment = attachment_from_initial(source.clone(), &initial, None);
                    self.attached_sources
                        .insert(key, AttachedSourceState { source, next_id });
                    result.attachments.push(attachment);
                }
                Err(failure) => result.failures.push(failure),
            }
        }
        self.trim_dormant_tail_cursors(&mut result);
        result
    }

    pub fn poll(&mut self) -> EspTailPollResult {
        if self.stopped {
            return EspTailPollResult::default();
        }
        let mut result = EspTailPollResult::default();
        let selected_keys = self.selected_tail_keys.iter().cloned().collect::<Vec<_>>();
        for key in selected_keys {
            let Some(tail) = self.tails.get_mut(&key) else {
                continue;
            };
            let outcome = tail.poll();
            let next_id = tail.next_id;
            if let Some(attached) = self.attached_sources.get_mut(&key) {
                attached.next_id = attached.next_id.max(next_id);
            }
            match outcome {
                Ok(Some(update)) => result.updates.push(update),
                Ok(None) => {}
                Err(failure) => result.failures.push(failure),
            }
        }
        result
    }

    pub fn stop(&mut self) {
        self.stopped = true;
        self.tails.clear();
        self.selected_tail_keys.clear();
        self.attached_sources.clear();
    }

    pub fn is_stopped(&self) -> bool {
        self.stopped
    }

    pub fn active_tail_count(&self) -> usize {
        self.selected_tail_keys
            .iter()
            .filter(|key| self.tails.contains_key(*key))
            .count()
    }

    pub fn active_paths(&self) -> Vec<PathBuf> {
        self.selected_tail_keys
            .iter()
            .filter_map(|key| self.tails.get(key))
            .map(|tail| tail.source.path.clone())
            .collect()
    }

    pub fn retained_tail_cursor_count(&self) -> usize {
        self.tails.len()
    }

    fn attachment_eviction_candidate(&self, selected_keys: &BTreeSet<String>) -> Option<String> {
        self.attached_sources
            .iter()
            .filter(|(key, _)| !selected_keys.contains(*key))
            .max_by(|(left_key, left), (right_key, right)| {
                source_cmp(&left.source, &right.source).then_with(|| left_key.cmp(right_key))
            })
            .map(|(key, _)| key.clone())
    }

    fn trim_dormant_tail_cursors(&mut self, result: &mut EspTailReconcileResult) {
        let mut dormant = self
            .tails
            .keys()
            .filter(|key| !self.selected_tail_keys.contains(*key))
            .cloned()
            .collect::<Vec<_>>();
        dormant.sort_by(|left_key, right_key| {
            match (
                self.attached_sources.get(left_key),
                self.attached_sources.get(right_key),
            ) {
                (Some(left), Some(right)) => {
                    source_cmp(&left.source, &right.source).then_with(|| left_key.cmp(right_key))
                }
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => left_key.cmp(right_key),
            }
        });

        while dormant.len() > MAX_DORMANT_TAIL_CURSORS {
            let Some(key) = dormant.pop() else {
                break;
            };
            if let Some(tail) = self.tails.remove(&key) {
                result.failures.push(EspTailFailure {
                    path: tail.source.path.clone(),
                    kind: DiscoveryPathFailureKind::ResourceLimit,
                    detail: format!(
                        "dormant tail cursor exceeded the bounded {MAX_DORMANT_TAIL_CURSORS}-cursor cache; reattachment retains only the final {MAX_INITIAL_READ_BYTES} bytes, so older bytes written while dormant may be omitted"
                    ),
                });
                if let Some(attached) = self.attached_sources.get_mut(&key) {
                    attached.next_id = attached.next_id.max(tail.next_id);
                }
            }
        }
    }
}

fn select_tail_sources(sources: &[DiscoveredLogSource]) -> Vec<DiscoveredLogSource> {
    let mut candidates = sources
        .iter()
        .filter(|source| {
            matches!(source.origin, DiscoverySourceOrigin::ActiveProcess)
                || (source.is_current
                    && matches!(
                        source.origin,
                        DiscoverySourceOrigin::EmbeddedKnown | DiscoverySourceOrigin::CuratedKnown
                    ))
        })
        .cloned()
        .collect::<Vec<_>>();
    candidates.sort_by(source_cmp);

    let mut seen = BTreeSet::new();
    candidates
        .into_iter()
        .filter(|source| seen.insert(path_identity(&source.path)))
        .take(MAX_ACTIVE_TAILS)
        .collect()
}

fn select_attachment_sources(
    sources: &[DiscoveredLogSource],
    selected_keys: &BTreeSet<String>,
) -> Vec<DiscoveredLogSource> {
    let mut candidates = sources.to_vec();
    candidates.sort_by(|left, right| {
        let left_selected = selected_keys.contains(&path_identity(&left.path));
        let right_selected = selected_keys.contains(&path_identity(&right.path));
        right_selected
            .cmp(&left_selected)
            .then_with(|| source_cmp(left, right))
    });
    let mut seen = BTreeSet::new();
    candidates
        .into_iter()
        .filter(|source| seen.insert(path_identity(&source.path)))
        .collect()
}

fn source_cmp(left: &DiscoveredLogSource, right: &DiscoveredLogSource) -> std::cmp::Ordering {
    left.priority
        .cmp(&right.priority)
        .then_with(|| right.modified.cmp(&left.modified))
        .then_with(|| path_identity(&left.path).cmp(&path_identity(&right.path)))
}

#[derive(Debug)]
struct ActiveTail {
    source: DiscoveredLogSource,
    byte_offset: u64,
    identity: Option<FileIdentity>,
    encoding: TailEncoding,
    pending_bytes: Vec<u8>,
    pending_text: String,
    parser_selection: ResolvedParser,
    next_id: u64,
    next_line: u32,
}

impl ActiveTail {
    fn attach(source: DiscoveredLogSource) -> Result<(Self, EspTailAttachment), EspTailFailure> {
        let initial = read_initial(&source.path)?;
        let attachment = attachment_from_initial(source.clone(), &initial, None);
        let next_id = next_entry_id(&initial.entries);
        let next_line = initial
            .entries
            .iter()
            .map(|entry| entry.line_number)
            .max()
            .map_or(1, |line| line.saturating_add(1));
        Ok((
            Self {
                source,
                byte_offset: initial.end_offset,
                identity: initial.identity,
                encoding: initial.encoding,
                pending_bytes: initial.pending_bytes,
                pending_text: initial.pending_text,
                parser_selection: initial.parser_selection,
                next_id,
                next_line,
            },
            attachment,
        ))
    }

    fn reattach(
        source: DiscoveredLogSource,
        previous_next_id: u64,
    ) -> Result<(Self, EspTailAttachment), EspTailFailure> {
        let initial = read_initial(&source.path)?;
        let mut entries = initial.entries.clone();
        let mut next_id = previous_next_id;
        let mut next_line = 1;
        assign_entry_identity(&mut entries, &mut next_id, &mut next_line);
        let attachment = EspTailAttachment {
            source: source.clone(),
            start_offset: initial.start_offset,
            end_offset: initial.end_offset,
            entries,
            reset_reason: Some(EspTailResetReason::Reattached),
        };
        Ok((
            Self {
                source,
                byte_offset: initial.end_offset,
                identity: initial.identity,
                encoding: initial.encoding,
                pending_bytes: initial.pending_bytes,
                pending_text: initial.pending_text,
                parser_selection: initial.parser_selection,
                next_id,
                next_line,
            },
            attachment,
        ))
    }

    fn poll(&mut self) -> Result<Option<EspTailUpdate>, EspTailFailure> {
        let mut file = open_tail_file(&self.source.path)?;
        let metadata = file
            .metadata()
            .map_err(|error| tail_failure(&self.source.path, "metadata", error))?;
        let current_identity = file_identity(&file, &metadata);
        if identities_differ(self.identity, current_identity) {
            return self.reset(EspTailResetReason::Rotated);
        }
        if metadata.len() < self.byte_offset {
            return self.reset(EspTailResetReason::Truncated);
        }
        if metadata.len() == self.byte_offset {
            return Ok(None);
        }

        file.seek(SeekFrom::Start(self.byte_offset))
            .map_err(|error| tail_failure(&self.source.path, "seek", error))?;
        let read_len = (metadata.len() - self.byte_offset).min(MAX_INITIAL_READ_BYTES);
        let mut bytes = vec![0; read_len as usize];
        file.read_exact(&mut bytes)
            .map_err(|error| tail_failure(&self.source.path, "read", error))?;
        self.byte_offset = self.byte_offset.saturating_add(read_len);
        self.identity = current_identity;

        let decoded = decode_incremental(&mut self.encoding, &mut self.pending_bytes, bytes);
        let mut text = std::mem::take(&mut self.pending_text);
        text.push_str(&decoded);
        let (complete, pending) = split_complete_text(&text, &self.parser_selection);
        if pending.len() > MAX_INITIAL_READ_BYTES as usize {
            self.pending_text.clear();
            self.pending_bytes.clear();
            return Err(EspTailFailure {
                path: self.source.path.clone(),
                kind: DiscoveryPathFailureKind::ResourceLimit,
                detail: format!(
                    "pending record exceeded the {MAX_INITIAL_READ_BYTES}-byte tail limit"
                ),
            });
        }
        self.pending_text = pending;
        if complete.is_empty() {
            return Ok(None);
        }

        let parsed = parser::parse_content_with_selection(
            &complete,
            &self.source.path.to_string_lossy(),
            &self.parser_selection,
        );
        let mut entries = parsed.entries;
        assign_entry_identity(&mut entries, &mut self.next_id, &mut self.next_line);
        if entries.is_empty() {
            return Ok(None);
        }
        Ok(Some(EspTailUpdate {
            path: self.source.path.clone(),
            source_id: self.source.source_id.clone(),
            family: self.source.family.clone(),
            entries,
            reset_reason: None,
        }))
    }

    fn reset(
        &mut self,
        reason: EspTailResetReason,
    ) -> Result<Option<EspTailUpdate>, EspTailFailure> {
        let initial = read_initial(&self.source.path)?;
        self.byte_offset = initial.end_offset;
        self.identity = initial.identity;
        self.encoding = initial.encoding;
        self.pending_bytes = initial.pending_bytes;
        self.pending_text = initial.pending_text;
        self.parser_selection = initial.parser_selection;
        self.next_line = 1;
        let mut entries = initial.entries;
        assign_entry_identity(&mut entries, &mut self.next_id, &mut self.next_line);
        Ok(Some(EspTailUpdate {
            path: self.source.path.clone(),
            source_id: self.source.source_id.clone(),
            family: self.source.family.clone(),
            entries,
            reset_reason: Some(reason),
        }))
    }
}

fn attachment_from_initial(
    source: DiscoveredLogSource,
    initial: &InitialTailState,
    reset_reason: Option<EspTailResetReason>,
) -> EspTailAttachment {
    EspTailAttachment {
        source,
        start_offset: initial.start_offset,
        end_offset: initial.end_offset,
        entries: initial.entries.clone(),
        reset_reason,
    }
}

fn next_entry_id(entries: &[LogEntry]) -> u64 {
    entries
        .iter()
        .map(|entry| entry.id)
        .max()
        .map_or(0, |id| id.saturating_add(1))
}

fn assign_entry_identity(entries: &mut [LogEntry], next_id: &mut u64, next_line: &mut u32) {
    for entry in entries {
        entry.id = *next_id;
        entry.line_number = *next_line;
        *next_id = next_id.saturating_add(1);
        *next_line = next_line.saturating_add(1);
    }
}

#[derive(Debug)]
struct InitialTailState {
    start_offset: u64,
    end_offset: u64,
    identity: Option<FileIdentity>,
    encoding: TailEncoding,
    pending_bytes: Vec<u8>,
    pending_text: String,
    parser_selection: ResolvedParser,
    entries: Vec<LogEntry>,
}

fn read_initial(path: &Path) -> Result<InitialTailState, EspTailFailure> {
    let mut file = open_tail_file(path)?;
    let metadata = file
        .metadata()
        .map_err(|error| tail_failure(path, "metadata", error))?;
    let end_offset = metadata.len();
    let identity = file_identity(&file, &metadata);
    let mut head = [0u8; 3];
    let head_len = file
        .read(&mut head)
        .map_err(|error| tail_failure(path, "read encoding prefix", error))?;
    let hint = encoding_hint(&head[..head_len]);

    let mut start_offset = end_offset.saturating_sub(MAX_INITIAL_READ_BYTES);
    if start_offset > 0 && hint.is_utf16() && start_offset % 2 != 0 {
        start_offset = start_offset.saturating_add(1);
    }
    file.seek(SeekFrom::Start(start_offset))
        .map_err(|error| tail_failure(path, "seek initial context", error))?;
    let mut bytes = vec![0; (end_offset - start_offset) as usize];
    file.read_exact(&mut bytes)
        .map_err(|error| tail_failure(path, "read initial context", error))?;

    if start_offset > 0 {
        let dropped = drop_leading_partial_record(&bytes, hint);
        bytes.drain(..dropped);
        start_offset = start_offset.saturating_add(dropped as u64);
    }
    let (encoding, decoded, pending_bytes) = decode_initial(hint, bytes);
    let path_text = path.to_string_lossy();
    let parser_selection = parser::detect::detect_parser(&path_text, &decoded);
    let (complete, pending_text) = split_complete_text(&decoded, &parser_selection);
    let entries = if complete.is_empty() {
        Vec::new()
    } else {
        parser::parse_content_with_selection(&complete, &path_text, &parser_selection).entries
    };

    Ok(InitialTailState {
        start_offset,
        end_offset,
        identity,
        encoding,
        pending_bytes,
        pending_text,
        parser_selection,
        entries,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EncodingHint {
    Utf8OrWindows1252,
    Utf16Le,
    Utf16Be,
}

impl EncodingHint {
    fn is_utf16(self) -> bool {
        matches!(self, Self::Utf16Le | Self::Utf16Be)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TailEncoding {
    Utf8,
    Windows1252,
    Utf16Le,
    Utf16Be,
}

fn encoding_hint(head: &[u8]) -> EncodingHint {
    if head.starts_with(&[0xff, 0xfe]) {
        EncodingHint::Utf16Le
    } else if head.starts_with(&[0xfe, 0xff]) {
        EncodingHint::Utf16Be
    } else {
        EncodingHint::Utf8OrWindows1252
    }
}

fn drop_leading_partial_record(bytes: &[u8], hint: EncodingHint) -> usize {
    match hint {
        EncodingHint::Utf8OrWindows1252 => bytes
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(bytes.len(), |index| index + 1),
        EncodingHint::Utf16Le => bytes
            .chunks_exact(2)
            .position(|pair| pair == [b'\n', 0])
            .map_or(bytes.len(), |index| (index + 1) * 2),
        EncodingHint::Utf16Be => bytes
            .chunks_exact(2)
            .position(|pair| pair == [0, b'\n'])
            .map_or(bytes.len(), |index| (index + 1) * 2),
    }
}

fn decode_initial(hint: EncodingHint, mut bytes: Vec<u8>) -> (TailEncoding, String, Vec<u8>) {
    match hint {
        EncodingHint::Utf16Le | EncodingHint::Utf16Be => {
            if bytes.starts_with(&[0xff, 0xfe]) || bytes.starts_with(&[0xfe, 0xff]) {
                bytes.drain(..2);
            }
            let pending = if bytes.len() % 2 == 1 {
                bytes.pop().into_iter().collect()
            } else {
                Vec::new()
            };
            let (text, _, _) = match hint {
                EncodingHint::Utf16Le => encoding_rs::UTF_16LE.decode(&bytes),
                EncodingHint::Utf16Be => encoding_rs::UTF_16BE.decode(&bytes),
                EncodingHint::Utf8OrWindows1252 => unreachable!(),
            };
            let encoding = match hint {
                EncodingHint::Utf16Le => TailEncoding::Utf16Le,
                EncodingHint::Utf16Be => TailEncoding::Utf16Be,
                EncodingHint::Utf8OrWindows1252 => unreachable!(),
            };
            (encoding, text.into_owned(), pending)
        }
        EncodingHint::Utf8OrWindows1252 => match std::str::from_utf8(&bytes) {
            Ok(text) => (TailEncoding::Utf8, text.to_string(), Vec::new()),
            Err(error) if error.error_len().is_none() => {
                let valid = error.valid_up_to();
                let text = String::from_utf8_lossy(&bytes[..valid]).into_owned();
                (TailEncoding::Utf8, text, bytes[valid..].to_vec())
            }
            Err(_) => {
                let (text, _, _) = encoding_rs::WINDOWS_1252.decode(&bytes);
                (TailEncoding::Windows1252, text.into_owned(), Vec::new())
            }
        },
    }
}

fn decode_incremental(
    encoding: &mut TailEncoding,
    pending: &mut Vec<u8>,
    bytes: Vec<u8>,
) -> String {
    let mut combined = std::mem::take(pending);
    combined.extend(bytes);
    match encoding {
        TailEncoding::Utf8 => match std::str::from_utf8(&combined) {
            Ok(text) => text.to_string(),
            Err(error) if error.error_len().is_none() => {
                let valid = error.valid_up_to();
                pending.extend_from_slice(&combined[valid..]);
                String::from_utf8_lossy(&combined[..valid]).into_owned()
            }
            Err(_) => {
                *encoding = TailEncoding::Windows1252;
                let (text, _, _) = encoding_rs::WINDOWS_1252.decode(&combined);
                text.into_owned()
            }
        },
        TailEncoding::Windows1252 => {
            let (text, _, _) = encoding_rs::WINDOWS_1252.decode(&combined);
            text.into_owned()
        }
        TailEncoding::Utf16Le | TailEncoding::Utf16Be => {
            if combined.len() % 2 == 1 {
                if let Some(last) = combined.pop() {
                    pending.push(last);
                }
            }
            let (text, _, _) = match encoding {
                TailEncoding::Utf16Le => encoding_rs::UTF_16LE.decode(&combined),
                TailEncoding::Utf16Be => encoding_rs::UTF_16BE.decode(&combined),
                TailEncoding::Utf8 | TailEncoding::Windows1252 => unreachable!(),
            };
            text.into_owned()
        }
    }
}

fn split_complete_text(text: &str, selection: &ResolvedParser) -> (String, String) {
    let cutoff = if matches!(selection.record_framing, RecordFraming::LogicalRecord)
        && matches!(selection.specialization, Some(ParserSpecialization::Ime))
    {
        find_complete_ime_cutoff(text)
    } else {
        text.rfind('\n').map_or(0, |index| index + 1)
    };
    (text[..cutoff].to_string(), text[cutoff..].to_string())
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
        0
    } else if text.ends_with('\n') {
        text.len()
    } else {
        text.rfind('\n').map_or(0, |index| index + 1)
    }
}

fn open_shared_read(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;

        options
            .share_mode(WINDOWS_SHARED_READ_WRITE_DELETE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0);
    }
    options.open(path)
}

fn open_tail_file(path: &Path) -> Result<File, EspTailFailure> {
    let file = open_shared_read(path).map_err(|error| tail_failure(path, "open", error))?;
    let metadata = file
        .metadata()
        .map_err(|error| tail_failure(path, "inspect opened tail", error))?;
    if metadata_is_reparse_point(&metadata) {
        return Err(EspTailFailure {
            path: path.to_path_buf(),
            kind: DiscoveryPathFailureKind::ReparseRejected,
            detail: "tail path is a symlink or reparse point".to_string(),
        });
    }
    if !metadata.is_file() {
        return Err(EspTailFailure {
            path: path.to_path_buf(),
            kind: DiscoveryPathFailureKind::NotRegularFile,
            detail: "tail path is not a regular file".to_string(),
        });
    }
    Ok(file)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    volume: u64,
    index: u64,
}

#[cfg(unix)]
fn file_identity(_file: &File, metadata: &Metadata) -> Option<FileIdentity> {
    use std::os::unix::fs::MetadataExt;
    Some(FileIdentity {
        volume: metadata.dev(),
        index: metadata.ino(),
    })
}

#[cfg(target_os = "windows")]
fn file_identity(file: &File, _metadata: &Metadata) -> Option<FileIdentity> {
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };

    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the handle is borrowed from the live `File`, and the output
    // points to a valid initialized structure for the duration of the call.
    unsafe {
        GetFileInformationByHandle(HANDLE(file.as_raw_handle()), &mut information).ok()?;
    }
    Some(FileIdentity {
        volume: information.dwVolumeSerialNumber as u64,
        index: ((information.nFileIndexHigh as u64) << 32) | information.nFileIndexLow as u64,
    })
}

#[cfg(not(any(unix, target_os = "windows")))]
fn file_identity(_file: &File, _metadata: &Metadata) -> Option<FileIdentity> {
    None
}

fn identities_differ(previous: Option<FileIdentity>, current: Option<FileIdentity>) -> bool {
    matches!((previous, current), (Some(left), Some(right)) if left != right)
}

fn tail_failure(path: &Path, operation: &str, error: std::io::Error) -> EspTailFailure {
    #[cfg(unix)]
    let no_follow_reparse = error.raw_os_error() == Some(libc::ELOOP);
    #[cfg(not(unix))]
    let no_follow_reparse = false;
    let kind = if no_follow_reparse {
        DiscoveryPathFailureKind::ReparseRejected
    } else {
        match error.kind() {
            std::io::ErrorKind::NotFound => DiscoveryPathFailureKind::Missing,
            std::io::ErrorKind::PermissionDenied => DiscoveryPathFailureKind::PermissionDenied,
            _ => DiscoveryPathFailureKind::Failed,
        }
    };
    EspTailFailure {
        path: path.to_path_buf(),
        kind,
        detail: format!("{operation} failed: {error}"),
    }
}

fn path_identity(path: &Path) -> String {
    let value = path.to_string_lossy().replace('\\', "/");
    if cfg!(target_os = "windows") {
        value.to_ascii_lowercase()
    } else {
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tail_failure_preserves_permission_denied_kind() {
        let failure = tail_failure(
            Path::new("protected.log"),
            "open tail",
            std::io::Error::from(std::io::ErrorKind::PermissionDenied),
        );

        assert_eq!(failure.kind, DiscoveryPathFailureKind::PermissionDenied);
    }
}
