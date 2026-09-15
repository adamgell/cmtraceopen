//! Backend-owned, disk-spooled GUI export sessions.
//!
//! The WebView sends bounded base64 envelopes containing one ordered NDJSON byte stream. Records
//! may cross envelope boundaries, so neither total export size nor one unusually large event can
//! turn back into a monolithic IPC call. The unredacted spool is an anonymous delete-on-close file;
//! only the existing redacting writer publishes a named destination.

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine as _;
use serde::Serialize;

use super::export::{ExportFormat, MappedColumnAccumulator};
use super::models::EvtxRecord;
use super::writer::{self, ExportStats};
use crate::state::app_state::AppState;

pub(crate) const MAX_EXPORT_CHUNK_BYTES: usize = 4 * 1024 * 1024;
const MAX_EXPORT_CHUNK_BASE64_CHARS: usize = MAX_EXPORT_CHUNK_BYTES.div_ceil(3) * 4;
const MAX_EXPORT_CHUNK_RECORD_SEPARATORS: usize = 1_000;
const MAX_EXPORT_SESSION_ID_CHARS: usize = 128;
const MAX_EXPORT_SESSIONS: usize = 16;
const MAX_CACHED_RECORD_SOURCE_LABELS: usize = 4_096;
const EXPORT_SESSION_IDLE_TTL: Duration = Duration::from_secs(60 * 60);

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EventLogExportSessionStatus {
    pub session_id: String,
    pub next_sequence: u64,
    pub received_records: u64,
    pub received_bytes: u64,
    pub expected_records: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EventLogExportResult {
    pub session_id: String,
    pub records: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExportSessionState {
    Receiving,
    Finalizing,
    Terminal,
}

struct EventLogExportSession {
    id: String,
    format: ExportFormat,
    destination: PathBuf,
    destination_identity: PathBuf,
    protected_sources: Vec<String>,
    expected_records: u64,
    next_sequence: u64,
    received_records: u64,
    received_bytes: u64,
    spool: Option<File>,
    cancel: Arc<AtomicBool>,
    state: ExportSessionState,
}

type SharedEventLogExportSession = Arc<Mutex<EventLogExportSession>>;

pub(crate) struct EventLogExportSessionEntry {
    session: SharedEventLogExportSession,
    cancel: Arc<AtomicBool>,
    destination_identity: PathBuf,
    last_access: Instant,
    finalizing: bool,
    expiry_abort: Option<tokio::task::AbortHandle>,
}

pub(crate) type EventLogExportSessionRegistry = HashMap<String, EventLogExportSessionEntry>;

impl EventLogExportSession {
    fn new(
        id: String,
        format: ExportFormat,
        destination: PathBuf,
        protected_sources: Vec<String>,
        expected_records: u64,
    ) -> Result<Self, String> {
        if destination.as_os_str().is_empty() || destination == Path::new("-") {
            return Err("event-log GUI export requires a destination file".to_string());
        }
        writer::reject_source_destination(&protected_sources, Some(&destination))?;
        let destination_identity = writer::normalized_path_identity(&destination);
        let cancel = Arc::new(AtomicBool::new(false));
        Ok(Self {
            id,
            format,
            destination,
            destination_identity,
            protected_sources,
            expected_records,
            next_sequence: 0,
            received_records: 0,
            received_bytes: 0,
            spool: Some(
                tempfile::tempfile()
                    .map_err(|error| format!("cannot create private export spool: {error}"))?,
            ),
            cancel,
            state: ExportSessionState::Receiving,
        })
    }

    fn status(&self) -> EventLogExportSessionStatus {
        EventLogExportSessionStatus {
            session_id: self.id.clone(),
            next_sequence: self.next_sequence,
            received_records: self.received_records,
            received_bytes: self.received_bytes,
            expected_records: self.expected_records,
        }
    }

    fn append_chunk(
        &mut self,
        sequence: u64,
        payload_base64: &str,
    ) -> Result<EventLogExportSessionStatus, String> {
        if self.state != ExportSessionState::Receiving {
            return Err("event-log export session is not accepting more data".to_string());
        }
        if self.cancel.load(Ordering::Acquire) {
            return Err("event-log export was cancelled".to_string());
        }
        if sequence != self.next_sequence {
            return Err(format!(
                "event-log export chunk sequence {sequence} does not match expected sequence {}",
                self.next_sequence
            ));
        }
        if payload_base64.is_empty() || payload_base64.len() > MAX_EXPORT_CHUNK_BASE64_CHARS {
            return Err(format!(
                "event-log export chunk base64 envelope must contain at most {MAX_EXPORT_CHUNK_BASE64_CHARS} characters"
            ));
        }
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(payload_base64)
            .map_err(|error| format!("event-log export chunk is not valid base64: {error}"))?;
        if decoded.is_empty() || decoded.len() > MAX_EXPORT_CHUNK_BYTES {
            return Err(format!(
                "event-log export chunk must decode to at most {MAX_EXPORT_CHUNK_BYTES} bytes"
            ));
        }
        let separators = decoded.iter().filter(|byte| **byte == b'\n').count();
        if separators > MAX_EXPORT_CHUNK_RECORD_SEPARATORS {
            return Err(format!(
                "event-log export chunk contains {separators} record separators; at most {MAX_EXPORT_CHUNK_RECORD_SEPARATORS} are allowed"
            ));
        }
        let received_records = self
            .received_records
            .checked_add(u64::try_from(separators).unwrap_or(u64::MAX))
            .ok_or_else(|| "event-log export record count overflowed".to_string())?;
        if received_records > self.expected_records {
            return Err(format!(
                "event-log export received more than the expected {} records",
                self.expected_records
            ));
        }
        let received_bytes = self
            .received_bytes
            .checked_add(u64::try_from(decoded.len()).unwrap_or(u64::MAX))
            .ok_or_else(|| "event-log export byte count overflowed".to_string())?;
        let Some(spool) = self.spool.as_mut() else {
            return Err("event-log export spool is unavailable".to_string());
        };
        if let Err(error) = spool.write_all(&decoded) {
            self.state = ExportSessionState::Terminal;
            self.spool.take();
            return Err(format!("cannot append to private export spool: {error}"));
        }
        self.next_sequence = self.next_sequence.saturating_add(1);
        self.received_records = received_records;
        self.received_bytes = received_bytes;
        Ok(self.status())
    }

    fn finalize(&mut self) -> Result<EventLogExportResult, String> {
        if self.state != ExportSessionState::Receiving {
            return Err("event-log export session cannot be finalized twice".to_string());
        }
        self.state = ExportSessionState::Finalizing;
        let result = self.finalize_inner();
        self.state = ExportSessionState::Terminal;
        self.spool.take();
        result
    }

    fn finalize_inner(&mut self) -> Result<EventLogExportResult, String> {
        if self.cancel.load(Ordering::Acquire) {
            return Err("event-log export was cancelled".to_string());
        }
        if self.received_records != self.expected_records {
            return Err(format!(
                "event-log export received {} of {} expected records",
                self.received_records, self.expected_records
            ));
        }
        let Some(spool) = self.spool.as_mut() else {
            return Err("event-log export spool is unavailable".to_string());
        };
        spool
            .flush()
            .map_err(|error| format!("cannot flush private export spool: {error}"))?;
        if self.received_bytes > 0 {
            spool
                .seek(SeekFrom::End(-1))
                .map_err(|error| format!("cannot inspect private export spool: {error}"))?;
            let mut final_byte = [0u8; 1];
            spool
                .read_exact(&mut final_byte)
                .map_err(|error| format!("cannot inspect private export spool: {error}"))?;
            if final_byte[0] != b'\n' {
                return Err(
                    "event-log export stream ended before its final record separator".into(),
                );
            }
        }

        spool
            .seek(SeekFrom::Start(0))
            .map_err(|error| format!("cannot rewind private export spool: {error}"))?;
        let mut mapped = MappedColumnAccumulator::default();
        let mut parsed_records = 0u64;
        let mut checked_sources = HashSet::new();
        {
            let reader = CancelReader::new(BufReader::new(&mut *spool), self.cancel.clone());
            let records = serde_json::Deserializer::from_reader(reader).into_iter::<EvtxRecord>();
            for record in records {
                let record = record
                    .map_err(|error| format!("cannot decode private export spool: {error}"))?;
                writer::validate_raw_xml_iter([&record], self.format)
                    .map_err(|error| error.to_string())?;
                let should_check_source = checked_sources.contains(&record.source_label)
                    || checked_sources.len() < MAX_CACHED_RECORD_SOURCE_LABELS;
                if should_check_source && !checked_sources.contains(&record.source_label) {
                    if writer::normalized_path_identity(Path::new(&record.source_label))
                        == self.destination_identity
                    {
                        return Err(
                            "output path cannot overwrite an opened source or manifest".to_string()
                        );
                    }
                    checked_sources.insert(record.source_label.clone());
                } else if !should_check_source
                    && writer::normalized_path_identity(Path::new(&record.source_label))
                        == self.destination_identity
                {
                    return Err(
                        "output path cannot overwrite an opened source or manifest".to_string()
                    );
                }
                mapped.observe(&record)?;
                parsed_records = parsed_records
                    .checked_add(1)
                    .ok_or_else(|| "event-log export parsed record count overflowed".to_string())?;
            }
        }
        if parsed_records != self.expected_records {
            return Err(format!(
                "event-log export decoded {parsed_records} of {} expected records",
                self.expected_records
            ));
        }

        let mut output_spool = spool
            .try_clone()
            .map_err(|error| format!("cannot clone private export spool: {error}"))?;
        output_spool
            .seek(SeekFrom::Start(0))
            .map_err(|error| format!("cannot rewind private export spool: {error}"))?;
        let mapped_columns = mapped.into_columns();
        let reader = CancelReader::new(BufReader::new(output_spool), self.cancel.clone());
        let records = serde_json::Deserializer::from_reader(reader)
            .into_iter::<EvtxRecord>()
            .map(|record| {
                record.map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
            });
        let mut validation_spool = spool
            .try_clone()
            .map_err(|error| format!("cannot clone private export spool: {error}"))?;
        let cancel = self.cancel.clone();
        let destination = self.destination.clone();
        let publication_destination = destination.clone();
        let protected_sources = self.protected_sources.clone();
        let expected_records = self.expected_records;
        let ExportStats { bytes, records } =
            writer::write_fallible_record_stream_to_destination_with_commit_check(
                records,
                self.format,
                &destination,
                &mapped_columns,
                move || {
                    validate_export_publication(
                        &mut validation_spool,
                        &cancel,
                        &publication_destination,
                        &protected_sources,
                        expected_records,
                    )
                },
            )?;
        if records != self.expected_records {
            return Err(format!(
                "event-log export wrote {records} of {} expected records",
                self.expected_records
            ));
        }
        Ok(EventLogExportResult {
            session_id: self.id.clone(),
            records,
            bytes,
        })
    }
}

fn validate_export_publication(
    spool: &mut File,
    cancel: &Arc<AtomicBool>,
    destination: &Path,
    protected_sources: &[String],
    expected_records: u64,
) -> Result<(), String> {
    if cancel.load(Ordering::Acquire) {
        return Err("event-log export was cancelled".to_string());
    }
    writer::reject_source_destination(protected_sources, Some(destination))?;
    let destination_identity = writer::normalized_path_identity(destination);
    spool
        .seek(SeekFrom::Start(0))
        .map_err(|error| format!("cannot rewind private export spool: {error}"))?;
    let reader = CancelReader::new(BufReader::new(spool), cancel.clone());
    let records = serde_json::Deserializer::from_reader(reader).into_iter::<EvtxRecord>();
    let mut parsed_records = 0u64;
    let mut checked_sources = HashSet::new();
    for record in records {
        let record =
            record.map_err(|error| format!("cannot decode private export spool: {error}"))?;
        parsed_records = parsed_records
            .checked_add(1)
            .ok_or_else(|| "event-log export parsed record count overflowed".to_string())?;
        if checked_sources.contains(&record.source_label) {
            continue;
        }
        if writer::normalized_path_identity(Path::new(&record.source_label)) == destination_identity
        {
            return Err("output path cannot overwrite an opened source or manifest".to_string());
        }
        if checked_sources.len() < MAX_CACHED_RECORD_SOURCE_LABELS {
            checked_sources.insert(record.source_label);
        }
    }
    if parsed_records != expected_records {
        return Err(format!(
            "event-log export decoded {parsed_records} of {expected_records} expected records"
        ));
    }
    if cancel.load(Ordering::Acquire) {
        return Err("event-log export was cancelled".to_string());
    }
    Ok(())
}

struct CancelReader<R> {
    inner: R,
    cancel: Arc<AtomicBool>,
}

impl<R> CancelReader<R> {
    fn new(inner: R, cancel: Arc<AtomicBool>) -> Self {
        Self { inner, cancel }
    }
}

impl<R: Read> Read for CancelReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.cancel.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "event-log export was cancelled",
            ));
        }
        self.inner.read(buffer)
    }
}

fn validate_session_id(session_id: &str) -> Result<(), String> {
    if session_id.is_empty()
        || session_id.len() > MAX_EXPORT_SESSION_ID_CHARS
        || session_id.chars().any(char::is_control)
    {
        return Err("invalid event-log export session ID".to_string());
    }
    Ok(())
}

fn prune_stale_export_sessions(sessions: &mut EventLogExportSessionRegistry, now: Instant) {
    sessions.retain(|_, entry| {
        let keep = entry.finalizing
            || now.saturating_duration_since(entry.last_access) < EXPORT_SESSION_IDLE_TTL;
        if !keep {
            entry.cancel.store(true, Ordering::Release);
            if let Some(expiry_abort) = entry.expiry_abort.take() {
                expiry_abort.abort();
            }
        }
        keep
    });
}

fn insert_export_session(
    sessions: &mut EventLogExportSessionRegistry,
    id: String,
    session: EventLogExportSession,
    now: Instant,
) -> Result<EventLogExportSessionStatus, String> {
    prune_stale_export_sessions(sessions, now);
    if sessions.len() >= MAX_EXPORT_SESSIONS {
        return Err(format!(
            "event-log export session capacity of {MAX_EXPORT_SESSIONS} is in use; close an existing export and retry"
        ));
    }
    if sessions
        .values()
        .any(|entry| entry.destination_identity == session.destination_identity)
    {
        return Err("another event-log export is already writing that destination".to_string());
    }
    let status = session.status();
    let cancel = session.cancel.clone();
    let destination_identity = session.destination_identity.clone();
    sessions.insert(
        id,
        EventLogExportSessionEntry {
            session: Arc::new(Mutex::new(session)),
            cancel,
            destination_identity,
            last_access: now,
            finalizing: false,
            expiry_abort: None,
        },
    );
    Ok(status)
}

fn find_session(state: &AppState, session_id: &str) -> Result<SharedEventLogExportSession, String> {
    validate_session_id(session_id)?;
    let mut sessions = state
        .event_log_export_sessions
        .lock()
        .map_err(|_| "event-log export session registry lock was poisoned".to_string())?;
    let now = Instant::now();
    prune_stale_export_sessions(&mut sessions, now);
    let entry = sessions
        .get_mut(session_id)
        .ok_or_else(|| "event-log export session was not found".to_string())?;
    entry.last_access = now;
    Ok(entry.session.clone())
}

fn begin_finalize_session(
    state: &AppState,
    session_id: &str,
) -> Result<SharedEventLogExportSession, String> {
    validate_session_id(session_id)?;
    let mut sessions = state
        .event_log_export_sessions
        .lock()
        .map_err(|_| "event-log export session registry lock was poisoned".to_string())?;
    let now = Instant::now();
    prune_stale_export_sessions(&mut sessions, now);
    let entry = sessions
        .get_mut(session_id)
        .ok_or_else(|| "event-log export session was not found".to_string())?;
    if entry.finalizing {
        return Err("event-log export session is already finalizing".to_string());
    }
    entry.finalizing = true;
    entry.last_access = now;
    Ok(entry.session.clone())
}

fn cancel_export_session(sessions: &mut EventLogExportSessionRegistry, session_id: &str) {
    let remove = sessions.get(session_id).is_some_and(|entry| {
        entry.cancel.store(true, Ordering::Release);
        !entry.finalizing
    });
    if remove {
        remove_export_session(sessions, session_id);
    }
}

fn remove_export_session(sessions: &mut EventLogExportSessionRegistry, session_id: &str) {
    let Some(mut entry) = sessions.remove(session_id) else {
        return;
    };
    if let Some(expiry_abort) = entry.expiry_abort.take() {
        expiry_abort.abort();
    }
}

async fn expire_export_session_after_idle(
    sessions: Arc<Mutex<EventLogExportSessionRegistry>>,
    session_id: String,
    idle_ttl: Duration,
) {
    let mut remaining = idle_ttl;
    loop {
        tokio::time::sleep(remaining).await;
        let mut registry = match sessions.lock() {
            Ok(registry) => registry,
            Err(_) => return,
        };
        let Some(entry) = registry.get(&session_id) else {
            return;
        };
        if entry.finalizing {
            // The finalizer owns cleanup and must retain the destination reservation until it exits.
            return;
        }
        let elapsed = Instant::now().saturating_duration_since(entry.last_access);
        if elapsed >= idle_ttl {
            if let Some(mut entry) = registry.remove(&session_id) {
                entry.cancel.store(true, Ordering::Release);
                // This task is the expiry owner, so merely discard its own abort handle and return.
                entry.expiry_abort.take();
            }
            return;
        }
        remaining = idle_ttl.saturating_sub(elapsed);
    }
}

#[tauri::command]
pub async fn evtx_create_export_session(
    format: ExportFormat,
    destination: String,
    source_paths: Vec<String>,
    expected_records: u64,
    state: tauri::State<'_, AppState>,
) -> Result<EventLogExportSessionStatus, String> {
    let id = uuid::Uuid::new_v4().to_string();
    let destination = PathBuf::from(destination);
    let session = tokio::task::spawn_blocking({
        let id = id.clone();
        move || EventLogExportSession::new(id, format, destination, source_paths, expected_records)
    })
    .await
    .map_err(|error| format!("export session creation task failed: {error}"))??;
    let mut sessions = state
        .event_log_export_sessions
        .lock()
        .map_err(|_| "event-log export session registry lock was poisoned".to_string())?;
    let status = insert_export_session(&mut sessions, id.clone(), session, Instant::now())?;
    let expiry_task = tokio::spawn(expire_export_session_after_idle(
        Arc::clone(&state.event_log_export_sessions),
        id.clone(),
        EXPORT_SESSION_IDLE_TTL,
    ));
    sessions
        .get_mut(&id)
        .expect("export session inserted while registry lock is held")
        .expiry_abort = Some(expiry_task.abort_handle());
    drop(expiry_task);
    drop(sessions);
    Ok(status)
}

#[tauri::command]
pub async fn evtx_append_export_chunk(
    session_id: String,
    sequence: u64,
    payload_base64: String,
    state: tauri::State<'_, AppState>,
) -> Result<EventLogExportSessionStatus, String> {
    let session = find_session(&state, &session_id)?;
    tokio::task::spawn_blocking(move || {
        session
            .lock()
            .map_err(|_| "event-log export session lock was poisoned".to_string())?
            .append_chunk(sequence, &payload_base64)
    })
    .await
    .map_err(|error| format!("export append task failed: {error}"))?
}

#[tauri::command]
pub async fn evtx_finalize_export_session(
    session_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<EventLogExportResult, String> {
    let session = begin_finalize_session(&state, &session_id)?;
    let result = match tokio::task::spawn_blocking(move || {
        session
            .lock()
            .map_err(|_| "event-log export session lock was poisoned".to_string())?
            .finalize()
    })
    .await
    {
        Ok(result) => result,
        Err(error) => Err(format!("export finalize task failed: {error}")),
    };
    let mut sessions = state
        .event_log_export_sessions
        .lock()
        .map_err(|_| "event-log export session registry lock was poisoned".to_string())?;
    remove_export_session(&mut sessions, &session_id);
    if let Ok(stats) = &result {
        log::info!(
            "event=evtx_export destination_session={} records={} bytes={}",
            stats.session_id,
            stats.records,
            stats.bytes
        );
    }
    result
}

#[tauri::command]
pub fn evtx_close_export_session(
    session_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    validate_session_id(&session_id)?;
    let mut sessions = state
        .event_log_export_sessions
        .lock()
        .map_err(|_| "event-log export session registry lock was poisoned".to_string())?;
    cancel_export_session(&mut sessions, &session_id);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_log::maps::MappedColumn;
    use crate::event_log::models::{EvtxField, EvtxLevel, EvtxOriginKind};
    use crate::event_log::writer;

    fn record(id: u64, message: &str) -> EvtxRecord {
        EvtxRecord {
            id,
            event_record_id: id,
            event_record_id_text: Some(id.to_string()),
            timestamp: "2026-08-30T12:00:00.000Z".to_string(),
            timestamp_epoch: i64::try_from(id).unwrap_or(i64::MAX),
            provider: "Provider".to_string(),
            channel: "Application".to_string(),
            event_id: 100,
            level: EvtxLevel::Information,
            computer: "TESTHOST".to_string(),
            message: message.to_string(),
            event_data: vec![EvtxField {
                name: "Detail".to_string(),
                value: "Value".to_string(),
            }],
            raw_xml: format!("<Event><System><EventID>{id}</EventID></System></Event>"),
            source_label: "source.evtx".to_string(),
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

    fn append_bytes(session: &mut EventLogExportSession, bytes: &[u8], chunk_size: usize) {
        for (sequence, chunk) in bytes.chunks(chunk_size).enumerate() {
            let encoded = base64::engine::general_purpose::STANDARD.encode(chunk);
            session
                .append_chunk(u64::try_from(sequence).unwrap(), &encoded)
                .unwrap();
        }
    }

    fn session(
        destination: &Path,
        format: ExportFormat,
        expected_records: u64,
    ) -> EventLogExportSession {
        EventLogExportSession::new(
            "test-export".to_string(),
            format,
            destination.to_path_buf(),
            Vec::new(),
            expected_records,
        )
        .unwrap()
    }

    #[test]
    fn chunked_sessions_match_the_existing_writer_for_every_format() {
        let mut second = record(2, "second");
        second.mapped.push(MappedColumn {
            property: "RemoteHost".to_string(),
            text: "host-two".to_string(),
            complete: true,
        });
        let mut first = record(1, "first");
        first.mapped.push(MappedColumn {
            property: "UserName".to_string(),
            text: "user-one".to_string(),
            complete: true,
        });
        let records = vec![second, first];
        let mut ndjson = Vec::new();
        for record in &records {
            serde_json::to_writer(&mut ndjson, record).unwrap();
            ndjson.push(b'\n');
        }
        for format in [
            ExportFormat::Csv,
            ExportFormat::Tsv,
            ExportFormat::Json,
            ExportFormat::Xml,
            ExportFormat::Html,
            ExportFormat::RawXml,
        ] {
            let directory = tempfile::tempdir().unwrap();
            let destination = directory
                .path()
                .join(format!("events.{}", format.extension()));
            let mut export = session(&destination, format, records.len() as u64);
            append_bytes(&mut export, &ndjson, 17);
            let result = export.finalize().unwrap();
            let actual = std::fs::read(&destination).unwrap();
            let mut expected = Vec::new();
            let stats = writer::write_records(&mut expected, format, &records).unwrap();
            assert_eq!(actual, expected, "format {format:?}");
            assert_eq!(result.bytes, stats.bytes);
            assert_eq!(result.records, stats.records);
        }
    }

    #[test]
    fn one_record_can_cross_the_transport_envelope_without_truncation() {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("events.json");
        let mut source = record(1, "large structured event");
        source.event_data = (0..9_000)
            .map(|index| EvtxField {
                name: format!("Field{index}"),
                value: "x".repeat(512),
            })
            .collect();
        let mut ndjson = serde_json::to_vec(&source).unwrap();
        assert!(ndjson.len() > MAX_EXPORT_CHUNK_BYTES);
        ndjson.push(b'\n');
        let mut export = session(&destination, ExportFormat::Json, 1);
        append_bytes(&mut export, &ndjson, MAX_EXPORT_CHUNK_BYTES);

        export.finalize().unwrap();

        let records: Vec<EvtxRecord> =
            serde_json::from_slice(&std::fs::read(destination).unwrap()).unwrap();
        assert_eq!(records[0].event_data.len(), source.event_data.len());
        assert_eq!(
            records[0].event_data.last().unwrap().name,
            source.event_data.last().unwrap().name
        );
        assert_eq!(
            records[0].event_data.last().unwrap().value,
            source.event_data.last().unwrap().value
        );
    }

    #[test]
    fn session_accepts_more_than_the_legacy_64_mib_ipc_limit() {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("events.json");
        let expected_records = 65u64;
        let mut export = session(&destination, ExportFormat::Json, expected_records);
        let message = "x".repeat(1024 * 1024);
        let mut received_bytes = 0usize;

        for sequence in 0..expected_records {
            let mut line = serde_json::to_vec(&record(sequence + 1, &message)).unwrap();
            line.push(b'\n');
            received_bytes += line.len();
            let encoded = base64::engine::general_purpose::STANDARD.encode(&line);
            let status = export.append_chunk(sequence, &encoded).unwrap();
            assert_eq!(status.next_sequence, sequence + 1);
        }
        assert!(received_bytes > 64 * 1024 * 1024);

        let result = export.finalize().unwrap();

        assert_eq!(result.records, expected_records);
        let output: Vec<EvtxRecord> =
            serde_json::from_slice(&std::fs::read(destination).unwrap()).unwrap();
        assert_eq!(output.len(), usize::try_from(expected_records).unwrap());
        assert_eq!(output.first().unwrap().id, 1);
        assert_eq!(output.last().unwrap().id, expected_records);
    }

    #[test]
    fn malformed_or_incomplete_stream_never_replaces_the_destination() {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("events.json");
        std::fs::write(&destination, b"sentinel").unwrap();
        let mut export = session(&destination, ExportFormat::Json, 1);
        append_bytes(&mut export, b"{not-json}\n", 64);

        assert!(export.finalize().is_err());
        assert_eq!(std::fs::read(destination).unwrap(), b"sentinel");
    }

    #[test]
    fn sequence_and_expected_count_are_authoritative() {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("events.json");
        let mut export = session(&destination, ExportFormat::Json, 2);
        let line = format!("{}\n", serde_json::to_string(&record(1, "one")).unwrap());
        let encoded = base64::engine::general_purpose::STANDARD.encode(line);

        assert!(export.append_chunk(1, &encoded).is_err());
        export.append_chunk(0, &encoded).unwrap();
        assert!(export.append_chunk(0, &encoded).is_err());
        assert!(export.finalize().is_err());
        assert!(!destination.exists());
    }

    #[test]
    fn cancellation_during_finalize_preserves_the_destination() {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("events.json");
        std::fs::write(&destination, b"sentinel").unwrap();
        let source = record(1, "one");
        let line = format!("{}\n", serde_json::to_string(&source).unwrap());
        let mut export = session(&destination, ExportFormat::Json, 1);
        append_bytes(&mut export, line.as_bytes(), 64);
        export.cancel.store(true, Ordering::Release);

        assert!(export.finalize().is_err());
        assert_eq!(std::fs::read(destination).unwrap(), b"sentinel");
    }

    #[test]
    fn record_source_remains_protected_when_initial_source_paths_are_empty() {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("source.evtx");
        std::fs::write(&destination, b"sentinel").unwrap();
        let mut source = record(1, "one");
        source.source_label = destination.to_string_lossy().into_owned();
        let line = format!("{}\n", serde_json::to_string(&source).unwrap());
        let mut export = session(&destination, ExportFormat::Csv, 1);
        append_bytes(&mut export, line.as_bytes(), 64);

        let error = export.finalize().unwrap_err();

        assert!(error.contains("cannot overwrite"));
        assert_eq!(std::fs::read(destination).unwrap(), b"sentinel");
    }

    #[test]
    fn publication_revalidates_record_sources_instead_of_trusting_creation_identity() {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("source.evtx");
        std::fs::write(&destination, b"sentinel").unwrap();
        let mut source = record(1, "one");
        source.source_label = destination.to_string_lossy().into_owned();
        let line = format!("{}\n", serde_json::to_string(&source).unwrap());
        let mut export = session(&destination, ExportFormat::Csv, 1);
        // Model the creation-time identity becoming stale through a link/alias change. The final
        // publication check must re-resolve both sides rather than trusting this cached value.
        export.destination_identity = directory.path().join("old-target");
        append_bytes(&mut export, line.as_bytes(), 64);

        let error = export.finalize().unwrap_err();

        assert!(error.contains("cannot overwrite"));
        assert_eq!(std::fs::read(destination).unwrap(), b"sentinel");
    }

    #[test]
    fn active_sessions_cannot_target_the_same_destination() {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("events.json");
        let first = session(&destination, ExportFormat::Json, 0);
        let second = session(&destination, ExportFormat::Json, 0);
        let mut registry = EventLogExportSessionRegistry::new();
        insert_export_session(&mut registry, "first".to_string(), first, Instant::now()).unwrap();

        assert!(
            insert_export_session(&mut registry, "second".to_string(), second, Instant::now(),)
                .is_err()
        );
    }

    #[test]
    fn cancelling_a_finalizer_keeps_its_destination_reserved_until_exit() {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("events.json");
        let first = session(&destination, ExportFormat::Json, 0);
        let cancellation = first.cancel.clone();
        let mut registry = EventLogExportSessionRegistry::new();
        insert_export_session(&mut registry, "first".to_string(), first, Instant::now()).unwrap();
        registry.get_mut("first").unwrap().finalizing = true;

        cancel_export_session(&mut registry, "first");

        assert!(cancellation.load(Ordering::Acquire));
        assert!(registry.contains_key("first"));
        let second = session(&destination, ExportFormat::Json, 0);
        assert!(
            insert_export_session(&mut registry, "second".to_string(), second, Instant::now())
                .is_err()
        );
        registry.remove("first");
        let replacement = session(&destination, ExportFormat::Json, 0);
        insert_export_session(
            &mut registry,
            "replacement".to_string(),
            replacement,
            Instant::now(),
        )
        .unwrap();
    }

    #[test]
    fn abandoned_sessions_are_reaped_without_another_export_command() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        runtime.block_on(async {
            let directory = tempfile::tempdir().unwrap();
            let destination = directory.path().join("events.json");
            let export = session(&destination, ExportFormat::Json, 0);
            let cancellation = export.cancel.clone();
            let registry = Arc::new(Mutex::new(EventLogExportSessionRegistry::new()));
            insert_export_session(
                &mut registry.lock().unwrap(),
                "abandoned".to_string(),
                export,
                Instant::now(),
            )
            .unwrap();
            drop(tokio::spawn(expire_export_session_after_idle(
                Arc::clone(&registry),
                "abandoned".to_string(),
                Duration::from_millis(10),
            )));

            tokio::time::sleep(Duration::from_millis(50)).await;

            assert!(registry.lock().unwrap().is_empty());
            assert!(cancellation.load(Ordering::Acquire));
        });
    }

    #[test]
    fn normal_close_aborts_the_detached_expiry_sleeper() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        runtime.block_on(async {
            let directory = tempfile::tempdir().unwrap();
            let destination = directory.path().join("events.json");
            let export = session(&destination, ExportFormat::Json, 0);
            let registry = Arc::new(Mutex::new(EventLogExportSessionRegistry::new()));
            insert_export_session(
                &mut registry.lock().unwrap(),
                "closed".to_string(),
                export,
                Instant::now(),
            )
            .unwrap();
            let expiry_task = tokio::spawn(expire_export_session_after_idle(
                Arc::clone(&registry),
                "closed".to_string(),
                Duration::from_secs(60 * 60),
            ));
            let expiry_abort = expiry_task.abort_handle();
            registry
                .lock()
                .unwrap()
                .get_mut("closed")
                .unwrap()
                .expiry_abort = Some(expiry_abort.clone());
            drop(expiry_task);

            cancel_export_session(&mut registry.lock().unwrap(), "closed");
            tokio::task::yield_now().await;

            assert!(registry.lock().unwrap().is_empty());
            assert!(expiry_abort.is_finished());
        });
    }
}
