//! Firewall continuation and source ownership. Candidates parse outside the
//! owner lock; checkpoint commit and event enqueue share the current-owner fence.
use crate::{
    fs_identity::{file_identity, identities_differ, FileIdentity},
    models::{firewall::FirewallCoverage, log_entry::LogEntry},
    parser::firewall_source::*,
    state::app_state::AppState,
};
use cmtraceopen_parser::parser::firewall_stream::{FirewallRowReplacement, FirewallStream};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, Metadata},
    io::{Read, Seek, SeekFrom},
    path::Path,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FirewallControlToken {
    pub source_session_id: String,
    pub watch_epoch: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartAdmission {
    Started,
    Current,
    Rejected,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallTransition {
    Generation,
    Windows1252,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum FirewallDecodingKind {
    Ready,
    Pending,
    Gap,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum FirewallGapReason {
    ReadFailed,
    InvalidEncoding,
    GenerationUnverifiable,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FirewallDecodingStatus {
    pub kind: FirewallDecodingKind,
    pub pending_bytes: u8,
    pub reason: Option<FirewallGapReason>,
}
impl FirewallDecodingStatus {
    fn from_decoder(decoder: &FirewallDecoder) -> Self {
        Self {
            kind: if decoder.pending_bytes() == 0 {
                FirewallDecodingKind::Ready
            } else {
                FirewallDecodingKind::Pending
            },
            pending_bytes: decoder.pending_bytes() as u8,
            reason: None,
        }
    }
}
#[derive(Clone)]
pub struct FirewallCheckpoint {
    pub decoder: FirewallDecoder,
    pub stream: FirewallStream,
    pub identity: Option<FileIdentity>,
}
pub struct FirewallOwner {
    pub session_id: String,
    pub checkpoint: FirewallCheckpoint,
    pub pending: Option<FirewallTransition>,
    pub decoding: FirewallDecodingStatus,
    epoch: u64,
    revision: u64,
    active: bool,
    paused: bool,
}
#[derive(Clone)]
pub struct FirewallReadRequest {
    pub revision: u64,
    pub checkpoint: FirewallCheckpoint,
    pub pending: Option<FirewallTransition>,
}
pub struct FirewallBatch {
    pub entries: Vec<LogEntry>,
    pub replacements: Vec<FirewallRowReplacement>,
    pub coverage: FirewallCoverage,
    pub observed_through_line: u32,
    pub reset: bool,
    pub decoding: FirewallDecodingStatus,
}
pub struct FirewallReadOutcome {
    checkpoint: Option<FirewallCheckpoint>,
    pending: Option<FirewallTransition>,
    batch: FirewallBatch,
    changed: bool,
}
impl FirewallOwner {
    pub fn new(snapshot: FirewallSourceSnapshot, identity: Option<FileIdentity>) -> Self {
        Self {
            session_id: uuid::Uuid::new_v4().to_string(),
            decoding: FirewallDecodingStatus::from_decoder(&snapshot.decoder),
            checkpoint: FirewallCheckpoint {
                decoder: snapshot.decoder,
                stream: snapshot.stream,
                identity,
            },
            pending: None,
            epoch: 0,
            revision: 0,
            active: false,
            paused: false,
        }
    }
    fn same_session(&self, token: &FirewallControlToken) -> bool {
        token.source_session_id == self.session_id
            && token.watch_epoch > 0
            && token.watch_epoch <= 9_007_199_254_740_991
    }
    pub fn is_current(&self, token: &FirewallControlToken) -> bool {
        self.same_session(token) && token.watch_epoch == self.epoch && self.active
    }
    pub fn start(&mut self, token: Option<&FirewallControlToken>) -> StartAdmission {
        let Some(t) = token.filter(|t| self.same_session(t)) else {
            return StartAdmission::Rejected;
        };
        if t.watch_epoch < self.epoch {
            return StartAdmission::Rejected;
        }
        if t.watch_epoch == self.epoch {
            return if self.active {
                StartAdmission::Current
            } else {
                StartAdmission::Rejected
            };
        }
        self.epoch = t.watch_epoch;
        self.revision += 1;
        self.active = true;
        self.paused = false;
        StartAdmission::Started
    }
    pub fn stop(&mut self, token: Option<&FirewallControlToken>) -> bool {
        let Some(t) = token.filter(|t| self.same_session(t) && t.watch_epoch >= self.epoch) else {
            return false;
        };
        self.epoch = t.watch_epoch;
        self.revision += 1;
        self.active = false;
        true
    }
    pub fn set_paused(&mut self, token: Option<&FirewallControlToken>, paused: bool) -> bool {
        let Some(_) = token.filter(|t| self.is_current(t)) else {
            return false;
        };
        self.paused = paused;
        self.revision += 1;
        true
    }
    pub fn request(&self, token: &FirewallControlToken) -> Option<FirewallReadRequest> {
        (self.is_current(token) && !self.paused).then(|| FirewallReadRequest {
            revision: self.revision,
            checkpoint: self.checkpoint.clone(),
            pending: self.pending,
        })
    }
    pub fn commit(
        &mut self,
        token: &FirewallControlToken,
        revision: u64,
        outcome: FirewallReadOutcome,
        publish: impl FnOnce(FirewallBatch),
    ) -> bool {
        if !self.is_current(token) || self.paused || revision != self.revision {
            return false;
        }
        if let Some(checkpoint) = outcome.checkpoint {
            self.checkpoint = checkpoint;
        }
        self.pending = outcome.pending;
        self.revision += 1;
        let report = outcome.changed || outcome.batch.decoding != self.decoding;
        self.decoding = outcome.batch.decoding.clone();
        if report {
            publish(outcome.batch);
        }
        true
    }
}

pub fn commit_current(
    state: &AppState,
    path: &Path,
    token: &FirewallControlToken,
    revision: u64,
    outcome: FirewallReadOutcome,
    publish: impl FnOnce(FirewallBatch),
) -> Result<bool, crate::error::AppError> {
    let mut files = state
        .open_files
        .lock()
        .map_err(|e| crate::error::AppError::State(e.to_string()))?;
    let Some(file) = files.get_mut(path) else {
        return Ok(false);
    };
    let Some(owner) = file.firewall.as_mut() else {
        return Ok(false);
    };
    let committed = owner.commit(token, revision, outcome, publish);
    if committed {
        file.byte_offset = owner.checkpoint.decoder.raw_offset();
        file.file_identity = owner.checkpoint.identity;
    }
    Ok(committed)
}

pub fn read_bytes(file: &mut File, out: &mut Vec<u8>, limit: Option<usize>) -> std::io::Result<()> {
    if let Some(limit) = limit {
        file.take(limit as u64).read_to_end(out)?;
    } else {
        file.read_to_end(out)?;
    }
    Ok(())
}
pub fn read_candidate(request: &FirewallReadRequest, path: &Path) -> FirewallReadOutcome {
    read_candidate_with(request, path, read_bytes)
}
/// Reader injection supports deterministic I/O failure/race tests; production
/// reads exactly the admitted handle and never reopens it to infer encoding.
pub fn read_candidate_with(
    request: &FirewallReadRequest,
    path: &Path,
    mut read: impl FnMut(&mut File, &mut Vec<u8>, Option<usize>) -> std::io::Result<()>,
) -> FirewallReadOutcome {
    let mut pending = request.pending;
    let result = (|| {
        let mut file = File::open(path).map_err(|_| FirewallGapReason::ReadFailed)?;
        let metadata = file.metadata().map_err(|_| FirewallGapReason::ReadFailed)?;
        let identity = file_identity(&file, &metadata);
        if identities_differ(request.checkpoint.identity, identity)
            || metadata.len() < request.checkpoint.decoder.raw_offset()
        {
            pending = Some(FirewallTransition::Generation);
        }
        read_opened(
            request,
            path,
            &mut file,
            &metadata,
            identity,
            &mut pending,
            &mut read,
        )
    })();
    match result {
        Ok(outcome) => outcome,
        Err(reason) => {
            let mut stream = request.checkpoint.stream.clone();
            let observed = stream
                .push_text("", &path.to_string_lossy())
                .observed_through_line;
            FirewallReadOutcome {
                checkpoint: None,
                pending,
                changed: false,
                batch: FirewallBatch {
                    entries: vec![],
                    replacements: vec![],
                    coverage: stream.coverage(),
                    observed_through_line: observed,
                    reset: false,
                    decoding: FirewallDecodingStatus {
                        kind: FirewallDecodingKind::Gap,
                        pending_bytes: request.checkpoint.decoder.pending_bytes() as u8,
                        reason: Some(reason),
                    },
                },
            }
        }
    }
}
fn read_opened(
    request: &FirewallReadRequest,
    path: &Path,
    file: &mut File,
    _metadata: &Metadata,
    identity: Option<FileIdentity>,
    pending: &mut Option<FirewallTransition>,
    read: &mut impl FnMut(&mut File, &mut Vec<u8>, Option<usize>) -> std::io::Result<()>,
) -> Result<FirewallReadOutcome, FirewallGapReason> {
    let path = path.to_string_lossy();
    let mut checkpoint = request.checkpoint.clone();
    if pending.is_none() {
        file.seek(SeekFrom::Start(checkpoint.decoder.raw_offset()))
            .map_err(|_| FirewallGapReason::ReadFailed)?;
        let mut bytes = Vec::with_capacity(FIREWALL_READ_CHUNK_BYTES);
        read(file, &mut bytes, Some(FIREWALL_READ_CHUNK_BYTES))
            .map_err(|_| FirewallGapReason::ReadFailed)?;
        match checkpoint.decoder.push(&bytes) {
            Ok(decoded) => {
                let delta = checkpoint.stream.push_text(&decoded.text, &path);
                let decoding = FirewallDecodingStatus::from_decoder(&checkpoint.decoder);
                return Ok(FirewallReadOutcome {
                    checkpoint: Some(checkpoint),
                    pending: None,
                    changed: !bytes.is_empty(),
                    batch: FirewallBatch {
                        entries: delta.entries,
                        replacements: delta.replacements,
                        coverage: delta.coverage,
                        observed_through_line: delta.observed_through_line,
                        reset: false,
                        decoding,
                    },
                });
            }
            Err(FirewallDecodeError::NeedsWindows1252) => {
                *pending = Some(FirewallTransition::Windows1252)
            }
            Err(FirewallDecodeError::InvalidExplicitEncoding) => {
                return Err(FirewallGapReason::InvalidEncoding)
            }
        }
    }
    let force_cp = *pending == Some(FirewallTransition::Windows1252);
    if force_cp && (identity.is_none() || identity != request.checkpoint.identity) {
        return Err(FirewallGapReason::GenerationUnverifiable);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| FirewallGapReason::ReadFailed)?;
    let mut bytes = Vec::new();
    read(file, &mut bytes, None).map_err(|_| FirewallGapReason::ReadFailed)?;
    let (result, snapshot) = snapshot_bytes(&bytes, &path, checkpoint.stream.next_id(), force_cp)
        .map_err(|_| FirewallGapReason::InvalidEncoding)?;
    let decoding = FirewallDecodingStatus::from_decoder(&snapshot.decoder);
    let checkpoint = FirewallCheckpoint {
        decoder: snapshot.decoder,
        stream: snapshot.stream,
        identity,
    };
    Ok(FirewallReadOutcome {
        checkpoint: Some(checkpoint),
        pending: None,
        changed: true,
        batch: FirewallBatch {
            entries: result.entries,
            replacements: vec![],
            coverage: result.firewall_coverage.unwrap_or_default(),
            observed_through_line: result.total_lines,
            reset: true,
            decoding,
        },
    })
}

/// Firewall workers never own the authoritative checkpoint. Each bounded read
/// starts from the current OpenFile and its result re-enters that same fence.
pub fn start_session(
    path: std::path::PathBuf,
    control: FirewallControlToken,
    app: tauri::AppHandle,
) -> Result<super::tail::TailSession, crate::error::AppError> {
    use std::sync::atomic::Ordering;
    use tauri::{Emitter, Manager};
    let (session, stopped) = super::tail::TailSession::controlled();
    std::thread::Builder::new()
        .name("firewall-tail".into())
        .spawn(move || {
            while !stopped.load(Ordering::Relaxed) {
                let state = app.state::<AppState>();
                let request = {
                    let Ok(files) = state.open_files.lock() else {
                        break;
                    };
                    let Some(owner) = files.get(&path).and_then(|f| f.firewall.as_ref()) else {
                        break;
                    };
                    if !owner.is_current(&control) {
                        break;
                    }
                    owner.request(&control)
                };
                let mut catch_up = false;
                if let Some(request) = request {
                    let outcome = read_candidate(&request, &path);
                    catch_up = outcome.checkpoint.as_ref().is_some_and(|checkpoint| {
                        checkpoint
                            .decoder
                            .raw_offset()
                            .saturating_sub(request.checkpoint.decoder.raw_offset())
                            >= FIREWALL_READ_CHUNK_BYTES as u64
                    });
                    let committed = commit_current(
                        &state,
                        &path,
                        &control,
                        request.revision,
                        outcome,
                        |batch| {
                            let payload = crate::commands::parsing::TailPayload::firewall(
                                path.to_string_lossy().into_owned(),
                                control.clone(),
                                batch,
                            );
                            if let Err(error) = app.emit("tail-new-entries", &payload) {
                                log::error!("Failed to emit firewall entries: {error}");
                            }
                        },
                    );
                    if committed.is_err() {
                        break;
                    }
                }
                if !catch_up {
                    std::thread::park_timeout(std::time::Duration::from_millis(500));
                }
            }
            // A stopped or superseded watcher is not EOF; no finalization occurs.
        })
        .map_err(|error| {
            crate::error::AppError::Internal(format!("Unable to start firewall watcher: {error}"))
        })?;
    Ok(session)
}
