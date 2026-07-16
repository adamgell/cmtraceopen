//! Cancellable, single-owner ESP diagnostics live-session lifecycle.
//!
//! The control-plane mutex is used only to reserve or locate a session. Native
//! evidence I/O, projection, thread joins, and frontend emission always occur
//! after that mutex is released.

use std::collections::{BTreeMap, BTreeSet};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use chrono::{SecondsFormat, Utc};
use cmtraceopen_parser::esp::{
    EspArtifactCoverage, EspDiagnosticsReducer, EspDiagnosticsSnapshot, EspEvidenceRecord,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use super::discovery::{
    DiscoveredLogSource, DISCOVERY_INTERVAL, MAX_SESSION_DURATION, UPDATE_DEBOUNCE,
};

pub const ESP_SESSION_UPDATE_EVENT: &str = "esp-diagnostics-session-update";
const TAIL_POLL_INTERVAL: Duration = Duration::from_millis(50);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum EspSessionState {
    Starting,
    Live,
    Stopping,
    Stopped,
    Expired,
    Failed,
}

impl EspSessionState {
    fn is_terminal(&self) -> bool {
        matches!(self, Self::Stopped | Self::Expired | Self::Failed)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum EspUpdateReason {
    EvidenceChanged,
    DiscoveryRefresh,
    Stopped,
    Expired,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EspSessionEnvelope {
    pub session_id: String,
    pub request_id: String,
    pub sequence: u64,
    pub state: EspSessionState,
    pub snapshot: EspDiagnosticsSnapshot,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EspSessionUpdate {
    pub session_id: String,
    pub request_id: String,
    pub sequence: u64,
    pub state: EspSessionState,
    pub reason: EspUpdateReason,
    pub emitted_at_utc: String,
    pub snapshot: EspDiagnosticsSnapshot,
}

#[derive(Debug, Clone, Serialize, Error, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum EspSessionError {
    #[error("ESP diagnostics request ID must be a UUID")]
    InvalidRequestId,
    #[error("ESP diagnostics session ID must be a UUID")]
    InvalidSessionId,
    #[error("live ESP diagnostics are only supported on Windows")]
    UnsupportedPlatform,
    #[error("an ESP diagnostics session is already active: {existing_session_id}")]
    SessionConflict { existing_session_id: String },
    #[error("ESP diagnostics session was not found")]
    SessionNotFound,
    #[error("ESP diagnostics session state failed: {message}")]
    State { message: String },
    #[error("ESP diagnostics worker failed: {message}")]
    Worker { message: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EspClockReading {
    pub monotonic: Duration,
    pub utc: String,
}

pub trait EspSessionClock: Send + Sync {
    fn now(&self) -> EspClockReading;
    fn wait(&self, cancellation: &EspCancellation, duration: Duration);
}

#[derive(Debug)]
pub struct SystemEspSessionClock {
    started: Instant,
}

impl Default for SystemEspSessionClock {
    fn default() -> Self {
        Self {
            started: Instant::now(),
        }
    }
}

impl EspSessionClock for SystemEspSessionClock {
    fn now(&self) -> EspClockReading {
        EspClockReading {
            monotonic: self.started.elapsed(),
            utc: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        }
    }

    fn wait(&self, cancellation: &EspCancellation, duration: Duration) {
        cancellation.wait(duration);
    }
}

#[derive(Debug, Default)]
pub struct EspCancellation {
    cancelled: AtomicBool,
    wait_lock: Mutex<()>,
    changed: Condvar,
}

impl EspCancellation {
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        self.changed.notify_all();
    }

    fn wait(&self, duration: Duration) {
        if self.is_cancelled() {
            return;
        }
        if let Ok(guard) = self.wait_lock.lock() {
            let _ = self
                .changed
                .wait_timeout_while(guard, duration, |_| !self.is_cancelled());
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct EspProviderBatch {
    pub records: Vec<EspEvidenceRecord>,
    pub coverage: Vec<EspArtifactCoverage>,
}

pub trait EspEvidenceProvider: Send + Sync {
    fn collect(&self, observed_at_utc: &str) -> EspProviderBatch;
}

#[derive(Debug, Clone, Default)]
pub struct EspDiscoveryBatch {
    pub sources: Vec<DiscoveredLogSource>,
    pub coverage: Vec<EspArtifactCoverage>,
}

pub trait EspDiscoveryProvider: Send + Sync {
    fn discover(&self, observed_at_utc: &str) -> EspDiscoveryBatch;
}

#[derive(Debug, Clone, Default)]
pub struct EspTailEvidenceBatch {
    pub records: Vec<EspEvidenceRecord>,
    pub coverage: Vec<EspArtifactCoverage>,
    pub replace_artifact_ids: Vec<String>,
    pub changed: bool,
}

pub trait EspSessionTail: Send {
    fn reconcile(
        &mut self,
        sources: &[DiscoveredLogSource],
        observed_at_utc: &str,
    ) -> EspTailEvidenceBatch;
    fn poll(&mut self, observed_at_utc: &str) -> EspTailEvidenceBatch;
    fn stop(&mut self);
}

pub trait EspSessionTailFactory: Send + Sync {
    fn create(&self) -> Box<dyn EspSessionTail>;
}

pub trait EspSessionEventSink: Send + Sync {
    fn emit(&self, update: EspSessionUpdate) -> Result<(), String>;
}

#[derive(Clone)]
pub struct EspSessionDependencies {
    clock: Arc<dyn EspSessionClock>,
    registry: Arc<dyn EspEvidenceProvider>,
    event_logs: Arc<dyn EspEvidenceProvider>,
    system: Arc<dyn EspEvidenceProvider>,
    process: Arc<dyn EspEvidenceProvider>,
    discovery: Arc<dyn EspDiscoveryProvider>,
    tail_factory: Arc<dyn EspSessionTailFactory>,
    sink: Arc<dyn EspSessionEventSink>,
    live_supported: bool,
}

impl EspSessionDependencies {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        clock: Arc<dyn EspSessionClock>,
        registry: Arc<dyn EspEvidenceProvider>,
        event_logs: Arc<dyn EspEvidenceProvider>,
        system: Arc<dyn EspEvidenceProvider>,
        process: Arc<dyn EspEvidenceProvider>,
        discovery: Arc<dyn EspDiscoveryProvider>,
        tail_factory: Arc<dyn EspSessionTailFactory>,
        sink: Arc<dyn EspSessionEventSink>,
    ) -> Self {
        Self {
            clock,
            registry,
            event_logs,
            system,
            process,
            discovery,
            tail_factory,
            sink,
            live_supported: cfg!(target_os = "windows"),
        }
    }

    #[cfg(debug_assertions)]
    #[doc(hidden)]
    pub fn with_live_supported_for_tests(mut self, live_supported: bool) -> Self {
        self.live_supported = live_supported;
        self
    }
}

pub struct EspSessionManager {
    dependencies: EspSessionDependencies,
    control: Mutex<SessionControl>,
}

impl EspSessionManager {
    pub fn new(dependencies: EspSessionDependencies) -> Self {
        Self {
            dependencies,
            control: Mutex::new(SessionControl::default()),
        }
    }

    pub fn start(&self, request_id: &str) -> Result<EspSessionEnvelope, EspSessionError> {
        validate_request_id(request_id)?;
        if !self.dependencies.live_supported {
            return Err(EspSessionError::UnsupportedPlatform);
        }

        let session_id = Uuid::new_v4().to_string();
        self.reserve(&session_id, request_id)?;

        let reading = self.dependencies.clock.now();
        let engine = SessionEngine::initialize(&self.dependencies, &reading);
        let snapshot = engine.snapshot(&reading.utc);
        let active = Arc::new(ActiveSession {
            session_id: session_id.clone(),
            request_id: request_id.to_string(),
            published: Mutex::new(PublishedSession {
                sequence: 1,
                state: EspSessionState::Live,
                snapshot: snapshot.clone(),
            }),
            cancellation: Arc::new(EspCancellation::default()),
            activation: WorkerActivation::default(),
            worker: WorkerJoin::default(),
        });

        let worker_active = Arc::clone(&active);
        let failure_active = Arc::clone(&active);
        let worker_dependencies = self.dependencies.clone();
        let failure_dependencies = self.dependencies.clone();
        let worker = thread::Builder::new()
            .name(format!("esp-session-{session_id}"))
            .spawn(move || {
                failure_active.activation.wait(&failure_active.cancellation);
                if catch_unwind(AssertUnwindSafe(|| {
                    run_worker(engine, worker_active, worker_dependencies);
                }))
                .is_err()
                {
                    let reading = failure_dependencies.clock.now();
                    if let Ok(envelope) = failure_active.envelope() {
                        publish(
                            &failure_active,
                            &failure_dependencies,
                            EspSessionState::Failed,
                            EspUpdateReason::Failed,
                            envelope.snapshot,
                            &reading.utc,
                        );
                    }
                }
            })
            .map_err(|error| {
                self.clear_reservation(&session_id);
                worker_error(error)
            })?;
        if let Err(error) = active.worker.install(worker) {
            active.cancellation.cancel();
            active.activation.release();
            self.clear_reservation(&session_id);
            return Err(error);
        }

        let mut control = self.control.lock().map_err(state_error)?;
        if control
            .reservation
            .as_ref()
            .map_or(true, |reservation| reservation.session_id != session_id)
        {
            active.cancellation.cancel();
            active.activation.release();
            drop(control);
            join_active(&active)?;
            return Err(EspSessionError::State {
                message: "session reservation was lost before activation".to_string(),
            });
        }
        control.reservation = None;
        control.active = Some(Arc::clone(&active));
        drop(control);
        active.activation.release();

        Ok(EspSessionEnvelope {
            session_id,
            request_id: request_id.to_string(),
            sequence: 1,
            state: EspSessionState::Live,
            snapshot,
        })
    }

    pub fn get(&self, session_id: &str) -> Result<EspSessionEnvelope, EspSessionError> {
        validate_session_id(session_id)?;
        let active = {
            let control = self.control.lock().map_err(state_error)?;
            control
                .active
                .as_ref()
                .filter(|active| active.session_id == session_id)
                .cloned()
        }
        .ok_or(EspSessionError::SessionNotFound)?;
        active.envelope()
    }

    pub fn stop(&self, session_id: &str) -> Result<EspSessionEnvelope, EspSessionError> {
        validate_session_id(session_id)?;
        let active = {
            let control = self.control.lock().map_err(state_error)?;
            control
                .active
                .as_ref()
                .filter(|active| active.session_id == session_id)
                .cloned()
        }
        .ok_or(EspSessionError::SessionNotFound)?;

        active.cancellation.cancel();
        join_active(&active)?;
        let envelope = active.envelope()?;

        let mut control = self.control.lock().map_err(state_error)?;
        if control
            .active
            .as_ref()
            .is_some_and(|candidate| Arc::ptr_eq(candidate, &active))
        {
            control.active = None;
        }
        drop(control);
        Ok(envelope)
    }

    fn reserve(&self, session_id: &str, request_id: &str) -> Result<(), EspSessionError> {
        loop {
            let stale = {
                let mut control = self.control.lock().map_err(state_error)?;
                if let Some(reservation) = &control.reservation {
                    return Err(EspSessionError::SessionConflict {
                        existing_session_id: reservation.session_id.clone(),
                    });
                }
                if let Some(active) = &control.active {
                    if !active.is_terminal()? {
                        return Err(EspSessionError::SessionConflict {
                            existing_session_id: active.session_id.clone(),
                        });
                    }
                    control.active.take()
                } else {
                    control.reservation = Some(SessionReservation {
                        session_id: session_id.to_string(),
                        request_id: request_id.to_string(),
                    });
                    return Ok(());
                }
            };
            if let Some(stale) = stale {
                join_active(&stale)?;
            }
        }
    }

    fn clear_reservation(&self, session_id: &str) {
        if let Ok(mut control) = self.control.lock() {
            if control
                .reservation
                .as_ref()
                .is_some_and(|reservation| reservation.session_id == session_id)
            {
                control.reservation = None;
            }
        }
    }
}

impl Drop for EspSessionManager {
    fn drop(&mut self) {
        let active = self
            .control
            .get_mut()
            .ok()
            .and_then(|control| control.active.take());
        if let Some(active) = active {
            active.cancellation.cancel();
            let _ = join_active(&active);
        }
    }
}

#[derive(Default)]
struct SessionControl {
    reservation: Option<SessionReservation>,
    active: Option<Arc<ActiveSession>>,
}

struct SessionReservation {
    session_id: String,
    #[allow(dead_code)]
    request_id: String,
}

struct ActiveSession {
    session_id: String,
    request_id: String,
    published: Mutex<PublishedSession>,
    cancellation: Arc<EspCancellation>,
    activation: WorkerActivation,
    worker: WorkerJoin,
}

impl ActiveSession {
    fn envelope(&self) -> Result<EspSessionEnvelope, EspSessionError> {
        let published = self.published.lock().map_err(state_error)?;
        Ok(EspSessionEnvelope {
            session_id: self.session_id.clone(),
            request_id: self.request_id.clone(),
            sequence: published.sequence,
            state: published.state.clone(),
            snapshot: published.snapshot.clone(),
        })
    }

    fn is_terminal(&self) -> Result<bool, EspSessionError> {
        self.published
            .lock()
            .map(|published| published.state.is_terminal())
            .map_err(state_error)
    }
}

struct PublishedSession {
    sequence: u64,
    state: EspSessionState,
    snapshot: EspDiagnosticsSnapshot,
}

#[derive(Default)]
struct WorkerActivation {
    released: Mutex<bool>,
    changed: Condvar,
}

impl WorkerActivation {
    fn release(&self) {
        if let Ok(mut released) = self.released.lock() {
            *released = true;
            self.changed.notify_all();
        }
    }

    fn wait(&self, cancellation: &EspCancellation) {
        let Ok(mut released) = self.released.lock() else {
            return;
        };
        while !*released && !cancellation.is_cancelled() {
            match self.changed.wait(released) {
                Ok(next) => released = next,
                Err(_) => return,
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ProviderSlot {
    Registry,
    EventLogs,
    System,
    Process,
}

struct SessionEngine {
    started_at: Duration,
    next_refresh: Duration,
    last_emit: Duration,
    dirty: bool,
    pending_reason: EspUpdateReason,
    provider_records: BTreeMap<ProviderSlot, Vec<EspEvidenceRecord>>,
    discovery_coverage: Vec<EspArtifactCoverage>,
    tail_records: Vec<EspEvidenceRecord>,
    tail_coverage: Vec<EspArtifactCoverage>,
    sources: Vec<DiscoveredLogSource>,
    tail: Box<dyn EspSessionTail>,
    tail_stopped: bool,
}

impl SessionEngine {
    fn initialize(dependencies: &EspSessionDependencies, reading: &EspClockReading) -> Self {
        let provider_records = collect_provider_records(dependencies, &reading.utc);
        let discovery = dependencies.discovery.discover(&reading.utc);
        let mut tail = dependencies.tail_factory.create();
        let tail_batch = tail.reconcile(&discovery.sources, &reading.utc);
        let mut engine = Self {
            started_at: reading.monotonic,
            next_refresh: reading.monotonic + DISCOVERY_INTERVAL,
            last_emit: reading.monotonic,
            dirty: false,
            pending_reason: EspUpdateReason::EvidenceChanged,
            provider_records,
            discovery_coverage: discovery.coverage,
            tail_records: Vec::new(),
            tail_coverage: Vec::new(),
            sources: discovery.sources,
            tail,
            tail_stopped: false,
        };
        engine.apply_tail_batch(tail_batch);
        engine.dirty = false;
        engine
    }

    fn snapshot(&self, generated_at_utc: &str) -> EspDiagnosticsSnapshot {
        let mut reducer = EspDiagnosticsReducer::new(generated_at_utc.to_string());
        for records in self.provider_records.values() {
            reducer.ingest_all(records.iter().cloned());
        }
        reducer.ingest_all(
            self.discovery_coverage
                .iter()
                .cloned()
                .map(EspEvidenceRecord::Coverage),
        );
        reducer.ingest_all(self.tail_records.iter().cloned());
        reducer.ingest_all(
            self.tail_coverage
                .iter()
                .cloned()
                .map(EspEvidenceRecord::Coverage),
        );
        reducer.snapshot()
    }

    fn poll_tail(&mut self, observed_at_utc: &str) {
        let batch = self.tail.poll(observed_at_utc);
        if self.apply_tail_batch(batch) {
            self.pending_reason = EspUpdateReason::EvidenceChanged;
        }
    }

    fn refresh(&mut self, dependencies: &EspSessionDependencies, reading: &EspClockReading) {
        self.provider_records = collect_provider_records(dependencies, &reading.utc);
        let discovery = dependencies.discovery.discover(&reading.utc);
        self.discovery_coverage = discovery.coverage;
        self.sources = discovery.sources;
        let tail_batch = self.tail.reconcile(&self.sources, &reading.utc);
        self.apply_tail_batch(tail_batch);
        self.pending_reason = EspUpdateReason::DiscoveryRefresh;
        self.dirty = true;
        while self.next_refresh <= reading.monotonic {
            self.next_refresh += DISCOVERY_INTERVAL;
        }
    }

    fn apply_tail_batch(&mut self, batch: EspTailEvidenceBatch) -> bool {
        let EspTailEvidenceBatch {
            mut records,
            coverage,
            replace_artifact_ids,
            changed,
        } = batch;
        records.retain(is_local_record);
        if !changed && records.is_empty() && coverage.is_empty() && replace_artifact_ids.is_empty()
        {
            return false;
        }
        let replacements = replace_artifact_ids.into_iter().collect::<BTreeSet<_>>();
        if !replacements.is_empty() {
            self.tail_records.retain(|record| {
                record_artifact_id(record).map_or(true, |id| !replacements.contains(id))
            });
            self.tail_coverage
                .retain(|coverage| !replacements.contains(&coverage.artifact_id));
        }
        self.tail_records.extend(records);
        if !coverage.is_empty() {
            let updated_artifacts = coverage
                .iter()
                .map(|coverage| coverage.artifact_id.as_str())
                .collect::<BTreeSet<_>>();
            self.tail_coverage
                .retain(|current| !updated_artifacts.contains(current.artifact_id.as_str()));
            self.tail_coverage.extend(coverage);
        }
        self.dirty = true;
        true
    }

    fn stop_tail(&mut self) {
        if !self.tail_stopped {
            self.tail.stop();
            self.tail_stopped = true;
        }
    }
}

impl Drop for SessionEngine {
    fn drop(&mut self) {
        self.stop_tail();
    }
}

fn run_worker(
    mut engine: SessionEngine,
    active: Arc<ActiveSession>,
    dependencies: EspSessionDependencies,
) {
    loop {
        let reading = dependencies.clock.now();
        if reading.monotonic.saturating_sub(engine.started_at) >= MAX_SESSION_DURATION {
            engine.stop_tail();
            publish(
                &active,
                &dependencies,
                EspSessionState::Expired,
                EspUpdateReason::Expired,
                engine.snapshot(&reading.utc),
                &reading.utc,
            );
            return;
        }
        if active.cancellation.is_cancelled() {
            engine.stop_tail();
            publish(
                &active,
                &dependencies,
                EspSessionState::Stopped,
                EspUpdateReason::Stopped,
                engine.snapshot(&reading.utc),
                &reading.utc,
            );
            return;
        }

        dependencies
            .clock
            .wait(&active.cancellation, TAIL_POLL_INTERVAL);
        let reading = dependencies.clock.now();
        if active.cancellation.is_cancelled() {
            engine.stop_tail();
            publish(
                &active,
                &dependencies,
                EspSessionState::Stopped,
                EspUpdateReason::Stopped,
                engine.snapshot(&reading.utc),
                &reading.utc,
            );
            return;
        }
        if reading.monotonic.saturating_sub(engine.started_at) >= MAX_SESSION_DURATION {
            engine.stop_tail();
            publish(
                &active,
                &dependencies,
                EspSessionState::Expired,
                EspUpdateReason::Expired,
                engine.snapshot(&reading.utc),
                &reading.utc,
            );
            return;
        }

        engine.poll_tail(&reading.utc);
        if reading.monotonic >= engine.next_refresh {
            engine.refresh(&dependencies, &reading);
        }
        if engine.dirty && reading.monotonic.saturating_sub(engine.last_emit) >= UPDATE_DEBOUNCE {
            let snapshot = engine.snapshot(&reading.utc);
            let reason = engine.pending_reason.clone();
            engine.dirty = false;
            engine.last_emit = reading.monotonic;
            publish(
                &active,
                &dependencies,
                EspSessionState::Live,
                reason,
                snapshot,
                &reading.utc,
            );
        }
    }
}

fn publish(
    active: &ActiveSession,
    dependencies: &EspSessionDependencies,
    state: EspSessionState,
    reason: EspUpdateReason,
    snapshot: EspDiagnosticsSnapshot,
    emitted_at_utc: &str,
) {
    let update = {
        let Ok(mut published) = active.published.lock() else {
            return;
        };
        published.sequence = published.sequence.saturating_add(1);
        published.state = state.clone();
        published.snapshot = snapshot.clone();
        EspSessionUpdate {
            session_id: active.session_id.clone(),
            request_id: active.request_id.clone(),
            sequence: published.sequence,
            state,
            reason,
            emitted_at_utc: emitted_at_utc.to_string(),
            snapshot,
        }
    };
    if let Err(error) = dependencies.sink.emit(update) {
        log::warn!("failed to emit ESP session update: {error}");
    }
}

fn collect_provider_records(
    dependencies: &EspSessionDependencies,
    observed_at_utc: &str,
) -> BTreeMap<ProviderSlot, Vec<EspEvidenceRecord>> {
    [
        (ProviderSlot::Registry, dependencies.registry.as_ref()),
        (ProviderSlot::EventLogs, dependencies.event_logs.as_ref()),
        (ProviderSlot::System, dependencies.system.as_ref()),
        (ProviderSlot::Process, dependencies.process.as_ref()),
    ]
    .into_iter()
    .map(|(slot, provider)| {
        let mut batch = provider.collect(observed_at_utc);
        batch.records.retain(is_local_record);
        batch
            .records
            .extend(batch.coverage.into_iter().map(EspEvidenceRecord::Coverage));
        (slot, batch.records)
    })
    .collect()
}

fn is_local_record(record: &EspEvidenceRecord) -> bool {
    !matches!(record, EspEvidenceRecord::Graph(_))
}

fn record_artifact_id(record: &EspEvidenceRecord) -> Option<&str> {
    match record {
        EspEvidenceRecord::Registry(value) => Some(&value.context.provenance.source_artifact_id),
        EspEvidenceRecord::Json(value) => Some(&value.context.provenance.source_artifact_id),
        EspEvidenceRecord::EventLog(value) => Some(&value.context.provenance.source_artifact_id),
        EspEvidenceRecord::Ime(value) => Some(&value.context.provenance.source_artifact_id),
        EspEvidenceRecord::DeploymentLog(value) => {
            Some(&value.context.provenance.source_artifact_id)
        }
        EspEvidenceRecord::Process(value) => Some(&value.context.provenance.source_artifact_id),
        EspEvidenceRecord::System(value) => Some(&value.context.provenance.source_artifact_id),
        EspEvidenceRecord::DeliveryOptimization(value) => {
            Some(&value.context.provenance.source_artifact_id)
        }
        EspEvidenceRecord::Graph(value) => Some(&value.context.provenance.source_artifact_id),
        EspEvidenceRecord::Coverage(value) => Some(&value.artifact_id),
    }
}

fn join_active(active: &ActiveSession) -> Result<(), EspSessionError> {
    active.worker.join()
}

fn validate_request_id(request_id: &str) -> Result<(), EspSessionError> {
    Uuid::parse_str(request_id)
        .map(|_| ())
        .map_err(|_| EspSessionError::InvalidRequestId)
}

fn validate_session_id(session_id: &str) -> Result<(), EspSessionError> {
    Uuid::parse_str(session_id)
        .map(|_| ())
        .map_err(|_| EspSessionError::InvalidSessionId)
}

#[derive(Default)]
struct WorkerJoin {
    state: Mutex<WorkerJoinState>,
    changed: Condvar,
}

#[derive(Default)]
struct WorkerJoinState {
    handle: Option<JoinHandle<()>>,
    joining: bool,
    joined: bool,
}

impl WorkerJoin {
    fn install(&self, handle: JoinHandle<()>) -> Result<(), EspSessionError> {
        let mut state = self.state.lock().map_err(state_error)?;
        if state.handle.is_some() || state.joining || state.joined {
            return Err(EspSessionError::State {
                message: "worker handle was already installed".to_string(),
            });
        }
        state.handle = Some(handle);
        Ok(())
    }

    fn join(&self) -> Result<(), EspSessionError> {
        let handle = loop {
            let mut state = self.state.lock().map_err(state_error)?;
            if state.joined {
                return Ok(());
            }
            if state.joining {
                state = self.changed.wait(state).map_err(state_error)?;
                if state.joined {
                    return Ok(());
                }
                continue;
            }
            if let Some(handle) = state.handle.take() {
                state.joining = true;
                break handle;
            }
            state.joined = true;
            self.changed.notify_all();
            return Ok(());
        };

        let result = handle.join();
        let mut state = self.state.lock().map_err(state_error)?;
        state.joining = false;
        state.joined = true;
        self.changed.notify_all();
        result.map_err(|_| EspSessionError::Worker {
            message: "session worker panicked".to_string(),
        })
    }
}

fn state_error(error: impl std::fmt::Display) -> EspSessionError {
    EspSessionError::State {
        message: error.to_string(),
    }
}

fn worker_error(error: impl std::fmt::Display) -> EspSessionError {
    EspSessionError::Worker {
        message: error.to_string(),
    }
}
