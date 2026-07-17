//! Cancellable, single-owner ESP diagnostics live-session lifecycle.
//!
//! The control-plane mutex is used only to reserve or locate a session. Native
//! evidence I/O, projection, thread joins, and frontend emission always occur
//! after that mutex is released.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, TryLockError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use chrono::{DateTime, SecondsFormat, Utc};
use cmtraceopen_parser::esp::{
    EspArtifactCoverage, EspDiagnosticsReducer, EspDiagnosticsSnapshot,
    EspEvidenceIdentityAllocator, EspEvidenceIdentityRejectionCounts, EspEvidenceRecord,
    EspIdentifiedEvidenceRecord,
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
    #[serde(rename = "error")]
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
    InitialSnapshot,
    EvidenceChanged,
    DiscoveryRefresh,
    Stopped,
    Expired,
    #[serde(rename = "error")]
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

#[cfg(debug_assertions)]
#[doc(hidden)]
pub trait EspSessionLifecycleProbe: Send + Sync {
    fn before_cancellation_request(&self) {}

    fn before_cancellation_transition_lock(&self) {}

    fn cancellation_transition_waiting_for_publication(&self) {}

    fn after_cancellation_transition(&self, _state: &EspSessionState) {}

    fn after_publish_cancellation_sample(
        &self,
        _state: &EspSessionState,
        _reason: &EspUpdateReason,
        _cancellation: &EspCancellation,
    ) {
    }

    fn before_update_delivery(&self, _update: &EspSessionUpdate) {}
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
    #[cfg(debug_assertions)]
    lifecycle_probe: Option<Arc<dyn EspSessionLifecycleProbe>>,
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
            #[cfg(debug_assertions)]
            lifecycle_probe: None,
        }
    }

    #[cfg(debug_assertions)]
    #[doc(hidden)]
    pub fn with_live_supported_for_tests(mut self, live_supported: bool) -> Self {
        self.live_supported = live_supported;
        self
    }

    #[cfg(debug_assertions)]
    #[doc(hidden)]
    pub fn with_lifecycle_probe_for_tests(
        mut self,
        lifecycle_probe: Arc<dyn EspSessionLifecycleProbe>,
    ) -> Self {
        self.lifecycle_probe = Some(lifecycle_probe);
        self
    }
}

pub struct EspSessionManager {
    dependencies: EspSessionDependencies,
    start_shutdown_gate: Mutex<()>,
    control: Mutex<SessionControl>,
}

impl EspSessionManager {
    pub fn new(dependencies: EspSessionDependencies) -> Self {
        Self {
            dependencies,
            start_shutdown_gate: Mutex::new(()),
            control: Mutex::new(SessionControl::default()),
        }
    }

    pub fn start(&self, request_id: &str) -> Result<EspSessionEnvelope, EspSessionError> {
        validate_request_id(request_id)?;
        if !self.dependencies.live_supported {
            return Err(EspSessionError::UnsupportedPlatform);
        }
        let _start_guard = self.start_shutdown_gate.lock().map_err(state_error)?;

        let session_id = Uuid::new_v4().to_string();
        self.reserve(&session_id, request_id)?;

        let reading = self.dependencies.clock.now();
        let starting_snapshot = EspDiagnosticsReducer::new(reading.utc).snapshot();
        let active = Arc::new(ActiveSession {
            session_id: session_id.clone(),
            request_id: request_id.to_string(),
            published: Mutex::new(PublishedSession {
                sequence: 0,
                state: EspSessionState::Starting,
                snapshot: starting_snapshot.clone(),
            }),
            publication_gate: Mutex::new(()),
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
                    run_worker(worker_active, worker_dependencies);
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
        let shutting_down = control.shutting_down;
        if shutting_down
            || control
                .reservation
                .as_ref()
                .map_or(true, |reservation| reservation.session_id != session_id)
        {
            active.cancellation.cancel();
            active.activation.release();
            drop(control);
            join_active(&active)?;
            return if shutting_down {
                Err(shutting_down_error())
            } else {
                Err(EspSessionError::State {
                    message: "session reservation was lost before activation".to_string(),
                })
            };
        }
        control.reservation = None;
        control.active = Some(Arc::clone(&active));
        drop(control);
        active.activation.release();

        Ok(EspSessionEnvelope {
            session_id,
            request_id: request_id.to_string(),
            sequence: 0,
            state: EspSessionState::Starting,
            snapshot: starting_snapshot,
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

        active.cancel_and_mark_stopping(&self.dependencies)?;
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

    /// Cancels and joins any active worker without requiring a caller-owned
    /// session ID. Application shutdown uses this path before the runtime and
    /// event sink are torn down.
    pub fn shutdown(&self) -> Result<(), EspSessionError> {
        let active = {
            let _shutdown_guard = self.start_shutdown_gate.lock().map_err(state_error)?;
            let mut control = self.control.lock().map_err(state_error)?;
            control.shutting_down = true;
            control.reservation = None;
            control.active.clone()
        };
        if let Some(active) = &active {
            active.cancel_and_mark_stopping(&self.dependencies)?;
            active.activation.release();
            join_active(active)?;
        }
        let mut control = self.control.lock().map_err(state_error)?;
        if let Some(active) = active {
            if control
                .active
                .as_ref()
                .is_some_and(|candidate| Arc::ptr_eq(candidate, &active))
            {
                control.active = None;
            }
        }
        Ok(())
    }

    fn reserve(&self, session_id: &str, request_id: &str) -> Result<(), EspSessionError> {
        loop {
            let stale = {
                let mut control = self.control.lock().map_err(state_error)?;
                if control.shutting_down {
                    return Err(shutting_down_error());
                }
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
            active.activation.release();
            let _ = join_active(&active);
        }
    }
}

#[derive(Default)]
struct SessionControl {
    reservation: Option<SessionReservation>,
    active: Option<Arc<ActiveSession>>,
    shutting_down: bool,
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
    publication_gate: Mutex<()>,
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

    fn cancel_and_mark_stopping(
        &self,
        _dependencies: &EspSessionDependencies,
    ) -> Result<(), EspSessionError> {
        #[cfg(debug_assertions)]
        if let Some(probe) = &_dependencies.lifecycle_probe {
            probe.before_cancellation_request();
            probe.before_cancellation_transition_lock();
        }
        let _publication_guard = match self.publication_gate.try_lock() {
            Ok(guard) => guard,
            Err(TryLockError::WouldBlock) => {
                #[cfg(debug_assertions)]
                if let Some(probe) = &_dependencies.lifecycle_probe {
                    probe.cancellation_transition_waiting_for_publication();
                }
                self.publication_gate
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
            }
            Err(TryLockError::Poisoned(error)) => error.into_inner(),
        };
        let mut published = self.published.lock().map_err(state_error)?;
        self.cancellation.cancel();
        if matches!(
            published.state,
            EspSessionState::Starting | EspSessionState::Live
        ) {
            published.state = EspSessionState::Stopping;
        }
        #[cfg(debug_assertions)]
        let state = published.state.clone();
        drop(published);
        #[cfg(debug_assertions)]
        if let Some(probe) = &_dependencies.lifecycle_probe {
            probe.after_cancellation_transition(&state);
        }
        Ok(())
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
    utc_high_water_mark: String,
    dirty: bool,
    pending_reason: EspUpdateReason,
    provider_records: BTreeMap<ProviderSlot, Vec<EspIdentifiedEvidenceRecord>>,
    discovery_coverage: Vec<EspIdentifiedEvidenceRecord>,
    tail_records: Vec<EspIdentifiedEvidenceRecord>,
    tail_coverage: Vec<EspIdentifiedEvidenceRecord>,
    identity_allocator: EspEvidenceIdentityAllocator,
    identity_rejections: EspEvidenceIdentityRejectionCounts,
    sources: Vec<DiscoveredLogSource>,
    tail: Box<dyn EspSessionTail>,
    tail_stopped: bool,
}

impl SessionEngine {
    fn initialize(
        dependencies: &EspSessionDependencies,
        reading: &EspClockReading,
        cancellation: &EspCancellation,
    ) -> Option<Self> {
        let provider_records = collect_provider_records(dependencies, &reading.utc, cancellation)?;
        if cancellation.is_cancelled() {
            return None;
        }
        let discovery = dependencies.discovery.discover(&reading.utc);
        if cancellation.is_cancelled() {
            return None;
        }
        let mut tail = dependencies.tail_factory.create();
        let tail_batch = tail.reconcile(&discovery.sources, &reading.utc);
        if cancellation.is_cancelled() {
            tail.stop();
            return None;
        }
        let mut identity_allocator = EspEvidenceIdentityAllocator::new();
        let mut identity_rejections = EspEvidenceIdentityRejectionCounts::default();
        let provider_records = provider_records
            .into_iter()
            .map(|(slot, records)| {
                (
                    slot,
                    reconcile_identified_records(
                        Vec::new(),
                        records,
                        &mut identity_allocator,
                        &mut identity_rejections,
                    ),
                )
            })
            .collect();
        let discovery_coverage = reconcile_identified_records(
            Vec::new(),
            discovery
                .coverage
                .into_iter()
                .map(EspEvidenceRecord::Coverage)
                .collect(),
            &mut identity_allocator,
            &mut identity_rejections,
        );
        let mut engine = Self {
            started_at: reading.monotonic,
            next_refresh: reading.monotonic + DISCOVERY_INTERVAL,
            last_emit: reading.monotonic,
            utc_high_water_mark: reading.utc.clone(),
            dirty: false,
            pending_reason: EspUpdateReason::EvidenceChanged,
            provider_records,
            discovery_coverage,
            tail_records: Vec::new(),
            tail_coverage: Vec::new(),
            identity_allocator,
            identity_rejections,
            sources: discovery.sources,
            tail,
            tail_stopped: false,
        };
        engine.apply_tail_batch(tail_batch);
        engine.dirty = false;
        Some(engine)
    }

    fn snapshot(&mut self, requested_generated_at_utc: &str) -> EspDiagnosticsSnapshot {
        let generated_at_utc = coherent_utc_timestamp(
            requested_generated_at_utc,
            std::iter::once(self.utc_high_water_mark.as_str()).chain(
                self.retained_records()
                    .filter_map(|record| record.record().observed_at_utc()),
            ),
        );
        self.utc_high_water_mark.clone_from(&generated_at_utc);
        let mut reducer = EspDiagnosticsReducer::new(generated_at_utc.to_string());
        for records in self.provider_records.values() {
            reducer.ingest_identified_all(records.iter().cloned());
        }
        reducer.ingest_identified_all(self.discovery_coverage.iter().cloned());
        reducer.ingest_identified_all(self.tail_records.iter().cloned());
        reducer.ingest_identified_all(self.tail_coverage.iter().cloned());
        reducer.merge_identity_rejections(self.identity_rejections);
        reducer.snapshot()
    }

    fn retained_records(&self) -> impl Iterator<Item = &EspIdentifiedEvidenceRecord> {
        self.provider_records
            .values()
            .flat_map(|records| records.iter())
            .chain(self.discovery_coverage.iter())
            .chain(self.tail_records.iter())
            .chain(self.tail_coverage.iter())
    }

    fn advance_utc_high_water_mark(&mut self, completed_at_utc: &str) {
        self.utc_high_water_mark = coherent_utc_timestamp(
            completed_at_utc,
            std::iter::once(self.utc_high_water_mark.as_str()),
        );
    }

    fn poll_tail(&mut self, observed_at_utc: &str) -> bool {
        let batch = self.tail.poll(observed_at_utc);
        let changed = self.apply_tail_batch(batch);
        if changed {
            self.pending_reason = EspUpdateReason::EvidenceChanged;
        }
        changed
    }

    fn refresh(
        &mut self,
        dependencies: &EspSessionDependencies,
        reading: &EspClockReading,
        cancellation: &EspCancellation,
    ) -> bool {
        let Some(provider_records) =
            collect_provider_records(dependencies, &reading.utc, cancellation)
        else {
            return false;
        };
        if cancellation.is_cancelled() {
            return false;
        }
        let mut previous = std::mem::take(&mut self.provider_records);
        self.provider_records = provider_records
            .into_iter()
            .map(|(slot, records)| {
                (
                    slot,
                    reconcile_identified_records(
                        previous.remove(&slot).unwrap_or_default(),
                        records,
                        &mut self.identity_allocator,
                        &mut self.identity_rejections,
                    ),
                )
            })
            .collect();
        let discovery = dependencies.discovery.discover(&reading.utc);
        if cancellation.is_cancelled() {
            return false;
        }
        self.discovery_coverage = reconcile_identified_records(
            std::mem::take(&mut self.discovery_coverage),
            discovery
                .coverage
                .into_iter()
                .map(EspEvidenceRecord::Coverage)
                .collect(),
            &mut self.identity_allocator,
            &mut self.identity_rejections,
        );
        self.sources = discovery.sources;
        let tail_batch = self.tail.reconcile(&self.sources, &reading.utc);
        if cancellation.is_cancelled() {
            return false;
        }
        self.apply_tail_batch(tail_batch);
        self.pending_reason = EspUpdateReason::DiscoveryRefresh;
        self.dirty = true;
        while self.next_refresh <= reading.monotonic {
            self.next_refresh += DISCOVERY_INTERVAL;
        }
        true
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
                record_artifact_id(record.record()).map_or(true, |id| !replacements.contains(id))
            });
            self.tail_coverage.retain(|record| {
                coverage_artifact_id(record.record()).map_or(true, |id| !replacements.contains(id))
            });
        }
        self.tail_records.extend(reconcile_identified_records(
            Vec::new(),
            records,
            &mut self.identity_allocator,
            &mut self.identity_rejections,
        ));
        if !coverage.is_empty() {
            let updated_artifacts = coverage
                .iter()
                .map(|coverage| coverage.artifact_id.as_str())
                .collect::<BTreeSet<_>>();
            let previous = std::mem::take(&mut self.tail_coverage);
            let (updated_previous, mut unchanged): (Vec<_>, Vec<_>) =
                previous.into_iter().partition(|current| {
                    coverage_artifact_id(current.record())
                        .is_some_and(|id| updated_artifacts.contains(id))
                });
            unchanged.extend(reconcile_identified_records(
                updated_previous,
                coverage
                    .into_iter()
                    .map(EspEvidenceRecord::Coverage)
                    .collect(),
                &mut self.identity_allocator,
                &mut self.identity_rejections,
            ));
            self.tail_coverage = unchanged;
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

fn coherent_utc_timestamp<'a>(
    requested_utc: &str,
    observed_at_values: impl IntoIterator<Item = &'a str>,
) -> String {
    let mut latest = DateTime::parse_from_rfc3339(requested_utc)
        .ok()
        .map(|value| value.with_timezone(&Utc));
    let mut coherent = requested_utc.to_string();
    for observed_at_utc in observed_at_values {
        let Some(observed) = DateTime::parse_from_rfc3339(observed_at_utc)
            .ok()
            .map(|value| value.with_timezone(&Utc))
        else {
            continue;
        };
        if latest.map_or(true, |current| observed > current) {
            coherent = observed.to_rfc3339_opts(SecondsFormat::AutoSi, true);
            latest = Some(observed);
        }
    }
    coherent
}

fn run_worker(active: Arc<ActiveSession>, dependencies: EspSessionDependencies) {
    if active.cancellation.is_cancelled() {
        publish_current_snapshot(
            &active,
            &dependencies,
            EspSessionState::Stopped,
            EspUpdateReason::Stopped,
        );
        return;
    }

    let reading = dependencies.clock.now();
    let Some(mut engine) = SessionEngine::initialize(&dependencies, &reading, &active.cancellation)
    else {
        publish_current_snapshot(
            &active,
            &dependencies,
            EspSessionState::Stopped,
            EspUpdateReason::Stopped,
        );
        return;
    };
    let collection_completed_at_utc = dependencies.clock.now().utc;
    engine.advance_utc_high_water_mark(&collection_completed_at_utc);
    let initial_snapshot = engine.snapshot(&collection_completed_at_utc);
    if active.cancellation.is_cancelled() {
        engine.stop_tail();
        publish(
            &active,
            &dependencies,
            EspSessionState::Stopped,
            EspUpdateReason::Stopped,
            initial_snapshot,
            &collection_completed_at_utc,
        );
        return;
    }
    publish(
        &active,
        &dependencies,
        EspSessionState::Live,
        EspUpdateReason::InitialSnapshot,
        initial_snapshot,
        &collection_completed_at_utc,
    );

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

        let tail_changed = engine.poll_tail(&reading.utc);
        let refresh_due = reading.monotonic >= engine.next_refresh;
        let refreshed =
            refresh_due && engine.refresh(&dependencies, &reading, &active.cancellation);
        if active.cancellation.is_cancelled() {
            let stopped_at = dependencies.clock.now();
            engine.stop_tail();
            publish(
                &active,
                &dependencies,
                EspSessionState::Stopped,
                EspUpdateReason::Stopped,
                engine.snapshot(&stopped_at.utc),
                &stopped_at.utc,
            );
            return;
        }
        if tail_changed || refreshed {
            let collection_completed_at_utc = dependencies.clock.now().utc;
            engine.advance_utc_high_water_mark(&collection_completed_at_utc);
        }
        if engine.dirty && reading.monotonic.saturating_sub(engine.last_emit) >= UPDATE_DEBOUNCE {
            let publication_utc = dependencies.clock.now().utc;
            let snapshot = engine.snapshot(&publication_utc);
            let reason = engine.pending_reason.clone();
            engine.dirty = false;
            engine.last_emit = reading.monotonic;
            publish(
                &active,
                &dependencies,
                EspSessionState::Live,
                reason,
                snapshot,
                &publication_utc,
            );
        }
    }
}

fn publish_current_snapshot(
    active: &ActiveSession,
    dependencies: &EspSessionDependencies,
    state: EspSessionState,
    reason: EspUpdateReason,
) {
    let reading = dependencies.clock.now();
    let Ok(envelope) = active.envelope() else {
        return;
    };
    publish(
        active,
        dependencies,
        state,
        reason,
        envelope.snapshot,
        &reading.utc,
    );
}

fn publish(
    active: &ActiveSession,
    dependencies: &EspSessionDependencies,
    state: EspSessionState,
    reason: EspUpdateReason,
    snapshot: EspDiagnosticsSnapshot,
    emitted_at_utc: &str,
) {
    let _publication_guard = active
        .publication_gate
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let emitted_at_utc = coherent_utc_timestamp(
        emitted_at_utc,
        std::iter::once(snapshot.generated_at_utc.as_str()),
    );
    let update = {
        let Ok(mut published) = active.published.lock() else {
            return;
        };
        if published.state.is_terminal() {
            return;
        }
        let cancellation_wins = active.cancellation.is_cancelled()
            || matches!(published.state, EspSessionState::Stopping);
        #[cfg(debug_assertions)]
        if let Some(probe) = &dependencies.lifecycle_probe {
            probe.after_publish_cancellation_sample(&state, &reason, &active.cancellation);
        }
        let (state, reason) = if cancellation_wins && state != EspSessionState::Stopped {
            (EspSessionState::Stopped, EspUpdateReason::Stopped)
        } else {
            (state, reason)
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
            emitted_at_utc,
            snapshot,
        }
    };
    #[cfg(debug_assertions)]
    if let Some(probe) = &dependencies.lifecycle_probe {
        probe.before_update_delivery(&update);
    }
    if let Err(error) = dependencies.sink.emit(update) {
        log::warn!("failed to emit ESP session update: {error}");
    }
}

fn collect_provider_records(
    dependencies: &EspSessionDependencies,
    observed_at_utc: &str,
    cancellation: &EspCancellation,
) -> Option<BTreeMap<ProviderSlot, Vec<EspEvidenceRecord>>> {
    let providers = [
        (ProviderSlot::Registry, dependencies.registry.as_ref()),
        (ProviderSlot::EventLogs, dependencies.event_logs.as_ref()),
        (ProviderSlot::System, dependencies.system.as_ref()),
        (ProviderSlot::Process, dependencies.process.as_ref()),
    ];
    let mut records = BTreeMap::new();
    for (slot, provider) in providers {
        if cancellation.is_cancelled() {
            return None;
        }
        let mut batch = provider.collect(observed_at_utc);
        if cancellation.is_cancelled() {
            return None;
        }
        batch.records.retain(is_local_record);
        batch
            .records
            .extend(batch.coverage.into_iter().map(EspEvidenceRecord::Coverage));
        records.insert(slot, batch.records);
    }
    Some(records)
}

fn reconcile_identified_records(
    previous: Vec<EspIdentifiedEvidenceRecord>,
    records: Vec<EspEvidenceRecord>,
    allocator: &mut EspEvidenceIdentityAllocator,
    identity_rejections: &mut EspEvidenceIdentityRejectionCounts,
) -> Vec<EspIdentifiedEvidenceRecord> {
    let mut previous_occurrences = BTreeMap::<(String, String), VecDeque<usize>>::new();
    for identified in previous {
        previous_occurrences
            .entry(record_identity_key(identified.record()))
            .or_default()
            .push_back(identified.occurrence_ordinal());
    }

    records
        .into_iter()
        .filter_map(|record| {
            let key = record_identity_key(&record);
            if let Some(occurrence) = previous_occurrences
                .get_mut(&key)
                .and_then(VecDeque::pop_front)
            {
                return Some(EspIdentifiedEvidenceRecord::with_occurrence(
                    record, occurrence,
                ));
            }
            match allocator.try_identify(record) {
                Ok(identified) => Some(identified),
                Err(error) => {
                    identity_rejections.record(error);
                    None
                }
            }
        })
        .collect()
}

fn record_identity_key(record: &EspEvidenceRecord) -> (String, String) {
    match record {
        EspEvidenceRecord::Registry(value) => observation_identity_key(&value.context),
        EspEvidenceRecord::Json(value) => observation_identity_key(&value.context),
        EspEvidenceRecord::EventLog(value) => observation_identity_key(&value.context),
        EspEvidenceRecord::Ime(value) => observation_identity_key(&value.context),
        EspEvidenceRecord::DeploymentLog(value) => observation_identity_key(&value.context),
        EspEvidenceRecord::Process(value) => observation_identity_key(&value.context),
        EspEvidenceRecord::System(value) => observation_identity_key(&value.context),
        EspEvidenceRecord::DeliveryOptimizationSummary(_) => (
            "delivery-optimization.summary".to_string(),
            "delivery-optimization.summary".to_string(),
        ),
        EspEvidenceRecord::DeliveryOptimization(value) => observation_identity_key(&value.context),
        EspEvidenceRecord::Graph(value) => observation_identity_key(&value.context),
        EspEvidenceRecord::Coverage(value) => value
            .evidence
            .first()
            .map(evidence_identity_key)
            .unwrap_or_else(|| (value.artifact_id.clone(), value.artifact_id.clone())),
    }
}

fn observation_identity_key(
    context: &cmtraceopen_parser::esp::EspObservationContext,
) -> (String, String) {
    (
        context.provenance.source_artifact_id.clone(),
        context.evidence_ref.evidence_id.clone(),
    )
}

fn evidence_identity_key(evidence: &cmtraceopen_parser::esp::EspEvidenceRef) -> (String, String) {
    (
        evidence.source_artifact_id.clone(),
        evidence.evidence_id.clone(),
    )
}

fn coverage_artifact_id(record: &EspEvidenceRecord) -> Option<&str> {
    let EspEvidenceRecord::Coverage(coverage) = record else {
        return None;
    };
    Some(&coverage.artifact_id)
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
        EspEvidenceRecord::DeliveryOptimizationSummary(_) => None,
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

fn shutting_down_error() -> EspSessionError {
    EspSessionError::State {
        message: "ESP diagnostics session manager is shutting down".to_string(),
    }
}

fn worker_error(error: impl std::fmt::Display) -> EspSessionError {
    EspSessionError::Worker {
        message: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::{coherent_utc_timestamp, EspSessionState, EspUpdateReason};

    #[test]
    fn failed_session_wire_values_match_the_frontend_error_contract() {
        assert_eq!(
            serde_json::to_value(EspSessionState::Failed).expect("serialize failed state"),
            "error"
        );
        assert_eq!(
            serde_json::to_value(EspUpdateReason::Failed).expect("serialize failed reason"),
            "error"
        );
    }

    #[test]
    fn coherent_timestamp_compares_offsets_and_ignores_malformed_evidence_times() {
        let requested = "2026-07-16T02:30:05-04:00";
        assert_eq!(
            coherent_utc_timestamp(requested, ["not-a-timestamp", "2026-07-16T08:30:04+02:00"]),
            requested
        );
        assert_eq!(
            coherent_utc_timestamp(
                requested,
                ["not-a-timestamp", "2026-07-16T08:30:06.123456789+02:00"]
            ),
            "2026-07-16T06:30:06.123456789Z"
        );
    }
}
