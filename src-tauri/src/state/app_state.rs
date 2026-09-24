use std::collections::HashMap;
use std::path::PathBuf;
#[cfg(feature = "event-log")]
use std::sync::atomic::AtomicBool;
/// Named only by [`EventLogQueryCancel::in_flight`], which carries the same
/// predicate.
#[cfg(all(feature = "event-log", any(target_os = "windows", test)))]
use std::sync::atomic::AtomicUsize;
#[cfg(any(feature = "esp-diagnostics", feature = "event-log"))]
use std::sync::Arc;
use std::sync::Mutex;
#[cfg(feature = "event-log")]
use std::sync::RwLock;

#[cfg(feature = "esp-diagnostics")]
use crate::esp::session::{EspSessionError, EspSessionManager};
#[cfg(feature = "event-log")]
use crate::event_log::analysis_session::EventLogAnalysisSessionRegistry;
#[cfg(feature = "event-log")]
use crate::event_log::export_session::EventLogExportSessionRegistry;
#[cfg(feature = "event-log")]
use crate::event_log::provider_db::ProviderStore;
use crate::parser::ResolvedParser;
#[cfg(feature = "sccm-diagnostics")]
use crate::sccm::collector::SccmAdvancedCapabilityStore;
use crate::timeline::store::Timeline;
use crate::watcher::tail::{InitialLogicalRecord, TailSession};

#[allow(dead_code)]
/// Represents a currently open log file.
pub struct OpenFile {
    pub path: PathBuf,
    pub parser_selection: ResolvedParser,
    /// One-shot, bounded handoff from initial parsing to the first tail session.
    pub initial_logical_record: Option<InitialLogicalRecord>,
    /// Current byte offset for tail tracking
    pub byte_offset: u64,
}

/// Cancellation state for one logical live-channel load.
///
/// The frontend issues one `evtx_query_channels` invoke per channel, all carrying the same
/// request id. Every per-channel read must share one flag so a stop reaches all of them, and the
/// entry must stay registered until the last of them settles, so a stop cannot orphan workers by
/// landing between two settles.
#[cfg(feature = "event-log")]
pub(crate) struct EventLogQueryCancel {
    pub flag: AtomicBool,
    /// How many per-channel reads still hold this entry.
    ///
    /// Only the registering path counts: `acquire_query_cancel` and
    /// `release_query_cancel` live behind the same predicate, because only the
    /// Windows query path ever inserts an entry (every other platform answers
    /// `evtx_query_channels` with "only available on Windows" and so has nothing
    /// to hold an entry open). Gated with them rather than feature-gated alone,
    /// which left the field unread — and the `dead_code` lint fatal — on every
    /// non-Windows build.
    #[cfg(any(target_os = "windows", test))]
    pub in_flight: AtomicUsize,
}

/// Application-wide managed state.
pub struct AppState {
    pub open_files: Mutex<HashMap<PathBuf, OpenFile>>,
    /// Active tail-watching sessions keyed by file path
    pub tail_sessions: Mutex<HashMap<PathBuf, TailSession>>,
    /// File paths passed as CLI arguments at startup via OS file association.
    /// Consumed (cleared) on first retrieval so they are only processed once.
    pub initial_file_paths: Mutex<Vec<String>>,
    /// App-owned workspace selected by a validated startup argument.
    /// Consumed on first retrieval so the launch intent is applied once.
    pub initial_workspace: Mutex<Option<String>>,
    /// Opaque elevation restore ticket identifier supplied by the elevated
    /// relaunch. Consumed on first retrieval; the ticket it names is itself
    /// single-use, so a replayed identifier restores nothing.
    pub initial_elevation_restore: Mutex<Option<String>>,
    /// File paths a second launch handed over to the window that is running.
    ///
    /// A second launch is detected as soon as the app is running, which can be
    /// before the frontend is listening, so its paths wait here to be claimed
    /// rather than being announced into an empty room. Claiming takes the whole
    /// list, so a handed-over path is opened once.
    pub second_launch_paths: Mutex<Vec<String>>,
    /// Active unified multi-file timelines keyed by timeline id.
    pub timelines: Mutex<HashMap<String, Timeline>>,
    #[cfg(feature = "sccm-diagnostics")]
    pub sccm_advanced_capabilities: Mutex<SccmAdvancedCapabilityStore>,
    /// Installed during Tauri setup and taken during application shutdown so
    /// its worker and AppHandle-backed event sink cannot outlive the runtime.
    #[cfg(feature = "esp-diagnostics")]
    esp_session_manager: Mutex<Option<Arc<EspSessionManager>>>,
    /// Event maps loaded from disk, applied while rendering event rows.
    ///
    /// Behind an `Arc<RwLock<..>>` rather than a `Mutex` on the state itself so a command can take
    /// a cheap handle and carry it into `spawn_blocking`. Parsing a hundred thousand records is
    /// exactly the blocking work that must not run while the application state lock is held.
    #[cfg(feature = "event-log")]
    pub event_maps: Arc<RwLock<cmtraceopen_parser::eventmap::MapRegistry>>,
    /// Provider metadata databases, read to render an event's own description.
    ///
    /// Held the same way and for the same reason as [`event_maps`](Self::event_maps).
    #[cfg(feature = "event-log")]
    pub provider_store: Arc<RwLock<ProviderStore>>,
    /// Backend-owned, chunk-fed timeline/diagnosis snapshots keyed by opaque session id.
    ///
    /// Held the same way as [`event_log_export_sessions`](Self::event_log_export_sessions) so a
    /// blocking task can take the registry for itself: looking a session up runs the stale-session
    /// prune, which drops the buffers of whatever it evicts.
    #[cfg(feature = "event-log")]
    pub(crate) event_log_analysis_sessions: Arc<Mutex<EventLogAnalysisSessionRegistry>>,
    /// Backend-owned, bounded-transport GUI export sessions keyed by opaque session id.
    #[cfg(feature = "event-log")]
    pub(crate) event_log_export_sessions: Arc<Mutex<EventLogExportSessionRegistry>>,
    /// Cancellation flags for in-flight live channel queries, keyed by request id.
    ///
    /// A query registers its flag before the read starts and removes it when the read settles, so
    /// the registry holds at most one entry per in-flight request. Held behind an `Arc` like the
    /// session registries so a command can take a cheap handle into a blocking task and still
    /// clean its entry up afterwards.
    #[cfg(feature = "event-log")]
    pub(crate) event_log_query_cancels: Arc<Mutex<HashMap<String, Arc<EventLogQueryCancel>>>>,
}

impl AppState {
    pub fn new(initial_file_paths: Vec<String>) -> Self {
        Self::with_initial_launch(initial_file_paths, None, None)
    }

    pub fn with_initial_launch(
        initial_file_paths: Vec<String>,
        initial_workspace: Option<String>,
        initial_elevation_restore: Option<String>,
    ) -> Self {
        Self {
            open_files: Mutex::new(HashMap::new()),
            tail_sessions: Mutex::new(HashMap::new()),
            initial_file_paths: Mutex::new(initial_file_paths),
            initial_workspace: Mutex::new(initial_workspace),
            initial_elevation_restore: Mutex::new(initial_elevation_restore),
            second_launch_paths: Mutex::new(Vec::new()),
            timelines: Mutex::new(HashMap::new()),
            #[cfg(feature = "sccm-diagnostics")]
            sccm_advanced_capabilities: Mutex::new(SccmAdvancedCapabilityStore::default()),
            #[cfg(feature = "esp-diagnostics")]
            esp_session_manager: Mutex::new(None),
            #[cfg(feature = "event-log")]
            event_maps: Arc::new(RwLock::new(cmtraceopen_parser::eventmap::MapRegistry::new())),
            #[cfg(feature = "event-log")]
            provider_store: Arc::new(RwLock::new(ProviderStore::default())),
            #[cfg(feature = "event-log")]
            event_log_analysis_sessions: Arc::new(Mutex::new(HashMap::new())),
            #[cfg(feature = "event-log")]
            event_log_export_sessions: Arc::new(Mutex::new(HashMap::new())),
            #[cfg(feature = "event-log")]
            event_log_query_cancels: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Takes the file paths a second launch handed over, clearing them.
    ///
    /// The claim is the only way those paths leave the handoff, so a window woken
    /// about a launch it already claimed cannot open the same file twice.
    pub fn take_second_launch_paths(&self) -> Result<Vec<String>, crate::error::AppError> {
        let mut guard = self
            .second_launch_paths
            .lock()
            .map_err(|error| crate::error::AppError::State(error.to_string()))?;
        Ok(std::mem::take(&mut *guard))
    }

    #[cfg(feature = "esp-diagnostics")]
    pub fn install_esp_session_manager(
        &self,
        manager: Arc<EspSessionManager>,
    ) -> Result<(), EspSessionError> {
        let mut slot = self
            .esp_session_manager
            .lock()
            .map_err(|error| EspSessionError::State {
                message: error.to_string(),
            })?;
        if slot.is_some() {
            return Err(EspSessionError::State {
                message: "ESP diagnostics session manager is already initialized".to_string(),
            });
        }
        *slot = Some(manager);
        Ok(())
    }

    #[cfg(feature = "esp-diagnostics")]
    pub fn esp_session_manager(&self) -> Result<Arc<EspSessionManager>, EspSessionError> {
        self.esp_session_manager
            .lock()
            .map_err(|error| EspSessionError::State {
                message: error.to_string(),
            })?
            .clone()
            .ok_or_else(|| EspSessionError::State {
                message: "ESP diagnostics session manager is not initialized".to_string(),
            })
    }

    #[cfg(feature = "esp-diagnostics")]
    pub fn shutdown_esp_session_manager(&self) -> Result<(), EspSessionError> {
        let manager = self
            .esp_session_manager
            .lock()
            .map_err(|error| EspSessionError::State {
                message: error.to_string(),
            })?
            .take();
        if let Some(manager) = manager {
            manager.shutdown()?;
        }
        Ok(())
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::AppState;
    #[cfg(feature = "esp-diagnostics")]
    use crate::esp::session::EspSessionError;

    #[cfg(feature = "esp-diagnostics")]
    #[test]
    fn esp_manager_is_unavailable_until_application_setup_installs_it() {
        let state = AppState::default();
        assert!(matches!(
            state.esp_session_manager(),
            Err(EspSessionError::State { message })
                if message == "ESP diagnostics session manager is not initialized"
        ));
    }

    #[test]
    fn a_second_launch_hands_its_paths_over_once() {
        let state = AppState::default();
        state
            .second_launch_paths
            .lock()
            .expect("state lock")
            .push(r"C:\Logs\ime.log".to_string());

        assert_eq!(
            state.take_second_launch_paths().expect("claim"),
            [r"C:\Logs\ime.log"],
        );

        // A window woken twice claims once: the second claim finds nothing, so
        // the path cannot be opened again from the handoff.
        assert!(state.take_second_launch_paths().expect("claim").is_empty());
    }
}
