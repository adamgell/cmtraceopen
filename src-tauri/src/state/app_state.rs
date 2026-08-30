use std::collections::HashMap;
use std::path::PathBuf;
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
    #[cfg(feature = "event-log")]
    pub(crate) event_log_analysis_sessions: Mutex<EventLogAnalysisSessionRegistry>,
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
            event_log_analysis_sessions: Mutex::new(HashMap::new()),
        }
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

#[cfg(all(test, feature = "esp-diagnostics"))]
mod tests {
    use super::AppState;
    use crate::esp::session::EspSessionError;

    #[test]
    fn esp_manager_is_unavailable_until_application_setup_installs_it() {
        let state = AppState::default();
        assert!(matches!(
            state.esp_session_manager(),
            Err(EspSessionError::State { message })
                if message == "ESP diagnostics session manager is not initialized"
        ));
    }
}
