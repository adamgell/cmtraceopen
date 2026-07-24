use std::collections::HashMap;
use std::path::PathBuf;
#[cfg(feature = "esp-diagnostics")]
use std::sync::Arc;
use std::sync::Mutex;

#[cfg(feature = "esp-diagnostics")]
use crate::esp::session::{EspSessionError, EspSessionManager};
use crate::models::log_entry::LogEntry;
use crate::parser::ResolvedParser;
use crate::timeline::store::Timeline;
use crate::watcher::tail::TailSession;

#[allow(dead_code)]
/// Represents a currently open log file.
pub struct OpenFile {
    pub path: PathBuf,
    pub entries: Vec<LogEntry>,
    pub parser_selection: ResolvedParser,
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
    /// Active unified multi-file timelines keyed by timeline id.
    pub timelines: Mutex<HashMap<String, Timeline>>,
    /// Installed during Tauri setup and taken during application shutdown so
    /// its worker and AppHandle-backed event sink cannot outlive the runtime.
    #[cfg(feature = "esp-diagnostics")]
    esp_session_manager: Mutex<Option<Arc<EspSessionManager>>>,
}

impl AppState {
    pub fn new(initial_file_paths: Vec<String>) -> Self {
        Self::with_initial_launch(initial_file_paths, None)
    }

    pub fn with_initial_launch(
        initial_file_paths: Vec<String>,
        initial_workspace: Option<String>,
    ) -> Self {
        Self {
            open_files: Mutex::new(HashMap::new()),
            tail_sessions: Mutex::new(HashMap::new()),
            initial_file_paths: Mutex::new(initial_file_paths),
            initial_workspace: Mutex::new(initial_workspace),
            timelines: Mutex::new(HashMap::new()),
            #[cfg(feature = "esp-diagnostics")]
            esp_session_manager: Mutex::new(None),
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
