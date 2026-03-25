use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use crate::models::log_entry::LogEntry;
use crate::parser::ResolvedParser;
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
}

impl AppState {
    pub fn new(initial_file_paths: Vec<String>) -> Self {
        Self {
            open_files: Mutex::new(HashMap::new()),
            tail_sessions: Mutex::new(HashMap::new()),
            initial_file_paths: Mutex::new(initial_file_paths),
        }
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new(Vec::new())
    }
}
