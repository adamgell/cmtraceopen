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
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            open_files: Mutex::new(HashMap::new()),
            tail_sessions: Mutex::new(HashMap::new()),
        }
    }
}
