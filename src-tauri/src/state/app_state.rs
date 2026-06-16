use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use serde::Serialize;
use uuid::Uuid;

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

#[derive(Debug, Clone)]
pub struct ParsedEntriesSession {
    pub entries: Vec<LogEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ParsedEntriesSessionMetadata {
    pub session_key: String,
    pub entry_count: usize,
}

/// Application-wide managed state.
pub struct AppState {
    pub open_files: Mutex<HashMap<PathBuf, OpenFile>>,
    /// Active tail-watching sessions keyed by file path
    pub tail_sessions: Mutex<HashMap<PathBuf, TailSession>>,
    /// File paths passed as CLI arguments at startup via OS file association.
    /// Consumed (cleared) on first retrieval so they are only processed once.
    pub initial_file_paths: Mutex<Vec<String>>,
    /// Active unified multi-file timelines keyed by timeline id.
    pub timelines: Mutex<HashMap<String, Timeline>>,
    /// Backend-owned parsed-entry sessions keyed by opaque session id.
    pub parsed_entry_sessions: Mutex<HashMap<String, ParsedEntriesSession>>,
}

impl AppState {
    pub fn new(initial_file_paths: Vec<String>) -> Self {
        Self {
            open_files: Mutex::new(HashMap::new()),
            tail_sessions: Mutex::new(HashMap::new()),
            initial_file_paths: Mutex::new(initial_file_paths),
            timelines: Mutex::new(HashMap::new()),
            parsed_entry_sessions: Mutex::new(HashMap::new()),
        }
    }

    pub fn register_parsed_entries_session(
        &self,
        entries: Vec<LogEntry>,
    ) -> Result<Option<ParsedEntriesSessionMetadata>, crate::error::AppError> {
        if entries.is_empty() {
            return Ok(None);
        }

        let session_key = Uuid::new_v4().to_string();
        let entry_count = entries.len();
        let session = ParsedEntriesSession { entries };

        let mut sessions = self
            .parsed_entry_sessions
            .lock()
            .map_err(|error| crate::error::AppError::State(error.to_string()))?;
        sessions.insert(session_key.clone(), session);

        Ok(Some(ParsedEntriesSessionMetadata {
            session_key,
            entry_count,
        }))
    }

    pub fn get_parsed_entries_session_entries(
        &self,
        session_key: &str,
    ) -> Result<Option<Vec<LogEntry>>, crate::error::AppError> {
        let sessions = self
            .parsed_entry_sessions
            .lock()
            .map_err(|error| crate::error::AppError::State(error.to_string()))?;

        Ok(sessions
            .get(session_key)
            .map(|session| session.entries.clone()))
    }

    pub fn with_parsed_entries_session<R, F>(
        &self,
        session_key: &str,
        f: F,
    ) -> Result<Option<R>, crate::error::AppError>
    where
        F: FnOnce(&[LogEntry]) -> R,
    {
        let sessions = self
            .parsed_entry_sessions
            .lock()
            .map_err(|error| crate::error::AppError::State(error.to_string()))?;

        Ok(sessions.get(session_key).map(|session| f(&session.entries)))
    }

    pub fn release_parsed_entries_session(
        &self,
        session_key: &str,
    ) -> Result<bool, crate::error::AppError> {
        let mut sessions = self
            .parsed_entry_sessions
            .lock()
            .map_err(|error| crate::error::AppError::State(error.to_string()))?;

        Ok(sessions.remove(session_key).is_some())
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use crate::models::log_entry::{LogFormat, Severity};

    use super::*;

    fn sample_entry(id: u64, message: &str) -> LogEntry {
        LogEntry {
            id,
            line_number: (id + 1) as u32,
            message: message.to_string(),
            component: None,
            timestamp: None,
            timestamp_display: None,
            severity: Severity::Info,
            thread: None,
            thread_display: None,
            source_file: None,
            format: LogFormat::Plain,
            file_path: "session-test.log".to_string(),
            timezone_offset: None,
            error_code_spans: Vec::new(),
            ip_address: None,
            host_name: None,
            mac_address: None,
            result_code: None,
            gle_code: None,
            setup_phase: None,
            operation_name: None,
            http_method: None,
            uri_stem: None,
            uri_query: None,
            status_code: None,
            sub_status: None,
            time_taken_ms: None,
            client_ip: None,
            server_ip: None,
            user_agent: None,
            server_port: None,
            username: None,
            win32_status: None,
            query_name: None,
            query_type: None,
            response_code: None,
            dns_direction: None,
            dns_protocol: None,
            source_ip: None,
            dns_flags: None,
            dns_event_id: None,
            zone_name: None,
            entry_kind: None,
            whatif: None,
            section_name: None,
            section_color: None,
            iteration: None,
            tags: None,
        }
    }

    #[test]
    fn register_and_release_parsed_entries_session_round_trips_entries() {
        let state = AppState::default();
        let entries = vec![sample_entry(0, "alpha"), sample_entry(1, "beta")];

        let metadata = state
            .register_parsed_entries_session(entries.clone())
            .expect("session should register")
            .expect("non-empty entries should produce metadata");

        assert_eq!(metadata.entry_count, 2);

        let stored_entries = state
            .get_parsed_entries_session_entries(&metadata.session_key)
            .expect("session lookup should succeed")
            .expect("session should exist");

        assert_eq!(stored_entries.len(), entries.len());
        assert_eq!(stored_entries[0].id, entries[0].id);
        assert_eq!(stored_entries[0].message, entries[0].message);
        assert_eq!(stored_entries[1].id, entries[1].id);
        assert_eq!(stored_entries[1].message, entries[1].message);

        assert!(state
            .release_parsed_entries_session(&metadata.session_key)
            .expect("release should succeed"));
        assert!(state
            .get_parsed_entries_session_entries(&metadata.session_key)
            .expect("lookup should succeed")
            .is_none());
    }

    #[test]
    fn release_parsed_entries_session_is_idempotent_for_unknown_or_duplicate_keys() {
        let state = AppState::default();
        let metadata = state
            .register_parsed_entries_session(vec![sample_entry(0, "alpha")])
            .expect("session should register")
            .expect("session metadata should exist");

        assert!(state
            .release_parsed_entries_session(&metadata.session_key)
            .expect("first release should succeed"));
        assert!(!state
            .release_parsed_entries_session(&metadata.session_key)
            .expect("second release should succeed"));
        assert!(!state
            .release_parsed_entries_session("missing-session-key")
            .expect("unknown release should succeed"));
    }

    #[test]
    fn register_parsed_entries_session_skips_empty_entry_sets() {
        let state = AppState::default();

        let metadata = state
            .register_parsed_entries_session(Vec::new())
            .expect("empty registration should succeed");

        assert!(metadata.is_none());
        assert!(state
            .parsed_entry_sessions
            .lock()
            .expect("lock should succeed")
            .is_empty());
    }
}
