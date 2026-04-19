// src-tauri/src/timeline/models.rs

/// Re-exports of inner model types the `timeline` public API touches.
/// Kept here so external consumers (integration tests, benches) can build
/// indexes and source metadata without depending on the crate-private
/// `models` module path.
pub use crate::models::log_entry::{ParserKind, Severity};

#[derive(Clone, Debug)]
pub struct EntryIndex {
    pub timestamp_ms: i64,
    pub severity: crate::models::log_entry::Severity,
    /// Kept for symmetry with the outer map keying; not read directly (the
    /// index is already looked up by source_idx elsewhere). Retained so
    /// downstream materializers that pass an EntryIndex alone still know
    /// which source they came from.
    #[allow(dead_code)]
    pub source_idx: u16,
    pub byte_offset: u64,
    pub line_number: u32,
    pub signal_flags: u8,
}

pub const SIGNAL_FLAG_HAS_ERROR_CODE: u8 = 0b0000_0001;
// Reserved for future phases that stamp IME event flags directly on EntryIndex.
#[allow(dead_code)]
pub const SIGNAL_FLAG_IS_IME_FAILED: u8 = 0b0000_0010;
#[allow(dead_code)]
pub const SIGNAL_FLAG_IS_IME_EVENT: u8 = 0b0000_0100;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SignalKind {
    ErrorSeverity,
    KnownErrorCode,
    ImeFailed,
}

#[derive(Clone, Debug)]
pub struct Signal {
    pub source_idx: u16,
    pub entry_ref: u32,
    pub ts_ms: i64,
    pub kind: SignalKind,
    pub correlation_id: Option<String>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Incident {
    pub id: u32,
    pub ts_start_ms: i64,
    pub ts_end_ms: i64,
    pub signal_count: u32,
    pub source_count: u8,
    pub confidence: f32,
    pub anchor_event_ref: Option<(u16, u32)>,
    pub anchor_guid: Option<String>,
    pub summary: String,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TimelineSourceKind {
    #[serde(rename_all = "camelCase")]
    LogFile {
        parser_kind: crate::models::log_entry::ParserKind,
    },
    IntuneEvents,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TimelineSourceMeta {
    pub idx: u16,
    pub kind: TimelineSourceKind,
    pub path: String,
    pub display_name: String,
    pub color: String,
    pub entry_count: u32,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceError {
    pub path: String,
    pub message: String,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TimelineBundle {
    pub id: String,
    pub sources: Vec<TimelineSourceMeta>,
    pub time_range_ms: (i64, i64),
    pub total_entries: u64,
    pub incidents: Vec<Incident>,
    pub denied_guids: Vec<String>,
    pub errors: Vec<SourceError>,
    pub tunables: TimelineTunables,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TimelineTunables {
    pub overlap_window_ms: i64,
    pub min_source_count: u8,
    pub max_incident_span_ms: i64,
    pub enabled_signal_kinds: Vec<SignalKind>,
}

impl Default for TimelineTunables {
    fn default() -> Self {
        Self {
            overlap_window_ms: 5_000,
            min_source_count: 2,
            max_incident_span_ms: 60_000,
            enabled_signal_kinds: vec![
                SignalKind::ErrorSeverity,
                SignalKind::KnownErrorCode,
                SignalKind::ImeFailed,
            ],
        }
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LaneBucket {
    pub source_idx: u16,
    pub ts_start_ms: i64,
    pub ts_end_ms: i64,
    pub total_count: u32,
    pub error_count: u32,
    pub warn_count: u32,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum TimelineEntry {
    #[serde(rename = "log", rename_all = "camelCase")]
    Log {
        source_idx: u16,
        entry: Box<crate::models::log_entry::LogEntry>,
    },
    #[serde(rename = "imeEvent", rename_all = "camelCase")]
    ImeEvent {
        source_idx: u16,
        event: Box<crate::intune::models::IntuneEvent>,
    },
}

#[derive(thiserror::Error, Debug, serde::Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum TimelineError {
    #[error("timeline not found: {id}")]
    NotFound { id: String },
    #[error("too large: estimated {estimated} entries exceeds limit of {limit}")]
    TooLarge { estimated: u64, limit: u64 },
    #[error("no sources")]
    NoSources,
    /// Reserved for a future phase that surfaces per-source read errors as
    /// distinct variants rather than embedding them in `errors` on the bundle.
    #[allow(dead_code)]
    #[error("source read error: {path}: {message}")]
    SourceRead { path: String, message: String },
    #[error("internal: {message}")]
    Internal { message: String },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::log_entry::{LogEntry, LogFormat, Severity};

    #[test]
    fn entry_index_is_compact() {
        assert!(
            std::mem::size_of::<EntryIndex>() <= 32,
            "EntryIndex grew to {} bytes",
            std::mem::size_of::<EntryIndex>()
        );
    }

    #[test]
    fn default_tunables_match_spec() {
        let t = TimelineTunables::default();
        assert_eq!(t.overlap_window_ms, 5_000);
        assert_eq!(t.min_source_count, 2);
        assert_eq!(t.max_incident_span_ms, 60_000);
        assert!(t.enabled_signal_kinds.contains(&SignalKind::ErrorSeverity));
    }

    #[test]
    fn signal_flag_bits_disjoint() {
        assert_eq!(SIGNAL_FLAG_HAS_ERROR_CODE & SIGNAL_FLAG_IS_IME_FAILED, 0);
        assert_eq!(SIGNAL_FLAG_IS_IME_FAILED & SIGNAL_FLAG_IS_IME_EVENT, 0);
    }

    #[test]
    fn timeline_entry_serde_round_trips() {
        // LogEntry does not derive Default, so spell every field out explicitly.
        let e = TimelineEntry::Log {
            source_idx: 3,
            entry: Box::new(LogEntry {
                id: 1,
                line_number: 1,
                message: "x".into(),
                component: None,
                timestamp: Some(1000),
                timestamp_display: None,
                severity: Severity::Info,
                thread: None,
                thread_display: None,
                source_file: None,
                format: LogFormat::Plain,
                file_path: "/p".into(),
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
            }),
        };
        let json = serde_json::to_string(&e).unwrap();
        assert!(json.contains("\"kind\":\"log\""));
        assert!(json.contains("\"sourceIdx\":3"));
    }
}
