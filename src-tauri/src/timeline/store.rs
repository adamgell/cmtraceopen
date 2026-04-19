use std::collections::HashMap;
use crate::intune::models::IntuneEvent;
use crate::timeline::models::*;

/// Server-side timeline. Holds compact indexes per source and sparse IME event arrays.
/// Full LogEntry text is NOT retained — it is re-materialized from file offset on demand.
pub struct Timeline {
    pub bundle: TimelineBundle,
    pub indexes: HashMap<u16, Vec<EntryIndex>>,
    pub ime_events: HashMap<u16, Vec<IntuneEvent>>,
    pub raw_signals: Vec<Signal>, // cached for tunable re-runs
}

impl Timeline {
    /// Fresh recount across indexes + IME events. `bundle.total_entries` is
    /// the canonical value; this helper is retained for tests/diagnostics.
    #[allow(dead_code)]
    pub fn total_entries(&self) -> u64 {
        self.indexes.values().map(|v| v.len() as u64).sum::<u64>()
            + self.ime_events.values().map(|v| v.len() as u64).sum::<u64>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::log_entry::Severity;

    #[test]
    fn total_entries_sums_across_sources() {
        let mut indexes = HashMap::new();
        indexes.insert(0u16, vec![
            EntryIndex { timestamp_ms: 1, severity: Severity::Info,
                source_idx: 0, byte_offset: 0, line_number: 1, signal_flags: 0 },
            EntryIndex { timestamp_ms: 2, severity: Severity::Error,
                source_idx: 0, byte_offset: 10, line_number: 2, signal_flags: 1 },
        ]);
        indexes.insert(1u16, vec![
            EntryIndex { timestamp_ms: 3, severity: Severity::Info,
                source_idx: 1, byte_offset: 0, line_number: 1, signal_flags: 0 },
        ]);
        let tl = Timeline {
            bundle: TimelineBundle {
                id: "t1".into(),
                sources: vec![],
                time_range_ms: (1, 3),
                total_entries: 3,
                incidents: vec![],
                denied_guids: vec![],
                errors: vec![],
                tunables: Default::default(),
            },
            indexes,
            ime_events: HashMap::new(),
            raw_signals: vec![],
        };
        assert_eq!(tl.total_entries(), 3);
    }
}
