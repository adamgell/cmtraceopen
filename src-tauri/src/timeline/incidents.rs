use std::collections::HashMap;

use crate::intune::models::IntuneEvent;
use crate::models::log_entry::Severity;
use crate::timeline::models::*;

/// Walk per-source indexes and IME events, emit raw signals, sort by ts_ms.
pub fn emit_signals(
    indexes: &HashMap<u16, Vec<EntryIndex>>,
    ime_events: &HashMap<u16, Vec<IntuneEvent>>,
    enabled: &[SignalKind],
) -> Vec<Signal> {
    let want_err = enabled.contains(&SignalKind::ErrorSeverity);
    let want_code = enabled.contains(&SignalKind::KnownErrorCode);
    let want_ime = enabled.contains(&SignalKind::ImeFailed);

    let mut out: Vec<Signal> = Vec::new();

    for (src_idx, idx_vec) in indexes {
        for (entry_ref, ei) in idx_vec.iter().enumerate() {
            let entry_ref = entry_ref as u32;
            if want_err && matches!(ei.severity, Severity::Error) {
                out.push(Signal {
                    source_idx: *src_idx,
                    entry_ref,
                    ts_ms: ei.timestamp_ms,
                    kind: SignalKind::ErrorSeverity,
                    correlation_id: None,
                });
            }
            if want_code && (ei.signal_flags & SIGNAL_FLAG_HAS_ERROR_CODE) != 0 {
                out.push(Signal {
                    source_idx: *src_idx,
                    entry_ref,
                    ts_ms: ei.timestamp_ms,
                    kind: SignalKind::KnownErrorCode,
                    correlation_id: None,
                });
            }
        }
    }

    if want_ime {
        for (src_idx, evs) in ime_events {
            for (entry_ref, ev) in evs.iter().enumerate() {
                if ev.status_is_failed() {
                    if let Some(ts) = ev.start_time_epoch_ms() {
                        out.push(Signal {
                            source_idx: *src_idx,
                            entry_ref: entry_ref as u32,
                            ts_ms: ts,
                            kind: SignalKind::ImeFailed,
                            correlation_id: None,
                        });
                    }
                }
            }
        }
    }

    out.sort_by_key(|s| s.ts_ms);
    out
}

#[cfg(test)]
mod tests_emit {
    use super::*;

    fn ei(ts: i64, sev: Severity, flags: u8, src: u16, line: u32) -> EntryIndex {
        EntryIndex {
            timestamp_ms: ts,
            severity: sev,
            source_idx: src,
            byte_offset: 0,
            line_number: line,
            signal_flags: flags,
        }
    }

    #[test]
    fn emits_error_severity_signal() {
        let mut idx = HashMap::new();
        idx.insert(0, vec![ei(100, Severity::Error, 0, 0, 1)]);
        let sigs = emit_signals(&idx, &HashMap::new(), &[SignalKind::ErrorSeverity]);
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].kind, SignalKind::ErrorSeverity);
    }

    #[test]
    fn emits_error_code_signal_independent_of_severity() {
        let mut idx = HashMap::new();
        idx.insert(
            0,
            vec![ei(100, Severity::Info, SIGNAL_FLAG_HAS_ERROR_CODE, 0, 1)],
        );
        let sigs = emit_signals(&idx, &HashMap::new(), &[SignalKind::KnownErrorCode]);
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].kind, SignalKind::KnownErrorCode);
    }

    #[test]
    fn disabled_kinds_are_skipped() {
        let mut idx = HashMap::new();
        idx.insert(
            0,
            vec![ei(100, Severity::Error, SIGNAL_FLAG_HAS_ERROR_CODE, 0, 1)],
        );
        let sigs = emit_signals(&idx, &HashMap::new(), &[SignalKind::KnownErrorCode]);
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].kind, SignalKind::KnownErrorCode);
    }

    #[test]
    fn signals_are_sorted_by_ts() {
        let mut idx = HashMap::new();
        idx.insert(
            0,
            vec![
                ei(300, Severity::Error, 0, 0, 1),
                ei(100, Severity::Error, 0, 0, 2),
                ei(200, Severity::Error, 0, 0, 3),
            ],
        );
        let sigs = emit_signals(&idx, &HashMap::new(), &[SignalKind::ErrorSeverity]);
        let ts: Vec<i64> = sigs.iter().map(|s| s.ts_ms).collect();
        assert_eq!(ts, vec![100, 200, 300]);
    }
}
