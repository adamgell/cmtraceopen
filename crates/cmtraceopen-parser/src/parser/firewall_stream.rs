//! Bounded physical-line continuation shared by snapshots and live firewall sources.
use super::windows_firewall::{parse_record, FirewallContext, MAX_FIREWALL_LINE_BYTES};
use crate::models::{firewall::*, log_entry::LogEntry};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
/// A complete replacement of a provisional snapshot-EOF row.
pub struct FirewallRowReplacement {
    /// Source-local ID that the consumer must match before replacing.
    pub expected_id: u64,
    /// Physical line that the consumer must match before replacing.
    pub expected_line_number: u32,
    /// Complete revised row, retaining the provisional source-local identity.
    pub entry: LogEntry,
}
#[derive(Debug, Clone)]
/// A directive checkpoint used to interpret subsequent physical records.
pub struct FirewallContextChange {
    /// Physical line at which this context becomes active.
    pub line_number: u32,
    /// Validated schema and clock directives for this checkpoint.
    pub context: FirewallContext,
}
#[derive(Debug, Clone, Default)]
/// Rows and cumulative coverage produced by one stream operation.
pub struct FirewallDelta {
    /// New source rows to append.
    pub entries: Vec<LogEntry>,
    /// Complete replacements of previously emitted provisional rows.
    pub replacements: Vec<FirewallRowReplacement>,
    /// Current cumulative coverage; consumers replace their previous snapshot.
    pub coverage: FirewallCoverage,
    /// Greatest physical line completed or observed at snapshot EOF.
    pub observed_through_line: u32,
    /// Directive checkpoints encountered during this operation.
    pub context_changes: Vec<FirewallContextChange>,
}

#[derive(Debug, Clone)]
/// Bounded decoded-text continuation shared by snapshot and incremental parsing.
pub struct FirewallStream {
    context: FirewallContext,
    next_id: u64,
    next_line: u32,
    observed: u32,
    pending: String,
    pending_cr: bool,
    line_active: bool,
    padding: u64,
    oversized: bool,
    provisional_id: Option<u64>,
    provisional_coverage: FirewallCoverage,
    committed: FirewallCoverage,
}
impl FirewallStream {
    /// Create an empty source generation at the supplied ID and physical line.
    pub fn new(next_id: u64, next_line: u32) -> Self {
        Self {
            context: FirewallContext::default(),
            next_id,
            next_line,
            observed: next_line.saturating_sub(1),
            pending: String::with_capacity(MAX_FIREWALL_LINE_BYTES),
            pending_cr: false,
            line_active: false,
            padding: 0,
            oversized: false,
            provisional_id: None,
            provisional_coverage: FirewallCoverage::default(),
            committed: FirewallCoverage::default(),
        }
    }
    /// Read the current validated schema and time directives.
    pub fn context(&self) -> &FirewallContext {
        &self.context
    }
    /// ID to assign to the next new source row.
    pub fn next_id(&self) -> u64 {
        self.next_id
    }
    /// Physical line currently being accumulated.
    pub fn next_line(&self) -> u32 {
        self.next_line
    }
    /// Allocated byte capacity of the retained decoded line buffer.
    pub fn retained_text_bytes(&self) -> usize {
        self.pending.capacity()
    }
    /// Discard old context and unfinished text; restart physical lines at one.
    pub fn reset_generation(&mut self, next_id: u64) {
        *self = Self::new(next_id, 1);
    }
    /// Current cumulative coverage including reversible provisional contributions.
    pub fn coverage(&self) -> FirewallCoverage {
        let mut c = self.committed.clone();
        c.merge(&self.provisional_coverage);
        c.padding.add(self.padding, self.next_line);
        c
    }
    fn text_char(&mut self, ch: char) {
        if ch == '\0' && self.pending.is_empty() && !self.oversized {
            self.padding = self.padding.saturating_add(1);
        } else if !self.oversized {
            if self.pending.len() + ch.len_utf8() <= MAX_FIREWALL_LINE_BYTES {
                // A cloned String can have capacity == len; avoid geometric growth past the cap.
                if self.pending.capacity() < self.pending.len() + ch.len_utf8() {
                    self.pending
                        .reserve_exact(MAX_FIREWALL_LINE_BYTES - self.pending.len());
                }
                self.pending.push(ch);
            } else {
                self.oversized = true;
            }
        }
    }
    fn emit_record(&mut self, path: &str, delta: &mut FirewallDelta, provisional: bool) {
        let id = self.provisional_id.unwrap_or(self.next_id);
        let mut parsed = parse_record(&self.pending, &self.context, id, self.next_line, path);
        if self.oversized {
            let f = parsed.entry.firewall.as_mut().expect("firewall record");
            f.truncated = true;
            f.record_kind = FirewallRecordKind::Malformed;
            f.fields.clear();
            parsed.entry.message = "Oversized firewall record (truncated)".into();
            parsed.entry.severity = crate::models::log_entry::Severity::Info;
            parsed.entry.timestamp = None;
            parsed.entry.timezone_offset = None;
            parsed.coverage = FirewallCoverage::default();
            parsed.coverage.oversized.add(1, self.next_line);
            parsed.coverage.unplaced_timestamps.add(1, self.next_line);
        }
        if let Some(expected_id) = self.provisional_id {
            delta.replacements.push(FirewallRowReplacement {
                expected_id,
                expected_line_number: self.next_line,
                entry: parsed.entry,
            });
        } else {
            self.next_id = self.next_id.saturating_add(1);
            delta.entries.push(parsed.entry);
        }
        if provisional {
            self.provisional_id = Some(id);
            self.provisional_coverage = parsed.coverage;
        } else {
            self.committed.merge(&parsed.coverage);
        }
    }
    fn finish_line(&mut self, path: &str, delta: &mut FirewallDelta) {
        let before = self.context.clone();
        let is_directive = self.pending.trim_start().starts_with('#');
        if self.oversized {
            // A capped directive must not install a partial schema or retain the old one.
            if is_directive {
                let key = self.pending.trim_start().split(':').next().unwrap_or("");
                if key.eq_ignore_ascii_case("#Fields") {
                    self.context.directive("#Fields:");
                } else if key.eq_ignore_ascii_case("#Software") {
                    self.context.directive("#Software:");
                } else if key.eq_ignore_ascii_case("#Time Format") {
                    self.context.directive("#Time Format:");
                }
            }
            self.emit_record(path, delta, false);
        } else if is_directive {
            self.context.directive(&self.pending);
        } else if !self.pending.trim().is_empty() {
            self.emit_record(path, delta, false);
        }
        if self.context != before {
            delta.context_changes.push(FirewallContextChange {
                line_number: self.next_line.saturating_add(1),
                context: self.context.clone(),
            });
        }
        self.committed.padding.add(self.padding, self.next_line);
        self.observed = self.next_line;
        self.next_line = self.next_line.saturating_add(1);
        self.pending.clear();
        self.pending_cr = false;
        self.line_active = false;
        self.padding = 0;
        self.oversized = false;
        self.provisional_id = None;
        self.provisional_coverage = FirewallCoverage::default();
    }
    fn finish_delta(&self, mut delta: FirewallDelta) -> FirewallDelta {
        delta.coverage = self.coverage();
        delta.observed_through_line = self.observed;
        delta
    }
    /// Consume decoded text; newly begun unterminated rows wait for a line boundary.
    pub fn push_text(&mut self, text: &str, file_path: &str) -> FirewallDelta {
        let mut delta = FirewallDelta::default();
        for ch in text.chars() {
            self.line_active = true;
            if ch == '\n' {
                self.finish_line(file_path, &mut delta);
                continue;
            }
            if self.pending_cr {
                self.pending_cr = false;
                self.text_char('\r');
            }
            if ch == '\r' {
                self.pending_cr = true;
            } else {
                self.text_char(ch);
            }
        }
        if !text.is_empty() && self.provisional_id.is_some() {
            self.emit_record(file_path, &mut delta, true);
        }
        self.finish_delta(delta)
    }
    /// Expose an unfinished data row provisionally without finalizing partial directives.
    pub fn snapshot_eof(&mut self, file_path: &str) -> FirewallDelta {
        let mut delta = FirewallDelta::default();
        if self.line_active {
            self.observed = self.next_line;
        }
        if self.oversized
            || (!self.pending.trim().is_empty() && !self.pending.trim_start().starts_with('#'))
        {
            self.emit_record(file_path, &mut delta, true);
        }
        self.finish_delta(delta)
    }
}

/// Apply the same stable replacements used by native and frontend snapshot consumers.
/// Apply source-local append and full replacement rows to a snapshot vector.
pub fn apply_delta(entries: &mut Vec<LogEntry>, delta: FirewallDelta) {
    entries.extend(delta.entries);
    for replacement in delta.replacements {
        if let Some(entry) = entries.iter_mut().find(|e| {
            e.id == replacement.expected_id && e.line_number == replacement.expected_line_number
        }) {
            *entry = replacement.entry;
        }
    }
}
