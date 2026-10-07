//! Firewall timeline records are indexed and decoded against one source snapshot.
//! Identity/length checks detect replacement and observed truncation. Same-identity
//! in-place edits or truncate/regrow between observations are not immutable snapshots.
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use super::models::EntryIndex;
use crate::fs_identity::{file_identity, FileIdentity};
use crate::models::log_entry::LogEntry;
use crate::parser::firewall_source::{FirewallDecoder, FirewallEncoding, RawLineSpan};
use crate::parser::NativeParseArtifacts;
use cmtraceopen_parser::parser::firewall_stream::FirewallContextChange;
use cmtraceopen_parser::parser::windows_firewall::{
    parse_record, FirewallContext, MAX_FIREWALL_LINE_BYTES,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub enum FirewallMaterializationError {
    #[error("Source changed. Rebuild the timeline to continue.")]
    SourceChanged,
    #[error("Source generation cannot be verified. Reopen the source on a supported filesystem.")]
    GenerationUnverifiable,
    #[error("Source could not be read or decoded. Check the file and rebuild the timeline.")]
    ReadDecodeFailure,
    #[error("The firewall index or field context is invalid. Rebuild the timeline.")]
    InvalidIndexContext,
}

#[derive(Debug)]
struct IndexedRow {
    span: RawLineSpan,
    id: u64,
}

#[derive(Debug)]
pub struct FirewallRuntime {
    pub identity: Option<FileIdentity>,
    pub encoding: FirewallEncoding,
    pub snapshot_len: u64,
    /// Only contexts referenced by eligible indexed records; adjacent equals coalesce.
    pub contexts: Vec<FirewallContextChange>,
    rows: BTreeMap<u32, IndexedRow>,
}
impl FirewallRuntime {
    pub fn context_at(&self, line: u32) -> Option<&FirewallContext> {
        let end = self
            .contexts
            .partition_point(|point| point.line_number <= line);
        end.checked_sub(1)
            .map(|index| &self.contexts[index].context)
    }
}

pub struct IndexedFirewall {
    pub entries: Vec<EntryIndex>,
    pub runtime: FirewallRuntime,
    pub excluded: u32,
}

pub fn index_firewall(
    artifacts: &NativeParseArtifacts,
) -> Result<IndexedFirewall, FirewallMaterializationError> {
    let source = artifacts
        .firewall
        .as_ref()
        .ok_or(FirewallMaterializationError::InvalidIndexContext)?;
    let spans: BTreeMap<_, _> = source
        .raw_spans
        .iter()
        .map(|span| (span.line_number, span))
        .collect();
    let mut runtime = FirewallRuntime {
        identity: artifacts.identity,
        encoding: source.decoder.encoding(),
        snapshot_len: artifacts.result.byte_offset,
        contexts: vec![],
        rows: BTreeMap::new(),
    };
    let mut entries = Vec::new();
    let mut excluded = 0u32;
    for entry in &artifacts.result.entries {
        let Some(timestamp_ms) = entry.timestamp else {
            excluded = excluded.saturating_add(1);
            continue;
        };
        let span = spans
            .get(&entry.line_number)
            .ok_or(FirewallMaterializationError::InvalidIndexContext)?;
        let end = source
            .context_changes
            .partition_point(|point| point.line_number <= entry.line_number);
        let context = end
            .checked_sub(1)
            .map(|i| &source.context_changes[i].context)
            .ok_or(FirewallMaterializationError::InvalidIndexContext)?;
        if runtime.contexts.last().map(|last| &last.context) != Some(context) {
            runtime.contexts.push(FirewallContextChange {
                line_number: entry.line_number,
                context: context.clone(),
            });
        }
        runtime.rows.insert(
            entry.line_number,
            IndexedRow {
                span: (*span).clone(),
                id: entry.id,
            },
        );
        entries.push(EntryIndex {
            timestamp_ms,
            severity: entry.severity,
            source_idx: 0,
            byte_offset: span.start,
            line_number: entry.line_number,
            signal_flags: 0,
        });
    }
    Ok(IndexedFirewall {
        entries,
        runtime,
        excluded,
    })
}

/// One opened, validated source handle per request. Never reopen the pathname per row.
pub struct FirewallReadSession<'a> {
    file: File,
    path: String,
    runtime: &'a FirewallRuntime,
}
impl<'a> FirewallReadSession<'a> {
    pub fn open(
        path: &Path,
        runtime: &'a FirewallRuntime,
    ) -> Result<Self, FirewallMaterializationError> {
        let expected = runtime
            .identity
            .ok_or(FirewallMaterializationError::GenerationUnverifiable)?;
        let file = File::open(path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                FirewallMaterializationError::SourceChanged
            } else {
                FirewallMaterializationError::ReadDecodeFailure
            }
        })?;
        let metadata = file
            .metadata()
            .map_err(|_| FirewallMaterializationError::ReadDecodeFailure)?;
        let identity = file_identity(&file, &metadata)
            .ok_or(FirewallMaterializationError::GenerationUnverifiable)?;
        if identity != expected || metadata.len() < runtime.snapshot_len {
            return Err(FirewallMaterializationError::SourceChanged);
        }
        Ok(Self {
            file,
            path: path.to_string_lossy().into_owned(),
            runtime,
        })
    }
}

pub fn materialize_firewall_entry(
    session: &mut FirewallReadSession<'_>,
    context: &FirewallContext,
    index: &EntryIndex,
) -> Result<LogEntry, FirewallMaterializationError> {
    use FirewallMaterializationError::{InvalidIndexContext, ReadDecodeFailure};
    let row = session
        .runtime
        .rows
        .get(&index.line_number)
        .ok_or(InvalidIndexContext)?;
    if row.span.start != index.byte_offset
        || session.runtime.context_at(index.line_number) != Some(context)
    {
        return Err(InvalidIndexContext);
    }
    let length = row
        .span
        .end
        .checked_sub(row.span.start)
        .ok_or(InvalidIndexContext)?;
    // UTF-16 can use twice as many raw bytes as decoded UTF-8 for ASCII. The
    // extra four bytes cover a CRLF terminator. This is not a 64KiB raw cutoff.
    if length == 0 || length > 2 * (MAX_FIREWALL_LINE_BYTES as u64 + 2) {
        return Err(InvalidIndexContext);
    }
    session
        .file
        .seek(SeekFrom::Start(row.span.start))
        .map_err(|_| ReadDecodeFailure)?;
    let mut remaining = length;
    let mut raw = [0u8; 4096];
    let mut text = String::new();
    let mut decoder = FirewallDecoder::for_encoding(session.runtime.encoding);
    while remaining > 0 {
        let count = remaining.min(raw.len() as u64) as usize;
        session
            .file
            .read_exact(&mut raw[..count])
            .map_err(|_| ReadDecodeFailure)?;
        let decoded = decoder.push(&raw[..count]).map_err(|_| ReadDecodeFailure)?;
        if text.len() + decoded.text.len() > MAX_FIREWALL_LINE_BYTES + 2 {
            return Err(InvalidIndexContext);
        }
        text.push_str(&decoded.text);
        remaining -= count as u64;
    }
    if decoder.pending_bytes() != 0 {
        return Err(ReadDecodeFailure);
    }
    let line = text.strip_suffix('\n').unwrap_or(&text);
    let line = line.strip_suffix('\r').unwrap_or(line);
    if line.contains('\n') || line.len() > MAX_FIREWALL_LINE_BYTES {
        return Err(InvalidIndexContext);
    }
    let entry = parse_record(line, context, row.id, index.line_number, &session.path).entry;
    if entry.timestamp != Some(index.timestamp_ms) || entry.severity != index.severity {
        return Err(InvalidIndexContext);
    }
    Ok(entry)
}
