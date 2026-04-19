use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use crate::models::log_entry::LogEntry;
use crate::parser::ResolvedParser;
use crate::timeline::models::*;

/// Read raw bytes of a single log entry starting at byte_offset, trimming at
/// the first newline. Works for single-line formats and newline-terminated
/// logical records. 64 KiB upper bound.
fn read_entry_raw(path: &Path, byte_offset: u64) -> std::io::Result<Vec<u8>> {
    let mut f = File::open(path)?;
    f.seek(SeekFrom::Start(byte_offset))?;
    let mut buf = vec![0u8; 64 * 1024];
    let n = f.read(&mut buf)?;
    buf.truncate(n);
    if let Some(pos) = buf.iter().position(|&b| b == b'\n') {
        buf.truncate(pos + 1);
    }
    Ok(buf)
}

/// Materialize a full LogEntry from its EntryIndex. Runs the source parser
/// over the raw bytes at byte_offset.
pub fn materialize_log_entry(
    path: &Path,
    parser: &ResolvedParser,
    ei: &EntryIndex,
) -> Option<LogEntry> {
    let raw = read_entry_raw(path, ei.byte_offset).ok()?;
    let text = String::from_utf8_lossy(&raw).into_owned();
    parser.parse_one_line(&text, ei.line_number).ok()
}

/// Materialize just the message text — cheap path for GUID scanning.
pub fn materialize_msg(
    path: &Path,
    parser: &ResolvedParser,
    ei: &EntryIndex,
) -> Option<String> {
    materialize_log_entry(path, parser, ei).map(|e| e.message)
}

#[cfg(test)]
mod tests_mat {
    use super::*;
    use std::io::Write;

    #[test]
    fn reads_first_line_at_offset_zero() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("t.log");
        let mut f = File::create(&p).unwrap();
        writeln!(f, "line-zero").unwrap();
        writeln!(f, "line-one").unwrap();
        let raw = read_entry_raw(&p, 0).unwrap();
        let s = String::from_utf8_lossy(&raw);
        assert!(s.starts_with("line-zero"));
    }

    #[test]
    fn reads_from_mid_file_offset() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("t.log");
        let mut f = File::create(&p).unwrap();
        writeln!(f, "abc").unwrap();
        writeln!(f, "defg").unwrap();
        let raw = read_entry_raw(&p, 4).unwrap();
        let s = String::from_utf8_lossy(&raw);
        assert!(s.starts_with("defg"));
    }
}
