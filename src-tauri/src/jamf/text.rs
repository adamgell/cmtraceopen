//! Shared line reading for the JAMF log parsers.
//!
//! These logs are written by the `jamf` binary and by Self Service, both of
//! which can emit non-UTF-8 bytes (policy names and error strings pass through
//! whatever the source encoding was). `BufRead::read_line` rejects such input
//! outright and `lines().map_while(Result::ok)` silently stops at the first bad
//! line — one drops the whole file, the other loses every event after the fault
//! with no indication. Neither is acceptable for a diagnostics tool.
//!
//! So we read at the byte level and decode per line, following the same
//! UTF-8 → Windows-1252 fallback the main parser uses
//! (`cmtraceopen_parser::parser::decode_bytes`). Reading bytes also means the
//! caller can track true file offsets arithmetically instead of issuing a seek
//! per line.

use std::io::{BufRead, ErrorKind};

use crate::error::AppError;

/// Decodes one raw log line, falling back to Windows-1252 when it is not valid
/// UTF-8. Never fails: a diagnostics view showing a few replacement characters
/// beats one showing an I/O error.
pub fn decode_line(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(s) => s.to_string(),
        Err(_) => {
            let (cow, _, _) = encoding_rs::WINDOWS_1252.decode(bytes);
            cow.into_owned()
        }
    }
}

/// Calls `visit` once per line with `(byte_offset, decoded_line)`, where the
/// line has trailing CR/LF stripped and `byte_offset` is the line's start offset
/// in the file.
///
/// Genuine I/O failures (a vanishing volume, a read error) propagate; malformed
/// text does not, because that is what [`decode_line`] absorbs.
pub fn for_each_line<R, F>(reader: &mut R, mut visit: F) -> Result<(), AppError>
where
    R: BufRead,
    F: FnMut(u64, &str),
{
    let mut offset: u64 = 0;
    let mut buf: Vec<u8> = Vec::with_capacity(256);
    loop {
        buf.clear();
        let n = match reader.read_until(b'\n', &mut buf) {
            Ok(n) => n,
            // A partially written line can surface as Interrupted; retrying is
            // correct and matches std's own convention.
            Err(ref e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(AppError::Io(e)),
        };
        if n == 0 {
            return Ok(());
        }
        let line_start = offset;
        offset += n as u64;

        let mut end = buf.len();
        while end > 0 && (buf[end - 1] == b'\n' || buf[end - 1] == b'\r') {
            end -= 1;
        }
        visit(line_start, &decode_line(&buf[..end]));
    }
}
