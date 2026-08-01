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
        let (consumed, truncated) = match read_capped_line(reader, &mut buf) {
            Ok(v) => v,
            Err(e) => return Err(AppError::Io(e)),
        };
        if consumed == 0 {
            return Ok(());
        }
        let line_start = offset;
        offset += consumed;

        let mut end = buf.len();
        while end > 0 && (buf[end - 1] == b'\n' || buf[end - 1] == b'\r') {
            end -= 1;
        }
        let mut text = decode_line(&buf[..end]);
        if truncated {
            text.push_str(TRUNCATION_MARKER);
        }
        visit(line_start, &text);
    }
}

/// Appended to any line clipped at [`MAX_LINE_BYTES`], so a truncated record is
/// visibly truncated rather than quietly wrong.
const TRUNCATION_MARKER: &str = "…[truncated]";

/// Upper bound on a single retained log line. Real `jamf.log` records are well
/// under a kilobyte; anything past this is a corrupt or binary file rather than
/// a record worth keeping whole.
const MAX_LINE_BYTES: usize = 64 * 1024;

/// Reads one newline-terminated record into `buf`, keeping at most
/// [`MAX_LINE_BYTES`] of it.
///
/// `BufRead::read_until` grows its buffer to the next delimiter, so a file with
/// no newline at all — a truncated binary blob, a wrong file picked by a
/// glob — would be pulled into memory whole. Cap the retained bytes and drain
/// the rest, so the offset arithmetic still reflects true file positions.
///
/// Returns `(bytes_consumed_from_the_file, was_truncated)`.
fn read_capped_line<R: BufRead>(reader: &mut R, buf: &mut Vec<u8>) -> std::io::Result<(u64, bool)> {
    let mut consumed: u64 = 0;
    let mut truncated = false;
    loop {
        let available = match reader.fill_buf() {
            Ok(b) => b,
            Err(ref e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if available.is_empty() {
            return Ok((consumed, truncated));
        }
        let (chunk, done) = match available.iter().position(|b| *b == b'\n') {
            Some(i) => (&available[..=i], true),
            None => (available, false),
        };
        let take = chunk.len();

        let room = MAX_LINE_BYTES.saturating_sub(buf.len());
        if room == 0 {
            truncated = true;
        } else if take > room {
            buf.extend_from_slice(&chunk[..room]);
            truncated = true;
        } else {
            buf.extend_from_slice(chunk);
        }

        reader.consume(take);
        consumed += take as u64;
        if done {
            return Ok((consumed, truncated));
        }
    }
}
