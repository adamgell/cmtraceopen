//! Native-only decoding and raw source spans for Windows Firewall logs.
//! Decoder updates are transactional; incomplete encodings remain resumable.
use cmtraceopen_parser::parser::firewall_stream::{
    apply_delta, FirewallContextChange, FirewallStream,
};
use serde::Serialize;

pub const FIREWALL_READ_CHUNK_BYTES: usize = 65_536;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum FirewallEncoding {
    #[default]
    Undetermined,
    Utf8,
    Windows1252,
    Utf16Le,
    Utf16Be,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FirewallDecodeError {
    #[error("Firewall decoding gap: invalid explicit UTF-8 or UTF-16 encoding")]
    InvalidExplicitEncoding,
    #[error("Firewall decoding gap: this source requires a Windows-1252 reparse")]
    NeedsWindows1252,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawLineSpan {
    pub line_number: u32,
    /// First non-padding raw byte. Includes ordinary whitespace and excludes BOM.
    pub start: u64,
    /// Exclusive raw end, including the line terminator when present.
    pub end: u64,
}

#[derive(Debug, Default)]
pub struct DecodedFirewallChunk {
    pub text: String,
    pub lines: Vec<RawLineSpan>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FirewallDecoder {
    encoding: FirewallEncoding,
    explicit_bom: bool,
    carry: Vec<u8>,
    raw_offset: u64,
    decoded_end: u64,
    line_start: u64,
    completed_lines: u32,
    line_has_text: bool,
}

impl FirewallDecoder {
    pub fn windows1252() -> Self {
        Self {
            encoding: FirewallEncoding::Windows1252,
            ..Self::default()
        }
    }
    pub fn encoding(&self) -> FirewallEncoding {
        self.encoding
    }
    pub fn has_explicit_bom(&self) -> bool {
        self.explicit_bom
    }
    pub fn raw_offset(&self) -> u64 {
        self.raw_offset
    }
    pub fn pending_bytes(&self) -> usize {
        self.carry.len()
    }
    pub fn pending_span(&self) -> Option<RawLineSpan> {
        (self.decoded_end > self.line_start).then(|| RawLineSpan {
            line_number: self.completed_lines.saturating_add(1),
            start: self.line_start,
            end: self.decoded_end,
        })
    }
    /// Commit nothing on definitive invalid input, including raw offset/carry.
    pub fn push(&mut self, bytes: &[u8]) -> Result<DecodedFirewallChunk, FirewallDecodeError> {
        let mut candidate = self.clone();
        let decoded = candidate.decode(bytes)?;
        *self = candidate;
        Ok(decoded)
    }
    fn scalar(&mut self, ch: char, end: u64, out: &mut DecodedFirewallChunk) {
        out.text.push(ch);
        self.decoded_end = end;
        if ch == '\0' && !self.line_has_text {
            self.line_start = end;
        } else if ch == '\n' {
            out.lines.push(RawLineSpan {
                line_number: self.completed_lines.saturating_add(1),
                start: self.line_start,
                end,
            });
            self.completed_lines = self.completed_lines.saturating_add(1);
            self.line_start = end;
            self.line_has_text = false;
        } else {
            self.line_has_text = true;
        }
    }
    fn decode(&mut self, bytes: &[u8]) -> Result<DecodedFirewallChunk, FirewallDecodeError> {
        let base = self.raw_offset - self.carry.len() as u64;
        self.raw_offset += bytes.len() as u64;
        let mut data = std::mem::take(&mut self.carry);
        data.extend_from_slice(bytes);
        let mut start = 0;
        let mut out = DecodedFirewallChunk::default();
        if self.encoding == FirewallEncoding::Undetermined {
            if data.is_empty() {
                return Ok(out);
            }
            let boms: &[(&[u8], FirewallEncoding)] = &[
                (&[0xef, 0xbb, 0xbf], FirewallEncoding::Utf8),
                (&[0xff, 0xfe], FirewallEncoding::Utf16Le),
                (&[0xfe, 0xff], FirewallEncoding::Utf16Be),
            ];
            if let Some((bom, encoding)) = boms.iter().find(|(bom, _)| data.starts_with(bom)) {
                self.encoding = *encoding;
                self.explicit_bom = true;
                start = bom.len();
                self.line_start = base + start as u64;
                self.decoded_end = self.line_start;
            } else if boms.iter().any(|(bom, _)| bom.starts_with(&data)) {
                self.carry = data;
                return Ok(out);
            } else {
                self.encoding = FirewallEncoding::Utf8;
            }
        }
        match self.encoding {
            FirewallEncoding::Utf8 => {
                let (valid, pending) = match std::str::from_utf8(&data[start..]) {
                    Ok(text) => (text, 0),
                    Err(error) if error.error_len().is_none() => (
                        std::str::from_utf8(&data[start..start + error.valid_up_to()])
                            .expect("UTF-8 validator supplied a valid prefix"),
                        data.len() - start - error.valid_up_to(),
                    ),
                    Err(_) => {
                        return Err(if self.explicit_bom {
                            FirewallDecodeError::InvalidExplicitEncoding
                        } else {
                            FirewallDecodeError::NeedsWindows1252
                        })
                    }
                };
                let mut offset = base + start as u64;
                for ch in valid.chars() {
                    offset += ch.len_utf8() as u64;
                    self.scalar(ch, offset, &mut out);
                }
                self.carry.extend_from_slice(&data[data.len() - pending..]);
            }
            FirewallEncoding::Windows1252 => {
                let (text, _) =
                    encoding_rs::WINDOWS_1252.decode_without_bom_handling(&data[start..]);
                for (i, ch) in text.chars().enumerate() {
                    self.scalar(ch, base + (start + i + 1) as u64, &mut out);
                }
            }
            FirewallEncoding::Utf16Le | FirewallEncoding::Utf16Be => {
                let le = self.encoding == FirewallEncoding::Utf16Le;
                let unit = |i| {
                    let pair = [data[i], data[i + 1]];
                    if le {
                        u16::from_le_bytes(pair)
                    } else {
                        u16::from_be_bytes(pair)
                    }
                };
                let mut i = start;
                while i + 1 < data.len() {
                    let first = unit(i);
                    let width = if (0xd800..=0xdbff).contains(&first) {
                        4
                    } else {
                        2
                    };
                    if i + width > data.len() {
                        break;
                    }
                    let ch = if width == 4 {
                        char::decode_utf16([first, unit(i + 2)])
                            .next()
                            .and_then(Result::ok)
                    } else {
                        char::from_u32(first as u32)
                    }
                    .ok_or(FirewallDecodeError::InvalidExplicitEncoding)?;
                    i += width;
                    self.scalar(ch, base + i as u64, &mut out);
                }
                self.carry.extend_from_slice(&data[i..]);
            }
            FirewallEncoding::Undetermined => unreachable!("BOM prefix returned above"),
        }
        debug_assert!(self.carry.len() <= 3);
        Ok(out)
    }
}

/// Optional artifacts alongside ParseResult; rows live only in the outer result.
/// Snapshot spans/checkpoints may grow with the initial file. The retained
/// continuation itself consists only of the bounded decoder and stream.
pub struct FirewallSourceSnapshot {
    pub decoder: FirewallDecoder,
    pub stream: FirewallStream,
    pub raw_spans: Vec<RawLineSpan>,
    pub context_changes: Vec<FirewallContextChange>,
}

pub fn snapshot_bytes(
    bytes: &[u8],
    path: &str,
    next_id: u64,
    force_windows1252: bool,
) -> Result<
    (
        crate::models::log_entry::ParseResult,
        FirewallSourceSnapshot,
    ),
    FirewallDecodeError,
> {
    let mut decoder = if force_windows1252 {
        FirewallDecoder::windows1252()
    } else {
        FirewallDecoder::default()
    };
    let decoded = match decoder.push(bytes) {
        Ok(decoded) => decoded,
        Err(FirewallDecodeError::NeedsWindows1252) => {
            decoder = FirewallDecoder::windows1252();
            decoder.push(bytes)?
        }
        Err(error) => return Err(error),
    };
    let mut raw_spans = decoded.lines;
    if let Some(span) = decoder.pending_span() {
        raw_spans.push(span);
    }
    let mut stream = FirewallStream::new(next_id, 1);
    let mut delta = stream.push_text(&decoded.text, path);
    let context_changes = std::mem::take(&mut delta.context_changes);
    let mut entries = Vec::new();
    apply_delta(&mut entries, delta);
    let end = stream.snapshot_eof(path);
    let total_lines = end.observed_through_line;
    let coverage = end.coverage.clone();
    apply_delta(&mut entries, end);
    let selection = super::ResolvedParser::windows_firewall();
    let result = crate::models::log_entry::ParseResult {
        entries,
        format_detected: selection.compatibility_format(),
        parser_selection: selection.to_info(),
        total_lines,
        parse_errors: coverage.parse_errors(),
        file_path: path.to_owned(),
        file_size: bytes.len() as u64,
        modified_unix_ms: None,
        byte_offset: decoder.raw_offset(),
        firewall_coverage: Some(coverage),
    };
    Ok((
        result,
        FirewallSourceSnapshot {
            decoder,
            stream,
            raw_spans,
            context_changes,
        },
    ))
}
