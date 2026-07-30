use std::sync::OnceLock;

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::error_db::lookup::lookup_error_code;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmSignalKind {
    HResult,
    Gle,
    ExitCode,
    ReturnCode,
    Status,
}

/// A structured diagnostic token captured from an SCCM evidence message.
///
/// `start` and `end` are an end-exclusive range measured in UTF-16 code units,
/// matching JavaScript string indexes rather than UTF-8 byte offsets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmSignal {
    pub kind: SccmSignalKind,
    pub raw: String,
    pub numeric: Option<u32>,
    pub start: usize,
    pub end: usize,
    pub error_description: Option<String>,
    pub error_category: Option<String>,
}

struct SignalPattern {
    kind: SccmSignalKind,
    regex: Regex,
}

fn signal_patterns() -> &'static [SignalPattern] {
    static CELL: OnceLock<Vec<SignalPattern>> = OnceLock::new();
    CELL.get_or_init(|| {
        [
            (
                SccmSignalKind::HResult,
                r"(?i:\bhr)=(?P<value>0[xX][0-9A-Fa-f]{8})\b",
            ),
            (
                SccmSignalKind::HResult,
                r"(?i:\bHRESULT)[ \t]+(?P<value>0[xX][0-9A-Fa-f]{8})\b",
            ),
            (
                SccmSignalKind::Gle,
                r"(?i:\[gle)=(?P<value>0[xX][0-9A-Fa-f]{8})\]",
            ),
            (
                SccmSignalKind::ExitCode,
                r"(?i:\bexit[ \t]+code)[ \t]+(?P<value>[0-9]+)\b",
            ),
            (
                SccmSignalKind::ExitCode,
                r"(?i:\bexitcode)[ \t]*=[ \t]*(?P<value>[0-9]+)\b",
            ),
            (
                SccmSignalKind::ReturnCode,
                r"(?i:\breturn[ \t]+code)[ \t]+(?P<value>[0-9]+)\b",
            ),
            (SccmSignalKind::Status, r"(?i:\bstatus)=(?P<value>[0-9]+)\b"),
        ]
        .into_iter()
        .map(|(kind, pattern)| SignalPattern {
            kind,
            regex: Regex::new(pattern).expect("SCCM signal regex must compile"),
        })
        .collect()
    })
}

/// Extract structured SCCM diagnostic tokens in message order.
///
/// Capture does not depend on the embedded error database: unknown or
/// out-of-range values are retained with absent numeric/enrichment fields.
pub fn extract_signals(message: &str) -> Vec<SccmSignal> {
    let mut signals = signal_patterns()
        .iter()
        .flat_map(|pattern| {
            pattern.regex.captures_iter(message).filter_map(|captures| {
                let value = captures.name("value")?;
                let raw = value.as_str();
                let numeric = parse_numeric(raw);
                let (error_description, error_category) = numeric
                    .map(|_| lookup_error_code(raw))
                    .filter(|result| result.found)
                    .map(|result| (Some(result.description), Some(result.category)))
                    .unwrap_or((None, None));
                let start = message[..value.start()].encode_utf16().count();
                let end = start + raw.encode_utf16().count();

                Some(SccmSignal {
                    kind: pattern.kind.clone(),
                    raw: raw.to_owned(),
                    numeric,
                    start,
                    end,
                    error_description,
                    error_category,
                })
            })
        })
        .collect::<Vec<_>>();

    signals.sort_by_key(|signal| (signal.start, signal_kind_order(&signal.kind), signal.end));
    signals.dedup_by(|right, left| {
        right.kind == left.kind
            && right.raw == left.raw
            && right.start == left.start
            && right.end == left.end
    });
    signals
}

fn parse_numeric(raw: &str) -> Option<u32> {
    raw.strip_prefix("0x")
        .or_else(|| raw.strip_prefix("0X"))
        .map_or_else(|| raw.parse().ok(), |hex| u32::from_str_radix(hex, 16).ok())
}

fn signal_kind_order(kind: &SccmSignalKind) -> u8 {
    match kind {
        SccmSignalKind::HResult => 0,
        SccmSignalKind::Gle => 1,
        SccmSignalKind::ExitCode => 2,
        SccmSignalKind::ReturnCode => 3,
        SccmSignalKind::Status => 4,
    }
}
