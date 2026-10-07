//! Windows Firewall grammar. Source values are preserved; only explicit UTC yields an epoch.
use crate::models::{
    firewall::*,
    log_entry::{LogEntry, LogFormat, Severity},
};
use chrono::NaiveDateTime;
use std::{collections::HashSet, net::IpAddr};

pub const MAX_FIREWALL_LINE_BYTES: usize = 65_536;
pub const MAX_PROBE_LINES: usize = 128;
pub const CANONICAL_FIELDS: [&str; 18] = [
    "date", "time", "action", "protocol", "src-ip", "dst-ip", "src-port", "dst-port", "size",
    "tcpflags", "tcpsyn", "tcpack", "tcpwin", "icmptype", "icmpcode", "info", "path", "pid",
];

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FirewallContext {
    pub declared_fields: Option<Vec<String>>,
    pub time_basis: FirewallTimeBasis,
    rejected_fields: Vec<String>,
}
impl FirewallContext {
    /// Install only complete physical directives; the stream owns their termination.
    pub fn directive(&mut self, line: &str) -> bool {
        let line = line.trim();
        if !line.starts_with('#') {
            return false;
        }
        if let Some((name, value)) = line[1..].split_once(':') {
            let value = value.trim();
            if name.eq_ignore_ascii_case("Software") {
                *self = Self::default();
            } else if name.eq_ignore_ascii_case("Time Format") {
                self.time_basis = if value.eq_ignore_ascii_case("Local") {
                    FirewallTimeBasis::Local
                } else if value.eq_ignore_ascii_case("UTC") {
                    FirewallTimeBasis::Utc
                } else {
                    FirewallTimeBasis::Unknown
                };
            } else if name.eq_ignore_ascii_case("Fields") {
                self.declared_fields = None;
                self.rejected_fields.clear();
                // Do not retain an oversized header even for direct callers.
                if line.len() > MAX_FIREWALL_LINE_BYTES {
                    return true;
                }
                let fields: Vec<String> = value.split_whitespace().map(str::to_owned).collect();
                let mut seen = HashSet::new();
                let valid = !fields.is_empty()
                    && fields.iter().all(|f| {
                        f.bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                            && seen.insert(f.to_ascii_lowercase())
                    });
                if valid {
                    self.declared_fields = Some(fields);
                } else {
                    self.rejected_fields = fields;
                }
            }
        }
        true
    }
}

fn stamp(date: &str, time: &str) -> Option<NaiveDateTime> {
    if date.len() != 10 || time.len() != 8 {
        return None;
    }
    NaiveDateTime::parse_from_str(&format!("{date} {time}"), "%Y-%m-%d %H:%M:%S").ok()
}
fn number_or_hyphen(s: &str) -> bool {
    s == "-" || (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
}
fn canonical(tokens: &[&str]) -> bool {
    if !matches!(tokens.len(), 17 | 18) || stamp(tokens[0], tokens[1]).is_none() {
        return false;
    }
    let loss = tokens[2] == "INFO-EVENTS-LOST";
    if !matches!(tokens[2], "ALLOW" | "DROP" | "INFO-EVENTS-LOST") {
        return false;
    }
    let protocol = tokens[3];
    if !(matches!(
        protocol,
        "TCP" | "UDP" | "ICMP" | "ICMPV6" | "ICMPv6" | "IPv6"
    ) || protocol.parse::<u8>().is_ok()
        || (loss && protocol == "-"))
    {
        return false;
    }
    if !tokens[4..6]
        .iter()
        .all(|s| *s == "-" || s.parse::<IpAddr>().is_ok())
    {
        return false;
    }
    if ![6, 7, 8, 10, 11, 12, 13, 14]
        .iter()
        .all(|&i| number_or_hyphen(tokens[i]))
    {
        return false;
    }
    if tokens.len() == 18 && !number_or_hyphen(tokens[17]) {
        return false;
    }
    tokens[9]
        .bytes()
        .all(|b| b.is_ascii_alphabetic() || b == b'-')
        && matches!(tokens[16], "SEND" | "RECEIVE" | "FORWARD" | "-")
}

/// Bounded meaningful-text probe; skips leading NUL padding without copying it.
pub fn probe(content: &str) -> bool {
    probe_measured(content).0
}

fn probe_measured(content: &str) -> (bool, usize) {
    let mut scanned = 0;
    let mut cursor = 0;
    let mut meaningful = 0;
    let bytes = content.as_bytes();
    while cursor < bytes.len() && meaningful < MAX_PROBE_LINES {
        // Only leading NUL padding is exempt from the work budget. Inspect
        // ordinary text byte by byte so a huge physical line cannot bypass it.
        while bytes.get(cursor) == Some(&0) {
            cursor += 1;
        }
        let start = cursor;
        while cursor < bytes.len() && bytes[cursor] != b'\n' {
            if scanned == MAX_FIREWALL_LINE_BYTES {
                return (false, scanned);
            }
            cursor += 1;
            scanned += 1;
        }
        // We only slice at a physical boundary; a budget hit inside a UTF-8
        // scalar returns above without constructing an invalid string slice.
        let line = &content[start..cursor];
        if cursor < bytes.len() {
            if scanned == MAX_FIREWALL_LINE_BYTES {
                return (false, scanned);
            }
            cursor += 1;
            scanned += 1;
        }
        if line.trim().is_empty() {
            continue;
        }
        meaningful += 1;
        let trimmed = line.trim();
        if let Some((key, value)) = trimmed.strip_prefix('#').and_then(|s| s.split_once(':')) {
            if key.eq_ignore_ascii_case("Software")
                && value
                    .trim()
                    .eq_ignore_ascii_case("Microsoft Windows Firewall")
            {
                return (true, scanned);
            }
            if key.eq_ignore_ascii_case("Fields") {
                let mut c = FirewallContext::default();
                c.directive(trimmed);
                if let Some(fields) = c.declared_fields {
                    let required = &CANONICAL_FIELDS[..8];
                    if required
                        .iter()
                        .all(|required| fields.iter().any(|f| f.eq_ignore_ascii_case(required)))
                        && !fields.iter().any(|f| {
                            f.eq_ignore_ascii_case("cs-method")
                                || f.eq_ignore_ascii_case("cs-uri-stem")
                        })
                    {
                        return (true, scanned);
                    }
                }
            }
        } else if canonical(&trimmed.split_whitespace().collect::<Vec<_>>()) {
            return (true, scanned);
        }
    }
    (false, scanned)
}

pub struct FirewallRecordResult {
    pub entry: LogEntry,
    pub coverage: FirewallCoverage,
}

fn endpoint(ip: Option<&str>, port: Option<&str>) -> String {
    let ip = ip.unwrap_or("-");
    match port.filter(|s| *s != "-") {
        Some(port) if ip.contains(':') => format!("[{ip}]:{port}"),
        Some(port) => format!("{ip}:{port}"),
        None => ip.to_owned(),
    }
}

pub fn parse_record(
    line: &str,
    context: &FirewallContext,
    id: u64,
    line_number: u32,
    file_path: &str,
) -> FirewallRecordResult {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    let canonical_fields;
    let (declared, origin) = if let Some(fields) = context.declared_fields.as_ref() {
        (fields.as_slice(), FirewallSchemaOrigin::Header)
    } else if canonical(&tokens) {
        canonical_fields = CANONICAL_FIELDS[..tokens.len()]
            .iter()
            .map(|s| (*s).to_owned())
            .collect::<Vec<_>>();
        (canonical_fields.as_slice(), FirewallSchemaOrigin::Canonical)
    } else {
        (
            context.rejected_fields.as_slice(),
            FirewallSchemaOrigin::Unavailable,
        )
    };
    let action_pos = declared
        .iter()
        .position(|f| f.eq_ignore_ascii_case("action"));
    let is_loss = action_pos.and_then(|i| tokens.get(i)) == Some(&"INFO-EVENTS-LOST");
    let missing_final_pid = is_loss
        && declared
            .last()
            .is_some_and(|f| f.eq_ignore_ascii_case("pid"))
        && tokens.len() + 1 == declared.len();
    let mapped = origin != FirewallSchemaOrigin::Unavailable
        && (tokens.len() == declared.len() || missing_final_pid)
        && !line.contains('\0');
    let fields = if mapped {
        declared
            .iter()
            .enumerate()
            .map(|(i, name)| FirewallField {
                name: name.clone(),
                value: tokens.get(i).map(|s| (*s).to_owned()),
            })
            .collect()
    } else {
        Vec::new()
    };
    let record = FirewallRecord {
        raw_line: line.to_owned(),
        declared_fields: declared.to_vec(),
        fields,
        schema_origin: origin,
        time_basis: context.time_basis,
        record_kind: if !mapped {
            FirewallRecordKind::Malformed
        } else if is_loss {
            FirewallRecordKind::EventsLost
        } else {
            FirewallRecordKind::Traffic
        },
        truncated: false,
    };
    let display = match (record.field("date"), record.field("time")) {
        (Some(date), Some(time)) => Some(format!(
            "{date} {time}{}",
            if context.time_basis == FirewallTimeBasis::Utc {
                " UTC"
            } else {
                ""
            }
        )),
        _ => None,
    };
    let timestamp = if context.time_basis == FirewallTimeBasis::Utc {
        record
            .field("date")
            .zip(record.field("time"))
            .and_then(|(d, t)| stamp(d, t))
            .map(|t| t.and_utc().timestamp_millis())
    } else {
        None
    };
    let mut coverage = FirewallCoverage::default();
    if timestamp.is_none() {
        coverage.unplaced_timestamps.add(1, line_number);
    }
    let (message, severity) = match record.record_kind {
        FirewallRecordKind::Malformed => {
            coverage.malformed.add(1, line_number);
            (format!("Unparsed firewall record: {line}"), Severity::Info)
        }
        FirewallRecordKind::EventsLost => {
            coverage.loss_events.add(1, line_number);
            let count = record.field("info").and_then(|s| s.parse::<u64>().ok());
            if let Some(n) = count {
                coverage.lost_events.add(n, line_number);
            } else {
                coverage.unknown_loss_count.add(1, line_number);
            }
            (
                count
                    .map(|n| format!("INFO-EVENTS-LOST: {n} events lost"))
                    .unwrap_or_else(|| "INFO-EVENTS-LOST: loss count unavailable".into()),
                Severity::Warning,
            )
        }
        FirewallRecordKind::Traffic => (
            format!(
                "{} {} {} → {} ({})",
                record.field("action").unwrap_or("-"),
                record.field("protocol").unwrap_or("-"),
                endpoint(record.field("src-ip"), record.field("src-port")),
                endpoint(record.field("dst-ip"), record.field("dst-port")),
                record.field("path").unwrap_or("-")
            ),
            Severity::Info,
        ),
    };
    FirewallRecordResult {
        entry: LogEntry {
            id,
            line_number,
            message,
            timestamp,
            timestamp_display: display,
            severity,
            timezone_offset: timestamp.map(|_| 0),
            format: LogFormat::Timestamped,
            file_path: file_path.to_owned(),
            firewall: Some(record),
            ..Default::default()
        },
        coverage,
    }
}

#[cfg(test)]
mod probe_tests {
    use super::*;

    #[test]
    fn probe_stops_within_an_oversized_physical_line() {
        for prefix in ["x".repeat(2 * 1024 * 1024), " ".repeat(2 * 1024 * 1024)] {
            let content = format!("{prefix}\n#Software: Microsoft Windows Firewall\n");
            let (found, inspected_text_bytes) = probe_measured(&content);
            assert!(!found);
            assert!(
                inspected_text_bytes <= MAX_FIREWALL_LINE_BYTES,
                "inspected {inspected_text_bytes} non-padding bytes"
            );
        }
    }
}
