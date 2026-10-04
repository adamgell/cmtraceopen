pub mod burn;
pub mod cbs;
pub mod ccm;
pub mod cmtlog;
pub mod detect;
pub mod dhcp;
pub mod dism;
pub mod dns_debug;
pub mod dns_types;
pub mod iis_w3c;
pub mod intune_macos;
pub mod msi;
pub mod panther;
pub mod patchmypc_detection;
pub mod plain;
pub mod psadt;
pub mod registry;
pub mod reporting_events;
pub mod secureboot_log;
pub mod severity;
pub mod simple;
pub mod timestamped;

use crate::{
    intune::device::windows::inventory::{self, DeviceInventoryLogDialect},
    models::log_entry::{LogEntry, ParseResult, ParserSpecialization},
};
use chrono::{Local, LocalResult, NaiveDateTime, TimeZone};
use std::path::Path;

/// Post-process parsed entries to detect error code spans in messages.
pub fn annotate_error_code_spans(entries: &mut [LogEntry]) {
    for entry in entries.iter_mut() {
        let spans = crate::error_db::lookup::detect_error_code_spans(&entry.message);
        if !spans.is_empty() {
            entry.error_code_spans = spans;
        }
    }
}

/// Interpret a zoneless wall-clock timestamp that the source wrote on the
/// machine it was captured from.
///
/// CBS.log and dism.log record the servicing host's clock with no offset. Their
/// text is therefore a local wall clock, and reading it as UTC invents a zone
/// the file never carried: every epoch consumer (sorting, ranges, elapsed) then
/// disagrees with the timestamp text the same record renders by exactly the
/// machine's offset. Resolving through `Local` keeps the epoch and the rendered
/// record on one wall clock.
///
/// Two wall clocks a zone cannot place resolve to `None`, and the record keeps
/// its text with no epoch: a clock inside a DST gap that the probes below cannot
/// bound, and a clock a fall-back transition repeats. Both are genuinely
/// ambiguous from the stamp alone. Choosing an occurrence would be a guess: a
/// gap or repeated hour is either read with a neighbouring offset, which orders
/// it before the records that led up to it or after the ones that follow, or
/// carried from record to record, which either drags an hour of records forward
/// on a small stamp inversion between writer threads or steps backwards across a
/// sparse interval inside the repeated hour. A missing epoch is visible to every
/// consumer; a wrong one is not.
pub(crate) fn local_wall_clock_millis(naive: NaiveDateTime) -> Option<i64> {
    match naive.and_local_timezone(Local) {
        LocalResult::Single(value) => Some(value.timestamp_millis()),
        LocalResult::Ambiguous(..) => None,
        LocalResult::None => gap_transition_millis(naive),
    }
}

/// The first instant the local zone can represent at or after `naive`, for a
/// wall clock that falls inside a DST gap.
///
/// Returns `None` when the gap is wider than the probe window, which leaves the
/// zone's own boundary unresolvable from the offsets alone.
fn gap_transition_millis(naive: NaiveDateTime) -> Option<i64> {
    let hour = chrono::Duration::hours(1);
    let before = (naive - hour).and_local_timezone(Local).earliest()?;
    let after = (naive + hour).and_local_timezone(Local).earliest()?;
    let post_gap_offset = *after.offset();

    // Equal offsets mean the window holds no boundary to find, so the bisection
    // below would converge on a wrong instant.
    if *before.offset() == post_gap_offset {
        return None;
    }

    let mut low = before.timestamp_millis();
    let mut high = after.timestamp_millis();
    while high - low > 1 {
        let middle = low + (high - low) / 2;
        match Local.timestamp_millis_opt(middle).single() {
            Some(value) if *value.offset() == post_gap_offset => high = middle,
            _ => low = middle,
        }
    }

    Some(high)
}

pub use detect::ResolvedParser;

/// Result of parsing a single batch of records with a preselected parser.
pub struct ParsedChunk {
    pub entries: Vec<LogEntry>,
    pub total_lines: u32,
    pub parse_errors: u32,
}

/// Parse log content that has already been read into memory, auto-detecting its format.
///
/// `file_path` is used only for display/provenance and by format detection heuristics
/// (e.g. extension-based hints) — no filesystem I/O is performed. `file_size` is the
/// source file size in bytes and is passed through to `ParseResult`; callers that do
/// not have a source file (e.g. pasted content) may pass `content.len() as u64`.
///
/// Native-only concerns (reading file bytes, decoding EVTX event logs, etc.) live in
/// the src-tauri parser shim on top of this pure entry point.
pub fn parse_content(
    content: &str,
    file_path: &str,
    file_size: u64,
) -> (ParseResult, ResolvedParser) {
    let path_obj = Path::new(file_path);
    let selection = detect::detect_parser(file_path, content);
    let parsed_chunk = parse_content_with_selection(content, file_path, &selection);

    let result = ParseResult {
        entries: parsed_chunk.entries,
        format_detected: selection.compatibility_format(),
        parser_selection: selection.to_info(),
        total_lines: parsed_chunk.total_lines,
        parse_errors: parsed_chunk.parse_errors,
        file_path: path_obj.to_string_lossy().to_string(),
        file_size,
        // No file was read here, so there is no modified time to report.
        modified_unix_ms: None,
        byte_offset: file_size,
    };

    (result, selection)
}

/// Parse already-split lines using the backend-owned parser selection.
pub fn parse_lines_with_selection(
    lines: &[&str],
    file_path: &str,
    selection: &ResolvedParser,
) -> (Vec<LogEntry>, u32) {
    let (mut entries, parse_errors) = match selection.implementation {
        crate::models::log_entry::ParserImplementation::Ccm => {
            ccm::parse_lines_with_specialization(lines, file_path, selection.specialization)
        }
        crate::models::log_entry::ParserImplementation::Simple => {
            simple::parse_lines(lines, file_path)
        }
        crate::models::log_entry::ParserImplementation::IisW3c => {
            iis_w3c::parse_lines(lines, file_path)
        }
        crate::models::log_entry::ParserImplementation::ReportingEvents => {
            reporting_events::parse_lines(lines, file_path)
        }
        crate::models::log_entry::ParserImplementation::PlainText => {
            plain::parse_lines(lines, file_path)
        }
        crate::models::log_entry::ParserImplementation::Msi => msi::parse_lines(lines, file_path),
        crate::models::log_entry::ParserImplementation::PsadtLegacy => {
            psadt::parse_lines(lines, file_path)
        }
        crate::models::log_entry::ParserImplementation::IntuneMacOs => {
            intune_macos::parse_lines(lines, file_path)
        }
        crate::models::log_entry::ParserImplementation::IntuneDeviceInventory => {
            // A Device Inventory selection normally carries the dialect that
            // detection resolved. A selection that arrives without one is
            // malformed rather than impossible — it can only reach here from a
            // hand-built `ResolvedParser` or a future override surface — so it
            // degrades to the generic timestamped reading instead of panicking
            // the whole parse. All three dialects are timestamp-led, so the
            // fallback still produces usable records.
            match device_inventory_dialect(selection.specialization) {
                Some(dialect) => inventory::parse_lines(file_path, lines, dialect),
                None => timestamped::parse_lines(lines, file_path, selection.date_order),
            }
        }
        crate::models::log_entry::ParserImplementation::Dhcp => dhcp::parse_lines(lines, file_path),
        crate::models::log_entry::ParserImplementation::Burn => burn::parse_lines(lines, file_path),
        crate::models::log_entry::ParserImplementation::PatchMyPcDetection => {
            patchmypc_detection::parse_lines(lines, file_path)
        }
        crate::models::log_entry::ParserImplementation::Registry => {
            // Registry files are parsed via a dedicated IPC command, not the log pipeline.
            (vec![], 0)
        }
        crate::models::log_entry::ParserImplementation::SecureBootLog => {
            secureboot_log::parse_lines(lines, file_path)
        }
        crate::models::log_entry::ParserImplementation::DnsDebug => {
            dns_debug::parse_lines(lines, file_path, selection.date_order)
        }
        crate::models::log_entry::ParserImplementation::DnsAudit => {
            // EVTX files are parsed via the binary path in parse_file(), not the line-based pipeline.
            // SecureBootLog has its own dedicated IPC command; not routed through this pipeline.
            (vec![], 0)
        }
        crate::models::log_entry::ParserImplementation::CmtLog => {
            cmtlog::parse_lines(lines, file_path)
        }
        crate::models::log_entry::ParserImplementation::CompanyPortal => {
            crate::intune::portal::windows::company_portal::logs::parse_lines(lines, file_path)
        }
        crate::models::log_entry::ParserImplementation::GenericTimestamped => {
            match selection.parser {
                crate::models::log_entry::ParserKind::Cbs => cbs::parse_lines(lines, file_path),
                crate::models::log_entry::ParserKind::Dism => dism::parse_lines(lines, file_path),
                crate::models::log_entry::ParserKind::Panther => {
                    panther::parse_lines(lines, file_path)
                }
                _ => timestamped::parse_lines(lines, file_path, selection.date_order),
            }
        }
    };
    annotate_error_code_spans(&mut entries);
    (entries, parse_errors)
}

/// Parse text content using the backend-owned parser selection.
pub fn parse_content_with_selection(
    content: &str,
    file_path: &str,
    selection: &ResolvedParser,
) -> ParsedChunk {
    let total_lines = content.lines().count() as u32;
    let (mut entries, parse_errors) = match selection.implementation {
        crate::models::log_entry::ParserImplementation::Ccm => {
            ccm::parse_content(content, file_path, selection.specialization)
        }
        // See the matching arm in `parse_lines_with_selection`: a Device
        // Inventory selection missing its dialect degrades to the generic
        // timestamped reading rather than panicking.
        crate::models::log_entry::ParserImplementation::IntuneDeviceInventory
            if device_inventory_dialect(selection.specialization).is_some() =>
        {
            inventory::parse_content(
                file_path,
                content,
                device_inventory_dialect(selection.specialization)
                    .expect("guarded by the match arm above"),
            )
        }
        _ => {
            let lines: Vec<&str> = content.lines().collect();
            parse_lines_with_selection(&lines, file_path, selection)
        }
    };
    // For whole-content parse paths (which don't go through
    // parse_lines_with_selection), ensure error code spans are annotated. The
    // Device Inventory arm only takes that path when it resolved a dialect; a
    // dialect-less selection fell through to parse_lines_with_selection, which
    // already annotated.
    let used_whole_content_path = match selection.implementation {
        crate::models::log_entry::ParserImplementation::Ccm => true,
        crate::models::log_entry::ParserImplementation::IntuneDeviceInventory => {
            device_inventory_dialect(selection.specialization).is_some()
        }
        _ => false,
    };
    if used_whole_content_path {
        annotate_error_code_spans(&mut entries);
    }

    ParsedChunk {
        entries,
        total_lines,
        parse_errors,
    }
}

fn device_inventory_dialect(
    specialization: Option<ParserSpecialization>,
) -> Option<DeviceInventoryLogDialect> {
    match specialization {
        Some(ParserSpecialization::IntuneDeviceInventoryHarvester) => {
            Some(DeviceInventoryLogDialect::Harvester)
        }
        Some(ParserSpecialization::IntuneDeviceInventoryAdaptor) => {
            Some(DeviceInventoryLogDialect::InventoryAdaptor)
        }
        Some(ParserSpecialization::IntuneDeviceInventoryRotationFailure) => {
            Some(DeviceInventoryLogDialect::RotationFailure)
        }
        _ => None,
    }
}

/// Encoding detected from file BOM, used for both initial read and tailing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileEncoding {
    Utf8,
    Utf16Le,
    Utf16Be,
}

/// Detect encoding from the leading bytes of a file.
pub fn detect_encoding(bytes: &[u8]) -> FileEncoding {
    if bytes.starts_with(&[0xFF, 0xFE]) {
        FileEncoding::Utf16Le
    } else if bytes.starts_with(&[0xFE, 0xFF]) {
        FileEncoding::Utf16Be
    } else {
        FileEncoding::Utf8
    }
}

/// Decode raw bytes to a String based on the detected encoding.
/// For UTF-16, also normalizes CRLF to LF.
pub fn decode_bytes(bytes: &[u8], encoding: FileEncoding) -> Result<String, String> {
    match encoding {
        FileEncoding::Utf16Le => {
            let data = if bytes.starts_with(&[0xFF, 0xFE]) {
                &bytes[2..]
            } else {
                bytes
            };
            let (cow, _, had_errors) = encoding_rs::UTF_16LE.decode(data);
            if had_errors {
                log::warn!("Encoding errors during UTF-16LE decode");
            }
            Ok(cow.into_owned().replace("\r\n", "\n"))
        }
        FileEncoding::Utf16Be => {
            let data = if bytes.starts_with(&[0xFE, 0xFF]) {
                &bytes[2..]
            } else {
                bytes
            };
            let (cow, _, had_errors) = encoding_rs::UTF_16BE.decode(data);
            if had_errors {
                log::warn!("Encoding errors during UTF-16BE decode");
            }
            Ok(cow.into_owned().replace("\r\n", "\n"))
        }
        FileEncoding::Utf8 => {
            let bytes_no_bom = if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
                &bytes[3..]
            } else {
                bytes
            };
            match std::str::from_utf8(bytes_no_bom) {
                Ok(s) => Ok(s.to_string()),
                Err(_) => {
                    let (cow, _, had_errors) = encoding_rs::WINDOWS_1252.decode(bytes_no_bom);
                    if had_errors {
                        log::warn!("Encoding errors during Windows-1252 fallback decode");
                    }
                    Ok(cow.into_owned())
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::log_entry::{
        ParseQuality, ParserImplementation, ParserKind, ParserProvenance, ParserSpecialization,
        RecordFraming,
    };
    use crate::parser::timestamped::DateOrder;
    use chrono::TimeZone;

    #[test]
    fn test_parse_lines_with_selection_uses_timestamp_date_order() {
        let selection = ResolvedParser::generic_timestamped(DateOrder::DayFirst);
        let lines = ["15/01/2024 08:00:00 Processing request"];

        let (entries, parse_errors) = parse_lines_with_selection(&lines, "sample.log", &selection);

        assert_eq!(parse_errors, 0);
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].timestamp_display.as_deref(),
            Some("2024-01-15 08:00:00.000")
        );
    }

    #[test]
    fn test_parse_lines_with_selection_can_use_panther_selection() {
        let selection = ResolvedParser::new(
            ParserKind::Panther,
            ParserImplementation::GenericTimestamped,
            ParserProvenance::Dedicated,
            ParseQuality::SemiStructured,
            RecordFraming::LogicalRecord,
            DateOrder::MonthFirst,
            None,
        );
        let lines = ["2024-01-15 08:00:00, Info SP Setup complete"];

        let (entries, parse_errors) =
            parse_lines_with_selection(&lines, "setupact.log", &selection);

        assert_eq!(parse_errors, 0);
        assert_eq!(entries.len(), 1);
        assert_eq!(
            selection.compatibility_format(),
            crate::models::log_entry::LogFormat::Timestamped
        );
        assert_eq!(entries[0].message, "Setup complete");
        assert_eq!(entries[0].component.as_deref(), Some("SP"));
    }

    #[test]
    fn test_parse_lines_with_selection_can_use_cbs_selection() {
        let selection = ResolvedParser::new(
            ParserKind::Cbs,
            ParserImplementation::GenericTimestamped,
            ParserProvenance::Dedicated,
            ParseQuality::SemiStructured,
            RecordFraming::LogicalRecord,
            DateOrder::MonthFirst,
            None,
        );
        let lines = [
            "2024-01-15 08:00:00, Info                  CBS    Exec: Started servicing",
            "Continuation detail",
        ];

        let (entries, parse_errors) = parse_lines_with_selection(&lines, "CBS.log", &selection);

        assert_eq!(parse_errors, 0);
        assert_eq!(entries.len(), 1);
        assert_eq!(
            selection.compatibility_format(),
            crate::models::log_entry::LogFormat::Timestamped
        );
        assert_eq!(entries[0].component.as_deref(), Some("CBS"));
        assert_eq!(
            entries[0].message,
            "Exec: Started servicing\nContinuation detail"
        );
    }

    #[test]
    fn test_parse_lines_with_selection_can_use_dism_selection() {
        let selection = ResolvedParser::new(
            ParserKind::Dism,
            ParserImplementation::GenericTimestamped,
            ParserProvenance::Dedicated,
            ParseQuality::SemiStructured,
            RecordFraming::LogicalRecord,
            DateOrder::MonthFirst,
            None,
        );
        let lines = [
            "2024-01-15 08:00:00, Warning               DISM   DISM Package Manager: Retry needed",
            "Extra context",
        ];

        let (entries, parse_errors) = parse_lines_with_selection(&lines, "DISM.log", &selection);

        assert_eq!(parse_errors, 0);
        assert_eq!(entries.len(), 1);
        assert_eq!(
            selection.compatibility_format(),
            crate::models::log_entry::LogFormat::Timestamped
        );
        assert_eq!(entries[0].component.as_deref(), Some("DISM"));
        assert_eq!(
            entries[0].message,
            "DISM Package Manager: Retry needed\nExtra context"
        );
    }

    #[test]
    fn test_parse_lines_with_selection_can_use_reporting_events_selection() {
        let selection = ResolvedParser::new(
            ParserKind::ReportingEvents,
            ParserImplementation::ReportingEvents,
            ParserProvenance::Dedicated,
            ParseQuality::Structured,
            RecordFraming::PhysicalLine,
            DateOrder::MonthFirst,
            None,
        );
        let lines = [
            "{11111111-1111-1111-1111-111111111111}\t2024-01-15 08:00:00:123-0500\t1\t183\t[AGENT_INSTALLING_SUCCEEDED]\t101\t{22222222-2222-2222-2222-222222222222}\t1\t80240022\tWindows Update Agent\tFailure\tContent Install\tInstallation failed for KB5034123\tAAAAAAAAAAAAAAAA.1.0.0.3.0",
        ];

        let (entries, parse_errors) =
            parse_lines_with_selection(&lines, "ReportingEvents.log", &selection);

        assert_eq!(parse_errors, 0);
        assert_eq!(entries.len(), 1);
        assert_eq!(
            selection.compatibility_format(),
            crate::models::log_entry::LogFormat::Timestamped
        );
        assert_eq!(
            entries[0].component.as_deref(),
            Some("Windows Update Agent")
        );
        assert_eq!(
            entries[0].severity,
            crate::models::log_entry::Severity::Error
        );
    }

    #[test]
    fn test_parse_lines_with_selection_can_use_ime_specialization() {
        let selection = ResolvedParser::new(
            ParserKind::Ccm,
            ParserImplementation::Ccm,
            ParserProvenance::Dedicated,
            ParseQuality::Structured,
            RecordFraming::LogicalRecord,
            DateOrder::MonthFirst,
            Some(ParserSpecialization::Ime),
        );
        let lines = [
            r#"<![LOG[Powershell execution is done, exitCode = 1]LOG]!><time="11:16:37.3093207" date="3-12-2026" component="HealthScripts" context="" type="1" thread="50" file="">"#,
            r#"<![LOG[[HS] err output = Downloaded profile payload is not valid JSON."#,
            r#"At C:\Windows\IMECache\HealthScripts\script.ps1:457 char:9"#,
            r#"]LOG]!><time="11:16:42.3322734" date="3-12-2026" component="HealthScripts" context="" type="1" thread="50" file="">"#,
        ];

        let (entries, parse_errors) =
            parse_lines_with_selection(&lines, "HealthScripts.log", &selection);

        assert_eq!(parse_errors, 0);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].line_number, 1);
        assert_eq!(entries[1].line_number, 2);
        assert!(entries[1]
            .message
            .contains("Downloaded profile payload is not valid JSON"));
        assert!(entries[1]
            .message
            .contains("At C:\\Windows\\IMECache\\HealthScripts\\script.ps1:457 char:9"));
    }

    #[test]
    fn test_parse_content_with_selection_can_use_ime_specialization() {
        let selection = ResolvedParser::new(
            ParserKind::Ccm,
            ParserImplementation::Ccm,
            ParserProvenance::Dedicated,
            ParseQuality::Structured,
            RecordFraming::LogicalRecord,
            DateOrder::MonthFirst,
            Some(ParserSpecialization::Ime),
        );
        let content = concat!(
            "<![LOG[Client Health evaluation starts.]LOG]!><time=\"23:00:10.6893636\" date=\"11-12-2025\" component=\"ClientHealth\" context=\"\" type=\"1\" thread=\"1\" file=\"\">\n",
            "<![LOG[Set MdmDeviceCertificate : 3788C1E384FDCB3F173A3222CB4191883A94224E\n",
            "More detail]LOG]!><time=\"23:00:11.4573058\" date=\"11-12-2025\" component=\"ClientHealth\" context=\"\" type=\"3\" thread=\"1\" file=\"\">"
        );

        let parsed = parse_content_with_selection(content, "ClientHealth.log", &selection);

        assert_eq!(parsed.total_lines, 3);
        assert_eq!(parsed.parse_errors, 0);
        assert_eq!(parsed.entries.len(), 2);
        assert_eq!(
            parsed.entries[0].format,
            crate::models::log_entry::LogFormat::Ccm
        );
        assert_eq!(parsed.entries[1].line_number, 2);
        assert_eq!(
            parsed.entries[1].severity,
            crate::models::log_entry::Severity::Error
        );
        assert!(parsed.entries[1].message.contains("More detail"));
    }

    #[test]
    fn test_parse_content_with_selection_keeps_non_ime_ccm_physical_line_behavior() {
        let selection = ResolvedParser::ccm();
        let content = concat!(
            "<![LOG[Normal CCM record]LOG]!><time=\"08:00:00.000+000\" date=\"01-01-2024\" component=\"Test\" context=\"\" type=\"1\" thread=\"100\" file=\"\">\n",
            "Continuation that should remain a plain fallback line"
        );

        let parsed = parse_content_with_selection(content, "sample.log", &selection);

        assert_eq!(parsed.total_lines, 2);
        assert_eq!(parsed.parse_errors, 1);
        assert_eq!(parsed.entries.len(), 2);
        assert_eq!(
            parsed.entries[0].format,
            crate::models::log_entry::LogFormat::Ccm
        );
        assert_eq!(
            parsed.entries[1].format,
            crate::models::log_entry::LogFormat::Plain
        );
        assert_eq!(parsed.entries[1].line_number, 2);
    }

    #[test]
    fn test_parsed_entries_have_error_spans() {
        let content = r#"<![LOG[Installation failed with error 0x80070005 access denied]LOG]!><time="10:00:00.000+000" date="01-01-2024" component="TestComp" context="" type="3" thread="1234" file="">"#;
        let selection = ResolvedParser::ccm();
        let parsed = parse_content_with_selection(content, "test.log", &selection);
        assert_eq!(parsed.entries.len(), 1);
        assert!(!parsed.entries[0].error_code_spans.is_empty());
        assert_eq!(parsed.entries[0].error_code_spans[0].code_hex, "0x80070005");
    }

    #[test]
    fn test_local_wall_clock_millis_keeps_the_clock_the_source_wrote() {
        let naive =
            NaiveDateTime::parse_from_str("2024-01-15 08:00:00", "%Y-%m-%d %H:%M:%S").unwrap();

        let millis = local_wall_clock_millis(naive).expect("wall clock resolves");

        // The epoch renders back to the wall clock the record carried, which is
        // what keeps the Date/Time column and the epoch consumers (Time Range,
        // sorting, elapsed) in agreement (#657).
        let rendered = Local
            .timestamp_millis_opt(millis)
            .single()
            .expect("local instant");
        assert_eq!(rendered.naive_local(), naive);

        // The zone this instant actually sits in decides whether the two
        // readings can be told apart: a zone that happened to sit on UTC that
        // day (London in January) cannot.
        if rendered.offset().local_minus_utc() != 0 {
            assert_ne!(millis, naive.and_utc().timestamp_millis());
        }
    }

    #[test]
    fn test_local_wall_clock_millis_keeps_a_skipped_clock_in_non_decreasing_order() {
        // A spring-forward gap is the one reading no zone can resolve. The
        // epoch order around the transition must still be non-decreasing, or a
        // chronological merge places a gap record after a later wall clock.
        let wall_clocks = [
            "2024-03-10 01:30:00", // before the US transition
            "2024-03-10 02:30:00", // inside it, where US zones skip an hour
            "2024-03-10 03:00:00", // after it
            "2024-03-10 04:00:00",
        ];
        let epochs: Vec<i64> = wall_clocks
            .iter()
            .map(|text| {
                let naive =
                    NaiveDateTime::parse_from_str(text, "%Y-%m-%d %H:%M:%S").expect("wall clock");
                local_wall_clock_millis(naive).expect("wall clock resolves")
            })
            .collect();

        assert!(
            epochs.windows(2).all(|pair| pair[0] <= pair[1]),
            "{wall_clocks:?} produced {epochs:?}"
        );
    }

    #[test]
    fn test_a_repeated_wall_clock_reports_no_epoch() {
        // A fall-back transition makes 01:30 happen twice. The stamp cannot say
        // which pass it belongs to, so no epoch is asserted: the record keeps
        // its text and the gap stays visible instead of being placed an hour
        // from the truth in silence.
        let naive =
            NaiveDateTime::parse_from_str("2024-11-03 01:30:00", "%Y-%m-%d %H:%M:%S").unwrap();
        let repeated = matches!(naive.and_local_timezone(Local), LocalResult::Ambiguous(..));

        let resolved = local_wall_clock_millis(naive);

        if repeated {
            assert_eq!(
                resolved, None,
                "a wall clock the zone repeats must not be given an epoch"
            );
        } else {
            assert!(
                resolved.is_some(),
                "a zone without that transition resolves the wall clock"
            );
        }
    }

    #[test]
    fn test_an_unrepeated_wall_clock_still_reports_an_epoch() {
        let naive =
            NaiveDateTime::parse_from_str("2024-01-15 08:00:00", "%Y-%m-%d %H:%M:%S").unwrap();
        assert!(local_wall_clock_millis(naive).is_some());
    }

    #[test]
    fn test_parse_lines_with_dns_debug_selection() {
        let selection = ResolvedParser::dns_debug(DateOrder::MonthFirst);
        let lines = [
            "4/11/2026 3:29:17 PM 0294 PACKET  000002DAEC36D650 UDP Rcv 127.0.0.1       d07e   Q [0001   D   NOERROR] SOA    (4)home(4)gell(3)one(0)",
            "4/11/2026 3:29:17 PM 0294 PACKET  000002DAEC36D650 UDP Snd 127.0.0.1       d07e R Q [8085 A DR  NOERROR] SOA    (4)home(4)gell(3)one(0)",
        ];

        let (entries, parse_errors) = parse_lines_with_selection(&lines, "dns.log", &selection);

        assert_eq!(parse_errors, 0);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].query_name.as_deref(), Some("home.gell.one"));
        assert_eq!(
            entries[0].format,
            crate::models::log_entry::LogFormat::DnsDebug
        );
    }
}
