use cmtraceopen_parser::{
    intune::device::windows::inventory::{
        detect_dialect, frame_logical_records, parse_content, parse_lines,
        DeviceInventoryLogDialect, LogicalRecordSegment, MAX_LOGICAL_RECORD_BYTES,
    },
    models::log_entry::{
        LogEntry, LogFormat, ParseQuality, ParserImplementation, ParserKind, ParserProvenance,
        ParserSpecialization, RecordFraming, Severity,
    },
    parser::{
        detect::ResolvedParser, parse_content as parse_with_dispatcher,
        parse_content_with_selection, parse_lines_with_selection, timestamped::DateOrder,
    },
};

const HARVESTER: &str = "7/30/2026 6:00:53 AM [Information] Completed harvesting signed policies: 118 succeeded, 0 failed to collect.\n7/30/2026 10:08:52 AM [Warning] Reporting dropped attribute error for ExampleField: ErrorCode=404.\n7/30/2026 10:08:53 AM [Error] Harvester error code: 404, Message: ExampleField result is null.";

const ADAPTOR: &str = "[Thu Jul 30 13:05:01 2026][8604] - Adapter result:\n{\"Status\":200,\"HResult\":\"0x00000000\",\"Data\":{\"Example\":\"value\"}}\n[Thu Jul 30 13:05:03 2026][8604] - Completed action with HRESULT 0x0, MI_Result 0x0.";

const ROTATION_FAILURE: &str = "2026-07-30T13:05:01.1234567-04:00 Failed to rotate Device Inventory log.\nSystem.IO.IOException: The process cannot access the file.\n   at Synthetic.Inventory.Rotate()";

const PARTIAL_ROTATION_FAILURE_HEADERS: [&str; 3] = [
    "2026-07-30T13:05:01.1234567-04:00 Failed to rollback transaction.",
    "2026-07-30T13:05:01.1234567-04:00 Rotation failedover to backup.",
    "2026-07-30T13:05:01.1234567-04:00 Failed to rotateCredentials.",
];

#[test]
fn parses_harvester_headers_with_direct_severity_mapping() {
    let (entries, parse_errors) = parse_content(
        "IntuneInventoryHarvesterLog.log",
        HARVESTER,
        DeviceInventoryLogDialect::Harvester,
    );

    assert_eq!(parse_errors, 0);
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].severity, Severity::Info);
    assert_eq!(
        entries[0].message,
        "Completed harvesting signed policies: 118 succeeded, 0 failed to collect."
    );
    assert_eq!(entries[1].severity, Severity::Warning);
    assert_eq!(entries[2].severity, Severity::Error);
    assert_eq!(entries[0].format, LogFormat::Timestamped);
    assert_eq!(entries[0].line_number, 1);
    assert!(entries[0].timestamp.is_some());
}

#[test]
fn frames_adaptor_json_as_part_of_its_logical_record() {
    let (entries, parse_errors) = parse_content(
        "InventoryAdaptor.log",
        ADAPTOR,
        DeviceInventoryLogDialect::InventoryAdaptor,
    );

    assert_eq!(parse_errors, 0);
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].thread, Some(8604));
    assert_eq!(entries[0].severity, Severity::Info);
    assert_eq!(
        entries[0].message,
        "Adapter result:\n{\"Status\":200,\"HResult\":\"0x00000000\",\"Data\":{\"Example\":\"value\"}}"
    );
    assert_eq!(
        entries[1].message,
        "Completed action with HRESULT 0x0, MI_Result 0x0."
    );
    assert_eq!(entries[1].format, LogFormat::Timestamped);
}

#[test]
fn frames_rotation_failure_exception_stack() {
    let (entries, parse_errors) = parse_content(
        "IntuneDeviceInventory.log",
        ROTATION_FAILURE,
        DeviceInventoryLogDialect::RotationFailure,
    );

    assert_eq!(parse_errors, 0);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].severity, Severity::Error);
    assert_eq!(
        entries[0].message,
        "Failed to rotate Device Inventory log.\nSystem.IO.IOException: The process cannot access the file.\n   at Synthetic.Inventory.Rotate()"
    );
    assert_eq!(entries[0].format, LogFormat::Timestamped);
    assert_eq!(entries[0].timezone_offset, Some(-240));
}

#[test]
fn detects_content_with_two_headers_or_a_matching_path_hint_but_never_path_alone() {
    let one_harvester_header =
        "7/30/2026 6:00:53 AM [Information] Completed harvesting signed policies: 118 succeeded, 0 failed to collect.";

    assert_eq!(
        detect_dialect("unrelated.log", HARVESTER),
        Some(DeviceInventoryLogDialect::Harvester)
    );
    assert_eq!(
        detect_dialect("IntuneInventoryHarvesterLog.log", one_harvester_header),
        Some(DeviceInventoryLogDialect::Harvester)
    );
    assert_eq!(detect_dialect("unrelated.log", one_harvester_header), None);
    assert_eq!(
        detect_dialect("IntuneInventoryHarvesterLog.log", "ordinary text"),
        None
    );
    assert_eq!(
        detect_dialect("unrelated.log", ADAPTOR),
        Some(DeviceInventoryLogDialect::InventoryAdaptor)
    );
    assert_eq!(
        detect_dialect("InventoryAdaptor.log", ADAPTOR.lines().next().unwrap()),
        Some(DeviceInventoryLogDialect::InventoryAdaptor)
    );
    assert_eq!(
        detect_dialect("unrelated.log", ROTATION_FAILURE),
        Some(DeviceInventoryLogDialect::RotationFailure)
    );
}

#[test]
fn rejects_generic_iso_timestamp_content_as_rotation_failure() {
    let generic_iso = "2026-07-30T13:05:01.1234567-04:00 Completed an unrelated service operation.";

    assert_eq!(detect_dialect("unrelated.log", generic_iso), None);
}

#[test]
fn generic_failure_prefixes_do_not_identify_rotation_failures() {
    let generic_failures = [
        "2026-07-30T13:05:01.1234567-04:00 Failed to load configuration.",
        "2026-07-30T13:05:01.1234567-04:00 Unhandled exception in service.",
    ];

    for path in ["unrelated.log", "IntuneDeviceInventory.log"] {
        for content in generic_failures {
            assert_eq!(
                detect_dialect(path, content),
                None,
                "generic failure prefix must not identify rotation for {path}: {content}"
            );
        }
    }
}

#[test]
fn partial_rotation_phrases_do_not_identify_rotation_failures() {
    for path in ["unrelated.log", "IntuneDeviceInventory.log"] {
        for content in PARTIAL_ROTATION_FAILURE_HEADERS {
            assert_eq!(
                detect_dialect(path, content),
                None,
                "partial rotation phrase must not identify rotation for {path}: {content}"
            );
        }
    }
}

#[test]
fn registered_rotation_failure_phrases_remain_detectable() {
    let registered_failures = [
        "2026-07-30T13:05:01.1234567-04:00 Failed to rotate Device Inventory log.",
        "2026-07-30T13:05:01.1234567-04:00 Device Inventory rotation failed.",
        "2026-07-30T13:05:01.1234567-04:00 Failed to roll Device Inventory log.",
        "2026-07-30T13:05:01.1234567-04:00 FAILED TO ROTATE",
        "2026-07-30T13:05:01.1234567-04:00 Device Inventory RoTaTiOn FaIlEd   ",
        "2026-07-30T13:05:01.1234567-04:00 FAILED TO ROLL\tbefore archive.",
    ];

    for path in ["unrelated.log", "IntuneDeviceInventory.log"] {
        for content in registered_failures {
            assert_eq!(
                detect_dialect(path, content),
                Some(DeviceInventoryLogDialect::RotationFailure),
                "registered rotation phrase must remain detectable for {path}: {content}"
            );
        }
    }
}

#[test]
fn a_device_inventory_selection_without_a_dialect_degrades_instead_of_panicking() {
    // A Device Inventory selection normally carries the dialect detection
    // resolved. One that does not is malformed, not impossible, and the
    // hardened dispatcher must fall back rather than panic the parse.
    let dialect_less = ResolvedParser::new(
        ParserKind::IntuneDeviceInventory,
        ParserImplementation::IntuneDeviceInventory,
        ParserProvenance::Dedicated,
        ParseQuality::Structured,
        RecordFraming::LogicalRecord,
        DateOrder::MonthFirst,
        None,
    );

    let parsed = parse_content_with_selection(ROTATION_FAILURE, "whatever.log", &dialect_less);
    assert!(!parsed.entries.is_empty());

    let lines: Vec<&str> = ROTATION_FAILURE.lines().collect();
    let (entries, _) = parse_lines_with_selection(&lines, "whatever.log", &dialect_less);
    assert!(!entries.is_empty());
}

#[test]
fn detects_rotation_failure_from_exception_evidence_without_the_literal_wording() {
    // The producer's rotation wording is not a fixed string. A .NET exception
    // beneath an ISO-8601 header is sufficient evidence on its own.
    let other_wording = "2026-07-30T13:05:01.1234567-04:00 Could not roll the inventory log over.\nSystem.UnauthorizedAccessException: Access to the path is denied.\n   at Synthetic.Inventory.Rotate()";

    for path in ["unrelated.log", "IntuneDeviceInventory.log"] {
        assert_eq!(
            detect_dialect(path, other_wording),
            Some(DeviceInventoryLogDialect::RotationFailure)
        );

        let (result, selection) =
            parse_with_dispatcher(other_wording, path, other_wording.len() as u64);
        assert_eq!(selection.parser, ParserKind::IntuneDeviceInventory);
        assert_eq!(
            selection.specialization,
            Some(ParserSpecialization::IntuneDeviceInventoryRotationFailure)
        );
        assert_eq!(result.entries[0].severity, Severity::Error);
    }
}

#[test]
fn rotation_severity_comes_from_failure_evidence_not_from_every_header() {
    // A header with no failure wording and no exception beneath it is an
    // ordinary record: the dialect does not make every line an Error.
    let mixed = "2026-07-30T13:05:00.0000000-04:00 Starting scheduled inventory rotation.\n2026-07-30T13:05:01.1234567-04:00 Failed to rotate Device Inventory log.\nSystem.IO.IOException: The process cannot access the file.\n   at Synthetic.Inventory.Rotate()\n2026-07-30T13:05:02.0000000-04:00 Rotation retry scheduled.";

    let (entries, parse_errors) = parse_content(
        "IntuneDeviceInventory.log",
        mixed,
        DeviceInventoryLogDialect::RotationFailure,
    );

    assert_eq!(parse_errors, 0);
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].severity, Severity::Info);
    assert_eq!(entries[1].severity, Severity::Error);
    assert_eq!(entries[2].severity, Severity::Info);
}

#[test]
fn rotation_severity_ignores_a_generic_keyword_in_a_continuation() {
    // The contract is explicit: Error comes from the header or from exception
    // content, never because a continuation happens to mention "error".
    let keyword_only = "2026-07-30T13:05:00.0000000-04:00 Rotation summary follows.\n  previous run reported error counters: 0";

    let (entries, _) = parse_content(
        "IntuneDeviceInventory.log",
        keyword_only,
        DeviceInventoryLogDialect::RotationFailure,
    );

    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].severity, Severity::Info);
}

#[test]
fn generic_failure_prefixes_do_not_claim_rotation_severity() {
    let generic_failures = [
        "2026-07-30T13:05:01.1234567-04:00 Failed to load configuration.",
        "2026-07-30T13:05:01.1234567-04:00 Unhandled exception in service.",
    ];

    for content in generic_failures {
        let (entries, parse_errors) = parse_content(
            "IntuneDeviceInventory.log",
            content,
            DeviceInventoryLogDialect::RotationFailure,
        );

        assert_eq!(parse_errors, 0);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].severity, Severity::Info);
    }
}

#[test]
fn partial_rotation_phrases_do_not_claim_rotation_severity() {
    for path in ["unrelated.log", "IntuneDeviceInventory.log"] {
        for content in PARTIAL_ROTATION_FAILURE_HEADERS {
            let (entries, parse_errors) =
                parse_content(path, content, DeviceInventoryLogDialect::RotationFailure);

            assert_eq!(parse_errors, 0);
            assert_eq!(entries.len(), 1);
            assert_eq!(
                entries[0].severity,
                Severity::Info,
                "partial rotation phrase must stay informational for {path}: {content}"
            );
        }
    }
}

#[test]
fn preserves_blank_lines_inside_adaptor_json_continuations() {
    let content = "[Thu Jul 30 13:05:01 2026][8604] - Adapter result:\n{\n\n  \"Status\": 200\n}\n[Thu Jul 30 13:05:03 2026][8604] - Completed action.";

    let (entries, parse_errors) = parse_content(
        "InventoryAdaptor.log",
        content,
        DeviceInventoryLogDialect::InventoryAdaptor,
    );

    assert_eq!(parse_errors, 0);
    assert_eq!(entries.len(), 2);
    assert_eq!(
        entries[0].message,
        "Adapter result:\n{\n\n  \"Status\": 200\n}"
    );
}

#[test]
fn preserves_blank_lines_inside_rotation_stack_continuations() {
    let content = "2026-07-30T13:05:01.1234567-04:00 Failed to rotate Device Inventory log.\nSystem.IO.IOException: The process cannot access the file.\n\n   at Synthetic.Inventory.Rotate()";

    let (entries, parse_errors) = parse_content(
        "IntuneDeviceInventory.log",
        content,
        DeviceInventoryLogDialect::RotationFailure,
    );

    assert_eq!(parse_errors, 0);
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].message,
        "Failed to rotate Device Inventory log.\nSystem.IO.IOException: The process cannot access the file.\n\n   at Synthetic.Inventory.Rotate()"
    );
}

#[test]
fn preserves_unknown_levels_orphans_crlf_and_truncated_final_records() {
    let content = "orphan before a record\r\n7/30/2026 6:00:53 AM [Verbose] Not a recognized level.\r\n7/30/2026 6:00:54 AM [Information] First recognized record.\r\ntrailing continuation\r\n7/30/2026 6:00:55 AM [Warning] Truncated final record.";

    let (entries, parse_errors) = parse_content(
        "IntuneInventoryHarvesterLog.log",
        content,
        DeviceInventoryLogDialect::Harvester,
    );

    assert_eq!(parse_errors, 0);
    assert_eq!(entries.len(), 4);
    assert_eq!(entries[0].message, "orphan before a record");
    assert_eq!(
        entries[1].message,
        "7/30/2026 6:00:53 AM [Verbose] Not a recognized level."
    );
    assert_eq!(
        entries[2].message,
        "First recognized record.\ntrailing continuation"
    );
    assert_eq!(entries[3].message, "Truncated final record.");
    assert!(entries
        .iter()
        .all(|entry| entry.format == LogFormat::Timestamped));
}

#[test]
fn parse_lines_is_observationally_identical_to_parse_content() {
    // Incremental callers already hold physical lines, so they parse them
    // directly instead of rejoining them into one buffer. The two entry points
    // must not drift.
    for (content, dialect) in [
        (HARVESTER, DeviceInventoryLogDialect::Harvester),
        (ADAPTOR, DeviceInventoryLogDialect::InventoryAdaptor),
        (ROTATION_FAILURE, DeviceInventoryLogDialect::RotationFailure),
    ] {
        let (from_content, content_errors) = parse_content("Device.log", content, dialect);
        let lines: Vec<&str> = content.lines().collect();
        let (from_lines, line_errors) = parse_lines("Device.log", &lines, dialect);

        assert_eq!(content_errors, line_errors);
        assert_eq!(projection(&from_content), projection(&from_lines));
        assert!(!from_lines.is_empty());
    }
}

#[test]
fn harvester_continuations_frame_incrementally_the_way_they_parse() {
    // Harvester reports LogicalRecord framing because a non-header line
    // attaches to the record above it. A continuation that arrives in a later
    // append must therefore reproduce the whole-file reading rather than
    // becoming a detached record.
    let header = "7/30/2026 6:00:54 AM [Information] First recognized record.";
    let continuation = "trailing continuation";
    let next_header = "7/30/2026 6:00:55 AM [Warning] Second record.";
    let whole_file_content = format!("{header}\n{continuation}\n{next_header}");

    let first = frame_logical_records(
        DeviceInventoryLogDialect::Harvester,
        None,
        &[LogicalRecordSegment::LineStart(header)],
    );
    assert!(
        first.completed_records.is_empty(),
        "a harvester header must stay pending until its continuations are known"
    );

    let second = frame_logical_records(
        DeviceInventoryLogDialect::Harvester,
        first.pending_record,
        &[
            LogicalRecordSegment::LineStart(continuation),
            LogicalRecordSegment::LineStart(next_header),
        ],
    );

    // Each framed record is parsed on its own, exactly as tailing parses it.
    let incremental: Vec<(Severity, String)> = second
        .completed_records
        .iter()
        .map(|record| &record.content)
        .chain(second.pending_record.iter())
        .flat_map(|record| {
            let (entries, _) = parse_content(
                "IntuneInventoryHarvesterLog.log",
                record,
                DeviceInventoryLogDialect::Harvester,
            );
            entries
                .into_iter()
                .map(|entry| (entry.severity, entry.message))
                .collect::<Vec<_>>()
        })
        .collect();

    let (whole_file, _) = parse_content(
        "IntuneInventoryHarvesterLog.log",
        &whole_file_content,
        DeviceInventoryLogDialect::Harvester,
    );
    let expected: Vec<(Severity, String)> = whole_file
        .into_iter()
        .map(|entry| (entry.severity, entry.message))
        .collect();

    assert_eq!(incremental, expected);
    assert_eq!(
        incremental[0].1,
        "First recognized record.\ntrailing continuation"
    );
}

#[test]
fn logical_record_limit_is_exact_and_lossless() {
    let header = "7/30/2026 6:00:54 AM [Information] bounded:";
    let exact_padding = "x".repeat(MAX_LOGICAL_RECORD_BYTES - header.len() - 1);
    let exact_text = format!("{header}\n{exact_padding}");
    let exact = frame_logical_records(
        DeviceInventoryLogDialect::Harvester,
        None,
        &[
            LogicalRecordSegment::LineStart(header),
            LogicalRecordSegment::LineStart(&exact_padding),
        ],
    );

    assert!(exact.completed_records.is_empty());
    assert_eq!(exact.pending_record.as_deref(), Some(exact_text.as_str()));
    assert_eq!(
        exact.pending_record.as_ref().unwrap().len(),
        MAX_LOGICAL_RECORD_BYTES
    );
    assert_eq!(exact.overflow_count, 0);

    let overflow_padding = format!("{exact_padding}Z");
    let overflow_text = format!("{header}\n{overflow_padding}");
    let overflow = frame_logical_records(
        DeviceInventoryLogDialect::Harvester,
        None,
        &[
            LogicalRecordSegment::LineStart(header),
            LogicalRecordSegment::LineStart(&overflow_padding),
        ],
    )
    .flush_pending();
    let chunks: Vec<&str> = overflow
        .completed_records
        .iter()
        .map(|record| record.content.as_str())
        .collect();

    assert_eq!(overflow.overflow_count, 1);
    assert!(chunks
        .iter()
        .all(|chunk| chunk.len() <= MAX_LOGICAL_RECORD_BYTES));
    assert_eq!(chunks.concat(), overflow_text);
    assert!(chunks.concat().ends_with('Z'));
}

#[test]
fn logical_record_split_is_utf8_safe_and_preserves_every_byte() {
    let header = "[Thu Jul 30 13:05:01 2026][8604] - UTF-8 boundary:";
    let bytes_before_emoji = MAX_LOGICAL_RECORD_BYTES - 1;
    let padding = "x".repeat(bytes_before_emoji - header.len() - 1);
    let continuation = format!("{padding}🧪TAIL-SENTINEL");
    let original = format!("{header}\n{continuation}");
    let framed = frame_logical_records(
        DeviceInventoryLogDialect::InventoryAdaptor,
        None,
        &[
            LogicalRecordSegment::LineStart(header),
            LogicalRecordSegment::LineStart(&continuation),
        ],
    )
    .flush_pending();
    let chunks: Vec<&str> = framed
        .completed_records
        .iter()
        .map(|record| record.content.as_str())
        .collect();

    assert_eq!(framed.overflow_count, 1);
    assert!(chunks
        .iter()
        .all(|chunk| chunk.len() <= MAX_LOGICAL_RECORD_BYTES));
    assert_eq!(chunks.concat().as_bytes(), original.as_bytes());
    assert!(chunks.concat().ends_with("🧪TAIL-SENTINEL"));
}

#[test]
fn every_dialect_bounds_oversized_single_lines_and_keeps_parse_entry_points_equal() {
    let cases = [
        (
            DeviceInventoryLogDialect::Harvester,
            "7/30/2026 6:00:54 AM [Error] HARVESTER-START",
            Severity::Error,
        ),
        (
            DeviceInventoryLogDialect::InventoryAdaptor,
            "[Thu Jul 30 13:05:01 2026][8604] - ADAPTOR-START",
            Severity::Info,
        ),
        (
            DeviceInventoryLogDialect::RotationFailure,
            "2026-07-30T13:05:01.1234567-04:00 Failed to rotate ROTATION-START",
            Severity::Error,
        ),
    ];

    for (dialect, header, expected_severity) in cases {
        let oversized = format!(
            "MULTILINE-START-{}🧪-{}-TAIL-SENTINEL",
            "x".repeat(MAX_LOGICAL_RECORD_BYTES),
            match dialect {
                DeviceInventoryLogDialect::Harvester => "HARVESTER",
                DeviceInventoryLogDialect::InventoryAdaptor => "ADAPTOR",
                DeviceInventoryLogDialect::RotationFailure => "ROTATION",
            }
        );
        let next_header = match dialect {
            DeviceInventoryLogDialect::Harvester => "7/30/2026 6:00:55 AM [Warning] NEXT-RECORD",
            DeviceInventoryLogDialect::InventoryAdaptor => {
                "[Thu Jul 30 13:05:02 2026][8604] - NEXT-RECORD"
            }
            DeviceInventoryLogDialect::RotationFailure => {
                "2026-07-30T13:05:02.1234567-04:00 NEXT-RECORD"
            }
        };
        let content = format!("{header}\n{oversized}\n{next_header}");
        let lines: Vec<&str> = content.lines().collect();
        let (from_content, content_errors) = parse_content("Device.log", &content, dialect);
        let (from_lines, line_errors) = parse_lines("Device.log", &lines, dialect);

        assert_eq!(content_errors, 1, "unexpected error count for {dialect:?}");
        assert_eq!(content_errors, line_errors);
        assert_eq!(projection(&from_content), projection(&from_lines));
        assert_eq!(from_content[0].line_number, 1);
        assert_eq!(from_content[0].severity, expected_severity);
        assert_eq!(from_content.last().unwrap().line_number, 3);
        assert!(from_content
            .iter()
            .any(|entry| entry.message.contains("TAIL-SENTINEL")));
        assert!(from_content
            .iter()
            .all(|entry| entry.message.len() <= MAX_LOGICAL_RECORD_BYTES));
    }
}

#[test]
fn framing_never_builds_an_oversized_pending_record_before_splitting() {
    let header = "[Thu Jul 30 13:05:01 2026][8604] - PEAK-START";
    let continuation = format!(
        "HUGE-LINE-START-{}🧪-HUGE-LINE-TAIL",
        "x".repeat(MAX_LOGICAL_RECORD_BYTES * 3)
    );
    let original = format!("{header}\n{continuation}");
    let framed = frame_logical_records(
        DeviceInventoryLogDialect::InventoryAdaptor,
        None,
        &[
            LogicalRecordSegment::LineStart(header),
            LogicalRecordSegment::LineStart(&continuation),
        ],
    )
    .flush_pending();
    let reconstructed = framed
        .completed_records
        .iter()
        .map(|record| record.content.as_str())
        .collect::<String>();

    assert!(framed.max_pending_bytes_observed <= MAX_LOGICAL_RECORD_BYTES);
    assert!(framed
        .completed_records
        .iter()
        .all(|record| record.content.len() <= MAX_LOGICAL_RECORD_BYTES));
    assert_eq!(reconstructed.as_bytes(), original.as_bytes());
    assert!(reconstructed.ends_with("🧪-HUGE-LINE-TAIL"));
}

/// Compare entries by the fields the parse contract owns.
fn projection(entries: &[LogEntry]) -> Vec<(u32, Severity, String)> {
    entries
        .iter()
        .map(|entry| (entry.line_number, entry.severity, entry.message.clone()))
        .collect()
}

#[test]
fn dispatcher_selects_each_device_inventory_dialect_with_stable_metadata() {
    let cases = [
        (
            "IntuneInventoryHarvesterLog.log",
            HARVESTER,
            ParserSpecialization::IntuneDeviceInventoryHarvester,
            RecordFraming::LogicalRecord,
            3,
        ),
        (
            "InventoryAdaptor.log",
            ADAPTOR,
            ParserSpecialization::IntuneDeviceInventoryAdaptor,
            RecordFraming::LogicalRecord,
            2,
        ),
        (
            "IntuneDeviceInventory.log",
            ROTATION_FAILURE,
            ParserSpecialization::IntuneDeviceInventoryRotationFailure,
            RecordFraming::LogicalRecord,
            1,
        ),
    ];

    for (path, content, specialization, framing, entry_count) in cases {
        let (result, selection) = parse_with_dispatcher(content, path, content.len() as u64);

        assert_eq!(selection.parser, ParserKind::IntuneDeviceInventory);
        assert_eq!(
            selection.implementation,
            ParserImplementation::IntuneDeviceInventory
        );
        assert_eq!(selection.specialization, Some(specialization));
        assert_eq!(selection.record_framing, framing);
        assert_eq!(selection.compatibility_format(), LogFormat::Timestamped);
        assert_eq!(result.format_detected, LogFormat::Timestamped);
        assert_eq!(result.entries.len(), entry_count);
        assert_eq!(result.parser_selection.specialization, Some(specialization));
    }
}

#[test]
fn dispatcher_preserves_logical_records_and_common_error_code_annotations() {
    let (adaptor, _) = parse_with_dispatcher(ADAPTOR, "InventoryAdaptor.log", ADAPTOR.len() as u64);
    assert_eq!(
        adaptor.entries[0].message,
        "Adapter result:\n{\"Status\":200,\"HResult\":\"0x00000000\",\"Data\":{\"Example\":\"value\"}}"
    );

    let error_harvester = "7/30/2026 10:08:53 AM [Error] Harvester failed with 0x80070005.";
    let (harvester, _) = parse_with_dispatcher(
        error_harvester,
        "IntuneInventoryHarvesterLog.log",
        error_harvester.len() as u64,
    );
    assert_eq!(
        harvester.entries[0].error_code_spans[0].code_hex,
        "0x80070005"
    );
}

#[test]
fn dispatcher_keeps_path_only_and_generic_timestamp_collisions_out_of_device_inventory() {
    let (path_only, path_only_selection) = parse_with_dispatcher(
        "ordinary text",
        "IntuneInventoryHarvesterLog.log",
        "ordinary text".len() as u64,
    );
    assert_eq!(path_only_selection.parser, ParserKind::Plain);
    assert_eq!(path_only.parser_selection.specialization, None);

    let generic_iso = "2026-07-30T13:05:01.1234567-04:00 Completed an unrelated service operation.\n2026-07-30T13:05:02.1234567-04:00 Completed another unrelated service operation.";
    let (timestamped, timestamped_selection) = parse_with_dispatcher(
        generic_iso,
        "IntuneDeviceInventory.log",
        generic_iso.len() as u64,
    );
    assert_eq!(timestamped_selection.parser, ParserKind::Timestamped);
    assert_eq!(
        timestamped_selection.implementation,
        ParserImplementation::GenericTimestamped
    );
    assert_eq!(timestamped.parser_selection.specialization, None);
}

#[test]
fn dispatcher_keeps_generic_failure_prefixes_out_of_device_inventory() {
    let generic_failures = [
        "2026-07-30T13:05:01.1234567-04:00 Failed to load configuration.\n2026-07-30T13:05:02.1234567-04:00 Completed an unrelated service operation.",
        "2026-07-30T13:05:01.1234567-04:00 Unhandled exception in service.\n2026-07-30T13:05:02.1234567-04:00 Completed an unrelated service operation.",
    ];

    for path in ["unrelated.log", "IntuneDeviceInventory.log"] {
        for content in generic_failures {
            let (result, selection) = parse_with_dispatcher(content, path, content.len() as u64);

            assert_eq!(selection.parser, ParserKind::Timestamped);
            assert_eq!(
                selection.implementation,
                ParserImplementation::GenericTimestamped
            );
            assert_eq!(selection.specialization, None);
            assert_eq!(result.parser_selection.specialization, None);
            assert_eq!(result.entries.len(), 2);
        }
    }
}

#[test]
fn dispatcher_keeps_partial_rotation_phrases_out_of_device_inventory() {
    for path in ["unrelated.log", "IntuneDeviceInventory.log"] {
        for header in PARTIAL_ROTATION_FAILURE_HEADERS {
            let content = format!(
                "{header}\n2026-07-30T13:05:02.1234567-04:00 Completed an unrelated service operation."
            );
            let (result, selection) = parse_with_dispatcher(&content, path, content.len() as u64);

            assert_eq!(selection.parser, ParserKind::Timestamped);
            assert_eq!(
                selection.implementation,
                ParserImplementation::GenericTimestamped
            );
            assert_eq!(selection.specialization, None);
            assert_eq!(result.parser_selection.specialization, None);
            assert_eq!(result.entries.len(), 2);
        }
    }
}
