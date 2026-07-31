use cmtraceopen_parser::{
    intune::device::windows::inventory::{
        detect_dialect, parse_content, DeviceInventoryLogDialect,
    },
    models::log_entry::{
        LogFormat, ParserImplementation, ParserKind, ParserSpecialization, RecordFraming, Severity,
    },
    parser::parse_content as parse_with_dispatcher,
};

const HARVESTER: &str = "7/30/2026 6:00:53 AM [Information] Completed harvesting signed policies: 118 succeeded, 0 failed to collect.\n7/30/2026 10:08:52 AM [Warning] Reporting dropped attribute error for ExampleField: ErrorCode=404.\n7/30/2026 10:08:53 AM [Error] Harvester error code: 404, Message: ExampleField result is null.";

const ADAPTOR: &str = "[Thu Jul 30 13:05:01 2026][8604] - Adapter result:\n{\"Status\":200,\"HResult\":\"0x00000000\",\"Data\":{\"Example\":\"value\"}}\n[Thu Jul 30 13:05:03 2026][8604] - Completed action with HRESULT 0x0, MI_Result 0x0.";

const ROTATION_FAILURE: &str = "2026-07-30T13:05:01.1234567-04:00 Failed to rotate Device Inventory log.\nSystem.IO.IOException: The process cannot access the file.\n   at Synthetic.Inventory.Rotate()";

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
fn dispatcher_selects_each_device_inventory_dialect_with_stable_metadata() {
    let cases = [
        (
            "IntuneInventoryHarvesterLog.log",
            HARVESTER,
            ParserSpecialization::IntuneDeviceInventoryHarvester,
            RecordFraming::PhysicalLine,
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
