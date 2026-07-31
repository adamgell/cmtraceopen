use cmtraceopen_parser::{
    intune::device::windows::inventory::{
        detect_dialect, parse_content, DeviceInventoryLogDialect,
    },
    models::log_entry::{LogFormat, Severity},
};

const HARVESTER: &str = "7/30/2026 6:00:53 AM [Information] Completed harvesting signed policies: 118 succeeded, 0 failed to collect.\n7/30/2026 10:08:52 AM [Warning] Reporting dropped attribute error for ExampleField: ErrorCode=404.\n7/30/2026 10:08:53 AM [Error] Harvester error code: 404, Message: ExampleField result is null.";

const ADAPTOR: &str = "[Thu Jul 30 13:05:01 2026][8604] - Adapter result:\n{\"Status\":200,\"HResult\":\"0x00000000\",\"Data\":{\"Example\":\"value\"}}\n[Thu Jul 30 13:05:03 2026][8604] - Completed action with HRESULT 0x0, MI_Result 0x0.";

const ROTATION_FAILURE: &str = "2026-07-30T13:05:01.1234567-04:00 Failed to rotate Device Inventory log.\nSystem.IO.IOException: The process cannot access the file.\n   at Synthetic.Inventory.Rotate()";

#[test]
fn parses_harvester_headers_with_direct_severity_mapping() {
    let (entries, parse_errors) = parse_content(
        HARVESTER,
        "IntuneInventoryHarvesterLog.log",
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
        ADAPTOR,
        "IntuneInventoryAdapterLog.log",
        DeviceInventoryLogDialect::Adaptor,
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
        ROTATION_FAILURE,
        "IntuneDeviceInventory.log",
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
        detect_dialect(HARVESTER, "unrelated.log"),
        Some(DeviceInventoryLogDialect::Harvester)
    );
    assert_eq!(
        detect_dialect(one_harvester_header, "IntuneInventoryHarvesterLog.log"),
        Some(DeviceInventoryLogDialect::Harvester)
    );
    assert_eq!(detect_dialect(one_harvester_header, "unrelated.log"), None);
    assert_eq!(
        detect_dialect("ordinary text", "IntuneInventoryHarvesterLog.log"),
        None
    );
    assert_eq!(
        detect_dialect(ADAPTOR, "unrelated.log"),
        Some(DeviceInventoryLogDialect::Adaptor)
    );
    assert_eq!(
        detect_dialect(ROTATION_FAILURE, "unrelated.log"),
        Some(DeviceInventoryLogDialect::RotationFailure)
    );
}

#[test]
fn preserves_unknown_levels_orphans_crlf_and_truncated_final_records() {
    let content = "orphan before a record\r\n7/30/2026 6:00:53 AM [Verbose] Not a recognized level.\r\n7/30/2026 6:00:54 AM [Information] First recognized record.\r\ntrailing continuation\r\n7/30/2026 6:00:55 AM [Warning] Truncated final record.";

    let (entries, parse_errors) = parse_content(
        content,
        "IntuneInventoryHarvesterLog.log",
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
