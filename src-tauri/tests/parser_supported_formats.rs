use app_lib::models::log_entry::{
    DateFieldOrder, EntryKind, LogFormat, ParseResult, ParserImplementation, ParserKind,
    ParserSpecialization, RecordFraming, Severity,
};
use app_lib::parser::ResolvedParser;
use std::collections::BTreeSet;
use std::path::PathBuf;

const DECLARED_PARSER_KINDS: [ParserKind; 21] = [
    ParserKind::Ccm,
    ParserKind::Simple,
    ParserKind::Timestamped,
    ParserKind::Plain,
    ParserKind::IisW3c,
    ParserKind::Panther,
    ParserKind::Cbs,
    ParserKind::Dism,
    ParserKind::ReportingEvents,
    ParserKind::Msi,
    ParserKind::PsadtLegacy,
    ParserKind::IntuneMacOs,
    ParserKind::IntuneDeviceInventory,
    ParserKind::Dhcp,
    ParserKind::Burn,
    ParserKind::PatchMyPcDetection,
    ParserKind::Registry,
    ParserKind::SecureBootLog,
    ParserKind::DnsDebug,
    ParserKind::DnsAudit,
    ParserKind::CmtLog,
];

fn contract_name(kind: ParserKind) -> &'static str {
    match kind {
        ParserKind::Ccm => "ccm",
        ParserKind::Simple => "simple",
        ParserKind::Timestamped => "timestamped",
        ParserKind::Plain => "plain",
        ParserKind::IisW3c => "iis_w3c",
        ParserKind::Panther => "panther",
        ParserKind::Cbs => "cbs",
        ParserKind::Dism => "dism",
        ParserKind::ReportingEvents => "reporting_events",
        ParserKind::Msi => "msi",
        ParserKind::PsadtLegacy => "psadt",
        ParserKind::IntuneMacOs => "intune_macos",
        ParserKind::IntuneDeviceInventory => "intune_device_inventory",
        ParserKind::Dhcp => "dhcp",
        ParserKind::Burn => "burn",
        ParserKind::PatchMyPcDetection => "patchmypc_detection",
        ParserKind::Registry => "registry",
        ParserKind::SecureBootLog => "secureboot",
        ParserKind::DnsDebug => "dns_debug",
        ParserKind::DnsAudit => "dns_audit",
        ParserKind::CmtLog => "cmtlog",
    }
}

#[test]
fn support_inventory_names_every_parser_kind_once() {
    let names = DECLARED_PARSER_KINDS
        .into_iter()
        .map(contract_name)
        .collect::<BTreeSet<_>>();
    assert_eq!(names.len(), DECLARED_PARSER_KINDS.len());
}

fn fixture_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("corpus")
        .join(relative)
}

fn parse_fixture(relative: &str) -> (ParseResult, ResolvedParser) {
    let path = fixture_path(relative);
    app_lib::parser::parse_file(&path.to_string_lossy()).expect("fixture should parse")
}

fn detect_fixture(relative: &str) -> ResolvedParser {
    let path = fixture_path(relative);
    let content = std::fs::read_to_string(&path).expect("fixture should be UTF-8");
    app_lib::parser::detect::detect_parser(&path.to_string_lossy(), &content)
}

fn assert_selection(
    selection: &ResolvedParser,
    parser: ParserKind,
    implementation: ParserImplementation,
    framing: RecordFraming,
) {
    assert_eq!(selection.parser, parser);
    assert_eq!(selection.implementation, implementation);
    assert_eq!(selection.record_framing, framing);
}

#[test]
fn text_contract_ccm() {
    let (result, selection) = parse_fixture("ccm/clean/basic.log");
    assert_selection(
        &selection,
        ParserKind::Ccm,
        ParserImplementation::Ccm,
        RecordFraming::LogicalRecord,
    );
    assert_eq!(result.format_detected, LogFormat::Ccm);
    assert_eq!(result.parse_errors, 0);
    assert_eq!(result.entries[0].component.as_deref(), Some("CcmExec"));
    assert_eq!(result.entries[0].thread, Some(100));
    assert_eq!(result.entries[2].severity, Severity::Error);
}

#[test]
fn text_contract_simple() {
    let (result, selection) = parse_fixture("simple/clean/basic.log");
    assert_selection(
        &selection,
        ParserKind::Simple,
        ParserImplementation::Simple,
        RecordFraming::PhysicalLine,
    );
    assert_eq!(result.format_detected, LogFormat::Simple);
    assert_eq!(result.parse_errors, 0);
    assert_eq!(result.entries[0].component.as_deref(), Some("CcmExec"));
    assert_eq!(result.entries[0].thread, Some(100));
    assert_eq!(result.entries[2].severity, Severity::Error);
}

#[test]
fn text_contract_timestamped() {
    let (result, selection) = parse_fixture("timestamped/clean/mixed.log");
    assert_selection(
        &selection,
        ParserKind::Timestamped,
        ParserImplementation::GenericTimestamped,
        RecordFraming::PhysicalLine,
    );
    assert_eq!(
        selection.to_info().date_order,
        Some(DateFieldOrder::MonthFirst)
    );
    assert_eq!(result.format_detected, LogFormat::Timestamped);
    assert_eq!(result.parse_errors, 0);
    assert_eq!(result.entries.len(), 4);
    assert!(result.entries[..3]
        .iter()
        .all(|entry| entry.timestamp.is_some()));
    assert!(result.entries[3].timestamp.is_none());
    assert_eq!(
        result.entries[3].timestamp_display.as_deref(),
        Some("09:15:33.250")
    );
    assert_eq!(result.entries[1].severity, Severity::Warning);
}

#[test]
fn text_contract_plain() {
    let (result, selection) = parse_fixture("plain/unstructured.txt");
    assert_selection(
        &selection,
        ParserKind::Plain,
        ParserImplementation::PlainText,
        RecordFraming::PhysicalLine,
    );
    assert_eq!(result.format_detected, LogFormat::Plain);
    assert_eq!(result.parse_errors, 0);
    assert!(result
        .entries
        .iter()
        .all(|entry| entry.timestamp.is_none() && entry.component.is_none()));
}

#[test]
fn text_contract_iis_w3c() {
    let (result, selection) = parse_fixture("iis_w3c/clean/u_ex260329.log");
    assert_selection(
        &selection,
        ParserKind::IisW3c,
        ParserImplementation::IisW3c,
        RecordFraming::PhysicalLine,
    );
    assert_eq!(result.format_detected, LogFormat::Timestamped);
    assert_eq!(result.parse_errors, 0);
    assert_eq!(result.entries[0].http_method.as_deref(), Some("GET"));
    assert_eq!(result.entries[0].status_code, Some(200));
    assert_eq!(result.entries[1].uri_query.as_deref(), Some("id=42"));
    assert_eq!(result.entries[1].sub_status, Some(7));
}

#[test]
fn text_contract_panther() {
    let (result, selection) = parse_fixture("panther/clean/setupact.log");
    assert_selection(
        &selection,
        ParserKind::Panther,
        ParserImplementation::GenericTimestamped,
        RecordFraming::LogicalRecord,
    );
    assert_eq!(result.parse_errors, 0);
    assert_eq!(result.entries[0].component.as_deref(), Some("MIG"));
    assert!(result.entries[0]
        .message
        .contains("Additional migration detail"));
    assert_eq!(result.entries[1].severity, Severity::Warning);
}

#[test]
fn text_contract_cbs() {
    let (result, selection) = parse_fixture("cbs/clean/CBS.log");
    assert_selection(
        &selection,
        ParserKind::Cbs,
        ParserImplementation::GenericTimestamped,
        RecordFraming::LogicalRecord,
    );
    assert_eq!(result.parse_errors, 0);
    assert_eq!(result.entries[0].component.as_deref(), Some("CBS"));
    assert!(result.entries[0].message.contains("Continuation detail"));
    assert_eq!(result.entries[1].severity, Severity::Error);
}

#[test]
fn text_contract_dism() {
    let (result, selection) = parse_fixture("dism/clean/dism.log");
    assert_selection(
        &selection,
        ParserKind::Dism,
        ParserImplementation::GenericTimestamped,
        RecordFraming::LogicalRecord,
    );
    assert_eq!(result.parse_errors, 0);
    assert_eq!(result.entries[0].component.as_deref(), Some("DISM"));
    assert!(result.entries[0].message.contains("Continuation detail"));
    assert_eq!(result.entries[1].severity, Severity::Warning);
}

#[test]
fn text_contract_reporting_events() {
    let (result, selection) = parse_fixture("reporting_events/clean/ReportingEvents.log");
    assert_selection(
        &selection,
        ParserKind::ReportingEvents,
        ParserImplementation::ReportingEvents,
        RecordFraming::PhysicalLine,
    );
    assert_eq!(result.parse_errors, 0);
    assert_eq!(
        result.entries[0].component.as_deref(),
        Some("Windows Update Agent")
    );
    assert!(result.entries[0]
        .message
        .contains("Installation Successful"));
    assert_eq!(result.entries[1].severity, Severity::Error);
}

#[test]
fn text_contract_msi() {
    let (result, selection) = parse_fixture("msi/clean/basic.log");
    assert_selection(
        &selection,
        ParserKind::Msi,
        ParserImplementation::Msi,
        RecordFraming::PhysicalLine,
    );
    assert_eq!(result.parse_errors, 0);
    assert!(result.entries.len() >= 6);
    assert!(result.entries.iter().any(|entry| entry
        .component
        .as_deref()
        .is_some_and(|component| component.starts_with("MSI-"))));
    assert!(result
        .entries
        .iter()
        .any(|entry| entry.message.contains("InstallInitialize")));
}

#[test]
fn text_contract_psadt_legacy() {
    let (result, selection) = parse_fixture("psadt/clean/Deploy-Application.log");
    assert_selection(
        &selection,
        ParserKind::PsadtLegacy,
        ParserImplementation::PsadtLegacy,
        RecordFraming::PhysicalLine,
    );
    assert_eq!(result.parse_errors, 0);
    assert_eq!(
        result.entries[0].component.as_deref(),
        Some("Initialization")
    );
    assert_eq!(
        result.entries[1].source_file.as_deref(),
        Some("Start-ADTMsiProcess")
    );
}

#[test]
fn text_contract_intune_macos() {
    let (result, selection) = parse_fixture("intune_macos/clean/IntuneMDMDaemon.log");
    assert_selection(
        &selection,
        ParserKind::IntuneMacOs,
        ParserImplementation::IntuneMacOs,
        RecordFraming::PhysicalLine,
    );
    assert_eq!(result.parse_errors, 0);
    assert_eq!(
        result.entries[0].component.as_deref(),
        Some("IntuneMDM-Daemon")
    );
    assert_eq!(
        result.entries[0].source_file.as_deref(),
        Some("SyncActivityTracer")
    );
    assert_eq!(result.entries[1].severity, Severity::Error);
}

#[test]
fn text_contract_intune_device_inventory_harvester() {
    let (result, selection) =
        parse_fixture("intune_device_inventory/clean/IntuneInventoryHarvesterLog.log");
    assert_selection(
        &selection,
        ParserKind::IntuneDeviceInventory,
        ParserImplementation::IntuneDeviceInventory,
        RecordFraming::PhysicalLine,
    );
    assert_eq!(
        selection.specialization,
        Some(ParserSpecialization::IntuneDeviceInventoryHarvester)
    );
    assert_eq!(result.format_detected, LogFormat::Timestamped);
    assert_eq!(result.parse_errors, 0);
    assert_eq!(result.entries.len(), 3);
    assert_eq!(result.entries[1].severity, Severity::Warning);
}

#[test]
fn text_contract_intune_device_inventory_adaptor() {
    let (result, selection) = parse_fixture("intune_device_inventory/clean/InventoryAdaptor.log_");
    assert_selection(
        &selection,
        ParserKind::IntuneDeviceInventory,
        ParserImplementation::IntuneDeviceInventory,
        RecordFraming::LogicalRecord,
    );
    assert_eq!(
        selection.specialization,
        Some(ParserSpecialization::IntuneDeviceInventoryAdaptor)
    );
    assert_eq!(result.format_detected, LogFormat::Timestamped);
    assert_eq!(result.parse_errors, 0);
    assert_eq!(result.entries.len(), 2);
    assert_eq!(result.entries[0].thread, Some(8604));
    assert_eq!(
        result.entries[0].message,
        "Adapter result:\n{\"Status\":200,\"HResult\":\"0x00000000\",\"Data\":{\"Example\":\"value\"}}"
    );
}

#[test]
fn text_contract_dhcp() {
    let (result, selection) = parse_fixture("dhcp/clean/DhcpSrvLog-Mon.log");
    assert_selection(
        &selection,
        ParserKind::Dhcp,
        ParserImplementation::Dhcp,
        RecordFraming::PhysicalLine,
    );
    assert_eq!(result.parse_errors, 0);
    assert_eq!(result.entries[0].ip_address.as_deref(), Some("192.0.2.10"));
    assert_eq!(
        result.entries[0].mac_address.as_deref(),
        Some("00:11:22:33:44:55")
    );
    assert_eq!(
        result.entries[1].ip_address.as_deref(),
        Some("2001:db8::10")
    );
    assert_eq!(result.entries[1].severity, Severity::Error);
}

#[test]
fn text_contract_burn() {
    let (result, selection) = parse_fixture("burn/clean/bundle.log");
    assert_selection(
        &selection,
        ParserKind::Burn,
        ParserImplementation::Burn,
        RecordFraming::PhysicalLine,
    );
    assert_eq!(result.parse_errors, 0);
    assert_eq!(result.entries[0].component.as_deref(), Some("i001"));
    assert_eq!(result.entries[0].thread, Some(0x07A4));
    assert_eq!(result.entries[1].severity, Severity::Error);
}

#[test]
fn text_contract_patchmypc_detection() {
    let (result, selection) = parse_fixture("patchmypc_detection/clean/detection.log");
    assert_selection(
        &selection,
        ParserKind::PatchMyPcDetection,
        ParserImplementation::PatchMyPcDetection,
        RecordFraming::PhysicalLine,
    );
    assert_eq!(result.parse_errors, 0);
    assert_eq!(result.entries[0].component.as_deref(), Some("PatchMyPC"));
    assert_eq!(result.entries[0].host_name.as_deref(), Some("TESTDEVICE"));
    assert_eq!(
        result.entries[1].operation_name.as_deref(),
        Some("Requirement")
    );
}

#[test]
fn selection_contract_registry() {
    let selection = detect_fixture("registry/clean/basic.reg");
    assert_selection(
        &selection,
        ParserKind::Registry,
        ParserImplementation::Registry,
        RecordFraming::PhysicalLine,
    );
    assert_eq!(selection.compatibility_format(), LogFormat::Plain);
}

#[test]
fn text_contract_secureboot() {
    let (result, selection) = parse_fixture("secureboot/clean/SecureBootCertificateUpdate.log");
    assert_selection(
        &selection,
        ParserKind::SecureBootLog,
        ParserImplementation::SecureBootLog,
        RecordFraming::PhysicalLine,
    );
    assert_eq!(result.parse_errors, 0);
    assert_eq!(result.entries[0].component.as_deref(), Some("DETECT"));
    assert!(result.entries[0].timestamp.is_some());
    assert_eq!(result.entries[1].message, "Secure Boot is enabled");
}

#[test]
fn text_contract_dns_debug() {
    let (result, selection) = parse_fixture("dns_debug/clean/basic.log");
    assert_selection(
        &selection,
        ParserKind::DnsDebug,
        ParserImplementation::DnsDebug,
        RecordFraming::LogicalRecord,
    );
    assert_eq!(result.format_detected, LogFormat::DnsDebug);
    assert_eq!(result.parse_errors, 0);
    assert!(result
        .entries
        .iter()
        .any(|entry| entry.query_name.as_deref() == Some("home.gell.one")));
    assert!(result
        .entries
        .iter()
        .any(|entry| entry.dns_protocol.as_deref() == Some("UDP")));
}

#[test]
fn selection_contract_dns_audit() {
    let selection = ResolvedParser::dns_audit();
    assert_selection(
        &selection,
        ParserKind::DnsAudit,
        ParserImplementation::DnsAudit,
        RecordFraming::PhysicalLine,
    );
    assert_eq!(selection.compatibility_format(), LogFormat::DnsAudit);
}

#[test]
fn text_contract_cmtlog() {
    let (result, selection) = parse_fixture("cmtlog/clean/basic.cmtlog");
    assert_selection(
        &selection,
        ParserKind::CmtLog,
        ParserImplementation::CmtLog,
        RecordFraming::PhysicalLine,
    );
    assert_eq!(result.format_detected, LogFormat::CmtLog);
    assert_eq!(result.parse_errors, 0);
    assert_eq!(result.entries[0].entry_kind, Some(EntryKind::Header));
    assert_eq!(result.entries[1].entry_kind, Some(EntryKind::Section));
    assert_eq!(result.entries[2].entry_kind, Some(EntryKind::Iteration));
    assert_eq!(result.entries[3].severity, Severity::Success);
    assert_eq!(result.entries[3].whatif, Some(true));
}

#[test]
fn specialization_contract_ime() {
    let (result, selection) = parse_fixture("ime/multiline/HealthScripts.log");
    assert_selection(
        &selection,
        ParserKind::Ccm,
        ParserImplementation::Ccm,
        RecordFraming::LogicalRecord,
    );
    assert_eq!(selection.specialization, Some(ParserSpecialization::Ime));
    assert_eq!(result.parse_errors, 0);
    assert!(result.entries[1]
        .message
        .contains("Invoke-RestMethod -Method Post"));
    assert_eq!(result.entries[1].line_number, 2);
}

#[test]
fn plain_ids_are_contiguous_across_blank_lines() {
    let lines = ["first", "", "third"];
    let (entries, errors) = app_lib::parser::plain::parse_lines(&lines, "plain.log");
    assert_eq!(errors, 0);
    assert_eq!(
        entries.iter().map(|entry| entry.id).collect::<Vec<_>>(),
        vec![0, 1]
    );
    assert_eq!(
        entries
            .iter()
            .map(|entry| entry.line_number)
            .collect::<Vec<_>>(),
        vec![1, 3]
    );
}

fn utf16_bytes(content: &str, little_endian: bool) -> Vec<u8> {
    let mut bytes = if little_endian {
        vec![0xFF, 0xFE]
    } else {
        vec![0xFE, 0xFF]
    };
    for unit in content.encode_utf16() {
        let encoded = if little_endian {
            unit.to_le_bytes()
        } else {
            unit.to_be_bytes()
        };
        bytes.extend_from_slice(&encoded);
    }
    bytes
}

#[test]
fn encoding_boms_and_windows_1252_decode_at_file_boundary() {
    let temp = tempfile::tempdir().expect("temp dir");
    let cases = [
        (
            "utf8.log",
            b"\xEF\xBB\xBFutf8 message".to_vec(),
            "utf8 message",
        ),
        (
            "utf16le.log",
            utf16_bytes("little endian", true),
            "little endian",
        ),
        (
            "utf16be.log",
            utf16_bytes("big endian", false),
            "big endian",
        ),
        (
            "windows1252.log",
            b"caf\xE9 message".to_vec(),
            "caf\u{e9} message",
        ),
    ];

    for (name, bytes, expected_message) in cases {
        let path = temp.path().join(name);
        std::fs::write(&path, &bytes).expect("write encoded fixture");
        let (result, selection) =
            app_lib::parser::parse_file(&path.to_string_lossy()).expect("parse encoded fixture");
        assert_eq!(selection.parser, ParserKind::Plain, "{name}");
        assert_eq!(result.entries[0].message, expected_message, "{name}");
        assert_eq!(result.file_size, bytes.len() as u64, "{name}");
        assert_eq!(result.byte_offset, bytes.len() as u64, "{name}");
    }
}

#[test]
fn encoding_utf16le_registry_reaches_dedicated_parser_without_data_loss() {
    let content = concat!(
        "Windows Registry Editor Version 5.00\r\n\r\n",
        "[HKEY_LOCAL_MACHINE\\SOFTWARE\\CMTraceOpenTest]\r\n",
        "\"Enabled\"=dword:00000001\r\n",
    );
    let bytes = utf16_bytes(content, true);
    let temp = tempfile::tempdir().expect("temp dir");
    let path = temp.path().join("contract.reg");
    std::fs::write(&path, &bytes).expect("write UTF-16LE Registry fixture");

    let decoded =
        app_lib::parser::read_file_content(&path.to_string_lossy()).expect("decode Registry file");
    let result = app_lib::parser::registry::parse_registry_content(
        &decoded,
        &path.to_string_lossy(),
        bytes.len() as u64,
    );

    assert_eq!(result.file_size, bytes.len() as u64);
    assert_eq!(result.total_keys, 1);
    assert_eq!(result.total_values, 1);
    assert_eq!(result.parse_errors, 0);
    assert_eq!(result.keys[0].values[0].name, "Enabled");
    assert_eq!(result.keys[0].values[0].data, "0x00000001 (1)");
}

#[test]
fn psadt_success_is_success_severity() {
    let lines = [
        "[2026-07-29 09:00:01.200] [Install] [Start-ADTMsiProcess] [Success] :: Installation complete",
    ];
    let (entries, errors) = app_lib::parser::psadt::parse_lines(&lines, "Deploy-Application.log");
    assert_eq!(errors, 0);
    assert_eq!(entries[0].severity, Severity::Success);
}

#[test]
fn secureboot_success_is_success_severity() {
    let lines = ["2026-07-29 09:50:01 [DETECT] [SUCCESS] Secure Boot is enabled"];
    let (entries, errors) =
        app_lib::parser::secureboot_log::parse_lines(&lines, "SecureBootCertificateUpdate.log");
    assert_eq!(errors, 0);
    assert_eq!(entries[0].severity, Severity::Success);
}

#[test]
fn secureboot_invalid_timestamp_is_preserved_as_parse_error() {
    let invalid = "2026-13-40 25:61:61 [DETECT] [INFO] impossible timestamp";
    let (entries, errors) =
        app_lib::parser::secureboot_log::parse_lines(&[invalid], "SecureBootCertificateUpdate.log");
    assert_eq!(errors, 1);
    assert_eq!(entries[0].message, invalid);
    assert_eq!(entries[0].format, LogFormat::Plain);
    assert!(entries[0].timestamp.is_none());
    assert!(entries[0].timestamp_display.is_none());
}
