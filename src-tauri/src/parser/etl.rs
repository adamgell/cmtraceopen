use regex::Regex;
use serde::Serialize;
use std::collections::HashMap;

const MAX_EVENTS: usize = 50_000;

/// Known IME ETW provider GUIDs
const KNOWN_PROVIDERS: &[(&str, &str)] = &[
    (
        "{1db28f2e-8f80-4027-8c5a-a11f7f10f62d}",
        "Microsoft_SideCar",
    ),
    (
        "{e20927af-32d7-4d5d-9f73-82f077a1c891}",
        "Microsoft-Intune-Sidecar-Client-Telemetry",
    ),
    (
        "{56b809b5-d9e6-4f21-a807-2a1e3ed4159e}",
        "Microsoft-Epm-Events",
    ),
    (
        "{8ad61205-8e7e-4be4-8d30-e2480500b39a}",
        "Microsoft-Intune-Epm-Client-Telemetry",
    ),
];

/// AppInstallStatus2 from DLL reflection
pub static APP_INSTALL_STATUS2: &[(u32, &str)] = &[
    (0, "Unknown"),
    (1000, "Installed"),
    (1001, "InstalledButDependenciesNotPresent"),
    (1002, "InstalledPendingReboot"),
    (2000, "Installing"),
    (2001, "InstallingPendingReboot"),
    (3000, "NotApplicable"),
    (4000, "Failed"),
    (5000, "UninstalledByGateway"),
    (5001, "NotInstalled"),
    (6000, "Uninstalling"),
    (7000, "UninstallFailed"),
];

/// Applicability result codes
pub static APPLICABILITY_CODES: &[(u32, &str)] = &[
    (0, "Applicable"),
    (1, "RequirementsNotMet"),
    (3, "HostPlatformNotApplicable"),
    (1000, "ProcessorArch"),
    (1001, "DiskSpace"),
    (1002, "OSVersion"),
    (1003, "PhysicalMemory"),
    (1004, "LogicalProcessors"),
    (1005, "CPUSpeed"),
    (1006, "FileSystem"),
    (1007, "Registry"),
    (1008, "Script"),
];

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum EtlEventCategory {
    ProcessElevation,
    ProcessCreation,
    DriverMessage,
    Telemetry,
    EPMStateChange,
    UACPrompt,
    Other,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EtlEvent {
    pub timestamp: String,
    pub provider: String,
    pub provider_guid: String,
    pub event_id: u32,
    pub process_id: u32,
    pub thread_id: u32,
    pub message: Option<String>,
    pub category: EtlEventCategory,
    pub elevation_data: Option<ElevationData>,
    pub telemetry_data: Option<TelemetryData>,
    pub raw_data: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ElevationData {
    pub file_name: Option<String>,
    pub file_path: Option<String>,
    pub publisher: Option<String>,
    pub user_name: Option<String>,
    pub elevation_type: Option<String>,
    pub result: Option<String>,
    pub user_justification: Option<String>,
    pub hash_value: Option<String>,
    pub file_version: Option<String>,
    pub file_description: Option<String>,
    pub file_product_name: Option<String>,
    pub rule_id: Option<String>,
    pub policy_id: Option<String>,
    pub child_process_behavior: Option<String>,
    pub process_type: Option<String>,
    pub parent_process_name: Option<String>,
    pub is_background_process: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TelemetryData {
    pub component_name: Option<String>,
    pub correlation_id: Option<String>,
    pub event_name: Option<String>,
    pub event_message: Option<String>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub error_stack_trace: Option<String>,
    pub custom_json: Option<String>,
    pub app_info_id: Option<String>,
    pub app_info_version: Option<String>,
}

/// Resolve a provider GUID to a friendly name using the known providers list.
fn resolve_provider_name(guid: &str) -> String {
    let guid_lower = guid.to_lowercase();
    for (known_guid, name) in KNOWN_PROVIDERS {
        if known_guid.to_lowercase() == guid_lower {
            return name.to_string();
        }
    }
    guid.to_string()
}

/// Filter `<Null>` values, returning None for them.
fn filter_null(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.eq_ignore_ascii_case("<null>") || trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Classify an event by its EventID into a category.
fn classify_event(event_id: u32) -> EtlEventCategory {
    match event_id {
        1030 => EtlEventCategory::ProcessElevation,
        3 => EtlEventCategory::ProcessCreation,
        41 => EtlEventCategory::DriverMessage,
        50 => EtlEventCategory::UACPrompt,
        1058 | 1061 | 1067 => EtlEventCategory::EPMStateChange,
        1 | 4 => EtlEventCategory::Telemetry,
        _ => EtlEventCategory::Other,
    }
}

/// Build ElevationData from the raw EventData fields for EventID 1030.
fn build_elevation_data(raw_data: &HashMap<String, String>) -> ElevationData {
    let is_background = raw_data
        .get("IsBackgroundProcess")
        .and_then(|v| filter_null(v))
        .map(|v| v.eq_ignore_ascii_case("true") || v == "1");

    ElevationData {
        file_name: raw_data.get("FileName").and_then(|v| filter_null(v)),
        file_path: raw_data.get("FilePath").and_then(|v| filter_null(v)),
        publisher: raw_data.get("Publisher").and_then(|v| filter_null(v)),
        user_name: raw_data.get("UserName").and_then(|v| filter_null(v)),
        elevation_type: raw_data.get("ElevationType").and_then(|v| filter_null(v)),
        result: raw_data.get("Result").and_then(|v| filter_null(v)),
        user_justification: raw_data
            .get("UserJustification")
            .and_then(|v| filter_null(v)),
        hash_value: raw_data.get("HashValue").and_then(|v| filter_null(v)),
        file_version: raw_data.get("FileVersion").and_then(|v| filter_null(v)),
        file_description: raw_data
            .get("FileDescription")
            .and_then(|v| filter_null(v)),
        file_product_name: raw_data
            .get("FileProductName")
            .and_then(|v| filter_null(v)),
        rule_id: raw_data.get("RuleId").and_then(|v| filter_null(v)),
        policy_id: raw_data.get("PolicyId").and_then(|v| filter_null(v)),
        child_process_behavior: raw_data
            .get("ChildProcessBehavior")
            .and_then(|v| filter_null(v)),
        process_type: raw_data.get("ProcessType").and_then(|v| filter_null(v)),
        parent_process_name: raw_data
            .get("ParentProcessName")
            .and_then(|v| filter_null(v)),
        is_background_process: is_background,
    }
}

/// Build TelemetryData from the raw EventData fields for EventID 1/4.
fn build_telemetry_data(raw_data: &HashMap<String, String>) -> TelemetryData {
    TelemetryData {
        component_name: raw_data.get("ComponentName").and_then(|v| filter_null(v)),
        correlation_id: raw_data.get("CorrelationId").and_then(|v| filter_null(v)),
        event_name: raw_data.get("EventName").and_then(|v| filter_null(v)),
        event_message: raw_data.get("EventMessage").and_then(|v| filter_null(v)),
        error_code: raw_data.get("ErrorCode").and_then(|v| filter_null(v)),
        error_message: raw_data.get("ErrorMessage").and_then(|v| filter_null(v)),
        error_stack_trace: raw_data
            .get("ErrorStackTrace")
            .and_then(|v| filter_null(v)),
        custom_json: raw_data.get("CustomJson").and_then(|v| filter_null(v)),
        app_info_id: raw_data.get("AppInfoId").and_then(|v| filter_null(v)),
        app_info_version: raw_data.get("AppInfoVersion").and_then(|v| filter_null(v)),
    }
}

/// Parse ETL events from tracerpt XML content.
///
/// This is the core parsing logic that works on XML text. It uses regex-based
/// extraction following the PowerShell reference pattern, which is more reliable
/// than a strict XML parser for potentially malformed tracerpt output.
pub fn parse_etl_xml(content: &str) -> Result<Vec<EtlEvent>, String> {
    let event_re = Regex::new(r"(?s)<Event\s+xmlns=[^>]*>(.*?)</Event>")
        .map_err(|e| format!("Failed to compile event regex: {}", e))?;
    let provider_re =
        Regex::new(r#"<Provider\s+[^>]*?Guid="([^"]*)"[^>]*?(?:Name="([^"]*)")?[^/]*/>"#)
            .map_err(|e| format!("Failed to compile provider regex: {}", e))?;
    let provider_alt_re =
        Regex::new(r#"<Provider\s+[^>]*?Name="([^"]*)"[^>]*?Guid="([^"]*)"[^/]*/>"#)
            .map_err(|e| format!("Failed to compile provider alt regex: {}", e))?;
    let event_id_re = Regex::new(r"<EventID[^>]*>(\d+)</EventID>")
        .map_err(|e| format!("Failed to compile event ID regex: {}", e))?;
    let time_re = Regex::new(r#"<TimeCreated\s+SystemTime="([^"]*)"[^/]*/>"#)
        .map_err(|e| format!("Failed to compile time regex: {}", e))?;
    let exec_re =
        Regex::new(r#"<Execution\s+ProcessID="(\d+)"\s+ThreadID="(\d+)"[^/]*/>"#)
            .map_err(|e| format!("Failed to compile execution regex: {}", e))?;
    let data_re = Regex::new(r#"<Data\s+Name="([^"]*)">([\s\S]*?)</Data>"#)
        .map_err(|e| format!("Failed to compile data regex: {}", e))?;
    let message_re = Regex::new(r"(?s)<Message>(.*?)</Message>")
        .map_err(|e| format!("Failed to compile message regex: {}", e))?;

    let mut events = Vec::new();

    for event_cap in event_re.captures_iter(content) {
        if events.len() >= MAX_EVENTS {
            break;
        }

        let event_body = &event_cap[1];

        // Extract EventID
        let event_id = match event_id_re.captures(event_body) {
            Some(cap) => cap[1].parse::<u32>().unwrap_or(0),
            None => continue,
        };

        // Skip MSNT_SystemTrace header events
        if event_id == 0 {
            continue;
        }

        // Extract provider GUID and name
        let (provider_guid, provider_name_attr) =
            if let Some(cap) = provider_re.captures(event_body) {
                (
                    cap[1].to_string(),
                    cap.get(2).map(|m| m.as_str().to_string()),
                )
            } else if let Some(cap) = provider_alt_re.captures(event_body) {
                (cap[2].to_string(), Some(cap[1].to_string()))
            } else {
                (String::new(), None)
            };

        let provider = provider_name_attr.unwrap_or_else(|| resolve_provider_name(&provider_guid));

        // Extract timestamp
        let timestamp = time_re
            .captures(event_body)
            .map(|cap| cap[1].to_string())
            .unwrap_or_default();

        // Extract process and thread IDs
        let (process_id, thread_id) = exec_re
            .captures(event_body)
            .map(|cap| {
                (
                    cap[1].parse::<u32>().unwrap_or(0),
                    cap[2].parse::<u32>().unwrap_or(0),
                )
            })
            .unwrap_or((0, 0));

        // Extract EventData fields
        let mut raw_data = HashMap::new();
        for data_cap in data_re.captures_iter(event_body) {
            let name = data_cap[1].to_string();
            let value = data_cap[2].trim().to_string();
            raw_data.insert(name, value);
        }

        // Extract message from RenderingInfo
        let message = message_re
            .captures(event_body)
            .map(|cap| cap[1].trim().to_string())
            .and_then(|m| if m.is_empty() { None } else { Some(m) });

        // Classify the event
        let category = classify_event(event_id);

        // Build structured data based on category
        let elevation_data = if event_id == 1030 {
            Some(build_elevation_data(&raw_data))
        } else {
            None
        };

        let telemetry_data = if event_id == 1 || event_id == 4 {
            Some(build_telemetry_data(&raw_data))
        } else {
            None
        };

        events.push(EtlEvent {
            timestamp,
            provider,
            provider_guid,
            event_id,
            process_id,
            thread_id,
            message,
            category,
            elevation_data,
            telemetry_data,
            raw_data,
        });
    }

    Ok(events)
}

/// Parse ETL events from tracerpt XML output.
/// Accepts either .etl files (auto-converts via tracerpt on Windows) or .xml files.
pub fn parse_etl_file(path: &str) -> Result<Vec<EtlEvent>, String> {
    let path_lower = path.to_lowercase();

    if path_lower.ends_with(".etl") {
        parse_etl_binary(path)
    } else if path_lower.ends_with(".xml") {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read XML file '{}': {}", path, e))?;
        parse_etl_xml(&content)
    } else {
        Err(format!(
            "Unsupported file extension for ETL parsing: '{}'. Expected .etl or .xml",
            path
        ))
    }
}

/// Parse an .etl binary file by running tracerpt on Windows to convert it to XML.
#[cfg(target_os = "windows")]
fn parse_etl_binary(path: &str) -> Result<Vec<EtlEvent>, String> {
    let temp_dir = std::env::temp_dir();
    let temp_xml = temp_dir.join(format!(
        "cmtraceopen_etl_{}.xml",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0)
    ));

    let output = std::process::Command::new("tracerpt")
        .arg(path)
        .arg("-of")
        .arg("XML")
        .arg("-o")
        .arg(temp_xml.to_str().unwrap_or("output.xml"))
        .arg("-y")
        .output()
        .map_err(|e| format!("Failed to run tracerpt: {}. Is tracerpt.exe available?", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Clean up temp file on error
        let _ = std::fs::remove_file(&temp_xml);
        return Err(format!("tracerpt failed: {}", stderr));
    }

    let content = std::fs::read_to_string(&temp_xml).map_err(|e| {
        let _ = std::fs::remove_file(&temp_xml);
        format!("Failed to read tracerpt output: {}", e)
    })?;

    // Clean up temp file
    let _ = std::fs::remove_file(&temp_xml);

    parse_etl_xml(&content)
}

#[cfg(not(target_os = "windows"))]
fn parse_etl_binary(_path: &str) -> Result<Vec<EtlEvent>, String> {
    Err("ETL files can only be converted on Windows".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_etl_xml_events() {
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<Events>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Epm-Events" Guid="{56b809b5-d9e6-4f21-a807-2a1e3ed4159e}" />
    <EventID>1030</EventID>
    <Level>4</Level>
    <TimeCreated SystemTime="2026-03-17T15:18:00.626223400-04:00" />
    <Execution ProcessID="4668" ThreadID="7548" />
  </System>
  <EventData>
    <Data Name="FileName">bash.exe</Data>
    <Data Name="Publisher">The Git Development Community</Data>
    <Data Name="FilePath">C:\Program Files\Git\bin\bash.exe</Data>
    <Data Name="UserName">DOMAIN\testuser</Data>
  </EventData>
  <RenderingInfo Culture="en-US">
    <Message>[EPM Driver] - Unmanaged elevation occurred</Message>
  </RenderingInfo>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Epm-Events" Guid="{56b809b5-d9e6-4f21-a807-2a1e3ed4159e}" />
    <EventID>3</EventID>
    <Level>4</Level>
    <TimeCreated SystemTime="2026-03-17T15:19:00.000000000-04:00" />
    <Execution ProcessID="1234" ThreadID="5678" />
  </System>
  <EventData>
    <Data Name="ProcessName">notepad.exe</Data>
  </EventData>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Guid="{8ad61205-8e7e-4be4-8d30-e2480500b39a}" />
    <EventID>1</EventID>
    <Level>4</Level>
    <TimeCreated SystemTime="2026-03-17T15:20:00.000000000-04:00" />
    <Execution ProcessID="2000" ThreadID="3000" />
  </System>
  <EventData>
    <Data Name="ComponentName">EpmClient</Data>
    <Data Name="CorrelationId">abc-123</Data>
    <Data Name="EventName">PolicySync</Data>
  </EventData>
</Event>
</Events>"#;

        let events = parse_etl_xml(xml).expect("Should parse successfully");
        assert_eq!(events.len(), 3);

        // First event: ProcessElevation (EventID 1030)
        assert_eq!(events[0].event_id, 1030);
        assert!(matches!(
            events[0].category,
            EtlEventCategory::ProcessElevation
        ));
        assert_eq!(events[0].provider, "Microsoft-Epm-Events");
        assert_eq!(events[0].process_id, 4668);
        assert_eq!(events[0].thread_id, 7548);
        assert_eq!(
            events[0].timestamp,
            "2026-03-17T15:18:00.626223400-04:00"
        );
        assert_eq!(
            events[0].message.as_deref(),
            Some("[EPM Driver] - Unmanaged elevation occurred")
        );

        let elev = events[0].elevation_data.as_ref().unwrap();
        assert_eq!(elev.file_name.as_deref(), Some("bash.exe"));
        assert_eq!(
            elev.publisher.as_deref(),
            Some("The Git Development Community")
        );
        assert_eq!(
            elev.file_path.as_deref(),
            Some("C:\\Program Files\\Git\\bin\\bash.exe")
        );
        assert_eq!(elev.user_name.as_deref(), Some("DOMAIN\\testuser"));

        // Second event: ProcessCreation (EventID 3)
        assert_eq!(events[1].event_id, 3);
        assert!(matches!(
            events[1].category,
            EtlEventCategory::ProcessCreation
        ));
        assert!(events[1].elevation_data.is_none());
        assert!(events[1].telemetry_data.is_none());
        assert_eq!(events[1].process_id, 1234);

        // Third event: Telemetry (EventID 1)
        assert_eq!(events[2].event_id, 1);
        assert!(matches!(events[2].category, EtlEventCategory::Telemetry));
        assert_eq!(
            events[2].provider,
            "Microsoft-Intune-Epm-Client-Telemetry"
        );

        let telem = events[2].telemetry_data.as_ref().unwrap();
        assert_eq!(telem.component_name.as_deref(), Some("EpmClient"));
        assert_eq!(telem.correlation_id.as_deref(), Some("abc-123"));
        assert_eq!(telem.event_name.as_deref(), Some("PolicySync"));
    }

    #[test]
    fn test_skip_header_events() {
        let xml = r#"<Events>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="MSNT_SystemTrace" Guid="{9e814aad-3204-11d2-9a82-006008a86939}" />
    <EventID>0</EventID>
    <Level>0</Level>
    <TimeCreated SystemTime="2026-03-17T00:00:00.000000000Z" />
    <Execution ProcessID="0" ThreadID="0" />
  </System>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Epm-Events" Guid="{56b809b5-d9e6-4f21-a807-2a1e3ed4159e}" />
    <EventID>1030</EventID>
    <Level>4</Level>
    <TimeCreated SystemTime="2026-03-17T15:18:00.000000000-04:00" />
    <Execution ProcessID="100" ThreadID="200" />
  </System>
  <EventData>
    <Data Name="FileName">cmd.exe</Data>
  </EventData>
</Event>
</Events>"#;

        let events = parse_etl_xml(xml).expect("Should parse successfully");
        // EventID 0 should be skipped
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_id, 1030);
    }

    #[test]
    fn test_null_values_filtered() {
        let xml = r#"<Events>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Epm-Events" Guid="{56b809b5-d9e6-4f21-a807-2a1e3ed4159e}" />
    <EventID>1030</EventID>
    <Level>4</Level>
    <TimeCreated SystemTime="2026-03-17T15:18:00.000000000-04:00" />
    <Execution ProcessID="100" ThreadID="200" />
  </System>
  <EventData>
    <Data Name="FileName">test.exe</Data>
    <Data Name="Publisher"><Null></Data>
    <Data Name="FilePath"><Null></Data>
    <Data Name="UserName">testuser</Data>
    <Data Name="UserJustification"><Null></Data>
    <Data Name="HashValue"></Data>
  </EventData>
</Event>
</Events>"#;

        let events = parse_etl_xml(xml).expect("Should parse successfully");
        assert_eq!(events.len(), 1);

        let elev = events[0].elevation_data.as_ref().unwrap();
        assert_eq!(elev.file_name.as_deref(), Some("test.exe"));
        assert!(elev.publisher.is_none(), "Null publisher should be None");
        assert!(elev.file_path.is_none(), "Null file_path should be None");
        assert_eq!(elev.user_name.as_deref(), Some("testuser"));
        assert!(
            elev.user_justification.is_none(),
            "Null justification should be None"
        );
        assert!(elev.hash_value.is_none(), "Empty hash should be None");
    }

    #[test]
    fn test_provider_guid_resolution() {
        assert_eq!(
            resolve_provider_name("{56b809b5-d9e6-4f21-a807-2a1e3ed4159e}"),
            "Microsoft-Epm-Events"
        );
        assert_eq!(
            resolve_provider_name("{1db28f2e-8f80-4027-8c5a-a11f7f10f62d}"),
            "Microsoft_SideCar"
        );
        // Unknown GUID should return itself
        assert_eq!(
            resolve_provider_name("{00000000-0000-0000-0000-000000000000}"),
            "{00000000-0000-0000-0000-000000000000}"
        );
    }

    #[test]
    fn test_classify_event() {
        assert!(matches!(
            classify_event(1030),
            EtlEventCategory::ProcessElevation
        ));
        assert!(matches!(
            classify_event(3),
            EtlEventCategory::ProcessCreation
        ));
        assert!(matches!(
            classify_event(41),
            EtlEventCategory::DriverMessage
        ));
        assert!(matches!(classify_event(50), EtlEventCategory::UACPrompt));
        assert!(matches!(
            classify_event(1058),
            EtlEventCategory::EPMStateChange
        ));
        assert!(matches!(
            classify_event(1061),
            EtlEventCategory::EPMStateChange
        ));
        assert!(matches!(
            classify_event(1067),
            EtlEventCategory::EPMStateChange
        ));
        assert!(matches!(classify_event(1), EtlEventCategory::Telemetry));
        assert!(matches!(classify_event(4), EtlEventCategory::Telemetry));
        assert!(matches!(classify_event(9999), EtlEventCategory::Other));
    }

    #[test]
    fn test_unsupported_extension() {
        let result = parse_etl_file("test.txt");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("Unsupported file extension"));
    }

    #[test]
    fn test_max_events_cap() {
        // Generate XML with MAX_EVENTS + 10 events to verify capping
        let mut xml = String::from("<Events>");
        for i in 1..=(MAX_EVENTS + 10) {
            xml.push_str(&format!(
                r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Test" Guid="{{test}}" />
    <EventID>{}</EventID>
    <TimeCreated SystemTime="2026-03-17T00:00:00Z" />
    <Execution ProcessID="1" ThreadID="1" />
  </System>
</Event>"#,
                i
            ));
        }
        xml.push_str("</Events>");

        let events = parse_etl_xml(&xml).expect("Should parse");
        assert_eq!(events.len(), MAX_EVENTS);
    }
}
