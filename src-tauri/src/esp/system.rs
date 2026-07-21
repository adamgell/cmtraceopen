//! Bounded, read-only system evidence acquisition for ESP diagnostics.

use std::collections::BTreeMap;
use std::time::Duration;

use cmtraceopen_parser::esp::{
    normalize_timestamp, EspClassifiedString, EspDeliveryOptimizationEventKind,
    EspDeliveryOptimizationEvidence, EspDeliveryOptimizationObservation, EspElevationState,
    EspEvidenceProvenance, EspEvidenceRef, EspHardwareEvidence, EspObservationContext,
    EspParseState, EspSensitivity, EspSourceAccessState, EspSourceKind, EspSystemFact,
    EspSystemObservation,
};
#[cfg(any(target_os = "windows", test))]
use regex::Regex;
use serde::{Deserialize, Serialize};
#[cfg(any(target_os = "windows", test))]
use serde_json::Value;

pub const SYSTEM_QUERY_TIMEOUT: Duration = Duration::from_secs(3);
pub const MAX_SYSTEM_ROWS: usize = 64;

#[cfg(any(target_os = "windows", test))]
const DELIVERY_OPTIMIZATION_SCRIPT: &str = concat!(
    "$ErrorActionPreference='Stop';try{",
    "$env:PSModulePath=[System.IO.Path]::Combine($PSHOME,'Modules');",
    "$deliveryOptimizationModule=[System.IO.Path]::Combine($env:PSModulePath,'DeliveryOptimization','DeliveryOptimization.psd1');",
    "Microsoft.PowerShell.Core\\Import-Module -Name $deliveryOptimizationModule -Force -ErrorAction Stop;",
    "$perf=DeliveryOptimization\\Get-DeliveryOptimizationPerfSnapThisMonth|Select-Object DownloadHttpBytes,DownloadLanBytes,DownloadCacheHostBytes;",
    "$events=@(DeliveryOptimization\\Get-DeliveryOptimizationLog|Where-Object {$_.Function -match '(DownloadStart)|(DownloadCompleted)' -and ($_.Message -like '*.intunewin.bin,*' -or $_.Message -like '*Microsoft Office Click-to-Run*')}|Select-Object -First 64|ForEach-Object {[pscustomobject]@{Function=[string]$_.Function;TimeCreated=$_.TimeCreated.ToUniversalTime().ToString('o');Message=[string]$_.Message}});",
    "[pscustomobject]@{perf=$perf;events=$events}|ConvertTo-Json -Compress -Depth 4;",
    "}catch{[Console]::Error.Write(('CMTRACEOPEN_HRESULT=0x{0:X8}' -f [int]$_.Exception.HResult));exit 1}",
);

#[cfg(target_os = "windows")]
const MAX_COMMAND_OUTPUT_BYTES: usize = 1024 * 1024;
#[cfg(target_os = "windows")]
const MAX_COMMAND_ERROR_BYTES: usize = 16 * 1024;

#[cfg(any(target_os = "windows", test))]
#[derive(Debug)]
struct BoundedCommandOutput {
    status: std::process::ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    stdout_truncated: bool,
    stderr_truncated: bool,
}

#[cfg(any(target_os = "windows", test))]
#[derive(Debug)]
struct BoundedReaderOutput {
    bytes: Vec<u8>,
    truncated: bool,
}

#[cfg(any(target_os = "windows", test))]
fn run_bounded_command(
    mut command: std::process::Command,
    timeout: Duration,
    max_stdout_bytes: usize,
    max_stderr_bytes: usize,
) -> Result<BoundedCommandOutput, SystemReadError> {
    use std::io::ErrorKind;
    use std::process::Stdio;
    use std::time::Instant;

    if timeout.is_zero() {
        return Err(SystemReadError::TimedOut);
    }

    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Every bounded ESP subprocess is spawned here, so hide the console window
    // at this choke point to keep console tools (powershell.exe, etc.) from
    // flashing a window when ESP diagnostics start. No-op off Windows.
    crate::process_util::apply_hidden_window(&mut command);
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) if error.kind() == ErrorKind::NotFound => return Err(SystemReadError::Missing),
        Err(_) => {
            return Err(SystemReadError::Failed(
                "Delivery Optimization command could not start".to_string(),
            ))
        }
    };

    let stdout = child.stdout.take().ok_or_else(|| {
        SystemReadError::Failed("Delivery Optimization stdout pipe was unavailable".to_string())
    })?;
    let stderr = child.stderr.take().ok_or_else(|| {
        SystemReadError::Failed("Delivery Optimization stderr pipe was unavailable".to_string())
    })?;
    let stdout_reader = match spawn_bounded_reader(stdout, max_stdout_bytes, "stdout") {
        Ok(reader) => reader,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
    };
    let stderr_reader = match spawn_bounded_reader(stderr, max_stderr_bytes, "stderr") {
        Ok(reader) => reader,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_reader.join();
            return Err(error);
        }
    };

    let deadline = Instant::now() + timeout;
    let (status, timed_out) = loop {
        match child.try_wait() {
            Ok(Some(status)) => break (status, false),
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Ok(None) => {
                let _ = child.kill();
                let status = child.wait().map_err(|_| {
                    SystemReadError::Failed(
                        "Delivery Optimization command could not be reaped after timeout"
                            .to_string(),
                    )
                })?;
                break (status, true);
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                return Err(SystemReadError::Failed(
                    "Delivery Optimization command wait failed".to_string(),
                ));
            }
        }
    };

    let stdout = join_bounded_reader(stdout_reader, "stdout")?;
    let stderr = join_bounded_reader(stderr_reader, "stderr")?;
    if timed_out {
        return Err(SystemReadError::TimedOut);
    }

    Ok(BoundedCommandOutput {
        status,
        stdout: stdout.bytes,
        stderr: stderr.bytes,
        stdout_truncated: stdout.truncated,
        stderr_truncated: stderr.truncated,
    })
}

#[cfg(any(target_os = "windows", test))]
fn spawn_bounded_reader<R>(
    reader: R,
    max_bytes: usize,
    stream_name: &str,
) -> Result<std::thread::JoinHandle<std::io::Result<BoundedReaderOutput>>, SystemReadError>
where
    R: std::io::Read + Send + 'static,
{
    std::thread::Builder::new()
        .name(format!("esp-command-{stream_name}"))
        .spawn(move || drain_bounded_reader(reader, max_bytes))
        .map_err(|_| {
            SystemReadError::Failed(format!(
                "Delivery Optimization {stream_name} reader could not start"
            ))
        })
}

#[cfg(any(target_os = "windows", test))]
fn drain_bounded_reader(
    mut reader: impl std::io::Read,
    max_bytes: usize,
) -> std::io::Result<BoundedReaderOutput> {
    let mut bytes = Vec::with_capacity(max_bytes.min(8 * 1024));
    let mut truncated = false;
    let mut buffer = [0_u8; 8 * 1024];

    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let remaining = max_bytes.saturating_sub(bytes.len());
        let retained = remaining.min(read);
        bytes.extend_from_slice(&buffer[..retained]);
        truncated |= retained < read;
    }

    Ok(BoundedReaderOutput { bytes, truncated })
}

#[cfg(any(target_os = "windows", test))]
fn join_bounded_reader(
    reader: std::thread::JoinHandle<std::io::Result<BoundedReaderOutput>>,
    stream_name: &str,
) -> Result<BoundedReaderOutput, SystemReadError> {
    reader
        .join()
        .map_err(|_| {
            SystemReadError::Failed(format!(
                "Delivery Optimization {stream_name} reader stopped unexpectedly"
            ))
        })?
        .map_err(|_| {
            SystemReadError::Failed(format!(
                "Delivery Optimization {stream_name} could not be read"
            ))
        })
}

#[cfg(any(target_os = "windows", test))]
fn classify_delivery_command_failure(output: &BoundedCommandOutput) -> SystemReadError {
    if structured_hresult(&output.stderr).is_some_and(|code| windows_hresult_matches(code, 5)) {
        SystemReadError::PermissionDenied
    } else {
        SystemReadError::Failed(format!(
            "Delivery Optimization command failed with exit code {}",
            output.status.code().unwrap_or(-1)
        ))
    }
}

#[cfg(any(target_os = "windows", test))]
fn structured_hresult(stderr: &[u8]) -> Option<u32> {
    const PREFIX: &str = "CMTRACEOPEN_HRESULT=0x";
    let stderr = std::str::from_utf8(stderr).ok()?;
    let value = stderr.split_once(PREFIX)?.1;
    let digits = value
        .chars()
        .take_while(|character| character.is_ascii_hexdigit())
        .take(8)
        .collect::<String>();
    (!digits.is_empty())
        .then(|| u32::from_str_radix(&digits, 16).ok())
        .flatten()
}

#[cfg(any(target_os = "windows", test))]
fn windows_hresult_matches(code: u32, win32_code: u32) -> bool {
    code == win32_code || code == (0x8007_0000 | win32_code)
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub enum SystemSource {
    Elevation,
    OperatingSystem,
    ComputerSystem,
    Bios,
    Tpm,
    ImeService,
    DeliveryOptimization,
}

impl SystemSource {
    fn artifact_id(self) -> &'static str {
        match self {
            Self::Elevation => "system.elevation",
            Self::OperatingSystem => "system.operating-system",
            Self::ComputerSystem => "system.computer-system",
            Self::Bios => "system.bios",
            Self::Tpm => "system.tpm",
            Self::ImeService => "system.ime-service",
            Self::DeliveryOptimization => "system.delivery-optimization",
        }
    }
}

const QUERY_SOURCES: &[SystemSource] = &[
    SystemSource::OperatingSystem,
    SystemSource::ComputerSystem,
    SystemSource::Bios,
    SystemSource::Tpm,
    SystemSource::ImeService,
    SystemSource::DeliveryOptimization,
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SystemReadError {
    Missing,
    PermissionDenied,
    TimedOut,
    Failed(String),
    Unsupported,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SystemRow {
    values: BTreeMap<String, String>,
}

impl SystemRow {
    pub fn new<I, K, V>(values: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        Self {
            values: values
                .into_iter()
                .map(|(name, value)| (name.into(), value.into()))
                .collect(),
        }
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.values
            .iter()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemQueryBatch {
    pub rows: Vec<SystemRow>,
    pub completion: Result<(), SystemReadError>,
}

impl SystemQueryBatch {
    pub fn complete(rows: Vec<SystemRow>) -> Self {
        Self {
            rows,
            completion: Ok(()),
        }
    }

    pub fn missing() -> Self {
        Self {
            rows: Vec::new(),
            completion: Err(SystemReadError::Missing),
        }
    }

    pub fn unsupported() -> Self {
        Self {
            rows: Vec::new(),
            completion: Err(SystemReadError::Unsupported),
        }
    }
}

pub trait SystemProvider {
    fn elevation(&self) -> Result<bool, SystemReadError>;

    fn query(&self, source: SystemSource, timeout: Duration, max_rows: usize) -> SystemQueryBatch;
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SystemSourceCoverage {
    pub source: SystemSource,
    pub access_state: EspSourceAccessState,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ImeServiceEvidence {
    pub state: Option<String>,
    pub start_mode: Option<String>,
    pub process_id: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SystemEvidence {
    pub elevation: EspElevationState,
    pub hostname: Option<String>,
    pub hardware: EspHardwareEvidence,
    pub ime_service: Option<ImeServiceEvidence>,
    pub delivery_optimization: Option<EspDeliveryOptimizationEvidence>,
    pub delivery_optimization_observations: Vec<EspDeliveryOptimizationObservation>,
    pub observations: Vec<EspSystemObservation>,
    pub coverage: Vec<SystemSourceCoverage>,
}

pub fn elevation_from_probe(
    result: Result<bool, SystemReadError>,
) -> (EspElevationState, SystemSourceCoverage) {
    match result {
        Ok(is_elevated) => (
            EspElevationState {
                is_elevated,
                restart_supported: true,
                restricted_sources: Vec::new(),
            },
            SystemSourceCoverage {
                source: SystemSource::Elevation,
                access_state: EspSourceAccessState::Available,
                detail: None,
            },
        ),
        Err(error) => {
            let restart_supported = error != SystemReadError::Unsupported;
            let (access_state, detail) = coverage_for_error(&error, false);
            (
                EspElevationState {
                    is_elevated: false,
                    restart_supported,
                    restricted_sources: Vec::new(),
                },
                SystemSourceCoverage {
                    source: SystemSource::Elevation,
                    access_state,
                    detail,
                },
            )
        }
    }
}

pub fn current_elevation_state() -> EspElevationState {
    elevation_from_probe(LiveSystemProvider.elevation()).0
}

pub fn collect_system_evidence(
    provider: &impl SystemProvider,
    observed_at_utc: &str,
) -> SystemEvidence {
    let (mut elevation, elevation_coverage) = elevation_from_probe(provider.elevation());
    let mut rows_by_source = BTreeMap::new();
    let mut coverage = vec![elevation_coverage];

    for &source in QUERY_SOURCES {
        let mut batch = provider.query(source, SYSTEM_QUERY_TIMEOUT, MAX_SYSTEM_ROWS);
        batch.rows.truncate(MAX_SYSTEM_ROWS);
        let partial = !batch.rows.is_empty();
        let (access_state, detail) = match &batch.completion {
            Ok(()) => (EspSourceAccessState::Available, None),
            Err(error) => coverage_for_error(error, partial),
        };
        if access_state == EspSourceAccessState::PermissionDenied {
            elevation
                .restricted_sources
                .push(source.artifact_id().to_string());
        }
        coverage.push(SystemSourceCoverage {
            source,
            access_state,
            detail,
        });
        rows_by_source.insert(source, batch.rows);
    }

    elevation.restricted_sources.sort();
    elevation.restricted_sources.dedup();

    let operating_system = rows_by_source
        .get(&SystemSource::OperatingSystem)
        .and_then(|rows| rows.first());
    let computer_system = rows_by_source
        .get(&SystemSource::ComputerSystem)
        .and_then(|rows| rows.first());
    let bios = rows_by_source
        .get(&SystemSource::Bios)
        .and_then(|rows| rows.first());
    let tpm = rows_by_source
        .get(&SystemSource::Tpm)
        .and_then(|rows| rows.first());

    let hostname = value(computer_system, "Name");
    let os_version = value(operating_system, "Version");
    let os_build = value(operating_system, "BuildNumber");
    let manufacturer = value(computer_system, "Manufacturer");
    let model = value(computer_system, "Model");
    let serial_number = value(bios, "SerialNumber");
    let tpm_version = value(tpm, "SpecVersion")
        .and_then(|raw| raw.split(',').next().map(str::trim).map(str::to_string))
        .filter(|raw| !raw.is_empty());

    let hardware = EspHardwareEvidence {
        os_version: os_version.clone(),
        os_build: os_build.clone(),
        manufacturer: manufacturer.clone(),
        model: model.clone(),
        serial_number: serial_number.clone().map(|value| EspClassifiedString {
            value,
            sensitivity: EspSensitivity::Sensitive,
        }),
        tpm_version: tpm_version.clone(),
        evidence: Vec::new(),
    };

    let facts = [
        (
            SystemSource::ComputerSystem,
            hostname.clone().map(EspSystemFact::Hostname),
        ),
        (
            SystemSource::OperatingSystem,
            os_version.map(EspSystemFact::OsVersion),
        ),
        (
            SystemSource::OperatingSystem,
            os_build.map(EspSystemFact::OsBuild),
        ),
        (
            SystemSource::ComputerSystem,
            manufacturer.map(EspSystemFact::Manufacturer),
        ),
        (
            SystemSource::ComputerSystem,
            model.map(EspSystemFact::Model),
        ),
        (
            SystemSource::Bios,
            serial_number.map(EspSystemFact::SerialNumber),
        ),
        (
            SystemSource::Tpm,
            tpm_version.map(EspSystemFact::TpmVersion),
        ),
        (
            SystemSource::Elevation,
            Some(EspSystemFact::Elevation(elevation.clone())),
        ),
    ];
    let observations = facts
        .into_iter()
        .filter_map(|(source, fact)| fact.map(|fact| (source, fact)))
        .enumerate()
        .map(|(index, (source, fact))| {
            let sensitivity = if matches!(fact, EspSystemFact::SerialNumber(_)) {
                EspSensitivity::Sensitive
            } else {
                EspSensitivity::Public
            };
            EspSystemObservation {
                context: observation_context(source, index, observed_at_utc, sensitivity),
                fact,
            }
        })
        .collect();

    let ime_service = rows_by_source
        .get(&SystemSource::ImeService)
        .and_then(|rows| rows.first())
        .map(|row| ImeServiceEvidence {
            state: value(Some(row), "State"),
            start_mode: value(Some(row), "StartMode"),
            process_id: row.get("ProcessId").and_then(|raw| raw.parse().ok()),
        });

    let delivery_rows = rows_by_source
        .get(&SystemSource::DeliveryOptimization)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let delivery_optimization = delivery_optimization_from_rows(delivery_rows, observed_at_utc);
    let delivery_optimization_observations = delivery_observations(delivery_rows, observed_at_utc);

    SystemEvidence {
        elevation,
        hostname,
        hardware,
        ime_service,
        delivery_optimization,
        delivery_optimization_observations,
        observations,
        coverage,
    }
}

pub fn delivery_optimization_from_rows(
    rows: &[SystemRow],
    _observed_at_utc: &str,
) -> Option<EspDeliveryOptimizationEvidence> {
    let counter_rows = rows
        .iter()
        .filter(|row| {
            !matches!(
                row.get("_Kind"),
                Some(kind)
                    if kind.eq_ignore_ascii_case("Status")
                        || kind.eq_ignore_ascii_case("Event")
            )
        })
        .collect::<Vec<_>>();
    if counter_rows.is_empty() {
        return None;
    }

    let sum = |name: &str| {
        counter_rows.iter().fold(0_u64, |total, row| {
            total.saturating_add(row.get(name).and_then(|raw| raw.parse().ok()).unwrap_or(0))
        })
    };
    let download_http_bytes = sum("DownloadHttpBytes");
    let download_lan_bytes = sum("DownloadLanBytes");
    let download_cache_host_bytes = sum("DownloadCacheHostBytes");
    let share = |bytes: u64| {
        (download_http_bytes != 0).then(|| (bytes as f64 / download_http_bytes as f64) * 100.0)
    };

    Some(EspDeliveryOptimizationEvidence {
        download_http_bytes,
        download_lan_bytes,
        download_cache_host_bytes,
        peer_share_percent: share(download_lan_bytes),
        connected_cache_share_percent: share(download_cache_host_bytes),
        transfers: Vec::new(),
        evidence: Vec::new(),
    })
}

fn delivery_observations(
    rows: &[SystemRow],
    observed_at_utc: &str,
) -> Vec<EspDeliveryOptimizationObservation> {
    rows.iter()
        .filter(|row| matches!(row.get("_Kind"), Some(kind) if kind.eq_ignore_ascii_case("Event")))
        .filter_map(|row| {
            let function = row.get("Function")?;
            let kind = if function.to_ascii_lowercase().contains("downloadcompleted") {
                EspDeliveryOptimizationEventKind::DownloadCompleted
            } else if function.to_ascii_lowercase().contains("downloadstart") {
                EspDeliveryOptimizationEventKind::DownloadStarted
            } else {
                return None;
            };
            Some((row, kind))
        })
        .take(MAX_SYSTEM_ROWS)
        .enumerate()
        .map(|(index, (row, kind))| {
            let mut context = observation_context(
                SystemSource::DeliveryOptimization,
                index,
                observed_at_utc,
                EspSensitivity::Public,
            );
            context.source_timestamp = value(Some(row), "TimeCreated")
                .map(|timestamp| normalize_timestamp(&timestamp, None));
            EspDeliveryOptimizationObservation {
                context,
                kind,
                content_id: value(Some(row), "ContentId"),
                app_id: value(Some(row), "AppId"),
                http_bytes: row.get("BytesFromHttp").and_then(|raw| raw.parse().ok()),
                lan_bytes: row
                    .get("BytesFromLanPeers")
                    .and_then(|raw| raw.parse().ok()),
                cache_host_bytes: row
                    .get("BytesFromCacheServer")
                    .and_then(|raw| raw.parse().ok()),
            }
        })
        .collect()
}

#[cfg(any(target_os = "windows", test))]
fn parse_delivery_json(output: &[u8], max_rows: usize) -> Result<Vec<SystemRow>, SystemReadError> {
    let document: Value = serde_json::from_slice(output).map_err(|_| {
        SystemReadError::Failed("Delivery Optimization JSON was malformed".to_string())
    })?;
    let mut rows = Vec::new();
    if let Some(perf) = document.get("perf").and_then(Value::as_object) {
        rows.push(json_row(perf, "Perf"));
    }
    if let Some(events) = document.get("events") {
        let records = events
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or_else(|| std::slice::from_ref(events));
        rows.extend(
            records
                .iter()
                .take(max_rows.saturating_sub(rows.len()))
                .filter_map(Value::as_object)
                .filter_map(delivery_event_row),
        );
    }
    rows.truncate(max_rows);
    Ok(rows)
}

#[cfg(any(target_os = "windows", test))]
fn delivery_event_row(values: &serde_json::Map<String, Value>) -> Option<SystemRow> {
    let function = values.get("Function")?.as_str()?;
    let lower_function = function.to_ascii_lowercase();
    if !lower_function.contains("downloadstart") && !lower_function.contains("downloadcompleted") {
        return None;
    }

    let message = values.get("Message").and_then(Value::as_str);
    let content_id = values
        .get("ContentId")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| message.and_then(extract_delivery_content_id));
    let app_id = values
        .get("AppId")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| message.and_then(extract_delivery_app_id));

    let mut row = vec![
        ("_Kind".to_string(), "Event".to_string()),
        ("Function".to_string(), function.to_string()),
    ];
    if let Some(timestamp) = values.get("TimeCreated").and_then(Value::as_str) {
        row.push(("TimeCreated".to_string(), timestamp.to_string()));
    }
    if let Some(content_id) = content_id.filter(|value| !value.trim().is_empty()) {
        row.push(("ContentId".to_string(), content_id));
    }
    if let Some(app_id) = app_id.filter(|value| !value.trim().is_empty()) {
        row.push(("AppId".to_string(), app_id));
    }
    Some(SystemRow::new(row))
}

#[cfg(any(target_os = "windows", test))]
fn extract_delivery_content_id(message: &str) -> Option<String> {
    let file_id = Regex::new(r"(?i)\bfileid\s*(?::|=)\s*([^,\s]+)")
        .expect("constant Delivery Optimization file-id regex");
    let mut content_id = file_id.captures(message)?.get(1)?.as_str();
    let guid_prefix =
        Regex::new(r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
            .expect("constant Delivery Optimization GUID-prefix regex");
    if content_id.len() > 37
        && content_id.as_bytes().get(36) == Some(&b'.')
        && guid_prefix.is_match(&content_id[..36])
    {
        content_id = &content_id[37..];
    }
    (!content_id.is_empty()).then(|| content_id.to_string())
}

#[cfg(any(target_os = "windows", test))]
fn extract_delivery_app_id(message: &str) -> Option<String> {
    let labeled_app_id = Regex::new(
        r"(?i)\bapp(?:lication)?id\s*(?::|=)\s*\{?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\}?",
    )
    .expect("constant Delivery Optimization app-id regex");
    if let Some(app_id) = labeled_app_id
        .captures(message)
        .and_then(|captures| captures.get(1))
    {
        return Some(app_id.as_str().to_string());
    }

    let lower_message = message.to_ascii_lowercase();
    let marker = ".intunewin.bin,";
    let marker_index = lower_message.find(marker)?;
    let guid = Regex::new(r"(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
        .expect("constant Delivery Optimization trailing GUID regex");
    if let Some(app_id) = guid.find_iter(&message[..marker_index]).last() {
        return Some(app_id.as_str().to_string());
    }
    let tail = &message[marker_index + marker.len()..];
    guid.find(tail).map(|value| value.as_str().to_string())
}

#[cfg(any(target_os = "windows", test))]
fn json_row(values: &serde_json::Map<String, Value>, kind: &str) -> SystemRow {
    let mut row = vec![("_Kind".to_string(), kind.to_string())];
    row.extend(values.iter().filter_map(|(name, value)| match value {
        Value::String(value) => Some((name.clone(), value.clone())),
        Value::Number(value) => Some((name.clone(), value.to_string())),
        Value::Bool(value) => Some((name.clone(), value.to_string())),
        Value::Null | Value::Array(_) | Value::Object(_) => None,
    }));
    SystemRow::new(row)
}

fn value(row: Option<&SystemRow>, name: &str) -> Option<String> {
    row.and_then(|row| row.get(name))
        .map(str::trim)
        .filter(|value| {
            !value.is_empty()
                && !value.eq_ignore_ascii_case("unknown")
                && !value.eq_ignore_ascii_case("to be filled by o.e.m.")
        })
        .map(str::to_string)
}

fn coverage_for_error(
    error: &SystemReadError,
    partial: bool,
) -> (EspSourceAccessState, Option<String>) {
    match error {
        SystemReadError::Missing => (EspSourceAccessState::Missing, None),
        SystemReadError::PermissionDenied => (EspSourceAccessState::PermissionDenied, None),
        SystemReadError::TimedOut => (
            EspSourceAccessState::Failed,
            Some(
                if partial {
                    "query timed out after partial results"
                } else {
                    "query timed out"
                }
                .to_string(),
            ),
        ),
        SystemReadError::Failed(detail) => (EspSourceAccessState::Failed, Some(detail.clone())),
        SystemReadError::Unsupported => (EspSourceAccessState::Unsupported, None),
    }
}

fn observation_context(
    source: SystemSource,
    index: usize,
    observed_at_utc: &str,
    sensitivity: EspSensitivity,
) -> EspObservationContext {
    let source_artifact_id = source.artifact_id().to_string();
    EspObservationContext {
        evidence_ref: EspEvidenceRef {
            evidence_id: format!("esp-{}-{index}", source.artifact_id()),
            source_artifact_id: source_artifact_id.clone(),
        },
        provenance: EspEvidenceProvenance {
            source_kind: if source == SystemSource::DeliveryOptimization {
                EspSourceKind::DeliveryOptimization
            } else {
                EspSourceKind::System
            },
            source_artifact_id,
            file_path: None,
            line_number: None,
            record_number: Some(index as u64),
            registry: None,
            event: None,
        },
        source_timestamp: None,
        observed_at_utc: observed_at_utc.to_string(),
        sensitivity,
        parse_state: EspParseState::Parsed,
        access_state: EspSourceAccessState::Available,
    }
}

#[cfg(any(target_os = "windows", test))]
const SYSTEM_QUERY_CANCELLATION_GRACE: Duration = Duration::from_millis(250);

#[cfg(any(target_os = "windows", test))]
const SYSTEM_QUERY_COM_CANCEL_TIMEOUT_SECONDS: u32 = 1;

#[cfg(any(target_os = "windows", test))]
const SYSTEM_QUERY_WORKER_COUNT: usize = 4;

#[cfg(test)]
const SYSTEM_QUERY_MAX_OWNED_WORKERS: usize = 64;

#[cfg(all(target_os = "windows", not(test)))]
const SYSTEM_QUERY_MAX_OWNED_WORKERS: usize = 16;

#[cfg(any(target_os = "windows", test))]
#[derive(Clone)]
struct SystemQueryCancellation {
    requested: std::sync::Arc<std::sync::atomic::AtomicBool>,
    worker_thread: std::sync::Arc<std::sync::Mutex<Option<std::thread::Thread>>>,
    #[cfg(target_os = "windows")]
    worker_thread_id: std::sync::Arc<std::sync::atomic::AtomicU32>,
}

#[cfg(any(target_os = "windows", test))]
impl SystemQueryCancellation {
    fn new() -> Self {
        Self {
            requested: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            worker_thread: std::sync::Arc::new(std::sync::Mutex::new(None)),
            #[cfg(target_os = "windows")]
            worker_thread_id: std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0)),
        }
    }

    fn register_worker(&self) {
        *self
            .worker_thread
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(std::thread::current());
        #[cfg(target_os = "windows")]
        self.worker_thread_id.store(
            // SAFETY: GetCurrentThreadId has no preconditions and returns the caller's ID.
            unsafe { windows::Win32::System::Threading::GetCurrentThreadId() },
            std::sync::atomic::Ordering::Release,
        );
    }

    fn clear_worker(&self) {
        #[cfg(target_os = "windows")]
        self.worker_thread_id
            .store(0, std::sync::atomic::Ordering::Release);
        *self
            .worker_thread
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
    }

    fn is_cancelled(&self) -> bool {
        self.requested.load(std::sync::atomic::Ordering::Acquire)
    }

    fn request_cancel(&self) {
        self.requested
            .store(true, std::sync::atomic::Ordering::Release);
        if let Some(worker) = self
            .worker_thread
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
        {
            worker.unpark();
        }
        #[cfg(target_os = "windows")]
        {
            let thread_id = self
                .worker_thread_id
                .load(std::sync::atomic::Ordering::Acquire);
            if thread_id != 0 {
                // SAFETY: the worker enables COM call cancellation before making blocking WMI calls.
                let _ = unsafe {
                    windows::Win32::System::Com::CoCancelCall(
                        thread_id,
                        SYSTEM_QUERY_COM_CANCEL_TIMEOUT_SECONDS,
                    )
                };
            }
        }
    }
}

#[cfg(any(target_os = "windows", test))]
type SystemQueryWork = Box<
    dyn FnOnce(
            std::time::Instant,
            std::sync::Arc<std::sync::Mutex<Vec<SystemRow>>>,
            SystemQueryCancellation,
        ) -> Result<SystemQueryBatch, SystemReadError>
        + Send,
>;

#[cfg(any(target_os = "windows", test))]
struct SystemQueryJob {
    deadline: std::time::Instant,
    partial_rows: std::sync::Arc<std::sync::Mutex<Vec<SystemRow>>>,
    cancellation: SystemQueryCancellation,
    work: SystemQueryWork,
    result_sender: std::sync::mpsc::SyncSender<Result<SystemQueryBatch, SystemReadError>>,
    caller_finished: std::sync::mpsc::Receiver<()>,
}

#[cfg(any(target_os = "windows", test))]
struct SystemQueryCallerCompletion {
    sender: std::sync::mpsc::Sender<()>,
}

#[cfg(any(target_os = "windows", test))]
impl Drop for SystemQueryCallerCompletion {
    fn drop(&mut self) {
        let _ = self.sender.send(());
    }
}

#[cfg(any(target_os = "windows", test))]
enum SystemQueryWorkerMessage {
    Run(SystemQueryJob),
    Shutdown,
}

#[cfg(any(target_os = "windows", test))]
struct SystemQueryWorkerReaper {
    max_workers: usize,
    owned_workers: std::sync::atomic::AtomicUsize,
    quarantined: std::sync::Mutex<Vec<std::thread::JoinHandle<()>>>,
}

#[cfg(any(target_os = "windows", test))]
impl SystemQueryWorkerReaper {
    fn new(max_workers: usize) -> Self {
        Self {
            max_workers,
            owned_workers: std::sync::atomic::AtomicUsize::new(0),
            quarantined: std::sync::Mutex::new(Vec::with_capacity(max_workers)),
        }
    }

    fn try_reserve_worker(&self) -> bool {
        self.reap_finished();
        let mut owned = self
            .owned_workers
            .load(std::sync::atomic::Ordering::Acquire);
        loop {
            if owned >= self.max_workers {
                return false;
            }
            match self.owned_workers.compare_exchange_weak(
                owned,
                owned + 1,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(actual) => owned = actual,
            }
        }
    }

    fn release_worker(&self) {
        let previous = self
            .owned_workers
            .fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
        debug_assert!(previous > 0, "WMI worker ownership underflow");
    }

    fn adopt(&self, handle: std::thread::JoinHandle<()>) {
        self.reap_finished();
        self.quarantined
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(handle);
    }

    fn reap_finished(&self) {
        let finished = {
            let mut quarantined = self
                .quarantined
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let mut finished = Vec::new();
            let mut index = 0;
            while index < quarantined.len() {
                if quarantined[index].is_finished() {
                    finished.push(quarantined.swap_remove(index));
                } else {
                    index += 1;
                }
            }
            finished
        };
        for handle in finished {
            let _ = handle.join();
            self.release_worker();
        }
    }

    #[cfg(test)]
    fn owned_worker_count(&self) -> usize {
        self.reap_finished();
        self.owned_workers
            .load(std::sync::atomic::Ordering::Acquire)
    }

    #[cfg(test)]
    fn quarantined_worker_count(&self) -> usize {
        self.reap_finished();
        self.quarantined
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }
}

#[cfg(any(target_os = "windows", test))]
fn system_query_worker_reaper() -> &'static SystemQueryWorkerReaper {
    static REAPER: std::sync::OnceLock<SystemQueryWorkerReaper> = std::sync::OnceLock::new();
    REAPER.get_or_init(|| SystemQueryWorkerReaper::new(SYSTEM_QUERY_MAX_OWNED_WORKERS))
}

#[cfg(any(target_os = "windows", test))]
struct OwnedSystemQueryWorkerHandle {
    handle: Option<std::thread::JoinHandle<()>>,
    reaper: &'static SystemQueryWorkerReaper,
}

#[cfg(any(target_os = "windows", test))]
impl OwnedSystemQueryWorkerHandle {
    fn new(handle: std::thread::JoinHandle<()>, reaper: &'static SystemQueryWorkerReaper) -> Self {
        Self {
            handle: Some(handle),
            reaper,
        }
    }

    fn transfer_to_reaper(mut self) {
        if let Some(handle) = self.handle.take() {
            self.reaper.adopt(handle);
        }
    }

    #[cfg(test)]
    fn join(mut self) {
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
            self.reaper.release_worker();
        }
    }
}

#[cfg(any(target_os = "windows", test))]
impl Drop for OwnedSystemQueryWorkerHandle {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            self.reaper.adopt(handle);
        }
    }
}

#[cfg(any(target_os = "windows", test))]
struct SystemQueryWorker {
    id: u64,
    sender: std::sync::mpsc::SyncSender<SystemQueryWorkerMessage>,
    busy: std::sync::Arc<std::sync::atomic::AtomicBool>,
    handle: OwnedSystemQueryWorkerHandle,
}

#[cfg(any(target_os = "windows", test))]
struct SystemQueryWorkerPoolState {
    workers: Vec<SystemQueryWorker>,
    next_worker_id: u64,
}

#[cfg(any(target_os = "windows", test))]
struct SystemQueryWorkerPool {
    desired_worker_count: usize,
    reaper: &'static SystemQueryWorkerReaper,
    state: std::sync::Mutex<SystemQueryWorkerPoolState>,
}

#[cfg(any(target_os = "windows", test))]
impl SystemQueryWorkerPool {
    fn start(worker_count: usize) -> Result<Self, String> {
        Self::start_with_reaper(worker_count, system_query_worker_reaper())
    }

    fn start_with_reaper(
        worker_count: usize,
        reaper: &'static SystemQueryWorkerReaper,
    ) -> Result<Self, String> {
        if worker_count == 0 {
            return Err("WMI worker pool must contain at least one worker".to_string());
        }

        let mut workers = Vec::with_capacity(worker_count);
        for index in 0..worker_count {
            match Self::spawn_worker(index as u64, reaper) {
                Ok(worker) => workers.push(worker),
                Err(error) => {
                    for worker in workers {
                        Self::transfer_worker_to_reaper(worker, true);
                    }
                    return Err(error);
                }
            }
        }

        Ok(Self {
            desired_worker_count: worker_count,
            reaper,
            state: std::sync::Mutex::new(SystemQueryWorkerPoolState {
                workers,
                next_worker_id: worker_count as u64,
            }),
        })
    }

    fn spawn_worker(
        id: u64,
        reaper: &'static SystemQueryWorkerReaper,
    ) -> Result<SystemQueryWorker, String> {
        if !reaper.try_reserve_worker() {
            return Err(format!(
                "WMI worker ownership ceiling of {} reached; the bounded circuit breaker is open until a quarantined worker exits.",
                reaper.max_workers
            ));
        }
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let busy = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let worker_busy = std::sync::Arc::clone(&busy);
        let handle = std::thread::Builder::new()
            .name(format!("esp-wmi-query-{id}"))
            .spawn(move || {
                while let Ok(message) = receiver.recv() {
                    let SystemQueryWorkerMessage::Run(job) = message else {
                        break;
                    };
                    job.cancellation.register_worker();
                    let worker_cancellation = job.cancellation.clone();
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        (job.work)(job.deadline, job.partial_rows, worker_cancellation)
                    }))
                    .unwrap_or_else(|_| {
                        Err(SystemReadError::Failed("WMI worker panicked".to_string()))
                    });
                    job.cancellation.clear_worker();
                    let _ = job.result_sender.send(result);
                    // Do not reuse this COM thread until CoCancelCall and the caller's
                    // bounded cleanup window have both finished.
                    let _ = job.caller_finished.recv();
                    worker_busy.store(false, std::sync::atomic::Ordering::Release);
                }
                worker_busy.store(false, std::sync::atomic::Ordering::Release);
            });
        match handle {
            Ok(handle) => Ok(SystemQueryWorker {
                id,
                sender,
                busy,
                handle: OwnedSystemQueryWorkerHandle::new(handle, reaper),
            }),
            Err(error) => {
                reaper.release_worker();
                Err(format!("WMI worker pool could not start: {error}"))
            }
        }
    }

    fn replenish_locked(&self, state: &mut SystemQueryWorkerPoolState) -> Result<(), String> {
        self.reaper.reap_finished();
        while state.workers.len() < self.desired_worker_count {
            let id = state.next_worker_id;
            let worker = Self::spawn_worker(id, self.reaper)?;
            state.next_worker_id = state.next_worker_id.saturating_add(1);
            state.workers.push(worker);
        }
        Ok(())
    }

    fn dispatch(&self, mut job: SystemQueryJob) -> Result<u64, String> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut capacity_error = self.replenish_locked(&mut state).err();
        let mut index = 0;
        while index < state.workers.len() {
            if state.workers[index]
                .busy
                .compare_exchange(
                    false,
                    true,
                    std::sync::atomic::Ordering::AcqRel,
                    std::sync::atomic::Ordering::Acquire,
                )
                .is_err()
            {
                index += 1;
                continue;
            }
            let worker_id = state.workers[index].id;
            match state.workers[index]
                .sender
                .send(SystemQueryWorkerMessage::Run(job))
            {
                Ok(()) => return Ok(worker_id),
                Err(std::sync::mpsc::SendError(SystemQueryWorkerMessage::Run(returned))) => {
                    state.workers[index]
                        .busy
                        .store(false, std::sync::atomic::Ordering::Release);
                    job = returned;
                    let worker = state.workers.swap_remove(index);
                    Self::transfer_worker_to_reaper(worker, false);
                    if let Err(error) = self.replenish_locked(&mut state) {
                        capacity_error = Some(error);
                    }
                }
                Err(std::sync::mpsc::SendError(SystemQueryWorkerMessage::Shutdown)) => {
                    unreachable!("dispatch only sends query jobs")
                }
            }
        }
        Err(capacity_error.unwrap_or_else(|| {
            "All bounded WMI workers are busy; this query was not started.".to_string()
        }))
    }

    fn quarantine(&self, worker_id: u64) -> Result<(), String> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(index) = state
            .workers
            .iter()
            .position(|worker| worker.id == worker_id)
        else {
            return Ok(());
        };
        let worker = state.workers.swap_remove(index);
        Self::transfer_worker_to_reaper(worker, false);
        self.replenish_locked(&mut state)
    }

    fn transfer_worker_to_reaper(worker: SystemQueryWorker, request_shutdown: bool) {
        let SystemQueryWorker { sender, handle, .. } = worker;
        if request_shutdown {
            let _ = sender.try_send(SystemQueryWorkerMessage::Shutdown);
        }
        drop(sender);
        handle.transfer_to_reaper();
    }

    #[cfg(test)]
    fn owned_worker_count(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .workers
            .len()
    }

    #[cfg(test)]
    fn busy_worker_count(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .workers
            .iter()
            .filter(|worker| worker.busy.load(std::sync::atomic::Ordering::Acquire))
            .count()
    }

    #[cfg(test)]
    fn shutdown_and_join(&self) -> usize {
        let workers = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .workers
            .drain(..)
            .collect::<Vec<_>>();
        let joined = workers.len();
        for worker in workers {
            let SystemQueryWorker { sender, handle, .. } = worker;
            let _ = sender.send(SystemQueryWorkerMessage::Shutdown);
            drop(sender);
            handle.join();
        }
        joined
    }
}

#[cfg(any(target_os = "windows", test))]
impl Drop for SystemQueryWorkerPool {
    fn drop(&mut self) {
        let state = self
            .state
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for worker in state.workers.drain(..) {
            Self::transfer_worker_to_reaper(worker, true);
        }
    }
}

#[cfg(any(target_os = "windows", test))]
fn run_bounded_system_query<F>(timeout: Duration, work: F) -> SystemQueryBatch
where
    F: FnOnce(
            std::time::Instant,
            std::sync::Arc<std::sync::Mutex<Vec<SystemRow>>>,
            SystemQueryCancellation,
        ) -> Result<SystemQueryBatch, SystemReadError>
        + Send
        + 'static,
{
    static WORKER_POOL: std::sync::OnceLock<Result<SystemQueryWorkerPool, String>> =
        std::sync::OnceLock::new();

    let pool =
        match WORKER_POOL.get_or_init(|| SystemQueryWorkerPool::start(SYSTEM_QUERY_WORKER_COUNT)) {
            Ok(pool) => pool,
            Err(error) => {
                return SystemQueryBatch {
                    rows: Vec::new(),
                    completion: Err(SystemReadError::Failed(error.clone())),
                }
            }
        };
    run_bounded_system_query_with_pool(pool, timeout, work)
}

#[cfg(any(target_os = "windows", test))]
fn run_bounded_system_query_with_pool<F>(
    pool: &SystemQueryWorkerPool,
    timeout: Duration,
    work: F,
) -> SystemQueryBatch
where
    F: FnOnce(
            std::time::Instant,
            std::sync::Arc<std::sync::Mutex<Vec<SystemRow>>>,
            SystemQueryCancellation,
        ) -> Result<SystemQueryBatch, SystemReadError>
        + Send
        + 'static,
{
    use std::sync::{mpsc, Arc, Mutex};
    use std::time::Instant;

    let deadline = Instant::now() + timeout;
    let partial_rows = Arc::new(Mutex::new(Vec::new()));
    let cancellation = SystemQueryCancellation::new();
    let (sender, receiver) = mpsc::sync_channel(1);
    let (caller_finished_sender, caller_finished) = mpsc::channel();
    let _caller_completion = SystemQueryCallerCompletion {
        sender: caller_finished_sender,
    };
    let job = SystemQueryJob {
        deadline,
        partial_rows: Arc::clone(&partial_rows),
        cancellation: cancellation.clone(),
        work: Box::new(work),
        result_sender: sender,
        caller_finished,
    };
    let worker_id = match pool.dispatch(job) {
        Ok(worker_id) => worker_id,
        Err(detail) => {
            return SystemQueryBatch {
                rows: Vec::new(),
                completion: Err(SystemReadError::Failed(detail)),
            }
        }
    };

    let remaining = deadline.saturating_duration_since(Instant::now());
    match receiver.recv_timeout(remaining) {
        Ok(result) => finish_system_query_result(result, &partial_rows),
        Err(mpsc::RecvTimeoutError::Timeout) => {
            cancellation.request_cancel();
            match receiver.recv_timeout(SYSTEM_QUERY_CANCELLATION_GRACE) {
                Ok(result) => SystemQueryBatch {
                    rows: merge_system_query_rows(result, &partial_rows),
                    completion: Err(SystemReadError::TimedOut),
                },
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    let _ = pool.quarantine(worker_id);
                    SystemQueryBatch {
                        rows: clone_partial_rows(&partial_rows),
                        completion: Err(SystemReadError::Failed(
                            "WMI worker stopped during cancellation".to_string(),
                        )),
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    let replacement_error = pool.quarantine(worker_id).err();
                    let mut detail = "WMI query timed out and its worker did not stop within the 250 ms cancellation window; the worker remains owned by the bounded WMI pool reaper while a replacement worker continues later queries."
                        .to_string();
                    if let Some(error) = replacement_error {
                        detail.push(' ');
                        detail.push_str(&error);
                    }
                    SystemQueryBatch {
                        rows: clone_partial_rows(&partial_rows),
                        completion: Err(SystemReadError::Failed(detail)),
                    }
                }
            }
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            let _ = pool.quarantine(worker_id);
            SystemQueryBatch {
                rows: clone_partial_rows(&partial_rows),
                completion: Err(SystemReadError::Failed(
                    "WMI worker stopped before returning a result".to_string(),
                )),
            }
        }
    }
}

#[cfg(any(target_os = "windows", test))]
fn finish_system_query_result(
    result: Result<SystemQueryBatch, SystemReadError>,
    partial_rows: &std::sync::Arc<std::sync::Mutex<Vec<SystemRow>>>,
) -> SystemQueryBatch {
    match result {
        Ok(batch) => batch,
        Err(error) => SystemQueryBatch {
            rows: clone_partial_rows(partial_rows),
            completion: Err(error),
        },
    }
}

#[cfg(any(target_os = "windows", test))]
fn merge_system_query_rows(
    result: Result<SystemQueryBatch, SystemReadError>,
    partial_rows: &std::sync::Arc<std::sync::Mutex<Vec<SystemRow>>>,
) -> Vec<SystemRow> {
    let mut rows = clone_partial_rows(partial_rows);
    for row in finish_system_query_result(result, partial_rows).rows {
        if !rows.contains(&row) {
            rows.push(row);
        }
    }
    rows
}

#[cfg(any(target_os = "windows", test))]
fn clone_partial_rows(rows: &std::sync::Arc<std::sync::Mutex<Vec<SystemRow>>>) -> Vec<SystemRow> {
    rows.lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

#[cfg(any(target_os = "windows", test))]
fn powershell_path_from_windows_directory(
    windows_directory: &std::path::Path,
) -> std::path::PathBuf {
    windows_directory
        .join("System32")
        .join("WindowsPowerShell")
        .join("v1.0")
        .join("powershell.exe")
}

pub struct LiveSystemProvider;

#[derive(Debug, Clone)]
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(crate) enum WmiRequest {
    OperatingSystem,
    ComputerSystem,
    Bios,
    Tpm,
    ImeService,
    Processes(Vec<String>),
}

#[cfg(any(target_os = "windows", test))]
fn finish_wmi_query(request: &WmiRequest, rows: Vec<SystemRow>) -> SystemQueryBatch {
    if rows.is_empty() && !matches!(request, WmiRequest::Processes(_)) {
        SystemQueryBatch::missing()
    } else {
        SystemQueryBatch::complete(rows)
    }
}

#[cfg(target_os = "windows")]
mod windows_provider {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use windows::core::{BSTR, HRESULT, PCWSTR};
    use windows::Win32::Foundation::{CloseHandle, E_ACCESSDENIED, HANDLE, RPC_E_CHANGED_MODE};
    use windows::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows::Win32::System::Com::{
        CoCreateInstance, CoDisableCallCancellation, CoEnableCallCancellation, CoInitializeEx,
        CoUninitialize, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED,
    };
    use windows::Win32::System::SystemInformation::GetSystemWindowsDirectoryW;
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows::Win32::System::Variant::{VariantClear, VariantToString, VARIANT};
    use windows::Win32::System::Wmi::{
        IWbemClassObject, IWbemLocator, WbemLocator, WBEM_E_ACCESS_DENIED, WBEM_E_INVALID_CLASS,
        WBEM_E_INVALID_NAMESPACE, WBEM_E_NOT_FOUND, WBEM_FLAG_FORWARD_ONLY,
        WBEM_FLAG_RETURN_IMMEDIATELY, WBEM_S_TIMEDOUT,
    };

    use super::{
        classify_delivery_command_failure, finish_wmi_query, parse_delivery_json,
        powershell_path_from_windows_directory, run_bounded_command, run_bounded_system_query,
        LiveSystemProvider, SystemProvider, SystemQueryBatch, SystemQueryCancellation,
        SystemReadError, SystemRow, SystemSource, WmiRequest, DELIVERY_OPTIMIZATION_SCRIPT,
        MAX_COMMAND_ERROR_BYTES, MAX_COMMAND_OUTPUT_BYTES,
    };

    const MAX_VARIANT_CHARS: usize = 4096;
    struct HandleGuard(HANDLE);

    impl Drop for HandleGuard {
        fn drop(&mut self) {
            if !self.0.is_invalid() {
                // SAFETY: this guard owns the token handle returned by OpenProcessToken.
                let _ = unsafe { CloseHandle(self.0) };
            }
        }
    }

    struct ComGuard {
        initialized_here: bool,
    }

    impl ComGuard {
        fn initialize() -> Result<Self, SystemReadError> {
            // SAFETY: the current thread is initialized once for the lifetime of this guard.
            let result = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
            if result.is_ok() {
                Ok(Self {
                    initialized_here: true,
                })
            } else if result == RPC_E_CHANGED_MODE {
                Ok(Self {
                    initialized_here: false,
                })
            } else {
                Err(error_from_hresult(result, "COM initialization failed"))
            }
        }
    }

    impl Drop for ComGuard {
        fn drop(&mut self) {
            if self.initialized_here {
                // SAFETY: paired with the successful CoInitializeEx call above.
                unsafe { CoUninitialize() };
            }
        }
    }

    struct ComCallCancellationGuard;

    impl ComCallCancellationGuard {
        fn enable() -> Result<Self, SystemReadError> {
            // SAFETY: this enables cancellation only for outgoing COM calls on this worker thread.
            unsafe { CoEnableCallCancellation(None) }.map_err(|error| {
                error_from_windows(error, "COM call cancellation could not be enabled")
            })?;
            Ok(Self)
        }
    }

    impl Drop for ComCallCancellationGuard {
        fn drop(&mut self) {
            // SAFETY: paired with CoEnableCallCancellation on the same worker thread.
            let _ = unsafe { CoDisableCallCancellation(None) };
        }
    }

    impl SystemProvider for LiveSystemProvider {
        fn elevation(&self) -> Result<bool, SystemReadError> {
            let mut token = HANDLE::default();
            // SAFETY: token points to valid writable storage and is closed by HandleGuard.
            if let Err(error) =
                unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }
            {
                // A silent probe failure makes the app wrongly report "Standard user"
                // even when elevated; surface the exact Win32 error to the app log.
                log::warn!("ESP elevation probe: OpenProcessToken failed: {error:?}");
                return Err(error_from_windows(error, "process token query failed"));
            }
            let _token = HandleGuard(token);
            let mut elevation = TOKEN_ELEVATION::default();
            let mut returned = 0_u32;
            // SAFETY: elevation is valid writable TOKEN_ELEVATION storage of the declared size.
            if let Err(error) = unsafe {
                GetTokenInformation(
                    token,
                    TokenElevation,
                    Some((&mut elevation as *mut TOKEN_ELEVATION).cast()),
                    std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                    &mut returned,
                )
            } {
                log::warn!(
                    "ESP elevation probe: GetTokenInformation(TokenElevation) failed: {error:?}"
                );
                return Err(error_from_windows(error, "token elevation query failed"));
            }
            if elevation.TokenIsElevated == 0 {
                // Not an error, but log the anomalous case so a wrongly-unelevated
                // reading on an actually-elevated process is diagnosable.
                log::warn!(
                    "ESP elevation probe: token reports not elevated (TokenIsElevated=0, returned_len={returned})"
                );
            }
            Ok(elevation.TokenIsElevated != 0)
        }

        fn query(
            &self,
            source: SystemSource,
            timeout: Duration,
            max_rows: usize,
        ) -> SystemQueryBatch {
            let request = match source {
                SystemSource::OperatingSystem => WmiRequest::OperatingSystem,
                SystemSource::ComputerSystem => WmiRequest::ComputerSystem,
                SystemSource::Bios => WmiRequest::Bios,
                SystemSource::Tpm => WmiRequest::Tpm,
                SystemSource::ImeService => WmiRequest::ImeService,
                SystemSource::DeliveryOptimization => {
                    return query_delivery_optimization(timeout, max_rows)
                }
                SystemSource::Elevation => {
                    return SystemQueryBatch {
                        rows: Vec::new(),
                        completion: Err(SystemReadError::Unsupported),
                    }
                }
            };
            query_wmi(request, timeout, max_rows)
        }
    }

    pub(crate) fn query_wmi(
        request: WmiRequest,
        timeout: Duration,
        max_rows: usize,
    ) -> SystemQueryBatch {
        run_bounded_system_query(timeout, move |deadline, partial_rows, cancellation| {
            query_wmi_inner(request, deadline, max_rows, partial_rows, cancellation)
        })
    }

    fn query_wmi_inner(
        request: WmiRequest,
        deadline: Instant,
        max_rows: usize,
        partial_rows: Arc<Mutex<Vec<SystemRow>>>,
        cancellation: SystemQueryCancellation,
    ) -> Result<SystemQueryBatch, SystemReadError> {
        ensure_query_active(deadline, &cancellation)?;
        let _com = ComGuard::initialize()?;
        let _call_cancellation = ComCallCancellationGuard::enable()?;
        ensure_query_active(deadline, &cancellation)?;
        let (namespace, query, properties) = wmi_spec(&request);
        // SAFETY: WbemLocator is a registered in-process COM class and no outer object is used.
        let locator: IWbemLocator =
            unsafe { CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER) }
                .map_err(|error| error_from_windows(error, "WMI locator creation failed"))?;
        ensure_query_active(deadline, &cancellation)?;
        let namespace = BSTR::from(namespace);
        let empty = BSTR::new();
        // SAFETY: all BSTR inputs live through the synchronous ConnectServer call.
        let services =
            unsafe { locator.ConnectServer(&namespace, &empty, &empty, &empty, 0, &empty, None) }
                .map_err(|error| error_from_windows(error, "WMI namespace connection failed"))?;
        ensure_query_active(deadline, &cancellation)?;
        let language = BSTR::from("WQL");
        let query = BSTR::from(query.as_str());
        let flags = WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY;
        // SAFETY: query text is selected exclusively from wmi_spec's fixed allowlist.
        let enumerator = unsafe { services.ExecQuery(&language, &query, flags, None) }
            .map_err(|error| error_from_windows(error, "WMI query failed"))?;
        ensure_query_active(deadline, &cancellation)?;

        let mut rows = Vec::new();
        let cap = max_rows.min(512);
        while rows.len() < cap {
            ensure_query_active(deadline, &cancellation)?;
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(SystemReadError::TimedOut);
            }
            let timeout_ms = remaining.as_millis().min(i32::MAX as u128) as i32;
            let mut objects: [Option<IWbemClassObject>; 1] = [None];
            let mut returned = 0_u32;
            // SAFETY: the output slice and returned count are valid for the synchronous call.
            let result = unsafe { enumerator.Next(timeout_ms, &mut objects, &mut returned) };
            if result.0 == WBEM_S_TIMEDOUT.0 {
                return Err(SystemReadError::TimedOut);
            }
            if result.is_err() {
                return Err(error_from_hresult(result, "WMI enumeration failed"));
            }
            if returned == 0 {
                break;
            }
            if let Some(object) = objects[0].take() {
                let row = read_wmi_row(&object, properties)?;
                partial_rows
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .push(row.clone());
                rows.push(row);
            }
        }

        Ok(finish_wmi_query(&request, rows))
    }

    fn ensure_query_active(
        deadline: Instant,
        cancellation: &SystemQueryCancellation,
    ) -> Result<(), SystemReadError> {
        if cancellation.is_cancelled() || Instant::now() >= deadline {
            Err(SystemReadError::TimedOut)
        } else {
            Ok(())
        }
    }

    fn read_wmi_row(
        object: &IWbemClassObject,
        properties: &[&str],
    ) -> Result<SystemRow, SystemReadError> {
        let mut values = Vec::with_capacity(properties.len());
        for property in properties {
            let property_name = property.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
            let mut variant = VARIANT::default();
            // SAFETY: property_name is nul-terminated and variant is valid writable storage.
            let get_result = unsafe {
                object.Get(
                    PCWSTR::from_raw(property_name.as_ptr()),
                    0,
                    &mut variant,
                    None,
                    None,
                )
            };
            if let Err(error) = get_result {
                // SAFETY: VariantClear accepts an initialized VARIANT, including VT_EMPTY.
                let _ = unsafe { VariantClear(&mut variant) };
                return Err(error_from_windows(error, "WMI property read failed"));
            }
            let mut buffer = [0_u16; MAX_VARIANT_CHARS];
            // SAFETY: buffer is valid writable UTF-16 storage; variant came from IWbemClassObject.
            let conversion = unsafe { VariantToString(&variant, &mut buffer) };
            // SAFETY: releases any allocation owned by the property VARIANT exactly once.
            let _ = unsafe { VariantClear(&mut variant) };
            if conversion.is_ok() {
                let length = buffer
                    .iter()
                    .position(|unit| *unit == 0)
                    .unwrap_or(buffer.len());
                values.push((
                    (*property).to_string(),
                    String::from_utf16_lossy(&buffer[..length]),
                ));
            }
        }
        Ok(SystemRow::new(values))
    }

    fn wmi_spec(request: &WmiRequest) -> (&'static str, String, &'static [&'static str]) {
        match request {
            WmiRequest::OperatingSystem => (
                r"ROOT\CIMV2",
                "SELECT Version, BuildNumber FROM Win32_OperatingSystem".to_string(),
                &["Version", "BuildNumber"],
            ),
            WmiRequest::ComputerSystem => (
                r"ROOT\CIMV2",
                "SELECT Name, Manufacturer, Model FROM Win32_ComputerSystem".to_string(),
                &["Name", "Manufacturer", "Model"],
            ),
            WmiRequest::Bios => (
                r"ROOT\CIMV2",
                "SELECT SerialNumber FROM Win32_BIOS".to_string(),
                &["SerialNumber"],
            ),
            WmiRequest::Tpm => (
                r"ROOT\CIMV2\Security\MicrosoftTpm",
                "SELECT SpecVersion FROM Win32_Tpm".to_string(),
                &["SpecVersion"],
            ),
            WmiRequest::ImeService => (
                r"ROOT\CIMV2",
                "SELECT State, StartMode, ProcessId FROM Win32_Service WHERE Name='IntuneManagementExtension'".to_string(),
                &["State", "StartMode", "ProcessId"],
            ),
            WmiRequest::Processes(names) => {
                let conditions = names
                    .iter()
                    .take(36)
                    .filter(|name| {
                        name.len() <= 255
                            && name.to_ascii_lowercase().ends_with(".exe")
                            && name.chars().all(|character| {
                                character.is_ascii_alphanumeric()
                                    || " ._-()".contains(character)
                            })
                    })
                    .map(|name| format!("Name='{name}'"))
                    .collect::<Vec<_>>();
                let predicate = if conditions.is_empty() {
                    "1=0".to_string()
                } else {
                    conditions.join(" OR ")
                };
                (
                    r"ROOT\CIMV2",
                    format!(
                        "SELECT ProcessId, ParentProcessId, Name, CreationDate, CommandLine FROM Win32_Process WHERE {predicate}"
                    ),
                    &["ProcessId", "ParentProcessId", "Name", "CreationDate", "CommandLine"],
                )
            }
        }
    }

    fn query_delivery_optimization(timeout: Duration, max_rows: usize) -> SystemQueryBatch {
        let deadline = Instant::now() + timeout;
        let powershell = match trusted_powershell_path() {
            Ok(path) => path,
            Err(error) => {
                return SystemQueryBatch {
                    rows: Vec::new(),
                    completion: Err(error),
                }
            }
        };
        if Instant::now() >= deadline {
            return SystemQueryBatch {
                rows: Vec::new(),
                completion: Err(SystemReadError::TimedOut),
            };
        }

        let mut command = Command::new(&powershell);
        command.args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            DELIVERY_OPTIMIZATION_SCRIPT,
        ]);
        let output = match run_bounded_command(
            command,
            deadline.saturating_duration_since(Instant::now()),
            MAX_COMMAND_OUTPUT_BYTES,
            MAX_COMMAND_ERROR_BYTES,
        ) {
            Ok(output) => output,
            Err(SystemReadError::Missing) => return SystemQueryBatch::missing(),
            Err(error) => {
                return SystemQueryBatch {
                    rows: Vec::new(),
                    completion: Err(error),
                }
            }
        };
        if output.stdout_truncated {
            return SystemQueryBatch {
                rows: Vec::new(),
                completion: Err(SystemReadError::Failed(
                    "Delivery Optimization output exceeded the size limit".to_string(),
                )),
            };
        }
        if !output.status.success() {
            return SystemQueryBatch {
                rows: Vec::new(),
                completion: Err(classify_delivery_command_failure(&output)),
            };
        }
        if output.stderr_truncated {
            return SystemQueryBatch {
                rows: Vec::new(),
                completion: Err(SystemReadError::Failed(
                    "Delivery Optimization error output exceeded the size limit".to_string(),
                )),
            };
        }

        match parse_delivery_json(&output.stdout, max_rows) {
            Ok(rows) if rows.is_empty() => SystemQueryBatch::missing(),
            Ok(rows) => SystemQueryBatch::complete(rows),
            Err(error) => SystemQueryBatch {
                rows: Vec::new(),
                completion: Err(error),
            },
        }
    }

    fn trusted_powershell_path() -> Result<PathBuf, SystemReadError> {
        const MAX_WINDOWS_DIRECTORY_UNITS: usize = 32_768;

        let mut buffer = vec![0_u16; 260];
        loop {
            // SAFETY: buffer is writable UTF-16 storage and the API receives its exact length.
            let length = unsafe { GetSystemWindowsDirectoryW(Some(&mut buffer)) } as usize;
            if length == 0 {
                return Err(SystemReadError::Failed(
                    "trusted Windows directory could not be resolved".to_string(),
                ));
            }
            if length < buffer.len() {
                buffer.truncate(length);
                break;
            }
            let required = length.saturating_add(1);
            if required > MAX_WINDOWS_DIRECTORY_UNITS {
                return Err(SystemReadError::Failed(
                    "trusted Windows directory exceeded the size limit".to_string(),
                ));
            }
            buffer.resize(required, 0);
        }

        let windows_directory = PathBuf::from(OsString::from_wide(&buffer));
        if !windows_directory.is_absolute() {
            return Err(SystemReadError::Failed(
                "trusted Windows directory was not absolute".to_string(),
            ));
        }
        let powershell = powershell_path_from_windows_directory(&windows_directory);
        if !powershell.is_file() {
            return Err(SystemReadError::Missing);
        }
        Ok(powershell)
    }

    fn error_from_windows(error: windows::core::Error, context: &str) -> SystemReadError {
        error_from_hresult(error.code(), context)
    }

    fn error_from_hresult(error: HRESULT, context: &str) -> SystemReadError {
        if error == E_ACCESSDENIED || error.0 == WBEM_E_ACCESS_DENIED.0 {
            SystemReadError::PermissionDenied
        } else if [
            WBEM_E_INVALID_CLASS.0,
            WBEM_E_INVALID_NAMESPACE.0,
            WBEM_E_NOT_FOUND.0,
        ]
        .contains(&error.0)
        {
            SystemReadError::Missing
        } else {
            SystemReadError::Failed(format!("{context} (HRESULT 0x{:08X})", error.0 as u32))
        }
    }
}

#[cfg(target_os = "windows")]
pub(crate) use windows_provider::query_wmi;

#[cfg(not(target_os = "windows"))]
impl SystemProvider for LiveSystemProvider {
    fn elevation(&self) -> Result<bool, SystemReadError> {
        Err(SystemReadError::Unsupported)
    }

    fn query(
        &self,
        _source: SystemSource,
        _timeout: Duration,
        _max_rows: usize,
    ) -> SystemQueryBatch {
        SystemQueryBatch::unsupported()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::Path;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use cmtraceopen_parser::esp::{EspSensitivity, EspSourceAccessState, EspSystemFact};

    use super::*;

    #[derive(Clone)]
    struct FakeSystemProvider {
        elevation: Result<bool, SystemReadError>,
        batches: BTreeMap<SystemSource, SystemQueryBatch>,
    }

    impl FakeSystemProvider {
        fn new(elevation: Result<bool, SystemReadError>) -> Self {
            Self {
                elevation,
                batches: BTreeMap::new(),
            }
        }

        fn with(
            mut self,
            source: SystemSource,
            rows: Vec<SystemRow>,
            completion: Result<(), SystemReadError>,
        ) -> Self {
            self.batches
                .insert(source, SystemQueryBatch { rows, completion });
            self
        }
    }

    impl SystemProvider for FakeSystemProvider {
        fn elevation(&self) -> Result<bool, SystemReadError> {
            self.elevation.clone()
        }

        fn query(
            &self,
            source: SystemSource,
            timeout: Duration,
            max_rows: usize,
        ) -> SystemQueryBatch {
            assert_eq!(timeout, SYSTEM_QUERY_TIMEOUT);
            assert_eq!(max_rows, MAX_SYSTEM_ROWS);
            self.batches
                .get(&source)
                .cloned()
                .unwrap_or_else(SystemQueryBatch::missing)
        }
    }

    fn row(values: &[(&str, &str)]) -> SystemRow {
        SystemRow::new(values.iter().map(|(name, value)| (*name, *value)))
    }

    #[test]
    fn elevation_probe_distinguishes_elevated_non_elevated_errors_and_unsupported() {
        let (elevated, coverage) = elevation_from_probe(Ok(true));
        assert!(elevated.is_elevated);
        assert!(elevated.restart_supported);
        assert!(elevated.restricted_sources.is_empty());
        assert_eq!(coverage.access_state, EspSourceAccessState::Available);

        let (standard_user, coverage) = elevation_from_probe(Ok(false));
        assert!(!standard_user.is_elevated);
        assert!(standard_user.restart_supported);
        assert!(standard_user.restricted_sources.is_empty());
        assert_eq!(coverage.access_state, EspSourceAccessState::Available);

        let (failed, coverage) =
            elevation_from_probe(Err(SystemReadError::Failed("token query failed".into())));
        assert!(!failed.is_elevated);
        assert!(failed.restart_supported);
        assert_eq!(coverage.access_state, EspSourceAccessState::Failed);
        assert_eq!(coverage.detail.as_deref(), Some("token query failed"));

        let (unsupported, coverage) = elevation_from_probe(Err(SystemReadError::Unsupported));
        assert!(!unsupported.is_elevated);
        assert!(!unsupported.restart_supported);
        assert_eq!(coverage.access_state, EspSourceAccessState::Unsupported);
    }

    #[test]
    fn hardware_rows_become_typed_facts_without_raw_hardware_hash() {
        let provider = FakeSystemProvider::new(Ok(true))
            .with(
                SystemSource::OperatingSystem,
                vec![row(&[("Version", "10.0.26100"), ("BuildNumber", "26100")])],
                Ok(()),
            )
            .with(
                SystemSource::ComputerSystem,
                vec![row(&[
                    ("Name", "ESP-LAB-01"),
                    ("Manufacturer", "Contoso"),
                    ("Model", "Virtual Machine"),
                    ("HardwareHash", "must-never-leave-provider"),
                ])],
                Ok(()),
            )
            .with(
                SystemSource::Bios,
                vec![row(&[("SerialNumber", "LAB-SERIAL-7")])],
                Ok(()),
            )
            .with(
                SystemSource::Tpm,
                vec![row(&[("SpecVersion", "2.0, 0, 1.59")])],
                Ok(()),
            );

        let evidence = collect_system_evidence(&provider, "2026-07-15T14:00:00Z");
        assert_eq!(evidence.hostname.as_deref(), Some("ESP-LAB-01"));
        assert_eq!(evidence.hardware.os_version.as_deref(), Some("10.0.26100"));
        assert_eq!(evidence.hardware.os_build.as_deref(), Some("26100"));
        assert_eq!(evidence.hardware.manufacturer.as_deref(), Some("Contoso"));
        assert_eq!(evidence.hardware.model.as_deref(), Some("Virtual Machine"));
        assert_eq!(
            evidence
                .hardware
                .serial_number
                .as_ref()
                .map(|value| (&value.value, &value.sensitivity)),
            Some((&"LAB-SERIAL-7".to_string(), &EspSensitivity::Sensitive))
        );
        assert_eq!(evidence.hardware.tpm_version.as_deref(), Some("2.0"));
        assert!(evidence.observations.iter().any(|observation| {
            observation.fact == EspSystemFact::Hostname("ESP-LAB-01".into())
        }));

        let serialized = serde_json::to_string(&evidence).expect("system evidence serializes");
        assert!(!serialized.contains("must-never-leave-provider"));
        assert!(!serialized.to_ascii_lowercase().contains("hardwarehash"));
    }

    #[test]
    fn delivery_optimization_counters_use_http_bytes_as_denominator() {
        let evidence = delivery_optimization_from_rows(
            &[row(&[
                ("DownloadHttpBytes", "1000"),
                ("DownloadLanBytes", "200"),
                ("DownloadCacheHostBytes", "100"),
            ])],
            "2026-07-15T14:00:00Z",
        )
        .expect("counter row");

        assert_eq!(evidence.download_http_bytes, 1000);
        assert_eq!(evidence.download_lan_bytes, 200);
        assert_eq!(evidence.download_cache_host_bytes, 100);
        assert_eq!(evidence.peer_share_percent, Some(20.0));
        assert_eq!(evidence.connected_cache_share_percent, Some(10.0));

        let zero = delivery_optimization_from_rows(
            &[row(&[
                ("DownloadHttpBytes", "0"),
                ("DownloadLanBytes", "200"),
                ("DownloadCacheHostBytes", "100"),
            ])],
            "2026-07-15T14:00:00Z",
        )
        .expect("zero counter row");
        assert_eq!(zero.peer_share_percent, None);
        assert_eq!(zero.connected_cache_share_percent, None);
    }

    #[test]
    fn delivery_optimization_uses_only_log_start_and_completion_events() {
        let rows = [
            row(&[
                ("_Kind", "Event"),
                ("Function", "DownloadStart"),
                ("ContentId", "content-start"),
                ("AppId", "11111111-1111-1111-1111-111111111111"),
                ("TimeCreated", "2026-07-15T13:00:00Z"),
            ]),
            row(&[
                ("_Kind", "Event"),
                ("Function", "DownloadCompleted"),
                ("ContentId", "content-complete"),
                ("AppId", "22222222-2222-2222-2222-222222222222"),
                ("TimeCreated", "2026-07-15T13:01:00-04:00"),
            ]),
            row(&[
                ("_Kind", "Status"),
                ("Status", "Error"),
                ("FileId", "must-not-be-started-error"),
            ]),
            row(&[
                ("_Kind", "Status"),
                ("Status", "Paused"),
                ("FileId", "must-not-be-started-paused"),
            ]),
        ];

        let observations = delivery_observations(&rows, "2026-07-15T14:00:00Z");

        assert_eq!(observations.len(), 2);
        assert_eq!(
            observations[0].kind,
            EspDeliveryOptimizationEventKind::DownloadStarted
        );
        assert_eq!(observations[0].content_id.as_deref(), Some("content-start"));
        assert_eq!(
            observations[0].app_id.as_deref(),
            Some("11111111-1111-1111-1111-111111111111")
        );
        assert_eq!(
            observations[0]
                .context
                .source_timestamp
                .as_ref()
                .and_then(|timestamp| timestamp.normalized_utc.as_deref()),
            Some("2026-07-15T13:00:00Z")
        );
        assert_eq!(
            observations[1].kind,
            EspDeliveryOptimizationEventKind::DownloadCompleted
        );
        assert_eq!(
            observations[1]
                .context
                .source_timestamp
                .as_ref()
                .and_then(|timestamp| timestamp.normalized_utc.as_deref()),
            Some("2026-07-15T17:01:00Z")
        );
        assert!(observations.iter().all(|observation| {
            !matches!(
                observation.content_id.as_deref(),
                Some("must-not-be-started-error" | "must-not-be-started-paused")
            )
        }));
    }

    #[test]
    fn delivery_optimization_live_script_uses_log_events_instead_of_status_snapshots() {
        assert!(DELIVERY_OPTIMIZATION_SCRIPT.contains("Get-DeliveryOptimizationLog"));
        assert!(DELIVERY_OPTIMIZATION_SCRIPT.contains("DownloadStart"));
        assert!(DELIVERY_OPTIMIZATION_SCRIPT.contains("DownloadCompleted"));
        assert!(DELIVERY_OPTIMIZATION_SCRIPT.contains("CMTRACEOPEN_HRESULT=0x"));
        assert!(!DELIVERY_OPTIMIZATION_SCRIPT.contains("Get-DeliveryOptimizationStatus"));
    }

    #[test]
    fn delivery_optimization_live_script_pins_the_inbox_module_before_invocation() {
        let trusted_module_root = "$env:PSModulePath=[System.IO.Path]::Combine($PSHOME,'Modules');";
        let trusted_module_manifest = "$deliveryOptimizationModule=[System.IO.Path]::Combine($env:PSModulePath,'DeliveryOptimization','DeliveryOptimization.psd1');";
        let trusted_import = "Microsoft.PowerShell.Core\\Import-Module -Name $deliveryOptimizationModule -Force -ErrorAction Stop;";
        let perf_command = "DeliveryOptimization\\Get-DeliveryOptimizationPerfSnapThisMonth";
        let log_command = "DeliveryOptimization\\Get-DeliveryOptimizationLog";

        let root_index = DELIVERY_OPTIMIZATION_SCRIPT
            .find(trusted_module_root)
            .expect("script must discard inherited module search paths");
        let manifest_index = DELIVERY_OPTIMIZATION_SCRIPT
            .find(trusted_module_manifest)
            .expect("script must build the inbox Delivery Optimization manifest path");
        let import_index = DELIVERY_OPTIMIZATION_SCRIPT
            .find(trusted_import)
            .expect("script must import the inbox Delivery Optimization module explicitly");

        for command in [perf_command, log_command] {
            let command_index = DELIVERY_OPTIMIZATION_SCRIPT
                .find(command)
                .expect("Delivery Optimization commands must be module-qualified");
            assert!(root_index < manifest_index);
            assert!(manifest_index < import_index);
            assert!(import_index < command_index);
        }
        assert!(!DELIVERY_OPTIMIZATION_SCRIPT
            .contains("$perf=Get-DeliveryOptimizationPerfSnapThisMonth"));
        assert!(!DELIVERY_OPTIMIZATION_SCRIPT.contains("$events=@(Get-DeliveryOptimizationLog"));
    }

    #[cfg(unix)]
    #[test]
    fn bounded_command_drains_output_larger_than_pipe_capacity_before_waiting() {
        let mut command = std::process::Command::new("/bin/dd");
        command.args(["if=/dev/zero", "bs=262144", "count=1"]);

        let output = run_bounded_command(command, Duration::from_secs(2), 512 * 1024, 16 * 1024)
            .expect("large child output must not deadlock behind an unread pipe");

        assert!(output.status.success());
        assert_eq!(output.stdout.len(), 262_144);
        assert!(!output.stdout_truncated);
        assert!(!output.stderr_truncated);
    }

    #[cfg(unix)]
    #[test]
    fn bounded_command_drains_but_does_not_retain_output_past_the_byte_cap() {
        let mut command = std::process::Command::new("/bin/dd");
        command.args(["if=/dev/zero", "bs=262144", "count=1"]);

        let output = run_bounded_command(command, Duration::from_secs(2), 4 * 1024, 4 * 1024)
            .expect("oversized output is drained without blocking");

        assert!(output.status.success());
        assert_eq!(output.stdout.len(), 4 * 1024);
        assert!(output.stdout_truncated);
    }

    #[cfg(unix)]
    #[test]
    fn delivery_command_failure_uses_structured_numeric_hresult_for_permission_denied() {
        for code in ["00000005", "80070005"] {
            let mut command = std::process::Command::new("/bin/sh");
            command.args([
                "-c",
                &format!("printf 'CMTRACEOPEN_HRESULT=0x{code}' >&2; exit 1"),
            ]);

            let output = run_bounded_command(command, Duration::from_secs(2), 4 * 1024, 4 * 1024)
                .expect("structured failure output");

            assert_eq!(
                classify_delivery_command_failure(&output),
                SystemReadError::PermissionDenied,
                "unexpected classification for Windows error 0x{code}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn bounded_command_kills_and_reaps_a_timed_out_child() {
        let mut command = std::process::Command::new("/bin/sleep");
        command.arg("5");
        let started = Instant::now();

        let error = run_bounded_command(command, Duration::from_millis(50), 4 * 1024, 4 * 1024)
            .expect_err("sleeping child must time out");

        assert_eq!(error, SystemReadError::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn bounded_commands_hide_the_console_window_before_spawning() {
        // Every bounded ESP subprocess must route through the CREATE_NO_WINDOW
        // choke point so no console window flashes when ESP diagnostics start.
        // The flag is a no-op off Windows, so assert structurally that the spawn
        // path applies it: the real call at the spawn site must precede the
        // child spawn, so the earliest `apply_hidden_window` in this file wins
        // over this test's own literal (which appears after `command.spawn()`).
        let source = include_str!("system.rs");
        let hide_index = source
            .find("apply_hidden_window(&mut command)")
            .expect("run_bounded_command must hide the console window before spawning");
        let spawn_index = source
            .find("command.spawn()")
            .expect("run_bounded_command spawns the child via command.spawn()");
        assert!(
            hide_index < spawn_index,
            "apply_hidden_window must run before command.spawn()"
        );
    }

    #[test]
    fn delivery_optimization_json_extracts_content_app_and_source_time() {
        let output = br#"{
            "perf": {
                "DownloadHttpBytes": 1000,
                "DownloadLanBytes": 200,
                "DownloadCacheHostBytes": 100
            },
            "events": [
                {
                    "Function": "CService::DownloadStart",
                    "TimeCreated": "2026-07-15T13:00:00Z",
                    "Message": "fileId: aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa.content-start, 11111111-1111-1111-1111-111111111111.intunewin.bin, downloading"
                },
                {
                    "Function": "CService::DownloadCompleted",
                    "TimeCreated": "2026-07-15T13:01:00-04:00",
                    "Message": "Microsoft Office Click-to-Run fileId = bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb.office-file-42, completed"
                },
                {
                    "Function": "DownloadPaused",
                    "TimeCreated": "2026-07-15T13:02:00Z",
                    "Message": "fileId: must-not-be-emitted, paused"
                }
            ]
        }"#;

        let rows = parse_delivery_json(output, MAX_SYSTEM_ROWS).expect("production-shaped JSON");
        assert_eq!(rows.len(), 3);
        let counters = delivery_optimization_from_rows(&rows, "2026-07-15T14:00:00Z")
            .expect("performance counters");
        assert_eq!(counters.download_http_bytes, 1000);
        assert_eq!(counters.peer_share_percent, Some(20.0));

        let observations = delivery_observations(&rows, "2026-07-15T14:00:00Z");
        assert_eq!(observations.len(), 2);
        assert_eq!(observations[0].content_id.as_deref(), Some("content-start"));
        assert_eq!(
            observations[0].app_id.as_deref(),
            Some("11111111-1111-1111-1111-111111111111")
        );
        assert_eq!(
            observations[1].content_id.as_deref(),
            Some("office-file-42")
        );
        assert_eq!(observations[1].app_id, None);
        assert_eq!(
            observations[1]
                .context
                .source_timestamp
                .as_ref()
                .and_then(|timestamp| timestamp.normalized_utc.as_deref()),
            Some("2026-07-15T17:01:00Z")
        );
    }

    #[test]
    fn timed_out_source_retains_partial_rows_and_other_successful_sources() {
        let provider = FakeSystemProvider::new(Ok(true))
            .with(
                SystemSource::OperatingSystem,
                vec![row(&[("Version", "10.0.26100")])],
                Ok(()),
            )
            .with(
                SystemSource::Tpm,
                vec![row(&[("SpecVersion", "2.0")])],
                Err(SystemReadError::TimedOut),
            );

        let evidence = collect_system_evidence(&provider, "2026-07-15T14:00:00Z");
        assert_eq!(evidence.hardware.os_version.as_deref(), Some("10.0.26100"));
        assert_eq!(evidence.hardware.tpm_version.as_deref(), Some("2.0"));
        let tpm = evidence
            .coverage
            .iter()
            .find(|coverage| coverage.source == SystemSource::Tpm)
            .expect("TPM coverage");
        assert_eq!(tpm.access_state, EspSourceAccessState::Failed);
        assert_eq!(
            tpm.detail.as_deref(),
            Some("query timed out after partial results")
        );
    }

    #[test]
    fn bounded_worker_cancels_and_joins_timed_out_work() {
        let active_workers = Arc::new(AtomicUsize::new(0));
        let exited_workers = Arc::new(AtomicUsize::new(0));

        for _ in 0..3 {
            let active_for_worker = Arc::clone(&active_workers);
            let exited_for_worker = Arc::clone(&exited_workers);
            let started_at = Instant::now();
            let batch =
                run_bounded_system_query(Duration::from_millis(25), move |_, _, cancellation| {
                    active_for_worker.fetch_add(1, Ordering::SeqCst);
                    while !cancellation.is_cancelled() {
                        std::thread::park_timeout(Duration::from_millis(1));
                    }
                    active_for_worker.fetch_sub(1, Ordering::SeqCst);
                    exited_for_worker.fetch_add(1, Ordering::SeqCst);
                    Err(SystemReadError::TimedOut)
                });

            let elapsed = started_at.elapsed();
            assert!(
                elapsed < Duration::from_millis(500),
                "blocked setup escaped the outer timeout: {elapsed:?}"
            );
            assert!(batch.rows.is_empty());
            assert_eq!(batch.completion, Err(SystemReadError::TimedOut));
            assert_eq!(active_workers.load(Ordering::SeqCst), 0);
        }

        assert_eq!(exited_workers.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn com_cancellation_timeout_is_expressed_in_seconds() {
        assert_eq!(SYSTEM_QUERY_COM_CANCEL_TIMEOUT_SECONDS, 1);
        assert_ne!(
            SYSTEM_QUERY_COM_CANCEL_TIMEOUT_SECONDS,
            SYSTEM_QUERY_CANCELLATION_GRACE.as_millis() as u32
        );
    }

    #[test]
    fn bounded_pool_allows_overlapping_healthy_queries() {
        let pool = Arc::new(SystemQueryWorkerPool::start(2).expect("start bounded test pool"));
        let (started_sender, started_receiver) = std::sync::mpsc::sync_channel(1);
        let (release_sender, release_receiver) = std::sync::mpsc::sync_channel(1);
        let first_pool = Arc::clone(&pool);
        let first = std::thread::spawn(move || {
            run_bounded_system_query_with_pool(
                &first_pool,
                Duration::from_secs(1),
                move |_, _, _| {
                    started_sender.send(()).expect("signal first query");
                    release_receiver.recv().expect("release first query");
                    Ok(SystemQueryBatch::complete(Vec::new()))
                },
            )
        });
        started_receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("first query reached worker");

        let second =
            run_bounded_system_query_with_pool(&pool, Duration::from_secs(1), |_, _, _| {
                Ok(SystemQueryBatch::complete(Vec::new()))
            });
        release_sender.send(()).expect("release first query");
        let first = first.join().expect("first caller joins");

        assert_eq!(first, SystemQueryBatch::complete(Vec::new()));
        assert_eq!(second, SystemQueryBatch::complete(Vec::new()));
        assert_eq!(pool.shutdown_and_join(), 2);
    }

    #[test]
    fn stuck_worker_remains_owned_while_later_query_completes() {
        let reaper = Box::leak(Box::new(SystemQueryWorkerReaper::new(8)));
        let pool = SystemQueryWorkerPool::start_with_reaper(2, reaper)
            .expect("start isolated bounded test pool");
        let (release_sender, release_receiver) = std::sync::mpsc::sync_channel(1);
        let started_at = Instant::now();
        let stuck =
            run_bounded_system_query_with_pool(&pool, Duration::from_millis(10), move |_, _, _| {
                release_receiver.recv().expect("release stuck COM seam");
                Ok(SystemQueryBatch::complete(Vec::new()))
            });

        assert!(
            started_at.elapsed() < Duration::from_secs(1),
            "uncooperative worker blocked bounded collection"
        );
        assert!(matches!(
            stuck.completion,
            Err(SystemReadError::Failed(ref detail))
                if detail.contains("remains owned by the bounded WMI pool")
        ));
        assert_eq!(pool.owned_worker_count(), 2);
        assert_eq!(pool.busy_worker_count(), 0);
        assert_eq!(reaper.owned_worker_count(), 3);
        assert_eq!(reaper.quarantined_worker_count(), 1);

        let healthy =
            run_bounded_system_query_with_pool(&pool, Duration::from_secs(1), |_, _, _| {
                Ok(SystemQueryBatch::complete(Vec::new()))
            });
        assert_eq!(healthy, SystemQueryBatch::complete(Vec::new()));

        release_sender.send(()).expect("release stuck COM seam");
        assert_eq!(pool.shutdown_and_join(), 2);
        let cleanup_deadline = Instant::now() + Duration::from_secs(1);
        while reaper.owned_worker_count() != 0 && Instant::now() < cleanup_deadline {
            std::thread::yield_now();
        }
        assert_eq!(reaper.owned_worker_count(), 0);
    }

    #[test]
    fn four_uncooperative_timeouts_do_not_poison_healthy_capacity() {
        let pool = SystemQueryWorkerPool::start(4).expect("start bounded test pool");
        let mut releases = Vec::new();
        let mut timed_out = Vec::new();

        for _ in 0..4 {
            let (release_sender, release_receiver) = std::sync::mpsc::sync_channel(1);
            releases.push(release_sender);
            timed_out.push(run_bounded_system_query_with_pool(
                &pool,
                Duration::from_millis(10),
                move |_, _, _| {
                    release_receiver
                        .recv()
                        .expect("release uncooperative WMI seam");
                    Ok(SystemQueryBatch::complete(Vec::new()))
                },
            ));
        }

        let healthy =
            run_bounded_system_query_with_pool(&pool, Duration::from_secs(1), |_, _, _| {
                Ok(SystemQueryBatch::complete(vec![row(&[(
                    "Source",
                    "healthy-after-four-timeouts",
                )])]))
            });

        for release in releases {
            release.send(()).expect("release uncooperative WMI seam");
        }
        let cleanup_deadline = Instant::now() + Duration::from_secs(1);
        while pool.busy_worker_count() != 0 && Instant::now() < cleanup_deadline {
            std::thread::yield_now();
        }
        let joined = pool.shutdown_and_join();

        assert!(timed_out.iter().all(|batch| matches!(
            batch.completion,
            Err(SystemReadError::Failed(ref detail))
                if detail.contains("remains owned by the bounded WMI pool")
        )));
        assert_eq!(
            healthy,
            SystemQueryBatch::complete(vec![row(&[("Source", "healthy-after-four-timeouts")])])
        );
        assert_eq!(joined, 4);
    }

    #[test]
    fn reaper_ceiling_opens_and_recovers_the_bounded_circuit_breaker() {
        let reaper = Box::leak(Box::new(SystemQueryWorkerReaper::new(2)));
        let pool = SystemQueryWorkerPool::start_with_reaper(1, reaper)
            .expect("start isolated bounded test pool");
        let mut releases = Vec::new();
        let mut timed_out = Vec::new();

        for _ in 0..2 {
            let (release_sender, release_receiver) = std::sync::mpsc::sync_channel(1);
            releases.push(release_sender);
            timed_out.push(run_bounded_system_query_with_pool(
                &pool,
                Duration::from_millis(10),
                move |_, _, _| {
                    release_receiver
                        .recv()
                        .expect("release uncooperative WMI seam");
                    Ok(SystemQueryBatch::complete(Vec::new()))
                },
            ));
        }

        let circuit_open =
            run_bounded_system_query_with_pool(&pool, Duration::from_secs(1), |_, _, _| {
                Ok(SystemQueryBatch::complete(Vec::new()))
            });

        assert!(matches!(
            timed_out[0].completion,
            Err(SystemReadError::Failed(ref detail))
                if detail.contains("replacement worker continues")
        ));
        assert!(matches!(
            timed_out[1].completion,
            Err(SystemReadError::Failed(ref detail))
                if detail.contains("bounded circuit breaker is open")
        ));
        assert!(matches!(
            circuit_open.completion,
            Err(SystemReadError::Failed(ref detail))
                if detail.contains("bounded circuit breaker is open")
        ));
        assert_eq!(reaper.owned_worker_count(), 2);
        assert_eq!(reaper.quarantined_worker_count(), 2);
        assert_eq!(pool.owned_worker_count(), 0);

        for release in releases {
            release.send(()).expect("release uncooperative WMI seam");
        }
        let cleanup_deadline = Instant::now() + Duration::from_secs(1);
        while reaper.owned_worker_count() != 0 && Instant::now() < cleanup_deadline {
            std::thread::yield_now();
        }
        assert_eq!(reaper.owned_worker_count(), 0);

        let recovered =
            run_bounded_system_query_with_pool(&pool, Duration::from_secs(1), |_, _, _| {
                Ok(SystemQueryBatch::complete(vec![row(&[(
                    "Source",
                    "recovered-after-reap",
                )])]))
            });
        assert_eq!(
            recovered,
            SystemQueryBatch::complete(vec![row(&[("Source", "recovered-after-reap")])])
        );
        assert_eq!(pool.shutdown_and_join(), 1);
        assert_eq!(reaper.owned_worker_count(), 0);
    }

    #[test]
    fn ownership_ceiling_preserves_remaining_healthy_capacity() {
        let reaper = Box::leak(Box::new(SystemQueryWorkerReaper::new(3)));
        let pool = SystemQueryWorkerPool::start_with_reaper(2, reaper)
            .expect("start isolated bounded test pool");
        let mut releases = Vec::new();

        for _ in 0..2 {
            let (release_sender, release_receiver) = std::sync::mpsc::sync_channel(1);
            releases.push(release_sender);
            let timed_out = run_bounded_system_query_with_pool(
                &pool,
                Duration::from_millis(10),
                move |_, _, _| {
                    release_receiver
                        .recv()
                        .expect("release uncooperative WMI seam");
                    Ok(SystemQueryBatch::complete(Vec::new()))
                },
            );
            assert!(matches!(
                timed_out.completion,
                Err(SystemReadError::Failed(ref detail))
                    if detail.contains("remains owned by the bounded WMI pool")
            ));
        }

        assert_eq!(reaper.owned_worker_count(), 3);
        assert_eq!(reaper.quarantined_worker_count(), 2);
        assert_eq!(pool.owned_worker_count(), 1);

        let healthy =
            run_bounded_system_query_with_pool(&pool, Duration::from_secs(1), |_, _, _| {
                Ok(SystemQueryBatch::complete(vec![row(&[(
                    "Source",
                    "healthy-at-ownership-ceiling",
                )])]))
            });
        assert_eq!(
            healthy,
            SystemQueryBatch::complete(vec![row(&[("Source", "healthy-at-ownership-ceiling")])])
        );

        for release in releases {
            release.send(()).expect("release uncooperative WMI seam");
        }
        assert_eq!(pool.shutdown_and_join(), 1);
        let cleanup_deadline = Instant::now() + Duration::from_secs(1);
        while reaper.owned_worker_count() != 0 && Instant::now() < cleanup_deadline {
            std::thread::yield_now();
        }
        assert_eq!(reaper.owned_worker_count(), 0);
    }

    #[test]
    fn dropping_pool_with_unreleased_work_returns_within_bound() {
        let pool = SystemQueryWorkerPool::start(1).expect("start bounded test pool");
        let (started_sender, started_receiver) = std::sync::mpsc::sync_channel(1);
        let (release_sender, release_receiver) = std::sync::mpsc::sync_channel(1);
        let (result_sender, result_receiver) = std::sync::mpsc::sync_channel(1);
        let (caller_finished_sender, caller_finished) = std::sync::mpsc::channel();
        let job = SystemQueryJob {
            deadline: Instant::now() + Duration::from_secs(1),
            partial_rows: Arc::new(std::sync::Mutex::new(Vec::new())),
            cancellation: SystemQueryCancellation::new(),
            work: Box::new(move |_, _, _| {
                started_sender.send(()).expect("signal stuck worker");
                release_receiver.recv().expect("release stuck worker");
                Ok(SystemQueryBatch::complete(Vec::new()))
            }),
            result_sender,
            caller_finished,
        };
        assert!(pool.dispatch(job).is_ok());
        started_receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("worker started");

        let (drop_finished_sender, drop_finished_receiver) = std::sync::mpsc::sync_channel(1);
        let drop_thread = std::thread::spawn(move || {
            drop(pool);
            drop_finished_sender.send(()).expect("signal pool drop");
        });
        let returned_within_bound = drop_finished_receiver
            .recv_timeout(Duration::from_millis(100))
            .is_ok();

        release_sender.send(()).expect("release stuck worker");
        caller_finished_sender
            .send(())
            .expect("acknowledge caller completion");
        result_receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("worker result after release")
            .expect("worker completion");
        if !returned_within_bound {
            drop_finished_receiver
                .recv_timeout(Duration::from_secs(1))
                .expect("pool drop completes after cleanup");
        }
        drop_thread.join().expect("drop thread joins");

        assert!(
            returned_within_bound,
            "pool Drop blocked on an unreleased worker instead of transferring ownership"
        );
    }

    #[test]
    fn dropped_pool_transfers_unfinished_handle_to_bounded_reaper() {
        let reaper = Box::leak(Box::new(SystemQueryWorkerReaper::new(4)));
        let pool = SystemQueryWorkerPool::start_with_reaper(1, reaper)
            .expect("start isolated bounded test pool");
        let (started_sender, started_receiver) = std::sync::mpsc::sync_channel(1);
        let (release_sender, release_receiver) = std::sync::mpsc::sync_channel(1);
        let (result_sender, result_receiver) = std::sync::mpsc::sync_channel(1);
        let (caller_finished_sender, caller_finished) = std::sync::mpsc::channel();
        let job = SystemQueryJob {
            deadline: Instant::now() + Duration::from_secs(1),
            partial_rows: Arc::new(std::sync::Mutex::new(Vec::new())),
            cancellation: SystemQueryCancellation::new(),
            work: Box::new(move |_, _, _| {
                started_sender.send(()).expect("signal stuck worker");
                release_receiver.recv().expect("release stuck worker");
                Ok(SystemQueryBatch::complete(Vec::new()))
            }),
            result_sender,
            caller_finished,
        };
        assert!(pool.dispatch(job).is_ok());
        started_receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("worker started");

        drop(pool);

        assert_eq!(reaper.owned_worker_count(), 1);
        assert_eq!(reaper.quarantined_worker_count(), 1);

        release_sender.send(()).expect("release stuck worker");
        caller_finished_sender
            .send(())
            .expect("acknowledge caller completion");
        result_receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("worker result after release")
            .expect("worker completion");
        let cleanup_deadline = Instant::now() + Duration::from_secs(1);
        while reaper.owned_worker_count() != 0 && Instant::now() < cleanup_deadline {
            std::thread::yield_now();
        }
        assert_eq!(reaper.owned_worker_count(), 0);
    }

    #[test]
    fn timeout_grace_preserves_result_and_shared_partial_rows_without_duplicates() {
        let pool = SystemQueryWorkerPool::start(1).expect("start bounded test pool");
        let shared_row = row(&[("Source", "shared-partial")]);
        let result_only_row = row(&[("Source", "result-only")]);
        let shared_for_worker = shared_row.clone();
        let result_for_worker = result_only_row.clone();

        let batch = run_bounded_system_query_with_pool(
            &pool,
            Duration::from_millis(10),
            move |_, partial_rows, cancellation| {
                partial_rows
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .push(shared_for_worker.clone());
                while !cancellation.is_cancelled() {
                    std::thread::park_timeout(Duration::from_millis(1));
                }
                Ok(SystemQueryBatch::complete(vec![
                    shared_for_worker,
                    result_for_worker,
                ]))
            },
        );

        assert_eq!(batch.rows, vec![shared_row, result_only_row]);
        assert_eq!(batch.completion, Err(SystemReadError::TimedOut));
        assert_eq!(pool.shutdown_and_join(), 1);
    }

    #[test]
    fn worker_slot_is_not_reused_before_cancelling_caller_finishes() {
        let pool = SystemQueryWorkerPool::start(1).expect("start bounded test pool");
        let (result_sender, result_receiver) = std::sync::mpsc::sync_channel(1);
        let (caller_finished_sender, caller_finished) = std::sync::mpsc::channel();
        let job = SystemQueryJob {
            deadline: Instant::now() + Duration::from_secs(1),
            partial_rows: Arc::new(std::sync::Mutex::new(Vec::new())),
            cancellation: SystemQueryCancellation::new(),
            work: Box::new(|_, _, _| Ok(SystemQueryBatch::complete(Vec::new()))),
            result_sender,
            caller_finished,
        };
        assert!(pool.dispatch(job).is_ok());
        assert_eq!(
            result_receiver
                .recv_timeout(Duration::from_secs(1))
                .expect("worker result"),
            Ok(SystemQueryBatch::complete(Vec::new()))
        );

        assert_eq!(pool.busy_worker_count(), 1);
        let blocked =
            run_bounded_system_query_with_pool(&pool, Duration::from_millis(25), |_, _, _| {
                Ok(SystemQueryBatch::complete(Vec::new()))
            });
        assert!(matches!(
            blocked.completion,
            Err(SystemReadError::Failed(ref detail)) if detail.contains("workers are busy")
        ));

        caller_finished_sender
            .send(())
            .expect("finish cancelling caller");
        let cleanup_deadline = Instant::now() + Duration::from_secs(1);
        while pool.busy_worker_count() != 0 && Instant::now() < cleanup_deadline {
            std::thread::yield_now();
        }
        assert_eq!(pool.busy_worker_count(), 0);
        assert_eq!(pool.shutdown_and_join(), 1);
    }

    #[test]
    fn successful_empty_process_query_is_available_not_missing() {
        let process_batch = finish_wmi_query(
            &WmiRequest::Processes(vec!["msiexec.exe".to_string()]),
            Vec::new(),
        );
        assert_eq!(process_batch, SystemQueryBatch::complete(Vec::new()));

        let missing_service = finish_wmi_query(&WmiRequest::ImeService, Vec::new());
        assert_eq!(missing_service, SystemQueryBatch::missing());
    }

    #[test]
    fn trusted_powershell_path_is_absolute_and_never_uses_path_search() {
        let windows_directory = Path::new(if cfg!(target_os = "windows") {
            r"C:\trusted\windows"
        } else {
            "/trusted/windows"
        });
        let executable = powershell_path_from_windows_directory(windows_directory);

        assert!(executable.is_absolute());
        assert_eq!(
            executable,
            windows_directory
                .join("System32")
                .join("WindowsPowerShell")
                .join("v1.0")
                .join("powershell.exe")
        );
        assert!(!include_str!("system.rs").contains("Command::new(\"powershell.exe\")"));
    }

    #[test]
    fn non_elevated_collection_reports_permission_limited_partial_coverage() {
        let provider = FakeSystemProvider::new(Ok(false))
            .with(
                SystemSource::OperatingSystem,
                vec![row(&[("Version", "10.0.26100")])],
                Ok(()),
            )
            .with(
                SystemSource::Tpm,
                Vec::new(),
                Err(SystemReadError::PermissionDenied),
            );

        let evidence = collect_system_evidence(&provider, "2026-07-15T14:00:00Z");
        assert!(!evidence.elevation.is_elevated);
        assert_eq!(evidence.hardware.os_version.as_deref(), Some("10.0.26100"));
        assert_eq!(evidence.hardware.tpm_version, None);
        assert_eq!(evidence.elevation.restricted_sources, vec!["system.tpm"]);
        assert!(evidence.coverage.iter().any(|coverage| {
            coverage.source == SystemSource::Tpm
                && coverage.access_state == EspSourceAccessState::PermissionDenied
        }));
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn live_system_provider_is_explicitly_unsupported_off_windows() {
        let provider = LiveSystemProvider;
        assert_eq!(provider.elevation(), Err(SystemReadError::Unsupported));
        assert_eq!(
            provider.query(
                SystemSource::OperatingSystem,
                SYSTEM_QUERY_TIMEOUT,
                MAX_SYSTEM_ROWS,
            ),
            SystemQueryBatch::unsupported()
        );
    }
}
