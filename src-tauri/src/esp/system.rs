//! Bounded, read-only system evidence acquisition for ESP diagnostics.

use std::collections::BTreeMap;
use std::time::Duration;

use cmtraceopen_parser::esp::{
    EspClassifiedString, EspDeliveryOptimizationEventKind, EspDeliveryOptimizationEvidence,
    EspDeliveryOptimizationObservation, EspElevationState, EspEvidenceProvenance, EspEvidenceRef,
    EspHardwareEvidence, EspObservationContext, EspParseState, EspSensitivity,
    EspSourceAccessState, EspSourceKind, EspSystemFact, EspSystemObservation,
};
use serde::{Deserialize, Serialize};

pub const SYSTEM_QUERY_TIMEOUT: Duration = Duration::from_secs(3);
pub const MAX_SYSTEM_ROWS: usize = 64;

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
        .filter(
            |row| !matches!(row.get("_Kind"), Some(kind) if kind.eq_ignore_ascii_case("Status")),
        )
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
    let total = u128::from(download_http_bytes)
        + u128::from(download_lan_bytes)
        + u128::from(download_cache_host_bytes);
    let share = |bytes: u64| (total != 0).then(|| (bytes as f64 / total as f64) * 100.0);

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
        .filter(|row| matches!(row.get("_Kind"), Some(kind) if kind.eq_ignore_ascii_case("Status")))
        .take(MAX_SYSTEM_ROWS)
        .enumerate()
        .map(|(index, row)| {
            let completed = row
                .get("Status")
                .is_some_and(|status| status.eq_ignore_ascii_case("Complete"));
            EspDeliveryOptimizationObservation {
                context: observation_context(
                    SystemSource::DeliveryOptimization,
                    index,
                    observed_at_utc,
                    EspSensitivity::Public,
                ),
                kind: if completed {
                    EspDeliveryOptimizationEventKind::DownloadCompleted
                } else {
                    EspDeliveryOptimizationEventKind::DownloadStarted
                },
                content_id: value(Some(row), "FileId"),
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

pub struct LiveSystemProvider;

#[cfg(target_os = "windows")]
#[derive(Debug, Clone)]
pub(crate) enum WmiRequest {
    OperatingSystem,
    ComputerSystem,
    Bios,
    Tpm,
    ImeService,
    Processes(Vec<String>),
}

#[cfg(target_os = "windows")]
mod windows_provider {
    use std::io::ErrorKind;
    use std::process::{Command, Stdio};
    use std::thread;
    use std::time::{Duration, Instant};

    use serde_json::Value;
    use windows::core::{BSTR, HRESULT, PCWSTR};
    use windows::Win32::Foundation::{CloseHandle, E_ACCESSDENIED, HANDLE, RPC_E_CHANGED_MODE};
    use windows::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows::Win32::System::Com::{
        CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER,
        COINIT_MULTITHREADED,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows::Win32::System::Variant::{VariantClear, VariantToString, VARIANT};
    use windows::Win32::System::Wmi::{
        IWbemClassObject, IWbemLocator, WbemLocator, WBEM_E_ACCESS_DENIED, WBEM_E_INVALID_CLASS,
        WBEM_E_INVALID_NAMESPACE, WBEM_E_NOT_FOUND, WBEM_FLAG_FORWARD_ONLY,
        WBEM_FLAG_RETURN_IMMEDIATELY, WBEM_S_TIMEDOUT,
    };

    use super::{
        LiveSystemProvider, SystemProvider, SystemQueryBatch, SystemReadError, SystemRow,
        SystemSource, WmiRequest,
    };

    const MAX_VARIANT_CHARS: usize = 4096;
    const MAX_COMMAND_OUTPUT_BYTES: usize = 1024 * 1024;
    const DO_SCRIPT: &str = "$ErrorActionPreference='Stop';$perf=Get-DeliveryOptimizationPerfSnapThisMonth|Select-Object DownloadHttpBytes,DownloadLanBytes,DownloadCacheHostBytes;$status=@(Get-DeliveryOptimizationStatus|Select-Object -First 64 FileId,Status,BytesFromHttp,BytesFromLanPeers,BytesFromCacheServer);[pscustomobject]@{perf=$perf;status=$status}|ConvertTo-Json -Compress -Depth 4";

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

    impl SystemProvider for LiveSystemProvider {
        fn elevation(&self) -> Result<bool, SystemReadError> {
            let mut token = HANDLE::default();
            // SAFETY: token points to valid writable storage and is closed by HandleGuard.
            unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }
                .map_err(|error| error_from_windows(error, "process token query failed"))?;
            let _token = HandleGuard(token);
            let mut elevation = TOKEN_ELEVATION::default();
            let mut returned = 0_u32;
            // SAFETY: elevation is valid writable TOKEN_ELEVATION storage of the declared size.
            unsafe {
                GetTokenInformation(
                    token,
                    TokenElevation,
                    Some((&mut elevation as *mut TOKEN_ELEVATION).cast()),
                    std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                    &mut returned,
                )
            }
            .map_err(|error| error_from_windows(error, "token elevation query failed"))?;
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
        match query_wmi_inner(request, timeout, max_rows) {
            Ok(batch) => batch,
            Err(error) => SystemQueryBatch {
                rows: Vec::new(),
                completion: Err(error),
            },
        }
    }

    fn query_wmi_inner(
        request: WmiRequest,
        timeout: Duration,
        max_rows: usize,
    ) -> Result<SystemQueryBatch, SystemReadError> {
        let _com = ComGuard::initialize()?;
        let (namespace, query, properties) = wmi_spec(request);
        // SAFETY: WbemLocator is a registered in-process COM class and no outer object is used.
        let locator: IWbemLocator =
            unsafe { CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER) }
                .map_err(|error| error_from_windows(error, "WMI locator creation failed"))?;
        let namespace = BSTR::from(namespace);
        let empty = BSTR::new();
        // SAFETY: all BSTR inputs live through the synchronous ConnectServer call.
        let services =
            unsafe { locator.ConnectServer(&namespace, &empty, &empty, &empty, 0, &empty, None) }
                .map_err(|error| error_from_windows(error, "WMI namespace connection failed"))?;
        let language = BSTR::from("WQL");
        let query = BSTR::from(query.as_str());
        let flags = WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY;
        // SAFETY: query text is selected exclusively from wmi_spec's fixed allowlist.
        let enumerator = unsafe { services.ExecQuery(&language, &query, flags, None) }
            .map_err(|error| error_from_windows(error, "WMI query failed"))?;

        let deadline = Instant::now() + timeout;
        let mut rows = Vec::new();
        let cap = max_rows.min(512);
        while rows.len() < cap {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(SystemQueryBatch {
                    rows,
                    completion: Err(SystemReadError::TimedOut),
                });
            }
            let timeout_ms = remaining.as_millis().min(i32::MAX as u128) as i32;
            let mut objects: [Option<IWbemClassObject>; 1] = [None];
            let mut returned = 0_u32;
            // SAFETY: the output slice and returned count are valid for the synchronous call.
            let result = unsafe { enumerator.Next(timeout_ms, &mut objects, &mut returned) };
            if result.0 == WBEM_S_TIMEDOUT.0 {
                return Ok(SystemQueryBatch {
                    rows,
                    completion: Err(SystemReadError::TimedOut),
                });
            }
            if result.is_err() {
                return Err(error_from_hresult(result, "WMI enumeration failed"));
            }
            if returned == 0 {
                break;
            }
            if let Some(object) = objects[0].take() {
                rows.push(read_wmi_row(&object, properties)?);
            }
        }

        if rows.is_empty() {
            Ok(SystemQueryBatch::missing())
        } else {
            Ok(SystemQueryBatch::complete(rows))
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

    fn wmi_spec(request: WmiRequest) -> (&'static str, String, &'static [&'static str]) {
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
                    .into_iter()
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
        let mut child = match Command::new("powershell.exe")
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                DO_SCRIPT,
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(child) => child,
            Err(error) if error.kind() == ErrorKind::NotFound => {
                return SystemQueryBatch::unsupported()
            }
            Err(_) => {
                return SystemQueryBatch {
                    rows: Vec::new(),
                    completion: Err(SystemReadError::Failed(
                        "Delivery Optimization command could not start".to_string(),
                    )),
                }
            }
        };

        let deadline = Instant::now() + timeout;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Some(status),
                Ok(None) if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(20));
                }
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
                Err(_) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return SystemQueryBatch {
                        rows: Vec::new(),
                        completion: Err(SystemReadError::Failed(
                            "Delivery Optimization command wait failed".to_string(),
                        )),
                    };
                }
            }
        };
        let Some(status) = status else {
            return SystemQueryBatch {
                rows: Vec::new(),
                completion: Err(SystemReadError::TimedOut),
            };
        };
        if !status.success() {
            return SystemQueryBatch {
                rows: Vec::new(),
                completion: Err(SystemReadError::Failed(format!(
                    "Delivery Optimization command failed with exit code {}",
                    status.code().unwrap_or(-1)
                ))),
            };
        }

        let output = match child.wait_with_output() {
            Ok(output) if output.stdout.len() <= MAX_COMMAND_OUTPUT_BYTES => output.stdout,
            Ok(_) => {
                return SystemQueryBatch {
                    rows: Vec::new(),
                    completion: Err(SystemReadError::Failed(
                        "Delivery Optimization output exceeded the size limit".to_string(),
                    )),
                }
            }
            Err(_) => {
                return SystemQueryBatch {
                    rows: Vec::new(),
                    completion: Err(SystemReadError::Failed(
                        "Delivery Optimization output read failed".to_string(),
                    )),
                }
            }
        };
        match parse_delivery_json(&output, max_rows) {
            Ok(rows) if rows.is_empty() => SystemQueryBatch::missing(),
            Ok(rows) => SystemQueryBatch::complete(rows),
            Err(error) => SystemQueryBatch {
                rows: Vec::new(),
                completion: Err(error),
            },
        }
    }

    fn parse_delivery_json(
        output: &[u8],
        max_rows: usize,
    ) -> Result<Vec<SystemRow>, SystemReadError> {
        let document: Value = serde_json::from_slice(output).map_err(|_| {
            SystemReadError::Failed("Delivery Optimization JSON was malformed".to_string())
        })?;
        let mut rows = Vec::new();
        if let Some(perf) = document.get("perf").and_then(Value::as_object) {
            rows.push(json_row(perf, "Perf"));
        }
        if let Some(status) = document.get("status") {
            let records = status
                .as_array()
                .map(Vec::as_slice)
                .unwrap_or_else(|| std::slice::from_ref(status));
            rows.extend(
                records
                    .iter()
                    .filter_map(Value::as_object)
                    .take(max_rows.saturating_sub(rows.len()))
                    .map(|record| json_row(record, "Status")),
            );
        }
        rows.truncate(max_rows);
        Ok(rows)
    }

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
    use std::time::Duration;

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
    fn delivery_optimization_counters_use_total_download_bytes_as_denominator() {
        let evidence = delivery_optimization_from_rows(
            &[row(&[
                ("DownloadHttpBytes", "700"),
                ("DownloadLanBytes", "200"),
                ("DownloadCacheHostBytes", "100"),
            ])],
            "2026-07-15T14:00:00Z",
        )
        .expect("counter row");

        assert_eq!(evidence.download_http_bytes, 700);
        assert_eq!(evidence.download_lan_bytes, 200);
        assert_eq!(evidence.download_cache_host_bytes, 100);
        assert_eq!(evidence.peer_share_percent, Some(20.0));
        assert_eq!(evidence.connected_cache_share_percent, Some(10.0));

        let zero = delivery_optimization_from_rows(
            &[row(&[
                ("DownloadHttpBytes", "0"),
                ("DownloadLanBytes", "0"),
                ("DownloadCacheHostBytes", "0"),
            ])],
            "2026-07-15T14:00:00Z",
        )
        .expect("zero counter row");
        assert_eq!(zero.peer_share_percent, None);
        assert_eq!(zero.connected_cache_share_percent, None);
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
