//! Bounded, read-only acquisition of ESP-related Windows registry evidence.

use std::collections::BTreeSet;

use cmtraceopen_parser::esp::{
    EspEvidenceProvenance, EspEvidenceRef, EspNodeCacheEntry, EspObservationContext,
    EspObservationValue, EspParseState, EspRegistryObservation, EspRegistryProvenance, EspScope,
    EspSensitivity, EspSourceAccessState, EspSourceKind,
};
use serde::{Deserialize, Serialize};

/// `KEY_READ | KEY_WOW64_64KEY` from the Windows registry API.
pub const REGISTRY_READ_ACCESS: u32 = 0x0002_0019 | 0x0000_0100;
pub const MAX_REGISTRY_DEPTH: usize = 8;
pub const MAX_REGISTRY_VALUE_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegistryTarget {
    pub hive: &'static str,
    pub key: &'static str,
}

pub const ESP_REGISTRY_TARGETS: &[RegistryTarget] = &[
    RegistryTarget {
        hive: "HKLM",
        key: r"SOFTWARE\Microsoft\Provisioning\Diagnostics\Autopilot",
    },
    RegistryTarget {
        hive: "HKLM",
        key: r"SOFTWARE\Microsoft\Provisioning\AutopilotSettings",
    },
    RegistryTarget {
        hive: "HKLM",
        key: r"SOFTWARE\Microsoft\Provisioning\OMADM",
    },
    RegistryTarget {
        hive: "HKLM",
        key: r"SOFTWARE\Microsoft\Provisioning\NodeCache\CSP",
    },
    RegistryTarget {
        hive: "HKLM",
        key: r"SOFTWARE\Microsoft\Windows\Autopilot\EnrollmentStatusTracking",
    },
    RegistryTarget {
        hive: "HKLM",
        key: r"SOFTWARE\Microsoft\Enrollments",
    },
    RegistryTarget {
        hive: "HKLM",
        key: r"SOFTWARE\Microsoft\EnterpriseDesktopAppManagement",
    },
    RegistryTarget {
        hive: "HKLM",
        key: r"SOFTWARE\Microsoft\OfficeCSP",
    },
    RegistryTarget {
        hive: "HKLM",
        key: r"SOFTWARE\Microsoft\IntuneManagementExtension",
    },
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryReadError {
    Missing,
    PermissionDenied,
    Failed(String),
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryValueSnapshot {
    pub name: String,
    pub value: EspObservationValue,
    pub size_bytes: usize,
}

impl RegistryValueSnapshot {
    pub fn text(name: impl Into<String>, value: impl Into<String>) -> Self {
        let value = value.into();
        let size_bytes = value.len();
        Self {
            name: name.into(),
            value: EspObservationValue::Text(value),
            size_bytes,
        }
    }

    pub fn text_with_size(
        name: impl Into<String>,
        value: impl Into<String>,
        size_bytes: usize,
    ) -> Self {
        Self {
            name: name.into(),
            value: EspObservationValue::Text(value.into()),
            size_bytes,
        }
    }

    pub fn integer(name: impl Into<String>, value: i64) -> Self {
        Self {
            name: name.into(),
            value: EspObservationValue::Integer(value),
            size_bytes: std::mem::size_of::<i64>(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrySnapshotKey {
    pub relative_key: String,
    pub values: Vec<RegistryValueSnapshot>,
}

pub trait RegistryProvider {
    fn read_tree(
        &self,
        target: &RegistryTarget,
        access: u32,
    ) -> Result<Vec<RegistrySnapshotKey>, RegistryReadError>;

    fn lookup_uninstall_display_name(
        &self,
        product_code: &str,
        access: u32,
    ) -> Result<Option<String>, RegistryReadError>;
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RegistryRootEvidence {
    pub hive: String,
    pub key: String,
    pub access_state: EspSourceAccessState,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ScopedRegistryObservation {
    pub scope: Option<EspScope>,
    pub observation: EspRegistryObservation,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UninstallProductName {
    pub product_code: String,
    pub display_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct RegistryEvidence {
    pub roots: Vec<RegistryRootEvidence>,
    pub observations: Vec<ScopedRegistryObservation>,
    pub node_cache: Vec<EspNodeCacheEntry>,
    pub uninstall_names: Vec<UninstallProductName>,
}

pub fn collect_registry_evidence(
    provider: &impl RegistryProvider,
    observed_product_codes: &[String],
    observed_at_utc: &str,
) -> RegistryEvidence {
    let mut evidence = RegistryEvidence::default();

    for (target_index, target) in ESP_REGISTRY_TARGETS.iter().enumerate() {
        match provider.read_tree(target, REGISTRY_READ_ACCESS) {
            Ok(entries) => {
                evidence
                    .roots
                    .push(root_evidence(target, EspSourceAccessState::Available, None));
                append_tree_observations(
                    &mut evidence,
                    target,
                    target_index,
                    entries,
                    observed_at_utc,
                );
            }
            Err(error) => {
                let (access_state, detail) = access_state_for_error(error);
                evidence
                    .roots
                    .push(root_evidence(target, access_state, detail));
            }
        }
    }

    evidence.node_cache.sort_by_key(|entry| entry.index);
    evidence.uninstall_names = lookup_observed_uninstall_names(provider, observed_product_codes);
    evidence
}

pub fn classify_registry_scope(key: &str) -> Option<EspScope> {
    let components = key.split('\\').collect::<Vec<_>>();
    let start = components
        .iter()
        .position(|component| {
            component.eq_ignore_ascii_case("EnrollmentStatusTracking")
                || component.eq_ignore_ascii_case("EnterpriseDesktopAppManagement")
        })
        .map_or(0, |index| index + 1);

    components[start..].iter().find_map(|component| {
        if component.eq_ignore_ascii_case("Device") {
            Some(EspScope::Device)
        } else if component.eq_ignore_ascii_case("User") {
            Some(EspScope::User)
        } else {
            None
        }
    })
}

fn append_tree_observations(
    evidence: &mut RegistryEvidence,
    target: &RegistryTarget,
    target_index: usize,
    entries: Vec<RegistrySnapshotKey>,
    observed_at_utc: &str,
) {
    let node_cache_target = target.key.ends_with(r"NodeCache\CSP");

    for (entry_index, entry) in entries.into_iter().enumerate() {
        if registry_depth(&entry.relative_key) > MAX_REGISTRY_DEPTH {
            continue;
        }

        let full_key = if entry.relative_key.is_empty() {
            target.key.to_string()
        } else {
            format!("{}\\{}", target.key, entry.relative_key)
        };
        let scope = classify_registry_scope(&full_key);
        let mut entry_evidence = Vec::new();

        for (value_index, value) in entry.values.iter().enumerate() {
            if value.size_bytes > MAX_REGISTRY_VALUE_BYTES {
                continue;
            }

            let source_artifact_id = format!("registry:{}\\{}", target.hive, target.key);
            let evidence_ref = EspEvidenceRef {
                evidence_id: format!("esp-registry-{target_index}-{entry_index}-{value_index}"),
                source_artifact_id: source_artifact_id.clone(),
            };
            entry_evidence.push(evidence_ref.clone());
            let sensitivity = registry_sensitivity(&full_key, &value.name);
            let observation = EspRegistryObservation {
                context: EspObservationContext {
                    evidence_ref,
                    provenance: EspEvidenceProvenance {
                        source_kind: EspSourceKind::Registry,
                        source_artifact_id,
                        file_path: None,
                        line_number: None,
                        record_number: None,
                        registry: Some(EspRegistryProvenance {
                            hive: target.hive.to_string(),
                            key: full_key.clone(),
                            value_name: Some(value.name.clone()),
                        }),
                        event: None,
                    },
                    source_timestamp: None,
                    observed_at_utc: observed_at_utc.to_string(),
                    sensitivity,
                    parse_state: EspParseState::Parsed,
                    access_state: EspSourceAccessState::Available,
                },
                hive: target.hive.to_string(),
                key: full_key.clone(),
                value_name: value.name.clone(),
                value: value.value.clone(),
            };
            evidence.observations.push(ScopedRegistryObservation {
                scope: scope.clone(),
                observation,
            });
        }

        if node_cache_target {
            if let Some(node_cache_entry) = node_cache_entry(&entry, entry_evidence) {
                evidence.node_cache.push(node_cache_entry);
            }
        }
    }
}

fn node_cache_entry(
    entry: &RegistrySnapshotKey,
    evidence: Vec<EspEvidenceRef>,
) -> Option<EspNodeCacheEntry> {
    let index = entry
        .relative_key
        .rsplit('\\')
        .next()?
        .parse::<u64>()
        .ok()?;
    let node_uri = text_value(&entry.values, "NodeURI")?;
    let expected_value = text_value(&entry.values, "ExpectedValue");

    Some(EspNodeCacheEntry {
        index,
        node_uri,
        expected_value,
        sensitivity: EspSensitivity::Restricted,
        evidence,
    })
}

fn text_value(values: &[RegistryValueSnapshot], name: &str) -> Option<String> {
    values.iter().find_map(|value| {
        if !value.name.eq_ignore_ascii_case(name) || value.size_bytes > MAX_REGISTRY_VALUE_BYTES {
            return None;
        }
        match &value.value {
            EspObservationValue::Text(value) => Some(value.clone()),
            EspObservationValue::Integer(value) => Some(value.to_string()),
            EspObservationValue::Unsigned(value) => Some(value.to_string()),
            EspObservationValue::Boolean(value) => Some(value.to_string()),
            EspObservationValue::StringList(value) => Some(value.join(";")),
        }
    })
}

fn lookup_observed_uninstall_names(
    provider: &impl RegistryProvider,
    observed_product_codes: &[String],
) -> Vec<UninstallProductName> {
    observed_product_codes
        .iter()
        .map(|product_code| product_code.to_ascii_uppercase())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter_map(|product_code| {
            provider
                .lookup_uninstall_display_name(&product_code, REGISTRY_READ_ACCESS)
                .ok()
                .flatten()
                .map(|display_name| UninstallProductName {
                    product_code,
                    display_name,
                })
        })
        .collect()
}

fn registry_depth(relative_key: &str) -> usize {
    relative_key
        .split('\\')
        .filter(|component| !component.is_empty())
        .count()
}

fn registry_sensitivity(key: &str, value_name: &str) -> EspSensitivity {
    let combined = format!("{key}\\{value_name}").to_ascii_lowercase();
    if combined.contains("nodecache") {
        EspSensitivity::Restricted
    } else if ["upn", "sid", "tenant", "entdmid", "serial"]
        .iter()
        .any(|marker| combined.contains(marker))
    {
        EspSensitivity::Sensitive
    } else {
        EspSensitivity::Public
    }
}

fn root_evidence(
    target: &RegistryTarget,
    access_state: EspSourceAccessState,
    detail: Option<String>,
) -> RegistryRootEvidence {
    RegistryRootEvidence {
        hive: target.hive.to_string(),
        key: target.key.to_string(),
        access_state,
        detail,
    }
}

fn access_state_for_error(error: RegistryReadError) -> (EspSourceAccessState, Option<String>) {
    match error {
        RegistryReadError::Missing => (EspSourceAccessState::Missing, None),
        RegistryReadError::PermissionDenied => (EspSourceAccessState::PermissionDenied, None),
        RegistryReadError::Failed(detail) => (EspSourceAccessState::Failed, Some(detail)),
        RegistryReadError::Unsupported => (EspSourceAccessState::Unsupported, None),
    }
}

#[cfg(target_os = "windows")]
#[derive(Debug, Default, Clone, Copy)]
pub struct WindowsRegistryProvider;

#[cfg(target_os = "windows")]
impl RegistryProvider for WindowsRegistryProvider {
    fn read_tree(
        &self,
        target: &RegistryTarget,
        access: u32,
    ) -> Result<Vec<RegistrySnapshotKey>, RegistryReadError> {
        use winreg::enums::HKEY_LOCAL_MACHINE;
        use winreg::RegKey;

        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let root = hklm
            .open_subkey_with_flags(target.key, access)
            .map_err(map_io_error)?;
        let mut entries = Vec::new();
        read_key_bounded(&root, String::new(), 0, access, &mut entries);
        Ok(entries)
    }

    fn lookup_uninstall_display_name(
        &self,
        product_code: &str,
        access: u32,
    ) -> Result<Option<String>, RegistryReadError> {
        use winreg::enums::HKEY_LOCAL_MACHINE;
        use winreg::RegKey;

        let key_path =
            format!(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{product_code}");
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let key = match hklm.open_subkey_with_flags(key_path, access) {
            Ok(key) => key,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(map_io_error(error)),
        };
        match key.get_value::<String, _>("DisplayName") {
            Ok(display_name) => Ok(Some(display_name)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(map_io_error(error)),
        }
    }
}

#[cfg(target_os = "windows")]
pub fn collect_live_registry_evidence(
    observed_product_codes: &[String],
    observed_at_utc: &str,
) -> RegistryEvidence {
    collect_registry_evidence(
        &WindowsRegistryProvider,
        observed_product_codes,
        observed_at_utc,
    )
}

#[cfg(not(target_os = "windows"))]
pub fn collect_live_registry_evidence(
    _observed_product_codes: &[String],
    _observed_at_utc: &str,
) -> Result<RegistryEvidence, RegistryReadError> {
    Err(RegistryReadError::Unsupported)
}

#[cfg(target_os = "windows")]
fn read_key_bounded(
    key: &winreg::RegKey,
    relative_key: String,
    depth: usize,
    access: u32,
    entries: &mut Vec<RegistrySnapshotKey>,
) {
    let values = key
        .enum_values()
        .filter_map(Result::ok)
        .filter(|(_, value)| value.bytes.len() <= MAX_REGISTRY_VALUE_BYTES)
        .map(|(name, value)| RegistryValueSnapshot {
            name,
            size_bytes: value.bytes.len(),
            value: decode_windows_registry_value(&value),
        })
        .collect::<Vec<_>>();
    entries.push(RegistrySnapshotKey {
        relative_key: relative_key.clone(),
        values,
    });

    if depth >= MAX_REGISTRY_DEPTH {
        return;
    }

    let mut subkeys = key.enum_keys().filter_map(Result::ok).collect::<Vec<_>>();
    subkeys.sort_by_key(|name| name.to_ascii_lowercase());
    for subkey_name in subkeys {
        let Ok(subkey) = key.open_subkey_with_flags(&subkey_name, access) else {
            continue;
        };
        let child_relative_key = if relative_key.is_empty() {
            subkey_name
        } else {
            format!("{relative_key}\\{subkey_name}")
        };
        read_key_bounded(&subkey, child_relative_key, depth + 1, access, entries);
    }
}

#[cfg(target_os = "windows")]
fn decode_windows_registry_value(value: &winreg::RegValue) -> EspObservationValue {
    use winreg::enums::{REG_DWORD, REG_QWORD};

    if value.vtype == REG_DWORD && value.bytes.len() >= 4 {
        return EspObservationValue::Unsigned(u64::from(u32::from_le_bytes([
            value.bytes[0],
            value.bytes[1],
            value.bytes[2],
            value.bytes[3],
        ])));
    }
    if value.vtype == REG_QWORD && value.bytes.len() >= 8 {
        return EspObservationValue::Unsigned(u64::from_le_bytes([
            value.bytes[0],
            value.bytes[1],
            value.bytes[2],
            value.bytes[3],
            value.bytes[4],
            value.bytes[5],
            value.bytes[6],
            value.bytes[7],
        ]));
    }

    let utf16 = value
        .bytes
        .chunks_exact(2)
        .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
        .take_while(|unit| *unit != 0)
        .collect::<Vec<_>>();
    if !utf16.is_empty() {
        return EspObservationValue::Text(String::from_utf16_lossy(&utf16));
    }

    EspObservationValue::Text(
        value
            .bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
    )
}

#[cfg(target_os = "windows")]
fn map_io_error(error: std::io::Error) -> RegistryReadError {
    match error.kind() {
        std::io::ErrorKind::NotFound => RegistryReadError::Missing,
        std::io::ErrorKind::PermissionDenied => RegistryReadError::PermissionDenied,
        _ => RegistryReadError::Failed(error.to_string()),
    }
}
