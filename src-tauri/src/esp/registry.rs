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
    pub access_error: Option<RegistryReadError>,
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
pub struct RegistryDescendantCoverage {
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
    pub descendant_coverage: Vec<RegistryDescendantCoverage>,
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

    evidence
        .descendant_coverage
        .sort_by(|left, right| left.key.cmp(&right.key));
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
        if registry_depth(&entry.relative_key) > MAX_REGISTRY_DEPTH
            || is_hardware_identity_registry_name(&entry.relative_key)
        {
            continue;
        }

        let full_key = if entry.relative_key.is_empty() {
            target.key.to_string()
        } else {
            format!("{}\\{}", target.key, entry.relative_key)
        };
        if let Some(error) = entry.access_error.as_ref() {
            let (access_state, detail) = access_state_for_error(error.clone());
            evidence
                .descendant_coverage
                .push(RegistryDescendantCoverage {
                    hive: target.hive.to_string(),
                    key: full_key.clone(),
                    access_state,
                    detail,
                });
        }
        let scope = classify_registry_scope(&full_key);
        let mut entry_evidence = Vec::new();

        for (value_index, value) in entry.values.iter().enumerate() {
            if value.size_bytes > MAX_REGISTRY_VALUE_BYTES
                || is_hardware_identity_registry_name(&value.name)
            {
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

fn is_hardware_identity_registry_name(value: &str) -> bool {
    let normalized = value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect::<String>();
    normalized.contains("hardwarehash") || normalized.contains("devicehardwaredata")
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
        RegistryReadError::PermissionDenied => (
            EspSourceAccessState::PermissionDenied,
            Some(
                "Access denied; restart CMTrace Open as administrator to read this registry key."
                    .to_string(),
            ),
        ),
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
    if is_hardware_identity_registry_name(&relative_key) {
        return;
    }

    let mut access_error = None;
    let mut values = Vec::new();
    for value_result in key.enum_values() {
        let (name, value) = match value_result {
            Ok(value) => value,
            Err(error) => {
                record_registry_error(&mut access_error, map_io_error(error));
                continue;
            }
        };
        if is_hardware_identity_registry_name(&name) || value.bytes.len() > MAX_REGISTRY_VALUE_BYTES
        {
            continue;
        }
        let size_bytes = value.bytes.len();
        if let Some(value) = decode_registry_value(value.vtype.clone() as u32, &value.bytes) {
            values.push(RegistryValueSnapshot {
                name,
                size_bytes,
                value,
            });
        }
    }
    let entry_index = entries.len();
    entries.push(RegistrySnapshotKey {
        relative_key: relative_key.clone(),
        values,
        access_error,
    });

    if depth >= MAX_REGISTRY_DEPTH {
        return;
    }

    let mut subkeys = Vec::new();
    for subkey_result in key.enum_keys() {
        match subkey_result {
            Ok(name) => subkeys.push(name),
            Err(error) => {
                record_registry_error(&mut entries[entry_index].access_error, map_io_error(error))
            }
        }
    }
    subkeys.sort_by_key(|name| name.to_ascii_lowercase());
    for subkey_name in subkeys {
        if is_hardware_identity_registry_name(&subkey_name) {
            continue;
        }
        let child_relative_key = if relative_key.is_empty() {
            subkey_name.clone()
        } else {
            format!("{relative_key}\\{subkey_name}")
        };
        let subkey = match key.open_subkey_with_flags(&subkey_name, access) {
            Ok(subkey) => subkey,
            Err(error) => {
                entries.push(RegistrySnapshotKey {
                    relative_key: child_relative_key,
                    values: Vec::new(),
                    access_error: Some(map_io_error(error)),
                });
                continue;
            }
        };
        read_key_bounded(&subkey, child_relative_key, depth + 1, access, entries);
    }
}

#[cfg(target_os = "windows")]
fn record_registry_error(slot: &mut Option<RegistryReadError>, error: RegistryReadError) {
    if slot.is_none()
        || matches!(error, RegistryReadError::PermissionDenied)
            && !matches!(slot, Some(RegistryReadError::PermissionDenied))
    {
        *slot = Some(error);
    }
}

#[cfg(any(target_os = "windows", test))]
fn decode_registry_value(value_type: u32, bytes: &[u8]) -> Option<EspObservationValue> {
    if bytes.len() > MAX_REGISTRY_VALUE_BYTES {
        return None;
    }

    let decoded = match value_type {
        // REG_SZ and REG_EXPAND_SZ
        1 | 2 => decode_utf16_units(bytes).and_then(|units| {
            let end = units
                .iter()
                .position(|unit| *unit == 0)
                .unwrap_or(units.len());
            String::from_utf16(&units[..end])
                .ok()
                .map(EspObservationValue::Text)
        }),
        // REG_DWORD
        4 if bytes.len() == 4 => Some(EspObservationValue::Unsigned(u64::from(
            u32::from_le_bytes(bytes.try_into().expect("length checked")),
        ))),
        // REG_DWORD_BIG_ENDIAN
        5 if bytes.len() == 4 => Some(EspObservationValue::Unsigned(u64::from(
            u32::from_be_bytes(bytes.try_into().expect("length checked")),
        ))),
        // REG_MULTI_SZ
        7 => decode_utf16_units(bytes).and_then(|mut units| {
            while units.last() == Some(&0) {
                units.pop();
            }
            if units.is_empty() {
                return Some(EspObservationValue::StringList(Vec::new()));
            }
            units
                .split(|unit| *unit == 0)
                .map(String::from_utf16)
                .collect::<Result<Vec<_>, _>>()
                .ok()
                .map(EspObservationValue::StringList)
        }),
        // REG_QWORD
        11 if bytes.len() == 8 => Some(EspObservationValue::Unsigned(u64::from_le_bytes(
            bytes.try_into().expect("length checked"),
        ))),
        _ => None,
    };

    Some(decoded.unwrap_or_else(|| typed_hex_registry_value(value_type, bytes)))
}

#[cfg(any(target_os = "windows", test))]
fn decode_utf16_units(bytes: &[u8]) -> Option<Vec<u16>> {
    if bytes.len() % 2 != 0 {
        return None;
    }
    Some(
        bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect(),
    )
}

#[cfg(any(target_os = "windows", test))]
fn typed_hex_registry_value(value_type: u32, bytes: &[u8]) -> EspObservationValue {
    let hex = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    EspObservationValue::Text(format!("registry-type-{value_type}:hex:{hex}"))
}

#[cfg(target_os = "windows")]
fn map_io_error(error: std::io::Error) -> RegistryReadError {
    match error.kind() {
        std::io::ErrorKind::NotFound => RegistryReadError::Missing,
        std::io::ErrorKind::PermissionDenied => RegistryReadError::PermissionDenied,
        _ => RegistryReadError::Failed(error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16_bytes(units: &[u16]) -> Vec<u8> {
        units.iter().flat_map(|unit| unit.to_le_bytes()).collect()
    }

    #[test]
    fn registry_value_decoder_preserves_each_supported_type_without_guessing() {
        assert_eq!(
            decode_registry_value(1, &utf16_bytes(&[b'A' as u16, b'B' as u16, 0])),
            Some(EspObservationValue::Text("AB".to_string()))
        );
        assert_eq!(
            decode_registry_value(2, &utf16_bytes(&[b'%' as u16, b'X' as u16, b'%' as u16, 0])),
            Some(EspObservationValue::Text("%X%".to_string()))
        );
        assert_eq!(
            decode_registry_value(
                7,
                &utf16_bytes(&[
                    b'o' as u16,
                    b'n' as u16,
                    b'e' as u16,
                    0,
                    b't' as u16,
                    b'w' as u16,
                    b'o' as u16,
                    0,
                    0,
                ]),
            ),
            Some(EspObservationValue::StringList(vec![
                "one".to_string(),
                "two".to_string(),
            ]))
        );
        assert_eq!(
            decode_registry_value(4, &[0x78, 0x56, 0x34, 0x12]),
            Some(EspObservationValue::Unsigned(0x1234_5678))
        );
        assert_eq!(
            decode_registry_value(5, &[0x12, 0x34, 0x56, 0x78]),
            Some(EspObservationValue::Unsigned(0x1234_5678))
        );
        assert_eq!(
            decode_registry_value(11, &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]),
            Some(EspObservationValue::Unsigned(0x0102_0304_0506_0708))
        );
        assert_eq!(
            decode_registry_value(3, &[b'A', 0, b'B', 0]),
            Some(EspObservationValue::Text(
                "registry-type-3:hex:41004200".to_string()
            ))
        );
        assert_eq!(
            decode_registry_value(42, &[0xde, 0xad, 0xbe, 0xef]),
            Some(EspObservationValue::Text(
                "registry-type-42:hex:deadbeef".to_string()
            ))
        );
        assert_eq!(
            decode_registry_value(0, &[]),
            Some(EspObservationValue::Text(
                "registry-type-0:hex:".to_string()
            ))
        );
    }

    #[test]
    fn registry_value_decoder_is_lossless_for_malformed_values_and_enforces_cap() {
        assert_eq!(
            decode_registry_value(1, &[0x41]),
            Some(EspObservationValue::Text(
                "registry-type-1:hex:41".to_string()
            ))
        );
        assert_eq!(
            decode_registry_value(1, &[0x00, 0xd8, 0x00, 0x00]),
            Some(EspObservationValue::Text(
                "registry-type-1:hex:00d80000".to_string()
            ))
        );
        assert_eq!(
            decode_registry_value(4, &[0x01, 0x02, 0x03]),
            Some(EspObservationValue::Text(
                "registry-type-4:hex:010203".to_string()
            ))
        );
        assert!(decode_registry_value(3, &vec![0xab; MAX_REGISTRY_VALUE_BYTES]).is_some());
        assert_eq!(
            decode_registry_value(3, &vec![0xab; MAX_REGISTRY_VALUE_BYTES + 1]),
            None
        );
    }
}
