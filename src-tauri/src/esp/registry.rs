//! Bounded, read-only acquisition of ESP-related Windows registry evidence.

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

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
pub const MAX_REGISTRY_KEYS: usize = 4_096;
pub const MAX_REGISTRY_VALUES: usize = 16_384;
pub const MAX_REGISTRY_TOTAL_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_REGISTRY_UNINSTALL_LOOKUPS: usize = 256;
pub const MAX_REGISTRY_ACQUISITION_DURATION: Duration = Duration::from_secs(3);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegistryAcquisitionLimits {
    pub max_keys: usize,
    pub max_values: usize,
    pub max_total_bytes: usize,
    pub max_uninstall_lookups: usize,
    pub max_duration: Duration,
}

impl Default for RegistryAcquisitionLimits {
    fn default() -> Self {
        Self {
            max_keys: MAX_REGISTRY_KEYS,
            max_values: MAX_REGISTRY_VALUES,
            max_total_bytes: MAX_REGISTRY_TOTAL_BYTES,
            max_uninstall_lookups: MAX_REGISTRY_UNINSTALL_LOOKUPS,
            max_duration: MAX_REGISTRY_ACQUISITION_DURATION,
        }
    }
}

#[derive(Debug)]
pub struct RegistryAcquisitionBudget {
    limits: RegistryAcquisitionLimits,
    deadline: Instant,
    keys: usize,
    values: usize,
    total_bytes: usize,
    uninstall_candidates: usize,
    limitations: Vec<String>,
    limitation_occurrences: u64,
    last_limitation: Option<String>,
}

impl RegistryAcquisitionBudget {
    fn new(limits: RegistryAcquisitionLimits) -> Self {
        Self {
            limits,
            deadline: Instant::now() + limits.max_duration,
            keys: 0,
            values: 0,
            total_bytes: 0,
            uninstall_candidates: 0,
            limitations: Vec::new(),
            limitation_occurrences: 0,
            last_limitation: None,
        }
    }

    fn checkpoint(&self) -> u64 {
        self.limitation_occurrences
    }

    fn detail_since(&self, checkpoint: u64) -> Option<String> {
        (checkpoint < self.limitation_occurrences)
            .then(|| self.last_limitation.clone())
            .flatten()
    }

    fn record_limitation(&mut self, detail: impl Into<String>) {
        let detail = detail.into();
        self.limitation_occurrences = self.limitation_occurrences.saturating_add(1);
        self.last_limitation = Some(detail.clone());
        if !self.limitations.contains(&detail) {
            self.limitations.push(detail);
        }
    }

    fn check_time(&mut self) -> bool {
        if Instant::now() >= self.deadline {
            self.record_limitation("Registry acquisition time budget was exhausted.");
            false
        } else {
            true
        }
    }

    fn root_unavailable_detail(&mut self) -> Option<String> {
        if !self.check_time() {
            return Some("Registry acquisition time budget was exhausted.".to_string());
        }
        let detail = if self.keys >= self.limits.max_keys {
            Some("Registry key budget was exhausted.")
        } else if self.values >= self.limits.max_values {
            Some("Registry value budget was exhausted.")
        } else if self.total_bytes >= self.limits.max_total_bytes {
            Some("Registry byte budget was exhausted.")
        } else {
            None
        };
        detail.map(|detail| {
            self.record_limitation(detail);
            detail.to_string()
        })
    }

    fn take_key(&mut self) -> bool {
        if !self.check_time() {
            return false;
        }
        if self.keys >= self.limits.max_keys {
            self.record_limitation("Registry key budget was exhausted.");
            return false;
        }
        self.keys += 1;
        true
    }

    #[cfg(target_os = "windows")]
    fn remaining_keys(&self) -> usize {
        self.limits.max_keys.saturating_sub(self.keys)
    }

    fn take_value(&mut self, size_bytes: usize) -> bool {
        if !self.check_time() {
            return false;
        }
        if self.values >= self.limits.max_values {
            self.record_limitation("Registry value budget was exhausted.");
            return false;
        }
        if size_bytes > self.limits.max_total_bytes.saturating_sub(self.total_bytes) {
            self.record_limitation("Registry byte budget was exhausted.");
            return false;
        }
        self.values += 1;
        self.total_bytes += size_bytes;
        true
    }

    fn take_uninstall_candidate(&mut self) -> bool {
        if !self.check_time() {
            return false;
        }
        if self.uninstall_candidates >= self.limits.max_uninstall_lookups {
            self.record_limitation("Registry uninstall lookup budget was exhausted.");
            return false;
        }
        self.uninstall_candidates += 1;
        true
    }
}

#[cfg(any(target_os = "windows", test))]
#[derive(Debug)]
struct BoundedRegistryNameSet {
    capacity: usize,
    names: BTreeSet<(String, String)>,
    eligible_seen: bool,
    truncated: bool,
}

#[cfg(any(target_os = "windows", test))]
impl BoundedRegistryNameSet {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            names: BTreeSet::new(),
            eligible_seen: false,
            truncated: false,
        }
    }

    fn push(&mut self, name: String) {
        if is_hardware_identity_registry_name(&name) {
            return;
        }
        self.eligible_seen = true;
        self.names.insert((name.to_ascii_lowercase(), name));
        if self.names.len() > self.capacity {
            self.names.pop_last();
            self.truncated = true;
        }
    }

    fn has_eligible_names(&self) -> bool {
        self.eligible_seen
    }

    fn truncated(&self) -> bool {
        self.truncated
    }

    fn into_names(self) -> Vec<String> {
        self.names.into_iter().map(|(_, name)| name).collect()
    }
}

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

    fn read_tree_bounded(
        &self,
        target: &RegistryTarget,
        access: u32,
        budget: &mut RegistryAcquisitionBudget,
    ) -> Result<Vec<RegistrySnapshotKey>, RegistryReadError> {
        self.read_tree(target, access)
            .map(|entries| bound_registry_snapshot(entries, budget))
    }

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
    pub sensitivity: EspSensitivity,
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub limitations: Vec<String>,
}

pub fn collect_registry_evidence(
    provider: &impl RegistryProvider,
    observed_product_codes: &[String],
    observed_at_utc: &str,
) -> RegistryEvidence {
    collect_registry_evidence_with_limits(
        provider,
        observed_product_codes,
        observed_at_utc,
        RegistryAcquisitionLimits::default(),
    )
}

fn collect_registry_evidence_with_limits(
    provider: &impl RegistryProvider,
    observed_product_codes: &[String],
    observed_at_utc: &str,
    limits: RegistryAcquisitionLimits,
) -> RegistryEvidence {
    let mut evidence = RegistryEvidence::default();
    let mut budget = RegistryAcquisitionBudget::new(limits);

    for (target_index, target) in ESP_REGISTRY_TARGETS.iter().enumerate() {
        if let Some(detail) = budget.root_unavailable_detail() {
            evidence.roots.push(root_evidence(
                target,
                EspSourceAccessState::Failed,
                Some(format!("Partial registry evidence: {detail}")),
            ));
            continue;
        }

        let checkpoint = budget.checkpoint();
        match provider.read_tree_bounded(target, REGISTRY_READ_ACCESS, &mut budget) {
            Ok(entries) => {
                let detail = budget.detail_since(checkpoint);
                evidence.roots.push(root_evidence(
                    target,
                    if detail.is_some() {
                        EspSourceAccessState::Failed
                    } else {
                        EspSourceAccessState::Available
                    },
                    detail.map(|detail| format!("Partial registry evidence: {detail}")),
                ));
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
    evidence.uninstall_names =
        lookup_observed_uninstall_names(provider, observed_product_codes, &mut budget);
    evidence.limitations = budget.limitations;
    evidence
}

fn bound_registry_snapshot(
    mut entries: Vec<RegistrySnapshotKey>,
    budget: &mut RegistryAcquisitionBudget,
) -> Vec<RegistrySnapshotKey> {
    let mut bounded = Vec::new();
    entries.sort_by(|left, right| {
        left.relative_key
            .to_ascii_lowercase()
            .cmp(&right.relative_key.to_ascii_lowercase())
            .then_with(|| left.relative_key.cmp(&right.relative_key))
    });

    for mut entry in entries {
        if !budget.take_key() {
            break;
        }
        if registry_depth(&entry.relative_key) > MAX_REGISTRY_DEPTH {
            budget.record_limitation(format!(
                "Registry depth budget of {MAX_REGISTRY_DEPTH} was exhausted."
            ));
            continue;
        }
        entry.values.sort_by(|left, right| {
            left.name
                .to_ascii_lowercase()
                .cmp(&right.name.to_ascii_lowercase())
                .then_with(|| left.name.cmp(&right.name))
        });
        let mut values = Vec::new();
        let mut stop = false;
        for value in entry.values {
            if value.size_bytes > MAX_REGISTRY_VALUE_BYTES {
                budget.record_limitation(format!(
                    "Registry per-value byte limit of {MAX_REGISTRY_VALUE_BYTES} was exceeded."
                ));
                continue;
            }
            if !budget.take_value(value.size_bytes) {
                stop = true;
                break;
            }
            values.push(value);
        }
        entry.values = values;
        bounded.push(entry);
        if stop {
            break;
        }
    }

    bounded
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
            || node_cache_target && node_cache_contains_hardware_identity(&entry)
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
                    sensitivity: registry_path_sensitivity(&full_key),
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
    budget: &mut RegistryAcquisitionBudget,
) -> Vec<UninstallProductName> {
    let mut product_codes = BTreeSet::new();
    for product_code in observed_product_codes {
        if !budget.take_uninstall_candidate() {
            break;
        }
        if let Some(product_code) = normalize_msi_product_code(product_code) {
            product_codes.insert(product_code);
        }
    }

    product_codes
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

fn normalize_msi_product_code(product_code: &str) -> Option<String> {
    let product_code = product_code.trim();
    let inner =
        if product_code.len() == 38 && product_code.starts_with('{') && product_code.ends_with('}')
        {
            &product_code[1..37]
        } else if product_code.len() == 36 {
            product_code
        } else {
            return None;
        };
    let valid = inner.split('-').map(str::len).eq([8, 4, 4, 4, 12])
        && inner
            .chars()
            .all(|character| character == '-' || character.is_ascii_hexdigit());
    valid.then(|| format!("{{{}}}", inner.to_ascii_uppercase()))
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

fn node_cache_contains_hardware_identity(entry: &RegistrySnapshotKey) -> bool {
    entry.values.iter().any(|value| match &value.value {
        EspObservationValue::Text(value) => is_hardware_identity_registry_name(value),
        EspObservationValue::StringList(values) => values
            .iter()
            .any(|value| is_hardware_identity_registry_name(value)),
        EspObservationValue::Integer(_)
        | EspObservationValue::Unsigned(_)
        | EspObservationValue::Boolean(_) => false,
    })
}

fn registry_sensitivity(key: &str, value_name: &str) -> EspSensitivity {
    let path_sensitivity = registry_path_sensitivity(key);
    if path_sensitivity != EspSensitivity::Public {
        return path_sensitivity;
    }
    if is_sensitive_registry_field_name(value_name) {
        EspSensitivity::Sensitive
    } else {
        EspSensitivity::Public
    }
}

fn registry_path_sensitivity(key: &str) -> EspSensitivity {
    let components = key.split('\\').collect::<Vec<_>>();
    if components
        .iter()
        .any(|component| normalize_registry_field_name(component) == "nodecache")
    {
        EspSensitivity::Restricted
    } else if components.iter().any(|component| {
        is_windows_sid_component(component) || is_sensitive_registry_field_name(component)
    }) {
        EspSensitivity::Sensitive
    } else {
        EspSensitivity::Public
    }
}

fn is_sensitive_registry_field_name(value: &str) -> bool {
    matches!(
        normalize_registry_field_name(value).as_str(),
        "upn"
            | "userprincipalname"
            | "sid"
            | "usersid"
            | "tenant"
            | "tenantid"
            | "tenantdomain"
            | "aadtenantid"
            | "aadtenantdomain"
            | "cloudassignedtenantid"
            | "cloudassignedtenantdomain"
            | "entdmid"
            | "serial"
            | "serialnumber"
    )
}

fn normalize_registry_field_name(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn is_windows_sid_component(component: &str) -> bool {
    let mut fields = component.split('-');
    if !fields
        .next()
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("s"))
        || fields.next() != Some("1")
    {
        return false;
    }
    let Some(identifier_authority) = fields.next() else {
        return false;
    };
    if !is_sid_identifier_authority(identifier_authority) {
        return false;
    }
    let mut subauthority_count = 0;
    for field in fields {
        subauthority_count += 1;
        if subauthority_count > 15 || !is_sid_subauthority(field) {
            return false;
        }
    }
    subauthority_count != 0
}

fn is_sid_identifier_authority(value: &str) -> bool {
    const MAX_DECIMAL_IDENTIFIER_AUTHORITY: u64 = u32::MAX as u64;
    const MIN_HEX_IDENTIFIER_AUTHORITY: u64 = MAX_DECIMAL_IDENTIFIER_AUTHORITY + 1;
    const MAX_IDENTIFIER_AUTHORITY: u64 = 0xFFFF_FFFF_FFFF;

    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        return hex.len() == 12
            && hex.chars().all(|character| character.is_ascii_hexdigit())
            && u64::from_str_radix(hex, 16).is_ok_and(|authority| {
                (MIN_HEX_IDENTIFIER_AUTHORITY..=MAX_IDENTIFIER_AUTHORITY).contains(&authority)
            });
    }

    is_canonical_sid_decimal(value)
        && value
            .parse::<u64>()
            .is_ok_and(|authority| authority <= MAX_DECIMAL_IDENTIFIER_AUTHORITY)
}

fn is_sid_subauthority(value: &str) -> bool {
    is_canonical_sid_decimal(value) && value.parse::<u32>().is_ok()
}

fn is_canonical_sid_decimal(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 10
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && (value == "0" || !value.starts_with('0'))
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
        let mut budget = RegistryAcquisitionBudget::new(RegistryAcquisitionLimits::default());
        self.read_tree_bounded(target, access, &mut budget)
    }

    fn read_tree_bounded(
        &self,
        target: &RegistryTarget,
        access: u32,
        budget: &mut RegistryAcquisitionBudget,
    ) -> Result<Vec<RegistrySnapshotKey>, RegistryReadError> {
        use winreg::enums::HKEY_LOCAL_MACHINE;
        use winreg::RegKey;

        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let root = hklm
            .open_subkey_with_flags(target.key, access)
            .map_err(map_io_error)?;
        let mut entries = Vec::new();
        read_key_bounded(&root, String::new(), 0, access, &mut entries, budget);
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
    budget: &mut RegistryAcquisitionBudget,
) {
    if is_hardware_identity_registry_name(&relative_key) {
        return;
    }
    if !budget.take_key() {
        return;
    }

    let mut access_error = None;
    let mut values = Vec::new();
    let mut budget_limited = false;
    for value_result in key.enum_values() {
        if !budget.check_time() {
            budget_limited = true;
            break;
        }
        let (name, value) = match value_result {
            Ok(value) => value,
            Err(error) => {
                record_registry_error(&mut access_error, map_io_error(error));
                continue;
            }
        };
        if is_hardware_identity_registry_name(&name) {
            continue;
        }
        if value.bytes.len() > MAX_REGISTRY_VALUE_BYTES {
            budget.record_limitation(format!(
                "Registry per-value byte limit of {MAX_REGISTRY_VALUE_BYTES} was exceeded."
            ));
            continue;
        }
        let size_bytes = value.bytes.len();
        if !budget.take_value(size_bytes) {
            budget_limited = true;
            break;
        }
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

    if budget_limited {
        return;
    }

    let mut subkeys = BoundedRegistryNameSet::new(budget.remaining_keys());
    for subkey_result in key.enum_keys() {
        if !budget.check_time() {
            return;
        }
        match subkey_result {
            Ok(name) => subkeys.push(name),
            Err(error) => {
                record_registry_error(&mut entries[entry_index].access_error, map_io_error(error))
            }
        }
    }
    if subkeys.truncated() {
        budget.record_limitation("Registry key budget was exhausted.");
    }
    if depth >= MAX_REGISTRY_DEPTH {
        if subkeys.has_eligible_names() {
            budget.record_limitation(format!(
                "Registry depth budget of {MAX_REGISTRY_DEPTH} was exhausted."
            ));
        }
        return;
    }

    for subkey_name in subkeys.into_names() {
        if !budget.check_time() {
            return;
        }
        if budget.remaining_keys() == 0 {
            budget.record_limitation("Registry key budget was exhausted.");
            return;
        }
        let child_relative_key = if relative_key.is_empty() {
            subkey_name.clone()
        } else {
            format!("{relative_key}\\{subkey_name}")
        };
        let subkey = match key.open_subkey_with_flags(&subkey_name, access) {
            Ok(subkey) => subkey,
            Err(error) => {
                if !budget.take_key() {
                    return;
                }
                entries.push(RegistrySnapshotKey {
                    relative_key: child_relative_key,
                    values: Vec::new(),
                    access_error: Some(map_io_error(error)),
                });
                continue;
            }
        };
        read_key_bounded(
            &subkey,
            child_relative_key,
            depth + 1,
            access,
            entries,
            budget,
        );
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
    use std::cell::RefCell;

    use super::*;

    struct BudgetRegistryProvider {
        entries: Vec<RegistrySnapshotKey>,
        reads: RefCell<usize>,
        uninstall_lookups: RefCell<Vec<String>>,
    }

    struct RepeatingRegistryProvider {
        entries: Vec<RegistrySnapshotKey>,
        uninstall_lookups: RefCell<Vec<String>>,
    }

    impl RegistryProvider for BudgetRegistryProvider {
        fn read_tree(
            &self,
            target: &RegistryTarget,
            _access: u32,
        ) -> Result<Vec<RegistrySnapshotKey>, RegistryReadError> {
            *self.reads.borrow_mut() += 1;
            if target.key == ESP_REGISTRY_TARGETS[0].key {
                Ok(self.entries.clone())
            } else {
                Err(RegistryReadError::Missing)
            }
        }

        fn lookup_uninstall_display_name(
            &self,
            product_code: &str,
            _access: u32,
        ) -> Result<Option<String>, RegistryReadError> {
            self.uninstall_lookups
                .borrow_mut()
                .push(product_code.to_string());
            Ok(Some(format!("Product {product_code}")))
        }
    }

    impl RegistryProvider for RepeatingRegistryProvider {
        fn read_tree(
            &self,
            _target: &RegistryTarget,
            _access: u32,
        ) -> Result<Vec<RegistrySnapshotKey>, RegistryReadError> {
            Ok(self.entries.clone())
        }

        fn lookup_uninstall_display_name(
            &self,
            product_code: &str,
            _access: u32,
        ) -> Result<Option<String>, RegistryReadError> {
            self.uninstall_lookups
                .borrow_mut()
                .push(product_code.to_string());
            Ok(Some(format!("Product {product_code}")))
        }
    }

    fn budget_provider() -> BudgetRegistryProvider {
        BudgetRegistryProvider {
            entries: (0..4)
                .map(|index| RegistrySnapshotKey {
                    relative_key: format!("Child-{index}"),
                    values: vec![RegistryValueSnapshot::text_with_size(
                        format!("Value-{index}"),
                        format!("Data-{index}"),
                        4,
                    )],
                    access_error: None,
                })
                .collect(),
            reads: RefCell::new(0),
            uninstall_lookups: RefCell::new(Vec::new()),
        }
    }

    fn acquisition_limits(
        max_keys: usize,
        max_values: usize,
        max_total_bytes: usize,
        max_uninstall_lookups: usize,
        max_duration: std::time::Duration,
    ) -> RegistryAcquisitionLimits {
        RegistryAcquisitionLimits {
            max_keys,
            max_values,
            max_total_bytes,
            max_uninstall_lookups,
            max_duration,
        }
    }

    fn utf16_bytes(units: &[u16]) -> Vec<u8> {
        units.iter().flat_map(|unit| unit.to_le_bytes()).collect()
    }

    #[test]
    fn registry_aggregate_key_value_and_byte_budgets_preserve_partial_evidence() {
        let cases = [
            (
                "key",
                acquisition_limits(2, 16, 1024, 0, std::time::Duration::from_secs(5)),
                2,
            ),
            (
                "value",
                acquisition_limits(16, 2, 1024, 0, std::time::Duration::from_secs(5)),
                2,
            ),
            (
                "byte",
                acquisition_limits(16, 16, 8, 0, std::time::Duration::from_secs(5)),
                2,
            ),
        ];

        for (expected_limit, limits, expected_observations) in cases {
            let provider = budget_provider();
            let evidence = collect_registry_evidence_with_limits(
                &provider,
                &[],
                "2026-07-16T12:00:00Z",
                limits,
            );

            assert_eq!(
                evidence.observations.len(),
                expected_observations,
                "wrong retained observation count for {expected_limit} budget"
            );
            assert_eq!(
                evidence.roots[0].access_state,
                EspSourceAccessState::Failed,
                "partial root was reported as complete for {expected_limit} budget"
            );
            assert!(evidence
                .limitations
                .iter()
                .any(|detail| detail.to_ascii_lowercase().contains(expected_limit)));
        }
    }

    #[test]
    fn registry_snapshot_truncation_is_deterministic_across_provider_order() {
        let entries = ["Zulu", "Alpha", "Mike"]
            .map(|relative_key| RegistrySnapshotKey {
                relative_key: relative_key.to_string(),
                values: Vec::new(),
                access_error: None,
            })
            .to_vec();
        let limits = acquisition_limits(2, 16, 1024, 0, std::time::Duration::from_secs(5));

        let forward =
            bound_registry_snapshot(entries.clone(), &mut RegistryAcquisitionBudget::new(limits));
        let reverse = bound_registry_snapshot(
            entries.into_iter().rev().collect(),
            &mut RegistryAcquisitionBudget::new(limits),
        );
        let retained_keys = |entries: Vec<RegistrySnapshotKey>| {
            entries
                .into_iter()
                .map(|entry| entry.relative_key)
                .collect::<Vec<_>>()
        };

        assert_eq!(retained_keys(forward), ["Alpha", "Mike"]);
        assert_eq!(retained_keys(reverse), ["Alpha", "Mike"]);
    }

    #[test]
    fn registry_review_subkey_truncation_keeps_smallest_eligible_names_across_provider_order() {
        let names = ["Zulu", "HardwareHash", "Alpha", "Mike"];
        let select = |names: Vec<&str>| {
            let mut selected = BoundedRegistryNameSet::new(2);
            for name in names {
                selected.push(name.to_string());
            }
            assert!(selected.has_eligible_names());
            assert!(selected.truncated());
            selected.into_names()
        };

        assert_eq!(select(names.to_vec()), ["Alpha", "Mike"]);
        assert_eq!(select(names.into_iter().rev().collect()), ["Alpha", "Mike"]);
    }

    #[test]
    fn registry_review_value_truncation_is_deterministic_across_provider_order() {
        let values = ["Zulu", "Alpha", "Mike"]
            .map(|name| RegistryValueSnapshot::text_with_size(name, name, 1))
            .to_vec();
        let entry = |values| RegistrySnapshotKey {
            relative_key: "Child".to_string(),
            values,
            access_error: None,
        };
        let limits = acquisition_limits(1, 2, 1024, 0, std::time::Duration::from_secs(5));

        let forward = bound_registry_snapshot(
            vec![entry(values.clone())],
            &mut RegistryAcquisitionBudget::new(limits),
        );
        let reverse = bound_registry_snapshot(
            vec![entry(values.into_iter().rev().collect())],
            &mut RegistryAcquisitionBudget::new(limits),
        );
        let retained_names = |entries: Vec<RegistrySnapshotKey>| {
            entries[0]
                .values
                .iter()
                .map(|value| value.name.clone())
                .collect::<Vec<_>>()
        };

        assert_eq!(retained_names(forward), ["Alpha", "Mike"]);
        assert_eq!(retained_names(reverse), ["Alpha", "Mike"]);
    }

    #[test]
    fn registry_review_repeated_oversized_values_mark_every_affected_root_partial() {
        let provider = RepeatingRegistryProvider {
            entries: vec![RegistrySnapshotKey {
                relative_key: "Child".to_string(),
                values: vec![RegistryValueSnapshot::text_with_size(
                    "Oversized",
                    "not retained",
                    MAX_REGISTRY_VALUE_BYTES + 1,
                )],
                access_error: None,
            }],
            uninstall_lookups: RefCell::new(Vec::new()),
        };

        let evidence = collect_registry_evidence_with_limits(
            &provider,
            &[],
            "2026-07-16T12:00:00Z",
            acquisition_limits(32, 32, 1024, 0, std::time::Duration::from_secs(5)),
        );

        assert!(evidence
            .roots
            .iter()
            .all(|root| root.access_state == EspSourceAccessState::Failed));
        assert!(evidence
            .limitations
            .iter()
            .any(|detail| detail.contains("per-value")));
        assert_eq!(evidence.limitations.len(), 1);
    }

    #[test]
    fn registry_review_depth_truncation_marks_every_affected_root_partial() {
        let provider = RepeatingRegistryProvider {
            entries: vec![RegistrySnapshotKey {
                relative_key: (0..=MAX_REGISTRY_DEPTH)
                    .map(|index| format!("Level{index}"))
                    .collect::<Vec<_>>()
                    .join("\\"),
                values: Vec::new(),
                access_error: None,
            }],
            uninstall_lookups: RefCell::new(Vec::new()),
        };

        let evidence = collect_registry_evidence_with_limits(
            &provider,
            &[],
            "2026-07-16T12:00:00Z",
            acquisition_limits(32, 32, 1024, 0, std::time::Duration::from_secs(5)),
        );

        assert!(evidence
            .roots
            .iter()
            .all(|root| root.access_state == EspSourceAccessState::Failed));
        assert!(evidence
            .limitations
            .iter()
            .any(|detail| detail.contains("depth budget")));
        assert_eq!(evidence.limitations.len(), 1);
    }

    #[test]
    fn registry_time_budget_skips_reads_and_reports_partial_coverage() {
        let provider = budget_provider();
        let evidence = collect_registry_evidence_with_limits(
            &provider,
            &[],
            "2026-07-16T12:00:00Z",
            acquisition_limits(16, 16, 1024, 16, std::time::Duration::ZERO),
        );

        assert_eq!(*provider.reads.borrow(), 0);
        assert!(evidence.observations.is_empty());
        assert!(evidence
            .roots
            .iter()
            .all(|root| root.access_state == EspSourceAccessState::Failed));
        assert!(evidence
            .limitations
            .iter()
            .any(|detail| detail.to_ascii_lowercase().contains("time")));
    }

    #[test]
    fn registry_uninstall_lookup_budget_caps_observed_product_codes_honestly() {
        let provider = BudgetRegistryProvider {
            entries: Vec::new(),
            reads: RefCell::new(0),
            uninstall_lookups: RefCell::new(Vec::new()),
        };
        let product_codes = [
            "{11111111-1111-1111-1111-111111111111}",
            "{22222222-2222-2222-2222-222222222222}",
            "{33333333-3333-3333-3333-333333333333}",
        ]
        .map(str::to_string);

        let evidence = collect_registry_evidence_with_limits(
            &provider,
            &product_codes,
            "2026-07-16T12:00:00Z",
            acquisition_limits(16, 16, 1024, 2, std::time::Duration::from_secs(5)),
        );

        assert_eq!(provider.uninstall_lookups.borrow().len(), 2);
        assert_eq!(evidence.uninstall_names.len(), 2);
        assert!(evidence
            .limitations
            .iter()
            .any(|detail| detail.to_ascii_lowercase().contains("uninstall lookup")));
    }

    #[test]
    fn registry_review_canonicalizes_bare_and_braced_product_codes_before_lookup() {
        let provider = BudgetRegistryProvider {
            entries: Vec::new(),
            reads: RefCell::new(0),
            uninstall_lookups: RefCell::new(Vec::new()),
        };
        let product_codes = [
            "11111111-1111-1111-1111-111111111111".to_string(),
            "{11111111-1111-1111-1111-111111111111}".to_string(),
        ];

        let evidence = collect_registry_evidence_with_limits(
            &provider,
            &product_codes,
            "2026-07-16T12:00:00Z",
            acquisition_limits(16, 16, 1024, 2, std::time::Duration::from_secs(5)),
        );

        assert_eq!(
            provider.uninstall_lookups.into_inner(),
            ["{11111111-1111-1111-1111-111111111111}"]
        );
        assert_eq!(evidence.uninstall_names.len(), 1);
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

    #[test]
    fn registry_path_sensitivity_accepts_complete_sid_grammar() {
        for sid in [
            "S-1-0-0",
            "S-1-5-21-111-222-333-1001",
            "S-1-12-1-111-222-333",
            "S-1-15-2-1",
            "S-1-16-12288",
            "S-1-4294967295-1",
            "S-1-0x000100000000-1",
            "S-1-0XFFFFFFFFFFFF-4294967295",
            "S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15",
        ] {
            assert_eq!(
                registry_path_sensitivity(&format!(
                    r"SOFTWARE\Microsoft\Windows\Autopilot\User\{sid}\Readable"
                )),
                EspSensitivity::Sensitive,
                "valid SID component was not classified as sensitive: {sid}"
            );
        }

        for near_miss in [
            "S-1-5",
            "S-2-5-1",
            "S-1-05-1",
            "S-1-4294967296-1",
            "S-1-281474976710655-1",
            "S-1-10000000000-1",
            "S-1-0x-1",
            "S-1-0x100000000-1",
            "S-1-0x000000000005-1",
            "S-1-0x1000000000000-1",
            "S-1-5-01",
            "S-1-5-00000000000",
            "S-1-5-4294967296",
            "S-1-5-1-1-1-1-1-1-1-1-1-1-1-1-1-1-1-1",
            "S-1-5-not-numeric",
            "prefix-S-1-5-21",
        ] {
            assert_eq!(
                registry_path_sensitivity(&format!(
                    r"SOFTWARE\Microsoft\Windows\Autopilot\User\{near_miss}\Readable"
                )),
                EspSensitivity::Public,
                "near-miss SID component was classified as sensitive: {near_miss}"
            );
        }
    }

    #[test]
    fn registry_path_sensitivity_uses_case_insensitive_semantic_field_names() {
        for field in [
            "TenantId",
            "tenantid",
            "TENANTID",
            "tenant-id",
            "UserSID",
            "user_sid",
            "CloudAssignedTenantId",
            "cloud-assigned-tenant-domain",
            "AADTenantId",
            "UserPrincipalName",
            "EntDMID",
            "SerialNumber",
        ] {
            assert_eq!(
                registry_path_sensitivity(&format!(
                    r"SOFTWARE\Microsoft\Windows\Autopilot\{field}\Readable"
                )),
                EspSensitivity::Sensitive,
                "documented sensitive field was not classified as sensitive: {field}"
            );
        }

        for ordinary in ["Outside", "NotASid", "Presidential", "SerializationMode"] {
            assert_eq!(
                registry_path_sensitivity(&format!(
                    r"SOFTWARE\Microsoft\Windows\Autopilot\{ordinary}\Readable"
                )),
                EspSensitivity::Public,
                "ordinary path component was classified as sensitive: {ordinary}"
            );
        }
    }

    #[test]
    fn registry_value_name_sensitivity_rejects_substring_false_positives() {
        let public_key = r"SOFTWARE\Microsoft\Windows\Autopilot\Readable";
        for field in [
            "UPN",
            "UserPrincipalName",
            "UserSID",
            "tenantid",
            "CloudAssignedTenantId",
            "TenantDomain",
            "EntDMID",
            "SerialNumber",
        ] {
            assert_eq!(
                registry_sensitivity(public_key, field),
                EspSensitivity::Sensitive,
                "documented sensitive value name was not classified as sensitive: {field}"
            );
        }

        for ordinary in ["Outside", "NotASid", "Presidential", "SerializationMode"] {
            assert_eq!(
                registry_sensitivity(public_key, ordinary),
                EspSensitivity::Public,
                "ordinary value name was classified as sensitive: {ordinary}"
            );
        }
    }
}
