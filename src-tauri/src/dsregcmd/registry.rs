use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::dsregcmd::extended::unbraced_guid;
use crate::dsregcmd::models::{
    DsregcmdEnrollmentEntry, DsregcmdEnrollmentEvidence, DsregcmdEvidenceSource,
    DsregcmdOsVersionEvidence, DsregcmdPolicyEvidenceValue, DsregcmdProxyEvidence,
    DsregcmdWhfbPolicyEvidence,
};

const REGISTRY_FOLDER: [&str; 2] = ["evidence", "registry"];
const POLICYMANAGER_CURRENT_FILE: &str = "policymanager-device.reg";
const POLICYMANAGER_PROVIDERS_FILE: &str = "policymanager-providers.reg";
const HKCU_POLICIES_FILE: &str = "hkcu-policies.reg";
const HKLM_POLICIES_FILE: &str = "hklm-policies.reg";
const HKCU_MICROSOFT_POLICIES_FILE: &str = "hkcu-microsoft-policies.reg";
const HKLM_MICROSOFT_POLICIES_FILE: &str = "hklm-microsoft-policies.reg";
const OS_VERSION_FILE: &str = "os-version.reg";
const PROXY_INTERNET_SETTINGS_FILE: &str = "proxy-internet-settings.reg";
const ENROLLMENTS_FILE: &str = "enrollments.reg";

#[derive(Debug, Clone, PartialEq, Eq)]
enum RegistryValue {
    Dword(u32),
    String(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RegistrySnapshotValuePreview {
    pub name: String,
    pub value_type: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RegistrySnapshotKeyPreview {
    pub path: String,
    pub value_count: u32,
    pub values: Vec<RegistrySnapshotValuePreview>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RegistrySnapshotSummary {
    pub key_count: u32,
    pub value_count: u32,
    pub keys: Vec<RegistrySnapshotKeyPreview>,
}

type RegistryKeyMap = HashMap<String, HashMap<String, RegistryValue>>;

pub fn inspect_registry_snapshot_file(path: &Path) -> Option<RegistrySnapshotSummary> {
    let content = fs::read_to_string(path).ok().or_else(|| {
        fs::read(path)
            .ok()
            .and_then(|bytes| decode_reg_content(&bytes))
    })?;
    let registry = parse_reg_snapshot(&content);

    Some(build_registry_snapshot_summary(&registry))
}

pub fn load_whfb_policy_evidence(bundle_path: &Path) -> DsregcmdWhfbPolicyEvidence {
    let mut evidence = DsregcmdWhfbPolicyEvidence::default();

    let current_path = registry_file_path(bundle_path, POLICYMANAGER_CURRENT_FILE);
    let provider_path = registry_file_path(bundle_path, POLICYMANAGER_PROVIDERS_FILE);
    let hkcu_policies_path = registry_file_path(bundle_path, HKCU_POLICIES_FILE);
    let hklm_policies_path = registry_file_path(bundle_path, HKLM_POLICIES_FILE);
    let hkcu_microsoft_policies_path =
        registry_file_path(bundle_path, HKCU_MICROSOFT_POLICIES_FILE);
    let hklm_microsoft_policies_path =
        registry_file_path(bundle_path, HKLM_MICROSOFT_POLICIES_FILE);

    let current_registry = load_registry_map_or_empty(&current_path, &mut evidence.artifact_paths);
    let provider_registry =
        load_registry_map_or_empty(&provider_path, &mut evidence.artifact_paths);
    let hkcu_policy_registry =
        load_registry_map_or_empty(&hkcu_policies_path, &mut evidence.artifact_paths);
    let hklm_policy_registry =
        load_registry_map_or_empty(&hklm_policies_path, &mut evidence.artifact_paths);
    let hkcu_microsoft_policy_registry =
        load_registry_map_or_empty(&hkcu_microsoft_policies_path, &mut evidence.artifact_paths);
    let hklm_microsoft_policy_registry =
        load_registry_map_or_empty(&hklm_microsoft_policies_path, &mut evidence.artifact_paths);

    evidence.policy_enabled = build_policy_value(
        current_policy_value(&current_registry, "UsePassportForWork"),
        provider_policy_value(&provider_registry, "UsePassportForWork"),
        machine_policy_value(
            &hklm_policy_registry,
            &hklm_microsoft_policy_registry,
            "UsePassportForWork",
        ),
        user_policy_value(
            &hkcu_policy_registry,
            &hkcu_microsoft_policy_registry,
            "UsePassportForWork",
        ),
        false,
    );
    evidence.post_logon_enabled = build_policy_value(
        current_policy_value(&current_registry, "DisablePostLogonProvisioning"),
        provider_policy_value(&provider_registry, "DisablePostLogonProvisioning"),
        machine_policy_value(
            &hklm_policy_registry,
            &hklm_microsoft_policy_registry,
            "DisablePostLogonProvisioning",
        ),
        user_policy_value(
            &hkcu_policy_registry,
            &hkcu_microsoft_policy_registry,
            "DisablePostLogonProvisioning",
        ),
        true,
    );
    evidence.pin_recovery_enabled = build_policy_value(
        current_policy_value(&current_registry, "EnablePinRecovery"),
        provider_policy_value(&provider_registry, "EnablePinRecovery"),
        machine_policy_value(
            &hklm_policy_registry,
            &hklm_microsoft_policy_registry,
            "EnablePinRecovery",
        ),
        user_policy_value(
            &hkcu_policy_registry,
            &hkcu_microsoft_policy_registry,
            "EnablePinRecovery",
        ),
        false,
    );
    evidence.require_security_device = build_policy_value(
        current_policy_value(&current_registry, "RequireSecurityDevice"),
        provider_policy_value(&provider_registry, "RequireSecurityDevice"),
        machine_policy_value(
            &hklm_policy_registry,
            &hklm_microsoft_policy_registry,
            "RequireSecurityDevice",
        ),
        user_policy_value(
            &hkcu_policy_registry,
            &hkcu_microsoft_policy_registry,
            "RequireSecurityDevice",
        ),
        false,
    );
    evidence.use_certificate_for_on_prem_auth = build_policy_value(
        current_policy_value(&current_registry, "UseCertificateForOnPremAuth"),
        provider_policy_value(&provider_registry, "UseCertificateForOnPremAuth"),
        machine_policy_value(
            &hklm_policy_registry,
            &hklm_microsoft_policy_registry,
            "UseCertificateForOnPremAuth",
        ),
        user_policy_value(
            &hkcu_policy_registry,
            &hkcu_microsoft_policy_registry,
            "UseCertificateForOnPremAuth",
        ),
        false,
    );
    evidence.use_cloud_trust_for_on_prem_auth = build_policy_value(
        current_policy_value(&current_registry, "UseCloudTrustForOnPremAuth"),
        provider_policy_value(&provider_registry, "UseCloudTrustForOnPremAuth"),
        machine_policy_value(
            &hklm_policy_registry,
            &hklm_microsoft_policy_registry,
            "UseCloudTrustForOnPremAuth",
        ),
        user_policy_value(
            &hkcu_policy_registry,
            &hkcu_microsoft_policy_registry,
            "UseCloudTrustForOnPremAuth",
        ),
        false,
    );

    annotate_missing_policy_evidence(&mut evidence);

    evidence
}

pub fn load_os_version_evidence(bundle_path: &Path) -> Option<DsregcmdOsVersionEvidence> {
    let path = registry_file_path(bundle_path, OS_VERSION_FILE);
    let registry = load_registry_map(&path)?;

    let mut evidence = DsregcmdOsVersionEvidence::default();
    for (key_path, values) in &registry {
        let lower = key_path.to_ascii_lowercase();
        if !lower.contains("\\windows nt\\currentversion") {
            continue;
        }
        evidence.current_build = extract_string_value(values, "CurrentBuild")
            .or_else(|| extract_string_value(values, "CurrentBuildNumber"));
        evidence.display_version = extract_string_value(values, "DisplayVersion");
        evidence.product_name = extract_string_value(values, "ProductName");
        evidence.ubr = extract_dword_value(values, "UBR");
        evidence.edition_id = extract_string_value(values, "EditionID");
        break;
    }

    Some(evidence)
}

pub fn load_proxy_evidence(bundle_path: &Path) -> Option<DsregcmdProxyEvidence> {
    let ie_path = registry_file_path(bundle_path, PROXY_INTERNET_SETTINGS_FILE);

    let ie_registry = load_registry_map(&ie_path)?;

    let mut evidence = DsregcmdProxyEvidence::default();

    for (key_path, values) in &ie_registry {
        let lower = key_path.to_ascii_lowercase();
        if !lower.contains("\\internet settings") {
            continue;
        }
        evidence.proxy_enabled = extract_dword_value(values, "ProxyEnable").map(|v| v != 0);
        evidence.proxy_server = extract_string_value(values, "ProxyServer");
        evidence.proxy_override = extract_string_value(values, "ProxyOverride");
        evidence.auto_config_url = extract_string_value(values, "AutoConfigURL");
        break;
    }

    if let Some(url) = &evidence.auto_config_url {
        evidence.wpad_detected = url.to_ascii_lowercase().contains("wpad");
    }

    Some(evidence)
}

/// Read the enrollments export.
///
/// The export is assessable only when it holds the Enrollments root key header
/// itself, `[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Enrollments]` (any letter
/// case); otherwise the evidence is not collected (`None`), never zero.
///
/// An enrollment is a GUID-shaped first path segment below that root, braced or
/// unbraced (Windows writes it unbraced). Each distinct GUID counts once,
/// whatever its values or its `EnrollmentState`:
/// - Non-GUID children such as `Context`, `Status` or `Ownership` are not
///   enrollments.
/// - A deeper key (`<guid>\FirstSync`, `<guid>\DMClient\...`) is not an
///   enrollment of its own, but it does show that its enrollment exists.
/// - Braced and unbraced forms of one GUID, in any letter case, are one
///   enrollment. It takes each value its keys agree on; a value they disagree
///   on stays unknown, so the order of the keys never changes the evidence.
///
/// Enrollments are counted from the key headers, not from the parsed values,
/// so an enrollment key with no named values (or only a default `@` value)
/// still counts. Over-counting only makes the negative rarer; an undercount
/// would read as "no enrollment" by mistake (#883).
pub fn load_enrollment_evidence(bundle_path: &Path) -> Option<DsregcmdEnrollmentEvidence> {
    let path = registry_file_path(bundle_path, ENROLLMENTS_FILE);
    let content = read_registry_export(&path)?;
    if !reg_key_headers(&content)
        .any(|key_path| key_path.eq_ignore_ascii_case(ENROLLMENTS_ROOT_KEY))
    {
        return None;
    }
    let registry = parse_reg_snapshot(&content);

    // Each distinct GUID in file order, with its name as first written.
    let mut seen = HashSet::new();
    let mut guids = Vec::new();
    for key_path in reg_key_headers(&content) {
        if let Some((_, segment, guid)) = enrollment_key_of(key_path) {
            let canonical = guid.to_ascii_lowercase();
            if seen.insert(canonical.clone()) {
                guids.push((canonical, segment));
            }
        }
    }

    // The named values of every first-level key of each GUID.
    let mut values_by_guid: HashMap<String, Vec<&HashMap<String, RegistryValue>>> = HashMap::new();
    for (key_path, values) in &registry {
        if let Some((enrollment_key, _, guid)) = enrollment_key_of(key_path) {
            if enrollment_key.len() == key_path.len() {
                values_by_guid
                    .entry(guid.to_ascii_lowercase())
                    .or_default()
                    .push(values);
            }
        }
    }

    let enrollments = guids
        .into_iter()
        .map(|(canonical, segment)| {
            let values = values_by_guid
                .get(&canonical)
                .map(Vec::as_slice)
                .unwrap_or_default();
            DsregcmdEnrollmentEntry {
                guid: Some(segment.to_string()),
                upn: agreed(values.iter().map(|v| extract_string_value(v, "UPN"))),
                provider_id: agreed(values.iter().map(|v| extract_string_value(v, "ProviderID"))),
                enrollment_state: agreed(
                    values
                        .iter()
                        .map(|v| extract_dword_value(v, "EnrollmentState")),
                ),
            }
        })
        .collect::<Vec<_>>();

    let enrollment_count = u32::try_from(enrollments.len()).unwrap_or(u32::MAX);

    Some(DsregcmdEnrollmentEvidence {
        enrollment_count,
        enrollments,
    })
}

/// The one value every present value agrees on: `None` when there is none or
/// when two of them differ, whatever their order.
fn agreed<T: PartialEq>(values: impl Iterator<Item = Option<T>>) -> Option<T> {
    let mut agreed = None;
    for value in values.flatten() {
        match &agreed {
            None => agreed = Some(value),
            Some(existing) if *existing == value => {}
            Some(_) => return None,
        }
    }
    agreed
}

const ENROLLMENTS_ROOT_KEY: &str = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Enrollments";

/// The enrollment a key path belongs to, for a key at or below a GUID-shaped
/// first segment under the Enrollments root: the path of that first-level key,
/// the segment as written, and its unbraced GUID. `None` for the root itself,
/// a non-GUID child, or any key outside the root.
fn enrollment_key_of(key_path: &str) -> Option<(&str, &str, &str)> {
    let root_len = ENROLLMENTS_ROOT_KEY.len();
    let below_root = key_path
        .get(..root_len)
        .filter(|root| root.eq_ignore_ascii_case(ENROLLMENTS_ROOT_KEY))
        .and_then(|_| key_path[root_len..].strip_prefix('\\'))?;
    let segment = below_root.split('\\').next()?;
    let guid = unbraced_guid(segment)?;
    Some((&key_path[..root_len + 1 + segment.len()], segment, guid))
}

/// Every `[...]` key header of a `.reg` export, in file order, including keys
/// that hold no named values (which `parse_reg_snapshot` leaves out).
fn reg_key_headers(content: &str) -> impl Iterator<Item = &str> {
    content.lines().filter_map(|line| {
        let line = line.trim();
        (line.starts_with('[') && line.ends_with(']') && line.len() >= 2)
            .then(|| line[1..line.len() - 1].trim())
    })
}

fn extract_string_value(
    values: &HashMap<String, RegistryValue>,
    value_name: &str,
) -> Option<String> {
    let key = value_name.to_ascii_lowercase();
    values.get(&key).map(|v| match v {
        RegistryValue::String(s) => s.clone(),
        RegistryValue::Dword(d) => d.to_string(),
    })
}

fn extract_dword_value(values: &HashMap<String, RegistryValue>, value_name: &str) -> Option<u32> {
    let key = value_name.to_ascii_lowercase();
    values.get(&key).and_then(|v| match v {
        RegistryValue::Dword(d) => Some(*d),
        RegistryValue::String(s) => {
            let trimmed = s.trim();
            if let Some(hex) = trimmed.strip_prefix("0x") {
                u32::from_str_radix(hex, 16).ok()
            } else {
                trimmed.parse().ok()
            }
        }
    })
}

fn annotate_missing_policy_evidence(evidence: &mut DsregcmdWhfbPolicyEvidence) {
    let has_artifacts = !evidence.artifact_paths.is_empty();
    if !has_artifacts {
        return;
    }

    let missing_note = Some(
        "Registry artifacts were captured, but no mapped PassportForWork policy values were present in this bundle.".to_string(),
    );

    for field in [
        &mut evidence.policy_enabled,
        &mut evidence.post_logon_enabled,
        &mut evidence.pin_recovery_enabled,
        &mut evidence.require_security_device,
        &mut evidence.use_certificate_for_on_prem_auth,
        &mut evidence.use_cloud_trust_for_on_prem_auth,
    ] {
        if field.display_value.is_none() && field.note.is_none() {
            field.note = missing_note.clone();
        }
    }
}

fn registry_file_path(bundle_path: &Path, file_name: &str) -> PathBuf {
    REGISTRY_FOLDER
        .iter()
        .fold(bundle_path.to_path_buf(), |path, segment| {
            path.join(segment)
        })
        .join(file_name)
}

/// Read and parse one `.reg` export.
///
/// `None` means the artifact was not collected: the file is absent, cannot be
/// read, or its decoded content holds no `[...]` key header at all (empty or
/// not a registry export). A coverage gap is not evidence of an empty registry
/// (#883), so callers must not turn `None` into a zero count. `Some` means the
/// content was a registry export; the map may still be empty when the exported
/// keys carry no named values, which keeps "exported, nothing relevant inside"
/// distinct from "not collected".
fn load_registry_map(path: &Path) -> Option<RegistryKeyMap> {
    read_registry_export(path).map(|content| parse_reg_snapshot(&content))
}

/// The decoded text of one `.reg` export, under the same "collected" rule as
/// [`load_registry_map`]: `None` unless the content holds a key header.
fn read_registry_export(path: &Path) -> Option<String> {
    if !path.is_file() {
        return None;
    }

    let content = fs::read_to_string(path).ok().or_else(|| {
        fs::read(path)
            .ok()
            .and_then(|bytes| decode_reg_content(&bytes))
    })?;

    let collected = reg_key_headers(&content).next().is_some();
    collected.then_some(content)
}

/// Like [`load_registry_map`] for the WHFB policy lookups, which merge several
/// optional exports. The artifact path is recorded only for a collected export,
/// so `artifact_paths` means "collected", never "attempted".
fn load_registry_map_or_empty(path: &Path, artifact_paths: &mut Vec<String>) -> RegistryKeyMap {
    match load_registry_map(path) {
        Some(registry) => {
            artifact_paths.push(path.to_string_lossy().to_string());
            registry
        }
        None => HashMap::new(),
    }
}

fn decode_reg_content(bytes: &[u8]) -> Option<String> {
    if bytes.starts_with(&[0xFF, 0xFE]) {
        let units = bytes[2..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|chunk| u16::from_le_bytes(*chunk))
            .collect::<Vec<u16>>();
        return Some(String::from_utf16_lossy(&units));
    }

    if bytes.starts_with(&[0xFE, 0xFF]) {
        let units = bytes[2..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|chunk| u16::from_be_bytes(*chunk))
            .collect::<Vec<u16>>();
        return Some(String::from_utf16_lossy(&units));
    }

    match String::from_utf8(bytes.to_vec()) {
        Ok(content) => Some(content),
        Err(_) => {
            let (content, _, _) = encoding_rs::WINDOWS_1252.decode(bytes);
            Some(content.into_owned())
        }
    }
}

fn build_registry_snapshot_summary(registry: &RegistryKeyMap) -> RegistrySnapshotSummary {
    let mut keys = registry.iter().collect::<Vec<_>>();
    keys.sort_by(|left, right| left.0.cmp(right.0));

    let key_count = u32::try_from(keys.len()).unwrap_or(u32::MAX);
    let value_count = u32::try_from(registry.values().map(|values| values.len()).sum::<usize>())
        .unwrap_or(u32::MAX);

    let keys = keys
        .into_iter()
        .take(6)
        .map(|(path, values)| {
            let mut values = values.iter().collect::<Vec<_>>();
            values.sort_by(|left, right| left.0.cmp(right.0));

            RegistrySnapshotKeyPreview {
                path: path.clone(),
                value_count: u32::try_from(values.len()).unwrap_or(u32::MAX),
                values: values
                    .into_iter()
                    .take(8)
                    .map(|(name, value)| {
                        let (value_type, rendered_value) = render_registry_value(value);
                        RegistrySnapshotValuePreview {
                            name: name.clone(),
                            value_type,
                            value: rendered_value,
                        }
                    })
                    .collect(),
            }
        })
        .collect();

    RegistrySnapshotSummary {
        key_count,
        value_count,
        keys,
    }
}

fn render_registry_value(value: &RegistryValue) -> (String, String) {
    match value {
        RegistryValue::Dword(raw) => ("dword".to_string(), format!("0x{raw:08X} ({raw})")),
        RegistryValue::String(raw) => ("string".to_string(), raw.clone()),
    }
}

fn current_policy_value(registry: &RegistryKeyMap, value_name: &str) -> Option<bool> {
    policy_value_from_keys(registry, value_name, |path| {
        let normalized = path.to_ascii_lowercase();
        normalized.contains("\\policymanager\\current\\device\\")
            && normalized.contains("\\passportforwork")
            && normalized.contains("\\policies")
    })
}

fn provider_policy_value(registry: &RegistryKeyMap, value_name: &str) -> Option<bool> {
    policy_value_from_keys(registry, value_name, |path| {
        let normalized = path.to_ascii_lowercase();
        normalized.contains("\\policymanager\\providers\\")
            && normalized.contains("\\default\\device\\")
            && normalized.contains("\\passportforwork")
            && normalized.contains("\\policies")
    })
}

fn machine_policy_value(
    policy_registry: &RegistryKeyMap,
    microsoft_policy_registry: &RegistryKeyMap,
    value_name: &str,
) -> Option<bool> {
    policy_value_from_keys(policy_registry, value_name, |path| {
        let normalized = path.to_ascii_lowercase();
        normalized.contains("\\software\\policies\\microsoft\\passportforwork")
            || normalized.contains("\\software\\policies\\passportforwork")
    })
    .or_else(|| {
        policy_value_from_keys(microsoft_policy_registry, value_name, |path| {
            path.to_ascii_lowercase()
                .contains("\\software\\microsoft\\policies\\passportforwork")
        })
    })
}

fn user_policy_value(
    policy_registry: &RegistryKeyMap,
    microsoft_policy_registry: &RegistryKeyMap,
    value_name: &str,
) -> Option<bool> {
    policy_value_from_keys(policy_registry, value_name, |path| {
        let normalized = path.to_ascii_lowercase();
        normalized.contains("\\software\\policies\\microsoft\\passportforwork")
            || normalized.contains("\\software\\policies\\passportforwork")
    })
    .or_else(|| {
        policy_value_from_keys(microsoft_policy_registry, value_name, |path| {
            path.to_ascii_lowercase()
                .contains("\\software\\microsoft\\policies\\passportforwork")
        })
    })
}

fn policy_value_from_keys(
    registry: &RegistryKeyMap,
    value_name: &str,
    matches_key: impl Fn(&str) -> bool,
) -> Option<bool> {
    let value_name = value_name.to_ascii_lowercase();

    registry.iter().find_map(|(path, values)| {
        if !matches_key(path) {
            return None;
        }

        values.get(&value_name).and_then(parse_registry_bool)
    })
}

fn build_policy_value(
    current_value: Option<bool>,
    provider_value: Option<bool>,
    machine_policy_value: Option<bool>,
    user_policy_value: Option<bool>,
    invert: bool,
) -> DsregcmdPolicyEvidenceValue {
    let adjusted_current = current_value.map(|value| if invert { !value } else { value });
    let adjusted_provider = provider_value.map(|value| if invert { !value } else { value });
    let adjusted_machine = machine_policy_value.map(|value| if invert { !value } else { value });
    let adjusted_user = user_policy_value.map(|value| if invert { !value } else { value });

    let (display_value, source, note) = match (adjusted_current, adjusted_provider) {
        (Some(current), Some(provider)) if current == provider => (
            Some(current),
            Some(DsregcmdEvidenceSource::PolicyManagerComparison),
            Some("PolicyManager current state and provider state agree.".to_string()),
        ),
        (Some(current), Some(provider)) => (
            Some(current),
            Some(DsregcmdEvidenceSource::PolicyManagerCurrent),
            Some(format!(
                "Policy delivered but not effective. Provider state says {} while current effective state says {}.",
                format_bool(provider),
                format_bool(current)
            )),
        ),
        (Some(current), None) => (
            Some(current),
            Some(DsregcmdEvidenceSource::PolicyManagerCurrent),
            None,
        ),
        (None, Some(provider)) => (
            Some(provider),
            Some(DsregcmdEvidenceSource::PolicyManagerProvider),
            Some("Only provider-delivered policy was available, so this may not reflect the current effective state yet.".to_string()),
        ),
        (None, None) => match (adjusted_machine, adjusted_user) {
            (Some(machine), _) => (
                Some(machine),
                Some(DsregcmdEvidenceSource::WindowsPolicyMachine),
                Some("Derived from the exported Windows machine policy hive.".to_string()),
            ),
            (None, Some(user)) => (
                Some(user),
                Some(DsregcmdEvidenceSource::WindowsPolicyUser),
                Some("Derived from the exported Windows user policy hive.".to_string()),
            ),
            (None, None) => (None, None, None),
        },
    };

    DsregcmdPolicyEvidenceValue {
        display_value,
        current_value: adjusted_current,
        provider_value: adjusted_provider,
        source,
        note,
    }
}

fn format_bool(value: bool) -> &'static str {
    if value {
        "Yes"
    } else {
        "No"
    }
}

fn parse_reg_snapshot(content: &str) -> RegistryKeyMap {
    let mut registry = HashMap::new();
    let mut current_key: Option<String> = None;

    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with("Windows Registry Editor") {
            continue;
        }

        if line.starts_with('[') && line.ends_with(']') {
            current_key = Some(line[1..line.len() - 1].trim().to_string());
            continue;
        }

        let Some(key_path) = current_key.as_ref() else {
            continue;
        };
        let Some((value_name, value)) = parse_reg_value(line) else {
            continue;
        };

        registry
            .entry(key_path.clone())
            .or_insert_with(HashMap::new)
            .insert(value_name.to_ascii_lowercase(), value);
    }

    registry
}

fn parse_reg_value(line: &str) -> Option<(String, RegistryValue)> {
    let (name, value) = line.split_once('=')?;
    let normalized_name = name.trim().trim_matches('"');
    if normalized_name.is_empty() || normalized_name == "@" {
        return None;
    }

    let value = parse_registry_value(value.trim())?;
    Some((normalized_name.to_string(), value))
}

fn parse_registry_value(value: &str) -> Option<RegistryValue> {
    if let Some(raw_value) = value.strip_prefix("dword:") {
        let parsed = u32::from_str_radix(raw_value.trim(), 16).ok()?;
        return Some(RegistryValue::Dword(parsed));
    }

    if value.starts_with('"') && value.ends_with('"') && value.len() >= 2 {
        return Some(RegistryValue::String(
            value[1..value.len() - 1]
                .replace("\\\\", "\\")
                .replace("\\\"", "\""),
        ));
    }

    Some(RegistryValue::String(value.to_string()))
}

fn parse_registry_bool(value: &RegistryValue) -> Option<bool> {
    match value {
        RegistryValue::Dword(raw) => Some(*raw != 0),
        RegistryValue::String(raw) => match raw.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" => Some(true),
            "0" | "false" | "no" => Some(false),
            _ => None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::{
        decode_reg_content, inspect_registry_snapshot_file, load_enrollment_evidence,
        load_os_version_evidence, load_proxy_evidence, load_whfb_policy_evidence,
        parse_reg_snapshot,
    };
    use crate::dsregcmd::models::{
        DsregcmdEnrollmentEntry, DsregcmdEnrollmentEvidence, DsregcmdEvidenceSource,
    };
    use std::collections::HashMap;

    use super::{extract_dword_value, RegistryValue};

    fn bundle_with_enrollments_export(bytes: &[u8]) -> tempfile::TempDir {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let registry_dir = temp_dir.path().join("evidence").join("registry");
        std::fs::create_dir_all(&registry_dir).expect("create registry dir");
        std::fs::write(registry_dir.join("enrollments.reg"), bytes).expect("write export");
        temp_dir
    }

    const ROOT: &str = r"[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Enrollments]";

    fn export_with_root(body: &str) -> String {
        format!("Windows Registry Editor Version 5.00\r\n\r\n{ROOT}\r\n\r\n{body}")
    }

    /// `reg export` writes UTF-16LE with a byte order mark and CRLF lines.
    fn utf16le_export(text: &str) -> Vec<u8> {
        let mut bytes = vec![0xFF, 0xFE];
        for unit in text
            .replace("\r\n", "\n")
            .replace('\n', "\r\n")
            .encode_utf16()
        {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        bytes
    }

    fn collected(export: &str) -> DsregcmdEnrollmentEvidence {
        let bundle = bundle_with_enrollments_export(export.as_bytes());
        let evidence = load_enrollment_evidence(bundle.path()).expect("export was collected");
        assert_eq!(
            usize::try_from(evidence.enrollment_count).expect("count fits"),
            evidence.enrollments.len(),
            "the count and the list never disagree"
        );
        evidence
    }

    fn guids(evidence: &DsregcmdEnrollmentEvidence) -> Vec<&str> {
        evidence
            .enrollments
            .iter()
            .map(|entry| {
                entry
                    .guid
                    .as_deref()
                    .expect("every enrollment carries its GUID")
            })
            .collect()
    }

    /// #883: a present export that yields no registry keys was not read, so it
    /// is a coverage gap (`None`), never "zero enrollments".
    #[test]
    fn enrollments_export_empty_is_not_collected() {
        let bundle = bundle_with_enrollments_export(b"");
        assert_eq!(load_enrollment_evidence(bundle.path()), None);
    }

    #[test]
    fn enrollments_export_undecodable_is_not_collected() {
        let bundle = bundle_with_enrollments_export(&[0xFF, 0xFE, 0x00, 0xD8, 0x01, 0x00, 0xFF]);
        assert_eq!(load_enrollment_evidence(bundle.path()), None);

        let bundle = bundle_with_enrollments_export(&[0x80, 0x81, 0x9D, 0xFF, 0x00, 0xC3]);
        assert_eq!(load_enrollment_evidence(bundle.path()), None);
    }

    #[cfg(unix)]
    #[test]
    fn enrollments_export_unreadable_is_not_collected() {
        use std::os::unix::fs::PermissionsExt;

        let bundle = bundle_with_enrollments_export(export_with_root("").as_bytes());
        let file = bundle
            .path()
            .join("evidence")
            .join("registry")
            .join("enrollments.reg");
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o000))
            .expect("remove permissions");
        // A privileged runner can still read the file, which is not a gap.
        if std::fs::read(&file).is_ok() {
            return;
        }
        assert_eq!(load_enrollment_evidence(bundle.path()), None);
    }

    /// The root key header is what makes the export assessable. An export
    /// that holds other keys, or only enrollment subkeys, is not collected.
    #[test]
    fn enrollments_export_without_root_header_is_not_collected() {
        for export in [
            "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Provisioning]\r\n\"Value\"=dword:00000001\r\n",
            "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Enrollments\\AAAAAAAA-1111-2222-3333-BBBBBBBBBBBB]\r\n\"EnrollmentState\"=dword:00000001\r\n",
            "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Enrollments]\r\n",
        ] {
            let bundle = bundle_with_enrollments_export(export.as_bytes());
            assert_eq!(load_enrollment_evidence(bundle.path()), None, "{export}");
        }

        // The root header matches in any letter case.
        let lower_case_root = export_with_root("").to_ascii_lowercase();
        assert_eq!(collected(&lower_case_root).enrollment_count, 0);
    }

    /// A root export with no GUID subkeys is real registry evidence, whatever
    /// shape a key without enrollments takes.
    #[test]
    fn enrollments_export_root_without_guid_subkeys_is_zero() {
        for export in [
            export_with_root(""),
            export_with_root(
                "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Enrollments\\Context]\r\n\r\n[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Enrollments\\Status]\r\n",
            ),
            format!("Windows Registry Editor Version 5.00\r\n\r\n{ROOT}\r\n@=\"\"\r\n"),
        ] {
            let evidence = collected(&export);
            assert_eq!(evidence.enrollment_count, 0);
            assert!(evidence.enrollments.is_empty());
        }
    }

    /// Windows names the enrollment subkeys with the unbraced GUID (an enrolled
    /// device recorded 2026-07-23, and the ESP corpus at
    /// `crates/cmtraceopen-parser/tests/fixtures/esp/edge-cases.json`). The
    /// GUIDs and values here are synthetic.
    #[test]
    fn enrollments_export_unbraced_guid_subkey_is_counted() {
        let export = utf16le_export(&export_with_root(
            r#"[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Enrollments\Context]
"LastLoggedOnUserSID"="S-1-5-21-0-0-0-1001"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Enrollments\Ownership]
"CorrelationID"="00000000-0000-0000-0000-000000000000"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Enrollments\Status]

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Enrollments\AAAAAAAA-1111-2222-3333-BBBBBBBBBBBB]
"EnrollmentState"=dword:00000001
"EnrollmentType"=dword:00000006
"ProviderID"="MS DM Server"
"UPN"="user@contoso.test"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Enrollments\AAAAAAAA-1111-2222-3333-BBBBBBBBBBBB\DMClient]

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Enrollments\AAAAAAAA-1111-2222-3333-BBBBBBBBBBBB\DMClient\MS DM Server]
"EntDMID"="11111111-0000-0000-0000-000000000000"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Enrollments\AAAAAAAA-1111-2222-3333-BBBBBBBBBBBB\FirstSync]
"SkipDeviceStatusPage"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Enrollments\cccccccc-4444-5555-6666-dddddddddddd]
"EnrollmentState"=dword:00000006
"ProviderID"="MS DM Server"
"#,
        ));
        let bundle = bundle_with_enrollments_export(&export);

        let evidence = load_enrollment_evidence(bundle.path()).expect("export was collected");
        assert_eq!(evidence.enrollment_count, 2);
        assert_eq!(
            evidence.enrollments,
            [
                DsregcmdEnrollmentEntry {
                    guid: Some("AAAAAAAA-1111-2222-3333-BBBBBBBBBBBB".to_string()),
                    upn: Some("user@contoso.test".to_string()),
                    provider_id: Some("MS DM Server".to_string()),
                    enrollment_state: Some(1),
                },
                DsregcmdEnrollmentEntry {
                    guid: Some("cccccccc-4444-5555-6666-dddddddddddd".to_string()),
                    upn: None,
                    provider_id: Some("MS DM Server".to_string()),
                    enrollment_state: Some(6),
                },
            ]
        );
    }

    #[test]
    fn enrollments_export_braced_and_unbraced_guid_subkeys_are_counted() {
        let evidence = collected(&export_with_root(
            r#"[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Enrollments\{11111111-2222-3333-4444-555555555555}]
"EnrollmentState"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Enrollments\66666666-7777-8888-9999-AAAAAAAAAAAA]
"EnrollmentState"=dword:00000001
"#,
        ));

        assert_eq!(
            guids(&evidence),
            [
                "{11111111-2222-3333-4444-555555555555}",
                "66666666-7777-8888-9999-AAAAAAAAAAAA"
            ]
        );
    }

    /// An enrollment key with no named values, or only a default `@` value, is
    /// still an enrollment, and so is one that only a deeper key header names.
    /// Leaving any of them out would undercount toward "no enrollment".
    #[test]
    fn enrollments_export_guid_subkey_without_named_values_is_counted() {
        let no_values = "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Enrollments\\AAAAAAAA-1111-2222-3333-BBBBBBBBBBBB]\r\n";
        let default_only = "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Enrollments\\AAAAAAAA-1111-2222-3333-BBBBBBBBBBBB]\r\n@=\"\"\r\n";
        let deeper_only = "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Enrollments\\AAAAAAAA-1111-2222-3333-BBBBBBBBBBBB\\FirstSync]\r\n\"SkipDeviceStatusPage\"=dword:00000000\r\n";

        for body in [no_values, default_only, deeper_only] {
            let evidence = collected(&export_with_root(body));
            assert_eq!(
                evidence.enrollments,
                [DsregcmdEnrollmentEntry {
                    guid: Some("AAAAAAAA-1111-2222-3333-BBBBBBBBBBBB".to_string()),
                    upn: None,
                    provider_id: None,
                    enrollment_state: None,
                }],
                "{body}"
            );
        }
    }

    /// Braced and unbraced forms of one GUID, in any letter case, and its
    /// deeper keys are one enrollment. It keeps the values its keys agree on
    /// and leaves a value they disagree on unknown, so the order of the keys
    /// never changes the evidence.
    #[test]
    fn enrollments_export_guid_variants_count_once() {
        let unbraced_state_1 = "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Enrollments\\AAAAAAAA-1111-2222-3333-BBBBBBBBBBBB]\r\n\"EnrollmentState\"=dword:00000001\r\n\"ProviderID\"=\"MS DM Server\"\r\n\r\n";
        let braced_state_6 = "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Enrollments\\{aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb}]\r\n\"EnrollmentState\"=dword:00000006\r\n\"ProviderID\"=\"MS DM Server\"\r\n\r\n";
        let braced_no_values = "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Enrollments\\{aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb}]\r\n\r\n";
        let lower_case_deeper = "[hkey_local_machine\\software\\microsoft\\enrollments\\aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb\\DMClient]\r\n\r\n";

        // The keys disagree on EnrollmentState, so it is unknown in either order.
        for body in [
            format!("{unbraced_state_1}{braced_state_6}{lower_case_deeper}"),
            format!("{lower_case_deeper}{braced_state_6}{unbraced_state_1}"),
        ] {
            let evidence = collected(&export_with_root(&body));
            assert_eq!(evidence.enrollment_count, 1, "{body}");
            assert_eq!(evidence.enrollments[0].enrollment_state, None, "{body}");
            assert_eq!(
                evidence.enrollments[0].provider_id.as_deref(),
                Some("MS DM Server"),
                "{body}"
            );
        }

        // A key without the value does not disagree with one that has it.
        for body in [
            format!("{unbraced_state_1}{braced_no_values}"),
            format!("{braced_no_values}{unbraced_state_1}"),
        ] {
            let evidence = collected(&export_with_root(&body));
            assert_eq!(evidence.enrollment_count, 1, "{body}");
            assert_eq!(evidence.enrollments[0].enrollment_state, Some(1), "{body}");
        }
    }

    /// A deeper key's values are not its enrollment's values: only the
    /// first-level GUID key supplies UPN, ProviderID and EnrollmentState.
    #[test]
    fn enrollments_export_deeper_key_values_are_not_the_enrollments() {
        let evidence = collected(&export_with_root(
            r#"[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Enrollments\AAAAAAAA-1111-2222-3333-BBBBBBBBBBBB]
"EnrollmentState"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Enrollments\AAAAAAAA-1111-2222-3333-BBBBBBBBBBBB\DMClient\MS DM Server]
"EnrollmentState"=dword:00000006
"UPN"="deeper@contoso.test"
"ProviderID"="Deeper Provider"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Enrollments\CCCCCCCC-4444-5555-6666-DDDDDDDDDDDD\FirstSync]
"EnrollmentState"=dword:00000001
"UPN"="first-sync@contoso.test"
"#,
        ));

        assert_eq!(
            evidence.enrollments,
            [
                DsregcmdEnrollmentEntry {
                    guid: Some("AAAAAAAA-1111-2222-3333-BBBBBBBBBBBB".to_string()),
                    upn: None,
                    provider_id: None,
                    enrollment_state: Some(1),
                },
                DsregcmdEnrollmentEntry {
                    guid: Some("CCCCCCCC-4444-5555-6666-DDDDDDDDDDDD".to_string()),
                    upn: None,
                    provider_id: None,
                    enrollment_state: None,
                },
            ]
        );
    }

    #[test]
    fn enrollments_export_malformed_or_outside_keys_are_not_enrollments() {
        let evidence = collected(&export_with_root(
            r#"[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Enrollments\{1234}]
"EnrollmentState"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Enrollments\AAAAAAAA-1111-2222-3333-BBBBBBBBBBB]
"EnrollmentState"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Enrollments\{AAAAAAAA-1111-2222-3333-BBBBBBBBBBBB]
"EnrollmentState"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\EnrollmentsBackup\AAAAAAAA-1111-2222-3333-BBBBBBBBBBBB]
"EnrollmentState"=dword:00000001

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Enrollments\AAAAAAAA-1111-2222-3333-BBBBBBBBBBBB]
"EnrollmentState"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Provisioning\AAAAAAAA-1111-2222-3333-BBBBBBBBBBBB]
"EnrollmentState"=dword:00000001
"#,
        ));

        assert_eq!(evidence.enrollment_count, 0);
        assert!(evidence.enrollments.is_empty());
    }

    #[test]
    fn unreadable_policy_exports_are_not_recorded_as_artifacts() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let registry_dir = temp_dir.path().join("evidence").join("registry");
        std::fs::create_dir_all(&registry_dir).expect("create registry dir");
        std::fs::write(registry_dir.join("policymanager-device.reg"), b"").expect("write");
        std::fs::write(registry_dir.join("os-version.reg"), b"").expect("write");
        std::fs::write(registry_dir.join("proxy-internet-settings.reg"), b"").expect("write");

        assert!(load_whfb_policy_evidence(temp_dir.path())
            .artifact_paths
            .is_empty());
        assert_eq!(load_os_version_evidence(temp_dir.path()), None);
        assert_eq!(load_proxy_evidence(temp_dir.path()), None);
    }

    #[test]
    fn parses_registry_snapshot_values() {
        let sample = r#"Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\Current\Device\PassportForWork\Policies]
"UsePassportForWork"=dword:00000001
"DisablePostLogonProvisioning"=dword:00000000
"EnablePinRecovery"=dword:00000001
"#;

        let registry = parse_reg_snapshot(sample);
        assert_eq!(registry.len(), 1);
        let key = registry
            .keys()
            .next()
            .expect("expected a parsed registry key");
        assert!(key.contains("PassportForWork"));
    }

    #[test]
    fn derives_whfb_policy_evidence_from_bundle_files() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let registry_dir = temp_dir.path().join("evidence").join("registry");
        std::fs::create_dir_all(&registry_dir).expect("create registry dir");

        std::fs::write(
            registry_dir.join("policymanager-device.reg"),
            r#"Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\Current\Device\PassportForWork\Policies]
"UsePassportForWork"=dword:00000001
"DisablePostLogonProvisioning"=dword:00000001
"EnablePinRecovery"=dword:00000000
"#,
        )
        .expect("write current registry sample");

        std::fs::write(
            registry_dir.join("policymanager-providers.reg"),
            r#"Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\Providers\{11111111-1111-1111-1111-111111111111}\default\Device\PassportForWork\Policies]
"UsePassportForWork"=dword:00000001
"DisablePostLogonProvisioning"=dword:00000000
"#,
        )
        .expect("write provider registry sample");

        let evidence = load_whfb_policy_evidence(temp_dir.path());
        assert_eq!(evidence.policy_enabled.display_value, Some(true));
        assert_eq!(
            evidence.policy_enabled.source,
            Some(DsregcmdEvidenceSource::PolicyManagerComparison)
        );
        assert_eq!(evidence.post_logon_enabled.display_value, Some(false));
        assert_eq!(
            evidence.post_logon_enabled.source,
            Some(DsregcmdEvidenceSource::PolicyManagerCurrent)
        );
        assert!(evidence
            .post_logon_enabled
            .note
            .as_deref()
            .unwrap_or_default()
            .contains("Policy delivered but not effective"));
        assert_eq!(evidence.pin_recovery_enabled.display_value, Some(false));
    }

    #[test]
    fn decodes_utf16le_reg_exports() {
        let utf16 = vec![
            0xFF, 0xFE, 0x57, 0x00, 0x69, 0x00, 0x6E, 0x00, 0x64, 0x00, 0x6F, 0x00, 0x77, 0x00,
            0x73, 0x00,
        ];
        let decoded = decode_reg_content(&utf16).expect("decode utf16 reg export");
        assert_eq!(decoded, "Windows");
    }

    #[test]
    fn decodes_windows_1252_reg_exports() {
        let decoded = decode_reg_content(b"Windows\x80").expect("decode Windows-1252 reg export");
        assert_eq!(decoded, "Windows€");
    }

    #[test]
    fn inspects_registry_snapshot_file_summary() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let path = temp_dir.path().join("snapshot.reg");
        std::fs::write(
            &path,
            r#"Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\Current\Device\PassportForWork\Policies]
"UsePassportForWork"=dword:00000001
"TenantName"="Contoso"
"#,
        )
        .expect("write registry snapshot");

        let summary = inspect_registry_snapshot_file(&path).expect("registry summary");
        assert_eq!(summary.key_count, 1);
        assert_eq!(summary.value_count, 2);
        assert!(summary
            .keys
            .first()
            .expect("key preview")
            .path
            .contains("PassportForWork"));
    }

    #[test]
    fn falls_back_to_windows_policy_hive_values() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let registry_dir = temp_dir.path().join("evidence").join("registry");
        std::fs::create_dir_all(&registry_dir).expect("create registry dir");

        let utf16_content = "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Policies\\PassportForWork]\r\n\"UsePassportForWork\"=dword:00000001\r\n\"DisablePostLogonProvisioning\"=dword:00000000\r\n";
        let mut bytes = vec![0xFF, 0xFE];
        for unit in utf16_content.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }

        std::fs::write(registry_dir.join("hklm-microsoft-policies.reg"), bytes)
            .expect("write hklm policies sample");

        let evidence = load_whfb_policy_evidence(temp_dir.path());
        assert_eq!(evidence.policy_enabled.display_value, Some(true));
        assert_eq!(
            evidence.policy_enabled.source,
            Some(DsregcmdEvidenceSource::WindowsPolicyMachine)
        );
        assert_eq!(evidence.post_logon_enabled.display_value, Some(true));
    }

    #[test]
    fn loads_os_version_evidence_from_bundle() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let registry_dir = temp_dir.path().join("evidence").join("registry");
        std::fs::create_dir_all(&registry_dir).expect("create registry dir");

        std::fs::write(
            registry_dir.join("os-version.reg"),
            r#"Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion]
"CurrentBuild"="22631"
"DisplayVersion"="23H2"
"ProductName"="Windows 11 Enterprise"
"UBR"=dword:00000FA0
"EditionID"="Enterprise"
"#,
        )
        .expect("write os version sample");

        let evidence = load_os_version_evidence(temp_dir.path()).expect("os version evidence");
        assert_eq!(evidence.current_build.as_deref(), Some("22631"));
        assert_eq!(evidence.display_version.as_deref(), Some("23H2"));
        assert_eq!(
            evidence.product_name.as_deref(),
            Some("Windows 11 Enterprise")
        );
        assert_eq!(evidence.ubr, Some(4000));
        assert_eq!(evidence.edition_id.as_deref(), Some("Enterprise"));
    }

    #[test]
    fn returns_none_when_os_version_file_missing() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        assert!(load_os_version_evidence(temp_dir.path()).is_none());
    }

    #[test]
    fn loads_proxy_evidence_from_bundle() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let registry_dir = temp_dir.path().join("evidence").join("registry");
        std::fs::create_dir_all(&registry_dir).expect("create registry dir");

        std::fs::write(
            registry_dir.join("proxy-internet-settings.reg"),
            r#"Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings]
"ProxyEnable"=dword:00000001
"ProxyServer"="http://proxy.contoso.com:8080"
"ProxyOverride"="*.contoso.com;localhost"
"AutoConfigURL"="http://wpad.contoso.com/wpad.dat"
"#,
        )
        .expect("write proxy sample");

        let evidence = load_proxy_evidence(temp_dir.path()).expect("proxy evidence");
        assert_eq!(evidence.proxy_enabled, Some(true));
        assert_eq!(
            evidence.proxy_server.as_deref(),
            Some("http://proxy.contoso.com:8080")
        );
        assert!(evidence.wpad_detected);
    }

    #[test]
    fn enrollments_export_braced_guid_subkeys_are_counted() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let registry_dir = temp_dir.path().join("evidence").join("registry");
        std::fs::create_dir_all(&registry_dir).expect("create registry dir");

        std::fs::write(
            registry_dir.join("enrollments.reg"),
            r#"Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Enrollments]

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Enrollments\{11111111-2222-3333-4444-555555555555}]
"UPN"="user@contoso.com"
"ProviderID"="MS DM Server"
"EnrollmentState"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Enrollments\{11111111-2222-3333-4444-555555555555}\FirstSync]
"SyncComplete"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Enrollments\{22222222-3333-4444-5555-666666666666}]
"UPN"="admin@contoso.com"
"ProviderID"="MS DM Server"
"EnrollmentState"=dword:00000001
"#,
        )
        .expect("write enrollments sample");

        let evidence = load_enrollment_evidence(temp_dir.path()).expect("enrollment evidence");
        assert_eq!(evidence.enrollment_count, 2);
        assert_eq!(evidence.enrollments.len(), 2);
        assert!(evidence
            .enrollments
            .iter()
            .any(|e| e.upn.as_deref() == Some("user@contoso.com")));

        // Verify GUID extraction
        let user_entry = evidence
            .enrollments
            .iter()
            .find(|e| e.upn.as_deref() == Some("user@contoso.com"))
            .expect("user enrollment entry");
        assert_eq!(
            user_entry.guid.as_deref(),
            Some("{11111111-2222-3333-4444-555555555555}")
        );

        let admin_entry = evidence
            .enrollments
            .iter()
            .find(|e| e.upn.as_deref() == Some("admin@contoso.com"))
            .expect("admin enrollment entry");
        assert_eq!(
            admin_entry.guid.as_deref(),
            Some("{22222222-3333-4444-5555-666666666666}")
        );
    }
    #[test]
    fn parses_escaped_quotes_in_registry_strings() {
        let sample = r#"[HKEY_LOCAL_MACHINE\SOFTWARE\Test]
"Value"="C:\\path with \"quotes\""
"#;
        let registry = parse_reg_snapshot(sample);
        let values = registry
            .get(r"HKEY_LOCAL_MACHINE\SOFTWARE\Test")
            .expect("expected parsed key");
        match values.get("value") {
            Some(RegistryValue::String(value)) => {
                assert_eq!(value, r#"C:\path with "quotes""#);
            }
            other => panic!("expected string value, got {other:?}"),
        }
    }
    #[test]
    fn preserves_literal_backslashes_before_escaped_quotes() {
        // Encodes C:\dir + two literal backslashes + "quoted": the .reg
        // escape chain is \\ for each literal backslash and \" for the quote.
        let sample = r#"[HKEY_LOCAL_MACHINE\SOFTWARE\Test]
"Value"="C:\\dir\\\\\"quoted\""
"#;
        let registry = parse_reg_snapshot(sample);
        let values = registry
            .get(r"HKEY_LOCAL_MACHINE\SOFTWARE\Test")
            .expect("expected parsed key");
        match values.get("value") {
            Some(RegistryValue::String(value)) => {
                assert_eq!(value, r#"C:\dir\\"quoted""#);
            }
            other => panic!("expected string value, got {other:?}"),
        }
    }

    #[test]
    fn extracts_dword_from_hex_string() {
        let mut values = HashMap::new();
        values.insert(
            "ubr".to_string(),
            RegistryValue::String("0x00000FA0".to_string()),
        );
        assert_eq!(extract_dword_value(&values, "UBR"), Some(4000));
    }

    #[test]
    fn annotates_missing_note_on_all_policy_fields() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let registry_dir = temp_dir.path().join("evidence").join("registry");
        std::fs::create_dir_all(&registry_dir).expect("create registry dir");

        std::fs::write(
            registry_dir.join("policymanager-device.reg"),
            r#"Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\Current\Device\SomeOtherPolicy]
"Value"=dword:00000001
"#,
        )
        .expect("write registry sample");

        let evidence = load_whfb_policy_evidence(temp_dir.path());
        for field in [
            &evidence.policy_enabled,
            &evidence.post_logon_enabled,
            &evidence.pin_recovery_enabled,
            &evidence.require_security_device,
            &evidence.use_certificate_for_on_prem_auth,
            &evidence.use_cloud_trust_for_on_prem_auth,
        ] {
            assert!(
                field.note.is_some(),
                "missing-note annotation should cover every policy field"
            );
        }
    }
}
