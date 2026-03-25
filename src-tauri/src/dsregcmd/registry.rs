use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

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
const PROXY_CONNECTIONS_FILE: &str = "proxy-connections.reg";
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
    let content = fs::read_to_string(path)
        .ok()
        .or_else(|| fs::read(path).ok().and_then(|bytes| decode_reg_content(&bytes)))?;
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

    let current_registry = load_registry_map(&current_path, &mut evidence.artifact_paths);
    let provider_registry = load_registry_map(&provider_path, &mut evidence.artifact_paths);
    let hkcu_policy_registry = load_registry_map(&hkcu_policies_path, &mut evidence.artifact_paths);
    let hklm_policy_registry = load_registry_map(&hklm_policies_path, &mut evidence.artifact_paths);
    let hkcu_microsoft_policy_registry =
        load_registry_map(&hkcu_microsoft_policies_path, &mut evidence.artifact_paths);
    let hklm_microsoft_policy_registry =
        load_registry_map(&hklm_microsoft_policies_path, &mut evidence.artifact_paths);

    evidence.policy_enabled = build_policy_value(
        current_policy_value(&current_registry, "UsePassportForWork"),
        provider_policy_value(&provider_registry, "UsePassportForWork"),
        machine_policy_value(&hklm_policy_registry, &hklm_microsoft_policy_registry, "UsePassportForWork"),
        user_policy_value(&hkcu_policy_registry, &hkcu_microsoft_policy_registry, "UsePassportForWork"),
        false,
    );
    evidence.post_logon_enabled = build_policy_value(
        current_policy_value(&current_registry, "DisablePostLogonProvisioning"),
        provider_policy_value(&provider_registry, "DisablePostLogonProvisioning"),
        machine_policy_value(&hklm_policy_registry, &hklm_microsoft_policy_registry, "DisablePostLogonProvisioning"),
        user_policy_value(&hkcu_policy_registry, &hkcu_microsoft_policy_registry, "DisablePostLogonProvisioning"),
        true,
    );
    evidence.pin_recovery_enabled = build_policy_value(
        current_policy_value(&current_registry, "EnablePinRecovery"),
        provider_policy_value(&provider_registry, "EnablePinRecovery"),
        machine_policy_value(&hklm_policy_registry, &hklm_microsoft_policy_registry, "EnablePinRecovery"),
        user_policy_value(&hkcu_policy_registry, &hkcu_microsoft_policy_registry, "EnablePinRecovery"),
        false,
    );
    evidence.require_security_device = build_policy_value(
        current_policy_value(&current_registry, "RequireSecurityDevice"),
        provider_policy_value(&provider_registry, "RequireSecurityDevice"),
        machine_policy_value(&hklm_policy_registry, &hklm_microsoft_policy_registry, "RequireSecurityDevice"),
        user_policy_value(&hkcu_policy_registry, &hkcu_microsoft_policy_registry, "RequireSecurityDevice"),
        false,
    );
    evidence.use_certificate_for_on_prem_auth = build_policy_value(
        current_policy_value(&current_registry, "UseCertificateForOnPremAuth"),
        provider_policy_value(&provider_registry, "UseCertificateForOnPremAuth"),
        machine_policy_value(&hklm_policy_registry, &hklm_microsoft_policy_registry, "UseCertificateForOnPremAuth"),
        user_policy_value(&hkcu_policy_registry, &hkcu_microsoft_policy_registry, "UseCertificateForOnPremAuth"),
        false,
    );
    evidence.use_cloud_trust_for_on_prem_auth = build_policy_value(
        current_policy_value(&current_registry, "UseCloudTrustForOnPremAuth"),
        provider_policy_value(&provider_registry, "UseCloudTrustForOnPremAuth"),
        machine_policy_value(&hklm_policy_registry, &hklm_microsoft_policy_registry, "UseCloudTrustForOnPremAuth"),
        user_policy_value(&hkcu_policy_registry, &hkcu_microsoft_policy_registry, "UseCloudTrustForOnPremAuth"),
        false,
    );

    annotate_missing_policy_evidence(&mut evidence);

    evidence
}

pub fn load_os_version_evidence(bundle_path: &Path) -> Option<DsregcmdOsVersionEvidence> {
    let path = registry_file_path(bundle_path, OS_VERSION_FILE);
    let mut artifact_paths = Vec::new();
    let registry = load_registry_map(&path, &mut artifact_paths);
    if artifact_paths.is_empty() {
        return None;
    }

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
    let conn_path = registry_file_path(bundle_path, PROXY_CONNECTIONS_FILE);

    let mut artifact_paths = Vec::new();
    let ie_registry = load_registry_map(&ie_path, &mut artifact_paths);
    let conn_registry = load_registry_map(&conn_path, &mut artifact_paths);

    if artifact_paths.is_empty() {
        return None;
    }

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

    if let Some(ref url) = evidence.auto_config_url {
        evidence.wpad_detected = url.to_ascii_lowercase().contains("wpad");
    }

    // Check for WinHTTP proxy in connections registry
    for (key_path, values) in &conn_registry {
        let lower = key_path.to_ascii_lowercase();
        if lower.contains("\\internet settings\\connections") {
            evidence.winhttp_proxy =
                extract_string_value(values, "WinHttpSettings")
                    .or_else(|| extract_string_value(values, "DefaultConnectionSettings"));
            break;
        }
    }

    Some(evidence)
}

pub fn load_enrollment_evidence(bundle_path: &Path) -> Option<DsregcmdEnrollmentEvidence> {
    let path = registry_file_path(bundle_path, ENROLLMENTS_FILE);
    let mut artifact_paths = Vec::new();
    let registry = load_registry_map(&path, &mut artifact_paths);
    if artifact_paths.is_empty() {
        return None;
    }

    let mut enrollments = Vec::new();

    for (key_path, values) in &registry {
        let lower = key_path.to_ascii_lowercase();
        // Each enrollment is under a GUID subkey: ...\Enrollments\{GUID}
        if !lower.contains("\\enrollments\\{") {
            continue;
        }
        // Skip deeper subkeys (e.g., ...\{GUID}\FirstSync)
        let after_guid = key_path
            .rfind('}')
            .map(|pos| &key_path[pos + 1..])
            .unwrap_or("");
        if after_guid.contains('\\') {
            continue;
        }

        let guid = key_path
            .rfind('{')
            .and_then(|start| {
                key_path.rfind('}').map(|end| key_path[start..=end].to_string())
            });

        enrollments.push(DsregcmdEnrollmentEntry {
            guid,
            upn: extract_string_value(values, "UPN"),
            provider_id: extract_string_value(values, "ProviderID"),
            enrollment_state: extract_dword_value(values, "EnrollmentState"),
        });
    }

    let enrollment_count = u32::try_from(enrollments.len()).unwrap_or(u32::MAX);

    Some(DsregcmdEnrollmentEvidence {
        enrollment_count,
        enrollments,
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

fn extract_dword_value(
    values: &HashMap<String, RegistryValue>,
    value_name: &str,
) -> Option<u32> {
    let key = value_name.to_ascii_lowercase();
    values.get(&key).and_then(|v| match v {
        RegistryValue::Dword(d) => Some(*d),
        RegistryValue::String(s) => s.trim().parse().ok(),
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

    if evidence.policy_enabled.display_value.is_none() && evidence.policy_enabled.note.is_none() {
        evidence.policy_enabled.note = missing_note.clone();
    }

    if evidence.post_logon_enabled.display_value.is_none() && evidence.post_logon_enabled.note.is_none() {
        evidence.post_logon_enabled.note = missing_note;
    }
}

fn registry_file_path(bundle_path: &Path, file_name: &str) -> PathBuf {
    REGISTRY_FOLDER
        .iter()
        .fold(bundle_path.to_path_buf(), |path, segment| path.join(segment))
        .join(file_name)
}

fn load_registry_map(path: &Path, artifact_paths: &mut Vec<String>) -> RegistryKeyMap {
    if !path.is_file() {
        return HashMap::new();
    }

    artifact_paths.push(path.to_string_lossy().to_string());

    match fs::read_to_string(path) {
        Ok(content) => parse_reg_snapshot(&content),
        Err(_) => match fs::read(path)
            .ok()
            .and_then(|bytes| decode_reg_content(&bytes))
        {
            Some(content) => parse_reg_snapshot(&content),
            None => HashMap::new(),
        },
    }
}

fn decode_reg_content(bytes: &[u8]) -> Option<String> {
    if bytes.starts_with(&[0xFF, 0xFE]) {
        let units = bytes[2..]
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect::<Vec<u16>>();
        return Some(String::from_utf16_lossy(&units));
    }

    if bytes.starts_with(&[0xFE, 0xFF]) {
        let units = bytes[2..]
            .chunks_exact(2)
            .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
            .collect::<Vec<u16>>();
        return Some(String::from_utf16_lossy(&units));
    }

    String::from_utf8(bytes.to_vec()).ok()
}

fn build_registry_snapshot_summary(registry: &RegistryKeyMap) -> RegistrySnapshotSummary {
    let mut keys = registry.iter().collect::<Vec<_>>();
    keys.sort_by(|left, right| left.0.cmp(right.0));

    let key_count = u32::try_from(keys.len()).unwrap_or(u32::MAX);
    let value_count = u32::try_from(
        registry
            .values()
            .map(|values| values.len())
            .sum::<usize>(),
    )
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

        values
            .get(&value_name)
            .and_then(parse_registry_bool)
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
        if line.is_empty()
            || line.starts_with(';')
            || line.starts_with("Windows Registry Editor")
        {
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
        return Some(RegistryValue::String(value[1..value.len() - 1].replace("\\\\", "\\")));
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
    use crate::dsregcmd::models::DsregcmdEvidenceSource;

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
            0xFF, 0xFE, 0x57, 0x00, 0x69, 0x00, 0x6E, 0x00, 0x64, 0x00, 0x6F, 0x00, 0x77,
            0x00, 0x73, 0x00,
        ];
        let decoded = decode_reg_content(&utf16).expect("decode utf16 reg export");
        assert_eq!(decoded, "Windows");
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
        assert_eq!(evidence.product_name.as_deref(), Some("Windows 11 Enterprise"));
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
        assert_eq!(evidence.proxy_server.as_deref(), Some("http://proxy.contoso.com:8080"));
        assert!(evidence.wpad_detected);
    }

    #[test]
    fn loads_enrollment_evidence_from_bundle() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let registry_dir = temp_dir.path().join("evidence").join("registry");
        std::fs::create_dir_all(&registry_dir).expect("create registry dir");

        std::fs::write(
            registry_dir.join("enrollments.reg"),
            r#"Windows Registry Editor Version 5.00

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
        assert!(evidence.enrollments.iter().any(|e| e.upn.as_deref() == Some("user@contoso.com")));

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
}