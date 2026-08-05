use std::collections::BTreeSet;

use super::{
    normalize_public_discovery, role_key, PrivateAdvancedSourceFact, PrivateSccmEnvironment,
    SccmCaptureRoot, SccmDiscoveryFailure, SccmDiscoveryProvider, SccmEnvironmentDiscovery,
};

#[cfg(any(test, target_os = "windows"))]
use super::{SccmDetectedRole, SccmDiscoveryBasis};
use super::{SccmDiscoveryIssue, SccmDiscoveryIssueCode};
use crate::sccm::SccmRole;

#[cfg(any(test, target_os = "windows"))]
const FIXED_ROLE_QUERY: &str = "$ErrorActionPreference='Stop'; Get-CimInstance -Namespace 'root/cimv2' -ClassName 'Win32_Service' -Filter \"Name='CcmExec' OR Name='SMS_EXECUTIVE' OR Name='SMS_ADMIN_SERVICE' OR Name='WSUSService'\" | Select-Object Name,PathName | ConvertTo-Json -Compress";

#[cfg(any(test, target_os = "windows"))]
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct CimServiceFact {
    name: String,
    path_name: Option<String>,
}

#[cfg(any(test, target_os = "windows"))]
#[derive(Debug, serde::Deserialize)]
#[serde(untagged)]
enum CimServiceFacts {
    One(CimServiceFact),
    Many(Vec<CimServiceFact>),
}

#[derive(Debug, Default)]
pub struct NativeDiscoveryProvider;

impl SccmDiscoveryProvider for NativeDiscoveryProvider {
    fn discover(&self) -> Result<PrivateSccmEnvironment, SccmDiscoveryFailure> {
        discover_native().map(assemble_native_environment)
    }
}

fn assemble_native_environment(mut environment: PrivateSccmEnvironment) -> PrivateSccmEnvironment {
    normalize_private_roots(&mut environment.roots);
    environment.advanced_source_facts.clear();

    let management_point_observed = environment
        .roles
        .iter()
        .any(|fact| fact.role == SccmRole::ManagementPoint);
    if management_point_observed {
        for root in environment
            .roots
            .iter()
            .filter(|root| root.role == SccmRole::ManagementPoint)
        {
            environment
                .advanced_source_facts
                .push(PrivateAdvancedSourceFact {
                    source_id: "advanced-client-notification-bgb".to_owned(),
                    role_scope: "managementPoint".to_owned(),
                    path_class: "configuredRoleLogRoot".to_owned(),
                    root: root.path.clone(),
                    source_version: environment.configmgr_version.clone(),
                    pxe_enabled: false,
                });
        }
    }

    environment
}

pub fn discover_environment() -> Result<SccmEnvironmentDiscovery, SccmDiscoveryFailure> {
    discover_environment_with(&NativeDiscoveryProvider)
}

pub fn discover_environment_with(
    provider: &dyn SccmDiscoveryProvider,
) -> Result<SccmEnvironmentDiscovery, SccmDiscoveryFailure> {
    let mut private = provider.discover()?;
    normalize_private_roots(&mut private.roots);
    let advanced_sources = super::advanced_capture::advanced_source_options(&private);
    Ok(normalize_public_discovery(SccmEnvironmentDiscovery {
        supported: private.supported,
        configmgr_version: private.configmgr_version,
        roles: private.roles,
        sources: Vec::new(),
        issues: private.issues,
        advanced_sources,
    }))
}

pub(crate) fn normalized_private_environment(
    provider: &dyn SccmDiscoveryProvider,
) -> Result<PrivateSccmEnvironment, SccmDiscoveryFailure> {
    let mut environment = provider.discover()?;
    normalize_private_roots(&mut environment.roots);
    environment
        .roles
        .sort_by_key(|role| (role_key(&role.role), role.basis));
    environment.roles.dedup();
    environment.issues.sort_by_key(|issue| {
        (
            issue.code,
            issue.role.as_ref().map(role_key).unwrap_or_default(),
        )
    });
    environment.issues.dedup();
    Ok(environment)
}

fn normalize_private_roots(roots: &mut Vec<SccmCaptureRoot>) {
    roots.sort_by_key(|root| {
        (
            role_key(&root.role),
            root.path
                .to_string_lossy()
                .replace('\\', "/")
                .to_lowercase(),
        )
    });
    let mut seen = BTreeSet::new();
    roots.retain(|root| {
        seen.insert((
            role_key(&root.role),
            root.path
                .to_string_lossy()
                .replace('\\', "/")
                .to_lowercase(),
        ))
    });
}

#[cfg(not(target_os = "windows"))]
fn discover_native() -> Result<PrivateSccmEnvironment, SccmDiscoveryFailure> {
    Ok(PrivateSccmEnvironment {
        supported: false,
        issues: vec![SccmDiscoveryIssue {
            code: SccmDiscoveryIssueCode::UnsupportedPlatform,
            role: None,
        }],
        ..PrivateSccmEnvironment::default()
    })
}

#[cfg(target_os = "windows")]
fn discover_native() -> Result<PrivateSccmEnvironment, SccmDiscoveryFailure> {
    use std::path::PathBuf;
    use std::process::Command;
    use winreg::enums::HKEY_LOCAL_MACHINE;
    use winreg::RegKey;

    const CLIENT_SETUP_KEY: &str = r"SOFTWARE\Microsoft\CCM\Setup";
    const SITE_SERVER_KEY: &str = r"SOFTWARE\Microsoft\SMS\Setup";

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let mut environment = PrivateSccmEnvironment {
        supported: true,
        private_host: std::env::var("COMPUTERNAME").ok(),
        ..PrivateSccmEnvironment::default()
    };

    match hklm.open_subkey(CLIENT_SETUP_KEY) {
        Ok(key) => {
            environment.roles.push(SccmDetectedRole {
                role: SccmRole::Client,
                basis: SccmDiscoveryBasis::Registry,
            });
            environment.configmgr_version = key.get_value::<String, _>("ProductVersion").ok();
        }
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            environment.issues.push(SccmDiscoveryIssue {
                code: SccmDiscoveryIssueCode::RegistryAccessDenied,
                role: Some(SccmRole::Client),
            });
        }
        Err(_) => {}
    }

    let mut server_install_root = None;
    match hklm.open_subkey(SITE_SERVER_KEY) {
        Ok(key) => {
            environment.roles.push(SccmDetectedRole {
                role: SccmRole::SiteServer,
                basis: SccmDiscoveryBasis::Registry,
            });
            environment.private_site_code = key.get_value::<String, _>("Site Code").ok();
            if let Ok(path) = key.get_value::<String, _>("Installation Directory") {
                server_install_root = Some(PathBuf::from(&path));
                environment.roots.push(SccmCaptureRoot {
                    role: SccmRole::SiteServer,
                    path: PathBuf::from(path).join("Logs"),
                });
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            environment.issues.push(SccmDiscoveryIssue {
                code: SccmDiscoveryIssueCode::RegistryAccessDenied,
                role: Some(SccmRole::SiteServer),
            });
        }
        Err(_) => {}
    }

    for (key_name, role) in [
        (r"SOFTWARE\Microsoft\SMS\MP", SccmRole::ManagementPoint),
        (r"SOFTWARE\Microsoft\SMS\DP", SccmRole::DistributionPoint),
        (r"SOFTWARE\Microsoft\SMS\SUP", SccmRole::SoftwareUpdatePoint),
        (r"SOFTWARE\Microsoft\SMS\WSUS", SccmRole::WsUs),
        (r"SOFTWARE\Microsoft\SMS\Providers", SccmRole::Provider),
        (
            r"SOFTWARE\Microsoft\SMS\AdminService",
            SccmRole::AdminService,
        ),
    ] {
        match hklm.open_subkey(key_name) {
            Ok(key) => {
                let path = key
                    .get_value::<String, _>("Log Directory")
                    .ok()
                    .map(PathBuf::from)
                    .or_else(|| server_install_root.as_ref().map(|path| path.join("Logs")))
                    .or_else(|| default_role_root(&role));
                environment.roles.push(SccmDetectedRole {
                    role: role.clone(),
                    basis: SccmDiscoveryBasis::Registry,
                });
                if let Some(path) = path {
                    environment.roots.push(SccmCaptureRoot { role, path });
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                environment.issues.push(SccmDiscoveryIssue {
                    code: SccmDiscoveryIssueCode::RegistryAccessDenied,
                    role: Some(role),
                });
            }
            _ => {}
        }
    }

    match Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            FIXED_ROLE_QUERY,
        ])
        .output()
    {
        Ok(output) if output.status.success() => {
            apply_cim_service_facts(
                &mut environment,
                &output.stdout,
                server_install_root.as_deref(),
            );
        }
        Ok(output) if !output.status.success() => {
            environment.issues.push(SccmDiscoveryIssue {
                code: SccmDiscoveryIssueCode::CimAccessDenied,
                role: None,
            });
        }
        Err(_) => environment.issues.push(SccmDiscoveryIssue {
            code: SccmDiscoveryIssueCode::DiscoveryFailed,
            role: None,
        }),
        _ => {}
    }

    Ok(environment)
}

#[cfg(any(test, target_os = "windows"))]
fn apply_cim_service_facts(
    environment: &mut PrivateSccmEnvironment,
    output: &[u8],
    server_install_root: Option<&std::path::Path>,
) {
    let Ok(facts) = serde_json::from_slice::<CimServiceFacts>(output) else {
        return;
    };
    let facts = match facts {
        CimServiceFacts::One(fact) => vec![fact],
        CimServiceFacts::Many(facts) => facts,
    };
    let client_root = client_root_from_service_facts(&facts);

    for fact in facts {
        let Some(role) = role_for_cim_service(&fact.name) else {
            continue;
        };
        environment.roles.push(SccmDetectedRole {
            role: role.clone(),
            basis: SccmDiscoveryBasis::Cim,
        });
        let path = match role {
            SccmRole::Client => client_root.clone(),
            _ => server_install_root
                .map(|path| path.join("Logs"))
                .or_else(|| default_role_root(&role)),
        };
        if let Some(path) = path {
            environment.roots.push(SccmCaptureRoot { role, path });
        }
    }
}

#[cfg(test)]
fn client_root_from_service_output(output: &[u8]) -> Option<std::path::PathBuf> {
    let facts = serde_json::from_slice::<CimServiceFacts>(output).ok()?;
    let facts = match facts {
        CimServiceFacts::One(fact) => vec![fact],
        CimServiceFacts::Many(facts) => facts,
    };
    client_root_from_service_facts(&facts)
}

#[cfg(any(test, target_os = "windows"))]
fn client_root_from_service_facts(facts: &[CimServiceFact]) -> Option<std::path::PathBuf> {
    let mut ccmexec_count = 0;
    let mut roots = BTreeSet::new();
    for fact in facts {
        if fact.name != "CcmExec" {
            continue;
        }
        ccmexec_count += 1;
        if let Some(root) = fact
            .path_name
            .as_deref()
            .and_then(client_root_from_service_path)
        {
            roots.insert(root);
        }
    }
    (ccmexec_count == 1 && roots.len() == 1)
        .then(|| roots.into_iter().next())
        .flatten()
}

#[cfg(any(test, target_os = "windows"))]
fn client_root_from_service_path(path_name: &str) -> Option<std::path::PathBuf> {
    if path_name.chars().any(char::is_control) {
        return None;
    }
    let path_name = path_name.trim();
    if path_name.is_empty() {
        return None;
    }

    let executable = if let Some(stripped) = path_name.strip_prefix('"') {
        let closing_quote = stripped.find('"')?;
        let trailing = &stripped[closing_quote + 1..];
        if (!trailing.is_empty() && !trailing.starts_with(char::is_whitespace))
            || trailing.contains('"')
        {
            return None;
        }
        &stripped[..closing_quote]
    } else {
        let lower = path_name.to_ascii_lowercase();
        let executable_end = lower.find(".exe")? + ".exe".len();
        let trailing = &path_name[executable_end..];
        if !trailing.is_empty() && !trailing.starts_with(char::is_whitespace) {
            return None;
        }
        &path_name[..executable_end]
    };

    if executable.contains('/')
        || executable.contains(r"\\")
        || executable.contains('"')
        || executable.len() < 4
    {
        return None;
    }
    let bytes = executable.as_bytes();
    if !bytes[0].is_ascii_alphabetic() || bytes[1] != b':' || bytes[2] != b'\\' {
        return None;
    }

    let components = executable[3..].split('\\');
    let mut last = None;
    for component in components {
        if component.is_empty()
            || component == "."
            || component == ".."
            || component.contains(':')
            || component.contains('*')
            || component.contains('?')
        {
            return None;
        }
        last = Some(component);
    }
    if !last.is_some_and(|name| name.eq_ignore_ascii_case("CcmExec.exe")) {
        return None;
    }

    let parent_end = executable.rfind('\\')?;
    Some(std::path::PathBuf::from(format!(
        "{}\\Logs",
        &executable[..parent_end]
    )))
}

#[cfg(any(test, target_os = "windows"))]
fn role_for_cim_service(service_name: &str) -> Option<SccmRole> {
    match service_name {
        "CcmExec" => Some(SccmRole::Client),
        "SMS_EXECUTIVE" => Some(SccmRole::SiteServer),
        "SMS_ADMIN_SERVICE" => Some(SccmRole::AdminService),
        "WSUSService" => Some(SccmRole::WsUs),
        _ => None,
    }
}

#[cfg(any(test, target_os = "windows"))]
fn default_role_root(role: &SccmRole) -> Option<std::path::PathBuf> {
    let system_drive = std::env::var_os("SystemDrive")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(r"C:\"));
    let program_files = std::env::var_os("ProgramFiles").map(std::path::PathBuf::from);
    match role {
        SccmRole::ManagementPoint | SccmRole::AdminService => {
            Some(system_drive.join("SMS_CCM").join("Logs"))
        }
        SccmRole::DistributionPoint => Some(system_drive.join("SMS_DP$").join("sms").join("logs")),
        SccmRole::SoftwareUpdatePoint | SccmRole::Provider | SccmRole::SiteServer => {
            program_files.map(|path| path.join("Microsoft Configuration Manager").join("Logs"))
        }
        SccmRole::WsUs => program_files.map(|path| path.join("Update Services").join("LogFiles")),
        SccmRole::Client | SccmRole::Unknown(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::Instant;

    use super::*;
    use crate::sccm::collector::{
        advanced_source_contracts, advanced_source_options, capture_advanced_authorized,
        SccmAdvancedCapabilityStore, SccmAdvancedCaptureAuthorizationRequest,
        SccmAdvancedSourceAvailability,
    };
    fn observed_role(role: SccmRole) -> SccmDetectedRole {
        SccmDetectedRole {
            role,
            basis: SccmDiscoveryBasis::Registry,
        }
    }

    #[test]
    fn production_assembly_derives_bgb_only_from_matching_management_point_role_and_root() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("BgbServer.log"), b"observed-bgb").unwrap();
        let environment = assemble_native_environment(PrivateSccmEnvironment {
            supported: true,
            configmgr_version: Some("5.00.9141.1000".to_owned()),
            roles: vec![observed_role(SccmRole::ManagementPoint)],
            roots: vec![SccmCaptureRoot {
                role: SccmRole::ManagementPoint,
                path: root.path().to_owned(),
            }],
            ..PrivateSccmEnvironment::default()
        });

        assert_eq!(environment.advanced_source_facts.len(), 1);
        assert_eq!(
            environment.advanced_source_facts[0],
            PrivateAdvancedSourceFact {
                source_id: "advanced-client-notification-bgb".to_owned(),
                role_scope: "managementPoint".to_owned(),
                path_class: "configuredRoleLogRoot".to_owned(),
                root: root.path().to_owned(),
                source_version: Some("5.00.9141.1000".to_owned()),
                pxe_enabled: false,
            }
        );

        let options = advanced_source_options(&environment);
        assert_eq!(
            options
                .iter()
                .find(|option| option.source_id == "advanced-client-notification-bgb")
                .unwrap()
                .availability,
            SccmAdvancedSourceAvailability::Observed
        );
        assert!(options
            .iter()
            .filter(|option| option.source_id != "advanced-client-notification-bgb")
            .all(|option| {
                option.availability == SccmAdvancedSourceAvailability::OperatorDeclaredCandidate
            }));

        let contract = advanced_source_contracts()
            .iter()
            .find(|contract| contract.source_id == "advanced-client-notification-bgb")
            .unwrap();
        let request = SccmAdvancedCaptureAuthorizationRequest {
            card_id: contract.card_id.to_owned(),
            card_version: contract.card_version.to_owned(),
            source_id: contract.source_id.to_owned(),
            role_scope: "managementPoint".to_owned(),
            path_class: "configuredRoleLogRoot".to_owned(),
            expected_source_version: environment.configmgr_version.clone(),
            selected_root: root.path().to_string_lossy().into_owned(),
        };
        let now = Instant::now();
        let mut store = SccmAdvancedCapabilityStore::default();
        let capability = store.authorize(&environment, request, now).unwrap();
        let authorization = store.consume(&capability.capability_handle, now).unwrap();
        let output = tempfile::tempdir().unwrap();
        let bundle = output.path().join("bundle");
        capture_advanced_authorized(authorization, &bundle).unwrap();
        let manifest = fs::read_to_string(bundle.join("sccm-server-manifest.json")).unwrap();
        assert!(manifest.contains("\"roleProvenance\": \"observed\""));
    }

    #[test]
    fn production_assembly_requires_both_role_and_same_role_root() {
        let root = tempfile::tempdir().unwrap();
        for environment in [
            PrivateSccmEnvironment {
                supported: true,
                roots: vec![SccmCaptureRoot {
                    role: SccmRole::ManagementPoint,
                    path: root.path().to_owned(),
                }],
                ..PrivateSccmEnvironment::default()
            },
            PrivateSccmEnvironment {
                supported: true,
                roles: vec![observed_role(SccmRole::ManagementPoint)],
                ..PrivateSccmEnvironment::default()
            },
            PrivateSccmEnvironment {
                supported: true,
                roles: vec![observed_role(SccmRole::ManagementPoint)],
                roots: vec![SccmCaptureRoot {
                    role: SccmRole::SiteServer,
                    path: root.path().to_owned(),
                }],
                ..PrivateSccmEnvironment::default()
            },
        ] {
            assert!(assemble_native_environment(environment)
                .advanced_source_facts
                .is_empty());
        }
    }

    #[test]
    fn production_assembly_replaces_injected_or_tampered_advanced_facts() {
        let root = tempfile::tempdir().unwrap();
        let hostile = tempfile::tempdir().unwrap();
        let environment = assemble_native_environment(PrivateSccmEnvironment {
            supported: true,
            roles: vec![observed_role(SccmRole::SiteServer)],
            roots: vec![SccmCaptureRoot {
                role: SccmRole::SiteServer,
                path: root.path().to_owned(),
            }],
            advanced_source_facts: vec![PrivateAdvancedSourceFact {
                source_id: "advanced-client-notification-bgb".to_owned(),
                role_scope: "managementPoint".to_owned(),
                path_class: "configuredRoleLogRoot".to_owned(),
                root: hostile.path().to_owned(),
                source_version: Some("forged".to_owned()),
                pxe_enabled: true,
            }],
            ..PrivateSccmEnvironment::default()
        });

        assert!(environment.advanced_source_facts.is_empty());
    }

    #[test]
    fn ccmexec_service_path_derives_one_sibling_logs_root() {
        let client_root = PathBuf::from(r"C:\Program Files\SMS_CCM\Logs");
        let mut environment = PrivateSccmEnvironment {
            supported: true,
            ..PrivateSccmEnvironment::default()
        };

        apply_cim_service_facts(
            &mut environment,
            br#"{"Name":"CcmExec","PathName":"C:\\Program Files\\SMS_CCM\\CcmExec.exe"}"#,
            None,
        );

        assert_eq!(
            environment.roles,
            vec![SccmDetectedRole {
                role: SccmRole::Client,
                basis: SccmDiscoveryBasis::Cim,
            }]
        );
        assert_eq!(
            environment.roots,
            vec![SccmCaptureRoot {
                role: SccmRole::Client,
                path: client_root,
            }]
        );
    }

    #[test]
    fn ccmexec_service_path_accepts_quotes_and_trailing_arguments() {
        let root = client_root_from_service_output(
            br#"{"Name":"CcmExec","PathName":"\"C:\\Program Files\\SMS_CCM\\CcmExec.exe\" -service"}"#,
        );

        assert_eq!(root, Some(PathBuf::from(r"C:\Program Files\SMS_CCM\Logs")));
    }

    #[test]
    fn ccmexec_service_path_rejects_control_whitespace_around_exact_paths() {
        let executable = r#"C:\Program Files\SMS_CCM\CcmExec.exe"#;
        for control in ['\t', '\r', '\n'] {
            for leading in [true, false] {
                for quoted in [true, false] {
                    let exact_path = if quoted {
                        format!(r#""{executable}""#)
                    } else {
                        executable.to_owned()
                    };
                    let path_name = if leading {
                        format!("{control}{exact_path}")
                    } else {
                        format!("{exact_path}{control}")
                    };
                    let output = serde_json::json!({
                        "Name": "CcmExec",
                        "PathName": path_name,
                    });

                    assert_eq!(
                        client_root_from_service_output(output.to_string().as_bytes()),
                        None,
                        "control whitespace must not authorize a root: {control:?}, leading={leading}, quoted={quoted}"
                    );
                }
            }
        }
    }

    #[test]
    fn ccmexec_service_path_rejects_wrapper_relative_unc_and_wrong_basename() {
        for output in [
            br#"{"Name":"ccmexec","PathName":"C:\\Program Files\\SMS_CCM\\CcmExec.exe"}"#.as_slice(),
            br#"{"Name":"CcmExec","PathName":"cmd.exe /c C:\\Program Files\\SMS_CCM\\CcmExec.exe"}"#.as_slice(),
            br#"{"Name":"CcmExec","PathName":"CcmExec.exe"}"#.as_slice(),
            br#"{"Name":"CcmExec","PathName":"\\\\server\\SMS_CCM\\CcmExec.exe"}"#.as_slice(),
            br#"{"Name":"CcmExec","PathName":"C:\\Program Files\\SMS_CCM\\Other.exe"}"#.as_slice(),
            br#"{"Name":"CcmExec","PathName":"C:\\Program Files\\SMS_CCM\\..\\CcmExec.exe"}"#.as_slice(),
        ] {
            assert_eq!(client_root_from_service_output(output), None);
        }
    }

    #[test]
    fn missing_legacy_windir_root_is_not_selected() {
        let mut environment = PrivateSccmEnvironment::default();

        apply_cim_service_facts(
            &mut environment,
            br#"{"Name":"CcmExec","PathName":"C:\\Program Files\\SMS_CCM\\CcmExec.exe"}"#,
            None,
        );

        assert_eq!(
            environment.roots,
            vec![SccmCaptureRoot {
                role: SccmRole::Client,
                path: PathBuf::from(r"C:\Program Files\SMS_CCM\Logs"),
            }]
        );
        assert!(!environment
            .roots
            .iter()
            .any(|root| root.path.to_string_lossy() == r"C:\Windows\CCM\Logs"));
    }

    #[test]
    fn fixed_cim_query_selects_only_exact_service_name_and_path() {
        assert!(FIXED_ROLE_QUERY.contains("Name='CcmExec'"));
        assert!(FIXED_ROLE_QUERY.contains("Select-Object Name,PathName"));
        assert!(FIXED_ROLE_QUERY.contains("PathName"));
        assert!(!FIXED_ROLE_QUERY.contains("StartName"));
        assert!(!FIXED_ROLE_QUERY.contains("Select-Object -ExpandProperty Name"));
    }

    #[test]
    fn serialized_discovery_never_contains_service_path() {
        let service_path = r"C:\Program Files\SMS_CCM\CcmExec.exe";
        let value = normalize_public_discovery(SccmEnvironmentDiscovery {
            supported: true,
            configmgr_version: None,
            roles: vec![SccmDetectedRole {
                role: SccmRole::Client,
                basis: SccmDiscoveryBasis::Cim,
            }],
            sources: Vec::new(),
            issues: Vec::new(),
            advanced_sources: Vec::new(),
        });
        let serialized = serde_json::to_string(&value).unwrap();
        assert!(!serialized.contains(service_path));
        assert!(!serialized.contains(r"C:\Windows\CCM\Logs"));
    }

    #[test]
    fn ccmexec_role_is_retained_when_service_root_is_absent() {
        let mut environment = PrivateSccmEnvironment::default();

        apply_cim_service_facts(&mut environment, br#"{"Name":"CcmExec"}"#, None);

        assert_eq!(environment.roles[0].role, SccmRole::Client);
        assert!(environment.roots.is_empty());
    }
}
