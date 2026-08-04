use std::collections::BTreeSet;

use super::{
    normalize_public_discovery, role_key, PrivateSccmEnvironment, SccmCaptureRoot,
    SccmDiscoveryFailure, SccmDiscoveryProvider, SccmEnvironmentDiscovery,
};

#[cfg(any(test, target_os = "windows"))]
use super::{SccmDetectedRole, SccmDiscoveryBasis};
use super::{SccmDiscoveryIssue, SccmDiscoveryIssueCode};
#[cfg(any(test, target_os = "windows"))]
use crate::sccm::SccmRole;

#[cfg(any(test, target_os = "windows"))]
const FIXED_ROLE_QUERY: &str = "$ErrorActionPreference='Stop'; Get-CimInstance -Namespace 'root/cimv2' -ClassName 'Win32_Service' -Filter \"Name='CcmExec' OR Name='SMS_EXECUTIVE' OR Name='SMS_ADMIN_SERVICE' OR Name='WSUSService'\" | Select-Object -ExpandProperty Name | ConvertTo-Json -Compress";

#[derive(Debug, Default)]
pub struct NativeDiscoveryProvider;

impl SccmDiscoveryProvider for NativeDiscoveryProvider {
    fn discover(&self) -> Result<PrivateSccmEnvironment, SccmDiscoveryFailure> {
        discover_native()
    }
}

pub fn discover_environment() -> Result<SccmEnvironmentDiscovery, SccmDiscoveryFailure> {
    discover_environment_with(&NativeDiscoveryProvider)
}

pub fn discover_environment_with(
    provider: &dyn SccmDiscoveryProvider,
) -> Result<SccmEnvironmentDiscovery, SccmDiscoveryFailure> {
    let mut private = provider.discover()?;
    normalize_private_roots(&mut private.roots);
    Ok(normalize_public_discovery(SccmEnvironmentDiscovery {
        supported: private.supported,
        configmgr_version: private.configmgr_version,
        roles: private.roles,
        sources: Vec::new(),
        issues: private.issues,
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
            if let Some(path) = client_log_root() {
                environment.roots.push(SccmCaptureRoot {
                    role: SccmRole::Client,
                    path,
                });
            }
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
            let client_root = client_log_root();
            apply_cim_service_facts(
                &mut environment,
                &output.stdout,
                server_install_root.as_deref(),
                client_root.as_deref(),
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

#[cfg(target_os = "windows")]
fn client_log_root() -> Option<std::path::PathBuf> {
    std::env::var_os("WINDIR")
        .map(std::path::PathBuf::from)
        .map(|path| path.join("CCM").join("Logs"))
}

#[cfg(any(test, target_os = "windows"))]
fn apply_cim_service_facts(
    environment: &mut PrivateSccmEnvironment,
    output: &[u8],
    server_install_root: Option<&std::path::Path>,
    allow_listed_client_root: Option<&std::path::Path>,
) {
    #[derive(serde::Deserialize)]
    #[serde(untagged)]
    enum ServiceNames {
        One(String),
        Many(Vec<String>),
    }

    let Ok(names) = serde_json::from_slice::<ServiceNames>(output) else {
        return;
    };
    let names = match names {
        ServiceNames::One(name) => vec![name],
        ServiceNames::Many(names) => names,
    };

    for service_name in names.into_iter().collect::<BTreeSet<_>>() {
        let Some(role) = role_for_cim_service(&service_name) else {
            continue;
        };
        environment.roles.push(SccmDetectedRole {
            role: role.clone(),
            basis: SccmDiscoveryBasis::Cim,
        });
        let path = match role {
            SccmRole::Client => allow_listed_client_root.map(std::path::Path::to_path_buf),
            _ => server_install_root
                .map(|path| path.join("Logs"))
                .or_else(|| default_role_root(&role)),
        };
        if let Some(path) = path {
            environment.roots.push(SccmCaptureRoot { role, path });
        }
    }
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
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn ccmexec_service_without_setup_registry_fact_admits_client_and_fixed_root() {
        let client_root = PathBuf::from(r"C:\Windows\CCM\Logs");
        let mut environment = PrivateSccmEnvironment {
            supported: true,
            ..PrivateSccmEnvironment::default()
        };

        apply_cim_service_facts(&mut environment, br#""CcmExec""#, None, Some(&client_root));

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
    fn similarly_named_or_untrusted_service_output_does_not_admit_client() {
        for output in [
            br#""CcmExecHelper""#.as_slice(),
            br#""CCMEXEC""#.as_slice(),
            br#"" CcmExec ""#.as_slice(),
            br#"["NotCcmExec", "CcmExecAgent"]"#.as_slice(),
            br#"{"Name":"CcmExec"}"#.as_slice(),
            b"CcmExec".as_slice(),
        ] {
            let mut environment = PrivateSccmEnvironment::default();
            let client_root = PathBuf::from(r"C:\Windows\CCM\Logs");
            apply_cim_service_facts(&mut environment, output, None, Some(&client_root));

            assert!(environment.roles.is_empty());
            assert!(environment.roots.is_empty());
        }
    }

    #[test]
    fn ccmexec_service_never_supplies_or_invents_a_client_root() {
        let mut environment = PrivateSccmEnvironment::default();

        apply_cim_service_facts(&mut environment, br#""CcmExec""#, None, None);

        assert_eq!(environment.roles[0].role, SccmRole::Client);
        assert!(environment.roots.is_empty());
    }

    #[test]
    fn fixed_cim_query_requests_only_allow_listed_service_names() {
        assert!(FIXED_ROLE_QUERY.contains("Name='CcmExec'"));
        assert!(FIXED_ROLE_QUERY.contains("Select-Object -ExpandProperty Name"));
        assert!(!FIXED_ROLE_QUERY.contains("PathName"));
        assert!(!FIXED_ROLE_QUERY.contains("StartName"));
    }
}
