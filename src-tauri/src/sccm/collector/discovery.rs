use std::collections::BTreeSet;

use super::{
    normalize_public_discovery, role_key, PrivateSccmEnvironment, SccmCaptureRoot,
    SccmDiscoveryFailure, SccmDiscoveryProvider, SccmEnvironmentDiscovery,
};

#[cfg(target_os = "windows")]
use super::{SccmDetectedRole, SccmDiscoveryBasis, SccmDiscoveryIssue, SccmDiscoveryIssueCode};
#[cfg(not(target_os = "windows"))]
use super::{SccmDiscoveryIssue, SccmDiscoveryIssueCode};
#[cfg(target_os = "windows")]
use crate::sccm::SccmRole;

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
    const FIXED_ROLE_QUERY: &str = "$ErrorActionPreference='Stop'; Get-CimInstance -Namespace 'root/cimv2' -ClassName 'Win32_Service' -Filter \"Name='SMS_EXECUTIVE' OR Name='SMS_ADMIN_SERVICE' OR Name='WSUSService'\" | Select-Object -ExpandProperty Name | ConvertTo-Json -Compress";

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
            if let Some(windows) = std::env::var_os("WINDIR") {
                environment.roots.push(SccmCaptureRoot {
                    role: SccmRole::Client,
                    path: PathBuf::from(windows).join("CCM").join("Logs"),
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
            let facts = String::from_utf8_lossy(&output.stdout);
            for (service, role) in [
                ("SMS_EXECUTIVE", SccmRole::SiteServer),
                ("SMS_ADMIN_SERVICE", SccmRole::AdminService),
                ("WSUSService", SccmRole::WsUs),
            ] {
                if facts.contains(service) {
                    environment.roles.push(SccmDetectedRole {
                        role: role.clone(),
                        basis: SccmDiscoveryBasis::Cim,
                    });
                    if let Some(path) = server_install_root
                        .as_ref()
                        .map(|path| path.join("Logs"))
                        .or_else(|| default_role_root(&role))
                    {
                        environment.roots.push(SccmCaptureRoot { role, path });
                    }
                }
            }
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
