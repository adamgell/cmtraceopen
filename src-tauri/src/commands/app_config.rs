use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Serialize;
use tauri::{AppHandle, Manager};

use crate::error::{AppError, CmdResult};

const DISABLE_UPDATE_CHECKS_ENV: &str = "CMTRACEOPEN_DISABLE_UPDATE_CHECKS";

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdatePolicy {
    pub update_checks_disabled_by_policy: bool,
}

fn is_truthy_policy_value(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on" | "disabled" | "disable"
    )
}

fn update_checks_disabled_by_environment() -> bool {
    std::env::var(DISABLE_UPDATE_CHECKS_ENV)
        .map(|value| is_truthy_policy_value(&value))
        .unwrap_or(false)
}

#[cfg(target_os = "windows")]
fn update_checks_disabled_by_registry() -> bool {
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
    use winreg::RegKey;

    const SUBKEY: &str = r"Software\CMTrace Open";
    const VALUE: &str = "DisableUpdateChecks";

    [HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER]
        .into_iter()
        .filter_map(|hive| RegKey::predef(hive).open_subkey(SUBKEY).ok())
        .any(|key| {
            key.get_value::<u32, _>(VALUE)
                .map(|value| value != 0)
                .or_else(|_| {
                    key.get_value::<String, _>(VALUE)
                        .map(|value| is_truthy_policy_value(&value))
                })
                .unwrap_or(false)
        })
}

#[cfg(not(target_os = "windows"))]
fn update_checks_disabled_by_registry() -> bool {
    false
}

fn get_app_logs_dir(app: &AppHandle) -> CmdResult<PathBuf> {
    let path = app.path().app_log_dir().map_err(|error| {
        AppError::Internal(format!("Failed to resolve app log directory: {error}"))
    })?;

    fs::create_dir_all(&path).map_err(|error| {
        AppError::Internal(format!(
            "Failed to create app log directory '{}': {error}",
            path.display()
        ))
    })?;

    Ok(path)
}

fn open_directory_in_file_manager(path: &Path) -> CmdResult<()> {
    #[cfg(target_os = "windows")]
    {
        Command::new("explorer")
            .arg(path)
            .spawn()
            .map_err(|error| {
                AppError::Internal(format!(
                    "Failed to open Explorer for '{}': {error}",
                    path.display()
                ))
            })?;

        return Ok(());
    }

    #[cfg(target_os = "macos")]
    {
        Command::new("open").arg(path).spawn().map_err(|error| {
            AppError::Internal(format!(
                "Failed to open Finder for '{}': {error}",
                path.display()
            ))
        })?;

        return Ok(());
    }

    #[cfg(target_os = "linux")]
    {
        Command::new("xdg-open")
            .arg(path)
            .spawn()
            .map_err(|error| {
                AppError::Internal(format!(
                    "Failed to open file manager for '{}': {error}",
                    path.display()
                ))
            })?;

        return Ok(());
    }

    #[allow(unreachable_code)]
    Err(AppError::PlatformUnsupported(
        "Opening the application logs folder is not supported on this platform.".to_string(),
    ))
}

#[tauri::command]
pub fn get_update_policy() -> UpdatePolicy {
    UpdatePolicy {
        update_checks_disabled_by_policy: update_checks_disabled_by_environment()
            || update_checks_disabled_by_registry(),
    }
}

#[tauri::command]
pub fn get_available_workspaces() -> Vec<&'static str> {
    let mut workspaces = vec!["log"];

    if cfg!(feature = "intune-diagnostics") {
        workspaces.push("intune");
        workspaces.push("new-intune");
    }

    if cfg!(feature = "dsregcmd") {
        workspaces.push("dsregcmd");
    }

    if cfg!(feature = "macos-diag") {
        workspaces.push("macos-diag");
    }

    if cfg!(feature = "deployment") {
        workspaces.push("deployment");
    }

    if cfg!(feature = "event-log") {
        workspaces.push("event-log");
    }

    if cfg!(feature = "sysmon") {
        workspaces.push("sysmon");
    }

    if cfg!(feature = "secureboot") {
        workspaces.push("secureboot");
    }

    workspaces.push("timeline");
    workspaces.push("dns-dhcp");

    workspaces
}

#[tauri::command]
pub fn open_app_logs_folder(app: AppHandle) -> CmdResult<()> {
    let logs_dir = get_app_logs_dir(&app)?;

    log::info!("app.logs_folder.open requested path={}", logs_dir.display());

    if let Err(error) = open_directory_in_file_manager(&logs_dir) {
        log::error!(
            "app.logs_folder.open failed path={} error={}",
            logs_dir.display(),
            error
        );
        return Err(error);
    }

    log::info!("app.logs_folder.open succeeded path={}", logs_dir.display());

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::is_truthy_policy_value;

    #[test]
    fn truthy_policy_values_disable_update_checks() {
        for value in ["1", "true", "TRUE", " yes ", "on", "disabled", "disable"] {
            assert!(is_truthy_policy_value(value), "{value} should be truthy");
        }
    }

    #[test]
    fn non_truthy_policy_values_do_not_disable_update_checks() {
        for value in ["", "0", "false", "no", "off", "enabled"] {
            assert!(
                !is_truthy_policy_value(value),
                "{value} should not be truthy"
            );
        }
    }
}
