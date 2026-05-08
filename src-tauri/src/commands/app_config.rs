use serde::Serialize;

const DISABLE_UPDATE_CHECKS_ENV: &str = "CMTRACEOPEN_DISABLE_UPDATE_CHECKS";
const STARTUP_UPDATE_CHECKS_ENABLED_BY_DEFAULT: bool = false;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdatePolicy {
    pub startup_update_checks_enabled_by_default: bool,
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

#[tauri::command]
pub fn get_update_policy() -> UpdatePolicy {
    UpdatePolicy {
        startup_update_checks_enabled_by_default: STARTUP_UPDATE_CHECKS_ENABLED_BY_DEFAULT,
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
