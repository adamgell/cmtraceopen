use std::fs;
use std::path::PathBuf;

#[cfg(target_os = "windows")]
use std::path::Path;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};

#[cfg(target_os = "windows")]
const FILE_ASSOCIATION_PROG_ID: &str = "CMTraceOpen.LogFile";
const REGISTERED_APPLICATION_NAME: &str = "CMTrace Open";
#[cfg(target_os = "windows")]
const FILE_ASSOCIATION_CAPABILITIES_PATH: &str = "Software\\CMTraceOpen\\Capabilities";
#[cfg(target_os = "windows")]
const DEFAULT_APPS_SETTINGS_URI: &str = "ms-settings:defaultapps?registeredAppUser=CMTrace%20Open";
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
const LOG_FILE_EXTENSIONS: &[&str] = &[".log", ".lo_", ".log_", ".cmtlog"];
const FILE_ASSOCIATION_PROMPT_FILE_NAME: &str = "file-association-preferences.json";

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileAssociationPromptStatus {
    pub supported: bool,
    pub should_prompt: bool,
    pub is_registered: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FileAssociationPreferences {
    suppress_prompt: bool,
}

fn get_file_association_preferences_path(
    app: &AppHandle,
) -> Result<PathBuf, crate::error::AppError> {
    let mut path = app
        .path()
        .app_config_dir()
        .map_err(|e| crate::error::AppError::Internal(e.to_string()))?;
    path.push(FILE_ASSOCIATION_PROMPT_FILE_NAME);
    Ok(path)
}

fn read_file_association_preferences(
    app: &AppHandle,
) -> Result<FileAssociationPreferences, crate::error::AppError> {
    let path = get_file_association_preferences_path(app)?;

    if !path.exists() {
        return Ok(FileAssociationPreferences::default());
    }

    let content =
        fs::read_to_string(&path).map_err(|e| crate::error::AppError::Internal(e.to_string()))?;
    serde_json::from_str(&content).map_err(|e| crate::error::AppError::Internal(e.to_string()))
}

fn write_file_association_preferences(
    app: &AppHandle,
    preferences: &FileAssociationPreferences,
) -> Result<(), crate::error::AppError> {
    let path = get_file_association_preferences_path(app)?;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| crate::error::AppError::Internal(e.to_string()))?;
    }

    let content = serde_json::to_string_pretty(preferences)
        .map_err(|e| crate::error::AppError::Internal(e.to_string()))?;
    fs::write(path, content).map_err(|e| crate::error::AppError::Internal(e.to_string()))
}

#[cfg(target_os = "windows")]
fn get_expected_open_command() -> Result<String, crate::error::AppError> {
    let executable_path =
        std::env::current_exe().map_err(|e| crate::error::AppError::Internal(e.to_string()))?;

    if let Some(launcher_path) = resolve_dev_launcher_path(&executable_path) {
        return Ok(format!(
            "\"{}\" -OpenPath \"%1\"",
            launcher_path.to_string_lossy()
        ));
    }

    Ok(format!("\"{}\" \"%1\"", executable_path.to_string_lossy()))
}

#[cfg(target_os = "windows")]
fn resolve_dev_launcher_path(executable_path: &Path) -> Option<PathBuf> {
    let debug_dir = executable_path.parent()?;
    if !debug_dir
        .file_name()
        .and_then(|value| value.to_str())
        .map(|value| value.eq_ignore_ascii_case("debug"))
        .unwrap_or(false)
    {
        return None;
    }

    let target_dir = debug_dir.parent()?;
    if !target_dir
        .file_name()
        .and_then(|value| value.to_str())
        .map(|value| value.eq_ignore_ascii_case("target"))
        .unwrap_or(false)
    {
        return None;
    }

    let src_tauri_dir = target_dir.parent()?;
    if !src_tauri_dir
        .file_name()
        .and_then(|value| value.to_str())
        .map(|value| value.eq_ignore_ascii_case("src-tauri"))
        .unwrap_or(false)
    {
        return None;
    }

    let repo_root = src_tauri_dir.parent()?;
    let launcher_path = repo_root.join("Launch-CMTraceOpen.cmd");
    launcher_path.is_file().then_some(launcher_path)
}

#[cfg(target_os = "windows")]
fn normalize_registry_value(value: &str) -> String {
    value.trim().replace('/', "\\").to_ascii_lowercase()
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn has_visible_application_capabilities(
    application_name: &str,
    application_description: &str,
) -> bool {
    application_name == REGISTERED_APPLICATION_NAME && !application_description.trim().is_empty()
}

#[cfg(target_os = "windows")]
fn is_log_file_handler_registered() -> Result<bool, crate::error::AppError> {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;

    let expected_command = normalize_registry_value(&get_expected_open_command()?);
    let current_user = RegKey::predef(HKEY_CURRENT_USER);

    let registered_applications = match current_user.open_subkey("Software\\RegisteredApplications")
    {
        Ok(key) => key,
        Err(_) => return Ok(false),
    };
    let capabilities_path: String =
        match registered_applications.get_value(REGISTERED_APPLICATION_NAME) {
            Ok(value) => value,
            Err(_) => return Ok(false),
        };
    if capabilities_path != FILE_ASSOCIATION_CAPABILITIES_PATH {
        return Ok(false);
    }

    let capabilities = match current_user.open_subkey(FILE_ASSOCIATION_CAPABILITIES_PATH) {
        Ok(key) => key,
        Err(_) => return Ok(false),
    };
    let application_name: String = match capabilities.get_value("ApplicationName") {
        Ok(value) => value,
        Err(_) => return Ok(false),
    };
    let application_description: String = match capabilities.get_value("ApplicationDescription") {
        Ok(value) => value,
        Err(_) => return Ok(false),
    };
    if !has_visible_application_capabilities(&application_name, &application_description) {
        return Ok(false);
    }

    let file_associations = match capabilities.open_subkey("FileAssociations") {
        Ok(key) => key,
        Err(_) => return Ok(false),
    };
    for extension in LOG_FILE_EXTENSIONS {
        let prog_id: String = match file_associations.get_value(extension) {
            Ok(value) => value,
            Err(_) => return Ok(false),
        };
        if prog_id != FILE_ASSOCIATION_PROG_ID {
            return Ok(false);
        }
    }

    let classes = match current_user.open_subkey("Software\\Classes") {
        Ok(key) => key,
        Err(_) => return Ok(false),
    };

    for extension in LOG_FILE_EXTENSIONS {
        let open_with_prog_ids =
            match classes.open_subkey(format!("{}\\OpenWithProgids", extension)) {
                Ok(key) => key,
                Err(_) => return Ok(false),
            };
        let registration: String = match open_with_prog_ids.get_value(FILE_ASSOCIATION_PROG_ID) {
            Ok(value) => value,
            Err(_) => return Ok(false),
        };
        if !registration.is_empty() {
            return Ok(false);
        }
    }

    let command_key = classes
        .open_subkey(format!(
            "{}\\shell\\open\\command",
            FILE_ASSOCIATION_PROG_ID
        ))
        .map_err(|e| crate::error::AppError::Internal(e.to_string()))?;
    let command_value: String = command_key
        .get_value("")
        .map_err(|e| crate::error::AppError::Internal(e.to_string()))?;

    Ok(normalize_registry_value(&command_value) == expected_command)
}

#[cfg(target_os = "windows")]
fn register_log_file_handler_for_current_user() -> Result<(), crate::error::AppError> {
    use windows::Win32::UI::Shell::{SHChangeNotify, SHCNE_ASSOCCHANGED, SHCNF_IDLIST};
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;

    let current_user = RegKey::predef(HKEY_CURRENT_USER);
    let classes = current_user
        .create_subkey("Software\\Classes")
        .map_err(|e| crate::error::AppError::Internal(e.to_string()))?
        .0;

    let executable_path =
        std::env::current_exe().map_err(|e| crate::error::AppError::Internal(e.to_string()))?;
    let executable_path_str = executable_path.to_string_lossy().to_string();
    let open_command = get_expected_open_command()?;

    let (prog_id_key, _) = classes
        .create_subkey(FILE_ASSOCIATION_PROG_ID)
        .map_err(|e| crate::error::AppError::Internal(e.to_string()))?;
    prog_id_key
        .set_value("", &"CMTrace Open Log File")
        .map_err(|e| crate::error::AppError::Internal(e.to_string()))?;

    let (default_icon_key, _) = prog_id_key
        .create_subkey("DefaultIcon")
        .map_err(|e| crate::error::AppError::Internal(e.to_string()))?;
    default_icon_key
        .set_value("", &format!("\"{}\",0", executable_path_str))
        .map_err(|e| crate::error::AppError::Internal(e.to_string()))?;

    let (command_key, _) = prog_id_key
        .create_subkey("shell\\open\\command")
        .map_err(|e| crate::error::AppError::Internal(e.to_string()))?;
    command_key
        .set_value("", &open_command)
        .map_err(|e| crate::error::AppError::Internal(e.to_string()))?;

    let (registered_applications, _) = current_user
        .create_subkey("Software\\RegisteredApplications")
        .map_err(|e| crate::error::AppError::Internal(e.to_string()))?;
    registered_applications
        .set_value(
            REGISTERED_APPLICATION_NAME,
            &FILE_ASSOCIATION_CAPABILITIES_PATH,
        )
        .map_err(|e| crate::error::AppError::Internal(e.to_string()))?;

    let (capabilities, _) = current_user
        .create_subkey(FILE_ASSOCIATION_CAPABILITIES_PATH)
        .map_err(|e| crate::error::AppError::Internal(e.to_string()))?;
    capabilities
        .set_value("ApplicationName", &REGISTERED_APPLICATION_NAME)
        .map_err(|e| crate::error::AppError::Internal(e.to_string()))?;
    capabilities
        .set_value(
            "ApplicationDescription",
            &"Open and analyze Windows, ConfigMgr, Intune, and Autopilot log files.",
        )
        .map_err(|e| crate::error::AppError::Internal(e.to_string()))?;
    let (file_associations, _) = capabilities
        .create_subkey("FileAssociations")
        .map_err(|e| crate::error::AppError::Internal(e.to_string()))?;

    // Advertise a candidate through Default Apps and Open With. Do not write
    // an extension's default value or Windows' protected UserChoice state.
    for extension in LOG_FILE_EXTENSIONS {
        file_associations
            .set_value(extension, &FILE_ASSOCIATION_PROG_ID)
            .map_err(|e| crate::error::AppError::Internal(e.to_string()))?;
        let (open_with_prog_ids, _) = classes
            .create_subkey(format!("{}\\OpenWithProgids", extension))
            .map_err(|e| crate::error::AppError::Internal(e.to_string()))?;
        open_with_prog_ids
            .set_value(FILE_ASSOCIATION_PROG_ID, &"")
            .map_err(|e| crate::error::AppError::Internal(e.to_string()))?;
    }

    // New handler registrations are not guaranteed to appear until the Shell
    // invalidates its association cache.
    unsafe {
        SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, None, None);
    }

    Ok(())
}

#[cfg(target_os = "windows")]
fn launch_windows_default_apps() -> Result<(), crate::error::AppError> {
    use windows::core::{w, PCWSTR};
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    let settings_uri: Vec<u16> = DEFAULT_APPS_SETTINGS_URI
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let result = unsafe {
        ShellExecuteW(
            None,
            w!("open"),
            PCWSTR::from_raw(settings_uri.as_ptr()),
            PCWSTR::null(),
            PCWSTR::null(),
            SW_SHOWNORMAL,
        )
    };

    let status = result.0 as usize;
    if status <= 32 {
        return Err(crate::error::AppError::Internal(format!(
            "Windows could not open Default Apps settings (ShellExecute status {status})."
        )));
    }

    Ok(())
}

#[tauri::command]
pub fn get_file_association_prompt_status(
    app: AppHandle,
) -> Result<FileAssociationPromptStatus, crate::error::AppError> {
    let preferences = read_file_association_preferences(&app)?;

    #[cfg(target_os = "windows")]
    {
        let is_registered = is_log_file_handler_registered()?;
        Ok(FileAssociationPromptStatus {
            supported: true,
            should_prompt: !preferences.suppress_prompt && !is_registered,
            is_registered,
        })
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = preferences;
        let _ = app;
        Ok(FileAssociationPromptStatus {
            supported: false,
            should_prompt: false,
            is_registered: false,
        })
    }
}

#[tauri::command]
pub fn register_log_file_handler(app: AppHandle) -> Result<(), crate::error::AppError> {
    #[cfg(target_os = "windows")]
    {
        register_log_file_handler_for_current_user()?;
        write_file_association_preferences(
            &app,
            &FileAssociationPreferences {
                suppress_prompt: false,
            },
        )?;
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = app;
        Err(crate::error::AppError::PlatformUnsupported(
            "File handler registration is only supported on Windows.".to_string(),
        ))
    }
}

#[tauri::command]
pub fn open_windows_default_apps() -> Result<(), crate::error::AppError> {
    #[cfg(target_os = "windows")]
    {
        launch_windows_default_apps()
    }

    #[cfg(not(target_os = "windows"))]
    {
        Err(crate::error::AppError::PlatformUnsupported(
            "Windows Default Apps settings are only available on Windows.".to_string(),
        ))
    }
}

#[tauri::command]
pub fn set_file_association_prompt_suppressed(
    app: AppHandle,
    suppressed: bool,
) -> Result<(), crate::error::AppError> {
    write_file_association_preferences(
        &app,
        &FileAssociationPreferences {
            suppress_prompt: suppressed,
        },
    )
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::{has_visible_application_capabilities, LOG_FILE_EXTENSIONS};

    #[test]
    fn log_file_extensions_include_each_unique_rotation() {
        assert_eq!(LOG_FILE_EXTENSIONS, &[".log", ".lo_", ".log_", ".cmtlog"]);

        let unique_extensions: HashSet<_> = LOG_FILE_EXTENSIONS.iter().copied().collect();
        assert_eq!(unique_extensions.len(), LOG_FILE_EXTENSIONS.len());
    }

    #[test]
    fn visible_registration_requires_the_expected_name_and_a_description() {
        assert!(has_visible_application_capabilities(
            "CMTrace Open",
            "Open and analyze log files.",
        ));
        assert!(!has_visible_application_capabilities("CMTrace Open", "   "));
        assert!(!has_visible_application_capabilities(
            "Another App",
            "Open and analyze log files.",
        ));
    }
}
