use std::fs;
use std::path::PathBuf;

#[cfg(target_os = "windows")]
use std::path::Path;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};

#[cfg(target_os = "windows")]
const FILE_ASSOCIATION_PROG_ID: &str = "CMTraceOpen.LogFile";
const FILE_ASSOCIATION_PROMPT_FILE_NAME: &str = "file-association-preferences.json";

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileAssociationPromptStatus {
    pub supported: bool,
    pub should_prompt: bool,
    pub is_associated: bool,
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

#[cfg(target_os = "windows")]
fn is_app_associated_with_log_extensions() -> Result<bool, crate::error::AppError> {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;

    let expected_command = normalize_registry_value(&get_expected_open_command()?);
    let classes = RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey("Software\\Classes")
        .map_err(|e| crate::error::AppError::Internal(e.to_string()))?;

    for extension in [".log", ".lo_"] {
        let extension_key = match classes.open_subkey(extension) {
            Ok(key) => key,
            Err(_) => return Ok(false),
        };

        let prog_id: String = extension_key
            .get_value("")
            .map_err(|e| crate::error::AppError::Internal(e.to_string()))?;

        if prog_id != FILE_ASSOCIATION_PROG_ID {
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
fn associate_log_extensions_with_app() -> Result<(), crate::error::AppError> {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;

    let classes = RegKey::predef(HKEY_CURRENT_USER)
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

    for extension in [".log", ".lo_"] {
        let (extension_key, _) = classes
            .create_subkey(extension)
            .map_err(|e| crate::error::AppError::Internal(e.to_string()))?;
        extension_key
            .set_value("", &FILE_ASSOCIATION_PROG_ID)
            .map_err(|e| crate::error::AppError::Internal(e.to_string()))?;
        extension_key
            .set_value("Content Type", &"text/plain")
            .map_err(|e| crate::error::AppError::Internal(e.to_string()))?;
        extension_key
            .set_value("PerceivedType", &"text")
            .map_err(|e| crate::error::AppError::Internal(e.to_string()))?;
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
        let is_associated = is_app_associated_with_log_extensions()?;
        Ok(FileAssociationPromptStatus {
            supported: true,
            should_prompt: !preferences.suppress_prompt && !is_associated,
            is_associated,
        })
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = preferences;
        let _ = app;
        Ok(FileAssociationPromptStatus {
            supported: false,
            should_prompt: false,
            is_associated: false,
        })
    }
}

#[tauri::command]
pub fn associate_log_files_with_app(app: AppHandle) -> Result<(), crate::error::AppError> {
    #[cfg(target_os = "windows")]
    {
        associate_log_extensions_with_app()?;
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
            "File association is only supported on Windows.".to_string(),
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
