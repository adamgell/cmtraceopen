use std::fs;
use std::path::PathBuf;

#[cfg(target_os = "windows")]
use std::path::Path;

use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
const LOG_FILE_EXTENSIONS: &[&str] = &[".log", ".lo_", ".log_", ".cmtlog"];
const FILE_ASSOCIATION_PROMPT_FILE_PREFIX: &str = "file-association-preferences";

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
struct FileAssociationIdentity {
    application_name: String,
    prog_id: String,
    capabilities_path: String,
    default_apps_settings_uri: String,
    preferences_file_name: String,
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn file_association_identity(
    product_name: Option<&str>,
) -> Result<FileAssociationIdentity, crate::error::AppError> {
    let application_name = product_name.ok_or_else(|| {
        crate::error::AppError::InvalidInput(
            "The configured product name is required for file handler registration.".to_string(),
        )
    })?;
    let registry_stem = match application_name {
        "CMTrace Open" => "CMTraceOpen",
        "CMTrace Open Lite" => "CMTraceOpenLite",
        "CMTrace Open Nightly" => "CMTraceOpenNightly",
        "CMTrace Open Lite Nightly" => "CMTraceOpenLiteNightly",
        _ => {
            return Err(crate::error::AppError::InvalidInput(format!(
                "File handler registration is not configured for product {application_name:?}."
            )))
        }
    };
    let encoded_application_name = utf8_percent_encode(application_name, NON_ALPHANUMERIC);
    let default_apps_settings_uri =
        format!("ms-settings:defaultapps?registeredAppUser={encoded_application_name}");

    Ok(FileAssociationIdentity {
        application_name: application_name.to_string(),
        prog_id: format!("{registry_stem}.LogFile"),
        capabilities_path: format!("Software\\{registry_stem}\\Capabilities"),
        default_apps_settings_uri,
        preferences_file_name: format!(
            "{FILE_ASSOCIATION_PROMPT_FILE_PREFIX}-{registry_stem}.json"
        ),
    })
}

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
    identity: &FileAssociationIdentity,
) -> Result<PathBuf, crate::error::AppError> {
    let mut path = app
        .path()
        .app_config_dir()
        .map_err(|e| crate::error::AppError::Internal(e.to_string()))?;
    path.push(&identity.preferences_file_name);
    Ok(path)
}

fn read_file_association_preferences(
    app: &AppHandle,
    identity: &FileAssociationIdentity,
) -> Result<FileAssociationPreferences, crate::error::AppError> {
    let path = get_file_association_preferences_path(app, identity)?;

    if !path.exists() {
        return Ok(FileAssociationPreferences::default());
    }

    let content =
        fs::read_to_string(&path).map_err(|e| crate::error::AppError::Internal(e.to_string()))?;
    serde_json::from_str(&content).map_err(|e| crate::error::AppError::Internal(e.to_string()))
}

fn write_file_association_preferences(
    app: &AppHandle,
    identity: &FileAssociationIdentity,
    preferences: &FileAssociationPreferences,
) -> Result<(), crate::error::AppError> {
    let path = get_file_association_preferences_path(app, identity)?;

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
    expected_application_name: &str,
    application_name: &str,
    application_description: &str,
) -> bool {
    application_name == expected_application_name && !application_description.trim().is_empty()
}

#[cfg(any(target_os = "windows", test))]
fn optional_registry_entry<T>(
    result: std::io::Result<T>,
) -> Result<Option<T>, crate::error::AppError> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(crate::error::AppError::Internal(error.to_string())),
    }
}

#[cfg(target_os = "windows")]
fn is_log_file_handler_registered(
    identity: &FileAssociationIdentity,
) -> Result<bool, crate::error::AppError> {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;

    let expected_command = normalize_registry_value(&get_expected_open_command()?);
    let current_user = RegKey::predef(HKEY_CURRENT_USER);

    let registered_applications = match optional_registry_entry(
        current_user.open_subkey("Software\\RegisteredApplications"),
    )? {
        Some(key) => key,
        None => return Ok(false),
    };
    let capabilities_path: String = match optional_registry_entry(
        registered_applications.get_value(identity.application_name.as_str()),
    )? {
        Some(value) => value,
        None => return Ok(false),
    };
    if capabilities_path != identity.capabilities_path {
        return Ok(false);
    }

    let capabilities = match optional_registry_entry(
        current_user.open_subkey(identity.capabilities_path.as_str()),
    )? {
        Some(key) => key,
        None => return Ok(false),
    };
    let application_name: String =
        match optional_registry_entry(capabilities.get_value("ApplicationName"))? {
            Some(value) => value,
            None => return Ok(false),
        };
    let application_description: String =
        match optional_registry_entry(capabilities.get_value("ApplicationDescription"))? {
            Some(value) => value,
            None => return Ok(false),
        };
    if !has_visible_application_capabilities(
        &identity.application_name,
        &application_name,
        &application_description,
    ) {
        return Ok(false);
    }

    let file_associations =
        match optional_registry_entry(capabilities.open_subkey("FileAssociations"))? {
            Some(key) => key,
            None => return Ok(false),
        };
    for extension in LOG_FILE_EXTENSIONS {
        let prog_id: String = match optional_registry_entry(file_associations.get_value(extension))?
        {
            Some(value) => value,
            None => return Ok(false),
        };
        if prog_id != identity.prog_id {
            return Ok(false);
        }
    }

    let classes = match optional_registry_entry(current_user.open_subkey("Software\\Classes"))? {
        Some(key) => key,
        None => return Ok(false),
    };

    for extension in LOG_FILE_EXTENSIONS {
        let open_with_prog_ids = match optional_registry_entry(
            classes.open_subkey(format!("{}\\OpenWithProgids", extension)),
        )? {
            Some(key) => key,
            None => return Ok(false),
        };
        let registration: String =
            match optional_registry_entry(open_with_prog_ids.get_value(identity.prog_id.as_str()))?
            {
                Some(value) => value,
                None => return Ok(false),
            };
        if !registration.is_empty() {
            return Ok(false);
        }
    }

    let command_key = match optional_registry_entry(
        classes.open_subkey(format!("{}\\shell\\open\\command", identity.prog_id)),
    )? {
        Some(key) => key,
        None => return Ok(false),
    };
    let command_value: String = match optional_registry_entry(command_key.get_value(""))? {
        Some(value) => value,
        None => return Ok(false),
    };

    Ok(normalize_registry_value(&command_value) == expected_command)
}

#[cfg(target_os = "windows")]
fn register_log_file_handler_for_current_user(
    identity: &FileAssociationIdentity,
) -> Result<(), crate::error::AppError> {
    use windows::Win32::UI::Shell::{
        SHChangeNotify, SHCNE_ASSOCCHANGED, SHCNF_FLUSH, SHCNF_IDLIST,
    };
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
        .create_subkey(identity.prog_id.as_str())
        .map_err(|e| crate::error::AppError::Internal(e.to_string()))?;
    prog_id_key
        .set_value("", &format!("{} Log File", identity.application_name))
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
            identity.application_name.as_str(),
            &identity.capabilities_path,
        )
        .map_err(|e| crate::error::AppError::Internal(e.to_string()))?;

    let (capabilities, _) = current_user
        .create_subkey(identity.capabilities_path.as_str())
        .map_err(|e| crate::error::AppError::Internal(e.to_string()))?;
    capabilities
        .set_value("ApplicationName", &identity.application_name)
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
            .set_value(extension, &identity.prog_id)
            .map_err(|e| crate::error::AppError::Internal(e.to_string()))?;
        let (open_with_prog_ids, _) = classes
            .create_subkey(format!("{}\\OpenWithProgids", extension))
            .map_err(|e| crate::error::AppError::Internal(e.to_string()))?;
        open_with_prog_ids
            .set_value(identity.prog_id.as_str(), &"")
            .map_err(|e| crate::error::AppError::Internal(e.to_string()))?;
    }

    // Wait for the Shell to invalidate its association cache before the caller
    // immediately verifies the registration and opens Default Apps.
    unsafe {
        SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST | SHCNF_FLUSH, None, None);
    }

    Ok(())
}

#[cfg(target_os = "windows")]
fn launch_windows_default_apps(
    identity: &FileAssociationIdentity,
) -> Result<(), crate::error::AppError> {
    use windows::core::{w, PCWSTR};
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    let settings_uri: Vec<u16> = identity
        .default_apps_settings_uri
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

#[cfg(any(target_os = "windows", test))]
async fn run_file_association_operation<F, R>(operation: F) -> Result<R, crate::error::AppError>
where
    F: FnOnce() -> Result<R, crate::error::AppError> + Send + 'static,
    R: Send + 'static,
{
    tauri::async_runtime::spawn_blocking(operation)
        .await
        .map_err(|error| {
            crate::error::AppError::Internal(format!(
                "FileAssociationRegistrationTaskFailed: {error}"
            ))
        })?
}

#[tauri::command]
pub fn get_file_association_prompt_status(
    app: AppHandle,
) -> Result<FileAssociationPromptStatus, crate::error::AppError> {
    let identity = file_association_identity(app.config().product_name.as_deref())?;
    let preferences = read_file_association_preferences(&app, &identity)?;

    #[cfg(target_os = "windows")]
    {
        let is_registered = is_log_file_handler_registered(&identity)?;
        Ok(FileAssociationPromptStatus {
            supported: true,
            should_prompt: !preferences.suppress_prompt && !is_registered,
            is_registered,
        })
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = identity;
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
pub async fn register_log_file_handler(app: AppHandle) -> Result<(), crate::error::AppError> {
    #[cfg(target_os = "windows")]
    {
        let identity = file_association_identity(app.config().product_name.as_deref())?;
        run_file_association_operation(move || {
            register_log_file_handler_for_current_user(&identity)
        })
        .await
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
pub fn open_windows_default_apps(app: AppHandle) -> Result<(), crate::error::AppError> {
    #[cfg(target_os = "windows")]
    {
        let identity = file_association_identity(app.config().product_name.as_deref())?;
        launch_windows_default_apps(&identity)
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = app;
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
    let identity = file_association_identity(app.config().product_name.as_deref())?;
    write_file_association_preferences(
        &app,
        &identity,
        &FileAssociationPreferences {
            suppress_prompt: suppressed,
        },
    )
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::fs;
    use std::path::Path;

    use super::{
        file_association_identity, has_visible_application_capabilities, optional_registry_entry,
        run_file_association_operation, LOG_FILE_EXTENSIONS,
    };

    #[test]
    fn registration_operations_run_on_the_blocking_pool() {
        let caller = std::thread::current().id();
        let worker = tauri::async_runtime::block_on(run_file_association_operation(|| {
            Ok(std::thread::current().id())
        }))
        .expect("blocking registration operation completes");

        assert_ne!(worker, caller, "registry I/O must leave the caller thread");
    }

    #[test]
    fn handler_identity_is_bounded_and_distinct_for_every_shipped_product() {
        let cases = [
            (
                "CMTrace Open",
                "CMTraceOpen.LogFile",
                "Software\\CMTraceOpen\\Capabilities",
                "ms-settings:defaultapps?registeredAppUser=CMTrace%20Open",
                "file-association-preferences-CMTraceOpen.json",
            ),
            (
                "CMTrace Open Lite",
                "CMTraceOpenLite.LogFile",
                "Software\\CMTraceOpenLite\\Capabilities",
                "ms-settings:defaultapps?registeredAppUser=CMTrace%20Open%20Lite",
                "file-association-preferences-CMTraceOpenLite.json",
            ),
            (
                "CMTrace Open Nightly",
                "CMTraceOpenNightly.LogFile",
                "Software\\CMTraceOpenNightly\\Capabilities",
                "ms-settings:defaultapps?registeredAppUser=CMTrace%20Open%20Nightly",
                "file-association-preferences-CMTraceOpenNightly.json",
            ),
            (
                "CMTrace Open Lite Nightly",
                "CMTraceOpenLiteNightly.LogFile",
                "Software\\CMTraceOpenLiteNightly\\Capabilities",
                "ms-settings:defaultapps?registeredAppUser=CMTrace%20Open%20Lite%20Nightly",
                "file-association-preferences-CMTraceOpenLiteNightly.json",
            ),
        ];
        let mut prog_ids = HashSet::new();
        let mut capabilities_paths = HashSet::new();
        let mut settings_uris = HashSet::new();
        let mut preferences_file_names = HashSet::new();

        for (
            product_name,
            expected_prog_id,
            expected_capabilities_path,
            expected_uri,
            expected_preferences_file_name,
        ) in cases
        {
            let identity = file_association_identity(Some(product_name))
                .expect("shipped product name must have an association identity");

            assert_eq!(identity.application_name, product_name);
            assert_eq!(identity.prog_id, expected_prog_id);
            assert_eq!(identity.capabilities_path, expected_capabilities_path);
            assert_eq!(identity.default_apps_settings_uri, expected_uri);
            assert_eq!(
                identity.preferences_file_name,
                expected_preferences_file_name
            );
            prog_ids.insert(identity.prog_id);
            capabilities_paths.insert(identity.capabilities_path);
            settings_uris.insert(identity.default_apps_settings_uri);
            preferences_file_names.insert(identity.preferences_file_name);
        }

        assert_eq!(prog_ids.len(), cases.len());
        assert_eq!(capabilities_paths.len(), cases.len());
        assert_eq!(settings_uris.len(), cases.len());
        assert_eq!(preferences_file_names.len(), cases.len());
    }

    #[test]
    fn handler_identity_rejects_unconfigured_product_names() {
        for product_name in [
            None,
            Some(""),
            Some("CMTrace Open Beta"),
            Some("Another App"),
        ] {
            assert!(matches!(
                file_association_identity(product_name),
                Err(crate::error::AppError::InvalidInput(_))
            ));
        }
    }

    fn load_tauri_config(file_name: &str) -> serde_json::Value {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(file_name);
        let contents = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
        serde_json::from_str(&contents)
            .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()))
    }

    fn load_installer_asset(file_name: &str) -> String {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("installer")
            .join(file_name);
        fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
    }

    #[test]
    fn windows_packaging_disables_installer_associations_without_removing_other_platforms() {
        let base_config = load_tauri_config("tauri.conf.json");
        let base_associations = base_config
            .pointer("/bundle/fileAssociations")
            .and_then(serde_json::Value::as_array)
            .expect("base bundle.fileAssociations must be an array");
        let mut base_extensions: Vec<_> = base_associations
            .iter()
            .flat_map(|association| {
                association
                    .get("ext")
                    .and_then(serde_json::Value::as_array)
                    .into_iter()
                    .flatten()
            })
            .map(|extension| {
                extension
                    .as_str()
                    .expect("file association extensions must be strings")
            })
            .collect();
        base_extensions.sort_unstable();

        assert_eq!(base_extensions, ["cmtlog", "lo_", "log", "log_"]);

        let windows_config = load_tauri_config("tauri.windows.conf.json");
        let windows_associations = windows_config
            .pointer("/bundle/fileAssociations")
            .and_then(serde_json::Value::as_array)
            .expect("Windows bundle.fileAssociations override must be an array");

        assert!(windows_associations.is_empty());
    }

    #[test]
    fn log_file_extensions_include_each_unique_rotation() {
        assert_eq!(LOG_FILE_EXTENSIONS, &[".log", ".lo_", ".log_", ".cmtlog"]);

        let unique_extensions: HashSet<_> = LOG_FILE_EXTENSIONS.iter().copied().collect();
        assert_eq!(unique_extensions.len(), LOG_FILE_EXTENSIONS.len());
    }

    #[test]
    fn nsis_uninstall_cleanup_is_scoped_and_preserves_replacement_installs() {
        let config = load_tauri_config("tauri.conf.json");
        assert_eq!(
            config
                .pointer("/bundle/windows/nsis/installerHooks")
                .and_then(serde_json::Value::as_str),
            Some("installer/windows-installer-hooks.nsh")
        );
        let hook = load_installer_asset("windows-installer-hooks.nsh");

        assert!(hook.contains("${If} $UpdateMode = 1"));
        assert!(hook.contains("${GetOptions} $R0 \"_?=\" $R1"));
        assert!(hook
            .contains("CMTRACE_REMOVE_RUNTIME_FILE_ASSOCIATION \"CMTrace Open\" \"CMTraceOpen\""));
        assert!(hook.contains(
            "CMTRACE_REMOVE_RUNTIME_FILE_ASSOCIATION \"CMTrace Open Nightly\" \"CMTraceOpenNightly\""
        ));
        assert!(hook.contains(
            "CMTRACE_REMOVE_RUNTIME_FILE_ASSOCIATION \"CMTrace Open Lite\" \"CMTraceOpenLite\""
        ));
        assert!(hook.contains(
            "CMTRACE_REMOVE_RUNTIME_FILE_ASSOCIATION \"CMTrace Open Lite Nightly\" \"CMTraceOpenLiteNightly\""
        ));
        for extension in LOG_FILE_EXTENSIONS {
            assert!(
                hook.contains(&format!("Software\\Classes\\{extension}\\OpenWithProgids")),
                "NSIS cleanup must remove {extension} OpenWithProgids"
            );
        }
        assert!(hook.contains("SHChangeNotify"));
    }

    #[test]
    fn msi_uninstall_cleanup_covers_each_installed_edition_without_crossing_channels() {
        let package: serde_json::Value =
            serde_json::from_str(&load_installer_asset("package.signed.json"))
                .expect("signed MSI package configuration must be valid JSON");
        let actions = package
            .pointer("/msi/customActions/powershell")
            .and_then(serde_json::Value::as_array)
            .expect("MSI PowerShell custom actions must be an array");

        let cases = [
            (
                "src-tauri\\installer\\remove-stable-file-associations.ps1",
                "REMOVE~=\"ALL\" AND NOT UPGRADINGPRODUCTCODE AND ProductName=\"CMTrace Open\"",
                "remove-stable-file-associations.ps1",
                [
                    ("CMTrace Open", "CMTraceOpen"),
                    ("CMTrace Open Lite", "CMTraceOpenLite"),
                ],
                "CMTrace Open Nightly",
            ),
            (
                "src-tauri\\installer\\remove-nightly-file-associations.ps1",
                "REMOVE~=\"ALL\" AND NOT UPGRADINGPRODUCTCODE AND ProductName=\"CMTrace Open Nightly\"",
                "remove-nightly-file-associations.ps1",
                [
                    ("CMTrace Open Nightly", "CMTraceOpenNightly"),
                    ("CMTrace Open Lite Nightly", "CMTraceOpenLiteNightly"),
                ],
                "CMTrace Open\"; RegistryStem = \"CMTraceOpen\"",
            ),
        ];

        for (file_path, condition, script_name, identities, excluded_identity) in cases {
            let action = actions
                .iter()
                .find(|action| {
                    action.get("filePath").and_then(serde_json::Value::as_str) == Some(file_path)
                })
                .unwrap_or_else(|| panic!("missing MSI cleanup action {file_path}"));
            assert_eq!(
                action.get("condition").and_then(serde_json::Value::as_str),
                Some(condition)
            );
            assert_eq!(
                action.get("sequence").and_then(serde_json::Value::as_str),
                Some("EndOfExecution")
            );
            assert_eq!(
                action
                    .get("continueOnError")
                    .and_then(serde_json::Value::as_bool),
                Some(true)
            );

            let script = load_installer_asset(script_name);
            for (application_name, registry_stem) in identities {
                assert!(script.contains(&format!(
                    "ApplicationName = \"{application_name}\"; RegistryStem = \"{registry_stem}\""
                )));
            }
            assert!(!script.contains(excluded_identity));
            for extension in LOG_FILE_EXTENSIONS {
                assert!(script.contains(&format!("\"{extension}\"")));
            }
            assert!(script.contains("Registry::HKEY_USERS"));
            assert!(script.contains("ProfileList"));
            assert!(script.contains("SHChangeNotify"));
        }
    }

    #[test]
    fn visible_registration_requires_the_expected_name_and_a_description() {
        assert!(has_visible_application_capabilities(
            "CMTrace Open",
            "CMTrace Open",
            "Open and analyze log files.",
        ));
        assert!(!has_visible_application_capabilities(
            "CMTrace Open",
            "CMTrace Open",
            "   ",
        ));
        assert!(!has_visible_application_capabilities(
            "CMTrace Open",
            "Another App",
            "Open and analyze log files.",
        ));
    }

    #[test]
    fn registry_readback_only_treats_missing_entries_as_unregistered() {
        assert_eq!(optional_registry_entry(Ok(42)).unwrap(), Some(42));
        assert_eq!(
            optional_registry_entry::<i32>(Err(
                std::io::Error::from(std::io::ErrorKind::NotFound,)
            ))
            .unwrap(),
            None,
        );
        assert!(matches!(
            optional_registry_entry::<i32>(Err(std::io::Error::from(
                std::io::ErrorKind::PermissionDenied,
            ))),
            Err(crate::error::AppError::Internal(_))
        ));
    }
}
