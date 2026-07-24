use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemDateTimePreferences {
    pub date_pattern: String,
    pub time_pattern: String,
    pub am_designator: Option<String>,
    pub pm_designator: Option<String>,
}

#[tauri::command]
pub fn get_system_date_time_preferences(
) -> Result<SystemDateTimePreferences, crate::error::AppError> {
    #[cfg(target_os = "windows")]
    {
        use winreg::enums::HKEY_CURRENT_USER;
        use winreg::RegKey;

        let key = RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey("Control Panel\\International")
            .map_err(|error| {
                crate::error::AppError::Internal(format!(
                    "failed to open Windows international settings: {}",
                    error
                ))
            })?;

        let date_pattern: String = key.get_value("sShortDate").map_err(|error| {
            crate::error::AppError::Internal(format!(
                "failed to read Windows short date format: {}",
                error
            ))
        })?;

        let time_pattern: String = key
            .get_value("sTimeFormat")
            .or_else(|_| key.get_value("sShortTime"))
            .map_err(|error| {
                crate::error::AppError::Internal(format!(
                    "failed to read Windows time format: {}",
                    error
                ))
            })?;

        let am_designator = key
            .get_value::<String, _>("s1159")
            .ok()
            .filter(|value| !value.trim().is_empty());

        let pm_designator = key
            .get_value::<String, _>("s2359")
            .ok()
            .filter(|value| !value.trim().is_empty());

        Ok(SystemDateTimePreferences {
            date_pattern,
            time_pattern,
            am_designator,
            pm_designator,
        })
    }

    #[cfg(not(target_os = "windows"))]
    {
        Ok(SystemDateTimePreferences {
            date_pattern: "yyyy-MM-dd".to_string(),
            time_pattern: "HH:mm:ss".to_string(),
            am_designator: Some("AM".to_string()),
            pm_designator: Some("PM".to_string()),
        })
    }
}

/// Pin (or unpin) the main window as always-on-top and keep the Window menu's
/// checkbox in sync with the applied state. The frontend ui-store persists the
/// preference and re-applies it on startup, so this command is the single point
/// that actually touches the window and the menu.
#[tauri::command]
pub fn set_always_on_top<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    enabled: bool,
) -> Result<(), crate::error::AppError> {
    use tauri::menu::MenuItemKind;
    use tauri::Manager;

    if let Some(window) = app.get_webview_window("main") {
        window.set_always_on_top(enabled).map_err(|error| {
            crate::error::AppError::Internal(format!("failed to set always-on-top: {error}"))
        })?;
    }

    if let Some(menu) = app.menu() {
        if let Some(MenuItemKind::Check(item)) =
            menu.get(crate::menu::MENU_ID_WINDOW_ALWAYS_ON_TOP)
        {
            let _ = item.set_checked(enabled);
        }
    }

    Ok(())
}
