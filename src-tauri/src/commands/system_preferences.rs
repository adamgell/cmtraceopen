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
