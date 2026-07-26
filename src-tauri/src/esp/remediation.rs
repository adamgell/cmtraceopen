//! ESP remediation: force a failed ESP-tracked app past the Enrollment Status
//! Page by flipping its per-app Sidecar `InstallationState` 4 (Failed) -> 3
//! (Installed) and clearing `ErrorHresult`, taking a targeted backup first so the
//! change is one-click reversible.
//!
//! This is the tool's only device-mutating action. It is Windows-only, requires
//! elevation (HKLM write), and does NOT install the app -- it only stops ESP from
//! blocking on the failed app. The caller is responsible for confirming intent.

use serde::{Deserialize, Serialize};

#[cfg(windows)]
const SIDECAR_KEY: &str = r"SOFTWARE\Microsoft\Windows\Autopilot\EnrollmentStatusTracking\Device\Setup\Apps\Tracking\Sidecar";

/// The prior values of the app's Sidecar tracking key, captured before the flip.
/// `None` means the value did not exist and should be deleted on restore.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EspAppFlipBackup {
    pub app_id: String,
    pub installation_state: Option<u32>,
    pub error_hresult: Option<u32>,
}

/// Outcome of a flip: the new state plus the backup needed to undo it.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EspAppFlipResult {
    pub app_id: String,
    pub installation_state: u32,
    pub backup: EspAppFlipBackup,
}

/// The app id is written as a single registry subkey name, so it must be one safe
/// segment -- alphanumerics, underscore, or hyphen only -- to prevent escaping the
/// Sidecar key (no separators, no `..` traversal).
pub fn validate_app_id(app_id: &str) -> Result<(), String> {
    let safe = !app_id.is_empty()
        && app_id.len() <= 256
        && app_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if safe {
        Ok(())
    } else {
        Err(format!(
            "Refusing to write an unexpected app identifier: {app_id:?}"
        ))
    }
}

#[cfg(windows)]
fn open_app_key(app_id: &str) -> Result<winreg::RegKey, String> {
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE};
    use winreg::RegKey;

    validate_app_id(app_id)?;
    let path = format!(r"{SIDECAR_KEY}\{app_id}");
    RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags(&path, KEY_READ | KEY_WRITE)
        .map_err(|error| {
            format!("Could not open the app's ESP tracking key (run elevated): {error}")
        })
}

#[cfg(windows)]
pub fn flip_app_installed(app_id: &str) -> Result<EspAppFlipResult, String> {
    let key = open_app_key(app_id)?;
    let backup = EspAppFlipBackup {
        app_id: app_id.to_string(),
        installation_state: key.get_value::<u32, _>("InstallationState").ok(),
        error_hresult: key.get_value::<u32, _>("ErrorHresult").ok(),
    };
    key.set_value("InstallationState", &3u32)
        .map_err(|error| format!("Failed to set InstallationState: {error}"))?;
    // Clear the recorded failure so ESP does not re-read it; absence is fine.
    let _ = key.delete_value("ErrorHresult");
    Ok(EspAppFlipResult {
        app_id: app_id.to_string(),
        installation_state: 3,
        backup,
    })
}

#[cfg(windows)]
pub fn restore_app_state(backup: &EspAppFlipBackup) -> Result<(), String> {
    let key = open_app_key(&backup.app_id)?;
    match backup.installation_state {
        Some(value) => key
            .set_value("InstallationState", &value)
            .map_err(|error| format!("Failed to restore InstallationState: {error}"))?,
        None => {
            let _ = key.delete_value("InstallationState");
        }
    }
    match backup.error_hresult {
        Some(value) => key
            .set_value("ErrorHresult", &value)
            .map_err(|error| format!("Failed to restore ErrorHresult: {error}"))?,
        None => {
            let _ = key.delete_value("ErrorHresult");
        }
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn flip_app_installed(app_id: &str) -> Result<EspAppFlipResult, String> {
    validate_app_id(app_id)?;
    Err("Forcing an app's ESP state is only available on Windows.".to_string())
}

#[cfg(not(windows))]
pub fn restore_app_state(backup: &EspAppFlipBackup) -> Result<(), String> {
    validate_app_id(&backup.app_id)?;
    Err("Restoring an app's ESP state is only available on Windows.".to_string())
}

#[cfg(test)]
mod tests {
    use super::validate_app_id;

    #[test]
    fn accepts_a_decorated_win32_app_id() {
        assert!(validate_app_id("Win32App_431bae97-f077-4f2d-9102-78ed781451e9_1").is_ok());
    }

    #[test]
    fn rejects_separators_traversal_and_stray_characters() {
        assert!(validate_app_id("").is_err());
        assert!(validate_app_id(r"Win32App\..\..\Software").is_err());
        assert!(validate_app_id("foo/bar").is_err());
        assert!(validate_app_id("..").is_err());
        assert!(validate_app_id("dot.segment").is_err());
        assert!(validate_app_id("has space").is_err());
        assert!(validate_app_id("{58976ff3-87ca-4691-bdfc-671f37f07cb6}").is_err());
    }
}
