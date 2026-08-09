use std::path::PathBuf;

pub const JAMF_BINARY: &str = "/usr/local/bin/jamf";
pub const JAMF_LOG: &str = "/var/log/jamf.log";
pub const JAMF_APP_SUPPORT: &str = "/Library/Application Support/JAMF";
pub const JAMF_RECEIPTS: &str = "/Library/Application Support/JAMF/Receipts";
pub const JAMF_PLIST: &str = "/Library/Preferences/com.jamfsoftware.jamf.plist";
pub const JAMF_CONNECT_APP: &str = "/Applications/Jamf Connect.app";
/// Pre-2020 bundle name. macOS volumes are case-insensitive by default, so this
/// only differs from [`JAMF_CONNECT_APP`] on a case-sensitive volume.
pub const JAMF_CONNECT_APP_LEGACY: &str = "/Applications/JAMF Connect.app";
pub const JAMF_CONNECT_PLIST: &str = "/Library/Preferences/com.jamf.connect.plist";
pub const JAMF_CONNECT_LOG_SYSTEM: &str = "/Library/Logs/JAMFConnect.log";
/// System-level support directory installed by the JAMF Connect package. Present
/// (with `JCDaemon.app` and a `Logs/` directory) even when the menu-bar app
/// itself is not deployed to `/Applications`.
pub const JAMF_CONNECT_APP_SUPPORT: &str = "/Library/Application Support/JamfConnect";
pub const SELF_SERVICE_APP: &str = "/Applications/Self Service.app";

/// JAMF Connect settings are delivered by MDM, so the live values land in
/// `/Library/Managed Preferences`, not `/Library/Preferences`. Ordered
/// most-authoritative first; each entry is a `(plist, key)` pair because the
/// IdP key differs between the login and main preference domains.
pub const JAMF_CONNECT_IDP_SOURCES: &[(&str, &str)] = &[
    (
        "/Library/Managed Preferences/com.jamf.connect.login.plist",
        "OIDCProvider",
    ),
    (
        "/Library/Managed Preferences/com.jamf.connect.plist",
        "Provider",
    ),
    (
        "/Library/Preferences/com.jamf.connect.login.plist",
        "OIDCProvider",
    ),
    ("/Library/Preferences/com.jamf.connect.plist", "Provider"),
    // Legacy: the key this module originally queried.
    (
        "/Library/Preferences/com.jamf.connect.plist",
        "OIDCProvider",
    ),
];

/// Returns the installed JAMF Connect app bundle, preferring the modern name.
pub fn jamf_connect_app_dir() -> Option<PathBuf> {
    [JAMF_CONNECT_APP, JAMF_CONNECT_APP_LEGACY]
        .iter()
        .map(PathBuf::from)
        .find(|p| p.is_dir())
}

pub fn jamf_connect_info_plist() -> PathBuf {
    jamf_connect_app_dir()
        .unwrap_or_else(|| PathBuf::from(JAMF_CONNECT_APP))
        .join("Contents/Info.plist")
}

pub fn jamf_app_logs_dir() -> PathBuf {
    PathBuf::from("/Library/Application Support/JAMF/Logs")
}

/// The invoking user's home directory, or `None` when `HOME` is unset, empty or
/// not valid Unicode.
///
/// This previously fell back to `/tmp`, which silently pointed every per-user
/// path at a world-writable shared directory — the wrong place to read
/// diagnostics from, and the wrong place to teach callers to look. Callers
/// should skip the per-user sources instead.
pub fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
}

/// Verified-real path: `~/Library/Logs/JAMF` contains `selfservice.log`,
/// `selfservice_debug.log`, and (when JAMF Connect is installed) per-user
/// JAMF Connect logs.
pub fn jamf_user_logs_dir() -> Option<PathBuf> {
    home_dir().map(|h| h.join("Library/Logs/JAMF"))
}

pub fn self_service_log_file() -> Option<PathBuf> {
    jamf_user_logs_dir().map(|d| d.join("selfservice.log"))
}

pub fn self_service_debug_log_file() -> Option<PathBuf> {
    jamf_user_logs_dir().map(|d| d.join("selfservice_debug.log"))
}

pub fn connect_user_logs_dir() -> Option<PathBuf> {
    jamf_user_logs_dir().map(|d| d.join("JAMF Connect"))
}
