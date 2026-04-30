use std::path::PathBuf;

pub const JAMF_BINARY: &str = "/usr/local/bin/jamf";
pub const JAMF_LOG: &str = "/var/log/jamf.log";
pub const JAMF_APP_SUPPORT: &str = "/Library/Application Support/JAMF";
pub const JAMF_RECEIPTS: &str = "/Library/Application Support/JAMF/Receipts";
pub const JAMF_PLIST: &str = "/Library/Preferences/com.jamfsoftware.jamf.plist";
pub const JAMF_CONNECT_APP: &str = "/Applications/JAMF Connect.app";
pub const JAMF_CONNECT_PLIST: &str = "/Library/Preferences/com.jamf.connect.plist";
pub const JAMF_CONNECT_LOG_SYSTEM: &str = "/Library/Logs/JAMFConnect.log";
pub const SELF_SERVICE_APP: &str = "/Applications/Self Service.app";

pub fn jamf_connect_info_plist() -> PathBuf {
    PathBuf::from(JAMF_CONNECT_APP).join("Contents/Info.plist")
}

pub fn jamf_app_logs_dir() -> PathBuf {
    PathBuf::from("/Library/Application Support/JAMF/Logs")
}

pub fn home_dir() -> PathBuf {
    PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string()))
}

/// Verified-real path: `~/Library/Logs/JAMF` contains `selfservice.log`,
/// `selfservice_debug.log`, and (when JAMF Connect is installed) per-user
/// JAMF Connect logs.
pub fn jamf_user_logs_dir() -> PathBuf {
    home_dir().join("Library/Logs/JAMF")
}

pub fn self_service_log_file() -> PathBuf {
    jamf_user_logs_dir().join("selfservice.log")
}

pub fn self_service_debug_log_file() -> PathBuf {
    jamf_user_logs_dir().join("selfservice_debug.log")
}

pub fn connect_user_logs_dir() -> PathBuf {
    jamf_user_logs_dir().join("JAMF Connect")
}
