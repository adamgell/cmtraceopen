use std::path::Path;
use std::process::Command;
use std::time::Duration;

use crate::error::AppError;
use crate::jamf::models::{JamfDirectoryStatus, JamfEnvironment};
use crate::jamf::paths;
use crate::macos_diag::models::FdaStatus;

// TODO(jamf-detect): enforce in read_jamf_version once we wrap Command in a timeout.
#[allow(dead_code)]
const JAMF_VERSION_TIMEOUT: Duration = Duration::from_secs(5);

pub fn collect_environment_impl() -> Result<JamfEnvironment, AppError> {
    let jamf_installed = Path::new(paths::JAMF_BINARY).is_file();
    let directories = scan_directories();
    let last_check_in = if directories.jamf_log {
        crate::jamf::policy_log::parse_policy_log_impl(Path::new(paths::JAMF_LOG))
            .ok()
            .and_then(|r| {
                r.events
                    .iter()
                    .filter(|e| {
                        matches!(
                            e.trigger,
                            crate::jamf::models::JamfPolicyTrigger::RecurringCheckIn
                        )
                    })
                    .map(|e| e.timestamp)
                    .max()
            })
    } else {
        None
    };
    let jamf_version = if jamf_installed {
        read_jamf_version()
    } else {
        None
    };
    let jss_url = read_jss_url();
    let jamf_connect_installed = Path::new(paths::JAMF_CONNECT_APP).is_dir();
    let jamf_connect_version = if jamf_connect_installed {
        read_jamf_connect_version()
    } else {
        None
    };
    let jamf_connect_idp = if jamf_connect_installed {
        read_jamf_connect_idp()
    } else {
        None
    };

    let summary = build_summary(
        jamf_installed,
        &jamf_version,
        jamf_connect_installed,
        &directories,
    );

    Ok(JamfEnvironment {
        jamf_installed,
        jamf_version,
        jss_url,
        last_check_in,
        mdm_profile_present: false, // Filled in Task 1.5 wiring.
        mdm_organization: None,
        jamf_connect_installed,
        jamf_connect_version,
        jamf_connect_idp,
        fda_status: FdaStatus::Unknown,
        directories,
        summary,
    })
}

fn scan_directories() -> JamfDirectoryStatus {
    JamfDirectoryStatus {
        jamf_log: Path::new(paths::JAMF_LOG).is_file(),
        jamf_app_support: Path::new(paths::JAMF_APP_SUPPORT).is_dir(),
        jamf_receipts: Path::new(paths::JAMF_RECEIPTS).is_dir(),
        jamf_user_logs: paths::jamf_user_logs_dir().is_dir(),
        self_service_log: paths::self_service_log_file().is_file(),
        connect_log: Path::new(paths::JAMF_CONNECT_LOG_SYSTEM).is_file(),
        connect_user_logs: paths::connect_user_logs_dir().is_dir(),
    }
}

fn read_jamf_version() -> Option<String> {
    let output = Command::new(paths::JAMF_BINARY)
        .arg("version")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let raw = String::from_utf8_lossy(&output.stdout);
    // Real output: `version=11.26.1-t1774880441315`
    raw.lines()
        .find_map(|line| line.strip_prefix("version=").map(str::to_string))
}

fn read_jss_url() -> Option<String> {
    let output = Command::new("/usr/libexec/PlistBuddy")
        .args(["-c", "Print :jss_url", paths::JAMF_PLIST])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let url = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if url.is_empty() { None } else { Some(url) }
}

fn read_jamf_connect_version() -> Option<String> {
    let plist_buf = paths::jamf_connect_info_plist();
    let plist = plist_buf.to_string_lossy();
    let output = Command::new("/usr/libexec/PlistBuddy")
        .args(["-c", "Print :CFBundleShortVersionString", plist.as_ref()])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let v = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if v.is_empty() { None } else { Some(v) }
}

fn read_jamf_connect_idp() -> Option<String> {
    let output = Command::new("/usr/libexec/PlistBuddy")
        .args(["-c", "Print :OIDCProvider", paths::JAMF_CONNECT_PLIST])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let v = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if v.is_empty() { None } else { Some(v) }
}

fn build_summary(
    jamf_installed: bool,
    jamf_version: &Option<String>,
    jamf_connect_installed: bool,
    dirs: &JamfDirectoryStatus,
) -> String {
    if !jamf_installed {
        return "JAMF binary not found at /usr/local/bin/jamf. Workspace is showing read-only views; bundle imports still work.".to_string();
    }
    let v = jamf_version.as_deref().unwrap_or("unknown version");
    let connect = if jamf_connect_installed {
        " · JAMF Connect installed"
    } else {
        ""
    };
    let log = if dirs.jamf_log { "" } else { " · jamf.log missing" };
    format!("JAMF binary detected ({v}){connect}{log}")
}
