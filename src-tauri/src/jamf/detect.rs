use std::path::Path;
use std::process::{Command, Output};
use std::sync::mpsc;
use std::time::Duration;

use crate::error::AppError;
use crate::jamf::models::{JamfDirectoryStatus, JamfEnvironment};
use crate::jamf::paths;
use crate::macos_diag::models::FdaStatus;

const JAMF_VERSION_TIMEOUT: Duration = Duration::from_secs(5);

/// Runs a command, giving up after `timeout`.
///
/// `/usr/local/bin/jamf` talks to the JSS, so it can block for a long time on a
/// degraded network — and this runs inside a Tauri command, where blocking
/// stalls the caller. The work happens on a helper thread so a wedged process
/// cannot hold the IPC call open; if it times out we abandon the thread rather
/// than leaving a half-read pipe, which is the safer trade for a read-only
/// diagnostic.
fn output_with_timeout(program: &str, args: &[&str], timeout: Duration) -> Option<Output> {
    let (tx, rx) = mpsc::channel();
    let program = program.to_string();
    let args: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    let spawn_program = program.clone();
    std::thread::spawn(move || {
        let _ = tx.send(Command::new(&spawn_program).args(&args).output());
    });
    match rx.recv_timeout(timeout) {
        Ok(Ok(output)) => Some(output),
        Ok(Err(e)) => {
            log::warn!("failed to run {program:?}: {e}");
            None
        }
        Err(_) => {
            log::warn!("{program:?} exceeded {timeout:?}; abandoning");
            None
        }
    }
}

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
    // The menu-bar app is not always deployed to /Applications even where the
    // JAMF Connect package (JCDaemon + login plugin) is installed, so treat the
    // system support directory as evidence too — otherwise the workspace
    // reports "not detected" on a host that is plainly configured for it.
    let jamf_connect_installed = paths::jamf_connect_app_dir().is_some()
        || Path::new(paths::JAMF_CONNECT_APP_SUPPORT).is_dir();
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
    let output = output_with_timeout(paths::JAMF_BINARY, &["version"], JAMF_VERSION_TIMEOUT)?;
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
    for (plist, key) in paths::JAMF_CONNECT_IDP_SOURCES {
        if !Path::new(plist).is_file() {
            continue;
        }
        let output = match Command::new("/usr/libexec/PlistBuddy")
            .args(["-c", &format!("Print :{key}"), plist])
            .output()
        {
            Ok(o) => o,
            Err(_) => continue,
        };
        if !output.status.success() {
            continue;
        }
        let v = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !v.is_empty() {
            return Some(v);
        }
    }
    None
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
