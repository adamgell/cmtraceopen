use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use crate::error::AppError;
use crate::jamf::models::{JamfDirectoryStatus, JamfEnvironment};
use crate::jamf::paths;

const JAMF_VERSION_TIMEOUT: Duration = Duration::from_secs(5);

/// PlistBuddy reads a local file, but "local" is a claim the filesystem gets to
/// break: a plist on a hung network home or a wedged PlistBuddy would stall the
/// whole environment probe, so bound it like the `jamf` calls.
const PLISTBUDDY_TIMEOUT: Duration = Duration::from_secs(5);

const PLISTBUDDY: &str = "/usr/libexec/PlistBuddy";

/// Runs a command, killing it if it outlives `timeout`.
///
/// `/usr/local/bin/jamf` talks to the JSS, so it can block for a long time on a
/// degraded network — and this runs inside a Tauri command, where blocking
/// stalls the caller. Own the child rather than detaching the work, so a wedged
/// process is reaped instead of being left behind on every collection.
fn output_with_timeout(program: &str, args: &[&str], timeout: Duration) -> Option<Output> {
    let mut child = match Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            log::warn!("failed to run {program:?}: {e}");
            return None;
        }
    };

    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if Instant::now() >= deadline {
                    log::warn!("{program:?} exceeded {timeout:?}; terminating");
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                std::thread::sleep(POLL_INTERVAL);
            }
            Err(e) => {
                log::warn!("failed to wait on {program:?}: {e}");
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }

    // Safe to drain only now that the child has exited: these commands emit far
    // less than a pipe buffer, so it cannot have blocked on a full pipe.
    child.wait_with_output().ok()
}

const POLL_INTERVAL: Duration = Duration::from_millis(20);

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

    let (mdm_profile_present, mdm_organization) = read_mdm_identity();
    let fda_status = crate::macos_diag::environment::detect_full_disk_access();

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
        mdm_profile_present,
        mdm_organization,
        jamf_connect_installed,
        jamf_connect_version,
        jamf_connect_idp,
        fda_status,
        directories,
        summary,
    })
}

/// Payload type carried by the MDM enrollment profile itself.
const MDM_PAYLOAD_TYPE: &str = "com.apple.mdm";

/// Reports whether an MDM profile is installed and which organization issued it.
///
/// The organization is the one on the enrollment profile — the tenant that owns
/// the JAMF instance, which is also the value stamped on the profiles it
/// deploys. That makes it the right `expected_organization` for
/// [`crate::jamf::profiles::filter_jamf_profiles_impl`], which otherwise can
/// only recognize profiles whose payloads are JAMF-specific.
///
/// Never fails: profile enumeration is unavailable off macOS and can be denied
/// at runtime, and neither is a reason for the whole environment probe to error.
fn read_mdm_identity() -> (bool, Option<String>) {
    let result = match crate::macos_diag::profiles::list_profiles_impl() {
        Ok(r) => r,
        Err(e) => {
            log::debug!("MDM profile enumeration unavailable: {e:?}");
            return (false, None);
        }
    };

    let mdm_profile = result.profiles.iter().find(|p| {
        p.payloads.iter().any(|payload| {
            payload.payload_type == MDM_PAYLOAD_TYPE
                || payload.payload_identifier == MDM_PAYLOAD_TYPE
        })
    });

    // `profiles status -type enrollment` still reports enrollment even when the
    // profile list is empty, so treat either signal as present.
    let present = mdm_profile.is_some() || result.enrollment_status.enrolled;
    let organization = mdm_profile.and_then(|p| p.profile_organization.clone());
    (present, organization)
}

fn scan_directories() -> JamfDirectoryStatus {
    JamfDirectoryStatus {
        jamf_log: Path::new(paths::JAMF_LOG).is_file(),
        jamf_app_support: Path::new(paths::JAMF_APP_SUPPORT).is_dir(),
        jamf_receipts: Path::new(paths::JAMF_RECEIPTS).is_dir(),
        // Absent HOME means the per-user sources are simply not locatable, which
        // reads the same as "not present" to the caller.
        jamf_user_logs: paths::jamf_user_logs_dir().is_some_and(|p| p.is_dir()),
        self_service_log: paths::self_service_log_file().is_some_and(|p| p.is_file()),
        connect_log: Path::new(paths::JAMF_CONNECT_LOG_SYSTEM).is_file(),
        connect_user_logs: paths::connect_user_logs_dir().is_some_and(|p| p.is_dir()),
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
    let output = output_with_timeout(
        PLISTBUDDY,
        &["-c", "Print :jss_url", paths::JAMF_PLIST],
        PLISTBUDDY_TIMEOUT,
    )?;
    if !output.status.success() {
        return None;
    }
    let url = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if url.is_empty() {
        None
    } else {
        Some(url)
    }
}

fn read_jamf_connect_version() -> Option<String> {
    let plist_buf = paths::jamf_connect_info_plist();
    let plist = plist_buf.to_string_lossy();
    let output = output_with_timeout(
        PLISTBUDDY,
        &["-c", "Print :CFBundleShortVersionString", plist.as_ref()],
        PLISTBUDDY_TIMEOUT,
    )?;
    if !output.status.success() {
        return None;
    }
    let v = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if v.is_empty() {
        None
    } else {
        Some(v)
    }
}

fn read_jamf_connect_idp() -> Option<String> {
    for (plist, key) in paths::JAMF_CONNECT_IDP_SOURCES {
        if !Path::new(plist).is_file() {
            continue;
        }
        let print_key = format!("Print :{key}");
        let output =
            match output_with_timeout(PLISTBUDDY, &["-c", &print_key, plist], PLISTBUDDY_TIMEOUT) {
                Some(o) => o,
                None => continue,
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
    let log = if dirs.jamf_log {
        ""
    } else {
        " · jamf.log missing"
    };
    format!("JAMF binary detected ({v}){connect}{log}")
}
