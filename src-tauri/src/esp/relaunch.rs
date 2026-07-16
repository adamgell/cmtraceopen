//! Explicit, user-initiated restart-as-administrator support for ESP diagnostics.
//!
//! Relaunch arguments are rebuilt from a tiny app-owned allowlist. Evidence
//! paths, arbitrary shell text, and anything resembling a credential are never
//! forwarded to the elevated child.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use thiserror::Error;

const ESP_WORKSPACE_ARGUMENT: &str = "--workspace=esp-diagnostics";
const SECRET_MARKERS: &[&str] = &[
    "access-token",
    "accesstoken",
    "api-key",
    "apikey",
    "authorization",
    "bearer",
    "client-secret",
    "clientsecret",
    "password",
    "refresh-token",
    "refreshtoken",
    "secret",
    "token",
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum EspRelaunchReason {
    Launched,
    AlreadyElevated,
    ElevationCancelled,
    UnsupportedPlatform,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EspRelaunchResult {
    pub launched: bool,
    pub reason: EspRelaunchReason,
}

#[derive(Debug, Clone, Serialize, Error, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum EspRelaunchError {
    #[error("an unsafe startup argument prevented administrator restart")]
    UnsafeArgument,
    #[error("administrator restart failed: {message}")]
    LaunchFailed { message: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EspElevationLaunchError {
    Cancelled,
    Failed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EspRelaunchRequest {
    pub verb: String,
    pub executable: PathBuf,
    pub arguments: Vec<String>,
    pub parameters: String,
    pub close_process_handle: bool,
}

pub trait EspRelaunchProvider {
    fn platform_supported(&self) -> bool;
    fn is_elevated(&self) -> Result<bool, String>;
    fn current_executable(&self) -> Result<PathBuf, String>;
    fn startup_arguments(&self) -> Vec<String>;
    fn launch_elevated(&self, request: &EspRelaunchRequest) -> Result<(), EspElevationLaunchError>;
}

pub fn restart_with_provider(
    provider: &impl EspRelaunchProvider,
) -> Result<EspRelaunchResult, EspRelaunchError> {
    if !provider.platform_supported() {
        return Ok(result(false, EspRelaunchReason::UnsupportedPlatform));
    }
    if provider
        .is_elevated()
        .map_err(|_| launch_failed("unable to determine the current elevation state"))?
    {
        return Ok(result(false, EspRelaunchReason::AlreadyElevated));
    }

    let arguments = allowlisted_arguments(&provider.startup_arguments())?;
    let executable = provider
        .current_executable()
        .map_err(|_| launch_failed("unable to resolve the CMTrace Open executable"))?;
    if executable.to_string_lossy().contains('\0') {
        return Err(EspRelaunchError::UnsafeArgument);
    }
    let request = EspRelaunchRequest {
        verb: "runas".to_string(),
        executable,
        parameters: build_windows_parameter_line(&arguments),
        arguments,
        close_process_handle: true,
    };

    match provider.launch_elevated(&request) {
        Ok(()) => Ok(result(true, EspRelaunchReason::Launched)),
        Err(EspElevationLaunchError::Cancelled) => {
            Ok(result(false, EspRelaunchReason::ElevationCancelled))
        }
        Err(EspElevationLaunchError::Failed(message)) => {
            Err(launch_failed(&sanitize_failure_detail(&message)))
        }
    }
}

fn result(launched: bool, reason: EspRelaunchReason) -> EspRelaunchResult {
    EspRelaunchResult { launched, reason }
}

fn launch_failed(message: &str) -> EspRelaunchError {
    EspRelaunchError::LaunchFailed {
        message: message.to_string(),
    }
}

fn allowlisted_arguments(arguments: &[String]) -> Result<Vec<String>, EspRelaunchError> {
    for argument in arguments {
        let normalized = argument.to_ascii_lowercase();
        if argument.contains('\0')
            || SECRET_MARKERS
                .iter()
                .any(|marker| normalized.contains(marker))
        {
            return Err(EspRelaunchError::UnsafeArgument);
        }
    }

    let mut preserve_workspace = false;
    let mut index = 0;
    while index < arguments.len() {
        let argument = &arguments[index];
        if argument.eq_ignore_ascii_case(ESP_WORKSPACE_ARGUMENT)
            || argument.eq_ignore_ascii_case("--esp-diagnostics")
        {
            preserve_workspace = true;
        } else if argument.eq_ignore_ascii_case("--workspace")
            && arguments
                .get(index + 1)
                .is_some_and(|value| value.eq_ignore_ascii_case("esp-diagnostics"))
        {
            preserve_workspace = true;
            index += 1;
        }
        index += 1;
    }

    // The command is reachable only from this workspace's elevation banner,
    // so make the destination explicit even when the original launch had no
    // workspace argument. Unknown arguments and evidence paths are dropped.
    let _ = preserve_workspace;
    Ok(vec![ESP_WORKSPACE_ARGUMENT.to_string()])
}

pub fn build_windows_parameter_line(arguments: &[String]) -> String {
    arguments
        .iter()
        .map(|argument| quote_windows_argument(argument))
        .collect::<Vec<_>>()
        .join(" ")
}

fn quote_windows_argument(argument: &str) -> String {
    if !argument.is_empty()
        && !argument
            .chars()
            .any(|character| character.is_whitespace() || character == '"')
    {
        return argument.to_string();
    }

    let mut quoted = String::from("\"");
    let mut backslashes = 0usize;
    for character in argument.chars() {
        if character == '\\' {
            backslashes += 1;
            continue;
        }
        if character == '"' {
            quoted.extend(std::iter::repeat('\\').take(backslashes * 2 + 1));
            quoted.push('"');
        } else {
            quoted.extend(std::iter::repeat('\\').take(backslashes));
            quoted.push(character);
        }
        backslashes = 0;
    }
    quoted.extend(std::iter::repeat('\\').take(backslashes * 2));
    quoted.push('"');
    quoted
}

fn sanitize_failure_detail(message: &str) -> String {
    let sanitized = super::process::sanitize_command_line(message);
    sanitized
        .chars()
        .filter(|character| !character.is_control())
        .take(256)
        .collect()
}

#[derive(Debug, Clone, Copy, Default)]
pub struct NativeEspRelaunchProvider;

impl EspRelaunchProvider for NativeEspRelaunchProvider {
    fn platform_supported(&self) -> bool {
        cfg!(target_os = "windows")
    }

    fn is_elevated(&self) -> Result<bool, String> {
        #[cfg(target_os = "windows")]
        {
            use super::system::{LiveSystemProvider, SystemProvider};
            LiveSystemProvider
                .elevation()
                .map_err(|error| format!("{error:?}"))
        }
        #[cfg(not(target_os = "windows"))]
        {
            Err("unsupported platform".to_string())
        }
    }

    fn current_executable(&self) -> Result<PathBuf, String> {
        std::env::current_exe().map_err(|error| error.to_string())
    }

    fn startup_arguments(&self) -> Vec<String> {
        std::env::args().skip(1).collect()
    }

    fn launch_elevated(&self, request: &EspRelaunchRequest) -> Result<(), EspElevationLaunchError> {
        launch_elevated_native(request)
    }
}

#[cfg(not(target_os = "windows"))]
fn launch_elevated_native(_request: &EspRelaunchRequest) -> Result<(), EspElevationLaunchError> {
    Err(EspElevationLaunchError::Failed(
        "unsupported platform".to_string(),
    ))
}

#[cfg(target_os = "windows")]
fn launch_elevated_native(request: &EspRelaunchRequest) -> Result<(), EspElevationLaunchError> {
    use std::ffi::OsStr;
    use std::iter::once;
    use std::os::windows::ffi::OsStrExt;

    use windows::core::{HRESULT, PCWSTR};
    use windows::Win32::Foundation::{CloseHandle, ERROR_CANCELLED};
    use windows::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    let verb = OsStr::new(&request.verb)
        .encode_wide()
        .chain(once(0))
        .collect::<Vec<_>>();
    let executable = request
        .executable
        .as_os_str()
        .encode_wide()
        .chain(once(0))
        .collect::<Vec<_>>();
    let parameters = OsStr::new(&request.parameters)
        .encode_wide()
        .chain(once(0))
        .collect::<Vec<_>>();
    let mut execute = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS,
        lpVerb: PCWSTR(verb.as_ptr()),
        lpFile: PCWSTR(executable.as_ptr()),
        lpParameters: PCWSTR(parameters.as_ptr()),
        nShow: SW_SHOWNORMAL.0,
        ..Default::default()
    };

    if let Err(error) = unsafe { ShellExecuteExW(&mut execute) } {
        if error.code() == HRESULT::from_win32(ERROR_CANCELLED.0) {
            return Err(EspElevationLaunchError::Cancelled);
        }
        return Err(EspElevationLaunchError::Failed(error.to_string()));
    }

    if request.close_process_handle && !execute.hProcess.is_invalid() {
        if let Err(error) = unsafe { CloseHandle(execute.hProcess) } {
            log::warn!("unable to close elevated ESP process handle: {error}");
        }
    }
    Ok(())
}
