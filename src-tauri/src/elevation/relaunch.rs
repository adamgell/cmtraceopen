//! Platform mechanics for restart-as-administrator.
//!
//! This module owns the only `ShellExecute`/`runas` implementation in the
//! application. It is deliberately free of any workspace's models so it stays
//! available regardless of which product features are compiled in.
//!
//! What reaches the elevated child is rebuilt from nothing: the current
//! executable, the fixed `runas` verb, and at most one validated opaque restore
//! ticket identifier. The caller's own startup arguments are never forwarded.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::restore_ticket::validate_ticket_id;

/// The single startup option the elevated child accepts.
pub const ELEVATION_RESTORE_FLAG: &str = "--elevation-restore=";

/// Substrings that must never appear in anything handed to the elevated child.
///
/// Nothing is forwarded today, so this is a standing assertion rather than a
/// filter: if a future change starts propagating arguments, it fails closed.
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

/// Longest failure detail shown to the user.
const MAX_FAILURE_DETAIL: usize = 256;

/// The outcome of a restart request. Cancellation is an outcome, not an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RelaunchReason {
    Launched,
    AlreadyElevated,
    ElevationCancelled,
    UnsupportedPlatform,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelaunchResult {
    pub launched: bool,
    pub reason: RelaunchReason,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Error)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum RelaunchError {
    #[error("an unsafe startup argument prevented administrator restart")]
    UnsafeArgument,
    #[error("administrator restart failed: {message}")]
    LaunchFailed { message: String },
}

/// Separates "the user said no" from "the launch broke".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ElevationLaunchError {
    Cancelled,
    Failed(String),
}

/// Exactly what will be handed to `ShellExecuteExW`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelaunchRequest {
    pub verb: String,
    pub executable: PathBuf,
    pub arguments: Vec<String>,
    pub parameters: String,
    pub close_process_handle: bool,
}

/// The platform surface the restart flow needs, so the policy above it is
/// testable without a Windows token or a UAC prompt.
pub trait RelaunchProvider {
    fn platform_supported(&self) -> bool;
    fn is_elevated(&self) -> Result<bool, String>;
    fn current_executable(&self) -> Result<PathBuf, String>;
    fn launch_elevated(&self, request: &RelaunchRequest) -> Result<(), ElevationLaunchError>;
}

/// Request an elevated restart, optionally carrying a restore ticket.
///
/// Returns `Ok` with `launched: false` for the three non-failure outcomes
/// (unsupported platform, already elevated, user cancelled UAC). Only the
/// caller decides whether to exit the current process, and only when
/// `launched` is true.
pub fn restart_with_provider(
    provider: &impl RelaunchProvider,
    restore_ticket_id: Option<&str>,
) -> Result<RelaunchResult, RelaunchError> {
    if !provider.platform_supported() {
        return Ok(result(false, RelaunchReason::UnsupportedPlatform));
    }
    if provider
        .is_elevated()
        .map_err(|_| launch_failed("unable to determine the current elevation state"))?
    {
        return Ok(result(false, RelaunchReason::AlreadyElevated));
    }

    let arguments = elevated_arguments(restore_ticket_id)?;
    let executable = provider
        .current_executable()
        .map_err(|_| launch_failed("unable to resolve the CMTrace Open executable"))?;
    if executable.to_string_lossy().contains('\0') {
        return Err(RelaunchError::UnsafeArgument);
    }

    let request = RelaunchRequest {
        verb: "runas".to_string(),
        executable,
        parameters: build_windows_parameter_line(&arguments),
        arguments,
        close_process_handle: true,
    };

    match provider.launch_elevated(&request) {
        Ok(()) => Ok(result(true, RelaunchReason::Launched)),
        Err(ElevationLaunchError::Cancelled) => {
            Ok(result(false, RelaunchReason::ElevationCancelled))
        }
        Err(ElevationLaunchError::Failed(message)) => {
            Err(launch_failed(&sanitize_failure_detail(&message)))
        }
    }
}

fn result(launched: bool, reason: RelaunchReason) -> RelaunchResult {
    RelaunchResult { launched, reason }
}

fn launch_failed(message: &str) -> RelaunchError {
    RelaunchError::LaunchFailed {
        message: message.to_string(),
    }
}

/// Build the child's argument list from scratch.
///
/// The result is either empty or exactly one `--elevation-restore=<id>` whose
/// identifier has already passed the ticket character-set check.
fn elevated_arguments(restore_ticket_id: Option<&str>) -> Result<Vec<String>, RelaunchError> {
    let Some(id) = restore_ticket_id else {
        return Ok(Vec::new());
    };
    validate_ticket_id(id).map_err(|_| RelaunchError::UnsafeArgument)?;

    let argument = format!("{ELEVATION_RESTORE_FLAG}{id}");
    if argument.contains('\0') || contains_secret_marker(&argument) {
        return Err(RelaunchError::UnsafeArgument);
    }
    Ok(vec![argument])
}

fn contains_secret_marker(value: &str) -> bool {
    let normalized = value.to_ascii_lowercase();
    SECRET_MARKERS
        .iter()
        .any(|marker| normalized.contains(marker))
}

/// Read the restore ticket identifier out of a startup argument list.
///
/// Only the exact `--elevation-restore=<id>` form is accepted, and the
/// identifier must pass the same validation used when it was minted. A
/// malformed option yields `None`: it is never treated as a file path, and it
/// never suppresses a legitimate positional open.
pub fn parse_restore_argument<S: AsRef<str>>(arguments: &[S]) -> Option<String> {
    arguments.iter().find_map(|argument| {
        let id = argument.as_ref().strip_prefix(ELEVATION_RESTORE_FLAG)?;
        validate_ticket_id(id).ok()?;
        Some(id.to_string())
    })
}

/// Join arguments using the Win32 `CommandLineToArgvW` quoting rules.
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
            quoted.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
            quoted.push('"');
        } else {
            quoted.extend(std::iter::repeat_n('\\', backslashes));
            quoted.push(character);
        }
        backslashes = 0;
    }
    quoted.extend(std::iter::repeat_n('\\', backslashes * 2));
    quoted.push('"');
    quoted
}

/// Strip secret-shaped text and control characters, then bound the length.
fn sanitize_failure_detail(message: &str) -> String {
    let redacted = if contains_secret_marker(message) {
        "[REDACTED]".to_string()
    } else {
        message.to_string()
    };
    redacted
        .chars()
        .filter(|character| !character.is_control())
        .take(MAX_FAILURE_DETAIL)
        .collect()
}

/// Whether the current process holds an elevated token.
///
/// A probe failure is reported rather than swallowed: silently answering
/// "not elevated" would make the app offer a pointless UAC prompt to a user who
/// is already an administrator.
pub fn is_process_elevated() -> Result<bool, String> {
    #[cfg(target_os = "windows")]
    {
        use windows::Win32::Foundation::{CloseHandle, HANDLE};
        use windows::Win32::Security::{
            GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
        };
        use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

        struct HandleGuard(HANDLE);
        impl Drop for HandleGuard {
            fn drop(&mut self) {
                if !self.0.is_invalid() {
                    // SAFETY: the handle came from OpenProcessToken and is closed once.
                    let _ = unsafe { CloseHandle(self.0) };
                }
            }
        }

        let mut token = HANDLE::default();
        // SAFETY: token points to valid writable storage and is closed by HandleGuard.
        if let Err(error) =
            unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }
        {
            log::warn!("elevation probe: OpenProcessToken failed: {error:?}");
            return Err("process token query failed".to_string());
        }
        let _token = HandleGuard(token);

        let mut elevation = TOKEN_ELEVATION::default();
        let mut returned = 0_u32;
        // SAFETY: elevation is valid writable TOKEN_ELEVATION storage of the declared size.
        if let Err(error) = unsafe {
            GetTokenInformation(
                token,
                TokenElevation,
                Some((&mut elevation as *mut TOKEN_ELEVATION).cast()),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut returned,
            )
        } {
            log::warn!("elevation probe: GetTokenInformation(TokenElevation) failed: {error:?}");
            return Err("token elevation query failed".to_string());
        }
        Ok(elevation.TokenIsElevated != 0)
    }
    #[cfg(not(target_os = "windows"))]
    {
        Err("unsupported platform".to_string())
    }
}

/// The provider used in production.
#[derive(Debug, Clone, Copy, Default)]
pub struct NativeRelaunchProvider;

impl RelaunchProvider for NativeRelaunchProvider {
    fn platform_supported(&self) -> bool {
        cfg!(target_os = "windows")
    }

    fn is_elevated(&self) -> Result<bool, String> {
        is_process_elevated()
    }

    fn current_executable(&self) -> Result<PathBuf, String> {
        std::env::current_exe().map_err(|error| error.to_string())
    }

    fn launch_elevated(&self, request: &RelaunchRequest) -> Result<(), ElevationLaunchError> {
        launch_elevated_native(request)
    }
}

#[cfg(not(target_os = "windows"))]
fn launch_elevated_native(_request: &RelaunchRequest) -> Result<(), ElevationLaunchError> {
    Err(ElevationLaunchError::Failed(
        "unsupported platform".to_string(),
    ))
}

/// Resolve the working directory the elevated child should start in.
///
/// Returns the executable's parent (the verified app install directory)
/// wide-encoded and NUL-terminated. If the executable has no parent, falls
/// back to the Windows system directory. Both are trusted, non-attacker-
/// writable locations, so the elevated process never inherits the caller's
/// (untrusted) working directory — closing a DLL-planting elevation-of-
/// privilege lever where a name-resolved DLL in an attacker-writable cwd would
/// otherwise load elevated.
#[cfg(target_os = "windows")]
fn elevated_working_directory(exe: &std::path::Path) -> Vec<u16> {
    use std::iter::once;
    use std::os::windows::ffi::OsStrExt;

    if let Some(parent) = exe.parent().filter(|parent| !parent.as_os_str().is_empty()) {
        return parent.as_os_str().encode_wide().chain(once(0)).collect();
    }

    windows_system_directory()
}

/// The Windows system directory (e.g. `C:\Windows\System32`) wide-encoded and
/// NUL-terminated, used as a trusted fallback working directory.
#[cfg(target_os = "windows")]
fn windows_system_directory() -> Vec<u16> {
    use windows::Win32::System::SystemInformation::GetSystemDirectoryW;

    // MAX_PATH-sized buffer; GetSystemDirectoryW returns the length written
    // (excluding the terminator) on success, or 0 on failure.
    let mut buffer = [0u16; 260];
    let length = unsafe { GetSystemDirectoryW(Some(&mut buffer)) } as usize;
    if length == 0 || length >= buffer.len() {
        // Last-resort fixed path; still a trusted, non-attacker-writable dir.
        return "C:\\Windows\\System32\0".encode_utf16().collect();
    }

    buffer[..length]
        .iter()
        .copied()
        .chain(std::iter::once(0))
        .collect()
}

#[cfg(target_os = "windows")]
fn launch_elevated_native(request: &RelaunchRequest) -> Result<(), ElevationLaunchError> {
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
    // Pin the elevated child's working directory to the trusted install dir.
    // This buffer must outlive the ShellExecuteExW call, like the others.
    let directory = elevated_working_directory(&request.executable);
    let mut execute = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS,
        lpVerb: PCWSTR(verb.as_ptr()),
        lpFile: PCWSTR(executable.as_ptr()),
        lpParameters: PCWSTR(parameters.as_ptr()),
        lpDirectory: PCWSTR(directory.as_ptr()),
        nShow: SW_SHOWNORMAL.0,
        ..Default::default()
    };

    if let Err(error) = unsafe { ShellExecuteExW(&mut execute) } {
        if error.code() == HRESULT::from_win32(ERROR_CANCELLED.0) {
            return Err(ElevationLaunchError::Cancelled);
        }
        return Err(ElevationLaunchError::Failed(error.to_string()));
    }

    if request.close_process_handle && !execute.hProcess.is_invalid() {
        if let Err(error) = unsafe { CloseHandle(execute.hProcess) } {
            log::warn!("unable to close elevated process handle: {error}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    use crate::elevation::restore_ticket::new_ticket_id;

    struct FakeProvider {
        supported: bool,
        elevated: Result<bool, String>,
        executable: Result<PathBuf, String>,
        outcome: Option<ElevationLaunchError>,
        seen: RefCell<Vec<RelaunchRequest>>,
    }

    impl FakeProvider {
        fn windows() -> Self {
            Self {
                supported: true,
                elevated: Ok(false),
                executable: Ok(PathBuf::from(
                    r"C:\Program Files\CMTrace Open\cmtrace-open.exe",
                )),
                outcome: None,
                seen: RefCell::new(Vec::new()),
            }
        }
    }

    impl RelaunchProvider for FakeProvider {
        fn platform_supported(&self) -> bool {
            self.supported
        }
        fn is_elevated(&self) -> Result<bool, String> {
            self.elevated.clone()
        }
        fn current_executable(&self) -> Result<PathBuf, String> {
            self.executable.clone()
        }
        fn launch_elevated(&self, request: &RelaunchRequest) -> Result<(), ElevationLaunchError> {
            self.seen.borrow_mut().push(request.clone());
            match &self.outcome {
                None => Ok(()),
                Some(error) => Err(error.clone()),
            }
        }
    }

    #[test]
    fn an_unsupported_platform_does_not_prompt() {
        let provider = FakeProvider {
            supported: false,
            ..FakeProvider::windows()
        };

        let result = restart_with_provider(&provider, None).expect("no error");

        assert_eq!(
            result,
            RelaunchResult {
                launched: false,
                reason: RelaunchReason::UnsupportedPlatform
            }
        );
        assert!(
            provider.seen.borrow().is_empty(),
            "no launch may be attempted on an unsupported platform"
        );
    }

    #[test]
    fn an_already_elevated_process_does_not_relaunch() {
        let provider = FakeProvider {
            elevated: Ok(true),
            ..FakeProvider::windows()
        };

        let result = restart_with_provider(&provider, None).expect("no error");

        assert_eq!(result.reason, RelaunchReason::AlreadyElevated);
        assert!(!result.launched);
        assert!(provider.seen.borrow().is_empty());
    }

    #[test]
    fn an_unreadable_elevation_state_is_a_sanitized_failure() {
        let provider = FakeProvider {
            elevated: Err("token query failed".to_string()),
            ..FakeProvider::windows()
        };

        let error = restart_with_provider(&provider, None).unwrap_err();

        assert_eq!(
            error,
            RelaunchError::LaunchFailed {
                message: "unable to determine the current elevation state".to_string()
            }
        );
    }

    #[test]
    fn a_successful_launch_builds_the_fixed_runas_request() {
        let provider = FakeProvider::windows();
        let id = new_ticket_id();

        let result = restart_with_provider(&provider, Some(&id)).expect("no error");

        assert_eq!(result.reason, RelaunchReason::Launched);
        assert!(result.launched);

        let seen = provider.seen.borrow();
        let request = seen.first().expect("one launch");
        assert_eq!(request.verb, "runas");
        assert_eq!(
            request.executable,
            PathBuf::from(r"C:\Program Files\CMTrace Open\cmtrace-open.exe")
        );
        assert_eq!(request.arguments, vec![format!("--elevation-restore={id}")]);
        assert!(request.close_process_handle);
    }

    #[test]
    fn a_workspace_only_restart_passes_no_arguments() {
        let provider = FakeProvider::windows();

        restart_with_provider(&provider, None).expect("no error");

        let seen = provider.seen.borrow();
        let request = seen.first().expect("one launch");
        assert!(
            request.arguments.is_empty(),
            "a restart with no ticket must forward nothing"
        );
        assert_eq!(request.parameters, "");
    }

    #[test]
    fn a_malformed_ticket_identifier_is_refused() {
        let provider = FakeProvider::windows();

        let error = restart_with_provider(&provider, Some("../../etc/passwd")).unwrap_err();

        assert_eq!(error, RelaunchError::UnsafeArgument);
        assert!(
            provider.seen.borrow().is_empty(),
            "a bad identifier must be caught before any launch"
        );
    }

    #[test]
    fn cancellation_is_reported_as_an_outcome_not_a_failure() {
        let provider = FakeProvider {
            outcome: Some(ElevationLaunchError::Cancelled),
            ..FakeProvider::windows()
        };

        let result = restart_with_provider(&provider, None).expect("cancellation is not an error");

        assert_eq!(result.reason, RelaunchReason::ElevationCancelled);
        assert!(!result.launched);
    }

    #[test]
    fn a_launch_failure_is_sanitized() {
        let provider = FakeProvider {
            outcome: Some(ElevationLaunchError::Failed(
                "failed with bearer token abc123\u{7}".to_string(),
            )),
            ..FakeProvider::windows()
        };

        let error = restart_with_provider(&provider, None).unwrap_err();

        let RelaunchError::LaunchFailed { message } = error else {
            panic!("expected a launch failure");
        };
        assert_eq!(message, "[REDACTED]");
    }

    #[test]
    fn a_launch_failure_drops_control_characters_and_is_bounded() {
        let provider = FakeProvider {
            outcome: Some(ElevationLaunchError::Failed(format!(
                "boom\u{7}{}",
                "x".repeat(MAX_FAILURE_DETAIL * 2)
            ))),
            ..FakeProvider::windows()
        };

        let error = restart_with_provider(&provider, None).unwrap_err();

        let RelaunchError::LaunchFailed { message } = error else {
            panic!("expected a launch failure");
        };
        assert_eq!(message.len(), MAX_FAILURE_DETAIL);
        assert!(!message.chars().any(char::is_control));
    }

    #[test]
    fn an_executable_containing_nul_is_rejected() {
        let provider = FakeProvider {
            executable: Ok(PathBuf::from("C:\\CMTrace\0\\cmtrace-open.exe")),
            ..FakeProvider::windows()
        };

        assert_eq!(
            restart_with_provider(&provider, None).unwrap_err(),
            RelaunchError::UnsafeArgument
        );
    }

    #[test]
    fn an_unresolvable_executable_is_a_sanitized_failure() {
        let provider = FakeProvider {
            executable: Err("no such process".to_string()),
            ..FakeProvider::windows()
        };

        assert_eq!(
            restart_with_provider(&provider, None).unwrap_err(),
            RelaunchError::LaunchFailed {
                message: "unable to resolve the CMTrace Open executable".to_string()
            }
        );
    }

    #[test]
    fn windows_quoting_handles_spaces_quotes_and_trailing_slashes() {
        assert_eq!(build_windows_parameter_line(&[]), "");
        assert_eq!(
            build_windows_parameter_line(&["--plain".to_string()]),
            "--plain"
        );
        assert_eq!(
            build_windows_parameter_line(&["with space".to_string()]),
            "\"with space\""
        );
        assert_eq!(
            build_windows_parameter_line(&[r#"say "hi""#.to_string()]),
            r#""say \"hi\"""#
        );
        // A trailing backslash before the closing quote must be doubled or it
        // would escape the quote itself.
        assert_eq!(
            build_windows_parameter_line(&[r"C:\dir with space\".to_string()]),
            r#""C:\dir with space\\""#
        );
        assert_eq!(build_windows_parameter_line(&[String::new()]), "\"\"");
    }

    #[test]
    fn restore_argument_parsing_accepts_only_the_exact_option() {
        let id = new_ticket_id();

        assert_eq!(
            parse_restore_argument(&[format!("--elevation-restore={id}")]),
            Some(id.clone())
        );
        assert_eq!(
            parse_restore_argument(&["--workspace=esp-diagnostics".to_string()]),
            None
        );
        assert_eq!(
            parse_restore_argument(&["--elevation-restore=".to_string()]),
            None
        );
        assert_eq!(
            parse_restore_argument(&["--elevation-restore=../../etc/passwd".to_string()]),
            None
        );
        // A separate value is not the accepted form.
        assert_eq!(
            parse_restore_argument(&["--elevation-restore".to_string(), id.clone()]),
            None
        );
    }

    #[test]
    fn a_positional_path_is_never_read_as_a_ticket() {
        let id = new_ticket_id();
        let arguments = vec![
            r"C:\logs\app.log".to_string(),
            format!("--elevation-restore={id}"),
        ];

        // The positional path is untouched and the option still resolves.
        assert_eq!(parse_restore_argument(&arguments), Some(id));
        assert_eq!(
            parse_restore_argument(&[r"C:\logs\--elevation-restore=x.log".to_string()]),
            None
        );
    }
}

#[cfg(all(test, target_os = "windows"))]
mod windows_relaunch_tests {
    use super::*;
    use std::iter::once;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;

    #[test]
    fn elevated_working_directory_pins_the_executable_parent() {
        let exe = Path::new(r"C:\Program Files\CMTrace Open\cmtrace-open.exe");
        let expected: Vec<u16> = Path::new(r"C:\Program Files\CMTrace Open")
            .as_os_str()
            .encode_wide()
            .chain(once(0))
            .collect();

        let directory = elevated_working_directory(exe);

        assert_eq!(directory, expected);
        // The pointer handed to SHELLEXECUTEINFOW.lpDirectory must be non-null
        // (non-empty) and the wide string NUL-terminated.
        assert_eq!(directory.last(), Some(&0));
        assert!(directory.len() > 1);
    }

    #[test]
    fn elevated_working_directory_falls_back_to_system_dir_without_parent() {
        // A bare filename has an empty parent, so the trusted system directory
        // is used instead of leaving the working directory NULL (which would
        // inherit the caller's untrusted cwd).
        let directory = elevated_working_directory(Path::new("cmtrace-open.exe"));

        assert_eq!(directory.last(), Some(&0));
        assert!(directory.len() > 1, "fallback directory must be non-empty");
    }
}
