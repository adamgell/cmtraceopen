//! Helpers for spawning child processes without showing a console window
//! flash on Windows. See issue #138.

use std::process::Command;

/// `CREATE_NO_WINDOW` from `winbase.h`. Suppresses the flash of a console
/// window when the GUI app spawns a console subprocess (powershell.exe,
/// cmd.exe, reg.exe, sc.exe, wevtutil.exe, dsregcmd.exe, etc.).
#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Build a `Command` for `program` that, on Windows, won't pop a console
/// window. On other platforms behaves identically to `Command::new`.
pub fn hidden_command<S: AsRef<std::ffi::OsStr>>(program: S) -> Command {
    let mut cmd = Command::new(program);
    apply_hidden_window(&mut cmd);
    cmd
}

/// Apply the no-window flag to an existing `Command`. Useful when callers
/// already have a `Command` they need to flag (e.g. when a builder pattern
/// fits better than `hidden_command`).
#[cfg(target_os = "windows")]
pub fn apply_hidden_window(cmd: &mut Command) {
    use std::os::windows::process::CommandExt;
    cmd.creation_flags(CREATE_NO_WINDOW);
}

#[cfg(not(target_os = "windows"))]
pub fn apply_hidden_window(_cmd: &mut Command) {}
