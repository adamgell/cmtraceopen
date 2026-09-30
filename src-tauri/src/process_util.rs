//! Helpers for spawning child processes: no console window flash on Windows
//! (issue #138), and a deadline plus output caps for tools that can hang or
//! talk too much (issue #684).

use std::io::Read;
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

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

/// Generous defaults for the tools that need a deadline.
///
/// They exist to end a hang, not to shorten a legitimate read: a diagnostic tool
/// that takes tens of seconds on a busy host must still finish, so the deadline
/// is far longer than any healthy run and the caps are far larger than any real
/// capture. A run that meets either is truncating or hanging, and the caller is
/// told which.
pub const TOOL_DEADLINE: Duration = Duration::from_secs(120);
pub const TOOL_OUTPUT_BYTES: usize = 32 * 1024 * 1024;
pub const TOOL_ERROR_BYTES: usize = 256 * 1024;

/// What a bounded child process produced.
#[derive(Debug)]
pub struct BoundedCommandOutput {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
}

#[derive(Debug)]
struct BoundedReaderOutput {
    bytes: Vec<u8>,
    truncated: bool,
}

/// Run `command` under a deadline, draining both pipes while it runs.
///
/// A child that writes more than a pipe buffer holds would block forever if its
/// output were read only after it exited, so both streams are drained on their
/// own threads and at most `max_stdout_bytes` / `max_stderr_bytes` are retained.
/// A child that outlives `timeout` is killed and reaped, and the call fails with
/// [`std::io::ErrorKind::TimedOut`]; a program that does not exist fails with
/// [`std::io::ErrorKind::NotFound`]. Truncation is reported on the returned
/// value rather than as an error, so a caller that only needs the exit status
/// still learns that it did not see all of the output.
pub fn run_bounded_command(
    command: &mut Command,
    timeout: Duration,
    max_stdout_bytes: usize,
    max_stderr_bytes: usize,
) -> std::io::Result<BoundedCommandOutput> {
    if timeout.is_zero() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "a bounded command needs a non-zero deadline",
        ));
    }

    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Every bounded subprocess is spawned here, so the no-window flag is applied
    // at this one choke point: a console tool must never flash a window when the
    // app runs it on a user's behalf. No-op off Windows.
    apply_hidden_window(command);

    let mut child = command.spawn()?;

    let stdout = child.stdout.take().ok_or_else(|| {
        std::io::Error::other("a bounded command could not capture its stdout pipe")
    })?;
    let stderr = child.stderr.take().ok_or_else(|| {
        std::io::Error::other("a bounded command could not capture its stderr pipe")
    })?;

    let stdout_reader = match spawn_bounded_reader(stdout, max_stdout_bytes, "stdout") {
        Ok(reader) => reader,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
    };
    let stderr_reader = match spawn_bounded_reader(stderr, max_stderr_bytes, "stderr") {
        Ok(reader) => reader,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_reader.join();
            return Err(error);
        }
    };

    let deadline = Instant::now() + timeout;
    let (status, timed_out) = loop {
        match child.try_wait() {
            Ok(Some(status)) => break (status, false),
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Ok(None) => {
                let _ = child.kill();
                let status = child.wait()?;
                break (status, true);
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                return Err(error);
            }
        }
    };

    let stdout = join_bounded_reader(stdout_reader, "stdout")?;
    let stderr = join_bounded_reader(stderr_reader, "stderr")?;
    if timed_out {
        return Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "the command exceeded its deadline and was terminated",
        ));
    }

    Ok(BoundedCommandOutput {
        status,
        stdout: stdout.bytes,
        stderr: stderr.bytes,
        stdout_truncated: stdout.truncated,
        stderr_truncated: stderr.truncated,
    })
}

fn spawn_bounded_reader<R>(
    reader: R,
    max_bytes: usize,
    stream_name: &str,
) -> std::io::Result<std::thread::JoinHandle<std::io::Result<BoundedReaderOutput>>>
where
    R: Read + Send + 'static,
{
    std::thread::Builder::new()
        .name(format!("bounded-command-{stream_name}"))
        .spawn(move || drain_bounded_reader(reader, max_bytes))
        .map_err(|error| {
            std::io::Error::other(format!(
                "a bounded command could not start its {stream_name} reader: {error}"
            ))
        })
}

fn drain_bounded_reader(
    mut reader: impl Read,
    max_bytes: usize,
) -> std::io::Result<BoundedReaderOutput> {
    let mut bytes = Vec::with_capacity(max_bytes.min(8 * 1024));
    let mut truncated = false;
    let mut buffer = [0_u8; 8 * 1024];

    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let remaining = max_bytes.saturating_sub(bytes.len());
        let retained = remaining.min(read);
        bytes.extend_from_slice(&buffer[..retained]);
        truncated |= retained < read;
    }

    Ok(BoundedReaderOutput { bytes, truncated })
}

fn join_bounded_reader(
    reader: std::thread::JoinHandle<std::io::Result<BoundedReaderOutput>>,
    stream_name: &str,
) -> std::io::Result<BoundedReaderOutput> {
    reader
        .join()
        .map_err(|_| {
            std::io::Error::other(format!(
                "a bounded command's {stream_name} reader stopped unexpectedly"
            ))
        })?
        .map_err(|error| {
            std::io::Error::other(format!(
                "a bounded command's {stream_name} could not be read: {error}"
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hidden_command_builds_requested_program() {
        let cmd = hidden_command("powershell.exe");

        assert_eq!(cmd.get_program(), "powershell.exe");
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn hidden_window_flag_matches_win32_create_no_window() {
        assert_eq!(CREATE_NO_WINDOW, 0x0800_0000);
    }
}
