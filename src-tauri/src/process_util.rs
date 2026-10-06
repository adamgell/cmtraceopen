//! Helpers for spawning child processes: no console window flash on Windows
//! (issue #138), and a deadline plus output caps for tools that can hang or
//! talk too much (issue #684).

use std::io::Read;
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::fd::AsRawFd as PipeHandle;
#[cfg(windows)]
use std::os::windows::io::AsRawHandle as PipeHandle;

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
/// output were read only after it exited, so both streams are polled without
/// blocking and at most `max_stdout_bytes` / `max_stderr_bytes` are retained.
/// The deadline covers child exit and both pipe EOFs. On timeout the direct
/// child is killed and reaped and our pipe handles are closed; descendants may
/// survive, but cannot retain our reader resources or prolong the call. It fails with
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

    let deadline = Instant::now().checked_add(timeout).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "command deadline is too large",
        )
    })?;
    let mut child = command.spawn()?;
    let result = (|| {
        let mut stdout = child.stdout.take().ok_or_else(|| {
            std::io::Error::other("a bounded command could not capture its stdout pipe")
        })?;
        let mut stderr = child.stderr.take().ok_or_else(|| {
            std::io::Error::other("a bounded command could not capture its stderr pipe")
        })?;
        prepare_pipe(&stdout)?;
        prepare_pipe(&stderr)?;
        let mut stdout_output = BoundedReaderOutput::new(max_stdout_bytes);
        let mut stderr_output = BoundedReaderOutput::new(max_stderr_bytes);
        let mut stdout_done = false;
        let mut stderr_done = false;
        let mut status = None;
        loop {
            if Instant::now() >= deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "the command or its output pipes exceeded the deadline",
                ));
            }
            // One bounded read from each stream per turn keeps a noisy stream
            // from starving the other stream or the deadline check.
            let mut progressed = false;
            if !stdout_done {
                progressed |=
                    stdout_output.poll(&mut stdout, max_stdout_bytes, &mut stdout_done)?;
            }
            if !stderr_done {
                progressed |=
                    stderr_output.poll(&mut stderr, max_stderr_bytes, &mut stderr_done)?;
            }
            if status.is_none() {
                status = child.try_wait()?;
            }
            if let Some(status) = status.filter(|_| stdout_done && stderr_done) {
                return Ok(BoundedCommandOutput {
                    status,
                    stdout: stdout_output.bytes,
                    stderr: stderr_output.bytes,
                    stdout_truncated: stdout_output.truncated,
                    stderr_truncated: stderr_output.truncated,
                });
            }
            if !progressed {
                std::thread::sleep(
                    Duration::from_millis(5)
                        .min(deadline.saturating_duration_since(Instant::now())),
                );
            }
        }
    })();
    // The closure drops both owned pipes before cleanup, even if a descendant
    // retains a write handle. No reader threads are left blocked on those pipes.
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    result
}

/// Refuse partial tool evidence before a consumer parses or projects it.
pub fn ensure_complete_output(output: &BoundedCommandOutput) -> std::io::Result<()> {
    if output.stdout_truncated || output.stderr_truncated {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "tool output exceeded its byte limit; result is incomplete",
        ));
    }
    Ok(())
}

/// Run a tool whose consumer requires complete output from both streams.
pub fn run_complete_command(
    command: &mut Command,
    timeout: Duration,
    max_stdout_bytes: usize,
    max_stderr_bytes: usize,
) -> std::io::Result<BoundedCommandOutput> {
    let output = run_bounded_command(command, timeout, max_stdout_bytes, max_stderr_bytes)?;
    ensure_complete_output(&output)?;
    Ok(output)
}
impl BoundedReaderOutput {
    fn new(max_bytes: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(max_bytes.min(8 * 1024)),
            truncated: false,
        }
    }

    fn poll(
        &mut self,
        pipe: &mut (impl Read + PipeHandle),
        max_bytes: usize,
        done: &mut bool,
    ) -> std::io::Result<bool> {
        let mut buffer = [0_u8; 8 * 1024];
        match read_pipe(pipe, &mut buffer) {
            Ok(0) => {
                *done = true;
                Ok(true)
            }
            Ok(read) => {
                let retained = max_bytes.saturating_sub(self.bytes.len()).min(read);
                self.bytes.extend_from_slice(&buffer[..retained]);
                self.truncated |= retained < read;
                Ok(true)
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) =>
            {
                Ok(false)
            }
            Err(error) => Err(error),
        }
    }
}

#[cfg(unix)]
fn prepare_pipe(pipe: &impl PipeHandle) -> std::io::Result<()> {
    // SAFETY: the borrowed pipe owns a live descriptor; these fcntl operations
    // only inspect/update that descriptor's flags and retain existing flags.
    unsafe {
        let flags = libc::fcntl(pipe.as_raw_fd(), libc::F_GETFL);
        if flags == -1
            || libc::fcntl(pipe.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) == -1
        {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(unix)]
fn read_pipe(pipe: &mut (impl Read + PipeHandle), buffer: &mut [u8]) -> std::io::Result<usize> {
    pipe.read(buffer)
}

#[cfg(windows)]
fn prepare_pipe(_pipe: &impl PipeHandle) -> std::io::Result<()> {
    Ok(())
}

#[cfg(windows)]
fn read_pipe(pipe: &mut (impl Read + PipeHandle), buffer: &mut [u8]) -> std::io::Result<usize> {
    use windows::Win32::Foundation::{ERROR_BROKEN_PIPE, HANDLE};
    use windows::Win32::System::Pipes::PeekNamedPipe;
    let mut available = 0;
    // SAFETY: the handle is borrowed from a live, exclusively owned read pipe.
    // No other thread issues I/O on it. We read only already-available bytes,
    // avoiding a blocking read while a descendant holds an otherwise empty pipe.
    let result = unsafe {
        PeekNamedPipe(
            HANDLE(pipe.as_raw_handle()),
            None,
            0,
            None,
            Some(&mut available),
            None,
        )
    };
    if let Err(error) = result {
        if error.code() == ERROR_BROKEN_PIPE.to_hresult() {
            return Ok(0);
        }
        return Err(std::io::Error::from_raw_os_error(error.code().0 & 0xffff));
    }
    if available == 0 {
        return Err(std::io::ErrorKind::WouldBlock.into());
    }
    let count = buffer.len().min(available as usize);
    pipe.read(&mut buffer[..count])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn deadline_covers_pipes_held_by_descendants_after_child_exit() {
        let started = Instant::now();
        let result = run_bounded_command(
            Command::new("sh").args(["-c", "sleep 2 & exit 0"]),
            Duration::from_millis(100),
            1024,
            1024,
        );
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "descendant-held pipes exceeded deadline"
        );
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
    }
    // Re-exec the test binary so inherited-pipe behavior is exercised on
    // Windows as well as Unix, without depending on a shell or installed tools.
    #[test]
    #[allow(
        clippy::zombie_processes,
        reason = "the isolated fixture must exit before its descendant to reproduce inherited pipes"
    )]
    fn descendant_pipe_fixture() {
        let Ok(mode) = std::env::var("CMTRACE_BOUNDED_PIPE_FIXTURE") else {
            return;
        };
        if mode == "holder" {
            std::thread::sleep(Duration::from_secs(2));
            return;
        }
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "process_util::tests::descendant_pipe_fixture",
                "--nocapture",
            ])
            .env("CMTRACE_BOUNDED_PIPE_FIXTURE", "holder")
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        if mode == "wait" {
            child.wait().unwrap();
        } else {
            // This fixture must exit before the descendant to reproduce the
            // inherited-pipe case. The parent test invokes only this fixture.
            std::process::exit(0);
        }
    }

    #[test]
    fn deadline_covers_descendant_pipes_on_all_platforms() {
        for mode in ["exit", "wait"] {
            let started = Instant::now();
            let result = run_bounded_command(
                Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "process_util::tests::descendant_pipe_fixture",
                        "--nocapture",
                    ])
                    .env("CMTRACE_BOUNDED_PIPE_FIXTURE", mode),
                Duration::from_millis(300),
                4096,
                4096,
            );
            assert!(
                started.elapsed() < Duration::from_millis(1500),
                "{mode}: descendant-held pipes exceeded deadline"
            );
            assert_eq!(
                result.unwrap_err().kind(),
                std::io::ErrorKind::TimedOut,
                "{mode}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn continuous_output_cannot_starve_deadline() {
        let started = Instant::now();
        let result = run_bounded_command(
            Command::new("sh").args(["-c", "while :; do printf output; printf error >&2; done"]),
            Duration::from_millis(100),
            8,
            8,
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
    }

    #[cfg(unix)]
    #[test]
    fn both_streams_drain_past_caps_and_distinguish_exact_limit() {
        for cap in [0, 4, 5] {
            let output = run_bounded_command(
                Command::new("sh").args(["-c", "printf 12345; printf 67890 >&2"]),
                Duration::from_secs(2),
                cap,
                cap,
            )
            .unwrap();
            assert_eq!(output.stdout, b"12345"[..cap]);
            assert_eq!(output.stderr, b"67890"[..cap]);
            assert_eq!(output.stdout_truncated, cap < 5);
            assert_eq!(output.stderr_truncated, cap < 5);
        }
        let output = run_bounded_command(Command::new("sh").args(["-c", "i=0; while [ $i -lt 10000 ]; do printf 12345678; printf 87654321 >&2; i=$((i+1)); done"]), Duration::from_secs(5), 9, 10).unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout.len(), 9);
        assert_eq!(output.stderr.len(), 10);
        assert!(output.stdout_truncated && output.stderr_truncated);
    }

    #[test]
    fn complete_command_refuses_each_capped_stream() {
        for stderr in [false, true] {
            #[cfg(windows)]
            let mut command = {
                let mut command = Command::new("cmd.exe");
                command.args([
                    "/C",
                    if stderr {
                        "echo bounded-error 1>&2"
                    } else {
                        "echo bounded-output"
                    },
                ]);
                command
            };
            #[cfg(unix)]
            let mut command = {
                let mut command = Command::new("sh");
                command.args([
                    "-c",
                    if stderr {
                        "printf bounded-error >&2"
                    } else {
                        "printf bounded-output"
                    },
                ]);
                command
            };
            let error =
                run_complete_command(&mut command, Duration::from_secs(5), 2, 2).unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        }
    }

    #[test]
    fn complete_command_retains_uncapped_output() {
        #[cfg(windows)]
        let mut command = {
            let mut command = Command::new("cmd.exe");
            command.args(["/C", "echo bounded-output"]);
            command
        };
        #[cfg(unix)]
        let mut command = {
            let mut command = Command::new("sh");
            command.args(["-c", "printf bounded-output"]);
            command
        };
        let output = run_complete_command(&mut command, Duration::from_secs(5), 64, 64).unwrap();
        assert!(output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).contains("bounded-output"));
    }

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
