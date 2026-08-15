#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import tempfile
import time
import sys
from typing import NoReturn, Sequence


PROCESS_ENV_ALLOWLIST = (
    "COMSPEC",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "PATH",
    "PATHEXT",
    "SystemRoot",
    "TEMP",
    "TMP",
    "TMPDIR",
    "WINDIR",
)

def _load_command_policy() -> object:
    path = Path(__file__).with_name("check_command_policy.py")
    spec = importlib.util.spec_from_file_location(
        "cmtraceopen_check_command_policy", path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load repository check policy: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_COMMAND_POLICY = _load_command_policy()
_validate_check_command = getattr(_COMMAND_POLICY, "validate_check_command")


class ContainmentError(RuntimeError):
    def __init__(self, message: str, exit_code: int | None) -> None:
        super().__init__(message)
        self.exit_code = exit_code


def minimal_environment() -> dict[str, str]:
    return {
        key: os.environ[key]
        for key in PROCESS_ENV_ALLOWLIST
        if key in os.environ
    }


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _wait_without_reaping(process: subprocess.Popen[bytes], timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while True:
        status = os.waitid(
            os.P_PID,
            process.pid,
            os.WEXITED | os.WNOWAIT | os.WNOHANG,
        )
        if status is not None:
            return
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(
                f"repository check timed out after {timeout:g} seconds"
            )
        time.sleep(min(0.01, remaining))


def _terminate_group_and_reap(process: subprocess.Popen[bytes]) -> int:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except PermissionError as error:
        try:
            return_code = process.wait(timeout=0)
        except subprocess.TimeoutExpired:
            raise ContainmentError(
                "cannot terminate live repository check process group: "
                f"{error}",
                None,
            ) from error
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            return return_code
        except PermissionError as verification_error:
            error = verification_error
        raise ContainmentError(
            "cannot verify repository check process group termination: "
            f"{error}",
            return_code,
        ) from error
    except ProcessLookupError:
        pass
    return process.wait()


def _captured_text(stream: object) -> str:
    stream.seek(0)
    return stream.read().decode("utf-8", errors="replace")


def _git_environment() -> dict[str, str]:
    environment = minimal_environment()
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    return environment


def _git(cwd: Path, *args: str) -> bytes:
    try:
        result = subprocess.run(
            [
                "git",
                "-c",
                "core.fsmonitor=false",
                "-C",
                str(cwd),
                *args,
            ],
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_git_environment(),
            timeout=30,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        detail = getattr(error, "stderr", b"").decode(
            "utf-8", errors="replace"
        ).strip()
        raise ValueError(
            f"cannot observe lane Git state"
            + (f": {detail}" if detail else "")
        ) from error
    return result.stdout


def _git_text(cwd: Path, *args: str) -> str:
    try:
        return _git(cwd, *args).decode("utf-8").rstrip("\n")
    except UnicodeDecodeError as error:
        raise ValueError("lane Git identity is not valid UTF-8") from error


def _path_identity(path: Path) -> dict[str, int]:
    if not path.is_absolute():
        raise ValueError("repository check cwd must be absolute")
    try:
        info = path.lstat()
    except OSError as error:
        raise ValueError(f"repository check cwd is unavailable: {error}") from error
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise ValueError("repository check cwd must be a real directory")
    return {"device": info.st_dev, "inode": info.st_ino}


def _registration(cwd: Path) -> dict[bytes, bytes]:
    output = _git(cwd, "worktree", "list", "--porcelain", "-z")
    if not output or not output.endswith(b"\0\0"):
        raise ValueError("malformed Git worktree registration output")
    encoded_cwd = os.fsencode(str(cwd))
    matches: list[dict[bytes, bytes]] = []
    for record in output[:-2].split(b"\0\0"):
        fields: dict[bytes, bytes] = {}
        for field in record.split(b"\0"):
            key, separator, value = field.partition(b" ")
            if not key or key in fields:
                raise ValueError("malformed Git worktree registration")
            if key in {b"worktree", b"HEAD", b"branch"} and (
                not separator or not value
            ):
                raise ValueError("malformed Git worktree registration")
            fields[key] = value
        if fields.get(b"worktree") == encoded_cwd:
            matches.append(fields)
    if len(matches) != 1:
        raise ValueError("repository check cwd is not uniquely Git-registered")
    registration = matches[0]
    if b"prunable" in registration:
        raise ValueError("repository check cwd Git registration is prunable")
    return registration


def observe_worktree(cwd: Path) -> dict[str, object]:
    identity = _path_identity(cwd)
    try:
        top_level = Path(
            _git_text(
                cwd,
                "rev-parse",
                "--path-format=absolute",
                "--show-toplevel",
            )
        ).resolve(strict=True)
        common_dir = Path(
            _git_text(
                cwd,
                "rev-parse",
                "--path-format=absolute",
                "--git-common-dir",
            )
        ).resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise ValueError(f"cannot canonicalize lane Git identity: {error}") from error
    if top_level != cwd:
        raise ValueError("repository check cwd is not the Git worktree top level")
    head_sha = _git_text(cwd, "rev-parse", "--verify", "HEAD")
    if re.fullmatch(r"[0-9a-fA-F]{40}", head_sha) is None:
        raise ValueError("observed lane HEAD is not a 40-hex SHA")
    branch_ref = _git_text(cwd, "symbolic-ref", "--quiet", "HEAD")
    if not branch_ref.startswith("refs/heads/"):
        raise ValueError("repository check cwd is not on a local branch")
    branch = branch_ref.removeprefix("refs/heads/")
    registration = _registration(cwd)
    if registration.get(b"HEAD", b"").decode("ascii", errors="replace") != head_sha:
        raise ValueError("Git registration HEAD does not match observed HEAD")
    if os.fsdecode(registration.get(b"branch", b"")) != branch_ref:
        raise ValueError("Git registration branch does not match observed branch")
    if _path_identity(cwd) != identity:
        raise ValueError("repository check cwd changed while observing Git state")
    return {
        "worktree": str(cwd),
        "worktreeIdentity": identity,
        "gitCommonDir": str(common_dir),
        "branch": branch,
        "headSha": head_sha,
    }


def _validate_expected_worktree(
    observed: dict[str, object],
    *,
    worktree_device: int,
    worktree_inode: int,
    git_common_dir: Path,
    branch: str,
    head_sha: str,
) -> None:
    if (
        isinstance(worktree_device, bool)
        or not isinstance(worktree_device, int)
        or worktree_device < 0
        or isinstance(worktree_inode, bool)
        or not isinstance(worktree_inode, int)
        or worktree_inode < 0
    ):
        raise ValueError("manifest-bound worktree identity is invalid")
    if not branch or re.fullmatch(r"[0-9a-fA-F]{40}", head_sha) is None:
        raise ValueError("manifest-bound branch or HEAD is invalid")
    try:
        expected_common_dir = git_common_dir.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise ValueError(
            f"manifest-bound Git common directory is unavailable: {error}"
        ) from error
    expected = {
        "worktree": observed["worktree"],
        "worktreeIdentity": {
            "device": worktree_device,
            "inode": worktree_inode,
        },
        "gitCommonDir": str(expected_common_dir),
        "branch": branch,
        "headSha": head_sha,
    }
    if observed != expected:
        raise ValueError(
            "repository check cwd identity, Git registration, branch, or HEAD "
            "does not match the lane manifest"
        )


def _observe_expected_worktree(
    cwd: Path,
    *,
    worktree_device: int,
    worktree_inode: int,
    git_common_dir: Path,
    branch: str,
    head_sha: str,
) -> dict[str, object]:
    observed = observe_worktree(cwd)
    _validate_expected_worktree(
        observed,
        worktree_device=worktree_device,
        worktree_inode=worktree_inode,
        git_common_dir=git_common_dir,
        branch=branch,
        head_sha=head_sha,
    )
    return observed


def _artifact(
    command: Sequence[str],
    *,
    binding: dict[str, object] | None,
    base_sha: str,
    outcome: str,
    exit_code: int | None,
    stdout: str,
    stderr: str,
    failure_classification: str,
    error: str | None,
) -> dict[str, object]:
    return {
        "schemaVersion": 2,
        "kind": "repo_check",
        "outcome": outcome,
        "command": list(command),
        "worktree": None if binding is None else binding["worktree"],
        "worktreeIdentity": (
            None if binding is None else binding["worktreeIdentity"]
        ),
        "gitCommonDir": None if binding is None else binding["gitCommonDir"],
        "branch": None if binding is None else binding["branch"],
        "headSha": None if binding is None else binding["headSha"],
        "baseSha": base_sha,
        "exitCode": exit_code,
        "observedAt": _utc_now(),
        "stdout": stdout,
        "stderr": stderr,
        "failureClassification": failure_classification,
        "error": error,
    }


def run(
    command: Sequence[str],
    *,
    cwd: Path,
    timeout: float,
    worktree_device: int,
    worktree_inode: int,
    git_common_dir: Path,
    branch: str,
    head_sha: str,
    base_sha: str,
) -> dict[str, object]:
    command = _validate_check_command(command)
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("repository check timeout must be finite and positive")
    if os.name != "posix":
        return _artifact(
            command,
            binding=None,
            base_sha=base_sha,
            outcome="setup_failed",
            exit_code=None,
            stdout="",
            stderr="",
            failure_classification="runner_failure",
            error="repository checks require POSIX process-group isolation",
        )
    try:
        binding = _observe_expected_worktree(
            cwd,
            worktree_device=worktree_device,
            worktree_inode=worktree_inode,
            git_common_dir=git_common_dir,
            branch=branch,
            head_sha=head_sha,
        )
    except ValueError as error:
        return _artifact(
            command,
            binding=None,
            base_sha=base_sha,
            outcome="setup_failed",
            exit_code=None,
            stdout="",
            stderr="",
            failure_classification="runner_failure",
            error=str(error),
        )

    def finish(
        *,
        outcome: str,
        exit_code: int | None,
        stdout: str,
        stderr: str,
        failure_classification: str,
        error: str | None,
    ) -> dict[str, object]:
        try:
            after = _observe_expected_worktree(
                cwd,
                worktree_device=worktree_device,
                worktree_inode=worktree_inode,
                git_common_dir=git_common_dir,
                branch=branch,
                head_sha=head_sha,
            )
            if after != binding:
                raise ValueError(
                    "repository check cwd identity changed during execution"
                )
        except ValueError as binding_error:
            return _artifact(
                command,
                binding=binding,
                base_sha=base_sha,
                outcome="setup_failed",
                exit_code=None,
                stdout=stdout,
                stderr=stderr,
                failure_classification="runner_failure",
                error=str(binding_error),
            )
        return _artifact(
            command,
            binding=after,
            base_sha=base_sha,
            outcome=outcome,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            failure_classification=failure_classification,
            error=error,
        )

    with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
        try:
            process = subprocess.Popen(
                list(command),
                cwd=cwd,
                env=minimal_environment(),
                stdin=subprocess.DEVNULL,
                stdout=stdout_file,
                stderr=stderr_file,
                start_new_session=True,
            )
        except OSError as error:
            return finish(
                outcome="spawn_failed",
                exit_code=None,
                stdout="",
                stderr="",
                failure_classification="runner_failure",
                error=f"cannot execute repository check: {error}",
            )

        try:
            _wait_without_reaping(process, timeout)
        except TimeoutError as timeout_error:
            try:
                _terminate_group_and_reap(process)
            except ContainmentError as containment_error:
                return finish(
                    outcome="containment_failed",
                    exit_code=containment_error.exit_code,
                    stdout=_captured_text(stdout_file),
                    stderr=_captured_text(stderr_file),
                    failure_classification="runner_failure",
                    error=str(containment_error),
                )
            return finish(
                outcome="timed_out",
                exit_code=None,
                stdout=_captured_text(stdout_file),
                stderr=_captured_text(stderr_file),
                failure_classification="runner_failure",
                error=str(timeout_error),
            )
        except BaseException:
            _terminate_group_and_reap(process)
            raise

        try:
            exit_code = _terminate_group_and_reap(process)
        except ContainmentError as error:
            return finish(
                outcome="containment_failed",
                exit_code=error.exit_code,
                stdout=_captured_text(stdout_file),
                stderr=_captured_text(stderr_file),
                failure_classification="runner_failure",
                error=str(error),
            )
        stdout = _captured_text(stdout_file)
        stderr = _captured_text(stderr_file)

    return finish(
        outcome="completed",
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        failure_classification=("success" if exit_code == 0 else "command_failure"),
        error=None,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run repository-controlled checks without parent credentials."
    )
    parser.add_argument("--cwd", required=True, type=Path)
    parser.add_argument("--timeout", required=True, type=float)
    parser.add_argument("--expected-worktree-device", required=True, type=int)
    parser.add_argument("--expected-worktree-inode", required=True, type=int)
    parser.add_argument("--expected-git-common-dir", required=True, type=Path)
    parser.add_argument("--expected-branch", required=True)
    parser.add_argument("--expected-head-sha", required=True)
    parser.add_argument("--base-sha", required=True)
    parser.add_argument("--artifact", required=True, type=Path)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.command[:1] == ["--"]:
        args.command = args.command[1:]
    return args


def _publish_artifact(path: Path, artifact: dict[str, object]) -> None:
    if path.name in {"", ".", ".."}:
        raise ValueError("artifact path must name a file")
    content = (
        json.dumps(artifact, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    parent = path.parent
    before = parent.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
        raise ValueError("artifact parent must be a real directory")
    directory_fd = os.open(
        parent,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    identity = (before.st_dev, before.st_ino)
    try:
        opened = os.fstat(directory_fd)
        if (opened.st_dev, opened.st_ino) != identity:
            raise OSError("artifact parent changed while opening")
        descriptor = os.open(
            path.name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory_fd,
        )
        try:
            view = memoryview(content)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("artifact write made no progress")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.fsync(directory_fd)
        after = parent.lstat()
        opened_after = os.fstat(directory_fd)
        if (
            stat.S_ISLNK(after.st_mode)
            or (after.st_dev, after.st_ino) != identity
            or (opened_after.st_dev, opened_after.st_ino) != identity
        ):
            raise OSError("artifact parent changed during publication")
    finally:
        os.close(directory_fd)


def _cli_exit_code(artifact: dict[str, object]) -> int:
    if artifact["outcome"] != "completed":
        return 2
    exit_code = artifact["exitCode"]
    if not isinstance(exit_code, int):
        return 2
    if exit_code < 0:
        return min(255, 128 + abs(exit_code))
    return min(255, exit_code)


def main() -> NoReturn:
    args = parse_args()
    try:
        artifact = run(
            args.command,
            cwd=args.cwd,
            timeout=args.timeout,
            worktree_device=args.expected_worktree_device,
            worktree_inode=args.expected_worktree_inode,
            git_common_dir=args.expected_git_common_dir,
            branch=args.expected_branch,
            head_sha=args.expected_head_sha,
            base_sha=args.base_sha,
        )
        _publish_artifact(args.artifact, artifact)
    except (OSError, ValueError) as error:
        raise SystemExit(f"error: {error}") from error
    print(json.dumps(artifact, sort_keys=True, separators=(",", ":")))
    raise SystemExit(_cli_exit_code(artifact))


if __name__ == "__main__":
    main()
