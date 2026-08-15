from __future__ import annotations

import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest import mock


SKILL_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = SKILL_ROOT / "scripts" / "run_repo_check.py"
SPEC = importlib.util.spec_from_file_location("run_repo_check", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
run_repo_check = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(run_repo_check)


HEAD_SHA = "a" * 40
BASE_SHA = "b" * 40


def fake_binding(cwd: Path, head_sha: str) -> dict[str, object]:
    info = cwd.lstat()
    return {
        "worktree": str(cwd),
        "worktreeIdentity": {"device": info.st_dev, "inode": info.st_ino},
        "gitCommonDir": str(cwd),
        "branch": "omp/issue-317",
        "headSha": head_sha,
    }


def run_check(
    command: list[str] | tuple[str, ...],
    *,
    cwd: Path,
    timeout: float,
    head_sha: str = HEAD_SHA,
    base_sha: str = BASE_SHA,
) -> dict[str, object]:
    canonical_cwd = cwd.resolve(strict=True)
    info = canonical_cwd.lstat()
    arguments = {
        "cwd": canonical_cwd,
        "timeout": timeout,
        "worktree_device": info.st_dev,
        "worktree_inode": info.st_ino,
        "git_common_dir": canonical_cwd,
        "branch": "omp/issue-317",
        "head_sha": head_sha,
        "base_sha": base_sha,
    }
    if not canonical_cwd.is_dir():
        return run_repo_check.run(command, **arguments)
    with mock.patch.object(
        run_repo_check,
        "observe_worktree",
        return_value=fake_binding(canonical_cwd, head_sha),
    ):
        return run_repo_check.run(command, **arguments)


def run_git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={
            **os.environ,
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
        },
        timeout=15,
    )
    return result.stdout.strip()


def create_registered_repo(root: Path) -> tuple[Path, dict[str, object]]:
    repo = root / "repo"
    repo.mkdir()
    repo = repo.resolve(strict=True)
    run_git(repo, "init", "--quiet")
    run_git(repo, "config", "user.name", "Runner Tests")
    run_git(repo, "config", "user.email", "runner@example.invalid")
    (repo / "tracked.txt").write_text("baseline\n", encoding="utf-8")
    run_git(repo, "add", "tracked.txt")
    run_git(repo, "commit", "--quiet", "-m", "baseline")
    run_git(repo, "checkout", "--quiet", "-b", "omp/issue-317")
    return repo, run_repo_check.observe_worktree(repo)


def run_bound_check(
    command: list[str],
    *,
    cwd: Path,
    binding: dict[str, object],
    base_sha: str = BASE_SHA,
) -> dict[str, object]:
    identity = binding["worktreeIdentity"]
    assert isinstance(identity, dict)
    return run_repo_check.run(
        command,
        cwd=cwd,
        timeout=30,
        worktree_device=identity["device"],
        worktree_inode=identity["inode"],
        git_common_dir=Path(str(binding["gitCommonDir"])),
        branch=str(binding["branch"]),
        head_sha=str(binding["headSha"]),
        base_sha=base_sha,
    )


class RepositoryCheckTests(unittest.TestCase):
    def test_repository_code_cannot_observe_parent_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            observed = root / "observed.txt"
            test_module = root / "test_credentials.py"
            test_module.write_text(
                "import os\n"
                "from pathlib import Path\n"
                "import unittest\n\n"
                "class CredentialVisibilityTests(unittest.TestCase):\n"
                "    def test_parent_credentials_are_absent(self):\n"
                f"        Path({str(observed)!r}).write_text(str(any("
                "name in os.environ for name in "
                "('LLMGATEWAY_API_KEY', 'GH_TOKEN', 'GITHUB_TOKEN', "
                "'AWS_SECRET_ACCESS_KEY'))), encoding='utf-8')\n",
                encoding="utf-8",
            )
            with mock.patch.dict(
                os.environ,
                {
                    "LLMGATEWAY_API_KEY": "gateway-secret",
                    "GH_TOKEN": "github-secret",
                    "GITHUB_TOKEN": "github-secret",
                    "AWS_SECRET_ACCESS_KEY": "cloud-secret",
                },
            ):
                result = run_check(["python3", "-m", "unittest", "test_credentials"],
                cwd=root,
                timeout=30,
                head_sha="a" * 40,
                base_sha="b" * 40,)

            self.assertEqual("completed", result["outcome"])
            self.assertEqual("success", result["failureClassification"])
            self.assertEqual(0, result["exitCode"])
            self.assertEqual("False", observed.read_text(encoding="utf-8"))

    def test_artifact_binds_independently_observed_worktree_and_head(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo, binding = create_registered_repo(Path(directory))

            result = run_bound_check(
                ["git", "diff", "--check"],
                cwd=repo,
                binding=binding,
            )

            self.assertEqual("completed", result["outcome"])
            self.assertEqual(binding["worktree"], result["worktree"])
            self.assertEqual(
                binding["worktreeIdentity"],
                result["worktreeIdentity"],
            )
            self.assertEqual(binding["gitCommonDir"], result["gitCommonDir"])
            self.assertEqual(binding["branch"], result["branch"])
            self.assertEqual(binding["headSha"], result["headSha"])

    def test_renamed_lane_replacements_block_before_replacement_code_runs(
        self,
    ) -> None:
        for replacement_kind in ("symlink", "directory", "primary_checkout"):
            with self.subTest(replacement=replacement_kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                repo, binding = create_registered_repo(root)
                displaced = root / "displaced"
                repo.rename(displaced)
                replacement = root / "repo"
                target = replacement
                if replacement_kind == "symlink":
                    target = root / "symlink-target"
                    target.mkdir()
                    os.symlink(target, replacement, target_is_directory=True)
                else:
                    replacement.mkdir()
                marker = target / "replacement-ran"
                test_module = target / "test_replacement.py"
                test_module.write_text(
                    "from pathlib import Path\n"
                    "import unittest\n\n"
                    "class ReplacementTests(unittest.TestCase):\n"
                    "    def test_replacement(self):\n"
                    f"        Path({str(marker)!r}).write_text('ran', encoding='utf-8')\n",
                    encoding="utf-8",
                )
                if replacement_kind == "primary_checkout":
                    run_git(replacement, "init", "--quiet")
                    run_git(replacement, "config", "user.name", "Replacement")
                    run_git(
                        replacement,
                        "config",
                        "user.email",
                        "replacement@example.invalid",
                    )
                    run_git(replacement, "add", "test_replacement.py")
                    run_git(replacement, "commit", "--quiet", "-m", "replacement")
                    run_git(
                        replacement,
                        "checkout",
                        "--quiet",
                        "-b",
                        "omp/issue-317",
                    )

                result = run_bound_check(
                    ["python3", "-m", "unittest", "test_replacement"],
                    cwd=replacement,
                    binding=binding,
                )

                self.assertEqual("setup_failed", result["outcome"])
                self.assertEqual(
                    "runner_failure",
                    result["failureClassification"],
                )
                self.assertFalse(marker.exists())

    def test_runner_uses_no_shell_and_a_bounded_process_group(self) -> None:

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            process_handle = mock.Mock(pid=123)
            process_handle.wait.return_value = 7
            with mock.patch.object(
                run_repo_check.subprocess,
                "Popen",
                return_value=process_handle,
            ) as process, mock.patch.object(
                run_repo_check.os,
                "waitid",
                return_value=object(),
            ) as waitid, mock.patch.object(
                run_repo_check.os,
                "killpg",
            ) as kill_group:
                result = run_check(["cargo", "test", "--package", "cmtraceopen-parser"],
                cwd=root,
                timeout=12,
                head_sha="a" * 40,
                base_sha="b" * 40,)

            self.assertEqual("completed", result["outcome"])
            self.assertEqual("command_failure", result["failureClassification"])
            self.assertEqual(7, result["exitCode"])
            self.assertEqual(
                ["cargo", "test", "--package", "cmtraceopen-parser"],
                process.call_args.args[0],
            )
            self.assertEqual(root.resolve(), process.call_args.kwargs["cwd"])
            self.assertEqual(subprocess.DEVNULL, process.call_args.kwargs["stdin"])
            self.assertTrue(process.call_args.kwargs["start_new_session"])
            self.assertNotIn("shell", process.call_args.kwargs)
            waitid.assert_called_once_with(
                run_repo_check.os.P_PID,
                123,
                (
                    run_repo_check.os.WEXITED
                    | run_repo_check.os.WNOWAIT
                    | run_repo_check.os.WNOHANG
                ),
            )
            process_handle.wait.assert_called_once_with()
            kill_group.assert_called_once_with(123, run_repo_check.signal.SIGKILL)

    def test_timeout_is_structurally_distinct_and_reaps_process_group(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            process_handle = mock.Mock(pid=456)
            process_handle.wait.return_value = -9
            with mock.patch.object(
                run_repo_check.subprocess,
                "Popen",
                return_value=process_handle,
            ), mock.patch.object(
                run_repo_check,
                "_wait_without_reaping",
                side_effect=TimeoutError("timed out"),
            ), mock.patch.object(
                run_repo_check.os,
                "killpg",
            ) as kill_group:
                result = run_check(["cargo", "test"],
                cwd=Path(directory),
                timeout=1,
                head_sha="a" * 40,
                base_sha="b" * 40,)

            self.assertEqual("timed_out", result["outcome"])
            self.assertEqual("runner_failure", result["failureClassification"])
            self.assertIsNone(result["exitCode"])
            kill_group.assert_called_once_with(456, run_repo_check.signal.SIGKILL)
            process_handle.wait.assert_called_once_with()

    def test_runner_terminates_descendants_after_parent_exits(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pid_path = root / "descendant.pid"
            sentinel = root / "descendant-survived"
            descendant = (
                "import os, pathlib, time; "
                f"pathlib.Path({str(pid_path)!r}).write_text(str(os.getpid())); "
                "time.sleep(30); "
                f"pathlib.Path({str(sentinel)!r}).write_text('survived')"
            )
            test_module = root / "test_descendant.py"
            test_module.write_text(
                "import pathlib\n"
                "import subprocess\n"
                "import sys\n"
                "import time\n"
                "import unittest\n\n"
                "class DescendantTests(unittest.TestCase):\n"
                "    def test_spawn_descendant(self):\n"
                f"        subprocess.Popen([sys.executable, '-c', {descendant!r}])\n"
                f"        pid_path = pathlib.Path({str(pid_path)!r})\n"
                "        deadline = time.monotonic() + 5\n"
                "        while time.monotonic() < deadline and not pid_path.exists():\n"
                "            time.sleep(0.01)\n"
                "        self.assertTrue(pid_path.exists())\n",
                encoding="utf-8",
            )

            result = run_check(
                ["python3", "-m", "unittest", "test_descendant"],
                cwd=root,
                timeout=30,
                head_sha="a" * 40,
                base_sha="b" * 40,
            )
            pid = int(pid_path.read_text(encoding="utf-8"))
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    break
                time.sleep(0.05)
            else:
                self.fail("runner descendant remained alive after group termination")

            self.assertEqual("completed", result["outcome"])
            self.assertEqual(0, result["exitCode"])
            self.assertFalse(sentinel.exists())

    def test_runner_bounds_actual_stdout_and_stderr_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output_size = run_repo_check.CAPTURE_LIMIT_BYTES + 257
            (root / "test_output.py").write_text(
                "import sys\n"
                "import unittest\n\n"
                "class OutputTests(unittest.TestCase):\n"
                "    def test_output(self):\n"
                f"        sys.stdout.write('o' * {output_size})\n"
                f"        sys.stderr.write('e' * {output_size})\n",
                encoding="utf-8",
            )

            result = run_check(
                ["python3", "-m", "unittest", "test_output"],
                cwd=root,
                timeout=30,
                head_sha="a" * 40,
                base_sha="b" * 40,
            )

            self.assertEqual("completed", result["outcome"])
            self.assertEqual(
                run_repo_check.CAPTURE_LIMIT_BYTES,
                len(result["stdout"]),
            )
            self.assertEqual(
                run_repo_check.CAPTURE_LIMIT_BYTES,
                len(result["stderr"]),
            )
            self.assertTrue(result["stdoutTruncated"])
            self.assertTrue(result["stderrTruncated"])

    def test_artifact_write_failure_leaves_destination_retryable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "check.json"
            artifact = {"kind": "repo_check", "value": "complete"}
            before = set(root.iterdir())

            with mock.patch.object(
                run_repo_check.os,
                "write",
                side_effect=OSError("injected write failure"),
            ), self.assertRaisesRegex(OSError, "injected write failure"):
                run_repo_check._publish_artifact(path, artifact)

            self.assertFalse(path.exists())
            self.assertEqual(before, set(root.iterdir()))
            run_repo_check._publish_artifact(path, artifact)
            self.assertEqual(artifact, json.loads(path.read_text(encoding="utf-8")))
            self.assertEqual({path}, set(root.iterdir()))

    def test_artifact_publication_failures_roll_back_and_retry(self) -> None:
        real_fsync = os.fsync
        for fail_at in (1, 2, 3):
            with self.subTest(fail_at=fail_at), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                path = root / "check.json"
                artifact = {"kind": "repo_check", "value": "complete"}
                before = set(root.iterdir())
                calls = 0

                def fsync(descriptor: int) -> None:
                    nonlocal calls
                    calls += 1
                    if calls == fail_at:
                        raise OSError("injected publication failure")
                    real_fsync(descriptor)

                with mock.patch.object(
                    run_repo_check.os,
                    "fsync",
                    side_effect=fsync,
                ), self.assertRaisesRegex(OSError, "injected publication failure"):
                    run_repo_check._publish_artifact(path, artifact)
                expected_calls = fail_at if fail_at == 1 else fail_at + 1
                self.assertEqual(expected_calls, calls)

                self.assertFalse(path.exists())
                self.assertEqual(before, set(root.iterdir()))
                run_repo_check._publish_artifact(path, artifact)
                self.assertEqual(
                    artifact,
                    json.loads(path.read_text(encoding="utf-8")),
                )

    def test_artifact_publication_is_create_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "check.json"
            original = {"value": "original"}
            run_repo_check._publish_artifact(path, original)

            with self.assertRaises(FileExistsError):
                run_repo_check._publish_artifact(path, {"value": "replacement"})

            self.assertEqual(original, json.loads(path.read_text(encoding="utf-8")))

    def test_spawn_is_runner_failure_but_import_error_is_completed_command(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with mock.patch.dict(
                os.environ,
                {"PATH": str(root)},
            ):
                spawn = run_check(["mdbook", "build"],
                cwd=root,
                timeout=30,
                head_sha="a" * 40,
                base_sha="b" * 40,)
            imported = run_check(["python3", "-m", "unittest", "definitely_missing_repo_module"],
            cwd=root,
            timeout=30,
            head_sha="a" * 40,
            base_sha="b" * 40,)

            self.assertEqual("spawn_failed", spawn["outcome"])
            self.assertEqual("completed", imported["outcome"])
            self.assertEqual(
                "command_failure",
                imported["failureClassification"],
            )

    def test_printed_expected_marker_and_crash_never_self_classifies(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            test_module = root / "test_crash.py"
            test_module.write_text(
                "import unittest\n\n"
                "class CrashTests(unittest.TestCase):\n"
                "    def test_crash(self):\n"
                "        print('expected assertion')\n"
                "        raise RuntimeError('crash')\n",
                encoding="utf-8",
            )
            result = run_check(["python3", "-m", "unittest", "test_crash"],
            cwd=root,
            timeout=30,
            head_sha="a" * 40,
            base_sha="b" * 40,)

            self.assertEqual("completed", result["outcome"])
            self.assertEqual("command_failure", result["failureClassification"])

    def test_process_group_termination_denial_never_reports_success(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            process_handle = mock.Mock(pid=789)
            process_handle.wait.return_value = 0
            with mock.patch.object(
                run_repo_check.subprocess,
                "Popen",
                return_value=process_handle,
            ), mock.patch.object(
                run_repo_check.os,
                "waitid",
                return_value=object(),
            ), mock.patch.object(
                run_repo_check.os,
                "killpg",
                side_effect=PermissionError("denied"),
            ):
                result = run_check(["cargo", "check"],
                cwd=Path(directory),
                timeout=30,
                head_sha="a" * 40,
                base_sha="b" * 40,)

            self.assertEqual("containment_failed", result["outcome"])
            self.assertEqual("runner_failure", result["failureClassification"])
            self.assertEqual(0, result["exitCode"])
            process_handle.wait.assert_called_once_with(timeout=0)

    def test_exited_zombie_only_group_is_verified_absent_after_reap(self) -> None:
        process_handle = mock.Mock(pid=789)
        process_handle.wait.return_value = 0
        with mock.patch.object(
            run_repo_check.os,
            "killpg",
            side_effect=[
                PermissionError("zombie-only group"),
                ProcessLookupError(),
            ],
        ) as killpg:
            self.assertEqual(
                0,
                run_repo_check._terminate_group_and_reap(process_handle),
            )

        process_handle.wait.assert_called_once_with(timeout=0)
        self.assertEqual(
            [
                mock.call(789, run_repo_check.signal.SIGKILL),
                mock.call(789, 0),
            ],
            killpg.call_args_list,
        )

    def test_runner_accepts_every_checked_in_repository_check_form(self) -> None:
        allowed = (
            ("python3", "-m", "unittest", "tests.focused", "-v"),
            (
                "python3",
                "-m",
                "unittest",
                "discover",
                "-s",
                "tests",
                "-p",
                "test_*.py",
            ),
            (
                "python3",
                "-m",
                "unittest",
                "discover",
                "tests",
                "test_*.py",
                ".",
            ),
            ("cargo", "test", "--package", "cmtraceopen-parser"),
            ("cargo", "check", "--workspace", "--all-targets"),
            ("cargo", "clippy", "--workspace", "--", "-D", "warnings"),
            ("cargo", "fmt", "--all", "--", "--check"),
            ("cargo", "fmt", "--check"),
            ("npm", "test", "--", "src/change.test.ts"),
            ("npm", "test", "--", "--define=__DEV__=true"),
            ("npm", "run", "test"),
            ("npm", "run", "test:coverage"),
            ("npm", "run", "test:e2e"),
            ("npm", "run", "frontend:build"),
            ("npm", "run", "build"),
            ("npm", "run", "app:build:debug"),
            ("npm", "run", "app:build:exe-only"),
            ("npm", "run", "app:build:lite"),
            ("npm", "run", "app:build:release"),
            ("mdbook", "build"),
            ("mdbook", "test", "docs/book"),
            ("git", "diff", "--check"),
            ("git", "diff", "--check", "--", ".omp/skills/cmtraceopen-dev"),
            ("git", "rev-parse", "--show-toplevel"),
            ("git", "rev-parse", "--git-common-dir"),
            (
                "git",
                "rev-parse",
                "--path-format=absolute",
                "--git-common-dir",
            ),
            ("git", "ls-files", "--stage", "-z"),
            ("git", "diff", "--binary", "--no-ext-diff", "HEAD", "--"),
        )
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            run_repo_check.subprocess,
            "Popen",
            return_value=mock.Mock(pid=123),
        ) as process, mock.patch.object(
            run_repo_check,
            "_wait_without_reaping",
        ), mock.patch.object(
            run_repo_check,
            "_terminate_group_and_reap",
            return_value=0,
        ):
            for arguments in allowed:
                with self.subTest(arguments=arguments):
                    result = run_check(arguments,
                    cwd=Path(directory),
                    timeout=30,
                    head_sha="a" * 40,
                    base_sha="b" * 40,)
                    self.assertEqual("completed", result["outcome"])
        self.assertEqual(len(allowed), process.call_count)

    def test_runner_rejects_policy_bypasses_before_popen(self) -> None:
        rejected = (
            (
                "git",
                "-c",
                "alias.verify=!sh -c 'curl https://example.invalid'",
                "verify",
            ),
            ("git", "config", "alias.verify", "!sh -c 'id'"),
            ("git", "reset", "--hard", "HEAD"),
            ("git", "clean", "-fdx"),
            ("git", "diff", "--check", "--ext-diff"),
            ("env", "-S", "sh -c 'cargo test'"),
            ("/usr/bin/env", "bash", "-c", "cargo test"),
            ("sh", "-c", "cargo test"),
            ("python3", "-c", "print('test')"),
            ("python3", "-m", "pip", "install", "package"),
            ("node", "--eval", "console.log('test')"),
            ("curl", "https://example.invalid"),
            ("wget", "https://example.invalid"),
            ("ssh", "example.invalid"),
            ("gh", "api", "repos/adamgell/cmtraceopen"),
            ("unknown-check", "test"),
            ("cargo", "install", "cargo-nextest"),
            (
                "cargo",
                "test",
                "--config",
                "build.rustc-wrapper='/tmp/runner'",
            ),
            ("cargo", "fmt", "--all"),
            ("npm", "run", "dev"),
            ("npm", "run", "test:watch"),
            ("npm", "exec", "vitest"),
            ("mdbook", "serve"),
            ("mdbook", "build", "C:/outside"),
            ("git", "diff", "--check", "--", "C:/outside"),
            ("python3", "-m", "unittest", "C:/outside"),
            ("python3", "-m", "unittest", "discover", "C:/outside"),
            ("python3", "-m", "unittest", "discover", "/etc"),
            ("python3", "-m", "unittest", "discover", ".."),
            (
                "python3",
                "-m",
                "unittest",
                "discover",
                "tests",
                "test_*.py",
                "/etc",
            ),
            ("npm", "test", "--", "--config=PATHS=/etc/crontab"),
            ("npm", "test", "--", "--config=DIRS=../outside"),
            ("npm", "test", "--", "--config=PATHS=src,/etc/crontab"),
            ("npm", "test", "--", "--config=DIRS=src\\..\\outside"),
            ("npm", "test", "--", "--config=PATHS=src:/etc/crontab"),
            ("npm", "test", "--", "--config=PATHS=src;/etc/crontab"),
            ("npm", "test", "--", "--config=PATHS=src, /etc/crontab"),
            ("npm", "test", "--", "--config=PATHS=src /etc/crontab"),
            ("npm", "test", "--", "--config=PATHS='/etc/crontab'"),
            ("npm", "test", "--", '--config=DIRS="../outside"'),
            ("npm", "test", "--", "--config=PATHS='C:outside'"),
            ("npm", "test", "--", "--config=DIRS=src ..\\outside"),
            ("npm", "test", "--", "--config=PATHS=C:outside"),
        )
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            run_repo_check.subprocess,
            "Popen",
        ) as process:
            for arguments in rejected:
                with self.subTest(arguments=arguments), self.assertRaisesRegex(
                    ValueError,
                    "repository check policy",
                ):
                    run_check(arguments,
                    cwd=Path(directory),
                    timeout=30,
                    head_sha="a" * 40,
                    base_sha="b" * 40,)
        process.assert_not_called()

    def test_runner_rejects_invalid_timeouts_before_popen(self) -> None:
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            run_repo_check.subprocess,
            "Popen",
        ) as process:
            for timeout in (
                float("nan"),
                float("inf"),
                float("-inf"),
                0.0,
                -1.0,
            ):
                with self.subTest(timeout=timeout), self.assertRaisesRegex(
                    ValueError,
                    "finite and positive",
                ):
                    run_check(
                        ["cargo", "test"],
                        cwd=Path(directory),
                        timeout=timeout,
                    )
        process.assert_not_called()

    def test_parser_requires_every_manifest_binding_flag(self) -> None:
        arguments = [
            "run_repo_check.py",
            "--cwd",
            "/repo",
            "--timeout",
            "30",
            "--expected-worktree-device",
            "17",
            "--expected-worktree-inode",
            "23",
            "--expected-git-common-dir",
            "/repo/.git",
            "--expected-branch",
            "feature",
            "--expected-head-sha",
            HEAD_SHA,
            "--base-sha",
            BASE_SHA,
            "--artifact",
            "/tmp/check.json",
            "--",
            "cargo",
            "test",
        ]
        required_bindings = {
            "--expected-worktree-device": 17,
            "--expected-worktree-inode": 23,
            "--expected-git-common-dir": Path("/repo/.git"),
            "--expected-branch": "feature",
            "--expected-head-sha": HEAD_SHA,
        }
        with mock.patch.object(run_repo_check.sys, "argv", arguments):
            parsed = run_repo_check.parse_args()
        for flag, expected in required_bindings.items():
            attribute = flag.removeprefix("--").replace("-", "_")
            self.assertEqual(expected, getattr(parsed, attribute))
            index = arguments.index(flag)
            omitted = arguments[:index] + arguments[index + 2 :]
            with (
                self.subTest(flag=flag),
                mock.patch.object(run_repo_check.sys, "argv", omitted),
                mock.patch.object(
                    run_repo_check.sys,
                    "stderr",
                    new_callable=io.StringIO,
                ),
                self.assertRaises(SystemExit),
            ):
                run_repo_check.parse_args()
        self.assertEqual(["cargo", "test"], parsed.command)

    def test_main_rejects_old_python_before_argument_parsing(self) -> None:
        with (
            mock.patch.object(run_repo_check.sys, "version_info", (3, 10)),
            mock.patch.object(run_repo_check, "parse_args") as parse_args,
            self.assertRaisesRegex(SystemExit, "Python 3.11 or newer"),
        ):
            run_repo_check.main()
        parse_args.assert_not_called()

    def test_runner_rejects_empty_commands_and_non_directories(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            file_path = root / "file"
            file_path.write_text("content", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "command"):
                run_check([],
                cwd=root,
                timeout=30,
                head_sha="a" * 40,
                base_sha="b" * 40,)
            missing_cwd = run_check(["cargo", "test"],
            cwd=file_path,
            timeout=30,
            head_sha="a" * 40,
            base_sha="b" * 40,)
            self.assertEqual("setup_failed", missing_cwd["outcome"])


if __name__ == "__main__":
    unittest.main()
