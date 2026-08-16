from __future__ import annotations

import hashlib
import contextlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest.mock import patch
import unittest


REPO_ROOT = Path(__file__).parents[4]
SCRIPT_ROOT = Path(__file__).parents[1] / "scripts"
VALIDATOR_PATH = SCRIPT_ROOT / "validate_model_probe.py"
WRITER_PATH = SCRIPT_ROOT / "write_project_config.py"
THRESHOLDS_PATH = (
    Path(__file__).parents[1] / "references" / "model-role-thresholds.json"
)

VALIDATOR_SPEC = importlib.util.spec_from_file_location(
    "validate_model_probe", VALIDATOR_PATH
)
if VALIDATOR_SPEC is None or VALIDATOR_SPEC.loader is None:
    raise RuntimeError(f"cannot load validator from {VALIDATOR_PATH}")
validator = importlib.util.module_from_spec(VALIDATOR_SPEC)
VALIDATOR_SPEC.loader.exec_module(validator)

WRITER_SPEC = importlib.util.spec_from_file_location("write_project_config", WRITER_PATH)
if WRITER_SPEC is None or WRITER_SPEC.loader is None:
    raise RuntimeError(f"cannot load config writer from {WRITER_PATH}")
writer = importlib.util.module_from_spec(WRITER_SPEC)
WRITER_SPEC.loader.exec_module(writer)

SELECTORS = {
    "reasoning": "llmgateway/gpt-5.6-sol",
    "mid": "llmgateway/grok-4-20-reasoning",
    "scaffold": "llmgateway/gpt-5.6-luna",
    "advisor": "llmgateway/gpt-5.6-sol",
}
EXPECTED_CONFIG = """modelRoles:
  reasoning: "llmgateway/gpt-5.6-sol"
  mid: "llmgateway/grok-4-20-reasoning"
  scaffold: "llmgateway/gpt-5.6-luna"
  advisor: "llmgateway/gpt-5.6-sol"

advisor:
  enabled: true
  syncBacklog: 1
  immuneTurns: 3

retry:
  modelFallback: false

async:
  enabled: true

memory:
  backend: local

lsp:
  enabled: true

skills:
  enabled: true
  enableSkillCommands: true
  enableClaudeUser: false
  enableClaudeProject: true
  enableAgentsUser: true
  enableAgentsProject: true
  customDirectories:
    - ~/.omp/agent/skillsets/cmtraceopen

task:
  batch: true
  eager: preferred
  enableLsp: true
  maxConcurrency: 6
  maxRecursionDepth: 1
  showResolvedModelBadge: true
  isolation:
    mode: auto
    apply: false
    merge: branch
    commits: generic
"""
CHARTER_RESULT = """# Coder charter

**Role:** Implementation engineer

Red first: capture the failing test before production code.
The Coder may not merge, or close issues.
"""


def _events(selector: str) -> list[dict[str, object]]:
    provider, model = selector.split("/", 1)
    return [
        {
            "type": "tool_execution_start",
            "toolCallId": "read-1",
            "toolName": "read",
            "args": {"path": ".Clairvoyance/staff/coder-charter.md"},
        },
        {
            "type": "tool_execution_end",
            "toolCallId": "read-1",
            "toolName": "read",
            "isError": False,
            "result": CHARTER_RESULT,
        },
        {
            "type": "message_end",
            "message": {
                "role": "assistant",
                "provider": provider,
                "api": "openai-completions",
                "model": model,
                "timestamp": 1786708802123,
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(
                            validator.EXPECTED_FINAL, separators=(",", ":")
                        ),
                    }
                ],
            },
        },
    ]


class _FailingFile:
    def __init__(self, stream: object, stage: str) -> None:
        self._stream = stream
        self._stage = stage

    def __enter__(self) -> _FailingFile:
        return self

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: object,
    ) -> bool | None:
        if self._stage == "close":
            self._stream.close()
            if exception_type is None:
                raise OSError("injected close failure")
            return None
        return self._stream.__exit__(exception_type, exception, traceback)

    def write(self, data: bytes) -> int:
        if self._stage == "write":
            self._stream.write(data[: max(1, len(data) // 2)])
            raise OSError("injected write failure")
        return self._stream.write(data)

    def flush(self) -> None:
        if self._stage == "flush":
            raise OSError("injected flush failure")
        self._stream.flush()

    def fileno(self) -> int:
        return self._stream.fileno()


class _ReplacingReadFile:
    def __init__(self, stream: object, path: Path, replacement: bytes) -> None:
        self._stream = stream
        self._path = path
        self._replacement = replacement

    def __enter__(self) -> _ReplacingReadFile:
        return self

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: object,
    ) -> bool | None:
        return self._stream.__exit__(exception_type, exception, traceback)

    def read(self) -> bytes:
        existing = self._stream.read()
        replacement_path = self._path.with_name(f".{self._path.name}.replacement")
        replacement_path.write_bytes(self._replacement)
        os.replace(replacement_path, self._path)
        return existing

    def fileno(self) -> int:
        return self._stream.fileno()



class ProjectConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.discovery_path = self.root / "discovery.json"
        self.artifacts: dict[str, Path] = {}
        models = []
        for selector in dict.fromkeys(SELECTORS.values()):
            provider, model = selector.split("/", 1)
            models.append(
                {
                    "selector": selector,
                    "provider": provider,
                    "id": model,
                    "contextWindow": 2_000_000,
                    "maxTokens": 128_000,
                }
            )
            artifact_path = self.root / f"probe-{model}.jsonl"
            artifact_path.write_text(
                "".join(
                    json.dumps(event, separators=(",", ":")) + "\n"
                    for event in _events(selector)
                ),
                encoding="utf-8",
            )
            self.artifacts[selector] = artifact_path
        self.discovery_path.write_text(
            json.dumps({"models": models}), encoding="utf-8"
        )

        roles: dict[str, object] = {}
        for role, selector in SELECTORS.items():
            evidence = validator.validate_probe(
                self.discovery_path,
                self.artifacts[selector],
                THRESHOLDS_PATH,
                selector,
                role,
            )
            roles[role] = {
                "selector": selector,
                "provider": evidence["provider"],
                "api": evidence["api"],
                "discoveryArtifact": str(self.discovery_path),
                "artifact": str(self.artifacts[selector]),
                "evidence": evidence,
                "promotionReason": None,
            }
        self.report = {
            "schemaVersion": 1,
            "generatedAt": "2026-08-14T20:25:32Z",
            "primaryProvider": "llmgateway",
            "roles": roles,
        }
        self.report_path = self.root / "model-probe-report.json"
        self.report_path.write_text(json.dumps(self.report), encoding="utf-8")

    def test_validated_role_report_renders_exact_project_config(self) -> None:
        selectors = writer.validate_role_report(self.report_path, REPO_ROOT)

        self.assertEqual(SELECTORS, selectors)
        self.assertEqual(EXPECTED_CONFIG, writer.render_config(selectors))

    def test_artifact_mutation_after_role_validation_rejects_model_map(self) -> None:
        real_run = subprocess.run
        for artifact_path in (
            self.artifacts[SELECTORS["mid"]],
            self.discovery_path,
        ):
            with self.subTest(artifact=artifact_path.name):
                original = artifact_path.read_bytes()
                mutated = False

                def mutate_validated_artifact(
                    command: list[str], *args: object, **kwargs: object
                ) -> subprocess.CompletedProcess[str]:
                    nonlocal mutated
                    completed = real_run(command, *args, **kwargs)
                    role = command[command.index("--role") + 1]
                    if role == "mid" and not mutated:
                        mutated = True
                        artifact_path.write_bytes(original + b"\n")
                    return completed

                try:
                    with patch.object(
                        writer.subprocess,
                        "run",
                        side_effect=mutate_validated_artifact,
                    ), self.assertRaisesRegex(
                        ValueError, "probe artifacts changed during role validation"
                    ):
                        writer.validate_role_report(self.report_path, REPO_ROOT)
                    self.assertTrue(mutated)
                finally:
                    artifact_path.write_bytes(original)

    def test_artifact_snapshot_rejects_non_regular_file_before_open(self) -> None:
        artifact = self.root / "artifact-directory"
        artifact.mkdir()

        with patch.object(Path, "open") as open_file, self.assertRaisesRegex(
            ValueError,
            "probe artifact must be a regular file",
        ):
            writer._artifact_snapshot(artifact)

        open_file.assert_not_called()

    def test_identical_existing_config_is_idempotent(self) -> None:
        path = self.root / "config.yml"
        path.write_bytes(EXPECTED_CONFIG.encode("utf-8"))

        status = writer.write_create_only(path, EXPECTED_CONFIG)

        self.assertEqual("unchanged", status)
        self.assertEqual(EXPECTED_CONFIG.encode("utf-8"), path.read_bytes())

    def test_check_exact_requires_existing_byte_identical_config(self) -> None:
        path = self.root / "config.yml"
        with self.assertRaisesRegex(ValueError, "missing"):
            writer.check_exact(path, EXPECTED_CONFIG)
        self.assertFalse(path.exists())

        path.write_bytes(EXPECTED_CONFIG.encode("utf-8"))
        self.assertEqual("unchanged", writer.check_exact(path, EXPECTED_CONFIG))

        differing = EXPECTED_CONFIG.encode("utf-8") + b"# drift\n"
        path.write_bytes(differing)
        with self.assertRaisesRegex(ValueError, "differs"):
            writer.check_exact(path, EXPECTED_CONFIG)
        self.assertEqual(differing, path.read_bytes())

    def test_existing_config_must_be_a_regular_file(self) -> None:
        path = self.root / "config.yml"
        target = self.root / "matching-target.yml"
        target.write_text(EXPECTED_CONFIG, encoding="utf-8")
        operations = (writer.check_exact, writer.write_create_only)

        path.symlink_to(target)
        for operation in operations:
            with self.subTest(kind="symlink", operation=operation.__name__):
                with self.assertRaisesRegex(ValueError, "regular file"):
                    operation(path, EXPECTED_CONFIG)
        self.assertEqual(EXPECTED_CONFIG.encode("utf-8"), target.read_bytes())

        path.unlink()
        path.mkdir()
        for operation in operations:
            with self.subTest(kind="directory", operation=operation.__name__):
                with self.assertRaisesRegex(ValueError, "regular file"):
                    operation(path, EXPECTED_CONFIG)
        self.assertEqual([], list(path.iterdir()))

    def test_existing_config_replacement_during_inspection_fails_closed(
        self,
    ) -> None:
        path = self.root / "config.yml"
        path.write_text(EXPECTED_CONFIG, encoding="utf-8")
        real_fdopen = os.fdopen

        for operation in (writer.check_exact, writer.write_create_only):
            replaced = False

            def fdopen_with_replacement(
                descriptor: int, mode: str, *args: object, **kwargs: object
            ) -> _ReplacingReadFile:
                nonlocal replaced
                replaced = True
                return _ReplacingReadFile(
                    real_fdopen(descriptor, mode, *args, **kwargs),
                    path,
                    EXPECTED_CONFIG.encode("utf-8"),
                )

            with self.subTest(operation=operation.__name__):
                with patch(
                    "os.fdopen", side_effect=fdopen_with_replacement
                ), self.assertRaisesRegex(
                    ValueError, "config output changed during inspection"
                ):
                    operation(path, EXPECTED_CONFIG)
                self.assertTrue(replaced)
                self.assertEqual(
                    EXPECTED_CONFIG.encode("utf-8"), path.read_bytes()
                )

    def test_initial_parent_symlink_is_rejected(self) -> None:
        external_parent = self.root / "external"
        external_parent.mkdir()
        parent = self.root / "publish"
        parent.symlink_to(external_parent, target_is_directory=True)
        output = parent / "config.yml"

        for operation in (writer.check_exact, writer.write_create_only):
            with self.subTest(operation=operation.__name__):
                with self.assertRaisesRegex(ValueError, "non-symlink directory"):
                    operation(output, EXPECTED_CONFIG)
        self.assertEqual([], list(external_parent.iterdir()))

    def test_parent_replacement_before_unchanged_return_fails_closed(
        self,
    ) -> None:
        real_existing_status = writer._existing_bytes_status

        for operation in (writer.check_exact, writer.write_create_only):
            parent = self.root / f"publish-{operation.__name__}"
            parent.mkdir()
            output = parent / "config.yml"
            output.write_text(EXPECTED_CONFIG, encoding="utf-8")
            displaced_parent = self.root / f"displaced-{operation.__name__}"
            replacement_parent = self.root / f"replacement-{operation.__name__}"

            def replace_parent_before_return(
                existing: bytes, proposed: bytes
            ) -> str:
                status = real_existing_status(existing, proposed)
                parent.rename(displaced_parent)
                replacement_parent.mkdir()
                parent.symlink_to(
                    replacement_parent, target_is_directory=True
                )
                return status

            with self.subTest(operation=operation.__name__):
                with patch.object(
                    writer,
                    "_existing_bytes_status",
                    side_effect=replace_parent_before_return,
                ), self.assertRaisesRegex(
                    ValueError, "parent directory changed"
                ):
                    operation(output, EXPECTED_CONFIG)
                self.assertFalse(output.exists())
                self.assertEqual(
                    EXPECTED_CONFIG.encode("utf-8"),
                    (displaced_parent / output.name).read_bytes(),
                )
                self.assertEqual([], list(replacement_parent.iterdir()))

    def test_check_cli_requires_existing_exact_config(self) -> None:
        output = self.root / "config.yml"
        command = [
            sys.executable,
            str(WRITER_PATH),
            "--check",
            "--report",
            str(self.report_path),
            "--repo-root",
            str(REPO_ROOT),
            "--output",
            str(output),
        ]

        missing = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(0, missing.returncode)
        self.assertFalse(output.exists())

        output.write_text(EXPECTED_CONFIG, encoding="utf-8")
        exact = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(0, exact.returncode, exact.stderr)
        self.assertEqual(
            {"ok": True, "status": "unchanged"},
            json.loads(exact.stdout),
        )

    def test_differing_existing_config_is_byte_preserved_and_blocks(self) -> None:
        path = self.root / "config.yml"
        existing = b"userOwned: true\n\xff"
        proposed = EXPECTED_CONFIG.encode("utf-8")
        path.write_bytes(existing)

        with self.assertRaises(ValueError) as caught:
            writer.write_create_only(path, EXPECTED_CONFIG)

        self.assertEqual(existing, path.read_bytes())
        error = json.loads(str(caught.exception))
        self.assertEqual(False, error["ok"])
        self.assertEqual("existing_config_differs", error["classification"])
        self.assertEqual(hashlib.sha256(existing).hexdigest(), error["existingSha256"])
        self.assertEqual(hashlib.sha256(proposed).hexdigest(), error["proposedSha256"])
        self.assertNotIn("userOwned", str(caught.exception))
        self.assertNotIn(EXPECTED_CONFIG, str(caught.exception))

    def test_staged_name_allocation_is_bounded(self) -> None:
        output = self.root / "config.yml"
        real_open = os.open
        attempts = 0

        def collide_on_staged_name(
            path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
            flags: int,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> int:
            nonlocal attempts
            if path == ".config.yml.collision.tmp":
                attempts += 1
                if attempts > 16:
                    raise RuntimeError("staged-name allocation did not stop")
                raise FileExistsError(path)
            return real_open(path, flags, mode, dir_fd=dir_fd)

        with patch(
            "secrets.token_hex", return_value="collision"
        ), patch(
            "os.open", side_effect=collide_on_staged_name
        ), self.assertRaisesRegex(
            OSError, "cannot allocate staged config path"
        ):
            writer.write_create_only(output, EXPECTED_CONFIG)

        self.assertEqual(16, attempts)
        self.assertFalse(output.exists())


    def test_create_failures_leave_no_partial_destination_and_retry(self) -> None:
        original_fdopen = os.fdopen
        for stage in ("write", "flush", "fsync", "close", "install"):
            with self.subTest(stage=stage):
                output = self.root / f"{stage}-config.yml"
                entries_before = set(self.root.iterdir())

                def fdopen_with_failure(
                    descriptor: int, mode: str, *args: object, **kwargs: object
                ) -> object:
                    stream = original_fdopen(descriptor, mode, *args, **kwargs)
                    return _FailingFile(stream, stage)

                with contextlib.ExitStack() as stack:
                    if stage in {"write", "flush", "close"}:
                        stack.enter_context(
                            patch("os.fdopen", side_effect=fdopen_with_failure)
                        )
                    elif stage == "fsync":
                        stack.enter_context(
                            patch("os.fsync", side_effect=OSError("injected fsync failure"))
                        )
                    else:
                        stack.enter_context(
                            patch("os.link", side_effect=OSError("injected install failure"))
                        )
                    with self.assertRaises(OSError):
                        writer.write_create_only(output, EXPECTED_CONFIG)

                self.assertFalse(output.exists())
                self.assertEqual(entries_before, set(self.root.iterdir()))
                self.assertEqual(
                    "created", writer.write_create_only(output, EXPECTED_CONFIG)
                )
                self.assertEqual(EXPECTED_CONFIG.encode("utf-8"), output.read_bytes())

    def test_post_publish_directory_fsync_failure_is_reported(self) -> None:
        output = self.root / "post-publish-fsync-config.yml"
        real_fsync = os.fsync
        calls = 0

        def fail_directory_fsync(descriptor: int) -> None:
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("injected directory fsync failure")
            real_fsync(descriptor)

        with patch("os.fsync", side_effect=fail_directory_fsync):
            with self.assertRaisesRegex(OSError, "directory fsync failure"):
                writer.write_create_only(output, EXPECTED_CONFIG)

        self.assertEqual(2, calls)
        self.assertEqual(EXPECTED_CONFIG.encode("utf-8"), output.read_bytes())

    def test_platform_link_limitation_fails_closed_and_retries(self) -> None:
        output = self.root / "config.yml"
        entries_before = set(self.root.iterdir())
        unsupported = NotImplementedError(
            "link: src_dir_fd and dst_dir_fd unavailable on this platform"
        )

        with patch("os.link", side_effect=unsupported), self.assertRaisesRegex(
            ValueError,
            "platform cannot atomically publish config",
        ):
            writer.write_create_only(output, EXPECTED_CONFIG)

        self.assertFalse(output.exists())
        self.assertEqual(entries_before, set(self.root.iterdir()))
        self.assertEqual("created", writer.write_create_only(output, EXPECTED_CONFIG))

    def test_link_errno_detection_tolerates_missing_platform_constants(
        self,
    ) -> None:
        class LimitedErrno:
            ENOSYS = 38

        output = self.root / "config.yml"
        entries_before = set(self.root.iterdir())
        unsupported = OSError(LimitedErrno.ENOSYS, "unsupported")

        with patch.object(writer, "errno", LimitedErrno), patch(
            "os.link",
            side_effect=unsupported,
        ), self.assertRaisesRegex(
            ValueError,
            "platform cannot atomically publish config",
        ):
            writer.write_create_only(output, EXPECTED_CONFIG)

        self.assertFalse(output.exists())
        self.assertEqual(entries_before, set(self.root.iterdir()))
        self.assertEqual("created", writer.write_create_only(output, EXPECTED_CONFIG))

    def test_concurrent_destination_wins_atomic_install(self) -> None:
        output = self.root / "config.yml"
        concurrent = b"userOwned: true\n"
        entries_before = set(self.root.iterdir())
        real_link = os.link
        # Threat boundary: cooperating writers may race to publish, but do not
        # mutate another invocation's random sibling temp name.

        def create_concurrent_destination(
            source: str | bytes | os.PathLike[str] | os.PathLike[bytes],
            destination: str | bytes | os.PathLike[str] | os.PathLike[bytes],
            *args: object,
            **kwargs: object,
        ) -> None:
            descriptor = os.open(
                destination,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=kwargs.get("dst_dir_fd"),
            )
            try:
                os.write(descriptor, concurrent)
            finally:
                os.close(descriptor)
            real_link(source, destination, *args, **kwargs)

        with patch("os.link", side_effect=create_concurrent_destination):
            with self.assertRaises(ValueError):
                writer.write_create_only(output, EXPECTED_CONFIG)

        self.assertEqual(concurrent, output.read_bytes())
        self.assertEqual(
            entries_before | {output},
            set(self.root.iterdir()),
        )

    def test_parent_replacement_cannot_redirect_publication_or_cleanup(self) -> None:
        parent = self.root / "publish"
        parent.mkdir()
        output = parent / "config.yml"
        displaced_parent = self.root / "displaced-publish"
        replacement_parent = self.root / "replacement-publish"
        sentinel = replacement_parent / "sentinel"
        unrelated_temporary: Path | None = None
        real_link = os.link

        def replace_parent_during_publication(
            source: str | bytes | os.PathLike[str] | os.PathLike[bytes],
            destination: str | bytes | os.PathLike[str] | os.PathLike[bytes],
            *args: object,
            **kwargs: object,
        ) -> None:
            nonlocal unrelated_temporary
            parent.rename(displaced_parent)
            replacement_parent.mkdir()
            sentinel.write_bytes(b"unrelated")
            parent.symlink_to(replacement_parent, target_is_directory=True)
            unrelated_temporary = replacement_parent / Path(source).name
            unrelated_temporary.write_bytes(b"unrelated temporary")
            real_link(source, destination, *args, **kwargs)

        with patch(
            "os.link", side_effect=replace_parent_during_publication
        ), self.assertRaisesRegex(ValueError, "parent directory changed"):
            writer.write_create_only(output, EXPECTED_CONFIG)
        self.assertFalse(output.exists())
        self.assertEqual(
            EXPECTED_CONFIG.encode("utf-8"),
            (displaced_parent / output.name).read_bytes(),
        )
        self.assertEqual(
            {output.name},
            {entry.name for entry in displaced_parent.iterdir()},
        )
        self.assertEqual(b"unrelated", sentinel.read_bytes())
        self.assertIsNotNone(unrelated_temporary)
        assert unrelated_temporary is not None
        self.assertEqual(b"unrelated temporary", unrelated_temporary.read_bytes())

    def test_probe_validator_timeout_fails_closed(self) -> None:
        def time_out(*args: object, **kwargs: object) -> None:
            self.assertEqual(60, kwargs.get("timeout"))
            raise subprocess.TimeoutExpired(cmd=args[0], timeout=60)

        with patch.object(writer.subprocess, "run", side_effect=time_out):
            with self.assertRaisesRegex(
                ValueError, "probe validation timed out for reasoning"
            ):
                writer.validate_role_report(self.report_path, REPO_ROOT)

    def test_selector_policy_rejects_invalid_promotions(self) -> None:
        invalid = (
            (
                "mid",
                "openai-codex/gpt-5.6-sol",
                None,
                "mid must use a validated llmgateway selector",
            ),
            (
                "mid",
                "llmgateway/grok-4-20-reasoning",
                "promotion",
                "mid cannot record a Sol safety promotion",
            ),
            (
                "reasoning",
                "llmgateway/gpt-5.6-sol",
                "promotion",
                "gateway reasoning must not record a promotion reason",
            ),
            (
                "reasoning",
                "openai-codex/gpt-5.5-sol",
                "failed gateway",
                "reasoning selector violates the recorded Sol-promotion contract",
            ),
            (
                "reasoning",
                "openai-codex/gpt-5.6-sol",
                " ",
                "promoted reasoning must name the failed gateway evidence",
            ),
        )

        for role, selector, reason, expected_error in invalid:
            with self.subTest(role=role, selector=selector, reason=reason):
                with self.assertRaisesRegex(ValueError, expected_error):
                    writer._validate_selector_policy(role, selector, reason)

    def test_selector_policy_accepts_recorded_sol_promotion(self) -> None:
        writer._validate_selector_policy(
            "advisor",
            "openai-codex/gpt-5.6-sol",
            "gateway probe failed the advisor threshold",
        )


    def test_probe_evidence_mismatch_blocks_without_creating_config(self) -> None:
        roles = self.report["roles"]
        assert isinstance(roles, dict)
        reasoning = roles["reasoning"]
        assert isinstance(reasoning, dict)
        evidence = reasoning["evidence"]
        assert isinstance(evidence, dict)
        evidence["artifactSha256"] = "0" * 64
        self.report_path.write_text(json.dumps(self.report), encoding="utf-8")
        output = self.root / "config.yml"

        result = subprocess.run(
            [
                sys.executable,
                str(WRITER_PATH),
                "--report",
                str(self.report_path),
                "--repo-root",
                str(REPO_ROOT),
                "--output",
                str(output),
            ],
            check=False,
            capture_output=True,
            text=True,
        )

        self.assertNotEqual(0, result.returncode)
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
