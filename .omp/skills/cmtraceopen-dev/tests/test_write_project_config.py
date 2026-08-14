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


class ProjectConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
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

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_validated_role_report_renders_exact_project_config(self) -> None:
        selectors = writer.validate_role_report(self.report_path, REPO_ROOT)

        self.assertEqual(SELECTORS, selectors)
        self.assertEqual(EXPECTED_CONFIG, writer.render_config(selectors))

    def test_identical_existing_config_is_idempotent(self) -> None:
        path = self.root / "config.yml"
        path.write_bytes(EXPECTED_CONFIG.encode("utf-8"))

        status = writer.write_create_only(path, EXPECTED_CONFIG)

        self.assertEqual("unchanged", status)
        self.assertEqual(EXPECTED_CONFIG.encode("utf-8"), path.read_bytes())

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

    def test_create_failures_leave_no_partial_destination_and_retry(self) -> None:
        original_open = Path.open
        for stage in ("write", "flush", "fsync", "close", "install"):
            with self.subTest(stage=stage):
                output = self.root / f"{stage}-config.yml"
                entries_before = set(self.root.iterdir())

                def open_with_failure(
                    path: Path, mode: str = "r", *args: object, **kwargs: object
                ) -> object:
                    stream = original_open(path, mode, *args, **kwargs)
                    if mode == "xb":
                        return _FailingFile(stream, stage)
                    return stream

                with contextlib.ExitStack() as stack:
                    if stage in {"write", "flush", "close"}:
                        stack.enter_context(patch.object(Path, "open", open_with_failure))
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

    def test_concurrent_destination_wins_atomic_install(self) -> None:
        output = self.root / "config.yml"
        concurrent = b"userOwned: true\n"
        entries_before = set(self.root.iterdir())
        real_link = os.link

        def create_concurrent_destination(
            source: str | bytes | os.PathLike[str] | os.PathLike[bytes],
            destination: str | bytes | os.PathLike[str] | os.PathLike[bytes],
            *args: object,
            **kwargs: object,
        ) -> None:
            Path(destination).write_bytes(concurrent)
            real_link(source, destination, *args, **kwargs)

        with patch("os.link", side_effect=create_concurrent_destination):
            with self.assertRaises(ValueError):
                writer.write_create_only(output, EXPECTED_CONFIG)

        self.assertEqual(concurrent, output.read_bytes())
        self.assertEqual(
            entries_before | {output},
            set(self.root.iterdir()),
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
