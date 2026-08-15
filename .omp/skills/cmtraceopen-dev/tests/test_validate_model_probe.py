from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


SCRIPT_PATH = Path(__file__).parents[1] / "scripts" / "validate_model_probe.py"
SPEC = importlib.util.spec_from_file_location("validate_model_probe", SCRIPT_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load validator from {SCRIPT_PATH}")
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)

SELECTOR = "test-provider/test-model"
FINAL_TIMESTAMP_MS = 1786708802123
CHARTER_RESULT = """# Coder charter

**Role:** Implementation engineer (Coder)

Red first: capture the failing test before production code.
The Coder may not merge, or close issues.
"""
FINAL_OBJECT = {
    "schemaVersion": 1,
    "source": ".Clairvoyance/staff/coder-charter.md",
    "role": "Implementation engineer",
    "redFirst": True,
    "mayMerge": False,
    "conflictRejected": True,
}


def valid_events() -> list[dict[str, object]]:
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
                "provider": "test-provider",
                "api": "openai-completions",
                "model": "test-model",
                "timestamp": FINAL_TIMESTAMP_MS,
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(FINAL_OBJECT, separators=(",", ":")),
                    }
                ],
            },
        },
    ]


def valid_discovery() -> dict[str, object]:
    return {
        "models": [
            {
                "selector": SELECTOR,
                "provider": "test-provider",
                "id": "test-model",
                "contextWindow": 131072,
                "maxTokens": 32768,
            }
        ]
    }


def thresholds() -> dict[str, object]:
    return {
        "schemaVersion": 1,
        "roles": {
            "reasoning": {
                "minContextWindow": 131072,
                "minMaxTokens": 32768,
            }
        },
    }


class ProbeValidationTests(unittest.TestCase):
    def test_valid_trace_and_discovery_metadata_pass(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            discovery_path = root / "discovery.json"
            artifact_path = root / "artifact.jsonl"
            thresholds_path = root / "thresholds.json"
            discovery_path.write_text(json.dumps(valid_discovery()), encoding="utf-8")
            artifact_bytes = b"".join(
                json.dumps(event, separators=(",", ":")).encode("utf-8") + b"\n"
                for event in valid_events()
            )
            artifact_path.write_bytes(artifact_bytes)
            thresholds_path.write_text(json.dumps(thresholds()), encoding="utf-8")

            evidence = validator.validate_probe(
                discovery_path,
                artifact_path,
                thresholds_path,
                SELECTOR,
                "reasoning",
            )

        canonical_final = json.dumps(
            FINAL_OBJECT,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        self.assertEqual(
            evidence,
            {
                "fixtureVersion": 1,
                "selector": SELECTOR,
                "provider": "test-provider",
                "api": "openai-completions",
                "discoveredModelId": "test-model",
                "contextWindow": 131072,
                "maxTokens": 32768,
                "readPath": ".Clairvoyance/staff/coder-charter.md",
                "readResultSha256": hashlib.sha256(
                    CHARTER_RESULT.encode("utf-8")
                ).hexdigest(),
                "finalObjectSha256": hashlib.sha256(canonical_final).hexdigest(),
                "artifactSha256": hashlib.sha256(artifact_bytes).hexdigest(),
                "validatedAt": "2026-08-14T12:00:02.123000+00:00",
            },
        )

    def test_missing_exact_read_call_fails(self) -> None:
        events = valid_events()
        events[0]["args"] = {"path": "README.md"}

        with self.assertRaises(ValueError):
            validator.validate_trace(events, SELECTOR)

    def test_failed_read_completion_fails(self) -> None:
        failed = valid_events()
        failed[1]["isError"] = True
        completion_before_start = valid_events()
        completion_before_start[0], completion_before_start[1] = (
            completion_before_start[1],
            completion_before_start[0],
        )
        answer_before_completion = valid_events()
        answer_before_completion[1], answer_before_completion[2] = (
            answer_before_completion[2],
            answer_before_completion[1],
        )

        for events in (failed, completion_before_start, answer_before_completion):
            with self.subTest(events=events):
                with self.assertRaises(ValueError):
                    validator.validate_trace(events, SELECTOR)

    def test_nonempty_read_error_fails_even_when_is_error_is_false(self) -> None:
        events = valid_events()
        events[1]["error"] = "read denied"

        with self.assertRaises(ValueError):
            validator.validate_trace(events, SELECTOR)

    def test_each_required_charter_marker_is_mandatory(self) -> None:
        self.assertTrue(validator._REQUIRED_CHARTER_MARKERS)
        for marker in validator._REQUIRED_CHARTER_MARKERS:
            with self.subTest(marker=marker):
                self.assertIn(marker, CHARTER_RESULT)
                events = valid_events()
                events[1]["result"] = CHARTER_RESULT.replace(marker, "removed", 1)

                with self.assertRaises(ValueError):
                    validator.validate_trace(events, SELECTOR)

    def test_required_markers_match_the_checked_in_coder_charter(self) -> None:
        charter = (
            Path(__file__).resolve().parents[4]
            / ".Clairvoyance"
            / "staff"
            / "coder-charter.md"
        ).read_text(encoding="utf-8")

        for marker in validator._REQUIRED_CHARTER_MARKERS:
            with self.subTest(marker=marker):
                self.assertIn(marker, charter)


    def test_duplicate_or_extra_tool_call_fails(self) -> None:
        duplicate = valid_events()
        duplicate.insert(1, dict(duplicate[0], toolCallId="read-2"))
        extra = valid_events()
        extra.insert(
            2,
            {
                "type": "tool_execution_start",
                "toolCallId": "bash-1",
                "toolName": "bash",
                "args": {"command": "true"},
                "timestamp": "2026-08-14T12:00:01+00:00",
            },
        )

        for events in (duplicate, extra):
            with self.subTest(events=events):
                with self.assertRaises(ValueError):
                    validator.validate_trace(events, SELECTOR)

    def test_wrong_final_json_fails(self) -> None:
        wrong_value = dict(FINAL_OBJECT, mayMerge=True)
        wrong_types = dict(
            FINAL_OBJECT,
            schemaVersion=True,
            redFirst=1,
            mayMerge=0,
            conflictRejected=1,
        )

        for wrong in (wrong_value, wrong_types):
            with self.subTest(wrong=wrong):
                events = valid_events()
                message = events[-1]["message"]
                assert isinstance(message, dict)
                message["content"] = [{"type": "text", "text": json.dumps(wrong)}]
                with self.assertRaises(ValueError):
                    validator.validate_trace(events, SELECTOR)

    def test_empty_or_malformed_jsonl_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            artifact_path = Path(directory) / "artifact.jsonl"
            for content in (
                "",
                '{"type":"message_end"}\nnot-json\n',
                '{"type":"message_end","value":NaN}\n',
                '{"type":"message_end","value":Infinity}\n',
                '{"type":"message_end","value":-Infinity}\n',
            ):
                with self.subTest(content=content):
                    artifact_path.write_text(content, encoding="utf-8")
                    with self.assertRaises(ValueError):
                        validator.read_jsonl(artifact_path)

        malformed_messages = (
            {"type": "message_end"},
            {
                "type": "message_end",
                "message": "not-an-object",
            },
            {
                "type": "message_end",
                "message": {},
            },
            {
                "type": "message_end",
                "message": {"role": 1, "timestamp": FINAL_TIMESTAMP_MS},
            },
            {
                "type": "message_end",
                "message": {"role": "user"},
            },
        )
        for malformed_message in malformed_messages:
            with self.subTest(malformed_message=malformed_message):
                events = valid_events()
                events.append(malformed_message)
                with self.assertRaises(ValueError):
                    validator.validate_trace(events, SELECTOR)

        for invalid_timestamp in (None, True, 0, -1, 1.0, "1786708802123"):
            with self.subTest(timestamp=invalid_timestamp):
                events = valid_events()
                events.append(
                    {
                        "type": "message_end",
                        "message": {
                            "role": "user",
                            "timestamp": invalid_timestamp,
                        },
                    }
                )
                with self.assertRaises(ValueError):
                    validator.validate_trace(events, SELECTOR)

    def test_role_threshold_failure_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            discovery = valid_discovery()
            models = discovery["models"]
            assert isinstance(models, list)
            models[0]["contextWindow"] = 131071
            discovery_path = root / "discovery.json"
            artifact_path = root / "artifact.jsonl"
            thresholds_path = root / "thresholds.json"
            discovery_path.write_text(json.dumps(discovery), encoding="utf-8")
            artifact_path.write_text(
                "".join(json.dumps(event) + "\n" for event in valid_events()),
                encoding="utf-8",
            )
            thresholds_path.write_text(json.dumps(thresholds()), encoding="utf-8")

            with self.assertRaises(ValueError):
                validator.validate_probe(
                    discovery_path,
                    artifact_path,
                    thresholds_path,
                    SELECTOR,
                    "reasoning",
                )

            discovery_path.write_text(
                json.dumps(valid_discovery()),
                encoding="utf-8",
            )
            for invalid_fixture_version in (True, 1.0):
                with self.subTest(fixtureVersion=invalid_fixture_version):
                    invalid_thresholds = thresholds()
                    invalid_thresholds["schemaVersion"] = invalid_fixture_version
                    thresholds_path.write_text(
                        json.dumps(invalid_thresholds),
                        encoding="utf-8",
                    )
                    with self.assertRaises(ValueError):
                        validator.validate_probe(
                            discovery_path,
                            artifact_path,
                            thresholds_path,
                            SELECTOR,
                            "reasoning",
                        )

    def test_selector_must_match_observed_provider_and_model(self) -> None:
        events = valid_events()
        message = events[-1]["message"]
        assert isinstance(message, dict)
        message["model"] = "other-model"

        with self.assertRaises(ValueError):
            validator.validate_trace(events, SELECTOR)

        discovery = valid_discovery()
        models = discovery["models"]
        assert isinstance(models, list)
        models.append(dict(models[0]))
        with self.assertRaises(ValueError):
            validator.find_discovered_model(discovery, SELECTOR)


if __name__ == "__main__":
    unittest.main()
