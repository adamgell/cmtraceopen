from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
from typing import NoReturn


EXPECTED_FINAL = {
    "schemaVersion": 1,
    "source": ".Clairvoyance/staff/coder-charter.md",
    "role": "Implementation engineer",
    "redFirst": True,
    "mayMerge": False,
    "conflictRejected": True,
}
EXPECTED_READ_PATH = ".Clairvoyance/staff/coder-charter.md"
_REQUIRED_CHARTER_MARKERS = (
    "**Role:** Implementation engineer",
    "Red first:",
    "merge, or close issues",
)


def _fail(message: str) -> NoReturn:
    raise ValueError(message)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _fail(f"duplicate JSON key: {key}")
        result[key] = value
    return result

def _reject_non_json_number(value: str) -> NoReturn:
    _fail(f"invalid JSON number: {value}")


def _parse_json(text: str, source: str) -> object:
    try:
        return json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_non_json_number,
        )
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ValueError(f"malformed JSON in {source}: {error}") from error


def _read_json_object(path: Path) -> dict[str, object]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise ValueError(f"cannot read {path}: {error}") from error
    value = _parse_json(text, str(path))
    if not isinstance(value, dict):
        _fail(f"{path} must contain one JSON object")
    return value


def _parse_jsonl(text: str, path: Path) -> list[dict[str, object]]:
    if not text.strip():
        _fail(f"{path} is empty")

    events: list[dict[str, object]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            _fail(f"blank JSONL record at {path}:{line_number}")
        event = _parse_json(line, f"{path}:{line_number}")
        if not isinstance(event, dict) or not isinstance(event.get("type"), str):
            _fail(f"malformed event at {path}:{line_number}")
        events.append(event)
    return events


def read_jsonl(path: Path) -> list[dict[str, object]]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise ValueError(f"cannot read {path}: {error}") from error
    return _parse_jsonl(text, path)


def _required_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        _fail(f"missing or invalid {label}")
    return value


def _required_positive_integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        _fail(f"missing or invalid {label}")
    return value


def find_discovered_model(
    discovery: dict[str, object], selector: str
) -> dict[str, object]:
    models = discovery.get("models")
    if not isinstance(models, list):
        _fail("discovery models must be a list")

    matches = [
        model
        for model in models
        if isinstance(model, dict) and model.get("selector") == selector
    ]
    if len(matches) != 1:
        _fail(f"selector must occur exactly once in discovery: {selector}")

    model = matches[0]
    provider = _required_string(model.get("provider"), "discovery provider")
    model_id = _required_string(model.get("id"), "discovery model id")
    _required_positive_integer(model.get("contextWindow"), "contextWindow")
    _required_positive_integer(model.get("maxTokens"), "maxTokens")
    if f"{provider}/{model_id}" != selector:
        _fail("discovery selector does not match provider and model id")
    return model


def _tool_result_text(result: object) -> str:
    if isinstance(result, str):
        return result
    if isinstance(result, dict):
        result = result.get("content")
    if not isinstance(result, list):
        _fail("read completion result must be text")

    parts: list[str] = []
    for item in result:
        if not isinstance(item, dict) or item.get("type") != "text":
            _fail("read completion result contains non-text content")
        parts.append(_required_string(item.get("text"), "read result text"))
    return "".join(parts)


def _assistant_text(message: dict[str, object]) -> str:
    content = message.get("content")
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        _fail("final assistant message has no text content")

    parts: list[str] = []
    for item in content:
        if not isinstance(item, dict):
            _fail("malformed final assistant content")
        if item.get("type") == "text":
            parts.append(_required_string(item.get("text"), "assistant text"))
    if not parts:
        _fail("final assistant message has no text content")
    return "".join(parts)


def _validated_timestamp(message: dict[str, object]) -> str:
    timestamp = message.get("timestamp")
    if type(timestamp) is not int or timestamp <= 0:
        _fail("message timestamp must be a positive epoch-millisecond integer")
    seconds, milliseconds = divmod(timestamp, 1000)
    try:
        parsed = datetime.fromtimestamp(seconds, tz=timezone.utc)
    except (OSError, OverflowError, ValueError) as error:
        raise ValueError("message timestamp is outside the supported range") from error
    return parsed.replace(microsecond=milliseconds * 1000).isoformat()


def validate_trace(
    events: list[dict[str, object]], selector: str
) -> dict[str, object]:
    if not events:
        _fail("trace is empty")
    for event in events:
        if not isinstance(event, dict) or not isinstance(event.get("type"), str):
            _fail("trace contains a malformed event")

    starts = [
        (index, event)
        for index, event in enumerate(events)
        if event["type"] == "tool_execution_start"
    ]
    ends = [
        (index, event)
        for index, event in enumerate(events)
        if event["type"] == "tool_execution_end"
    ]
    if len(starts) != 1 or len(ends) != 1:
        _fail("trace must contain exactly one tool start and one tool end")

    start_index, start = starts[0]
    if start.get("toolName") != "read":
        _fail("the only tool call must be read")
    args = start.get("args")
    if not isinstance(args, dict) or args.get("path") != EXPECTED_READ_PATH:
        _fail("read call path does not match the required charter")
    tool_call_id = _required_string(start.get("toolCallId"), "toolCallId")

    end_index, end = ends[0]
    if end.get("toolCallId") != tool_call_id or end.get("toolName") != "read":
        _fail("read completion does not match the read call")
    if end.get("isError") is not False or end.get("error") not in (None, ""):
        _fail("read tool call did not complete successfully")
    read_result = _tool_result_text(end.get("result"))
    if not read_result or any(marker not in read_result for marker in _REQUIRED_CHARTER_MARKERS):
        _fail("read result is empty or lacks required charter markers")

    assistant_messages: list[tuple[int, dict[str, object], str]] = []
    for index, event in enumerate(events):
        if event["type"] != "message_end":
            continue
        message = event.get("message")
        if not isinstance(message, dict):
            _fail("message_end event must contain a message object")
        role = _required_string(message.get("role"), "message_end role")
        validated_at = _validated_timestamp(message)
        if role == "assistant":
            assistant_messages.append((index, message, validated_at))
    if not assistant_messages:
        _fail("trace has no final assistant message")

    final_message_index, final_message, validated_at = assistant_messages[-1]
    if not start_index < end_index < final_message_index:
        _fail("successful read must complete before the final assistant message")
    provider = _required_string(final_message.get("provider"), "observed provider")
    api = _required_string(final_message.get("api"), "observed api")
    model = _required_string(final_message.get("model"), "observed model")
    if f"{provider}/{model}" != selector:
        _fail("selector does not match the observed provider and model")

    final_object = _parse_json(_assistant_text(final_message), "final assistant message")
    if (
        not isinstance(final_object, dict)
        or final_object.keys() != EXPECTED_FINAL.keys()
        or any(
            type(final_object[key]) is not type(expected)
            or final_object[key] != expected
            for key, expected in EXPECTED_FINAL.items()
        )
    ):
        _fail("final assistant JSON does not exactly match the expected object")

    canonical_final = json.dumps(
        EXPECTED_FINAL,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return {
        "selector": selector,
        "provider": provider,
        "api": api,
        "readPath": EXPECTED_READ_PATH,
        "readResultSha256": hashlib.sha256(read_result.encode("utf-8")).hexdigest(),
        "finalObjectSha256": hashlib.sha256(canonical_final).hexdigest(),
        "validatedAt": validated_at,
    }


def validate_probe(
    discovery_path: Path,
    artifact_path: Path,
    thresholds_path: Path,
    selector: str,
    role: str,
) -> dict[str, object]:
    discovery = _read_json_object(discovery_path)
    thresholds = _read_json_object(thresholds_path)
    try:
        artifact_bytes = artifact_path.read_bytes()
        artifact_text = artifact_bytes.decode("utf-8")
    except (OSError, UnicodeError) as error:
        raise ValueError(f"cannot read {artifact_path}: {error}") from error
    events = _parse_jsonl(artifact_text, artifact_path)
    trace = validate_trace(events, selector)
    model = find_discovered_model(discovery, selector)

    fixture_version = thresholds.get("schemaVersion")
    if type(fixture_version) is not int or fixture_version != 1:
        _fail("threshold fixture schemaVersion must be integer 1")
    roles = thresholds.get("roles")
    if not isinstance(roles, dict):
        _fail("threshold fixture roles must be an object")
    role_thresholds = roles.get(role)
    if not isinstance(role_thresholds, dict):
        _fail(f"threshold role is missing: {role}")
    min_context = _required_positive_integer(
        role_thresholds.get("minContextWindow"), "minContextWindow"
    )
    min_max_tokens = _required_positive_integer(
        role_thresholds.get("minMaxTokens"), "minMaxTokens"
    )

    context_window = _required_positive_integer(
        model.get("contextWindow"), "contextWindow"
    )
    max_tokens = _required_positive_integer(model.get("maxTokens"), "maxTokens")
    if context_window < min_context or max_tokens < min_max_tokens:
        _fail(f"discovered model does not meet the {role} role threshold")
    if model.get("provider") != trace["provider"]:
        _fail("discovery provider does not match the observed provider")

    return {
        "fixtureVersion": fixture_version,
        "selector": selector,
        "provider": trace["provider"],
        "api": trace["api"],
        "discoveredModelId": model["id"],
        "contextWindow": context_window,
        "maxTokens": max_tokens,
        "readPath": trace["readPath"],
        "readResultSha256": trace["readResultSha256"],
        "finalObjectSha256": trace["finalObjectSha256"],
        "artifactSha256": hashlib.sha256(artifact_bytes).hexdigest(),
        "validatedAt": trace["validatedAt"],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--discovery", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--thresholds", type=Path, required=True)
    parser.add_argument("--selector", required=True)
    parser.add_argument("--role", required=True)
    args = parser.parse_args()
    try:
        evidence = validate_probe(
            args.discovery,
            args.artifact,
            args.thresholds,
            args.selector,
            args.role,
        )
    except (OSError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 1
    print(json.dumps(evidence, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
