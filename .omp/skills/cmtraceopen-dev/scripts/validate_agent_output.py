#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path
from typing import Callable, NoReturn, Sequence


def _load_lane_state() -> object:
    path = Path(__file__).with_name("lane_state.py")
    spec = importlib.util.spec_from_file_location("cmtraceopen_lane_state", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load path validator: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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


_LANE_STATE = _load_lane_state()
_is_portable_repo_relative: Callable[..., bool] = getattr(
    _LANE_STATE, "_is_portable_repo_relative"
)
_decode_json_object: Callable[[str, str], dict[str, object]] = getattr(
    _LANE_STATE, "_decode_json_object"
)
_require_sha: Callable[[object, str], str] = getattr(
    _LANE_STATE, "_require_sha"
)
_validate_independent_review_gate_states: Callable[[object, str], None] = getattr(
    _LANE_STATE, "_validate_independent_review_gate_states"
)
_COMMAND_POLICY = _load_command_policy()
_validate_check_command: Callable[[Sequence[object]], tuple[str, ...]] = getattr(
    _COMMAND_POLICY, "validate_check_command"
)

ROLES = {
    "code-review",
    "coder",
    "reducer-adversary",
    "reducer-contract",
    "reducer-integration",
    "tech-writer",
    "ui-design",
}

_INTEGRATION_GATE_STATES = {
    "implementation": frozenset({"green"}),
    "conformance": frozenset({"passed"}),
    "review": frozenset({"passed"}),
    "native_lab": frozenset({"passed", "not_required"}),
    "mergeability": frozenset({"mergeable"}),
}


TEXT_LIST_KEYS = {
    "code-review": ("coverage", "blockers"),
    "coder": ("blockers",),
    "reducer-adversary": ("failure_scenarios", "blockers"),
    "reducer-contract": ("evidence", "blockers"),
    "reducer-integration": ("blockers",),
    "tech-writer": ("evidence_sources", "blockers"),
    "ui-design": ("blockers",),
}


def _fail(message: str) -> NoReturn:
    raise ValueError(message)


def _list(payload: dict[str, object], key: str) -> list[object]:
    value = payload.get(key)
    if not isinstance(value, list):
        _fail(f"{key} must be a list")
    return value


def _validate_text_list(payload: dict[str, object], key: str) -> None:
    for index, value in enumerate(_list(payload, key)):
        if not isinstance(value, str) or not value:
            _fail(f"{key}[{index}] must be a nonempty string")


def _validate_command(value: object, label: str) -> None:
    if not isinstance(value, dict) or set(value) != {
        "argv",
        "timeout_seconds",
    }:
        _fail(f"{label} must contain only argv and timeout_seconds")
    argv = value["argv"]
    if not isinstance(argv, list):
        _fail(f"{label}.argv must be an argument list")
    _validate_check_command(argv)
    timeout = value["timeout_seconds"]
    if type(timeout) is not int or not 1 <= timeout <= 3600:
        _fail(f"{label}.timeout_seconds must be an integer from 1 to 3600")


def _validate_command_list(payload: dict[str, object], key: str) -> None:
    for index, value in enumerate(_list(payload, key)):
        _validate_command(value, f"{key}[{index}]")


def _validate_scenario_list(payload: dict[str, object], key: str) -> None:
    for index, value in enumerate(_list(payload, key)):
        label = f"{key}[{index}]"
        if not isinstance(value, str) or not value:
            _fail(f"{label} must be a nonempty string")
        if len(value) > 4096:
            _fail(f"{label} must contain at most 4096 characters")
        if any(
            ord(character) < 0x20 or 0x7F <= ord(character) <= 0x9F
            for character in value
        ):
            _fail(f"{label} must not contain control characters")


def _validate_nonempty_fields(
    value: object, keys: Sequence[str], label: str
) -> dict[str, object]:
    if not isinstance(value, dict):
        _fail(f"{label} must be an object")
    for key in keys:
        field = value.get(key)
        if not isinstance(field, str) or not field:
            _fail(f"{label}.{key} must be a nonempty string")
    return value


def _validate_object_list(
    payload: dict[str, object], key: str, fields: Sequence[str]
) -> None:
    for index, value in enumerate(_list(payload, key)):
        _validate_nonempty_fields(value, fields, f"{key}[{index}]")

def _validate_review_findings(payload: dict[str, object]) -> None:
    for index, value in enumerate(_list(payload, "findings")):
        label = f"findings[{index}]"
        item = _validate_nonempty_fields(
            value,
            ("file_line", "mechanism", "failure_scenario", "severity"),
            label,
        )
        file_path, separator, line = item["file_line"].rpartition(":")
        if (
            not separator
            or not _is_portable_repo_relative(file_path)
            or not line.isascii()
            or not line.isdigit()
            or line.startswith("0")
        ):
            _fail(f"{label}.file_line must be a portable path and positive line")


def _validate_reducer_contract_decisions(payload: dict[str, object]) -> None:
    for index, value in enumerate(_list(payload, "decisions")):
        label = f"decisions[{index}]"
        item = _validate_nonempty_fields(
            value,
            ("contract", "evidence", "consequence"),
            label,
        )
        _validate_command(item.get("test"), f"{label}.test")


def _require_nonempty(payload: dict[str, object], *keys: str) -> None:
    for key in keys:
        value = payload.get(key)
        if not isinstance(value, (list, dict)) or not value:
            _fail(f"{key} must be nonempty")


def _require_empty(payload: dict[str, object], *keys: str) -> None:
    for key in keys:
        value = payload.get(key)
        if not isinstance(value, (list, dict)) or value:
            _fail(f"{key} must be empty")


def _validate_path(value: object, label: str) -> None:
    if not _is_portable_repo_relative(value):
        _fail(f"{label} is not a portable repository-relative path")


def _validate_proposal_paths(payload: dict[str, object], key: str) -> None:
    for index, value in enumerate(_list(payload, key)):
        label = f"{key}[{index}]"
        item = _validate_nonempty_fields(value, ("path",), label)
        _validate_path(item["path"], f"{label}.path")
        is_fixture = key == "fixture_proposals"
        required_field = "content" if is_fixture else "patch_intent"
        _validate_nonempty_fields(item, (required_field,), label)
        if is_fixture:
            continue
        if item.get("operation") not in {"create", "replace", "delete"}:
            _fail(f"{label}.operation is invalid")
        if not isinstance(item.get("exact_content"), str):
            _fail(f"{label}.exact_content must be a string")


def _validate_blocked(payload: dict[str, object], empty_keys: Sequence[str]) -> None:
    _require_nonempty(payload, "blockers")
    _require_empty(payload, *empty_keys)


def _validate_coder(payload: dict[str, object], phase: str) -> None:
    proposal_keys = (
        "implementation_proposals",
        "proposed_red_checks",
        "proposed_green_checks",
        "proposed_verification_checks",
    )
    for key in (
        "proposed_red_checks",
        "proposed_green_checks",
        "proposed_verification_checks",
    ):
        _validate_command_list(payload, key)
    if phase == "blocked":
        _validate_blocked(payload, proposal_keys)
        return
    if _list(payload, "blockers"):
        _fail("productive coder output cannot contain blockers")
    _require_nonempty(payload, "implementation_proposals")
    _validate_proposal_paths(payload, "implementation_proposals")
    if phase == "red_proposal":
        _require_nonempty(payload, "proposed_red_checks")
        _require_empty(
            payload,
            "proposed_green_checks",
            "proposed_verification_checks",
        )
    elif phase == "green_proposal":
        _require_empty(payload, "proposed_red_checks")
        _require_nonempty(
            payload, "proposed_green_checks", "proposed_verification_checks"
        )
    else:
        _fail(f"invalid coder phase: {phase}")

def _validate_edit_role(
    payload: dict[str, object], phase: str, check_keys: Sequence[str]
) -> None:
    work_keys = ("edit_proposals", *check_keys)
    if phase == "blocked":
        _validate_blocked(payload, work_keys)
        return
    if phase != "edit_proposal":
        _fail(f"invalid {payload.get('role')} phase: {phase}")
    if _list(payload, "blockers"):
        _fail("productive edit output cannot contain blockers")
    _require_nonempty(payload, *work_keys)
    _validate_proposal_paths(payload, "edit_proposals")


def _validate_adversary(payload: dict[str, object], phase: str) -> None:
    work_keys = ("adversarial_contracts", "fixture_proposals", "failure_scenarios")
    if phase == "blocked":
        _validate_blocked(payload, work_keys)
        return
    if phase != "adversarial_red":
        _fail(f"invalid reducer-adversary phase: {phase}")
    if _list(payload, "blockers"):
        _fail("productive adversarial output cannot contain blockers")
    _require_nonempty(payload, *work_keys)
    for index, value in enumerate(_list(payload, "adversarial_contracts")):
        label = f"adversarial_contracts[{index}]"
        contract = _validate_nonempty_fields(
            value,
            ("invariant", "expected_failure"),
            label,
        )
        _validate_command(
            contract.get("proposed_red_command"),
            f"{label}.proposed_red_command",
        )
        fixture = _validate_nonempty_fields(
            contract.get("fixture_proposal"),
            ("path", "content"),
            f"adversarial_contracts[{index}].fixture_proposal",
        )
        _validate_path(
            fixture["path"],
            f"adversarial_contracts[{index}].fixture_proposal.path",
        )
    _validate_proposal_paths(payload, "fixture_proposals")


def _validate_report_role(
    payload: dict[str, object],
    phase: str,
    productive_phase: str,
    work_keys: Sequence[str],
    blocked_keys: Sequence[str] | None = None,
) -> None:
    if phase == "blocked":
        _validate_blocked(payload, work_keys if blocked_keys is None else blocked_keys)
        return
    if phase != productive_phase:
        _fail(f"invalid {payload.get('role')} phase: {phase}")
    if _list(payload, "blockers"):
        _fail("productive report output cannot contain blockers")
    _require_nonempty(payload, *work_keys)


def _validate_integration_report(
    payload: dict[str, object],
    phase: str,
) -> None:
    _validate_report_role(
        payload,
        phase,
        "integration_report",
        ("heads", "gate_states"),
    )
    if phase == "blocked":
        return
    heads = payload["heads"]
    gate_states = payload["gate_states"]
    if not isinstance(heads, dict):
        _fail("reducer-integration.heads must be an object")
    if not isinstance(gate_states, dict):
        _fail("reducer-integration.gate_states must be an object")
    for name, head_sha in heads.items():
        if not isinstance(name, str) or not name:
            _fail("reducer-integration head name must be nonempty")
        _require_sha(
            head_sha,
            f"reducer-integration.heads.{name}",
        )
    if gate_states.keys() != _INTEGRATION_GATE_STATES.keys():
        _fail(
            "reducer-integration.gate_states must contain exactly "
            "implementation, conformance, review, native_lab, and mergeability"
        )
    for name, allowed_states in _INTEGRATION_GATE_STATES.items():
        if gate_states[name] not in allowed_states:
            _fail(
                f"reducer-integration.gate_states.{name} is invalid"
            )


def validate_output(role: str, payload: object) -> None:
    if role not in ROLES:
        _fail(f"unknown role: {role}")
    if not isinstance(payload, dict):
        _fail("agent output must be an object")
    if payload.get("role") != role:
        _fail(f"role discriminator must equal {role}")
    for key in TEXT_LIST_KEYS[role]:
        _validate_text_list(payload, key)
    phase = payload.get("phase")
    if not isinstance(phase, str) or not phase:
        _fail("phase discriminator must be a nonempty string")
    _list(payload, "blockers")
    if role in {"coder", "ui-design", "tech-writer"}:
        _validate_nonempty_fields(payload, ("summary",), role)
    elif role == "code-review":
        _require_sha(payload.get("head_sha"), "code-review.head_sha")
        _require_sha(payload.get("base_sha"), "code-review.base_sha")
        _validate_review_findings(payload)
    elif role == "reducer-contract":
        _validate_reducer_contract_decisions(payload)
        _validate_command_list(payload, "tests")

    if role == "coder":
        _validate_coder(payload, phase)
    elif role == "ui-design":
        _validate_scenario_list(payload, "proposed_browser_checks")
        _validate_edit_role(payload, phase, ("proposed_browser_checks",))
    elif role == "tech-writer":
        _validate_command_list(payload, "proposed_source_link_render_checks")
        _validate_edit_role(
            payload,
            phase,
            ("evidence_sources", "proposed_source_link_render_checks"),
        )
    elif role == "reducer-adversary":
        _validate_adversary(payload, phase)
    elif role == "code-review":
        _validate_report_role(
            payload,
            phase,
            "review_report",
            ("gate_states", "coverage"),
            ("findings", "gate_states", "coverage"),
        )
        if phase == "review_report":
            _validate_independent_review_gate_states(
                payload.get("gate_states"),
                "code-review.gate_states",
            )
    elif role == "reducer-contract":
        _validate_report_role(
            payload, phase, "contract_report", ("decisions", "evidence", "tests")
        )
    else:
        _validate_integration_report(payload, phase)


def _parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--role", required=True, choices=sorted(ROLES))
    parser.add_argument("--input", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    try:
        text = args.input.read_text(encoding="utf-8")
        payload = _decode_json_object(text, str(args.input))
        validate_output(args.role, payload)
    except (OSError, UnicodeError, ValueError) as error:
        print(json.dumps({"ok": False, "reason": str(error)}, separators=(",", ":")))
        return 1
    print(json.dumps({"ok": True, "role": args.role}, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
