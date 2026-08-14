from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from typing import NoReturn, Sequence
from urllib.parse import urlparse


SCHEMA_VERSION = 1
LANE_STATES = {
    "allocated",
    "running",
    "blocked",
    "reviewing",
    "ready_for_adam",
    "merged",
    "abandoned",
}
GATE_STATES = {"not_run", "running", "passed", "failed", "stale", "unavailable"}
NATIVE_STATES = GATE_STATES | {"not_required"}
NATIVE_REQUIREMENTS = {"required", "not_required"}
IMPLEMENTATION_STATES = {"not_run", "red", "green", "failed", "stale"}
MERGEABILITY_STATES = {
    "not_run",
    "mergeable",
    "conflicting",
    "blocked",
    "stale",
    "unavailable",
}
TRANSITIONS = {
    "allocated": {"running", "blocked", "abandoned"},
    "running": {"blocked", "reviewing", "abandoned"},
    "blocked": {"running", "abandoned"},
    "reviewing": {"running", "blocked", "ready_for_adam"},
    "ready_for_adam": {"reviewing", "blocked", "merged", "abandoned"},
    "merged": set(),
    "abandoned": set(),
}

_GATE_BASE_SENSITIVITY = {
    "focused": False,
    "aggregate": True,
    "conformance": True,
    "coderabbit": True,
    "independent_review": True,
    "native_lab": False,
    "mergeability": True,
}
_ROOT_KEYS = {"schemaVersion", "updatedAt", "lanes", "aggregateGate", "rootSafety"}
_LANE_KEYS = {
    "issue",
    "title",
    "agentId",
    "role",
    "worktree",
    "branch",
    "allowedPaths",
    "dependsOn",
    "sharedContractPaths",
    "integrationOrder",
    "headSha",
    "allocationBaseSha",
    "currentBaseSha",
    "remoteSha",
    "pr",
    "lease",
    "laneState",
    "implementationState",
    "mergeabilityState",
    "redEvidence",
    "blocker",
    "nextAction",
    "gates",
    "nativeLabRequirement",
}
_OBSERVATION_KEYS = {
    "state",
    "headSha",
    "baseSha",
    "command",
    "scenario",
    "exitCode",
    "observedAt",
    "artifact",
    "baseSensitive",
}
_FEATURE_OWNER_KEYS = {
    "schemaVersion",
    "owner",
    "role",
    "worktree",
    "allowedPaths",
    "state",
    "assignedAt",
    "transferCount",
    "evidenceInvalidatedAt",
}
_ROOT_SLOTS = {"stage1Before", "stage1After", "stage2Before", "stage2After"}
_SHA_PATTERN = re.compile(r"[0-9a-fA-F]{40}\Z")


def _fail(message: str) -> NoReturn:
    raise ValueError(message)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _require_exact_keys(value: dict[str, object], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        _fail(f"{label} keys are invalid (missing={missing}, extra={extra})")


def _require_nonempty_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        _fail(f"{label} must be a non-empty string")
    return value


def _require_optional_string(value: object, label: str) -> None:
    if value is not None:
        _require_nonempty_string(value, label)


def _require_int(value: object, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        _fail(f"{label} must be an integer greater than or equal to {minimum}")
    return value

def _require_enum(value: object, choices: set[str], label: str) -> str:
    if not isinstance(value, str) or value not in choices:
        _fail(f"{label} is invalid")
    return value


def _require_schema_version(value: object, label: str) -> None:
    if type(value) is not int or value != SCHEMA_VERSION:
        _fail(f"{label} must be {SCHEMA_VERSION}")


def _require_string_list(value: object, label: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        _fail(f"{label} must be a list of non-empty strings")
    if len(value) != len(set(value)):
        _fail(f"{label} must not contain duplicates")
    return value


def _require_sha(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA_PATTERN.fullmatch(value) is None:
        _fail(f"{label} must be a 40-hex SHA")
    return value


def _require_utc(value: object, label: str) -> str:
    if not isinstance(value, str):
        _fail(f"{label} must be a timezone-aware UTC ISO-8601 string")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise ValueError(f"{label} must be a timezone-aware UTC ISO-8601 string") from error
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        _fail(f"{label} must be a timezone-aware UTC ISO-8601 string")
    return value


def _require_optional_utc(value: object, label: str) -> None:
    if value is not None:
        _require_utc(value, label)


def _states_for_gate(name: str) -> set[str]:
    if name == "native_lab":
        return NATIVE_STATES
    if name == "mergeability":
        return MERGEABILITY_STATES
    return GATE_STATES


def empty_manifest() -> dict[str, object]:
    return {
        "schemaVersion": SCHEMA_VERSION,
        "updatedAt": _utc_now(),
        "lanes": {},
        "aggregateGate": {"holder": None, "queue": [], "acquiredAt": None},
        "rootSafety": {
            "stage1Before": None,
            "stage1After": None,
            "stage2Before": None,
            "stage2After": None,
        },
    }


def _validate_observation(
    observation: object,
    label: str,
    states: set[str],
    *,
    lane_head: str,
    current_base: str,
    require_matching_head: bool,
    require_matching_base: bool,
) -> dict[str, object]:
    if not isinstance(observation, dict):
        _fail(f"{label} must be an object")
    _require_exact_keys(observation, _OBSERVATION_KEYS, label)
    state_value = _require_enum(observation["state"], states, f"{label}.state")
    if not isinstance(observation["baseSensitive"], bool):
        _fail(f"{label}.baseSensitive must be boolean")

    initial_state = state_value in {"not_run", "not_required"}
    evidence_keys = (
        "headSha",
        "baseSha",
        "command",
        "scenario",
        "exitCode",
        "observedAt",
        "artifact",
    )
    if initial_state:
        if any(observation[key] is not None for key in evidence_keys):
            _fail(f"{label} initial state must not contain observation evidence")
        return observation

    head_sha = _require_sha(observation["headSha"], f"{label}.headSha")
    base_sha = _require_sha(observation["baseSha"], f"{label}.baseSha")
    command = observation["command"]
    scenario = observation["scenario"]
    _require_optional_string(command, f"{label}.command")
    _require_optional_string(scenario, f"{label}.scenario")
    if command is None and scenario is None:
        _fail(f"{label} requires command or scenario")
    _require_int(observation["exitCode"], f"{label}.exitCode", minimum=0)
    _require_utc(observation["observedAt"], f"{label}.observedAt")
    _require_nonempty_string(observation["artifact"], f"{label}.artifact")
    if require_matching_head and head_sha != lane_head:
        _fail(f"{label}.headSha must match the lane head")
    if require_matching_base and base_sha != current_base:
        _fail(f"{label}.baseSha must match the lane current base")
    return observation


def _validate_lane(lane_key: str, lane: object) -> None:
    if not isinstance(lane, dict):
        _fail(f"lane {lane_key} must be an object")
    _require_exact_keys(lane, _LANE_KEYS, f"lane {lane_key}")

    issue = _require_int(lane["issue"], f"lane {lane_key}.issue", minimum=1)
    if lane_key != str(issue):
        _fail(f"lane key {lane_key} must match issue {issue}")
    _require_nonempty_string(lane["title"], f"lane {lane_key}.title")
    agent_id = _require_nonempty_string(lane["agentId"], f"lane {lane_key}.agentId")
    _require_nonempty_string(lane["role"], f"lane {lane_key}.role")
    worktree = _require_nonempty_string(lane["worktree"], f"lane {lane_key}.worktree")
    if not Path(worktree).is_absolute():
        _fail(f"lane {lane_key}.worktree must be absolute")
    _require_nonempty_string(lane["branch"], f"lane {lane_key}.branch")
    _require_string_list(lane["allowedPaths"], f"lane {lane_key}.allowedPaths")
    _require_string_list(lane["dependsOn"], f"lane {lane_key}.dependsOn")
    _require_string_list(lane["sharedContractPaths"], f"lane {lane_key}.sharedContractPaths")
    _require_int(lane["integrationOrder"], f"lane {lane_key}.integrationOrder", minimum=1)
    head_sha = _require_sha(lane["headSha"], f"lane {lane_key}.headSha")
    _require_sha(lane["allocationBaseSha"], f"lane {lane_key}.allocationBaseSha")
    current_base = _require_sha(lane["currentBaseSha"], f"lane {lane_key}.currentBaseSha")
    if lane["remoteSha"] is not None:
        _require_sha(lane["remoteSha"], f"lane {lane_key}.remoteSha")

    pr = lane["pr"]
    if not isinstance(pr, dict):
        _fail(f"lane {lane_key}.pr must be an object")
    _require_exact_keys(pr, {"number", "url"}, f"lane {lane_key}.pr")
    if (pr["number"] is None) != (pr["url"] is None):
        _fail(f"lane {lane_key}.pr number and url must both be set or both be null")
    if pr["number"] is not None:
        _validate_pr(pr["number"], pr["url"])

    lease = lane["lease"]
    if not isinstance(lease, dict):
        _fail(f"lane {lane_key}.lease must be an object")
    _require_exact_keys(
        lease,
        {"owner", "expiresAt", "heartbeatAt", "lastVerifiedAt"},
        f"lane {lane_key}.lease",
    )
    lease_owner = _require_nonempty_string(lease["owner"], f"lane {lane_key}.lease.owner")
    if lease_owner != agent_id:
        _fail(f"lane {lane_key} must have exactly one owner")
    for field in ("expiresAt", "heartbeatAt", "lastVerifiedAt"):
        _require_utc(lease[field], f"lane {lane_key}.lease.{field}")

    _require_enum(lane["laneState"], LANE_STATES, f"lane {lane_key}.laneState")
    _require_enum(
        lane["implementationState"],
        IMPLEMENTATION_STATES,
        f"lane {lane_key}.implementationState",
    )
    _require_enum(
        lane["mergeabilityState"],
        MERGEABILITY_STATES,
        f"lane {lane_key}.mergeabilityState",
    )
    _require_optional_string(lane["blocker"], f"lane {lane_key}.blocker")
    _require_nonempty_string(lane["nextAction"], f"lane {lane_key}.nextAction")

    red_evidence = lane["redEvidence"]
    if not isinstance(red_evidence, list):
        _fail(f"lane {lane_key}.redEvidence must be a list")
    for index, observation in enumerate(red_evidence):
        _validate_observation(
            observation,
            f"lane {lane_key}.redEvidence[{index}]",
            {"failed"},
            lane_head=head_sha,
            current_base=current_base,
            require_matching_head=False,
            require_matching_base=False,
        )

    gates = lane["gates"]
    if not isinstance(gates, dict):
        _fail(f"lane {lane_key}.gates must be an object")
    _require_exact_keys(gates, set(_GATE_BASE_SENSITIVITY), f"lane {lane_key}.gates")
    for gate_name, observation in gates.items():
        states = _states_for_gate(gate_name)
        validated = _validate_observation(
            observation,
            f"lane {lane_key}.gates.{gate_name}",
            states,
            lane_head=head_sha,
            current_base=current_base,
            require_matching_head=observation.get("state") != "stale",
            require_matching_base=(
                observation.get("state") != "stale"
                and observation.get("baseSensitive") is True
            ),
        )
        if gate_name != "native_lab" and validated["baseSensitive"] != _GATE_BASE_SENSITIVITY[gate_name]:
            _fail(f"lane {lane_key}.gates.{gate_name}.baseSensitive is invalid")

    requirement = lane["nativeLabRequirement"]
    if not isinstance(requirement, dict):
        _fail(f"lane {lane_key}.nativeLabRequirement must be an object")
    _require_exact_keys(requirement, {"state", "reason"}, f"lane {lane_key}.nativeLabRequirement")
    _require_enum(
        requirement["state"],
        NATIVE_REQUIREMENTS,
        f"lane {lane_key}.nativeLabRequirement.state",
    )
    _require_nonempty_string(requirement["reason"], f"lane {lane_key}.nativeLabRequirement.reason")


def validate_manifest(data: dict[str, object]) -> None:
    if not isinstance(data, dict):
        _fail("manifest must be an object")
    _require_exact_keys(data, _ROOT_KEYS, "manifest")
    _require_schema_version(data["schemaVersion"], "schemaVersion")
    _require_utc(data["updatedAt"], "updatedAt")

    lanes = data["lanes"]
    if not isinstance(lanes, dict):
        _fail("lanes must be an object")
    for lane_key, lane in lanes.items():
        if not isinstance(lane_key, str):
            _fail("lane keys must be strings")
        _validate_lane(lane_key, lane)

    aggregate_gate = data["aggregateGate"]
    if not isinstance(aggregate_gate, dict):
        _fail("aggregateGate must be an object")
    _require_exact_keys(aggregate_gate, {"holder", "queue", "acquiredAt"}, "aggregateGate")
    _require_optional_string(aggregate_gate["holder"], "aggregateGate.holder")
    _require_string_list(aggregate_gate["queue"], "aggregateGate.queue")
    _require_optional_utc(aggregate_gate["acquiredAt"], "aggregateGate.acquiredAt")
    if (aggregate_gate["holder"] is None) != (aggregate_gate["acquiredAt"] is None):
        _fail("aggregateGate holder and acquiredAt must both be set or both be null")

    root_safety = data["rootSafety"]
    if not isinstance(root_safety, dict):
        _fail("rootSafety must be an object")
    _require_exact_keys(root_safety, _ROOT_SLOTS, "rootSafety")
    for slot, artifact in root_safety.items():
        _require_optional_string(artifact, f"rootSafety.{slot}")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _fail(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_json_object(path: Path) -> dict[str, object]:
    try:
        text = path.read_text(encoding="utf-8")
        value = json.loads(text, object_pairs_hook=_unique_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot load JSON from {path}: {error}") from error
    if not isinstance(value, dict):
        _fail(f"{path} must contain one JSON object")
    return value


def load_manifest(path: Path) -> dict[str, object]:
    data = _load_json_object(path)
    validate_manifest(data)
    return data


def ensure_state_dir(path: Path) -> None:
    parent = path.parent
    try:
        parent_info = parent.stat()
    except OSError as error:
        raise ValueError(f"Git common directory parent does not exist: {parent}") from error
    if not stat.S_ISDIR(parent_info.st_mode):
        _fail(f"Git common directory parent is not a directory: {parent}")

    try:
        info = path.lstat()
    except FileNotFoundError:
        try:
            path.mkdir(mode=0o700)
        except FileExistsError:
            pass
        except OSError as error:
            raise ValueError(f"cannot create state directory {path}: {error}") from error
        try:
            info = path.lstat()
        except OSError as error:
            raise ValueError(f"cannot verify state directory {path}: {error}") from error
    except OSError as error:
        raise ValueError(f"cannot inspect state directory {path}: {error}") from error

    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        _fail(f"state directory must be a real directory: {path}")


def _write_temporary_json(path: Path, data: dict[str, object]) -> Path:
    ensure_state_dir(path.parent)
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        delete=False,
        dir=path.parent,
    ) as temporary:
        temporary_path = Path(temporary.name)
        json.dump(data, temporary, sort_keys=True, separators=(",", ":"))
        temporary.write("\n")
        temporary.flush()
        os.fsync(temporary.fileno())
    return temporary_path


def _atomic_json_write(path: Path, data: dict[str, object]) -> None:
    temporary_path = _write_temporary_json(path, data)
    try:
        os.replace(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)


def _atomic_json_create(path: Path, data: dict[str, object]) -> bool:
    temporary_path = _write_temporary_json(path, data)
    try:
        try:
            os.link(temporary_path, path)
        except FileExistsError:
            return False
        return True
    finally:
        temporary_path.unlink(missing_ok=True)


def atomic_write(path: Path, data: dict[str, object]) -> None:
    validate_manifest(data)
    _atomic_json_write(path, data)


def initialize_manifest(path: Path) -> tuple[dict[str, object], bool]:
    data = empty_manifest()
    validate_manifest(data)
    if _atomic_json_create(path, data):
        return data, True
    return load_manifest(path), False


def _touch(data: dict[str, object]) -> None:
    data["updatedAt"] = _utc_now()


def _lane(data: dict[str, object], issue: str) -> dict[str, object]:
    lanes = data.get("lanes")
    if not isinstance(lanes, dict) or issue not in lanes or not isinstance(lanes[issue], dict):
        _fail(f"unknown lane: {issue}")
    return lanes[issue]


def _commit_candidate(data: dict[str, object], candidate: dict[str, object]) -> None:
    validate_manifest(candidate)
    data.clear()
    data.update(candidate)


def allocate_lane(data: dict[str, object], lane: dict[str, object]) -> None:
    validate_manifest(data)
    candidate = deepcopy(data)
    lane_copy = deepcopy(lane)
    if not isinstance(lane_copy, dict) or "issue" not in lane_copy:
        _fail("lane must contain issue")
    issue = lane_copy["issue"]
    _require_int(issue, "lane.issue", minimum=1)
    key = str(issue)
    lanes = candidate["lanes"]
    if key in lanes:
        _fail(f"lane already exists: {key}")
    if lane_copy.get("laneState") != "allocated":
        _fail("new lane must have laneState allocated")
    if lane_copy.get("allocationBaseSha") != lane_copy.get("currentBaseSha"):
        _fail("allocationBaseSha and currentBaseSha must match at allocation")
    if lane_copy.get("implementationState") != "not_run" or lane_copy.get("redEvidence") != []:
        _fail("new lane must begin before RED evidence")
    if lane_copy.get("mergeabilityState") != "not_run":
        _fail("new lane mergeability must be not_run")
    lanes[key] = lane_copy
    _touch(candidate)
    _commit_candidate(data, candidate)


def transition_lane(data: dict[str, object], issue: str, state: str) -> None:
    validate_manifest(data)
    _require_enum(state, LANE_STATES, "lane state")
    candidate = deepcopy(data)
    lane = _lane(candidate, issue)
    current = lane["laneState"]
    if state not in TRANSITIONS[current]:
        _fail(f"invalid lane transition: {current} -> {state}")
    lane["laneState"] = state
    _touch(candidate)
    _commit_candidate(data, candidate)


def _stale_observation(observation: dict[str, object]) -> None:
    if observation["state"] not in {"not_run", "not_required"}:
        observation["state"] = "stale"


def transfer_owner(data: dict[str, object], issue: str, owner: str, role: str) -> None:
    validate_manifest(data)
    _require_nonempty_string(owner, "owner")
    _require_nonempty_string(role, "role")
    candidate = deepcopy(data)
    lane = _lane(candidate, issue)
    if lane["laneState"] != "blocked":
        _fail("lane owner transfer requires blocked state")
    lane["agentId"] = owner
    lane["role"] = role
    lane["lease"]["owner"] = owner
    for gate_name in (
        "focused",
        "aggregate",
        "conformance",
        "coderabbit",
        "independent_review",
        "mergeability",
    ):
        _stale_observation(lane["gates"][gate_name])
    native = lane["gates"]["native_lab"]
    if native["baseSensitive"]:
        _stale_observation(native)
    if lane["mergeabilityState"] != "not_run":
        lane["mergeabilityState"] = "stale"
    _touch(candidate)
    _commit_candidate(data, candidate)


def heartbeat_lane(
    data: dict[str, object],
    issue: str,
    owner: str,
    at: str,
    expires_at: str,
) -> None:
    validate_manifest(data)
    _require_utc(at, "heartbeat time")
    _require_utc(expires_at, "lease expiry")
    candidate = deepcopy(data)
    lane = _lane(candidate, issue)
    if lane["agentId"] != owner or lane["lease"]["owner"] != owner:
        _fail("heartbeat owner must be the current sole owner")
    lane["lease"]["heartbeatAt"] = at
    lane["lease"]["lastVerifiedAt"] = at
    lane["lease"]["expiresAt"] = expires_at
    _touch(candidate)
    _commit_candidate(data, candidate)


def _validate_new_observation(
    lane: dict[str, object],
    observation: dict[str, object],
    label: str,
    states: set[str],
) -> dict[str, object]:
    return _validate_observation(
        observation,
        label,
        states,
        lane_head=lane["headSha"],
        current_base=lane["currentBaseSha"],
        require_matching_head=True,
        require_matching_base=True,
    )


def record_red(data: dict[str, object], issue: str, observation: dict[str, object]) -> None:
    validate_manifest(data)
    candidate = deepcopy(data)
    lane = _lane(candidate, issue)
    observation_copy = deepcopy(observation)
    _validate_new_observation(lane, observation_copy, "RED observation", {"failed"})
    lane["redEvidence"].append(observation_copy)
    lane["implementationState"] = "red"
    _touch(candidate)
    _commit_candidate(data, candidate)


def record_observation(
    data: dict[str, object],
    issue: str,
    gate: str,
    observation: dict[str, object],
) -> None:
    validate_manifest(data)
    if gate not in _GATE_BASE_SENSITIVITY:
        _fail(f"unknown gate: {gate}")
    candidate = deepcopy(data)
    lane = _lane(candidate, issue)
    observation_copy = deepcopy(observation)
    states = _states_for_gate(gate)
    validated = _validate_new_observation(lane, observation_copy, f"gate {gate}", states)
    if gate != "native_lab" and validated["baseSensitive"] != _GATE_BASE_SENSITIVITY[gate]:
        _fail(f"gate {gate}.baseSensitive is invalid")
    lane["gates"][gate] = observation_copy
    if gate == "mergeability":
        lane["mergeabilityState"] = observation_copy["state"]
    _touch(candidate)
    _commit_candidate(data, candidate)


def _stale_for_revision_change(lane: dict[str, object], *, head_changed: bool) -> None:
    for observation in lane["gates"].values():
        if observation["state"] in {"not_run", "not_required"}:
            continue
        if head_changed or observation["baseSensitive"]:
            observation["state"] = "stale"
    mergeability = lane["gates"]["mergeability"]
    if mergeability["state"] == "stale" and lane["mergeabilityState"] != "not_run":
        lane["mergeabilityState"] = "stale"


def record_status(data: dict[str, object], issue: str, status: dict[str, object]) -> None:
    validate_manifest(data)
    if not isinstance(status, dict) or not status:
        _fail("status must be a non-empty object")
    allowed = {
        "headSha",
        "currentBaseSha",
        "implementationState",
        "mergeabilityState",
        "blocker",
        "nextAction",
    }
    unknown = set(status) - allowed
    if unknown:
        _fail(f"unknown status fields: {sorted(unknown)}")
    candidate = deepcopy(data)
    lane = _lane(candidate, issue)
    head_changed = "headSha" in status and status["headSha"] != lane["headSha"]
    base_changed = "currentBaseSha" in status and status["currentBaseSha"] != lane["currentBaseSha"]
    for key, value in status.items():
        lane[key] = deepcopy(value)
    if head_changed or base_changed:
        _stale_for_revision_change(lane, head_changed=head_changed)
    _touch(candidate)
    _commit_candidate(data, candidate)


def _validate_feature_owner(owner: dict[str, object]) -> None:
    if not isinstance(owner, dict):
        _fail("feature owner must be an object")
    _require_exact_keys(owner, _FEATURE_OWNER_KEYS, "feature owner")
    _require_schema_version(owner["schemaVersion"], "feature owner schemaVersion")
    _require_nonempty_string(owner["owner"], "feature owner.owner")
    _require_nonempty_string(owner["role"], "feature owner.role")
    worktree = _require_nonempty_string(owner["worktree"], "feature owner.worktree")
    if not Path(worktree).is_absolute():
        _fail("feature owner.worktree must be absolute")
    _require_string_list(owner["allowedPaths"], "feature owner.allowedPaths")
    _require_enum(owner["state"], {"active", "blocked"}, "feature owner.state")
    _require_utc(owner["assignedAt"], "feature owner.assignedAt")
    _require_int(owner["transferCount"], "feature owner.transferCount")
    _require_optional_utc(owner["evidenceInvalidatedAt"], "feature owner.evidenceInvalidatedAt")


def _load_feature_owner(path: Path) -> dict[str, object]:
    owner = _load_json_object(path)
    _validate_feature_owner(owner)
    return owner


def record_feature_owner(path: Path, owner: dict[str, object]) -> None:
    owner_copy = deepcopy(owner)
    _validate_feature_owner(owner_copy)
    if _atomic_json_create(path, owner_copy):
        return
    existing = _load_feature_owner(path)
    if existing != owner_copy:
        _fail("a different feature owner record already exists")


def set_feature_owner_state(path: Path, state: str) -> None:
    _require_enum(state, {"active", "blocked"}, "feature owner state")
    owner = _load_feature_owner(path)
    owner["state"] = state
    _validate_feature_owner(owner)
    _atomic_json_write(path, owner)


def transfer_feature_owner(path: Path, owner: str, role: str, assigned_at: str) -> None:
    _require_nonempty_string(owner, "owner")
    _require_nonempty_string(role, "role")
    _require_utc(assigned_at, "assignedAt")
    record = _load_feature_owner(path)
    if record["state"] != "blocked":
        _fail("feature owner transfer requires blocked state")
    record["owner"] = owner
    record["role"] = role
    record["assignedAt"] = assigned_at
    record["transferCount"] += 1
    record["evidenceInvalidatedAt"] = assigned_at
    record["state"] = "active"
    _validate_feature_owner(record)
    _atomic_json_write(path, record)


def _validate_pr(number: object, url: object) -> None:
    _require_int(number, "PR number", minimum=1)
    parsed = urlparse(_require_nonempty_string(url, "PR URL"))
    if parsed.scheme != "https" or not parsed.netloc or not parsed.path:
        _fail("PR URL must be an absolute HTTPS URL")


def record_pr(data: dict[str, object], issue: str, number: int, url: str) -> None:
    validate_manifest(data)
    _validate_pr(number, url)
    candidate = deepcopy(data)
    _lane(candidate, issue)["pr"] = {"number": number, "url": url}
    _touch(candidate)
    _commit_candidate(data, candidate)


def record_remote(data: dict[str, object], issue: str, remote_sha: str) -> None:
    validate_manifest(data)
    _require_sha(remote_sha, "remote SHA")
    candidate = deepcopy(data)
    _lane(candidate, issue)["remoteSha"] = remote_sha
    _touch(candidate)
    _commit_candidate(data, candidate)


def record_root_snapshot(data: dict[str, object], slot: str, artifact: str) -> None:
    validate_manifest(data)
    if slot not in _ROOT_SLOTS:
        _fail(f"invalid root snapshot slot: {slot}")
    _require_nonempty_string(artifact, "root snapshot artifact")
    candidate = deepcopy(data)
    candidate["rootSafety"][slot] = artifact
    _touch(candidate)
    _commit_candidate(data, candidate)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    init_parser = subparsers.add_parser("init")
    init_parser.add_argument("path", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            manifest, created = initialize_manifest(args.path)
            output = {**manifest, "created": created}
            print(json.dumps(output, sort_keys=True, separators=(",", ":")))
            return 0
    except (OSError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 1
    _fail(f"unknown command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
