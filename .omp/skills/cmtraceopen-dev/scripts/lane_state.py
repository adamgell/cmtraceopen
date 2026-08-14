from __future__ import annotations

import argparse
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import fnmatch
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import time
from typing import Callable, Iterator, NoReturn, Sequence
from urllib.parse import unquote, urlparse


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

HEAD_BOUND = {
    "focused",
    "aggregate",
    "conformance",
    "coderabbit",
    "independent_review",
    "native_lab",
    "mergeability",
}
BASE_BOUND = {
    "aggregate",
    "conformance",
    "coderabbit",
    "independent_review",
    "mergeability",
}
DOWNSTREAM_BOUND = {
    "aggregate",
    "conformance",
    "coderabbit",
    "independent_review",
    "mergeability",
}
LOCK_TIMEOUT_SECONDS = 2.0


class RetriableConflict(RuntimeError):
    pass


class TerminalRejection(RuntimeError):
    pass

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
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
_STAGE1_ALLOWED_PATHS = [
    ".omp/**",
    ".Clairvoyance/library.md",
    ".Clairvoyance/kickoff-prompt.md",
    "docs/superpowers/specs/2026-08-14-omp-agent-driven-development-design.md",
    "docs/superpowers/plans/2026-08-14-omp-agent-driven-development.md",
]
_BASE_ARTIFACT_KEYS = {
    "schemaVersion",
    "kind",
    "headSha",
    "currentBaseSha",
    "integrationCommand",
    "integrationExitCode",
    "gateCommand",
    "gateExitCode",
    "rawEvidenceUri",
    "observedAt",
}
_GITHUB_REVIEW_ARTIFACT_KEYS = _BASE_ARTIFACT_KEYS | {
    "prNumber",
    "prUrl",
    "reviewGate",
}


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

def _require_issue_list(value: object, label: str) -> list[int]:
    if not isinstance(value, list):
        _fail(f"{label} must be a list of positive issue numbers")
    issues = [_require_int(item, label, minimum=1) for item in value]
    if len(issues) != len(set(issues)):
        _fail(f"{label} must not contain duplicates")
    return issues


def _require_sha(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA_PATTERN.fullmatch(value) is None:
        _fail(f"{label} must be a 40-hex SHA")
    return value

def _require_sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None:
        _fail(f"{label} must be a lowercase SHA-256 digest")
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
    _require_issue_list(lane["dependsOn"], f"lane {lane_key}.dependsOn")
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
            require_matching_head=(
                isinstance(observation, dict)
                and observation.get("state") != "stale"
            ),
            require_matching_base=True,
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
    for lane_key, lane in lanes.items():
        for upstream_issue in lane["dependsOn"]:
            upstream_key = str(upstream_issue)
            if upstream_key == lane_key or upstream_key not in lanes:
                _fail(f"lane {lane_key}.dependsOn references an invalid upstream issue")

    aggregate_gate = data["aggregateGate"]
    if not isinstance(aggregate_gate, dict):
        _fail("aggregateGate must be an object")
    _require_exact_keys(aggregate_gate, {"holder", "queue", "acquiredAt"}, "aggregateGate")
    _require_optional_string(aggregate_gate["holder"], "aggregateGate.holder")
    _require_string_list(aggregate_gate["queue"], "aggregateGate.queue")
    _require_optional_utc(aggregate_gate["acquiredAt"], "aggregateGate.acquiredAt")
    if (aggregate_gate["holder"] is None) != (aggregate_gate["acquiredAt"] is None):
        _fail("aggregateGate holder and acquiredAt must both be set or both be null")
    holder = aggregate_gate["holder"]
    queue = aggregate_gate["queue"]
    if holder is not None and holder not in lanes:
        _fail("aggregateGate holder must name an existing lane")
    if any(issue not in lanes for issue in queue):
        _fail("aggregateGate queue must contain existing lanes")
    if holder in queue:
        _fail("aggregateGate holder must not also be queued")

    root_safety = data["rootSafety"]
    if not isinstance(root_safety, dict):
        _fail("rootSafety must be an object")
    _require_exact_keys(root_safety, _ROOT_SLOTS, "rootSafety")
    for slot, snapshot in root_safety.items():
        if snapshot is None:
            continue
        if not isinstance(snapshot, dict):
            _fail(f"rootSafety.{slot} must be an object or null")
        _require_exact_keys(
            snapshot,
            {"artifact", "sha256"},
            f"rootSafety.{slot}",
        )
        artifact = _require_nonempty_string(
            snapshot["artifact"],
            f"rootSafety.{slot}.artifact",
        )
        parsed = urlparse(artifact)
        if (
            parsed.scheme != "file"
            or parsed.netloc not in {"", "localhost"}
            or parsed.query
            or parsed.fragment
        ):
            _fail(f"rootSafety.{slot}.artifact must be a local file:// URI")
        _require_sha256(snapshot["sha256"], f"rootSafety.{slot}.sha256")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _fail(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _decode_json_object(text: str, source: str) -> dict[str, object]:
    try:
        value = json.loads(text, object_pairs_hook=_unique_object)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot load JSON from {source}: {error}") from error
    if not isinstance(value, dict):
        _fail(f"{source} must contain one JSON object")
    return value

def _git_bytes(repo: Path, *args: str) -> bytes:
    try:
        repository = repo.resolve(strict=True)
    except OSError as error:
        raise ValueError(f"cannot resolve repository {repo}: {error}") from error
    if not repository.is_dir():
        _fail(f"repository is not a directory: {repo}")
    environment = os.environ.copy()
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    try:
        result = subprocess.run(
            ["git", "-C", str(repository), *args],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        stderr = getattr(error, "stderr", b"")
        detail = stderr.decode("utf-8", errors="replace").strip()
        raise ValueError(
            f"git {' '.join(args)} failed"
            + (f": {detail}" if detail else "")
        ) from error
    return result.stdout


def git_text(repo: Path, *args: str) -> str:
    try:
        return _git_bytes(repo, *args).decode("utf-8").rstrip("\n")
    except UnicodeDecodeError as error:
        raise ValueError("git output is not valid UTF-8") from error


def _is_repo_relative(value: object) -> bool:
    if not isinstance(value, str) or not value or "\0" in value:
        return False
    parts = value.split("/")
    return not value.startswith("/") and all(
        part not in {"", ".", ".."} for part in parts
    )


def _require_repo_relative(value: str, label: str) -> str:
    if not _is_repo_relative(value):
        _fail(f"{label} escapes the worktree")
    return value


def changed_paths(repo: Path, allocation_base: str) -> list[str]:
    _require_sha(allocation_base, "allocation base")
    try:
        tracked_output = _git_bytes(
            repo,
            "diff",
            "--name-only",
            "--no-ext-diff",
            "-z",
            allocation_base,
            "--",
        ).decode("utf-8")
        untracked_output = _git_bytes(
            repo,
            "ls-files",
            "--others",
            "--exclude-standard",
            "-z",
        ).decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("Git path output is not valid UTF-8") from error
    paths = {
        _require_repo_relative(path, "changed path")
        for path in (*tracked_output.split("\0"), *untracked_output.split("\0"))
        if path
    }
    return sorted(paths)


def check_allowed_paths(paths: list[str], allowlist: list[str]) -> list[str]:
    candidate_paths = _require_string_list(paths, "changed paths")
    patterns = [
        _require_repo_relative(pattern, "allowed path")
        for pattern in _require_string_list(allowlist, "allowed paths")
    ]
    return sorted(
        path
        for path in candidate_paths
        if not _is_repo_relative(path)
        or not any(fnmatch.fnmatchcase(path, pattern) for pattern in patterns)
    )


def enforce_lane_paths(data: dict[str, object], issue: str) -> list[str]:
    validate_manifest(data)
    candidate = deepcopy(data)
    lane = _lane(candidate, issue)
    paths = changed_paths(
        Path(lane["worktree"]),
        lane["allocationBaseSha"],
    )
    disallowed = check_allowed_paths(paths, lane["allowedPaths"])
    if not disallowed:
        return []
    if lane["laneState"] in {"merged", "abandoned"}:
        _fail("cannot block a terminal lane for a path ownership violation")
    lane["laneState"] = "blocked"
    lane["blocker"] = "disallowed paths: " + ", ".join(disallowed)
    lane["nextAction"] = "restore path ownership before continuing"
    _touch(candidate)
    _commit_candidate(data, candidate)
    return disallowed


def _index_tree_sha(repo: Path) -> str:
    index: dict[bytes, object] = {}
    for record in _git_bytes(repo, "ls-files", "--stage", "-z").split(b"\0"):
        if not record:
            continue
        try:
            metadata, path = record.split(b"\t", 1)
            mode, object_hex, stage = metadata.split(b" ")
            object_id = bytes.fromhex(object_hex.decode("ascii"))
        except (ValueError, UnicodeError) as error:
            raise ValueError("Git index entry is malformed") from error
        if stage != b"0":
            _fail("cannot snapshot an index with unmerged entries")
        if len(object_id) != 20:
            _fail("Git index entry has an invalid object ID")
        components = path.split(b"/")
        if any(not component for component in components):
            _fail("Git index entry has an invalid path")
        node = index
        for component in components[:-1]:
            child = node.setdefault(component, {})
            if not isinstance(child, dict):
                _fail("Git index contains a file/directory collision")
            node = child
        name = components[-1]
        if name in node:
            _fail("Git index contains duplicate paths")
        node[name] = (mode, object_id)

    def tree_digest(node: dict[bytes, object]) -> bytes:
        entries: list[tuple[bytes, bytes]] = []
        for name, value in node.items():
            if isinstance(value, dict):
                mode = b"40000"
                object_id = tree_digest(value)
                sort_key = name + b"/"
            else:
                mode, object_id = value
                sort_key = name
            entries.append(
                (sort_key, mode + b" " + name + b"\0" + object_id)
            )
        payload = b"".join(entry for _, entry in sorted(entries))
        header = b"tree " + str(len(payload)).encode("ascii") + b"\0"
        return hashlib.sha1(header + payload, usedforsecurity=False).digest()

    return tree_digest(index).hex()


def root_snapshot(repo: Path) -> dict[str, object]:
    head_sha = git_text(repo, "rev-parse", "HEAD")
    index_tree_sha = _index_tree_sha(repo)
    _require_sha(head_sha, "root snapshot headSha")
    _require_sha(index_tree_sha, "root snapshot indexTreeSha")
    tracked_diff = _git_bytes(
        repo,
        "diff",
        "--binary",
        "--no-ext-diff",
        "HEAD",
        "--",
    )
    try:
        untracked_paths = _git_bytes(
            repo,
            "ls-files",
            "--others",
            "--exclude-standard",
            "-z",
        ).decode("utf-8").split("\0")
    except UnicodeDecodeError as error:
        raise ValueError("Git path output is not valid UTF-8") from error
    untracked: list[dict[str, str]] = []
    repository = repo.resolve(strict=True)
    for relative_path in sorted(path for path in untracked_paths if path):
        _require_repo_relative(relative_path, "untracked path")
        path = repository / relative_path
        try:
            info = path.lstat()
            digest = hashlib.sha256()
            digest.update(relative_path.encode("utf-8"))
            digest.update(b"\0")
            if stat.S_ISLNK(info.st_mode):
                digest.update(b"symlink\0")
                digest.update(os.readlink(os.fsencode(path)))
            elif stat.S_ISREG(info.st_mode):
                digest.update(b"regular\0")
                file_fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
                try:
                    opened = os.fstat(file_fd)
                    if (
                        not stat.S_ISREG(opened.st_mode)
                        or (info.st_dev, info.st_ino)
                        != (opened.st_dev, opened.st_ino)
                    ):
                        _fail(
                            "untracked path changed while hashing: "
                            + relative_path
                        )
                    while chunk := os.read(file_fd, 1024 * 1024):
                        digest.update(chunk)
                finally:
                    os.close(file_fd)
            else:
                _fail(f"untracked path has unsupported file kind: {relative_path}")
        except OSError as error:
            raise ValueError(
                f"cannot hash untracked path {relative_path}: {error}"
            ) from error
        untracked.append(
            {"path": relative_path, "sha256": digest.hexdigest()}
        )
    return {
        "headSha": head_sha,
        "indexTreeSha": index_tree_sha,
        "trackedDiffSha256": hashlib.sha256(tracked_diff).hexdigest(),
        "untracked": untracked,
    }




def ensure_state_dir(path: Path) -> None:
    parent = path.parent
    try:
        parent_info = parent.stat()
    except OSError as error:
        raise ValueError(f"Git common directory parent does not exist: {parent}") from error
    if not stat.S_ISDIR(parent_info.st_mode):
        _fail(f"Git common directory parent is not a directory: {parent}")

    created = False
    try:
        info = path.lstat()
    except FileNotFoundError:
        try:
            path.mkdir(mode=0o700)
            created = True
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

    if created:
        directory_fd = os.open(
            path,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
        try:
            opened = os.fstat(directory_fd)
            if (info.st_dev, info.st_ino) != (opened.st_dev, opened.st_ino):
                _fail(f"new state directory changed before mode verification: {path}")
            os.fchmod(directory_fd, 0o700)
            info = os.fstat(directory_fd)
        finally:
            os.close(directory_fd)

    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        _fail(f"state directory must be a real directory: {path}")
    if stat.S_IMODE(info.st_mode) != 0o700:
        _fail(f"state directory must have mode 0700: {path}")


@contextmanager
def _open_state_dir(path: Path, *, create: bool = True) -> Iterator[int]:
    if create:
        ensure_state_dir(path)
    try:
        before = path.lstat()
    except OSError as error:
        raise ValueError(
            f"cannot inspect state directory {path}: {error}"
        ) from error
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        directory_fd = os.open(path, flags)
    except OSError as error:
        raise ValueError(f"cannot securely open state directory {path}: {error}") from error
    try:
        opened = os.fstat(directory_fd)
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            _fail(f"state directory changed while opening: {path}")
        if not stat.S_ISDIR(opened.st_mode) or stat.S_IMODE(opened.st_mode) != 0o700:
            _fail(f"opened state directory must be a mode 0700 directory: {path}")
        yield directory_fd
    finally:
        os.close(directory_fd)


def _load_json_object_at(
    directory_fd: int,
    name: str,
    source: str,
) -> dict[str, object]:
    try:
        file_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
        with os.fdopen(file_fd, encoding="utf-8") as source_file:
            text = source_file.read()
    except (OSError, UnicodeError) as error:
        raise ValueError(f"cannot load JSON from {source}: {error}") from error
    return _decode_json_object(text, source)


def _load_json_object(path: Path) -> dict[str, object]:
    with _open_state_dir(path.parent) as directory_fd:
        return _load_json_object_at(directory_fd, path.name, str(path))


def _load_manifest_at(directory_fd: int, name: str, source: str) -> dict[str, object]:
    data = _load_json_object_at(directory_fd, name, source)
    validate_manifest(data)
    return data


def load_manifest(path: Path) -> dict[str, object]:
    with _open_state_dir(path.parent) as directory_fd:
        return _load_manifest_at(directory_fd, path.name, str(path))

def load_manifest_readonly(path: Path) -> dict[str, object]:
    with _open_state_dir(path.parent, create=False) as directory_fd:
        return _load_manifest_at(directory_fd, path.name, str(path))



def _write_temporary_json(directory_fd: int, data: dict[str, object]) -> str:
    for _ in range(128):
        temporary_name = f".lane-state-{secrets.token_hex(16)}.tmp"
        try:

            temporary_fd = os.open(
                temporary_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=directory_fd,
            )
        except FileExistsError:
            continue
        try:
            with os.fdopen(temporary_fd, mode="w", encoding="utf-8") as temporary:
                json.dump(data, temporary, sort_keys=True, separators=(",", ":"))
                temporary.write("\n")
                temporary.flush()
                os.fsync(temporary.fileno())
        except BaseException:
            os.unlink(temporary_name, dir_fd=directory_fd)
            raise
        return temporary_name
    raise OSError("cannot allocate a unique state-directory temporary file")


def _atomic_json_write_at(
    directory_fd: int,
    name: str,
    data: dict[str, object],
) -> None:
    temporary_name = _write_temporary_json(directory_fd, data)
    try:
        os.replace(
            temporary_name,
            name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
    finally:
        try:
            os.unlink(temporary_name, dir_fd=directory_fd)
        except FileNotFoundError:
            pass


def _atomic_json_create_at(
    directory_fd: int,
    name: str,
    data: dict[str, object],
) -> bool:
    temporary_name = _write_temporary_json(directory_fd, data)
    try:
        try:
            os.link(
                temporary_name,
                name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
                follow_symlinks=False,
            )
        except FileExistsError:
            return False
        return True
    finally:
        os.unlink(temporary_name, dir_fd=directory_fd)


def _atomic_json_write(path: Path, data: dict[str, object]) -> None:
    with _open_state_dir(path.parent) as directory_fd:
        _atomic_json_write_at(directory_fd, path.name, data)

def _atomic_json_create(path: Path, data: dict[str, object]) -> bool:
    with _open_state_dir(path.parent) as directory_fd:
        return _atomic_json_create_at(directory_fd, path.name, data)


def atomic_write(path: Path, data: dict[str, object]) -> None:
    validate_manifest(data)
    _atomic_json_write(path, data)


def initialize_manifest(path: Path) -> tuple[dict[str, object], bool]:
    data = empty_manifest()
    validate_manifest(data)
    with _open_state_dir(path.parent) as directory_fd:
        if _atomic_json_create_at(directory_fd, path.name, data):
            return data, True
        return _load_manifest_at(directory_fd, path.name, str(path)), False


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

def _rebind_observation_base(
    observation: dict[str, object],
    current_base_sha: str,
) -> None:
    if observation["baseSha"] is not None:
        observation["baseSha"] = current_base_sha


def _apply_heads(
    lane: dict[str, object],
    *,
    head_sha: str,
    current_base_sha: str,
) -> None:
    _require_sha(head_sha, "lane head SHA")
    _require_sha(current_base_sha, "lane current base SHA")
    head_changed = head_sha != lane["headSha"]
    base_changed = current_base_sha != lane["currentBaseSha"]
    if not head_changed and not base_changed:
        return

    lane["headSha"] = head_sha
    lane["currentBaseSha"] = current_base_sha
    if base_changed:
        for observation in lane["gates"].values():
            _rebind_observation_base(observation, current_base_sha)
        for gate_name in BASE_BOUND:
            _stale_observation(lane["gates"][gate_name])
        native = lane["gates"]["native_lab"]
        if native["baseSensitive"]:
            _stale_observation(native)
    if head_changed:
        for gate_name in HEAD_BOUND:
            _stale_observation(lane["gates"][gate_name])
        lane["implementationState"] = "stale"
    lane["mergeabilityState"] = "stale"


def update_heads(
    data: dict[str, object],
    issue: str,
    *,
    head_sha: str,
    current_base_sha: str,
) -> None:
    validate_manifest(data)
    candidate = deepcopy(data)
    _apply_heads(
        _lane(candidate, issue),
        head_sha=head_sha,
        current_base_sha=current_base_sha,
    )
    _touch(candidate)
    _commit_candidate(data, candidate)


def invalidate_dependents(
    data: dict[str, object],
    upstream_issue: str,
    changed_paths: list[str],
) -> list[str]:
    validate_manifest(data)
    if upstream_issue not in data["lanes"]:
        _fail(f"unknown upstream lane: {upstream_issue}")
    paths = _require_string_list(changed_paths, "changed paths")
    candidate = deepcopy(data)
    lanes = candidate["lanes"]
    pending = [int(upstream_issue)]
    visited = {int(upstream_issue)}
    invalidated: list[str] = []
    ordered_lanes = sorted(
        lanes.items(),
        key=lambda item: (item[1]["integrationOrder"], int(item[0])),
    )
    while pending:
        current = pending.pop(0)
        for issue, lane in ordered_lanes:
            if int(issue) in visited or current not in lane["dependsOn"]:
                continue
            visited.add(int(issue))
            pending.append(int(issue))
            if not any(
                fnmatch.fnmatchcase(changed_path, pattern)
                for changed_path in paths
                for pattern in lane["sharedContractPaths"]
            ):
                continue
            for gate_name in DOWNSTREAM_BOUND:
                _stale_observation(lane["gates"][gate_name])
            lane["mergeabilityState"] = "stale"
            if lane["laneState"] == "ready_for_adam":
                lane["laneState"] = "reviewing"
            lane["nextAction"] = (
                f"revalidate shared contract after issue {upstream_issue}"
            )
            invalidated.append(issue)
    if invalidated:
        _touch(candidate)
        _commit_candidate(data, candidate)
    return invalidated


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


def _validate_base_evidence(
    data: dict[str, object],
    issue: str,
    gate: str,
    observation: dict[str, object],
) -> None:
    if gate not in BASE_BOUND and gate != "native_lab":
        _fail(f"gate {gate} does not accept base integration evidence")
    lane = _lane(data, issue)
    _validate_new_observation(
        lane,
        observation,
        f"gate {gate}",
        _states_for_gate(gate),
    )
    if gate == "native_lab" and not observation["baseSensitive"]:
        _fail("native_lab base evidence must declare baseSensitive")

    artifact_uri = _require_nonempty_string(
        observation["artifact"],
        f"gate {gate}.artifact",
    )
    parsed = urlparse(artifact_uri)
    if (
        parsed.scheme != "file"
        or parsed.netloc not in {"", "localhost"}
        or parsed.query
        or parsed.fragment
    ):
        _fail(f"gate {gate}.artifact must be a local file:// URI")
    try:
        artifact_path = Path(unquote(parsed.path)).resolve(strict=True)
        artifact = _decode_json_object(
            artifact_path.read_text(encoding="utf-8"),
            str(artifact_path),
        )
    except (OSError, UnicodeError) as error:
        raise ValueError(f"cannot read base evidence artifact: {error}") from error

    expected_kind = (
        "github_review"
        if gate in {"coderabbit", "independent_review"}
        else "synthetic_merge"
    )
    artifact_keys = (
        _GITHUB_REVIEW_ARTIFACT_KEYS
        if expected_kind == "github_review"
        else _BASE_ARTIFACT_KEYS
    )
    _require_exact_keys(artifact, artifact_keys, "base evidence artifact")
    _require_schema_version(
        artifact["schemaVersion"],
        "base evidence artifact.schemaVersion",
    )
    if artifact["kind"] != expected_kind:
        _fail(f"gate {gate} requires {expected_kind} base evidence")
    if expected_kind == "github_review":
        pr = lane["pr"]
        if pr["number"] is None:
            _fail(f"gate {gate} requires a recorded pull request")
        _require_enum(
            artifact["reviewGate"],
            {"coderabbit", "independent_review"},
            "base evidence artifact.reviewGate",
        )
        _require_int(
            artifact["prNumber"],
            "base evidence artifact.prNumber",
            minimum=1,
        )
        _require_nonempty_string(
            artifact["prUrl"],
            "base evidence artifact.prUrl",
        )
        if artifact["reviewGate"] != gate:
            _fail("base evidence artifact.reviewGate does not match the gate")
        if artifact["prNumber"] != pr["number"]:
            _fail("base evidence artifact.prNumber does not match the lane PR")
        if artifact["prUrl"] != pr["url"]:
            _fail("base evidence artifact.prUrl does not match the lane PR")
    if artifact["headSha"] != lane["headSha"]:
        _fail("base evidence artifact headSha does not match the lane head")
    if artifact["currentBaseSha"] != lane["currentBaseSha"]:
        _fail("base evidence artifact currentBaseSha does not match the lane base")
    _require_sha(artifact["headSha"], "base evidence artifact.headSha")
    _require_sha(
        artifact["currentBaseSha"],
        "base evidence artifact.currentBaseSha",
    )
    _require_nonempty_string(
        artifact["integrationCommand"],
        "base evidence artifact.integrationCommand",
    )
    _require_nonempty_string(
        artifact["gateCommand"],
        "base evidence artifact.gateCommand",
    )
    if type(artifact["integrationExitCode"]) is not int or artifact["integrationExitCode"] != 0:
        _fail("base evidence artifact.integrationExitCode must be 0")
    if type(artifact["gateExitCode"]) is not int or artifact["gateExitCode"] != 0:
        _fail("base evidence artifact.gateExitCode must be 0")
    raw_uri = _require_nonempty_string(
        artifact["rawEvidenceUri"],
        "base evidence artifact.rawEvidenceUri",
    )
    if not urlparse(raw_uri).scheme:
        _fail("base evidence artifact.rawEvidenceUri must be a URI")
    _require_utc(artifact["observedAt"], "base evidence artifact.observedAt")


def validate_base_evidence(
    data: dict[str, object],
    issue: str,
    gate: str,
    observation: dict[str, object],
) -> None:
    validate_manifest(data)
    _validate_base_evidence(data, issue, gate, observation)


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
    successful = validated["state"] in {"passed", "mergeable"}
    requires_base_evidence = (
        gate in BASE_BOUND
        or gate == "native_lab" and validated["baseSensitive"] is True
    )
    if successful and requires_base_evidence:
        validate_base_evidence(candidate, issue, gate, observation_copy)
    lane["gates"][gate] = observation_copy
    if gate == "mergeability":
        lane["mergeabilityState"] = observation_copy["state"]
    _touch(candidate)
    _commit_candidate(data, candidate)


def record_status(data: dict[str, object], issue: str, status: dict[str, object]) -> None:
    validate_manifest(data)
    if not isinstance(status, dict) or not status:
        _fail("status must be a non-empty object")
    allowed = {
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
    for key, value in status.items():
        lane[key] = deepcopy(value)
    _touch(candidate)
    _commit_candidate(data, candidate)


def acquire_aggregate_gate(
    data: dict[str, object],
    issue: str,
    acquired_at: str,
) -> None:
    validate_manifest(data)
    _require_utc(acquired_at, "aggregate gate acquisition time")
    candidate = deepcopy(data)
    _lane(candidate, issue)
    gate = candidate["aggregateGate"]
    holder = gate["holder"]
    queue = gate["queue"]
    if holder == issue:
        raise TerminalRejection(f"lane {issue} already holds the aggregate gate")
    if holder is not None:
        if issue not in queue:
            queue.append(issue)
            _touch(candidate)
            _commit_candidate(data, candidate)
        raise RetriableConflict(f"aggregate gate is held by lane {holder}")
    if queue and queue[0] != issue:
        raise TerminalRejection(
            f"lane {issue} cannot acquire before queued lane {queue[0]}"
        )
    if queue:
        queue.pop(0)
    gate["holder"] = issue
    gate["acquiredAt"] = acquired_at
    _touch(candidate)
    _commit_candidate(data, candidate)


def release_aggregate_gate(data: dict[str, object], issue: str) -> None:
    validate_manifest(data)
    candidate = deepcopy(data)
    _lane(candidate, issue)
    gate = candidate["aggregateGate"]
    if gate["holder"] != issue:
        raise TerminalRejection(f"lane {issue} does not hold the aggregate gate")
    gate["holder"] = None
    gate["acquiredAt"] = None
    _touch(candidate)
    _commit_candidate(data, candidate)


def _strictly_new_updated_at(previous: str) -> str:
    previous_time = datetime.fromisoformat(_require_utc(previous, "updatedAt"))
    current_time = datetime.now(timezone.utc)
    if current_time <= previous_time:
        current_time = previous_time + timedelta(microseconds=1)
    return current_time.isoformat()


def _acquire_lock(directory_fd: int, lock_name: str) -> int:
    try:
        lock_fd = os.open(
            lock_name,
            os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory_fd,
        )
    except OSError as error:
        raise TerminalRejection(f"cannot open manifest lock: {error}") from error
    deadline = time.monotonic() + LOCK_TIMEOUT_SECONDS
    while True:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return lock_fd
        except BlockingIOError as error:
            if time.monotonic() >= deadline:
                os.close(lock_fd)
                raise RetriableConflict(
                    "manifest lock remained contended for two seconds"
                ) from error
            time.sleep(min(0.01, max(0.0, deadline - time.monotonic())))
        except OSError as error:
            os.close(lock_fd)
            raise TerminalRejection(f"cannot lock manifest: {error}") from error


def _persist_mutation(
    directory_fd: int,
    name: str,
    data: dict[str, object],
    previous_updated_at: str,
) -> None:
    data["updatedAt"] = _strictly_new_updated_at(previous_updated_at)
    validate_manifest(data)
    _atomic_json_write_at(directory_fd, name, data)


def _revalidate_passed_base_evidence(data: dict[str, object]) -> None:
    for issue, lane in data["lanes"].items():
        for gate in BASE_BOUND:
            observation = lane["gates"][gate]
            if observation["state"] in {"passed", "mergeable"}:
                _validate_base_evidence(data, issue, gate, observation)
        native_observation = lane["gates"]["native_lab"]
        if (
            native_observation["state"] == "passed"
            and native_observation["baseSensitive"]
        ):
            _validate_base_evidence(
                data,
                issue,
                "native_lab",
                native_observation,
            )


def _mutate_manifest(
    path: Path,
    expected_updated_at: str,
    mutation: Callable[[dict[str, object]], None],
) -> dict[str, object]:
    _require_utc(expected_updated_at, "expected updatedAt")
    with _open_state_dir(path.parent) as directory_fd:
        lock_fd = _acquire_lock(directory_fd, f"{path.name}.lock")
        try:
            try:
                current = _load_manifest_at(directory_fd, path.name, str(path))
                if current["updatedAt"] != expected_updated_at:
                    raise RetriableConflict("manifest updatedAt is stale")
                _revalidate_passed_base_evidence(current)
                candidate = deepcopy(current)
                try:
                    mutation(candidate)
                except RetriableConflict:
                    if candidate != current:
                        _persist_mutation(
                            directory_fd,
                            path.name,
                            candidate,
                            current["updatedAt"],
                        )
                    raise
                except TerminalRejection:
                    raise
                except (OSError, ValueError) as error:
                    raise TerminalRejection(str(error)) from error
                _persist_mutation(
                    directory_fd,
                    path.name,
                    candidate,
                    current["updatedAt"],
                )
                return candidate
            except (RetriableConflict, TerminalRejection):
                raise
            except (OSError, ValueError) as error:
                raise TerminalRejection(str(error)) from error
        finally:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)


def mutate_manifest(
    path: Path,
    expected_updated_at: str,
    mutation: Callable[[dict[str, object]], None],
) -> dict[str, object]:
    try:
        return _mutate_manifest(path, expected_updated_at, mutation)
    except (RetriableConflict, TerminalRejection):
        raise
    except (OSError, ValueError) as error:
        raise TerminalRejection(str(error)) from error


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
    if owner["allowedPaths"] != _STAGE1_ALLOWED_PATHS:
        _fail("feature owner.allowedPaths must match the exact Stage 1 ownership set")
    _require_enum(
        owner["state"],
        {"active", "blocked", "released"},
        "feature owner.state",
    )
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
    _require_enum(
        state,
        {"active", "blocked", "released"},
        "feature owner state",
    )
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
    lane = _lane(candidate, issue)
    changed = lane["pr"] != {"number": number, "url": url}
    lane["pr"] = {"number": number, "url": url}
    if changed:
        for gate in ("coderabbit", "independent_review"):
            _stale_observation(lane["gates"][gate])
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
    artifact_uri = _require_nonempty_string(
        artifact,
        "root snapshot artifact",
    )
    parsed = urlparse(artifact_uri)
    if (
        parsed.scheme != "file"
        or parsed.netloc not in {"", "localhost"}
        or parsed.query
        or parsed.fragment
    ):
        _fail("root snapshot artifact must be a local file:// URI")
    try:
        artifact_path = Path(unquote(parsed.path)).resolve(strict=True)
        artifact_bytes = artifact_path.read_bytes()
    except OSError as error:
        raise ValueError(f"cannot read root snapshot artifact: {error}") from error
    candidate = deepcopy(data)
    candidate["rootSafety"][slot] = {
        "artifact": artifact_uri,
        "sha256": hashlib.sha256(artifact_bytes).hexdigest(),
    }
    _touch(candidate)
    _commit_candidate(data, candidate)


class _ClassifiedArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise TerminalRejection(message)


def _add_manifest_mutation_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--expected-updated-at", required=True)


def _read_cli_json(path: Path) -> dict[str, object]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise ValueError(f"cannot read JSON from {path}: {error}") from error
    return _decode_json_object(text, str(path))


def _print_json(value: dict[str, object]) -> None:
    print(json.dumps(value, sort_keys=True, separators=(",", ":")))


def _print_terminal(error: BaseException) -> int:
    _print_json(
        {
            "ok": False,
            "classification": "terminal_rejection",
            "reason": str(error),
        }
    )
    return 2


def main(argv: Sequence[str] | None = None) -> int:
    parser = _ClassifiedArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init")
    init_parser.add_argument("--git-common-dir", type=Path, required=True)

    show_parser = subparsers.add_parser("show")
    show_parser.add_argument("--manifest", type=Path, required=True)

    allocate_parser = subparsers.add_parser("allocate")
    _add_manifest_mutation_arguments(allocate_parser)
    allocate_parser.add_argument("--lane-json", type=Path, required=True)

    transition_parser = subparsers.add_parser("transition")
    _add_manifest_mutation_arguments(transition_parser)
    transition_parser.add_argument("--issue", required=True)
    transition_parser.add_argument("--state", required=True)

    transfer_parser = subparsers.add_parser("transfer-owner")
    _add_manifest_mutation_arguments(transfer_parser)
    transfer_parser.add_argument("--issue", required=True)
    transfer_parser.add_argument("--owner", required=True)
    transfer_parser.add_argument("--role", required=True)

    feature_record_parser = subparsers.add_parser("record-feature-owner")
    feature_record_parser.add_argument(
        "--git-common-dir",
        type=Path,
        required=True,
    )
    feature_record_parser.add_argument("--owner", required=True)
    feature_record_parser.add_argument("--role", required=True)
    feature_record_parser.add_argument("--worktree", required=True)
    feature_record_parser.add_argument("--assigned-at", required=True)
    feature_record_parser.add_argument(
        "--allow",
        action="append",
        required=True,
    )

    invalidate_parser = subparsers.add_parser("invalidate-dependents")
    _add_manifest_mutation_arguments(invalidate_parser)
    invalidate_parser.add_argument("--upstream", required=True)
    invalidate_parser.add_argument(
        "--changed-path",
        action="append",
        required=True,
        dest="changed_paths",
    )

    feature_state_parser = subparsers.add_parser("feature-owner-state")
    feature_state_parser.add_argument(
        "--git-common-dir",
        type=Path,
        required=True,
    )
    feature_state_parser.add_argument(
        "--state",
        choices=("active", "blocked", "released"),
        required=True,
    )

    feature_transfer_parser = subparsers.add_parser(
        "transfer-feature-owner"
    )
    feature_transfer_parser.add_argument(
        "--git-common-dir",
        type=Path,
        required=True,
    )
    feature_transfer_parser.add_argument("--owner", required=True)
    feature_transfer_parser.add_argument("--role", required=True)
    feature_transfer_parser.add_argument("--assigned-at", required=True)

    heartbeat_parser = subparsers.add_parser("heartbeat")
    _add_manifest_mutation_arguments(heartbeat_parser)
    heartbeat_parser.add_argument("--issue", required=True)
    heartbeat_parser.add_argument("--owner", required=True)
    heartbeat_parser.add_argument("--at", required=True)
    heartbeat_parser.add_argument("--expires-at", required=True)

    update_parser = subparsers.add_parser("update-heads")
    _add_manifest_mutation_arguments(update_parser)
    update_parser.add_argument("--issue", required=True)
    update_parser.add_argument("--head", required=True)
    update_parser.add_argument("--current-base", required=True)

    red_parser = subparsers.add_parser("record-red")
    _add_manifest_mutation_arguments(red_parser)
    red_parser.add_argument("--issue", required=True)
    red_parser.add_argument("--observation-json", type=Path, required=True)

    observation_parser = subparsers.add_parser("record-observation")
    _add_manifest_mutation_arguments(observation_parser)
    observation_parser.add_argument("--issue", required=True)
    observation_parser.add_argument("--gate", required=True)
    observation_parser.add_argument(
        "--observation-json",
        type=Path,
        required=True,
    )

    status_parser = subparsers.add_parser("record-status")
    _add_manifest_mutation_arguments(status_parser)
    status_parser.add_argument("--issue", required=True)
    status_parser.add_argument("--status-json", type=Path, required=True)

    pr_parser = subparsers.add_parser("record-pr")
    _add_manifest_mutation_arguments(pr_parser)
    pr_parser.add_argument("--issue", required=True)
    pr_parser.add_argument("--number", type=int, required=True)
    pr_parser.add_argument("--url", required=True)

    remote_parser = subparsers.add_parser("record-remote")
    _add_manifest_mutation_arguments(remote_parser)
    remote_parser.add_argument("--issue", required=True)
    remote_parser.add_argument("--sha", required=True)

    root_parser = subparsers.add_parser("record-root-snapshot")
    _add_manifest_mutation_arguments(root_parser)
    root_parser.add_argument("--slot", required=True)
    root_parser.add_argument("--artifact", required=True)

    acquire_parser = subparsers.add_parser("acquire-gate")
    _add_manifest_mutation_arguments(acquire_parser)
    acquire_parser.add_argument("--issue", required=True)
    acquire_parser.add_argument("--at", required=True)

    release_parser = subparsers.add_parser("release-gate")
    _add_manifest_mutation_arguments(release_parser)
    release_parser.add_argument("--issue", required=True)

    check_parser = subparsers.add_parser("check-paths")
    check_parser.add_argument("--repo", type=Path, required=True)
    check_parser.add_argument("--allocation-base", required=True)
    check_parser.add_argument("--allow", action="append", required=True)

    snapshot_parser = subparsers.add_parser("snapshot-root")
    snapshot_parser.add_argument("--repo", type=Path, required=True)

    try:
        args = parser.parse_args(argv)
    except TerminalRejection as error:
        return _print_terminal(error)

    try:
        if args.command == "init":
            path = args.git_common_dir / "omp" / "lanes.json"
            manifest, created = initialize_manifest(path)
            _print_json({**manifest, "created": created})
            return 0
        if args.command == "show":
            _print_json(load_manifest_readonly(args.manifest))
            return 0
        if args.command == "check-paths":
            paths = changed_paths(args.repo, args.allocation_base)
            disallowed = check_allowed_paths(paths, args.allow)
            if disallowed:
                raise TerminalRejection(
                    "disallowed paths: " + ", ".join(disallowed)
                )
            _print_json({"ok": True, "paths": paths, "disallowed": []})
            return 0
        if args.command == "snapshot-root":
            _print_json(root_snapshot(args.repo))
            return 0

        feature_owner_path = (
            args.git_common_dir / "omp" / "stage1-owner.json"
            if hasattr(args, "git_common_dir")
            else None
        )
        if args.command == "record-feature-owner":
            record_feature_owner(
                feature_owner_path,
                {
                    "schemaVersion": SCHEMA_VERSION,
                    "owner": args.owner,
                    "role": args.role,
                    "worktree": args.worktree,
                    "allowedPaths": args.allow,
                    "state": "active",
                    "assignedAt": args.assigned_at,
                    "transferCount": 0,
                    "evidenceInvalidatedAt": None,
                },
            )
            _print_json({"ok": True, "state": "active"})
            return 0
        if args.command == "feature-owner-state":
            set_feature_owner_state(
                feature_owner_path,
                args.state,
            )
            _print_json({"ok": True, "state": args.state})
            return 0
        if args.command == "transfer-feature-owner":
            transfer_feature_owner(
                feature_owner_path,
                args.owner,
                args.role,
                args.assigned_at,
            )
            _print_json({"ok": True, "state": "active"})
            return 0

        command_fields: dict[str, object] = {}

        def mutation(data: dict[str, object]) -> None:
            if args.command == "allocate":
                allocate_lane(data, _read_cli_json(args.lane_json))
            elif args.command == "transition":
                transition_lane(data, args.issue, args.state)
            elif args.command == "transfer-owner":
                transfer_owner(data, args.issue, args.owner, args.role)
            elif args.command == "invalidate-dependents":
                command_fields["invalidated"] = invalidate_dependents(
                    data,
                    args.upstream,
                    args.changed_paths,
                )
            elif args.command == "heartbeat":
                heartbeat_lane(
                    data,
                    args.issue,
                    args.owner,
                    args.at,
                    args.expires_at,
                )
            elif args.command == "update-heads":
                update_heads(
                    data,
                    args.issue,
                    head_sha=args.head,
                    current_base_sha=args.current_base,
                )
            elif args.command == "record-red":
                record_red(
                    data,
                    args.issue,
                    _read_cli_json(args.observation_json),
                )
            elif args.command == "record-observation":
                record_observation(
                    data,
                    args.issue,
                    args.gate,
                    _read_cli_json(args.observation_json),
                )
            elif args.command == "record-status":
                record_status(
                    data,
                    args.issue,
                    _read_cli_json(args.status_json),
                )
            elif args.command == "record-pr":
                record_pr(data, args.issue, args.number, args.url)
            elif args.command == "record-remote":
                record_remote(data, args.issue, args.sha)
            elif args.command == "record-root-snapshot":
                record_root_snapshot(data, args.slot, args.artifact)
            elif args.command == "acquire-gate":
                acquire_aggregate_gate(data, args.issue, args.at)
            elif args.command == "release-gate":
                release_aggregate_gate(data, args.issue)
            else:
                _fail(f"unknown command: {args.command}")

        updated = mutate_manifest(
            args.manifest,
            args.expected_updated_at,
            mutation,
        )
    except RetriableConflict as error:
        _print_json(
            {
                "ok": False,
                "classification": "retriable_conflict",
                "reason": str(error),
            }
        )
        return 75
    except (TerminalRejection, OSError, ValueError) as error:
        return _print_terminal(error)

    if args.command in {"acquire-gate", "release-gate"}:
        command_fields["aggregateGate"] = updated["aggregateGate"]
    _print_json(
        {
            "ok": True,
            "updatedAt": updated["updatedAt"],
            **command_fields,
        }
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
