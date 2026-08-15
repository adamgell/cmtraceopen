from __future__ import annotations

import argparse
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import time
from typing import Callable, Iterator, NoReturn, Protocol, Sequence
from urllib.parse import unquote, urlparse

FEATURE_OWNER_STATES = ("active", "blocked", "released")

SCHEMA_VERSION = 2
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
INDEPENDENT_REVIEW_GATE_STATES = {
    "ci": "passed",
    "coderabbit": "passed",
    "charter_review": "passed",
    "contract_conformance": "passed",
}
CODERABBIT_BOT_LOGINS = frozenset({
    "coderabbitai",
    "coderabbitai[bot]",
})
NATIVE_STATES = GATE_STATES | {"not_required"}
NATIVE_REQUIREMENTS = {"required", "not_required"}
DISPATCH_ROLES = {
    "code-review",
    "coder",
    "reducer-adversary",
    "reducer-contract",
    "reducer-integration",
    "tech-writer",
    "ui-design",
}
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
GIT_TIMEOUT_SECONDS = 30.0
ARTIFACT_HASH_CHUNK_SIZE = 1024 * 1024
LOCK_TIMEOUT_SECONDS = 2.0
PR_URL_PREFIX = "https://github.com/adamgell/cmtraceopen/pull/"
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


class RetriableConflict(RuntimeError):
    pass


class TerminalRejection(RuntimeError):
    pass

class UpdateDigest(Protocol):
    def update(self, data: bytes, /) -> object: ...

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
    "worktreeIdentity",
    "gitCommonDir",
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
    "redClassification",
    "baseSensitive",
}
_OBSERVATION_ARTIFACT_REF_KEYS = {"uri", "sha256"}
_WORKTREE_IDENTITY_KEYS = {"device", "inode"}
_REPO_CHECK_ARTIFACT_KEYS = {
    "schemaVersion",
    "kind",
    "outcome",
    "command",
    "worktree",
    "worktreeIdentity",
    "gitCommonDir",
    "branch",
    "headSha",
    "baseSha",
    "exitCode",
    "observedAt",
    "stdout",
    "stderr",
    "failureClassification",
    "error",
}
_RED_CLASSIFICATION_KEYS = {
    "kind",
    "artifactSha256",
    "focusedTest",
    "fixture",
    "expectedAssertion",
    "reviewedAt",
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
_ROOT_SAFETY_KEYS = {"stage1Before", "stage1After", "stage2Waves"}
_ROOT_ARTIFACT_KEYS = {"artifact", "sha256"}
_STAGE2_WAVE_KEYS = {
    "waveId",
    "laneBindings",
    "managedWorktreesSha256",
    "before",
    "after",
}
_STAGE2_LANE_BINDING_KEYS = {"allocationBaseSha", "worktree"}
_ROOT_SNAPSHOT_KEYS = {
    "headSha",
    "indexTreeSha",
    "trackedDiffSha256",
    "untracked",
    "filesystemSha256",
    "gitControlsSha256",
    "managedWorktreesSha256",
}
_WINDOWS_RESERVED_NAMES = {
    "aux",
    "con",
    "nul",
    "prn",
    "conin$",
    "conout$",
    "com¹",
    "com²",
    "com³",
    "lpt¹",
    "lpt²",
    "lpt³",
    *(f"com{index}" for index in range(1, 10)),
    *(f"lpt{index}" for index in range(1, 10)),
}
_SHA_PATTERN = re.compile(r"[0-9a-fA-F]{40}\Z")
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
_STAGE1_ALLOWED_PATHS = [
    ".omp/**",
    ".Clairvoyance/library.md",
    ".Clairvoyance/kickoff-prompt.md",
    ".Clairvoyance/staff/**",
    ".claude/skills/coderabbit-review-loop/**",
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
    "isDraft",
    "rawEvidenceSha256",
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


def _validate_independent_review_gate_states(
    value: object,
    label: str,
) -> None:
    if not isinstance(value, dict):
        _fail(f"{label} must be an object")
    _require_exact_keys(value, set(INDEPENDENT_REVIEW_GATE_STATES), label)
    for gate, expected_state in INDEPENDENT_REVIEW_GATE_STATES.items():
        if value[gate] != expected_state:
            _fail(f"{label}.{gate} must be exactly {expected_state}")


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


def _require_worktree_identity(
    value: object,
    label: str,
) -> dict[str, object]:
    if not isinstance(value, dict):
        _fail(f"{label} must be an object")
    _require_exact_keys(value, _WORKTREE_IDENTITY_KEYS, label)
    _require_int(value["device"], f"{label}.device")
    _require_int(value["inode"], f"{label}.inode")
    return value

def _require_enum(
    value: object,
    choices: Sequence[str] | set[str],
    label: str,
) -> str:
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

def _require_command(value: object, label: str) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(item, str) or not item for item in value)
    ):
        _fail(f"{label} must be a non-empty direct argv array")
    return value


def _read_hashed_json_uri(
    uri_value: object,
    sha256_value: object,
    label: str,
) -> dict[str, object]:
    uri = _require_nonempty_string(uri_value, f"{label}.uri")
    expected_sha256 = _require_sha256(sha256_value, f"{label}.sha256")
    parsed = urlparse(uri)
    if (
        parsed.scheme != "file"
        or parsed.netloc not in {"", "localhost"}
        or parsed.query
        or parsed.fragment
    ):
        _fail(f"{label}.uri must be a local file:// URI")
    path = Path(unquote(parsed.path))
    if not path.is_absolute():
        _fail(f"{label}.uri must identify an absolute path")
    try:
        expected = path.lstat()
        if not stat.S_ISREG(expected.st_mode):
            _fail(f"{label}.uri must identify a regular file")
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            opened = os.fstat(descriptor)
            if _stable_stat_identity(opened) != _stable_stat_identity(expected):
                _fail(f"{label} changed while opening")
            digest = hashlib.sha256()
            chunks: list[bytes] = []
            while chunk := os.read(descriptor, ARTIFACT_HASH_CHUNK_SIZE):
                digest.update(chunk)
                chunks.append(chunk)
            if _stable_stat_identity(os.fstat(descriptor)) != _stable_stat_identity(
                opened
            ):
                _fail(f"{label} changed while reading")
        finally:
            os.close(descriptor)
        if _stable_stat_identity(path.lstat()) != _stable_stat_identity(expected):
            _fail(f"{label} path changed while reading")
    except OSError as error:
        raise ValueError(f"cannot read {label}: {error}") from error
    if digest.hexdigest() != expected_sha256:
        _fail(f"{label}.sha256 does not match artifact content")
    try:
        text = b"".join(chunks).decode("utf-8")
    except UnicodeError as error:
        raise ValueError(f"{label} is not valid UTF-8") from error
    return _decode_json_object(text, uri)


def _read_observation_artifact(
    reference: object,
    label: str,
) -> dict[str, object]:
    if not isinstance(reference, dict):
        _fail(f"{label} must be a content-hashed artifact reference")
    _require_exact_keys(reference, _OBSERVATION_ARTIFACT_REF_KEYS, label)
    return _read_hashed_json_uri(
        reference["uri"],
        reference["sha256"],
        label,
    )


def _validate_repo_check_artifact(
    artifact: dict[str, object],
    observation: dict[str, object],
    label: str,
) -> None:
    _require_exact_keys(artifact, _REPO_CHECK_ARTIFACT_KEYS, label)
    _require_schema_version(artifact["schemaVersion"], f"{label}.schemaVersion")
    if artifact["kind"] != "repo_check":
        _fail(f"{label}.kind must be repo_check")
    _require_enum(
        artifact["outcome"],
        {
            "completed",
            "timed_out",
            "setup_failed",
            "spawn_failed",
            "containment_failed",
        },
        f"{label}.outcome",
    )
    classification = _require_enum(
        artifact["failureClassification"],
        {"success", "command_failure", "runner_failure"},
        f"{label}.failureClassification",
    )
    if classification == "runner_failure":
        _fail(
            f"{label} runner infrastructure failures are never RED, GREEN, "
            "or gate evidence"
        )
    command = _require_command(artifact["command"], f"{label}.command")
    worktree = _require_nonempty_string(
        artifact["worktree"],
        f"{label}.worktree",
    )
    if not Path(worktree).is_absolute():
        _fail(f"{label}.worktree must be absolute")
    _require_worktree_identity(
        artifact["worktreeIdentity"],
        f"{label}.worktreeIdentity",
    )
    git_common_dir = _require_nonempty_string(
        artifact["gitCommonDir"],
        f"{label}.gitCommonDir",
    )
    if not Path(git_common_dir).is_absolute():
        _fail(f"{label}.gitCommonDir must be absolute")
    _require_nonempty_string(artifact["branch"], f"{label}.branch")
    head_sha = _require_sha(artifact["headSha"], f"{label}.headSha")
    base_sha = _require_sha(artifact["baseSha"], f"{label}.baseSha")
    exit_code = artifact["exitCode"]
    if exit_code is not None and (
        isinstance(exit_code, bool) or not isinstance(exit_code, int)
    ):
        _fail(f"{label}.exitCode must be an integer or null")
    observed_at = _require_utc(artifact["observedAt"], f"{label}.observedAt")
    stdout = artifact["stdout"]
    stderr = artifact["stderr"]
    if not isinstance(stdout, str) or not isinstance(stderr, str):
        _fail(f"{label} output must be strings")
    _require_optional_string(artifact["error"], f"{label}.error")

    if command != observation["command"]:
        _fail(f"{label}.command does not match the observation command")
    if head_sha != observation["headSha"]:
        _fail(f"{label}.headSha does not match the observation head")
    if base_sha != observation["baseSha"]:
        _fail(f"{label}.baseSha does not match the observation base")
    if exit_code != observation["exitCode"]:
        _fail(f"{label}.exitCode does not match the observation exit")
    if observed_at != observation["observedAt"]:
        _fail(f"{label}.observedAt does not match the observation time")

    outcome = artifact["outcome"]
    error = artifact["error"]
    if classification == "success":
        if outcome != "completed" or exit_code != 0 or error is not None:
            _fail(f"{label} success classification is inconsistent")
    elif classification == "command_failure":
        if outcome != "completed" or exit_code in {None, 0} or error is not None:
            _fail(f"{label} command failure classification is inconsistent")


def _require_repo_check_lane_binding(
    artifact: dict[str, object],
    lane: dict[str, object],
    label: str,
) -> None:
    if artifact.get("kind") != "repo_check":
        return
    for field in (
        "worktree",
        "worktreeIdentity",
        "gitCommonDir",
        "branch",
    ):
        if artifact[field] != lane[field]:
            _fail(f"{label}.{field} does not match the allocated lane")


def _validate_red_classification(
    value: object,
    observation: dict[str, object],
    label: str,
) -> None:
    if not isinstance(value, dict):
        _fail(f"{label} must be an object")
    _require_exact_keys(value, _RED_CLASSIFICATION_KEYS, label)
    if value["kind"] != "main_reviewed_expected_assertion_failure":
        _fail(f"{label}.kind is invalid")
    reference = observation["artifact"]
    if (
        not isinstance(reference, dict)
        or value["artifactSha256"] != reference.get("sha256")
    ):
        _fail(f"{label}.artifactSha256 must bind the runner artifact")
    _require_sha256(value["artifactSha256"], f"{label}.artifactSha256")
    _require_optional_string(value["focusedTest"], f"{label}.focusedTest")
    _require_optional_string(value["fixture"], f"{label}.fixture")
    if value["focusedTest"] is None and value["fixture"] is None:
        _fail(f"{label} requires a focused test or fixture identity")
    _require_nonempty_string(
        value["expectedAssertion"],
        f"{label}.expectedAssertion",
    )
    reviewed_at = _require_utc(value["reviewedAt"], f"{label}.reviewedAt")
    observed_at = _require_utc(
        observation["observedAt"],
        f"{label} observation observedAt",
    )
    if datetime.fromisoformat(reviewed_at) < datetime.fromisoformat(observed_at):
        _fail(f"{label}.reviewedAt must not precede the runner observation")


def _is_coderabbit_login(value: object) -> bool:
    return (
        isinstance(value, str)
        and value.casefold() in CODERABBIT_BOT_LOGINS
    )


def _validate_coderabbit_raw_verdict(
    raw: dict[str, object],
    artifact: dict[str, object],
    label: str,
) -> None:
    _require_exact_keys(
        raw,
        {"pull_request", "summary", "unresolved_threads", "reviews"},
        label,
    )
    pull_request = raw["pull_request"]
    if not isinstance(pull_request, dict):
        _fail(f"{label}.pull_request must be an object")
    _require_exact_keys(
        pull_request,
        {
            "number",
            "url",
            "head_sha",
            "base_sha",
            "is_draft",
            "review_decision",
        },
        f"{label}.pull_request",
    )
    if pull_request["number"] != artifact["prNumber"]:
        _fail(f"{label} pull request number does not match review evidence")
    if pull_request["url"] != artifact["prUrl"]:
        _fail(f"{label} pull request URL does not match review evidence")
    if pull_request["head_sha"] != artifact["headSha"]:
        _fail(f"{label} head does not match review evidence")
    if pull_request["base_sha"] != artifact["currentBaseSha"]:
        _fail(f"{label} base does not match review evidence")
    if pull_request["is_draft"] is not True:
        _fail(f"{label} pull request must be draft")

    summary = raw["summary"]
    if not isinstance(summary, dict):
        _fail(f"{label}.summary must be an object")
    _require_exact_keys(
        summary,
        {
            "review_count",
            "coderabbit_review_count",
            "unresolved_thread_count",
            "unresolved_coderabbit_thread_count",
            "latest_coderabbit_review",
            "latest_coderabbit_review_state",
            "approved_at_head",
        },
        f"{label}.summary",
    )
    for field in (
        "review_count",
        "coderabbit_review_count",
        "unresolved_thread_count",
        "unresolved_coderabbit_thread_count",
    ):
        _require_int(summary[field], f"{label}.summary.{field}")
    if summary["approved_at_head"] is not True:
        _fail(f"{label} must report approved_at_head true")
    if summary["unresolved_coderabbit_thread_count"] != 0:
        _fail(f"{label} must report zero actionable CodeRabbit threads")

    latest = summary["latest_coderabbit_review"]
    if not isinstance(latest, dict):
        _fail(f"{label} requires a latest CodeRabbit review")
    _require_exact_keys(
        latest,
        {"id", "state", "body", "submittedAt", "author", "commit"},
        f"{label}.summary.latest_coderabbit_review",
    )
    author = latest["author"]
    commit = latest["commit"]
    if (
        latest["state"] != "APPROVED"
        or summary["latest_coderabbit_review_state"] != "APPROVED"
        or not isinstance(author, dict)
        or not _is_coderabbit_login(author.get("login"))
        or not isinstance(commit, dict)
        or commit.get("oid") != artifact["headSha"]
        or not latest["submittedAt"]
    ):
        _fail(f"{label} latest CodeRabbit review is not approved at head")

    reviews = raw["reviews"]
    threads = raw["unresolved_threads"]
    if not isinstance(reviews, list) or summary["review_count"] != len(reviews):
        _fail(f"{label} review count is inconsistent")
    coderabbit_reviews = [
        review
        for review in reviews
        if isinstance(review, dict)
        and isinstance(review.get("author"), dict)
        and _is_coderabbit_login(review["author"].get("login"))
        and review.get("submittedAt") is not None
    ]
    if (
        summary["coderabbit_review_count"] != len(coderabbit_reviews)
        or not coderabbit_reviews
        or latest not in coderabbit_reviews
    ):
        _fail(f"{label} CodeRabbit review count is inconsistent")
    if not isinstance(threads, list) or summary["unresolved_thread_count"] != len(
        threads
    ):
        _fail(f"{label} unresolved thread count is inconsistent")
    for thread in threads:
        if not isinstance(thread, dict):
            _fail(f"{label} unresolved thread must be an object")
        comments = thread.get("comments")
        nodes = comments.get("nodes") if isinstance(comments, dict) else None
        if not isinstance(nodes, list):
            _fail(f"{label} unresolved thread comments must be a list")
        if (
            thread.get("isResolved") is False
            and thread.get("isOutdated") is False
            and any(
                isinstance(comment, dict)
                and isinstance(comment.get("author"), dict)
                and _is_coderabbit_login(comment["author"].get("login"))
                for comment in nodes
            )
        ):
            _fail(f"{label} contains an actionable CodeRabbit thread")


def _validate_independent_raw_verdict(
    raw: dict[str, object],
    artifact: dict[str, object],
    label: str,
) -> None:
    _require_exact_keys(
        raw,
        {
            "role",
            "phase",
            "head_sha",
            "base_sha",
            "findings",
            "gate_states",
            "coverage",
            "blockers",
        },
        label,
    )
    if raw["role"] != "code-review" or raw["phase"] != "review_report":
        _fail(f"{label} must be a code-review review_report")
    if raw["head_sha"] != artifact["headSha"]:
        _fail(f"{label} head does not match review evidence")
    if raw["base_sha"] != artifact["currentBaseSha"]:
        _fail(f"{label} base does not match review evidence")
    if raw["findings"] != []:
        _fail(f"{label} must contain no findings")
    if raw["blockers"] != []:
        _fail(f"{label} must contain no blockers")
    coverage = _require_string_list(raw["coverage"], f"{label}.coverage")
    if not coverage:
        _fail(f"{label}.coverage must not be empty")
    _validate_independent_review_gate_states(
        raw["gate_states"],
        f"{label}.gate_states",
    )


def _validate_github_review_raw_verdict(
    raw: dict[str, object],
    artifact: dict[str, object],
    label: str,
) -> None:
    if artifact["reviewGate"] == "coderabbit":
        _validate_coderabbit_raw_verdict(raw, artifact, f"{label}.rawEvidence")
    else:
        _validate_independent_raw_verdict(raw, artifact, f"{label}.rawEvidence")


def _validate_base_artifact_shape(
    artifact: dict[str, object],
    kind: str,
    label: str,
    *,
    require_clean_review: bool,
) -> None:
    keys = (
        _GITHUB_REVIEW_ARTIFACT_KEYS
        if kind == "github_review"
        else _BASE_ARTIFACT_KEYS
    )
    _require_exact_keys(artifact, keys, label)
    _require_schema_version(artifact["schemaVersion"], f"{label}.schemaVersion")
    if artifact["kind"] != kind:
        _fail(f"{label}.kind must be {kind}")
    _require_sha(artifact["headSha"], f"{label}.headSha")
    _require_sha(artifact["currentBaseSha"], f"{label}.currentBaseSha")
    _require_command(artifact["integrationCommand"], f"{label}.integrationCommand")
    _require_command(artifact["gateCommand"], f"{label}.gateCommand")
    if type(artifact["integrationExitCode"]) is not int:
        _fail(f"{label}.integrationExitCode must be an integer")
    if type(artifact["gateExitCode"]) is not int:
        _fail(f"{label}.gateExitCode must be an integer")
    raw_uri = _require_nonempty_string(
        artifact["rawEvidenceUri"],
        f"{label}.rawEvidenceUri",
    )
    if not urlparse(raw_uri).scheme:
        _fail(f"{label}.rawEvidenceUri must be a URI")
    _require_utc(artifact["observedAt"], f"{label}.observedAt")
    if kind == "github_review":
        _require_int(artifact["prNumber"], f"{label}.prNumber", minimum=1)
        _require_nonempty_string(artifact["prUrl"], f"{label}.prUrl")
        _require_enum(
            artifact["reviewGate"],
            {"coderabbit", "independent_review"},
            f"{label}.reviewGate",
        )
        if artifact["isDraft"] is not True:
            _fail(f"{label}.isDraft must be true")
        _require_sha256(
            artifact["rawEvidenceSha256"],
            f"{label}.rawEvidenceSha256",
        )
        raw = _read_hashed_json_uri(
            artifact["rawEvidenceUri"],
            artifact["rawEvidenceSha256"],
            f"{label}.rawEvidence",
        )
        if require_clean_review:
            _validate_github_review_raw_verdict(raw, artifact, label)


def _require_gate_artifact_kind(
    gate: str,
    observation: dict[str, object],
    artifact: dict[str, object],
) -> None:
    if gate in {"focused", "native_lab"} and not observation["baseSensitive"]:
        expected = "repo_check"
    elif gate in {"coderabbit", "independent_review"}:
        expected = "github_review"
    else:
        expected = "synthetic_merge"
    if artifact.get("kind") != expected:
        _fail(f"successful {gate} requires {expected} evidence")


def _validated_observation_artifact(
    observation: dict[str, object],
    label: str,
) -> dict[str, object]:
    artifact = _read_observation_artifact(
        observation["artifact"],
        f"{label}.artifact",
    )
    kind = artifact.get("kind")
    if kind == "repo_check":
        _validate_repo_check_artifact(artifact, observation, f"{label} artifact")
    elif kind in {"synthetic_merge", "github_review"}:
        _validate_base_artifact_shape(
            artifact,
            kind,
            f"{label} artifact",
            require_clean_review=observation["state"] == "passed",
        )
        if observation["command"] is not None:
            if artifact["gateCommand"] != observation["command"]:
                _fail(f"{label} artifact gateCommand does not match the observation")
            if artifact["gateExitCode"] != observation["exitCode"]:
                _fail(f"{label} artifact gateExitCode does not match the observation")
        if artifact["headSha"] != observation["headSha"]:
            _fail(f"{label} artifact headSha does not match the observation")
        if artifact["currentBaseSha"] != observation["baseSha"]:
            _fail(f"{label} artifact base does not match the observation")
        if artifact["observedAt"] != observation["observedAt"]:
            _fail(f"{label} artifact observedAt does not match the observation")
    else:
        _fail(f"{label} artifact kind is invalid")
    return artifact


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
            "stage2Waves": {},
        },
    }


def _validate_observation(
    observation: object,
    label: str,
    states: set[str],
    *,
    lane_binding: dict[str, object],
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
        "redClassification",
    )
    if initial_state:
        if any(observation[key] is not None for key in evidence_keys):
            _fail(f"{label} initial state must not contain observation evidence")
        return observation

    head_sha = _require_sha(observation["headSha"], f"{label}.headSha")
    base_sha = _require_sha(observation["baseSha"], f"{label}.baseSha")
    command = observation["command"]
    scenario = observation["scenario"]
    if command is not None:
        _require_command(command, f"{label}.command")
    _require_optional_string(scenario, f"{label}.scenario")
    if command is None and scenario is None:
        _fail(f"{label} requires command or scenario")
    exit_code = observation["exitCode"]
    if isinstance(exit_code, bool) or not isinstance(exit_code, int):
        _fail(f"{label}.exitCode must be an integer")
    if state_value in {"passed", "mergeable"} and exit_code != 0:
        _fail(f"{label} successful state requires exitCode 0")
    if state_value == "failed" and command is not None and exit_code == 0:
        _fail(f"{label} failed command requires a nonzero exit")
    _require_utc(observation["observedAt"], f"{label}.observedAt")
    artifact = _validated_observation_artifact(observation, label)
    _require_repo_check_lane_binding(artifact, lane_binding, label)
    red_classification = observation["redClassification"]
    if red_classification is not None:
        _validate_red_classification(
            red_classification,
            observation,
            f"{label}.redClassification",
        )
    if state_value in {"passed", "mergeable"}:
        if artifact["kind"] == "repo_check":
            if artifact["failureClassification"] != "success":
                _fail(f"{label} successful state requires successful runner evidence")
        elif artifact.get("gateExitCode") != 0:
            _fail(f"{label} successful state requires successful gate evidence")
        if red_classification is not None:
            _fail(f"{label} successful state must not contain RED classification")
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
    role = _require_enum(lane["role"], DISPATCH_ROLES, f"lane {lane_key}.role")
    worktree = _require_nonempty_string(lane["worktree"], f"lane {lane_key}.worktree")
    if not Path(worktree).is_absolute():
        _fail(f"lane {lane_key}.worktree must be absolute")
    _require_worktree_identity(
        lane["worktreeIdentity"],
        f"lane {lane_key}.worktreeIdentity",
    )
    git_common_dir = _require_nonempty_string(
        lane["gitCommonDir"],
        f"lane {lane_key}.gitCommonDir",
    )
    if not Path(git_common_dir).is_absolute():
        _fail(f"lane {lane_key}.gitCommonDir must be absolute")
    _require_nonempty_string(lane["branch"], f"lane {lane_key}.branch")
    allowed_paths = _require_string_list(
        lane["allowedPaths"],
        f"lane {lane_key}.allowedPaths",
    )
    for pattern in allowed_paths:
        _require_portable_repo_relative(
            pattern,
            f"lane {lane_key}.allowedPaths",
            allow_glob=True,
        )
    _require_issue_list(lane["dependsOn"], f"lane {lane_key}.dependsOn")
    shared_contract_paths = _require_string_list(
        lane["sharedContractPaths"],
        f"lane {lane_key}.sharedContractPaths",
    )
    for pattern in shared_contract_paths:
        _require_portable_repo_relative(
            pattern,
            f"lane {lane_key}.sharedContractPaths",
            allow_glob=True,
        )
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
    implementation_state = _require_enum(
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
            lane_binding=lane,
            lane_head=head_sha,
            current_base=current_base,
            require_matching_head=False,
            require_matching_base=False,
        )
    if role == "coder":
        if any(
            observation["command"] is None or observation["exitCode"] == 0
            for observation in red_evidence
        ):
            _fail(f"lane {lane_key} coder RED evidence requires a failed command")
        if implementation_state == "green" and not red_evidence:
            _fail(f"lane {lane_key} coder green state requires RED evidence")

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
            lane_binding=lane,
            lane_head=head_sha,
            current_base=current_base,
            require_matching_head=(
                isinstance(observation, dict)
                and observation.get("state") != "stale"
            ),
            require_matching_base=(
                isinstance(observation, dict)
                and observation.get("state") != "stale"
                and observation.get("baseSensitive") is True
            ),
        )
        if gate_name != "native_lab" and validated["baseSensitive"] != _GATE_BASE_SENSITIVITY[gate_name]:
            _fail(f"lane {lane_key}.gates.{gate_name}.baseSensitive is invalid")
        if validated["state"] in {"passed", "mergeable"}:
            artifact = _validated_observation_artifact(
                validated,
                f"lane {lane_key}.gates.{gate_name}",
            )
            _require_gate_artifact_kind(gate_name, validated, artifact)

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
    native_state = gates["native_lab"]["state"]
    if requirement["state"] == "required" and native_state == "not_required":
        _fail(f"lane {lane_key} required native lab cannot be not_required")
    if requirement["state"] == "not_required" and native_state != "not_required":
        _fail(f"lane {lane_key} native lab must remain not_required")

    for gate_name, successful_state in (
        ("coderabbit", "passed"),
        ("independent_review", "passed"),
        ("mergeability", "mergeable"),
    ):
        if gates[gate_name]["state"] != successful_state:
            continue
        if pr["number"] is None:
            _fail(f"lane {lane_key} successful {gate_name} requires a PR")
        if lane["remoteSha"] != head_sha:
            _fail(
                f"lane {lane_key} successful {gate_name} requires remoteSha "
                "to match headSha"
            )


def _validate_root_artifact_ref(snapshot: object, label: str) -> dict[str, object]:
    if not isinstance(snapshot, dict):
        _fail(f"{label} must be an object")
    _require_exact_keys(snapshot, _ROOT_ARTIFACT_KEYS, label)
    artifact = _require_nonempty_string(snapshot["artifact"], f"{label}.artifact")
    parsed = urlparse(artifact)
    if (
        parsed.scheme != "file"
        or parsed.netloc not in {"", "localhost"}
        or parsed.query
        or parsed.fragment
    ):
        _fail(f"{label}.artifact must be a local file:// URI")
    _require_sha256(snapshot["sha256"], f"{label}.sha256")
    return snapshot


def _validate_active_lane_identities(lanes: dict[str, object]) -> None:
    seen: dict[str, dict[object, str]] = {
        "agentId": {},
        "worktree": {},
        "worktree directory": {},
        "branch": {},
        "pull request": {},
    }
    for lane_key, value in lanes.items():
        lane = value
        if lane["laneState"] in {"merged", "abandoned"}:
            continue
        identities: dict[str, object] = {
            "agentId": lane["agentId"],
            "worktree": lane["worktree"],
            "worktree directory": (
                lane["worktreeIdentity"]["device"],
                lane["worktreeIdentity"]["inode"],
            ),
            "branch": lane["branch"],
        }
        if lane["pr"]["number"] is not None:
            identities["pull request"] = (
                lane["pr"]["number"],
                lane["pr"]["url"],
            )
        for label, identity in identities.items():
            previous = seen[label].get(identity)
            if previous is not None:
                _fail(
                    f"duplicate active lane {label}: "
                    f"{previous} and {lane_key}"
                )
            seen[label][identity] = lane_key


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
    _validate_active_lane_identities(lanes)
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
    _require_exact_keys(root_safety, _ROOT_SAFETY_KEYS, "rootSafety")
    stage1_before = root_safety["stage1Before"]
    stage1_after = root_safety["stage1After"]
    if stage1_before is not None:
        _validate_root_artifact_ref(stage1_before, "rootSafety.stage1Before")
    if stage1_after is not None:
        if stage1_before is None:
            _fail("rootSafety.stage1After requires stage1Before")
        _validate_root_artifact_ref(stage1_after, "rootSafety.stage1After")
        if stage1_before["sha256"] != stage1_after["sha256"]:
            _fail("rootSafety Stage 1 before and after artifacts must match")

    stage2_waves = root_safety["stage2Waves"]
    if not isinstance(stage2_waves, dict):
        _fail("rootSafety.stage2Waves must be an object")
    bound_lanes: set[str] = set()
    for wave_key, stage2_wave in stage2_waves.items():
        if not isinstance(wave_key, str) or not wave_key:
            _fail("rootSafety.stage2Waves keys must be non-empty strings")
        label = f"rootSafety.stage2Waves.{wave_key}"
        if not isinstance(stage2_wave, dict):
            _fail(f"{label} must be an object")
        _require_exact_keys(stage2_wave, _STAGE2_WAVE_KEYS, label)
        wave_id = _require_nonempty_string(
            stage2_wave["waveId"],
            f"{label}.waveId",
        )
        if wave_id != wave_key:
            _fail(f"{label}.waveId must match its key")
        bindings = stage2_wave["laneBindings"]
        if not isinstance(bindings, dict) or not bindings:
            _fail(f"{label}.laneBindings must be a non-empty object")
        for lane_key, binding in bindings.items():
            if lane_key not in lanes:
                _fail(f"{label}.laneBindings must name existing lanes")
            if lane_key in bound_lanes:
                _fail("a lane must not belong to more than one Stage 2 wave")
            bound_lanes.add(lane_key)
            binding_label = f"{label}.laneBindings.{lane_key}"
            if not isinstance(binding, dict):
                _fail(f"{binding_label} must be an object")
            _require_exact_keys(
                binding,
                _STAGE2_LANE_BINDING_KEYS,
                binding_label,
            )
            allocation_base = _require_sha(
                binding["allocationBaseSha"],
                f"{binding_label}.allocationBaseSha",
            )
            worktree = _require_nonempty_string(
                binding["worktree"],
                f"{binding_label}.worktree",
            )
            if allocation_base != lanes[lane_key]["allocationBaseSha"]:
                _fail(
                    f"{binding_label}.allocationBaseSha does not match the lane"
                )
            if worktree != lanes[lane_key]["worktree"]:
                _fail(f"{binding_label}.worktree does not match the lane")
        _require_sha256(
            stage2_wave["managedWorktreesSha256"],
            f"{label}.managedWorktreesSha256",
        )
        before = _validate_root_artifact_ref(
            stage2_wave["before"],
            f"{label}.before",
        )
        after = stage2_wave["after"]
        if after is not None:
            validated_after = _validate_root_artifact_ref(
                after,
                f"{label}.after",
            )
            if validated_after["sha256"] != before["sha256"]:
                _fail("rootSafety Stage 2 before and after artifacts must match")
    for lane in lanes.values():
        if lane["laneState"] == "ready_for_adam":
            _require_ready_for_adam(data, lane)



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

def _minimal_process_environment() -> dict[str, str]:
    return {
        key: os.environ[key]
        for key in PROCESS_ENV_ALLOWLIST
        if key in os.environ
    }


def _git_bytes(repo: Path, *args: str) -> bytes:
    try:
        repository = repo.resolve(strict=True)
    except OSError as error:
        raise ValueError(f"cannot resolve repository {repo}: {error}") from error
    if not repository.is_dir():
        _fail(f"repository is not a directory: {repo}")
    environment = _minimal_process_environment()
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    try:
        result = subprocess.run(
            [
                "git",
                "-c",
                "core.fsmonitor=false",
                "-C",
                str(repository),
                *args,
            ],
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            timeout=GIT_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as error:
        raise ValueError(
            f"git {' '.join(args)} timed out after {GIT_TIMEOUT_SECONDS:g} seconds"
        ) from error
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


def _worktree_path_identity(path: Path) -> dict[str, int]:
    if not path.is_absolute():
        _fail("lane worktree path must be absolute")
    try:
        info = path.lstat()
    except OSError as error:
        raise ValueError(f"cannot inspect lane worktree {path}: {error}") from error
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        _fail(f"lane worktree must be a real directory: {path}")
    return {"device": info.st_dev, "inode": info.st_ino}


def _registered_worktree_fields(repo: Path) -> dict[bytes, bytes]:
    output = _git_bytes(repo, "worktree", "list", "--porcelain", "-z")
    _normalized_worktree_registrations(output)
    encoded_path = os.fsencode(str(repo))
    matches: list[dict[bytes, bytes]] = []
    for record in output[:-2].split(b"\0\0"):
        fields: dict[bytes, bytes] = {}
        for field in record.split(b"\0"):
            key, _, value = field.partition(b" ")
            fields[key] = value
        if fields.get(b"worktree") == encoded_path:
            matches.append(fields)
    if len(matches) != 1:
        _fail(f"lane worktree is not uniquely registered with Git: {repo}")
    registration = matches[0]
    if b"prunable" in registration:
        _fail(f"lane worktree Git registration is prunable: {repo}")
    return registration


def observe_lane_worktree(worktree: Path) -> dict[str, object]:
    identity = _worktree_path_identity(worktree)
    try:
        top_level = Path(
            git_text(
                worktree,
                "rev-parse",
                "--path-format=absolute",
                "--show-toplevel",
            )
        ).resolve(strict=True)
        common_dir = Path(
            git_text(
                worktree,
                "rev-parse",
                "--path-format=absolute",
                "--git-common-dir",
            )
        ).resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise ValueError(f"cannot canonicalize lane Git identity: {error}") from error
    if top_level != worktree:
        _fail("lane worktree path does not name the Git worktree top level")
    if not common_dir.is_dir():
        _fail("lane Git common directory is not a directory")
    head_sha = _require_sha(
        git_text(worktree, "rev-parse", "--verify", "HEAD"),
        "observed lane HEAD",
    )
    branch_ref = git_text(worktree, "symbolic-ref", "--quiet", "HEAD")
    if not branch_ref.startswith("refs/heads/"):
        _fail("lane worktree HEAD is not attached to a local branch")
    branch = branch_ref.removeprefix("refs/heads/")
    if not branch:
        _fail("lane worktree branch is empty")
    registration = _registered_worktree_fields(worktree)
    if registration.get(b"HEAD", b"").decode("ascii", errors="replace") != head_sha:
        _fail("lane worktree registration HEAD does not match observed HEAD")
    if os.fsdecode(registration.get(b"branch", b"")) != branch_ref:
        _fail("lane worktree registration branch does not match observed branch")
    if _worktree_path_identity(worktree) != identity:
        _fail("lane worktree identity changed while observing Git state")
    return {
        "worktree": str(worktree),
        "worktreeIdentity": identity,
        "gitCommonDir": str(common_dir),
        "branch": branch,
        "headSha": head_sha,
    }


def require_lane_worktree_current(
    lane: dict[str, object],
    *,
    expected_head: str | None = None,
) -> dict[str, object]:
    worktree = Path(_require_nonempty_string(lane["worktree"], "lane.worktree"))
    try:
        observed = observe_lane_worktree(worktree)
    except ValueError as error:
        _fail(f"lane worktree identity cannot be observed: {error}")
    expected = {
        "worktree": lane["worktree"],
        "worktreeIdentity": lane["worktreeIdentity"],
        "gitCommonDir": lane["gitCommonDir"],
        "branch": lane["branch"],
        "headSha": lane["headSha"] if expected_head is None else expected_head,
    }
    if observed != expected:
        _fail("lane worktree identity, registration, branch, or HEAD changed")
    return observed


def _is_observed_repo_relative(value: object) -> bool:
    if not isinstance(value, str) or not value:
        return False
    if value.startswith("/") or "\\" in value:
        return False
    if (
        len(value) >= 3
        and value[0].isascii()
        and value[0].isalpha()
        and value[1:3] == ":/"
    ):
        return False
    if any(
        ord(character) <= 0x1F or 0x7F <= ord(character) <= 0x9F
        for character in value
    ):
        return False
    return all(part not in {"", ".", ".."} for part in value.split("/"))


def _require_observed_repo_relative(value: str, label: str) -> str:
    if not _is_observed_repo_relative(value):
        _fail(f"{label} escapes the worktree")
    return value


def _is_portable_repo_relative(
    value: object,
    *,
    allow_glob: bool = False,
) -> bool:
    if (
        not isinstance(value, str)
        or not _is_observed_repo_relative(value)
        or value == "~"
        or value.startswith("~/")
        or "%00" in value.casefold()
        or any(character.isspace() for character in value)
    ):
        return False
    invalid_characters = '<>:"|'
    if not allow_glob:
        invalid_characters += "?*"
    parts = value.split("/")
    if any(
        any(character in invalid_characters for character in part)
        for part in parts
    ):
        return False
    return all(
        not part.endswith((".", " "))
        and part.split(".", 1)[0].casefold() not in _WINDOWS_RESERVED_NAMES
        for part in parts
    )


def _require_portable_repo_relative(
    value: str,
    label: str,
    *,
    allow_glob: bool = False,
) -> str:
    if not _is_portable_repo_relative(value, allow_glob=allow_glob):
        _fail(f"{label} must be a portable repository-relative path")
    return value

def _compile_path_glob(pattern: str) -> re.Pattern[str]:
    expression: list[str] = []
    index = 0
    while index < len(pattern):
        if pattern == "**":
            expression.append(r"[^/]+(?:/[^/]+)*")
            index = 2
        elif pattern.startswith("**/", index):
            expression.append(r"(?:[^/]+/)*")
            index += 3
        elif pattern.startswith("/**/", index):
            expression.append(r"/(?:[^/]+/)*")
            index += 4
        elif pattern.startswith("/**", index) and index + 3 == len(pattern):
            expression.append(r"(?:/[^/]+)*")
            index += 3
        elif pattern.startswith("**", index):
            expression.append(".*")
            index += 2
        elif pattern[index] == "*":
            expression.append("[^/]*")
            index += 1
        elif pattern[index] == "?":
            expression.append("[^/]")
            index += 1
        else:
            expression.append(re.escape(pattern[index]))
            index += 1
    return re.compile("".join(expression))


def _path_glob_matches(path: str, pattern: re.Pattern[str]) -> bool:
    return pattern.fullmatch(path) is not None


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
        _require_observed_repo_relative(path, "changed path")
        for path in (*tracked_output.split("\0"), *untracked_output.split("\0"))
        if path
    }
    return sorted(paths)

def _base_tracked_paths(repo: Path, allocation_base: str) -> set[str]:
    _require_sha(allocation_base, "allocation base")
    try:
        output = _git_bytes(
            repo,
            "ls-tree",
            "-r",
            "--name-only",
            "-z",
            allocation_base,
            "--",
        ).decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("Git tree path output is not valid UTF-8") from error
    return {
        _require_observed_repo_relative(path, "base tracked path")
        for path in output.split("\0")
        if path
    }


def _canonical_path_violations(
    repo: Path,
    allocation_base: str,
    paths: list[str],
    *,
    approved_delete_path: str | None = None,
) -> list[str]:
    try:
        worktree = repo.resolve(strict=True)
        worktree_info = worktree.stat()
    except OSError as error:
        raise ValueError(f"cannot resolve lane worktree {repo}: {error}") from error
    if not stat.S_ISDIR(worktree_info.st_mode):
        _fail(f"lane worktree is not a directory: {repo}")

    candidate_paths = _require_string_list(paths, "changed paths")
    if approved_delete_path is not None:
        approved_delete_path = _require_portable_repo_relative(
            approved_delete_path,
            "approved delete path",
        )
        if approved_delete_path not in candidate_paths:
            _fail("approved delete path is not a changed path")

    base_paths: set[str] | None = None
    violations: list[str] = []
    for relative_path in candidate_paths:
        _require_observed_repo_relative(relative_path, "changed path")
        candidate = worktree
        components = relative_path.split("/")
        for index, component in enumerate(components):
            candidate /= component
            is_final = index == len(components) - 1
            try:
                candidate_info = candidate.lstat()
            except FileNotFoundError:
                if not is_final or relative_path != approved_delete_path:
                    violations.append(relative_path)
                    break
                if base_paths is None:
                    base_paths = _base_tracked_paths(repo, allocation_base)
                if relative_path not in base_paths:
                    violations.append(relative_path)
                break
            except OSError:
                violations.append(relative_path)
                break
            try:
                canonical = candidate.resolve(strict=True)
                canonical_info = canonical.stat()
                canonical.relative_to(worktree)
            except (OSError, ValueError):
                violations.append(relative_path)
                break

            if not is_final:
                if not stat.S_ISDIR(canonical_info.st_mode):
                    violations.append(relative_path)
                    break
                continue
            if relative_path == approved_delete_path:
                violations.append(relative_path)
                continue
            if stat.S_ISREG(candidate_info.st_mode):
                continue
            if stat.S_ISLNK(candidate_info.st_mode) and (
                stat.S_ISREG(canonical_info.st_mode)
                or stat.S_ISDIR(canonical_info.st_mode)
            ):
                continue
            violations.append(relative_path)
    return sorted(set(violations))


def check_allowed_paths(paths: list[str], allowlist: list[str]) -> list[str]:
    candidate_paths = _require_string_list(paths, "changed paths")
    patterns = [
        _compile_path_glob(
            _require_portable_repo_relative(
                pattern,
                "allowed path",
                allow_glob=True,
            )
        )
        for pattern in _require_string_list(allowlist, "allowed paths")
    ]
    return sorted(
        path
        for path in candidate_paths
        if not _is_observed_repo_relative(path)
        or not any(_path_glob_matches(path, pattern) for pattern in patterns)
    )


def _disallowed_changed_paths(
    repo: Path,
    allocation_base: str,
    paths: list[str],
    allowlist: list[str],
    *,
    approved_delete_path: str | None = None,
) -> list[str]:
    unsafe = _canonical_path_violations(
        repo,
        allocation_base,
        paths,
        approved_delete_path=approved_delete_path,
    )
    outside_allowlist = check_allowed_paths(paths, allowlist)
    return sorted(set(unsafe).union(outside_allowlist))


def enforce_lane_paths(
    data: dict[str, object],
    issue: str,
    *,
    approved_delete_path: str | None = None,
) -> list[str]:
    validate_manifest(data)
    candidate = deepcopy(data)
    lane = _lane(candidate, issue)
    require_lane_worktree_current(lane)
    worktree = Path(lane["worktree"])
    paths = changed_paths(
        worktree,
        lane["allocationBaseSha"],
    )
    disallowed = _disallowed_changed_paths(
        worktree,
        lane["allocationBaseSha"],
        paths,
        lane["allowedPaths"],
        approved_delete_path=approved_delete_path,
    )
    require_lane_worktree_current(lane)
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
def _digest_field(digest: UpdateDigest, value: bytes) -> None:
    digest.update(len(value).to_bytes(8, "big"))
    digest.update(value)


def _regular_file_sha256(path: Path, expected: os.stat_result) -> bytes:
    digest = hashlib.sha256()
    file_descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(file_descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _stable_stat_identity(opened) != _stable_stat_identity(expected)
        ):
            _fail(f"filesystem entry changed while hashing: {path}")
        while chunk := os.read(file_descriptor, ARTIFACT_HASH_CHUNK_SIZE):
            digest.update(chunk)
        if _stable_stat_identity(os.fstat(file_descriptor)) != _stable_stat_identity(
            opened
        ):
            _fail(f"filesystem entry changed while hashing: {path}")
    finally:
        os.close(file_descriptor)
    return digest.digest()

def _stable_stat_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _hash_filesystem_node(
    digest: UpdateDigest,
    path: Path,
    label: bytes,
    *,
    exclude_managed_roots: bool = False,
    reject_symlinks: bool = False,
) -> None:
    pending: list[
        tuple[
            str,
            Path,
            bytes,
            bool,
            os.stat_result | None,
        ]
    ] = [("enter", path, label, exclude_managed_roots, None)]
    while pending:
        action, current, current_label, exclude_roots, expected = pending.pop()
        if action == "verify":
            try:
                current_info = current.lstat()
            except OSError as error:
                raise ValueError(
                    f"filesystem entry changed while hashing: {current}"
                ) from error
            if (
                expected is None
                or _stable_stat_identity(current_info)
                != _stable_stat_identity(expected)
            ):
                _fail(f"filesystem entry changed while hashing: {current}")
            continue
        try:
            info = current.lstat()
        except OSError as error:
            raise ValueError(
                f"cannot inspect filesystem entry {current}: {error}"
            ) from error
        _digest_field(digest, current_label)
        _digest_field(digest, stat.S_IMODE(info.st_mode).to_bytes(4, "big"))
        if stat.S_ISREG(info.st_mode):
            _digest_field(digest, b"regular")
            try:
                content_sha = _regular_file_sha256(current, info)
            except OSError as error:
                raise ValueError(
                    f"cannot hash filesystem entry {current}: {error}"
                ) from error
            _digest_field(digest, content_sha)
            pending.append(("verify", current, b"", False, info))
            continue
        if stat.S_ISLNK(info.st_mode):
            if reject_symlinks:
                _fail(f"protected control path contains symlink: {current}")
            _digest_field(digest, b"symlink")
            try:
                target = os.readlink(os.fsencode(current))
            except OSError as error:
                raise ValueError(
                    f"cannot read filesystem symlink {current}: {error}"
                ) from error
            _digest_field(digest, target)
            pending.append(("verify", current, b"", False, info))
            continue
        if not stat.S_ISDIR(info.st_mode):
            _fail(f"filesystem entry has unsupported kind: {current}")
        _digest_field(digest, b"directory")
        pending.append(("verify", current, b"", False, info))
        try:
            children = sorted(
                current.iterdir(),
                key=lambda child: os.fsencode(child.name),
                reverse=True,
            )
        except OSError as error:
            raise ValueError(
                f"cannot list filesystem directory {current}: {error}"
            ) from error
        for child in children:
            if exclude_roots and child.name in (".git", ".worktrees"):
                continue
            child_label = (
                os.fsencode(child.name)
                if not current_label
                else current_label + b"/" + os.fsencode(child.name)
            )
            pending.append(
                ("enter", child, child_label, False, None)
            )


def _filesystem_sha256(repository: Path) -> str:
    digest = hashlib.sha256()
    _hash_filesystem_node(
        digest,
        repository,
        b"",
        exclude_managed_roots=True,
    )
    return digest.hexdigest()



def _non_symlink_parent_chain(path: Path) -> tuple[tuple[int, int, int], ...]:
    if not path.is_absolute():
        _fail(f"protected control path must be absolute: {path}")
    current = Path(path.anchor)
    identities: list[tuple[int, int, int]] = []
    for component in path.parts[1:-1]:
        current /= component
        try:
            info = current.lstat()
        except OSError as error:
            raise ValueError(
                f"cannot inspect protected control parent {current}: {error}"
            ) from error
        if stat.S_ISLNK(info.st_mode):
            _fail(f"protected control path contains symlink: {current}")
        if not stat.S_ISDIR(info.st_mode):
            _fail(f"protected control parent is not a directory: {current}")
        identities.append((info.st_dev, info.st_ino, info.st_mode))
    return tuple(identities)


def _hash_protected_control(
    digest: UpdateDigest,
    path: Path,
    label: bytes,
) -> None:
    before = _non_symlink_parent_chain(path)
    try:
        path.lstat()
    except FileNotFoundError:
        _digest_field(digest, label)
        _digest_field(digest, b"missing")
        try:
            path.lstat()
        except FileNotFoundError:
            pass
        except OSError as error:
            raise ValueError(
                f"cannot verify protected control path {path}: {error}"
            ) from error
        else:
            _fail(f"protected control path changed while hashing: {path}")
    except OSError as error:
        raise ValueError(
            f"cannot inspect protected control path {path}: {error}"
        ) from error
    else:
        _hash_filesystem_node(
            digest,
            path,
            label,
            reject_symlinks=True,
        )
    after = _non_symlink_parent_chain(path)
    if before != after:
        _fail(f"protected control path changed while hashing: {path}")

def _normalized_worktree_registrations(
    output: bytes,
) -> tuple[tuple[bytes, ...], ...]:
    if not output or not output.endswith(b"\0\0"):
        _fail("malformed Git worktree registration output")
    identities: list[tuple[bytes, ...]] = []
    canonical_paths: set[bytes] = set()
    for record in output[:-2].split(b"\0\0"):
        if not record:
            _fail("malformed empty Git worktree registration")
        fields: dict[bytes, bytes] = {}
        for field in record.split(b"\0"):
            key, separator, value = field.partition(b" ")
            if key not in {
                b"worktree",
                b"HEAD",
                b"branch",
                b"detached",
                b"bare",
                b"locked",
                b"prunable",
            }:
                _fail("unknown Git worktree registration field")
            if key in fields:
                _fail("duplicate Git worktree registration field")
            if key in {b"worktree", b"HEAD", b"branch"}:
                if not separator or not value:
                    _fail("malformed Git worktree registration field")
            elif key in {b"detached", b"bare"}:
                if separator:
                    _fail("malformed Git worktree registration marker")
            elif separator and not value:
                _fail("malformed Git worktree registration state")
            fields[key] = value
        if b"worktree" not in fields:
            _fail("Git worktree registration is missing its path")
        path = Path(os.fsdecode(fields[b"worktree"]))
        if not path.is_absolute():
            _fail("Git worktree registration path must be absolute")
        try:
            canonical_path = os.fsencode(path.resolve(strict=False))
        except (OSError, RuntimeError) as error:
            raise ValueError(
                f"cannot canonicalize Git worktree registration path: {error}"
            ) from error
        if canonical_path in canonical_paths:
            _fail("duplicate Git worktree registration path")
        canonical_paths.add(canonical_path)

        bare = b"bare" in fields
        identity_fields = {
            key
            for key in (b"branch", b"detached", b"bare")
            if key in fields
        }
        if len(identity_fields) != 1:
            _fail("Git worktree registration must have one identity")
        if bare:
            if b"HEAD" in fields:
                _fail("bare Git worktree registration must not contain HEAD")
            identity_kind = b"bare"
            identity = b""
        else:
            head = fields.get(b"HEAD")
            if (
                head is None
                or re.fullmatch(rb"[0-9a-fA-F]{40}", head) is None
            ):
                _fail("Git worktree registration HEAD must be a 40-hex SHA")
            if b"branch" in fields:
                identity = fields[b"branch"]
                if (
                    not identity.startswith(b"refs/")
                    or any(
                        byte <= 0x20
                        or byte in b"~^:?*[\\"
                        for byte in identity
                    )
                ):
                    _fail("Git worktree registration branch is invalid")
                identity_kind = b"branch"
            else:
                identity_kind = b"detached"
                identity = b""
        identities.append(
            (
                canonical_path,
                identity_kind,
                identity,
                b"locked" if b"locked" in fields else b"unlocked",
                fields.get(b"locked", b""),
                b"prunable" if b"prunable" in fields else b"registered",
                fields.get(b"prunable", b""),
            )
        )
    return tuple(sorted(identities))




def _managed_worktrees_sha256(repository: Path) -> str:
    digest = hashlib.sha256()
    managed = repository / ".worktrees"
    try:
        managed_info = managed.lstat()
    except FileNotFoundError:
        managed_info = None
    except OSError as error:
        raise ValueError(
            f"cannot inspect managed worktree directory {managed}: {error}"
        ) from error
    entry_info: dict[str, os.stat_result] = {}
    if managed_info is not None:
        if stat.S_ISLNK(managed_info.st_mode):
            _fail(f"managed worktree directory must not be a symlink: {managed}")
        if not stat.S_ISDIR(managed_info.st_mode):
            _fail(f"managed worktree path is not a directory: {managed}")
        try:
            entries = sorted(
                managed.iterdir(),
                key=lambda entry: os.fsencode(entry.name),
            )
        except OSError as error:
            raise ValueError(
                f"cannot list managed worktree directory {managed}: {error}"
            ) from error
        for entry in entries:
            try:
                info = entry.lstat()
            except OSError as error:
                raise ValueError(
                    f"cannot inspect managed worktree entry {entry}: {error}"
                ) from error
            entry_info[entry.name] = info
            _digest_field(digest, os.fsencode(entry.name))
            _digest_field(
                digest,
                stat.S_IMODE(info.st_mode).to_bytes(4, "big"),
            )
            if stat.S_ISDIR(info.st_mode):
                _digest_field(digest, b"directory")
            elif stat.S_ISLNK(info.st_mode):
                _digest_field(digest, b"symlink")
                try:
                    _digest_field(digest, os.readlink(os.fsencode(entry)))
                except OSError as error:
                    raise ValueError(
                        f"cannot read managed worktree symlink {entry}: {error}"
                    ) from error
            elif stat.S_ISREG(info.st_mode):
                _digest_field(digest, b"regular")
                try:
                    _digest_field(
                        digest,
                        _regular_file_sha256(entry, info),
                    )
                except OSError as error:
                    raise ValueError(
                        f"cannot hash managed worktree entry {entry}: {error}"
                    ) from error
            else:
                _fail(f"managed worktree entry has unsupported kind: {entry}")
    registrations = _git_bytes(
        repository,
        "worktree",
        "list",
        "--porcelain",
        "-z",
    )
    _digest_field(digest, b"registrations")
    for registration in _normalized_worktree_registrations(registrations):
        _digest_field(digest, b"registration")
        for value in registration:
            _digest_field(digest, value)
    try:
        current_managed_info = managed.lstat()
    except FileNotFoundError:
        current_managed_info = None
    except OSError as error:
        raise ValueError(
            f"cannot verify managed worktree directory {managed}: {error}"
        ) from error
    if (managed_info is None) != (current_managed_info is None):
        _fail(f"managed worktree directory changed while hashing: {managed}")
    if managed_info is not None and current_managed_info is not None:
        if (
            _stable_stat_identity(managed_info)
            != _stable_stat_identity(current_managed_info)
        ):
            _fail(f"managed worktree directory changed while hashing: {managed}")
        try:
            current_entries = {
                entry.name: entry.lstat()
                for entry in managed.iterdir()
            }
        except OSError as error:
            raise ValueError(
                f"cannot verify managed worktree entries in {managed}: {error}"
            ) from error
        if set(entry_info) != set(current_entries) or any(
            _stable_stat_identity(entry_info[name])
            != _stable_stat_identity(current_entries[name])
            for name in entry_info
        ):
            _fail(f"managed worktree entries changed while hashing: {managed}")
    if registrations != _git_bytes(
        repository,
        "worktree",
        "list",
        "--porcelain",
        "-z",
    ):
        _fail("Git worktree registrations changed while hashing")
    return digest.hexdigest()

def _configured_hooks_path(repo: Path, common_dir: Path) -> Path:
    configured = git_text(
        repo,
        "config",
        "--path",
        "--get",
        "--default",
        str(common_dir / "hooks"),
        "core.hooksPath",
    )
    if not configured:
        _fail("core.hooksPath must not be empty")
    path = Path(configured)
    return path if path.is_absolute() else repo / path



def _git_controls_sha256(repo: Path) -> str:
    git_dir = Path(git_text(repo, "rev-parse", "--absolute-git-dir"))
    common_dir = Path(
        git_text(
            repo,
            "rev-parse",
            "--path-format=absolute",
            "--git-common-dir",
        )
    )
    controls: list[tuple[bytes, Path]] = [
        (b"HEAD", git_dir / "HEAD"),
        (b"index", git_dir / "index"),
        (b"config", common_dir / "config"),
        (b"worktree-config", git_dir / "config.worktree"),
        (b"hooks", _configured_hooks_path(repo, common_dir)),
        (b"info-attributes", common_dir / "info" / "attributes"),
        (b"info-exclude", common_dir / "info" / "exclude"),
        (b"info-sparse-checkout", git_dir / "info" / "sparse-checkout"),
    ]
    digest = hashlib.sha256()
    for label, path in controls:
        _hash_protected_control(digest, path, label)
    return digest.hexdigest()


def _root_snapshot_once(repo: Path) -> dict[str, object]:
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
        observed_relative = relative_path.removesuffix("/")
        _require_observed_repo_relative(
            observed_relative, "untracked path"
        )
        if (
            observed_relative == ".worktrees"
            or observed_relative.startswith(".worktrees/")
        ):
            continue
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
                digest.update(_regular_file_sha256(path, info))
            else:
                _fail(f"untracked path has unsupported file kind: {relative_path}")
            if _stable_stat_identity(path.lstat()) != _stable_stat_identity(info):
                _fail(
                    "untracked path changed while hashing: "
                    + relative_path
                )
        except OSError as error:
            raise ValueError(
                f"cannot hash untracked path {relative_path}: {error}"
            ) from error
        untracked.append(
            {"path": relative_path, "sha256": digest.hexdigest()}
        )
    filesystem_sha256 = _filesystem_sha256(repository)
    git_controls_sha256 = _git_controls_sha256(repository)
    managed_worktrees_sha256 = _managed_worktrees_sha256(repository)
    if git_text(repo, "rev-parse", "HEAD") != head_sha:
        _fail("root snapshot HEAD changed while hashing")
    if _index_tree_sha(repo) != index_tree_sha:
        _fail("root snapshot index changed while hashing")
    return {
        "headSha": head_sha,
        "indexTreeSha": index_tree_sha,
        "trackedDiffSha256": hashlib.sha256(tracked_diff).hexdigest(),
        "untracked": untracked,
        "filesystemSha256": filesystem_sha256,
        "gitControlsSha256": git_controls_sha256,
        "managedWorktreesSha256": managed_worktrees_sha256,
    }


def root_snapshot(repo: Path) -> dict[str, object]:
    first = _root_snapshot_once(repo)
    second = _root_snapshot_once(repo)
    if first != second:
        _fail("root snapshot changed between passes")
    return second


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
        opened = os.fstat(directory_fd)
        identity = (opened.st_dev, opened.st_ino)
        _require_pinned_directory_path(path.parent, directory_fd, identity)
        _atomic_json_write_at(directory_fd, path.name, data)
        _require_pinned_directory_path(path.parent, directory_fd, identity)


def _atomic_json_create(path: Path, data: dict[str, object]) -> bool:
    with _open_state_dir(path.parent) as directory_fd:
        opened = os.fstat(directory_fd)
        identity = (opened.st_dev, opened.st_ino)
        _require_pinned_directory_path(path.parent, directory_fd, identity)
        created = _atomic_json_create_at(directory_fd, path.name, data)
        _require_pinned_directory_path(path.parent, directory_fd, identity)
        return created


def atomic_write(path: Path, data: dict[str, object]) -> None:
    validate_manifest(data)
    _atomic_json_write(path, data)


def initialize_manifest(path: Path) -> tuple[dict[str, object], bool]:
    data = empty_manifest()
    validate_manifest(data)
    with _open_state_dir(path.parent) as directory_fd:
        opened = os.fstat(directory_fd)
        identity = (opened.st_dev, opened.st_ino)
        _require_pinned_directory_path(path.parent, directory_fd, identity)
        created = _atomic_json_create_at(directory_fd, path.name, data)
        _require_pinned_directory_path(path.parent, directory_fd, identity)
        if created:
            return data, True
        existing = _load_manifest_at(directory_fd, path.name, str(path))
        _require_pinned_directory_path(path.parent, directory_fd, identity)
        return existing, False


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
    worktree_value = lane_copy.get("worktree")
    if not isinstance(worktree_value, str):
        _fail("lane.worktree must be an absolute path")
    try:
        worktree = Path(worktree_value).resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise ValueError("lane.worktree cannot be resolved") from error
    observed = observe_lane_worktree(worktree)
    if observed["branch"] != lane_copy.get("branch"):
        _fail("allocated worktree branch does not match lane.branch")
    if observed["headSha"] != lane_copy.get("headSha"):
        _fail("allocated worktree HEAD does not match lane.headSha")
    lane_copy.update(observed)
    if lane_copy.get("mergeabilityState") != "not_run":
        _fail("new lane mergeability must be not_run")
    if lane_copy.get("remoteSha") is not None:
        _fail("new lane remoteSha must be null")
    if lane_copy.get("pr") != {"number": None, "url": None}:
        _fail("new lane pull request must be empty")
    if lane_copy.get("blocker") is not None:
        _fail("new lane blocker must be null")
    native_lab = lane_copy.get("nativeLabRequirement")
    native_requirement = (
        native_lab.get("state")
        if isinstance(native_lab, dict)
        else None
    )
    gates = lane_copy.get("gates")
    if not isinstance(gates, dict):
        _fail("new lane gates must be an object")
    for gate_name, observation in gates.items():
        if not isinstance(observation, dict):
            _fail(f"new lane gate {gate_name} must be an object")
        expected_state = (
            "not_required"
            if gate_name == "native_lab"
            and native_requirement == "not_required"
            else "not_run"
        )
        if observation.get("state") != expected_state:
            _fail(f"new lane gate {gate_name} must be {expected_state}")
    require_lane_worktree_current(lane_copy)
    lanes[key] = lane_copy
    _touch(candidate)
    _commit_candidate(data, candidate)


def _require_ready_for_adam(
    data: dict[str, object],
    lane: dict[str, object],
) -> None:
    if lane["pr"]["number"] is None:
        _fail("ready_for_adam requires a pull request")
    if lane["remoteSha"] != lane["headSha"]:
        _fail("ready_for_adam requires local head and remote SHA identity")
    if lane["implementationState"] != "green":
        _fail("ready_for_adam requires green implementation state")
    if lane["role"] == "coder" and not lane["redEvidence"]:
        _fail("ready_for_adam requires coder RED evidence")
    if lane["mergeabilityState"] != "mergeable":
        _fail("ready_for_adam requires mergeable state")
    if lane["blocker"] is not None:
        _fail("ready_for_adam requires no blocker")
    lane_key = str(lane["issue"])
    matching_waves = [
        wave
        for wave in data["rootSafety"]["stage2Waves"].values()
        if lane_key in wave["laneBindings"]
    ]
    if len(matching_waves) != 1 or matching_waves[0]["after"] is None:
        _fail("ready_for_adam requires a completed Stage 2 wave snapshot")
    binding = matching_waves[0]["laneBindings"][lane_key]
    if (
        binding["allocationBaseSha"] != lane["allocationBaseSha"]
        or binding["worktree"] != lane["worktree"]
    ):
        _fail("ready_for_adam Stage 2 lane binding is stale")
    required_gates = {
        "focused": "passed",
        "aggregate": "passed",
        "conformance": "passed",
        "coderabbit": "passed",
        "independent_review": "passed",
        "mergeability": "mergeable",
    }
    for review_gate in ("coderabbit", "independent_review"):
        artifact = _validated_observation_artifact(
            lane["gates"][review_gate],
            f"ready_for_adam {review_gate}",
        )
        if artifact.get("kind") != "github_review" or artifact.get("isDraft") is not True:
            _fail("ready_for_adam requires draft pull request review evidence")
    for gate_name, required_state in required_gates.items():
        if lane["gates"][gate_name]["state"] != required_state:
            _fail(
                f"ready_for_adam requires current {gate_name} "
                f"state {required_state}"
            )
    native_required = lane["nativeLabRequirement"]["state"] == "required"
    native_state = lane["gates"]["native_lab"]["state"]
    expected_native = "passed" if native_required else "not_required"
    if native_state != expected_native:
        _fail(f"ready_for_adam requires native_lab state {expected_native}")
    for dependency in lane["dependsOn"]:
        dependency_lane = data["lanes"][str(dependency)]
        if dependency_lane["laneState"] not in {"ready_for_adam", "merged"}:
            _fail(
                f"ready_for_adam requires dependency {dependency} delivered"
            )


def _demote_ready_dependents(
    data: dict[str, object],
    upstream_issue: str,
) -> None:
    pending = [int(upstream_issue)]
    while pending:
        delivered_issue = pending.pop(0)
        for lane_key, lane in data["lanes"].items():
            if (
                delivered_issue not in lane["dependsOn"]
                or lane["laneState"] != "ready_for_adam"
            ):
                continue
            lane["laneState"] = "reviewing"
            lane["nextAction"] = (
                f"revalidate dependency delivery after issue {delivered_issue}"
            )
            pending.append(int(lane_key))


def transition_lane(data: dict[str, object], issue: str, state: str) -> None:
    validate_manifest(data)
    _require_enum(state, LANE_STATES, "lane state")
    candidate = deepcopy(data)
    lane = _lane(candidate, issue)
    current = lane["laneState"]
    if state not in TRANSITIONS[current]:
        _fail(f"invalid lane transition: {current} -> {state}")
    if state == "ready_for_adam":
        require_lane_worktree_current(lane)
    if state == "ready_for_adam":
        _require_ready_for_adam(candidate, lane)
    lane["laneState"] = state
    if state == "ready_for_adam":
        require_lane_worktree_current(lane)
    if (
        current in {"ready_for_adam", "merged"}
        and state not in {"ready_for_adam", "merged"}
    ):
        _demote_ready_dependents(candidate, issue)
    _touch(candidate)
    _commit_candidate(data, candidate)


def _stale_observation(observation: dict[str, object]) -> None:
    if observation["state"] not in {"not_run", "not_required"}:
        observation["state"] = "stale"


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
    lane = _lane(candidate, issue)
    require_lane_worktree_current(lane, expected_head=head_sha)
    changed = (
        head_sha != lane["headSha"]
        or current_base_sha != lane["currentBaseSha"]
    )
    was_ready = lane["laneState"] == "ready_for_adam"
    _apply_heads(
        lane,
        head_sha=head_sha,
        current_base_sha=current_base_sha,
    )
    require_lane_worktree_current(lane)
    if changed and was_ready:
        lane["laneState"] = "reviewing"
        lane["nextAction"] = "revalidate gates after head update"
        _demote_ready_dependents(candidate, issue)
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
            patterns = [
                _compile_path_glob(pattern)
                for pattern in lane["sharedContractPaths"]
            ]
            if not any(
                _path_glob_matches(changed_path, pattern)
                for changed_path in paths
                for pattern in patterns
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
        lane_binding=lane,
        lane_head=lane["headSha"],
        current_base=lane["currentBaseSha"],
        require_matching_head=True,
        require_matching_base=True,
    )


def record_red(data: dict[str, object], issue: str, observation: dict[str, object]) -> None:
    validate_manifest(data)
    candidate = deepcopy(data)
    lane = _lane(candidate, issue)
    require_lane_worktree_current(lane)
    observation_copy = deepcopy(observation)
    _validate_new_observation(lane, observation_copy, "RED observation", {"failed"})
    artifact = _validated_observation_artifact(
        observation_copy,
        "RED observation",
    )
    if (
        artifact["kind"] != "repo_check"
        or artifact["outcome"] != "completed"
        or artifact["failureClassification"] != "command_failure"
        or observation_copy["redClassification"] is None
    ):
        _fail(
            "RED observation requires command failure evidence and "
            "Main-reviewed expected assertion classification"
        )
    lane["redEvidence"].append(observation_copy)
    lane["implementationState"] = "red"
    require_lane_worktree_current(lane)
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

    artifact = _validated_observation_artifact(
        observation,
        f"gate {gate}",
    )

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
        if artifact["isDraft"] is not True:
            _fail("base evidence artifact.isDraft must be true")
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
    _require_command(
        artifact["integrationCommand"],
        "base evidence artifact.integrationCommand",
    )
    _require_command(
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
    require_lane_worktree_current(lane)
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
    require_lane_worktree_current(lane)
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


def _require_pinned_directory_path(
    path: Path,
    directory_fd: int,
    identity: tuple[int, int],
) -> None:
    try:
        named = path.lstat()
        opened = os.fstat(directory_fd)
    except OSError as error:
        raise ValueError(
            f"cannot revalidate state directory path {path}: {error}"
        ) from error
    if (
        stat.S_ISLNK(named.st_mode)
        or not stat.S_ISDIR(named.st_mode)
        or not stat.S_ISDIR(opened.st_mode)
        or stat.S_IMODE(named.st_mode) != 0o700
        or stat.S_IMODE(opened.st_mode) != 0o700
        or (named.st_dev, named.st_ino) != identity
        or (opened.st_dev, opened.st_ino) != identity
    ):
        _fail(f"state directory path no longer names the pinned directory: {path}")


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
        pinned_directory = os.fstat(directory_fd)
        pinned_directory_identity = (
            pinned_directory.st_dev,
            pinned_directory.st_ino,
        )
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
                        _require_pinned_directory_path(
                            path.parent,
                            directory_fd,
                            pinned_directory_identity,
                        )
                        _persist_mutation(
                            directory_fd,
                            path.name,
                            candidate,
                            current["updatedAt"],
                        )
                        _require_pinned_directory_path(
                            path.parent,
                            directory_fd,
                            pinned_directory_identity,
                        )
                    raise
                except (OSError, ValueError) as error:
                    raise TerminalRejection(str(error)) from error
                _require_pinned_directory_path(
                    path.parent,
                    directory_fd,
                    pinned_directory_identity,
                )
                _persist_mutation(
                    directory_fd,
                    path.name,
                    candidate,
                    current["updatedAt"],
                )
                _require_pinned_directory_path(
                    path.parent,
                    directory_fd,
                    pinned_directory_identity,
                )
                return candidate
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
        FEATURE_OWNER_STATES,
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
    _require_enum(state, FEATURE_OWNER_STATES, "feature owner state")
    owner = _load_feature_owner(path)
    if owner["state"] == state:
        return
    if owner["state"] == "released":
        _fail("released feature owner state is terminal")
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
    validated_number = _require_int(number, "PR number", minimum=1)
    expected = f"{PR_URL_PREFIX}{validated_number}"
    if _require_nonempty_string(url, "PR URL") != expected:
        _fail(f"PR URL must be exactly {expected}")


def record_pr(data: dict[str, object], issue: str, number: int, url: str) -> None:
    validate_manifest(data)
    _validate_pr(number, url)
    candidate = deepcopy(data)
    lane = _lane(candidate, issue)
    changed = lane["pr"] != {"number": number, "url": url}
    lane["pr"] = {"number": number, "url": url}
    if changed:
        for gate in ("coderabbit", "independent_review", "mergeability"):
            _stale_observation(lane["gates"][gate])
        lane["mergeabilityState"] = "stale"
    _touch(candidate)
    _commit_candidate(data, candidate)


def record_remote(data: dict[str, object], issue: str, remote_sha: str) -> None:
    validate_manifest(data)
    _require_sha(remote_sha, "remote SHA")
    candidate = deepcopy(data)
    lane = _lane(candidate, issue)
    changed = lane["remoteSha"] != remote_sha
    lane["remoteSha"] = remote_sha
    if changed:
        for gate in ("coderabbit", "independent_review", "mergeability"):
            _stale_observation(lane["gates"][gate])
        lane["mergeabilityState"] = "stale"
    _touch(candidate)
    _commit_candidate(data, candidate)


def _validate_root_snapshot_payload(snapshot: dict[str, object]) -> None:
    _require_exact_keys(
        snapshot,
        _ROOT_SNAPSHOT_KEYS,
        "root snapshot artifact",
    )
    _require_sha(snapshot["headSha"], "root snapshot artifact.headSha")
    _require_sha(
        snapshot["indexTreeSha"],
        "root snapshot artifact.indexTreeSha",
    )
    for field in (
        "trackedDiffSha256",
        "filesystemSha256",
        "gitControlsSha256",
        "managedWorktreesSha256",
    ):
        _require_sha256(
            snapshot[field],
            f"root snapshot artifact.{field}",
        )
    untracked = snapshot["untracked"]
    if not isinstance(untracked, list):
        _fail("root snapshot artifact.untracked must be a list")
    paths: list[str] = []
    for index, entry in enumerate(untracked):
        label = f"root snapshot artifact.untracked[{index}]"
        if not isinstance(entry, dict):
            _fail(f"{label} must be an object")
        _require_exact_keys(entry, {"path", "sha256"}, label)
        path = _require_nonempty_string(entry["path"], f"{label}.path")
        _require_observed_repo_relative(path, f"{label}.path")
        if path == ".worktrees" or path.startswith(".worktrees/"):
            _fail(f"{label}.path must not name a managed worktree")
        _require_sha256(entry["sha256"], f"{label}.sha256")
        paths.append(path)
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        _fail(
            "root snapshot artifact.untracked paths must be unique and sorted"
        )


def _read_valid_root_snapshot_artifact(
    artifact_uri: str,
) -> tuple[str, dict[str, object]]:
    parsed = urlparse(artifact_uri)
    if (
        parsed.scheme != "file"
        or parsed.netloc not in {"", "localhost"}
        or parsed.query
        or parsed.fragment
    ):
        _fail("root snapshot artifact must be a local file:// URI")
    artifact_path = Path(unquote(parsed.path))
    before_parents = _non_symlink_parent_chain(artifact_path)
    file_descriptor: int | None = None
    try:
        expected = artifact_path.lstat()
        if stat.S_ISLNK(expected.st_mode):
            _fail("root snapshot artifact must not be a symlink")
        if not stat.S_ISREG(expected.st_mode):
            _fail("root snapshot artifact must be a regular file")
        file_descriptor = os.open(
            artifact_path,
            os.O_RDONLY | os.O_NOFOLLOW,
        )
        opened = os.fstat(file_descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _stable_stat_identity(expected)
            != _stable_stat_identity(opened)
        ):
            _fail("root snapshot artifact changed while opening")
        digest = hashlib.sha256()
        content = bytearray()
        while chunk := os.read(file_descriptor, ARTIFACT_HASH_CHUNK_SIZE):
            digest.update(chunk)
            content.extend(chunk)
        if (
            _stable_stat_identity(opened)
            != _stable_stat_identity(os.fstat(file_descriptor))
        ):
            _fail("root snapshot artifact changed while reading")
    except OSError as error:
        raise ValueError(f"cannot read root snapshot artifact: {error}") from error
    finally:
        if file_descriptor is not None:
            os.close(file_descriptor)
    try:
        current = artifact_path.lstat()
    except OSError as error:
        raise ValueError(f"cannot verify root snapshot artifact: {error}") from error
    if (
        _stable_stat_identity(expected)
        != _stable_stat_identity(current)
    ):
        _fail("root snapshot artifact changed while reading")
    if before_parents != _non_symlink_parent_chain(artifact_path):
        _fail("root snapshot artifact path changed while reading")
    try:
        artifact_text = content.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError(
            "root snapshot artifact must be valid UTF-8 JSON"
        ) from error
    snapshot = _decode_json_object(artifact_text, str(artifact_path))
    _validate_root_snapshot_payload(snapshot)
    return digest.hexdigest(), snapshot


def record_root_snapshot(
    data: dict[str, object],
    slot: str,
    artifact: str,
    *,
    wave_id: str | None = None,
    issues: Sequence[int] | None = None,
) -> None:
    validate_manifest(data)
    if slot not in {
        "stage1Before",
        "stage1After",
        "stage2Before",
        "stage2After",
    }:
        _fail(f"invalid root snapshot slot: {slot}")
    artifact_uri = _require_nonempty_string(
        artifact,
        "root snapshot artifact",
    )
    artifact_sha256, snapshot = _read_valid_root_snapshot_artifact(artifact_uri)
    artifact_ref = {
        "artifact": artifact_uri,
        "sha256": artifact_sha256,
    }
    candidate = deepcopy(data)
    root_safety = candidate["rootSafety"]

    if slot in {"stage1Before", "stage1After"}:
        if wave_id is not None or issues is not None:
            _fail("Stage 1 root snapshots do not accept wave metadata")
        if root_safety[slot] is not None:
            _fail(f"root snapshot slot {slot} is immutable once recorded")
        if slot == "stage1After":
            before = root_safety["stage1Before"]
            if before is None:
                _fail("stage1After requires stage1Before")
            if before["sha256"] != artifact_sha256:
                _fail("Stage 1 before and after root snapshots must match")
        root_safety[slot] = artifact_ref
    else:
        required_wave_id = _require_nonempty_string(
            wave_id,
            "Stage 2 wave ID",
        )
        issue_numbers = _require_issue_list(
            list(issues) if issues is not None else None,
            "Stage 2 wave issues",
        )
        if not issue_numbers or issue_numbers != sorted(issue_numbers):
            _fail("Stage 2 wave issues must be non-empty and sorted")
        issue_keys = [str(issue) for issue in issue_numbers]
        if slot == "stage2Before":
            stage2_waves = root_safety["stage2Waves"]
            if required_wave_id in stage2_waves:
                _fail("Stage 2 wave root snapshot is immutable once recorded")
            allocated = sorted(
                int(issue)
                for issue, lane in candidate["lanes"].items()
                if lane["laneState"] == "allocated"
            )
            if issue_numbers != allocated:
                _fail(
                    "Stage 2 before snapshot must bind the complete allocated wave"
                )
            bindings = {
                issue: {
                    "allocationBaseSha": candidate["lanes"][issue][
                        "allocationBaseSha"
                    ],
                    "worktree": candidate["lanes"][issue]["worktree"],
                }
                for issue in issue_keys
            }
            stage2_waves[required_wave_id] = {
                "waveId": required_wave_id,
                "laneBindings": bindings,
                "managedWorktreesSha256": snapshot[
                    "managedWorktreesSha256"
                ],
                "before": artifact_ref,
                "after": None,
            }
        else:
            wave = root_safety["stage2Waves"].get(required_wave_id)
            if wave is None:
                _fail("stage2After requires a matching Stage 2 before snapshot")
            if wave["after"] is not None:
                _fail("Stage 2 after snapshot is immutable once recorded")
            if wave["waveId"] != required_wave_id:
                _fail("Stage 2 after snapshot wave ID does not match")
            if issue_numbers != sorted(int(issue) for issue in wave["laneBindings"]):
                _fail("Stage 2 after snapshot lane set does not match")
            if any(
                candidate["lanes"][issue]["laneState"]
                not in {"reviewing", "ready_for_adam"}
                for issue in issue_keys
            ):
                _fail("Stage 2 after snapshot requires every wave lane reviewing")
            if (
                snapshot["managedWorktreesSha256"]
                != wave["managedWorktreesSha256"]
            ):
                _fail("Stage 2 managed worktree registration set changed")
            if artifact_sha256 != wave["before"]["sha256"]:
                _fail("Stage 2 before and after root snapshots must match")
            wave["after"] = artifact_ref
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
        choices=FEATURE_OWNER_STATES,
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
    root_parser.add_argument("--wave-id")
    root_parser.add_argument("--issues", nargs="+", type=int)

    acquire_parser = subparsers.add_parser("acquire-gate")
    _add_manifest_mutation_arguments(acquire_parser)
    acquire_parser.add_argument("--issue", required=True)
    acquire_parser.add_argument("--at", required=True)

    release_parser = subparsers.add_parser("release-gate")
    _add_manifest_mutation_arguments(release_parser)
    release_parser.add_argument("--issue", required=True)

    check_parser = subparsers.add_parser("check-paths")
    check_parser.add_argument("--manifest", type=Path, required=True)
    check_parser.add_argument("--issue", required=True)
    check_parser.add_argument("--approved-delete-path")

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
            manifest = load_manifest_readonly(args.manifest)
            lane = _lane(manifest, args.issue)
            require_lane_worktree_current(lane)
            worktree = Path(lane["worktree"])
            paths = changed_paths(
                worktree,
                lane["allocationBaseSha"],
            )
            disallowed = _disallowed_changed_paths(
                worktree,
                lane["allocationBaseSha"],
                paths,
                lane["allowedPaths"],
                approved_delete_path=args.approved_delete_path,
            )
            require_lane_worktree_current(lane)
            if disallowed:
                raise TerminalRejection(
                    "disallowed paths: " + ", ".join(disallowed)
                )
            result = {"ok": True, "paths": paths, "disallowed": []}
            if args.approved_delete_path is not None:
                result["approvedDeletePath"] = args.approved_delete_path
            _print_json(result)
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
                record_root_snapshot(
                    data,
                    args.slot,
                    args.artifact,
                    wave_id=args.wave_id,
                    issues=args.issues,
                )
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
