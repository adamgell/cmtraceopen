from __future__ import annotations

from copy import deepcopy
import hashlib
import importlib.util
import io
import json
import os
import shlex
import shutil
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from urllib.parse import unquote, urlparse


SCRIPT_PATH = Path(__file__).parents[1] / "scripts" / "lane_state.py"
SPEC = importlib.util.spec_from_file_location("lane_state", SCRIPT_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load lane state helpers from {SCRIPT_PATH}")
lane_state = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lane_state)

SHA_A = "a" * 40
SHA_B = "b" * 40
PR_URL = "https://github.com/adamgell/cmtraceopen/pull/42"
PR_43_URL = "https://github.com/adamgell/cmtraceopen/pull/43"
SHA_C = "c" * 40
NOW = "2026-08-14T12:00:00+00:00"
LATER = "2026-08-14T12:05:00+00:00"
ALLOWED_PATHS = ["crates/cmtraceopen-parser/**"]
STAGE1_ALLOWED_PATHS = [
    ".omp/**",
    ".Clairvoyance/library.md",
    ".Clairvoyance/kickoff-prompt.md",
    ".Clairvoyance/staff/**",
    ".claude/skills/coderabbit-review-loop/**",
    "docs/superpowers/specs/2026-08-14-omp-agent-driven-development-design.md",
    "docs/superpowers/plans/2026-08-14-omp-agent-driven-development.md",
]
CHECK_COMMAND = ["python3", "-m", "unittest", "test_lane_state", "-v"]


def path_identity(path: Path) -> dict[str, int]:
    info = path.lstat()
    return {"device": info.st_dev, "inode": info.st_ino}


def artifact_ref(path: Path) -> dict[str, str]:
    content = path.read_bytes()
    return {
        "uri": path.resolve().as_uri(),
        "sha256": hashlib.sha256(content).hexdigest(),
    }


def artifact_path(reference: object) -> Path:
    assert isinstance(reference, dict)
    uri = reference["uri"]
    assert isinstance(uri, str)
    return Path(unquote(urlparse(uri).path))


def write_repo_check_artifact(
    root: Path,
    *,
    head_sha: str = SHA_A,
    base_sha: str = SHA_B,
    exit_code: int = 0,
    command: list[str] | None = None,
    outcome: str = "completed",
    classification: str | None = None,
    name: str = "repo-check",
    worktree: Path | None = None,
    worktree_identity: dict[str, int] | None = None,
    git_common_dir: Path | None = None,
    branch: str = "omp/issue-317",
) -> dict[str, str]:
    command = CHECK_COMMAND.copy() if command is None else command
    if classification is None:
        classification = "success" if exit_code == 0 else "command_failure"
    worktree = root if worktree is None else worktree
    if worktree_identity is None:
        worktree_identity = path_identity(worktree)
    git_common_dir = root if git_common_dir is None else git_common_dir
    artifact = {
        "schemaVersion": 2,
        "kind": "repo_check",
        "outcome": outcome,
        "command": command,
        "worktree": str(worktree.resolve()),
        "worktreeIdentity": worktree_identity,
        "gitCommonDir": str(git_common_dir.resolve()),
        "branch": branch,
        "headSha": head_sha,
        "baseSha": base_sha,
        "exitCode": exit_code,
        "observedAt": NOW,
        "stdout": (
            "AssertionError: requested behavior absent"
            if exit_code != 0
            else ""
        ),
        "stderr": "",
        "stdoutTruncated": False,
        "stderrTruncated": False,
        "failureClassification": classification,
        "error": None if outcome == "completed" else f"{outcome} error",
    }
    path = root / f"{name}.json"
    path.write_text(
        json.dumps(artifact, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    return artifact_ref(path)

def reviewed_red(reference: dict[str, str]) -> dict[str, str]:
    return {
        "kind": "main_reviewed_expected_assertion_failure",
        "artifactSha256": reference["sha256"],
        "focusedTest": "test_lane_state.py::focused",
        "fixture": "tests/fixtures/focused.json",
        "expectedAssertion": "requested behavior absent",
        "reviewedAt": NOW,
    }



def root_snapshot_fixture() -> dict[str, object]:
    return {
        "headSha": SHA_A,
        "indexTreeSha": SHA_B,
        "trackedDiffSha256": "0" * 64,
        "untracked": [
            {
                "path": "scratch.txt",
                "sha256": "1" * 64,
            }
        ],
        "filesystemSha256": "2" * 64,
        "gitControlsSha256": "3" * 64,
        "managedWorktreesSha256": "4" * 64,
    }

TEST_GIT_TIMEOUT_SECONDS = 15.0


def git_test_environment() -> dict[str, str]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("GIT_")
    }
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_CONFIG_COUNT": "3",
            "GIT_CONFIG_KEY_0": "core.hooksPath",
            "GIT_CONFIG_VALUE_0": os.devnull,
            "GIT_CONFIG_KEY_1": "commit.gpgSign",
            "GIT_CONFIG_VALUE_1": "false",
            "GIT_CONFIG_KEY_2": "tag.gpgSign",
            "GIT_CONFIG_VALUE_2": "false",
        }
    )
    return environment


def run_git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=git_test_environment(),
        timeout=TEST_GIT_TIMEOUT_SECONDS,
    )
    return result.stdout.strip()


def clone_git_repo(source: Path, destination: Path) -> None:
    subprocess.run(
        [
            "git",
            "clone",
            "--quiet",
            "--no-hardlinks",
            str(source),
            str(destination),
        ],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=git_test_environment(),
        timeout=TEST_GIT_TIMEOUT_SECONDS,
    )


def run_git_unchecked(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=git_test_environment(),
        timeout=TEST_GIT_TIMEOUT_SECONDS,
    )

def create_git_repo(root: Path) -> tuple[Path, str]:
    repo = root / "repo"
    repo.mkdir()
    run_git(repo, "init", "--quiet")
    run_git(repo, "config", "user.name", "Lane State Tests")
    run_git(repo, "config", "user.email", "lane-state@example.invalid")
    (repo / "owned.txt").write_text("baseline\n", encoding="utf-8")
    run_git(repo, "add", "owned.txt")
    run_git(repo, "commit", "--quiet", "-m", "baseline")
    return repo, run_git(repo, "rev-parse", "HEAD")


def gate(state: str = "not_run", *, base_sensitive: bool = False) -> dict[str, object]:
    return {
        "state": state,
        "headSha": None,
        "baseSha": None,
        "command": None,
        "scenario": None,
        "exitCode": None,
        "observedAt": None,
        "artifact": None,
        "redClassification": None,
        "baseSensitive": base_sensitive,
    }


def valid_lane(
    worktree: Path,
    *,
    issue: int = 317,
    state: str = "allocated",
) -> dict[str, object]:
    return {
        "issue": issue,
        "title": f"issue {issue} title",
        "agentId": "Task",
        "role": "coder",
        "worktree": str(worktree.resolve()),
        "worktreeIdentity": (
            path_identity(worktree)
            if worktree.exists()
            else {"device": 0, "inode": issue}
        ),
        "gitCommonDir": str(worktree.resolve()),
        "branch": f"omp/issue-{issue}",
        "allowedPaths": ALLOWED_PATHS.copy(),
        "dependsOn": [],
        "sharedContractPaths": [],
        "integrationOrder": issue,
        "headSha": SHA_A,
        "allocationBaseSha": SHA_B,
        "currentBaseSha": SHA_B,
        "remoteSha": None,
        "pr": {"number": None, "url": None},
        "lease": {
            "owner": "Task",
            "expiresAt": LATER,
            "heartbeatAt": NOW,
            "lastVerifiedAt": NOW,
        },
        "laneState": state,
        "implementationState": "not_run",
        "mergeabilityState": "not_run",
        "redEvidence": [],
        "blocker": None,
        "nextAction": "record RED",
        "gates": {
            "focused": gate(),
            "aggregate": gate(base_sensitive=True),
            "conformance": gate(base_sensitive=True),
            "coderabbit": gate(base_sensitive=True),
            "independent_review": gate(base_sensitive=True),
            "native_lab": gate("not_required"),
            "mergeability": gate(base_sensitive=True),
        },
        "nativeLabRequirement": {
            "state": "not_required",
            "reason": "issue contract",
        },
    }


def create_registered_lane(
    root: Path,
    *,
    issue: int = 317,
) -> tuple[Path, Path, dict[str, object], str]:
    primary, head_sha = create_git_repo(root)
    worktree = root / f"registered-lane-{issue}"
    branch = f"omp/issue-{issue}"
    run_git(
        primary,
        "worktree",
        "add",
        "--quiet",
        "-b",
        branch,
        str(worktree),
        head_sha,
    )
    lane = valid_lane(worktree, issue=issue)
    lane["headSha"] = head_sha
    lane["allocationBaseSha"] = head_sha
    lane["currentBaseSha"] = head_sha
    lane["allowedPaths"] = ["owned.txt"]
    manifest = lane_state.empty_manifest()
    lane_state.allocate_lane(manifest, lane)
    return primary, worktree, manifest, head_sha


def valid_observation(
    root: Path,
    *,
    state: str = "passed",
    head_sha: str = SHA_A,
    base_sha: str = SHA_B,
    base_sensitive: bool = False,
    exit_code: int | None = None,
    classification: str | None = None,
    outcome: str = "completed",
    name: str | None = None,
    include_red_review: bool | None = None,
    lane: dict[str, object] | None = None,
) -> dict[str, object]:
    if exit_code is None:
        exit_code = 1 if state == "failed" else 0
    if name is None:
        name = (
            f"repo-check-{head_sha[0]}-{base_sha[0]}-"
            f"{exit_code}-{classification or 'default'}-{outcome}"
        )
    artifact = write_repo_check_artifact(
        root,
        head_sha=head_sha,
        base_sha=base_sha,
        exit_code=exit_code,
        classification=classification,
        outcome=outcome,
        name=name,
        worktree=(
            root
            if lane is None
            else Path(str(lane["worktree"]))
        ),
        worktree_identity=(
            None
            if lane is None
            else lane["worktreeIdentity"]
        ),
        git_common_dir=(
            None
            if lane is None
            else Path(str(lane["gitCommonDir"]))
        ),
        branch=(
            "omp/issue-317"
            if lane is None
            else str(lane["branch"])
        ),
    )
    if include_red_review is None:
        include_red_review = state == "failed"
    return {
        "state": state,
        "headSha": head_sha,
        "baseSha": base_sha,
        "command": CHECK_COMMAND.copy(),
        "scenario": None,
        "exitCode": exit_code,
        "observedAt": NOW,
        "artifact": artifact,
        "redClassification": (
            reviewed_red(artifact) if include_red_review else None
        ),
        "baseSensitive": base_sensitive,
    }


def observed_lane(
    lane: dict[str, object],
    *,
    expected_head: str | None = None,
) -> dict[str, object]:
    return {
        "worktree": lane["worktree"],
        "worktreeIdentity": lane["worktreeIdentity"],
        "gitCommonDir": lane["gitCommonDir"],
        "branch": lane["branch"],
        "headSha": lane["headSha"] if expected_head is None else expected_head,
    }


def allocate_test_lane(
    manifest: dict[str, object],
    lane: dict[str, object],
) -> None:
    worktree = Path(str(lane["worktree"]))
    if worktree.is_absolute() and worktree.exists():
        lane["worktree"] = str(worktree.resolve())
        lane["worktreeIdentity"] = path_identity(worktree)
    with mock.patch.object(
        lane_state,
        "observe_lane_worktree",
        return_value=observed_lane(lane),
    ):
        lane_state.allocate_lane(manifest, lane)


def record_test_red(
    manifest: dict[str, object],
    issue: str,
    observation: dict[str, object],
) -> None:
    with mock.patch.object(
        lane_state,
        "require_lane_worktree_current",
        side_effect=lambda lane, **kwargs: observed_lane(
            lane,
            expected_head=kwargs.get("expected_head"),
        ),
    ):
        lane_state.record_red(manifest, issue, observation)


def record_test_observation(
    manifest: dict[str, object],
    issue: str,
    gate_name: str,
    observation: dict[str, object],
) -> None:
    with mock.patch.object(
        lane_state,
        "require_lane_worktree_current",
        side_effect=lambda lane, **kwargs: observed_lane(
            lane,
            expected_head=kwargs.get("expected_head"),
        ),
    ):
        lane_state.record_observation(
            manifest,
            issue,
            gate_name,
            observation,
        )


def transition_test_lane(
    manifest: dict[str, object],
    issue: str,
    state: str,
) -> None:
    with mock.patch.object(
        lane_state,
        "require_lane_worktree_current",
        side_effect=lambda lane, **kwargs: observed_lane(
            lane,
            expected_head=kwargs.get("expected_head"),
        ),
    ):
        lane_state.transition_lane(manifest, issue, state)


def update_test_heads(
    manifest: dict[str, object],
    issue: str,
    *,
    head_sha: str,
    current_base_sha: str,
) -> None:
    with mock.patch.object(
        lane_state,
        "require_lane_worktree_current",
        side_effect=lambda lane, **kwargs: observed_lane(
            lane,
            expected_head=kwargs.get("expected_head"),
        ),
    ):
        lane_state.update_heads(
            manifest,
            issue,
            head_sha=head_sha,
            current_base_sha=current_base_sha,
        )


def enforce_test_lane_paths(
    manifest: dict[str, object],
    issue: str,
    *,
    approved_delete_path: str | None = None,
) -> list[str]:
    with mock.patch.object(
        lane_state,
        "require_lane_worktree_current",
        side_effect=lambda lane, **kwargs: observed_lane(
            lane,
            expected_head=kwargs.get("expected_head"),
        ),
    ):
        return lane_state.enforce_lane_paths(
            manifest,
            issue,
            approved_delete_path=approved_delete_path,
        )

def clean_coderabbit_review(
    *,
    head_sha: str,
    base_sha: str,
    pr_number: int,
    pr_url: str,
) -> dict[str, object]:
    latest_review = {
        "id": "coderabbit-review",
        "state": "APPROVED",
        "body": "Approved",
        "submittedAt": NOW,
        "author": {"login": "coderabbitai"},
        "commit": {"oid": head_sha},
    }
    return {
        "pull_request": {
            "number": pr_number,
            "url": pr_url,
            "head_sha": head_sha,
            "base_sha": base_sha,
            "is_draft": True,
            "review_decision": "APPROVED",
        },
        "summary": {
            "review_count": 1,
            "coderabbit_review_count": 1,
            "unresolved_thread_count": 0,
            "unresolved_coderabbit_thread_count": 0,
            "latest_coderabbit_review": latest_review,
            "latest_coderabbit_review_state": "APPROVED",
            "approved_at_head": True,
        },
        "unresolved_threads": [],
        "reviews": [latest_review],
    }


def clean_independent_review(
    *,
    head_sha: str,
    base_sha: str,
) -> dict[str, object]:
    return {
        "role": "code-review",
        "phase": "review_report",
        "head_sha": head_sha,
        "base_sha": base_sha,
        "findings": [],
        "gate_states": {
            "ci": "passed",
            "coderabbit": "passed",
            "charter_review": "passed",
            "contract_conformance": "passed",
        },
        "coverage": ["crates/cmtraceopen-parser/src/lib.rs"],
        "blockers": [],
    }


def rewrite_review_raw(
    observation: dict[str, object],
    raw: dict[str, object],
) -> None:
    evidence_path = artifact_path(observation["artifact"])
    artifact = json.loads(evidence_path.read_text(encoding="utf-8"))
    raw_path = Path(unquote(urlparse(artifact["rawEvidenceUri"]).path))
    raw_path.write_text(json.dumps(raw), encoding="utf-8")
    artifact["rawEvidenceSha256"] = hashlib.sha256(raw_path.read_bytes()).hexdigest()
    evidence_path.write_text(json.dumps(artifact), encoding="utf-8")
    observation["artifact"] = artifact_ref(evidence_path)


def write_base_artifact(
    root: Path,
    *,
    kind: str = "synthetic_merge",
    head_sha: str = SHA_A,
    current_base_sha: str = SHA_B,
    name: str = "base-evidence",
    pr_number: int = 42,
    pr_url: str = PR_URL,
    review_gate: str | None = None,
) -> dict[str, str]:
    path = root / f"{name}.json"
    artifact: dict[str, object] = {
        "schemaVersion": 2,
        "kind": kind,
        "headSha": head_sha,
        "currentBaseSha": current_base_sha,
        "integrationCommand": ["git", "merge-tree", "base", "head"],
        "integrationExitCode": 0,
        "gateCommand": CHECK_COMMAND.copy(),
        "gateExitCode": 0,
        "rawEvidenceUri": "file:///tmp/raw-evidence.txt",
        "observedAt": NOW,
    }
    if kind == "github_review":
        if review_gate == "coderabbit":
            raw_evidence = clean_coderabbit_review(
                head_sha=head_sha,
                base_sha=current_base_sha,
                pr_number=pr_number,
                pr_url=pr_url,
            )
        else:
            raw_evidence = clean_independent_review(
                head_sha=head_sha,
                base_sha=current_base_sha,
            )
        raw_path = root / f"{name}-raw.json"
        raw_path.write_text(json.dumps(raw_evidence), encoding="utf-8")
        artifact.update(
            {
                "prNumber": pr_number,
                "prUrl": pr_url,
                "reviewGate": review_gate,
                "isDraft": True,
                "rawEvidenceUri": raw_path.resolve().as_uri(),
                "rawEvidenceSha256": hashlib.sha256(
                    raw_path.read_bytes()
                ).hexdigest(),
            }
        )
    path.write_text(json.dumps(artifact), encoding="utf-8")
    return artifact_ref(path)


def base_observation(
    root: Path,
    gate_name: str,
    *,
    head_sha: str = SHA_A,
    base_sha: str = SHA_B,
    base_sensitive: bool = True,
    pr_number: int = 42,
    pr_url: str = PR_URL,
) -> dict[str, object]:
    kind = (
        "github_review"
        if gate_name in {"coderabbit", "independent_review"}
        else "synthetic_merge"
    )
    observation = valid_observation(
        root,
        state="mergeable" if gate_name == "mergeability" else "passed",
        head_sha=head_sha,
        base_sha=base_sha,
        base_sensitive=base_sensitive,
        name=f"{gate_name}-repo-check-{head_sha[0]}-{base_sha[0]}",
    )
    observation["artifact"] = write_base_artifact(
        root,
        kind=kind,
        head_sha=head_sha,
        current_base_sha=base_sha,
        name=(
            f"{gate_name}-{kind}-{head_sha[0]}-{base_sha[0]}-{pr_number}"
        ),
        pr_number=pr_number,
        pr_url=pr_url,
        review_gate=gate_name if kind == "github_review" else None,
    )
    return observation


def allocate_issue(
    manifest: dict[str, object],
    root: Path,
    issue: int,
    *,
    depends_on: list[int] | None = None,
    shared_contract_paths: list[str] | None = None,
) -> None:
    worktree = root / f"lane-{issue}"
    worktree.mkdir(exist_ok=True)
    lane = valid_lane(worktree, issue=issue)
    lane["agentId"] = lane["lease"]["owner"] = f"Task-{issue}"
    lane["dependsOn"] = [] if depends_on is None else depends_on
    lane["sharedContractPaths"] = (
        [] if shared_contract_paths is None else shared_contract_paths
    )
    allocate_test_lane(manifest, lane)


def record_all_observations(
    manifest: dict[str, object],
    root: Path,
    issue: str,
    *,
    native_base_sensitive: bool = False,
) -> None:
    lane = manifest["lanes"][issue]
    head_sha = lane["headSha"]
    base_sha = lane["currentBaseSha"]
    if native_base_sensitive:
        lane["nativeLabRequirement"] = {
            "state": "required",
            "reason": "issue contract",
        }
        lane["gates"]["native_lab"] = gate()
    if lane["role"] == "coder" and not lane["redEvidence"]:
        record_test_red(manifest, issue, valid_observation(
            root,
            state="failed",
            head_sha=head_sha,
            base_sha=base_sha,
            lane=lane,
            name=f"{issue}-red-{head_sha[0]}-{base_sha[0]}",
        ))
    pr_number = int(issue)
    pr_url = lane_state.PR_URL_PREFIX + issue
    lane_state.record_pr(manifest, issue, pr_number, pr_url)
    lane_state.record_remote(manifest, issue, head_sha)
    record_test_observation(
        manifest,
        issue,
        "focused",
        valid_observation(
            root,
            head_sha=head_sha,
            base_sha=base_sha,
            lane=lane,
            name=f"{issue}-focused-{head_sha[0]}-{base_sha[0]}",
        ),
    )
    for gate_name in (
        "aggregate",
        "conformance",
        "coderabbit",
        "independent_review",
        "mergeability",
    ):
        record_test_observation(manifest, issue, gate_name, base_observation(
            root,
            gate_name,
            head_sha=head_sha,
            base_sha=base_sha,
            pr_number=pr_number,
            pr_url=pr_url,
        ))
    if native_base_sensitive:
        record_test_observation(manifest, issue, "native_lab", base_observation(
            root,
            "native_lab",
            head_sha=head_sha,
            base_sha=base_sha,
        ))

def prepare_ready_lane(
    manifest: dict[str, object],
    root: Path,
    issue: str,
) -> None:
    artifact = root / "stage2-root.json"
    artifact.write_text(
        json.dumps(root_snapshot_fixture()),
        encoding="utf-8",
    )
    artifact_uri = artifact.resolve().as_uri()
    lane_state.record_root_snapshot(
        manifest,
        "stage2Before",
        artifact_uri,
        wave_id="wave-ready",
        issues=[int(issue)],
    )
    record_all_observations(manifest, root, issue)
    manifest["lanes"][issue]["implementationState"] = "green"
    transition_test_lane(manifest, issue, "running")
    transition_test_lane(manifest, issue, "reviewing")
    lane_state.record_root_snapshot(
        manifest,
        "stage2After",
        artifact_uri,
        wave_id="wave-ready",
        issues=[int(issue)],
    )


def write_manifest(root: Path, manifest: dict[str, object]) -> Path:
    common = root / "common"
    common.mkdir()
    path = common / "omp" / "lanes.json"
    lane_state.atomic_write(path, manifest)
    return path
def valid_feature_owner(worktree: Path, *, state: str = "active") -> dict[str, object]:
    return {
        "schemaVersion": 2,
        "owner": "OmpOverlayOwner",
        "role": "coder",
        "worktree": str(worktree.resolve()),
        "allowedPaths": STAGE1_ALLOWED_PATHS.copy(),
        "state": state,
        "assignedAt": NOW,
        "transferCount": 0,
        "evidenceInvalidatedAt": None,
    }


class ManifestTests(unittest.TestCase):
    def test_empty_manifest_has_schema_and_free_semaphore(self) -> None:
        manifest = lane_state.empty_manifest()

        self.assertEqual(2, manifest["schemaVersion"])
        self.assertEqual({}, manifest["lanes"])
        self.assertEqual(
            {"holder": None, "queue": [], "acquiredAt": None},
            manifest["aggregateGate"],
        )
        self.assertEqual(
            {
                "stage1Before": None,
                "stage1After": None,
                "stage2Waves": {},
            },
            manifest["rootSafety"],
        )
        self.assertTrue(str(manifest["updatedAt"]).endswith("+00:00"))
        lane_state.validate_manifest(manifest)

    def test_atomic_write_round_trips_valid_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            common = Path(directory) / "common"
            common.mkdir()
            path = common / "omp" / "lanes.json"
            manifest = lane_state.empty_manifest()

            lane_state.atomic_write(path, manifest)

            self.assertEqual(manifest, lane_state.load_manifest(path))
            self.assertEqual([path], list(path.parent.iterdir()))

    def test_state_directory_swap_cannot_redirect_atomic_write(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            common = root / "common"
            state_dir = common / "omp"
            state_dir.mkdir(parents=True, mode=0o700)
            displaced = common / "opened-omp"
            attacker = root / "attacker"
            attacker.mkdir(mode=0o700)
            path = state_dir / "lanes.json"
            real_write_temporary_json = lane_state._write_temporary_json

            def swap_before_tempfile(*args: object, **kwargs: object) -> object:
                state_dir.rename(displaced)
                state_dir.symlink_to(attacker, target_is_directory=True)
                return real_write_temporary_json(*args, **kwargs)

            with mock.patch.object(
                lane_state,
                "_write_temporary_json",
                side_effect=swap_before_tempfile,
            ), self.assertRaisesRegex(
                ValueError, "no longer names the pinned directory"
            ):
                lane_state.atomic_write(path, lane_state.empty_manifest())

            self.assertTrue((displaced / "lanes.json").is_file())
            self.assertFalse((attacker / "lanes.json").exists())

    def test_invalid_gate_state_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            valid = lane_state.empty_manifest()
            valid["lanes"]["317"] = valid_lane(Path(directory))
            invalid_manifests = []

            boolean_version = deepcopy(valid)
            boolean_version["schemaVersion"] = True
            invalid_manifests.append(("boolean schema version", boolean_version))

            unknown_state = deepcopy(valid)
            unknown_state["lanes"]["317"]["gates"]["focused"]["state"] = "maybe"
            invalid_manifests.append(("unknown gate state", unknown_state))

            unhashable_state = deepcopy(valid)
            unhashable_state["lanes"]["317"]["gates"]["focused"]["state"] = []
            invalid_manifests.append(("unhashable gate state", unhashable_state))

            for label, manifest in invalid_manifests:
                with self.subTest(label=label):
                    with self.assertRaises(ValueError):
                        lane_state.validate_manifest(manifest)

    def test_native_requirement_and_gate_state_must_agree(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            required = lane_state.empty_manifest()
            required_lane = valid_lane(root)
            required_lane["nativeLabRequirement"]["state"] = "required"
            required["lanes"]["317"] = required_lane
            with self.assertRaisesRegex(ValueError, "native"):
                lane_state.validate_manifest(required)

            not_required = lane_state.empty_manifest()
            not_required_lane = valid_lane(root)
            not_required_lane["gates"]["native_lab"] = gate()
            not_required["lanes"]["317"] = not_required_lane
            with self.assertRaisesRegex(ValueError, "native"):
                lane_state.validate_manifest(not_required)

    def test_incompatible_native_observation_is_rejected_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = lane_state.empty_manifest()
            allocate_test_lane(manifest, valid_lane(Path(directory)))
            original = deepcopy(manifest)

            with self.assertRaisesRegex(ValueError, "native"):
                record_test_observation(manifest, "317", "native_lab", valid_observation(Path(directory)))

            self.assertEqual(original, manifest)

    def test_allocation_rejects_invalid_shape_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            valid = valid_lane(Path(directory))
            invalid_lanes = []

            missing = deepcopy(valid)
            del missing["title"]
            invalid_lanes.append(("missing field", missing))

            extra = deepcopy(valid)
            extra["unexpected"] = True
            invalid_lanes.append(("extra field", extra))

            relative = deepcopy(valid)
            relative["worktree"] = "relative/worktree"
            invalid_lanes.append(("relative worktree", relative))

            unknown_role = deepcopy(valid)
            unknown_role["role"] = "unknown"
            invalid_lanes.append(("unknown role", unknown_role))

            malformed_sha = deepcopy(valid)
            malformed_sha["headSha"] = "short"
            invalid_lanes.append(("malformed SHA", malformed_sha))

            unequal_bases = deepcopy(valid)
            unequal_bases["currentBaseSha"] = SHA_C
            invalid_lanes.append(("unequal allocation bases", unequal_bases))

            multiple_owners = deepcopy(valid)
            multiple_owners["lease"]["owner"] = "Other"
            invalid_lanes.append(("multiple owners", multiple_owners))
            remote = deepcopy(valid)
            remote["remoteSha"] = SHA_A
            invalid_lanes.append(("preexisting remote", remote))

            pull_request = deepcopy(valid)
            pull_request["pr"] = {
                "number": 42,
                "url": lane_state.PR_URL_PREFIX + "42",
            }
            invalid_lanes.append(("preexisting pull request", pull_request))

            blocked = deepcopy(valid)
            blocked["blocker"] = "already blocked"
            invalid_lanes.append(("preexisting blocker", blocked))

            passed_gate = deepcopy(valid)
            passed_gate["gates"]["focused"] = valid_observation(Path(directory))
            invalid_lanes.append(("prepassed gate", passed_gate))
            missing_gates = deepcopy(valid)
            del missing_gates["gates"]
            invalid_lanes.append(("missing gates", missing_gates))

            missing_native = deepcopy(valid)
            del missing_native["nativeLabRequirement"]
            invalid_lanes.append(("missing native requirement", missing_native))

            for label, lane in invalid_lanes:
                with self.subTest(label=label):
                    manifest = lane_state.empty_manifest()
                    original = deepcopy(manifest)
                    with self.assertRaises(ValueError):
                        allocate_test_lane(manifest, lane)
                    self.assertEqual(original, manifest)

    def test_active_lane_identities_are_unique(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first_worktree = root / "lane"
            second_worktree = root / "other"
            alias_parent = root / "alias"
            first_worktree.mkdir()
            second_worktree.mkdir()
            alias_parent.mkdir()

            def lanes() -> tuple[dict[str, object], dict[str, object]]:
                first = valid_lane(first_worktree, issue=317)
                second = valid_lane(second_worktree, issue=318)
                first["agentId"] = first["lease"]["owner"] = "Agent-317"
                second["agentId"] = second["lease"]["owner"] = "Agent-318"
                return first, second

            cases = [
                (
                    "agentId",
                    lambda first, second: (
                        second.__setitem__("agentId", first["agentId"]),
                        second["lease"].__setitem__("owner", first["agentId"]),
                    ),
                ),
                (
                    "worktree",
                    lambda first, second: second.__setitem__(
                        "worktree", first["worktree"]
                    ),
                ),
                (
                    "branch",
                    lambda first, second: second.__setitem__(
                        "branch", first["branch"]
                    ),
                ),
                (
                    "pull request",
                    lambda first, second: (
                        first.__setitem__(
                            "pr",
                            {
                                "number": 42,
                                "url": lane_state.PR_URL_PREFIX + "42",
                            },
                        ),
                        second.__setitem__(
                            "pr",
                            {
                                "number": 42,
                                "url": lane_state.PR_URL_PREFIX + "42",
                            },
                        ),
                    ),
                ),
            ]

            for label, collide in cases:
                with self.subTest(label=label):
                    first, second = lanes()
                    collide(first, second)
                    manifest = lane_state.empty_manifest()
                    manifest["lanes"] = {"317": first, "318": second}
                    with self.assertRaisesRegex(ValueError, "duplicate active lane"):
                        lane_state.validate_manifest(manifest)

    def test_terminal_lanes_may_reuse_active_lane_identities(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for terminal in ("merged", "abandoned"):
                with self.subTest(terminal=terminal):
                    active = valid_lane(root / "active", issue=317)
                    inactive = valid_lane(root / "inactive", issue=318, state=terminal)
                    inactive["agentId"] = active["agentId"]
                    inactive["lease"]["owner"] = active["lease"]["owner"]
                    inactive["worktree"] = active["worktree"]
                    inactive["branch"] = active["branch"]
                    shared_pr = {
                        "number": 42,
                        "url": lane_state.PR_URL_PREFIX + "42",
                    }
                    active["pr"] = shared_pr.copy()
                    inactive["pr"] = shared_pr.copy()
                    manifest = lane_state.empty_manifest()
                    manifest["lanes"] = {"317": active, "318": inactive}

                    lane_state.validate_manifest(manifest)

    def test_allocation_canonicalizes_worktree_before_identity_check(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            worktree = root / "lane"
            alias_parent = root / "alias"
            worktree.mkdir()
            alias_parent.mkdir()
            manifest = lane_state.empty_manifest()
            first = valid_lane(worktree, issue=317)
            allocate_test_lane(manifest, first)
            second = valid_lane(worktree, issue=318)
            second["worktree"] = str(
                alias_parent / ".." / worktree.name
            )
            self.assertNotEqual(
                str(worktree.resolve()), second["worktree"]
            )
            second["agentId"] = second["lease"]["owner"] = "Agent-318"
            original = deepcopy(manifest)

            with self.assertRaisesRegex(ValueError, "duplicate active lane worktree"):
                allocate_test_lane(manifest, second)

            self.assertEqual(original, manifest)

    def test_manifest_validation_does_not_require_active_worktree(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = lane_state.empty_manifest()
            lane = valid_lane(Path(directory) / "missing", issue=317)
            manifest["lanes"] = {"317": lane}

            lane_state.validate_manifest(manifest)

    def test_init_creates_absent_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            common = Path(directory) / "common"
            common.mkdir()
            path = common / "omp" / "lanes.json"

            manifest, created = lane_state.initialize_manifest(path)

            self.assertTrue(created)
            self.assertEqual(manifest, lane_state.load_manifest(path))

    def test_init_rejects_state_directory_replacement_after_create(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            common = Path(directory) / "common"
            common.mkdir()
            state_dir = common / "omp"
            path = state_dir / "lanes.json"
            detached = common / "detached-omp"
            original_create = lane_state._atomic_json_create_at

            def swap_after_create(
                directory_fd: int,
                name: str,
                data: dict[str, object],
            ) -> bool:
                created = original_create(directory_fd, name, data)
                state_dir.rename(detached)
                state_dir.mkdir(mode=0o700)
                state_dir.chmod(0o700)
                (state_dir / "unrelated").write_text(
                    "preserve",
                    encoding="utf-8",
                )
                return created

            with mock.patch.object(
                lane_state,
                "_atomic_json_create_at",
                side_effect=swap_after_create,
            ), self.assertRaisesRegex(ValueError, "pinned directory"):
                lane_state.initialize_manifest(path)

            self.assertEqual(
                "preserve",
                (state_dir / "unrelated").read_text(encoding="utf-8"),
            )
            self.assertFalse(path.exists())
            self.assertTrue((detached / path.name).is_file())

    def test_init_preserves_existing_active_manifest_byte_for_byte(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            common = Path(directory) / "common"
            state_dir = common / "omp"
            state_dir.mkdir(parents=True, mode=0o700)
            state_dir.chmod(0o700)
            path = state_dir / "lanes.json"
            manifest = lane_state.empty_manifest()
            manifest["lanes"]["317"] = valid_lane(Path(directory), state="running")
            original = (json.dumps(manifest, indent=2) + "\n").encode()
            path.write_bytes(original)

            loaded, created = lane_state.initialize_manifest(path)

            self.assertFalse(created)
            self.assertEqual(manifest, loaded)
            self.assertEqual(original, path.read_bytes())

    def test_init_creates_absent_git_common_omp_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            common = Path(directory) / "common"
            common.mkdir()
            path = common / "omp" / "lanes.json"

            lane_state.initialize_manifest(path)

            mode = stat.S_IMODE(path.parent.lstat().st_mode)
            self.assertTrue(path.parent.is_dir())
            self.assertEqual(0o700, mode)

    def test_state_directory_symlink_or_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for kind in ("symlink", "file"):
                with self.subTest(kind=kind):
                    common = root / kind
                    common.mkdir()
                    state_dir = common / "omp"
                    if kind == "symlink":
                        target = root / f"{kind}-target"
                        target.mkdir()
                        state_dir.symlink_to(target, target_is_directory=True)
                    else:
                        state_dir.write_text("not a directory", encoding="utf-8")

                    with self.assertRaises(ValueError):
                        lane_state.ensure_state_dir(state_dir)
                    self.assertFalse((state_dir / "lanes.json").exists())

            wrong_mode = root / "wrong-mode" / "omp"
            wrong_mode.mkdir(parents=True, mode=0o755)
            wrong_mode.chmod(0o755)
            with self.assertRaises(ValueError):
                lane_state.atomic_write(wrong_mode / "lanes.json", lane_state.empty_manifest())
            self.assertFalse((wrong_mode / "lanes.json").exists())

    def test_init_rejects_invalid_existing_manifest_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state_dir = Path(directory) / "common" / "omp"
            state_dir.mkdir(parents=True, mode=0o700)
            state_dir.chmod(0o700)
            path = state_dir / "lanes.json"
            original = b'{"schemaVersion":99,"lanes":{}}\n'
            path.write_bytes(original)

            with self.assertRaises(ValueError):
                lane_state.initialize_manifest(path)

            self.assertEqual(original, path.read_bytes())

            dangling = state_dir / "dangling-lanes.json"
            dangling.symlink_to(state_dir / "missing-target.json")
            with self.assertRaises(ValueError):
                lane_state.initialize_manifest(dangling)
            self.assertTrue(dangling.is_symlink())


class LifecycleTests(unittest.TestCase):
    def test_allocated_can_transition_to_running(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = lane_state.empty_manifest()
            allocate_test_lane(manifest, valid_lane(Path(directory)))

            transition_test_lane(manifest, "317", "running")

            self.assertEqual("running", manifest["lanes"]["317"]["laneState"])

    def test_owner_transfer_stales_gate_review_and_mergeability_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = lane_state.empty_manifest()
            red_evidence = valid_observation(Path(directory), state="failed")
            allocate_test_lane(manifest, valid_lane(Path(directory)))
            manifest["lanes"]["317"]["nativeLabRequirement"]["state"] = "required"
            manifest["lanes"]["317"]["gates"]["native_lab"] = gate()
            record_test_red(manifest, "317", red_evidence)
            lane_state.record_pr(
                manifest,
                "317",
                42,
                PR_URL,
            )
            lane_state.record_remote(manifest, "317", SHA_A)
            transition_test_lane(manifest, "317", "blocked")
            for gate_name in (
                "focused",
                "aggregate",
                "conformance",
                "coderabbit",
                "independent_review",
                "mergeability",
            ):
                observation = (
                    valid_observation(Path(directory))
                    if gate_name == "focused"
                    else base_observation(Path(directory), gate_name)
                )
                record_test_observation(manifest, "317", gate_name, observation)
            record_test_observation(manifest, "317", "native_lab", base_observation(Path(directory), "native_lab"))
            manifest["lanes"]["317"]["mergeabilityState"] = "mergeable"

            lane_state.transfer_owner(manifest, "317", "Replacement", "coder")

            transferred = manifest["lanes"]["317"]
            self.assertEqual("blocked", transferred["laneState"])
            self.assertEqual("Replacement", transferred["agentId"])
            self.assertEqual("Replacement", transferred["lease"]["owner"])
            self.assertEqual("coder", transferred["role"])
            self.assertEqual([red_evidence], transferred["redEvidence"])
            self.assertEqual("stale", transferred["mergeabilityState"])
            self.assertTrue(
                all(
                    transferred["gates"][name]["state"] == "stale"
                    for name in transferred["gates"]
                )
            )

    def test_allocation_base_is_immutable_when_current_base_changes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = lane_state.empty_manifest()
            allocate_test_lane(manifest, valid_lane(Path(directory)))
            manifest["lanes"]["317"]["nativeLabRequirement"]["state"] = "required"
            manifest["lanes"]["317"]["gates"]["native_lab"] = gate()
            record_test_observation(manifest, "317", "focused", valid_observation(Path(directory)))
            record_test_observation(manifest, "317", "native_lab", valid_observation(Path(directory)))
            record_test_observation(manifest, "317", "aggregate", base_observation(Path(directory), "aggregate"))

            update_test_heads(manifest, "317", head_sha=SHA_A, current_base_sha=SHA_C)

            lane = manifest["lanes"]["317"]
            self.assertEqual(SHA_B, lane["allocationBaseSha"])
            self.assertEqual(SHA_C, lane["currentBaseSha"])
            self.assertEqual("passed", lane["gates"]["focused"]["state"])
            self.assertEqual("passed", lane["gates"]["native_lab"]["state"])
            self.assertEqual("stale", lane["gates"]["aggregate"]["state"])
            self.assertEqual(SHA_B, lane["gates"]["focused"]["baseSha"])
            self.assertEqual(SHA_B, lane["gates"]["native_lab"]["baseSha"])
            self.assertEqual(SHA_B, lane["gates"]["aggregate"]["baseSha"])
            lane_state.validate_manifest(manifest)

    def test_running_cannot_transition_directly_to_ready_for_adam(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = lane_state.empty_manifest()
            allocate_test_lane(manifest, valid_lane(Path(directory)))
            transition_test_lane(manifest, "317", "running")

            with self.assertRaises(ValueError):
                transition_test_lane(manifest, "317", "ready_for_adam")

            self.assertEqual("running", manifest["lanes"]["317"]["laneState"])

    def test_ready_for_adam_requires_complete_current_delivery_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def prepared() -> dict[str, object]:
                manifest = lane_state.empty_manifest()
                allocate_issue(manifest, root, 317)
                prepare_ready_lane(manifest, root, "317")
                return manifest

            valid = prepared()
            transition_test_lane(valid, "317", "ready_for_adam")
            self.assertEqual(
                "ready_for_adam",
                valid["lanes"]["317"]["laneState"],
            )

            readiness_rejections = {
                "missing PR": (
                    lambda lane: lane.__setitem__(
                        "pr",
                        {"number": None, "url": None},
                    ),
                    "ready_for_adam requires a pull request",
                ),
                "remote mismatch": (
                    lambda lane: lane.__setitem__("remoteSha", SHA_C),
                    "ready_for_adam requires local head and remote SHA identity",
                ),
            }
            for label, (mutate, reason) in readiness_rejections.items():
                with self.subTest(label=label):
                    manifest = prepared()
                    lane = manifest["lanes"]["317"]
                    mutate(lane)
                    original = deepcopy(manifest)
                    with self.assertRaisesRegex(ValueError, reason):
                        lane_state._require_ready_for_adam(manifest, lane)
                    self.assertEqual(original, manifest)

            root_safety_rejections = {
                "missing stage2 wave": (
                    lambda root_safety: root_safety.__setitem__(
                        "stage2Waves",
                        {},
                    ),
                    "completed Stage 2 wave snapshot",
                ),
                "incomplete stage2 wave": (
                    lambda root_safety: root_safety["stage2Waves"][
                        "wave-ready"
                    ].__setitem__(
                        "after",
                        None,
                    ),
                    "completed Stage 2 wave snapshot",
                ),
            }
            for label, (mutate, reason) in root_safety_rejections.items():
                with self.subTest(label=label):
                    manifest = prepared()
                    mutate(manifest["rootSafety"])
                    original = deepcopy(manifest)
                    with self.assertRaisesRegex(ValueError, reason):
                        transition_test_lane(manifest, "317", "ready_for_adam")
                    self.assertEqual(original, manifest)

            mutations = {
                "incomplete gate": lambda lane: lane["gates"].__setitem__(
                    "focused",
                    gate(),
                ),
                "implementation not green": lambda lane: lane.__setitem__(
                    "implementationState",
                    "red",
                ),
                "blocker present": lambda lane: lane.__setitem__(
                    "blocker",
                    "blocked",
                ),
            }
            for label, mutate in mutations.items():
                with self.subTest(label=label):
                    manifest = prepared()
                    mutate(manifest["lanes"]["317"])
                    original = deepcopy(manifest)
                    with self.assertRaises(ValueError):
                        transition_test_lane(manifest, "317", "ready_for_adam")
                    self.assertEqual(original, manifest)

            dependency = prepared()
            upstream_worktree = root / "lane-316"
            upstream_worktree.mkdir()
            upstream = valid_lane(upstream_worktree, issue=316, state="running")
            upstream["agentId"] = upstream["lease"]["owner"] = "Task-316"
            dependency["lanes"]["316"] = upstream
            dependency["lanes"]["317"]["dependsOn"] = [316]
            original = deepcopy(dependency)
            with self.assertRaisesRegex(ValueError, "depend"):
                transition_test_lane(dependency, "317", "ready_for_adam")
            self.assertEqual(original, dependency)

    def test_persisted_ready_lane_reasserts_readiness_invariants(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = lane_state.empty_manifest()
            allocate_issue(manifest, root, 317)
            prepare_ready_lane(manifest, root, "317")
            transition_test_lane(manifest, "317", "ready_for_adam")
            manifest["lanes"]["317"]["gates"]["focused"]["state"] = "stale"

            with self.assertRaisesRegex(ValueError, "ready_for_adam"):
                lane_state.validate_manifest(manifest)

    def test_head_update_demotes_ready_lane_before_staling_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = lane_state.empty_manifest()
            allocate_issue(manifest, root, 317)
            prepare_ready_lane(manifest, root, "317")
            transition_test_lane(manifest, "317", "ready_for_adam")

            update_test_heads(manifest, "317", head_sha=SHA_C, current_base_sha=SHA_B)

            lane = manifest["lanes"]["317"]
            self.assertEqual("reviewing", lane["laneState"])
            self.assertIn("revalidate", lane["nextAction"])
            self.assertEqual("stale", lane["gates"]["focused"]["state"])

    def test_delivery_loss_recursively_demotes_ready_dependents(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = lane_state.empty_manifest()
            allocate_issue(manifest, root, 317)
            allocate_issue(manifest, root, 318, depends_on=[317])
            allocate_issue(manifest, root, 319, depends_on=[318])
            snapshot = root / "dependency-stage2.json"
            snapshot.write_text(
                json.dumps(root_snapshot_fixture()),
                encoding="utf-8",
            )
            snapshot_uri = snapshot.resolve().as_uri()
            lane_state.record_root_snapshot(
                manifest,
                "stage2Before",
                snapshot_uri,
                wave_id="dependency-delivery",
                issues=[317, 318, 319],
            )
            for issue in ("317", "318", "319"):
                record_all_observations(manifest, root, issue)
                manifest["lanes"][issue]["implementationState"] = "green"
                transition_test_lane(manifest, issue, "running")
                transition_test_lane(manifest, issue, "reviewing")
            lane_state.record_root_snapshot(
                manifest,
                "stage2After",
                snapshot_uri,
                wave_id="dependency-delivery",
                issues=[317, 318, 319],
            )
            for issue in ("317", "318", "319"):
                transition_test_lane(manifest, issue, "ready_for_adam")

            transition_test_lane(manifest, "317", "reviewing")

            self.assertEqual("reviewing", manifest["lanes"]["317"]["laneState"])
            for issue in ("318", "319"):
                lane = manifest["lanes"][issue]
                self.assertEqual("reviewing", lane["laneState"])
                self.assertIn("revalidate dependency", lane["nextAction"])

    def test_persisted_ready_lane_rejects_non_draft_review_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = lane_state.empty_manifest()
            allocate_issue(manifest, root, 317)
            prepare_ready_lane(manifest, root, "317")
            transition_test_lane(manifest, "317", "ready_for_adam")
            observation = manifest["lanes"]["317"]["gates"]["coderabbit"]
            path = artifact_path(observation["artifact"])
            artifact = json.loads(path.read_text(encoding="utf-8"))
            artifact["isDraft"] = False
            path.write_text(json.dumps(artifact), encoding="utf-8")
            observation["artifact"] = artifact_ref(path)

            with self.assertRaisesRegex(ValueError, "Draft|draft"):
                lane_state.validate_manifest(manifest)

    def test_merged_and_abandoned_are_terminal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            for terminal in ("merged", "abandoned"):
                with self.subTest(terminal=terminal):
                    manifest = lane_state.empty_manifest()
                    manifest["lanes"]["317"] = valid_lane(Path(directory), state=terminal)
                    lane_state.validate_manifest(manifest)

                    with self.assertRaises(ValueError):
                        transition_test_lane(manifest, "317", "running")

                    self.assertEqual(terminal, manifest["lanes"]["317"]["laneState"])

    def test_expired_lease_does_not_change_owner(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = lane_state.empty_manifest()
            lane = valid_lane(Path(directory))
            lane["lease"]["expiresAt"] = "2020-01-01T00:00:00+00:00"
            allocate_test_lane(manifest, lane)

            lane_state.validate_manifest(manifest)

            self.assertEqual("Task", manifest["lanes"]["317"]["agentId"])
            self.assertEqual("Task", manifest["lanes"]["317"]["lease"]["owner"])

    def test_owner_transfer_requires_blocked_lane(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = lane_state.empty_manifest()
            allocate_test_lane(manifest, valid_lane(Path(directory)))
            transition_test_lane(manifest, "317", "running")

            with self.assertRaises(ValueError):
                lane_state.transfer_owner(manifest, "317", "Replacement", "coder")

            self.assertEqual("Task", manifest["lanes"]["317"]["agentId"])


class FeatureOwnerTests(unittest.TestCase):
    def test_stage1_owner_create_is_non_destructive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            common = Path(directory) / "common"
            common.mkdir()
            path = common / "omp" / "stage1-owner.json"
            owner = valid_feature_owner(Path(directory))
            lane_state.record_feature_owner(path, owner)
            original = path.read_bytes()

            lane_state.record_feature_owner(path, owner.copy())
            self.assertEqual(original, path.read_bytes())

            differing = owner.copy()
            differing["owner"] = "Other"
            with self.assertRaises(ValueError):
                lane_state.record_feature_owner(path, differing)
            self.assertEqual(original, path.read_bytes())

            dangling = common / "omp" / "dangling-owner.json"
            dangling.symlink_to(common / "omp" / "missing-owner.json")
            with self.assertRaises(ValueError):
                lane_state.record_feature_owner(dangling, owner)
            self.assertTrue(dangling.is_symlink())

    def test_stage1_owner_requires_exact_allowed_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            common = Path(directory) / "common"
            common.mkdir()
            path = common / "omp" / "stage1-owner.json"
            for label, allowed_paths in (
                ("missing", STAGE1_ALLOWED_PATHS[:-1]),
                ("extra", [*STAGE1_ALLOWED_PATHS, "other/**"]),
                ("reordered", list(reversed(STAGE1_ALLOWED_PATHS))),
            ):
                with self.subTest(label=label):
                    owner = valid_feature_owner(Path(directory))
                    owner["allowedPaths"] = allowed_paths
                    with self.assertRaises(ValueError):
                        lane_state.record_feature_owner(path, owner)
                    self.assertFalse(path.exists())

    def test_stage1_transfer_marks_all_evidence_invalidated(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            common = Path(directory) / "common"
            common.mkdir()
            path = common / "omp" / "stage1-owner.json"
            lane_state.record_feature_owner(
                path,
                valid_feature_owner(Path(directory), state="blocked"),
            )

            lane_state.transfer_feature_owner(path, "Replacement", "reviewer", LATER)

            owner = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual("Replacement", owner["owner"])
            self.assertEqual("reviewer", owner["role"])
            self.assertEqual("active", owner["state"])
            self.assertEqual(LATER, owner["assignedAt"])
            self.assertEqual(LATER, owner["evidenceInvalidatedAt"])
            self.assertEqual(1, owner["transferCount"])

    def test_stage1_owner_transfer_requires_blocked_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            common = Path(directory) / "common"
            common.mkdir()
            path = common / "omp" / "stage1-owner.json"
            lane_state.record_feature_owner(path, valid_feature_owner(Path(directory)))
            original = path.read_bytes()

            with self.assertRaises(ValueError):
                lane_state.transfer_feature_owner(path, "Replacement", "reviewer", LATER)

            self.assertEqual(original, path.read_bytes())

    def test_released_feature_owner_is_terminal_and_byte_preserved(self) -> None:
        self.assertEqual(
            ("active", "blocked", "released"),
            lane_state.FEATURE_OWNER_STATES,
        )
        with tempfile.TemporaryDirectory() as directory:
            common = Path(directory) / "common"
            common.mkdir()
            path = common / "omp" / "stage1-owner.json"
            lane_state.record_feature_owner(path, valid_feature_owner(Path(directory)))
            lane_state.set_feature_owner_state(path, "released")
            released = path.read_bytes()

            lane_state.set_feature_owner_state(path, "released")
            self.assertEqual(released, path.read_bytes())
            for state in ("active", "blocked"):
                with self.subTest(state=state):
                    with self.assertRaisesRegex(ValueError, "terminal"):
                        lane_state.set_feature_owner_state(path, state)
                    self.assertEqual(released, path.read_bytes())

    def test_stage1_owner_first_use_creates_state_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            common = Path(directory) / "common"
            common.mkdir()
            path = common / "omp" / "stage1-owner.json"

            lane_state.record_feature_owner(path, valid_feature_owner(Path(directory)))

            self.assertTrue(path.is_file())
            self.assertEqual(0o700, stat.S_IMODE(path.parent.lstat().st_mode))


class EvidenceTests(unittest.TestCase):
    def test_observation_requires_command_or_scenario_exit_code_time_and_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            required_variants = (
                ("command and scenario", {"command": None, "scenario": None}),
                ("exit code", {"exitCode": None}),
                ("observed time", {"observedAt": None}),
                ("artifact", {"artifact": None}),
            )
            for label, updates in required_variants:
                with self.subTest(missing=label):
                    manifest = lane_state.empty_manifest()
                    allocate_test_lane(manifest, valid_lane(Path(directory)))
                    observation = valid_observation(Path(directory))
                    observation.update(updates)

                    with self.assertRaises(ValueError):
                        record_test_observation(manifest, "317", "focused", observation)

                    self.assertEqual("not_run", manifest["lanes"]["317"]["gates"]["focused"]["state"])

    def test_observation_head_must_match_lane_head(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            invalid_observations = (
                (
                    "head",
                    valid_observation(
                        Path(directory),
                        head_sha=SHA_C,
                        name="wrong-head",
                    ),
                ),
                (
                    "base",
                    valid_observation(
                        Path(directory),
                        base_sha=SHA_C,
                        name="wrong-base",
                    ),
                ),
            )
            for revision, observation in invalid_observations:
                with self.subTest(revision=revision):
                    manifest = lane_state.empty_manifest()
                    allocate_test_lane(manifest, valid_lane(Path(directory)))
                    original = deepcopy(manifest)

                    with self.assertRaises(ValueError):
                        record_test_observation(manifest, "317", "focused", observation)

                    self.assertEqual(original, manifest)

    def test_red_evidence_is_append_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = lane_state.empty_manifest()
            allocate_test_lane(manifest, valid_lane(Path(directory)))
            first = valid_observation(
                Path(directory),
                state="failed",
                name="first-red",
            )
            second = valid_observation(
                Path(directory),
                state="failed",
                name="second-red",
            )

            record_test_red(manifest, "317", first)
            record_test_red(manifest, "317", second)

            evidence = manifest["lanes"]["317"]["redEvidence"]
            self.assertEqual([first, second], evidence)
            self.assertEqual("red", manifest["lanes"]["317"]["implementationState"])

    def test_red_command_requires_nonzero_exit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = lane_state.empty_manifest()
            allocate_test_lane(manifest, valid_lane(Path(directory)))
            observation = valid_observation(
                Path(directory),
                state="failed",
                exit_code=0,
            )
            original = deepcopy(manifest)

            with self.assertRaisesRegex(ValueError, "nonzero exit"):
                record_test_red(manifest, "317", observation)

            self.assertEqual(original, manifest)

    def test_negative_signal_exit_is_failure_but_not_automatically_red(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = lane_state.empty_manifest()
            allocate_test_lane(manifest, valid_lane(root))
            observation = valid_observation(
                root,
                state="failed",
                exit_code=-9,
                classification="command_failure",
                include_red_review=False,
            )

            record_test_observation(manifest, "317", "focused", observation)
            self.assertEqual(-9, manifest["lanes"]["317"]["gates"]["focused"]["exitCode"])

            original = deepcopy(manifest)
            with self.assertRaisesRegex(ValueError, "Main-reviewed"):
                record_test_red(manifest, "317", observation)
            self.assertEqual(original, manifest)

    def test_expected_red_requires_content_bound_runner_classification(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = lane_state.empty_manifest()
            allocate_test_lane(manifest, valid_lane(root))
            observation = valid_observation(
                root,
                state="failed",
                name="expected-red",
            )

            record_test_red(manifest, "317", observation)

            self.assertEqual(
                [observation],
                manifest["lanes"]["317"]["redEvidence"],
            )
    def test_missing_or_malformed_main_red_review_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for variant in ("missing", "malformed", "wrong-artifact"):
                with self.subTest(variant=variant):
                    manifest = lane_state.empty_manifest()
                    allocate_test_lane(manifest, valid_lane(root))
                    observation = valid_observation(
                        root,
                        state="failed",
                        name=f"manual-{variant}",
                    )
                    if variant == "missing":
                        observation["redClassification"] = None
                    elif variant == "malformed":
                        observation["redClassification"] = {"kind": "reviewed"}
                    else:
                        observation["redClassification"]["artifactSha256"] = "0" * 64

                    with self.assertRaises(ValueError):
                        record_test_red(manifest, "317", observation)


    def test_import_failure_without_main_review_is_not_red(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = lane_state.empty_manifest()
            allocate_test_lane(manifest, valid_lane(root))
            observation = valid_observation(
                root,
                state="failed",
                include_red_review=False,
                name="import-failure",
            )
            path = artifact_path(observation["artifact"])
            artifact = json.loads(path.read_text(encoding="utf-8"))
            artifact["stderr"] = "ModuleNotFoundError: missing dependency"
            path.write_text(json.dumps(artifact), encoding="utf-8")
            observation["artifact"] = artifact_ref(path)

            with self.assertRaisesRegex(ValueError, "Main-reviewed"):
                record_test_red(manifest, "317", observation)

    def test_successful_focused_gate_binds_hashed_runner_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = lane_state.empty_manifest()
            allocate_test_lane(manifest, valid_lane(root))
            observation = valid_observation(root, name="focused-green")

            record_test_observation(manifest, "317", "focused", observation)

            recorded = manifest["lanes"]["317"]["gates"]["focused"]
            self.assertEqual(observation, recorded)
            reference = recorded["artifact"]
            self.assertEqual(
                hashlib.sha256(artifact_path(reference).read_bytes()).hexdigest(),
                reference["sha256"],
            )
    def test_focused_success_rejects_mislabeled_base_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = lane_state.empty_manifest()
            allocate_test_lane(manifest, valid_lane(root))
            observation = valid_observation(root, name="focused-mislabeled")
            observation["artifact"] = write_base_artifact(
                root,
                name="focused-mislabeled-base",
            )
            with self.assertRaisesRegex(ValueError, "repo_check"):
                record_test_observation(manifest, "317", "focused", observation)


    def test_missing_stale_and_mismatched_runner_artifacts_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def rejects(observation: dict[str, object]) -> None:
                manifest = lane_state.empty_manifest()
                allocate_test_lane(manifest, valid_lane(root))
                with self.assertRaises(ValueError):
                    record_test_observation(manifest, "317", "focused", observation)

            nonexistent = valid_observation(root, name="nonexistent")
            nonexistent["artifact"] = {
                "uri": (root / "does-not-exist.json").resolve().as_uri(),
                "sha256": "0" * 64,
            }
            rejects(nonexistent)

            stale = valid_observation(root, name="stale")
            artifact_path(stale["artifact"]).write_text(
                "{}\n",
                encoding="utf-8",
            )
            rejects(stale)

            for field, wrong_value in (
                ("command", ["python3.14", "different-test.py"]),
                ("headSha", SHA_C),
                ("baseSha", SHA_C),
                ("exitCode", 7),
                ("stdoutTruncated", "false"),
                ("stderrTruncated", 0),
                ("stdoutTruncated", True),
                ("stderrTruncated", True),
            ):
                with self.subTest(field=field):
                    observation = valid_observation(
                        root,
                        name=f"mismatch-{field}",
                    )
                    path = artifact_path(observation["artifact"])
                    artifact = json.loads(path.read_text(encoding="utf-8"))
                    artifact[field] = wrong_value
                    path.write_text(json.dumps(artifact), encoding="utf-8")
                    observation["artifact"] = artifact_ref(path)
                    rejects(observation)

    def test_runner_infrastructure_artifacts_cannot_be_recorded_as_evidence(self) -> None:
        message = "runner infrastructure failures are never RED, GREEN, or gate evidence"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for outcome in (
                "timed_out",
                "spawn_failed",
                "setup_failed",
                "containment_failed",
            ):
                with self.subTest(outcome=outcome):
                    observation = valid_observation(
                        root,
                        state="failed",
                        classification="runner_failure",
                        outcome=outcome,
                        name=f"infra-{outcome}",
                    )
                    path = artifact_path(observation["artifact"])
                    artifact = json.loads(path.read_text(encoding="utf-8"))
                    artifact["exitCode"] = None
                    path.write_text(json.dumps(artifact), encoding="utf-8")
                    observation["artifact"] = artifact_ref(path)

                    for entry_point in ("red", "gate"):
                        with self.subTest(entry_point=entry_point):
                            manifest = lane_state.empty_manifest()
                            allocate_test_lane(manifest, valid_lane(root))
                            before = deepcopy(manifest)
                            with self.assertRaisesRegex(ValueError, message):
                                if entry_point == "red":
                                    record_test_red(manifest, "317", observation)
                                else:
                                    record_test_observation(
                                        manifest,
                                        "317",
                                        "focused",
                                        observation,
                                    )
                            self.assertEqual(before, manifest)

    def test_unbound_setup_failure_cannot_be_recorded_as_evidence(self) -> None:
        message = "runner infrastructure failures are never RED, GREEN, or gate evidence"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = lane_state.empty_manifest()
            allocate_test_lane(manifest, valid_lane(root))
            observation = valid_observation(
                root,
                state="failed",
                classification="runner_failure",
                outcome="setup_failed",
                name="unbound-setup-failure",
            )
            path = artifact_path(observation["artifact"])
            artifact = json.loads(path.read_text(encoding="utf-8"))
            for field in (
                "worktree",
                "worktreeIdentity",
                "gitCommonDir",
                "branch",
                "headSha",
                "exitCode",
            ):
                artifact[field] = None
            path.write_text(json.dumps(artifact), encoding="utf-8")
            observation["artifact"] = artifact_ref(path)

            with self.assertRaisesRegex(ValueError, message):
                record_test_red(manifest, "317", observation)
            with self.assertRaisesRegex(ValueError, message):
                record_test_observation(manifest, "317", "focused", observation)


    def test_coder_green_requires_red_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = lane_state.empty_manifest()
            allocate_test_lane(manifest, valid_lane(Path(directory)))
            original = deepcopy(manifest)

            with self.assertRaisesRegex(ValueError, "RED evidence"):
                lane_state.record_status(
                    manifest,
                    "317",
                    {"implementationState": "green"},
                )

            self.assertEqual(original, manifest)


    def test_heartbeat_requires_current_owner_and_updates_last_verified(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = lane_state.empty_manifest()
            allocate_test_lane(manifest, valid_lane(Path(directory)))

            with self.assertRaises(ValueError):
                lane_state.heartbeat_lane(manifest, "317", "Other", LATER, LATER)
            lane_state.heartbeat_lane(
                manifest,
                "317",
                "Task",
                LATER,
                "2026-08-14T12:10:00+00:00",
            )

            lease = manifest["lanes"]["317"]["lease"]
            self.assertEqual(LATER, lease["heartbeatAt"])
            self.assertEqual(LATER, lease["lastVerifiedAt"])
            self.assertEqual("2026-08-14T12:10:00+00:00", lease["expiresAt"])

    def test_pr_remote_status_and_root_artifacts_are_validated(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = lane_state.empty_manifest()
            allocate_test_lane(manifest, valid_lane(Path(directory)))
            artifact = Path(directory) / "root-stage1-before.json"
            artifact_bytes = json.dumps(
                root_snapshot_fixture(),
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            artifact.write_bytes(artifact_bytes)
            artifact_uri = artifact.resolve().as_uri()

            lane_state.record_pr(manifest, "317", 42, PR_URL)
            lane_state.record_remote(manifest, "317", SHA_C)
            record_test_red(manifest, "317", valid_observation(Path(directory), state="failed"))
            lane_state.record_status(
                manifest,
                "317",
                {
                    "implementationState": "green",
                    "mergeabilityState": "mergeable",
                    "blocker": None,
                    "nextAction": "independent review",
                },
            )
            lane_state.record_root_snapshot(
                manifest,
                "stage1Before",
                artifact_uri,
            )

            lane = manifest["lanes"]["317"]
            self.assertEqual(
                {"number": 42, "url": PR_URL},
                lane["pr"],
            )
            self.assertEqual(SHA_C, lane["remoteSha"])
            self.assertEqual("green", lane["implementationState"])
            self.assertEqual("mergeable", lane["mergeabilityState"])
            self.assertEqual(
                {
                    "artifact": artifact_uri,
                    "sha256": hashlib.sha256(artifact_bytes).hexdigest(),
                },
                manifest["rootSafety"]["stage1Before"],
            )

            invalid_calls = (
                lambda: lane_state.record_pr(manifest, "317", 0, "not-a-url"),
                lambda: lane_state.record_remote(manifest, "317", "short"),
                lambda: lane_state.record_status(manifest, "317", {"implementationState": "done"}),
                lambda: lane_state.record_root_snapshot(manifest, "unknown", "artifact.txt"),
            )
            for call in invalid_calls:
                with self.subTest(call=call):
                    with self.assertRaises(ValueError):
                        call()



class TestInfrastructureTests(unittest.TestCase):
    def test_git_helpers_disable_ambient_behavior_and_have_timeouts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            destination = root / "destination"
            completed = subprocess.CompletedProcess(
                args=["git"],
                returncode=0,
                stdout="",
                stderr="",
            )
            actions = (
                lambda: run_git(source, "status"),
                lambda: clone_git_repo(source, destination),
                lambda: run_git_unchecked(source, "status"),
            )
            for action in actions:
                with self.subTest(action=action):
                    with mock.patch(
                        "subprocess.run",
                        return_value=completed,
                    ) as run:
                        action()
                    arguments = run.call_args
                    environment = arguments.kwargs["env"]
                    self.assertEqual(os.devnull, environment["GIT_CONFIG_GLOBAL"])
                    self.assertEqual(os.devnull, environment["GIT_CONFIG_SYSTEM"])
                    self.assertEqual("0", environment["GIT_TERMINAL_PROMPT"])
                    self.assertEqual(subprocess.DEVNULL, arguments.kwargs["stdin"])
                    self.assertGreater(arguments.kwargs["timeout"], 0)
                    configured = {
                        environment[f"GIT_CONFIG_KEY_{index}"]: environment[
                            f"GIT_CONFIG_VALUE_{index}"
                        ]
                        for index in range(int(environment["GIT_CONFIG_COUNT"]))
                    }
                    self.assertEqual(os.devnull, configured["core.hooksPath"])
                    self.assertEqual("false", configured["commit.gpgSign"])
                    self.assertEqual("false", configured["tag.gpgSign"])


class GitHelperTests(unittest.TestCase):
    def test_git_commands_are_noninteractive_bounded_and_timeout_cleanly(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            completed = subprocess.CompletedProcess(
                args=["git"],
                returncode=0,
                stdout=b"result",
                stderr=b"",
            )
            with mock.patch.object(
                lane_state.subprocess,
                "run",
                return_value=completed,
            ) as run:
                self.assertEqual(b"result", lane_state._git_bytes(repo, "status"))

            arguments = run.call_args
            self.assertEqual(subprocess.DEVNULL, arguments.kwargs["stdin"])
            self.assertGreater(arguments.kwargs["timeout"], 0)
            self.assertEqual(
                "0",
                arguments.kwargs["env"]["GIT_OPTIONAL_LOCKS"],
            )
            self.assertEqual(
                "0",
                arguments.kwargs["env"]["GIT_TERMINAL_PROMPT"],
            )
            with mock.patch.dict(
                os.environ,
                {
                    "LLMGATEWAY_API_KEY": "gateway-secret",
                    "GH_TOKEN": "github-secret",
                    "AWS_SECRET_ACCESS_KEY": "cloud-secret",
                },
            ), mock.patch.object(
                lane_state.subprocess,
                "run",
                return_value=completed,
            ) as scrubbed_run:
                lane_state._git_bytes(repo, "status")

            scrubbed_environment = scrubbed_run.call_args.kwargs["env"]
            for secret_name in (
                "LLMGATEWAY_API_KEY",
                "GH_TOKEN",
                "AWS_SECRET_ACCESS_KEY",
            ):
                self.assertFalse(secret_name in scrubbed_environment)

            with mock.patch.object(
                lane_state.subprocess,
                "run",
                side_effect=subprocess.TimeoutExpired(["git"], 1),
            ):
                with self.assertRaisesRegex(ValueError, "timed out"):
                    lane_state._git_bytes(repo, "status")

    def test_git_commands_ignore_hostile_ambient_repository_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo, head = create_git_repo(Path(directory))
            hostile = {
                "GIT_DIR": str(Path(directory) / "hostile.git"),
                "GIT_WORK_TREE": str(Path(directory) / "hostile-worktree"),
                "GIT_INDEX_FILE": str(Path(directory) / "hostile-index"),
                "GIT_OBJECT_DIRECTORY": str(Path(directory) / "hostile-objects"),
                "GIT_ALTERNATE_OBJECT_DIRECTORIES": str(
                    Path(directory) / "alternate-objects"
                ),
                "GIT_COMMON_DIR": str(Path(directory) / "hostile-common"),
                "GIT_CONFIG_GLOBAL": str(Path(directory) / "hostile-config"),
                "GIT_CONFIG_SYSTEM": str(Path(directory) / "hostile-system"),
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "core.repositoryFormatVersion",
                "GIT_CONFIG_VALUE_0": "999",
            }
            with mock.patch.dict(os.environ, hostile):
                self.assertEqual(head, lane_state.git_text(repo, "rev-parse", "HEAD"))
                completed = subprocess.CompletedProcess(
                    args=["git"],
                    returncode=0,
                    stdout=b"",
                    stderr=b"",
                )
                with mock.patch.object(
                    lane_state.subprocess,
                    "run",
                    return_value=completed,
                ) as run:
                    lane_state._git_bytes(repo, "status")

            git_environment = {
                key: value
                for key, value in run.call_args.kwargs["env"].items()
                if key.startswith("GIT_")
            }
            self.assertEqual(
                {
                    "GIT_CONFIG_GLOBAL": os.devnull,
                    "GIT_CONFIG_SYSTEM": os.devnull,
                    "GIT_OPTIONAL_LOCKS": "0",
                    "GIT_TERMINAL_PROMPT": "0",
                },
                git_environment,
            )

    def test_git_commands_disable_repository_fsmonitor_hooks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo, _ = create_git_repo(root)
            marker = root / "fsmonitor-ran"
            hook = root / "hostile-fsmonitor"
            hook.write_text(
                "#!/bin/sh\n"
                f"printf touched > {shlex.quote(str(marker))}\n",
                encoding="utf-8",
            )
            hook.chmod(0o700)
            run_git(repo, "config", "core.fsmonitor", str(hook))
            real_run = subprocess.run

            with mock.patch.object(
                lane_state.subprocess,
                "run",
                side_effect=real_run,
            ) as run:
                self.assertEqual(b"", lane_state._git_bytes(repo, "status", "--short"))

            self.assertEqual(
                [
                    "git",
                    "-c",
                    "core.fsmonitor=false",
                    "-C",
                    str(repo.resolve()),
                    "status",
                    "--short",
                ],
                run.call_args.args[0],
            )
            self.assertFalse(marker.exists())


class PathOwnershipTests(unittest.TestCase):
    def test_tracked_and_untracked_paths_are_checked(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo, allocation_base = create_git_repo(Path(directory))
            (repo / "owned.txt").write_text("modified\n", encoding="utf-8")
            (repo / "untracked.txt").write_text("new\n", encoding="utf-8")

            self.assertEqual(
                ["owned.txt", "untracked.txt"],
                lane_state.changed_paths(repo, allocation_base),
            )
            self.assertEqual(
                ["untracked.txt"],
                lane_state.check_allowed_paths(
                    lane_state.changed_paths(repo, allocation_base),
                    ["owned.txt"],
                ),
            )

    def test_observed_git_spaces_and_colons_pass_a_portable_allowlist(self) -> None:
        observed_paths = [
            "artifacts/release notes:final.txt",
            "é:/report.txt",
        ]
        tracked_output = ("\0".join(observed_paths) + "\0").encode()
        with mock.patch.object(
            lane_state,
            "_git_bytes",
            side_effect=[tracked_output, b""],
        ):
            paths = lane_state.changed_paths(Path("/repo"), SHA_A)

        self.assertEqual(sorted(observed_paths), paths)
        self.assertEqual(
            [],
            lane_state.check_allowed_paths(
                ["artifacts/release notes:final.txt"],
                ["artifacts/**"],
            ),
        )
        self.assertEqual([], lane_state.check_allowed_paths(paths, ["**"]))

    def test_changed_paths_reject_unsafe_observed_git_output(self) -> None:
        for observed_path in (
            "/tmp/outside",
            "C:/outside",
            "../outside",
            "src/../../outside",
            "src\\outside",
            "src/control\u001fpath",
        ):
            with (
                self.subTest(observed_path=observed_path),
                mock.patch.object(
                    lane_state,
                    "_git_bytes",
                    side_effect=[f"{observed_path}\0".encode(), b""],
                ),
                self.assertRaises(ValueError),
            ):
                lane_state.changed_paths(Path("/repo"), SHA_A)

    def test_root_snapshot_validates_managed_paths_before_excluding_them(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo, _ = create_git_repo(Path(directory))
            git_bytes = lane_state._git_bytes

            def inject_unsafe_path(repository: Path, *args: str) -> bytes:
                if args == (
                    "ls-files",
                    "--others",
                    "--exclude-standard",
                    "-z",
                ):
                    return b".worktrees/bad\\name\0"
                return git_bytes(repository, *args)

            with (
                mock.patch.object(
                    lane_state,
                    "_git_bytes",
                    side_effect=inject_unsafe_path,
                ),
                self.assertRaisesRegex(ValueError, "untracked path"),
            ):
                lane_state.root_snapshot(repo)

    def test_proposal_allowlist_paths_remain_portable(self) -> None:
        invalid_patterns = (
            "artifacts/release notes.txt",
            "artifacts/release:notes.txt",
            "artifacts/CON",
            "docs/NUL.txt",
            "docs/trailing.",
            "src/COM¹.txt",
            "src/LPT².log",
            "src/CONIN$",
            "src/conout$.txt",
        )
        for pattern in invalid_patterns:
            with self.subTest(pattern=pattern), self.assertRaises(ValueError):
                lane_state.check_allowed_paths(
                    ["artifacts/release notes:final.txt"],
                    [pattern],
                )

        with tempfile.TemporaryDirectory() as directory:
            for field in ("allowedPaths", "sharedContractPaths"):
                for pattern in invalid_patterns:
                    with self.subTest(field=field, pattern=pattern):
                        manifest = lane_state.empty_manifest()
                        lane = valid_lane(Path(directory))
                        lane[field] = [pattern]
                        with self.assertRaises(ValueError):
                            allocate_test_lane(manifest, lane)
        self.assertTrue(
            lane_state.is_portable_repo_relative("src/資料-résumé.txt")
        )

    def test_out_of_scope_path_blocks_lane_without_deleting_it(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo, allocation_base = create_git_repo(Path(directory))
            (repo / "outside.txt").write_text("out of scope\n", encoding="utf-8")
            manifest = lane_state.empty_manifest()
            lane = valid_lane(repo)
            lane["allowedPaths"] = ["owned.txt"]
            lane["allocationBaseSha"] = allocation_base
            lane["currentBaseSha"] = allocation_base
            allocate_test_lane(manifest, lane)

            disallowed = enforce_test_lane_paths(manifest, "317")

            self.assertEqual(["outside.txt"], disallowed)
            self.assertIn("317", manifest["lanes"])
            blocked = manifest["lanes"]["317"]
            self.assertEqual("blocked", blocked["laneState"])
            self.assertIn("outside.txt", blocked["blocker"])
            self.assertEqual(
                "restore path ownership before continuing",
                blocked["nextAction"],
            )

    def test_changed_symlink_to_outside_blocks_lane(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo, allocation_base = create_git_repo(root)
            outside = root / "outside.txt"
            outside.write_text("outside\n", encoding="utf-8")
            (repo / "escape.txt").symlink_to(outside)
            manifest = lane_state.empty_manifest()
            lane = valid_lane(repo)
            lane["allowedPaths"] = ["escape.txt"]
            lane["allocationBaseSha"] = allocation_base
            lane["currentBaseSha"] = allocation_base
            allocate_test_lane(manifest, lane)

            disallowed = enforce_test_lane_paths(manifest, "317")

            self.assertEqual(["escape.txt"], disallowed)
            self.assertEqual("blocked", manifest["lanes"]["317"]["laneState"])

    def test_changed_path_through_parent_symlink_escape_blocks_lane(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo, _ = create_git_repo(root)
            tracked = repo / "linked" / "changed.txt"
            tracked.parent.mkdir()
            tracked.write_text("inside\n", encoding="utf-8")
            run_git(repo, "add", "linked/changed.txt")
            run_git(repo, "commit", "--quiet", "-m", "add linked path")
            allocation_base = run_git(repo, "rev-parse", "HEAD")
            outside = root / "outside"
            outside.mkdir()
            (outside / "changed.txt").write_text("outside\n", encoding="utf-8")
            tracked.unlink()
            tracked.parent.rmdir()
            tracked.parent.symlink_to(outside, target_is_directory=True)
            manifest = lane_state.empty_manifest()
            lane = valid_lane(repo)
            lane["allowedPaths"] = ["linked", "linked/**"]
            lane["allocationBaseSha"] = allocation_base
            lane["currentBaseSha"] = allocation_base
            allocate_test_lane(manifest, lane)

            disallowed = enforce_test_lane_paths(manifest, "317")

            self.assertIn("linked/changed.txt", disallowed)
            self.assertEqual("blocked", manifest["lanes"]["317"]["laneState"])

    def test_only_exact_approved_deleted_path_passes_canonical_check(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo, _ = create_git_repo(Path(directory))
            deleted = repo / "deleted.txt"
            deleted.write_text("delete me\n", encoding="utf-8")
            run_git(repo, "add", "deleted.txt")
            run_git(repo, "commit", "--quiet", "-m", "add deleted fixture")
            allocation_base = run_git(repo, "rev-parse", "HEAD")
            (repo / "owned.txt").write_text("changed\n", encoding="utf-8")
            deleted.unlink()

            unapproved = lane_state.empty_manifest()
            unapproved_lane = valid_lane(repo)
            unapproved_lane["allowedPaths"] = ["owned.txt", "deleted.txt"]
            unapproved_lane["allocationBaseSha"] = allocation_base
            unapproved_lane["currentBaseSha"] = allocation_base
            allocate_test_lane(unapproved, unapproved_lane)

            self.assertEqual(
                ["deleted.txt"],
                enforce_test_lane_paths(unapproved, "317"),
            )
            self.assertEqual("blocked", unapproved["lanes"]["317"]["laneState"])

            approved = lane_state.empty_manifest()
            approved_lane = valid_lane(repo)
            approved_lane["allowedPaths"] = ["owned.txt", "deleted.txt"]
            approved_lane["allocationBaseSha"] = allocation_base
            approved_lane["currentBaseSha"] = allocation_base
            allocate_test_lane(approved, approved_lane)

            self.assertEqual(
                [],
                enforce_test_lane_paths(
                    approved,
                    "317",
                    approved_delete_path="deleted.txt",
                ),
            )
            self.assertEqual("allocated", approved["lanes"]["317"]["laneState"])

            deleted.write_text("still present\n", encoding="utf-8")
            present = lane_state.empty_manifest()
            present_lane = valid_lane(repo)
            present_lane["allowedPaths"] = ["owned.txt", "deleted.txt"]
            present_lane["allocationBaseSha"] = allocation_base
            present_lane["currentBaseSha"] = allocation_base
            allocate_test_lane(present, present_lane)

            self.assertEqual(
                ["deleted.txt"],
                enforce_test_lane_paths(
                    present,
                    "317",
                    approved_delete_path="deleted.txt",
                ),
            )
            self.assertEqual("blocked", present["lanes"]["317"]["laneState"])

    def test_contained_changed_symlink_passes_when_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo, _ = create_git_repo(Path(directory))
            target = repo / "target.txt"

            target.write_text("target\n", encoding="utf-8")
            run_git(repo, "add", "target.txt")
            run_git(repo, "commit", "--quiet", "-m", "add symlink target")
            allocation_base = run_git(repo, "rev-parse", "HEAD")
            (repo / "link.txt").symlink_to("target.txt")
            manifest = lane_state.empty_manifest()
            lane = valid_lane(repo)
            lane["allowedPaths"] = ["link.txt"]
            lane["allocationBaseSha"] = allocation_base
            lane["currentBaseSha"] = allocation_base
            allocate_test_lane(manifest, lane)

            self.assertEqual(
                [],
                enforce_test_lane_paths(manifest, "317"),
            )
            self.assertEqual("allocated", manifest["lanes"]["317"]["laneState"])

    def test_missing_untracked_candidate_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo, allocation_base = create_git_repo(Path(directory))
            manifest = lane_state.empty_manifest()
            lane = valid_lane(repo)
            lane["allowedPaths"] = ["vanished.txt"]
            lane["allocationBaseSha"] = allocation_base
            lane["currentBaseSha"] = allocation_base
            allocate_test_lane(manifest, lane)

            with mock.patch.object(
                lane_state,
                "changed_paths",
                return_value=["vanished.txt"],
            ):
                disallowed = enforce_test_lane_paths(manifest, "317")

            self.assertEqual(["vanished.txt"], disallowed)
            self.assertEqual("blocked", manifest["lanes"]["317"]["laneState"])

    def test_glob_allowlist_does_not_escape_worktree(self) -> None:
        self.assertEqual(
            ["../outside", "/tmp/outside", "src/../../outside"],
            lane_state.check_allowed_paths(
                ["src/main.py", "../outside", "/tmp/outside", "src/../../outside"],
                ["**"],
            ),
        )
        with self.assertRaises(ValueError):
            lane_state.check_allowed_paths(["src/main.py"], ["../**"])
        with self.assertRaises(ValueError):
            lane_state.check_allowed_paths(["src/main.py"], ["/tmp/**"])

    def test_observed_changed_paths_reject_only_containment_hazards(self) -> None:
        unsafe = [
            "/tmp/outside",
            "C:/outside",
            "../outside",
            "src/../../outside",
            "src/./file.ts",
            "src//file.ts",
            "src\\file.ts",
            "src/nul\0file.ts",
            "src/control\u001ffile.ts",
            "src/control\u0085file.ts",
        ]
        legal_posix = [
            "src/release notes:final.txt",
            "src/CON",
            "src/a?.md",
            'src/a"b|c<d>.md',
            "src/trailing.",
        ]

        self.assertEqual(
            sorted(unsafe),
            lane_state.check_allowed_paths(
                [*legal_posix, *unsafe],
                ["**"],
            ),
        )
        with self.assertRaises(ValueError):
            lane_state.check_allowed_paths([""], ["**"])


    def test_glob_allowlist_is_slash_aware_and_recursive(self) -> None:
        paths = [
            "main.py",
            "src/a.py",
            "src/ab.py",
            "src/nested/a.py",
            "src/test.py",
            "src/unit/deep/test.py",
            "src/x.py",
        ]

        self.assertEqual(
            ["main.py", "src/nested/a.py", "src/unit/deep/test.py"],
            lane_state.check_allowed_paths(paths, ["src/*.py"]),
        )
        self.assertIn(
            "src/x.py",
            lane_state.check_allowed_paths(paths, ["src?x.py"]),
        )
        self.assertEqual(
            ["main.py", "src/a.py", "src/ab.py", "src/nested/a.py", "src/x.py"],
            lane_state.check_allowed_paths(paths, ["src/**/test.py"]),
        )
        self.assertEqual(
            [],
            lane_state.check_allowed_paths(paths, ["**/*.py"]),
        )



class WorktreeIdentityTests(unittest.TestCase):
    def test_check_paths_rejects_symlink_replacement_without_touching_target(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            primary, worktree, manifest, _ = create_registered_lane(root)
            displaced = root / "displaced-lane"
            worktree.rename(displaced)
            os.symlink(primary, worktree, target_is_directory=True)
            target_content = (primary / "owned.txt").read_bytes()
            manifest_path = write_manifest(root, manifest)
            output = io.StringIO()

            with mock.patch("sys.stdout", output):
                exit_code = lane_state.main(
                    [
                        "check-paths",
                        "--manifest",
                        str(manifest_path),
                        "--issue",
                        "317",
                    ]
                )

            self.assertEqual(2, exit_code)
            self.assertEqual(target_content, (primary / "owned.txt").read_bytes())

    def test_evidence_recording_rejects_real_directory_replacement(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, worktree, manifest, head_sha = create_registered_lane(root)
            lane = manifest["lanes"]["317"]
            observation = valid_observation(
                root,
                state="failed",
                head_sha=head_sha,
                base_sha=head_sha,
                lane=lane,
            )
            displaced = root / "displaced-lane"
            worktree.rename(displaced)
            worktree.mkdir()
            sentinel = worktree / "replacement-content"
            sentinel.write_text("untouched\n", encoding="utf-8")
            original = deepcopy(manifest)

            with self.assertRaisesRegex(ValueError, "worktree"):
                lane_state.record_red(manifest, "317", observation)

            self.assertEqual(original, manifest)
            self.assertEqual("untouched\n", sentinel.read_text(encoding="utf-8"))

    def test_readiness_rejects_primary_checkout_replacement(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            primary, worktree, manifest, _ = create_registered_lane(root)
            prepare_ready_lane(manifest, root, "317")
            displaced = root / "displaced-lane"
            worktree.rename(displaced)
            primary.rename(worktree)
            sentinel = worktree / "owned.txt"
            content = sentinel.read_bytes()
            original = deepcopy(manifest)

            with self.assertRaisesRegex(ValueError, "worktree"):
                lane_state.transition_lane(
                    manifest,
                    "317",
                    "ready_for_adam",
                )

            self.assertEqual(original, manifest)
            self.assertEqual(content, sentinel.read_bytes())

    def test_missing_worktree_can_still_be_blocked_and_abandoned(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, worktree, manifest, _ = create_registered_lane(root)
            worktree.rename(root / "displaced-lane")

            lane_state.transition_lane(manifest, "317", "blocked")
            lane_state.transition_lane(manifest, "317", "abandoned")

            self.assertEqual("abandoned", manifest["lanes"]["317"]["laneState"])
class RootSnapshotTests(unittest.TestCase):
    def test_hooks_path_lookup_errors_fail_closed(self) -> None:
        with mock.patch.object(
            lane_state,
            "git_text",
            side_effect=ValueError("git config failed"),
        ):
            with self.assertRaisesRegex(ValueError, "git config failed"):
                lane_state._configured_hooks_path(
                    Path("/repo"),
                    Path("/common"),
                )

    def test_existing_modified_file_change_alters_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo, _ = create_git_repo(Path(directory))
            before = lane_state.root_snapshot(repo)
            (repo / "owned.txt").write_text("modified\n", encoding="utf-8")
            after = lane_state.root_snapshot(repo)

            self.assertEqual(before["headSha"], after["headSha"])
            self.assertEqual(before["indexTreeSha"], after["indexTreeSha"])
            self.assertNotEqual(
                before["trackedDiffSha256"],
                after["trackedDiffSha256"],
            )

    def test_snapshot_rejects_regular_file_changed_after_hashing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo, _ = create_git_repo(Path(directory))
            raced = repo / "race.txt"
            raced.write_text("before\n", encoding="utf-8")
            regular_file_sha256 = lane_state._regular_file_sha256

            def mutate_after_hash(
                path: Path, expected: os.stat_result
            ) -> bytes:
                result = regular_file_sha256(path, expected)
                if path == raced:
                    path.write_text("after\n", encoding="utf-8")
                return result

            with mock.patch.object(
                lane_state,
                "_regular_file_sha256",
                side_effect=mutate_after_hash,
            ):
                with self.assertRaisesRegex(
                    ValueError, "filesystem entry changed while hashing"
                ):
                    lane_state._filesystem_sha256(repo)

    def test_snapshot_rejects_directory_changed_after_listing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo, _ = create_git_repo(Path(directory))
            iterdir = Path.iterdir

            def mutate_after_listing(path: Path) -> object:
                children = list(iterdir(path))
                if path == repo:
                    (repo / "late.txt").write_text("late\n", encoding="utf-8")
                return iter(children)

            with mock.patch.object(
                Path,
                "iterdir",
                autospec=True,
                side_effect=mutate_after_listing,
            ):
                with self.assertRaisesRegex(
                    ValueError, "filesystem entry changed while hashing"
                ):
                    lane_state._filesystem_sha256(repo)

    def test_snapshot_rejects_symlink_changed_after_reading(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "first.txt"
            second = root / "second.txt"
            first.write_text("first\n", encoding="utf-8")
            second.write_text("second\n", encoding="utf-8")
            link = root / "link.txt"
            link.symlink_to(first.name)
            readlink = os.readlink

            def retarget_after_read(path: object) -> object:
                target = readlink(path)
                link.unlink()
                link.symlink_to(second.name)
                return target

            with mock.patch.object(
                os,
                "readlink",
                side_effect=retarget_after_read,
            ):
                with self.assertRaisesRegex(
                    ValueError, "filesystem entry changed while hashing"
                ):
                    lane_state._hash_filesystem_node(
                        hashlib.sha256(),
                        link,
                        b"link.txt",
                    )


    def test_staged_file_changes_index_tree_but_not_head(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo, _ = create_git_repo(Path(directory))
            before = lane_state.root_snapshot(repo)
            (repo / "staged.txt").write_text("staged\n", encoding="utf-8")
            run_git(repo, "add", "staged.txt")

            after = lane_state.root_snapshot(repo)

            self.assertEqual(before["headSha"], after["headSha"])
            self.assertNotEqual(before["indexTreeSha"], after["indexTreeSha"])
            self.assertNotEqual(
                before["gitControlsSha256"],
                after["gitControlsSha256"],
            )
            self.assertEqual(run_git(repo, "write-tree"), after["indexTreeSha"])

    def test_unmerged_index_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo, allocation_base = create_git_repo(Path(directory))
            run_git(repo, "checkout", "--quiet", "-b", "left")
            (repo / "owned.txt").write_text("left\n", encoding="utf-8")
            run_git(repo, "commit", "--quiet", "-am", "left")
            run_git(repo, "checkout", "--quiet", "-b", "right", allocation_base)
            (repo / "owned.txt").write_text("right\n", encoding="utf-8")
            run_git(repo, "commit", "--quiet", "-am", "right")
            run_git(repo, "checkout", "--quiet", "left")
            merge = run_git_unchecked(repo, "merge", "--no-edit", "right")
            self.assertNotEqual(0, merge.returncode)

            with self.assertRaisesRegex(ValueError, "unmerged"):
                lane_state.root_snapshot(repo)

    def test_record_root_snapshot_rejects_invalid_snapshot_payloads(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = lane_state.empty_manifest()
            valid = root_snapshot_fixture()
            missing = deepcopy(valid)
            missing.pop("managedWorktreesSha256")
            extra = deepcopy(valid)
            extra["unexpected"] = True
            wrong_untracked = deepcopy(valid)
            wrong_untracked["untracked"] = {"path": "scratch.txt"}
            invalid_untracked_path = deepcopy(valid)
            invalid_untracked_path["untracked"] = [
                {
                    "path": "../escape",
                    "sha256": "1" * 64,
                }
            ]
            malformed_digest = deepcopy(valid)
            malformed_head = deepcopy(valid)
            malformed_head["headSha"] = "not-a-git-sha"
            malformed_digest["gitControlsSha256"] = "not-a-digest"
            payloads = {
                "opaque JSON": {},
                "missing field": missing,
                "extra field": extra,
                "wrong field type": wrong_untracked,
                "invalid untracked path": invalid_untracked_path,
                "malformed digest": malformed_digest,
                "malformed Git SHA": malformed_head,
            }
            for label, payload in payloads.items():
                with self.subTest(label=label):
                    artifact = root / f"{label.replace(' ', '-')}.json"
                    artifact.write_text(
                        json.dumps(payload),
                        encoding="utf-8",
                    )
                    original = deepcopy(manifest)
                    with self.assertRaises(ValueError):
                        lane_state.record_root_snapshot(
                            manifest,
                            "stage1Before",
                            artifact.resolve().as_uri(),
                        )
                    self.assertEqual(original, manifest)

    def test_record_root_snapshot_accepts_exact_helper_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo, _ = create_git_repo(root)
            payload = lane_state.root_snapshot(repo)
            artifact = root / "root-snapshot.json"
            artifact_bytes = json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            artifact.write_bytes(artifact_bytes)
            manifest = lane_state.empty_manifest()

            lane_state.record_root_snapshot(
                manifest,
                "stage1Before",
                artifact.resolve().as_uri(),
            )

            self.assertEqual(
                {
                    "artifact": artifact.resolve().as_uri(),
                    "sha256": hashlib.sha256(artifact_bytes).hexdigest(),
                },
                manifest["rootSafety"]["stage1Before"],
            )

    def test_stage1_snapshot_artifacts_must_match(self) -> None:
        manifest = lane_state.empty_manifest()
        manifest["rootSafety"]["stage1Before"] = {
            "artifact": "file:///tmp/stage1-before.json",
            "sha256": "1" * 64,
        }
        manifest["rootSafety"]["stage1After"] = {
            "artifact": "file:///tmp/stage1-after.json",
            "sha256": "2" * 64,
        }

        with self.assertRaisesRegex(ValueError, "Stage 1"):
            lane_state.validate_manifest(manifest)

    def test_stage2_wave_snapshot_binds_complete_allocated_lane_set(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = lane_state.empty_manifest()
            allocate_issue(manifest, root, 317)
            allocate_issue(manifest, root, 318)
            artifact = root / "stage2.json"
            artifact_bytes = json.dumps(
                root_snapshot_fixture(),
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            artifact.write_bytes(artifact_bytes)
            artifact_uri = artifact.resolve().as_uri()

            with self.assertRaisesRegex(ValueError, "complete allocated wave"):
                lane_state.record_root_snapshot(
                    manifest,
                    "stage2Before",
                    artifact_uri,
                    wave_id="wave-1",
                    issues=[317],
                )

            lane_state.record_root_snapshot(
                manifest,
                "stage2Before",
                artifact_uri,
                wave_id="wave-1",
                issues=[317, 318],
            )

            wave = manifest["rootSafety"]["stage2Waves"]["wave-1"]
            self.assertEqual("wave-1", wave["waveId"])
            self.assertEqual(["317", "318"], list(wave["laneBindings"]))
            self.assertEqual(
                "4" * 64,
                wave["managedWorktreesSha256"],
            )
            self.assertEqual(
                hashlib.sha256(artifact_bytes).hexdigest(),
                wave["before"]["sha256"],
            )
            with self.assertRaisesRegex(ValueError, "immutable"):
                lane_state.record_root_snapshot(
                    manifest,
                    "stage2Before",
                    artifact_uri,
                    wave_id="wave-1",
                    issues=[317, 318],
                )

            for issue in ("317", "318"):
                transition_test_lane(manifest, issue, "running")
                transition_test_lane(manifest, issue, "reviewing")
            lane_state.record_root_snapshot(
                manifest,
                "stage2After",
                artifact_uri,
                wave_id="wave-1",
                issues=[317, 318],
            )
            completed_wave = manifest["rootSafety"]["stage2Waves"]["wave-1"]
            self.assertEqual(completed_wave["before"], completed_wave["after"])

    def test_stage2_after_compares_persisted_lane_set_in_numeric_order(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = lane_state.empty_manifest()
            allocate_issue(manifest, root, 999)
            allocate_issue(manifest, root, 1000)
            artifact = root / "stage2-persisted-order.json"
            artifact.write_text(
                json.dumps(root_snapshot_fixture()),
                encoding="utf-8",
            )
            artifact_uri = artifact.resolve().as_uri()
            lane_state.record_root_snapshot(
                manifest,
                "stage2Before",
                artifact_uri,
                wave_id="wave-persisted-order",
                issues=[999, 1000],
            )

            manifest = lane_state.load_manifest(write_manifest(root, manifest))
            wave = manifest["rootSafety"]["stage2Waves"]["wave-persisted-order"]
            self.assertEqual(["1000", "999"], list(wave["laneBindings"]))
            for issue in ("999", "1000"):
                transition_test_lane(manifest, issue, "running")
                transition_test_lane(manifest, issue, "reviewing")

            original = deepcopy(manifest)
            with self.assertRaisesRegex(ValueError, "lane set does not match"):
                lane_state.record_root_snapshot(
                    manifest,
                    "stage2After",
                    artifact_uri,
                    wave_id="wave-persisted-order",
                    issues=[999],
                )
            self.assertEqual(original, manifest)

            lane_state.record_root_snapshot(
                manifest,
                "stage2After",
                artifact_uri,
                wave_id="wave-persisted-order",
                issues=[999, 1000],
            )
            completed_wave = manifest["rootSafety"]["stage2Waves"][
                "wave-persisted-order"
            ]
            self.assertEqual(completed_wave["before"], completed_wave["after"])

    def test_stage2_after_rejects_changed_managed_worktree_set(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = lane_state.empty_manifest()
            allocate_issue(manifest, root, 317)
            before_artifact = root / "stage2-before.json"
            before_artifact.write_text(
                json.dumps(root_snapshot_fixture()),
                encoding="utf-8",
            )
            lane_state.record_root_snapshot(
                manifest,
                "stage2Before",
                before_artifact.resolve().as_uri(),
                wave_id="wave-1",
                issues=[317],
            )
            transition_test_lane(manifest, "317", "running")
            transition_test_lane(manifest, "317", "reviewing")
            changed = root_snapshot_fixture()
            changed["managedWorktreesSha256"] = "5" * 64
            after_artifact = root / "stage2-after.json"
            after_artifact.write_text(json.dumps(changed), encoding="utf-8")
            original = deepcopy(manifest)

            with self.assertRaisesRegex(
                ValueError,
                "managed worktree registration set changed",
            ):
                lane_state.record_root_snapshot(
                    manifest,
                    "stage2After",
                    after_artifact.resolve().as_uri(),
                    wave_id="wave-1",
                    issues=[317],
                )

            self.assertEqual(original, manifest)

    def test_record_root_snapshot_rejects_symlinked_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            target = root / "snapshot.json"
            target.write_text(
                json.dumps(root_snapshot_fixture()),
                encoding="utf-8",
            )
            artifact = root / "snapshot-link.json"
            artifact.symlink_to(target)
            manifest = lane_state.empty_manifest()
            original = deepcopy(manifest)

            with self.assertRaisesRegex(ValueError, "symlink"):
                lane_state.record_root_snapshot(
                    manifest,
                    "stage1Before",
                    artifact.absolute().as_uri(),
                )
            self.assertEqual(original, manifest)

    def test_root_artifact_is_chunk_hashed_inside_manifest_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = lane_state.empty_manifest()
            path = write_manifest(root, manifest)
            artifact = root / "large-snapshot.json"
            artifact_bytes = json.dumps(
                root_snapshot_fixture(),
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            artifact.write_bytes(artifact_bytes)
            chunk_size = 64
            callback_active = False
            chunk_sizes: list[int] = []
            original_mutate = lane_state.mutate_manifest
            real_sha256 = hashlib.sha256

            class TrackingDigest:
                def __init__(self) -> None:
                    self.digest = real_sha256()

                def update(self, chunk: bytes) -> None:
                    if not callback_active:
                        raise AssertionError("artifact hashed outside mutation callback")
                    chunk_sizes.append(len(chunk))
                    self.digest.update(chunk)

                def hexdigest(self) -> str:
                    return self.digest.hexdigest()

            def tracking_sha256(data: bytes = b"") -> TrackingDigest:
                digest = TrackingDigest()
                if data:
                    digest.update(data)
                return digest

            def observing_mutate(
                manifest_path: Path,
                expected_updated_at: str,
                mutation: object,
            ) -> dict[str, object]:
                def observed(data: dict[str, object]) -> None:
                    nonlocal callback_active
                    callback_active = True
                    try:
                        mutation(data)
                    finally:
                        callback_active = False

                return original_mutate(
                    manifest_path,
                    expected_updated_at,
                    observed,
                )

            output = io.StringIO()
            with (
                mock.patch.object(
                    lane_state,
                    "ARTIFACT_HASH_CHUNK_SIZE",
                    chunk_size,
                ),
                mock.patch.object(
                    lane_state,
                    "mutate_manifest",
                    side_effect=observing_mutate,
                ),
                mock.patch.object(
                    Path,
                    "read_bytes",
                    side_effect=AssertionError("whole-file read"),
                ),
                mock.patch.object(
                    lane_state.hashlib,
                    "sha256",
                    side_effect=tracking_sha256,
                ),
                mock.patch("sys.stdout", output),
            ):
                exit_code = lane_state.main(
                    [
                        "record-root-snapshot",
                        "--manifest",
                        str(path),
                        "--expected-updated-at",
                        manifest["updatedAt"],
                        "--slot",
                        "stage1Before",
                        "--artifact",
                        artifact.resolve().as_uri(),
                    ]
                )

            self.assertEqual(0, exit_code)
            self.assertEqual(
                [
                    len(artifact_bytes[offset : offset + chunk_size])
                    for offset in range(0, len(artifact_bytes), chunk_size)
                ],
                chunk_sizes,
            )
            updated = lane_state.load_manifest(path)
            self.assertEqual(
                hashlib.sha256(artifact.read_bytes()).hexdigest(),
                updated["rootSafety"]["stage1Before"]["sha256"],
            )
            with self.assertRaisesRegex(ValueError, "local file"):
                lane_state.record_root_snapshot(
                    updated,
                    "stage1After",
                    "https://example.invalid/snapshot.json",
                )
            with self.assertRaisesRegex(ValueError, "cannot read root snapshot artifact"):
                lane_state.record_root_snapshot(
                    updated,
                    "stage1After",
                    (root / "missing.json").resolve().as_uri(),
                )

    def test_untracked_files_use_shared_hash_chunk_size(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            (repo / "untracked.txt").write_bytes(b"x" * 20)
            read_sizes: list[int] = []
            real_read = os.read

            def fake_git_bytes(_repo: Path, *args: str) -> bytes:
                if args == ("rev-parse", "HEAD"):
                    return SHA_A.encode()
                if args == ("ls-files", "--stage", "-z"):
                    return b""
                if args == (
                    "ls-files",
                    "--others",
                    "--exclude-standard",
                    "-z",
                ):
                    return b"untracked.txt\0"
                if args[0] == "diff":
                    return b""
                raise AssertionError(f"unexpected Git command: {args}")

            def tracking_read(file_descriptor: int, size: int) -> bytes:
                read_sizes.append(size)
                return real_read(file_descriptor, size)

            with (
                mock.patch.object(lane_state, "ARTIFACT_HASH_CHUNK_SIZE", 7),
                mock.patch.object(
                    lane_state,
                    "_git_bytes",
                    side_effect=fake_git_bytes,
                ),
                mock.patch.object(
                    lane_state,
                    "_filesystem_sha256",
                    return_value="0" * 64,
                ),
                mock.patch.object(
                    lane_state,
                    "_git_controls_sha256",
                    return_value="0" * 64,
                ),
                mock.patch.object(
                    lane_state,
                    "_managed_worktrees_sha256",
                    return_value="0" * 64,
                ),
                mock.patch.object(
                    lane_state.os,
                    "read",
                    side_effect=tracking_read,
                ),
            ):
                lane_state.root_snapshot(repo)
            self.assertEqual([7] * 8, read_sizes)

    def test_untracked_file_mutation_during_hashing_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo, _ = create_git_repo(Path(directory))
            path = repo / "untracked.txt"
            path.write_bytes(b"before")
            identity = path.lstat().st_dev, path.lstat().st_ino
            read = os.read
            mutated = False

            def mutate_after_read(file_descriptor: int, size: int) -> bytes:
                nonlocal mutated
                chunk = read(file_descriptor, size)
                opened = os.fstat(file_descriptor)
                if chunk and not mutated and (opened.st_dev, opened.st_ino) == identity:
                    mutated = True
                    path.write_bytes(b"after")
                return chunk

            with mock.patch.object(
                lane_state.os,
                "read",
                side_effect=mutate_after_read,
            ):
                with self.assertRaisesRegex(
                    ValueError, "changed while hashing"
                ):
                    lane_state.root_snapshot(repo)

    def test_untracked_symlink_retarget_during_hashing_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo, _ = create_git_repo(Path(directory))
            link = repo / "untracked-link"
            link.symlink_to("first")
            canonical_link = repo.resolve(strict=True) / link.name
            readlink = os.readlink
            retargeted = False

            def retarget_after_read(path: object) -> object:
                nonlocal retargeted
                target = readlink(path)
                if os.fsdecode(path) == str(canonical_link) and not retargeted:
                    retargeted = True
                    link.unlink()
                    link.symlink_to("second")
                return target

            with mock.patch.object(
                lane_state.os,
                "readlink",
                side_effect=retarget_after_read,
            ):
                with self.assertRaisesRegex(
                    ValueError, "changed while hashing"
                ):
                    lane_state.root_snapshot(repo)

    def test_snapshot_rejects_head_change_before_return(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo, _ = create_git_repo(Path(directory))
            managed_worktrees_sha256 = lane_state._managed_worktrees_sha256

            def change_head_after_hash(repository: Path) -> str:
                result = managed_worktrees_sha256(repository)
                run_git(
                    repository,
                    "commit",
                    "--quiet",
                    "--allow-empty",
                    "-m",
                    "concurrent head change",
                )
                return result

            with mock.patch.object(
                lane_state,
                "_managed_worktrees_sha256",
                side_effect=change_head_after_hash,
            ):
                with self.assertRaisesRegex(ValueError, "HEAD changed"):
                    lane_state.root_snapshot(repo)

    def test_untracked_content_change_alters_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo, _ = create_git_repo(Path(directory))
            path = repo / "untracked.txt"
            path.write_bytes(b"first")
            before = lane_state.root_snapshot(repo)
            path.write_bytes(b"second")
            after = lane_state.root_snapshot(repo)

            self.assertNotEqual(before["untracked"], after["untracked"])

    def test_snapshot_rechecks_filesystem_after_component_hashing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo, _ = create_git_repo(Path(directory))
            ignored = repo / "ignored.txt"
            ignored.write_text("before\n", encoding="utf-8")
            (repo / ".git" / "info" / "exclude").write_text(
                "ignored.txt\n",
                encoding="utf-8",
            )
            filesystem_sha256 = lane_state._filesystem_sha256
            mutated = False

            def mutate_after_hash(repository: Path) -> str:
                nonlocal mutated
                result = filesystem_sha256(repository)
                if not mutated:
                    mutated = True
                    ignored.write_text("after\n", encoding="utf-8")
                return result

            with mock.patch.object(
                lane_state,
                "_filesystem_sha256",
                side_effect=mutate_after_hash,
            ):
                with self.assertRaisesRegex(ValueError, "changed between passes"):
                    lane_state.root_snapshot(repo)

    def test_snapshot_rechecks_git_controls_after_component_hashing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo, _ = create_git_repo(Path(directory))
            exclude = repo / ".git" / "info" / "exclude"
            git_controls_sha256 = lane_state._git_controls_sha256
            mutated = False

            def mutate_after_hash(repository: Path) -> str:
                nonlocal mutated
                result = git_controls_sha256(repository)
                if not mutated:
                    mutated = True
                    exclude.write_text("changed\n", encoding="utf-8")
                return result

            with mock.patch.object(
                lane_state,
                "_git_controls_sha256",
                side_effect=mutate_after_hash,
            ):
                with self.assertRaisesRegex(ValueError, "changed between passes"):
                    lane_state.root_snapshot(repo)

    def test_untracked_symlink_target_change_alters_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo, _ = create_git_repo(Path(directory))
            (repo / "target-one").write_text("one", encoding="utf-8")
            (repo / "target-two").write_text("two", encoding="utf-8")
            link = repo / "untracked-link"
            link.symlink_to("target-one")
            before = lane_state.root_snapshot(repo)
            link.unlink()
            link.symlink_to("target-two")
            after = lane_state.root_snapshot(repo)

            before_link = next(
                item
                for item in before["untracked"]
                if item["path"] == "untracked-link"
            )
            after_link = next(
                item
                for item in after["untracked"]
                if item["path"] == "untracked-link"
            )
            self.assertNotEqual(before_link["sha256"], after_link["sha256"])

    def test_snapshot_covers_ignored_files_modes_and_symlink_targets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo, _ = create_git_repo(Path(directory))
            (repo / ".gitignore").write_text("ignored-*\n", encoding="utf-8")
            run_git(repo, "add", ".gitignore")
            run_git(repo, "commit", "--quiet", "-m", "ignore fixtures")
            ignored = repo / "ignored-file"
            ignored.write_text("one\n", encoding="utf-8")
            first = lane_state.root_snapshot(repo)
            self.assertEqual([], first["untracked"])
            self.assertRegex(first["filesystemSha256"], r"^[0-9a-f]{64}$")
            self.assertRegex(first["gitControlsSha256"], r"^[0-9a-f]{64}$")

            ignored.write_text("two\n", encoding="utf-8")
            content_changed = lane_state.root_snapshot(repo)
            self.assertNotEqual(
                first["filesystemSha256"],
                content_changed["filesystemSha256"],
            )

            ignored.chmod(0o700)
            mode_changed = lane_state.root_snapshot(repo)
            self.assertNotEqual(
                content_changed["filesystemSha256"],
                mode_changed["filesystemSha256"],
            )

            link = repo / "ignored-link"
            link.symlink_to("first-target")
            linked = lane_state.root_snapshot(repo)
            link.unlink()
            link.symlink_to("second-target")
            relinked = lane_state.root_snapshot(repo)
            self.assertNotEqual(
                linked["filesystemSha256"],
                relinked["filesystemSha256"],
            )

    def test_snapshot_excludes_only_root_managed_worktrees(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo, _ = create_git_repo(Path(directory))
            (repo / ".gitignore").write_text(
                "/.worktrees/\n/ignored-outside\n",
                encoding="utf-8",
            )
            run_git(repo, "add", ".gitignore")
            run_git(repo, "commit", "--quiet", "-m", "ignore managed fixtures")

            managed = repo / ".worktrees" / "lane" / "state"
            managed.parent.mkdir(parents=True)
            managed.write_text("one\n", encoding="utf-8")
            nested = repo / "user" / ".worktrees" / "state"
            nested.parent.mkdir(parents=True)
            nested.write_text("one\n", encoding="utf-8")
            ignored = repo / "ignored-outside"
            ignored.write_text("one\n", encoding="utf-8")
            baseline = lane_state.root_snapshot(repo)

            managed.write_text("two\n", encoding="utf-8")
            managed_changed = lane_state.root_snapshot(repo)
            self.assertEqual(
                baseline["filesystemSha256"],
                managed_changed["filesystemSha256"],
            )

            nested.write_text("two\n", encoding="utf-8")
            nested_changed = lane_state.root_snapshot(repo)
            self.assertNotEqual(
                managed_changed["filesystemSha256"],
                nested_changed["filesystemSha256"],
            )

            ignored.write_text("two\n", encoding="utf-8")
            ignored_changed = lane_state.root_snapshot(repo)
            self.assertNotEqual(
                nested_changed["filesystemSha256"],
                ignored_changed["filesystemSha256"],
            )

    def test_managed_worktrees_digest_tracks_entries_and_registrations(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo, head = create_git_repo(Path(directory))
            baseline = lane_state.root_snapshot(repo)
            self.assertEqual(
                {
                    "headSha",
                    "indexTreeSha",
                    "trackedDiffSha256",
                    "untracked",
                    "filesystemSha256",
                    "gitControlsSha256",
                    "managedWorktreesSha256",
                },
                set(baseline),
            )

            managed = repo / ".worktrees"
            lane = managed / "lane"
            run_git(repo, "worktree", "add", "--detach", str(lane), head)
            registered = lane_state.root_snapshot(repo)
            self.assertNotEqual(
                baseline["managedWorktreesSha256"],
                registered["managedWorktreesSha256"],
            )

            (lane / "scratch.txt").write_text("lane write\n", encoding="utf-8")
            lane_written = lane_state.root_snapshot(repo)
            self.assertEqual(
                registered["managedWorktreesSha256"],
                lane_written["managedWorktreesSha256"],
            )

            (lane / "owned.txt").write_text(
                "linked worktree commit\n",
                encoding="utf-8",
            )
            run_git(lane, "commit", "--quiet", "-am", "linked advance")
            head_advanced = lane_state.root_snapshot(repo)
            self.assertEqual(
                registered["managedWorktreesSha256"],
                head_advanced["managedWorktreesSha256"],
            )

            run_git(lane, "switch", "--quiet", "-c", "issue-317")
            branch_changed = lane_state.root_snapshot(repo)
            self.assertNotEqual(
                head_advanced["managedWorktreesSha256"],
                branch_changed["managedWorktreesSha256"],
            )

            run_git(repo, "worktree", "remove", "--force", str(lane))
            removed = lane_state.root_snapshot(repo)
            self.assertEqual(
                baseline["managedWorktreesSha256"],
                removed["managedWorktreesSha256"],
            )

            leftover = managed / "leftover"

            ordinary_file = managed / "ordinary.txt"
            ordinary_file.write_text("ordinary\n", encoding="utf-8")
            with_file = lane_state.root_snapshot(repo)
            self.assertNotEqual(
                baseline["managedWorktreesSha256"],
                with_file["managedWorktreesSha256"],
            )
            ordinary_file.unlink()

            ordinary_directory = managed / "ordinary-directory"
            ordinary_directory.mkdir()
            with_directory = lane_state.root_snapshot(repo)
            self.assertNotEqual(
                baseline["managedWorktreesSha256"],
                with_directory["managedWorktreesSha256"],
            )
            ordinary_directory.rmdir()

            ordinary_symlink = managed / "ordinary-symlink"
            ordinary_symlink.symlink_to("ordinary-target")
            with_symlink = lane_state.root_snapshot(repo)
            self.assertNotEqual(
                baseline["managedWorktreesSha256"],
                with_symlink["managedWorktreesSha256"],
            )
            ordinary_symlink.unlink()
            self.assertEqual(
                baseline["managedWorktreesSha256"],
                lane_state.root_snapshot(repo)["managedWorktreesSha256"],
            )
            leftover.mkdir()
            leftover_snapshot = lane_state.root_snapshot(repo)
            self.assertNotEqual(
                baseline["managedWorktreesSha256"],
                leftover_snapshot["managedWorktreesSha256"],
            )
            leftover.rmdir()

            stale = managed / "stale"
            run_git(repo, "worktree", "add", "--detach", str(stale), head)
            shutil.rmtree(stale)
            stale_registration = lane_state.root_snapshot(repo)
            self.assertNotEqual(
                baseline["managedWorktreesSha256"],
                stale_registration["managedWorktreesSha256"],
            )
            run_git(repo, "worktree", "prune")
            pruned = lane_state.root_snapshot(repo)
            self.assertEqual(
                baseline["managedWorktreesSha256"],
                pruned["managedWorktreesSha256"],
            )

    def test_worktree_registration_parser_rejects_malformed_records(self) -> None:
        path = b"/tmp/cmtraceopen-lane"
        valid = (
            b"worktree "
            + path
            + b"\0HEAD "
            + SHA_A.encode("ascii")
            + b"\0detached\0\0"
        )
        same_identity_new_head = valid.replace(
            SHA_A.encode("ascii"),
            SHA_B.encode("ascii"),
        )
        self.assertEqual(
            lane_state._normalized_worktree_registrations(valid),
            lane_state._normalized_worktree_registrations(
                same_identity_new_head
            ),
        )

        invalid_records = {
            "empty": b"",
            "relative path": valid.replace(path, b"relative/lane"),
            "missing identity": valid.replace(b"detached\0", b""),
            "malformed head": valid.replace(
                SHA_A.encode("ascii"),
                b"short",
            ),
            "duplicate field": valid.replace(
                b"detached\0",
                b"detached\0detached\0",
            ),
            "unknown field": valid.replace(
                b"detached\0",
                b"detached\0unknown value\0",
            ),
            "duplicate record": valid + valid,
        }
        for label, raw in invalid_records.items():
            with self.subTest(label=label):
                with self.assertRaises(ValueError):
                    lane_state._normalized_worktree_registrations(raw)

    def test_git_controls_reject_symlinked_controls_and_parents(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            repo, _ = create_git_repo(root)
            git_dir = Path(run_git(repo, "rev-parse", "--absolute-git-dir"))
            outside = root / "outside"
            outside.mkdir()
            outside_file = outside / "control"
            outside_file.write_text("outside\n", encoding="utf-8")

            attributes = git_dir / "info" / "attributes"
            attributes.symlink_to(outside_file)
            with self.assertRaisesRegex(ValueError, "symlink"):
                lane_state.root_snapshot(repo)
            attributes.unlink()

            hooks = root / "external-hooks"
            hooks.mkdir()
            (hooks / "pre-commit").symlink_to(outside_file)
            run_git(repo, "config", "core.hooksPath", str(hooks))
            with self.assertRaisesRegex(ValueError, "symlink"):
                lane_state.root_snapshot(repo)
            (hooks / "pre-commit").unlink()

            hooks_parent = root / "hooks-parent"
            hooks_parent.symlink_to(outside, target_is_directory=True)
            run_git(
                repo,
                "config",
                "core.hooksPath",
                str(hooks_parent),
            )
            with self.assertRaisesRegex(ValueError, "symlink"):
                lane_state.root_snapshot(repo)

    def test_snapshot_covers_primary_git_control_files_and_hooks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo, head = create_git_repo(Path(directory))
            git_dir = Path(run_git(repo, "rev-parse", "--absolute-git-dir"))
            hooks = Path(directory).resolve() / "effective-hooks"
            hooks.mkdir()
            run_git(repo, "config", "core.hooksPath", str(hooks))
            baseline = lane_state.root_snapshot(repo)

            run_git(repo, "config", "cmtraceopen.marker", "one")
            config_changed = lane_state.root_snapshot(repo)
            self.assertNotEqual(
                baseline["gitControlsSha256"],
                config_changed["gitControlsSha256"],
            )

            (hooks / "pre-commit").write_text("#!/bin/sh\n", encoding="utf-8")
            hooks_changed = lane_state.root_snapshot(repo)
            self.assertNotEqual(
                config_changed["gitControlsSha256"],
                hooks_changed["gitControlsSha256"],
            )

            info = git_dir / "info"
            (info / "attributes").write_text("* -text\n", encoding="utf-8")
            attributes_changed = lane_state.root_snapshot(repo)
            self.assertNotEqual(
                hooks_changed["gitControlsSha256"],
                attributes_changed["gitControlsSha256"],
            )

            (info / "exclude").write_text("private\n", encoding="utf-8")
            exclude_changed = lane_state.root_snapshot(repo)
            self.assertNotEqual(
                attributes_changed["gitControlsSha256"],
                exclude_changed["gitControlsSha256"],
            )

            branch = run_git(repo, "symbolic-ref", "--short", "HEAD")
            head_file = git_dir / "HEAD"
            (git_dir / "refs" / "heads" / "alternate").write_text(
                head + "\n",
                encoding="ascii",
            )
            head_file.write_text(
                "ref: refs/heads/alternate\n",
                encoding="ascii",
            )
            head_control_changed = lane_state.root_snapshot(repo)
            self.assertEqual(head, head_control_changed["headSha"])
            self.assertNotEqual(
                exclude_changed["gitControlsSha256"],
                head_control_changed["gitControlsSha256"],
            )

            head_file.write_text(f"ref: refs/heads/{branch}\n", encoding="ascii")
            before_primary_change = lane_state.root_snapshot(repo)
            (repo / "owned.txt").write_text("branch update\n", encoding="utf-8")
            run_git(repo, "commit", "--quiet", "-am", "branch update")
            primary_changed = lane_state.root_snapshot(repo)
            self.assertNotEqual(
                before_primary_change["headSha"],
                primary_changed["headSha"],
            )

            run_git(repo, "branch", "unrelated", head)
            before_packing = lane_state.root_snapshot(repo)
            run_git(repo, "pack-refs", "--all", "--prune")
            packed = lane_state.root_snapshot(repo)
            self.assertEqual(
                before_packing["headSha"],
                packed["headSha"],
            )
            self.assertEqual(
                before_packing["gitControlsSha256"],
                packed["gitControlsSha256"],
            )

            sparse_checkout = info / "sparse-checkout"
            sparse_checkout.write_text("/*\n", encoding="utf-8")
            sparse_first = lane_state.root_snapshot(repo)
            sparse_checkout.write_text("!/private\n", encoding="utf-8")
            sparse_second = lane_state.root_snapshot(repo)
            self.assertNotEqual(
                sparse_first["gitControlsSha256"],
                sparse_second["gitControlsSha256"],
            )

    def test_snapshot_handles_deep_directory_chain_without_recursion(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo, _ = create_git_repo(Path(directory))
            deepest = repo
            for depth in range(100):
                deepest /= f"d{depth:03}"
                deepest.mkdir()
            (deepest / "leaf.txt").write_text("leaf\n", encoding="utf-8")

            original_limit = sys.getrecursionlimit()
            try:
                sys.setrecursionlimit(80)
                snapshot = lane_state.root_snapshot(repo)
            finally:
                sys.setrecursionlimit(original_limit)

            self.assertRegex(snapshot["filesystemSha256"], r"\A[0-9a-f]{64}\Z")

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires os.mkfifo")
    def test_snapshot_rejects_unsupported_primary_filesystem_nodes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo, _ = create_git_repo(Path(directory))
            fifo = repo / "unsupported-fifo"
            os.mkfifo(fifo)

            with self.assertRaisesRegex(ValueError, "unsupported"):
                lane_state.root_snapshot(repo)

    def test_identical_checkout_produces_identical_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo, _ = create_git_repo(root)
            clone = root / "clone"
            clone_git_repo(repo, clone)

            source = lane_state.root_snapshot(repo)
            copied = lane_state.root_snapshot(clone)
            for field in (
                "headSha",
                "indexTreeSha",
                "trackedDiffSha256",
                "untracked",
                "filesystemSha256",
            ):
                self.assertEqual(source[field], copied[field])


class InvalidationTests(unittest.TestCase):
    def test_lane_head_change_stales_every_head_bound_observation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = lane_state.empty_manifest()
            allocate_issue(manifest, root, 317)
            record_all_observations(
                manifest,
                root,
                "317",
                native_base_sensitive=True,
            )
            manifest["lanes"]["317"]["implementationState"] = "green"
            manifest["lanes"]["317"]["mergeabilityState"] = "mergeable"

            update_test_heads(manifest, "317", head_sha=SHA_C, current_base_sha=SHA_B)

            lane = manifest["lanes"]["317"]
            self.assertEqual(SHA_C, lane["headSha"])
            self.assertEqual("stale", lane["implementationState"])
            self.assertEqual("stale", lane["mergeabilityState"])
            self.assertTrue(
                all(
                    lane["gates"][gate_name]["state"] == "stale"
                    for gate_name in (
                        "focused",
                        "aggregate",
                        "conformance",
                        "coderabbit",
                        "independent_review",
                        "native_lab",
                        "mergeability",
                    )
                )
            )

    def test_base_head_change_stales_aggregate_reviews_and_mergeability(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = lane_state.empty_manifest()
            allocate_issue(manifest, root, 317)
            record_all_observations(
                manifest,
                root,
                "317",
                native_base_sensitive=True,
            )
            manifest["lanes"]["317"]["implementationState"] = "green"
            manifest["lanes"]["317"]["mergeabilityState"] = "mergeable"

            update_test_heads(manifest, "317", head_sha=SHA_A, current_base_sha=SHA_C)

            lane = manifest["lanes"]["317"]
            self.assertEqual("green", lane["implementationState"])
            self.assertEqual("passed", lane["gates"]["focused"]["state"])
            for gate_name in (
                "aggregate",
                "conformance",
                "coderabbit",
                "independent_review",
                "native_lab",
                "mergeability",
            ):
                self.assertEqual("stale", lane["gates"][gate_name]["state"])
            self.assertEqual("stale", lane["mergeabilityState"])
            self.assertTrue(
                all(
                    observation["baseSha"] == SHA_B
                    for observation in lane["gates"].values()
                    if observation["baseSha"] is not None
                )
            )


    def test_unchanged_heads_preserve_observations(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = lane_state.empty_manifest()
            allocate_issue(manifest, root, 317)
            record_all_observations(manifest, root, "317")
            original_lane = deepcopy(manifest["lanes"]["317"])

            update_test_heads(manifest, "317", head_sha=SHA_A, current_base_sha=SHA_B)

            self.assertEqual(original_lane, manifest["lanes"]["317"])

    def test_shared_contract_change_stales_direct_and_transitive_dependents(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = lane_state.empty_manifest()
            allocate_issue(manifest, root, 317)
            allocate_issue(
                manifest,
                root,
                318,
                depends_on=[317],
                shared_contract_paths=["contracts/**"],
            )
            allocate_issue(
                manifest,
                root,
                319,
                depends_on=[318],
                shared_contract_paths=["contracts/**"],
            )
            artifact = root / "stage2-root.json"
            artifact.write_text(
                json.dumps(root_snapshot_fixture()),
                encoding="utf-8",
            )
            artifact_uri = artifact.resolve().as_uri()
            manifest["lanes"]["317"]["laneState"] = "merged"
            lane_state.record_root_snapshot(
                manifest,
                "stage2Before",
                artifact_uri,
                wave_id="dependent-wave",
                issues=[318, 319],
            )
            for issue in ("318", "319"):
                record_all_observations(manifest, root, issue)
                manifest["lanes"][issue]["implementationState"] = "green"
                transition_test_lane(manifest, issue, "running")
                transition_test_lane(manifest, issue, "reviewing")
            lane_state.record_root_snapshot(
                manifest,
                "stage2After",
                artifact_uri,
                wave_id="dependent-wave",
                issues=[318, 319],
            )
            for issue in ("318", "319"):
                transition_test_lane(manifest, issue, "ready_for_adam")

            invalidated = lane_state.invalidate_dependents(
                manifest,
                "317",
                ["contracts/schema.json"],
            )

            self.assertEqual(["318", "319"], invalidated)
            for issue in invalidated:
                lane = manifest["lanes"][issue]
                self.assertEqual("reviewing", lane["laneState"])
                self.assertEqual("stale", lane["mergeabilityState"])
                self.assertIn("revalidate", lane["nextAction"])
                self.assertTrue(
                    all(
                        lane["gates"][gate_name]["state"] == "stale"
                        for gate_name in (
                            "aggregate",
                            "conformance",
                            "coderabbit",
                            "independent_review",
                            "mergeability",
                        )
                    )
                )

    def test_unrelated_upstream_change_preserves_downstream_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = lane_state.empty_manifest()
            allocate_issue(manifest, root, 317)
            allocate_issue(
                manifest,
                root,
                318,
                depends_on=[317],
                shared_contract_paths=["contracts/**"],
            )
            record_all_observations(manifest, root, "318")
            original_lane = deepcopy(manifest["lanes"]["318"])

            invalidated = lane_state.invalidate_dependents(
                manifest,
                "317",
                ["src/unrelated.py"],
            )

            self.assertEqual([], invalidated)
            self.assertEqual(original_lane, manifest["lanes"]["318"])


class BaseEvidenceTests(unittest.TestCase):
    def test_base_sensitive_pass_requires_matching_integration_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for gate_name in (
                "aggregate",
                "conformance",
                "coderabbit",
                "independent_review",
                "native_lab",
                "mergeability",
            ):
                with self.subTest(gate=gate_name):
                    manifest = lane_state.empty_manifest()
                    allocate_issue(manifest, root, 317)
                    observation = base_observation(root, gate_name)

                    if gate_name in {"coderabbit", "independent_review"}:
                        with self.assertRaises(ValueError):
                            lane_state.validate_base_evidence(
                                manifest,
                                "317",
                                gate_name,
                                observation,
                            )
                        lane_state.record_pr(
                            manifest,
                            "317",
                            42,
                            PR_URL,
                        )
                    lane_state.validate_base_evidence(
                        manifest,
                        "317",
                        gate_name,
                        observation,
                    )

    def test_github_review_artifact_binds_exact_pr_and_gate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for gate_name in ("coderabbit", "independent_review"):
                with self.subTest(gate=gate_name):
                    manifest = lane_state.empty_manifest()
                    allocate_issue(manifest, root, 317)
                    lane_state.record_pr(
                        manifest,
                        "317",
                        42,
                        PR_URL,
                    )
                    observation = base_observation(root, gate_name)
                    evidence_path = artifact_path(observation["artifact"])
                    original = json.loads(evidence_path.read_text(encoding="utf-8"))

                    lane_state.validate_base_evidence(
                        manifest,
                        "317",
                        gate_name,
                        observation,
                    )

                    for field, wrong_value in (
                        ("prNumber", 43),
                        ("prUrl", PR_43_URL),
                        (
                            "reviewGate",
                            "independent_review"
                            if gate_name == "coderabbit"
                            else "coderabbit",
                        ),
                        ("isDraft", False),
                    ):
                        with self.subTest(gate=gate_name, field=field):
                            invalid = deepcopy(original)
                            invalid[field] = wrong_value
                            evidence_path.write_text(
                                json.dumps(invalid),
                                encoding="utf-8",
                            )
                            observation["artifact"] = artifact_ref(evidence_path)
                            with self.assertRaises(ValueError):
                                lane_state.validate_base_evidence(
                                    manifest,
                                    "317",
                                    gate_name,
                                    observation,
                                )
                            evidence_path.write_text(
                                json.dumps(original),
                                encoding="utf-8",
                            )
                            observation["artifact"] = artifact_ref(evidence_path)
                    for missing_field in (
                        "prNumber",
                        "prUrl",
                        "reviewGate",
                        "isDraft",
                        "rawEvidenceSha256",
                    ):
                        with self.subTest(
                            gate=gate_name,
                            missing=missing_field,
                        ):
                            invalid = deepcopy(original)
                            invalid.pop(missing_field)
                            evidence_path.write_text(
                                json.dumps(invalid),
                                encoding="utf-8",
                            )
                            observation["artifact"] = artifact_ref(evidence_path)
                            with self.assertRaises(ValueError):
                                lane_state.validate_base_evidence(
                                    manifest,
                                    "317",
                                    gate_name,
                                    observation,
                                )
                    invalid = deepcopy(original)
                    invalid["unexpected"] = True
                    evidence_path.write_text(
                        json.dumps(invalid),
                        encoding="utf-8",
                    )
                    observation["artifact"] = artifact_ref(evidence_path)
                    with self.assertRaises(ValueError):
                        lane_state.validate_base_evidence(
                            manifest,
                            "317",
                            gate_name,
                            observation,
                        )

    def test_coderabbit_pass_requires_clean_stable_raw_verdict(self) -> None:
        variants = (
            "unapproved",
            "actionable-thread",
            "wrong-base",
            "stale-head",
        )
        for variant in variants:
            with self.subTest(variant=variant):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    manifest = lane_state.empty_manifest()
                    allocate_issue(manifest, root, 317)
                    lane_state.record_pr(manifest, "317", 42, PR_URL)
                    observation = base_observation(root, "coderabbit")
                    evidence_path = artifact_path(observation["artifact"])
                    artifact = json.loads(
                        evidence_path.read_text(encoding="utf-8")
                    )
                    raw_path = Path(
                        unquote(urlparse(artifact["rawEvidenceUri"]).path)
                    )
                    raw = json.loads(raw_path.read_text(encoding="utf-8"))
                    if variant == "unapproved":
                        raw["summary"]["approved_at_head"] = False
                    elif variant == "actionable-thread":
                        raw["summary"][
                            "unresolved_coderabbit_thread_count"
                        ] = 1
                        raw["summary"]["unresolved_thread_count"] = 1
                        raw["unresolved_threads"] = [
                            {
                                "id": "thread-1",
                                "isResolved": False,
                                "isOutdated": False,
                                "comments": {
                                    "nodes": [
                                        {
                                            "author": {
                                                "login": "coderabbitai[bot]"
                                            }
                                        }
                                    ]
                                },
                            }
                        ]
                    elif variant == "wrong-base":
                        raw["pull_request"]["base_sha"] = SHA_C
                    else:
                        raw["pull_request"]["head_sha"] = SHA_C
                    rewrite_review_raw(observation, raw)

                    with self.assertRaises(ValueError):
                        lane_state.validate_base_evidence(
                            manifest,
                            "317",
                            "coderabbit",
                            observation,
                        )

    def test_independent_pass_requires_clean_exact_head_raw_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = lane_state.empty_manifest()
            allocate_issue(manifest, root, 317)
            lane_state.record_pr(manifest, "317", 42, PR_URL)
            observation = base_observation(root, "independent_review")
            lane_state.validate_base_evidence(
                manifest,
                "317",
                "independent_review",
                observation,
            )

        variants = (
            "findings",
            "blockers",
            "empty-coverage",
            "empty-gate-states",
            "uppercase-failed-gate",
            "missing-gate",
            "extra-gate",
            "non-passed-gate",
            "wrong-base",
            "stale-head",
        )
        for variant in variants:
            with self.subTest(variant=variant):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    manifest = lane_state.empty_manifest()
                    allocate_issue(manifest, root, 317)
                    lane_state.record_pr(manifest, "317", 42, PR_URL)
                    observation = base_observation(root, "independent_review")
                    evidence_path = artifact_path(observation["artifact"])
                    artifact = json.loads(
                        evidence_path.read_text(encoding="utf-8")
                    )
                    raw_path = Path(
                        unquote(urlparse(artifact["rawEvidenceUri"]).path)
                    )
                    raw = json.loads(raw_path.read_text(encoding="utf-8"))
                    if variant == "findings":
                        raw["findings"] = [
                            {
                                "file_line": "src/change.ts:1",
                                "mechanism": "unsafe behavior",
                                "failure_scenario": "review blocker",
                                "severity": "important",
                            }
                        ]
                    elif variant == "blockers":
                        raw["blockers"] = ["missing exact-head gate"]
                    elif variant == "empty-coverage":
                        raw["coverage"] = []
                    elif variant == "empty-gate-states":
                        raw["gate_states"] = {}
                    elif variant == "uppercase-failed-gate":
                        raw["gate_states"] = {"CI": "failed"}
                    elif variant == "missing-gate":
                        raw["gate_states"].pop("charter_review")
                    elif variant == "extra-gate":
                        raw["gate_states"]["focused"] = "passed"
                    elif variant == "non-passed-gate":
                        raw["gate_states"]["ci"] = "failed"
                    elif variant == "wrong-base":
                        raw["base_sha"] = SHA_C
                    else:
                        raw["head_sha"] = SHA_C
                    rewrite_review_raw(observation, raw)

                    with self.assertRaises(ValueError):
                        lane_state.validate_base_evidence(
                            manifest,
                            "317",
                            "independent_review",
                            observation,
                        )

    def test_review_raw_evidence_rejects_bytes_changed_after_hash(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for gate_name in ("coderabbit", "independent_review"):
                with self.subTest(gate=gate_name):
                    manifest = lane_state.empty_manifest()
                    allocate_issue(manifest, root, 317)
                    lane_state.record_pr(manifest, "317", 42, PR_URL)
                    observation = base_observation(root, gate_name)
                    evidence_path = artifact_path(observation["artifact"])
                    artifact = json.loads(
                        evidence_path.read_text(encoding="utf-8")
                    )
                    raw_path = Path(
                        unquote(urlparse(artifact["rawEvidenceUri"]).path)
                    )
                    raw_path.write_bytes(raw_path.read_bytes() + b"\n")

                    with self.assertRaises(ValueError):
                        lane_state.validate_base_evidence(
                            manifest,
                            "317",
                            gate_name,
                            observation,
                        )

    def test_failed_review_observation_keeps_nonclean_raw_verdict(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = lane_state.empty_manifest()
            allocate_issue(manifest, root, 317)
            lane_state.record_pr(manifest, "317", 42, PR_URL)
            observation = base_observation(root, "coderabbit")
            evidence_path = artifact_path(observation["artifact"])
            artifact = json.loads(evidence_path.read_text(encoding="utf-8"))
            raw_path = Path(
                unquote(urlparse(artifact["rawEvidenceUri"]).path)
            )
            raw = json.loads(raw_path.read_text(encoding="utf-8"))
            raw["summary"]["approved_at_head"] = False
            rewrite_review_raw(observation, raw)
            evidence_path = artifact_path(observation["artifact"])
            artifact = json.loads(evidence_path.read_text(encoding="utf-8"))
            artifact["gateExitCode"] = 1
            evidence_path.write_text(json.dumps(artifact), encoding="utf-8")
            observation["artifact"] = artifact_ref(evidence_path)
            observation["state"] = "failed"
            observation["exitCode"] = 1

            record_test_observation(
                manifest,
                "317",
                "coderabbit",
                observation,
            )

            self.assertEqual(
                "failed",
                manifest["lanes"]["317"]["gates"]["coderabbit"]["state"],
            )

    def test_pr_change_stales_reviews_and_mergeability(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = lane_state.empty_manifest()
            allocate_issue(manifest, root, 317)
            lane_state.record_pr(manifest, "317", 42, PR_URL)
            lane_state.record_remote(manifest, "317", SHA_A)
            for gate_name in (
                "coderabbit",
                "independent_review",
                "mergeability",
            ):
                record_test_observation(manifest, "317", gate_name, base_observation(root, gate_name))

            lane_state.record_pr(manifest, "317", 43, PR_43_URL)

            lane = manifest["lanes"]["317"]
            for gate_name in (
                "coderabbit",
                "independent_review",
                "mergeability",
            ):
                self.assertEqual("stale", lane["gates"][gate_name]["state"])
            self.assertEqual("stale", lane["mergeabilityState"])

    def test_remote_change_stales_reviews_and_mergeability(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = lane_state.empty_manifest()
            allocate_issue(manifest, root, 317)
            lane_state.record_pr(manifest, "317", 42, PR_URL)
            lane_state.record_remote(manifest, "317", SHA_A)
            for gate_name in (
                "coderabbit",
                "independent_review",
                "mergeability",
            ):
                record_test_observation(manifest, "317", gate_name, base_observation(root, gate_name))

            lane_state.record_remote(manifest, "317", SHA_C)

            lane = manifest["lanes"]["317"]
            for gate_name in (
                "coderabbit",
                "independent_review",
                "mergeability",
            ):
                self.assertEqual("stale", lane["gates"][gate_name]["state"])
            self.assertEqual("stale", lane["mergeabilityState"])

    def test_review_success_requires_current_pr_and_remote_head(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = lane_state.empty_manifest()
            allocate_issue(manifest, root, 317)
            observation = base_observation(root, "coderabbit")

            with self.assertRaises(ValueError):
                record_test_observation(manifest, "317", "coderabbit", observation)
            lane_state.record_pr(manifest, "317", 42, PR_URL)
            with self.assertRaises(ValueError):
                record_test_observation(manifest, "317", "coderabbit", observation)
            lane_state.record_remote(manifest, "317", SHA_A)
            record_test_observation(manifest, "317", "coderabbit", observation)

            manifest["lanes"]["317"]["remoteSha"] = SHA_C
            with self.assertRaises(ValueError):
                lane_state.validate_manifest(manifest)

    def test_pr_url_is_exact_repository_identity(self) -> None:
        invalid_urls = (
            "https://github.com/example/repo/pull/42",
            PR_43_URL,
            "https://github.com/adamgell/cmtraceopen/pull/42/",
            "https://github.com/adamgell/cmtraceopen/pull/42?diff=split",
        )
        with tempfile.TemporaryDirectory() as directory:
            for url in invalid_urls:
                with self.subTest(url=url):
                    manifest = lane_state.empty_manifest()
                    allocate_issue(manifest, Path(directory), 317)
                    original = deepcopy(manifest)
                    with self.assertRaises(ValueError):
                        lane_state.record_pr(manifest, "317", 42, url)
                    self.assertEqual(original, manifest)

    def test_base_artifact_with_relabelled_current_base_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = lane_state.empty_manifest()
            allocate_issue(manifest, root, 317)
            manifest["lanes"]["317"]["currentBaseSha"] = SHA_C
            observation = base_observation(root, "aggregate")
            observation["baseSha"] = SHA_C

            with self.assertRaises(ValueError):
                lane_state.validate_base_evidence(
                    manifest,
                    "317",
                    "aggregate",
                    observation,
                )


class SemaphoreTests(unittest.TestCase):
    def test_only_one_lane_holds_aggregate_gate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = lane_state.empty_manifest()
            allocate_issue(manifest, root, 317)
            allocate_issue(manifest, root, 318)

            lane_state.acquire_aggregate_gate(manifest, "317", NOW)
            with self.assertRaises(lane_state.RetriableConflict):
                lane_state.acquire_aggregate_gate(manifest, "318", LATER)

            self.assertEqual("317", manifest["aggregateGate"]["holder"])
            self.assertEqual(["318"], manifest["aggregateGate"]["queue"])

    def test_release_leaves_gate_free_and_preserves_fifo_queue(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = lane_state.empty_manifest()
            for issue in (317, 318, 319):
                allocate_issue(manifest, root, issue)
            manifest["aggregateGate"] = {
                "holder": "317",
                "queue": ["318", "319"],
                "acquiredAt": NOW,
            }

            lane_state.release_aggregate_gate(manifest, "317")

            self.assertEqual(
                {"holder": None, "queue": ["318", "319"], "acquiredAt": None},
                manifest["aggregateGate"],
            )

    def test_first_queued_lane_acquires_with_new_timestamp(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = lane_state.empty_manifest()
            for issue in (317, 318, 319):
                allocate_issue(manifest, root, issue)
            manifest["aggregateGate"] = {
                "holder": "317",
                "queue": ["318", "319"],
                "acquiredAt": NOW,
            }
            lane_state.release_aggregate_gate(manifest, "317")

            lane_state.acquire_aggregate_gate(manifest, "318", LATER)

            self.assertEqual("318", manifest["aggregateGate"]["holder"])
            self.assertEqual(["319"], manifest["aggregateGate"]["queue"])
            self.assertEqual(LATER, manifest["aggregateGate"]["acquiredAt"])

    def test_non_holder_cannot_release(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = lane_state.empty_manifest()
            allocate_issue(manifest, root, 317)
            allocate_issue(manifest, root, 318)
            lane_state.acquire_aggregate_gate(manifest, "317", NOW)
            original = deepcopy(manifest)

            with self.assertRaises(lane_state.TerminalRejection):
                lane_state.release_aggregate_gate(manifest, "318")

            self.assertEqual(original, manifest)


class MutationRetryTests(unittest.TestCase):
    def test_manifest_publication_rejects_state_directory_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = lane_state.empty_manifest()
            allocate_issue(manifest, root, 317)
            path = write_manifest(root, manifest)
            detached = root / "detached-state"
            original_write = lane_state._atomic_json_write_at

            def swap_after_write(
                directory_fd: int,
                name: str,
                data: dict[str, object],
            ) -> None:
                original_write(directory_fd, name, data)
                path.parent.rename(detached)
                path.parent.mkdir(mode=0o700)
                (path.parent / "unrelated").write_text(
                    "preserve",
                    encoding="utf-8",
                )

            with mock.patch.object(
                lane_state,
                "_atomic_json_write_at",
                side_effect=swap_after_write,
            ), self.assertRaises(lane_state.TerminalRejection):
                lane_state.mutate_manifest(
                    path,
                    manifest["updatedAt"],
                    lambda data: lane_state.record_status(
                        data,
                        "317",
                        {"nextAction": "changed"},
                    ),
                )

            self.assertEqual(
                "preserve",
                (path.parent / "unrelated").read_text(encoding="utf-8"),
            )
            self.assertFalse(path.exists())
            self.assertTrue((detached / path.name).is_file())

    def test_atomic_write_rejects_state_directory_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state_dir = root / "state"
            state_dir.mkdir(mode=0o700)
            state_dir.chmod(0o700)
            path = state_dir / "lanes.json"
            path.write_text(
                json.dumps(lane_state.empty_manifest()),
                encoding="utf-8",
            )
            detached = root / "detached-state"
            original_write = lane_state._atomic_json_write_at

            def swap_after_write(
                directory_fd: int,
                name: str,
                data: dict[str, object],
            ) -> None:
                original_write(directory_fd, name, data)
                state_dir.rename(detached)
                state_dir.mkdir(mode=0o700)
                state_dir.chmod(0o700)
                (state_dir / "unrelated").write_text(
                    "preserve",
                    encoding="utf-8",
                )

            with mock.patch.object(
                lane_state,
                "_atomic_json_write_at",
                side_effect=swap_after_write,
            ), self.assertRaisesRegex(ValueError, "pinned directory"):
                lane_state.atomic_write(path, lane_state.empty_manifest())

            self.assertEqual(
                "preserve",
                (state_dir / "unrelated").read_text(encoding="utf-8"),
            )
            self.assertFalse(path.exists())
            self.assertTrue((detached / path.name).is_file())

    def test_lock_contention_is_retriable_and_does_not_mutate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = lane_state.empty_manifest()
            allocate_issue(manifest, root, 317)
            path = write_manifest(root, manifest)
            original = path.read_bytes()
            called = False

            def mutation(data: dict[str, object]) -> None:
                nonlocal called
                called = True
                transition_test_lane(data, "317", "running")

            with (
                mock.patch.object(lane_state, "LOCK_TIMEOUT_SECONDS", 0.0),
                mock.patch.object(
                    lane_state.fcntl,
                    "flock",
                    side_effect=BlockingIOError,
                ),
                self.assertRaises(lane_state.RetriableConflict),
            ):
                lane_state.mutate_manifest(path, manifest["updatedAt"], mutation)

            self.assertFalse(called)
            self.assertEqual(original, path.read_bytes())

    def test_stale_updated_at_is_retriable_and_does_not_mutate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = lane_state.empty_manifest()
            allocate_issue(manifest, root, 317)
            transition_test_lane(manifest, "317", "blocked")
            path = write_manifest(root, manifest)
            expected = manifest["updatedAt"]

            first = lane_state.mutate_manifest(
                path,
                expected,
                lambda data: lane_state.transfer_owner(
                    data,
                    "317",
                    "Replacement",
                    "coder",
                ),
            )
            first_bytes = path.read_bytes()
            with self.assertRaises(lane_state.RetriableConflict):
                lane_state.mutate_manifest(
                    path,
                    expected,
                    lambda data: lane_state.transfer_owner(
                        data,
                        "317",
                        "SecondReplacement",
                        "coder",
                    ),
                )

            self.assertNotEqual(expected, first["updatedAt"])
            self.assertEqual(first_bytes, path.read_bytes())
            self.assertEqual(
                "Replacement",
                lane_state.load_manifest(path)["lanes"]["317"]["agentId"],
            )

    def test_gate_contention_preserves_fifo_before_retriable_result(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = lane_state.empty_manifest()
            allocate_issue(manifest, root, 317)
            allocate_issue(manifest, root, 318)
            lane_state.acquire_aggregate_gate(manifest, "317", NOW)
            path = write_manifest(root, manifest)

            with self.assertRaises(lane_state.RetriableConflict):
                lane_state.mutate_manifest(
                    path,
                    manifest["updatedAt"],
                    lambda data: lane_state.acquire_aggregate_gate(
                        data,
                        "318",
                        LATER,
                    ),
                )

            persisted = lane_state.load_manifest(path)
            self.assertEqual("317", persisted["aggregateGate"]["holder"])
            self.assertEqual(["318"], persisted["aggregateGate"]["queue"])
            self.assertNotEqual(manifest["updatedAt"], persisted["updatedAt"])

    def test_reload_revalidates_base_artifacts_before_mutation(self) -> None:
        variants = (
            ("deleted", "aggregate"),
            ("changed", "aggregate"),
            ("relabelled", "aggregate"),
            ("nonzero", "aggregate"),
            ("wrong-head", "aggregate"),
            ("wrong-base", "aggregate"),
            ("deleted-native", "native_lab"),
        )
        for variant, gate_name in variants:
            with self.subTest(variant=variant):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    manifest = lane_state.empty_manifest()
                    allocate_issue(manifest, root, 317)
                    if gate_name == "native_lab":
                        manifest["lanes"]["317"]["nativeLabRequirement"][
                            "state"
                        ] = "required"
                        manifest["lanes"]["317"]["gates"]["native_lab"] = gate()
                    observation = base_observation(root, gate_name)
                    record_test_observation(manifest, "317", gate_name, observation)
                    path = write_manifest(root, manifest)
                    original = path.read_bytes()
                    evidence_path = artifact_path(observation["artifact"])
                    if variant in {"deleted", "deleted-native"}:
                        evidence_path.unlink()
                    else:
                        artifact = json.loads(
                            evidence_path.read_text(encoding="utf-8")
                        )
                        if variant == "changed":
                            artifact["unexpected"] = True
                        elif variant == "relabelled":
                            artifact["kind"] = "github_review"
                        elif variant == "nonzero":
                            artifact["gateExitCode"] = 1
                        elif variant == "wrong-head":
                            artifact["headSha"] = SHA_C
                        elif variant == "wrong-base":
                            artifact["currentBaseSha"] = SHA_C
                        evidence_path.write_text(
                            json.dumps(artifact),
                            encoding="utf-8",
                        )
                    called = False

                    def mutation(data: dict[str, object]) -> None:
                        nonlocal called
                        called = True
                        transition_test_lane(data, "317", "running")

                    with self.assertRaises(lane_state.TerminalRejection):
                        lane_state.mutate_manifest(
                            path,
                            manifest["updatedAt"],
                            mutation,
                        )

                    self.assertFalse(called)
                    self.assertEqual(original, path.read_bytes())

    def test_owner_conflict_is_terminal_and_not_retried(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = lane_state.empty_manifest()
            allocate_issue(manifest, root, 317)
            path = write_manifest(root, manifest)
            original = path.read_bytes()

            with self.assertRaises(lane_state.TerminalRejection):
                lane_state.mutate_manifest(
                    path,
                    manifest["updatedAt"],
                    lambda data: lane_state.heartbeat_lane(
                        data,
                        "317",
                        "Other",
                        LATER,
                        LATER,
                    ),
                )

            self.assertEqual(original, path.read_bytes())

    def test_invariant_violation_is_terminal_and_not_retried(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = lane_state.empty_manifest()
            allocate_issue(manifest, root, 317)
            path = write_manifest(root, manifest)
            original = path.read_bytes()

            with self.assertRaises(lane_state.TerminalRejection):
                lane_state.mutate_manifest(
                    path,
                    manifest["updatedAt"],
                    lambda data: transition_test_lane(data, "317", "ready_for_adam"),
                )

            self.assertEqual(original, path.read_bytes())
            with self.assertRaises(lane_state.TerminalRejection):
                lane_state.mutate_manifest(
                    path,
                    "not-a-timestamp",
                    lambda data: transition_test_lane(data, "317", "running"),
                )
            self.assertEqual(original, path.read_bytes())


class CliTests(unittest.TestCase):
    def test_init_prints_manifest_and_created_without_rewriting_existing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            common = Path(directory) / "common"
            common.mkdir()
            path = common / "omp" / "lanes.json"
            output = io.StringIO()

            with mock.patch("sys.stdout", output):
                self.assertEqual(
                    0,
                    lane_state.main(["init", "--git-common-dir", str(common)]),
                )
            created_output = json.loads(output.getvalue())
            self.assertTrue(created_output.pop("created"))
            lane_state.validate_manifest(created_output)
            original = path.read_bytes()

            output = io.StringIO()
            with mock.patch("sys.stdout", output):
                self.assertEqual(
                    0,
                    lane_state.main(["init", "--git-common-dir", str(common)]),
                )
            existing_output = json.loads(output.getvalue())

            self.assertFalse(existing_output.pop("created"))
            self.assertEqual(created_output, existing_output)
            self.assertEqual(original, path.read_bytes())

    def test_mutation_cli_reports_success_and_new_updated_at(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = lane_state.empty_manifest()
            allocate_issue(manifest, root, 317)
            path = write_manifest(root, manifest)
            output = io.StringIO()

            with (
                mock.patch("sys.stdout", output),
                mock.patch.object(
                    lane_state,
                    "require_lane_worktree_current",
                    side_effect=lambda lane, **kwargs: observed_lane(
                        lane,
                        expected_head=kwargs.get("expected_head"),
                    ),
                ),
            ):
                exit_code = lane_state.main(
                    [
                        "update-heads",
                        "--manifest",
                        str(path),
                        "--issue",
                        "317",
                        "--head",
                        SHA_C,
                        "--current-base",
                        SHA_B,
                        "--expected-updated-at",
                        manifest["updatedAt"],
                    ]
                )

            result = json.loads(output.getvalue())
            self.assertEqual(0, exit_code)
            self.assertTrue(result["ok"])
            self.assertNotEqual(manifest["updatedAt"], result["updatedAt"])
            self.assertEqual(
                SHA_C,
                lane_state.load_manifest(path)["lanes"]["317"]["headSha"],
            )

    def test_mutation_cli_classifies_retriable_and_terminal_results(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = lane_state.empty_manifest()
            allocate_issue(manifest, root, 317)
            path = write_manifest(root, manifest)

            retriable_output = io.StringIO()
            with mock.patch("sys.stdout", retriable_output):
                retriable_exit = lane_state.main(
                    [
                        "update-heads",
                        "--manifest",
                        str(path),
                        "--issue",
                        "317",
                        "--head",
                        SHA_C,
                        "--current-base",
                        SHA_B,
                        "--expected-updated-at",
                        "2020-01-01T00:00:00+00:00",
                    ]
                )
            retriable = json.loads(retriable_output.getvalue())
            self.assertEqual(75, retriable_exit)
            self.assertEqual("retriable_conflict", retriable["classification"])

            terminal_output = io.StringIO()
            with mock.patch("sys.stdout", terminal_output):
                terminal_exit = lane_state.main(
                    [
                        "transfer-owner",
                        "--manifest",
                        str(path),
                        "--issue",
                        "317",
                        "--owner",
                        "Replacement",
                        "--role",
                        "coder",
                        "--expected-updated-at",
                        manifest["updatedAt"],
                    ]
                )
            terminal = json.loads(terminal_output.getvalue())
            self.assertEqual(2, terminal_exit)
            self.assertEqual("terminal_rejection", terminal["classification"])

    def test_every_manifest_mutation_dispatch_executes_real_callback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lane_json = root / "lane.json"
            lane_worktree = root / "lane-317"
            lane_worktree.mkdir()
            lane_json_worktree = root / "lane-318"
            lane_json_worktree.mkdir()
            lane_json_payload = valid_lane(lane_json_worktree, issue=318)
            lane_json_payload["agentId"] = lane_json_payload["lease"]["owner"] = (
                "Task-318"
            )
            lane_json.write_text(
                json.dumps(lane_json_payload),
                encoding="utf-8",
            )
            observation_json = root / "observation.json"
            observation_json.write_text(
                json.dumps(
                    valid_observation(
                        root,
                        state="failed",
                        lane=valid_lane(lane_worktree),
                    )
                ),
            )
            status_json = root / "status.json"
            status_json.write_text(
                json.dumps({"nextAction": "continue"}),
                encoding="utf-8",
            )
            snapshot_artifact = root / "snapshot.json"
            snapshot_bytes = json.dumps(
                root_snapshot_fixture(),
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            snapshot_artifact.write_bytes(snapshot_bytes)

            def prepared_manifest(command: str) -> dict[str, object]:
                manifest = lane_state.empty_manifest()
                allocate_issue(manifest, root, 317)
                lane = manifest["lanes"]["317"]
                if command == "transfer-owner":
                    lane["laneState"] = "blocked"
                elif command == "invalidate-dependents":
                    allocate_issue(
                        manifest,
                        root,
                        318,
                        depends_on=[317],
                        shared_contract_paths=["contracts/**"],
                    )
                elif command == "release-gate":
                    manifest["aggregateGate"] = {
                        "holder": "317",
                        "queue": [],
                        "acquiredAt": NOW,
                    }
                lane_state.validate_manifest(manifest)
                return manifest

            cases = (
                (
                    "allocate",
                    ["--lane-json", str(lane_json)],
                    ("lanes", "318", "issue"),
                    318,
                    set(),
                ),
                (
                    "transition",
                    ["--issue", "317", "--state", "running"],
                    ("lanes", "317", "laneState"),
                    "running",
                    set(),
                ),
                (
                    "transfer-owner",
                    [
                        "--issue",
                        "317",
                        "--owner",
                        "Replacement",
                        "--role",
                        "coder",
                    ],
                    ("lanes", "317", "lease", "owner"),
                    "Replacement",
                    set(),
                ),
                (
                    "invalidate-dependents",
                    [
                        "--upstream",
                        "317",
                        "--changed-path",
                        "contracts/api.py",
                    ],
                    ("lanes", "318", "nextAction"),
                    "revalidate shared contract after issue 317",
                    {"invalidated"},
                ),
                (
                    "heartbeat",
                    [
                        "--issue",
                        "317",
                        "--owner",
                        "Task-317",
                        "--at",
                        LATER,
                        "--expires-at",
                        "2026-08-14T12:10:00+00:00",
                    ],
                    ("lanes", "317", "lease", "lastVerifiedAt"),
                    LATER,
                    set(),
                ),
                (
                    "update-heads",
                    [
                        "--issue",
                        "317",
                        "--head",
                        SHA_C,
                        "--current-base",
                        SHA_B,
                    ],
                    ("lanes", "317", "headSha"),
                    SHA_C,
                    set(),
                ),
                (
                    "record-red",
                    [
                        "--issue",
                        "317",
                        "--observation-json",
                        str(observation_json),
                    ],
                    ("lanes", "317", "redEvidence", 0, "state"),
                    "failed",
                    set(),
                ),
                (
                    "record-observation",
                    [
                        "--issue",
                        "317",
                        "--gate",
                        "focused",
                        "--observation-json",
                        str(observation_json),
                    ],
                    ("lanes", "317", "gates", "focused", "state"),
                    "failed",
                    set(),
                ),
                (
                    "record-status",
                    [
                        "--issue",
                        "317",
                        "--status-json",
                        str(status_json),
                    ],
                    ("lanes", "317", "nextAction"),
                    "continue",
                    set(),
                ),
                (
                    "record-pr",
                    [
                        "--issue",
                        "317",
                        "--number",
                        "42",
                        "--url",
                        PR_URL,
                    ],
                    ("lanes", "317", "pr", "number"),
                    42,
                    set(),
                ),
                (
                    "record-remote",
                    ["--issue", "317", "--sha", SHA_C],
                    ("lanes", "317", "remoteSha"),
                    SHA_C,
                    set(),
                ),
                (
                    "record-root-snapshot",
                    [
                        "--slot",
                        "stage1Before",
                        "--artifact",
                        snapshot_artifact.resolve().as_uri(),
                    ],
                    ("rootSafety", "stage1Before", "sha256"),
                    hashlib.sha256(snapshot_bytes).hexdigest(),
                    set(),
                ),
                (
                    "acquire-gate",
                    ["--issue", "317", "--at", LATER],
                    ("aggregateGate", "holder"),
                    "317",
                    {"aggregateGate"},
                ),
                (
                    "release-gate",
                    ["--issue", "317"],
                    ("aggregateGate", "holder"),
                    None,
                    {"aggregateGate"},
                ),
            )

            for command, options, expected_path, expected, extra_fields in cases:
                with self.subTest(command=command):
                    manifest = prepared_manifest(command)
                    path = root / f"{command}.json"
                    lane_state.atomic_write(path, manifest)
                    output = io.StringIO()
                    with (
                        mock.patch("sys.stdout", output),
                        mock.patch.object(
                            lane_state,
                            "observe_lane_worktree",
                            return_value=observed_lane(lane_json_payload),
                        ),
                        mock.patch.object(
                            lane_state,
                            "require_lane_worktree_current",
                            side_effect=lambda lane, **kwargs: observed_lane(
                                lane,
                                expected_head=kwargs.get("expected_head"),
                            ),
                        ),
                    ):
                        exit_code = lane_state.main(
                            [
                                command,
                                "--manifest",
                                str(path),
                                "--expected-updated-at",
                                manifest["updatedAt"],
                                *options,
                            ]
                        )

                    self.assertEqual(0, exit_code)
                    updated = lane_state.load_manifest(path)
                    lane_state.validate_manifest(updated)
                    actual: object = updated
                    for component in expected_path:
                        actual = actual[component]
                    self.assertEqual(expected, actual)
                    result = json.loads(output.getvalue())
                    self.assertEqual(
                        {"ok", "updatedAt"} | extra_fields,
                        set(result),
                    )
                    self.assertTrue(result["ok"])
                    self.assertEqual(updated["updatedAt"], result["updatedAt"])
                    if command == "invalidate-dependents":
                        self.assertEqual(["318"], result["invalidated"])

    def test_record_commands_reject_stale_heads_and_wrong_owner(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = lane_state.empty_manifest()
            allocate_issue(manifest, root, 317)
            path = write_manifest(root, manifest)
            original = path.read_bytes()
            stale_red_json = root / "stale-red.json"
            stale_red_json.write_text(
                json.dumps(
                    valid_observation(
                        root,
                        state="failed",
                        head_sha=SHA_C,
                        name="stale-red-artifact",
                    )
                ),
                encoding="utf-8",
            )
            stale_gate_json = root / "stale-gate.json"
            stale_gate_json.write_text(
                json.dumps(
                    valid_observation(
                        root,
                        base_sha=SHA_C,
                        name="stale-gate-artifact",
                    )
                ),
                encoding="utf-8",
            )
            common = [
                "--manifest",
                str(path),
                "--expected-updated-at",
                manifest["updatedAt"],
                "--issue",
                "317",
            ]
            commands = (
                [
                    "record-red",
                    *common,
                    "--observation-json",
                    str(stale_red_json),
                ],
                [
                    "record-observation",
                    *common,
                    "--gate",
                    "focused",
                    "--observation-json",
                    str(stale_gate_json),
                ],
                [
                    "heartbeat",
                    *common,
                    "--owner",
                    "Other",
                    "--at",
                    LATER,

                    "--expires-at",
                    "2026-08-14T12:10:00+00:00",
                ],
            )
            for command in commands:
                with self.subTest(command=command[0]):
                    output = io.StringIO()
                    with mock.patch("sys.stdout", output):
                        self.assertEqual(2, lane_state.main(command))
                    self.assertEqual(
                        "terminal_rejection",
                        json.loads(output.getvalue())["classification"],
                    )
                    self.assertEqual(original, path.read_bytes())
    def test_check_paths_is_bound_to_validated_manifest_lane(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo, head = create_git_repo(root)
            run_git(repo, "checkout", "--quiet", "-b", "omp/issue-317")
            manifest = lane_state.empty_manifest()
            lane = valid_lane(repo)
            lane["headSha"] = head
            lane["allocationBaseSha"] = head
            lane["currentBaseSha"] = head
            lane["allowedPaths"] = ["owned.txt"]
            lane_state.allocate_lane(manifest, lane)
            path = write_manifest(root, manifest)
            (repo / "owned.txt").write_text("changed\n", encoding="utf-8")
            output = io.StringIO()

            with mock.patch("sys.stdout", output):
                self.assertEqual(
                    0,
                    lane_state.main(
                        [
                            "check-paths",
                            "--manifest",
                            str(path),
                            "--issue",
                            "317",
                        ]
                    ),
                )
            self.assertEqual(
                {"ok": True, "paths": ["owned.txt"], "disallowed": []},
                json.loads(output.getvalue()),
            )

            outside = root / "outside.txt"
            outside.write_text("outside\n", encoding="utf-8")
            (repo / "owned.txt").unlink()
            (repo / "owned.txt").symlink_to(outside)
            escape_output = io.StringIO()
            with mock.patch("sys.stdout", escape_output):
                self.assertEqual(
                    2,
                    lane_state.main(
                        [
                            "check-paths",
                            "--manifest",
                            str(path),
                            "--issue",
                            "317",
                        ]
                    ),
                )
            self.assertIn(
                "owned.txt",
                json.loads(escape_output.getvalue())["reason"],
            )

            legacy_output = io.StringIO()
            with (
                mock.patch("sys.stdout", legacy_output),
                mock.patch("sys.stderr", io.StringIO()),
            ):
                self.assertEqual(
                    2,
                    lane_state.main(
                        [
                            "check-paths",
                            "--repo",
                            str(root / "attacker"),
                            "--allocation-base",
                            SHA_A,
                            "--allow",
                            "**",
                        ]
                    ),
                )
            self.assertEqual(
                "terminal_rejection",
                json.loads(legacy_output.getvalue())["classification"],
            )

    def test_check_paths_allows_only_exact_allowlisted_delete(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo, _ = create_git_repo(root)
            deleted = repo / "deleted.txt"
            deleted.write_text("delete me\n", encoding="utf-8")
            run_git(repo, "add", "deleted.txt")
            run_git(repo, "commit", "--quiet", "-m", "add deleted fixture")
            head = run_git(repo, "rev-parse", "HEAD")
            run_git(repo, "checkout", "--quiet", "-b", "omp/issue-317")
            deleted.unlink()

            manifest = lane_state.empty_manifest()
            lane = valid_lane(repo)
            lane["headSha"] = head
            lane["allocationBaseSha"] = head
            lane["currentBaseSha"] = head
            lane["allowedPaths"] = ["deleted.txt"]
            lane_state.allocate_lane(manifest, lane)
            path = write_manifest(root, manifest)

            without_approval = io.StringIO()
            with mock.patch("sys.stdout", without_approval):
                self.assertEqual(
                    2,
                    lane_state.main(
                        [
                            "check-paths",
                            "--manifest",
                            str(path),
                            "--issue",
                            "317",
                        ]
                    ),
                )
            self.assertIn(
                "deleted.txt",
                json.loads(without_approval.getvalue())["reason"],
            )

            approved = io.StringIO()
            with mock.patch("sys.stdout", approved):
                self.assertEqual(
                    0,
                    lane_state.main(
                        [
                            "check-paths",
                            "--manifest",
                            str(path),
                            "--issue",
                            "317",
                            "--approved-delete-path",
                            "deleted.txt",
                        ]
                    ),
                )
            self.assertEqual(
                {
                    "ok": True,
                    "paths": ["deleted.txt"],
                    "disallowed": [],
                    "approvedDeletePath": "deleted.txt",
                },
                json.loads(approved.getvalue()),
            )

            manifest["lanes"]["317"]["allowedPaths"] = ["other.txt"]
            lane_state.atomic_write(path, manifest)
            outside_allowlist = io.StringIO()
            with mock.patch("sys.stdout", outside_allowlist):
                self.assertEqual(
                    2,
                    lane_state.main(
                        [
                            "check-paths",
                            "--manifest",
                            str(path),
                            "--issue",
                            "317",
                            "--approved-delete-path",
                            "deleted.txt",
                        ]
                    ),
                )
            self.assertIn(
                "deleted.txt",
                json.loads(outside_allowlist.getvalue())["reason"],
            )

    def test_feature_owner_commands_cover_the_complete_lifecycle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            common = Path(directory) / "common"
            common.mkdir()
            record_command = [
                "record-feature-owner",
                "--git-common-dir",
                str(common),
                "--owner",
                "OmpOverlayOwner",
                "--role",
                "coder",
                "--worktree",
                str(Path(directory).resolve()),
                "--assigned-at",
                NOW,
            ]
            for allowed in STAGE1_ALLOWED_PATHS:
                record_command.extend(["--allow", allowed])
            commands = (
                record_command,
                [
                    "feature-owner-state",
                    "--git-common-dir",
                    str(common),
                    "--state",
                    "blocked",
                ],
                [
                    "transfer-feature-owner",
                    "--git-common-dir",
                    str(common),
                    "--owner",
                    "Replacement",
                    "--role",
                    "coder",
                    "--assigned-at",
                    LATER,
                ],
                [
                    "feature-owner-state",
                    "--git-common-dir",
                    str(common),
                    "--state",
                    "released",
                ],
            )
            for command in commands:
                output = io.StringIO()
                with mock.patch("sys.stdout", output):
                    self.assertEqual(0, lane_state.main(command))
                self.assertTrue(json.loads(output.getvalue())["ok"])

            owner_path = common / "omp" / "stage1-owner.json"
            owner = json.loads(owner_path.read_text(encoding="utf-8"))
            self.assertEqual("Replacement", owner["owner"])
            self.assertEqual("released", owner["state"])


    def test_cli_parse_rejections_are_classified_json(self) -> None:
        output = io.StringIO()
        with (
            mock.patch("sys.stdout", output),
            mock.patch("sys.stderr", io.StringIO()),
        ):
            self.assertEqual(
                2,
                lane_state.main(
                    [
                        "transition",
                        "--manifest",
                        "/tmp/lanes.json",
                        "--issue",
                        "317",
                        "--state",
                        "running",
                    ]
                ),
            )
        self.assertEqual(
            "terminal_rejection",
            json.loads(output.getvalue())["classification"],
        )

if __name__ == "__main__":
    unittest.main()
