from __future__ import annotations

from copy import deepcopy
import importlib.util
import io
import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock


SCRIPT_PATH = Path(__file__).parents[1] / "scripts" / "lane_state.py"
SPEC = importlib.util.spec_from_file_location("lane_state", SCRIPT_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load lane state helpers from {SCRIPT_PATH}")
lane_state = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lane_state)

SHA_A = "a" * 40
SHA_B = "b" * 40
SHA_C = "c" * 40
NOW = "2026-08-14T12:00:00+00:00"
LATER = "2026-08-14T12:05:00+00:00"
ALLOWED_PATHS = ["crates/cmtraceopen-parser/**"]
STAGE1_ALLOWED_PATHS = [
    ".omp/**",
    ".Clairvoyance/library.md",
    ".Clairvoyance/kickoff-prompt.md",
    "docs/superpowers/specs/2026-08-14-omp-agent-driven-development-design.md",
    "docs/superpowers/plans/2026-08-14-omp-agent-driven-development.md",
]


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


def valid_observation(
    *,
    state: str = "passed",
    head_sha: str = SHA_A,
    base_sha: str = SHA_B,
    base_sensitive: bool = False,
) -> dict[str, object]:
    return {
        "state": state,
        "headSha": head_sha,
        "baseSha": base_sha,
        "command": "python3.14 test_lane_state.py -v",
        "scenario": None,
        "exitCode": 0,
        "observedAt": NOW,
        "artifact": ".superpowers/evidence/task-4.txt",
        "baseSensitive": base_sensitive,
    }

def write_base_artifact(
    root: Path,
    *,
    kind: str = "synthetic_merge",
    head_sha: str = SHA_A,
    current_base_sha: str = SHA_B,
    name: str = "base-evidence",
) -> str:
    path = root / f"{name}.json"
    path.write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "kind": kind,
                "headSha": head_sha,
                "currentBaseSha": current_base_sha,
                "integrationCommand": "git merge-tree base head",
                "integrationExitCode": 0,
                "gateCommand": "python3.14 focused-test.py -v",
                "gateExitCode": 0,
                "rawEvidenceUri": "file:///tmp/raw-evidence.txt",
                "observedAt": NOW,
            }
        ),
        encoding="utf-8",
    )
    return path.resolve().as_uri()


def base_observation(
    root: Path,
    gate_name: str,
    *,
    head_sha: str = SHA_A,
    base_sha: str = SHA_B,
    base_sensitive: bool = True,
) -> dict[str, object]:
    kind = (
        "github_review"
        if gate_name in {"coderabbit", "independent_review"}
        else "synthetic_merge"
    )
    observation = valid_observation(
        state="mergeable" if gate_name == "mergeability" else "passed",
        head_sha=head_sha,
        base_sha=base_sha,
        base_sensitive=base_sensitive,
    )
    observation["artifact"] = write_base_artifact(
        root,
        kind=kind,
        head_sha=head_sha,
        current_base_sha=base_sha,
        name=f"{gate_name}-{kind}-{head_sha[0]}-{base_sha[0]}",
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
    lane = valid_lane(root, issue=issue)
    lane["dependsOn"] = [] if depends_on is None else depends_on
    lane["sharedContractPaths"] = (
        [] if shared_contract_paths is None else shared_contract_paths
    )
    lane_state.allocate_lane(manifest, lane)


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
    lane_state.record_pr(
        manifest,
        issue,
        42,
        "https://github.com/example/repo/pull/42",
    )
    lane_state.record_observation(
        manifest,
        issue,
        "focused",
        valid_observation(head_sha=head_sha, base_sha=base_sha),
    )
    for gate_name in (
        "aggregate",
        "conformance",
        "coderabbit",
        "independent_review",
        "mergeability",
    ):
        lane_state.record_observation(
            manifest,
            issue,
            gate_name,
            base_observation(
                root,
                gate_name,
                head_sha=head_sha,
                base_sha=base_sha,
            ),
        )
    lane_state.record_observation(
        manifest,
        issue,
        "native_lab",
        (
            base_observation(
                root,
                "native_lab",
                head_sha=head_sha,
                base_sha=base_sha,
            )
            if native_base_sensitive
            else valid_observation(head_sha=head_sha, base_sha=base_sha)
        ),
    )


def write_manifest(root: Path, manifest: dict[str, object]) -> Path:
    common = root / "common"
    common.mkdir()
    path = common / "omp" / "lanes.json"
    lane_state.atomic_write(path, manifest)
    return path
def valid_feature_owner(worktree: Path, *, state: str = "active") -> dict[str, object]:
    return {
        "schemaVersion": 1,
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

        self.assertEqual(1, manifest["schemaVersion"])
        self.assertEqual({}, manifest["lanes"])
        self.assertEqual(
            {"holder": None, "queue": [], "acquiredAt": None},
            manifest["aggregateGate"],
        )
        self.assertEqual(
            {
                "stage1Before": None,
                "stage1After": None,
                "stage2Before": None,
                "stage2After": None,
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

            malformed_sha = deepcopy(valid)
            malformed_sha["headSha"] = "short"
            invalid_lanes.append(("malformed SHA", malformed_sha))

            unequal_bases = deepcopy(valid)
            unequal_bases["currentBaseSha"] = SHA_C
            invalid_lanes.append(("unequal allocation bases", unequal_bases))

            multiple_owners = deepcopy(valid)
            multiple_owners["lease"]["owner"] = "Other"
            invalid_lanes.append(("multiple owners", multiple_owners))

            for label, lane in invalid_lanes:
                with self.subTest(label=label):
                    manifest = lane_state.empty_manifest()
                    original = deepcopy(manifest)
                    with self.assertRaises(ValueError):
                        lane_state.allocate_lane(manifest, lane)
                    self.assertEqual(original, manifest)

    def test_init_creates_absent_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            common = Path(directory) / "common"
            common.mkdir()
            path = common / "omp" / "lanes.json"

            manifest, created = lane_state.initialize_manifest(path)

            self.assertTrue(created)
            self.assertEqual(manifest, lane_state.load_manifest(path))

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
            lane_state.allocate_lane(manifest, valid_lane(Path(directory)))

            lane_state.transition_lane(manifest, "317", "running")

            self.assertEqual("running", manifest["lanes"]["317"]["laneState"])

    def test_owner_transfer_stales_gate_review_and_mergeability_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = lane_state.empty_manifest()
            red_evidence = valid_observation(state="failed")
            lane_state.allocate_lane(manifest, valid_lane(Path(directory)))
            lane_state.record_red(manifest, "317", red_evidence)
            lane_state.record_pr(
                manifest,
                "317",
                42,
                "https://github.com/example/repo/pull/42",
            )
            lane_state.transition_lane(manifest, "317", "blocked")
            for gate_name in (
                "focused",
                "aggregate",
                "conformance",
                "coderabbit",
                "independent_review",
                "mergeability",
            ):
                observation = (
                    valid_observation()
                    if gate_name == "focused"
                    else base_observation(Path(directory), gate_name)
                )
                lane_state.record_observation(
                    manifest,
                    "317",
                    gate_name,
                    observation,
                )
            lane_state.record_observation(
                manifest,
                "317",
                "native_lab",
                base_observation(Path(directory), "native_lab"),
            )
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
            lane_state.allocate_lane(manifest, valid_lane(Path(directory)))
            lane_state.record_observation(
                manifest,
                "317",
                "focused",
                valid_observation(),
            )
            lane_state.record_observation(
                manifest,
                "317",
                "native_lab",
                valid_observation(),
            )
            lane_state.record_observation(
                manifest,
                "317",
                "aggregate",
                base_observation(Path(directory), "aggregate"),
            )

            lane_state.record_status(manifest, "317", {"currentBaseSha": SHA_C})

            lane = manifest["lanes"]["317"]
            self.assertEqual(SHA_B, lane["allocationBaseSha"])
            self.assertEqual(SHA_C, lane["currentBaseSha"])
            self.assertEqual("passed", lane["gates"]["focused"]["state"])
            self.assertEqual("passed", lane["gates"]["native_lab"]["state"])
            self.assertEqual("stale", lane["gates"]["aggregate"]["state"])
            self.assertEqual(SHA_C, lane["gates"]["focused"]["baseSha"])
            self.assertEqual(SHA_C, lane["gates"]["native_lab"]["baseSha"])
            self.assertEqual(SHA_C, lane["gates"]["aggregate"]["baseSha"])
            lane_state.validate_manifest(manifest)

    def test_running_cannot_transition_directly_to_ready_for_adam(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = lane_state.empty_manifest()
            lane_state.allocate_lane(manifest, valid_lane(Path(directory)))
            lane_state.transition_lane(manifest, "317", "running")

            with self.assertRaises(ValueError):
                lane_state.transition_lane(manifest, "317", "ready_for_adam")

            self.assertEqual("running", manifest["lanes"]["317"]["laneState"])

    def test_merged_and_abandoned_are_terminal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            for terminal in ("merged", "abandoned"):
                with self.subTest(terminal=terminal):
                    manifest = lane_state.empty_manifest()
                    manifest["lanes"]["317"] = valid_lane(Path(directory), state=terminal)
                    lane_state.validate_manifest(manifest)

                    with self.assertRaises(ValueError):
                        lane_state.transition_lane(manifest, "317", "running")

                    self.assertEqual(terminal, manifest["lanes"]["317"]["laneState"])

    def test_expired_lease_does_not_change_owner(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = lane_state.empty_manifest()
            lane = valid_lane(Path(directory))
            lane["lease"]["expiresAt"] = "2020-01-01T00:00:00+00:00"
            lane_state.allocate_lane(manifest, lane)

            lane_state.validate_manifest(manifest)

            self.assertEqual("Task", manifest["lanes"]["317"]["agentId"])
            self.assertEqual("Task", manifest["lanes"]["317"]["lease"]["owner"])

    def test_owner_transfer_requires_blocked_lane(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = lane_state.empty_manifest()
            lane_state.allocate_lane(manifest, valid_lane(Path(directory)))
            lane_state.transition_lane(manifest, "317", "running")

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
                    lane_state.allocate_lane(manifest, valid_lane(Path(directory)))
                    observation = valid_observation()
                    observation.update(updates)

                    with self.assertRaises(ValueError):
                        lane_state.record_observation(
                            manifest,
                            "317",
                            "focused",
                            observation,
                        )

                    self.assertEqual("not_run", manifest["lanes"]["317"]["gates"]["focused"]["state"])

    def test_observation_head_must_match_lane_head(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            invalid_observations = (
                ("head", valid_observation(head_sha=SHA_C)),
                ("base", valid_observation(base_sha=SHA_C)),
            )
            for revision, observation in invalid_observations:
                with self.subTest(revision=revision):
                    manifest = lane_state.empty_manifest()
                    lane_state.allocate_lane(manifest, valid_lane(Path(directory)))
                    original = deepcopy(manifest)

                    with self.assertRaises(ValueError):
                        lane_state.record_observation(
                            manifest,
                            "317",
                            "focused",
                            observation,
                        )

                    self.assertEqual(original, manifest)

    def test_red_evidence_is_append_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = lane_state.empty_manifest()
            lane_state.allocate_lane(manifest, valid_lane(Path(directory)))
            first = valid_observation(state="failed")
            second = valid_observation(state="failed")
            second["artifact"] = ".superpowers/evidence/task-4-second.txt"

            lane_state.record_red(manifest, "317", first)
            lane_state.record_red(manifest, "317", second)

            evidence = manifest["lanes"]["317"]["redEvidence"]
            self.assertEqual([first, second], evidence)
            self.assertEqual("red", manifest["lanes"]["317"]["implementationState"])

    def test_heartbeat_requires_current_owner_and_updates_last_verified(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = lane_state.empty_manifest()
            lane_state.allocate_lane(manifest, valid_lane(Path(directory)))

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
            lane_state.allocate_lane(manifest, valid_lane(Path(directory)))

            lane_state.record_pr(manifest, "317", 42, "https://github.com/example/repo/pull/42")
            lane_state.record_remote(manifest, "317", SHA_C)
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
                ".superpowers/evidence/root-stage1-before.txt",
            )

            lane = manifest["lanes"]["317"]
            self.assertEqual(
                {"number": 42, "url": "https://github.com/example/repo/pull/42"},
                lane["pr"],
            )
            self.assertEqual(SHA_C, lane["remoteSha"])
            self.assertEqual("green", lane["implementationState"])
            self.assertEqual("mergeable", lane["mergeabilityState"])
            self.assertEqual(
                ".superpowers/evidence/root-stage1-before.txt",
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


class InvalidationTests(unittest.TestCase):
    def test_lane_head_change_stales_every_head_bound_observation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = lane_state.empty_manifest()
            allocate_issue(manifest, root, 317)
            record_all_observations(manifest, root, "317")
            manifest["lanes"]["317"]["implementationState"] = "green"
            manifest["lanes"]["317"]["mergeabilityState"] = "mergeable"

            lane_state.update_heads(
                manifest,
                "317",
                head_sha=SHA_C,
                current_base_sha=SHA_B,
            )

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

            lane_state.update_heads(
                manifest,
                "317",
                head_sha=SHA_A,
                current_base_sha=SHA_C,
            )

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
                    observation["baseSha"] == SHA_C
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

            lane_state.update_heads(
                manifest,
                "317",
                head_sha=SHA_A,
                current_base_sha=SHA_B,
            )

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
            for issue in ("318", "319"):
                record_all_observations(manifest, root, issue)
                lane_state.transition_lane(manifest, issue, "running")
                lane_state.transition_lane(manifest, issue, "reviewing")
                lane_state.transition_lane(manifest, issue, "ready_for_adam")
                manifest["lanes"][issue]["mergeabilityState"] = "mergeable"

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
                            "https://github.com/example/repo/pull/42",
                        )
                    lane_state.validate_base_evidence(
                        manifest,
                        "317",
                        gate_name,
                        observation,
                    )

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
                lane_state.transition_lane(data, "317", "running")

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
            lane_state.transition_lane(manifest, "317", "blocked")
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
                    lambda data: lane_state.transition_lane(
                        data,
                        "317",
                        "ready_for_adam",
                    ),
                )

            self.assertEqual(original, path.read_bytes())
            with self.assertRaises(lane_state.TerminalRejection):
                lane_state.mutate_manifest(
                    path,
                    "not-a-timestamp",
                    lambda data: lane_state.transition_lane(
                        data,
                        "317",
                        "running",
                    ),
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
                self.assertEqual(0, lane_state.main(["init", str(path)]))
            created_output = json.loads(output.getvalue())
            self.assertTrue(created_output.pop("created"))
            lane_state.validate_manifest(created_output)
            original = path.read_bytes()

            output = io.StringIO()
            with mock.patch("sys.stdout", output):
                self.assertEqual(0, lane_state.main(["init", str(path)]))
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

            with mock.patch("sys.stdout", output):
                exit_code = lane_state.main(
                    [
                        "update-heads",
                        str(path),
                        "317",
                        "--head-sha",
                        SHA_C,
                        "--current-base-sha",
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
                        str(path),
                        "317",
                        "--head-sha",
                        SHA_C,
                        "--current-base-sha",
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
                        str(path),
                        "317",
                        "Replacement",
                        "coder",
                        "--expected-updated-at",
                        manifest["updatedAt"],
                    ]
                )
            terminal = json.loads(terminal_output.getvalue())
            self.assertEqual(2, terminal_exit)
            self.assertEqual("terminal_rejection", terminal["classification"])


if __name__ == "__main__":
    unittest.main()
