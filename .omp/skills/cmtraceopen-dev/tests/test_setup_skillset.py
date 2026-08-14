from __future__ import annotations

import contextlib
import io
import importlib.util
import os
from pathlib import Path
import shutil
import tempfile
import sys
import unittest
from unittest.mock import patch


SKILL_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = SKILL_ROOT / "scripts" / "setup_skillset.py"
SPEC = importlib.util.spec_from_file_location("setup_skillset", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
setup_skillset = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(setup_skillset)

EXPECTED_RELATIVE_PATHS = {
    "branch-lane-verification": ".hermes/skills/software-development/branch-lane-verification",
    "cmtrace-scaffold-pipeline": ".hermes/skills/software-development/cmtrace-scaffold-pipeline",
    "cmtraceopen": ".hermes/skills/software-development/cmtraceopen",
    "cmtraceopen-code-review": ".hermes/skills/software-development/cmtraceopen-code-review",
    "contract-scoped-review": ".hermes/skills/software-development/contract-scoped-review",
    "github-code-review": ".hermes/skills/github/github-code-review",
    "github-issues": ".hermes/skills/github/github-issues",
    "github-pr-workflow": ".hermes/skills/github/github-pr-workflow",
    "mdbook-docs": ".hermes/skills/software-development/mdbook-docs",
    "semantic-reducer-development": ".hermes/skills/software-development/semantic-reducer-development",
    "semantic-reducer-framework": ".hermes/skills/software-development/semantic-reducer-framework",
    "systematic-debugging": ".hermes/skills/software-development/systematic-debugging",
    "test-driven-development": ".hermes/skills/software-development/test-driven-development",
    "windows-lab-workers": ".hermes/skills/software-development/windows-lab-workers",
    "windows-remote-validation": ".hermes/skills/system-administration/windows-remote-validation",
}


class SkillsetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.sources = self._create_sources(self.root)
        self.target = self.root / "target"

    def _create_sources(self, root: Path) -> dict[str, Path]:
        sources: dict[str, Path] = {}
        for name in ("alpha", "beta", "gamma"):
            source = root / "sources" / name
            source.mkdir(parents=True)
            (source / "SKILL.md").write_text(f"# {name}\n")
            sources[name] = source
        return sources

    def _create_approved_sources(self, home: Path) -> dict[str, Path]:
        sources = {
            name: home / relative_path
            for name, relative_path in EXPECTED_RELATIVE_PATHS.items()
        }
        for name, source in sources.items():
            source.mkdir(parents=True)
            (source / "SKILL.md").write_text(f"# {name}\n")
        return sources

    def _snapshot_links(self, target: Path) -> dict[str, tuple[int, str]]:
        return {
            entry.name: (entry.lstat().st_ino, os.readlink(entry))
            for entry in target.iterdir()
        }

    def test_creates_only_approved_directory_symlinks(self) -> None:
        result = setup_skillset.reconcile(self.target, self.sources, check=False)

        self.assertEqual(set(self.sources), {entry.name for entry in self.target.iterdir()})
        for name, source in self.sources.items():
            link = self.target / name
            self.assertTrue(link.is_symlink())
            self.assertEqual(source.resolve(), link.resolve())
        self.assertEqual(sorted(self.sources), result["created"])
        self.assertEqual([], result["replaced"])
        self.assertEqual([], result["missing"])
        self.assertEqual([], result["wrong"])

    def test_missing_source_fails_before_target_mutation(self) -> None:
        for missing_part in ("directory", "SKILL.md"):
            with self.subTest(missing_part=missing_part):
                case_root = self.root / missing_part
                sources = self._create_sources(case_root)
                missing = sources["beta"]
                (missing / "SKILL.md").unlink()
                if missing_part == "directory":
                    missing.rmdir()
                target = case_root / "target"
                target.mkdir()
                decoy = case_root / "decoy"
                decoy.mkdir()
                wrong_link = target / "alpha"
                wrong_link.symlink_to(decoy, target_is_directory=True)
                before = self._snapshot_links(target)

                with self.assertRaisesRegex(ValueError, "beta"):
                    setup_skillset.reconcile(target, sources, check=False)

                self.assertEqual(before, self._snapshot_links(target))
                self.assertFalse((target / "beta").exists())
                self.assertFalse((target / "gamma").exists())

    def test_unexpected_target_entry_blocks_without_deleting_it(self) -> None:
        for kind in ("file", "directory"):
            for blocked_name in ("unexpected", "alpha"):
                with self.subTest(kind=kind, blocked_name=blocked_name):
                    case_root = self.root / f"{kind}-{blocked_name}"
                    sources = self._create_sources(case_root)
                    target = case_root / "target"
                    target.mkdir()
                    decoy = case_root / "decoy"
                    decoy.mkdir()
                    wrong_name = "beta" if blocked_name == "alpha" else "alpha"
                    wrong_link = target / wrong_name
                    wrong_link.symlink_to(decoy, target_is_directory=True)
                    blocked = target / blocked_name
                    if kind == "file":
                        expected_bytes = b"preserve exactly\x00\xff"
                        blocked.write_bytes(expected_bytes)
                    else:
                        blocked.mkdir()
                        expected_bytes = b"directory contents"
                        (blocked / "payload.bin").write_bytes(expected_bytes)

                    with self.assertRaisesRegex(ValueError, blocked_name):
                        setup_skillset.reconcile(target, sources, check=False)

                    self.assertTrue(wrong_link.is_symlink())
                    self.assertEqual(decoy.resolve(), wrong_link.resolve())
                    if kind == "file":
                        self.assertEqual(expected_bytes, blocked.read_bytes())
                    else:
                        self.assertEqual(
                            expected_bytes, (blocked / "payload.bin").read_bytes()
                        )
                    untouched_missing = set(sources) - {blocked_name, wrong_name}
                    for name in untouched_missing:
                        self.assertFalse((target / name).exists())

    def test_unexpected_target_symlink_blocks_without_deleting_it(self) -> None:
        self.target.mkdir()
        decoy = self.root / "decoy"
        decoy.mkdir()
        wrong_link = self.target / "alpha"
        wrong_link.symlink_to(decoy, target_is_directory=True)
        unexpected = self.target / "unexpected"
        unexpected.symlink_to("missing-destination", target_is_directory=True)
        original_destination = os.readlink(unexpected)

        with self.assertRaisesRegex(ValueError, "unexpected"):
            setup_skillset.reconcile(self.target, self.sources, check=False)

        self.assertTrue(wrong_link.is_symlink())
        self.assertEqual(decoy.resolve(), wrong_link.resolve())
        self.assertTrue(unexpected.is_symlink())
        self.assertEqual(original_destination, os.readlink(unexpected))
        self.assertFalse((self.target / "beta").exists())
        self.assertFalse((self.target / "gamma").exists())

    def test_wrong_existing_symlink_is_replaced(self) -> None:
        self.target.mkdir()
        decoy = self.root / "decoy"
        decoy.mkdir()
        wrong_link = self.target / "alpha"
        wrong_link.symlink_to(decoy, target_is_directory=True)

        result = setup_skillset.reconcile(self.target, self.sources, check=False)

        self.assertTrue(wrong_link.is_symlink())
        self.assertEqual(self.sources["alpha"].resolve(), wrong_link.resolve())
        self.assertEqual(["alpha"], result["replaced"])
        self.assertEqual(["beta", "gamma"], result["created"])
        self.assertEqual([], result["missing"])
        self.assertEqual([], result["wrong"])

    def test_reconcile_preserves_state_when_link_staging_fails(self) -> None:
        for failure in (OSError("link failed"), KeyboardInterrupt()):
            with self.subTest(failure=type(failure).__name__):
                case_root = self.root / type(failure).__name__
                sources = self._create_sources(case_root)
                target = case_root / "target"
                target.mkdir()
                decoy = case_root / "decoy"
                decoy.mkdir()
                for name in ("alpha", "beta"):
                    (target / name).symlink_to(decoy, target_is_directory=True)
                before = self._snapshot_links(target)
                original_symlink_to = Path.symlink_to

                def fail_for_beta(
                    path: Path,
                    destination: Path,
                    target_is_directory: bool = False,
                ) -> None:
                    if path.name == "beta":
                        raise failure
                    original_symlink_to(
                        path,
                        destination,
                        target_is_directory=target_is_directory,
                    )

                with patch.object(Path, "symlink_to", fail_for_beta), self.assertRaises(
                    type(failure)
                ):
                    setup_skillset.reconcile(target, sources, check=False)

                self.assertEqual(before, self._snapshot_links(target))
                self.assertFalse((target / "gamma").exists())

    def test_reconcile_rolls_back_every_commit_boundary(self) -> None:
        cases = (("existing", 6), ("absent", 4))
        for target_state, replace_count in cases:
            for fail_at in range(1, replace_count + 1):
                for timing in ("before", "after"):
                    for failure_type in (OSError, KeyboardInterrupt):
                        label = f"{target_state}-{fail_at}-{timing}-{failure_type.__name__}"
                        with self.subTest(label=label):
                            case_root = self.root / label
                            sources = self._create_sources(case_root)
                            delta = case_root / "sources" / "delta"
                            delta.mkdir()
                            (delta / "SKILL.md").write_text("# delta\n")
                            sources["delta"] = delta
                            target = case_root / "target"
                            if target_state == "existing":
                                target.mkdir()
                                decoy = case_root / "decoy"
                                decoy.mkdir()
                                for name in ("alpha", "beta"):
                                    (target / name).symlink_to(
                                        decoy, target_is_directory=True
                                    )
                                before = self._snapshot_links(target)
                            original_replace = os.replace
                            calls = 0

                            def interrupt_replace(
                                source: Path, destination: Path
                            ) -> None:
                                nonlocal calls
                                calls += 1
                                should_fail = calls == fail_at
                                if should_fail and timing == "before":
                                    raise failure_type("replace interrupted")
                                original_replace(source, destination)
                                if should_fail:
                                    raise failure_type("replace interrupted")

                            with patch.object(
                                os, "replace", interrupt_replace
                            ), self.assertRaises(failure_type):
                                setup_skillset.reconcile(target, sources, check=False)

                            if target_state == "existing":
                                self.assertEqual(before, self._snapshot_links(target))
                                self.assertEqual(
                                    {"alpha", "beta"},
                                    {entry.name for entry in target.iterdir()},
                                )
                            else:
                                self.assertFalse(target.exists())

    def test_reconcile_removes_new_target_parents_when_mkdir_is_interrupted(
        self,
    ) -> None:
        for failure in (OSError("mkdir failed"), KeyboardInterrupt()):
            with self.subTest(failure=type(failure).__name__):
                case_root = self.root / f"mkdir-{type(failure).__name__}"
                sources = self._create_sources(case_root)
                created_root = case_root / "new-parent"
                target = created_root / "nested" / "target"
                original_mkdir = Path.mkdir
                failed = False

                def interrupt_target_mkdir(
                    path: Path,
                    mode: int = 0o777,
                    parents: bool = False,
                    exist_ok: bool = False,
                ) -> None:
                    nonlocal failed
                    original_mkdir(
                        path, mode=mode, parents=parents, exist_ok=exist_ok
                    )
                    if path == target and not failed:
                        failed = True
                        raise failure

                with patch.object(
                    Path, "mkdir", interrupt_target_mkdir
                ), self.assertRaises(type(failure)):
                    setup_skillset.reconcile(target, sources, check=False)

                self.assertFalse(created_root.exists())

    def test_workspace_cleanup_failure_is_nonfatal_after_commit(self) -> None:
        for target_state in ("existing", "absent"):
            for failure in (OSError("cleanup failed"), KeyboardInterrupt()):
                label = f"{target_state}-{type(failure).__name__}"
                with self.subTest(label=label):
                    case_root = self.root / f"cleanup-{label}"
                    sources = self._create_sources(case_root)
                    target = case_root / "target"
                    if target_state == "existing":
                        target.mkdir()
                        decoy = case_root / "decoy"
                        decoy.mkdir()
                        (target / "alpha").symlink_to(
                            decoy, target_is_directory=True
                        )
                    original_rmtree = shutil.rmtree
                    interrupted = False

                    def cleanup_then_interrupt(
                        path: Path, *args: object, **kwargs: object
                    ) -> None:
                        nonlocal interrupted
                        original_rmtree(path, *args, **kwargs)
                        if not interrupted:
                            interrupted = True
                            raise failure

                    with patch.object(shutil, "rmtree", cleanup_then_interrupt):
                        result = setup_skillset.reconcile(
                            target, sources, check=False
                        )

                    self.assertEqual(set(sources), set(self._snapshot_links(target)))
                    if target_state == "existing":
                        self.assertEqual(["alpha"], result["replaced"])
                    else:
                        self.assertEqual(sorted(sources), result["created"])

    def test_check_mode_reports_clean_without_mutation(self) -> None:
        home = self.root / "home"
        repo = self.root / "repo"
        repo.mkdir()
        sources = self._create_approved_sources(home)
        target = home / ".omp/agent/skillsets/cmtraceopen"
        setup_skillset.reconcile(target, sources, check=False)
        before = {
            entry.name: (entry.lstat().st_ino, os.readlink(entry))
            for entry in target.iterdir()
        }
        arguments = [
            "setup_skillset.py",
            "--home",
            str(home),
            "--repo",
            str(repo),
            "--check",
        ]
        output = io.StringIO()

        with patch.object(sys, "argv", arguments), contextlib.redirect_stdout(output):
            setup_skillset.main()

        after = {
            entry.name: (entry.lstat().st_ino, os.readlink(entry))
            for entry in target.iterdir()
        }
        self.assertEqual(before, after)
        self.assertEqual(
            "Skillset clean: 15 approved links; no drift.\n", output.getvalue()
        )

    def test_check_mode_reports_drift_without_mutation(self) -> None:
        for drift in ("missing", "wrong"):
            with self.subTest(drift=drift):
                home = self.root / f"{drift}-home"
                repo = self.root / f"{drift}-repo"
                repo.mkdir()
                sources = self._create_approved_sources(home)
                target = home / ".omp/agent/skillsets/cmtraceopen"
                arguments = [
                    "setup_skillset.py",
                    "--home",
                    str(home),
                    "--repo",
                    str(repo),
                    "--check",
                ]
                if drift == "wrong":
                    target = self.root / "custom-target"
                    setup_skillset.reconcile(target, sources, check=False)
                    wrong_link = target / "branch-lane-verification"
                    wrong_link.unlink()
                    decoy = self.root / "decoy"
                    decoy.mkdir()
                    wrong_link.symlink_to(decoy, target_is_directory=True)
                    before = {
                        entry.name: (entry.lstat().st_ino, os.readlink(entry))
                        for entry in target.iterdir()
                    }
                    arguments.extend(("--target", str(target)))

                with patch.object(sys, "argv", arguments), contextlib.redirect_stdout(
                    io.StringIO()
                ), self.assertRaises(SystemExit) as exit_context:
                    setup_skillset.main()

                self.assertEqual(1, exit_context.exception.code)
                if drift == "missing":
                    self.assertFalse(target.exists())
                else:
                    after = {
                        entry.name: (entry.lstat().st_ino, os.readlink(entry))
                        for entry in target.iterdir()
                    }
                    self.assertEqual(before, after)

    def test_main_rejects_target_symlink_without_following_it(self) -> None:
        for destination_exists in (True, False):
            with self.subTest(destination_exists=destination_exists):
                case_root = self.root / f"target-link-{destination_exists}"
                home = case_root / "home"
                repo = case_root / "repo"
                repo.mkdir(parents=True)
                self._create_approved_sources(home)
                destination = case_root / "destination"
                if destination_exists:
                    destination.mkdir()
                target = case_root / "target"
                target.symlink_to(destination, target_is_directory=True)
                original_destination = os.readlink(target)
                arguments = [
                    "setup_skillset.py",
                    "--home",
                    str(home),
                    "--repo",
                    str(repo),
                    "--target",
                    str(target),
                ]

                with patch.object(sys, "argv", arguments), self.assertRaisesRegex(
                    SystemExit, "target must be a directory"
                ):
                    setup_skillset.main()

                self.assertTrue(target.is_symlink())
                self.assertEqual(original_destination, os.readlink(target))
                if destination_exists:
                    self.assertEqual([], list(destination.iterdir()))
                else:
                    self.assertFalse(destination.exists())

    def test_resolves_exact_approved_skill_sources(self) -> None:
        home = self.root / "home"
        repo = self.root / "repo"
        expected = {
            name: home / relative_path
            for name, relative_path in EXPECTED_RELATIVE_PATHS.items()
        }

        self.assertEqual(expected, setup_skillset.resolve_sources(home, repo))


if __name__ == "__main__":
    unittest.main()
