from __future__ import annotations

import contextlib
from collections.abc import Iterator
import io
import importlib.util
import os
from pathlib import Path
import shutil
import stat
import tempfile
import threading
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
        approved_tree_sha256 = setup_skillset.APPROVED_SKILL_TREE_SHA256.copy()
        self.addCleanup(
            setattr,
            setup_skillset,
            "APPROVED_SKILL_TREE_SHA256",
            approved_tree_sha256,
        )
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
        identities = setup_skillset.validate_sources(sources)
        setup_skillset.APPROVED_SKILL_TREE_SHA256 = {
            name: identity.tree_sha256
            for name, identity in identities.items()
        }
        return sources

    def _snapshot_links(self, target: Path) -> dict[str, tuple[int, str]]:
        return {
            entry.name: (entry.lstat().st_ino, os.readlink(entry))
            for entry in target.iterdir()
        }

    def test_requires_python_3_11_or_newer(self) -> None:
        with self.assertRaisesRegex(SystemExit, "Python 3.11 or newer"):
            setup_skillset._require_supported_python((3, 10, 14))
        setup_skillset._require_supported_python((3, 11, 0))

    def test_main_rejects_old_python_before_argument_parsing(self) -> None:
        with patch.object(
            setup_skillset.sys,
            "version_info",
            (3, 10, 14),
        ), patch.object(setup_skillset, "parse_args") as parse_args:
            with self.assertRaisesRegex(SystemExit, "Python 3.11 or newer"):
                setup_skillset.main()

        parse_args.assert_not_called()

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

    def test_changed_approved_tree_fails_before_target_mutation(self) -> None:
        source = self.sources["alpha"]
        references = source / "references"
        references.mkdir()
        reference = references / "contract.md"
        reference.write_text("approved\n", encoding="utf-8")
        identities = setup_skillset.validate_sources(self.sources)
        approved = {
            name: identity.tree_sha256
            for name, identity in identities.items()
        }
        reference.write_text("injected\n", encoding="utf-8")

        with self.assertRaisesRegex(ValueError, "approved tree digest"):
            setup_skillset.reconcile(
                self.target,
                self.sources,
                check=False,
                approved_tree_sha256=approved,
            )

        self.assertFalse(self.target.exists())

    def test_approved_tree_digest_requires_exact_source_names(self) -> None:
        identities = setup_skillset.validate_sources(self.sources)
        approved = {
            name: identity.tree_sha256
            for name, identity in identities.items()
        }

        for invalid in (
            {**approved, "unexpected": "0" * 64},
            {name: digest for name, digest in approved.items() if name != "alpha"},
        ):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(
                ValueError,
                "approved skill names",
            ):
                setup_skillset.reconcile(
                    self.target,
                    self.sources,
                    check=True,
                    approved_tree_sha256=invalid,
                )

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

    def test_nested_source_symlink_is_rejected_before_target_mutation(self) -> None:
        case_root = self.root / "stable-source-links"
        sources = self._create_sources(case_root)
        source = sources["beta"]
        actual_source = case_root / "actual-beta"
        source.rename(actual_source)
        source.symlink_to(actual_source, target_is_directory=True)
        skill = actual_source / "SKILL.md"
        actual_skill = actual_source / "actual-SKILL.md"
        skill.rename(actual_skill)
        skill.symlink_to(actual_skill)
        target = case_root / "target"

        with self.assertRaisesRegex(ValueError, "must not contain symlinks"):
            setup_skillset.reconcile(target, sources, check=False)

        self.assertFalse(target.exists())

    def test_writable_source_entry_is_rejected_before_target_mutation(self) -> None:
        skill = self.sources["beta"] / "SKILL.md"
        skill.chmod(skill.stat().st_mode | stat.S_IWGRP)

        with self.assertRaisesRegex(ValueError, "group/world writable"):
            setup_skillset.reconcile(self.target, self.sources, check=False)

        self.assertFalse(self.target.exists())

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

    def test_changed_wrong_link_blocks_without_overwriting_concurrent_entry(
        self,
    ) -> None:
        self.target.mkdir()
        original_target = self.root / "original"
        original_target.mkdir()
        concurrent_target = self.root / "concurrent"
        concurrent_target.mkdir()
        wrong_link = self.target / "alpha"
        wrong_link.symlink_to(original_target, target_is_directory=True)
        original_replace = setup_skillset._replace_wrong_link
        changed = False

        def change_before_replace(
            current: Path,
            target_descriptor: int,
            backup: Path,
            backup_descriptor: int,
            desired: Path,
            expected: tuple[int, int, int, str],
        ) -> tuple[int, int, int, str]:
            nonlocal changed
            if not changed:
                changed = True
                current.unlink()
                current.symlink_to(concurrent_target, target_is_directory=True)
            return original_replace(
                current,
                target_descriptor,
                backup,
                backup_descriptor,
                desired,
                expected,
            )

        with patch.object(
            setup_skillset,
            "_replace_wrong_link",
            change_before_replace,
        ), self.assertRaisesRegex(ValueError, "changed during reconciliation"):
            setup_skillset.reconcile(self.target, self.sources, check=False)

        self.assertTrue(wrong_link.is_symlink())
        self.assertEqual(concurrent_target.resolve(), wrong_link.resolve())
        self.assertFalse((self.target / "beta").exists())
        self.assertFalse((self.target / "gamma").exists())

    def test_post_rename_swaps_are_preserved_at_target_and_backup(
        self,
    ) -> None:
        for entry_kind in ("file", "directory", "symlink"):
            with self.subTest(entry_kind=entry_kind):
                case_root = self.root / f"post-rename-{entry_kind}"
                sources = self._create_sources(case_root)
                target = case_root / "target"
                target.mkdir()
                original_target = case_root / "original"
                original_target.mkdir()
                current = target / "alpha"
                current.symlink_to(
                    original_target, target_is_directory=True
                )
                concurrent_target = case_root / "concurrent"
                concurrent_target.mkdir()
                original_publish = setup_skillset._publish_symlink_exclusive
                swapped = False

                def swap_after_rename(
                    destination: Path,
                    desired: Path,
                    target_descriptor: int,
                ) -> tuple[int, int, int, str]:
                    nonlocal swapped
                    if destination.name == "alpha" and not swapped:
                        swapped = True
                        if entry_kind == "file":
                            destination.write_text(
                                "concurrent\n", encoding="utf-8"
                            )
                        elif entry_kind == "directory":
                            destination.mkdir()
                            (destination / "owned.txt").write_text(
                                "concurrent\n", encoding="utf-8"
                            )
                        else:
                            destination.symlink_to(
                                concurrent_target,
                                target_is_directory=True,
                            )
                    return original_publish(
                        destination,
                        desired,
                        target_descriptor,
                    )

                with patch.object(
                    setup_skillset,
                    "_publish_symlink_exclusive",
                    swap_after_rename,
                ), self.assertRaisesRegex(
                    ValueError, "appeared during reconciliation"
                ) as raised:
                    setup_skillset.reconcile(target, sources, check=False)

                if entry_kind == "file":
                    self.assertEqual(
                        "concurrent\n",
                        current.read_text(encoding="utf-8"),
                    )
                elif entry_kind == "directory":
                    self.assertEqual(
                        "concurrent\n",
                        (current / "owned.txt").read_text(
                            encoding="utf-8"
                        ),
                    )
                else:
                    self.assertTrue(current.is_symlink())
                    self.assertEqual(
                        concurrent_target.resolve(), current.resolve()
                    )
                workspaces = [
                    path
                    for path in case_root.iterdir()
                    if path.name.startswith(".setup-skillset-")
                ]
                self.assertEqual(1, len(workspaces))
                backup = workspaces[0] / "backups" / "alpha"
                self.assertTrue(backup.is_symlink())
                self.assertEqual(original_target.resolve(), backup.resolve())
                self.assertTrue(
                    any(
                        str(backup) in note
                        for note in getattr(
                            raised.exception, "__notes__", ()
                        )
                    )
                )
                self.assertFalse((target / "beta").exists())
                self.assertFalse((target / "gamma").exists())

    def test_initially_correct_link_change_blocks_success(self) -> None:
        self.target.mkdir()
        for name, source in self.sources.items():
            (self.target / name).symlink_to(
                source.resolve(), target_is_directory=True
            )
        concurrent_target = self.root / "concurrent"
        concurrent_target.mkdir()
        alpha = self.target / "alpha"
        original_revalidate = setup_skillset._revalidate_entries

        def change_before_revalidation(*args: object) -> None:
            alpha.unlink()
            alpha.symlink_to(concurrent_target, target_is_directory=True)
            original_revalidate(*args)

        with patch.object(
            setup_skillset,
            "_revalidate_entries",
            change_before_revalidation,
        ), self.assertRaisesRegex(ValueError, "changed during reconciliation"):
            setup_skillset.reconcile(self.target, self.sources, check=False)

        self.assertEqual(concurrent_target.resolve(), alpha.resolve())

    def test_link_retarget_during_identity_capture_is_rejected(self) -> None:
        self.target.mkdir()
        original_target = self.root / "original"
        original_target.mkdir()
        concurrent_target = self.root / "concurrent"
        concurrent_target.mkdir()
        alpha = self.target / "alpha"
        alpha.symlink_to(original_target, target_is_directory=True)
        original_readlink = os.readlink
        changed = False

        def retarget_during_readlink(
            path: os.PathLike[str],
            *,
            dir_fd: int | None = None,
        ) -> str:
            nonlocal changed
            inspected = (
                alpha
                if dir_fd is not None and Path(path) == Path("alpha")
                else Path(path)
            )
            if inspected == alpha and not changed:
                changed = True
                alpha.unlink()
                alpha.symlink_to(
                    concurrent_target, target_is_directory=True
                )
            if dir_fd is None:
                return original_readlink(path)
            return original_readlink(path, dir_fd=dir_fd)

        with patch.object(
            setup_skillset.os,
            "readlink",
            retarget_during_readlink,
        ), self.assertRaisesRegex(ValueError, "changed during inspection"):
            setup_skillset.reconcile(self.target, self.sources, check=False)

        self.assertEqual(concurrent_target.resolve(), alpha.resolve())
        self.assertFalse((self.target / "beta").exists())
        self.assertFalse((self.target / "gamma").exists())

    def test_missing_link_publication_never_overwrites_concurrent_entry(
        self,
    ) -> None:
        self.target.mkdir()
        concurrent_target = self.root / "concurrent"
        concurrent_target.mkdir()
        original_publish = setup_skillset._publish_symlink_exclusive
        changed = False

        def create_before_publish(
            destination: Path,
            desired: Path,
            target_descriptor: int,
        ) -> tuple[int, int, int, str]:
            nonlocal changed
            if destination.name == "alpha" and not changed:
                changed = True
                destination.symlink_to(concurrent_target, target_is_directory=True)
            return original_publish(
                destination,
                desired,
                target_descriptor,
            )

        with patch.object(
            setup_skillset,
            "_publish_symlink_exclusive",
            create_before_publish,
        ), self.assertRaisesRegex(ValueError, "appeared during reconciliation"):
            setup_skillset.reconcile(self.target, self.sources, check=False)

        concurrent = self.target / "alpha"
        self.assertTrue(concurrent.is_symlink())
        self.assertEqual(concurrent_target.resolve(), concurrent.resolve())
        self.assertFalse((self.target / "beta").exists())
        self.assertFalse((self.target / "gamma").exists())

    def test_nonregular_lock_failure_is_not_masked_and_does_not_mutate(
        self,
    ) -> None:
        original_open = setup_skillset.os.open
        directory_descriptor = original_open(self.root, os.O_RDONLY)

        def open_directory_for_lock(
            path: object,
            flags: int,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> int:
            if flags & os.O_CREAT:
                return os.dup(directory_descriptor)
            return original_open(path, flags, mode, dir_fd=dir_fd)

        try:
            with patch.object(
                setup_skillset.os,
                "open",
                side_effect=open_directory_for_lock,
            ), self.assertRaisesRegex(ValueError, "lock must be a regular file"):
                setup_skillset.reconcile(self.target, self.sources, check=False)
        finally:
            os.close(directory_descriptor)

        self.assertFalse(self.target.exists())

    def test_lock_open_failure_is_classified_without_mutation(self) -> None:
        original_open = setup_skillset.os.open

        def deny_lock_open(
            path: object,
            flags: int,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> int:
            if flags & os.O_CREAT:
                raise PermissionError("denied")
            return original_open(path, flags, mode, dir_fd=dir_fd)

        with patch.object(
            setup_skillset.os,
            "open",
            side_effect=deny_lock_open,
        ), self.assertRaisesRegex(ValueError, "open the skillset lock") as caught:
            setup_skillset.reconcile(self.target, self.sources, check=False)

        self.assertIsInstance(caught.exception.__cause__, PermissionError)
        self.assertFalse(self.target.exists())

    def test_lock_path_stays_stable_when_target_parents_appear(self) -> None:
        lock_root = self.root / "locks"
        lock_root.mkdir()
        target = self.root / "new-home" / ".omp" / "skillset"
        expected_lock_names = {
            setup_skillset.hashlib.sha256(key).hexdigest() + ".lock"
            for key in setup_skillset._lock_target_keys(target)
        }
        with patch.object(
            setup_skillset.tempfile,
            "gettempdir",
            return_value=str(lock_root),
        ):
            with setup_skillset._skillset_lock(target):
                first = list(lock_root.iterdir())
            target.parent.mkdir(parents=True)
            with setup_skillset._skillset_lock(target):
                second = list(lock_root.iterdir())

        self.assertEqual(first, second)
        self.assertEqual(1, len(second))
        lock_directory = second[0]
        self.assertTrue(lock_directory.is_dir())
        self.assertEqual(0o700, stat.S_IMODE(lock_directory.stat().st_mode))
        self.assertEqual(
            expected_lock_names,
            {path.name for path in lock_directory.iterdir()},
        )

    def test_symlink_and_dotdot_target_aliases_share_canonical_lock(
        self,
    ) -> None:
        lock_root = self.root / "alias-locks"
        lock_root.mkdir()
        real_parent = self.root / "real-parent"
        real_parent.mkdir()
        (real_parent / "nested").mkdir()
        alias_parent = self.root / "alias-parent"
        alias_parent.symlink_to(real_parent, target_is_directory=True)
        canonical_target = real_parent / "target"
        alias_target = alias_parent / "nested" / ".." / "target"
        expected_lock_names = {
            setup_skillset.hashlib.sha256(key).hexdigest() + ".lock"
            for target in (canonical_target, alias_target)
            for key in setup_skillset._lock_target_keys(target)
        }

        with patch.object(
            setup_skillset.tempfile,
            "gettempdir",
            return_value=str(lock_root),
        ):
            with setup_skillset._skillset_lock(canonical_target):
                pass
            with setup_skillset._skillset_lock(alias_target):
                pass

        lock_directory = next(lock_root.iterdir())
        self.assertEqual(
            expected_lock_names,
            {path.name for path in lock_directory.iterdir()},
        )

    def test_distinct_lock_keys_acquire_sorted_and_release_reverse(
        self,
    ) -> None:
        real_parent = self.root / "ordered-real"
        real_parent.mkdir()
        alias_parent = self.root / "ordered-alias"
        alias_parent.symlink_to(real_parent, target_is_directory=True)
        target = alias_parent / "target"
        lock_root = self.root / "ordered-locks"
        events: list[tuple[str, str]] = []

        @contextlib.contextmanager
        def record_lock(path: Path) -> Iterator[None]:
            events.append(("acquire", path.name))
            try:
                yield
            finally:
                events.append(("release", path.name))

        with patch.object(
            setup_skillset,
            "_lock_directory",
            return_value=lock_root,
        ), patch.object(
            setup_skillset,
            "_skillset_lock_file",
            record_lock,
        ):
            with setup_skillset._skillset_lock(target):
                pass

        acquired = [
            name for action, name in events if action == "acquire"
        ]
        released = [
            name for action, name in events if action == "release"
        ]
        self.assertEqual(2, len(acquired))
        self.assertEqual(len(acquired), len(set(acquired)))
        self.assertEqual(sorted(acquired), acquired)
        self.assertEqual(list(reversed(acquired)), released)

    def test_same_literal_target_contends_after_parent_becomes_symlink(
        self,
    ) -> None:
        lock_root = self.root / "drift-locks"
        lock_root.mkdir()
        real_parent = self.root / "real-parent"
        real_parent.mkdir()
        literal_parent = self.root / "literal-parent"
        target = literal_parent / "target"
        lexical_lock_name = (
            setup_skillset.hashlib.sha256(
                os.fsencode(
                    setup_skillset._lexical_lock_target(target)
                )
            ).hexdigest()
            + ".lock"
        )
        expected_lock_names = {
            setup_skillset.hashlib.sha256(key).hexdigest() + ".lock"
            for key in setup_skillset._lock_target_keys(target)
        }
        second_opened_lexical_lock = threading.Event()
        second_entered = threading.Event()
        worker_errors: list[BaseException] = []
        original_open = setup_skillset.os.open

        def acquire_again() -> None:
            try:
                with setup_skillset._skillset_lock(target):
                    second_entered.set()
            except BaseException as error:
                worker_errors.append(error)

        worker = threading.Thread(target=acquire_again)

        def observe_second_lock_open(
            path: object,
            flags: int,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> int:
            descriptor = original_open(
                path,
                flags,
                mode,
                dir_fd=dir_fd,
            )
            if (
                threading.current_thread() is worker
                and flags & os.O_CREAT
                and Path(path).name == lexical_lock_name
            ):
                second_opened_lexical_lock.set()
            return descriptor

        with patch.object(
            setup_skillset.tempfile,
            "gettempdir",
            return_value=str(lock_root),
        ):
            with setup_skillset._skillset_lock(target):
                literal_parent.symlink_to(
                    real_parent,
                    target_is_directory=True,
                )
                expected_lock_names.update(
                    setup_skillset.hashlib.sha256(key).hexdigest() + ".lock"
                    for key in setup_skillset._lock_target_keys(target)
                )
                with patch.object(
                    setup_skillset.os,
                    "open",
                    side_effect=observe_second_lock_open,
                ):
                    worker.start()
                    self.assertTrue(
                        second_opened_lexical_lock.wait(10)
                    )
                    self.assertFalse(second_entered.wait(0.2))
            self.assertTrue(second_entered.wait(10))
            worker.join(10)

        self.assertFalse(worker.is_alive())
        self.assertEqual([], worker_errors)
        lock_directory = next(lock_root.iterdir())
        self.assertEqual(
            expected_lock_names,
            {path.name for path in lock_directory.iterdir()},
        )

    def test_concurrent_target_creation_is_preserved(self) -> None:
        target = self.root / "new-target"
        original_mkdir = Path.mkdir
        appeared = False

        def create_target_concurrently(
            path: Path,
            *args: object,
            **kwargs: object,
        ) -> None:
            nonlocal appeared
            if path == target and not appeared:
                appeared = True
                original_mkdir(path)
                raise FileExistsError(path)
            original_mkdir(path, *args, **kwargs)

        with patch.object(
            Path,
            "mkdir",
            create_target_concurrently,
        ), self.assertRaisesRegex(ValueError, "target appeared"):
            setup_skillset.reconcile(target, self.sources, check=False)

        self.assertTrue(target.is_dir())
        self.assertEqual([], list(target.iterdir()))

    def test_created_target_swap_before_publication_is_preserved(self) -> None:
        target = self.root / "new-target"
        original_revalidate = setup_skillset._revalidate_entries
        swapped = False

        def swap_before_revalidation(*args: object) -> None:
            nonlocal swapped
            if not swapped:
                swapped = True
                target.rmdir()
                target.mkdir()
            original_revalidate(*args)

        with patch.object(
            setup_skillset,
            "_revalidate_entries",
            swap_before_revalidation,
        ), self.assertRaisesRegex(ValueError, "target directory changed"):
            setup_skillset.reconcile(target, self.sources, check=False)

        self.assertTrue(target.is_dir())
        self.assertEqual([], list(target.iterdir()))

    def test_existing_target_swap_cannot_redirect_publication_or_rollback(
        self,
    ) -> None:
        self.target.mkdir()
        original_destination = self.root / "original-destination"
        original_destination.mkdir()
        (self.target / "alpha").symlink_to(
            original_destination,
            target_is_directory=True,
        )
        captured_target = self.root / "captured-target"
        original_commit = setup_skillset._commit_link
        swapped = False

        def swap_before_commit(*args: object, **kwargs: object) -> None:
            nonlocal swapped
            if not swapped:
                swapped = True
                self.target.rename(captured_target)
                self.target.mkdir()
            original_commit(*args, **kwargs)

        with patch.object(
            setup_skillset,
            "_commit_link",
            swap_before_commit,
        ), self.assertRaisesRegex(ValueError, "target directory changed"):
            setup_skillset.reconcile(
                self.target,
                self.sources,
                check=False,
            )

        self.assertEqual([], list(self.target.iterdir()))
        self.assertTrue((captured_target / "alpha").is_symlink())
        self.assertEqual(
            original_destination.resolve(),
            (captured_target / "alpha").resolve(),
        )
        self.assertFalse((captured_target / "beta").exists())
        self.assertFalse((captured_target / "gamma").exists())

    def test_created_parent_swap_cannot_redirect_descendants(self) -> None:
        first_parent = self.root / "new-parent"
        target = first_parent / "child" / "target"
        outside = self.root / "outside"
        outside.mkdir()
        original_revalidate = setup_skillset._require_directory_identities
        swapped = False

        def swap_parent_before_descendant(
            identities: dict[Path, tuple[int, int]],
            label: str,
        ) -> None:
            nonlocal swapped
            if first_parent in identities and not swapped:
                swapped = True
                first_parent.rmdir()
                first_parent.symlink_to(
                    outside, target_is_directory=True
                )
            original_revalidate(identities, label)

        with patch.object(
            setup_skillset,
            "_require_directory_identities",
            swap_parent_before_descendant,
        ), self.assertRaisesRegex(ValueError, "target ancestor changed"):
            setup_skillset.reconcile(target, self.sources, check=False)

        self.assertTrue(first_parent.is_symlink())
        self.assertEqual(outside.resolve(), first_parent.resolve())
        self.assertFalse((outside / "child").exists())


    def test_reconcile_rolls_back_every_commit_boundary(self) -> None:
        cases = ("existing", "absent")
        for target_state in cases:
            for fail_at in range(1, 5):
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
                            original_commit = setup_skillset._commit_link
                            calls = 0

                            def interrupt_commit(*args: object, **kwargs: object) -> None:
                                nonlocal calls
                                calls += 1
                                should_fail = calls == fail_at
                                if should_fail and timing == "before":
                                    raise failure_type("commit interrupted")
                                original_commit(*args, **kwargs)
                                if should_fail:
                                    raise failure_type("commit interrupted")

                            with patch.object(
                                setup_skillset,
                                "_commit_link",
                                interrupt_commit,
                            ), self.assertRaises(failure_type):
                                setup_skillset.reconcile(target, sources, check=False)

                            if target_state == "existing":
                                self.assertEqual(
                                    {
                                        name: destination
                                        for name, (_, destination) in before.items()
                                    },
                                    {
                                        name: destination
                                        for name, (_, destination) in (
                                            self._snapshot_links(target).items()
                                        )
                                    },
                                )
                                self.assertEqual(
                                    {"alpha", "beta"},
                                    {entry.name for entry in target.iterdir()},
                                )
                            else:
                                self.assertFalse(target.exists())

    def test_rollback_error_does_not_replace_primary_failure(self) -> None:
        class PrimaryFailure(RuntimeError):
            pass

        self.target.mkdir()
        original_destination = self.root / "rollback-original"
        original_destination.mkdir()
        (self.target / "alpha").symlink_to(
            original_destination,
            target_is_directory=True,
        )
        original_commit = setup_skillset._commit_link
        interrupted = False

        def fail_after_commit(*args: object, **kwargs: object) -> None:
            nonlocal interrupted
            original_commit(*args, **kwargs)
            if not interrupted:
                interrupted = True
                raise PrimaryFailure("primary commit failure")

        with patch.object(
            setup_skillset,
            "_commit_link",
            fail_after_commit,
        ), patch.object(
            setup_skillset,
            "_restore_backup_exclusive",
            side_effect=OSError("rollback restore failure"),
        ), self.assertRaisesRegex(
            PrimaryFailure, "primary commit failure"
        ) as raised:
            setup_skillset.reconcile(
                self.target,
                self.sources,
                check=False,
            )

        self.assertTrue(
            any(
                "rollback restore failure" in note
                for note in getattr(raised.exception, "__notes__", ())
            )
        )
        workspaces = [
            path
            for path in self.root.iterdir()
            if path.name.startswith(".setup-skillset-")
        ]
        self.assertEqual(1, len(workspaces))
        self.assertTrue((workspaces[0] / "backups" / "alpha").is_symlink())

    def test_reconcile_preserves_unrecorded_target_when_mkdir_is_interrupted(
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
                    if path == target:
                        (path / "owned.txt").write_text(
                            "unrecorded\n",
                            encoding="utf-8",
                        )
                    if path == target and not failed:
                        failed = True
                        raise failure

                with patch.object(
                    Path, "mkdir", interrupt_target_mkdir
                ), self.assertRaises(type(failure)) as raised:
                    setup_skillset.reconcile(target, sources, check=False)

                self.assertFalse(target.exists())
                workspaces = [
                    path
                    for path in case_root.iterdir()
                    if path.name.startswith(".setup-skillset-")
                ]
                self.assertEqual(1, len(workspaces))
                preserved_parent = (
                    workspaces[0]
                    / "created-directories"
                    / "directory-0"
                )
                self.assertEqual(
                    "unrecorded\n",
                    (preserved_parent / "target" / "owned.txt").read_text(
                        encoding="utf-8"
                    ),
                )
                self.assertTrue(
                    any(
                        str(preserved_parent) in note
                        for note in getattr(
                            raised.exception, "__notes__", ()
                        )
                    )
                )

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

    def test_workspace_replacement_is_retained_before_cleanup(self) -> None:
        original_rename = Path.rename
        retained_original: Path | None = None
        replaced = False

        def replace_during_cleanup_move(
            path: Path,
            destination: os.PathLike[str],
        ) -> Path:
            nonlocal replaced, retained_original
            destination_path = Path(destination)
            if (
                not replaced
                and path.name.startswith(".setup-skillset-")
                and destination_path.name == "workspace"
            ):
                replaced = True
                retained_original = path.with_name(
                    f"{path.name}-original"
                )
                original_rename(path, retained_original)
                path.mkdir()
                (path / "concurrent.txt").write_text(
                    "preserve\n",
                    encoding="utf-8",
                )
            return original_rename(path, destination_path)

        with patch.object(
            Path,
            "rename",
            replace_during_cleanup_move,
        ), self.assertRaisesRegex(
            ValueError, "replacement preserved at"
        ):
            setup_skillset.reconcile(
                self.target,
                self.sources,
                check=False,
            )

        assert retained_original is not None
        cleanup_containers = [
            path
            for path in self.root.iterdir()
            if path.name.startswith(".setup-skillset-cleanup-")
        ]
        self.assertEqual(1, len(cleanup_containers))
        preserved_replacement = cleanup_containers[0] / "workspace"
        self.assertEqual(
            "preserve\n",
            (preserved_replacement / "concurrent.txt").read_text(
                encoding="utf-8"
            ),
        )
        self.assertTrue(retained_original.is_dir())

    def test_install_mode_reports_exact_changes_and_noop(self) -> None:
        home = self.root / "install-home"
        repo = self.root / "install-repo"
        repo.mkdir()
        sources = self._create_approved_sources(home)
        target = home / ".omp/agent/skillsets/cmtraceopen"
        setup_skillset.reconcile(target, sources, check=False)
        created_name, replaced_name = sorted(sources)[:2]
        (target / created_name).unlink()
        (target / replaced_name).unlink()
        decoy = self.root / "install-decoy"
        decoy.mkdir()
        (target / replaced_name).symlink_to(decoy, target_is_directory=True)
        arguments = [
            "setup_skillset.py",
            "--home",
            str(home),
            "--repo",
            str(repo),
        ]

        changed_output = io.StringIO()
        with patch.object(sys, "argv", arguments), contextlib.redirect_stdout(
            changed_output
        ):
            setup_skillset.main()

        self.assertEqual(
            (
                f"created: {created_name}\n"
                f"replaced: {replaced_name}\n"
                "Skillset reconciled: 15 approved links; 1 created, 1 replaced.\n"
            ),
            changed_output.getvalue(),
        )

        unchanged_output = io.StringIO()
        with patch.object(sys, "argv", arguments), contextlib.redirect_stdout(
            unchanged_output
        ):
            setup_skillset.main()

        self.assertEqual(
            "Skillset reconciled: 15 approved links; 0 created, 0 replaced.\n",
            unchanged_output.getvalue(),
        )

    def test_main_rejects_tampered_source_without_target_mutation(self) -> None:
        home = self.root / "tamper-home"
        repo = self.root / "tamper-repo"
        repo.mkdir()
        sources = self._create_approved_sources(home)
        target = home / ".omp/agent/skillsets/cmtraceopen"
        setup_skillset.reconcile(target, sources, check=False)
        before = self._snapshot_links(target)
        skill = sources["cmtraceopen"] / "SKILL.md"
        skill.write_text(
            skill.read_text(encoding="utf-8") + "injected\n",
            encoding="utf-8",
        )
        arguments = [
            "setup_skillset.py",
            "--home",
            str(home),
            "--repo",
            str(repo),
        ]

        with patch.object(sys, "argv", arguments), self.assertRaisesRegex(
            SystemExit,
            "does not match its approved tree digest",
        ):
            setup_skillset.main()

        self.assertEqual(before, self._snapshot_links(target))


    def test_check_mode_reports_clean_without_mutation(self) -> None:
        home = self.root / "home"
        repo = self.root / "repo"
        repo.mkdir()
        sources = self._create_approved_sources(home)
        target = home / ".omp/agent/skillsets/cmtraceopen"
        setup_skillset.reconcile(target, sources, check=False)
        before = self._snapshot_links(target)
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

        after = self._snapshot_links(target)
        self.assertEqual(before, after)
        self.assertEqual(
            "Skillset clean: 15 approved links; no drift.\n", output.getvalue()
        )

    def test_check_mode_target_link_swap_blocks_clean_success(self) -> None:
        self.target.mkdir()
        for name, source in self.sources.items():
            (self.target / name).symlink_to(
                source.resolve(),
                target_is_directory=True,
            )
        before = self._snapshot_links(self.target)
        concurrent = self.root / "concurrent-target"
        concurrent.mkdir()
        alpha = self.target / "alpha"
        original_revalidate = setup_skillset._revalidate_entries
        swapped = False

        def swap_before_revalidation(*args: object) -> None:
            nonlocal swapped
            if not swapped:
                swapped = True
                alpha.unlink()
                alpha.symlink_to(concurrent, target_is_directory=True)
            original_revalidate(*args)

        with patch.object(
            setup_skillset,
            "_revalidate_entries",
            swap_before_revalidation,
        ), self.assertRaisesRegex(ValueError, "changed during reconciliation"):
            setup_skillset.reconcile(
                self.target,
                self.sources,
                check=True,
            )

        after = self._snapshot_links(self.target)
        self.assertEqual(before["beta"], after["beta"])
        self.assertEqual(before["gamma"], after["gamma"])
        self.assertEqual(concurrent.resolve(), alpha.resolve())

    def test_check_mode_source_directory_swap_blocks_clean_success(
        self,
    ) -> None:
        self.target.mkdir()
        for name, source in self.sources.items():
            (self.target / name).symlink_to(
                source.resolve(),
                target_is_directory=True,
            )
        before = self._snapshot_links(self.target)
        source = self.sources["alpha"]
        original_source = self.root / "original-alpha-source"
        original_revalidate = setup_skillset._revalidate_entries
        swapped = False

        def swap_before_revalidation(*args: object) -> None:
            nonlocal swapped
            if not swapped:
                swapped = True
                source.rename(original_source)
                source.mkdir()
                (source / "SKILL.md").write_text("# replacement\n")
            original_revalidate(*args)

        with patch.object(
            setup_skillset,
            "_revalidate_entries",
            swap_before_revalidation,
        ), self.assertRaisesRegex(ValueError, "sources changed"):
            setup_skillset.reconcile(
                self.target,
                self.sources,
                check=True,
            )

        self.assertEqual(before, self._snapshot_links(self.target))
        self.assertEqual("# replacement\n", (source / "SKILL.md").read_text())

    def test_check_mode_skill_swap_blocks_clean_success(self) -> None:
        self.target.mkdir()
        for name, source in self.sources.items():
            (self.target / name).symlink_to(
                source.resolve(),
                target_is_directory=True,
            )
        before = self._snapshot_links(self.target)
        skill = self.sources["alpha"] / "SKILL.md"
        original_skill = self.sources["alpha"] / "original-SKILL.md"
        original_revalidate = setup_skillset._revalidate_entries
        swapped = False

        def swap_before_revalidation(*args: object) -> None:
            nonlocal swapped
            if not swapped:
                swapped = True
                skill.rename(original_skill)
                skill.write_text("# replacement\n")
            original_revalidate(*args)

        with patch.object(
            setup_skillset,
            "_revalidate_entries",
            swap_before_revalidation,
        ), self.assertRaisesRegex(ValueError, "sources changed"):
            setup_skillset.reconcile(
                self.target,
                self.sources,
                check=True,
            )

        self.assertEqual(before, self._snapshot_links(self.target))
        self.assertEqual("# replacement\n", skill.read_text())

    def test_check_mode_does_not_create_a_lock_file(self) -> None:
        self.target.mkdir()
        for name, source in self.sources.items():
            (self.target / name).symlink_to(
                source.resolve(),
                target_is_directory=True,
            )
        lock_root = self.root / "locks"
        lock_root.mkdir()

        with patch.object(
            setup_skillset.tempfile,
            "gettempdir",
            return_value=str(lock_root),
        ):
            result = setup_skillset.reconcile(
                self.target,
                self.sources,
                check=True,
            )

        self.assertEqual([], list(lock_root.iterdir()))
        self.assertEqual([], result["missing"])
        self.assertEqual([], result["wrong"])

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
                    before = self._snapshot_links(target)
                    arguments.extend(("--target", str(target)))

                with patch.object(sys, "argv", arguments), contextlib.redirect_stdout(
                    io.StringIO()
                ), self.assertRaises(SystemExit) as exit_context:
                    setup_skillset.main()

                self.assertEqual(1, exit_context.exception.code)
                if drift == "missing":
                    self.assertFalse(target.exists())
                else:
                    after = self._snapshot_links(target)
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
        self.assertEqual(
            set(EXPECTED_RELATIVE_PATHS),
            set(setup_skillset.APPROVED_SKILL_TREE_SHA256),
        )
        for digest in setup_skillset.APPROVED_SKILL_TREE_SHA256.values():
            self.assertRegex(digest, r"^[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()
