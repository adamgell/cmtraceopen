#!/usr/bin/env python3
from __future__ import annotations

import argparse
from collections.abc import Collection, Iterator
from contextlib import ExitStack, contextmanager
from typing import NamedTuple
import hashlib
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile


def _require_supported_python(version: tuple[int, ...]) -> None:
    if version < (3, 11):
        raise SystemExit("error: setup_skillset.py requires Python 3.11 or newer")


APPROVED_SKILLS: dict[str, tuple[str, str]] = {
    "branch-lane-verification": (
        "home",
        ".hermes/skills/software-development/branch-lane-verification",
    ),
    "cmtrace-scaffold-pipeline": (
        "home",
        ".hermes/skills/software-development/cmtrace-scaffold-pipeline",
    ),
    "cmtraceopen": ("home", ".hermes/skills/software-development/cmtraceopen"),
    "cmtraceopen-code-review": (
        "home",
        ".hermes/skills/software-development/cmtraceopen-code-review",
    ),
    "contract-scoped-review": (
        "home",
        ".hermes/skills/software-development/contract-scoped-review",
    ),
    "github-code-review": ("home", ".hermes/skills/github/github-code-review"),
    "github-issues": ("home", ".hermes/skills/github/github-issues"),
    "github-pr-workflow": ("home", ".hermes/skills/github/github-pr-workflow"),
    "mdbook-docs": ("home", ".hermes/skills/software-development/mdbook-docs"),
    "semantic-reducer-development": (
        "home",
        ".hermes/skills/software-development/semantic-reducer-development",
    ),
    "semantic-reducer-framework": (
        "home",
        ".hermes/skills/software-development/semantic-reducer-framework",
    ),
    "systematic-debugging": (
        "home",
        ".hermes/skills/software-development/systematic-debugging",
    ),
    "test-driven-development": (
        "home",
        ".hermes/skills/software-development/test-driven-development",
    ),
    "windows-lab-workers": (
        "home",
        ".hermes/skills/software-development/windows-lab-workers",
    ),
    "windows-remote-validation": (
        "home",
        ".hermes/skills/system-administration/windows-remote-validation",
    ),
}

APPROVED_SKILL_TREE_SHA256: dict[str, str] = {
    "branch-lane-verification": (
        "4164efcd967e208ad5c8eb913c3bc72ad44feb4e5bc102058d0a7ceb3557552c"
    ),
    "cmtrace-scaffold-pipeline": (
        "bea4fa1d2cb8d556c6fb51c85dde6122bfbacb8721bd17aa01b81e9c2bb1fcd9"
    ),
    "cmtraceopen": (
        "4b4b3276dcfc008da21e709e3edac08681074bcd1756bc0b75cc8061a63e72d8"
    ),
    "cmtraceopen-code-review": (
        "ba70993c4b5b8bff2fd523b9b93c1797cb14e77bebf79ff21a7a4e412a37487f"
    ),
    "contract-scoped-review": (
        "30564a296fd4690fdc63af624eed1a56bf65074bae0fecf750daa9a539f16e61"
    ),
    # NousResearch/hermes-agent@4a2198bf5124f0c4d915cb958f141116ae8607f0.
    "github-code-review": (
        "5e166a8ea948fe41ddd3e0207d0fa26b3e29243c16f6b979dcc24e901d635a10"
    ),
    "github-issues": (
        "dd55fd6c7ac90a20f0e63b2aa4fbff6a1e4f1aea52c1810821f7279d40a69128"
    ),
    "github-pr-workflow": (
        "198b3e52369e6c2d4d9317fb4cfef1b1f2c930939f2a69d0af6cfdf55ae9ed50"
    ),
    "mdbook-docs": (
        "017a84030b9f041858a723dce9a4ffb5b3d09d361f888fd0b3ca1e9974877b96"
    ),
    "semantic-reducer-development": (
        "8229bec1629a1b3707ddb914113ec07461737a3b06162ef55bf02f8be5d1b01e"
    ),
    "semantic-reducer-framework": (
        "ea5551854616e9348bc05fcce171afeaca6c20228a993c3710f73b135c1ac6eb"
    ),
    "systematic-debugging": (
        "899fb826d982e6deb2d78ff18a472338eec9ee29370960505d6990f2910e84d3"
    ),
    "test-driven-development": (
        "8edf89c2b79e5bdcee42b10be580f1e60e50a1a53f31f3cf2486625dd67fe096"
    ),
    "windows-lab-workers": (
        "f7feb5e803dd03f5222bba44b088e3f76aa531a532f6ec9610f053e7fe16b466"
    ),
    "windows-remote-validation": (
        "933460289f050de080b859546e8f12a5af0c0f4ebdf353b860bc40a745037ad4"
    ),
}


def resolve_sources(home: Path, repo: Path) -> dict[str, Path]:
    roots = {"home": home, "repo": repo}
    return {
        name: roots[root] / relative_path
        for name, (root, relative_path) in APPROVED_SKILLS.items()
    }


StatIdentity = tuple[int, int, int, int, int, int, int, int, int]
LinkIdentity = tuple[int, int, int, str]
EntryIdentity = tuple[int, int, int, int, int, str | None]
DirectoryIdentity = tuple[int, int]


class SourceIdentity(NamedTuple):
    directory_entry: StatIdentity
    directory_link: str | None
    resolved: Path
    directory: StatIdentity
    skill_entry: StatIdentity
    skill_link: str | None
    resolved_skill: Path
    skill: StatIdentity
    skill_sha256: str
    tree_sha256: str


def _stat_identity(info: os.stat_result) -> StatIdentity:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_uid,
        info.st_gid,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _stable_lstat(path: Path, label: str) -> tuple[StatIdentity, str | None]:
    try:
        before = path.lstat()
        link_target = (
            os.readlink(path) if stat.S_ISLNK(before.st_mode) else None
        )
        after = path.lstat()
    except OSError as error:
        raise ValueError(f"{label} does not exist: {path}") from error
    before_identity = _stat_identity(before)
    if before_identity != _stat_identity(after):
        raise ValueError(f"{label} changed during inspection: {path}")
    return before_identity, link_target


def _stable_entry_at(
    descriptor: int,
    name: str,
    display_path: Path,
    label: str,
) -> tuple[StatIdentity, str | None]:
    try:
        before = os.stat(
            name,
            dir_fd=descriptor,
            follow_symlinks=False,
        )
        link_target = (
            os.readlink(name, dir_fd=descriptor)
            if stat.S_ISLNK(before.st_mode)
            else None
        )
        after = os.stat(
            name,
            dir_fd=descriptor,
            follow_symlinks=False,
        )
    except OSError as error:
        raise ValueError(f"{label} does not exist: {display_path}") from error
    identity = _stat_identity(before)
    if identity != _stat_identity(after):
        raise ValueError(f"{label} changed during inspection: {display_path}")
    return identity, link_target


def _capture_file_content(
    path: Path,
    expected: StatIdentity,
    label: str,
) -> str:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ValueError(f"{label} changed during inspection: {path}") from error
    try:
        if _stat_identity(os.fstat(descriptor)) != expected:
            raise ValueError(f"{label} changed during inspection: {path}")
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        if _stat_identity(os.fstat(descriptor)) != expected:
            raise ValueError(f"{label} changed during inspection: {path}")
    finally:
        os.close(descriptor)
    final, final_link = _stable_lstat(path, label)
    if final_link is not None or final != expected:
        raise ValueError(f"{label} changed during inspection: {path}")
    return digest.hexdigest()

def _require_trusted_source_entry(identity: StatIdentity, path: Path) -> None:
    if hasattr(os, "geteuid") and identity[4] != os.geteuid():
        raise ValueError(f"skill source entry is not owned by the current user: {path}")
    if identity[2] & (stat.S_IWGRP | stat.S_IWOTH):
        raise ValueError(f"skill source entry is group/world writable: {path}")


def _capture_source_tree(root: Path) -> str:
    digest = hashlib.sha256()

    def add(kind: bytes, relative: Path, content_sha256: str = "") -> None:
        encoded = os.fsencode(relative.as_posix())
        digest.update(kind)
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
        if content_sha256:
            digest.update(bytes.fromhex(content_sha256))

    def visit(directory: Path, relative: Path) -> None:
        directory_identity, directory_link = _stable_lstat(
            directory,
            "skill source tree directory",
        )
        if directory_link is not None or not stat.S_ISDIR(directory_identity[2]):
            raise ValueError(f"skill source tree entry must be a directory: {directory}")
        _require_trusted_source_entry(directory_identity, directory)
        try:
            with os.scandir(directory) as iterator:
                entries = sorted(
                    iterator,
                    key=lambda entry: os.fsencode(entry.name),
                )
        except OSError as error:
            raise ValueError(f"cannot read skill source tree: {directory}") from error
        for entry in entries:
            path = directory / entry.name
            child_relative = relative / entry.name
            identity, link_target = _stable_lstat(
                path,
                "skill source tree entry",
            )
            if link_target is not None:
                raise ValueError(f"skill source tree must not contain symlinks: {path}")
            _require_trusted_source_entry(identity, path)
            if stat.S_ISDIR(identity[2]):
                add(b"D", child_relative)
                visit(path, child_relative)
            elif stat.S_ISREG(identity[2]):
                add(
                    b"F",
                    child_relative,
                    _capture_file_content(
                        path,
                        identity,
                        "skill source tree file",
                    ),
                )
            else:
                raise ValueError(
                    f"skill source tree entry must be a file or directory: {path}"
                )
        final_identity, final_link = _stable_lstat(
            directory,
            "skill source tree directory",
        )
        if final_link is not None or final_identity != directory_identity:
            raise ValueError(f"skill source tree changed during inspection: {directory}")

    visit(root, Path())
    return digest.hexdigest()


def _capture_skill_identity(
    descriptor: int,
    source: Path,
    resolved_source: Path,
) -> tuple[StatIdentity, str | None, Path, StatIdentity, str]:
    skill = source / "SKILL.md"
    entry_identity, link_target = _stable_entry_at(
        descriptor,
        "SKILL.md",
        skill,
        "SKILL.md",
    )
    resolved_skill = (resolved_source / "SKILL.md").resolve(strict=True)
    content_identity, content_link = _stable_lstat(
        resolved_skill,
        "resolved SKILL.md",
    )
    if content_link is not None or not stat.S_ISREG(content_identity[2]):
        raise ValueError(f"SKILL.md must resolve to a regular file: {skill}")
    skill_sha256 = _capture_file_content(
        resolved_skill,
        content_identity,
        "SKILL.md",
    )
    final_identity, final_link = _stable_entry_at(
        descriptor,
        "SKILL.md",
        skill,
        "SKILL.md",
    )
    if (
        final_identity != entry_identity
        or final_link != link_target
        or (resolved_source / "SKILL.md").resolve(strict=True)
        != resolved_skill
    ):
        raise ValueError(f"SKILL.md changed during inspection: {skill}")
    return (
        entry_identity,
        link_target,
        resolved_skill,
        content_identity,
        skill_sha256,
    )


def _capture_source_identity(source: Path) -> SourceIdentity:
    entry_identity, link_target = _stable_lstat(
        source,
        "source directory",
    )
    resolved = source.resolve(strict=True)
    directory_identity, resolved_link = _stable_lstat(
        resolved,
        "resolved source directory",
    )
    if resolved_link is not None or not stat.S_ISDIR(directory_identity[2]):
        raise ValueError(
            f"source directory must resolve to a directory: {source}"
        )

    descriptor, _ = _open_pinned_directory(
        resolved,
        "resolved source directory",
        (directory_identity[0], directory_identity[1]),
    )
    try:
        if _stat_identity(os.fstat(descriptor)) != directory_identity:
            raise ValueError(
                f"source directory changed during inspection: {source}"
            )
        (
            skill_entry,
            skill_link,
            resolved_skill,
            skill_identity,
            skill_sha256,
        ) = _capture_skill_identity(descriptor, source, resolved)
        tree_sha256 = _capture_source_tree(resolved)
        final_entry, final_link = _stable_lstat(
            source,
            "source directory",
        )
        if (
            final_entry != entry_identity
            or final_link != link_target
            or source.resolve(strict=True) != resolved
        ):
            raise ValueError(
                f"source directory changed during inspection: {source}"
            )
    finally:
        os.close(descriptor)
    return SourceIdentity(
        directory_entry=entry_identity,
        directory_link=link_target,
        resolved=resolved,
        directory=directory_identity,
        skill_entry=skill_entry,
        skill_link=skill_link,
        resolved_skill=resolved_skill,
        skill=skill_identity,
        skill_sha256=skill_sha256,
        tree_sha256=tree_sha256,
    )


def validate_sources(
    sources: dict[str, Path],
) -> dict[str, SourceIdentity]:
    identities: dict[str, SourceIdentity] = {}
    errors: list[str] = []
    for name, source in sorted(sources.items()):
        try:
            identities[name] = _capture_source_identity(source)
        except (OSError, ValueError) as error:
            errors.append(f"{name}: {error}")
    if errors:
        raise ValueError("invalid skill sources:\n" + "\n".join(errors))
    return identities

def _require_approved_tree_digests(
    identities: dict[str, SourceIdentity],
    approved_tree_sha256: dict[str, str],
) -> None:
    if set(identities) != set(approved_tree_sha256):
        raise ValueError("approved skill names must match the resolved source names")
    for name, identity in identities.items():
        expected = approved_tree_sha256[name]
        if (
            len(expected) != 64
            or expected.lower() != expected
            or any(character not in "0123456789abcdef" for character in expected)
        ):
            raise ValueError(f"{name}: approved tree digest must be lowercase SHA-256")
        if identity.tree_sha256 != expected:
            raise ValueError(f"{name}: source does not match its approved tree digest")


def _require_source_identities(
    sources: dict[str, Path],
    expected: dict[str, SourceIdentity],
) -> None:
    try:
        current = validate_sources(sources)
    except ValueError as error:
        raise ValueError(
            "approved skill sources changed during reconciliation"
        ) from error
    if current != expected:
        raise ValueError(
            "approved skill sources changed during reconciliation"
        )


def _entry_exists_at(descriptor: int, name: str) -> bool:
    try:
        os.stat(name, dir_fd=descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return False
    return True


def _entry_identity_at(
    descriptor: int,
    name: str,
    display_path: Path,
) -> EntryIdentity:
    before = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
    link_target = (
        os.readlink(name, dir_fd=descriptor)
        if stat.S_ISLNK(before.st_mode)
        else None
    )
    after = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
    before_identity = (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_ctime_ns,
        before.st_size,
    )
    after_identity = (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_ctime_ns,
        after.st_size,
    )
    if before_identity != after_identity:
        raise ValueError(
            f"target entry changed during inspection: {display_path}"
        )
    return *before_identity, link_target


def _link_identity_at(
    descriptor: int,
    name: str,
    display_path: Path,
) -> LinkIdentity:
    identity = _entry_identity_at(descriptor, name, display_path)
    if not stat.S_ISLNK(identity[2]):
        raise ValueError(
            f"approved target changed to a non-symlink: {display_path}"
        )
    assert identity[5] is not None
    return identity[0], identity[1], identity[2], identity[5]


def _link_identity(identity: EntryIdentity) -> LinkIdentity:
    if not stat.S_ISLNK(identity[2]) or identity[5] is None:
        raise ValueError("target entry is not a symlink")
    return identity[0], identity[1], identity[2], identity[5]


def _directory_identity(path: Path, label: str) -> DirectoryIdentity:
    try:
        info = path.lstat()
    except OSError as error:
        raise ValueError(
            f"{label} changed during reconciliation: {path}"
        ) from error
    if not stat.S_ISDIR(info.st_mode):
        raise ValueError(f"{label} changed during reconciliation: {path}")
    return info.st_dev, info.st_ino


def _open_pinned_directory(
    path: Path,
    label: str,
    expected: DirectoryIdentity | None = None,
) -> tuple[int, DirectoryIdentity]:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ValueError(
            f"{label} changed during reconciliation: {path}"
        ) from error
    try:
        info = os.fstat(descriptor)
        identity = info.st_dev, info.st_ino
        if not stat.S_ISDIR(info.st_mode):
            raise ValueError(
                f"{label} changed during reconciliation: {path}"
            )
        if expected is not None and identity != expected:
            raise ValueError(
                f"{label} changed during reconciliation: {path}"
            )
        if _directory_identity(path, label) != identity:
            raise ValueError(
                f"{label} changed during reconciliation: {path}"
            )
        return descriptor, identity
    except BaseException:
        os.close(descriptor)
        raise


def _require_directory_identities(
    identities: dict[Path, DirectoryIdentity],
    label: str,
) -> None:
    for path, expected in identities.items():
        if _directory_identity(path, label) != expected:
            raise ValueError(f"{label} changed during reconciliation: {path}")


def _require_paths_absent(paths: Collection[Path], label: str) -> None:
    for path in paths:
        try:
            path.lstat()
        except FileNotFoundError:
            continue
        except OSError as error:
            raise ValueError(
                f"{label} changed during reconciliation: {path}"
            ) from error
        raise ValueError(f"{label} changed during reconciliation: {path}")


def _require_target_entries(
    descriptor: int,
    target: Path,
    expected_names: Collection[str],
) -> None:
    if set(os.listdir(descriptor)) != set(expected_names):
        raise ValueError(
            f"target entries changed during reconciliation: {target}"
        )


def _revalidate_entries(
    target: Path,
    target_identity: DirectoryIdentity,
    target_descriptor: int,
    entries: Collection[str],
    identities: dict[str, EntryIdentity],
) -> None:
    info = os.fstat(target_descriptor)
    if (
        not stat.S_ISDIR(info.st_mode)
        or (info.st_dev, info.st_ino) != target_identity
        or _directory_identity(target, "target directory")
        != target_identity
    ):
        raise ValueError(
            f"target directory changed during reconciliation: {target}"
        )
    _require_target_entries(target_descriptor, target, entries)
    for name, expected in identities.items():
        try:
            current = _entry_identity_at(
                target_descriptor,
                name,
                target / name,
            )
        except OSError as error:
            raise ValueError(
                f"approved target changed during reconciliation: {target / name}"
            ) from error
        if current != expected:
            raise ValueError(
                f"approved target changed during reconciliation: {target / name}"
            )

def _lock_directory() -> Path:
    try:
        temporary_root = Path(tempfile.gettempdir()).resolve(strict=True)
        if not temporary_root.is_dir():
            raise ValueError(
                f"temporary lock root must be a directory: {temporary_root}"
            )
        if hasattr(os, "geteuid"):
            user_key = str(os.geteuid())
        else:
            user_key = hashlib.sha256(
                os.fsencode(os.path.expanduser("~"))
            ).hexdigest()[:16]
        lock_root = temporary_root / f"cmtraceopen-skillset-{user_key}"
        try:
            lock_root.mkdir(mode=0o700)
            lock_root.chmod(0o700)
        except FileExistsError:
            pass
        lock_info = lock_root.lstat()
    except OSError as error:
        raise ValueError(
            "cannot prepare the skillset lock directory"
        ) from error
    if not stat.S_ISDIR(lock_info.st_mode):
        raise ValueError(
            f"skillset lock root must be a directory: {lock_root}"
        )
    if (
        hasattr(os, "geteuid")
        and lock_info.st_uid != os.geteuid()
    ):
        raise ValueError(
            f"skillset lock root must be owned by the current user: {lock_root}"
        )
    if stat.S_IMODE(lock_info.st_mode) != 0o700:
        raise ValueError(
            f"skillset lock root must have mode 0700: {lock_root}"
        )
    return lock_root


def _lexical_lock_target(target: Path) -> Path:
    try:
        candidate = target if target.is_absolute() else Path.cwd() / target
        return Path(os.path.normpath(os.path.abspath(candidate)))
    except OSError as error:
        raise ValueError(
            f"cannot normalize the skillset lock target: {target}"
        ) from error


def _canonical_lock_target(target: Path) -> Path:
    candidate = target if target.is_absolute() else Path.cwd() / target
    missing_parts: list[str] = []
    try:
        while True:
            try:
                existing_ancestor = candidate.resolve(strict=True)
            except FileNotFoundError:
                parent = candidate.parent
                if parent == candidate:
                    raise
                missing_parts.append(candidate.name)
                candidate = parent
                continue
            break
    except OSError as error:
        raise ValueError(
            f"cannot canonicalize the skillset lock target: {target}"
        ) from error
    return Path(
        os.path.normpath(
            existing_ancestor.joinpath(
                *reversed(missing_parts)
            )
        )
    )


def _lock_target_keys(target: Path) -> tuple[bytes, ...]:
    return tuple(
        sorted(
            {
                os.fsencode(_lexical_lock_target(target)),
                os.fsencode(_canonical_lock_target(target)),
            }
        )
    )


@contextmanager
def _skillset_lock_file(lock_path: Path) -> Iterator[None]:
    flags = os.O_CREAT | os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(lock_path, flags, 0o600)
    except OSError as error:
        raise ValueError("cannot open the skillset lock") from error
    locked = False
    active_error: BaseException | None = None
    try:
        try:
            lock_info = os.fstat(descriptor)
            if not stat.S_ISREG(lock_info.st_mode):
                raise ValueError("skillset lock must be a regular file")
            if os.name == "nt":
                import msvcrt

                if lock_info.st_size == 0:
                    os.write(descriptor, b"\0")
                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_LOCK, 1)
            else:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_EX)
        except OSError as error:
            raise ValueError("cannot acquire the skillset lock") from error
        locked = True
        yield
    except BaseException as error:
        active_error = error
        raise
    finally:
        cleanup_error: OSError | None = None
        try:
            if locked:
                if os.name == "nt":
                    os.lseek(descriptor, 0, os.SEEK_SET)
                    msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
        except OSError as error:
            cleanup_error = error
        try:
            os.close(descriptor)
        except OSError as error:
            if cleanup_error is None:
                cleanup_error = error
            else:
                cleanup_error.add_note(f"close also failed: {error}")
        if cleanup_error is not None:
            if active_error is not None:
                active_error.add_note(
                    f"skillset lock cleanup failed: {cleanup_error}"
                )
            else:
                raise ValueError(
                    "cannot release the skillset lock"
                ) from cleanup_error


@contextmanager
def _skillset_lock(target: Path) -> Iterator[None]:
    lock_root = _lock_directory()
    lock_keys = sorted(
        {
            hashlib.sha256(key).hexdigest()
            for key in _lock_target_keys(target)
        }
    )
    with ExitStack() as locks:
        for lock_key in lock_keys:
            locks.enter_context(
                _skillset_lock_file(
                    lock_root / f"{lock_key}.lock"
                )
            )
        yield


def _add_rollback_note(error: BaseException, message: str) -> None:
    error.add_note(f"rollback: {message}")


def _publish_symlink_exclusive(
    destination: Path,
    desired: Path,
    target_descriptor: int,
) -> LinkIdentity:
    try:
        os.symlink(
            desired,
            destination.name,
            target_is_directory=True,
            dir_fd=target_descriptor,
        )
    except FileExistsError as error:
        raise ValueError(
            f"approved target appeared during reconciliation: {destination}"
        ) from error
    return _link_identity_at(
        target_descriptor,
        destination.name,
        destination,
    )


def _restore_backup_exclusive(
    name: str,
    target: Path,
    target_descriptor: int,
    backup: Path,
    backup_descriptor: int,
    expected: LinkIdentity,
) -> bool:
    if _link_identity_at(backup_descriptor, name, backup) != expected:
        raise ValueError(
            f"backup changed during reconciliation: {backup}"
        )
    try:
        os.symlink(
            expected[3],
            name,
            target_is_directory=True,
            dir_fd=target_descriptor,
        )
    except FileExistsError:
        return False
    restored = _link_identity_at(
        target_descriptor,
        name,
        target / name,
    )
    if restored[3] != expected[3]:
        raise ValueError(
            f"restored target changed during reconciliation: {target / name}"
        )
    if _link_identity_at(backup_descriptor, name, backup) != expected:
        raise ValueError(
            f"backup changed during reconciliation: {backup}"
        )
    os.unlink(name, dir_fd=backup_descriptor)
    return True


def _replace_wrong_link(
    current: Path,
    target_descriptor: int,
    backup: Path,
    backup_descriptor: int,
    desired: Path,
    expected: LinkIdentity,
) -> LinkIdentity:
    if (
        _link_identity_at(
            target_descriptor,
            current.name,
            current,
        )
        != expected
    ):
        raise ValueError(
            f"approved target changed during reconciliation: {current}"
        )
    moved_identity: EntryIdentity | None = None
    try:
        os.replace(
            current.name,
            backup.name,
            src_dir_fd=target_descriptor,
            dst_dir_fd=backup_descriptor,
        )
        moved_identity = _entry_identity_at(
            backup_descriptor,
            backup.name,
            backup,
        )
        moved_link_identity = (
            None
            if not stat.S_ISLNK(moved_identity[2])
            else (
                moved_identity[0],
                moved_identity[1],
                moved_identity[2],
                moved_identity[5],
            )
        )
        if moved_link_identity != expected:
            raise ValueError(
                f"approved target changed during reconciliation: {current}"
            )
        return _publish_symlink_exclusive(
            current,
            desired,
            target_descriptor,
        )
    except BaseException as primary_error:
        if moved_identity is not None:
            try:
                backup_unchanged = (
                    _entry_identity_at(
                        backup_descriptor,
                        backup.name,
                        backup,
                    )
                    == moved_identity
                )
            except (OSError, ValueError):
                backup_unchanged = False
            if backup_unchanged and stat.S_ISLNK(moved_identity[2]):
                try:
                    restored = _restore_backup_exclusive(
                        current.name,
                        current.parent,
                        target_descriptor,
                        backup,
                        backup_descriptor,
                        (
                            moved_identity[0],
                            moved_identity[1],
                            moved_identity[2],
                            moved_identity[5],
                        ),
                    )
                except BaseException as rollback_error:
                    _add_rollback_note(
                        primary_error,
                        f"{rollback_error}; entry preserved at {backup}",
                    )
                else:
                    if not restored:
                        _add_rollback_note(
                            primary_error,
                            f"entry preserved at {backup}",
                        )
            elif backup_unchanged:
                _add_rollback_note(
                    primary_error,
                    f"entry preserved at {backup}",
                )
            else:
                _add_rollback_note(
                    primary_error,
                    f"backup preservation is ambiguous at {backup}",
                )
        raise


def _commit_link(
    name: str,
    target: Path,
    target_descriptor: int,
    desired: Path,
    backup: Path | None,
    backup_descriptor: int | None,
    expected: LinkIdentity | None,
    installed: dict[str, LinkIdentity],
) -> None:
    if backup is None:
        identity = _publish_symlink_exclusive(
            target / name,
            desired,
            target_descriptor,
        )
    else:
        if expected is None or backup_descriptor is None:
            raise ValueError(f"missing identity for replacement: {target / name}")
        identity = _replace_wrong_link(
            target / name,
            target_descriptor,
            backup / name,
            backup_descriptor,
            desired,
            expected,
        )
    installed[name] = identity


def _cleanup_workspace(
    workspace: Path,
    expected_identity: DirectoryIdentity,
) -> None:
    if _directory_identity(workspace, "workspace") != expected_identity:
        raise ValueError(
            f"workspace changed before cleanup: {workspace}"
        )
    cleanup_container = Path(
        tempfile.mkdtemp(
            prefix=".setup-skillset-cleanup-",
            dir=workspace.parent,
        )
    ).resolve(strict=True)
    cleanup_identity = _directory_identity(
        cleanup_container,
        "cleanup container",
    )
    cleanup_workspace = cleanup_container / "workspace"
    try:
        try:
            workspace.rename(cleanup_workspace)
        except OSError as error:
            raise ValueError(
                f"workspace changed before cleanup: {workspace}"
            ) from error
        try:
            moved_identity = _directory_identity(
                cleanup_workspace,
                "workspace",
            )
        except ValueError as error:
            raise ValueError(
                "workspace changed before cleanup; replacement preserved at "
                f"{cleanup_workspace}"
            ) from error
        if moved_identity != expected_identity:
            raise ValueError(
                "workspace changed before cleanup; replacement preserved at "
                f"{cleanup_workspace}"
            )
        shutil.rmtree(cleanup_workspace)
    finally:
        try:
            if (
                _directory_identity(
                    cleanup_container,
                    "cleanup container",
                )
                == cleanup_identity
            ):
                cleanup_container.rmdir()
        except (OSError, ValueError):
            pass


def _quarantine_installed_entry(
    name: str,
    target: Path,
    target_descriptor: int,
    rollback: Path,
    rollback_descriptor: int,
    expected: LinkIdentity,
) -> tuple[bool, bool]:
    if not _entry_exists_at(target_descriptor, name):
        return True, False
    try:
        current = _link_identity_at(
            target_descriptor,
            name,
            target / name,
        )
    except (OSError, ValueError):
        return False, False
    if current != expected:
        return False, False
    os.replace(
        name,
        name,
        src_dir_fd=target_descriptor,
        dst_dir_fd=rollback_descriptor,
    )
    moved = _entry_identity_at(
        rollback_descriptor,
        name,
        rollback / name,
    )
    moved_link = (
        None
        if not stat.S_ISLNK(moved[2])
        else (moved[0], moved[1], moved[2], moved[5])
    )
    return True, moved_link != expected


def reconcile(
    target: Path,
    sources: dict[str, Path],
    *,
    check: bool,
    approved_tree_sha256: dict[str, str] | None = None,
) -> dict[str, list[str]]:
    source_identities = validate_sources(sources)
    if approved_tree_sha256 is not None:
        _require_approved_tree_digests(source_identities, approved_tree_sha256)
    if check:
        return _reconcile_locked(
            target,
            sources,
            source_identities,
            check=True,
        )
    with _skillset_lock(target):
        _require_source_identities(sources, source_identities)
        return _reconcile_locked(
            target,
            sources,
            source_identities,
            check=False,
        )


def _reconcile_locked(
    target: Path,
    sources: dict[str, Path],
    source_identities: dict[str, SourceIdentity],
    *,
    check: bool,
) -> dict[str, list[str]]:
    result = {"created": [], "replaced": [], "missing": [], "wrong": []}
    target_descriptor: int | None = None
    backup_descriptor: int | None = None
    rollback_descriptor: int | None = None
    workspace: Path | None = None
    workspace_identity: DirectoryIdentity | None = None
    active_error: BaseException | None = None
    safe_to_cleanup = True

    try:
        try:
            target_info = target.lstat()
        except FileNotFoundError:
            target_info = None
        if target_info is not None and not stat.S_ISDIR(target_info.st_mode):
            raise ValueError(
                f"target must be a directory, not an existing entry: {target}"
            )

        target_created = target_info is None
        target_identity = (
            None
            if target_info is None
            else (target_info.st_dev, target_info.st_ino)
        )
        if target_identity is not None:
            target_descriptor, target_identity = _open_pinned_directory(
                target,
                "target directory",
                target_identity,
            )
            entries = set(os.listdir(target_descriptor))
            unexpected = sorted(entries - set(sources))
            if unexpected:
                raise ValueError(
                    "unexpected target entries: " + ", ".join(unexpected)
                )
            captured_entries = {
                name: _entry_identity_at(
                    target_descriptor,
                    name,
                    target / name,
                )
                for name in entries
            }
            obstructing = sorted(
                name
                for name, identity in captured_entries.items()
                if not stat.S_ISLNK(identity[2])
            )
            if obstructing:
                raise ValueError(
                    "approved target names must be symlinks: "
                    + ", ".join(obstructing)
                )
            entry_identities = captured_entries
        else:
            entries = set()
            entry_identities = {}

        desired = {
            name: identity.resolved
            for name, identity in source_identities.items()
        }
        missing = sorted(set(sources) - entries)
        wrong = sorted(
            name
            for name, identity in entry_identities.items()
            if identity[5] != str(desired[name])
        )

        created_parents: list[Path] = []
        workspace_parent = target.parent
        while True:
            try:
                workspace_parent_identity = _directory_identity(
                    workspace_parent,
                    "target ancestor",
                )
            except ValueError:
                try:
                    workspace_parent.lstat()
                except FileNotFoundError:
                    created_parents.append(workspace_parent)
                    workspace_parent = workspace_parent.parent
                    continue
                raise
            break

        protected_directories = {
            workspace_parent: workspace_parent_identity,
        }
        if check:
            result["missing"] = missing
            result["wrong"] = wrong
            _require_directory_identities(
                protected_directories,
                "target ancestor",
            )
            if target_identity is None:
                _require_paths_absent(
                    [target, *created_parents],
                    "target path",
                )
            else:
                assert target_descriptor is not None
                _revalidate_entries(
                    target,
                    target_identity,
                    target_descriptor,
                    entries,
                    entry_identities,
                )
            _require_source_identities(sources, source_identities)
            return result

        if not missing and not wrong:
            assert target_identity is not None
            assert target_descriptor is not None
            _require_directory_identities(
                protected_directories,
                "target ancestor",
            )
            _revalidate_entries(
                target,
                target_identity,
                target_descriptor,
                entries,
                entry_identities,
            )
            _require_source_identities(sources, source_identities)
            return result

        created_directories: dict[Path, DirectoryIdentity] = {}
        installed: dict[str, LinkIdentity] = {}
        _require_source_identities(sources, source_identities)
        _require_directory_identities(
            protected_directories,
            "target ancestor",
        )
        workspace = Path(
            tempfile.mkdtemp(
                prefix=".setup-skillset-",
                dir=workspace_parent,
            )
        ).resolve(strict=True)
        workspace_identity = _directory_identity(workspace, "workspace")
        _require_directory_identities(
            protected_directories,
            "target ancestor",
        )
        backups = workspace / "backups"
        rollback = workspace / "rollback"
        created_directory_backups = workspace / "created-directories"
        backups.mkdir()
        rollback.mkdir()
        created_directory_backups.mkdir()
        backup_descriptor, _ = _open_pinned_directory(
            backups,
            "backup directory",
        )
        rollback_descriptor, _ = _open_pinned_directory(
            rollback,
            "rollback directory",
        )

        try:
            for created_parent in reversed(created_parents):
                _require_directory_identities(
                    protected_directories,
                    "target ancestor",
                )
                try:
                    created_parent.mkdir()
                except FileExistsError as error:
                    raise ValueError(
                        "target parent appeared during reconciliation: "
                        f"{created_parent}"
                    ) from error
                identity = _directory_identity(
                    created_parent,
                    "target ancestor",
                )
                protected_directories[created_parent] = identity
                created_directories[created_parent] = identity
            if target_created:
                _require_directory_identities(
                    protected_directories,
                    "target ancestor",
                )
                try:
                    target.mkdir()
                except FileExistsError as error:
                    raise ValueError(
                        f"target appeared during reconciliation: {target}"
                    ) from error
                target_identity = _directory_identity(
                    target,
                    "target directory",
                )
                created_directories[target] = target_identity
                target_descriptor, target_identity = (
                    _open_pinned_directory(
                        target,
                        "target directory",
                        target_identity,
                    )
                )
            _require_directory_identities(
                protected_directories,
                "target ancestor",
            )
            assert target_identity is not None
            assert target_descriptor is not None
            _revalidate_entries(
                target,
                target_identity,
                target_descriptor,
                entries,
                entry_identities,
            )
            for name in wrong:
                _commit_link(
                    name,
                    target,
                    target_descriptor,
                    desired[name],
                    backups,
                    backup_descriptor,
                    _link_identity(entry_identities[name]),
                    installed,
                )
            for name in missing:
                _commit_link(
                    name,
                    target,
                    target_descriptor,
                    desired[name],
                    None,
                    None,
                    None,
                    installed,
                )
            _require_directory_identities(
                protected_directories,
                "target ancestor",
            )
            if (
                _directory_identity(target, "target directory")
                != target_identity
            ):
                raise ValueError(
                    f"target directory changed during reconciliation: {target}"
                )
            _require_target_entries(
                target_descriptor,
                target,
                sources,
            )
            for name, expected_target in desired.items():
                identity = _link_identity_at(
                    target_descriptor,
                    name,
                    target / name,
                )
                if identity[3] != str(expected_target):
                    raise ValueError(
                        "approved target changed during reconciliation: "
                        f"{target / name}"
                    )
            _require_source_identities(sources, source_identities)
        except BaseException as primary_error:
            active_error = primary_error
            if (
                target_descriptor is not None
                and rollback_descriptor is not None
            ):
                for name, identity in reversed(installed.items()):
                    try:
                        removed, preserved = (
                            _quarantine_installed_entry(
                                name,
                                target,
                                target_descriptor,
                                rollback,
                                rollback_descriptor,
                                identity,
                            )
                        )
                    except BaseException as rollback_error:
                        safe_to_cleanup = False
                        _add_rollback_note(
                            primary_error,
                            f"{rollback_error}",
                        )
                        continue
                    if preserved:
                        safe_to_cleanup = False
                        _add_rollback_note(
                            primary_error,
                            "concurrent entry preserved at "
                            f"{rollback / name}",
                        )
                    elif not removed:
                        safe_to_cleanup = False
                        _add_rollback_note(
                            primary_error,
                            "concurrent entry retained at "
                            f"{target / name}",
                        )
            if (
                target_descriptor is not None
                and backup_descriptor is not None
            ):
                for name in reversed(wrong):
                    if not _entry_exists_at(backup_descriptor, name):
                        continue
                    backup = backups / name
                    try:
                        restored = _restore_backup_exclusive(
                            name,
                            target,
                            target_descriptor,
                            backup,
                            backup_descriptor,
                            _link_identity(entry_identities[name]),
                        )
                    except BaseException as rollback_error:
                        safe_to_cleanup = False
                        _add_rollback_note(
                            primary_error,
                            f"{rollback_error}; entry preserved at {backup}",
                        )
                        continue
                    if not restored:
                        safe_to_cleanup = False
                        _add_rollback_note(
                            primary_error,
                            f"entry preserved at {backup}",
                        )
            if target_descriptor is not None:
                try:
                    os.close(target_descriptor)
                except BaseException as rollback_error:
                    safe_to_cleanup = False
                    _add_rollback_note(
                        primary_error,
                        f"{rollback_error}",
                    )
                target_descriptor = None
            for index, (directory, identity) in enumerate(
                reversed(created_directories.items())
            ):
                try:
                    current_info = directory.lstat()
                except FileNotFoundError:
                    continue
                if (
                    not stat.S_ISDIR(current_info.st_mode)
                    or (current_info.st_dev, current_info.st_ino)
                    != identity
                ):
                    safe_to_cleanup = False
                    _add_rollback_note(
                        primary_error,
                        f"concurrent entry retained at {directory}",
                    )
                    continue
                preserved = (
                    created_directory_backups / f"directory-{index}"
                )
                try:
                    directory.rename(preserved)
                except FileNotFoundError:
                    continue
                except OSError as rollback_error:
                    safe_to_cleanup = False
                    _add_rollback_note(
                        primary_error,
                        f"{rollback_error}; directory retained at {directory}",
                    )
                    continue
                try:
                    moved_identity = _directory_identity(
                        preserved,
                        "created directory",
                    )
                except ValueError:
                    safe_to_cleanup = False
                    _add_rollback_note(
                        primary_error,
                        f"concurrent entry preserved at {preserved}",
                    )
                    continue
                if moved_identity != identity:
                    safe_to_cleanup = False
                    _add_rollback_note(
                        primary_error,
                        f"concurrent directory preserved at {preserved}",
                    )
                    continue
                try:
                    preserved.rmdir()
                except OSError as rollback_error:
                    safe_to_cleanup = False
                    _add_rollback_note(
                        primary_error,
                        f"{rollback_error}; directory preserved at {preserved}",
                    )
            raise

        result["replaced"] = wrong
        result["created"] = missing
        return result
    except BaseException as error:
        active_error = error
        raise
    finally:
        for descriptor in (
            rollback_descriptor,
            backup_descriptor,
            target_descriptor,
        ):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except BaseException as close_error:
                    if active_error is not None:
                        _add_rollback_note(
                            active_error,
                            f"{close_error}",
                        )
        if (
            workspace is not None
            and workspace_identity is not None
            and safe_to_cleanup
        ):
            try:
                _cleanup_workspace(workspace, workspace_identity)
            except ValueError as cleanup_error:
                if active_error is not None:
                    _add_rollback_note(
                        active_error,
                        f"{cleanup_error}; workspace retained at {workspace}",
                    )
                else:
                    raise
            except BaseException as cleanup_error:
                if active_error is not None:
                    _add_rollback_note(
                        active_error,
                        f"{cleanup_error}; workspace cleanup failed at {workspace}",
                    )
                else:
                    print(
                        f"warning: workspace cleanup failed for {workspace}: "
                        f"{cleanup_error}",
                        file=sys.stderr,
                    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Install the curated CMTrace Open skillset as directory symlinks."
    )
    parser.add_argument("--check", action="store_true", help="report drift without changes")
    parser.add_argument("--home", type=Path, default=Path.home())
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--target", type=Path)
    return parser.parse_args()


def main() -> None:
    _require_supported_python(tuple(sys.version_info[:2]))
    args = parse_args()
    home = args.home.expanduser().resolve()
    repo = args.repo.expanduser().resolve()
    target = (
        Path(os.path.abspath(args.target.expanduser()))
        if args.target is not None
        else home / ".omp/agent/skillsets/cmtraceopen"
    )
    sources = resolve_sources(home, repo)

    try:
        result = reconcile(
            target,
            sources,
            check=args.check,
            approved_tree_sha256=APPROVED_SKILL_TREE_SHA256,
        )
    except ValueError as error:
        raise SystemExit(f"error: {error}") from error

    if args.check:
        drift = result["missing"] + result["wrong"]
        if drift:
            for name in result["missing"]:
                print(f"missing: {name}")
            for name in result["wrong"]:
                print(f"wrong: {name}")
            raise SystemExit(1)
        print(f"Skillset clean: {len(sources)} approved links; no drift.")
        return

    for name in result["created"]:
        print(f"created: {name}")
    for name in result["replaced"]:
        print(f"replaced: {name}")
    print(
        f"Skillset reconciled: {len(sources)} approved links; "
        f"{len(result['created'])} created, {len(result['replaced'])} replaced."
    )


if __name__ == "__main__":
    main()
