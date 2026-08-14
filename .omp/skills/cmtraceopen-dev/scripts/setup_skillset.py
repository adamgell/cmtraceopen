#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import tempfile


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


def resolve_sources(home: Path, repo: Path) -> dict[str, Path]:
    roots = {"home": home, "repo": repo}
    return {
        name: roots[root] / relative_path
        for name, (root, relative_path) in APPROVED_SKILLS.items()
    }


def validate_sources(sources: dict[str, Path]) -> None:
    errors: list[str] = []
    for name, source in sorted(sources.items()):
        if not source.is_dir():
            errors.append(f"{name}: source directory does not exist: {source}")
        elif not (source / "SKILL.md").is_file():
            errors.append(f"{name}: SKILL.md does not exist: {source / 'SKILL.md'}")
    if errors:
        raise ValueError("invalid skill sources:\n" + "\n".join(errors))


def reconcile(
    target: Path, sources: dict[str, Path], *, check: bool
) -> dict[str, list[str]]:
    validate_sources(sources)
    result = {"created": [], "replaced": [], "missing": [], "wrong": []}

    if target.is_symlink() or (target.exists() and not target.is_dir()):
        raise ValueError(f"target must be a directory, not an existing entry: {target}")

    if target.exists():
        entries = {entry.name: entry for entry in target.iterdir()}
        unexpected = sorted(set(entries) - set(sources))
        if unexpected:
            raise ValueError("unexpected target entries: " + ", ".join(unexpected))

        obstructing = sorted(
            name for name, entry in entries.items() if not entry.is_symlink()
        )
        if obstructing:
            raise ValueError(
                "approved target names must be symlinks: " + ", ".join(obstructing)
            )
    else:
        entries = {}

    desired = {name: source.resolve() for name, source in sources.items()}
    missing = sorted(set(sources) - set(entries))
    wrong = sorted(
        name
        for name, entry in entries.items()
        if entry.resolve(strict=False) != desired[name]
    )

    if check:
        result["missing"] = missing
        result["wrong"] = wrong
        return result

    if not missing and not wrong:
        return result

    target_created = not target.exists()
    created_parents: list[Path] = []
    parent = target.parent
    while not parent.exists() and not parent.is_symlink():
        created_parents.append(parent)
        parent = parent.parent

    workspace_parent = parent if parent.exists() else parent.parent
    workspace: Path | None = None
    safe_to_cleanup = True
    try:
        workspace = Path(
            tempfile.mkdtemp(prefix=".setup-skillset-", dir=workspace_parent)
        )
        staged = workspace / "staged"
        backups = workspace / "backups"
        staged.mkdir()
        backups.mkdir()
        for name in wrong + missing:
            (staged / name).symlink_to(desired[name], target_is_directory=True)

        target.parent.mkdir(parents=True, exist_ok=True)
        if target_created:
            target.mkdir()
        for name in wrong:
            os.replace(target / name, backups / name)
            os.replace(staged / name, target / name)
        for name in missing:
            os.replace(staged / name, target / name)
    except BaseException:
        try:
            for name in missing:
                created = target / name
                if created.is_symlink():
                    created.unlink()
            if workspace is not None:
                backups = workspace / "backups"
                for name in wrong:
                    backup = backups / name
                    if backup.is_symlink():
                        current = target / name
                        if current.is_symlink():
                            current.unlink()
                        os.replace(backup, current)
            if target_created and target.exists():
                target.rmdir()
            for created_parent in created_parents:
                if created_parent.exists():
                    created_parent.rmdir()
        except BaseException:
            safe_to_cleanup = False
            raise
        raise
    finally:
        if workspace is not None and safe_to_cleanup:
            try:
                shutil.rmtree(workspace)
            except BaseException:
                pass

    result["replaced"] = wrong
    result["created"] = missing
    return result


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
        result = reconcile(target, sources, check=args.check)
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

    print(f"Installed {len(sources)} approved skill links.")


if __name__ == "__main__":
    main()
