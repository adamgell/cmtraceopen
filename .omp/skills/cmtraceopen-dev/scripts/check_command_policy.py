#!/usr/bin/env python3
from __future__ import annotations

from typing import NoReturn, Sequence, cast


_ALLOWED_CARGO_SUBCOMMANDS = frozenset({"check", "clippy", "fmt", "test"})
_ALLOWED_NPM_SCRIPTS = frozenset(
    {
        "app:build:debug",
        "app:build:exe-only",
        "app:build:lite",
        "app:build:release",
        "build",
        "frontend:build",
        "test",
        "test:coverage",
        "test:e2e",
    }
)


def _reject(reason: str) -> NoReturn:
    raise ValueError(f"repository check policy rejects command: {reason}")


def _is_control_free(argument: str) -> bool:
    return not any(
        ord(character) < 0x20 or 0x7F <= ord(character) <= 0x9F
        for character in argument
    )


def _is_repo_relative_path(argument: str) -> bool:
    if not argument or argument.startswith(("/", "\\")) or "\\" in argument:
        return False
    parts = argument.split("/")
    return all(part not in {"", ".."} for part in parts)


def _contains_external_path(argument: str) -> bool:
    candidate = argument.split("=", 1)[-1]
    return candidate.startswith(("/", "\\")) or ".." in candidate.split("/")


def _validate_python(argv: tuple[str, ...]) -> None:
    if len(argv) < 4 or argv[1:3] != ("-m", "unittest"):
        _reject("python3 is limited to unittest module or discover invocations")
    unittest_arguments = argv[3:]
    if unittest_arguments[0] != "discover":
        if not any(not argument.startswith("-") for argument in unittest_arguments):
            _reject("unittest module invocation must name a test module or path")
        for argument in unittest_arguments:
            if argument.startswith(("/", "\\")) or ".." in argument.split("/"):
                _reject("unittest targets must be repository-relative")
        return

    positional: list[str] = []
    index = 1
    while index < len(unittest_arguments):
        argument = unittest_arguments[index]
        if argument in {"-s", "--start-directory", "-t", "--top-level-directory"}:
            index += 1
            if index >= len(unittest_arguments) or not _is_repo_relative_path(
                unittest_arguments[index]
            ):
                _reject("unittest discovery roots must be repository-relative")
        elif argument.startswith(("--start-directory=", "--top-level-directory=")):
            _, value = argument.split("=", 1)
            if not _is_repo_relative_path(value):
                _reject("unittest discovery roots must be repository-relative")
        elif argument in {"-p", "--pattern", "-k", "--durations"}:
            index += 1
            if index >= len(unittest_arguments):
                _reject("unittest discovery option requires a value")
        elif argument.startswith(("--pattern=", "-k=", "--durations=")):
            if not argument.split("=", 1)[1]:
                _reject("unittest discovery option requires a value")
        elif argument in {
            "-b",
            "--buffer",
            "-c",
            "--catch",
            "-f",
            "--failfast",
            "--locals",
            "-q",
            "--quiet",
            "-v",
            "--verbose",
        }:
            pass
        elif argument.startswith("-"):
            _reject("unittest discovery contains an unsupported option")
        else:
            positional.append(argument)
        index += 1

    if len(positional) > 3:
        _reject("unittest discover accepts at most three positional arguments")
    for root_index in (0, 2):
        if root_index < len(positional) and not _is_repo_relative_path(
            positional[root_index]
        ):
            _reject("unittest discovery roots must be repository-relative")


def _validate_cargo(argv: tuple[str, ...]) -> None:
    if len(argv) < 2 or argv[1] not in _ALLOWED_CARGO_SUBCOMMANDS:
        _reject("cargo subcommand is not an approved check")
    arguments = argv[2:]
    forbidden_options = {
        "--allow-dirty",
        "--allow-staged",
        "--config",
        "--fix",
        "--manifest-path",
        "--target-dir",
    }
    if any(
        argument in forbidden_options
        or argument.startswith("--config=")
        or argument.startswith("--manifest-path=")
        or argument.startswith("--target-dir=")
        for argument in arguments
    ):
        _reject("cargo command contains a mutating or external-config option")
    if argv[1] == "fmt" and "--check" not in arguments:
        _reject("cargo fmt is allowed only with check semantics")


def _validate_npm(argv: tuple[str, ...]) -> None:
    if len(argv) >= 2 and argv[1] == "test":
        first_forwarded = 2
    elif len(argv) >= 3 and argv[1] == "run" and argv[2] in _ALLOWED_NPM_SCRIPTS:
        first_forwarded = 3
    else:
        _reject("npm command is not a checked-in noninteractive test or build script")
    if len(argv) > first_forwarded and argv[first_forwarded] != "--":
        _reject("npm script arguments must follow the explicit -- separator")
    if any(_contains_external_path(argument) for argument in argv[first_forwarded + 1 :]):
        _reject("npm script arguments must not select paths outside the repository")


def _validate_mdbook(argv: tuple[str, ...]) -> None:
    if len(argv) not in {2, 3} or argv[1] not in {"build", "test"}:
        _reject("mdbook is limited to build or test")
    if len(argv) == 3 and not _is_repo_relative_path(argv[2]):
        _reject("mdbook book path must be repository-relative")


def _validate_git(argv: tuple[str, ...]) -> None:
    arguments = argv[1:]
    fixed_forms = {
        ("rev-parse", "--show-toplevel"),
        ("rev-parse", "--git-common-dir"),
        ("rev-parse", "--path-format=absolute", "--git-common-dir"),
        ("ls-files", "--stage", "-z"),
    }
    if arguments in fixed_forms:
        return
    if arguments[:2] == ("diff", "--check"):
        remainder = arguments[2:]
        if not remainder:
            return
        if remainder[0] != "--":
            _reject("git diff --check paths require the explicit -- separator")
        path_arguments = remainder[1:]
    elif arguments[:5] == ("diff", "--binary", "--no-ext-diff", "HEAD", "--"):
        path_arguments = arguments[5:]
    else:
        _reject("git command is not a named read-only verification form")
    if any(not _is_repo_relative_path(argument) for argument in path_arguments):
        _reject("git verification paths must be repository-relative")


def validate_check_command(argv: Sequence[object]) -> tuple[str, ...]:
    if isinstance(argv, (str, bytes)):
        _reject("command must be an argument vector")
    command = tuple(argv)
    if not 1 <= len(command) <= 128:
        _reject("command must contain 1 to 128 arguments")
    for index, argument in enumerate(command):
        if (
            not isinstance(argument, str)
            or not argument
            or len(argument) > 4096
            or not _is_control_free(argument)
        ):
            _reject(
                f"argument {index} must be a bounded nonempty control-free string"
            )
    checked_command = cast(tuple[str, ...], command)
    executable = checked_command[0]
    validators = {
        "cargo": _validate_cargo,
        "git": _validate_git,
        "mdbook": _validate_mdbook,
        "npm": _validate_npm,
        "python3": _validate_python,
    }
    validator = validators.get(executable)
    if validator is None:
        _reject(f"executable {executable!r} is not approved")
    validator(checked_command)
    return checked_command
