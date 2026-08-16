from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import subprocess
import sys
from typing import NoReturn


ROLE_NAMES = ("reasoning", "mid", "scaffold", "advisor")
_GATEWAY_ONLY_ROLES = {"mid", "scaffold"}
_SOL_PROMOTION_SELECTOR = "openai-codex/gpt-5.6-sol"


def _fail(message: str) -> NoReturn:
    raise ValueError(message)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _fail(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_non_json_number(value: str) -> NoReturn:
    _fail(f"invalid JSON number: {value}")


def _read_json_object(path: Path) -> dict[str, object]:
    try:
        text = path.read_text(encoding="utf-8")
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_non_json_number,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read valid JSON from {path}: {error}") from error
    if not isinstance(value, dict):
        _fail(f"JSON root must be an object: {path}")
    return value


def _required_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        _fail(f"missing or invalid {label}")
    return value


def _validate_selector_policy(
    role: str, selector: str, promotion_reason: object
) -> None:
    if role in _GATEWAY_ONLY_ROLES:
        if not selector.startswith("llmgateway/"):
            _fail(f"{role} must use a validated llmgateway selector")
        if promotion_reason is not None:
            _fail(f"{role} cannot record a Sol safety promotion")
        return

    if selector.startswith("llmgateway/"):
        if promotion_reason is not None:
            _fail(f"gateway {role} must not record a promotion reason")
        return
    if selector != _SOL_PROMOTION_SELECTOR:
        _fail(f"{role} selector violates the recorded Sol-promotion contract")
    if not isinstance(promotion_reason, str) or not promotion_reason.strip():
        _fail(f"promoted {role} must name the failed gateway evidence")


def _stat_signature(info: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _artifact_snapshot(
    path: Path,
) -> tuple[
    tuple[int, int, int, int, int, int],
    tuple[int, int, int, int, int, int],
    str,
]:
    try:
        link_before = path.lstat()
        if not stat.S_ISREG(link_before.st_mode):
            _fail(f"probe artifact must be a regular file: {path}")
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            file_before = os.fstat(stream.fileno())
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
            file_after = os.fstat(stream.fileno())
        link_after = path.lstat()
        target_after = path.stat()
    except OSError as error:
        raise ValueError(f"cannot snapshot probe artifact {path}: {error}") from error

    link_signature = _stat_signature(link_before)
    file_signature = _stat_signature(file_before)
    if (
        link_signature != _stat_signature(link_after)
        or file_signature != _stat_signature(file_after)
        or file_signature != _stat_signature(target_after)
    ):
        _fail(f"probe artifact changed while snapshotting: {path}")
    return link_signature, file_signature, digest.hexdigest()


def validate_role_report(report_path: Path, repo_root: Path) -> dict[str, str]:
    report = _read_json_object(report_path)
    if type(report.get("schemaVersion")) is not int or report["schemaVersion"] != 1:
        _fail("role report schemaVersion must be integer 1")
    if report.get("primaryProvider") != "llmgateway":
        _fail("role report primaryProvider must be llmgateway")

    roles = report.get("roles")
    if not isinstance(roles, dict) or set(roles) != set(ROLE_NAMES):
        _fail("role report must contain exactly reasoning, mid, scaffold, and advisor")

    validator_path = (
        repo_root
        / ".omp"
        / "skills"
        / "cmtraceopen-dev"
        / "scripts"
        / "validate_model_probe.py"
    )
    thresholds_path = (
        repo_root
        / ".omp"
        / "skills"
        / "cmtraceopen-dev"
        / "references"
        / "model-role-thresholds.json"
    )
    role_inputs: list[
        tuple[str, str, str, str, Path, Path, dict[str, object]]
    ] = []
    for role in ROLE_NAMES:
        role_record = roles[role]
        if not isinstance(role_record, dict):
            _fail(f"role report entry must be an object: {role}")
        selector = _required_string(role_record.get("selector"), f"{role}.selector")
        provider = _required_string(role_record.get("provider"), f"{role}.provider")
        api = _required_string(role_record.get("api"), f"{role}.api")
        discovery = Path(
            _required_string(
                role_record.get("discoveryArtifact"), f"{role}.discoveryArtifact"
            )
        )
        artifact = Path(
            _required_string(role_record.get("artifact"), f"{role}.artifact")
        )
        if not discovery.is_absolute() or not artifact.is_absolute():
            _fail(f"{role} probe artifact paths must be absolute")
        recorded_evidence = role_record.get("evidence")
        if not isinstance(recorded_evidence, dict):
            _fail(f"{role}.evidence must be an object")
        _validate_selector_policy(role, selector, role_record.get("promotionReason"))
        role_inputs.append(
            (
                role,
                selector,
                provider,
                api,
                discovery,
                artifact,
                recorded_evidence,
            )
        )
    reported_selectors = {
        role: selector
        for role, selector, *_ in role_inputs
    }
    if reported_selectors["advisor"] != reported_selectors["reasoning"]:
        _fail("advisor selector must equal reasoning selector")

    artifact_paths = tuple(
        dict.fromkeys(
            artifact_path
            for role_input in role_inputs
            for artifact_path in role_input[4:6]
        )
    )
    artifact_snapshots = {
        artifact_path: _artifact_snapshot(artifact_path)
        for artifact_path in artifact_paths
    }

    selectors: dict[str, str] = {}
    for (
        role,
        selector,
        provider,
        api,
        discovery,
        artifact,
        recorded_evidence,
    ) in role_inputs:
        try:
            completed = subprocess.run(
                [
                    sys.executable,
                    str(validator_path),
                    "--discovery",
                    str(discovery),
                    "--artifact",
                    str(artifact),
                    "--thresholds",
                    str(thresholds_path),
                    "--selector",
                    selector,
                    "--role",
                    role,
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=60,
            )
        except subprocess.TimeoutExpired as error:
            raise ValueError(f"probe validation timed out for {role}") from error
        if completed.returncode != 0:
            detail = completed.stderr.strip() or f"exit {completed.returncode}"
            _fail(f"probe validation failed for {role}: {detail}")
        try:
            observed = json.loads(
                completed.stdout,
                object_pairs_hook=_unique_object,
                parse_constant=_reject_non_json_number,
            )
        except json.JSONDecodeError as error:
            raise ValueError(
                f"probe validator returned malformed JSON for {role}: {error}"
            ) from error
        if not isinstance(observed, dict) or observed != recorded_evidence:
            _fail(f"probe evidence mismatch for {role}")
        if provider != observed.get("provider") or api != observed.get("api"):
            _fail(f"provider/API mismatch for {role}")
        selectors[role] = selector

    if artifact_snapshots != {
        artifact_path: _artifact_snapshot(artifact_path)
        for artifact_path in artifact_paths
    }:
        _fail("probe artifacts changed during role validation")
    return selectors


def render_config(selectors: dict[str, str]) -> str:
    if set(selectors) != set(ROLE_NAMES):
        _fail("selectors must contain exactly reasoning, mid, scaffold, and advisor")
    quoted = {
        role: json.dumps(_required_string(selectors[role], f"{role} selector"))
        for role in ROLE_NAMES
    }
    return f'''modelRoles:
  reasoning: {quoted["reasoning"]}
  mid: {quoted["mid"]}
  scaffold: {quoted["scaffold"]}
  advisor: {quoted["advisor"]}

advisor:
  enabled: true
  syncBacklog: 1
  immuneTurns: 3

retry:
  modelFallback: false

async:
  enabled: true

memory:
  backend: local

lsp:
  enabled: true

skills:
  enabled: true
  enableSkillCommands: true
  enableClaudeUser: false
  enableClaudeProject: true
  enableAgentsUser: true
  enableAgentsProject: true
  customDirectories:
    - ~/.omp/agent/skillsets/cmtraceopen

task:
  batch: true
  eager: preferred
  enableLsp: true
  maxConcurrency: 6
  maxRecursionDepth: 1
  showResolvedModelBadge: true
  isolation:
    mode: auto
    apply: false
    merge: branch
    commits: generic
'''


def _existing_bytes_status(existing: bytes, proposed: bytes) -> str:
    if existing == proposed:
        return "unchanged"
    raise ValueError(
        json.dumps(
            {
                "ok": False,
                "classification": "existing_config_differs",
                "existingSha256": hashlib.sha256(existing).hexdigest(),
                "proposedSha256": hashlib.sha256(proposed).hexdigest(),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )


def _existing_status_at(
    parent_descriptor: int, name: str, proposed: bytes
) -> str | None:
    try:
        before = os.stat(
            name, dir_fd=parent_descriptor, follow_symlinks=False
        )
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(before.st_mode):
        _fail(f"existing config output must be a regular file: {name}")

    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(
            name,
            flags,
            dir_fd=parent_descriptor,
        )
    except OSError as error:
        raise ValueError(
            f"config output changed during inspection: {name}"
        ) from error

    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _stat_signature(opened) != _stat_signature(before)
        ):
            _fail(f"config output changed during inspection: {name}")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            existing = stream.read()
            after_read = os.fstat(stream.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)

    try:
        after_path = os.stat(
            name, dir_fd=parent_descriptor, follow_symlinks=False
        )
    except OSError as error:
        raise ValueError(
            f"config output changed during inspection: {name}"
        ) from error
    if (
        _stat_signature(after_read) != _stat_signature(opened)
        or _stat_signature(after_path) != _stat_signature(opened)
    ):
        _fail(f"config output changed during inspection: {name}")
    return _existing_bytes_status(existing, proposed)


def _open_pinned_directory(path: Path) -> int:
    before = path.lstat()
    if not stat.S_ISDIR(before.st_mode):
        _fail(f"parent must be an existing non-symlink directory: {path}")
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        after = path.lstat()
        expected = (before.st_dev, before.st_ino)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or not stat.S_ISDIR(after.st_mode)
            or (opened.st_dev, opened.st_ino) != expected
            or (after.st_dev, after.st_ino) != expected
        ):
            _fail(f"parent directory changed while pinning: {path}")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _require_pinned_directory(path: Path, descriptor: int) -> None:
    try:
        current = path.lstat()
        pinned = os.fstat(descriptor)
    except OSError as error:
        raise ValueError(f"parent directory changed: {path}") from error
    if (
        not stat.S_ISDIR(current.st_mode)
        or not stat.S_ISDIR(pinned.st_mode)
        or (current.st_dev, current.st_ino) != (pinned.st_dev, pinned.st_ino)
    ):
        _fail(f"parent directory changed: {path}")


def check_exact(path: Path, content: str) -> str:
    parent_descriptor = _open_pinned_directory(path.parent)
    try:
        status = _existing_status_at(
            parent_descriptor, path.name, content.encode("utf-8")
        )
        if status is None:
            _fail(f"qualified project config is missing: {path}")
        _require_pinned_directory(path.parent, parent_descriptor)
        return status
    finally:
        os.close(parent_descriptor)


def _write_staged(stream: object, proposed: bytes) -> None:
    remaining = memoryview(proposed)
    while remaining:
        written = stream.write(remaining)
        if not written:
            raise OSError("staged config write made no progress")
        remaining = remaining[written:]
    stream.flush()
    os.fsync(stream.fileno())


def write_create_only(path: Path, content: str) -> str:
    proposed = content.encode("utf-8")
    parent_descriptor = _open_pinned_directory(path.parent)
    descriptor = -1
    temporary_name: str | None = None
    try:
        existing_status = _existing_status_at(
            parent_descriptor, path.name, proposed
        )
        if existing_status is not None:
            _require_pinned_directory(path.parent, parent_descriptor)
            return existing_status

        for _ in range(16):
            temporary_name = f".{path.name}.{secrets.token_hex(16)}.tmp"
            try:
                descriptor = os.open(
                    temporary_name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                    dir_fd=parent_descriptor,
                )
                break
            except FileExistsError:
                temporary_name = None
        else:
            raise OSError("cannot allocate staged config path")

        stream = os.fdopen(descriptor, "wb")
        descriptor = -1
        with stream:
            _write_staged(stream, proposed)
        try:
            # Both names are resolved in the captured parent directory.
            os.link(
                temporary_name,
                path.name,
                src_dir_fd=parent_descriptor,
                dst_dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except FileExistsError:
            raced_status = _existing_status_at(
                parent_descriptor, path.name, proposed
            )
            if raced_status is None:
                raise
            _require_pinned_directory(path.parent, parent_descriptor)
            return raced_status
        except (NotImplementedError, TypeError) as error:
            raise ValueError(
                "platform cannot atomically publish config"
            ) from error
        except OSError as error:
            unsupported = {
                value
                for name in ("ENOSYS", "ENOTSUP", "EOPNOTSUPP")
                if (value := getattr(errno, name, None)) is not None
            }
            if error.errno in unsupported:
                raise ValueError(
                    "platform cannot atomically publish config"
                ) from error
            raise
        os.fsync(parent_descriptor)
        _require_pinned_directory(path.parent, parent_descriptor)
        return "created"
    finally:
        try:
            if descriptor >= 0:
                os.close(descriptor)
        finally:
            try:
                if temporary_name is not None:
                    try:
                        os.unlink(temporary_name, dir_fd=parent_descriptor)
                    except FileNotFoundError:
                        pass
            finally:
                os.close(parent_descriptor)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--check", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    repo_root = args.repo_root.expanduser().absolute()
    report_path = args.report.expanduser()
    output_path = args.output.expanduser()
    if not output_path.is_absolute():
        output_path = repo_root / output_path
    try:
        selectors = validate_role_report(report_path, repo_root)
        rendered = render_config(selectors)
        status = (
            check_exact(output_path, rendered)
            if args.check
            else write_create_only(output_path, rendered)
        )
    except (OSError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 1
    print(json.dumps({"ok": True, "status": status}, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
