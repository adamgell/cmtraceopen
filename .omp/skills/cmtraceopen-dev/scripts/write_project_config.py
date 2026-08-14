from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import secrets
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
    selectors: dict[str, str] = {}
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
        )
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


def _existing_status(path: Path, proposed: bytes) -> str | None:
    try:
        existing = path.read_bytes()
    except FileNotFoundError:
        return None
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


def _same_inode(first: os.stat_result, second: os.stat_result) -> bool:
    return (first.st_dev, first.st_ino) == (second.st_dev, second.st_ino)


def _cleanup_staged_entry(
    directory_fd: int,
    temporary_name: str,
    staged_fd: int,
    output_name: str,
) -> None:
    quarantine_name = (
        f".{output_name}.cleanup.{secrets.token_hex(16)}.tmp"
    )
    try:
        os.rename(
            temporary_name,
            quarantine_name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
    except FileNotFoundError:
        return

    try:
        claimed_fd = os.open(
            quarantine_name,
            os.O_RDONLY | os.O_NOFOLLOW,
            dir_fd=directory_fd,
        )
    except OSError:
        return
    try:
        try:
            claimed_identity = os.fstat(claimed_fd)
            staged_identity = os.fstat(staged_fd)
        except OSError:
            return
        if _same_inode(claimed_identity, staged_identity):
            os.unlink(quarantine_name, dir_fd=directory_fd)
    finally:
        os.close(claimed_fd)


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
    existing_status = _existing_status(path, proposed)
    if existing_status is not None:
        return existing_status

    directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    lock_fd: int | None = None
    try:
        lock_fd = os.open(
            f".{path.name}.lock",
            os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory_fd,
        )
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        locked_status = _existing_status(path, proposed)
        if locked_status is not None:
            return locked_status

        while True:
            temporary_name = (
                f".{path.name}.{secrets.token_hex(16)}.tmp"
            )
            try:
                staged_fd = os.open(
                    temporary_name,
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=directory_fd,
                )
                break
            except FileExistsError:
                continue

        try:
            staged_identity = os.fstat(staged_fd)
            stream = os.fdopen(staged_fd, "wb", closefd=False)
            with stream:
                _write_staged(stream, proposed)
            try:
                os.link(
                    temporary_name,
                    path.name,
                    src_dir_fd=directory_fd,
                    dst_dir_fd=directory_fd,
                    follow_symlinks=False,
                )
            except FileExistsError:
                raced_status = _existing_status(path, proposed)
                if raced_status is None:
                    raise
                return raced_status

            installed_fd = os.open(
                path.name,
                os.O_RDONLY | os.O_NOFOLLOW,
                dir_fd=directory_fd,
            )
            try:
                installed_identity = os.fstat(installed_fd)
            finally:
                os.close(installed_fd)
            if not _same_inode(staged_identity, installed_identity):
                raise OSError("installed config does not match the staged inode")
            return "created"
        finally:
            try:
                _cleanup_staged_entry(
                    directory_fd,
                    temporary_name,
                    staged_fd,
                    path.name,
                )
            finally:
                os.close(staged_fd)
    finally:
        if lock_fd is not None:
            os.close(lock_fd)
        os.close(directory_fd)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
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
        status = write_create_only(output_path, render_config(selectors))
    except (OSError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 1
    print(json.dumps({"ok": True, "status": status}, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
