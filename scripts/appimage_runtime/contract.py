"""Fixed candidate and fail-closed observations for the manual runtime harness."""

import io
import os
import re
import stat
from pathlib import PurePosixPath

SOURCE = "ac7ad3862cf982a17a5ec761fa3891446c168a7f"
MERGE = "ab42494e2049e1df2275e08aec50a80b559d3c9b"
TREE = "1a2b9730a203bf18da216987acee79d439907363"
RUN = "37801602436"
ARTIFACT_ID = 11562044837
ARTIFACT_SHA256 = "381756ef4be7c209761c17b65a0c1c41b407f803cc66b1dea41043bf879cd466"
ARTIFACT_NAME = "CMTrace Open_1.6.3_amd64.AppImage"
CASES = ("ordinary", "catalog-renderer-subset")
CHECKS = ("fuse", "open", "find", "filter", "tail", "reopen", "exited")
REASONS = frozenset(("ok", "isolation-unavailable", "bubblewrap-unavailable",
                     "fuse-unavailable", "accessibility-unavailable", "gui-unavailable",
                     "application-exited", "ui-assertion", "timeout", "cancelled",
                     "evidence-invalid", "artifact-mismatch", "harness-error"))
STAGES = frozenset(("unobserved", "preflight", "launch", "open", "ready", "find-open-focus", "find-query",
                    "find-selection", "find-count", "filter", "clear-filter", "tail", "exit",
                    "relaunch", "reopen", "reopen-dialog", "reopen-location", "reopen-path", "reopen-submit", "reopen-count", "final-image", "complete"))
OBSERVATIONS = frozenset(("splash_absent", "window_active", "window_stable", "rows_match",
                          "find_button_visible", "find_input_unique", "find_input_focused",
                          "find_query_matches", "beta_selected", "find_scope_valid", "match_name", "match_text", "match_conflict",
                          "find_placeholder_present", "find_placeholder_unique", "find_placeholder_entry",
                          "find_placeholder_showing", "find_name_present", "find_entry_present",
                          "find_placeholder_tag_input", "find_placeholder_text_role",
                          "find_placeholder_editable", "find_placeholder_focused",
                          "error_os", "error_command", "error_value", "error_attribute", "error_type",
                          "error_atspi", "error_other", "scope_entries_unique", "scope_close_unique",
                          "scope_common_present", "scope_named_group", "status_unique", "scope_common_showing",
                          "scope_roles_valid", "scope_buttons_valid", "scope_inputs_valid", "reopen_chooser_in_app", "reopen_chooser_on_desktop", "reopen_path_matches", "reopen_location_unique", "reopen_open_unique"))


def diagnostics():
    return dict(stage="unobserved", elapsed_ms=0, observations={}, final_image="absent")


def sanitize_diagnostics(data):
    if not isinstance(data, dict) or set(data) != {"stage", "elapsed_ms", "observations", "final_image"}:
        raise ValueError("evidence-invalid")
    if data["stage"] not in STAGES or type(data["elapsed_ms"]) is not int or not 0 <= data["elapsed_ms"] <= 300000:
        raise ValueError("evidence-invalid")
    observations = data["observations"]
    if (not isinstance(observations, dict) or not set(observations) <= OBSERVATIONS
            or any(type(value) is not bool for value in observations.values())
            or data["final_image"] not in ("absent", "acceptance", "failure")):
        raise ValueError("evidence-invalid")
    return dict(data, observations=dict(observations))


def namespace_command(uid, gid, root):
    if uid <= 0 or gid <= 0 or not root.is_absolute():
        raise ValueError("isolation-unavailable")
    return ["/usr/bin/unshare", "--net", "--", "/usr/bin/setpriv",
            f"--reuid={uid}", f"--regid={gid}", "--clear-groups",
            "--inh-caps=-all", "--ambient-caps=-all", "/usr/bin/env", "-i",
            "PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C.UTF-8",
            "PYTHONDONTWRITEBYTECODE=1", f"HOME={root / 'home'}",
            "/usr/bin/python3", "-m", "appimage_runtime.session", str(root)]


def read_owned_file(path, uid, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_nlink != 1 or info.st_size > limit:
            raise ValueError("evidence-invalid")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            result = stream.read(limit + 1)
        if len(result) > limit:
            raise ValueError("evidence-invalid")
        return result
    finally:
        os.close(fd)


def sanitize_png(data):
    from PIL import Image
    try:
        if len(data) > 10 * 1024 * 1024:
            raise ValueError("evidence-invalid")
        with Image.open(io.BytesIO(data)) as original:
            if original.format != "PNG" or not (0 < original.width <= 1280 and 0 < original.height <= 900):
                raise ValueError("evidence-invalid")
            original.load()
            clean = Image.new("RGB", original.size)
            clean.paste(original.convert("RGB"))
            output = io.BytesIO()
            clean.save(output, format="PNG")
            return output.getvalue()
    except Exception as error:
        raise ValueError("evidence-invalid") from error


def validate_binding(report, digest):
    build = report["build"]
    actual = (build["source_commit"], build["built_commit"], build["built_tree"],
              build["image"]["GITHUB_RUN_ID"], build["image"]["GITHUB_RUN_ATTEMPT"],
              report["inspection"]["sha256"], digest)
    if actual != (SOURCE, MERGE, TREE, RUN, "1", ARTIFACT_SHA256, ARTIFACT_SHA256):
        raise ValueError("artifact-mismatch")


def validate_identity(status, uid, gid, host_ns, current_ns, links, routes):
    if uid <= 0 or gid <= 0:
        raise ValueError("isolation-unavailable")
    for name, expected in (("Uid", uid), ("Gid", gid)):
        if list(map(int, status[name].split())) != [expected] * 4:
            raise ValueError("isolation-unavailable")
    if status["Groups"].strip() or status["NoNewPrivs"].strip() != "0":
        raise ValueError("isolation-unavailable")
    if any(int(status[name], 16) for name in ("CapInh", "CapPrm", "CapEff", "CapAmb")):
        raise ValueError("isolation-unavailable")
    if current_ns["net"] == host_ns["net"] or any(current_ns[k] != host_ns[k] for k in ("mnt", "pid", "user")):
        raise ValueError("isolation-unavailable")
    if len(links) != 1 or links[0]["ifname"] != "lo" or "UP" in links[0]["flags"] or routes:
        raise ValueError("isolation-unavailable")


def fuse_mount(mountinfo, executable):
    executable = PurePosixPath(executable)
    matches = []
    for line in mountinfo.splitlines():
        before, separator, after = line.partition(" - ")
        if not separator:
            raise ValueError("fuse-unavailable")
        fields, filesystem = before.split(), after.split()[0]
        mount = PurePosixPath(re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), fields[4]))
        if (filesystem == "fuse" or filesystem.startswith("fuse.")) and "ro" in fields[5].split(","):
            if executable == mount / "usr/bin/cmtrace-open":
                matches.append(str(mount))
    if len(matches) != 1:
        raise ValueError("fuse-unavailable")
    return matches[0]


def descendant_pids(parents, root):
    found = {root}
    while True:
        expanded = found | {pid for pid, parent in parents.items() if parent in found}
        if expanded == found:
            return found
        found = expanded


def validate_rows(rows, expected):
    if len(rows) != len(expected) or len(set(expected)) != len(expected):
        raise ValueError("ui-assertion")
    observed = []
    for row in rows:
        tokens = set(re.findall(r"\bJAMMY_[A-Z0-9_]+\b", row["text"]))
        if row["role"] != "option" or len(tokens) != 1:
            raise ValueError("ui-assertion")
        observed.extend(tokens)
    if sorted(observed) != sorted(expected):
        raise ValueError("ui-assertion")


def sanitize_case(data):
    if set(data) != {"case", "status", "reason", "checks", "counts", "diagnostics"}:
        raise ValueError("evidence-invalid")
    if data["case"] not in CASES or data["status"] not in ("passed", "blocked", "failed") or data["reason"] not in REASONS:
        raise ValueError("evidence-invalid")
    checks, counts = data["checks"], data["counts"]
    if not isinstance(checks, dict) or not set(checks) <= set(CHECKS) or any(type(v) is not bool for v in checks.values()):
        raise ValueError("evidence-invalid")
    if not isinstance(counts, list) or any(type(v) is not int for v in counts) or counts != [3, 1, 3, 4, 4][:len(counts)] or len(counts) > 5:
        raise ValueError("evidence-invalid")
    if data["status"] == "passed" and (data["reason"] != "ok" or checks != dict.fromkeys(CHECKS, True) or counts != [3, 1, 3, 4, 4]):
        raise ValueError("evidence-invalid")
    if data["status"] != "passed" and data["reason"] == "ok":
        raise ValueError("evidence-invalid")
    diagnostic = sanitize_diagnostics(data["diagnostics"])
    if data["status"] == "passed" and (diagnostic["stage"] != "complete" or diagnostic["final_image"] != "acceptance"):
        raise ValueError("evidence-invalid")
    if data["status"] != "passed" and diagnostic["final_image"] == "acceptance":
        raise ValueError("evidence-invalid")
    return dict(case=data["case"], status=data["status"], reason=data["reason"], checks=dict(checks), counts=list(counts), diagnostics=diagnostic)


def validate_payload(payload):
    if set(payload) != {"AppRun", "AppRun.wrapped", "usr/bin/cmtrace-open"}:
        raise ValueError("fuse-unavailable")
    for item in payload.values():
        if item != dict(mode=stat.S_IFREG | 0o755, uid=0, gid=0):
            raise ValueError("fuse-unavailable")


def sanitize_fuse(proofs, passed):
    if not isinstance(proofs, list) or len(proofs) > 2 or (passed and len(proofs) != 2):
        raise ValueError("evidence-invalid")
    result = []
    for item in proofs:
        if set(item) != {"pid", "mount_id", "filesystem", "payload_root_0755"}:
            raise ValueError("evidence-invalid")
        if any(type(item[k]) is not int or not 0 < item[k] < 2**31 for k in ("pid", "mount_id")):
            raise ValueError("evidence-invalid")
        if not re.fullmatch(r"fuse(?:\.[A-Za-z0-9_.-]{1,100})?", item["filesystem"]) or item["payload_root_0755"] is not True:
            raise ValueError("evidence-invalid")
        result.append(dict(item))
    return result


def accessible_role(role, attributes):
    for attribute in attributes:
        if attribute in ("xml-roles:listbox", "xml-roles:option", "xml-roles:group", "xml-roles:status"):
            return attribute.split(":", 1)[1]
    return {"list box": "listbox", "list item": "option"}.get(role, role)


def fuse_metadata(mountinfo, executable):
    mount = fuse_mount(mountinfo, executable)
    for line in mountinfo.splitlines():
        before, _, after = line.partition(" - ")
        fields = before.split()
        decoded = re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), fields[4])
        filesystem = after.split()[0]
        if decoded == mount and (filesystem == "fuse" or filesystem.startswith("fuse.")):
            return dict(mount_id=int(fields[0]), filesystem=filesystem)
    raise ValueError("fuse-unavailable")


def owned_fuse_mounts(mountinfo, uid, root):
    if uid <= 0 or not root.is_absolute():
        raise ValueError("harness-error")
    mounts = []
    for line in mountinfo.splitlines():
        before, _, after = line.partition(" - ")
        mount = PurePosixPath(re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), before.split()[4]))
        if not mount.is_relative_to(root):
            continue
        fields = after.split()
        if not (fields[0] == "fuse" or fields[0].startswith("fuse.")) or f"user_id={uid}" not in fields[2].split(","):
            raise ValueError("harness-error")
        mounts.append(str(mount))
    return sorted(mounts, key=lambda path: len(PurePosixPath(path).parts), reverse=True)


def unmount_command(uid, gid, mount):
    if uid <= 0 or gid <= 0 or not PurePosixPath(mount).is_absolute():
        raise ValueError("harness-error")
    return ["/usr/bin/setpriv", f"--reuid={uid}", f"--regid={gid}", "--clear-groups",
            "--inh-caps=-all", "--ambient-caps=-all", "/usr/bin/env", "-i",
            "PATH=/usr/bin:/bin:/usr/sbin:/sbin", "/usr/bin/fusermount3", "-u", "--", mount]
