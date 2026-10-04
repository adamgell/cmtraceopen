"""Fixed candidate and fail-closed observations for the manual runtime harness."""

import re
from pathlib import PurePosixPath

SOURCE = "0a1bb21add1e7d331d4f4e2a00be8c317240bebf"
MERGE = "9433d28d28db986c0a2204b22cf20a7643d7f3df"
TREE = "5481bee5fc7f503b075ed6501bc9556db65de76e"
RUN = "37222916777"
ARTIFACT_ID = 11311507149
ARTIFACT_SHA256 = "fe80fa10c11b0dbd16198579169a08e4f2ed5ab5e72da876c3ec0197153b9873"
ARTIFACT_NAME = "CMTrace Open_1.6.0_amd64.AppImage"
CASES = ("ordinary", "catalog-renderer-subset")
CHECKS = ("fuse", "open", "find", "filter", "tail", "reopen", "exited")
REASONS = frozenset(("ok", "isolation-unavailable", "bubblewrap-unavailable",
                     "fuse-unavailable", "accessibility-unavailable", "gui-unavailable",
                     "application-exited", "ui-assertion", "timeout", "cancelled",
                     "evidence-invalid", "artifact-mismatch", "harness-error"))


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
    if set(data) != {"case", "status", "reason", "checks", "counts"}:
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
    return {"case": data["case"], "status": data["status"], "reason": data["reason"], "checks": dict(checks), "counts": list(counts)}
