"""Read-only bubblewrap diagnostics; never change policy or relax its gate."""

import errno
import os
from pathlib import Path
import select
import stat
import subprocess
import time

STDERR_LIMIT = 4096
POLICY_INTS = {"apparmor_restrict_unprivileged_userns": 1, "unprivileged_userns_clone": 1,
               "max_user_namespaces": 2**31 - 1, "bwrap_mode": 0o7777,
               "bwrap_uid": 2**32 - 1, "bwrap_gid": 2**32 - 1}
ERRORS = frozenset(("ok", "namespace-denied", "mount-denied", "other", "signal", "timeout", "spawn-error"))


def unknown_policy():
    return dict.fromkeys(POLICY_INTS) | dict(apparmor_enabled=None, current_label="unknown", bwrap_file_caps=None)


def read_small(path):
    try:
        with Path(path).open("rb") as stream:
            value = stream.read(1025)
        return value.decode("utf-8").strip() if len(value) <= 1024 else None
    except (OSError, UnicodeError):
        return None


def read_policy():
    policy = unknown_policy()
    for key, path in (("apparmor_restrict_unprivileged_userns", "/proc/sys/kernel/apparmor_restrict_unprivileged_userns"),
                      ("unprivileged_userns_clone", "/proc/sys/kernel/unprivileged_userns_clone"),
                      ("max_user_namespaces", "/proc/sys/user/max_user_namespaces")):
        value = read_small(path)
        if value is not None and value.isdecimal() and 0 <= int(value) <= POLICY_INTS[key]:
            policy[key] = int(value)
    enabled = read_small("/sys/module/apparmor/parameters/enabled")
    if enabled in ("Y", "N"):
        policy["apparmor_enabled"] = enabled == "Y"
    label = read_small("/proc/self/attr/current")
    if label == "unconfined":
        policy["current_label"] = "unconfined"
    elif label and label.endswith((" (enforce)", " (complain)")):
        policy["current_label"] = "confined"
    try:
        info = os.stat("/usr/bin/bwrap")
        policy.update(bwrap_mode=stat.S_IMODE(info.st_mode), bwrap_uid=info.st_uid, bwrap_gid=info.st_gid)
    except OSError:
        pass
    try:
        policy["bwrap_file_caps"] = bool(os.getxattr("/usr/bin/bwrap", "security.capability"))
    except OSError as error:
        if error.errno == errno.ENODATA:
            policy["bwrap_file_caps"] = False
    return policy


def classify_error(raw):
    # These are error categories, not attribution to AppArmor or another policy.
    text = raw.lower()
    denied = b"operation not permitted" in text or b"permission denied" in text or b"no permissions" in text
    if b"namespace" in text and denied:
        return "namespace-denied"
    if b"mount" in text and denied:
        return "mount-denied"
    return "other"


def sanitize(data):
    if not isinstance(data, dict) or set(data) != {"returncode", "signal", "timed_out", "stderr_truncated", "error_class", "policy"}:
        raise ValueError("evidence-invalid")
    rc, sig, timed_out, category = (data[key] for key in ("returncode", "signal", "timed_out", "error_class"))
    if type(timed_out) is not bool or type(data["stderr_truncated"]) is not bool or category not in ERRORS:
        raise ValueError("evidence-invalid")
    if rc is not None and (type(rc) is not int or not -64 <= rc <= 255):
        raise ValueError("evidence-invalid")
    expected_signal = -rc if rc is not None and rc < 0 else None
    if (sig is not None and type(sig) is not int) or sig != expected_signal:
        raise ValueError("evidence-invalid")
    if timed_out:
        valid = category == "timeout" and rc is not None
    elif rc is None:
        valid = category == "spawn-error"
    elif rc == 0:
        valid = category == "ok"
    elif rc < 0:
        valid = category == "signal"
    else:
        valid = category in ("namespace-denied", "mount-denied", "other")
    policy = data["policy"]
    if not valid or not isinstance(policy, dict) or set(policy) != set(unknown_policy()):
        raise ValueError("evidence-invalid")
    for key, limit in POLICY_INTS.items():
        if policy[key] is not None and (type(policy[key]) is not int or not 0 <= policy[key] <= limit):
            raise ValueError("evidence-invalid")
    for key in ("apparmor_enabled", "bwrap_file_caps"):
        if policy[key] is not None and type(policy[key]) is not bool:
            raise ValueError("evidence-invalid")
    if policy["current_label"] not in ("unknown", "unconfined", "confined"):
        raise ValueError("evidence-invalid")
    return dict(data, policy=dict(policy))


def probe(seconds=15):
    result = dict(returncode=None, signal=None, timed_out=False, stderr_truncated=False,
                  error_class="spawn-error", policy=read_policy())
    try:
        process = subprocess.Popen(["/usr/bin/bwrap", "--ro-bind", "/", "/", "--", "/usr/bin/true"],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    except OSError:
        return sanitize(result)
    captured = bytearray()
    deadline = time.monotonic() + seconds
    try:
        os.set_blocking(process.stderr.fileno(), False)
        eof = False
        while not eof or process.poll() is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                result["timed_out"] = True
                process.kill()
                break
            if eof:
                time.sleep(min(0.05, remaining))
                continue
            readable, _, _ = select.select([process.stderr], [], [], min(0.2, remaining))
            if readable:
                chunk = os.read(process.stderr.fileno(), STDERR_LIMIT)
                if not chunk:
                    eof = True
                    continue
                available = STDERR_LIMIT - len(captured)
                captured.extend(chunk[:available])
                result["stderr_truncated"] |= len(chunk) > available
        result["returncode"] = process.wait(timeout=3)
    finally:
        process.stderr.close()
        if process.poll() is None:
            process.kill()
            process.wait(timeout=3)
    rc = result["returncode"]
    result["signal"] = -rc if rc < 0 else None
    result["error_class"] = ("timeout" if result["timed_out"] else "signal" if rc < 0
                             else "ok" if rc == 0 else classify_error(captured))
    return sanitize(result)
