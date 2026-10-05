"""Run only after the host creates the offline namespace and drops privileges."""

import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys

from . import contract, sandbox


def query(args):
    return subprocess.check_output(args, stderr=subprocess.DEVNULL, timeout=10, text=True)


def status(pid="self"):
    return dict(line.split(":", 1) for line in Path(f"/proc/{pid}/status").read_text().splitlines() if ":" in line)


def namespaces():
    return {key: os.readlink(f"/proc/self/ns/{key}") for key in ("net", "mnt", "pid", "user")}


def blocked(case, reason):
    return dict(case=case, status="blocked", reason=reason, checks={}, counts=[], diagnostics=contract.diagnostics())


def preflight(context, root):
    routes = json.loads(query(["ip", "-j", "route", "show", "table", "all"]))
    routes += json.loads(query(["ip", "-j", "-6", "route", "show", "table", "all"]))
    contract.validate_identity(status(), context["uid"], context["gid"], context["namespaces"],
                               namespaces(), json.loads(query(["ip", "-j", "link", "show"])), routes)
    if subprocess.run(["sudo", "-n", "-l"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10).returncode == 0:
        raise ValueError("isolation-unavailable")
    if os.access("/var/run/docker.sock", os.W_OK):
        raise ValueError("isolation-unavailable")
    proof = sandbox.probe()
    (root / "proof/sandbox.json").write_text(json.dumps(proof))
    if proof["error_class"] != "ok":
        raise ValueError("bubblewrap-unavailable")
    if not stat.S_ISCHR(os.stat("/dev/fuse").st_mode) or not os.access("/dev/fuse", os.R_OK | os.W_OK):
        raise ValueError("fuse-unavailable")


def main(root):
    context = json.loads((root / "context.json").read_text())
    try:
        preflight(context, root)
    except Exception as error:
        reason = str(error) if str(error) in contract.REASONS else "isolation-unavailable"
        for case in contract.CASES:
            (root / case / "out/result.json").write_text(json.dumps(blocked(case, reason)))
        return 1
    (root / "proof/preflight.json").write_text(json.dumps({"identity": True, "offline": True, "bubblewrap": True, "fuse_device": True}))
    for case in contract.CASES:
        area = root / case
        env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1",
               "HOME": str(area / "home"), "XDG_RUNTIME_DIR": str(area / "runtime"),
               "XDG_CACHE_HOME": str(area / "cache"), "XDG_CONFIG_HOME": str(area / "config"),
               "XDG_DATA_HOME": str(area / "data"), "TMPDIR": str(area / "tmp"),
               "NO_AT_BRIDGE": "0", "GTK_MODULES": "atk-bridge", "GDK_BACKEND": "x11"}
        if case == "catalog-renderer-subset":
            env.update(WEBKIT_DISABLE_DMABUF_RENDERER="1", WEBKIT_DISABLE_COMPOSITING_MODE="1")
        command = ["xvfb-run", "--auto-servernum", "--server-args=-screen 0 1280x900x24 -nolisten tcp",
                   "dbus-run-session", "--", "/usr/bin/python3", "-m", "appimage_runtime.ui", str(root), case]
        process = subprocess.Popen(command, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        try:
            process.wait(timeout=300)
        except subprocess.TimeoutExpired:
            (area / "out/result.json").write_text(json.dumps(blocked(case, "timeout")))
        finally:
            try:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=3)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                pass
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        if not (area / "out/result.json").is_file():
            (area / "out/result.json").write_text(json.dumps(blocked(case, "gui-unavailable")))
    return 0


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1])))
