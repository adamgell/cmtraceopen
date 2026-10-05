"""Privileged VM supervisor. Never execute this module on a developer host."""

import grp
import hashlib
import json
import os
from pathlib import Path
import platform
import pwd
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time

from . import contract, processes, sandbox
from .session import blocked, namespaces, status

ACCOUNT = "cmtrace-runtime-probe"
PACKAGE_NAMES = ("python3-apt", "python3-pyatspi", "libatk-adaptor", "at-spi2-core", "python3-pil", "bubblewrap", "xvfb", "xauth", "icewm", "dbus-x11", "xdotool", "imagemagick", "fuse3", "iproute2", "util-linux", "libwebkit2gtk-4.1-0", "libjavascriptcoregtk-4.1-0", "libayatana-appindicator3-1", "libc6", "libcom-err2", "libdrm2", "libegl1", "libexpat1", "libfontconfig1", "libfreetype6", "libfribidi0", "libgbm1", "libgcc-s1", "libgl1", "libglvnd0", "libglx0", "libgmp10", "libgpg-error0", "libharfbuzz0b", "libstdc++6", "libuuid1", "libx11-6", "libx11-xcb1", "libxcb1", "zlib1g")


def run(args):
    subprocess.run(args, check=True, timeout=20, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def packages():
    import apt
    release = platform.freedesktop_os_release()
    version, codename = release["VERSION_ID"], release["VERSION_CODENAME"]
    if release["ID"] != "ubuntu" or (version, codename) not in (("22.04", "jammy"), ("24.04", "noble")):
        raise ValueError("harness-error")
    names = PACKAGE_NAMES + (("libfuse2", "libgtk-3-0") if version == "22.04" else ("libfuse2t64", "libgtk-3-0t64"))
    cache, result = apt.Cache(), {}
    for name in names:
        installed = cache[name].installed
        if installed is None or not re.fullmatch(r"[A-Za-z0-9.+:~_-]{1,120}", installed.version):
            raise ValueError("harness-error")
        origins = sorted({origin.archive for origin in installed.origins if origin.trusted and origin.origin == "Ubuntu" and origin.archive in (codename, codename + "-updates", codename + "-security")})
        if not origins:
            raise ValueError("harness-error")
        result[name] = dict(version=installed.version, archives=origins)
    return version, result


def kill_owned(uid):
    """Bind signals to pidfds, and never target a process of another account."""
    if uid <= 0:
        raise ValueError("harness-error")
    for sig, seconds in ((signal.SIGTERM, 3), (signal.SIGKILL, 5)):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            found = False
            for proc in Path("/proc").iterdir():
                if not proc.name.isdecimal():
                    continue
                fd = None
                try:
                    fd = os.pidfd_open(int(proc.name))
                    current = status(proc.name)
                    if int(current["Uid"].split()[0]) == uid and current["State"].strip()[0] != "Z":
                        found = True
                        signal.pidfd_send_signal(fd, sig)
                except (FileNotFoundError, ProcessLookupError):
                    pass
                finally:
                    if fd is not None:
                        os.close(fd)
            # An empty /proc sample is not a lifetime proof: a helper may fork
            # and exit during enumeration. As the host subreaper, require the
            # kernel to report ECHILD as well before deleting evidence/account.
            while True:
                try:
                    reaped, _ = os.waitpid(-1, os.WNOHANG)
                except ChildProcessError:
                    if not found:
                        return
                    break
                if reaped == 0:
                    break
            time.sleep(0.1)
    raise ValueError("harness-error")


def cleanup_fuse(root, uid, gid):
    # The root was newly created for this run. Only this account's FUSE mounts
    # beneath it may be detached, including mounts made before UI proof existed.
    deadline = time.monotonic() + 20
    mounts = contract.owned_fuse_mounts(Path("/proc/self/mountinfo").read_text(), uid, root)
    for mount in mounts:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ValueError("harness-error")
        subprocess.run(contract.unmount_command(uid, gid, mount), check=True,
                       timeout=min(5, remaining), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if contract.owned_fuse_mounts(Path("/proc/self/mountinfo").read_text(), uid, root):
        raise ValueError("harness-error")


def collect(root, uid, output):
    try:
        preflight = json.loads(contract.read_owned_file(root / "proof/preflight.json", uid, 1024))
    except (OSError, ValueError):
        preflight = {}
    expected = dict(identity=True, offline=True, bubblewrap=True, fuse_device=True)
    if preflight != expected:
        preflight = {}
    try:
        sandbox_proof = sandbox.sanitize(json.loads(contract.read_owned_file(root / "proof/sandbox.json", uid, 4096)))
    except (OSError, ValueError, TypeError, KeyError):
        sandbox_proof = None
    cases, images, size = [], {}, 65536  # Reserve space for the bounded summary.
    for case in contract.CASES:
        area = root / case / "out"
        try:
            data = contract.sanitize_case(json.loads(contract.read_owned_file(area / "result.json", uid, 4096)))
            if data["checks"] and (preflight != expected or sandbox_proof is None or sandbox_proof["error_class"] != "ok"):
                raise ValueError("evidence-invalid")
            passed = data["status"] == "passed"
            proofs = []
            if (area / "fuse.json").exists():
                proofs = json.loads(contract.read_owned_file(area / "fuse.json", uid, 4096))
            data["fuse_observations"] = contract.sanitize_fuse(proofs, passed)
            if (area / "final.png").exists() != (data["diagnostics"]["final_image"] != "absent"):
                raise ValueError("evidence-invalid")
            for phase in ("initial", "final"):
                path = area / f"{phase}.png"
                if not path.exists():
                    if passed:
                        raise ValueError("evidence-invalid")
                    continue
                clean = contract.sanitize_png(contract.read_owned_file(path, uid, 10 * 1024 * 1024))
                size += len(clean)
                if size > 10 * 1024 * 1024:
                    raise ValueError("evidence-invalid")
                images[f"{case}-{phase}.png"] = clean
        except (OSError, ValueError, TypeError, KeyError):
            data = blocked(case, "evidence-invalid")
            images = {name: value for name, value in images.items() if not name.startswith(case + "-")}
        cases.append(data)
    for name, data in images.items():
        (output / name).write_bytes(data)
    return preflight, cases, sandbox_proof


def main(artifact_dir, output, harness_sha):
    if sys.platform != "linux" or os.geteuid() != 0 or not re.fullmatch(r"[0-9a-f]{40}", harness_sha):
        raise ValueError("harness-error")
    if not artifact_dir.is_absolute() or not output.is_absolute() or output.is_symlink() or not output.is_dir():
        raise ValueError("harness-error")
    summary = dict(artifact_id=contract.ARTIFACT_ID, producer_run=contract.RUN, sha256=contract.ARTIFACT_SHA256,
                   source=contract.SOURCE, built_commit=contract.MERGE, built_tree=contract.TREE,
                   reviewed_harness=harness_sha, display="Xvfb X11; no Wayland or physical GPU claim",
                   cases=[blocked(case, "harness-error") for case in contract.CASES])
    root, uid, created, process = None, None, False, None
    def cancel(_signum, _frame):
        raise InterruptedError("cancelled")
    signal.signal(signal.SIGTERM, cancel)
    signal.signal(signal.SIGINT, cancel)
    try:
        try:
            pwd.getpwnam(ACCOUNT)
        except KeyError:
            pass
        else:
            raise ValueError("isolation-unavailable")
        summary["ubuntu"], summary["packages"] = packages()
        image = artifact_dir / "appimage" / contract.ARTIFACT_NAME
        report = json.loads((artifact_dir / "provenance/appimage-abi.json").read_text())
        root = Path(tempfile.mkdtemp(prefix="cmtrace-runtime-", dir="/tmp"))
        root.chmod(0o755)
        shutil.copyfile(image, root / "candidate.AppImage")
        digest = hashlib.sha256((root / "candidate.AppImage").read_bytes()).hexdigest()
        contract.validate_binding(report, digest)
        (root / "candidate.AppImage").chmod(0o555)
        shutil.copytree(Path(__file__).parent, root / "appimage_runtime", ignore=shutil.ignore_patterns("__pycache__"))
        run(["useradd", "--system", "--user-group", "--no-create-home", "--home-dir", str(root / "home"), "--shell", "/usr/sbin/nologin", ACCOUNT])
        created = True
        account = pwd.getpwnam(ACCOUNT)
        uid, gid = account.pw_uid, account.pw_gid
        if uid <= 0 or gid <= 0 or set(os.getgrouplist(ACCOUNT, gid)) != {gid}:
            raise ValueError("isolation-unavailable")
        for parent, children in [(root, ("home", "proof"))] + [(root / case, ("home", "runtime", "cache", "config", "data", "tmp", "out")) for case in contract.CASES]:
            parent.mkdir(mode=0o755, exist_ok=True)
            for name in children:
                path = parent / name
                path.mkdir(mode=0o700)
                os.chown(path, uid, gid)
        (root / "context.json").write_text(json.dumps(dict(uid=uid, gid=gid, namespaces=namespaces())))
        processes.become_subreaper()
        process = subprocess.Popen(contract.namespace_command(uid, gid, root), cwd=root,
                                   env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        process.wait(timeout=660)
        kill_owned(uid)
        summary["preflight"], summary["cases"], summary["sandbox"] = collect(root, uid, output)
    except (Exception, KeyboardInterrupt) as error:
        reason = str(error) if str(error) in contract.REASONS else ("timeout" if isinstance(error, subprocess.TimeoutExpired) else "harness-error")
        summary["cases"] = [blocked(case, reason) for case in contract.CASES]
    finally:
        # Do not allow a second cancellation to interrupt the bounded cleanup.
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        if process and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        try:
            if uid is not None:
                kill_owned(uid)
                cleanup_fuse(root, uid, gid)
            if created:
                run(["userdel", ACCOUNT])
                try:
                    group = grp.getgrnam(ACCOUNT)
                except KeyError:
                    pass
                else:
                    if group.gr_gid != gid:
                        raise ValueError("harness-error")
                    run(["groupdel", ACCOUNT])
            if root:
                shutil.rmtree(root)
        except Exception:
            summary["cases"] = [blocked(case, "harness-error") for case in contract.CASES]
        encoded = json.dumps(summary, indent=2) + "\n"
        if len(encoded.encode()) > 65536:
            encoded = json.dumps(dict(status="blocked", reason="evidence-invalid"))
            summary["cases"] = [blocked(case, "evidence-invalid") for case in contract.CASES]
        (output / "summary.json").write_text(encoded)
    return 0 if all(case["status"] == "passed" for case in summary["cases"]) else 1


if __name__ == "__main__":
    try:
        sys.exit(main(Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]))
    except Exception:
        # Never emit app strings, environment values or a raw traceback.
        print("Runtime harness blocked before initialization.", file=sys.stderr)
        sys.exit(1)
