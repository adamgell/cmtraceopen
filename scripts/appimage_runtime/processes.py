"""Kernel-backed child-family supervision; no namespaces or host policy changes."""

import ctypes
import os
import subprocess
import sys


def become_subreaper():
    if sys.platform != "linux":
        raise ValueError("isolation-unavailable")
    # PR_SET_CHILD_SUBREAPER affects this process only. Orphaned descendants
    # are adopted here instead of disappearing into the host's PID 1.
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "subreaper unavailable")


def supervise(command):
    become_subreaper()
    launcher = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    exit_code = None
    while True:
        try:
            pid, status = os.waitpid(-1, 0)
        except ChildProcessError:
            break  # ECHILD: no child can remain alive to create a later helper.
        if pid == launcher.pid and exit_code is None:
            exit_code = os.waitstatus_to_exitcode(status)
            launcher.returncode = exit_code
    return 0 if exit_code == 0 else 1


if __name__ == "__main__":
    try:
        sys.exit(supervise(sys.argv[1:]))
    except Exception:
        sys.exit(1)
