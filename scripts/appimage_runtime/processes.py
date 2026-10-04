"""Per-controller child adoption and stable process identities; no namespace changes."""

import ctypes
import os
from pathlib import Path
import sys

from .contract import descendant_pids


def become_subreaper():
    if sys.platform != "linux":
        raise ValueError("isolation-unavailable")
    # PR_SET_CHILD_SUBREAPER affects this process only. Orphaned app helpers
    # remain observable children even if they fork between shutdown snapshots.
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "subreaper unavailable")


def snapshot():
    result = {}
    for path in Path("/proc").iterdir():
        if path.name.isdecimal():
            try:
                fields = (path / "stat").read_text().rsplit(")", 1)[1].split()
                # /proc/PID/stat fields 4, 22 and 3: parent, start time, state.
                result[int(path.name)] = (int(fields[1]), int(fields[19]), fields[0])
            except (OSError, IndexError, ValueError):
                pass
    return result


class LaunchTracker:
    def __init__(self, owner, initial):
        self.owner = owner
        children = descendant_pids({pid: row[0] for pid, row in initial.items()}, owner) - {owner}
        self.baseline = {pid: initial[pid][1] for pid in children}
        self.identities = set()

    def active(self, current):
        parents = {pid: row[0] for pid, row in current.items()}
        excluded = {self.owner}
        for pid, started in self.baseline.items():
            if pid in current and current[pid][1] == started:
                excluded.update(descendant_pids(parents, pid))
        children = descendant_pids(parents, self.owner) - excluded
        self.identities.update((pid, current[pid][1]) for pid in children)
        return {pid for pid, started in self.identities if pid in current and current[pid][1] == started and current[pid][2] != "Z"}

    def reap(self, current, launcher):
        for pid, started in self.identities:
            if pid != launcher and pid in current and current[pid] == (self.owner, started, "Z"):
                try:
                    os.waitpid(pid, os.WNOHANG)
                except ChildProcessError:
                    pass
