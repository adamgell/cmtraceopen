"""AT-SPI acceptance assertions inside the shared, offline X11/D-Bus session."""

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid

from . import contract, processes
from .session import status

TOKENS = ["JAMMY_OPEN_ALPHA", "JAMMY_FIND_BETA", "JAMMY_FILTER_GAMMA"]


class Blocked(Exception):
    pass


def command(args):
    subprocess.run(args, check=True, timeout=10, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def key(*keys):
    command(["xdotool", "key", "--clearmodifiers", *keys])


def type_text(text):
    command(["xdotool", "type", "--clearmodifiers", "--delay", "12", "--", text])


def poll(predicate, seconds=30, reason="ui-assertion", blocked=False):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            result = predicate()
            if result:
                return result
        except (ValueError, LookupError):
            pass
        time.sleep(0.2)
    raise (Blocked(reason) if blocked else ValueError(reason))


def process_table():
    parents = {}
    for proc in Path("/proc").iterdir():
        if proc.name.isdecimal():
            try:
                parents[int(proc.name)] = int(status(proc.name)["PPid"])
            except (OSError, KeyError):
                pass
    return parents


def fixture_line(token, index):
    return f'<![LOG[{token}]LOG]!><time="12:00:00.{index:03d}+000" date="10-04-2026" component="RuntimeFixture" context="" type="1" thread="1" file="runtime-fixture.log">\n'


class Controller:
    def __init__(self, root, case, atspi):
        self.root, self.case, self.atspi = root, case, atspi
        self.area = root / case
        self.out = self.area / "out"
        self.result = dict(case=case, status="blocked", reason="harness-error", checks={}, counts=[])
        self.proofs = []
        self.tracker = None
        self.app, self.application, self.window = None, None, None
        self.fixture = self.area / "data/runtime-fixture.log"

    def walk(self, root):
        pending, seen = [root], 0
        while pending:
            node = pending.pop()
            seen += 1
            if seen > 4000:
                raise Blocked("accessibility-unavailable")
            yield node
            try:
                pending.extend(reversed(list(node)))
            except Exception as error:
                raise Blocked("accessibility-unavailable") from error

    def role(self, node):
        return contract.accessible_role(node.getRoleName(), node.getAttributes())

    def showing(self, node):
        return node.getState().contains(self.atspi.STATE_SHOWING)

    def nodes(self):
        if self.application is None:
            raise Blocked("accessibility-unavailable")
        return list(self.walk(self.application))

    def find(self, name, roles=None):
        return next((node for node in self.nodes() if node.name == name and self.showing(node) and (roles is None or self.role(node) in roles)), None)

    def text(self, node):
        parts = []
        for item in self.walk(node):
            if item.name:
                parts.append(item.name)
            try:
                text = item.queryText()
                if text.characterCount > 10000:
                    raise Blocked("accessibility-unavailable")
                parts.append(text.getText(0, -1))
            except NotImplementedError:
                pass
        return " ".join(parts)

    def rows(self):
        box = self.find("Log entries", {"listbox"})
        if box is None:
            raise LookupError("listbox")
        return [dict(role="option", text=self.text(node), selected=node.getState().contains(self.atspi.STATE_SELECTED))
                for node in self.walk(box) if self.role(node) == "option" and self.showing(node)]

    def expect_rows(self, expected, seconds=30):
        def correct():
            rows = self.rows()
            contract.validate_rows(rows, expected)
            return rows
        rows = poll(correct, seconds)
        self.result["counts"].append(len(rows))
        return rows

    def focused_editable(self):
        for node in self.nodes():
            state = node.getState()
            if state.contains(self.atspi.STATE_FOCUSED) and state.contains(self.atspi.STATE_EDITABLE):
                return node
        return None

    def click(self, name):
        node = poll(lambda: self.find(name, {"push button", "button"}))
        action = node.queryAction()
        for index in range(action.nActions):
            if action.getName(index) in ("click", "press", "activate") and action.doAction(index):
                return
        raise ValueError("ui-assertion")

    def live_fuse(self):
        descendants = contract.descendant_pids(process_table(), self.app.pid)
        for pid in descendants:
            try:
                exe = os.readlink(f"/proc/{pid}/exe")
                if not exe.endswith("/usr/bin/cmtrace-open"):
                    continue
                mounts = Path(f"/proc/{pid}/mountinfo").read_text()
                mount = contract.fuse_mount(mounts, exe)
                payload = {}
                for name in ("AppRun", "AppRun.wrapped", "usr/bin/cmtrace-open"):
                    info = (Path(mount) / name).lstat()
                    payload[name] = dict(mode=info.st_mode, uid=info.st_uid, gid=info.st_gid)
                contract.validate_payload(payload)
                proof = dict(pid=pid, **contract.fuse_metadata(mounts, exe), payload_root_0755=True)
                return pid, proof
            except (OSError, ValueError, StopIteration):
                continue
        return None

    def launch(self, with_file):
        self.application = None
        self.tracker = processes.LaunchTracker(os.getpid(), processes.snapshot())
        self.app = subprocess.Popen([str(self.root / "candidate.AppImage")] + ([str(self.fixture)] if with_file else []),
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        pid, proof = poll(self.live_fuse, reason="fuse-unavailable", blocked=True)
        self.proofs.append(proof)
        self.result["checks"]["fuse"] = True
        desktop = self.atspi.Registry.getDesktop(0)
        def accessible_app():
            for app in desktop:
                if app.get_process_id() == pid:
                    return app
            return None
        self.application = poll(accessible_app, reason="accessibility-unavailable", blocked=True)
        def visible_window():
            found = subprocess.run(["xdotool", "search", "--onlyvisible", "--pid", str(pid)], capture_output=True, text=True, timeout=5)
            return next((line for line in found.stdout.splitlines() if line.isdecimal()), None)
        self.window = poll(visible_window, reason="gui-unavailable", blocked=True)
        command(["xdotool", "windowsize", self.window, "1100", "780"])
        command(["xdotool", "windowactivate", "--sync", self.window])
        # The listbox is the required accessibility baseline even before opening a file.
        poll(lambda: self.find("Log entries", {"listbox"}) if with_file else self.focused_or_window(),
             reason="accessibility-unavailable", blocked=True)

    def focused_or_window(self):
        return any(self.showing(node) and self.role(node) in ("frame", "window") for node in self.nodes())

    def screenshot(self, phase):
        command(["import", "-window", self.window, str(self.out / f"{phase}.png")])

    def exit_app(self):
        command(["xdotool", "windowactivate", "--sync", self.window])
        # Observe before close; the subreaper also adopts helpers forked and
        # orphaned between snapshots, so a surviving helper cannot disappear.
        self.tracker.active(processes.snapshot())
        # IceWM sends the normal WM_DELETE_WINDOW request; no kill is accepted as exit evidence.
        key("alt+F4")
        def gone():
            self.app.poll()  # Reap the launcher through Popen to retain its exit code.
            current = processes.snapshot()
            active = self.tracker.active(current)
            self.tracker.reap(current, self.app.pid)
            mount_ids = {int(line.split()[0]) for line in Path("/proc/self/mountinfo").read_text().splitlines()}
            return self.app.returncode == 0 and not active and self.proofs[-1]["mount_id"] not in mount_ids
        poll(gone, 20)
        self.application = None

    def execute(self):
        self.fixture.write_text("".join(fixture_line(token, i) for i, token in enumerate(TOKENS, 1)))
        self.launch(True)
        self.expect_rows(TOKENS)
        self.result["checks"]["open"] = True
        self.screenshot("initial")
        key("ctrl+f")
        poll(lambda: self.find("Close find bar", {"push button", "button"}) and self.focused_editable())
        type_text(TOKENS[1])
        key("Return")
        def found_beta():
            rows = self.rows()
            contract.validate_rows(rows, TOKENS)
            selected = [row for row in rows if row["selected"]]
            contract.validate_rows(selected, [TOKENS[1]])
            return any(re.fullmatch(r"1\s+of\s+1", (node.name or "").strip()) for node in self.nodes())
        poll(found_beta)
        self.result["checks"]["find"] = True
        self.click("Close find bar")
        key("ctrl+shift+l")
        poll(lambda: self.find("Filter", {"dialog"}) and self.focused_editable())
        type_text(TOKENS[2])
        self.click("Apply")
        self.expect_rows([TOKENS[2]])
        self.result["checks"]["filter"] = True
        key("ctrl+shift+l")
        poll(lambda: self.find("Filter", {"dialog"}))
        self.click("Clear Filter")
        self.expect_rows(TOKENS)
        delta = "JAMMY_TAIL_DELTA_" + uuid.uuid4().hex.upper()
        with self.fixture.open("a") as fixture:
            fixture.write(fixture_line(delta, 4))
            fixture.flush()
            os.fsync(fixture.fileno())
        expected = TOKENS + [delta]
        self.expect_rows(expected, 15)
        self.result["checks"]["tail"] = True
        self.exit_app()
        self.launch(False)
        key("ctrl+o")
        poll(lambda: any(self.role(node) in ("file chooser", "dialog") and self.showing(node) for node in self.nodes()))
        key("ctrl+l")
        poll(self.focused_editable)
        type_text(str(self.fixture))
        key("Return")
        self.expect_rows(expected)
        self.result["checks"]["reopen"] = True
        self.screenshot("final")
        self.exit_app()
        self.result["checks"]["exited"] = True
        self.result.update(status="passed", reason="ok")


def main(root, case):
    controller = None
    try:
        import pyatspi
        pyatspi.setTimeout(1500, 5000)
        command(["dbus-send", "--session", "--type=method_call", "--dest=org.a11y.Bus", "/org/a11y/bus", "org.freedesktop.DBus.Properties.Set", "string:org.a11y.Status", "string:IsEnabled", "variant:boolean:true"])
        subprocess.Popen(["icewm"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        processes.become_subreaper()
        controller = Controller(root, case, pyatspi)
        controller.execute()
    except Exception as error:
        if controller is None:
            result = dict(case=case, status="blocked", reason="accessibility-unavailable", checks={}, counts=[])
        else:
            result = controller.result
            if isinstance(error, Blocked):
                result.update(status="blocked", reason=str(error))
            elif isinstance(error, ValueError) and str(error) == "ui-assertion":
                result.update(status="failed", reason="ui-assertion")
            else:
                result.update(status="blocked", reason="harness-error")
    else:
        result = controller.result
    area = root / case / "out"
    (area / "result.json").write_text(json.dumps(result))
    (area / "fuse.json").write_text(json.dumps(controller.proofs if controller else []))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1]), sys.argv[2]))
