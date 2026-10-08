"""AT-SPI acceptance assertions inside the shared, offline X11/D-Bus session."""

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid

from . import contract
from .session import blocked, status

TOKENS = ["JAMMY_OPEN_ALPHA", "JAMMY_FIND_BETA", "JAMMY_FILTER_GAMMA"]


class Blocked(Exception):
    pass


def command(args):
    subprocess.run(args, check=True, timeout=10, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def key(*keys):
    command(["xdotool", "key", "--clearmodifiers", *keys])


def type_text(text):
    command(["xdotool", "type", "--clearmodifiers", "--delay", "12", "--", text])


def is_atspi_error(error):
    return type(error).__module__ in ("gi.repository.GLib", "gi.repository.Gio", "gi.repository.Atspi", "gi.overrides.GLib")


def poll(predicate, seconds=30, reason="ui-assertion", blocked=False):
    deadline = time.monotonic() + seconds
    inaccessible = False
    while time.monotonic() < deadline:
        try:
            result = predicate()
            inaccessible = False
            if result:
                return result
        except (ValueError, LookupError):
            inaccessible = False
        except Exception as error:
            if not is_atspi_error(error):
                raise
            # Startup/tree mutation may invalidate an AT-SPI object between
            # samples. Resample within the original deadline, never infer pass.
            inaccessible = True
        time.sleep(0.2)
    if inaccessible:
        raise Blocked("accessibility-unavailable")
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
        self.result = blocked(case, "harness-error")
        self.proofs = []
        self.app, self.application, self.window = None, None, None
        self.fixture = self.area / "data/runtime-fixture.log"
        self._window_sample = None

    def stage(self, name):
        self.result["diagnostics"].update(stage=name, elapsed_ms=0, observations={})

    def observe(self, **facts):
        self.result["diagnostics"]["observations"].update(facts)

    def wait(self, stage, predicate, seconds=30, **kwargs):
        self.stage(stage)
        started = time.monotonic()
        try:
            return poll(predicate, seconds, **kwargs)
        finally:
            self.result["diagnostics"]["elapsed_ms"] = min(300000, max(0, int((time.monotonic() - started) * 1000)))

    def walk(self, root):
        for node, _ in self.walk_paths(root):
            yield node

    def walk_paths(self, root):
        pending, seen = [(root, ())], 0
        while pending:
            node, parents = pending.pop()
            seen += 1
            if seen > 4000:
                raise Blocked("accessibility-unavailable")
            yield node, parents
            try:
                pending.extend((child, parents + (node,)) for child in reversed(list(node)))
            except Exception as error:
                if is_atspi_error(error):
                    raise  # Resample the whole tree, never skip a missing child.
                raise Blocked("accessibility-unavailable") from error

    def role(self, node):
        # The actual Find control is a declared HTML input with editable state.
        # Enum/name/interface guesses failed on this fixed artifact's bridge.
        if ("tag:input" in node.getAttributes()
                and node.getState().contains(self.atspi.STATE_EDITABLE)):
            return "entry"
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

    def direct_text(self, node):
        try:
            text = node.queryText()
            if text.characterCount > 10000:
                raise Blocked("accessibility-unavailable")
            return text.getText(0, -1)
        except NotImplementedError:
            return ""

    def window_geometry(self):
        active = subprocess.check_output(["xdotool", "getactivewindow"], text=True, timeout=5, stderr=subprocess.DEVNULL).strip()
        if active != self.window:
            return None
        output = subprocess.check_output(["xdotool", "getwindowgeometry", "--shell", self.window], text=True, timeout=5, stderr=subprocess.DEVNULL)
        fields = dict(line.split("=", 1) for line in output.splitlines())
        window, x, y, width, height = (int(fields[key]) for key in ("WINDOW", "X", "Y", "WIDTH", "HEIGHT"))
        if window != int(self.window) or (width, height) != (1100, 780) or x < 0 or y < 0 or x + width > 1280 or y + height > 900:
            return None
        return window, x, y, width, height

    def ready(self, expected):
        # index.html's overlay remains in the tree during the 500 ms fade.
        # STATE_SHOWING alone does not prove that underlying rows are unobscured.
        splash = any("id:splash" in node.getAttributes()
                     or node.name == "Log Viewer & Troubleshooting Tool"
                     or (self.role(node) in ("static", "text") and self.direct_text(node) == "Log Viewer & Troubleshooting Tool")
                     or (self.role(node) == "image" and node.name == "CMTrace Open") for node in self.nodes())
        geometry = self.window_geometry()
        rows_match = True
        if expected is not None:
            try:
                contract.validate_rows(self.rows(), expected)
            except (ValueError, LookupError):
                rows_match = False
        stable = geometry is not None and geometry == self._window_sample
        self.observe(splash_absent=not splash, window_active=geometry is not None,
                     window_stable=stable, rows_match=rows_match)
        self._window_sample = geometry if not splash and rows_match else None
        return not splash and rows_match and stable

    def find_input(self):
        # WebKit exposes HTML input[type=text] as entry, with placeholder-text.
        nodes = self.nodes()
        placeholders = [node for node in nodes if "placeholder-text:Find..." in node.getAttributes()]
        self.observe(find_placeholder_present=bool(placeholders), find_placeholder_unique=len(placeholders) == 1,
                     find_placeholder_entry=any(self.role(node) == "entry" for node in placeholders),
                     find_placeholder_showing=any(self.showing(node) for node in placeholders),
                     find_name_present=any(node.name == "Find..." for node in nodes),
                     find_entry_present=any(self.role(node) == "entry" for node in nodes),
                     find_placeholder_tag_input=any("tag:input" in node.getAttributes() for node in placeholders),
                     find_placeholder_text_role=any(node.getRole() == self.atspi.ROLE_TEXT for node in placeholders),
                     find_placeholder_editable=any(node.getState().contains(self.atspi.STATE_EDITABLE) for node in placeholders),
                     find_placeholder_focused=any(node.getState().contains(self.atspi.STATE_FOCUSED) for node in placeholders))
        candidates = [node for node in placeholders if self.role(node) == "entry" and self.showing(node)]
        unique = len(candidates) == 1
        focused = unique and all(candidates[0].getState().contains(state)
                                 for state in (self.atspi.STATE_FOCUSED, self.atspi.STATE_EDITABLE))
        self.observe(find_input_unique=unique, find_input_focused=focused)
        return candidates[0] if focused else None

    def find_open(self):
        visible = self.find("Close find bar", {"push button", "button"}) is not None
        self.observe(find_button_visible=visible)
        intended = self.find_input()
        return visible and intended is not None

    def query_matches(self):
        node = self.find_input()
        matches = node is not None and self.direct_text(node) == TOKENS[1]
        self.observe(find_query_matches=matches)
        return matches

    def beta_selected(self):
        rows_match, selected = False, False
        try:
            rows = self.rows()
            contract.validate_rows(rows, TOKENS)
            rows_match = True
            contract.validate_rows([row for row in rows if row["selected"]], [TOKENS[1]])
            selected = True
        except (ValueError, LookupError):
            pass
        self.observe(rows_match=rows_match, beta_selected=selected)
        return selected

    def find_scope(self):
        entries, closes = [], []
        for node, parents in self.walk_paths(self.application):
            if not self.showing(node):
                continue
            role = self.role(node)
            if role == "entry" and "placeholder-text:Find..." in node.getAttributes():
                entries.append(parents)
            if role in ("push button", "button") and node.name == "Close find bar":
                closes.append(parents)
        self.observe(scope_entries_unique=len(entries) == 1, scope_close_unique=len(closes) == 1)
        if len(entries) != 1 or len(closes) != 1:
            return []
        groups = [node for node, _ in self.walk_paths(self.application)
                  if self.role(node) == "group" and node.name == "Find bar" and self.showing(node)]
        common = groups[0] if len(groups) == 1 else None
        valid = common is not None and common in entries[0] and common in closes[0]
        self.observe(scope_common_present=common is not None,
                     scope_named_group=valid,
                     scope_common_showing=common is not None and self.showing(common))
        if not valid:
            return []
        scoped = list(self.walk_paths(common))
        buttons, inputs = [], 0
        expected = {"Match case": {"toggle button"}, "Use regular expression": {"toggle button"},
                    "Previous match": {"push button", "button"}, "Next match": {"push button", "button"},
                    "Close find bar": {"push button", "button"}}
        for node, parents in scoped:
            role = self.role(node)
            if role not in ("group", "status", "section", "static", "text", "image", "separator", "entry", "push button", "button", "toggle button"):
                attrs = node.getAttributes()
                categories = {"statusbar": "status bar", "panel": "panel", "label": "label",
                              "filler": "filler", "unknown": "unknown", "invalid": "invalid",
                              "notification": "notification", "paragraph": "paragraph", "canvas": "canvas",
                              "embedded": "embedded", "grouping": "grouping", "statusbar_joined": "statusbar",
                              "checkbox": "check box", "redundant": "redundant object", "drawing_area": "drawing area",
                              "svg": "svg", "icon": "icon"}
                self.observe(scope_roles_valid=False,
                             scope_unexpected_showing=self.showing(node),
                             scope_unexpected_in_control=any(self.role(parent) in ("entry", "push button", "button", "toggle button") for parent in parents),
                             scope_unexpected_name_count=re.fullmatch(r"1\s+of\s+1", node.name or "") is not None,
                             scope_unexpected_tag_svg="tag:svg" in attrs,
                             scope_unexpected_named_status=node.name == "Find results",
                             scope_unexpected_xml_status="xml-roles:status" in attrs,
                             scope_unexpected_tag_span="tag:span" in attrs,
                             scope_unexpected_tag_div="tag:div" in attrs,
                             scope_unexpected_role_other=role not in categories.values(),
                             **{"scope_unexpected_role_" + key: role == value
                                for key, value in categories.items()})
                return []
            if role == "entry":
                inputs += 1
            if role in ("push button", "button", "toggle button"):
                if not self.showing(node) or role not in expected.get(node.name, set()):
                    self.observe(scope_buttons_valid=False)
                    return []
                buttons.append(node.name)
        self.observe(scope_roles_valid=True, scope_buttons_valid=sorted(buttons) == sorted(expected),
                     scope_inputs_valid=inputs == 1)
        return scoped if inputs == 1 and sorted(buttons) == sorted(expected) else []

    def match_count(self):
        selected = self.beta_selected()
        query = self.query_matches()
        scoped = self.find_scope()
        statuses = [node for node, parents in scoped
                    if self.role(node) == "status" and node.name == "Find results"
                    and self.showing(node)
                    and not any(self.role(parent) in ("entry", "push button", "button", "toggle button")
                                for parent in parents)]
        texts = len(statuses) == 1 and re.fullmatch(r"1\s+of\s+1", self.direct_text(statuses[0]).strip()) is not None
        self.observe(find_scope_valid=bool(scoped), status_unique=len(statuses) == 1,
                     match_text=texts)
        return selected and query and bool(scoped) and texts

    def focused_editable(self):
        for node in self.nodes():
            state = node.getState()
            if state.contains(self.atspi.STATE_FOCUSED) and state.contains(self.atspi.STATE_EDITABLE):
                return node
        return None

    def chooser_nodes(self):
        return [node for node, parents in self.walk_paths(self.application)
                if any(self.role(parent) in ("file chooser", "dialog") and self.showing(parent) for parent in parents)]

    def chooser_location(self):
        candidates = [node for node in self.chooser_nodes() if self.showing(node)
                      and all(node.getState().contains(state) for state in
                              (self.atspi.STATE_FOCUSED, self.atspi.STATE_EDITABLE))]
        self.observe(reopen_location_unique=len(candidates) == 1)
        return candidates[0] if len(candidates) == 1 else None

    def chooser_path_matches(self):
        node = self.chooser_location()
        matches = node is not None and self.direct_text(node) == str(self.fixture)
        self.observe(reopen_path_matches=matches)
        return matches

    def click(self, name, chooser=False):
        def intended():
            if not chooser:
                return self.find(name, {"push button", "button"})
            candidates = [node for node in self.chooser_nodes() if node.name == name
                          and self.showing(node) and self.role(node) in ("push button", "button")]
            self.observe(reopen_open_unique=len(candidates) == 1)
            return candidates[0] if len(candidates) == 1 else None
        node = poll(intended)
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
        self._window_sample = None
        self.app = subprocess.Popen(["/usr/bin/python3", "-m", "appimage_runtime.processes",
                                     str(self.root / "candidate.AppImage")] + ([str(self.fixture)] if with_file else []),
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
        def configure_window():
            try:
                command(["xdotool", "windowsize", self.window, "1100", "780"])
                command(["xdotool", "windowactivate", "--sync", self.window])
            except subprocess.CalledProcessError as error:
                if error.returncode != 1:
                    raise
                return False  # IceWM may not have managed the new window yet.
            return True
        poll(configure_window, reason="gui-unavailable", blocked=True)
        # The listbox is the required accessibility baseline even before opening a file.
        poll(lambda: self.find("Log entries", {"listbox"}) if with_file else self.focused_or_window(),
             reason="accessibility-unavailable", blocked=True)

    def focused_or_window(self):
        return any(self.showing(node) and self.role(node) in ("frame", "window") for node in self.nodes())

    def screenshot(self, phase):
        window = self.window
        if phase == "final":
            # A native modal can obscure the app. Capture only an active window
            # owned by this disposable case UID; never another account's UI.
            try:
                active = subprocess.check_output(["xdotool", "getactivewindow"], text=True,
                                                 timeout=5, stderr=subprocess.DEVNULL).strip()
                pid = subprocess.check_output(["xdotool", "getwindowpid", active], text=True,
                                              timeout=5, stderr=subprocess.DEVNULL).strip()
                if active.isdecimal() and pid.isdecimal() and int(pid) > 0:
                    if int(status(pid)["Uid"].split()[0]) == os.getuid():
                        window = active
            except (OSError, ValueError, subprocess.CalledProcessError):
                pass
        command(["import", "-window", window, str(self.out / f"{phase}.png")])

    def capture_failure(self):
        self.result["diagnostics"]["final_image"] = "absent"
        try:
            (self.out / "final.png").unlink(missing_ok=True)
            if self.window is not None:
                self.screenshot("final")
                self.result["diagnostics"]["final_image"] = "failure"
        except Exception:
            # Best-effort evidence must not replace the original assertion.
            try:
                (self.out / "final.png").unlink(missing_ok=True)
            except OSError:
                pass

    def exit_app(self):
        self.stage("exit")
        command(["xdotool", "windowactivate", "--sync", self.window])
        # IceWM sends the normal WM_DELETE_WINDOW request; no kill is accepted as exit evidence.
        key("alt+F4")
        def gone():
            # The dedicated supervisor succeeds only after waitpid reaches ECHILD.
            self.app.poll()
            mount_ids = {int(line.split()[0]) for line in Path("/proc/self/mountinfo").read_text().splitlines()}
            return self.app.returncode == 0 and self.proofs[-1]["mount_id"] not in mount_ids
        poll(gone, 20)
        self.application = None

    def chooser_visible(self):
        in_app = any(self.role(node) in ("file chooser", "dialog") and self.showing(node) for node in self.nodes())
        # Observation only, from this case's private accessibility bus.
        # Never act on another app or copy arbitrary names/text to evidence.
        on_desktop = False
        for app in self.atspi.Registry.getDesktop(0):
            pid = app.get_process_id()
            try:
                if pid <= 0 or int(status(pid)["Uid"].split()[0]) != os.getuid():
                    continue
            except OSError:
                continue  # A vanished app is not an observed chooser.
            on_desktop |= any(self.role(node) in ("file chooser", "dialog") and self.showing(node)
                              for node in self.walk(app))
        self.observe(reopen_chooser_in_app=in_app, reopen_chooser_on_desktop=on_desktop)
        return in_app

    def execute(self):
        self.fixture.write_text("".join(fixture_line(token, i) for i, token in enumerate(TOKENS, 1)))
        self.stage("launch")
        self.launch(True)
        self.stage("open")
        self.expect_rows(TOKENS)
        self.result["checks"]["open"] = True
        self.wait("ready", lambda: self.ready(TOKENS))
        self.screenshot("initial")
        self.stage("find-open-focus")
        key("ctrl+f")
        self.wait("find-open-focus", self.find_open)
        self.stage("find-query")
        type_text(TOKENS[1])
        self.wait("find-query", self.query_matches)
        key("Return")
        self.wait("find-selection", self.beta_selected)
        self.wait("find-count", self.match_count)
        self.result["checks"]["find"] = True
        self.screenshot("initial")  # Preserve the accepted Find state in the fixed evidence slot.
        self.stage("filter")
        self.click("Close find bar")
        key("ctrl+shift+l")
        poll(lambda: self.find("Filter", {"dialog"}) and self.focused_editable())
        type_text(TOKENS[2])
        self.click("Apply")
        self.expect_rows([TOKENS[2]])
        self.result["checks"]["filter"] = True
        self.stage("clear-filter")
        key("ctrl+shift+l")
        poll(lambda: self.find("Filter", {"dialog"}))
        self.click("Clear Filter")
        self.expect_rows(TOKENS)
        self.stage("tail")
        delta = "JAMMY_TAIL_DELTA_" + uuid.uuid4().hex.upper()
        with self.fixture.open("a") as fixture:
            fixture.write(fixture_line(delta, 4))
            fixture.flush()
            os.fsync(fixture.fileno())
        expected = TOKENS + [delta]
        self.expect_rows(expected, 15)
        self.result["checks"]["tail"] = True
        self.exit_app()
        self.stage("relaunch")
        self.launch(False)
        self.wait("ready", lambda: self.ready(None))
        self.stage("reopen")
        key("ctrl+o")
        self.wait("reopen-dialog", self.chooser_visible)
        key("ctrl+l")
        self.wait("reopen-location", self.chooser_location)
        type_text(str(self.fixture))
        self.wait("reopen-path", self.chooser_path_matches)
        # Location entry activation is not the dialog's explicit Open action,
        # particularly for the product's multi-file picker. Activate that action.
        self.stage("reopen-submit")
        self.click("Open", chooser=True)
        self.stage("reopen-count")
        self.expect_rows(expected)
        self.result["checks"]["reopen"] = True
        self.stage("final-image")
        self.screenshot("final")
        self.result["diagnostics"]["final_image"] = "acceptance"
        self.exit_app()
        self.result["checks"]["exited"] = True
        self.result.update(status="passed", reason="ok")
        self.stage("complete")


def exception_observations(error):
    # Fixed boolean categories only: never emit exception messages, tracebacks,
    # arbitrary class names, subprocess commands or accessibility strings.
    if isinstance(error, subprocess.CalledProcessError):
        category = "command"
    elif isinstance(error, OSError):
        category = "os"
    elif isinstance(error, ValueError):
        category = "value"
    elif isinstance(error, AttributeError):
        category = "attribute"
    elif isinstance(error, TypeError):
        category = "type"
    elif is_atspi_error(error):
        category = "atspi"
    else:
        category = "other"
    return {"error_" + name: name == category for name in
            ("command", "os", "value", "attribute", "type", "atspi", "other")}


def main(root, case):
    controller = None
    try:
        import pyatspi
        pyatspi.setTimeout(1500, 5000)
        command(["dbus-send", "--session", "--type=method_call", "--dest=org.a11y.Bus", "/org/a11y/bus", "org.freedesktop.DBus.Properties.Set", "string:org.a11y.Status", "string:IsEnabled", "variant:boolean:true"])
        subprocess.Popen(["icewm"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        controller = Controller(root, case, pyatspi)
        controller.execute()
    except Exception as error:
        if controller is None:
            result = blocked(case, "accessibility-unavailable")
        else:
            result = controller.result
            if isinstance(error, Blocked):
                result.update(status="blocked", reason=str(error))
            elif isinstance(error, ValueError) and str(error) == "ui-assertion":
                result.update(status="failed", reason="ui-assertion")
            else:
                result.update(status="blocked", reason="harness-error")
            controller.observe(**exception_observations(error))
            controller.capture_failure()
    else:
        result = controller.result
    area = root / case / "out"
    (area / "result.json").write_text(json.dumps(result))
    (area / "fuse.json").write_text(json.dumps(controller.proofs if controller else []))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1]), sys.argv[2]))
