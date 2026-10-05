"""Offline regressions: fake accessibility and OS boundaries, no app execution."""

import copy
import importlib.util
import json
import os
import subprocess
from pathlib import Path
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from appimage_runtime import contract, session, ui


class Node:
    def __init__(self, name="", role="static", attrs=(), states=("showing",), text=None, children=()):
        self.name, self.role, self.attrs = name, role, list(attrs)
        self.states, self.value, self.children = set(states), text, list(children)

    def __iter__(self):
        return iter(self.children)

    def getRoleName(self):
        return self.role

    def getAttributes(self):
        return self.attrs

    def getState(self):
        return SimpleNamespace(contains=lambda state: state in self.states)

    def queryText(self):
        if self.value is None:
            raise NotImplementedError
        return SimpleNamespace(characterCount=len(self.value), getText=lambda start, end: self.value)


class DiagnosticsTests(unittest.TestCase):
    def api(self, obj, name):
        function = getattr(obj, name, None)
        self.assertTrue(callable(function), name + " is not implemented")
        return function

    def controller(self, *nodes):
        atspi = SimpleNamespace(STATE_SHOWING="showing", STATE_SELECTED="selected",
                                STATE_FOCUSED="focused", STATE_EDITABLE="editable")
        controller = ui.Controller(Path("/tmp/offline-fixture"), "ordinary", atspi)
        rows = [Node(token, "list item", states=("showing", "selected") if i == 1 else ("showing",))
                for i, token in enumerate(ui.TOKENS)]
        controller.application = Node(role="application", children=[Node("Log entries", "list box", children=rows), *nodes])
        controller.window = "42"
        return controller

    def entry(self, **overrides):
        return Node(**(dict(role="entry", attrs=("placeholder-text:Find...",),
                            states=("showing", "focused", "editable"), text=ui.TOKENS[1]) | overrides))

    def bar(self, count=None, text=None):
        controls = [Node(name, "toggle button" if name in ("Match case", "Use regular expression") else "push button") for name in
                    ("Match case", "Use regular expression", "Previous match", "Next match", "Close find bar")]
        return Node(role="section", text=text, children=[self.entry(), *controls] + ([count] if count else []))

    def test_find_count_accepts_scoped_section_text_and_boundary_object_markers(self):
        for bar in (self.bar(Node(role="section", text="1 of 1")),
                    self.bar(text="\ufffc 1 of 1 \ufffc\ufffc\ufffc\ufffc\ufffc")):
            self.assertTrue(self.controller(bar).match_count())

    def test_find_modes_require_actual_toggle_roles_and_navigation_requires_buttons(self):
        bar = self.bar(text="1 of 1")
        for control in bar.children[1:3]: control.role = "toggle button"
        self.assertTrue(self.controller(bar).match_count())
        for index, role in ((1, "push button"), (2, "push button"), (3, "toggle button"), (4, "toggle button"), (5, "toggle button")):
            bad = copy.deepcopy(bar); bad.children[index].role = role
            self.assertFalse(self.controller(bad).match_count())

    def test_find_count_rejects_known_failure_status_and_conflicting_nonempty_text(self):
        for status in ("No results", "Invalid regex", "1 of 1 unexpected"):
            self.assertFalse(self.controller(self.bar(Node(name="1 of 1", text=status))).match_count())
        for status in ("No results", "Invalid regex"):
            bar = self.bar(Node(name="1 of 1")); bar.children.append(Node(text=status))
            self.assertFalse(self.controller(bar).match_count())

    def test_find_count_rejects_global_decoy_when_local_count_is_wrong(self):
        controller = self.controller(self.bar(text="0 of 1"), Node(text="1 of 1"))
        self.assertFalse(controller.match_count())

    def test_find_count_rejects_ambiguous_or_broad_scope_and_unexpected_literal_text(self):
        for extra in (Node("Close find bar", "push button"), self.entry(), Node("unrelated", "push button"),
                      Node("Filter", "dialog"), Node("Log entries", "list box")):
            bar = self.bar(Node(text="1 of 1")); bar.children.append(extra)
            self.assertFalse(self.controller(bar).match_count())
        for value in ("0 of 1", "private 1 of 1", "1 of 1 .*", "1\ufffc of 1"):
            self.assertFalse(self.controller(self.bar(text=value)).match_count())
        bar = self.bar(Node(text="1 of 1")); bar.children[0].value = "wrong query"
        self.assertFalse(self.controller(bar).match_count())
        bar = self.bar(Node(text="1 of 1")); bar.states.clear()
        self.assertFalse(self.controller(bar).match_count())
        bar = self.bar(Node(name="1 of 1", text="0 of 1"))
        self.assertFalse(self.controller(bar).match_count())
        bar = self.bar(text="0 of 1")
        bar.children[1].children.append(Node(text="1 of 1"))
        self.assertFalse(self.controller(bar).match_count())
        bar = self.bar(Node(text="1 of 1"))
        self.assertFalse(self.controller(bar, self.entry()).match_count())
        bar = self.bar(Node(text="1 of 1"))
        close = bar.children.pop(5)
        self.assertFalse(self.controller(Node(role="section", children=[bar, close, Node("Log entries", "list box")])).match_count())

    def test_ready_waits_for_splash_removal_even_with_visible_fixture_rows(self):
        for splash in (Node(role="section", attrs=("id:splash",), states=()),
                       Node("Log Viewer & Troubleshooting Tool", states=()),
                       Node(text="Log Viewer & Troubleshooting Tool", states=()),
                       Node("CMTrace Open", "image", states=())):
            controller = self.controller(splash)
            ready = self.api(controller, "ready")
            with patch.object(controller, "window_geometry", return_value=(42, 0, 0, 1100, 780)):
                self.assertFalse(ready(ui.TOKENS))
                self.assertFalse(ready(ui.TOKENS))
                controller.application.children.pop()
                self.assertFalse(ready(ui.TOKENS), "first clear sample is not stable")
                self.assertTrue(ready(ui.TOKENS))

    def test_readiness_resets_on_window_or_rows_change_and_applies_to_relaunch(self):
        controller = self.controller()
        ready = self.api(controller, "ready")
        with patch.object(controller, "window_geometry", side_effect=[(42, 0, 0, 1100, 780), None,
                          (42, 2, 0, 1100, 780), (42, 2, 0, 1100, 780)]):
            self.assertFalse(ready(ui.TOKENS))
            self.assertFalse(ready(ui.TOKENS))
            self.assertFalse(ready(ui.TOKENS))
            self.assertTrue(ready(ui.TOKENS))
        with patch.object(controller, "window_geometry", return_value=(42, 2, 0, 1100, 780)):
            controller.application.children[0].children.pop()
            self.assertFalse(ready(ui.TOKENS))
            self.assertFalse(ready(None))
            self.assertTrue(ready(None))

    def test_find_requires_unique_intended_visible_focused_editable_entry(self):
        good = self.entry()
        controller = self.controller(good, self.entry(attrs=("placeholder-text:Highlight...",)))
        find = self.api(controller, "find_input")
        self.assertIs(find(), good)
        for bad in (self.entry(role="push button"), self.entry(attrs=()),
                    self.entry(states=("focused", "editable")), self.entry(states=("showing", "editable")),
                    self.entry(states=("showing", "focused"))):
            controller = self.controller(bad)
            self.assertIsNone(controller.find_input())
        self.assertIsNone(self.controller(good, self.entry()).find_input())

    def test_find_readback_rejects_wrong_input_value_and_never_records_text(self):
        entry = self.entry()
        controller = self.controller(entry)
        matches = self.api(controller, "query_matches")
        self.assertTrue(matches())
        entry.value = "private wrong query"
        self.assertFalse(matches())
        self.assertNotIn("private", json.dumps(controller.result))

    def test_count_accepts_static_name_or_text_but_requires_beta_and_all_three_rows(self):
        for count in (Node("1 of 1"), Node(text="1 of 1"), Node(role="text", text="1 of 1")):
            controller = self.controller(self.bar(count))
            count_matches = self.api(controller, "match_count")
            self.assertTrue(count_matches())
            rows = controller.application.children[0].children
            rows[1].states.discard("selected")
            rows[0].states.add("selected")
            self.assertFalse(count_matches())
            rows[0].states.discard("selected")
            rows[1].states.add("selected")
            rows.pop()
            self.assertFalse(count_matches())
        for count in (Node("1 of 1", "push button"), Node("1 of 1", states=()),
                      Node(text="0 of 1"), Node(text="private 1 of 1")):
            self.assertFalse(self.controller(self.bar(count)).match_count())

    def test_wait_records_exact_stage_elapsed_and_only_boolean_observations(self):
        controller = self.controller(self.entry())
        wait = self.api(controller, "wait")
        now = [0.0]
        def tick(seconds):
            now[0] += seconds
        with patch.object(ui.time, "monotonic", side_effect=lambda: now[0]), patch.object(ui.time, "sleep", side_effect=tick):
            with self.assertRaisesRegex(ValueError, "ui-assertion"):
                wait("find-count", controller.match_count, seconds=0.4)
        diag = controller.result["diagnostics"]
        self.assertEqual(diag["stage"], "find-count")
        self.assertEqual(diag["elapsed_ms"], 400)
        self.assertTrue(diag["observations"]["beta_selected"])
        self.assertTrue(all(type(value) is bool for value in diag["observations"].values()))

    def test_failure_image_uses_existing_slot_and_preserves_failure_if_capture_fails(self):
        controller = self.controller()
        capture = self.api(controller, "capture_failure")
        controller.result.update(status="failed", reason="ui-assertion")
        with tempfile.TemporaryDirectory() as directory:
            controller.out = Path(directory)
            with patch.object(controller, "screenshot", side_effect=lambda phase: (controller.out / (phase + ".png")).write_bytes(b"fixture")) as shot:
                capture()
                shot.assert_called_once_with("final")
                self.assertEqual(controller.result["diagnostics"]["final_image"], "failure")
            with patch.object(controller, "screenshot", side_effect=OSError):
                capture()
            self.assertEqual(controller.result["status"], "failed")
            self.assertEqual(controller.result["reason"], "ui-assertion")
            self.assertEqual(controller.result["diagnostics"]["final_image"], "absent")
            self.assertFalse((controller.out / "final.png").exists())

    def test_diagnostic_schema_rejects_free_text_unknown_fields_and_false_pass(self):
        valid = self.controller().result
        self.assertIn("diagnostics", valid, "bounded case diagnostics are missing")
        self.assertEqual(contract.sanitize_case(valid), valid)
        for key, value in (("stage", "private application text"), ("elapsed_ms", -1), ("elapsed_ms", True),
                           ("elapsed_ms", 300001), ("observations", {"raw": "secret"}),
                           ("observations", {"beta_selected": 1}), ("final_image", "secret.png")):
            bad = copy.deepcopy(valid); bad["diagnostics"][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                contract.sanitize_case(bad)
        good = copy.deepcopy(valid)
        good.update(status="passed", reason="ok", checks=dict.fromkeys(contract.CHECKS, True), counts=[3, 1, 3, 4, 4])
        with self.assertRaises(ValueError): contract.sanitize_case(good)
        good["diagnostics"].update(stage="complete", final_image="acceptance")
        contract.sanitize_case(good)

    def test_synthetic_timeout_evidence_and_cleanup_errors_do_not_claim_preflight(self):
        for reason in ("timeout", "evidence-invalid", "harness-error"):
            data = session.blocked("ordinary", reason)
            self.assertEqual(data["diagnostics"]["stage"], "unobserved")
            contract.sanitize_case(data)

    def test_session_records_preflight_only_when_observed_and_timeout_as_unobserved(self):
        for preflight_failure in (True, False):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory); (root / "proof").mkdir()
                (root / "context.json").write_text("{}")
                for case in contract.CASES: (root / case / "out").mkdir(parents=True)
                def wait(timeout):
                    if timeout == 300: raise subprocess.TimeoutExpired("offline fixture", timeout)
                    return 0
                process = SimpleNamespace(pid=123456, wait=wait)
                with patch.object(session, "preflight", side_effect=ValueError("bubblewrap-unavailable") if preflight_failure else None), patch.object(session.subprocess, "Popen", return_value=process) as spawn, patch.object(session.os, "killpg"):
                    session.main(root)
                    if preflight_failure: spawn.assert_not_called()
                for case in contract.CASES:
                    data = json.loads((root / case / "out/result.json").read_text())
                    self.assertEqual(data["diagnostics"]["stage"], "preflight" if preflight_failure else "unobserved")
                    self.assertEqual(data["reason"], "bubblewrap-unavailable" if preflight_failure else "timeout")
                    contract.sanitize_case(data)

    def test_execute_cannot_send_keys_or_screenshot_before_readiness(self):
        controller = self.controller(Node(attrs=("id:splash",)))
        with tempfile.TemporaryDirectory() as directory:
            controller.fixture = Path(directory) / "fixture.log"
            now = [0.0]
            def tick(seconds):
                now[0] += seconds
            with patch.object(controller, "launch"), patch.object(controller, "window_geometry", return_value=(42, 0, 0, 1100, 780)), patch.object(ui.time, "monotonic", side_effect=lambda: now[0]), patch.object(ui.time, "sleep", side_effect=tick), patch.object(ui, "key") as key, patch.object(ui, "type_text") as typed, patch.object(controller, "screenshot") as shot:
                with self.assertRaisesRegex(ValueError, "ui-assertion"):
                    controller.execute()
                key.assert_not_called(); typed.assert_not_called(); shot.assert_not_called()
            self.assertEqual(controller.result["diagnostics"]["stage"], "ready")
            self.assertNotIn("find", controller.result["checks"])

    def test_execute_distinguishes_each_find_failure_without_marking_find_passed(self):
        for stage in ("find-open-focus", "find-query", "find-selection", "find-count"):
            bar = self.bar(Node("1 of 1"))
            entry = bar.children[0]
            controller = self.controller(bar)
            if stage == "find-open-focus": entry.states.discard("focused")
            if stage == "find-query": entry.value = "wrong"
            if stage == "find-selection": controller.application.children[0].children[1].states.discard("selected")
            if stage == "find-count": bar.children[-1].name = "0 of 1"
            with tempfile.TemporaryDirectory() as directory:
                controller.fixture = Path(directory) / "fixture.log"
                now = [0.0]
                def tick(seconds): now[0] += seconds
                with patch.object(controller, "launch"), patch.object(controller, "window_geometry", return_value=(42, 0, 0, 1100, 780)), patch.object(ui.time, "monotonic", side_effect=lambda: now[0]), patch.object(ui.time, "sleep", side_effect=tick), patch.object(ui, "key") as key, patch.object(ui, "type_text") as typed, patch.object(controller, "screenshot"):
                    with self.assertRaisesRegex(ValueError, "ui-assertion"):
                        controller.execute()
                    self.assertEqual(controller.result["diagnostics"]["stage"], stage)
                    self.assertNotIn("find", controller.result["checks"])
                    if stage == "find-open-focus": typed.assert_not_called()
                    if stage in ("find-open-focus", "find-query"):
                        self.assertEqual(key.call_args_list, [unittest.mock.call("ctrl+f")])

    def test_window_geometry_requires_active_exact_sized_window_inside_display(self):
        controller = self.controller()
        geometry = "WINDOW=42\nX=10\nY=20\nWIDTH=1100\nHEIGHT=780\nSCREEN=0\n"
        with patch.object(ui.subprocess, "check_output", side_effect=["42\n", geometry]):
            self.assertEqual(controller.window_geometry(), (42, 10, 20, 1100, 780))
        for active, content in (("43\n", geometry), ("42\n", geometry.replace("WIDTH=1100", "WIDTH=1")),
                                ("42\n", geometry.replace("Y=20", "Y=200")), ("42\n", geometry.replace("WINDOW=42", "WINDOW=43"))):
            with patch.object(ui.subprocess, "check_output", side_effect=[active, content]):
                self.assertIsNone(controller.window_geometry())

    def test_capture_cleanup_error_cannot_mask_assertion(self):
        controller = self.controller()
        with patch.object(Path, "unlink", side_effect=PermissionError):
            controller.capture_failure()
        self.assertEqual(controller.result["diagnostics"]["final_image"], "absent")

    def test_collection_retains_bounded_failure_image_and_requires_sandbox_proof(self):
        from PIL import Image
        from appimage_runtime import host, sandbox
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); output = root / "sanitized"; output.mkdir()
            (root / "proof").mkdir()
            (root / "proof/preflight.json").write_text(json.dumps(dict(identity=True, offline=True, bubblewrap=True, fuse_device=True)))
            proof = dict(returncode=0, signal=None, timed_out=False, stderr_truncated=False, error_class="ok", policy=sandbox.unknown_policy())
            (root / "proof/sandbox.json").write_text(json.dumps(proof))
            for case in contract.CASES:
                area = root / case / "out"; area.mkdir(parents=True)
                data = session.blocked(case, "ui-assertion")
                data.update(status="failed", checks=dict(fuse=True, open=True), counts=[3])
                data["diagnostics"].update(stage="find-count", final_image="failure", observations=dict(beta_selected=True, match_name=False, match_text=False))
                (area / "result.json").write_text(json.dumps(data))
                (area / "fuse.json").write_text(json.dumps([dict(pid=1234, mount_id=53, filesystem="fuse.CMTrace", payload_root_0755=True)]))
                Image.new("RGB", (20, 20)).save(area / "final.png")
            _, cases, observed = host.collect(root, os.getuid(), output)
            self.assertEqual(observed, proof)
            self.assertTrue(all(item["status"] == "failed" and item["diagnostics"]["final_image"] == "failure" for item in cases))
            self.assertEqual(sorted(path.name for path in output.iterdir()), ["catalog-renderer-subset-final.png", "ordinary-final.png"])
            for bad in (dict(proof, error_class="other", returncode=1), dict(proof, raw="private"), None):
                path = root / "proof/sandbox.json"
                if bad is None: path.unlink()
                else: path.write_text(json.dumps(bad))
                for image in output.iterdir(): image.unlink()
                _, cases, _ = host.collect(root, os.getuid(), output)
                self.assertTrue(all(item["reason"] == "evidence-invalid" for item in cases))
                self.assertTrue(all(item["diagnostics"]["stage"] == "unobserved" for item in cases))
                self.assertEqual(list(output.iterdir()), [])


class SandboxDiagnosticsTests(unittest.TestCase):
    def sandbox(self):
        self.assertIsNotNone(importlib.util.find_spec("appimage_runtime.sandbox"), "sandbox diagnostics are missing")
        from appimage_runtime import sandbox
        return sandbox

    def test_classification_has_no_freeform_error_or_app_armor_inference(self):
        sandbox = self.sandbox()
        for raw, expected in ((b"bwrap: Creating new namespace failed: Operation not permitted private", "namespace-denied"),
                              (b"bwrap: No permissions to create new namespace", "namespace-denied"),
                              (b"bwrap: mount /private: Permission denied", "mount-denied"),
                              (b"private unknown error", "other")):
            result = sandbox.classify_error(raw)
            self.assertEqual(result, expected)
            self.assertNotIn("private", result)

    def test_policy_reads_only_fixed_files_and_missing_values_stay_unknown(self):
        sandbox = self.sandbox()
        with patch.object(sandbox, "read_small", return_value=None), patch.object(sandbox.os, "stat", side_effect=OSError), patch.object(sandbox.os, "getxattr", side_effect=OSError, create=True):
            policy = sandbox.read_policy()
        self.assertTrue(all(value is None for key, value in policy.items() if key != "current_label"))
        self.assertEqual(policy["current_label"], "unknown")
        def read(path):
            return {"/proc/sys/kernel/apparmor_restrict_unprivileged_userns": "1",
                    "/proc/sys/kernel/unprivileged_userns_clone": "1",
                    "/proc/sys/user/max_user_namespaces": "515199",
                    "/sys/module/apparmor/parameters/enabled": "Y",
                    "/proc/self/attr/current": "private-profile (enforce)"}.get(path)
        with patch.object(sandbox, "read_small", side_effect=read), patch.object(sandbox.os, "stat", return_value=SimpleNamespace(st_mode=0o100755, st_uid=0, st_gid=0)), patch.object(sandbox.os, "getxattr", return_value=b"caps", create=True):
            policy = sandbox.read_policy()
        self.assertEqual(policy["apparmor_restrict_unprivileged_userns"], 1)
        self.assertEqual(policy["current_label"], "confined")
        self.assertNotIn("private", json.dumps(policy))
        self.assertTrue(policy["bwrap_file_caps"])

    def test_probe_caps_and_classifies_stderr_preserves_exit_and_exact_command(self):
        sandbox = self.sandbox()
        raw = b"bwrap: Creating new namespace failed: Operation not permitted\n" + b"private" * 3000
        for returncode in (0, 1, -9):
            read_fd, write_fd = os.pipe()
            done = threading.Event()
            def writer():
                try:
                    with os.fdopen(write_fd, "wb") as stream:
                        stream.write(raw)
                finally:
                    done.set()
            thread = threading.Thread(target=writer)
            pipe = os.fdopen(read_fd, "rb", buffering=0)
            process = SimpleNamespace(stderr=pipe, poll=lambda: returncode if done.is_set() else None,
                                      wait=lambda timeout: returncode, kill=lambda: None)
            thread.start()
            try:
                with patch.object(sandbox.subprocess, "Popen", return_value=process) as spawn, patch.object(sandbox, "read_policy", return_value=sandbox.unknown_policy()):
                    result = sandbox.probe()
                self.assertEqual(spawn.call_args.args[0], ["/usr/bin/bwrap", "--ro-bind", "/", "/", "--", "/usr/bin/true"])
                self.assertEqual(result["returncode"], returncode)
                self.assertEqual(result["signal"], 9 if returncode == -9 else None)
                self.assertTrue(result["stderr_truncated"])
                self.assertEqual(result["error_class"], {0: "ok", 1: "namespace-denied", -9: "signal"}[returncode])
                self.assertNotIn("private", json.dumps(result))
                self.assertEqual(sandbox.sanitize(result), result)
            finally:
                pipe.close(); thread.join(timeout=2)
            self.assertFalse(thread.is_alive())

    def test_preflight_keeps_sandbox_failure_as_mandatory_gate_and_retains_proof(self):
        sandbox = self.sandbox()
        failed = dict(returncode=1, signal=None, timed_out=False, stderr_truncated=False,
                      error_class="namespace-denied", policy=sandbox.unknown_policy())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / "proof").mkdir()
            with patch.object(session, "query", return_value="[]"), patch.object(session, "status", return_value={}), patch.object(session, "namespaces", return_value={}), patch.object(contract, "validate_identity"), patch.object(session.subprocess, "run", return_value=SimpleNamespace(returncode=1)), patch.object(session.os, "access", return_value=False), patch.object(sandbox, "probe", return_value=failed), patch.object(session.os, "stat") as fuse_stat:
                with self.assertRaisesRegex(ValueError, "bubblewrap-unavailable"):
                    session.preflight(dict(uid=1234, gid=1235, namespaces={}), root)
                fuse_stat.assert_not_called()
            self.assertEqual(json.loads((root / "proof/sandbox.json").read_text()), failed)

    def test_spawn_error_and_timeout_remain_fail_closed_with_no_raw_error(self):
        sandbox = self.sandbox()
        with patch.object(sandbox, "read_policy", return_value=sandbox.unknown_policy()), patch.object(sandbox.subprocess, "Popen", side_effect=OSError("private error")):
            result = sandbox.probe()
        self.assertEqual(result["error_class"], "spawn-error")
        self.assertIsNone(result["returncode"])
        self.assertNotIn("private", json.dumps(result))
        read_fd, write_fd = os.pipe()
        pipe = os.fdopen(read_fd, "rb", buffering=0)
        killed = []
        process = SimpleNamespace(stderr=pipe, poll=lambda: -9 if killed else None,
                                  wait=lambda timeout: -9, kill=lambda: killed.append(True))
        try:
            with patch.object(sandbox, "read_policy", return_value=sandbox.unknown_policy()), patch.object(sandbox.subprocess, "Popen", return_value=process):
                result = sandbox.probe(seconds=0.01)
            self.assertEqual(result["error_class"], "timeout")
            self.assertEqual(result["returncode"], -9)
            self.assertEqual(result["signal"], 9)
            self.assertTrue(result["timed_out"])
            self.assertEqual(len(killed), 1)
        finally:
            pipe.close(); os.close(write_fd)

    def test_schema_rejects_inconsistent_exit_signal_error_and_unsanitized_policy(self):
        sandbox = self.sandbox()
        valid = dict(returncode=1, signal=None, timed_out=False, stderr_truncated=True,
                     error_class="namespace-denied", policy=sandbox.unknown_policy())
        self.assertEqual(sandbox.sanitize(valid), valid)
        for change in (dict(returncode=True), dict(signal=9), dict(returncode=0), dict(timed_out=True),
                       dict(error_class="private error"), dict(stderr="private"), dict(stderr_truncated=1),
                       dict(policy=dict(valid["policy"], current_label="private profile")),
                       dict(policy=dict(valid["policy"], bwrap_mode=True)),
                       dict(policy=dict(valid["policy"], bwrap_file_caps="yes"))):
            with self.subTest(change=change), self.assertRaises(ValueError):
                sandbox.sanitize(valid | change)
