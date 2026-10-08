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

    def getRole(self):
        return {"entry":79, "text":61}.get(self.role, 0)

    def getRoleName(self):
        return self.role

    def getAttributes(self):
        return self.attrs

    def getState(self):
        return SimpleNamespace(contains=lambda state: state in self.states)

    def queryEditableText(self):
        if self.role not in ("entry", "text"):
            raise NotImplementedError
        return SimpleNamespace()

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
                                STATE_FOCUSED="focused", STATE_EDITABLE="editable", ROLE_ENTRY=79, ROLE_TEXT=61)
        controller = ui.Controller(Path("/tmp/offline-fixture"), "ordinary", atspi)
        rows = [Node(token, "list item", states=("showing", "selected") if i == 1 else ("showing",))
                for i, token in enumerate(ui.TOKENS)]
        controller.application = Node(role="application", children=[Node("Log entries", "list box", children=rows), *nodes])
        controller.window = "42"
        return controller

    def entry(self, **overrides):
        return Node(**(dict(role="entry", attrs=("placeholder-text:Find...", "tag:input"),
                            states=("showing", "focused", "editable"), text=ui.TOKENS[1]) | overrides))

    def bar(self, count=None, text="1 of 1"):
        controls = [Node(name, "toggle button" if name in ("Match case", "Use regular expression") else "push button") for name in
                    ("Match case", "Use regular expression", "Previous match", "Next match", "Close find bar")]
        status = count if count is not None else Node("Find results", "status", text=text)
        return Node("Find bar", "group", children=[self.entry(), *controls, status])

    def test_find_count_requires_named_group_and_named_status_text(self):
        self.assertTrue(self.controller(self.bar()).match_count())
        for role in ("section", "application", "document"):
            bar = self.bar(); bar.role = role
            self.assertFalse(self.controller(bar).match_count())
        for name in ("", "Other bar"):
            bar = self.bar(); bar.name = name
            self.assertFalse(self.controller(bar).match_count())
        for count in (Node("1 of 1"), Node(text="1 of 1"), Node("Other results", "status", text="1 of 1"),
                      Node("Find results", "status", text="1 of 1", states=())):
            self.assertFalse(self.controller(self.bar(count)).match_count())

    def test_unexpected_scope_role_diagnostics_remain_fixed_booleans_and_fail_closed(self):
        for role in ("status bar", "panel", "private unsupported role"):
            controller = self.controller(self.bar(Node("Find results", role, attrs=("tag:span",), text="1 of 1")))
            self.assertFalse(controller.match_count())
            facts = controller.result["diagnostics"]["observations"]
            self.assertTrue(facts["scope_unexpected_named_status"])
            self.assertTrue(facts["scope_unexpected_tag_span"])
            self.assertEqual(facts["scope_unexpected_role_statusbar"], role == "status bar")
            self.assertEqual(facts["scope_unexpected_role_other"], role == "private unsupported role")
            contract.sanitize_diagnostics(controller.result["diagnostics"])
            self.assertNotIn("private", json.dumps(controller.result))

    def test_unexpected_control_descendant_diagnostics_do_not_accept_count_decoys(self):
        bar = self.bar(text="0 of 1")
        bar.children[1].children.append(Node("1 of 1", "redundant object", attrs=("tag:svg",)))
        controller = self.controller(bar)
        self.assertFalse(controller.match_count())
        facts = controller.result["diagnostics"]["observations"]
        for key in ("scope_unexpected_in_control", "scope_unexpected_name_count", "scope_unexpected_role_redundant", "scope_unexpected_tag_svg", "scope_unexpected_showing"):
            self.assertTrue(facts[key])
        contract.sanitize_diagnostics(controller.result["diagnostics"])

    def test_find_modes_require_actual_toggle_roles_and_navigation_requires_buttons(self):
        for index, role in ((1, "push button"), (2, "push button"), (3, "toggle button"), (4, "toggle button"), (5, "toggle button")):
            bar = self.bar(); bar.children[index].role = role
            self.assertFalse(self.controller(bar).match_count())

    def test_find_count_rejects_wrong_status_and_global_or_control_decoys(self):
        for text in ("0 of 1", "No results", "Invalid regex", "private 1 of 1", "1 of 1 unexpected", "1\ufffc of 1", ""):
            bar = self.bar(text=text)
            self.assertFalse(self.controller(bar, Node("Find results", "status", text="1 of 1")).match_count())
            bar.children[1].children.append(Node("Find results", "status", text="1 of 1"))
            self.assertFalse(self.controller(bar).match_count())

    def test_find_count_rejects_ambiguous_scope_controls_and_status(self):
        for extra in (Node("Close find bar", "push button"), self.entry(), Node("unrelated", "push button"),
                      Node("Filter", "dialog"), Node("Log entries", "list box"), Node("Find results", "status", text="1 of 1")):
            bar = self.bar(); bar.children.append(extra)
            self.assertFalse(self.controller(bar).match_count())
        bar = self.bar(); bar.children[0].value = "wrong query"
        self.assertFalse(self.controller(bar).match_count())
        bar = self.bar(); bar.states.clear()
        self.assertFalse(self.controller(bar).match_count())
        self.assertFalse(self.controller(self.bar(), self.bar()).match_count())
        self.assertFalse(self.controller(self.bar(), self.entry()).match_count())
        bar = self.bar(); close = bar.children.pop(5)
        self.assertFalse(self.controller(Node(role="section", children=[bar, close])).match_count())

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
        for bad in (self.entry(role="push button", attrs=("placeholder-text:Find...", "tag:button")), self.entry(attrs=()),
                    self.entry(states=("focused", "editable")), self.entry(states=("showing", "editable")),
                    self.entry(states=("showing", "focused"))):
            controller = self.controller(bad)
            self.assertIsNone(controller.find_input())
        self.assertIsNone(self.controller(good, self.entry()).find_input())

    def test_find_diagnostics_distinguish_placeholder_role_visibility_without_relaxing_selector(self):
        for node, entry, showing in ((self.entry(role="static", attrs=("placeholder-text:Find...", "tag:span")), False, True),
                                     (self.entry(states=("focused", "editable")), True, False)):
            controller = self.controller(node)
            self.assertIsNone(controller.find_input())
            facts = controller.result["diagnostics"]["observations"]
            self.assertTrue(facts["find_placeholder_present"])
            self.assertTrue(facts["find_placeholder_unique"])
            self.assertEqual(facts["find_placeholder_entry"], entry)
            self.assertEqual(facts["find_placeholder_showing"], showing)
            contract.sanitize_diagnostics(controller.result["diagnostics"])
        controller = self.controller(self.entry(attrs=(), name="Find..."))
        self.assertIsNone(controller.find_input())
        self.assertTrue(controller.result["diagnostics"]["observations"]["find_name_present"])
        self.assertFalse(controller.result["diagnostics"]["observations"]["find_placeholder_present"])

    def test_exception_diagnostics_are_fixed_boolean_categories_without_private_strings(self):
        for error, category in ((ValueError("private value"), "value"),
                                (TypeError("private type"), "type"),
                                (AttributeError("private attribute"), "attribute"),
                                (OSError("private path"), "os"),
                                (subprocess.CalledProcessError(1, "private command"), "command"),
                                (RuntimeError("private other"), "other")):
            facts = ui.exception_observations(error)
            self.assertTrue(facts["error_"+category])
            self.assertEqual(sum(facts.values()), 1)
            diagnostic=contract.diagnostics(); diagnostic["observations"]=facts
            contract.sanitize_diagnostics(diagnostic)
            self.assertNotIn("private", json.dumps(facts))

    def test_bubblewrap_id_map_denial_classification_does_not_emit_raw_stderr(self):
        from appimage_runtime import sandbox
        for marker in (b"uid map", b"gid map", b"uid_map", b"gid_map"):
            self.assertEqual(sandbox.classify_error(b"private: "+marker+b": Permission denied"), "id-map-denied")
        self.assertEqual(sandbox.classify_error(b"private: uid map: unknown error"), "other")

    def test_declared_input_handles_non_entry_role_name_without_accepting_static_text(self):
        intended=self.entry(role="text")
        intended.getRole=lambda: 79
        controller=self.controller(intended)
        self.assertIs(controller.find_input(), intended)
        bar=self.bar(text="1 of 1"); bar.children[0]=intended
        self.assertTrue(self.controller(bar).match_count())
        static=self.entry(role="text", attrs=("placeholder-text:Find...",))
        self.assertIsNone(self.controller(static).find_input())

    def test_transient_atspi_error_resamples_but_repeated_errors_never_pass(self):
        Error=type("Error", (Exception,), {"__module__":"gi.repository.GLib"})
        with patch.object(ui.time, "sleep"):
            sequence=iter((Error("private object"), True))
            def sample():
                value=next(sequence)
                if isinstance(value, Exception): raise value
                return value
            self.assertTrue(ui.poll(sample))
        now=[0.0]
        def tick(seconds): now[0]+=seconds
        def inaccessible(): raise Error("private unavailable")
        with patch.object(ui.time, "monotonic", side_effect=lambda: now[0]), patch.object(ui.time, "sleep", side_effect=tick):
            with self.assertRaisesRegex(ui.Blocked, "accessibility-unavailable"):
                ui.poll(inaccessible, seconds=0.4)
        def unrelated(): raise TypeError("implementation defect")
        with self.assertRaises(TypeError): ui.poll(unrelated)

    def test_input_requires_html_tag_and_editable_state_and_preserves_scope(self):
        intended=self.entry(role="text")
        self.assertIs(self.controller(intended).find_input(), intended)
        bar=self.bar(text="1 of 1"); bar.children[0]=intended
        self.assertTrue(self.controller(bar).match_count())
        for bad in (self.entry(role="text", attrs=("placeholder-text:Find...", "tag:span")),
                    self.entry(role="text", states=("showing", "focused")),
                    self.entry(role="push button", attrs=("placeholder-text:Find...", "tag:button"))):
            self.assertIsNone(self.controller(bad).find_input())

    def test_tree_mutation_atspi_error_is_resampled_without_skipping_children(self):
        Error=type("Error", (Exception,), {"__module__":"gi.repository.GLib"})
        controller=self.controller()
        original=controller.application.children[0]
        class MutatingNode(Node):
            def __iter__(self): raise Error("private missing child")
        controller.application.children[0]=MutatingNode()
        with self.assertRaises(Error): controller.nodes()
        controller.application.children[0]=original
        self.assertTrue(controller.nodes())

    def test_count_failure_stops_acceptance_before_later_checks(self):
        controller = self.controller()
        def wait(stage, predicate, *args, **kwargs):
            controller.stage(stage)
            if stage == "find-count":
                raise ValueError("ui-assertion")
        with tempfile.TemporaryDirectory() as directory, patch.object(controller, "launch"), patch.object(controller, "wait", side_effect=wait), patch.object(controller, "expect_rows"), patch.object(controller, "screenshot"), patch.object(controller, "click") as click, patch.object(ui, "key"), patch.object(ui, "type_text"):
            controller.fixture = Path(directory) / "fixture.log"
            with self.assertRaisesRegex(ValueError, "ui-assertion"):
                controller.execute()
        self.assertNotIn("find", controller.result["checks"])
        self.assertNotIn("filter", controller.result["checks"])
        click.assert_not_called()
        self.assertEqual(controller.result["diagnostics"]["stage"], "find-count")

    def test_external_chooser_diagnostic_is_read_only_and_rejects_other_accounts(self):
        controller=self.controller()
        original=controller.application
        external=Node(role="application",children=[Node(role="dialog")])
        external.get_process_id=lambda: 123
        controller.atspi.Registry=SimpleNamespace(getDesktop=lambda index:[external])
        with patch.object(ui,"status",return_value={"Uid":str(os.getuid())}):
            self.assertFalse(controller.chooser_visible())
        self.assertIs(controller.application,original)
        facts=controller.result["diagnostics"]["observations"]
        self.assertFalse(facts["reopen_chooser_in_app"])
        self.assertTrue(facts["reopen_chooser_on_desktop"])
        with patch.object(ui,"status",return_value={"Uid":str(os.getuid()+1)}):
            self.assertFalse(controller.chooser_visible())
        self.assertFalse(facts["reopen_chooser_on_desktop"])
        contract.sanitize_diagnostics(controller.result["diagnostics"])

    def test_chooser_location_requires_unique_native_dialog_field_and_exact_path_readback(self):
        intended=self.entry(text="/tmp/offline-fixture/ordinary/data/runtime-fixture.log")
        unrelated=self.entry(text="private unrelated")
        dialog=Node(role="dialog",children=[intended])
        controller=self.controller(dialog,unrelated)
        self.assertIs(controller.chooser_location(),intended)
        self.assertTrue(controller.chooser_path_matches())
        intended.value="private wrong path"
        self.assertFalse(controller.chooser_path_matches())
        self.assertNotIn("private",json.dumps(controller.result))
        dialog.children.append(self.entry())
        self.assertIsNone(controller.chooser_location())

    def test_native_final_capture_requires_active_window_owner_to_match_case_uid(self):
        controller=self.controller()
        for uid,expected in ((os.getuid(),"84"),(os.getuid()+1,"42")):
            with patch.object(ui.subprocess,"check_output",side_effect=["84","123"]), patch.object(ui,"status",return_value={"Uid":str(uid)}), patch.object(ui,"command") as run:
                controller.screenshot("final")
                self.assertEqual(run.call_args.args[0][2],expected)
        with patch.object(ui.subprocess,"check_output") as observe,patch.object(ui,"command") as run:
            controller.screenshot("initial")
            observe.assert_not_called()
            self.assertEqual(run.call_args.args[0][2],"42")

    def test_native_open_action_is_scoped_to_dialog_not_a_main_window_decoy(self):
        intended=Node("Open","push button")
        action=SimpleNamespace(nActions=1,getName=lambda index:"click",doAction=lambda index:True)
        intended.queryAction=lambda:action
        decoy=Node("Open","push button")
        decoy.queryAction=lambda:self.fail("main-window decoy activated")
        controller=self.controller(Node(role="dialog",children=[intended]),decoy)
        controller.click("Open",chooser=True)
        self.assertTrue(controller.result["diagnostics"]["observations"]["reopen_open_unique"])

    def test_find_readback_rejects_wrong_input_value_and_never_records_text(self):
        entry = self.entry()
        controller = self.controller(entry)
        matches = self.api(controller, "query_matches")
        self.assertTrue(matches())
        entry.value = "private wrong query"
        self.assertFalse(matches())
        self.assertNotIn("private", json.dumps(controller.result))

    def test_count_requires_beta_selection_and_all_three_rows(self):
        controller = self.controller(self.bar())
        self.assertTrue(controller.match_count())
        rows = controller.application.children[0].children
        rows[1].states.discard("selected"); rows[0].states.add("selected")
        self.assertFalse(controller.match_count())
        rows[0].states.discard("selected"); rows[1].states.add("selected")
        rows.pop()
        self.assertFalse(controller.match_count())

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

    def test_collection_preserves_failure_when_unclaimed_image_cleanup_fails(self):
        from PIL import Image
        from appimage_runtime import host, sandbox
        for failure in ("stale", "partial", "symlink"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); output = root / "sanitized"; output.mkdir()
                (root / "proof").mkdir()
                (root / "proof/preflight.json").write_text(json.dumps(dict(identity=True, offline=True, bubblewrap=True, fuse_device=True)))
                proof = dict(returncode=0, signal=None, timed_out=False, stderr_truncated=False,
                             error_class="ok", policy=sandbox.unknown_policy())
                (root / "proof/sandbox.json").write_text(json.dumps(proof))
                for case in contract.CASES:
                    controller = self.controller()
                    controller.out = root / case / "out"; controller.out.mkdir(parents=True)
                    controller.result.update(case=case, status="failed", reason="ui-assertion",
                                             checks=dict(open=True), counts=[3])
                    controller.result["diagnostics"].update(stage="exit", observations=dict(beta_selected=True))
                    final = controller.out / "final.png"
                    if failure == "stale": Image.new("RGB", (20, 20)).save(final)
                    if failure == "symlink":
                        (root / "private-not-an-image").write_bytes(b"must not be read")
                        final.symlink_to(root / "private-not-an-image")
                    def partial_capture(phase):
                        self.assertEqual(phase, "final")
                        final.write_bytes(b"incomplete PNG: never upload")
                        raise OSError("capture failed")
                    unlink_effect = [None, PermissionError()] if failure == "partial" else PermissionError()
                    with patch.object(Path, "unlink", side_effect=unlink_effect), patch.object(controller, "screenshot", side_effect=partial_capture):
                        controller.capture_failure()
                    self.assertEqual(controller.result["diagnostics"]["final_image"], "absent")
                    (controller.out / "result.json").write_text(json.dumps(controller.result))
                read_owned = contract.read_owned_file
                def read_claimed(path, uid, limit):
                    self.assertNotEqual(path.name, "final.png", "unclaimed image must not be read")
                    return read_owned(path, uid, limit)
                with patch.object(contract, "read_owned_file", side_effect=read_claimed):
                    _, cases, _ = host.collect(root, os.getuid(), output)
                for data in cases:
                    self.assertEqual((data["status"], data["reason"], data["diagnostics"]["stage"]),
                                     ("failed", "ui-assertion", "exit"))
                    self.assertEqual(data["checks"], dict(open=True))
                    self.assertEqual(data["diagnostics"]["observations"], dict(beta_selected=True))
                self.assertEqual(list(output.iterdir()), [])

    def test_collection_rejects_missing_or_invalid_claimed_final_image(self):
        from appimage_runtime import host
        for image in (None, b"invalid PNG"):
            with self.subTest(image=image), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); output = root / "sanitized"; output.mkdir()
                for case in contract.CASES:
                    area = root / case / "out"; area.mkdir(parents=True)
                    data = session.blocked(case, "ui-assertion")
                    data.update(status="failed")
                    data["diagnostics"].update(stage="exit", final_image="failure")
                    (area / "result.json").write_text(json.dumps(data))
                    if image is not None: (area / "final.png").write_bytes(image)
                _, cases, _ = host.collect(root, os.getuid(), output)
                self.assertTrue(all(data["reason"] == "evidence-invalid" for data in cases))
                self.assertEqual(list(output.iterdir()), [])

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

    def test_probe_retains_timeout_when_bounded_reap_waits_expire(self):
        sandbox = self.sandbox()
        for outcome in ("unreaped", "second-wait", "poll-race"):
            with self.subTest(outcome=outcome):
                read_fd, write_fd = os.pipe()
                pipe = os.fdopen(read_fd, "rb", buffering=0)
                waits, kills, state = [], [], dict(returncode=None)
                def wait(timeout):
                    waits.append(timeout)
                    if outcome == "poll-race" or outcome == "second-wait" and len(waits) == 2:
                        state["returncode"] = -9
                    if len(waits) == 1 or outcome == "unreaped":
                        raise subprocess.TimeoutExpired("offline fixture", timeout)
                    return state["returncode"]
                process = SimpleNamespace(stderr=pipe, poll=lambda: state["returncode"],
                                          wait=wait, kill=lambda: kills.append(True))
                try:
                    with patch.object(sandbox, "read_policy", return_value=sandbox.unknown_policy()), patch.object(sandbox.subprocess, "Popen", return_value=process):
                        try:
                            result = sandbox.probe(seconds=0)
                        except subprocess.TimeoutExpired:
                            self.fail("bounded reap timeout discarded the probe diagnostics")
                    self.assertEqual(result["error_class"], "timeout")
                    self.assertTrue(result["timed_out"])
                    self.assertEqual(result["returncode"], None if outcome == "unreaped" else -9)
                    self.assertEqual(result["signal"], None if outcome == "unreaped" else 9)
                    self.assertEqual(waits, [3] if outcome == "poll-race" else [3, 3])
                    self.assertEqual(len(kills), 1 if outcome == "poll-race" else 2)
                    self.assertTrue(pipe.closed)
                    self.assertEqual(sandbox.sanitize(result), result)
                finally:
                    pipe.close(); os.close(write_fd)

    def test_unknown_timeout_exit_is_retained_but_cannot_pass_preflight(self):
        sandbox = self.sandbox()
        proof = dict(returncode=None, signal=None, timed_out=True, stderr_truncated=False,
                     error_class="timeout", policy=sandbox.unknown_policy())
        try:
            self.assertEqual(sandbox.sanitize(proof), proof)
        except ValueError:
            self.fail("unobserved exit after a reap timeout must remain a valid diagnostic")
        for change in (dict(error_class="ok"), dict(timed_out=False), dict(signal=9)):
            with self.subTest(change=change), self.assertRaises(ValueError):
                sandbox.sanitize(proof | change)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / "proof").mkdir()
            (root / "context.json").write_text(json.dumps(dict(uid=1234, gid=1235, namespaces={})))
            for case in contract.CASES: (root / case / "out").mkdir(parents=True)
            with patch.object(session, "query", return_value="[]"), patch.object(session, "status", return_value={}), patch.object(session, "namespaces", return_value={}), patch.object(contract, "validate_identity"), patch.object(session.subprocess, "run", return_value=SimpleNamespace(returncode=1)), patch.object(session.os, "access", return_value=False), patch.object(sandbox, "probe", return_value=proof), patch.object(session.os, "stat") as fuse_stat, patch.object(session.subprocess, "Popen") as spawn:
                self.assertEqual(session.main(root), 1)
                fuse_stat.assert_not_called(); spawn.assert_not_called()
            self.assertEqual(json.loads((root / "proof/sandbox.json").read_text()), proof)
            for case in contract.CASES:
                result = json.loads((root / case / "out/result.json").read_text())
                self.assertEqual((result["status"], result["reason"], result["diagnostics"]["stage"]),
                                 ("blocked", "bubblewrap-unavailable", "preflight"))
