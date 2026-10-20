"""Offline private-bus and real-launch-path contracts; never execute the app."""

import copy
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from appimage_runtime import contract, session, ui

try:
    from appimage_runtime import private_bus
except ImportError:
    private_bus = None


class PrivateBusTests(unittest.TestCase):
    def api(self, name):
        self.assertIsNotNone(private_bus, "private-bus boundary is not implemented")
        return getattr(private_bus, name)

    def area(self, directory):
        area = Path(directory) / "ordinary"
        (area / "runtime").mkdir(parents=True, mode=0o700)
        return area

    def test_configuration_uses_owned_private_socket_and_external_auth_only(self):
        write = self.api("write_configuration")
        with tempfile.TemporaryDirectory(dir="/tmp", prefix="crt-") as directory:
            area = self.area(directory)
            config = write(area, os.getuid())
            text = config.read_text()
            self.assertIn(f"<listen>unix:path={area / 'runtime/bus'}</listen>", text)
            self.assertIn("<auth>EXTERNAL</auth>", text)
            self.assertIn(f'<allow user="{os.getuid()}"/>', text)
            self.assertIn("<standard_session_servicedirs/>", text)
            self.assertEqual(stat.S_IMODE(config.stat().st_mode), 0o600)
            for unsafe in ("<include", "<includedir", "tcp:", "ANONYMOUS", "system.conf", "<fork"):
                self.assertNotIn(unsafe, text)
            with self.assertRaises(FileExistsError):
                write(area, os.getuid())

    def test_configuration_rejects_root_wrong_owner_nonprivate_or_symlink_runtime(self):
        write = self.api("write_configuration")
        with tempfile.TemporaryDirectory(dir="/tmp", prefix="crt-") as directory:
            area = self.area(directory)
            for uid in (0, os.getuid() + 1):
                with self.assertRaisesRegex(ValueError, "private-bus-unavailable"):
                    write(area, uid)
            (area / "runtime").chmod(0o755)
            with self.assertRaises(ValueError):
                write(area, os.getuid())
            (area / "runtime").rmdir()
            target = area / "elsewhere"; target.mkdir(mode=0o700)
            (area / "runtime").symlink_to(target)
            with self.assertRaises(ValueError):
                write(area, os.getuid())

    def test_verification_requires_the_private_socket_and_rejects_host_bus_addresses(self):
        verify = self.api("verify")
        with tempfile.TemporaryDirectory(dir="/tmp", prefix="crt-") as directory:
            area = self.area(directory)
            address = "unix:path=" + str(area / "runtime/bus")
            with socket.socket(socket.AF_UNIX) as bus:
                bus.bind(str(area / "runtime/bus"))
                for valid in (address, address + ",guid=" + "a" * 32):
                    with patch.dict(os.environ, {"DBUS_SESSION_BUS_ADDRESS": valid}, clear=True):
                        self.assertEqual(verify(area, os.getuid()), valid)
                for bad in ("", "unix:path=/run/user/501/bus", "unix:abstract=host",
                            address + ";unix:path=/host", address + ",guid=bad"):
                    with patch.dict(os.environ, {"DBUS_SESSION_BUS_ADDRESS": bad}, clear=True), self.assertRaises(ValueError):
                        verify(area, os.getuid())
                for name in ("DBUS_SYSTEM_BUS_ADDRESS", "DBUS_STARTER_ADDRESS"):
                    with patch.dict(os.environ, {"DBUS_SESSION_BUS_ADDRESS": address, name: "host"}, clear=True), self.assertRaises(ValueError):
                        verify(area, os.getuid())

    def test_owner_queries_only_verified_bus_and_checks_pid_uid_and_stable_name(self):
        owner = self.api("owner")
        replies = ["boolean true\n", ":1.7\n", "uint32 313\n", f"uint32 {os.getuid()}\n", ":1.7\n"]
        with patch.object(private_bus, "verify", return_value="unix:path=/owned/bus"), \
                patch.object(private_bus.subprocess, "run", side_effect=[SimpleNamespace(stdout=s) for s in replies]) as run:
            self.assertEqual(owner(Path("/owned"), os.getuid()), (":1.7", 313))
        self.assertEqual(run.call_count, 5)
        for call in run.call_args_list:
            self.assertIn("--bus=unix:path=/owned/bus", call.args[0])
            self.assertNotIn("--session", call.args[0])
            self.assertEqual(call.kwargs["timeout"], 5)
            self.assertEqual(call.kwargs["stderr"], subprocess.DEVNULL)

    def test_owner_rejects_malformed_or_changed_owner_wrong_uid_and_query_failure(self):
        owner = self.api("owner")
        good = ["boolean true\n", ":1.7\n", "uint32 313\n", f"uint32 {os.getuid()}\n", ":1.7\n"]
        for index, bad in ((1, "secret"), (2, "uint32 0"), (3, "uint32 0"), (4, ":1.8")):
            replies = good.copy(); replies[index] = bad
            with patch.object(private_bus, "verify", return_value="unix:path=/owned/bus"), \
                    patch.object(private_bus.subprocess, "run", side_effect=[SimpleNamespace(stdout=s) for s in replies]), self.assertRaises(ValueError):
                owner(Path("/owned"), os.getuid())
        with patch.object(private_bus, "verify", return_value="unix:path=/owned/bus"), \
                patch.object(private_bus.subprocess, "run", side_effect=subprocess.TimeoutExpired("fixture", 5)), self.assertRaises(ValueError):
            owner(Path("/owned"), os.getuid())

    def test_absent_owner_remains_absent_without_requesting_an_app_callback(self):
        owner = self.api("owner")
        with patch.object(private_bus, "verify", return_value="unix:path=/owned/bus"), \
                patch.object(private_bus.subprocess, "run", return_value=SimpleNamespace(stdout="boolean false\n")) as run:
            self.assertIsNone(owner(Path("/owned"), os.getuid()))
            self.assertEqual(run.call_count, 1)
            self.assertIn("org.freedesktop.DBus.NameHasOwner", run.call_args.args[0])


class SingleInstanceScenarioTests(unittest.TestCase):
    def controller(self, directory):
        controller = ui.Controller(Path(directory), "ordinary", None)
        (controller.area / "data").mkdir(parents=True)
        controller.proofs = [dict(pid=313, mount_id=53, filesystem="fuse.CMTrace", payload_root_0755=True)]
        controller.app = SimpleNamespace(pid=300, poll=lambda: None)
        controller.window = "42"
        controller.owner = (":1.7", 313)
        return controller

    def test_second_real_launch_forwards_relative_file_and_preserves_primary(self):
        self.assertTrue(hasattr(ui.Controller, "handoff"), "actual two-launch handoff is missing")
        with tempfile.TemporaryDirectory() as directory:
            controller = self.controller(directory)
            child = SimpleNamespace(wait=lambda timeout: 0)
            with patch.object(ui.subprocess, "Popen", return_value=child) as spawn, \
                    patch.object(controller, "owned_mounts", return_value=["/owned/primary"]), \
                    patch.object(controller, "same_primary", return_value=True), \
                    patch.object(controller, "handoff_rows") as rows, patch.object(controller, "wait", side_effect=lambda stage, f: f()):
                controller.handoff()
            args = spawn.call_args.args[0]
            self.assertEqual(args[:2], ["/usr/bin/python3", str(Path(ui.__file__).with_name("processes.py"))])
            self.assertEqual(args[2], str(Path(directory) / "candidate.AppImage"))
            self.assertEqual(args[3], "handoff fixture.log")
            self.assertEqual(spawn.call_args.kwargs["cwd"], controller.area / "data")
            self.assertIs(controller.result["checks"]["handoff"], True)
            self.assertEqual(len(rows.call_args.args[1]), 1)
            self.assertTrue(rows.call_args.args[1][0].startswith("JAMMY_HANDOFF_"))

    def test_handoff_failure_or_timeout_never_claims_success(self):
        self.assertTrue(hasattr(ui.Controller, "handoff"))
        for outcome in (1, subprocess.TimeoutExpired("fixture", 20)):
            with tempfile.TemporaryDirectory() as directory:
                controller = self.controller(directory)
                def wait(timeout):
                    if isinstance(outcome, Exception): raise outcome
                    return outcome
                with patch.object(ui.subprocess, "Popen", return_value=SimpleNamespace(wait=wait)), \
                        patch.object(controller, "owned_mounts", return_value=[]), self.assertRaisesRegex(ValueError, "ui-assertion"):
                    controller.handoff()
                self.assertNotIn("handoff", controller.result["checks"])

    def test_same_primary_requires_fuse_pid_mount_bus_owner_and_active_window(self):
        self.assertTrue(hasattr(ui.Controller, "same_primary"))
        with tempfile.TemporaryDirectory() as directory:
            controller = self.controller(directory)
            for live, owner, mounts, geometry, expected in (
                ((313, controller.proofs[0]), (":1.7", 313), ["/owned"], (42, 0, 0, 1100, 780), True),
                ((314, controller.proofs[0]), (":1.7", 313), ["/owned"], (42, 0, 0, 1100, 780), False),
                ((313, controller.proofs[0]), (":1.8", 313), ["/owned"], (42, 0, 0, 1100, 780), False),
                ((313, controller.proofs[0]), (":1.7", 313), ["/owned", "/secondary"], (42, 0, 0, 1100, 780), False),
                ((313, controller.proofs[0]), (":1.7", 313), ["/owned"], None, False)):
                with patch.object(controller, "live_fuse", return_value=live), patch.object(ui.private_bus, "owner", return_value=owner), \
                        patch.object(controller, "owned_mounts", return_value=mounts), patch.object(controller, "window_geometry", return_value=geometry), patch.object(controller, "unique_handoff_window", return_value=True):
                    self.assertEqual(controller.same_primary(["/owned"]), expected)

    def test_handoff_rejects_extra_window_or_duplicate_visible_log_list(self):
        with tempfile.TemporaryDirectory() as directory:
            controller = self.controller(directory)
            box = SimpleNamespace(name="Log entries")
            for windows, boxes, expected in (("42\n", [box], True), ("42\n43\n", [box], False),
                                             ("43\n", [box], False), ("42\n", [box, box], False)):
                with patch.object(ui.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout=windows)), \
                        patch.object(controller, "nodes", return_value=boxes), patch.object(controller, "showing", return_value=True), \
                        patch.object(controller, "role", return_value="listbox"):
                    self.assertEqual(controller.unique_handoff_window(), expected)

    def test_handoff_rows_rechecks_original_window_after_row_observation(self):
        with tempfile.TemporaryDirectory() as directory:
            controller = self.controller(directory)
            rows = [dict(role="option", text="JAMMY_HANDOFF", selected=False)]
            def once(stage, predicate):
                result = predicate()
                if not result: raise ValueError("ui-assertion")
                return result
            for states in ([False], [True, False], [True, True]):
                controller.result["counts"] = []
                with patch.object(controller, "same_primary", side_effect=states), patch.object(controller, "rows", return_value=rows), \
                        patch.object(controller, "wait", side_effect=once):
                    if states == [True, True]:
                        controller.handoff_rows([], ["JAMMY_HANDOFF"])
                        self.assertEqual(controller.result["counts"], [1])
                    else:
                        with self.assertRaises(ValueError): controller.handoff_rows([], ["JAMMY_HANDOFF"])
                        self.assertEqual(controller.result["counts"], [])

    def test_unverified_private_bus_prevents_any_application_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            controller = self.controller(directory)
            with patch.object(ui.private_bus, "verify", side_effect=ValueError("private-bus-unavailable")), patch.object(controller, "launch") as launch:
                with self.assertRaises(ui.Blocked):
                    controller.execute()
                launch.assert_not_called()
                self.assertNotIn("private_bus", controller.result["checks"])

    def test_restart_owner_must_belong_to_new_fuse_process_and_new_bus_connection(self):
        self.assertTrue(hasattr(ui.Controller, "primary_owner"))
        with tempfile.TemporaryDirectory() as directory:
            controller = self.controller(directory)
            for owner, expected in (((":1.8", 313), (":1.8", 313)), ((":1.7", 313), None), ((":1.8", 999), None), (None, None)):
                with patch.object(ui.private_bus, "owner", return_value=owner):
                    self.assertEqual(controller.primary_owner(previous=(":1.7", 313)), expected)


class FinalBindingTests(unittest.TestCase):
    def test_pending_binding_rejects_even_a_matching_historical_tuple(self):
        self.assertTrue(hasattr(contract, "require_ready_binding"), "pending binding guard is missing")
        with patch.object(contract, "BINDING_READY", False):
            with self.assertRaisesRegex(ValueError, "binding-pending"):
                contract.require_ready_binding()
            with self.assertRaisesRegex(ValueError, "binding-pending"):
                contract.validate_binding({}, "0" * 64)

    def test_new_acceptance_checks_and_handoff_count_are_mandatory(self):
        for name in ("private_bus", "single_instance_owner", "handoff", "single_instance_release", "single_instance_restart"):
            self.assertIn(name, contract.CHECKS)
        good = dict(case="ordinary", status="passed", reason="ok", checks=dict.fromkeys(contract.CHECKS, True),
                    counts=[3, 1, 3, 4, 1, 4], diagnostics=dict(contract.diagnostics(), stage="complete", final_image="acceptance"))
        self.assertEqual(contract.sanitize_case(good), good)
        for name in contract.CHECKS:
            bad = copy.deepcopy(good); bad["checks"].pop(name)
            with self.assertRaises(ValueError): contract.sanitize_case(bad)
        bad = copy.deepcopy(good); bad["counts"] = [3, 1, 3, 4, 4]
        with self.assertRaises(ValueError): contract.sanitize_case(bad)


if __name__ == "__main__":
    unittest.main()
