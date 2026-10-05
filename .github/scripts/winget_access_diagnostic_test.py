import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch
from urllib.error import HTTPError


ROOT = Path(__file__).resolve().parents[2]
HELPER = Path(__file__).with_name("winget_access_diagnostic.py")
TOKEN = "owned-test-secret-never-print"
FORK = {
    "id": "R_kgDOR7rtDA", "nameWithOwner": "adamgell/winget-pkgs",
    "owner": {"login": "adamgell"}, "viewerPermission": "WRITE",
    "isArchived": False, "isDisabled": False, "isFork": True,
    "parent": {"nameWithOwner": "microsoft/winget-pkgs"},
}


class Response(io.BytesIO):
    def __init__(self, body, headers=None):
        super().__init__(json.dumps(body).encode())
        self.headers = headers or {}


class DiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(HELPER.exists(), "read-only diagnostic helper is missing")
        spec = importlib.util.spec_from_file_location("diagnostic", HELPER)
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)

    def responses(self, fork=None):
        return [Response({"login": "adamgell", "ignored": TOKEN}, {
            "X-OAuth-Scopes": "public_repo, read:user",
            "X-Accepted-OAuth-Scopes": "user", "Authorization": TOKEN,
        }), Response({"data": {"fork": fork or FORK, "byId": FORK}})]

    def test_reads_only_expected_endpoints_and_reports_allowlisted_metadata(self):
        with patch.object(self.module.request, "build_opener") as build:
            build.return_value.open.side_effect = self.responses()
            result = self.module.diagnose(TOKEN)
        calls = build.return_value.open.call_args_list
        self.assertEqual([c.args[0].full_url for c in calls],
                         ["https://api.github.com/user", "https://api.github.com/graphql"])
        self.assertEqual([c.args[0].method for c in calls], ["GET", "POST"])
        query = json.loads(calls[1].args[0].data)["query"]
        self.assertTrue(query.lstrip().startswith("query "))
        self.assertNotIn("mutation", query)
        self.assertIn('node(id: "R_kgDOR7rtDA")', query)
        self.assertIn('repository(owner: "adamgell", name: "winget-pkgs")', query)
        self.assertEqual(result["authenticated_login"], "adamgell")
        self.assertEqual(result["fork_by_name"]["viewerPermission"], "WRITE")
        self.assertTrue(result["fork_identity_matches"])
        self.assertEqual(result["oauth_scope_headers"]["X-OAuth-Scopes"], "public_repo, read:user")
        self.assertNotIn(TOKEN, json.dumps(result))
        self.assertNotIn("Authorization", json.dumps(result))

    def test_fork_identity_mismatch_is_reported(self):
        fork = dict(FORK, id="different-id")
        with patch.object(self.module.request, "build_opener") as build:
            build.return_value.open.side_effect = self.responses(fork)
            self.assertFalse(self.module.diagnose(TOKEN)["fork_identity_matches"])

    def test_graphql_error_body_is_not_exposed(self):
        with patch.object(self.module.request, "build_opener") as build:
            build.return_value.open.side_effect = [self.responses()[0], Response({"errors": [{"message": TOKEN}]})]
            with self.assertRaises(self.module.DiagnosticError) as error:
                self.module.diagnose(TOKEN)
        self.assertNotIn(TOKEN, str(error.exception))

    def test_redirect_is_rejected(self):
        handler = self.module.NoRedirect()
        with self.assertRaises(self.module.DiagnosticError):
            handler.redirect_request(None, None, 302, "redirect", {}, "https://example.com/")

    def test_http_failure_prints_status_without_body_or_credential(self):
        output = io.StringIO()
        with patch.dict(os.environ, {"GITHUB_TOKEN": TOKEN}), patch.object(self.module.request, "build_opener") as build:
            build.return_value.open.side_effect = HTTPError("https://api.github.com/user", 403, TOKEN, {}, io.BytesIO(TOKEN.encode()))
            with contextlib.redirect_stdout(output):
                self.assertEqual(self.module.main(), 1)
        self.assertIn("403", output.getvalue())
        self.assertNotIn(TOKEN, output.getvalue())

    def test_missing_token_performs_no_request(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(self.module.request, "build_opener") as build:
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(self.module.main(), 1)
            build.assert_not_called()


class WorkflowTests(unittest.TestCase):
    def test_diagnostic_and_publisher_are_mutually_exclusive(self):
        workflow = (ROOT / ".github/workflows/winget-publish.yml").read_text()
        self.assertIn("diagnostic_only:\n", workflow)
        self.assertIn("if: ${{ github.event_name != 'workflow_dispatch' || !inputs.diagnostic_only }}", workflow)
        self.assertIn("if: ${{ github.event_name == 'workflow_dispatch' && inputs.diagnostic_only }}", workflow)
        diagnostic = workflow.split("  diagnose-access:\n")[1]
        self.assertIn("environment: release", diagnostic)
        self.assertIn("GITHUB_TOKEN: ${{ secrets.WINGET_PAT }}", diagnostic)
        self.assertIn("python3 .github/scripts/winget_access_diagnostic.py", diagnostic)
        self.assertNotIn("komac", diagnostic)
        self.assertNotIn("submit", diagnostic)
        ci = (ROOT / ".github/workflows/cmtrace-ci.yml").read_text()
        self.assertIn("python3 -B -m unittest discover -s .github/scripts -p winget_access_diagnostic_test.py", ci)


if __name__ == "__main__":
    unittest.main()
