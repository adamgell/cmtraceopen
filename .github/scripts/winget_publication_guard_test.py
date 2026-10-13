import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError


ROOT = Path(__file__).resolve().parents[2]
HELPER = Path(__file__).with_name("winget_publication_guard.py")
TOKEN = "guard-test-token-never-print"
MANIFEST_PATH = "manifests/a/AdamGell/CMTraceOpen/1.6.2/AdamGell.CMTraceOpen.yaml"
MANIFEST = {"type": "file", "path": MANIFEST_PATH}


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(HELPER.exists(), "merged-version guard is missing")
        spec = importlib.util.spec_from_file_location("guard", HELPER)
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)

    def run_guard(self, response=None, failure=None, tag="v1.6.2", token=TOKEN):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output"
            log = io.StringIO()
            env = {"TAG_NAME": tag, "GITHUB_TOKEN": token, "GITHUB_OUTPUT": str(output)}
            with patch.dict(os.environ, env, clear=True), patch.object(self.module.request, "build_opener") as build:
                build.return_value.open.return_value = io.BytesIO(json.dumps(response).encode())
                build.return_value.open.side_effect = failure
                with contextlib.redirect_stdout(log):
                    status = self.module.main()
                calls = build.return_value.open.call_args_list
            self.assertNotIn(TOKEN, log.getvalue())
            return status, output.read_text() if output.exists() else "", log.getvalue(), calls

    def test_merged_version_skips_publication_using_only_exact_upstream_get(self):
        status, output, log, calls = self.run_guard(MANIFEST)
        self.assertEqual(status, 0)
        self.assertEqual(output, "already_published=true\n")
        self.assertIn("already exists", log)
        self.assertEqual(len(calls), 1)
        req = calls[0].args[0]
        self.assertEqual(req.get_method(), "GET")
        self.assertEqual(req.full_url, "https://api.github.com/repos/microsoft/winget-pkgs/contents/" + MANIFEST_PATH)
        self.assertEqual(req.get_header("Authorization"), "Bearer " + TOKEN)
        self.assertIsNone(req.data)

    def test_missing_version_allows_existing_submission_path(self):
        failure = HTTPError("unused", 404, TOKEN, {}, io.BytesIO(TOKEN.encode()))
        status, output, _, _ = self.run_guard(failure=failure)
        self.assertEqual(status, 0)
        self.assertEqual(output, "already_published=false\n")

    def test_non_404_http_errors_do_not_allow_submission(self):
        for code in (401, 403, 429, 500, 503):
            with self.subTest(code=code):
                failure = HTTPError("unused", code, TOKEN, {}, io.BytesIO(TOKEN.encode()))
                status, output, log, _ = self.run_guard(failure=failure)
                self.assertEqual(status, 1)
                self.assertEqual(output, "")
                self.assertIn(str(code), log)

    def test_network_failures_do_not_allow_submission(self):
        status, output, _, _ = self.run_guard(failure=URLError(TOKEN))
        self.assertEqual(status, 1)
        self.assertEqual(output, "")

    def test_unexpected_api_responses_do_not_allow_submission(self):
        for response in (None, [], {}, {"type": "dir", "path": MANIFEST_PATH},
                         {"type": "file", "path": "unrelated/manifest.yaml"}):
            with self.subTest(response=response):
                status, output, _, _ = self.run_guard(response)
                self.assertEqual(status, 1)
                self.assertEqual(output, "")

    def test_invalid_tag_and_missing_token_make_no_request(self):
        for tag, token in (("v1.6.2/../other", TOKEN), ("v1.6.2\n", TOKEN),
                           ("", TOKEN), ("v1.6.2", "")):
            with self.subTest(tag=tag, token_present=bool(token)):
                status, output, _, calls = self.run_guard(MANIFEST, tag=tag, token=token)
                self.assertEqual(status, 1)
                self.assertEqual(output, "")
                self.assertEqual(calls, [])

    def test_unprefixed_tag_preserves_existing_version_derivation(self):
        status, output, _, calls = self.run_guard(MANIFEST, tag="1.6.2")
        self.assertEqual((status, output), (0, "already_published=true\n"))
        self.assertTrue(calls[0].args[0].full_url.endswith(MANIFEST_PATH))

    def test_redirects_are_refused(self):
        with self.assertRaises(self.module.GuardError):
            self.module.NoRedirect().redirect_request(None, None, 302, "redirect", {}, "https://example.com")


class WorkflowTests(unittest.TestCase):
    def test_release_edits_do_not_trigger_publication(self):
        workflow = (ROOT / ".github/workflows/winget-publish.yml").read_text()
        self.assertIn("types: [published]", workflow)
        self.assertNotIn("types: [published, edited]", workflow)

    def test_merged_version_guard_covers_generation_and_submission(self):
        workflow = (ROOT / ".github/workflows/winget-publish.yml").read_text()
        publisher = workflow.split("  diagnose-access:\n")[0]
        steps = publisher.split("      - name: ")
        guard = next((s for s in steps if s.startswith("Check existing winget version\n")), "")
        self.assertTrue(guard, "publication needs an upstream version check")
        self.assertIn("if: github.event_name == 'release' || inputs.submit", guard)
        self.assertIn("GITHUB_TOKEN: ${{ github.token }}", guard)
        self.assertNotIn("secrets.WINGET_PAT", guard)
        self.assertLess(publisher.index("Check existing winget version"), publisher.index("Install komac"))
        names = ("Install komac", "Derive version and URLs", "Generate manifests",
                 "Apply locale metadata", "Show patched manifest", "Submit to winget-pkgs")
        for name in names:
            step = next(s for s in steps if s.startswith(name + "\n"))
            condition = next(line for line in step.splitlines() if line.strip().startswith("if:"))
            self.assertIn("steps.publication.outputs.already_published != 'true'", condition, name)
        submit = next(s for s in steps if s.startswith("Submit to winget-pkgs\n"))
        self.assertIn("github.event_name == 'release' || inputs.submit", submit)
        self.assertIn("komac submit $manifest.Directory.FullName --yes", submit)
        self.assertIn("GITHUB_TOKEN: ${{ secrets.WINGET_PAT }}", submit)


if __name__ == "__main__":
    unittest.main()
