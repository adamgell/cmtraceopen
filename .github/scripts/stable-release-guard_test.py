import importlib.util
from pathlib import Path
import unittest

SCRIPT = Path(__file__).with_name('stable-release-guard.py')

class StableReleaseTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('guard', SCRIPT)
        self.guard = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.guard)
        self.release = {'tag_name': 'v1.6.3', 'draft': False, 'prerelease': False, 'published_at': '2026-10-10T12:00:00Z'}

    def test_accepts_published_stable(self):
        self.guard.validate_release('v1.6.3', self.release)

    def test_accepts_numeric_stable_tag_supported_by_release_workflow(self):
        self.guard.validate_release('1.6.3', self.release | {'tag_name': '1.6.3'})

    def test_rejects_nightly_and_malformed_tags(self):
        for tag in ['nightly', 'v1.6.3-nightly', 'v01.6.3', '../main', 'v1.6.3\n']:
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                self.guard.validate_release(tag, self.release)

    def test_rejects_draft_prerelease_unpublished_and_missing_flags(self):
        for changes in [{'draft': True}, {'prerelease': True}, {'published_at': None}, {'draft': None}, {'prerelease': 0}]:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.guard.validate_release('v1.6.3', self.release | changes)

    def test_rejects_wrong_release(self):
        with self.assertRaises(ValueError):
            self.guard.validate_release('v1.6.2', self.release)

    def test_workflow_guards_before_tool_download(self):
        workflow = (SCRIPT.parents[1] / 'workflows/winget-publish.yml').read_text()
        self.assertLess(workflow.index('stable-release-guard.py'), workflow.index('- name: Install komac'))

if __name__ == '__main__':
    unittest.main()
