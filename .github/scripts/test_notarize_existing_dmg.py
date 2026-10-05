"""Offline tests: external GitHub/Apple boundaries are replaced; no credentials/network."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).with_name('notarize-existing-dmg.py')


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(SCRIPT.exists(), 'missing bounded notarization implementation')
        spec = importlib.util.spec_from_file_location('notarize', SCRIPT)
        self.m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.m)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.env = {'GITHUB_REPOSITORY': self.m.REPO, 'GITHUB_EVENT_NAME': 'workflow_dispatch',
                    'GITHUB_REF': 'refs/heads/main', 'GITHUB_SHA': 'a' * 40,
                    'GITHUB_WORKFLOW_SHA': 'a' * 40, 'REVIEWED_WORKFLOW_SHA': 'a' * 40,
                    'GITHUB_WORKFLOW_REF': self.m.REPO + '/.github/workflows/notarize-existing-dmg.yml@refs/heads/main',
                    'GITHUB_RUN_ID': '12345', 'GITHUB_RUN_ATTEMPT': '1',
                    'APPLE_ID': 'private@example.test', 'APPLE_PASSWORD': 'secret-do-not-retain',
                    'APPLE_TEAM_ID': 'CRHL85PH9Y'}
        self.patch_env = patch.dict(os.environ, self.env, clear=True)
        self.patch_env.start()
        self.addCleanup(self.patch_env.stop)
        self.sid = 'abcdefab-cdef-4abc-8def-abcdefabcdef'

    def prepare_local(self):
        data = b'already signed frozen fixture'
        (self.root / self.m.NAME).write_bytes(data)
        self.addCleanup(patch.stopall)
        patch.object(self.m, 'SHA256', hashlib.sha256(data).hexdigest()).start()
        patch.object(self.m, 'SIZE', len(data)).start()
        self.m.write_json(self.root / 'prepared.json', {'context': self.m.context(), 'sha256': self.m.SHA256})

    def apple(self, mode='accepted'):
        def run(args, **kwargs):
            self.calls.append(args)
            verb = args[2]
            if verb == 'submit':
                if mode == 'timeout':
                    raise subprocess.TimeoutExpired(args, 120, output=b'secret-do-not-retain')
                if mode == 'malformed':
                    return subprocess.CompletedProcess(args, 1, 'secret-do-not-retain', 'private@example.test')
                return subprocess.CompletedProcess(args, 0, json.dumps({'id': self.sid.upper() if mode == 'upper-submit' else self.sid}), '')
            if verb == 'wait':
                self.assertEqual(json.loads((self.root / 'submission.json').read_text())['id'], self.sid)
                if mode == 'pending':
                    raise subprocess.TimeoutExpired(args, 510)
                return subprocess.CompletedProcess(args, 0, json.dumps({'id': self.sid.upper() if mode == 'upper-wait' else self.sid, 'status': 'Accepted'}), '')
            if verb == 'log':
                log = {'jobId': self.sid, 'status': 'Accepted', 'sha256': self.m.SHA256,
                       'archiveFilename': self.m.NAME, 'ticketContents': [{'cdhash': self.m.CDHASH}],
                       'issues': [{'severity': 'warning', 'message': 'private@example.test secret-do-not-retain'}]}
                if mode == 'wrong-log':
                    log['sha256'] = 'f' * 64
                if mode == 'upper-log':
                    log['jobId'] = self.sid.upper()
                if mode == 'wrong-id':
                    log['jobId'] = 'ffffffff-ffff-4fff-8fff-ffffffffffff'
                Path(args[4]).write_text(json.dumps(log))
                return subprocess.CompletedProcess(args, 0, '', '')
            self.fail('unexpected external command')
        return run

    def test_context_rejects_reruns_unreviewed_refs_and_wrong_repo(self):
        self.m.context()
        for key, value in [('GITHUB_RUN_ATTEMPT', '2'), ('GITHUB_EVENT_NAME', 'push'),
                           ('GITHUB_SHA', 'b' * 40), ('GITHUB_REF', 'refs/tags/v1.6.2'),
                           ('GITHUB_REPOSITORY', 'someone/else')]:
            with self.subTest(key=key), patch.dict(os.environ, {key: value}):
                with self.assertRaises(self.m.Stop): self.m.context()

    def test_frozen_release_metadata_rejects_replacements_and_publication(self):
        asset = {'id': self.m.ASSET, 'name': self.m.NAME, 'size': self.m.SIZE,
                 'digest': 'sha256:' + self.m.SHA256, 'state': 'uploaded', 'updated_at': self.m.UPDATED}
        release = {'id': self.m.RELEASE, 'tag_name': self.m.TAG, 'draft': True, 'prerelease': False, 'assets': [asset]}
        self.m.validate_release(release)
        for key, value in [('id', 1), ('size', 1), ('digest', 'sha256:' + 'f' * 64), ('updated_at', 'later')]:
            bad = copy.deepcopy(release); bad['assets'][0][key] = value
            with self.subTest(key=key), self.assertRaises(self.m.Stop): self.m.validate_release(bad)
        for key in ['draft', 'prerelease']:
            bad = copy.deepcopy(release); bad[key] = not bad[key]
            with self.assertRaises(self.m.Stop): self.m.validate_release(bad)

    def test_one_submit_and_id_persisted_before_polling_without_credentials_in_evidence(self):
        self.prepare_local(); self.calls = []
        with patch.object(subprocess, 'run', side_effect=self.apple()): self.m.submit(self.root)
        self.assertEqual([c[2] for c in self.calls], ['submit', 'wait', 'log'])
        self.assertEqual(json.loads((self.root / 'notarization.json').read_text())['status'], 'Accepted')
        retained = ''.join(p.read_text() for p in self.root.glob('*.json'))
        for secret in self.env['APPLE_ID'], self.env['APPLE_PASSWORD'], self.env['APPLE_TEAM_ID']:
            self.assertNotIn(secret, retained)
        self.assertNotIn('--password', retained)
        with patch.object(subprocess, 'run') as run, self.assertRaises(self.m.Stop): self.m.submit(self.root)
        run.assert_not_called()

    def test_unknown_upload_never_retries_or_retains_raw_error(self):
        for mode in ['timeout', 'malformed']:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                self.root = Path(tmp); self.prepare_local(); self.calls = []
                with patch.object(subprocess, 'run', side_effect=self.apple(mode)), self.assertRaises(self.m.Stop): self.m.submit(self.root)
                self.assertEqual([c[2] for c in self.calls], ['submit'])
                self.assertTrue((self.root / 'submission-intent.json').exists())
                retained = ''.join(p.read_text() for p in self.root.glob('*.json'))
                self.assertNotIn('secret-do-not-retain', retained)
                self.assertEqual(json.loads((self.root / 'notarization.json').read_text())['status'], 'Upload outcome uncertain')

    def test_poll_timeout_preserves_id_and_stops(self):
        self.prepare_local(); self.calls = []
        with patch.object(subprocess, 'run', side_effect=self.apple('pending')), self.assertRaises(self.m.Stop): self.m.submit(self.root)
        self.assertEqual([c[2] for c in self.calls], ['submit', 'wait'])
        self.assertEqual(json.loads((self.root / 'submission.json').read_text())['id'], self.sid)

    def test_mismatched_apple_log_fails_acceptance(self):
        self.prepare_local(); self.calls = []
        with patch.object(subprocess, 'run', side_effect=self.apple('wrong-log')), self.assertRaises(self.m.Stop): self.m.submit(self.root)
        self.assertNotEqual(json.loads((self.root / 'notarization.json').read_text())['status'], 'Accepted')

    def test_changed_bytes_or_context_block_submission_before_secret_use(self):
        self.prepare_local(); (self.root / self.m.NAME).write_bytes(b'changed')
        with patch.object(subprocess, 'run') as run, self.assertRaises(self.m.Stop): self.m.submit(self.root)
        run.assert_not_called()

    def test_any_previous_dispatch_blocks_a_second_upload(self):
        self.m.validate_history([{'workflow_runs': [{'id': 12345}]}], '12345')
        for pages in [[], [{'workflow_runs': [{'id': 12345}]}, {'workflow_runs': [{'id': 12344}]}]]:
            with self.assertRaises(self.m.Stop): self.m.validate_history(pages, '12345')

    def test_producer_requires_original_source_event_attempt_and_success(self):
        run = {'id': self.m.PRODUCER, 'head_sha': self.m.SOURCE, 'head_branch': self.m.TAG,
               'event': 'push', 'run_attempt': 1, 'status': 'completed', 'conclusion': 'success'}
        self.m.validate_producer(run)
        for key, value in [('id', 1), ('head_sha', 'b' * 40), ('head_branch', 'main'),
                           ('event', 'workflow_dispatch'), ('run_attempt', 2), ('conclusion', 'failure')]:
            with self.subTest(key=key), self.assertRaises(self.m.Stop): self.m.validate_producer({**run, key: value})

    def test_prepared_context_cannot_be_reused_by_another_run(self):
        self.prepare_local()
        with patch.dict(os.environ, {'GITHUB_RUN_ID': '12346'}), patch.object(subprocess, 'run') as run:
            with self.assertRaises(self.m.Stop): self.m.submit(self.root)
            run.assert_not_called()

    def test_subprocess_environment_does_not_export_credentials(self):
        with patch.dict(os.environ, {'GH_TOKEN': 'github-secret'}), patch.object(subprocess, 'run') as run:
            run.return_value = subprocess.CompletedProcess([], 0, '', '')
            self.m.command(['xcrun', 'notarytool', '--version'], apple=True)
            env = run.call_args.kwargs['env']
            for key in (*self.m.SECRETS, 'GH_TOKEN', 'GITHUB_TOKEN'): self.assertNotIn(key, env)

    def test_final_assessment_keeps_rejection_and_byte_mutation_as_failures(self):
        self.prepare_local()
        self.m.write_json(self.root / 'notarization.json', {'status': 'Accepted', 'sha256': self.m.SHA256})
        with patch.object(self.m, 'frozen_remote'), patch.object(subprocess, 'run') as run:
            run.return_value = subprocess.CompletedProcess([], 3, '', 'source=Unnotarized Developer ID')
            with self.assertRaises(self.m.Stop): self.m.assess(self.root)
        self.assertEqual(json.loads((self.root / 'assessment.json').read_text())['exit_code'], 3)

    def test_frozen_constants_are_the_approved_asset(self):
        self.assertEqual((self.m.RELEASE, self.m.ASSET, self.m.SIZE), (403346505, 611407025, 13814673))
        self.assertEqual(self.m.SHA256, 'ba9dd76823612370c58ad6881e4da6efd826ac565f63e5701b334f6bca84b02e')
        self.assertEqual(self.m.SOURCE, 'c142b2294b4d686ecba3286cd42812587ca0a334')

    def test_apple_uuid_case_differences_are_not_different_submissions(self):
        for mode in ['upper-submit', 'upper-wait', 'upper-log']:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                self.root = Path(tmp); self.prepare_local(); self.calls = []
                with patch.object(subprocess, 'run', side_effect=self.apple(mode)): self.m.submit(self.root)
                self.assertEqual(json.loads((self.root / 'notarization.json').read_text())['status'], 'Accepted')

    def test_foreign_or_malformed_apple_id_cannot_pass(self):
        for value in [None, 42, [], 'not-a-uuid']:
            self.assertIsNone(self.m.parsed_id(json.dumps({'id': value})))
        self.prepare_local(); self.calls = []
        with patch.object(subprocess, 'run', side_effect=self.apple('wrong-id')), self.assertRaises(self.m.Stop): self.m.submit(self.root)

    def test_attestation_requires_authenticated_run_not_only_predicate(self):
        invocation = f'https://github.com/{self.m.REPO}/actions/runs/{self.m.PRODUCER}/attempts/1'
        record = {'verificationResult': {'signature': {'certificate': {'runInvocationURI': invocation}},
                  'statement': {'predicate': {'runDetails': {'metadata': {'invocationId': invocation}}}}}}
        self.assertTrue(hasattr(self.m, 'validate_attestation'), 'missing authenticated run validation')
        self.m.validate_attestation([record])
        for value in ['', invocation.replace('/attempts/1', '/attempts/2')]:
            bad = copy.deepcopy(record); bad['verificationResult']['signature']['certificate']['runInvocationURI'] = value
            with self.assertRaises(self.m.Stop): self.m.validate_attestation([bad])

    def test_online_assessment_does_not_reuse_or_populate_cache(self):
        self.prepare_local()
        self.m.write_json(self.root / 'notarization.json', {'status': 'Accepted', 'sha256': self.m.SHA256})
        with patch.object(self.m, 'frozen_remote'), patch.object(subprocess, 'run') as run:
            run.return_value = subprocess.CompletedProcess([], 0, '', 'source=Notarized Developer ID')
            self.m.assess(self.root)
            args = run.call_args.args[0]
            self.assertIn('--ignore-cache', args)
            self.assertIn('--no-cache', args)


if __name__ == '__main__':
    unittest.main()
