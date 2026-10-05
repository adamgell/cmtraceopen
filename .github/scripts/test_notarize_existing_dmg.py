"""Offline tests: external GitHub/Apple boundaries are replaced; no credentials/network."""
import copy
import hashlib
import importlib.util
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import runpy
import sys
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

    def test_only_the_exact_failed_dispatch_is_exempt_from_history(self):
        self.m.validate_history([{'workflow_runs': [{'id': 37337656143}, {'id': 12345}]}], '12345')
        for ids in [[], [12345], [37337656143], [12345, 12344], [37337656143, 12345, 12344],
                    [37337656143, 12345, 12345]]:
            pages = [{'workflow_runs': [{'id': value} for value in ids]}]
            with self.assertRaises(self.m.Stop): self.m.validate_history(pages, '12345')
        with self.assertRaises(self.m.Stop):
            self.m.validate_history([{'workflow_runs': [{'id': 37337656143}]}], '37337656143')

    def failed_attempt(self):
        run = {'id': 37337656143, 'workflow_id': 375531990,
               'head_sha': 'fdfba6caff93d938dcac095b8f6b8c00b44e38e6', 'head_branch': 'main',
               'path': '.github/workflows/notarize-existing-dmg.yml', 'event': 'workflow_dispatch',
               'run_attempt': 1, 'status': 'completed', 'conclusion': 'failure'}
        job = {'id': 111856413194, 'run_id': run['id'], 'run_attempt': 1,
               'head_sha': run['head_sha'], 'status': 'completed', 'conclusion': 'failure',
               'steps': [{'name': name, 'number': number, 'status': 'completed', 'conclusion': result}
                         for number, name, result in [
                             (3, 'Verify frozen asset and original producer', 'failure'),
                             (4, 'Submit unchanged DMG once and record Apple result', 'skipped'),
                             (5, 'Assess unchanged DMG online', 'skipped')]]}
        return run, {'total_count': 1, 'jobs': [job]}

    def test_failed_attempt_exception_requires_exact_identity_and_skipped_submit(self):
        run, jobs = self.failed_attempt()
        self.m.validate_failed_attempt(run, jobs)
        for key, value in [('id', 1), ('workflow_id', 1), ('head_sha', 'b' * 40),
                           ('path', 'other.yml'), ('head_branch', 'other'), ('event', 'push'),
                           ('run_attempt', 2), ('status', 'in_progress'), ('conclusion', 'success')]:
            with self.subTest(key=key), self.assertRaises(self.m.Stop):
                self.m.validate_failed_attempt({**run, key: value}, jobs)
        for key, value in [('id', 1), ('run_id', 1), ('run_attempt', 2), ('head_sha', 'b' * 40),
                           ('status', 'in_progress'), ('conclusion', 'success')]:
            bad = copy.deepcopy(jobs); bad['jobs'][0][key] = value
            with self.subTest(job_key=key), self.assertRaises(self.m.Stop):
                self.m.validate_failed_attempt(run, bad)
        for status in ['success', 'failure', 'cancelled', None]:
            bad = copy.deepcopy(jobs); bad['jobs'][0]['steps'][1]['conclusion'] = status
            with self.subTest(submit=status), self.assertRaises(self.m.Stop):
                self.m.validate_failed_attempt(run, bad)
        for bad in [{'total_count': 0, 'jobs': []}, {'total_count': 2, 'jobs': jobs['jobs'] * 2}]:
            with self.assertRaises(self.m.Stop): self.m.validate_failed_attempt(run, bad)
        for steps in [jobs['jobs'][0]['steps'][:1], jobs['jobs'][0]['steps'] * 2]:
            bad = copy.deepcopy(jobs); bad['jobs'][0]['steps'] = steps
            with self.assertRaises(self.m.Stop): self.m.validate_failed_attempt(run, bad)

    def test_failed_draft_read_blocks_prepare_and_submit(self):
        run, jobs = self.failed_attempt()
        calls = []
        def github(path, paginate=False):
            calls.append(path)
            if path.startswith('actions/workflows/'):
                return [{'workflow_runs': [{'id': 37337656143}, {'id': 12345}]}]
            if path == 'actions/runs/37337656143': return run
            if path == 'actions/runs/37337656143/attempts/1/jobs?per_page=100': return jobs
            if path == 'git/ref/tags/v1.6.2': return {'object': {'sha': self.m.TAG_OBJECT}}
            if path.startswith('git/tags/'): return {'object': {'sha': self.m.SOURCE}}
            if path == 'releases/403346505': raise self.m.Stop('GitHub API GET releases/403346505 failed (exit 1, HTTP 404)')
            self.fail('unexpected GitHub request: ' + path)
        target = self.root / 'notarization'
        with patch.object(self.m, 'api', side_effect=github), patch.object(subprocess, 'run') as external:
            with self.assertRaisesRegex(self.m.Stop, 'HTTP 404'): self.m.prepare(target)
            with self.assertRaises(FileNotFoundError): self.m.submit(target)
            external.assert_not_called()
        self.assertEqual(calls[-1], 'releases/403346505')
        self.assertFalse((target / 'prepared.json').exists())
        self.assertFalse((target / 'submission-intent.json').exists())

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

    def test_failed_api_identifies_request_exit_and_http_without_raw_stderr(self):
        with patch.object(subprocess, 'run') as run:
            run.return_value = subprocess.CompletedProcess([], 1, '', 'gh: Not Found (HTTP 404) secret-do-not-retain')
            with self.assertRaises(self.m.Stop) as caught:
                self.m.api('releases/403346505')
        self.assertEqual(str(caught.exception), 'GitHub API GET releases/403346505 failed (exit 1, HTTP 404)')
        self.assertNotIn('secret-do-not-retain', str(caught.exception))

    def test_prepare_cli_reports_safe_failure_reason_before_first_checkpoint(self):
        cases = [(1, '', 'gh: Forbidden (HTTP 403) secret-do-not-retain',
                  'GitHub API GET actions/workflows/notarize-existing-dmg.yml/runs?per_page=100 failed (exit 1, HTTP 403)'),
                 (0, 'secret-do-not-retain', '', 'JSONDecodeError')]
        for code, stdout, stderr, expected in cases:
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as tmp:
                target = Path(tmp) / 'notarization'
                capture = io.StringIO()
                with patch.object(sys, 'argv', [str(SCRIPT), 'prepare', str(target)]), \
                     patch.object(subprocess, 'run') as run, contextlib.redirect_stderr(capture):
                    run.return_value = subprocess.CompletedProcess([], code, stdout, stderr)
                    with self.assertRaises(SystemExit) as caught:
                        runpy.run_path(str(SCRIPT), run_name='__main__')
                self.assertEqual(caught.exception.code, 1)
                self.assertIn(expected, capture.getvalue())
                self.assertNotIn('secret-do-not-retain', capture.getvalue())
                self.assertEqual(run.call_count, 1)
                self.assertEqual(run.call_args.args[0][:2], ['gh', 'api'])
                self.assertEqual(list(target.glob('*.json')), [])


if __name__ == '__main__':
    unittest.main()
