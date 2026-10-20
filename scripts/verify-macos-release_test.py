import importlib.util
import io
import json
from pathlib import Path
import plistlib
import shutil
import tarfile
import tempfile
import unittest
import os
import subprocess
from unittest.mock import patch

SCRIPT = Path(__file__).with_name('verify-macos-release.py')

class MacTrustTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('verify_mac', SCRIPT)
        self.m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.m)
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); self.bundle = self.root / 'bundle'
        (self.bundle / 'macos').mkdir(parents=True); (self.bundle / 'dmg').mkdir()
        self.app = self.bundle / 'macos/CMTrace Open.app'
        (self.app / 'Contents/MacOS').mkdir(parents=True)
        (self.app / 'Contents/MacOS/cmtrace-open').write_bytes(b'signed fixture payload')
        (self.app / 'Contents/Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier': 'com.cmtrace.open', 'CFBundleShortVersionString': '1.6.3', 'CFBundleExecutable': 'cmtrace-open'}))
        (self.bundle / 'dmg/test.dmg').write_bytes(b'dmg fixture')
        self.archive = self.bundle / 'macos/test.app.tar.gz'
        with tarfile.open(self.archive, 'w:gz') as tar: tar.add(self.app, arcname=self.app.name)
        self.receipts = self.root / 'receipts'
        self.calls = []

    def command(self, args, records):
        self.calls.append(args)
        if args[:2] == ['hdiutil', 'attach']:
            mount = Path(args[args.index('-mountpoint') + 1]); shutil.copytree(self.app, mount / self.app.name)
        if args[:2] == ['codesign', '--display']:
            return 'Authority=Developer ID Application: Adam Gell (CRHL85PH9Y)\nTeamIdentifier=CRHL85PH9Y\nIdentifier=com.cmtrace.open\nCodeDirectory v=20500 size=123 flags=0x10000(runtime) hashes=1+1 location=embedded\n'
        return ''

    def verify(self):
        with patch.object(self.m, 'command', side_effect=self.command):
            return self.m.verify(self.bundle, self.receipts, '1.6.3', 'a' * 40, '123', '1')

    def test_complete_trust_proof_binds_both_archives_and_payloads(self):
        self.verify()
        doc = json.loads((self.receipts / 'macos-trust.json').read_text())
        self.assertEqual(doc['status'], 'PASS'); self.assertFalse(doc['nativeAcceptance'])
        self.assertEqual(len(doc['artifacts']), 2); self.assertEqual(len(doc['applications']), 3)
        self.assertEqual(len({a['executable']['sha256'] for a in doc['applications']}), 1)
        self.assertTrue(any(c[:2] == ['hdiutil', 'detach'] for c in self.calls))

    def test_unsigned_or_wrong_team_rejected(self):
        with patch.object(self.m, 'command', return_value='TeamIdentifier=OTHER\n'):
            with self.assertRaises(ValueError): self.m.verify_app(self.app, '1.6.3', [])

    def test_wrong_bundle_version_rejected(self):
        with patch.object(self.m, 'command', side_effect=self.command), self.assertRaises(ValueError):
            self.m.verify_app(self.app, '1.6.2', [])

    def test_missing_ticket_or_gatekeeper_rejected_and_receipt_retained(self):
        def fail(args, records):
            if args[:3] == ['xcrun', 'stapler', 'validate']: raise ValueError('missing staple')
            return self.command(args, records)
        with patch.object(self.m, 'command', side_effect=fail), self.assertRaises(ValueError):
            self.m.verify(self.bundle, self.receipts, '1.6.3', 'a' * 40, '123', '1')
        self.assertEqual(json.loads((self.receipts / 'macos-trust.json').read_text())['status'], 'FAIL')

    def test_changed_updater_payload_rejected(self):
        original = self.command
        def change(args, records):
            if args[:2] == ['hdiutil', 'attach']:
                (self.app / 'Contents/MacOS/cmtrace-open').write_bytes(b'different payload')
            return original(args, records)
        with patch.object(self.m, 'command', side_effect=change), self.assertRaisesRegex(ValueError, 'payload'):
            self.m.verify(self.bundle, self.receipts, '1.6.3', 'a' * 40, '123', '1')

    def test_ambiguous_artifacts_rejected(self):
        (self.bundle / 'dmg/second.dmg').write_bytes(b'other')
        with self.assertRaises(ValueError): self.verify()

    def test_archive_traversal_rejected(self):
        with tarfile.open(self.archive, 'w:gz') as tar:
            entry = tarfile.TarInfo('../escape'); entry.size = 1; tar.addfile(entry, io.BytesIO(b'x'))
        with self.assertRaises(ValueError): self.verify()

class DmgNotaryStepTests(unittest.TestCase):
    def run_step(self, mode='accepted'):
        workflow = (SCRIPT.parents[1] / '.github/workflows/cmtrace-release.yml').read_text()
        marker = '      - name: Notarize and staple final macOS DMG\n'
        self.assertIn(marker, workflow, 'Producer must notarize the DMG before strict trust verification')
        self.assertLess(workflow.index(marker), workflow.index('      - name: Verify macOS release trust'))
        block = workflow.split(marker)[1].split('\n      - name:')[0]
        code = block.split("          python3 - <<'PY'\n")[1].split('\n          PY')[0]
        code = '\n'.join(line[10:] for line in code.splitlines())
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        root = Path(temporary.name); dmg = root / 'bundle/dmg/test.dmg'
        dmg.parent.mkdir(parents=True); dmg.write_bytes(b'signed unstapled DMG')
        receipts = root / 'receipts'
        calls = []
        sid = '11111111-2222-3333-4444-555555555555'
        def command(args, **kwargs):
            self.assertFalse({'APPLE_ID','APPLE_PASSWORD','APPLE_TEAM_ID','GH_TOKEN','GITHUB_TOKEN'} & kwargs['env'].keys())
            calls.append(args[:])
            if args[:3] == ['xcrun','notarytool','submit']:
                if mode == 'submit-timeout': raise subprocess.TimeoutExpired(args,120)
                return subprocess.CompletedProcess(args,0,json.dumps({'id':sid}), '')
            if args[:3] == ['xcrun','notarytool','wait']:
                self.assertTrue((receipts/'submission.json').is_file(), 'Submission must be durable before wait')
                return subprocess.CompletedProcess(args,0,json.dumps({'id':sid,'status':'Invalid' if mode=='rejected' else 'Accepted'}), '')
            if args[:3] == ['xcrun','stapler','staple']: dmg.write_bytes(b'signed stapled DMG')
            return subprocess.CompletedProcess(args,0,'', 'TeamIdentifier=CRHL85PH9Y\n')
        env = {'BUNDLE_ROOT':str(root/'bundle'), 'NOTARY_RECEIPTS':str(receipts),
               'APPLE_ID':'fixture-user','APPLE_PASSWORD':'fixture-password','APPLE_TEAM_ID':'CRHL85PH9Y',
               'GITHUB_RUN_ATTEMPT':'2' if mode=='rerun' else '1','GITHUB_RUN_ID':'123'}
        with patch.dict(os.environ,env,clear=True), patch.object(subprocess,'run',side_effect=command):
            if mode == 'accepted': exec(compile(code,'<producer-notarization>','exec'),{})
            else:
                with self.assertRaises(SystemExit): exec(compile(code,'<producer-notarization>','exec'),{})
        return receipts, calls

    def test_producer_records_submission_before_wait_and_staples_accepted_dmg(self):
        receipts,calls=self.run_step()
        result=json.loads((receipts/'result.json').read_text())
        self.assertEqual(result['status'],'PASS')
        self.assertNotEqual(result['submittedSha256'],result['stapledSha256'])
        self.assertEqual(len([c for c in calls if c[:3]==['xcrun','notarytool','submit']]),1)
        self.assertTrue(any(c[:3]==['xcrun','stapler','validate'] for c in calls))
        self.assertNotIn('fixture-password',''.join(p.read_text() for p in receipts.glob('*.json')))

    def test_submission_timeout_retains_intent_and_never_retries(self):
        receipts,calls=self.run_step('submit-timeout')
        self.assertTrue((receipts/'submission-intent.json').is_file())
        self.assertFalse((receipts/'submission.json').exists())
        self.assertEqual(len([c for c in calls if c[:3]==['xcrun','notarytool','submit']]),1)
        self.assertFalse(any(c[:2]==['xcrun','stapler'] for c in calls))

    def test_rejected_submission_never_staples_or_reports_pass(self):
        receipts,calls=self.run_step('rejected')
        self.assertEqual(json.loads((receipts/'result.json').read_text())['status'],'FAIL')
        self.assertFalse(any(c[:2]==['xcrun','stapler'] for c in calls))

    def test_rerun_cannot_submit_a_second_time(self):
        receipts,calls=self.run_step('rerun')
        self.assertEqual(calls,[])
        self.assertFalse((receipts/'submission-intent.json').exists())

if __name__ == '__main__': unittest.main()
