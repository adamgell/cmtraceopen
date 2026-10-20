import importlib.util
import io
import json
from pathlib import Path
import plistlib
import shutil
import tarfile
import tempfile
import unittest
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

if __name__ == '__main__': unittest.main()
