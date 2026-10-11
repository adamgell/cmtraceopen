"""Read-only Apple trust checks for the release app, DMG and updater payload."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import subprocess
import tarfile
import tempfile

TEAM = 'CRHL85PH9Y'
IDENTIFIER = 'com.cmtrace.open'


def file_evidence(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError(f'Expected a regular release file: {path}')
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return {'path': str(path), 'bytes': path.stat().st_size, 'sha256': digest.hexdigest()}


def command(args, records):
    # Verification needs no Apple account credentials or publication token.
    env = {k: v for k, v in os.environ.items() if k not in
           ('APPLE_ID', 'APPLE_PASSWORD', 'APPLE_CERTIFICATE_PASSWORD', 'GH_TOKEN', 'GITHUB_TOKEN')}
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=90, env=env)
    except (OSError, subprocess.TimeoutExpired):
        records.append({'tool': args[0], 'arguments': args[1:], 'status': 'failed-or-timed-out'})
        raise ValueError(f'{args[0]} verification failed or timed out') from None
    records.append({'tool': args[0], 'arguments': args[1:], 'exitCode': result.returncode,
                    'stdout': result.stdout[:32768], 'stderr': result.stderr[:32768]})
    if result.returncode != 0:
        raise ValueError(f'{args[0]} verification failed ({result.returncode})')
    return result.stdout + result.stderr


def verify_app(app, version, records):
    if not app.is_dir() or app.is_symlink(): raise ValueError('Expected one regular application bundle')
    with (app / 'Contents/Info.plist').open('rb') as stream: info = plistlib.load(stream)
    if info.get('CFBundleIdentifier') != IDENTIFIER or info.get('CFBundleShortVersionString') != version:
        raise ValueError('Application identity/version differs from release')
    executable = info.get('CFBundleExecutable', '')
    if not executable or Path(executable).name != executable: raise ValueError('Invalid bundle executable name')
    payload = file_evidence(app / 'Contents/MacOS' / executable)
    command(['codesign', '--verify', '--deep', '--strict', '--verbose=4', str(app)], records)
    details = command(['codesign', '--display', '--verbose=4', str(app)], records)
    for expected in (f'TeamIdentifier={TEAM}', f'Identifier={IDENTIFIER}',
                     f'Authority=Developer ID Application: Adam Gell ({TEAM})'):
        if expected not in details.splitlines(): raise ValueError('Unexpected Developer ID application identity')
    if not re.search(r'^CodeDirectory .*flags=.*\bruntime\b', details, re.M):
        raise ValueError('Application hardened runtime is missing')
    command(['xcrun', 'stapler', 'validate', str(app)], records)
    command(['spctl', '--assess', '--type', 'execute', '--ignore-cache', '--no-cache', '--verbose=4', str(app)], records)
    if payload != file_evidence(app / 'Contents/MacOS' / executable): raise ValueError('Application payload changed during verification')
    return {'path': str(app), 'teamIdentifier': TEAM, 'identifier': IDENTIFIER, 'version': version, 'executable': payload}


def exactly_one(paths, label):
    paths = list(paths)
    if len(paths) != 1: raise ValueError(f'Expected exactly one {label}; found {len(paths)}')
    return paths[0]


def verify(bundle, receipts, version, source, run_id, attempt):
    if not re.fullmatch(r'\d+\.\d+\.\d+', version) or not re.fullmatch(r'[0-9a-f]{40}', source):
        raise ValueError('Invalid source/version context')
    if not re.fullmatch(r'[1-9][0-9]*', run_id) or not re.fullmatch(r'[1-9][0-9]*', attempt):
        raise ValueError('Invalid GitHub run context')
    receipts.mkdir(parents=True, exist_ok=False)
    doc = {'schemaVersion': 1, 'sourceCommit': source, 'runId': run_id, 'runAttempt': attempt,
           'version': version, 'status': 'FAIL', 'nativeAcceptance': False,
           'artifacts': [], 'applications': [], 'commands': []}
    temp = Path(tempfile.mkdtemp(prefix='cmtrace-release-trust-'))
    mounted = False
    mount = temp / 'dmg'; mount.mkdir()
    try:
        app = exactly_one((bundle / 'macos').glob('*.app'), 'built app')
        dmg = exactly_one((bundle / 'dmg').glob('*.dmg'), 'DMG')
        archive = exactly_one((bundle / 'macos').glob('*.app.tar.gz'), 'updater archive')
        doc['artifacts'] = [file_evidence(dmg), file_evidence(archive)]
        doc['applications'].append(verify_app(app, version, doc['commands']))
        command(['hdiutil', 'verify', str(dmg)], doc['commands'])
        command(['codesign', '--verify', '--strict', '--verbose=4', str(dmg)], doc['commands'])
        details = command(['codesign', '--display', '--verbose=4', str(dmg)], doc['commands'])
        if f'TeamIdentifier={TEAM}' not in details.splitlines() or f'Authority=Developer ID Application: Adam Gell ({TEAM})' not in details.splitlines():
            raise ValueError('Unexpected DMG Developer ID identity')
        command(['xcrun', 'stapler', 'validate', str(dmg)], doc['commands'])
        command(['spctl', '--assess', '--type', 'open', '--context', 'context:primary-signature',
                 '--ignore-cache', '--no-cache', '--verbose=4', str(dmg)], doc['commands'])
        mounted = True  # Also attempt detach after a partially failed attach.
        command(['hdiutil', 'attach', '-readonly', '-nobrowse', '-mountpoint', str(mount), str(dmg)], doc['commands'])
        doc['applications'].append(verify_app(exactly_one(mount.glob('*.app'), 'DMG app'), version, doc['commands']))
        extracted = temp / 'updater'; extracted.mkdir()
        with tarfile.open(archive, 'r:gz') as tar:
            members = tar.getmembers()
            if len(members) > 100000 or sum(m.size for m in members) > 1024 * 1024 * 1024:
                raise ValueError('Updater archive exceeds verification resource limits')
            if any(not m.name.startswith(app.name + '/') and m.name != app.name for m in members):
                raise ValueError('Unexpected updater archive member')
            tar.extractall(extracted, members=members, filter='data')
        doc['applications'].append(verify_app(exactly_one(extracted.glob('*.app'), 'updater app'), version, doc['commands']))
        if len({a['executable']['sha256'] for a in doc['applications']}) != 1:
            raise ValueError('DMG/updater application payload differs from built app')
        if doc['artifacts'] != [file_evidence(dmg), file_evidence(archive)]:
            raise ValueError('Release artifacts changed during verification')
        doc['status'] = 'PASS'
    except (ValueError, OSError, tarfile.TarError) as error:
        doc['failure'] = str(error)[:2048]
        raise
    finally:
        try:
            if mounted:
                command(['hdiutil', 'detach', str(mount)], doc['commands'])
                mounted = False
        except ValueError:
            doc['status'] = 'FAIL'
            raise
        finally:
            (receipts / 'macos-trust.json').write_text(json.dumps(doc, indent=2) + '\n')
            if not mounted: shutil.rmtree(temp)
    return doc


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--receipts', type=Path, required=True)
    parser.add_argument('--version', required=True)
    args = parser.parse_args()
    source = subprocess.run(['git', 'rev-parse', 'HEAD'], check=True, capture_output=True, text=True, timeout=10).stdout.strip()
    verify(args.bundle, args.receipts, args.version, source, os.environ['GITHUB_RUN_ID'], os.environ['GITHUB_RUN_ATTEMPT'])
