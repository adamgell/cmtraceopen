"""One-off v1.6.2 DMG notarization. No builds, signing, stapling or release writes."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import uuid

REPO = 'adamgell/cmtraceopen'
TAG = 'v1.6.2'
TAG_OBJECT = '7d7cb1bec8b372fbaf08845c2ac6bab6668ba6c0'
SOURCE = 'c142b2294b4d686ecba3286cd42812587ca0a334'
RELEASE = 403346505
ASSET = 611407025
NAME = 'CMTrace.Open_1.6.2_aarch64.dmg'
SIZE = 13814673
SHA256 = 'ba9dd76823612370c58ad6881e4da6efd826ac565f63e5701b334f6bca84b02e'
UPDATED = '2026-10-05T03:51:18Z'
CDHASH = '941142b0dd718a98ee2d0e2bfd3bc67434bd6e2c'
PRODUCER = 37260205745
WORKFLOW = 'notarize-existing-dmg.yml'
FAILED_RUN = 37337656143
FAILED_COMMIT = 'fdfba6caff93d938dcac095b8f6b8c00b44e38e6'
SECRETS = ('APPLE_ID', 'APPLE_PASSWORD', 'APPLE_TEAM_ID')


class Stop(Exception):
    """Safe diagnostic: never carry a subprocess command or raw Apple output."""


def require(condition, message):
    if not condition:
        raise Stop(message)


def context():
    env = os.environ
    sha = env.get('REVIEWED_WORKFLOW_SHA', '')
    require(re.fullmatch('[0-9a-f]{40}', sha), 'A reviewed workflow commit is required')
    require(env.get('GITHUB_REPOSITORY') == REPO and env.get('GITHUB_EVENT_NAME') == 'workflow_dispatch', 'Wrong repository or trigger')
    require(env.get('GITHUB_REF') == 'refs/heads/main', 'Dispatch must use reviewed main')
    require(env.get('GITHUB_SHA') == env.get('GITHUB_WORKFLOW_SHA') == sha, 'Workflow commit differs from review')
    require(env.get('GITHUB_WORKFLOW_REF') == f'{REPO}/.github/workflows/{WORKFLOW}@refs/heads/main', 'Wrong workflow identity')
    require(env.get('GITHUB_RUN_ATTEMPT') == '1', 'Reruns are forbidden; inspect the original submission')
    require(re.fullmatch('[1-9][0-9]*', env.get('GITHUB_RUN_ID', '')), 'Missing run identity')
    return {'workflow_commit': sha, 'run_id': env['GITHUB_RUN_ID'], 'run_attempt': 1,
            'workflow': f'{REPO}/.github/workflows/{WORKFLOW}'}


def write_json(path, value):
    # Exclusive checkpoints prevent a repeated phase from overwriting its ledger.
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    path.chmod(0o600)


def command(args, timeout=45, apple=False):
    env = {k: v for k, v in os.environ.items() if k not in SECRETS}
    if apple:
        env.pop('GH_TOKEN', None)
        env.pop('GITHUB_TOKEN', None)
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout, env=env)
    except (subprocess.TimeoutExpired, OSError):
        # Exception objects contain argv (including the password). Never retain them.
        raise Stop('External operation failed or timed out; inspect retained checkpoints') from None


def checked(args, timeout=45, operation='Read-only verification'):
    result = command(args, timeout)
    if result.returncode != 0:
        status = re.search(r'\(HTTP ([0-9]{3})\)', result.stderr)
        http = f', HTTP {status.group(1)}' if status else ''
        raise Stop(f'{operation} failed (exit {result.returncode}{http})')
    return result.stdout


def api(path, paginate=False):
    args = ['gh', 'api']
    if paginate:
        args += ['--paginate', '--slurp']
    return json.loads(checked(args + [f'repos/{REPO}/{path}'], operation=f'GitHub API GET {path}'))


def validate_release(release):
    require(release['id'] == RELEASE and release['tag_name'] == TAG and release['draft'] is True
            and release['prerelease'] is False, 'Release must remain the exact draft')
    assets = [a for a in release['assets'] if a['name'] == NAME or a['id'] == ASSET]
    require(len(assets) == 1, 'DMG asset missing or duplicated')
    a = assets[0]
    require((a['id'], a['name'], a['size'], a['digest'], a['state'], a['updated_at']) ==
            (ASSET, NAME, SIZE, 'sha256:' + SHA256, 'uploaded', UPDATED), 'DMG asset identity changed')
    return a


def frozen_remote():
    require(api(f'git/ref/tags/{TAG}')['object']['sha'] == TAG_OBJECT, 'Product tag moved')
    require(api(f'git/tags/{TAG_OBJECT}')['object']['sha'] == SOURCE, 'Product source changed')
    release = api(f'releases/{RELEASE}')
    validate_release(release)
    require(api('releases/latest')['tag_name'] == 'v1.6.0', 'Public release changed')
    return release


def verify_file(root):
    path = root / NAME
    require(path.is_file() and not path.is_symlink() and path.stat().st_size == SIZE, 'DMG file size/type changed')
    with path.open('rb') as stream:
        digest = hashlib.sha256()
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
        require(digest.hexdigest() == SHA256, 'DMG bytes changed')
    return path


def validate_producer(run):
    require((run['id'], run['head_sha'], run['head_branch'], run['event'], run['run_attempt'], run['status'], run['conclusion']) ==
            (PRODUCER, SOURCE, TAG, 'push', 1, 'completed', 'success'), 'Original producer binding failed')


def validate_history(pages, current):
    runs = [r for page in pages for r in page['workflow_runs']]
    require(current != str(FAILED_RUN) and len(runs) == 2
            and {str(r['id']) for r in runs} == {str(FAILED_RUN), current},
            'Only the reviewed failed run and this one recovery dispatch are permitted')


def validate_failed_attempt(run, jobs):
    require((run['id'], run['workflow_id'], run['head_sha'], run['head_branch'], run['path'],
             run['event'], run['run_attempt'], run['status'], run['conclusion']) ==
            (FAILED_RUN, 375531990, FAILED_COMMIT, 'main', f'.github/workflows/{WORKFLOW}',
             'workflow_dispatch', 1, 'completed', 'failure'), 'Earlier run identity or attempt changed')
    require(jobs['total_count'] == len(jobs['jobs']) == 1, 'Earlier attempt job inventory changed')
    job = jobs['jobs'][0]
    require((job['id'], job['run_id'], job['run_attempt'], job['head_sha'], job['status'], job['conclusion']) ==
            (111856413194, FAILED_RUN, 1, FAILED_COMMIT, 'completed', 'failure'), 'Earlier job identity changed')
    for number, name, conclusion in [
            (3, 'Verify frozen asset and original producer', 'failure'),
            (4, 'Submit unchanged DMG once and record Apple result', 'skipped'),
            (5, 'Assess unchanged DMG online', 'skipped')]:
        steps = [s for s in job['steps'] if s['name'] == name or s['number'] == number]
        require(len(steps) == 1 and (steps[0]['number'], steps[0]['name'], steps[0]['status'], steps[0]['conclusion']) ==
                (number, name, 'completed', conclusion), 'Earlier Apple submission was not provably skipped')


def validate_attestation(proof):
    invocation = f'https://github.com/{REPO}/actions/runs/{PRODUCER}/attempts/1'
    # Certificate extensions are authenticated by GitHub's OIDC issuer; the
    # signed predicate alone is supplied by the producing workflow.
    require(any(p['verificationResult']['signature']['certificate'].get('runInvocationURI') == invocation
                and p['verificationResult']['statement']['predicate']['runDetails']['metadata']['invocationId'] == invocation
                for p in proof), 'Authenticated attestation producer invocation differs')


def prepare(root):
    ctx = context()
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    history = api(f'actions/workflows/{WORKFLOW}/runs?per_page=100', True)
    validate_history(history, ctx['run_id'])
    failed = api(f'actions/runs/{FAILED_RUN}')
    jobs = api(f'actions/runs/{FAILED_RUN}/attempts/1/jobs?per_page=100')
    validate_failed_attempt(failed, jobs)
    write_json(root / 'previous-failed-attempt.json', {'run': failed, 'jobs': jobs})
    # This hosted-token read must succeed before prepared.json can permit Apple submission.
    release = frozen_remote()
    run = api(f'actions/runs/{PRODUCER}')
    validate_producer(run)
    write_json(root / 'original-producer.json', run)
    write_json(root / 'release-before.json', release)
    # Bound the download and never run/mount it. All GitHub operations remain read-only.
    with (root / NAME).open('xb') as stream:
        result = subprocess.run(['gh', 'api', '-H', 'Accept: application/octet-stream',
                                 f'repos/{REPO}/releases/assets/{ASSET}'],
                                stdout=stream, stderr=subprocess.PIPE, timeout=60)
    require(result.returncode == 0, 'DMG download failed')
    path = verify_file(root)
    path.chmod(0o444)
    proof = json.loads(checked(['gh', 'attestation', 'verify', str(path), '--repo', REPO,
        '--source-digest', SOURCE, '--source-ref', 'refs/tags/' + TAG,
        '--signer-workflow', f'{REPO}/.github/workflows/cmtrace-release.yml', '--format', 'json'], 60))
    validate_attestation(proof)
    write_json(root / 'original-attestation.json', proof)
    checked(['hdiutil', 'verify', str(path)], 60)
    checked(['codesign', '--verify', '--strict', '--verbose=4', str(path)])
    details = command(['codesign', '--display', '--verbose=4', str(path)])
    require(details.returncode == 0 and f'CDHash={CDHASH}\n' in details.stderr
            and 'TeamIdentifier=CRHL85PH9Y\n' in details.stderr
            and 'Authority=Developer ID Application: Adam Gell (CRHL85PH9Y)\n' in details.stderr, 'Developer ID identity differs')
    baseline = command(['spctl', '--assess', '--type', 'open', '--context', 'context:primary-signature',
                        '--ignore-cache', '--no-cache', '--verbose=4', str(path)], 60)
    require(baseline.returncode == 3 and 'source=Unnotarized Developer ID' in baseline.stderr, 'DMG no longer has the expected rejection; stop before submitting')
    write_json(root / 'prepared.json', {'context': ctx, 'source': SOURCE, 'tag_object': TAG_OBJECT,
               'release_id': RELEASE, 'asset_id': ASSET, 'sha256': SHA256, 'size': SIZE,
               'producer_run': PRODUCER, 'producer_attempt': 1, 'baseline': baseline.stderr})


def prepared(root):
    doc = json.loads((root / 'prepared.json').read_text())
    require(doc['context'] == context() and doc['sha256'] == SHA256, 'Prepared evidence belongs to another run')
    return verify_file(root)


def canonical_id(value):
    try:
        if not isinstance(value, str):
            return None
        normalized = str(uuid.UUID(value))
        return normalized if normalized == value.lower() else None
    except ValueError:
        return None


def parsed_id(text):
    try:
        return canonical_id(json.loads(text)['id'])
    except (ValueError, TypeError, KeyError):
        return None


def scrub(value, secrets):
    if isinstance(value, str):
        for secret in secrets:
            value = value.replace(secret, '[redacted]')
        return value
    if isinstance(value, list):
        return [scrub(v, secrets) for v in value]
    if isinstance(value, dict):
        return {scrub(k, secrets): scrub(v, secrets) for k, v in value.items()}
    return value


def submit(root):
    path = prepared(root)
    require(not (root / 'submission-intent.json').exists(), 'Submission already attempted; do not retry')
    secrets = [os.environ.get(k, '') for k in SECRETS]
    require(all(secrets) and secrets[2] == 'CRHL85PH9Y', 'Existing Apple credentials/team required')
    auth = ['--apple-id', secrets[0], '--password', secrets[1], '--team-id', secrets[2]]
    write_json(root / 'submission-intent.json', {'context': context(), 'sha256': SHA256,
               'status': 'Upload may have begun; never resubmit without investigating this run'})
    state = {'status': 'Upload outcome uncertain', 'sha256': SHA256}
    try:
        result = command(['xcrun', 'notarytool', 'submit', str(path), *auth,
                          '--no-wait', '--output-format', 'json'], 120, apple=True)
        sid = parsed_id(result.stdout)
        if sid:
            write_json(root / 'submission.json', {'id': sid, 'sha256': SHA256, 'context': context()})
            print(f'Apple submission ID: {sid}', flush=True)
            state['id'] = sid
            state['status'] = 'Submission recorded; completion unknown'
        require(result.returncode == 0 and sid, 'Upload outcome uncertain; inspect checkpoint, never resubmit')
        # At most eight minutes of server polling; preserve time for log/receipt upload.
        result = command(['xcrun', 'notarytool', 'wait', sid, *auth,
                          '--timeout', '8m', '--output-format', 'json'], 510, apple=True)
        response = json.loads(result.stdout)
        require(result.returncode == 0 and canonical_id(response.get('id')) == sid, 'Notarization wait incomplete; use recorded ID for read-only lookup')
        status = response.get('status')
        require(status in ('Accepted', 'Invalid', 'Rejected'), 'Notarization remains incomplete')
        # Raw Apple diagnostics stay outside the evidence directory and are removed.
        with tempfile.TemporaryDirectory(prefix='cmtrace-notary-log-') as temporary:
            log_path = Path(temporary) / 'notary.json'
            result = command(['xcrun', 'notarytool', 'log', sid, str(log_path), *auth], 60, apple=True)
            require(result.returncode == 0 and log_path.stat().st_size <= 4 * 1024 * 1024, 'Notarization log unavailable')
            log = json.loads(log_path.read_text())
            allowed = ('jobId', 'status', 'statusSummary', 'sha256', 'archiveFilename', 'uploadDate', 'logFormatVersion', 'issues', 'ticketContents')
            write_json(root / 'apple-log.json', scrub({k: log[k] for k in allowed if k in log}, secrets))
        require(status == log.get('status') == 'Accepted' and canonical_id(log.get('jobId')) == sid
                and log.get('sha256') == SHA256 and log.get('archiveFilename') == NAME
                and any(t.get('cdhash') == CDHASH for t in log.get('ticketContents', [])), 'Apple acceptance does not match the exact DMG')
        verify_file(root)
        state['status'] = 'Accepted'
    finally:
        write_json(root / 'notarization.json', state)


def assess(root):
    path = prepared(root)
    accepted = json.loads((root / 'notarization.json').read_text())
    require(accepted['status'] == 'Accepted' and accepted['sha256'] == SHA256, 'Apple acceptance missing')
    frozen_remote()
    result = command(['spctl', '--assess', '--type', 'open', '--context', 'context:primary-signature',
                      '--ignore-cache', '--no-cache', '--verbose=4', str(path)], 60)
    verify_file(root)
    write_json(root / 'assessment.json', {'context': context(), 'sha256': SHA256,
               'exit_code': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr,
               'release_remains_draft': True})
    require(result.returncode == 0 and 'source=Notarized Developer ID' in result.stderr, 'Online DMG assessment remains blocked')


if __name__ == '__main__':
    try:
        require(len(sys.argv) == 3 and sys.argv[1] in ('prepare', 'submit', 'assess'), 'Expected phase and evidence directory')
        os.umask(0o077)
        {'prepare': prepare, 'submit': submit, 'assess': assess}[sys.argv[1]](Path(sys.argv[2]))
    except (Stop, ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError) as error:
        # Never print exception repr/traceback: a subprocess exception may carry secrets.
        reason = str(error) if isinstance(error, Stop) else type(error).__name__
        print(f'Recovery stopped: {reason}. Inspect retained checkpoints; never automatically resubmit.', file=sys.stderr)
        sys.exit(1)
