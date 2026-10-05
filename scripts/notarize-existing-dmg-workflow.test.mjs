import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import test from 'node:test';

const workflow = new URL('../.github/workflows/notarize-existing-dmg.yml', import.meta.url);
const root = new URL('../', import.meta.url);

test('one-off workflow is manual, bounded and cannot write release assets', () => {
  assert.ok(existsSync(workflow), 'missing one-off workflow');
  const text = readFileSync(workflow, 'utf8');
  assert.match(text, /^  workflow_dispatch:$/m);
  assert.doesNotMatch(text, /^  (push|pull_request|schedule|workflow_run):/m);
  assert.equal([...text.matchAll(/^  [a-z][\w-]*:\n    name:/gm)].length, 1);
  assert.match(text, /timeout-minutes: 20/);
  assert.match(text, /contents: read/);
  assert.match(text, /attestations: read/);
  assert.doesNotMatch(text, /(?:contents|attestations|id-token): write|secrets: inherit/);
  assert.match(text, /persist-credentials: false/);
  assert.match(text, /ref: \$\{\{ github.workflow_sha \}\}/);
  assert.match(text, /cancel-in-progress: false/);
  const steps = text.split(/^      - /m).slice(1);
  const credentialSteps = steps.filter(s => /secrets\.APPLE_/.test(s));
  assert.equal(credentialSteps.length, 1);
  assert.match(credentialSteps[0], /notarize-existing-dmg\.py submit/);
  assert.match(credentialSteps[0], /timeout-minutes: 12/);
  assert.doesNotMatch(credentialSteps[0], /GH_TOKEN|GITHUB_TOKEN|set -x/);
  assert.doesNotMatch(text, /APPLE_CERTIFICATE|KEYCHAIN_PASSWORD|stapler|cargo |npm ci|tauri-action|gh release upload/);
  assert.match(text, /if: always\(\)/);
  assert.match(text, /notarization\/\*\.json/);
  assert.doesNotMatch(text, /path:.*\.dmg/);
  for (const action of text.matchAll(/uses: ([^\s]+)@(\S+)/g)) {
    assert.match(action[2], /^[0-9a-f]{40}$/);
  }
});

test('bounded validator and submission tests run offline', () => {
  const result = spawnSync('python3', ['-B', '-m', 'unittest', 'discover', '-s', '.github/scripts', '-p', 'test_notarize_existing_dmg.py'], { cwd: root, encoding: 'utf8', timeout: 20000 });
  assert.equal(result.status, 0, result.stdout + result.stderr);
});

test('recovery tests are wired into existing CI', () => {
  assert.match(readFileSync(new URL('.github/workflows/cmtrace-ci.yml', root), 'utf8'), /node --test[^\n]*scripts\/notarize-existing-dmg-workflow\.test\.mjs/);
});
