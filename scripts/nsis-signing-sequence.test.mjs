import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const workflow = readFileSync(new URL('../.github/workflows/codesign.yml', import.meta.url), 'utf8');
const steps = workflow.split(/^      - name: /m).slice(1);
function step(name) {
  const result = steps.find(block => block.startsWith(`${name}\n`));
  assert.ok(result, `missing ${name}`);
  return result;
}

test('NSIS payload signing occurs during bundling after credential-free compilation', () => {
  const compile = step('Compile full edition without bundling');
  const bundle = step('Bundle NSIS with signed application payload');
  assert.match(compile, /app:build:release .* --no-bundle/);
  assert.doesNotMatch(compile, /env:|AZURE_|SIGNING_/);
  assert.match(bundle, /signCommand/);
  assert.match(bundle, /sign-tauri-windows\.ps1/);
  assert.match(bundle, /args = @\('-NoLogo', '-NoProfile', '-NonInteractive', '-File', \$hook, '%1'\)/);
  assert.match(bundle, /node scripts\/tauri\.mjs bundle .* --bundles nsis --config \$configPath/);
  assert.doesNotMatch(bundle, /tauri\.mjs build|app:build|npm ci|Install-Module/);
  assert.match(bundle, /if \(\$LASTEXITCODE -ne 0\).*throw/);
  const ordered = [compile, bundle, step('Save full edition binary'),
    step('Build lite edition (standalone EXE)'), step('Sign release EXEs'),
    step('Verify NSIS bundled application signature'),
    step('Generate updater signature for NSIS installer')].map(block => steps.indexOf(block));
  assert.deepEqual(ordered, [...ordered].sort((a, b) => a - b));
});

test('bundler hook uses the existing action module version and credential names', () => {
  assert.match(step('Install existing Artifact Signing module for bundler hook'),
    /Install-Module -Name ArtifactSigning -RequiredVersion 0\.1\.8 -Force -Repository PSGallery/);
  const bundle = step('Bundle NSIS with signed application payload');
  for (const name of ['AZURE_TENANT_ID', 'AZURE_CLIENT_ID', 'AZURE_CLIENT_SECRET',
    'SIGNING_ENDPOINT', 'SIGNING_ACCOUNT_NAME', 'SIGNING_PROFILE_NAME']) {
    assert.ok(bundle.includes(`secrets.${name}`));
    assert.ok(step('Sign release EXEs').includes(`secrets.${name}`));
  }
});
